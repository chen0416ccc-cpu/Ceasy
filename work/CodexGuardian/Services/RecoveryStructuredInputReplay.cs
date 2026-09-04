using CodexGuardian.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CodexGuardian.Services;

internal sealed record RecoveryStructuredInputCanonicalForm(
    string CanonicalJson,
    string InputDigest,
    IReadOnlyList<string> AttachmentPaths);

internal static class RecoveryStructuredInputCanonicalizer
{
    private const int MaximumInputBytes = 2 * 1024 * 1024;
    private const int MaximumInputItems = 21;
    private const int MaximumPathLength = 1024;

    internal static RecoveryStructuredInputCanonicalForm Parse(string? rawInputJson)
    {
        if (string.IsNullOrWhiteSpace(rawInputJson) ||
            Encoding.UTF8.GetByteCount(rawInputJson) > MaximumInputBytes)
        {
            throw Failure("input-unavailable");
        }

        try
        {
            using var document = JsonDocument.Parse(rawInputJson, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Array ||
                root.GetArrayLength() is < 1 or > MaximumInputItems)
            {
                throw Failure("input-shape");
            }

            var attachmentPaths = new List<string>();
            var hasText = false;
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
                   {
                       Indented = false,
                       SkipValidation = false
                   }))
            {
                writer.WriteStartArray();
                var index = 0;
                foreach (var item in root.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object ||
                        !item.TryGetProperty("type", out var typeElement) ||
                        typeElement.ValueKind != JsonValueKind.String)
                    {
                        throw Failure("item-shape");
                    }

                    var type = typeElement.GetString();
                    switch (type)
                    {
                        case "text":
                            if (hasText || index != 0 ||
                                !HasExactProperties(item, "type", "text", "text_elements") ||
                                !item.TryGetProperty("text", out var textElement) ||
                                textElement.ValueKind != JsonValueKind.String ||
                                string.IsNullOrWhiteSpace(textElement.GetString()) ||
                                !item.TryGetProperty("text_elements", out var textElements) ||
                                textElements.ValueKind != JsonValueKind.Array ||
                                textElements.GetArrayLength() != 0)
                            {
                                throw Failure("text-shape");
                            }

                            hasText = true;
                            writer.WriteStartObject();
                            writer.WriteString("type", "text");
                            writer.WriteString("text", textElement.GetString());
                            writer.WritePropertyName("text_elements");
                            writer.WriteStartArray();
                            writer.WriteEndArray();
                            writer.WriteEndObject();
                            break;

                        case "localImage":
                            if (!HasExactProperties(item, "type", "path") ||
                                !item.TryGetProperty("path", out var pathElement) ||
                                pathElement.ValueKind != JsonValueKind.String)
                            {
                                throw Failure("attachment-shape");
                            }

                            var path = pathElement.GetString();
                            if (string.IsNullOrWhiteSpace(path) ||
                                path.Length > MaximumPathLength ||
                                path.IndexOf('\0') >= 0 ||
                                !Path.IsPathFullyQualified(path))
                            {
                                throw Failure("attachment-path");
                            }

                            attachmentPaths.Add(path);
                            writer.WriteStartObject();
                            writer.WriteString("type", "localImage");
                            writer.WriteString("path", path);
                            writer.WriteEndObject();
                            break;

                        default:
                            throw Failure("input-kind");
                    }

                    index++;
                }

                if (attachmentPaths.Count == 0)
                {
                    throw Failure("attachment-missing");
                }

                writer.WriteEndArray();
                writer.Flush();
            }

            var bytes = stream.GetBuffer().AsSpan(0, checked((int)stream.Length));
            return new RecoveryStructuredInputCanonicalForm(
                Encoding.UTF8.GetString(bytes),
                Convert.ToHexString(SHA256.HashData(bytes)),
                Array.AsReadOnly(attachmentPaths.ToArray()));
        }
        catch (RecoveryStructuredInputReplayException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new RecoveryStructuredInputReplayException("input-json", exception);
        }
        catch (ArgumentException exception)
        {
            throw new RecoveryStructuredInputReplayException("input-path", exception);
        }
    }

    internal static string ComputeDigest(JsonElement input) =>
        Parse(input.GetRawText()).InputDigest;

    private static bool HasExactProperties(JsonElement item, params string[] expected)
    {
        var names = item.EnumerateObject().Select(static property => property.Name).ToArray();
        return names.Length == expected.Length &&
               names.Distinct(StringComparer.Ordinal).Count() == names.Length &&
               names.Order(StringComparer.Ordinal).SequenceEqual(
                   expected.Order(StringComparer.Ordinal),
                   StringComparer.Ordinal);
    }

    private static RecoveryStructuredInputReplayException Failure(string code) => new(code);
}

internal interface IRecoveryStructuredInputReplayAuthority
{
    Task<RecoveryStructuredInputReplayLease> AcquireAsync(
        string threadId,
        TurnSnapshot failedTurn,
        CancellationToken cancellationToken);
}

internal sealed class RecoveryStructuredInputReplayLease : IAsyncDisposable
{
    private AttachmentRecoveryReplayLease? _presentationLease;

    internal RecoveryStructuredInputReplayLease(
        RecoveryStructuredInputCanonicalForm canonical,
        AttachmentRecoveryReplayLease presentationLease)
    {
        CanonicalInputJson = canonical.CanonicalJson;
        InputDigest = canonical.InputDigest;
        _presentationLease = presentationLease ??
            throw new ArgumentNullException(nameof(presentationLease));
    }

    internal string CanonicalInputJson { get; }

    internal string InputDigest { get; }

    internal bool IsCurrent => _presentationLease?.IsCurrent == true;

    public async ValueTask DisposeAsync()
    {
        var lease = Interlocked.Exchange(ref _presentationLease, null);
        if (lease is not null)
        {
            await lease.DisposeAsync().ConfigureAwait(false);
        }
    }
}

internal sealed class RecoveryStructuredInputReplayAuthority : IRecoveryStructuredInputReplayAuthority
{
    private readonly FollowUpOperationJournal _followUpJournal;
    private readonly AttachmentPresentationLeaseService _presentationLeases;

    internal RecoveryStructuredInputReplayAuthority(
        FollowUpOperationJournal followUpJournal,
        AttachmentPresentationLeaseService presentationLeases)
    {
        _followUpJournal = followUpJournal ?? throw new ArgumentNullException(nameof(followUpJournal));
        _presentationLeases = presentationLeases ??
            throw new ArgumentNullException(nameof(presentationLeases));
        if (!string.Equals(
                Path.TrimEndingDirectorySeparator(_followUpJournal.DataDirectory),
                Path.TrimEndingDirectorySeparator(_presentationLeases.DataDirectory),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Replay authorities must share one data directory.");
        }
    }

    public async Task<RecoveryStructuredInputReplayLease> AcquireAsync(
        string threadId,
        TurnSnapshot failedTurn,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(threadId);
        ArgumentNullException.ThrowIfNull(failedTurn);
        var canonical = RecoveryStructuredInputCanonicalizer.Parse(failedTurn.RawUserInputJson);
        var journal = await _followUpJournal.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (journal.RequiresConservativeRecovery ||
            journal.ReadStatus != FollowUpJournalReadStatus.Healthy)
        {
            throw new RecoveryStructuredInputReplayException("follow-up-authority-unavailable");
        }

        var matches = journal.Records.Where(record =>
                record.State == FollowUpOperationState.Confirmed &&
                record.SourceKind is FollowUpPayloadSourceKind.StructuredPreset or
                    FollowUpPayloadSourceKind.WorkflowPreset &&
                string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(record.NewTurnId, failedTurn.Id, StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        if (matches.Length != 1)
        {
            throw new RecoveryStructuredInputReplayException("follow-up-lineage-unavailable");
        }

        var operation = matches[0];
        if (operation.AttachmentContentIds.Count == 0 ||
            operation.PresentationLeaseId is null ||
            operation.PayloadDigest is null ||
            operation.ReplayInputDigest is null ||
            !string.Equals(
                operation.ReplayInputDigest,
                canonical.InputDigest,
                StringComparison.Ordinal))
        {
            throw new RecoveryStructuredInputReplayException("replay-identity-mismatch");
        }

        var references = await _presentationLeases.ReadReferenceSnapshotAsync(cancellationToken)
            .ConfigureAwait(false);
        var reference = references.IsHealthy
            ? references.References.SingleOrDefault(candidate => string.Equals(
                candidate.LeaseId,
                operation.PresentationLeaseId,
                StringComparison.Ordinal))
            : null;
        if (reference is null ||
            reference.State != AttachmentPresentationReferenceState.Ready ||
            !FollowUpAttachmentAuthorityReader.PresentationMatches(operation, reference))
        {
            throw new RecoveryStructuredInputReplayException("presentation-authority-unavailable");
        }

        AttachmentRecoveryReplayLease? presentation = null;
        try
        {
            presentation = await _presentationLeases.AcquireRecoveryReplayLeaseAsync(
                    operation.PresentationLeaseId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(
                    presentation.OperationId,
                    operation.OperationId,
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    presentation.PayloadDigest,
                    operation.PayloadDigest,
                    StringComparison.Ordinal) ||
                presentation.Generation != reference.Generation ||
                !presentation.Items.Select(static item => item.ContentId).SequenceEqual(
                    operation.AttachmentContentIds,
                    StringComparer.Ordinal) ||
                canonical.AttachmentPaths.Count != presentation.Items.Count)
            {
                throw new RecoveryStructuredInputReplayException("presentation-identity-mismatch");
            }

            for (var index = 0; index < presentation.Items.Count; index++)
            {
                var item = presentation.Items[index];
                if (item.Order != index ||
                    !string.Equals(item.OwnerInputKind, "local_image", StringComparison.Ordinal) ||
                    !item.DetectedType.StartsWith("image/", StringComparison.Ordinal) ||
                    !string.Equals(
                        item.PresentationPath,
                        canonical.AttachmentPaths[index],
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new RecoveryStructuredInputReplayException("presentation-item-mismatch");
                }
            }

            var result = new RecoveryStructuredInputReplayLease(canonical, presentation);
            presentation = null;
            return result;
        }
        catch (RecoveryStructuredInputReplayException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                JsonException or ArgumentException or NotSupportedException)
        {
            throw new RecoveryStructuredInputReplayException(
                "presentation-replay-unavailable",
                exception);
        }
        finally
        {
            if (presentation is not null)
            {
                await presentation.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}

internal sealed class RecoveryStructuredInputReplayException : InvalidOperationException
{
    internal RecoveryStructuredInputReplayException(string code, Exception? innerException = null)
        : base("Structured recovery replay authority is unavailable.", innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}
