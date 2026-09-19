using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodexGuardian.Models;

namespace CodexGuardian.Services;

public enum FollowUpOperationState
{
    Prepared,
    Dispatching,
    Retryable,
    Uncertain,
    Confirmed,
    Abandoned
}

public enum FollowUpJournalReadStatus
{
    Missing,
    Healthy,
    RecoveredFromBackup,
    Corrupted,
    UnsupportedSchema
}

public enum FollowUpPayloadSourceKind
{
    LegacyText,
    StructuredPreset,
    WorkflowPreset
}

public sealed record FollowUpOperationRecord(
    string OperationId,
    string ThreadId,
    string MessageId,
    FollowUpTriggerKind Trigger,
    string ExpectedTurnId,
    DateTimeOffset? ScheduledAtUtc,
    string? MessageHash,
    FollowUpOperationState State,
    string ClientMessageId,
    string? NewTurnId,
    string? CompletionTurnId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    int AttemptCount)
{
    public FollowUpPayloadSourceKind SourceKind { get; init; } =
        FollowUpPayloadSourceKind.LegacyText;

    public int? PayloadSchemaVersion { get; init; }

    public string? PayloadDigest { get; init; }

    public IReadOnlyList<string> AttachmentContentIds { get; init; } = [];

    public string? PresentationLeaseId { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ReplayInputDigest { get; init; }
}

public sealed record FollowUpJournalSnapshot(
    FollowUpJournalReadStatus ReadStatus,
    long Generation,
    bool RequiresConservativeRecovery,
    IReadOnlyList<FollowUpOperationRecord> Records);

public sealed record FollowUpJournalPrepareResult(
    FollowUpOperationRecord Record,
    bool Created,
    bool RequiresReconciliation);

public sealed record FollowUpJournalTransitionResult(
    bool Changed,
    FollowUpOperationRecord? Record,
    long Generation);

public sealed class FollowUpOperationJournal
{
    internal const int CurrentSchemaVersion = 2;
    internal const int DefaultMaximumRecords = 4096;
    internal const long DefaultMaximumFileBytes = 4 * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly int _maximumRecords;
    private readonly long _maximumFileBytes;
    private readonly List<FollowUpOperationRecord> _records = [];
    private bool _loaded;
    private bool _requiresConservativeRecovery;
    private bool _unsupportedSchema;
    private long _generation;
    private FollowUpJournalReadStatus _readStatus = FollowUpJournalReadStatus.Missing;

    public FollowUpOperationJournal(
        string dataDirectory,
        int maximumRecords = DefaultMaximumRecords,
        long maximumFileBytes = DefaultMaximumFileBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        if (maximumRecords < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        if (maximumFileBytes < 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFileBytes));
        }

        DataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        JournalPath = Path.Combine(DataDirectory, "follow-up-operations.json");
        BackupPath = Path.Combine(DataDirectory, "follow-up-operations.previous.json");
        InitializationMarkerPath = Path.Combine(DataDirectory, "follow-up-operations.initialized");
        _maximumRecords = maximumRecords;
        _maximumFileBytes = maximumFileBytes;
    }

    public string DataDirectory { get; }

    public string JournalPath { get; }

    public string BackupPath { get; }

    public string InitializationMarkerPath { get; }

    public async Task<FollowUpJournalSnapshot> ReadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return CreateSnapshot();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<FollowUpOperationRecord>> FindByMessageAsync(
        string threadId,
        string messageId,
        CancellationToken cancellationToken = default)
    {
        threadId = NormalizeRequiredId(threadId, nameof(threadId));
        messageId = NormalizeRequiredId(messageId, nameof(messageId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return _records
                .Where(record =>
                    string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(record.MessageId, messageId, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(record => record.UpdatedAt)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<FollowUpJournalPrepareResult> GetOrCreateAsync(
        string operationId,
        string threadId,
        string messageId,
        FollowUpTriggerKind trigger,
        string expectedTurnId,
        DateTimeOffset? scheduledAtUtc,
        string messageHash,
        string clientMessageId,
        CancellationToken cancellationToken = default)
    {
        var normalized = NormalizeNewRecord(
            operationId,
            threadId,
            messageId,
            trigger,
            expectedTurnId,
            scheduledAtUtc,
            messageHash,
            clientMessageId);
        return await GetOrCreateNormalizedAsync(normalized, cancellationToken).ConfigureAwait(false);
    }

    public async Task<FollowUpJournalPrepareResult> GetOrCreateStructuredAsync(
        string operationId,
        string threadId,
        string messageId,
        FollowUpTriggerKind trigger,
        string expectedTurnId,
        DateTimeOffset? scheduledAtUtc,
        StructuredPresetPayload payload,
        string? presentationLeaseId,
        FollowUpPayloadSourceKind sourceKind,
        string clientMessageId,
        CancellationToken cancellationToken = default,
        string? replayInputDigest = null)
    {
        var normalized = NormalizeStructuredRecord(
            operationId,
            threadId,
            messageId,
            trigger,
            expectedTurnId,
            scheduledAtUtc,
            payload,
            presentationLeaseId,
            sourceKind,
            clientMessageId,
            replayInputDigest);
        return await GetOrCreateNormalizedAsync(normalized, cancellationToken).ConfigureAwait(false);
    }

    private async Task<FollowUpJournalPrepareResult> GetOrCreateNormalizedAsync(
        FollowUpOperationRecord normalized,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();

            var existing = FindCore(normalized.OperationId);
            if (existing is not null)
            {
                EnsureSameOperationIdentity(existing, normalized);
                if (!HasSameSemanticInputs(existing, normalized))
                {
                    if (existing.State is not FollowUpOperationState.Prepared and not
                        FollowUpOperationState.Retryable)
                    {
                        throw new InvalidOperationException(
                            "A dispatched or terminal follow-up operation cannot be replaced with different inputs.");
                    }

                    var replacement = CreateInitialRecord(normalized, DateTimeOffset.UtcNow);
                    var replacementCandidate = new List<FollowUpOperationRecord>(_records);
                    replacementCandidate[FindIndex(existing.OperationId)] = replacement;
                    var replacementPersisted = await PersistCandidateAsync(
                            replacementCandidate,
                            cancellationToken)
                        .ConfigureAwait(false);
                    Commit(replacementPersisted);
                    return new(
                        replacement,
                        Created: true,
                        RequiresReconciliation: replacement.State == FollowUpOperationState.Uncertain);
                }

                return new(
                    existing,
                    Created: false,
                    RequiresReconciliation: existing.State is
                        FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain);
            }

            var blocking = _records
                .Select((record, index) => (record, index))
                .Where(candidate =>
                    string.Equals(
                        candidate.record.ThreadId,
                        normalized.ThreadId,
                        StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(
                        candidate.record.MessageId,
                        normalized.MessageId,
                        StringComparison.OrdinalIgnoreCase) &&
                    candidate.record.State != FollowUpOperationState.Abandoned)
                .ToArray();
            if (blocking.Any(candidate =>
                    string.Equals(
                        candidate.record.ExpectedTurnId,
                        normalized.ExpectedTurnId,
                        StringComparison.OrdinalIgnoreCase) ||
                    candidate.record.State is not FollowUpOperationState.Prepared and not
                        FollowUpOperationState.Retryable))
            {
                throw new InvalidOperationException(
                    "The follow-up message already has a non-replaceable durable operation.");
            }

            var now = DateTimeOffset.UtcNow;
            var record = CreateInitialRecord(normalized, now);
            var candidate = new List<FollowUpOperationRecord>(_records);
            foreach (var stale in blocking)
            {
                candidate[stale.index] = stale.record with
                {
                    State = FollowUpOperationState.Abandoned,
                    UpdatedAt = now
                };
            }

            candidate.Add(record);
            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return new(
                record,
                Created: true,
                RequiresReconciliation: record.State == FollowUpOperationState.Uncertain);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<FollowUpJournalTransitionResult> TryTransitionAsync(
        string operationId,
        FollowUpOperationState expectedState,
        FollowUpOperationState nextState,
        string? newTurnId = null,
        CancellationToken cancellationToken = default)
    {
        operationId = NormalizeRequiredId(operationId, nameof(operationId));
        newTurnId = NormalizeOptionalId(newTurnId, nameof(newTurnId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var index = FindIndex(operationId);
            if (index < 0 || _records[index].State != expectedState)
            {
                return new(false, index < 0 ? null : _records[index], _generation);
            }

            var current = _records[index];
            ValidateTransition(current, nextState, newTurnId);
            var effectiveNewTurnId = MergeStableId(current.NewTurnId, newTurnId, nameof(newTurnId));
            var updated = current with
            {
                State = nextState,
                NewTurnId = effectiveNewTurnId,
                UpdatedAt = DateTimeOffset.UtcNow,
                AttemptCount = nextState == FollowUpOperationState.Dispatching
                    ? checked(current.AttemptCount + 1)
                    : current.AttemptCount
            };
            var candidate = new List<FollowUpOperationRecord>(_records);
            candidate[index] = updated;
            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return new(true, updated, _generation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<FollowUpOperationRecord?> MarkCompletedAsync(
        string threadId,
        string completedTurnId,
        string? recoveredFromTurnId,
        CancellationToken cancellationToken = default)
    {
        threadId = NormalizeRequiredId(threadId, nameof(threadId));
        completedTurnId = NormalizeRequiredId(completedTurnId, nameof(completedTurnId));
        recoveredFromTurnId = NormalizeOptionalId(recoveredFromTurnId, nameof(recoveredFromTurnId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var matches = _records
                .Select((record, index) => (record, index))
                .Where(candidate =>
                    candidate.record.State == FollowUpOperationState.Confirmed &&
                    string.Equals(candidate.record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) &&
                    (string.Equals(
                         candidate.record.NewTurnId,
                         completedTurnId,
                         StringComparison.OrdinalIgnoreCase) ||
                     recoveredFromTurnId is not null && string.Equals(
                         candidate.record.NewTurnId,
                         recoveredFromTurnId,
                         StringComparison.OrdinalIgnoreCase)))
                .ToArray();
            if (matches.Length > 1)
            {
                throw new InvalidOperationException(
                    "A normal completion matches more than one confirmed follow-up operation.");
            }

            if (matches.Length == 0)
            {
                return null;
            }

            var match = matches[0];
            if (match.record.CompletionTurnId is not null)
            {
                if (!string.Equals(
                        match.record.CompletionTurnId,
                        completedTurnId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "A confirmed follow-up completion turn cannot be changed.");
                }

                return match.record;
            }

            var updated = match.record with
            {
                CompletionTurnId = completedTurnId,
                UpdatedAt = DateTimeOffset.UtcNow
            };
            var candidate = new List<FollowUpOperationRecord>(_records);
            candidate[match.index] = updated;
            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return updated;
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<int> PruneInactiveCompletedAsync(
        IReadOnlyDictionary<string, ThreadFollowUpSettings> configured,
        CancellationToken cancellationToken = default) =>
        PruneInactiveCompletedAsync(
            configured,
            Array.Empty<string>(),
            cancellationToken);

    internal async Task<int> PruneInactiveCompletedAsync(
        IReadOnlyDictionary<string, ThreadFollowUpSettings> configured,
        IReadOnlyCollection<string> protectedOperationIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configured);
        ArgumentNullException.ThrowIfNull(protectedOperationIds);
        var protectedOperations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var operationId in protectedOperationIds)
        {
            if (!Guid.TryParseExact(operationId, "D", out var parsedOperationId))
            {
                throw new ArgumentException(
                    "Presentation prune protection contains an invalid operation identity.",
                    nameof(protectedOperationIds));
            }

            protectedOperations.Add(parsedOperationId.ToString("D"));
        }

        var configuredMessages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in configured)
        {
            if (!Guid.TryParse(pair.Key, out var parsedThreadId) || pair.Value is null)
            {
                throw new ArgumentException(
                    "The current follow-up configuration contains an invalid task identity.",
                    nameof(configured));
            }

            var threadId = parsedThreadId.ToString("D");
            foreach (var message in pair.Value.Messages ?? [])
            {
                if (message is null || !Guid.TryParse(message.Id, out var parsedMessageId))
                {
                    throw new ArgumentException(
                        "The current follow-up configuration contains an invalid message identity.",
                        nameof(configured));
                }

                configuredMessages.Add(CreateMessageKey(threadId, parsedMessageId.ToString("D")));
            }
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var candidate = _records
                .Where(record =>
                    protectedOperations.Contains(record.OperationId) ||
                    record.State != FollowUpOperationState.Abandoned &&
                    !(record.State == FollowUpOperationState.Confirmed &&
                      record.CompletionTurnId is not null &&
                      !configuredMessages.Contains(CreateMessageKey(
                          record.ThreadId,
                          record.MessageId))))
                .ToList();
            var removed = _records.Count - candidate.Count;
            if (removed == 0)
            {
                return 0;
            }

            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return removed;
        }
        finally
        {
            _gate.Release();
        }
    }

    public static string ComputeMessageHash(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(message)));
    }

    public static string CreateOperationId(string threadId, string messageId, string expectedTurnId)
        => CreateDeterministicId($"codex-guardian-follow-up|operation|{threadId}|{messageId}|{expectedTurnId}");

    public static string CreateStructuredOperationId(
        string threadId,
        string messageId,
        string expectedTurnId,
        string payloadDigest)
    {
        payloadDigest = NormalizeHash(payloadDigest);
        return CreateDeterministicId(
            $"codex-guardian-follow-up|structured-operation|{threadId}|{messageId}|{expectedTurnId}|{payloadDigest}");
    }

    public static string CreateClientMessageId(string operationId)
        => CreateDeterministicId($"codex-guardian-follow-up|client-message|{operationId}");

    private async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_loaded)
        {
            return;
        }

        _loaded = true;
        DataDirectorySafety.Revalidate(DataDirectory);
        CleanupTemporaryFiles();
        try
        {
            var primary = await TryReadDocumentAsync(JournalPath, cancellationToken).ConfigureAwait(false);
            if (primary.Status == FollowUpJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (primary.Status == FollowUpJournalReadStatus.Healthy)
            {
                LoadDocument(primary.Document!, FollowUpJournalReadStatus.Healthy, promotePending: false);
                return;
            }

            var backup = await TryReadDocumentAsync(BackupPath, cancellationToken).ConfigureAwait(false);
            if (backup.Status == FollowUpJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (backup.Status == FollowUpJournalReadStatus.Healthy)
            {
                LoadDocument(
                    backup.Document!,
                    FollowUpJournalReadStatus.RecoveredFromBackup,
                    promotePending: true);
                return;
            }

            if (primary.Status == FollowUpJournalReadStatus.Missing &&
                backup.Status == FollowUpJournalReadStatus.Missing &&
                !File.Exists(InitializationMarkerPath))
            {
                _readStatus = FollowUpJournalReadStatus.Missing;
                return;
            }

            MarkCorrupted();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _loaded = false;
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            MarkCorrupted();
        }
    }

    private async Task<JournalLoadResult> TryReadDocumentAsync(
        string path,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (!File.Exists(path))
        {
            return new(FollowUpJournalReadStatus.Missing, null);
        }

        try
        {
            var file = new FileInfo(path);
            if (file.Length <= 0 || file.Length > _maximumFileBytes)
            {
                return new(FollowUpJournalReadStatus.Corrupted, null);
            }

            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (json.RootElement.ValueKind != JsonValueKind.Object ||
                !json.RootElement.TryGetProperty("schemaVersion", out var schemaElement) ||
                schemaElement.ValueKind != JsonValueKind.Number ||
                !schemaElement.TryGetInt32(out var schemaVersion))
            {
                return new(FollowUpJournalReadStatus.Corrupted, null);
            }

            if (schemaVersion == 1)
            {
                var legacy = json.RootElement.Deserialize<LegacyJournalDocument>(JsonOptions);
                if (legacy is null || !ValidateLegacyDocument(legacy))
                {
                    return new(FollowUpJournalReadStatus.Corrupted, null);
                }

                return new(
                    FollowUpJournalReadStatus.Healthy,
                    MigrateLegacyDocument(legacy));
            }

            if (schemaVersion != CurrentSchemaVersion)
            {
                return new(FollowUpJournalReadStatus.UnsupportedSchema, null);
            }

            var document = json.RootElement.Deserialize<JournalDocument>(JsonOptions);
            return document is not null && ValidateDocument(document)
                ? new(FollowUpJournalReadStatus.Healthy, document)
                : new(FollowUpJournalReadStatus.Corrupted, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new(FollowUpJournalReadStatus.Corrupted, null);
        }
    }

    private void LoadDocument(
        JournalDocument document,
        FollowUpJournalReadStatus status,
        bool promotePending)
    {
        var records = document.Records!;
        if (promotePending)
        {
            var now = DateTimeOffset.UtcNow;
            records = records.Select(record => record.State is
                    FollowUpOperationState.Prepared or FollowUpOperationState.Dispatching or
                    FollowUpOperationState.Retryable
                    ? record with { State = FollowUpOperationState.Uncertain, UpdatedAt = now }
                    : record)
                .ToList();
        }

        _records.AddRange(records);
        _generation = document.Generation;
        _requiresConservativeRecovery = document.RequiresConservativeRecovery;
        _readStatus = status;
    }

    private bool ValidateDocument(JournalDocument document)
    {
        if (document.Generation < 0 || document.Records is null ||
            document.Records.Count > _maximumRecords || string.IsNullOrWhiteSpace(document.Checksum))
        {
            return false;
        }

        var operationIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in document.Records)
        {
            if (!ValidateRecord(record) || !operationIds.Add(record.OperationId))
            {
                return false;
            }
        }

        var expected = ComputeChecksum(
            document.SchemaVersion,
            document.Generation,
            document.RequiresConservativeRecovery,
            document.Records);
        return IsSha256(document.Checksum) && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(document.Checksum));
    }

    private bool ValidateLegacyDocument(LegacyJournalDocument document)
    {
        if (document.SchemaVersion != 1 ||
            document.Generation < 0 ||
            document.Records is null ||
            document.Records.Count > _maximumRecords ||
            string.IsNullOrWhiteSpace(document.Checksum))
        {
            return false;
        }

        var operationIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in document.Records)
        {
            if (!ValidateLegacyRecord(record) || !operationIds.Add(record.OperationId))
            {
                return false;
            }
        }

        var expected = ComputeLegacyChecksum(
            document.SchemaVersion,
            document.Generation,
            document.RequiresConservativeRecovery,
            document.Records);
        return IsSha256(document.Checksum) && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(document.Checksum));
    }

    private static JournalDocument MigrateLegacyDocument(LegacyJournalDocument document)
    {
        var now = DateTimeOffset.UtcNow;
        var records = document.Records!
            .Select(record => new FollowUpOperationRecord(
                record.OperationId,
                record.ThreadId,
                record.MessageId,
                record.Trigger,
                record.ExpectedTurnId,
                record.ScheduledAtUtc,
                record.MessageHash,
                record.State == FollowUpOperationState.Dispatching
                    ? FollowUpOperationState.Uncertain
                    : record.State,
                record.ClientMessageId,
                record.NewTurnId,
                record.CompletionTurnId,
                record.CreatedAt,
                record.State == FollowUpOperationState.Dispatching ? now : record.UpdatedAt,
                record.AttemptCount)
            {
                SourceKind = FollowUpPayloadSourceKind.LegacyText,
                PayloadSchemaVersion = null,
                PayloadDigest = null,
                AttachmentContentIds = [],
                PresentationLeaseId = null,
                ReplayInputDigest = null
            })
            .ToList();
        return new JournalDocument(
            CurrentSchemaVersion,
            document.Generation,
            document.RequiresConservativeRecovery,
            ComputeChecksum(
                CurrentSchemaVersion,
                document.Generation,
                document.RequiresConservativeRecovery,
                records),
            records);
    }

    private async Task<PersistedCandidate> PersistCandidateAsync(
        List<FollowUpOperationRecord> candidate,
        CancellationToken cancellationToken)
    {
        var nextGeneration = checked(_generation + 1);
        PruneTerminalRecordsByCount(candidate);
        byte[] bytes;
        while (true)
        {
            bytes = SerializeDocument(nextGeneration, candidate);
            if (bytes.LongLength <= _maximumFileBytes)
            {
                break;
            }

            var terminalIndex = FindOldestTerminalIndex(candidate);
            if (terminalIndex < 0)
            {
                throw new InvalidOperationException(
                    "The follow-up journal contains too many pending operations for its disk limit.");
            }

            candidate.RemoveAt(terminalIndex);
        }

        DataDirectorySafety.Revalidate(DataDirectory);
        Directory.CreateDirectory(DataDirectory);
        DataDirectorySafety.Revalidate(DataDirectory);
        EnsureInitializationMarker();
        var tempPath = Path.Combine(
            DataDirectory,
            $".{Path.GetFileName(JournalPath)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        try
        {
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            await using (var stream = new FileStream(
                             tempPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, JournalPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, BackupPath);
            if (File.Exists(JournalPath))
            {
                File.Replace(
                    tempPath,
                    JournalPath,
                    _readStatus == FollowUpJournalReadStatus.Healthy ? BackupPath : null,
                    ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, JournalPath);
            }

            return new(candidate, nextGeneration);
        }
        finally
        {
            TryDeleteTemporaryFile(tempPath);
        }
    }

    private byte[] SerializeDocument(long generation, IReadOnlyList<FollowUpOperationRecord> records)
    {
        var checksum = ComputeChecksum(
            CurrentSchemaVersion,
            generation,
            _requiresConservativeRecovery,
            records);
        return JsonSerializer.SerializeToUtf8Bytes(
            new JournalDocument(
                CurrentSchemaVersion,
                generation,
                _requiresConservativeRecovery,
                checksum,
                records.ToList()),
            JsonOptions);
    }

    private void EnsureInitializationMarker()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, InitializationMarkerPath);
        if (File.Exists(InitializationMarkerPath))
        {
            return;
        }

        var tempPath = Path.Combine(
            DataDirectory,
            $".{Path.GetFileName(InitializationMarkerPath)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        try
        {
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            using (var stream = new FileStream(
                       tempPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       128,
                       FileOptions.WriteThrough))
            {
                stream.Write("schema=2\n"u8);
                stream.Flush(flushToDisk: true);
            }

            try
            {
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, InitializationMarkerPath);
                File.Move(tempPath, InitializationMarkerPath);
            }
            catch (IOException) when (File.Exists(InitializationMarkerPath))
            {
            }
        }
        finally
        {
            TryDeleteTemporaryFile(tempPath);
        }
    }

    private void CleanupTemporaryFiles()
    {
        if (!Directory.Exists(DataDirectory))
        {
            return;
        }

        try
        {
            var patterns = new[]
            {
                $".{Path.GetFileName(JournalPath)}.*.tmp",
                $".{Path.GetFileName(InitializationMarkerPath)}.*.tmp"
            };
            foreach (var path in patterns.SelectMany(pattern =>
                         Directory.EnumerateFiles(DataDirectory, pattern, SearchOption.TopDirectoryOnly)))
            {
                TryDeleteTemporaryFile(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private void TryDeleteTemporaryFile(string path)
    {
        try
        {
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void ValidateTransition(
        FollowUpOperationRecord current,
        FollowUpOperationState nextState,
        string? newTurnId)
    {
        if (current.State == nextState)
        {
            throw new InvalidOperationException("A follow-up journal transition must change state.");
        }

        var allowed = current.State switch
        {
            FollowUpOperationState.Prepared =>
                nextState is FollowUpOperationState.Dispatching or FollowUpOperationState.Abandoned,
            FollowUpOperationState.Dispatching =>
                nextState is FollowUpOperationState.Retryable or FollowUpOperationState.Uncertain or
                    FollowUpOperationState.Confirmed or FollowUpOperationState.Abandoned,
            FollowUpOperationState.Retryable =>
                nextState is FollowUpOperationState.Dispatching or FollowUpOperationState.Abandoned,
            FollowUpOperationState.Uncertain =>
                nextState is FollowUpOperationState.Confirmed or FollowUpOperationState.Abandoned,
            _ => false
        };
        if (!allowed)
        {
            throw new InvalidOperationException(
                $"Follow-up journal transition {current.State} -> {nextState} is not allowed.");
        }

        if (nextState == FollowUpOperationState.Confirmed &&
            string.IsNullOrWhiteSpace(newTurnId) && string.IsNullOrWhiteSpace(current.NewTurnId))
        {
            throw new InvalidOperationException("A confirmed follow-up operation must identify its committed turn.");
        }
    }

    private static FollowUpOperationRecord NormalizeNewRecord(
        string operationId,
        string threadId,
        string messageId,
        FollowUpTriggerKind trigger,
        string expectedTurnId,
        DateTimeOffset? scheduledAtUtc,
        string messageHash,
        string clientMessageId)
    {
        if (!Enum.IsDefined(trigger))
        {
            throw new ArgumentOutOfRangeException(nameof(trigger));
        }

        operationId = NormalizeRequiredId(operationId, nameof(operationId));
        threadId = NormalizeRequiredId(threadId, nameof(threadId));
        messageId = NormalizeRequiredId(messageId, nameof(messageId));
        expectedTurnId = NormalizeRequiredId(expectedTurnId, nameof(expectedTurnId));
        clientMessageId = NormalizeRequiredId(clientMessageId, nameof(clientMessageId));
        messageHash = NormalizeHash(messageHash);
        scheduledAtUtc = scheduledAtUtc?.ToUniversalTime();
        if (trigger == FollowUpTriggerKind.ScheduledAt && scheduledAtUtc is null ||
            trigger == FollowUpTriggerKind.AfterNormalCompletion && scheduledAtUtc is not null)
        {
            throw new ArgumentException("The follow-up trigger and schedule are inconsistent.", nameof(scheduledAtUtc));
        }

        return new FollowUpOperationRecord(
            operationId,
            threadId,
            messageId,
            trigger,
            expectedTurnId,
            scheduledAtUtc,
            messageHash,
            FollowUpOperationState.Prepared,
            clientMessageId,
            NewTurnId: null,
            CompletionTurnId: null,
            CreatedAt: default,
            UpdatedAt: default,
            AttemptCount: 0)
        {
            SourceKind = FollowUpPayloadSourceKind.LegacyText,
            PayloadSchemaVersion = null,
            PayloadDigest = null,
            AttachmentContentIds = [],
            PresentationLeaseId = null,
            ReplayInputDigest = null
        };
    }

    private static FollowUpOperationRecord NormalizeStructuredRecord(
        string operationId,
        string threadId,
        string messageId,
        FollowUpTriggerKind trigger,
        string expectedTurnId,
        DateTimeOffset? scheduledAtUtc,
        StructuredPresetPayload payload,
        string? presentationLeaseId,
        FollowUpPayloadSourceKind sourceKind,
        string clientMessageId,
        string? replayInputDigest)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.HasValidIdentity())
        {
            throw new ArgumentException("A canonical structured payload is required.", nameof(payload));
        }

        if (sourceKind is not FollowUpPayloadSourceKind.StructuredPreset and not
            FollowUpPayloadSourceKind.WorkflowPreset)
        {
            throw new ArgumentOutOfRangeException(nameof(sourceKind));
        }

        if (!Enum.IsDefined(trigger))
        {
            throw new ArgumentOutOfRangeException(nameof(trigger));
        }

        operationId = NormalizeRequiredId(operationId, nameof(operationId));
        threadId = NormalizeRequiredId(threadId, nameof(threadId));
        messageId = NormalizeRequiredId(messageId, nameof(messageId));
        expectedTurnId = NormalizeRequiredId(expectedTurnId, nameof(expectedTurnId));
        clientMessageId = NormalizeRequiredId(clientMessageId, nameof(clientMessageId));
        scheduledAtUtc = scheduledAtUtc?.ToUniversalTime();
        if (trigger == FollowUpTriggerKind.ScheduledAt && scheduledAtUtc is null ||
            trigger == FollowUpTriggerKind.AfterNormalCompletion && scheduledAtUtc is not null)
        {
            throw new ArgumentException(
                "The follow-up trigger and schedule are inconsistent.",
                nameof(scheduledAtUtc));
        }

        var contentIds = payload.Attachments
            .Select(reference => reference.ContentId)
            .ToArray();
        presentationLeaseId = NormalizeOptionalLeaseId(presentationLeaseId);
        replayInputDigest = string.IsNullOrWhiteSpace(replayInputDigest)
            ? null
            : NormalizeHash(replayInputDigest);
        if (contentIds.Length == 0 && presentationLeaseId is not null ||
            contentIds.Length > 0 && presentationLeaseId is null)
        {
            throw new ArgumentException(
                "Structured attachment content and presentation lease identity are inconsistent.",
                nameof(presentationLeaseId));
        }

        return new FollowUpOperationRecord(
            operationId,
            threadId,
            messageId,
            trigger,
            expectedTurnId,
            scheduledAtUtc,
            MessageHash: null,
            FollowUpOperationState.Prepared,
            clientMessageId,
            NewTurnId: null,
            CompletionTurnId: null,
            CreatedAt: default,
            UpdatedAt: default,
            AttemptCount: 0)
        {
            SourceKind = sourceKind,
            PayloadSchemaVersion = payload.SchemaVersion,
            PayloadDigest = payload.PayloadDigest,
            AttachmentContentIds = Array.AsReadOnly(contentIds),
            PresentationLeaseId = presentationLeaseId,
            ReplayInputDigest = replayInputDigest
        };
    }

    private static bool ValidateRecord(FollowUpOperationRecord record)
    {
        if (record is null ||
            !Guid.TryParseExact(record.OperationId, "D", out _) ||
            !Guid.TryParseExact(record.ThreadId, "D", out _) ||
            !Guid.TryParseExact(record.MessageId, "D", out _) ||
            !Guid.TryParseExact(record.ExpectedTurnId, "D", out _) ||
            !Guid.TryParseExact(record.ClientMessageId, "D", out _) ||
            record.NewTurnId is not null && !Guid.TryParseExact(record.NewTurnId, "D", out _) ||
            record.CompletionTurnId is not null && !Guid.TryParseExact(record.CompletionTurnId, "D", out _) ||
            !Enum.IsDefined(record.Trigger) || !Enum.IsDefined(record.State) ||
            !Enum.IsDefined(record.SourceKind) ||
            record.AttachmentContentIds is null ||
            record.AttemptCount < 0 ||
            record.CreatedAt == default || record.UpdatedAt < record.CreatedAt)
        {
            return false;
        }

        if (record.Trigger == FollowUpTriggerKind.ScheduledAt && record.ScheduledAtUtc is null ||
            record.Trigger == FollowUpTriggerKind.AfterNormalCompletion && record.ScheduledAtUtc is not null)
        {
            return false;
        }

        return ValidatePayloadIdentity(record) &&
               (record.State != FollowUpOperationState.Confirmed || record.NewTurnId is not null) &&
               (record.CompletionTurnId is null || record.State == FollowUpOperationState.Confirmed);
    }

    private static bool ValidatePayloadIdentity(FollowUpOperationRecord record)
    {
        if (record.SourceKind == FollowUpPayloadSourceKind.LegacyText)
        {
            return IsSha256(record.MessageHash) &&
                   record.PayloadSchemaVersion is null &&
                   record.PayloadDigest is null &&
                   record.AttachmentContentIds.Count == 0 &&
                   record.PresentationLeaseId is null &&
                   record.ReplayInputDigest is null;
        }

        if (record.SourceKind is not FollowUpPayloadSourceKind.StructuredPreset and not
            FollowUpPayloadSourceKind.WorkflowPreset ||
            record.MessageHash is not null ||
            record.PayloadSchemaVersion != StructuredPresetPayload.CurrentSchemaVersion ||
            !IsSha256(record.PayloadDigest) ||
            record.AttachmentContentIds.Count > 20 ||
            record.AttachmentContentIds.Any(contentId =>
                !AttachmentIdentity.IsCanonicalContentId(contentId)) ||
            record.ReplayInputDigest is not null && !IsSha256(record.ReplayInputDigest))
        {
            return false;
        }

        return record.AttachmentContentIds.Count == 0
            ? record.PresentationLeaseId is null
            : IsPresentationLeaseId(record.PresentationLeaseId);
    }

    private static bool ValidateLegacyRecord(LegacyFollowUpOperationRecord record)
    {
        if (record is null ||
            !Guid.TryParseExact(record.OperationId, "D", out _) ||
            !Guid.TryParseExact(record.ThreadId, "D", out _) ||
            !Guid.TryParseExact(record.MessageId, "D", out _) ||
            !Guid.TryParseExact(record.ExpectedTurnId, "D", out _) ||
            !Guid.TryParseExact(record.ClientMessageId, "D", out _) ||
            record.NewTurnId is not null && !Guid.TryParseExact(record.NewTurnId, "D", out _) ||
            record.CompletionTurnId is not null &&
            !Guid.TryParseExact(record.CompletionTurnId, "D", out _) ||
            !Enum.IsDefined(record.Trigger) ||
            !Enum.IsDefined(record.State) ||
            !IsSha256(record.MessageHash) ||
            record.AttemptCount < 0 ||
            record.CreatedAt == default ||
            record.UpdatedAt < record.CreatedAt)
        {
            return false;
        }

        if (record.Trigger == FollowUpTriggerKind.ScheduledAt && record.ScheduledAtUtc is null ||
            record.Trigger == FollowUpTriggerKind.AfterNormalCompletion &&
            record.ScheduledAtUtc is not null)
        {
            return false;
        }

        return (record.State != FollowUpOperationState.Confirmed || record.NewTurnId is not null) &&
               (record.CompletionTurnId is null || record.State == FollowUpOperationState.Confirmed);
    }

    private void EnsureSameOperationIdentity(
        FollowUpOperationRecord existing,
        FollowUpOperationRecord requested)
    {
        if (!string.Equals(existing.ThreadId, requested.ThreadId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.MessageId, requested.MessageId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.ExpectedTurnId, requested.ExpectedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.ClientMessageId, requested.ClientMessageId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The follow-up operation id belongs to a different identity.");
        }

        if (existing.SourceKind != requested.SourceKind)
        {
            throw new InvalidOperationException(
                "The follow-up operation id belongs to a different payload source kind.");
        }

        if (requested.SourceKind != FollowUpPayloadSourceKind.LegacyText &&
            (existing.PayloadSchemaVersion != requested.PayloadSchemaVersion ||
             !string.Equals(existing.PayloadDigest, requested.PayloadDigest, StringComparison.Ordinal) ||
             !existing.AttachmentContentIds.SequenceEqual(
                 requested.AttachmentContentIds,
                 StringComparer.Ordinal) ||
              !string.Equals(
                  existing.PresentationLeaseId,
                  requested.PresentationLeaseId,
                  StringComparison.Ordinal) ||
              !string.Equals(
                  existing.ReplayInputDigest,
                  requested.ReplayInputDigest,
                  StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                "The structured follow-up operation id belongs to a different payload identity.");
        }
    }

    private static bool HasSameSemanticInputs(
        FollowUpOperationRecord existing,
        FollowUpOperationRecord requested) =>
        (requested.SourceKind == FollowUpPayloadSourceKind.LegacyText
            ? string.Equals(existing.MessageHash, requested.MessageHash, StringComparison.Ordinal)
            : existing.PayloadSchemaVersion == requested.PayloadSchemaVersion &&
              string.Equals(existing.PayloadDigest, requested.PayloadDigest, StringComparison.Ordinal) &&
              existing.AttachmentContentIds.SequenceEqual(
                  requested.AttachmentContentIds,
                  StringComparer.Ordinal) &&
               string.Equals(
                   existing.PresentationLeaseId,
                   requested.PresentationLeaseId,
                   StringComparison.Ordinal) &&
               string.Equals(
                   existing.ReplayInputDigest,
                   requested.ReplayInputDigest,
                   StringComparison.Ordinal)) &&
        existing.Trigger == requested.Trigger &&
        existing.ScheduledAtUtc == requested.ScheduledAtUtc;

    private FollowUpOperationRecord CreateInitialRecord(
        FollowUpOperationRecord normalized,
        DateTimeOffset now) => normalized with
    {
        State = _requiresConservativeRecovery
            ? FollowUpOperationState.Uncertain
            : FollowUpOperationState.Prepared,
        NewTurnId = null,
        CompletionTurnId = null,
        CreatedAt = now,
        UpdatedAt = now,
        AttemptCount = 0
    };

    private static string CreateMessageKey(string threadId, string messageId) =>
        threadId + "|" + messageId;

    private static string CreateDeterministicId(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value))[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes).ToString("D");
    }

    private static string ComputeChecksum(
        int schemaVersion,
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<FollowUpOperationRecord> records)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new JournalIntegrityPayload(schemaVersion, generation, requiresConservativeRecovery, records),
            JsonOptions);
        return Convert.ToHexString(SHA256.HashData(payload));
    }

    private static string ComputeLegacyChecksum(
        int schemaVersion,
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<LegacyFollowUpOperationRecord> records)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new LegacyJournalIntegrityPayload(
                schemaVersion,
                generation,
                requiresConservativeRecovery,
                records),
            JsonOptions);
        return Convert.ToHexString(SHA256.HashData(payload));
    }

    private void PruneTerminalRecordsByCount(List<FollowUpOperationRecord> candidate)
    {
        while (candidate.Count > _maximumRecords)
        {
            var index = FindOldestTerminalIndex(candidate);
            if (index < 0)
            {
                throw new InvalidOperationException(
                    "The follow-up journal contains more pending operations than its record limit permits.");
            }

            candidate.RemoveAt(index);
        }
    }

    private static int FindOldestTerminalIndex(IReadOnlyList<FollowUpOperationRecord> records)
    {
        var selected = -1;
        for (var index = 0; index < records.Count; index++)
        {
            if (records[index].State != FollowUpOperationState.Abandoned)
            {
                continue;
            }

            if (selected < 0 || records[index].UpdatedAt < records[selected].UpdatedAt)
            {
                selected = index;
            }
        }

        return selected;
    }

    private FollowUpOperationRecord? FindCore(string operationId)
    {
        var index = FindIndex(operationId);
        return index < 0 ? null : _records[index];
    }

    private int FindIndex(string operationId)
    {
        for (var index = 0; index < _records.Count; index++)
        {
            if (string.Equals(_records[index].OperationId, operationId, StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return -1;
    }

    private FollowUpJournalSnapshot CreateSnapshot() => new(
        _readStatus,
        _generation,
        _requiresConservativeRecovery,
        _records.ToArray());

    private void Commit(PersistedCandidate persisted)
    {
        _records.Clear();
        _records.AddRange(persisted.Records);
        _generation = persisted.Generation;
        _readStatus = FollowUpJournalReadStatus.Healthy;
    }

    private void MarkCorrupted()
    {
        _records.Clear();
        _requiresConservativeRecovery = true;
        _readStatus = FollowUpJournalReadStatus.Corrupted;
    }

    private void MarkUnsupportedSchema()
    {
        _records.Clear();
        _requiresConservativeRecovery = true;
        _unsupportedSchema = true;
        _readStatus = FollowUpJournalReadStatus.UnsupportedSchema;
    }

    private void ThrowIfUnsupportedSchema()
    {
        if (_unsupportedSchema)
        {
            throw new NotSupportedException("The follow-up journal schema is newer than this Guardian build.");
        }
    }

    private static string NormalizeRequiredId(string value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed))
        {
            throw new ArgumentException("A UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private static string? NormalizeOptionalId(string? value, string parameterName) =>
        string.IsNullOrWhiteSpace(value) ? null : NormalizeRequiredId(value, parameterName);

    private static string NormalizeHash(string value)
    {
        value = value?.Trim().ToUpperInvariant() ?? string.Empty;
        if (!IsSha256(value))
        {
            throw new ArgumentException("A SHA-256 hash is required.", nameof(value));
        }

        return value;
    }

    private static string? NormalizeOptionalLeaseId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        value = value.Trim().ToUpperInvariant();
        if (!IsPresentationLeaseId(value))
        {
            throw new ArgumentException(
                "A canonical opaque presentation lease id is required.",
                nameof(value));
        }

        return value;
    }

    private static bool IsPresentationLeaseId(string? value) =>
        value is { Length: 32 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static string? MergeStableId(string? existing, string? requested, string parameterName)
    {
        if (existing is not null && requested is not null &&
            !string.Equals(existing, requested, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("A persisted stable id cannot be changed.", parameterName);
        }

        return existing ?? requested;
    }

    private sealed record PersistedCandidate(List<FollowUpOperationRecord> Records, long Generation);

    private sealed record JournalLoadResult(
        FollowUpJournalReadStatus Status,
        JournalDocument? Document);

    private sealed record JournalDocument(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        List<FollowUpOperationRecord>? Records);

    private sealed record JournalIntegrityPayload(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<FollowUpOperationRecord> Records);

    private sealed record LegacyFollowUpOperationRecord(
        string OperationId,
        string ThreadId,
        string MessageId,
        FollowUpTriggerKind Trigger,
        string ExpectedTurnId,
        DateTimeOffset? ScheduledAtUtc,
        string MessageHash,
        FollowUpOperationState State,
        string ClientMessageId,
        string? NewTurnId,
        string? CompletionTurnId,
        DateTimeOffset CreatedAt,
        DateTimeOffset UpdatedAt,
        int AttemptCount);

    private sealed record LegacyJournalDocument(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        List<LegacyFollowUpOperationRecord>? Records);

    private sealed record LegacyJournalIntegrityPayload(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<LegacyFollowUpOperationRecord> Records);
}
