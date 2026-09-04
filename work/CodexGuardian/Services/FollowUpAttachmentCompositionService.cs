using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal sealed record FollowUpAttachmentDraftTarget(
    string ThreadId,
    string MessageId,
    long Version);

internal enum FollowUpAttachmentCompositionStatus
{
    Committed,
    StaleTarget,
    NoAttachments
}

internal sealed record FollowUpAttachmentCompositionResult(
    FollowUpAttachmentDraftTarget Target,
    IReadOnlyList<PresetAttachmentReference> Attachments,
    int ImportedCount,
    FollowUpAttachmentCompositionStatus Status,
    string? Text);

internal sealed record FollowUpAttachmentSaveCandidate(
    int MessageNumber,
    StructuredPresetPayload Payload);

internal enum FollowUpAttachmentSaveCapabilityStatus
{
    Satisfied,
    Waiting,
    Unsupported
}

internal sealed record FollowUpAttachmentSaveCapabilityResult(
    FollowUpAttachmentSaveCapabilityStatus Status,
    int MessageNumber,
    string Code)
{
    internal bool CanSave => Status == FollowUpAttachmentSaveCapabilityStatus.Satisfied;

    internal static FollowUpAttachmentSaveCapabilityResult Satisfied { get; } =
        new(FollowUpAttachmentSaveCapabilityStatus.Satisfied, 0, "supported");

    internal static FollowUpAttachmentSaveCapabilityResult Waiting(
        int messageNumber,
        string code) =>
        new(FollowUpAttachmentSaveCapabilityStatus.Waiting, messageNumber, code);

    internal static FollowUpAttachmentSaveCapabilityResult Unsupported(
        int messageNumber,
        string code) =>
        new(FollowUpAttachmentSaveCapabilityStatus.Unsupported, messageNumber, code);
}

internal delegate Task<bool> TryCommitFollowUpAttachmentsAsync(
    FollowUpAttachmentDraftTarget target,
    IReadOnlyList<PresetAttachmentReference> attachments,
    CancellationToken cancellationToken);

internal sealed class FollowUpAttachmentCompositionService
{
    private const string CleanupRequestFailureDataKey =
        "FollowUpAttachmentCompositionCleanupRequestFailure";

    private readonly AttachmentImportService _importer;
    private readonly AttachmentDraftAuthority _draftAuthority;
    private readonly Func<IReadOnlyList<string>, CancellationToken, Task>
        _requestZeroReferenceCleanupAsync;
    private readonly IDesktopStructuredInputCapabilityProvider? _structuredCapabilities;
    private readonly FollowUpAttachmentSaveAuthorityValidator? _saveAuthorityValidator;

    public FollowUpAttachmentCompositionService(
        AttachmentImportService importer,
        AttachmentDraftAuthority draftAuthority,
        Func<IReadOnlyList<string>, CancellationToken, Task> requestZeroReferenceCleanupAsync,
        IDesktopStructuredInputCapabilityProvider? structuredCapabilities = null,
        FollowUpAttachmentSaveAuthorityValidator? saveAuthorityValidator = null)
    {
        ArgumentNullException.ThrowIfNull(importer);
        ArgumentNullException.ThrowIfNull(draftAuthority);
        ArgumentNullException.ThrowIfNull(requestZeroReferenceCleanupAsync);
        _importer = importer;
        _draftAuthority = draftAuthority;
        _requestZeroReferenceCleanupAsync = requestZeroReferenceCleanupAsync;
        _structuredCapabilities = structuredCapabilities;
        _saveAuthorityValidator = saveAuthorityValidator;
    }

    internal Task<FollowUpAttachmentSaveCapabilityResult> ValidateSaveAsync(
        IReadOnlyList<FollowUpAttachmentSaveCandidate> candidates,
        CancellationToken cancellationToken) =>
        ValidateSaveAsync(settings: null, candidates, cancellationToken);

    internal async Task<FollowUpAttachmentSaveCapabilityResult> ValidateSaveAsync(
        AppSettings? settings,
        IReadOnlyList<FollowUpAttachmentSaveCandidate> candidates,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        cancellationToken.ThrowIfCancellationRequested();
        var attachmentCandidates = new List<FollowUpAttachmentSaveCandidate>(candidates.Count);
        foreach (var candidate in candidates)
        {
            if (candidate is null || candidate.MessageNumber <= 0 || candidate.Payload is null)
            {
                throw new ArgumentException(
                    "Attachment save candidates must identify a message and payload.",
                    nameof(candidates));
            }

            if (candidate.Payload.Attachments.Count > 0)
            {
                attachmentCandidates.Add(candidate);
            }
        }

        if (attachmentCandidates.Count == 0)
        {
            return FollowUpAttachmentSaveCapabilityResult.Satisfied;
        }

        var firstMessageNumber = attachmentCandidates[0].MessageNumber;
        var structuredCapabilities = _structuredCapabilities;
        if (structuredCapabilities is null)
        {
            return FollowUpAttachmentSaveCapabilityResult.Waiting(
                firstMessageNumber,
                "capability-provider-unavailable");
        }

        DesktopStructuredInputCapabilities capabilities;
        try
        {
            // The installed-package provider performs bounded synchronous evidence reads.
            // Keep those reads off the WPF dispatcher while preserving one fresh read per Save.
            capabilities = await Task.Run(
                    async () => await structuredCapabilities
                        .ReadAsync(cancellationToken)
                        .ConfigureAwait(false),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return FollowUpAttachmentSaveCapabilityResult.Waiting(
                firstMessageNumber,
                "capability-read-failed");
        }

        if (capabilities is null)
        {
            return FollowUpAttachmentSaveCapabilityResult.Waiting(
                firstMessageNumber,
                "capability-read-empty");
        }

        foreach (var candidate in attachmentCandidates)
        {
            var requirement = capabilities.Evaluate(candidate.Payload);
            if (requirement.IsSatisfied)
            {
                continue;
            }

            return requirement.Code is "capability-unknown" or "capability-invalid"
                ? FollowUpAttachmentSaveCapabilityResult.Waiting(
                    candidate.MessageNumber,
                    requirement.Code)
                : FollowUpAttachmentSaveCapabilityResult.Unsupported(
                    candidate.MessageNumber,
                    requirement.Code);
        }

        var authorityValidator = _saveAuthorityValidator;
        if (authorityValidator is not null)
        {
            if (settings is null)
            {
                return FollowUpAttachmentSaveCapabilityResult.Waiting(
                    firstMessageNumber,
                    "attachment-authority-settings-unavailable");
            }

            var authority = await authorityValidator
                .ValidateAsync(settings, attachmentCandidates, cancellationToken)
                .ConfigureAwait(false);
            if (!authority.CanSave)
            {
                return authority.Status == FollowUpAttachmentSaveAuthorityStatus.UnsupportedPayload
                    ? FollowUpAttachmentSaveCapabilityResult.Unsupported(
                        authority.MessageNumber,
                        authority.Code)
                    : FollowUpAttachmentSaveCapabilityResult.Waiting(
                        authority.MessageNumber,
                        authority.Code);
            }
        }

        return FollowUpAttachmentSaveCapabilityResult.Satisfied;
    }

    public async Task<FollowUpAttachmentCompositionResult> ComposeFilesAsync(
        FollowUpAttachmentDraftTarget target,
        IReadOnlyList<PresetAttachmentReference> existingAttachments,
        IReadOnlyList<string> sourcePaths,
        AttachmentLimitSettings limits,
        TryCommitFollowUpAttachmentsAsync tryCommitAsync,
        CancellationToken cancellationToken)
    {
        ValidateArguments(target, existingAttachments, tryCommitAsync);
        ArgumentNullException.ThrowIfNull(sourcePaths);
        cancellationToken.ThrowIfCancellationRequested();
        var imported = await _importer.ImportFilesAsync(
                sourcePaths,
                existingAttachments,
                limits,
                cancellationToken)
            .ConfigureAwait(false);
        return await CommitImportedAsync(
                target,
                existingAttachments,
                imported,
                text: null,
                tryCommitAsync,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FollowUpAttachmentCompositionResult> ComposeClipboardAsync(
        FollowUpAttachmentDraftTarget target,
        IReadOnlyList<PresetAttachmentReference> existingAttachments,
        ClipboardAttachmentSource source,
        AttachmentLimitSettings limits,
        TryCommitFollowUpAttachmentsAsync tryCommitAsync,
        CancellationToken cancellationToken)
    {
        ValidateArguments(target, existingAttachments, tryCommitAsync);
        ArgumentNullException.ThrowIfNull(source);
        cancellationToken.ThrowIfCancellationRequested();
        var imported = await _importer.ImportClipboardAsync(
                source,
                existingAttachments,
                limits,
                cancellationToken)
            .ConfigureAwait(false);
        return await CommitImportedAsync(
                target,
                existingAttachments,
                imported.Attachments,
                imported.Text,
                tryCommitAsync,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<FollowUpAttachmentCompositionResult> CommitImportedAsync(
        FollowUpAttachmentDraftTarget target,
        IReadOnlyList<PresetAttachmentReference> existingAttachments,
        IReadOnlyList<PresetAttachmentReference> importedAttachments,
        string? text,
        TryCommitFollowUpAttachmentsAsync tryCommitAsync,
        CancellationToken cancellationToken)
    {
        if (importedAttachments.Count == 0)
        {
            return new FollowUpAttachmentCompositionResult(
                target,
                CopyReferences(existingAttachments),
                0,
                FollowUpAttachmentCompositionStatus.NoAttachments,
                text);
        }

        var imported = CopyReferences(importedAttachments);
        IDisposable? pins = null;
        Exception? primaryFailure = null;
        var committed = false;
        try
        {
            pins = _draftAuthority.AcquireTransientPins(imported);
            cancellationToken.ThrowIfCancellationRequested();
            var combined = CopyReferences(existingAttachments.Concat(imported));
            committed = await tryCommitAsync(target, combined, cancellationToken)
                .ConfigureAwait(false);
            if (!committed)
            {
                return new FollowUpAttachmentCompositionResult(
                    target,
                    CopyReferences(existingAttachments),
                    imported.Count,
                    FollowUpAttachmentCompositionStatus.StaleTarget,
                    text);
            }

            return new FollowUpAttachmentCompositionResult(
                target,
                combined,
                imported.Count,
                FollowUpAttachmentCompositionStatus.Committed,
                text);
        }
        catch (Exception exception)
        {
            primaryFailure = exception;
            throw;
        }
        finally
        {
            pins?.Dispose();
            if (!committed)
            {
                await RequestCleanupAsync(imported, primaryFailure).ConfigureAwait(false);
            }
        }
    }

    private async Task RequestCleanupAsync(
        IReadOnlyList<PresetAttachmentReference> imported,
        Exception? primaryFailure)
    {
        var contentIds = imported
            .Select(static attachment => attachment.ContentId)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        try
        {
            await _requestZeroReferenceCleanupAsync(contentIds, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception cleanupFailure)
        {
            if (primaryFailure is null)
            {
                throw;
            }

            primaryFailure.Data[CleanupRequestFailureDataKey] = cleanupFailure;
        }
    }

    private static void ValidateArguments(
        FollowUpAttachmentDraftTarget target,
        IReadOnlyList<PresetAttachmentReference> existingAttachments,
        TryCommitFollowUpAttachmentsAsync tryCommitAsync)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(existingAttachments);
        ArgumentNullException.ThrowIfNull(tryCommitAsync);
        if (string.IsNullOrWhiteSpace(target.ThreadId) ||
            !AttachmentIdentity.IsCanonicalReferenceId(target.MessageId) ||
            target.Version < 0)
        {
            throw new ArgumentException(
                "The attachment composition target is invalid.",
                nameof(target));
        }
    }

    private static IReadOnlyList<PresetAttachmentReference> CopyReferences(
        IEnumerable<PresetAttachmentReference> attachments) =>
        Array.AsReadOnly(attachments.ToArray());
}
