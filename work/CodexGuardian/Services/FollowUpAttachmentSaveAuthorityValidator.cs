using CodexGuardian.Models;
using System.Text.Json;

namespace CodexGuardian.Services;

internal enum FollowUpAttachmentSaveAuthorityStatus
{
    Supported,
    UnsupportedPayload,
    ObjectMissingOrDamaged,
    AuthorityUnavailable,
    PendingOperationConflict,
    PresentationIdentityMismatch
}

internal sealed record FollowUpAttachmentSaveAuthorityResult(
    FollowUpAttachmentSaveAuthorityStatus Status,
    int MessageNumber,
    string Code)
{
    internal bool CanSave => Status == FollowUpAttachmentSaveAuthorityStatus.Supported;

    internal static FollowUpAttachmentSaveAuthorityResult Supported { get; } =
        new(FollowUpAttachmentSaveAuthorityStatus.Supported, 0, "supported");

    internal static FollowUpAttachmentSaveAuthorityResult Unsupported(
        int messageNumber,
        string code) =>
        new(FollowUpAttachmentSaveAuthorityStatus.UnsupportedPayload, messageNumber, code);

    internal static FollowUpAttachmentSaveAuthorityResult ObjectUnavailable(
        int messageNumber,
        string code) =>
        new(FollowUpAttachmentSaveAuthorityStatus.ObjectMissingOrDamaged, messageNumber, code);

    internal static FollowUpAttachmentSaveAuthorityResult Authority(
        int messageNumber,
        string code) =>
        new(FollowUpAttachmentSaveAuthorityStatus.AuthorityUnavailable, messageNumber, code);

    internal static FollowUpAttachmentSaveAuthorityResult Pending(
        int messageNumber,
        string code) =>
        new(FollowUpAttachmentSaveAuthorityStatus.PendingOperationConflict, messageNumber, code);

    internal static FollowUpAttachmentSaveAuthorityResult IdentityMismatch(
        int messageNumber,
        string code) =>
        new(FollowUpAttachmentSaveAuthorityStatus.PresentationIdentityMismatch, messageNumber, code);
}

/// <summary>
/// Performs the read-only authority checks required before an attachment-bearing preset
/// draft can be durably saved. The caller may use the result to keep the draft dirty.
/// </summary>
internal sealed class FollowUpAttachmentSaveAuthorityValidator
{
    private readonly string _dataDirectory;
    private readonly SettingsService _settingsService;
    private readonly AttachmentDraftAuthority _draftAuthority;
    private readonly FollowUpOperationJournal _followUpJournal;
    private readonly RecoveryOperationJournal _recoveryJournal;
    private readonly AttachmentPresentationLeaseService _presentation;
    private readonly ManagedAttachmentStore _store;
    private readonly SemaphoreSlim _mutationGate;

    internal FollowUpAttachmentSaveAuthorityValidator(
        string dataDirectory,
        SettingsService settingsService,
        AttachmentDraftAuthority draftAuthority,
        FollowUpOperationJournal followUpJournal,
        RecoveryOperationJournal recoveryJournal,
        AttachmentPresentationLeaseService presentation,
        ManagedAttachmentStore store)
    {
        ArgumentNullException.ThrowIfNull(settingsService);
        ArgumentNullException.ThrowIfNull(draftAuthority);
        ArgumentNullException.ThrowIfNull(followUpJournal);
        ArgumentNullException.ThrowIfNull(recoveryJournal);
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(store);

        _dataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        if (!PathsEqual(_dataDirectory, settingsService.DataDirectory) ||
            !PathsEqual(_dataDirectory, followUpJournal.DataDirectory) ||
            !PathsEqual(_dataDirectory, recoveryJournal.DataDirectory) ||
            !PathsEqual(_dataDirectory, presentation.DataDirectory) ||
            !PathsEqual(_dataDirectory, store.DataDirectory))
        {
            throw new ArgumentException(
                "Attachment save authority sources must share one data directory.",
                nameof(dataDirectory));
        }

        _settingsService = settingsService;
        _draftAuthority = draftAuthority;
        _followUpJournal = followUpJournal;
        _recoveryJournal = recoveryJournal;
        _presentation = presentation;
        _store = store;
        _mutationGate = AttachmentMutationLeaseRegistry.Get(_dataDirectory);
    }

    internal async Task<FollowUpAttachmentSaveAuthorityResult> ValidateAsync(
        AppSettings settings,
        IReadOnlyList<FollowUpAttachmentSaveCandidate> candidates,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(candidates);
        cancellationToken.ThrowIfCancellationRequested();

        var candidateResult = ValidateCandidates(candidates);
        if (candidateResult is not null)
        {
            return candidateResult;
        }

        var attachmentCandidates = candidates
            .Where(candidate => candidate.Payload.Attachments.Count > 0)
            .ToArray();
        if (attachmentCandidates.Length == 0)
        {
            return FollowUpAttachmentSaveAuthorityResult.Supported;
        }

        AuthorityReadResult before;
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            before = await ReadAuthorityStateUnderMutationLeaseAsync(
                    settings,
                    attachmentCandidates,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _mutationGate.Release();
        }

        if (before.Failure is not null)
        {
            return before.Failure;
        }

        foreach (var candidate in attachmentCandidates)
        {
            foreach (var attachment in candidate.Payload.Attachments)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bool verified;
                try
                {
                    verified = await _store.VerifyAsync(attachment, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception) when (IsAuthorityReadFailure(exception))
                {
                    verified = false;
                }

                if (!verified)
                {
                    return FollowUpAttachmentSaveAuthorityResult.ObjectUnavailable(
                        candidate.MessageNumber,
                        "managed-object-missing-or-damaged");
                }
            }
        }

        AuthorityReadResult after;
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            after = await ReadAuthorityStateUnderMutationLeaseAsync(
                    settings,
                    attachmentCandidates,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _mutationGate.Release();
        }

        if (after.Failure is not null)
        {
            return after.Failure;
        }

        return before.State is not null && before.State == after.State
            ? FollowUpAttachmentSaveAuthorityResult.Supported
            : FollowUpAttachmentSaveAuthorityResult.Authority(
                FirstMessageNumber(attachmentCandidates),
                "authority-changed-during-validation");
    }

    private async Task<AuthorityReadResult> ReadAuthorityStateUnderMutationLeaseAsync(
        AppSettings settings,
        IReadOnlyList<FollowUpAttachmentSaveCandidate> candidates,
        CancellationToken cancellationToken)
    {
        var messageNumber = FirstMessageNumber(candidates);
        AttachmentSettingsReferenceSnapshot settingsSnapshot;
        try
        {
            settingsSnapshot = await _settingsService
                .ReadAttachmentReferenceSnapshotUnderMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsAuthorityReadFailure(exception))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "settings-read-failed"));
        }

        var settingsResult = ValidateSettings(settings, settingsSnapshot, candidates);
        if (settingsResult is not null)
        {
            return AuthorityReadResult.Failed(settingsResult);
        }

        var draftSnapshot = _draftAuthority.ReadSnapshot();
        if (!draftSnapshot.IsHealthy ||
            draftSnapshot.Version < 0 ||
            draftSnapshot.ContentIds is null ||
            draftSnapshot.ContentIds.Any(contentId =>
                !AttachmentIdentity.IsCanonicalContentId(contentId)))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "draft-authority-unavailable"));
        }

        var requiredContentIds = candidates
            .SelectMany(candidate => candidate.Payload.Attachments)
            .Select(attachment => attachment.ContentId)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (requiredContentIds.Any(contentId =>
                !draftSnapshot.ContentIds.Contains(contentId, StringComparer.Ordinal)))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "draft-reference-unpinned"));
        }

        FollowUpJournalSnapshot followUpSnapshot;
        RecoveryJournalSnapshot recoverySnapshot;
        try
        {
            followUpSnapshot = await _followUpJournal.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            recoverySnapshot = await _recoveryJournal.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsAuthorityReadFailure(exception))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "journal-read-failed"));
        }

        if (!IsHealthy(followUpSnapshot))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "follow-up-journal-unavailable"));
        }

        if (!IsHealthy(recoverySnapshot))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "recovery-journal-unavailable"));
        }

        AttachmentPresentationReferenceSnapshot presentationSnapshot;
        try
        {
            presentationSnapshot = _presentation.ReadReferenceSnapshotUnderMutationLease();
        }
        catch (Exception exception) when (IsAuthorityReadFailure(exception))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "presentation-read-failed"));
        }

        FollowUpAttachmentSaveAuthorityResult? presentationResult;
        try
        {
            presentationResult = ValidatePresentationAuthority(
                followUpSnapshot,
                presentationSnapshot,
                requiredContentIds,
                messageNumber);
        }
        catch (Exception exception) when (IsAuthorityReadFailure(exception))
        {
            return AuthorityReadResult.Failed(
                FollowUpAttachmentSaveAuthorityResult.Authority(
                    messageNumber,
                    "presentation-identity-unavailable"));
        }
        if (presentationResult is not null)
        {
            return AuthorityReadResult.Failed(presentationResult);
        }

        return AuthorityReadResult.Succeeded(new ValidatedAuthorityState(
            settingsSnapshot.SettingsGeneration,
            settingsSnapshot.PreviousSettingsGeneration,
            followUpSnapshot.Generation,
            recoverySnapshot.Generation,
            draftSnapshot.Version,
            presentationSnapshot.LeaseVersion,
            presentationSnapshot.TransactionVersion));
    }

    private static FollowUpAttachmentSaveAuthorityResult? ValidateCandidates(
        IReadOnlyList<FollowUpAttachmentSaveCandidate> candidates)
    {
        for (var index = 0; index < candidates.Count; index++)
        {
            var candidate = candidates[index];
            var messageNumber = candidate?.MessageNumber > 0
                ? candidate.MessageNumber
                : index + 1;
            if (candidate is null || candidate.MessageNumber <= 0 || candidate.Payload is null)
            {
                return FollowUpAttachmentSaveAuthorityResult.Unsupported(
                    messageNumber,
                    "candidate-invalid");
            }

            if (!candidate.Payload.HasValidIdentity())
            {
                return FollowUpAttachmentSaveAuthorityResult.Unsupported(
                    candidate.MessageNumber,
                    "payload-identity-invalid");
            }
        }

        return null;
    }

    private static FollowUpAttachmentSaveAuthorityResult? ValidateSettings(
        AppSettings settings,
        AttachmentSettingsReferenceSnapshot snapshot,
        IReadOnlyList<FollowUpAttachmentSaveCandidate> candidates)
    {
        var messageNumber = FirstMessageNumber(candidates);
        if (settings.ReadStatus is not SettingsReadStatus.Missing and not SettingsReadStatus.Healthy ||
            !snapshot.IsHealthy ||
            snapshot.SettingsGeneration < 0 ||
            snapshot.PreviousSettingsGeneration < 0 ||
            snapshot.CurrentContentIds is null ||
            snapshot.PreviousContentIds is null ||
            snapshot.CurrentContentIds.Concat(snapshot.PreviousContentIds).Any(contentId =>
                !AttachmentIdentity.IsCanonicalContentId(contentId)))
        {
            return FollowUpAttachmentSaveAuthorityResult.Authority(
                messageNumber,
                "settings-authority-unavailable");
        }

        if (settings.SettingsGeneration != snapshot.SettingsGeneration ||
            settings.PreviousSettingsGeneration != snapshot.PreviousSettingsGeneration)
        {
            return FollowUpAttachmentSaveAuthorityResult.Authority(
                messageNumber,
                "settings-generation-changed");
        }

        return null;
    }

    private static FollowUpAttachmentSaveAuthorityResult? ValidatePresentationAuthority(
        FollowUpJournalSnapshot followUp,
        AttachmentPresentationReferenceSnapshot presentation,
        IReadOnlyCollection<string> requiredContentIds,
        int messageNumber)
    {
        if (!presentation.IsHealthy ||
            presentation.LeaseVersion < 0 ||
            presentation.TransactionVersion < 0 ||
            presentation.References is null)
        {
            return FollowUpAttachmentSaveAuthorityResult.Authority(
                messageNumber,
                "presentation-authority-unavailable");
        }

        var recordsByOperation = followUp.Records.ToDictionary(
            record => record.OperationId,
            StringComparer.OrdinalIgnoreCase);
        var referencesByLease = presentation.References.ToDictionary(
            reference => reference.LeaseId,
            StringComparer.Ordinal);

        foreach (var reference in presentation.References)
        {
            if (reference.State is AttachmentPresentationReferenceState.Materializing or
                AttachmentPresentationReferenceState.CleanupPending)
            {
                return FollowUpAttachmentSaveAuthorityResult.Pending(
                    messageNumber,
                    reference.State == AttachmentPresentationReferenceState.Materializing
                        ? "presentation-materializing"
                        : "presentation-cleanup-pending");
            }

            if (!recordsByOperation.TryGetValue(reference.OperationId, out var record) ||
                !HasAttachmentPresentation(record) ||
                !FollowUpAttachmentAuthorityReader.PresentationMatches(record, reference))
            {
                return FollowUpAttachmentSaveAuthorityResult.IdentityMismatch(
                    messageNumber,
                    "presentation-identity-mismatch");
            }
        }

        foreach (var record in followUp.Records.Where(HasAttachmentPresentation))
        {
            if (record.PresentationLeaseId is null ||
                !referencesByLease.TryGetValue(record.PresentationLeaseId, out var reference) ||
                reference.State != AttachmentPresentationReferenceState.Ready ||
                !FollowUpAttachmentAuthorityReader.PresentationMatches(record, reference))
            {
                return FollowUpAttachmentSaveAuthorityResult.IdentityMismatch(
                    messageNumber,
                    "journal-presentation-mismatch");
            }
        }

        if (followUp.Records.Any(record =>
                record.AttachmentContentIds is { Count: > 0 } &&
                record.AttachmentContentIds.Any(requiredContentIds.Contains) &&
                record.State is FollowUpOperationState.Prepared or
                    FollowUpOperationState.Dispatching or
                    FollowUpOperationState.Retryable or
                    FollowUpOperationState.Uncertain))
        {
            return FollowUpAttachmentSaveAuthorityResult.Pending(
                messageNumber,
                "pending-operation-conflict");
        }

        return null;
    }

    private static bool HasAttachmentPresentation(FollowUpOperationRecord record) =>
        (record.SourceKind is FollowUpPayloadSourceKind.StructuredPreset or
            FollowUpPayloadSourceKind.WorkflowPreset) &&
        record.AttachmentContentIds is { Count: > 0 } &&
        record.PresentationLeaseId is not null;

    private static bool IsHealthy(FollowUpJournalSnapshot snapshot) =>
        snapshot is not null &&
        !snapshot.RequiresConservativeRecovery &&
        snapshot.Generation >= 0 &&
        snapshot.Records is not null &&
        snapshot.ReadStatus is FollowUpJournalReadStatus.Missing or FollowUpJournalReadStatus.Healthy;

    private static bool IsHealthy(RecoveryJournalSnapshot snapshot) =>
        snapshot is not null &&
        !snapshot.RequiresConservativeRecovery &&
        snapshot.Generation >= 0 &&
        snapshot.Records is not null &&
        snapshot.ReadStatus is RecoveryJournalReadStatus.Missing or RecoveryJournalReadStatus.Healthy;

    private static int FirstMessageNumber(
        IReadOnlyList<FollowUpAttachmentSaveCandidate> candidates) =>
        candidates.Count == 0 || candidates[0] is null || candidates[0].MessageNumber <= 0
            ? 1
            : candidates[0].MessageNumber;

    private static bool IsAuthorityReadFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or InvalidDataException or
        JsonException or NotSupportedException or ArgumentException or InvalidOperationException;

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(left),
            Path.TrimEndingDirectorySeparator(right),
            StringComparison.OrdinalIgnoreCase);

    private sealed record ValidatedAuthorityState(
        long SettingsGeneration,
        long PreviousSettingsGeneration,
        long FollowUpJournalGeneration,
        long RecoveryJournalGeneration,
        long DraftVersion,
        long LeaseVersion,
        long TransactionVersion);

    private sealed record AuthorityReadResult(
        ValidatedAuthorityState? State,
        FollowUpAttachmentSaveAuthorityResult? Failure)
    {
        internal static AuthorityReadResult Succeeded(ValidatedAuthorityState state) =>
            new(state, null);

        internal static AuthorityReadResult Failed(
            FollowUpAttachmentSaveAuthorityResult failure) =>
            new(null, failure);
    }
}
