using CodexGuardian.Models;
using System.Text.Json;

namespace CodexGuardian.Services;

internal enum AttachmentPresentationReconciliationStatus
{
    Healthy,
    InvalidConfiguration,
    SettingsUnavailable,
    SettingsGenerationChanged,
    DraftAuthorityUnavailable,
    FollowUpJournalUnavailable,
    RecoveryJournalUnavailable,
    PresentationAuthorityUnavailable,
    PresentationIdentityMismatch,
    MaterializingJournalConflict,
    CleanupPendingActiveConflict,
    PostCleanupAuthorityUnavailable,
    PresentationCleanupPending,
    JournalPersistenceUnavailable,
    ManagedObjectCleanupIncomplete
}

internal sealed record AttachmentPresentationReconciliationResult(
    bool IsHealthy,
    AttachmentPresentationReconciliationStatus Status,
    int DeletedLeaseCount,
    int CleanupPendingLeaseCount,
    int RetainedLeaseCount,
    int PrunedJournalRecordCount,
    int DeletedManagedObjectCount);

internal sealed class AttachmentPresentationReconciliationService
{
    private readonly string _dataDirectory;
    private readonly SettingsService _settingsService;
    private readonly AttachmentDraftAuthority _draftAuthority;
    private readonly FollowUpOperationJournal _followUpJournal;
    private readonly RecoveryOperationJournal _recoveryJournal;
    private readonly AttachmentPresentationLeaseService _presentation;
    private readonly AttachmentReferenceCoordinator _coordinator;
    private readonly SemaphoreSlim _mutationGate;

    internal AttachmentPresentationReconciliationService(
        string dataDirectory,
        SettingsService settingsService,
        AttachmentDraftAuthority draftAuthority,
        FollowUpOperationJournal followUpJournal,
        RecoveryOperationJournal recoveryJournal,
        AttachmentPresentationLeaseService presentation,
        AttachmentReferenceCoordinator coordinator)
    {
        _settingsService = settingsService ?? throw new ArgumentNullException(nameof(settingsService));
        _draftAuthority = draftAuthority ?? throw new ArgumentNullException(nameof(draftAuthority));
        _followUpJournal = followUpJournal ?? throw new ArgumentNullException(nameof(followUpJournal));
        _recoveryJournal = recoveryJournal ?? throw new ArgumentNullException(nameof(recoveryJournal));
        _presentation = presentation ?? throw new ArgumentNullException(nameof(presentation));
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _dataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        if (!PathsEqual(_dataDirectory, settingsService.DataDirectory) ||
            !PathsEqual(_dataDirectory, followUpJournal.DataDirectory) ||
            !PathsEqual(_dataDirectory, recoveryJournal.DataDirectory) ||
            !PathsEqual(_dataDirectory, presentation.DataDirectory) ||
            !PathsEqual(_dataDirectory, coordinator.DataDirectory))
        {
            throw new ArgumentException(
                "Presentation reconciliation authorities must share one data directory.",
                nameof(dataDirectory));
        }

        _mutationGate = AttachmentMutationLeaseRegistry.Get(_dataDirectory);
    }

    internal async Task<AttachmentPresentationReconciliationResult> ReconcileAsync(
        AppSettings settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!HasValidConfiguredMessageIdentities(settings))
        {
            return Blocked(AttachmentPresentationReconciliationStatus.InvalidConfiguration);
        }

        var deletedContentIds = new HashSet<string>(StringComparer.Ordinal);
        var deletedLeaseCount = 0;
        var cleanupPendingLeaseCount = 0;
        var retainedLeaseCount = 0;
        var prunedJournalRecordCount = 0;
        var status = AttachmentPresentationReconciliationStatus.Healthy;

        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settingsSnapshot = await _settingsService
                .ReadAttachmentReferenceSnapshotUnderMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var draftSnapshot = _draftAuthority.ReadSnapshot();
            var followUpSnapshot = await _followUpJournal.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            var recoverySnapshot = await _recoveryJournal.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            var presentationSnapshot = _presentation.ReadReferenceSnapshotUnderMutationLease();

            status = ValidateAuthoritySnapshots(
                settings,
                settingsSnapshot,
                draftSnapshot,
                followUpSnapshot,
                recoverySnapshot,
                presentationSnapshot);
            if (status != AttachmentPresentationReconciliationStatus.Healthy)
            {
                return Blocked(status);
            }

            status = ValidatePresentationJournalIdentity(
                followUpSnapshot,
                recoverySnapshot,
                presentationSnapshot);
            if (status != AttachmentPresentationReconciliationStatus.Healthy)
            {
                return Blocked(status);
            }

            var recordsByOperation = followUpSnapshot.Records.ToDictionary(
                record => record.OperationId,
                StringComparer.OrdinalIgnoreCase);
            foreach (var reference in presentationSnapshot.References
                         .OrderBy(reference => reference.LeaseId, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                recordsByOperation.TryGetValue(reference.OperationId, out var record);
                if (!ShouldCleanup(record, recoverySnapshot.Records) ||
                    !HasZeroReferencesExcludingTarget(
                        reference,
                        settingsSnapshot,
                        draftSnapshot,
                        followUpSnapshot.Records,
                        recoverySnapshot.Records,
                        presentationSnapshot.References))
                {
                    retainedLeaseCount++;
                    continue;
                }

                var cleanup = _presentation.CleanupUnderMutationLease(
                    reference.LeaseId,
                    new AttachmentPresentationCleanupAuthorization(
                        RecoveryLineageClosed: true,
                        ZeroReferenceProven: true));
                if (cleanup.Status == AttachmentPresentationCleanupStatus.Deleted)
                {
                    deletedLeaseCount++;
                    deletedContentIds.UnionWith(reference.ContentIds);
                }
                else if (cleanup.Status == AttachmentPresentationCleanupStatus.CleanupPending)
                {
                    cleanupPendingLeaseCount++;
                }
                else
                {
                    retainedLeaseCount++;
                }
            }

            var remainingPresentation = _presentation.ReadReferenceSnapshotUnderMutationLease();
            if (!remainingPresentation.IsHealthy)
            {
                return new AttachmentPresentationReconciliationResult(
                    IsHealthy: false,
                    AttachmentPresentationReconciliationStatus.PostCleanupAuthorityUnavailable,
                    deletedLeaseCount,
                    cleanupPendingLeaseCount,
                    retainedLeaseCount,
                    prunedJournalRecordCount,
                    DeletedManagedObjectCount: 0);
            }

            var protectedOperationIds = remainingPresentation.References
                .Select(reference => reference.OperationId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            prunedJournalRecordCount = await _followUpJournal.PruneInactiveCompletedAsync(
                    settings.ThreadFollowUps,
                    protectedOperationIds,
                    cancellationToken)
                .ConfigureAwait(false);
            if (cleanupPendingLeaseCount > 0)
            {
                status = AttachmentPresentationReconciliationStatus.PresentationCleanupPending;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                JsonException or NotSupportedException or ArgumentException or
                InvalidOperationException or OverflowException)
        {
            status = AttachmentPresentationReconciliationStatus.JournalPersistenceUnavailable;
        }
        finally
        {
            _mutationGate.Release();
        }

        var deletedManagedObjectCount = 0;
        if (deletedContentIds.Count > 0)
        {
            try
            {
                var managedCleanup = await _coordinator.RequestZeroReferenceCleanupWithResultAsync(
                        deletedContentIds.Order(StringComparer.Ordinal).ToArray(),
                        cancellationToken)
                    .ConfigureAwait(false);
                deletedManagedObjectCount = managedCleanup.DeletedCount;
                if (!managedCleanup.IsHealthy &&
                    (status is AttachmentPresentationReconciliationStatus.Healthy or
                        AttachmentPresentationReconciliationStatus.PresentationCleanupPending))
                {
                    status = AttachmentPresentationReconciliationStatus.ManagedObjectCleanupIncomplete;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or InvalidDataException or
                    JsonException or NotSupportedException or ArgumentException or InvalidOperationException)
            {
                if (status is AttachmentPresentationReconciliationStatus.Healthy or
                    AttachmentPresentationReconciliationStatus.PresentationCleanupPending)
                {
                    status = AttachmentPresentationReconciliationStatus.ManagedObjectCleanupIncomplete;
                }
            }
        }

        return new AttachmentPresentationReconciliationResult(
            IsHealthy: status == AttachmentPresentationReconciliationStatus.Healthy,
            status,
            deletedLeaseCount,
            cleanupPendingLeaseCount,
            retainedLeaseCount,
            prunedJournalRecordCount,
            deletedManagedObjectCount);
    }

    private static AttachmentPresentationReconciliationStatus ValidateAuthoritySnapshots(
        AppSettings settings,
        AttachmentSettingsReferenceSnapshot settingsSnapshot,
        AttachmentDraftPinSnapshot draftSnapshot,
        FollowUpJournalSnapshot followUpSnapshot,
        RecoveryJournalSnapshot recoverySnapshot,
        AttachmentPresentationReferenceSnapshot presentationSnapshot)
    {
        if (!settingsSnapshot.IsHealthy ||
            settings.ReadStatus is not SettingsReadStatus.Missing and not SettingsReadStatus.Healthy)
        {
            return AttachmentPresentationReconciliationStatus.SettingsUnavailable;
        }

        if (settings.SettingsGeneration != settingsSnapshot.SettingsGeneration ||
            settings.PreviousSettingsGeneration != settingsSnapshot.PreviousSettingsGeneration)
        {
            return AttachmentPresentationReconciliationStatus.SettingsGenerationChanged;
        }

        if (!draftSnapshot.IsHealthy)
        {
            return AttachmentPresentationReconciliationStatus.DraftAuthorityUnavailable;
        }

        if (followUpSnapshot.RequiresConservativeRecovery ||
            followUpSnapshot.ReadStatus is not FollowUpJournalReadStatus.Missing and not
                FollowUpJournalReadStatus.Healthy)
        {
            return AttachmentPresentationReconciliationStatus.FollowUpJournalUnavailable;
        }

        if (recoverySnapshot.RequiresConservativeRecovery ||
            recoverySnapshot.ReadStatus is not RecoveryJournalReadStatus.Missing and not
                RecoveryJournalReadStatus.Healthy)
        {
            return AttachmentPresentationReconciliationStatus.RecoveryJournalUnavailable;
        }

        return presentationSnapshot.IsHealthy
            ? AttachmentPresentationReconciliationStatus.Healthy
            : AttachmentPresentationReconciliationStatus.PresentationAuthorityUnavailable;
    }

    private static AttachmentPresentationReconciliationStatus ValidatePresentationJournalIdentity(
        FollowUpJournalSnapshot followUpSnapshot,
        RecoveryJournalSnapshot recoverySnapshot,
        AttachmentPresentationReferenceSnapshot presentationSnapshot)
    {
        var recordsByOperation = followUpSnapshot.Records.ToDictionary(
            record => record.OperationId,
            StringComparer.OrdinalIgnoreCase);
        var referencesByLease = presentationSnapshot.References.ToDictionary(
            reference => reference.LeaseId,
            StringComparer.Ordinal);

        foreach (var reference in presentationSnapshot.References)
        {
            if (!recordsByOperation.TryGetValue(reference.OperationId, out var record))
            {
                continue;
            }

            if (reference.State == AttachmentPresentationReferenceState.Materializing)
            {
                return AttachmentPresentationReconciliationStatus.MaterializingJournalConflict;
            }

            if (!HasAttachmentPresentation(record) ||
                !FollowUpAttachmentAuthorityReader.PresentationMatches(record, reference))
            {
                return AttachmentPresentationReconciliationStatus.PresentationIdentityMismatch;
            }

            if (reference.State == AttachmentPresentationReferenceState.CleanupPending &&
                IsRecordPinned(record, recoverySnapshot.Records))
            {
                return AttachmentPresentationReconciliationStatus.CleanupPendingActiveConflict;
            }
        }

        foreach (var record in followUpSnapshot.Records.Where(HasAttachmentPresentation))
        {
            if (!referencesByLease.TryGetValue(record.PresentationLeaseId!, out var reference))
            {
                if (IsRecordPinned(record, recoverySnapshot.Records))
                {
                    return AttachmentPresentationReconciliationStatus.PresentationIdentityMismatch;
                }

                continue;
            }

            if (!FollowUpAttachmentAuthorityReader.PresentationMatches(record, reference))
            {
                return AttachmentPresentationReconciliationStatus.PresentationIdentityMismatch;
            }
        }

        return AttachmentPresentationReconciliationStatus.Healthy;
    }

    private static bool ShouldCleanup(
        FollowUpOperationRecord? record,
        IReadOnlyList<RecoveryOperationRecord> recoveryRecords) =>
        record is null ||
        record.State == FollowUpOperationState.Abandoned ||
        record.State == FollowUpOperationState.Confirmed && !IsRecordPinned(record, recoveryRecords);

    private static bool HasZeroReferencesExcludingTarget(
        AttachmentPresentationReference target,
        AttachmentSettingsReferenceSnapshot settings,
        AttachmentDraftPinSnapshot draft,
        IReadOnlyList<FollowUpOperationRecord> followUpRecords,
        IReadOnlyList<RecoveryOperationRecord> recoveryRecords,
        IReadOnlyList<AttachmentPresentationReference> presentationReferences)
    {
        foreach (var contentId in target.ContentIds)
        {
            if (settings.CurrentContentIds.Contains(contentId, StringComparer.Ordinal) ||
                settings.PreviousContentIds.Contains(contentId, StringComparer.Ordinal) ||
                draft.ContentIds.Contains(contentId, StringComparer.Ordinal) ||
                presentationReferences.Any(reference =>
                    !string.Equals(reference.LeaseId, target.LeaseId, StringComparison.Ordinal) &&
                    reference.ContentIds.Contains(contentId, StringComparer.Ordinal)) ||
                followUpRecords.Any(record =>
                    !string.Equals(record.OperationId, target.OperationId, StringComparison.OrdinalIgnoreCase) &&
                    record.AttachmentContentIds.Contains(contentId, StringComparer.Ordinal) &&
                    IsRecordPinned(record, recoveryRecords)))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsRecordPinned(
        FollowUpOperationRecord record,
        IReadOnlyList<RecoveryOperationRecord> recoveryRecords) =>
        record.State switch
        {
            FollowUpOperationState.Prepared => true,
            FollowUpOperationState.Dispatching => true,
            FollowUpOperationState.Retryable => true,
            FollowUpOperationState.Uncertain => true,
            FollowUpOperationState.Confirmed =>
                record.CompletionTurnId is null &&
                !FollowUpAttachmentAuthorityReader.IsRecoveryLineageClosed(record, recoveryRecords),
            _ => false
        };

    private static bool HasAttachmentPresentation(FollowUpOperationRecord record) =>
        (record.SourceKind is FollowUpPayloadSourceKind.StructuredPreset or
            FollowUpPayloadSourceKind.WorkflowPreset) &&
        record.AttachmentContentIds.Count > 0 &&
        record.PresentationLeaseId is not null;

    private static bool HasValidConfiguredMessageIdentities(AppSettings settings)
    {
        if (settings.ThreadFollowUps is null)
        {
            return false;
        }

        foreach (var pair in settings.ThreadFollowUps)
        {
            if (!Guid.TryParseExact(pair.Key, "D", out _) || pair.Value?.Messages is null ||
                pair.Value.Messages.Any(message =>
                    message is null || !Guid.TryParseExact(message.Id, "D", out _)))
            {
                return false;
            }
        }

        return true;
    }

    private static AttachmentPresentationReconciliationResult Blocked(
        AttachmentPresentationReconciliationStatus status) =>
        new(
            IsHealthy: false,
            status,
            DeletedLeaseCount: 0,
            CleanupPendingLeaseCount: 0,
            RetainedLeaseCount: 0,
            PrunedJournalRecordCount: 0,
            DeletedManagedObjectCount: 0);

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(left),
            Path.TrimEndingDirectorySeparator(right),
            StringComparison.OrdinalIgnoreCase);
}
