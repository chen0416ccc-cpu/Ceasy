using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal sealed class FollowUpAttachmentRuntime
{
    internal FollowUpAttachmentRuntime(
        string dataDirectory,
        SettingsService settingsService,
        FollowUpOperationJournal? followUpJournal,
        RecoveryOperationJournal? recoveryJournal,
        IDesktopStructuredInputCapabilityProvider? structuredCapabilities = null)
    {
        StructuredCapabilities = structuredCapabilities;
        Store = new ManagedAttachmentStore(dataDirectory);
        DraftAuthority = new AttachmentDraftAuthority();
        Presentation = new AttachmentPresentationLeaseService(dataDirectory, Store);
        var authorityReader = new FollowUpAttachmentAuthorityReader(
            DraftAuthority,
            followUpJournal,
            recoveryJournal,
            Presentation);
        Coordinator = new AttachmentReferenceCoordinator(
            dataDirectory,
            Store,
            settingsService,
            authorityReader);
        Reconciliation = followUpJournal is not null && recoveryJournal is not null
            ? new AttachmentPresentationReconciliationService(
                dataDirectory,
                settingsService,
                DraftAuthority,
                followUpJournal,
                recoveryJournal,
                Presentation,
                Coordinator)
            : null;
        SaveAuthorityValidator = followUpJournal is not null && recoveryJournal is not null
            ? new FollowUpAttachmentSaveAuthorityValidator(
                dataDirectory,
                settingsService,
                DraftAuthority,
                followUpJournal,
                recoveryJournal,
                Presentation,
                Store)
            : null;
        Importer = new AttachmentImportService(Store, Coordinator.RequestZeroReferenceCleanupAsync);
        Composition = new FollowUpAttachmentCompositionService(
            Importer,
            DraftAuthority,
            Coordinator.RequestZeroReferenceCleanupAsync,
            structuredCapabilities,
            SaveAuthorityValidator);
        Clipboard = new ClipboardAttachmentReader();
        Thumbnails = new ManagedAttachmentThumbnailService(Store);
    }

    internal ManagedAttachmentStore Store { get; }

    internal IDesktopStructuredInputCapabilityProvider? StructuredCapabilities { get; }

    internal AttachmentDraftAuthority DraftAuthority { get; }

    internal AttachmentPresentationLeaseService Presentation { get; }

    internal AttachmentReferenceCoordinator Coordinator { get; }

    internal AttachmentPresentationReconciliationService? Reconciliation { get; }

    internal FollowUpAttachmentSaveAuthorityValidator? SaveAuthorityValidator { get; }

    internal AttachmentImportService Importer { get; }

    internal FollowUpAttachmentCompositionService Composition { get; }

    internal ClipboardAttachmentReader Clipboard { get; }

    internal ManagedAttachmentThumbnailService Thumbnails { get; }

}

internal sealed class FollowUpAttachmentAuthorityReader : IAttachmentReferenceAuthorityReader
{
    private readonly AttachmentDraftAuthority _draftAuthority;
    private readonly FollowUpOperationJournal? _followUpJournal;
    private readonly RecoveryOperationJournal? _recoveryJournal;
    private readonly AttachmentPresentationLeaseService _presentation;

    internal FollowUpAttachmentAuthorityReader(
        AttachmentDraftAuthority draftAuthority,
        FollowUpOperationJournal? followUpJournal,
        RecoveryOperationJournal? recoveryJournal,
        AttachmentPresentationLeaseService presentation)
    {
        _draftAuthority = draftAuthority ?? throw new ArgumentNullException(nameof(draftAuthority));
        _followUpJournal = followUpJournal;
        _recoveryJournal = recoveryJournal;
        _presentation = presentation ?? throw new ArgumentNullException(nameof(presentation));
        if ((followUpJournal is not null &&
             !PathsEqual(followUpJournal.DataDirectory, presentation.DataDirectory)) ||
            (recoveryJournal is not null &&
             !PathsEqual(recoveryJournal.DataDirectory, presentation.DataDirectory)))
        {
            throw new ArgumentException(
                "Attachment authority sources must share one data directory.",
                nameof(followUpJournal));
        }
    }

    public async Task<AttachmentReferenceAuthoritySnapshot> ReadAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var draft = _draftAuthority.ReadSnapshot();
        var presentation = _presentation.ReadReferenceSnapshotUnderMutationLease();
        if (_followUpJournal is null || _recoveryJournal is null)
        {
            return CreateUnavailableSnapshot(draft, presentation);
        }

        var followUp = await _followUpJournal.ReadAsync(cancellationToken).ConfigureAwait(false);
        var recovery = await _recoveryJournal.ReadAsync(cancellationToken).ConfigureAwait(false);
        var isHealthy = draft.IsHealthy &&
                        presentation.IsHealthy &&
                        IsHealthy(followUp) &&
                        IsHealthy(recovery);
        var operations = new List<AttachmentOperationReference>();
        var leaseContentIds = new HashSet<string>(StringComparer.Ordinal);
        var transactionContentIds = new HashSet<string>(StringComparer.Ordinal);
        var structuredRecords = followUp.Records
            .Where(record => record.SourceKind is
                FollowUpPayloadSourceKind.StructuredPreset or FollowUpPayloadSourceKind.WorkflowPreset)
            .ToDictionary(record => record.OperationId, StringComparer.OrdinalIgnoreCase);
        var presentationByLease = presentation.References
            .ToDictionary(reference => reference.LeaseId, StringComparer.Ordinal);

        foreach (var reference in presentation.References)
        {
            if (reference.State == AttachmentPresentationReferenceState.Materializing)
            {
                transactionContentIds.UnionWith(reference.ContentIds);
                continue;
            }

            if (reference.State == AttachmentPresentationReferenceState.CleanupPending)
            {
                continue;
            }

            if (!structuredRecords.TryGetValue(reference.OperationId, out var readyRecord) ||
                !PresentationMatches(readyRecord, reference))
            {
                isHealthy = false;
            }
        }

        foreach (var record in structuredRecords.Values)
        {
            if (record.AttachmentContentIds.Count == 0 && record.PresentationLeaseId is null)
            {
                continue;
            }

            if (record.AttachmentContentIds.Count == 0 || record.PresentationLeaseId is null)
            {
                isHealthy = false;
                continue;
            }

            if (!presentationByLease.TryGetValue(record.PresentationLeaseId, out var presentationReference) ||
                !PresentationMatches(record, presentationReference) ||
                presentationReference.State == AttachmentPresentationReferenceState.Materializing)
            {
                isHealthy = false;
            }

            if (record.State == FollowUpOperationState.Abandoned)
            {
                continue;
            }

            if (!TryMapState(record.State, out var state))
            {
                isHealthy = false;
                continue;
            }

            var successorCompletedNormally = record.CompletionTurnId is not null;
            var recoveryLineageClosed = IsRecoveryLineageClosed(record, recovery.Records);
            var operationPinned = false;
            foreach (var contentId in record.AttachmentContentIds.Distinct(StringComparer.Ordinal))
            {
                var operation = new AttachmentOperationReference(
                    contentId,
                    state,
                    successorCompletedNormally,
                    recoveryLineageClosed);
                operations.Add(operation);
                if (AttachmentReferenceCoordinator.IsOperationReferencePinned(operation, contentId))
                {
                    operationPinned = true;
                    leaseContentIds.Add(contentId);
                }
            }

            if (presentationReference?.State == AttachmentPresentationReferenceState.CleanupPending &&
                operationPinned)
            {
                isHealthy = false;
            }
        }

        return new AttachmentReferenceAuthoritySnapshot(
            IsHealthy: isHealthy,
            FollowUpJournalGeneration: Math.Max(0, followUp.Generation),
            RecoveryJournalGeneration: Math.Max(0, recovery.Generation),
            DraftVersion: Math.Max(0, draft.Version),
            LeaseVersion: Math.Max(0, presentation.LeaseVersion),
            TransactionVersion: Math.Max(0, presentation.TransactionVersion),
            DraftContentIds: draft.ContentIds,
            LeaseContentIds: leaseContentIds.Order(StringComparer.Ordinal).ToArray(),
            TransactionContentIds: transactionContentIds.Order(StringComparer.Ordinal).ToArray(),
            Operations: operations.ToArray());
    }

    private static AttachmentReferenceAuthoritySnapshot CreateUnavailableSnapshot(
        AttachmentDraftPinSnapshot draft,
        AttachmentPresentationReferenceSnapshot presentation) =>
        new(
            IsHealthy: false,
            FollowUpJournalGeneration: 0,
            RecoveryJournalGeneration: 0,
            DraftVersion: Math.Max(0, draft.Version),
            LeaseVersion: Math.Max(0, presentation.LeaseVersion),
            TransactionVersion: Math.Max(0, presentation.TransactionVersion),
            DraftContentIds: draft.ContentIds,
            LeaseContentIds: Array.Empty<string>(),
            TransactionContentIds: presentation.References
                .Where(reference =>
                    reference.State == AttachmentPresentationReferenceState.Materializing)
                .SelectMany(reference => reference.ContentIds)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            Operations: Array.Empty<AttachmentOperationReference>());

    internal static bool PresentationMatches(
        FollowUpOperationRecord record,
        AttachmentPresentationReference reference) =>
        string.Equals(record.OperationId, reference.OperationId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(record.PresentationLeaseId, reference.LeaseId, StringComparison.Ordinal) &&
        string.Equals(record.PayloadDigest, reference.PayloadDigest, StringComparison.Ordinal) &&
        record.AttachmentContentIds
            .Distinct(StringComparer.Ordinal)
            .SequenceEqual(reference.ContentIds, StringComparer.Ordinal);

    internal static bool IsRecoveryLineageClosed(
        FollowUpOperationRecord record,
        IReadOnlyList<RecoveryOperationRecord> recoveryRecords) =>
        record.State == FollowUpOperationState.Confirmed &&
        record.NewTurnId is not null &&
        recoveryRecords.Any(recovery =>
            string.Equals(recovery.ThreadId, record.ThreadId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(recovery.FailedTurnId, record.NewTurnId, StringComparison.OrdinalIgnoreCase) &&
            recovery.State == RecoveryOperationState.Abandoned);

    private static bool TryMapState(
        FollowUpOperationState source,
        out AttachmentOperationReferenceState state)
    {
        state = source switch
        {
            FollowUpOperationState.Prepared => AttachmentOperationReferenceState.Prepared,
            FollowUpOperationState.Dispatching => AttachmentOperationReferenceState.Dispatching,
            FollowUpOperationState.Retryable => AttachmentOperationReferenceState.Retryable,
            FollowUpOperationState.Uncertain => AttachmentOperationReferenceState.Uncertain,
            FollowUpOperationState.Confirmed => AttachmentOperationReferenceState.Confirmed,
            _ => default
        };
        return source is FollowUpOperationState.Prepared or FollowUpOperationState.Dispatching or
            FollowUpOperationState.Retryable or FollowUpOperationState.Uncertain or
            FollowUpOperationState.Confirmed;
    }

    private static bool IsHealthy(FollowUpJournalSnapshot snapshot) =>
        !snapshot.RequiresConservativeRecovery &&
        snapshot.ReadStatus is FollowUpJournalReadStatus.Missing or FollowUpJournalReadStatus.Healthy;

    private static bool IsHealthy(RecoveryJournalSnapshot snapshot) =>
        !snapshot.RequiresConservativeRecovery &&
        snapshot.ReadStatus is RecoveryJournalReadStatus.Missing or RecoveryJournalReadStatus.Healthy;

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(left),
            Path.TrimEndingDirectorySeparator(right),
            StringComparison.OrdinalIgnoreCase);
}
