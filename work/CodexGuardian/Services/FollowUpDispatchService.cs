using CodexGuardian.Models;
using System.Text.Json;

namespace CodexGuardian.Services;

internal interface IFollowUpStateReader
{
    Task<TurnSnapshot?> ReadLatestTurnAsync(string threadId, CancellationToken cancellationToken);

    Task<ThreadSummary> ReadThreadForRecoveryAsync(string threadId, CancellationToken cancellationToken);

    Task<TurnSnapshot?> FindRecentTurnByClientMessageIdAsync(
        string threadId,
        string clientMessageId,
        CancellationToken cancellationToken);
}

internal interface IFollowUpOwnerStateGuard : IAsyncDisposable
{
    DesktopThreadOwnerStateSnapshot Snapshot { get; }

    bool IsCurrent { get; }
}

internal sealed record FollowUpOwnerStateGuardAcquireResult(
    DesktopThreadOwnerStateGuardStatus Status,
    IFollowUpOwnerStateGuard? Guard,
    string Detail)
{
    internal bool IsAvailable => Status == DesktopThreadOwnerStateGuardStatus.Available && Guard is not null;
}

internal interface IFollowUpDesktopChannel
{
    bool SupportsGuardedAutomaticSend { get; }

    Task<FollowUpOwnerStateGuardAcquireResult> AcquireThreadOwnerStateGuardAsync(
        string threadId,
        CancellationToken cancellationToken);

    JsonElement EncodeStructuredTurnInput(
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        DesktopStructuredInputCapabilityLease capabilityLease,
        IReadOnlyDictionary<string, string> presentationPaths);

    Task<DesktopStartTurnResult> StartTextTurnAsync(
        string threadId,
        string message,
        string clientMessageId,
        CancellationToken cancellationToken,
        Func<bool> canStartWrite);

    Task<DesktopStartTurnResult> StartStructuredTurnAsync(
        string threadId,
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        DesktopStructuredInputCapabilityLease capabilityLease,
        IReadOnlyDictionary<string, string> presentationPaths,
        string clientMessageId,
        CancellationToken cancellationToken,
        Func<bool> canStartWrite);
}

internal interface IFollowUpOwnerActivator
{
    Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
        string threadId,
        CancellationToken cancellationToken);

    DesktopUserActivityResult CheckUserActivity();
}

internal sealed class AppServerFollowUpStateReader : IFollowUpStateReader
{
    private readonly AppServerClient _inner;
    private readonly LocalConversationHistoryReader _localHistory;

    internal AppServerFollowUpStateReader(
        AppServerClient inner,
        LocalConversationHistoryReader? localHistory = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _localHistory = localHistory ?? new LocalConversationHistoryReader();
    }

    public async Task<TurnSnapshot?> ReadLatestTurnAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        var appServerTask = _inner.ReadLatestTurnAsync(threadId, cancellationToken);
        var localTask = _localHistory.ReadLatestTerminalEventAsync(threadId, cancellationToken);
        await Task.WhenAll(appServerTask, localTask).ConfigureAwait(false);
        return ReconcileLatestTurn(appServerTask.Result, localTask.Result);
    }

    public Task<ThreadSummary> ReadThreadForRecoveryAsync(string threadId, CancellationToken cancellationToken) =>
        _inner.ReadThreadForRecoveryAsync(threadId, cancellationToken);

    public Task<TurnSnapshot?> FindRecentTurnByClientMessageIdAsync(
        string threadId,
        string clientMessageId,
        CancellationToken cancellationToken) =>
        _inner.FindRecentTurnByClientMessageIdAsync(
            threadId,
            clientMessageId,
            cancellationToken: cancellationToken);

    internal static TurnSnapshot? ReconcileLatestTurn(
        TurnSnapshot? appServerTurn,
        LocalConversationTerminalEvent? localTerminal) =>
        LocalConversationHistoryReader.ReconcileLatestTurn(appServerTurn, localTerminal);
}

internal sealed class DesktopFollowUpChannel(DesktopIpcClient inner) : IFollowUpDesktopChannel
{
    public bool SupportsGuardedAutomaticSend =>
        inner.GetRecoveryTransportCapabilities(RecoveryActionKind.SendContinue)
            .IsGuardedAutomaticRecoveryEligible;

    public async Task<FollowUpOwnerStateGuardAcquireResult> AcquireThreadOwnerStateGuardAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        var result = await inner.AcquireThreadOwnerStateGuardAsync(threadId, cancellationToken)
            .ConfigureAwait(false);
        return new FollowUpOwnerStateGuardAcquireResult(
            result.Status,
            result.Guard is null ? null : new DesktopFollowUpOwnerStateGuard(result.Guard),
            result.Detail);
    }

    public JsonElement EncodeStructuredTurnInput(
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        DesktopStructuredInputCapabilityLease capabilityLease,
        IReadOnlyDictionary<string, string> presentationPaths) =>
        inner.EncodeStructuredTurnInput(
            payload,
            capabilities,
            capabilityLease,
            presentationPaths);

    public Task<DesktopStartTurnResult> StartTextTurnAsync(
        string threadId,
        string message,
        string clientMessageId,
        CancellationToken cancellationToken,
        Func<bool> canStartWrite) =>
        inner.StartTextTurnAsync(
            threadId,
            message,
            clientMessageId,
            cancellationToken,
            canStartWrite);

    public Task<DesktopStartTurnResult> StartStructuredTurnAsync(
        string threadId,
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        DesktopStructuredInputCapabilityLease capabilityLease,
        IReadOnlyDictionary<string, string> presentationPaths,
        string clientMessageId,
        CancellationToken cancellationToken,
        Func<bool> canStartWrite) =>
        inner.StartStructuredTurnAsync(
            threadId,
            payload,
            capabilities,
            capabilityLease,
            presentationPaths,
            clientMessageId,
            cancellationToken,
            canStartWrite);

    private sealed class DesktopFollowUpOwnerStateGuard(DesktopThreadOwnerStateGuard innerGuard)
        : IFollowUpOwnerStateGuard
    {
        public DesktopThreadOwnerStateSnapshot Snapshot => innerGuard.Snapshot;

        public bool IsCurrent => innerGuard.IsCurrent;

        public ValueTask DisposeAsync() => innerGuard.DisposeAsync();
    }
}

internal sealed class FollowUpOwnerActivator(DesktopThreadOwnerActivator inner) : IFollowUpOwnerActivator
{
    public Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
        string threadId,
        CancellationToken cancellationToken) =>
        inner.EnsureOwnerAsync(threadId, cancellationToken);

    public DesktopUserActivityResult CheckUserActivity() => inner.CheckUserActivity();
}

internal enum FollowUpDispatchFailureKind
{
    None,
    StateChanged,
    DesktopUnavailable,
    DesktopOwnerUnavailable,
    UserActive,
    DesktopIncompatible,
    PolicyChanged,
    PersistenceFailed,
    WorkflowBlocked,
    Uncertain
}

internal sealed record FollowUpDispatchResult(
    bool Success,
    string Message,
    FollowUpDispatchFailureKind FailureKind = FollowUpDispatchFailureKind.None,
    string? NewTurnId = null)
{
    internal static FollowUpDispatchResult Ok(string message, string? newTurnId = null) =>
        new(true, message, NewTurnId: newTurnId);

    internal static FollowUpDispatchResult Failed(
        string message,
        FollowUpDispatchFailureKind failureKind) =>
        new(false, message, failureKind);
}

internal sealed record FollowUpWorkflowDispatchCheckpoint(
    string TargetConversationId,
    string ExpectedTurnId,
    long TargetOwnerRevision,
    string PayloadDigest);

internal sealed record FollowUpWorkflowDispatchContext(
    string OperationId,
    string ClientMessageId,
    FollowUpTriggerKind JournalTrigger,
    DateTimeOffset? ScheduledAtUtc,
    Func<FollowUpWorkflowDispatchCheckpoint, CancellationToken, Task<bool>> AuthorizeWriteAsync);

internal sealed class FollowUpDispatchService
{
    private static readonly TimeSpan DurableWriteTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DesktopCommitTimeout = TimeSpan.FromSeconds(40);
    private static readonly AttachmentPresentationRequirements ConservativeImagePresentation =
        new(
            SupportsSeparateDisplayName: false,
            RequiresFileNameSuffix: true,
            AllowHardLinks: false);

    private readonly IFollowUpStateReader _stateReader;
    private readonly IFollowUpDesktopChannel _desktop;
    private readonly IFollowUpOwnerActivator _ownerActivator;
    private readonly FollowUpOperationJournal _journal;
    private readonly GuardianLog _log;
    private readonly IRecoveryInterferenceGuard? _interferenceGuard;
    private readonly IDesktopStructuredInputCapabilityProvider? _structuredCapabilities;
    private readonly ManagedAttachmentStore? _attachmentStore;
    private readonly AttachmentPresentationLeaseService? _presentationLeases;
    private readonly AttachmentDraftAuthority? _attachmentPins;
    private readonly ThreadActionCoordinator? _threadActions;
    private readonly SemaphoreSlim[] _operationLeases = Enumerable.Range(0, 64)
        .Select(static _ => new SemaphoreSlim(1, 1))
        .ToArray();

    internal FollowUpDispatchService(
        AppServerClient stateReader,
        DesktopIpcClient desktop,
        DesktopThreadOwnerActivator ownerActivator,
        FollowUpOperationJournal journal,
        GuardianLog log,
        IRecoveryInterferenceGuard? interferenceGuard = null,
        IDesktopStructuredInputCapabilityProvider? structuredCapabilities = null,
        ManagedAttachmentStore? attachmentStore = null,
        AttachmentPresentationLeaseService? presentationLeases = null,
        AttachmentDraftAuthority? attachmentPins = null,
        ThreadActionCoordinator? threadActions = null)
        : this(
            new AppServerFollowUpStateReader(stateReader),
            new DesktopFollowUpChannel(desktop),
            new FollowUpOwnerActivator(ownerActivator),
            journal,
            log,
            interferenceGuard,
            structuredCapabilities,
            attachmentStore,
            presentationLeases,
            attachmentPins,
            threadActions)
    {
    }

    internal FollowUpDispatchService(
        IFollowUpStateReader stateReader,
        IFollowUpDesktopChannel desktop,
        IFollowUpOwnerActivator ownerActivator,
        FollowUpOperationJournal journal,
        GuardianLog log,
        IRecoveryInterferenceGuard? interferenceGuard = null,
        IDesktopStructuredInputCapabilityProvider? structuredCapabilities = null,
        ManagedAttachmentStore? attachmentStore = null,
        AttachmentPresentationLeaseService? presentationLeases = null,
        AttachmentDraftAuthority? attachmentPins = null,
        ThreadActionCoordinator? threadActions = null)
    {
        _stateReader = stateReader ?? throw new ArgumentNullException(nameof(stateReader));
        _desktop = desktop ?? throw new ArgumentNullException(nameof(desktop));
        _ownerActivator = ownerActivator ?? throw new ArgumentNullException(nameof(ownerActivator));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _interferenceGuard = interferenceGuard;
        _structuredCapabilities = structuredCapabilities;
        _attachmentStore = attachmentStore;
        _presentationLeases = presentationLeases;
        _attachmentPins = attachmentPins;
        _threadActions = threadActions;
        var structuredDependencyCount = new object?[]
        {
            structuredCapabilities,
            attachmentStore,
            presentationLeases,
            attachmentPins
        }.Count(value => value is not null);
        if (structuredDependencyCount is > 0 and < 4)
        {
            throw new ArgumentException(
                "Structured follow-up dispatch dependencies must be supplied as one complete set.",
                nameof(structuredCapabilities));
        }
    }

    internal Task<FollowUpJournalSnapshot> ReadJournalAsync(
        CancellationToken cancellationToken = default) =>
        _journal.ReadAsync(cancellationToken);

    internal Task<FollowUpOperationRecord?> MarkCompletedAsync(
        string threadId,
        string completedTurnId,
        string? recoveredFromTurnId,
        CancellationToken cancellationToken = default) =>
        // An id-less turn has no journal record to complete. The journal rejects a non-UUID id with
        // ArgumentException, which GuardianEngine treated as a persistence outage and answered by
        // setting RequiresConservativeRecovery -- blocking queued sends for every thread, not just this
        // one. Nothing to mark is not a failure.
        Guid.TryParse(completedTurnId, out _)
            ? _journal.MarkCompletedAsync(
                threadId,
                completedTurnId,
                recoveredFromTurnId,
                cancellationToken)
            : Task.FromResult<FollowUpOperationRecord?>(null);

    internal async Task<int> PruneInactiveCompletedAsync(
        IReadOnlyDictionary<string, ThreadFollowUpSettings> configured,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyCollection<string> protectedOperationIds;
        if (_presentationLeases is not null)
        {
            var presentation = await _presentationLeases
                .ReadReferenceSnapshotAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!presentation.IsHealthy)
            {
                return 0;
            }

            protectedOperationIds = presentation.References
                .Select(reference => reference.OperationId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        else
        {
            var journal = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (journal.RequiresConservativeRecovery ||
                journal.ReadStatus is not FollowUpJournalReadStatus.Missing and not
                    FollowUpJournalReadStatus.Healthy)
            {
                return 0;
            }

            protectedOperationIds = journal.Records
                .Where(record => record.PresentationLeaseId is not null)
                .Select(record => record.OperationId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        return await _journal.PruneInactiveCompletedAsync(
                configured,
                protectedOperationIds,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<FollowUpDispatchResult> ExecuteAsync(
        ThreadSummary thread,
        TurnSnapshot expectedCompletedTurn,
        FollowUpMessageDefinition definition,
        bool includeSubAgents,
        Func<bool> isDispatchAllowed,
        CancellationToken cancellationToken)
    {
        await using var threadActionLease = _threadActions is null
            ? null
            : await _threadActions.AcquireAsync(thread.Id, cancellationToken)
                .ConfigureAwait(false);
        var lease = _operationLeases[
            (int)((uint)StringComparer.OrdinalIgnoreCase.GetHashCode(thread.Id) % _operationLeases.Length)];
        await lease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ExecuteCoreAsync(
                    thread,
                    expectedCompletedTurn,
                    definition,
                    includeSubAgents,
                    isDispatchAllowed,
                    workflowContext: null,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            lease.Release();
        }
    }

    internal async Task<FollowUpDispatchResult> ExecuteWorkflowAsync(
        ThreadSummary thread,
        TurnSnapshot expectedCompletedTurn,
        FollowUpMessageDefinition definition,
        bool includeSubAgents,
        Func<bool> isDispatchAllowed,
        FollowUpWorkflowDispatchContext workflowContext,
        CancellationToken cancellationToken)
    {
        workflowContext = NormalizeWorkflowContext(workflowContext);
        await using var threadActionLease = _threadActions is null
            ? null
            : await _threadActions.AcquireAsync(thread.Id, cancellationToken)
                .ConfigureAwait(false);
        var lease = _operationLeases[
            (int)((uint)StringComparer.OrdinalIgnoreCase.GetHashCode(thread.Id) % _operationLeases.Length)];
        await lease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ExecuteCoreAsync(
                    thread,
                    expectedCompletedTurn,
                    definition,
                    includeSubAgents,
                    isDispatchAllowed,
                    workflowContext,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            lease.Release();
        }
    }

    internal async Task<FollowUpDispatchResult> ReconcilePendingAsync(
        ThreadSummary thread,
        FollowUpOperationRecord operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(thread);
        ArgumentNullException.ThrowIfNull(operation);
        if (!string.Equals(operation.ThreadId, thread.Id, StringComparison.OrdinalIgnoreCase) ||
            operation.State is not FollowUpOperationState.Dispatching and not FollowUpOperationState.Uncertain)
        {
            return FollowUpDispatchResult.Failed(
                "The pending follow-up reconciliation target is no longer valid.",
                FollowUpDispatchFailureKind.StateChanged);
        }

        var lease = _operationLeases[
            (int)((uint)StringComparer.OrdinalIgnoreCase.GetHashCode(thread.Id) % _operationLeases.Length)];
        await lease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (operation.State == FollowUpOperationState.Dispatching)
            {
                operation = await TransitionAfterDispatchAsync(
                        operation,
                        FollowUpOperationState.Uncertain,
                        thread.Id,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (operation.State == FollowUpOperationState.Confirmed)
                {
                    return FollowUpDispatchResult.Ok(
                        "The follow-up was already confirmed while reconciliation was starting.",
                        operation.NewTurnId);
                }

                if (operation.State != FollowUpOperationState.Uncertain)
                {
                    return FollowUpDispatchResult.Failed(
                        "The pending dispatch could not be durably moved into conservative reconciliation.",
                        FollowUpDispatchFailureKind.PersistenceFailed);
                }
            }

            return await ReconcileUncertainAsync(thread, operation, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            lease.Release();
        }
    }

    internal async Task<FollowUpDispatchResult> ReconcileWorkflowAsync(
        ThreadSummary thread,
        string operationId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(thread);
        if (!Guid.TryParse(operationId, out var parsedOperationId) || parsedOperationId == Guid.Empty)
        {
            throw new ArgumentException("A workflow operation UUID is required.", nameof(operationId));
        }

        operationId = parsedOperationId.ToString("D");
        var snapshot = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (snapshot.ReadStatus is not FollowUpJournalReadStatus.Missing and not
                FollowUpJournalReadStatus.Healthy and not FollowUpJournalReadStatus.RecoveredFromBackup)
        {
            return FollowUpDispatchResult.Failed(
                "The workflow follow-up journal is unavailable for conservative reconciliation.",
                FollowUpDispatchFailureKind.PersistenceFailed);
        }

        var operation = snapshot.Records.SingleOrDefault(record => string.Equals(
            record.OperationId,
            operationId,
            StringComparison.OrdinalIgnoreCase));
        if (operation is null || operation.SourceKind != FollowUpPayloadSourceKind.WorkflowPreset ||
            !string.Equals(operation.ThreadId, thread.Id, StringComparison.OrdinalIgnoreCase))
        {
            return FollowUpDispatchResult.Failed(
                "No authoritative workflow follow-up operation exists to reconcile; nothing was sent.",
                FollowUpDispatchFailureKind.Uncertain);
        }

        if (operation.State == FollowUpOperationState.Confirmed)
        {
            return FollowUpDispatchResult.Ok(
                "The workflow follow-up was already confirmed by its durable journal.",
                operation.NewTurnId);
        }

        return operation.State is FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain
            ? await ReconcilePendingAsync(thread, operation, cancellationToken).ConfigureAwait(false)
            : FollowUpDispatchResult.Failed(
                "The workflow follow-up has no possibly-sent operation to reconcile; nothing was sent.",
                FollowUpDispatchFailureKind.Uncertain);
    }

    private async Task<FollowUpDispatchResult> ExecuteCoreAsync(
        ThreadSummary thread,
        TurnSnapshot expectedCompletedTurn,
        FollowUpMessageDefinition definition,
        bool includeSubAgents,
        Func<bool> isDispatchAllowed,
        FollowUpWorkflowDispatchContext? workflowContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(thread);
        ArgumentNullException.ThrowIfNull(expectedCompletedTurn);
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(isDispatchAllowed);
        if (definition.Attachments.Count > 0 && !HasStructuredDispatchDependencies)
        {
            return FollowUpDispatchResult.Failed(
                "Verified Desktop attachment dispatch is unavailable for the current installation.",
                FollowUpDispatchFailureKind.DesktopIncompatible);
        }

        StructuredPresetPayload payload;
        try
        {
            payload = StructuredPresetPayload.Create(definition.Message, definition.Attachments);
        }
        catch (ArgumentException)
        {
            return FollowUpDispatchResult.Failed(
                "The follow-up payload is no longer valid.",
                FollowUpDispatchFailureKind.StateChanged);
        }

        var hasAttachments = payload.Attachments.Count > 0;
        var message = payload.Text;
        var journalTrigger = workflowContext?.JournalTrigger ?? definition.Trigger;
        var journalScheduledAtUtc = workflowContext?.ScheduledAtUtc ?? definition.ScheduledAtUtc;
        if (!FollowUpQueuePlanner.IsNormalCompletion(expectedCompletedTurn))
        {
            return FollowUpDispatchResult.Failed(
                "The follow-up or its expected normal completion is no longer valid.",
                FollowUpDispatchFailureKind.StateChanged);
        }

        if (!IsPolicyAllowed(isDispatchAllowed))
        {
            return FollowUpDispatchResult.Failed(
                "Preset dispatch is disabled or its authorization changed.",
                FollowUpDispatchFailureKind.PolicyChanged);
        }

        if (!_desktop.SupportsGuardedAutomaticSend)
        {
            return FollowUpDispatchResult.Failed(
                "Codex Desktop does not expose the guarded stock owner contract required for follow-up messages.",
                FollowUpDispatchFailureKind.DesktopIncompatible);
        }

        if (hasAttachments && !HasStructuredDispatchDependencies)
        {
            return FollowUpDispatchResult.Failed(
                "Verified Desktop attachment dispatch is unavailable for the current installation.",
                FollowUpDispatchFailureKind.DesktopIncompatible);
        }

        IDisposable? acquiredAttachmentPins = null;
        if (hasAttachments)
        {
            try
            {
                acquiredAttachmentPins = _attachmentPins!.AcquireTransientPins(payload.Attachments);
            }
            catch (Exception exception) when (
                exception is ArgumentException or InvalidOperationException or OverflowException)
            {
                return FollowUpDispatchResult.Failed(
                    "The attachment reference authority is unavailable; nothing was sent.",
                    FollowUpDispatchFailureKind.DesktopUnavailable);
            }
        }

        using var attachmentPinLease = acquiredAttachmentPins;
        var operationId = workflowContext?.OperationId ?? (hasAttachments
            ? FollowUpOperationJournal.CreateStructuredOperationId(
                thread.Id,
                definition.Id,
                expectedCompletedTurn.Id,
                payload.PayloadDigest)
            : FollowUpOperationJournal.CreateOperationId(
                thread.Id,
                definition.Id,
                expectedCompletedTurn.Id));
        var clientMessageId = workflowContext?.ClientMessageId ??
                              FollowUpOperationJournal.CreateClientMessageId(operationId);
        StructuredDispatchContext? structuredContext = null;
        if (hasAttachments)
        {
            try
            {
                var capabilities = await _structuredCapabilities!.ReadAsync(cancellationToken)
                    .ConfigureAwait(false);
                var capabilityLease = capabilities.AcquireLease(payload);
                var managedObjects = new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal);
                foreach (var attachment in payload.Attachments)
                {
                    if (managedObjects.ContainsKey(attachment.ContentId))
                    {
                        continue;
                    }

                    var managedObject = await _attachmentStore!
                        .ResolveVerifiedAsync(attachment, cancellationToken)
                        .ConfigureAwait(false);
                    if (managedObject is null)
                    {
                        return FollowUpDispatchResult.Failed(
                            "A managed attachment changed before dispatch; nothing was sent.",
                            FollowUpDispatchFailureKind.StateChanged);
                    }

                    managedObjects.Add(attachment.ContentId, managedObject);
                }

                var presentationLease = await _presentationLeases!.AcquireAsync(
                        operationId,
                        payload,
                        managedObjects,
                        ConservativeImagePresentation,
                        cancellationToken)
                    .ConfigureAwait(false);
                var nativeInput = _desktop.EncodeStructuredTurnInput(
                    payload,
                    capabilities,
                    capabilityLease,
                    presentationLease.PresentationPaths);
                structuredContext = new StructuredDispatchContext(
                    payload,
                    capabilityLease,
                    presentationLease,
                    RecoveryStructuredInputCanonicalizer.ComputeDigest(nativeInput));
            }
            catch (DesktopStructuredInputCapabilityException)
            {
                return FollowUpDispatchResult.Failed(
                    "The current Desktop structured-input capability does not support this payload.",
                    FollowUpDispatchFailureKind.DesktopIncompatible);
            }
            catch (AttachmentPresentationException exception)
            {
                _log.Trace("Attachment presentation preparation failed: " + exception.Code, thread.Id);
                return FollowUpDispatchResult.Failed(
                    "The attachment presentation lease could not be prepared; nothing was sent.",
                    FollowUpDispatchFailureKind.DesktopUnavailable);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or InvalidDataException or
                    NotSupportedException)
            {
                _log.Trace("Structured follow-up preparation failed: " + exception.Message, thread.Id);
                return FollowUpDispatchResult.Failed(
                    "The structured follow-up could not be prepared; nothing was sent.",
                    FollowUpDispatchFailureKind.DesktopUnavailable);
            }
        }

        FollowUpOperationRecord operation;
        try
        {
            operation = hasAttachments || workflowContext is not null
                ? (await _journal.GetOrCreateStructuredAsync(
                        operationId,
                        thread.Id,
                        definition.Id,
                        journalTrigger,
                        expectedCompletedTurn.Id,
                        journalScheduledAtUtc,
                        payload,
                        structuredContext?.PresentationLease.LeaseId,
                        workflowContext is null
                            ? FollowUpPayloadSourceKind.StructuredPreset
                            : FollowUpPayloadSourceKind.WorkflowPreset,
                        clientMessageId,
                        cancellationToken,
                        structuredContext?.ReplayInputDigest)
                    .ConfigureAwait(false)).Record
                : (await _journal.GetOrCreateAsync(
                        operationId,
                        thread.Id,
                        definition.Id,
                        journalTrigger,
                        expectedCompletedTurn.Id,
                        journalScheduledAtUtc,
                        FollowUpOperationJournal.ComputeMessageHash(message),
                        clientMessageId,
                        cancellationToken)
                    .ConfigureAwait(false)).Record;
        }
        catch (Exception exception) when (IsPersistenceException(exception))
        {
            _log.Error("Follow-up journal preparation failed; no message was sent: " + exception.Message, thread.Id);
            return FollowUpDispatchResult.Failed(
                "The follow-up journal could not commit a dispatch identity; nothing was sent.",
                FollowUpDispatchFailureKind.PersistenceFailed);
        }

        if (operation.State == FollowUpOperationState.Confirmed)
        {
            return FollowUpDispatchResult.Ok(
                "The follow-up was already confirmed by its durable journal.",
                operation.NewTurnId);
        }

        if (operation.State == FollowUpOperationState.Abandoned)
        {
            return FollowUpDispatchResult.Failed(
                "The stale follow-up operation is closed and will not be sent for this completion.",
                FollowUpDispatchFailureKind.StateChanged);
        }

        if (operation.State == FollowUpOperationState.Dispatching)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    FollowUpOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            if (operation.State != FollowUpOperationState.Uncertain)
            {
                return FollowUpDispatchResult.Failed(
                    "A prior dispatch could not be moved into conservative reconciliation; nothing was sent.",
                    FollowUpDispatchFailureKind.PersistenceFailed);
            }
        }

        if (operation.State == FollowUpOperationState.Uncertain)
        {
            return await ReconcileUncertainAsync(thread, operation, cancellationToken).ConfigureAwait(false);
        }

        var latest = await _stateReader.ReadLatestTurnAsync(thread.Id, cancellationToken).ConfigureAwait(false);
        var stateCheck = ValidateExpectedNormalCompletion(latest, expectedCompletedTurn.Id);
        if (stateCheck is not null)
        {
            await AbandonBeforeDispatchAsync(operation, cancellationToken).ConfigureAwait(false);
            return stateCheck;
        }

        var eligibility = await RevalidateEligibilityAsync(thread.Id, includeSubAgents, cancellationToken)
            .ConfigureAwait(false);
        if (eligibility is not null)
        {
            return eligibility;
        }

        var activation = await _ownerActivator.EnsureOwnerAsync(thread.Id, cancellationToken).ConfigureAwait(false);
        _log.WriteDispatchGate(
            thread.Id,
            expectedCompletedTurn.Id,
            "followUpOwnerActivation",
            activation.Status.ToString(),
            activation.IsAvailable);
        if (!activation.IsAvailable)
        {
            return activation.Status switch
            {
                DesktopThreadOwnerActivationStatus.Incompatible => FollowUpDispatchResult.Failed(
                    activation.Detail,
                    FollowUpDispatchFailureKind.DesktopIncompatible),
                DesktopThreadOwnerActivationStatus.DeferredForUserActivity => FollowUpDispatchResult.Failed(
                    activation.Detail,
                    FollowUpDispatchFailureKind.UserActive),
                _ => FollowUpDispatchResult.Failed(
                    activation.Detail,
                    FollowUpDispatchFailureKind.DesktopOwnerUnavailable)
            };
        }

        var guardResult = await _desktop.AcquireThreadOwnerStateGuardAsync(thread.Id, cancellationToken)
            .ConfigureAwait(false);
        _log.WriteDispatchGate(
            thread.Id,
            expectedCompletedTurn.Id,
            "followUpOwnerSnapshot",
            guardResult.Status.ToString(),
            guardResult.IsAvailable);
        if (!guardResult.IsAvailable)
        {
            return FollowUpDispatchResult.Failed(
                guardResult.Detail,
                guardResult.Status == DesktopThreadOwnerStateGuardStatus.Incompatible
                    ? FollowUpDispatchFailureKind.DesktopIncompatible
                    : FollowUpDispatchFailureKind.DesktopOwnerUnavailable);
        }

        await using var ownerGuard = guardResult.Guard!;
        var ownerCheck = ValidateOwnerNormalCompletion(ownerGuard.Snapshot, expectedCompletedTurn.Id);
        if (ownerCheck is not null)
        {
            await AbandonBeforeDispatchAsync(operation, cancellationToken).ConfigureAwait(false);
            return ownerCheck;
        }

        if (!IsPolicyAllowed(isDispatchAllowed))
        {
            return FollowUpDispatchResult.Failed(
                "The follow-up policy changed before dispatch.",
                FollowUpDispatchFailureKind.PolicyChanged);
        }

        latest = await _stateReader.ReadLatestTurnAsync(thread.Id, cancellationToken).ConfigureAwait(false);
        stateCheck = ValidateExpectedNormalCompletion(latest, expectedCompletedTurn.Id);
        if (stateCheck is not null)
        {
            await AbandonBeforeDispatchAsync(operation, cancellationToken).ConfigureAwait(false);
            return stateCheck;
        }

        eligibility = await RevalidateEligibilityAsync(thread.Id, includeSubAgents, cancellationToken)
            .ConfigureAwait(false);
        if (eligibility is not null)
        {
            return eligibility;
        }

        if (!ownerGuard.IsCurrent)
        {
            return FollowUpDispatchResult.Failed(
                "The Desktop owner changed during final follow-up validation.",
                FollowUpDispatchFailureKind.DesktopOwnerUnavailable);
        }

        var activity = await ValidateUserIdleAsync(
                thread.Id,
                expectedCompletedTurn.Id,
                "followUpBeforeDispatchIntent",
                cancellationToken)
            .ConfigureAwait(false);
        if (activity is not null)
        {
            return activity;
        }

        if (structuredContext is not null &&
            await RevalidateStructuredDispatchAsync(
                    operation,
                    structuredContext,
                    cancellationToken)
                .ConfigureAwait(false) is null)
        {
            return FollowUpDispatchResult.Failed(
                "The structured payload capability or presentation lease changed before dispatch.",
                FollowUpDispatchFailureKind.DesktopIncompatible);
        }

        var dispatching = await TransitionBeforeDispatchAsync(operation, cancellationToken).ConfigureAwait(false);
        if (dispatching is null)
        {
            return FollowUpDispatchResult.Failed(
                "The follow-up dispatch intent could not be committed; nothing was sent.",
                FollowUpDispatchFailureKind.PersistenceFailed);
        }

        operation = dispatching;
        if (workflowContext is not null)
        {
            bool authorized;
            try
            {
                authorized = await workflowContext.AuthorizeWriteAsync(
                        new FollowUpWorkflowDispatchCheckpoint(
                            thread.Id,
                            expectedCompletedTurn.Id,
                            ownerGuard.Snapshot.Revision,
                            payload.PayloadDigest),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return await ReturnRetryableBeforeWriteAsync(
                        operation,
                        thread.Id,
                        "Workflow authorization was canceled before the Desktop write.",
                        FollowUpDispatchFailureKind.PolicyChanged,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (IsPersistenceException(exception))
            {
                _log.Error(
                    "Workflow dispatch authorization failed before the Desktop write: " + exception.Message,
                    thread.Id);
                return await ReturnRetryableBeforeWriteAsync(
                        operation,
                        thread.Id,
                        "Workflow authorization could not commit its durable intent; nothing was sent.",
                        FollowUpDispatchFailureKind.PersistenceFailed,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!authorized)
            {
                return await AbandonRejectedAsync(
                        operation,
                        thread.Id,
                        "The workflow correlation or action state rejected the final Desktop write.",
                        FollowUpDispatchFailureKind.WorkflowBlocked,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        if (!IsPolicyAllowed(isDispatchAllowed) || cancellationToken.IsCancellationRequested || !ownerGuard.IsCurrent)
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    "The policy or Desktop owner changed before the follow-up write; the unsent operation remains retryable.",
                    FollowUpDispatchFailureKind.PolicyChanged,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        RecoveryInterferenceSnapshot? finalObservation = null;
        try
        {
            activity = await ValidateUserIdleAsync(
                    thread.Id,
                    expectedCompletedTurn.Id,
                    "followUpBeforeStartTurn",
                    cancellationToken,
                    observation => finalObservation = observation)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    "Monitoring stopped during the final editor check; the unsent follow-up remains retryable.",
                    FollowUpDispatchFailureKind.PolicyChanged,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (activity is not null)
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    activity.Message,
                    activity.FailureKind,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (!IsPolicyAllowed(isDispatchAllowed) || cancellationToken.IsCancellationRequested)
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    "The follow-up policy changed after the final editor check; the unsent operation remains retryable.",
                    FollowUpDispatchFailureKind.PolicyChanged,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (!ownerGuard.IsCurrent)
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    "The Desktop owner changed after the final editor check; the unsent operation remains retryable.",
                    FollowUpDispatchFailureKind.DesktopOwnerUnavailable,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        DesktopStructuredInputCapabilities? finalStructuredCapabilities = null;
        if (structuredContext is not null)
        {
            finalStructuredCapabilities = await RevalidateStructuredDispatchAsync(
                    operation,
                    structuredContext,
                    cancellationToken)
                .ConfigureAwait(false);
            if (finalStructuredCapabilities is null)
            {
                return await ReturnRetryableBeforeWriteAsync(
                        operation,
                        thread.Id,
                        "The structured payload capability or presentation lease changed before the Desktop write.",
                        FollowUpDispatchFailureKind.DesktopIncompatible,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        using var commit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        commit.CancelAfter(DesktopCommitTimeout);
        using var dispatchGuardLifetime = new CancellationTokenSource();
        var interferenceWatch = WatchDispatchInterferenceAsync(
            finalObservation,
            commit,
            dispatchGuardLifetime.Token);
        try
        {
            var started = structuredContext is null
                ? await _desktop.StartTextTurnAsync(
                        thread.Id,
                        message,
                        operation.ClientMessageId,
                        commit.Token,
                        () => IsPolicyAllowed(isDispatchAllowed) && ownerGuard.IsCurrent)
                    .ConfigureAwait(false)
                : await _desktop.StartStructuredTurnAsync(
                        thread.Id,
                        structuredContext.Payload,
                        finalStructuredCapabilities!,
                        structuredContext.CapabilityLease,
                        structuredContext.PresentationLease.PresentationPaths,
                        operation.ClientMessageId,
                        commit.Token,
                        () => IsPolicyAllowed(isDispatchAllowed) && ownerGuard.IsCurrent)
                    .ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(started.TurnId) ||
                string.Equals(started.TurnId, expectedCompletedTurn.Id, StringComparison.OrdinalIgnoreCase))
            {
                await TransitionAfterDispatchAsync(
                        operation,
                        FollowUpOperationState.Uncertain,
                        thread.Id,
                        cancellationToken)
                    .ConfigureAwait(false);
                return FollowUpDispatchResult.Failed(
                    "Desktop accepted the follow-up but its successor turn could not be identified.",
                    FollowUpDispatchFailureKind.Uncertain);
            }

            var confirmed = await TransitionAfterDispatchAsync(
                    operation,
                    FollowUpOperationState.Confirmed,
                    thread.Id,
                    cancellationToken,
                    started.TurnId)
                .ConfigureAwait(false);
            return confirmed.State == FollowUpOperationState.Confirmed
                ? FollowUpDispatchResult.Ok(
                    "The queued follow-up was sent through the stock Codex Desktop owner channel.",
                    started.TurnId)
                : FollowUpDispatchResult.Failed(
                    "Desktop accepted the follow-up, but durable confirmation failed; it will not be resent.",
                    FollowUpDispatchFailureKind.Uncertain);
        }
        catch (OperationCanceledException) when (commit.IsCancellationRequested)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    FollowUpOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return await ReconcileUncertainAsync(thread, operation, cancellationToken).ConfigureAwait(false);
        }
        catch (DesktopIpcProtocolException exception) when (
            exception.Code is "no-client-found" or "guardian-owner-unavailable")
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    "The stock Desktop owner rejected the request before dispatch.",
                    FollowUpDispatchFailureKind.DesktopOwnerUnavailable,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is DesktopStructuredInputCapabilityException or
                DesktopStructuredInputEncodingException or AttachmentPresentationException)
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    "The structured follow-up became incompatible before the Desktop write.",
                    FollowUpDispatchFailureKind.DesktopIncompatible,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DesktopIpcProtocolException exception) when (
            string.Equals(exception.Code, "guardian-state-changed", StringComparison.Ordinal))
        {
            return await AbandonRejectedAsync(
                    operation,
                    thread.Id,
                    "The Desktop task state changed before the follow-up could be committed.",
                    FollowUpDispatchFailureKind.StateChanged,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DesktopIpcProtocolException exception) when (
            exception.Code is "guardian-original-input-unavailable" or "request-version-mismatch" or
                "no-handler-for-request" or "invalid-initialize-response" or "guardian-invalid-request" or
                "guardian-message-id-conflict")
        {
            return await AbandonRejectedAsync(
                    operation,
                    thread.Id,
                    "Codex Desktop rejected this follow-up request as incompatible.",
                    FollowUpDispatchFailureKind.DesktopIncompatible,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DesktopIpcProtocolException exception) when (
            exception.Stage == DesktopIpcDeliveryStage.Rejected)
        {
            return await AbandonRejectedAsync(
                    operation,
                    thread.Id,
                    "Codex Desktop permanently rejected this follow-up request as incompatible.",
                    FollowUpDispatchFailureKind.DesktopIncompatible,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (IsDefinitelyNotDispatched(exception))
        {
            return await ReturnRetryableBeforeWriteAsync(
                    operation,
                    thread.Id,
                    "Desktop failed before the follow-up request was dispatched.",
                    FollowUpDispatchFailureKind.DesktopUnavailable,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is DesktopIpcProtocolException or DesktopIpcDeliveryException or IOException or TimeoutException)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    FollowUpOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Warning("Follow-up delivery is uncertain; it will not be resent: " + exception.Message, thread.Id);
            return await ReconcileUncertainAsync(thread, operation, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            dispatchGuardLifetime.Cancel();
            await interferenceWatch.ConfigureAwait(false);
        }
    }

    internal static FollowUpDispatchResult? ValidateExpectedNormalCompletion(
        TurnSnapshot? latest,
        string expectedTurnId)
    {
        if (latest is null ||
            !string.Equals(latest.Id, expectedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !FollowUpQueuePlanner.IsNormalCompletion(latest))
        {
            return FollowUpDispatchResult.Failed(
                "The expected normal completed turn is no longer the verified latest turn.",
                FollowUpDispatchFailureKind.StateChanged);
        }

        return null;
    }

    internal static FollowUpDispatchResult? ValidateOwnerNormalCompletion(
        DesktopThreadOwnerStateSnapshot snapshot,
        string expectedTurnId)
    {
        if (!string.Equals(snapshot.RuntimeStatus, "idle", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.LatestTurnId, expectedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.LatestTurnStatus, "completed", StringComparison.OrdinalIgnoreCase))
        {
            return FollowUpDispatchResult.Failed(
                "The Desktop owner does not report the expected idle completed turn.",
                FollowUpDispatchFailureKind.StateChanged);
        }

        return null;
    }

    private bool HasStructuredDispatchDependencies =>
        _structuredCapabilities is not null &&
        _attachmentStore is not null &&
        _presentationLeases is not null &&
        _attachmentPins is not null;

    private async Task<DesktopStructuredInputCapabilities?> RevalidateStructuredDispatchAsync(
        FollowUpOperationRecord operation,
        StructuredDispatchContext context,
        CancellationToken cancellationToken)
    {
        if (!HasStructuredDispatchDependencies ||
            operation.SourceKind is not FollowUpPayloadSourceKind.StructuredPreset and not
                FollowUpPayloadSourceKind.WorkflowPreset ||
            !string.Equals(
                operation.PayloadDigest,
                context.Payload.PayloadDigest,
                StringComparison.Ordinal) ||
            !string.Equals(
                operation.PresentationLeaseId,
                context.PresentationLease.LeaseId,
                StringComparison.Ordinal) ||
            !string.Equals(
                operation.ReplayInputDigest,
                context.ReplayInputDigest,
                StringComparison.Ordinal) ||
            !operation.AttachmentContentIds.SequenceEqual(
                context.Payload.Attachments.Select(attachment => attachment.ContentId),
                StringComparer.Ordinal))
        {
            return null;
        }

        try
        {
            var capabilities = await _structuredCapabilities!.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!capabilities.Matches(context.CapabilityLease, context.Payload) ||
                !await _presentationLeases!
                    .VerifyAsync(context.PresentationLease, context.Payload, cancellationToken)
                    .ConfigureAwait(false))
            {
                return null;
            }

            return capabilities;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                NotSupportedException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private async Task<FollowUpDispatchResult?> RevalidateEligibilityAsync(
        string threadId,
        bool includeSubAgents,
        CancellationToken cancellationToken)
    {
        try
        {
            var current = await _stateReader.ReadThreadForRecoveryAsync(threadId, cancellationToken)
                .ConfigureAwait(false);
            var result = RecoveryService.ValidateTargetThreadEligibility(threadId, includeSubAgents, current);
            return result is null
                ? null
                : FollowUpDispatchResult.Failed(
                    result.Message,
                    FollowUpDispatchFailureKind.PolicyChanged);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to revalidate the follow-up target: " + exception.Message, threadId);
            return FollowUpDispatchResult.Failed(
                "The target task metadata could not be revalidated.",
                FollowUpDispatchFailureKind.DesktopUnavailable);
        }
    }

    private async Task<FollowUpDispatchResult?> ValidateUserIdleAsync(
        string threadId,
        string turnId,
        string stage,
        CancellationToken cancellationToken,
        Action<RecoveryInterferenceSnapshot?>? captureObservation = null)
    {
        RecoveryInterferenceSnapshot? observation = null;
        if (_interferenceGuard is not null)
        {
            try
            {
                observation = await _interferenceGuard.CheckAsync(threadId, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _log.Trace("Follow-up editor observation failed; Windows idle fallback was used: " + exception.Message);
            }
        }

        captureObservation?.Invoke(observation);
        var activity = RecoveryService.ResolveDispatchActivity(
            observation,
            _ownerActivator.CheckUserActivity);
        _log.WriteDispatchGate(threadId, turnId, stage, activity.Status.ToString(), activity.IsIdle);
        return activity.IsIdle
            ? null
            : FollowUpDispatchResult.Failed(activity.Detail, FollowUpDispatchFailureKind.UserActive);
    }

    private async Task<FollowUpDispatchResult> ReconcileUncertainAsync(
        ThreadSummary thread,
        FollowUpOperationRecord operation,
        CancellationToken cancellationToken)
    {
        try
        {
            var matching = await _stateReader.FindRecentTurnByClientMessageIdAsync(
                    thread.Id,
                    operation.ClientMessageId,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (matching is not null)
            {
                var confirmed = await TransitionAfterDispatchAsync(
                        operation,
                        FollowUpOperationState.Confirmed,
                        thread.Id,
                        cancellationToken,
                        matching.Id)
                    .ConfigureAwait(false);
                if (confirmed.State == FollowUpOperationState.Confirmed)
                {
                    return FollowUpDispatchResult.Ok(
                        "The stable follow-up client id matched an existing turn.",
                        matching.Id);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to reconcile an uncertain follow-up: " + exception.Message, thread.Id);
        }

        return FollowUpDispatchResult.Failed(
            "A prior follow-up may have been dispatched. Guardian will not send it again without proof.",
            FollowUpDispatchFailureKind.Uncertain);
    }

    private async Task WatchDispatchInterferenceAsync(
        RecoveryInterferenceSnapshot? observation,
        CancellationTokenSource commit,
        CancellationToken cancellationToken)
    {
        if (_interferenceGuard is null || observation is null)
        {
            return;
        }

        try
        {
            await _interferenceGuard.WaitForChangeAsync(observation.Version, cancellationToken)
                .ConfigureAwait(false);
            if (!cancellationToken.IsCancellationRequested)
            {
                commit.Cancel();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _log.Trace("Follow-up editor change tracking failed closed: " + exception.Message);
            commit.Cancel();
        }
    }

    private async Task<FollowUpOperationRecord?> TransitionBeforeDispatchAsync(
        FollowUpOperationRecord operation,
        CancellationToken cancellationToken)
    {
        try
        {
            var transition = await _journal.TryTransitionAsync(
                    operation.OperationId,
                    operation.State,
                    FollowUpOperationState.Dispatching,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return transition.Changed ? transition.Record : null;
        }
        catch (Exception exception) when (IsPersistenceException(exception))
        {
            _log.Error("Follow-up journal transition failed before sending: " + exception.Message);
            return null;
        }
    }

    private async Task<FollowUpDispatchResult> ReturnRetryableBeforeWriteAsync(
        FollowUpOperationRecord operation,
        string threadId,
        string message,
        FollowUpDispatchFailureKind failureKind,
        CancellationToken cancellationToken)
    {
        var retryable = await TransitionAfterDispatchAsync(
                operation,
                FollowUpOperationState.Retryable,
                threadId,
                cancellationToken)
            .ConfigureAwait(false);
        return retryable.State == FollowUpOperationState.Retryable
            ? FollowUpDispatchResult.Failed(message, failureKind)
            : FollowUpDispatchResult.Failed(
                "The follow-up was not sent, but its durable dispatch intent could not be marked retryable.",
                FollowUpDispatchFailureKind.PersistenceFailed);
    }

    private async Task<FollowUpDispatchResult> AbandonRejectedAsync(
        FollowUpOperationRecord operation,
        string threadId,
        string message,
        FollowUpDispatchFailureKind failureKind,
        CancellationToken cancellationToken)
    {
        var abandoned = await TransitionAfterDispatchAsync(
                operation,
                FollowUpOperationState.Abandoned,
                threadId,
                cancellationToken)
            .ConfigureAwait(false);
        return abandoned.State == FollowUpOperationState.Abandoned
            ? FollowUpDispatchResult.Failed(message, failureKind)
            : FollowUpDispatchResult.Failed(
                "Desktop rejected the follow-up, but its durable operation could not be closed.",
                FollowUpDispatchFailureKind.PersistenceFailed);
    }

    private async Task<FollowUpOperationRecord> TransitionAfterDispatchAsync(
        FollowUpOperationRecord operation,
        FollowUpOperationState nextState,
        string threadId,
        CancellationToken cancellationToken,
        string? newTurnId = null)
    {
        _ = cancellationToken;
        using var durableWrite = new CancellationTokenSource(DurableWriteTimeout);
        try
        {
            var transition = await _journal.TryTransitionAsync(
                    operation.OperationId,
                    operation.State,
                    nextState,
                    newTurnId,
                    durableWrite.Token)
                .ConfigureAwait(false);
            return transition.Record ?? operation;
        }
        catch (Exception exception) when (IsPersistenceException(exception) || exception is OperationCanceledException)
        {
            _log.Error(
                "Follow-up journal transition failed after dispatch; the operation remains conservative: " +
                exception.Message,
                threadId);
            return operation;
        }
    }

    private async Task AbandonBeforeDispatchAsync(
        FollowUpOperationRecord operation,
        CancellationToken cancellationToken)
    {
        if (operation.State is FollowUpOperationState.Prepared or FollowUpOperationState.Retryable)
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    FollowUpOperationState.Abandoned,
                    operation.ThreadId,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static bool IsPolicyAllowed(Func<bool> policy)
    {
        try
        {
            return policy();
        }
        catch
        {
            return false;
        }
    }

    private static bool IsPersistenceException(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or InvalidOperationException or
            NotSupportedException or ArgumentException;

    private static FollowUpWorkflowDispatchContext NormalizeWorkflowContext(
        FollowUpWorkflowDispatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!Guid.TryParse(context.OperationId, out var parsedOperationId) ||
            parsedOperationId == Guid.Empty ||
            !Guid.TryParse(context.ClientMessageId, out var parsedClientMessageId) ||
            parsedClientMessageId == Guid.Empty ||
            context.AuthorizeWriteAsync is null ||
            !Enum.IsDefined(context.JournalTrigger))
        {
            throw new ArgumentException("The workflow follow-up dispatch identity is invalid.", nameof(context));
        }

        var scheduledAtUtc = context.ScheduledAtUtc?.ToUniversalTime();
        if (context.JournalTrigger == FollowUpTriggerKind.ScheduledAt && scheduledAtUtc is null ||
            context.JournalTrigger == FollowUpTriggerKind.AfterNormalCompletion && scheduledAtUtc is not null)
        {
            throw new ArgumentException(
                "The workflow follow-up trigger and schedule are inconsistent.",
                nameof(context));
        }

        var operationId = parsedOperationId.ToString("D");
        var clientMessageId = parsedClientMessageId.ToString("D");
        if (!string.Equals(
                clientMessageId,
                WorkflowOperationJournal.CreateClientMessageId(operationId),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The workflow client message identity does not match its action operation.",
                nameof(context));
        }

        return context with
        {
            OperationId = operationId,
            ClientMessageId = clientMessageId,
            ScheduledAtUtc = scheduledAtUtc
        };
    }

    private static bool IsDefinitelyNotDispatched(Exception exception) => exception switch
    {
        DesktopIpcProtocolException protocol => protocol.Stage == DesktopIpcDeliveryStage.NotDispatched,
        DesktopIpcDeliveryException delivery => delivery.Stage == DesktopIpcDeliveryStage.NotDispatched,
        _ => false
    };

    private sealed record StructuredDispatchContext(
        StructuredPresetPayload Payload,
        DesktopStructuredInputCapabilityLease CapabilityLease,
        AttachmentPresentationLease PresentationLease,
        string ReplayInputDigest);
}
