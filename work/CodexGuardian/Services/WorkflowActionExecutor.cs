using CodexGuardian.Models;
using System.Security.Cryptography;
using System.Text;

namespace CodexGuardian.Services;

internal enum WorkflowActionExecutionStatus
{
    Confirmed,
    Waiting,
    Retryable,
    Uncertain,
    Blocked,
    Exhausted,
    Canceled,
    CapabilityUnavailable
}

internal sealed record WorkflowActionExecutionResult(
    WorkflowActionExecutionStatus Status,
    WorkflowActionOperationRecord? Record,
    string Message);

internal sealed record WorkflowPresetDispatchRequest(
    ThreadSummary TargetThread,
    TurnSnapshot ExpectedCompletedTurn,
    FollowUpMessageDefinition Preset,
    FollowUpTriggerKind JournalTrigger,
    DateTimeOffset? ScheduledAtUtc,
    string ActionOperationId,
    string ClientMessageId,
    bool IncludeSubAgents,
    Func<bool> IsDispatchAllowed,
    Func<FollowUpWorkflowDispatchCheckpoint, CancellationToken, Task<bool>> AuthorizeWriteAsync);

internal interface IWorkflowPresetDispatcher
{
    Task<FollowUpDispatchResult> DispatchAsync(
        WorkflowPresetDispatchRequest request,
        CancellationToken cancellationToken);

    Task<FollowUpDispatchResult> ReconcileAsync(
        ThreadSummary targetThread,
        string actionOperationId,
        CancellationToken cancellationToken);
}

internal sealed class FollowUpWorkflowPresetDispatcher(FollowUpDispatchService inner)
    : IWorkflowPresetDispatcher
{
    public Task<FollowUpDispatchResult> DispatchAsync(
        WorkflowPresetDispatchRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return inner.ExecuteWorkflowAsync(
            request.TargetThread,
            request.ExpectedCompletedTurn,
            request.Preset,
            request.IncludeSubAgents,
            request.IsDispatchAllowed,
            new FollowUpWorkflowDispatchContext(
                request.ActionOperationId,
                request.ClientMessageId,
                request.JournalTrigger,
                request.ScheduledAtUtc,
                request.AuthorizeWriteAsync),
            cancellationToken);
    }

    public Task<FollowUpDispatchResult> ReconcileAsync(
        ThreadSummary targetThread,
        string actionOperationId,
        CancellationToken cancellationToken) =>
        inner.ReconcileWorkflowAsync(targetThread, actionOperationId, cancellationToken);
}

internal interface IWorkflowConversationProtectionService
{
    Task<ConversationProtectionSnapshot> ReadAsync(
        string conversationId,
        CancellationToken cancellationToken);

    Task<ConversationProtectionEnableResult> EnableAsync(
        string conversationId,
        long expectedSettingsGeneration,
        CancellationToken cancellationToken);
}

internal sealed class SettingsWorkflowConversationProtectionService(SettingsService inner)
    : IWorkflowConversationProtectionService
{
    public Task<ConversationProtectionSnapshot> ReadAsync(
        string conversationId,
        CancellationToken cancellationToken) =>
        inner.ReadConversationProtectionAsync(conversationId, cancellationToken);

    public Task<ConversationProtectionEnableResult> EnableAsync(
        string conversationId,
        long expectedSettingsGeneration,
        CancellationToken cancellationToken) =>
        inner.EnableConversationProtectionAsync(
            conversationId,
            expectedSettingsGeneration,
            cancellationToken);
}

internal interface IWorkflowActionExecutor
{
    Task<WorkflowActionExecutionResult> ExecuteSendPresetAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        ThreadSummary targetThread,
        TurnSnapshot expectedCompletedTurn,
        string presetOwnerConversationId,
        FollowUpMessageDefinition preset,
        bool includeSubAgents,
        Func<bool> isDispatchAllowed,
        CancellationToken cancellationToken = default);

    Task<WorkflowActionExecutionResult> ExecuteEnableConversationProtectionAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        ThreadSummary targetThread,
        CancellationToken cancellationToken = default);

    Task<WorkflowActionExecutionResult> MarkNewConversationUnavailableAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        CancellationToken cancellationToken = default);

    Task<WorkflowActionExecutionResult> MarkBlockedAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        string? resolvedTargetConversationId,
        string failureClass,
        CancellationToken cancellationToken = default);

    Task<WorkflowActionExecutionResult> MarkExhaustedAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        string? resolvedTargetConversationId,
        CancellationToken cancellationToken = default);
}

internal sealed class WorkflowActionExecutor :
    IWorkflowActionExecutor,
    IWorkflowPresetDispatchConfirmationSource
{
    private readonly WorkflowOperationJournal _journal;
    private readonly IWorkflowPresetDispatcher _presetDispatcher;
    private readonly IWorkflowConversationProtectionService _protection;
    private readonly SemaphoreSlim[] _operationLeases = Enumerable.Range(0, 64)
        .Select(static _ => new SemaphoreSlim(1, 1))
        .ToArray();
    private event EventHandler<WorkflowPresetDispatchConfirmedEventArgs>?
        PresetDispatchConfirmedInternal;

    internal WorkflowActionExecutor(
        WorkflowOperationJournal journal,
        IWorkflowPresetDispatcher presetDispatcher,
        IWorkflowConversationProtectionService protection)
    {
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _presetDispatcher = presetDispatcher ?? throw new ArgumentNullException(nameof(presetDispatcher));
        _protection = protection ?? throw new ArgumentNullException(nameof(protection));
    }

    event EventHandler<WorkflowPresetDispatchConfirmedEventArgs>?
        IWorkflowPresetDispatchConfirmationSource.PresetDispatchConfirmed
    {
        add => PresetDispatchConfirmedInternal += value;
        remove => PresetDispatchConfirmedInternal -= value;
    }

    public async Task<WorkflowActionExecutionResult> ExecuteSendPresetAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        ThreadSummary targetThread,
        TurnSnapshot expectedCompletedTurn,
        string presetOwnerConversationId,
        FollowUpMessageDefinition preset,
        bool includeSubAgents,
        Func<bool> isDispatchAllowed,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targetThread);
        ArgumentNullException.ThrowIfNull(expectedCompletedTurn);
        ArgumentNullException.ThrowIfNull(preset);
        ArgumentNullException.ThrowIfNull(isDispatchAllowed);
        var action = GetAction(rule, actionIndex, WorkflowActionKind.SendPresetMessage);
        triggerEventId = NormalizeId(triggerEventId, nameof(triggerEventId));
        presetOwnerConversationId = NormalizeId(
            presetOwnerConversationId,
            nameof(presetOwnerConversationId));
        var expectedTargetId = rule.ResolveKnownDestinationConversationId();
        if (expectedTargetId is null ||
            !string.Equals(targetThread.Id, expectedTargetId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The workflow send target does not match its current or existing-conversation destination.");
        }

        if (!string.Equals(
                action.PresetOwnerConversationId,
                presetOwnerConversationId,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(action.PresetMessageId, preset.Id, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The workflow action selected a different preset identity.");
        }

        StructuredPresetPayload payload;
        try
        {
            payload = StructuredPresetPayload.Create(preset.Message, preset.Attachments);
        }
        catch (ArgumentException)
        {
            return new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Blocked,
                null,
                "The selected workflow preset payload is invalid.");
        }

        var actionOperationId = WorkflowOperationJournal.CreateActionOperationId(
            rule.RuleId,
            rule.Revision,
            triggerEventId,
            actionIndex);
        var lease = LeaseFor(actionOperationId);
        await lease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var prepared = await _journal.GetOrCreateActionAsync(
                    rule,
                    triggerEventId,
                    actionIndex,
                    targetThread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            var current = prepared.Record;
            var terminal = ProjectTerminal(current);
            if (terminal is not null)
            {
                return terminal;
            }

            if (current.State == WorkflowActionOperationState.Dispatching)
            {
                return ProjectUncertain(current);
            }

            if (current.State == WorkflowActionOperationState.Uncertain)
            {
                return await ReconcileSendAsync(targetThread, current, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (targetThread.IsArchived || targetThread.IsEphemeral || targetThread.IsSubAgent)
            {
                return await BlockAsync(current, "target-unavailable", cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!preset.IsEnabled)
            {
                return await BlockAsync(current, "preset-disabled", cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!FollowUpQueuePlanner.IsNormalCompletion(expectedCompletedTurn))
            {
                return await BlockAsync(current, "target-not-complete", cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!IsPolicyAllowed(isDispatchAllowed))
            {
                return new WorkflowActionExecutionResult(
                    WorkflowActionExecutionStatus.Waiting,
                    current,
                    "The workflow send policy is not currently eligible.");
            }

            string? authorizationFailure = null;
            async Task<bool> AuthorizeWriteAsync(
                FollowUpWorkflowDispatchCheckpoint checkpoint,
                CancellationToken authorizeCancellationToken)
            {
                if (!string.Equals(
                        checkpoint.TargetConversationId,
                        targetThread.Id,
                        StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(
                        checkpoint.ExpectedTurnId,
                        expectedCompletedTurn.Id,
                        StringComparison.OrdinalIgnoreCase) ||
                    checkpoint.TargetOwnerRevision <= 0 ||
                    !string.Equals(checkpoint.PayloadDigest, payload.PayloadDigest, StringComparison.Ordinal))
                {
                    authorizationFailure = "checkpoint-mismatch";
                    await _journal.TryMarkTerminalAsync(
                            current.ActionOperationId,
                            WorkflowActionOperationState.Blocked,
                            authorizationFailure,
                            authorizeCancellationToken)
                        .ConfigureAwait(false);
                    return false;
                }

                var binding = await _journal.TryBindExecutionAsync(
                        current.ActionOperationId,
                        payload.PayloadDigest,
                        checkpoint.TargetOwnerRevision,
                        authorizeCancellationToken)
                    .ConfigureAwait(false);
                if (binding.Status == WorkflowExecutionBindingStatus.NoProgress)
                {
                    authorizationFailure = "no-progress";
                    return false;
                }

                if (binding.Status is not WorkflowExecutionBindingStatus.Bound and not
                    WorkflowExecutionBindingStatus.AlreadyBound)
                {
                    authorizationFailure = "action-state-changed";
                    return false;
                }

                var dispatching = await _journal.TryStartDispatchAsync(
                        current.ActionOperationId,
                        authorizeCancellationToken)
                    .ConfigureAwait(false);
                if (dispatching.Record?.State == WorkflowActionOperationState.Dispatching)
                {
                    return true;
                }

                authorizationFailure = "action-state-changed";
                return false;
            }

            var request = new WorkflowPresetDispatchRequest(
                targetThread,
                expectedCompletedTurn,
                preset,
                rule.Trigger.Kind == WorkflowTriggerKind.ScheduledAt
                    ? FollowUpTriggerKind.ScheduledAt
                    : FollowUpTriggerKind.AfterNormalCompletion,
                rule.Trigger.Kind == WorkflowTriggerKind.ScheduledAt
                    ? rule.Trigger.ScheduledAtUtc
                    : null,
                current.ActionOperationId,
                current.ClientMessageId!,
                includeSubAgents,
                isDispatchAllowed,
                AuthorizeWriteAsync);
            var dispatch = await _presetDispatcher.DispatchAsync(request, cancellationToken)
                .ConfigureAwait(false);
            current = await ReadActionAsync(current.ActionOperationId, cancellationToken)
                .ConfigureAwait(false) ?? current;
            if (dispatch.Success)
            {
                if (!Guid.TryParse(dispatch.NewTurnId, out var parsedTurnId) || parsedTurnId == Guid.Empty)
                {
                    return await MarkUncertainAsync(
                            current,
                            "missing-turn-receipt",
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                var confirmed = await _journal.TryMarkConfirmedAsync(
                        current.ActionOperationId,
                        new WorkflowActionReceipt(
                            targetThread.Id,
                            parsedTurnId.ToString("D"),
                            ProtectionSettingsGeneration: null),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (confirmed.Record is { State: WorkflowActionOperationState.Confirmed } record)
                {
                    if (confirmed.Changed)
                    {
                        PublishPresetDispatchConfirmed(record);
                    }

                    return new WorkflowActionExecutionResult(
                        WorkflowActionExecutionStatus.Confirmed,
                        record,
                        "The workflow preset send was authoritatively confirmed.");
                }

                return await MarkUncertainAsync(
                            current,
                            "receipt-persistence-failed",
                            cancellationToken)
                    .ConfigureAwait(false);
            }

            if (dispatch.FailureKind == FollowUpDispatchFailureKind.Uncertain)
            {
                return await MarkUncertainAsync(
                        current,
                        "desktop-uncertain",
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (current.State == WorkflowActionOperationState.Blocked)
            {
                return ProjectTerminal(current)!;
            }

            if (current.State == WorkflowActionOperationState.Dispatching)
            {
                var retryable = await _journal.TryMarkRetryableProvenUnsentAsync(
                        current.ActionOperationId,
                        MapFailureClass(dispatch.FailureKind),
                        cancellationToken)
                    .ConfigureAwait(false);
                return new WorkflowActionExecutionResult(
                    WorkflowActionExecutionStatus.Retryable,
                    retryable.Record,
                    dispatch.Message);
            }

            if (dispatch.FailureKind is FollowUpDispatchFailureKind.DesktopIncompatible or
                FollowUpDispatchFailureKind.StateChanged)
            {
                return await BlockAsync(
                        current,
                        MapFailureClass(dispatch.FailureKind),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            return new WorkflowActionExecutionResult(
                authorizationFailure is null
                    ? WorkflowActionExecutionStatus.Waiting
                    : WorkflowActionExecutionStatus.Retryable,
                current,
                dispatch.Message);
        }
        finally
        {
            lease.Release();
        }
    }

    public async Task<WorkflowActionExecutionResult> ExecuteEnableConversationProtectionAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        ThreadSummary targetThread,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targetThread);
        _ = GetAction(rule, actionIndex, WorkflowActionKind.EnableConversationProtection);
        triggerEventId = NormalizeId(triggerEventId, nameof(triggerEventId));
        var expectedTargetId = rule.ResolveKnownDestinationConversationId();
        if (expectedTargetId is null ||
            !string.Equals(targetThread.Id, expectedTargetId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The workflow protection target does not match its current or existing destination.");
        }

        var actionOperationId = WorkflowOperationJournal.CreateActionOperationId(
            rule.RuleId,
            rule.Revision,
            triggerEventId,
            actionIndex);
        var lease = LeaseFor(actionOperationId);
        await lease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var prepared = await _journal.GetOrCreateActionAsync(
                    rule,
                    triggerEventId,
                    actionIndex,
                    targetThread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            var current = prepared.Record;
            var terminal = ProjectTerminal(current);
            if (terminal is not null)
            {
                return terminal;
            }

            if (current.State == WorkflowActionOperationState.Dispatching)
            {
                return ProjectUncertain(current);
            }

            if (current.State == WorkflowActionOperationState.Uncertain)
            {
                return await ReconcileProtectionAsync(current, targetThread.Id, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (targetThread.IsArchived || targetThread.IsEphemeral || targetThread.IsSubAgent)
            {
                return await BlockAsync(current, "target-unavailable", cancellationToken)
                    .ConfigureAwait(false);
            }

            var before = await _protection.ReadAsync(targetThread.Id, cancellationToken)
                .ConfigureAwait(false);
            if (!before.IsAvailable)
            {
                return await BlockAsync(current, "settings-unavailable", cancellationToken)
                    .ConfigureAwait(false);
            }

            var fingerprint = CreateProtectionFingerprint(targetThread.Id, before.IsEnabled);
            var binding = await _journal.TryBindExecutionAsync(
                    current.ActionOperationId,
                    fingerprint,
                    before.SettingsGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
            if (binding.Status == WorkflowExecutionBindingStatus.NoProgress)
            {
                return ProjectTerminal(binding.Record!)!;
            }

            if (binding.Status is not WorkflowExecutionBindingStatus.Bound and not
                WorkflowExecutionBindingStatus.AlreadyBound)
            {
                var bindingTerminal = binding.Record is null
                    ? null
                    : ProjectTerminal(binding.Record);
                if (bindingTerminal is not null)
                {
                    return bindingTerminal;
                }

                return new WorkflowActionExecutionResult(
                    WorkflowActionExecutionStatus.Waiting,
                    binding.Record,
                    "The workflow protection action changed before execution.");
            }

            var dispatching = await _journal.TryStartDispatchAsync(
                    current.ActionOperationId,
                    cancellationToken)
                .ConfigureAwait(false);
            current = dispatching.Record ?? current;
            if (current.State != WorkflowActionOperationState.Dispatching)
            {
                return ProjectTerminal(current) ?? ProjectUncertain(current);
            }

            var enabled = await _protection.EnableAsync(
                    targetThread.Id,
                    before.SettingsGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
            if (enabled.Status == ConversationProtectionEnableStatus.Confirmed)
            {
                var confirmed = await _journal.TryMarkConfirmedAsync(
                        current.ActionOperationId,
                        new WorkflowActionReceipt(
                            targetThread.Id,
                            GeneratedTurnId: null,
                            enabled.SettingsGeneration),
                        cancellationToken)
                    .ConfigureAwait(false);
                return confirmed.Record?.State == WorkflowActionOperationState.Confirmed
                    ? new WorkflowActionExecutionResult(
                        WorkflowActionExecutionStatus.Confirmed,
                        confirmed.Record,
                        enabled.Changed
                            ? "Conversation protection was enabled."
                            : "Conversation protection was already enabled.")
                    : await MarkUncertainAsync(
                            current,
                            "receipt-persistence-failed",
                            cancellationToken)
                        .ConfigureAwait(false);
            }

            var retryable = await _journal.TryMarkRetryableProvenUnsentAsync(
                    current.ActionOperationId,
                    enabled.Status == ConversationProtectionEnableStatus.GenerationChanged
                        ? "settings-generation-changed"
                        : "settings-unavailable",
                    cancellationToken)
                .ConfigureAwait(false);
            if (enabled.Status == ConversationProtectionEnableStatus.Unavailable)
            {
                return await BlockAsync(
                        retryable.Record ?? current,
                        "settings-unavailable",
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            return new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Retryable,
                retryable.Record,
                "The settings generation changed before protection could be enabled.");
        }
        finally
        {
            lease.Release();
        }
    }

    public async Task<WorkflowActionExecutionResult> MarkNewConversationUnavailableAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        CancellationToken cancellationToken = default)
    {
        _ = GetAction(rule, actionIndex, WorkflowActionKind.SendPresetMessage);
        if (rule.Destination.Kind != WorkflowDestinationKind.NewConversation)
        {
            throw new InvalidOperationException("The workflow destination is not a new conversation.");
        }

        triggerEventId = NormalizeId(triggerEventId, nameof(triggerEventId));
        var prepared = await _journal.GetOrCreateActionAsync(
                rule,
                triggerEventId,
                actionIndex,
                resolvedTargetConversationId: null,
                cancellationToken)
            .ConfigureAwait(false);
        var terminal = ProjectTerminal(prepared.Record);
        if (terminal is not null)
        {
            return terminal;
        }

        var blocked = await _journal.TryMarkTerminalAsync(
                prepared.Record.ActionOperationId,
                WorkflowActionOperationState.Blocked,
                "new-conversation-unavailable",
                cancellationToken)
            .ConfigureAwait(false);
        return new WorkflowActionExecutionResult(
            WorkflowActionExecutionStatus.CapabilityUnavailable,
            blocked.Record,
            "The stock Desktop create-and-first-turn capability has not been proved.");
    }

    public Task<WorkflowActionExecutionResult> MarkBlockedAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        string? resolvedTargetConversationId,
        string failureClass,
        CancellationToken cancellationToken = default) =>
        MarkTerminalActionAsync(
            rule,
            triggerEventId,
            actionIndex,
            resolvedTargetConversationId,
            WorkflowActionOperationState.Blocked,
            failureClass,
            cancellationToken);

    public Task<WorkflowActionExecutionResult> MarkExhaustedAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        string? resolvedTargetConversationId,
        CancellationToken cancellationToken = default) =>
        MarkTerminalActionAsync(
            rule,
            triggerEventId,
            actionIndex,
            resolvedTargetConversationId,
            WorkflowActionOperationState.Exhausted,
            "retry-exhausted",
            cancellationToken);

    private async Task<WorkflowActionExecutionResult> MarkTerminalActionAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        string? resolvedTargetConversationId,
        WorkflowActionOperationState terminalState,
        string failureClass,
        CancellationToken cancellationToken)
    {
        _ = GetAction(rule, actionIndex);
        triggerEventId = NormalizeId(triggerEventId, nameof(triggerEventId));
        var expectedTargetId = rule.ResolveKnownDestinationConversationId();
        if (rule.Destination.Kind == WorkflowDestinationKind.NewConversation)
        {
            if (resolvedTargetConversationId is not null)
            {
                throw new InvalidOperationException(
                    "A new-conversation workflow action cannot bind an existing target.");
            }
        }
        else if (expectedTargetId is null ||
                 !string.Equals(
                     expectedTargetId,
                     resolvedTargetConversationId,
                     StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The blocked workflow action target does not match its canonical destination.");
        }

        var prepared = await _journal.GetOrCreateActionAsync(
                rule,
                triggerEventId,
                actionIndex,
                resolvedTargetConversationId,
                cancellationToken)
            .ConfigureAwait(false);
        var terminal = ProjectTerminal(prepared.Record);
        if (terminal is not null)
        {
            return terminal;
        }

        if (prepared.Record.State is WorkflowActionOperationState.Dispatching or
            WorkflowActionOperationState.Uncertain)
        {
            return ProjectUncertain(prepared.Record);
        }

        var terminalResult = await _journal.TryMarkTerminalAsync(
                prepared.Record.ActionOperationId,
                terminalState,
                failureClass,
                cancellationToken)
            .ConfigureAwait(false);
        return new WorkflowActionExecutionResult(
            terminalState == WorkflowActionOperationState.Exhausted
                ? WorkflowActionExecutionStatus.Exhausted
                : WorkflowActionExecutionStatus.Blocked,
            terminalResult.Record ?? prepared.Record,
            terminalState == WorkflowActionOperationState.Exhausted
                ? "The workflow action exhausted its proven-unsent retry allowance."
                : "The workflow action is blocked by its current authoritative conditions.");
    }

    private async Task<WorkflowActionExecutionResult> ReconcileSendAsync(
        ThreadSummary targetThread,
        WorkflowActionOperationRecord current,
        CancellationToken cancellationToken)
    {
        var reconciled = await _presetDispatcher.ReconcileAsync(
                targetThread,
                current.ActionOperationId,
                cancellationToken)
            .ConfigureAwait(false);
        if (!reconciled.Success || !Guid.TryParse(reconciled.NewTurnId, out var parsedTurnId) ||
            parsedTurnId == Guid.Empty)
        {
            return ProjectUncertain(current);
        }

        var confirmed = await _journal.TryMarkConfirmedAsync(
                current.ActionOperationId,
                new WorkflowActionReceipt(
                    targetThread.Id,
                    parsedTurnId.ToString("D"),
                    ProtectionSettingsGeneration: null),
                cancellationToken)
            .ConfigureAwait(false);
        if (confirmed.Record is { State: WorkflowActionOperationState.Confirmed } record)
        {
            if (confirmed.Changed)
            {
                PublishPresetDispatchConfirmed(record);
            }

            return new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Confirmed,
                record,
                "The uncertain workflow preset send was authoritatively reconciled.");
        }

        return ProjectUncertain(current);
    }

    private void PublishPresetDispatchConfirmed(WorkflowActionOperationRecord action)
    {
        if (action.ActionKind != WorkflowActionKind.SendPresetMessage ||
            action.State != WorkflowActionOperationState.Confirmed ||
            action.GeneratedTurnId is null)
        {
            return;
        }

        EventSubscriberDispatcher.Invoke(
            PresetDispatchConfirmedInternal,
            this,
            new WorkflowPresetDispatchConfirmedEventArgs(action));
    }

    private async Task<WorkflowActionExecutionResult> ReconcileProtectionAsync(
        WorkflowActionOperationRecord current,
        string targetConversationId,
        CancellationToken cancellationToken)
    {
        var snapshot = await _protection.ReadAsync(targetConversationId, cancellationToken)
            .ConfigureAwait(false);
        if (!snapshot.IsAvailable || !snapshot.IsEnabled || snapshot.SettingsGeneration <= 0 ||
            current.ExecutionFingerprint is null ||
            current.AuthoritativeTargetGeneration is null)
        {
            return ProjectUncertain(current);
        }

        var initiallyEnabled = string.Equals(
            current.ExecutionFingerprint,
            CreateProtectionFingerprint(targetConversationId, initiallyEnabled: true),
            StringComparison.Ordinal);
        var initiallyDisabled = string.Equals(
            current.ExecutionFingerprint,
            CreateProtectionFingerprint(targetConversationId, initiallyEnabled: false),
            StringComparison.Ordinal);
        var confirmsState = initiallyEnabled &&
                            snapshot.SettingsGeneration >= current.AuthoritativeTargetGeneration ||
                            initiallyDisabled &&
                            snapshot.SettingsGeneration > current.AuthoritativeTargetGeneration;
        if (!confirmsState)
        {
            return ProjectUncertain(current);
        }

        var confirmed = await _journal.TryMarkConfirmedAsync(
                current.ActionOperationId,
                new WorkflowActionReceipt(
                    targetConversationId,
                    GeneratedTurnId: null,
                    snapshot.SettingsGeneration),
                cancellationToken)
            .ConfigureAwait(false);
        return confirmed.Record?.State == WorkflowActionOperationState.Confirmed
            ? new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Confirmed,
                confirmed.Record,
                "The uncertain protection action was reconciled from the committed settings generation.")
            : ProjectUncertain(current);
    }

    private async Task<WorkflowActionExecutionResult> BlockAsync(
        WorkflowActionOperationRecord current,
        string failureClass,
        CancellationToken cancellationToken)
    {
        var blocked = await _journal.TryMarkTerminalAsync(
                current.ActionOperationId,
                WorkflowActionOperationState.Blocked,
                failureClass,
                cancellationToken)
            .ConfigureAwait(false);
        return new WorkflowActionExecutionResult(
            WorkflowActionExecutionStatus.Blocked,
            blocked.Record ?? current,
            "The workflow action is blocked by its current authoritative conditions.");
    }

    private async Task<WorkflowActionExecutionResult> MarkUncertainAsync(
        WorkflowActionOperationRecord current,
        string failureClass,
        CancellationToken cancellationToken)
    {
        if (current.State == WorkflowActionOperationState.Dispatching)
        {
            var uncertain = await _journal.TryMarkUncertainAsync(
                    current.ActionOperationId,
                    failureClass,
                    cancellationToken)
                .ConfigureAwait(false);
            current = uncertain.Record ?? current;
        }

        return ProjectUncertain(current);
    }

    private async Task<WorkflowActionOperationRecord?> ReadActionAsync(
        string actionOperationId,
        CancellationToken cancellationToken)
    {
        var snapshot = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        return snapshot.Actions.SingleOrDefault(action => string.Equals(
            action.ActionOperationId,
            actionOperationId,
            StringComparison.OrdinalIgnoreCase));
    }

    private static WorkflowActionDefinition GetAction(
        WorkflowRuleDefinition rule,
        int actionIndex,
        WorkflowActionKind expectedKind)
    {
        var action = GetAction(rule, actionIndex);
        if (action.Kind != expectedKind)
        {
            throw new InvalidOperationException("The workflow action kind changed.");
        }

        return action;
    }

    private static WorkflowActionDefinition GetAction(
        WorkflowRuleDefinition rule,
        int actionIndex)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (!rule.HasValidIdentity() || !rule.IsEnabled)
        {
            throw new ArgumentException("An enabled canonical workflow rule is required.", nameof(rule));
        }

        if (actionIndex < 0 || actionIndex >= rule.Actions.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(actionIndex));
        }

        var action = rule.Actions[actionIndex];
        if (action.Order != actionIndex)
        {
            throw new InvalidOperationException("The workflow action order changed.");
        }

        return action;
    }

    private SemaphoreSlim LeaseFor(string actionOperationId) =>
        _operationLeases[
            (int)((uint)StringComparer.OrdinalIgnoreCase.GetHashCode(actionOperationId) %
                  _operationLeases.Length)];

    private static WorkflowActionExecutionResult? ProjectTerminal(
        WorkflowActionOperationRecord record) =>
        record.State switch
        {
            WorkflowActionOperationState.Confirmed => new(
                WorkflowActionExecutionStatus.Confirmed,
                record,
                "The workflow action is already confirmed."),
            WorkflowActionOperationState.Blocked => new(
                string.Equals(
                    record.FailureClass,
                    "new-conversation-unavailable",
                    StringComparison.Ordinal)
                    ? WorkflowActionExecutionStatus.CapabilityUnavailable
                    : WorkflowActionExecutionStatus.Blocked,
                record,
                "The workflow action is durably blocked."),
            WorkflowActionOperationState.Exhausted => new(
                WorkflowActionExecutionStatus.Exhausted,
                record,
                "The workflow action exhausted its proven-unsent retry allowance."),
            WorkflowActionOperationState.Canceled => new(
                WorkflowActionExecutionStatus.Canceled,
                record,
                "The workflow action is canceled."),
            _ => null
        };

    private static WorkflowActionExecutionResult ProjectUncertain(
        WorkflowActionOperationRecord record) =>
        new(
            WorkflowActionExecutionStatus.Uncertain,
            record,
            "The workflow action may have been applied and requires authoritative reconciliation.");

    private static string CreateProtectionFingerprint(
        string targetConversationId,
        bool initiallyEnabled) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            "|",
            "CodexFree.Workflow.EnableConversationProtection.v1",
            targetConversationId,
            initiallyEnabled ? "enabled" : "disabled"))));

    private static string MapFailureClass(FollowUpDispatchFailureKind failureKind) =>
        failureKind switch
        {
            FollowUpDispatchFailureKind.StateChanged => "state-changed",
            FollowUpDispatchFailureKind.DesktopUnavailable => "desktop-unavailable",
            FollowUpDispatchFailureKind.DesktopOwnerUnavailable => "owner-unavailable",
            FollowUpDispatchFailureKind.UserActive => "user-active",
            FollowUpDispatchFailureKind.DesktopIncompatible => "desktop-incompatible",
            FollowUpDispatchFailureKind.PolicyChanged => "policy-changed",
            FollowUpDispatchFailureKind.PersistenceFailed => "persistence-failed",
            FollowUpDispatchFailureKind.WorkflowBlocked => "workflow-blocked",
            FollowUpDispatchFailureKind.Uncertain => "desktop-uncertain",
            _ => "dispatch-failed"
        };

    private static bool IsPolicyAllowed(Func<bool> predicate)
    {
        try
        {
            return predicate();
        }
        catch
        {
            return false;
        }
    }

    private static string NormalizeId(string? value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }
}
