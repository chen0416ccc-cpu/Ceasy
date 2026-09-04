using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal sealed record WorkflowDispatchPolicyToken(
    string RuleId,
    int RuleRevision,
    string DefinitionDigest,
    string TriggerEventId,
    int ActionIndex,
    long SettingsGeneration,
    long RuleStoreGeneration,
    string TargetConversationId,
    string PresetOwnerConversationId,
    string PresetMessageId,
    string PayloadDigest);

internal interface IWorkflowDispatchPolicyAuthority
{
    bool IsCurrent(WorkflowDispatchPolicyToken token);
}

internal sealed class WorkflowRuleActionRunner(
    WorkflowExecutionResolver resolver,
    IWorkflowActionExecutor executor,
    IWorkflowDispatchPolicyAuthority dispatchPolicy) : IWorkflowRuleActionRunner
{
    public async Task<WorkflowActionExecutionResult> RunAsync(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        int actionIndex,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(triggerEvent);
        if (actionIndex < 0 || actionIndex >= rule.Actions.Count ||
            rule.Actions[actionIndex].Order != actionIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(actionIndex));
        }

        var action = rule.Actions[actionIndex];
        var resolution = await resolver.ResolveAsync(rule, triggerEvent, cancellationToken)
            .ConfigureAwait(false);
        var resolvedTargetId = rule.ResolveKnownDestinationConversationId();
        if (!resolution.SourceEventAfterActivation)
        {
            return await executor.MarkBlockedAsync(
                    rule,
                    triggerEvent.TriggerEventId,
                    actionIndex,
                    resolvedTargetId,
                    "source-event-invalid",
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (!resolution.SourceConversationExists)
        {
            return Waiting("The workflow source conversation is missing, archived, or not a root conversation.");
        }

        if (!resolution.RuleAndPresetEnabled)
        {
            return Waiting("The workflow rule or one of its exact preset references is not enabled.");
        }

        if (rule.Destination.Kind == WorkflowDestinationKind.NewConversation)
        {
            return action.Kind == WorkflowActionKind.SendPresetMessage
                ? await executor.MarkNewConversationUnavailableAsync(
                        rule,
                        triggerEvent.TriggerEventId,
                        actionIndex,
                        cancellationToken)
                    .ConfigureAwait(false)
                : await executor.MarkBlockedAsync(
                        rule,
                        triggerEvent.TriggerEventId,
                        actionIndex,
                        resolvedTargetConversationId: null,
                        "new-target-action-invalid",
                        cancellationToken)
                    .ConfigureAwait(false);
        }

        if (!resolution.TargetConversationExists ||
            resolution.TargetConversation?.Thread is not { } targetThread)
        {
            return Waiting("The exact workflow target is missing, archived, or not a root conversation.");
        }

        if (!resolution.TargetIdle || resolution.TargetConversation.LatestTurn is not { } targetTurn)
        {
            return Waiting(
                resolution.TargetHasPendingOperation
                    ? "The workflow target has an unresolved owner operation."
                    : "The workflow target is not idle on one authoritative normal completion.");
        }

        if (action.Kind == WorkflowActionKind.EnableConversationProtection)
        {
            return await executor.ExecuteEnableConversationProtectionAsync(
                    rule,
                    triggerEvent.TriggerEventId,
                    actionIndex,
                    targetThread,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (!resolution.TargetPolicyAllowsAction)
        {
            return Waiting("The current workflow target policy does not permit this action.");
        }

        if (!resolution.ManagedAttachmentsAvailable)
        {
            return Waiting("A selected workflow preset attachment or structured capability is unavailable.");
        }

        if (action.Kind == WorkflowActionKind.SendPresetMessage &&
            resolution.Presets.TryGetValue(actionIndex, out var retryPreset) &&
            retryPreset.Definition is { } retryDefinition &&
            resolution.CurrentTriggerActions.SingleOrDefault(candidate =>
                candidate.ActionIndex == actionIndex) is
            {
                State: WorkflowActionOperationState.Retryable
            } retryable &&
            FollowUpRetryPolicy.IsExhausted(retryDefinition, retryable.AttemptCount))
        {
            return await executor.MarkExhaustedAsync(
                    rule,
                    triggerEvent.TriggerEventId,
                    actionIndex,
                    resolvedTargetId,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (!resolution.Presets.TryGetValue(actionIndex, out var resolvedPreset) ||
            resolvedPreset.Definition is not { } preset ||
            resolvedPreset.Payload is not { } payload)
        {
            return Waiting("The exact workflow preset could not be resolved from current settings.");
        }

        var policyToken = new WorkflowDispatchPolicyToken(
            rule.RuleId,
            rule.Revision,
            rule.DefinitionDigest,
            triggerEvent.TriggerEventId,
            actionIndex,
            resolution.SettingsGeneration,
            resolution.RuleStoreGeneration,
            targetThread.Id,
            resolvedPreset.OwnerConversationId,
            resolvedPreset.MessageId,
            payload.PayloadDigest);
        if (!IsPolicyCurrent(policyToken))
        {
            return Waiting("The workflow policy generation changed before owner dispatch.");
        }

        return await executor.ExecuteSendPresetAsync(
                rule,
                triggerEvent.TriggerEventId,
                actionIndex,
                targetThread,
                targetTurn,
                resolvedPreset.OwnerConversationId,
                preset,
                includeSubAgents: false,
                () => IsPolicyCurrent(policyToken),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private bool IsPolicyCurrent(WorkflowDispatchPolicyToken token)
    {
        try
        {
            return dispatchPolicy.IsCurrent(token);
        }
        catch
        {
            return false;
        }
    }

    private static WorkflowActionExecutionResult Waiting(string message) =>
        new(WorkflowActionExecutionStatus.Waiting, Record: null, message);
}
