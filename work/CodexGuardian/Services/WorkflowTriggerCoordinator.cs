using CodexGuardian.Models;
using System.Globalization;

namespace CodexGuardian.Services;

internal sealed record WorkflowConditionEvaluationResult(
    bool IsAllowed,
    IReadOnlyList<WorkflowConditionKind> FailedConditions);

internal interface IWorkflowConditionEvaluator
{
    Task<WorkflowConditionEvaluationResult> EvaluateAsync(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        CancellationToken cancellationToken);
}

internal interface IWorkflowRuleActionRunner
{
    Task<WorkflowActionExecutionResult> RunAsync(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        int actionIndex,
        CancellationToken cancellationToken);
}

internal sealed record WorkflowTriggeredRuleResult(
    string RuleId,
    WorkflowTriggerEventRecord TriggerEvent,
    bool TriggerCreated,
    WorkflowConditionEvaluationResult Conditions,
    IReadOnlyList<WorkflowActionExecutionResult> Actions);

internal sealed class WorkflowTriggerCoordinator
{
    private readonly WorkflowOperationJournal _journal;
    private readonly IWorkflowConditionEvaluator _conditions;
    private readonly IWorkflowRuleActionRunner _runner;

    internal WorkflowTriggerCoordinator(
        WorkflowOperationJournal journal,
        IWorkflowConditionEvaluator conditions,
        IWorkflowRuleActionRunner runner)
    {
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _conditions = conditions ?? throw new ArgumentNullException(nameof(conditions));
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
    }

    internal Task<IReadOnlyList<WorkflowTriggeredRuleResult>> ProcessScheduledAsync(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        observedAtUtc = RequireUtc(observedAtUtc, nameof(observedAtUtc));
        var matched = ValidateRules(rules)
            .Where(rule =>
                rule.IsEnabled &&
                rule.Trigger.Kind == WorkflowTriggerKind.ScheduledAt &&
                rule.Trigger.ScheduledAtUtc is { } scheduledAtUtc &&
                scheduledAtUtc >= rule.ActivatedAtUtc &&
                scheduledAtUtc <= observedAtUtc)
            .ToArray();
        return ProcessAsync(
            matched,
            rule => new TriggerRequest(
                WorkflowTriggerKind.ScheduledAt,
                rule.OwnerConversationId,
                rule.RuleId,
                rule.RuleId,
                "scheduled:" + rule.Trigger.ScheduledAtUtc!.Value.UtcTicks,
                observedAtUtc,
                CausationId: null),
            cancellationToken);
    }

    internal async Task<IReadOnlyList<WorkflowTriggeredRuleResult>> ProcessConversationCompletedAsync(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        ThreadSummary sourceConversation,
        TurnSnapshot completedTurn,
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sourceConversation);
        ArgumentNullException.ThrowIfNull(completedTurn);
        observedAtUtc = RequireUtc(observedAtUtc, nameof(observedAtUtc));
        if (sourceConversation.IsArchived || sourceConversation.IsSubAgent ||
            sourceConversation.IsEphemeral ||
            !FollowUpQueuePlanner.IsNormalCompletion(completedTurn) ||
            !TryReadCompletedAtUtc(completedTurn, out var completedAtUtc) ||
            observedAtUtc < completedAtUtc)
        {
            return Array.Empty<WorkflowTriggeredRuleResult>();
        }

        var matched = ValidateRules(rules)
            .Where(rule =>
                rule.IsEnabled &&
                rule.Trigger.Kind == WorkflowTriggerKind.ConversationCompletedNormally &&
                string.Equals(
                    rule.Trigger.SourceConversationId,
                    sourceConversation.Id,
                    StringComparison.OrdinalIgnoreCase) &&
                completedAtUtc >= rule.ActivatedAtUtc)
            .ToArray();
        if (matched.Length == 0)
        {
            return Array.Empty<WorkflowTriggeredRuleResult>();
        }

        var snapshot = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        var parents = snapshot.Actions.Where(action =>
                action.State == WorkflowActionOperationState.Confirmed &&
                string.Equals(
                    action.ConfirmedTargetConversationId,
                    sourceConversation.Id,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    action.GeneratedTurnId,
                    completedTurn.Id,
                    StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (parents.Length > 1)
        {
            throw new InvalidDataException(
                "A completed workflow turn has more than one parent action receipt.");
        }

        var causationId = parents.SingleOrDefault()?.ActionOperationId;
        return await ProcessAsync(
                matched,
                _ => new TriggerRequest(
                    WorkflowTriggerKind.ConversationCompletedNormally,
                    sourceConversation.Id,
                    sourceConversation.Id,
                    completedTurn.Id,
                    "normal-completion:" + completedTurn.CompletedAt!.Value.ToString(
                        CultureInfo.InvariantCulture),
                    observedAtUtc,
                    causationId),
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<WorkflowTriggeredRuleResult>>
        ProcessPresetDispatchConfirmedAsync(
            IReadOnlyList<WorkflowRuleDefinition> rules,
            string sourceActionOperationId,
            DateTimeOffset observedAtUtc,
            CancellationToken cancellationToken = default)
    {
        observedAtUtc = RequireUtc(observedAtUtc, nameof(observedAtUtc));
        sourceActionOperationId = NormalizeId(
            sourceActionOperationId,
            nameof(sourceActionOperationId));
        var snapshot = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        var source = snapshot.Actions.SingleOrDefault(action => string.Equals(
            action.ActionOperationId,
            sourceActionOperationId,
            StringComparison.OrdinalIgnoreCase));
        if (source is null || source.State != WorkflowActionOperationState.Confirmed ||
            source.ActionKind != WorkflowActionKind.SendPresetMessage ||
            source.PresetOwnerConversationId is null || source.PresetMessageId is null ||
            source.GeneratedTurnId is null)
        {
            return Array.Empty<WorkflowTriggeredRuleResult>();
        }

        var matched = ValidateRules(rules)
            .Where(rule =>
                rule.IsEnabled &&
                rule.Trigger.Kind == WorkflowTriggerKind.PresetDispatchConfirmed &&
                string.Equals(
                    rule.Trigger.SourceConversationId,
                    source.PresetOwnerConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    rule.Trigger.SourcePresetMessageId,
                    source.PresetMessageId,
                    StringComparison.OrdinalIgnoreCase) &&
                observedAtUtc >= rule.ActivatedAtUtc)
            .ToArray();
        return await ProcessAsync(
                matched,
                _ => new TriggerRequest(
                    WorkflowTriggerKind.PresetDispatchConfirmed,
                    source.PresetOwnerConversationId,
                    source.PresetMessageId,
                    source.ActionOperationId,
                    source.GeneratedTurnId,
                    observedAtUtc,
                    source.ActionOperationId),
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<WorkflowTriggeredRuleResult>> ResumeDurableTriggerAsync(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        WorkflowTriggerEventRecord triggerEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(triggerEvent);
        var matched = ValidateRules(rules)
            .Where(rule => RuleMatchesDurableTrigger(rule, triggerEvent))
            .OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
            .ToArray();
        var results = new List<WorkflowTriggeredRuleResult>(matched.Length);
        foreach (var rule in matched)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await ExecutePreparedRuleAsync(
                    rule,
                    triggerEvent,
                    triggerCreated: false,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return results.AsReadOnly();
    }

    private async Task<IReadOnlyList<WorkflowTriggeredRuleResult>> ProcessAsync(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        Func<WorkflowRuleDefinition, TriggerRequest> createRequest,
        CancellationToken cancellationToken)
    {
        var results = new List<WorkflowTriggeredRuleResult>(rules.Count);
        foreach (var rule in rules.OrderBy(rule => rule.RuleId, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = createRequest(rule);
            var prepared = await _journal.GetOrCreateTriggerEventAsync(
                    request.Kind,
                    request.SourceConversationId,
                    request.SourceId,
                    request.SourceTurnOrOperationId,
                    request.Occurrence,
                    request.ObservedAtUtc,
                    causationId: request.CausationId,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            results.Add(await ExecutePreparedRuleAsync(
                    rule,
                    prepared.Record,
                    prepared.Created,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return results.AsReadOnly();
    }

    private async Task<WorkflowTriggeredRuleResult> ExecutePreparedRuleAsync(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        bool triggerCreated,
        CancellationToken cancellationToken)
    {
        var conditions = await _conditions.EvaluateAsync(rule, triggerEvent, cancellationToken)
            .ConfigureAwait(false);
        if (!conditions.IsAllowed)
        {
            return new WorkflowTriggeredRuleResult(
                rule.RuleId,
                triggerEvent,
                triggerCreated,
                NormalizeConditionResult(rule, conditions),
                Array.Empty<WorkflowActionExecutionResult>());
        }

        var actionResults = new List<WorkflowActionExecutionResult>(rule.Actions.Count);
        for (var actionIndex = 0; actionIndex < rule.Actions.Count; actionIndex++)
        {
            var actionResult = await _runner.RunAsync(
                    rule,
                    triggerEvent,
                    actionIndex,
                    cancellationToken)
                .ConfigureAwait(false);
            actionResults.Add(actionResult);
            if (actionResult.Status != WorkflowActionExecutionStatus.Confirmed)
            {
                break;
            }
        }

        return new WorkflowTriggeredRuleResult(
            rule.RuleId,
            triggerEvent,
            triggerCreated,
            NormalizeConditionResult(rule, conditions),
            actionResults.AsReadOnly());
    }

    private static WorkflowConditionEvaluationResult NormalizeConditionResult(
        WorkflowRuleDefinition rule,
        WorkflowConditionEvaluationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.FailedConditions is null ||
            result.FailedConditions.Any(condition =>
                !Enum.IsDefined(condition) || !rule.Conditions.Contains(condition)) ||
            result.IsAllowed && result.FailedConditions.Count != 0 ||
            !result.IsAllowed && result.FailedConditions.Count == 0)
        {
            throw new InvalidDataException("The workflow condition result is not finite or self-consistent.");
        }

        return new WorkflowConditionEvaluationResult(
            result.IsAllowed,
            Array.AsReadOnly(result.FailedConditions.Distinct().Order().ToArray()));
    }

    private static IReadOnlyList<WorkflowRuleDefinition> ValidateRules(
        IReadOnlyList<WorkflowRuleDefinition> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var validation = WorkflowRuleGraphValidator.Validate(rules);
        if (validation.Issues.Any(issue =>
                issue.Code != WorkflowRuleValidationIssueCode.NewConversationUnavailable))
        {
            throw new InvalidDataException("The trigger coordinator requires a canonical acyclic rule set.");
        }

        return rules;
    }

    private static bool RuleMatchesDurableTrigger(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent)
    {
        if (!rule.IsEnabled || rule.Trigger.Kind != triggerEvent.TriggerKind)
        {
            return false;
        }

        return triggerEvent.TriggerKind switch
        {
            WorkflowTriggerKind.ScheduledAt =>
                rule.Trigger.ScheduledAtUtc is { } scheduledAtUtc &&
                scheduledAtUtc >= rule.ActivatedAtUtc &&
                triggerEvent.ObservedAtUtc >= scheduledAtUtc &&
                string.Equals(
                    rule.OwnerConversationId,
                    triggerEvent.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(rule.RuleId, triggerEvent.SourceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    rule.RuleId,
                    triggerEvent.SourceTurnOrOperationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    triggerEvent.Occurrence,
                    "scheduled:" + scheduledAtUtc.UtcTicks,
                    StringComparison.Ordinal),
            WorkflowTriggerKind.ConversationCompletedNormally =>
                string.Equals(
                    rule.Trigger.SourceConversationId,
                    triggerEvent.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    triggerEvent.SourceConversationId,
                    triggerEvent.SourceId,
                    StringComparison.OrdinalIgnoreCase) &&
                CompletionOccurrenceAllowsRule(triggerEvent.Occurrence, rule.ActivatedAtUtc),
            WorkflowTriggerKind.PresetDispatchConfirmed =>
                triggerEvent.ObservedAtUtc >= rule.ActivatedAtUtc &&
                string.Equals(
                    rule.Trigger.SourceConversationId,
                    triggerEvent.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    rule.Trigger.SourcePresetMessageId,
                    triggerEvent.SourceId,
                    StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool CompletionOccurrenceAllowsRule(
        string occurrence,
        DateTimeOffset activatedAtUtc)
    {
        const string prefix = "normal-completion:";
        if (string.Equals(occurrence, "normal-completion", StringComparison.Ordinal))
        {
            return true;
        }

        if (!occurrence.StartsWith(prefix, StringComparison.Ordinal) ||
            !long.TryParse(
                occurrence.AsSpan(prefix.Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var completedAtSeconds))
        {
            return false;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(completedAtSeconds) >= activatedAtUtc;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static DateTimeOffset RequireUtc(DateTimeOffset value, string parameterName)
    {
        if (value == default)
        {
            throw new ArgumentException("A workflow observation time is required.", parameterName);
        }

        return value.ToUniversalTime();
    }

    private static bool TryReadCompletedAtUtc(
        TurnSnapshot turn,
        out DateTimeOffset completedAtUtc)
    {
        completedAtUtc = default;
        if (turn.CompletedAt is not { } completedAt)
        {
            return false;
        }

        try
        {
            completedAtUtc = DateTimeOffset.FromUnixTimeSeconds(completedAt);
            return true;
        }
        catch (ArgumentOutOfRangeException)
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

    private sealed record TriggerRequest(
        WorkflowTriggerKind Kind,
        string SourceConversationId,
        string SourceId,
        string SourceTurnOrOperationId,
        string Occurrence,
        DateTimeOffset ObservedAtUtc,
        string? CausationId);
}
