using CodexGuardian.Models;
using System.Collections.ObjectModel;

namespace CodexGuardian.Services;

internal enum WorkflowRuleValidationIssueCode
{
    RuleSetLimitExceeded,
    InvalidDefinition,
    DuplicateRuleId,
    NewConversationUnavailable,
    CycleDetected
}

internal sealed record WorkflowRuleValidationIssue(
    WorkflowRuleValidationIssueCode Code,
    string? RuleId,
    int? ActionIndex,
    string Detail,
    IReadOnlyList<string> RulePath);

internal sealed record WorkflowRuleGraphCapabilities(bool AllowsNewConversation)
{
    internal static WorkflowRuleGraphCapabilities Conservative { get; } = new(false);
}

internal sealed record WorkflowRuleGraphValidationResult(
    bool IsValid,
    IReadOnlyList<WorkflowRuleValidationIssue> Issues,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Edges);

internal static class WorkflowRuleGraphValidator
{
    internal const int MaximumRules = 2048;

    internal static WorkflowRuleGraphValidationResult Validate(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        WorkflowRuleGraphCapabilities? capabilities = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        capabilities ??= WorkflowRuleGraphCapabilities.Conservative;
        var issues = new List<WorkflowRuleValidationIssue>();
        if (rules.Count > MaximumRules)
        {
            issues.Add(new WorkflowRuleValidationIssue(
                WorkflowRuleValidationIssueCode.RuleSetLimitExceeded,
                RuleId: null,
                ActionIndex: null,
                "The workflow rule set exceeds its hard bound.",
                Array.Empty<string>()));
            return CreateResult(issues, new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase));
        }

        var rulesById = new Dictionary<string, WorkflowRuleDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            if (rule is null || !rule.HasValidIdentity())
            {
                issues.Add(new WorkflowRuleValidationIssue(
                    WorkflowRuleValidationIssueCode.InvalidDefinition,
                    rule?.RuleId,
                    ActionIndex: null,
                    "A workflow rule does not have canonical typed identity.",
                    Array.Empty<string>()));
                continue;
            }

            if (!rulesById.TryAdd(rule.RuleId, rule))
            {
                issues.Add(new WorkflowRuleValidationIssue(
                    WorkflowRuleValidationIssueCode.DuplicateRuleId,
                    rule.RuleId,
                    ActionIndex: null,
                    "Only one revision of a workflow rule may be active in a validated rule set.",
                    [rule.RuleId]));
            }

            if (rule.Destination.Kind == WorkflowDestinationKind.NewConversation &&
                !capabilities.AllowsNewConversation)
            {
                issues.Add(new WorkflowRuleValidationIssue(
                    WorkflowRuleValidationIssueCode.NewConversationUnavailable,
                    rule.RuleId,
                    ActionIndex: null,
                    "The installed stock Desktop owner has not proved create-and-first-turn capability.",
                    [rule.RuleId]));
            }
        }

        if (issues.Any(issue => issue.Code is
                WorkflowRuleValidationIssueCode.InvalidDefinition or
                WorkflowRuleValidationIssueCode.DuplicateRuleId or
                WorkflowRuleValidationIssueCode.RuleSetLimitExceeded))
        {
            return CreateResult(
                issues,
                new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase));
        }

        var normalCompletionTriggers = new Dictionary<string, List<string>>(
            StringComparer.OrdinalIgnoreCase);
        var dispatchConfirmationTriggers = new Dictionary<PresetKey, List<string>>();
        foreach (var rule in rulesById.Values)
        {
            switch (rule.Trigger.Kind)
            {
                case WorkflowTriggerKind.ConversationCompletedNormally:
                    AddLookup(
                        normalCompletionTriggers,
                        rule.Trigger.SourceConversationId!,
                        rule.RuleId);
                    break;
                case WorkflowTriggerKind.PresetDispatchConfirmed:
                    AddLookup(
                        dispatchConfirmationTriggers,
                        new PresetKey(
                            rule.Trigger.SourceConversationId!,
                            rule.Trigger.SourcePresetMessageId!),
                        rule.RuleId);
                    break;
            }
        }

        var edges = rulesById.Keys.ToDictionary(
            ruleId => ruleId,
            _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rulesById.Values)
        {
            foreach (var action in rule.Actions.Where(action =>
                         action.Kind == WorkflowActionKind.SendPresetMessage))
            {
                var presetKey = new PresetKey(
                    action.PresetOwnerConversationId!,
                    action.PresetMessageId!);
                if (dispatchConfirmationTriggers.TryGetValue(presetKey, out var dispatchTargets))
                {
                    edges[rule.RuleId].UnionWith(dispatchTargets);
                }

                var targetConversationId = rule.ResolveKnownDestinationConversationId();
                if (targetConversationId is not null &&
                    normalCompletionTriggers.TryGetValue(targetConversationId, out var completionTargets))
                {
                    edges[rule.RuleId].UnionWith(completionTargets);
                }
            }
        }

        var cycle = FindFirstCycle(edges);
        if (cycle.Count > 0)
        {
            issues.Add(new WorkflowRuleValidationIssue(
                WorkflowRuleValidationIssueCode.CycleDetected,
                cycle[0],
                ActionIndex: null,
                "The workflow graph contains a direct or transitive trigger cycle.",
                cycle));
        }

        return CreateResult(issues, edges);
    }

    private static WorkflowRuleGraphValidationResult CreateResult(
        IReadOnlyList<WorkflowRuleValidationIssue> issues,
        IReadOnlyDictionary<string, HashSet<string>> edges)
    {
        var projected = edges
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(
                pair => pair.Key,
                pair => (IReadOnlyList<string>)Array.AsReadOnly(pair.Value
                    .Order(StringComparer.Ordinal)
                    .ToArray()),
                StringComparer.OrdinalIgnoreCase);
        return new WorkflowRuleGraphValidationResult(
            issues.Count == 0,
            Array.AsReadOnly(issues.ToArray()),
            new ReadOnlyDictionary<string, IReadOnlyList<string>>(projected));
    }

    private static IReadOnlyList<string> FindFirstCycle(
        IReadOnlyDictionary<string, HashSet<string>> edges)
    {
        var state = edges.Keys.ToDictionary(
            ruleId => ruleId,
            _ => 0,
            StringComparer.OrdinalIgnoreCase);
        var stack = new List<string>();
        var stackIndexes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<string>? cycle = null;

        bool Visit(string ruleId)
        {
            state[ruleId] = 1;
            stackIndexes[ruleId] = stack.Count;
            stack.Add(ruleId);
            foreach (var target in edges[ruleId].Order(StringComparer.Ordinal))
            {
                if (!state.TryGetValue(target, out var targetState))
                {
                    continue;
                }

                if (targetState == 0 && Visit(target))
                {
                    return true;
                }

                if (targetState == 1)
                {
                    var start = stackIndexes[target];
                    cycle = stack.Skip(start).Append(target).ToArray();
                    return true;
                }
            }

            stack.RemoveAt(stack.Count - 1);
            stackIndexes.Remove(ruleId);
            state[ruleId] = 2;
            return false;
        }

        foreach (var ruleId in edges.Keys.Order(StringComparer.Ordinal))
        {
            if (state[ruleId] == 0 && Visit(ruleId))
            {
                break;
            }
        }

        return cycle ?? Array.Empty<string>();
    }

    private static void AddLookup<TKey>(
        Dictionary<TKey, List<string>> lookup,
        TKey key,
        string ruleId)
        where TKey : notnull
    {
        if (!lookup.TryGetValue(key, out var values))
        {
            values = [];
            lookup.Add(key, values);
        }

        values.Add(ruleId);
    }

    private sealed record PresetKey(string OwnerConversationId, string MessageId);
}
