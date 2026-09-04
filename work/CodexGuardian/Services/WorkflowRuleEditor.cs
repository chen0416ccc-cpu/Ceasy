using CodexGuardian.Models;
using System.Security.Cryptography;
using System.Text;

namespace CodexGuardian.Services;

internal sealed record WorkflowRuleEditorDraft(
    string MessageId,
    bool IsEnabled,
    WorkflowTriggerKind TriggerKind,
    string? SourceConversationId,
    string? SourcePresetMessageId,
    DateTimeOffset? ScheduledAtUtc,
    WorkflowDestinationKind DestinationKind,
    string? TargetConversationId,
    bool EnableTargetProtection);

internal static class WorkflowRuleEditor
{
    private static readonly IReadOnlyList<WorkflowConditionKind> DefaultConditions =
        Array.AsReadOnly(
        [
            WorkflowConditionKind.SourceConversationExists,
            WorkflowConditionKind.TargetConversationExists,
            WorkflowConditionKind.RuleAndPresetEnabled,
            WorkflowConditionKind.SourceEventAfterActivation,
            WorkflowConditionKind.TargetIdle,
            WorkflowConditionKind.TargetPolicyAllowsAction,
            WorkflowConditionKind.ManagedAttachmentsAvailable
        ]);

    internal static string CreateManagedRuleId(
        string ownerConversationId,
        string presetMessageId)
    {
        var owner = NormalizeId(ownerConversationId, nameof(ownerConversationId));
        var preset = NormalizeId(presetMessageId, nameof(presetMessageId));
        var payload = Encoding.UTF8.GetBytes(owner + "\n" + preset);
        var hash = SHA256.HashData(payload);
        Span<byte> bytes = stackalloc byte[16];
        hash.AsSpan(0, bytes.Length).CopyTo(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes, bigEndian: true).ToString("D");
    }

    internal static WorkflowRuleDefinition? FindManagedRule(
        WorkflowRuleStoreSnapshot? snapshot,
        string ownerConversationId,
        string presetMessageId)
    {
        if (snapshot is null)
        {
            return null;
        }

        var ruleId = CreateManagedRuleId(ownerConversationId, presetMessageId);
        return snapshot.Rules.SingleOrDefault(rule => string.Equals(
            rule.RuleId,
            ruleId,
            StringComparison.OrdinalIgnoreCase));
    }

    internal static IReadOnlyList<WorkflowRuleDefinition> BuildReplacement(
        WorkflowRuleStoreSnapshot snapshot,
        string ownerConversationId,
        IReadOnlyList<WorkflowRuleEditorDraft> drafts,
        DateTimeOffset activatedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(drafts);
        var owner = NormalizeId(ownerConversationId, nameof(ownerConversationId));
        if (activatedAtUtc == default)
        {
            throw new ArgumentException("A workflow activation boundary is required.", nameof(activatedAtUtc));
        }

        var existingManaged = snapshot.Rules
            .Where(rule => IsManagedRuleForOwner(rule, owner))
            .ToDictionary(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase);
        var replacement = snapshot.Rules
            .Where(rule => !IsManagedRuleForOwner(rule, owner))
            .ToList();
        var seenMessages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var draft in drafts)
        {
            var messageId = NormalizeId(draft.MessageId, nameof(draft.MessageId));
            if (!seenMessages.Add(messageId))
            {
                throw new ArgumentException("Workflow editor drafts contain a duplicate preset id.", nameof(drafts));
            }

            var ruleId = CreateManagedRuleId(owner, messageId);
            existingManaged.TryGetValue(ruleId, out var existing);
            replacement.Add(BuildManagedRule(
                owner,
                draft with { MessageId = messageId },
                activatedAtUtc.ToUniversalTime(),
                existing));
        }

        return replacement
            .OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
            .ToArray();
    }

    internal static bool IsManagedRuleForOwner(
        WorkflowRuleDefinition rule,
        string ownerConversationId)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var owner = NormalizeId(ownerConversationId, nameof(ownerConversationId));
        var sends = rule.Actions.Where(action =>
                action.Kind == WorkflowActionKind.SendPresetMessage &&
                string.Equals(
                    action.PresetOwnerConversationId,
                    owner,
                    StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return sends.Length == 1 &&
               string.Equals(
                   rule.RuleId,
                   CreateManagedRuleId(owner, sends[0].PresetMessageId!),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static WorkflowRuleDefinition BuildManagedRule(
        string ownerConversationId,
        WorkflowRuleEditorDraft draft,
        DateTimeOffset activatedAtUtc,
        WorkflowRuleDefinition? existing)
    {
        var trigger = draft.TriggerKind switch
        {
            WorkflowTriggerKind.ScheduledAt when draft.ScheduledAtUtc is { } scheduledAtUtc =>
                new WorkflowTriggerDefinition
                {
                    Kind = WorkflowTriggerKind.ScheduledAt,
                    ScheduledAtUtc = scheduledAtUtc.ToUniversalTime()
                },
            WorkflowTriggerKind.ConversationCompletedNormally =>
                new WorkflowTriggerDefinition
                {
                    Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                    SourceConversationId = NormalizeId(
                        draft.SourceConversationId,
                        nameof(draft.SourceConversationId))
                },
            WorkflowTriggerKind.PresetDispatchConfirmed =>
                new WorkflowTriggerDefinition
                {
                    Kind = WorkflowTriggerKind.PresetDispatchConfirmed,
                    SourceConversationId = NormalizeId(
                        draft.SourceConversationId,
                        nameof(draft.SourceConversationId)),
                    SourcePresetMessageId = NormalizeId(
                        draft.SourcePresetMessageId,
                        nameof(draft.SourcePresetMessageId))
                },
            _ => throw new ArgumentException(
                "The workflow editor trigger is incomplete or unsupported.",
                nameof(draft))
        };
        var destination = draft.DestinationKind switch
        {
            WorkflowDestinationKind.CurrentConversation => new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.CurrentConversation
            },
            WorkflowDestinationKind.ExistingConversation => new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation,
                ConversationId = NormalizeId(
                    draft.TargetConversationId,
                    nameof(draft.TargetConversationId))
            },
            WorkflowDestinationKind.NewConversation => new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.NewConversation
            },
            _ => throw new ArgumentOutOfRangeException(nameof(draft))
        };
        var actions = new List<WorkflowActionDefinition>();
        if (draft.EnableTargetProtection)
        {
            actions.Add(new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = actions.Count
            });
        }

        actions.Add(new WorkflowActionDefinition
        {
            Kind = WorkflowActionKind.SendPresetMessage,
            PresetOwnerConversationId = ownerConversationId,
            PresetMessageId = draft.MessageId,
            Order = actions.Count
        });
        var conditions = draft.EnableTargetProtection
            ? Array.AsReadOnly(DefaultConditions.Where(static condition =>
                    condition is not WorkflowConditionKind.TargetPolicyAllowsAction)
                .ToArray())
            : DefaultConditions;

        if (existing is not null &&
            existing.IsEnabled == draft.IsEnabled &&
            string.Equals(
                existing.OwnerConversationId,
                ownerConversationId,
                StringComparison.OrdinalIgnoreCase) &&
            existing.Trigger == trigger &&
            existing.Destination == destination &&
            existing.Conditions.SequenceEqual(conditions) &&
            existing.Actions.SequenceEqual(actions))
        {
            return existing;
        }

        return WorkflowRuleDefinition.Create(
            CreateManagedRuleId(ownerConversationId, draft.MessageId),
            existing is null ? 1 : checked(existing.Revision + 1),
            ownerConversationId,
            draft.IsEnabled,
            activatedAtUtc,
            trigger,
            destination,
            conditions,
            actions);
    }

    private static string NormalizeId(string? value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty canonical UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }
}
