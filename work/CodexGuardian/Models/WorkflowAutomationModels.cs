using System.Security.Cryptography;
using System.Text.Json;

namespace CodexGuardian.Models;

public enum WorkflowTriggerKind
{
    ScheduledAt,
    ConversationCompletedNormally,
    PresetDispatchConfirmed
}

public enum WorkflowDestinationKind
{
    CurrentConversation,
    ExistingConversation,
    NewConversation
}

public enum WorkflowConditionKind
{
    SourceConversationExists,
    TargetConversationExists,
    RuleAndPresetEnabled,
    SourceEventAfterActivation,
    TargetIdle,
    TargetPolicyAllowsAction,
    ManagedAttachmentsAvailable
}

public enum WorkflowActionKind
{
    SendPresetMessage,
    EnableConversationProtection
}

public sealed record WorkflowTriggerDefinition
{
    public required WorkflowTriggerKind Kind { get; init; }

    public string? SourceConversationId { get; init; }

    public string? SourcePresetMessageId { get; init; }

    public DateTimeOffset? ScheduledAtUtc { get; init; }
}

public sealed record WorkflowDestinationDefinition
{
    public required WorkflowDestinationKind Kind { get; init; }

    public string? ConversationId { get; init; }
}

public sealed record WorkflowActionDefinition
{
    public required WorkflowActionKind Kind { get; init; }

    public string? PresetOwnerConversationId { get; init; }

    public string? PresetMessageId { get; init; }

    public int Order { get; init; }
}

public sealed class WorkflowRuleDefinition
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumConditions = 16;
    public const int MaximumActions = 8;

    private WorkflowRuleDefinition(
        int schemaVersion,
        string ruleId,
        int revision,
        string ownerConversationId,
        bool isEnabled,
        DateTimeOffset activatedAtUtc,
        WorkflowTriggerDefinition trigger,
        WorkflowDestinationDefinition destination,
        IReadOnlyList<WorkflowConditionKind> conditions,
        IReadOnlyList<WorkflowActionDefinition> actions,
        string definitionDigest)
    {
        SchemaVersion = schemaVersion;
        RuleId = ruleId;
        Revision = revision;
        OwnerConversationId = ownerConversationId;
        IsEnabled = isEnabled;
        ActivatedAtUtc = activatedAtUtc;
        Trigger = trigger;
        Destination = destination;
        Conditions = conditions;
        Actions = actions;
        DefinitionDigest = definitionDigest;
    }

    public int SchemaVersion { get; }

    public string RuleId { get; }

    public int Revision { get; }

    public string OwnerConversationId { get; }

    public bool IsEnabled { get; }

    public DateTimeOffset ActivatedAtUtc { get; }

    public WorkflowTriggerDefinition Trigger { get; }

    public WorkflowDestinationDefinition Destination { get; }

    public IReadOnlyList<WorkflowConditionKind> Conditions { get; }

    public IReadOnlyList<WorkflowActionDefinition> Actions { get; }

    public string DefinitionDigest { get; }

    public static WorkflowRuleDefinition Create(
        string ruleId,
        int revision,
        string ownerConversationId,
        bool isEnabled,
        DateTimeOffset activatedAtUtc,
        WorkflowTriggerDefinition trigger,
        WorkflowDestinationDefinition destination,
        IEnumerable<WorkflowConditionKind>? conditions,
        IEnumerable<WorkflowActionDefinition> actions)
    {
        ruleId = NormalizeId(ruleId, nameof(ruleId));
        ownerConversationId = NormalizeId(ownerConversationId, nameof(ownerConversationId));
        if (revision <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        if (activatedAtUtc == default)
        {
            throw new ArgumentException("A workflow activation boundary is required.", nameof(activatedAtUtc));
        }

        activatedAtUtc = activatedAtUtc.ToUniversalTime();
        var normalizedTrigger = NormalizeTrigger(trigger);
        var normalizedDestination = NormalizeDestination(destination);
        var normalizedConditions = NormalizeConditions(conditions);
        var normalizedActions = NormalizeActions(actions);
        var digest = ComputeDigest(
            CurrentSchemaVersion,
            ruleId,
            revision,
            ownerConversationId,
            isEnabled,
            activatedAtUtc,
            normalizedTrigger,
            normalizedDestination,
            normalizedConditions,
            normalizedActions);
        return new WorkflowRuleDefinition(
            CurrentSchemaVersion,
            ruleId,
            revision,
            ownerConversationId,
            isEnabled,
            activatedAtUtc,
            normalizedTrigger,
            normalizedDestination,
            normalizedConditions,
            normalizedActions,
            digest);
    }

    internal bool HasValidIdentity()
    {
        if (SchemaVersion != CurrentSchemaVersion || !IsCanonicalSha256(DefinitionDigest))
        {
            return false;
        }

        try
        {
            var canonical = Create(
                RuleId,
                Revision,
                OwnerConversationId,
                IsEnabled,
                ActivatedAtUtc,
                Trigger,
                Destination,
                Conditions,
                Actions);
            return string.Equals(RuleId, canonical.RuleId, StringComparison.Ordinal) &&
                   Revision == canonical.Revision &&
                   string.Equals(
                       OwnerConversationId,
                       canonical.OwnerConversationId,
                       StringComparison.Ordinal) &&
                   IsEnabled == canonical.IsEnabled &&
                   ActivatedAtUtc == canonical.ActivatedAtUtc &&
                   Trigger == canonical.Trigger &&
                   Destination == canonical.Destination &&
                   Conditions.SequenceEqual(canonical.Conditions) &&
                   Actions.SequenceEqual(canonical.Actions) &&
                   string.Equals(
                       DefinitionDigest,
                       canonical.DefinitionDigest,
                       StringComparison.Ordinal);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or OverflowException)
        {
            return false;
        }
    }

    internal string? ResolveKnownDestinationConversationId() =>
        Destination.Kind switch
        {
            WorkflowDestinationKind.CurrentConversation => OwnerConversationId,
            WorkflowDestinationKind.ExistingConversation => Destination.ConversationId,
            _ => null
        };

    private static WorkflowTriggerDefinition NormalizeTrigger(WorkflowTriggerDefinition trigger)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        if (!Enum.IsDefined(trigger.Kind))
        {
            throw new ArgumentOutOfRangeException(nameof(trigger));
        }

        return trigger.Kind switch
        {
            WorkflowTriggerKind.ScheduledAt when
                trigger.ScheduledAtUtc is { } scheduledAtUtc &&
                scheduledAtUtc != default &&
                trigger.SourceConversationId is null &&
                trigger.SourcePresetMessageId is null =>
                trigger with { ScheduledAtUtc = scheduledAtUtc.ToUniversalTime() },
            WorkflowTriggerKind.ConversationCompletedNormally when
                trigger.ScheduledAtUtc is null &&
                trigger.SourcePresetMessageId is null =>
                trigger with
                {
                    SourceConversationId = NormalizeId(
                        trigger.SourceConversationId,
                        nameof(trigger.SourceConversationId))
                },
            WorkflowTriggerKind.PresetDispatchConfirmed when trigger.ScheduledAtUtc is null =>
                trigger with
                {
                    SourceConversationId = NormalizeId(
                        trigger.SourceConversationId,
                        nameof(trigger.SourceConversationId)),
                    SourcePresetMessageId = NormalizeId(
                        trigger.SourcePresetMessageId,
                        nameof(trigger.SourcePresetMessageId))
                },
            _ => throw new ArgumentException(
                "The workflow trigger contains fields that do not belong to its typed kind.",
                nameof(trigger))
        };
    }

    private static WorkflowDestinationDefinition NormalizeDestination(
        WorkflowDestinationDefinition destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!Enum.IsDefined(destination.Kind))
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }

        return destination.Kind switch
        {
            WorkflowDestinationKind.CurrentConversation when destination.ConversationId is null =>
                destination,
            WorkflowDestinationKind.ExistingConversation => destination with
            {
                ConversationId = NormalizeId(destination.ConversationId, nameof(destination.ConversationId))
            },
            WorkflowDestinationKind.NewConversation when destination.ConversationId is null => destination,
            _ => throw new ArgumentException(
                "The workflow destination contains fields that do not belong to its typed kind.",
                nameof(destination))
        };
    }

    private static IReadOnlyList<WorkflowConditionKind> NormalizeConditions(
        IEnumerable<WorkflowConditionKind>? conditions)
    {
        var source = conditions?.ToArray() ?? [];
        if (source.Length > MaximumConditions || source.Any(condition => !Enum.IsDefined(condition)))
        {
            throw new ArgumentException("The workflow condition set is invalid or unbounded.", nameof(conditions));
        }

        return Array.AsReadOnly(source.Distinct().Order().ToArray());
    }

    private static IReadOnlyList<WorkflowActionDefinition> NormalizeActions(
        IEnumerable<WorkflowActionDefinition> actions)
    {
        ArgumentNullException.ThrowIfNull(actions);
        var source = actions.ToArray();
        if (source.Length is < 1 or > MaximumActions || source.Any(action => action is null))
        {
            throw new ArgumentException("A bounded non-empty workflow action list is required.", nameof(actions));
        }

        var ordered = source.OrderBy(action => action.Order).ToArray();
        var normalized = new List<WorkflowActionDefinition>(ordered.Length);
        var semanticKeys = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < ordered.Length; index++)
        {
            var action = ordered[index];
            if (action.Order != index || !Enum.IsDefined(action.Kind))
            {
                throw new ArgumentException(
                    "Workflow action order must be unique, contiguous, and typed.",
                    nameof(actions));
            }

            var candidate = action.Kind switch
            {
                WorkflowActionKind.SendPresetMessage => action with
                {
                    PresetOwnerConversationId = NormalizeId(
                        action.PresetOwnerConversationId,
                        nameof(action.PresetOwnerConversationId)),
                    PresetMessageId = NormalizeId(
                        action.PresetMessageId,
                        nameof(action.PresetMessageId))
                },
                WorkflowActionKind.EnableConversationProtection when
                    action.PresetOwnerConversationId is null && action.PresetMessageId is null => action,
                _ => throw new ArgumentException(
                    "The workflow action contains fields that do not belong to its typed kind.",
                    nameof(actions))
            };
            var semanticKey = string.Join(
                "|",
                ((int)candidate.Kind).ToString(System.Globalization.CultureInfo.InvariantCulture),
                candidate.PresetOwnerConversationId ?? string.Empty,
                candidate.PresetMessageId ?? string.Empty);
            if (!semanticKeys.Add(semanticKey))
            {
                throw new ArgumentException("A workflow rule cannot contain duplicate actions.", nameof(actions));
            }

            normalized.Add(candidate);
        }

        return Array.AsReadOnly(normalized.ToArray());
    }

    private static string ComputeDigest(
        int schemaVersion,
        string ruleId,
        int revision,
        string ownerConversationId,
        bool isEnabled,
        DateTimeOffset activatedAtUtc,
        WorkflowTriggerDefinition trigger,
        WorkflowDestinationDefinition destination,
        IReadOnlyList<WorkflowConditionKind> conditions,
        IReadOnlyList<WorkflowActionDefinition> actions)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
               {
                   Indented = false,
                   SkipValidation = false
               }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", schemaVersion);
            writer.WriteString("ruleId", ruleId);
            writer.WriteNumber("revision", revision);
            writer.WriteString("ownerConversationId", ownerConversationId);
            writer.WriteBoolean("isEnabled", isEnabled);
            writer.WriteNumber("activatedAtUtcTicks", activatedAtUtc.UtcTicks);
            writer.WritePropertyName("trigger");
            writer.WriteStartObject();
            writer.WriteNumber("kind", (int)trigger.Kind);
            writer.WriteString("sourceConversationId", trigger.SourceConversationId);
            writer.WriteString("sourcePresetMessageId", trigger.SourcePresetMessageId);
            if (trigger.ScheduledAtUtc is { } scheduledAtUtc)
            {
                writer.WriteNumber("scheduledAtUtcTicks", scheduledAtUtc.UtcTicks);
            }
            else
            {
                writer.WriteNull("scheduledAtUtcTicks");
            }

            writer.WriteEndObject();
            writer.WritePropertyName("destination");
            writer.WriteStartObject();
            writer.WriteNumber("kind", (int)destination.Kind);
            writer.WriteString("conversationId", destination.ConversationId);
            writer.WriteEndObject();
            writer.WritePropertyName("conditions");
            writer.WriteStartArray();
            foreach (var condition in conditions)
            {
                writer.WriteNumberValue((int)condition);
            }

            writer.WriteEndArray();
            writer.WritePropertyName("actions");
            writer.WriteStartArray();
            foreach (var action in actions)
            {
                writer.WriteStartObject();
                writer.WriteNumber("order", action.Order);
                writer.WriteNumber("kind", (int)action.Kind);
                writer.WriteString("presetOwnerConversationId", action.PresetOwnerConversationId);
                writer.WriteString("presetMessageId", action.PresetMessageId);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        return Convert.ToHexString(
            SHA256.HashData(stream.GetBuffer().AsSpan(0, checked((int)stream.Length))));
    }

    private static string NormalizeId(string? value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty canonical UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private static bool IsCanonicalSha256(string? value) =>
        value is { Length: SHA256.HashSizeInBytes * 2 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');
}
