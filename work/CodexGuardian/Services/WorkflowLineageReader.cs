using CodexGuardian.Models;
using System.Security.Cryptography;
using System.Text;

namespace CodexGuardian.Services;

internal interface IWorkflowLineageReader
{
    Task<WorkflowLineageSnapshot> ReadAsync(CancellationToken cancellationToken = default);
}

internal enum WorkflowLineageHealth
{
    Empty,
    Healthy,
    Conservative,
    Unavailable
}

internal enum WorkflowLineageUnavailableReason
{
    None,
    CorruptedJournal,
    UnsupportedSchema,
    InvalidSnapshot,
    ReadFailed
}

internal enum WorkflowLineageItemKind
{
    TriggerOnly,
    Action
}

internal enum WorkflowLineageFailureReason
{
    None,
    SourceInvalid,
    TargetUnavailable,
    PresetUnavailable,
    PolicyBlocked,
    UserActive,
    DesktopUnavailable,
    DesktopIncompatible,
    PersistenceFailed,
    ReceiptUnavailable,
    StateChanged,
    SettingsUnavailable,
    Uncertain,
    RetryExhausted,
    NewConversationUnavailable,
    NoProgress,
    CorrelationLifetimeExhausted,
    CorrelationClockInvalid,
    DispatchBudgetExhausted,
    CorrelationAuthorityUnavailable,
    Other
}

internal sealed record WorkflowLineageItem(
    WorkflowLineageItemKind Kind,
    string ItemRef,
    string CorrelationRef,
    string? ParentActionRef,
    int CorrelationDepth,
    WorkflowTriggerKind TriggerKind,
    string SourceConversationRef,
    DateTimeOffset ObservedAtUtc,
    string? RuleRef,
    int? RuleRevision,
    int? ActionIndex,
    WorkflowActionKind? ActionKind,
    WorkflowDestinationKind? DestinationKind,
    string? TargetConversationRef,
    string? PresetRef,
    WorkflowActionOperationState? State,
    WorkflowLineageFailureReason FailureReason,
    int AttemptCount,
    DateTimeOffset? CreatedAtUtc,
    DateTimeOffset? UpdatedAtUtc,
    DateTimeOffset? LastRecordedAttemptAtUtc);

internal sealed record WorkflowLineageSnapshot(
    WorkflowLineageHealth Health,
    WorkflowLineageUnavailableReason UnavailableReason,
    long Generation,
    int TotalCorrelationCount,
    int TotalTriggerCount,
    int TotalActionCount,
    bool IsTruncated,
    IReadOnlyList<WorkflowLineageItem> Items);

internal sealed class WorkflowJournalLineageReader : IWorkflowLineageReader
{
    internal const int DefaultMaximumRows = 256;

    private readonly Func<CancellationToken, Task<WorkflowJournalSnapshot>> _readSnapshotAsync;
    private readonly int _maximumRows;

    internal WorkflowJournalLineageReader(
        WorkflowOperationJournal journal,
        int maximumRows = DefaultMaximumRows)
        : this(
            (journal ?? throw new ArgumentNullException(nameof(journal))).ReadAsync,
            maximumRows)
    {
    }

    internal WorkflowJournalLineageReader(
        Func<CancellationToken, Task<WorkflowJournalSnapshot>> readSnapshotAsync,
        int maximumRows = DefaultMaximumRows)
    {
        _readSnapshotAsync = readSnapshotAsync ??
            throw new ArgumentNullException(nameof(readSnapshotAsync));
        if (maximumRows < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumRows),
                "The lineage row bound must be positive.");
        }

        _maximumRows = maximumRows;
    }

    public async Task<WorkflowLineageSnapshot> ReadAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            var snapshot = await _readSnapshotAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return Project(snapshot, _maximumRows);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Unavailable(WorkflowLineageUnavailableReason.ReadFailed);
        }
    }

    internal static WorkflowLineageSnapshot Project(
        WorkflowJournalSnapshot? snapshot,
        int maximumRows = DefaultMaximumRows)
    {
        if (maximumRows < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRows));
        }

        if (snapshot is null)
        {
            return Unavailable(WorkflowLineageUnavailableReason.InvalidSnapshot);
        }

        if (snapshot.ReadStatus == WorkflowJournalReadStatus.Corrupted)
        {
            return Unavailable(WorkflowLineageUnavailableReason.CorruptedJournal);
        }

        if (snapshot.ReadStatus == WorkflowJournalReadStatus.UnsupportedSchema)
        {
            return Unavailable(WorkflowLineageUnavailableReason.UnsupportedSchema);
        }

        try
        {
            if (!TryValidate(snapshot, out var triggerEvents, out var actions))
            {
                return Unavailable(WorkflowLineageUnavailableReason.InvalidSnapshot);
            }

            if (snapshot.ReadStatus == WorkflowJournalReadStatus.Missing)
            {
                return triggerEvents.Count == 0 && actions.Count == 0 &&
                       snapshot.Generation == 0 && !snapshot.RequiresConservativeRecovery
                    ? Empty()
                    : Unavailable(WorkflowLineageUnavailableReason.InvalidSnapshot);
            }

            var groups = BuildGroups(triggerEvents, actions);
            var selected = new List<WorkflowLineageItem>();
            var truncated = false;
            foreach (var group in groups)
            {
                if (selected.Count + group.Items.Count > maximumRows)
                {
                    truncated = true;
                    break;
                }

                selected.AddRange(group.Items);
            }

            var health = snapshot.RequiresConservativeRecovery ||
                         snapshot.ReadStatus == WorkflowJournalReadStatus.RecoveredFromBackup
                ? WorkflowLineageHealth.Conservative
                : groups.Count == 0
                    ? WorkflowLineageHealth.Empty
                    : WorkflowLineageHealth.Healthy;
            return new WorkflowLineageSnapshot(
                health,
                WorkflowLineageUnavailableReason.None,
                snapshot.Generation,
                groups.Count,
                triggerEvents.Count,
                actions.Count,
                truncated,
                Array.AsReadOnly(selected.ToArray()));
        }
        catch
        {
            return Unavailable(WorkflowLineageUnavailableReason.InvalidSnapshot);
        }
    }

    private static bool TryValidate(
        WorkflowJournalSnapshot snapshot,
        out IReadOnlyList<WorkflowTriggerEventRecord> triggerEvents,
        out IReadOnlyList<WorkflowActionOperationRecord> actions)
    {
        triggerEvents = snapshot.TriggerEvents ?? Array.Empty<WorkflowTriggerEventRecord>();
        actions = snapshot.Actions ?? Array.Empty<WorkflowActionOperationRecord>();
        if (!Enum.IsDefined(snapshot.ReadStatus) ||
            snapshot.Generation < 0 ||
            snapshot.ReadStatus != WorkflowJournalReadStatus.Missing && snapshot.Generation == 0 ||
            triggerEvents.Count > WorkflowOperationJournal.DefaultMaximumTriggerEvents ||
            actions.Count > WorkflowOperationJournal.DefaultMaximumActions)
        {
            return false;
        }

        var eventsById = new Dictionary<string, WorkflowTriggerEventRecord>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var triggerEvent in triggerEvents)
        {
            if (!IsValidTrigger(triggerEvent) ||
                !eventsById.TryAdd(triggerEvent.TriggerEventId, triggerEvent))
            {
                return false;
            }
        }

        var actionsById = new Dictionary<string, WorkflowActionOperationRecord>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var action in actions)
        {
            if (!IsValidAction(action) ||
                !actionsById.TryAdd(action.ActionOperationId, action))
            {
                return false;
            }
        }

        foreach (var triggerEvent in triggerEvents)
        {
            if (triggerEvent.CausationId is null)
            {
                if (triggerEvent.CorrelationDepth != 0 ||
                    !EqualId(triggerEvent.CorrelationId, triggerEvent.TriggerEventId))
                {
                    return false;
                }
            }
            else if (!actionsById.TryGetValue(triggerEvent.CausationId, out var parent) ||
                     parent.State != WorkflowActionOperationState.Confirmed ||
                     !EqualId(parent.CorrelationId, triggerEvent.CorrelationId) ||
                     triggerEvent.CorrelationDepth != parent.CorrelationDepth)
            {
                return false;
            }
        }

        foreach (var action in actions)
        {
            if (!eventsById.TryGetValue(action.TriggerEventId, out var triggerEvent) ||
                !EqualId(action.CorrelationId, triggerEvent.CorrelationId) ||
                !EqualId(action.CausationId, triggerEvent.TriggerEventId) ||
                action.CorrelationDepth != triggerEvent.CorrelationDepth + 1 ||
                action.CreatedAtUtc < triggerEvent.ObservedAtUtc)
            {
                return false;
            }
        }

        foreach (var correlation in triggerEvents.GroupBy(
                     static value => value.CorrelationId,
                     StringComparer.OrdinalIgnoreCase))
        {
            if (!eventsById.TryGetValue(correlation.Key, out var root) ||
                correlation.Any(value => value.ObservedAtUtc < root.ObservedAtUtc))
            {
                return false;
            }

            var correlationActions = actions.Where(value =>
                    EqualId(value.CorrelationId, correlation.Key))
                .ToArray();
            if (correlationActions.Length > WorkflowOperationJournal.MaximumActionsPerCorrelation ||
                correlationActions.GroupBy(
                        static value => value.RuleId,
                        StringComparer.OrdinalIgnoreCase)
                    .Any(group => group.Count() >
                        WorkflowOperationJournal.MaximumActionsPerRulePerCorrelation) ||
                correlationActions.Sum(value => value.DispatchAttemptTimesUtc?.Count ?? 0) >
                    WorkflowOperationJournal.MaximumRecordedDispatchAttemptsPerCorrelation)
            {
                return false;
            }

        }

        return actions.All(action => eventsById.ContainsKey(action.CorrelationId));
    }

    private static bool IsValidTrigger(WorkflowTriggerEventRecord? triggerEvent)
    {
        if (triggerEvent is null ||
            !Enum.IsDefined(triggerEvent.TriggerKind) ||
            !IsCanonicalId(triggerEvent.TriggerEventId) ||
            !IsCanonicalId(triggerEvent.SourceConversationId) ||
            !IsCanonicalId(triggerEvent.SourceId) ||
            !IsCanonicalId(triggerEvent.SourceTurnOrOperationId) ||
            !IsCanonicalId(triggerEvent.CorrelationId) ||
            triggerEvent.CausationId is not null && !IsCanonicalId(triggerEvent.CausationId) ||
            triggerEvent.CorrelationDepth is < 0 or > WorkflowOperationJournal.MaximumCorrelationDepth ||
            !IsUtc(triggerEvent.ObservedAtUtc) ||
            !IsBoundedToken(triggerEvent.Occurrence, 128))
        {
            return false;
        }

        return EqualId(
            triggerEvent.TriggerEventId,
            WorkflowOperationJournal.CreateTriggerEventId(
                triggerEvent.TriggerKind,
                triggerEvent.SourceConversationId,
                triggerEvent.SourceId,
                triggerEvent.SourceTurnOrOperationId,
                triggerEvent.Occurrence));
    }

    private static bool IsValidAction(WorkflowActionOperationRecord? action)
    {
        if (action is null ||
            !IsCanonicalId(action.ActionOperationId) ||
            !IsCanonicalId(action.RuleId) ||
            action.RuleRevision <= 0 ||
            !IsSha256(action.DefinitionDigest) ||
            !IsCanonicalId(action.TriggerEventId) ||
            !IsCanonicalId(action.CorrelationId) ||
            !IsCanonicalId(action.CausationId) ||
            action.ActionIndex is < 0 or >= WorkflowRuleDefinition.MaximumActions ||
            action.CorrelationDepth is < 1 or > WorkflowOperationJournal.MaximumCorrelationDepth ||
            !Enum.IsDefined(action.ActionKind) ||
            !Enum.IsDefined(action.DestinationKind) ||
            !Enum.IsDefined(action.State) ||
            action.AttemptCount < 0 ||
            action.TargetConversationId is not null && !IsCanonicalId(action.TargetConversationId) ||
            action.PresetOwnerConversationId is not null &&
            !IsCanonicalId(action.PresetOwnerConversationId) ||
            action.PresetMessageId is not null && !IsCanonicalId(action.PresetMessageId) ||
            action.ClientMessageId is not null && !IsCanonicalId(action.ClientMessageId) ||
            action.ConfirmedTargetConversationId is not null &&
            !IsCanonicalId(action.ConfirmedTargetConversationId) ||
            action.GeneratedTurnId is not null && !IsCanonicalId(action.GeneratedTurnId) ||
            action.ProtectionSettingsGeneration is <= 0 ||
            (action.ExecutionFingerprint is null) !=
            (action.AuthoritativeTargetGeneration is null) ||
            action.ExecutionFingerprint is not null && !IsSha256(action.ExecutionFingerprint) ||
            action.AuthoritativeTargetGeneration is < 0 ||
            !IsUtc(action.CreatedAtUtc) || !IsUtc(action.UpdatedAtUtc) ||
            action.UpdatedAtUtc < action.CreatedAtUtc ||
            action.FailureClass is not null && !IsFailureClass(action.FailureClass) ||
            !EqualId(
                action.ActionOperationId,
                WorkflowOperationJournal.CreateActionOperationId(
                    action.RuleId,
                    action.RuleRevision,
                    action.TriggerEventId,
                    action.ActionIndex)))
        {
            return false;
        }

        var attempts = action.DispatchAttemptTimesUtc ?? Array.Empty<DateTimeOffset>();
        if (attempts.Count != action.AttemptCount ||
            attempts.Any(value => !IsUtc(value) || value < action.CreatedAtUtc ||
                                  value > action.UpdatedAtUtc) ||
            attempts.Zip(attempts.Skip(1), static (left, right) => left <= right).Any(valid => !valid))
        {
            return false;
        }

        var actionShapeValid = action.ActionKind switch
        {
            WorkflowActionKind.SendPresetMessage =>
                IsCanonicalId(action.PresetOwnerConversationId) &&
                IsCanonicalId(action.PresetMessageId) &&
                IsCanonicalId(action.ClientMessageId) &&
                EqualId(
                    action.ClientMessageId,
                    WorkflowOperationJournal.CreateClientMessageId(action.ActionOperationId)),
            WorkflowActionKind.EnableConversationProtection =>
                action.PresetOwnerConversationId is null && action.PresetMessageId is null &&
                action.ClientMessageId is null,
            _ => false
        };
        if (!actionShapeValid ||
            action.DestinationKind is WorkflowDestinationKind.CurrentConversation or
                WorkflowDestinationKind.ExistingConversation && action.TargetConversationId is null ||
            action.ActionKind == WorkflowActionKind.EnableConversationProtection &&
            action.TargetConversationId is null)
        {
            return false;
        }

        var hasReceipt = action.ConfirmedTargetConversationId is not null ||
                         action.GeneratedTurnId is not null ||
                         action.ProtectionSettingsGeneration is not null;
        if (action.State == WorkflowActionOperationState.Confirmed)
        {
            if (!hasReceipt || action.ConfirmedTargetConversationId is null ||
                action.TargetConversationId is not null &&
                !EqualId(action.TargetConversationId, action.ConfirmedTargetConversationId) ||
                action.ActionKind == WorkflowActionKind.SendPresetMessage &&
                (action.GeneratedTurnId is null || action.ProtectionSettingsGeneration is not null) ||
                action.ActionKind == WorkflowActionKind.EnableConversationProtection &&
                (action.GeneratedTurnId is not null || action.ProtectionSettingsGeneration is null))
            {
                return false;
            }
        }
        else if (hasReceipt)
        {
            return false;
        }

        return action.State switch
        {
            WorkflowActionOperationState.Prepared =>
                action.AttemptCount == 0 && action.FailureClass is null,
            WorkflowActionOperationState.Dispatching =>
                action.AttemptCount > 0 && action.FailureClass is null,
            WorkflowActionOperationState.Retryable or WorkflowActionOperationState.Uncertain =>
                action.AttemptCount > 0 && action.FailureClass is not null,
            WorkflowActionOperationState.Confirmed =>
                action.AttemptCount > 0,
            WorkflowActionOperationState.Exhausted or WorkflowActionOperationState.Canceled or
                WorkflowActionOperationState.Blocked => action.FailureClass is not null,
            _ => false
        };
    }

    private static IReadOnlyList<CorrelationProjection> BuildGroups(
        IReadOnlyList<WorkflowTriggerEventRecord> triggerEvents,
        IReadOnlyList<WorkflowActionOperationRecord> actions)
    {
        var actionsByTrigger = actions.ToLookup(
            static value => value.TriggerEventId,
            StringComparer.OrdinalIgnoreCase);
        var groups = new List<CorrelationProjection>();
        foreach (var correlation in triggerEvents.GroupBy(
                     static value => value.CorrelationId,
                     StringComparer.OrdinalIgnoreCase))
        {
            var items = new List<WorkflowLineageItem>();
            foreach (var triggerEvent in correlation)
            {
                var triggerActions = actionsByTrigger[triggerEvent.TriggerEventId].ToArray();
                if (triggerActions.Length == 0)
                {
                    items.Add(ProjectTrigger(triggerEvent));
                    continue;
                }

                items.AddRange(triggerActions.Select(action => ProjectAction(triggerEvent, action)));
            }

            var ordered = items
                .OrderBy(static value => value.ObservedAtUtc)
                .ThenBy(static value => value.CorrelationDepth)
                .ThenBy(static value => value.ActionIndex ?? -1)
                .ThenBy(static value => value.CreatedAtUtc)
                .ThenBy(static value => value.ItemRef, StringComparer.Ordinal)
                .ToArray();
            var latestAt = ordered.Max(static value =>
                value.UpdatedAtUtc ?? value.ObservedAtUtc);
            groups.Add(new CorrelationProjection(latestAt, Array.AsReadOnly(ordered)));
        }

        return groups
            .OrderByDescending(static value => value.LatestAtUtc)
            .ThenBy(static value => value.Items[0].CorrelationRef, StringComparer.Ordinal)
            .ToArray();
    }

    private static WorkflowLineageItem ProjectTrigger(WorkflowTriggerEventRecord triggerEvent) =>
        new(
            WorkflowLineageItemKind.TriggerOnly,
            Opaque("event", triggerEvent.TriggerEventId),
            Opaque("flow", triggerEvent.CorrelationId),
            OpaqueOrNull("action", triggerEvent.CausationId),
            triggerEvent.CorrelationDepth,
            triggerEvent.TriggerKind,
            Opaque("task", triggerEvent.SourceConversationId),
            triggerEvent.ObservedAtUtc,
            RuleRef: null,
            RuleRevision: null,
            ActionIndex: null,
            ActionKind: null,
            DestinationKind: null,
            TargetConversationRef: null,
            PresetRef: null,
            State: null,
            WorkflowLineageFailureReason.None,
            AttemptCount: 0,
            CreatedAtUtc: null,
            UpdatedAtUtc: null,
            LastRecordedAttemptAtUtc: null);

    private static WorkflowLineageItem ProjectAction(
        WorkflowTriggerEventRecord triggerEvent,
        WorkflowActionOperationRecord action) =>
        new(
            WorkflowLineageItemKind.Action,
            Opaque("action", action.ActionOperationId),
            Opaque("flow", action.CorrelationId),
            OpaqueOrNull("action", triggerEvent.CausationId),
            action.CorrelationDepth,
            triggerEvent.TriggerKind,
            Opaque("task", triggerEvent.SourceConversationId),
            triggerEvent.ObservedAtUtc,
            Opaque("rule", action.RuleId),
            action.RuleRevision,
            action.ActionIndex,
            action.ActionKind,
            action.DestinationKind,
            OpaqueOrNull(
                "task",
                action.ConfirmedTargetConversationId ?? action.TargetConversationId),
            OpaqueOrNull("preset", action.PresetMessageId),
            action.State,
            MapFailure(action.FailureClass),
            action.AttemptCount,
            action.CreatedAtUtc,
            action.UpdatedAtUtc,
            action.DispatchAttemptTimesUtc?.LastOrDefault());

    private static WorkflowLineageFailureReason MapFailure(string? failureClass) =>
        failureClass switch
        {
            null => WorkflowLineageFailureReason.None,
            "source-event-invalid" => WorkflowLineageFailureReason.SourceInvalid,
            "target-unavailable" or "target-not-complete" or "new-target-action-invalid" =>
                WorkflowLineageFailureReason.TargetUnavailable,
            "preset-disabled" => WorkflowLineageFailureReason.PresetUnavailable,
            "checkpoint-mismatch" or "policy-changed" or "workflow-blocked" =>
                WorkflowLineageFailureReason.PolicyBlocked,
            "user-active" => WorkflowLineageFailureReason.UserActive,
            "desktop-unavailable" or "owner-unavailable" =>
                WorkflowLineageFailureReason.DesktopUnavailable,
            "desktop-incompatible" => WorkflowLineageFailureReason.DesktopIncompatible,
            "persistence-failed" or "receipt-persistence-failed" =>
                WorkflowLineageFailureReason.PersistenceFailed,
            "missing-turn-receipt" => WorkflowLineageFailureReason.ReceiptUnavailable,
            "state-changed" or "action-state-changed" => WorkflowLineageFailureReason.StateChanged,
            "settings-unavailable" or "settings-generation-changed" =>
                WorkflowLineageFailureReason.SettingsUnavailable,
            "desktop-uncertain" or "restart-uncertain" => WorkflowLineageFailureReason.Uncertain,
            "retry-exhausted" => WorkflowLineageFailureReason.RetryExhausted,
            "new-conversation-unavailable" =>
                WorkflowLineageFailureReason.NewConversationUnavailable,
            "no-progress" => WorkflowLineageFailureReason.NoProgress,
            "correlation-lifetime-exhausted" =>
                WorkflowLineageFailureReason.CorrelationLifetimeExhausted,
            "correlation-clock-invalid" => WorkflowLineageFailureReason.CorrelationClockInvalid,
            "dispatch-budget-exhausted" => WorkflowLineageFailureReason.DispatchBudgetExhausted,
            "correlation-authority-unavailable" =>
                WorkflowLineageFailureReason.CorrelationAuthorityUnavailable,
            _ => WorkflowLineageFailureReason.Other
        };

    private static WorkflowLineageSnapshot Empty() => new(
        WorkflowLineageHealth.Empty,
        WorkflowLineageUnavailableReason.None,
        Generation: 0,
        TotalCorrelationCount: 0,
        TotalTriggerCount: 0,
        TotalActionCount: 0,
        IsTruncated: false,
        Array.Empty<WorkflowLineageItem>());

    private static WorkflowLineageSnapshot Unavailable(
        WorkflowLineageUnavailableReason reason) => new(
        WorkflowLineageHealth.Unavailable,
        reason,
        Generation: 0,
        TotalCorrelationCount: 0,
        TotalTriggerCount: 0,
        TotalActionCount: 0,
        IsTruncated: false,
        Array.Empty<WorkflowLineageItem>());

    internal static string CreateOpaqueReference(string prefix, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return prefix + "-" + Convert.ToHexString(digest.AsSpan(0, 6));
    }

    private static string Opaque(string prefix, string value) =>
        CreateOpaqueReference(prefix, value);

    private static string? OpaqueOrNull(string prefix, string? value) =>
        value is null ? null : Opaque(prefix, value);

    private static bool IsCanonicalId(string? value) =>
        Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty &&
        string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool EqualId(string? left, string? right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool IsUtc(DateTimeOffset value) =>
        value != default && value.Offset == TimeSpan.Zero;

    private static bool IsSha256(string? value) =>
        value is { Length: SHA256.HashSizeInBytes * 2 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool IsBoundedToken(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or ':' or '.');

    private static bool IsFailureClass(string? value) =>
        value is { Length: > 0 and <= 64 } && value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private sealed record CorrelationProjection(
        DateTimeOffset LatestAtUtc,
        IReadOnlyList<WorkflowLineageItem> Items);
}
