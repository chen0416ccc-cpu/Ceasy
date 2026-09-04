using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class WorkflowLineageProjectionOfflineTests
{
    private static readonly DateTimeOffset Epoch =
        DateTimeOffset.Parse("2026-08-17T08:00:00Z");

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow lineage projects confirmed downstream expired causation",
            TestConfirmedDownstreamExpiredLineageAsync,
            assert);
        await RunCaseAsync(
            "workflow lineage projects every durable action state",
            TestActionStateMatrixAsync,
            assert);
        await RunCaseAsync(
            "workflow lineage exposes only opaque privacy bounded fields",
            TestPrivacyAndOpaqueProjectionAsync,
            assert);
        await RunCaseAsync(
            "workflow lineage distinguishes empty conservative and unavailable health",
            TestHealthAndFailClosedProjectionAsync,
            assert);
        await RunCaseAsync(
            "workflow lineage truncates only at a complete correlation boundary",
            TestCorrelationAwareTruncationAsync,
            assert);
    }

    private static Task TestConfirmedDownstreamExpiredLineageAsync()
    {
        var root = CreateRootTrigger(seed: 100, Epoch, "scheduled-root");
        var confirmed = CreateAction(
            root,
            seed: 101,
            WorkflowActionOperationState.Confirmed);
        var downstream = CreateDownstreamTrigger(
            confirmed,
            seed: 102,
            Epoch.AddHours(25));
        var expired = CreateAction(
            downstream,
            seed: 103,
            WorkflowActionOperationState.Blocked,
            "correlation-lifetime-exhausted");
        var projected = Project([root, downstream], [confirmed, expired]);

        Ensure(
            projected.Health == WorkflowLineageHealth.Healthy &&
            projected.UnavailableReason == WorkflowLineageUnavailableReason.None &&
            projected.TotalCorrelationCount == 1 &&
            projected.TotalTriggerCount == 2 &&
            projected.TotalActionCount == 2 &&
            projected.Items.Count == 2 &&
            !projected.IsTruncated,
            "the complete two-stage correlation was not projected");
        var first = projected.Items.Single(item => item.State == WorkflowActionOperationState.Confirmed);
        var second = projected.Items.Single(item => item.State == WorkflowActionOperationState.Blocked);
        Ensure(
            first.CorrelationRef == second.CorrelationRef &&
            second.ParentActionRef == first.ItemRef &&
            first.CorrelationDepth == 1 && second.CorrelationDepth == 2 &&
            second.TriggerKind == WorkflowTriggerKind.PresetDispatchConfirmed &&
            second.FailureReason == WorkflowLineageFailureReason.CorrelationLifetimeExhausted &&
            second.AttemptCount == 0 && second.LastRecordedAttemptAtUtc is null,
            "downstream causation, depth, or terminal lifetime state changed");
        Ensure(
            first.AttemptCount == 1 &&
            first.LastRecordedAttemptAtUtc == confirmed.DispatchAttemptTimesUtc![0] &&
            first.TargetConversationRef is not null &&
            first.PresetRef is not null,
            "confirmed action attempt, target, or preset evidence was omitted");
        Ensure(
            WorkflowJournalLineageReader.DefaultMaximumRows == 256 &&
            WorkflowJournalLineageReader.CreateOpaqueReference(
                "task",
                root.SourceConversationId) == first.SourceConversationRef,
            "the compact lineage bound or shared opaque reference contract changed");
        return Task.CompletedTask;
    }

    private static Task TestActionStateMatrixAsync()
    {
        var states = new[]
        {
            WorkflowActionOperationState.Prepared,
            WorkflowActionOperationState.Dispatching,
            WorkflowActionOperationState.Retryable,
            WorkflowActionOperationState.Uncertain,
            WorkflowActionOperationState.Confirmed,
            WorkflowActionOperationState.Exhausted,
            WorkflowActionOperationState.Canceled,
            WorkflowActionOperationState.Blocked
        };
        var triggers = new List<WorkflowTriggerEventRecord>();
        var actions = new List<WorkflowActionOperationRecord>();
        for (var index = 0; index < states.Length; index++)
        {
            var trigger = CreateRootTrigger(
                200 + index * 10,
                Epoch.AddMinutes(index),
                "state-" + index);
            triggers.Add(trigger);
            actions.Add(CreateAction(
                trigger,
                201 + index * 10,
                states[index],
                FailureFor(states[index])));
        }

        var projected = Project(triggers, actions);
        Ensure(
            projected.Health == WorkflowLineageHealth.Healthy &&
            projected.Items.Count == states.Length &&
            states.All(state => projected.Items.Count(item => item.State == state) == 1),
            "one or more durable journal states were lost or merged");
        Ensure(
            projected.Items.Single(item => item.State == WorkflowActionOperationState.Retryable)
                .FailureReason == WorkflowLineageFailureReason.DesktopUnavailable &&
            projected.Items.Single(item => item.State == WorkflowActionOperationState.Uncertain)
                .FailureReason == WorkflowLineageFailureReason.Uncertain &&
            projected.Items.Single(item => item.State == WorkflowActionOperationState.Exhausted)
                .FailureReason == WorkflowLineageFailureReason.RetryExhausted &&
            projected.Items.Single(item => item.State == WorkflowActionOperationState.Blocked)
                .FailureReason == WorkflowLineageFailureReason.PolicyBlocked,
            "controlled failure-class projection changed");
        return Task.CompletedTask;
    }

    private static Task TestPrivacyAndOpaqueProjectionAsync()
    {
        var trigger = CreateRootTrigger(seed: 400, Epoch, "private-occurrence");
        var action = CreateAction(
            trigger,
            seed: 401,
            WorkflowActionOperationState.Uncertain,
            "timeout-after-write");
        var item = Project([trigger], [action]).Items.Single();
        var rawValues = new[]
        {
            trigger.TriggerEventId,
            trigger.CorrelationId,
            trigger.SourceConversationId,
            action.ActionOperationId,
            action.RuleId,
            action.TargetConversationId!,
            action.PresetMessageId!
        };
        var projectedText = item.ToString();

        Ensure(
            rawValues.All(value => !projectedText.Contains(value, StringComparison.OrdinalIgnoreCase)) &&
            item.ItemRef.StartsWith("action-", StringComparison.Ordinal) &&
            item.CorrelationRef.StartsWith("flow-", StringComparison.Ordinal) &&
            item.SourceConversationRef.StartsWith("task-", StringComparison.Ordinal) &&
            item.RuleRef!.StartsWith("rule-", StringComparison.Ordinal) &&
            item.TargetConversationRef!.StartsWith("task-", StringComparison.Ordinal) &&
            item.PresetRef!.StartsWith("preset-", StringComparison.Ordinal) &&
            item.FailureReason == WorkflowLineageFailureReason.Other &&
            !projectedText.Contains("timeout-after-write", StringComparison.Ordinal),
            "a raw identifier or failure token crossed the projection boundary");

        var propertyNames = typeof(WorkflowLineageItem)
            .GetProperties()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var forbidden = new[]
        {
            "Message",
            "Content",
            "Path",
            "Title",
            "Cwd",
            "Occurrence",
            "SourceTurnOrOperationId",
            "GeneratedTurnId",
            "ClientMessageId",
            "DefinitionDigest",
            "ExecutionFingerprint"
        };
        Ensure(
            forbidden.All(name => !propertyNames.Contains(name)),
            "a content, path, title, cwd, or internal receipt field entered the DTO");
        return Task.CompletedTask;
    }

    private static async Task TestHealthAndFailClosedProjectionAsync()
    {
        var empty = WorkflowJournalLineageReader.Project(new WorkflowJournalSnapshot(
            WorkflowJournalReadStatus.Missing,
            Generation: 0,
            RequiresConservativeRecovery: false,
            Array.Empty<WorkflowTriggerEventRecord>(),
            Array.Empty<WorkflowActionOperationRecord>()));
        Ensure(
            empty.Health == WorkflowLineageHealth.Empty && empty.Items.Count == 0,
            "an uninitialized empty journal was not treated as empty");

        var trigger = CreateRootTrigger(seed: 500, Epoch, "recovered");
        var action = CreateAction(trigger, seed: 501, WorkflowActionOperationState.Prepared);
        var conservative = WorkflowJournalLineageReader.Project(new WorkflowJournalSnapshot(
            WorkflowJournalReadStatus.RecoveredFromBackup,
            Generation: 3,
            RequiresConservativeRecovery: true,
            [trigger],
            [action]));
        Ensure(
            conservative.Health == WorkflowLineageHealth.Conservative &&
            conservative.Items.Count == 1,
            "backup recovery was projected as healthy or discarded");

        var corrupted = WorkflowJournalLineageReader.Project(new WorkflowJournalSnapshot(
            WorkflowJournalReadStatus.Corrupted,
            Generation: 4,
            RequiresConservativeRecovery: true,
            [trigger],
            [action]));
        var unsupported = WorkflowJournalLineageReader.Project(new WorkflowJournalSnapshot(
            WorkflowJournalReadStatus.UnsupportedSchema,
            Generation: 4,
            RequiresConservativeRecovery: true,
            [trigger],
            [action]));
        EnsureUnavailable(
            corrupted,
            WorkflowLineageUnavailableReason.CorruptedJournal,
            "corrupt journal");
        EnsureUnavailable(
            unsupported,
            WorkflowLineageUnavailableReason.UnsupportedSchema,
            "unsupported journal");

        var dangling = WorkflowJournalLineageReader.Project(new WorkflowJournalSnapshot(
            WorkflowJournalReadStatus.Healthy,
            Generation: 1,
            RequiresConservativeRecovery: false,
            Array.Empty<WorkflowTriggerEventRecord>(),
            [action]));
        EnsureUnavailable(
            dangling,
            WorkflowLineageUnavailableReason.InvalidSnapshot,
            "dangling action");

        var throwingReader = new WorkflowJournalLineageReader(
            _ => Task.FromException<WorkflowJournalSnapshot>(new IOException("private-path")));
        var failed = await throwingReader.ReadAsync(CancellationToken.None);
        EnsureUnavailable(
            failed,
            WorkflowLineageUnavailableReason.ReadFailed,
            "reader exception");
        Ensure(
            !failed.ToString().Contains("private-path", StringComparison.Ordinal),
            "reader exception detail escaped the fail-closed result");
    }

    private static Task TestCorrelationAwareTruncationAsync()
    {
        const int newerSingleCorrelations = 768;
        var triggers = new List<WorkflowTriggerEventRecord>();
        var actions = new List<WorkflowActionOperationRecord>();
        var olderRoot = CreateRootTrigger(seed: 1000, Epoch, "older-root");
        var olderConfirmed = CreateAction(
            olderRoot,
            seed: 1001,
            WorkflowActionOperationState.Confirmed);
        var olderDownstream = CreateDownstreamTrigger(
            olderConfirmed,
            seed: 1002,
            Epoch.AddHours(1));
        var olderBlocked = CreateAction(
            olderDownstream,
            seed: 1003,
            WorkflowActionOperationState.Blocked,
            "policy-changed");
        triggers.AddRange([olderRoot, olderDownstream]);
        actions.AddRange([olderConfirmed, olderBlocked]);

        for (var index = 0; index < newerSingleCorrelations; index++)
        {
            var trigger = CreateRootTrigger(
                2000 + index * 4,
                Epoch.AddDays(2).AddMinutes(index),
                "newer-" + index);
            triggers.Add(trigger);
            actions.Add(CreateAction(
                trigger,
                2001 + index * 4,
                WorkflowActionOperationState.Prepared));
        }

        var olderOnly = Project(
            [olderRoot, olderDownstream],
            [olderConfirmed, olderBlocked]);
        var olderCorrelationRef = olderOnly.Items[0].CorrelationRef;
        var projected = WorkflowJournalLineageReader.Project(
            HealthySnapshot(triggers, actions),
            maximumRows: 769);
        Ensure(
            projected.Health == WorkflowLineageHealth.Healthy &&
            projected.IsTruncated &&
            projected.TotalCorrelationCount == newerSingleCorrelations + 1 &&
            projected.TotalActionCount == newerSingleCorrelations + 2 &&
            projected.Items.Count == newerSingleCorrelations &&
            projected.Items.All(item => item.CorrelationRef != olderCorrelationRef),
            "the row bound split a correlation or packed older rows after the first omitted group");
        return Task.CompletedTask;
    }

    private static WorkflowLineageSnapshot Project(
        IReadOnlyList<WorkflowTriggerEventRecord> triggers,
        IReadOnlyList<WorkflowActionOperationRecord> actions) =>
        WorkflowJournalLineageReader.Project(HealthySnapshot(triggers, actions));

    private static WorkflowJournalSnapshot HealthySnapshot(
        IReadOnlyList<WorkflowTriggerEventRecord> triggers,
        IReadOnlyList<WorkflowActionOperationRecord> actions) =>
        new(
            WorkflowJournalReadStatus.Healthy,
            Generation: 7,
            RequiresConservativeRecovery: false,
            triggers,
            actions);

    private static WorkflowTriggerEventRecord CreateRootTrigger(
        int seed,
        DateTimeOffset observedAtUtc,
        string occurrence)
    {
        var sourceConversationId = Id(seed);
        var sourceId = Id(seed + 1_000_000);
        var sourceTurnId = Id(seed + 2_000_000);
        var triggerEventId = WorkflowOperationJournal.CreateTriggerEventId(
            WorkflowTriggerKind.ScheduledAt,
            sourceConversationId,
            sourceId,
            sourceTurnId,
            occurrence);
        return new WorkflowTriggerEventRecord(
            triggerEventId,
            WorkflowTriggerKind.ScheduledAt,
            sourceConversationId,
            sourceId,
            sourceTurnId,
            occurrence,
            triggerEventId,
            CausationId: null,
            CorrelationDepth: 0,
            observedAtUtc);
    }

    private static WorkflowTriggerEventRecord CreateDownstreamTrigger(
        WorkflowActionOperationRecord parent,
        int seed,
        DateTimeOffset observedAtUtc)
    {
        var occurrence = "confirmed-" + seed;
        var triggerEventId = WorkflowOperationJournal.CreateTriggerEventId(
            WorkflowTriggerKind.PresetDispatchConfirmed,
            parent.PresetOwnerConversationId!,
            parent.PresetMessageId!,
            parent.ActionOperationId,
            occurrence);
        return new WorkflowTriggerEventRecord(
            triggerEventId,
            WorkflowTriggerKind.PresetDispatchConfirmed,
            parent.PresetOwnerConversationId!,
            parent.PresetMessageId!,
            parent.ActionOperationId,
            occurrence,
            parent.CorrelationId,
            parent.ActionOperationId,
            parent.CorrelationDepth,
            observedAtUtc);
    }

    private static WorkflowActionOperationRecord CreateAction(
        WorkflowTriggerEventRecord trigger,
        int seed,
        WorkflowActionOperationState state,
        string? failureClass = null)
    {
        var ruleId = Id(seed + 3_000_000);
        var actionOperationId = WorkflowOperationJournal.CreateActionOperationId(
            ruleId,
            ruleRevision: 1,
            trigger.TriggerEventId,
            actionIndex: 0);
        var targetId = Id(seed + 4_000_000);
        var presetOwnerId = Id(seed + 5_000_000);
        var presetId = Id(seed + 6_000_000);
        var attemptCount = state is WorkflowActionOperationState.Dispatching or
            WorkflowActionOperationState.Retryable or
            WorkflowActionOperationState.Uncertain or
            WorkflowActionOperationState.Confirmed
            ? 1
            : 0;
        var createdAtUtc = trigger.ObservedAtUtc.AddSeconds(1);
        var updatedAtUtc = attemptCount == 0 ? createdAtUtc : createdAtUtc.AddSeconds(1);
        var confirmed = state == WorkflowActionOperationState.Confirmed;
        return new WorkflowActionOperationRecord(
            actionOperationId,
            ruleId,
            RuleRevision: 1,
            DefinitionDigest: new string('A', 64),
            trigger.TriggerEventId,
            trigger.CorrelationId,
            trigger.TriggerEventId,
            ActionIndex: 0,
            CorrelationDepth: trigger.CorrelationDepth + 1,
            WorkflowActionKind.SendPresetMessage,
            WorkflowDestinationKind.ExistingConversation,
            targetId,
            presetOwnerId,
            presetId,
            WorkflowOperationJournal.CreateClientMessageId(actionOperationId),
            state,
            attemptCount,
            failureClass,
            ConfirmedTargetConversationId: confirmed ? targetId : null,
            GeneratedTurnId: confirmed ? Id(seed + 7_000_000) : null,
            ProtectionSettingsGeneration: null,
            createdAtUtc,
            updatedAtUtc)
        {
            DispatchAttemptTimesUtc = attemptCount == 0
                ? null
                : Array.AsReadOnly([createdAtUtc])
        };
    }

    private static string? FailureFor(WorkflowActionOperationState state) => state switch
    {
        WorkflowActionOperationState.Retryable => "owner-unavailable",
        WorkflowActionOperationState.Uncertain => "desktop-uncertain",
        WorkflowActionOperationState.Exhausted => "retry-exhausted",
        WorkflowActionOperationState.Canceled => "policy-changed",
        WorkflowActionOperationState.Blocked => "policy-changed",
        _ => null
    };

    private static void EnsureUnavailable(
        WorkflowLineageSnapshot snapshot,
        WorkflowLineageUnavailableReason reason,
        string context) =>
        Ensure(
            snapshot.Health == WorkflowLineageHealth.Unavailable &&
            snapshot.UnavailableReason == reason &&
            snapshot.Generation == 0 &&
            snapshot.TotalCorrelationCount == 0 &&
            snapshot.TotalTriggerCount == 0 &&
            snapshot.TotalActionCount == 0 &&
            !snapshot.IsTruncated && snapshot.Items.Count == 0,
            context + " exposed partial or stale lineage");

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.Message);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static string Id(int value) =>
        $"00000000-0000-4000-8000-{value:000000000000}";
}
