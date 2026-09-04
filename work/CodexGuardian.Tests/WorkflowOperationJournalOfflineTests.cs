using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class WorkflowOperationJournalOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow ledger derives stable trigger action correlation causation and client identities",
            TestStableIdentityAndIdempotencyAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger permits retry only after proven-unsent dispatch failure",
            TestTransitionSafetyAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger binds execution identity and blocks no-progress correlation revisits",
            TestExecutionBindingAndNoProgressAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger records typed protection receipts without Desktop turn identity",
            TestProtectionReceiptAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger promotes healthy restart dispatching state to uncertain",
            TestHealthyRestartPromotionAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger backup recovery promotes pending work and blocks new operations",
            TestBackupRecoveryAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger preserves downstream correlation and requires confirmed causation",
            TestDownstreamLineageAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger bounds durable correlation elapsed lifetime",
            TestCorrelationLifetimeBoundAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger blocks dispatch after the per-hour correlation budget",
            TestHourlyDispatchBudgetAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger blocks prepared and bound actions after a clock rollback",
            TestClockRollbackBoundAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger fails closed on corrupt and unsupported durable documents",
            TestCorruptAndUnsupportedAsync,
            assert);
        await RunCaseAsync(
            "workflow ledger enforces bounded action capacity without pruning active identity",
            TestCapacityBoundAsync,
            assert);
    }

    private static async Task TestStableIdentityAndIdempotencyAsync()
    {
        var root = CreateRoot();
        var journal = CreateJournal(root);
        var rule = ScheduledSendRule(seed: 100);
        var firstEvent = await CreateScheduledEventAsync(journal, rule, "occurrence-100");
        var repeatedEvent = await journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            rule.OwnerConversationId,
            rule.RuleId,
            rule.RuleId,
            "occurrence-100",
            Activation.AddHours(3),
            cancellationToken: CancellationToken.None);
        Ensure(firstEvent.Created && !repeatedEvent.Created, "trigger event idempotency changed");
        Ensure(
            firstEvent.Record.TriggerEventId == repeatedEvent.Record.TriggerEventId &&
            firstEvent.Record.CorrelationId == firstEvent.Record.TriggerEventId &&
            firstEvent.Record.CausationId is null && firstEvent.Record.CorrelationDepth == 0,
            "external trigger lineage identity changed");

        var firstAction = await journal.GetOrCreateActionAsync(
            rule,
            firstEvent.Record.TriggerEventId,
            actionIndex: 0,
            cancellationToken: CancellationToken.None);
        var repeatedAction = await journal.GetOrCreateActionAsync(
            rule,
            firstEvent.Record.TriggerEventId,
            actionIndex: 0,
            cancellationToken: CancellationToken.None);
        Ensure(firstAction.Created && !repeatedAction.Created, "action operation idempotency changed");
        Ensure(
            firstAction.Record.ActionOperationId == repeatedAction.Record.ActionOperationId &&
            firstAction.Record.CorrelationId == firstEvent.Record.CorrelationId &&
            firstAction.Record.CausationId == firstEvent.Record.TriggerEventId &&
            firstAction.Record.CorrelationDepth == 1 &&
            firstAction.Record.ClientMessageId == WorkflowOperationJournal.CreateClientMessageId(
                firstAction.Record.ActionOperationId),
            "action correlation causation or client identity changed");

        var json = await File.ReadAllTextAsync(journal.JournalPath);
        Ensure(
            !json.Contains("prompt-body-secret", StringComparison.Ordinal) &&
            !json.Contains("attachment-path-secret", StringComparison.Ordinal) &&
            !json.Contains("working-directory-secret", StringComparison.Ordinal),
            "workflow journal stored content-bearing fields");
        Ensure(new FileInfo(journal.JournalPath).Length <= WorkflowOperationJournal.DefaultMaximumFileBytes,
            "workflow journal exceeded its byte bound");
    }

    private static async Task TestTransitionSafetyAsync()
    {
        var journal = CreateJournal();
        var rule = ScheduledSendRule(seed: 200);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-200");
        var prepared = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        var invalidRetry = await journal.TryMarkRetryableProvenUnsentAsync(
            prepared.Record.ActionOperationId,
            "owner-unavailable",
            CancellationToken.None);
        Ensure(!invalidRetry.Changed, "prepared action became retryable without dispatch intent");

        var dispatching = await journal.TryStartDispatchAsync(
            prepared.Record.ActionOperationId,
            CancellationToken.None);
        Ensure(
            dispatching.Changed && dispatching.Record is
            {
                State: WorkflowActionOperationState.Dispatching,
                AttemptCount: 1
            },
            "workflow dispatch intent was not durably counted");
        var invalidTerminal = await journal.TryMarkTerminalAsync(
            prepared.Record.ActionOperationId,
            WorkflowActionOperationState.Blocked,
            "policy-changed",
            CancellationToken.None);
        Ensure(!invalidTerminal.Changed, "dispatching action bypassed uncertainty or proven-unsent handling");

        var retryable = await journal.TryMarkRetryableProvenUnsentAsync(
            prepared.Record.ActionOperationId,
            "owner-unavailable",
            CancellationToken.None);
        Ensure(
            retryable.Changed && retryable.Record is
            {
                State: WorkflowActionOperationState.Retryable,
                FailureClass: "owner-unavailable"
            },
            "proven-unsent workflow failure did not become retryable");
        var secondDispatch = await journal.TryStartDispatchAsync(
            prepared.Record.ActionOperationId,
            CancellationToken.None);
        Ensure(secondDispatch.Record?.AttemptCount == 2, "workflow retry attempt count changed");
        var uncertain = await journal.TryMarkUncertainAsync(
            prepared.Record.ActionOperationId,
            "timeout-after-write",
            CancellationToken.None);
        Ensure(uncertain.Record?.State == WorkflowActionOperationState.Uncertain, "uncertain state was not durable");
        var confirmed = await journal.TryMarkConfirmedAsync(
            prepared.Record.ActionOperationId,
            new WorkflowActionReceipt(rule.OwnerConversationId, Id(299), null),
            CancellationToken.None);
        Ensure(
            confirmed.Changed && confirmed.Record is
            {
                State: WorkflowActionOperationState.Confirmed,
                GeneratedTurnId: not null,
                ProtectionSettingsGeneration: null
            },
            "authoritative workflow send receipt was not confirmed");
        var replay = await journal.TryMarkConfirmedAsync(
            prepared.Record.ActionOperationId,
            new WorkflowActionReceipt(rule.OwnerConversationId, Id(299), null),
            CancellationToken.None);
        Ensure(!replay.Changed, "identical confirmed receipt was rewritten");
        await AssertThrowsAsync<InvalidOperationException>(() => journal.TryMarkConfirmedAsync(
            prepared.Record.ActionOperationId,
            new WorkflowActionReceipt(rule.OwnerConversationId, Id(298), null),
            CancellationToken.None));
    }

    private static async Task TestProtectionReceiptAsync()
    {
        var journal = CreateJournal();
        var owner = Id(300);
        var target = Id(301);
        var rule = WorkflowRuleDefinition.Create(
            Id(302),
            1,
            owner,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(target),
            null,
            [Protect(0)]);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-300");
        var prepared = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        Ensure(
            prepared.Record.ClientMessageId is null && prepared.Record.TargetConversationId == target,
            "protection action fabricated Desktop send identity");
        _ = await journal.TryStartDispatchAsync(prepared.Record.ActionOperationId, CancellationToken.None);
        var confirmed = await journal.TryMarkConfirmedAsync(
            prepared.Record.ActionOperationId,
            new WorkflowActionReceipt(target, null, ProtectionSettingsGeneration: 9),
            CancellationToken.None);
        Ensure(
            confirmed.Record is
            {
                State: WorkflowActionOperationState.Confirmed,
                GeneratedTurnId: null,
                ProtectionSettingsGeneration: 9
            },
            "typed protection receipt was not persisted");
    }

    private static async Task TestExecutionBindingAndNoProgressAsync()
    {
        var journal = CreateJournal();
        var owner = Id(250);
        var target = Id(251);
        var rule = WorkflowRuleDefinition.Create(
            Id(252),
            1,
            owner,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(target),
            null,
            [Send(owner, Id(253), 0), Send(owner, Id(254), 1)]);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-250");
        var first = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        var fingerprint = new string('A', 64);
        var bound = await journal.TryBindExecutionAsync(
            first.Record.ActionOperationId,
            fingerprint.ToLowerInvariant(),
            authoritativeTargetGeneration: 17,
            CancellationToken.None);
        var repeated = await journal.TryBindExecutionAsync(
            first.Record.ActionOperationId,
            fingerprint,
            authoritativeTargetGeneration: 17,
            CancellationToken.None);
        Ensure(
            bound.Status == WorkflowExecutionBindingStatus.Bound &&
            bound.Record?.ExecutionFingerprint == fingerprint &&
            bound.Record.AuthoritativeTargetGeneration == 17 &&
            repeated.Status == WorkflowExecutionBindingStatus.AlreadyBound,
            "workflow execution binding was not canonical or idempotent");
        await AssertThrowsAsync<InvalidOperationException>(() => journal.TryBindExecutionAsync(
            first.Record.ActionOperationId,
            new string('B', 64),
            authoritativeTargetGeneration: 17,
            CancellationToken.None));

        var second = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            1,
            cancellationToken: CancellationToken.None);
        var blocked = await journal.TryBindExecutionAsync(
            second.Record.ActionOperationId,
            fingerprint,
            authoritativeTargetGeneration: 17,
            CancellationToken.None);
        Ensure(
            blocked.Status == WorkflowExecutionBindingStatus.NoProgress &&
            blocked.Record?.State == WorkflowActionOperationState.Blocked &&
            blocked.Record.FailureClass == "no-progress",
            "workflow correlation revisit bypassed the no-progress circuit");

        var restarted = await CreateJournal(journal.DataDirectory)
            .ReadAsync(CancellationToken.None);
        Ensure(
            restarted.ReadStatus == WorkflowJournalReadStatus.Healthy &&
            restarted.Actions.Count == 2 &&
            restarted.Actions.Single(action =>
                action.ActionOperationId == second.Record.ActionOperationId).State ==
            WorkflowActionOperationState.Blocked,
            "workflow execution binding or no-progress state was not durable");
    }

    private static async Task TestHealthyRestartPromotionAsync()
    {
        var root = CreateRoot();
        var journal = CreateJournal(root);
        var rule = ScheduledSendRule(seed: 400);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-400");
        var prepared = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        _ = await journal.TryStartDispatchAsync(prepared.Record.ActionOperationId, CancellationToken.None);

        var restarted = CreateJournal(root);
        var snapshot = await restarted.ReadAsync(CancellationToken.None);
        Ensure(
            snapshot.ReadStatus == WorkflowJournalReadStatus.Healthy &&
            !snapshot.RequiresConservativeRecovery &&
            snapshot.Actions.Single() is
            {
                State: WorkflowActionOperationState.Uncertain,
                FailureClass: "restart-uncertain",
                AttemptCount: 1
            },
            "healthy restart did not conservatively promote dispatching state");
        var confirmed = await restarted.TryMarkConfirmedAsync(
            prepared.Record.ActionOperationId,
            new WorkflowActionReceipt(rule.OwnerConversationId, Id(499), null),
            CancellationToken.None);
        Ensure(confirmed.Record?.State == WorkflowActionOperationState.Confirmed,
            "restart uncertainty could not reconcile to confirmed");
    }

    private static async Task TestBackupRecoveryAsync()
    {
        var root = CreateRoot();
        var journal = CreateJournal(root);
        var rule = ScheduledSendRule(seed: 500);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-500");
        var prepared = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        _ = await journal.TryStartDispatchAsync(prepared.Record.ActionOperationId, CancellationToken.None);
        Ensure(File.Exists(journal.BackupPath), "workflow backup was not created before crash simulation");
        await File.WriteAllTextAsync(journal.JournalPath, "{");

        var recovered = CreateJournal(root);
        var snapshot = await recovered.ReadAsync(CancellationToken.None);
        Ensure(
            snapshot.ReadStatus == WorkflowJournalReadStatus.RecoveredFromBackup &&
            snapshot.RequiresConservativeRecovery &&
            snapshot.Actions.Single().State == WorkflowActionOperationState.Uncertain &&
            snapshot.Actions.Single().AttemptCount == 1,
            "backup recovery did not enter conservative uncertainty");
        await AssertThrowsAsync<InvalidOperationException>(() => recovered.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            Id(590),
            Id(591),
            Id(591),
            "occurrence-501",
            Activation.AddHours(2),
            cancellationToken: CancellationToken.None));
        var reconciled = await recovered.TryMarkConfirmedAsync(
            prepared.Record.ActionOperationId,
            new WorkflowActionReceipt(rule.OwnerConversationId, Id(599), null),
            CancellationToken.None);
        Ensure(reconciled.Record?.State == WorkflowActionOperationState.Confirmed,
            "recovered existing action could not be reconciled");
    }

    private static async Task TestDownstreamLineageAsync()
    {
        var journal = CreateJournal();
        var sourceRule = ScheduledSendRule(seed: 600);
        var external = await CreateScheduledEventAsync(journal, sourceRule, "occurrence-600");
        var sourceAction = await journal.GetOrCreateActionAsync(
            sourceRule,
            external.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        await AssertThrowsAsync<InvalidOperationException>(() => journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.PresetDispatchConfirmed,
            sourceRule.OwnerConversationId,
            sourceRule.Actions[0].PresetMessageId!,
            sourceAction.Record.ActionOperationId,
            "dispatch-600",
            Activation.AddHours(2),
            causationId: sourceAction.Record.ActionOperationId,
            cancellationToken: CancellationToken.None));
        _ = await journal.TryStartDispatchAsync(sourceAction.Record.ActionOperationId, CancellationToken.None);
        _ = await journal.TryMarkConfirmedAsync(
            sourceAction.Record.ActionOperationId,
            new WorkflowActionReceipt(sourceRule.OwnerConversationId, Id(699), null),
            CancellationToken.None);

        var downstream = await journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.PresetDispatchConfirmed,
            sourceRule.OwnerConversationId,
            sourceRule.Actions[0].PresetMessageId!,
            sourceAction.Record.ActionOperationId,
            "dispatch-600",
            Activation.AddHours(2),
            causationId: sourceAction.Record.ActionOperationId,
            cancellationToken: CancellationToken.None);
        Ensure(
            downstream.Record.CorrelationId == external.Record.CorrelationId &&
            downstream.Record.CausationId == sourceAction.Record.ActionOperationId &&
            downstream.Record.CorrelationDepth == sourceAction.Record.CorrelationDepth,
            "downstream trigger did not inherit lineage");
        var childRule = WorkflowRuleDefinition.Create(
            Id(610),
            1,
            sourceRule.OwnerConversationId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.PresetDispatchConfirmed,
                SourceConversationId = sourceRule.OwnerConversationId,
                SourcePresetMessageId = sourceRule.Actions[0].PresetMessageId
            },
            Existing(Id(611)),
            null,
            [Protect(0)]);
        var childAction = await journal.GetOrCreateActionAsync(
            childRule,
            downstream.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        Ensure(
            childAction.Record.CorrelationId == external.Record.CorrelationId &&
            childAction.Record.CorrelationDepth == 2,
            "child action correlation depth changed");
        await AssertThrowsAsync<InvalidOperationException>(() => journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.PresetDispatchConfirmed,
            sourceRule.OwnerConversationId,
            sourceRule.Actions[0].PresetMessageId!,
            sourceAction.Record.ActionOperationId,
            "dispatch-601",
            Activation.AddHours(2),
            correlationId: Id(612),
            causationId: sourceAction.Record.ActionOperationId,
            cancellationToken: CancellationToken.None));
    }

    private static async Task TestCorrelationLifetimeBoundAsync()
    {
        var clock = new WorkflowTestTimeProvider(Activation.AddHours(3));
        var journal = new WorkflowOperationJournal(CreateRoot(), timeProvider: clock);
        var sourceRule = ScheduledSendRule(seed: 650);
        var external = await CreateScheduledEventAsync(
            journal,
            sourceRule,
            "occurrence-650");
        var sourceAction = await journal.GetOrCreateActionAsync(
            sourceRule,
            external.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        _ = await journal.TryStartDispatchAsync(
            sourceAction.Record.ActionOperationId,
            CancellationToken.None);
        _ = await journal.TryMarkConfirmedAsync(
            sourceAction.Record.ActionOperationId,
            new WorkflowActionReceipt(sourceRule.OwnerConversationId, Id(659), null),
            CancellationToken.None);

        var boundary = external.Record.ObservedAtUtc +
                       WorkflowOperationJournal.MaximumCorrelationLifetime;
        clock.SetUtcNow(boundary);
        var accepted = await journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.PresetDispatchConfirmed,
            sourceRule.OwnerConversationId,
            sourceRule.Actions[0].PresetMessageId!,
            sourceAction.Record.ActionOperationId,
            "lifetime-boundary",
            boundary,
            causationId: sourceAction.Record.ActionOperationId,
            cancellationToken: CancellationToken.None);
        Ensure(
            accepted.Created && accepted.Record.ObservedAtUtc == boundary,
            "the inclusive correlation lifetime boundary was rejected");

        var retryableRule = DownstreamProtectionRule(660, sourceRule);
        var preparedRule = DownstreamProtectionRule(663, sourceRule);
        var retryableAction = await journal.GetOrCreateActionAsync(
            retryableRule,
            accepted.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        var preparedAction = await journal.GetOrCreateActionAsync(
            preparedRule,
            accepted.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        var boundaryDispatch = await journal.TryStartDispatchAsync(
            retryableAction.Record.ActionOperationId,
            CancellationToken.None);
        _ = await journal.TryMarkRetryableProvenUnsentAsync(
            retryableAction.Record.ActionOperationId,
            "owner-unavailable",
            CancellationToken.None);
        Ensure(
            boundaryDispatch.Record?.State == WorkflowActionOperationState.Dispatching,
            "the inclusive correlation lifetime boundary blocked dispatch");

        clock.Advance(TimeSpan.FromTicks(1));
        var expiredRetryable = await journal.TryStartDispatchAsync(
            retryableAction.Record.ActionOperationId,
            CancellationToken.None);
        var expiredPrepared = await journal.TryStartDispatchAsync(
            preparedAction.Record.ActionOperationId,
            CancellationToken.None);
        Ensure(
            expiredRetryable.Record is
            {
                State: WorkflowActionOperationState.Blocked,
                AttemptCount: 1,
                FailureClass: "correlation-lifetime-exhausted"
            } &&
            expiredPrepared.Record is
            {
                State: WorkflowActionOperationState.Blocked,
                AttemptCount: 0,
                FailureClass: "correlation-lifetime-exhausted"
            },
            "an expired prepared or retryable action entered dispatch");

        var beforeInvalid = await journal.ReadAsync(CancellationToken.None);
        var beforeInvalidHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(journal.JournalPath)));
        await AssertThrowsAsync<InvalidOperationException>(() =>
            journal.GetOrCreateTriggerEventAsync(
                WorkflowTriggerKind.PresetDispatchConfirmed,
                sourceRule.OwnerConversationId,
                sourceRule.Actions[0].PresetMessageId!,
                sourceAction.Record.ActionOperationId,
                "observation-before-root",
                external.Record.ObservedAtUtc.AddTicks(-1),
                causationId: sourceAction.Record.ActionOperationId,
                cancellationToken: CancellationToken.None));
        var afterInvalid = await journal.ReadAsync(CancellationToken.None);
        var afterInvalidHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(journal.JournalPath)));
        var restarted = await new WorkflowOperationJournal(
                journal.DataDirectory,
                timeProvider: clock)
            .ReadAsync(CancellationToken.None);
        Ensure(
            restarted.ReadStatus == WorkflowJournalReadStatus.Healthy &&
            restarted.TriggerEvents.Count == 2 &&
            restarted.Actions.Count(action =>
                action.FailureClass == "correlation-lifetime-exhausted") == 2 &&
            beforeInvalid.Generation == afterInvalid.Generation &&
            string.Equals(beforeInvalidHash, afterInvalidHash, StringComparison.Ordinal),
            "the lifetime gate was not durable or malformed time changed the journal");
    }

    private static async Task TestHourlyDispatchBudgetAsync()
    {
        var clock = new WorkflowTestTimeProvider(Activation.AddHours(3));
        var journal = new WorkflowOperationJournal(CreateRoot(), timeProvider: clock);
        var owner = Id(670);
        var rule = WorkflowRuleDefinition.Create(
            Id(671),
            1,
            owner,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(owner),
            null,
            [
                Send(owner, Id(672), 0),
                Send(owner, Id(673), 1),
                Send(owner, Id(674), 2),
                Send(owner, Id(675), 3)
            ]);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-670");
        var actions = new List<WorkflowActionPrepareResult>();
        for (var actionIndex = 0; actionIndex < rule.Actions.Count; actionIndex++)
        {
            actions.Add(await journal.GetOrCreateActionAsync(
                rule,
                trigger.Record.TriggerEventId,
                actionIndex,
                cancellationToken: CancellationToken.None));
        }

        var action = actions[0];
        for (var attempt = 1;
             attempt <= WorkflowOperationJournal.MaximumDispatchAttemptsPerCorrelationPerHour;
             attempt++)
        {
            var dispatching = await journal.TryStartDispatchAsync(
                action.Record.ActionOperationId,
                CancellationToken.None);
            Ensure(
                dispatching.Record is
                {
                    State: WorkflowActionOperationState.Dispatching
                } && dispatching.Record.AttemptCount == attempt &&
                dispatching.Record.DispatchAttemptTimesUtc?.Count == attempt,
                "a dispatch inside the hourly correlation budget was blocked");
            var retryable = await journal.TryMarkRetryableProvenUnsentAsync(
                action.Record.ActionOperationId,
                "owner-unavailable",
                CancellationToken.None);
            Ensure(
                retryable.Record?.State == WorkflowActionOperationState.Retryable,
                "the budget fixture did not retain proven-unsent retry authority");
        }

        var exhausted = await journal.TryStartDispatchAsync(
            actions[1].Record.ActionOperationId,
            CancellationToken.None);
        var exhaustedGeneration = (await journal.ReadAsync(CancellationToken.None)).Generation;
        var repeated = await journal.TryStartDispatchAsync(
            actions[1].Record.ActionOperationId,
            CancellationToken.None);
        var replayGeneration = (await journal.ReadAsync(CancellationToken.None)).Generation;
        Ensure(
            exhausted.Changed && exhausted.Record is
            {
                State: WorkflowActionOperationState.Blocked,
                AttemptCount: 0,
                FailureClass: "dispatch-budget-exhausted"
            } && !repeated.Changed && exhaustedGeneration == replayGeneration,
            "the aggregate dispatch after the hourly budget was not durably blocked once");

        var otherRule = ScheduledSendRule(seed: 680);
        var otherTrigger = await CreateScheduledEventAsync(journal, otherRule, "occurrence-680");
        var otherAction = await journal.GetOrCreateActionAsync(
            otherRule,
            otherTrigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        var otherDispatch = await journal.TryStartDispatchAsync(
            otherAction.Record.ActionOperationId,
            CancellationToken.None);
        Ensure(
            otherDispatch.Record?.State == WorkflowActionOperationState.Dispatching,
            "one full correlation consumed another correlation's budget");

        clock.Advance(TimeSpan.FromHours(1));
        var inclusiveBoundary = await journal.TryStartDispatchAsync(
            actions[2].Record.ActionOperationId,
            CancellationToken.None);
        Ensure(
            inclusiveBoundary.Record is
            {
                State: WorkflowActionOperationState.Blocked,
                FailureClass: "dispatch-budget-exhausted"
            },
            "attempts exactly one hour old escaped the inclusive rolling window");

        clock.Advance(TimeSpan.FromTicks(1));
        var nextWindowJournal = new WorkflowOperationJournal(
            journal.DataDirectory,
            timeProvider: clock);
        var nextWindow = await nextWindowJournal.TryStartDispatchAsync(
            action.Record.ActionOperationId,
            CancellationToken.None);
        Ensure(
            nextWindow.Record is
            {
                State: WorkflowActionOperationState.Dispatching,
                AttemptCount: 65
            } && nextWindow.Record.DispatchAttemptTimesUtc?.Count == 65 &&
            nextWindow.Record.DispatchAttemptTimesUtc[^1] == clock.GetUtcNow(),
            "expired dispatch timestamps did not release the next rolling window");

        var restartedJournal = new WorkflowOperationJournal(
            journal.DataDirectory,
            timeProvider: clock);
        var restarted = await restartedJournal.ReadAsync(CancellationToken.None);
        var firstAfterRestart = restarted.Actions.Single(record =>
            record.ActionOperationId == action.Record.ActionOperationId);
        var generationBeforeAliasAttempt = restarted.Generation;
        var hashBeforeAliasAttempt = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(journal.JournalPath)));
        var exposed = firstAfterRestart.DispatchAttemptTimesUtc as IList<DateTimeOffset>;
        var mutationRejected = exposed is null;
        if (exposed is not null)
        {
            try
            {
                exposed.RemoveAt(0);
            }
            catch (NotSupportedException)
            {
                mutationRejected = true;
            }
        }

        var afterAliasAttempt = await restartedJournal.ReadAsync(CancellationToken.None);
        var hashAfterAliasAttempt = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(journal.JournalPath)));
        var retained = afterAliasAttempt.Actions.Single(record =>
            record.ActionOperationId == action.Record.ActionOperationId);
        Ensure(
            restarted.ReadStatus == WorkflowJournalReadStatus.Healthy &&
            firstAfterRestart.AttemptCount == 65 &&
            firstAfterRestart.DispatchAttemptTimesUtc?.Count == 65 &&
            mutationRejected && retained.DispatchAttemptTimesUtc?.Count == 65 &&
            afterAliasAttempt.Generation == generationBeforeAliasAttempt &&
            string.Equals(hashBeforeAliasAttempt, hashAfterAliasAttempt, StringComparison.Ordinal),
            "dispatch-time evidence did not survive restart or leaked a mutable alias");
    }

    private static async Task TestClockRollbackBoundAsync()
    {
        var clock = new WorkflowTestTimeProvider(Activation.AddHours(3));
        var journal = new WorkflowOperationJournal(CreateRoot(), timeProvider: clock);
        var owner = Id(690);
        var rule = WorkflowRuleDefinition.Create(
            Id(691),
            1,
            owner,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(owner),
            null,
            [Send(owner, Id(692), 0), Send(owner, Id(693), 1)]);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-690");
        var direct = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        var binding = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            1,
            cancellationToken: CancellationToken.None);

        clock.SetUtcNow(Activation.AddHours(2).AddMinutes(30));
        var directBlocked = await journal.TryStartDispatchAsync(
            direct.Record.ActionOperationId,
            CancellationToken.None);
        var bindingBlocked = await journal.TryBindExecutionAsync(
            binding.Record.ActionOperationId,
            new string('A', 64),
            authoritativeTargetGeneration: 7,
            CancellationToken.None);
        var restarted = await new WorkflowOperationJournal(
                journal.DataDirectory,
                timeProvider: clock)
            .ReadAsync(CancellationToken.None);
        Ensure(
            directBlocked.Record is
            {
                State: WorkflowActionOperationState.Blocked,
                AttemptCount: 0,
                FailureClass: "correlation-clock-invalid"
            } &&
            bindingBlocked.Status == WorkflowExecutionBindingStatus.InvalidState &&
            bindingBlocked.Record is
            {
                State: WorkflowActionOperationState.Blocked,
                AttemptCount: 0,
                FailureClass: "correlation-clock-invalid"
            } &&
            restarted.ReadStatus == WorkflowJournalReadStatus.Healthy &&
            restarted.Actions.Count(action =>
                action.FailureClass == "correlation-clock-invalid") == 2,
            "a clock rollback entered dispatch or damaged the workflow journal");
    }

    private static async Task TestCorruptAndUnsupportedAsync()
    {
        var corruptRoot = CreateRoot();
        Directory.CreateDirectory(corruptRoot);
        await File.WriteAllTextAsync(Path.Combine(corruptRoot, "workflow-operations.json"), "{");
        await File.WriteAllTextAsync(Path.Combine(corruptRoot, "workflow-operations.previous.json"), "{");
        await File.WriteAllBytesAsync(
            Path.Combine(corruptRoot, "workflow-operations.initialized"),
            [1]);
        var corrupt = await CreateJournal(corruptRoot).ReadAsync(CancellationToken.None);
        Ensure(
            corrupt.ReadStatus == WorkflowJournalReadStatus.Corrupted &&
            corrupt.RequiresConservativeRecovery,
            "corrupt workflow journal was not fail closed");

        var unsupportedRoot = CreateRoot();
        Directory.CreateDirectory(unsupportedRoot);
        await File.WriteAllTextAsync(
            Path.Combine(unsupportedRoot, "workflow-operations.json"),
            "{\"schemaVersion\":99}");
        var unsupportedJournal = CreateJournal(unsupportedRoot);
        var unsupported = await unsupportedJournal.ReadAsync(CancellationToken.None);
        Ensure(
            unsupported.ReadStatus == WorkflowJournalReadStatus.UnsupportedSchema &&
            unsupported.RequiresConservativeRecovery,
            "unsupported workflow journal schema was accepted");
        await AssertThrowsAsync<NotSupportedException>(() => unsupportedJournal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            Id(700),
            Id(701),
            Id(701),
            "occurrence-700",
            Activation,
            cancellationToken: CancellationToken.None));

        var legacyRoot = CreateRoot();
        Directory.CreateDirectory(legacyRoot);
        await File.WriteAllTextAsync(
            Path.Combine(legacyRoot, "workflow-operations.json"),
            "{\"schemaVersion\":1}");
        var legacy = await CreateJournal(legacyRoot).ReadAsync(CancellationToken.None);
        Ensure(
            WorkflowOperationJournal.CurrentSchemaVersion == 2 &&
            legacy.ReadStatus == WorkflowJournalReadStatus.UnsupportedSchema &&
            legacy.RequiresConservativeRecovery,
            "legacy workflow schema without dispatch-time evidence was not fail closed");
    }

    private static async Task TestCapacityBoundAsync()
    {
        var journal = new WorkflowOperationJournal(
            CreateRoot(),
            maximumTriggerEvents: 4,
            maximumActions: 1,
            maximumFileBytes: WorkflowOperationJournal.DefaultMaximumFileBytes,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var owner = Id(800);
        var rule = WorkflowRuleDefinition.Create(
            Id(801),
            1,
            owner,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(Id(802)),
            null,
            [Send(owner, Id(803), 0), Protect(1)]);
        var trigger = await CreateScheduledEventAsync(journal, rule, "occurrence-800");
        var first = await journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            cancellationToken: CancellationToken.None);
        await AssertThrowsAsync<InvalidOperationException>(() => journal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            1,
            cancellationToken: CancellationToken.None));
        var snapshot = await journal.ReadAsync(CancellationToken.None);
        Ensure(
            snapshot.Actions.Count == 1 &&
            snapshot.Actions[0].ActionOperationId == first.Record.ActionOperationId &&
            snapshot.Actions[0].State == WorkflowActionOperationState.Prepared,
            "capacity failure pruned or changed active workflow identity");
    }

    private static WorkflowOperationJournal CreateJournal(string? root = null) =>
        new(
            root ?? CreateRoot(),
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));

    private static WorkflowRuleDefinition DownstreamProtectionRule(
        int seed,
        WorkflowRuleDefinition sourceRule) =>
        WorkflowRuleDefinition.Create(
            Id(seed),
            1,
            sourceRule.OwnerConversationId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.PresetDispatchConfirmed,
                SourceConversationId = sourceRule.OwnerConversationId,
                SourcePresetMessageId = sourceRule.Actions[0].PresetMessageId
            },
            Existing(Id(seed + 1)),
            null,
            [Protect(0)]);

    private static WorkflowRuleDefinition ScheduledSendRule(int seed)
    {
        var owner = Id(seed);
        return WorkflowRuleDefinition.Create(
            Id(seed + 1),
            1,
            owner,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(owner),
            null,
            [Send(owner, Id(seed + 2), 0)]);
    }

    private static Task<WorkflowTriggerEventPrepareResult> CreateScheduledEventAsync(
        WorkflowOperationJournal journal,
        WorkflowRuleDefinition rule,
        string occurrence) =>
        journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            rule.OwnerConversationId,
            rule.RuleId,
            rule.RuleId,
            occurrence,
            Activation.AddHours(2),
            cancellationToken: CancellationToken.None);

    private static WorkflowTriggerDefinition ScheduledTrigger() => new()
    {
        Kind = WorkflowTriggerKind.ScheduledAt,
        ScheduledAtUtc = Activation.AddHours(1)
    };

    private static WorkflowDestinationDefinition Existing(string conversationId) => new()
    {
        Kind = WorkflowDestinationKind.ExistingConversation,
        ConversationId = conversationId
    };

    private static WorkflowActionDefinition Send(string ownerConversationId, string messageId, int order) => new()
    {
        Kind = WorkflowActionKind.SendPresetMessage,
        PresetOwnerConversationId = ownerConversationId,
        PresetMessageId = messageId,
        Order = order
    };

    private static WorkflowActionDefinition Protect(int order) => new()
    {
        Kind = WorkflowActionKind.EnableConversationProtection,
        Order = order
    };

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "wj-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private static string Id(int value) =>
        $"00000000-0000-0000-0000-{value:D12}";

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

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
            assert(false, $"{name}: {exception.GetType().Name} - {exception.Message}");
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
