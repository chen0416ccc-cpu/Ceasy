using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

// AR27 coverage: a recovery that really happened has to stay visible after Guardian restarts, and a
// wait parked behind a busy owner has to be able to say so. Both properties failed live for reasons
// no existing test could catch, and each lives in a different file — the durable count in the
// journal, the escalation schedule in the engine, the owner-busy discriminator on the execution
// result — so they are pinned together here, around the one behaviour they jointly produce.
internal static class RecoveryVisibilityOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "an untouched journal reports no confirmed resend",
            TestEmptyLedgerAsync,
            assert);
        await RunCaseAsync(
            "a confirmed resend is counted with its transition time",
            TestConfirmedDispatchCountedAsync,
            assert);
        await RunCaseAsync(
            "an abandoned resend keeps counting its successor turn",
            TestAbandonedDispatchStillCountsAsync,
            assert);
        await RunCaseAsync(
            "a resend without a successor turn is not counted",
            TestPendingDispatchNotCountedAsync,
            assert);
        await RunCaseAsync(
            "another thread's confirmed resend is not counted",
            TestOtherThreadDispatchNotCountedAsync,
            assert);
        await RunCaseAsync(
            "the confirmed resend count survives a journal reload",
            TestLedgerSurvivesReloadAsync,
            assert);
        await RunCaseAsync(
            "the recovery service answers an empty ledger for a non thread id",
            TestServiceLedgerRejectsNonThreadIdAsync,
            assert);
        await RunCaseAsync(
            "the ledger describes an owner busy wait and clamps a backwards clock",
            () => Task.Run(TestLedgerPredicates),
            assert);
        await RunCaseAsync(
            "stall durations format down to seconds minutes and hours",
            () => Task.Run(TestStallDurationFormat),
            assert);
        await RunCaseAsync(
            "the stall line carries the refusal count the wait and the dispatch history",
            () => Task.Run(TestStallDescription),
            assert);
        await RunCaseAsync(
            "only an owner busy refusal carries a runtime status",
            () => Task.Run(TestOwnerBusyDiscriminator),
            assert);
        await RunCaseAsync(
            "an active or unknown owner snapshot refuses as owner busy and names the status",
            () => Task.Run(TestNotIdleOwnerSnapshot),
            assert);
        await RunCaseAsync(
            "a systemError owner still on the failed turn is dispatchable",
            () => Task.Run(TestSystemErrorOwnerIsDispatchable),
            assert);
        await RunCaseAsync(
            "stall reporting starts at five refusals and then doubles",
            () => Task.Run(TestStallReportingSchedule),
            assert);
    }
    private static async Task TestEmptyLedgerAsync() =>
        await WithJournalAsync(async (journal, threadId) =>
        {
            var ledger = await journal.ReadThreadLedgerAsync(threadId);
            Ensure(
                ledger.ConfirmedDispatches == 0 &&
                ledger.LastConfirmedAt is null &&
                !ledger.HasEverDispatched,
                "a journal with no records claimed a confirmed resend");
        });

    private static async Task TestConfirmedDispatchCountedAsync() =>
        await WithJournalAsync(async (journal, threadId) =>
        {
            var failedTurnId = NewId();
            var newTurnId = NewId();
            await ConfirmAsync(journal, threadId, failedTurnId, newTurnId);
            var record = await journal.FindAsync(threadId, failedTurnId);
            var ledger = await journal.ReadThreadLedgerAsync(threadId);
            Ensure(
                record is not null &&
                record.State == RecoveryOperationState.Confirmed &&
                record.NewTurnId == newTurnId,
                "the journal did not confirm the resend under test");
            Ensure(
                ledger.ConfirmedDispatches == 1 &&
                ledger.HasEverDispatched &&
                ledger.LastConfirmedAt == record!.UpdatedAt,
                "a confirmed resend was not counted at its own transition time");
        });

    // The invariant the whole ledger rests on. Abandonment only says the failed turn this record
    // targeted is no longer the thread's current turn — it is cleanup, not failure — so a resend
    // that reached Codex and returned a successor turn must keep counting after it. Dropping
    // abandoned records here is exactly how a working recovery would go back to looking like one
    // that never fired, which is the complaint AR27 exists to answer.
    private static async Task TestAbandonedDispatchStillCountsAsync() =>
        await WithJournalAsync(async (journal, threadId) =>
        {
            var failedTurnId = NewId();
            var newTurnId = NewId();
            await ConfirmAsync(journal, threadId, failedTurnId, newTurnId);
            var abandoned = await journal.TryTransitionAsync(
                threadId,
                failedTurnId,
                RecoveryOperationState.Confirmed,
                RecoveryOperationState.Abandoned);
            var ledger = await journal.ReadThreadLedgerAsync(threadId);
            Ensure(
                abandoned.Changed &&
                abandoned.Record is { State: RecoveryOperationState.Abandoned } &&
                abandoned.Record.NewTurnId == newTurnId,
                "abandoning the operation dropped the successor turn it had already committed");
            Ensure(
                ledger.ConfirmedDispatches == 1 &&
                ledger.LastConfirmedAt == abandoned.Record!.UpdatedAt,
                "an abandoned resend stopped counting even though its successor turn survived");
        });
    private static async Task TestPendingDispatchNotCountedAsync() =>
        await WithJournalAsync(async (journal, threadId) =>
        {
            var preparedTurnId = NewId();
            var uncertainTurnId = NewId();
            await PrepareAsync(journal, threadId, preparedTurnId);
            await DispatchAsync(journal, threadId, uncertainTurnId);
            await journal.TryTransitionAsync(
                threadId,
                uncertainTurnId,
                RecoveryOperationState.Dispatching,
                RecoveryOperationState.Uncertain);
            var ledger = await journal.ReadThreadLedgerAsync(threadId);
            Ensure(
                ledger.ConfirmedDispatches == 0 && ledger.LastConfirmedAt is null,
                "a resend with no successor turn was counted as a confirmed resend");
        });

    private static async Task TestOtherThreadDispatchNotCountedAsync() =>
        await WithJournalAsync(async (journal, threadId) =>
        {
            var otherThreadId = NewId();
            await ConfirmAsync(journal, otherThreadId, NewId(), NewId());
            var mineLedger = await journal.ReadThreadLedgerAsync(threadId);
            var otherLedger = await journal.ReadThreadLedgerAsync(otherThreadId);
            Ensure(
                mineLedger.ConfirmedDispatches == 0,
                "another thread's confirmed resend leaked into this thread's ledger");
            Ensure(
                otherLedger.ConfirmedDispatches == 1,
                "the thread that owns the confirmed resend did not see it");
        });

    // The durability claim: the count has to come back after the process that produced it is gone,
    // because an in-memory attempt counter resetting on restart is the second way a real resend
    // disappeared from the UI.
    private static async Task TestLedgerSurvivesReloadAsync() =>
        await WithJournalAsync(async (journal, threadId) =>
        {
            var root = journal.DataDirectory;
            var failedTurnId = NewId();
            await ConfirmAsync(journal, threadId, failedTurnId, NewId());
            await ConfirmAsync(journal, threadId, NewId(), NewId());
            var reloaded = new RecoveryOperationJournal(root);
            var ledger = await reloaded.ReadThreadLedgerAsync(threadId);
            var records = await reloaded.ReadAsync();
            var latest = records.Records
                .Where(record => !string.IsNullOrWhiteSpace(record.NewTurnId))
                .Max(record => record.UpdatedAt);
            Ensure(
                ledger.ConfirmedDispatches == 2 && ledger.LastConfirmedAt == latest,
                "a fresh journal over the same directory forgot the confirmed resends");
        });
    // The engine calls the ledger on every scan, including for the pseudo threads the watcher
    // synthesizes, so the forwarder has to answer "no history" instead of throwing on an id that
    // could never have a journal record: a descriptive read must never be able to block a dispatch.
    private static async Task TestServiceLedgerRejectsNonThreadIdAsync() =>
        await WithJournalAsync(async (journal, threadId) =>
        {
            var root = journal.DataDirectory;
            using var log = new GuardianLog(root);
            await using var stateReader = new AppServerClient(new CodexCliLocator(), log);
            await using var desktop = new DesktopIpcClient(log);
            var service = new RecoveryService(
                stateReader,
                desktop,
                new DesktopThreadOwnerActivator(desktop, log),
                journal,
                log);
            await ConfirmAsync(journal, threadId, NewId(), NewId());
            var rejected = await service.ReadRecoveryLedgerAsync("not-a-thread-id");
            var accepted = await service.ReadRecoveryLedgerAsync(threadId);
            Ensure(
                rejected.ConfirmedDispatches == 0 && rejected.LastConfirmedAt is null,
                "a non uuid thread id produced a non empty ledger");
            Ensure(
                accepted.ConfirmedDispatches == 1,
                "the service did not forward a real thread id to the journal");
        });

    private static void TestLedgerPredicates()
    {
        var now = DateTimeOffset.UtcNow;
        Ensure(
            !GuardianRecoveryLedger.Empty.HasEverDispatched &&
            !GuardianRecoveryLedger.Empty.IsOwnerBusyStalled &&
            GuardianRecoveryLedger.Empty.OwnerBusyDuration(now) == TimeSpan.Zero,
            "an empty ledger claimed history or a stall");
        Ensure(
            new GuardianRecoveryLedger(1, now).HasEverDispatched,
            "a ledger with one confirmed resend denied having dispatched");
        var stalled = new GuardianRecoveryLedger(0, null, 3, now.AddMinutes(-2));
        Ensure(
            stalled.IsOwnerBusyStalled && stalled.OwnerBusyDuration(now) == TimeSpan.FromMinutes(2),
            "a counted owner busy wait did not report itself or its duration");
        Ensure(
            !new GuardianRecoveryLedger(0, null, 3, null).IsOwnerBusyStalled,
            "refusals without a start time were treated as a measurable stall");
        Ensure(
            !new GuardianRecoveryLedger(0, null, 0, now.AddMinutes(-1)).IsOwnerBusyStalled,
            "a start time without refusals was treated as a stall");
        // A clock that moves backwards must not turn into a negative wait in the log or the UI.
        Ensure(
            new GuardianRecoveryLedger(0, null, 1, now.AddMinutes(5)).OwnerBusyDuration(now) == TimeSpan.Zero,
            "a start time in the future produced a negative wait");
    }
    private static void TestStallDurationFormat()
    {
        Ensure(
            GuardianEngine.FormatStallDuration(TimeSpan.FromSeconds(-5)) == "0s" &&
            GuardianEngine.FormatStallDuration(TimeSpan.Zero) == "0s",
            "a non positive wait did not format as 0s");
        Ensure(
            GuardianEngine.FormatStallDuration(TimeSpan.FromSeconds(45)) == "45s" &&
            GuardianEngine.FormatStallDuration(TimeSpan.FromSeconds(59.9)) == "59s",
            "a sub minute wait did not format as seconds");
        Ensure(
            GuardianEngine.FormatStallDuration(TimeSpan.FromSeconds(60)) == "1m00s" &&
            GuardianEngine.FormatStallDuration(TimeSpan.FromSeconds(150)) == "2m30s" &&
            GuardianEngine.FormatStallDuration(TimeSpan.FromSeconds(3570)) == "59m30s",
            "a sub hour wait did not format as minutes and seconds");
        Ensure(
            GuardianEngine.FormatStallDuration(TimeSpan.FromHours(1)) == "1h00m" &&
            GuardianEngine.FormatStallDuration(TimeSpan.FromMinutes(185)) == "3h05m",
            "an hour long wait did not format as hours and minutes");
    }

    private static void TestStallDescription()
    {
        var now = DateTimeOffset.UtcNow;
        var confirmed = GuardianEngine.DescribeOwnerBusyStall(
            "owner busy.",
            7,
            new GuardianRecoveryLedger(2, now.AddMinutes(-30), 7, now.AddMinutes(-10)),
            now);
        Ensure(
            confirmed.StartsWith("owner busy.", StringComparison.Ordinal) &&
            confirmed.Contains("Declined 7 time(s)", StringComparison.Ordinal) &&
            confirmed.Contains("10m00s", StringComparison.Ordinal) &&
            confirmed.Contains("2 recovery dispatch(es) already confirmed", StringComparison.Ordinal),
            "the stall line dropped the refusal count, the wait, or the confirmed history");
        var never = GuardianEngine.DescribeOwnerBusyStall(
            "owner busy.",
            5,
            new GuardianRecoveryLedger(0, null, 5, now.AddSeconds(-90)),
            now);
        Ensure(
            never.Contains("Declined 5 time(s)", StringComparison.Ordinal) &&
            never.Contains("1m30s", StringComparison.Ordinal) &&
            never.Contains("no recovery dispatch has been confirmed", StringComparison.Ordinal),
            "the stall line did not say that no resend had ever been confirmed");
    }
    // OwnerRuntimeStatus is the discriminator the engine uses to tell a wait apart from a hard
    // refusal — all three owner problems share DesktopOwnerUnavailable — so it must be set on the
    // busy path and left null everywhere else, or the stall counter would either never start or
    // never stop.
    private static void TestOwnerBusyDiscriminator()
    {
        var busy = RecoveryExecutionResult.OwnerBusy("owner busy.", "task_running");
        Ensure(
            !busy.Success &&
            !busy.IsUserBlocked &&
            busy.FailureKind == RecoveryFailureKind.DesktopOwnerUnavailable &&
            busy.OwnerRuntimeStatus == "task_running",
            "an owner busy refusal did not carry the owner's runtime status");
        Ensure(
            RecoveryExecutionResult.OwnerBusy("owner busy.", "   ").OwnerRuntimeStatus == "unknown",
            "a blank runtime status was not normalized");
        Ensure(
            RecoveryExecutionResult
                .Failed("owner missing.", failureKind: RecoveryFailureKind.DesktopOwnerUnavailable)
                .OwnerRuntimeStatus is null,
            "an ordinary owner failure was mistaken for a busy owner");
        Ensure(
            RecoveryExecutionResult.Ok("sent.", NewId()).OwnerRuntimeStatus is null,
            "a successful dispatch carried a busy owner status");
    }

    private static void TestNotIdleOwnerSnapshot()
    {
        var failedTurnId = NewId();
        var busy = RecoveryService.ValidateOwnerStateSnapshot(
            NewOwnerSnapshot("active", failedTurnId, "failed"),
            failedTurnId);
        Ensure(
            busy is not null &&
            busy.FailureKind == RecoveryFailureKind.DesktopOwnerUnavailable &&
            busy.OwnerRuntimeStatus == "active" &&
            busy.Message.Contains("active", StringComparison.Ordinal),
            "an active owner did not refuse as owner busy with a named status");
        var unknown = RecoveryService.ValidateOwnerStateSnapshot(
            NewOwnerSnapshot("some new state", failedTurnId, "failed"),
            failedTurnId);
        Ensure(
            unknown is not null && unknown.OwnerRuntimeStatus == "somenewstate",
            "an unknown runtime status was accepted instead of failing closed");
        var stale = RecoveryService.ValidateOwnerStateSnapshot(
            NewOwnerSnapshot("idle", NewId(), "failed"),
            failedTurnId);
        Ensure(
            stale is not null &&
            stale.FailureKind == RecoveryFailureKind.StateChanged &&
            stale.OwnerRuntimeStatus is null,
            "an idle owner on a different turn was reported as a busy owner");
        Ensure(
            RecoveryService.ValidateOwnerStateSnapshot(
                NewOwnerSnapshot("idle", failedTurnId, "failed"),
                failedTurnId) is null,
            "an idle owner still parked on the failed turn was refused");
    }

    // The AR28 unlock, and the single reason the user had never seen a resend land: a 429 leaves the
    // owner in `systemError`, so a gate that required `idle` could never fire on the failures that
    // matter. `systemError` has to pass the runtime check and then be judged by turn identity alone —
    // still the failed turn we are recovering, still an abnormal terminal state.
    private static void TestSystemErrorOwnerIsDispatchable()
    {
        Ensure(
            RecoveryService.IsOwnerRuntimeStatusDispatchable("idle") &&
            RecoveryService.IsOwnerRuntimeStatusDispatchable("systemError") &&
            RecoveryService.IsOwnerRuntimeStatusDispatchable("SYSTEMERROR"),
            "a terminal owner runtime status was not dispatchable");
        Ensure(
            !RecoveryService.IsOwnerRuntimeStatusDispatchable("active") &&
            !RecoveryService.IsOwnerRuntimeStatusDispatchable("streaming") &&
            !RecoveryService.IsOwnerRuntimeStatusDispatchable(string.Empty) &&
            !RecoveryService.IsOwnerRuntimeStatusDispatchable(null),
            "a running or unknown owner runtime status was treated as dispatchable");
        var failedTurnId = NewId();
        Ensure(
            RecoveryService.ValidateOwnerStateSnapshot(
                NewOwnerSnapshot("systemError", failedTurnId, "failed"),
                failedTurnId) is null,
            "a systemError owner still parked on the failed turn was refused");
        Ensure(
            RecoveryService.ValidateOwnerStateSnapshot(
                NewOwnerSnapshot("systemError", failedTurnId, "interrupted"),
                failedTurnId) is null,
            "a systemError owner on an interrupted failed turn was refused");
        var moved = RecoveryService.ValidateOwnerStateSnapshot(
            NewOwnerSnapshot("systemError", NewId(), "failed"),
            failedTurnId);
        Ensure(
            moved is not null && moved.FailureKind == RecoveryFailureKind.StateChanged,
            "a systemError owner that had moved to another turn was not refused as a state change");
        var recovered = RecoveryService.ValidateOwnerStateSnapshot(
            NewOwnerSnapshot("systemError", failedTurnId, "completed"),
            failedTurnId);
        Ensure(
            recovered is not null && recovered.FailureKind == RecoveryFailureKind.StateChanged,
            "a systemError owner whose turn had completed was resent anyway");
    }
    // The schedule is the reason a multi-hour wait produces a handful of log lines instead of one
    // per scan, and the reason it produces any at all: before AR27 the repeated-failure check
    // silenced the busy-owner refusal permanently after its first line.
    private static void TestStallReportingSchedule()
    {
        Ensure(
            GuardianEngine.OwnerBusyStallReportThreshold == 5,
            "the first stall report no longer lands at five refusals");
        foreach (var refusals in new[] { 1, 2, 3, 4 })
        {
            Ensure(
                !GuardianEngine.ShouldReportOwnerBusyStall(refusals, 0),
                $"a wait of {refusals} refusal(s) was reported before the threshold");
        }

        Ensure(
            GuardianEngine.ShouldReportOwnerBusyStall(5, 0),
            "the fifth refusal was not reported");
        Ensure(
            !GuardianEngine.ShouldReportOwnerBusyStall(6, 5) &&
            !GuardianEngine.ShouldReportOwnerBusyStall(9, 5),
            "a refusal below the doubled threshold was reported again");
        Ensure(
            GuardianEngine.ShouldReportOwnerBusyStall(10, 5) &&
            GuardianEngine.ShouldReportOwnerBusyStall(20, 10) &&
            GuardianEngine.ShouldReportOwnerBusyStall(40, 20),
            "the doubling escalation stopped reporting a growing wait");
        Ensure(
            !GuardianEngine.ShouldReportOwnerBusyStall(19, 10),
            "a wait short of the next doubling was reported early");
    }

    private static DesktopThreadOwnerStateSnapshot NewOwnerSnapshot(
        string runtimeStatus,
        string latestTurnId,
        string latestTurnStatus) =>
        new(
            NewId(),
            "codex-desktop",
            NewId(),
            1,
            runtimeStatus,
            latestTurnId,
            latestTurnStatus);
    private static string NewId() => Guid.NewGuid().ToString("D");

    private static async Task<RecoveryOperationRecord> PrepareAsync(
        RecoveryOperationJournal journal,
        string threadId,
        string failedTurnId)
    {
        var operationId = AppServerClient.CreateRecoveryMessageId(
            threadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal);
        var prepared = await journal.GetOrCreateAsync(
            operationId,
            threadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash("offline recovery visibility"),
            operationId);
        return prepared.Record;
    }

    private static async Task DispatchAsync(
        RecoveryOperationJournal journal,
        string threadId,
        string failedTurnId)
    {
        await PrepareAsync(journal, threadId, failedTurnId);
        var dispatching = await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Prepared,
            RecoveryOperationState.Dispatching);
        Ensure(dispatching.Changed, "the operation under test could not be moved to Dispatching");
    }

    private static async Task ConfirmAsync(
        RecoveryOperationJournal journal,
        string threadId,
        string failedTurnId,
        string newTurnId)
    {
        await DispatchAsync(journal, threadId, failedTurnId);
        var confirmed = await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Dispatching,
            RecoveryOperationState.Confirmed,
            newTurnId: newTurnId);
        Ensure(confirmed.Changed, "the operation under test could not be confirmed");
    }
    // Every root is under the declared D-drive test data root and is deleted again: journals here
    // are throwaway fixtures and must never land next to the real recovery-operations.json.
    private static async Task WithJournalAsync(Func<RecoveryOperationJournal, string, Task> test)
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.Combine(parent, "recovery-visibility-" + Guid.NewGuid().ToString("N"));
        if (!root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The offline test data root must stay on the D drive.");
        }

        Directory.CreateDirectory(root);
        try
        {
            await test(new RecoveryOperationJournal(root), NewId()).ConfigureAwait(false);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().ConfigureAwait(false);
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
