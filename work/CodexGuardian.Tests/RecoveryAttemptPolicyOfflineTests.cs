using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class RecoveryAttemptPolicyOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync("recovery policy defaults to finite 500 per failed turn", TestDefaultsAsync, assert);
        await RunCaseAsync("recovery policy round trips finite unlimited and counting modes", TestRoundTripAsync, assert);
        await RunCaseAsync("recovery journal persists incident budget metadata", TestJournalMetadataAsync, assert);
        await RunCaseAsync("legacy recovery journal upgrades to conservative original-only metadata", TestLegacyUpgradeAsync, assert);
        await RunCaseAsync("original-only policy rejects successor preparation", TestOriginalOnlyRejectsSuccessorAsync, assert);
        await RunCaseAsync("new failures do not inherit an unrelated incident", TestNewIncidentIsolationAsync, assert);
        await RunCaseAsync("successor policies inherit exact frozen lineage", TestSuccessorLineageAsync, assert);
        await RunCaseAsync("unresolved successors and no-progress circuits fail closed", TestSuccessorSafetyGatesAsync, assert);
        await RunCaseAsync("ordinary failures are not mistaken for recovery successors", TestSuccessorClassificationAsync, assert);
        await RunCaseAsync("per-failed-turn service path gives an exact successor its own budget", TestPerFailedTurnServicePathAsync, assert);
        await RunCaseAsync("shared-incident service path blocks an exhausted successor budget", TestSharedIncidentServicePathAsync, assert);
        await RunCaseAsync("retryable service path counts a prior unsent dispatch attempt", TestRetryableServicePathAsync, assert);
        await RunCaseAsync("unlimited service path still blocks the third no-progress successor", TestUnlimitedNoProgressServicePathAsync, assert);
        await RunCaseAsync("service path preserves frozen incident policy after journal restart", TestJournalRestartServicePathAsync, assert);
    }

    private static async Task TestDefaultsAsync()
    {
        var settings = new AppSettings();
        Ensure(
            settings.MaximumRecoveryAttempts == RecoveryAttemptPolicyLimits.DefaultMaximumAttempts &&
            settings.MaximumRecoveryAttempts == 500 &&
            settings.MaximumAttemptsPerFailure == 500 &&
            !settings.UnlimitedRecoveryAttempts &&
            settings.RecoveryCountingMode == RecoveryCountingMode.PerFailedTurn,
            "new settings expose the approved 500 finite per-failed-turn policy");

        await WithSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            var legacy = await WriteAndLoadLegacyAsync(service, root, 7, 5);
            Ensure(
                legacy.MaximumRecoveryAttempts == 500 &&
                legacy.MaximumAttemptsPerFailure == 500 &&
                !legacy.UnlimitedRecoveryAttempts &&
                legacy.RecoveryCountingMode == RecoveryCountingMode.PerFailedTurn,
                "the prototype five-attempt default is not preserved as a user policy");
        });
    }

    private static async Task TestRoundTripAsync()
    {
        await WithSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            await service.SaveAsync(new AppSettings
            {
                MaximumRecoveryAttempts = RecoveryAttemptPolicyLimits.MaximumFiniteAttempts,
                MaximumAttemptsPerFailure = RecoveryAttemptPolicyLimits.MaximumFiniteAttempts,
                UnlimitedRecoveryAttempts = true,
                RecoveryCountingMode = RecoveryCountingMode.SharedIncidentBudget
            });
            var loaded = await service.LoadAsync();
            Ensure(
                loaded.MaximumRecoveryAttempts == RecoveryAttemptPolicyLimits.MaximumFiniteAttempts &&
                loaded.MaximumAttemptsPerFailure == RecoveryAttemptPolicyLimits.MaximumFiniteAttempts &&
                loaded.UnlimitedRecoveryAttempts &&
                loaded.RecoveryCountingMode == RecoveryCountingMode.SharedIncidentBudget,
                "finite upper bound, unlimited flag, and shared incident mode round-trip");

            loaded.RecoveryCountingMode = RecoveryCountingMode.OriginalFailedTurnOnly;
            loaded.UnlimitedRecoveryAttempts = false;
            loaded.MaximumRecoveryAttempts = 1;
            loaded.MaximumAttemptsPerFailure = 1;
            await service.SaveAsync(loaded);
            var revised = await service.LoadAsync();
            Ensure(
                revised.MaximumRecoveryAttempts == 1 &&
                !revised.UnlimitedRecoveryAttempts &&
                revised.RecoveryCountingMode == RecoveryCountingMode.OriginalFailedTurnOnly,
                "original-only finite policy round-trips without resetting the generation");
        });
    }

    private static async Task TestJournalMetadataAsync()
    {
        await WithRootAsync(async root =>
        {
            var journal = new RecoveryOperationJournal(root);
            var operationId = Guid.NewGuid().ToString("D");
            var threadId = Guid.NewGuid().ToString("D");
            var failedTurnId = Guid.NewGuid().ToString("D");
            var incidentId = Guid.NewGuid().ToString("D");
            var policy = new RecoveryIncidentPolicy(
                incidentId,
                failedTurnId,
                ParentOperationId: null,
                RecoveryCountingMode.SharedIncidentBudget,
                MaximumAttempts: 500,
                UnlimitedAttempts: true,
                PolicyVersion: 9,
                FailureSignature: RecoveryOperationJournal.ComputeInputHash("429|no-work"),
                NoProgressCount: 1);
            var prepared = await journal.GetOrCreateAsync(
                operationId,
                threadId,
                failedTurnId,
                RecoveryActionKind.ResendOriginal,
                RecoveryOperationJournal.ComputeInputHash("payload"),
                clientMessageId: operationId,
                incidentPolicy: policy);
            var reloaded = await new RecoveryOperationJournal(root).ReadAsync();
            var record = reloaded.Records.Single();
            Ensure(
                prepared.Created &&
                record.IncidentId == incidentId &&
                record.RootFailedTurnId == failedTurnId &&
                record.CountingMode == RecoveryCountingMode.SharedIncidentBudget &&
                record.MaximumAttempts == 500 &&
                record.UnlimitedAttempts &&
                record.PolicyVersion == 9 &&
                record.NoProgressCount == 1,
                "incident budget metadata survives the checksummed journal round-trip");
        });
    }

    private static async Task TestLegacyUpgradeAsync()
    {
        await WithRootAsync(async root =>
        {
            var operationId = Guid.NewGuid().ToString("D");
            var threadId = Guid.NewGuid().ToString("D");
            var failedTurnId = Guid.NewGuid().ToString("D");
            var legacyRecord = new
            {
                operationId,
                threadId,
                failedTurnId,
                action = RecoveryActionKind.ResendOriginal,
                inputHash = RecoveryOperationJournal.ComputeInputHash("legacy"),
                state = RecoveryOperationState.Confirmed,
                clientMessageId = operationId,
                newTurnId = Guid.NewGuid().ToString("D"),
                createdAt = DateTimeOffset.UtcNow.AddMinutes(-1),
                updatedAt = DateTimeOffset.UtcNow,
                attemptCount = 1
            };
            var records = new[] { legacyRecord };
            var integrity = new
            {
                schemaVersion = 1,
                generation = 4L,
                requiresConservativeRecovery = false,
                records
            };
            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            var checksum = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(integrity, options)));
            var document = new
            {
                schemaVersion = 1,
                generation = 4L,
                requiresConservativeRecovery = false,
                checksum,
                records
            };
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(
                Path.Combine(root, "recovery-operations.json"),
                JsonSerializer.Serialize(document, options));
            var snapshot = await new RecoveryOperationJournal(root).ReadAsync();
            var record = snapshot.Records.Single();
            Ensure(
                snapshot.ReadStatus == RecoveryJournalReadStatus.Healthy &&
                record.CountingMode == RecoveryCountingMode.OriginalFailedTurnOnly &&
                record.IncidentId == operationId &&
                record.RootFailedTurnId == failedTurnId &&
                record.MaximumAttempts == 1 &&
                !record.UnlimitedAttempts,
                "schema one records receive conservative original-only incident metadata");
        });
    }

    private static async Task TestOriginalOnlyRejectsSuccessorAsync()
    {
        await WithRootAsync(async root =>
        {
            var journal = new RecoveryOperationJournal(root);
            var rootTurn = Guid.NewGuid().ToString("D");
            var policy = new RecoveryIncidentPolicy(
                Guid.NewGuid().ToString("D"),
                rootTurn,
                null,
                RecoveryCountingMode.OriginalFailedTurnOnly,
                500,
                false,
                1,
                RecoveryOperationJournal.ComputeInputHash("failure"),
                0);
            var threw = false;
            try
            {
                await journal.GetOrCreateAsync(
                    Guid.NewGuid().ToString("D"),
                    Guid.NewGuid().ToString("D"),
                    Guid.NewGuid().ToString("D"),
                    RecoveryActionKind.ResendOriginal,
                    RecoveryOperationJournal.ComputeInputHash("successor"),
                    null,
                    policy);
            }
            catch (ArgumentException)
            {
                threw = true;
            }

            Ensure(threw, "original-only incident metadata rejects a non-root failed turn");
        });
    }

    private static Task TestNewIncidentIsolationAsync()
    {
        var threadId = Guid.NewGuid().ToString("D");
        var previousFailedTurnId = Guid.NewGuid().ToString("D");
        var currentFailedTurn = FailedTurn();
        var previous = Record(
            threadId,
            previousFailedTurnId,
            RecoveryCountingMode.SharedIncidentBudget,
            incidentId: Guid.NewGuid().ToString("D"),
            rootFailedTurnId: previousFailedTurnId,
            parentOperationId: null,
            attemptCount: 1,
            state: RecoveryOperationState.Confirmed);

        var policy = RecoveryService.ResolveIncidentPolicySnapshot(
            [previous],
            threadId,
            currentFailedTurn,
            Decision(),
            new RecoveryCurrentTurnReconciliation(null, false, false, 0),
            policyVersion: 11,
            RecoveryCountingMode.PerFailedTurn,
            defaultMaximumAttempts: 500,
            defaultUnlimitedAttempts: false);

        Ensure(
            policy.IncidentId != previous.IncidentId &&
            policy.RootFailedTurnId == currentFailedTurn.Id &&
            policy.ParentOperationId is null &&
            policy.CountingMode == RecoveryCountingMode.SharedIncidentBudget,
            "an unrelated proven-unsent 429 created a fresh shared-budget incident");
        return Task.CompletedTask;
    }

    private static Task TestSuccessorLineageAsync()
    {
        var threadId = Guid.NewGuid().ToString("D");
        var rootFailedTurnId = Guid.NewGuid().ToString("D");
        var incidentId = Guid.NewGuid().ToString("D");
        var parentOperationId = Guid.NewGuid().ToString("D");
        var successor = FailedTurn();
        var decision = Decision();
        var signature = RecoveryService.BuildFailureSignature(successor, decision);
        var parent = Record(
            threadId,
            rootFailedTurnId,
            RecoveryCountingMode.SharedIncidentBudget,
            incidentId,
            rootFailedTurnId,
            parentOperationId: null,
            attemptCount: 1,
            state: RecoveryOperationState.Confirmed,
            operationId: parentOperationId,
            newTurnId: successor.Id,
            failureSignature: signature,
            noProgressCount: 1,
            maximumAttempts: 3);
        var lineage = new RecoveryCurrentTurnReconciliation(parent, true, false, 0);

        var inherited = RecoveryService.ResolveIncidentPolicySnapshot(
            [parent],
            threadId,
            successor,
            decision,
            lineage,
            policyVersion: 99,
            RecoveryCountingMode.PerFailedTurn,
            defaultMaximumAttempts: 500,
            defaultUnlimitedAttempts: false);
        Ensure(
            inherited.IncidentId == incidentId &&
            inherited.RootFailedTurnId == rootFailedTurnId &&
            inherited.ParentOperationId == parentOperationId &&
            inherited.CountingMode == RecoveryCountingMode.SharedIncidentBudget &&
            inherited.MaximumAttempts == 3 &&
            inherited.PolicyVersion == parent.PolicyVersion &&
            inherited.NoProgressCount == 0,
            "an exact proven-unsent 429 successor did not inherit its frozen incident and bypass the generic no-progress circuit");

        var perTurnParent = parent with { CountingMode = RecoveryCountingMode.PerFailedTurn, AttemptCount = 9 };
        var perTurn = RecoveryService.ResolveIncidentPolicySnapshot(
            [perTurnParent],
            threadId,
            successor,
            decision,
            lineage with { RecoverySuccessor = perTurnParent },
            policyVersion: 99,
            RecoveryCountingMode.PerFailedTurn,
            defaultMaximumAttempts: 1,
            defaultUnlimitedAttempts: false);
        Ensure(
            perTurn.CountingMode == RecoveryCountingMode.PerFailedTurn &&
            perTurn.MaximumAttempts == perTurnParent.MaximumAttempts,
            "per-failed-turn successor policy did not retain its frozen mode and limit");
        return Task.CompletedTask;
    }

    private static Task TestSuccessorSafetyGatesAsync()
    {
        var threadId = Guid.NewGuid().ToString("D");
        var successor = GenericTransientFailedTurn();
        var parent = Record(
            threadId,
            Guid.NewGuid().ToString("D"),
            RecoveryCountingMode.SharedIncidentBudget,
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            parentOperationId: null,
            attemptCount: 1,
            state: RecoveryOperationState.Confirmed,
            newTurnId: successor.Id,
            failureSignature: RecoveryService.BuildFailureSignature(successor, Decision()),
            noProgressCount: 2);
        var unresolved = new RecoveryCurrentTurnReconciliation(parent, false, false, 0);
        var unresolvedBlocked = false;
        try
        {
            _ = RecoveryService.ResolveIncidentPolicySnapshot(
                [parent],
                threadId,
                successor,
                Decision(),
                unresolved,
                1,
                RecoveryCountingMode.SharedIncidentBudget,
                500,
                false);
        }
        catch (Exception exception) when (exception.Message.Contains("could not be attributed", StringComparison.Ordinal))
        {
            unresolvedBlocked = true;
        }

        var blocked = parent with { NoProgressCount = 2 };
        var exactBlocked = false;
        try
        {
            _ = RecoveryService.ResolveIncidentPolicySnapshot(
                [blocked],
                threadId,
                successor,
                Decision(),
                new RecoveryCurrentTurnReconciliation(blocked, true, false, 0),
                1,
                RecoveryCountingMode.SharedIncidentBudget,
                500,
                true);
        }
        catch (Exception exception) when (exception.Message.Contains("Three Guardian-created", StringComparison.Ordinal))
        {
            exactBlocked = true;
        }

        var workSuccessor = successor with { HasToolActivity = true, HasWorkOutput = true };
        var reset = RecoveryService.ResolveIncidentPolicySnapshot(
            [blocked],
            threadId,
            workSuccessor,
            Decision(),
            new RecoveryCurrentTurnReconciliation(blocked, true, false, 0),
            1,
            RecoveryCountingMode.SharedIncidentBudget,
            500,
            true);
        Ensure(
            unresolvedBlocked && exactBlocked && reset.NoProgressCount == 0,
            "unresolved successor, three no-progress failures, or genuine work did not gate/reset recovery correctly");
        return Task.CompletedTask;
    }

    private static Task TestSuccessorClassificationAsync()
    {
        var turn = FailedTurn();
        var record = Record(
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            RecoveryCountingMode.SharedIncidentBudget,
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            null,
            0,
            RecoveryOperationState.Confirmed,
            newTurnId: turn.Id);
        Ensure(
            !GuardianEngine.ShouldBlockFailedRecoverySuccessor(turn, null, false) &&
            GuardianEngine.ShouldBlockFailedRecoverySuccessor(turn, record, false) &&
            !GuardianEngine.ShouldBlockFailedRecoverySuccessor(turn, record, true),
            "ordinary failures, unresolved successors, and exact non-original successors were not separated");
        return Task.CompletedTask;
    }

    private static async Task TestPerFailedTurnServicePathAsync()
    {
        await WithRootAsync(async root =>
        {
            var thread = Thread();
            var successor = ContinuableFailedTurn();
            var decision = ContinueDecision();
            var journal = new RecoveryOperationJournal(root);
            var parent = await SeedConfirmedParentAsync(
                journal,
                thread.Id,
                Guid.NewGuid().ToString("D"),
                successor.Id,
                RecoveryCountingMode.PerFailedTurn,
                maximumAttempts: 1,
                action: RecoveryActionKind.SendContinue);
            var policyCalls = 0;

            var result = await ExecuteServiceAsync(
                root,
                journal,
                thread,
                successor,
                RecoveryCountingMode.OriginalFailedTurnOnly,
                defaultMaximumAttempts: 1,
                defaultUnlimitedAttempts: false,
                () => Interlocked.Increment(ref policyCalls) == 1,
                decision);
            var snapshot = await journal.ReadAsync();
            var successorRecord = snapshot.Records.SingleOrDefault(record =>
                string.Equals(record.FailedTurnId, successor.Id, StringComparison.OrdinalIgnoreCase));

            Ensure(
                !result.Success &&
                result.FailureKind == RecoveryFailureKind.PolicyChanged &&
                policyCalls == 2 &&
                successorRecord is
                {
                    State: RecoveryOperationState.Prepared,
                    AttemptCount: 0,
                    CountingMode: RecoveryCountingMode.PerFailedTurn,
                    MaximumAttempts: 1
                } &&
                successorRecord.ParentOperationId == parent.OperationId &&
                successorRecord.IncidentId == parent.IncidentId,
                "an exact successor did not receive a fresh per-turn budget before the second policy gate stopped dispatch");
        });
    }

    private static async Task TestSharedIncidentServicePathAsync()
    {
        await WithRootAsync(async root =>
        {
            var thread = Thread();
            var successor = FailedTurn();
            var journal = new RecoveryOperationJournal(root);
            await SeedConfirmedParentAsync(
                journal,
                thread.Id,
                Guid.NewGuid().ToString("D"),
                successor.Id,
                RecoveryCountingMode.SharedIncidentBudget,
                maximumAttempts: 1);
            var policyCalls = 0;

            var result = await ExecuteServiceAsync(
                root,
                journal,
                thread,
                successor,
                RecoveryCountingMode.PerFailedTurn,
                defaultMaximumAttempts: 500,
                defaultUnlimitedAttempts: false,
                () => Interlocked.Increment(ref policyCalls) > 0);
            var snapshot = await journal.ReadAsync();

            Ensure(
                !result.Success &&
                result.FailureKind == RecoveryFailureKind.StateChanged &&
                result.Message.Contains("budget is exhausted", StringComparison.OrdinalIgnoreCase) &&
                policyCalls == 1 &&
                snapshot.Records.Count == 1 &&
                snapshot.Records.All(record => !string.Equals(
                    record.FailedTurnId,
                    successor.Id,
                    StringComparison.OrdinalIgnoreCase)),
                "an exhausted shared incident created a successor operation or passed the service budget gate");
        });
    }

    private static async Task TestRetryableServicePathAsync()
    {
        await WithRootAsync(async root =>
        {
            var thread = Thread();
            var failedTurn = FailedTurn();
            var journal = new RecoveryOperationJournal(root);
            var retryable = await SeedRetryableAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                RecoveryCountingMode.PerFailedTurn,
                maximumAttempts: 1);
            var policyCalls = 0;

            var result = await ExecuteServiceAsync(
                root,
                journal,
                thread,
                failedTurn,
                RecoveryCountingMode.PerFailedTurn,
                defaultMaximumAttempts: 500,
                defaultUnlimitedAttempts: false,
                () => Interlocked.Increment(ref policyCalls) > 0);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);

            Ensure(
                !result.Success &&
                result.FailureKind == RecoveryFailureKind.StateChanged &&
                result.Message.Contains("budget is exhausted", StringComparison.OrdinalIgnoreCase) &&
                policyCalls == 1 &&
                persisted is { State: RecoveryOperationState.Retryable, AttemptCount: 1 } &&
                persisted.OperationId == retryable.OperationId,
                "a retryable operation whose finite attempt was already consumed reached redispatch preparation");
        });
    }

    private static async Task TestUnlimitedNoProgressServicePathAsync()
    {
        await WithRootAsync(async root =>
        {
            var thread = Thread();
            var successor = GenericTransientFailedTurn();
            var decision = Decision();
            var journal = new RecoveryOperationJournal(root);
            await SeedConfirmedParentAsync(
                journal,
                thread.Id,
                Guid.NewGuid().ToString("D"),
                successor.Id,
                RecoveryCountingMode.SharedIncidentBudget,
                maximumAttempts: 1,
                unlimitedAttempts: true,
                noProgressCount: 2,
                failureSignature: RecoveryService.BuildFailureSignature(successor, decision));
            var policyCalls = 0;

            var result = await ExecuteServiceAsync(
                root,
                journal,
                thread,
                successor,
                RecoveryCountingMode.PerFailedTurn,
                defaultMaximumAttempts: 500,
                defaultUnlimitedAttempts: false,
                () => Interlocked.Increment(ref policyCalls) > 0,
                decision);
            var snapshot = await journal.ReadAsync();

            Ensure(
                !result.Success &&
                result.FailureKind == RecoveryFailureKind.StateChanged &&
                result.Message.Contains("no observable progress", StringComparison.OrdinalIgnoreCase) &&
                policyCalls == 1 &&
                snapshot.Records.Count == 1,
                "unlimited attempts bypassed the third identical no-progress successor circuit");
        });
    }

    private static async Task TestJournalRestartServicePathAsync()
    {
        await WithRootAsync(async root =>
        {
            var thread = Thread();
            var successor = ContinuableFailedTurn();
            var decision = ContinueDecision();
            var firstJournal = new RecoveryOperationJournal(root);
            var parent = await SeedConfirmedParentAsync(
                firstJournal,
                thread.Id,
                Guid.NewGuid().ToString("D"),
                successor.Id,
                RecoveryCountingMode.SharedIncidentBudget,
                maximumAttempts: 7,
                action: RecoveryActionKind.SendContinue,
                policyVersion: 23);
            var restartedJournal = new RecoveryOperationJournal(root);
            var policyCalls = 0;

            var result = await ExecuteServiceAsync(
                root,
                restartedJournal,
                thread,
                successor,
                RecoveryCountingMode.OriginalFailedTurnOnly,
                defaultMaximumAttempts: 1,
                defaultUnlimitedAttempts: false,
                () => Interlocked.Increment(ref policyCalls) == 1,
                decision);
            var snapshot = await restartedJournal.ReadAsync();
            var successorRecord = snapshot.Records.SingleOrDefault(record =>
                string.Equals(record.FailedTurnId, successor.Id, StringComparison.OrdinalIgnoreCase));

            Ensure(
                !result.Success &&
                result.FailureKind == RecoveryFailureKind.PolicyChanged &&
                policyCalls == 2 &&
                successorRecord is
                {
                    State: RecoveryOperationState.Prepared,
                    AttemptCount: 0,
                    CountingMode: RecoveryCountingMode.SharedIncidentBudget,
                    MaximumAttempts: 7,
                    UnlimitedAttempts: false,
                    PolicyVersion: 23
                } &&
                successorRecord.IncidentId == parent.IncidentId &&
                successorRecord.RootFailedTurnId == parent.RootFailedTurnId &&
                successorRecord.ParentOperationId == parent.OperationId,
                "a restarted service used its new defaults instead of the durable frozen incident policy");
        });
    }

    private static async Task<RecoveryExecutionResult> ExecuteServiceAsync(
        string root,
        RecoveryOperationJournal journal,
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        RecoveryCountingMode defaultCountingMode,
        int defaultMaximumAttempts,
        bool defaultUnlimitedAttempts,
        Func<bool> isDispatchAllowed,
        RecoveryDecision? decision = null)
    {
        using var log = new GuardianLog(root);
        await using var stateReader = new AppServerClient(new CodexCliLocator(), log);
        await using var desktop = new DesktopIpcClient(log);
        var service = new RecoveryService(
            stateReader,
            desktop,
            new DesktopThreadOwnerActivator(desktop, log),
            journal,
            log,
            defaultCountingMode: defaultCountingMode,
            defaultMaximumAttempts: defaultMaximumAttempts,
            defaultUnlimitedAttempts: defaultUnlimitedAttempts);
        var result = await service.ExecuteAsync(
            thread,
            failedTurn,
            decision ?? Decision(),
            SettingsService.DefaultContinueMessage,
            includeSubAgents: false,
            service.BeginScopeValidationGeneration(),
            isDispatchAllowed);
        Ensure(
            !stateReader.IsConnected && !desktop.IsConnected,
            "the offline service-path fixture reached a live transport connection");
        return result;
    }

    private static async Task<RecoveryOperationRecord> SeedConfirmedParentAsync(
        RecoveryOperationJournal journal,
        string threadId,
        string failedTurnId,
        string successorTurnId,
        RecoveryCountingMode countingMode,
        int maximumAttempts,
        bool unlimitedAttempts = false,
        int noProgressCount = 0,
        string? failureSignature = null,
        long policyVersion = 17,
        RecoveryActionKind action = RecoveryActionKind.ResendOriginal)
    {
        var operationId = Guid.NewGuid().ToString("D");
        var policy = new RecoveryIncidentPolicy(
            Guid.NewGuid().ToString("D"),
            failedTurnId,
            ParentOperationId: null,
            countingMode,
            maximumAttempts,
            unlimitedAttempts,
            policyVersion,
            failureSignature ?? RecoveryOperationJournal.ComputeInputHash("parent-failure"),
            noProgressCount);
        var prepared = await journal.GetOrCreateAsync(
            operationId,
            threadId,
            failedTurnId,
            action,
            RecoveryOperationJournal.ComputeInputHash("parent-payload"),
            operationId,
            policy);
        var dispatching = await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Prepared,
            RecoveryOperationState.Dispatching,
            operationId);
        var confirmed = await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Dispatching,
            RecoveryOperationState.Confirmed,
            operationId,
            successorTurnId);
        Ensure(
            prepared.Created && dispatching.Changed && confirmed.Changed && confirmed.Record is not null,
            "the service-path fixture could not seed a confirmed parent operation");
        return confirmed.Record!;
    }

    private static async Task<RecoveryOperationRecord> SeedRetryableAsync(
        RecoveryOperationJournal journal,
        string threadId,
        string failedTurnId,
        RecoveryCountingMode countingMode,
        int maximumAttempts)
    {
        var operationId = Guid.NewGuid().ToString("D");
        var policy = new RecoveryIncidentPolicy(
            Guid.NewGuid().ToString("D"),
            failedTurnId,
            ParentOperationId: null,
            countingMode,
            maximumAttempts,
            UnlimitedAttempts: false,
            PolicyVersion: 19,
            RecoveryOperationJournal.ComputeInputHash("retryable-failure"),
            NoProgressCount: 0);
        var prepared = await journal.GetOrCreateAsync(
            operationId,
            threadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash("retryable-payload"),
            operationId,
            policy);
        var dispatching = await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Prepared,
            RecoveryOperationState.Dispatching,
            operationId);
        var retryable = await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Dispatching,
            RecoveryOperationState.Retryable,
            operationId);
        Ensure(
            prepared.Created && dispatching.Changed && retryable.Changed && retryable.Record is not null,
            "the service-path fixture could not seed a retryable operation");
        return retryable.Record!;
    }

    private static ThreadSummary Thread() =>
        new(
            Guid.NewGuid().ToString("D"),
            "offline recovery policy",
            "",
            @"D:\Workspace",
            "appServer",
            1,
            2,
            IsSubAgent: false,
            IsEphemeral: false);

    private static TurnSnapshot FailedTurn(string? id = null) =>
        new(
            id ?? Guid.NewGuid().ToString("D"),
            "failed",
            "temporary provider failure",
            "rate_limit",
            429,
            "retry this",
            false,
            false,
            false,
            "failed",
            1,
            2,
            HasConfirmedLocalTerminal: true,
            UserMessageClientIds: [Guid.NewGuid().ToString("D")],
            HasUserMessage: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static TurnSnapshot ContinuableFailedTurn(string? id = null) =>
        FailedTurn(id) with
        {
            HasReasoningOutput = true
        };

    private static TurnSnapshot GenericTransientFailedTurn(string? id = null) =>
        FailedTurn(id) with
        {
            ErrorCode = "server_error",
            HttpStatusCode = 500
        };

    private static RecoveryDecision Decision() =>
        new(
            RecoveryActionKind.ResendOriginal,
            TaskHealth.NeedsAttention,
            "temporary provider failure",
            IsTransient: true);

    private static RecoveryDecision ContinueDecision() =>
        new(
            RecoveryActionKind.SendContinue,
            TaskHealth.NeedsAttention,
            "temporary provider failure after reasoning started",
            IsTransient: true);

    private static RecoveryOperationRecord Record(
        string threadId,
        string failedTurnId,
        RecoveryCountingMode mode,
        string incidentId,
        string rootFailedTurnId,
        string? parentOperationId,
        int attemptCount,
        RecoveryOperationState state,
        string? operationId = null,
        string? newTurnId = null,
        string? failureSignature = null,
        int noProgressCount = 0,
        int maximumAttempts = 500)
    {
        var effectiveOperationId = operationId ?? Guid.NewGuid().ToString("D");
        return new(
            effectiveOperationId,
            threadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash("policy-test"),
            state,
            effectiveOperationId,
            newTurnId,
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow,
            attemptCount,
            incidentId,
            rootFailedTurnId,
            parentOperationId,
            mode,
            maximumAttempts,
            false,
            7,
            failureSignature ?? RecoveryOperationJournal.ComputeInputHash("policy-test-failure"),
            noProgressCount);
    }

    private static async Task<AppSettings> WriteAndLoadLegacyAsync(
        SettingsService service,
        string root,
        int version,
        int attempts)
    {
        Directory.CreateDirectory(root);
        await File.WriteAllTextAsync(
            Path.Combine(root, "settings.json"),
            JsonSerializer.Serialize(new
            {
                ConfigurationVersion = version,
                MaximumAttemptsPerFailure = attempts,
                MonitorOnly = true
            }));
        return await service.LoadAsync();
    }

    private static async Task WithRootAsync(Func<string, Task> action)
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required");
        }

        var root = Path.GetFullPath(Path.Combine(
            parent,
            "recovery-policy-" + Guid.NewGuid().ToString("N")));
        Ensure(root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase), "policy tests use D-drive data");
        try { await action(root); }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static Task WithSettingsRootAsync(Func<string, Task> action) => WithRootAsync(action);

    private static void Ensure(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static async Task RunCaseAsync(string name, Func<Task> test, Action<bool, string> assert)
    {
        try { await test(); assert(true, name); }
        catch (Exception exception) { assert(false, $"{name}: {exception.Message}"); }
    }
}
