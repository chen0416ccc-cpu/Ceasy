using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

internal static class RecoveryReconciliationOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "existing recovery reconciliation ignores a missing journal record",
            TestMissingRecordAsync,
            assert);
        await RunCaseAsync(
            "existing dispatching recovery is quarantined before observation",
            TestDispatchingOperationAsync,
            assert);
        await RunCaseAsync(
            "existing recovery reconciles one stable client id to confirmed",
            TestUniqueStableIdAsync,
            assert);
        await RunCaseAsync(
            "existing recovery keeps ambiguous stable ids uncertain",
            TestAmbiguousStableIdAsync,
            assert);
        await RunCaseAsync(
            "existing append recovery abandons an unattributed newer turn",
            TestUnattributedNewerTurnAsync,
            assert);
        await RunCaseAsync(
            "existing in-place retry confirms the observed replacement turn",
            TestInPlaceRetryReplacementTurnAsync,
            assert);
        await RunCaseAsync(
            "execute path returns an existing confirmed resend before capability checks",
            TestExecuteConfirmedOperationAsync,
            assert);
        await RunCaseAsync(
            "execute path reconciles an existing dispatching resend before capability checks",
            TestExecuteDispatchingOperationAsync,
            assert);
        await RunCaseAsync(
            "execute path keeps an id-less uncertain resend blocked for manual review",
            TestExecuteIdlessUncertainOperationAsync,
            assert);
        await RunCaseAsync(
            "an unproven native owner channel leaves prepared and retryable operations unchanged",
            TestExecuteUnsupportedPendingOperationsAsync,
            assert);
        await RunCaseAsync(
            "execute path rejects an existing action mismatch without a second operation",
            TestExecuteActionMismatchAsync,
            assert);
        await RunCaseAsync(
            "legacy id-less pending record does not poison unrelated new operations",
            TestLegacyIdlessRecordIsolationAsync,
            assert);
        await RunCaseAsync(
            "legacy id-less recovery cannot be assigned a new identity during closure",
            TestLegacyIdlessIdentityCannotBeFilledAsync,
            assert);
        await RunCaseAsync(
            "local failed terminal preserves full app-server replay evidence",
            TestFailedTerminalPreservesAppServerEvidenceAsync,
            assert);
    }

    private static Task TestFailedTerminalPreservesAppServerEvidenceAsync()
    {
        var turnId = Guid.NewGuid().ToString("D");
        var clientMessageId = Guid.NewGuid().ToString("D");
        var appServerTurn = new TurnSnapshot(
            turnId,
            "completed",
            "We're currently experiencing high demand, which may cause temporary errors.",
            "responseTooManyFailedAttempts",
            429,
            "retry the exact request",
            HasAttachments: true,
            HasAssistantOutput: false,
            HasWorkOutput: false,
            OutputFingerprint: "full-evidence",
            StartedAt: 100,
            CompletedAt: 101,
            RawUserInputJson: "[{\"type\":\"text\",\"text\":\"retry the exact request\"},{\"type\":\"localImage\",\"path\":\"D:\\\\evidence.png\"}]",
            UserMessageClientIds: [clientMessageId],
            HasUserMessage: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: false);
        var localTerminal = new LocalConversationTerminalEvent(
            Guid.NewGuid().ToString("D"),
            turnId,
            @"D:\\sessions\\rollout.jsonl",
            128,
            DateTimeOffset.FromUnixTimeSeconds(101),
            new TurnSnapshot(
                turnId,
                "failed",
                null,
                null,
                null,
                string.Empty,
                HasAttachments: false,
                HasAssistantOutput: false,
                HasWorkOutput: false,
                OutputFingerprint: "local-terminal",
                StartedAt: null,
                CompletedAt: 101,
                HasUserMessage: false,
                HasCompleteItemEvidence: false));

        var reconciled = LocalConversationHistoryReader.ReconcileLatestTurn(appServerTurn, localTerminal);
        var decision = new RecoveryClassifier().Classify(reconciled);
        Ensure(
            reconciled is
            {
                Status: "failed",
                ErrorCode: "responseTooManyFailedAttempts",
                HttpStatusCode: 429,
                HasConfirmedLocalTerminal: true,
                HasUserMessage: true,
                HasAttachments: true,
                HasCompleteItemEvidence: true,
                RawUserInputJson: not null
            } &&
            decision.Action == RecoveryActionKind.ResendOriginal &&
            RecoveryClassifier.IsProvenUnsentOriginalReplay(reconciled!, decision),
            "local task_complete metadata erased the full app-server input/item evidence");
        return Task.CompletedTask;
    }

    private static async Task TestMissingRecordAsync()
    {
        await WithFixtureAsync(async (root, thread, failedTurn, journal, service, readCount, recentTurns, _) =>
        {
            var before = await journal.ReadAsync();
            var result = await service.ReconcileExistingOperationAsync(thread, failedTurn);
            var after = await journal.ReadAsync();
            Ensure(
                result is null &&
                after.Generation == before.Generation &&
                after.Records.Count == 0 &&
                readCount() == 0,
                "a protection-off reconciliation created an operation or queried turns without a journal record");
        });
    }

    private static async Task TestDispatchingOperationAsync()
    {
        await WithFixtureAsync(async (root, thread, failedTurn, journal, service, readCount, recentTurns, _) =>
        {
            var clientMessageId = Guid.NewGuid().ToString("D");
            await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                clientMessageId,
                RecoveryOperationState.Dispatching);

            var result = await service.ReconcileExistingOperationAsync(thread, failedTurn);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                result is { State: RecoveryOperationState.Uncertain } &&
                persisted is { State: RecoveryOperationState.Uncertain } &&
                readCount() == 1,
                "a dispatching operation was not moved to uncertain before bounded observation");
        });
    }

    private static async Task TestUniqueStableIdAsync()
    {
        await WithFixtureAsync(async (root, thread, failedTurn, journal, service, readCount, recentTurns, _) =>
        {
            var clientMessageId = Guid.NewGuid().ToString("D");
            await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                clientMessageId,
                RecoveryOperationState.Uncertain);
            var replacementTurn = failedTurn with
            {
                Id = Guid.NewGuid().ToString("D"),
                Status = "completed",
                UserMessageClientIds = [clientMessageId]
            };
            recentTurns.Add(replacementTurn);

            var result = await service.ReconcileExistingOperationAsync(thread, failedTurn);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                result is { State: RecoveryOperationState.Confirmed, NewTurnId: not null } record &&
                string.Equals(record.NewTurnId, replacementTurn.Id, StringComparison.OrdinalIgnoreCase) &&
                persisted is { State: RecoveryOperationState.Confirmed, NewTurnId: not null } persistedRecord &&
                string.Equals(persistedRecord.NewTurnId, replacementTurn.Id, StringComparison.OrdinalIgnoreCase) &&
                readCount() == 1,
                "a unique stable client id did not reconcile to the observed replacement turn");
        });
    }

    private static async Task TestAmbiguousStableIdAsync()
    {
        await WithFixtureAsync(async (root, thread, failedTurn, journal, service, readCount, recentTurns, _) =>
        {
            var clientMessageId = Guid.NewGuid().ToString("D");
            await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                clientMessageId,
                RecoveryOperationState.Uncertain);
            var first = failedTurn with
            {
                Id = Guid.NewGuid().ToString("D"),
                UserMessageClientIds = [clientMessageId]
            };
            var second = failedTurn with
            {
                Id = Guid.NewGuid().ToString("D"),
                UserMessageClientIds = [clientMessageId]
            };
            recentTurns.Add(first);
            recentTurns.Add(second);

            var result = await service.ReconcileExistingOperationAsync(thread, failedTurn);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                result is { State: RecoveryOperationState.Uncertain } &&
                persisted is { State: RecoveryOperationState.Uncertain } &&
                first.Id != second.Id &&
                readCount() == 1,
                "multiple stable-id matches were treated as a confirmed send");
        });
    }

    private static async Task TestUnattributedNewerTurnAsync()
    {
        await WithFixtureAsync(async (root, thread, failedTurn, journal, service, readCount, recentTurns, _) =>
        {
            var clientMessageId = Guid.NewGuid().ToString("D");
            // Append recovery carries a stable client message id, so an unmatched newer turn proves
            // nothing about this operation and must not be adopted as its successor.
            await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                clientMessageId,
                RecoveryOperationState.Uncertain,
                RecoveryActionKind.SendContinue);
            var newerTurn = failedTurn with
            {
                Id = Guid.NewGuid().ToString("D"),
                Status = "completed",
                UserMessageClientIds = [Guid.NewGuid().ToString("D")]
            };
            recentTurns.Add(newerTurn);

            var result = await service.ReconcileExistingOperationAsync(thread, failedTurn);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                result is { State: RecoveryOperationState.Abandoned } &&
                persisted is { State: RecoveryOperationState.Abandoned } &&
                newerTurn.Id != failedTurn.Id &&
                readCount() == 1,
                "an unattributed newer turn did not close the uncertain append operation without redispatch");
        });
    }

    private static async Task TestInPlaceRetryReplacementTurnAsync()
    {
        await WithFixtureAsync(async (root, thread, failedTurn, journal, service, readCount, recentTurns, _) =>
        {
            var clientMessageId = Guid.NewGuid().ToString("D");
            await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                clientMessageId,
                RecoveryOperationState.Uncertain,
                RecoveryActionKind.ResendOriginal);
            // The owner's edit contract acknowledges without a turn id and only accepts the edit while
            // the failed turn is still last, so a newer latest turn is the replacement it produced.
            var replacementTurn = failedTurn with
            {
                Id = NewerTurnId(failedTurn.Id),
                Status = "completed",
                UserMessageClientIds = [Guid.NewGuid().ToString("D")]
            };
            recentTurns.Add(replacementTurn);

            var result = await service.ReconcileExistingOperationAsync(thread, failedTurn);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                result is { State: RecoveryOperationState.Confirmed } &&
                persisted is { State: RecoveryOperationState.Confirmed, NewTurnId: not null } record &&
                string.Equals(record.NewTurnId, replacementTurn.Id, StringComparison.OrdinalIgnoreCase) &&
                replacementTurn.Id != failedTurn.Id &&
                readCount() == 1,
                "an uncertain in-place retry did not adopt the observed replacement turn as its confirmation");
        });
    }

    private static async Task TestExecuteConfirmedOperationAsync()
    {
        await WithFixtureAsync(async (
            root,
            thread,
            failedTurn,
            journal,
            service,
            readCount,
            recentTurns,
            transportConnected) =>
        {
            var decision = ClassifyOriginalResend(failedTurn);
            var newTurnId = Guid.NewGuid().ToString("D");
            var clientMessageId = AppServerClient.CreateRecoveryMessageId(
                thread.Id,
                failedTurn.Id,
                decision.Action);
            var operation = await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                clientMessageId,
                RecoveryOperationState.Confirmed,
                decision.Action,
                RecoveryService.BuildRecoveryPayloadHash(decision.Action, failedTurn.UserText),
                newTurnId);

            var result = await ExecuteAsync(service, thread, failedTurn, decision);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                result is { Success: true, NewTurnId: not null } &&
                string.Equals(result.NewTurnId, newTurnId, StringComparison.OrdinalIgnoreCase) &&
                persisted is { State: RecoveryOperationState.Confirmed, NewTurnId: not null } record &&
                string.Equals(record.NewTurnId, newTurnId, StringComparison.OrdinalIgnoreCase) &&
                record.OperationId == operation.OperationId &&
                readCount() == 0 &&
                !transportConnected(),
                "an existing confirmed resend was hidden by capability checks or opened a transport");
        });
    }

    private static async Task TestExecuteDispatchingOperationAsync()
    {
        await WithFixtureAsync(async (
            root,
            thread,
            failedTurn,
            journal,
            service,
            readCount,
            recentTurns,
            transportConnected) =>
        {
            var decision = ClassifyOriginalResend(failedTurn);
            var clientMessageId = AppServerClient.CreateRecoveryMessageId(
                thread.Id,
                failedTurn.Id,
                decision.Action);
            await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                clientMessageId,
                RecoveryOperationState.Dispatching,
                decision.Action,
                RecoveryService.BuildRecoveryPayloadHash(decision.Action, failedTurn.UserText));
            var replacementTurn = failedTurn with
            {
                Id = Guid.NewGuid().ToString("D"),
                Status = "completed",
                UserMessageClientIds = [clientMessageId]
            };
            recentTurns.Add(replacementTurn);

            var result = await ExecuteAsync(service, thread, failedTurn, decision);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                result is { Success: true, NewTurnId: not null } &&
                string.Equals(result.NewTurnId, replacementTurn.Id, StringComparison.OrdinalIgnoreCase) &&
                persisted is
                {
                    State: RecoveryOperationState.Confirmed,
                    AttemptCount: 1,
                    NewTurnId: not null
                } record &&
                string.Equals(record.NewTurnId, replacementTurn.Id, StringComparison.OrdinalIgnoreCase) &&
                readCount() == 1 &&
                !transportConnected(),
                "an existing dispatching resend was not quarantined and reconciled before capability checks");
        });
    }

    private static async Task TestExecuteIdlessUncertainOperationAsync()
    {
        await WithFixtureAsync(async (
            root,
            thread,
            failedTurn,
            journal,
            service,
            readCount,
            recentTurns,
            transportConnected) =>
        {
            var decision = ClassifyOriginalResend(failedTurn);
            var operationId = await WriteLegacyIdlessUncertainOperationAsync(
                root,
                thread.Id,
                failedTurn.Id,
                decision.Action,
                RecoveryService.BuildRecoveryPayloadHash(decision.Action, failedTurn.UserText));

            var result = await ExecuteAsync(service, thread, failedTurn, decision);
            var snapshot = await journal.ReadAsync();
            var persisted = snapshot.Records.Single();
            Ensure(
                !result.Success &&
                result.IsUserBlocked &&
                result.FailureKind == RecoveryFailureKind.DesktopUnavailable &&
                snapshot.Records.Count == 1 &&
                persisted.OperationId == operationId &&
                persisted is
                {
                    State: RecoveryOperationState.Uncertain,
                    ClientMessageId: null,
                    AttemptCount: 1
                } &&
                readCount() == 1 &&
                !transportConnected(),
                "an id-less uncertain resend escaped manual review or was assigned a replacement identity");
        });
    }

    private static async Task TestExecuteUnsupportedPendingOperationsAsync()
    {
        foreach (var state in new[]
                 {
                     RecoveryOperationState.Prepared,
                     RecoveryOperationState.Retryable
                 })
        {
            await WithFixtureAsync(async (
                root,
                thread,
                failedTurn,
                journal,
                service,
                readCount,
                recentTurns,
                transportConnected) =>
            {
                var decision = ClassifyOriginalResend(failedTurn);
                var clientMessageId = AppServerClient.CreateRecoveryMessageId(
                    thread.Id,
                    failedTurn.Id,
                    decision.Action);
                var operation = await CreateOperationAsync(
                    journal,
                    thread.Id,
                    failedTurn.Id,
                    clientMessageId,
                    state,
                    decision.Action,
                    RecoveryService.BuildRecoveryPayloadHash(decision.Action, failedTurn.UserText));
                var initialAttemptCount = operation.AttemptCount;

                var result = await ExecuteAsync(service, thread, failedTurn, decision);
                var snapshot = await journal.ReadAsync();
                var persisted = snapshot.Records.Single();
                Ensure(
                    !result.Success &&
                    result.IsUserBlocked &&
                    // What matters here is that the durable operation and the transport are untouched, not
                    // how severe the refusal is called. An unproven channel is transient (Guardian ahead of
                    // Codex Desktop, or Desktop restarting), and DesktopIncompatible made it permanent --
                    // it locks until a new failed turn arrives and carries no retry time, so the operation
                    // stayed Prepared forever. DesktopUnavailable retries on the desktop signal instead.
                    result.FailureKind == RecoveryFailureKind.DesktopUnavailable &&
                    result.Message.Contains("native owner channel", StringComparison.OrdinalIgnoreCase) &&
                    snapshot.Records.Count == 1 &&
                    persisted.OperationId == operation.OperationId &&
                    persisted.State == state &&
                    persisted.AttemptCount == initialAttemptCount &&
                    persisted.ClientMessageId == clientMessageId &&
                    readCount() == 0 &&
                    !transportConnected(),
                    $"an unproven native owner channel changed the durable {state} operation or opened a transport");
            },
            requireCurrentNativeChannel: true);
        }
    }

    private static async Task TestExecuteActionMismatchAsync()
    {
        await WithFixtureAsync(async (
            root,
            thread,
            failedTurn,
            journal,
            service,
            readCount,
            recentTurns,
            transportConnected) =>
        {
            var decision = ClassifyOriginalResend(failedTurn);
            var existingAction = RecoveryActionKind.SendContinue;
            var existingClientId = AppServerClient.CreateRecoveryMessageId(
                thread.Id,
                failedTurn.Id,
                existingAction);
            var existing = await CreateOperationAsync(
                journal,
                thread.Id,
                failedTurn.Id,
                existingClientId,
                RecoveryOperationState.Prepared,
                existingAction,
                RecoveryService.BuildRecoveryPayloadHash(
                    existingAction,
                    SettingsService.DefaultContinueMessage));

            var result = await ExecuteAsync(service, thread, failedTurn, decision);
            var snapshot = await journal.ReadAsync();
            var persisted = snapshot.Records.Single();
            Ensure(
                !result.Success &&
                result.IsUserBlocked &&
                result.FailureKind == RecoveryFailureKind.StateChanged &&
                snapshot.Records.Count == 1 &&
                persisted.OperationId == existing.OperationId &&
                persisted.Action == existingAction &&
                persisted.State == RecoveryOperationState.Prepared &&
                persisted.AttemptCount == 0 &&
                readCount() == 0 &&
                !transportConnected(),
                "an existing action mismatch created a second operation or reached dispatch");
        });
    }

    private static async Task TestLegacyIdlessRecordIsolationAsync()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.Combine(parent, "reconcile-isolation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var legacyThread = Guid.NewGuid().ToString("D");
            var legacyTurn = Guid.NewGuid().ToString("D");
            await WriteLegacyIdlessUncertainOperationAsync(
                root,
                legacyThread,
                legacyTurn,
                RecoveryActionKind.ResendOriginal,
                RecoveryOperationJournal.ComputeInputHash("legacy isolation"));
            var journal = new RecoveryOperationJournal(root);
            var unrelatedThread = Guid.NewGuid().ToString("D");
            var unrelatedTurn = Guid.NewGuid().ToString("D");
            var unrelatedOperation = Guid.NewGuid().ToString("D");
            var prepared = await journal.GetOrCreateAsync(
                unrelatedOperation,
                unrelatedThread,
                unrelatedTurn,
                RecoveryActionKind.SendContinue,
                RecoveryOperationJournal.ComputeInputHash("unrelated"));
            var snapshot = await journal.ReadAsync();
            Ensure(
                prepared.Record.State == RecoveryOperationState.Prepared &&
                prepared.Record.ClientMessageId == unrelatedOperation &&
                snapshot.Records.Count == 2 &&
                snapshot.Records.Single(record => record.FailedTurnId == legacyTurn).State ==
                    RecoveryOperationState.Uncertain,
                "a legacy id-less pending record changed the initial state of an unrelated new operation");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task TestLegacyIdlessIdentityCannotBeFilledAsync()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.Combine(parent, "reconcile-immutable-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var threadId = Guid.NewGuid().ToString("D");
            var failedTurnId = Guid.NewGuid().ToString("D");
            await WriteLegacyIdlessUncertainOperationAsync(
                root,
                threadId,
                failedTurnId,
                RecoveryActionKind.ResendOriginal,
                RecoveryOperationJournal.ComputeInputHash("legacy immutable"));
            var journal = new RecoveryOperationJournal(root);
            var generatedId = Guid.NewGuid().ToString("D");
            var threw = false;
            try
            {
                await journal.TryTransitionAsync(
                    threadId,
                    failedTurnId,
                    RecoveryOperationState.Uncertain,
                    RecoveryOperationState.Abandoned,
                    clientMessageId: generatedId);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            var persisted = await journal.FindAsync(threadId, failedTurnId);
            Ensure(
                threw && persisted is
                {
                    State: RecoveryOperationState.Uncertain,
                    ClientMessageId: null
                },
                "a legacy id-less operation accepted a newly fabricated client identity during closure");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static Task<RecoveryExecutionResult> ExecuteAsync(
        RecoveryService service,
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        RecoveryDecision decision) =>
        service.ExecuteAsync(
            thread,
            failedTurn,
            decision,
            SettingsService.DefaultContinueMessage,
            includeSubAgents: false,
            service.BeginScopeValidationGeneration(),
            isDispatchAllowed: static () => true);

    private static RecoveryDecision ClassifyOriginalResend(TurnSnapshot failedTurn)
    {
        var decision = new RecoveryClassifier().Classify(failedTurn);
        Ensure(
            decision is { Action: RecoveryActionKind.ResendOriginal, IsTransient: true },
            "the reconciliation fixture did not classify as an exact original resend");
        return decision;
    }

    private static async Task<RecoveryOperationRecord> CreateOperationAsync(
        RecoveryOperationJournal journal,
        string threadId,
        string failedTurnId,
        string? clientMessageId,
        RecoveryOperationState state,
        RecoveryActionKind action = RecoveryActionKind.ResendOriginal,
        string? inputHash = null,
        string? newTurnId = null)
    {
        var operationId = AppServerClient.CreateRecoveryMessageId(threadId, failedTurnId, action);
        var incidentPolicy = new RecoveryIncidentPolicy(
            Guid.NewGuid().ToString("D"),
            failedTurnId,
            ParentOperationId: null,
            RecoveryCountingMode.PerFailedTurn,
            MaximumAttempts: 500,
            UnlimitedAttempts: false,
            PolicyVersion: 1,
            RecoveryOperationJournal.ComputeInputHash("offline reconciliation failure"),
            NoProgressCount: 0);
        var operation = await journal.GetOrCreateAsync(
            operationId,
            threadId,
            failedTurnId,
            action,
            inputHash ?? RecoveryOperationJournal.ComputeInputHash("offline reconciliation"),
            clientMessageId,
            incidentPolicy);
        if (state is RecoveryOperationState.Prepared)
        {
            return operation.Record;
        }

        await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Prepared,
            RecoveryOperationState.Dispatching,
            clientMessageId);
        if (state is RecoveryOperationState.Dispatching)
        {
            return (await journal.FindAsync(threadId, failedTurnId))!;
        }

        if (state is RecoveryOperationState.Retryable)
        {
            await journal.TryTransitionAsync(
                threadId,
                failedTurnId,
                RecoveryOperationState.Dispatching,
                RecoveryOperationState.Retryable,
                clientMessageId);
            return (await journal.FindAsync(threadId, failedTurnId))!;
        }

        if (state is RecoveryOperationState.Confirmed)
        {
            await journal.TryTransitionAsync(
                threadId,
                failedTurnId,
                RecoveryOperationState.Dispatching,
                RecoveryOperationState.Confirmed,
                clientMessageId,
                newTurnId ?? Guid.NewGuid().ToString("D"));
            return (await journal.FindAsync(threadId, failedTurnId))!;
        }

        await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Dispatching,
            RecoveryOperationState.Uncertain,
            clientMessageId);
        return (await journal.FindAsync(threadId, failedTurnId))!;
    }

    private static async Task<string> WriteLegacyIdlessUncertainOperationAsync(
        string root,
        string threadId,
        string failedTurnId,
        RecoveryActionKind action,
        string inputHash)
    {
        var operationId = AppServerClient.CreateRecoveryMessageId(threadId, failedTurnId, action);
        var now = DateTimeOffset.UtcNow;
        var record = new
        {
            operationId,
            threadId,
            failedTurnId,
            action,
            inputHash,
            state = RecoveryOperationState.Uncertain,
            clientMessageId = (string?)null,
            newTurnId = (string?)null,
            createdAt = now.AddSeconds(-1),
            updatedAt = now,
            attemptCount = 1
        };
        var records = new[] { record };
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var integrity = new
        {
            schemaVersion = RecoveryOperationJournal.LegacySchemaVersion,
            generation = 1L,
            requiresConservativeRecovery = false,
            records
        };
        var checksum = Convert.ToHexString(
            SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(integrity, options)));
        var document = new
        {
            schemaVersion = RecoveryOperationJournal.LegacySchemaVersion,
            generation = 1L,
            requiresConservativeRecovery = false,
            checksum,
            records
        };
        Directory.CreateDirectory(root);
        await File.WriteAllTextAsync(
            Path.Combine(root, "recovery-operations.json"),
            JsonSerializer.Serialize(document, options));
        return operationId;
    }

    // Turn ids are UUIDv7 in production, whose leading hex digits are a millisecond timestamp, so a
    // replacement turn always orders after the turn it replaced. Recovery now uses that ordering to tell
    // a replacement apart from a stale read of the observed list — the journal recorded exactly that
    // inversion once. Random v4 ids order arbitrarily, so a fixture that drew one straight from
    // Guid.NewGuid decided this case on a coin flip; draw one that satisfies the ordering the real id
    // scheme guarantees instead.
    private static string NewerTurnId(string failedTurnId)
    {
        for (var attempt = 0; attempt < 256; attempt++)
        {
            var candidate = Guid.NewGuid().ToString("D");
            if (string.Compare(candidate, failedTurnId, StringComparison.OrdinalIgnoreCase) > 0)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            "no candidate turn id ordering after the failed turn could be drawn");
    }

    private static async Task WithFixtureAsync(
        Func<
            string,
            ThreadSummary,
            TurnSnapshot,
            RecoveryOperationJournal,
            RecoveryService,
            Func<int>,
            IList<TurnSnapshot>,
            Func<bool>,
            Task> test,
        bool requireCurrentNativeChannel = false)
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.Combine(parent, "reconcile-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var thread = new ThreadSummary(
            Guid.NewGuid().ToString("D"),
            "offline reconciliation",
            "",
            @"D:\Workspace",
            "appServer",
            1,
            2,
            false,
            false);
        var failedTurn = new TurnSnapshot(
            Guid.NewGuid().ToString("D"),
            "failed",
            "provider failure",
            "internal_error",
            500,
            "retry",
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
        var journal = new RecoveryOperationJournal(root);
        var readCount = 0;
        var recentTurns = new List<TurnSnapshot>();
        try
        {
            using var log = new GuardianLog(root);
            await using var stateReader = new AppServerClient(new CodexCliLocator(), log);
            await using var desktop = new DesktopIpcClient(log);
            var wrappedReader = new Func<string, int, CancellationToken, Task<IReadOnlyList<TurnSnapshot>>>(
                (threadId, limit, cancellationToken) =>
                {
                    _ = threadId;
                    _ = limit;
                    _ = cancellationToken;
                    Interlocked.Increment(ref readCount);
                    return Task.FromResult<IReadOnlyList<TurnSnapshot>>(recentTurns.ToArray());
                });
            var service = new RecoveryService(
                stateReader,
                desktop,
                new DesktopThreadOwnerActivator(desktop, log),
                journal,
                log,
                readRecentTurns: wrappedReader,
                requireCurrentNativeChannel: requireCurrentNativeChannel);
            await test(
                root,
                thread,
                failedTurn,
                journal,
                service,
                () => Volatile.Read(ref readCount),
                recentTurns,
                () => stateReader.IsConnected || desktop.IsConnected);
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException("reconciliation fixture cleanup failed", exception);
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
