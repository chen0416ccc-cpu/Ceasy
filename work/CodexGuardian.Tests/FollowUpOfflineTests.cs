using CodexGuardian;
using CodexGuardian.Localization;
using CodexGuardian.Models;
using CodexGuardian.Services;
using CodexGuardian.ViewModels;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Windows.Threading;
using System.Xml.Linq;
using WpfColor = System.Windows.Media.Color;

internal static class FollowUpOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "follow-up arming distinguishes old normal completion, abnormal turns, and unknown state",
            TestCompletionArmingAsync,
            assert);
        await RunCaseAsync(
            "follow-up queue waits through failures and advances only after ordered normal completions",
            TestQueueOrderingAsync,
            assert);
        await RunCaseAsync(
            "follow-up error retries keep blank at 500 and never resend uncertain deliveries",
            TestErrorRetryLimitAsync,
            assert);
        await RunCaseAsync(
            "follow-up runtime presentation distinguishes scheduled pending uncertain blocked and exhausted queues",
            TestRuntimePresentationAsync,
            assert);
        await RunCaseAsync(
            "scheduled follow-ups expose one bounded deadline without bypassing queue order",
            TestScheduledQueueAsync,
            assert);
        await RunCaseAsync(
            "preset authorization stays explicit and independent from automatic recovery mode",
            TestPresetAuthorizationPolicyAsync,
            assert);
        await RunCaseAsync(
            "follow-up dispatch commits one stable Desktop send and durable confirmation",
            TestDispatchSuccessAsync,
            assert);
        await RunCaseAsync(
            "structured follow-up dispatch binds capability presentation journal and one owner send",
            TestStructuredDispatchAsync,
            assert);
        await RunCaseAsync(
            "follow-up policy, editing, and cancellation gates remain retryable before the Desktop write",
            TestDispatchPreWriteGuardsAsync,
            assert);
        await RunCaseAsync(
            "follow-up Desktop rejection stages close or retry operations without duplicate sends",
            TestDispatchDeliveryClassificationsAsync,
            assert);
        await RunCaseAsync(
            "follow-up restart reconciliation uses only the stable client id and never resends",
            TestPendingReconciliationAsync,
            assert);
        await RunCaseAsync(
            "follow-up settings normalize bounded per-task queues and UTC schedules",
            TestSettingsNormalizationAsync,
            assert);
        await RunCaseAsync(
            "follow-up settings enforce per-message, per-task, task-count, and global bounds",
            TestSettingsLimitsAsync,
            assert);
        await RunCaseAsync(
            "follow-up journal preserves stable at-most-once identity across restart and uncertainty",
            TestJournalAtMostOnceAsync,
            assert);
        await RunCaseAsync(
            "follow-up journal revises only retryable semantics and rolls safe operations across expected turns",
            TestJournalSemanticRevisionAsync,
            assert);
        await RunCaseAsync(
            "follow-up journal backup recovery promotes pending dispatch to uncertain",
            TestJournalBackupRecoveryAsync,
            assert);
        await RunCaseAsync(
            "follow-up journal prunes only inactive terminal records and fails closed at capacity",
            TestJournalPruningAndCapacityAsync,
            assert);
        await RunCaseAsync(
            "follow-up schedule and WPF wiring separate preset authority from the recovery monitor gate",
            TestScheduleAndUiContractAsync,
            assert);
        await RunCaseAsync(
            "attachment capability failure keeps the ViewModel draft and both durable stores unchanged",
            TestAttachmentSaveCommandCapabilityGateAsync,
            assert);
        await RunCaseAsync(
            "follow-up preview fixture is D-drive isolated and cannot start live integration",
            TestPreviewFixtureIsolationAsync,
            assert);
    }

    private static Task TestCompletionArmingAsync()
    {
        var normalId = Guid.NewGuid().ToString("D");
        var normal = NormalTurn(normalId);
        var anchored = FollowUpQueuePlanner.EvaluateCompletionArm(normal, "idle");
        Ensure(
            anchored.Kind == FollowUpCompletionArmKind.AnchoredToCurrentCompletion &&
            anchored.CanArm &&
            string.Equals(anchored.AnchorTurnId, normalId, StringComparison.OrdinalIgnoreCase),
            "a reliable existing completion was not captured as the save baseline");

        var active = FollowUpQueuePlanner.EvaluateCompletionArm(null, "active");
        Ensure(
            active.Kind == FollowUpCompletionArmKind.AwaitNextNormalCompletion &&
            active.CanArm &&
            active.AnchorTurnId is null,
            "an active task did not arm its next normal completion");

        var failed = FollowUpQueuePlanner.EvaluateCompletionArm(
            TerminalTurn(Guid.NewGuid().ToString("D"), "failed"),
            "idle");
        Ensure(
            failed.Kind == FollowUpCompletionArmKind.AwaitNextNormalCompletion &&
            failed.CanArm &&
            failed.AnchorTurnId is null,
            "a failed turn did not defer to recovery before the next completion");

        var unreliableCompletion = FollowUpQueuePlanner.EvaluateCompletionArm(
            normal with { HasCompleteItemEvidence = false },
            "idle");
        Ensure(
            unreliableCompletion.Kind == FollowUpCompletionArmKind.Unknown &&
            !unreliableCompletion.CanArm,
            "an unverified completed turn was accepted as a completion baseline");

        var previousMessage = CompletionMessage(0);
        var replacementMessage = CompletionMessage(0);
        var previousSuccessorId = Guid.NewGuid().ToString("D");
        var rearmed = new ThreadFollowUpSettings
        {
            CompletionAnchorTurnId = normal.Id,
            Messages = [replacementMessage]
        };
        var previousConfirmed = Operation(
            previousMessage,
            Guid.NewGuid().ToString("D"),
            FollowUpOperationState.Confirmed,
            previousSuccessorId);
        Ensure(
            FollowUpQueuePlanner.Evaluate(
                rearmed,
                normal,
                [previousConfirmed],
                DateTimeOffset.UtcNow).Kind == FollowUpQueueDecisionKind.Waiting &&
            FollowUpQueuePlanner.Evaluate(
                rearmed,
                NormalTurn(Guid.NewGuid().ToString("D")),
                [previousConfirmed],
                DateTimeOffset.UtcNow) is
            {
                Kind: FollowUpQueueDecisionKind.Ready,
                Message.Id: var readyMessageId
            } &&
            string.Equals(readyMessageId, replacementMessage.Id, StringComparison.OrdinalIgnoreCase),
            "re-saving a task did not re-arm the replacement queue from the current completion baseline");
        return Task.CompletedTask;
    }

    private static Task TestPresetAuthorizationPolicyAsync()
    {
        var legacy = CompletionMessage(0);
        var workflow = legacy with
        {
            Id = Guid.NewGuid().ToString("D"),
            UseWorkflowAutomation = true
        };
        var enabledQueue = new ThreadFollowUpSettings
        {
            IsEnabled = true,
            Messages = [legacy, workflow]
        };
        var pausedQueue = enabledQueue with { IsEnabled = false };
        Ensure(
            PresetAutomationPolicy.IsLegacyQueueMessageAuthorized(enabledQueue, legacy) &&
            !PresetAutomationPolicy.IsLegacyQueueMessageAuthorized(enabledQueue, workflow) &&
            !PresetAutomationPolicy.IsLegacyQueueMessageAuthorized(
                enabledQueue,
                legacy with { IsEnabled = false }) &&
            !PresetAutomationPolicy.IsLegacyQueueMessageAuthorized(pausedQueue, legacy),
            "legacy preset authorization inherited recovery mode or crossed into workflow ownership");
        return Task.CompletedTask;
    }

    private static Task TestQueueOrderingAsync()
    {
        var firstMessage = CompletionMessage(0);
        var secondMessage = CompletionMessage(1);
        var baselineTurn = NormalTurn(Guid.NewGuid().ToString("D"));
        var nextTurn = NormalTurn(Guid.NewGuid().ToString("D"));
        var settings = new ThreadFollowUpSettings
        {
            CompletionAnchorTurnId = baselineTurn.Id,
            Messages = [firstMessage, secondMessage]
        };

        Ensure(
            FollowUpQueuePlanner.Evaluate(
                settings,
                baselineTurn,
                [],
                DateTimeOffset.UtcNow).Kind == FollowUpQueueDecisionKind.Waiting,
            "the save-time completion baseline was sent immediately");

        var ready = FollowUpQueuePlanner.Evaluate(settings, nextTurn, [], DateTimeOffset.UtcNow);
        Ensure(
            ready.Kind == FollowUpQueueDecisionKind.Ready &&
            string.Equals(ready.Message?.Id, firstMessage.Id, StringComparison.OrdinalIgnoreCase),
            "the first message did not become ready after a newer normal completion");

        Ensure(
            FollowUpQueuePlanner.Evaluate(
                settings,
                TerminalTurn(nextTurn.Id, "failed"),
                [],
                DateTimeOffset.UtcNow).Kind == FollowUpQueueDecisionKind.Waiting,
            "a failed turn consumed a completion-triggered queue item");

        var successorId = Guid.NewGuid().ToString("D");
        var confirmedFirst = Operation(
            firstMessage,
            baselineTurn.Id,
            FollowUpOperationState.Confirmed,
            successorId);
        Ensure(
            FollowUpQueuePlanner.Evaluate(
                settings,
                TerminalTurn(successorId, "inProgress"),
                [confirmedFirst],
                DateTimeOffset.UtcNow).Kind == FollowUpQueueDecisionKind.Waiting,
            "the second message bypassed the running successor of the first message");

        var secondReady = FollowUpQueuePlanner.Evaluate(
            settings,
            NormalTurn(successorId),
            [confirmedFirst],
            DateTimeOffset.UtcNow);
        Ensure(
            secondReady.Kind == FollowUpQueueDecisionKind.Ready &&
            string.Equals(secondReady.Message?.Id, secondMessage.Id, StringComparison.OrdinalIgnoreCase),
            "the second message did not preserve queue order after the first successor completed");

        var uncertain = Operation(
            firstMessage,
            baselineTurn.Id,
            FollowUpOperationState.Uncertain);
        var uncertainDecision = FollowUpQueuePlanner.Evaluate(
            settings,
            nextTurn,
            [uncertain],
            DateTimeOffset.UtcNow);
        Ensure(
            uncertainDecision.Kind == FollowUpQueueDecisionKind.ReconcilePending &&
            uncertainDecision.PendingOperation?.OperationId == uncertain.OperationId,
            "an uncertain prior send did not enter stable-id reconciliation before the queue advanced");

        var disabledHead = firstMessage with { IsEnabled = false };
        var disabledSettings = new ThreadFollowUpSettings
        {
            Messages = [disabledHead, secondMessage with { Order = 1, Trigger = FollowUpTriggerKind.ScheduledAt,
                ScheduledAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }]
        };
        var scheduledThreadId = Guid.NewGuid().ToString("D");
        var disabledConfirmed = confirmedFirst with
        {
            ThreadId = scheduledThreadId,
            MessageId = disabledHead.Id,
            CompletionTurnId = null
        };
        Ensure(
            FollowUpQueuePlanner.FindNextScheduledAtUtc(
                new Dictionary<string, ThreadFollowUpSettings> { [scheduledThreadId] = disabledSettings },
                [disabledConfirmed]) is null,
            "a later schedule bypassed a disabled but unfinished confirmed predecessor");

        var disabledCompleted = disabledConfirmed with { CompletionTurnId = successorId };
        Ensure(
            FollowUpQueuePlanner.FindDueScheduledThreadIds(
                new Dictionary<string, ThreadFollowUpSettings> { [scheduledThreadId] = disabledSettings },
                [disabledCompleted],
                DateTimeOffset.UtcNow).SequenceEqual([scheduledThreadId]),
            "a later schedule did not become eligible after the disabled predecessor completed");
        return Task.CompletedTask;
    }

    private static Task TestRuntimePresentationAsync()
    {
        var completion = CompletionMessage(0);
        var completionSettings = new ThreadFollowUpSettings
        {
            IsEnabled = true,
            CompletionAnchorTurnId = Guid.NewGuid().ToString("D"),
            Messages = [completion]
        };
        var scheduled = ScheduledMessage(0, DateTimeOffset.UtcNow.AddHours(2));
        var scheduledSettings = new ThreadFollowUpSettings
        {
            IsEnabled = true,
            Messages = [scheduled]
        };
        var none = new FollowUpQueueDecision(
            FollowUpQueueDecisionKind.None,
            null,
            "none");
        var ready = new FollowUpQueueDecision(
            FollowUpQueueDecisionKind.Ready,
            completion,
            "ready");
        var scheduledWaiting = new FollowUpQueueDecision(
            FollowUpQueueDecisionKind.Waiting,
            scheduled,
            "scheduled",
            scheduled.ScheduledAtUtc);

        var absent = FollowUpQueuePlanner.DescribeRuntime(null, none, []);
        var paused = FollowUpQueuePlanner.DescribeRuntime(
            completionSettings with { IsEnabled = false },
            none,
            []);
        var scheduledRuntime = FollowUpQueuePlanner.DescribeRuntime(
            scheduledSettings,
            scheduledWaiting,
            []);
        var readyRuntime = FollowUpQueuePlanner.DescribeRuntime(
            completionSettings,
            ready,
            []);
        var dispatching = FollowUpQueuePlanner.DescribeRuntime(
            completionSettings,
            ready,
            [Operation(completion, "turn-dispatching", FollowUpOperationState.Dispatching)]);
        var uncertain = FollowUpQueuePlanner.DescribeRuntime(
            completionSettings,
            ready,
            [Operation(completion, "turn-uncertain", FollowUpOperationState.Uncertain)]);
        var blocked = FollowUpQueuePlanner.DescribeRuntime(
            completionSettings,
            new FollowUpQueueDecision(FollowUpQueueDecisionKind.Blocked, completion, "blocked"),
            []);
        var exhausted = FollowUpQueuePlanner.DescribeRuntime(
            completionSettings,
            none,
            [Operation(
                completion,
                "turn-confirmed",
                FollowUpOperationState.Confirmed,
                Guid.NewGuid().ToString("D"))]);
        var individuallyDisabled = FollowUpQueuePlanner.DescribeRuntime(
            completionSettings with
            {
                Messages = [completion with { IsEnabled = false }]
            },
            none,
            []);

        Ensure(
            absent.Kind == FollowUpQueueRuntimeKind.None && absent.TotalMessageCount == 0 &&
            paused.Kind == FollowUpQueueRuntimeKind.Paused &&
            scheduledRuntime.Kind == FollowUpQueueRuntimeKind.Scheduled &&
            scheduledRuntime.NextScheduledAtUtc == scheduled.ScheduledAtUtc &&
            readyRuntime.Kind == FollowUpQueueRuntimeKind.Ready &&
            dispatching.Kind == FollowUpQueueRuntimeKind.Dispatching &&
            uncertain.Kind == FollowUpQueueRuntimeKind.Uncertain &&
            blocked.Kind == FollowUpQueueRuntimeKind.Blocked &&
            exhausted.Kind == FollowUpQueueRuntimeKind.Exhausted &&
            exhausted.ConfirmedMessageCount == 1 &&
            individuallyDisabled.Kind == FollowUpQueueRuntimeKind.Blocked,
            "the structured follow-up runtime presentation collapsed distinct queue states");
        return Task.CompletedTask;
    }

    private static Task TestErrorRetryLimitAsync()
    {
        Ensure(
            FollowUpRetryPolicy.DefaultMaximumErrorRetries == 500 &&
            FollowUpRetryPolicy.MaximumErrorRetriesLimit == 10_000 &&
            FollowUpRetryPolicy.GetEffectiveMaximumErrorRetries(null) == 500 &&
            FollowUpRetryPolicy.NormalizeMaximumErrorRetries(null) is null &&
            FollowUpRetryPolicy.NormalizeMaximumErrorRetries(-1) == 0 &&
            FollowUpRetryPolicy.NormalizeMaximumErrorRetries(10_001) == 10_000,
            "the persisted retry policy did not keep its blank default and fail-closed bounds");

        var item = new FollowUpMessageItem { Id = Guid.NewGuid().ToString("D") };
        Ensure(
            item.TryGetMaximumErrorRetries(out var blankRetries) &&
            blankRetries is null &&
            item.EffectiveMaximumErrorRetries == 500,
            "a blank editor retry value did not project to the effective default");
        item.MaximumErrorRetriesText = "0";
        Ensure(
            item.TryGetMaximumErrorRetries(out var zeroRetries) &&
            zeroRetries == 0 &&
            item.EffectiveMaximumErrorRetries == 0,
            "zero did not disable error retries explicitly");
        item.MaximumErrorRetriesText = "10001";
        Ensure(
            !item.TryGetMaximumErrorRetries(out _) &&
            !item.HasValidMaximumErrorRetries &&
            !string.IsNullOrWhiteSpace(
                ((System.ComponentModel.IDataErrorInfo)item)[nameof(item.MaximumErrorRetriesText)]),
            "an out-of-range editor retry value was accepted");
        item.MaximumErrorRetriesText = "-1";
        Ensure(
            !item.TryGetMaximumErrorRetries(out _),
            "a negative editor retry value was accepted");
        item.RetryIndefinitely = true;
        Ensure(
            item.TryGetMaximumErrorRetries(out var infiniteRetries) &&
            infiniteRetries is null &&
            item.HasValidMaximumErrorRetries &&
            !item.IsFiniteRetry,
            "the explicit infinite retry mode still depended on an integer sentinel");
        item.RetryIndefinitely = false;

        var currentTurn = NormalTurn(Guid.NewGuid().ToString("D"));
        var defaultMessage = CompletionMessage(0);
        var defaultSettings = new ThreadFollowUpSettings { Messages = [defaultMessage] };
        var defaultLastRetry = FollowUpQueuePlanner.Evaluate(
            defaultSettings,
            currentTurn,
            [Operation(
                defaultMessage,
                currentTurn.Id,
                FollowUpOperationState.Retryable,
                attemptCount: 500)],
            DateTimeOffset.UtcNow);
        var defaultExhausted = FollowUpQueuePlanner.Evaluate(
            defaultSettings,
            currentTurn,
            [Operation(
                defaultMessage,
                currentTurn.Id,
                FollowUpOperationState.Retryable,
                attemptCount: 501)],
            DateTimeOffset.UtcNow);
        Ensure(
            defaultLastRetry.Kind == FollowUpQueueDecisionKind.Ready &&
            defaultExhausted.Kind == FollowUpQueueDecisionKind.Blocked,
            "the blank 500-retry policy confused total attempts with post-error retries");

        var zeroMessage = defaultMessage with { MaximumErrorRetries = 0 };
        var zeroDecision = FollowUpQueuePlanner.Evaluate(
            new ThreadFollowUpSettings { Messages = [zeroMessage] },
            currentTurn,
            [Operation(
                zeroMessage,
                currentTurn.Id,
                FollowUpOperationState.Retryable,
                attemptCount: 1)],
            DateTimeOffset.UtcNow);
        var oneMessage = defaultMessage with { MaximumErrorRetries = 1 };
        var oneRetryReady = FollowUpQueuePlanner.Evaluate(
            new ThreadFollowUpSettings { Messages = [oneMessage] },
            currentTurn,
            [Operation(
                oneMessage,
                currentTurn.Id,
                FollowUpOperationState.Retryable,
                attemptCount: 1)],
            DateTimeOffset.UtcNow);
        var oneRetryExhausted = FollowUpQueuePlanner.Evaluate(
            new ThreadFollowUpSettings { Messages = [oneMessage] },
            currentTurn,
            [Operation(
                oneMessage,
                currentTurn.Id,
                FollowUpOperationState.Retryable,
                attemptCount: 2)],
            DateTimeOffset.UtcNow);
        Ensure(
            zeroDecision.Kind == FollowUpQueueDecisionKind.Blocked &&
            oneRetryReady.Kind == FollowUpQueueDecisionKind.Ready &&
            oneRetryExhausted.Kind == FollowUpQueueDecisionKind.Blocked,
            "the zero and one retry boundaries were not enforced exactly");

        var infiniteMessage = defaultMessage with
        {
            RetryIndefinitely = true,
            MaximumErrorRetries = null
        };
        var infiniteDecision = FollowUpQueuePlanner.Evaluate(
            new ThreadFollowUpSettings { Messages = [infiniteMessage] },
            currentTurn,
            [Operation(
                infiniteMessage,
                currentTurn.Id,
                FollowUpOperationState.Retryable,
                attemptCount: 1_000_000)],
            DateTimeOffset.UtcNow);
        Ensure(
            infiniteDecision.Kind == FollowUpQueueDecisionKind.Ready &&
            !FollowUpRetryPolicy.IsExhausted(infiniteMessage, int.MaxValue),
            "explicit infinite retry was collapsed into a finite or overflowing integer budget");

        var uncertain = FollowUpQueuePlanner.Evaluate(
            defaultSettings,
            currentTurn,
            [Operation(
                defaultMessage,
                currentTurn.Id,
                FollowUpOperationState.Uncertain,
                attemptCount: 9_999)],
            DateTimeOffset.UtcNow);
        Ensure(
            uncertain.Kind == FollowUpQueueDecisionKind.ReconcilePending &&
            uncertain.PendingOperation?.State == FollowUpOperationState.Uncertain,
            "an uncertain delivery was incorrectly converted into a configured retry");
        return Task.CompletedTask;
    }

    private static Task TestScheduledQueueAsync()
    {
        var threadId = Guid.NewGuid().ToString("D");
        var now = new DateTimeOffset(2026, 8, 4, 4, 0, 0, TimeSpan.Zero);
        var scheduled = ScheduledMessage(0, now.AddMinutes(30));
        var settings = new ThreadFollowUpSettings { Messages = [scheduled] };
        var current = NormalTurn(Guid.NewGuid().ToString("D"));

        var waiting = FollowUpQueuePlanner.Evaluate(settings, current, [], now);
        Ensure(
            waiting.Kind == FollowUpQueueDecisionKind.Waiting &&
            waiting.NextScheduledAtUtc == scheduled.ScheduledAtUtc,
            "the future schedule did not publish its exact UTC deadline");

        var byThread = new Dictionary<string, ThreadFollowUpSettings>(StringComparer.OrdinalIgnoreCase)
        {
            [threadId] = settings
        };
        Ensure(
            FollowUpQueuePlanner.FindNextScheduledAtUtc(byThread, []) == scheduled.ScheduledAtUtc,
            "the event loop did not select the first scheduled queue deadline");
        Ensure(
            FollowUpQueuePlanner.FindDueScheduledThreadIds(byThread, [], now).Count == 0 &&
            FollowUpQueuePlanner.FindDueScheduledThreadIds(
                byThread,
                [],
                scheduled.ScheduledAtUtc!.Value).SequenceEqual([threadId]),
            "scheduled wakeups were not bounded to the due thread");

        Ensure(
            FollowUpQueuePlanner.Evaluate(
                settings,
                TerminalTurn(current.Id, "interrupted"),
                [],
                scheduled.ScheduledAtUtc!.Value).Kind == FollowUpQueueDecisionKind.Waiting,
            "a due schedule bypassed abnormal-turn recovery priority");

        var completionFirst = new ThreadFollowUpSettings
        {
            CompletionAnchorTurnId = current.Id,
            Messages = [CompletionMessage(0), scheduled with { Order = 1 }]
        };
        var completionFirstMap = new Dictionary<string, ThreadFollowUpSettings>(
            StringComparer.OrdinalIgnoreCase)
        {
            [threadId] = completionFirst
        };
        Ensure(
            FollowUpQueuePlanner.FindNextScheduledAtUtc(completionFirstMap, []) is null &&
            FollowUpQueuePlanner.FindDueScheduledThreadIds(
                completionFirstMap,
                [],
                scheduled.ScheduledAtUtc.Value).Count == 0,
            "a later timed message bypassed the first unsent queue item");

        var secondScheduled = ScheduledMessage(1, scheduled.ScheduledAtUtc.Value);
        var scheduledFirst = new ThreadFollowUpSettings
        {
            Messages = [scheduled, secondScheduled]
        };
        var dueHead = FollowUpQueuePlanner.Evaluate(
            scheduledFirst,
            current,
            [],
            scheduled.ScheduledAtUtc.Value);
        Ensure(
            dueHead.Kind == FollowUpQueueDecisionKind.Ready &&
            string.Equals(dueHead.Message?.Id, scheduled.Id, StringComparison.OrdinalIgnoreCase),
            "the due scheduled queue head was not selected first");
        var scheduledSuccessorId = Guid.NewGuid().ToString("D");
        var confirmedHead = Operation(
            scheduled,
            current.Id,
            FollowUpOperationState.Confirmed,
            scheduledSuccessorId);
        Ensure(
            FollowUpQueuePlanner.Evaluate(
                scheduledFirst,
                TerminalTurn(scheduledSuccessorId, "inProgress"),
                [confirmedHead],
                scheduled.ScheduledAtUtc.Value).Kind == FollowUpQueueDecisionKind.Waiting &&
            FollowUpQueuePlanner.Evaluate(
                scheduledFirst,
                NormalTurn(scheduledSuccessorId),
                [confirmedHead],
                scheduled.ScheduledAtUtc.Value) is
            {
                Kind: FollowUpQueueDecisionKind.Ready,
                Message.Id: var secondScheduledId
            } &&
            string.Equals(secondScheduledId, secondScheduled.Id, StringComparison.OrdinalIgnoreCase),
            "a later scheduled item bypassed the running successor of the confirmed queue head");
        return Task.CompletedTask;
    }

    private static async Task TestDispatchSuccessAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            using var fixture = new FollowUpDispatchFixture(root);
            var successorTurnId = Guid.NewGuid().ToString("D");
            fixture.Desktop.StartResult = new DesktopStartTurnResult(successorTurnId);

            var result = await fixture.Service.ExecuteAsync(
                fixture.Thread,
                fixture.ExpectedTurn,
                fixture.Message,
                includeSubAgents: false,
                isDispatchAllowed: static () => true,
                CancellationToken.None);

            var operationId = FollowUpOperationJournal.CreateOperationId(
                fixture.Thread.Id,
                fixture.Message.Id,
                fixture.ExpectedTurn.Id);
            var stableClientMessageId = FollowUpOperationJournal.CreateClientMessageId(operationId);
            var snapshot = await fixture.Journal.ReadAsync();
            var operation = snapshot.Records.Single();
            Ensure(
                result.Success &&
                result.NewTurnId == successorTurnId &&
                fixture.Desktop.StartCount == 1 &&
                fixture.Desktop.StartThreadIds.Single() == fixture.Thread.Id &&
                fixture.Desktop.StartMessages.Single() == fixture.Message.Message &&
                fixture.Desktop.StartClientMessageIds.Single() == stableClientMessageId &&
                fixture.Desktop.LastGuard?.DisposeCount == 1 &&
                operation.OperationId == operationId &&
                operation.ClientMessageId == stableClientMessageId &&
                operation.State == FollowUpOperationState.Confirmed &&
                operation.NewTurnId == successorTurnId &&
                operation.AttemptCount == 1,
                "the successful follow-up did not bind one stable Desktop send to one confirmed journal record");
        });
    }

    private static async Task TestStructuredDispatchAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            var thread = RootThread(Guid.NewGuid().ToString("D"));
            var expectedTurn = NormalTurn(Guid.NewGuid().ToString("D"));
            var stateReader = new FakeFollowUpStateReader(thread, expectedTurn);
            var desktop = new FakeFollowUpDesktopChannel(thread, expectedTurn)
            {
                StartResult = new DesktopStartTurnResult(Guid.NewGuid().ToString("D"))
            };
            var owner = new FakeFollowUpOwnerActivator();
            var journal = new FollowUpOperationJournal(root);
            using var log = new GuardianLog(root);
            var store = new ManagedAttachmentStore(root);
            var pins = new AttachmentDraftAuthority();
            var presentation = new AttachmentPresentationLeaseService(root, store);
            var supported = CodexStructuredInputCapabilityInspector.Inspect(
                CreateStructuredSemanticSnapshot(epoch: 41));
            var capabilities = new SequenceStructuredCapabilityProvider(_ => supported);
            var service = new FollowUpDispatchService(
                stateReader,
                desktop,
                owner,
                journal,
                log,
                new SequenceFollowUpInterferenceGuard(
                    static _ => ClearInterference(),
                    static _ => ClearInterference()),
                capabilities,
                store,
                presentation,
                pins);
            var png = Convert.FromBase64String(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
            await using var source = new MemoryStream(png, writable: false);
            var managed = await store.ImportBytesAsync(
                source,
                "dispatch.png",
                new AttachmentLimitSettings(),
                CancellationToken.None);
            var attachment = new PresetAttachmentReference
            {
                Id = Guid.NewGuid().ToString("D"),
                ContentId = managed.ContentId,
                OriginalFileName = "dispatch.png",
                DetectedType = managed.DetectedType,
                OwnerInputKind = "local_image",
                ByteLength = managed.ByteLength,
                Order = 0
            };
            var message = CompletionMessage(0) with { Attachments = [attachment] };
            var payload = StructuredPresetPayload.Create(message.Message, message.Attachments);

            var result = await service.ExecuteAsync(
                thread,
                expectedTurn,
                message,
                includeSubAgents: false,
                isDispatchAllowed: static () => true,
                CancellationToken.None);
            var operation = (await journal.ReadAsync()).Records.Single();
            var expectedOperationId = FollowUpOperationJournal.CreateStructuredOperationId(
                thread.Id,
                message.Id,
                expectedTurn.Id,
                payload.PayloadDigest);
            Ensure(
                result.Success &&
                desktop.StructuredStartCount == 1 &&
                desktop.StartCount == 1 &&
                desktop.LastStructuredPayload?.PayloadDigest == payload.PayloadDigest &&
                desktop.LastStructuredCapabilityLease?.PayloadDigest == payload.PayloadDigest &&
                desktop.LastPresentationPaths is { Count: 1 } paths &&
                paths.Values.All(path =>
                    path.StartsWith(presentation.PresentationRoot, StringComparison.OrdinalIgnoreCase) &&
                    File.Exists(path)) &&
                capabilities.ReadCount == 3 &&
                operation.OperationId == expectedOperationId &&
                operation.SourceKind == FollowUpPayloadSourceKind.StructuredPreset &&
                operation.PayloadDigest == payload.PayloadDigest &&
                operation.AttachmentContentIds.SequenceEqual([managed.ContentId]) &&
                operation.PresentationLeaseId is { Length: 32 } &&
                operation.State == FollowUpOperationState.Confirmed &&
                operation.NewTurnId == desktop.StartResult.TurnId,
                "the structured follow-up did not retain one capability lease, presentation, journal identity, and owner send");

            var completedOperation = await journal.MarkCompletedAsync(
                thread.Id,
                desktop.StartResult.TurnId,
                recoveredFromTurnId: null,
                CancellationToken.None);
            var successfulCleanup = await presentation.CleanupAsync(
                operation.PresentationLeaseId!,
                new AttachmentPresentationCleanupAuthorization(
                    RecoveryLineageClosed: true,
                    ZeroReferenceProven: true),
                CancellationToken.None);
            Ensure(
                completedOperation?.CompletionTurnId == desktop.StartResult.TurnId &&
                successfulCleanup.Status == AttachmentPresentationCleanupStatus.Deleted,
                "a completed structured follow-up did not close its lineage before presentation cleanup");

            var driftRoot = Path.Combine(root, "capability-drift");
            var driftThread = RootThread(Guid.NewGuid().ToString("D"));
            var driftTurn = NormalTurn(Guid.NewGuid().ToString("D"));
            var driftStateReader = new FakeFollowUpStateReader(driftThread, driftTurn);
            var driftDesktop = new FakeFollowUpDesktopChannel(driftThread, driftTurn);
            var driftJournal = new FollowUpOperationJournal(driftRoot);
            using var driftLog = new GuardianLog(driftRoot);
            var driftStore = new ManagedAttachmentStore(driftRoot);
            var driftPins = new AttachmentDraftAuthority();
            var driftPresentation = new AttachmentPresentationLeaseService(driftRoot, driftStore);
            var driftProvider = new SequenceStructuredCapabilityProvider(read =>
                read == 1
                    ? CodexStructuredInputCapabilityInspector.Inspect(
                        CreateStructuredSemanticSnapshot(epoch: 51))
                    : CodexStructuredInputCapabilityInspector.Inspect(
                        CreateStructuredSemanticSnapshot(epoch: 52)));
            var driftService = new FollowUpDispatchService(
                driftStateReader,
                driftDesktop,
                new FakeFollowUpOwnerActivator(),
                driftJournal,
                driftLog,
                new SequenceFollowUpInterferenceGuard(
                    static _ => ClearInterference(),
                    static _ => ClearInterference()),
                driftProvider,
                driftStore,
                driftPresentation,
                driftPins);
            await using var driftSource = new MemoryStream(png, writable: false);
            var driftManaged = await driftStore.ImportBytesAsync(
                driftSource,
                "drift.png",
                new AttachmentLimitSettings(),
                CancellationToken.None);
            var driftMessage = CompletionMessage(0) with
            {
                Attachments =
                [
                    attachment with
                    {
                        Id = Guid.NewGuid().ToString("D"),
                        ContentId = driftManaged.ContentId,
                        OriginalFileName = "drift.png",
                        DetectedType = driftManaged.DetectedType,
                        ByteLength = driftManaged.ByteLength
                    }
                ]
            };
            var driftResult = await driftService.ExecuteAsync(
                driftThread,
                driftTurn,
                driftMessage,
                includeSubAgents: false,
                isDispatchAllowed: static () => true,
                CancellationToken.None);
            var driftOperation = (await driftJournal.ReadAsync()).Records.Single();
            Ensure(
                !driftResult.Success &&
                driftResult.FailureKind == FollowUpDispatchFailureKind.DesktopIncompatible &&
                driftDesktop.StructuredStartCount == 0 &&
                driftOperation.State == FollowUpOperationState.Prepared,
                "capability drift crossed the durable dispatch-intent or Desktop write boundary");

            var abandonedDrift = await driftJournal.TryTransitionAsync(
                driftOperation.OperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Abandoned,
                cancellationToken: CancellationToken.None);
            var driftCleanup = await driftPresentation.CleanupAsync(
                driftOperation.PresentationLeaseId!,
                new AttachmentPresentationCleanupAuthorization(
                    RecoveryLineageClosed: true,
                    ZeroReferenceProven: true),
                CancellationToken.None);
            Ensure(
                abandonedDrift.Changed &&
                abandonedDrift.Record?.State == FollowUpOperationState.Abandoned &&
                driftCleanup.Status == AttachmentPresentationCleanupStatus.Deleted,
                "a capability-drift operation did not close before presentation cleanup");
        });
    }

    private static async Task TestDispatchPreWriteGuardsAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            using (var policyDenied = new FollowUpDispatchFixture(Path.Combine(root, "policy-denied")))
            {
                var result = await policyDenied.Service.ExecuteAsync(
                    policyDenied.Thread,
                    policyDenied.ExpectedTurn,
                    policyDenied.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: static () => false,
                    CancellationToken.None);
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.PolicyChanged &&
                    policyDenied.Desktop.StartCount == 0 &&
                    (await policyDenied.Journal.ReadAsync()).ReadStatus == FollowUpJournalReadStatus.Missing,
                    "a revoked preset policy created a dispatch identity or reached the Desktop sender");
            }

            using (var policyRace = new FollowUpDispatchFixture(Path.Combine(root, "policy-race")))
            {
                var policyChecks = 0;
                var result = await policyRace.Service.ExecuteAsync(
                    policyRace.Thread,
                    policyRace.ExpectedTurn,
                    policyRace.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: () => Interlocked.Increment(ref policyChecks) <= 2,
                    CancellationToken.None);
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.PolicyChanged &&
                    policyChecks == 3 &&
                    policyRace.Desktop.StartCount == 0 &&
                    (await policyRace.Journal.ReadAsync()).Records.Single().State ==
                        FollowUpOperationState.Retryable,
                    "a policy change after durable dispatch intent was not returned to retryable before write");
            }

            var editingGuard = new SequenceFollowUpInterferenceGuard(
                static _ => ClearInterference(),
                static _ => EditingInterference());
            using (var editing = new FollowUpDispatchFixture(
                       Path.Combine(root, "second-editing"),
                       editingGuard))
            {
                var result = await editing.Service.ExecuteAsync(
                    editing.Thread,
                    editing.ExpectedTurn,
                    editing.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: static () => true,
                    CancellationToken.None);
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.UserActive &&
                    editingGuard.CheckCount == 2 &&
                    editing.Desktop.StartCount == 0 &&
                    (await editing.Journal.ReadAsync()).Records.Single().State ==
                        FollowUpOperationState.Retryable,
                    "editing detected after dispatch intent was not made retryable before Desktop write");
            }

            using var cancellation = new CancellationTokenSource();
            var cancellationGuard = new SequenceFollowUpInterferenceGuard(
                static _ => ClearInterference(),
                token =>
                {
                    cancellation.Cancel();
                    token.ThrowIfCancellationRequested();
                    return ClearInterference();
                });
            using (var cancelled = new FollowUpDispatchFixture(
                       Path.Combine(root, "caller-cancelled"),
                       cancellationGuard))
            {
                var result = await cancelled.Service.ExecuteAsync(
                    cancelled.Thread,
                    cancelled.ExpectedTurn,
                    cancelled.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: static () => true,
                    cancellation.Token);
                Ensure(
                    cancellation.IsCancellationRequested &&
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.PolicyChanged &&
                    cancellationGuard.CheckCount == 2 &&
                    cancelled.Desktop.StartCount == 0 &&
                    (await cancelled.Journal.ReadAsync()).Records.Single().State ==
                        FollowUpOperationState.Retryable,
                    "caller cancellation during the final editor check escaped without a durable retryable state");
            }
        });
    }

    private static async Task TestDispatchDeliveryClassificationsAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            using (var ownerRejected = new FollowUpDispatchFixture(Path.Combine(root, "owner-rejected")))
            {
                ownerRejected.Desktop.ProtocolException = new DesktopIpcProtocolException(
                    "no-client-found",
                    "owner missing",
                    DesktopIpcDeliveryStage.Rejected);
                var result = await ownerRejected.Service.ExecuteAsync(
                    ownerRejected.Thread,
                    ownerRejected.ExpectedTurn,
                    ownerRejected.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: static () => true,
                    CancellationToken.None);
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.DesktopOwnerUnavailable &&
                    ownerRejected.Desktop.StartCount == 0 &&
                    (await ownerRejected.Journal.ReadAsync()).Records.Single().State == FollowUpOperationState.Retryable,
                    "a no-client-found rejection was not kept retryable before any Desktop write");
            }

            using (var stateChanged = new FollowUpDispatchFixture(Path.Combine(root, "state-changed")))
            {
                stateChanged.Desktop.ProtocolException = new DesktopIpcProtocolException(
                    "guardian-state-changed",
                    "state changed",
                    DesktopIpcDeliveryStage.Rejected);
                var result = await stateChanged.Service.ExecuteAsync(
                    stateChanged.Thread,
                    stateChanged.ExpectedTurn,
                    stateChanged.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: static () => true,
                    CancellationToken.None);
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.StateChanged &&
                    (await stateChanged.Journal.ReadAsync()).Records.Single().State == FollowUpOperationState.Abandoned,
                    "a target state change was left retryable instead of permanently closed");
            }

            using (var incompatible = new FollowUpDispatchFixture(Path.Combine(root, "incompatible")))
            {
                incompatible.Desktop.ProtocolException = new DesktopIpcProtocolException(
                    "request-version-mismatch",
                    "version mismatch",
                    DesktopIpcDeliveryStage.Rejected);
                var result = await incompatible.Service.ExecuteAsync(
                    incompatible.Thread,
                    incompatible.ExpectedTurn,
                    incompatible.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: static () => true,
                    CancellationToken.None);
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.DesktopIncompatible &&
                    (await incompatible.Journal.ReadAsync()).Records.Single().State == FollowUpOperationState.Abandoned,
                    "a permanently incompatible Desktop protocol was not closed");
            }

            using (var unknown = new FollowUpDispatchFixture(Path.Combine(root, "unknown-delivery")))
            {
                unknown.Desktop.DeliveryException = new DesktopIpcDeliveryException(
                    DesktopIpcDeliveryStage.DispatchedUnknown,
                    "acknowledgement lost after write");
                var result = await unknown.Service.ExecuteAsync(
                    unknown.Thread,
                    unknown.ExpectedTurn,
                    unknown.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: static () => true,
                    CancellationToken.None);
                var operation = (await unknown.Journal.ReadAsync()).Records.Single();
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.Uncertain &&
                    operation.State == FollowUpOperationState.Uncertain &&
                    unknown.StateReader.ReconciledClientMessageIds.SequenceEqual([operation.ClientMessageId]) &&
                    unknown.Desktop.StartCount == 0,
                    "a dispatched-unknown Desktop failure was resent or downgraded to retryable");
            }

            using (var writeGate = new FollowUpDispatchFixture(Path.Combine(root, "write-gate")))
            {
                var policyAllowed = true;
                writeGate.Desktop.BeforeWritePredicate = () => policyAllowed = false;
                var result = await writeGate.Service.ExecuteAsync(
                    writeGate.Thread,
                    writeGate.ExpectedTurn,
                    writeGate.Message,
                    includeSubAgents: false,
                    isDispatchAllowed: () => policyAllowed,
                    CancellationToken.None);
                var operation = (await writeGate.Journal.ReadAsync()).Records.Single();
                Ensure(
                    !result.Success &&
                    result.FailureKind == FollowUpDispatchFailureKind.DesktopUnavailable &&
                    operation.State == FollowUpOperationState.Retryable &&
                    writeGate.Desktop.WritePredicateCount == 1 &&
                    writeGate.Desktop.PredicateObservedWhileWriteGateHeld &&
                    writeGate.Desktop.StartCount == 0,
                    "the exact write-gate predicate was not evaluated under the Desktop write gate");
            }
        });
    }

    private static async Task TestPendingReconciliationAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            var thread = RootThread(Guid.NewGuid().ToString("D"));
            var expectedTurn = NormalTurn(Guid.NewGuid().ToString("D"));
            var dispatchingMessage = CompletionMessage(0);
            var uncertainMessage = CompletionMessage(1);
            var dispatchingOperationId = FollowUpOperationJournal.CreateOperationId(
                thread.Id,
                dispatchingMessage.Id,
                expectedTurn.Id);
            var uncertainOperationId = FollowUpOperationJournal.CreateOperationId(
                thread.Id,
                uncertainMessage.Id,
                expectedTurn.Id);
            var dispatchingClientId = FollowUpOperationJournal.CreateClientMessageId(dispatchingOperationId);
            var uncertainClientId = FollowUpOperationJournal.CreateClientMessageId(uncertainOperationId);
            var journal = new FollowUpOperationJournal(root);
            await journal.GetOrCreateAsync(
                dispatchingOperationId,
                thread.Id,
                dispatchingMessage.Id,
                dispatchingMessage.Trigger,
                expectedTurn.Id,
                null,
                FollowUpOperationJournal.ComputeMessageHash(dispatchingMessage.Message),
                dispatchingClientId);
            await journal.TryTransitionAsync(
                dispatchingOperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            await journal.GetOrCreateAsync(
                uncertainOperationId,
                thread.Id,
                uncertainMessage.Id,
                uncertainMessage.Trigger,
                expectedTurn.Id,
                null,
                FollowUpOperationJournal.ComputeMessageHash(uncertainMessage.Message),
                uncertainClientId);
            await journal.TryTransitionAsync(
                uncertainOperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            await journal.TryTransitionAsync(
                uncertainOperationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Uncertain);

            var restartedJournal = new FollowUpOperationJournal(root);
            var restarted = await restartedJournal.ReadAsync();
            var stateReader = new FakeFollowUpStateReader(thread, expectedTurn);
            var matchedTurn = NormalTurn(Guid.NewGuid().ToString("D"));
            var recomputedDispatchingOperationId = FollowUpOperationJournal.CreateOperationId(
                thread.Id,
                dispatchingMessage.Id,
                expectedTurn.Id);
            var recomputedDispatchingClientId = FollowUpOperationJournal.CreateClientMessageId(
                recomputedDispatchingOperationId);
            Ensure(
                string.Equals(recomputedDispatchingOperationId, dispatchingOperationId, StringComparison.Ordinal) &&
                string.Equals(recomputedDispatchingClientId, dispatchingClientId, StringComparison.Ordinal),
                "restart reconciliation did not deterministically recompute the operation and client identities");
            stateReader.ReconciledTurns[recomputedDispatchingClientId] = matchedTurn;
            var desktop = new FakeFollowUpDesktopChannel(thread, expectedTurn);
            var owner = new FakeFollowUpOwnerActivator();
            using var log = new GuardianLog(root);
            var service = new FollowUpDispatchService(
                stateReader,
                desktop,
                owner,
                restartedJournal,
                log);

            var dispatchingResult = await service.ReconcilePendingAsync(
                thread,
                restarted.Records.Single(record => record.OperationId == dispatchingOperationId),
                CancellationToken.None);
            var uncertainResult = await service.ReconcilePendingAsync(
                thread,
                restarted.Records.Single(record => record.OperationId == uncertainOperationId),
                CancellationToken.None);
            var final = await restartedJournal.ReadAsync();
            Ensure(
                dispatchingResult.Success &&
                dispatchingResult.NewTurnId == matchedTurn.Id &&
                !uncertainResult.Success &&
                uncertainResult.FailureKind == FollowUpDispatchFailureKind.Uncertain &&
                desktop.StartCount == 0 &&
                stateReader.ReconciledClientMessageIds.SequenceEqual(
                    [recomputedDispatchingClientId, uncertainClientId],
                    StringComparer.OrdinalIgnoreCase) &&
                final.Records.Single(record => record.OperationId == dispatchingOperationId).State ==
                    FollowUpOperationState.Confirmed &&
                final.Records.Single(record => record.OperationId == uncertainOperationId).State ==
                    FollowUpOperationState.Uncertain,
                "restart reconciliation resent a pending operation or used anything other than its stable client id");
        });
    }

    private static async Task TestSettingsNormalizationAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            var service = new SettingsService(root);
            var threadId = Guid.NewGuid().ToString("D");
            var completionAnchor = Guid.NewGuid().ToString("D");
            var completionId = Guid.NewGuid().ToString("D");
            var scheduledId = Guid.NewGuid().ToString("D");
            var infiniteId = Guid.NewGuid().ToString("D");
            var scheduledAt = new DateTimeOffset(2026, 8, 4, 9, 45, 0, TimeSpan.FromHours(8));
            var settings = new AppSettings
            {
                MonitorOnly = true,
                ConversationOrder =
                [
                    " task-alpha ",
                    "TASK-ALPHA",
                    string.Empty,
                    new string('x', SettingsService.MaximumConversationIdLength + 1),
                    "task-beta"
                ],
                ThreadFollowUps = new(StringComparer.OrdinalIgnoreCase)
            };
            settings.ThreadFollowUps[threadId.ToUpperInvariant()] = new ThreadFollowUpSettings
            {
                CompletionAnchorTurnId = completionAnchor.ToUpperInvariant(),
                Messages =
                [
                    new FollowUpMessageDefinition
                    {
                        Id = completionId.ToUpperInvariant(),
                        Message = "  completion message  ",
                        Order = 7
                    },
                    new FollowUpMessageDefinition
                    {
                        Id = scheduledId,
                        Message = "scheduled message",
                        Trigger = FollowUpTriggerKind.ScheduledAt,
                        ScheduledAtUtc = scheduledAt,
                        MaximumErrorRetries = 20_000,
                        Order = 1
                    },
                    new FollowUpMessageDefinition
                    {
                        Id = completionId,
                        Message = "duplicate",
                        Order = 9
                    },
                    new FollowUpMessageDefinition
                    {
                        Id = infiniteId,
                        Message = "infinite retries",
                        RetryIndefinitely = true,
                        MaximumErrorRetries = 42,
                        Order = 8
                    },
                    new FollowUpMessageDefinition
                    {
                        Id = Guid.NewGuid().ToString("D"),
                        Message = "missing schedule",
                        Trigger = FollowUpTriggerKind.ScheduledAt,
                        Order = 10
                    }
                ]
            };
            settings.ThreadFollowUps["not-a-task-id"] = new ThreadFollowUpSettings
            {
                Messages = [CompletionMessage(0)]
            };

            await service.SaveAsync(settings);
            var loaded = await new SettingsService(root).LoadAsync();
            Ensure(loaded.MonitorOnly, "settings normalization kept automatic recovery fail-closed");
            Ensure(
                loaded.ConversationOrder.SequenceEqual(
                    ["task-alpha", "task-beta"],
                    StringComparer.OrdinalIgnoreCase),
                "conversation order trimming, duplicate removal, or identity bounds drifted");
            Ensure(loaded.ThreadFollowUps.Count == 1, "invalid task identities were retained");
            Ensure(
                loaded.ThreadFollowUps.TryGetValue(threadId, out var configured) &&
                configured.CompletionAnchorTurnId == completionAnchor &&
                configured.Messages.Count == 3,
                "the valid task queue did not round-trip");
            Ensure(
                configured!.Messages[0].Id == scheduledId &&
                configured.Messages[0].Order == 0 &&
                configured.Messages[0].ScheduledAtUtc == scheduledAt.ToUniversalTime() &&
                configured.Messages[0].MaximumErrorRetries ==
                    FollowUpRetryPolicy.MaximumErrorRetriesLimit &&
                configured.Messages[1].Id == completionId &&
                configured.Messages[1].Order == 1 &&
                configured.Messages[1].Message == "completion message" &&
                configured.Messages[1].MaximumErrorRetries is null &&
                configured.Messages[2].Id == infiniteId &&
                configured.Messages[2].Order == 2 &&
                configured.Messages[2].RetryIndefinitely &&
                configured.Messages[2].MaximumErrorRetries is null,
                "queue order, retry bounds, trimming, duplicate removal, or UTC normalization drifted");
        });
    }

    private static Task TestSettingsLimitsAsync()
    {
        Ensure(
            SettingsService.MaximumFollowUpMessageLength == 4000 &&
            SettingsService.MaximumFollowUpMessagesPerThread == 64 &&
            SettingsService.MaximumFollowUpThreadCount == 500 &&
            SettingsService.MaximumTotalFollowUpMessages == 2048 &&
            SettingsService.MaximumConversationOrderCount == 500 &&
            SettingsService.MaximumConversationIdLength == 128 &&
            FollowUpRetryPolicy.DefaultMaximumErrorRetries == 500 &&
            FollowUpRetryPolicy.MaximumErrorRetriesLimit == 10_000,
            "the documented follow-up settings bounds drifted");

        Ensure(
            SettingsService.NormalizeConversationOrder(
                    Enumerable.Range(0, 501).Select(index => $"task-{index}"))
                .Count == 500,
            "501 conversation order entries crossed the persisted order bound");

        var perTaskId = Guid.NewGuid().ToString("D");
        var perTaskSource = new Dictionary<string, ThreadFollowUpSettings>(StringComparer.OrdinalIgnoreCase)
        {
            [perTaskId] = new ThreadFollowUpSettings
            {
                Messages = Enumerable.Range(0, 65)
                    .Select(index => new FollowUpMessageDefinition
                    {
                        Id = Guid.NewGuid().ToString("D"),
                        Message = index == 0 ? new string('x', 4001) : $"bounded-{index}",
                        Order = index
                    })
                    .ToArray()
            }
        };
        var perTask = SettingsService.NormalizeThreadFollowUps(perTaskSource)[perTaskId];
        Ensure(
            perTask.Messages.Count == 64 &&
            perTask.Messages[0].Message.Length == 4000,
            "65 messages or a 4001-character message crossed the per-task settings bounds");

        var taskBoundSource = Enumerable.Range(0, 501)
            .ToDictionary(
                _ => Guid.NewGuid().ToString("D"),
                index => new ThreadFollowUpSettings { Messages = [CompletionMessage(index)] },
                StringComparer.OrdinalIgnoreCase);
        Ensure(
            SettingsService.NormalizeThreadFollowUps(taskBoundSource).Count == 500,
            "501 configured tasks crossed the persisted task-count bound");

        var totalBoundSource = Enumerable.Range(0, 33)
            .ToDictionary(
                _ => Guid.NewGuid().ToString("D"),
                _ => new ThreadFollowUpSettings
                {
                    Messages = Enumerable.Range(0, 64)
                        .Select(CompletionMessage)
                        .ToArray()
                },
                StringComparer.OrdinalIgnoreCase);
        var totalBound = SettingsService.NormalizeThreadFollowUps(totalBoundSource);
        Ensure(
            totalBound.Sum(pair => pair.Value.Messages.Count) == 2048,
            "the global follow-up message bound was not enforced exactly");
        return Task.CompletedTask;
    }

    private static async Task TestJournalAtMostOnceAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            var threadId = Guid.NewGuid().ToString("D");
            var message = CompletionMessage(0);
            var expectedTurnId = Guid.NewGuid().ToString("D");
            var successorTurnId = Guid.NewGuid().ToString("D");
            const string secretMessage = "message text must never enter the operation journal";
            var messageHash = FollowUpOperationJournal.ComputeMessageHash(secretMessage);
            var operationId = FollowUpOperationJournal.CreateOperationId(
                threadId,
                message.Id,
                expectedTurnId);
            var clientMessageId = FollowUpOperationJournal.CreateClientMessageId(operationId);
            var journal = new FollowUpOperationJournal(root);

            Ensure(
                operationId == FollowUpOperationJournal.CreateOperationId(
                    threadId,
                    message.Id,
                    expectedTurnId) &&
                clientMessageId == FollowUpOperationJournal.CreateClientMessageId(operationId),
                "deterministic follow-up identities changed between identical computations");

            Ensure(
                (await journal.ReadAsync()).ReadStatus == FollowUpJournalReadStatus.Missing,
                "a fresh journal was not missing");
            var prepared = await journal.GetOrCreateAsync(
                operationId,
                threadId,
                message.Id,
                message.Trigger,
                expectedTurnId,
                null,
                messageHash,
                clientMessageId);
            Ensure(
                prepared.Created &&
                prepared.Record.State == FollowUpOperationState.Prepared &&
                prepared.Record.ClientMessageId == clientMessageId,
                "the first durable operation was not prepared with its stable identity");
            Ensure(
                !File.ReadAllText(journal.JournalPath, Encoding.UTF8).Contains(
                    secretMessage,
                    StringComparison.Ordinal),
                "the operation journal persisted message content");

            var restartedPrepared = await new FollowUpOperationJournal(root).ReadAsync();
            Ensure(
                restartedPrepared.ReadStatus == FollowUpJournalReadStatus.Healthy &&
                restartedPrepared.Records.Single().State == FollowUpOperationState.Prepared &&
                restartedPrepared.Records.Single().OperationId == operationId &&
                restartedPrepared.Records.Single().ClientMessageId == clientMessageId,
                "a prepared operation or its stable identity did not survive restart");

            var dispatching = await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            Ensure(
                dispatching.Changed &&
                dispatching.Record?.AttemptCount == 1,
                "dispatch intent was not durably counted");
            var restartedDispatching = await new FollowUpOperationJournal(root).ReadAsync();
            Ensure(
                restartedDispatching.Records.Single().State == FollowUpOperationState.Dispatching,
                "a restart lost the ambiguous dispatch intent");

            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Uncertain);
            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Uncertain,
                FollowUpOperationState.Confirmed,
                successorTurnId);
            var completion = await journal.MarkCompletedAsync(
                threadId,
                successorTurnId,
                recoveredFromTurnId: null);
            Ensure(
                completion?.State == FollowUpOperationState.Confirmed &&
                completion.NewTurnId == successorTurnId &&
                completion.CompletionTurnId == successorTurnId,
                "confirmed delivery and successor completion were not bound together");

            var duplicate = await journal.GetOrCreateAsync(
                operationId,
                threadId,
                message.Id,
                message.Trigger,
                expectedTurnId,
                null,
                messageHash,
                clientMessageId);
            Ensure(
                !duplicate.Created &&
                duplicate.Record.State == FollowUpOperationState.Confirmed,
                "the same completion created a second delivery identity");
            Ensure(
                await ThrowsAsync<InvalidOperationException>(() => journal.GetOrCreateAsync(
                    operationId,
                    threadId,
                    message.Id,
                    message.Trigger,
                    expectedTurnId,
                    null,
                    FollowUpOperationJournal.ComputeMessageHash("changed content"),
                    clientMessageId)),
                "mutable content was accepted under an existing operation identity");
        });
    }

    private static async Task TestJournalSemanticRevisionAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            var revisionRoot = Path.Combine(root, "revision");
            var journal = new FollowUpOperationJournal(revisionRoot);
            var threadId = Guid.NewGuid().ToString("D");
            var messageId = Guid.NewGuid().ToString("D");
            var expectedTurnId = Guid.NewGuid().ToString("D");
            var operationId = FollowUpOperationJournal.CreateOperationId(threadId, messageId, expectedTurnId);
            var clientMessageId = FollowUpOperationJournal.CreateClientMessageId(operationId);
            var first = await journal.GetOrCreateAsync(
                operationId,
                threadId,
                messageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                expectedTurnId,
                null,
                FollowUpOperationJournal.ComputeMessageHash("revision-one"),
                clientMessageId);
            var scheduledAt = DateTimeOffset.UtcNow.AddHours(1);
            var revised = await journal.GetOrCreateAsync(
                operationId,
                threadId,
                messageId,
                FollowUpTriggerKind.ScheduledAt,
                expectedTurnId,
                scheduledAt,
                FollowUpOperationJournal.ComputeMessageHash("revision-two"),
                clientMessageId);
            Ensure(
                revised.Created &&
                revised.Record.OperationId == first.Record.OperationId &&
                revised.Record.ClientMessageId == first.Record.ClientMessageId &&
                revised.Record.State == FollowUpOperationState.Prepared &&
                revised.Record.Trigger == FollowUpTriggerKind.ScheduledAt &&
                revised.Record.ScheduledAtUtc == scheduledAt.ToUniversalTime() &&
                revised.Record.AttemptCount == 0 &&
                revised.Record.NewTurnId is null &&
                revised.Record.CompletionTurnId is null,
                "a never-dispatched configuration revision did not atomically reset its safe journal record");

            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Retryable);
            var retryableRevision = await journal.GetOrCreateAsync(
                operationId,
                threadId,
                messageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                expectedTurnId,
                null,
                FollowUpOperationJournal.ComputeMessageHash("revision-three"),
                clientMessageId);
            Ensure(
                retryableRevision.Created &&
                retryableRevision.Record.State == FollowUpOperationState.Prepared &&
                retryableRevision.Record.AttemptCount == 0,
                "a definitely-unsent retryable operation did not accept one atomic semantic revision");

            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Uncertain);
            Ensure(
                await ThrowsAsync<InvalidOperationException>(() => journal.GetOrCreateAsync(
                    operationId,
                    threadId,
                    messageId,
                    FollowUpTriggerKind.AfterNormalCompletion,
                    expectedTurnId,
                    null,
                    FollowUpOperationJournal.ComputeMessageHash("forbidden-uncertain-revision"),
                    clientMessageId)),
                "an uncertain operation accepted mutable configuration semantics");
            var successorTurnId = Guid.NewGuid().ToString("D");
            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Uncertain,
                FollowUpOperationState.Confirmed,
                successorTurnId);
            Ensure(
                await ThrowsAsync<InvalidOperationException>(() => journal.GetOrCreateAsync(
                    operationId,
                    threadId,
                    messageId,
                    FollowUpTriggerKind.AfterNormalCompletion,
                    expectedTurnId,
                    null,
                    FollowUpOperationJournal.ComputeMessageHash("forbidden-confirmed-revision"),
                    clientMessageId)),
                "a confirmed operation accepted mutable configuration semantics");

            var crossRoot = Path.Combine(root, "cross-turn");
            var crossJournal = new FollowUpOperationJournal(crossRoot);
            var crossThreadId = Guid.NewGuid().ToString("D");
            var crossMessageId = Guid.NewGuid().ToString("D");
            var oldExpectedTurnId = Guid.NewGuid().ToString("D");
            var oldOperationId = FollowUpOperationJournal.CreateOperationId(
                crossThreadId,
                crossMessageId,
                oldExpectedTurnId);
            await crossJournal.GetOrCreateAsync(
                oldOperationId,
                crossThreadId,
                crossMessageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                oldExpectedTurnId,
                null,
                FollowUpOperationJournal.ComputeMessageHash("cross-turn"),
                FollowUpOperationJournal.CreateClientMessageId(oldOperationId));
            var nextExpectedTurnId = Guid.NewGuid().ToString("D");
            var nextOperationId = FollowUpOperationJournal.CreateOperationId(
                crossThreadId,
                crossMessageId,
                nextExpectedTurnId);
            var next = await crossJournal.GetOrCreateAsync(
                nextOperationId,
                crossThreadId,
                crossMessageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                nextExpectedTurnId,
                null,
                FollowUpOperationJournal.ComputeMessageHash("cross-turn"),
                FollowUpOperationJournal.CreateClientMessageId(nextOperationId));
            var crossSnapshot = await crossJournal.ReadAsync();
            Ensure(
                next.Created &&
                next.Record.State == FollowUpOperationState.Prepared &&
                crossSnapshot.Records.Single(record => record.OperationId == oldOperationId).State ==
                    FollowUpOperationState.Abandoned,
                "a newer expected turn did not atomically replace an unsent prepared operation");

            await crossJournal.TryTransitionAsync(
                nextOperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            await crossJournal.TryTransitionAsync(
                nextOperationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Retryable);
            var thirdExpectedTurnId = Guid.NewGuid().ToString("D");
            var thirdOperationId = FollowUpOperationJournal.CreateOperationId(
                crossThreadId,
                crossMessageId,
                thirdExpectedTurnId);
            var third = await crossJournal.GetOrCreateAsync(
                thirdOperationId,
                crossThreadId,
                crossMessageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                thirdExpectedTurnId,
                null,
                FollowUpOperationJournal.ComputeMessageHash("cross-turn"),
                FollowUpOperationJournal.CreateClientMessageId(thirdOperationId));
            Ensure(
                third.Created &&
                third.Record.State == FollowUpOperationState.Prepared &&
                (await crossJournal.ReadAsync()).Records.Single(record => record.OperationId == nextOperationId).State ==
                    FollowUpOperationState.Abandoned,
                "a newer expected turn did not atomically replace a definitely-unsent retryable operation");

            await crossJournal.TryTransitionAsync(
                thirdOperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            await crossJournal.TryTransitionAsync(
                thirdOperationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Uncertain);
            var blockedExpectedTurnId = Guid.NewGuid().ToString("D");
            var blockedOperationId = FollowUpOperationJournal.CreateOperationId(
                crossThreadId,
                crossMessageId,
                blockedExpectedTurnId);
            Ensure(
                await ThrowsAsync<InvalidOperationException>(() => crossJournal.GetOrCreateAsync(
                    blockedOperationId,
                    crossThreadId,
                    crossMessageId,
                    FollowUpTriggerKind.AfterNormalCompletion,
                    blockedExpectedTurnId,
                    null,
                    FollowUpOperationJournal.ComputeMessageHash("cross-turn"),
                    FollowUpOperationJournal.CreateClientMessageId(blockedOperationId))),
                "an uncertain operation was bypassed by creating the same message for a newer expected turn");
        });
    }

    private static async Task TestJournalBackupRecoveryAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            var threadId = Guid.NewGuid().ToString("D");
            var message = CompletionMessage(0);
            var expectedTurnId = Guid.NewGuid().ToString("D");
            var operationId = FollowUpOperationJournal.CreateOperationId(
                threadId,
                message.Id,
                expectedTurnId);
            var clientMessageId = FollowUpOperationJournal.CreateClientMessageId(operationId);
            var journal = new FollowUpOperationJournal(root);
            await journal.GetOrCreateAsync(
                operationId,
                threadId,
                message.Id,
                message.Trigger,
                expectedTurnId,
                null,
                FollowUpOperationJournal.ComputeMessageHash(message.Message),
                clientMessageId);
            await journal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching);
            Ensure(File.Exists(journal.BackupPath), "the previous journal generation was not retained");

            File.WriteAllText(journal.JournalPath, "{broken", new UTF8Encoding(false));
            var recovered = await new FollowUpOperationJournal(root).ReadAsync();
            var recoveredRecord = recovered.Records.Single();
            Ensure(
                recovered.ReadStatus == FollowUpJournalReadStatus.RecoveredFromBackup &&
                recoveredRecord.State == FollowUpOperationState.Uncertain &&
                recoveredRecord.OperationId == operationId &&
                recoveredRecord.ClientMessageId == clientMessageId &&
                recoveredRecord.MessageHash == FollowUpOperationJournal.ComputeMessageHash(message.Message),
                "backup recovery did not conservatively promote the prior prepared operation");
            Ensure(
                !Directory.EnumerateFiles(root, "*.tmp", SearchOption.TopDirectoryOnly).Any(),
                "journal recovery left an unbounded temporary file");
        });
    }

    private static async Task TestJournalPruningAndCapacityAsync()
    {
        await WithIsolatedRootAsync(async root =>
        {
            var pruneJournal = new FollowUpOperationJournal(Path.Combine(root, "prune"));
            var abandonedThreadId = Guid.NewGuid().ToString("D");
            var abandonedMessage = CompletionMessage(0);
            var abandonedTurnId = Guid.NewGuid().ToString("D");
            var abandonedOperationId = FollowUpOperationJournal.CreateOperationId(
                abandonedThreadId,
                abandonedMessage.Id,
                abandonedTurnId);
            await pruneJournal.GetOrCreateAsync(
                abandonedOperationId,
                abandonedThreadId,
                abandonedMessage.Id,
                abandonedMessage.Trigger,
                abandonedTurnId,
                null,
                FollowUpOperationJournal.ComputeMessageHash(abandonedMessage.Message),
                FollowUpOperationJournal.CreateClientMessageId(abandonedOperationId));
            await pruneJournal.TryTransitionAsync(
                abandonedOperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Abandoned);

            var inactiveThreadId = Guid.NewGuid().ToString("D");
            var inactiveMessage = CompletionMessage(0);
            var inactiveOperation = await CreateConfirmedOperationAsync(
                pruneJournal,
                inactiveThreadId,
                inactiveMessage,
                markCompleted: true);
            var activeThreadId = Guid.NewGuid().ToString("D");
            var activeMessage = CompletionMessage(0) with { IsEnabled = false };
            var activeOperation = await CreateConfirmedOperationAsync(
                pruneJournal,
                activeThreadId,
                activeMessage,
                markCompleted: true);
            var unfinishedThreadId = Guid.NewGuid().ToString("D");
            var unfinishedMessage = CompletionMessage(0);
            var unfinishedOperation = await CreateConfirmedOperationAsync(
                pruneJournal,
                unfinishedThreadId,
                unfinishedMessage,
                markCompleted: false);
            var configured = new Dictionary<string, ThreadFollowUpSettings>(StringComparer.OrdinalIgnoreCase)
            {
                [activeThreadId] = new ThreadFollowUpSettings
                {
                    IsEnabled = false,
                    Messages = [activeMessage]
                }
            };
            var removed = await pruneJournal.PruneInactiveCompletedAsync(configured);
            var pruned = await pruneJournal.ReadAsync();
            Ensure(
                removed == 2 &&
                !pruned.Records.Any(record => record.OperationId == abandonedOperationId) &&
                !pruned.Records.Any(record => record.OperationId == inactiveOperation.OperationId) &&
                pruned.Records.Any(record => record.OperationId == activeOperation.OperationId) &&
                pruned.Records.Any(record => record.OperationId == unfinishedOperation.OperationId),
                "pruning removed an active/unfinished confirmation or retained an abandoned/inactive completion");

            var capacityJournal = new FollowUpOperationJournal(
                Path.Combine(root, "capacity"),
                maximumRecords: 2);
            var capacityAbandoned = await PrepareUniqueOperationAsync(capacityJournal, "capacity-abandoned");
            await capacityJournal.TryTransitionAsync(
                capacityAbandoned.OperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Abandoned);
            var retainedOne = await PrepareUniqueOperationAsync(capacityJournal, "capacity-one");
            var retainedTwo = await PrepareUniqueOperationAsync(capacityJournal, "capacity-two");
            var capacitySnapshot = await capacityJournal.ReadAsync();
            Ensure(
                capacitySnapshot.Records.Count == 2 &&
                !capacitySnapshot.Records.Any(record => record.OperationId == capacityAbandoned.OperationId) &&
                capacitySnapshot.Records.Any(record => record.OperationId == retainedOne.OperationId) &&
                capacitySnapshot.Records.Any(record => record.OperationId == retainedTwo.OperationId),
                "capacity pruning did not remove only the oldest abandoned operation");
            Ensure(
                await ThrowsAsync<InvalidOperationException>(() =>
                    PrepareUniqueOperationAsync(capacityJournal, "capacity-overflow")),
                "journal capacity silently discarded a non-terminal operation");
            Ensure(
                (await capacityJournal.ReadAsync()).Records.Count == 2,
                "a rejected capacity write changed the committed journal generation");
        });
    }

    private static async Task TestAttachmentSaveCommandCapabilityGateAsync()
    {
        await RunOnStaDispatcherAsync(() => WithIsolatedRootAsync(async root =>
        {
            var threadId = Guid.NewGuid().ToString("D");
            var turnId = Guid.NewGuid().ToString("D");
            var messageId = Guid.NewGuid().ToString("D");
            const string savedMessage = "Review the completed turn.";
            var settings = new AppSettings
            {
                UiLanguage = UiLanguages.English,
                MonitoringEnabled = false,
                MonitorOnly = true,
                MinimizeToTray = false,
                StartWithWindows = false
            };
            settings.ThreadFollowUps[threadId] = new ThreadFollowUpSettings
            {
                IsEnabled = true,
                CompletionAnchorTurnId = turnId,
                Messages =
                [
                    new FollowUpMessageDefinition
                    {
                        Id = messageId,
                        Message = savedMessage,
                        Attachments =
                        [
                            new PresetAttachmentReference
                            {
                                Id = Guid.NewGuid().ToString("D"),
                                ContentId = new string('A', 64),
                                OriginalFileName = "reference.png",
                                DetectedType = "image/png",
                                OwnerInputKind = "local_image",
                                ByteLength = 2048,
                                Order = 0
                            },
                            new PresetAttachmentReference
                            {
                                Id = Guid.NewGuid().ToString("D"),
                                ContentId = new string('B', 64),
                                OriginalFileName = "notes.txt",
                                DetectedType = "text/plain",
                                OwnerInputKind = "local_file",
                                ByteLength = 1024,
                                Order = 1
                            }
                        ],
                        Trigger = FollowUpTriggerKind.AfterNormalCompletion,
                        IsEnabled = true,
                        Order = 0
                    }
                ]
            };

            var settingsService = new SettingsService(root);
            using var log = new GuardianLog(root);
            var appServer = new AppServerClient(new CodexCliLocator(), log);
            var desktop = new DesktopIpcClient(log);
            var classifier = new RecoveryClassifier();
            var recovery = new RecoveryService(
                appServer,
                desktop,
                new DesktopThreadOwnerActivator(desktop, log),
                new RecoveryOperationJournal(root),
                log);
            var engine = new GuardianEngine(
                settings,
                appServer,
                desktop,
                recovery,
                classifier,
                new LocalConversationHistoryReader(Path.Combine(root, "preview-sessions")),
                log,
                null,
                null,
                previewIsolationMode: true);
            var supported = CodexStructuredInputCapabilityInspector.Inspect(
                CreateStructuredSemanticSnapshot(epoch: 61));
            var capabilities = new SequenceStructuredCapabilityProvider(_ => supported);
            var attachments = new FollowUpAttachmentRuntime(
                root,
                settingsService,
                followUpJournal: null,
                recoveryJournal: null,
                structuredCapabilities: capabilities);
            var workflowRules = new WorkflowRuleStore(root);
            var localization = new LocalizationService(UiLanguages.English);
            await using var viewModel = new MainViewModel(
                settings,
                settingsService,
                new StartupService(),
                log,
                engine,
                appServer,
                desktop,
                classifier,
                localization,
                enhancedObservationStatus: null,
                previewIsolationMode: false,
                attachmentComposition: attachments.Composition,
                attachmentDraftAuthority: attachments.DraftAuthority,
                conversationMutations: null,
                workflowRuleStore: workflowRules,
                workflowRuleSnapshot: null,
                workflowAutomationHost: null);
            var task = new GuardianTaskItem
            {
                Id = threadId,
                Name = "Attachment Save gate",
                Preview = "Offline capability fixture",
                Cwd = root,
                RawSource = "offline",
                CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-2),
                UpdatedAt = DateTimeOffset.UtcNow,
                LatestTurnId = turnId,
                CompletionAnchorTurnId = turnId,
                CanArmCompletionFollowUps = true
            };
            viewModel.Tasks.Add(task);
            viewModel.SelectedTask = task;
            viewModel.OpenFollowUpEditorCommand.Execute(task);

            Ensure(
                viewModel.FollowUpMessages.Count == 1 &&
                viewModel.FollowUpMessages[0].Attachments.Count == 2 &&
                !File.Exists(settingsService.SettingsPath) &&
                !File.Exists(workflowRules.RulePath),
                "the isolated ViewModel fixture was not clean before Save");
            var settingsGeneration = settings.SettingsGeneration;
            FollowUpMessageItem? focusedItem = null;
            viewModel.FollowUpMessageFocusRequested += (item, _) => focusedItem = item;
            var draft = viewModel.FollowUpMessages[0];
            draft.Message = savedMessage + " Unsaved edit.";
            Ensure(
                viewModel.HasUnsavedFollowUpChanges &&
                viewModel.SaveFollowUpMessagesCommand.CanExecute(null),
                "the attachment Save fixture did not produce an executable dirty draft");

            await ExecuteCommandAndWaitAsync(viewModel.SaveFollowUpMessagesCommand);

            Ensure(
                capabilities.ReadCount == 1 &&
                viewModel.HasUnsavedFollowUpChanges &&
                ReferenceEquals(viewModel.SelectedFollowUpMessage, draft) &&
                ReferenceEquals(focusedItem, draft) &&
                draft.IsEditing &&
                string.Equals(
                    viewModel.FollowUpEditorStatus,
                    localization.Format("FollowUp.AttachmentCapabilityUnsupported", 1),
                    StringComparison.Ordinal) &&
                settings.SettingsGeneration == settingsGeneration &&
                settings.ThreadFollowUps[threadId].Messages.Single().Message == savedMessage &&
                !File.Exists(settingsService.SettingsPath) &&
                !File.Exists(workflowRules.RulePath) &&
                !engine.IsRunning &&
                appServer.ProcessStartCount == 0 &&
                appServer.RequestCount == 0 &&
                !desktop.IsConnected,
                "an unsupported local_file Save changed durable state, lost the draft, or crossed a live boundary");
        }));
    }

    private static async Task TestPreviewFixtureIsolationAsync()
    {
        const string previewData =
            @"D:\CodexData\CodexGuardian\r13-follow-up-preview-offline-test\preview-data";
        var launch = GuardianLaunchOptions.Parse(
        [
            "--safe-preview",
            "--follow-up-preview-fixture",
            "--data-directory",
            previewData
        ]);
        Ensure(
            launch.SafePreview &&
            launch.FollowUpPreviewFixture &&
            !launch.Background &&
            !launch.AllowsLiveIntegration &&
            string.Equals(launch.DataDirectory, previewData, StringComparison.OrdinalIgnoreCase),
            "the accepted follow-up preview launch contract was not normalized correctly");

        const string sharedSingleInstance = "Local\\CodexGuardian.SingleInstance";
        const string sharedReleaseExchange = "Local\\CodexGuardian.ReleaseExchange";
        var caseVariantLaunch = GuardianLaunchOptions.Parse(
        [
            "--safe-preview",
            "--data-directory",
            previewData.ToUpperInvariant()
        ]);
        var separatePreviewLaunch = GuardianLaunchOptions.Parse(
        [
            "--safe-preview",
            "--data-directory",
            previewData + "-other"
        ]);
        var productionLaunch = GuardianLaunchOptions.Parse([]);
        var isolatedSingleInstance = launch.ResolveStartupMutexName(sharedSingleInstance);
        var isolatedReleaseExchange = launch.ResolveStartupMutexName(sharedReleaseExchange);
        Ensure(
            isolatedSingleInstance.StartsWith(
                sharedSingleInstance + ".SafePreview.",
                StringComparison.Ordinal) &&
            isolatedReleaseExchange.StartsWith(
                sharedReleaseExchange + ".SafePreview.",
                StringComparison.Ordinal) &&
            string.Equals(
                isolatedSingleInstance,
                caseVariantLaunch.ResolveStartupMutexName(sharedSingleInstance),
                StringComparison.Ordinal) &&
            !string.Equals(
                isolatedSingleInstance,
                separatePreviewLaunch.ResolveStartupMutexName(sharedSingleInstance),
                StringComparison.Ordinal) &&
            string.Equals(
                productionLaunch.ResolveStartupMutexName(sharedSingleInstance),
                sharedSingleInstance,
                StringComparison.Ordinal) &&
            string.Equals(
                productionLaunch.ResolveStartupMutexName(sharedReleaseExchange),
                sharedReleaseExchange,
                StringComparison.Ordinal) &&
            !isolatedSingleInstance.Contains(previewData, StringComparison.OrdinalIgnoreCase) &&
            !isolatedReleaseExchange.Contains(previewData, StringComparison.OrdinalIgnoreCase),
            "safe previews did not isolate startup ownership by normalized data root while preserving production mutex names");

        Ensure(
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(
                ["--follow-up-preview-fixture", "--data-directory", previewData])) &&
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(["--safe-preview"])) &&
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(
                ["--safe-preview", "--data-directory", @"C:\preview-data"])) &&
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(
                ["--safe-preview", "--data-directory", @"D:\CodexData\CodexGuardian"])) &&
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(
                ["--safe-preview", "--data-directory", "relative-preview-data"])) &&
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(
                ["--safe-preview", "--data-directory", @"\\server\share\preview-data"])) &&
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(
                ["--safe-preview", "--background", "--data-directory", previewData])) &&
            Throws<ArgumentException>(() => GuardianLaunchOptions.Parse(
                ["--safe-preview", "--data-directory", previewData, "--data-directory", previewData])),
            "an unsafe, hidden, ambiguous, or non-D-drive preview launch was accepted");

        var now = new DateTimeOffset(2026, 8, 4, 9, 30, 0, TimeSpan.Zero);
        var persistedAppearance = new AppSettings
        {
            UiLanguage = UiLanguages.English,
            UiTheme = UiThemes.Dark,
            MonitoringEnabled = true,
            MonitorOnly = false,
            MinimizeToTray = true,
            StartWithWindows = true
        };
        persistedAppearance.ThreadEnabled["must-not-leak"] = true;
        var fixture = FollowUpPreviewFixture.Create(now, persistedAppearance);
        var configured = fixture.Settings.ThreadFollowUps.TryGetValue(
            FollowUpPreviewFixture.TaskId,
            out var candidate)
            ? candidate
            : throw new InvalidOperationException("the preview task has no follow-up queue");
        Ensure(
            fixture.Settings.UiLanguage == UiLanguages.English &&
            fixture.Settings.UiTheme == UiThemes.Dark &&
            !fixture.Settings.MonitoringEnabled &&
            fixture.Settings.MonitorOnly &&
            !fixture.Settings.MinimizeToTray &&
            !fixture.Settings.StartWithWindows &&
            fixture.Settings.ThreadEnabled.Count == 0 &&
            fixture.Settings.ConversationOrder.SequenceEqual(
                [
                    FollowUpPreviewFixture.TaskId,
                    FollowUpPreviewFixture.ProcessingTaskId,
                    FollowUpPreviewFixture.AttentionTaskId,
                    FollowUpPreviewFixture.ArchivedTaskId
                ],
                StringComparer.OrdinalIgnoreCase) &&
            configured.IsEnabled &&
            configured.CompletionAnchorTurnId == FollowUpPreviewFixture.TurnId &&
            configured.Messages.Count == 2 &&
            configured.Messages[0].Message == "Review the completed turn." &&
            configured.Messages[0].Id == FollowUpPreviewFixture.CompletionMessageId &&
            configured.Messages[0].Order == 0 &&
            configured.Messages[0].Trigger == FollowUpTriggerKind.AfterNormalCompletion &&
            configured.Messages[1].Id == FollowUpPreviewFixture.ScheduledMessageId &&
            configured.Messages[1].Message == "Check tomorrow's result." &&
            configured.Messages[1].Order == 1 &&
            configured.Messages[1].Trigger == FollowUpTriggerKind.ScheduledAt &&
            configured.Messages[1].ScheduledAtUtc == now.AddDays(1) &&
            configured.Messages[1].ScheduledAtUtc?.Offset == TimeSpan.Zero &&
            fixture.Snapshot.States.Count == 4 &&
            fixture.Snapshot.States[0].Thread.Id == FollowUpPreviewFixture.TaskId &&
            fixture.Snapshot.States[0].Thread.Name == "Preset message preview" &&
            fixture.Snapshot.States[0].Thread.RuntimeStatus == "idle" &&
            fixture.Snapshot.States[0].Turn?.Id == FollowUpPreviewFixture.TurnId &&
            FollowUpQueuePlanner.IsNormalCompletion(fixture.Snapshot.States[0].Turn) &&
            fixture.Snapshot.States.Any(state =>
                state.Thread.Id == FollowUpPreviewFixture.ProcessingTaskId &&
                state.Health == TaskHealth.Processing) &&
            fixture.Snapshot.States.Any(state =>
                state.Thread.Id == FollowUpPreviewFixture.AttentionTaskId &&
                state.Health == TaskHealth.ManualReview) &&
            fixture.Snapshot.States.Any(state =>
                state.Thread.Id == FollowUpPreviewFixture.ArchivedTaskId &&
                state.Thread.IsArchived) &&
            fixture.WorkflowLineage.Health == WorkflowLineageHealth.Healthy &&
            fixture.WorkflowLineage.TotalCorrelationCount == 2 &&
            fixture.WorkflowLineage.TotalTriggerCount == 3 &&
            fixture.WorkflowLineage.TotalActionCount == 3 &&
            fixture.WorkflowLineage.Items.Count(item =>
                item.State == WorkflowActionOperationState.Confirmed) == 1 &&
            fixture.WorkflowLineage.Items.Count(item =>
                item.State == WorkflowActionOperationState.Uncertain) == 1 &&
            fixture.WorkflowLineage.Items.Count(item =>
                item.State == WorkflowActionOperationState.Blocked) == 1,
            "the in-memory multi-conversation preview fixture or two-message queue drifted");

        var chineseFixture = FollowUpPreviewFixture.Create(
            now,
            new AppSettings { UiLanguage = UiLanguages.SimplifiedChinese });
        var chineseMessages = chineseFixture.Settings.ThreadFollowUps[FollowUpPreviewFixture.TaskId].Messages;
        Ensure(
            chineseFixture.Snapshot.States[0].Thread.Name == "预制消息预览" &&
            chineseFixture.Snapshot.States.Any(state => state.Thread.Name == "恢复待复核") &&
            chineseFixture.Snapshot.States.Any(state => state.Thread.Name == "已归档记录") &&
            chineseMessages[0].Message == "复核已完成回合。" &&
            chineseMessages[1].Message == "明日检查结果。" &&
            chineseMessages[1].UseWorkflowAutomation &&
            chineseFixture.WorkflowRules.Count == 1,
            "the isolated preview fixture did not localize its concise visible content");

        await RunOnStaDispatcherAsync(() => WithIsolatedRootAsync(async root =>
        {
            using var log = new GuardianLog(root);
            var appServer = new AppServerClient(new CodexCliLocator(), log);
            var desktop = new DesktopIpcClient(log);
            var classifier = new RecoveryClassifier();
            var previewLocalization = new LocalizationService();
            previewLocalization.SetLanguage(fixture.Settings.UiLanguage);
            var recovery = new RecoveryService(
                appServer,
                desktop,
                new DesktopThreadOwnerActivator(desktop, log),
                new RecoveryOperationJournal(root),
                log);
            var engine = new GuardianEngine(
                fixture.Settings,
                appServer,
                desktop,
                recovery,
                classifier,
                new LocalConversationHistoryReader(Path.Combine(root, "preview-sessions")),
                log,
                null,
                null,
                previewIsolationMode: true);
            await using var viewModel = new MainViewModel(
                fixture.Settings,
                new SettingsService(root),
                new StartupService(),
                log,
                engine,
                appServer,
                desktop,
                classifier,
                previewLocalization,
                null,
                previewIsolationMode: true);

            viewModel.LoadFollowUpPreviewFixture(fixture);
            await viewModel.InitializeAsync();
            Ensure(
                viewModel.SelectedPage == "FollowUpDetail" &&
                viewModel.IsFollowUpDetailPage &&
                viewModel.SelectedTask is
                {
                    Id: FollowUpPreviewFixture.TaskId,
                    FollowUpQueueState: FollowUpQueueVisualState.WaitingForCompletion
                } &&
                viewModel.SelectedFollowUpsEnabled &&
                viewModel.FollowUpMessages.Count == 2 &&
                viewModel.FollowUpMessages[0].Trigger == FollowUpTriggerKind.AfterNormalCompletion &&
                viewModel.FollowUpMessages[1].Trigger == FollowUpTriggerKind.ScheduledAt,
                "the preview editor route task or message queue was incomplete");
            Ensure(
                viewModel.WorkflowLineageItems.Count == 3 &&
                viewModel.WorkflowLineageItems.All(item =>
                    !item.AutomationName.Contains(
                        FollowUpPreviewFixture.TaskId,
                        StringComparison.OrdinalIgnoreCase)),
                "the preview workflow lineage count or privacy projection drifted");
            Ensure(
                viewModel.WorkflowLineageItems.Any(item =>
                    item.RouteText.Contains("Active terminal task", StringComparison.Ordinal) &&
                    item.RouteText.Contains("Recovery review", StringComparison.Ordinal)),
                "the preview workflow lineage route text drifted");
            Ensure(
                viewModel.WorkflowLineageItems.Any(item =>
                    item.MetaText.Contains("Preset 2", StringComparison.Ordinal)),
                "the preview workflow lineage metadata text drifted");
            Ensure(
                viewModel.WorkflowLineageItems.Count(item => item.IsCorrelationStart) == 2 &&
                viewModel.WorkflowLineageItems.Any(item => item.IndentWidth > 0),
                "the preview workflow lineage correlation hierarchy drifted");
            Ensure(
                viewModel.WorkflowLineageItems.All(item =>
                    item.NextActionText.StartsWith("Next", StringComparison.Ordinal)),
                "the preview workflow lineage next-action text drifted");
            Ensure(
                !viewModel.AutoRecoveryEnabled &&
                !viewModel.CanEnableAutoRecovery &&
                !viewModel.CanEnableConversationProtection &&
                !viewModel.IsMonitoring &&
                !viewModel.ScanNowCommand.CanExecute(null) &&
                !viewModel.ProbeDesktopChannelCommand.CanExecute(null) &&
                !viewModel.RunReadOnlyDiagnosticCommand.CanExecute(null) &&
                !viewModel.OpenDataFolderCommand.CanExecute(null),
                "the preview view model exposed a live command");
            Ensure(
                !engine.IsRunning &&
                appServer.ProcessStartCount == 0 &&
                appServer.RequestCount == 0 &&
                !desktop.IsConnected &&
                !File.Exists(Path.Combine(root, "workflow-operations.json")),
                "the preview view model started a live runtime or wrote workflow authority");

            var stableRows = viewModel.WorkflowLineageItems.ToDictionary(
                static item => item.StableRef,
                StringComparer.Ordinal);
            var collectionNotifications = 0;
            NotifyCollectionChangedEventHandler collectionChanged = (_, _) =>
                collectionNotifications++;
            viewModel.WorkflowLineageItems.CollectionChanged += collectionChanged;
            viewModel.ApplyWorkflowLineageSnapshot(
                fixture.WorkflowLineage,
                forceLocalizedRefresh: true);
            Ensure(
                collectionNotifications == 0 &&
                viewModel.WorkflowLineageItems.All(item =>
                    ReferenceEquals(item, stableRows[item.StableRef])),
                "an identical lineage refresh replaced rows or reset the collection");

            var uncertain = fixture.WorkflowLineage.Items.Single(item =>
                item.State == WorkflowActionOperationState.Uncertain);
            var retryable = uncertain with
            {
                State = WorkflowActionOperationState.Retryable,
                FailureReason = WorkflowLineageFailureReason.DesktopUnavailable,
                UpdatedAtUtc = uncertain.UpdatedAtUtc?.AddSeconds(1)
            };
            var updatedLineage = fixture.WorkflowLineage with
            {
                Generation = fixture.WorkflowLineage.Generation + 1,
                Items = fixture.WorkflowLineage.Items.Select(item =>
                    item.ItemRef == uncertain.ItemRef ? retryable : item).ToArray()
            };
            viewModel.ApplyWorkflowLineageSnapshot(updatedLineage);
            var updatedRow = viewModel.WorkflowLineageItems.Single(item =>
                item.StableRef == uncertain.ItemRef);
            Ensure(
                collectionNotifications == 0 &&
                ReferenceEquals(updatedRow, stableRows[uncertain.ItemRef]) &&
                updatedRow.StateText == "Retryable" &&
                updatedRow.FailureText == "Desktop channel unavailable",
                "a state-only lineage refresh churned collection identity or lost controlled status");
            viewModel.ApplyWorkflowLineageSnapshot(fixture.WorkflowLineage);
            Ensure(
                updatedRow.StateText == "Retryable",
                "a stale lineage generation rolled the visible state backward");
            viewModel.WorkflowLineageItems.CollectionChanged -= collectionChanged;

            var originalTask = viewModel.SelectedTask ??
                throw new InvalidOperationException("the preview task selection disappeared");
            viewModel.NavigateCommand.Execute("Overview");
            Ensure(
                viewModel.IsOverviewPage &&
                viewModel.WorkflowLineageItems.Count == 3 &&
                !viewModel.RefreshWorkflowLineageCommand.CanExecute(null),
                "the isolated Activity route did not retain its in-memory lineage fixture");
            viewModel.OpenFollowUpEditorCommand.Execute(originalTask);
            var originalFirst = viewModel.FollowUpMessages[0];
            var originalFirstText = originalFirst.Message;
            var alternateTask = new GuardianTaskItem
            {
                Id = "13000000-0000-4000-8000-000000000099",
                Name = "Alternate isolated preview task",
                Preview = "No configured queue",
                Cwd = @"D:\CodexData\CodexGuardian\preview-fixture-alternate",
                RawSource = "previewFixture",
                CreatedAt = now.AddMinutes(-10),
                UpdatedAt = now.AddMinutes(-1)
            };
            viewModel.Tasks.Add(alternateTask);

            viewModel.BackToTasksCommand.Execute(null);
            Ensure(
                viewModel.IsTasksPage &&
                ReferenceEquals(viewModel.SelectedTask, originalTask) &&
                viewModel.FollowUpMessages.Count == 2,
                "returning from the follow-up detail page discarded its selected task or draft model");

            originalFirst.Message += " local draft";
            Ensure(viewModel.HasUnsavedFollowUpChanges, "editing did not mark the follow-up draft dirty");
            viewModel.OpenFollowUpEditorCommand.Execute(alternateTask);
            Ensure(
                viewModel.IsFollowUpDetailPage &&
                ReferenceEquals(viewModel.SelectedTask, originalTask) &&
                viewModel.HasUnsavedFollowUpChanges,
                "a dirty follow-up draft was silently replaced by another task");

            viewModel.DiscardFollowUpChanges();
            Ensure(
                !viewModel.HasUnsavedFollowUpChanges &&
                viewModel.FollowUpMessages[0].Message == originalFirstText,
                "discarding the draft did not restore the durable queue");
            viewModel.BackToTasksCommand.Execute(null);
            viewModel.OpenFollowUpEditorCommand.Execute(alternateTask);
            Ensure(
                viewModel.IsFollowUpDetailPage &&
                ReferenceEquals(viewModel.SelectedTask, alternateTask) &&
                viewModel.FollowUpMessages.Count == 0,
                "a clean follow-up editor could not switch to another task");

            viewModel.OpenFollowUpEditorCommand.Execute(originalTask);
            var scheduledMessage = viewModel.FollowUpMessages[1];
            Ensure(
                viewModel.FollowUpMessages.Count == 2 &&
                viewModel.MoveFollowUpMessage(scheduledMessage, 0) &&
                ReferenceEquals(viewModel.FollowUpMessages[0], scheduledMessage) &&
                viewModel.FollowUpMessages[0].Order == 0 &&
                viewModel.FollowUpMessages[1].Order == 1 &&
                viewModel.HasUnsavedFollowUpChanges,
                "the drag-order transaction did not move and renumber the local draft exactly");
            viewModel.DiscardFollowUpChanges();

            Ensure(
                Throws<InvalidOperationException>(engine.Start) &&
                await ThrowsAsync<InvalidOperationException>(() => engine.ScanOnceAsync()) &&
                Throws<InvalidOperationException>(() => engine.SetMonitorOnly(false)) &&
                Throws<InvalidOperationException>(() => engine.SetGlobalProtectionEnabled(true)) &&
                Throws<InvalidOperationException>(() => engine.SetThreadFollowUps(
                    FollowUpPreviewFixture.TaskId,
                    configured)) &&
                fixture.Settings.MonitorOnly &&
                !fixture.Settings.MonitoringEnabled &&
                appServer.ProcessStartCount == 0 &&
                appServer.RequestCount == 0,
                "an internal preview call crossed the Engine live-integration gate");
        }));

        var guardianRoot = FindGuardianSourceRoot();
        var program = File.ReadAllText(Path.Combine(guardianRoot, "Program.cs"), Encoding.UTF8);
        var app = File.ReadAllText(Path.Combine(guardianRoot, "App.xaml.cs"), Encoding.UTF8);
        var engineSource = File.ReadAllText(
            Path.Combine(guardianRoot, "Services", "GuardianEngine.cs"),
            Encoding.UTF8);
        var viewModelSource = File.ReadAllText(
            Path.Combine(guardianRoot, "ViewModels", "MainViewModel.cs"),
            Encoding.UTF8);
        var windowSource = File.ReadAllText(
            Path.Combine(guardianRoot, "MainWindow.xaml.cs"),
            Encoding.UTF8);
        var startupCoreSource = SliceSource(
            app.Replace("\r\n", "\n", StringComparison.Ordinal),
            "private async Task<StartupOutcome> StartupCoreAsync(",
            "private void ShowStartupNoticeIfAllowed(");
        var saveFollowUpsSource = SliceSource(
            viewModelSource.Replace("\r\n", "\n", StringComparison.Ordinal),
            "private async Task SaveFollowUpMessagesAsync()",
            "internal static bool TryConvertLocalScheduleToUtc(");
        var normalizedWindowSource = windowSource.Replace(
            "\r\n",
            "\n",
            StringComparison.Ordinal);
        var windowConstructorSource = SliceSource(
            normalizedWindowSource,
            "public MainWindow(MainViewModel viewModel, bool enableTray = true)",
            "internal void ActivateForStartup(bool showWindow)");
        var windowActivationSource = SliceSource(
            normalizedWindowSource,
            "internal void ActivateForStartup(bool showWindow)",
            "internal void DeactivateForExit()");
        var windowDeactivationSource = SliceSource(
            normalizedWindowSource,
            "internal void DeactivateForExit()",
            "private Forms.ContextMenuStrip BuildTrayMenu()");
        var viewModelInitialization = startupCoreSource.IndexOf(
            "await viewModel.InitializeForApplicationStartupAsync(",
            StringComparison.Ordinal);
        var windowCreation = startupCoreSource.IndexOf(
            "var window = new MainWindow(\n" +
            "            viewModel,\n" +
            "            enableTray: !launchOptions.SafePreview,\n" +
            "            attachmentRuntime,\n" +
            "            launchOptions.SafePreview,\n" +
            "            log);",
            StringComparison.Ordinal);
        var windowActivation = startupCoreSource.IndexOf(
            "window.ActivateForStartup(showWindow: !launchOptions.Background);",
            StringComparison.Ordinal);
        var startupPublication = startupCoreSource.IndexOf(
            "startup.PublishAtomic(viewModel.MarkApplicationStartupPublished);",
            StringComparison.Ordinal);
        Ensure(
            program.Contains("--follow-up-preview-fixture requires --safe-preview", StringComparison.Ordinal) &&
            program.Contains("NormalizePreviewDataDirectory", StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "launchOptions.ResolveStartupMutexName(SingleInstanceMutexName)",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "launchOptions.ResolveStartupMutexName(ReleaseExchangeMutexName)",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "await settingsService.LoadAsync(startup.CancellationToken);",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "var settingsService = new SettingsService(\n" +
                "            launchOptions.DataDirectory,\n" +
                "            monitoringEnabledAfterNormalization: !launchOptions.SafePreview);",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains("if (launchOptions.SafePreview)", StringComparison.Ordinal) &&
            startupCoreSource.Contains("settings.MonitoringEnabled = false;", StringComparison.Ordinal) &&
            startupCoreSource.Contains("if (launchOptions.AllowsLiveIntegration)", StringComparison.Ordinal) &&
            startupCoreSource.Contains("\"preview-sessions\"", StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "var attachmentRuntime = new FollowUpAttachmentRuntime(",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "var structuredCapabilities = launchOptions.AllowsLiveIntegration\n" +
                "            ? new InstalledCodexStructuredInputCapabilityProvider(settings.AttachmentLimits)\n" +
                "            : null;",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "var structuredDispatchReady = false;\n" +
                "        if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "attachmentRuntime.Reconciliation.ReconcileAsync(\n" +
                "                    settings,\n" +
                "                    startup.CancellationToken);",
                StringComparison.Ordinal) &&
            startupCoreSource.Contains(
                "structuredCapabilities: structuredDispatchReady\n" +
                "                    ? attachmentRuntime.StructuredCapabilities\n" +
                "                    : null,\n" +
                "                attachmentStore: structuredDispatchReady ? attachmentRuntime.Store : null,\n" +
                "                presentationLeases: structuredDispatchReady ? attachmentRuntime.Presentation : null,\n" +
                "                attachmentPins: structuredDispatchReady ? attachmentRuntime.DraftAuthority : null",
                StringComparison.Ordinal) &&
            viewModelInitialization >= 0 && windowCreation > viewModelInitialization &&
            windowActivation > windowCreation && startupPublication > windowActivation &&
            !startupCoreSource.Contains("Path.GetTempPath()", StringComparison.Ordinal) &&
            engineSource.Contains("Monitoring cannot start in isolated preview mode.", StringComparison.Ordinal) &&
            engineSource.Contains("Live task scans are disabled in isolated preview mode.", StringComparison.Ordinal) &&
            viewModelSource.Contains(
                "private bool CanUseLiveControls() => !_previewIsolationMode;",
                StringComparison.Ordinal) &&
            !viewModelSource.Contains("SafeDrill", StringComparison.Ordinal) &&
            !viewModelSource.Contains("ToggleMonitoring", StringComparison.Ordinal) &&
            saveFollowUpsSource.Contains(
                "if (!_previewIsolationMode)\n        {\n            _engine.SetThreadFollowUps(task.Id, configured);\n        }",
                StringComparison.Ordinal) &&
            windowConstructorSource.Contains(
                "_attachmentRuntime = attachmentRuntime;",
                StringComparison.Ordinal) &&
            windowConstructorSource.Contains(
                "_previewIsolationMode = previewIsolationMode;",
                StringComparison.Ordinal) &&
            !windowConstructorSource.Contains("NotifyIcon", StringComparison.Ordinal) &&
            !windowConstructorSource.Contains("CreateTrayIcon", StringComparison.Ordinal) &&
            windowActivationSource.Contains("if (_enableTray)", StringComparison.Ordinal) &&
            windowActivationSource.Contains("_notifyIcon.Visible = true;", StringComparison.Ordinal) &&
            windowDeactivationSource.Contains("CleanupTrayResources(ref failure);", StringComparison.Ordinal),
            "the source-level preview isolation composition contract drifted");
    }

    private static Task TestScheduleAndUiContractAsync()
    {
        Ensure(
            MainViewModel.TryConvertLocalScheduleToUtc(
                new DateTime(2026, 8, 4),
                "09:30",
                TimeZoneInfo.Utc,
                out var utc) &&
            utc == new DateTimeOffset(2026, 8, 4, 9, 30, 0, TimeSpan.Zero),
            "a valid 24-hour local schedule did not convert exactly");
        Ensure(
            !MainViewModel.TryConvertLocalScheduleToUtc(
                new DateTime(2026, 8, 4),
                "9:30",
                TimeZoneInfo.Utc,
                out _) &&
            !MainViewModel.TryConvertLocalScheduleToUtc(
                null,
                "09:30",
                TimeZoneInfo.Utc,
                out _),
            "an incomplete or non-canonical schedule was accepted");

        var daylightStart = TimeZoneInfo.TransitionTime.CreateFloatingDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            3,
            2,
            DayOfWeek.Sunday);
        var daylightEnd = TimeZoneInfo.TransitionTime.CreateFloatingDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            11,
            1,
            DayOfWeek.Sunday);
        var daylightRule = TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(
            new DateTime(2020, 1, 1),
            new DateTime(2030, 12, 31),
            TimeSpan.FromHours(1),
            daylightStart,
            daylightEnd);
        var daylightZone = TimeZoneInfo.CreateCustomTimeZone(
            "CodexGuardian-FollowUp-DST-Test",
            TimeSpan.FromHours(-5),
            "Follow-up DST test",
            "Follow-up standard",
            "Follow-up daylight",
            [daylightRule]);
        Ensure(
            !MainViewModel.TryConvertLocalScheduleToUtc(
                new DateTime(2026, 3, 8),
                "02:30",
                daylightZone,
                out _) &&
            !MainViewModel.TryConvertLocalScheduleToUtc(
                new DateTime(2026, 11, 1),
                "01:30",
                daylightZone,
                out _),
            "invalid or ambiguous DST wall time was accepted");
        Ensure(
            MainViewModel.TryConvertLocalScheduleToUtc(
                new DateTime(2026, 1, 15),
                "09:30",
                daylightZone,
                out var winterUtc) &&
            winterUtc == new DateTimeOffset(2026, 1, 15, 14, 30, 0, TimeSpan.Zero) &&
            MainViewModel.TryConvertLocalScheduleToUtc(
                new DateTime(2026, 7, 15),
                "09:30",
                daylightZone,
                out var summerUtc) &&
            summerUtc == new DateTimeOffset(2026, 7, 15, 13, 30, 0, TimeSpan.Zero),
            "valid winter and daylight-saving wall times did not convert with their exact offsets");

        var guardianRoot = FindGuardianSourceRoot();
        var projectPath = Path.Combine(guardianRoot, "CodexGuardian.csproj");
        var logoPngPath = Path.Combine(guardianRoot, "Assets", "CeasyLogo.png");
        var logoIcoPath = Path.Combine(guardianRoot, "Assets", "Ceasy.ico");
        var appXamlPath = Path.Combine(guardianRoot, "App.xaml");
        var appCodePath = Path.Combine(guardianRoot, "App.xaml.cs");
        var xamlPath = Path.Combine(guardianRoot, "MainWindow.xaml");
        var windowPath = Path.Combine(guardianRoot, "MainWindow.xaml.cs");
        var viewModelPath = Path.Combine(guardianRoot, "ViewModels", "MainViewModel.cs");
        var recoveryModelsPath = Path.Combine(guardianRoot, "Models", "RecoveryModels.cs");
        var enginePath = Path.Combine(guardianRoot, "Services", "GuardianEngine.cs");
        var windowMotionRoot = Path.Combine(guardianRoot, "WindowMotion");
        var zhPath = Path.Combine(guardianRoot, "Localization", "AppStrings.resx");
        var enPath = Path.Combine(guardianRoot, "Localization", "AppStrings.en.resx");
        var project = File.ReadAllText(projectPath, Encoding.UTF8);
        var appXaml = File.ReadAllText(appXamlPath, Encoding.UTF8);
        var appCode = File.ReadAllText(appCodePath, Encoding.UTF8);
        var xaml = File.ReadAllText(xamlPath, Encoding.UTF8);
        var xamlDocument = XDocument.Parse(xaml);
        XNamespace xamlNamespace = "http://schemas.microsoft.com/winfx/2006/xaml";
        var lineageElement = xamlDocument.Descendants().Single(element =>
            string.Equals(
                (string?)element.Attribute(xamlNamespace + "Name"),
                "ActivityLineageStage",
                StringComparison.Ordinal));
        var lineageXaml = lineageElement.ToString(SaveOptions.DisableFormatting);
        var window = File.ReadAllText(windowPath, Encoding.UTF8);
        var viewModel = File.ReadAllText(viewModelPath, Encoding.UTF8);
        var recoveryModels = File.ReadAllText(recoveryModelsPath, Encoding.UTF8);
        var engine = File.ReadAllText(enginePath, Encoding.UTF8);
        var windowMotion = Directory.Exists(windowMotionRoot)
            ? string.Join(
                Environment.NewLine,
                Directory.EnumerateFiles(windowMotionRoot, "*.cs", SearchOption.AllDirectories)
                    .OrderBy(path => path, StringComparer.Ordinal)
                    .Select(path => File.ReadAllText(path, Encoding.UTF8)))
            : string.Empty;
        var followUpPage = SliceSource(
            xaml,
            "<Grid x:Name=\"FollowUpEditor\"",
            "Binding IsRecoveryPage");
        var dragGrip = SliceSource(
            followUpPage,
            "AutomationProperties.AutomationId=\"FollowUpDragGripButton\"",
            "</Button>");
        var focusTitleBar = SliceSource(
            xaml,
            "<!-- Focus Workspace title bar -->",
            "<!-- The navigation dock floats independently of the working surface. -->");
        var focusProductRail = SliceSource(
            xaml,
            "<!-- The navigation dock floats independently of the working surface. -->",
            "<controls:GlassSurface x:Name=\"WorkspaceGlassSurface\"");
        var workspaceViewport = SliceSource(
            xaml,
            "<controls:GlassSurface x:Name=\"WorkspaceGlassSurface\"",
            "<Grid x:Name=\"WorkspaceViewport\"");
        var conversationStudio = SliceSource(
            xaml,
            "<!-- Conversations studio -->",
            "<!-- Preset-message second-level workspace -->");
        // Strip comments before slicing, not after: SliceSource stops at the first "</DataTemplate>" it
        // finds, so a comment quoting that tag would silently shorten the guarded region to a prefix and
        // leave the trailing triggers unguarded. Stripping first also means the assertions below cannot be
        // satisfied by markup that only appears inside a comment.
        var keepAliveRowTemplate = SliceSource(
            StripXamlComments(xaml),
            "<DataTemplate DataType=\"{x:Type vm:KeepAliveThreadViewModel}\">",
            "</DataTemplate>");
        var baseButtonStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"BaseButtonStyle\"",
            "<Style x:Key=\"PrimaryButtonStyle\"");
        var minimizeHandler = SliceSource(
            window,
            "private async void Minimize_Click",
            "private void Maximize_Click");
        var maximizeHandler = SliceSource(
            window,
            "private void Maximize_Click",
            "private void Close_Click");
        var toggleCheckStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"ToggleCheckStyle\"",
            "<Style x:Key=\"ConversationListItemStyle\"");
        var conversationListItemStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"ConversationListItemStyle\"",
            "<Style x:Key=\"FlatListItemStyle\"");
        var railNavigationButtonStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"RailNavigationButtonStyle\"",
            "<Style x:Key=\"RailUtilityButtonStyle\"");
        var railUtilityButtonStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"RailUtilityButtonStyle\"",
            "<Style x:Key=\"DangerIconButtonStyle\"");
        var calendarDayButtonStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"CodexCalendarDayButtonStyle\"",
            "<Style x:Key=\"CodexCalendarButtonStyle\"");
        var calendarItemStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"CodexCalendarItemStyle\"",
            "<Style x:Key=\"CodexCalendarStyle\"");
        var fieldTextBoxStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"FieldTextBoxStyle\"",
            "<Style x:Key=\"FieldComboBoxStyle\"");
        var fieldComboBoxStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"FieldComboBoxStyle\"",
            "<Style x:Key=\"FieldComboBoxItemStyle\"");
        var fieldComboBoxItemStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"FieldComboBoxItemStyle\"",
            "<Style TargetType=\"DatePickerTextBox\"");
        var namedOptionTemplate = SliceSource(
            appXaml,
            "<DataTemplate x:Key=\"NamedOptionTemplate\">",
            "</DataTemplate>");
        var fieldContentHost = SliceSource(
            fieldTextBoxStyle,
            "<ScrollViewer x:Name=\"PART_ContentHost\"",
            "/>");
        var workflowDestinationComboBox = SliceSource(
            followUpPage,
            "<ComboBox AutomationProperties.AutomationId=\"WorkflowDestinationComboBox\"",
            "</ComboBox>");
        var datePickerTextBoxStyle = SliceSource(
            appXaml,
            "<Style TargetType=\"DatePickerTextBox\">",
            "<Style x:Key=\"CodexCalendarNavigationButtonStyle\"");
        var datePickerTextBoxContentHost = SliceSource(
            datePickerTextBoxStyle,
            "<ScrollViewer x:Name=\"PART_ContentHost\"",
            "/>");
        var datePickerStyle = SliceSource(
            appXaml,
            "<Style TargetType=\"DatePicker\">",
            "<Style x:Key=\"ToggleCheckStyle\"");
        var datePickerTemplate = SliceSource(
            datePickerStyle,
            "<ControlTemplate TargetType=\"DatePicker\">",
            "</ControlTemplate>");
        var tasksSearchStage = SliceSource(
            xaml,
            "<Grid x:Name=\"TasksSearchStage\"",
            "<Grid x:Name=\"TasksScopeStage\"");
        var windowButtonStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"WindowButtonStyle\"",
            "<Style x:Key=\"CloseWindowButtonStyle\"");
        var toggleMaximizeSource = SliceSource(
            window,
            "private async void ToggleMaximize",
            "private void Window_StateChanged");
        var stateChangedSource = SliceSource(
            window,
            "private void Window_StateChanged",
            "private void UpdateCaptionControls");
        Ensure(
            !xaml.Contains("CommandParameter=\"FollowUps\"", StringComparison.Ordinal) &&
            !xaml.Contains("Binding IsFollowUpsPage", StringComparison.Ordinal) &&
            !xaml.Contains("AutomationProperties.AutomationId=\"FollowUpTaskList\"", StringComparison.Ordinal) &&
            xaml.Contains("Binding IsTasksNavigationSelected", StringComparison.Ordinal) &&
            xaml.Contains("Binding IsFollowUpDetailPage", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"TaskFollowUpEntryButton\"", StringComparison.Ordinal) &&
            xaml.Contains("Command=\"{Binding DataContext.OpenFollowUpEditorCommand", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"FollowUpBackButton\"", StringComparison.Ordinal) &&
            xaml.Contains("Command=\"{Binding BackToTasksCommand}\"", StringComparison.Ordinal) &&
            xaml.Contains("ItemsSource=\"{Binding FollowUpMessages}\"", StringComparison.Ordinal) &&
            xaml.Contains("SelectedDate=\"{Binding ScheduledDateLocal", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"FollowUpScheduleDatePicker\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"FollowUpScheduleTimeTextBox\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowRuleEditor\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowWhenGroup\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowWhereGroup\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowThenGroup\"", StringComparison.Ordinal) &&
            xaml.Contains("Command=\"{Binding SaveFollowUpMessagesCommand}\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"FollowUpMessageList\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"FollowUpSaveButton\"", StringComparison.Ordinal) &&
            File.Exists(logoPngPath) &&
            File.Exists(logoIcoPath) &&
            new FileInfo(logoPngPath).Length > 0 &&
            new FileInfo(logoIcoPath).Length > 0 &&
            project.Contains("<ApplicationIcon>Assets\\Ceasy.ico</ApplicationIcon>", StringComparison.Ordinal) &&
            project.Contains("<Resource Include=\"Assets\\CeasyLogo.png\" />", StringComparison.Ordinal) &&
            xaml.Contains("Icon=\"/CodexGuardian;component/Assets/Ceasy.ico\"", StringComparison.Ordinal) &&
            xaml.Contains("Source=\"/CodexGuardian;component/Assets/CeasyLogo.png\"", StringComparison.Ordinal) &&
            !xaml.Contains("SafeDrill", StringComparison.Ordinal) &&
            !xaml.Contains("Recovery.Backoff", StringComparison.Ordinal) &&
            // The two backoff values are now editable on the guardrails page. They were previously asserted
            // absent because nothing consumed them in XAML; the settings they write have always been real.
            xaml.Contains("BaseBackoffSeconds", StringComparison.Ordinal) &&
            xaml.Contains("MaximumBackoffSeconds", StringComparison.Ordinal) &&
            !xaml.Contains("Settings.InterfaceDescription", StringComparison.Ordinal) &&
            !xaml.Contains("Settings.StartupDescription", StringComparison.Ordinal) &&
            !xaml.Contains("Settings.DiscoveryDescription", StringComparison.Ordinal) &&
            !xaml.Contains("ToggleMonitoringCommand", StringComparison.Ordinal),
            "the task-row detail route, editor wiring, production drill removal, or always-on monitoring contract drifted");
        Ensure(
            appXaml.Contains("<FontFamily x:Key=\"DisplayFont\">Segoe UI Variable Display, Microsoft YaHei UI</FontFamily>", StringComparison.Ordinal) &&
            appXaml.Contains("<FontFamily x:Key=\"BodyFont\">Segoe UI Variable Text, Microsoft YaHei UI</FontFamily>", StringComparison.Ordinal) &&
            appXaml.Contains("<Setter Property=\"TextOptions.TextHintingMode\" Value=\"Auto\" />", StringComparison.Ordinal) &&
            appXaml.Contains("<Setter Property=\"FontSize\" Value=\"12\" />", StringComparison.Ordinal) &&
            xaml.Contains("UseLayoutRounding=\"True\"", StringComparison.Ordinal) &&
            xaml.Contains("SnapsToDevicePixels=\"True\"", StringComparison.Ordinal) &&
            xaml.Contains("TextOptions.TextHintingMode=\"Auto\"", StringComparison.Ordinal) &&
             xaml.Contains("CaptionHeight=\"56\"", StringComparison.Ordinal) &&
             xaml.Contains("<ColumnDefinition Width=\"212\" />", StringComparison.Ordinal) &&
             xaml.Contains("<RowDefinition Height=\"52\" />", StringComparison.Ordinal) &&
             !xaml.Contains("<!-- Product deck -->", StringComparison.Ordinal) &&
             !xaml.Contains("<!-- Workspace deck -->", StringComparison.Ordinal) &&
             !xaml.Contains("SelectedPageDescription", StringComparison.Ordinal) &&
             focusTitleBar.Contains("Grid.Column=\"1\"", StringComparison.Ordinal) &&
             focusTitleBar.Contains("Text=\"{Binding SelectedPageTitle}\"", StringComparison.Ordinal) &&
             focusTitleBar.Contains("Text=\"{Binding MonitoringSummaryText}\"", StringComparison.Ordinal) &&
             focusTitleBar.Contains("AutomationProperties.AutomationId=\"UpdateUtilityButton\"", StringComparison.Ordinal) &&
             // This button used to be a hard-coded Collapsed placeholder, and the literal was asserted because
             // nothing could ever show it. It now has a real signal behind it, so the binding is asserted
             // instead: that still says what the old line said — the button must not sit in the title bar
             // unconditionally — and additionally says the only thing allowed to reveal it is a check result.
             focusTitleBar.Contains(
                 "Visibility=\"{Binding HasUpdateAvailable, Converter={StaticResource BoolToVisibility}}\"",
                 StringComparison.Ordinal) &&
             focusTitleBar.Contains("Command=\"{Binding OpenProjectPageCommand}\"", StringComparison.Ordinal) &&
             !focusTitleBar.Contains("SelectedPageDescription", StringComparison.Ordinal) &&
             !focusTitleBar.Contains("Binding [Shell.Pulse]", StringComparison.Ordinal) &&
             !focusTitleBar.Contains("EngineState", StringComparison.Ordinal) &&
             !focusTitleBar.Contains("ScanNowCommand", StringComparison.Ordinal) &&
             focusProductRail.Contains("Source=\"/CodexGuardian;component/Assets/CeasyLogo.png\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("AutomationProperties.AutomationId=\"ConversationsScopeButton\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("AutomationProperties.AutomationId=\"ActivityScopeButton\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("AutomationProperties.AutomationId=\"GuardrailsScopeButton\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("AutomationProperties.AutomationId=\"PreferencesScopeButton\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("AutomationProperties.AutomationId=\"ProjectUtilityButton\"", StringComparison.Ordinal) &&
             // The mark itself is the project link. The chrome opt-in is what makes it clickable at all —
             // without it the click is taken by window dragging — and the badge is drawn on top of it, so the
             // badge has to stay out of hit-testing or it becomes a 9px dead spot over the button.
             focusProductRail.Contains("AutomationProperties.AutomationId=\"BrandProjectButton\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("shell:WindowChrome.IsHitTestVisibleInChrome=\"True\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("IsHitTestVisible=\"False\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("Command=\"{Binding OpenProjectPageCommand}\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("AutomationProperties.AutomationId=\"ThemeUtilityButton\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("CommandParameter=\"Tasks\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("CommandParameter=\"Overview\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("CommandParameter=\"Recovery\"", StringComparison.Ordinal) &&
             focusProductRail.Contains("CommandParameter=\"Settings\"", StringComparison.Ordinal) &&
             !focusProductRail.Contains("ToggleMonitoringCommand", StringComparison.Ordinal) &&
             workspaceViewport.Contains("Grid.Row=\"2\"", StringComparison.Ordinal) &&
             workspaceViewport.Contains("Grid.Column=\"1\"", StringComparison.Ordinal) &&
             railNavigationButtonStyle.Contains("<Setter Property=\"Width\" Value=\"40\" />", StringComparison.Ordinal) &&
             railNavigationButtonStyle.Contains("<Setter Property=\"Height\" Value=\"40\" />", StringComparison.Ordinal) &&
             railNavigationButtonStyle.Contains("<Setter Property=\"ToolTipService.Placement\" Value=\"Right\" />", StringComparison.Ordinal) &&
             railUtilityButtonStyle.Contains("<Setter Property=\"Width\" Value=\"32\" />", StringComparison.Ordinal) &&
             railUtilityButtonStyle.Contains("<Setter Property=\"Height\" Value=\"32\" />", StringComparison.Ordinal) &&
             !conversationStudio.Contains("Text=\"{Binding TaskFilterSummaryText}\"", StringComparison.Ordinal) &&
             !conversationStudio.Contains("Text=\"{Binding ConversationScopeText}\"", StringComparison.Ordinal),
            "the Focus Workspace shell, crisp typography, or temporary inner-page contract drifted");
        VerifyThemePaletteContract(appXaml);
        Ensure(
            new AppSettings().UiTheme == UiThemes.Dark &&
            appXaml.Contains("x:Key=\"GlassSurfaceBrush\"", StringComparison.Ordinal) &&
            appXaml.Contains("x:Key=\"GlassSurfaceStrongBrush\"", StringComparison.Ordinal) &&
            appXaml.Contains("x:Key=\"GlassBorderBrush\"", StringComparison.Ordinal) &&
            appXaml.Contains("x:Key=\"AmbientGlowBrush\"", StringComparison.Ordinal) &&
            appXaml.Contains("x:Key=\"ControlSurfaceBrush\"", StringComparison.Ordinal) &&
            appXaml.Contains("x:Key=\"FieldSurfaceBrush\"", StringComparison.Ordinal) &&
            appXaml.Contains("x:Key=\"DisabledInkBrush\"", StringComparison.Ordinal) &&
            xaml.Contains("CornerRadius=\"8\"", StringComparison.Ordinal) &&
            xaml.Contains("Background=\"{DynamicResource AmbientCoolBrush}\"", StringComparison.Ordinal) &&
            xaml.Contains("Background=\"{DynamicResource AmbientWarmBrush}\"", StringComparison.Ordinal) &&
            xaml.Contains("Background=\"{DynamicResource GlassSurfaceStrongBrush}\"", StringComparison.Ordinal) &&
            xaml.Contains("BorderBrush=\"{DynamicResource GlassBorderBrush}\"", StringComparison.Ordinal) &&
            !xaml.Contains("<BlurEffect", StringComparison.Ordinal) &&
            !xaml.Contains("EngineState", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ConversationRefreshButton\"", StringComparison.Ordinal) &&
            xaml.Contains("Command=\"{Binding ScanNowCommand}\"", StringComparison.Ordinal),
            "the dark-first single-accent glass foundation or engineering-entry removal drifted");
        // The keep-alive row must take both its surface and its hover tint from the palette. An inline
        // SolidColorBrush or a ColorAnimation cannot: ColorAnimation.To takes no DynamicResource, so either
        // one pins the dark values and leaves the row unreadable under the light theme.
        //
        // The literal-colour and ObjectAnimation bans close the paths a Background-only check misses -- a
        // DataTrigger or nested Style.Triggers Setter, a DiscreteObjectKeyFrame carrying its colour in an
        // attribute rather than a child element, and a thickened BorderBrush. Neither pattern occurs in the
        // template today, so neither can false-alarm. The single-template check keeps the guard bound to the
        // rendering contract rather than to a file position: WPF resolves an implicit DataTemplate from the
        // nearest Resources scope, so a second copy elsewhere would render instead while this one stayed
        // pristine and green.
        //
        // Banning hex spellings alone is not enough, because a colour can leave the palette without any hex
        // at all: Value="Black", <Border.Background>#E61A2232</Border.Background>, sc#1,0.1,0.13,0.2, or a
        // gradient brush element with a literal GradientStop. Enumerating spellings is a losing game, so the
        // paint-assignment check requires the opposite -- every property in here that paints something has to
        // take its value from a markup extension, which is the only kind of value the theme can reach at all.
        // The remaining substring bans cover the two forms that hide a colour outside an attribute value.
        var keepAliveRowTemplateCount = CountOccurrences(
            xaml,
            "<DataTemplate DataType=\"{x:Type vm:KeepAliveThreadViewModel}\">");
        var keepAliveRowLiteralPaint = CollectLiteralPaintAssignments(keepAliveRowTemplate);
        Ensure(
            keepAliveRowTemplate.Length > 0 &&
            keepAliveRowTemplateCount == 1 &&
            keepAliveRowTemplate.Contains(
                "Background=\"{DynamicResource ConversationSurfaceBrush}\"",
                StringComparison.Ordinal) &&
            keepAliveRowTemplate.Contains("x:Name=\"KeepAliveHoverVeil\"", StringComparison.Ordinal) &&
            keepAliveRowTemplate.Contains(
                "Background=\"{DynamicResource ConversationHoverBrush}\"",
                StringComparison.Ordinal) &&
            keepAliveRowTemplate.Contains(
                "Storyboard.TargetName=\"KeepAliveHoverVeil\"",
                StringComparison.Ordinal) &&
            keepAliveRowTemplate.Contains("Storyboard.TargetProperty=\"Opacity\"", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("<SolidColorBrush", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("<LinearGradientBrush", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("<RadialGradientBrush", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("<ImageBrush", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("<DrawingBrush", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("<VisualBrush", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("<ColorAnimation", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("ObjectAnimation", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("=\"#", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains(">#", StringComparison.Ordinal) &&
            !keepAliveRowTemplate.Contains("sc#", StringComparison.Ordinal) &&
            keepAliveRowLiteralPaint.Length == 0,
            "the keep-alive row surface left the theme palette or reintroduced a hard-coded fill: "
                + string.Join(", ", keepAliveRowLiteralPaint));
        // A DynamicResource naming a key nobody defines resolves to nothing at all: WPF leaves the
        // property unset rather than throwing, so a typo such as SurfaceBrush for GlassSurfaceStrongBrush
        // ships as an unpainted surface that is only visible under whichever theme it clashes with. Both
        // markup files must resolve every reference against the dictionaries or the theme palettes.
        var markupKeys = CollectAttributeValues(appXaml, "x:Key");
        markupKeys.UnionWith(CollectAttributeValues(xaml, "x:Key"));
        markupKeys.UnionWith(CollectPaletteKeys(window));
        var resourceReferences = CollectResourceReferences(appXaml, "DynamicResource");
        resourceReferences.UnionWith(CollectResourceReferences(appXaml, "StaticResource"));
        resourceReferences.UnionWith(CollectResourceReferences(xaml, "DynamicResource"));
        resourceReferences.UnionWith(CollectResourceReferences(xaml, "StaticResource"));
        var danglingReferences = resourceReferences
            .Where(reference => !reference.Contains('.', StringComparison.Ordinal))
            // An implicit WPF style can be referenced as {StaticResource {x:Type controls:GlassSurface}}.
            // The lightweight token scanner sees the nested markup extension's opening token as a key;
            // it is a type lookup, not a resource dictionary entry.
            .Where(reference => !reference.StartsWith("{x:Type", StringComparison.Ordinal))
            .Where(reference => !markupKeys.Contains(reference))
            .OrderBy(reference => reference, StringComparer.Ordinal)
            .ToArray();
        Ensure(
            markupKeys.Count > 0 &&
            resourceReferences.Count > 0 &&
            danglingReferences.Length == 0,
            "markup references resource keys that nothing defines: "
                + string.Join(", ", danglingReferences));
        Ensure(
            baseButtonStyle.Contains("x:Name=\"CommonStates\"", StringComparison.Ordinal) &&
            baseButtonStyle.Contains("x:Name=\"Normal\"", StringComparison.Ordinal) &&
            baseButtonStyle.Contains("x:Name=\"MouseOver\"", StringComparison.Ordinal) &&
            baseButtonStyle.Contains("x:Name=\"Pressed\"", StringComparison.Ordinal) &&
            baseButtonStyle.Contains("x:Name=\"Disabled\"", StringComparison.Ordinal) &&
            !baseButtonStyle.Contains("<Trigger Property=\"IsPressed\"", StringComparison.Ordinal),
            "the shared button visual-state contract drifted");
        Ensure(
            fieldTextBoxStyle.Contains("<Setter Property=\"TextAlignment\" Value=\"Left\"", StringComparison.Ordinal) &&
            fieldTextBoxStyle.Contains("<Setter Property=\"HorizontalContentAlignment\" Value=\"Stretch\"", StringComparison.Ordinal) &&
            fieldTextBoxStyle.Contains("<Setter Property=\"VerticalContentAlignment\" Value=\"Center\"", StringComparison.Ordinal) &&
            fieldContentHost.Contains("HorizontalAlignment=\"Stretch\"", StringComparison.Ordinal) &&
            fieldContentHost.Contains("VerticalAlignment=\"Stretch\"", StringComparison.Ordinal) &&
            !fieldContentHost.Contains("TemplateBinding Padding", StringComparison.Ordinal) &&
            tasksSearchStage.Contains("TextAlignment=\"Left\"", StringComparison.Ordinal) &&
            tasksSearchStage.Contains("Padding=\"34,0,72,0\"", StringComparison.Ordinal) &&
            tasksSearchStage.Contains("Margin=\"34,0,38,0\"", StringComparison.Ordinal) &&
            datePickerTextBoxStyle.Contains("<Setter Property=\"TextAlignment\" Value=\"Left\"", StringComparison.Ordinal) &&
            datePickerTextBoxStyle.Contains("<Setter Property=\"HorizontalContentAlignment\" Value=\"Stretch\"", StringComparison.Ordinal) &&
            datePickerTextBoxStyle.Contains("<Setter Property=\"VerticalContentAlignment\" Value=\"Center\"", StringComparison.Ordinal) &&
            datePickerTextBoxContentHost.Contains("HorizontalAlignment=\"Stretch\"", StringComparison.Ordinal) &&
            datePickerTextBoxContentHost.Contains("VerticalAlignment=\"Stretch\"", StringComparison.Ordinal) &&
            !datePickerTextBoxContentHost.Contains("TemplateBinding Padding", StringComparison.Ordinal) &&
            datePickerTemplate.Contains("x:Name=\"PART_TextBox\"", StringComparison.Ordinal) &&
            datePickerTemplate.Contains("HorizontalAlignment=\"{TemplateBinding HorizontalContentAlignment}\"", StringComparison.Ordinal) &&
            datePickerTemplate.Contains("VerticalAlignment=\"{TemplateBinding VerticalContentAlignment}\"", StringComparison.Ordinal) &&
            datePickerTemplate.Contains("HorizontalContentAlignment=\"Stretch\"", StringComparison.Ordinal) &&
            datePickerTemplate.Contains("VerticalContentAlignment=\"Center\"", StringComparison.Ordinal),
            "text fields and the date picker must use one left-aligned, stretch-hosted content contract without doubled padding");
        Ensure(
            workflowDestinationComboBox.Contains(
                "Style=\"{StaticResource FieldComboBoxStyle}\"",
                StringComparison.Ordinal) &&
            fieldComboBoxStyle.Contains(
                "MinWidth=\"{Binding PlacementTarget.ActualWidth, RelativeSource={RelativeSource AncestorType=Popup}}\"",
                StringComparison.Ordinal) &&
            fieldComboBoxItemStyle.Contains(
                "<Trigger Property=\"IsEnabled\" Value=\"False\">",
                StringComparison.Ordinal) &&
            fieldComboBoxItemStyle.Contains(
                "<Setter Property=\"Foreground\" Value=\"{DynamicResource DisabledInkBrush}\" />",
                StringComparison.Ordinal) &&
            !namedOptionTemplate.Contains(
                "Foreground=\"{DynamicResource InkBrush}\"",
                StringComparison.Ordinal),
            "workflow pickers must retain the themed popup width and a legible disabled-item state");
        Ensure(
            !xaml.Contains("WindowTransitionOverlay", StringComparison.Ordinal) &&
            !xaml.Contains("WindowTransitionSnapshot", StringComparison.Ordinal) &&
            !xaml.Contains("AllowsTransparency=\"True\"", StringComparison.Ordinal) &&
            !minimizeHandler.Contains("CaptureShellSnapshot", StringComparison.Ordinal) &&
            !toggleMaximizeSource.Contains("CaptureShellSnapshot", StringComparison.Ordinal) &&
            !window.Contains("CaptureWindowTransitionSnapshot", StringComparison.Ordinal) &&
            !minimizeHandler.Contains("RenderTargetBitmap", StringComparison.Ordinal) &&
            !toggleMaximizeSource.Contains("RenderTargetBitmap", StringComparison.Ordinal) &&
            !windowMotion.Contains("RenderTargetBitmap", StringComparison.Ordinal) &&
            !windowButtonStyle.Contains("BasedOn=", StringComparison.Ordinal) &&
            !windowButtonStyle.Contains("BackEase", StringComparison.Ordinal) &&
            !windowButtonStyle.Contains("ScaleTransform", StringComparison.Ordinal) &&
            window.Contains("WindowMotionController", StringComparison.Ordinal) &&
            minimizeHandler.Contains("WindowMotionRequest.Minimize", StringComparison.Ordinal) &&
            maximizeHandler.Contains("ToggleMaximize", StringComparison.Ordinal) &&
            toggleMaximizeSource.Contains("WindowMotionRequest.Restore", StringComparison.Ordinal) &&
            toggleMaximizeSource.Contains("WindowMotionRequest.Maximize", StringComparison.Ordinal) &&
            windowMotion.Contains("DwmRegisterThumbnail", StringComparison.Ordinal) &&
            windowMotion.Contains("DwmUpdateThumbnailProperties", StringComparison.Ordinal) &&
            windowMotion.Contains("DwmUnregisterThumbnail", StringComparison.Ordinal) &&
            windowMotion.Contains("DwmQueryThumbnailSourceSize", StringComparison.Ordinal) &&
            windowMotion.Contains("FreezeRepresentation", StringComparison.Ordinal) &&
            windowMotion.Contains("TransitionsForcedDisabled", StringComparison.Ordinal) &&
            windowMotion.Contains("Cloak", StringComparison.Ordinal) &&
            windowMotion.Contains("ExtendedFrameBounds", StringComparison.Ordinal) &&
            windowMotion.Contains("CompositionTarget.Rendering", StringComparison.Ordinal) &&
            windowMotion.Contains("Stopwatch", StringComparison.Ordinal) &&
            windowMotion.Contains("ClientAreaAnimation", StringComparison.Ordinal) &&
            windowMotion.Contains("DestroyWindow", StringComparison.Ordinal) &&
            windowMotion.Contains("finally", StringComparison.Ordinal) &&
            CountOccurrences(minimizeHandler, "SystemCommands.MinimizeWindow(this)") == 2 &&
            CountOccurrences(toggleMaximizeSource, "SystemCommands.RestoreWindow(this)") == 2 &&
            CountOccurrences(toggleMaximizeSource, "SystemCommands.MaximizeWindow(this)") == 2 &&
            !windowMotion.Contains("SystemCommands.", StringComparison.Ordinal) &&
            windowMotion.Contains("FlushCompositionNoThrow", StringComparison.Ordinal) &&
            windowMotion.Contains("RestoreForegroundNoThrow", StringComparison.Ordinal) &&
            windowMotion.Contains("GetLastInputInfo", StringComparison.Ordinal) &&
            windowMotion.Contains("WindowMotionStage", StringComparison.Ordinal) &&
            windowMotion.Contains("WindowMotionFailureReason", StringComparison.Ordinal) &&
            windowMotion.Contains("WindowMotionErrorDomain", StringComparison.Ordinal) &&
            windowMotion.Contains("ReadSurfaceState", StringComparison.Ordinal) &&
            windowMotion.Contains("IsAboveInZOrder", StringComparison.Ordinal) &&
            windowMotion.Contains("frameCount = checked(frameCount + 1);", StringComparison.Ordinal) &&
            windowMotion.Contains("optionalFailureStage = stage;", StringComparison.Ordinal) &&
            windowMotion.Contains("optionalErrorCode = freezeResult;", StringComparison.Ordinal) &&
            windowMotion.Contains("ReadSourceState", StringComparison.Ordinal) &&
            windowMotion.Contains("IsZoomed", StringComparison.Ordinal) &&
            windowMotion.Contains("MatchesRequestedState", StringComparison.Ordinal) &&
            windowMotion.Contains("StateCommitUnconfirmed", StringComparison.Ordinal) &&
            windowMotion.Contains("DestinationBoundsUnchanged", StringComparison.Ordinal) &&
            windowMotion.Contains("candidateBounds != startBounds.Value", StringComparison.Ordinal) &&
            windowMotion.Contains("!endBounds.HasValue || !endBounds.Value.IsUsable", StringComparison.Ordinal) &&
            windowMotion.Contains("stateCommitted = true;", StringComparison.Ordinal) &&
            windowMotion.IndexOf("stage = WindowMotionStage.CommitWindowState;", StringComparison.Ordinal) <
                windowMotion.IndexOf("stage = WindowMotionStage.DisableSource;", StringComparison.Ordinal) &&
            windowMotion.IndexOf("stage = WindowMotionStage.EnableSourceForCommit;", StringComparison.Ordinal) <
                windowMotion.IndexOf("stage = WindowMotionStage.CommitMinimize;", StringComparison.Ordinal) &&
            windowMotion.Contains(
                "DwmwaFreezeRepresentation,\n                enabled: true,\n                out var freezeResult",
                StringComparison.Ordinal) &&
            window.Contains("WriteWindowMotion", StringComparison.Ordinal) &&
            !windowMotion.Contains(
                "transitionWindow,\n                sourceWindow,",
                StringComparison.Ordinal) &&
            stateChangedSource.Contains("UpdateCaptionControls();", StringComparison.Ordinal) &&
            ReadResourceKeys(zhPath).Contains("Window.Maximize") &&
            ReadResourceKeys(zhPath).Contains("Window.Restore") &&
            ReadResourceKeys(enPath).Contains("Window.Maximize") &&
            ReadResourceKeys(enPath).Contains("Window.Restore") &&
            window.Contains("_localization.LanguageChanged += OnLanguageChanged;", StringComparison.Ordinal) &&
            window.Contains("Dispatcher.Invoke(UpdateCaptionControls);", StringComparison.Ordinal),
            "window motion must use a cancellable top-level DWM thumbnail transition, authoritative state readback, changed resize bounds, and exhaustive cleanup");
        Ensure(
            calendarDayButtonStyle.Contains("x:Name=\"CommonStates\"", StringComparison.Ordinal) &&
            calendarDayButtonStyle.Contains("x:Name=\"SelectionStates\"", StringComparison.Ordinal) &&
            calendarDayButtonStyle.Contains("x:Name=\"ActiveStates\"", StringComparison.Ordinal) &&
            calendarDayButtonStyle.Contains("x:Name=\"DayStates\"", StringComparison.Ordinal) &&
            calendarDayButtonStyle.Contains("x:Name=\"BlackoutDayStates\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("x:Name=\"PART_PreviousButton\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("x:Name=\"PART_HeaderButton\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("x:Name=\"PART_NextButton\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("Data=\"M 6,0 L 1,5 L 6,10\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("Data=\"M 0,0 L 5,5 L 0,10\"", StringComparison.Ordinal) &&
            !calendarItemStyle.Contains("Content=\"&#xE76B;\"", StringComparison.Ordinal) &&
            !calendarItemStyle.Contains("Content=\"&#xE76C;\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("x:Name=\"PART_MonthView\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("x:Name=\"PART_YearView\"", StringComparison.Ordinal) &&
            calendarItemStyle.Contains("CalendarItem.DayTitleTemplateResourceKey", StringComparison.Ordinal) &&
            datePickerStyle.Contains("CalendarStyle\" Value=\"{StaticResource CodexDatePickerCalendarStyle}", StringComparison.Ordinal) &&
            datePickerStyle.Contains("x:Name=\"PART_TextBox\"", StringComparison.Ordinal) &&
            datePickerStyle.Contains("x:Name=\"PART_Button\"", StringComparison.Ordinal) &&
            datePickerStyle.Contains("x:Name=\"PART_Popup\"", StringComparison.Ordinal),
            "the themed date picker or complete calendar state template drifted");
        Ensure(
            baseButtonStyle.Contains("x:Name=\"ButtonScale\"", StringComparison.Ordinal) &&
            // Press feedback stays below 150 ms so a pointer can outrun it. Release uses the shared spring
            // easing surface and its deliberate 360 ms settling window; the retired BackEase release is
            // asserted absent so the base button and custom spring do not compete for the same transition.
            baseButtonStyle.Contains("GeneratedDuration=\"0:0:0.07\"", StringComparison.Ordinal) &&
            baseButtonStyle.Contains("GeneratedDuration=\"0:0:0.36\"", StringComparison.Ordinal) &&
            baseButtonStyle.Contains("<CubicEase EasingMode=\"EaseOut\" />", StringComparison.Ordinal) &&
            !baseButtonStyle.Contains("<BackEase", StringComparison.Ordinal) &&
            appXaml.Contains("<Trigger Property=\"Validation.HasError\" Value=\"True\">", StringComparison.Ordinal) &&
            appXaml.Contains("TargetName=\"FieldRoot\" Property=\"BorderBrush\" Value=\"{DynamicResource DangerBrush}\"", StringComparison.Ordinal) &&
            toggleCheckStyle.Contains("x:Name=\"ThumbTransform\"", StringComparison.Ordinal) &&
            toggleCheckStyle.Contains("x:Name=\"ToggleScale\"", StringComparison.Ordinal) &&
            toggleCheckStyle.Contains("<VisualStateGroup x:Name=\"CheckStates\">", StringComparison.Ordinal) &&
            toggleCheckStyle.Contains("<VisualTransition From=\"Unchecked\"", StringComparison.Ordinal) &&
            toggleCheckStyle.Contains("<VisualTransition From=\"Checked\"", StringComparison.Ordinal) &&
            toggleCheckStyle.Contains("ToggleThumbBrush", StringComparison.Ordinal) &&
            appXaml.Contains("x:Key=\"ToggleThumbBrush\"", StringComparison.Ordinal) &&
            toggleCheckStyle.Contains("<BackEase", StringComparison.Ordinal) &&
            conversationListItemStyle.Contains("Duration=\"0:0:0.18\"", StringComparison.Ordinal) &&
            conversationListItemStyle.Contains("Duration=\"0:0:0.2\"", StringComparison.Ordinal) &&
            conversationListItemStyle.Contains("<CubicEase EasingMode=\"EaseOut\" />", StringComparison.Ordinal) &&
            window.Contains("TimeSpan.FromMilliseconds(200)", StringComparison.Ordinal) &&
            window.Contains("EasingFunction = new BackEase", StringComparison.Ordinal) &&
            window.Contains("TimeSpan.FromMilliseconds(220)", StringComparison.Ordinal),
            "the interaction language drifted: press feedback, spring release, or non-linear easing changed");
        Ensure(
            !followUpPage.Contains("FollowUpTaskList", StringComparison.Ordinal) &&
            !followUpPage.Contains("FollowUpMoveUpButton", StringComparison.Ordinal) &&
            !followUpPage.Contains("FollowUpMoveDownButton", StringComparison.Ordinal) &&
            !followUpPage.Contains("MoveFollowUpMessageUpCommand", StringComparison.Ordinal) &&
            !followUpPage.Contains("MoveFollowUpMessageDownCommand", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpDragGripButton\"", StringComparison.Ordinal) &&
            followUpPage.Contains("PreviewMouseLeftButtonDown=\"FollowUpDragGrip_PreviewMouseLeftButtonDown\"", StringComparison.Ordinal) &&
            followUpPage.Contains("LostMouseCapture=\"FollowUpDragGrip_LostMouseCapture\"", StringComparison.Ordinal) &&
            followUpPage.Contains("ShowDropBefore", StringComparison.Ordinal) &&
            followUpPage.Contains("ShowDropAfter", StringComparison.Ordinal) &&
            !followUpPage.Contains("StrokeDashArray=\"5 4\"", StringComparison.Ordinal) &&
            !followUpPage.Contains("Opacity=\"0.58\"", StringComparison.Ordinal) &&
            followUpPage.Contains("VirtualizingPanel.IsVirtualizing=\"False\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpAddMessageButton\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpRemoveMessageButton\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpEditMessageButton\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpDoneEditingButton\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpMaximumErrorRetriesTextBox\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpRetryIndefinitelyToggle\"", StringComparison.Ordinal) &&
            followUpPage.Contains("IsEnabled=\"{Binding IsFiniteRetry}\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpMessageEditorRegion\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpMessageEnabledToggle\"", StringComparison.Ordinal) &&
            !followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpSequencePanel\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpSaveDock\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpDraftEmptyHint\"", StringComparison.Ordinal) &&
            followUpPage.Contains("AutomationProperties.LiveSetting=\"Polite\"", StringComparison.Ordinal) &&
            followUpPage.Contains("x:Name=\"FollowUpRouteHeader\"", StringComparison.Ordinal) &&
            !followUpPage.Contains("x:Name=\"FollowUpToolStrip\"", StringComparison.Ordinal) &&
            followUpPage.Contains("x:Name=\"FollowUpMessageTimeline\"", StringComparison.Ordinal) &&
            followUpPage.Contains("x:Name=\"FollowUpEmptyState\"", StringComparison.Ordinal) &&
            !followUpPage.Contains("Binding [FollowUp.ActiveQueue]", StringComparison.Ordinal) &&
            !followUpPage.Contains("Binding [FollowUp.DraftSequence]", StringComparison.Ordinal) &&
            !followUpPage.Contains("<ColumnDefinition Width=\"248\"", StringComparison.Ordinal) &&
            !followUpPage.Contains("MaxHeight=\"460\"", StringComparison.Ordinal) &&
            followUpPage.Contains("HorizontalAlignment=\"Stretch\"", StringComparison.Ordinal) &&
            followUpPage.Contains("ColumnDefinition Width=\"Auto\"", StringComparison.Ordinal) &&
            followUpPage.Contains("ColumnDefinition Width=\"*\"", StringComparison.Ordinal) &&
            followUpPage.Contains("MinHeight=\"78\"", StringComparison.Ordinal) &&
            followUpPage.Contains("MinHeight=\"48\"", StringComparison.Ordinal) &&
            followUpPage.Contains("MinHeight=\"62\"", StringComparison.Ordinal) &&
            followUpPage.Contains("MaxHeight=\"112\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpAutomationModeComboBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"WorkflowTriggerComboBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"WorkflowScheduleDatePicker\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"WorkflowScheduleTimeTextBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"WorkflowSourceConversationComboBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"WorkflowSourcePresetComboBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"WorkflowDestinationComboBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"WorkflowTargetConversationComboBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("<ColumnDefinition Width=\"*\" MinWidth=\"220\" />", StringComparison.Ordinal) &&
             followUpPage.Contains("<ColumnDefinition Width=\"*\" MinWidth=\"210\" />", StringComparison.Ordinal) &&
             followUpPage.Contains("<ColumnDefinition Width=\"*\" MinWidth=\"230\" />", StringComparison.Ordinal) &&
             !followUpPage.Contains("Width=\"140\"", StringComparison.Ordinal) &&
             !followUpPage.Contains("Width=\"80\"", StringComparison.Ordinal) &&
             !followUpPage.Contains("Width=\"184\"", StringComparison.Ordinal) &&
             followUpPage.Contains("Height=\"32\"", StringComparison.Ordinal) &&
             xaml.Contains("MinWidth=\"1024\"", StringComparison.Ordinal) &&
             xaml.Contains("MinHeight=\"680\"", StringComparison.Ordinal) &&
             CountOccurrences(followUpPage, "IsTextSearchEnabled=\"True\"") >= 3 &&
             followUpPage.Contains("SelectedValuePath=\"Id\"", StringComparison.Ordinal) &&
             followUpPage.Contains("SelectedValuePath=\"MessageId\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpScheduleDatePicker\"", StringComparison.Ordinal) &&
             followUpPage.Contains("AutomationProperties.AutomationId=\"FollowUpScheduleTimeTextBox\"", StringComparison.Ordinal) &&
             followUpPage.Contains("ItemTemplate=\"{StaticResource NamedOptionTemplate}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("Background=\"{DynamicResource SurfaceSubtleBrush}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("<ColumnDefinition Width=\"42\" />", StringComparison.Ordinal) &&
             followUpPage.Contains("Text=\"{Binding ContentPreview}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("Value=\"{Binding EffectiveMaximumErrorRetries}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("Value=\"{Binding MaximumErrorRetriesText}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("Value=\"{DynamicResource DangerBrush}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("Text=\"{Binding MaximumErrorRetriesText, UpdateSourceTrigger=PropertyChanged, ValidatesOnDataErrors=True}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("FocusVisualStyle=\"{x:Null}\"", StringComparison.Ordinal) &&
             followUpPage.Contains("Binding IsEditing", StringComparison.Ordinal) &&
             followUpPage.Contains("BorderThickness=\"1\"", StringComparison.Ordinal) &&
             followUpPage.Contains("CornerRadius=\"8\"", StringComparison.Ordinal) &&
             dragGrip.Contains("x:Name=\"GripHoverSurface\"", StringComparison.Ordinal) &&
             dragGrip.Contains("x:Name=\"GripPressedSurface\"", StringComparison.Ordinal) &&
             dragGrip.Contains("Duration=\"0:0:0.16\"", StringComparison.Ordinal) &&
             dragGrip.Contains("Duration=\"0:0:0.2\"", StringComparison.Ordinal) &&
             dragGrip.Contains("RelativeSource AncestorType=Button", StringComparison.Ordinal) &&
             !dragGrip.Contains("Background=\"{DynamicResource ControlSurfaceBrush}\"", StringComparison.Ordinal) &&
             !dragGrip.Contains("CornerRadius=\"11\"", StringComparison.Ordinal) &&
             !dragGrip.Contains("StringFormat={}{0:00}", StringComparison.Ordinal) &&
             !followUpPage.Contains("Height=\"70\"", StringComparison.Ordinal) &&
             followUpPage.Contains("<Setter Property=\"Opacity\" Value=\"0\" />", StringComparison.Ordinal) &&
             !followUpPage.Contains("Panel.ZIndex=\"5\"", StringComparison.Ordinal),
            "the bounded message surface, responsive workflow editor, stateful drag grip, transparent source slot, or compact save action drifted");
        var dragPreviewConstructor = SliceSource(
            window,
            "public FollowUpDragPreviewWindow(",
            "public bool IsSettled");
        var conversationDragMouseDown = SliceSource(
            window,
            "private void ConversationDragGrip_PreviewMouseLeftButtonDown",
            "private void ConversationDragGrip_PreviewMouseMove");
        var conversationDragMouseMove = SliceSource(
            window,
            "private void ConversationDragGrip_PreviewMouseMove",
            "private void Window_PreviewMouseMove");
        var beginConversationDrag = SliceSource(
            window,
            "private bool BeginConversationDrag",
            "private void UpdateConversationDragPreview");
        var conversationCaptureLoss = SliceSource(
            window,
            "private void ConversationDragGrip_LostMouseCapture",
            "private async void ConversationDragGrip_PreviewKeyDown");
        var cancelConversationDrag = SliceSource(
            window,
            "private void CancelConversationDrag",
            "private void OnConversationCollectionChanged");
        var followUpDragMouseDown = SliceSource(
            window,
            "private void FollowUpDragGrip_PreviewMouseLeftButtonDown",
            "private void FollowUpDragGrip_PreviewMouseMove");
        var followUpDragMouseMove = SliceSource(
            window,
            "private void FollowUpDragGrip_PreviewMouseMove",
            "private void FollowUpDragGrip_PreviewMouseLeftButtonUp");
        var beginFollowUpDrag = SliceSource(
            window,
            "private bool BeginFollowUpDrag",
            "private void UpdateFollowUpDragPreview");
        var followUpCaptureLoss = SliceSource(
            window,
            "private void FollowUpDragGrip_LostMouseCapture",
            "private void FollowUpDragGrip_PreviewKeyDown");
        var cancelFollowUpDrag = SliceSource(
            window,
            "private void CancelFollowUpDrag",
            "private void DetachViewModelEvents");
        var beginFollowUpSettle = SliceSource(
            window,
            "private void BeginFollowUpSettle",
            "private void CompleteFollowUpSettle");
        var windowDragTracking = SliceSource(
            window,
            "private void Window_PreviewMouseMove",
            "private async void ConversationDragGrip_PreviewMouseLeftButtonUp");
        var windowDragCancellation = SliceSource(
            window,
            "private void Window_PreviewKeyDown",
            "private bool BeginFollowUpDrag");
        var windowDeactivation = SliceSource(
            window,
            "private void Window_Deactivated",
            "private async void Window_Closing");
        var conversationGripStyle = SliceSource(
            appXaml,
            "<Style x:Key=\"ConversationDragGripButtonStyle\"",
            "<Style x:Key=\"ConversationListItemStyle\"");
        Ensure(
            window.Contains("SystemParameters.MinimumVerticalDragDistance", StringComparison.Ordinal) &&
            window.Contains("FollowUpDragPreviewWindow", StringComparison.Ordinal) &&
            window.Contains("item.IsEditing = false", StringComparison.Ordinal) &&
            window.Contains("const double previewHeight = 68", StringComparison.Ordinal) &&
            window.Contains("FollowUp.RetryShort", StringComparison.Ordinal) &&
            window.Contains("ShowActivated = false", StringComparison.Ordinal) &&
            window.Contains("WsExNoActivate | WsExTransparent | WsExToolWindow", StringComparison.Ordinal) &&
            window.Contains("GetCursorPos(out var cursor)", StringComparison.Ordinal) &&
            window.Contains("SetWindowPos(", StringComparison.Ordinal) &&
            conversationGripStyle.Contains("<Setter Property=\"Cursor\" Value=\"Hand\"", StringComparison.Ordinal) &&
            dragGrip.Contains("Cursor=\"Hand\"", StringComparison.Ordinal) &&
            !conversationDragMouseDown.Contains("CaptureMouse", StringComparison.Ordinal) &&
            !conversationDragMouseDown.Contains("Mouse.Capture", StringComparison.Ordinal) &&
            !conversationDragMouseDown.Contains("SelectedTask", StringComparison.Ordinal) &&
            !conversationDragMouseDown.Contains("ReferenceEquals", StringComparison.Ordinal) &&
            !followUpDragMouseDown.Contains("CaptureMouse", StringComparison.Ordinal) &&
            !followUpDragMouseDown.Contains("Mouse.Capture", StringComparison.Ordinal) &&
            conversationDragMouseMove.Contains("SystemParameters.MinimumHorizontalDragDistance", StringComparison.Ordinal) &&
            conversationDragMouseMove.Contains("SystemParameters.MinimumVerticalDragDistance", StringComparison.Ordinal) &&
            followUpDragMouseMove.Contains("SystemParameters.MinimumHorizontalDragDistance", StringComparison.Ordinal) &&
            followUpDragMouseMove.Contains("SystemParameters.MinimumVerticalDragDistance", StringComparison.Ordinal) &&
            beginConversationDrag.Contains("Mouse.Capture(_conversationDragCaptureOwner, CaptureMode.Element)", StringComparison.Ordinal) &&
            beginFollowUpDrag.Contains("Mouse.Capture(_followUpDragCaptureOwner, CaptureMode.Element)", StringComparison.Ordinal) &&
            beginConversationDrag.Contains("Mouse.OverrideCursor = Cursors.SizeAll", StringComparison.Ordinal) &&
            beginFollowUpDrag.Contains("Mouse.OverrideCursor = Cursors.SizeAll", StringComparison.Ordinal) &&
            xaml.Contains("PreviewMouseMove=\"Window_PreviewMouseMove\"", StringComparison.Ordinal) &&
            xaml.Contains("PreviewMouseLeftButtonUp=\"Window_PreviewMouseLeftButtonUp\"", StringComparison.Ordinal) &&
            xaml.Contains("LostMouseCapture=\"ConversationDragGrip_LostMouseCapture\"", StringComparison.Ordinal) &&
            xaml.Contains("LostMouseCapture=\"FollowUpDragGrip_LostMouseCapture\"", StringComparison.Ordinal) &&
            windowDragTracking.Contains("ConversationDragGrip_PreviewMouseMove", StringComparison.Ordinal) &&
            windowDragTracking.Contains("FollowUpDragGrip_PreviewMouseMove", StringComparison.Ordinal) &&
            windowDragTracking.Contains("ConversationDragGrip_PreviewMouseLeftButtonUp", StringComparison.Ordinal) &&
            windowDragTracking.Contains("FollowUpDragGrip_PreviewMouseLeftButtonUp", StringComparison.Ordinal) &&
            cancelConversationDrag.Contains("Mouse.OverrideCursor = null", StringComparison.Ordinal) &&
            cancelConversationDrag.Contains("ReleaseMouseCapture", StringComparison.Ordinal) &&
            conversationCaptureLoss.Contains("CancelConversationDrag(releaseCapture: false)", StringComparison.Ordinal) &&
            cancelFollowUpDrag.Contains("Mouse.OverrideCursor = null", StringComparison.Ordinal) &&
            cancelFollowUpDrag.Contains("ReleaseMouseCapture", StringComparison.Ordinal) &&
            followUpCaptureLoss.Contains("CancelFollowUpDrag(releaseCapture: false)", StringComparison.Ordinal) &&
            beginFollowUpSettle.Contains("ReleaseFollowUpDragCapture()", StringComparison.Ordinal) &&
            windowDragCancellation.Contains("CancelConversationDrag()", StringComparison.Ordinal) &&
            windowDragCancellation.Contains("CancelFollowUpDrag()", StringComparison.Ordinal) &&
            windowDeactivation.Contains("CancelConversationDrag()", StringComparison.Ordinal) &&
            windowDeactivation.Contains("CancelFollowUpDrag()", StringComparison.Ordinal) &&
            !window.Contains("Cursors.SizeNS", StringComparison.Ordinal) &&
            window.Contains("DropShadowEffect", StringComparison.Ordinal) &&
            window.Contains("var gripBox = new Border", StringComparison.Ordinal) &&
            window.Contains("gripBox.SetResourceReference(Border.BackgroundProperty, \"PrimarySoftBrush\")", StringComparison.Ordinal) &&
            window.Contains("gripBox.SetResourceReference(Border.BorderBrushProperty, \"PrimaryBrush\")", StringComparison.Ordinal) &&
            !window.Contains("var gripRail = new Border", StringComparison.Ordinal) &&
            !window.Contains("var gripColumn = new StackPanel", StringComparison.Ordinal) &&
            window.Contains("CompositionTarget.Rendering += OnFollowUpRendering", StringComparison.Ordinal) &&
            window.Contains("UpdateFollowUpAutoScrollVelocity", StringComparison.Ordinal) &&
            window.Contains("maximumVelocity = 760", StringComparison.Ordinal) &&
            window.Contains("AnimateFollowUpNeighborDisplacement", StringComparison.Ordinal) &&
            window.Contains("BeginFollowUpSettle", StringComparison.Ordinal) &&
            window.Contains("_followUpVisualInsertionIndex == insertionIndex", StringComparison.Ordinal) &&
            window.Contains("_followUpDragPreview.IsSettled", StringComparison.Ordinal) &&
            window.Contains("TimeSpan.FromMilliseconds(650)", StringComparison.Ordinal) &&
            window.Contains("scrollViewer.ScrollableHeight", StringComparison.Ordinal) &&
            window.Contains("Key.Escape", StringComparison.Ordinal) &&
            window.Contains("ReleaseMouseCapture", StringComparison.Ordinal) &&
            window.Contains("RestoreTaskListContext", StringComparison.Ordinal) &&
            window.Contains("ConfirmDiscardUnsavedFollowUps", StringComparison.Ordinal) &&
            engine.Contains("FollowUpQueuePlanner.DescribeRuntime", StringComparison.Ordinal) &&
            engine.Contains("FollowUpQueue =", StringComparison.Ordinal) &&
            viewModel.Contains("ApplyTaskFollowUpRuntimeDisplay", StringComparison.Ordinal) &&
            recoveryModels.Contains("FollowUpQueueRuntimeSnapshot? FollowUpQueue", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool IsDragSource", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool IsEditing", StringComparison.Ordinal) &&
            recoveryModels.Contains("public string MessagePreview", StringComparison.Ordinal) &&
            recoveryModels.Contains("public string MaximumErrorRetriesText", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool RetryIndefinitely", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool IsFiniteRetry", StringComparison.Ordinal) &&
            recoveryModels.Contains("IDataErrorInfo", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool ShowDropBefore", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool ShowDropAfter", StringComparison.Ordinal) &&
            window.Contains("cursorScreenPixels.X - pointerOffset.X", StringComparison.Ordinal) &&
            window.Contains("public void Advance(double elapsedSeconds)", StringComparison.Ordinal) &&
            window.Contains("const double stiffness = 250", StringComparison.Ordinal) &&
            window.Contains("surface.SetResourceReference(Border.BackgroundProperty, \"GlassSurfaceStrongBrush\")", StringComparison.Ordinal) &&
            dragPreviewConstructor.Contains("IsHitTestVisible = false", StringComparison.Ordinal) &&
            dragPreviewConstructor.Contains("Left = -32000", StringComparison.Ordinal),
            "out-of-window drag preview, slot caching, live displacement, continuous auto-scroll, settlement, or cancellation drifted");
        Ensure(
            xaml.Contains("x:Name=\"WorkspaceViewport\"", StringComparison.Ordinal) &&
            xaml.Contains("x:Name=\"WorkspaceViewportTransform\"", StringComparison.Ordinal) &&
            window.Contains("ScheduleWorkspaceTransition", StringComparison.Ordinal) &&
            window.Contains("AnimateWorkspaceTransition", StringComparison.Ordinal) &&
            window.Contains("ApplyRouteVisibility", StringComparison.Ordinal) &&
            window.Contains("AnimateRouteReveal", StringComparison.Ordinal) &&
            window.Contains("CancelRouteRevealAnimations", StringComparison.Ordinal) &&
            window.Contains("ScheduleConversationContentTransition", StringComparison.Ordinal) &&
            window.Contains("AnimateTaskWorkbenchTransition", StringComparison.Ordinal) &&
            window.Contains("CompleteRouteReveal", StringComparison.Ordinal) &&
            window.Contains("FindToolTipOwner(Mouse.DirectlyOver)", StringComparison.Ordinal) &&
            window.Contains("ToolTipService.GetToolTip(current)", StringComparison.Ordinal) &&
            window.Contains("MouseLeave += OnSuppressedToolTipOwnerMouseLeave", StringComparison.Ordinal) &&
            window.Contains("ReadLocalValue(ToolTipService.IsEnabledProperty)", StringComparison.Ordinal) &&
            window.Contains("ClearValue(ToolTipService.IsEnabledProperty)", StringComparison.Ordinal) &&
            window.Contains("RestoreSuppressedToolTip", StringComparison.Ordinal) &&
            window.Contains("FollowUpRouteHeader", StringComparison.Ordinal) &&
            window.Contains("FollowUpMessageTimeline", StringComparison.Ordinal) &&
            window.Contains("TasksIndexHeaderStage", StringComparison.Ordinal) &&
            window.Contains("TasksSearchStage", StringComparison.Ordinal) &&
            window.Contains("TasksScopeStage", StringComparison.Ordinal) &&
            window.Contains("TaskWorkbenchHeaderStage", StringComparison.Ordinal) &&
            window.Contains("GuardrailsChannelStage", StringComparison.Ordinal) &&
            window.Contains("TasksPageRoot", StringComparison.Ordinal) &&
            window.Contains("ActivityPageRoot", StringComparison.Ordinal) &&
            window.Contains("GuardrailsPageRoot", StringComparison.Ordinal) &&
            window.Contains("PreferencesPageRoot", StringComparison.Ordinal) &&
            window.Contains("AnimateRouteElement(root, 0, TimeSpan.FromMilliseconds(260))", StringComparison.Ordinal) &&
            window.Contains("AnimateRouteElement(stage, 0, TimeSpan.FromMilliseconds(220))", StringComparison.Ordinal) &&
            window.Contains("new CubicEase", StringComparison.Ordinal) &&
            xaml.Contains("x:Name=\"ThemeUtilityButton\"", StringComparison.Ordinal) &&
            window.Contains("StartThemeTransition", StringComparison.Ordinal) &&
            window.Contains("CancelThemeTransition(keepCurrentColors: true)", StringComparison.Ordinal) &&
            window.Contains("ParallelTimeline", StringComparison.Ordinal) &&
            window.Contains("ColorAnimation", StringComparison.Ordinal) &&
            window.Contains("ApplyAnimationClock", StringComparison.Ordinal) &&
            !xaml.Contains("ThemeTransitionOverlay", StringComparison.Ordinal) &&
            !xaml.Contains("ThemeTransitionSnapshot", StringComparison.Ordinal) &&
            !window.Contains("CombinedGeometry", StringComparison.Ordinal) &&
            !window.Contains("EllipseGeometry", StringComparison.Ordinal) &&
            window.Contains("CancelThemeTransition", StringComparison.Ordinal) &&
            window.Contains("SystemParameters.ClientAreaAnimation", StringComparison.Ordinal) &&
            window.Contains("HandoffBehavior.SnapshotAndReplace", StringComparison.Ordinal),
            "the stable-shell workspace transition, replacement semantics, or reduced-motion gate drifted");
        Ensure(
            lineageElement.Ancestors().Any(element => string.Equals(
                (string?)element.Attribute(xamlNamespace + "Name"),
                "ActivityPageRoot",
                StringComparison.Ordinal)) &&
            lineageXaml.Contains("WorkflowLineageRegion", StringComparison.Ordinal) &&
            lineageXaml.Contains("WorkflowLineageEntryList", StringComparison.Ordinal) &&
            lineageXaml.Contains("WorkflowLineageStatus", StringComparison.Ordinal) &&
            lineageXaml.Contains("RefreshWorkflowLineageButton", StringComparison.Ordinal) &&
            lineageXaml.Contains("Value=\"{Binding AutomationName}\"", StringComparison.Ordinal) &&
            lineageXaml.Contains("Value=\"{Binding AutomationId}\"", StringComparison.Ordinal) &&
            lineageXaml.Contains("VirtualizingPanel.IsVirtualizing=\"True\"", StringComparison.Ordinal) &&
            lineageXaml.Contains("VirtualizingPanel.VirtualizationMode=\"Recycling\"", StringComparison.Ordinal) &&
            lineageXaml.Contains("ItemsSource=\"{Binding WorkflowLineageItems}\"", StringComparison.Ordinal) &&
            lineageXaml.Contains("{Binding MetaText}", StringComparison.Ordinal) &&
            lineageXaml.Contains("{Binding NextActionText}", StringComparison.Ordinal) &&
            lineageXaml.Contains("{Binding IndentWidth}", StringComparison.Ordinal) &&
            lineageXaml.Contains("{Binding IsCorrelationStart}", StringComparison.Ordinal) &&
            !lineageXaml.Contains("{Binding DetailText}", StringComparison.Ordinal) &&
            !lineageXaml.Contains("{Binding AttemptText}", StringComparison.Ordinal) &&
            !lineageXaml.Contains("SurfaceSubtleBrush", StringComparison.Ordinal) &&
            !lineageElement.Descendants().Any(element => element.Name.LocalName is
                "TextBox" or "ComboBox" or "CheckBox" or "ToggleButton") &&
            !lineageXaml.Contains("{Binding Message", StringComparison.Ordinal) &&
            !lineageXaml.Contains("{Binding Preview", StringComparison.Ordinal) &&
            !lineageXaml.Contains("{Binding Cwd", StringComparison.Ordinal) &&
            !lineageXaml.Contains("{Binding Attachments", StringComparison.Ordinal) &&
            !lineageXaml.Contains("SendFollowUp", StringComparison.Ordinal) &&
            !lineageXaml.Contains("ProtectionCommand", StringComparison.Ordinal) &&
            !xaml.Contains("WorkflowPageRoot", StringComparison.Ordinal) &&
            !xaml.Contains("CommandParameter=\"Workflow\"", StringComparison.Ordinal) &&
            window.Contains("ActivityLineageStage", StringComparison.Ordinal),
            "the Activity lineage region lost its read-only, virtualized, accessible route contract");
        Ensure(
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedConversationUnarchiveButton\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedConversationDeleteButton\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedConversationDeleteConfirmButton\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedConversationDeleteCancelButton\"", StringComparison.Ordinal) &&
            xaml.Contains("DataContext.UnarchiveConversationCommand", StringComparison.Ordinal) &&
            xaml.Contains("DataContext.RequestDeleteConversationCommand", StringComparison.Ordinal) &&
            xaml.Contains("DataContext.ConfirmDeleteConversationCommand", StringComparison.Ordinal) &&
            xaml.Contains("DataContext.CancelDeleteConversationCommand", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedConversationMutationProgress\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.HelpText=\"{Binding UnarchiveActionHint}\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.HelpText=\"{Binding DeleteActionHint}\"", StringComparison.Ordinal) &&
            SliceSource(
                    xaml,
                    "AutomationProperties.AutomationId=\"ArchivedConversationUnarchiveButton\"",
                    "</Grid>")
                .Split(
                    "ToolTipService.ShowOnDisabled=\"True\"",
                    StringSplitOptions.None).Length - 1 == 2 &&
            xaml.Contains("Binding IsDeleteConfirmationOpen", StringComparison.Ordinal) &&
            xaml.Contains("Binding IsConversationMutationPending", StringComparison.Ordinal) &&
            xaml.Contains("Binding HasConversationMutationStatus", StringComparison.Ordinal) &&
            xaml.Contains("<ColumnDefinition Width=\"76\" />", StringComparison.Ordinal) &&
            viewModel.Contains("Tasks.UnarchiveUnavailable", StringComparison.Ordinal) &&
            viewModel.Contains("Tasks.DeleteUnavailable", StringComparison.Ordinal) &&
            !SliceSource(
                    xaml,
                    "AutomationProperties.AutomationId=\"ArchivedConversationUnarchiveButton\"",
                    "</Grid>")
                .Contains("IsEnabled=\"False\"", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool IsConversationMutationPending", StringComparison.Ordinal) &&
            recoveryModels.Contains("public bool IsDeleteConfirmationOpen", StringComparison.Ordinal) &&
            recoveryModels.Contains("public string ConversationMutationStatusText", StringComparison.Ordinal) &&
            viewModel.Contains("ConversationMutationService? conversationMutations", StringComparison.Ordinal) &&
            viewModel.Contains("ExecuteConversationMutationAsync", StringComparison.Ordinal) &&
            viewModel.Contains("ConversationMutationUiLease", StringComparison.Ordinal) &&
            viewModel.Contains("HasDirtyDraft:", StringComparison.Ordinal) &&
            viewModel.Contains("IsStillAllowed: lease.IsAllowed", StringComparison.Ordinal) &&
            viewModel.Contains("ConversationMutationFailureKind.Uncertain", StringComparison.Ordinal) &&
            viewModel.Contains(
                "Isolated preview cannot construct a conversation mutation service.",
                StringComparison.Ordinal) &&
            appCode.Contains(
                "var conversationMutationJournal = new ConversationMutationOperationJournal(",
                StringComparison.Ordinal) &&
            appCode.Contains("if (launchOptions.AllowsLiveIntegration)", StringComparison.Ordinal) &&
            appCode.Contains("conversationMutations: conversationMutations", StringComparison.Ordinal) &&
            ReadResourceKeys(zhPath).Contains("Tasks.DeleteConfirm") &&
            ReadResourceKeys(enPath).Contains("Tasks.DeleteConfirm") &&
            !viewModel.Contains("thread/unarchive", StringComparison.Ordinal) &&
            !viewModel.Contains("thread/delete", StringComparison.Ordinal),
            "archived task actions lost owner-gated commands, inline confirmation, bounded state, preview isolation, or stable width");

        var selectedTaskSource = SliceSource(
            viewModel,
            "public GuardianTaskItem? SelectedTask",
            "public bool HasSelectedTask");
        var saveSource = SliceSource(
            viewModel,
            "private async Task SaveFollowUpMessagesAsync",
            "internal static bool TryConvertLocalScheduleToUtc");
        var navigateSource = SliceSource(
            viewModel,
            "private void Navigate",
            "private void SetAutomaticRecoveryEnabled");
        var durableSaveIndex = saveSource.IndexOf(
            "if (!await SaveSettingsAsync())",
            StringComparison.Ordinal);
        var workflowSnapshotIndex = saveSource.IndexOf(
            "CaptureDurableSnapshotAsync(",
            StringComparison.Ordinal);
        var workflowWriteIndex = saveSource.IndexOf(
            "_workflowRuleStore.SaveAsync(",
            StringComparison.Ordinal);
        var workflowRollbackIndex = saveSource.LastIndexOf(
            "TryRestoreWorkflowRuleStoreAsync",
            StringComparison.Ordinal);
        var rollbackIndex = saveSource.IndexOf(
            "Settings.ThreadFollowUps[task.Id] = previous",
            StringComparison.Ordinal);
        var policyPublishIndex = saveSource.IndexOf(
            "_engine.SetThreadFollowUps(task.Id, configured)",
            StringComparison.Ordinal);
        Ensure(
            durableSaveIndex >= 0 &&
            workflowSnapshotIndex >= 0 &&
            workflowWriteIndex > workflowSnapshotIndex &&
            workflowRollbackIndex > durableSaveIndex &&
            rollbackIndex > durableSaveIndex &&
            policyPublishIndex > durableSaveIndex &&
            policyPublishIndex > rollbackIndex &&
            saveSource.Contains(
                "var needsCompletionAnchor = SelectedFollowUpsEnabled && definitions.Any",
                StringComparison.Ordinal) &&
            saveSource.Contains("definition.IsEnabled &&", StringComparison.Ordinal),
            "settings publication, rollback, or disabled-queue baseline semantics drifted");
        Ensure(
            selectedTaskSource.Contains("_isFollowUpEditorDirty", StringComparison.Ordinal) &&
            selectedTaskSource.Contains("FollowUp.SaveBeforeTaskSwitch", StringComparison.Ordinal) &&
            selectedTaskSource.Contains("RestoreSelectedTaskBinding();", StringComparison.Ordinal) &&
            viewModel.Contains("CanSaveFollowUps() => CanEditFollowUps() && _isFollowUpEditorDirty", StringComparison.Ordinal) &&
            viewModel.Contains("OnFollowUpMessagePropertyChanged", StringComparison.Ordinal) &&
            viewModel.Contains("nameof(FollowUpMessageItem.ScheduledTimeText)", StringComparison.Ordinal) &&
            viewModel.Contains("nameof(FollowUpMessageItem.MaximumErrorRetriesText)", StringComparison.Ordinal) &&
            viewModel.Contains("EditFollowUpMessageCommand", StringComparison.Ordinal) &&
            viewModel.Contains("CloseFollowUpMessageEditorCommand", StringComparison.Ordinal) &&
            viewModel.Contains("item.TryGetMaximumErrorRetries", StringComparison.Ordinal) &&
            viewModel.Contains("public bool HasUnsavedFollowUpChanges", StringComparison.Ordinal) &&
            viewModel.Contains("internal bool MoveFollowUpMessage", StringComparison.Ordinal) &&
            viewModel.Contains("SelectedPage = \"FollowUpDetail\";", StringComparison.Ordinal) &&
            navigateSource.Contains(
                "page is \"Overview\" or \"Tasks\" or \"Recovery\" or \"KeepAlive\" or \"Settings\"",
                StringComparison.Ordinal) &&
            !navigateSource.Contains("FollowUps", StringComparison.Ordinal) &&
            !navigateSource.Contains("SafeDrill", StringComparison.Ordinal),
            "navigation, dirty tracking, or dirty task-switch protection drifted");

        var evaluateFollowUpSource = SliceSource(
            engine,
            "private async Task<GuardianTaskState> EvaluateFollowUpAsync",
            "internal static DateTimeOffset? NextAttemptAfterFailure");
        var dispatchIndex = evaluateFollowUpSource.IndexOf(
            "var result = await _followUps.ExecuteAsync",
            StringComparison.Ordinal);
        var currentPolicySource = SliceSource(
            engine,
            "private bool IsFollowUpPolicyCurrent",
            "internal static TaskHealth ActiveTaskHealth");
        var journalPolicySource = SliceSource(
            engine,
            "private bool CanUseFollowUpJournal",
            "private static IReadOnlyDictionary<string, ThreadFollowUpSettings> CaptureSchedulableFollowUps");
        var recoveryPolicySource = SliceSource(
            engine,
            "private bool IsDispatchPolicyCurrent",
            "private bool IsFollowUpPolicyCurrent");
        var recoveryEvaluationSource = SliceSource(
            engine,
            "private async Task<GuardianTaskState> EvaluateThreadAsync",
            "private async Task<GuardianTaskState> EvaluateFollowUpAsync");
        Ensure(
            dispatchIndex >= 0 &&
            !evaluateFollowUpSource.Contains("policy.MonitorOnly", StringComparison.Ordinal) &&
            !currentPolicySource.Contains("policy.MonitorOnly", StringComparison.Ordinal) &&
            !journalPolicySource.Contains("policy.MonitorOnly", StringComparison.Ordinal) &&
            recoveryPolicySource.Contains("!policy.MonitorOnly", StringComparison.Ordinal) &&
            recoveryEvaluationSource.Contains("if (policy.MonitorOnly)", StringComparison.Ordinal),
            "the preset queue inherited the automatic-recovery monitor gate or the recovery gate was removed");

        var zhKeys = ReadResourceKeys(zhPath);
        var enKeys = ReadResourceKeys(enPath);
        Ensure(
            zhKeys.SetEquals(enKeys) &&
            new[]
            {
                "Tasks.FollowUpQueue",
                "Tasks.UnarchiveUnavailable",
                "Tasks.DeleteUnavailable",
                "FollowUp.BackToTasks",
                "FollowUp.DragHandle",
                "FollowUp.ActiveQueue",
                "FollowUp.DraftSequence",
                "FollowUp.MessageEnabledShort",
                "FollowUp.TriggerCompletion",
                "FollowUp.TriggerScheduled",
                "FollowUp.Edit",
                "FollowUp.DoneEditing",
                "FollowUp.MaximumErrorRetries",
                "FollowUp.RetryShort",
                "FollowUp.RetryInfinite",
                "FollowUp.RetryDefaultHint",
                "FollowUp.InvalidRetry",
                "FollowUp.SaveFailed",
                "FollowUp.SaveBeforeTaskSwitch",
                "FollowUp.UnsavedCloseMessage"
            }.All(zhKeys.Contains),
            "the bilingual follow-up resource contract is incomplete");
        return Task.CompletedTask;
    }

    private static FollowUpMessageDefinition CompletionMessage(int order) =>
        new()
        {
            Id = Guid.NewGuid().ToString("D"),
            Message = $"completion-{order}",
            Order = order
        };

    private static CodexStructuredInputSemanticSnapshot CreateStructuredSemanticSnapshot(long epoch) =>
        new()
        {
            Acquisition = StructuredInputEvidenceAcquisition.ReadOnlyAsar,
            PackageName = "openai-codex-electron",
            ProductName = "Codex",
            PackageVersion = "26.810.41047",
            Epoch = epoch,
            FollowerMethods = new HashSet<string>(StringComparer.Ordinal)
            {
                "thread-follower-start-turn",
                "thread-follower-edit-last-user-turn"
            },
            StartTurnHostHandler = "thread-follower-start-turn-for-host",
            StartTurnAssertsOwner = true,
            NativeMethod = "turn/start",
            NativeMethodVersion = 1,
            PreservesInput = true,
            PreservesStableClientUserMessageId = true,
            NativeInputKinds = new HashSet<string>(StringComparer.Ordinal)
            {
                "text",
                "localImage"
            },
            HandlerShapeSha256 = new string('A', 64),
            InputShapeSha256 = new string('B', 64),
            SupportsAttachmentOnly = true,
            MaximumAttachmentCount = 20,
            MaximumBytesPerFile = 100L * 1024 * 1024,
            MaximumBytesPerPayload = 500L * 1024 * 1024
        };

    private static FollowUpMessageDefinition ScheduledMessage(int order, DateTimeOffset scheduledAtUtc) =>
        new()
        {
            Id = Guid.NewGuid().ToString("D"),
            Message = $"scheduled-{order}",
            Trigger = FollowUpTriggerKind.ScheduledAt,
            ScheduledAtUtc = scheduledAtUtc.ToUniversalTime(),
            Order = order
        };

    private static TurnSnapshot NormalTurn(string id) =>
        new(
            Id: id,
            Status: "completed",
            ErrorMessage: null,
            ErrorCode: null,
            HttpStatusCode: null,
            UserText: "test",
            HasAttachments: false,
            HasAssistantOutput: true,
            HasWorkOutput: true,
            OutputFingerprint: "normal-" + id,
            StartedAt: 1,
            CompletedAt: 2,
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static TurnSnapshot TerminalTurn(string id, string status) =>
        new(
            Id: id,
            Status: status,
            ErrorMessage: status,
            ErrorCode: "test",
            HttpStatusCode: 500,
            UserText: "test",
            HasAttachments: false,
            HasAssistantOutput: false,
            HasWorkOutput: false,
            OutputFingerprint: status + "-" + id,
            StartedAt: 1,
            CompletedAt: 2,
            HasConfirmedLocalTerminal: !string.Equals(
                status,
                "inProgress",
                StringComparison.OrdinalIgnoreCase),
            HasUserMessage: true,
            HasFinalAssistantOutput: false,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static FollowUpOperationRecord Operation(
        FollowUpMessageDefinition message,
        string expectedTurnId,
        FollowUpOperationState state,
        string? newTurnId = null,
        int? attemptCount = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            OperationId: Guid.NewGuid().ToString("D"),
            ThreadId: Guid.NewGuid().ToString("D"),
            MessageId: message.Id,
            Trigger: message.Trigger,
            ExpectedTurnId: expectedTurnId,
            ScheduledAtUtc: message.ScheduledAtUtc,
            MessageHash: FollowUpOperationJournal.ComputeMessageHash(message.Message),
            State: state,
            ClientMessageId: Guid.NewGuid().ToString("D"),
            NewTurnId: newTurnId,
            CompletionTurnId: null,
            CreatedAt: now,
            UpdatedAt: now,
            AttemptCount: attemptCount ?? (state == FollowUpOperationState.Prepared ? 0 : 1));
    }

    private static ThreadSummary RootThread(string id) =>
        new(
            Id: id,
            Name: "Follow-up test task",
            Preview: string.Empty,
            Cwd: "D:\\follow-up-test",
            Source: "cli",
            CreatedAt: 1,
            UpdatedAt: 2,
            IsSubAgent: false,
            IsEphemeral: false,
            RuntimeStatus: "idle",
            IsArchived: false);

    private static RecoveryInterferenceSnapshot ClearInterference() =>
        new(
            RecoveryInterferenceStatus.Clear,
            "The test editor is clear.",
            HasFocusedDraft: false,
            DateTimeOffset.UtcNow);

    private static RecoveryInterferenceSnapshot EditingInterference() =>
        new(
            RecoveryInterferenceStatus.Editing,
            "The test editor contains an active draft.",
            HasFocusedDraft: true,
            DateTimeOffset.UtcNow);

    private static async Task<FollowUpOperationRecord> CreateConfirmedOperationAsync(
        FollowUpOperationJournal journal,
        string threadId,
        FollowUpMessageDefinition message,
        bool markCompleted)
    {
        var expectedTurnId = Guid.NewGuid().ToString("D");
        var successorTurnId = Guid.NewGuid().ToString("D");
        var operationId = FollowUpOperationJournal.CreateOperationId(threadId, message.Id, expectedTurnId);
        await journal.GetOrCreateAsync(
            operationId,
            threadId,
            message.Id,
            message.Trigger,
            expectedTurnId,
            message.ScheduledAtUtc,
            FollowUpOperationJournal.ComputeMessageHash(message.Message),
            FollowUpOperationJournal.CreateClientMessageId(operationId));
        await journal.TryTransitionAsync(
            operationId,
            FollowUpOperationState.Prepared,
            FollowUpOperationState.Dispatching);
        await journal.TryTransitionAsync(
            operationId,
            FollowUpOperationState.Dispatching,
            FollowUpOperationState.Confirmed,
            successorTurnId);
        if (markCompleted)
        {
            await journal.MarkCompletedAsync(threadId, successorTurnId, recoveredFromTurnId: null);
        }

        return (await journal.ReadAsync()).Records.Single(record => record.OperationId == operationId);
    }

    private static async Task<FollowUpOperationRecord> PrepareUniqueOperationAsync(
        FollowUpOperationJournal journal,
        string message)
    {
        var threadId = Guid.NewGuid().ToString("D");
        var messageId = Guid.NewGuid().ToString("D");
        var expectedTurnId = Guid.NewGuid().ToString("D");
        var operationId = FollowUpOperationJournal.CreateOperationId(threadId, messageId, expectedTurnId);
        return (await journal.GetOrCreateAsync(
            operationId,
            threadId,
            messageId,
            FollowUpTriggerKind.AfterNormalCompletion,
            expectedTurnId,
            null,
            FollowUpOperationJournal.ComputeMessageHash(message),
            FollowUpOperationJournal.CreateClientMessageId(operationId))).Record;
    }

    private static string SliceSource(string source, string startToken, string endToken)
    {
        var start = source.IndexOf(startToken, StringComparison.Ordinal);
        var end = start < 0
            ? -1
            : source.IndexOf(endToken, start + startToken.Length, StringComparison.Ordinal);
        return start >= 0 && end > start ? source[start..end] : string.Empty;
    }

    // XAML comments are inert markup, so a Contains assertion that counts them as evidence can be
    // satisfied by a comment while the live attribute does the opposite. Strip them before asserting.
    private static string StripXamlComments(string source)
    {
        var builder = new StringBuilder(source.Length);
        var cursor = 0;
        while (cursor < source.Length)
        {
            var open = source.IndexOf("<!--", cursor, StringComparison.Ordinal);
            if (open < 0)
            {
                builder.Append(source, cursor, source.Length - cursor);
                break;
            }

            builder.Append(source, cursor, open - cursor);
            var close = source.IndexOf("-->", open + 4, StringComparison.Ordinal);
            if (close < 0)
            {
                break;
            }

            cursor = close + 3;
        }

        return builder.ToString();
    }

    // Collects every value of the given attribute, e.g. every x:Key in a resource dictionary.
    private static HashSet<string> CollectAttributeValues(string markup, string attribute)
    {
        var values = new HashSet<string>(StringComparer.Ordinal);
        var token = attribute + "=\"";
        var cursor = 0;
        while (true)
        {
            var start = markup.IndexOf(token, cursor, StringComparison.Ordinal);
            if (start < 0)
            {
                break;
            }

            var valueStart = start + token.Length;
            var valueEnd = markup.IndexOf('"', valueStart);
            if (valueEnd < 0)
            {
                break;
            }

            values.Add(markup[valueStart..valueEnd]);
            cursor = valueEnd + 1;
        }

        return values;
    }

    private static void VerifyThemePaletteContract(string appXaml)
    {
        var light = ReadThemePalette("LightThemePalette");
        var dark = ReadThemePalette("DarkThemePalette");
        string[] surfaces =
        [
            "CanvasBrush", "PaperBrush", "SurfaceSubtleBrush", "GlassSurfaceBrush",
            "GlassSurfaceStrongBrush", "ConversationSurfaceBrush", "ConversationHoverBrush",
            "ConversationSelectedBrush", "ControlSurfaceBrush", "ControlHoverBrush", "FieldSurfaceBrush"
        ];
        string[] required =
        [
            .. surfaces, "InkBrush", "InkMutedBrush", "InkSubtleBrush", "PrimaryBrush", "SignatureBrush",
            "GlassBorderBrush", "BorderBrush", "BorderStrongBrush", "DisabledInkBrush",
            "DisabledSurfaceBrush", "GreenBrush", "OrangeBrush", "YellowBrush", "DangerBrush"
        ];
        Ensure(new HashSet<string>(light.Keys, StringComparer.Ordinal).SetEquals(dark.Keys) &&
            required.All(key => light.ContainsKey(key) && dark.ContainsKey(key)),
            "light and dark theme palettes lost required semantic roles or key parity");
        Ensure(surfaces.All(key => light[key] != dark[key]) && light["InkBrush"] != dark["InkBrush"] &&
            RelativeLuminance(light["CanvasBrush"]) > RelativeLuminance(dark["CanvasBrush"]),
            "light and dark themes must have independently tuned surfaces and primary text");

        foreach (var (name, palette) in new[] { ("light", light), ("dark", dark) })
        {
            Ensure(palette["PrimaryBrush"] == palette["SignatureBrush"],
                name + " theme split the primary and signature accent roles");
            var canvas = palette["CanvasBrush"];
            Ensure(canvas.A == byte.MaxValue, name + " theme canvas must define an opaque contrast backdrop");
            foreach (var role in surfaces)
            {
                var surface = CompositeOver(palette[role], canvas);
                var ink = CompositeOver(palette["InkBrush"], surface);
                var inkLuminance = RelativeLuminance(ink);
                var surfaceLuminance = RelativeLuminance(surface);
                var ratio = (Math.Max(inkLuminance, surfaceLuminance) + 0.05) /
                    (Math.Min(inkLuminance, surfaceLuminance) + 0.05);
                Ensure(ratio >= 4.5,
                    $"{name} primary text contrast against {role} is {ratio:F2}:1, below 4.5:1");
            }
        }

        var app = XDocument.Parse(appXaml);
        XNamespace xamlNamespace = "http://schemas.microsoft.com/winfx/2006/xaml";
        var bootstrapAccents = new[] { "PrimaryBrush", "SignatureBrush" }.Select(key =>
            ParseThemeColor((string?)app.Descendants().Single(element =>
                (string?)element.Attribute(xamlNamespace + "Key") == key).Attribute("Color") ??
                throw new InvalidOperationException("Missing bootstrap accent color: " + key))).ToArray();
        Ensure(bootstrapAccents.All(color => color == dark["PrimaryBrush"]),
            "the dark-first bootstrap colors do not preserve the runtime primary/signature alias");
    }

    private static Dictionary<string, WpfColor> ReadThemePalette(string fieldName)
    {
        // Read the production palette without constructing a Window or starting the Application.
        var palette = typeof(MainWindow).GetField(
                fieldName,
                System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)?.GetValue(null)
            as IReadOnlyDictionary<string, string> ??
            throw new InvalidOperationException("Missing production theme palette: " + fieldName);
        return palette.ToDictionary(pair => pair.Key, pair => ParseThemeColor(pair.Value), StringComparer.Ordinal);
    }

    private static WpfColor ParseThemeColor(string value) =>
        System.Windows.Media.ColorConverter.ConvertFromString(value) is WpfColor color
            ? color
            : throw new InvalidOperationException("Invalid theme color: " + value);

    private static WpfColor CompositeOver(WpfColor foreground, WpfColor background)
    {
        var alpha = foreground.A / 255d;
        return WpfColor.FromRgb(
            (byte)Math.Round(foreground.R * alpha + background.R * (1 - alpha)),
            (byte)Math.Round(foreground.G * alpha + background.G * (1 - alpha)),
            (byte)Math.Round(foreground.B * alpha + background.B * (1 - alpha)));
    }

    private static double RelativeLuminance(WpfColor color)
    {
        static double Linear(byte channel)
        {
            var value = channel / 255d;
            return value <= 0.04045 ? value / 12.92 : Math.Pow((value + 0.055) / 1.055, 2.4);
        }

        return 0.2126 * Linear(color.R) + 0.7152 * Linear(color.G) + 0.0722 * Linear(color.B);
    }

    // Collects the key named by every {DynamicResource X} / {StaticResource X} markup extension.
    // WPF resolves these at runtime and fails silently: a missing DynamicResource simply leaves the
    // property unset, so a typo surfaces only as an unpainted surface, never as an exception.
    private static HashSet<string> CollectResourceReferences(string markup, string extension)
    {
        var references = new HashSet<string>(StringComparer.Ordinal);
        var token = "{" + extension + " ";
        var cursor = 0;
        while (true)
        {
            var start = markup.IndexOf(token, cursor, StringComparison.Ordinal);
            if (start < 0)
            {
                break;
            }

            var keyStart = start + token.Length;
            var keyEnd = markup.IndexOfAny(['}', ',', ' '], keyStart);
            if (keyEnd < 0)
            {
                break;
            }

            references.Add(markup[keyStart..keyEnd]);
            cursor = keyEnd;
        }

        return references;
    }

    // Collects the palette keys declared as ["Name"] = "#AARRGGBB" in the theme dictionaries.
    private static HashSet<string> CollectPaletteKeys(string code)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var cursor = 0;
        while (true)
        {
            var start = code.IndexOf("[\"", cursor, StringComparison.Ordinal);
            if (start < 0)
            {
                break;
            }

            var keyStart = start + 2;
            var keyEnd = code.IndexOf('"', keyStart);
            if (keyEnd < 0)
            {
                break;
            }

            var tail = code.AsSpan(keyEnd + 1);
            if (tail.StartsWith("] = \"#", StringComparison.Ordinal))
            {
                keys.Add(code[keyStart..keyEnd]);
            }

            cursor = keyEnd + 1;
        }

        return keys;
    }

    // The keep-alive row guard bans the hex spellings of a hard-coded colour, but a colour can leave the
    // palette without a single '#': Value="Black", an scRGB triple, or a gradient brush whose stops are
    // literal. Enumerating spellings is a losing game, so this inverts the check -- it collects every
    // assignment to a property that paints something and returns the ones whose value is not a markup
    // extension, which is the only kind of value ApplyThemePalette can reach at all.
    private static string[] CollectLiteralPaintAssignments(string markup)
    {
        string[] paintProperties =
        [
            "Background",
            "BorderBrush",
            "Fill",
            "Stroke",
            "Foreground",
            "OpacityMask"
        ];

        var offenders = new List<string>();
        foreach (var property in paintProperties)
        {
            var token = property + "=\"";
            var cursor = 0;
            while (true)
            {
                var start = markup.IndexOf(token, cursor, StringComparison.Ordinal);
                if (start < 0)
                {
                    break;
                }

                cursor = start + token.Length;

                // Guard against matching the tail of a longer name: KeepAliveRowBackground="..." ends in
                // Background=" but is a different property. A '.' prefix is kept, because that is how an
                // attached property is spelled (TextElement.Foreground) and it paints just the same.
                if (start > 0 && IsXamlNameCharacter(markup[start - 1]))
                {
                    continue;
                }

                var valueEnd = markup.IndexOf('"', cursor);
                if (valueEnd < 0)
                {
                    break;
                }

                var value = markup[cursor..valueEnd];
                if (!IsThemeReachablePaintValue(value))
                {
                    offenders.Add(property + "=\"" + value + "\"");
                }

                cursor = valueEnd + 1;
            }
        }

        // A Setter carries the property name in one attribute and the colour in another, so the scan above
        // never sees it. Both attribute orders occur in real XAML, so the tag is read as a whole. A Setter
        // with no Value attribute is the property-element form, whose brush lands in a child element that
        // the <SolidColorBrush and gradient-brush bans already cover.
        var setterCursor = 0;
        while (true)
        {
            var open = markup.IndexOf("<Setter", setterCursor, StringComparison.Ordinal);
            if (open < 0)
            {
                break;
            }

            var close = markup.IndexOf('>', open);
            if (close < 0)
            {
                break;
            }

            setterCursor = close + 1;
            var tag = markup[open..close];
            var property = ReadXamlAttribute(tag, "Property");
            var value = ReadXamlAttribute(tag, "Value");
            if (property is null || value is null)
            {
                continue;
            }

            var bareProperty = property[(property.LastIndexOf('.') + 1)..];
            if (Array.IndexOf(paintProperties, bareProperty) >= 0 && !IsThemeReachablePaintValue(value))
            {
                offenders.Add("Setter " + property + "=\"" + value + "\"");
            }
        }

        return offenders.ToArray();
    }

    // Only a markup extension survives a theme flip: {DynamicResource X} re-reads the dictionary
    // ApplyThemePalette rewrites, and {Binding} / {TemplateBinding} defer to something that does. A literal
    // -- hex, scRGB, or a named colour -- is baked into the BAML and stays put through every theme change.
    // "{}" is XAML's escape for a value that merely starts with a brace, so it is a literal too.
    // Transparent is the one literal that is safe, because it paints nothing in either palette while still
    // taking part in hit testing, which is what the hover veil's resting state needs.
    private static bool IsThemeReachablePaintValue(string value) =>
        value.Equals("Transparent", StringComparison.Ordinal) ||
        (value.StartsWith('{') && !value.StartsWith("{}", StringComparison.Ordinal));

    private static bool IsXamlNameCharacter(char value) => value == '_' || char.IsLetterOrDigit(value);

    private static string? ReadXamlAttribute(string tag, string attribute)
    {
        var token = attribute + "=\"";
        var cursor = 0;
        while (true)
        {
            var start = tag.IndexOf(token, cursor, StringComparison.Ordinal);
            if (start < 0)
            {
                return null;
            }

            cursor = start + token.Length;
            if (start > 0 && IsXamlNameCharacter(tag[start - 1]))
            {
                continue;
            }

            var end = tag.IndexOf('"', cursor);
            return end < 0 ? null : tag[cursor..end];
        }
    }

    private static HashSet<string> ReadResourceKeys(string path)
    {
        var document = XDocument.Load(path, LoadOptions.None);
        return document.Root!
            .Elements("data")
            .Select(element => (string?)element.Attribute("name"))
            .Where(name => name is not null)
            .Select(name => name!)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static string FindGuardianSourceRoot()
    {
        var current = Directory.GetCurrentDirectory();
        var candidates = new[]
        {
            Path.Combine(current, "work", "CodexGuardian"),
            Path.Combine(current, "CodexGuardian")
        };
        return candidates.FirstOrDefault(candidate =>
                   File.Exists(Path.Combine(candidate, "MainWindow.xaml")) &&
                   File.Exists(Path.Combine(candidate, "Services", "GuardianEngine.cs")))
               ?? throw new DirectoryNotFoundException(
                   "The FollowUp source contract requires the project checkout as the test working directory.");
    }

    private static async Task WithIsolatedRootAsync(Func<string, Task> action)
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "CodexGuardian",
            "follow-up-offline-" + Guid.NewGuid().ToString("N"));
        try
        {
            await action(root);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static Task RunOnStaDispatcherAsync(Func<Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        var completion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            Exception? failure = null;
            try
            {
                var dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(
                    new DispatcherSynchronizationContext(dispatcher));
                _ = dispatcher.InvokeAsync(async () =>
                {
                    try
                    {
                        await action();
                    }
                    catch (Exception exception)
                    {
                        failure = exception;
                    }
                    finally
                    {
                        dispatcher.BeginInvokeShutdown(DispatcherPriority.Background);
                    }
                });
                Dispatcher.Run();
            }
            catch (Exception exception)
            {
                failure = exception;
            }

            if (failure is null)
            {
                completion.TrySetResult();
            }
            else
            {
                completion.TrySetException(failure);
            }
        })
        {
            IsBackground = true,
            Name = "CodexGuardian.FollowUpPreviewFixture"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task;
    }

    private sealed class FollowUpDispatchFixture : IDisposable
    {
        internal FollowUpDispatchFixture(
            string root,
            IRecoveryInterferenceGuard? interferenceGuard = null)
        {
            Thread = RootThread(Guid.NewGuid().ToString("D"));
            ExpectedTurn = NormalTurn(Guid.NewGuid().ToString("D"));
            Message = CompletionMessage(0);
            StateReader = new FakeFollowUpStateReader(Thread, ExpectedTurn);
            Desktop = new FakeFollowUpDesktopChannel(Thread, ExpectedTurn);
            Owner = new FakeFollowUpOwnerActivator();
            Journal = new FollowUpOperationJournal(root);
            Log = new GuardianLog(root);
            Service = new FollowUpDispatchService(
                StateReader,
                Desktop,
                Owner,
                Journal,
                Log,
                interferenceGuard ?? new SequenceFollowUpInterferenceGuard(
                    static _ => ClearInterference(),
                    static _ => ClearInterference()));
        }

        internal ThreadSummary Thread { get; }

        internal TurnSnapshot ExpectedTurn { get; }

        internal FollowUpMessageDefinition Message { get; }

        internal FakeFollowUpStateReader StateReader { get; }

        internal FakeFollowUpDesktopChannel Desktop { get; }

        internal FakeFollowUpOwnerActivator Owner { get; }

        internal FollowUpOperationJournal Journal { get; }

        internal GuardianLog Log { get; }

        internal FollowUpDispatchService Service { get; }

        public void Dispose() => Log.Dispose();
    }

    private sealed class FakeFollowUpStateReader(
        ThreadSummary thread,
        TurnSnapshot latestTurn) : IFollowUpStateReader
    {
        internal Dictionary<string, TurnSnapshot> ReconciledTurns { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal List<string> ReconciledClientMessageIds { get; } = [];

        public Task<TurnSnapshot?> ReadLatestTurnAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "the dispatch state reader targeted a different task");
            return Task.FromResult<TurnSnapshot?>(latestTurn);
        }

        public Task<ThreadSummary> ReadThreadForRecoveryAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "the eligibility reader targeted a different task");
            return Task.FromResult(thread);
        }

        public Task<TurnSnapshot?> FindRecentTurnByClientMessageIdAsync(
            string threadId,
            string clientMessageId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "the reconciliation reader targeted a different task");
            ReconciledClientMessageIds.Add(clientMessageId);
            return Task.FromResult<TurnSnapshot?>(
                ReconciledTurns.TryGetValue(clientMessageId, out var matching) ? matching : null);
        }
    }

    private sealed class SequenceStructuredCapabilityProvider(
        Func<int, DesktopStructuredInputCapabilities> select) : IDesktopStructuredInputCapabilityProvider
    {
        internal int ReadCount { get; private set; }

        public Task<DesktopStructuredInputCapabilities> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCount++;
            return Task.FromResult(select(ReadCount));
        }
    }

    private sealed class FakeFollowUpDesktopChannel : IFollowUpDesktopChannel
    {
        private readonly ThreadSummary _thread;
        private readonly TurnSnapshot _expectedTurn;

        internal FakeFollowUpDesktopChannel(ThreadSummary thread, TurnSnapshot expectedTurn)
        {
            _thread = thread;
            _expectedTurn = expectedTurn;
            StartResult = new DesktopStartTurnResult(Guid.NewGuid().ToString("D"));
        }

        public bool SupportsGuardedAutomaticSend { get; set; } = true;

        internal DesktopStartTurnResult StartResult { get; set; }

        internal DesktopIpcProtocolException? ProtocolException { get; set; }

        internal DesktopIpcDeliveryException? DeliveryException { get; set; }

        internal Action? BeforeWritePredicate { get; set; }

        internal int WritePredicateCount { get; private set; }

        internal bool PredicateObservedWhileWriteGateHeld { get; private set; }

        internal int StartCount { get; private set; }

        internal int StructuredStartCount { get; private set; }

        internal StructuredPresetPayload? LastStructuredPayload { get; private set; }

        internal DesktopStructuredInputCapabilities? LastStructuredCapabilities { get; private set; }

        internal DesktopStructuredInputCapabilityLease? LastStructuredCapabilityLease { get; private set; }

        internal IReadOnlyDictionary<string, string>? LastPresentationPaths { get; private set; }

        internal List<string> StartThreadIds { get; } = [];

        internal List<string> StartMessages { get; } = [];

        internal List<string> StartClientMessageIds { get; } = [];

        internal FakeFollowUpOwnerStateGuard? LastGuard { get; private set; }

        public Task<FollowUpOwnerStateGuardAcquireResult> AcquireThreadOwnerStateGuardAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, _thread.Id, StringComparison.OrdinalIgnoreCase),
                "the Desktop owner guard targeted a different task");
            LastGuard = new FakeFollowUpOwnerStateGuard(new DesktopThreadOwnerStateSnapshot(
                _thread.Id,
                "test-host",
                "test-owner",
                Revision: 1,
                RuntimeStatus: "idle",
                LatestTurnId: _expectedTurn.Id,
                LatestTurnStatus: "completed"));
            return Task.FromResult(new FollowUpOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Available,
                LastGuard,
                "The fake owner guard is available."));
        }

        public System.Text.Json.JsonElement EncodeStructuredTurnInput(
            StructuredPresetPayload payload,
            DesktopStructuredInputCapabilities capabilities,
            DesktopStructuredInputCapabilityLease capabilityLease,
            IReadOnlyDictionary<string, string> presentationPaths)
        {
            if (!capabilities.Matches(capabilityLease, payload))
            {
                throw new DesktopStructuredInputCapabilityException(
                    "capability-lease-stale",
                    "The fake structured-input capability lease is stale.");
            }

            return new DesktopStructuredInputEncoder().Encode(
                payload,
                capabilities,
                presentationPaths);
        }

        public Task<DesktopStartTurnResult> StartTextTurnAsync(
            string threadId,
            string message,
            string clientMessageId,
            CancellationToken cancellationToken,
            Func<bool> canStartWrite)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (ProtocolException is not null)
            {
                throw ProtocolException;
            }

            if (DeliveryException is not null)
            {
                throw DeliveryException;
            }

            var writeGateHeld = true;
            try
            {
                BeforeWritePredicate?.Invoke();
                WritePredicateCount++;
                PredicateObservedWhileWriteGateHeld |= writeGateHeld;
                if (!canStartWrite())
                {
                    throw new DesktopIpcDeliveryException(
                        DesktopIpcDeliveryStage.NotDispatched,
                        "The fake guarded write predicate rejected the request.");
                }
            }
            finally
            {
                writeGateHeld = false;
            }

            StartCount++;
            StartThreadIds.Add(threadId);
            StartMessages.Add(message);
            StartClientMessageIds.Add(clientMessageId);
            return Task.FromResult(StartResult);
        }

        public Task<DesktopStartTurnResult> StartStructuredTurnAsync(
            string threadId,
            StructuredPresetPayload payload,
            DesktopStructuredInputCapabilities capabilities,
            DesktopStructuredInputCapabilityLease capabilityLease,
            IReadOnlyDictionary<string, string> presentationPaths,
            string clientMessageId,
            CancellationToken cancellationToken,
            Func<bool> canStartWrite)
        {
            StructuredStartCount++;
            LastStructuredPayload = payload;
            LastStructuredCapabilities = capabilities;
            LastStructuredCapabilityLease = capabilityLease;
            LastPresentationPaths = presentationPaths;
            return StartTextTurnAsync(
                threadId,
                payload.Text,
                clientMessageId,
                cancellationToken,
                canStartWrite);
        }
    }

    private sealed class FakeFollowUpOwnerStateGuard(
        DesktopThreadOwnerStateSnapshot snapshot) : IFollowUpOwnerStateGuard
    {
        public DesktopThreadOwnerStateSnapshot Snapshot { get; } = snapshot;

        public bool IsCurrent { get; set; } = true;

        internal int DisposeCount { get; private set; }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeFollowUpOwnerActivator : IFollowUpOwnerActivator
    {
        internal DesktopThreadOwnerActivationResult Activation { get; set; } =
            new(DesktopThreadOwnerActivationStatus.AlreadyAvailable, "The fake owner is available.");

        internal DesktopUserActivityResult Activity { get; set; } =
            new(DesktopUserActivityStatus.Idle, "The fake desktop is idle.");

        public Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            _ = threadId;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Activation);
        }

        public DesktopUserActivityResult CheckUserActivity() => Activity;
    }

    private sealed class SequenceFollowUpInterferenceGuard(
        params Func<CancellationToken, RecoveryInterferenceSnapshot>[] checks) : IRecoveryInterferenceGuard
    {
        private int _checkCount;

        internal int CheckCount => Volatile.Read(ref _checkCount);

        public Task<RecoveryInterferenceSnapshot> CheckAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            _ = threadId;
            cancellationToken.ThrowIfCancellationRequested();
            var index = Interlocked.Increment(ref _checkCount) - 1;
            if (index >= checks.Length)
            {
                throw new InvalidOperationException("The dispatch performed an unexpected editor check.");
            }

            return Task.FromResult(checks[index](cancellationToken));
        }

        public Task WaitForChangeAsync(long observedVersion, CancellationToken cancellationToken)
        {
            _ = observedVersion;
            return Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    private static async Task<bool> ThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static async Task ExecuteCommandAndWaitAsync(
        System.Windows.Input.ICommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        var completed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var observedRunning = false;
        EventHandler? handler = null;
        handler = (_, _) =>
        {
            if (!command.CanExecute(null))
            {
                observedRunning = true;
            }
            else if (observedRunning)
            {
                completed.TrySetResult();
            }
        };
        command.CanExecuteChanged += handler;
        try
        {
            command.Execute(null);
            await completed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            command.CanExecuteChanged -= handler;
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> action,
        Action<bool, string> assert)
    {
        try
        {
            await action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static int CountOccurrences(string source, string value)
    {
        var count = 0;
        var index = 0;
        while ((index = source.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }

        return count;
    }

    private static void Ensure(bool condition, string detail)
    {
        if (!condition)
        {
            throw new InvalidOperationException(detail);
        }
    }
}
