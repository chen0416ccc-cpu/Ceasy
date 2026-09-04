using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class WorkflowActionExecutorOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow executor reuses owner preflight and one stable at-most-once identity",
            TestExistingConversationSendAsync,
            assert);
        await RunCaseAsync(
            "workflow executor reconciles uncertain owner delivery without redispatch",
            TestUncertainSendReconciliationAsync,
            assert);
        await RunCaseAsync(
            "workflow executor blocks same-generation no-progress sends before owner write",
            TestNoProgressSendAsync,
            assert);
        await RunCaseAsync(
            "workflow executor blocks a prepared send after clock rollback before owner write",
            TestClockRollbackSendAsync,
            assert);
        await RunCaseAsync(
            "workflow executor confirms idempotent protection with a typed settings receipt",
            TestProtectionActionAsync,
            assert);
        await RunCaseAsync(
            "workflow executor projects a full correlation budget as blocked before protection write",
            TestProtectionDispatchBudgetAsync,
            assert);
        await RunCaseAsync(
            "workflow executor persists retry exhaustion before another owner write",
            TestRetryExhaustionAsync,
            assert);
        await RunCaseAsync(
            "workflow executor keeps new-conversation actions truthfully unavailable",
            TestNewConversationUnavailableAsync,
            assert);
    }

    private static async Task TestExistingConversationSendAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var confirmations = new List<WorkflowActionOperationRecord>();
        ((IWorkflowPresetDispatchConfirmationSource)fixture.Executor).PresetDispatchConfirmed +=
            (_, eventArgs) => confirmations.Add(eventArgs.Action);
        var preset = Preset(Guid.NewGuid().ToString("D"), "continue with the next verified step");
        var rule = SendRule(fixture.Target.Id, preset.Id);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "send-1");
        var result = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target,
            fixture.LatestTurn,
            rule.OwnerConversationId,
            preset,
            includeSubAgents: false,
            isDispatchAllowed: static () => true);
        var outer = (await fixture.WorkflowJournal.ReadAsync()).Actions.Single();
        var inner = (await fixture.FollowUpJournal.ReadAsync()).Records.Single();
        Ensure(
            result.Status == WorkflowActionExecutionStatus.Confirmed &&
            outer.State == WorkflowActionOperationState.Confirmed &&
            outer.GeneratedTurnId == fixture.Desktop.StartResult.TurnId &&
            outer.ExecutionFingerprint == StructuredPresetPayload.Create(
                preset.Message,
                preset.Attachments).PayloadDigest &&
            outer.AuthoritativeTargetGeneration == fixture.Desktop.OwnerRevision &&
            inner.SourceKind == FollowUpPayloadSourceKind.WorkflowPreset &&
            inner.OperationId == outer.ActionOperationId &&
            inner.ClientMessageId == outer.ClientMessageId &&
            inner.State == FollowUpOperationState.Confirmed &&
            fixture.Desktop.StartInvocationCount == 1 &&
            fixture.Desktop.StartClientMessageIds.SequenceEqual([outer.ClientMessageId!]) &&
            fixture.Owner.ActivationCount == 1 && fixture.Desktop.GuardAcquireCount == 1 &&
            fixture.Interference.CheckCount >= 2 && fixture.Desktop.WritePredicateCount == 1 &&
            confirmations.Count == 1 &&
            confirmations[0].ActionOperationId == outer.ActionOperationId,
            "workflow send bypassed a preflight gate or split its durable identity");

        var repeated = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target,
            fixture.LatestTurn,
            rule.OwnerConversationId,
            preset,
            includeSubAgents: false,
            isDispatchAllowed: static () => true);
        Ensure(
            repeated.Status == WorkflowActionExecutionStatus.Confirmed &&
            fixture.Desktop.StartInvocationCount == 1 && confirmations.Count == 1,
            "confirmed workflow send was dispatched more than once");
    }

    private static async Task TestUncertainSendReconciliationAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var confirmations = new List<WorkflowActionOperationRecord>();
        ((IWorkflowPresetDispatchConfirmationSource)fixture.Executor).PresetDispatchConfirmed +=
            (_, eventArgs) => confirmations.Add(eventArgs.Action);
        var preset = Preset(Guid.NewGuid().ToString("D"), "inspect the uncertain delivery");
        var rule = SendRule(fixture.Target.Id, preset.Id);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "send-2");
        fixture.Desktop.DeliveryException = new DesktopIpcDeliveryException(
            DesktopIpcDeliveryStage.DispatchedUnknown,
            "acknowledgement lost after the owner write");
        var first = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target,
            fixture.LatestTurn,
            rule.OwnerConversationId,
            preset,
            false,
            static () => true);
        var uncertain = (await fixture.WorkflowJournal.ReadAsync()).Actions.Single();
        Ensure(
            first.Status == WorkflowActionExecutionStatus.Uncertain &&
            uncertain.State == WorkflowActionOperationState.Uncertain &&
            fixture.Desktop.StartInvocationCount == 1 && confirmations.Count == 0,
            "unknown owner delivery was not retained as uncertain");

        fixture.Desktop.DeliveryException = null;
        var repeated = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target,
            fixture.LatestTurn,
            rule.OwnerConversationId,
            preset,
            false,
            static () => true);
        Ensure(
            repeated.Status == WorkflowActionExecutionStatus.Uncertain &&
            fixture.Desktop.StartInvocationCount == 1,
            "uncertain workflow delivery was blindly resent");

        var reconciledTurn = NormalTurn(Guid.NewGuid().ToString("D"));
        fixture.StateReader.ReconciledTurns[uncertain.ClientMessageId!] = reconciledTurn;
        var reconciled = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target,
            fixture.LatestTurn,
            rule.OwnerConversationId,
            preset,
            false,
            static () => true);
        Ensure(
            reconciled.Status == WorkflowActionExecutionStatus.Confirmed &&
            reconciled.Record?.GeneratedTurnId == reconciledTurn.Id &&
            fixture.Desktop.StartInvocationCount == 1 &&
            confirmations.Count == 1 &&
            confirmations[0].GeneratedTurnId == reconciledTurn.Id,
            "authoritative client-id readback did not close uncertainty without redispatch");
    }

    private static async Task TestNoProgressSendAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var firstPreset = Preset(Guid.NewGuid().ToString("D"), "same payload");
        var secondPreset = Preset(Guid.NewGuid().ToString("D"), "same payload");
        var rule = WorkflowRuleDefinition.Create(
            Guid.NewGuid().ToString("D"),
            1,
            fixture.Target.Id,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(fixture.Target.Id),
            null,
            [Send(fixture.Target.Id, firstPreset.Id, 0), Send(fixture.Target.Id, secondPreset.Id, 1)]);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "send-3");
        var first = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target,
            fixture.LatestTurn,
            fixture.Target.Id,
            firstPreset,
            false,
            static () => true);
        Ensure(first.Status == WorkflowActionExecutionStatus.Confirmed, "first no-progress fixture send failed");

        fixture.LatestTurn = NormalTurn(first.Record!.GeneratedTurnId!);
        var second = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            1,
            fixture.Target,
            fixture.LatestTurn,
            fixture.Target.Id,
            secondPreset,
            false,
            static () => true);
        Ensure(
            second.Status == WorkflowActionExecutionStatus.Blocked &&
            second.Record?.FailureClass == "no-progress" &&
            fixture.Desktop.StartInvocationCount == 1,
            "same-generation no-progress send reached the owner write");
    }

    private static async Task TestClockRollbackSendAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var confirmations = new List<WorkflowActionOperationRecord>();
        ((IWorkflowPresetDispatchConfirmationSource)fixture.Executor).PresetDispatchConfirmed +=
            (_, eventArgs) => confirmations.Add(eventArgs.Action);
        var preset = Preset(Guid.NewGuid().ToString("D"), "clock rollback must stay unsent");
        var rule = SendRule(fixture.Target.Id, preset.Id);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "clock-rollback");
        _ = await fixture.WorkflowJournal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target.Id);

        fixture.Clock.SetUtcNow(Activation.AddHours(2).AddMinutes(30));
        var result = await fixture.Executor.ExecuteSendPresetAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target,
            fixture.LatestTurn,
            rule.OwnerConversationId,
            preset,
            includeSubAgents: false,
            isDispatchAllowed: static () => true);
        var outer = (await fixture.WorkflowJournal.ReadAsync()).Actions.Single();
        var inner = await fixture.FollowUpJournal.ReadAsync();
        Ensure(
            result.Status == WorkflowActionExecutionStatus.Blocked &&
            outer is
            {
                State: WorkflowActionOperationState.Blocked,
                AttemptCount: 0,
                FailureClass: "correlation-clock-invalid"
            } &&
            fixture.Desktop.StartInvocationCount == 0 && confirmations.Count == 0 &&
            inner.Records.All(record => record.State is not FollowUpOperationState.Dispatching and not
                FollowUpOperationState.Uncertain and not FollowUpOperationState.Confirmed),
            "clock rollback reached the owner write or left ambiguous inner dispatch state");
    }

    private static async Task TestProtectionActionAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var rule = WorkflowRuleDefinition.Create(
            Guid.NewGuid().ToString("D"),
            1,
            fixture.Target.Id,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(fixture.Target.Id),
            null,
            [new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = 0
            }]);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "protect-1");
        var before = await fixture.Settings.LoadAsync();
        var result = await fixture.Executor.ExecuteEnableConversationProtectionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target);
        var committed = await fixture.Settings.LoadAsync();
        Ensure(
            result.Status == WorkflowActionExecutionStatus.Confirmed &&
            result.Record?.ProtectionSettingsGeneration == before.SettingsGeneration + 1 &&
            committed.ThreadProtectionEnabled.TryGetValue(fixture.Target.Id, out var enabled) && enabled &&
            !committed.GlobalProtectionEnabled && fixture.Desktop.StartInvocationCount == 0,
            "workflow protection action lacked a typed local settings receipt");

        var repeated = await fixture.Executor.ExecuteEnableConversationProtectionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target);
        var afterRepeat = await fixture.Settings.LoadAsync();
        Ensure(
            repeated.Status == WorkflowActionExecutionStatus.Confirmed &&
            afterRepeat.SettingsGeneration == committed.SettingsGeneration,
            "confirmed protection action rewrote settings on replay");
    }

    private static async Task TestProtectionDispatchBudgetAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var presetId = Guid.NewGuid().ToString("D");
        var rule = WorkflowRuleDefinition.Create(
            Guid.NewGuid().ToString("D"),
            1,
            fixture.Target.Id,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(fixture.Target.Id),
            null,
            [
                Send(fixture.Target.Id, presetId, 0),
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.EnableConversationProtection,
                    Order = 1
                }
            ]);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "protect-budget");
        var send = await fixture.WorkflowJournal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target.Id);
        for (var attempt = 0;
             attempt < WorkflowOperationJournal.MaximumDispatchAttemptsPerCorrelationPerHour;
             attempt++)
        {
            _ = await fixture.WorkflowJournal.TryStartDispatchAsync(send.Record.ActionOperationId);
            _ = await fixture.WorkflowJournal.TryMarkRetryableProvenUnsentAsync(
                send.Record.ActionOperationId,
                "owner-unavailable");
        }

        var before = await fixture.Settings.LoadAsync();
        var result = await fixture.Executor.ExecuteEnableConversationProtectionAsync(
            rule,
            trigger.Record.TriggerEventId,
            1,
            fixture.Target);
        var after = await fixture.Settings.LoadAsync();
        Ensure(
            result.Status == WorkflowActionExecutionStatus.Blocked &&
            result.Record is
            {
                State: WorkflowActionOperationState.Blocked,
                AttemptCount: 0,
                FailureClass: "dispatch-budget-exhausted"
            } &&
            after.SettingsGeneration == before.SettingsGeneration &&
            !after.ThreadProtectionEnabled.ContainsKey(fixture.Target.Id),
            "a full correlation budget was projected as uncertain or reached the protection write");
    }

    private static async Task TestNewConversationUnavailableAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var presetId = Guid.NewGuid().ToString("D");
        var rule = WorkflowRuleDefinition.Create(
            Guid.NewGuid().ToString("D"),
            1,
            fixture.Target.Id,
            true,
            Activation,
            ScheduledTrigger(),
            new WorkflowDestinationDefinition { Kind = WorkflowDestinationKind.NewConversation },
            null,
            [Send(fixture.Target.Id, presetId, 0)]);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "new-1");
        var result = await fixture.Executor.MarkNewConversationUnavailableAsync(
            rule,
            trigger.Record.TriggerEventId,
            0);
        Ensure(
            result.Status == WorkflowActionExecutionStatus.CapabilityUnavailable &&
            result.Record?.State == WorkflowActionOperationState.Blocked &&
            result.Record.FailureClass == "new-conversation-unavailable" &&
            result.Record.TargetConversationId is null && fixture.Desktop.StartInvocationCount == 0,
            "new-conversation action was simulated or silently downgraded");
    }

    private static async Task TestRetryExhaustionAsync()
    {
        using var fixture = await WorkflowExecutorFixture.CreateAsync();
        var preset = Preset(Guid.NewGuid().ToString("D"), "do not retry again");
        var rule = SendRule(fixture.Target.Id, preset.Id);
        var trigger = await CreateTriggerAsync(fixture.WorkflowJournal, rule, "exhaust-1");
        var prepared = await fixture.WorkflowJournal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target.Id);
        _ = await fixture.WorkflowJournal.TryStartDispatchAsync(
            prepared.Record.ActionOperationId);
        _ = await fixture.WorkflowJournal.TryMarkRetryableProvenUnsentAsync(
            prepared.Record.ActionOperationId,
            "desktop-unavailable");
        var result = await fixture.Executor.MarkExhaustedAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            fixture.Target.Id);
        var record = (await fixture.WorkflowJournal.ReadAsync()).Actions.Single();
        Ensure(
            result.Status == WorkflowActionExecutionStatus.Exhausted &&
            record.State == WorkflowActionOperationState.Exhausted &&
            record.AttemptCount == 1 &&
            record.FailureClass == "retry-exhausted" &&
            fixture.Desktop.StartInvocationCount == 0,
            "retry exhaustion was not durable or reached the owner write");
    }

    private static WorkflowRuleDefinition SendRule(string targetConversationId, string presetId) =>
        WorkflowRuleDefinition.Create(
            Guid.NewGuid().ToString("D"),
            1,
            targetConversationId,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(targetConversationId),
            null,
            [Send(targetConversationId, presetId, 0)]);

    private static WorkflowActionDefinition Send(
        string ownerConversationId,
        string presetId,
        int order) =>
        new()
        {
            Kind = WorkflowActionKind.SendPresetMessage,
            PresetOwnerConversationId = ownerConversationId,
            PresetMessageId = presetId,
            Order = order
        };

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

    private static FollowUpMessageDefinition Preset(string id, string message) => new()
    {
        Id = id,
        Message = message,
        IsEnabled = true,
        UseWorkflowAutomation = true,
        Order = 0
    };

    private static Task<WorkflowTriggerEventPrepareResult> CreateTriggerAsync(
        WorkflowOperationJournal journal,
        WorkflowRuleDefinition rule,
        string occurrence) =>
        journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            rule.OwnerConversationId,
            rule.RuleId,
            rule.RuleId,
            occurrence,
            Activation.AddHours(2));

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

    private static ThreadSummary RootThread(string id) =>
        new(
            Id: id,
            Name: "Workflow target",
            Preview: string.Empty,
            Cwd: "D:\\workflow-test",
            Source: "cli",
            CreatedAt: 1,
            UpdatedAt: 2,
            IsSubAgent: false,
            IsEphemeral: false,
            RuntimeStatus: "idle",
            IsArchived: false);

    private sealed class WorkflowExecutorFixture : IDisposable
    {
        private WorkflowExecutorFixture(string root)
        {
            Target = RootThread(Guid.NewGuid().ToString("D"));
            LatestTurn = NormalTurn(Guid.NewGuid().ToString("D"));
            StateReader = new FakeWorkflowStateReader(this);
            Desktop = new FakeWorkflowDesktopChannel(this);
            Owner = new FakeWorkflowOwnerActivator();
            Interference = new ClearWorkflowInterferenceGuard();
            FollowUpJournal = new FollowUpOperationJournal(Path.Combine(root, "follow-up"));
            Clock = new WorkflowTestTimeProvider(Activation.AddHours(3));
            WorkflowJournal = new WorkflowOperationJournal(
                Path.Combine(root, "workflow"),
                timeProvider: Clock);
            Settings = new SettingsService(Path.Combine(root, "settings"));
            Log = new GuardianLog(Path.Combine(root, "log"));
            var followUp = new FollowUpDispatchService(
                StateReader,
                Desktop,
                Owner,
                FollowUpJournal,
                Log,
                Interference);
            Executor = new WorkflowActionExecutor(
                WorkflowJournal,
                new FollowUpWorkflowPresetDispatcher(followUp),
                new SettingsWorkflowConversationProtectionService(Settings));
        }

        internal ThreadSummary Target { get; }

        internal TurnSnapshot LatestTurn { get; set; }

        internal WorkflowTestTimeProvider Clock { get; }

        internal FakeWorkflowStateReader StateReader { get; }

        internal FakeWorkflowDesktopChannel Desktop { get; }

        internal FakeWorkflowOwnerActivator Owner { get; }

        internal ClearWorkflowInterferenceGuard Interference { get; }

        internal FollowUpOperationJournal FollowUpJournal { get; }

        internal WorkflowOperationJournal WorkflowJournal { get; }

        internal SettingsService Settings { get; }

        internal GuardianLog Log { get; }

        internal WorkflowActionExecutor Executor { get; }

        internal static async Task<WorkflowExecutorFixture> CreateAsync()
        {
            var fixture = new WorkflowExecutorFixture(CreateRoot());
            await fixture.Settings.SaveAsync(new AppSettings { RecentThreadLimit = 37 });
            return fixture;
        }

        public void Dispose() => Log.Dispose();
    }

    private sealed class FakeWorkflowStateReader(WorkflowExecutorFixture fixture)
        : IFollowUpStateReader
    {
        internal Dictionary<string, TurnSnapshot> ReconciledTurns { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public Task<TurnSnapshot?> ReadLatestTurnAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(threadId == fixture.Target.Id, "state reader target changed");
            return Task.FromResult<TurnSnapshot?>(fixture.LatestTurn);
        }

        public Task<ThreadSummary> ReadThreadForRecoveryAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(threadId == fixture.Target.Id, "eligibility target changed");
            return Task.FromResult(fixture.Target);
        }

        public Task<TurnSnapshot?> FindRecentTurnByClientMessageIdAsync(
            string threadId,
            string clientMessageId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(threadId == fixture.Target.Id, "reconciliation target changed");
            return Task.FromResult<TurnSnapshot?>(
                ReconciledTurns.TryGetValue(clientMessageId, out var turn) ? turn : null);
        }
    }

    private sealed class FakeWorkflowDesktopChannel(WorkflowExecutorFixture fixture)
        : IFollowUpDesktopChannel
    {
        internal long OwnerRevision { get; set; } = 7;

        internal DesktopStartTurnResult StartResult { get; } =
            new(Guid.NewGuid().ToString("D"));

        internal DesktopIpcDeliveryException? DeliveryException { get; set; }

        internal int GuardAcquireCount { get; private set; }

        internal int StartInvocationCount { get; private set; }

        internal int WritePredicateCount { get; private set; }

        internal List<string> StartClientMessageIds { get; } = [];

        public bool SupportsGuardedAutomaticSend => true;

        public Task<FollowUpOwnerStateGuardAcquireResult> AcquireThreadOwnerStateGuardAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(threadId == fixture.Target.Id, "owner guard target changed");
            GuardAcquireCount++;
            return Task.FromResult(new FollowUpOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Available,
                new FakeWorkflowOwnerGuard(new DesktopThreadOwnerStateSnapshot(
                    fixture.Target.Id,
                    "workflow-host",
                    "workflow-owner",
                    OwnerRevision,
                    "idle",
                    fixture.LatestTurn.Id,
                    "completed")),
                "available"));
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
            StartInvocationCount++;
            WritePredicateCount++;
            if (!canStartWrite())
            {
                throw new DesktopIpcDeliveryException(
                    DesktopIpcDeliveryStage.NotDispatched,
                    "write predicate rejected");
            }

            if (DeliveryException is not null)
            {
                throw DeliveryException;
            }

            Ensure(threadId == fixture.Target.Id && !string.IsNullOrWhiteSpace(message),
                "Desktop start-turn inputs changed");
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
            Func<bool> canStartWrite) =>
            StartTextTurnAsync(
                threadId,
                payload.Text,
                clientMessageId,
                cancellationToken,
                canStartWrite);
    }

    private sealed class FakeWorkflowOwnerGuard(DesktopThreadOwnerStateSnapshot snapshot)
        : IFollowUpOwnerStateGuard
    {
        public DesktopThreadOwnerStateSnapshot Snapshot { get; } = snapshot;

        public bool IsCurrent => true;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeWorkflowOwnerActivator : IFollowUpOwnerActivator
    {
        internal int ActivationCount { get; private set; }

        public Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            _ = threadId;
            cancellationToken.ThrowIfCancellationRequested();
            ActivationCount++;
            return Task.FromResult(new DesktopThreadOwnerActivationResult(
                DesktopThreadOwnerActivationStatus.AlreadyAvailable,
                "available"));
        }

        public DesktopUserActivityResult CheckUserActivity() =>
            new(DesktopUserActivityStatus.Idle, "idle");
    }

    private sealed class ClearWorkflowInterferenceGuard : IRecoveryInterferenceGuard
    {
        private int _checkCount;

        internal int CheckCount => Volatile.Read(ref _checkCount);

        public Task<RecoveryInterferenceSnapshot> CheckAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            _ = threadId;
            cancellationToken.ThrowIfCancellationRequested();
            var version = Interlocked.Increment(ref _checkCount);
            return Task.FromResult(new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Clear,
                "clear",
                HasFocusedDraft: false,
                DateTimeOffset.UtcNow,
                version));
        }

        public async Task WaitForChangeAsync(
            long observedVersion,
            CancellationToken cancellationToken)
        {
            _ = observedVersion;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }
    }

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "we-" + Guid.NewGuid().ToString("N")[..8]);
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
