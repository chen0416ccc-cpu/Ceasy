using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class WorkflowTriggerCoordinatorOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow trigger coordinator emits one stable scheduled occurrence and resumes idempotently",
            TestScheduledTriggerAsync,
            assert);
        await RunCaseAsync(
            "workflow completion trigger requires final output and inherits parent correlation",
            TestCompletionCorrelationAsync,
            assert);
        await RunCaseAsync(
            "workflow dispatch-confirmed trigger requires an authoritative generated-turn receipt",
            TestDispatchConfirmedTriggerAsync,
            assert);
        await RunCaseAsync(
            "workflow conditions are finite and non-confirmed actions stop ordered execution",
            TestConditionsAndActionOrderingAsync,
            assert);
    }

    private static async Task TestScheduledTriggerAsync()
    {
        var journal = new WorkflowOperationJournal(
            CreateRoot(),
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var conditions = new FakeConditionEvaluator();
        var runner = new FakeActionRunner(WorkflowActionExecutionStatus.Confirmed);
        var coordinator = new WorkflowTriggerCoordinator(journal, conditions, runner);
        var rule = ScheduledRule(seed: 100, actionCount: 1);
        var early = await coordinator.ProcessScheduledAsync([rule], Activation.AddMinutes(30));
        var first = await coordinator.ProcessScheduledAsync([rule], Activation.AddHours(2));
        var repeated = await coordinator.ProcessScheduledAsync([rule], Activation.AddHours(3));
        Ensure(
            early.Count == 0 && first.Count == 1 && first[0].TriggerCreated &&
            repeated.Count == 1 && !repeated[0].TriggerCreated &&
            first[0].TriggerEvent.TriggerEventId == repeated[0].TriggerEvent.TriggerEventId &&
            runner.Calls.Count == 2 && conditions.Calls.Count == 2,
            "scheduled occurrence identity changed or could not resume idempotently");
    }

    private static async Task TestCompletionCorrelationAsync()
    {
        var journal = new WorkflowOperationJournal(
            CreateRoot(),
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var targetConversationId = Id(210);
        var parentRule = ScheduledRule(
            seed: 200,
            actionCount: 1,
            targetConversationId: targetConversationId);
        var parentTrigger = await journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            parentRule.OwnerConversationId,
            parentRule.RuleId,
            parentRule.RuleId,
            "parent",
            Activation.AddHours(2));
        var parentAction = await journal.GetOrCreateActionAsync(
            parentRule,
            parentTrigger.Record.TriggerEventId,
            0,
            targetConversationId);
        _ = await journal.TryStartDispatchAsync(parentAction.Record.ActionOperationId);
        var generatedTurnId = Id(211);
        _ = await journal.TryMarkConfirmedAsync(
            parentAction.Record.ActionOperationId,
            new WorkflowActionReceipt(targetConversationId, generatedTurnId, null));

        var completionRule = CompletionRule(Id(212), targetConversationId, Id(213));
        var conditions = new FakeConditionEvaluator();
        var runner = new FakeActionRunner(WorkflowActionExecutionStatus.Confirmed);
        var coordinator = new WorkflowTriggerCoordinator(journal, conditions, runner);
        var source = RootThread(targetConversationId);
        var incomplete = NormalTurn(generatedTurnId) with { HasFinalAssistantOutput = false };
        var ignored = await coordinator.ProcessConversationCompletedAsync(
            [completionRule],
            source,
            incomplete,
            Activation.AddHours(3));
        var accepted = await coordinator.ProcessConversationCompletedAsync(
            [completionRule],
            source,
            NormalTurn(generatedTurnId),
            Activation.AddHours(3));
        Ensure(
            ignored.Count == 0 && accepted.Count == 1 &&
            accepted[0].TriggerEvent.CausationId == parentAction.Record.ActionOperationId &&
            accepted[0].TriggerEvent.CorrelationId == parentTrigger.Record.CorrelationId &&
            accepted[0].TriggerEvent.CorrelationDepth == parentAction.Record.CorrelationDepth &&
            accepted[0].TriggerEvent.Occurrence ==
                "normal-completion:" + incomplete.CompletedAt,
            "normal completion fired without final output or lost workflow lineage");
    }

    private static async Task TestDispatchConfirmedTriggerAsync()
    {
        var journal = new WorkflowOperationJournal(
            CreateRoot(),
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var sourceRule = ScheduledRule(seed: 300, actionCount: 1);
        var sourceTrigger = await journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            sourceRule.OwnerConversationId,
            sourceRule.RuleId,
            sourceRule.RuleId,
            "source",
            Activation.AddHours(2));
        var sourceAction = await journal.GetOrCreateActionAsync(
            sourceRule,
            sourceTrigger.Record.TriggerEventId,
            0);
        var downstreamRule = DispatchRule(
            Id(310),
            sourceAction.Record.PresetOwnerConversationId!,
            sourceAction.Record.PresetMessageId!,
            Id(311));
        var runner = new FakeActionRunner(WorkflowActionExecutionStatus.Confirmed);
        var coordinator = new WorkflowTriggerCoordinator(
            journal,
            new FakeConditionEvaluator(),
            runner);
        var ignored = await coordinator.ProcessPresetDispatchConfirmedAsync(
            [downstreamRule],
            sourceAction.Record.ActionOperationId,
            Activation.AddHours(3));
        _ = await journal.TryStartDispatchAsync(sourceAction.Record.ActionOperationId);
        _ = await journal.TryMarkConfirmedAsync(
            sourceAction.Record.ActionOperationId,
            new WorkflowActionReceipt(sourceRule.OwnerConversationId, Id(312), null));
        var accepted = await coordinator.ProcessPresetDispatchConfirmedAsync(
            [downstreamRule],
            sourceAction.Record.ActionOperationId,
            Activation.AddHours(3));
        Ensure(
            ignored.Count == 0 && accepted.Count == 1 &&
            accepted[0].TriggerEvent.CausationId == sourceAction.Record.ActionOperationId &&
            accepted[0].TriggerEvent.CorrelationId == sourceTrigger.Record.CorrelationId &&
            accepted[0].TriggerEvent.Occurrence == Id(312),
            "preset dispatch trigger fired before confirmation or lost its generated-turn receipt");
    }

    private static async Task TestConditionsAndActionOrderingAsync()
    {
        var journal = new WorkflowOperationJournal(
            CreateRoot(),
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var conditions = new FakeConditionEvaluator
        {
            Result = new WorkflowConditionEvaluationResult(
                false,
                [WorkflowConditionKind.TargetIdle])
        };
        var runner = new FakeActionRunner(
            WorkflowActionExecutionStatus.Confirmed,
            WorkflowActionExecutionStatus.Uncertain,
            WorkflowActionExecutionStatus.Confirmed);
        var coordinator = new WorkflowTriggerCoordinator(journal, conditions, runner);
        var rule = ScheduledRule(seed: 400, actionCount: 3);
        var blocked = await coordinator.ProcessScheduledAsync([rule], Activation.AddHours(2));
        Ensure(
            blocked.Single().Actions.Count == 0 && runner.Calls.Count == 0,
            "failed finite conditions still invoked workflow actions");

        conditions.Result = new WorkflowConditionEvaluationResult(true, []);
        var executed = await coordinator.ProcessScheduledAsync([rule], Activation.AddHours(3));
        Ensure(
            executed.Single().Actions.Select(result => result.Status).SequenceEqual([
                WorkflowActionExecutionStatus.Confirmed,
                WorkflowActionExecutionStatus.Uncertain
            ]) &&
            runner.Calls.Select(call => call.ActionIndex).SequenceEqual([0, 1]),
            "ordered workflow execution continued after a non-confirmed action");
    }

    private static WorkflowRuleDefinition ScheduledRule(
        int seed,
        int actionCount,
        string? targetConversationId = null)
    {
        var owner = Id(seed);
        var target = targetConversationId ?? owner;
        var actions = new List<WorkflowActionDefinition>();
        if (actionCount >= 1)
        {
            actions.Add(Send(owner, Id(seed + 2), 0));
        }

        if (actionCount >= 2)
        {
            actions.Add(new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = 1
            });
        }

        if (actionCount >= 3)
        {
            actions.Add(Send(owner, Id(seed + 3), 2));
        }

        return WorkflowRuleDefinition.Create(
            Id(seed + 1),
            1,
            owner,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = Activation.AddHours(1)
            },
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation,
                ConversationId = target
            },
            [WorkflowConditionKind.TargetIdle],
            actions);
    }

    private static WorkflowRuleDefinition CompletionRule(
        string ruleId,
        string sourceConversationId,
        string targetConversationId) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            1,
            sourceConversationId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                SourceConversationId = sourceConversationId
            },
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation,
                ConversationId = targetConversationId
            },
            null,
            [Send(sourceConversationId, Id(214), 0)]);

    private static WorkflowRuleDefinition DispatchRule(
        string ruleId,
        string sourceConversationId,
        string sourcePresetId,
        string targetConversationId) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            1,
            sourceConversationId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.PresetDispatchConfirmed,
                SourceConversationId = sourceConversationId,
                SourcePresetMessageId = sourcePresetId
            },
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation,
                ConversationId = targetConversationId
            },
            null,
            [new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = 0
            }]);

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

    private static ThreadSummary RootThread(string id) =>
        new(
            id,
            "Workflow source",
            string.Empty,
            "D:\\workflow-source",
            "cli",
            1,
            2,
            IsSubAgent: false,
            IsEphemeral: false,
            RuntimeStatus: "idle",
            IsArchived: false);

    private static TurnSnapshot NormalTurn(string id) =>
        new(
            id,
            "completed",
            ErrorMessage: null,
            ErrorCode: null,
            HttpStatusCode: null,
            UserText: "test",
            HasAttachments: false,
            HasAssistantOutput: true,
            HasWorkOutput: true,
            OutputFingerprint: "normal-" + id,
            StartedAt: Activation.ToUnixTimeSeconds(),
            CompletedAt: Activation.AddMinutes(1).ToUnixTimeSeconds(),
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private sealed class FakeConditionEvaluator : IWorkflowConditionEvaluator
    {
        internal WorkflowConditionEvaluationResult Result { get; set; } =
            new(true, []);

        internal List<string> Calls { get; } = [];

        public Task<WorkflowConditionEvaluationResult> EvaluateAsync(
            WorkflowRuleDefinition rule,
            WorkflowTriggerEventRecord triggerEvent,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.Add(rule.RuleId + "|" + triggerEvent.TriggerEventId);
            return Task.FromResult(Result);
        }
    }

    private sealed class FakeActionRunner(params WorkflowActionExecutionStatus[] statuses)
        : IWorkflowRuleActionRunner
    {
        private readonly Queue<WorkflowActionExecutionStatus> _statuses = new(statuses);

        internal List<(string RuleId, string TriggerEventId, int ActionIndex)> Calls { get; } = [];

        public Task<WorkflowActionExecutionResult> RunAsync(
            WorkflowRuleDefinition rule,
            WorkflowTriggerEventRecord triggerEvent,
            int actionIndex,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.Add((rule.RuleId, triggerEvent.TriggerEventId, actionIndex));
            var status = _statuses.Count > 0
                ? _statuses.Dequeue()
                : WorkflowActionExecutionStatus.Confirmed;
            return Task.FromResult(new WorkflowActionExecutionResult(
                status,
                Record: null,
                "fake"));
        }
    }

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "wt-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private static string Id(int value) =>
        $"00000000-0000-0000-0000-{value:000000000000}";

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
