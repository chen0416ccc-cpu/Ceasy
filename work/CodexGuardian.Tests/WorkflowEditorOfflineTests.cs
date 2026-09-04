using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Collections.Concurrent;
using System.IO;
using System.Text;

internal static class WorkflowEditorOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "workflow editor derives stable managed identity and advances revision only on change",
            TestStableManagedIdentity,
            assert);
        RunCase(
            "workflow editor preserves unrelated rules and removes only its owner-managed rules",
            TestReplacementScope,
            assert);
        RunCase(
            "workflow-mode presets are skipped by legacy scheduling while confirmed barriers remain",
            TestLegacyPlannerIsolation,
            assert);
        RunCase(
            "workflow-mode settings normalize additively without reinterpreting legacy presets",
            TestSettingsNormalization,
            assert);
        RunCase(
            "workflow editor exposes the existing second-level When Where Then contract",
            TestUiContract,
            assert);
        return Task.CompletedTask;
    }

    private static void TestStableManagedIdentity()
    {
        var owner = Id(1);
        var message = Id(2);
        var source = Id(3);
        var target = Id(4);
        var firstDraft = Draft(message, source, target, protect: true);
        var empty = Snapshot([]);
        var first = WorkflowRuleEditor.BuildReplacement(
            empty,
            owner,
            [firstDraft],
            Activation).Single();
        var stableId = WorkflowRuleEditor.CreateManagedRuleId(owner, message);
        var healthy = Snapshot([first], generation: 1);
        var unchanged = WorkflowRuleEditor.BuildReplacement(
            healthy,
            owner,
            [firstDraft],
            Activation.AddHours(1)).Single();
        var changed = WorkflowRuleEditor.BuildReplacement(
            healthy,
            owner,
            [firstDraft with { TargetConversationId = Id(5) }],
            Activation.AddHours(2)).Single();
        Ensure(
            first.RuleId == stableId && first.Revision == 1 &&
            first.Actions.Count == 2 &&
            first.Actions[0].Kind == WorkflowActionKind.EnableConversationProtection &&
            first.Actions[0].Order == 0 &&
            first.Actions[1].Kind == WorkflowActionKind.SendPresetMessage &&
            first.Actions[1].Order == 1 &&
            !first.Conditions.Contains(WorkflowConditionKind.TargetPolicyAllowsAction) &&
            first.Conditions.Contains(WorkflowConditionKind.ManagedAttachmentsAvailable) &&
            ReferenceEquals(first, unchanged) &&
            unchanged.ActivatedAtUtc == Activation &&
            changed.RuleId == stableId && changed.Revision == 2 &&
            changed.ActivatedAtUtc == Activation.AddHours(2) &&
            changed.DefinitionDigest != first.DefinitionDigest,
            "managed workflow identity or revision activation semantics drifted");
    }

    private static void TestReplacementScope()
    {
        var owner = Id(10);
        var message = Id(11);
        var managed = WorkflowRuleEditor.BuildReplacement(
            Snapshot([]),
            owner,
            [Draft(message, Id(12), Id(13), protect: false)],
            Activation).Single();
        var unrelated = WorkflowRuleDefinition.Create(
            Id(14),
            1,
            Id(15),
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = Activation.AddDays(1)
            },
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.CurrentConversation
            },
            null,
            [
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.EnableConversationProtection,
                    Order = 0
                }
            ]);
        var removed = WorkflowRuleEditor.BuildReplacement(
            Snapshot([managed, unrelated], generation: 2),
            owner,
            [],
            Activation.AddHours(1));
        var newConversation = WorkflowRuleEditor.BuildReplacement(
            Snapshot([unrelated], generation: 3),
            owner,
            [Draft(message, Id(12), target: null, protect: false) with
            {
                DestinationKind = WorkflowDestinationKind.NewConversation
            }],
            Activation.AddHours(2));
        var validation = WorkflowRuleGraphValidator.Validate(newConversation);
        Ensure(
            removed.Count == 1 && removed[0].RuleId == unrelated.RuleId &&
            WorkflowRuleEditor.FindManagedRule(
                Snapshot([managed, unrelated]),
                owner,
                message)?.RuleId == managed.RuleId &&
            validation.Issues.Count(issue =>
                issue.Code == WorkflowRuleValidationIssueCode.NewConversationUnavailable) == 1 &&
            validation.Issues.All(issue =>
                issue.Code == WorkflowRuleValidationIssueCode.NewConversationUnavailable),
            "managed replacement removed unrelated authority or hid new-conversation unavailability");
    }

    private static void TestLegacyPlannerIsolation()
    {
        var threadId = Id(20);
        var workflow = new FollowUpMessageDefinition
        {
            Id = Id(21),
            Message = "workflow",
            Trigger = FollowUpTriggerKind.ScheduledAt,
            ScheduledAtUtc = Activation.AddMinutes(-10),
            IsEnabled = true,
            UseWorkflowAutomation = true,
            Order = 0
        };
        var legacy = new FollowUpMessageDefinition
        {
            Id = Id(22),
            Message = "legacy",
            Trigger = FollowUpTriggerKind.ScheduledAt,
            ScheduledAtUtc = Activation.AddMinutes(5),
            IsEnabled = true,
            Order = 1
        };
        var settings = new ThreadFollowUpSettings
        {
            IsEnabled = true,
            Messages = [workflow, legacy]
        };
        var turn = NormalTurn(Id(23), Activation.AddMinutes(-1));
        var ready = FollowUpQueuePlanner.Evaluate(
            settings,
            turn,
            [],
            Activation.AddMinutes(10));
        var map = new Dictionary<string, ThreadFollowUpSettings>(StringComparer.OrdinalIgnoreCase)
        {
            [threadId] = settings
        };
        var confirmed = new FollowUpOperationRecord(
            Id(24),
            threadId,
            workflow.Id,
            workflow.Trigger,
            turn.Id,
            workflow.ScheduledAtUtc,
            FollowUpOperationJournal.ComputeMessageHash(workflow.Message),
            FollowUpOperationState.Confirmed,
            Id(25),
            Id(26),
            CompletionTurnId: null,
            Activation.AddMinutes(-5),
            Activation.AddMinutes(-4),
            AttemptCount: 1)
        {
            SourceKind = FollowUpPayloadSourceKind.WorkflowPreset
        };
        var barrier = FollowUpQueuePlanner.Evaluate(
            settings,
            turn,
            [confirmed],
            Activation.AddMinutes(10));
        Ensure(
            ready.Kind == FollowUpQueueDecisionKind.Ready && ready.Message?.Id == legacy.Id &&
            FollowUpQueuePlanner.FindNextScheduledAtUtc(map, []) == legacy.ScheduledAtUtc &&
            FollowUpQueuePlanner.FindDueScheduledThreadIds(
                map,
                [],
                Activation).Count == 0 &&
            !FollowUpQueuePlanner.RequiresCompletionAnchor(
                true,
                [workflow with
                {
                    Trigger = FollowUpTriggerKind.AfterNormalCompletion,
                    ScheduledAtUtc = null
                }]) &&
            barrier.Kind == FollowUpQueueDecisionKind.Waiting &&
            barrier.Message?.Id == legacy.Id,
            "legacy planning sent a workflow preset or discarded its confirmed successor barrier");
    }

    private static void TestSettingsNormalization()
    {
        var threadId = Id(30);
        var legacyId = Id(31);
        var workflowId = Id(32);
        var normalized = SettingsService.NormalizeThreadFollowUps(
            new ConcurrentDictionary<string, ThreadFollowUpSettings>(
                new Dictionary<string, ThreadFollowUpSettings>(StringComparer.OrdinalIgnoreCase)
                {
                    [threadId] = new()
                    {
                        Messages =
                        [
                            new FollowUpMessageDefinition
                            {
                                Id = legacyId,
                                Message = "legacy",
                                WorkflowRuleRevision = 99,
                                WorkflowRuleDigest = new string('A', 64),
                                Order = 0
                            },
                            new FollowUpMessageDefinition
                            {
                                Id = workflowId,
                                Message = "workflow",
                                UseWorkflowAutomation = true,
                                WorkflowRuleRevision = 7,
                                WorkflowRuleDigest = new string('B', 64),
                                Order = 1
                            }
                        ]
                    }
                },
                StringComparer.OrdinalIgnoreCase));
        var messages = normalized[threadId].Messages;
        Ensure(
            !messages[0].UseWorkflowAutomation &&
            messages[1].UseWorkflowAutomation &&
            messages[0].WorkflowRuleRevision is null &&
            messages[0].WorkflowRuleDigest is null &&
            messages[1].WorkflowRuleRevision == 7 &&
            messages[1].WorkflowRuleDigest == new string('B', 64) &&
            messages[0].Trigger == FollowUpTriggerKind.AfterNormalCompletion &&
            messages[1].Trigger == FollowUpTriggerKind.AfterNormalCompletion,
            "the additive workflow marker reinterpreted a legacy preset");
    }

    private static void TestUiContract()
    {
        var root = Path.Combine(Environment.CurrentDirectory, "work", "CodexGuardian");
        var xaml = File.ReadAllText(Path.Combine(root, "MainWindow.xaml"), Encoding.UTF8);
        var viewModel = File.ReadAllText(
            Path.Combine(root, "ViewModels", "MainViewModel.cs"),
            Encoding.UTF8);
        var planner = File.ReadAllText(
            Path.Combine(root, "Services", "FollowUpQueuePlanner.cs"),
            Encoding.UTF8);
        var resolver = File.ReadAllText(
            Path.Combine(root, "Services", "WorkflowExecutionResolver.cs"),
            Encoding.UTF8);
        var policy = File.ReadAllText(
            Path.Combine(root, "Services", "PresetAutomationPolicy.cs"),
            Encoding.UTF8);
        Ensure(
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowRuleEditor\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowWhenGroup\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowWhereGroup\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowThenGroup\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowSourceConversationComboBox\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowSourcePresetComboBox\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowTargetConversationComboBox\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"WorkflowEnableProtectionToggle\"", StringComparison.Ordinal) &&
            xaml.Contains("Binding IsFollowUpDetailPage", StringComparison.Ordinal) &&
            !xaml.Contains("CommandParameter=\"Workflow\"", StringComparison.Ordinal) &&
            viewModel.Contains("public bool IsNewConversationWorkflowAvailable => false;", StringComparison.Ordinal) &&
            viewModel.Contains("WorkflowRuleEditor.BuildReplacement", StringComparison.Ordinal) &&
            planner.Contains("message.UseWorkflowAutomation", StringComparison.Ordinal) &&
            resolver.Contains(
                "PresetAutomationPolicy.IsWorkflowMessageAuthorized",
                StringComparison.Ordinal) &&
            policy.Contains(
                "UseWorkflowAutomation: true",
                StringComparison.Ordinal),
            "the per-conversation workflow editor or fail-closed mode boundary drifted");
    }

    private static WorkflowRuleEditorDraft Draft(
        string messageId,
        string source,
        string? target,
        bool protect) =>
        new(
            messageId,
            IsEnabled: true,
            WorkflowTriggerKind.ConversationCompletedNormally,
            source,
            SourcePresetMessageId: null,
            ScheduledAtUtc: null,
            WorkflowDestinationKind.ExistingConversation,
            target,
            protect);

    private static WorkflowRuleStoreSnapshot Snapshot(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        long generation = 0) =>
        new(
            generation == 0
                ? WorkflowRuleStoreReadStatus.Missing
                : WorkflowRuleStoreReadStatus.Healthy,
            generation,
            RequiresConservativeRecovery: false,
            rules,
            WorkflowRuleGraphValidator.Validate(rules));

    private static TurnSnapshot NormalTurn(string id, DateTimeOffset completedAtUtc) =>
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
            OutputFingerprint: "workflow-editor-" + id,
            StartedAt: completedAtUtc.AddMinutes(-1).ToUnixTimeSeconds(),
            CompletedAt: completedAtUtc.ToUnixTimeSeconds(),
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static void RunCase(
        string name,
        Action test,
        Action<bool, string> assert)
    {
        try
        {
            test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
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
        $"00000000-0000-0000-0000-{value:000000000000}";
}
