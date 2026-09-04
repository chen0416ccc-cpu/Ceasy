using CodexGuardian.Models;
using CodexGuardian.Services;

internal static class WorkflowAutomationOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00+08:00");

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "workflow canonical digest normalizes UUID condition and UTC representations",
            TestCanonicalDigest,
            assert);
        RunCase(
            "workflow typed definitions reject cross-kind fields duplicates and unbounded shapes",
            TestTypedDefinitionValidation,
            assert);
        RunCase(
            "legacy follow-up queues retain their original trigger and ordering semantics",
            TestLegacyQueueIsolation,
            assert);
        RunCase(
            "workflow graph accepts an acyclic completion-to-protection chain",
            TestAcyclicGraph,
            assert);
        RunCase(
            "workflow graph rejects same-preset dispatch self-trigger",
            TestPresetSelfCycle,
            assert);
        RunCase(
            "workflow graph rejects same-conversation completion self-trigger",
            TestCompletionSelfCycle,
            assert);
        RunCase(
            "workflow graph rejects cross-conversation A to B to A completion cycles",
            TestCrossConversationCycle,
            assert);
        RunCase(
            "workflow graph rejects transitive cross-preset dispatch cycles",
            TestCrossPresetCycle,
            assert);
        RunCase(
            "workflow graph keeps new-conversation unavailable until owner capability is proved",
            TestNewConversationCapability,
            assert);
        RunCase(
            "workflow graph rejects duplicate active revisions of one rule identity",
            TestDuplicateRuleIdentity,
            assert);
        return Task.CompletedTask;
    }

    private static void TestCanonicalDigest()
    {
        var ruleId = Id(1);
        var owner = Id(2);
        var target = Id(3);
        var presetOwner = Id(4);
        var preset = Id(5);
        var first = WorkflowRuleDefinition.Create(
            "{" + ruleId.ToUpperInvariant() + "}",
            revision: 7,
            owner.ToUpperInvariant(),
            isEnabled: true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = DateTimeOffset.Parse("2026-08-16T09:30:00+08:00")
            },
            Existing(target.ToUpperInvariant()),
            [
                WorkflowConditionKind.TargetIdle,
                WorkflowConditionKind.SourceEventAfterActivation,
                WorkflowConditionKind.TargetIdle
            ],
            [
                Send(presetOwner.ToUpperInvariant(), preset.ToUpperInvariant(), 0),
                Protect(1)
            ]);
        var second = WorkflowRuleDefinition.Create(
            ruleId,
            revision: 7,
            owner,
            isEnabled: true,
            Activation.ToUniversalTime(),
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = DateTimeOffset.Parse("2026-08-16T01:30:00Z")
            },
            Existing(target),
            [
                WorkflowConditionKind.SourceEventAfterActivation,
                WorkflowConditionKind.TargetIdle
            ],
            [Send(presetOwner, preset, 0), Protect(1)]);
        Ensure(first.HasValidIdentity() && second.HasValidIdentity(), "canonical workflow identity failed");
        Ensure(first.RuleId == ruleId && first.OwnerConversationId == owner, "UUIDs were not canonicalized");
        Ensure(first.ActivatedAtUtc.Offset == TimeSpan.Zero, "activation was not normalized to UTC");
        Ensure(
            first.Conditions.SequenceEqual(second.Conditions) &&
            first.DefinitionDigest == second.DefinitionDigest,
            "equivalent workflow definitions produced different digests");

        var changedDestination = WorkflowRuleDefinition.Create(
            ruleId,
            revision: 7,
            owner,
            true,
            Activation,
            second.Trigger,
            Current(),
            second.Conditions,
            second.Actions);
        var changedOrder = WorkflowRuleDefinition.Create(
            ruleId,
            revision: 7,
            owner,
            true,
            Activation,
            second.Trigger,
            second.Destination,
            second.Conditions,
            [Protect(0), Send(presetOwner, preset, 1)]);
        var changedRevision = WorkflowRuleDefinition.Create(
            ruleId,
            revision: 8,
            owner,
            true,
            Activation,
            second.Trigger,
            second.Destination,
            second.Conditions,
            second.Actions);
        Ensure(
            first.DefinitionDigest != changedDestination.DefinitionDigest &&
            first.DefinitionDigest != changedOrder.DefinitionDigest &&
            first.DefinitionDigest != changedRevision.DefinitionDigest,
            "behavioral workflow changes did not change the canonical digest");
    }

    private static void TestTypedDefinitionValidation()
    {
        var owner = Id(10);
        var preset = Id(11);
        AssertThrows<ArgumentException>(() => WorkflowRuleDefinition.Create(
            Id(12),
            1,
            owner,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = Activation,
                SourceConversationId = owner
            },
            Current(),
            null,
            [Send(owner, preset, 0)]));
        AssertThrows<ArgumentException>(() => WorkflowRuleDefinition.Create(
            Id(13),
            1,
            owner,
            true,
            Activation,
            Scheduled(),
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation
            },
            null,
            [Send(owner, preset, 0)]));
        AssertThrows<ArgumentException>(() => WorkflowRuleDefinition.Create(
            Id(14),
            1,
            owner,
            true,
            Activation,
            Scheduled(),
            Current(),
            null,
            [
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.EnableConversationProtection,
                    PresetOwnerConversationId = owner,
                    PresetMessageId = preset,
                    Order = 0
                }
            ]));
        AssertThrows<ArgumentException>(() => WorkflowRuleDefinition.Create(
            Id(15),
            1,
            owner,
            true,
            Activation,
            Scheduled(),
            Current(),
            null,
            [Send(owner, preset, 1)]));
        AssertThrows<ArgumentException>(() => WorkflowRuleDefinition.Create(
            Id(16),
            1,
            owner,
            true,
            Activation,
            Scheduled(),
            Current(),
            Enumerable.Repeat(WorkflowConditionKind.TargetIdle, WorkflowRuleDefinition.MaximumConditions + 1),
            [Send(owner, preset, 0)]));
        AssertThrows<ArgumentException>(() => WorkflowRuleDefinition.Create(
            Id(17),
            1,
            owner,
            true,
            Activation,
            Scheduled(),
            Current(),
            null,
            [Send(owner, preset, 0), Send(owner, preset, 1)]));
    }

    private static void TestLegacyQueueIsolation()
    {
        var threadId = Id(20);
        var firstId = Id(21);
        var secondId = Id(22);
        var schedule = DateTimeOffset.Parse("2026-08-16T10:00:00+08:00");
        var normalized = SettingsService.NormalizeThreadFollowUps(
            new Dictionary<string, ThreadFollowUpSettings>
            {
                [threadId] = new()
                {
                    IsEnabled = true,
                    Messages =
                    [
                        new FollowUpMessageDefinition
                        {
                            Id = secondId,
                            Message = "scheduled",
                            Trigger = FollowUpTriggerKind.ScheduledAt,
                            ScheduledAtUtc = schedule,
                            Order = 1
                        },
                        new FollowUpMessageDefinition
                        {
                            Id = firstId,
                            Message = "completion",
                            Trigger = FollowUpTriggerKind.AfterNormalCompletion,
                            Order = 0
                        }
                    ]
                }
            });
        var messages = normalized[threadId].Messages;
        Ensure(
            messages.Count == 2 &&
            messages[0].Id == firstId &&
            !messages[0].UseWorkflowAutomation &&
            messages[0].Trigger == FollowUpTriggerKind.AfterNormalCompletion &&
            messages[0].ScheduledAtUtc is null &&
            messages[1].Id == secondId &&
            messages[1].Trigger == FollowUpTriggerKind.ScheduledAt &&
            messages[1].ScheduledAtUtc == schedule.ToUniversalTime(),
            "legacy follow-up queue semantics were reinterpreted");
        Ensure(
            typeof(FollowUpMessageDefinition).GetProperties().All(property =>
                property.PropertyType != typeof(WorkflowRuleDefinition)),
            "legacy follow-up definitions were coupled to workflow rules");
    }

    private static void TestAcyclicGraph()
    {
        var conversationA = Id(30);
        var conversationB = Id(31);
        var conversationC = Id(32);
        var ruleA = Rule(
            Id(33),
            conversationA,
            Scheduled(),
            Existing(conversationB),
            [Send(conversationA, Id(34), 0)]);
        var ruleB = Rule(
            Id(35),
            conversationB,
            NormalCompletion(conversationB),
            Existing(conversationC),
            [Protect(0)]);
        var result = WorkflowRuleGraphValidator.Validate([ruleA, ruleB]);
        Ensure(result.IsValid && result.Issues.Count == 0, "acyclic workflow graph was rejected");
        Ensure(result.Edges[ruleA.RuleId].SequenceEqual([ruleB.RuleId]), "completion edge was not derived");
        Ensure(result.Edges[ruleB.RuleId].Count == 0, "protection action fabricated a trigger edge");
    }

    private static void TestPresetSelfCycle()
    {
        var owner = Id(40);
        var preset = Id(41);
        var rule = Rule(
            Id(42),
            owner,
            PresetConfirmed(owner, preset),
            Existing(Id(43)),
            [Send(owner, preset, 0)]);
        AssertCycle([rule], [rule.RuleId, rule.RuleId]);
    }

    private static void TestCompletionSelfCycle()
    {
        var owner = Id(50);
        var rule = Rule(
            Id(51),
            owner,
            NormalCompletion(owner),
            Current(),
            [Send(owner, Id(52), 0)]);
        AssertCycle([rule], [rule.RuleId, rule.RuleId]);
    }

    private static void TestCrossConversationCycle()
    {
        var conversationA = Id(60);
        var conversationB = Id(61);
        var ruleA = Rule(
            Id(62),
            conversationA,
            NormalCompletion(conversationA),
            Existing(conversationB),
            [Send(conversationA, Id(63), 0)]);
        var ruleB = Rule(
            Id(64),
            conversationB,
            NormalCompletion(conversationB),
            Existing(conversationA),
            [Send(conversationB, Id(65), 0)]);
        AssertCycle([ruleA, ruleB], [ruleA.RuleId, ruleB.RuleId, ruleA.RuleId]);
    }

    private static void TestCrossPresetCycle()
    {
        var owner = Id(70);
        var firstPreset = Id(71);
        var secondPreset = Id(72);
        var ruleA = Rule(
            Id(73),
            owner,
            PresetConfirmed(owner, firstPreset),
            Existing(Id(75)),
            [Send(owner, secondPreset, 0)]);
        var ruleB = Rule(
            Id(74),
            owner,
            PresetConfirmed(owner, secondPreset),
            Existing(Id(76)),
            [Send(owner, firstPreset, 0)]);
        AssertCycle([ruleA, ruleB], [ruleA.RuleId, ruleB.RuleId, ruleA.RuleId]);
    }

    private static void TestNewConversationCapability()
    {
        var owner = Id(80);
        var rule = Rule(
            Id(81),
            owner,
            Scheduled(),
            NewConversation(),
            [Send(owner, Id(82), 0)]);
        var unavailable = WorkflowRuleGraphValidator.Validate([rule]);
        Ensure(
            !unavailable.IsValid && unavailable.Issues.Any(issue =>
                issue.Code == WorkflowRuleValidationIssueCode.NewConversationUnavailable &&
                issue.RuleId == rule.RuleId),
            "new-conversation action was not kept unavailable");
        var proved = WorkflowRuleGraphValidator.Validate(
            [rule],
            new WorkflowRuleGraphCapabilities(AllowsNewConversation: true));
        Ensure(proved.IsValid, "proved new-conversation capability was still rejected");
    }

    private static void TestDuplicateRuleIdentity()
    {
        var rule = Rule(
            Id(90),
            Id(91),
            Scheduled(),
            Existing(Id(92)),
            [Protect(0)]);
        var duplicate = WorkflowRuleGraphValidator.Validate([rule, rule]);
        Ensure(
            !duplicate.IsValid && duplicate.Issues.Any(issue =>
                issue.Code == WorkflowRuleValidationIssueCode.DuplicateRuleId),
            "duplicate rule identity was accepted");
    }

    private static WorkflowRuleDefinition Rule(
        string ruleId,
        string ownerConversationId,
        WorkflowTriggerDefinition trigger,
        WorkflowDestinationDefinition destination,
        IReadOnlyList<WorkflowActionDefinition> actions) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            revision: 1,
            ownerConversationId,
            isEnabled: true,
            Activation,
            trigger,
            destination,
            [
                WorkflowConditionKind.RuleAndPresetEnabled,
                WorkflowConditionKind.SourceEventAfterActivation,
                WorkflowConditionKind.TargetPolicyAllowsAction
            ],
            actions);

    private static WorkflowTriggerDefinition Scheduled() => new()
    {
        Kind = WorkflowTriggerKind.ScheduledAt,
        ScheduledAtUtc = Activation.AddHours(1)
    };

    private static WorkflowTriggerDefinition NormalCompletion(string conversationId) => new()
    {
        Kind = WorkflowTriggerKind.ConversationCompletedNormally,
        SourceConversationId = conversationId
    };

    private static WorkflowTriggerDefinition PresetConfirmed(
        string conversationId,
        string presetMessageId) => new()
    {
        Kind = WorkflowTriggerKind.PresetDispatchConfirmed,
        SourceConversationId = conversationId,
        SourcePresetMessageId = presetMessageId
    };

    private static WorkflowDestinationDefinition Current() => new()
    {
        Kind = WorkflowDestinationKind.CurrentConversation
    };

    private static WorkflowDestinationDefinition Existing(string conversationId) => new()
    {
        Kind = WorkflowDestinationKind.ExistingConversation,
        ConversationId = conversationId
    };

    private static WorkflowDestinationDefinition NewConversation() => new()
    {
        Kind = WorkflowDestinationKind.NewConversation
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

    private static void AssertCycle(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        IReadOnlyList<string> expectedPath)
    {
        var result = WorkflowRuleGraphValidator.Validate(rules);
        var issue = result.Issues.SingleOrDefault(candidate =>
            candidate.Code == WorkflowRuleValidationIssueCode.CycleDetected);
        Ensure(!result.IsValid && issue is not null, "workflow cycle was accepted");
        Ensure(issue!.RulePath.SequenceEqual(expectedPath), "workflow cycle path was not deterministic");
    }

    private static string Id(int value) =>
        $"00000000-0000-0000-0000-{value:D12}";

    private static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void RunCase(string name, Action test, Action<bool, string> assert)
    {
        try
        {
            test();
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
