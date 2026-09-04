using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Collections.Concurrent;
using System.IO;

internal static class WorkflowExecutionPipelineOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow resolution uses exact root and preset identities instead of titles",
            TestExactResolutionAsync,
            assert);
        await RunCaseAsync(
            "workflow resolution requires the preset workflow-mode activation marker",
            TestPresetModeActivationAsync,
            assert);
        await RunCaseAsync(
            "monitor-only recovery does not block an explicitly authorized workflow preset",
            TestMonitorOnlyWorkflowAuthorizationAsync,
            assert);
        await RunCaseAsync(
            "workflow protection action precedes and authorizes its managed preset send",
            TestProtectionBeforeManagedSendAsync,
            assert);
        await RunCaseAsync(
            "workflow source activation uses authoritative completion time and confirmed receipts",
            TestSourceActivationAsync,
            assert);
        await RunCaseAsync(
            "workflow finite conditions report archived busy and attachment failures",
            TestFiniteConditionFailuresAsync,
            assert);
        await RunCaseAsync(
            "workflow operation authority excludes its own inner dispatch but detects other work",
            TestOperationAuthorityOwnershipAsync,
            assert);
        await RunCaseAsync(
            "workflow runner bridges the exact existing target through a revocable policy token",
            TestExistingTargetRunnerAsync,
            assert);
        await RunCaseAsync(
            "workflow runner exhausts only proven-unsent preset retries",
            TestRetryExhaustionAsync,
            assert);
        await RunCaseAsync(
            "workflow runner waits on unresolved target work before local protection",
            TestBusyThenProtectionAsync,
            assert);
        await RunCaseAsync(
            "workflow runner keeps new-conversation creation explicitly unavailable",
            TestNewConversationUnavailableAsync,
            assert);
    }

    private static async Task TestExactResolutionAsync()
    {
        var sourceId = Id(100);
        var targetId = Id(101);
        var wrongSameTitleId = Id(102);
        var presetOwnerId = Id(103);
        var presetId = Id(104);
        var wrongPresetId = Id(105);
        var source = RootThread(sourceId, "Repeated title");
        var target = RootThread(targetId, "Repeated title");
        var wrongSameTitle = RootThread(wrongSameTitleId, "Repeated title");
        var exact = AppServerWorkflowConversationAuthorityReader.ResolveExactDirectoryEntry(
            targetId,
            [wrongSameTitle, target],
            []);
        var ambiguous = AppServerWorkflowConversationAuthorityReader.ResolveExactDirectoryEntry(
            targetId,
            [target],
            [target with { IsArchived = true }]);
        Ensure(
            exact.Status == WorkflowConversationAuthorityStatus.Available &&
            exact.Thread?.Id == targetId &&
            ambiguous.Status == WorkflowConversationAuthorityStatus.Ambiguous,
            "exact directory resolution used a title or accepted duplicate authority");

        var completedAt = Activation.AddMinutes(5);
        var sourceTurn = NormalTurn(Id(106), completedAt);
        var targetTurn = NormalTurn(Id(107), Activation.AddMinutes(6));
        var preset = Preset(presetId, "send the exact preset");
        var wrongPreset = Preset(wrongPresetId, "wrong preset");
        var settings = Settings(
            targetId,
            presetOwnerId,
            [wrongPreset, preset],
            monitorOnly: false);
        var rule = CompletionSendRule(
            Id(108),
            sourceId,
            targetId,
            presetOwnerId,
            presetId,
            Enum.GetValues<WorkflowConditionKind>());
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(7));
        var fixture = CreateFixture(
            settings,
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(source, sourceTurn, sourceTurn),
                [targetId] = Available(target, targetTurn),
                [presetOwnerId] = Available(RootThread(presetOwnerId, "Preset owner"), targetTurn),
                [wrongSameTitleId] = Available(wrongSameTitle, targetTurn)
            });
        var resolution = await fixture.Resolver.ResolveAsync(rule, trigger);
        var conditions = await new WorkflowFiniteConditionEvaluator(fixture.Resolver)
            .EvaluateAsync(rule, trigger, CancellationToken.None);
        Ensure(
            conditions.IsAllowed && conditions.FailedConditions.Count == 0 &&
            resolution.TargetConversation?.Thread?.Id == targetId &&
            resolution.Presets[0].Definition?.Id == presetId &&
            resolution.Presets[0].Definition?.Message == preset.Message &&
            fixture.Conversations.RequestedIds.Contains(sourceId) &&
            fixture.Conversations.RequestedTurns[sourceId] == sourceTurn.Id &&
            fixture.Conversations.RequestedIds.Contains(targetId) &&
            fixture.Conversations.RequestedIds.Contains(presetOwnerId),
            "workflow resolution changed an exact conversation or preset reference");

        fixture.Rules.Snapshot = fixture.Rules.Snapshot with
        {
            IsCurrentEnabled = false,
            RuleStoreGeneration = 14
        };
        var stale = await new WorkflowFiniteConditionEvaluator(fixture.Resolver)
            .EvaluateAsync(rule, trigger, CancellationToken.None);
        Ensure(
            !stale.IsAllowed &&
            stale.FailedConditions.SequenceEqual([WorkflowConditionKind.RuleAndPresetEnabled]),
            "a replaced rule revision remained eligible for execution");
    }

    private static async Task TestSourceActivationAsync()
    {
        var sourceId = Id(200);
        var targetId = Id(201);
        var presetId = Id(202);
        var oldTurn = NormalTurn(Id(203), Activation.AddSeconds(-1));
        var targetTurn = NormalTurn(Id(204), Activation.AddMinutes(2));
        var settings = Settings(
            targetId,
            sourceId,
            [Preset(presetId, "activation check")],
            monitorOnly: false);
        var completionRule = CompletionSendRule(
            Id(205),
            sourceId,
            targetId,
            sourceId,
            presetId,
            [WorkflowConditionKind.SourceEventAfterActivation]);
        var completionTrigger = CompletionEvent(
            completionRule,
            oldTurn,
            Activation.AddHours(1));
        var fixture = CreateFixture(
            settings,
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), oldTurn, oldTurn),
                [targetId] = Available(RootThread(targetId), targetTurn)
            });
        var oldCompletion = await fixture.Resolver.ResolveAsync(
            completionRule,
            completionTrigger);
        Ensure(
            !oldCompletion.SourceEventAfterActivation,
            "a stale completion became new merely because it was observed after activation");

        var sourcePresetId = Id(206);
        var generatedTurnId = Id(207);
        var sourceActionId = Id(208);
        var dispatchRule = DispatchProtectionRule(
            Id(209),
            sourceId,
            sourcePresetId,
            targetId);
        var dispatchTrigger = DispatchEvent(
            dispatchRule,
            sourceActionId,
            generatedTurnId,
            Activation.AddMinutes(4));
        fixture.Operations.Snapshot = new WorkflowOperationAuthoritySnapshot(
            true,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            SourceAction(
                sourceActionId,
                sourceId,
                sourcePresetId,
                generatedTurnId,
                WorkflowActionOperationState.Uncertain,
                Activation.AddMinutes(3)));
        var uncertain = await fixture.Resolver.ResolveAsync(dispatchRule, dispatchTrigger);
        fixture.Operations.Snapshot = fixture.Operations.Snapshot with
        {
            SourceDispatchAction = fixture.Operations.Snapshot.SourceDispatchAction! with
            {
                State = WorkflowActionOperationState.Confirmed
            }
        };
        var confirmed = await fixture.Resolver.ResolveAsync(dispatchRule, dispatchTrigger);
        Ensure(
            !uncertain.SourceEventAfterActivation && confirmed.SourceEventAfterActivation,
            "dispatch confirmation fired without one confirmed generated-turn receipt");
    }

    private static async Task TestPresetModeActivationAsync()
    {
        var sourceId = Id(150);
        var targetId = Id(151);
        var presetOwnerId = Id(152);
        var presetId = Id(153);
        var sourceTurn = NormalTurn(Id(154), Activation.AddMinutes(1));
        var targetTurn = NormalTurn(Id(155), Activation.AddMinutes(2));
        var preset = Preset(presetId, "inactive workflow preset") with
        {
            UseWorkflowAutomation = false
        };
        var settings = Settings(
            targetId,
            presetOwnerId,
            [preset],
            monitorOnly: false);
        var rule = WorkflowRuleDefinition.Create(
            WorkflowRuleEditor.CreateManagedRuleId(presetOwnerId, presetId),
            1,
            presetOwnerId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                SourceConversationId = sourceId
            },
            Existing(targetId),
            [WorkflowConditionKind.RuleAndPresetEnabled],
            [Send(presetOwnerId, presetId, 0)]);
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(3));
        var fixture = CreateFixture(
            settings,
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn),
                [presetOwnerId] = Available(RootThread(presetOwnerId), targetTurn)
            });
        var resolution = await fixture.Resolver.ResolveAsync(rule, trigger);
        var stalePreset = preset with
        {
            UseWorkflowAutomation = true,
            WorkflowRuleRevision = rule.Revision,
            WorkflowRuleDigest = new string('A', 64)
        };
        var staleFixture = CreateFixture(
            Settings(targetId, presetOwnerId, [stalePreset], monitorOnly: false),
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn),
                [presetOwnerId] = Available(RootThread(presetOwnerId), targetTurn)
            });
        var stale = await staleFixture.Resolver.ResolveAsync(rule, trigger);
        var boundPreset = stalePreset with
        {
            WorkflowRuleDigest = rule.DefinitionDigest
        };
        var boundFixture = CreateFixture(
            Settings(targetId, presetOwnerId, [boundPreset], monitorOnly: false),
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn),
                [presetOwnerId] = Available(RootThread(presetOwnerId), targetTurn)
            });
        var bound = await boundFixture.Resolver.ResolveAsync(rule, trigger);
        Ensure(
            !resolution.RuleAndPresetEnabled &&
            !stale.RuleAndPresetEnabled &&
            bound.RuleAndPresetEnabled &&
            bound.Presets[0].Definition?.Id == presetId,
            "a legacy or stale rule binding remained eligible through the workflow execution path");
    }

    private static async Task TestMonitorOnlyWorkflowAuthorizationAsync()
    {
        var sourceId = Id(175);
        var targetId = Id(176);
        var ownerId = Id(177);
        var presetId = Id(178);
        var sourceTurn = NormalTurn(Id(179), Activation.AddMinutes(1));
        var targetTurn = NormalTurn(Id(180), Activation.AddMinutes(2));
        var preset = Preset(presetId, "monitor-only workflow");
        var rule = CompletionSendRule(
            Id(181),
            sourceId,
            targetId,
            ownerId,
            presetId,
            null);
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(3));
        var conversations = new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
            StringComparer.OrdinalIgnoreCase)
        {
            [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
            [targetId] = Available(RootThread(targetId), targetTurn),
            [ownerId] = Available(RootThread(ownerId), targetTurn)
        };

        var authorizedFixture = CreateFixture(
            Settings(targetId, ownerId, [preset], monitorOnly: true),
            conversations);
        var authorizedResolution = await authorizedFixture.Resolver.ResolveAsync(rule, trigger);
        Ensure(
            authorizedResolution.RuleAndPresetEnabled &&
            authorizedResolution.TargetPolicyAllowsAction,
            "MonitorOnly incorrectly revoked an explicitly authorized workflow preset");

        var executor = new FakeWorkflowActionExecutor();
        var dispatched = await new WorkflowRuleActionRunner(
                authorizedFixture.Resolver,
                executor,
                new FakeDispatchPolicyAuthority())
            .RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            dispatched.Status == WorkflowActionExecutionStatus.Confirmed &&
            executor.SendCalls.Count == 1,
            "an authorized workflow preset did not reach the guarded owner executor in monitor-only mode");

        var globalOffSettings = Settings(targetId, ownerId, [preset], monitorOnly: true);
        globalOffSettings.GlobalProtectionEnabled = false;
        var globalOff = await CreateFixture(globalOffSettings, conversations)
            .Resolver.ResolveAsync(rule, trigger);
        var targetOffSettings = Settings(targetId, ownerId, [preset], monitorOnly: true);
        targetOffSettings.ThreadProtectionEnabled[targetId] = false;
        var targetOff = await CreateFixture(targetOffSettings, conversations)
            .Resolver.ResolveAsync(rule, trigger);
        Ensure(
            !globalOff.TargetPolicyAllowsAction && !targetOff.TargetPolicyAllowsAction,
            "global or exact target protection could be bypassed in monitor-only mode");

        var unauthorizedFixture = CreateFixture(
            Settings(
                targetId,
                ownerId,
                [preset with { UseWorkflowAutomation = false }],
                monitorOnly: true),
            conversations);
        var unauthorizedResolution = await unauthorizedFixture.Resolver.ResolveAsync(rule, trigger);
        var blocked = await new WorkflowRuleActionRunner(
                unauthorizedFixture.Resolver,
                executor,
                new FakeDispatchPolicyAuthority())
            .RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            !unauthorizedResolution.RuleAndPresetEnabled &&
            !unauthorizedResolution.TargetPolicyAllowsAction &&
            blocked.Status == WorkflowActionExecutionStatus.Waiting &&
            executor.SendCalls.Count == 1,
            "turning off the explicit workflow marker left a monitor-only workflow eligible");
    }

    private static async Task TestFiniteConditionFailuresAsync()
    {
        var sourceId = Id(300);
        var targetId = Id(301);
        var presetOwnerId = Id(302);
        var presetId = Id(303);
        var sourceTurn = NormalTurn(Id(304), Activation.AddMinutes(2));
        var targetTurn = NormalTurn(Id(305), Activation.AddMinutes(3));
        var attachment = new PresetAttachmentReference
        {
            Id = Id(306),
            ContentId = new string('A', 64),
            OriginalFileName = "image.png",
            DetectedType = "image/png",
            OwnerInputKind = "image",
            ByteLength = 12,
            Order = 0
        };
        var preset = Preset(presetId, "attachment unavailable") with
        {
            Attachments = [attachment]
        };
        var settings = Settings(
            targetId,
            presetOwnerId,
            [preset],
            monitorOnly: false);
        var rule = CompletionSendRule(
            Id(307),
            sourceId,
            targetId,
            presetOwnerId,
            presetId,
            Enum.GetValues<WorkflowConditionKind>());
        var fixture = CreateFixture(
            settings,
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(
                    RootThread(targetId) with { IsArchived = true },
                    targetTurn),
                [presetOwnerId] = Available(RootThread(presetOwnerId), targetTurn)
            },
            attachmentsAvailable: false);
        fixture.Operations.Snapshot = new WorkflowOperationAuthoritySnapshot(
            true,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { targetId },
            SourceDispatchAction: null);
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(4));
        var result = await new WorkflowFiniteConditionEvaluator(fixture.Resolver)
            .EvaluateAsync(rule, trigger, CancellationToken.None);
        Ensure(
            !result.IsAllowed &&
            result.FailedConditions.SequenceEqual([
                WorkflowConditionKind.TargetConversationExists,
                WorkflowConditionKind.TargetIdle,
                WorkflowConditionKind.TargetPolicyAllowsAction,
                WorkflowConditionKind.ManagedAttachmentsAvailable
            ]),
            "finite condition failures were missing, unordered, or inferred from content");
    }

    private static async Task TestProtectionBeforeManagedSendAsync()
    {
        var sourceId = Id(190);
        var targetId = Id(191);
        var presetId = Id(192);
        var sourceTurn = NormalTurn(Id(193), Activation.AddMinutes(1));
        var targetTurn = NormalTurn(Id(194), Activation.AddMinutes(2));
        var preset = Preset(presetId, "protect then send");
        var rule = WorkflowRuleDefinition.Create(
            Id(195),
            1,
            sourceId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                SourceConversationId = sourceId
            },
            Existing(targetId),
            null,
            [
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.EnableConversationProtection,
                    Order = 0
                },
                Send(sourceId, presetId, 1)
            ]);
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(3));
        var settings = Settings(targetId, sourceId, [preset], monitorOnly: true);
        settings.ThreadProtectionEnabled[targetId] = false;
        var fixture = CreateFixture(
            settings,
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn)
            });
        var executor = new FakeWorkflowActionExecutor();
        var policy = new FakeDispatchPolicyAuthority();
        var runner = new WorkflowRuleActionRunner(fixture.Resolver, executor, policy);

        var protection = await runner.RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            protection.Status == WorkflowActionExecutionStatus.Confirmed &&
            executor.ProtectionCalls.SequenceEqual([targetId]) &&
            executor.SendCalls.Count == 0,
            "an unprotected managed target could not execute its leading protection action");

        settings.ThreadProtectionEnabled[targetId] = true;
        settings.SettingsGeneration++;
        var send = await runner.RunAsync(rule, trigger, 1, CancellationToken.None);
        Ensure(
            send.Status == WorkflowActionExecutionStatus.Confirmed &&
            executor.SendCalls.Count == 1 &&
            executor.SendCalls[0].Target.Id == targetId &&
            policy.Tokens.Count >= 3 &&
            policy.Tokens.All(token => token.ActionIndex == 1) &&
            policy.Tokens.All(token => token.SettingsGeneration == settings.SettingsGeneration),
            "the protected target did not re-resolve and dispatch through its current policy generation");

        var managedRule = WorkflowRuleEditor.BuildReplacement(
                new WorkflowRuleStoreSnapshot(
                    WorkflowRuleStoreReadStatus.Missing,
                    Generation: 0,
                    RequiresConservativeRecovery: false,
                    Rules: [],
                    Validation: WorkflowRuleGraphValidator.Validate([])),
                sourceId,
                [
                    new WorkflowRuleEditorDraft(
                        MessageId: presetId,
                        IsEnabled: true,
                        TriggerKind: WorkflowTriggerKind.ConversationCompletedNormally,
                        SourceConversationId: sourceId,
                        SourcePresetMessageId: null,
                        ScheduledAtUtc: null,
                        DestinationKind: WorkflowDestinationKind.ExistingConversation,
                        TargetConversationId: targetId,
                        EnableTargetProtection: true)
                ],
                Activation)
            .Single();
        var attachmentPreset = preset with
        {
            Message = "protect before unavailable attachment",
            Attachments =
            [
                new PresetAttachmentReference
                {
                    Id = Id(196),
                    ContentId = new string('B', 64),
                    OriginalFileName = "unavailable.png",
                    DetectedType = "image/png",
                    OwnerInputKind = "image",
                    ByteLength = 32,
                    Order = 0
                }
            ],
            WorkflowRuleRevision = managedRule.Revision,
            WorkflowRuleDigest = managedRule.DefinitionDigest
        };
        var managedSettings = Settings(
            targetId,
            sourceId,
            [attachmentPreset],
            monitorOnly: true);
        managedSettings.ThreadProtectionEnabled[targetId] = false;
        var managedFixture = CreateFixture(
            managedSettings,
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn)
            },
            attachmentsAvailable: false);
        var managedExecutor = new FakeWorkflowActionExecutor(protectedTargetId =>
        {
            managedSettings.ThreadProtectionEnabled[protectedTargetId] = true;
            managedSettings.SettingsGeneration++;
        });
        var coordinator = new WorkflowTriggerCoordinator(
            new WorkflowOperationJournal(
                CreateRoot(),
                timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3))),
            new WorkflowFiniteConditionEvaluator(managedFixture.Resolver),
            new WorkflowRuleActionRunner(
                managedFixture.Resolver,
                managedExecutor,
                new FakeDispatchPolicyAuthority()));
        var coordinated = await coordinator.ProcessConversationCompletedAsync(
            [managedRule],
            RootThread(sourceId),
            sourceTurn,
            Activation.AddMinutes(3),
            CancellationToken.None);
        Ensure(
            !coordinated.Single().Conditions.IsAllowed &&
            coordinated.Single().Conditions.FailedConditions.SequenceEqual([
                WorkflowConditionKind.ManagedAttachmentsAvailable
            ]) &&
            coordinated.Single().Actions.Count == 0 &&
            managedExecutor.ProtectionCalls.Count == 0 &&
            managedExecutor.SendCalls.Count == 0 &&
            !managedSettings.ThreadProtectionEnabled[targetId] &&
            !managedRule.Conditions.Contains(WorkflowConditionKind.TargetPolicyAllowsAction) &&
            managedRule.Conditions.Contains(WorkflowConditionKind.ManagedAttachmentsAvailable),
            "coordinator allowed protection or sent before attachment authority became available");
    }

    private static async Task TestExistingTargetRunnerAsync()
    {
        var sourceId = Id(400);
        var targetId = Id(401);
        var presetOwnerId = Id(402);
        var presetId = Id(403);
        var sourceTurn = NormalTurn(Id(404), Activation.AddMinutes(2));
        var targetTurn = NormalTurn(Id(405), Activation.AddMinutes(3));
        var preset = Preset(presetId, "run exact target");
        var settings = Settings(
            targetId,
            presetOwnerId,
            [preset],
            monitorOnly: false,
            generation: 41);
        var rule = CompletionSendRule(
            Id(406),
            sourceId,
            targetId,
            presetOwnerId,
            presetId,
            null);
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(4));
        var fixture = CreateFixture(
            settings,
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn),
                [presetOwnerId] = Available(RootThread(presetOwnerId), targetTurn)
            });
        var executor = new FakeWorkflowActionExecutor();
        var policy = new FakeDispatchPolicyAuthority();
        var runner = new WorkflowRuleActionRunner(fixture.Resolver, executor, policy);
        var result = await runner.RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            result.Status == WorkflowActionExecutionStatus.Confirmed &&
            executor.SendCalls.Count == 1 &&
            executor.SendCalls[0].Target.Id == targetId &&
            executor.SendCalls[0].PresetOwnerId == presetOwnerId &&
            executor.SendCalls[0].Preset.Id == presetId &&
            policy.Tokens.Count >= 3 &&
            policy.Tokens.All(token =>
                token.SettingsGeneration == 41 &&
                token.RuleStoreGeneration == 13 &&
                token.TargetConversationId == targetId &&
                token.PresetMessageId == presetId),
            "runner changed the exact target, preset, or revocable policy identity");

        policy.IsAllowed = false;
        var revoked = await runner.RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            revoked.Status == WorkflowActionExecutionStatus.Waiting &&
            executor.SendCalls.Count == 1,
            "a revoked workflow policy still reached the owner executor");
    }

    private static async Task TestOperationAuthorityOwnershipAsync()
    {
        var root = CreateRoot();
        var workflowJournal = new WorkflowOperationJournal(
            Path.Combine(root, "workflow"),
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var followUpJournal = new FollowUpOperationJournal(Path.Combine(root, "follow-up"));
        var ownerId = Id(350);
        var targetId = Id(351);
        var presetId = Id(352);
        var rule = WorkflowRuleDefinition.Create(
            Id(353),
            1,
            ownerId,
            true,
            Activation,
            ScheduledTrigger(),
            Existing(targetId),
            null,
            [Send(ownerId, presetId, 0)]);
        var trigger = await workflowJournal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            ownerId,
            rule.RuleId,
            rule.RuleId,
            "scheduled:" + rule.Trigger.ScheduledAtUtc!.Value.UtcTicks,
            Activation.AddHours(1));
        var action = await workflowJournal.GetOrCreateActionAsync(
            rule,
            trigger.Record.TriggerEventId,
            0,
            targetId);
        var expectedTurnId = Id(354);
        var payload = StructuredPresetPayload.Create("own inner dispatch", []);
        _ = await followUpJournal.GetOrCreateStructuredAsync(
            action.Record.ActionOperationId,
            targetId,
            presetId,
            FollowUpTriggerKind.AfterNormalCompletion,
            expectedTurnId,
            scheduledAtUtc: null,
            payload,
            presentationLeaseId: null,
            FollowUpPayloadSourceKind.WorkflowPreset,
            action.Record.ClientMessageId!);
        var reader = new JournalWorkflowOperationAuthorityReader(
            workflowJournal,
            followUpJournal);
        var own = await reader.ReadAsync(trigger.Record, CancellationToken.None);
        Ensure(
            own.IsAvailable && !own.BusyConversationIds.Contains(targetId),
            "the current action's inner follow-up prevented its own reconciliation");

        _ = await followUpJournal.GetOrCreateAsync(
            Id(355),
            targetId,
            Id(356),
            FollowUpTriggerKind.AfterNormalCompletion,
            expectedTurnId,
            scheduledAtUtc: null,
            FollowUpOperationJournal.ComputeMessageHash("other pending work"),
            Id(357));
        var other = await reader.ReadAsync(trigger.Record, CancellationToken.None);
        Ensure(
            other.BusyConversationIds.Contains(targetId),
            "a different unresolved owner operation was not treated as target busy");
    }

    private static async Task TestBusyThenProtectionAsync()
    {
        var sourceId = Id(500);
        var targetId = Id(501);
        var sourceTurn = NormalTurn(Id(502), Activation.AddMinutes(2));
        var targetTurn = NormalTurn(Id(503), Activation.AddMinutes(3));
        var rule = CompletionProtectionRule(Id(504), sourceId, targetId);
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(4));
        var fixture = CreateFixture(
            Settings(targetId, sourceId, [], monitorOnly: true),
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn)
            });
        fixture.Operations.Snapshot = new WorkflowOperationAuthoritySnapshot(
            true,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { targetId },
            SourceDispatchAction: null);
        var executor = new FakeWorkflowActionExecutor();
        var runner = new WorkflowRuleActionRunner(
            fixture.Resolver,
            executor,
            new FakeDispatchPolicyAuthority());
        var waiting = await runner.RunAsync(rule, trigger, 0, CancellationToken.None);
        fixture.Operations.Snapshot = fixture.Operations.Snapshot with
        {
            BusyConversationIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        };
        var confirmed = await runner.RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            waiting.Status == WorkflowActionExecutionStatus.Waiting &&
            confirmed.Status == WorkflowActionExecutionStatus.Confirmed &&
            executor.ProtectionCalls.SequenceEqual([targetId]),
            "busy target work was ignored or protection was applied to another conversation");
    }

    private static async Task TestRetryExhaustionAsync()
    {
        var sourceId = Id(450);
        var targetId = Id(451);
        var presetId = Id(452);
        var sourceTurn = NormalTurn(Id(453), Activation.AddMinutes(2));
        var targetTurn = NormalTurn(Id(454), Activation.AddMinutes(3));
        var preset = Preset(presetId, "do not exceed retry budget") with
        {
            MaximumErrorRetries = 0
        };
        var rule = CompletionSendRule(
            Id(455),
            sourceId,
            targetId,
            sourceId,
            presetId,
            null);
        var trigger = CompletionEvent(rule, sourceTurn, Activation.AddMinutes(4));
        var fixture = CreateFixture(
            Settings(targetId, sourceId, [preset], monitorOnly: false),
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn)
            });
        fixture.Operations.Snapshot = fixture.Operations.Snapshot with
        {
            CurrentTriggerActions =
            [
                SourceAction(
                    Id(456),
                    sourceId,
                    presetId,
                    Id(457),
                    WorkflowActionOperationState.Retryable,
                    Activation.AddMinutes(3)) with
                {
                    RuleId = rule.RuleId,
                    RuleRevision = rule.Revision,
                    DefinitionDigest = rule.DefinitionDigest,
                    TriggerEventId = trigger.TriggerEventId,
                    TargetConversationId = targetId,
                    AttemptCount = 1
                }
            ]
        };
        var executor = new FakeWorkflowActionExecutor();
        var runner = new WorkflowRuleActionRunner(
            fixture.Resolver,
            executor,
            new FakeDispatchPolicyAuthority());
        var result = await runner.RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            result.Status == WorkflowActionExecutionStatus.Exhausted &&
            executor.ExhaustedCalls == 1 &&
            executor.SendCalls.Count == 0,
            "a proven-unsent action exceeded its configured retry allowance");

        var infinitePreset = Preset(Id(458), "keep retrying proven-unsent errors") with
        {
            RetryIndefinitely = true
        };
        var infiniteRule = CompletionSendRule(
            Id(459),
            sourceId,
            targetId,
            sourceId,
            infinitePreset.Id,
            null);
        var infiniteTrigger = CompletionEvent(
            infiniteRule,
            sourceTurn,
            Activation.AddMinutes(4));
        var infiniteFixture = CreateFixture(
            Settings(targetId, sourceId, [infinitePreset], monitorOnly: false),
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [sourceId] = Available(RootThread(sourceId), sourceTurn, sourceTurn),
                [targetId] = Available(RootThread(targetId), targetTurn)
            });
        infiniteFixture.Operations.Snapshot = infiniteFixture.Operations.Snapshot with
        {
            CurrentTriggerActions =
            [
                SourceAction(
                    Id(460),
                    sourceId,
                    infinitePreset.Id,
                    Id(461),
                    WorkflowActionOperationState.Retryable,
                    Activation.AddMinutes(3)) with
                {
                    RuleId = infiniteRule.RuleId,
                    RuleRevision = infiniteRule.Revision,
                    DefinitionDigest = infiniteRule.DefinitionDigest,
                    TriggerEventId = infiniteTrigger.TriggerEventId,
                    TargetConversationId = targetId,
                    AttemptCount = FollowUpRetryPolicy.MaximumErrorRetriesLimit + 1
                }
            ]
        };
        var infiniteExecutor = new FakeWorkflowActionExecutor();
        var infiniteResult = await new WorkflowRuleActionRunner(
                infiniteFixture.Resolver,
                infiniteExecutor,
                new FakeDispatchPolicyAuthority())
            .RunAsync(infiniteRule, infiniteTrigger, 0, CancellationToken.None);
        Ensure(
            infiniteResult.Status == WorkflowActionExecutionStatus.Confirmed &&
            infiniteExecutor.ExhaustedCalls == 0 &&
            infiniteExecutor.SendCalls.Count == 1,
            "explicit infinite retry was exhausted by the finite retry ceiling");
    }

    private static async Task TestNewConversationUnavailableAsync()
    {
        var ownerId = Id(600);
        var presetId = Id(601);
        var rule = WorkflowRuleDefinition.Create(
            Id(602),
            1,
            ownerId,
            true,
            Activation,
            ScheduledTrigger(),
            new WorkflowDestinationDefinition { Kind = WorkflowDestinationKind.NewConversation },
            null,
            [Send(ownerId, presetId, 0)]);
        var trigger = ScheduledEvent(rule, Activation.AddHours(1));
        var fixture = CreateFixture(
            Settings(ownerId, ownerId, [Preset(presetId, "new conversation")], monitorOnly: false),
            new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase)
            {
                [ownerId] = Available(
                    RootThread(ownerId),
                    NormalTurn(Id(603), Activation.AddMinutes(1)))
            });
        var executor = new FakeWorkflowActionExecutor();
        var runner = new WorkflowRuleActionRunner(
            fixture.Resolver,
            executor,
            new FakeDispatchPolicyAuthority());
        var result = await runner.RunAsync(rule, trigger, 0, CancellationToken.None);
        Ensure(
            result.Status == WorkflowActionExecutionStatus.CapabilityUnavailable &&
            executor.NewConversationUnavailableCalls == 1 &&
            executor.SendCalls.Count == 0 &&
            executor.ProtectionCalls.Count == 0,
            "new-conversation work was simulated or redirected to an existing conversation");
    }

    private static WorkflowFixture CreateFixture(
        AppSettings settings,
        IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot> conversations,
        bool attachmentsAvailable = true)
    {
        var conversationReader = new FakeConversationAuthorityReader(conversations);
        var settingsReader = new FakeSettingsAuthorityReader(
            new WorkflowSettingsAuthoritySnapshot(true, settings));
        var operations = new FakeOperationAuthorityReader(new WorkflowOperationAuthoritySnapshot(
            true,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            SourceDispatchAction: null));
        var rules = new FakeRuleRevisionAuthorityReader(
            new WorkflowRuleRevisionAuthoritySnapshot(
                true,
                true,
                RuleStoreGeneration: 13));
        var resolver = new WorkflowExecutionResolver(
            conversationReader,
            settingsReader,
            rules,
            operations,
            new FakeAttachmentAvailabilityReader(attachmentsAvailable));
        return new WorkflowFixture(resolver, conversationReader, rules, operations);
    }

    private static AppSettings Settings(
        string targetId,
        string presetOwnerId,
        IReadOnlyList<FollowUpMessageDefinition> messages,
        bool monitorOnly,
        long generation = 7)
    {
        var settings = new AppSettings
        {
            MonitorOnly = monitorOnly,
            GlobalProtectionEnabled = true,
            ProtectNewThreadsByDefault = false,
            ThreadProtectionEnabled = new ConcurrentDictionary<string, bool>(
                new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
                {
                    [targetId] = true
                },
                StringComparer.OrdinalIgnoreCase),
            ThreadFollowUps = new ConcurrentDictionary<string, ThreadFollowUpSettings>(
                new Dictionary<string, ThreadFollowUpSettings>(StringComparer.OrdinalIgnoreCase)
                {
                    [presetOwnerId] = new ThreadFollowUpSettings
                    {
                        IsEnabled = true,
                        Messages = messages
                    }
                },
                StringComparer.OrdinalIgnoreCase)
        };
        settings.ReadStatus = SettingsReadStatus.Healthy;
        settings.SettingsGeneration = generation;
        settings.PreviousSettingsGeneration = Math.Max(1, generation - 1);
        return settings;
    }

    private static WorkflowRuleDefinition CompletionSendRule(
        string ruleId,
        string sourceConversationId,
        string targetConversationId,
        string presetOwnerConversationId,
        string presetId,
        IEnumerable<WorkflowConditionKind>? conditions) =>
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
            Existing(targetConversationId),
            conditions,
            [Send(presetOwnerConversationId, presetId, 0)]);

    private static WorkflowRuleDefinition CompletionProtectionRule(
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
            Existing(targetConversationId),
            null,
            [new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = 0
            }]);

    private static WorkflowRuleDefinition DispatchProtectionRule(
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
            Existing(targetConversationId),
            [WorkflowConditionKind.SourceEventAfterActivation],
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

    private static WorkflowDestinationDefinition Existing(string conversationId) => new()
    {
        Kind = WorkflowDestinationKind.ExistingConversation,
        ConversationId = conversationId
    };

    private static WorkflowTriggerDefinition ScheduledTrigger() => new()
    {
        Kind = WorkflowTriggerKind.ScheduledAt,
        ScheduledAtUtc = Activation.AddMinutes(30)
    };

    private static WorkflowTriggerEventRecord CompletionEvent(
        WorkflowRuleDefinition rule,
        TurnSnapshot turn,
        DateTimeOffset observedAtUtc) =>
        Event(
            WorkflowTriggerKind.ConversationCompletedNormally,
            rule.Trigger.SourceConversationId!,
            rule.Trigger.SourceConversationId!,
            turn.Id,
            "normal-completion:" + turn.CompletedAt,
            observedAtUtc);

    private static WorkflowTriggerEventRecord DispatchEvent(
        WorkflowRuleDefinition rule,
        string sourceActionId,
        string generatedTurnId,
        DateTimeOffset observedAtUtc) =>
        Event(
            WorkflowTriggerKind.PresetDispatchConfirmed,
            rule.Trigger.SourceConversationId!,
            rule.Trigger.SourcePresetMessageId!,
            sourceActionId,
            generatedTurnId,
            observedAtUtc);

    private static WorkflowTriggerEventRecord ScheduledEvent(
        WorkflowRuleDefinition rule,
        DateTimeOffset observedAtUtc) =>
        Event(
            WorkflowTriggerKind.ScheduledAt,
            rule.OwnerConversationId,
            rule.RuleId,
            rule.RuleId,
            "scheduled:" + rule.Trigger.ScheduledAtUtc!.Value.UtcTicks,
            observedAtUtc);

    private static WorkflowTriggerEventRecord Event(
        WorkflowTriggerKind kind,
        string sourceConversationId,
        string sourceId,
        string sourceTurnOrOperationId,
        string occurrence,
        DateTimeOffset observedAtUtc)
    {
        var eventId = Guid.NewGuid().ToString("D");
        return new WorkflowTriggerEventRecord(
            eventId,
            kind,
            sourceConversationId,
            sourceId,
            sourceTurnOrOperationId,
            occurrence,
            eventId,
            CausationId: null,
            CorrelationDepth: 0,
            observedAtUtc);
    }

    private static WorkflowActionOperationRecord SourceAction(
        string actionId,
        string presetOwnerId,
        string presetId,
        string generatedTurnId,
        WorkflowActionOperationState state,
        DateTimeOffset updatedAtUtc) =>
        new(
            actionId,
            Id(900),
            1,
            new string('A', 64),
            Id(901),
            Id(902),
            Id(901),
            0,
            1,
            WorkflowActionKind.SendPresetMessage,
            WorkflowDestinationKind.ExistingConversation,
            Id(903),
            presetOwnerId,
            presetId,
            Id(904),
            state,
            1,
            FailureClass: null,
            ConfirmedTargetConversationId: Id(903),
            generatedTurnId,
            ProtectionSettingsGeneration: null,
            updatedAtUtc.AddMinutes(-1),
            updatedAtUtc);

    private static WorkflowConversationAuthoritySnapshot Available(
        ThreadSummary thread,
        TurnSnapshot? latest,
        TurnSnapshot? required = null) =>
        new(
            WorkflowConversationAuthorityStatus.Available,
            thread,
            latest,
            required);

    private static FollowUpMessageDefinition Preset(string id, string message) => new()
    {
        Id = id,
        Message = message,
        IsEnabled = true,
        UseWorkflowAutomation = true,
        Order = 0
    };

    private static ThreadSummary RootThread(string id, string name = "Workflow conversation") =>
        new(
            id,
            name,
            string.Empty,
            "D:\\workflow",
            "cli",
            Activation.ToUnixTimeSeconds(),
            Activation.AddMinutes(1).ToUnixTimeSeconds(),
            IsSubAgent: false,
            IsEphemeral: false,
            RuntimeStatus: "idle",
            IsArchived: false);

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
            OutputFingerprint: "normal-" + id,
            StartedAt: completedAtUtc.AddMinutes(-1).ToUnixTimeSeconds(),
            CompletedAt: completedAtUtc.ToUnixTimeSeconds(),
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static string Id(int value) =>
        $"00000000-0000-0000-0000-{value:000000000000}";

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "wx-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private sealed record WorkflowFixture(
        WorkflowExecutionResolver Resolver,
        FakeConversationAuthorityReader Conversations,
        FakeRuleRevisionAuthorityReader Rules,
        FakeOperationAuthorityReader Operations);

    private sealed class FakeConversationAuthorityReader(
        IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot> snapshots)
        : IWorkflowConversationAuthorityReader
    {
        internal HashSet<string> RequestedIds { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal Dictionary<string, string?> RequestedTurns { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public Task<IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot>> ReadAsync(
            IReadOnlyList<WorkflowConversationReadRequest> requests,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var request in requests)
            {
                RequestedIds.Add(request.ConversationId);
                RequestedTurns[request.ConversationId] = request.RequiredTurnId;
                result[request.ConversationId] = snapshots.TryGetValue(
                    request.ConversationId,
                    out var snapshot)
                    ? snapshot
                    : WorkflowConversationAuthoritySnapshot.Missing;
            }

            return Task.FromResult<IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot>>(
                result);
        }
    }

    private sealed class FakeSettingsAuthorityReader(WorkflowSettingsAuthoritySnapshot snapshot)
        : IWorkflowSettingsAuthorityReader
    {
        public Task<WorkflowSettingsAuthoritySnapshot> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(snapshot);
        }
    }

    private sealed class FakeOperationAuthorityReader(WorkflowOperationAuthoritySnapshot snapshot)
        : IWorkflowOperationAuthorityReader
    {
        internal WorkflowOperationAuthoritySnapshot Snapshot { get; set; } = snapshot;

        public Task<WorkflowOperationAuthoritySnapshot> ReadAsync(
            WorkflowTriggerEventRecord triggerEvent,
            CancellationToken cancellationToken)
        {
            _ = triggerEvent;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Snapshot);
        }
    }

    private sealed class FakeRuleRevisionAuthorityReader(
        WorkflowRuleRevisionAuthoritySnapshot snapshot)
        : IWorkflowRuleRevisionAuthorityReader
    {
        internal WorkflowRuleRevisionAuthoritySnapshot Snapshot { get; set; } = snapshot;

        public Task<WorkflowRuleRevisionAuthoritySnapshot> ReadAsync(
            WorkflowRuleDefinition rule,
            CancellationToken cancellationToken)
        {
            _ = rule;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Snapshot);
        }
    }

    private sealed class FakeAttachmentAvailabilityReader(bool available)
        : IWorkflowAttachmentAvailabilityReader
    {
        public Task<bool> IsAvailableAsync(
            StructuredPresetPayload payload,
            CancellationToken cancellationToken)
        {
            _ = payload;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(available);
        }
    }

    private sealed class FakeDispatchPolicyAuthority : IWorkflowDispatchPolicyAuthority
    {
        internal bool IsAllowed { get; set; } = true;

        internal List<WorkflowDispatchPolicyToken> Tokens { get; } = [];

        public bool IsCurrent(WorkflowDispatchPolicyToken token)
        {
            Tokens.Add(token);
            return IsAllowed;
        }
    }

    private sealed class FakeWorkflowActionExecutor : IWorkflowActionExecutor
    {
        private readonly Action<string>? _protectionCommitted;

        internal FakeWorkflowActionExecutor(Action<string>? protectionCommitted = null) =>
            _protectionCommitted = protectionCommitted;

        internal List<(ThreadSummary Target, string PresetOwnerId, FollowUpMessageDefinition Preset)>
            SendCalls { get; } = [];

        internal List<string> ProtectionCalls { get; } = [];

        internal int NewConversationUnavailableCalls { get; private set; }

        internal int BlockedCalls { get; private set; }

        internal int ExhaustedCalls { get; private set; }

        public Task<WorkflowActionExecutionResult> ExecuteSendPresetAsync(
            WorkflowRuleDefinition rule,
            string triggerEventId,
            int actionIndex,
            ThreadSummary targetThread,
            TurnSnapshot expectedCompletedTurn,
            string presetOwnerConversationId,
            FollowUpMessageDefinition preset,
            bool includeSubAgents,
            Func<bool> isDispatchAllowed,
            CancellationToken cancellationToken = default)
        {
            _ = rule;
            _ = triggerEventId;
            _ = actionIndex;
            _ = expectedCompletedTurn;
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(!includeSubAgents, "workflow runner broadened root eligibility");
            if (!isDispatchAllowed() || !isDispatchAllowed())
            {
                return Task.FromResult(new WorkflowActionExecutionResult(
                    WorkflowActionExecutionStatus.Waiting,
                    Record: null,
                    "policy changed"));
            }

            SendCalls.Add((targetThread, presetOwnerConversationId, preset));
            return Task.FromResult(new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Confirmed,
                Record: null,
                "confirmed"));
        }

        public Task<WorkflowActionExecutionResult> ExecuteEnableConversationProtectionAsync(
            WorkflowRuleDefinition rule,
            string triggerEventId,
            int actionIndex,
            ThreadSummary targetThread,
            CancellationToken cancellationToken = default)
        {
            _ = rule;
            _ = triggerEventId;
            _ = actionIndex;
            cancellationToken.ThrowIfCancellationRequested();
            ProtectionCalls.Add(targetThread.Id);
            _protectionCommitted?.Invoke(targetThread.Id);
            return Task.FromResult(new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Confirmed,
                Record: null,
                "confirmed"));
        }

        public Task<WorkflowActionExecutionResult> MarkNewConversationUnavailableAsync(
            WorkflowRuleDefinition rule,
            string triggerEventId,
            int actionIndex,
            CancellationToken cancellationToken = default)
        {
            _ = rule;
            _ = triggerEventId;
            _ = actionIndex;
            cancellationToken.ThrowIfCancellationRequested();
            NewConversationUnavailableCalls++;
            return Task.FromResult(new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.CapabilityUnavailable,
                Record: null,
                "unavailable"));
        }

        public Task<WorkflowActionExecutionResult> MarkBlockedAsync(
            WorkflowRuleDefinition rule,
            string triggerEventId,
            int actionIndex,
            string? resolvedTargetConversationId,
            string failureClass,
            CancellationToken cancellationToken = default)
        {
            _ = rule;
            _ = triggerEventId;
            _ = actionIndex;
            _ = resolvedTargetConversationId;
            _ = failureClass;
            cancellationToken.ThrowIfCancellationRequested();
            BlockedCalls++;
            return Task.FromResult(new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Blocked,
                Record: null,
                "blocked"));
        }

        public Task<WorkflowActionExecutionResult> MarkExhaustedAsync(
            WorkflowRuleDefinition rule,
            string triggerEventId,
            int actionIndex,
            string? resolvedTargetConversationId,
            CancellationToken cancellationToken = default)
        {
            _ = rule;
            _ = triggerEventId;
            _ = actionIndex;
            _ = resolvedTargetConversationId;
            cancellationToken.ThrowIfCancellationRequested();
            ExhaustedCalls++;
            return Task.FromResult(new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Exhausted,
                Record: null,
                "exhausted"));
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
