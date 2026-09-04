using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Collections.Concurrent;
using System.IO;

internal static class WorkflowAutomationRuntimeOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow production policy authority revokes settings rule target preset and payload drift",
            TestProductionPolicyAuthorityAsync,
            assert);
        await RunCaseAsync(
            "workflow production policy authority rejects UI-managed settings binding drift",
            TestUiManagedPolicyBindingAsync,
            assert);
        await RunCaseAsync(
            "workflow runtime schedules once and cascades only durable send confirmations",
            TestScheduledCascadeAsync,
            assert);
        await RunCaseAsync(
            "workflow startup reconciles uncertain actions without replaying replaced rules",
            TestRestartAndRuleReplacementAsync,
            assert);
        await RunCaseAsync(
            "workflow conservative startup reconciles only existing uncertainty",
            TestConservativeStartupAsync,
            assert);
        await RunCaseAsync(
            "workflow event adapter serializes completion policy and scheduled wakes",
            TestEventAdapterAsync,
            assert);
        await RunCaseAsync(
            "workflow event adapter overflow forces bounded durable reconciliation",
            TestEventAdapterOverflowAsync,
            assert);
        await RunCaseAsync(
            "workflow production host schedules retries wakes on authority and stops deterministically",
            TestProductionHostAsync,
            assert);
        await RunCaseAsync(
            "workflow production event sources compose only inside the guarded live host",
            TestProductionEventSourceContractsAsync,
            assert);
        await RunCaseAsync(
            "workflow authority source ignores presentation-only duplicate snapshots",
            TestAuthorityFingerprintAsync,
            assert);
        await RunCaseAsync(
            "Guardian snapshot publication de-duplicates identical authoritative state",
            TestGuardianSnapshotFingerprintAsync,
            assert);
    }

    private static Task TestAuthorityFingerprintAsync()
    {
        var thread = new ThreadSummary(
            Id(900),
            "authority fingerprint",
            string.Empty,
            @"D:\Workspace",
            "appServer",
            1,
            2,
            false,
            false,
            RuntimeStatus: "active");
        var state = new GuardianTaskState(
            thread,
            Turn: null,
            RecoveryDecision.None(TaskHealth.Processing, "running"),
            IsEnabled: true,
            TaskHealth.Processing,
            StatusText: "running",
            LastEvent: "running",
            Attempts: 0,
            NextAttemptAt: null);
        var statistics = GuardianSnapshotStatistics.FromLegacy(1);
        var baseline = new GuardianTaskSnapshot([state], statistics);
        var presentationOnly = new GuardianTaskSnapshot(
            [state with
            {
                StatusText = "localized running",
                LastEvent = "localized event",
                Observation = new GuardianTaskObservation(
                    GuardianObservedPhase.Reasoning,
                    "reasoning",
                    null,
                    null,
                    false,
                    null,
                    null,
                    Activation)
            }],
            statistics);
        var protectionChanged = new GuardianTaskSnapshot(
            [state with { IsEnabled = false }],
            statistics);
        var baselineFingerprint =
            GuardianWorkflowAutomationAuthorityChangeSource.CreateAuthorityFingerprint(baseline);
        Ensure(
            string.Equals(
                baselineFingerprint,
                GuardianWorkflowAutomationAuthorityChangeSource.CreateAuthorityFingerprint(
                    presentationOnly),
                StringComparison.Ordinal) &&
            !string.Equals(
                baselineFingerprint,
                GuardianWorkflowAutomationAuthorityChangeSource.CreateAuthorityFingerprint(
                    protectionChanged),
                StringComparison.Ordinal),
            "presentation-only snapshots woke workflow reconciliation or a protection change was lost");
        return Task.CompletedTask;
    }

    private static Task TestGuardianSnapshotFingerprintAsync()
    {
        var thread = new ThreadSummary(
            Id(901),
            "snapshot fingerprint",
            "429",
            @"D:\Workspace",
            "appServer",
            1,
            2,
            false,
            false,
            RuntimeStatus: "idle");
        var turn = new TurnSnapshot(
            Id(902),
            "failed",
            "temporary provider failure",
            "responseTooManyFailedAttempts",
            429,
            "request",
            false,
            false,
            false,
            "failed",
            1,
            2,
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasCompleteItemEvidence: true);
        var state = new GuardianTaskState(
            thread,
            turn,
            new RecoveryDecision(
                RecoveryActionKind.ResendOriginal,
                TaskHealth.NeedsAttention,
                "429",
                true),
            IsEnabled: true,
            TaskHealth.NeedsAttention,
            StatusText: "429 detected",
            LastEvent: "429 detected",
            Attempts: 0,
            NextAttemptAt: null);
        var secondState = state with
        {
            Thread = thread with
            {
                Id = Id(903),
                Name = "snapshot fingerprint second"
            }
        };
        var snapshot = new GuardianTaskSnapshot(
            [state, secondState],
            GuardianSnapshotStatistics.FromLegacy(2));
        var duplicate = new GuardianTaskSnapshot(
            [state, secondState],
            GuardianSnapshotStatistics.FromLegacy(2));
        var reordered = new GuardianTaskSnapshot(
            [secondState, state],
            GuardianSnapshotStatistics.FromLegacy(2));
        var changed = new GuardianTaskSnapshot(
            [state with { Attempts = 1 }, secondState],
            GuardianSnapshotStatistics.FromLegacy(2));

        Ensure(
            string.Equals(
                GuardianEngine.CreateSnapshotFingerprint(snapshot),
                GuardianEngine.CreateSnapshotFingerprint(duplicate),
                StringComparison.Ordinal) &&
            string.Equals(
                GuardianEngine.CreateSnapshotFingerprint(snapshot),
                GuardianEngine.CreateSnapshotFingerprint(reordered),
                StringComparison.Ordinal) &&
            !string.Equals(
                GuardianEngine.CreateSnapshotFingerprint(snapshot),
                GuardianEngine.CreateSnapshotFingerprint(changed),
                StringComparison.Ordinal),
            "identical 429 snapshots are suppressed while a real recovery-state change remains publishable");
        return Task.CompletedTask;
    }

    private static Task TestProductionEventSourceContractsAsync()
    {
        var sourceRoot = Directory.GetCurrentDirectory();
        var engine = File.ReadAllText(Path.Combine(
            sourceRoot,
            "work",
            "CodexGuardian",
            "Services",
            "GuardianEngine.cs")).Replace("\r\n", "\n", StringComparison.Ordinal);
        var executor = File.ReadAllText(Path.Combine(
            sourceRoot,
            "work",
            "CodexGuardian",
            "Services",
            "WorkflowActionExecutor.cs")).Replace("\r\n", "\n", StringComparison.Ordinal);
        var startup = File.ReadAllText(Path.Combine(
            sourceRoot,
            "work",
            "CodexGuardian",
            "App.xaml.cs")).Replace("\r\n", "\n", StringComparison.Ordinal);
        var viewModel = File.ReadAllText(Path.Combine(
            sourceRoot,
            "work",
            "CodexGuardian",
            "ViewModels",
            "MainViewModel.cs")).Replace("\r\n", "\n", StringComparison.Ordinal);
        var host = File.ReadAllText(Path.Combine(
            sourceRoot,
            "work",
            "CodexGuardian",
            "Services",
            "WorkflowAutomationHost.cs")).Replace("\r\n", "\n", StringComparison.Ordinal);
        var followUpIndex = engine.IndexOf("var state = await EvaluateFollowUpAsync(", StringComparison.Ordinal);
        var normalIndex = engine.IndexOf(
            "if (FollowUpQueuePlanner.IsNormalCompletion(turn))",
            StringComparison.Ordinal);
        var publishIndex = engine.IndexOf("WorkflowCompletionObserved", normalIndex, StringComparison.Ordinal);
        var durableConfirmIndex = executor.IndexOf(
            "TryMarkConfirmedAsync(",
            StringComparison.Ordinal);
        var confirmationPublishIndex = executor.IndexOf(
            "PublishPresetDispatchConfirmed(record)",
            durableConfirmIndex,
            StringComparison.Ordinal);
        var liveCompositionStart = startup.IndexOf(
            "WorkflowAutomationHost? workflowAutomationHost = null;",
            StringComparison.Ordinal);
        var liveCompositionEnd = startup.IndexOf(
            "var viewModel = new MainViewModel(",
            liveCompositionStart,
            StringComparison.Ordinal);
        var liveComposition = liveCompositionStart >= 0 && liveCompositionEnd > liveCompositionStart
            ? startup[liveCompositionStart..liveCompositionEnd]
            : string.Empty;
        var startupSave = viewModel.IndexOf(
            "await SaveSettingsForApplicationStartupAsync(",
            StringComparison.Ordinal);
        var hostStart = viewModel.IndexOf(
            "await _workflowAutomationHost.StartAsync(cancellationToken);",
            startupSave,
            StringComparison.Ordinal);
        var engineStart = viewModel.IndexOf("_engine.Start();", hostStart, StringComparison.Ordinal);
        var exitCore = startup.IndexOf(
            "private async Task FinishExitCoreAsync(TaskCompletionSource exitOwner)",
            StringComparison.Ordinal);
        var hostDispose = startup.IndexOf(
            "await workflowAutomationHost.DisposeAsync();",
            exitCore,
            StringComparison.Ordinal);
        var viewModelDispose = startup.IndexOf(
            "await viewModel.DisposeAsync();",
            exitCore,
            StringComparison.Ordinal);
        Ensure(
            followUpIndex >= 0 && normalIndex > followUpIndex && publishIndex > normalIndex &&
            durableConfirmIndex >= 0 && confirmationPublishIndex > durableConfirmIndex &&
            liveComposition.StartsWith(
                "WorkflowAutomationHost? workflowAutomationHost = null;\n        " +
                "if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            liveComposition.Contains("new WorkflowAutomationRuntime(", StringComparison.Ordinal) &&
            liveComposition.Contains("new WorkflowRuleActionRunner(", StringComparison.Ordinal) &&
            liveComposition.Contains("new WorkflowDispatchPolicyAuthority(", StringComparison.Ordinal) &&
            liveComposition.Contains("new WorkflowAutomationHost(", StringComparison.Ordinal) &&
            liveComposition.Contains(
                "new GuardianWorkflowAutomationAuthorityChangeSource(engine, desktopIpc)",
                StringComparison.Ordinal) &&
            startupSave >= 0 && hostStart > startupSave && engineStart > hostStart &&
            hostDispose > exitCore && viewModelDispose > hostDispose &&
            host.Contains("Channel.CreateBounded<byte>", StringComparison.Ordinal) &&
            host.Contains("NotifyScheduledWakeAsync", StringComparison.Ordinal) &&
            host.Contains("NotifyPolicyOrCapabilityChangedAsync", StringComparison.Ordinal) &&
            host.Contains("DefaultMaximumReconciliationDelay", StringComparison.Ordinal) &&
            host.Contains("await _adapter.DisposeAsync()", StringComparison.Ordinal),
            "workflow events moved ahead of authority, escaped the live gate, or lost bounded lifecycle ownership");
        return Task.CompletedTask;
    }

    private static async Task TestProductionPolicyAuthorityAsync()
    {
        var root = CreateRoot("policy");
        var ownerId = Id(100);
        var targetId = Id(101);
        var changedTargetId = Id(102);
        var presetId = Id(103);
        var ruleId = Id(104);
        var settingsService = new SettingsService(root);
        var preset = Preset(presetId, "first payload");
        var settings = Settings(ownerId, preset);
        settings.ThreadProtectionEnabled[targetId] = true;
        await settingsService.SaveAsync(settings);
        var loaded = await settingsService.LoadAsync();
        var ruleStore = new WorkflowRuleStore(root);
        var rule = ScheduledSendRule(
            ruleId,
            revision: 1,
            ownerId,
            targetId,
            presetId,
            Activation.AddMinutes(10),
            Activation);
        var savedRules = await ruleStore.SaveAsync([rule]);
        var payload = StructuredPresetPayload.Create(preset.Message, preset.Attachments);
        var token = Token(
            rule,
            loaded.SettingsGeneration,
            savedRules.Generation,
            targetId,
            ownerId,
            presetId,
            payload.PayloadDigest);
        var authority = new WorkflowDispatchPolicyAuthority(settingsService);
        Ensure(
            await authority.IsCurrentAsync(token, CancellationToken.None) && authority.IsCurrent(token),
            "the exact persisted policy token was not accepted synchronously");

        var changedPreset = preset with { Message = "changed payload" };
        var payloadChangedSettings = Settings(ownerId, changedPreset);
        payloadChangedSettings.ThreadProtectionEnabled[targetId] = true;
        payloadChangedSettings.ThreadProtectionEnabled[changedTargetId] = true;
        await settingsService.SaveAsync(payloadChangedSettings);
        Ensure(!authority.IsCurrent(token), "settings or payload drift did not revoke the old token");

        var changedSettings = await settingsService.LoadAsync();
        var changedPayload = StructuredPresetPayload.Create(
            changedPreset.Message,
            changedPreset.Attachments);
        var changedToken = token with
        {
            SettingsGeneration = changedSettings.SettingsGeneration,
            PayloadDigest = changedPayload.PayloadDigest
        };
        Ensure(authority.IsCurrent(changedToken), "the current settings generation was not accepted");

        var replacement = ScheduledSendRule(
            ruleId,
            revision: 2,
            ownerId,
            changedTargetId,
            presetId,
            Activation.AddMinutes(10),
            Activation.AddMinutes(1));
        var replacedRules = await ruleStore.SaveAsync([replacement]);
        Ensure(!authority.IsCurrent(changedToken), "a replaced rule generation left the old token current");

        var mismatchedTarget = changedToken with
        {
            RuleRevision = replacement.Revision,
            DefinitionDigest = replacement.DefinitionDigest,
            RuleStoreGeneration = replacedRules.Generation
        };
        Ensure(!authority.IsCurrent(mismatchedTarget), "the final predicate ignored target drift");
        var currentToken = mismatchedTarget with { TargetConversationId = changedTargetId };
        Ensure(authority.IsCurrent(currentToken), "the exact replacement rule token was rejected");

        var protectionChanged = await settingsService.LoadAsync();
        protectionChanged.ThreadProtectionEnabled[changedTargetId] = false;
        await settingsService.SaveAsync(protectionChanged);
        var protectionDrift = await settingsService.LoadAsync();
        Ensure(
            !authority.IsCurrent(currentToken with
            {
                SettingsGeneration = protectionDrift.SettingsGeneration
            }),
            "disabling the exact target protection remained authorized at the current settings generation");

        var globalChanged = await settingsService.LoadAsync();
        globalChanged.GlobalProtectionEnabled = false;
        globalChanged.ThreadProtectionEnabled[changedTargetId] = true;
        await settingsService.SaveAsync(globalChanged);
        var globalDrift = await settingsService.LoadAsync();
        Ensure(
            !authority.IsCurrent(currentToken with
            {
                SettingsGeneration = globalDrift.SettingsGeneration
            }),
            "disabling global protection remained authorized at the current settings generation");

        var presetChanged = await settingsService.LoadAsync();
        var currentQueue = presetChanged.ThreadFollowUps[ownerId];
        presetChanged.ThreadFollowUps[ownerId] = currentQueue with
        {
            Messages = [changedPreset with { IsEnabled = false }]
        };
        presetChanged.ThreadProtectionEnabled[changedTargetId] = true;
        await settingsService.SaveAsync(presetChanged);
        var presetDrift = await settingsService.LoadAsync();
        Ensure(
            !authority.IsCurrent(currentToken with
            {
                SettingsGeneration = presetDrift.SettingsGeneration
            }),
            "a disabled exact preset remained dispatchable at the current settings generation");
    }

    private static async Task TestUiManagedPolicyBindingAsync()
    {
        var root = CreateRoot("managed-policy");
        var ownerId = Id(150);
        var targetId = Id(151);
        var presetId = Id(152);
        var ruleId = WorkflowRuleEditor.CreateManagedRuleId(ownerId, presetId);
        var rule = ScheduledSendRule(
            ruleId,
            revision: 4,
            ownerId,
            targetId,
            presetId,
            Activation.AddMinutes(15),
            Activation);
        var preset = Preset(presetId, "managed binding") with
        {
            WorkflowRuleRevision = rule.Revision,
            WorkflowRuleDigest = rule.DefinitionDigest
        };
        var ruleStore = new WorkflowRuleStore(root);
        var savedRules = await ruleStore.SaveAsync([rule]);
        var settingsService = new SettingsService(root);
        var settings = Settings(ownerId, preset);
        settings.ThreadProtectionEnabled[targetId] = true;
        await settingsService.SaveAsync(settings);
        var loaded = await settingsService.LoadAsync();
        var payload = StructuredPresetPayload.Create(preset.Message, preset.Attachments);
        var token = Token(
            rule,
            loaded.SettingsGeneration,
            savedRules.Generation,
            targetId,
            ownerId,
            presetId,
            payload.PayloadDigest);
        var authority = new WorkflowDispatchPolicyAuthority(settingsService);
        Ensure(
            authority.IsCurrent(token),
            "the exact UI-managed settings binding was rejected");

        var revisionChanged = Settings(
            ownerId,
            preset with { WorkflowRuleRevision = rule.Revision + 1 });
        revisionChanged.ThreadProtectionEnabled[targetId] = true;
        await settingsService.SaveAsync(revisionChanged);
        var revisionDrift = await settingsService.LoadAsync();
        Ensure(
            !authority.IsCurrent(token with
            {
                SettingsGeneration = revisionDrift.SettingsGeneration
            }),
            "UI-managed settings revision drift remained dispatchable at the final predicate");

        var mismatchedDigest = string.Equals(
            rule.DefinitionDigest,
            new string('A', 64),
            StringComparison.Ordinal)
            ? new string('B', 64)
            : new string('A', 64);
        var digestChanged = Settings(
            ownerId,
            preset with { WorkflowRuleDigest = mismatchedDigest });
        digestChanged.ThreadProtectionEnabled[targetId] = true;
        await settingsService.SaveAsync(digestChanged);
        var digestDrift = await settingsService.LoadAsync();
        Ensure(
            !authority.IsCurrent(token with
            {
                SettingsGeneration = digestDrift.SettingsGeneration
            }),
            "UI-managed settings digest drift remained dispatchable at the final predicate");

        var restoredSettings = Settings(ownerId, preset);
        restoredSettings.ThreadProtectionEnabled[targetId] = true;
        await settingsService.SaveAsync(restoredSettings);
        var restored = await settingsService.LoadAsync();
        Ensure(
            authority.IsCurrent(token with
            {
                SettingsGeneration = restored.SettingsGeneration
            }),
            "restoring the exact UI-managed settings binding did not restore authority");
    }

    private static async Task TestScheduledCascadeAsync()
    {
        var root = CreateRoot("cascade");
        var ownerId = Id(200);
        var targetId = Id(201);
        var downstreamTargetId = Id(202);
        var presetId = Id(203);
        var activatedAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        var scheduledAt = DateTimeOffset.UtcNow.AddMinutes(1);
        var scheduledRule = ScheduledSendRule(
            Id(204),
            1,
            ownerId,
            targetId,
            presetId,
            scheduledAt,
            activatedAt);
        var downstreamRule = DispatchProtectionRule(
            Id(205),
            ownerId,
            presetId,
            downstreamTargetId,
            activatedAt);
        var ruleStore = new WorkflowRuleStore(root);
        await ruleStore.SaveAsync([scheduledRule, downstreamRule]);
        var journal = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(scheduledAt));
        var runner = new DurableFakeRunner(journal);
        var coordinator = new WorkflowTriggerCoordinator(
            journal,
            new AllowAllConditions(),
            runner);
        var runtime = new WorkflowAutomationRuntime(ruleStore, journal, coordinator, runner);

        var next = await runtime.FindNextScheduledWakeAsync(activatedAt);
        Ensure(next == scheduledAt, "the exact future schedule was not exposed as the next wake");
        var first = await runtime.ProcessScheduledWakeAsync(scheduledAt);
        var snapshot = await journal.ReadAsync();
        Ensure(
            first.Status == WorkflowAutomationRuntimeStatus.Healthy &&
            first.ReplayedConfirmations >= 1 &&
            first.NextScheduledWakeAtUtc is null &&
            snapshot.TriggerEvents.Count == 2 &&
            snapshot.Actions.Count == 2 &&
            snapshot.Actions.All(action => action.State == WorkflowActionOperationState.Confirmed) &&
            snapshot.Actions.Any(action => action.RuleId == scheduledRule.RuleId) &&
            snapshot.Actions.Any(action => action.RuleId == downstreamRule.RuleId),
            $"a scheduled send did not cascade through one durable confirmation receipt " +
            $"(status={first.Status}, replayed={first.ReplayedConfirmations}, " +
            $"next={first.NextScheduledWakeAtUtc:o}, triggers={snapshot.TriggerEvents.Count}, " +
            $"actions={string.Join(',', snapshot.Actions.Select(action =>
                action.RuleId + ':' + action.State))})");

        await runtime.ProcessScheduledWakeAsync(scheduledAt.AddMinutes(1));
        var repeated = await journal.ReadAsync();
        Ensure(
            repeated.TriggerEvents.Count == 2 && repeated.Actions.Count == 2,
            "a duplicate scheduled wake created another occurrence or action");
    }

    private static async Task TestRestartAndRuleReplacementAsync()
    {
        var root = CreateRoot("restart");
        var sourceId = Id(300);
        var targetId = Id(301);
        var presetId = Id(302);
        var rule = CompletionSendRule(
            Id(303),
            1,
            sourceId,
            targetId,
            presetId,
            Activation);
        var ruleStore = new WorkflowRuleStore(root);
        await ruleStore.SaveAsync([rule]);
        var original = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var trigger = await CreateCompletionTriggerAsync(
            original,
            sourceId,
            Activation.AddMinutes(5));
        var prepared = await original.GetOrCreateActionAsync(rule, trigger.TriggerEventId, 0, targetId);
        await original.TryStartDispatchAsync(prepared.Record.ActionOperationId);

        var restarted = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var runner = new DurableFakeRunner(restarted);
        var coordinator = new WorkflowTriggerCoordinator(
            restarted,
            new AllowAllConditions(),
            runner);
        var runtime = new WorkflowAutomationRuntime(ruleStore, restarted, coordinator, runner);
        var reconciled = await runtime.ReconcileStartupAsync(Activation.AddMinutes(6));
        var after = await restarted.ReadAsync();
        Ensure(
            reconciled.Status == WorkflowAutomationRuntimeStatus.Healthy &&
            after.Actions.Single().State == WorkflowActionOperationState.Confirmed &&
            runner.CallsFor(rule.RuleId) >= 1,
            "restart did not reconcile the dispatching action through its durable identity");

        var replacementRoot = CreateRoot("replace");
        var replacementStore = new WorkflowRuleStore(replacementRoot);
        var oldRule = CompletionSendRule(
            Id(304),
            1,
            sourceId,
            targetId,
            presetId,
            Activation);
        await replacementStore.SaveAsync([oldRule]);
        var oldJournal = new WorkflowOperationJournal(
            replacementRoot,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var oldTrigger = await CreateCompletionTriggerAsync(
            oldJournal,
            sourceId,
            Activation.AddMinutes(5));
        var oldPrepared = await oldJournal.GetOrCreateActionAsync(
            oldRule,
            oldTrigger.TriggerEventId,
            0,
            targetId);
        await oldJournal.TryStartDispatchAsync(oldPrepared.Record.ActionOperationId);
        var replacement = CompletionSendRule(
            oldRule.RuleId,
            2,
            sourceId,
            targetId,
            presetId,
            Activation.AddMinutes(10));
        await replacementStore.SaveAsync([replacement]);

        var replacementJournal = new WorkflowOperationJournal(
            replacementRoot,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var replacementRunner = new DurableFakeRunner(replacementJournal);
        var replacementRuntime = new WorkflowAutomationRuntime(
            replacementStore,
            replacementJournal,
            new WorkflowTriggerCoordinator(
                replacementJournal,
                new AllowAllConditions(),
                replacementRunner),
            replacementRunner);
        await replacementRuntime.ReconcileStartupAsync(Activation.AddMinutes(11));
        var replacementSnapshot = await replacementJournal.ReadAsync();
        Ensure(
            replacementRunner.TotalCalls == 0 &&
            replacementSnapshot.Actions.Single().State == WorkflowActionOperationState.Uncertain,
            "a replacement activated after the source event replayed the old durable action");
    }

    private static async Task TestConservativeStartupAsync()
    {
        var root = CreateRoot("conservative");
        var ownerId = Id(400);
        var targetId = Id(401);
        var presetId = Id(402);
        var rule = WorkflowRuleDefinition.Create(
            Id(403),
            1,
            ownerId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = Activation.AddMinutes(1)
            },
            Existing(targetId),
            null,
            [
                Send(ownerId, presetId, 0),
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.EnableConversationProtection,
                    Order = 1
                }
            ]);
        var ruleStore = new WorkflowRuleStore(root);
        await ruleStore.SaveAsync([rule]);
        var journal = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var trigger = await journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ScheduledAt,
            ownerId,
            rule.RuleId,
            rule.RuleId,
            "scheduled:" + rule.Trigger.ScheduledAtUtc!.Value.UtcTicks,
            Activation.AddMinutes(1));
        var action = await journal.GetOrCreateActionAsync(rule, trigger.Record.TriggerEventId, 0, targetId);
        await journal.TryStartDispatchAsync(action.Record.ActionOperationId);
        File.WriteAllText(journal.JournalPath, "{corrupt");

        var recovered = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var runner = new DurableFakeRunner(recovered);
        var runtime = new WorkflowAutomationRuntime(
            ruleStore,
            recovered,
            new WorkflowTriggerCoordinator(recovered, new AllowAllConditions(), runner),
            runner);
        var result = await runtime.ReconcileStartupAsync(Activation.AddMinutes(2));
        var snapshot = await recovered.ReadAsync();
        Ensure(
            result.Status == WorkflowAutomationRuntimeStatus.ConservativeRecovery &&
            result.ReconciledActions.Count == 1 &&
            snapshot.RequiresConservativeRecovery &&
            snapshot.Actions.Count == 1 &&
            snapshot.Actions[0].State == WorkflowActionOperationState.Confirmed,
            "conservative recovery created a new action or failed to reconcile existing uncertainty");
    }

    private static async Task TestEventAdapterAsync()
    {
        var root = CreateRoot("adapter");
        var sourceId = Id(500);
        var targetId = Id(501);
        var scheduledTargetId = Id(502);
        var completionRule = CompletionProtectionRule(
            Id(503),
            sourceId,
            targetId,
            Activation);
        var scheduledAt = Activation.AddHours(1);
        var scheduledRule = ScheduledProtectionRule(
            Id(504),
            sourceId,
            scheduledTargetId,
            scheduledAt,
            Activation);
        var ruleStore = new WorkflowRuleStore(root);
        await ruleStore.SaveAsync([completionRule, scheduledRule]);
        var journal = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var completionAllowed = false;
        var runner = new DurableFakeRunner(
            journal,
            (rule, _) => rule.RuleId != completionRule.RuleId || completionAllowed);
        var runtime = new WorkflowAutomationRuntime(
            ruleStore,
            journal,
            new WorkflowTriggerCoordinator(journal, new AllowAllConditions(), runner),
            runner);
        var completions = new FakeCompletionSource();
        var confirmations = new FakeConfirmationSource();
        await using var adapter = new WorkflowAutomationEventAdapter(
            runtime,
            completions,
            confirmations);
        await adapter.StartAsync(Activation);
        Ensure(
            adapter.NextScheduledWakeAtUtc == scheduledAt,
            "adapter startup did not publish the next scheduled deadline");

        var completedTurn = NormalTurn(Id(505), Activation.AddMinutes(5));
        completions.Publish(new WorkflowAuthoritativeCompletionEventArgs(
            RootThread(sourceId),
            completedTurn,
            Activation.AddMinutes(6)));
        await WaitUntilAsync(
            async () => (await journal.ReadAsync()).TriggerEvents.Any(trigger =>
                trigger.TriggerKind == WorkflowTriggerKind.ConversationCompletedNormally),
            TimeSpan.FromSeconds(5));
        Ensure(
            (await journal.ReadAsync()).Actions.Count == 0,
            "a waiting completion action wrote an owner operation before policy became eligible");

        completionAllowed = true;
        await adapter.NotifyPolicyOrCapabilityChangedAsync(Activation.AddMinutes(7));
        Ensure(
            (await journal.ReadAsync()).Actions.Any(action =>
                action.RuleId == completionRule.RuleId &&
                action.State == WorkflowActionOperationState.Confirmed),
            "a policy or capability wake did not resume the durable completion trigger");

        await adapter.NotifyScheduledWakeAsync(scheduledAt);
        var final = await journal.ReadAsync();
        Ensure(
            final.Actions.Any(action =>
                action.RuleId == scheduledRule.RuleId &&
                action.State == WorkflowActionOperationState.Confirmed) &&
            adapter.NextScheduledWakeAtUtc is null &&
            adapter.LastFailure is null,
            "the scheduled adapter wake was not serialized with prior workflow events");
    }

    private static async Task TestEventAdapterOverflowAsync()
    {
        var root = CreateRoot("adapter-overflow");
        var sourceId = Id(520);
        var targetId = Id(521);
        var rule = CompletionProtectionRule(Id(522), sourceId, targetId, Activation);
        var ruleStore = new WorkflowRuleStore(root);
        await ruleStore.SaveAsync([rule]);
        var journal = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var runner = new BlockingWaitingRunner();
        var runtime = new WorkflowAutomationRuntime(
            ruleStore,
            journal,
            new WorkflowTriggerCoordinator(journal, new AllowAllConditions(), runner),
            runner);
        var completions = new FakeCompletionSource();
        var confirmations = new FakeConfirmationSource();
        await using var adapter = new WorkflowAutomationEventAdapter(
            runtime,
            completions,
            confirmations,
            queueCapacity: 2);
        var overflowObserved = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        adapter.StateChanged += (_, eventArgs) =>
        {
            if (eventArgs.Origin == WorkflowAutomationResultOrigin.OverflowReconciliation &&
                eventArgs.Failure is null)
            {
                overflowObserved.TrySetResult();
            }
        };
        await adapter.StartAsync(Activation);

        completions.Publish(new WorkflowAuthoritativeCompletionEventArgs(
            RootThread(sourceId),
            NormalTurn(Id(523), Activation.AddMinutes(1)),
            Activation.AddMinutes(2)));
        await runner.Entered.WaitAsync(TimeSpan.FromSeconds(5));
        for (var index = 0; index < 8; index++)
        {
            completions.Publish(new WorkflowAuthoritativeCompletionEventArgs(
                RootThread(sourceId),
                NormalTurn(Id(530 + index), Activation.AddMinutes(3 + index)),
                Activation.AddMinutes(4 + index)));
        }

        runner.Release();
        await overflowObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Ensure(
            runner.Calls >= 2 && adapter.LastFailure is null,
            "adapter overflow did not reconcile the durable trigger through one bounded worker");
    }

    private static async Task TestProductionHostAsync()
    {
        var root = CreateRoot("production-host");
        var scheduledOwnerId = Id(540);
        var scheduledTargetId = Id(541);
        var retrySourceId = Id(542);
        var retryTargetId = Id(543);
        var changeSourceId = Id(544);
        var changeTargetId = Id(545);
        var scheduledRule = ScheduledProtectionRule(
            Id(546),
            scheduledOwnerId,
            scheduledTargetId,
            Activation.AddHours(1),
            Activation);
        var retryRule = CompletionProtectionRule(
            Id(547),
            retrySourceId,
            retryTargetId,
            Activation);
        var changeRule = CompletionProtectionRule(
            Id(548),
            changeSourceId,
            changeTargetId,
            Activation);
        var ruleStore = new WorkflowRuleStore(root);
        await ruleStore.SaveAsync([scheduledRule, retryRule, changeRule]);
        var journal = new WorkflowOperationJournal(
            root,
            timeProvider: new WorkflowTestTimeProvider(Activation.AddHours(3)));
        var allowed = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var runner = new DurableFakeRunner(
            journal,
            (rule, _) => rule.RuleId == scheduledRule.RuleId ||
                         allowed.ContainsKey(rule.RuleId));
        var runtime = new WorkflowAutomationRuntime(
            ruleStore,
            journal,
            new WorkflowTriggerCoordinator(journal, new AllowAllConditions(), runner),
            runner);
        var completions = new FakeCompletionSource();
        var confirmations = new FakeConfirmationSource();
        var adapter = new WorkflowAutomationEventAdapter(runtime, completions, confirmations);
        var changes = new FakeAuthorityChangeSource();
        var clock = new FakeWorkflowAutomationClock(Activation);
        using var log = new GuardianLog(root);
        await using var host = new WorkflowAutomationHost(
            adapter,
            changes,
            log,
            clock,
            minimumReconciliationDelay: TimeSpan.FromMinutes(1),
            maximumReconciliationDelay: TimeSpan.FromMinutes(4),
            maximumTimerSlice: TimeSpan.FromHours(6));
        var lineageInvalidations = 0;
        host.LineageInvalidated += (_, _) => Interlocked.Increment(ref lineageInvalidations);
        host.LineageInvalidated += (_, _) => throw new InvalidOperationException(
            "lineage subscriber isolation fixture");
        await host.StartAsync();
        Ensure(
            host.IsStarted && host.NextScheduledWakeAtUtc == Activation.AddHours(1) &&
            lineageInvalidations > 0,
            "production host startup did not publish the exact future schedule or lineage invalidation");

        clock.Advance(TimeSpan.FromHours(1));
        await WaitUntilAsync(
            async () => (await journal.ReadAsync()).Actions.Any(action =>
                action.RuleId == scheduledRule.RuleId &&
                action.State == WorkflowActionOperationState.Confirmed),
            TimeSpan.FromSeconds(5));

        completions.Publish(new WorkflowAuthoritativeCompletionEventArgs(
            RootThread(retrySourceId),
            NormalTurn(Id(549), clock.GetUtcNow()),
            clock.GetUtcNow()));
        await WaitUntilAsync(
            async () => (await journal.ReadAsync()).TriggerEvents.Any(trigger =>
                string.Equals(
                    trigger.SourceConversationId,
                    retrySourceId,
                    StringComparison.OrdinalIgnoreCase)),
            TimeSpan.FromSeconds(5));
        await WaitUntilAsync(
            () => Task.FromResult(host.NextReconciliationWakeAtUtc is not null),
            TimeSpan.FromSeconds(5));
        Ensure(
            !(await journal.ReadAsync()).Actions.Any(action => action.RuleId == retryRule.RuleId),
            "a waiting workflow wrote an action before its authority became eligible");

        allowed[retryRule.RuleId] = true;
        clock.Advance(TimeSpan.FromMinutes(1));
        await WaitUntilAsync(
            async () => (await journal.ReadAsync()).Actions.Any(action =>
                action.RuleId == retryRule.RuleId &&
                action.State == WorkflowActionOperationState.Confirmed),
            TimeSpan.FromSeconds(5));

        completions.Publish(new WorkflowAuthoritativeCompletionEventArgs(
            RootThread(changeSourceId),
            NormalTurn(Id(550), clock.GetUtcNow()),
            clock.GetUtcNow()));
        await WaitUntilAsync(
            async () => (await journal.ReadAsync()).TriggerEvents.Any(trigger =>
                string.Equals(
                    trigger.SourceConversationId,
                    changeSourceId,
                    StringComparison.OrdinalIgnoreCase)),
            TimeSpan.FromSeconds(5));
        allowed[changeRule.RuleId] = true;
        changes.Publish();
        await WaitUntilAsync(
            async () => (await journal.ReadAsync()).Actions.Any(action =>
                action.RuleId == changeRule.RuleId &&
                action.State == WorkflowActionOperationState.Confirmed),
            TimeSpan.FromSeconds(5));

        await host.DisposeAsync();
        var callsAfterDispose = runner.TotalCalls;
        var invalidationsAfterDispose = lineageInvalidations;
        changes.Publish();
        completions.Publish(new WorkflowAuthoritativeCompletionEventArgs(
            RootThread(changeSourceId),
            NormalTurn(Id(551), clock.GetUtcNow()),
            clock.GetUtcNow()));
        clock.Advance(TimeSpan.FromHours(1));
        await Task.Delay(50);
        Ensure(
            runner.TotalCalls == callsAfterDispose &&
            lineageInvalidations == invalidationsAfterDispose,
            "disposed workflow host continued consuming completion, authority, or lineage events");
    }

    private static WorkflowDispatchPolicyToken Token(
        WorkflowRuleDefinition rule,
        long settingsGeneration,
        long ruleStoreGeneration,
        string targetId,
        string ownerId,
        string presetId,
        string payloadDigest) =>
        new(
            rule.RuleId,
            rule.Revision,
            rule.DefinitionDigest,
            Id(900),
            ActionIndex: 0,
            settingsGeneration,
            ruleStoreGeneration,
            targetId,
            ownerId,
            presetId,
            payloadDigest);

    private static AppSettings Settings(string ownerId, FollowUpMessageDefinition preset)
    {
        var settings = new AppSettings
        {
            MonitorOnly = true,
            GlobalProtectionEnabled = true,
            ThreadFollowUps = new ConcurrentDictionary<string, ThreadFollowUpSettings>(
                StringComparer.OrdinalIgnoreCase)
        };
        settings.ThreadFollowUps[ownerId] = new ThreadFollowUpSettings
        {
            IsEnabled = true,
            Messages = [preset]
        };
        return settings;
    }

    private static WorkflowRuleDefinition ScheduledSendRule(
        string ruleId,
        int revision,
        string ownerId,
        string targetId,
        string presetId,
        DateTimeOffset scheduledAtUtc,
        DateTimeOffset activatedAtUtc) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            revision,
            ownerId,
            true,
            activatedAtUtc,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = scheduledAtUtc
            },
            Existing(targetId),
            null,
            [Send(ownerId, presetId, 0)]);

    private static WorkflowRuleDefinition CompletionSendRule(
        string ruleId,
        int revision,
        string sourceId,
        string targetId,
        string presetId,
        DateTimeOffset activatedAtUtc) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            revision,
            sourceId,
            true,
            activatedAtUtc,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                SourceConversationId = sourceId
            },
            Existing(targetId),
            null,
            [Send(sourceId, presetId, 0)]);

    private static WorkflowRuleDefinition CompletionProtectionRule(
        string ruleId,
        string sourceId,
        string targetId,
        DateTimeOffset activatedAtUtc) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            1,
            sourceId,
            true,
            activatedAtUtc,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                SourceConversationId = sourceId
            },
            Existing(targetId),
            null,
            [new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = 0
            }]);

    private static WorkflowRuleDefinition ScheduledProtectionRule(
        string ruleId,
        string ownerId,
        string targetId,
        DateTimeOffset scheduledAtUtc,
        DateTimeOffset activatedAtUtc) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            1,
            ownerId,
            true,
            activatedAtUtc,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = scheduledAtUtc
            },
            Existing(targetId),
            null,
            [new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = 0
            }]);

    private static WorkflowRuleDefinition DispatchProtectionRule(
        string ruleId,
        string sourceOwnerId,
        string sourcePresetId,
        string targetId,
        DateTimeOffset activatedAtUtc) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            1,
            sourceOwnerId,
            true,
            activatedAtUtc,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.PresetDispatchConfirmed,
                SourceConversationId = sourceOwnerId,
                SourcePresetMessageId = sourcePresetId
            },
            Existing(targetId),
            null,
            [new WorkflowActionDefinition
            {
                Kind = WorkflowActionKind.EnableConversationProtection,
                Order = 0
            }]);

    private static WorkflowActionDefinition Send(string ownerId, string presetId, int order) => new()
    {
        Kind = WorkflowActionKind.SendPresetMessage,
        PresetOwnerConversationId = ownerId,
        PresetMessageId = presetId,
        Order = order
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

    private static async Task<WorkflowTriggerEventRecord> CreateCompletionTriggerAsync(
        WorkflowOperationJournal journal,
        string sourceId,
        DateTimeOffset completedAtUtc)
    {
        var turnId = Guid.NewGuid().ToString("D");
        return (await journal.GetOrCreateTriggerEventAsync(
            WorkflowTriggerKind.ConversationCompletedNormally,
            sourceId,
            sourceId,
            turnId,
            "normal-completion:" + completedAtUtc.ToUnixTimeSeconds(),
            completedAtUtc.AddMinutes(1))).Record;
    }

    private static ThreadSummary RootThread(string id) => new(
        id,
        "Workflow runtime",
        string.Empty,
        "D:\\workflow-runtime",
        "cli",
        Activation.ToUnixTimeSeconds(),
        Activation.AddMinutes(1).ToUnixTimeSeconds(),
        IsSubAgent: false,
        IsEphemeral: false,
        RuntimeStatus: "idle",
        IsArchived: false);

    private static TurnSnapshot NormalTurn(string id, DateTimeOffset completedAtUtc) => new(
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

    private static string CreateRoot(string suffix)
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "wr-" + suffix + "-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private static string Id(int value) =>
        $"00000000-0000-0000-0000-{value:000000000000}";

    private static async Task WaitUntilAsync(
        Func<Task<bool>> condition,
        TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(20);
        }

        throw new TimeoutException("The workflow event adapter did not reach the expected state.");
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

    private sealed class AllowAllConditions : IWorkflowConditionEvaluator
    {
        public Task<WorkflowConditionEvaluationResult> EvaluateAsync(
            WorkflowRuleDefinition rule,
            WorkflowTriggerEventRecord triggerEvent,
            CancellationToken cancellationToken)
        {
            _ = rule;
            _ = triggerEvent;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new WorkflowConditionEvaluationResult(
                IsAllowed: true,
                FailedConditions: Array.Empty<WorkflowConditionKind>()));
        }
    }

    private sealed class DurableFakeRunner : IWorkflowRuleActionRunner
    {
        private readonly WorkflowOperationJournal _journal;
        private readonly Func<WorkflowRuleDefinition, int, bool> _isAllowed;
        private readonly ConcurrentDictionary<string, int> _calls =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string> _generatedTurns =
            new(StringComparer.OrdinalIgnoreCase);

        internal DurableFakeRunner(
            WorkflowOperationJournal journal,
            Func<WorkflowRuleDefinition, int, bool>? isAllowed = null)
        {
            _journal = journal;
            _isAllowed = isAllowed ?? (static (_, _) => true);
        }

        internal int TotalCalls => _calls.Values.Sum();

        internal int CallsFor(string ruleId) =>
            _calls.TryGetValue(ruleId, out var value) ? value : 0;

        public async Task<WorkflowActionExecutionResult> RunAsync(
            WorkflowRuleDefinition rule,
            WorkflowTriggerEventRecord triggerEvent,
            int actionIndex,
            CancellationToken cancellationToken)
        {
            _calls.AddOrUpdate(rule.RuleId, 1, static (_, current) => current + 1);
            if (!_isAllowed(rule, actionIndex))
            {
                return new WorkflowActionExecutionResult(
                    WorkflowActionExecutionStatus.Waiting,
                    Record: null,
                    "waiting");
            }

            var targetId = rule.ResolveKnownDestinationConversationId() ??
                throw new InvalidOperationException("The fake runner requires an existing target.");
            var prepared = await _journal.GetOrCreateActionAsync(
                rule,
                triggerEvent.TriggerEventId,
                actionIndex,
                targetId,
                cancellationToken);
            var current = prepared.Record;
            if (current.State == WorkflowActionOperationState.Confirmed)
            {
                return new WorkflowActionExecutionResult(
                    WorkflowActionExecutionStatus.Confirmed,
                    current,
                    "already confirmed");
            }

            if (current.State is WorkflowActionOperationState.Prepared or
                WorkflowActionOperationState.Retryable)
            {
                current = (await _journal.TryStartDispatchAsync(
                    current.ActionOperationId,
                    cancellationToken)).Record ?? current;
            }

            if (current.State is not WorkflowActionOperationState.Dispatching and not
                WorkflowActionOperationState.Uncertain)
            {
                return new WorkflowActionExecutionResult(
                    WorkflowActionExecutionStatus.Waiting,
                    current,
                    "not dispatchable");
            }

            var action = rule.Actions[actionIndex];
            var receipt = action.Kind == WorkflowActionKind.SendPresetMessage
                ? new WorkflowActionReceipt(
                    targetId,
                    _generatedTurns.GetOrAdd(
                        current.ActionOperationId,
                        static _ => Guid.NewGuid().ToString("D")),
                    ProtectionSettingsGeneration: null)
                : new WorkflowActionReceipt(
                    targetId,
                    GeneratedTurnId: null,
                    ProtectionSettingsGeneration: 1);
            var confirmed = await _journal.TryMarkConfirmedAsync(
                current.ActionOperationId,
                receipt,
                cancellationToken);
            return new WorkflowActionExecutionResult(
                confirmed.Record?.State == WorkflowActionOperationState.Confirmed
                    ? WorkflowActionExecutionStatus.Confirmed
                    : WorkflowActionExecutionStatus.Uncertain,
                confirmed.Record,
                "confirmed");
        }
    }

    private sealed class BlockingWaitingRunner : IWorkflowRuleActionRunner
    {
        private readonly TaskCompletionSource _entered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _calls;

        internal Task Entered => _entered.Task;

        internal int Calls => Volatile.Read(ref _calls);

        internal void Release() => _release.TrySetResult();

        public async Task<WorkflowActionExecutionResult> RunAsync(
            WorkflowRuleDefinition rule,
            WorkflowTriggerEventRecord triggerEvent,
            int actionIndex,
            CancellationToken cancellationToken)
        {
            _ = rule;
            _ = triggerEvent;
            _ = actionIndex;
            Interlocked.Increment(ref _calls);
            _entered.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
            return new WorkflowActionExecutionResult(
                WorkflowActionExecutionStatus.Waiting,
                Record: null,
                "waiting");
        }
    }

    private sealed class FakeAuthorityChangeSource : IWorkflowAutomationAuthorityChangeSource
    {
        private int _disposed;

        public event EventHandler<EventArgs>? AuthorityChanged;

        internal void Publish()
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                AuthorityChanged?.Invoke(this, EventArgs.Empty);
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _disposed, 1);
            AuthorityChanged = null;
        }
    }

    private sealed class FakeWorkflowAutomationClock(DateTimeOffset initialUtc)
        : IWorkflowAutomationClock
    {
        private readonly object _gate = new();
        private readonly List<PendingDelay> _pending = [];
        private DateTimeOffset _utcNow = initialUtc.ToUniversalTime();

        public DateTimeOffset GetUtcNow()
        {
            lock (_gate)
            {
                return _utcNow;
            }
        }

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (delay <= TimeSpan.Zero)
            {
                return Task.CompletedTask;
            }

            var completion = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_gate)
            {
                _pending.Add(new PendingDelay(_utcNow + delay, completion));
            }

            _ = cancellationToken.Register(
                static state => ((TaskCompletionSource)state!).TrySetCanceled(),
                completion);
            return completion.Task;
        }

        internal void Advance(TimeSpan elapsed)
        {
            if (elapsed < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(elapsed));
            }

            PendingDelay[] ready;
            lock (_gate)
            {
                _utcNow += elapsed;
                ready = _pending.Where(delay =>
                        delay.TargetUtc <= _utcNow && !delay.Completion.Task.IsCompleted)
                    .ToArray();
                _pending.RemoveAll(delay =>
                    delay.TargetUtc <= _utcNow || delay.Completion.Task.IsCompleted);
            }

            foreach (var pending in ready)
            {
                pending.Completion.TrySetResult();
            }
        }

        private sealed record PendingDelay(
            DateTimeOffset TargetUtc,
            TaskCompletionSource Completion);
    }

    private sealed class FakeCompletionSource : IWorkflowAuthoritativeCompletionSource
    {
        public event EventHandler<WorkflowAuthoritativeCompletionEventArgs>? CompletionObserved;

        internal void Publish(WorkflowAuthoritativeCompletionEventArgs eventArgs) =>
            CompletionObserved?.Invoke(this, eventArgs);
    }

    private sealed class FakeConfirmationSource : IWorkflowPresetDispatchConfirmationSource
    {
        public event EventHandler<WorkflowPresetDispatchConfirmedEventArgs>? PresetDispatchConfirmed;

        internal void Publish(WorkflowActionOperationRecord action) =>
            PresetDispatchConfirmed?.Invoke(
                this,
                new WorkflowPresetDispatchConfirmedEventArgs(action));
    }
}
