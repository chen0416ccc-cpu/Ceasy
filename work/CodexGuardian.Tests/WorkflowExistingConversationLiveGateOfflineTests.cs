using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Globalization;
using System.IO;

internal static class WorkflowExistingConversationLiveGateOfflineTests
{
    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "workflow live gate requires one explicit prepare or confirmed-send mode",
            TestArgumentMatrix,
            assert);
        RunCase(
            "workflow live gate freezes one bounded existing-target configuration",
            TestConfiguration,
            assert);
        RunCase(
            "workflow live gate exposes a distinct future scheduled-host mode",
            TestScheduledHostMode,
            assert);
        RunCase(
            "workflow authority merges matching bounded local terminal evidence",
            TestLocalTerminalReconciliation,
            assert);
        RunCase(
            "final follow-up state authority merges matching bounded local terminal evidence",
            TestFinalFollowUpLocalTerminalReconciliation,
            assert);
        RunCase(
            "workflow live gate projects idle state only from an exact stock owner snapshot",
            TestStockOwnerRuntimeProjection,
            assert);
        RunCase(
            "Windows composer observation treats only a verified default desktop with no foreground as clear",
            TestNoForegroundComposerClassification,
            assert);
        RunCase(
            "workflow live gate stays tests-only without recovery CDP or package mutation",
            TestSourceBoundary,
            assert);
        return Task.CompletedTask;
    }

    private static void TestArgumentMatrix()
    {
        var prepare = WorkflowExistingConversationLiveGate.Parse(Arguments(prepareOnly: true));
        var confirmed = WorkflowExistingConversationLiveGate.Parse(Arguments(prepareOnly: false));
        Ensure(prepare.PrepareOnly && !confirmed.PrepareOnly, "live gate modes were not distinct");
        Ensure(
            Throws(() => WorkflowExistingConversationLiveGate.Parse(
                Arguments(prepareOnly: true).Concat(
                    [WorkflowExistingConversationLiveGate.ConfirmArgument]).ToArray())) &&
            Throws(() => WorkflowExistingConversationLiveGate.Parse(
                Arguments(prepareOnly: true)
                    .Where(argument => !string.Equals(
                        argument,
                        WorkflowExistingConversationLiveGate.PrepareArgument,
                        StringComparison.OrdinalIgnoreCase))
                    .ToArray())) &&
            Throws(() => WorkflowExistingConversationLiveGate.Parse(
                ReplaceValue(
                    Arguments(prepareOnly: true),
                    WorkflowExistingConversationLiveGate.DataDirectoryArgument,
                    @"C:\Temp\live-gate"))) &&
            Throws(() => WorkflowExistingConversationLiveGate.Parse(
                Arguments(prepareOnly: true).Concat(["--unknown-live-gate-argument"]).ToArray())),
            "live gate accepted ambiguous consent or unsafe argument values");
    }

    private static void TestConfiguration()
    {
        var options = WorkflowExistingConversationLiveGate.Parse(Arguments(prepareOnly: true));
        var configuration = WorkflowExistingConversationLiveGate.BuildConfiguration(options);
        Ensure(
            configuration.Rule.IsEnabled &&
            configuration.Rule.Trigger.Kind == WorkflowTriggerKind.ScheduledAt &&
            configuration.Rule.Destination.Kind == WorkflowDestinationKind.ExistingConversation &&
            string.Equals(
                configuration.Rule.Destination.ConversationId,
                options.TargetThreadId,
                StringComparison.OrdinalIgnoreCase) &&
            configuration.Rule.Actions.Count == 1 &&
            configuration.Rule.Actions[0].Kind == WorkflowActionKind.SendPresetMessage &&
            configuration.Preset.UseWorkflowAutomation &&
            configuration.Preset.MaximumErrorRetries == 0 &&
            !configuration.Preset.RetryIndefinitely &&
            configuration.Preset.Attachments.Count == 0 &&
            !configuration.Settings.MonitoringEnabled &&
            configuration.Settings.MonitorOnly &&
            !configuration.Settings.AutomaticRecoveryEnabled &&
            configuration.Settings.GlobalProtectionEnabled &&
            configuration.Settings.ThreadProtectionEnabled.Count == 1 &&
            configuration.Settings.ThreadProtectionEnabled[options.TargetThreadId] &&
            !configuration.Settings.KeepAliveEnabled &&
            !configuration.Settings.KeepAliveSentinelEnabled &&
            !configuration.Settings.MinimizeToTray &&
            !configuration.Settings.StartWithWindows &&
            !configuration.Settings.ProtectNewThreadsByDefault &&
            configuration.Settings.ThreadEnabled.Count == 1 &&
            configuration.Settings.ThreadEnabled[options.TargetThreadId] &&
            configuration.Settings.ThreadFollowUps.Count == 1 &&
            Guid.TryParse(configuration.TriggerEventId, out _) &&
            Guid.TryParse(configuration.ActionOperationId, out _) &&
            Guid.TryParse(configuration.ClientMessageId, out _) &&
            configuration.Payload.Attachments.Count == 0,
            "live gate configuration broadened recovery policy or lost stable identity");
    }

    private static void TestScheduledHostMode()
    {
        var prepare = WorkflowExistingConversationLiveGate.Parse(
            Arguments(prepareOnly: true, scheduledHost: true));
        var confirmed = WorkflowExistingConversationLiveGate.Parse(
            Arguments(prepareOnly: false, scheduledHost: true));
        Ensure(
            prepare.PrepareOnly && prepare.ExerciseScheduledHost &&
            !confirmed.PrepareOnly && confirmed.ExerciseScheduledHost &&
            Throws(() => WorkflowExistingConversationLiveGate.Parse(
                Arguments(prepareOnly: true, scheduledHost: true)
                    .Concat([WorkflowExistingConversationLiveGate.ScheduledHostArgument])
                    .ToArray())),
            "scheduled-host mode was ambiguous with the direct live-send gate");
    }

    private static void TestSourceBoundary()
    {
        var root = Directory.GetCurrentDirectory();
        var gatePath = Path.Combine(
            root,
            "work",
            "CodexGuardian.Tests",
            "WorkflowExistingConversationLiveGate.cs");
        var programPath = Path.Combine(root, "work", "CodexGuardian.Tests", "Program.cs");
        var followUpPath = Path.Combine(
            root,
            "work",
            "CodexGuardian",
            "Services",
            "FollowUpDispatchService.cs");
        var gate = File.ReadAllText(gatePath);
        var program = File.ReadAllText(programPath);
        var followUp = File.ReadAllText(followUpPath);
        var dispatchIndex = program.IndexOf(
            "WorkflowExistingConversationLiveGate.IsRequested(args)",
            StringComparison.Ordinal);
        var failuresIndex = program.IndexOf("var failures = new List<string>();", StringComparison.Ordinal);
        Ensure(
            dispatchIndex >= 0 && failuresIndex > dispatchIndex &&
            gate.Contains("--confirm-real-workflow-send", StringComparison.Ordinal) &&
            gate.Contains("WindowsCodexInteractionHook", StringComparison.Ordinal) &&
            gate.Contains("StrictComposerInterferenceGuard", StringComparison.Ordinal) &&
            gate.Contains("WorkflowAutomationRuntime", StringComparison.Ordinal) &&
            gate.Contains("new WorkflowAutomationHost(", StringComparison.Ordinal) &&
            gate.Contains("SystemWorkflowAutomationClock.Instance", StringComparison.Ordinal) &&
            gate.Contains("RefreshingStockOwnerWorkflowConversationAuthorityReader", StringComparison.Ordinal) &&
            gate.Contains("scheduled-host-fired-before-due", StringComparison.Ordinal) &&
            gate.Contains("host.NextScheduledWakeAtUtc != options.ScheduledAtUtc", StringComparison.Ordinal) &&
            gate.Contains("WORKFLOW_LIVE_GATE_ARMED", StringComparison.Ordinal) &&
            gate.Contains("StockOwnerWorkflowConversationAuthorityReader", StringComparison.Ordinal) &&
            gate.Contains("AcquireThreadOwnerStateGuardAsync", StringComparison.Ordinal) &&
            gate.Contains("WORKFLOW_LIVE_GATE_COMPOSER", StringComparison.Ordinal) &&
            gate.Contains("FindRecentTurnByClientMessageIdAsync", StringComparison.Ordinal) &&
            gate.Contains("AttemptCount: 1", StringComparison.Ordinal) &&
            followUp.Contains("AcquireThreadOwnerStateGuardAsync", StringComparison.Ordinal) &&
            followUp.Contains(
                "LocalConversationHistoryReader.ReconcileLatestTurn",
                StringComparison.Ordinal) &&
            followUp.Contains(
                "ValidateOwnerNormalCompletion(ownerGuard.Snapshot",
                StringComparison.Ordinal) &&
            !gate.Contains("WaitForExactIdleTargetAsync", StringComparison.Ordinal) &&
            !gate.Contains("target-runtime-did-not-become-idle", StringComparison.Ordinal) &&
            !gate.Contains("new RecoveryService", StringComparison.Ordinal) &&
            !gate.Contains("CodexDeepObservationService", StringComparison.Ordinal) &&
            !gate.Contains("CodexCdp", StringComparison.Ordinal) &&
            !gate.Contains("thread/rollback", StringComparison.Ordinal) &&
            !gate.Contains("WindowsApps", StringComparison.Ordinal) &&
            !gate.Contains("state_5.sqlite", StringComparison.Ordinal),
            "live gate escaped its tests-only owner-channel boundary");
    }

    private static void TestLocalTerminalReconciliation()
    {
        var turnId = "019fb89b-9db1-7d70-9225-091ec086f06e";
        var appServerTurn = new TurnSnapshot(
            turnId,
            "completed",
            ErrorMessage: null,
            ErrorCode: null,
            HttpStatusCode: null,
            UserText: string.Empty,
            HasAttachments: false,
            HasAssistantOutput: true,
            HasWorkOutput: false,
            OutputFingerprint: "offline",
            StartedAt: 100,
            CompletedAt: 200,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true);
        var localTurn = appServerTurn with
        {
            HasConfirmedLocalTerminal = true
        };
        var local = new LocalConversationTerminalEvent(
            "019fb89a-5cfb-7b00-8e3a-6daf36d85570",
            turnId,
            @"D:\bounded\rollout.jsonl",
            ByteOffset: 128,
            RecordedAt: DateTimeOffset.FromUnixTimeSeconds(200),
            localTurn);
        var reconciled = AppServerWorkflowConversationAuthorityReader.ReconcileTurns(
            [appServerTurn],
            turnId,
            local);
        Ensure(
            reconciled.LatestTurn is { HasConfirmedLocalTerminal: true } &&
            reconciled.RequiredTurn is { HasConfirmedLocalTerminal: true } &&
            FollowUpQueuePlanner.IsNormalCompletion(reconciled.LatestTurn) &&
            FollowUpQueuePlanner.IsNormalCompletion(reconciled.RequiredTurn),
            "workflow authority did not merge the matching local terminal into current turn facts");
    }

    private static void TestFinalFollowUpLocalTerminalReconciliation()
    {
        var threadId = "019fb89a-5cfb-7b00-8e3a-6daf36d85570";
        var turnId = "019fb89b-9db1-7d70-9225-091ec086f06e";
        var appServerTurn = new TurnSnapshot(
            turnId,
            "completed",
            ErrorMessage: null,
            ErrorCode: null,
            HttpStatusCode: null,
            UserText: string.Empty,
            HasAttachments: false,
            HasAssistantOutput: true,
            HasWorkOutput: false,
            OutputFingerprint: "final-dispatch",
            StartedAt: 100,
            CompletedAt: 200,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true);
        var local = new LocalConversationTerminalEvent(
            threadId,
            turnId,
            @"D:\bounded\rollout.jsonl",
            ByteOffset: 128,
            RecordedAt: DateTimeOffset.FromUnixTimeSeconds(200),
            appServerTurn with { HasConfirmedLocalTerminal = true });
        var reconciled = AppServerFollowUpStateReader.ReconcileLatestTurn(appServerTurn, local);
        var mismatched = AppServerFollowUpStateReader.ReconcileLatestTurn(
            appServerTurn,
            local with { TurnId = "019fb89b-9db1-7d70-9225-091ec086f06f" });
        Ensure(
            reconciled is { HasConfirmedLocalTerminal: true } &&
            FollowUpQueuePlanner.IsNormalCompletion(reconciled) &&
            mismatched is { HasConfirmedLocalTerminal: false } &&
            !FollowUpQueuePlanner.IsNormalCompletion(mismatched),
            "final follow-up dispatch did not preserve the exact local-terminal authority boundary");
    }

    private static void TestStockOwnerRuntimeProjection()
    {
        var targetId = "019fb89a-5cfb-7b00-8e3a-6daf36d85570";
        var turnId = "019fb89b-9db1-7d70-9225-091ec086f06e";
        var turn = new TurnSnapshot(
            turnId,
            "completed",
            ErrorMessage: null,
            ErrorCode: null,
            HttpStatusCode: null,
            UserText: string.Empty,
            HasAttachments: false,
            HasAssistantOutput: true,
            HasWorkOutput: false,
            OutputFingerprint: "owner-runtime",
            StartedAt: 100,
            CompletedAt: 200,
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true);
        var thread = new ThreadSummary(
            targetId,
            "Bounded live target",
            string.Empty,
            @"D:\bounded",
            "cli",
            CreatedAt: 100,
            UpdatedAt: 200,
            IsSubAgent: false,
            IsEphemeral: false,
            RuntimeStatus: "notLoaded",
            IsArchived: false);
        var authority = new StaticConversationAuthorityReader(new Dictionary<
            string,
            WorkflowConversationAuthoritySnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [targetId] = new(
                WorkflowConversationAuthorityStatus.Available,
                thread,
                turn,
                RequiredTurn: null)
        });
        var owner = new DesktopThreadOwnerStateSnapshot(
            targetId,
            "host",
            "owner",
            Revision: 7,
            RuntimeStatus: "idle",
            LatestTurnId: turnId,
            LatestTurnStatus: "completed");
        var reader = new StockOwnerWorkflowConversationAuthorityReader(
            authority,
            targetId,
            turnId,
            owner);
        var projected = reader.ReadAsync(
                [new WorkflowConversationReadRequest(targetId)],
                CancellationToken.None)
            .GetAwaiter()
            .GetResult()[targetId];

        Ensure(
            projected.Thread?.RuntimeStatus == "idle" &&
            authority.Snapshots[targetId].Thread?.RuntimeStatus == "notLoaded" &&
            FollowUpDispatchService.ValidateOwnerNormalCompletion(owner, turnId) is null &&
            Throws(() => new StockOwnerWorkflowConversationAuthorityReader(
                authority,
                targetId,
                turnId,
                owner with { RuntimeStatus = "active" })),
            "independent app-server runtime state replaced or bypassed stock owner idle authority");
    }

    private static void TestNoForegroundComposerClassification()
    {
        var observedAt = DateTimeOffset.FromUnixTimeSeconds(200);
        var clear = WindowsCodexInteractionHook.ClassifyMissingForeground(
            isDefaultInputDesktop: true,
            observedAt: observedAt);
        var unknown = WindowsCodexInteractionHook.ClassifyMissingForeground(
            isDefaultInputDesktop: false,
            observedAt: observedAt);
        Ensure(
            clear is
            {
                Status: RecoveryInterferenceStatus.Clear,
                HasFocusedDraft: false,
                ObservedAt: var clearAt
            } &&
            clearAt == observedAt &&
            unknown is
            {
                Status: RecoveryInterferenceStatus.Unknown,
                HasFocusedDraft: false,
                ObservedAt: var unknownAt
            } &&
            unknownAt == observedAt,
            "missing foreground state bypassed the verified default input-desktop boundary");
    }

    private static string[] Arguments(bool prepareOnly, bool scheduledHost = false)
    {
        var scheduled = DateTimeOffset.Parse(
            "2026-08-15T12:00:00.0000000+00:00",
            CultureInfo.InvariantCulture).ToString("O", CultureInfo.InvariantCulture);
        var arguments = new List<string>
        {
            WorkflowExistingConversationLiveGate.GateArgument,
            prepareOnly
                ? WorkflowExistingConversationLiveGate.PrepareArgument
                : WorkflowExistingConversationLiveGate.ConfirmArgument,
            WorkflowExistingConversationLiveGate.TargetArgument,
            "019fb89a-5cfb-7b00-8e3a-6daf36d85570",
            WorkflowExistingConversationLiveGate.ExpectedTurnArgument,
            "019fb89b-9db1-7d70-9225-091ec086f06e",
            WorkflowExistingConversationLiveGate.RestoreArgument,
            "019fe1b7-672f-76f3-b2f8-8a4a2c03dec2",
            WorkflowExistingConversationLiveGate.RuleArgument,
            "2a80af6f-5e28-4517-9388-7405c82f68ec",
            WorkflowExistingConversationLiveGate.PresetArgument,
            "f5f9375b-7ab5-4e21-8a10-ef9f95f53d3a",
            WorkflowExistingConversationLiveGate.ScheduledArgument,
            scheduled,
            WorkflowExistingConversationLiveGate.DataDirectoryArgument,
            @"D:\CodexData\CodexGuardian\wf19a1\live-gates\2a80af6f-5e28-4517-9388-7405c82f68ec"
        };
        if (scheduledHost)
        {
            arguments.Insert(2, WorkflowExistingConversationLiveGate.ScheduledHostArgument);
        }

        return arguments.ToArray();
    }

    private static string[] ReplaceValue(string[] arguments, string name, string value)
    {
        var copy = arguments.ToArray();
        var index = Array.FindIndex(copy, argument => string.Equals(
            argument,
            name,
            StringComparison.OrdinalIgnoreCase));
        copy[index + 1] = value;
        return copy;
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private sealed class StaticConversationAuthorityReader(
        IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot> snapshots)
        : IWorkflowConversationAuthorityReader
    {
        internal IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot> Snapshots { get; } =
            snapshots;

        public Task<IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot>> ReadAsync(
            IReadOnlyList<WorkflowConversationReadRequest> requests,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Snapshots);
        }
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
            Console.WriteLine($"INFO  {name}: {exception.GetType().Name} - {exception.Message}");
            assert(false, name);
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
