using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Diagnostics;
using System.Globalization;
using System.IO;

internal sealed record WorkflowExistingConversationLiveGateOptions(
    bool PrepareOnly,
    bool ExerciseScheduledHost,
    string TargetThreadId,
    string ExpectedTurnId,
    string RestoreThreadId,
    string RuleId,
    string PresetId,
    DateTimeOffset ScheduledAtUtc,
    string DataDirectory);

internal sealed record WorkflowExistingConversationLiveGateConfiguration(
    WorkflowRuleDefinition Rule,
    FollowUpMessageDefinition Preset,
    AppSettings Settings,
    StructuredPresetPayload Payload,
    string TriggerEventId,
    string ActionOperationId,
    string ClientMessageId);

internal sealed class StockOwnerWorkflowConversationAuthorityReader :
    IWorkflowConversationAuthorityReader
{
    private readonly IWorkflowConversationAuthorityReader _inner;
    private readonly string _targetThreadId;
    private readonly string _expectedTurnId;
    private readonly DesktopThreadOwnerStateSnapshot _ownerSnapshot;

    internal StockOwnerWorkflowConversationAuthorityReader(
        IWorkflowConversationAuthorityReader inner,
        string targetThreadId,
        string expectedTurnId,
        DesktopThreadOwnerStateSnapshot ownerSnapshot)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        ArgumentNullException.ThrowIfNull(ownerSnapshot);
        if (!Guid.TryParse(targetThreadId, out var parsedTarget) || parsedTarget == Guid.Empty ||
            !Guid.TryParse(expectedTurnId, out var parsedTurn) || parsedTurn == Guid.Empty ||
            !string.Equals(
                ownerSnapshot.ConversationId,
                parsedTarget.ToString("D"),
                StringComparison.OrdinalIgnoreCase) ||
            FollowUpDispatchService.ValidateOwnerNormalCompletion(
                ownerSnapshot,
                parsedTurn.ToString("D")) is not null)
        {
            throw new ArgumentException(
                "An exact idle stock Desktop owner snapshot is required.",
                nameof(ownerSnapshot));
        }

        _targetThreadId = parsedTarget.ToString("D");
        _expectedTurnId = parsedTurn.ToString("D");
        _ownerSnapshot = ownerSnapshot;
    }

    public async Task<IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot>> ReadAsync(
        IReadOnlyList<WorkflowConversationReadRequest> requests,
        CancellationToken cancellationToken)
    {
        var snapshots = await _inner.ReadAsync(requests, cancellationToken).ConfigureAwait(false);
        if (!snapshots.TryGetValue(_targetThreadId, out var target) ||
            !target.IsActiveRoot ||
            target.Thread is not { } thread ||
            target.LatestTurn is not { } latest ||
            !string.Equals(latest.Id, _expectedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !FollowUpQueuePlanner.IsNormalCompletion(latest))
        {
            return snapshots;
        }

        var projected = snapshots.ToDictionary(
            static entry => entry.Key,
            static entry => entry.Value,
            StringComparer.OrdinalIgnoreCase);
        projected[_targetThreadId] = target with
        {
            Thread = thread with { RuntimeStatus = _ownerSnapshot.RuntimeStatus }
        };
        return projected;
    }
}

internal sealed class RefreshingStockOwnerWorkflowConversationAuthorityReader :
    IWorkflowConversationAuthorityReader
{
    private readonly IWorkflowConversationAuthorityReader _inner;
    private readonly DesktopIpcClient _desktop;
    private readonly string _targetThreadId;
    private readonly string _expectedTurnId;

    internal RefreshingStockOwnerWorkflowConversationAuthorityReader(
        IWorkflowConversationAuthorityReader inner,
        DesktopIpcClient desktop,
        string targetThreadId,
        string expectedTurnId)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _desktop = desktop ?? throw new ArgumentNullException(nameof(desktop));
        _targetThreadId = NormalizeId(targetThreadId, nameof(targetThreadId));
        _expectedTurnId = NormalizeId(expectedTurnId, nameof(expectedTurnId));
    }

    public async Task<IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot>> ReadAsync(
        IReadOnlyList<WorkflowConversationReadRequest> requests,
        CancellationToken cancellationToken)
    {
        var snapshots = await _inner.ReadAsync(requests, cancellationToken).ConfigureAwait(false);
        if (!snapshots.TryGetValue(_targetThreadId, out var target) ||
            !target.IsActiveRoot ||
            target.Thread is not { } thread ||
            target.LatestTurn is not { } latest ||
            !string.Equals(latest.Id, _expectedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !FollowUpQueuePlanner.IsNormalCompletion(latest))
        {
            return snapshots;
        }

        var ownerState = await _desktop.AcquireThreadOwnerStateGuardAsync(
                _targetThreadId,
                cancellationToken)
            .ConfigureAwait(false);
        if (!ownerState.IsAvailable)
        {
            return snapshots;
        }

        await using var ownerGuard = ownerState.Guard!;
        if (FollowUpDispatchService.ValidateOwnerNormalCompletion(
                ownerGuard.Snapshot,
                _expectedTurnId) is not null ||
            !ownerGuard.IsCurrent)
        {
            return snapshots;
        }

        var projected = snapshots.ToDictionary(
            static entry => entry.Key,
            static entry => entry.Value,
            StringComparer.OrdinalIgnoreCase);
        projected[_targetThreadId] = target with
        {
            Thread = thread with { RuntimeStatus = ownerGuard.Snapshot.RuntimeStatus }
        };
        return projected;
    }

    private static string NormalizeId(string? value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty workflow live-gate identity is required.", parameterName);
        }

        return parsed.ToString("D");
    }
}

internal static class WorkflowExistingConversationLiveGate
{
    internal const string GateArgument = "--workflow-existing-conversation-live-gate";
    internal const string PrepareArgument = "--prepare-only";
    internal const string ConfirmArgument = "--confirm-real-workflow-send";
    internal const string ScheduledHostArgument = "--exercise-scheduled-host";
    internal const string TargetArgument = "--target-thread-id";
    internal const string ExpectedTurnArgument = "--expected-turn-id";
    internal const string RestoreArgument = "--restore-thread-id";
    internal const string RuleArgument = "--gate-rule-id";
    internal const string PresetArgument = "--gate-preset-id";
    internal const string ScheduledArgument = "--scheduled-at-utc";
    internal const string DataDirectoryArgument = "--data-directory";
    internal const string DataRoot = @"D:\CodexData\CodexGuardian";
    internal const string TempRoot = @"D:\CodexTemp\CodexGuardian";
    internal const string MessagePrefix = "Ceasy \u6536\u53d1\u9a8c\u8bc1 ";
    private static readonly TimeSpan DirectExecutionTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ScheduledHostMinimumPrepareLead = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ScheduledHostMinimumArmLead = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan ScheduledHostMaximumLead = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan ScheduledHostCompletionGrace = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan TargetPresentationDelay = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan ReadbackTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ReadbackPollInterval = TimeSpan.FromMilliseconds(500);

    internal static bool IsRequested(IReadOnlyList<string> arguments) =>
        arguments.Any(argument => string.Equals(
            argument,
            GateArgument,
            StringComparison.OrdinalIgnoreCase));

    internal static WorkflowExistingConversationLiveGateOptions Parse(
        IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var allowedFlags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            GateArgument,
            PrepareArgument,
            ConfirmArgument,
            ScheduledHostArgument
        };
        var allowedValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            TargetArgument,
            ExpectedTurnArgument,
            RestoreArgument,
            RuleArgument,
            PresetArgument,
            ScheduledArgument,
            DataDirectoryArgument
        };
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (allowedFlags.Contains(argument))
            {
                if (!flags.Add(argument))
                {
                    throw new ArgumentException("The workflow live gate contains a duplicate flag.");
                }

                continue;
            }

            if (!allowedValues.Contains(argument) || index + 1 >= arguments.Count ||
                arguments[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException("The workflow live gate argument matrix is invalid.");
            }

            if (!values.TryAdd(argument, arguments[++index]))
            {
                throw new ArgumentException("The workflow live gate contains a duplicate value.");
            }
        }

        if (!flags.Contains(GateArgument) ||
            flags.Contains(PrepareArgument) == flags.Contains(ConfirmArgument) ||
            values.Count != allowedValues.Count)
        {
            throw new ArgumentException(
                "The workflow live gate requires exactly one prepare or confirmed-send mode and every identity value.");
        }

        var targetThreadId = NormalizeId(values[TargetArgument], TargetArgument);
        var expectedTurnId = NormalizeId(values[ExpectedTurnArgument], ExpectedTurnArgument);
        var restoreThreadId = NormalizeId(values[RestoreArgument], RestoreArgument);
        var ruleId = NormalizeId(values[RuleArgument], RuleArgument);
        var presetId = NormalizeId(values[PresetArgument], PresetArgument);
        if (string.Equals(targetThreadId, restoreThreadId, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The workflow live target and restore task must be distinct.");
        }

        if (!DateTimeOffset.TryParseExact(
                values[ScheduledArgument],
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var scheduledAtUtc) || scheduledAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("The workflow live schedule must be one round-trip UTC timestamp.");
        }

        var dataDirectory = NormalizeDataDirectory(values[DataDirectoryArgument]);
        return new WorkflowExistingConversationLiveGateOptions(
            flags.Contains(PrepareArgument),
            flags.Contains(ScheduledHostArgument),
            targetThreadId,
            expectedTurnId,
            restoreThreadId,
            ruleId,
            presetId,
            scheduledAtUtc,
            dataDirectory);
    }

    internal static WorkflowExistingConversationLiveGateConfiguration BuildConfiguration(
        WorkflowExistingConversationLiveGateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var rule = WorkflowRuleDefinition.Create(
            options.RuleId,
            revision: 1,
            options.TargetThreadId,
            isEnabled: true,
            options.ScheduledAtUtc.AddTicks(-1),
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = options.ScheduledAtUtc
            },
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation,
                ConversationId = options.TargetThreadId
            },
            conditions: null,
            actions:
            [
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.SendPresetMessage,
                    PresetOwnerConversationId = options.TargetThreadId,
                    PresetMessageId = options.PresetId,
                    Order = 0
                }
            ]);
        var preset = new FollowUpMessageDefinition
        {
            Id = options.PresetId,
            Message = BuildMessage(options.RuleId),
            Attachments = [],
            Trigger = FollowUpTriggerKind.ScheduledAt,
            ScheduledAtUtc = options.ScheduledAtUtc,
            IsEnabled = true,
            UseWorkflowAutomation = true,
            WorkflowRuleRevision = rule.Revision,
            WorkflowRuleDigest = rule.DefinitionDigest,
            RetryIndefinitely = false,
            MaximumErrorRetries = 0,
            Order = 0
        };
        var settings = new AppSettings
        {
            MonitoringEnabled = false,
            // Preset authorization is independent of automatic recovery in the current product policy.
            MonitorOnly = true,
            AutomaticRecoveryEnabled = false,
            GlobalProtectionEnabled = true,
            IncludeSubAgents = false,
            ProtectNewThreadsByDefault = false,
            MinimizeToTray = false,
            StartWithWindows = false
        };
        settings.ThreadEnabled[options.TargetThreadId] = true;
        settings.ThreadProtectionEnabled[options.TargetThreadId] = true;
        settings.ThreadFollowUps[options.TargetThreadId] = new ThreadFollowUpSettings
        {
            IsEnabled = true,
            Messages = [preset]
        };

        var payload = StructuredPresetPayload.Create(preset.Message, preset.Attachments);
        var occurrence = "scheduled:" + options.ScheduledAtUtc.UtcTicks.ToString(
            CultureInfo.InvariantCulture);
        var triggerEventId = WorkflowOperationJournal.CreateTriggerEventId(
            WorkflowTriggerKind.ScheduledAt,
            options.TargetThreadId,
            rule.RuleId,
            rule.RuleId,
            occurrence);
        var actionOperationId = WorkflowOperationJournal.CreateActionOperationId(
            rule.RuleId,
            rule.Revision,
            triggerEventId,
            actionIndex: 0);
        return new WorkflowExistingConversationLiveGateConfiguration(
            rule,
            preset,
            settings,
            payload,
            triggerEventId,
            actionOperationId,
            WorkflowOperationJournal.CreateClientMessageId(actionOperationId));
    }

    internal static string BuildMessage(string ruleId) =>
        MessagePrefix + NormalizeId(ruleId, nameof(ruleId)) +
        "\u3002\u53ea\u56de\u590d\u201c\u6536\u5230\u201d\uff0c\u4e0d\u8981\u8c03\u7528\u5de5\u5177\u6216\u4fee\u6539\u6587\u4ef6\u3002";

    internal static async Task<int> RunAsync(string[] arguments)
    {
        WorkflowExistingConversationLiveGateOptions options;
        try
        {
            options = Parse(arguments);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            Console.WriteLine("WORKFLOW_LIVE_GATE_FAILED code=argument-matrix-invalid");
            return 2;
        }

        using var timeout = new CancellationTokenSource(GetExecutionTimeout(options));
        try
        {
            return await RunCoreAsync(options, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine(
                "WORKFLOW_LIVE_GATE_STOPPED code=bounded-timeout realSend=" +
                (!options.PrepareOnly).ToString(CultureInfo.InvariantCulture));
            return 3;
        }
        catch (WorkflowLiveGateException exception)
        {
            Console.WriteLine(
                "WORKFLOW_LIVE_GATE_FAILED code=" + exception.Code + " realSend=" +
                (!options.PrepareOnly).ToString(CultureInfo.InvariantCulture));
            return 1;
        }
        catch (Exception exception)
        {
            Console.WriteLine(
                "WORKFLOW_LIVE_GATE_FAILED code=unexpected-" +
                GuardianLog.SanitizeIdentifier(exception.GetType().Name) + " realSend=" +
                (!options.PrepareOnly).ToString(CultureInfo.InvariantCulture));
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(
        WorkflowExistingConversationLiveGateOptions options,
        CancellationToken cancellationToken)
    {
        ValidateExecutionEnvironment(options);
        ValidateScheduleWindow(options, DateTimeOffset.UtcNow);

        EnsureNoGuardianProcess();
        Directory.CreateDirectory(options.DataDirectory);
        DataDirectorySafety.Revalidate(options.DataDirectory);
        using var log = new GuardianLog(options.DataDirectory);
        await using var appServer = new AppServerClient(new CodexCliLocator(), log);
        await using var desktop = new DesktopIpcClient(log);
        var localHistory = new LocalConversationHistoryReader();
        var target = await ReadExactTargetAsync(
                appServer,
                localHistory,
                options.TargetThreadId,
                options.ExpectedTurnId,
                cancellationToken)
            .ConfigureAwait(false);
        var rules = new WorkflowRuleStore(options.DataDirectory);
        var settings = new SettingsService(
            options.DataDirectory,
            monitoringEnabledAfterNormalization: false);
        var configuration = BuildConfiguration(options);
        var ruleSnapshot = await EnsureRuleAsync(rules, configuration.Rule, cancellationToken)
            .ConfigureAwait(false);
        var settingsSnapshot = await EnsureSettingsAsync(
                settings,
                configuration.Settings,
                configuration.Rule,
                cancellationToken)
            .ConfigureAwait(false);
        await desktop.EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
        if (!await desktop.ProbeNativeDesktopChannelAsync(cancellationToken).ConfigureAwait(false) ||
            !desktop.IsNativeChannelAvailable)
        {
            throw new WorkflowLiveGateException("stock-owner-channel-unavailable");
        }

        var workflowJournal = new WorkflowOperationJournal(options.DataDirectory);
        var followUpJournal = new FollowUpOperationJournal(options.DataDirectory);
        var initialWorkflow = await workflowJournal.ReadAsync(cancellationToken).ConfigureAwait(false);
        var priorAction = initialWorkflow.Actions.SingleOrDefault(action => string.Equals(
            action.ActionOperationId,
            configuration.ActionOperationId,
            StringComparison.OrdinalIgnoreCase));
        if (options.PrepareOnly)
        {
            var platform = new WindowsDesktopThreadOwnerActivationPlatform();
            var idle = platform.GetUserIdleTime();
            Console.WriteLine(
                "WORKFLOW_LIVE_GATE_PREPARED target=" + options.TargetThreadId +
                " expectedTurn=" + options.ExpectedTurnId +
                " mode=" + (options.ExerciseScheduledHost ? "scheduled-host" : "direct") +
                " scheduled=" + options.ScheduledAtUtc.ToString("O", CultureInfo.InvariantCulture) +
                " rule=" + configuration.Rule.RuleId +
                " preset=" + configuration.Preset.Id +
                " trigger=" + configuration.TriggerEventId +
                " action=" + configuration.ActionOperationId +
                " client=" + configuration.ClientMessageId +
                " payload=" + configuration.Payload.PayloadDigest +
                " settingsGeneration=" + settingsSnapshot.SettingsGeneration.ToString(
                    CultureInfo.InvariantCulture) +
                " ruleGeneration=" + ruleSnapshot.Generation.ToString(CultureInfo.InvariantCulture) +
                " targetStatus=" + GuardianLog.SanitizeIdentifier(target.RuntimeStatus) +
                " priorState=" + (priorAction?.State.ToString() ?? "Missing") +
                " idleSeconds=" + idle.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture) +
                " realSend=False");
            return 0;
        }

        return await ExecuteConfirmedGateAsync(
                options,
                configuration,
                settings,
                rules,
                workflowJournal,
                followUpJournal,
                appServer,
                localHistory,
                desktop,
                log,
                priorAction,
            cancellationToken)
            .ConfigureAwait(false);
    }

    private static TimeSpan GetExecutionTimeout(
        WorkflowExistingConversationLiveGateOptions options)
    {
        if (options.PrepareOnly || !options.ExerciseScheduledHost)
        {
            return DirectExecutionTimeout;
        }

        var remaining = options.ScheduledAtUtc - DateTimeOffset.UtcNow;
        if (remaining < TimeSpan.Zero)
        {
            remaining = TimeSpan.Zero;
        }

        var bounded = remaining + ScheduledHostCompletionGrace;
        return bounded > DirectExecutionTimeout ? bounded : DirectExecutionTimeout;
    }

    private static void ValidateScheduleWindow(
        WorkflowExistingConversationLiveGateOptions options,
        DateTimeOffset observedAtUtc)
    {
        var lead = options.ScheduledAtUtc - observedAtUtc.ToUniversalTime();
        if (!options.ExerciseScheduledHost)
        {
            if (lead > TimeSpan.Zero)
            {
                throw new WorkflowLiveGateException("schedule-not-due");
            }

            return;
        }

        var minimumLead = options.PrepareOnly
            ? ScheduledHostMinimumPrepareLead
            : ScheduledHostMinimumArmLead;
        if (lead < minimumLead)
        {
            throw new WorkflowLiveGateException("scheduled-host-lead-too-short");
        }

        if (lead > ScheduledHostMaximumLead)
        {
            throw new WorkflowLiveGateException("scheduled-host-lead-too-long");
        }
    }

    private static async Task<int> ExecuteConfirmedGateAsync(
        WorkflowExistingConversationLiveGateOptions options,
        WorkflowExistingConversationLiveGateConfiguration configuration,
        SettingsService settings,
        WorkflowRuleStore rules,
        WorkflowOperationJournal workflowJournal,
        FollowUpOperationJournal followUpJournal,
        AppServerClient appServer,
        LocalConversationHistoryReader localHistory,
        DesktopIpcClient desktop,
        GuardianLog log,
        WorkflowActionOperationRecord? priorAction,
        CancellationToken cancellationToken)
    {
        var platform = new WindowsDesktopThreadOwnerActivationPlatform();
        var ownerActivator = new DesktopThreadOwnerActivator(desktop, log);
        await using var windowsObservation = new WindowsCodexInteractionHook(log);
        if (!windowsObservation.Start())
        {
            throw new WorkflowLiveGateException("windows-composer-observer-unavailable");
        }

        if (options.ExerciseScheduledHost && priorAction is not null)
        {
            throw new WorkflowLiveGateException("scheduled-host-action-already-exists");
        }

        var restored = false;
        DesktopThreadOwnerStateSnapshot? stockOwnerSnapshot = null;
        try
        {
            if (priorAction?.State != WorkflowActionOperationState.Confirmed)
            {
                await ownerActivator.WaitForMinimumIdleAsync(cancellationToken).ConfigureAwait(false);
                platform.OpenThread(options.TargetThreadId);
                await Task.Delay(TargetPresentationDelay, cancellationToken).ConfigureAwait(false);
                var owner = await ownerActivator.EnsureOwnerAsync(
                        options.TargetThreadId,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (!owner.IsAvailable)
                {
                    throw new WorkflowLiveGateException(
                        "target-owner-" + GuardianLog.SanitizeIdentifier(owner.Status.ToString()));
                }

                _ = await ReadExactTargetAsync(
                        appServer,
                        localHistory,
                        options.TargetThreadId,
                        options.ExpectedTurnId,
                        cancellationToken)
                    .ConfigureAwait(false);
                stockOwnerSnapshot = await ReadExactStockOwnerSnapshotAsync(
                        desktop,
                        options.TargetThreadId,
                        options.ExpectedTurnId,
                        cancellationToken)
                    .ConfigureAwait(false);
                var composer = await windowsObservation.CheckAsync(
                        options.TargetThreadId,
                        cancellationToken)
                    .ConfigureAwait(false);
                Console.WriteLine(
                    "WORKFLOW_LIVE_GATE_COMPOSER status=" + composer.Status +
                    " focusedDraft=" + composer.HasFocusedDraft);
                if (composer.Status != RecoveryInterferenceStatus.Clear)
                {
                    throw new WorkflowLiveGateException(
                        composer.Status == RecoveryInterferenceStatus.Editing
                            ? "target-composer-editing"
                            : "target-composer-unknown");
                }
            }

            var beforeTurns = await appServer.ReadRecentTurnsAsync(
                    options.TargetThreadId,
                    limit: 20,
                    cancellationToken)
                .ConfigureAwait(false);
            var followUps = new FollowUpDispatchService(
                appServer,
                desktop,
                ownerActivator,
                followUpJournal,
                log,
                new StrictComposerInterferenceGuard(windowsObservation));
            var executor = new WorkflowActionExecutor(
                workflowJournal,
                new FollowUpWorkflowPresetDispatcher(followUps),
                new SettingsWorkflowConversationProtectionService(settings));
            IWorkflowConversationAuthorityReader conversationAuthority =
                new AppServerWorkflowConversationAuthorityReader(appServer, localHistory);
            if (options.ExerciseScheduledHost)
            {
                // A scheduled wake may occur well after the initial owner preflight. Reacquire
                // stock owner authority on every resolver read instead of projecting stale state.
                conversationAuthority = new RefreshingStockOwnerWorkflowConversationAuthorityReader(
                    conversationAuthority,
                    desktop,
                    options.TargetThreadId,
                    options.ExpectedTurnId);
            }
            else if (stockOwnerSnapshot is not null)
            {
                // The independent app-server's notLoaded state is process-local. Only the
                // verified stock Desktop snapshot may project live idle state into this gate.
                conversationAuthority = new StockOwnerWorkflowConversationAuthorityReader(
                    conversationAuthority,
                    options.TargetThreadId,
                    options.ExpectedTurnId,
                    stockOwnerSnapshot);
            }

            var resolver = new WorkflowExecutionResolver(
                conversationAuthority,
                new SettingsWorkflowSettingsAuthorityReader(settings),
                new StoreWorkflowRuleRevisionAuthorityReader(rules),
                new JournalWorkflowOperationAuthorityReader(workflowJournal, followUpJournal));
            var runner = new WorkflowRuleActionRunner(
                resolver,
                executor,
                new WorkflowDispatchPolicyAuthority(settings));
            var runtime = new WorkflowAutomationRuntime(
                rules,
                workflowJournal,
                new WorkflowTriggerCoordinator(
                    workflowJournal,
                    new WorkflowFiniteConditionEvaluator(resolver),
                    runner),
                runner);
            WorkflowActionOperationRecord current;
            if (options.ExerciseScheduledHost)
            {
                current = await ExecuteScheduledHostAsync(
                        options,
                        configuration,
                        workflowJournal,
                        runtime,
                        executor,
                        log,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                _ = await runtime.ProcessScheduledWakeAsync(DateTimeOffset.UtcNow, cancellationToken)
                    .ConfigureAwait(false);
                current = await ReadExactActionAsync(
                        workflowJournal,
                        configuration.ActionOperationId,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (current.State == WorkflowActionOperationState.Uncertain)
                {
                    _ = await runtime.ReconcilePendingAsync(DateTimeOffset.UtcNow, cancellationToken)
                        .ConfigureAwait(false);
                    current = await ReadExactActionAsync(
                            workflowJournal,
                            configuration.ActionOperationId,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            if (current is not
                {
                    State: WorkflowActionOperationState.Confirmed,
                    GeneratedTurnId: not null,
                    ClientMessageId: not null,
                    AttemptCount: 1
                } ||
                !string.Equals(
                    current.ClientMessageId,
                    configuration.ClientMessageId,
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    current.ConfirmedTargetConversationId,
                    options.TargetThreadId,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new WorkflowLiveGateException(
                    "workflow-action-not-confirmed-" +
                    GuardianLog.SanitizeIdentifier(current.State.ToString()));
            }

            var readback = await WaitForReadbackAsync(
                    appServer,
                    options.TargetThreadId,
                    configuration.ClientMessageId,
                    current.GeneratedTurnId,
                    cancellationToken)
                .ConfigureAwait(false);
            var followUp = await ReadExactFollowUpAsync(
                    followUpJournal,
                    configuration.ActionOperationId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (followUp is not
                {
                    State: FollowUpOperationState.Confirmed,
                    SourceKind: FollowUpPayloadSourceKind.WorkflowPreset,
                    NewTurnId: not null,
                    AttemptCount: 1
                } ||
                !string.Equals(
                    followUp.ClientMessageId,
                    configuration.ClientMessageId,
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    followUp.NewTurnId,
                    current.GeneratedTurnId,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new WorkflowLiveGateException("inner-follow-up-not-confirmed");
            }

            var afterTurns = await appServer.ReadRecentTurnsAsync(
                    options.TargetThreadId,
                    limit: 20,
                    cancellationToken)
                .ConfigureAwait(false);
            var beforeIds = beforeTurns.Select(turn => turn.Id).ToHashSet(
                StringComparer.OrdinalIgnoreCase);
            var newIds = afterTurns
                .Select(turn => turn.Id)
                .Where(id => !beforeIds.Contains(id))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (newIds.Length > 1 ||
                newIds.Length == 1 && !string.Equals(
                    newIds[0],
                    current.GeneratedTurnId,
                    StringComparison.OrdinalIgnoreCase) ||
                priorAction is null && newIds.Length != 1)
            {
                throw new WorkflowLiveGateException("turn-count-not-at-most-once");
            }

            Console.WriteLine(
                "WORKFLOW_LIVE_GATE_CONFIRMED target=" + options.TargetThreadId +
                " expectedTurn=" + options.ExpectedTurnId +
                " mode=" + (options.ExerciseScheduledHost ? "scheduled-host" : "direct") +
                " scheduled=" + options.ScheduledAtUtc.ToString("O", CultureInfo.InvariantCulture) +
                " action=" + current.ActionOperationId +
                " client=" + current.ClientMessageId +
                " generatedTurn=" + current.GeneratedTurnId +
                " readbackTurn=" + readback.Id +
                " outerState=" + current.State +
                " innerState=" + followUp.State +
                " attempts=" + current.AttemptCount.ToString(CultureInfo.InvariantCulture) +
                " newTurns=" + newIds.Length.ToString(CultureInfo.InvariantCulture) +
                " priorState=" + (priorAction?.State.ToString() ?? "Missing") +
                " realSend=True");
            return 0;
        }
        finally
        {
            try
            {
                platform.OpenThread(options.RestoreThreadId);
                await Task.Delay(TargetPresentationDelay, CancellationToken.None).ConfigureAwait(false);
                restored = true;
            }
            catch
            {
            }

            Console.WriteLine(
                "WORKFLOW_LIVE_GATE_RESTORE restored=" +
                restored.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static async Task<WorkflowActionOperationRecord> ExecuteScheduledHostAsync(
        WorkflowExistingConversationLiveGateOptions options,
        WorkflowExistingConversationLiveGateConfiguration configuration,
        WorkflowOperationJournal workflowJournal,
        WorkflowAutomationRuntime runtime,
        WorkflowActionExecutor executor,
        GuardianLog log,
        CancellationToken cancellationToken)
    {
        var armedAtUtc = DateTimeOffset.UtcNow;
        if (options.ScheduledAtUtc - armedAtUtc < ScheduledHostMinimumArmLead)
        {
            throw new WorkflowLiveGateException("scheduled-host-no-longer-armable");
        }

        var adapter = new WorkflowAutomationEventAdapter(
            runtime,
            EmptyWorkflowAuthoritativeCompletionSource.Instance,
            executor);
        await using var host = new WorkflowAutomationHost(
            adapter,
            new EmptyWorkflowAutomationAuthorityChangeSource(),
            log,
            clock: SystemWorkflowAutomationClock.Instance);
        await host.StartAsync(cancellationToken).ConfigureAwait(false);
        if (!host.IsStarted || host.LastFailure is not null ||
            host.NextScheduledWakeAtUtc != options.ScheduledAtUtc)
        {
            throw new WorkflowLiveGateException("scheduled-host-arm-state-mismatch");
        }

        if (await TryReadExactActionAsync(
                workflowJournal,
                configuration.ActionOperationId,
                cancellationToken).ConfigureAwait(false) is not null)
        {
            throw new WorkflowLiveGateException("scheduled-host-fired-before-due");
        }

        Console.WriteLine(
            "WORKFLOW_LIVE_GATE_ARMED target=" + options.TargetThreadId +
            " expectedTurn=" + options.ExpectedTurnId +
            " scheduled=" + options.ScheduledAtUtc.ToString("O", CultureInfo.InvariantCulture) +
            " action=" + configuration.ActionOperationId +
            " client=" + configuration.ClientMessageId +
            " leadSeconds=" + (options.ScheduledAtUtc - DateTimeOffset.UtcNow).TotalSeconds.ToString(
                "0.0",
                CultureInfo.InvariantCulture) +
            " realSendPending=True");

        var deadline = options.ScheduledAtUtc + ScheduledHostCompletionGrace;
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await TryReadExactActionAsync(
                    workflowJournal,
                    configuration.ActionOperationId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (current?.State == WorkflowActionOperationState.Confirmed)
            {
                return current;
            }

            if (current?.State is WorkflowActionOperationState.Blocked or
                WorkflowActionOperationState.Exhausted or
                WorkflowActionOperationState.Canceled)
            {
                throw new WorkflowLiveGateException(
                    "scheduled-host-terminal-" +
                    GuardianLog.SanitizeIdentifier(current.State.ToString()));
            }

            if (host.LastFailure is not null)
            {
                throw new WorkflowLiveGateException("scheduled-host-runtime-failed");
            }

            await Task.Delay(ReadbackPollInterval, cancellationToken).ConfigureAwait(false);
        }

        throw new WorkflowLiveGateException("scheduled-host-confirmation-timeout");
    }

    private static async Task<WorkflowActionOperationRecord?> TryReadExactActionAsync(
        WorkflowOperationJournal journal,
        string actionOperationId,
        CancellationToken cancellationToken)
    {
        var snapshot = await journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (snapshot.ReadStatus == WorkflowJournalReadStatus.Missing &&
            !snapshot.RequiresConservativeRecovery && snapshot.Actions.Count == 0)
        {
            return null;
        }

        if (snapshot.ReadStatus is not WorkflowJournalReadStatus.Healthy and not
                WorkflowJournalReadStatus.RecoveredFromBackup ||
            snapshot.RequiresConservativeRecovery)
        {
            throw new WorkflowLiveGateException("workflow-journal-unavailable");
        }

        return snapshot.Actions.SingleOrDefault(action => string.Equals(
            action.ActionOperationId,
            actionOperationId,
            StringComparison.OrdinalIgnoreCase));
    }

    private sealed class EmptyWorkflowAuthoritativeCompletionSource :
        IWorkflowAuthoritativeCompletionSource
    {
        internal static EmptyWorkflowAuthoritativeCompletionSource Instance { get; } = new();

        public event EventHandler<WorkflowAuthoritativeCompletionEventArgs>? CompletionObserved
        {
            add { }
            remove { }
        }
    }

    private sealed class EmptyWorkflowAutomationAuthorityChangeSource :
        IWorkflowAutomationAuthorityChangeSource
    {
        public event EventHandler<EventArgs>? AuthorityChanged
        {
            add { }
            remove { }
        }

        public void Dispose()
        {
        }
    }

    private static async Task<WorkflowRuleStoreSnapshot> EnsureRuleAsync(
        WorkflowRuleStore store,
        WorkflowRuleDefinition expected,
        CancellationToken cancellationToken)
    {
        var snapshot = await store.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (snapshot.ReadStatus == WorkflowRuleStoreReadStatus.Missing &&
            !snapshot.RequiresConservativeRecovery && snapshot.Rules.Count == 0)
        {
            snapshot = await store.SaveAsync([expected], cancellationToken).ConfigureAwait(false);
        }

        if (snapshot.ReadStatus != WorkflowRuleStoreReadStatus.Healthy ||
            snapshot.RequiresConservativeRecovery || snapshot.Generation <= 0 ||
            snapshot.Rules.Count != 1 || !RuleMatches(snapshot.Rules[0], expected))
        {
            throw new WorkflowLiveGateException("workflow-rule-authority-mismatch");
        }

        return snapshot;
    }

    private static async Task<AppSettings> EnsureSettingsAsync(
        SettingsService service,
        AppSettings expected,
        WorkflowRuleDefinition rule,
        CancellationToken cancellationToken)
    {
        var settings = await service.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (settings.ReadStatus == SettingsReadStatus.Missing &&
            !File.Exists(service.SettingsPath))
        {
            await service.SaveAsync(expected, cancellationToken).ConfigureAwait(false);
            settings = await service.LoadAsync(cancellationToken).ConfigureAwait(false);
        }

        if (settings.ReadStatus != SettingsReadStatus.Healthy ||
            settings.SettingsGeneration <= 0 || !SettingsMatch(settings, expected, rule))
        {
            throw new WorkflowLiveGateException("workflow-settings-authority-mismatch");
        }

        return settings;
    }

    private static async Task<ThreadSummary> ReadExactTargetAsync(
        AppServerClient appServer,
        LocalConversationHistoryReader localHistory,
        string targetThreadId,
        string expectedTurnId,
        CancellationToken cancellationToken)
    {
        var target = await appServer.ReadThreadForRecoveryAsync(targetThreadId, cancellationToken)
            .ConfigureAwait(false);
        var latestTask = appServer.ReadLatestTurnWithFullItemsAsync(targetThreadId, cancellationToken);
        var localTask = localHistory.ReadLatestTerminalEventAsync(
            targetThreadId,
            cancellationToken);
        await Task.WhenAll(latestTask, localTask).ConfigureAwait(false);
        var latest = LocalConversationHistoryReader.ReconcileLatestTurn(
            latestTask.Result,
            localTask.Result);
        Console.WriteLine(
            "WORKFLOW_LIVE_GATE_TARGET idMatch=" +
            string.Equals(target.Id, targetThreadId, StringComparison.OrdinalIgnoreCase) +
            " archived=" + target.IsArchived +
            " subAgent=" + target.IsSubAgent +
            " ephemeral=" + target.IsEphemeral +
            " runtime=" + GuardianLog.SanitizeIdentifier(target.RuntimeStatus) +
            " latest=" + (latest?.Id ?? "Missing") +
            " latestMatch=" + string.Equals(
                latest?.Id,
                expectedTurnId,
                StringComparison.OrdinalIgnoreCase) +
            " status=" + GuardianLog.SanitizeIdentifier(latest?.Status) +
            " confirmed=" + (latest?.HasConfirmedLocalTerminal ?? false) +
            " final=" + (latest?.HasFinalAssistantOutput ?? false) +
            " assistant=" + (latest?.HasAssistantOutput ?? false) +
            " completeEvidence=" + (latest?.HasCompleteItemEvidence ?? false));
        if (!string.Equals(target.Id, targetThreadId, StringComparison.OrdinalIgnoreCase))
        {
            throw new WorkflowLiveGateException("target-identity-mismatch");
        }

        if (target.IsArchived || target.IsSubAgent || target.IsEphemeral)
        {
            throw new WorkflowLiveGateException("target-not-active-root");
        }

        if (latest is null)
        {
            throw new WorkflowLiveGateException("target-latest-turn-missing");
        }

        if (!string.Equals(latest.Id, expectedTurnId, StringComparison.OrdinalIgnoreCase))
        {
            throw new WorkflowLiveGateException("target-latest-turn-mismatch");
        }

        if (!FollowUpQueuePlanner.IsNormalCompletion(latest))
        {
            throw new WorkflowLiveGateException("target-latest-turn-not-normal");
        }

        return target;
    }

    private static async Task<DesktopThreadOwnerStateSnapshot> ReadExactStockOwnerSnapshotAsync(
        DesktopIpcClient desktop,
        string targetThreadId,
        string expectedTurnId,
        CancellationToken cancellationToken)
    {
        var ownerState = await desktop.AcquireThreadOwnerStateGuardAsync(
                targetThreadId,
                cancellationToken)
            .ConfigureAwait(false);
        if (!ownerState.IsAvailable)
        {
            throw new WorkflowLiveGateException(
                "target-owner-state-" + GuardianLog.SanitizeIdentifier(ownerState.Status.ToString()));
        }

        await using var ownerGuard = ownerState.Guard!;
        if (FollowUpDispatchService.ValidateOwnerNormalCompletion(
                ownerGuard.Snapshot,
                expectedTurnId) is not null)
        {
            throw new WorkflowLiveGateException("target-owner-state-not-idle-completed");
        }

        if (!ownerGuard.IsCurrent)
        {
            throw new WorkflowLiveGateException("target-owner-state-changed");
        }

        Console.WriteLine(
            "WORKFLOW_LIVE_GATE_OWNER_STATE runtime=" +
            GuardianLog.SanitizeIdentifier(ownerGuard.Snapshot.RuntimeStatus) +
            " latest=" + ownerGuard.Snapshot.LatestTurnId +
            " latestStatus=" + GuardianLog.SanitizeIdentifier(ownerGuard.Snapshot.LatestTurnStatus) +
            " revision=" + ownerGuard.Snapshot.Revision.ToString(CultureInfo.InvariantCulture));
        return ownerGuard.Snapshot;
    }

    private static async Task<WorkflowActionOperationRecord> ReadExactActionAsync(
        WorkflowOperationJournal journal,
        string actionOperationId,
        CancellationToken cancellationToken)
    {
        var snapshot = await journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (snapshot.ReadStatus is not WorkflowJournalReadStatus.Healthy and not
                WorkflowJournalReadStatus.RecoveredFromBackup ||
            snapshot.RequiresConservativeRecovery)
        {
            throw new WorkflowLiveGateException("workflow-journal-unavailable");
        }

        return snapshot.Actions.SingleOrDefault(action => string.Equals(
                   action.ActionOperationId,
                   actionOperationId,
                   StringComparison.OrdinalIgnoreCase)) ??
               throw new WorkflowLiveGateException("workflow-action-missing");
    }

    private static async Task<FollowUpOperationRecord> ReadExactFollowUpAsync(
        FollowUpOperationJournal journal,
        string operationId,
        CancellationToken cancellationToken)
    {
        var snapshot = await journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (snapshot.ReadStatus is not FollowUpJournalReadStatus.Healthy and not
                FollowUpJournalReadStatus.RecoveredFromBackup ||
            snapshot.RequiresConservativeRecovery)
        {
            throw new WorkflowLiveGateException("follow-up-journal-unavailable");
        }

        return snapshot.Records.SingleOrDefault(record => string.Equals(
                   record.OperationId,
                   operationId,
                   StringComparison.OrdinalIgnoreCase)) ??
               throw new WorkflowLiveGateException("follow-up-operation-missing");
    }

    private static async Task<TurnSnapshot> WaitForReadbackAsync(
        AppServerClient appServer,
        string targetThreadId,
        string clientMessageId,
        string generatedTurnId,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + ReadbackTimeout;
        do
        {
            var matching = await appServer.FindRecentTurnByClientMessageIdAsync(
                    targetThreadId,
                    clientMessageId,
                    limit: 20,
                    cancellationToken)
                .ConfigureAwait(false);
            if (matching is not null && string.Equals(
                    matching.Id,
                    generatedTurnId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return matching;
            }

            await Task.Delay(ReadbackPollInterval, cancellationToken).ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);

        throw new WorkflowLiveGateException("authoritative-readback-missing");
    }

    private static bool RuleMatches(
        WorkflowRuleDefinition actual,
        WorkflowRuleDefinition expected) =>
        string.Equals(actual.RuleId, expected.RuleId, StringComparison.OrdinalIgnoreCase) &&
        actual.Revision == expected.Revision && actual.IsEnabled == expected.IsEnabled &&
        string.Equals(
            actual.DefinitionDigest,
            expected.DefinitionDigest,
            StringComparison.Ordinal);

    private static bool SettingsMatch(
        AppSettings actual,
        AppSettings expected,
        WorkflowRuleDefinition rule)
    {
        if (actual.MonitoringEnabled || !actual.MonitorOnly || actual.AutomaticRecoveryEnabled ||
            !actual.GlobalProtectionEnabled || actual.ThreadProtectionEnabled.Count != 1 ||
            !actual.ThreadProtectionEnabled.TryGetValue(rule.OwnerConversationId, out var protectedTarget) ||
            !protectedTarget ||
            actual.KeepAliveEnabled || actual.KeepAliveSentinelEnabled ||
            actual.MinimizeToTray || actual.StartWithWindows ||
            actual.IncludeSubAgents || actual.ProtectNewThreadsByDefault ||
            actual.ThreadEnabled.Count != 1 || actual.ThreadFollowUps.Count != 1 ||
            !actual.ThreadEnabled.TryGetValue(rule.OwnerConversationId, out var enabled) || !enabled ||
            !actual.ThreadFollowUps.TryGetValue(rule.OwnerConversationId, out var queue) ||
            !queue.IsEnabled || queue.Messages.Count != 1 ||
            !expected.ThreadFollowUps.TryGetValue(rule.OwnerConversationId, out var expectedQueue))
        {
            return false;
        }

        var message = queue.Messages[0];
        var expectedMessage = expectedQueue.Messages[0];
        return string.Equals(message.Id, expectedMessage.Id, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(message.Message, expectedMessage.Message, StringComparison.Ordinal) &&
               message.Attachments.Count == 0 && message.Trigger == FollowUpTriggerKind.ScheduledAt &&
               message.ScheduledAtUtc == expectedMessage.ScheduledAtUtc && message.IsEnabled &&
               message.UseWorkflowAutomation && message.WorkflowRuleRevision == rule.Revision &&
               string.Equals(
                   message.WorkflowRuleDigest,
                   rule.DefinitionDigest,
                   StringComparison.Ordinal) &&
               !message.RetryIndefinitely && message.MaximumErrorRetries == 0 && message.Order == 0;
    }

    private static void ValidateExecutionEnvironment(
        WorkflowExistingConversationLiveGateOptions options)
    {
        var temp = Environment.GetEnvironmentVariable("TEMP");
        var tmp = Environment.GetEnvironmentVariable("TMP");
        if (!IsStrictChild(temp, TempRoot) || !IsStrictChild(tmp, TempRoot) ||
            !string.Equals(
                Path.GetFullPath(temp!),
                Path.GetFullPath(tmp!),
                StringComparison.OrdinalIgnoreCase) ||
            !IsStrictChild(options.DataDirectory, DataRoot))
        {
            throw new WorkflowLiveGateException("write-environment-not-isolated");
        }

        var liveData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CodexGuardian");
        if (string.Equals(
                Path.GetFullPath(options.DataDirectory),
                Path.GetFullPath(liveData),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new WorkflowLiveGateException("live-data-directory-forbidden");
        }
    }

    private static void EnsureNoGuardianProcess()
    {
        using var current = Process.GetCurrentProcess();
        var conflicts = Process.GetProcessesByName("CodexGuardian")
            .Concat(Process.GetProcessesByName("CodexGuardian.Tests"))
            .Where(process => process.Id != current.Id)
            .ToArray();
        try
        {
            if (conflicts.Length != 0)
            {
                throw new WorkflowLiveGateException("guardian-or-test-process-conflict");
            }
        }
        finally
        {
            foreach (var process in conflicts)
            {
                process.Dispose();
            }
        }
    }

    private static string NormalizeDataDirectory(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value))
        {
            throw new ArgumentException("The workflow live gate data directory must be absolute.");
        }

        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(value))!;
        if (!IsStrictChild(normalized, DataRoot))
        {
            throw new ArgumentException("The workflow live gate data directory must be a D-drive child.");
        }

        return normalized;
    }

    private static bool IsStrictChild(string? candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        var normalizedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var relative = Path.GetRelativePath(normalizedRoot, normalizedCandidate);
        return relative.Length > 0 && !relative.StartsWith("..", StringComparison.Ordinal) &&
               !Path.IsPathFullyQualified(relative);
    }

    private static string NormalizeId(string value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private sealed class StrictComposerInterferenceGuard(
        IRecoveryInterferenceGuard inner) : IRecoveryInterferenceGuard
    {
        public async Task<RecoveryInterferenceSnapshot> CheckAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            var snapshot = await inner.CheckAsync(threadId, cancellationToken).ConfigureAwait(false);
            return snapshot.Status == RecoveryInterferenceStatus.Unknown
                ? snapshot with
                {
                    Status = RecoveryInterferenceStatus.Editing,
                    Detail = "The bounded live gate requires a verified clear Codex composer."
                }
                : snapshot;
        }

        public Task WaitForChangeAsync(
            long observedVersion,
            CancellationToken cancellationToken) =>
            inner.WaitForChangeAsync(observedVersion, cancellationToken);
    }

    private sealed class WorkflowLiveGateException(string code) : Exception
    {
        internal string Code { get; } = GuardianLog.SanitizeIdentifier(code);
    }
}
