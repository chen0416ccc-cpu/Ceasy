using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Reflection;

internal static class AutomaticRecoveryProtectionOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "automatic recovery requires global and current conversation protection",
            TestEffectiveAuthorityAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery policy snapshots isolate current protection authority",
            TestPolicySnapshotAsync,
            assert);
        await RunCaseAsync(
            "conversation protection initialization is disk-first preview-safe and user-stable",
            TestConversationProtectionInitializationAsync,
            assert);
        await RunCaseAsync(
            "production recovery requires current native package and composer proof",
            TestProductionDispatchProofsAsync,
            assert);
        await RunCaseAsync(
            "production recovery factory freezes live proofs and policy defaults",
            TestProductionRecoveryServiceFactoryAsync,
            assert);
        await RunCaseAsync(
            "active recovery incidents retain their frozen budget across default changes",
            TestFrozenIncidentAuthorityAsync,
            assert);
    }

    private static Task TestEffectiveAuthorityAsync()
    {
        var root = Thread("root");
        var settings = new AppSettings
        {
            GlobalProtectionEnabled = false,
            ProtectNewThreadsByDefault = true
        };
        settings.ThreadProtectionEnabled[root.Id] = true;
        Ensure(
            !GuardianEngine.ResolveThreadProtection(settings, root),
            "per-conversation protection bypassed the disabled global authority");
        Ensure(
            GuardianEngine.ResolveConversationProtection(settings, root),
            "global protection being off erased the saved conversation selection");

        settings.GlobalProtectionEnabled = true;
        Ensure(
            GuardianEngine.ResolveThreadProtection(settings, root),
            "the exact current per-conversation protection was not authorized");

        settings.ThreadProtectionEnabled[root.Id] = false;
        Ensure(
            !GuardianEngine.ResolveThreadProtection(settings, root),
            "an explicit per-conversation pause was replaced by the new-thread default");

        settings.ThreadProtectionEnabled.Clear();
        settings.ProtectNewThreadsByDefault = true;
        Ensure(
            !GuardianEngine.ResolveThreadProtection(settings, root),
            "a missing first-discovery entry was dynamically authorized by the mutable default");

        settings.ProtectNewThreadsByDefault = false;
        settings.ThreadEnabled[root.Id] = true;
        Ensure(
            !GuardianEngine.ResolveThreadProtection(settings, root),
            "legacy ThreadEnabled regained automatic recovery authority");

        settings.ThreadProtectionEnabled[root.Id] = true;
        settings.GlobalProtectionEnabled = true;
        Ensure(
            !GuardianEngine.ResolveThreadProtection(settings, root with { IsArchived = true }) &&
            !GuardianEngine.ResolveThreadProtection(settings, root with { IsEphemeral = true }) &&
            !GuardianEngine.ResolveThreadProtection(settings, root with { IsSubAgent = true }),
            "archived, ephemeral, or filtered subagent state bypassed recovery scope");

        settings.IncludeSubAgents = true;
        Ensure(
            GuardianEngine.ResolveThreadProtection(settings, root with { IsSubAgent = true }),
            "an explicitly included and protected subagent remained outside recovery scope");
        return Task.CompletedTask;
    }

    private static Task TestPolicySnapshotAsync()
    {
        var root = Thread("snapshot");
        var settings = new AppSettings
        {
            MonitorOnly = true,
            GlobalProtectionEnabled = true,
            ProtectNewThreadsByDefault = false
        };
        settings.ThreadEnabled[root.Id] = false;
        settings.ThreadProtectionEnabled[root.Id] = true;
        settings.ThreadFollowUps[root.Id] = new ThreadFollowUpSettings
        {
            Messages =
            [
                new FollowUpMessageDefinition
                {
                    Id = Guid.NewGuid().ToString("D"),
                    Message = "offline scheduled authority",
                    Trigger = FollowUpTriggerKind.ScheduledAt,
                    ScheduledAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
                    Order = 0
                }
            ]
        };

        var createSnapshot = typeof(GuardianEngine).GetMethod(
            "CreatePolicySnapshot",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingMethodException(nameof(GuardianEngine), "CreatePolicySnapshot");
        var snapshot = createSnapshot.Invoke(null, [7L, settings])
            ?? throw new InvalidOperationException("the recovery policy snapshot was null");
        var snapshotType = snapshot.GetType();
        var protectionProperty = snapshotType.GetProperty("ThreadProtectionEnabled")
            ?? throw new MissingMemberException(snapshotType.Name, "ThreadProtectionEnabled");
        var protection = protectionProperty.GetValue(snapshot) as IReadOnlyDictionary<string, bool>
            ?? throw new InvalidOperationException("the policy snapshot protection map was unavailable");
        var globalProperty = snapshotType.GetProperty("GlobalProtectionEnabled")
            ?? throw new MissingMemberException(snapshotType.Name, "GlobalProtectionEnabled");
        var automaticProperty = snapshotType.GetProperty("AutomaticRecoveryEnabled")
            ?? throw new MissingMemberException(snapshotType.Name, "AutomaticRecoveryEnabled");
        var captureSchedulable = typeof(GuardianEngine).GetMethod(
            "CaptureSchedulableFollowUps",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingMethodException(nameof(GuardianEngine), "CaptureSchedulableFollowUps");
        IReadOnlyDictionary<string, ThreadFollowUpSettings> CaptureSchedulable(object candidate) =>
            captureSchedulable.Invoke(null, [candidate]) as
                IReadOnlyDictionary<string, ThreadFollowUpSettings>
            ?? throw new InvalidOperationException("the schedulable follow-up map was unavailable");

        settings.GlobalProtectionEnabled = false;
        settings.ThreadProtectionEnabled[root.Id] = false;
        var initialSchedulable = CaptureSchedulable(snapshot);
        Ensure(
            globalProperty.GetValue(snapshot) is true &&
            automaticProperty.GetValue(snapshot) is false &&
            protection.TryGetValue(root.Id, out var snapshotted) && snapshotted &&
            initialSchedulable.ContainsKey(root.Id) &&
            snapshotType.GetProperty("ThreadEnabled") is null,
            "the runtime policy snapshot retained mutable or legacy recovery authority");

        settings.ThreadProtectionEnabled[root.Id] = true;
        var globalOffSnapshot = createSnapshot.Invoke(null, [8L, settings])
            ?? throw new InvalidOperationException("the global-off policy snapshot was null");
        var globalOffSchedulable = CaptureSchedulable(globalOffSnapshot);
        settings.GlobalProtectionEnabled = true;
        settings.ThreadProtectionEnabled[root.Id] = false;
        var threadOffSnapshot = createSnapshot.Invoke(null, [9L, settings])
            ?? throw new InvalidOperationException("the thread-off policy snapshot was null");
        var threadOffSchedulable = CaptureSchedulable(threadOffSnapshot);
        Ensure(
            globalOffSchedulable.Count == 0 &&
            threadOffSchedulable.Count == 0 &&
            FollowUpQueuePlanner.FindNextScheduledAtUtc(globalOffSchedulable, []) is null &&
            FollowUpQueuePlanner.FindNextScheduledAtUtc(threadOffSchedulable, []) is null,
            "disabled protection retained a past scheduled deadline and could create a hot wake loop");

        var engineSource = File.ReadAllText(
            Path.Combine(FindGuardianSourceRoot(), "Services", "GuardianEngine.cs"));
        var disabledBranch = engineSource.IndexOf(
            "if (!recoveryAuthorized)",
            StringComparison.Ordinal);
        var reconcileCall = engineSource.IndexOf(
            "ReconcileExistingOperationAsync",
            StringComparison.Ordinal);
        Ensure(
            disabledBranch >= 0 && reconcileCall > disabledBranch &&
            engineSource.Contains("policy.AutomaticRecoveryEnabled", StringComparison.Ordinal) &&
            engineSource.Contains("policy.GlobalProtectionEnabled", StringComparison.Ordinal) &&
            engineSource.Contains(
                "policy.ThreadProtectionEnabled.TryGetValue",
                StringComparison.Ordinal),
            "protection-off recovery did not retain a bounded existing-operation reconciliation path");
        return Task.CompletedTask;
    }

    private static async Task TestProductionDispatchProofsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var fallbackCalls = 0;
        DesktopUserActivityResult Fallback()
        {
            fallbackCalls++;
            return new DesktopUserActivityResult(
                DesktopUserActivityStatus.Idle,
                "Windows idle must not grant production recovery.");
        }

        var clear = RecoveryService.ResolveDispatchActivity(
            new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Clear,
                "Composer clear.",
                false,
                now),
            Fallback,
            now,
            requireExplicitClear: true);
        var unknown = RecoveryService.ResolveDispatchActivity(
            new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Unknown,
                "Composer unknown.",
                false,
                now),
            Fallback,
            now,
            requireExplicitClear: true);
        var stale = RecoveryService.ResolveDispatchActivity(
            new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Clear,
                "Composer stale.",
                false,
                now - RecoveryService.DispatchObservationMaxAge - TimeSpan.FromMilliseconds(1)),
            Fallback,
            now,
            requireExplicitClear: true);
        var missing = RecoveryService.ResolveDispatchActivity(
            null,
            Fallback,
            now,
            requireExplicitClear: true);
        Ensure(
            clear.Status == DesktopUserActivityStatus.Idle &&
            unknown.Status == DesktopUserActivityStatus.Unknown &&
            stale.Status == DesktopUserActivityStatus.Unknown &&
            missing.Status == DesktopUserActivityStatus.Unknown &&
            fallbackCalls == 0,
            "an unknown stale or missing composer observation fell back to Windows idle");

        var coordinator = new ThreadActionCoordinator();
        var threadId = Guid.NewGuid().ToString("D");
        await using (var first = await coordinator.AcquireAsync(threadId, CancellationToken.None))
        {
            var blocked = coordinator.AcquireAsync(threadId, CancellationToken.None).AsTask();
            await Task.Delay(40);
            Ensure(
                !blocked.IsCompleted,
                "two unattended actions entered the same conversation owner-send window");
            await first.DisposeAsync();
            await using var second = await blocked.WaitAsync(TimeSpan.FromSeconds(1));
        }

        var sourceRoot = FindGuardianSourceRoot();
        var appSource = File.ReadAllText(Path.Combine(sourceRoot, "App.xaml.cs"));
        var recoverySource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "Services",
            "RecoveryService.cs"));
        var desktopSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "Services",
            "DesktopIpcClient.cs"));
        var factorySource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "Services",
            "ProductionRecoveryServiceFactory.cs"));
        Ensure(
            appSource.Contains(
                "ProductionRecoveryServiceFactory.CreateLive(",
                StringComparison.Ordinal) &&
            appSource.Contains(
                "structuredCapabilities!",
                StringComparison.Ordinal) &&
            appSource.Contains(
                "threadActions!",
                StringComparison.Ordinal) &&
            !appSource.Contains(
                "requireCurrentNativeChannel: launchOptions.AllowsLiveIntegration",
                StringComparison.Ordinal) &&
            !appSource.Contains(
                "requireExplicitInterferenceClear: launchOptions.AllowsLiveIntegration",
                StringComparison.Ordinal) &&
            factorySource.Contains("requireCurrentNativeChannel: true", StringComparison.Ordinal) &&
            factorySource.Contains("requireExplicitInterferenceClear: true", StringComparison.Ordinal) &&
            factorySource.Contains(
                "ArgumentNullException.ThrowIfNull(semanticCapabilities);",
                StringComparison.Ordinal) &&
            factorySource.Contains(
                "ArgumentNullException.ThrowIfNull(threadActions);",
                StringComparison.Ordinal) &&
            factorySource.Contains(
                "defaultCountingMode: settings.RecoveryCountingMode",
                StringComparison.Ordinal) &&
            factorySource.Contains(
                "defaultMaximumAttempts: settings.MaximumRecoveryAttempts",
                StringComparison.Ordinal) &&
            factorySource.Contains(
                "defaultUnlimitedAttempts: settings.UnlimitedRecoveryAttempts",
                StringComparison.Ordinal) &&
            recoverySource.Contains("ValidateTransportSemanticLeaseAsync", StringComparison.Ordinal) &&
            recoverySource.Contains("_desktop.IsNativeChannelAvailable", StringComparison.Ordinal) &&
            desktopSource.Contains("native-channel-unavailable", StringComparison.Ordinal),
            "the production composition no longer binds native package and composer proof gates");
    }

    private static async Task TestProductionRecoveryServiceFactoryAsync()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.GetFullPath(Path.Combine(
            parent,
            "production-recovery-factory-" + Guid.NewGuid().ToString("N")));
        Ensure(
            root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase),
            "production recovery factory tests use D-drive data");
        Directory.CreateDirectory(root);
        try
        {
            using var log = new GuardianLog(root);
            await using var appServer = new AppServerClient(new CodexCliLocator(), log);
            await using var desktop = new DesktopIpcClient(log);
            var ownerActivator = new DesktopThreadOwnerActivator(desktop, log);
            var journal = new RecoveryOperationJournal(root);
            var guard = new ClearInterferenceGuard();
            var semanticCapabilities = new PolicyChangingCapabilityProvider();
            var threadActions = new ThreadActionCoordinator();
            var settings = new AppSettings
            {
                RecoveryCountingMode = RecoveryCountingMode.SharedIncidentBudget,
                MaximumRecoveryAttempts = 37,
                UnlimitedRecoveryAttempts = true
            };
            var recovery = ProductionRecoveryServiceFactory.CreateLive(
                appServer,
                desktop,
                ownerActivator,
                journal,
                log,
                guard,
                semanticCapabilities,
                replayAuthority: null,
                threadActions,
                settings);

            var instanceFields = BindingFlags.Instance | BindingFlags.NonPublic;
            object? Field(string name) =>
                typeof(RecoveryService).GetField(name, instanceFields)?.GetValue(recovery);
            Ensure(
                ReferenceEquals(Field("_interferenceGuard"), guard) &&
                ReferenceEquals(Field("_transportSemanticCapabilities"), semanticCapabilities) &&
                ReferenceEquals(Field("_threadActions"), threadActions) &&
                Field("_structuredInputReplayAuthority") is null &&
                Field("_requireCurrentNativeChannel") is true &&
                Field("_requireExplicitInterferenceClear") is true &&
                Field("_defaultCountingMode") is RecoveryCountingMode.SharedIncidentBudget &&
                Field("_defaultMaximumAttempts") is 37 &&
                Field("_defaultUnlimitedAttempts") is true,
                "the production recovery factory did not freeze its live dependencies and policy defaults");

            var rejectedMissingGuard = false;
            try
            {
                _ = ProductionRecoveryServiceFactory.CreateLive(
                    appServer,
                    desktop,
                    ownerActivator,
                    journal,
                    log,
                    null!,
                    semanticCapabilities,
                    replayAuthority: null,
                    threadActions,
                    settings);
            }
            catch (ArgumentNullException exception)
                when (string.Equals(
                    exception.ParamName,
                    "interferenceGuard",
                    StringComparison.Ordinal))
            {
                rejectedMissingGuard = true;
            }

            Ensure(
                rejectedMissingGuard && !appServer.IsConnected && !desktop.IsConnected,
                "the production recovery factory accepted a missing live proof or opened transport");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task TestConversationProtectionInitializationAsync()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.Combine(parent, "protection-init-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var log = new GuardianLog(root);
            var settings = new AppSettings();
            var legacyConversationId = Guid.NewGuid().ToString("D");
            var userConversationId = Guid.NewGuid().ToString("D");
            settings.ThreadEnabled[legacyConversationId] = true;
            await using (var engine = CreateEngine(settings, root, log, previewIsolationMode: false))
            {
                Ensure(
                    engine.TryInitializeThreadProtection(legacyConversationId, defaultEnabled: false) &&
                    settings.ThreadProtectionEnabled[legacyConversationId] &&
                    settings.ThreadEnabled[legacyConversationId],
                    "first discovery did not copy the legacy selection into the new authority map");
                Ensure(
                    engine.TryInitializeThreadProtection(userConversationId, defaultEnabled: false) &&
                    !settings.ThreadProtectionEnabled[userConversationId],
                    "first discovery did not commit the configured default exactly once");
                engine.SetThreadEnabled(userConversationId, enabled: true);
                Ensure(
                    !engine.TryInitializeThreadProtection(userConversationId, defaultEnabled: false) &&
                    settings.ThreadProtectionEnabled[userConversationId] &&
                    settings.ThreadEnabled[userConversationId],
                    "a later initializer overwrote an explicit user selection");
            }

            var previewSettings = new AppSettings();
            var previewConversationId = Guid.NewGuid().ToString("D");
            await using (var previewEngine = CreateEngine(
                             previewSettings,
                             root,
                             log,
                             previewIsolationMode: true))
            {
                Ensure(
                    !previewEngine.TryInitializeThreadProtection(
                        previewConversationId,
                        defaultEnabled: true) &&
                    previewSettings.ThreadProtectionEnabled.Count == 0 &&
                    previewSettings.ThreadEnabled.Count == 0,
                    "safe preview initialized or persisted conversation protection");
            }

            var viewModelSource = File.ReadAllText(Path.Combine(
                FindGuardianSourceRoot(),
                "ViewModels",
                "MainViewModel.cs"));
            var mainWindowSource = File.ReadAllText(Path.Combine(
                FindGuardianSourceRoot(),
                "MainWindow.xaml"));
            var queueStart = viewModelSource.IndexOf(
                "private void QueueConversationProtectionInitialization",
                StringComparison.Ordinal);
            var previewGuard = viewModelSource.IndexOf(
                "if (_previewIsolationMode || !CanEnableConversationProtection)",
                queueStart,
                StringComparison.Ordinal);
            var durableInitialization = viewModelSource.IndexOf(
                ".InitializeConversationProtectionDefaultsAsync(",
                queueStart,
                StringComparison.Ordinal);
            var enginePublication = viewModelSource.IndexOf(
                "if (!_engine.TryInitializeThreadProtection(conversationId, selected))",
                durableInitialization,
                StringComparison.Ordinal);
            Ensure(
                queueStart >= 0 && previewGuard > queueStart &&
                durableInitialization > previewGuard &&
                enginePublication > durableInitialization &&
                mainWindowSource.Contains(
                    "AutomationProperties.AutomationId=\"ConversationProtectionToggle\"",
                    StringComparison.Ordinal) &&
                mainWindowSource.Contains(
                    "IsChecked=\"{Binding SelectedTask.IsEnabled, Mode=TwoWay}\"",
                    StringComparison.Ordinal) &&
                mainWindowSource.Contains(
                    "IsEnabled=\"{Binding SelectedTask.CanToggleProtection}\"",
                    StringComparison.Ordinal),
                "conversation protection is not disk-first or is missing from the selected-task UI");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task TestFrozenIncidentAuthorityAsync()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.GetFullPath(Path.Combine(
            parent,
            "frozen-recovery-policy-" + Guid.NewGuid().ToString("N")));
        Ensure(
            root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase),
            "frozen recovery policy tests use D-drive data");
        Directory.CreateDirectory(root);
        try
        {
            using var log = new GuardianLog(root);
            var thread = Thread("frozen-policy");
            var failedTurn = new TurnSnapshot(
                Guid.NewGuid().ToString("D"),
                "failed",
                "temporary provider failure",
                "rate_limit",
                429,
                "retry the exact request",
                HasAttachments: false,
                HasAssistantOutput: false,
                HasWorkOutput: false,
                OutputFingerprint: "frozen-policy",
                StartedAt: 1,
                CompletedAt: 2,
                HasConfirmedLocalTerminal: true,
                UserMessageClientIds: [Guid.NewGuid().ToString("D")],
                HasUserMessage: true,
                HasReasoningOutput: true,
                HasCompleteItemEvidence: true,
                IsSingleTextUserInput: true);
            var classifier = new RecoveryClassifier();
            var decision = classifier.Classify(failedTurn);
            Ensure(
                decision is { Action: RecoveryActionKind.SendContinue, IsTransient: true },
                "the frozen-policy fixture was not classified as a recoverable continuation");

            var settings = new AppSettings
            {
                AutomaticRecoveryEnabled = true,
                MonitorOnly = false,
                GlobalProtectionEnabled = true,
                ProtectNewThreadsByDefault = false,
                MaximumRecoveryAttempts = 1,
                MaximumAttemptsPerFailure = 1,
                UnlimitedRecoveryAttempts = false,
                RecoveryCountingMode = RecoveryCountingMode.PerFailedTurn,
                BaseBackoffSeconds = 0,
                MaximumBackoffSeconds = 0
            };
            settings.ThreadEnabled[thread.Id] = true;
            settings.ThreadProtectionEnabled[thread.Id] = true;

            var journal = new RecoveryOperationJournal(root);
            var operationId = AppServerClient.CreateRecoveryMessageId(
                thread.Id,
                failedTurn.Id,
                decision.Action);
            var dispatchMessage = SettingsService.NormalizeContinueMessage(settings.ContinueMessage);
            var incidentPolicy = new RecoveryIncidentPolicy(
                Guid.NewGuid().ToString("D"),
                failedTurn.Id,
                ParentOperationId: null,
                RecoveryCountingMode.PerFailedTurn,
                MaximumAttempts: 7,
                UnlimitedAttempts: false,
                PolicyVersion: 11,
                RecoveryService.BuildFailureSignature(failedTurn, decision),
                NoProgressCount: 0);
            var prepared = await journal.GetOrCreateAsync(
                operationId,
                thread.Id,
                failedTurn.Id,
                decision.Action,
                RecoveryService.BuildRecoveryPayloadHash(decision.Action, dispatchMessage),
                operationId,
                incidentPolicy);
            var dispatching = await journal.TryTransitionAsync(
                thread.Id,
                failedTurn.Id,
                RecoveryOperationState.Prepared,
                RecoveryOperationState.Dispatching,
                operationId);
            var retryable = await journal.TryTransitionAsync(
                thread.Id,
                failedTurn.Id,
                RecoveryOperationState.Dispatching,
                RecoveryOperationState.Retryable,
                operationId);
            Ensure(
                prepared.Created && dispatching.Changed && retryable.Changed &&
                retryable.Record is { AttemptCount: 1, MaximumAttempts: 7 },
                "the frozen-policy fixture did not persist its first retryable dispatch attempt");

            var snapshot = await journal.ReadAsync();
            var lineage = await journal.ReconcileCurrentTurnAsync(
                thread.Id,
                failedTurn.Id,
                failedTurn.UserMessageClientIds,
                closeRecoverySuccessor: false,
                CancellationToken.None);
            var resolved = RecoveryService.ResolveIncidentPolicySnapshot(
                snapshot.Records,
                thread.Id,
                failedTurn,
                decision,
                lineage,
                policyVersion: 99,
                defaultCountingMode: RecoveryCountingMode.PerFailedTurn,
                defaultMaximumAttempts: 2,
                defaultUnlimitedAttempts: false);
            var persisted = await journal.FindAsync(thread.Id, failedTurn.Id);
            Ensure(
                resolved is
                {
                    MaximumAttempts: 7,
                    UnlimitedAttempts: false,
                    PolicyVersion: 11,
                    CountingMode: RecoveryCountingMode.PerFailedTurn
                } &&
                persisted is
                {
                    State: RecoveryOperationState.Retryable,
                    AttemptCount: 1,
                    MaximumAttempts: 7,
                    UnlimitedAttempts: false
                },
                "a later default policy replaced the frozen budget of an active recovery incident");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static GuardianEngine CreateEngine(
        AppSettings settings,
        string root,
        GuardianLog log,
        bool previewIsolationMode)
    {
        var appServer = new AppServerClient(new CodexCliLocator(), log);
        var desktop = new DesktopIpcClient(log);
        return new GuardianEngine(
            settings,
            appServer,
            desktop,
            new RecoveryService(
                appServer,
                desktop,
                new DesktopThreadOwnerActivator(desktop, log),
                new RecoveryOperationJournal(root),
                log),
            new RecoveryClassifier(),
            new LocalConversationHistoryReader(Path.Combine(root, "sessions")),
            log,
            previewIsolationMode: previewIsolationMode);
    }

    private static string FindGuardianSourceRoot()
    {
        var currentDirectoryCandidate = Path.Combine(
            Environment.CurrentDirectory,
            "work",
            "CodexGuardian");
        if (File.Exists(Path.Combine(
                currentDirectoryCandidate,
                "Services",
                "GuardianEngine.cs")))
        {
            return currentDirectoryCandidate;
        }

        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "work", "CodexGuardian");
            if (File.Exists(Path.Combine(candidate, "Services", "GuardianEngine.cs")))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("The CodexGuardian source root was not found.");
    }

    private static ThreadSummary Thread(string suffix) =>
        new(
            Guid.NewGuid().ToString("D"),
            "Protection " + suffix,
            string.Empty,
            @"D:\Workspace",
            "appServer",
            CreatedAt: 1,
            UpdatedAt: 2,
            IsSubAgent: false,
            IsEphemeral: false);

    private sealed class PolicyChangingCapabilityProvider : IDesktopStructuredInputCapabilityProvider
    {
        private static readonly DesktopStructuredInputCapabilities Supported = new(
            StructuredInputCapabilityState.Supported,
            new HashSet<string>(StringComparer.Ordinal) { "text" },
            SupportsAttachmentOnly: false,
            MaximumAttachmentCount: 0,
            MaximumBytesPerFile: 1,
            MaximumBytesPerPayload: 1,
            Epoch: 1,
            SemanticFingerprint: new string('A', 64),
            Detail: "Offline frozen-policy capability fixture.");

        internal Action? OnFirstRead { get; set; }

        internal int ReadCount { get; private set; }

        public Task<DesktopStructuredInputCapabilities> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCount++;
            if (ReadCount == 1)
            {
                OnFirstRead?.Invoke();
            }

            return Task.FromResult(Supported);
        }
    }

    private sealed class ClearInterferenceGuard : IRecoveryInterferenceGuard
    {
        public Task<RecoveryInterferenceSnapshot> CheckAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Clear,
                "Offline factory fixture.",
                HasFocusedDraft: false,
                DateTimeOffset.UtcNow));
        }

        public Task WaitForChangeAsync(
            long observedVersion,
            CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
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
