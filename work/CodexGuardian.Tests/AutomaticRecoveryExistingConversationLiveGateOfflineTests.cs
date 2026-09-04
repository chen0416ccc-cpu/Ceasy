using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

internal static class AutomaticRecoveryExistingConversationLiveGateOfflineTests
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "automatic recovery live gate requires one exact two-phase argument matrix",
            TestArgumentMatrixAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery live gate freezes deterministic target and payload authority",
            TestPlanAuthorityAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery live gate freezes one healthy settings generation and byte hash",
            TestSettingsPersistenceAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery live gate manifest is canonical tamper-evident and one-shot",
            TestManifestStoreAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery live gate policy revokes settings and authorization drift",
            TestPolicyAuthorityAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery live gate execution lease is exclusive and reusable",
            TestExecutionLeaseAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery live gate stays tests-only prepare-safe and owner-bound",
            TestSourceContractAsync,
            assert);
    }

    private static Task TestArgumentMatrixAsync()
    {
        var gateId = Guid.NewGuid().ToString("D");
        var targetId = Guid.NewGuid().ToString("D");
        var failedTurnId = Guid.NewGuid().ToString("D");
        var restoreId = Guid.NewGuid().ToString("D");
        var dataDirectory = Path.Combine(
            AutomaticRecoveryExistingConversationLiveGate.DataRoot,
            "offline-gates",
            gateId);
        var prepareArguments = new[]
        {
            AutomaticRecoveryExistingConversationLiveGate.GateArgument,
            AutomaticRecoveryExistingConversationLiveGate.PrepareArgument,
            AutomaticRecoveryExistingConversationLiveGate.GateIdArgument,
            gateId,
            AutomaticRecoveryExistingConversationLiveGate.TargetArgument,
            targetId,
            AutomaticRecoveryExistingConversationLiveGate.ExpectedTurnArgument,
            failedTurnId,
            AutomaticRecoveryExistingConversationLiveGate.RestoreArgument,
            restoreId,
            AutomaticRecoveryExistingConversationLiveGate.DataDirectoryArgument,
            dataDirectory
        };
        var prepared = AutomaticRecoveryExistingConversationLiveGate.Parse(prepareArguments);
        var digest = new string('A', 64);
        var confirmArguments = prepareArguments
            .Where(argument => !string.Equals(
                argument,
                AutomaticRecoveryExistingConversationLiveGate.PrepareArgument,
                StringComparison.OrdinalIgnoreCase))
            .Append(AutomaticRecoveryExistingConversationLiveGate.ConfirmArgument)
            .Append(AutomaticRecoveryExistingConversationLiveGate.AuthorizationDigestArgument)
            .Append(digest)
            .ToArray();
        var confirmed = AutomaticRecoveryExistingConversationLiveGate.Parse(confirmArguments);

        Ensure(
            prepared.PrepareOnly && prepared.AuthorizationDigest is null &&
            !confirmed.PrepareOnly && confirmed.AuthorizationDigest == digest &&
            prepared.GateId == gateId && prepared.TargetThreadId == targetId &&
            prepared.ExpectedFailedTurnId == failedTurnId && prepared.RestoreThreadId == restoreId &&
            prepared.DataDirectory == Path.GetFullPath(dataDirectory),
            "the exact prepare and confirm argument matrices did not normalize deterministically");
        Ensure(
            Throws<ArgumentException>(() => AutomaticRecoveryExistingConversationLiveGate.Parse(
                prepareArguments.Append(AutomaticRecoveryExistingConversationLiveGate.PrepareArgument).ToArray())) &&
            Throws<ArgumentException>(() => AutomaticRecoveryExistingConversationLiveGate.Parse(
                prepareArguments.Append(AutomaticRecoveryExistingConversationLiveGate.AuthorizationDigestArgument)
                    .Append(digest).ToArray())) &&
            Throws<ArgumentException>(() => AutomaticRecoveryExistingConversationLiveGate.Parse(
                confirmArguments.Where(value => value != digest).ToArray())) &&
            Throws<ArgumentException>(() => AutomaticRecoveryExistingConversationLiveGate.Parse(
                prepareArguments.Select(value => value == restoreId ? targetId : value).ToArray())) &&
            Throws<ArgumentException>(() => AutomaticRecoveryExistingConversationLiveGate.Parse(
                prepareArguments.Select(value => value == dataDirectory
                    ? Path.Combine(AutomaticRecoveryExistingConversationLiveGate.DataRoot, "wrong-leaf")
                    : value).ToArray())) &&
            Throws<ArgumentException>(() => AutomaticRecoveryExistingConversationLiveGate.Parse(
                prepareArguments.Append("--unknown-gate-value").ToArray())),
            "an ambiguous duplicate unbound or unsafe automatic-recovery gate argument was accepted");
        return Task.CompletedTask;
    }

    private static Task TestPlanAuthorityAsync()
    {
        var fixture = CreatePlanFixture();
        var plan = AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
            fixture.Options,
            fixture.Thread,
            fixture.Turn,
            fixture.Decision,
            fixture.Settings,
            fixture.SettingsSha256,
            fixture.PreparedAtUtc);
        var repeated = AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
            fixture.Options,
            fixture.Thread,
            fixture.Turn,
            fixture.Decision,
            fixture.Settings,
            fixture.SettingsSha256,
            fixture.PreparedAtUtc);
        Ensure(
            plan == repeated && plan.OperationId == plan.ClientMessageId &&
            plan.OperationId == AppServerClient.CreateRecoveryMessageId(
                fixture.Thread.Id,
                fixture.Turn.Id,
                fixture.Decision.Action) &&
            plan.PayloadDigest == RecoveryService.BuildRecoveryPayloadHash(
                fixture.Decision.Action,
                RecoveryClassifier.NormalizeRecoveryInput(fixture.Turn.UserText)) &&
            plan.ExpiresAtUtc > plan.PreparedAtUtc &&
            AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(plan).Length == 64,
            "the recovery plan did not freeze deterministic operation payload policy and expiry identity");

        fixture.Settings.GlobalProtectionEnabled = false;
        Ensure(
            Throws<InvalidOperationException>(() => AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
                fixture.Options,
                fixture.Thread,
                fixture.Turn,
                fixture.Decision,
                fixture.Settings,
                fixture.SettingsSha256,
                fixture.PreparedAtUtc)),
            "global protection being off still produced a live recovery authorization plan");
        fixture.Settings.GlobalProtectionEnabled = true;
        fixture.Settings.ThreadProtectionEnabled[fixture.Thread.Id] = false;
        Ensure(
            Throws<InvalidOperationException>(() => AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
                fixture.Options,
                fixture.Thread,
                fixture.Turn,
                fixture.Decision,
                fixture.Settings,
                fixture.SettingsSha256,
                fixture.PreparedAtUtc)),
            "an unprotected target still produced a live recovery authorization plan");
        fixture.Settings.ThreadProtectionEnabled[fixture.Thread.Id] = true;
        Ensure(
            Throws<InvalidOperationException>(() => AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
                fixture.Options,
                fixture.Thread,
                fixture.Turn,
                fixture.Decision with { Action = RecoveryActionKind.SendContinue },
                fixture.Settings,
                fixture.SettingsSha256,
                fixture.PreparedAtUtc)),
            "a caller-supplied recovery action bypassed classification of the exact failed turn");
        return Task.CompletedTask;
    }

    private static async Task TestSettingsPersistenceAsync()
    {
        var root = CreateRoot("settings");
        try
        {
            var targetId = Guid.NewGuid().ToString("D");
            var settings = new AppSettings
            {
                MonitoringEnabled = false,
                MonitorOnly = false,
                AutomaticRecoveryEnabled = true,
                GlobalProtectionEnabled = true,
                IncludeSubAgents = false,
                ProtectNewThreadsByDefault = false,
                MinimizeToTray = false,
                StartWithWindows = false
            };
            settings.ThreadEnabled[targetId] = true;
            settings.ThreadProtectionEnabled[targetId] = true;
            var service = new SettingsService(root, monitoringEnabledAfterNormalization: false);
            await service.SaveAsync(settings);
            var first = await service.LoadAsync();
            var firstHash = Convert.ToHexString(SHA256.HashData(
                await File.ReadAllBytesAsync(service.SettingsPath)));
            var second = await service.LoadAsync();
            var secondHash = Convert.ToHexString(SHA256.HashData(
                await File.ReadAllBytesAsync(service.SettingsPath)));

            Ensure(
                first.ReadStatus == SettingsReadStatus.Healthy &&
                second.ReadStatus == SettingsReadStatus.Healthy &&
                first.SettingsGeneration == 1 && second.SettingsGeneration == 1 &&
                first.PreviousSettingsGeneration == 1 && second.PreviousSettingsGeneration == 1 &&
                firstHash == secondHash && firstHash.Length == 64 &&
                first.AutomaticRecoveryEnabled &&
                first.GlobalProtectionEnabled && !first.MonitorOnly && !first.IncludeSubAgents &&
                first.ThreadProtectionEnabled.TryGetValue(targetId, out var selected) && selected,
                "the isolated gate settings changed generation bytes or exact recovery authority after reload");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestManifestStoreAsync()
    {
        var root = CreateRoot("manifest");
        try
        {
            var fixture = CreatePlanFixture(root) with
            {
                PreparedAtUtc = DateTimeOffset.UtcNow
            };
            var plan = AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
                fixture.Options,
                fixture.Thread,
                fixture.Turn,
                fixture.Decision,
                fixture.Settings,
                fixture.SettingsSha256,
                fixture.PreparedAtUtc);
            var digest = AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(plan);
            var store = new AutomaticRecoveryLiveGateManifestStore(root);
            var prepared = store.CreatePrepared(plan);
            var raw = await File.ReadAllBytesAsync(store.ManifestPath);
            Ensure(
                prepared is
                {
                    State: AutomaticRecoveryLiveGateAuthorizationState.Prepared,
                    Generation: 1,
                    NewTurnId: null
                } &&
                raw.Length > 0 && raw[^1] == (byte)'\n' && store.Read() == prepared,
                "the prepared live-gate manifest was not canonical or round-trippable");

            var outcomes = new ConcurrentBag<bool>();
            await Task.WhenAll(Enumerable.Range(0, 2).Select(index => Task.Run(() =>
            {
                _ = index;
                try
                {
                    _ = new AutomaticRecoveryLiveGateManifestStore(root).Transition(
                        AutomaticRecoveryLiveGateAuthorizationState.Prepared,
                        AutomaticRecoveryLiveGateAuthorizationState.Armed,
                        digest);
                    outcomes.Add(true);
                }
                catch (Exception exception) when (
                    exception is IOException or InvalidOperationException)
                {
                    outcomes.Add(false);
                }
            })));
            Ensure(
                outcomes.Count(value => value) == 1 && outcomes.Count(value => !value) == 1 &&
                store.Read() is
                {
                    State: AutomaticRecoveryLiveGateAuthorizationState.Armed,
                    Generation: 2
                },
                "concurrent confirmation attempts armed the same authorization more than once");

            var newTurnId = Guid.NewGuid().ToString("D");
            var confirmed = store.Transition(
                AutomaticRecoveryLiveGateAuthorizationState.Armed,
                AutomaticRecoveryLiveGateAuthorizationState.Confirmed,
                digest,
                newTurnId);
            Ensure(
                confirmed is
                {
                    State: AutomaticRecoveryLiveGateAuthorizationState.Confirmed,
                    Generation: 3,
                    NewTurnId: not null
                } &&
                confirmed.NewTurnId == newTurnId &&
                Throws<InvalidOperationException>(() => store.Transition(
                    AutomaticRecoveryLiveGateAuthorizationState.Prepared,
                    AutomaticRecoveryLiveGateAuthorizationState.Armed,
                    digest)),
                "a confirmed recovery authorization remained reusable");

            var expiredRoot = CreateRoot("expired");
            try
            {
                var expiredFixture = CreatePlanFixture(expiredRoot) with
                {
                    PreparedAtUtc = DateTimeOffset.UtcNow - TimeSpan.FromHours(1)
                };
                var expiredPlan = AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
                    expiredFixture.Options,
                    expiredFixture.Thread,
                    expiredFixture.Turn,
                    expiredFixture.Decision,
                    expiredFixture.Settings,
                    expiredFixture.SettingsSha256,
                    expiredFixture.PreparedAtUtc);
                var expiredDigest =
                    AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(expiredPlan);
                var expiredStore = new AutomaticRecoveryLiveGateManifestStore(expiredRoot);
                _ = expiredStore.CreatePrepared(expiredPlan);
                Ensure(
                    Throws<InvalidOperationException>(() => expiredStore.Transition(
                        AutomaticRecoveryLiveGateAuthorizationState.Prepared,
                        AutomaticRecoveryLiveGateAuthorizationState.Armed,
                        expiredDigest)),
                    "an expired recovery authorization was armed inside the manifest lease");
            }
            finally
            {
                Directory.Delete(expiredRoot, recursive: true);
            }

            var tamperRoot = CreateRoot("tamper");
            try
            {
                var tamperStore = new AutomaticRecoveryLiveGateManifestStore(tamperRoot);
                _ = tamperStore.CreatePrepared(plan with { GateId = Guid.NewGuid().ToString("D") });
                await File.AppendAllTextAsync(tamperStore.ManifestPath, " ");
                Ensure(
                    Throws<InvalidDataException>(() => tamperStore.Read()),
                    "a non-canonical or checksum-tampered recovery authorization was accepted");
            }
            finally
            {
                Directory.Delete(tamperRoot, recursive: true);
            }

            var shapeRoot = CreateRoot("shape");
            try
            {
                var shapeStore = new AutomaticRecoveryLiveGateManifestStore(shapeRoot);
                var shapePrepared = shapeStore.CreatePrepared(
                    plan with { GateId = Guid.NewGuid().ToString("D") });
                await WriteManifestAsync(shapeStore.ManifestPath, shapePrepared with { Plan = null! });
                Ensure(
                    Throws<InvalidDataException>(() => shapeStore.Read()),
                    "a checksum-valid null recovery plan was accepted");

                await WriteManifestAsync(
                    shapeStore.ManifestPath,
                    shapePrepared with
                    {
                        State = (AutomaticRecoveryLiveGateAuthorizationState)999
                    });
                Ensure(
                    Throws<InvalidDataException>(() => shapeStore.Read()),
                    "a checksum-valid unknown recovery authorization state was accepted");

                await WriteManifestAsync(
                    shapeStore.ManifestPath,
                    shapePrepared with
                    {
                        State = AutomaticRecoveryLiveGateAuthorizationState.Armed,
                        NewTurnId = Guid.NewGuid().ToString("D")
                    });
                Ensure(
                    Throws<InvalidDataException>(() => shapeStore.Read()),
                    "a non-confirmed recovery authorization carried a successor turn identity");
            }
            finally
            {
                Directory.Delete(shapeRoot, recursive: true);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestPolicyAuthorityAsync()
    {
        var root = CreateRoot("policy");
        try
        {
            var settingsPath = Path.Combine(root, "settings-policy.json");
            await File.WriteAllTextAsync(settingsPath, "policy-one");
            var settingsSha256 = Convert.ToHexString(SHA256.HashData(
                await File.ReadAllBytesAsync(settingsPath)));
            var fixture = CreatePlanFixture(root, settingsSha256) with
            {
                PreparedAtUtc = DateTimeOffset.UtcNow
            };
            var plan = AutomaticRecoveryExistingConversationLiveGate.BuildPlan(
                fixture.Options,
                fixture.Thread,
                fixture.Turn,
                fixture.Decision,
                fixture.Settings,
                settingsSha256,
                fixture.PreparedAtUtc);
            var digest = AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(plan);
            var store = new AutomaticRecoveryLiveGateManifestStore(root);
            _ = store.CreatePrepared(plan);
            _ = store.Transition(
                AutomaticRecoveryLiveGateAuthorizationState.Prepared,
                AutomaticRecoveryLiveGateAuthorizationState.Armed,
                digest);
            var authority = new AutomaticRecoveryLiveGatePolicyAuthority(
                store,
                digest,
                settingsPath,
                settingsSha256);
            Ensure(authority.IsCurrent(), "an exact armed recovery authority was not current");
            var expiredAuthority = new AutomaticRecoveryLiveGatePolicyAuthority(
                store,
                digest,
                settingsPath,
                settingsSha256,
                () => plan.ExpiresAtUtc);
            Ensure(!expiredAuthority.IsCurrent(), "an expired recovery authority remained current");

            await File.WriteAllTextAsync(settingsPath, "policy-two");
            Ensure(!authority.IsCurrent(), "settings-byte drift did not revoke the recovery authority");
            await File.WriteAllTextAsync(settingsPath, "policy-one");
            _ = store.Transition(
                AutomaticRecoveryLiveGateAuthorizationState.Armed,
                AutomaticRecoveryLiveGateAuthorizationState.Closed,
                digest);
            Ensure(!authority.IsCurrent(), "a consumed closed authorization remained current");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task TestExecutionLeaseAsync()
    {
        var first = AutomaticRecoveryExistingConversationLiveGate.AcquireExecutionLease();
        try
        {
            Ensure(
                Throws<AutomaticRecoveryLiveGateException>(() =>
                {
                    using var competing =
                        AutomaticRecoveryExistingConversationLiveGate.AcquireExecutionLease();
                }),
                "two recovery live gates acquired the owner-write lease concurrently");
        }
        finally
        {
            first.Dispose();
        }

        using var reacquired =
            AutomaticRecoveryExistingConversationLiveGate.AcquireExecutionLease();
        return Task.CompletedTask;
    }

    private static Task TestSourceContractAsync()
    {
        var sourceRoot = FindSourceRoot();
        var program = File.ReadAllText(Path.Combine(sourceRoot, "CodexGuardian.Tests", "Program.cs"));
        var gate = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Tests",
            "AutomaticRecoveryExistingConversationLiveGate.cs"));
        var productionApp = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian",
            "App.xaml.cs"));
        var productionFactory = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian",
            "Services",
            "ProductionRecoveryServiceFactory.cs"));
        var productionProgram = File.ReadAllText(Path.Combine(sourceRoot, "CodexGuardian", "Program.cs"));
        var gateDispatch = program.IndexOf(
            "if (AutomaticRecoveryExistingConversationLiveGate.IsRequested(args))",
            StringComparison.Ordinal);
        var deprecatedReject = program.IndexOf(
            "AUTOMATIC_RECOVERY_LIVE_GATE_FAILED code=deprecated-experiment-entry",
            StringComparison.Ordinal);
        var firstChildProbe = program.IndexOf(
            "if (BrokerConsentLedgerStoreOfflineTests.IsChildProbeInvocation(args))",
            StringComparison.Ordinal);
        var testMatrixStart = program.IndexOf("var failures = new List<string>();", StringComparison.Ordinal);
        var prepareStart = gate.IndexOf("private static async Task<int> PrepareAsync", StringComparison.Ordinal);
        var confirmStart = gate.IndexOf("private static async Task<int> ConfirmAsync", StringComparison.Ordinal);
        var protectedDataDirectory = gate.IndexOf(
            "DataDirectorySafety.CreateProtectedDirectory(options.DataDirectory)",
            prepareStart,
            StringComparison.Ordinal);
        var prepareLog = gate.IndexOf(
            "using var log = new GuardianLog(options.DataDirectory)",
            prepareStart,
            StringComparison.Ordinal);
        var armTransition = gate.IndexOf(
            "AutomaticRecoveryLiveGateAuthorizationState.Prepared,\n            AutomaticRecoveryLiveGateAuthorizationState.Armed",
            confirmStart,
            StringComparison.Ordinal);
        var ownerNavigation = gate.IndexOf("platform.OpenThread(options.TargetThreadId)", confirmStart, StringComparison.Ordinal);
        var ownerPreflight = gate.IndexOf("await ValidateOwnerSnapshotAsync(", confirmStart, StringComparison.Ordinal);
        var semanticProviderCreation = gate.IndexOf(
            "new InstalledCodexStructuredInputCapabilityProvider(settings.AttachmentLimits)",
            confirmStart,
            StringComparison.Ordinal);
        var threadCoordinatorCreation = gate.IndexOf(
            "new ThreadActionCoordinator()",
            confirmStart,
            StringComparison.Ordinal);
        var recoveryCreation = gate.IndexOf(
            "ProductionRecoveryServiceFactory.CreateLive(",
            confirmStart,
            StringComparison.Ordinal);
        var prepareStableClientCheck = gate.IndexOf(
            "await EnsureStableClientIdAbsentAsync(",
            prepareStart,
            StringComparison.Ordinal);
        var confirmStableClientCheck = gate.IndexOf(
            "await EnsureStableClientIdAbsentAsync(",
            confirmStart,
            StringComparison.Ordinal);
        var prepareSource = prepareStart >= 0 && confirmStart > prepareStart
            ? gate[prepareStart..confirmStart]
            : string.Empty;
        Ensure(
            gateDispatch >= 0 && deprecatedReject > gateDispatch && firstChildProbe > deprecatedReject &&
            testMatrixStart > deprecatedReject &&
            prepareStart >= 0 && confirmStart > prepareStart &&
            protectedDataDirectory > prepareStart && prepareLog > protectedDataDirectory &&
            armTransition > confirmStart && ownerNavigation > armTransition &&
            ownerPreflight > ownerNavigation &&
            semanticProviderCreation > ownerPreflight &&
            threadCoordinatorCreation > semanticProviderCreation &&
            recoveryCreation > threadCoordinatorCreation &&
            prepareStableClientCheck > prepareStart && prepareStableClientCheck < confirmStart &&
            confirmStableClientCheck > confirmStart && confirmStableClientCheck < recoveryCreation &&
            !prepareSource.Contains("new RecoveryService", StringComparison.Ordinal) &&
            !prepareSource.Contains("ProductionRecoveryServiceFactory.CreateLive(", StringComparison.Ordinal) &&
            !prepareSource.Contains("InstalledCodexStructuredInputCapabilityProvider", StringComparison.Ordinal) &&
            !prepareSource.Contains("ThreadActionCoordinator", StringComparison.Ordinal) &&
            !prepareSource.Contains("Directory.CreateDirectory(options.DataDirectory)", StringComparison.Ordinal) &&
            !gate.Contains("Directory.CreateDirectory(DataDirectory)", StringComparison.Ordinal) &&
            !prepareSource.Contains("OpenThread(", StringComparison.Ordinal) &&
            !prepareSource.Contains("StartTurnAsync", StringComparison.Ordinal) &&
            gate.Contains("WindowsCodexInteractionHook", StringComparison.Ordinal) &&
            gate.Contains("replayAuthority: null", StringComparison.Ordinal) &&
            !gate.Contains("StrictComposerInterferenceGuard", StringComparison.Ordinal) &&
            !gate.Contains("new RecoveryService", StringComparison.Ordinal) &&
            productionApp.Contains(
                "ProductionRecoveryServiceFactory.CreateLive(",
                StringComparison.Ordinal) &&
            productionFactory.Contains("requireCurrentNativeChannel: true", StringComparison.Ordinal) &&
            productionFactory.Contains("requireExplicitInterferenceClear: true", StringComparison.Ordinal) &&
            gate.Contains("AcquireThreadOwnerStateGuardAsync", StringComparison.Ordinal) &&
            gate.Contains("private static async Task ValidateOwnerSnapshotAsync", StringComparison.Ordinal) &&
            gate.Contains("await using var ownerGuard", StringComparison.Ordinal) &&
            gate.Contains("AutomaticRecoveryLiveGatePolicyAuthority", StringComparison.Ordinal) &&
            gate.Contains("EnsureStableClientIdAbsentAsync", StringComparison.Ordinal) &&
            gate.Contains("ExecutionSemaphoreName", StringComparison.Ordinal) &&
            gate.Contains("new Semaphore(", StringComparison.Ordinal) &&
            gate.Contains("RecoveryOperationState.Confirmed", StringComparison.Ordinal) &&
            !gate.Contains("FAILED code=\" + exception.Code + \" realSend=", StringComparison.Ordinal) &&
            !gate.Contains("CodexDeepObservationService", StringComparison.Ordinal) &&
            !gate.Contains("thread/rollback", StringComparison.OrdinalIgnoreCase) &&
            !gate.Contains("remote-debugging", StringComparison.OrdinalIgnoreCase) &&
            !productionProgram.Contains(
                AutomaticRecoveryExistingConversationLiveGate.GateArgument,
                StringComparison.Ordinal),
            "the recovery live gate is not fail-closed tests-only prepare-safe or stock-owner-bound");
        return Task.CompletedTask;
    }

    private static async Task WriteManifestAsync(
        string path,
        AutomaticRecoveryLiveGateManifest manifest)
    {
        var content = new AutomaticRecoveryLiveGateManifestContent(
            manifest.SchemaVersion,
            manifest.Generation,
            manifest.State,
            manifest.Plan,
            manifest.NewTurnId);
        var checksum = Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(content, ManifestJsonOptions)));
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            manifest with { Checksum = checksum },
            ManifestJsonOptions);
        var canonical = new byte[payload.Length + 1];
        payload.CopyTo(canonical, 0);
        canonical[^1] = (byte)'\n';
        await File.WriteAllBytesAsync(path, canonical);
    }

    private static PlanFixture CreatePlanFixture(
        string? root = null,
        string? settingsSha256 = null)
    {
        var gateId = Guid.NewGuid().ToString("D");
        var targetId = Guid.NewGuid().ToString("D");
        var failedTurnId = Guid.NewGuid().ToString("D");
        var restoreId = Guid.NewGuid().ToString("D");
        root ??= Path.Combine(
            AutomaticRecoveryExistingConversationLiveGate.DataRoot,
            "offline-gates",
            gateId);
        settingsSha256 ??= new string('B', 64);
        var options = new AutomaticRecoveryExistingConversationLiveGateOptions(
            PrepareOnly: true,
            gateId,
            targetId,
            failedTurnId,
            restoreId,
            root,
            AuthorizationDigest: null);
        var thread = new ThreadSummary(
            targetId,
            "offline recovery target",
            string.Empty,
            @"D:\Workspace",
            "appServer",
            1,
            2,
            false,
            false);
        var turn = new TurnSnapshot(
            failedTurnId,
            "failed",
            "provider failure",
            "internal_server_error",
            429,
            "retry this exact input",
            false,
            false,
            false,
            "failure-fingerprint",
            1,
            2,
            RawUserInputJson: "[{\"type\":\"text\",\"text\":\"retry this exact input\"}]",
            HasConfirmedLocalTerminal: true,
            UserMessageClientIds: [Guid.NewGuid().ToString("D")],
            HasUserMessage: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);
        var decision = new RecoveryDecision(
            RecoveryActionKind.ResendOriginal,
            TaskHealth.NeedsAttention,
            "retryable provider failure",
            true);
        var settings = new AppSettings
        {
            MonitorOnly = false,
            AutomaticRecoveryEnabled = true,
            GlobalProtectionEnabled = true,
            IncludeSubAgents = false,
            SettingsGeneration = 7,
            ReadStatus = SettingsReadStatus.Healthy
        };
        settings.ThreadEnabled[targetId] = true;
        settings.ThreadProtectionEnabled[targetId] = true;
        return new PlanFixture(
            options,
            thread,
            turn,
            decision,
            settings,
            settingsSha256,
            new DateTimeOffset(2026, 8, 16, 12, 0, 0, TimeSpan.Zero));
    }

    private static string CreateRoot(string label)
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.Combine(parent, "recovery-gate-" + label + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static string FindSourceRoot()
    {
        var current = Path.Combine(Environment.CurrentDirectory, "work");
        if (File.Exists(Path.Combine(current, "CodexGuardian.Tests", "Program.cs")))
        {
            return current;
        }

        throw new DirectoryNotFoundException("The Ceasy work source root was not found.");
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

    private sealed record PlanFixture(
        AutomaticRecoveryExistingConversationLiveGateOptions Options,
        ThreadSummary Thread,
        TurnSnapshot Turn,
        RecoveryDecision Decision,
        AppSettings Settings,
        string SettingsSha256,
        DateTimeOffset PreparedAtUtc);
}
