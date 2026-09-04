using CodexGuardian.Trust;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class WindowsNamedPipePeerTrustNativeProbeTests
{
    private const string ProbeArgument = "--native-peer-child-probe";
    private const string BrokerArgument = "--native-peer-child-probe-server";
    private const string ReadyMarker = "BROKER_NATIVE_PROBE_READY";
    private const string ConnectedMarker = "BROKER_NATIVE_PROBE_CONNECTED";
    private const string HelloMarker = "BROKER_NATIVE_PROBE_HELLO_SENT";
    private const string CompleteMarker = "BROKER_NATIVE_PROBE_COMPLETE";
    private const string ReleaseId = "r13-native-probe";
    private const string ChildReceiptPrefix = "NATIVE_PEER_CHILD_RECEIPT ";
    private const string ChildReceiptMarker = "NATIVE_PEER_CHILD_RECEIPT_V1";
    internal const string CompletionMarker = "NATIVE_PEER_PROBE_COMPLETE";
    private static readonly TimeSpan BrokerStabilityWindow = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan ChildCleanupTimeout = TimeSpan.FromSeconds(5);
    private static readonly MethodInfo CreatePipeCore =
        typeof(WindowsSameLogonNamedPipeServer).GetMethod(
            "CreateCore",
            BindingFlags.Static | BindingFlags.NonPublic,
            binder: null,
            types: new[] { typeof(string), typeof(string) },
            modifiers: null) ?? throw new MissingMethodException(
                typeof(WindowsSameLogonNamedPipeServer).FullName,
                "CreateCore");

    internal static void RunIfRequested(Action<bool, string> assert)
    {
        if (!Environment.GetCommandLineArgs().Contains(
                ProbeArgument,
                StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        RunCase(
            "native pipe descriptor is exact same-logon first-instance remote-reject",
            TestPipeSecurityContract,
            assert);
        RunCase(
            "real Broker child retains and revalidates exact native peer identity",
            TestRealBrokerPeer,
            assert);
        RunCase(
            "blocked native hello cancels within the Trust deadline without ending Broker",
            TestBlockedHelloCancellation,
            assert);
        RunCase(
            "pre-canceled native hello publishes no read generation",
            TestPreCanceledHelloRead,
            assert);
        RunCase(
            "native Broker second frame fails the exclusive hello gate",
            TestSecondFrameRejected,
            assert);
        RunCase(
            "native Broker oversized message fails the bounded hello gate",
            TestOversizedFrameRejected,
            assert);
        RunCase(
            "native Broker malformed UTF-8 fails the hello parser",
            TestMalformedHelloRejected,
            assert);
        RunCase(
            "native Broker exit before hello fails retained-process liveness",
            TestPeerExitBeforeHello,
            assert);
        Console.WriteLine(CompletionMarker);
    }

    internal static void WriteChildReceipt(
        Process process,
        string role,
        string scenario,
        string expectedExecutable,
        string argument)
    {
        if (!Environment.GetCommandLineArgs().Contains(
                ProbeArgument,
                StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        Ensure(role is "tests" or "broker", "native child receipt role is invalid");
        Ensure(
            scenario is "timeoutCancellation" or "realPeer" or
                "blockedHelloCancellation" or "preCanceledHelloRead" or
                "secondFrame" or "oversizedFrame" or "malformedHello" or
                "peerExitBeforeHello",
            "native child receipt scenario is invalid");
        Ensure(
            role == "broker"
                ? string.Equals(argument, BrokerArgument, StringComparison.Ordinal)
                : string.Equals(
                    argument,
                    WindowsNamedPipePeerTrustOfflineTests.TimeoutCancellationChildProbeArgument,
                    StringComparison.Ordinal),
            "native child receipt argument is invalid");

        var launch = WindowsPeerNative.CaptureLaunchedPeer(process.SafeHandle);
        var executablePath = Path.GetFullPath(expectedExecutable);
        Ensure(
            launch.ProcessId == checked((uint)process.Id) &&
            WindowsPeerNative.SamePath(launch.FinalImagePath, executablePath),
            "native child receipt did not bind the retained launch handle");
        var commandLine = $"\"{executablePath}\" {argument}";
        Console.WriteLine(ChildReceiptPrefix + JsonSerializer.Serialize(new
        {
            marker = ChildReceiptMarker,
            role,
            scenario,
            processId = launch.ProcessId,
            parentProcessId = Environment.ProcessId,
            creationTimeUtc = launch.CreationTimeUtc.ToString(
                "O",
                System.Globalization.CultureInfo.InvariantCulture),
            sessionId = launch.SessionId,
            executablePath,
            argument,
            commandLine
        }));
        Console.Out.Flush();
    }

    private static void TestPipeSecurityContract()
    {
        Ensure(OperatingSystem.IsWindows(), "native pipe security contract requires Windows");
        var endpoint = CreateEndpointName();
        using var server = WindowsSameLogonNamedPipeServer.Create(endpoint);
        var security = server.Security;
        Ensure(
            security.DaclProtected &&
            security.AccessControlEntryCount == 2 &&
            security.ClientAccessMask == WindowsSameLogonNamedPipeServer.ExpectedClientAccessMask &&
            security.OwnerRightsDenyMask == WindowsSameLogonNamedPipeServer.ExpectedOwnerRightsDenyMask &&
            security.OpenMode == WindowsSameLogonNamedPipeServer.ExpectedOpenMode &&
            security.PipeMode == WindowsSameLogonNamedPipeServer.ExpectedPipeMode &&
            security.OwnerSid.StartsWith("S-1-", StringComparison.Ordinal) &&
            security.AllowedLogonSid.StartsWith("S-1-5-5-", StringComparison.Ordinal) &&
            !string.Equals(
                security.OwnerSid,
                security.AllowedLogonSid,
                StringComparison.OrdinalIgnoreCase),
            "native pipe security descriptor widened its exact logon capability");

        var collision = Expect<System.ComponentModel.Win32Exception>(() =>
        {
            using var duplicate = WindowsSameLogonNamedPipeServer.Create(endpoint);
        });
        Ensure(
            collision.NativeErrorCode == 5,
            "FILE_FLAG_FIRST_PIPE_INSTANCE did not reject the occupied endpoint");

        var sidParts = security.AllowedLogonSid.Split('-');
        var lastPart = ulong.Parse(sidParts[^1], System.Globalization.CultureInfo.InvariantCulture);
        sidParts[^1] = (lastPart == ulong.MaxValue ? lastPart - 1 : lastPart + 1)
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        var wrongLogonSid = string.Join("-", sidParts);
        using var wrongSidServer = CreatePipeWithAllowedLogonSid(
            CreateEndpointName(),
            wrongLogonSid);
        var denied = Expect<System.ComponentModel.Win32Exception>(() =>
        {
            using var client = WindowsSameLogonNamedPipeClient.Connect(
                wrongSidServer.EndpointName,
                TimeSpan.FromMilliseconds(250),
                CancellationToken.None);
        });
        Ensure(
            denied.NativeErrorCode == 5,
            "a pipe DACL for another logon SID accepted the current token");
    }

    private static WindowsSameLogonNamedPipeServer CreatePipeWithAllowedLogonSid(
        string endpointName,
        string allowedLogonSid) =>
        (WindowsSameLogonNamedPipeServer)(CreatePipeCore.Invoke(
            obj: null,
            parameters: new object?[] { endpointName, allowedLogonSid }) ??
            throw new InvalidOperationException("The native pipe test fixture returned null."));

    private static void TestRealBrokerPeer()
    {
        Ensure(OperatingSystem.IsWindows(), "native Broker child probe requires Windows");
        var binRoot = ResolveArtifactsBinRoot();
        var guardianDirectory = Path.Combine(binRoot, "CodexGuardian", "release");
        var brokerDirectory = Path.Combine(binRoot, "CodexGuardian.Broker", "release");
        var brokerExecutable = Path.Combine(brokerDirectory, "CodexGuardian.Broker.exe");
        Ensure(File.Exists(brokerExecutable), "fresh Broker child apphost is unavailable");

        using var guardianArtifacts = CaptureGuardianArtifacts(binRoot);
        using var brokerArtifacts = CaptureBrokerArtifacts(binRoot);
        Ensure(
            guardianArtifacts.Root == brokerArtifacts.Root,
            "Guardian and Broker build artifacts do not share one exact release root");
        var pinnedWriteFailure = Expect<IOException>(() =>
        {
            using var unexpectedWrite = File.Open(
                brokerExecutable,
                FileMode.Open,
                FileAccess.Write,
                FileShare.ReadWrite | FileShare.Delete);
        });
        Ensure(
            (pinnedWriteFailure.HResult & 0xFFFF) == 32,
            "the retained Broker apphost did not reject a real write-open attempt");
        var manifestSha256 = ComputeManifestSha256(guardianArtifacts, brokerArtifacts);
        var manifest = VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId,
            manifestSha256,
            guardianArtifacts.Root,
            CreateRoleDefinition(guardianArtifacts),
            CreateRoleDefinition(brokerArtifacts));
        var brokerRelease = manifest.GetArtifactSet(BrokerPeerRole.Broker);
        var endpointName = CreateEndpointName();
        var connectionNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        var startInfo = new ProcessStartInfo(brokerExecutable)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = brokerDirectory
        };
        startInfo.ArgumentList.Add(BrokerArgument);
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException(
            "The exact Broker child apphost did not start.");
        WriteChildReceipt(process, "broker", "realPeer", brokerExecutable, BrokerArgument);
        var standardError = process.StandardError.ReadToEndAsync();
        WindowsNamedPipePeerTrustPlatform? callerOwnedPlatform = null;
        PendingPipePeerVerification? pending = null;
        VerifiedPipePeerIdentity? peer = null;
        ExecuteScenarioWithCleanup(
            process,
            standardError,
            () =>
            {
            var launch = WindowsPeerNative.CaptureLaunchedPeer(process.SafeHandle);
            brokerArtifacts.ValidateProcessImageMapping(process.SafeHandle);
            var wrongImageMapping = Expect<BrokerPeerTrustException>(() =>
                guardianArtifacts.ValidateProcessImageMapping(process.SafeHandle));
            using var restrictedProcess = WindowsPeerNative.DuplicateRestrictedProcessHandle(
                process.SafeHandle);
            using var queryToken = WindowsPeerNative.OpenQueryToken(restrictedProcess);
            Ensure(
                launch.ProcessId == checked((uint)process.Id) &&
                WindowsPeerNative.SamePath(launch.FinalImagePath, brokerExecutable) &&
                launch.AppModel == WindowsAppModelIdentity.Unpackaged,
                "the exact Broker launch handle did not bind to the expected apphost");
            Ensure(
                wrongImageMapping.Code == "peer-image-mapping-mismatch",
                "a different retained apphost was accepted as the Broker process image");
            var processGrantedAccess = WindowsPeerNative.ReadGrantedAccess(restrictedProcess);
            var tokenGrantedAccess = WindowsPeerNative.ReadGrantedAccess(queryToken);
            Ensure(
                processGrantedAccess == WindowsPeerNative.RestrictedProcessGrantedAccess,
                "the retained process handle access mask widened: 0x" +
                processGrantedAccess.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
            Ensure(
                tokenGrantedAccess == WindowsPeerNative.TokenQuery,
                "the retained token handle access mask widened: 0x" +
                tokenGrantedAccess.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));

            var bootstrap = JsonSerializer.Serialize(new
            {
                kind = "nativePeerProbe",
                mode = "normal",
                endpointName,
                connectionNonce,
                releaseId = ReleaseId,
                manifestSha256
            });
            process.StandardInput.WriteLine(bootstrap);
            process.StandardInput.Flush();
            Ensure(
                string.Equals(
                    ReadLineBounded(process.StandardOutput, TimeSpan.FromSeconds(10)),
                    ReadyMarker,
                    StringComparison.Ordinal),
                "Broker child did not publish its bounded ready marker");

            callerOwnedPlatform = WindowsNamedPipePeerTrustPlatform.ConnectToLaunchedServer(
                endpointName,
                process.SafeHandle,
                brokerArtifacts,
                TimeSpan.FromSeconds(5));
            var expectation = new BrokerPeerExpectation(
                launch.Token,
                launch.AppModel,
                brokerRelease,
                connectionNonce,
                launch.ProcessId,
                launch.CreationTimeUtc);
            pending = new WindowsNamedPipePeerVerifier(TimeSpan.FromSeconds(5))
                .BeginVerification(
                    callerOwnedPlatform,
                    NamedPipePeerKind.Server,
                    expectation);
            callerOwnedPlatform = null;
            peer = pending.CompleteAsync().AsTask().GetAwaiter().GetResult();
            pending.DisposeAsync().AsTask().GetAwaiter().GetResult();
            pending = null;
            Ensure(
                string.Equals(
                    ReadLineBounded(process.StandardOutput, TimeSpan.FromSeconds(10)),
                    HelloMarker,
                    StringComparison.Ordinal),
                "Broker child did not publish its hello marker");

            var initial = peer.InitialIdentity;
            var revalidated = peer.Revalidate();
            Ensure(
                initial.ProcessId == launch.ProcessId &&
                initial.CreationTimeUtc == launch.CreationTimeUtc &&
                initial.KernelSessionId == launch.SessionId &&
                initial.Token == launch.Token &&
                initial.AppModel == WindowsAppModelIdentity.Unpackaged &&
                initial.ImageFileObjectIsExact &&
                WindowsPeerNative.SamePath(initial.FinalImagePath, brokerExecutable) &&
                revalidated.ProcessId == initial.ProcessId &&
                revalidated.Token == initial.Token &&
                revalidated.ImageFileObjectIsExact &&
                revalidated.Artifacts.SequenceEqual(initial.Artifacts),
                "native Broker peer identity did not remain exact across revalidation");

            peer.Dispose();
            peer = null;
            EnsureChildRemainsAlive(
                process,
                "disposing the Guardian connection terminated the Broker child");
            process.StandardInput.WriteLine("EXIT");
            process.StandardInput.Flush();
            Ensure(
                string.Equals(
                    ReadLineBounded(process.StandardOutput, TimeSpan.FromSeconds(10)),
                    CompleteMarker,
                    StringComparison.Ordinal),
                "Broker child did not complete through its independent control channel");
            Ensure(
                process.WaitForExit((int)TimeSpan.FromSeconds(10).TotalMilliseconds) &&
                process.ExitCode == 0,
                "Broker child did not exit naturally after the exact control request");
            Ensure(
                standardError.GetAwaiter().GetResult().Length == 0,
                "Broker child emitted an unexpected error marker");
            },
            ("verified peer", () =>
            {
                peer?.Dispose();
                peer = null;
            }),
            ("pending verification", () =>
            {
                pending?.DisposeAsync().AsTask().GetAwaiter().GetResult();
                pending = null;
            }),
            ("caller-owned platform", () =>
            {
                callerOwnedPlatform?.Dispose();
                callerOwnedPlatform = null;
            }));
    }

    private static void TestBlockedHelloCancellation() => RunNativeFailureMode(
        scenario: "blockedHelloCancellation",
        mode: "stall",
        brokerMarker: ConnectedMarker,
        handshakeTimeout: TimeSpan.FromMilliseconds(250),
        expectedCode: "peer-handshake-timeout",
        expectDeadline: true);

    private static void TestPreCanceledHelloRead() => RunNativeFailureMode(
        scenario: "preCanceledHelloRead",
        mode: "stall",
        brokerMarker: ConnectedMarker,
        handshakeTimeout: TimeSpan.FromSeconds(5),
        expectedCode: "pre-canceled",
        expectDeadline: false,
        preCanceledDirectRead: true);

    private static void TestSecondFrameRejected() => RunNativeFailureMode(
        scenario: "secondFrame",
        mode: "secondFrame",
        brokerMarker: HelloMarker,
        handshakeTimeout: TimeSpan.FromSeconds(5),
        expectedCode: "peer-hello-read-order-invalid",
        expectDeadline: false);

    private static void TestOversizedFrameRejected() => RunNativeFailureMode(
        scenario: "oversizedFrame",
        mode: "oversize",
        brokerMarker: ConnectedMarker,
        handshakeTimeout: TimeSpan.FromSeconds(5),
        expectedCode: "peer-hello-too-large",
        expectDeadline: false);

    private static void TestMalformedHelloRejected() => RunNativeFailureMode(
        scenario: "malformedHello",
        mode: "malformed",
        brokerMarker: HelloMarker,
        handshakeTimeout: TimeSpan.FromSeconds(5),
        expectedCode: "invalid-peer-hello",
        expectDeadline: false);

    private static void TestPeerExitBeforeHello() => RunNativeFailureMode(
        scenario: "peerExitBeforeHello",
        mode: "exitBeforeHello",
        brokerMarker: ConnectedMarker,
        handshakeTimeout: TimeSpan.FromSeconds(5),
        expectedCode: "peer-process-exited",
        expectDeadline: false,
        exitBeforeVerification: true);

    private static void RunNativeFailureMode(
        string scenario,
        string mode,
        string brokerMarker,
        TimeSpan handshakeTimeout,
        string expectedCode,
        bool expectDeadline,
        bool exitBeforeVerification = false,
        bool preCanceledDirectRead = false)
    {
        var binRoot = ResolveArtifactsBinRoot();
        var brokerDirectory = Path.Combine(binRoot, "CodexGuardian.Broker", "release");
        var brokerExecutable = Path.Combine(brokerDirectory, "CodexGuardian.Broker.exe");
        using var guardianArtifacts = CaptureGuardianArtifacts(binRoot);
        using var brokerArtifacts = CaptureBrokerArtifacts(binRoot);
        var manifestSha256 = ComputeManifestSha256(guardianArtifacts, brokerArtifacts);
        var manifest = VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId,
            manifestSha256,
            guardianArtifacts.Root,
            CreateRoleDefinition(guardianArtifacts),
            CreateRoleDefinition(brokerArtifacts));
        var brokerRelease = manifest.GetArtifactSet(BrokerPeerRole.Broker);
        var endpointName = CreateEndpointName();
        var connectionNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var startInfo = new ProcessStartInfo(brokerExecutable)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = brokerDirectory
        };
        startInfo.ArgumentList.Add(BrokerArgument);
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException(
            "The failure-mode Broker child did not start.");
        WriteChildReceipt(process, "broker", scenario, brokerExecutable, BrokerArgument);
        var standardError = process.StandardError.ReadToEndAsync();
        WindowsNamedPipePeerTrustPlatform? callerOwnedPlatform = null;
        PendingPipePeerVerification? pending = null;
        ExecuteScenarioWithCleanup(
            process,
            standardError,
            () =>
            {
            var launch = WindowsPeerNative.CaptureLaunchedPeer(process.SafeHandle);
            var bootstrap = JsonSerializer.Serialize(new
            {
                kind = "nativePeerProbe",
                mode,
                endpointName,
                connectionNonce,
                releaseId = ReleaseId,
                manifestSha256
            });
            process.StandardInput.WriteLine(bootstrap);
            process.StandardInput.Flush();
            Ensure(
                string.Equals(
                    ReadLineBounded(process.StandardOutput, TimeSpan.FromSeconds(10)),
                    ReadyMarker,
                    StringComparison.Ordinal),
                "failure-mode Broker child did not publish ready");
            callerOwnedPlatform = WindowsNamedPipePeerTrustPlatform.ConnectToLaunchedServer(
                endpointName,
                process.SafeHandle,
                brokerArtifacts,
                TimeSpan.FromSeconds(5));
            Ensure(
                string.Equals(
                    ReadLineBounded(process.StandardOutput, TimeSpan.FromSeconds(10)),
                    brokerMarker,
                    StringComparison.Ordinal),
                "failure-mode Broker child did not publish its connection marker");
            var verifier = new WindowsNamedPipePeerVerifier(handshakeTimeout);
            var quarantineBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
            var expectation = new BrokerPeerExpectation(
                launch.Token,
                launch.AppModel,
                brokerRelease,
                connectionNonce,
                launch.ProcessId,
                launch.CreationTimeUtc);
            if (preCanceledDirectRead)
            {
                using var cancellation = new CancellationTokenSource();
                cancellation.Cancel();
                var preCanceledStopwatch = Stopwatch.StartNew();
                var cancellationFailure = Expect<OperationCanceledException>(() =>
                    _ = callerOwnedPlatform.ReadBoundedHelloAndCaptureIdentityAsync(
                            NamedPipePeerKind.Server,
                            BrokerPeerHelloProtocol.MaximumHelloBytes,
                            cancellation.Token)
                        .AsTask()
                        .GetAwaiter()
                        .GetResult());
                preCanceledStopwatch.Stop();
                Ensure(
                    cancellationFailure.CancellationToken == cancellation.Token &&
                    preCanceledStopwatch.Elapsed < TimeSpan.FromMilliseconds(500) &&
                    callerOwnedPlatform.ReadGeneration == 0,
                    "pre-canceled native read submitted work or published peer evidence");
                callerOwnedPlatform.Dispose();
                callerOwnedPlatform = null;
                EnsureChildRemainsAlive(
                    process,
                    "pre-canceled native read disposal terminated the Broker child");
                process.StandardInput.WriteLine("EXIT");
                process.StandardInput.Flush();
                Ensure(
                    string.Equals(
                        ReadLineBounded(process.StandardOutput, TimeSpan.FromSeconds(10)),
                        CompleteMarker,
                        StringComparison.Ordinal) &&
                    process.WaitForExit((int)TimeSpan.FromSeconds(10).TotalMilliseconds) &&
                    process.ExitCode == 0 &&
                    standardError.GetAwaiter().GetResult().Length == 0,
                    "pre-canceled native read did not release the Broker independently");
                return;
            }

            if (exitBeforeVerification)
            {
                process.StandardInput.WriteLine("EXIT_NOW");
                process.StandardInput.Flush();
                Ensure(
                    process.WaitForExit((int)TimeSpan.FromSeconds(10).TotalMilliseconds) &&
                    process.ExitCode == 0,
                    "peer-exit Broker child did not exit naturally");
                var consumedPlatform = callerOwnedPlatform;
                callerOwnedPlatform = null;
                var beginFailure = Expect<BrokerPeerTrustException>(() =>
                    _ = verifier.BeginVerification(
                        consumedPlatform,
                        NamedPipePeerKind.Server,
                        expectation));
                Ensure(
                    beginFailure.Code == expectedCode &&
                    verifier.Health is
                    {
                        IsUnhealthy: false,
                        ActiveConnectionCount: 0,
                        QuarantinedHandshakeCount: 0
                    } &&
                    WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline &&
                    standardError.GetAwaiter().GetResult().Length == 0,
                    "peer exit did not fail closed and release exact authority");
                return;
            }

            pending = verifier.BeginVerification(
                callerOwnedPlatform,
                NamedPipePeerKind.Server,
                expectation);
            callerOwnedPlatform = null;
            var stopwatch = Stopwatch.StartNew();
            var failure = Expect<BrokerPeerTrustException>(
                () => _ = pending.CompleteAsync().AsTask().GetAwaiter().GetResult());
            stopwatch.Stop();
            Ensure(
                failure.Code == expectedCode,
                "native failure mode returned " + failure.Code + " instead of " + expectedCode);
            if (expectDeadline)
            {
                Ensure(
                    stopwatch.Elapsed >= TimeSpan.FromMilliseconds(150) &&
                    stopwatch.Elapsed < TimeSpan.FromSeconds(3),
                    "blocked native hello did not respect the bounded Trust deadline");
            }

            pending.DisposeAsync().AsTask().GetAwaiter().GetResult();
            pending = null;
            Ensure(
                verifier.Health is
                {
                    IsUnhealthy: false,
                    ActiveConnectionCount: 0,
                    QuarantinedHandshakeCount: 0
                } &&
                WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                "native failure cleanup left Trust unhealthy or quarantined");
            EnsureChildRemainsAlive(
                process,
                "native failure cleanup terminated the Broker child");
            process.StandardInput.WriteLine("EXIT");
            process.StandardInput.Flush();
            Ensure(
                string.Equals(
                    ReadLineBounded(process.StandardOutput, TimeSpan.FromSeconds(10)),
                    CompleteMarker,
                    StringComparison.Ordinal),
                "failure-mode Broker child did not complete independently");
            Ensure(
                process.WaitForExit((int)TimeSpan.FromSeconds(10).TotalMilliseconds) &&
                process.ExitCode == 0 &&
                standardError.GetAwaiter().GetResult().Length == 0,
                "failure-mode Broker child did not exit cleanly");
            },
            ("pending verification", () =>
            {
                pending?.DisposeAsync().AsTask().GetAwaiter().GetResult();
                pending = null;
            }),
            ("caller-owned platform", () =>
            {
                callerOwnedPlatform?.Dispose();
                callerOwnedPlatform = null;
            }));
    }

    private static WindowsRetainedReleaseArtifacts CaptureGuardianArtifacts(string root) =>
        WindowsRetainedReleaseArtifacts.Capture(
            root,
            BrokerPeerRole.Guardian,
            Path.Combine("CodexGuardian", "release", "CodexGuardian.exe"),
            Path.Combine("CodexGuardian", "release", "CodexGuardian.dll"),
            Path.Combine("CodexGuardian", "release", "CodexGuardian.deps.json"),
            Path.Combine("CodexGuardian", "release", "CodexGuardian.runtimeconfig.json"),
            new[]
            {
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.AppHostExe,
                    Path.Combine("CodexGuardian", "release", "CodexGuardian.exe")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.ManagedEntryDll,
                    Path.Combine("CodexGuardian", "release", "CodexGuardian.dll")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.DepsJson,
                    Path.Combine("CodexGuardian", "release", "CodexGuardian.deps.json")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.RuntimeConfigJson,
                    Path.Combine("CodexGuardian", "release", "CodexGuardian.runtimeconfig.json"))
            });

    private static WindowsRetainedReleaseArtifacts CaptureBrokerArtifacts(string root) =>
        WindowsRetainedReleaseArtifacts.Capture(
            root,
            BrokerPeerRole.Broker,
            Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.exe"),
            Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.dll"),
            Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.deps.json"),
            Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.runtimeconfig.json"),
            new[]
            {
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.AppHostExe,
                    Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.exe")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.ManagedEntryDll,
                    Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.dll")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.DepsJson,
                    Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.deps.json")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.RuntimeConfigJson,
                    Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Broker.runtimeconfig.json")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.RuntimeDependency,
                    Path.Combine("CodexGuardian.Broker", "release", "CodexGuardian.Trust.dll"))
            });

    private static VerifiedReleaseRoleArtifacts CreateRoleDefinition(
        WindowsRetainedReleaseArtifacts artifacts) =>
        new(
            artifacts.Role,
            artifacts.AppHostRelativePath,
            artifacts.ManagedEntryRelativePath,
            artifacts.DepsRelativePath,
            artifacts.RuntimeConfigRelativePath,
            artifacts.Artifacts);

    private static string ComputeManifestSha256(
        WindowsRetainedReleaseArtifacts guardian,
        WindowsRetainedReleaseArtifacts broker)
    {
        var canonical = string.Join(
            "\n",
            guardian.Artifacts.Concat(broker.Artifacts)
                .OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
                .Select(artifact => string.Join(
                    "|",
                    artifact.Kind,
                    artifact.RelativePath,
                    artifact.Length,
                    artifact.Sha256,
                    artifact.VolumeSerialNumber,
                    artifact.FileId,
                    artifact.LinkCount)));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static string ResolveArtifactsBinRoot()
    {
        var configurationDirectory = Directory.GetParent(
            Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory)) ??
            throw new DirectoryNotFoundException("The test configuration directory is unavailable.");
        var projectDirectory = configurationDirectory.Parent ?? throw new DirectoryNotFoundException(
            "The test project artifact directory is unavailable.");
        return projectDirectory.FullName;
    }

    private static string CreateEndpointName() =>
        "CodexGuardian.r13.native." + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private static string ReadLineBounded(StreamReader reader, TimeSpan timeout) =>
        reader.ReadLineAsync().WaitAsync(timeout).GetAwaiter().GetResult() ??
        throw new EndOfStreamException("The Broker child output channel closed unexpectedly.");

    private static void EnsureChildRemainsAlive(Process process, string message)
    {
        if (process.WaitForExit((int)BrokerStabilityWindow.TotalMilliseconds))
        {
            throw new InvalidOperationException(
                message + " during the bounded stability window; exitCode=" + process.ExitCode);
        }

        process.Refresh();
        Ensure(!process.HasExited, message);
    }

    private static void ExecuteScenarioWithCleanup(
        Process process,
        Task<string> standardError,
        Action scenario,
        params (string Name, Action Cleanup)[] cleanupActions)
    {
        Exception? primaryFailure = null;
        try
        {
            scenario();
        }
        catch (Exception exception)
        {
            primaryFailure = exception;
        }

        var cleanupFailures = CleanupNativeProbeChild(
            process,
            standardError,
            cleanupActions);
        if (primaryFailure is null && cleanupFailures.Count == 0)
        {
            return;
        }

        if (primaryFailure is not null && cleanupFailures.Count == 0)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primaryFailure).Throw();
            return;
        }

        var failures = primaryFailure is null
            ? cleanupFailures
            : new[] { primaryFailure }.Concat(cleanupFailures).ToArray();
        throw new AggregateException(
            "The native Broker probe scenario or its bounded cleanup failed.",
            failures);
    }

    private static IReadOnlyList<Exception> CleanupNativeProbeChild(
        Process process,
        Task<string> standardError,
        IReadOnlyList<(string Name, Action Cleanup)> cleanupActions)
    {
        var failures = new List<Exception>();
        var pendingTasks = new List<(string Name, Task Task)>();
        var deadline = checked(
            Stopwatch.GetTimestamp() +
            (long)Math.Ceiling(ChildCleanupTimeout.TotalSeconds * Stopwatch.Frequency));

        foreach (var cleanupAction in cleanupActions)
        {
            var task = Task.Run(cleanupAction.Cleanup);
            if (!ObserveCleanupTask(
                    cleanupAction.Name,
                    task,
                    deadline,
                    maximumWaitMilliseconds: 500,
                    failures))
            {
                pendingTasks.Add((cleanupAction.Name, task));
            }
        }

        var exited = TryHasExited(process, failures);
        if (!exited)
        {
            var gracefulTask = Task.Run(() =>
            {
                process.StandardInput.WriteLine("EXIT");
                process.StandardInput.Flush();
            });
            if (!ObserveCleanupTask(
                    "graceful child exit command",
                    gracefulTask,
                    deadline,
                    maximumWaitMilliseconds: 500,
                    failures))
            {
                pendingTasks.Add(("graceful child exit command", gracefulTask));
            }

            var gracefulWait = Math.Min(RemainingMilliseconds(deadline), 1500);
            if (gracefulWait > 0)
            {
                try
                {
                    exited = process.WaitForExit(gracefulWait);
                }
                catch (Exception exception)
                {
                    failures.Add(new InvalidOperationException(
                        "Unable to wait for the native Broker child to exit naturally.",
                        exception));
                }
            }
        }

        if (!exited)
        {
            failures.Add(new InvalidOperationException(
                "The native Broker child required exact-process forced termination; pid=" +
                process.Id));
            var killTask = Task.Run(() => process.Kill(entireProcessTree: false));
            if (!ObserveCleanupTask(
                    "exact child kill",
                    killTask,
                    deadline,
                    maximumWaitMilliseconds: 500,
                    failures))
            {
                pendingTasks.Add(("exact child kill", killTask));
            }

            var killWait = RemainingMilliseconds(deadline);
            if (killWait > 0)
            {
                try
                {
                    exited = process.WaitForExit(killWait);
                }
                catch (Exception exception)
                {
                    failures.Add(new InvalidOperationException(
                        "Unable to wait for the killed native Broker child.",
                        exception));
                }
            }
        }

        if (!exited)
        {
            failures.Add(new TimeoutException(
                "The native Broker child cleanup deadline expired while the exact child remained alive; pid=" +
                process.Id));
        }

        foreach (var pendingTask in pendingTasks)
        {
            if (!ObserveCleanupTask(
                    pendingTask.Name,
                    pendingTask.Task,
                    deadline,
                    RemainingMilliseconds(deadline),
                    failures))
            {
                failures.Add(new TimeoutException(
                    "The native Broker cleanup step exceeded the shared deadline: " +
                    pendingTask.Name));
            }
        }

        if (!ObserveCleanupTask(
                "Broker stderr drain",
                standardError,
                deadline,
                RemainingMilliseconds(deadline),
                failures))
        {
            failures.Add(new TimeoutException(
                "The native Broker stderr drain exceeded the shared cleanup deadline."));
        }
        else if (standardError.Status == TaskStatus.RanToCompletion && standardError.Result.Length != 0)
        {
            failures.Add(new InvalidOperationException(
                "The native Broker emitted a cleanup error marker: " +
                standardError.Result.Trim()));
        }

        return failures;
    }

    private static bool ObserveCleanupTask(
        string name,
        Task task,
        long deadline,
        int maximumWaitMilliseconds,
        ICollection<Exception> failures)
    {
        var wait = Math.Min(RemainingMilliseconds(deadline), maximumWaitMilliseconds);
        if (wait <= 0)
        {
            if (!task.IsCompleted)
            {
                return false;
            }

            try
            {
                task.GetAwaiter().GetResult();
                return true;
            }
            catch (Exception exception)
            {
                failures.Add(new InvalidOperationException(
                    "The native Broker cleanup step failed: " + name,
                    exception));
                return true;
            }
        }

        try
        {
            return task.Wait(wait);
        }
        catch (AggregateException exception)
        {
            failures.Add(new InvalidOperationException(
                "The native Broker cleanup step failed: " + name,
                exception.Flatten()));
            return true;
        }
    }

    private static bool TryHasExited(Process process, ICollection<Exception> failures)
    {
        try
        {
            process.Refresh();
            return process.HasExited;
        }
        catch (Exception exception)
        {
            failures.Add(new InvalidOperationException(
                "Unable to query native Broker child liveness; pid=" + process.Id,
                exception));
            return false;
        }
    }

    private static int RemainingMilliseconds(long deadline)
    {
        var ticks = deadline - Stopwatch.GetTimestamp();
        if (ticks <= 0)
        {
            return 0;
        }

        return (int)Math.Clamp(
            Math.Ceiling(ticks * 1000D / Stopwatch.Frequency),
            1,
            int.MaxValue);
    }

    private static void RunCase(string name, Action action, Action<bool, string> assert)
    {
        try
        {
            action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + DescribeException(exception));
        }
    }

    private static TException Expect<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException(
            "Expected " + typeof(TException).Name + " was not thrown.");
    }

    private static string DescribeException(Exception exception)
    {
        var parts = new List<string>();
        AddException(exception);
        return string.Join(" <- ", parts);

        void AddException(Exception current)
        {
            if (current is AggregateException aggregate)
            {
                parts.Add(current.GetType().Name + ": " + current.Message);
                foreach (var inner in aggregate.Flatten().InnerExceptions)
                {
                    AddException(inner);
                }

                return;
            }

            var code = current is BrokerPeerTrustException trust
                ? " code=" + trust.Code
                : current is System.ComponentModel.Win32Exception windows
                    ? " win32=" + windows.NativeErrorCode
                    : string.Empty;
            parts.Add(current.GetType().Name + code + ": " + current.Message);
            if (current.InnerException is not null)
            {
                AddException(current.InnerException);
            }
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
