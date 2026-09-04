using CodexGuardian.Trust;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

internal static class WindowsNamedPipePeerTrustOfflineTests
{
    private const uint ProcessId = 4321;
    private const uint SessionId = 4;
    private const ulong VolumeSerial = 0x1234;
    private const string UserSid = "S-1-5-21-111-222-333-1001";
    private const string OtherUserSid = "S-1-5-21-111-222-333-1002";
    private const string LogonSid = "S-1-5-5-1-2";
    private const string OtherLogonSid = "S-1-5-5-1-3";
    private const string ConnectionNonce =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string ReleaseId = "release-20260801";
    private const string ManifestSha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string ReleaseRoot = @"D:\CodexGuardian\release-20260801";
    private const string TimeoutCancellationChildProbeMarker =
        "PEER_TRUST_TIMEOUT_CANCELLATION_CHILD_OK";
    internal const string TimeoutCancellationChildProbeArgument =
        "--peer-trust-timeout-cancellation-child-probe";
    private static readonly DateTimeOffset CreationTime =
        new DateTimeOffset(2026, 8, 1, 12, 0, 0, TimeSpan.Zero).AddTicks(7);
    private static readonly DateTimeOffset UtcNow =
        new(2026, 8, 1, 12, 5, 0, TimeSpan.Zero);

    internal static bool IsTimeoutCancellationChildProbeInvocation(
        IReadOnlyList<string> arguments) =>
        arguments.Count == 1 &&
        string.Equals(
            arguments[0],
            TimeoutCancellationChildProbeArgument,
            StringComparison.Ordinal);

    internal static int RunTimeoutCancellationChildProbe()
    {
        try
        {
            var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
            var identity = CreateIdentity(release);
            var lease = CreateLease(release, Enumerable.Repeat(identity, 4));
            var platform = CreatePlatform(release, lease, BrokerPeerRole.Broker);
            platform.BlockHelloRead();
            platform.SynchronouslyBlockHelloRead = true;
            platform.ReadCancellationFailure = new InvalidOperationException(
                "test timeout cancellation callback failure");
            var pending = new WindowsNamedPipePeerVerifier(TimeSpan.FromSeconds(1))
                .BeginVerification(
                    platform,
                    NamedPipePeerKind.Server,
                    CreateExpectation(release));
            Exception? completionFailure = null;
            var completion = Task.Run(() => Capture(
                () => _ = CompletePending(pending),
                out completionFailure));
            Ensure(
                platform.CancellationRegistrationReady.Wait(TimeSpan.FromSeconds(5)),
                "timeout child did not register its cancellation callback");
            Ensure(
                completion.Wait(TimeSpan.FromSeconds(5)),
                "timeout child did not complete within its bounded deadline");
            Ensure(
                completionFailure is BrokerPeerTrustException timeoutFailure &&
                timeoutFailure.Code == "peer-handshake-timeout" &&
                timeoutFailure.InnerException is OperationCanceledException,
                "timeout child lost its bounded trust failure");
            DisposePending(pending);
            Ensure(
                platform.ReadCancellationCallbackCount == 1 &&
                platform.AbortCount == 1 &&
                platform.ActiveHelloReadCount == 0 &&
                platform.DisposeCallCount == 1 &&
                lease.DisposeCallCount == 1,
                "timeout child leaked cancellation or peer authority");
            Console.WriteLine(TimeoutCancellationChildProbeMarker);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                "PEER_TRUST_TIMEOUT_CANCELLATION_CHILD_FAILED " + exception);
            return 1;
        }
    }

    internal static Task RunAsync(Action<bool, string> assert)
    {
        RunCase("peer trust API cannot bypass the pre-hello capture", TestApiSurface, assert);
        RunCase("peer hello preserves exact Windows FILETIME", TestHelloProtocol, assert);
        RunCase("verified release capability is sealed and deep frozen", TestCapabilityProvenance, assert);
        RunCase("verified release requires all framework runtime artifacts", TestRequiredRuntimeArtifacts, assert);
        RunCase("verified release root identity fails closed", TestReleaseRootValidation, assert);
        RunCase("verified release artifact paths and file identities fail closed", TestArtifactValidation, assert);
        RunCase("broker server peer retains and revalidates exact identity", TestExactServerPeer, assert);
        RunCase("guardian client peer binds hello read to impersonation", TestExactClientPeer, assert);
        RunCase("hello read generation and direction fail closed", TestHelloReadEvidenceFailures, assert);
        RunCase("PID session and creation binding fail closed", TestKernelAndHelloBinding, assert);
        RunCase("medium-plus token policy and logon SID shape are enforced", TestProcessTokenPolicy, assert);
        RunCase("client impersonation token policy is exact", TestImpersonationPolicy, assert);
        RunCase("AppModel and runtime artifact drift fail closed", TestIdentityDrift, assert);
        RunCase("retained release handle membership is exact", TestRetainedHandleMembership, assert);
        RunCase("process identity and capability collections are deep frozen", TestDeepFreeze, assert);
        RunCase("pending peer transfers or releases its lease once", TestPendingLifetime, assert);
        RunCase("exact platform admission spans verifier instances", TestCrossVerifierAdmission, assert);
        RunCase("concurrent complete calls transfer authority once", TestConcurrentComplete, assert);
        RunCase("concurrent complete and dispose preserve exact ownership", TestConcurrentCompleteDispose, assert);
        RunCase("timeout cancellation callback is isolated in a child process", TestTimeoutCancellationCallbackChildProbe, assert);
        RunCase("concurrent revalidate and dispose preserve exact ownership", TestConcurrentRevalidateDispose, assert);
        RunCase("begin and revalidate abort failures retain exact connection authority", TestBeginAndRevalidateAbortFailures, assert);
        RunCase("platform and cleanup failures preserve fail-closed codes", TestPlatformAndCleanupFailures, assert);
        RunCase("first abort attempt timeout retains exact connection authority", TestFirstAbortAttemptTimeouts, assert);
        RunCase("second abort failure remains sticky fail-stop", TestSecondAbortFailureFailStop, assert);
        RunCase("verified dispose cleanup failures retain exact authority", TestVerifiedDisposeCleanupFailures, assert);
        WindowsNamedPipePeerTrustNativeProbeTests.RunIfRequested(assert);
        return Task.CompletedTask;
    }

    private static void TestTimeoutCancellationCallbackChildProbe()
    {
        Ensure(OperatingSystem.IsWindows(), "timeout cancellation child probe requires Windows");
        var executable = Path.Combine(AppContext.BaseDirectory, "CodexGuardian.Tests.exe");
        Ensure(File.Exists(executable), "timeout cancellation child probe apphost is unavailable");
        var startInfo = new ProcessStartInfo(executable)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = AppContext.BaseDirectory
        };
        startInfo.ArgumentList.Add(TimeoutCancellationChildProbeArgument);
        using var process = Process.Start(startInfo) ??
            throw new InvalidOperationException("Timeout cancellation child probe did not start.");
        WindowsNamedPipePeerTrustNativeProbeTests.WriteChildReceipt(
            process,
            "tests",
            "timeoutCancellation",
            executable,
            TimeoutCancellationChildProbeArgument);
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        var exited = process.WaitForExit((int)TimeSpan.FromSeconds(15).TotalMilliseconds);
        if (!exited)
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }

        var output = standardOutput.GetAwaiter().GetResult();
        var error = standardError.GetAwaiter().GetResult();
        Ensure(
            exited &&
            process.ExitCode == 0 &&
            output.Contains(TimeoutCancellationChildProbeMarker, StringComparison.Ordinal),
            "timeout cancellation child probe failed: stdout=" + output + " stderr=" + error);
    }

    private static void TestApiSurface()
    {
        Ensure(
            typeof(VerifiedReleaseManifest).GetConstructors().Length == 0,
            "verified manifest unexpectedly has a public constructor");
        Ensure(
            typeof(VerifiedReleaseArtifactSet).GetConstructors().Length == 0,
            "verified artifact set unexpectedly has a public constructor");
        Ensure(
            typeof(PipePeerHelloReadEvidence).GetConstructors().Length == 0,
            "hello read evidence unexpectedly has a public constructor");
        Ensure(
            typeof(WindowsNamedPipePeerVerifier)
                .GetMethods(BindingFlags.Instance | BindingFlags.Public)
                .All(method =>
                    method.Name != "Verify" &&
                    method.GetParameters().All(parameter =>
                        parameter.ParameterType != typeof(BrokerPeerHello))),
            "peer verifier still exposes an already-parsed hello shortcut");
        var complete = typeof(PendingPipePeerVerification).GetMethod(nameof(PendingPipePeerVerification.CompleteAsync));
        Ensure(
            complete is not null &&
            complete.GetParameters().All(parameter =>
                parameter.ParameterType != typeof(BrokerPeerHello)),
            "pending CompleteAsync accepts caller-supplied hello data");
        Ensure(
            typeof(VerifiedPipePeerIdentity).Name.Contains("Identity", StringComparison.Ordinal),
            "one-sided identity proof is named as full channel authority");
        Ensure(
            typeof(IDisposable).IsAssignableFrom(typeof(INamedPipePeerTrustPlatform)) &&
            typeof(OwnedPipePeerResources).GetMethod(
                "MarkConnectionUnusable",
                BindingFlags.Instance | BindingFlags.NonPublic) is not null,
            "peer connection capability is not exclusively retained with a Trust-owned poison latch");
        Ensure(
            WindowsNamedPipePeerVerifier.DefaultConnectionCapacity > 0,
            "peer verifier does not expose a bounded default connection capacity");
    }

    private static void TestHelloProtocol()
    {
        var hello = CreateHello(BrokerPeerRole.Broker);
        var encoded = BrokerPeerHelloProtocol.Serialize(hello);
        Ensure(encoded.Length <= BrokerPeerHelloProtocol.MaximumHelloBytes, "hello exceeded its bound");
        Ensure(BrokerPeerHelloProtocol.Parse(encoded) == hello, "hello FILETIME did not round-trip exactly");

        var json = Encoding.UTF8.GetString(encoded);
        Ensure(json.Contains("creationTimeFileTime", StringComparison.Ordinal), "hello omitted FILETIME");
        Ensure(!json.Contains("UnixMilliseconds", StringComparison.Ordinal), "hello still uses lossy Unix milliseconds");
        Ensure(
            json.Contains(CreationTime.ToFileTime().ToString("X16"), StringComparison.Ordinal),
            "hello did not serialize canonical FILETIME");

        var extra = Encoding.UTF8.GetBytes(json[..^1] + ",\"extra\":true}");
        ExpectCode("invalid-peer-hello", () => BrokerPeerHelloProtocol.Parse(extra));
        var duplicate = Encoding.UTF8.GetBytes(json.Replace(
            "\"kind\":\"peerHello\"",
            "\"kind\":\"peerHello\",\"kind\":\"peerHello\"",
            StringComparison.Ordinal));
        ExpectCode("invalid-peer-hello", () => BrokerPeerHelloProtocol.Parse(duplicate));
        var fileTime = CreationTime.ToFileTime().ToString("X16");
        var malformedFileTime = Encoding.UTF8.GetBytes(json.Replace(
            fileTime,
            fileTime[..15],
            StringComparison.Ordinal));
        ExpectCode("invalid-peer-hello", () => BrokerPeerHelloProtocol.Parse(malformedFileTime));
        ExpectCode(
            "invalid-peer-hello",
            () => BrokerPeerHelloProtocol.Serialize(hello with { ConnectionNonce = "short" }));
        ExpectCode(
            "invalid-peer-hello",
            () => BrokerPeerHelloProtocol.Parse(new byte[] { 0x7B, 0xFF, 0x7D }));
        ExpectCode(
            "invalid-peer-hello",
            () => BrokerPeerHelloProtocol.Parse(
                new byte[BrokerPeerHelloProtocol.MaximumHelloBytes + 1]));
    }

    private static void TestCapabilityProvenance()
    {
        var guardianArtifacts = CreateArtifacts(BrokerPeerRole.Guardian).ToArray();
        var brokerArtifacts = CreateArtifacts(BrokerPeerRole.Broker).ToArray();
        var manifest = VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId,
            ManifestSha256,
            CreateReleaseRoot(),
            CreateRoleDefinition(BrokerPeerRole.Guardian, guardianArtifacts),
            CreateRoleDefinition(BrokerPeerRole.Broker, brokerArtifacts));
        var broker = manifest.GetArtifactSet(BrokerPeerRole.Broker);
        brokerArtifacts[0] = brokerArtifacts[0] with
        {
            Sha256 = new string('f', 64)
        };
        Ensure(
            broker.Artifacts[0].Sha256 != brokerArtifacts[0].Sha256,
            "verified artifact capability retained a mutable parser array");
        Ensure(
            ReferenceEquals(manifest.GetArtifactSet(BrokerPeerRole.Broker), broker),
            "manifest did not return its preverified role capability");
        var constructor = typeof(BrokerPeerExpectation).GetConstructors().Single();
        Ensure(
            constructor.GetParameters()[2].ParameterType == typeof(VerifiedReleaseArtifactSet),
            "expectation accepts raw release DTOs instead of a capability");
    }

    private static void TestRequiredRuntimeArtifacts()
    {
        var broker = CreateArtifacts(BrokerPeerRole.Broker).ToArray();
        foreach (var kind in new[]
        {
            ReleaseArtifactKind.AppHostExe,
            ReleaseArtifactKind.ManagedEntryDll,
            ReleaseArtifactKind.DepsJson,
            ReleaseArtifactKind.RuntimeConfigJson
        })
        {
            var missing = broker.Where(artifact => artifact.Kind != kind).ToArray();
            ExpectInvalidManifest(CreateRoleDefinition(BrokerPeerRole.Broker, missing));
        }

        ExpectInvalidManifest(CreateRoleDefinition(
            BrokerPeerRole.Broker,
            broker.Take(1).ToArray()));
        var duplicateKind = broker.ToArray();
        duplicateKind[3] = duplicateKind[3] with { Kind = ReleaseArtifactKind.DepsJson };
        ExpectInvalidManifest(CreateRoleDefinition(BrokerPeerRole.Broker, duplicateKind));
        ExpectInvalidManifest(CreateRoleDefinition(
            BrokerPeerRole.Broker,
            broker,
            appHostRelativePath: "Wrong.Broker.exe"));
        ExpectInvalidManifest(CreateRoleDefinition(
            BrokerPeerRole.Broker,
            broker,
            managedEntryRelativePath: @"sub\CodexGuardian.Broker.dll"));

        var withDependency = broker.Append(new WindowsArtifactIdentity(
            ReleaseArtifactKind.RuntimeDependency,
            @"runtimes\win-x64\native\support.dll",
            Path.Combine(ReleaseRoot, @"runtimes\win-x64\native\support.dll"),
            FileAttributes.Archive,
            64 * 1024,
            new string('9', 64),
            VolumeSerial,
            new string('9', 32),
            1,
            true)).ToArray();
        var manifest = CreateManifest(broker: CreateRoleDefinition(BrokerPeerRole.Broker, withDependency));
        Ensure(
            manifest.GetArtifactSet(BrokerPeerRole.Broker).Artifacts.Count == 5,
            "signed runtime dependency was not preserved");
        var nestedReparse = withDependency.ToArray();
        nestedReparse[^1] = nestedReparse[^1] with { TraversalIsReparseFree = false };
        ExpectInvalidManifest(CreateRoleDefinition(BrokerPeerRole.Broker, nestedReparse));
    }

    private static void TestReleaseRootValidation()
    {
        var root = CreateReleaseRoot();
        var cases = new[]
        {
            root with { FinalPath = @"\\server\share\release" },
            root with { FinalPath = @"D:\" },
            root with { Attributes = FileAttributes.Archive },
            root with { Attributes = FileAttributes.Directory | FileAttributes.ReparsePoint },
            root with { Attributes = FileAttributes.Directory | FileAttributes.Device },
            root with { VolumeSerialNumber = 0 },
            root with { FileId = new string('0', 32) },
            root with { TraversalIsReparseFree = false }
        };
        foreach (var invalid in cases)
        {
            ExpectCode(
                "invalid-verified-release",
                () => CreateManifest(root: invalid));
        }
    }

    private static void TestArtifactValidation()
    {
        var broker = CreateArtifacts(BrokerPeerRole.Broker).ToArray();
        var mutations = new List<WindowsArtifactIdentity[]>
        {
            Replace(broker, 1, artifact => artifact with { FinalPath = @"D:\outside\CodexGuardian.Broker.dll" }),
            Replace(broker, 1, artifact => artifact with { VolumeSerialNumber = VolumeSerial + 1 }),
            Replace(broker, 1, artifact => artifact with { LinkCount = 0 }),
            Replace(broker, 1, artifact => artifact with { LinkCount = 2 }),
            Replace(broker, 1, artifact => artifact with { Attributes = FileAttributes.Directory }),
            Replace(broker, 1, artifact => artifact with { Attributes = FileAttributes.ReparsePoint }),
            Replace(broker, 1, artifact => artifact with { Attributes = FileAttributes.Device }),
            Replace(broker, 1, artifact => artifact with { FileId = new string('0', 32) }),
            Replace(broker, 1, artifact => artifact with { FinalPath = broker[0].FinalPath }),
            Replace(broker, 1, artifact => artifact with { FileId = broker[0].FileId }),
            Replace(broker, 1, artifact => artifact with { TraversalIsReparseFree = false }),
            Replace(broker, 1, artifact => artifact with { RelativePath = @"..\evil.dll" })
        };
        foreach (var invalid in mutations)
        {
            ExpectInvalidManifest(CreateRoleDefinition(BrokerPeerRole.Broker, invalid));
        }

        var reserved = broker.Append(new WindowsArtifactIdentity(
            ReleaseArtifactKind.RuntimeDependency,
            "CON.dll",
            Path.Combine(ReleaseRoot, "CON.dll"),
            FileAttributes.Archive,
            1,
            new string('8', 64),
            VolumeSerial,
            new string('8', 32),
            1,
            true)).ToArray();
        ExpectInvalidManifest(CreateRoleDefinition(BrokerPeerRole.Broker, reserved));
    }

    private static void TestExactServerPeer()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var lease = CreateLease(release, Enumerable.Repeat(identity, 6));
        var platform = CreatePlatform(
            release,
            lease,
            BrokerPeerRole.Broker,
            Enumerable.Repeat(CreateKernel(), 6));
        var verifier = new WindowsNamedPipePeerVerifier();
        var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        Ensure(lease.CaptureCount == 2, "begin did not double-capture the broker identity");
        Ensure(platform.HelloReadCount == 0, "begin consumed hello before retaining the peer");
        var peer = CompletePending(pending);
        DisposePending(pending);
        Ensure(lease.CaptureCount == 4, "complete did not perform a second double capture");
        Ensure(platform.HelloReadCount == 1, "server hello was not consumed exactly once");
        Ensure(platform.ImpersonationTransactionCount == 0, "client attempted to impersonate a server");
        Ensure(platform.LastEvidence?.IsCleared == true, "hello buffer was not cleared after parsing");
        Ensure(ReferenceEquals(peer.InitialIdentity, identity), "exact broker identity was not retained");
        Ensure(ReferenceEquals(peer.Revalidate(), identity), "exact broker identity did not revalidate");
        peer.Dispose();
        peer.Dispose();
        Ensure(lease.DisposeCallCount == 1, "broker identity lease was not disposed exactly once");
        Expect<ObjectDisposedException>(() => _ = peer.Revalidate());
    }

    private static void TestExactClientPeer()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Guardian);
        var identity = CreateIdentity(release);
        var lease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var platform = CreatePlatform(
            release,
            lease,
            BrokerPeerRole.Guardian,
            Enumerable.Repeat(CreateKernel(), 4),
            impersonatedToken: CreateImpersonatedToken(identity.Token));
        var verifier = new WindowsNamedPipePeerVerifier();
        var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Client,
            CreateExpectation(release));
        Ensure(platform.ImpersonationTransactionCount == 0, "begin impersonated before the hello read");
        using var peer = CompletePending(pending);
        DisposePending(pending);
        Ensure(platform.ImpersonationTransactionCount == 1, "client hello was not bound to one atomic impersonation transaction");
        var readIndex = platform.Events.IndexOf("hello.read");
        var tokenIndex = platform.Events.IndexOf("impersonation.capture");
        Ensure(readIndex >= 0 && tokenIndex == readIndex + 1, "another platform operation intervened between hello read and token capture");
    }

    private static void TestHelloReadEvidenceFailures()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);

        var alreadyReadLease = CreateLease(release, Enumerable.Repeat(identity, 2));
        var alreadyRead = CreatePlatform(release, alreadyReadLease, BrokerPeerRole.Broker, initialReadGeneration: 1);
        ExpectCode(
            "peer-hello-read-order-invalid",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                alreadyRead,
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(alreadyReadLease.DisposeCallCount == 0, "begin disposed a lease that was never opened");
        Ensure(alreadyRead.AbortCount == 1, "pre-read connection was not aborted");

        var interleavedLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var interleaved = CreatePlatform(release, interleavedLease, BrokerPeerRole.Broker);
        interleaved.FramesConsumedPerHello = 2;
        ExpectCompleteCode("peer-hello-read-order-invalid", interleaved, release);
        Ensure(interleavedLease.DisposeCallCount == 1, "interleaved hello read leaked the lease");

        var driftLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var drift = CreatePlatform(release, driftLease, BrokerPeerRole.Broker);
        drift.EvidenceKernelAfter = CreateKernel(processId: ProcessId + 1);
        ExpectCompleteCode("peer-kernel-identity-changed", drift, release);

        var guardianRelease = CreateManifest().GetArtifactSet(BrokerPeerRole.Guardian);
        var guardianIdentity = CreateIdentity(guardianRelease);
        var missingTokenLease = CreateLease(guardianRelease, Enumerable.Repeat(guardianIdentity, 4));
        var missingToken = CreatePlatform(guardianRelease, missingTokenLease, BrokerPeerRole.Guardian);
        missingToken.OmitClientToken = true;
        ExpectCompleteCode("peer-hello-read-invalid", missingToken, guardianRelease);

        var serverTokenLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var serverToken = CreatePlatform(release, serverTokenLease, BrokerPeerRole.Broker);
        serverToken.IncludeServerToken = true;
        ExpectCompleteCode("peer-hello-read-invalid", serverToken, release);
    }

    private static void TestKernelAndHelloBinding()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);

        var pidMismatchLease = CreateLease(release, Enumerable.Repeat(identity, 2));
        ExpectCode(
            "peer-kernel-identity-mismatch",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(
                    release,
                    pidMismatchLease,
                    BrokerPeerRole.Broker,
                    new[] { CreateKernel(processId: ProcessId + 1) }),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));

        var beginDriftLease = CreateLease(release, Enumerable.Repeat(identity, 2));
        ExpectCode(
            "peer-kernel-identity-changed",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(
                    release,
                    beginDriftLease,
                    BrokerPeerRole.Broker,
                    new[] { CreateKernel(), CreateKernel(sessionId: SessionId + 1) }),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));

        foreach (var hello in new[]
        {
            CreateHello(BrokerPeerRole.Broker) with { ProcessId = ProcessId + 1 },
            CreateHello(BrokerPeerRole.Broker) with { SessionId = SessionId + 1 },
            CreateHello(BrokerPeerRole.Broker) with { CreationTimeUtc = CreationTime.AddTicks(1) }
        })
        {
            var lease = CreateLease(release, Enumerable.Repeat(identity, 4));
            var platform = CreatePlatform(release, lease, BrokerPeerRole.Broker, hello: hello);
            var expectedCode = hello.ProcessId != ProcessId
                ? "peer-process-id-mismatch"
                : "peer-hello-mismatch";
            ExpectCompleteCode(expectedCode, platform, release);
        }

        var completeDriftLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var completeDrift = CreatePlatform(
            release,
            completeDriftLease,
            BrokerPeerRole.Broker,
            new[]
            {
                CreateKernel(),
                CreateKernel(),
                CreateKernel(processId: ProcessId + 1)
            });
        ExpectCompleteCode("peer-kernel-identity-changed", completeDrift, release);
    }

    private static void TestProcessTokenPolicy()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var mediumPlus = CreateProcessToken() with { IntegrityLevelRid = 0x2100 };
        var mediumIdentity = CreateIdentity(release, token: mediumPlus);
        var mediumLease = CreateLease(release, Enumerable.Repeat(mediumIdentity, 4));
        using (CompletePeer(
            CreatePlatform(release, mediumLease, BrokerPeerRole.Broker),
            NamedPipePeerKind.Server,
            CreateExpectation(release, token: mediumPlus)))
        {
        }

        var invalidTokens = new[]
        {
            CreateProcessToken() with { IntegrityLevelRid = 0x1000 },
            CreateProcessToken() with { IntegrityLevelRid = 0x3000 },
            CreateProcessToken() with { ElevationType = (WindowsTokenElevationType)99 },
            CreateProcessToken() with { TokenType = (WindowsTokenType)99 },
            CreateProcessToken() with { LogonSid = UserSid },
            CreateProcessToken() with { LogonSidGroupCount = 0 },
            CreateProcessToken() with { LogonSidGroupCount = 2 },
            CreateProcessToken() with { AppContainerSid = "S-1-15-2-1" },
            CreateProcessToken() with { UiAccess = true },
            CreateProcessToken() with
            {
                ElevationType = WindowsTokenElevationType.Full,
                IsElevated = true
            }
        };
        foreach (var token in invalidTokens)
        {
            var lease = CreateLease(release, Enumerable.Repeat(CreateIdentity(release), 2));
            ExpectCode(
                "invalid-peer-expectation",
                () => new WindowsNamedPipePeerVerifier().BeginVerification(
                    CreatePlatform(release, lease, BrokerPeerRole.Broker),
                    NamedPipePeerKind.Server,
                    CreateExpectation(release, token: token)));
        }

        var expected = CreateProcessToken();
        var actualCases = new[]
        {
            ("peer-user-mismatch", expected with { UserSid = OtherUserSid }),
            ("peer-logon-mismatch", expected with { LogonSid = OtherLogonSid }),
            ("peer-logon-mismatch", expected with { AuthenticationId = 99UL })
        };
        foreach (var testCase in actualCases)
        {
            var actualIdentity = CreateIdentity(release, token: testCase.Item2);
            var lease = CreateLease(release, new[] { actualIdentity });
            ExpectCode(
                testCase.Item1,
                () => new WindowsNamedPipePeerVerifier().BeginVerification(
                    CreatePlatform(release, lease, BrokerPeerRole.Broker),
                    NamedPipePeerKind.Server,
                    CreateExpectation(release)));
            Ensure(lease.DisposeCallCount == 1, "failed token identity leaked the retained lease");
        }
    }

    private static void TestImpersonationPolicy()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Guardian);
        var identity = CreateIdentity(release);
        var baseToken = CreateImpersonatedToken(identity.Token);
        var cases = new[]
        {
            ("impersonated-peer-mismatch", baseToken with { UserSid = OtherUserSid }),
            ("impersonated-peer-mismatch", baseToken with { AuthenticationId = 99UL }),
            ("impersonated-token-policy", baseToken with { LogonSid = UserSid }),
            ("impersonated-token-policy", baseToken with { LogonSidGroupCount = 2 }),
            ("impersonated-token-policy", identity.Token),
            ("impersonated-token-policy", baseToken with
            {
                ImpersonationLevel = WindowsSecurityImpersonationLevel.Impersonation
            }),
            ("impersonated-token-policy", baseToken with
            {
                ImpersonationLevel = (WindowsSecurityImpersonationLevel)99
            })
        };
        foreach (var testCase in cases)
        {
            var lease = CreateLease(release, Enumerable.Repeat(identity, 4));
            var platform = CreatePlatform(
                release,
                lease,
                BrokerPeerRole.Guardian,
                impersonatedToken: testCase.Item2);
            ExpectCompleteCode(testCase.Item1, platform, release);
            Ensure(lease.DisposeCallCount == 1, "failed impersonation leaked the retained lease");
        }
    }

    private static void TestIdentityDrift()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var stable = CreateIdentity(release);
        var packaged = CreateIdentity(
            release,
            appModel: new WindowsAppModelIdentity(
                WindowsAppModelKind.Packaged,
                "CodexGuardian.Broker_1.0.0.0_x64__example",
                "CodexGuardian.Broker_example"));
        var packagedLease = CreateLease(release, new[] { packaged });
        ExpectCode(
            "peer-appmodel-mismatch",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(release, packagedLease, BrokerPeerRole.Broker),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));

        var changedArtifacts = release.Artifacts.ToArray();
        changedArtifacts[2] = changedArtifacts[2] with { Sha256 = new string('d', 64) };
        var changed = CreateIdentity(release, artifacts: changedArtifacts);
        var changedLease = CreateLease(release, new[] { changed });
        ExpectCode(
            "peer-artifact-mismatch",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(release, changedLease, BrokerPeerRole.Broker),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));

        var unmapped = CreateIdentity(release, imageFileObjectIsExact: false);
        var unmappedLease = CreateLease(release, new[] { unmapped });
        ExpectCode(
            "peer-image-mapping-mismatch",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(release, unmappedLease, BrokerPeerRole.Broker),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(unmappedLease.DisposeCallCount == 1, "unmapped process image leaked the retained lease");

        var traversalArtifacts = release.Artifacts.ToArray();
        traversalArtifacts[1] = traversalArtifacts[1] with { TraversalIsReparseFree = false };
        var traversalIdentity = CreateIdentity(release, artifacts: traversalArtifacts);
        var traversalLease = CreateLease(release, new[] { traversalIdentity });
        ExpectCode(
            "peer-artifact-invalid",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(release, traversalLease, BrokerPeerRole.Broker),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));

        var archiveOnly = release.Artifacts.ToArray();
        archiveOnly[0] = archiveOnly[0] with { Attributes = FileAttributes.Normal };
        var archiveIdentity = CreateIdentity(release, artifacts: archiveOnly);
        var archiveLease = CreateLease(release, Enumerable.Repeat(archiveIdentity, 4));
        using (CompletePeer(
            CreatePlatform(release, archiveLease, BrokerPeerRole.Broker),
            NamedPipePeerKind.Server,
            CreateExpectation(release)))
        {
        }

        var rootChanged = CreateIdentity(
            release,
            releaseRoot: release.Root with { FileId = new string('7', 32) });
        var rootLease = CreateLease(release, new[] { rootChanged });
        ExpectCode(
            "peer-artifact-mismatch",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(release, rootLease, BrokerPeerRole.Broker),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));

        var laterArtifacts = release.Artifacts.ToArray();
        laterArtifacts[1] = laterArtifacts[1] with { TraversalIsReparseFree = false };
        var later = CreateIdentity(release, artifacts: laterArtifacts);
        var laterLease = CreateLease(
            release,
            new[] { stable, stable, stable, stable, later });
        var laterPlatform = CreatePlatform(release, laterLease, BrokerPeerRole.Broker);
        using var peer = CompletePeer(
            laterPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        ExpectCode("peer-artifact-invalid", () => _ = peer.Revalidate());
        Ensure(laterLease.DisposeCallCount == 1, "failed revalidation retained authority");
        Expect<ObjectDisposedException>(() => _ = peer.Revalidate());
    }

    private static void TestRetainedHandleMembership()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var expectedPaths = release.Artifacts.Select(artifact => artifact.RelativePath).ToArray();
        var cases = new[]
        {
            new RetainedReleaseHandleSet(
                release.Root with { FileId = new string('7', 32) },
                expectedPaths),
            new RetainedReleaseHandleSet(release.Root, expectedPaths.Take(3).ToArray()),
            new RetainedReleaseHandleSet(
                release.Root,
                expectedPaths.Take(3).Append("unexpected.dll").ToArray()),
            new RetainedReleaseHandleSet(
                release.Root,
                expectedPaths.Take(3).Append(expectedPaths[0]).ToArray())
        };
        foreach (var handles in cases)
        {
            var lease = new FakeRetainedPeerIdentityLease(
                new[] { identity },
                handles);
            ExpectCode(
                "peer-retained-handles-invalid",
                () => new WindowsNamedPipePeerVerifier().BeginVerification(
                    CreatePlatform(release, lease, BrokerPeerRole.Broker),
                    NamedPipePeerKind.Server,
                    CreateExpectation(release)));
            Ensure(lease.DisposeCallCount == 1, "invalid retained handle set leaked the lease");
        }
    }

    private static void TestDeepFreeze()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var mutable = release.Artifacts.ToArray();
        var identity = CreateIdentity(release, artifacts: mutable);
        var originalHash = identity.Artifacts[0].Sha256;
        mutable[0] = mutable[0] with { Sha256 = new string('f', 64) };
        Ensure(identity.Artifacts[0].Sha256 == originalHash, "process identity retained a mutable artifact array");

        var retainedPaths = release.Artifacts.Select(artifact => artifact.RelativePath).ToArray();
        var handles = new RetainedReleaseHandleSet(release.Root, retainedPaths);
        retainedPaths[0] = "unexpected.exe";
        Ensure(
            handles.ArtifactRelativePaths[0] != retainedPaths[0],
            "retained handle membership retained a mutable path array");
    }

    private static void TestPendingLifetime()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var abandonedLease = CreateLease(release, Enumerable.Repeat(identity, 2));
        var abandonedPlatform = CreatePlatform(release, abandonedLease, BrokerPeerRole.Broker);
        var abandoned = new WindowsNamedPipePeerVerifier().BeginVerification(
            abandonedPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        DisposePending(abandoned);
        DisposePending(abandoned);
        Ensure(abandonedLease.DisposeCallCount == 1, "abandoned pending peer did not release once");
        Ensure(abandonedPlatform.AbortCount == 1, "abandoned pending peer did not abort once");
        Expect<ObjectDisposedException>(() => CompletePending(abandoned));

        var transferredLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var transferred = new WindowsNamedPipePeerVerifier().BeginVerification(
            CreatePlatform(release, transferredLease, BrokerPeerRole.Broker),
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var peer = CompletePending(transferred);
        Expect<ObjectDisposedException>(() => CompletePending(transferred));
        DisposePending(transferred);
        Ensure(transferredLease.DisposeCallCount == 0, "completed pending peer disposed a transferred lease");
        peer.Dispose();
        Ensure(transferredLease.DisposeCallCount == 1, "verified peer did not own the transferred lease once");

        var boundedLease = CreateLease(release, Enumerable.Repeat(identity, 2));
        var boundedPlatform = CreatePlatform(release, boundedLease, BrokerPeerRole.Broker);
        var boundedVerifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            beforeAuthorityTransfer: null,
            afterAuthorityTransfer: null,
            maximumConnections: 1);
        var boundedPending = boundedVerifier.BeginVerification(
            boundedPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var eventCountBeforeDuplicate = boundedPlatform.Events.Count;
        ExpectCode(
            "peer-trust-connection-already-owned",
            () => boundedVerifier.BeginVerification(
                boundedPlatform,
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(
            boundedPlatform.Events.Count == eventCountBeforeDuplicate,
            "duplicate connection admission touched the already-owned platform");

        var overflowLease = CreateLease(release, new[] { identity });
        var overflowPlatform = CreatePlatform(release, overflowLease, BrokerPeerRole.Broker);
        ExpectCode(
            "peer-trust-capacity-exceeded",
            () => boundedVerifier.BeginVerification(
                overflowPlatform,
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(
            overflowPlatform.Events.Count == 0 &&
            overflowPlatform.HelloReadCount == 0 &&
            overflowLease.DisposeCallCount == 0,
            "capacity rejection touched caller-owned connection state");
        overflowPlatform.Dispose();
        DisposePending(boundedPending);
        Ensure(boundedLease.DisposeCallCount == 1, "bounded admission did not release its exact lease once");
        Ensure(
            boundedVerifier.Health is
            {
                IsUnhealthy: false,
                ActiveConnectionCount: 0,
                QuarantinedHandshakeCount: 0,
                Capacity: 1
            },
            "healthy bounded admission did not return to zero ownership");
    }

    private static void TestConcurrentComplete()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var lease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var platform = CreatePlatform(release, lease, BrokerPeerRole.Broker);
        platform.BlockHelloRead();
        var pending = new WindowsNamedPipePeerVerifier().BeginVerification(
            platform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        VerifiedPipePeerIdentity? firstPeer = null;
        Exception? firstFailure = null;
        Exception? secondFailure = null;
        var first = Task.Run(() => Capture(() => firstPeer = CompletePending(pending), out firstFailure));
        Ensure(platform.HelloReadEntered.Wait(TimeSpan.FromSeconds(5)), "first Complete did not enter hello read");
        var second = Task.Run(() => Capture(() => _ = CompletePending(pending), out secondFailure));
        platform.ReleaseHelloRead();
        Ensure(Task.WaitAll(new[] { first, second }, TimeSpan.FromSeconds(10)), "concurrent Complete calls did not finish");
        Ensure(firstFailure is null && firstPeer is not null, "first Complete did not win authority");
        Ensure(secondFailure is ObjectDisposedException, "second Complete did not fail terminally");
        Ensure(platform.HelloReadCount == 1, "two Complete calls consumed two hello frames");
        Ensure(lease.DisposeCallCount == 0, "pending disposed a transferred lease during concurrent Complete");
        DisposePending(pending);
        firstPeer!.Dispose();
        Ensure(lease.DisposeCallCount == 1, "concurrent Complete did not preserve exact lease ownership");
    }

    private static void TestCrossVerifierAdmission()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var lease = CreateLease(release, Enumerable.Repeat(identity, 2));
        var platform = CreatePlatform(release, lease, BrokerPeerRole.Broker);
        var firstVerifier = new WindowsNamedPipePeerVerifier();
        var secondVerifier = new WindowsNamedPipePeerVerifier();
        var globalAdmissionBaseline = GetGlobalAdmissionCount();
        var pending = firstVerifier.BeginVerification(
            platform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        Exception? cleanupFailure = null;
        try
        {
            Ensure(
                GetGlobalAdmissionCount() == globalAdmissionBaseline + 1,
                "first verifier did not reserve the exact platform globally");
            var eventCount = platform.Events.Count;
            var readGenerationCount = platform.ReadGenerationReadCount;
            var helloReadCount = platform.HelloReadCount;
            var abortCount = platform.AbortCount;
            var disposeCount = platform.DisposeCallCount;
            ExpectCode(
                "peer-trust-connection-already-owned",
                () => secondVerifier.BeginVerification(
                    platform,
                    NamedPipePeerKind.Server,
                    CreateExpectation(release)));
            Ensure(
                platform.Events.Count == eventCount &&
                platform.ReadGenerationReadCount == readGenerationCount &&
                platform.HelloReadCount == helloReadCount &&
                platform.AbortCount == abortCount &&
                platform.DisposeCallCount == disposeCount &&
                lease.DisposeCallCount == 0,
                "cross-verifier rejection touched caller-owned platform state");
        }
        finally
        {
            Capture(() => DisposePending(pending), out cleanupFailure);
        }

        Ensure(cleanupFailure is null, "first verifier could not release its exact admission");
        Ensure(
            GetGlobalAdmissionCount() == globalAdmissionBaseline &&
            lease.DisposeCallCount == 1 &&
            platform.DisposeCallCount == 1,
            "normal release did not remove the exact global admission");
    }

    private static void TestConcurrentCompleteDispose()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var quarantineBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;

        using var beforeTransferEntered = new ManualResetEventSlim(false);
        using var allowBeforeTransfer = new ManualResetEventSlim(false);
        var disposeWinsLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var disposeWinsPlatform = CreatePlatform(
            release,
            disposeWinsLease,
            BrokerPeerRole.Broker);
        var disposeWinsVerifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            () =>
            {
                beforeTransferEntered.Set();
                allowBeforeTransfer.Wait();
            },
            null);
        var disposeWinsPending = disposeWinsVerifier.BeginVerification(
            disposeWinsPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        VerifiedPipePeerIdentity? disposedPeer = null;
        Exception? disposeWinsFailure = null;
        var transferAttempt = Task.Run(() => Capture(
            () => disposedPeer = CompletePending(disposeWinsPending),
            out disposeWinsFailure));
        Ensure(beforeTransferEntered.Wait(TimeSpan.FromSeconds(5)), "Complete did not reach the pre-transfer barrier");
        var disposeWins = disposeWinsPending.DisposeAsync().AsTask();
        allowBeforeTransfer.Set();
        Ensure(
            Task.WaitAll(new[] { transferAttempt, disposeWins }, TimeSpan.FromSeconds(5)),
            "pre-transfer Dispose race did not finish");
        Ensure(
            disposedPeer is null &&
            disposeWinsFailure is BrokerPeerTrustException disposed &&
            disposed.Code == "peer-handshake-cancelled",
            "Dispose did not win the pre-transfer CAS");
        Ensure(disposeWinsLease.DisposeCallCount == 1, "pre-transfer cancellation did not release once");

        using var failedTransferEntered = new ManualResetEventSlim(false);
        using var allowFailedTransfer = new ManualResetEventSlim(false);
        var failedTransferLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var failedTransferPlatform = CreatePlatform(
            release,
            failedTransferLease,
            BrokerPeerRole.Broker);
        failedTransferPlatform.AbortFailure = new IOException("test pre-transfer abort failure");
        failedTransferPlatform.AbortFailuresRemaining = 1;
        failedTransferPlatform.BlockAbortAttempt(2);
        var failedTransferVerifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            () =>
            {
                failedTransferEntered.Set();
                allowFailedTransfer.Wait();
            },
            null);
        var failedTransferPending = failedTransferVerifier.BeginVerification(
            failedTransferPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        Exception? failedCompleteFailure = null;
        Exception? failedDisposeFailure = null;
        var failedComplete = Task.Run(() => Capture(
            () => _ = CompletePending(failedTransferPending),
            out failedCompleteFailure));
        Ensure(
            failedTransferEntered.Wait(TimeSpan.FromSeconds(5)),
            "abort-failed Complete did not reach the pre-transfer barrier");
        var failedDispose = Task.Run(() => Capture(
            () => DisposePending(failedTransferPending),
            out failedDisposeFailure));
        Ensure(
            SpinWait.SpinUntil(() => failedTransferPlatform.AbortCount == 1, TimeSpan.FromSeconds(5)),
            "pre-transfer Dispose did not attempt the first abort");
        allowFailedTransfer.Set();
        Ensure(
            Task.WaitAll(new[] { failedComplete, failedDispose }, TimeSpan.FromSeconds(5)),
            "abort-failed pre-transfer race did not publish a shared terminal result");
        Ensure(
            failedCompleteFailure is BrokerPeerTrustException failedTransferFailure &&
            failedTransferFailure.Code == "peer-handshake-abort-failed" &&
            ReferenceEquals(failedCompleteFailure, failedDisposeFailure) &&
            failedCompleteFailure is not ObjectDisposedException,
            "pre-transfer abort failure was masked or not shared");
        Ensure(
            failedTransferPlatform.BlockedAbortEntered.Wait(TimeSpan.FromSeconds(5)),
            "pre-transfer quarantine retry did not run in the background");
        Ensure(failedTransferLease.DisposeCallCount == 0, "pre-transfer quarantine released the lease early");
        Ensure(
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline + 1,
            "pre-transfer abort failure did not retain one quarantine entry");
        failedTransferPlatform.ReleaseBlockedAbort();
        Ensure(
            SpinWait.SpinUntil(
                () => failedTransferLease.DisposeCallCount == 1 &&
                      failedTransferPlatform.DisposeCallCount == 1 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                TimeSpan.FromSeconds(5)),
            "pre-transfer quarantine did not close exact resources after retry");
        var repeatedFailedDispose = ExpectCode(
            "peer-handshake-abort-failed",
            () => DisposePending(failedTransferPending));
        Ensure(
            ReferenceEquals(failedCompleteFailure, repeatedFailedDispose),
            "pre-transfer abort failure changed across repeated Dispose");

        using var afterTransferEntered = new ManualResetEventSlim(false);
        using var allowAfterTransfer = new ManualResetEventSlim(false);
        var transferWinsLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var transferWinsPlatform = CreatePlatform(
            release,
            transferWinsLease,
            BrokerPeerRole.Broker);
        var transferWinsVerifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            null,
            () =>
            {
                afterTransferEntered.Set();
                allowAfterTransfer.Wait();
            });
        var transferWinsPending = transferWinsVerifier.BeginVerification(
            transferWinsPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        VerifiedPipePeerIdentity? transferredPeer = null;
        Exception? transferWinsFailure = null;
        var successfulTransfer = Task.Run(() => Capture(
            () => transferredPeer = CompletePending(transferWinsPending),
            out transferWinsFailure));
        Ensure(afterTransferEntered.Wait(TimeSpan.FromSeconds(5)), "Complete did not reach the post-transfer barrier");
        var postTransferDispose = transferWinsPending.DisposeAsync().AsTask();
        Ensure(
            !postTransferDispose.Wait(TimeSpan.FromMilliseconds(250)),
            "Dispose published success before transfer commit finished");
        Ensure(transferWinsLease.DisposeCallCount == 0, "transfer-committing Dispose stole the peer lease");
        allowAfterTransfer.Set();
        Ensure(
            Task.WaitAll(new[] { successfulTransfer, postTransferDispose }, TimeSpan.FromSeconds(5)),
            "committed transfer did not publish one shared terminal result");
        Ensure(transferWinsFailure is null && transferredPeer is not null, "successful transfer lost peer authority");
        transferredPeer!.Dispose();
        Ensure(transferWinsLease.DisposeCallCount == 1, "transferred peer did not release its lease once");

        var hookFailure = new InvalidOperationException("test post-transfer hook failure");
        var throwingHookLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var throwingHookPlatform = CreatePlatform(
            release,
            throwingHookLease,
            BrokerPeerRole.Broker);
        var throwingHookVerifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            null,
            () => throw hookFailure);
        var throwingHookPending = throwingHookVerifier.BeginVerification(
            throwingHookPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var observedHookFailure = Expect<InvalidOperationException>(
            () => _ = CompletePending(throwingHookPending));
        Ensure(
            ReferenceEquals(hookFailure, observedHookFailure),
            "throwing post-transfer hook was replaced by an unrelated failure");
        DisposePending(throwingHookPending);
        Ensure(
            throwingHookLease.DisposeCallCount == 1 &&
            throwingHookPlatform.DisposeCallCount == 1 &&
            throwingHookPlatform.AbortCount == 1 &&
            throwingHookVerifier.Health is
            {
                IsUnhealthy: false,
                ActiveConnectionCount: 0,
                QuarantinedHandshakeCount: 0
            },
            "throwing post-transfer hook leaked peer resources or admission authority");

        var cancellationLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var cancellationPlatform = CreatePlatform(
            release,
            cancellationLease,
            BrokerPeerRole.Broker);
        cancellationPlatform.BlockHelloRead();
        cancellationPlatform.SynchronouslyBlockHelloRead = true;
        var cancellationPending = new WindowsNamedPipePeerVerifier().BeginVerification(
            cancellationPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        Exception? cancellationFailure = null;
        var completing = Task.Run(() => Capture(
            () => _ = CompletePending(cancellationPending),
            out cancellationFailure));
        Ensure(
            cancellationPlatform.HelloReadEntered.Wait(TimeSpan.FromSeconds(5)),
            "Complete did not enter the blocked hello read");
        var disposing = cancellationPending.DisposeAsync().AsTask();
        Ensure(
            Task.WaitAll(new[] { completing, disposing }, TimeSpan.FromSeconds(5)),
            "DisposeAsync could not cancel a peer that never sent hello");
        Ensure(
            cancellationFailure is BrokerPeerTrustException cancelled &&
            cancelled.Code == "peer-handshake-cancelled",
            "shutdown cancellation lost its bounded trust failure");
        Ensure(cancellationLease.DisposeCallCount == 1, "cancelled handshake did not release once");
        Ensure(cancellationPlatform.AbortCount == 1, "cancelled handshake was not aborted exactly once");
        Ensure(cancellationPlatform.ActiveHelloReadCount == 0, "shutdown leaked an active hello read");

        var throwingCancellationLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var throwingCancellationPlatform = CreatePlatform(
            release,
            throwingCancellationLease,
            BrokerPeerRole.Broker);
        throwingCancellationPlatform.BlockHelloRead();
        throwingCancellationPlatform.SynchronouslyBlockHelloRead = true;
        throwingCancellationPlatform.ReadCancellationFailure = new InvalidOperationException(
            "test cancellation callback failure");
        var throwingCancellationPending = new WindowsNamedPipePeerVerifier().BeginVerification(
            throwingCancellationPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        Exception? throwingCancellationCompleteFailure = null;
        Exception? throwingCancellationDisposeFailure = null;
        var throwingCancellationComplete = Task.Run(() => Capture(
            () => _ = CompletePending(throwingCancellationPending),
            out throwingCancellationCompleteFailure));
        Ensure(
            throwingCancellationPlatform.CancellationRegistrationReady.Wait(TimeSpan.FromSeconds(5)),
            "throwing-cancellation Complete did not register its cancellation callback");
        var throwingCancellationDispose = Task.Run(() => Capture(
            () => DisposePending(throwingCancellationPending),
            out throwingCancellationDisposeFailure));
        Ensure(
            Task.WaitAll(
                new[] { throwingCancellationComplete, throwingCancellationDispose },
                TimeSpan.FromSeconds(5)),
            "throwing cancellation callback escaped the shared terminal path");
        Ensure(
            throwingCancellationCompleteFailure is BrokerPeerTrustException throwingCancelled &&
            throwingCancelled.Code == "peer-handshake-cancelled" &&
            throwingCancellationDisposeFailure is null &&
            throwingCancellationPlatform.ReadCancellationCallbackCount == 1 &&
            throwingCancellationPlatform.AbortCount == 1 &&
            throwingCancellationPlatform.ActiveHelloReadCount == 0 &&
            throwingCancellationLease.DisposeCallCount == 1 &&
            throwingCancellationPlatform.DisposeCallCount == 1,
            "throwing cancellation callback changed abort or terminal ownership");
        DisposePending(throwingCancellationPending);

        var callerLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var callerPlatform = CreatePlatform(release, callerLease, BrokerPeerRole.Broker);
        callerPlatform.BlockHelloRead();
        callerPlatform.SynchronouslyBlockHelloRead = true;
        callerPlatform.ReadCancellationFailure = new InvalidOperationException(
            "test caller cancellation callback failure");
        var callerPending = new WindowsNamedPipePeerVerifier().BeginVerification(
            callerPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        using var callerCancellation = new CancellationTokenSource();
        Exception? callerFailure = null;
        var callerCompleting = Task.Run(() => Capture(
            () => _ = CompletePending(callerPending, callerCancellation.Token),
            out callerFailure));
        Ensure(
            callerPlatform.CancellationRegistrationReady.Wait(TimeSpan.FromSeconds(5)),
            "caller-cancelled Complete did not register its cancellation callback");
        Exception? callerCancelInvocationFailure = null;
        Capture(callerCancellation.Cancel, out callerCancelInvocationFailure);
        Ensure(callerCompleting.Wait(TimeSpan.FromSeconds(5)), "caller cancellation did not finish");
        Ensure(
            callerFailure is BrokerPeerTrustException callerCancelled &&
            callerCancelled.Code == "peer-handshake-cancelled" &&
            callerCancelInvocationFailure is null &&
            callerPlatform.ReadCancellationCallbackCount == 1,
            "caller cancellation lost its bounded trust failure");
        Ensure(callerLease.DisposeCallCount == 1, "caller cancellation did not release once");
        Ensure(callerPlatform.AbortCount == 1, "caller cancellation did not abort once");
        Ensure(callerPlatform.ActiveHelloReadCount == 0, "caller cancellation leaked an active hello read");
        DisposePending(callerPending);

        var timeoutLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var timeoutPlatform = CreatePlatform(
            release,
            timeoutLease,
            BrokerPeerRole.Broker);
        timeoutPlatform.BlockHelloRead();
        timeoutPlatform.SynchronouslyBlockHelloRead = true;
        var timeoutPending = new WindowsNamedPipePeerVerifier(
            TimeSpan.FromMilliseconds(100)).BeginVerification(
            timeoutPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var stopwatch = Stopwatch.StartNew();
        var timeout = ExpectCode(
            "peer-handshake-timeout",
            () => _ = CompletePending(timeoutPending));
        stopwatch.Stop();
        Ensure(
            timeout.InnerException is OperationCanceledException &&
            stopwatch.Elapsed < TimeSpan.FromSeconds(2),
            "handshake deadline did not fail within a bounded interval");
        Ensure(timeoutLease.DisposeCallCount == 1, "timed-out handshake did not release once");
        Ensure(timeoutPlatform.AbortCount == 1, "timed-out handshake was not aborted exactly once");
        Ensure(timeoutPlatform.ActiveHelloReadCount == 0, "timed-out handshake leaked an active hello read");
        DisposePending(timeoutPending);

        var quarantinedLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var quarantinedPlatform = CreatePlatform(
            release,
            quarantinedLease,
            BrokerPeerRole.Broker);
        quarantinedPlatform.BlockHelloRead();
        quarantinedPlatform.SynchronouslyBlockHelloRead = true;
        quarantinedPlatform.AbortDoesNotReleaseHelloRead = true;
        quarantinedPlatform.IgnoreReadCancellation = true;
        var quarantinedPending = new WindowsNamedPipePeerVerifier(
            TimeSpan.FromMilliseconds(100)).BeginVerification(
            quarantinedPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var quarantineStopwatch = Stopwatch.StartNew();
        Exception? quarantineCompleteFailure = null;
        Exception? quarantineDisposeFailure = null;
        var quarantineComplete = Task.Run(() => Capture(
            () => _ = CompletePending(quarantinedPending),
            out quarantineCompleteFailure));
        Ensure(
            quarantinedPlatform.HelloReadEntered.Wait(TimeSpan.FromSeconds(5)),
            "non-cooperative Complete did not enter hello read");
        var quarantineDispose = Task.Run(() => Capture(
            () => DisposePending(quarantinedPending),
            out quarantineDisposeFailure));
        Ensure(
            Task.WaitAll(new[] { quarantineComplete, quarantineDispose }, TimeSpan.FromSeconds(5)),
            "non-cooperative Complete/Dispose did not publish a bounded terminal failure");
        quarantineStopwatch.Stop();
        var quarantineFailure = quarantineCompleteFailure as BrokerPeerTrustException ??
            throw new InvalidOperationException("Complete did not return a trust failure.");
        Ensure(
            quarantineFailure.Code == "peer-handshake-abort-failed" &&
            ReferenceEquals(quarantineCompleteFailure, quarantineDisposeFailure),
            "Complete and Dispose did not share the same quarantine terminal failure");
        Ensure(
            quarantineFailure.QuarantineState?.ReadTask is not null &&
            quarantineStopwatch.Elapsed >= WindowsNamedPipePeerVerifier.AbortDrainTimeout &&
            quarantineStopwatch.Elapsed < TimeSpan.FromSeconds(4),
            "non-cooperative read did not enter bounded quarantine");
        Ensure(quarantinedLease.DisposeCallCount == 0, "quarantine released retained handles while read was active");
        Ensure(quarantinedPlatform.ActiveHelloReadCount == 1, "quarantine lost the active read slot");
        Ensure(
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline + 1,
            "active read was not registered in quarantine");
        quarantinedPlatform.ReleaseHelloRead();
        Ensure(
            SpinWait.SpinUntil(
                () => quarantinedPlatform.ActiveHelloReadCount == 0 &&
                      quarantinedLease.DisposeCallCount == 1 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                TimeSpan.FromSeconds(5)),
            "late hello read did not drain and release its quarantined lease");
        Ensure(quarantinedPlatform.LastEvidence?.IsCleared == true, "late hello evidence was not cleared");
        var repeatedQuarantineFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => DisposePending(quarantinedPending));
        Ensure(
            ReferenceEquals(quarantineFailure, repeatedQuarantineFailure),
            "repeated Dispose lost the shared quarantine failure");

        var abortFailureLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var abortFailurePlatform = CreatePlatform(
            release,
            abortFailureLease,
            BrokerPeerRole.Broker);
        abortFailurePlatform.BlockHelloRead();
        abortFailurePlatform.SynchronouslyBlockHelloRead = true;
        abortFailurePlatform.AbortFailure = new IOException("test CancelIoEx failure");
        abortFailurePlatform.AbortFailuresRemaining = 1;
        abortFailurePlatform.AbortFailureDoesNotReleaseHelloRead = true;
        var abortFailurePending = new WindowsNamedPipePeerVerifier(
            TimeSpan.FromMilliseconds(100)).BeginVerification(
            abortFailurePlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var abortFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => _ = CompletePending(abortFailurePending));
        Ensure(abortFailure.QuarantineState?.AbortFailure is IOException, "abort failure was swallowed");
        Ensure(
            SpinWait.SpinUntil(
                () => abortFailureLease.DisposeCallCount == 1 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                TimeSpan.FromSeconds(5)),
            "abort-failed slot did not retry closure and release quarantine");
        Ensure(abortFailurePlatform.AbortCount == 2, "quarantine did not retry a failed slot abort exactly once");
        Ensure(abortFailurePlatform.ActiveHelloReadCount == 0, "abort failure leaked an active read");
        var repeatedAbortFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => DisposePending(abortFailurePending));
        Ensure(
            ReferenceEquals(abortFailure, repeatedAbortFailure),
            "abort-failed terminal result was not stable across Dispose");
    }

    private static void TestConcurrentRevalidateDispose()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var lease = CreateLease(release, Enumerable.Repeat(identity, 6));
        var platform = CreatePlatform(release, lease, BrokerPeerRole.Broker);
        var peer = CompletePeer(platform, NamedPipePeerKind.Server, CreateExpectation(release));
        lease.BlockCapture(5);
        WindowsProcessIdentity? result = null;
        Exception? failure = null;
        var revalidate = Task.Run(() => Capture(() => result = peer.Revalidate(), out failure));
        Ensure(lease.CaptureEntered.Wait(TimeSpan.FromSeconds(5)), "Revalidate did not enter the retained capture");
        var dispose = Task.Run(peer.Dispose);
        lease.ReleaseCapture();
        Ensure(Task.WaitAll(new[] { revalidate, dispose }, TimeSpan.FromSeconds(10)), "Revalidate/Dispose race did not finish");
        Ensure(failure is null && ReferenceEquals(result, identity), "Dispose invalidated an in-flight successful revalidation");
        Ensure(lease.DisposeCallCount == 1, "successful Revalidate/Dispose race did not release once");

        var changedArtifacts = release.Artifacts.ToArray();
        changedArtifacts[1] = changedArtifacts[1] with { Sha256 = new string('e', 64) };
        var changed = CreateIdentity(release, artifacts: changedArtifacts);
        var failedLease = CreateLease(
            release,
            new[] { identity, identity, identity, identity, changed });
        var failedPlatform = CreatePlatform(release, failedLease, BrokerPeerRole.Broker);
        var failedPeer = CompletePeer(
            failedPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        failedLease.BlockCapture(5);
        Exception? revalidateFailure = null;
        var failedRevalidate = Task.Run(() => Capture(() => _ = failedPeer.Revalidate(), out revalidateFailure));
        Ensure(failedLease.CaptureEntered.Wait(TimeSpan.FromSeconds(5)), "failed Revalidate did not enter capture");
        var failedPeerDispose = Task.Run(failedPeer.Dispose);
        failedLease.ReleaseCapture();
        Ensure(Task.WaitAll(new[] { failedRevalidate, failedPeerDispose }, TimeSpan.FromSeconds(10)), "failed Revalidate/Dispose race did not finish");
        Ensure(
            revalidateFailure is BrokerPeerTrustException trust && trust.Code == "peer-artifact-mismatch",
            "failed revalidation lost its trust code");
        Ensure(failedLease.DisposeCallCount == 1, "failed Revalidate/Dispose race released more than once");
    }

    private static void TestBeginAndRevalidateAbortFailures()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var quarantineBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var beforeLeaseVerifier = new WindowsNamedPipePeerVerifier();
        Ensure(!beforeLeaseVerifier.Health.IsUnhealthy, "peer trust began unhealthy");

        var beforeLease = CreateLease(release, new[] { identity });
        var beforeLeasePlatform = CreatePlatform(
            release,
            beforeLease,
            BrokerPeerRole.Broker,
            initialReadGeneration: 1);
        beforeLeasePlatform.AbortFailure = new IOException("test pre-lease close failure");
        beforeLeasePlatform.AbortFailuresRemaining = 1;
        beforeLeasePlatform.AbortFailureDoesNotReleaseHelloRead = true;
        beforeLeasePlatform.BlockAbortAttempt(2);
        var beforeLeaseFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => beforeLeaseVerifier.BeginVerification(
                beforeLeasePlatform,
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(
            beforeLeaseFailure.QuarantineState?.AbortFailure is IOException,
            "pre-lease abort failure was not retained");
        Ensure(
            beforeLeasePlatform.BlockedAbortEntered.Wait(TimeSpan.FromSeconds(5)),
            "pre-lease quarantine retry did not start in the background");
        Ensure(beforeLease.DisposeCallCount == 0, "pre-lease failure fabricated a lease release");
        Ensure(beforeLeasePlatform.DisposeCallCount == 0, "pre-lease quarantine released its connection early");
        Ensure(
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline + 1 &&
            beforeLeaseVerifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 1,
                QuarantinedHandshakeCount: 1
            },
            "pre-lease abort failure did not close handshake admission");

        var rejectedLease = CreateLease(release, new[] { identity });
        var rejectedPlatform = CreatePlatform(release, rejectedLease, BrokerPeerRole.Broker);
        ExpectCode(
            "peer-trust-quarantine-active",
            () => beforeLeaseVerifier.BeginVerification(
                rejectedPlatform,
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(
            rejectedPlatform.Events.Count == 0 &&
            rejectedPlatform.HelloReadCount == 0,
            "closed admission still inspected an untrusted connection");
        Ensure(rejectedLease.DisposeCallCount == 0, "closed admission opened or released a peer lease");
        Ensure(rejectedPlatform.DisposeCallCount == 0, "closed admission consumed caller-owned connection authority");
        rejectedPlatform.Dispose();

        beforeLeasePlatform.ReleaseBlockedAbort();
        Ensure(
            SpinWait.SpinUntil(
                () => beforeLeasePlatform.DisposeCallCount == 1 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                TimeSpan.FromSeconds(5)),
            "pre-lease quarantine did not close after the retry succeeded");
        Ensure(beforeLeasePlatform.AbortCount == 2, "pre-lease quarantine retried abort more than once");
        Ensure(
            beforeLeaseVerifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 0,
                QuarantinedHandshakeCount: 0
            },
            "drained quarantine incorrectly reopened sticky handshake admission");

        var afterLease = CreateLease(
            release,
            new[] { identity },
            captureFailure: new IOException("test post-lease capture failure"));
        var afterLeasePlatform = CreatePlatform(release, afterLease, BrokerPeerRole.Broker);
        afterLeasePlatform.AbortFailure = new IOException("test post-lease close failure");
        afterLeasePlatform.AbortFailuresRemaining = 1;
        afterLeasePlatform.BlockAbortAttempt(2);
        var afterLeaseVerifier = new WindowsNamedPipePeerVerifier();
        var afterLeaseFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => afterLeaseVerifier.BeginVerification(
                afterLeasePlatform,
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(
            afterLeasePlatform.BlockedAbortEntered.Wait(TimeSpan.FromSeconds(5)),
            "post-lease quarantine retry did not start in the background");
        Ensure(afterLease.DisposeCallCount == 0, "post-lease abort failure released retained handles early");
        Ensure(
            afterLeaseFailure.InnerException is AggregateException afterLeaseAggregate &&
            afterLeaseAggregate.Flatten().InnerExceptions.OfType<BrokerPeerTrustException>()
                .Any(value => value.Code == "peer-platform-failure"),
            "post-lease abort failure lost the original platform failure");
        afterLeasePlatform.ReleaseBlockedAbort();
        Ensure(
            SpinWait.SpinUntil(
                () => afterLease.DisposeCallCount == 1 &&
                      afterLeasePlatform.DisposeCallCount == 1 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                TimeSpan.FromSeconds(5)),
            "post-lease quarantine did not release exact resources after retry");

        var driftedIdentity = CreateIdentity(
            release,
            creationTime: CreationTime.AddTicks(1));
        var revalidateLease = CreateLease(
            release,
            Enumerable.Repeat(identity, 4).Concat(new[] { driftedIdentity, driftedIdentity }));
        var revalidatePlatform = CreatePlatform(
            release,
            revalidateLease,
            BrokerPeerRole.Broker);
        var peer = CompletePeer(
            revalidatePlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        revalidatePlatform.AbortFailure = new IOException("test revalidate close failure");
        revalidatePlatform.AbortFailuresRemaining = 1;
        revalidatePlatform.BlockAbortAttempt(2);
        var revalidateFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => peer.Revalidate());
        Ensure(
            revalidatePlatform.BlockedAbortEntered.Wait(TimeSpan.FromSeconds(5)),
            "revalidate quarantine retry did not start in the background");
        Ensure(revalidateLease.DisposeCallCount == 0, "revalidate abort failure released retained handles early");
        Ensure(
            revalidateFailure.InnerException is AggregateException revalidateAggregate &&
            revalidateAggregate.Flatten().InnerExceptions.OfType<BrokerPeerTrustException>().Any(),
            "revalidate abort failure lost the original trust mismatch");
        var repeatedRevalidateFailure = ExpectCode(
            "peer-handshake-abort-failed",
            peer.Dispose);
        Ensure(
            ReferenceEquals(revalidateFailure, repeatedRevalidateFailure),
            "revalidate abort failure was not stable across Dispose");
        Ensure(revalidateLease.DisposeCallCount == 0, "disposed invalid peer stole quarantine ownership");
        revalidatePlatform.ReleaseBlockedAbort();
        Ensure(
            SpinWait.SpinUntil(
                () => revalidateLease.DisposeCallCount == 1 &&
                      revalidatePlatform.DisposeCallCount == 1 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                TimeSpan.FromSeconds(5)),
            "revalidate quarantine did not release exact resources after retry");
    }

    private static void TestPlatformAndCleanupFailures()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var openLease = CreateLease(release, new[] { identity });
        var openPlatform = CreatePlatform(release, openLease, BrokerPeerRole.Broker);
        openPlatform.OpenFailure = new UnauthorizedAccessException("test access denied");
        ExpectCode(
            "peer-platform-failure",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                openPlatform,
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(openLease.DisposeCallCount == 0, "unopened lease was disposed");

        var captureLease = CreateLease(
            release,
            new[] { identity },
            captureFailure: new IOException("test capture failed"));
        ExpectCode(
            "peer-platform-failure",
            () => new WindowsNamedPipePeerVerifier().BeginVerification(
                CreatePlatform(release, captureLease, BrokerPeerRole.Broker),
                NamedPipePeerKind.Server,
                CreateExpectation(release)));
        Ensure(captureLease.DisposeCallCount == 1, "capture failure leaked the lease");

        var readLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var readPlatform = CreatePlatform(release, readLease, BrokerPeerRole.Broker);
        readPlatform.HelloReadFailure = new IOException("test read failed");
        ExpectCompleteCode("peer-platform-failure", readPlatform, release);
        Ensure(readLease.DisposeCallCount == 1, "hello read failure leaked the lease");

        var cleanupLease = CreateLease(
            release,
            Enumerable.Repeat(identity, 4),
            disposeFailure: new IOException("test cleanup failed"));
        var cleanupPlatform = CreatePlatform(
            release,
            cleanupLease,
            BrokerPeerRole.Broker,
            hello: CreateHello(BrokerPeerRole.Broker) with { ConnectionNonce = new string('d', 64) });
        var cleanupBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var cleanupVerifier = new WindowsNamedPipePeerVerifier();
        var cleanupPending = cleanupVerifier.BeginVerification(
            cleanupPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var exception = ExpectCode(
            "peer-handshake-abort-failed",
            () => _ = CompletePending(cleanupPending));
        var repeatedCleanupFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => DisposePending(cleanupPending));
        IEnumerable<Exception> cleanupFailures = exception.InnerException is AggregateException cleanupAggregate
            ? cleanupAggregate.Flatten().InnerExceptions
            : Array.Empty<Exception>();
        Ensure(
            cleanupFailures.OfType<BrokerPeerTrustException>().Any(value =>
                value.Code == "peer-hello-mismatch" &&
                value.Data["peer-trust-cleanup-failure"] is IOException) &&
            cleanupFailures.OfType<IOException>().Any(),
            "cleanup quarantine lost the original trust or retained-resource failure");
        Ensure(
            ReferenceEquals(exception, repeatedCleanupFailure),
            "cleanup failure was not stable across repeated Dispose");
        Ensure(cleanupLease.DisposeCallCount == 1, "cleanup failure retried lease disposal");
        Ensure(cleanupPlatform.DisposeCallCount == 1, "cleanup failure retried connection disposal");
        Ensure(
            cleanupVerifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 1,
                QuarantinedHandshakeCount: 1
            } &&
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == cleanupBaseline + 1,
            "cleanup failure released or reopened an unproven connection slot");
    }

    private static void TestFirstAbortAttemptTimeouts()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);

        var completeLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var completePlatform = CreatePlatform(release, completeLease, BrokerPeerRole.Broker);
        completePlatform.BlockHelloRead();
        completePlatform.SynchronouslyBlockHelloRead = true;
        completePlatform.IgnoreReadCancellation = true;
        var completeVerifier = new WindowsNamedPipePeerVerifier(TimeSpan.FromMilliseconds(100));
        var completePending = completeVerifier.BeginVerification(
            completePlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        completePlatform.BlockAbortAttempt(1);
        var completeBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var completeStopwatch = Stopwatch.StartNew();
        try
        {
            var completeFailure = ExpectCode(
                "peer-handshake-abort-failed",
                () => _ = CompletePending(completePending));
            completeStopwatch.Stop();
            AssertAbortTimeoutFailStop(
                "Complete",
                completeVerifier,
                completePlatform,
                completeLease,
                completeFailure,
                completeBaseline,
                completeStopwatch.Elapsed);
            Ensure(
                completeFailure.QuarantineState?.ReadTask is not null &&
                completePlatform.ActiveHelloReadCount == 1,
                "Complete timeout did not retain its active read for late observation");
            completePlatform.ReleaseHelloRead();
            Ensure(
                SpinWait.SpinUntil(
                    () => completePlatform.ActiveHelloReadCount == 0 &&
                          completePlatform.LastEvidence?.IsCleared == true,
                    TimeSpan.FromSeconds(5)),
                "Complete timeout did not clear late evidence while abort stayed blocked");
            Ensure(
                completeLease.DisposeCallCount == 0 &&
                completePlatform.DisposeCallCount == 0 &&
                completeVerifier.Health is
                {
                    IsUnhealthy: true,
                    ActiveConnectionCount: 1,
                    QuarantinedHandshakeCount: 1
                },
                "independent late-read cleanup released unproven connection authority");
            var repeatedCompleteFailure = ExpectCode(
                "peer-handshake-abort-failed",
                () => DisposePending(completePending));
            Ensure(
                ReferenceEquals(completeFailure, repeatedCompleteFailure),
                "Complete abort timeout did not retain a stable terminal result");
        }
        finally
        {
            completePlatform.ReleaseBlockedAbort();
        }
        AssertLateAbortSuccessDrained(
            "Complete",
            completeVerifier,
            completePlatform,
            completeLease,
            completeBaseline,
            expectClearedEvidence: true);

        var disposeLease = CreateLease(release, Enumerable.Repeat(identity, 2));
        var disposePlatform = CreatePlatform(release, disposeLease, BrokerPeerRole.Broker);
        disposePlatform.AbortFailure = new IOException("test late abort failure");
        disposePlatform.AbortFailuresRemaining = 1;
        var disposeVerifier = new WindowsNamedPipePeerVerifier();
        var disposePending = disposeVerifier.BeginVerification(
            disposePlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        disposePlatform.BlockAbortAttempt(1);
        var disposeBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var disposeStopwatch = Stopwatch.StartNew();
        try
        {
            var disposeFailure = ExpectCode(
                "peer-handshake-abort-failed",
                () => DisposePending(disposePending));
            disposeStopwatch.Stop();
            AssertAbortTimeoutFailStop(
                "Dispose",
                disposeVerifier,
                disposePlatform,
                disposeLease,
                disposeFailure,
                disposeBaseline,
                disposeStopwatch.Elapsed);
            var repeatedDisposeFailure = ExpectCode(
                "peer-handshake-abort-failed",
                () => DisposePending(disposePending));
            Ensure(
                ReferenceEquals(disposeFailure, repeatedDisposeFailure),
                "Dispose abort timeout did not retain a stable terminal result");
        }
        finally
        {
            disposePlatform.ReleaseBlockedAbort();
        }
        AssertLateAbortFailureRetained(
            "Dispose",
            disposeVerifier,
            disposePlatform,
            disposeLease,
            disposeBaseline);

        var driftedIdentity = CreateIdentity(
            release,
            creationTime: CreationTime.AddTicks(1));
        var revalidateLease = CreateLease(
            release,
            Enumerable.Repeat(identity, 4).Concat(new[] { driftedIdentity, driftedIdentity }));
        var revalidatePlatform = CreatePlatform(release, revalidateLease, BrokerPeerRole.Broker);
        var revalidateVerifier = new WindowsNamedPipePeerVerifier();
        var revalidatePending = revalidateVerifier.BeginVerification(
            revalidatePlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var revalidatePeer = CompletePending(revalidatePending);
        DisposePending(revalidatePending);
        revalidatePlatform.BlockAbortAttempt(1);
        var revalidateBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var revalidateStopwatch = Stopwatch.StartNew();
        try
        {
            var revalidateFailure = ExpectCode(
                "peer-handshake-abort-failed",
                () => _ = revalidatePeer.Revalidate());
            revalidateStopwatch.Stop();
            AssertAbortTimeoutFailStop(
                "Revalidate",
                revalidateVerifier,
                revalidatePlatform,
                revalidateLease,
                revalidateFailure,
                revalidateBaseline,
                revalidateStopwatch.Elapsed);
            var repeatedRevalidateFailure = ExpectCode(
                "peer-handshake-abort-failed",
                revalidatePeer.Dispose);
            Ensure(
                ReferenceEquals(revalidateFailure, repeatedRevalidateFailure),
                "Revalidate timeout did not retain a stable cleanup failure");
            Ensure(
                revalidateLease.DisposeCallCount == 0 &&
                revalidatePlatform.DisposeCallCount == 0,
                "disposed invalid peer stole timeout quarantine authority");
        }
        finally
        {
            revalidatePlatform.ReleaseBlockedAbort();
        }
        AssertLateAbortSuccessDrained(
            "Revalidate",
            revalidateVerifier,
            revalidatePlatform,
            revalidateLease,
            revalidateBaseline,
            expectClearedEvidence: false);
    }

    private static void TestSecondAbortFailureFailStop()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);

        var lateRetryLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var lateRetryPlatform = CreatePlatform(
            release,
            lateRetryLease,
            BrokerPeerRole.Broker,
            hello: CreateHello(BrokerPeerRole.Broker) with { ConnectionNonce = new string('d', 64) });
        lateRetryPlatform.AbortFailure = new IOException("test initial abort failure");
        lateRetryPlatform.AbortFailuresRemaining = 1;
        lateRetryPlatform.BlockAbortAttempt(2);
        var lateRetryVerifier = new WindowsNamedPipePeerVerifier();
        var lateRetryPending = lateRetryVerifier.BeginVerification(
            lateRetryPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var lateRetryBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var lateRetryFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => _ = CompletePending(lateRetryPending));
        Ensure(
            lateRetryPlatform.BlockedAbortEntered.Wait(TimeSpan.FromSeconds(5)),
            "second abort attempt did not enter its timeout barrier");
        Thread.Sleep(WindowsNamedPipePeerVerifier.AbortAttemptTimeout + TimeSpan.FromMilliseconds(500));
        Ensure(
            lateRetryPlatform.AbortCount == 2 &&
            lateRetryLease.DisposeCallCount == 0 &&
            lateRetryPlatform.DisposeCallCount == 0 &&
            lateRetryVerifier.Health.ActiveConnectionCount == 1,
            "timed-out second abort released authority before late completion");
        lateRetryPlatform.ReleaseBlockedAbort();
        Ensure(
            SpinWait.SpinUntil(
                () => lateRetryLease.DisposeCallCount == 1 &&
                      lateRetryPlatform.DisposeCallCount == 1 &&
                      lateRetryVerifier.Health.ActiveConnectionCount == 0 &&
                      lateRetryVerifier.Health.QuarantinedHandshakeCount == 0 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == lateRetryBaseline,
                TimeSpan.FromSeconds(5)),
            "late second-abort success did not drain exact connection authority");
        Ensure(
            lateRetryVerifier.Health.IsUnhealthy &&
            lateRetryVerifier.Health.RejectNewHandshakes &&
            lateRetryPlatform.AbortCount == 2,
            "late second-abort success reopened admission or retried again");
        var repeatedLateRetryFailure = ExpectCode(
            "peer-handshake-abort-failed",
            () => DisposePending(lateRetryPending));
        Ensure(
            ReferenceEquals(lateRetryFailure, repeatedLateRetryFailure),
            "late second-abort success changed the published terminal failure");

        var lease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var platform = CreatePlatform(release, lease, BrokerPeerRole.Broker);
        platform.BlockHelloRead();
        platform.SynchronouslyBlockHelloRead = true;
        platform.IgnoreReadCancellation = true;
        platform.AbortFailureDoesNotReleaseHelloRead = true;
        platform.AbortFailure = new IOException("test repeated CancelIoEx failure");
        platform.AbortFailuresRemaining = 2;
        var verifier = new WindowsNamedPipePeerVerifier(TimeSpan.FromMilliseconds(100));
        var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var quarantineBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        try
        {
            var failure = ExpectCode(
                "peer-handshake-abort-failed",
                () => _ = CompletePending(pending));
            Ensure(
                SpinWait.SpinUntil(() => platform.AbortCount == 2, TimeSpan.FromSeconds(5)),
                "quarantine did not execute the single bounded retry");
            Thread.Sleep(200);
            Ensure(platform.AbortCount == 2, "quarantine started a third abort attempt");
            Ensure(
                failure.QuarantineState is
                {
                    ReadTask: not null,
                    AbortFailure: IOException
                },
                "second abort failure lost retained read or abort evidence");
            Ensure(
                platform.ActiveHelloReadCount == 1 &&
                lease.DisposeCallCount == 0 &&
                platform.DisposeCallCount == 0 &&
                verifier.Health is
                {
                    IsUnhealthy: true,
                    RejectNewHandshakes: true,
                    ActiveConnectionCount: 1,
                    QuarantinedHandshakeCount: 1
                } &&
                WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline + 1,
                "second abort failure released retained connection authority");

            var rejectedLease = CreateLease(release, new[] { identity });
            var rejectedPlatform = CreatePlatform(release, rejectedLease, BrokerPeerRole.Broker);
            ExpectCode(
                "peer-trust-quarantine-active",
                () => verifier.BeginVerification(
                    rejectedPlatform,
                    NamedPipePeerKind.Server,
                    CreateExpectation(release)));
            Ensure(
                rejectedPlatform.ReadGenerationReadCount == 0 &&
                rejectedPlatform.Events.Count == 0 &&
                rejectedPlatform.HelloReadCount == 0 &&
                rejectedPlatform.AbortCount == 0 &&
                rejectedPlatform.DisposeCallCount == 0 &&
                rejectedLease.DisposeCallCount == 0,
                "sticky unhealthy admission touched a new caller-owned platform");
            rejectedPlatform.Dispose();

            var repeatedFailure = ExpectCode(
                "peer-handshake-abort-failed",
                () => DisposePending(pending));
            Ensure(
                ReferenceEquals(failure, repeatedFailure),
                "second abort failure changed across repeated Dispose");
        }
        finally
        {
            platform.ReleaseHelloRead();
        }

        Ensure(
            SpinWait.SpinUntil(
                () => platform.ActiveHelloReadCount == 0 &&
                      platform.LastEvidence?.IsCleared == true,
                TimeSpan.FromSeconds(5)),
            "failed abort quarantine did not observe and clear the late hello evidence");
        Ensure(
            platform.AbortCount == 2 &&
            lease.DisposeCallCount == 0 &&
            platform.DisposeCallCount == 0 &&
            verifier.Health is
            {
                IsUnhealthy: true,
                ActiveConnectionCount: 1,
                QuarantinedHandshakeCount: 1
            } &&
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline + 1,
            "released fake read changed fail-stop connection authority");
    }

    private static void TestVerifiedDisposeCleanupFailures()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);

        var leaseFailure = new IOException("test verified lease dispose failure");
        var failingLease = CreateLease(
            release,
            Enumerable.Repeat(identity, 4),
            disposeFailure: leaseFailure);
        var leasePlatform = CreatePlatform(release, failingLease, BrokerPeerRole.Broker);
        var leaseVerifier = new WindowsNamedPipePeerVerifier();
        var leasePending = leaseVerifier.BeginVerification(
            leasePlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var leasePeer = CompletePending(leasePending);
        DisposePending(leasePending);
        var leaseBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var firstLeaseFailure = ExpectCode("peer-handshake-abort-failed", leasePeer.Dispose);
        var repeatedLeaseFailure = ExpectCode("peer-handshake-abort-failed", leasePeer.Dispose);
        Ensure(
            ReferenceEquals(firstLeaseFailure, repeatedLeaseFailure) &&
            failingLease.DisposeCallCount == 1 &&
            leasePlatform.DisposeCallCount == 1 &&
            leasePlatform.AbortCount == 1 &&
            leaseVerifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 1,
                QuarantinedHandshakeCount: 1
            } &&
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == leaseBaseline + 1,
            "verified lease cleanup failure lost stable quarantine ownership");

        var platformLease = CreateLease(release, Enumerable.Repeat(identity, 4));
        var failingPlatform = CreatePlatform(release, platformLease, BrokerPeerRole.Broker);
        failingPlatform.DisposeFailure = new IOException("test verified platform dispose failure");
        var platformVerifier = new WindowsNamedPipePeerVerifier();
        var platformPending = platformVerifier.BeginVerification(
            failingPlatform,
            NamedPipePeerKind.Server,
            CreateExpectation(release));
        var platformPeer = CompletePending(platformPending);
        DisposePending(platformPending);
        var platformBaseline = WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount;
        var firstPlatformFailure = ExpectCode("peer-handshake-abort-failed", platformPeer.Dispose);
        var repeatedPlatformFailure = ExpectCode("peer-handshake-abort-failed", platformPeer.Dispose);
        Ensure(
            ReferenceEquals(firstPlatformFailure, repeatedPlatformFailure) &&
            platformLease.DisposeCallCount == 0 &&
            failingPlatform.DisposeCallCount == 1 &&
            failingPlatform.AbortCount == 1 &&
            platformVerifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 1,
                QuarantinedHandshakeCount: 1
            } &&
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == platformBaseline + 1,
            "verified platform cleanup failure released identity authority or changed terminal state");
    }

    private static void AssertAbortTimeoutFailStop(
        string operation,
        WindowsNamedPipePeerVerifier verifier,
        FakeNamedPipePeerTrustPlatform platform,
        FakeRetainedPeerIdentityLease lease,
        BrokerPeerTrustException failure,
        int quarantineBaseline,
        TimeSpan elapsed)
    {
        Ensure(
            failure.QuarantineState?.AbortFailure is PeerAbortAttemptTimeoutException,
            operation + " did not retain the bounded abort timeout");
        Ensure(
            elapsed >= WindowsNamedPipePeerVerifier.AbortAttemptTimeout - TimeSpan.FromMilliseconds(100) &&
            elapsed < WindowsNamedPipePeerVerifier.AbortAttemptTimeout + TimeSpan.FromSeconds(3),
            operation + " did not return within the bounded abort interval");
        Ensure(
            platform.AbortCount == 1 &&
            lease.DisposeCallCount == 0 &&
            platform.DisposeCallCount == 0 &&
            verifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 1,
                QuarantinedHandshakeCount: 1
            } &&
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline + 1,
            operation + " timeout did not retain exact fail-stop authority");
        Thread.Sleep(100);
        Ensure(platform.AbortCount == 1, operation + " timeout started a concurrent retry");
    }

    private static void AssertLateAbortSuccessDrained(
        string operation,
        WindowsNamedPipePeerVerifier verifier,
        FakeNamedPipePeerTrustPlatform platform,
        FakeRetainedPeerIdentityLease lease,
        int quarantineBaseline,
        bool expectClearedEvidence)
    {
        Ensure(
            SpinWait.SpinUntil(
                () => lease.DisposeCallCount == 1 &&
                      platform.DisposeCallCount == 1 &&
                      verifier.Health.ActiveConnectionCount == 0 &&
                      verifier.Health.QuarantinedHandshakeCount == 0 &&
                      WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline,
                TimeSpan.FromSeconds(5)),
            operation + " late abort success did not drain exact connection authority");
        Ensure(
            verifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 0,
                QuarantinedHandshakeCount: 0
            } &&
            platform.AbortCount == 1 &&
            (!expectClearedEvidence || platform.LastEvidence?.IsCleared == true),
            operation + " late abort success reopened admission or retained hello evidence");
    }

    private static void AssertLateAbortFailureRetained(
        string operation,
        WindowsNamedPipePeerVerifier verifier,
        FakeNamedPipePeerTrustPlatform platform,
        FakeRetainedPeerIdentityLease lease,
        int quarantineBaseline)
    {
        Ensure(
            SpinWait.SpinUntil(
                () => platform.AbortFailuresRemaining == 0,
                TimeSpan.FromSeconds(5)),
            operation + " late abort failure did not complete");
        Thread.Sleep(100);
        Ensure(
            platform.AbortCount == 1 &&
            lease.DisposeCallCount == 0 &&
            platform.DisposeCallCount == 0 &&
            verifier.Health is
            {
                IsUnhealthy: true,
                RejectNewHandshakes: true,
                ActiveConnectionCount: 1,
                QuarantinedHandshakeCount: 1
            } &&
            WindowsNamedPipePeerVerifier.QuarantinedHandshakeCount == quarantineBaseline + 1,
            operation + " late abort failure released or retried fail-stop authority");
    }

    private static VerifiedPipePeerIdentity CompletePeer(
        FakeNamedPipePeerTrustPlatform platform,
        NamedPipePeerKind peerKind,
        BrokerPeerExpectation expectation)
    {
        var verifier = new WindowsNamedPipePeerVerifier();
        var pending = verifier.BeginVerification(platform, peerKind, expectation);
        try
        {
            return CompletePending(pending);
        }
        finally
        {
            DisposePending(pending);
        }
    }

    private static VerifiedPipePeerIdentity CompletePending(
        PendingPipePeerVerification pending) =>
        pending.CompleteAsync().AsTask().GetAwaiter().GetResult();

    private static VerifiedPipePeerIdentity CompletePending(
        PendingPipePeerVerification pending,
        CancellationToken cancellationToken) =>
        pending.CompleteAsync(cancellationToken).AsTask().GetAwaiter().GetResult();

    private static void DisposePending(PendingPipePeerVerification pending) =>
        pending.DisposeAsync().AsTask().GetAwaiter().GetResult();

    private static BrokerPeerTrustException ExpectCompleteCode(
        string code,
        FakeNamedPipePeerTrustPlatform platform,
        VerifiedReleaseArtifactSet release)
    {
        var peerKind = release.Role == BrokerPeerRole.Guardian
            ? NamedPipePeerKind.Client
            : NamedPipePeerKind.Server;
        return ExpectCode(
            code,
            () => CompletePeer(platform, peerKind, CreateExpectation(release)));
    }

    private static BrokerPeerHello CreateHello(BrokerPeerRole role) =>
        new(
            BrokerPeerHelloProtocol.ProtocolVersion,
            role,
            ProcessId,
            SessionId,
            CreationTime,
            ConnectionNonce,
            ReleaseId,
            ManifestSha256);

    private static BrokerPeerExpectation CreateExpectation(
        VerifiedReleaseArtifactSet release,
        WindowsTokenIdentity? token = null,
        uint processId = ProcessId,
        DateTimeOffset? creationTime = null) =>
        new(
            token ?? CreateProcessToken(),
            WindowsAppModelIdentity.Unpackaged,
            release,
            ConnectionNonce,
            processId,
            creationTime ?? CreationTime);

    private static VerifiedReleaseManifest CreateManifest(
        WindowsReleaseRootIdentity? root = null,
        VerifiedReleaseRoleArtifacts? guardian = null,
        VerifiedReleaseRoleArtifacts? broker = null) =>
        VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId,
            ManifestSha256,
            root ?? CreateReleaseRoot(),
            guardian ?? CreateRoleDefinition(BrokerPeerRole.Guardian),
            broker ?? CreateRoleDefinition(BrokerPeerRole.Broker));

    private static WindowsReleaseRootIdentity CreateReleaseRoot() =>
        new(
            ReleaseRoot,
            FileAttributes.Directory | FileAttributes.Archive,
            VolumeSerial,
            new string('a', 32),
            true);

    private static VerifiedReleaseRoleArtifacts CreateRoleDefinition(
        BrokerPeerRole role,
        IReadOnlyList<WindowsArtifactIdentity>? artifacts = null,
        string? appHostRelativePath = null,
        string? managedEntryRelativePath = null,
        string? depsRelativePath = null,
        string? runtimeConfigRelativePath = null)
    {
        var stem = RoleStem(role);
        return new VerifiedReleaseRoleArtifacts(
            role,
            appHostRelativePath ?? stem + ".exe",
            managedEntryRelativePath ?? stem + ".dll",
            depsRelativePath ?? stem + ".deps.json",
            runtimeConfigRelativePath ?? stem + ".runtimeconfig.json",
            artifacts ?? CreateArtifacts(role));
    }

    private static IReadOnlyList<WindowsArtifactIdentity> CreateArtifacts(BrokerPeerRole role)
    {
        var stem = RoleStem(role);
        var seed = role == BrokerPeerRole.Guardian ? '1' : '5';
        return new[]
        {
            CreateArtifact(ReleaseArtifactKind.AppHostExe, stem + ".exe", seed, 128 * 1024),
            CreateArtifact(ReleaseArtifactKind.ManagedEntryDll, stem + ".dll", (char)(seed + 1), 512 * 1024),
            CreateArtifact(ReleaseArtifactKind.DepsJson, stem + ".deps.json", (char)(seed + 2), 64 * 1024),
            CreateArtifact(ReleaseArtifactKind.RuntimeConfigJson, stem + ".runtimeconfig.json", (char)(seed + 3), 4 * 1024)
        };
    }

    private static WindowsArtifactIdentity CreateArtifact(
        ReleaseArtifactKind kind,
        string relativePath,
        char identitySeed,
        long length) =>
        new(
            kind,
            relativePath,
            Path.Combine(ReleaseRoot, relativePath),
            FileAttributes.Archive,
            length,
            new string(identitySeed, 64),
            VolumeSerial,
            new string(identitySeed, 32),
            1,
            true);

    private static string RoleStem(BrokerPeerRole role) =>
        role == BrokerPeerRole.Broker
            ? "CodexGuardian.Broker"
            : "CodexGuardian";

    private static WindowsProcessIdentity CreateIdentity(
        VerifiedReleaseArtifactSet release,
        WindowsTokenIdentity? token = null,
        WindowsAppModelIdentity? appModel = null,
        WindowsReleaseRootIdentity? releaseRoot = null,
        IReadOnlyList<WindowsArtifactIdentity>? artifacts = null,
        uint processId = ProcessId,
        DateTimeOffset? creationTime = null,
        uint kernelSessionId = SessionId,
        bool imageFileObjectIsExact = true)
    {
        var selectedArtifacts = artifacts ?? release.Artifacts;
        var image = selectedArtifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe);
        return new WindowsProcessIdentity(
            processId,
            creationTime ?? CreationTime,
            kernelSessionId,
            token ?? CreateProcessToken(),
            appModel ?? WindowsAppModelIdentity.Unpackaged,
            image.FinalPath,
            imageFileObjectIsExact,
            releaseRoot ?? release.Root,
            selectedArtifacts);
    }

    private static WindowsTokenIdentity CreateProcessToken() =>
        new(
            UserSid,
            LogonSid,
            1,
            0x0000000100000002,
            SessionId,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Primary,
            null);

    private static WindowsTokenIdentity CreateImpersonatedToken(
        WindowsTokenIdentity processToken) =>
        processToken with
        {
            TokenType = WindowsTokenType.Impersonation,
            ImpersonationLevel = WindowsSecurityImpersonationLevel.Identification
        };

    private static PipePeerKernelIdentity CreateKernel(
        uint processId = ProcessId,
        uint sessionId = SessionId) =>
        new(processId, sessionId);

    private static FakeRetainedPeerIdentityLease CreateLease(
        VerifiedReleaseArtifactSet release,
        IEnumerable<WindowsProcessIdentity> identities,
        IEnumerable<bool>? aliveStates = null,
        Exception? captureFailure = null,
        Exception? disposeFailure = null) =>
        new(
            identities,
            new RetainedReleaseHandleSet(
                release.Root,
                release.Artifacts.Select(artifact => artifact.RelativePath).ToArray()),
            aliveStates,
            captureFailure,
            disposeFailure);

    private static FakeNamedPipePeerTrustPlatform CreatePlatform(
        VerifiedReleaseArtifactSet release,
        FakeRetainedPeerIdentityLease lease,
        BrokerPeerRole helloRole,
        IEnumerable<PipePeerKernelIdentity>? kernelIdentities = null,
        BrokerPeerHello? hello = null,
        WindowsTokenIdentity? impersonatedToken = null,
        long initialReadGeneration = 0) =>
        new(
            UtcNow,
            release,
            kernelIdentities ?? Enumerable.Repeat(CreateKernel(), 8),
            lease,
            BrokerPeerHelloProtocol.Serialize(hello ?? CreateHello(helloRole)),
            impersonatedToken ??
            (helloRole == BrokerPeerRole.Guardian
                ? CreateImpersonatedToken(CreateProcessToken())
                : null),
            initialReadGeneration);

    private static WindowsArtifactIdentity[] Replace(
        WindowsArtifactIdentity[] source,
        int index,
        Func<WindowsArtifactIdentity, WindowsArtifactIdentity> replacement)
    {
        var copy = source.ToArray();
        copy[index] = replacement(copy[index]);
        return copy;
    }

    private static void ExpectInvalidManifest(VerifiedReleaseRoleArtifacts broker) =>
        ExpectCode(
            "invalid-verified-release",
            () => CreateManifest(broker: broker));

    private static void Capture(Action action, out Exception? failure)
    {
        try
        {
            action();
            failure = null;
        }
        catch (Exception exception)
        {
            failure = exception;
        }
    }

    private static BrokerPeerTrustException ExpectCode(string code, Action action)
    {
        var exception = Expect<BrokerPeerTrustException>(action);
        Ensure(exception.Code == code, $"expected {code}, received {exception.Code}");
        return exception;
    }

    private static int GetGlobalAdmissionCount()
    {
        var field = typeof(PeerReadQuarantineRegistry).GetField(
            "GlobalAdmissions",
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new InvalidOperationException("Global admission registry field was not found.");
        var registry = field.GetValue(null) ??
            throw new InvalidOperationException("Global admission registry was not initialized.");
        var count = registry.GetType().GetProperty("Count")?.GetValue(registry);
        return count is int value
            ? value
            : throw new InvalidOperationException("Global admission registry count was unavailable.");
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
            $"Expected {typeof(TException).Name} was not thrown.");
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
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeNamedPipePeerTrustPlatform : INamedPipePeerTrustPlatform
    {
        private readonly Queue<PipePeerKernelIdentity> _kernelIdentities;
        private readonly FakeRetainedPeerIdentityLease _peerLease;
        private readonly byte[] _helloUtf8;
        private readonly WindowsTokenIdentity? _impersonatedToken;
        private int _abortCount;
        private long _readGeneration;
        private int _readGenerationReadCount;
        private bool _blockHelloRead;

        internal FakeNamedPipePeerTrustPlatform(
            DateTimeOffset utcNow,
            VerifiedReleaseArtifactSet expectedRelease,
            IEnumerable<PipePeerKernelIdentity> kernelIdentities,
            FakeRetainedPeerIdentityLease peerLease,
            byte[] helloUtf8,
            WindowsTokenIdentity? impersonatedToken,
            long initialReadGeneration)
        {
            UtcNow = utcNow;
            ExpectedRelease = expectedRelease;
            _kernelIdentities = new Queue<PipePeerKernelIdentity>(kernelIdentities);
            _peerLease = peerLease;
            _helloUtf8 = helloUtf8.ToArray();
            _impersonatedToken = impersonatedToken;
            _readGeneration = initialReadGeneration;
            EvidenceKernelBefore = CreateKernel();
            EvidenceKernelAfter = CreateKernel();
            AllowHelloRead.Set();
            AllowBlockedAbort.Set();
            Ensure(_kernelIdentities.Count > 0, "fake platform requires a kernel identity");
        }

        public DateTimeOffset UtcNow { get; }

        public long ReadGeneration
        {
            get
            {
                Interlocked.Increment(ref _readGenerationReadCount);
                return Volatile.Read(ref _readGeneration);
            }
        }

        internal VerifiedReleaseArtifactSet ExpectedRelease { get; }

        internal List<string> Events { get; } = new();

        internal ManualResetEventSlim HelloReadEntered { get; } = new(false);

        internal ManualResetEventSlim AllowHelloRead { get; } = new(false);

        internal ManualResetEventSlim CancellationRegistrationReady { get; } = new(false);

        internal ManualResetEventSlim BlockedAbortEntered { get; } = new(false);

        internal ManualResetEventSlim AllowBlockedAbort { get; } = new(false);

        internal PipePeerKernelIdentity EvidenceKernelBefore { get; set; }

        internal PipePeerKernelIdentity EvidenceKernelAfter { get; set; }

        internal int FramesConsumedPerHello { get; set; } = 1;

        internal bool OmitClientToken { get; set; }

        internal bool IncludeServerToken { get; set; }

        internal bool SynchronouslyBlockHelloRead { get; set; }

        internal bool AbortDoesNotReleaseHelloRead { get; set; }

        internal bool AbortFailureDoesNotReleaseHelloRead { get; set; }

        internal bool IgnoreReadCancellation { get; set; }

        internal Exception? OpenFailure { get; set; }

        internal Exception? HelloReadFailure { get; set; }

        internal Exception? AbortFailure { get; set; }

        internal Exception? DisposeFailure { get; set; }

        internal Exception? ReadCancellationFailure { get; set; }

        internal int AbortFailuresRemaining { get; set; }

        internal int BlockAbortAttemptNumber { get; private set; }

        internal int HelloReadCount { get; private set; }

        internal int ImpersonationTransactionCount { get; private set; }

        internal int AbortCount => Volatile.Read(ref _abortCount);

        internal int ReadGenerationReadCount => Volatile.Read(ref _readGenerationReadCount);

        internal int ReadCancellationCallbackCount => Volatile.Read(ref _readCancellationCallbackCount);

        internal int DisposeCallCount { get; private set; }

        internal int ActiveHelloReadCount => Volatile.Read(ref _activeHelloReadCount);

        internal string? LastAbortCode { get; private set; }

        internal PipePeerHelloReadEvidence? LastEvidence { get; private set; }

        private int _activeHelloReadCount;
        private int _readCancellationCallbackCount;

        public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
        {
            Events.Add("kernel.capture." + peerKind);
            return _kernelIdentities.Count > 1
                ? _kernelIdentities.Dequeue()
                : _kernelIdentities.Peek();
        }

        public IRetainedPeerIdentityLease OpenRetainedPeer(
            uint processId,
            VerifiedReleaseArtifactSet release)
        {
            Events.Add("lease.open");
            Ensure(processId == ProcessId, "fake platform received an unexpected PID");
            Ensure(ReferenceEquals(release, ExpectedRelease), "fake platform received another release capability");
            if (OpenFailure is not null)
            {
                throw OpenFailure;
            }

            return _peerLease;
        }

        public async ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
            NamedPipePeerKind peerKind,
            int maximumHelloBytes,
            CancellationToken cancellationToken)
        {
            Events.Add("hello.read");
            HelloReadCount++;
            HelloReadEntered.Set();
            Interlocked.Increment(ref _activeHelloReadCount);
            var cancellationFailure = ReadCancellationFailure;
            using var cancellationRegistration = cancellationFailure is null
                ? default
                : cancellationToken.Register(() =>
                {
                    Interlocked.Increment(ref _readCancellationCallbackCount);
                    throw cancellationFailure;
                });
            CancellationRegistrationReady.Set();
            try
            {
                if (_blockHelloRead && SynchronouslyBlockHelloRead)
                {
                    AllowHelloRead.Wait();
                }
                else if (_blockHelloRead)
                {
                    await Task.Run(
                        () => AllowHelloRead.Wait(cancellationToken),
                        CancellationToken.None);
                }

                if (!IgnoreReadCancellation)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }
                if (HelloReadFailure is not null)
                {
                    throw HelloReadFailure;
                }

                Ensure(_helloUtf8.Length <= maximumHelloBytes, "fake hello exceeded caller bound");
                var generation = Interlocked.Add(ref _readGeneration, FramesConsumedPerHello);
                WindowsTokenIdentity? token = null;
                if (peerKind == NamedPipePeerKind.Client && !OmitClientToken)
                {
                    Events.Add("impersonation.capture");
                    ImpersonationTransactionCount++;
                    token = _impersonatedToken;
                }
                else if (peerKind == NamedPipePeerKind.Server && IncludeServerToken)
                {
                    token = CreateImpersonatedToken(CreateProcessToken());
                }

                LastEvidence = new PipePeerHelloReadEvidence(
                    _helloUtf8,
                    generation,
                    EvidenceKernelBefore,
                    EvidenceKernelAfter,
                    token);
                return LastEvidence;
            }
            finally
            {
                Interlocked.Decrement(ref _activeHelloReadCount);
            }
        }

        public void AbortHandshake(string boundedFailureCode)
        {
            var abortAttempt = Interlocked.Increment(ref _abortCount);
            LastAbortCode = boundedFailureCode;
            Events.Add("handshake.abort");
            if (abortAttempt == BlockAbortAttemptNumber)
            {
                BlockedAbortEntered.Set();
                AllowBlockedAbort.Wait();
            }

            if (AbortFailure is not null && AbortFailuresRemaining > 0)
            {
                AbortFailuresRemaining--;
                if (!AbortDoesNotReleaseHelloRead &&
                    !AbortFailureDoesNotReleaseHelloRead)
                {
                    AllowHelloRead.Set();
                }

                throw AbortFailure;
            }

            if (!AbortDoesNotReleaseHelloRead)
            {
                AllowHelloRead.Set();
            }
        }

        public void Dispose()
        {
            DisposeCallCount++;
            Events.Add("connection.dispose");
            if (DisposeFailure is not null)
            {
                throw DisposeFailure;
            }
        }

        internal void BlockHelloRead()
        {
            _blockHelloRead = true;
            AllowHelloRead.Reset();
        }

        internal void ReleaseHelloRead() => AllowHelloRead.Set();

        internal void BlockAbortAttempt(int abortAttempt)
        {
            BlockAbortAttemptNumber = abortAttempt;
            BlockedAbortEntered.Reset();
            AllowBlockedAbort.Reset();
        }

        internal void ReleaseBlockedAbort() => AllowBlockedAbort.Set();
    }

    private sealed class FakeRetainedPeerIdentityLease : IRetainedPeerIdentityLease
    {
        private readonly object _sync = new();
        private readonly Queue<WindowsProcessIdentity> _identities;
        private readonly Queue<bool> _aliveStates;
        private readonly RetainedReleaseHandleSet _retainedHandles;
        private readonly Exception? _captureFailure;
        private readonly Exception? _disposeFailure;
        private int _captureCount;
        private int _disposed;
        private int _blockCaptureNumber;

        internal FakeRetainedPeerIdentityLease(
            IEnumerable<WindowsProcessIdentity> identities,
            RetainedReleaseHandleSet retainedHandles,
            IEnumerable<bool>? aliveStates = null,
            Exception? captureFailure = null,
            Exception? disposeFailure = null)
        {
            _identities = new Queue<WindowsProcessIdentity>(identities);
            _aliveStates = new Queue<bool>(aliveStates ?? new[] { true });
            _retainedHandles = retainedHandles;
            _captureFailure = captureFailure;
            _disposeFailure = disposeFailure;
            AllowCapture.Set();
            Ensure(_identities.Count > 0, "fake retained lease requires an identity");
            Ensure(_aliveStates.Count > 0, "fake retained lease requires a liveness state");
        }

        public bool IsAlive
        {
            get
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                lock (_sync)
                {
                    return _aliveStates.Count > 1
                        ? _aliveStates.Dequeue()
                        : _aliveStates.Peek();
                }
            }
        }

        public RetainedReleaseHandleSet RetainedHandles
        {
            get
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                RetainedHandleReadCount++;
                return _retainedHandles;
            }
        }

        internal ManualResetEventSlim CaptureEntered { get; } = new(false);

        internal ManualResetEventSlim AllowCapture { get; } = new(false);

        internal int DisposeCallCount { get; private set; }

        internal int CaptureCount => Volatile.Read(ref _captureCount);

        internal int RetainedHandleReadCount { get; private set; }

        public WindowsProcessIdentity Capture()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            var captureNumber = Interlocked.Increment(ref _captureCount);
            if (captureNumber == Volatile.Read(ref _blockCaptureNumber))
            {
                CaptureEntered.Set();
                AllowCapture.Wait(TimeSpan.FromSeconds(10));
            }

            if (_captureFailure is not null)
            {
                throw _captureFailure;
            }

            lock (_sync)
            {
                return _identities.Count > 1
                    ? _identities.Dequeue()
                    : _identities.Peek();
            }
        }

        public void Dispose()
        {
            DisposeCallCount++;
            Interlocked.Exchange(ref _disposed, 1);
            if (_disposeFailure is not null)
            {
                throw _disposeFailure;
            }
        }

        internal void BlockCapture(int captureNumber)
        {
            Volatile.Write(ref _blockCaptureNumber, captureNumber);
            AllowCapture.Reset();
        }

        internal void ReleaseCapture() => AllowCapture.Set();
    }
}
