using CodexGuardian.Trust;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

internal static class WindowsConnectedClientPeerTrustNativeTests
{
    internal const string ParentArgument = "--native-connected-client-probe";
    internal const string ChildArgument = "--native-connected-client-child-probe";
    internal const string CompletionMarker = "NATIVE_CONNECTED_CLIENT_PROBE_COMPLETE";
    private const string BrokerFirstDuplexScenario = "brokerFirstDuplex";
    private const string BrokerHelloRequiredScenario = "brokerHelloRequired";
    private const string DuplicateBrokerHelloScenario = "duplicateBrokerHello";
    private const string InvalidBrokerRoleScenario = "invalidBrokerRole";
    private const string GuardianSpokeFirstScenario = "guardianSpokeFirst";
    private const string WriteAfterReadScenario = "writeAfterRead";
    private const string WriteAfterLeaseScenario = "writeAfterLease";
    private const string ChildConnectedMarker = "NATIVE_CONNECTED_CLIENT_CHILD_CONNECTED";
    private const string ChildBrokerHelloMarker = "NATIVE_CONNECTED_CLIENT_CHILD_BROKER_HELLO_RECEIVED";
    private const string ChildHelloMarker = "NATIVE_CONNECTED_CLIENT_CHILD_HELLO_SENT";
    private const string ChildPongMarker = "NATIVE_CONNECTED_CLIENT_CHILD_PONG_SENT";
    private const string ChildDisconnectedMarker = "NATIVE_CONNECTED_CLIENT_CHILD_DISCONNECTED";
    private const string ChildScenarioCompleteMarker = "NATIVE_CONNECTED_CLIENT_CHILD_SCENARIO_COMPLETE";
    private const string ChildCompleteMarker = "NATIVE_CONNECTED_CLIENT_CHILD_COMPLETE";
    private const string ChildReceiptMarker = "NATIVE_CONNECTED_CLIENT_SYNTHETIC_CHILD_RECEIPT";
    private const string ReleaseId = "r13-connected-client-synthetic-tests-apphost-probe";
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(15);

    internal static bool IsChildProbeInvocation(IReadOnlyList<string> args) =>
        args.Contains(ChildArgument, StringComparer.OrdinalIgnoreCase);

    internal static async Task<int> RunChildProbeAsync(string[] args)
    {
        try
        {
            while (true)
            {
                var bootstrapLine = await Console.In.ReadLineAsync()
                    .WaitAsync(ProbeTimeout)
                    .ConfigureAwait(false) ?? throw new EndOfStreamException(
                        "The connected-client child did not receive its bootstrap.");
                if (string.Equals(bootstrapLine, "EXIT", StringComparison.Ordinal))
                {
                    break;
                }

                using var document = JsonDocument.Parse(bootstrapLine);
                var scenario = ReadString(document.RootElement, "scenario");
                var endpoint = ReadString(document.RootElement, "endpoint");
                var connectionNonce = ReadString(document.RootElement, "connectionNonce");
                var releaseId = ReadString(document.RootElement, "releaseId");
                var manifestSha256 = ReadString(document.RootElement, "manifestSha256");
                var expectedBrokerHello = new BrokerPeerHello(
                    BrokerPeerHelloProtocol.ProtocolVersion,
                    BrokerPeerRole.Broker,
                    ReadUInt32(document.RootElement, "brokerProcessId"),
                    ReadUInt32(document.RootElement, "brokerSessionId"),
                    DateTimeOffset.FromFileTime(
                        ReadInt64(document.RootElement, "brokerCreationTimeFileTime")),
                    connectionNonce,
                    releaseId,
                    manifestSha256);

                using var client = WindowsSameLogonNamedPipeClient.Connect(
                    endpoint,
                    TimeSpan.FromSeconds(5),
                    CancellationToken.None);
                WriteScenarioMarker(ChildConnectedMarker, scenario);
                using var current = Process.GetCurrentProcess();
                var launch = WindowsPeerNative.CaptureLaunchedPeer(current.SafeHandle);
                var guardianHello = new BrokerPeerHello(
                    BrokerPeerHelloProtocol.ProtocolVersion,
                    BrokerPeerRole.Guardian,
                    launch.ProcessId,
                    launch.SessionId,
                    launch.CreationTimeUtc,
                    connectionNonce,
                    releaseId,
                    manifestSha256);

                if (string.Equals(scenario, BrokerFirstDuplexScenario, StringComparison.Ordinal) ||
                    string.Equals(scenario, DuplicateBrokerHelloScenario, StringComparison.Ordinal))
                {
                    var brokerHelloFrame = await WindowsNamedPipeMessageIO.ReadMessageAsync(
                            client.Stream,
                            BrokerPeerHelloProtocol.MaximumHelloBytes,
                            CancellationToken.None)
                        .ConfigureAwait(false);
                    ValidateCanonicalBrokerHello(brokerHelloFrame, expectedBrokerHello);
                    WriteScenarioMarker(ChildBrokerHelloMarker, scenario);
                }
                else if (string.Equals(scenario, GuardianSpokeFirstScenario, StringComparison.Ordinal) ||
                         string.Equals(scenario, WriteAfterReadScenario, StringComparison.Ordinal))
                {
                    await WriteHelloAsync(client.Stream, guardianHello).ConfigureAwait(false);
                    WriteScenarioMarker(ChildHelloMarker, scenario);
                }
                else if (!string.Equals(scenario, InvalidBrokerRoleScenario, StringComparison.Ordinal) &&
                         !string.Equals(scenario, WriteAfterLeaseScenario, StringComparison.Ordinal) &&
                         !string.Equals(scenario, BrokerHelloRequiredScenario, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "The connected-client child received an unknown scenario.");
                }

                if (string.Equals(scenario, BrokerFirstDuplexScenario, StringComparison.Ordinal))
                {
                    await WriteHelloAsync(client.Stream, guardianHello).ConfigureAwait(false);
                    WriteScenarioMarker(ChildHelloMarker, scenario);
                    var ping = await WindowsNamedPipeMessageIO.ReadMessageAsync(
                            client.Stream,
                            AuthenticatedPipePeerConnection.AbsoluteMaximumMessageBytes,
                            CancellationToken.None)
                        .ConfigureAwait(false);
                    if (!ping.Span.SequenceEqual(Encoding.ASCII.GetBytes("PING")))
                    {
                        throw new InvalidDataException(
                            "The connected-client child received an unexpected ping.");
                    }

                    await WindowsNamedPipeMessageIO.WriteMessageAsync(
                            client.Stream,
                            Encoding.ASCII.GetBytes("PONG"),
                            CancellationToken.None)
                        .ConfigureAwait(false);
                    WriteScenarioMarker(ChildPongMarker, scenario);
                }

                var disconnected = await WindowsNamedPipeMessageIO.ReadMessageAsync(
                        client.Stream,
                        AuthenticatedPipePeerConnection.AbsoluteMaximumMessageBytes,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                if (!disconnected.IsEmpty)
                {
                    throw new InvalidDataException(
                        "The connected-client child received data after its owner closed.");
                }

                WriteScenarioMarker(ChildDisconnectedMarker, scenario);
                WriteScenarioMarker(ChildScenarioCompleteMarker, scenario);
            }

            WriteLine(ChildCompleteMarker);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("NATIVE_CONNECTED_CLIENT_CHILD_FAILED " + exception.GetType().Name);
            return 1;
        }
    }

    internal static async Task RunIfRequestedAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        if (!Environment.GetCommandLineArgs().Contains(
                ParentArgument,
                StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        var passed = false;
        try
        {
            await RunProbeAsync().ConfigureAwait(false);
            passed = true;
            assert(
                true,
                "synthetic Tests-apphost Guardian-role reverse peer trust and duplex ping/pong");
        }
        catch (Exception exception)
        {
            assert(false, "synthetic Tests-apphost Guardian-role reverse peer trust: " +
                DescribeFailure(exception));
        }

        if (passed)
        {
            WriteLine(CompletionMarker);
        }
    }

    private static async Task RunProbeAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The connected-client probe requires Windows.");
        }

        var binRoot = ResolveArtifactsBinRoot();
        var fixture = StageProbeFixture(binRoot);
        var testsDirectory = fixture.GuardianDirectory;
        var testsExecutable = fixture.GuardianExecutable;
        if (!File.Exists(testsExecutable))
        {
            throw new FileNotFoundException("The fresh Tests apphost is absent.", testsExecutable);
        }

        using var guardianArtifacts = CaptureArtifacts(
            fixture.Root,
            BrokerPeerRole.Guardian,
            "CodexGuardian",
            includeControl: true,
            includeTrust: true,
            includeProbeRuntime: true);
        using var brokerArtifacts = CaptureArtifacts(
            fixture.Root,
            BrokerPeerRole.Broker,
            "CodexGuardian.Broker",
            includeControl: true,
            includeTrust: true,
            includeProbeRuntime: false);
        var manifestSha256 = ComputeManifestSha256(guardianArtifacts, brokerArtifacts);
        var manifest = VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId,
            manifestSha256,
            guardianArtifacts.Root,
            CreateRoleDefinition(guardianArtifacts),
            CreateRoleDefinition(brokerArtifacts));
        var guardianRelease = manifest.GetArtifactSet(BrokerPeerRole.Guardian);
        var startInfo = new ProcessStartInfo(testsExecutable)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = testsDirectory
        };
        startInfo.ArgumentList.Add(ChildArgument);
        using var child = Process.Start(startInfo) ?? throw new InvalidOperationException(
            "The connected-client child did not start.");
        WriteSyntheticChildReceipt(child, testsExecutable);
        var standardError = child.StandardError.ReadToEndAsync();
        var guardianLaunch = WindowsPeerNative.CaptureLaunchedPeer(child.SafeHandle);
        using var current = Process.GetCurrentProcess();
        var brokerLaunch = WindowsPeerNative.CaptureLaunchedPeer(current.SafeHandle);
        try
        {
            await RunBrokerFirstDuplexScenarioAsync(
                child,
                guardianLaunch,
                brokerLaunch,
                guardianArtifacts,
                guardianRelease,
                manifestSha256).ConfigureAwait(false);
            await RunBrokerHelloRequiredScenarioAsync(
                child,
                guardianLaunch,
                brokerLaunch,
                guardianArtifacts,
                guardianRelease,
                manifestSha256).ConfigureAwait(false);
            await RunDuplicateBrokerHelloScenarioAsync(
                child,
                guardianLaunch,
                brokerLaunch,
                guardianArtifacts,
                guardianRelease,
                manifestSha256).ConfigureAwait(false);
            await RunInvalidBrokerRoleScenarioAsync(
                child,
                guardianLaunch,
                brokerLaunch,
                guardianArtifacts,
                guardianRelease,
                manifestSha256).ConfigureAwait(false);
            await RunGuardianSpokeFirstScenarioAsync(
                child,
                guardianLaunch,
                brokerLaunch,
                guardianArtifacts,
                guardianRelease,
                manifestSha256).ConfigureAwait(false);
            await RunWriteAfterReadScenarioAsync(
                child,
                guardianLaunch,
                brokerLaunch,
                guardianArtifacts,
                guardianRelease,
                manifestSha256).ConfigureAwait(false);
            await RunWriteAfterLeaseScenarioAsync(
                child,
                guardianLaunch,
                brokerLaunch,
                guardianArtifacts,
                guardianRelease,
                manifestSha256).ConfigureAwait(false);

            await child.StandardInput.WriteLineAsync("EXIT").ConfigureAwait(false);
            await child.StandardInput.FlushAsync().ConfigureAwait(false);
            Ensure(
                string.Equals(
                    await ReadLineBoundedAsync(child.StandardOutput).ConfigureAwait(false),
                    ChildCompleteMarker,
                    StringComparison.Ordinal),
                "the connected-client child did not complete after explicit EXIT");
            Ensure(
                child.WaitForExit((int)ProbeTimeout.TotalMilliseconds) &&
                child.ExitCode == 0 &&
                (await standardError.ConfigureAwait(false)).Length == 0,
                "the connected-client child did not exit cleanly");
        }
        finally
        {
            if (!child.HasExited)
            {
                try
                {
                    child.StandardInput.WriteLine("EXIT");
                    child.StandardInput.Flush();
                }
                catch { }

                try { child.WaitForExit(2000); } catch { }
                if (!child.HasExited)
                {
                    try { child.Kill(entireProcessTree: true); } catch { }
                }
            }
        }
    }

    private static async Task RunBrokerFirstDuplexScenarioAsync(
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var scenario = await ConnectScenarioAsync(
            BrokerFirstDuplexScenario,
            child,
            guardianLaunch,
            brokerLaunch,
            guardianArtifacts,
            guardianRelease,
            manifestSha256).ConfigureAwait(false);
        WindowsConnectedClientPeerTrustPlatform? platform = scenario.Platform;
        PendingPipePeerVerification? pending = null;
        AuthenticatedPipePeerConnection? connection = null;
        try
        {
            var transport = (INamedPipePeerMessageTransport)platform;
            await platform.WriteBrokerHelloBeforePeerAuthenticationAsync(scenario.BrokerHello)
                .ConfigureAwait(false);
            Ensure(
                platform.ReadGeneration == 0 && !transport.Completion.IsCompleted,
                "the Broker hello write advanced authentication or completed the transport");
            await ExpectTrustCodeAsync(
                "peer-message-before-authentication",
                () => transport.WriteMessageAsync(
                    Encoding.ASCII.GetBytes("UNAUTHENTICATED"),
                    CancellationToken.None).AsTask()).ConfigureAwait(false);
            await ExpectScenarioMarkerAsync(
                child,
                ChildBrokerHelloMarker,
                BrokerFirstDuplexScenario).ConfigureAwait(false);
            await ExpectScenarioMarkerAsync(
                child,
                ChildHelloMarker,
                BrokerFirstDuplexScenario).ConfigureAwait(false);

            var verifier = new WindowsNamedPipePeerVerifier(
                WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout);
            pending = verifier.BeginVerification(
                platform,
                NamedPipePeerKind.Client,
                scenario.Expectation);
            platform = null;
            connection = await pending.CompleteConnectionAsync()
                .AsTask()
                .WaitAsync(ProbeTimeout)
                .ConfigureAwait(false);
            await pending.DisposeAsync().ConfigureAwait(false);
            pending = null;

            await connection.WriteMessageAsync(
                    Encoding.ASCII.GetBytes("PING"),
                    CancellationToken.None)
                .ConfigureAwait(false);
            var pong = await connection.ReadMessageAsync(
                    AuthenticatedPipePeerConnection.AbsoluteMaximumMessageBytes,
                    CancellationToken.None)
                .AsTask()
                .WaitAsync(ProbeTimeout)
                .ConfigureAwait(false);
            Ensure(
                pong.Span.SequenceEqual(Encoding.ASCII.GetBytes("PONG")),
                "the authenticated connected-client channel returned a non-PONG reply");
            await ExpectScenarioMarkerAsync(
                child,
                ChildPongMarker,
                BrokerFirstDuplexScenario).ConfigureAwait(false);

            await connection.DisposeAsync().ConfigureAwait(false);
            connection = null;
            Ensure(
                !child.WaitForExit(500),
                "disposing the Guardian client channel terminated the managed child");
            await ExpectScenarioClosedAsync(child, BrokerFirstDuplexScenario)
                .ConfigureAwait(false);
        }
        finally
        {
            if (connection is not null)
            {
                try { await connection.DisposeAsync().ConfigureAwait(false); } catch { }
            }

            if (pending is not null)
            {
                try { await pending.DisposeAsync().ConfigureAwait(false); } catch { }
            }

            platform?.Dispose();
        }
    }

    private static async Task RunDuplicateBrokerHelloScenarioAsync(
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var scenario = await ConnectScenarioAsync(
            DuplicateBrokerHelloScenario,
            child,
            guardianLaunch,
            brokerLaunch,
            guardianArtifacts,
            guardianRelease,
            manifestSha256).ConfigureAwait(false);
        using var platform = scenario.Platform;
        await platform.WriteBrokerHelloBeforePeerAuthenticationAsync(scenario.BrokerHello)
            .ConfigureAwait(false);
        await ExpectScenarioMarkerAsync(
            child,
            ChildBrokerHelloMarker,
            DuplicateBrokerHelloScenario).ConfigureAwait(false);
        await ExpectTrustCodeAsync(
            "peer-broker-hello-write-order-invalid",
            () => platform.WriteBrokerHelloBeforePeerAuthenticationAsync(
                scenario.BrokerHello).AsTask()).ConfigureAwait(false);
        await ExpectTransportFailureAsync(
            platform,
            "peer-broker-hello-write-order-invalid").ConfigureAwait(false);
        platform.Dispose();
        await ExpectScenarioClosedAsync(child, DuplicateBrokerHelloScenario)
            .ConfigureAwait(false);
    }

    private static async Task RunBrokerHelloRequiredScenarioAsync(
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var scenario = await ConnectScenarioAsync(
            BrokerHelloRequiredScenario,
            child,
            guardianLaunch,
            brokerLaunch,
            guardianArtifacts,
            guardianRelease,
            manifestSha256).ConfigureAwait(false);
        using var platform = scenario.Platform;
        await ExpectTrustCodeAsync(
            "peer-broker-hello-required",
            () => Task.Run(() =>
            {
                using var lease = platform.OpenRetainedPeer(
                    scenario.Expectation.ProcessId,
                    guardianRelease);
            })).ConfigureAwait(false);
        platform.Dispose();
        await ExpectScenarioClosedAsync(child, BrokerHelloRequiredScenario)
            .ConfigureAwait(false);
    }

    private static async Task RunInvalidBrokerRoleScenarioAsync(
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var scenario = await ConnectScenarioAsync(
            InvalidBrokerRoleScenario,
            child,
            guardianLaunch,
            brokerLaunch,
            guardianArtifacts,
            guardianRelease,
            manifestSha256).ConfigureAwait(false);
        using var platform = scenario.Platform;
        await ExpectTrustCodeAsync(
            "peer-broker-hello-role-invalid",
            () => platform.WriteBrokerHelloBeforePeerAuthenticationAsync(
                scenario.BrokerHello with { Role = BrokerPeerRole.Guardian }).AsTask())
            .ConfigureAwait(false);
        await ExpectTransportFailureAsync(platform, "peer-broker-hello-role-invalid")
            .ConfigureAwait(false);
        platform.Dispose();
        await ExpectScenarioClosedAsync(child, InvalidBrokerRoleScenario)
            .ConfigureAwait(false);
    }

    private static async Task RunGuardianSpokeFirstScenarioAsync(
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var scenario = await ConnectScenarioAsync(
            GuardianSpokeFirstScenario,
            child,
            guardianLaunch,
            brokerLaunch,
            guardianArtifacts,
            guardianRelease,
            manifestSha256).ConfigureAwait(false);
        using var platform = scenario.Platform;
        await ExpectScenarioMarkerAsync(child, ChildHelloMarker, GuardianSpokeFirstScenario)
            .ConfigureAwait(false);
        await ExpectTrustCodeAsync(
            "peer-broker-hello-client-spoke-first",
            () => platform.WriteBrokerHelloBeforePeerAuthenticationAsync(
                scenario.BrokerHello).AsTask()).ConfigureAwait(false);
        await ExpectTransportFailureAsync(
            platform,
            "peer-broker-hello-client-spoke-first").ConfigureAwait(false);
        platform.Dispose();
        await ExpectScenarioClosedAsync(child, GuardianSpokeFirstScenario)
            .ConfigureAwait(false);
    }

    private static async Task RunWriteAfterReadScenarioAsync(
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var scenario = await ConnectScenarioAsync(
            WriteAfterReadScenario,
            child,
            guardianLaunch,
            brokerLaunch,
            guardianArtifacts,
            guardianRelease,
            manifestSha256).ConfigureAwait(false);
        using var platform = scenario.Platform;
        await ExpectScenarioMarkerAsync(child, ChildHelloMarker, WriteAfterReadScenario)
            .ConfigureAwait(false);
        using (var evidence = await platform.ReadBoundedHelloAndCaptureIdentityAsync(
                   NamedPipePeerKind.Client,
                   BrokerPeerHelloProtocol.MaximumHelloBytes,
                   CancellationToken.None).AsTask().WaitAsync(ProbeTimeout).ConfigureAwait(false))
        {
            Ensure(
                evidence.ReadGeneration == 1 && platform.ReadGeneration == 1,
                "the explicit Guardian hello read did not advance exactly one generation");
        }

        await ExpectTrustCodeAsync(
            "peer-broker-hello-write-order-invalid",
            () => platform.WriteBrokerHelloBeforePeerAuthenticationAsync(
                scenario.BrokerHello).AsTask()).ConfigureAwait(false);
        await ExpectTransportFailureAsync(
            platform,
            "peer-broker-hello-write-order-invalid").ConfigureAwait(false);
        platform.Dispose();
        await ExpectScenarioClosedAsync(child, WriteAfterReadScenario)
            .ConfigureAwait(false);
    }

    private static async Task RunWriteAfterLeaseScenarioAsync(
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var scenario = await ConnectScenarioAsync(
            WriteAfterLeaseScenario,
            child,
            guardianLaunch,
            brokerLaunch,
            guardianArtifacts,
            guardianRelease,
            manifestSha256).ConfigureAwait(false);
        using var platform = scenario.Platform;
        using var lease = platform.OpenRetainedPeer(
            scenario.Expectation.ProcessId,
            guardianRelease);
        await ExpectTrustCodeAsync(
            "peer-broker-hello-write-order-invalid",
            () => platform.WriteBrokerHelloBeforePeerAuthenticationAsync(
                scenario.BrokerHello).AsTask()).ConfigureAwait(false);
        await ExpectTransportFailureAsync(
            platform,
            "peer-broker-hello-write-order-invalid").ConfigureAwait(false);
        platform.Dispose();
        await ExpectScenarioClosedAsync(child, WriteAfterLeaseScenario)
            .ConfigureAwait(false);
    }

    private static async Task<ConnectedScenario> ConnectScenarioAsync(
        string scenario,
        Process child,
        WindowsLaunchedPeerIdentity guardianLaunch,
        WindowsLaunchedPeerIdentity brokerLaunch,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        VerifiedReleaseArtifactSet guardianRelease,
        string manifestSha256)
    {
        var endpoint = "CodexGuardian.r13.client." +
            Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var connectionNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var brokerHello = new BrokerPeerHello(
            BrokerPeerHelloProtocol.ProtocolVersion,
            BrokerPeerRole.Broker,
            brokerLaunch.ProcessId,
            brokerLaunch.SessionId,
            brokerLaunch.CreationTimeUtc,
            connectionNonce,
            ReleaseId,
            manifestSha256);
        using var server = WindowsSameLogonNamedPipeServer.Create(endpoint);
        var bootstrap = JsonSerializer.Serialize(new
        {
            scenario,
            endpoint,
            connectionNonce,
            releaseId = ReleaseId,
            manifestSha256,
            brokerProcessId = brokerHello.ProcessId,
            brokerSessionId = brokerHello.SessionId,
            brokerCreationTimeFileTime = brokerHello.CreationTimeUtc.ToFileTime()
        });
        await child.StandardInput.WriteLineAsync(bootstrap).ConfigureAwait(false);
        await child.StandardInput.FlushAsync().ConfigureAwait(false);
        await server.WaitForConnectionAsync(CancellationToken.None)
            .WaitAsync(ProbeTimeout)
            .ConfigureAwait(false);
        await ExpectScenarioMarkerAsync(child, ChildConnectedMarker, scenario)
            .ConfigureAwait(false);

        var requiresBrokerHello =
            !string.Equals(scenario, WriteAfterReadScenario, StringComparison.Ordinal) &&
            !string.Equals(scenario, WriteAfterLeaseScenario, StringComparison.Ordinal);
        var platform = requiresBrokerHello
            ? WindowsConnectedClientPeerTrustPlatform
                .TakeConnectedClientForBrokerFirstHandshake(
                    server,
                    child.SafeHandle,
                    guardianArtifacts)
            : WindowsConnectedClientPeerTrustPlatform.TakeConnectedClient(
                server,
                child.SafeHandle,
                guardianArtifacts);
        try
        {
            server.Dispose();
            Ensure(
                !server.IsConnected,
                "the caller retained a live server alias after connected-client ownership transfer");
            var expectation = new BrokerPeerExpectation(
                guardianLaunch.Token,
                guardianLaunch.AppModel,
                guardianRelease,
                connectionNonce,
                guardianLaunch.ProcessId,
                guardianLaunch.CreationTimeUtc);
            return new ConnectedScenario(platform, expectation, brokerHello);
        }
        catch
        {
            platform.Dispose();
            throw;
        }
    }

    private static NativeProbeFixture StageProbeFixture(string binRoot)
    {
        const int maximumFilesPerRelease = 16;
        const long maximumBytesPerRelease = 64L * 1024 * 1024;

        var binDirectory = new DirectoryInfo(Path.GetFullPath(binRoot));
        Ensure(
            binDirectory.Exists &&
            string.Equals(binDirectory.Name, "bin", StringComparison.OrdinalIgnoreCase),
            "the native probe bin root is invalid");
        var phaseDirectory = binDirectory.Parent ?? throw new DirectoryNotFoundException(
            "The native probe artifact phase root is unavailable.");
        Ensure(
            string.Equals(
                Path.GetPathRoot(phaseDirectory.FullName),
                "D:\\",
                StringComparison.OrdinalIgnoreCase),
            "the native probe fixture is not rooted on D drive");
        EnsureRegularDirectoryChain(binDirectory.FullName, phaseDirectory.FullName);

        var fixtureRoot = Path.Combine(
            phaseDirectory.FullName,
            "native-connected-client-fixture");
        Ensure(
            !Directory.Exists(fixtureRoot) && !File.Exists(fixtureRoot),
            "the native connected-client fixture already exists in this artifact phase");

        var testsRelease = Path.Combine(
            binDirectory.FullName,
            "CodexGuardian.Tests",
            "release");
        var guardianRelease = Path.Combine(
            binDirectory.FullName,
            "CodexGuardian",
            "release");
        var brokerRelease = Path.Combine(
            binDirectory.FullName,
            "CodexGuardian.Broker",
            "release");
        var controlRelease = Path.Combine(
            binDirectory.FullName,
            "CodexGuardian.Control",
            "release");
        var trustRelease = Path.Combine(
            binDirectory.FullName,
            "CodexGuardian.Trust",
            "release");
        foreach (var source in new[]
                 {
                     testsRelease,
                     guardianRelease,
                     brokerRelease,
                     controlRelease,
                     trustRelease
                 })
        {
            EnsureRegularDirectoryChain(source, binDirectory.FullName);
        }

        var canonicalControl = Path.Combine(controlRelease, "CodexGuardian.Control.dll");
        var canonicalTrust = Path.Combine(trustRelease, "CodexGuardian.Trust.dll");
        EnsureDependencyCopiesMatch(
            canonicalControl,
            Path.Combine(testsRelease, "CodexGuardian.Control.dll"),
            Path.Combine(brokerRelease, "CodexGuardian.Control.dll"));
        EnsureDependencyCopiesMatch(
            canonicalTrust,
            Path.Combine(testsRelease, "CodexGuardian.Trust.dll"),
            Path.Combine(brokerRelease, "CodexGuardian.Trust.dll"));

        var guardianDirectory = Path.Combine(fixtureRoot, "CodexGuardian", "release");
        var brokerDirectory = Path.Combine(fixtureRoot, "CodexGuardian.Broker", "release");
        var guardianFiles = new[]
        {
            new FixtureFile(Path.Combine(testsRelease, "CodexGuardian.Tests.exe"), "CodexGuardian.exe"),
            new FixtureFile(Path.Combine(guardianRelease, "CodexGuardian.dll"), "CodexGuardian.dll"),
            new FixtureFile(Path.Combine(guardianRelease, "CodexGuardian.deps.json"), "CodexGuardian.deps.json"),
            new FixtureFile(Path.Combine(guardianRelease, "CodexGuardian.runtimeconfig.json"), "CodexGuardian.runtimeconfig.json"),
            new FixtureFile(Path.Combine(testsRelease, "CodexGuardian.Tests.dll"), "CodexGuardian.Tests.dll"),
            new FixtureFile(Path.Combine(testsRelease, "CodexGuardian.Tests.deps.json"), "CodexGuardian.Tests.deps.json"),
            new FixtureFile(Path.Combine(testsRelease, "CodexGuardian.Tests.runtimeconfig.json"), "CodexGuardian.Tests.runtimeconfig.json"),
            new FixtureFile(canonicalControl, "CodexGuardian.Control.dll"),
            new FixtureFile(canonicalTrust, "CodexGuardian.Trust.dll")
        };
        var brokerFiles = new[]
        {
            new FixtureFile(Path.Combine(brokerRelease, "CodexGuardian.Broker.exe"), "CodexGuardian.Broker.exe"),
            new FixtureFile(Path.Combine(brokerRelease, "CodexGuardian.Broker.dll"), "CodexGuardian.Broker.dll"),
            new FixtureFile(Path.Combine(brokerRelease, "CodexGuardian.Broker.deps.json"), "CodexGuardian.Broker.deps.json"),
            new FixtureFile(Path.Combine(brokerRelease, "CodexGuardian.Broker.runtimeconfig.json"), "CodexGuardian.Broker.runtimeconfig.json"),
            new FixtureFile(canonicalControl, "CodexGuardian.Control.dll"),
            new FixtureFile(canonicalTrust, "CodexGuardian.Trust.dll")
        };
        Ensure(
            guardianFiles.Length == 9 && brokerFiles.Length == 6,
            "the synthetic native probe fixture allowlist changed");
        CopyBoundedFixtureFiles(
            guardianFiles,
            guardianDirectory,
            phaseDirectory.FullName,
            maximumFilesPerRelease,
            maximumBytesPerRelease);
        CopyBoundedFixtureFiles(
            brokerFiles,
            brokerDirectory,
            phaseDirectory.FullName,
            maximumFilesPerRelease,
            maximumBytesPerRelease);
        EnsureRegularDirectoryChain(fixtureRoot, phaseDirectory.FullName);

        var guardianExecutable = Path.Combine(guardianDirectory, "CodexGuardian.exe");
        Ensure(
            string.Equals(
                ComputeFileSha256(guardianExecutable),
                ComputeFileSha256(Path.Combine(testsRelease, "CodexGuardian.Tests.exe")),
                StringComparison.Ordinal),
            "the synthetic Guardian-role Tests apphost copy is not exact");

        return new NativeProbeFixture(
            fixtureRoot,
            guardianDirectory,
            guardianExecutable);
    }

    private static void CopyBoundedFixtureFiles(
        IReadOnlyList<FixtureFile> plan,
        string destination,
        string boundary,
        int maximumFiles,
        long maximumBytes)
    {
        ArgumentNullException.ThrowIfNull(plan);
        long totalBytes = 0;
        var destinationNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Ensure(
            plan.Count is > 0 && plan.Count <= maximumFiles,
            "a native probe fixture plan exceeds its file-count bound");
        foreach (var item in plan)
        {
            ArgumentNullException.ThrowIfNull(item);
            var file = new FileInfo(Path.GetFullPath(item.Source));
            Ensure(
                file.Exists &&
                (file.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) == 0,
                "a native probe fixture source is absent, a reparse point, or a device");
            Ensure(
                !string.IsNullOrWhiteSpace(item.DestinationName) &&
                string.Equals(
                    Path.GetFileName(item.DestinationName),
                    item.DestinationName,
                    StringComparison.Ordinal) &&
                destinationNames.Add(item.DestinationName),
                "a native probe fixture destination name is invalid or duplicated");
            totalBytes = checked(totalBytes + file.Length);
        }

        Ensure(
            totalBytes <= maximumBytes,
            "a native probe fixture plan exceeds its byte bound");
        Directory.CreateDirectory(destination);
        EnsureRegularDirectoryChain(destination, boundary);
        var destinationDirectory = new DirectoryInfo(destination);
        Ensure(
            (destinationDirectory.Attributes & FileAttributes.ReparsePoint) == 0,
            "a native probe fixture directory is a reparse point");
        foreach (var item in plan)
        {
            var source = new FileInfo(Path.GetFullPath(item.Source));
            var target = Path.Combine(destinationDirectory.FullName, item.DestinationName);
            Ensure(!File.Exists(target), "a native probe fixture target already exists");
            File.Copy(source.FullName, target, overwrite: false);
            var copied = new FileInfo(target);
            Ensure(
                copied.Exists &&
                (copied.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) == 0 &&
                copied.Length == source.Length &&
                string.Equals(
                    ComputeFileSha256(copied.FullName),
                    ComputeFileSha256(source.FullName),
                    StringComparison.Ordinal),
                "a native probe release file copy is incomplete");
        }
    }

    private static void EnsureDependencyCopiesMatch(
        string canonicalPath,
        params string[] copiedPaths)
    {
        var canonical = new FileInfo(Path.GetFullPath(canonicalPath));
        Ensure(
            canonical.Exists &&
            (canonical.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) == 0,
            "a canonical native probe dependency is absent or invalid");
        var canonicalSha256 = ComputeFileSha256(canonical.FullName);
        foreach (var path in copiedPaths)
        {
            var copy = new FileInfo(Path.GetFullPath(path));
            Ensure(
                copy.Exists &&
                (copy.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) == 0 &&
                copy.Length == canonical.Length &&
                string.Equals(
                    ComputeFileSha256(copy.FullName),
                    canonicalSha256,
                    StringComparison.Ordinal),
                "a native probe dependency copy differs from its canonical project output");
        }
    }

    private static void EnsureRegularDirectoryChain(string path, string boundary)
    {
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var fullBoundary = Path.TrimEndingDirectorySeparator(Path.GetFullPath(boundary));
        var boundaryPrefix = fullBoundary + Path.DirectorySeparatorChar;
        Ensure(
            string.Equals(fullPath, fullBoundary, StringComparison.OrdinalIgnoreCase) ||
            fullPath.StartsWith(boundaryPrefix, StringComparison.OrdinalIgnoreCase),
            "a native probe path escaped its artifact boundary");

        DirectoryInfo? current = new(fullPath);
        while (current is not null)
        {
            Ensure(current.Exists, "a native probe directory-chain component is absent");
            Ensure(
                (current.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) == 0,
                "a native probe directory-chain component is a reparse point or device");
            if (string.Equals(
                    Path.TrimEndingDirectorySeparator(current.FullName),
                    fullBoundary,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException(
            "The native probe directory chain did not reach its artifact boundary.");
    }

    private static string ComputeFileSha256(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed record NativeProbeFixture(
        string Root,
        string GuardianDirectory,
        string GuardianExecutable);

    private sealed record FixtureFile(string Source, string DestinationName);

    private static WindowsRetainedReleaseArtifacts CaptureArtifacts(
        string root,
        BrokerPeerRole role,
        string directoryName,
        bool includeControl,
        bool includeTrust,
        bool includeProbeRuntime) =>
        WindowsRetainedReleaseArtifacts.Capture(
            root,
            role,
            Path.Combine(directoryName, "release", directoryName + ".exe"),
            Path.Combine(directoryName, "release", directoryName + ".dll"),
            Path.Combine(directoryName, "release", directoryName + ".deps.json"),
            Path.Combine(directoryName, "release", directoryName + ".runtimeconfig.json"),
            BuildArtifactPaths(
                directoryName,
                includeControl,
                includeTrust,
                includeProbeRuntime));

    private static IReadOnlyList<WindowsReleaseArtifactPath> BuildArtifactPaths(
        string directoryName,
        bool includeControl,
        bool includeTrust,
        bool includeProbeRuntime)
    {
        var paths = new List<WindowsReleaseArtifactPath>
        {
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.AppHostExe,
                    Path.Combine(directoryName, "release", directoryName + ".exe")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.ManagedEntryDll,
                    Path.Combine(directoryName, "release", directoryName + ".dll")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.DepsJson,
                    Path.Combine(directoryName, "release", directoryName + ".deps.json")),
                new WindowsReleaseArtifactPath(
                    ReleaseArtifactKind.RuntimeConfigJson,
                    Path.Combine(directoryName, "release", directoryName + ".runtimeconfig.json"))
        };
        paths.AddRange(RuntimeDependencies(
            directoryName,
            includeControl,
            includeTrust,
            includeProbeRuntime));
        return paths;
    }

    private static IEnumerable<WindowsReleaseArtifactPath> RuntimeDependencies(
        string directoryName,
        bool includeControl,
        bool includeTrust,
        bool includeProbeRuntime)
    {
        if (includeControl)
        {
            yield return new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine(directoryName, "release", "CodexGuardian.Control.dll"));
        }

        if (includeTrust)
        {
            yield return new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine(directoryName, "release", "CodexGuardian.Trust.dll"));
        }

        if (includeProbeRuntime)
        {
            yield return new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine(directoryName, "release", "CodexGuardian.Tests.dll"));
            yield return new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine(directoryName, "release", "CodexGuardian.Tests.deps.json"));
            yield return new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine(directoryName, "release", "CodexGuardian.Tests.runtimeconfig.json"));
        }
    }

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
        var configuration = Directory.GetParent(
            Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory)) ??
            throw new DirectoryNotFoundException("The Tests configuration directory is unavailable.");
        return (configuration.Parent ?? throw new DirectoryNotFoundException(
            "The Tests artifact directory is unavailable.")).FullName;
    }

    private static async Task<string> ReadLineBoundedAsync(StreamReader reader)
    {
        var line = await reader.ReadLineAsync()
            .WaitAsync(ProbeTimeout)
            .ConfigureAwait(false);
        return line ?? throw new EndOfStreamException(
            "The connected-client child output channel closed unexpectedly.");
    }

    private static string ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!
            : throw new InvalidDataException("The connected-client bootstrap field is missing: " + name);

    private static uint ReadUInt32(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetUInt32(out var parsed)
            ? parsed
            : throw new InvalidDataException(
                "The connected-client bootstrap UInt32 field is missing: " + name);

    private static long ReadInt64(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt64(out var parsed)
            ? parsed
            : throw new InvalidDataException(
                "The connected-client bootstrap Int64 field is missing: " + name);

    private static async Task WriteHelloAsync(
        PipeStream stream,
        BrokerPeerHello hello)
    {
        var canonicalHello = BrokerPeerHelloProtocol.Serialize(hello);
        try
        {
            await WindowsNamedPipeMessageIO.WriteMessageAsync(
                    stream,
                    canonicalHello,
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonicalHello);
        }
    }

    private static void ValidateCanonicalBrokerHello(
        ReadOnlyMemory<byte> frame,
        BrokerPeerHello expected)
    {
        if (frame.IsEmpty)
        {
            throw new EndOfStreamException(
                "The connected-client child did not receive the Broker hello first frame.");
        }

        var parsed = BrokerPeerHelloProtocol.Parse(frame);
        var canonical = BrokerPeerHelloProtocol.Serialize(parsed);
        try
        {
            Ensure(
                frame.Span.SequenceEqual(canonical),
                "the connected-client child received a non-canonical Broker hello frame");
            Ensure(
                parsed == expected,
                "the connected-client child received an unexpected Broker hello identity");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private static async Task ExpectTrustCodeAsync(
        string expectedCode,
        Func<Task> operation)
    {
        try
        {
            await operation().WaitAsync(ProbeTimeout).ConfigureAwait(false);
        }
        catch (BrokerPeerTrustException exception) when (
            string.Equals(exception.Code, expectedCode, StringComparison.Ordinal))
        {
            return;
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                "The connected-client operation failed with an unexpected trust result.",
                exception);
        }

        throw new InvalidOperationException(
            "The connected-client operation unexpectedly succeeded; expected " + expectedCode + ".");
    }

    private static async Task ExpectTransportFailureAsync(
        WindowsConnectedClientPeerTrustPlatform platform,
        string expectedCode)
    {
        try
        {
            await ((INamedPipePeerMessageTransport)platform).Completion
                .WaitAsync(ProbeTimeout)
                .ConfigureAwait(false);
        }
        catch (BrokerPeerTrustException exception) when (
            string.Equals(exception.Code, expectedCode, StringComparison.Ordinal))
        {
            return;
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                "The connected-client transport completed with an unexpected failure.",
                exception);
        }

        throw new InvalidOperationException(
            "The failed Broker hello handshake completed its transport successfully.");
    }

    private static async Task ExpectScenarioMarkerAsync(
        Process child,
        string marker,
        string scenario)
    {
        var expected = marker + " " + scenario;
        Ensure(
            string.Equals(
                await ReadLineBoundedAsync(child.StandardOutput).ConfigureAwait(false),
                expected,
                StringComparison.Ordinal),
            "the connected-client child did not emit " + expected);
    }

    private static async Task ExpectScenarioClosedAsync(
        Process child,
        string scenario)
    {
        await ExpectScenarioMarkerAsync(child, ChildDisconnectedMarker, scenario)
            .ConfigureAwait(false);
        await ExpectScenarioMarkerAsync(child, ChildScenarioCompleteMarker, scenario)
            .ConfigureAwait(false);
    }

    private static void WriteScenarioMarker(string marker, string scenario) =>
        WriteLine(marker + " " + scenario);

    private static string DescribeFailure(Exception failure)
    {
        var parts = new List<string>();
        Exception? current = failure;
        for (var depth = 0; current is not null && depth < 8; depth++)
        {
            var trustCode = current is BrokerPeerTrustException trust
                ? ",code=" + trust.Code
                : string.Empty;
            var nativeCode = current is System.ComponentModel.Win32Exception native
                ? ",native=" + native.NativeErrorCode
                : string.Empty;
            var targetSite = current.TargetSite;
            var site = targetSite is null
                ? string.Empty
                : ",site=" + targetSite.DeclaringType?.Name + "." + targetSite.Name;

            parts.Add(
                "type=" + current.GetType().Name +
                trustCode +
                nativeCode +
                site +
                ",hresult=0x" + current.HResult.ToString("X8"));
            current = current.InnerException;
        }

        return string.Join(" -> ", parts);
    }

    private static void WriteSyntheticChildReceipt(Process child, string expectedExecutable)
    {
        var launch = WindowsPeerNative.CaptureLaunchedPeer(child.SafeHandle);
        var executablePath = Path.GetFullPath(expectedExecutable);
        Ensure(
            launch.ProcessId == checked((uint)child.Id) &&
            WindowsPeerNative.SamePath(launch.FinalImagePath, executablePath),
            "the synthetic connected-client receipt did not bind the retained launch handle");
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            marker = ChildReceiptMarker,
            role = "guardianSyntheticTestsApphost",
            scenario = "connectedClientDuplex",
            processId = launch.ProcessId,
            parentProcessId = Environment.ProcessId,
            creationTimeUtc = launch.CreationTimeUtc.ToString("O"),
            sessionId = launch.SessionId,
            argument = ChildArgument
        }));
        Console.Out.Flush();
    }

    private static void WriteLine(string value)
    {
        Console.WriteLine(value);
        Console.Out.Flush();
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record ConnectedScenario(
        WindowsConnectedClientPeerTrustPlatform Platform,
        BrokerPeerExpectation Expectation,
        BrokerPeerHello BrokerHello);
}
