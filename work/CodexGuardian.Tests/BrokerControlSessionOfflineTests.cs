using CodexGuardian.Broker;
using CodexGuardian.Control;
using CodexGuardian.Trust;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;

internal static class BrokerControlSessionOfflineTests
{
    private const string Epoch = "epoch-control-session-0001";
    private const string OtherEpoch = "epoch-control-session-0002";
    private const string LaunchOperation = "operation-control-launch-0001";
    private const uint GuardianProcessId = 4321;
    private const uint GuardianSessionId = 4;
    private const ulong VolumeSerial = 0x1234;
    private const string UserSid = "S-1-5-21-111-222-333-1001";
    private const string LogonSid = "S-1-5-5-1-2";
    private const string ConnectionNonce =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string ReleaseId = "release-20260806";
    private const string ManifestSha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string ReleaseRoot = @"D:\CodexGuardian\release-20260806";
    private static readonly DateTimeOffset GuardianCreationTime =
        new(2026, 8, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset RuntimeCreationTime =
        new(2026, 8, 6, 12, 5, 0, TimeSpan.Zero);
    private static readonly TimeSpan CaseTimeout = TimeSpan.FromSeconds(10);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "Broker control core has a bounded content-free production surface",
            TestProductionSurfaceAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker command results and subscription resync use exact envelopes",
            TestProtocolEnvelopesAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker session enforces hello-first duplicate-hello and epoch terminal rules",
            TestHelloAndEpochRulesAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker owner invokes one runtime start for accepted operation replay",
            TestStartReplayAndDisconnectAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker owner loses a single-instance race without adopting external Codex",
            TestRaceLostAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker owner degrades faulted observation and cleans natural exit exactly once",
            TestFaultAndNaturalExitAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker session clears resync only after a written full snapshot",
            TestSubscriptionResyncAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Guardian cancellation preserves accepted start while owner disposal cancels it",
            TestCancellationOwnershipAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker owner settles cleanup after a throwing reentrant cancellation callback",
            TestReentrantCancellationCleanupAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker production control-session sources are in the explicit release closure",
            TestReleaseClosureAsync,
            assert).ConfigureAwait(false);
    }

    private static Task TestProductionSurfaceAsync()
    {
        var ownerType = typeof(BrokerRuntimeOwnerV1);
        var sessionType = typeof(BrokerControlSessionV1);
        Ensure(
            ownerType.IsSealed && ownerType.IsNotPublic &&
            sessionType.IsSealed && sessionType.IsNotPublic,
            "Broker runtime owner or control session escaped the internal sealed boundary");
        Ensure(
            typeof(IAsyncDisposable).IsAssignableFrom(ownerType) &&
            typeof(IAsyncDisposable).IsAssignableFrom(sessionType),
            "Broker runtime owner or control session lacks one async lifetime owner");
        Ensure(
            sessionType.GetConstructors(BindingFlags.Instance | BindingFlags.Public).Length == 0,
            "Broker control session has a public construction path");
        Ensure(
            sessionType.GetProperties(BindingFlags.Instance | BindingFlags.Public).Length == 0,
            "Broker control session exposes a public detachable authority property");
        Ensure(
            !typeof(CodexCdpRuntimeStartResultV1).IsDefined(
                typeof(SerializableAttribute),
                inherit: false),
            "runtime start authority became serializable");

        var selectUnexpectedFailure = sessionType.GetMethod(
            "SelectUnexpectedFailure",
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new InvalidOperationException(
                "Broker control session lacks the stop-failure arbitration contract");
        object? Select(Exception failure, bool expectedStop) =>
            selectUnexpectedFailure.Invoke(null, new object?[] { failure, expectedStop });
        var writeFailure = new BrokerPeerTrustException(
            "peer-message-write-failed",
            "fake writer failure");
        var eofFailure = new BrokerPeerTrustException(
            "peer-message-eof",
            "fake peer EOF");
        var readCancellation = new BrokerPeerTrustException(
            "peer-message-read-cancelled",
            "fake read cancellation");
        var writeCancellation = new BrokerPeerTrustException(
            "peer-message-write-cancelled",
            "fake write cancellation");
        var operationCancellation = new OperationCanceledException(
            "fake default-token operation cancellation");
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var cancelledOperation = new OperationCanceledException(
            "fake cancelled operation",
            cancelled.Token);
        var disposedFailure = new ObjectDisposedException(
            "fake-session");
        var failures = new Exception[]
        {
            writeFailure,
            eofFailure,
            readCancellation,
            writeCancellation,
            operationCancellation,
            disposedFailure
        };
        Ensure(
            failures.All(failure => ReferenceEquals(Select(failure, expectedStop: false), failure)) &&
            ReferenceEquals(Select(writeFailure, expectedStop: true), writeFailure) &&
            ReferenceEquals(Select(eofFailure, expectedStop: true), eofFailure) &&
            Select(readCancellation, expectedStop: true) is null &&
            Select(writeCancellation, expectedStop: true) is null &&
            ReferenceEquals(Select(operationCancellation, expectedStop: true), operationCancellation) &&
            Select(cancelledOperation, expectedStop: true) is null &&
            ReferenceEquals(Select(disposedFailure, expectedStop: true), disposedFailure),
            "expected-stop arbitration hid a real transport failure or retained a cancellation");

        var cleanupA = new IOException("cleanup-a");
        var cleanupB = new IOException("cleanup-b");
        Ensure(
            ReferenceEquals(
                BrokerControlFailureArbitration.CombineCleanupFailures(null, cleanupA),
                cleanupA) &&
            ReferenceEquals(
                BrokerControlFailureArbitration.CombineCleanupFailures(cleanupA, cleanupA),
                cleanupA) &&
            BrokerControlFailureArbitration.CombineCleanupFailures(cleanupA, cleanupB) is
                AggregateException { InnerExceptions.Count: 2 } aggregate &&
            ReferenceEquals(aggregate.InnerExceptions[0], cleanupA) &&
            ReferenceEquals(aggregate.InnerExceptions[1], cleanupB),
            "cleanup failure arbitration lost identity or stable ordering");
        var primary = new BrokerControlSessionException(
            "control-test-primary",
            "fake primary failure");
        Ensure(
            ReferenceEquals(
                BrokerControlFailureArbitration.PreserveCleanupFailure(primary, cleanupA),
                primary) &&
            ReferenceEquals(
                primary.Data[BrokerControlFailureArbitration.CleanupFailureDataKey],
                cleanupA),
            "cleanup failure arbitration replaced the exact protocol primary");

        var sourceRoot = FindSourceRoot();
        var ownerSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Broker",
            "BrokerRuntimeOwner.cs"));
        var sessionSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Broker",
            "BrokerControlSession.cs"));
        var forbidden = new[]
        {
            "RecoveryService",
            "FollowUpDispatchService",
            "DesktopIpcClient",
            "Runtime.evaluate",
            "state_5.sqlite",
            "thread/rollback",
            "BrokerWebAuthnPlatform",
            "AppServerClient"
        };
        Ensure(
            forbidden.All(value =>
                !ownerSource.Contains(value, StringComparison.Ordinal) &&
                !sessionSource.Contains(value, StringComparison.Ordinal)),
            "Broker control core contains a write path or unrelated authority surface");
        var beginSubscription = sessionSource.IndexOf(
            "_subscriptionQueue.BeginSubscription(",
            StringComparison.Ordinal);
        var currentSnapshot = beginSubscription < 0
            ? -1
            : sessionSource.IndexOf(
                "var current = _owner.Current;",
                beginSubscription,
                StringComparison.Ordinal);
        var resyncCurrent = currentSnapshot < 0
            ? -1
            : sessionSource.IndexOf(
                "_subscriptionQueue.RequireResync(current);",
                currentSnapshot,
                StringComparison.Ordinal);
        Ensure(
            beginSubscription >= 0 &&
            currentSnapshot > beginSubscription &&
            resyncCurrent > currentSnapshot,
            "subscription establishment does not close the post-owner publication window");
        var processStarted = ownerSource.IndexOf(
            "CodexCdpBrokerSignal.CandidateProcessStarted",
            StringComparison.Ordinal);
        var ownershipVerified = ownerSource.IndexOf(
            "CodexCdpBrokerSignal.CandidateOwnershipVerified",
            processStarted + 1,
            StringComparison.Ordinal);
        var observerCreated = ownerSource.IndexOf(
            "var exitObserver = ObserveRuntimeExitAsync(committedLease);",
            ownershipVerified + 1,
            StringComparison.Ordinal);
        var runtimeCommitted = ownerSource.IndexOf(
            "_runtimeLease = committedLease;",
            observerCreated + 1,
            StringComparison.Ordinal);
        var observerCommitted = ownerSource.IndexOf(
            "_exitObserverTask = exitObserver;",
            runtimeCommitted + 1,
            StringComparison.Ordinal);
        var handshakeCompleted = ownerSource.IndexOf(
            "CodexCdpBrokerSignal.CdpHandshakeCompleted",
            observerCommitted + 1,
            StringComparison.Ordinal);
        var readyPublication = ownerSource.IndexOf(
            "QueuePublicationLocked(ready.Snapshot, excludedSession: null);",
            handshakeCompleted + 1,
            StringComparison.Ordinal);
        Ensure(
            processStarted >= 0 &&
            ownershipVerified > processStarted &&
            observerCreated > ownershipVerified &&
            runtimeCommitted > observerCreated &&
            observerCommitted > runtimeCommitted &&
            handshakeCompleted > observerCommitted &&
            readyPublication > handshakeCompleted &&
            ownerSource.Split(
                "_exitObserverTask = exitObserver;",
                StringSplitOptions.None).Length == 2,
            "managed ownership can commit without one exact observer before handshake publication");
        var normalizedOwnerSource = ownerSource.Replace("\r\n", "\n", StringComparison.Ordinal);
        var normalizedSessionSource = sessionSource.Replace("\r\n", "\n", StringComparison.Ordinal);
        Ensure(
            normalizedOwnerSource.Contains(
                "BrokerControlFailureArbitration.PreserveCleanupFailure(\n                    attachFailure,",
                StringComparison.Ordinal) &&
            normalizedSessionSource.Contains(
                "BrokerControlFailureArbitration.CombineCleanupFailures(\n                failure,",
                StringComparison.Ordinal) &&
            normalizedSessionSource.Contains(
                "failure = BrokerControlFailureArbitration.PreserveCleanupFailure(\n            failure,\n            cleanupFailure);",
                StringComparison.Ordinal),
            "Broker attach or session cleanup no longer preserves bounded secondary failures");
        var brokerProgram = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Broker",
            "Program.cs"));
        Ensure(
            !brokerProgram.Contains("--broker-control-session", StringComparison.Ordinal),
            "the probe-only Broker entry point was prematurely wired to production control");
        return Task.CompletedTask;
    }

    private static Task TestProtocolEnvelopesAsync()
    {
        var machine = new CodexCdpBrokerStateMachine(Epoch);
        var hello = new CodexCdpBrokerCommand(
            CodexCdpBrokerCommandKind.Hello,
            null,
            null,
            null);
        var result = machine.ApplyCommand(hello);
        var json = CodexCdpBrokerProtocol.SerializeCommandResult(hello, result);
        using var document = JsonDocument.Parse(json);
        Ensure(
            document.RootElement.EnumerateObject().Select(property => property.Name)
                .SequenceEqual(new[]
                {
                    "kind", "command", "disposition", "code", "brokerEpoch", "sequence"
                }),
            "command result property order or exact field set drifted");
        Ensure(
            document.RootElement.GetProperty("kind").GetString() == "commandResult" &&
            document.RootElement.GetProperty("command").GetString() == "hello" &&
            document.RootElement.GetProperty("disposition").GetString() == "accepted" &&
            document.RootElement.GetProperty("code").GetString() == "hello",
            "command result did not preserve the fixed state-machine result");
        Ensure(
            !json.Contains("operationId", StringComparison.OrdinalIgnoreCase) &&
            !json.Contains("prompt", StringComparison.OrdinalIgnoreCase) &&
            !json.Contains("response", StringComparison.OrdinalIgnoreCase) &&
            !json.Contains("reasoning", StringComparison.OrdinalIgnoreCase),
            "command result exposed request identity or content");

        var queue = new CodexCdpBrokerSubscriptionQueue(Epoch, capacity: 2);
        var current = machine.Current;
        Ensure(
            !queue.BeginSubscription(0, current) && queue.RequiresResync,
            "a stale subscription did not immediately require resync");
        var resync = queue.Drain(1).Single();
        Ensure(
            resync.Kind == CodexCdpBrokerNotificationKind.ResyncRequired &&
            resync.Sequence == current.Sequence,
            "the initial resync signal did not identify the current sequence");
        Ensure(
            queue.AcknowledgeFullSnapshot(current) && !queue.RequiresResync,
            "the exact current full snapshot did not acknowledge resync");
        return Task.CompletedTask;
    }

    private static async Task TestHelloAndEpochRulesAsync()
    {
        await using (var nonHello = await CreateStartedSessionAsync(
                         new FakeRuntimeControlHost()).ConfigureAwait(false))
        {
            nonHello.Peer.Platform.EnqueueMessage(CodexCdpBrokerProtocol.EncodeFrame(
                $"{{\"command\":\"getStatus\",\"brokerEpoch\":\"{Epoch}\"}}"));
            var failure = await ExpectAsync<BrokerControlSessionException>(
                () => nonHello.RunTask.WaitAsync(CaseTimeout)).ConfigureAwait(false);
            nonHello.ObserveExpectedFailure(failure);
            Ensure(
                failure.Code == "control-hello-required" &&
                nonHello.Owner.Current.ConnectedClients == 0,
                "a pre-hello command entered the Broker client set");
        }

        await using (var duplicate = await CreateStartedSessionAsync(
                         new FakeRuntimeControlHost()).ConfigureAwait(false))
        {
            await SendHelloAsync(duplicate).ConfigureAwait(false);
            duplicate.Peer.Platform.EnqueueMessage(CodexCdpBrokerProtocol.EncodeFrame(
                "{\"command\":\"hello\",\"protocol\":1}"));
            var failure = await ExpectAsync<BrokerControlSessionException>(
                () => duplicate.RunTask.WaitAsync(CaseTimeout)).ConfigureAwait(false);
            duplicate.ObserveExpectedFailure(failure);
            Ensure(
                failure.Code == "control-hello-repeated" &&
                duplicate.Owner.Current.ConnectedClients == 0,
                "a repeated hello did not terminally disconnect the client");
        }

        var mismatchHost = new FakeRuntimeControlHost();
        await using (var mismatch = await CreateStartedSessionAsync(
                         mismatchHost).ConfigureAwait(false))
        {
            await SendHelloAsync(mismatch).ConfigureAwait(false);
            var startingWrites = mismatch.Peer.Platform.WriteCount;
            var mismatchFrame = CodexCdpBrokerProtocol.EncodeFrame(
                $"{{\"command\":\"getStatus\",\"brokerEpoch\":\"{OtherEpoch}\"}}");
            var forbiddenStartFrame = CodexCdpBrokerProtocol.EncodeFrame(
                $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}");
            var terminalBatch = new byte[mismatchFrame.Length + forbiddenStartFrame.Length];
            mismatchFrame.CopyTo(terminalBatch, 0);
            forbiddenStartFrame.CopyTo(terminalBatch, mismatchFrame.Length);
            mismatch.Peer.Platform.EnqueueMessage(terminalBatch);
            await mismatch.Peer.Platform.WaitForWriteCountAsync(
                startingWrites + 1,
                CaseTimeout).ConfigureAwait(false);
            await mismatch.RunTask.WaitAsync(CaseTimeout).ConfigureAwait(false);
            using var rejected = JsonDocument.Parse(
                DecodeFrame(mismatch.Peer.Platform.GetWrite(startingWrites)));
            Ensure(
                rejected.RootElement.GetProperty("disposition").GetString() == "rejected" &&
                rejected.RootElement.GetProperty("code").GetString() == "broker-epoch-mismatch" &&
                mismatch.Owner.Current.ConnectedClients == 0 &&
                mismatch.Owner.Current.State == CodexCdpBrokerState.IdleNoCodex &&
                mismatchHost.StartCount == 0,
                "an epoch mismatch executed a later same-batch command or failed to close");
        }
    }

    private static async Task TestStartReplayAndDisconnectAsync()
    {
        var host = new FakeRuntimeControlHost();
        await using var context = await CreateStartedSessionAsync(host).ConfigureAwait(false);
        await SendHelloAsync(context).ConfigureAwait(false);
        Ensure(
            !context.Session.ClientId.Contains(UserSid, StringComparison.OrdinalIgnoreCase) &&
            !context.Session.ClientId.Contains(
                GuardianProcessId.ToString(),
                StringComparison.Ordinal),
            "the Broker-generated client id exposed Guardian identity");

        var startJson =
            $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}";
        var frame = CodexCdpBrokerProtocol.EncodeFrame(startJson);
        var joined = new byte[frame.Length * 32];
        for (var index = 0; index < 32; index++)
        {
            frame.CopyTo(joined, index * frame.Length);
        }

        var startingWrites = context.Peer.Platform.WriteCount;
        context.Peer.Platform.EnqueueMessage(joined);
        await context.Peer.Platform.WaitForWriteCountAsync(
            startingWrites + 32,
            CaseTimeout).ConfigureAwait(false);
        await WaitUntilAsync(
            () => context.Owner.Current.State == CodexCdpBrokerState.ManagedReady,
            CaseTimeout).ConfigureAwait(false);
        Ensure(host.StartCount == 1, "operation replay invoked the runtime host more than once");
        var dispositions = Enumerable.Range(startingWrites, 32)
            .Select(index =>
            {
                using var response = JsonDocument.Parse(
                    DecodeFrame(context.Peer.Platform.GetWrite(index)));
                return response.RootElement.GetProperty("disposition").GetString();
            })
            .ToArray();
        Ensure(
            dispositions.Count(value => value == "accepted") == 1 &&
            dispositions.Count(value => value == "replayed") == 31,
            "operation replay did not produce one reservation and bounded replay results");
        Ensure(
            context.Owner.Current.ActiveLaunchOperationId == LaunchOperation &&
            host.Lease is { IsAlive: true, DisposeCount: 0 },
            "managed-ready state did not retain the exact launch operation and lease");

        await context.Session.DisposeAsync().ConfigureAwait(false);
        await WaitUntilAsync(
            () => context.Owner.Current.ConnectedClients == 0,
            CaseTimeout).ConfigureAwait(false);
        Ensure(
            context.Owner.Current.State == CodexCdpBrokerState.ManagedReady &&
            host.Lease is { IsAlive: true, DisposeCount: 0 } &&
            host.DisposeCount == 0,
            "Guardian disconnect disposed or changed the Broker runtime owner");
        await context.Owner.DisposeAsync().ConfigureAwait(false);
        Ensure(
            host.DisposeCount == 1 && host.Lease?.DisposeCount == 1,
            "Broker owner disposal did not release the host and lease exactly once");
    }

    private static async Task TestRaceLostAsync()
    {
        var host = new FakeRuntimeControlHost(
            CodexCdpRuntimeReconciliationKind.NoCodex,
            CodexCdpRuntimeReconciliationKind.ExternalCodexPresent)
        {
            StartKind = CodexCdpRuntimeStartKind.RaceLost
        };
        await using var context = await CreateStartedSessionAsync(host).ConfigureAwait(false);
        await SendHelloAsync(context).ConfigureAwait(false);
        await SendCommandAsync(
            context,
            $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
            minimumWrites: 1).ConfigureAwait(false);
        await WaitUntilAsync(
            () => context.Owner.Current.State == CodexCdpBrokerState.ExternalCodexPresent,
            CaseTimeout).ConfigureAwait(false);
        Ensure(
            host.StartCount == 1 && host.ReconcileCount == 2 && host.Lease is null,
            "RaceLost created or adopted a runtime lease");
    }

    private static async Task TestFaultAndNaturalExitAsync()
    {
        var launchPublicationFailure = new IOException("fake-launch-publication-failed");
        var launchPublicationCount = 0;
        var launchPublicationHost = new FakeRuntimeControlHost();
        await using (var launchPublication = await CreateStartedSessionAsync(
                         launchPublicationHost,
                         publicationCheckpoint: snapshot =>
                         {
                             if (snapshot.State == CodexCdpBrokerState.LaunchingCandidate &&
                                 Interlocked.Exchange(ref launchPublicationCount, 1) == 0)
                             {
                                 throw launchPublicationFailure;
                             }
                         }).ConfigureAwait(false))
        {
            await SendHelloAsync(launchPublication).ConfigureAwait(false);
            var secondPeer = CreateGuardianPeerFixture();
            var secondConnection = await secondPeer.Pending.CompleteConnectionAsync()
                .ConfigureAwait(false);
            await secondPeer.Pending.DisposeAsync().ConfigureAwait(false);
            var secondVerified =
                GuardianManagedEntryProofOfflineTests.CreateVerifiedConnectionFixture(
                    secondConnection);
            var secondSession = await launchPublication.Owner.AttachGuardianAsync(secondVerified)
                .ConfigureAwait(false);
            var secondRun = secondSession.RunAsync();
            var secondContext = new SessionContext(
                launchPublication.Owner,
                secondSession,
                secondRun,
                secondPeer);
            await SendHelloAsync(secondContext).ConfigureAwait(false);

            launchPublication.Peer.Platform.EnqueueMessage(CodexCdpBrokerProtocol.EncodeFrame(
                $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}"));
            var launchFailure = await ExpectAsync<IOException>(
                    () => launchPublication.Owner.Completion.WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            launchPublication.ObserveExpectedFailure(launchFailure);
            secondContext.ObserveExpectedFailure(launchFailure);
            await WaitUntilAsync(
                () => launchPublication.Owner.Current.State ==
                          CodexCdpBrokerState.FaultedNoOwner &&
                      launchPublication.Owner.Current.ConnectedClients == 0 &&
                      launchPublication.RunTask.IsCompleted &&
                      secondRun.IsCompleted,
                CaseTimeout).ConfigureAwait(false);
            Ensure(
                ReferenceEquals(launchFailure, launchPublicationFailure) &&
                launchPublicationCount == 1 &&
                launchPublicationHost.StartCount == 0 &&
                launchPublicationHost.Lease is null &&
                launchPublicationHost.ReconcileCount == 1,
                "launch publication failure left a pending owner or started the runtime host");
            var launchDisposeFailure = await ExpectAsync<IOException>(
                    () => launchPublication.Owner.DisposeAsync().AsTask().WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(launchDisposeFailure, launchPublicationFailure) &&
                launchPublicationHost.DisposeCount == 1,
                "launch publication failure did not remain the exact terminal owner failure");
            await secondContext.DisposeAsync().ConfigureAwait(false);
        }

        using (var terminalEntered = new ManualResetEventSlim(false))
        using (var allowTerminal = new ManualResetEventSlim(false))
        {
            var disposeRaceHost = new FakeRuntimeControlHost();
            await using var disposeRace = await CreateStartedSessionAsync(
                    disposeRaceHost,
                    terminalFailureCheckpoint: _ =>
                    {
                        terminalEntered.Set();
                        if (!allowTerminal.Wait(CaseTimeout))
                        {
                            throw new TimeoutException(
                                "terminal failure checkpoint was not released");
                        }
                    })
                .ConfigureAwait(false);
            await SendHelloAsync(disposeRace).ConfigureAwait(false);
            await SendCommandAsync(
                disposeRace,
                $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
                minimumWrites: 1).ConfigureAwait(false);
            await WaitUntilAsync(
                () => disposeRace.Owner.Current.State == CodexCdpBrokerState.ManagedReady,
                CaseTimeout).ConfigureAwait(false);
            var disposeRaceLease = disposeRaceHost.Lease ??
                throw new InvalidOperationException("dispose-race test did not receive a lease");
            Ensure(
                disposeRaceLease.CompleteFaulted("short-code-001"),
                "dispose-race fixture did not publish one exit fault");
            Ensure(
                terminalEntered.Wait(CaseTimeout),
                "exit fault did not reach the terminal checkpoint");
            var racingDispose = disposeRace.Owner.DisposeAsync().AsTask();
            await WaitUntilAsync(
                () => disposeRace.RunTask.IsCompleted,
                CaseTimeout).ConfigureAwait(false);
            Ensure(
                !racingDispose.IsCompleted,
                "owner disposal did not wait for the in-flight exit observer");
            allowTerminal.Set();
            var disposeRaceFailure = await ExpectAsync<BrokerControlSessionException>(
                    () => racingDispose.WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            disposeRace.ObserveExpectedFailure(disposeRaceFailure);
            var completionRaceFailure = await ExpectAsync<BrokerControlSessionException>(
                    () => disposeRace.Owner.Completion.WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(disposeRaceFailure, completionRaceFailure) &&
                disposeRaceFailure.Code == "runtime-exit-observation-failed" &&
                Equals(
                    disposeRaceFailure.Data["runtime-exit-failure-code"],
                    "short-code-001") &&
                disposeRaceHost.DisposeCount == 1 &&
                disposeRaceLease.DisposeCount == 1,
                "Dispose race rewrote a terminal exit-observation failure as success");
        }

        var faultHost = new FakeRuntimeControlHost
        {
            ThrowOnLeaseDispose = true
        };
        await using (var fault = await CreateStartedSessionAsync(faultHost).ConfigureAwait(false))
        {
            await SendHelloAsync(fault).ConfigureAwait(false);
            await SendCommandAsync(
                fault,
                $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
                minimumWrites: 1).ConfigureAwait(false);
            await WaitUntilAsync(
                () => fault.Owner.Current.State == CodexCdpBrokerState.ManagedReady,
                CaseTimeout).ConfigureAwait(false);
            await SendCommandAsync(
                fault,
                $"{{\"command\":\"retireAfterCodexExit\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"operation-retire-0001\"}}",
                minimumWrites: 1).ConfigureAwait(false);
            var faultLease = faultHost.Lease ??
                throw new InvalidOperationException("fault test did not receive a runtime lease");
            Ensure(
                faultLease.CompleteFaulted("abc"),
                "the fault fixture did not publish one exact exit-observation failure");
            await WaitUntilAsync(
                () => fault.Owner.Current.State == CodexCdpBrokerState.ManagedUnverified,
                CaseTimeout).ConfigureAwait(false);
            var ownerFailure = await ExpectAsync<BrokerControlSessionException>(
                    () => fault.Owner.Completion.WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            fault.ObserveExpectedFailure(ownerFailure);
            await WaitUntilAsync(
                () => fault.Owner.Current.ConnectedClients == 0 && fault.RunTask.IsCompleted,
                CaseTimeout).ConfigureAwait(false);
            await fault.RunTask.ConfigureAwait(false);
            Ensure(
                faultHost.Lease is { IsAlive: true, DisposeCount: 0 } &&
                fault.Owner.Current.ActiveLaunchOperationId == LaunchOperation &&
                fault.Owner.Current.RetirementIntent ==
                    CodexCdpBrokerRetirementIntent.RetireAfterCodexExit &&
                !fault.Owner.Current.BrokerExitIntent &&
                !fault.Owner.Current.ManagedCodexExitIntent &&
                faultHost.ReconcileCount == 1 &&
                ownerFailure.Code == "runtime-exit-observation-failed" &&
                Equals(ownerFailure.Data["runtime-exit-failure-code"], "abc") &&
                !faultLease.CompleteNaturalExit(0) &&
                faultLease.IsAlive,
                "faulted exit observation did not fail-stop while retaining exact lease authority");

            var rejectedPeer = CreateGuardianPeerFixture();
            var rejectedConnection = await rejectedPeer.Pending.CompleteConnectionAsync()
                .ConfigureAwait(false);
            await rejectedPeer.Pending.DisposeAsync().ConfigureAwait(false);
            var rejectedVerified =
                GuardianManagedEntryProofOfflineTests.CreateVerifiedConnectionFixture(
                    rejectedConnection);
            var rejectedAttach = await ExpectAsync<BrokerControlSessionException>(
                    () => fault.Owner.AttachGuardianAsync(rejectedVerified).AsTask())
                .ConfigureAwait(false);
            Ensure(
                rejectedAttach.Code == "control-publication-failed" &&
                rejectedPeer.Platform.DisposeCount == 1 &&
                rejectedPeer.PeerLease.DisposeCount == 1,
                "terminal exit observation failure accepted a new control session or leaked it");

            var disposeFailure = await ExpectAsync<BrokerControlSessionException>(
                    () => fault.Owner.DisposeAsync().AsTask().WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(disposeFailure, ownerFailure) &&
                ownerFailure.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] is
                    IOException { Message: "fake-runtime-lease-dispose-failed" } &&
                faultHost.DisposeCount == 1 &&
                faultLease.DisposeCount == 1 &&
                faultLease.DisposeAttemptCount >= 2,
                "owner disposal did not release the retained faulted-observer lease exactly once");
        }

        var readyPublicationFailure = new IOException("fake-ready-publication-failed");
        var readyPublicationCount = 0;
        var readyPublicationHost = new FakeRuntimeControlHost();
        await using (var readyPublication = await CreateStartedSessionAsync(
                         readyPublicationHost,
                         publicationCheckpoint: snapshot =>
                         {
                             if (snapshot.State == CodexCdpBrokerState.ManagedReady &&
                                 Interlocked.Exchange(ref readyPublicationCount, 1) == 0)
                             {
                                 throw readyPublicationFailure;
                             }
                         }).ConfigureAwait(false))
        {
            await SendHelloAsync(readyPublication).ConfigureAwait(false);
            await SendCommandAsync(
                readyPublication,
                $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
                minimumWrites: 1).ConfigureAwait(false);
            await WaitUntilAsync(
                () => readyPublication.Owner.Current.State ==
                    CodexCdpBrokerState.ManagedUnverified,
                CaseTimeout).ConfigureAwait(false);
            var terminalPublicationFailure = await ExpectAsync<IOException>(
                    () => readyPublication.Owner.Completion.WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            readyPublication.ObserveExpectedFailure(terminalPublicationFailure);
            var readyLease = readyPublicationHost.Lease ??
                throw new InvalidOperationException("ready publication test did not receive a lease");
            Ensure(
                ReferenceEquals(terminalPublicationFailure, readyPublicationFailure) &&
                readyPublicationCount == 1 &&
                readyLease.CompleteNaturalExit(0),
                "ready publication failure did not retain one observed runtime lease");
            await WaitUntilAsync(
                () => readyPublication.Owner.Current.State ==
                          CodexCdpBrokerState.FaultedNoOwner &&
                      readyLease.DisposeCount == 1,
                CaseTimeout).ConfigureAwait(false);
            Ensure(
                readyPublicationHost.ReconcileCount == 1,
                "post-commit publication failure lost its observer or reopened reconciliation");
            var readyDisposeFailure = await ExpectAsync<IOException>(
                    () => readyPublication.Owner.DisposeAsync().AsTask().WaitAsync(CaseTimeout))
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(readyDisposeFailure, readyPublicationFailure) &&
                readyPublicationHost.DisposeCount == 1,
                "ready publication failure did not remain the exact terminal owner failure");
        }

        var naturalHost = new FakeRuntimeControlHost(
            CodexCdpRuntimeReconciliationKind.NoCodex,
            CodexCdpRuntimeReconciliationKind.NoCodex);
        await using var natural = await CreateStartedSessionAsync(naturalHost).ConfigureAwait(false);
        await SendHelloAsync(natural).ConfigureAwait(false);
        await SendCommandAsync(
            natural,
            $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
            minimumWrites: 1).ConfigureAwait(false);
        await WaitUntilAsync(
            () => natural.Owner.Current.State == CodexCdpBrokerState.ManagedReady,
            CaseTimeout).ConfigureAwait(false);
        var naturalLease = naturalHost.Lease ??
            throw new InvalidOperationException("natural-exit test did not receive a runtime lease");
        Ensure(
            naturalLease.CompleteNaturalExit(0),
            "the natural-exit fixture did not publish one exact exit");
        await WaitUntilAsync(
            () => natural.Owner.Current.State == CodexCdpBrokerState.IdleNoCodex,
            CaseTimeout).ConfigureAwait(false);
        Ensure(
            naturalHost.Lease.DisposeCount == 1 && naturalHost.ReconcileCount == 2,
            "natural exit did not dispose the terminated lease and reconcile exactly once");

        var cleanupFailureHost = new FakeRuntimeControlHost
        {
            ThrowOnLeaseDispose = true,
            BlockFirstLeaseDispose = true
        };
        var exitPublicationFailure = new IOException("fake-exit-publication-failed");
        var exitPublicationCount = 0;
        await using var cleanupFailure = await CreateStartedSessionAsync(
                cleanupFailureHost,
                publicationCheckpoint: snapshot =>
                {
                    if (snapshot.State == CodexCdpBrokerState.OwnedCodexExited &&
                        Interlocked.Exchange(ref exitPublicationCount, 1) == 0)
                    {
                        throw exitPublicationFailure;
                    }
                })
            .ConfigureAwait(false);
        await SendHelloAsync(cleanupFailure).ConfigureAwait(false);
        await SendCommandAsync(
            cleanupFailure,
            $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
            minimumWrites: 1).ConfigureAwait(false);
        await WaitUntilAsync(
            () => cleanupFailure.Owner.Current.State == CodexCdpBrokerState.ManagedReady,
            CaseTimeout).ConfigureAwait(false);
        var cleanupLease = cleanupFailureHost.Lease ??
            throw new InvalidOperationException("the cleanup-failure fixture did not receive a lease");
        Ensure(
            cleanupLease.CompleteNaturalExit(0),
            "the cleanup-failure fixture did not publish one exact natural exit");
        await cleanupLease.FirstDisposeEntered.WaitAsync(CaseTimeout).ConfigureAwait(false);
        var completionPublishedBeforeCleanup = cleanupFailure.Owner.Completion.IsCompleted;
        cleanupLease.AllowFirstDispose();
        Ensure(
            !completionPublishedBeforeCleanup,
            "owner published terminal completion before exact exit cleanup arbitration");
        await WaitUntilAsync(
            () => cleanupFailure.Owner.Current.State == CodexCdpBrokerState.FaultedNoOwner &&
                  cleanupLease.DisposeAttemptCount >= 1,
            CaseTimeout).ConfigureAwait(false);
        var cleanupException = await ExpectAsync<IOException>(
                () => cleanupFailure.Owner.Completion.WaitAsync(CaseTimeout))
            .ConfigureAwait(false);
        cleanupFailure.ObserveExpectedFailure(cleanupException);
        var disposeException = await ExpectAsync<IOException>(
            () => cleanupFailure.Owner.DisposeAsync().AsTask().WaitAsync(CaseTimeout))
            .ConfigureAwait(false);
        Ensure(
            ReferenceEquals(cleanupException, exitPublicationFailure) &&
            ReferenceEquals(disposeException, exitPublicationFailure) &&
            cleanupException.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] is
                IOException { Message: "fake-runtime-lease-dispose-failed" } &&
            exitPublicationCount == 1 &&
            cleanupFailureHost.ReconcileCount == 1 &&
            cleanupLease.DisposeCount == 1 &&
            cleanupLease.DisposeAttemptCount >= 2,
            "natural-exit publication failure skipped exact cleanup or lost secondary evidence");
    }

    private static async Task TestSubscriptionResyncAsync()
    {
        var host = new FakeRuntimeControlHost();
        await using var context = await CreateStartedSessionAsync(host).ConfigureAwait(false);
        await SendHelloAsync(context).ConfigureAwait(false);
        var subscribeWrites = await SendCommandAsync(
            context,
            $"{{\"command\":\"subscribe\",\"brokerEpoch\":\"{Epoch}\",\"afterSequence\":0}}",
            minimumWrites: 2).ConfigureAwait(false);
        Ensure(
            ReadKind(subscribeWrites[0]) == "commandResult" &&
            ReadKind(subscribeWrites[1]) == "resyncRequired",
            "a stale subscribe did not produce one result followed by resyncRequired");

        var fullWrites = await SendCommandAsync(
            context,
            $"{{\"command\":\"getFullSnapshot\",\"brokerEpoch\":\"{Epoch}\"}}",
            minimumWrites: 2).ConfigureAwait(false);
        Ensure(
            ReadKind(fullWrites[0]) == "commandResult" &&
            ReadKind(fullWrites[1]) == "fullSnapshot",
            "getFullSnapshot did not serialize result before the full snapshot");

        var startWrites = await SendCommandAsync(
            context,
            $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
            minimumWrites: 2).ConfigureAwait(false);
        Ensure(
            ReadKind(startWrites[0]) == "commandResult" &&
            startWrites.Skip(1).Any(frame => ReadKind(frame) == "stateChanged") &&
            startWrites.Skip(1).All(frame => ReadKind(frame) != "resyncRequired"),
            "a written current full snapshot did not restore incremental delivery");
    }

    private static async Task TestCancellationOwnershipAsync()
    {
        var callerCancellationHost = new FakeRuntimeControlHost();
        using (var callerCancellation = new CancellationTokenSource())
        await using (var cancelled = await CreateStartedSessionAsync(
                         callerCancellationHost,
                         callerCancellation.Token).ConfigureAwait(false))
        {
            await SendHelloAsync(cancelled).ConfigureAwait(false);
            callerCancellation.Cancel();
            await cancelled.RunTask.WaitAsync(CaseTimeout).ConfigureAwait(false);
            await WaitUntilAsync(
                () => cancelled.Owner.Current.ConnectedClients == 0,
                CaseTimeout).ConfigureAwait(false);
            Ensure(
                callerCancellationHost.DisposeCount == 0 &&
                cancelled.Owner.Current.State == CodexCdpBrokerState.IdleNoCodex,
                "caller cancellation disposed or changed the Broker runtime owner");
        }

        var sessionHost = new FakeRuntimeControlHost { BlockStart = true };
        await using (var context = await CreateStartedSessionAsync(sessionHost).ConfigureAwait(false))
        {
            await SendHelloAsync(context).ConfigureAwait(false);
            await SendCommandAsync(
                context,
                $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
                minimumWrites: 1).ConfigureAwait(false);
            await sessionHost.StartEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
            await context.Session.DisposeAsync().ConfigureAwait(false);
            Ensure(
                !sessionHost.StartCancellationObserved && sessionHost.StartCount == 1,
                "Guardian session disposal cancelled an accepted Broker-owned start");
            sessionHost.AllowStart();
            await WaitUntilAsync(
                () => context.Owner.Current.State == CodexCdpBrokerState.ManagedReady,
                CaseTimeout).ConfigureAwait(false);
            await Task.WhenAll(Enumerable.Range(0, 32)
                    .Select(_ => context.Owner.DisposeAsync().AsTask()))
                .WaitAsync(CaseTimeout)
                .ConfigureAwait(false);
            Ensure(
                sessionHost.DisposeCount == 1 && sessionHost.Lease?.DisposeCount == 1,
                "concurrent owner disposal released runtime authority more than once");
        }

        using (var disposalEntered = new ManualResetEventSlim(false))
        using (var allowDisposal = new ManualResetEventSlim(false))
        {
            var disposalWindowHost = new FakeRuntimeControlHost();
            await using var disposalWindow = await CreateStartedSessionAsync(
                    disposalWindowHost,
                    disposalCheckpoint: () =>
                    {
                        disposalEntered.Set();
                        if (!allowDisposal.Wait(CaseTimeout))
                        {
                            throw new TimeoutException("owner disposal checkpoint was not released");
                        }
                    })
                .ConfigureAwait(false);
            await SendHelloAsync(disposalWindow).ConfigureAwait(false);
            var ownerDisposal = disposalWindow.Owner.DisposeAsync().AsTask();
            try
            {
                Ensure(
                    disposalEntered.Wait(CaseTimeout) && !ownerDisposal.IsCompleted,
                    "owner disposal did not expose the registered-session stopping window");
                Ensure(
                    !disposalWindow.RunTask.IsCompleted &&
                    disposalWindow.Owner.Current.ConnectedClients == 1 &&
                    disposalWindow.Peer.Platform.DisposeCount == 0 &&
                    disposalWindow.Peer.PeerLease.DisposeCount == 0,
                    "owner disposal checkpoint ran after the registered session had already stopped");
                disposalWindow.Peer.Platform.EnqueueMessage(CodexCdpBrokerProtocol.EncodeFrame(
                    $"{{\"command\":\"getStatus\",\"brokerEpoch\":\"{Epoch}\"}}"));
                await disposalWindow.RunTask.WaitAsync(CaseTimeout).ConfigureAwait(false);
                await WaitUntilAsync(
                    () => disposalWindow.Owner.Current.ConnectedClients == 0,
                    CaseTimeout).ConfigureAwait(false);
                Ensure(
                    disposalWindow.Peer.Platform.DisposeCount == 1 &&
                    disposalWindow.Peer.PeerLease.DisposeCount == 1,
                    "owner stopping converted a registered session into a fault or leaked its connection");
            }
            finally
            {
                allowDisposal.Set();
            }

            await ownerDisposal.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                disposalWindowHost.DisposeCount == 1 && disposalWindowHost.Lease is null &&
                disposalWindow.Peer.Platform.DisposeCount == 1 &&
                disposalWindow.Peer.PeerLease.DisposeCount == 1,
                "owner disposal did not finish cleanly after the registered session stopped");
        }

        var ownerHost = new FakeRuntimeControlHost { BlockStart = true };
        await using var ownerContext = await CreateStartedSessionAsync(ownerHost).ConfigureAwait(false);
        await SendHelloAsync(ownerContext).ConfigureAwait(false);
        await SendCommandAsync(
            ownerContext,
            $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"{LaunchOperation}\"}}",
            minimumWrites: 1).ConfigureAwait(false);
        await ownerHost.StartEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        await ownerContext.Owner.DisposeAsync().AsTask().WaitAsync(CaseTimeout).ConfigureAwait(false);
        Ensure(
            ownerHost.StartCancellationObserved &&
            ownerHost.DisposeCount == 1 && ownerHost.Lease is null,
            "Broker owner disposal did not cancel an uncommitted runtime start");
    }

    private static async Task TestReentrantCancellationCleanupAsync()
    {
        var host = new FakeRuntimeControlHost();
        var owner = new BrokerRuntimeOwnerV1(host, Epoch);
        Task? reentrantDispose = null;
        host.CancellationCallback = () =>
        {
            reentrantDispose = owner.DisposeAsync().AsTask();
            throw new InvalidOperationException("fake-cancellation-callback-failed");
        };
        await owner.StartAsync().WaitAsync(CaseTimeout).ConfigureAwait(false);

        var disposeTask = owner.DisposeAsync().AsTask();
        var failure = await ExpectAsync<AggregateException>(
            () => disposeTask.WaitAsync(CaseTimeout)).ConfigureAwait(false);
        Ensure(
            failure.InnerExceptions.Count == 1 &&
            failure.InnerExceptions[0] is InvalidOperationException &&
            ReferenceEquals(disposeTask, reentrantDispose) &&
            host.DisposeCount == 1,
            "throwing cancellation reentrancy truncated cleanup or published another dispose task");

        await TestOwnedPeerResourceDisposeCompletionAsync().ConfigureAwait(false);
    }

    private static async Task TestOwnedPeerResourceDisposeCompletionAsync()
    {
        static Task<Exception?> StartDispose(
            OwnedPipePeerResources resources,
            ManualResetEventSlim? started = null,
            bool quarantined = false) =>
            Task.Run(() =>
            {
                started?.Set();
                try
                {
                    if (quarantined)
                    {
                        resources.DisposeQuarantinedResources();
                    }
                    else
                    {
                        resources.Dispose();
                    }

                    return null;
                }
                catch (Exception exception)
                {
                    return exception;
                }
            });

        static (PeerReadQuarantineRegistry Registry, OwnedPipePeerResources Resources,
            FakeMessagePlatform Platform, FakePeerLease Lease) CreateResources()
        {
            var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Guardian);
            var identity = CreateGuardianIdentity(release);
            var lease = new FakePeerLease(
                identity,
                new RetainedReleaseHandleSet(
                    release.Root,
                    release.Artifacts.Select(artifact => artifact.RelativePath).ToArray()));
            var platform = new FakeMessagePlatform(release, lease);
            var registry = new PeerReadQuarantineRegistry(capacity: 1);
            var resources = registry.Reserve(platform);
            resources.AttachPeerLease(lease);
            return (registry, resources, platform, lease);
        }

        var success = CreateResources();
        success.Platform.BlockDispose();
        var winner = StartDispose(success.Resources);
        Ensure(
            success.Platform.DisposeEntered.Wait(CaseTimeout),
            "owned peer resource winner did not enter platform disposal");
        using var followerOneStarted = new ManualResetEventSlim(false);
        using var followerTwoStarted = new ManualResetEventSlim(false);
        var followerOne = StartDispose(success.Resources, followerOneStarted);
        var followerTwo = StartDispose(success.Resources, followerTwoStarted);
        Ensure(
            followerOneStarted.Wait(CaseTimeout) && followerTwoStarted.Wait(CaseTimeout),
            "owned peer resource followers did not enter disposal");
        Ensure(
            !followerOne.Wait(TimeSpan.FromMilliseconds(100)) &&
            !followerTwo.Wait(TimeSpan.FromMilliseconds(100)),
            "owned peer resource follower returned before winner cleanup completed");
        success.Platform.ReleaseDispose();
        var successFailures = await Task.WhenAll(winner, followerOne, followerTwo)
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        Ensure(
            successFailures.All(exception => exception is null) &&
            success.Platform.DisposeCount == 1 &&
            success.Lease.DisposeCount == 1 &&
            success.Registry.Health.ActiveConnectionCount == 0,
            "shared peer resource disposal did not release all three stages exactly once");

        var failure = CreateResources();
        var platformFailure = new IOException("fake-peer-platform-dispose-failed");
        failure.Platform.DisposeFailure = platformFailure;
        failure.Platform.BlockDispose();
        var failedWinner = StartDispose(failure.Resources);
        Ensure(
            failure.Platform.DisposeEntered.Wait(CaseTimeout),
            "failing peer resource winner did not enter platform disposal");
        using var failedFollowerStarted = new ManualResetEventSlim(false);
        var failedFollower = StartDispose(failure.Resources, failedFollowerStarted);
        Ensure(
            failedFollowerStarted.Wait(CaseTimeout) &&
            !failedFollower.Wait(TimeSpan.FromMilliseconds(100)),
            "failing peer resource follower returned before terminal failure publication");
        failure.Platform.ReleaseDispose();
        var observedFailures = await Task.WhenAll(failedWinner, failedFollower)
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        Ensure(
            observedFailures.All(exception => ReferenceEquals(exception, platformFailure)) &&
            failure.Platform.DisposeCount == 1 &&
            failure.Lease.DisposeCount == 0 &&
            failure.Registry.Health.ActiveConnectionCount == 1,
            "peer resource followers did not observe the same sticky platform failure");
        failure.Resources.ReleaseQuarantineAdmission();
        failure.Lease.Dispose();
        Ensure(
            failure.Registry.Health.ActiveConnectionCount == 0 &&
            failure.Lease.DisposeCount == 1,
            "failing peer resource test did not release its isolated authority");

        var crossThreadReentrant = CreateResources();
        crossThreadReentrant.Platform.DisposeCallback = () =>
            Task.Run(() => crossThreadReentrant.Resources.Dispose())
                .GetAwaiter()
                .GetResult();
        var crossThreadFailure = await StartDispose(crossThreadReentrant.Resources)
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        var crossThreadReplay = await StartDispose(crossThreadReentrant.Resources)
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        Ensure(
            crossThreadFailure is InvalidOperationException
            {
                Message: "peer-resource-dispose-reentrant"
            } &&
            ReferenceEquals(crossThreadFailure, crossThreadReplay) &&
            crossThreadReentrant.Platform.DisposeCount == 1 &&
            crossThreadReentrant.Lease.DisposeCount == 0 &&
            crossThreadReentrant.Registry.Health.ActiveConnectionCount == 1,
            "logical cross-thread peer disposal reentrancy deadlocked or lost sticky authority");
        crossThreadReentrant.Resources.ReleaseQuarantineAdmission();
        crossThreadReentrant.Lease.Dispose();
        Ensure(
            crossThreadReentrant.Registry.Health.ActiveConnectionCount == 0 &&
            crossThreadReentrant.Lease.DisposeCount == 1,
            "cross-thread reentrancy test did not release its isolated authority");

        var noFlowReentrant = CreateResources();
        Task<Exception?>? noFlowWorker = null;
        noFlowReentrant.Platform.DisposeCallback = () =>
        {
            var nestedCompletion = new TaskCompletionSource<Exception?>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var queued = ThreadPool.UnsafeQueueUserWorkItem(
                static state =>
                {
                    var (resources, completion) = state;
                    try
                    {
                        resources.Dispose();
                        completion.TrySetResult(null);
                    }
                    catch (Exception exception)
                    {
                        completion.TrySetResult(exception);
                    }
                },
                (noFlowReentrant.Resources, nestedCompletion),
                preferLocal: false);
            if (!queued)
            {
                throw new InvalidOperationException("no-flow-worker-queue-failed");
            }

            noFlowWorker = nestedCompletion.Task;
            var nestedFailure = nestedCompletion.Task
                .WaitAsync(CaseTimeout)
                .GetAwaiter()
                .GetResult();
            if (nestedFailure is not null)
            {
                ExceptionDispatchInfo.Capture(nestedFailure).Throw();
            }
        };
        var noFlowFailure = await StartDispose(noFlowReentrant.Resources)
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        var noFlowReplay = await StartDispose(noFlowReentrant.Resources)
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        var joinedNoFlowFailure = await (noFlowWorker ??
                throw new InvalidOperationException("no-flow worker was not queued"))
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        Ensure(
            noFlowFailure is InvalidOperationException
            {
                Message: "peer-resource-dispose-wait-timeout"
            } &&
            ReferenceEquals(noFlowFailure, noFlowReplay) &&
            ReferenceEquals(noFlowFailure, joinedNoFlowFailure) &&
            noFlowReentrant.Platform.DisposeCount == 1 &&
            noFlowReentrant.Lease.DisposeCount == 0 &&
            noFlowReentrant.Registry.Health.ActiveConnectionCount == 1,
            "no-flow peer disposal reentrancy mismatch: " +
            $"failure={noFlowFailure?.GetType().Name}:{noFlowFailure?.Message}, " +
            $"replay={noFlowReplay?.GetType().Name}:{noFlowReplay?.Message}, " +
            $"same={ReferenceEquals(noFlowFailure, noFlowReplay)}, " +
            $"joined={ReferenceEquals(noFlowFailure, joinedNoFlowFailure)}, " +
            $"platform={noFlowReentrant.Platform.DisposeCount}, " +
            $"lease={noFlowReentrant.Lease.DisposeCount}, " +
            $"active={noFlowReentrant.Registry.Health.ActiveConnectionCount}");
        noFlowReentrant.Resources.ReleaseQuarantineAdmission();
        noFlowReentrant.Lease.Dispose();
        Ensure(
            noFlowReentrant.Registry.Health.ActiveConnectionCount == 0 &&
            noFlowReentrant.Lease.DisposeCount == 1,
            "no-flow reentrancy test did not release its isolated authority");

        var normalMode = CreateResources();
        normalMode.Platform.BlockDispose();
        var normalModeWinner = StartDispose(normalMode.Resources);
        Ensure(
            normalMode.Platform.DisposeEntered.Wait(CaseTimeout),
            "normal-mode peer disposal did not enter platform cleanup");
        Exception? normalModeMismatch = null;
        try
        {
            normalMode.Resources.DisposeQuarantinedResources();
        }
        catch (Exception exception)
        {
            normalModeMismatch = exception;
        }

        Ensure(
            normalModeMismatch is InvalidOperationException
            {
                Message: "peer-resource-dispose-mode-mismatch"
            },
            "normal-mode disposal accepted a quarantine follower");
        normalMode.Platform.ReleaseDispose();
        Ensure(
            await normalModeWinner.WaitAsync(CaseTimeout).ConfigureAwait(false) is null &&
            normalMode.Registry.Health.ActiveConnectionCount == 0,
            "normal-mode mismatch changed winner cleanup authority");

        var quarantineMode = CreateResources();
        quarantineMode.Platform.BlockDispose();
        var quarantineModeWinner = StartDispose(
            quarantineMode.Resources,
            quarantined: true);
        Ensure(
            quarantineMode.Platform.DisposeEntered.Wait(CaseTimeout),
            "quarantine-mode peer disposal did not enter platform cleanup");
        Exception? quarantineModeMismatch = null;
        try
        {
            quarantineMode.Resources.Dispose();
        }
        catch (Exception exception)
        {
            quarantineModeMismatch = exception;
        }

        Ensure(
            quarantineModeMismatch is InvalidOperationException
            {
                Message: "peer-resource-dispose-mode-mismatch"
            },
            "quarantine-mode disposal accepted a normal follower");
        quarantineMode.Platform.ReleaseDispose();
        Ensure(
            await quarantineModeWinner.WaitAsync(CaseTimeout).ConfigureAwait(false) is null &&
            quarantineMode.Lease.DisposeCount == 1 &&
            quarantineMode.Registry.Health.ActiveConnectionCount == 1,
            "quarantine-mode mismatch changed retained admission authority");
        quarantineMode.Resources.ReleaseQuarantineAdmission();

        var reentrant = CreateResources();
        Exception? reentrantFailure = null;
        reentrant.Platform.DisposeCallback = () =>
        {
            try
            {
                reentrant.Resources.Dispose();
            }
            catch (Exception exception)
            {
                reentrantFailure = exception;
            }
        };
        reentrant.Resources.Dispose();
        Ensure(
            reentrantFailure is InvalidOperationException
            {
                Message: "peer-resource-dispose-reentrant"
            } &&
            reentrant.Platform.DisposeCount == 1 &&
            reentrant.Lease.DisposeCount == 1 &&
            reentrant.Registry.Health.ActiveConnectionCount == 0,
            "synchronous peer resource reentrancy deadlocked or duplicated cleanup");
    }

    private static Task TestReleaseClosureAsync()
    {
        static int CountToken(string source, string token)
        {
            var count = 0;
            var offset = 0;
            while ((offset = source.IndexOf(token, offset, StringComparison.Ordinal)) >= 0)
            {
                count++;
                offset += token.Length;
            }

            return count;
        }

        var sourceRoot = FindSourceRoot();
        var releaseSource = File.ReadAllText(Path.Combine(sourceRoot, "package-release.ps1"));
        var requiredSources = new[]
        {
            "CodexGuardian.Broker\\BrokerRuntimeOwner.cs",
            "CodexGuardian.Broker\\BrokerControlSession.cs",
            "CodexGuardian.Trust\\BrokerPeerTrust.cs",
            "CodexGuardian.Tests\\BrokerControlSessionOfflineTests.cs",
            "CodexGuardian.Tests\\CodexCdpRuntimeOwnershipOfflineTests.cs"
        };
        var lines = releaseSource
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n')
            .Select(line => line.Trim())
            .ToArray();
        Ensure(
            requiredSources.All(source =>
                lines.Count(line => string.Equals(
                    line,
                    $"(Join-Path $SourceOutput '{source}'),",
                    StringComparison.Ordinal)) == 1 &&
                lines.Count(line => string.Equals(
                    line,
                    $"'{source}',",
                    StringComparison.Ordinal)) == 1 &&
                lines.Count(line => string.Equals(
                    line,
                    $"(Join-Path $SourceStage '{source}'),",
                    StringComparison.Ordinal)) == 1),
            "release source closure does not contain each Broker control-session source once per closure");
        var programSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Tests",
            "Program.cs"));
        const string focusedArgument = "\"--broker-control-session-offline-only\"";
        const string runtimeDispatch =
            "await CodexCdpRuntimeOwnershipOfflineTests.RunAsync(Assert);";
        const string sessionDispatch =
            "await BrokerControlSessionOfflineTests.RunAsync(Assert);";
        const string completionMarker =
            "Console.WriteLine(\"BROKER_CONTROL_SESSION_OFFLINE_TESTS_COMPLETE\");";
        const string runtimeHostFocusedArgument =
            "\"--broker-runtime-host-offline-only\"";
        const string runtimeHostCompletionMarker =
            "Console.WriteLine(\"BROKER_RUNTIME_HOST_OFFLINE_TESTS_COMPLETE\");";
        const string productionHostFocusedArgument =
            "\"--broker-production-host-offline-only\"";
        const string productionHostCompletionMarker =
            "Console.WriteLine(\"BROKER_PRODUCTION_HOST_OFFLINE_TESTS_COMPLETE\");";
        var focusedIndex = programSource.IndexOf(focusedArgument, StringComparison.Ordinal);
        var firstRuntimeIndex = programSource.IndexOf(runtimeDispatch, StringComparison.Ordinal);
        var firstSessionIndex = programSource.IndexOf(sessionDispatch, StringComparison.Ordinal);
        var markerIndex = programSource.IndexOf(completionMarker, StringComparison.Ordinal);
        var runtimeHostFocusedIndex = programSource.IndexOf(
            runtimeHostFocusedArgument,
            StringComparison.Ordinal);
        var secondRuntimeIndex = programSource.IndexOf(
            runtimeDispatch,
            firstRuntimeIndex + runtimeDispatch.Length,
            StringComparison.Ordinal);
        var secondSessionIndex = programSource.IndexOf(
            sessionDispatch,
            firstSessionIndex + sessionDispatch.Length,
            StringComparison.Ordinal);
        var runtimeHostMarkerIndex = programSource.IndexOf(
            runtimeHostCompletionMarker,
            StringComparison.Ordinal);
        var productionHostFocusedIndex = programSource.IndexOf(
            productionHostFocusedArgument,
            StringComparison.Ordinal);
        var thirdRuntimeIndex = programSource.IndexOf(
            runtimeDispatch,
            secondRuntimeIndex + runtimeDispatch.Length,
            StringComparison.Ordinal);
        var thirdSessionIndex = programSource.IndexOf(
            sessionDispatch,
            secondSessionIndex + sessionDispatch.Length,
            StringComparison.Ordinal);
        var productionHostMarkerIndex = programSource.IndexOf(
            productionHostCompletionMarker,
            StringComparison.Ordinal);
        var fullRuntimeIndex = programSource.LastIndexOf(runtimeDispatch, StringComparison.Ordinal);
        var fullSessionIndex = programSource.LastIndexOf(sessionDispatch, StringComparison.Ordinal);
        Ensure(
            CountToken(programSource, focusedArgument) == 1 &&
            CountToken(programSource, runtimeHostFocusedArgument) == 1 &&
            CountToken(programSource, productionHostFocusedArgument) == 1 &&
            CountToken(programSource, runtimeDispatch) == 4 &&
            CountToken(programSource, sessionDispatch) == 4 &&
            CountToken(programSource, completionMarker) == 1 &&
            CountToken(programSource, runtimeHostCompletionMarker) == 1 &&
            CountToken(programSource, productionHostCompletionMarker) == 1 &&
            focusedIndex < firstRuntimeIndex &&
            firstRuntimeIndex < firstSessionIndex &&
            firstSessionIndex < markerIndex &&
            markerIndex < runtimeHostFocusedIndex &&
            runtimeHostFocusedIndex < secondRuntimeIndex &&
            secondRuntimeIndex < secondSessionIndex &&
            secondSessionIndex < runtimeHostMarkerIndex &&
            runtimeHostMarkerIndex < productionHostFocusedIndex &&
            productionHostFocusedIndex < thirdRuntimeIndex &&
            thirdRuntimeIndex < thirdSessionIndex &&
            thirdSessionIndex < productionHostMarkerIndex &&
            productionHostMarkerIndex < fullRuntimeIndex &&
            fullRuntimeIndex < fullSessionIndex,
            "Tests Program does not preserve the focused and full Broker control-session dispatch contract");
        return Task.CompletedTask;
    }

    private static async Task<SessionContext> CreateStartedSessionAsync(
        FakeRuntimeControlHost host,
        CancellationToken cancellationToken = default,
        Action<CodexCdpBrokerSnapshot>? publicationCheckpoint = null,
        Action<Exception>? terminalFailureCheckpoint = null,
        Action? disposalCheckpoint = null)
    {
        var owner = new BrokerRuntimeOwnerV1(
            host,
            Epoch,
            publicationCheckpoint: publicationCheckpoint,
            terminalFailureCheckpoint: terminalFailureCheckpoint,
            disposalCheckpoint: disposalCheckpoint);
        await owner.StartAsync().WaitAsync(CaseTimeout).ConfigureAwait(false);
        Ensure(
            owner.Current.State == CodexCdpBrokerState.IdleNoCodex,
            "the fake Broker did not reconcile to an idle startable state");
        var peer = CreateGuardianPeerFixture();
        var connection = await peer.Pending.CompleteConnectionAsync().ConfigureAwait(false);
        await peer.Pending.DisposeAsync().ConfigureAwait(false);
        var verified = GuardianManagedEntryProofOfflineTests.CreateVerifiedConnectionFixture(
            connection);
        var session = await owner.AttachGuardianAsync(verified).ConfigureAwait(false);
        var runTask = session.RunAsync(cancellationToken);
        return new SessionContext(owner, session, runTask, peer);
    }

    private static async Task SendHelloAsync(SessionContext context)
    {
        var startingWrites = context.Peer.Platform.WriteCount;
        var startingConnectedClients = context.Owner.Current.ConnectedClients;
        context.Peer.Platform.EnqueueMessage(CodexCdpBrokerProtocol.EncodeFrame(
            "{\"command\":\"hello\",\"protocol\":1}"));
        await context.Peer.Platform.WaitForWriteCountAsync(
            startingWrites + 2,
            CaseTimeout).ConfigureAwait(false);
        Ensure(
            ReadKind(context.Peer.Platform.GetWrite(startingWrites)) == "commandResult" &&
            ReadKind(context.Peer.Platform.GetWrite(startingWrites + 1)) == "fullSnapshot" &&
            context.Owner.Current.ConnectedClients == startingConnectedClients + 1,
            "hello did not connect exactly once and return a full snapshot");
    }

    private static async Task<IReadOnlyList<byte[]>> SendCommandAsync(
        SessionContext context,
        string json,
        int minimumWrites)
    {
        var startingWrites = context.Peer.Platform.WriteCount;
        context.Peer.Platform.EnqueueMessage(CodexCdpBrokerProtocol.EncodeFrame(json));
        await context.Peer.Platform.WaitForWriteCountAsync(
            startingWrites + minimumWrites,
            CaseTimeout).ConfigureAwait(false);
        await Task.Delay(25).ConfigureAwait(false);
        return context.Peer.Platform.GetWrites(startingWrites);
    }

    private static string ReadKind(byte[] frame)
    {
        using var document = JsonDocument.Parse(DecodeFrame(frame));
        return document.RootElement.GetProperty("kind").GetString() ?? string.Empty;
    }

    private static string DecodeFrame(byte[] frame)
    {
        Ensure(frame.Length >= sizeof(uint), "outbound frame omitted its length prefix");
        var length = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(frame));
        Ensure(
            length == frame.Length - sizeof(uint),
            "outbound frame length did not match its payload");
        return Encoding.UTF8.GetString(frame, sizeof(uint), length);
    }

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow >= deadline)
            {
                throw new TimeoutException("The bounded Broker test condition did not become true.");
            }

            await Task.Delay(10).ConfigureAwait(false);
        }
    }

    private static string FindSourceRoot()
    {
        var candidate = new DirectoryInfo(Environment.CurrentDirectory);
        while (candidate is not null)
        {
            if (File.Exists(Path.Combine(candidate.FullName, "package-release.ps1")) &&
                File.Exists(Path.Combine(
                    candidate.FullName,
                    "CodexGuardian.Tests",
                    "CodexGuardian.Tests.csproj")))
            {
                return candidate.FullName;
            }

            var work = Path.Combine(candidate.FullName, "work");
            if (File.Exists(Path.Combine(work, "package-release.ps1")) &&
                File.Exists(Path.Combine(
                    work,
                    "CodexGuardian.Tests",
                    "CodexGuardian.Tests.csproj")))
            {
                return work;
            }

            candidate = candidate.Parent;
        }

        throw new DirectoryNotFoundException("The authoritative CodexGuardian workspace was not found.");
    }

    private static GuardianPeerFixture CreateGuardianPeerFixture()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Guardian);
        var identity = CreateGuardianIdentity(release);
        var peerLease = new FakePeerLease(
            identity,
            new RetainedReleaseHandleSet(
                release.Root,
                release.Artifacts.Select(artifact => artifact.RelativePath).ToArray()));
        var platform = new FakeMessagePlatform(release, peerLease);
        var verifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            beforeAuthorityTransfer: null,
            afterAuthorityTransfer: null,
            maximumConnections: 1);
        var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Client,
            new BrokerPeerExpectation(
                CreateProcessToken(),
                WindowsAppModelIdentity.Unpackaged,
                release,
                ConnectionNonce,
                GuardianProcessId,
                GuardianCreationTime));
        return new GuardianPeerFixture(verifier, platform, peerLease, pending);
    }

    private static VerifiedReleaseManifest CreateManifest() =>
        VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId,
            ManifestSha256,
            new WindowsReleaseRootIdentity(
                ReleaseRoot,
                FileAttributes.Directory | FileAttributes.Archive,
                VolumeSerial,
                new string('a', 32),
                true),
            CreateRoleDefinition(BrokerPeerRole.Guardian),
            CreateRoleDefinition(BrokerPeerRole.Broker));

    private static VerifiedReleaseRoleArtifacts CreateRoleDefinition(BrokerPeerRole role)
    {
        var stem = role == BrokerPeerRole.Broker ? "CodexGuardian.Broker" : "CodexGuardian";
        var seed = role == BrokerPeerRole.Guardian ? '1' : '5';
        var artifacts = new[]
        {
            CreateArtifact(ReleaseArtifactKind.AppHostExe, stem + ".exe", seed, 128 * 1024),
            CreateArtifact(ReleaseArtifactKind.ManagedEntryDll, stem + ".dll", (char)(seed + 1), 512 * 1024),
            CreateArtifact(ReleaseArtifactKind.DepsJson, stem + ".deps.json", (char)(seed + 2), 64 * 1024),
            CreateArtifact(ReleaseArtifactKind.RuntimeConfigJson, stem + ".runtimeconfig.json", (char)(seed + 3), 4 * 1024)
        };
        return new VerifiedReleaseRoleArtifacts(
            role,
            stem + ".exe",
            stem + ".dll",
            stem + ".deps.json",
            stem + ".runtimeconfig.json",
            artifacts);
    }

    private static WindowsArtifactIdentity CreateArtifact(
        ReleaseArtifactKind kind,
        string relativePath,
        char seed,
        long length) =>
        new(
            kind,
            relativePath,
            Path.Combine(ReleaseRoot, relativePath),
            FileAttributes.Archive,
            length,
            new string(seed, 64),
            VolumeSerial,
            new string(seed, 32),
            1,
            true);

    private static WindowsProcessIdentity CreateGuardianIdentity(VerifiedReleaseArtifactSet release)
    {
        var appHost = release.Artifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe);
        return new WindowsProcessIdentity(
            GuardianProcessId,
            GuardianCreationTime,
            GuardianSessionId,
            CreateProcessToken(),
            WindowsAppModelIdentity.Unpackaged,
            appHost.FinalPath,
            true,
            release.Root,
            release.Artifacts);
    }

    private static WindowsTokenIdentity CreateProcessToken() =>
        new(
            UserSid,
            LogonSid,
            1,
            0x0000000100000002,
            GuardianSessionId,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Primary,
            null);

    private static WindowsTokenIdentity CreateImpersonationToken() =>
        new(
            UserSid,
            LogonSid,
            1,
            0x0000000100000002,
            GuardianSessionId,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Impersonation,
            WindowsSecurityImpersonationLevel.Identification);

    private static BrokerPeerHello CreateGuardianHello() =>
        new(
            BrokerPeerHelloProtocol.ProtocolVersion,
            BrokerPeerRole.Guardian,
            GuardianProcessId,
            GuardianSessionId,
            GuardianCreationTime,
            ConnectionNonce,
            ReleaseId,
            ManifestSha256);

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().WaitAsync(CaseTimeout + CaseTimeout).ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static async Task<TException> ExpectAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("Expected " + typeof(TException).Name + ".");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class SessionContext : IAsyncDisposable
    {
        private readonly List<Exception> _expectedFailures = new();

        internal SessionContext(
            BrokerRuntimeOwnerV1 owner,
            BrokerControlSessionV1 session,
            Task runTask,
            GuardianPeerFixture peer)
        {
            Owner = owner;
            Session = session;
            RunTask = runTask;
            Peer = peer;
        }

        internal BrokerRuntimeOwnerV1 Owner { get; }

        internal BrokerControlSessionV1 Session { get; }

        internal Task RunTask { get; }

        internal GuardianPeerFixture Peer { get; }

        internal void ObserveExpectedFailure(Exception exception)
        {
            ArgumentNullException.ThrowIfNull(exception);
            _expectedFailures.Add(exception);
        }

        public async ValueTask DisposeAsync()
        {
            var failures = new List<Exception>();
            try
            {
                await Session.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                AddUnexpected(exception, failures);
            }

            try
            {
                await Owner.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                AddUnexpected(exception, failures);
            }

            try
            {
                await RunTask.ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                AddUnexpected(exception, failures);
            }

            if (failures.Count == 1)
            {
                ExceptionDispatchInfo.Capture(failures[0]).Throw();
            }

            if (failures.Count > 1)
            {
                throw new AggregateException(failures);
            }
        }

        private void AddUnexpected(Exception exception, ICollection<Exception> failures)
        {
            if (_expectedFailures.Any(expected => ReferenceEquals(expected, exception)) ||
                failures.Any(existing => ReferenceEquals(existing, exception)))
            {
                return;
            }

            failures.Add(exception);
        }
    }

    private sealed record GuardianPeerFixture(
        WindowsNamedPipePeerVerifier Verifier,
        FakeMessagePlatform Platform,
        FakePeerLease PeerLease,
        PendingPipePeerVerification Pending);

    private sealed class FakeMessagePlatform :
        INamedPipePeerTrustPlatform,
        INamedPipePeerMessageTransport
    {
        private readonly VerifiedReleaseArtifactSet _release;
        private readonly FakePeerLease _peerLease;
        private readonly ConcurrentQueue<byte[]> _reads = new();
        private readonly SemaphoreSlim _readSignal = new(0);
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _writeGate = new();
        private readonly List<byte[]> _writes = new();
        private int _blockDispose;
        private int _disposeCount;
        private long _readGeneration;

        internal FakeMessagePlatform(
            VerifiedReleaseArtifactSet release,
            FakePeerLease peerLease)
        {
            _release = release;
            _peerLease = peerLease;
        }

        public DateTimeOffset UtcNow => GuardianCreationTime.AddMinutes(1);

        public long ReadGeneration => Volatile.Read(ref _readGeneration);

        public Task Completion => _completion.Task;

        internal ManualResetEventSlim DisposeEntered { get; } = new(false);

        internal ManualResetEventSlim AllowDispose { get; } = new(false);

        internal Action? DisposeCallback { get; set; }

        internal Exception? DisposeFailure { get; set; }

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal int WriteCount
        {
            get
            {
                lock (_writeGate)
                {
                    return _writes.Count;
                }
            }
        }

        public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
        {
            Ensure(peerKind == NamedPipePeerKind.Client, "fake peer used the wrong pipe direction");
            return new PipePeerKernelIdentity(GuardianProcessId, GuardianSessionId);
        }

        public IRetainedPeerIdentityLease OpenRetainedPeer(
            uint processId,
            VerifiedReleaseArtifactSet release)
        {
            Ensure(processId == GuardianProcessId, "fake peer received the wrong process id");
            Ensure(ReferenceEquals(release, _release), "fake peer received another release");
            return _peerLease;
        }

        public ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
            NamedPipePeerKind peerKind,
            int maximumHelloBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hello = BrokerPeerHelloProtocol.Serialize(CreateGuardianHello());
            Ensure(hello.Length <= maximumHelloBytes, "fake Guardian hello exceeded the bound");
            var kernel = CaptureKernelPeer(peerKind);
            return ValueTask.FromResult(new PipePeerHelloReadEvidence(
                hello,
                Interlocked.Increment(ref _readGeneration),
                kernel,
                kernel,
                impersonatedClientToken: CreateImpersonationToken()));
        }

        public void AbortHandshake(string boundedFailureCode) =>
            ArgumentException.ThrowIfNullOrWhiteSpace(boundedFailureCode);

        public async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
            int maximumMessageBytes,
            CancellationToken cancellationToken)
        {
            await _readSignal.WaitAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return _reads.TryDequeue(out var message)
                ? message
                : ReadOnlyMemory<byte>.Empty;
        }

        public ValueTask WriteMessageAsync(
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_writeGate)
            {
                _writes.Add(message.ToArray());
            }

            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            if (Interlocked.Increment(ref _disposeCount) == 1)
            {
                DisposeEntered.Set();
                if (Volatile.Read(ref _blockDispose) != 0)
                {
                    AllowDispose.Wait(CaseTimeout);
                }

                _completion.TrySetResult();
                _readSignal.Release();
                DisposeCallback?.Invoke();
                if (DisposeFailure is not null)
                {
                    throw DisposeFailure;
                }
            }
        }

        internal void BlockDispose()
        {
            Interlocked.Exchange(ref _blockDispose, 1);
            DisposeEntered.Reset();
            AllowDispose.Reset();
        }

        internal void ReleaseDispose() => AllowDispose.Set();

        internal void EnqueueMessage(byte[] message)
        {
            _reads.Enqueue(message.ToArray());
            _readSignal.Release();
        }

        internal byte[] GetWrite(int index)
        {
            lock (_writeGate)
            {
                return _writes[index].ToArray();
            }
        }

        internal IReadOnlyList<byte[]> GetWrites(int startingIndex)
        {
            lock (_writeGate)
            {
                return _writes.Skip(startingIndex).Select(value => value.ToArray()).ToArray();
            }
        }

        internal async Task WaitForWriteCountAsync(int count, TimeSpan timeout) =>
            await WaitUntilAsync(() => WriteCount >= count, timeout).ConfigureAwait(false);
    }

    private sealed class FakePeerLease : IRetainedPeerIdentityLease
    {
        private readonly WindowsProcessIdentity _identity;
        private int _disposeCount;
        private int _disposed;

        internal FakePeerLease(
            WindowsProcessIdentity identity,
            RetainedReleaseHandleSet retainedHandles)
        {
            _identity = identity;
            RetainedHandles = retainedHandles;
        }

        public bool IsAlive
        {
            get
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                return true;
            }
        }

        public RetainedReleaseHandleSet RetainedHandles { get; }

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        public WindowsProcessIdentity Capture()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _identity;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Interlocked.Increment(ref _disposeCount);
            }
        }
    }

    private sealed class FakeRuntimeControlHost : ICodexCdpRuntimeControlHost
    {
        private readonly ConcurrentQueue<CodexCdpRuntimeReconciliationKind> _reconciliations;
        private readonly TaskCompletionSource _allowStart = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private CancellationTokenRegistration _cancellationRegistration;
        private int _cancellationRegistered;
        private int _disposeCount;
        private int _disposed;
        private int _reconcileCount;
        private int _startCancellationObserved;
        private int _startCount;

        internal FakeRuntimeControlHost(
            params CodexCdpRuntimeReconciliationKind[] reconciliations)
        {
            _reconciliations = new ConcurrentQueue<CodexCdpRuntimeReconciliationKind>(
                reconciliations.Length == 0
                    ? new[] { CodexCdpRuntimeReconciliationKind.NoCodex }
                    : reconciliations);
        }

        internal CodexCdpRuntimeStartKind StartKind { get; set; } =
            CodexCdpRuntimeStartKind.Owned;

        internal bool BlockStart { get; set; }

        internal Action? CancellationCallback { get; set; }

        internal bool BlockFirstLeaseDispose { get; set; }

        internal bool ThrowOnLeaseDispose { get; set; }

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal int ReconcileCount => Volatile.Read(ref _reconcileCount);

        internal int StartCount => Volatile.Read(ref _startCount);

        internal bool StartCancellationObserved =>
            Volatile.Read(ref _startCancellationObserved) != 0;

        internal FakeRuntimeLease? Lease { get; private set; }

        internal TaskCompletionSource StartEntered { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<CodexCdpRuntimeReconciliationKind> ReconcileAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (CancellationCallback is not null &&
                Interlocked.CompareExchange(ref _cancellationRegistered, 1, 0) == 0)
            {
                _cancellationRegistration = cancellationToken.UnsafeRegister(
                    static state => ((Action)state!).Invoke(),
                    CancellationCallback);
            }

            Interlocked.Increment(ref _reconcileCount);
            return ValueTask.FromResult(
                _reconciliations.TryDequeue(out var result)
                    ? result
                    : CodexCdpRuntimeReconciliationKind.NoCodex);
        }

        public async ValueTask<CodexCdpRuntimeStartResultV1> StartManagedAsync(
            string operationId,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            Interlocked.Increment(ref _startCount);
            StartEntered.TrySetResult();
            try
            {
                if (BlockStart)
                {
                    await _allowStart.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                }

                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException)
            {
                Interlocked.Exchange(ref _startCancellationObserved, 1);
                throw;
            }

            if (StartKind == CodexCdpRuntimeStartKind.RaceLost)
            {
                return CodexCdpRuntimeStartResultV1.RaceLost();
            }

            if (Lease is not null)
            {
                throw new InvalidOperationException("fake runtime host started more than once");
            }

            Lease = new FakeRuntimeLease(
                operationId,
                ThrowOnLeaseDispose,
                BlockFirstLeaseDispose);
            return CodexCdpRuntimeStartResultV1.Owned(Lease);
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Interlocked.Increment(ref _disposeCount);
            _cancellationRegistration.Dispose();
            if (Lease is not null)
            {
                await Lease.DisposeAsync().ConfigureAwait(false);
            }
        }

        internal void AllowStart() => _allowStart.TrySetResult();
    }

    private sealed class FakeRuntimeLease : ICodexCdpHandleLease
    {
        private readonly TaskCompletionSource<CodexCdpRuntimeExitResult> _exit = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _allowFirstDispose = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _firstDisposeEntered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly bool _blockFirstDispose;
        private readonly bool _throwOnDispose;
        private int _alive = 1;
        private int _disposeAttemptCount;
        private int _disposeCount;
        private int _disposed;

        internal FakeRuntimeLease(
            string operationId,
            bool throwOnDispose,
            bool blockFirstDispose)
        {
            _blockFirstDispose = blockFirstDispose;
            _throwOnDispose = throwOnDispose;
            Identity = new CodexCdpRuntimeIdentity(
                "runtime-control-0123456789",
                operationId,
                4242,
                RuntimeCreationTime);
        }

        public CodexCdpRuntimeIdentity Identity { get; }

        public bool IsAlive => Volatile.Read(ref _alive) != 0;

        public Task<CodexCdpRuntimeExitResult> Exit => _exit.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal int DisposeAttemptCount => Volatile.Read(ref _disposeAttemptCount);

        internal Task FirstDisposeEntered => _firstDisposeEntered.Task;

        internal bool CompleteNaturalExit(int exitCode)
        {
            var completed = _exit.TrySetResult(CodexCdpRuntimeExitResult.Natural(
                exitCode,
                RuntimeCreationTime.AddSeconds(1)));
            if (completed)
            {
                Interlocked.Exchange(ref _alive, 0);
            }

            return completed;
        }

        internal bool CompleteFaulted(string code) =>
            _exit.TrySetResult(CodexCdpRuntimeExitResult.Faulted(
                code,
                RuntimeCreationTime.AddSeconds(1)));

        internal void AllowFirstDispose() => _allowFirstDispose.TrySetResult();

        public async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref _disposeAttemptCount);
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Interlocked.Increment(ref _disposeCount);
                if (_blockFirstDispose)
                {
                    _firstDisposeEntered.TrySetResult();
                    await _allowFirstDispose.Task.ConfigureAwait(false);
                }

                Interlocked.Exchange(ref _alive, 0);
                if (_throwOnDispose)
                {
                    throw new IOException("fake-runtime-lease-dispose-failed");
                }
            }
        }
    }
}
