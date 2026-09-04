using CodexGuardian.Control;
using System;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

internal static class CodexCdpRuntimeOwnershipOfflineTests
{
    private const string Epoch = "epoch-runtime-0123456789";
    private const string LaunchOperation = "operation-runtime-launch-0001";
    private const string OtherOperation = "operation-runtime-launch-0002";
    private const string ClientId = "guardian-runtime-client-0001";
    private static readonly DateTimeOffset CreationTimeUtc =
        new(2026, 8, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan CaseTimeout = TimeSpan.FromSeconds(5);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "runtime start result transfers one exact lease and never adopts a race loser",
            TestStartResultOwnershipAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Guardian disconnect does not dispose the Broker runtime owner",
            TestClientDisconnectPreservesOwnerAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "transport fault degrades observation without ending the runtime lease",
            TestTransportFaultPreservesLeaseAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "natural exit publishes once and waits for explicit owner cleanup",
            TestNaturalExitAndOwnerCleanupAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime host and handle lease dispose concurrently exactly once",
            TestConcurrentDisposeAsync,
            assert).ConfigureAwait(false);
    }

    private static async Task TestStartResultOwnershipAsync()
    {
        var host = new FakeRuntimeControlHost();
        await using var owned = await host.StartManagedAsync(LaunchOperation).ConfigureAwait(false);
        Ensure(
            owned.Kind == CodexCdpRuntimeStartKind.Owned,
            "the fake runtime did not return an explicit owned result");
        var lease = owned.TakeOwnedLease();
        Ensure(
            ReferenceEquals(lease, host.Lease) &&
            lease.Identity.LaunchOperationId == LaunchOperation &&
            lease.Identity.ProcessId == 4242,
            "the retained runtime identity was not bound to the launch operation");
        await ExpectAsync<InvalidOperationException>(
            () => Task.Run(() => owned.TakeOwnedLease())).ConfigureAwait(false);
        await owned.DisposeAsync().ConfigureAwait(false);
        Ensure(
            lease.IsAlive && ((FakeCdpHandleLease)lease).DisposeCount == 0,
            "disposing a transferred start result disposed the retained lease");

        await using var raceLost = CodexCdpRuntimeStartResultV1.RaceLost();
        Ensure(
            raceLost.Kind == CodexCdpRuntimeStartKind.RaceLost,
            "the race-lost result did not retain its disjoint kind");
        await ExpectAsync<InvalidOperationException>(
            () => Task.Run(() => raceLost.TakeOwnedLease())).ConfigureAwait(false);
        var abandonedLease = new FakeCdpHandleLease(OtherOperation);
        await using (var abandoned = CodexCdpRuntimeStartResultV1.Owned(abandonedLease))
        {
            Ensure(
                abandoned.Kind == CodexCdpRuntimeStartKind.Owned,
                "the abandoned start result lost its owned kind");
        }

        Ensure(
            abandonedLease.DisposeCount == 1,
            "disposing an untransferred start result did not release its exact lease");

        var exitedBeforeTransferLease = new FakeCdpHandleLease(OtherOperation);
        await using (var exitedBeforeTransfer =
                     CodexCdpRuntimeStartResultV1.Owned(exitedBeforeTransferLease))
        {
            Ensure(
                exitedBeforeTransferLease.CompleteNaturalExit(exitCode: 7),
                "the transfer-race fixture did not publish one exact natural exit");
            var transferredAfterExit = exitedBeforeTransfer.TakeOwnedLease();
            Ensure(
                ReferenceEquals(transferredAfterExit, exitedBeforeTransferLease) &&
                !transferredAfterExit.IsAlive &&
                transferredAfterExit.Exit.IsCompleted,
                "a legal start result withheld exact lease authority after the runtime exited");
            await transferredAfterExit.DisposeAsync().ConfigureAwait(false);
        }

        CodexCdpRuntimeStartResultV1? reentrant = null;
        Task? reentrantDispose = null;
        var reentrantLease = new FakeCdpHandleLease(OtherOperation)
        {
            DisposeCallback = () =>
            {
                reentrantDispose = reentrant!.DisposeAsync().AsTask();
                throw new InvalidOperationException("fake-start-result-dispose-callback-failed");
            }
        };
        reentrant = CodexCdpRuntimeStartResultV1.Owned(reentrantLease);
        var outerDispose = reentrant.DisposeAsync().AsTask();
        await ExpectAsync<InvalidOperationException>(
            () => outerDispose).ConfigureAwait(false);
        Ensure(
            ReferenceEquals(outerDispose, reentrantDispose) &&
            reentrantLease.DisposeCount == 1,
            "reentrant start-result disposal published another task or lost cleanup failure");
        Ensure(host.StartCount == 1, "the explicit start result changed the host invocation count");
        await lease.DisposeAsync().ConfigureAwait(false);
        await host.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task TestClientDisconnectPreservesOwnerAsync()
    {
        var (machine, host, lease) = await CreateManagedReadyAsync().ConfigureAwait(false);
        var connected = machine.ConnectClient(ClientId);
        Ensure(
            connected.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            connected.Snapshot.ConnectedClients == 1,
            "the Guardian client was not connected to the managed runtime snapshot");

        var disconnected = machine.DisconnectClient(ClientId);
        Ensure(
            disconnected.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            disconnected.Snapshot.ConnectedClients == 0 &&
            disconnected.Snapshot.State == CodexCdpBrokerState.ManagedReady &&
            disconnected.Snapshot.OwnsManagedCodex &&
            !disconnected.Snapshot.BrokerExitIntent &&
            !disconnected.Snapshot.ManagedCodexExitIntent,
            "Guardian disconnect changed the Broker-owned runtime lifetime");
        Ensure(
            host.DisposeCount == 0 && lease.DisposeCount == 0 && lease.IsAlive,
            "Guardian disconnect disposed or ended the Broker runtime owner");
        TestSequenceExhaustionIsAtomic();
    }

    private static async Task TestTransportFaultPreservesLeaseAsync()
    {
        var (machine, host, lease) = await CreateManagedReadyAsync().ConfigureAwait(false);
        var degraded = machine.ApplySignal(CodexCdpBrokerSignal.FaultDetected);
        Ensure(
            degraded.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            degraded.Snapshot.State == CodexCdpBrokerState.ManagedUnverified &&
            degraded.Snapshot.OwnsManagedCodex &&
            !degraded.Snapshot.BrokerExitIntent &&
            !degraded.Snapshot.ManagedCodexExitIntent,
            "a transport fault did not degrade to retained unverified ownership");
        Ensure(
            lease.IsAlive && !lease.Exit.IsCompleted &&
            lease.DisposeCount == 0 && host.DisposeCount == 0,
            "a transport fault ended or disposed the fake process lease");

        var replay = machine.ApplySignal(CodexCdpBrokerSignal.FaultDetected);
        Ensure(
            replay.Disposition == CodexCdpBrokerApplyDisposition.Replayed &&
            replay.Snapshot.OwnsManagedCodex,
            "a repeated transport fault changed retained runtime ownership");

        var degradedSnapshot = replay.Snapshot;
        var missingOperation = machine.ApplySignal(CodexCdpBrokerSignal.CdpHandshakeCompleted);
        Ensure(
            missingOperation.Disposition == CodexCdpBrokerApplyDisposition.Rejected &&
            missingOperation.Code == "launch-operation-mismatch" &&
            missingOperation.Snapshot == degradedSnapshot,
            "an unbound verification signal restored managed runtime readiness");

        var wrongOperation = machine.ApplySignal(
            CodexCdpBrokerSignal.CdpHandshakeCompleted,
            OtherOperation);
        Ensure(
            wrongOperation.Disposition == CodexCdpBrokerApplyDisposition.Rejected &&
            wrongOperation.Code == "launch-operation-mismatch" &&
            wrongOperation.Snapshot == degradedSnapshot,
            "a different launch operation restored managed runtime readiness");

        var restored = machine.ApplySignal(
            CodexCdpBrokerSignal.CdpHandshakeCompleted,
            LaunchOperation);
        Ensure(
            restored.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            restored.Code == "managed-verification-restored" &&
            restored.Snapshot.State == CodexCdpBrokerState.ManagedReady &&
            restored.Snapshot.OwnsManagedCodex &&
            restored.Snapshot.ActiveLaunchOperationId == LaunchOperation &&
            restored.Snapshot.Sequence == degradedSnapshot.Sequence + 1,
            "the exact retained launch operation did not restore managed readiness once");
        Ensure(
            lease.IsAlive && !lease.Exit.IsCompleted &&
            lease.DisposeCount == 0 && host.DisposeCount == 0,
            "verification recovery replaced or disposed the retained runtime lease");
    }

    private static async Task TestNaturalExitAndOwnerCleanupAsync()
    {
        var (machine, host, lease) = await CreateManagedReadyAsync().ConfigureAwait(false);
        var publications = await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(() => lease.CompleteNaturalExit(exitCode: 0))))
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        var exit = await lease.Exit.WaitAsync(CaseTimeout).ConfigureAwait(false);

        Ensure(publications.Count(published => published) == 1, "natural exit published more than once");
        Ensure(
            exit.Kind == CodexCdpRuntimeExitKind.Natural &&
            exit.ExitCode == 0 &&
            exit.FailureCode is null &&
            !lease.IsAlive &&
            lease.NaturalExitPublicationCount == 1,
            "the natural exit result was not exact and terminal");
        Ensure(
            lease.DisposeCount == 0 && host.DisposeCount == 0,
            "natural exit implicitly disposed the runtime owner before reconciliation");

        var exited = machine.ApplySignal(CodexCdpBrokerSignal.OwnedCodexExited);
        Ensure(
            exited.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            exited.Snapshot.State == CodexCdpBrokerState.OwnedCodexExited &&
            !exited.Snapshot.OwnsManagedCodex,
            "natural process exit did not release state-machine ownership");
        await lease.DisposeAsync().ConfigureAwait(false);
        await lease.DisposeAsync().ConfigureAwait(false);
        Ensure(
            lease.DisposeCount == 1 && host.DisposeCount == 0,
            "explicit owner cleanup did not dispose the handle lease exactly once");

        var fault = CodexCdpRuntimeExitResult.Faulted(
            "runtime-handle-wait-failed",
            CreationTimeUtc.AddMinutes(1));
        Ensure(
            fault.Kind == CodexCdpRuntimeExitKind.Faulted &&
            fault.ExitCode is null &&
            fault.FailureCode == "runtime-handle-wait-failed",
            "faulted runtime exit metadata was not disjoint from a natural exit");
    }

    private static async Task TestConcurrentDisposeAsync()
    {
        var host = new FakeRuntimeControlHost();
        await using var result = await host.StartManagedAsync(LaunchOperation).ConfigureAwait(false);
        var lease = (FakeCdpHandleLease)result.TakeOwnedLease();
        await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(async () => await lease.DisposeAsync().ConfigureAwait(false))))
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        Ensure(lease.DisposeCount == 1, "concurrent lease disposal released ownership more than once");

        await Task.WhenAll(Enumerable.Range(0, 32)
                .Select(_ => Task.Run(async () => await host.DisposeAsync().ConfigureAwait(false))))
            .WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        Ensure(
            host.DisposeCount == 1 && lease.DisposeCount == 1,
            "concurrent host disposal did not share one owner cleanup");
        await ExpectAsync<ObjectDisposedException>(
            () => host.StartManagedAsync(LaunchOperation).AsTask()).ConfigureAwait(false);
    }

    private static async Task<(CodexCdpBrokerStateMachine Machine, FakeRuntimeControlHost Host,
        FakeCdpHandleLease Lease)> CreateManagedReadyAsync()
    {
        var machine = new CodexCdpBrokerStateMachine(Epoch);
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.BeginReconciliation).Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted &&
            machine.ApplySignal(CodexCdpBrokerSignal.NoCodexObserved).Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted,
            "the fake runtime did not reach idle reconciliation");
        var reserved = machine.ApplyCommand(new CodexCdpBrokerCommand(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            Epoch,
            LaunchOperation,
            null));
        Ensure(
            reserved.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            reserved.Snapshot.State == CodexCdpBrokerState.LaunchReserved,
            "the fake runtime launch was not reserved");

        var host = new FakeRuntimeControlHost();
        await using var result = await host.StartManagedAsync(LaunchOperation).ConfigureAwait(false);
        var lease = (FakeCdpHandleLease)result.TakeOwnedLease();
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.BeginCandidateLaunch, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            machine.ApplySignal(CodexCdpBrokerSignal.CandidateProcessStarted, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            machine.ApplySignal(CodexCdpBrokerSignal.CandidateOwnershipVerified, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Accepted,
            "the fake runtime did not retain verified candidate ownership");
        var ready = machine.ApplySignal(
            CodexCdpBrokerSignal.CdpHandshakeCompleted,
            LaunchOperation);
        Ensure(
            ready.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            ready.Snapshot.State == CodexCdpBrokerState.ManagedReady &&
            ready.Snapshot.OwnsManagedCodex,
            "the fake runtime did not reach managed-ready ownership");
        return (machine, host, lease);
    }

    private static void TestSequenceExhaustionIsAtomic()
    {
        static void AssertExhaustedMutationIsAtomic(
            CodexCdpBrokerStateMachine machine,
            Action mutation,
            string message)
        {
            SetSequence(machine, CodexCdpBrokerProtocol.MaximumSequence);
            var before = machine.Current;
            var failure = Expect<InvalidOperationException>(mutation);
            Ensure(
                failure.Message == "The broker sequence space is exhausted." &&
                machine.Current == before,
                message);
        }

        var connect = CreateIdleStateMachine();
        AssertExhaustedMutationIsAtomic(
            connect,
            () => connect.ConnectClient(ClientId),
            "sequence exhaustion partially connected a client");

        var disconnect = CreateIdleStateMachine();
        Ensure(
            disconnect.ConnectClient(ClientId).Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted,
            "sequence exhaustion disconnect fixture did not connect");
        AssertExhaustedMutationIsAtomic(
            disconnect,
            () => disconnect.DisconnectClient(ClientId),
            "sequence exhaustion partially disconnected a client");

        var operation = CreateIdleStateMachine();
        var startCommand = new CodexCdpBrokerCommand(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            Epoch,
            LaunchOperation,
            null);
        AssertExhaustedMutationIsAtomic(
            operation,
            () => operation.ApplyCommand(startCommand),
            "sequence exhaustion partially committed an operation ledger entry");

        var ownership = CreateVerifyingCandidateStateMachine();
        AssertExhaustedMutationIsAtomic(
            ownership,
            () => ownership.ApplySignal(
                CodexCdpBrokerSignal.CandidateOwnershipVerified,
                LaunchOperation),
            "sequence exhaustion partially acquired runtime ownership");

        var exited = CreateManagedReadyStateMachine();
        AssertExhaustedMutationIsAtomic(
            exited,
            () => exited.ApplySignal(CodexCdpBrokerSignal.OwnedCodexExited),
            "sequence exhaustion partially released runtime ownership");

        var faulted = CreateManagedReadyStateMachine();
        AssertExhaustedMutationIsAtomic(
            faulted,
            () => faulted.ApplySignal(CodexCdpBrokerSignal.FaultDetected),
            "sequence exhaustion partially degraded runtime observation");

        var boundary = CreateIdleStateMachine();
        SetSequence(boundary, CodexCdpBrokerProtocol.MaximumSequence - 1);
        var boundaryAccepted = boundary.ConnectClient(ClientId);
        Ensure(
            boundaryAccepted.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            boundaryAccepted.Snapshot.Sequence == CodexCdpBrokerProtocol.MaximumSequence,
            "the last available Broker sequence did not commit exactly once");
        var maximumSnapshot = boundary.Current;
        Ensure(
            boundary.ConnectClient(ClientId).Disposition ==
                CodexCdpBrokerApplyDisposition.Replayed &&
            boundary.ApplyCommand(new CodexCdpBrokerCommand(
                CodexCdpBrokerCommandKind.GetStatus,
                Epoch,
                null,
                null)).Snapshot == maximumSnapshot &&
            boundary.ConnectClient("bad").Snapshot == maximumSnapshot,
            "read-only replay or rejection stopped working at maximum sequence");
        Expect<InvalidOperationException>(() => boundary.DisconnectClient(ClientId));
        Ensure(
            boundary.Current == maximumSnapshot,
            "maximum-sequence disconnect changed state after rejection");

        var replay = CreateIdleStateMachine();
        Ensure(
            replay.ApplyCommand(startCommand).Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted,
            "operation replay fixture did not accept its initial operation");
        SetSequence(replay, CodexCdpBrokerProtocol.MaximumSequence);
        var replaySnapshot = replay.Current;
        Ensure(
            replay.ApplyCommand(startCommand).Disposition ==
                CodexCdpBrokerApplyDisposition.Replayed &&
            replay.Current == replaySnapshot,
            "operation replay mutated an exhausted sequence space");
    }

    private static CodexCdpBrokerStateMachine CreateIdleStateMachine()
    {
        var machine = new CodexCdpBrokerStateMachine(Epoch);
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.BeginReconciliation).Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted &&
            machine.ApplySignal(CodexCdpBrokerSignal.NoCodexObserved).Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted,
            "the sequence fixture did not reach idle state");
        return machine;
    }

    private static CodexCdpBrokerStateMachine CreateVerifyingCandidateStateMachine()
    {
        var machine = CreateIdleStateMachine();
        var reserved = machine.ApplyCommand(new CodexCdpBrokerCommand(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            Epoch,
            LaunchOperation,
            null));
        Ensure(
            reserved.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            machine.ApplySignal(CodexCdpBrokerSignal.BeginCandidateLaunch, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            machine.ApplySignal(CodexCdpBrokerSignal.CandidateProcessStarted, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Accepted,
            "the sequence fixture did not reach candidate verification");
        return machine;
    }

    private static CodexCdpBrokerStateMachine CreateManagedReadyStateMachine()
    {
        var machine = CreateVerifyingCandidateStateMachine();
        Ensure(
            machine.ApplySignal(
                    CodexCdpBrokerSignal.CandidateOwnershipVerified,
                    LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            machine.ApplySignal(CodexCdpBrokerSignal.CdpHandshakeCompleted, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Accepted,
            "the sequence fixture did not reach managed ready");
        return machine;
    }

    private static void SetSequence(CodexCdpBrokerStateMachine machine, long sequence)
    {
        var field = typeof(CodexCdpBrokerStateMachine).GetField(
            "_sequence",
            BindingFlags.Instance | BindingFlags.NonPublic) ??
            throw new InvalidOperationException("The Broker sequence field was not found.");
        field.SetValue(machine, sequence);
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().WaitAsync(CaseTimeout).ConfigureAwait(false);
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

        throw new InvalidOperationException("Expected " + typeof(TException).Name + ".");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeRuntimeControlHost : ICodexCdpRuntimeControlHost
    {
        private readonly object _sync = new();
        private FakeCdpHandleLease? _lease;
        private string? _operationId;
        private int _disposeCount;
        private int _disposed;
        private int _startCount;

        internal int StartCount => Volatile.Read(ref _startCount);

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal FakeCdpHandleLease Lease => _lease ??
            throw new InvalidOperationException("The fake runtime has not started.");

        public ValueTask<CodexCdpRuntimeReconciliationKind> ReconcileAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return ValueTask.FromResult(CodexCdpRuntimeReconciliationKind.NoCodex);
        }

        public ValueTask<CodexCdpRuntimeStartResultV1> StartManagedAsync(
            string operationId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!CodexCdpBrokerProtocol.IsControlIdentifier(operationId))
            {
                throw new ArgumentException("A valid runtime operation id is required.", nameof(operationId));
            }

            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                if (_lease is null)
                {
                    _operationId = operationId;
                    _lease = new FakeCdpHandleLease(operationId);
                    Interlocked.Increment(ref _startCount);
                    return ValueTask.FromResult(CodexCdpRuntimeStartResultV1.Owned(_lease));
                }

                throw new InvalidOperationException(
                    string.Equals(_operationId, operationId, StringComparison.Ordinal)
                        ? "runtime-start-called-more-than-once"
                        : "runtime-operation-conflict");
            }
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return ValueTask.CompletedTask;
            }

            Interlocked.Increment(ref _disposeCount);
            FakeCdpHandleLease? lease;
            lock (_sync)
            {
                lease = _lease;
            }

            return lease is null ? ValueTask.CompletedTask : lease.DisposeAsync();
        }
    }

    private sealed class FakeCdpHandleLease : ICodexCdpHandleLease
    {
        private readonly TaskCompletionSource<CodexCdpRuntimeExitResult> _exit = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _alive = 1;
        private int _disposeCount;
        private int _disposed;
        private int _naturalExitPublicationCount;

        internal FakeCdpHandleLease(string launchOperationId)
        {
            Identity = new CodexCdpRuntimeIdentity(
                "runtime-0123456789abcdef",
                launchOperationId,
                processId: 4242,
                CreationTimeUtc);
        }

        public CodexCdpRuntimeIdentity Identity { get; }

        public bool IsAlive => Volatile.Read(ref _alive) != 0;

        public Task<CodexCdpRuntimeExitResult> Exit => _exit.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal Action? DisposeCallback { get; init; }

        internal int NaturalExitPublicationCount => Volatile.Read(ref _naturalExitPublicationCount);

        internal bool CompleteNaturalExit(int exitCode)
        {
            if (Interlocked.CompareExchange(ref _alive, 0, 1) != 1)
            {
                return false;
            }

            var published = _exit.TrySetResult(CodexCdpRuntimeExitResult.Natural(
                exitCode,
                CreationTimeUtc.AddSeconds(1)));
            if (published)
            {
                Interlocked.Increment(ref _naturalExitPublicationCount);
            }

            return published;
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Interlocked.Increment(ref _disposeCount);
                DisposeCallback?.Invoke();
            }

            return ValueTask.CompletedTask;
        }
    }
}
