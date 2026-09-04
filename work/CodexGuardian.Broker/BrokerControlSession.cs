using CodexGuardian.Control;
using CodexGuardian.Trust;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal sealed class BrokerControlSessionException : IOException
{
    internal BrokerControlSessionException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(code))
        {
            throw new ArgumentException(
                "A bounded Broker control-session failure code is required.",
                nameof(code));
        }

        Code = code;
    }

    internal string Code { get; }
}

internal static class BrokerControlFailureArbitration
{
    internal const string CleanupFailureDataKey =
        "broker-control-cleanup-failure";
    internal const string ConcurrentFailureDataKey =
        "broker-control-concurrent-failure";

    internal static Exception CombineCleanupFailures(
        Exception? current,
        Exception next)
    {
        ArgumentNullException.ThrowIfNull(next);
        if (current is null || ReferenceEquals(current, next))
        {
            return current ?? next;
        }

        return new AggregateException(current, next);
    }

    internal static Exception? PreserveCleanupFailure(
        Exception? primary,
        Exception? cleanup) =>
        PreserveSecondaryFailure(primary, cleanup, CleanupFailureDataKey);

    internal static Exception? PreserveSecondaryFailure(
        Exception? primary,
        Exception? secondary,
        string dataKey)
    {
        if (secondary is null)
        {
            return primary;
        }

        if (primary is null || ReferenceEquals(primary, secondary))
        {
            return primary ?? secondary;
        }

        if (primary.Data[dataKey] is Exception existing)
        {
            if (!ReferenceEquals(existing, secondary))
            {
                primary.Data[dataKey] = new AggregateException(existing, secondary);
            }
        }
        else
        {
            primary.Data[dataKey] = secondary;
        }

        return primary;
    }

    internal static bool ContainsFailure(
        Exception? container,
        Exception? candidate)
    {
        if (container is null || candidate is null)
        {
            return false;
        }

        if (ReferenceEquals(container, candidate))
        {
            return true;
        }

        return container is AggregateException aggregate &&
            aggregate.InnerExceptions.Any(inner => ContainsFailure(inner, candidate));
    }
}

internal sealed class BrokerControlSessionV1 : IAsyncDisposable
{
    private const int MaximumMandatoryResponses = 64;
    private const int HelloPending = 0;
    private const int HelloConnecting = 1;
    private const int HelloConnected = 2;
    private const int HelloTerminal = 3;
    private static readonly CancellationToken StoppedCancellationToken =
        new(canceled: true);

    private readonly object _gate = new();
    private readonly BrokerRuntimeOwnerV1 _owner;
    private readonly VerifiedGuardianManagedEntryConnectionV1 _guardianConnection;
    private readonly CodexCdpBrokerCommandFrameDecoder _decoder = new();
    private readonly CodexCdpBrokerSubscriptionQueue _subscriptionQueue;
    private readonly Queue<BrokerOutboundFrameV1> _mandatoryResponses = new();
    private readonly SemaphoreSlim _outboundSignal = new(0);
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly TaskCompletionSource _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _terminalWriteCompletion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _disposeTask;
    private Task? _runTask;
    private bool _subscribed;
    private bool _terminalResponsePending;
    private bool _writerWakePending;
    private Exception? _terminalFailure;
    private int _cleanupStarted;
    private int _connected;
    private int _helloPhase = HelloPending;
    private int _resourcesDisposed;
    private int _stopRequested;

    internal BrokerControlSessionV1(
        BrokerRuntimeOwnerV1 owner,
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection,
        string clientId,
        int subscriptionCapacity)
    {
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));
        _guardianConnection = guardianConnection ??
            throw new ArgumentNullException(nameof(guardianConnection));
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(clientId))
        {
            throw new ArgumentException("A valid Broker-generated client id is required.", nameof(clientId));
        }

        ClientId = clientId;
        _subscriptionQueue = new CodexCdpBrokerSubscriptionQueue(
            owner.BrokerEpoch,
            subscriptionCapacity);
        ObserveFault(_completion.Task);
        ObserveFault(_terminalWriteCompletion.Task);
    }

    internal string ClientId { get; }

    internal Task Completion => _completion.Task;

    internal VerifiedGuardianManagedEntryConnectionV1 GuardianConnection => _guardianConnection;

    internal bool TryBeginHello()
    {
        lock (_gate)
        {
            if (_helloPhase != HelloPending ||
                Volatile.Read(ref _stopRequested) != 0 ||
                Volatile.Read(ref _cleanupStarted) != 0)
            {
                return false;
            }

            _helloPhase = HelloConnecting;
            return true;
        }
    }

    internal bool TryCommitConnected()
    {
        lock (_gate)
        {
            if (_helloPhase != HelloConnecting ||
                Volatile.Read(ref _stopRequested) != 0 ||
                Volatile.Read(ref _cleanupStarted) != 0)
            {
                _helloPhase = HelloTerminal;
                return false;
            }

            _helloPhase = HelloConnected;
            Volatile.Write(ref _connected, 1);
            return true;
        }
    }

    internal Task RunAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_runTask is not null || _disposeTask is not null)
            {
                return Task.FromException(new InvalidOperationException(
                    "The Broker control session can run only once."));
            }

            _runTask = RunAndPublishCompletionAsync(cancellationToken);
            return _runTask;
        }
    }

    internal void ObserveSnapshot(
        CodexCdpBrokerSnapshot snapshot,
        bool requireResync)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var signal = false;
        lock (_gate)
        {
            if (!_subscribed || Volatile.Read(ref _stopRequested) != 0)
            {
                return;
            }

            if (snapshot.Sequence < _subscriptionQueue.LatestSequence)
            {
                return;
            }

            if (requireResync)
            {
                signal = _subscriptionQueue.RequireResync(snapshot);
            }
            else if (snapshot.Sequence > _subscriptionQueue.LatestSequence)
            {
                _subscriptionQueue.Enqueue(snapshot);
                signal = true;
            }
        }

        if (signal)
        {
            SignalWriter();
        }
    }

    internal void RequestStopFromOwner() => RequestStop();

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposeTask is not null)
            {
                return new ValueTask(_disposeTask);
            }

            _disposeTask = DisposeCoreAsync(_runTask);
            return new ValueTask(_disposeTask);
        }
    }

    private async Task DisposeCoreAsync(Task? runTask)
    {
        // Publish the one-shot dispose task before cancellation can reenter this session.
        await Task.Yield();
        RequestStop();
        if (runTask is null)
        {
            await DisposeWithoutRunAsync().ConfigureAwait(false);
            return;
        }

        await AwaitRunForDisposeAsync(runTask).ConfigureAwait(false);
    }

    private async Task RunAndPublishCompletionAsync(CancellationToken cancellationToken)
    {
        try
        {
            await RunCoreAsync(cancellationToken).ConfigureAwait(false);
            _completion.TrySetResult();
        }
        catch (Exception exception)
        {
            _completion.TrySetException(exception);
            throw;
        }
    }

    private async Task RunCoreAsync(CancellationToken cancellationToken)
    {
        using var callerRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.UnsafeRegister(
                static state => ((BrokerControlSessionV1)state!).RequestStop(),
                this)
            : default;
        var reader = CaptureFailureAsync(ReadCommandsAsync);
        var writer = CaptureFailureAsync(WriteFramesAsync);
        var connection = CaptureFailureAsync(async () =>
            await _guardianConnection.Completion.ConfigureAwait(false));
        var first = await Task.WhenAny(reader, writer, connection).ConfigureAwait(false);
        var firstFailure = await first.ConfigureAwait(false);
        var expectedStop = Volatile.Read(ref _stopRequested) != 0 ||
            IsTerminalResponsePending() ||
            firstFailure is OperationCanceledException firstCancellation &&
            firstCancellation.CancellationToken.IsCancellationRequested;
        RequestStop();
        var loopFailures = await Task.WhenAll(reader, writer).ConfigureAwait(false);
        var failure = ReadTerminalFailure();
        failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            failure,
            SelectUnexpectedFailure(firstFailure, expectedStop),
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        foreach (var loopFailure in loopFailures)
        {
            failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
                failure,
                SelectUnexpectedFailure(loopFailure, expectedStop),
                BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        }

        var cleanupFailure = await CleanupAsync().ConfigureAwait(false);
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            cleanupFailure);
        var connectionFailure = await connection.ConfigureAwait(false);
        var unexpectedConnectionFailure = SelectUnexpectedFailure(
            connectionFailure,
            expectedStop);
        if (!BrokerControlFailureArbitration.ContainsFailure(
                cleanupFailure,
                unexpectedConnectionFailure))
        {
            failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
                failure,
                unexpectedConnectionFailure,
                BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private async Task ReadCommandsAsync()
    {
        try
        {
            while (true)
            {
                var message = await _guardianConnection.ReadMessageAsync(
                        CodexCdpBrokerProtocol.MaximumFrameBytes + sizeof(uint),
                        _lifetimeCancellation.Token)
                    .ConfigureAwait(false);
                var commands = _decoder.Append(message.Span);
                foreach (var command in commands)
                {
                    await ProcessCommandAsync(command).ConfigureAwait(false);
                    if (IsTerminalResponsePending())
                    {
                        await _terminalWriteCompletion.Task
                            .WaitAsync(_lifetimeCancellation.Token)
                            .ConfigureAwait(false);
                        return;
                    }
                }
            }
        }
        catch (BrokerPeerTrustException exception) when (
            string.Equals(exception.Code, "peer-message-eof", StringComparison.Ordinal))
        {
            _decoder.Complete();
            throw;
        }
    }

    private async Task ProcessCommandAsync(CodexCdpBrokerCommand command)
    {
        var helloComplete = Volatile.Read(ref _helloPhase) == HelloConnected;

        if (!helloComplete)
        {
            if (command.Kind != CodexCdpBrokerCommandKind.Hello)
            {
                throw Fail(
                    "control-hello-required",
                    "The first Broker control command must be hello.");
            }

            if (!TryBeginHello())
            {
                throw Fail(
                    "control-hello-repeated",
                    "The Broker control session received hello after its opening phase.");
            }

            var hello = await _owner.ConnectSessionAsync(
                    this,
                    _guardianConnection,
                    _lifetimeCancellation.Token)
                .ConfigureAwait(false);

            QueueMandatory(new BrokerOutboundFrameV1(
                CodexCdpBrokerProtocol.SerializeCommandResult(command, hello),
                FullSnapshot: null,
                AcknowledgeResync: false,
                StopAfterWrite: false));
            QueueMandatory(new BrokerOutboundFrameV1(
                CodexCdpBrokerProtocol.SerializeSnapshot(hello.Snapshot, fullSnapshot: true),
                hello.Snapshot,
                AcknowledgeResync: false,
                StopAfterWrite: false));
            return;
        }

        if (command.Kind == CodexCdpBrokerCommandKind.Hello)
        {
            throw Fail(
                "control-hello-repeated",
                "The Broker control session received a repeated hello.");
        }

        var execution = await _owner.ExecuteCommandAsync(
                this,
                _guardianConnection,
                command,
                _lifetimeCancellation.Token)
            .ConfigureAwait(false);
        var epochMismatch = string.Equals(
            execution.Result.Code,
            "broker-epoch-mismatch",
            StringComparison.Ordinal);
        QueueMandatory(new BrokerOutboundFrameV1(
            CodexCdpBrokerProtocol.SerializeCommandResult(command, execution.Result),
            FullSnapshot: null,
            AcknowledgeResync: false,
            StopAfterWrite: epochMismatch),
            terminalAfterWrite: epochMismatch);

        if (execution.Result.Disposition == CodexCdpBrokerApplyDisposition.Accepted)
        {
            if (command.Kind == CodexCdpBrokerCommandKind.Subscribe)
            {
                lock (_gate)
                {
                    _subscribed = true;
                    _subscriptionQueue.BeginSubscription(
                        command.AfterSequence!.Value,
                        execution.Result.Snapshot);
                    var current = _owner.Current;
                    if (current.Sequence > _subscriptionQueue.LatestSequence)
                    {
                        _subscriptionQueue.RequireResync(current);
                    }
                }

                SignalWriter();
            }
            else if (command.Kind is CodexCdpBrokerCommandKind.GetStatus or
                     CodexCdpBrokerCommandKind.GetFullSnapshot)
            {
                QueueMandatory(new BrokerOutboundFrameV1(
                    CodexCdpBrokerProtocol.SerializeSnapshot(
                        execution.Result.Snapshot,
                        fullSnapshot: true),
                    execution.Result.Snapshot,
                    AcknowledgeResync:
                        command.Kind == CodexCdpBrokerCommandKind.GetFullSnapshot,
                    StopAfterWrite: false));
            }
        }

        if (execution.InitiatingSessionSnapshot is not null)
        {
            ObserveSnapshot(execution.InitiatingSessionSnapshot, requireResync: false);
        }
    }

    private async Task WriteFramesAsync()
    {
        try
        {
            while (true)
            {
                await _outboundSignal.WaitAsync(_lifetimeCancellation.Token).ConfigureAwait(false);
                while (TryTakeOutbound(out var outbound))
                {
                    try
                    {
                        await _guardianConnection.WriteMessageAsync(
                                CodexCdpBrokerProtocol.EncodeFrame(outbound.Json),
                                _lifetimeCancellation.Token)
                            .ConfigureAwait(false);
                        if (outbound.AcknowledgeResync && outbound.FullSnapshot is not null)
                        {
                            var signal = false;
                            lock (_gate)
                            {
                                if (!_subscriptionQueue.AcknowledgeFullSnapshot(outbound.FullSnapshot) &&
                                    _subscriptionQueue.RequiresResync)
                                {
                                    signal = true;
                                }
                            }

                            if (signal)
                            {
                                SignalWriter();
                            }
                        }

                        if (outbound.StopAfterWrite)
                        {
                            _terminalWriteCompletion.TrySetResult();
                            RequestStop();
                            return;
                        }
                    }
                    catch (Exception exception)
                    {
                        RecordTerminalWriteFailure(exception);
                        throw;
                    }
                }
            }
        }
        catch (Exception exception)
        {
            RecordTerminalWriteFailure(exception);
            throw;
        }
    }

    private void RecordTerminalWriteFailure(Exception exception)
    {
        lock (_gate)
        {
            if (_terminalResponsePending && Volatile.Read(ref _stopRequested) == 0)
            {
                _terminalFailure ??= exception;
            }
        }

        _terminalWriteCompletion.TrySetException(exception);
    }

    private bool TryTakeOutbound(out BrokerOutboundFrameV1 outbound)
    {
        lock (_gate)
        {
            if (_mandatoryResponses.Count > 0)
            {
                outbound = _mandatoryResponses.Dequeue();
                return true;
            }

            if (_subscribed)
            {
                var notification = _subscriptionQueue.Drain(1);
                if (notification.Count == 1)
                {
                    outbound = new BrokerOutboundFrameV1(
                        CodexCdpBrokerProtocol.SerializeNotification(notification[0]),
                        FullSnapshot: null,
                        AcknowledgeResync: false,
                        StopAfterWrite: false);
                    return true;
                }
            }

            _writerWakePending = false;
        }

        outbound = null!;
        return false;
    }

    private void QueueMandatory(
        BrokerOutboundFrameV1 outbound,
        bool terminalAfterWrite = false)
    {
        Exception? capacityFailure = null;
        lock (_gate)
        {
            if (Volatile.Read(ref _stopRequested) != 0)
            {
                throw new OperationCanceledException(
                    "The Broker control session stopped before response queueing.",
                    StoppedCancellationToken);
            }

            if (_mandatoryResponses.Count >= MaximumMandatoryResponses)
            {
                capacityFailure = Fail(
                    "control-response-capacity-exceeded",
                    "The bounded Broker response queue is full.");
                _terminalFailure ??= capacityFailure;
                _terminalResponsePending = true;
            }
            else
            {
                if (terminalAfterWrite)
                {
                    _terminalResponsePending = true;
                }

                _mandatoryResponses.Enqueue(outbound);
            }
        }

        if (capacityFailure is not null)
        {
            RequestStop();
            throw capacityFailure;
        }

        SignalWriter();
    }

    private void SignalWriter()
    {
        lock (_gate)
        {
            if (_writerWakePending || Volatile.Read(ref _resourcesDisposed) != 0)
            {
                return;
            }

            _writerWakePending = true;
        }

        try
        {
            _outboundSignal.Release();
        }
        catch (ObjectDisposedException)
        {
            lock (_gate)
            {
                _writerWakePending = false;
            }
        }
        catch (Exception exception)
        {
            lock (_gate)
            {
                _writerWakePending = false;
                _terminalFailure ??= exception;
            }

            RequestStop(signalWriter: false);
        }
    }

    private void RequestStop(bool signalWriter = true)
    {
        if (Interlocked.Exchange(ref _stopRequested, 1) != 0)
        {
            return;
        }

        try
        {
            _lifetimeCancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception exception)
        {
            lock (_gate)
            {
                _terminalFailure ??= exception;
            }
        }

        lock (_gate)
        {
            if (Volatile.Read(ref _helloPhase) != HelloConnected)
            {
                _helloPhase = HelloTerminal;
            }

            if (_terminalResponsePending)
            {
                _terminalWriteCompletion.TrySetCanceled(_lifetimeCancellation.Token);
            }
        }

        if (signalWriter)
        {
            SignalWriter();
        }
    }

    private bool IsTerminalResponsePending()
    {
        lock (_gate)
        {
            return _terminalResponsePending;
        }
    }

    private Exception? ReadTerminalFailure()
    {
        lock (_gate)
        {
            return _terminalFailure;
        }
    }

    private async Task<Exception?> CleanupAsync()
    {
        bool connected;
        lock (_gate)
        {
            if (_cleanupStarted != 0)
            {
                return null;
            }

            _cleanupStarted = 1;
            _helloPhase = HelloTerminal;
            connected = _connected != 0;
            _connected = 0;
        }

        Exception? failure = null;
        try
        {
            await _owner.DisconnectSessionAsync(
                    this,
                    connected)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        try
        {
            await _guardianConnection.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = BrokerControlFailureArbitration.CombineCleanupFailures(
                failure,
                exception);
        }

        return failure;
    }

    private async Task DisposeWithoutRunAsync()
    {
        Exception? failure = null;
        try
        {
            failure = await CleanupAsync().ConfigureAwait(false);
        }
        finally
        {
            DisposeResources();
        }

        if (failure is null)
        {
            _completion.TrySetResult();
            return;
        }

        _completion.TrySetException(failure);
        ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private async Task AwaitRunForDisposeAsync(Task runTask)
    {
        Exception? failure = null;
        try
        {
            await runTask.ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = exception;
        }
        finally
        {
            DisposeResources();
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private void DisposeResources()
    {
        if (Interlocked.Exchange(ref _resourcesDisposed, 1) != 0)
        {
            return;
        }

        _outboundSignal.Dispose();
        _lifetimeCancellation.Dispose();
    }

    private static async Task<Exception?> CaptureFailureAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static void ObserveFault(Task task) =>
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously |
                TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);

    private static Exception? SelectUnexpectedFailure(
        Exception? failure,
        bool expectedStop)
    {
        if (failure is null)
        {
            return null;
        }

        if (failure is OperationCanceledException cancellation)
        {
            return expectedStop && cancellation.CancellationToken.IsCancellationRequested
                ? null
                : failure;
        }

        if (!expectedStop)
        {
            return failure;
        }

        if (failure is BrokerPeerTrustException peerFailure &&
            peerFailure.Code is
                "peer-message-read-cancelled" or
                "peer-message-write-cancelled")
        {
            return null;
        }

        return failure;
    }

    private static BrokerControlSessionException Fail(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private sealed record BrokerOutboundFrameV1(
        string Json,
        CodexCdpBrokerSnapshot? FullSnapshot,
        bool AcknowledgeResync,
        bool StopAfterWrite);
}
