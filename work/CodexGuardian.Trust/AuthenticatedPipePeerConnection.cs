using System;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Trust;

internal interface INamedPipePeerMessageTransport
{
    // The same per-connection platform owns this transport. Platform disposal must
    // cancel active I/O and settle Completion without requiring a second owner.
    Task Completion { get; }

    ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
        int maximumMessageBytes,
        CancellationToken cancellationToken);

    ValueTask WriteMessageAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken);
}

public sealed class AuthenticatedPipePeerConnection : IAsyncDisposable
{
    internal const int AbsoluteMaximumMessageBytes = 256 * 1024 + sizeof(uint);

    private readonly object _sync = new();
    private readonly VerifiedPipePeerIdentity _identity;
    private readonly INamedPipePeerMessageTransport _transport;
    private readonly Task _transportCompletion;
    private readonly SemaphoreSlim _readGate = new(1, 1);
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly TaskCompletionSource _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _closeCompleted = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _operationsDrained = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private Exception? _cleanupFailure;
    private Exception? _terminalFailure;
    private Exception? _transportCompletionFailure;
    private Task? _disposeTask;
    private int _activeOperationCount;
    private bool _closeStarted;

    internal AuthenticatedPipePeerConnection(
        VerifiedPipePeerIdentity identity,
        INamedPipePeerMessageTransport transport,
        BrokerPeerRole peerRole)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _transportCompletion = transport.Completion ??
            throw new ArgumentException(
                "The named pipe message transport has no completion task.",
                nameof(transport));
        if (!Enum.IsDefined(peerRole))
        {
            throw new ArgumentOutOfRangeException(nameof(peerRole));
        }

        PeerRole = peerRole;
        InitialIdentity = identity.InitialIdentity;
        _ = ObserveTransportCompletionAsync();
    }

    public BrokerPeerRole PeerRole { get; }

    public WindowsProcessIdentity InitialIdentity { get; }

    public Task Completion => _completion.Task;

    public WindowsProcessIdentity Revalidate()
    {
        EnterOperation();
        try
        {
            return _identity.Revalidate();
        }
        catch (Exception exception)
        {
            ThrowIfAlreadyClosed();
            var failure = NormalizeFailure(
                exception,
                "peer-message-revalidation-failed",
                "The authenticated named pipe peer could not be revalidated.");
            Close(failure);
            throw Rethrow(failure);
        }
        finally
        {
            ExitOperation();
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
        int maximumMessageBytes,
        CancellationToken cancellationToken = default)
    {
        if (maximumMessageBytes is < 1 or > AbsoluteMaximumMessageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumMessageBytes));
        }

        EnterOperation();
        try
        {
            var gateHeld = false;
            var readStarted = false;
            using var operationCancellation = new CancellationTokenSource();
            using var callerForwarder = RegisterCancellationForwarder(
                cancellationToken,
                operationCancellation);
            using var lifetimeForwarder = RegisterCancellationForwarder(
                _lifetimeCancellation.Token,
                operationCancellation);
            try
            {
                await _readGate.WaitAsync(operationCancellation.Token).ConfigureAwait(false);
                gateHeld = true;
                operationCancellation.Token.ThrowIfCancellationRequested();
                readStarted = true;
                var message = await _transport.ReadMessageAsync(
                        maximumMessageBytes,
                        operationCancellation.Token)
                    .ConfigureAwait(false);
                operationCancellation.Token.ThrowIfCancellationRequested();
                if (message.Length == 0)
                {
                    throw new BrokerPeerTrustException(
                        "peer-message-eof",
                        "The authenticated named pipe peer closed without another message.");
                }

                if (message.Length > maximumMessageBytes)
                {
                    throw new BrokerPeerTrustException(
                        "peer-message-too-large",
                        "The authenticated named pipe peer exceeded the requested message bound.");
                }

                ThrowIfAlreadyClosed();
                return message.ToArray();
            }
            catch (Exception exception)
            {
                ThrowIfAlreadyClosed();
                if (!readStarted &&
                    exception is OperationCanceledException &&
                    cancellationToken.IsCancellationRequested)
                {
                    throw;
                }

                var failure = NormalizeReadFailure(exception);
                Close(failure);
                throw Rethrow(failure);
            }
            finally
            {
                if (gateHeld)
                {
                    _readGate.Release();
                }
            }
        }
        finally
        {
            ExitOperation();
        }
    }

    public async ValueTask WriteMessageAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        if (message.Length is < 1 or > AbsoluteMaximumMessageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(message));
        }

        EnterOperation();
        try
        {
            var stableMessage = message.ToArray();
            try
            {
                var gateHeld = false;
                var writeStarted = false;
                using var operationCancellation = new CancellationTokenSource();
                using var callerForwarder = RegisterCancellationForwarder(
                    cancellationToken,
                    operationCancellation);
                using var lifetimeForwarder = RegisterCancellationForwarder(
                    _lifetimeCancellation.Token,
                    operationCancellation);
                try
                {
                    await _writeGate.WaitAsync(operationCancellation.Token).ConfigureAwait(false);
                    gateHeld = true;
                    operationCancellation.Token.ThrowIfCancellationRequested();
                    writeStarted = true;
                    await _transport.WriteMessageAsync(
                            stableMessage,
                            operationCancellation.Token)
                        .ConfigureAwait(false);
                    operationCancellation.Token.ThrowIfCancellationRequested();
                    ThrowIfAlreadyClosed();
                }
                catch (Exception exception)
                {
                    ThrowIfAlreadyClosed();
                    if (!writeStarted &&
                        exception is OperationCanceledException &&
                        cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }

                    var failure = NormalizeWriteFailure(exception);
                    Close(failure);
                    throw Rethrow(failure);
                }
                finally
                {
                    if (gateHeld)
                    {
                        _writeGate.Release();
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stableMessage);
            }
        }
        finally
        {
            ExitOperation();
        }
    }

    public ValueTask DisposeAsync()
    {
        Close(terminalFailure: null);
        lock (_sync)
        {
            _disposeTask ??= FinishDisposeAsync();
            return new ValueTask(_disposeTask);
        }
    }

    private async Task ObserveTransportCompletionAsync()
    {
        Exception failure;
        try
        {
            await _transportCompletion.ConfigureAwait(false);
            failure = new BrokerPeerTrustException(
                "peer-message-eof",
                "The authenticated named pipe peer closed its message channel.");
        }
        catch (Exception exception)
        {
            failure = NormalizeFailure(
                exception,
                "peer-message-transport-failed",
                "The authenticated named pipe message transport failed.");
        }

        ReportTransportCompletion(failure);
    }

    private void ReportTransportCompletion(Exception failure)
    {
        lock (_sync)
        {
            if (_closeStarted)
            {
                return;
            }

            _transportCompletionFailure ??= failure;
        }

        // Completion is terminal even if a platform fails to wake active I/O itself.
        Close(failure);
    }

    private void EnterOperation()
    {
        Exception? transportFailure;
        lock (_sync)
        {
            if (_closeStarted)
            {
                transportFailure = null;
            }
            else if (_transportCompletionFailure is not null)
            {
                transportFailure = _transportCompletionFailure;
            }
            else
            {
                _activeOperationCount++;
                return;
            }
        }

        if (transportFailure is not null)
        {
            Close(transportFailure);
        }

        ThrowUnavailable();
    }

    private void ExitOperation()
    {
        Exception? transportFailure = null;
        lock (_sync)
        {
            if (_activeOperationCount <= 0)
            {
                Environment.FailFast(
                    "The authenticated named pipe operation count lost ownership.");
            }

            _activeOperationCount--;
            if (_activeOperationCount == 0)
            {
                if (_closeStarted)
                {
                    _operationsDrained.TrySetResult();
                }
                else if (_transportCompletionFailure is not null)
                {
                    transportFailure = _transportCompletionFailure;
                }
            }
        }

        if (transportFailure is not null)
        {
            Close(transportFailure);
        }
    }

    private void Close(Exception? terminalFailure)
    {
        lock (_sync)
        {
            if (_closeStarted)
            {
                return;
            }

            _closeStarted = true;
            _terminalFailure = terminalFailure;
            if (_activeOperationCount == 0)
            {
                _operationsDrained.TrySetResult();
            }
        }

        CancelNoThrow(_lifetimeCancellation);
        Exception? cleanupFailure = null;
        try
        {
            // VerifiedPipePeerIdentity closes the platform before retained identity handles.
            _identity.Dispose();
        }
        catch (Exception exception)
        {
            cleanupFailure = exception;
            if (terminalFailure is not null)
            {
                terminalFailure.Data["peer-connection-cleanup-failure"] = exception;
            }
        }

        lock (_sync)
        {
            _cleanupFailure = cleanupFailure;
        }

        var completionFailure = terminalFailure ?? cleanupFailure;
        if (completionFailure is null)
        {
            _completion.TrySetResult();
        }
        else
        {
            _completion.TrySetException(completionFailure);
        }

        _closeCompleted.TrySetResult();
    }

    private async Task FinishDisposeAsync()
    {
        await _closeCompleted.Task.ConfigureAwait(false);
        await _operationsDrained.Task.ConfigureAwait(false);
        _readGate.Dispose();
        _writeGate.Dispose();
        _lifetimeCancellation.Dispose();

        Exception? cleanupFailure;
        lock (_sync)
        {
            cleanupFailure = _cleanupFailure;
        }

        if (cleanupFailure is not null)
        {
            throw Rethrow(cleanupFailure);
        }
    }

    private void ThrowIfAlreadyClosed()
    {
        lock (_sync)
        {
            if (!_closeStarted)
            {
                return;
            }
        }

        ThrowUnavailable();
    }

    private void ThrowUnavailable()
    {
        Exception? failure;
        lock (_sync)
        {
            failure = _terminalFailure;
        }

        if (failure is not null)
        {
            throw Rethrow(failure);
        }

        throw new ObjectDisposedException(nameof(AuthenticatedPipePeerConnection));
    }

    private static Exception NormalizeReadFailure(Exception exception) =>
        exception switch
        {
            BrokerPeerTrustException => exception,
            EndOfStreamException => new BrokerPeerTrustException(
                "peer-message-eof",
                "The authenticated named pipe peer closed during a message read.",
                exception),
            OperationCanceledException => new BrokerPeerTrustException(
                "peer-message-read-cancelled",
                "The authenticated named pipe message read was cancelled after it started.",
                exception),
            _ => NormalizeFailure(
                exception,
                "peer-message-read-failed",
                "The authenticated named pipe message read failed.")
        };

    private static Exception NormalizeWriteFailure(Exception exception) =>
        exception switch
        {
            BrokerPeerTrustException => exception,
            OperationCanceledException => new BrokerPeerTrustException(
                "peer-message-write-cancelled",
                "The authenticated named pipe message write was cancelled after it started.",
                exception),
            _ => NormalizeFailure(
                exception,
                "peer-message-write-failed",
                "The authenticated named pipe message write failed.")
        };

    private static Exception NormalizeFailure(
        Exception exception,
        string code,
        string message) =>
        exception is BrokerPeerTrustException
            ? exception
            : new BrokerPeerTrustException(code, message, exception);

    private static CancellationTokenRegistration RegisterCancellationForwarder(
        CancellationToken source,
        CancellationTokenSource destination) =>
        source.CanBeCanceled
            ? source.UnsafeRegister(
                static state => CancelNoThrow((CancellationTokenSource)state!),
                destination)
            : default;

    private static void CancelNoThrow(CancellationTokenSource cancellation)
    {
        try
        {
            cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception)
        {
        }
    }

    private static Exception Rethrow(Exception failure)
    {
        ExceptionDispatchInfo.Capture(failure).Throw();
        return failure;
    }
}
