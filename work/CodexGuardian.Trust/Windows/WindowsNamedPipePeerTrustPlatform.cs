using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Trust;

public sealed class WindowsNamedPipePeerTrustPlatform :
    INamedPipePeerTrustPlatform,
    INamedPipePeerMessageTransport
{
    private readonly object _sync = new();
    private readonly WindowsRetainedReleaseArtifacts _retainedRelease;
    private readonly CancellationTokenSource _nativeReadStop = new();
    private readonly CancellationToken _nativeReadStopToken;
    private readonly TaskCompletionSource _transportCompletion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private WindowsSameLogonNamedPipeClient? _client;
    private SafeProcessHandle? _exactLaunchHandle;
    private Exception? _disposeFailure;
    private long _readGeneration;
    private int _readStarted;
    private int _readStopRequested;
    private int _leaseOpened;
    private bool _disposeStarted;

    private WindowsNamedPipePeerTrustPlatform(
        WindowsSameLogonNamedPipeClient client,
        SafeProcessHandle exactLaunchHandle,
        WindowsRetainedReleaseArtifacts retainedRelease)
    {
        _client = client;
        _exactLaunchHandle = exactLaunchHandle;
        _retainedRelease = retainedRelease;
        _nativeReadStopToken = _nativeReadStop.Token;
    }

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public long ReadGeneration => Volatile.Read(ref _readGeneration);

    public static WindowsNamedPipePeerTrustPlatform ConnectToLaunchedServer(
        string endpointName,
        SafeProcessHandle exactLaunchHandle,
        WindowsRetainedReleaseArtifacts retainedRelease,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(exactLaunchHandle);
        ArgumentNullException.ThrowIfNull(retainedRelease);
        if (retainedRelease.Role != BrokerPeerRole.Broker)
        {
            throw new ArgumentException(
                "A server peer platform requires retained Broker release artifacts.",
                nameof(retainedRelease));
        }

        var retainedProcess = WindowsPeerNative.DuplicateRestrictedProcessHandle(exactLaunchHandle);
        WindowsSameLogonNamedPipeClient? client = null;
        try
        {
            retainedRelease.ValidateProcessImageMapping(retainedProcess);
            client = WindowsSameLogonNamedPipeClient.Connect(
                endpointName,
                timeout,
                cancellationToken);
            return new WindowsNamedPipePeerTrustPlatform(
                client,
                retainedProcess,
                retainedRelease);
        }
        catch
        {
            client?.Dispose();
            retainedProcess.Dispose();
            throw;
        }
    }

    public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
    {
        if (peerKind != NamedPipePeerKind.Server)
        {
            throw new BrokerPeerTrustException(
                "peer-platform-direction-unsupported",
                "This native probe platform only verifies the connected Broker server.");
        }

        var client = GetClient();
        if (!GetNamedPipeServerProcessId(client.SafePipeHandle, out var processId) || processId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the native broker server process id.");
        }

        if (!GetNamedPipeServerSessionId(client.SafePipeHandle, out var sessionId) || sessionId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the native broker server session id.");
        }

        return new PipePeerKernelIdentity(processId, sessionId);
    }

    public IRetainedPeerIdentityLease OpenRetainedPeer(
        uint processId,
        VerifiedReleaseArtifactSet release)
    {
        ArgumentNullException.ThrowIfNull(release);
        if (Interlocked.Exchange(ref _leaseOpened, 1) != 0)
        {
            throw new BrokerPeerTrustException(
                "peer-retained-handles-invalid",
                "The native peer identity lease was already opened.");
        }

        SafeProcessHandle? process = null;
        WindowsRetainedReleaseHandleLease? releaseHandles = null;
        try
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposeStarted, this);
                var exact = _exactLaunchHandle ?? throw new ObjectDisposedException(
                    nameof(WindowsNamedPipePeerTrustPlatform));
                if (WindowsPeerNative.ReadProcessId(exact) != processId)
                {
                    throw new BrokerPeerTrustException(
                        "peer-kernel-identity-mismatch",
                        "The pipe server is not the exact process object returned by launch.");
                }

                process = WindowsPeerNative.DuplicateRestrictedProcessHandle(exact);
                releaseHandles = _retainedRelease.DuplicateFor(release);
            }

            var lease = new WindowsRetainedPeerIdentityLease(process, releaseHandles, release);
            process = null;
            releaseHandles = null;
            return lease;
        }
        finally
        {
            releaseHandles?.Dispose();
            process?.Dispose();
        }
    }

    public async ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
        NamedPipePeerKind peerKind,
        int maximumHelloBytes,
        CancellationToken cancellationToken)
    {
        if (peerKind != NamedPipePeerKind.Server)
        {
            throw new BrokerPeerTrustException(
                "peer-platform-direction-unsupported",
                "This native probe platform only reads a Broker server hello.");
        }

        if (maximumHelloBytes is < 2 or > BrokerPeerHelloProtocol.MaximumHelloBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumHelloBytes));
        }

        if (Interlocked.Exchange(ref _readStarted, 1) != 0)
        {
            throw new BrokerPeerTrustException(
                "peer-hello-read-order-invalid",
                "The native broker hello read was already started.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var client = GetClient();
        var kernelBefore = CaptureKernelPeer(peerKind);
        var buffer = new byte[maximumHelloBytes + 1];
        var total = 0;
        try
        {
            using var cancellationRegistration = cancellationToken.UnsafeRegister(
                static state => ((WindowsNamedPipePeerTrustPlatform)state!).RequestReadStopNoThrow(),
                this);
            while (true)
            {
                ThrowIfReadStopped(cancellationToken);
                int read;
                try
                {
                    read = await client.Stream.ReadAsync(
                            buffer.AsMemory(total, buffer.Length - total),
                            _nativeReadStopToken)
                        .ConfigureAwait(false);
                }
                catch (Exception exception) when (
                    IsReadStopped(cancellationToken) &&
                    exception is IOException or OperationCanceledException)
                {
                    ThrowIfReadStopped(cancellationToken, exception);
                    throw;
                }

                // Cancellation can race a successful native completion. Late bytes must
                // never advance framing state or become peer evidence.
                ThrowIfReadStopped(cancellationToken);
                if (read == 0)
                {
                    throw new EndOfStreamException(
                        "The broker disconnected before completing its hello message.");
                }

                total = checked(total + read);
                if (total > maximumHelloBytes)
                {
                    throw new BrokerPeerTrustException(
                        "peer-hello-too-large",
                        "The native broker hello exceeded its bounded size.");
                }

                if (client.Stream.IsMessageComplete)
                {
                    break;
                }

                if (total == buffer.Length)
                {
                    throw new BrokerPeerTrustException(
                        "peer-hello-too-large",
                        "The native broker hello exceeded its bounded message frame.");
                }
            }

            ThrowIfReadStopped(cancellationToken);
            if (client.PeekAvailableBytes() != 0)
            {
                throw new BrokerPeerTrustException(
                    "peer-hello-read-order-invalid",
                    "The broker queued a second frame before hello verification completed.");
            }

            ThrowIfReadStopped(cancellationToken);
            var kernelAfter = CaptureKernelPeer(peerKind);
            ThrowIfReadStopped(cancellationToken);
            var generation = Interlocked.Increment(ref _readGeneration);
            return new PipePeerHelloReadEvidence(
                buffer.AsSpan(0, total),
                generation,
                kernelBefore,
                kernelAfter,
                impersonatedClientToken: null);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public void AbortHandshake(string boundedFailureCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(boundedFailureCode);
        RequestReadStopNoThrow();
        GetClient().CancelIoOrThrow();
    }

    Task INamedPipePeerMessageTransport.Completion => _transportCompletion.Task;

    ValueTask<ReadOnlyMemory<byte>> INamedPipePeerMessageTransport.ReadMessageAsync(
        int maximumMessageBytes,
        CancellationToken cancellationToken) =>
        ReadTransportMessageAsync(maximumMessageBytes, cancellationToken);

    ValueTask INamedPipePeerMessageTransport.WriteMessageAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken) =>
        WriteTransportMessageAsync(message, cancellationToken);

    public void Dispose()
    {
        RequestReadStopNoThrow();
        lock (_sync)
        {
            if (_disposeStarted)
            {
                if (_disposeFailure is not null)
                {
                    throw _disposeFailure;
                }

                return;
            }

            _disposeStarted = true;
            Exception? cleanupFailure = null;
            try
            {
                _client?.Dispose();
                _client = null;
            }
            catch (Exception exception)
            {
                cleanupFailure = exception;
            }

            try
            {
                _exactLaunchHandle?.Dispose();
                _exactLaunchHandle = null;
            }
            catch (Exception exception)
            {
                cleanupFailure = cleanupFailure is null
                    ? exception
                    : new AggregateException(cleanupFailure, exception);
            }

            try
            {
                _nativeReadStop.Dispose();
            }
            catch (Exception exception)
            {
                cleanupFailure = cleanupFailure is null
                    ? exception
                    : new AggregateException(cleanupFailure, exception);
            }

            _disposeFailure = cleanupFailure;
            if (cleanupFailure is null)
            {
                _transportCompletion.TrySetResult();
            }
            else
            {
                _transportCompletion.TrySetException(cleanupFailure);
                throw cleanupFailure;
            }
        }
    }

    private async ValueTask<ReadOnlyMemory<byte>> ReadTransportMessageAsync(
        int maximumMessageBytes,
        CancellationToken cancellationToken)
    {
        EnsureTransportAuthenticated();
        try
        {
            var client = GetClient();
            var message = await WindowsNamedPipeMessageIO.ReadMessageAsync(
                    client.Stream,
                    maximumMessageBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            if (message.IsEmpty)
            {
                CompleteTransport(null);
            }

            return message;
        }
        catch (Exception exception)
        {
            CompleteTransport(exception);
            throw;
        }
    }

    private async ValueTask WriteTransportMessageAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        EnsureTransportAuthenticated();
        try
        {
            var client = GetClient();
            await WindowsNamedPipeMessageIO.WriteMessageAsync(
                    client.Stream,
                    message,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            CompleteTransport(exception);
            throw;
        }
    }

    private void EnsureTransportAuthenticated()
    {
        if (Volatile.Read(ref _readGeneration) != 1)
        {
            throw new BrokerPeerTrustException(
                "peer-message-before-authentication",
                "The native pipe message channel is unavailable before peer authentication.");
        }
    }

    private void CompleteTransport(Exception? failure)
    {
        if (failure is null)
        {
            _transportCompletion.TrySetResult();
        }
        else
        {
            _transportCompletion.TrySetException(failure);
        }
    }

    private bool IsReadStopped(CancellationToken callerToken) =>
        callerToken.IsCancellationRequested ||
        Volatile.Read(ref _readStopRequested) != 0 ||
        _nativeReadStopToken.IsCancellationRequested;

    private void ThrowIfReadStopped(
        CancellationToken callerToken,
        Exception? innerException = null)
    {
        if (callerToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(
                "The bounded broker hello read was cancelled.",
                innerException,
                callerToken);
        }

        if (Volatile.Read(ref _readStopRequested) != 0 ||
            _nativeReadStopToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(
                "The native broker hello read was stopped.",
                innerException,
                _nativeReadStopToken);
        }
    }

    private void RequestReadStopNoThrow()
    {
        Interlocked.Exchange(ref _readStopRequested, 1);
        try
        {
            _nativeReadStop.Cancel();
        }
        catch
        {
        }

        try
        {
            Volatile.Read(ref _client)?.CancelIoNoThrow();
        }
        catch
        {
        }
    }

    private WindowsSameLogonNamedPipeClient GetClient()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            return _client ?? throw new ObjectDisposedException(
                nameof(WindowsNamedPipePeerTrustPlatform));
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe,
        out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerSessionId(
        SafePipeHandle pipe,
        out uint serverSessionId);
}
