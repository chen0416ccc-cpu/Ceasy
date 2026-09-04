using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Trust;

public sealed class WindowsConnectedClientPeerTrustPlatform :
    INamedPipePeerTrustPlatform,
    INamedPipePeerMessageTransport
{
    private const int BrokerHelloWriteNotStarted = 0;
    private const int BrokerHelloWriteInProgress = 1;
    private const int BrokerHelloWriteCompleted = 2;
    private const int BrokerHelloWriteFailed = 3;

    private readonly object _sync = new();
    private readonly WindowsRetainedReleaseArtifacts _retainedRelease;
    private readonly CancellationTokenSource _nativeReadStop = new();
    private readonly CancellationToken _nativeReadStopToken;
    private readonly bool _requiresBrokerHello;
    private readonly TaskCompletionSource _transportCompletion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private WindowsSameLogonNamedPipeServer? _server;
    private SafeProcessHandle? _exactClientHandle;
    private Exception? _brokerHelloFailure;
    private Exception? _disposeFailure;
    private long _readGeneration;
    private int _brokerHelloWriteState;
    private int _readStarted;
    private int _readStopRequested;
    private int _leaseOpened;
    private bool _disposeStarted;

    private WindowsConnectedClientPeerTrustPlatform(
        WindowsSameLogonNamedPipeServer server,
        SafeProcessHandle exactClientHandle,
        WindowsRetainedReleaseArtifacts retainedRelease,
        bool requiresBrokerHello)
    {
        _server = server;
        _exactClientHandle = exactClientHandle;
        _retainedRelease = retainedRelease;
        _requiresBrokerHello = requiresBrokerHello;
        _nativeReadStopToken = _nativeReadStop.Token;
    }

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public long ReadGeneration => Volatile.Read(ref _readGeneration);

    public static WindowsConnectedClientPeerTrustPlatform TakeConnectedClient(
        WindowsSameLogonNamedPipeServer connectedServer,
        SafeProcessHandle exactClientHandle,
        WindowsRetainedReleaseArtifacts retainedRelease) =>
        TakeConnectedClientCore(
            connectedServer,
            exactClientHandle,
            retainedRelease,
            requiresBrokerHello: false);

    public static WindowsConnectedClientPeerTrustPlatform
        TakeConnectedClientForBrokerFirstHandshake(
            WindowsSameLogonNamedPipeServer connectedServer,
            SafeProcessHandle exactClientHandle,
            WindowsRetainedReleaseArtifacts retainedRelease) =>
        TakeConnectedClientCore(
            connectedServer,
            exactClientHandle,
            retainedRelease,
            requiresBrokerHello: true);

    private static WindowsConnectedClientPeerTrustPlatform TakeConnectedClientCore(
        WindowsSameLogonNamedPipeServer connectedServer,
        SafeProcessHandle exactClientHandle,
        WindowsRetainedReleaseArtifacts retainedRelease,
        bool requiresBrokerHello)
    {
        ArgumentNullException.ThrowIfNull(connectedServer);
        ArgumentNullException.ThrowIfNull(exactClientHandle);
        ArgumentNullException.ThrowIfNull(retainedRelease);
        if (retainedRelease.Role != BrokerPeerRole.Guardian)
        {
            throw new ArgumentException(
                "A connected client peer platform requires retained Guardian release artifacts.",
                nameof(retainedRelease));
        }

        if (!connectedServer.IsConnected)
        {
            throw new InvalidOperationException(
                "The native named pipe server is not connected to a client.");
        }

        var ownedServer = connectedServer.TransferOwnership();
        SafeProcessHandle? retainedProcess = null;
        var ownershipCommitted = false;
        try
        {
            retainedProcess = WindowsPeerNative.DuplicateRestrictedProcessHandle(
                exactClientHandle);
            retainedRelease.ValidateProcessImageMapping(retainedProcess);
            var kernel = ReadClientKernelIdentity(ownedServer.SafePipeHandle);
            ValidateExactClientBinding(retainedProcess, kernel);
            var platform = new WindowsConnectedClientPeerTrustPlatform(
                ownedServer,
                retainedProcess,
                retainedRelease,
                requiresBrokerHello);
            retainedProcess = null;
            ownershipCommitted = true;
            return platform;
        }
        finally
        {
            retainedProcess?.Dispose();
            if (!ownershipCommitted)
            {
                ownedServer.Dispose();
            }
        }
    }

    public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
    {
        if (peerKind != NamedPipePeerKind.Client)
        {
            throw new BrokerPeerTrustException(
                "peer-platform-direction-unsupported",
                "This native connected-server platform only verifies the connected Guardian client.");
        }

        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            var server = _server ?? throw new ObjectDisposedException(
                nameof(WindowsConnectedClientPeerTrustPlatform));
            var exact = _exactClientHandle ?? throw new ObjectDisposedException(
                nameof(WindowsConnectedClientPeerTrustPlatform));
            var kernel = ReadClientKernelIdentity(server.SafePipeHandle);
            ValidateExactClientBinding(exact, kernel);
            return kernel;
        }
    }

    public async ValueTask WriteBrokerHelloBeforePeerAuthenticationAsync(
        BrokerPeerHello hello,
        CancellationToken cancellationToken = default)
    {
        byte[]? canonicalHello = null;
        try
        {
            BeginBrokerHelloWrite();
            ArgumentNullException.ThrowIfNull(hello);
            if (hello.Role != BrokerPeerRole.Broker)
            {
                throw new BrokerPeerTrustException(
                    "peer-broker-hello-role-invalid",
                    "The connected-client platform can only send a Broker-role hello.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            canonicalHello = BrokerPeerHelloProtocol.Serialize(hello);
            cancellationToken.ThrowIfCancellationRequested();

            WindowsSameLogonNamedPipeServer server;
            SafeProcessHandle exactClientHandle;
            PipePeerKernelIdentity kernelBefore;
            lock (_sync)
            {
                EnsureBrokerHelloWriteInProgress();
                server = _server ?? throw new ObjectDisposedException(
                    nameof(WindowsConnectedClientPeerTrustPlatform));
                exactClientHandle = _exactClientHandle ?? throw new ObjectDisposedException(
                    nameof(WindowsConnectedClientPeerTrustPlatform));
                EnsureNoQueuedClientFrameBeforeBrokerHello(server);
                kernelBefore = ReadClientKernelIdentity(server.SafePipeHandle);
                ValidateExactClientBinding(exactClientHandle, kernelBefore);
            }

            await WindowsNamedPipeMessageIO.WriteMessageAsync(
                    server.Stream,
                    canonicalHello,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            lock (_sync)
            {
                EnsureBrokerHelloWriteInProgress();
                if (!ReferenceEquals(_server, server) ||
                    !ReferenceEquals(_exactClientHandle, exactClientHandle))
                {
                    throw new BrokerPeerTrustException(
                        "peer-kernel-identity-changed",
                        "The exact Guardian client authority changed during the Broker hello write.");
                }

                var kernelAfter = ReadClientKernelIdentity(server.SafePipeHandle);
                ValidateExactClientBinding(exactClientHandle, kernelAfter);
                RequireStableKernelClient(kernelBefore, kernelAfter);
                _brokerHelloWriteState = BrokerHelloWriteCompleted;
            }
        }
        catch (Exception exception)
        {
            PoisonHandshake(exception);
            throw;
        }
        finally
        {
            if (canonicalHello is not null)
            {
                CryptographicOperations.ZeroMemory(canonicalHello);
            }
        }
    }

    public IRetainedPeerIdentityLease OpenRetainedPeer(
        uint processId,
        VerifiedReleaseArtifactSet release)
    {
        ArgumentNullException.ThrowIfNull(release);
        SafeProcessHandle? process = null;
        WindowsRetainedReleaseHandleLease? releaseHandles = null;
        BrokerPeerTrustException? concurrentWriteFailure = null;
        try
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposeStarted, this);
                if (_leaseOpened != 0)
                {
                    throw new BrokerPeerTrustException(
                        "peer-retained-handles-invalid",
                        "The native peer identity lease was already opened.");
                }

                _leaseOpened = 1;
                if (_brokerHelloWriteState == BrokerHelloWriteInProgress)
                {
                    concurrentWriteFailure = new BrokerPeerTrustException(
                        "peer-broker-hello-write-order-invalid",
                        "The retained Guardian identity lease raced the Broker hello write.");
                }
                else
                {
                    ThrowIfHandshakePoisoned();
                    RequireBrokerHelloWhenConfigured();
                    var exact = _exactClientHandle ?? throw new ObjectDisposedException(
                        nameof(WindowsConnectedClientPeerTrustPlatform));
                    if (WindowsPeerNative.ReadProcessId(exact) != processId)
                    {
                        throw new BrokerPeerTrustException(
                            "peer-kernel-identity-mismatch",
                            "The pipe client is not the exact process object captured at launch.");
                    }

                    process = WindowsPeerNative.DuplicateRestrictedProcessHandle(exact);
                    releaseHandles = _retainedRelease.DuplicateFor(release);
                }
            }

            if (concurrentWriteFailure is not null)
            {
                PoisonHandshake(concurrentWriteFailure);
                throw concurrentWriteFailure;
            }

            var ownedProcess = process ?? throw new InvalidOperationException(
                "The exact Guardian process handle was not retained for the peer lease.");
            var ownedReleaseHandles = releaseHandles ?? throw new InvalidOperationException(
                "The exact Guardian release handles were not retained for the peer lease.");
            var lease = new WindowsRetainedPeerIdentityLease(
                ownedProcess,
                ownedReleaseHandles,
                release);
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
        if (peerKind != NamedPipePeerKind.Client)
        {
            throw new BrokerPeerTrustException(
                "peer-platform-direction-unsupported",
                "This native connected-server platform only reads a Guardian client hello.");
        }

        if (maximumHelloBytes is < 2 or > BrokerPeerHelloProtocol.MaximumHelloBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumHelloBytes));
        }

        BrokerPeerTrustException? concurrentWriteFailure = null;
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            if (_readStarted != 0)
            {
                throw new BrokerPeerTrustException(
                    "peer-hello-read-order-invalid",
                    "The native Guardian hello read was already started.");
            }

            _readStarted = 1;
            if (_brokerHelloWriteState == BrokerHelloWriteInProgress)
            {
                concurrentWriteFailure = new BrokerPeerTrustException(
                    "peer-broker-hello-write-order-invalid",
                    "The Guardian hello read raced the Broker hello write.");
            }
            else
            {
                ThrowIfHandshakePoisoned();
                RequireBrokerHelloWhenConfigured();
            }
        }

        if (concurrentWriteFailure is not null)
        {
            PoisonHandshake(concurrentWriteFailure);
            throw concurrentWriteFailure;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var server = GetServer();
        var kernelBefore = CaptureKernelPeer(peerKind);
        var buffer = new byte[maximumHelloBytes + 1];
        var total = 0;
        try
        {
            using var cancellationRegistration = cancellationToken.UnsafeRegister(
                static state => ((WindowsConnectedClientPeerTrustPlatform)state!).RequestReadStopNoThrow(),
                this);
            while (true)
            {
                ThrowIfReadStopped(cancellationToken);
                int read;
                try
                {
                    read = await server.Stream.ReadAsync(
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

                // A cancellation racing a completed native read must not turn late bytes
                // into authenticated peer evidence.
                ThrowIfReadStopped(cancellationToken);
                if (read == 0)
                {
                    throw new EndOfStreamException(
                        "The Guardian client disconnected before completing its hello message.");
                }

                total = checked(total + read);
                if (total > maximumHelloBytes)
                {
                    throw new BrokerPeerTrustException(
                        "peer-hello-too-large",
                        "The Guardian client hello exceeded its bounded size.");
                }

                if (server.Stream.IsMessageComplete)
                {
                    break;
                }

                if (total == buffer.Length)
                {
                    throw new BrokerPeerTrustException(
                        "peer-hello-too-large",
                        "The Guardian client hello exceeded its bounded message frame.");
                }
            }

            ThrowIfReadStopped(cancellationToken);
            EnsureNoQueuedPreAuthenticationFrame(server);
            ThrowIfReadStopped(cancellationToken);

            // This block is intentionally synchronous: impersonation, token capture, and
            // RevertToSelf must occur on one thread without an await in between.
            var impersonatedClientToken = CaptureImpersonatedClientToken(
                server.SafePipeHandle);
            ThrowIfReadStopped(cancellationToken);
            var kernelAfter = CaptureKernelPeer(peerKind);
            ThrowIfReadStopped(cancellationToken);
            EnsureNoQueuedPreAuthenticationFrame(server);
            ThrowIfReadStopped(cancellationToken);

            var generation = Interlocked.Increment(ref _readGeneration);
            return new PipePeerHelloReadEvidence(
                buffer.AsSpan(0, total),
                generation,
                kernelBefore,
                kernelAfter,
                impersonatedClientToken);
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
        GetServer().CancelIoOrThrow();
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
        WindowsSameLogonNamedPipeServer? server;
        SafeProcessHandle? exact;
        lock (_sync)
        {
            if (_disposeStarted)
            {
                if (_disposeFailure is not null)
                {
                    ExceptionDispatchInfo.Capture(_disposeFailure).Throw();
                }

                return;
            }

            _disposeStarted = true;
            server = _server;
            exact = _exactClientHandle;
            _server = null;
            _exactClientHandle = null;
        }

        Exception? cleanupFailure = null;
        try
        {
            // The pipe is closed first so no I/O can continue using the exact process
            // capability after the transport has been torn down.
            server?.Dispose();
        }
        catch (Exception exception)
        {
            cleanupFailure = exception;
        }

        try
        {
            exact?.Dispose();
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

        lock (_sync)
        {
            _disposeFailure = cleanupFailure;
        }

        if (cleanupFailure is null)
        {
            _transportCompletion.TrySetResult();
            return;
        }

        _transportCompletion.TrySetException(cleanupFailure);
        throw cleanupFailure;
    }

    private async ValueTask<ReadOnlyMemory<byte>> ReadTransportMessageAsync(
        int maximumMessageBytes,
        CancellationToken cancellationToken)
    {
        EnsureTransportAuthenticated();
        try
        {
            var server = GetServer();
            var message = await WindowsNamedPipeMessageIO.ReadMessageAsync(
                    server.Stream,
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
            var server = GetServer();
            await WindowsNamedPipeMessageIO.WriteMessageAsync(
                    server.Stream,
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
        if (Volatile.Read(ref _readGeneration) != 1 ||
            Volatile.Read(ref _brokerHelloWriteState) == BrokerHelloWriteInProgress ||
            Volatile.Read(ref _brokerHelloWriteState) == BrokerHelloWriteFailed ||
            (_requiresBrokerHello &&
             Volatile.Read(ref _brokerHelloWriteState) != BrokerHelloWriteCompleted))
        {
            throw new BrokerPeerTrustException(
                "peer-message-before-authentication",
                "The native pipe message channel is unavailable before peer authentication.");
        }
    }

    private void BeginBrokerHelloWrite()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            if (_brokerHelloWriteState != BrokerHelloWriteNotStarted ||
                _readStarted != 0 ||
                _readGeneration != 0 ||
                _leaseOpened != 0)
            {
                var priorFailure = _brokerHelloFailure;
                throw priorFailure is null
                    ? new BrokerPeerTrustException(
                        "peer-broker-hello-write-order-invalid",
                        "The Broker hello must be written exactly once before any Guardian read or retained peer lease.")
                    : new BrokerPeerTrustException(
                        "peer-broker-hello-write-order-invalid",
                        "The Broker hello must be written exactly once before any Guardian read or retained peer lease.",
                        priorFailure);
            }

            _brokerHelloWriteState = BrokerHelloWriteInProgress;
        }
    }

    private void EnsureBrokerHelloWriteInProgress()
    {
        ObjectDisposedException.ThrowIf(_disposeStarted, this);
        if (_brokerHelloWriteState != BrokerHelloWriteInProgress)
        {
            var priorFailure = _brokerHelloFailure;
            throw priorFailure is null
                ? new BrokerPeerTrustException(
                    "peer-broker-hello-write-order-invalid",
                    "The Broker hello write no longer owns the pre-authentication pipe state.")
                : new BrokerPeerTrustException(
                    "peer-broker-hello-write-order-invalid",
                    "The Broker hello write no longer owns the pre-authentication pipe state.",
                    priorFailure);
        }
    }

    private void ThrowIfHandshakePoisoned()
    {
        if (_brokerHelloWriteState == BrokerHelloWriteFailed)
        {
            var priorFailure = _brokerHelloFailure ?? new InvalidOperationException(
                "The Broker hello failure state lost its terminal exception.");
            throw new BrokerPeerTrustException(
                "peer-handshake-unusable",
                "The connected-client handshake was permanently invalidated by a prior Broker hello failure.",
                priorFailure);
        }
    }

    private void RequireBrokerHelloWhenConfigured()
    {
        if (_requiresBrokerHello &&
            _brokerHelloWriteState != BrokerHelloWriteCompleted)
        {
            throw new BrokerPeerTrustException(
                "peer-broker-hello-required",
                "This production connected-client platform requires the exact-bound Broker hello before Guardian authentication.");
        }
    }

    private void PoisonHandshake(Exception failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        Exception terminalFailure;
        lock (_sync)
        {
            terminalFailure = _brokerHelloFailure ?? failure;
            _brokerHelloFailure = terminalFailure;
            _brokerHelloWriteState = BrokerHelloWriteFailed;
        }

        RequestReadStopNoThrow();
        CompleteTransport(terminalFailure);
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

    private WindowsSameLogonNamedPipeServer GetServer()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            return _server ?? throw new ObjectDisposedException(
                nameof(WindowsConnectedClientPeerTrustPlatform));
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
                "The bounded Guardian hello read was cancelled.",
                innerException,
                callerToken);
        }

        if (Volatile.Read(ref _readStopRequested) != 0 ||
            _nativeReadStopToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(
                "The native Guardian hello read was stopped.",
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
            Volatile.Read(ref _server)?.CancelIoNoThrow();
        }
        catch
        {
        }
    }

    private static void EnsureNoQueuedPreAuthenticationFrame(
        WindowsSameLogonNamedPipeServer server)
    {
        if (server.PeekAvailableBytes() != 0)
        {
            throw new BrokerPeerTrustException(
                "peer-hello-read-order-invalid",
                "The Guardian client queued a second frame before hello verification completed.");
        }
    }

    private static void EnsureNoQueuedClientFrameBeforeBrokerHello(
        WindowsSameLogonNamedPipeServer server)
    {
        if (server.PeekAvailableBytes() != 0)
        {
            throw new BrokerPeerTrustException(
                "peer-broker-hello-client-spoke-first",
                "The Guardian client sent data before the Broker hello first frame.");
        }
    }

    private static PipePeerKernelIdentity ReadClientKernelIdentity(
        SafePipeHandle pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe, out var processId) || processId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the native Guardian client process id.");
        }

        if (!GetNamedPipeClientSessionId(pipe, out var sessionId) || sessionId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the native Guardian client session id.");
        }

        return new PipePeerKernelIdentity(processId, sessionId);
    }

    private static void ValidateExactClientBinding(
        SafeProcessHandle exactClientHandle,
        PipePeerKernelIdentity kernelIdentity)
    {
        var exactProcessId = WindowsPeerNative.ReadProcessId(exactClientHandle);
        if (exactProcessId == 0 || exactProcessId != kernelIdentity.ProcessId)
        {
            throw new BrokerPeerTrustException(
                "peer-kernel-identity-mismatch",
                "The named pipe client is not the exact process object captured at launch.");
        }

        var exactSessionId = WindowsPeerNative.ReadProcessSessionId(exactProcessId);
        if (exactSessionId == 0 || exactSessionId != kernelIdentity.SessionId)
        {
            throw new BrokerPeerTrustException(
                "peer-kernel-identity-mismatch",
                "The named pipe client session does not match the exact process handle.");
        }
    }

    private static void RequireStableKernelClient(
        PipePeerKernelIdentity before,
        PipePeerKernelIdentity after)
    {
        if (before != after)
        {
            throw new BrokerPeerTrustException(
                "peer-kernel-identity-changed",
                "The named pipe Guardian client identity changed during the Broker hello write.");
        }
    }

    private static WindowsTokenIdentity CaptureImpersonatedClientToken(
        SafePipeHandle pipe)
    {
        if (!ImpersonateNamedPipeClient(pipe))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to impersonate the connected Guardian client for hello verification.");
        }

        WindowsTokenIdentity? identity = null;
        Exception? captureFailure = null;
        try
        {
            if (!OpenThreadToken(
                    GetCurrentThread(),
                    WindowsPeerNative.TokenQuery,
                    openAsSelf: true,
                    out var token))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to open the impersonated Guardian token for query.");
            }

            using (token)
            {
                identity = WindowsPeerNative.ReadTokenIdentity(token);
            }
        }
        catch (Exception exception)
        {
            captureFailure = exception;
        }

        if (!RevertToSelf())
        {
            var revertFailure = new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to revert the hello-verification thread from Guardian impersonation.");
            Exception terminalFailure = captureFailure is null
                ? revertFailure
                : new AggregateException(captureFailure, revertFailure);
            Environment.FailFast(
                "The hello-verification thread could not revert Guardian impersonation.",
                terminalFailure);
        }

        if (captureFailure is not null)
        {
            ExceptionDispatchInfo.Capture(captureFailure).Throw();
        }

        return identity ?? throw new InvalidOperationException(
            "The impersonated Guardian token capture returned no identity.");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientSessionId(
        SafePipeHandle pipe,
        out uint clientSessionId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateNamedPipeClient(SafePipeHandle pipe);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(
        IntPtr threadHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool openAsSelf,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();
}
