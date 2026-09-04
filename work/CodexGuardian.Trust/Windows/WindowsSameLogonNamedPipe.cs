using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Trust;

public sealed record WindowsNamedPipeSecuritySnapshot(
    string OwnerSid,
    string AllowedLogonSid,
    bool DaclProtected,
    int AccessControlEntryCount,
    uint ClientAccessMask,
    uint OwnerRightsDenyMask,
    uint OpenMode,
    uint PipeMode);

public sealed class WindowsSameLogonNamedPipeServer : IDisposable
{
    private const int OwnershipStateActive = 0;
    private const int OwnershipStateDisposed = 1;
    private const int OwnershipStateTransferred = 2;

    public const uint ExpectedOpenMode =
        PipeAccessDuplex | WindowsPeerNative.FileFlagOverlapped | FileFlagFirstPipeInstance;
    public const uint ExpectedPipeMode =
        PipeTypeMessage | PipeReadModeMessage | PipeWait | PipeRejectRemoteClients;
    public const uint ExpectedClientAccessMask = 0x0012019F;
    public const uint ExpectedOwnerRightsDenyMask = 0x000C0000;

    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint PipeTypeMessage = 0x00000004;
    private const uint PipeReadModeMessage = 0x00000002;
    private const uint PipeWait = 0x00000000;
    private const uint PipeRejectRemoteClients = 0x00000008;
    private const uint SecurityDescriptorRevision = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint SeKernelObject = 6;
    private const int PipeBufferBytes = 4096;
    private const int MaximumTransportMessageBytes = 64 * 1024;
    private const string OwnerRightsSid = "S-1-3-4";

    private readonly object _ownershipSync = new();
    private readonly NamedPipeServerStream _stream;
    private int _ownershipState;

    private WindowsSameLogonNamedPipeServer(
        string endpointName,
        NamedPipeServerStream stream,
        WindowsNamedPipeSecuritySnapshot security)
    {
        EndpointName = endpointName;
        _stream = stream;
        Security = security;
    }

    public string EndpointName { get; }

    public WindowsNamedPipeSecuritySnapshot Security { get; }

    public static WindowsSameLogonNamedPipeServer Create(string endpointName) =>
        CreateCore(endpointName, allowedLogonSid: null);

    private static WindowsSameLogonNamedPipeServer CreateCore(
        string endpointName,
        string? allowedLogonSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Native named pipes require Windows.");
        }

        ValidateEndpointName(endpointName);
        var token = WindowsPeerNative.ReadCurrentPrimaryToken();
        ValidateServerToken(token);
        var allowedSid = allowedLogonSid is null
            ? token.LogonSid
            : new SecurityIdentifier(allowedLogonSid).Value;
        if (!allowedSid.StartsWith("S-1-5-5-", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The test pipe capability is not a canonical logon SID.",
                nameof(allowedLogonSid));
        }

        var sddl =
            "O:" + token.UserSid +
            "D:P(D;;0x000C0000;;;OW)(A;;0x0012019F;;;" + allowedSid + ")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                SecurityDescriptorRevision,
                out var securityDescriptor,
                out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to create the protected same-logon pipe descriptor.");
        }

        SafePipeHandle? pipeHandle = null;
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = securityDescriptor,
                InheritHandle = false
            };
            pipeHandle = CreateNamedPipeW(
                ToPipePath(endpointName),
                ExpectedOpenMode,
                ExpectedPipeMode,
                1,
                PipeBufferBytes,
                PipeBufferBytes,
                0,
                ref attributes);
            if (pipeHandle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                pipeHandle.Dispose();
                pipeHandle = null;
                throw new Win32Exception(
                    error,
                    "Unable to create the first protected native broker pipe instance.");
            }

            var security = ReadAndValidateSecurity(pipeHandle, token.UserSid, allowedSid);
            var stream = new NamedPipeServerStream(
                PipeDirection.InOut,
                isAsync: true,
                isConnected: false,
                pipeHandle);
            pipeHandle = null;
            return new WindowsSameLogonNamedPipeServer(endpointName, stream, security);
        }
        finally
        {
            pipeHandle?.Dispose();
            _ = LocalFree(securityDescriptor);
        }
    }

    public async Task WaitForConnectionAsync(CancellationToken cancellationToken)
    {
        var stream = GetOwnedStream();
        await stream.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        stream.ReadMode = PipeTransmissionMode.Message;
    }

    internal NamedPipeServerStream Stream => GetOwnedStream();

    internal bool IsConnected
    {
        get
        {
            lock (_ownershipSync)
            {
                return _ownershipState == OwnershipStateActive && _stream.IsConnected;
            }
        }
    }

    internal WindowsSameLogonNamedPipeServer TransferOwnership()
    {
        lock (_ownershipSync)
        {
            ObjectDisposedException.ThrowIf(
                _ownershipState != OwnershipStateActive,
                this);
            _ownershipState = OwnershipStateTransferred;
            return new WindowsSameLogonNamedPipeServer(
                EndpointName,
                _stream,
                Security);
        }
    }

    internal void CancelIoNoThrow()
    {
        try
        {
            _ = CancelIoEx(SafePipeHandle, IntPtr.Zero);
        }
        catch
        {
        }
    }

    internal void CancelIoOrThrow()
    {
        if (!CancelIoEx(SafePipeHandle, IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != WindowsPeerNative.ErrorNotFound)
            {
                throw new Win32Exception(error, "Unable to cancel the native pipe operation.");
            }
        }
    }

    internal uint PeekAvailableBytes()
    {
        if (!PeekNamedPipe(
                SafePipeHandle,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                out var available,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to inspect the native pipe read boundary.");
        }

        return available;
    }

    public async ValueTask WriteMessageAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        var stream = GetOwnedStream();
        if (!stream.IsConnected)
        {
            throw new InvalidOperationException("The native broker pipe is not connected.");
        }

        if (message.Length is < 1 or > MaximumTransportMessageBytes)
        {
            throw new IOException("The native broker pipe message is outside its transport bound.");
        }

        await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        var ownsStream = false;
        lock (_ownershipSync)
        {
            if (_ownershipState == OwnershipStateActive)
            {
                _ownershipState = OwnershipStateDisposed;
                ownsStream = true;
            }
        }

        if (ownsStream)
        {
            _stream.Dispose();
        }
    }

    internal SafePipeHandle SafePipeHandle => GetOwnedStream().SafePipeHandle;

    private NamedPipeServerStream GetOwnedStream()
    {
        lock (_ownershipSync)
        {
            ObjectDisposedException.ThrowIf(
                _ownershipState != OwnershipStateActive,
                this);
            return _stream;
        }
    }

    internal static string ToPipePath(string endpointName) => @"\\.\pipe\" + endpointName;

    public static void ValidateEndpointName(string endpointName)
    {
        if (string.IsNullOrWhiteSpace(endpointName) ||
            endpointName.Length is < 16 or > 160 ||
            endpointName.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '-' and not '_'))
        {
            throw new ArgumentException("The native broker pipe endpoint name is invalid.", nameof(endpointName));
        }
    }

    private static void ValidateServerToken(WindowsTokenIdentity token)
    {
        if (string.IsNullOrWhiteSpace(token.UserSid) ||
            string.IsNullOrWhiteSpace(token.LogonSid) ||
            token.LogonSidGroupCount != 1 ||
            token.AuthenticationId == 0 ||
            token.SessionId == 0 ||
            token.IntegrityLevelRid is < 0x2000 or >= 0x3000 ||
            token.IsElevated ||
            token.ElevationType == WindowsTokenElevationType.Full ||
            token.IsAppContainer ||
            token.AppContainerSid is not null ||
            token.UiAccess ||
            token.TokenType != WindowsTokenType.Primary ||
            token.ImpersonationLevel is not null)
        {
            throw new BrokerPeerTrustException(
                "peer-token-policy",
                "The broker cannot create a same-logon endpoint from this process token.");
        }
    }

    private static WindowsNamedPipeSecuritySnapshot ReadAndValidateSecurity(
        SafePipeHandle pipe,
        string expectedOwnerSid,
        string expectedAllowedLogonSid)
    {
        var result = GetSecurityInfo(
            pipe,
            SeKernelObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            out _,
            out _,
            out _,
            out _,
            out var securityDescriptor);
        if (result != 0)
        {
            throw new Win32Exception(
                checked((int)result),
                "Unable to read back the native broker pipe descriptor.");
        }

        try
        {
            var length = GetSecurityDescriptorLength(securityDescriptor);
            if (length == 0 || length > 64 * 1024)
            {
                throw new IOException("The native broker pipe descriptor has an invalid size.");
            }

            var bytes = new byte[checked((int)length)];
            Marshal.Copy(securityDescriptor, bytes, 0, checked((int)length));
            var descriptor = new RawSecurityDescriptor(bytes, 0);
            var owner = descriptor.Owner?.Value ?? throw new IOException(
                "The native broker pipe owner is missing.");
            var dacl = descriptor.DiscretionaryAcl ?? throw new IOException(
                "The native broker pipe has a null DACL.");
            if (!string.Equals(owner, expectedOwnerSid, StringComparison.OrdinalIgnoreCase) ||
                (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                dacl.Count != 2)
            {
                throw new IOException("The native broker pipe descriptor is not exact and protected.");
            }

            CommonAce? ownerDeny = null;
            CommonAce? logonAllow = null;
            foreach (GenericAce ace in dacl)
            {
                if (ace is not CommonAce common ||
                    (common.AceFlags & AceFlags.Inherited) != 0)
                {
                    throw new IOException("The native broker pipe DACL contains an unsupported ACE.");
                }

                if (common.AceQualifier == AceQualifier.AccessDenied &&
                    string.Equals(
                        common.SecurityIdentifier.Value,
                        OwnerRightsSid,
                        StringComparison.OrdinalIgnoreCase))
                {
                    ownerDeny = common;
                }
                else if (common.AceQualifier == AceQualifier.AccessAllowed &&
                         string.Equals(
                             common.SecurityIdentifier.Value,
                             expectedAllowedLogonSid,
                             StringComparison.OrdinalIgnoreCase))
                {
                    logonAllow = common;
                }
                else
                {
                    throw new IOException("The native broker pipe DACL grants an unexpected principal.");
                }
            }

            if (ownerDeny is null ||
                logonAllow is null ||
                checked((uint)ownerDeny.AccessMask) != ExpectedOwnerRightsDenyMask ||
                checked((uint)logonAllow.AccessMask) != ExpectedClientAccessMask)
            {
                throw new IOException("The native broker pipe DACL access masks are not exact.");
            }

            return new WindowsNamedPipeSecuritySnapshot(
                owner,
                expectedAllowedLogonSid,
                true,
                dacl.Count,
                checked((uint)logonAllow.AccessMask),
                checked((uint)ownerDeny.AccessMask),
                ExpectedOpenMode,
                ExpectedPipeMode);
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor,
        uint stringSDRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipeW(
        string name,
        uint openMode,
        uint pipeMode,
        uint maximumInstances,
        uint outputBufferSize,
        uint inputBufferSize,
        uint defaultTimeout,
        ref SecurityAttributes securityAttributes);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        SafePipeHandle handle,
        uint objectType,
        uint securityInformation,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(SafePipeHandle pipe, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PeekNamedPipe(
        SafePipeHandle pipe,
        IntPtr buffer,
        uint bufferSize,
        IntPtr bytesRead,
        out uint totalBytesAvailable,
        IntPtr bytesLeftThisMessage);
}

internal sealed class WindowsSameLogonNamedPipeClient : IDisposable
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorPipeBusy = 231;
    private const uint PipeReadModeMessage = 0x00000002;
    private readonly NamedPipeClientStream _stream;
    private int _disposed;

    private WindowsSameLogonNamedPipeClient(NamedPipeClientStream stream)
    {
        _stream = stream;
    }

    internal NamedPipeClientStream Stream => _stream;

    internal SafePipeHandle SafePipeHandle => _stream.SafePipeHandle;

    internal static WindowsSameLogonNamedPipeClient Connect(
        string endpointName,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        WindowsSameLogonNamedPipeServer.ValidateEndpointName(endpointName);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var handle = CreateFileW(
                WindowsSameLogonNamedPipeServer.ToPipePath(endpointName),
                WindowsPeerNative.GenericRead | WindowsPeerNative.GenericWrite,
                0,
                IntPtr.Zero,
                WindowsPeerNative.OpenExisting,
                WindowsPeerNative.FileFlagOverlapped |
                WindowsPeerNative.SecuritySqosPresent |
                WindowsPeerNative.SecurityIdentification,
                IntPtr.Zero);
            if (!handle.IsInvalid)
            {
                var mode = PipeReadModeMessage;
                if (!SetNamedPipeHandleState(handle, ref mode, IntPtr.Zero, IntPtr.Zero))
                {
                    var error = Marshal.GetLastWin32Error();
                    handle.Dispose();
                    throw new Win32Exception(error, "Unable to select message mode for the broker pipe.");
                }

                NamedPipeClientStream? stream = null;
                try
                {
                    stream = new NamedPipeClientStream(
                        PipeDirection.InOut,
                        isAsync: true,
                        isConnected: true,
                        handle);
                    stream.ReadMode = PipeTransmissionMode.Message;
                    return new WindowsSameLogonNamedPipeClient(stream);
                }
                catch
                {
                    if (stream is not null)
                    {
                        stream.Dispose();
                    }
                    else
                    {
                        handle.Dispose();
                    }

                    throw;
                }
            }

            var errorCode = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (errorCode is not ErrorFileNotFound and not ErrorPipeBusy)
            {
                throw new Win32Exception(errorCode, "Unable to connect to the native broker pipe.");
            }

            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                throw new TimeoutException("The native broker pipe did not become available.");
            }

            var waitMilliseconds = checked((uint)Math.Clamp(
                Math.Ceiling(remaining.TotalMilliseconds),
                1,
                250));
            _ = WaitNamedPipeW(
                WindowsSameLogonNamedPipeServer.ToPipePath(endpointName),
                waitMilliseconds);
        }
    }

    internal void CancelIoNoThrow()
    {
        try
        {
            _ = CancelIoEx(SafePipeHandle, IntPtr.Zero);
        }
        catch
        {
        }
    }

    internal void CancelIoOrThrow()
    {
        if (!CancelIoEx(SafePipeHandle, IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != WindowsPeerNative.ErrorNotFound)
            {
                throw new Win32Exception(error, "Unable to cancel the bounded broker hello read.");
            }
        }
    }

    internal uint PeekAvailableBytes()
    {
        if (!PeekNamedPipe(
                SafePipeHandle,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                out var available,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to inspect the broker pipe read boundary.");
        }

        return available;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _stream.Dispose();
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetNamedPipeHandleState(
        SafePipeHandle pipe,
        ref uint mode,
        IntPtr maximumCollectionCount,
        IntPtr collectionDataTimeout);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WaitNamedPipeW(string name, uint timeoutMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(SafePipeHandle pipe, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PeekNamedPipe(
        SafePipeHandle pipe,
        IntPtr buffer,
        uint bufferSize,
        IntPtr bytesRead,
        out uint totalBytesAvailable,
        IntPtr bytesLeftThisMessage);
}

internal static class WindowsNamedPipeMessageIO
{
    internal const int MaximumMessageBytes =
        AuthenticatedPipePeerConnection.AbsoluteMaximumMessageBytes;

    internal static async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
        PipeStream stream,
        int maximumMessageBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ValidateMaximum(maximumMessageBytes);

        var buffer = new byte[checked(maximumMessageBytes + 1)];
        var total = 0;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var read = await stream.ReadAsync(
                        buffer.AsMemory(total, buffer.Length - total),
                        cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (read == 0)
                {
                    if (total == 0)
                    {
                        return ReadOnlyMemory<byte>.Empty;
                    }

                    throw new EndOfStreamException(
                        "The named pipe disconnected in the middle of a message.");
                }

                total = checked(total + read);
                if (total > maximumMessageBytes)
                {
                    throw new BrokerPeerTrustException(
                        "peer-message-too-large",
                        "The named pipe message exceeded its bounded transport size.");
                }

                if (stream.IsMessageComplete)
                {
                    var result = new byte[total];
                    buffer.AsSpan(0, total).CopyTo(result);
                    return result;
                }

                if (total == buffer.Length)
                {
                    throw new BrokerPeerTrustException(
                        "peer-message-too-large",
                        "The named pipe message exceeded its bounded message frame.");
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    internal static async ValueTask WriteMessageAsync(
        PipeStream stream,
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (message.Length is < 1 or > MaximumMessageBytes)
        {
            throw new BrokerPeerTrustException(
                "peer-message-too-large",
                "The named pipe message is outside its bounded transport size.");
        }

        await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateMaximum(int maximumMessageBytes)
    {
        if (maximumMessageBytes is < 1 or > MaximumMessageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumMessageBytes));
        }
    }
}
