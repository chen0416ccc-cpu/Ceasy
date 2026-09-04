using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal sealed class BrokerOwnedWindowV1 : IDisposable
{
    internal const string RegistrationSummary = "Confirm CodexGuardian setup";
    internal const string AssertionSummary = "Confirm CodexGuardian access";

    private const uint GaRoot = 2;
    private const uint Synchronize = 0x00100000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WmClose = 0x0010;
    private const uint WmDestroy = 0x0002;
    private const uint WmQuit = 0x0012;
    private const uint WmApp = 0x8000;
    private const uint ExecuteWorkMessage = WmApp + 0x431;
    private const uint UpdateSummaryMessage = WmApp + 0x432;
    private const uint WsCaption = 0x00C00000;
    private const uint WsSysMenu = 0x00080000;
    private const int CwUseDefault = unchecked((int)0x80000000);
    private const int SwShowNoActivate = 4;

    private readonly ConcurrentQueue<IWindowWorkItem> _workItems = new();
    private readonly TaskCompletionSource<BrokerOwnedWindowV1> _created = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ManualResetEventSlim _threadExited = new(initialState: false);
    private readonly object _summaryLock = new();
    private readonly WindowProcedure _windowProcedure;
    private readonly Thread _thread;
    private readonly string _windowClassName;
    private string _transactionSummary = RegistrationSummary;
    private BrokerOwnedWindowHandle? _identity;
    private nint _windowHandle;
    private nint _moduleHandle;
    private uint _ownerThreadId;
    private ushort _windowClassAtom;
    private int _activeCeremony;
    private int _disposed;

    private BrokerOwnedWindowV1()
    {
        _windowClassName = "CodexGuardian.Broker.UserPresence." + Guid.NewGuid().ToString("N");
        _windowProcedure = WindowProcedureCore;
        _thread = new Thread(ThreadMain)
        {
            IsBackground = true,
            Name = "CodexGuardian Broker user-presence window"
        };
        if (!_thread.TrySetApartmentState(ApartmentState.STA))
        {
            throw FailWindow("The Broker-owned window thread could not enter STA.");
        }
    }

    internal BrokerOwnedWindowHandle Handle
    {
        get
        {
            ValidateForCurrentProcess();
            return _identity ?? throw FailWindow("The Broker-owned window identity is absent.");
        }
    }

    internal static async ValueTask<BrokerOwnedWindowV1> CreateAsync(
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-platform-unavailable",
                "The Broker-owned user-presence window requires Windows.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var window = new BrokerOwnedWindowV1();
        window._thread.Start();
        try
        {
            return await window._created.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            window.Dispose();
            throw;
        }
    }

    internal void UpdateTransactionSummary(string summary)
    {
        ThrowIfDisposed();
        if (summary is not RegistrationSummary and not AssertionSummary)
        {
            throw new ArgumentException(
                "The Broker-owned window accepts only a fixed generic transaction summary.",
                nameof(summary));
        }

        lock (_summaryLock)
        {
            _transactionSummary = summary;
        }

        var handle = Volatile.Read(ref _windowHandle);
        if (handle == nint.Zero || !PostMessageW(handle, UpdateSummaryMessage, nint.Zero, nint.Zero))
        {
            throw FailWindow("The Broker-owned window could not update its transaction summary.");
        }
    }

    internal void ValidateForCurrentProcess()
    {
        ThrowIfDisposed();
        var handle = Volatile.Read(ref _windowHandle);
        var ownerThreadId = Volatile.Read(ref _ownerThreadId);
        if (handle == nint.Zero ||
            ownerThreadId == 0 ||
            !_thread.IsAlive ||
            !IsWindow(handle) ||
            GetAncestor(handle, GaRoot) != handle)
        {
            throw FailWindow("The Broker-owned top-level window is not live.");
        }

        var actualThreadId = GetWindowThreadProcessId(handle, out var processId);
        if (processId != checked((uint)Environment.ProcessId) || actualThreadId != ownerThreadId)
        {
            throw FailWindow("The user-presence window is not owned by the current Broker process.");
        }

        var threadHandle = OpenThread(Synchronize, inheritHandle: false, ownerThreadId);
        if (threadHandle == nint.Zero)
        {
            throw FailWindow("The Broker-owned window thread cannot be retained.");
        }

        try
        {
            if (WaitForSingleObject(threadHandle, milliseconds: 0) != WaitTimeout)
            {
                throw FailWindow("The Broker-owned window thread is no longer live.");
            }
        }
        finally
        {
            _ = CloseHandle(threadHandle);
        }
    }

    internal ValueTask<T> InvokeOnOwnerThreadAsync<T>(
        Func<T> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ThrowIfDisposed();
        if (cancellationToken.IsCancellationRequested)
        {
            return ValueTask.FromCanceled<T>(cancellationToken);
        }

        ValidateForCurrentProcess();
        if (Interlocked.CompareExchange(ref _activeCeremony, 1, 0) != 0)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-operation-busy",
                "The Broker-owned window already has an active user-presence ceremony.");
        }

        if (GetCurrentThreadId() == Volatile.Read(ref _ownerThreadId))
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(operation());
            }
            finally
            {
                Volatile.Write(ref _activeCeremony, 0);
            }
        }

        var item = new WindowWorkItem<T>(
            operation,
            cancellationToken,
            () => Volatile.Write(ref _activeCeremony, 0));
        _workItems.Enqueue(item);
        var handle = Volatile.Read(ref _windowHandle);
        if (handle == nint.Zero || !PostMessageW(handle, ExecuteWorkMessage, nint.Zero, nint.Zero))
        {
            item.Fail(FailWindow("The Broker-owned window could not schedule the ceremony."));
        }

        return new ValueTask<T>(item.Completion);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        FailPending(new ObjectDisposedException(nameof(BrokerOwnedWindowV1)));
        var handle = Volatile.Read(ref _windowHandle);
        if (handle != nint.Zero)
        {
            _ = PostMessageW(handle, WmClose, nint.Zero, nint.Zero);
        }
        else
        {
            var threadId = Volatile.Read(ref _ownerThreadId);
            if (threadId != 0)
            {
                _ = PostThreadMessageW(threadId, WmQuit, nint.Zero, nint.Zero);
            }
        }

        if (GetCurrentThreadId() != Volatile.Read(ref _ownerThreadId))
        {
            _threadExited.Wait(TimeSpan.FromSeconds(10));
        }

    }

    private void ThreadMain()
    {
        try
        {
            _ownerThreadId = GetCurrentThreadId();
            _moduleHandle = GetModuleHandleW(null);
            if (_moduleHandle == nint.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var windowClass = new WindowClassEx
            {
                Size = checked((uint)Marshal.SizeOf<WindowClassEx>()),
                WindowProcedure = Marshal.GetFunctionPointerForDelegate(_windowProcedure),
                Instance = _moduleHandle,
                ClassName = _windowClassName
            };
            _windowClassAtom = RegisterClassExW(ref windowClass);
            if (_windowClassAtom == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            _windowHandle = CreateWindowExW(
                extendedStyle: 0,
                _windowClassName,
                BuildWindowTitle(),
                WsCaption | WsSysMenu,
                CwUseDefault,
                CwUseDefault,
                width: 520,
                height: 180,
                parent: nint.Zero,
                menu: nint.Zero,
                _moduleHandle,
                parameter: nint.Zero);
            if (_windowHandle == nint.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (Volatile.Read(ref _disposed) != 0)
            {
                _created.TrySetCanceled();
                return;
            }

            _identity = BrokerOwnedWindowHandle.CreateOwned(
                _windowHandle,
                Environment.ProcessId,
                checked((int)_ownerThreadId),
                this);
            _ = ShowWindow(_windowHandle, SwShowNoActivate);
            _ = UpdateWindow(_windowHandle);
            _created.TrySetResult(this);

            while (true)
            {
                var result = GetMessageW(out var message, nint.Zero, 0, 0);
                if (result == 0)
                {
                    break;
                }

                if (result < 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                _ = TranslateMessage(ref message);
                _ = DispatchMessageW(ref message);
            }
        }
        catch (Exception exception)
        {
            _created.TrySetException(FailWindow(
                "The Broker-owned window could not initialize.",
                exception));
            FailPending(FailWindow("The Broker-owned window message loop failed.", exception));
        }
        finally
        {
            var handle = Interlocked.Exchange(ref _windowHandle, nint.Zero);
            if (handle != nint.Zero && IsWindow(handle))
            {
                _ = DestroyWindow(handle);
            }

            if (_windowClassAtom != 0 && _moduleHandle != nint.Zero)
            {
                _ = UnregisterClassW(_windowClassName, _moduleHandle);
            }

            FailPending(new ObjectDisposedException(nameof(BrokerOwnedWindowV1)));
            _threadExited.Set();
        }
    }

    private nint WindowProcedureCore(nint window, uint message, nint wParam, nint lParam)
    {
        try
        {
            switch (message)
            {
                case ExecuteWorkMessage:
                    while (_workItems.TryDequeue(out var item))
                    {
                        item.Execute();
                    }

                    return nint.Zero;
                case UpdateSummaryMessage:
                    _ = SetWindowTextW(window, BuildWindowTitle());
                    return nint.Zero;
                case WmClose:
                    _ = DestroyWindow(window);
                    return nint.Zero;
                case WmDestroy:
                    Interlocked.Exchange(ref _windowHandle, nint.Zero);
                    PostQuitMessage(0);
                    return nint.Zero;
                default:
                    return DefWindowProcW(window, message, wParam, lParam);
            }
        }
        catch (Exception exception)
        {
            FailPending(FailWindow("The Broker-owned window callback failed.", exception));
            return nint.Zero;
        }
    }

    private string BuildWindowTitle()
    {
        lock (_summaryLock)
        {
            return "CodexGuardian - " + _transactionSummary;
        }
    }

    private void FailPending(Exception exception)
    {
        while (_workItems.TryDequeue(out var item))
        {
            item.Fail(exception);
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private static BrokerUserPresenceVerificationException FailWindow(
        string message,
        Exception? innerException = null) =>
        new("user-presence-window-invalid", message, innerException);

    private interface IWindowWorkItem
    {
        void Execute();

        void Fail(Exception exception);
    }

    private sealed class WindowWorkItem<T>(
        Func<T> operation,
        CancellationToken cancellationToken,
        Action release) : IWindowWorkItem
    {
        private readonly TaskCompletionSource<T> _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _completed;

        internal Task<T> Completion => _completion.Task;

        public void Execute()
        {
            if (Interlocked.Exchange(ref _completed, 1) != 0)
            {
                return;
            }

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                _completion.TrySetResult(operation());
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                _completion.TrySetCanceled(cancellationToken);
            }
            catch (Exception exception)
            {
                _completion.TrySetException(exception);
            }
            finally
            {
                release();
            }
        }

        public void Fail(Exception exception)
        {
            if (Interlocked.Exchange(ref _completed, 1) != 0)
            {
                return;
            }

            try
            {
                _completion.TrySetException(exception);
            }
            finally
            {
                release();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WindowClassEx
    {
        internal uint Size;
        internal uint Style;
        internal nint WindowProcedure;
        internal int ClassExtraBytes;
        internal int WindowExtraBytes;
        internal nint Instance;
        internal nint Icon;
        internal nint Cursor;
        internal nint BackgroundBrush;
        internal string? MenuName;
        internal string ClassName;
        internal nint SmallIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        internal int X;
        internal int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeMessage
    {
        internal nint Window;
        internal uint Message;
        internal nuint WParam;
        internal nint LParam;
        internal uint Time;
        internal NativePoint Point;
        internal uint Private;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate nint WindowProcedure(nint window, uint message, nint wParam, nint lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint GetModuleHandleW(string? moduleName);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenThread(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(nint handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassExW(ref WindowClassEx windowClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnregisterClassW(string className, nint instance);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint CreateWindowExW(
        uint extendedStyle,
        string className,
        string windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        nint parent,
        nint menu,
        nint instance,
        nint parameter);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(nint window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(nint window);

    [DllImport("user32.dll")]
    private static extern nint GetAncestor(nint window, uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(nint window, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowTextW(nint window, string text);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessageW(nint window, uint message, nint wParam, nint lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostThreadMessageW(
        uint threadId,
        uint message,
        nint wParam,
        nint lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetMessageW(
        out NativeMessage message,
        nint window,
        uint minimumMessage,
        uint maximumMessage);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(ref NativeMessage message);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern nint DispatchMessageW(ref NativeMessage message);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern nint DefWindowProcW(nint window, uint message, nint wParam, nint lParam);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int exitCode);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(nint window, int commandShow);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateWindow(nint window);
}
