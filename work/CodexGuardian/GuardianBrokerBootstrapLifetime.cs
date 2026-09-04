using CodexGuardian.Trust;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian;

internal sealed record GuardianBrokerProcessExitV1(
    uint ProcessId,
    uint ExitCode);

internal interface IGuardianBrokerProcessObserverV1 : IAsyncDisposable
{
    Task<GuardianBrokerProcessExitV1> Completion { get; }
}

internal sealed class GuardianBrokerBootstrapFailureV1 : InvalidOperationException
{
    internal GuardianBrokerBootstrapFailureV1(
        string code,
        string message,
        Exception? innerException = null,
        Exception? concurrentFailure = null)
        : base(message, innerException)
    {
        Code = code;
        ConcurrentFailure = concurrentFailure;
    }

    internal string Code { get; }

    internal Exception? ConcurrentFailure { get; }
}

internal sealed class WindowsGuardianBrokerProcessObserverV1 :
    IGuardianBrokerProcessObserverV1
{
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint StillActive = 259;
    private static readonly TimeSpan UnregisterTimeout = TimeSpan.FromSeconds(2);

    private readonly object _gate = new();
    private readonly TaskCompletionSource<GuardianBrokerProcessExitV1> _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _callbackReturned = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly uint _processId;
    private SafeProcessHandle? _exactProcessHandle;
    private EventWaitHandle? _processWaitHandle;
    private RegisteredWaitHandle? _registeredWait;
    private ManualResetEvent? _retainedDrainEvent;
    private Task? _disposeTask;

    private WindowsGuardianBrokerProcessObserverV1(
        SafeProcessHandle exactProcessHandle,
        uint processId)
    {
        _exactProcessHandle = exactProcessHandle;
        _processId = processId;
        _processWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset)
        {
            SafeWaitHandle = new SafeWaitHandle(
                exactProcessHandle.DangerousGetHandle(),
                ownsHandle: false)
        };
    }

    public Task<GuardianBrokerProcessExitV1> Completion => _completion.Task;

    internal static WindowsGuardianBrokerProcessObserverV1 Create(
        SafeProcessHandle exactBrokerHandle,
        uint expectedProcessId)
    {
        ArgumentNullException.ThrowIfNull(exactBrokerHandle);
        if (expectedProcessId == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedProcessId));
        }

        SafeProcessHandle? duplicate = null;
        WindowsGuardianBrokerProcessObserverV1? observer = null;
        try
        {
            if (!DuplicateHandle(
                    GetCurrentProcess(),
                    exactBrokerHandle,
                    GetCurrentProcess(),
                    out duplicate,
                    desiredAccess: 0,
                    inheritHandle: false,
                    options: DuplicateSameAccess) ||
                duplicate is null ||
                duplicate.IsInvalid || duplicate.IsClosed)
            {
                duplicate?.Dispose();
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to duplicate the exact inherited Broker process handle.");
            }

            var processId = GetProcessId(duplicate);
            if (processId == 0)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to read the exact inherited Broker process id.");
            }

            if (processId != expectedProcessId)
            {
                throw new GuardianBrokerBootstrapFailureV1(
                    "guardian-broker-process-identity-mismatch",
                    "The inherited Broker process handle does not identify the authenticated Broker.");
            }

            observer = new WindowsGuardianBrokerProcessObserverV1(duplicate, processId);
            duplicate = null;
            observer.Start();
            return observer;
        }
        catch
        {
            observer?.DisposeAfterStartFailure();
            duplicate?.Dispose();
            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _disposeTask ??= DisposeCore();
            return new ValueTask(_disposeTask);
        }
    }

    private void Start()
    {
        var waitHandle = _processWaitHandle ?? throw new ObjectDisposedException(
            nameof(WindowsGuardianBrokerProcessObserverV1));
        var registered = ThreadPool.RegisterWaitForSingleObject(
            waitHandle,
            static (state, timedOut) =>
                ((WindowsGuardianBrokerProcessObserverV1)state!).OnProcessSignaled(timedOut),
            this,
            Timeout.InfiniteTimeSpan,
            executeOnlyOnce: true);
        if (registered is null)
        {
            throw new InvalidOperationException(
                "The exact Broker process observer could not register its wait.");
        }

        _registeredWait = registered;
    }

    private void OnProcessSignaled(bool timedOut)
    {
        try
        {
            if (timedOut)
            {
                throw new InvalidOperationException(
                    "The infinite exact Broker process wait timed out unexpectedly.");
            }

            var process = Volatile.Read(ref _exactProcessHandle) ??
                throw new ObjectDisposedException(
                    nameof(WindowsGuardianBrokerProcessObserverV1));
            if (!GetExitCodeProcess(process, out var exitCode))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to read the exact Broker process exit code.");
            }

            if (exitCode == StillActive)
            {
                throw new InvalidOperationException(
                    "The exact Broker process wait fired while the process remained active.");
            }

            _completion.TrySetResult(new GuardianBrokerProcessExitV1(_processId, exitCode));
        }
        catch (Exception exception)
        {
            _completion.TrySetException(exception);
        }
        finally
        {
            _callbackReturned.TrySetResult();
        }
    }

    private Task DisposeCore()
    {
        _ = _retainedDrainEvent;
        Exception? failure = null;
        var registered = _registeredWait;
        if (registered is not null)
        {
            var drain = new ManualResetEvent(false);
            bool unregisterAccepted;
            try
            {
                unregisterAccepted = registered.Unregister(drain);
            }
            catch (Exception exception)
            {
                unregisterAccepted = false;
                failure = exception;
            }

            if (failure is null)
            {
                if (unregisterAccepted)
                {
                    if (!drain.WaitOne(UnregisterTimeout))
                    {
                        failure = new TimeoutException(
                            "The exact Broker process observer did not prove callback drain in time.");
                    }
                }
                else if (!_callbackReturned.Task.Wait(UnregisterTimeout))
                {
                    failure = new InvalidOperationException(
                        "The exact Broker process observer could not unregister or prove callback return.");
                }
            }

            if (failure is null)
            {
                drain.Dispose();
            }
            else
            {
                _retainedDrainEvent = drain;
            }
        }

        if (failure is null)
        {
            try
            {
                _processWaitHandle?.Dispose();
                _processWaitHandle = null;
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        }

        if (failure is null)
        {
            try
            {
                _exactProcessHandle?.Dispose();
                _exactProcessHandle = null;
                _registeredWait = null;
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        }

        return failure is null
            ? Task.CompletedTask
            : Task.FromException(failure);
    }

    private void DisposeAfterStartFailure()
    {
        try
        {
            _processWaitHandle?.Dispose();
        }
        catch
        {
        }

        try
        {
            _exactProcessHandle?.Dispose();
        }
        catch
        {
        }

        _processWaitHandle = null;
        _exactProcessHandle = null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcessHandle,
        SafeProcessHandle sourceHandle,
        IntPtr targetProcessHandle,
        out SafeProcessHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(
        SafeProcessHandle process,
        out uint exitCode);
}

internal sealed class GuardianBrokerBootstrapLifetime : IAsyncDisposable
{
    private static readonly TimeSpan DefaultProcessPriorityWindow = TimeSpan.FromSeconds(2);

    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly TimeSpan _processPriorityWindow;
    private readonly Task _monitorTask;
    private VerifiedLocalReleaseLeaseV1? _releaseLease;
    private AuthenticatedPipePeerConnection? _authenticatedConnection;
    private SafeProcessHandle? _inheritedExactBrokerHandle;
    private IGuardianBrokerProcessObserverV1? _processObserver;
    private Action<Exception>? _failClosedShutdown;
    private GuardianBrokerBootstrapFailureV1? _terminalFailure;
    private Task? _disposeTask;
    private bool _disposeStarted;
    private bool _shutdownPublished;

    internal GuardianBrokerBootstrapLifetime(
        VerifiedLocalReleaseLeaseV1 releaseLease,
        AuthenticatedPipePeerConnection authenticatedConnection,
        SafeProcessHandle inheritedExactBrokerHandle,
        IGuardianBrokerProcessObserverV1 processObserver)
    {
        _releaseLease = releaseLease ?? throw new ArgumentNullException(nameof(releaseLease));
        _authenticatedConnection = authenticatedConnection ??
            throw new ArgumentNullException(nameof(authenticatedConnection));
        _inheritedExactBrokerHandle = inheritedExactBrokerHandle ??
            throw new ArgumentNullException(nameof(inheritedExactBrokerHandle));
        _processObserver = processObserver ?? throw new ArgumentNullException(nameof(processObserver));
        _processPriorityWindow = DefaultProcessPriorityWindow;
        _monitorTask = MonitorAsync(
            authenticatedConnection.Completion,
            processObserver.Completion,
            _lifetimeCancellation.Token);
    }

    internal void AttachFailClosedShutdown(Action<Exception> failClosedShutdown)
    {
        ArgumentNullException.ThrowIfNull(failClosedShutdown);
        GuardianBrokerBootstrapFailureV1? latchedFailure = null;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            if (_failClosedShutdown is not null)
            {
                throw new InvalidOperationException(
                    "The Guardian Broker fail-closed dispatcher was already attached.");
            }

            _failClosedShutdown = failClosedShutdown;
            if (_terminalFailure is not null && !_shutdownPublished)
            {
                _shutdownPublished = true;
                latchedFailure = _terminalFailure;
            }
        }

        if (latchedFailure is not null)
        {
            InvokeFailClosedShutdown(failClosedShutdown, latchedFailure);
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    private async Task MonitorAsync(
        Task pipeCompletion,
        Task<GuardianBrokerProcessExitV1> processCompletion,
        CancellationToken lifetimeCancellation)
    {
        var failure = await ObserveTerminalFailureAsync(
                pipeCompletion,
                processCompletion,
                lifetimeCancellation,
                _processPriorityWindow)
            .ConfigureAwait(false);
        if (failure is not null)
        {
            PublishTerminalFailure(failure);
        }
    }

    internal static async Task<GuardianBrokerBootstrapFailureV1?> ObserveTerminalFailureAsync(
        Task pipeCompletion,
        Task<GuardianBrokerProcessExitV1> processCompletion,
        CancellationToken lifetimeCancellation,
        TimeSpan processPriorityWindow)
    {
        ArgumentNullException.ThrowIfNull(pipeCompletion);
        ArgumentNullException.ThrowIfNull(processCompletion);
        if (processPriorityWindow <= TimeSpan.Zero ||
            processPriorityWindow > TimeSpan.FromSeconds(5))
        {
            throw new ArgumentOutOfRangeException(nameof(processPriorityWindow));
        }

        var processFailureTask = ObserveProcessFailureAsync(processCompletion);
        var pipeFailureTask = ObservePipeFailureAsync(pipeCompletion);
        var stoppedTask = Task.Delay(Timeout.InfiniteTimeSpan, lifetimeCancellation);
        var winner = await Task.WhenAny(
                processFailureTask,
                pipeFailureTask,
                stoppedTask)
            .ConfigureAwait(false);
        if (ReferenceEquals(winner, stoppedTask) || lifetimeCancellation.IsCancellationRequested)
        {
            return null;
        }

        GuardianBrokerBootstrapFailureV1 primary;
        GuardianBrokerBootstrapFailureV1? secondary = null;
        if (processCompletion.IsCompleted)
        {
            primary = await processFailureTask.ConfigureAwait(false);
            if (pipeCompletion.IsCompleted)
            {
                secondary = await pipeFailureTask.ConfigureAwait(false);
            }
        }
        else
        {
            var priorityDelay = Task.Delay(processPriorityWindow, lifetimeCancellation);
            var priorityWinner = await Task.WhenAny(processFailureTask, priorityDelay)
                .ConfigureAwait(false);
            if (ReferenceEquals(priorityWinner, processFailureTask))
            {
                primary = await processFailureTask.ConfigureAwait(false);
                secondary = await pipeFailureTask.ConfigureAwait(false);
            }
            else
            {
                if (lifetimeCancellation.IsCancellationRequested)
                {
                    return null;
                }

                primary = await pipeFailureTask.ConfigureAwait(false);
            }
        }

        if (secondary is not null)
        {
            primary = new GuardianBrokerBootstrapFailureV1(
                primary.Code,
                primary.Message,
                primary.InnerException,
                secondary);
        }

        return primary;
    }

    private void PublishTerminalFailure(GuardianBrokerBootstrapFailureV1 failure)
    {
        Action<Exception>? shutdown = null;
        lock (_gate)
        {
            if (_disposeStarted || _terminalFailure is not null)
            {
                return;
            }

            _terminalFailure = failure;
            if (_failClosedShutdown is not null && !_shutdownPublished)
            {
                _shutdownPublished = true;
                shutdown = _failClosedShutdown;
            }
        }

        if (shutdown is not null)
        {
            InvokeFailClosedShutdown(shutdown, failure);
        }
    }

    private static void InvokeFailClosedShutdown(
        Action<Exception> shutdown,
        Exception failure)
    {
        try
        {
            shutdown(failure);
        }
        catch (Exception dispatchFailure)
        {
            Environment.FailFast(
                "CodexGuardian could not dispatch its fail-closed Broker shutdown.",
                new AggregateException(failure, dispatchFailure));
        }
    }

    private async Task DisposeCoreAsync()
    {
        lock (_gate)
        {
            _disposeStarted = true;
        }

        var failures = new List<Exception>();
        try
        {
            _lifetimeCancellation.Cancel();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        try
        {
            await _monitorTask.ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        if (_processObserver is not null)
        {
            try
            {
                await _processObserver.DisposeAsync().ConfigureAwait(false);
                _processObserver = null;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        if (_authenticatedConnection is not null)
        {
            try
            {
                await _authenticatedConnection.DisposeAsync().ConfigureAwait(false);
                _authenticatedConnection = null;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        if (_inheritedExactBrokerHandle is not null)
        {
            try
            {
                _inheritedExactBrokerHandle.Dispose();
                _inheritedExactBrokerHandle = null;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        if (_releaseLease is not null)
        {
            try
            {
                _releaseLease.Dispose();
                _releaseLease = null;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        try
        {
            _lifetimeCancellation.Dispose();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        if (failures.Count == 1)
        {
            throw failures[0];
        }

        if (failures.Count > 1)
        {
            throw new AggregateException(
                "Guardian Broker bootstrap lifetime cleanup failed.",
                failures);
        }
    }

    private static async Task<GuardianBrokerBootstrapFailureV1> ObserveProcessFailureAsync(
        Task<GuardianBrokerProcessExitV1> processCompletion)
    {
        try
        {
            var exit = await processCompletion.ConfigureAwait(false);
            return new GuardianBrokerBootstrapFailureV1(
                "guardian-broker-process-exited",
                "The exact Broker process exited with code 0x" +
                exit.ExitCode.ToString("X8") + ".");
        }
        catch (Exception exception)
        {
            return new GuardianBrokerBootstrapFailureV1(
                "guardian-broker-process-observation-failed",
                "The exact Broker process observer failed.",
                exception);
        }
    }

    private static async Task<GuardianBrokerBootstrapFailureV1> ObservePipeFailureAsync(
        Task pipeCompletion)
    {
        try
        {
            await pipeCompletion.ConfigureAwait(false);
            return new GuardianBrokerBootstrapFailureV1(
                "guardian-broker-pipe-closed",
                "The authenticated Broker connection closed while Guardian was running.");
        }
        catch (Exception exception)
        {
            return new GuardianBrokerBootstrapFailureV1(
                "guardian-broker-pipe-failed",
                "The authenticated Broker connection failed while Guardian was running.",
                exception);
        }
    }
}
