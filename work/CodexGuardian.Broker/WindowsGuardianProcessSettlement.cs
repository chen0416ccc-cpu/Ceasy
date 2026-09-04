using CodexGuardian.Trust;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal enum BrokerGuardianProcessStopRequestV1
{
    None,
    LaunchRollback,
    AdmissionFailure,
    SessionEnded,
    OwnerTerminal,
    HostCancellation,
    Disposal
}

// StopRequest is retained for source compatibility with the in-flight Task 16
// interface. It is not an exit-causality field: the production root publishes
// exact process facts independently of whichever stop caller happens to race
// the observer continuation.
internal readonly record struct BrokerGuardianProcessExitV1(
    uint ProcessId,
    uint ExitCode,
    BrokerGuardianProcessStopRequestV1 StopRequest);

internal enum WindowsGuardianProcessRegistryHealthV1
{
    Empty,
    Reserved,
    Active,
    Quarantined
}

internal interface IWindowsGuardianProcessExitObserverV1 : IDisposable
{
    Task<uint> Completion { get; }
}

internal interface IWindowsGuardianRegisteredWaitV1
{
    bool Unregister(WaitHandle completionEvent);
}

internal interface IWindowsGuardianProcessObserverPlatformV1
{
    IWindowsGuardianRegisteredWaitV1 Register(
        WaitHandle waitHandle,
        WaitOrTimerCallback callback);

    bool TryGetExitCode(
        SafeProcessHandle processHandle,
        out uint exitCode,
        out int win32Error);
}

internal interface IWindowsGuardianProcessSettlementNativeV1
{
    IWindowsGuardianProcessExitObserverV1 ObserveExactProcess(
        SafeProcessHandle processHandle);

    uint WaitProcess(
        SafeProcessHandle processHandle,
        uint milliseconds,
        out int win32Error);

    bool TryTerminateProcess(
        SafeProcessHandle processHandle,
        uint exitCode,
        out int win32Error);

    bool TryTerminateJob(
        SafeFileHandle jobHandle,
        uint exitCode,
        out int win32Error);

    bool TryReadActiveJobProcessCount(
        SafeFileHandle jobHandle,
        out uint activeProcesses,
        out int win32Error);

    bool TryGetExitCode(
        SafeProcessHandle processHandle,
        out uint exitCode,
        out int win32Error);
}

internal sealed class WindowsGuardianProcessRegistryV1
{
    private static readonly WindowsGuardianProcessRegistryV1 ProductionInstance =
        new(WindowsGuardianProcessSettlementNativeV1.Instance, startQuarantineWorker: true);

    private readonly object _gate = new();
    private readonly IWindowsGuardianProcessSettlementNativeV1 _native;
    private readonly bool _startQuarantineWorker;
    private WindowsGuardianProcessRootV1? _entry;
    private WindowsGuardianProcessRegistryHealthV1 _health;
    private bool _launchConsumed;

    private WindowsGuardianProcessRegistryV1(
        IWindowsGuardianProcessSettlementNativeV1 native,
        bool startQuarantineWorker)
    {
        _native = native ?? throw new ArgumentNullException(nameof(native));
        _startQuarantineWorker = startQuarantineWorker;
    }

    internal static WindowsGuardianProcessRegistryV1 Production => ProductionInstance;

    internal WindowsGuardianProcessRegistryHealthV1 Health
    {
        get
        {
            lock (_gate)
            {
                return _health;
            }
        }
    }

    internal int RetainedProcessCount
    {
        get
        {
            lock (_gate)
            {
                return _entry is null ? 0 : 1;
            }
        }
    }

#if CODEXGUARDIAN_TEST_FRIEND
    internal static WindowsGuardianProcessRegistryV1 CreateIsolatedForTests() =>
        new(WindowsGuardianProcessSettlementNativeV1.Instance, startQuarantineWorker: false);

    internal static WindowsGuardianProcessRegistryV1 CreateForTests(
        IWindowsGuardianProcessSettlementNativeV1 native,
        bool startQuarantineWorker = false) =>
        new(native, startQuarantineWorker);
#endif

    internal WindowsGuardianProcessRootV1 ReserveLaunch()
    {
        lock (_gate)
        {
            if (_entry is not null)
            {
                throw new BrokerControlSessionException(
                    "managed-guardian-process-slot-unavailable",
                    "This Broker epoch already owns or quarantines one Guardian process.");
            }

            if (_launchConsumed)
            {
                throw new BrokerControlSessionException(
                    "managed-guardian-process-launch-consumed",
                    "This Broker epoch already consumed its one Guardian clean launch.");
            }

            var root = new WindowsGuardianProcessRootV1(
                this,
                _native,
                _startQuarantineWorker);
            _entry = root;
            _launchConsumed = true;
            _health = WindowsGuardianProcessRegistryHealthV1.Reserved;
            return root;
        }
    }

    internal void MarkActive(WindowsGuardianProcessRootV1 root)
    {
        lock (_gate)
        {
            RequireEntry(root);
            if (_health != WindowsGuardianProcessRegistryHealthV1.Reserved)
            {
                throw new InvalidOperationException(
                    "The Guardian process registry did not have a reserved launch slot.");
            }

            _health = WindowsGuardianProcessRegistryHealthV1.Active;
        }
    }

    internal void MarkQuarantined(WindowsGuardianProcessRootV1 root)
    {
        lock (_gate)
        {
            RequireEntry(root);
            _health = WindowsGuardianProcessRegistryHealthV1.Quarantined;
        }
    }

    internal void Release(WindowsGuardianProcessRootV1 root)
    {
        lock (_gate)
        {
            RequireEntry(root);
            _entry = null;
            _health = WindowsGuardianProcessRegistryHealthV1.Empty;
        }
    }

    private void RequireEntry(WindowsGuardianProcessRootV1 root)
    {
        if (!ReferenceEquals(_entry, root))
        {
            throw new InvalidOperationException(
                "The Guardian process registry received a foreign slot owner.");
        }
    }
}

internal sealed class WindowsGuardianProcessRootV1
{
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const uint StillActive = 259;
    private const uint SettlementExitCode = 0xC0DE0016;
    private const uint SettlementWaitMilliseconds = 5000;
    private const int QuarantineRetryCount = 40;
    private static readonly TimeSpan QuarantineRetryDelay = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan QuarantineLateObservationWait = TimeSpan.FromSeconds(5);

    private enum RootState
    {
        Reserved,
        Active,
        Quarantined,
        Released
    }

    private readonly object _gate = new();
    private readonly WindowsGuardianProcessRegistryV1 _registry;
    private readonly IWindowsGuardianProcessSettlementNativeV1 _native;
    private readonly bool _startQuarantineWorker;
    private readonly TaskCompletionSource<BrokerGuardianProcessExitV1> _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private static readonly AsyncLocal<WindowsGuardianProcessRootV1?> SettlementOwner = new();
    private SafeFileHandle? _jobHandle;
    private SafeProcessHandle? _processHandle;
    private IRetainedPeerIdentityLease? _identityLease;
    private IWindowsGuardianProcessExitObserverV1? _exitObserver;
    private WindowsProcessIdentity? _initialIdentity;
    private Task? _observationTask;
    private Task? _settlementTask;
    private Task? _quarantineWorker;
    private Exception? _stickyFailure;
    private RootState _state = RootState.Reserved;
    private uint _processId;
    private bool _assignedToJob;
    private bool _launchVerified;

    internal WindowsGuardianProcessRootV1(
        WindowsGuardianProcessRegistryV1 registry,
        IWindowsGuardianProcessSettlementNativeV1 native,
        bool startQuarantineWorker)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _native = native ?? throw new ArgumentNullException(nameof(native));
        _startQuarantineWorker = startQuarantineWorker;
    }

    internal Task<BrokerGuardianProcessExitV1> Completion => _completion.Task;

    internal bool CleanEnvironmentVerified
    {
        get
        {
            lock (_gate)
            {
                ThrowUnlessVerified();
                return true;
            }
        }
    }

    internal bool RuntimeNamespaceClosed
    {
        get
        {
            lock (_gate)
            {
                ThrowUnlessVerified();
                return true;
            }
        }
    }

    internal void AttachJob(SafeFileHandle jobHandle)
    {
        ArgumentNullException.ThrowIfNull(jobHandle);
        if (jobHandle.IsInvalid || jobHandle.IsClosed)
        {
            throw new ArgumentException("A valid Guardian ownership job is required.", nameof(jobHandle));
        }

        lock (_gate)
        {
            RequireState(RootState.Reserved);
            if (_jobHandle is not null)
            {
                throw new InvalidOperationException("The Guardian ownership job was already attached.");
            }

            _jobHandle = jobHandle;
        }
    }

    internal void AttachProcess(SafeProcessHandle processHandle, uint processId)
    {
        ArgumentNullException.ThrowIfNull(processHandle);
        if (processHandle.IsInvalid || processHandle.IsClosed || processId == 0)
        {
            throw new ArgumentException("A valid exact Guardian process is required.", nameof(processHandle));
        }

        lock (_gate)
        {
            RequireState(RootState.Reserved);
            if (_processHandle is not null)
            {
                throw new InvalidOperationException("The exact Guardian process was already attached.");
            }

            _processHandle = processHandle;
            _processId = processId;
            _state = RootState.Active;
        }

        _registry.MarkActive(this);
    }

    internal void StartObservation()
    {
        lock (_gate)
        {
            RequireState(RootState.Active);
            if (_exitObserver is not null)
            {
                throw new InvalidOperationException("The Guardian exit observer was already attached.");
            }

            var processHandle = _processHandle ?? throw new InvalidOperationException(
                "The exact Guardian process is unavailable for observation.");
            try
            {
                var observer = _native.ObserveExactProcess(processHandle) ??
                    throw new IOException(
                        "The Guardian process observer factory returned no authority.");
                _exitObserver = observer;
                _ = observer.Completion ?? throw new IOException(
                    "The Guardian process observer returned no completion task.");
                _observationTask = PublishObservationAsync(observer);
            }
            catch (Exception exception)
            {
                _completion.TrySetException(exception);
                throw;
            }
        }
    }

    internal SafeFileHandle BorrowJobHandle()
    {
        lock (_gate)
        {
            ThrowIfSettlementStarted();
            return _jobHandle ?? throw new InvalidOperationException(
                "The Guardian ownership job is unavailable.");
        }
    }

    internal SafeProcessHandle BorrowProcessHandle()
    {
        lock (_gate)
        {
            ThrowIfSettlementStarted();
            return _processHandle ?? throw new InvalidOperationException(
                "The exact Guardian process is unavailable.");
        }
    }

    internal void MarkAssignedToJob()
    {
        lock (_gate)
        {
            RequireState(RootState.Active);
            ThrowIfSettlementStarted();
            if (_assignedToJob)
            {
                throw new InvalidOperationException("The Guardian process was already assigned to its job.");
            }

            _assignedToJob = true;
        }
    }

    internal void AttachIdentity(
        IRetainedPeerIdentityLease identityLease,
        WindowsProcessIdentity initialIdentity)
    {
        ArgumentNullException.ThrowIfNull(identityLease);
        ArgumentNullException.ThrowIfNull(initialIdentity);
        lock (_gate)
        {
            RequireState(RootState.Active);
            ThrowIfSettlementStarted();
            if (_identityLease is not null)
            {
                throw new InvalidOperationException("The Guardian retained identity was already attached.");
            }

            _identityLease = identityLease;
            _initialIdentity = initialIdentity;
        }
    }

    internal void MarkLaunchVerified()
    {
        lock (_gate)
        {
            RequireState(RootState.Active);
            ThrowIfSettlementStarted();
            if (_launchVerified)
            {
                throw new InvalidOperationException(
                    "The Guardian clean launch was already marked verified.");
            }

            if (!_assignedToJob || _identityLease is null || _exitObserver is null)
            {
                throw new InvalidOperationException(
                    "The Guardian launch cannot be verified before job identity and exit observation attach.");
            }

            _launchVerified = true;
        }
    }

    internal WindowsProcessIdentity Revalidate()
    {
        lock (_gate)
        {
            ThrowUnlessVerified();
            ThrowIfSettlementStarted();
            var identityLease = _identityLease!;
            var initialIdentity = _initialIdentity!;
            if (!identityLease.IsAlive)
            {
                throw new BrokerControlSessionException(
                    "managed-guardian-process-exited",
                    "The Broker-owned Guardian process exited during identity revalidation.");
            }

            var current = identityLease.Capture();
            RequireExactIdentity(initialIdentity, current);
            return current;
        }
    }

    internal Task StopAsync(BrokerGuardianProcessStopRequestV1 stopRequest)
    {
        if (stopRequest == BrokerGuardianProcessStopRequestV1.None)
        {
            throw new ArgumentOutOfRangeException(nameof(stopRequest));
        }

        lock (_gate)
        {
            if (_settlementTask is not null)
            {
                if (ReferenceEquals(SettlementOwner.Value, this))
                {
                    return Task.FromException(new InvalidOperationException(
                        "Guardian process settlement cannot synchronously wait on itself."));
                }

                return _settlementTask;
            }

            if (_state == RootState.Released)
            {
                return Task.CompletedTask;
            }

            _settlementTask = Task.Run(SettleCore);
            return _settlementTask;
        }
    }

    private async Task PublishObservationAsync(IWindowsGuardianProcessExitObserverV1 observer)
    {
        try
        {
            var exitCode = await observer.Completion.ConfigureAwait(false);
            uint processId;
            lock (_gate)
            {
                processId = _processId;
            }

            _completion.TrySetResult(new BrokerGuardianProcessExitV1(
                processId,
                exitCode,
                BrokerGuardianProcessStopRequestV1.None));
        }
        catch (Exception exception)
        {
            _completion.TrySetException(exception);
        }
    }

    private void SettleCore()
    {
        var previousOwner = SettlementOwner.Value;
        SettlementOwner.Value = this;
        try
        {
            try
            {
                SettleCoreOwned();
            }
            catch (Exception failure)
            {
                var quarantineFailure = EnsureQuarantineForUnexpectedFailure(failure);
                ExceptionDispatchInfo.Capture(quarantineFailure).Throw();
            }
        }
        finally
        {
            SettlementOwner.Value = previousOwner;
        }
    }

    private void SettleCoreOwned()
    {
        SafeProcessHandle? processHandle;
        lock (_gate)
        {
            processHandle = _processHandle;
        }

        if (processHandle is null)
        {
            _completion.TrySetException(new BrokerControlSessionException(
                "managed-guardian-process-not-created",
                "The reserved Guardian launch ended before an exact process was created."));
            var emptyCleanupFailure = ReleaseResources();
            if (emptyCleanupFailure is not null)
            {
                throw EnterQuarantine(emptyCleanupFailure, startWorker: true);
            }

            return;
        }

        if (!TrySettleAuthority(SettlementWaitMilliseconds, out var settlementFailure))
        {
            throw EnterQuarantine(
                settlementFailure ?? new IOException(
                    "The exact Guardian process settlement failed without a bounded reason."),
                startWorker: true);
        }

        var observationFailure = CompleteExitEvidence();
        if (observationFailure is not null)
        {
            throw observationFailure;
        }

        var observationDrainFailure = WaitForObservationTerminal(SettlementWaitMilliseconds);
        if (observationDrainFailure is not null)
        {
            throw EnterQuarantine(observationDrainFailure, startWorker: true);
        }

        var cleanupFailure = ReleaseResources();
        if (cleanupFailure is not null)
        {
            throw EnterQuarantine(cleanupFailure, startWorker: true);
        }

    }

    private bool TrySettleAuthority(uint waitMilliseconds, out Exception? failure)
    {
        failure = null;
        SafeProcessHandle processHandle;
        SafeFileHandle? jobHandle;
        bool assignedToJob;
        lock (_gate)
        {
            processHandle = _processHandle ?? throw new InvalidOperationException(
                "The exact Guardian process is unavailable for settlement.");
            jobHandle = _jobHandle;
            assignedToJob = _assignedToJob;
        }

        var stopwatch = Stopwatch.StartNew();
        Exception? initialProofFailure = null;
        var initialWait = _native.WaitProcess(processHandle, 0, out var waitError);
        if (!TryClassifyWait(initialWait, waitError, out var processExited, out initialProofFailure))
        {
            processExited = false;
        }

        uint activeProcesses = 0;
        if (assignedToJob && jobHandle is null)
        {
            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                initialProofFailure,
                new IOException("The assigned Guardian ownership job is unavailable."));
            return false;
        }

        if (assignedToJob && processExited)
        {
            if (!_native.TryReadActiveJobProcessCount(
                    jobHandle!,
                    out activeProcesses,
                    out var queryError))
            {
                initialProofFailure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    initialProofFailure,
                    new Win32Exception(
                        queryError,
                        "Unable to query the Guardian ownership job process count."));
            }
        }

        if (processExited &&
            (!assignedToJob || activeProcesses == 0 && initialProofFailure is null))
        {
            return true;
        }

        bool terminationAccepted;
        int terminationError;
        if (assignedToJob)
        {
            terminationAccepted = _native.TryTerminateJob(
                jobHandle!,
                SettlementExitCode,
                out terminationError);
        }
        else
        {
            terminationAccepted = _native.TryTerminateProcess(
                processHandle,
                SettlementExitCode,
                out terminationError);
        }

        if (!terminationAccepted)
        {
            var terminationFailure = new Win32Exception(
                terminationError,
                assignedToJob
                    ? "Unable to terminate the exact Guardian ownership job."
                    : "Unable to terminate the exact suspended Guardian process.");
            if (!TryObserveTerminationRace(
                    processHandle,
                    jobHandle,
                    assignedToJob,
                    terminationFailure,
                    out failure))
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    initialProofFailure,
                    failure);
                return false;
            }

            return true;
        }

        if (!processExited)
        {
            var remaining = RemainingMilliseconds(stopwatch, waitMilliseconds);
            if (remaining == 0)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    initialProofFailure,
                    new TimeoutException(
                        "The exact Guardian process did not exit within the settlement bound."));
                return false;
            }

            var wait = _native.WaitProcess(
                processHandle,
                remaining,
                out waitError);
            if (!TryClassifyWait(wait, waitError, out processExited, out failure) ||
                !processExited)
            {
                failure ??= new TimeoutException(
                    "The exact Guardian process did not exit within the settlement bound.");
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    initialProofFailure,
                    failure);
                return false;
            }
        }

        if (!assignedToJob)
        {
            return true;
        }

        while (true)
        {
            if (!_native.TryReadActiveJobProcessCount(
                    jobHandle!,
                    out activeProcesses,
                    out var queryError))
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    initialProofFailure,
                    new Win32Exception(
                        queryError,
                        "Unable to prove the Guardian ownership job is empty."));
                return false;
            }

            if (activeProcesses == 0)
            {
                return true;
            }

            if (stopwatch.ElapsedMilliseconds >= waitMilliseconds)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    initialProofFailure,
                    new TimeoutException(
                        "The Guardian ownership job retained child processes after termination."));
                return false;
            }

            Thread.Sleep(checked((int)Math.Min(
                20u,
                RemainingMilliseconds(stopwatch, waitMilliseconds))));
        }
    }

    private bool TryObserveTerminationRace(
        SafeProcessHandle processHandle,
        SafeFileHandle? jobHandle,
        bool assignedToJob,
        Exception terminationFailure,
        out Exception? failure)
    {
        var wait = _native.WaitProcess(processHandle, 0, out var waitError);
        if (!TryClassifyWait(wait, waitError, out var processExited, out failure))
        {
            return false;
        }

        if (!processExited)
        {
            failure = terminationFailure;
            return false;
        }

        if (!assignedToJob)
        {
            return true;
        }

        if (jobHandle is null)
        {
            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                terminationFailure,
                new IOException("The assigned Guardian ownership job is unavailable."));
            return false;
        }

        if (!_native.TryReadActiveJobProcessCount(
                jobHandle,
                out var activeProcesses,
                out var queryError))
        {
            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                terminationFailure,
                new Win32Exception(
                    queryError,
                    "Unable to query the Guardian ownership job after a termination race."));
            return false;
        }

        if (activeProcesses != 0)
        {
            failure = terminationFailure;
            return false;
        }

        return true;
    }

    private static bool TryClassifyWait(
        uint wait,
        int win32Error,
        out bool processExited,
        out Exception? failure)
    {
        processExited = false;
        failure = null;
        switch (wait)
        {
            case WaitObject0:
                processExited = true;
                return true;
            case WaitTimeout:
                return true;
            case WaitFailed:
                failure = new Win32Exception(
                    win32Error,
                    "Unable to wait for the exact Guardian process.");
                return false;
            default:
                failure = new IOException(
                    "Windows returned an unexpected Guardian process wait result: 0x" +
                    wait.ToString("X8") + ".");
                return false;
        }
    }

    private Exception? CompleteExitEvidence()
    {
        if (_completion.Task.IsCompleted)
        {
            return _completion.Task.IsFaulted
                ? _completion.Task.Exception?.InnerException ?? _completion.Task.Exception
                : null;
        }

        SafeProcessHandle processHandle;
        uint processId;
        lock (_gate)
        {
            processHandle = _processHandle ?? throw new InvalidOperationException(
                "The exact Guardian process is unavailable for exit evidence.");
            processId = _processId;
        }

        if (!_native.TryGetExitCode(processHandle, out var exitCode, out var exitError))
        {
            var failure = new Win32Exception(
                exitError,
                "Unable to read the exact Guardian process exit code.");
            _completion.TrySetException(failure);
            return failure;
        }

        if (exitCode == StillActive)
        {
            var failure = new IOException(
                "The signaled Guardian process reported STILL_ACTIVE.");
            _completion.TrySetException(failure);
            return failure;
        }

        _completion.TrySetResult(new BrokerGuardianProcessExitV1(
            processId,
            exitCode,
            BrokerGuardianProcessStopRequestV1.None));
        return null;
    }

    private Exception? ReleaseResources()
    {
        IWindowsGuardianProcessExitObserverV1? observer;
        IRetainedPeerIdentityLease? identityLease;
        SafeProcessHandle? processHandle;
        SafeFileHandle? jobHandle;
        lock (_gate)
        {
            observer = _exitObserver;
            identityLease = _identityLease;
            processHandle = _processHandle;
            jobHandle = _jobHandle;
        }

        if (observer is not null)
        {
            var observationDrainFailure = WaitForObservationTerminal(
                SettlementWaitMilliseconds);
            if (observationDrainFailure is not null)
            {
                return observationDrainFailure;
            }
        }

        try
        {
            observer?.Dispose();
            lock (_gate)
            {
                _exitObserver = null;
                _observationTask = null;
            }
        }
        catch (Exception exception)
        {
            return exception;
        }

        try
        {
            identityLease?.Dispose();
            lock (_gate)
            {
                _identityLease = null;
            }
        }
        catch (Exception exception)
        {
            return exception;
        }

        try
        {
            processHandle?.Dispose();
            lock (_gate)
            {
                _processHandle = null;
            }
        }
        catch (Exception exception)
        {
            return exception;
        }

        try
        {
            jobHandle?.Dispose();
            lock (_gate)
            {
                _jobHandle = null;
            }
        }
        catch (Exception exception)
        {
            return exception;
        }

        try
        {
            _registry.Release(this);
        }
        catch (Exception exception)
        {
            return exception;
        }

        lock (_gate)
        {
            _state = RootState.Released;
        }

        return null;
    }

    private Exception EnsureQuarantineForUnexpectedFailure(Exception failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        try
        {
            return EnterQuarantine(failure, startWorker: true);
        }
        catch (Exception quarantineTransitionFailure)
        {
            BrokerControlSessionException sticky;
            lock (_gate)
            {
                if (_stickyFailure is BrokerControlSessionException existing)
                {
                    sticky = existing;
                }
                else
                {
                    sticky = new BrokerControlSessionException(
                        "managed-guardian-process-quarantined",
                        "The exact Guardian process authority could not be completely settled.",
                        failure);
                    _stickyFailure = sticky;
                    _state = RootState.Quarantined;
                }
            }

            if (!ReferenceEquals(quarantineTransitionFailure, sticky))
            {
                PreserveStickySecondary(quarantineTransitionFailure);
            }

            return sticky;
        }
    }

    private Exception EnterQuarantine(Exception failure, bool startWorker)
    {
        ArgumentNullException.ThrowIfNull(failure);
        BrokerControlSessionException sticky;
        lock (_gate)
        {
            if (_stickyFailure is BrokerControlSessionException existing)
            {
                return existing;
            }

            sticky = new BrokerControlSessionException(
                "managed-guardian-process-quarantined",
                "The exact Guardian process authority could not be completely settled.",
                failure);
            _stickyFailure = sticky;
            _state = RootState.Quarantined;
        }

        _registry.MarkQuarantined(this);
        if (startWorker && _startQuarantineWorker)
        {
            try
            {
                lock (_gate)
                {
                    _quarantineWorker ??= Task.Run(DrainQuarantineSafelyAsync);
                }
            }
            catch (Exception workerStartFailure)
            {
                PreserveStickySecondary(workerStartFailure);
            }
        }

        return sticky;
    }

    private async Task DrainQuarantineSafelyAsync()
    {
        try
        {
            await DrainQuarantineAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            PreserveStickySecondary(exception);
        }
    }

    private async Task DrainQuarantineAsync()
    {
        for (var attempt = 0; attempt < QuarantineRetryCount; attempt++)
        {
            await Task.Delay(QuarantineRetryDelay).ConfigureAwait(false);
            if (!TryDrainQuarantineOnce())
            {
                continue;
            }

            return;
        }

        Task<uint>? observedExit;
        lock (_gate)
        {
            observedExit = _exitObserver?.Completion;
        }

        if (observedExit is not null)
        {
            try
            {
                _ = await observedExit
                    .WaitAsync(QuarantineLateObservationWait)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException exception)
            {
                PreserveStickySecondary(new TimeoutException(
                    "The quarantined Guardian process observation exceeded its late-drain bound.",
                    exception));
            }
            catch (Exception exception)
            {
                PreserveStickySecondary(exception);
            }
        }

        _ = TryDrainQuarantineOnce();
    }

    private bool TryDrainQuarantineOnce()
    {
        try
        {
            bool processAuthorityPresent;
            lock (_gate)
            {
                if (_state == RootState.Released)
                {
                    return true;
                }

                processAuthorityPresent = _processHandle is not null;
            }

            if (!processAuthorityPresent)
            {
                var reservedCleanupFailure = ReleaseResources();
                PreserveStickySecondary(reservedCleanupFailure);
                return reservedCleanupFailure is null;
            }

            if (!TrySettleAuthority(
                    checked((uint)QuarantineRetryDelay.TotalMilliseconds),
                    out var settlementFailure))
            {
                PreserveStickySecondary(settlementFailure);
                return false;
            }

            var evidenceFailure = CompleteExitEvidence();
            if (evidenceFailure is not null)
            {
                PreserveStickySecondary(evidenceFailure);
                return false;
            }

            var observationDrainFailure = WaitForObservationTerminal(
                checked((uint)QuarantineRetryDelay.TotalMilliseconds));
            if (observationDrainFailure is not null)
            {
                PreserveStickySecondary(observationDrainFailure);
                return false;
            }

            var cleanupFailure = ReleaseResources();
            PreserveStickySecondary(cleanupFailure);
            return cleanupFailure is null;
        }
        catch (Exception exception)
        {
            PreserveStickySecondary(exception);
            return false;
        }
    }

    private Exception? WaitForObservationTerminal(uint waitMilliseconds)
    {
        Task? observationTask;
        lock (_gate)
        {
            observationTask = _observationTask;
        }

        if (observationTask is null)
        {
            return null;
        }

        try
        {
            if (!observationTask.Wait(TimeSpan.FromMilliseconds(waitMilliseconds)))
            {
                return new TimeoutException(
                    "The exact Guardian process observation did not drain within the settlement bound.");
            }

            observationTask.GetAwaiter().GetResult();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private void PreserveStickySecondary(Exception? failure)
    {
        if (failure is null)
        {
            return;
        }

        lock (_gate)
        {
            if (_stickyFailure is not null &&
                _stickyFailure.Data[BrokerControlFailureArbitration.CleanupFailureDataKey]
                    is null)
            {
                _stickyFailure.Data[
                    BrokerControlFailureArbitration.CleanupFailureDataKey] = failure;
            }
        }
    }

    private static uint RemainingMilliseconds(Stopwatch stopwatch, uint totalMilliseconds)
    {
        var remaining = (long)totalMilliseconds - stopwatch.ElapsedMilliseconds;
        return remaining <= 0
            ? 0
            : checked((uint)Math.Min(remaining, uint.MaxValue));
    }

    private void ThrowUnlessVerified()
    {
        if (_state != RootState.Active || !_launchVerified)
        {
            throw new ObjectDisposedException(nameof(WindowsGuardianProcessRootV1));
        }
    }

    private void ThrowIfSettlementStarted()
    {
        if (_settlementTask is not null || _state is RootState.Quarantined or RootState.Released)
        {
            throw new ObjectDisposedException(nameof(WindowsGuardianProcessRootV1));
        }
    }

    private void RequireState(RootState state)
    {
        if (_state != state)
        {
            throw new InvalidOperationException(
                "The Guardian process authority is in an invalid state: " + _state + ".");
        }
    }

    private static void RequireExactIdentity(
        WindowsProcessIdentity expected,
        WindowsProcessIdentity actual)
    {
        if (expected.ProcessId != actual.ProcessId ||
            expected.CreationTimeUtc != actual.CreationTimeUtc ||
            expected.KernelSessionId != actual.KernelSessionId ||
            expected.Token != actual.Token ||
            expected.AppModel != actual.AppModel ||
            !string.Equals(
                expected.FinalImagePath,
                actual.FinalImagePath,
                StringComparison.OrdinalIgnoreCase) ||
            expected.ImageFileObjectIsExact != actual.ImageFileObjectIsExact ||
            expected.ReleaseRoot != actual.ReleaseRoot ||
            !expected.Artifacts.SequenceEqual(actual.Artifacts))
        {
            throw new BrokerControlSessionException(
                "managed-guardian-process-drift",
                "The Broker-owned Guardian process identity changed after clean launch.");
        }
    }
}

internal sealed class WindowsGuardianProcessSettlementNativeV1 :
    IWindowsGuardianProcessSettlementNativeV1
{
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const uint StillActive = 259;
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint Synchronize = 0x00100000;
    private const int JobObjectBasicAccountingInformation = 1;

    internal static WindowsGuardianProcessSettlementNativeV1 Instance { get; } = new();

    private WindowsGuardianProcessSettlementNativeV1()
    {
    }

    public IWindowsGuardianProcessExitObserverV1 ObserveExactProcess(
        SafeProcessHandle processHandle) =>
        new ProcessExitObserver(
            DuplicateObservationHandle(processHandle),
            ProcessObserverPlatform.Instance);

#if CODEXGUARDIAN_TEST_FRIEND
    internal static IWindowsGuardianProcessExitObserverV1 CreateObserverForTests(
        SafeProcessHandle processHandle,
        IWindowsGuardianProcessObserverPlatformV1 platform) =>
        new ProcessExitObserver(processHandle, platform);
#endif

    public uint WaitProcess(
        SafeProcessHandle processHandle,
        uint milliseconds,
        out int win32Error)
    {
        var result = WaitForSingleObject(processHandle, milliseconds);
        win32Error = result == WaitFailed ? Marshal.GetLastWin32Error() : 0;
        return result;
    }

    public bool TryTerminateProcess(
        SafeProcessHandle processHandle,
        uint exitCode,
        out int win32Error)
    {
        var result = TerminateProcess(processHandle, exitCode);
        win32Error = result ? 0 : Marshal.GetLastWin32Error();
        return result;
    }

    public bool TryTerminateJob(
        SafeFileHandle jobHandle,
        uint exitCode,
        out int win32Error)
    {
        var result = TerminateJobObject(jobHandle, exitCode);
        win32Error = result ? 0 : Marshal.GetLastWin32Error();
        return result;
    }

    public bool TryReadActiveJobProcessCount(
        SafeFileHandle jobHandle,
        out uint activeProcesses,
        out int win32Error)
    {
        var information = new JOBOBJECT_BASIC_ACCOUNTING_INFORMATION();
        var result = QueryInformationJobObject(
            jobHandle,
            JobObjectBasicAccountingInformation,
            ref information,
            checked((uint)Marshal.SizeOf<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>()),
            IntPtr.Zero);
        activeProcesses = result ? information.ActiveProcesses : 0;
        win32Error = result ? 0 : Marshal.GetLastWin32Error();
        return result;
    }

    public bool TryGetExitCode(
        SafeProcessHandle processHandle,
        out uint exitCode,
        out int win32Error)
    {
        var result = GetExitCodeProcess(processHandle, out exitCode);
        win32Error = result ? 0 : Marshal.GetLastWin32Error();
        return result;
    }

    private static SafeProcessHandle DuplicateObservationHandle(
        SafeProcessHandle processHandle)
    {
        ArgumentNullException.ThrowIfNull(processHandle);
        var currentProcess = GetCurrentProcess();
        if (!DuplicateHandle(
                currentProcess,
                processHandle,
                currentProcess,
                out var duplicate,
                ProcessQueryLimitedInformation | Synchronize,
                inheritHandle: false,
                options: 0))
        {
            var error = Marshal.GetLastWin32Error();
            duplicate?.Dispose();
            throw new Win32Exception(
                error,
                "Unable to duplicate the exact Guardian process for exit observation.");
        }

        if (duplicate.IsInvalid)
        {
            duplicate.Dispose();
            throw new Win32Exception(
                "Windows returned an invalid Guardian process observation handle.");
        }

        return duplicate;
    }

    private sealed class ProcessExitObserver : IWindowsGuardianProcessExitObserverV1
    {
        private const int DisposeDrainMilliseconds = 5000;
        private static readonly AsyncLocal<ProcessExitObserver?> ActiveDispose = new();
        private readonly object _gate = new();
        private readonly TaskCompletionSource<uint> _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _callbackReturned = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ManualResetEvent _unregisterCompleted = new(initialState: false);
        private readonly IWindowsGuardianProcessObserverPlatformV1 _platform;
        private SafeProcessHandle? _processHandle;
        private EventWaitHandle? _waitHandle;
        private IWindowsGuardianRegisteredWaitV1? _registration;
        private Task<Exception?>? _disposeTask;

        internal ProcessExitObserver(
            SafeProcessHandle processHandle,
            IWindowsGuardianProcessObserverPlatformV1 platform)
        {
            _platform = platform ?? throw new ArgumentNullException(nameof(platform));
            _processHandle = processHandle;
            Completion = _completion.Task;
            try
            {
                _waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset)
                {
                    SafeWaitHandle = new SafeWaitHandle(
                        processHandle.DangerousGetHandle(),
                        ownsHandle: false)
                };
                var registration = _platform.Register(
                    _waitHandle,
                    OnProcessExited) ?? throw new InvalidOperationException(
                        "The Guardian process observer platform returned no registration authority.");
                _registration = registration;
            }
            catch
            {
                try
                {
                    var registration = Volatile.Read(ref _registration);
                    if (registration is not null)
                    {
                        var unregisterAccepted = registration.Unregister(_unregisterCompleted);
                        if (unregisterAccepted)
                        {
                            _ = _unregisterCompleted.WaitOne(DisposeDrainMilliseconds);
                        }
                    }
                }
                catch
                {
                    // The constructor is already failing; the owning root will
                    // quarantine its primary authority if this path is reached.
                }

                _waitHandle?.Dispose();
                _processHandle?.Dispose();
                _unregisterCompleted.Dispose();
                throw;
            }
        }

        public Task<uint> Completion { get; }

        public void Dispose()
        {
            if (!Completion.IsCompleted)
            {
                throw new InvalidOperationException(
                    "A pending Guardian process observer cannot release exact authority.");
            }

            Task<Exception?> disposeTask;
            TaskCompletionSource<Exception?>? winner = null;
            lock (_gate)
            {
                if (_disposeTask is null)
                {
                    winner = new TaskCompletionSource<Exception?>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    _disposeTask = winner.Task;
                }

                disposeTask = _disposeTask;
            }

            if (winner is null)
            {
                if (ReferenceEquals(ActiveDispose.Value, this))
                {
                    throw new InvalidOperationException(
                        "Guardian process observer disposal cannot synchronously wait on itself.");
                }

                Exception? followerFailure;
                try
                {
                    followerFailure = disposeTask
                        .WaitAsync(TimeSpan.FromMilliseconds(DisposeDrainMilliseconds))
                        .GetAwaiter()
                        .GetResult();
                }
                catch (TimeoutException exception)
                {
                    throw new InvalidOperationException(
                        "Guardian process observer disposal wait timed out.",
                        exception);
                }

                if (followerFailure is not null)
                {
                    ExceptionDispatchInfo.Capture(followerFailure).Throw();
                }

                return;
            }

            var previousOwner = ActiveDispose.Value;
            ActiveDispose.Value = this;
            Exception? failure = null;
            try
            {
                failure = DisposeCore();
            }
            catch (Exception exception)
            {
                failure = exception;
            }
            finally
            {
                ActiveDispose.Value = previousOwner;
                winner.TrySetResult(failure);
                if (failure is not null)
                {
                    lock (_gate)
                    {
                        if (ReferenceEquals(_disposeTask, disposeTask))
                        {
                            _disposeTask = null;
                        }
                    }
                }
            }

            if (failure is not null)
            {
                ExceptionDispatchInfo.Capture(failure).Throw();
            }
        }

        private void OnProcessExited(object? state, bool timedOut)
        {
            Exception? failure = null;
            uint exitCode = 0;
            try
            {
                if (timedOut)
                {
                    throw new TimeoutException(
                        "The infinite Guardian process exit registration timed out.");
                }

                var processHandle = Volatile.Read(ref _processHandle) ??
                    throw new ObjectDisposedException(nameof(ProcessExitObserver));
                if (!_platform.TryGetExitCode(
                        processHandle,
                        out exitCode,
                        out var exitError))
                {
                    throw new Win32Exception(
                        exitError,
                        "Unable to read the observed Guardian process exit code.");
                }

                if (exitCode == StillActive)
                {
                    throw new IOException(
                        "The signaled Guardian process reported STILL_ACTIVE.");
                }
            }
            catch (Exception exception)
            {
                failure = exception;
            }

            if (failure is null)
            {
                _completion.TrySetResult(exitCode);
            }
            else
            {
                _completion.TrySetException(failure);
            }

            // Resource release is deliberately owned by Dispose. Publishing the
            // completion before this barrier lets Dispose wait for the callback
            // to return before closing the duplicated exact process handle.
            _callbackReturned.TrySetResult();
        }

        private Exception? DisposeCore()
        {
            IWindowsGuardianRegisteredWaitV1? registration;
            EventWaitHandle? waitHandle;
            SafeProcessHandle? processHandle;
            lock (_gate)
            {
                registration = _registration;
                waitHandle = _waitHandle;
                processHandle = _processHandle;
            }

            if (registration is not null)
            {
                bool unregisterAccepted;
                try
                {
                    unregisterAccepted = registration.Unregister(_unregisterCompleted);
                }
                catch (Exception exception)
                {
                    return exception;
                }

                if (unregisterAccepted)
                {
                    if (!_unregisterCompleted.WaitOne(DisposeDrainMilliseconds))
                    {
                        return new TimeoutException(
                            "The exact Guardian process observer registration did not drain.");
                    }
                }
                else if (!_callbackReturned.Task.Wait(
                             TimeSpan.FromMilliseconds(DisposeDrainMilliseconds)))
                {
                    return new TimeoutException(
                        "The exact Guardian process observer callback did not return.");
                }
            }

            if (!_callbackReturned.Task.Wait(
                    TimeSpan.FromMilliseconds(DisposeDrainMilliseconds)))
            {
                return new TimeoutException(
                    "The exact Guardian process observer callback did not return.");
            }

            try
            {
                waitHandle?.Dispose();
                processHandle?.Dispose();
                _unregisterCompleted.Dispose();
            }
            catch (Exception exception)
            {
                return exception;
            }

            lock (_gate)
            {
                _registration = null;
                _waitHandle = null;
                _processHandle = null;
            }

            return null;
        }
    }

    private sealed class ProcessObserverPlatform :
        IWindowsGuardianProcessObserverPlatformV1
    {
        internal static ProcessObserverPlatform Instance { get; } = new();

        private ProcessObserverPlatform()
        {
        }

        public IWindowsGuardianRegisteredWaitV1 Register(
            WaitHandle waitHandle,
            WaitOrTimerCallback callback) =>
            new RegisteredWait(ThreadPool.RegisterWaitForSingleObject(
                waitHandle,
                callback,
                state: null,
                Timeout.InfiniteTimeSpan,
                executeOnlyOnce: true));

        public bool TryGetExitCode(
            SafeProcessHandle processHandle,
            out uint exitCode,
            out int win32Error)
        {
            var result = GetExitCodeProcess(processHandle, out exitCode);
            win32Error = result ? 0 : Marshal.GetLastWin32Error();
            return result;
        }
    }

    private sealed class RegisteredWait : IWindowsGuardianRegisteredWaitV1
    {
        private readonly RegisteredWaitHandle _registration;

        internal RegisteredWait(RegisteredWaitHandle registration)
        {
            _registration = registration ?? throw new ArgumentNullException(nameof(registration));
        }

        public bool Unregister(WaitHandle completionEvent) =>
            _registration.Unregister(completionEvent);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        internal long TotalUserTime;
        internal long TotalKernelTime;
        internal long ThisPeriodTotalUserTime;
        internal long ThisPeriodTotalKernelTime;
        internal uint TotalPageFaultCount;
        internal uint TotalProcesses;
        internal uint ActiveProcesses;
        internal uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        SafeProcessHandle handle,
        uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(
        SafeProcessHandle process,
        out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(
        SafeProcessHandle process,
        uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(
        SafeFileHandle job,
        uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        ref JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information,
        uint informationLength,
        IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess,
        SafeProcessHandle sourceHandle,
        IntPtr targetProcess,
        out SafeProcessHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);
}
