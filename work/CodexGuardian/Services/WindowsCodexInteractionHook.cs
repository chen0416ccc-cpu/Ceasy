using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using System.Windows.Automation;

namespace CodexGuardian.Services;

internal enum RecoveryInterferenceStatus
{
    Clear,
    Editing,
    Unknown
}

internal sealed record RecoveryInterferenceSnapshot(
    RecoveryInterferenceStatus Status,
    string Detail,
    bool HasFocusedDraft,
    DateTimeOffset ObservedAt,
    long Version = 0);

internal interface IRecoveryInterferenceGuard
{
    Task<RecoveryInterferenceSnapshot> CheckAsync(
        string threadId,
        CancellationToken cancellationToken);

    Task WaitForChangeAsync(long observedVersion, CancellationToken cancellationToken);
}

public interface IEnhancedObservationStatus
{
    bool IsAvailable { get; }

    EnhancedObservationMode Mode { get; }

    event EventHandler<EventArgs>? AvailabilityChanged;
}

internal sealed class WindowsCodexInteractionHook :
    IRecoveryInterferenceGuard,
    IEnhancedObservationStatus,
    IAsyncDisposable
{
    private const uint EventSystemForeground = 0x0003;
    private const uint EventObjectFocus = 0x8005;
    private const uint EventObjectValueChange = 0x800E;
    private const uint WineventOutOfContext = 0x0000;
    private const uint WineventSkipOwnProcess = 0x0002;
    private const uint DesktopReadObjects = 0x0001;
    private const int UoiName = 2;
    private static readonly TimeSpan ObservationTimeout = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan ShutdownWaitTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan DiagnosticInterval = TimeSpan.FromMinutes(1);
    private readonly GuardianLog _log;
    private readonly WinEventDelegate _callback;
    private readonly Channel<byte> _events = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
    {
        SingleReader = true,
        SingleWriter = false,
        AllowSynchronousContinuations = false,
        FullMode = BoundedChannelFullMode.DropWrite
    });
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _changeSync = new();
    private readonly SemaphoreSlim _inspectionGate = new(1, 1);
    private readonly List<IntPtr> _hooks = [];
    private RecoveryInterferenceSnapshot _snapshot = new(
        RecoveryInterferenceStatus.Unknown,
        "Codex editor observation has not started.",
        false,
        DateTimeOffset.MinValue);
    private TaskCompletionSource _changed = NewChangeCompletion();
    private Task? _worker;
    private long _winEventCount;
    private long _coalescedEventCount;
    private long _observationCount;
    private long _timeoutCount;
    private long _lastDiagnosticTimestamp = Stopwatch.GetTimestamp();
    private int _hookCount;
    private int _observationHealthy;
    private int _started;
    private int _disposed;

    internal WindowsCodexInteractionHook(GuardianLog log)
    {
        _log = log;
        _callback = OnWinEvent;
    }

    public bool IsAvailable =>
        Volatile.Read(ref _disposed) == 0 &&
        Volatile.Read(ref _hookCount) == 3 &&
        Volatile.Read(ref _observationHealthy) != 0 &&
        _worker is { IsCompleted: false };

    public EnhancedObservationMode Mode => IsAvailable
        ? EnhancedObservationMode.WindowsComposer
        : EnhancedObservationMode.Unavailable;

    public event EventHandler<EventArgs>? AvailabilityChanged;

    internal bool Start()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            return _hooks.Count > 0;
        }

        foreach (var eventId in new[] { EventSystemForeground, EventObjectFocus, EventObjectValueChange })
        {
            var hook = SetWinEventHook(
                eventId,
                eventId,
                IntPtr.Zero,
                _callback,
                0,
                0,
                WineventOutOfContext | WineventSkipOwnProcess);
            if (hook == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                UnhookAll();
                Publish(new RecoveryInterferenceSnapshot(
                    RecoveryInterferenceStatus.Unknown,
                    "Windows Codex editor events are unavailable.",
                    false,
                    DateTimeOffset.UtcNow));
                _log.Trace("Windows Codex interaction Hook could not start (Win32 " + error + ").");
                PublishAvailabilityChanged();
                return false;
            }

            _hooks.Add(hook);
        }

        Volatile.Write(ref _hookCount, _hooks.Count);
        _worker = ProcessEventsAsync(_lifetime.Token);
        _ = _worker.ContinueWith(
            _ =>
            {
                Interlocked.Exchange(ref _observationHealthy, 0);
                PublishAvailabilityChanged();
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        _events.Writer.TryWrite(0);
        _log.Info("Started the read-only Windows Codex interaction Hook.");
        PublishAvailabilityChanged();
        return true;
    }

    // The WinEvent worker keeps this snapshot current, so a synchronous reader is enough for the gate that
    // decides whether a recovery retry has to wait. Recovery must not wait on Windows-wide idle time: the
    // only interference worth deferring for is a Codex composer that is actually being typed into.
    internal RecoveryInterferenceSnapshot ReadLatestSnapshot() => Volatile.Read(ref _snapshot);

    internal bool IsComposerBeingEdited()
    {
        if (!IsAvailable)
        {
            return false;
        }

        // Focus alone is not editing. A Codex window in the foreground parks keyboard focus in its composer
        // permanently, so gating on Status == Editing deferred every retry for as long as Codex was
        // foreground. What justifies waiting is an unsent draft sitting in that composer.
        var snapshot = ReadLatestSnapshot();
        return snapshot.Status == RecoveryInterferenceStatus.Editing && snapshot.HasFocusedDraft;
    }

    public Task<RecoveryInterferenceSnapshot> CheckAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        // The stock UI does not expose a reliable foreground composer -> task mapping.
        // This guard therefore protects any focused Codex composer, not a claimed target draft.
        _ = threadId;
        return ObserveNowAsync(cancellationToken);
    }

    public Task WaitForChangeAsync(long observedVersion, CancellationToken cancellationToken)
    {
        Task changed;
        lock (_changeSync)
        {
            if (_snapshot.Version != observedVersion)
            {
                return Task.CompletedTask;
            }

            changed = _changed.Task;
        }

        return changed.WaitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        UnhookAll();
        Interlocked.Exchange(ref _observationHealthy, 0);
        PublishAvailabilityChanged();
        _events.Writer.TryComplete();
        _lifetime.Cancel();
        TaskCompletionSource changed;
        lock (_changeSync)
        {
            changed = _changed;
            _changed = NewChangeCompletion();
        }

        changed.TrySetResult();
        var workerCompleted = true;
        if (_worker is not null)
        {
            try
            {
                await _worker.WaitAsync(ShutdownWaitTimeout).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (TimeoutException)
            {
                workerCompleted = false;
                _log.Trace("Windows Codex interaction observation did not stop within its bounded shutdown wait.");
            }
        }

        if (workerCompleted)
        {
            _lifetime.Dispose();
        }
        else if (_worker is not null)
        {
            _ = _worker.ContinueWith(
                _ => _lifetime.Dispose(),
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private void OnWinEvent(
        IntPtr hook,
        uint eventType,
        IntPtr window,
        int objectId,
        int childId,
        uint eventThread,
        uint eventTime)
    {
        _ = hook;
        _ = eventType;
        _ = window;
        _ = objectId;
        _ = childId;
        _ = eventThread;
        _ = eventTime;
        Interlocked.Increment(ref _winEventCount);
        if (!_events.Writer.TryWrite(0))
        {
            Interlocked.Increment(ref _coalescedEventCount);
        }
    }

    private async Task ProcessEventsAsync(CancellationToken cancellationToken)
    {
        var reader = _events.Reader;
        while (await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            while (reader.TryRead(out _))
            {
            }

            await Task.Delay(TimeSpan.FromMilliseconds(80), cancellationToken).ConfigureAwait(false);
            while (reader.TryRead(out _))
            {
            }

            await ObserveNowAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<RecoveryInterferenceSnapshot> ObserveNowAsync(
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0 || Volatile.Read(ref _hookCount) != 3)
        {
            SetObservationHealth(false);
            return PublishObserved(Unknown(
                "Windows Codex editor events are unavailable; Windows idle fallback is required.",
                DateTimeOffset.UtcNow));
        }

        if (!await _inspectionGate.WaitAsync(ObservationTimeout, cancellationToken).ConfigureAwait(false))
        {
            Interlocked.Increment(ref _timeoutCount);
            SetObservationHealth(false);
            return PublishObserved(Unknown(
                "Codex editor observation timed out; Windows idle fallback is required.",
                DateTimeOffset.UtcNow));
        }

        var inspection = Task.Run(() =>
        {
            try
            {
                return InspectForegroundInteraction();
            }
            finally
            {
                _inspectionGate.Release();
            }
        });

        try
        {
            var result = await inspection.WaitAsync(ObservationTimeout, cancellationToken).ConfigureAwait(false);
            SetObservationHealth(result.Healthy);
            return PublishObserved(result.Snapshot);
        }
        catch (TimeoutException)
        {
            Interlocked.Increment(ref _timeoutCount);
            SetObservationHealth(false);
            return PublishObserved(Unknown(
                "Codex editor observation timed out; Windows idle fallback is required.",
                DateTimeOffset.UtcNow));
        }
    }

    private InteractionInspectionResult InspectForegroundInteraction()
    {
        var observedAt = DateTimeOffset.UtcNow;
        try
        {
            var foreground = GetForegroundWindow();
            if (foreground == IntPtr.Zero)
            {
                return Healthy(ClassifyMissingForeground(IsDefaultInputDesktop(), observedAt));
            }

            if (GetWindowThreadProcessId(foreground, out var processId) == 0 ||
                processId == 0)
            {
                return Healthy(Unknown("The foreground application could not be identified.", observedAt));
            }

            if (!TryIdentifyCodexProcess(checked((int)processId), out var isCodex))
            {
                return Healthy(Unknown("The foreground process could not be verified safely.", observedAt));
            }

            if (!isCodex)
            {
                return Healthy(new RecoveryInterferenceSnapshot(
                    RecoveryInterferenceStatus.Clear,
                    "The user is not editing a Codex composer.",
                    false,
                    observedAt));
            }

            var focused = AutomationElement.FocusedElement;
            if (focused is null)
            {
                return Healthy(Unknown("Codex is foreground, but its focused control is unavailable.", observedAt));
            }

            var current = focused;
            for (var depth = 0; depth < 8 && current is not null; depth++)
            {
                if (string.Equals(current.Current.ClassName, "ProseMirror", StringComparison.OrdinalIgnoreCase))
                {
                    var hasDraft = TryHasDraft(current);
                    return Healthy(new RecoveryInterferenceSnapshot(
                        RecoveryInterferenceStatus.Editing,
                        "A Codex composer has keyboard focus; recovery dispatch is deferred.",
                        hasDraft,
                        observedAt));
                }

                current = TreeWalker.ControlViewWalker.GetParent(current);
            }

            return Healthy(new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Clear,
                "Codex is foreground, but no composer is being edited.",
                false,
                observedAt));
        }
        catch (Exception exception) when (
            exception is COMException or ElementNotAvailableException or InvalidOperationException or
                Win32Exception or ArgumentException)
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                _log.Trace(
                    "Windows Codex interaction Hook observation degraded (" + exception.GetType().Name + ").");
            }

            return new InteractionInspectionResult(
                Unknown("Codex editor focus could not be verified safely.", observedAt),
                Healthy: false);
        }
    }

    internal static RecoveryInterferenceSnapshot ClassifyMissingForeground(
        bool isDefaultInputDesktop,
        DateTimeOffset observedAt) =>
        isDefaultInputDesktop
            ? new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Clear,
                "No application has foreground keyboard ownership.",
                false,
                observedAt)
            : Unknown(
                "The interactive Windows desktop could not be verified safely.",
                observedAt);

    private static bool IsDefaultInputDesktop()
    {
        var desktop = OpenInputDesktop(0, inherit: false, desiredAccess: DesktopReadObjects);
        if (desktop == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            var name = new StringBuilder(64);
            return GetUserObjectInformation(
                       desktop,
                       UoiName,
                       name,
                       checked((uint)(name.Capacity * sizeof(char))),
                       out _) &&
                   string.Equals(name.ToString(), "Default", StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            _ = CloseDesktop(desktop);
        }
    }

    private static bool TryIdentifyCodexProcess(int processId, out bool isCodex)
    {
        isCodex = false;
        try
        {
            using var process = Process.GetProcessById(processId);
            isCodex = string.Equals(process.ProcessName, "Codex", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(process.ProcessName, "ChatGPT", StringComparison.OrdinalIgnoreCase);
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return false;
        }
    }

    private static bool TryHasDraft(AutomationElement editor)
    {
        try
        {
            return editor.TryGetCurrentPattern(TextPattern.Pattern, out var pattern) &&
                   pattern is TextPattern textPattern &&
                   !string.IsNullOrWhiteSpace(textPattern.DocumentRange.GetText(64));
        }
        catch (Exception exception) when (
            exception is COMException or ElementNotAvailableException or InvalidOperationException)
        {
            return false;
        }
    }

    private RecoveryInterferenceSnapshot PublishObserved(RecoveryInterferenceSnapshot snapshot)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return snapshot with { Version = Volatile.Read(ref _snapshot).Version };
        }

        Interlocked.Increment(ref _observationCount);
        var published = Publish(snapshot);
        WriteDiagnosticSummaryIfDue(published.Status);
        return published;
    }

    private void WriteDiagnosticSummaryIfDue(RecoveryInterferenceStatus status)
    {
        var now = Stopwatch.GetTimestamp();
        var previous = Volatile.Read(ref _lastDiagnosticTimestamp);
        if (Stopwatch.GetElapsedTime(previous, now) < DiagnosticInterval ||
            Interlocked.CompareExchange(ref _lastDiagnosticTimestamp, now, previous) != previous)
        {
            return;
        }

        _log.WriteInteractionObservationSummary(
            Interlocked.Exchange(ref _winEventCount, 0),
            Interlocked.Exchange(ref _coalescedEventCount, 0),
            Interlocked.Exchange(ref _observationCount, 0),
            Interlocked.Exchange(ref _timeoutCount, 0),
            status.ToString(),
            IsAvailable);
    }

    private RecoveryInterferenceSnapshot Publish(RecoveryInterferenceSnapshot snapshot)
    {
        TaskCompletionSource? changed = null;
        RecoveryInterferenceSnapshot published;
        lock (_changeSync)
        {
            var previous = _snapshot;
            var stateChanged = previous.Status != snapshot.Status ||
                               previous.HasFocusedDraft != snapshot.HasFocusedDraft;
            published = snapshot with
            {
                Version = stateChanged ? previous.Version + 1 : previous.Version
            };
            Volatile.Write(ref _snapshot, published);
            if (stateChanged)
            {
                changed = _changed;
                _changed = NewChangeCompletion();
            }
        }

        changed?.TrySetResult();
        return published;
    }

    private void UnhookAll()
    {
        foreach (var hook in _hooks)
        {
            _ = UnhookWinEvent(hook);
        }

        _hooks.Clear();
        Volatile.Write(ref _hookCount, 0);
    }

    private void PublishAvailabilityChanged() => EventSubscriberDispatcher.Invoke(
        AvailabilityChanged,
        this,
        EventArgs.Empty,
        exception => _log.Trace(
            "An enhanced-observation status subscriber failed (" +
            exception.GetType().Name + ")."));

    private void SetObservationHealth(bool healthy)
    {
        var next = healthy && Volatile.Read(ref _disposed) == 0 ? 1 : 0;
        if (Interlocked.Exchange(ref _observationHealthy, next) != next)
        {
            PublishAvailabilityChanged();
        }
    }

    private static InteractionInspectionResult Healthy(RecoveryInterferenceSnapshot snapshot) =>
        new(snapshot, Healthy: true);

    private static RecoveryInterferenceSnapshot Unknown(string detail, DateTimeOffset observedAt) =>
        new(RecoveryInterferenceStatus.Unknown, detail, false, observedAt);

    private static TaskCompletionSource NewChangeCompletion() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private readonly record struct InteractionInspectionResult(
        RecoveryInterferenceSnapshot Snapshot,
        bool Healthy);

    private delegate void WinEventDelegate(
        IntPtr hook,
        uint eventType,
        IntPtr window,
        int objectId,
        int childId,
        uint eventThread,
        uint eventTime);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWinEventHook(
        uint eventMin,
        uint eventMax,
        IntPtr eventHookModule,
        WinEventDelegate callback,
        uint processId,
        uint threadId,
        uint flags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWinEvent(IntPtr hook);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(
        uint flags,
        [MarshalAs(UnmanagedType.Bool)] bool inherit,
        uint desiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformation(
        IntPtr handle,
        int index,
        StringBuilder information,
        uint length,
        out uint needed);
}
