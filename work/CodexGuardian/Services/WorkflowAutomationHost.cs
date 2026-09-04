using System;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CodexGuardian.Services;

internal interface IWorkflowAutomationWakeSink
{
    void NotifyPolicyOrCapabilityChanged();
}

internal interface IWorkflowAutomationClock
{
    DateTimeOffset GetUtcNow();

    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

internal sealed class SystemWorkflowAutomationClock : IWorkflowAutomationClock
{
    internal static SystemWorkflowAutomationClock Instance { get; } = new();

    public DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow;

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

internal sealed class WorkflowAutomationHost :
    IWorkflowAutomationWakeSink,
    IAsyncDisposable
{
    internal static readonly TimeSpan DefaultMinimumReconciliationDelay = TimeSpan.FromSeconds(15);
    internal static readonly TimeSpan DefaultMaximumReconciliationDelay = TimeSpan.FromMinutes(15);
    internal static readonly TimeSpan DefaultMaximumTimerSlice = TimeSpan.FromHours(24);

    private const int ScheduleChangedSignal = 1;
    private const int ReconcileSignal = 2;

    private readonly WorkflowAutomationEventAdapter _adapter;
    private readonly IWorkflowAutomationAuthorityChangeSource _authorityChanges;
    private readonly GuardianLog _log;
    private readonly IWorkflowAutomationClock _clock;
    private readonly TimeSpan _minimumReconciliationDelay;
    private readonly TimeSpan _maximumReconciliationDelay;
    private readonly TimeSpan _maximumTimerSlice;
    private readonly Channel<byte> _wake = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
    {
        SingleReader = true,
        SingleWriter = false,
        FullMode = BoundedChannelFullMode.DropOldest
    });
    private readonly object _stateSync = new();
    private CancellationTokenSource? _lifetime;
    private Task? _scheduler;
    private DateTimeOffset? _nextReconciliationWakeAtUtc;
    private TimeSpan _reconciliationDelay;
    private Exception? _lastFailure;
    private int _pendingSignals;
    private int _started;
    private int _disposed;

    internal WorkflowAutomationHost(
        WorkflowAutomationEventAdapter adapter,
        IWorkflowAutomationAuthorityChangeSource authorityChanges,
        GuardianLog log,
        IWorkflowAutomationClock? clock = null,
        TimeSpan? minimumReconciliationDelay = null,
        TimeSpan? maximumReconciliationDelay = null,
        TimeSpan? maximumTimerSlice = null)
    {
        _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        _authorityChanges = authorityChanges ??
            throw new ArgumentNullException(nameof(authorityChanges));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _clock = clock ?? SystemWorkflowAutomationClock.Instance;
        _minimumReconciliationDelay = minimumReconciliationDelay ??
            DefaultMinimumReconciliationDelay;
        _maximumReconciliationDelay = maximumReconciliationDelay ??
            DefaultMaximumReconciliationDelay;
        _maximumTimerSlice = maximumTimerSlice ?? DefaultMaximumTimerSlice;
        if (_minimumReconciliationDelay <= TimeSpan.Zero ||
            _maximumReconciliationDelay < _minimumReconciliationDelay ||
            _maximumTimerSlice <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimumReconciliationDelay),
                "Workflow automation wake bounds are invalid.");
        }

        _reconciliationDelay = _minimumReconciliationDelay;
    }

    internal bool IsStarted => Volatile.Read(ref _started) != 0;

    internal event EventHandler<EventArgs>? LineageInvalidated;

    internal DateTimeOffset? NextScheduledWakeAtUtc => _adapter.NextScheduledWakeAtUtc;

    internal DateTimeOffset? NextReconciliationWakeAtUtc
    {
        get
        {
            lock (_stateSync)
            {
                return _nextReconciliationWakeAtUtc;
            }
        }
    }

    internal Exception? LastFailure
    {
        get
        {
            lock (_stateSync)
            {
                return _lastFailure ?? _adapter.LastFailure;
            }
        }
    }

    internal async Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The workflow automation host is already started.");
        }

        _lifetime = new CancellationTokenSource();
        _adapter.StateChanged += OnAdapterStateChanged;
        _authorityChanges.AuthorityChanged += OnAuthorityChanged;
        try
        {
            await _adapter.StartAsync(_clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
            _scheduler = RunSchedulerAsync(_lifetime.Token);
            Signal(ScheduleChangedSignal);
        }
        catch
        {
            await DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public void NotifyPolicyOrCapabilityChanged()
    {
        if (Volatile.Read(ref _started) == 0 || Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        lock (_stateSync)
        {
            ResetReconciliationBackoffNoLock();
            _nextReconciliationWakeAtUtc = null;
        }

        Signal(ReconcileSignal);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _adapter.StateChanged -= OnAdapterStateChanged;
        _authorityChanges.AuthorityChanged -= OnAuthorityChanged;
        _authorityChanges.Dispose();
        _wake.Writer.TryComplete();
        TryCancel(_lifetime);
        if (_scheduler is not null)
        {
            try
            {
                await _scheduler.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        await _adapter.DisposeAsync().ConfigureAwait(false);
        _lifetime?.Dispose();
    }

    private async Task RunSchedulerAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var pendingSignals = Interlocked.Exchange(ref _pendingSignals, 0);
                DrainWakeTokens();
                if ((pendingSignals & ReconcileSignal) != 0)
                {
                    await ReconcileNowAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }

                var now = _clock.GetUtcNow();
                var scheduled = _adapter.NextScheduledWakeAtUtc;
                var reconciliation = NextReconciliationWakeAtUtc;
                if (reconciliation is not null &&
                    (scheduled is null || reconciliation <= scheduled))
                {
                    if (reconciliation <= now)
                    {
                        lock (_stateSync)
                        {
                            _nextReconciliationWakeAtUtc = null;
                        }

                        await ReconcileNowAsync(cancellationToken).ConfigureAwait(false);
                        continue;
                    }
                }
                else if (scheduled is not null && scheduled <= now)
                {
                    await _adapter.NotifyScheduledWakeAsync(now, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                var nextWake = Earlier(scheduled, reconciliation);
                if (nextWake is null)
                {
                    await WaitForWakeAsync(delay: null, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                var delay = nextWake.Value - now;
                if (delay > _maximumTimerSlice)
                {
                    delay = _maximumTimerSlice;
                }

                await WaitForWakeAsync(
                        delay > TimeSpan.Zero ? delay : TimeSpan.Zero,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                RecordFailure(exception);
                Signal(ScheduleChangedSignal);
            }
        }
    }

    private async Task ReconcileNowAsync(CancellationToken cancellationToken)
    {
        await _adapter.NotifyPolicyOrCapabilityChangedAsync(
                _clock.GetUtcNow(),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task WaitForWakeAsync(
        TimeSpan? delay,
        CancellationToken cancellationToken)
    {
        if (delay is null)
        {
            if (await _wake.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                DrainWakeTokens();
            }

            return;
        }

        using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var delayTask = _clock.DelayAsync(delay.Value, wait.Token);
        var wakeTask = _wake.Reader.WaitToReadAsync(wait.Token).AsTask();
        var completed = await Task.WhenAny(delayTask, wakeTask).ConfigureAwait(false);
        if (ReferenceEquals(completed, wakeTask) && await wakeTask.ConfigureAwait(false))
        {
            DrainWakeTokens();
        }

        TryCancel(wait);
        await IgnoreCanceledAsync(delayTask).ConfigureAwait(false);
        await IgnoreCanceledAsync(wakeTask).ConfigureAwait(false);
    }

    private void OnAdapterStateChanged(
        object? sender,
        WorkflowAutomationAdapterStateChangedEventArgs eventArgs)
    {
        _ = sender;
        if (eventArgs.Failure is not null)
        {
            RecordFailure(eventArgs.Failure);
            PublishLineageInvalidated();
            Signal(ScheduleChangedSignal);
            return;
        }

        var result = eventArgs.Result!;
        lock (_stateSync)
        {
            _lastFailure = null;
            if (HasConfirmedProgress(result))
            {
                ResetReconciliationBackoffNoLock();
            }

            if (RequiresReconciliationWake(result))
            {
                ScheduleReconciliationNoLock(_clock.GetUtcNow());
            }
            else if (IsFullReconciliation(eventArgs.Origin))
            {
                _nextReconciliationWakeAtUtc = null;
                ResetReconciliationBackoffNoLock();
            }
        }

        _log.Trace(
            "Workflow automation state: origin=" + eventArgs.Origin +
            ", status=" + result.Status +
            ", triggered=" + result.TriggeredRules.Count +
            ", reconciled=" + result.ReconciledActions.Count +
            ", replayed=" + result.ReplayedConfirmations + ".");
        PublishLineageInvalidated();
        Signal(ScheduleChangedSignal);
    }

    private void PublishLineageInvalidated() =>
        EventSubscriberDispatcher.Invoke(
            LineageInvalidated,
            this,
            EventArgs.Empty,
            exception => _log.Trace(
                "A workflow lineage subscriber failed (" +
                exception.GetType().Name + ")."));

    private void OnAuthorityChanged(object? sender, EventArgs eventArgs)
    {
        _ = sender;
        _ = eventArgs;
        NotifyPolicyOrCapabilityChanged();
    }

    private void RecordFailure(Exception exception)
    {
        lock (_stateSync)
        {
            _lastFailure = exception;
            ScheduleReconciliationNoLock(_clock.GetUtcNow());
        }

        _log.Warning(
            "Workflow automation host scheduled bounded reconciliation after " +
            exception.GetType().Name + ".");
    }

    private void ScheduleReconciliationNoLock(DateTimeOffset observedAtUtc)
    {
        var candidate = observedAtUtc.ToUniversalTime() + _reconciliationDelay;
        if (_nextReconciliationWakeAtUtc is null || candidate < _nextReconciliationWakeAtUtc)
        {
            _nextReconciliationWakeAtUtc = candidate;
        }

        var doubledTicks = _reconciliationDelay.Ticks > long.MaxValue / 2
            ? long.MaxValue
            : _reconciliationDelay.Ticks * 2;
        _reconciliationDelay = TimeSpan.FromTicks(Math.Min(
            doubledTicks,
            _maximumReconciliationDelay.Ticks));
    }

    private void ResetReconciliationBackoffNoLock()
    {
        _reconciliationDelay = _minimumReconciliationDelay;
    }

    private void Signal(int signal)
    {
        Interlocked.Or(ref _pendingSignals, signal);
        _wake.Writer.TryWrite(0);
    }

    private void DrainWakeTokens()
    {
        while (_wake.Reader.TryRead(out _))
        {
        }
    }

    private static bool RequiresReconciliationWake(WorkflowAutomationRuntimeResult result) =>
        result.Status is WorkflowAutomationRuntimeStatus.RulesUnavailable or
            WorkflowAutomationRuntimeStatus.JournalUnavailable ||
        result.TriggeredRules.SelectMany(static rule => rule.Actions)
            .Concat(result.ReconciledActions)
            .Any(static action => action.Status is
                WorkflowActionExecutionStatus.Waiting or
                WorkflowActionExecutionStatus.Retryable or
                WorkflowActionExecutionStatus.Uncertain);

    private static bool HasConfirmedProgress(WorkflowAutomationRuntimeResult result) =>
        result.ReplayedConfirmations > 0 ||
        result.TriggeredRules.SelectMany(static rule => rule.Actions)
            .Concat(result.ReconciledActions)
            .Any(static action => action.Status == WorkflowActionExecutionStatus.Confirmed);

    private static bool IsFullReconciliation(WorkflowAutomationResultOrigin origin) =>
        origin is WorkflowAutomationResultOrigin.Startup or
            WorkflowAutomationResultOrigin.PolicyOrCapabilityReconciliation or
            WorkflowAutomationResultOrigin.OverflowReconciliation;

    private static DateTimeOffset? Earlier(
        DateTimeOffset? left,
        DateTimeOffset? right) => left is null
        ? right
        : right is null || left <= right
            ? left
            : right;

    private static async Task IgnoreCanceledAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static void TryCancel(CancellationTokenSource? cancellation)
    {
        try
        {
            cancellation?.Cancel();
        }
        catch
        {
        }
    }
}
