using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal enum DesktopStreamRevisionDisposition
{
    Snapshot,
    AcceptedPatch,
    Stale,
    Gap
}

public sealed class GuardianEngine : IAsyncDisposable
{
    internal const string ProtectionPausedStatus = "Protection is disabled for this task.";
    internal const string GlobalProtectionPausedStatus = "Global protection is off.";
    internal const string GuardianBackgroundRunningStatus = "Guardian recovery turn is running in the background.";
    internal const string WaitingForUserIdleStatus =
        "A recoverable failure was detected. A Codex composer is being edited, so the retry waits for that draft to be released, bounded by a 20 second patience window.";
    internal const string WaitingForDesktopStatus = "Waiting for Codex Desktop to own this task; no hidden session will be used.";
    internal const string RecoveryChainBlockedStatus = RecoveryService.RecoveryChainBlockedMessage;

    internal static readonly TimeSpan ActiveTurnCacheLifetime = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan FullReconciliationInterval = TimeSpan.FromMinutes(15);
    // A composer being edited is an asynchronous veto, and composer state changes arrive on WinEvents, so
    // the re-read only needs to be spaced enough to keep an immediate waiter completion from turning into a
    // refresh loop. This used to be fifteen seconds of Windows-wide idle backoff, which delayed every retry
    // by that much even when nobody was typing.
    internal static readonly TimeSpan UserActivityRetryDelay = TimeSpan.FromSeconds(1);

    // A turn that just failed is retried on the very next pass of the monitor loop. This used to be
    // ComputeBackoff(1) -- twenty seconds plus jitter, doubling to forty and eighty on the following
    // failures -- so a congested API produced a guardian that looked stopped: the row said "cooling
    // down" for a minute and a half while nothing was in flight. Nothing is gained by waiting here.
    // The turn has already failed, and the only pause the user accepts is a composer that is being
    // edited, which the dispatch gate vetoes on its own regardless of this value.
    internal static readonly TimeSpan FirstRetryDelay = TimeSpan.Zero;

    // The flat gap between attempts once one has already gone out and come back a failure, capped at
    // one second by explicit requirement. It replaces the exponential ladder for every failure kind
    // that NextAttemptAfterFailure routes through a delay; the kinds that are conditions rather than
    // cooldowns (desktop signal, hard blockers) still wait for their signal instead of a clock.
    internal static readonly TimeSpan AttemptRetryDelay = TimeSpan.FromSeconds(1);

    private readonly AppSettings _settings;
    private readonly AppServerClient _appServer;
    private readonly DesktopIpcClient _desktopIpc;
    private readonly RecoveryService _recovery;
    private readonly FollowUpDispatchService? _followUps;
    private readonly RecoveryClassifier _classifier;
    private readonly LocalConversationHistoryReader _localHistory;
    private readonly LocalConversationEventWatcher _localEvents;
    private readonly GuardianLog _log;
    private readonly ICodexDeepObservationSource? _deepObservation;
    private readonly bool _previewIsolationMode;
    private readonly object _policySync = new();
    private readonly ReconciliationCycleCoordinator _reconciliationCycles = new();
    private readonly ConcurrentDictionary<string, AttemptState> _attempts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, FollowUpAttemptState> _followUpAttempts =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _lastCorrectedTurnIds = new(StringComparer.OrdinalIgnoreCase);
    // A local task_complete event may precede the read-only Desktop active-state projection.
    // Retain the exact turn id for one targeted verification so a confirmed terminal is not
    // hidden behind the activity fast path.
    private readonly ConcurrentDictionary<string, string> _localTerminalHints =
        new(StringComparer.OrdinalIgnoreCase);

    // Threads Codex is running right now, keyed by thread id, valued by the running turn id. Fed by
    // the rollout watcher's task_started marker and cleared by task_complete / turn_aborted, which
    // is the fastest evidence available locally: Codex writes it before any app-server round trip
    // could report it, so the amber running state reaches the window without waiting for a scan.
    private readonly ConcurrentDictionary<string, string> _localRunningTurns =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, CachedTurnState> _turnCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _cacheVersions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _diagnosticClassificationFingerprints =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _desktopActivityVetoes =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, long>> _desktopRevisionGaps =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _userIdleWaiters = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, GuardianTaskState> _stateCache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ThreadSummary> _threadDirectory =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ThreadRefreshQueue _pendingThreadRefreshes = new();
    private readonly ConcurrentDictionary<string, long> _desktopTerminalRevisions =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _desktopLatestTurnStates =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, bool> _desktopFollowingStates =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _targetedRefreshFailures =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _targetedRefreshRetryWaiters =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly MonitorLifecycle _monitorLifecycle = new();
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private readonly SemaphoreSlim _scanSignal = new(0, 1);
    private readonly SemaphoreSlim _followUpJournalRefreshGate = new(1, 1);
    private readonly ConcurrentDictionary<string, byte> _knownInteractiveThreadIds =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly object _snapshotPublicationSync = new();
    private readonly SemaphoreSlim _keepAliveGate = new(1, 1);
    private readonly KeepAliveCoordinator _keepAlive;
    private Task? _desktopReconnectTask;
    private Task? _appServerReconnectTask;
    private int _realtimeScanScheduled;
    private int _desktopReconnectLoopScheduled;
    private int _appServerReconnectLoopScheduled;
    private int _desktopConnectionState = -1;
    private DateTimeOffset? _nextConnectionRetryAt;
    private DateTimeOffset _nextFullReconciliationAt = DateTimeOffset.MinValue;
    private int _connectionFailureCount;
    private int _desktopConnectionFailureCount;
    private int _appServerConnectionFailureCount;
    private long _desktopWakeVersion;
    private long _desktopRevisionGapGeneration;
    private long _policyVersion;
    private int _fullReconciliationRequested = 1;
    private RecoveryPolicySnapshot _policySnapshot;
    private FollowUpJournalSnapshot _followUpJournalSnapshot = new(
        FollowUpJournalReadStatus.Missing,
        Generation: 0,
        RequiresConservativeRecovery: false,
        Records: []);
    private int _disposed;
    private string? _lastPublishedSnapshotFingerprint;

    public GuardianEngine(
        AppSettings settings,
        AppServerClient appServer,
        DesktopIpcClient desktopIpc,
        RecoveryService recovery,
        RecoveryClassifier classifier,
        LocalConversationHistoryReader localHistory,
        GuardianLog log)
        : this(
            settings,
            appServer,
            desktopIpc,
            recovery,
            classifier,
            localHistory,
            log,
            null,
            null)
    {
    }

    internal GuardianEngine(
        AppSettings settings,
        AppServerClient appServer,
        DesktopIpcClient desktopIpc,
        RecoveryService recovery,
        RecoveryClassifier classifier,
        LocalConversationHistoryReader localHistory,
        GuardianLog log,
        ICodexDeepObservationSource? deepObservation = null,
        FollowUpDispatchService? followUps = null,
        bool previewIsolationMode = false)
    {
        _settings = settings;
        _policySnapshot = CreatePolicySnapshot(_policyVersion, settings);
        _appServer = appServer;
        _desktopIpc = desktopIpc;
        _recovery = recovery;
        _followUps = followUps;
        _classifier = classifier;
        _localHistory = localHistory;
        _localEvents = new LocalConversationEventWatcher(log, localHistory.SessionsRoot);
        _keepAlive = new KeepAliveCoordinator(log);
        _log = log;
        _deepObservation = deepObservation;
        _previewIsolationMode = previewIsolationMode;
        _desktopIpc.ConnectionChanged += OnDesktopConnectionChanged;
        _desktopIpc.NativeChannelBecameAvailable += OnNativeChannelBecameAvailable;
        _desktopIpc.ActivityReceived += OnDesktopActivityReceived;
        _appServer.ConnectionChanged += OnAppServerConnectionChanged;
        _appServer.NotificationReceived += OnAppServerNotificationReceived;
        _localEvents.ThreadTouched += OnLocalThreadTouched;
        _localEvents.TerminalDetected += OnLocalTerminalDetected;
        _localEvents.RunningDetected += OnLocalRunningDetected;
        _localEvents.Faulted += OnLocalWatcherFaulted;
        if (_deepObservation is not null)
        {
            _deepObservation.ThreadChanged += OnDeepObservationThreadChanged;
        }
    }

    public bool IsRunning => _monitorLifecycle.IsRunning;

    public DateTimeOffset? LastScanAt { get; private set; }

    public event EventHandler<GuardianTaskSnapshot>? SnapshotUpdated;

    public event EventHandler<EngineStatusEventArgs>? StatusChanged;

    internal event EventHandler<WorkflowAuthoritativeCompletionEventArgs>?
        WorkflowCompletionObserved;

    public void Start()
    {
        if (_previewIsolationMode)
        {
            throw new InvalidOperationException("Monitoring cannot start in isolated preview mode.");
        }

        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (!_monitorLifecycle.TryStart(
                MonitorLoopAsync,
                _ =>
                {
                    _settings.MonitoringEnabled = true;
                    _turnCache.Clear();
                    _cacheVersions.Clear();
                    _desktopActivityVetoes.Clear();
                    _desktopRevisionGaps.Clear();
                    _desktopTerminalRevisions.Clear();
                    _desktopLatestTurnStates.Clear();
                    _desktopFollowingStates.Clear();
                    _targetedRefreshFailures.Clear();
                    _targetedRefreshRetryWaiters.Clear();
                    _localTerminalHints.Clear();
                    _localRunningTurns.Clear();
                    _userIdleWaiters.Clear();
                    _followUpAttempts.Clear();
                    _stateCache.Clear();
                    _threadDirectory.Clear();
                    _knownInteractiveThreadIds.Clear();
                    _pendingThreadRefreshes.Clear();
                    lock (_snapshotPublicationSync)
                    {
                        _lastPublishedSnapshotFingerprint = null;
                    }
                    Interlocked.Exchange(ref _desktopConnectionState, -1);
                    Interlocked.Exchange(ref _fullReconciliationRequested, 1);
                    _nextFullReconciliationAt = DateTimeOffset.UtcNow;
                    _nextConnectionRetryAt = null;
                    _connectionFailureCount = 0;
                    _desktopConnectionFailureCount = 0;
                    _appServerConnectionFailureCount = 0;
                    StatusChanged?.Invoke(
                        this,
                    new EngineStatusEventArgs("Starting", "Building the initial read-only task baseline...", true));
                    _log.Info(_settings.MonitorOnly
                        ? "Guardian started in monitor-only mode."
                        : "Guardian started with automatic recovery enabled.");
                }))
        {
            return;
        }
    }

    public Task StopAsync()
    {
        return _monitorLifecycle.StopAsync(async monitorTask =>
        {
            if (monitorTask is not null)
            {
                try
                {
                    await monitorTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }

            var desktopReconnectTask = _desktopReconnectTask;
            if (desktopReconnectTask is not null)
            {
                try
                {
                    await desktopReconnectTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }

            _desktopReconnectTask = null;
            var appServerReconnectTask = _appServerReconnectTask;
            if (appServerReconnectTask is not null)
            {
                try
                {
                    await appServerReconnectTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }

            _appServerReconnectTask = null;
            _userIdleWaiters.Clear();
            _reconciliationCycles.CancelPending();
            await _localEvents.StopAsync().ConfigureAwait(false);
            StatusChanged?.Invoke(this, new EngineStatusEventArgs("Paused", "Monitoring is paused.", false));
            _log.Info("Guardian monitoring paused.");
        }, () => _settings.MonitoringEnabled = false);
    }

    public async Task ScanOnceAsync(CancellationToken cancellationToken = default)
    {
        if (_previewIsolationMode)
        {
            throw new InvalidOperationException("Live task scans are disabled in isolated preview mode.");
        }

        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        if (IsRunning)
        {
            // A user-requested reconciliation intentionally bypasses stable terminal caching.
            _turnCache.Clear();
            var completion = _reconciliationCycles.Request(() => RequestFullReconciliation());
            await completion.WaitAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        ReleaseDesktopWaiters();
        _turnCache.Clear();
        await ScanCoreAsync(cancellationToken, "manual").ConfigureAwait(false);
    }

    private async Task ScanCoreAsync(CancellationToken cancellationToken, string trigger)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        if (!await _scanGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        ReconciliationCycle? reconciliationCycle = null;
        var startedAt = Stopwatch.GetTimestamp();
        var countersBefore = CaptureMonitorCounters();
        var outcome = "completed";
        var taskCount = 0;
        try
        {
            reconciliationCycle = _reconciliationCycles.Begin(() =>
                Interlocked.Exchange(ref _fullReconciliationRequested, 0));

            var absorbedRefreshes = DrainThreadRefreshes();
            foreach (var refresh in absorbedRefreshes)
            {
                if ((refresh.Value & ThreadRefreshKind.ReleaseDesktopWaiter) != 0)
                {
                    ReleaseDesktopWaiter(refresh.Key);
                }
            }

            StatusChanged?.Invoke(this, new EngineStatusEventArgs(
                "Reconciling",
                "Running the bounded task-directory safety reconciliation...",
                true));
            await using var readSession = await _appServer.OpenReadSessionAsync(cancellationToken).ConfigureAwait(false);
            var scanPolicy = CapturePolicySnapshot();
            await RefreshFollowUpJournalSnapshotAsync(cancellationToken).ConfigureAwait(false);
            if (!_desktopIpc.IsConnected)
            {
                ScheduleDesktopReconnect(immediate: true);
            }

            var activeThreadsTask = _appServer.ListThreadsAsync(
                _settings.RecentThreadLimit,
                scanPolicy.IncludeSubAgents,
                archived: false,
                cancellationToken);
            var archivedThreadsTask = _appServer.ListThreadsAsync(
                _settings.RecentThreadLimit,
                scanPolicy.IncludeSubAgents,
                archived: true,
                cancellationToken);
            await Task.WhenAll(activeThreadsTask, archivedThreadsTask).ConfigureAwait(false);
            var threads = MergeThreadDirectory(activeThreadsTask.Result, archivedThreadsTask.Result);

            var relevantThreads = threads
                .Where(thread => !thread.IsEphemeral)
                .ToArray();
            taskCount = relevantThreads.Length;
            var relevantIds = relevantThreads
                .Select(thread => thread.Id)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var threadId in relevantIds)
            {
                _knownInteractiveThreadIds[threadId] = 0;
            }

            foreach (var threadId in _knownInteractiveThreadIds.Keys)
            {
                if (!relevantIds.Contains(threadId))
                {
                    _knownInteractiveThreadIds.TryRemove(threadId, out _);
                }
            }

            PruneTurnCache(relevantThreads);
            PruneAttemptState(relevantThreads);
            var scopeGeneration = _recovery.BeginScopeValidationGeneration();

            using var concurrency = new SemaphoreSlim(4, 4);
            var scanTasks = relevantThreads.Select(async thread =>
            {
                // Ahead of every branch below: each one builds its state from an `AttemptState`, and
                // three of them used to take an unseeded one straight out of the dictionary.
                await EnsureAttemptLedgerSeededAsync(thread.Id, cancellationToken).ConfigureAwait(false);
                if (thread.IsArchived)
                {
                    return BuildArchivedState(thread);
                }

                await concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var verifiedThread = thread;
                    var revisionGaps = CaptureDesktopRevisionGaps(thread.Id);
                    if (revisionGaps.Count > 0)
                    {
                        verifiedThread = await _appServer
                            .ReadThreadForRecoveryAsync(thread.Id, cancellationToken)
                            .ConfigureAwait(false);
                        ClearDesktopRevisionGaps(thread.Id, revisionGaps);
                        ClearTargetedRefreshRetry(thread.Id);
                    }

                    if (HasDesktopRevisionGap(verifiedThread.Id))
                    {
                        return BuildDesktopRevisionGapState(verifiedThread, scanPolicy);
                    }

                    absorbedRefreshes.TryGetValue(thread.Id, out var absorbedRefreshKind);
                    _localTerminalHints.TryGetValue(thread.Id, out var localTerminalHint);
                    var recoveryRetryTurnId = CaptureRecoveryRetryTurnId(
                        thread.Id,
                        absorbedRefreshKind,
                        DateTimeOffset.Now);
                    var expectedTerminalTurnId = !string.IsNullOrWhiteSpace(localTerminalHint)
                        ? localTerminalHint
                        : recoveryRetryTurnId;
                    var forceTerminalVerification = !string.IsNullOrWhiteSpace(expectedTerminalTurnId);
                    if ((IsProtocolThreadActive(verifiedThread) || HasDesktopActivityVeto(verifiedThread.Id)) &&
                        !forceTerminalVerification)
                    {
                        _turnCache.TryRemove(verifiedThread.Id, out _);
                        _lastCorrectedTurnIds.TryRemove(verifiedThread.Id, out _);
                        return BuildActiveState(verifiedThread, scanPolicy);
                    }

                    var enabled = ResolveThreadProtection(scanPolicy, verifiedThread);
                    var turn = await ReadLatestTurnForScanAsync(
                            verifiedThread,
                            enabled,
                            cancellationToken,
                            expectedTerminalTurnId)
                        .ConfigureAwait(false);
                    ConsumeLocalTerminalHint(thread.Id, localTerminalHint, turn?.Id);
                    return await EvaluateThreadAsync(
                        verifiedThread,
                        turn,
                        scanPolicy,
                        scopeGeneration,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    _log.Warning($"Unable to inspect task state: {exception.Message}", thread.Id);
                    absorbedRefreshes.TryGetValue(thread.Id, out var absorbedRefreshKind);
                    if (HasDesktopRevisionGap(thread.Id) ||
                        (absorbedRefreshKind & ThreadRefreshKind.RetryRecovery) != 0)
                    {
                        ScheduleTargetedRefreshRetry(
                            thread.Id,
                            (absorbedRefreshKind & ThreadRefreshKind.RetryRecovery) != 0
                                ? ThreadRefreshKind.RetryRecovery
                                : ThreadRefreshKind.StateChanged);
                    }
                    return BuildUnavailableState(thread, exception.Message, scanPolicy);
                }
                finally
                {
                    concurrency.Release();
                }
            });

            var states = await Task.WhenAll(scanTasks).ConfigureAwait(false);
            PruneDesktopThreadState(relevantIds);
            var ordered = states
                .OrderBy(state => HealthOrder(state.Health))
                .ThenByDescending(state => state.Thread.UpdatedAt)
                .ToArray();

            var directoryIds = threads.Select(thread => thread.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var thread in threads)
            {
                _threadDirectory[thread.Id] = thread;
            }

            foreach (var threadId in _threadDirectory.Keys)
            {
                if (!directoryIds.Contains(threadId))
                {
                    _threadDirectory.TryRemove(threadId, out _);
                }
            }

            foreach (var state in ordered)
            {
                _stateCache[state.Thread.Id] = state;
                // A normal reply anywhere is the sentinel's trigger: on a contended endpoint it proves the
                // way in is open right now. Recorded regardless of whether the sentinel is currently on,
                // so switching it on does not have to wait for the next reply to become useful. Note this
                // no longer gates on `state.IsEnabled` — that is the automatic-recovery hold, and a
                // conversation with recovery switched off still answers normally.
                if (KeepAliveCoordinator.IsSettled(state) && !state.Thread.IsArchived)
                {
                    _keepAlive.NoteHealthyConversation(state.Thread.Id, DateTimeOffset.UtcNow);
                }
            }

            foreach (var threadId in _stateCache.Keys)
            {
                if (!relevantIds.Contains(threadId))
                {
                    _stateCache.TryRemove(threadId, out _);
                    _keepAlive.Forget(threadId);
                }
            }

            LastScanAt = DateTimeOffset.Now;
            _nextFullReconciliationAt = DateTimeOffset.UtcNow + FullReconciliationInterval;
            _connectionFailureCount = 0;
            _nextConnectionRetryAt = null;
            foreach (var threadId in _targetedRefreshFailures.Keys)
            {
                if (!HasDesktopRevisionGap(threadId))
                {
                    ClearTargetedRefreshRetry(threadId);
                }
            }
            PublishCachedSnapshot();
            reconciliationCycle?.Complete();
            StatusChanged?.Invoke(this, new EngineStatusEventArgs(
                    scanPolicy.MonitorOnly ? "Monitor only" : "Protected",
                $"{ordered.Length} tasks reconciled at {LastScanAt:HH:mm:ss}; steady-state updates are event-driven.",
                true));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            outcome = "cancelled";
            reconciliationCycle?.Cancel(cancellationToken);
            throw;
        }
        catch (Exception exception)
        {
            outcome = "failed";
            Interlocked.Exchange(ref _fullReconciliationRequested, 1);
            ScheduleConnectionRetry();
            StatusChanged?.Invoke(this, new EngineStatusEventArgs("Offline", exception.Message, false));
            _log.Error("Monitoring synchronization failed: " + exception.Message);
            reconciliationCycle?.Fail(exception);
        }
        finally
        {
            WriteMonitorCycleMetric(
                "fullReconciliation",
                trigger,
                outcome,
                startedAt,
                taskCount,
                countersBefore);
            _scanGate.Release();
        }
    }

    public void SetThreadEnabled(string threadId, bool enabled)
    {
        if (_previewIsolationMode)
        {
            throw new InvalidOperationException("Task protection cannot change in isolated preview mode.");
        }

        RecoveryPolicySnapshot policy;
        lock (_policySync)
        {
            _settings.ThreadEnabled[threadId] = enabled;
            _settings.ThreadProtectionEnabled[threadId] = enabled;
            policy = PublishPolicySnapshotLocked();
        }

        _log.Info(enabled ? "Task protection enabled." : "Task protection paused.", threadId);
        RequestThreadRefresh(threadId, ThreadRefreshKind.ReleaseDesktopWaiter);
    }

    internal bool TryInitializeThreadProtection(string threadId, bool defaultEnabled)
    {
        if (_previewIsolationMode || !Guid.TryParse(threadId, out var parsed) || parsed == Guid.Empty)
        {
            return false;
        }

        threadId = parsed.ToString("D");
        lock (_policySync)
        {
            if (_settings.ThreadProtectionEnabled.ContainsKey(threadId))
            {
                return false;
            }

            var selected = _settings.ThreadEnabled.TryGetValue(threadId, out var legacy)
                ? legacy
                : defaultEnabled;
            _settings.ThreadProtectionEnabled[threadId] = selected;
            _settings.ThreadEnabled.TryAdd(threadId, selected);
            PublishPolicySnapshotLocked();
        }

        RequestThreadRefresh(threadId, ThreadRefreshKind.ReleaseDesktopWaiter);
        return true;
    }

    public void SetThreadFollowUps(string threadId, ThreadFollowUpSettings? settings)
    {
        if (_previewIsolationMode)
        {
            throw new InvalidOperationException("Follow-up scheduling cannot start in isolated preview mode.");
        }

        if (!Guid.TryParse(threadId, out var parsedThreadId))
        {
            throw new ArgumentException("A task UUID is required.", nameof(threadId));
        }

        threadId = parsedThreadId.ToString("D");
        lock (_policySync)
        {
            if (settings is null || settings.Messages.Count == 0)
            {
                _settings.ThreadFollowUps.TryRemove(threadId, out _);
            }
            else
            {
                _settings.ThreadFollowUps[threadId] = settings;
            }

            PublishPolicySnapshotLocked();
        }

        _followUpAttempts.TryRemove(threadId, out _);
        InvalidateTurnCache(threadId);
        RequestThreadRefresh(threadId, ThreadRefreshKind.FollowUpPolicyChanged);
    }

    public void SetGlobalProtectionEnabled(bool enabled)
    {
        if (_previewIsolationMode && enabled)
        {
            throw new InvalidOperationException(
                "Conversation protection cannot be enabled in isolated preview mode.");
        }

        lock (_policySync)
        {
            if (_settings.GlobalProtectionEnabled == enabled)
            {
                return;
            }

            _settings.GlobalProtectionEnabled = enabled;
            PublishPolicySnapshotLocked();
        }

        SchedulePolicyRefresh(clearScope: false);
    }

    public void SetMonitorOnly(bool monitorOnly)
    {
        if (_previewIsolationMode && !monitorOnly)
        {
            throw new InvalidOperationException("Automatic recovery cannot be enabled in isolated preview mode.");
        }

        lock (_policySync)
        {
            if (_settings.MonitorOnly == monitorOnly &&
                _settings.AutomaticRecoveryEnabled == !monitorOnly)
            {
                return;
            }

            _settings.MonitorOnly = monitorOnly;
            _settings.AutomaticRecoveryEnabled = !monitorOnly;
            PublishPolicySnapshotLocked();
        }

        SchedulePolicyRefresh(clearScope: false);
    }

    public void SetAutomaticRecoveryPolicy(
        bool enabled,
        bool globalProtectionEnabled)
    {
        if (_previewIsolationMode && enabled)
        {
            throw new InvalidOperationException(
                "Automatic recovery cannot be enabled in isolated preview mode.");
        }

        lock (_policySync)
        {
            var monitorOnly = !enabled;
            if (_settings.AutomaticRecoveryEnabled == enabled &&
                _settings.MonitorOnly == monitorOnly &&
                _settings.GlobalProtectionEnabled == globalProtectionEnabled)
            {
                return;
            }

            _settings.AutomaticRecoveryEnabled = enabled;
            _settings.MonitorOnly = monitorOnly;
            _settings.GlobalProtectionEnabled = globalProtectionEnabled;
            PublishPolicySnapshotLocked();
        }

        SchedulePolicyRefresh(clearScope: false);
    }

    public void SetRecoveryAttemptPolicy(
        int maximumAttempts,
        bool unlimitedAttempts,
        RecoveryCountingMode countingMode)
    {
        if (!Enum.IsDefined(countingMode))
        {
            throw new ArgumentOutOfRangeException(nameof(countingMode));
        }

        maximumAttempts = Math.Clamp(
            maximumAttempts,
            1,
            RecoveryAttemptPolicyLimits.MaximumFiniteAttempts);
        lock (_policySync)
        {
            _settings.MaximumRecoveryAttempts = maximumAttempts;
            _settings.MaximumAttemptsPerFailure = maximumAttempts;
            _settings.UnlimitedRecoveryAttempts = unlimitedAttempts;
            _settings.RecoveryCountingMode = countingMode;
            PublishPolicySnapshotLocked();
        }

        _recovery.SetDefaultRecoveryPolicy(
            countingMode,
            maximumAttempts,
            unlimitedAttempts);
        SchedulePolicyRefresh(clearScope: false);
    }

    public void SetIncludeSubAgents(bool includeSubAgents)
    {
        lock (_policySync)
        {
            if (_settings.IncludeSubAgents == includeSubAgents)
            {
                return;
            }

            _settings.IncludeSubAgents = includeSubAgents;
            PublishPolicySnapshotLocked();
        }

        SchedulePolicyRefresh(clearScope: true);
    }

    public void SetKeepAliveEnabled(bool enabled)
    {
        lock (_policySync)
        {
            if (_settings.KeepAliveEnabled == enabled)
            {
                return;
            }

            _settings.KeepAliveEnabled = enabled;
            PublishPolicySnapshotLocked();
        }

        // Turning it off drops every auto-enrolment, so re-enabling later does not immediately fire a
        // backlog of heartbeats for conversations that have since gone quiet.
        if (!enabled)
        {
            _keepAlive.Reset();
        }

        ScheduleRealtimeScan();
    }

    public void SetKeepAliveSentinelEnabled(bool enabled)
    {
        lock (_policySync)
        {
            if (_settings.KeepAliveSentinelEnabled == enabled)
            {
                return;
            }

            _settings.KeepAliveSentinelEnabled = enabled;
            PublishPolicySnapshotLocked();
        }

        ScheduleRealtimeScan();
    }

    /// <summary>Nominates the conversation the sentinel sends into, or clears it when null or blank.</summary>
    public void SetKeepAliveSentinelThreadId(string? threadId)
    {
        var normalized = string.IsNullOrWhiteSpace(threadId) ? string.Empty : threadId.Trim();
        lock (_policySync)
        {
            if (string.Equals(_settings.KeepAliveSentinelThreadId, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _settings.KeepAliveSentinelThreadId = normalized;
            PublishPolicySnapshotLocked();
        }

        ScheduleRealtimeScan();
    }

    public void SetKeepAliveIntervalMinutes(int minutes)
    {
        var normalized = Math.Clamp(
            minutes,
            AppSettings.MinimumKeepAliveIntervalMinutes,
            AppSettings.MaximumKeepAliveIntervalMinutes);
        lock (_policySync)
        {
            if (_settings.KeepAliveIntervalMinutes == normalized)
            {
                return;
            }

            _settings.KeepAliveIntervalMinutes = normalized;
            PublishPolicySnapshotLocked();
        }

        ScheduleRealtimeScan();
    }

    public void SetKeepAliveMessage(string message)
    {
        var normalized = SettingsService.NormalizeKeepAliveMessage(message);
        lock (_policySync)
        {
            if (string.Equals(_settings.KeepAliveMessage, normalized, StringComparison.Ordinal))
            {
                return;
            }

            _settings.KeepAliveMessage = normalized;
            PublishPolicySnapshotLocked();
        }
    }

    /// <summary>Switches one conversation's own hold on or off.</summary>
    /// <remarks>
    /// Off is stored as an absent entry rather than false. There is no third state to distinguish it
    /// from now that the sentinel has its own destination, and keeping a false for every conversation the
    /// user ever glanced at would grow the settings file without meaning anything.
    /// </remarks>
    public void SetKeepAliveThreadEnabled(string threadId, bool enabled)
    {
        if (string.IsNullOrWhiteSpace(threadId))
        {
            return;
        }

        lock (_policySync)
        {
            if (enabled)
            {
                _settings.KeepAliveThreadEnabled[threadId] = true;
            }
            else
            {
                _settings.KeepAliveThreadEnabled.TryRemove(threadId, out _);
            }

            PublishPolicySnapshotLocked();
        }

        // Scan now rather than on the next timer tick: a hold that was just switched on is due
        // immediately, and the user is looking at the row.
        ScheduleRealtimeScan();
    }

    /// <summary>Keep-alive state for the UI: enrolment and last send time per conversation.</summary>
    public KeepAliveRuntimeSnapshot CaptureKeepAliveRuntime()
    {
        var policy = CapturePolicySnapshot();
        var states = _stateCache.Values
            .Select(AttachLocalRunningState)
            .ToArray();
        var sentinelArmed = _keepAlive.LastHealthyReplyAt is not null;
        var rows = states
            .Where(state => !state.Thread.IsArchived)
            .Select(state => new KeepAliveThreadRuntime(
                state.Thread.Id,
                state.Thread.Name,
                policy.KeepAlive.ThreadEnabled.TryGetValue(state.Thread.Id, out var choice) && choice,
                KeepAliveCoordinator.IsSentinelDestination(policy.KeepAlive, state.Thread.Id),
                sentinelArmed,
                KeepAliveCoordinator.IsSettled(state),
                _keepAlive.LastSentAt(state.Thread.Id)))
            .ToArray();
        return new KeepAliveRuntimeSnapshot(
            policy.KeepAlive.Enabled,
            policy.MonitorOnly,
            policy.KeepAlive.SentinelEnabled,
            sentinelArmed,
            policy.KeepAlive.SentinelThreadId.Length > 0,
            _keepAlive.FindNextDueAt(states, policy.KeepAlive),
            rows,
            _keepAlive.RecentSends());
    }

    public void SetProtectNewThreadsByDefault(bool protectByDefault)
    {
        lock (_policySync)
        {
            if (_settings.ProtectNewThreadsByDefault == protectByDefault)
            {
                return;
            }

            _settings.ProtectNewThreadsByDefault = protectByDefault;
            PublishPolicySnapshotLocked();
        }

        SchedulePolicyRefresh(clearScope: true);
    }

    private void SchedulePolicyRefresh(bool clearScope)
    {
        if (clearScope)
        {
            _turnCache.Clear();
            _lastCorrectedTurnIds.Clear();
        }

        foreach (var threadId in _stateCache.Keys)
        {
            RequestThreadRefresh(threadId, ThreadRefreshKind.ReleaseDesktopWaiter);
        }

        if (clearScope)
        {
            RequestFullReconciliation();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _desktopIpc.ConnectionChanged -= OnDesktopConnectionChanged;
        _desktopIpc.NativeChannelBecameAvailable -= OnNativeChannelBecameAvailable;
        _desktopIpc.ActivityReceived -= OnDesktopActivityReceived;
        _appServer.ConnectionChanged -= OnAppServerConnectionChanged;
        _appServer.NotificationReceived -= OnAppServerNotificationReceived;
        _localEvents.ThreadTouched -= OnLocalThreadTouched;
        _localEvents.TerminalDetected -= OnLocalTerminalDetected;
        _localEvents.RunningDetected -= OnLocalRunningDetected;
        _localEvents.Faulted -= OnLocalWatcherFaulted;
        if (_deepObservation is not null)
        {
            _deepObservation.ThreadChanged -= OnDeepObservationThreadChanged;
        }
        await StopAsync();
        await _scanGate.WaitAsync().ConfigureAwait(false);
        _scanGate.Release();
        await _localEvents.DisposeAsync();
        await _desktopIpc.DisposeAsync();
        await _appServer.DisposeAsync();
    }

    private async Task MonitorLoopAsync(CancellationToken cancellationToken)
    {
        await using var appServerMonitoringLease = _appServer.AcquireMonitoringLease();
        _localEvents.Start();
        ScheduleDesktopReconnect(immediate: true);
        ScheduleAppServerReconnect(immediate: true);
        while (!cancellationToken.IsCancellationRequested)
        {
            await ProcessPendingMonitorWorkAsync(cancellationToken).ConfigureAwait(false);
            await WaitForNextEventOrScheduledActionAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Sends at most one due keep-alive turn per monitor pass.
    /// </summary>
    /// <remarks>
    /// One per pass on purpose. Several conversations enrolled at the same time come due at the same
    /// time, and firing them together is exactly the burst that pushed resend intervals from under a
    /// second to 1.4 s when two recoveries collided. A heartbeat is never urgent, so the most overdue
    /// one goes now and the rest follow on later passes.
    /// </remarks>
    private async Task ProcessDueKeepAliveAsync(CancellationToken cancellationToken)
    {
        var policy = CapturePolicySnapshot();
        // MonitorOnly is the user's "look, do not touch" switch. Keep-alive writes, so it obeys it.
        if (!policy.KeepAlive.Enabled || policy.MonitorOnly)
        {
            return;
        }

        // Never let a heartbeat hold up the monitor loop; if a previous one is still in flight, skip.
        if (!await _keepAliveGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        try
        {
            var states = _stateCache.Values
                .Select(AttachLocalRunningState)
                .ToArray();
            var due = _keepAlive.SelectDue(states, policy.KeepAlive, DateTimeOffset.UtcNow);
            if (due.Count == 0)
            {
                return;
            }

            var target = due[0].ThreadId;
            await SendKeepAliveAsync(
                    target,
                    _keepAlive.SelectMessage(target, policy.KeepAlive.Message),
                    KeepAliveCoordinator.IsSentinelDestination(policy.KeepAlive, target),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _keepAliveGate.Release();
        }
    }

    private async Task SendKeepAliveAsync(
        string threadId,
        string message,
        bool isSentinel,
        CancellationToken cancellationToken)
    {
        // The send time is recorded before the attempt, not after. A failed heartbeat must not be
        // retried on the next pass a second later — that would hammer a channel that is already
        // unhappy. It waits out the normal interval like any other. The client id is recorded with it
        // so recovery can recognise the turn as a heartbeat and leave it unanswered rather than
        // resending it.
        var clientMessageId = Guid.NewGuid().ToString("D");
        _keepAlive.NoteSent(threadId, DateTimeOffset.UtcNow, clientMessageId, message);
        try
        {
            using var commit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            commit.CancelAfter(TimeSpan.FromSeconds(30));
            var started = await _desktopIpc.StartTextTurnAsync(
                    threadId,
                    message,
                    clientMessageId,
                    commit.Token,
                    () => !CapturePolicySnapshot().MonitorOnly)
                .ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(started.TurnId))
            {
                _log.Warning("Keep-alive was accepted without a new turn id.", threadId);
                return;
            }

            // Which switch caused the send is worth recording: the two have different failure modes, and
            // a log that only says "keep-alive turn sent" cannot answer whether the sentinel is working.
            _log.Info(
                isSentinel
                    ? "Keep-alive turn sent by the sentinel to hold the slot."
                    : "Keep-alive turn sent to hold this conversation's connection.",
                threadId);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _log.Warning("Keep-alive timed out before Codex Desktop answered.", threadId);
        }
        catch (Exception exception) when (
            exception is DesktopIpcProtocolException or DesktopIpcDeliveryException or IOException
                or TimeoutException or ArgumentException)
        {
            _log.Warning("Keep-alive could not be delivered: " + exception.Message, threadId);
        }
    }

    private async Task ProcessPendingMonitorWorkAsync(CancellationToken cancellationToken)
    {
        await ProcessDueKeepAliveAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var retryDue = _nextConnectionRetryAt is null || _nextConnectionRetryAt <= now;
        var fullReconciliationRequested = Volatile.Read(ref _fullReconciliationRequested) != 0;
        if (retryDue &&
            (fullReconciliationRequested || now >= _nextFullReconciliationAt))
        {
            await ScanCoreAsync(
                    cancellationToken,
                    fullReconciliationRequested ? "requested" : "scheduled")
                .ConfigureAwait(false);
            return;
        }

        if (Volatile.Read(ref _fullReconciliationRequested) != 0)
        {
            return;
        }

        foreach (var pair in _attempts)
        {
            if (pair.Value.TryTakeDueRetry(DateTimeOffset.Now) is not null)
            {
                RequestThreadRefresh(pair.Key, ThreadRefreshKind.RetryRecovery);
            }
        }

        foreach (var pair in _followUpAttempts)
        {
            if (pair.Value.NextAttemptAt is not null && pair.Value.NextAttemptAt <= DateTimeOffset.UtcNow)
            {
                pair.Value.MarkRetryQueued();
                RequestThreadRefresh(pair.Key, ThreadRefreshKind.RetryFollowUp);
            }
        }

        if (CanUseFollowUpJournal(CapturePolicySnapshot()))
        {
            var policy = CapturePolicySnapshot();
            var suppressed = _followUpAttempts
                .Where(pair => pair.Value.SuppressScheduledDeadline)
                .Select(pair => pair.Key)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var threadId in FollowUpQueuePlanner.FindDueScheduledThreadIds(
                         CaptureSchedulableFollowUps(policy),
                         _followUpJournalSnapshot.Records,
                         now,
                         suppressed))
            {
                _followUpAttempts.GetOrAdd(threadId, static _ => new FollowUpAttemptState())
                    .MarkScheduledWakeQueued();
                RequestThreadRefresh(threadId, ThreadRefreshKind.ScheduledFollowUp);
            }
        }

        var pending = DrainThreadRefreshes();
        if (pending.Count > 0)
        {
            await RefreshThreadsAsync(pending, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WaitForNextEventOrScheduledActionAsync(CancellationToken cancellationToken)
    {
        var nextWakeAt = NextScheduledActionAt();
        if (nextWakeAt is null)
        {
            await _scanSignal.WaitAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var delay = nextWakeAt.Value - DateTimeOffset.Now;
        var scheduledAction = Task.Delay(delay > TimeSpan.Zero ? delay : TimeSpan.Zero, waitCancellation.Token);
        var realtimeSignal = _scanSignal.WaitAsync(waitCancellation.Token);
        await Task.WhenAny(scheduledAction, realtimeSignal).ConfigureAwait(false);
        waitCancellation.Cancel();
        try
        {
            await Task.WhenAll(scheduledAction, realtimeSignal).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }
    }

    private DateTimeOffset? NextScheduledActionAt()
    {
        var now = DateTimeOffset.UtcNow;
        var retryAt = _nextConnectionRetryAt is { } retry && retry > now ? retry : (DateTimeOffset?)null;
        if (_pendingThreadRefreshes.Count > 0)
        {
            return retryAt ?? now;
        }

        if (Volatile.Read(ref _fullReconciliationRequested) != 0)
        {
            return retryAt ?? now;
        }

        if (_nextFullReconciliationAt <= now && retryAt is not null)
        {
            return retryAt;
        }

        var pendingRecovery = _attempts.Values
            .Select(attempt => attempt.NextAttemptAt)
            .Where(value => value is not null)
            .Min();
        var pendingFollowUp = _followUpAttempts.Values
            .Select(attempt => attempt.NextAttemptAt)
            .Where(value => value is not null)
            .Min();
        DateTimeOffset? scheduledFollowUp = null;
        var policy = CapturePolicySnapshot();
        if (CanUseFollowUpJournal(policy))
        {
            var suppressed = _followUpAttempts
                .Where(pair => pair.Value.SuppressScheduledDeadline)
                .Select(pair => pair.Key)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            scheduledFollowUp = FollowUpQueuePlanner.FindNextScheduledAtUtc(
                CaptureSchedulableFollowUps(policy),
                _followUpJournalSnapshot.Records,
                suppressed);
        }

        return MinimumDeadline(
            pendingRecovery,
            pendingFollowUp,
            scheduledFollowUp,
            NextKeepAliveDueAt(policy),
            _nextConnectionRetryAt,
            _nextFullReconciliationAt);
    }

    /// <summary>
    /// The earliest keep-alive deadline, so the monitor loop does not sleep straight past it.
    /// </summary>
    private DateTimeOffset? NextKeepAliveDueAt(RecoveryPolicySnapshot policy)
    {
        if (!policy.KeepAlive.Enabled || policy.MonitorOnly)
        {
            return null;
        }

        var states = _stateCache.Values
            .Select(AttachLocalRunningState)
            .ToArray();
        return _keepAlive.FindNextDueAt(states, policy.KeepAlive);
    }

    internal static DateTimeOffset? MinimumDeadline(params DateTimeOffset?[] values) =>
        values.Where(value => value is not null).Min();

    internal static bool IsRecoveryRetryDue(
        DateTimeOffset? nextAttemptAt,
        DateTimeOffset now) =>
        nextAttemptAt is not null && nextAttemptAt <= now;

    private void ScheduleConnectionRetry()
    {
        _connectionFailureCount = Math.Min(_connectionFailureCount + 1, 6);
        var seconds = Math.Min(60, Math.Pow(2, _connectionFailureCount));
        _nextConnectionRetryAt = DateTimeOffset.Now + TimeSpan.FromSeconds(seconds);
    }

    private void OnLocalTerminalDetected(object? sender, LocalConversationTerminalDetectedEventArgs eventArgs)
    {
        // Clearing the running marker comes before the sub-agent policy filter on purpose: "this turn
        // ended" is a fact about the turn, not a display preference, and a marker left behind by a
        // filtered terminal event would keep its row spinning forever.
        if (_localRunningTurns.TryRemove(eventArgs.ThreadId, out _))
        {
            PublishCachedSnapshot();
        }

        if (!ShouldScheduleLocalTerminal(
                CapturePolicySnapshot().IncludeSubAgents,
                eventArgs.IsSubAgent,
                _knownInteractiveThreadIds.ContainsKey(eventArgs.ThreadId)))
        {
            return;
        }

        _log.Trace($"Local terminal event detected for {eventArgs.ThreadId}/{eventArgs.TurnId}.");
        _localTerminalHints[eventArgs.ThreadId] = eventArgs.TurnId;
        _localHistory.RegisterSourceFile(eventArgs.ThreadId, eventArgs.SourceFile);
        InvalidateTurnCache(eventArgs.ThreadId);
        RequestThreadRefresh(eventArgs.ThreadId);
    }

    // The amber "Codex is working on this right now" row. Codex appends task_started to the rollout as
    // the turn starts, so this fires roughly a tenth of a second later -- the watcher's own debounce --
    // and publishes immediately instead of waiting for a scan to ask the app-server what changed. The
    // same policy filter as the terminal path decides whether a sub-agent turn is allowed to show.
    private void OnLocalRunningDetected(object? sender, LocalConversationRunningDetectedEventArgs eventArgs)
    {
        if (!ShouldScheduleLocalTerminal(
                CapturePolicySnapshot().IncludeSubAgents,
                eventArgs.IsSubAgent,
                _knownInteractiveThreadIds.ContainsKey(eventArgs.ThreadId)))
        {
            return;
        }

        _log.Trace($"Local running event detected for {eventArgs.ThreadId}/{eventArgs.TurnId}.");
        _localRunningTurns[eventArgs.ThreadId] = eventArgs.TurnId;
        _localHistory.RegisterSourceFile(eventArgs.ThreadId, eventArgs.SourceFile);
        PublishCachedSnapshot();
        InvalidateTurnCache(eventArgs.ThreadId);
        RequestThreadRefresh(eventArgs.ThreadId);
    }

    private void OnLocalThreadTouched(object? sender, LocalConversationThreadTouchedEventArgs eventArgs)
    {
        _localHistory.RegisterSourceFile(eventArgs.ThreadId, eventArgs.SourceFile);
        InvalidateTurnCache(eventArgs.ThreadId);
        RequestThreadRefresh(eventArgs.ThreadId);
    }

    internal static bool ShouldScheduleLocalTerminal(
        bool includeSubAgents,
        bool? eventIsSubAgent,
        bool isKnownInteractiveThread) =>
        includeSubAgents || eventIsSubAgent == false ||
        eventIsSubAgent is null && isKnownInteractiveThread;

    private void OnLocalWatcherFaulted(object? sender, LocalConversationWatcherFaultedEventArgs eventArgs)
    {
        _localHistory.InvalidateFileIndex();
        _turnCache.Clear();
        RequestFullReconciliation();
    }

    private void OnAppServerNotificationReceived(object? sender, AppServerNotificationEventArgs eventArgs)
    {
        if (!IsThreadScopedNotification(eventArgs.Method))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(eventArgs.ThreadId))
        {
            _log.Trace(
                "Ignored an unscoped app-server notification (" +
                GuardianLog.SanitizeIdentifier(eventArgs.Method) +
                "); the bounded safety reconciliation remains scheduled.");
            return;
        }

        InvalidateTurnCache(eventArgs.ThreadId);
        RequestThreadRefresh(eventArgs.ThreadId);
    }

    private void OnDeepObservationThreadChanged(
        object? sender,
        CodexDeepThreadChangedEventArgs eventArgs)
    {
        if (!IsRunning || !_settings.MonitoringEnabled)
        {
            return;
        }

        // Item phases are display-only. State, turn, and error edges wake an authoritative targeted read.
        PublishCachedSnapshot();
        if (!ShouldRefreshFromDeepObservation(eventArgs.Kind))
        {
            return;
        }

        InvalidateTurnCache(eventArgs.ThreadId);
        RequestThreadRefresh(eventArgs.ThreadId);
    }

    internal static bool ShouldRefreshFromDeepObservation(CodexDeepChangeKind kind) => kind is
        CodexDeepChangeKind.ThreadState or
        CodexDeepChangeKind.Turn or
        CodexDeepChangeKind.StreamError;

    private void OnAppServerConnectionChanged(object? sender, bool connected)
    {
        if (!IsRunning || !_settings.MonitoringEnabled)
        {
            return;
        }

        if (connected)
        {
            _appServerConnectionFailureCount = 0;
            return;
        }

        ScheduleAppServerReconnect();
    }

    internal static bool IsThreadScopedNotification(string method) => method is
        "error" or
        "thread/started" or
        "thread/status/changed" or
        "thread/archived" or
        "thread/deleted" or
        "thread/unarchived" or
        "thread/closed" or
        "thread/name/updated" or
        "turn/started" or
        "turn/completed";

    private void OnDesktopConnectionChanged(object? sender, bool connected)
    {
        if (!IsRunning || !_settings.MonitoringEnabled)
        {
            return;
        }

        var nextState = connected ? 1 : 0;
        if (Interlocked.Exchange(ref _desktopConnectionState, nextState) == nextState)
        {
            return;
        }

        if (connected)
        {
            _desktopConnectionFailureCount = 0;
            WakeDesktopWaiters();
            return;
        }

        var affectedThreadIds = ClearDesktopConnectionState();
        ScheduleDesktopReconnect();
        foreach (var threadId in affectedThreadIds)
        {
            RequestThreadRefresh(threadId);
        }
    }

    // A probe can prove the native channel long after the IPC connection was established -- Guardian
    // starting before Codex Desktop is the ordinary case. Recovery reports an unproven channel as
    // DesktopUnavailable and parks the task on the desktop signal, so without this the task waited for a
    // signal that had already come and gone.
    private void OnNativeChannelBecameAvailable(object? sender, EventArgs eventArgs)
    {
        if (!IsRunning || !_settings.MonitoringEnabled)
        {
            return;
        }

        _log.Info("The Codex Desktop native owner channel is ready; pending retries resume now.");
        WakeDesktopWaiters();
    }

    // Distinct from ReleaseDesktopWaiters, which only clears the flags: this bumps the wake version so a
    // failure racing the signal is retried immediately, and asks for a rescan of every parked thread.
    private void WakeDesktopWaiters()
    {
        Interlocked.Increment(ref _desktopWakeVersion);
        foreach (var pair in _attempts)
        {
            if (pair.Value.IsWaitingForDesktopSignal)
            {
                RequestThreadRefresh(pair.Key, ThreadRefreshKind.ReleaseDesktopWaiter);
            }
        }
        foreach (var pair in _followUpAttempts)
        {
            if (pair.Value.IsWaitingForDesktop)
            {
                pair.Value.ReleaseForStateSignal();
                RequestThreadRefresh(pair.Key);
            }
        }
    }

    private void OnDesktopActivityReceived(object? sender, DesktopIpcActivityEventArgs eventArgs)
    {
        if (eventArgs.Method == "ipc-connection-reset")
        {
            foreach (var threadId in ClearDesktopConnectionState())
            {
                InvalidateTurnCache(threadId);
                RequestThreadRefresh(threadId);
            }

            return;
        }

        if (eventArgs.Method is "thread-stream-following-changed" or "thread-stream-state-changed" &&
            !ShouldAcceptDesktopConversationSignal(
                eventArgs.ConversationId,
                _knownInteractiveThreadIds.ContainsKey(eventArgs.ConversationId),
                _threadDirectory.ContainsKey(eventArgs.ConversationId),
                _attempts.ContainsKey(eventArgs.ConversationId) ||
                _followUpAttempts.ContainsKey(eventArgs.ConversationId)))
        {
            return;
        }

        var changed = false;
        if (eventArgs.Method == "thread-stream-following-changed" &&
            eventArgs.Version == 1 &&
            !string.IsNullOrWhiteSpace(eventArgs.ConversationId) &&
            !string.IsNullOrWhiteSpace(eventArgs.SourceClientId) &&
            eventArgs.Following is not null)
        {
            // Following describes the stock owner/follower topology, not whether a turn is active.
            var followingKey = BuildDesktopStreamKey(
                eventArgs.ConversationId,
                eventArgs.HostId,
                eventArgs.SourceClientId);
            var hadFollowing = _desktopFollowingStates.TryGetValue(followingKey, out var previousFollowing);
            _desktopFollowingStates[followingKey] = eventArgs.Following.Value;
            var topologyChanged = !hadFollowing || previousFollowing != eventArgs.Following.Value;
            changed = topologyChanged &&
                      _attempts.TryGetValue(eventArgs.ConversationId, out var waitingAttempt) &&
                      waitingAttempt.IsWaitingForDesktopSignal;
        }
        else if (eventArgs.Method == "thread-stream-state-changed" &&
                  eventArgs.Version == 11 &&
                  !string.IsNullOrWhiteSpace(eventArgs.ConversationId) &&
                  !string.IsNullOrWhiteSpace(eventArgs.SourceClientId))
        {
            var streamKey = BuildDesktopStreamKey(
                eventArgs.ConversationId,
                eventArgs.HostId,
                eventArgs.SourceClientId);
            var revisionDisposition = ApplyDesktopStreamRevision(
                _desktopTerminalRevisions,
                streamKey,
                eventArgs.ChangeType,
                eventArgs.BaseRevision,
                eventArgs.Revision);
            if (revisionDisposition == DesktopStreamRevisionDisposition.Stale)
            {
                return;
            }

            var authoritativeSnapshot =
                revisionDisposition == DesktopStreamRevisionDisposition.Snapshot &&
                eventArgs.Revision is not null &&
                !string.IsNullOrWhiteSpace(eventArgs.HostId) &&
                TryResolveDesktopRuntimeActivity(eventArgs.RuntimeStatus, out _);
            if (authoritativeSnapshot)
            {
                changed |= ClearDesktopConversationStreamState(
                    eventArgs.ConversationId,
                    eventArgs.HostId,
                    streamKey);
                changed |= ClearDesktopRevisionGap(eventArgs.ConversationId, streamKey);
                changed |= SetDesktopActivityVeto(
                    eventArgs.ConversationId,
                    "stream:" + eventArgs.SourceClientId,
                    active: false);
            }

            var gapPending = HasDesktopRevisionGap(eventArgs.ConversationId, streamKey);
            if (revisionDisposition == DesktopStreamRevisionDisposition.Gap ||
                revisionDisposition == DesktopStreamRevisionDisposition.Snapshot && !authoritativeSnapshot)
            {
                _desktopLatestTurnStates.TryRemove(streamKey, out _);
                SetDesktopRevisionGap(eventArgs.ConversationId, streamKey);
                gapPending = true;
                changed = true;
            }
            else if (gapPending && eventArgs.HasRelevantStatePatch)
            {
                // A newer fact edge arrived while a targeted read may be in flight.
                // Touch the generation so that the older read cannot clear this gap.
                SetDesktopRevisionGap(eventArgs.ConversationId, streamKey);
                changed = true;
            }

            if (!gapPending && TryResolveDesktopRuntimeActivity(eventArgs.RuntimeStatus, out var active))
            {
                changed |= SetDesktopActivityVeto(
                    eventArgs.ConversationId,
                    "stream:" + eventArgs.SourceClientId,
                    active);
            }

            if (!gapPending &&
                DesktopThreadOwnerStateSnapshot.TryParse(eventArgs, out var snapshot) &&
                snapshot is not null)
            {
                var latestTurnState = snapshot.LatestTurnId + "\n" + snapshot.LatestTurnStatus;
                var hadPrevious = _desktopLatestTurnStates.TryGetValue(streamKey, out var previous);
                _desktopLatestTurnStates[streamKey] = latestTurnState;
                changed |= !hadPrevious ||
                           !string.Equals(previous, latestTurnState, StringComparison.OrdinalIgnoreCase);
            }
            else if (!gapPending &&
                     revisionDisposition == DesktopStreamRevisionDisposition.AcceptedPatch &&
                     eventArgs.HasRelevantStatePatch)
            {
                changed = true;
            }
        }
        else if (eventArgs.Method == "client-status-changed" &&
                 string.Equals(eventArgs.ClientStatus, "disconnected", StringComparison.OrdinalIgnoreCase) &&
                 !string.IsNullOrWhiteSpace(eventArgs.ClientId))
        {
            foreach (var threadId in RemoveDesktopClientState(eventArgs.ClientId))
            {
                InvalidateTurnCache(threadId);
                RequestThreadRefresh(threadId);
            }
            return;
        }

        var releaseWaiter = changed &&
                            !string.IsNullOrWhiteSpace(eventArgs.ConversationId) &&
                            ShouldReleaseDesktopWaiters(eventArgs.Method) &&
                            _attempts.TryGetValue(eventArgs.ConversationId, out var attempt) &&
                            attempt.IsWaitingForDesktopSignal;
        if (releaseWaiter)
        {
            Interlocked.Increment(ref _desktopWakeVersion);
            changed = true;
        }

        if (changed)
        {
            if (!string.IsNullOrWhiteSpace(eventArgs.ConversationId))
            {
                InvalidateTurnCache(eventArgs.ConversationId);
                RequestThreadRefresh(
                    eventArgs.ConversationId,
                    releaseWaiter ? ThreadRefreshKind.ReleaseDesktopWaiter : ThreadRefreshKind.StateChanged);
            }
            else
            {
                foreach (var threadId in _stateCache.Keys)
                {
                    RequestThreadRefresh(threadId);
                }
            }
        }
    }

    internal static bool ShouldReleaseDesktopWaiters(string method) =>
        method is "thread-stream-following-changed" or "thread-stream-state-changed";

    internal static bool ShouldAcceptDesktopConversationSignal(
        string? conversationId,
        bool isKnownInteractiveThread,
        bool isInThreadDirectory,
        bool hasRecoveryAttempt) =>
        Guid.TryParse(conversationId, out _) &&
        (isKnownInteractiveThread || isInThreadDirectory || hasRecoveryAttempt);

    internal bool HasDesktopActivityVeto(string threadId) =>
        _desktopActivityVetoes.TryGetValue(threadId, out var sources) && !sources.IsEmpty ||
        HasDesktopRevisionGap(threadId);

    internal bool HasDesktopRevisionGap(string threadId) =>
        _desktopRevisionGaps.TryGetValue(threadId, out var streams) && !streams.IsEmpty;

    private bool HasDesktopRevisionGap(string threadId, string streamKey) =>
        _desktopRevisionGaps.TryGetValue(threadId, out var streams) && streams.ContainsKey(streamKey);

    internal IReadOnlyDictionary<string, long> CaptureDesktopRevisionGaps(string threadId) =>
        _desktopRevisionGaps.TryGetValue(threadId, out var streams)
            ? streams.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

    private void SetDesktopRevisionGap(string threadId, string streamKey)
    {
        var streams = _desktopRevisionGaps.GetOrAdd(
            threadId,
            static _ => new ConcurrentDictionary<string, long>(StringComparer.OrdinalIgnoreCase));
        var generation = Interlocked.Increment(ref _desktopRevisionGapGeneration);
        streams.AddOrUpdate(streamKey, generation, (_, _) => generation);
    }

    private bool ClearDesktopRevisionGap(string threadId, string streamKey)
    {
        if (!_desktopRevisionGaps.TryGetValue(threadId, out var streams) ||
            !streams.TryRemove(streamKey, out _))
        {
            return false;
        }

        if (TryReadDesktopStreamSourceClientId(streamKey, out var sourceClientId))
        {
            SetDesktopActivityVeto(threadId, "stream:" + sourceClientId, active: false);
        }

        return true;
    }

    internal bool ClearDesktopRevisionGaps(
        string threadId,
        IReadOnlyDictionary<string, long> verifiedGaps)
    {
        if (verifiedGaps.Count == 0 || !_desktopRevisionGaps.TryGetValue(threadId, out var streams))
        {
            return false;
        }

        var changed = false;
        var versionedStreams = (ICollection<KeyValuePair<string, long>>)streams;
        foreach (var gap in verifiedGaps)
        {
            if (!versionedStreams.Remove(gap))
            {
                continue;
            }

            changed = true;
            if (TryReadDesktopStreamSourceClientId(gap.Key, out var sourceClientId))
            {
                changed |= SetDesktopActivityVeto(threadId, "stream:" + sourceClientId, active: false);
            }
        }

        return changed;
    }

    private bool SetDesktopActivityVeto(string threadId, string sourceKey, bool active)
    {
        if (active)
        {
            var sources = _desktopActivityVetoes.GetOrAdd(
                threadId,
                static _ => new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase));
            return sources.TryAdd(sourceKey, 0);
        }

        if (!_desktopActivityVetoes.TryGetValue(threadId, out var existing) ||
            !existing.TryRemove(sourceKey, out _))
        {
            return false;
        }

        return true;
    }

    private IReadOnlyCollection<string> RemoveDesktopClientState(string clientId)
    {
        var affected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in _desktopActivityVetoes)
        {
            if (SetDesktopActivityVeto(pair.Key, "stream:" + clientId, false))
            {
                affected.Add(pair.Key);
            }
        }

        var suffix = "|" + clientId;
        foreach (var pair in _desktopRevisionGaps)
        {
            if (pair.Value.Keys.Any(key => key.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
            {
                // A disconnect is not proof of an idle task. Preserve the gap until a
                // targeted read or authoritative replacement snapshot verifies it.
                affected.Add(pair.Key);
            }
        }

        foreach (var key in _desktopFollowingStates.Keys)
        {
            if (key.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                _desktopFollowingStates.TryRemove(key, out _);
                if (TryReadDesktopStreamThreadId(key, out var threadId))
                {
                    affected.Add(threadId);
                }
            }
        }

        foreach (var key in _desktopTerminalRevisions.Keys)
        {
            if (key.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadDesktopStreamThreadId(key, out var threadId))
                {
                    SetDesktopRevisionGap(threadId, key);
                    affected.Add(threadId);
                }

                _desktopTerminalRevisions.TryRemove(key, out _);
                _desktopLatestTurnStates.TryRemove(key, out _);
            }
        }

        return affected;
    }

    private IReadOnlyCollection<string> ClearDesktopConnectionState()
    {
        var affected = new HashSet<string>(_desktopActivityVetoes.Keys, StringComparer.OrdinalIgnoreCase);
        affected.UnionWith(_desktopRevisionGaps.Keys);
        foreach (var pair in _desktopTerminalRevisions)
        {
            if (!TryReadDesktopStreamThreadId(pair.Key, out var threadId))
            {
                continue;
            }

            SetDesktopRevisionGap(threadId, pair.Key);
            affected.Add(threadId);
        }

        foreach (var key in _desktopFollowingStates.Keys
                     .Concat(_desktopTerminalRevisions.Keys)
                     .Concat(_desktopLatestTurnStates.Keys))
        {
            if (TryReadDesktopStreamThreadId(key, out var threadId))
            {
                affected.Add(threadId);
            }
        }

        _desktopActivityVetoes.Clear();
        _desktopFollowingStates.Clear();
        _desktopTerminalRevisions.Clear();
        _desktopLatestTurnStates.Clear();
        return affected;
    }

    private bool ClearDesktopConversationStreamState(
        string threadId,
        string? hostId,
        string? exceptStreamKey = null)
    {
        var changed = false;
        var removedSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var prefix = threadId + "|";
        var hostPrefix = string.IsNullOrWhiteSpace(hostId)
            ? prefix
            : prefix + hostId + "|";
        foreach (var key in _desktopTerminalRevisions.Keys)
        {
            if (!key.StartsWith(hostPrefix, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(key, exceptStreamKey, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            changed |= _desktopTerminalRevisions.TryRemove(key, out _);
            changed |= _desktopLatestTurnStates.TryRemove(key, out _);
            var sourceSeparator = key.LastIndexOf('|');
            if (sourceSeparator >= 0 && sourceSeparator + 1 < key.Length)
            {
                removedSources.Add(key[(sourceSeparator + 1)..]);
            }
        }

        if (_desktopRevisionGaps.TryGetValue(threadId, out var gaps))
        {
            foreach (var key in gaps.Keys)
            {
                if (!key.StartsWith(hostPrefix, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(key, exceptStreamKey, StringComparison.OrdinalIgnoreCase) ||
                    !gaps.TryRemove(key, out _))
                {
                    continue;
                }

                changed = true;
                if (TryReadDesktopStreamSourceClientId(key, out var sourceClientId))
                {
                    removedSources.Add(sourceClientId);
                }
            }
        }

        if (_desktopActivityVetoes.TryGetValue(threadId, out var vetoes))
        {
            foreach (var sourceClientId in removedSources)
            {
                changed |= vetoes.TryRemove("stream:" + sourceClientId, out _);
            }
        }

        return changed;
    }

    internal static string BuildDesktopStreamKey(
        string conversationId,
        string? hostId,
        string sourceClientId) =>
        conversationId + "|" + (hostId ?? string.Empty) + "|" + sourceClientId;

    private static bool TryReadDesktopStreamThreadId(string key, out string threadId)
    {
        var separator = key.IndexOf('|');
        if (separator <= 0)
        {
            threadId = string.Empty;
            return false;
        }

        threadId = key[..separator];
        return true;
    }

    private static bool TryReadDesktopStreamSourceClientId(string key, out string sourceClientId)
    {
        var separator = key.LastIndexOf('|');
        if (separator < 0 || separator + 1 >= key.Length)
        {
            sourceClientId = string.Empty;
            return false;
        }

        sourceClientId = key[(separator + 1)..];
        return true;
    }

    internal static bool TryResolveDesktopRuntimeActivity(string? runtimeStatus, out bool active)
    {
        if (string.Equals(runtimeStatus, "active", StringComparison.OrdinalIgnoreCase))
        {
            active = true;
            return true;
        }

        if (string.Equals(runtimeStatus, "idle", StringComparison.OrdinalIgnoreCase))
        {
            active = false;
            return true;
        }

        active = false;
        return false;
    }

    internal static DesktopStreamRevisionDisposition ApplyDesktopStreamRevision(
        ConcurrentDictionary<string, long> watermarks,
        string key,
        string changeType,
        long? baseRevision,
        long? revision)
    {
        if (revision is null)
        {
            return DesktopStreamRevisionDisposition.Gap;
        }

        if (string.Equals(changeType, "snapshot", StringComparison.OrdinalIgnoreCase))
        {
            watermarks[key] = revision.Value;
            return DesktopStreamRevisionDisposition.Snapshot;
        }

        if (!string.Equals(changeType, "patches", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(changeType, "patch", StringComparison.OrdinalIgnoreCase))
        {
            return DesktopStreamRevisionDisposition.Gap;
        }

        while (true)
        {
            if (!watermarks.TryGetValue(key, out var previous))
            {
                if (watermarks.TryAdd(key, revision.Value))
                {
                    return DesktopStreamRevisionDisposition.Gap;
                }

                continue;
            }

            if (revision.Value <= previous || baseRevision is not null && baseRevision.Value < previous)
            {
                return DesktopStreamRevisionDisposition.Stale;
            }

            var isContiguous = baseRevision == previous;
            if (watermarks.TryUpdate(key, revision.Value, previous))
            {
                return isContiguous
                    ? DesktopStreamRevisionDisposition.AcceptedPatch
                    : DesktopStreamRevisionDisposition.Gap;
            }
        }
    }

    private bool ReleaseDesktopWaiter(string threadId)
    {
        if (!_attempts.TryGetValue(threadId, out var attempt) || !attempt.IsWaitingForDesktopSignal)
        {
            return false;
        }

        attempt.ReleaseDesktopWait();
        return true;
    }

    private bool ReleaseDesktopWaiters()
    {
        var released = false;
        foreach (var attempt in _attempts.Values)
        {
            released |= attempt.IsWaitingForDesktopSignal;
            attempt.ReleaseDesktopWait();
        }

        return released;
    }

    private void ScheduleDesktopReconnect(bool immediate = false)
    {
        if (!IsRunning || _desktopIpc.IsConnected ||
            Interlocked.CompareExchange(ref _desktopReconnectLoopScheduled, 1, 0) != 0)
        {
            return;
        }

        var cancellationToken = _monitorLifecycle.CancellationToken;
        _desktopReconnectTask = ReconnectDesktopLoopAsync(immediate, cancellationToken);
    }

    private async Task ReconnectDesktopLoopAsync(bool immediate, CancellationToken cancellationToken)
    {
        try
        {
            var delay = immediate
                ? TimeSpan.Zero
                : ComputeDesktopReconnectDelay(_desktopConnectionFailureCount + 1);
            while (!cancellationToken.IsCancellationRequested && !_desktopIpc.IsConnected)
            {
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }

                try
                {
                    await _desktopIpc.EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
                    if (_desktopIpc.IsConnected)
                    {
                        return;
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception exception)
                {
                    _log.Trace("Codex Desktop channel reconnect is waiting: " + exception.Message);
                }

                _desktopConnectionFailureCount = Math.Min(_desktopConnectionFailureCount + 1, 6);
                delay = ComputeDesktopReconnectDelay(_desktopConnectionFailureCount);
            }
        }
        finally
        {
            Interlocked.Exchange(ref _desktopReconnectLoopScheduled, 0);
            if (!cancellationToken.IsCancellationRequested && IsRunning && !_desktopIpc.IsConnected)
            {
                ScheduleDesktopReconnect();
            }
        }
    }

    private void ScheduleAppServerReconnect(bool immediate = false)
    {
        if (!IsRunning || _appServer.IsConnected ||
            Interlocked.CompareExchange(ref _appServerReconnectLoopScheduled, 1, 0) != 0)
        {
            return;
        }

        _appServerReconnectTask = ReconnectAppServerLoopAsync(
            immediate,
            _monitorLifecycle.CancellationToken);
    }

    private async Task ReconnectAppServerLoopAsync(bool immediate, CancellationToken cancellationToken)
    {
        try
        {
            var delay = immediate
                ? TimeSpan.Zero
                : ComputeDesktopReconnectDelay(_appServerConnectionFailureCount + 1);
            while (!cancellationToken.IsCancellationRequested && !_appServer.IsConnected)
            {
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }

                try
                {
                    await _appServer.EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
                    if (_appServer.IsConnected)
                    {
                        return;
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception exception)
                {
                    _log.Trace(
                        "The read-only app-server subscription reconnect is waiting: " + exception.Message);
                }

                _appServerConnectionFailureCount = Math.Min(_appServerConnectionFailureCount + 1, 6);
                delay = ComputeDesktopReconnectDelay(_appServerConnectionFailureCount);
            }
        }
        finally
        {
            Interlocked.Exchange(ref _appServerReconnectLoopScheduled, 0);
            if (!cancellationToken.IsCancellationRequested && IsRunning && !_appServer.IsConnected)
            {
                ScheduleAppServerReconnect();
            }
        }
    }

    internal static TimeSpan ComputeDesktopReconnectDelay(int failureCount)
    {
        var exponent = Math.Clamp(failureCount, 1, 6);
        return TimeSpan.FromSeconds(Math.Min(60, Math.Pow(2, exponent)));
    }

    private void RequestFullReconciliation([CallerMemberName] string reason = "")
    {
        if (Volatile.Read(ref _disposed) != 0 || !IsRunning)
        {
            return;
        }

        var newlyQueued = _reconciliationCycles.Synchronize(() =>
            Interlocked.Exchange(ref _fullReconciliationRequested, 1) == 0);

        if (newlyQueued)
        {
            _log.Trace("Full task-directory reconciliation queued by " + reason + ".");
        }
        ScheduleRealtimeScan();
    }

    private void RequestThreadRefresh(
        string? threadId,
        ThreadRefreshKind kind = ThreadRefreshKind.StateChanged)
    {
        if (Volatile.Read(ref _disposed) != 0 || !IsRunning || string.IsNullOrWhiteSpace(threadId))
        {
            return;
        }

        if ((kind & (ThreadRefreshKind.ScheduledFollowUp |
                     ThreadRefreshKind.RetryFollowUp |
                     ThreadRefreshKind.RetryRecovery)) == 0 &&
            _followUpAttempts.TryGetValue(threadId, out var followUpAttempt))
        {
            followUpAttempt.ReleaseForStateSignal();
        }

        if (!_pendingThreadRefreshes.TryEnqueue(threadId, kind))
        {
            RequestFullReconciliation();
            return;
        }

        ScheduleRealtimeScan();
    }

    private IReadOnlyDictionary<string, ThreadRefreshKind> DrainThreadRefreshes()
    {
        return _pendingThreadRefreshes.Drain();
    }

    private async Task RefreshThreadsAsync(
        IReadOnlyDictionary<string, ThreadRefreshKind> refreshes,
        CancellationToken cancellationToken)
    {
        if (!await _scanGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            foreach (var refresh in refreshes)
            {
                RequestThreadRefresh(refresh.Key, refresh.Value);
            }
            return;
        }

        var startedAt = Stopwatch.GetTimestamp();
        var countersBefore = CaptureMonitorCounters();
        var outcome = "completed";
        try
        {
            StatusChanged?.Invoke(this, new EngineStatusEventArgs(
                "Updating",
                $"Verifying {refreshes.Count} changed task(s) by ID...",
                true));
            await using var readSession = await _appServer.OpenReadSessionAsync(cancellationToken).ConfigureAwait(false);
            var policy = CapturePolicySnapshot();
            await RefreshFollowUpJournalSnapshotAsync(cancellationToken).ConfigureAwait(false);
            var scopeGeneration = _recovery.BeginScopeValidationGeneration();
            foreach (var refresh in refreshes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if ((refresh.Value & ThreadRefreshKind.ReleaseDesktopWaiter) != 0 &&
                    _attempts.TryGetValue(refresh.Key, out var waitingAttempt))
                {
                    waitingAttempt.ReleaseDesktopWait();
                }

                var revisionGaps = CaptureDesktopRevisionGaps(refresh.Key);
                // Seed the resend ledger before anything can return a state for this thread, including
                // the `BuildUnavailableState` degradations in the catch blocks below: every branch reads
                // the ledger off the attempt state, and only the recovery path used to seed it.
                await EnsureAttemptLedgerSeededAsync(refresh.Key, cancellationToken).ConfigureAwait(false);
                ThreadSummary thread;
                try
                {
                    thread = await _appServer
                        .ReadThreadForRecoveryAsync(refresh.Key, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception) when (!_appServer.IsConnected)
                {
                    throw;
                }
                catch (AppServerRequestException exception) when (
                    IsPermanentTargetReadRejection(exception.Code))
                {
                    if (_threadDirectory.TryGetValue(refresh.Key, out var existing))
                    {
                        _stateCache[refresh.Key] = BuildUnavailableState(existing, exception.Message, policy);
                    }

                    ClearTargetedRefreshRetry(refresh.Key);
                    _log.Trace(
                        "The changed task was rejected by the read-only protocol; it will wait for a new signal (" +
                        exception.Code + ").",
                        refresh.Key);
                    continue;
                }
                catch (Exception exception)
                {
                    if (_threadDirectory.TryGetValue(refresh.Key, out var existing))
                    {
                        _stateCache[refresh.Key] = BuildUnavailableState(existing, exception.Message, policy);
                    }

                    _log.Trace("Unable to refresh changed task metadata: " + exception.Message, refresh.Key);
                    ScheduleTargetedRefreshRetry(
                        refresh.Key,
                        (refresh.Value & ThreadRefreshKind.RetryRecovery) != 0
                            ? ThreadRefreshKind.RetryRecovery
                            : ThreadRefreshKind.StateChanged);
                    continue;
                }

                ClearDesktopRevisionGaps(refresh.Key, revisionGaps);
                _targetedRefreshFailures.TryRemove(thread.Id, out _);

                if (thread.IsSubAgent && !policy.IncludeSubAgents)
                {
                    RemoveCachedThread(thread.Id);
                    continue;
                }

                _threadDirectory[thread.Id] = thread;
                if (thread.IsEphemeral)
                {
                    _stateCache.TryRemove(thread.Id, out _);
                    _knownInteractiveThreadIds.TryRemove(thread.Id, out _);
                    continue;
                }

                _knownInteractiveThreadIds[thread.Id] = 0;
                GuardianTaskState state;
                var localTerminalHint = CaptureLocalTerminalHint(
                    thread.Id,
                    refresh.Value,
                    out var forceTerminalVerification);
                var recoveryRetryTurnId = CaptureRecoveryRetryTurnId(
                    thread.Id,
                    refresh.Value,
                    DateTimeOffset.Now);
                var expectedTerminalTurnId = !string.IsNullOrWhiteSpace(localTerminalHint)
                    ? localTerminalHint
                    : recoveryRetryTurnId;
                forceTerminalVerification |= !string.IsNullOrWhiteSpace(recoveryRetryTurnId);
                if (thread.IsArchived)
                {
                    state = BuildArchivedState(thread);
                }
                else if (HasDesktopRevisionGap(thread.Id))
                {
                    state = BuildDesktopRevisionGapState(thread, policy);
                }
                else if ((IsProtocolThreadActive(thread) || HasDesktopActivityVeto(thread.Id)) &&
                         !forceTerminalVerification)
                {
                    _turnCache.TryRemove(thread.Id, out _);
                    state = BuildActiveState(thread, policy);
                }
                else
                {
                    var enabled = ResolveThreadProtection(policy, thread);
                    var turn = await ReadLatestTurnForScanAsync(
                            thread,
                            enabled,
                            cancellationToken,
                            expectedTerminalTurnId)
                        .ConfigureAwait(false);
                    ConsumeLocalTerminalHint(thread.Id, localTerminalHint, turn?.Id);
                    state = await EvaluateThreadAsync(
                            thread,
                            turn,
                            policy,
                            scopeGeneration,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                _stateCache[thread.Id] = state;
            }

            LastScanAt = DateTimeOffset.Now;
            _connectionFailureCount = 0;
            _nextConnectionRetryAt = null;
            PublishCachedSnapshot();
            StatusChanged?.Invoke(this, new EngineStatusEventArgs(
                policy.MonitorOnly ? "Monitor only" : "Protected",
                $"{refreshes.Count} task event(s) verified at {LastScanAt:HH:mm:ss}",
                true));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            outcome = "cancelled";
            throw;
        }
        catch (Exception exception)
        {
            outcome = "failed";
            foreach (var refresh in refreshes)
            {
                RequestThreadRefresh(refresh.Key, refresh.Value);
            }
            ScheduleConnectionRetry();
            StatusChanged?.Invoke(this, new EngineStatusEventArgs("Offline", exception.Message, false));
            _log.Error("Targeted monitoring refresh failed: " + exception.Message);
        }
        finally
        {
            WriteMonitorCycleMetric(
                "targetedRefresh",
                refreshes.Values.Any(kind => (kind & ThreadRefreshKind.ReleaseDesktopWaiter) != 0)
                    ? "desktopWaiter"
                    : "stateSignal",
                outcome,
                startedAt,
                refreshes.Count,
                countersBefore);
            _scanGate.Release();
        }
    }

    private MonitorCounterSnapshot CaptureMonitorCounters() => new(
        _appServer.ProcessStartCount,
        _appServer.RequestCount,
        _appServer.ThreadListRequestCount,
        _appServer.TargetedReadRequestCount,
        _localHistory.FileIndexRefreshCount);

    private void WriteMonitorCycleMetric(
        string cycleKind,
        string trigger,
        string outcome,
        long startedAt,
        int taskCount,
        MonitorCounterSnapshot before)
    {
        var after = CaptureMonitorCounters();
        _log.WriteMonitorCycle(
            cycleKind,
            trigger,
            outcome,
            Stopwatch.GetElapsedTime(startedAt),
            taskCount,
            after.ProcessStarts - before.ProcessStarts,
            after.Requests - before.Requests,
            after.ThreadListRequests - before.ThreadListRequests,
            after.TargetedReadRequests - before.TargetedReadRequests,
            after.FileIndexRefreshes - before.FileIndexRefreshes);
    }

    private void RemoveCachedThread(string threadId)
    {
        _stateCache.TryRemove(threadId, out _);
        _threadDirectory.TryRemove(threadId, out _);
        _knownInteractiveThreadIds.TryRemove(threadId, out _);
        _desktopActivityVetoes.TryRemove(threadId, out _);
        _desktopRevisionGaps.TryRemove(threadId, out _);
        _turnCache.TryRemove(threadId, out _);
        _cacheVersions.TryRemove(threadId, out _);
        _attempts.TryRemove(threadId, out _);
        _followUpAttempts.TryRemove(threadId, out _);
        _diagnosticClassificationFingerprints.TryRemove(threadId, out _);
        _lastCorrectedTurnIds.TryRemove(threadId, out _);
        _localTerminalHints.TryRemove(threadId, out _);
        _targetedRefreshFailures.TryRemove(threadId, out _);
        _targetedRefreshRetryWaiters.TryRemove(threadId, out _);
    }

    private void ScheduleTargetedRefreshRetry(
        string threadId,
        ThreadRefreshKind refreshKind = ThreadRefreshKind.StateChanged)
    {
        var failureCount = _targetedRefreshFailures.AddOrUpdate(
            threadId,
            1,
            static (_, current) => Math.Min(4, current + 1));
        if (failureCount > 3)
        {
            RequestFullReconciliation();
            return;
        }

        if (_targetedRefreshRetryWaiters.TryAdd(threadId, 0))
        {
            _ = RetryTargetedRefreshAsync(
                threadId,
                refreshKind,
                TimeSpan.FromMilliseconds(400 * failureCount),
                _monitorLifecycle.CancellationToken);
        }
    }

    private void ClearTargetedRefreshRetry(string threadId)
    {
        _targetedRefreshFailures.TryRemove(threadId, out _);
        _targetedRefreshRetryWaiters.TryRemove(threadId, out _);
    }

    internal static bool IsPermanentTargetReadRejection(string code) =>
        code is "-32600" or "-32601" or "-32602";

    private async Task RetryTargetedRefreshAsync(
        string threadId,
        ThreadRefreshKind refreshKind,
        TimeSpan delay,
        CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            if (_targetedRefreshFailures.ContainsKey(threadId))
            {
                RequestThreadRefresh(threadId, refreshKind);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            _targetedRefreshRetryWaiters.TryRemove(threadId, out _);
        }
    }

    private void PublishCachedSnapshot()
    {        var ordered = _stateCache.Values
            .Select(AttachDeepObservation)
            .Select(AttachLocalRunningState)
            .OrderBy(state => HealthOrder(state.Health))
            .ThenByDescending(state => state.Thread.UpdatedAt)
            .ToArray();
        var directory = _threadDirectory.Values.ToArray();
        var snapshot = new GuardianTaskSnapshot(
            ordered,
            new GuardianSnapshotStatistics(
                DisplayedSessionCount: ordered.Length,
                TotalSessionCount: directory.Length,
                ArchivedSessionCount: directory.Count(thread => thread.IsArchived),
                FilteredSessionCount: Math.Max(0, directory.Length - ordered.Length),
                IsTruncated: false,
                IncludesArchived: true));
        var fingerprint = CreateSnapshotFingerprint(snapshot);
        lock (_snapshotPublicationSync)
        {
            if (string.Equals(
                    _lastPublishedSnapshotFingerprint,
                    fingerprint,
                    StringComparison.Ordinal))
            {
                return;
            }

            _lastPublishedSnapshotFingerprint = fingerprint;
        }

        SnapshotUpdated?.Invoke(this, snapshot);
        // One line per published snapshot, so the boundary between "the engine never had the numbers"
        // and "the window dropped them" is a matter of record rather than inference.
        _log.Trace(
            "Published a task snapshot: " +
            ordered.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " task(s), " +
            ordered.Count(state => state.RecoveryLedger is { ConfirmedDispatches: > 0 })
                .ToString(System.Globalization.CultureInfo.InvariantCulture) +
            " carrying a non-zero resend ledger.");
    }

    // Snapshot consumers rebuild WPF filters and templates. Keep display-only event bursts from
    // replaying those bindings when the authoritative task state has not changed.
    internal static string CreateSnapshotFingerprint(GuardianTaskSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(snapshot.States);
        ArgumentNullException.ThrowIfNull(snapshot.Statistics);

        var builder = new StringBuilder();
        AppendSnapshotField(builder, snapshot.Statistics.DisplayedSessionCount);
        AppendSnapshotField(builder, snapshot.Statistics.TotalSessionCount);
        AppendSnapshotField(builder, snapshot.Statistics.ArchivedSessionCount);
        AppendSnapshotField(builder, snapshot.Statistics.FilteredSessionCount);
        AppendSnapshotField(builder, snapshot.Statistics.IsTruncated);
        AppendSnapshotField(builder, snapshot.Statistics.IncludesArchived);
        foreach (var state in snapshot.States.OrderBy(
                     static state => state.Thread.Id,
                     StringComparer.OrdinalIgnoreCase))
        {
            AppendSnapshotField(builder, state.Thread.Id);
            AppendSnapshotField(builder, state.Thread.Name);
            AppendSnapshotField(builder, state.Thread.Preview);
            AppendSnapshotField(builder, state.Thread.Cwd);
            AppendSnapshotField(builder, state.Thread.Source);
            AppendSnapshotField(builder, state.Thread.CreatedAt);
            AppendSnapshotField(builder, state.Thread.UpdatedAt);
            AppendSnapshotField(builder, state.Thread.RuntimeStatus);
            AppendSnapshotField(builder, state.Thread.IsArchived);
            AppendSnapshotField(builder, state.Thread.IsPinned);
            AppendSnapshotField(builder, state.IsEnabled);
            AppendSnapshotField(builder, state.Health);
            AppendSnapshotField(builder, state.StatusText);
            AppendSnapshotField(builder, state.LastEvent);
            AppendSnapshotField(builder, state.Attempts);
            AppendSnapshotField(builder, state.NextAttemptAt?.UtcTicks);
            AppendSnapshotField(builder, state.IsGuardianManagedActivity);
            AppendSnapshotField(builder, state.IsRunningNow);
            AppendSnapshotField(builder, state.Decision.Action);
            AppendSnapshotField(builder, state.Turn?.Id);
            AppendSnapshotField(builder, state.Turn?.Status);
            AppendSnapshotField(builder, state.Turn?.ErrorCode);
            AppendSnapshotField(builder, state.Turn?.HttpStatusCode);
            AppendSnapshotField(builder, state.Turn?.HasConfirmedLocalTerminal);
            AppendSnapshotField(builder, state.Turn?.HasFinalAssistantOutput);
            AppendSnapshotField(builder, state.Turn?.HasReasoningOutput);
            AppendSnapshotField(builder, state.Turn?.HasToolActivity);
            AppendSnapshotField(builder, state.Turn?.HasCompleteItemEvidence);
            AppendSnapshotField(builder, state.Observation?.Phase);
            AppendSnapshotField(builder, state.Observation?.ItemType);
            AppendSnapshotField(builder, state.Observation?.ErrorKind);
            AppendSnapshotField(builder, state.Observation?.HttpStatusCode);
            AppendSnapshotField(builder, state.Observation?.WillRetry);
            AppendSnapshotField(builder, state.Observation?.ReconnectAttempt);
            AppendSnapshotField(builder, state.Observation?.ReconnectMaxAttempts);
            AppendSnapshotField(builder, state.FollowUpQueue?.Kind);
            AppendSnapshotField(builder, state.FollowUpQueue?.TotalMessageCount);
            AppendSnapshotField(builder, state.FollowUpQueue?.EnabledMessageCount);
            AppendSnapshotField(builder, state.FollowUpQueue?.ConfirmedMessageCount);
            AppendSnapshotField(builder, state.FollowUpQueue?.NextScheduledAtUtc?.UtcTicks);
            // The resend ledger has to take part in the fingerprint. Without these four fields a
            // snapshot whose ONLY change is "one more confirmed resend" hashes identically to the
            // previous one, PublishCachedSnapshot returns early, and the count the user is waiting to
            // see never reaches the window.
            AppendSnapshotField(builder, state.RecoveryLedger?.ConfirmedDispatches);
            AppendSnapshotField(builder, state.RecoveryLedger?.LastConfirmedAt?.UtcTicks);
            AppendSnapshotField(builder, state.RecoveryLedger?.OwnerBusyRefusals);
            AppendSnapshotField(builder, state.RecoveryLedger?.OwnerBusySince?.UtcTicks);
            builder.Append('\n');
        }

        return builder.ToString();
    }

    private static void AppendSnapshotField<T>(StringBuilder builder, T? value)
    {
        var text = value?.ToString() ?? string.Empty;
        builder.Append(text.Length).Append(':').Append(text).Append('|');
    }

    // The running marker lives outside the state cache because it changes on the rollout watcher's
    // schedule, not the scan's. Stamping it at publication time keeps a single source of truth and
    // lets one task_started event repaint the row without rebuilding any cached scan state.
    private GuardianTaskState AttachLocalRunningState(GuardianTaskState state) =>
        _localRunningTurns.ContainsKey(state.Thread.Id)
            ? state with { IsRunningNow = true }
            : state;

    private GuardianTaskState AttachDeepObservation(GuardianTaskState state)
    {
        if (_deepObservation?.TryGetThreadSnapshot(state.Thread.Id, out var snapshot) != true ||
            snapshot is null)
        {
            return state with { Observation = null };
        }

        return state with
        {
            Observation = new GuardianTaskObservation(
                MapDeepPhase(snapshot.Phase),
                snapshot.ItemType,
                snapshot.ErrorKind,
                snapshot.HttpStatusCode,
                snapshot.WillRetry,
                snapshot.ReconnectAttempt,
                snapshot.ReconnectMaxAttempts,
                snapshot.ObservedAt)
        };
    }

    private static GuardianObservedPhase MapDeepPhase(CodexDeepThreadPhase phase) => phase switch
    {
        CodexDeepThreadPhase.Idle => GuardianObservedPhase.Idle,
        CodexDeepThreadPhase.Running => GuardianObservedPhase.Running,
        CodexDeepThreadPhase.Reasoning => GuardianObservedPhase.Reasoning,
        CodexDeepThreadPhase.Tool => GuardianObservedPhase.Tool,
        CodexDeepThreadPhase.Reconnecting => GuardianObservedPhase.Reconnecting,
        CodexDeepThreadPhase.Completed => GuardianObservedPhase.Completed,
        CodexDeepThreadPhase.Failed => GuardianObservedPhase.Failed,
        CodexDeepThreadPhase.Interrupted => GuardianObservedPhase.Interrupted,
        _ => GuardianObservedPhase.Unknown
    };

    private void ScheduleRealtimeScan()
    {
        if (Volatile.Read(ref _disposed) != 0 ||
            !IsRunning ||
            Interlocked.Exchange(ref _realtimeScanScheduled, 1) != 0)
        {
            return;
        }

        var cancellationToken = _monitorLifecycle.CancellationToken;
        _ = SignalRealtimeScanAsync(cancellationToken);
    }

    private async Task SignalRealtimeScanAsync(CancellationToken cancellationToken)
    {
        var ownershipReleased = false;
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(400), cancellationToken).ConfigureAwait(false);
            // Clear before publishing so a concurrent enqueue can schedule its own wakeup.
            Interlocked.Exchange(ref _realtimeScanScheduled, 0);
            ownershipReleased = true;
            try
            {
                _scanSignal.Release();
            }
            catch (SemaphoreFullException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            if (!ownershipReleased)
            {
                Interlocked.Exchange(ref _realtimeScanScheduled, 0);
            }
        }
    }

    private async Task<TurnSnapshot?> ReadLatestTurnForScanAsync(
        ThreadSummary thread,
        bool enabled,
        CancellationToken cancellationToken,
        string? expectedLocalTerminalTurnId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var cacheVersion = _cacheVersions.GetOrAdd(thread.Id, 0);
        if (_turnCache.TryGetValue(thread.Id, out var cached) &&
            CanReuseTurnSnapshot(
                thread,
                cached.ThreadUpdatedAt,
                cached.Turn?.Status,
                cached.CheckedAt,
                now))
        {
            return cached.Turn;
        }

        var turn = await _appServer.ReadLatestTurnAsync(thread.Id, cancellationToken).ConfigureAwait(false);
        turn = await ReconcileLocalTerminalAsync(
                thread,
                turn,
                cancellationToken,
                expectedLocalTerminalTurnId)
            .ConfigureAwait(false);

        // Summary turns can omit the user-message boundary and attachment/item evidence. Once
        // the matching local terminal proves an abnormal candidate, make one bounded full read
        // for this exact task only; healthy and in-progress scans never pay that cost.
        if (ShouldReadFullTurnEvidence(turn))
        {
            var fullTurn = await _appServer
                .ReadLatestTurnWithFullItemsAsync(thread.Id, cancellationToken)
                .ConfigureAwait(false);
            turn = await ReconcileLocalTerminalAsync(
                    thread,
                    fullTurn,
                    cancellationToken,
                    expectedLocalTerminalTurnId)
                .ConfigureAwait(false);
        }

        if (_cacheVersions.TryGetValue(thread.Id, out var currentVersion) && currentVersion == cacheVersion)
        {
            _turnCache[thread.Id] = new CachedTurnState(thread.UpdatedAt, now, turn);
        }

        return turn;
    }

    private async Task<TurnSnapshot?> ReconcileLocalTerminalAsync(
        ThreadSummary thread,
        TurnSnapshot? appServerTurn,
        CancellationToken cancellationToken,
        string? expectedLocalTerminalTurnId = null)
    {
        if (appServerTurn is null)
        {
            return null;
        }

        if (!ShouldReadLocalTerminal(appServerTurn.Status))
        {
            return appServerTurn;
        }

        try
        {
            var localTerminal = await _localHistory
                .ReadLatestTerminalEventAsync(thread.Id, cancellationToken)
                .ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(expectedLocalTerminalTurnId) &&
                !string.Equals(appServerTurn.Id, expectedLocalTerminalTurnId, StringComparison.OrdinalIgnoreCase))
            {
                return appServerTurn;
            }

            var reconciled = LocalConversationHistoryReader.ReconcileLatestTurn(
                appServerTurn,
                localTerminal,
                allowActiveLocalTerminal: !string.IsNullOrWhiteSpace(expectedLocalTerminalTurnId));
            if (!string.Equals(appServerTurn.Status, reconciled?.Status, StringComparison.OrdinalIgnoreCase))
            {
                if (!_lastCorrectedTurnIds.TryGetValue(thread.Id, out var correctedTurnId) ||
                    !string.Equals(correctedTurnId, reconciled?.Id, StringComparison.OrdinalIgnoreCase))
                {
                    _lastCorrectedTurnIds[thread.Id] = reconciled?.Id ?? string.Empty;
                    _log.Trace(
                        "The local rollout terminal corrected an app-server turn that had lost its failure state.",
                        thread.Id);
                }
            }
            return reconciled;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to reconcile the latest local terminal event: " + exception.Message, thread.Id);
            return appServerTurn;
        }
    }

    internal static bool ShouldReadLocalTerminal(string status) =>
        string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "failed", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(status, "interrupted", StringComparison.OrdinalIgnoreCase);

    internal static bool ShouldForceTerminalVerification(
        ThreadRefreshKind refreshKind,
        string? localTerminalTurnId) =>
        (refreshKind & (ThreadRefreshKind.StateChanged | ThreadRefreshKind.RetryRecovery)) != 0 &&
        !string.IsNullOrWhiteSpace(localTerminalTurnId);

    private string? CaptureRecoveryRetryTurnId(
        string threadId,
        ThreadRefreshKind refreshKind,
        DateTimeOffset now)
    {
        if (!_attempts.TryGetValue(threadId, out var attempt))
        {
            return null;
        }

        if ((refreshKind & ThreadRefreshKind.RetryRecovery) != 0)
        {
            return string.IsNullOrWhiteSpace(attempt.FailureTurnId)
                ? null
                : attempt.FailureTurnId;
        }

        return attempt.TryTakeDueRetry(now);
    }

    private string? CaptureLocalTerminalHint(
        string threadId,
        ThreadRefreshKind refreshKind,
        out bool forceTerminalVerification)
    {
        _localTerminalHints.TryGetValue(threadId, out var hint);
        forceTerminalVerification = ShouldForceTerminalVerification(refreshKind, hint);
        return forceTerminalVerification ? hint : null;
    }

    private void ConsumeLocalTerminalHint(string threadId, string? expectedTurnId, string? observedTurnId)
    {
        _ = observedTurnId;
        if (string.IsNullOrWhiteSpace(expectedTurnId))
        {
            return;
        }

        // A hint is a one-shot wake credential. If the Desktop read already moved to a newer
        // turn, retaining the old hint would force every later full scan through reconciliation.
        ((ICollection<KeyValuePair<string, string>>)_localTerminalHints)
            .Remove(new KeyValuePair<string, string>(threadId, expectedTurnId));
    }

    internal static bool ShouldReadFullTurnEvidence(TurnSnapshot? turn) =>
        turn is not null &&
        turn.HasConfirmedLocalTerminal &&
        (string.Equals(turn.Status, "failed", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(turn.Status, "interrupted", StringComparison.OrdinalIgnoreCase)) &&
        (!turn.HasUserMessage || !turn.HasCompleteItemEvidence);

    private GuardianTaskState BuildActiveState(
        ThreadSummary thread,
        RecoveryPolicySnapshot policy)
    {
        var protectionSelected = ResolveConversationProtection(policy, thread);
        var attempt = _attempts.GetOrAdd(thread.Id, _ => new AttemptState());
        var isGuardianManaged = attempt.ActionCommitted;
        var status = isGuardianManaged
            ? GuardianBackgroundRunningStatus
            : "Codex activity stack reports that this task is still running.";
        var decision = RecoveryDecision.None(TaskHealth.Processing, status);
        return BuildState(
            thread,
            null,
            decision,
            protectionSelected,
            ActiveTaskHealth(protectionSelected),
            status,
            attempt,
            isGuardianManaged);
    }

    private GuardianTaskState BuildDesktopRevisionGapState(
        ThreadSummary thread,
        RecoveryPolicySnapshot policy)
    {
        const string status =
            "The Codex Desktop state stream missed an update; targeted verification is pending.";
        var protectionSelected = ResolveConversationProtection(policy, thread);
        var attempt = _attempts.GetOrAdd(thread.Id, _ => new AttemptState());
        return BuildState(
            thread,
            null,
            RecoveryDecision.None(TaskHealth.Unknown, status),
            protectionSelected,
            TaskHealth.Unknown,
            status,
            attempt);
    }

    private GuardianTaskState BuildArchivedState(ThreadSummary thread)
    {
        var attempt = _attempts.GetOrAdd(thread.Id, _ => new AttemptState());
        attempt.ResetArchived();
        const string status = "Archived task is shown for history only and is not eligible for recovery.";
        return BuildState(
            thread,
            null,
            RecoveryDecision.None(TaskHealth.Paused, status),
            false,
            TaskHealth.Paused,
            status,
            attempt);
    }

    private void PruneTurnCache(IReadOnlyCollection<ThreadSummary> threads)
    {
        var currentIds = threads.Select(thread => thread.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var threadId in _turnCache.Keys)
        {
            if (!currentIds.Contains(threadId))
            {
                _turnCache.TryRemove(threadId, out _);
                _cacheVersions.TryRemove(threadId, out _);
            }
        }
    }

    private void PruneAttemptState(IReadOnlyCollection<ThreadSummary> threads)
    {
        var currentIds = threads.Select(thread => thread.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var threadId in _attempts.Keys)
        {
            if (!currentIds.Contains(threadId))
            {
                _attempts.TryRemove(threadId, out _);
            }
        }

        foreach (var threadId in _followUpAttempts.Keys)
        {
            if (!currentIds.Contains(threadId))
            {
                _followUpAttempts.TryRemove(threadId, out _);
            }
        }
    }

    private async Task RefreshFollowUpJournalSnapshotAsync(CancellationToken cancellationToken)
    {
        if (_followUps is null)
        {
            return;
        }

        await _followUpJournalRefreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            try
            {
                var snapshot = await _followUps.ReadJournalAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!snapshot.RequiresConservativeRecovery &&
                    snapshot.ReadStatus is not
                        FollowUpJournalReadStatus.Corrupted and not FollowUpJournalReadStatus.UnsupportedSchema)
                {
                    var pruned = await _followUps.PruneInactiveCompletedAsync(
                            CapturePolicySnapshot().ThreadFollowUps,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (pruned > 0)
                    {
                        _log.Trace($"Pruned {pruned} inactive completed follow-up journal record(s).");
                        snapshot = await _followUps.ReadJournalAsync(cancellationToken)
                            .ConfigureAwait(false);
                    }
                }

                _followUpJournalSnapshot = snapshot;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _followUpJournalSnapshot = new FollowUpJournalSnapshot(
                    FollowUpJournalReadStatus.Corrupted,
                    Generation: 0,
                    RequiresConservativeRecovery: true,
                    Records: []);
                _log.Error("The follow-up journal is unavailable; queued sends are blocked: " + exception.Message);
            }
        }
        finally
        {
            _followUpJournalRefreshGate.Release();
        }
    }

    private bool CanUseFollowUpJournal(RecoveryPolicySnapshot policy) =>
        _followUps is not null &&
        !_followUpJournalSnapshot.RequiresConservativeRecovery &&
        _followUpJournalSnapshot.ReadStatus is not
            FollowUpJournalReadStatus.Corrupted and not FollowUpJournalReadStatus.UnsupportedSchema;

    private static IReadOnlyDictionary<string, ThreadFollowUpSettings> CaptureSchedulableFollowUps(
        RecoveryPolicySnapshot policy) =>
        policy.ThreadFollowUps
            .Where(pair =>
                policy.GlobalProtectionEnabled &&
                pair.Value.IsEnabled &&
                policy.ThreadProtectionEnabled.TryGetValue(pair.Key, out var configured) &&
                configured)
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);

    private void PruneDesktopThreadState(IReadOnlySet<string> currentIds)
    {
        foreach (var threadId in _desktopActivityVetoes.Keys)
        {
            if (!currentIds.Contains(threadId))
            {
                _desktopActivityVetoes.TryRemove(threadId, out _);
            }
        }

        foreach (var threadId in _desktopRevisionGaps.Keys)
        {
            if (!currentIds.Contains(threadId))
            {
                _desktopRevisionGaps.TryRemove(threadId, out _);
            }
        }
    }

    private void InvalidateTurnCache(string? threadId)
    {
        if (!string.IsNullOrWhiteSpace(threadId))
        {
            _cacheVersions.AddOrUpdate(threadId, 1, static (_, version) => unchecked(version + 1));
            _turnCache.TryRemove(threadId, out _);
        }
    }

    private bool IsConversationProtectionSelected(ThreadSummary thread) =>
        ResolveConversationProtection(CapturePolicySnapshot(), thread);

    internal static IReadOnlyList<ThreadSummary> MergeThreadDirectory(
        IEnumerable<ThreadSummary> activeThreads,
        IEnumerable<ThreadSummary> archivedThreads) =>
        activeThreads
            .Concat(archivedThreads)
            .GroupBy(thread => thread.Id, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(thread => thread.IsArchived).First())
            .ToArray();

    internal static bool ResolveThreadProtection(AppSettings settings, ThreadSummary thread)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(thread);
        return settings.GlobalProtectionEnabled &&
               ResolveConversationProtection(
                   settings.IncludeSubAgents,
                   settings.ThreadProtectionEnabled,
                   thread);
    }

    internal static bool ResolveConversationProtection(
        AppSettings settings,
        ThreadSummary thread)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(thread);
        return ResolveConversationProtection(
            settings.IncludeSubAgents,
            settings.ThreadProtectionEnabled,
            thread);
    }

    private RecoveryPolicySnapshot CapturePolicySnapshot() => Volatile.Read(ref _policySnapshot);

    private RecoveryPolicySnapshot PublishPolicySnapshotLocked()
    {
        _policyVersion = checked(_policyVersion + 1);
        var snapshot = CreatePolicySnapshot(_policyVersion, _settings);
        Volatile.Write(ref _policySnapshot, snapshot);
        return snapshot;
    }

    private static RecoveryPolicySnapshot CreatePolicySnapshot(long version, AppSettings settings) =>
        new(
            version,
            settings.AutomaticRecoveryEnabled,
            settings.MonitorOnly,
            settings.GlobalProtectionEnabled,
            settings.IncludeSubAgents,
            settings.MaximumRecoveryAttempts,
            settings.UnlimitedRecoveryAttempts,
            settings.RecoveryCountingMode,
            new Dictionary<string, bool>(
                settings.ThreadProtectionEnabled,
                StringComparer.OrdinalIgnoreCase),
            new Dictionary<string, ThreadFollowUpSettings>(
                settings.ThreadFollowUps,
                StringComparer.OrdinalIgnoreCase),
            CreateKeepAliveSnapshot(settings));

    private static KeepAlivePolicySnapshot CreateKeepAliveSnapshot(AppSettings settings) =>
        new(
            settings.KeepAliveEnabled,
            settings.KeepAliveSentinelEnabled,
            settings.KeepAliveSentinelThreadId?.Trim() ?? string.Empty,
            TimeSpan.FromMinutes(Math.Clamp(
                settings.KeepAliveIntervalMinutes,
                AppSettings.MinimumKeepAliveIntervalMinutes,
                AppSettings.MaximumKeepAliveIntervalMinutes)),
            SettingsService.NormalizeKeepAliveMessage(settings.KeepAliveMessage),
            new Dictionary<string, bool>(
                settings.KeepAliveThreadEnabled,
                StringComparer.OrdinalIgnoreCase));

    private static bool ResolveThreadProtection(
        RecoveryPolicySnapshot policy,
        ThreadSummary thread) =>
        policy.GlobalProtectionEnabled &&
        ResolveConversationProtection(
            policy.IncludeSubAgents,
            policy.ThreadProtectionEnabled,
            thread);

    private static bool ResolveConversationProtection(
        RecoveryPolicySnapshot policy,
        ThreadSummary thread) =>
        ResolveConversationProtection(
            policy.IncludeSubAgents,
            policy.ThreadProtectionEnabled,
            thread);

    private static bool ResolveConversationProtection(
        bool includeSubAgents,
        IReadOnlyDictionary<string, bool> threadProtectionEnabled,
        ThreadSummary thread)
    {
        if (thread.IsArchived || thread.IsEphemeral ||
            thread.IsSubAgent && !includeSubAgents)
        {
            return false;
        }

        return threadProtectionEnabled.TryGetValue(thread.Id, out var configured) && configured;
    }

    private bool IsDispatchPolicyCurrent(ThreadSummary thread, long expectedPolicyVersion)
    {
        var policy = CapturePolicySnapshot();
        return policy.Version == expectedPolicyVersion &&
               policy.AutomaticRecoveryEnabled &&
               !policy.MonitorOnly &&
               policy.GlobalProtectionEnabled &&
               ResolveThreadProtection(policy, thread);
    }

    private bool IsFollowUpPolicyCurrent(
        ThreadSummary thread,
        string messageId,
        string messageHash,
        long expectedPolicyVersion)
    {
        var policy = CapturePolicySnapshot();
        if (policy.Version != expectedPolicyVersion ||
            !policy.GlobalProtectionEnabled ||
            !ResolveConversationProtection(policy, thread) ||
            !policy.ThreadFollowUps.TryGetValue(thread.Id, out var configured) ||
            !configured.IsEnabled)
        {
            return false;
        }

        var message = configured.Messages.SingleOrDefault(candidate =>
            string.Equals(candidate.Id, messageId, StringComparison.OrdinalIgnoreCase));
        return message is not null &&
               PresetAutomationPolicy.IsLegacyQueueMessageAuthorized(configured, message) &&
               string.Equals(
                   FollowUpOperationJournal.ComputeMessageHash(
                       SettingsService.NormalizeFollowUpMessage(message.Message)),
                   messageHash,
                   StringComparison.Ordinal);
    }

    internal static TaskHealth ActiveTaskHealth(bool protectionEnabled)
    {
        _ = protectionEnabled;
        return TaskHealth.Processing;
    }

    internal static (TaskHealth Health, string Status) DescribeUnprotectedRecovery(RecoveryDecision decision) =>
        (decision.Health, ProtectionPausedStatus);

    internal static bool IsProtocolThreadActive(ThreadSummary thread) =>
        string.Equals(thread.RuntimeStatus, "active", StringComparison.OrdinalIgnoreCase);

    internal static bool IsFailedRecoverySuccessor(
        TurnSnapshot turn,
        RecoveryOperationRecord? recoverySuccessor) =>
        recoverySuccessor is not null &&
        (string.Equals(turn.Status, "failed", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(turn.Status, "interrupted", StringComparison.OrdinalIgnoreCase) &&
         turn.HasConfirmedLocalTerminal ||
         string.Equals(
             turn.Status,
             RecoveryClassifier.IncompleteTerminalStatus,
             StringComparison.OrdinalIgnoreCase));

    // An inexact successor is a residual record whose new turn id was never confirmed, which the
    // edit-last-user-turn contract produces on any confirmation timeout because it does not read the id
    // back. Treating that as a permanent block stranded the task: the block flag outlived every later
    // failure. An in-place retry is dispatched anyway -- the owner's expected-turn compare-and-swap either
    // applies the edit or rejects it as stale, so no message can be duplicated. Append actions keep the
    // stricter rule, because a lost acknowledgement there could mean a message did land.
    internal static bool ShouldBlockFailedRecoverySuccessor(
        TurnSnapshot turn,
        RecoveryOperationRecord? recoverySuccessor,
        bool isExactSuccessorMatch,
        RecoveryActionKind plannedAction = RecoveryActionKind.None) =>
        recoverySuccessor is not null &&
        IsFailedRecoverySuccessor(turn, recoverySuccessor) &&
        ((!isExactSuccessorMatch &&
          !RecoveryOperationJournal.IsInPlaceRetryAction(plannedAction)) ||
         recoverySuccessor.CountingMode == RecoveryCountingMode.OriginalFailedTurnOnly);

    internal static bool CanReuseTurnSnapshot(
        ThreadSummary thread,
        long cachedThreadUpdatedAt,
        string? cachedTurnStatus,
        DateTimeOffset cachedAt,
        DateTimeOffset now)
    {
        var age = now - cachedAt;
        if (age < TimeSpan.Zero)
        {
            return false;
        }

        if (string.Equals(cachedTurnStatus, "inProgress", StringComparison.OrdinalIgnoreCase))
        {
            return age < ActiveTurnCacheLifetime;
        }

        return cachedThreadUpdatedAt == thread.UpdatedAt;
    }

    // Seed once per thread from the durable journal. A resend that landed before this process started
    // is invisible to `Attempts`, which is precisely why a working recovery could look to the user like
    // one that had never fired. A failed read is non-fatal: the ledger only describes history and must
    // never block a dispatch.
    //
    // Every path that projects a thread into a `GuardianTaskState` has to come through here, not just
    // the recovery evaluation: a task that is running, archived, or parked behind a revision gap gets
    // its state from `BuildActiveState`/`BuildArchivedState`/`BuildDesktopRevisionGapState`, which take
    // an unseeded `AttemptState` straight out of the dictionary. That is exactly the window a freshly
    // resent task sits in — the successor turn is streaming, so the thread reads as active — so seeding
    // only inside the recovery path meant the ledger read 0 at the very moment it had something to say.
    private async Task<AttemptState> EnsureAttemptLedgerSeededAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        var attempt = _attempts.GetOrAdd(threadId, _ => new AttemptState());
        if (!attempt.IsRecoveryLedgerSeeded)
        {
            var ledger = await _recovery.ReadRecoveryLedgerAsync(threadId, cancellationToken)
                .ConfigureAwait(false);
            attempt.SeedRecoveryLedger(ledger);
            if (ledger.ConfirmedDispatches > 0)
            {
                // Once per thread per process. Without this line there is no way to tell a thread that
                // has never been resent from one whose history failed to load, which is the difference
                // between "the ledger says zero" and "the ledger did not arrive".
                _log.Trace(
                    "Seeded resend history from the durable journal: " +
                    ledger.ConfirmedDispatches.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                    " confirmed dispatch(es).",
                    threadId);
            }
        }

        return attempt;
    }

    internal Task<GuardianTaskState> EvaluateThreadForCurrentPolicyAsync(
        ThreadSummary thread,
        TurnSnapshot? turn,
        long scopeGeneration,
        CancellationToken cancellationToken = default) =>
        EvaluateThreadAsync(
            thread,
            turn,
            CapturePolicySnapshot(),
            scopeGeneration,
            cancellationToken);

    private async Task<GuardianTaskState> EvaluateThreadAsync(
        ThreadSummary thread,
        TurnSnapshot? turn,
        RecoveryPolicySnapshot policy,
        long scopeGeneration,
        CancellationToken cancellationToken)
    {
        var protectionSelected = ResolveConversationProtection(policy, thread);
        var recoveryAuthorized =
            policy.AutomaticRecoveryEnabled &&
            !policy.MonitorOnly &&
            policy.GlobalProtectionEnabled &&
            protectionSelected;

        var decision = _classifier.Classify(turn);
        var attempt = await EnsureAttemptLedgerSeededAsync(thread.Id, cancellationToken)
            .ConfigureAwait(false);

        var journalAvailable = true;
        string? journalError = null;
        RecoveryOperationRecord? recoverySuccessor = null;
        var recoverySuccessorExact = false;
        string? recoveredFromTurnId = null;

        if (turn is null)
        {
            const string noHistory = "No turn history is available for this historical task.";
            var noHistoryDecision = RecoveryDecision.None(TaskHealth.NoHistory, noHistory);
            RecordClassificationIfChanged(thread.Id, turn, noHistoryDecision);
            return BuildState(
                thread,
                turn,
                noHistoryDecision,
                protectionSelected,
                TaskHealth.NoHistory,
                noHistory,
                attempt);
        }

        RecordClassificationIfChanged(thread.Id, turn, decision);

        try
        {
            var journalReconciliation = await _recovery
                .ReconcileCurrentTurnAsync(thread.Id, turn, cancellationToken)
                .ConfigureAwait(false);
            recoverySuccessor = journalReconciliation.RecoverySuccessor;
            recoverySuccessorExact = journalReconciliation.IsExactSuccessorMatch;
            recoveredFromTurnId = journalReconciliation.IsExactSuccessorMatch
                ? journalReconciliation.RecoverySuccessor?.FailedTurnId
                : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            journalAvailable = false;
            journalError = exception.Message;
            attempt.BlockForJournalFailure(exception.Message);
            _log.Error("Unable to reconcile the current turn with recovery operations: " + exception.Message, thread.Id);
        }

        if (string.Equals(turn.Status, "completed", StringComparison.OrdinalIgnoreCase) &&
            decision.Health == TaskHealth.Healthy)
        {
            if (attempt.LastHealthyTurnId != turn.Id)
            {
                attempt.ResetHealthy(turn.Id);
            }

            var state = await EvaluateFollowUpAsync(
                    thread,
                    turn,
                    decision,
                    protectionSelected,
                    policy.GlobalProtectionEnabled && protectionSelected,
                    policy,
                    attempt,
                    recoveredFromTurnId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (FollowUpQueuePlanner.IsNormalCompletion(turn))
            {
                EventSubscriberDispatcher.Invoke(
                    WorkflowCompletionObserved,
                    this,
                    new WorkflowAuthoritativeCompletionEventArgs(
                        thread,
                        turn,
                        DateTimeOffset.UtcNow));
            }

            return state;
        }

        if (ShouldBlockFailedRecoverySuccessor(
                turn,
                recoverySuccessor,
                recoverySuccessorExact,
                decision.Action))
        {
            if (attempt.BlockRecoverySuccessorFailure(turn.Id, RecoveryChainBlockedStatus))
            {
                _log.Warning(RecoveryChainBlockedStatus, thread.Id);
            }

            var blockedDecision = RecoveryDecision.None(TaskHealth.ManualReview, RecoveryChainBlockedStatus);
            return BuildState(
                thread,
                turn,
                blockedDecision,
                protectionSelected,
                TaskHealth.ManualReview,
                RecoveryChainBlockedStatus,
                attempt);
        }

        // A heartbeat that went unanswered is not a failure worth recovering. Resending it would
        // repeat one message on the recovery cadence instead of the keep-alive interval, which is
        // both louder than holding the slot needs to be and the repetition pattern the generated
        // wording exists to avoid. The next interval sends a fresh one.
        if (_keepAlive.IsKeepAliveTurn(thread.Id, turn) &&
            decision.Action != RecoveryActionKind.None)
        {
            // Not marked Healthy: that would arm the sentinel, and an unanswered heartbeat is no proof
            // the way in is open — it is the opposite.
            const string heldStatus = "A keep-alive turn went unanswered; the next interval sends a fresh one.";
            var heldDecision = RecoveryDecision.None(TaskHealth.Unknown, heldStatus);
            RecordClassificationIfChanged(thread.Id, turn, heldDecision);
            return BuildState(
                thread,
                turn,
                heldDecision,
                protectionSelected,
                TaskHealth.Unknown,
                heldStatus,
                attempt);
        }

        if (decision.Action == RecoveryActionKind.None)
        {
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                decision.Health,
                decision.Reason,
                attempt);
        }

        if (!recoveryAuthorized)
        {
            if (journalAvailable)
            {
                try
                {
                    var existingOperation = await _recovery
                        .ReconcileExistingOperationAsync(thread, turn, cancellationToken)
                        .ConfigureAwait(false);
                    attempt.ApplyExistingOperation(existingOperation);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    _log.Error(
                        "Unable to reconcile an existing recovery operation while protection is off: " +
                        exception.Message,
                        thread.Id);
                }
            }

            attempt.ReleaseDesktopWait();
            attempt.NextAttemptAt = null;
            var disabledState = DescribeUnprotectedRecovery(decision);
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                disabledState.Health,
                policy.GlobalProtectionEnabled
                    ? disabledState.Status
                    : GlobalProtectionPausedStatus,
                attempt);
        }

        if (!attempt.FailureTurnId.Equals(turn.Id, StringComparison.OrdinalIgnoreCase))
        {
            attempt.BeginFailure(turn.Id, decision, FirstRetryDelay);
            _log.Warning(decision.Reason, thread.Id);
        }

        if (!journalAvailable)
        {
            attempt.BlockForJournalFailure(journalError ?? "unknown journal failure");
        }

        try
        {
            if (journalAvailable)
            {
                var persistedOperation = await _recovery.FindOperationAsync(
                        thread.Id,
                        turn.Id,
                        cancellationToken)
                    .ConfigureAwait(false);
                attempt.ApplyJournal(persistedOperation);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            attempt.BlockForJournalFailure(exception.Message);
            _log.Error("Unable to read the durable recovery journal: " + exception.Message, thread.Id);
        }

        if (attempt.IsJournalBlocked || attempt.IsBlockedUntilNewFailureTurn)
        {
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                TaskHealth.ManualReview,
                attempt.LastEvent,
                attempt);
        }

        if (policy.MonitorOnly)
        {
            attempt.NextAttemptAt = null;
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                decision.Health,
                "Monitor-only: " + decision.Reason,
                attempt);
        }

        if (attempt.ActionCommitted)
        {
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                TaskHealth.Processing,
                GuardianBackgroundRunningStatus,
                attempt,
                isGuardianManagedActivity: true);
        }

        if (attempt.IsWaitingForDesktopSignal)
        {
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                TaskHealth.WaitingForDesktop,
                attempt.LastEvent,
                attempt);
        }

        if (attempt.LastFailureKind == RecoveryFailureKind.UserActive &&
            _userIdleWaiters.ContainsKey(thread.Id))
        {
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                TaskHealth.WaitingForIdle,
                WaitingForUserIdleStatus,
                attempt);
        }

        var now = DateTimeOffset.Now;
        if (attempt.NextAttemptAt is not null && attempt.NextAttemptAt > now)
        {
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                RecoveryCooldownHealth(attempt.LastFailureKind, decision.Health),
                RecoveryCooldownStatus(attempt.LastFailureKind, decision.Reason),
                attempt);
        }

        var desktopWakeVersion = Volatile.Read(ref _desktopWakeVersion);
        var result = await _recovery.ExecuteAsync(
            thread,
            turn,
            decision,
            _settings.ContinueMessage,
            policy.IncludeSubAgents,
            scopeGeneration,
            () => IsDispatchPolicyCurrent(thread, policy.Version),
            cancellationToken);
        _log.WriteRecoveryResult(thread.Id, turn.Id, decision.Action, result);
        if (result.Success)
        {
            attempt.Attempts++;
            attempt.ActionCommitted = true;
            attempt.LastEvent = result.Message;
            attempt.NextAttemptAt = null;
            // Mirror the journal's rule exactly — only a dispatch that returned a successor turn counts
            // — so a restart that re-seeds this ledger cannot contradict the number already shown.
            if (!string.IsNullOrWhiteSpace(result.NewTurnId))
            {
                attempt.RecordConfirmedDispatch(now);
            }

            _log.Success(result.Message, thread.Id);
            return BuildState(
                thread,
                turn,
                decision,
                protectionSelected,
                TaskHealth.Processing,
                GuardianBackgroundRunningStatus,
                attempt,
                isGuardianManagedActivity: true);
        }

        if (!result.IsUserBlocked)
        {
            attempt.Attempts++;
        }

        // The busy-owner refusal used to be the quietest thing Guardian did: correct, repeated every
        // scan, and completely silent after the first line because the message never changed. Count it
        // and let the count itself break the suppression at widening thresholds, so a wait that has
        // been running for hours says so instead of looking like a stopped guardian.
        var ownerBusyStallRefusals = result.OwnerRuntimeStatus is { Length: > 0 }
            ? attempt.RecordOwnerBusyRefusal(now)
            : null;
        // A blocker that locks until a new failed turn ends the busy-owner story outright. A passing one
        // — the user typing, a dropped Desktop connection — does not: the idleness check never even ran,
        // so it is still the same wait and its clock has to keep running.
        if (result.OwnerRuntimeStatus is null && ShouldLockFailureUntilNewTurn(result.FailureKind))
        {
            attempt.ClearOwnerBusyStall();
        }

        var failureEvent = result.FailureKind == RecoveryFailureKind.UserActive
            ? WaitingForUserIdleStatus
            : result.Message;
        var repeatedFailure = ownerBusyStallRefusals is null &&
                              attempt.LastFailureKind == result.FailureKind &&
                              string.Equals(attempt.LastEvent, failureEvent, StringComparison.Ordinal);
        attempt.LastEvent = failureEvent;
        attempt.LastFailureKind = result.FailureKind;
        attempt.SetFailureLock(result.FailureKind);
        var desktopSignalChanged = IsDesktopEventDrivenFailure(result.FailureKind) &&
                                   Volatile.Read(ref _desktopWakeVersion) != desktopWakeVersion;
        attempt.SetDesktopWait(result.FailureKind, !desktopSignalChanged);
        attempt.NextAttemptAt = NextAttemptAfterFailure(
            result.FailureKind,
            now,
            AttemptRetryDelay,
            desktopSignalChanged);
        if (result.FailureKind == RecoveryFailureKind.DesktopUnavailable)
        {
            ScheduleDesktopReconnect();
        }
        else if (result.FailureKind == RecoveryFailureKind.UserActive)
        {
            ScheduleUserIdleWake(thread.Id);
        }
        if (!repeatedFailure)
        {
            _log.Warning(
                ownerBusyStallRefusals is { } stalledRefusals
                    ? DescribeOwnerBusyStall(attempt.LastEvent, stalledRefusals, attempt.RecoveryLedger, now)
                    : attempt.LastEvent,
                thread.Id);
        }
        var failureHealth = result.FailureKind switch
        {
            RecoveryFailureKind.UserActive => TaskHealth.WaitingForIdle,
            RecoveryFailureKind.DesktopOwnerUnavailable or RecoveryFailureKind.DesktopUnavailable =>
                TaskHealth.WaitingForDesktop,
            RecoveryFailureKind.StateChanged or
            RecoveryFailureKind.AtomicGuardUnavailable or
            RecoveryFailureKind.DesktopIncompatible => TaskHealth.ManualReview,
            RecoveryFailureKind.PolicyChanged => TaskHealth.Paused,
            _ => decision.Health
        };
        return BuildState(
            thread,
            turn,
            decision,
            IsConversationProtectionSelected(thread),
            failureHealth,
            attempt.LastEvent,
            attempt);
    }

    private async Task<GuardianTaskState> EvaluateFollowUpAsync(
        ThreadSummary thread,
        TurnSnapshot completedTurn,
        RecoveryDecision decision,
        bool protectionSelected,
        bool presetSubmissionAuthorized,
        RecoveryPolicySnapshot policy,
        AttemptState recoveryAttempt,
        string? recoveredFromTurnId,
        CancellationToken cancellationToken)
    {
        if (_followUps is null)
        {
            _followUpAttempts.TryRemove(thread.Id, out _);
            return BuildState(
                thread,
                completedTurn,
                decision,
                protectionSelected,
                decision.Health,
                decision.Reason,
                recoveryAttempt);
        }

        policy.ThreadFollowUps.TryGetValue(thread.Id, out var configured);
        var operations = _followUpJournalSnapshot.Records
            .Where(operation => string.Equals(
                operation.ThreadId,
                thread.Id,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var followUpAttempt = _followUpAttempts.GetOrAdd(
            thread.Id,
            static _ => new FollowUpAttemptState());
        var queue = FollowUpQueuePlanner.Evaluate(
            configured,
            completedTurn,
            operations,
            DateTimeOffset.UtcNow,
            recoveredFromTurnId);
        GuardianTaskState WithFollowUpQueue(GuardianTaskState state) =>
            state with
            {
                FollowUpQueue = FollowUpQueuePlanner.DescribeRuntime(
                    configured,
                    queue,
                    operations),
                // `BuildFollowUpState` projects a `FollowUpAttemptState`, which has no recovery history
                // of its own, so the resend ledger has to be carried over from the recovery attempt
                // state here. Without this a task that finished a turn and moved on to follow-ups
                // reported zero resends even though it had just been recovered.
                RecoveryLedger = recoveryAttempt.RecoveryLedger
            };
        var pendingCount = operations.Count(operation => operation.State is
            FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain);
        if (pendingCount > 1)
        {
            followUpAttempt.MarkFailure(
                FollowUpDispatchFailureKind.PersistenceFailed,
                queue.Detail,
                DateTimeOffset.UtcNow,
                TimeSpan.Zero);
            return WithFollowUpQueue(BuildFollowUpState(
                thread,
                completedTurn,
                decision,
                protectionSelected,
                TaskHealth.ManualReview,
                queue.Detail,
                followUpAttempt));
        }

        if (queue.Kind == FollowUpQueueDecisionKind.ReconcilePending && queue.PendingOperation is not null)
        {
            var reconciliation = await _followUps.ReconcilePendingAsync(
                    thread,
                    queue.PendingOperation,
                    cancellationToken)
                .ConfigureAwait(false);
            await RefreshFollowUpJournalSnapshotAsync(cancellationToken).ConfigureAwait(false);
            operations = _followUpJournalSnapshot.Records
                .Where(operation => string.Equals(
                    operation.ThreadId,
                    thread.Id,
                    StringComparison.OrdinalIgnoreCase))
                .ToArray();
            queue = FollowUpQueuePlanner.Evaluate(
                configured,
                completedTurn,
                operations,
                DateTimeOffset.UtcNow,
                recoveredFromTurnId);
            if (!reconciliation.Success)
            {
                followUpAttempt.MarkFailure(
                    reconciliation.FailureKind,
                    reconciliation.Message,
                    DateTimeOffset.UtcNow,
                    TimeSpan.Zero);
                _log.Warning(reconciliation.Message, thread.Id);
                return WithFollowUpQueue(BuildFollowUpState(
                    thread,
                    completedTurn,
                    decision,
                    protectionSelected,
                    TaskHealth.ManualReview,
                    reconciliation.Message,
                    followUpAttempt));
            }

            followUpAttempt.MarkSuccess(reconciliation.Message);
            _log.Success(reconciliation.Message, thread.Id);
        }

        try
        {
            var completedOperation = await _followUps.MarkCompletedAsync(
                    thread.Id,
                    completedTurn.Id,
                    recoveredFromTurnId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (completedOperation is not null)
            {
                await RefreshFollowUpJournalSnapshotAsync(cancellationToken).ConfigureAwait(false);
                operations = _followUpJournalSnapshot.Records
                    .Where(operation => string.Equals(
                        operation.ThreadId,
                        thread.Id,
                        StringComparison.OrdinalIgnoreCase))
                    .ToArray();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Error(
                "Unable to persist the normal completion of a follow-up; queued sends are blocked: " +
                exception.Message,
                thread.Id);
            _followUpJournalSnapshot = _followUpJournalSnapshot with
            {
                RequiresConservativeRecovery = true
            };
        }

        if (!presetSubmissionAuthorized || configured is null || !configured.IsEnabled)
        {
            _followUpAttempts.TryRemove(thread.Id, out _);
            return WithFollowUpQueue(BuildState(
                thread,
                completedTurn,
                decision,
                protectionSelected,
                decision.Health,
                decision.Reason,
                recoveryAttempt));
        }

        queue = FollowUpQueuePlanner.Evaluate(
            configured,
            completedTurn,
            operations,
            DateTimeOffset.UtcNow,
            recoveredFromTurnId);

        if (queue.Kind == FollowUpQueueDecisionKind.Blocked || !CanUseFollowUpJournal(policy))
        {
            var detail = queue.Kind == FollowUpQueueDecisionKind.Blocked
                ? queue.Detail
                : "The follow-up journal requires conservative review; queued sends are blocked.";
            followUpAttempt.MarkFailure(
                FollowUpDispatchFailureKind.PersistenceFailed,
                detail,
                DateTimeOffset.UtcNow,
                TimeSpan.Zero);
            return WithFollowUpQueue(BuildFollowUpState(
                thread,
                completedTurn,
                decision,
                protectionSelected,
                TaskHealth.ManualReview,
                detail,
                followUpAttempt));
        }

        if (queue.Kind != FollowUpQueueDecisionKind.Ready || queue.Message is null)
        {
            return WithFollowUpQueue(BuildState(
                thread,
                completedTurn,
                decision,
                protectionSelected,
                decision.Health,
                queue.Kind == FollowUpQueueDecisionKind.Waiting &&
                queue.NextScheduledAtUtc is not null
                    ? "A queued follow-up is waiting for its scheduled time."
                    : decision.Reason,
                recoveryAttempt));
        }

        followUpAttempt.MarkDispatchStarted();
        var messageHash = FollowUpOperationJournal.ComputeMessageHash(
            SettingsService.NormalizeFollowUpMessage(queue.Message.Message));
        var result = await _followUps.ExecuteAsync(
                thread,
                completedTurn,
                queue.Message,
                policy.IncludeSubAgents,
                () => IsFollowUpPolicyCurrent(
                    thread,
                    queue.Message.Id,
                    messageHash,
                    policy.Version),
                cancellationToken)
            .ConfigureAwait(false);
        await RefreshFollowUpJournalSnapshotAsync(cancellationToken).ConfigureAwait(false);
        operations = _followUpJournalSnapshot.Records
            .Where(operation => string.Equals(
                operation.ThreadId,
                thread.Id,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        queue = FollowUpQueuePlanner.Evaluate(
            configured,
            completedTurn,
            operations,
            DateTimeOffset.UtcNow,
            recoveredFromTurnId);
        if (result.Success)
        {
            followUpAttempt.MarkSuccess(result.Message);
            _log.Success(result.Message, thread.Id);
            return WithFollowUpQueue(BuildFollowUpState(
                thread,
                completedTurn,
                decision,
                protectionSelected,
                TaskHealth.Processing,
                "A queued follow-up turn is running in the background.",
                followUpAttempt,
                isGuardianManagedActivity: true));
        }

        var now = DateTimeOffset.UtcNow;
        followUpAttempt.MarkFailure(
            result.FailureKind,
            result.Message,
            now,
            ComputeBackoff(Math.Max(1, followUpAttempt.Attempts), thread.Id));
        if (result.FailureKind == FollowUpDispatchFailureKind.DesktopUnavailable)
        {
            ScheduleDesktopReconnect();
        }
        else if (result.FailureKind == FollowUpDispatchFailureKind.UserActive)
        {
            ScheduleUserIdleWake(thread.Id);
        }

        var health = result.FailureKind switch
        {
            FollowUpDispatchFailureKind.UserActive => TaskHealth.WaitingForIdle,
            FollowUpDispatchFailureKind.DesktopUnavailable or
                FollowUpDispatchFailureKind.DesktopOwnerUnavailable => TaskHealth.WaitingForDesktop,
            FollowUpDispatchFailureKind.PolicyChanged => TaskHealth.Paused,
            _ => TaskHealth.ManualReview
        };
        _log.Warning(result.Message, thread.Id);
        return WithFollowUpQueue(BuildFollowUpState(
            thread,
            completedTurn,
            decision,
            protectionSelected,
            health,
            result.Message,
            followUpAttempt));
    }

    internal static DateTimeOffset? NextAttemptAfterFailure(
        RecoveryFailureKind failureKind,
        DateTimeOffset now,
        TimeSpan transportBackoff,
        bool desktopSignalChanged = false) => failureKind switch
        {
            RecoveryFailureKind.DesktopUnavailable =>
                desktopSignalChanged ? now : null,
            RecoveryFailureKind.DesktopOwnerUnavailable => now + transportBackoff,
            RecoveryFailureKind.UserActive => now + UserActivityRetryDelay,
            RecoveryFailureKind.StateChanged or
            RecoveryFailureKind.AtomicGuardUnavailable or
            RecoveryFailureKind.DesktopIncompatible or
            RecoveryFailureKind.PolicyChanged => null,
            _ => now + transportBackoff
        };

    private void ScheduleUserIdleWake(string threadId)
    {
        if (!IsRunning || !_userIdleWaiters.TryAdd(threadId, 0))
        {
            return;
        }

        _ = WaitForUserIdleAndScheduleScanAsync(threadId, _monitorLifecycle.CancellationToken);
    }

    private async Task WaitForUserIdleAndScheduleScanAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        var shouldScan = false;
        try
        {
            await _recovery.WaitForRecoveryInterferenceToClearAsync(threadId, cancellationToken).ConfigureAwait(false);
            shouldScan = true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to wait for a clear Codex composer: " + exception.Message);
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
                shouldScan = true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }
        finally
        {
            _userIdleWaiters.TryRemove(threadId, out _);
        }

        if (shouldScan &&
            !cancellationToken.IsCancellationRequested &&
            IsRunning &&
            _attempts.TryGetValue(threadId, out var attempt) &&
            ShouldWakeUserIdleWaiter(attempt.NextAttemptAt, DateTimeOffset.Now))
        {
            InvalidateTurnCache(threadId);
            RequestThreadRefresh(threadId);
        }
    }

    internal static bool ShouldWakeUserIdleWaiter(
        DateTimeOffset? nextAttemptAt,
        DateTimeOffset now) =>
        nextAttemptAt is null || nextAttemptAt <= now;

    internal static TaskHealth RecoveryCooldownHealth(
        RecoveryFailureKind failureKind,
        TaskHealth fallback) => failureKind switch
        {
            RecoveryFailureKind.UserActive => TaskHealth.WaitingForIdle,
            RecoveryFailureKind.DesktopOwnerUnavailable or
                RecoveryFailureKind.DesktopUnavailable => TaskHealth.WaitingForDesktop,
            _ => fallback
        };

    internal static string RecoveryCooldownStatus(
        RecoveryFailureKind failureKind,
        string fallback) => failureKind switch
        {
            RecoveryFailureKind.UserActive => WaitingForUserIdleStatus,
            RecoveryFailureKind.DesktopOwnerUnavailable or
                RecoveryFailureKind.DesktopUnavailable => WaitingForDesktopStatus,
            _ => fallback
        };

    internal static bool IsDesktopEventDrivenFailure(RecoveryFailureKind failureKind) =>
        failureKind == RecoveryFailureKind.DesktopUnavailable;

    internal static bool ShouldLockFailureUntilNewTurn(RecoveryFailureKind failureKind) =>
        failureKind is RecoveryFailureKind.StateChanged or
            RecoveryFailureKind.AtomicGuardUnavailable or
            RecoveryFailureKind.DesktopIncompatible;

    // Roughly 30 s per scan, so the first stall report lands ~2.5 minutes into a wait and the
    // doubling keeps a wait that runs for hours down to a handful of lines instead of a
    // per-scan transcript.
    internal const int OwnerBusyStallReportThreshold = 5;

    // Hoisted out of AttemptState so the 5/10/20/40 escalation is testable: the nested class is
    // private and InternalsVisibleTo cannot reach it, and this schedule is the whole reason a
    // multi-hour wait produces four log lines instead of four hundred.
    internal static bool ShouldReportOwnerBusyStall(int refusals, int lastReportedRefusals) =>
        refusals >= OwnerBusyStallReportThreshold && refusals >= lastReportedRefusals * 2;

    // The stall line is the only place the log says out loud how long the wait has run and whether a
    // resend ever got through, so it carries both: a bare refusal count reads as churn, and the
    // dispatch history is exactly the fact that separates "blocked downstream" from "never tried".
    internal static string DescribeOwnerBusyStall(
        string message,
        int refusals,
        GuardianRecoveryLedger ledger,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(ledger);
        var history = ledger.HasEverDispatched
            ? $"{ledger.ConfirmedDispatches} recovery dispatch(es) already confirmed for this task"
            : "no recovery dispatch has been confirmed for this task yet";
        return $"{message} Declined {refusals} time(s) over " +
               $"{FormatStallDuration(ledger.OwnerBusyDuration(now))}; {history}.";
    }

    internal static string FormatStallDuration(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
        {
            duration = TimeSpan.Zero;
        }

        return duration.TotalHours >= 1
            ? $"{(int)duration.TotalHours}h{duration.Minutes:00}m"
            : duration.TotalMinutes >= 1
                ? $"{(int)duration.TotalMinutes}m{duration.Seconds:00}s"
                : $"{(int)duration.TotalSeconds}s";
    }

    private GuardianTaskState BuildUnavailableState(
        ThreadSummary thread,
        string error,
        RecoveryPolicySnapshot policy)
    {
        var attempt = _attempts.GetOrAdd(thread.Id, _ => new AttemptState());
        var protectionSelected = ResolveConversationProtection(policy, thread);
        return new GuardianTaskState(
            thread,
            null,
            RecoveryDecision.None(TaskHealth.Unknown, error),
            protectionSelected,
            TaskHealth.Unknown,
            "Unable to read latest turn",
            error,
            attempt.Attempts,
            attempt.NextAttemptAt,
            RecoveryLedger: attempt.RecoveryLedger);
    }

    private static GuardianTaskState BuildState(
        ThreadSummary thread,
        TurnSnapshot? turn,
        RecoveryDecision decision,
        bool enabled,
        TaskHealth health,
        string status,
        AttemptState attempt,
        bool isGuardianManagedActivity = false)
    {
        return new GuardianTaskState(
            ProjectLatestTurnActivity(thread, turn),
            turn,
            decision,
            enabled,
            health,
            status,
            string.IsNullOrWhiteSpace(attempt.LastEvent) ? status : attempt.LastEvent,
            attempt.Attempts,
            attempt.NextAttemptAt,
            isGuardianManagedActivity,
            RecoveryLedger: attempt.RecoveryLedger);
    }

    private static GuardianTaskState BuildFollowUpState(
        ThreadSummary thread,
        TurnSnapshot turn,
        RecoveryDecision decision,
        bool enabled,
        TaskHealth health,
        string status,
        FollowUpAttemptState attempt,
        bool isGuardianManagedActivity = false) =>
        new(
            ProjectLatestTurnActivity(thread, turn),
            turn,
            decision,
            enabled,
            health,
            status,
            string.IsNullOrWhiteSpace(attempt.LastEvent) ? status : attempt.LastEvent,
            attempt.Attempts,
            attempt.NextAttemptAt,
            isGuardianManagedActivity);

    internal static ThreadSummary ProjectLatestTurnActivity(
        ThreadSummary thread,
        TurnSnapshot? turn)
    {
        ArgumentNullException.ThrowIfNull(thread);
        if (turn is null)
        {
            return thread;
        }

        var latestActivityAt = thread.UpdatedAt;
        if (turn.StartedAt is long startedAt)
        {
            latestActivityAt = Math.Max(latestActivityAt, startedAt);
        }

        if (turn.CompletedAt is long completedAt)
        {
            latestActivityAt = Math.Max(latestActivityAt, completedAt);
        }

        return latestActivityAt == thread.UpdatedAt
            ? thread
            : thread with { UpdatedAt = latestActivityAt };
    }

    private TimeSpan ComputeBackoff(int failureNumber, string threadId)
    {
        var exponent = Math.Clamp(failureNumber - 1, 0, 8);
        var seconds = Math.Min(
            _settings.MaximumBackoffSeconds,
            _settings.BaseBackoffSeconds * Math.Pow(2, exponent));
        var stableJitter = Math.Abs(StringComparer.OrdinalIgnoreCase.GetHashCode(threadId) % 1000) / 1000d;
        seconds = Math.Min(_settings.MaximumBackoffSeconds, seconds * (1 + stableJitter * 0.18));
        return TimeSpan.FromSeconds(seconds);
    }

    private static int HealthOrder(TaskHealth health)
    {
        return health switch
        {
            TaskHealth.NeedsAttention => 0,
            TaskHealth.WaitingForIdle => 1,
            TaskHealth.WaitingForDesktop => 2,
            TaskHealth.CoolingDown => 3,
            TaskHealth.Recovering => 4,
            TaskHealth.ManualReview => 5,
            TaskHealth.Processing => 6,
            TaskHealth.Unknown => 7,
            TaskHealth.NoHistory => 8,
            TaskHealth.Healthy => 9,
            TaskHealth.Paused => 10,
            _ => 10
        };
    }

    private void RecordClassificationIfChanged(
        string threadId,
        TurnSnapshot? turn,
        RecoveryDecision decision)
    {
        var fingerprint = string.Join(
            '|',
            turn?.Id,
            turn?.Status,
            turn?.HasUserMessage,
            turn?.HasAssistantOutput,
            turn?.HasFinalAssistantOutput,
            turn?.HasCommentaryOutput,
            turn?.HasReasoningOutput,
            turn?.HasToolActivity,
            turn?.HasAmbiguousActivity,
            turn?.HasCompleteItemEvidence,
            turn?.HasConfirmedLocalTerminal,
            decision.Action,
            decision.Health);
        if (_diagnosticClassificationFingerprints.TryGetValue(threadId, out var previous) &&
            string.Equals(previous, fingerprint, StringComparison.Ordinal))
        {
            return;
        }

        _diagnosticClassificationFingerprints[threadId] = fingerprint;
        _log.WriteClassification(threadId, turn, decision);
    }

    private sealed record CachedTurnState(
        long ThreadUpdatedAt,
        DateTimeOffset CheckedAt,
        TurnSnapshot? Turn);

    private sealed record RecoveryPolicySnapshot(
        long Version,
        bool AutomaticRecoveryEnabled,
        bool MonitorOnly,
        bool GlobalProtectionEnabled,
        bool IncludeSubAgents,
        int MaximumRecoveryAttempts,
        bool UnlimitedRecoveryAttempts,
        RecoveryCountingMode RecoveryCountingMode,
        IReadOnlyDictionary<string, bool> ThreadProtectionEnabled,
        IReadOnlyDictionary<string, ThreadFollowUpSettings> ThreadFollowUps,
        KeepAlivePolicySnapshot KeepAlive);

    private sealed class AttemptState
    {
        private int _reportedOwnerBusyRefusals;

        public string FailureTurnId { get; private set; } = string.Empty;

        public string LastHealthyTurnId { get; private set; } = string.Empty;

        public int ConsecutiveFailures { get; private set; }

        public int Attempts { get; set; }

        public bool ActionCommitted { get; set; }

        public bool IsWaitingForDesktopSignal { get; private set; }

        public bool IsBlockedUntilNewFailureTurn { get; private set; }

        public bool IsJournalBlocked { get; private set; }

        public DateTimeOffset? NextAttemptAt { get; set; }

        public string LastEvent { get; set; } = string.Empty;

        public RecoveryFailureKind LastFailureKind { get; set; }

        // Per-thread lifetime history, not per-episode: it is seeded from the durable journal and then
        // advanced in memory, so it is deliberately NOT cleared by the Reset paths — only the
        // owner-busy stall fields are, because those describe one specific wait.
        public GuardianRecoveryLedger RecoveryLedger { get; private set; } = GuardianRecoveryLedger.Empty;

        public bool IsRecoveryLedgerSeeded { get; private set; }

        // Seeding only ever raises the counts. A journal read that is stale or fails open must not be
        // able to erase a dispatch this process already observed and reported to the user.
        public void SeedRecoveryLedger(GuardianRecoveryLedger ledger)
        {
            ArgumentNullException.ThrowIfNull(ledger);
            IsRecoveryLedgerSeeded = true;
            var lastConfirmedAt = RecoveryLedger.LastConfirmedAt is { } mine && ledger.LastConfirmedAt is { } theirs
                ? (mine > theirs ? mine : theirs)
                : RecoveryLedger.LastConfirmedAt ?? ledger.LastConfirmedAt;
            RecoveryLedger = RecoveryLedger with
            {
                ConfirmedDispatches = Math.Max(RecoveryLedger.ConfirmedDispatches, ledger.ConfirmedDispatches),
                LastConfirmedAt = lastConfirmedAt
            };
        }

        public void RecordConfirmedDispatch(DateTimeOffset at)
        {
            RecoveryLedger = RecoveryLedger with
            {
                ConfirmedDispatches = RecoveryLedger.ConfirmedDispatches + 1,
                LastConfirmedAt = at,
                OwnerBusyRefusals = 0,
                OwnerBusySince = null
            };
            _reportedOwnerBusyRefusals = 0;
        }

        // Returns the refusal count when the stall has crossed a reporting threshold and the caller
        // should therefore break its repeated-failure suppression, otherwise null.
        public int? RecordOwnerBusyRefusal(DateTimeOffset now)
        {
            var refusals = RecoveryLedger.OwnerBusyRefusals + 1;
            RecoveryLedger = RecoveryLedger with
            {
                OwnerBusyRefusals = refusals,
                OwnerBusySince = RecoveryLedger.OwnerBusySince ?? now
            };
            if (!ShouldReportOwnerBusyStall(refusals, _reportedOwnerBusyRefusals))
            {
                return null;
            }

            _reportedOwnerBusyRefusals = refusals;
            return refusals;
        }

        public void ClearOwnerBusyStall()
        {
            _reportedOwnerBusyRefusals = 0;
            RecoveryLedger = RecoveryLedger with { OwnerBusyRefusals = 0, OwnerBusySince = null };
        }

        public string? TryTakeDueRetry(DateTimeOffset now)
        {
            if (!IsRecoveryRetryDue(NextAttemptAt, now))
            {
                return null;
            }

            NextAttemptAt = null;
            return string.IsNullOrWhiteSpace(FailureTurnId) ? null : FailureTurnId;
        }

        public void BeginFailure(string turnId, RecoveryDecision decision, TimeSpan delay)
        {
            FailureTurnId = turnId;
            LastHealthyTurnId = string.Empty;
            ConsecutiveFailures++;
            Attempts = 0;
            ActionCommitted = false;
            IsWaitingForDesktopSignal = false;
            IsBlockedUntilNewFailureTurn = false;
            IsJournalBlocked = false;
            NextAttemptAt = DateTimeOffset.Now + delay;
            // No cooldown is started any more, so the event no longer claims one: the retry is queued
            // for the next pass of the monitor loop and the row should say so.
            LastEvent = $"Detected {decision.Action}; retrying now.";
            LastFailureKind = RecoveryFailureKind.None;
            ClearOwnerBusyStall();
        }

        public void ResetHealthy(string turnId)
        {
            FailureTurnId = string.Empty;
            LastHealthyTurnId = turnId;
            ConsecutiveFailures = 0;
            Attempts = 0;
            ActionCommitted = false;
            IsWaitingForDesktopSignal = false;
            IsBlockedUntilNewFailureTurn = false;
            IsJournalBlocked = false;
            NextAttemptAt = null;
            LastEvent = "Latest turn completed normally.";
            LastFailureKind = RecoveryFailureKind.None;
            ClearOwnerBusyStall();
        }

        public void ResetArchived()
        {
            FailureTurnId = string.Empty;
            LastHealthyTurnId = string.Empty;
            ConsecutiveFailures = 0;
            Attempts = 0;
            ActionCommitted = false;
            IsWaitingForDesktopSignal = false;
            IsBlockedUntilNewFailureTurn = false;
            IsJournalBlocked = false;
            NextAttemptAt = null;
            LastEvent = "Archived task is not monitored for recovery.";
            LastFailureKind = RecoveryFailureKind.None;
            ClearOwnerBusyStall();
        }

        public bool BlockRecoverySuccessorFailure(string turnId, string message)
        {
            var changed = !string.Equals(FailureTurnId, turnId, StringComparison.OrdinalIgnoreCase) ||
                          !IsBlockedUntilNewFailureTurn ||
                          !string.Equals(LastEvent, message, StringComparison.Ordinal);
            if (!string.Equals(FailureTurnId, turnId, StringComparison.OrdinalIgnoreCase))
            {
                FailureTurnId = turnId;
                LastHealthyTurnId = string.Empty;
                ConsecutiveFailures++;
                Attempts = 0;
            }

            ActionCommitted = false;
            IsWaitingForDesktopSignal = false;
            IsBlockedUntilNewFailureTurn = true;
            IsJournalBlocked = false;
            NextAttemptAt = null;
            LastEvent = message;
            return changed;
        }

        public void SetDesktopWait(RecoveryFailureKind failureKind, bool shouldWait)
        {
            IsWaitingForDesktopSignal = shouldWait && IsDesktopEventDrivenFailure(failureKind);
        }

        public void SetFailureLock(RecoveryFailureKind failureKind)
        {
            IsBlockedUntilNewFailureTurn = ShouldLockFailureUntilNewTurn(failureKind);
        }

        public void ReleaseDesktopWait()
        {
            IsWaitingForDesktopSignal = false;
        }

        public void ApplyJournal(RecoveryOperationRecord? operation)
        {
            IsJournalBlocked = false;
            if (operation is null ||
                !string.Equals(operation.FailedTurnId, FailureTurnId, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            Attempts = Math.Max(Attempts, operation.AttemptCount);
            ActionCommitted = operation.State is RecoveryOperationState.Accepted or RecoveryOperationState.Confirmed;
            if (ActionCommitted)
            {
                IsWaitingForDesktopSignal = false;
                IsBlockedUntilNewFailureTurn = false;
                NextAttemptAt = null;
                LastEvent = $"Durable recovery confirmed: {operation.NewTurnId}";
                return;
            }

            if (operation.State == RecoveryOperationState.Abandoned)
            {
                IsWaitingForDesktopSignal = false;
                IsBlockedUntilNewFailureTurn = true;
                NextAttemptAt = null;
                LastEvent = "The durable recovery operation is closed; this failed turn will not be sent again.";
            }
        }

        public void ApplyExistingOperation(RecoveryOperationRecord? operation)
        {
            if (operation is null)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(FailureTurnId))
            {
                FailureTurnId = operation.FailedTurnId;
            }

            ApplyJournal(operation);
        }

        public void BlockForJournalFailure(string error)
        {
            IsWaitingForDesktopSignal = false;
            IsJournalBlocked = true;
            NextAttemptAt = DateTimeOffset.Now + TimeSpan.FromSeconds(30);
            LastEvent = "Recovery journal unavailable; automatic sending is blocked: " + error;
        }
    }

    private sealed class FollowUpAttemptState
    {
        public bool IsWaitingForDesktop { get; private set; }

        public bool IsBlocked { get; private set; }

        public bool ScheduledWakeQueued { get; private set; }

        public DateTimeOffset? NextAttemptAt { get; private set; }

        public string LastEvent { get; private set; } = string.Empty;

        public int Attempts { get; private set; }

        public bool SuppressScheduledDeadline =>
            ScheduledWakeQueued || IsWaitingForDesktop || IsBlocked || NextAttemptAt is not null;

        public void MarkScheduledWakeQueued()
        {
            ScheduledWakeQueued = true;
        }

        public void MarkRetryQueued()
        {
            NextAttemptAt = null;
            ScheduledWakeQueued = true;
        }

        public void MarkDispatchStarted()
        {
            ScheduledWakeQueued = false;
            IsWaitingForDesktop = false;
            NextAttemptAt = null;
            Attempts++;
        }

        public void MarkSuccess(string message)
        {
            ScheduledWakeQueued = false;
            IsWaitingForDesktop = false;
            IsBlocked = false;
            NextAttemptAt = null;
            LastEvent = message;
        }

        public void MarkFailure(
            FollowUpDispatchFailureKind failureKind,
            string message,
            DateTimeOffset now,
            TimeSpan backoff)
        {
            ScheduledWakeQueued = false;
            LastEvent = message;
            switch (failureKind)
            {
                case FollowUpDispatchFailureKind.StateChanged:
                case FollowUpDispatchFailureKind.UserActive:
                    IsWaitingForDesktop = true;
                    IsBlocked = false;
                    NextAttemptAt = null;
                    break;
                case FollowUpDispatchFailureKind.DesktopUnavailable:
                    IsWaitingForDesktop = true;
                    IsBlocked = false;
                    NextAttemptAt = null;
                    break;
                case FollowUpDispatchFailureKind.DesktopOwnerUnavailable:
                    IsWaitingForDesktop = false;
                    IsBlocked = false;
                    NextAttemptAt = now + backoff;
                    break;
                case FollowUpDispatchFailureKind.PolicyChanged:
                    IsWaitingForDesktop = false;
                    IsBlocked = false;
                    NextAttemptAt = null;
                    break;
                default:
                    IsWaitingForDesktop = false;
                    IsBlocked = true;
                    NextAttemptAt = null;
                    break;
            }
        }

        public void ReleaseForStateSignal()
        {
            ScheduledWakeQueued = false;
            if (!IsBlocked)
            {
                IsWaitingForDesktop = false;
                NextAttemptAt = null;
            }
        }
    }
}

[Flags]
internal enum ThreadRefreshKind
{
    StateChanged = 1,
    ReleaseDesktopWaiter = 2,
    ScheduledFollowUp = 4,
    RetryFollowUp = 8,
    FollowUpPolicyChanged = 16,
    RetryRecovery = 32
}

internal readonly record struct MonitorCounterSnapshot(
    long ProcessStarts,
    long Requests,
    long ThreadListRequests,
    long TargetedReadRequests,
    int FileIndexRefreshes);

internal sealed class ThreadRefreshQueue(int capacity = ThreadRefreshQueue.DefaultCapacity)
{
    internal const int DefaultCapacity = 2048;
    private readonly object _sync = new();
    private readonly int _capacity = capacity > 0
        ? capacity
        : throw new ArgumentOutOfRangeException(nameof(capacity));
    private readonly Dictionary<string, ThreadRefreshKind> _pending =
        new(StringComparer.OrdinalIgnoreCase);

    internal int Count
    {
        get
        {
            lock (_sync)
            {
                return _pending.Count;
            }
        }
    }

    internal bool TryEnqueue(string threadId, ThreadRefreshKind kind)
    {
        if (string.IsNullOrWhiteSpace(threadId))
        {
            return false;
        }

        lock (_sync)
        {
            if (_pending.TryGetValue(threadId, out var current))
            {
                _pending[threadId] = current | kind;
                return true;
            }

            if (_pending.Count >= _capacity)
            {
                return false;
            }

            _pending.Add(threadId, kind);
            return true;
        }
    }

    internal IReadOnlyDictionary<string, ThreadRefreshKind> Drain()
    {
        lock (_sync)
        {
            var drained = new Dictionary<string, ThreadRefreshKind>(_pending, StringComparer.OrdinalIgnoreCase);
            _pending.Clear();
            return drained;
        }
    }

    internal void Clear()
    {
        lock (_sync)
        {
            _pending.Clear();
        }
    }
}

internal sealed class ReconciliationCycleCoordinator
{
    private readonly object _sync = new();
    private ReconciliationCycle? _pending;

    internal Task Request(Action requestReconciliation)
    {
        ArgumentNullException.ThrowIfNull(requestReconciliation);
        lock (_sync)
        {
            _pending ??= new ReconciliationCycle();
            requestReconciliation();
            return _pending.Completion;
        }
    }

    internal ReconciliationCycle? Begin(Action beginReconciliation)
    {
        ArgumentNullException.ThrowIfNull(beginReconciliation);
        lock (_sync)
        {
            beginReconciliation();
            var cycle = _pending;
            _pending = null;
            return cycle;
        }
    }

    internal T Synchronize<T>(Func<T> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        lock (_sync)
        {
            return operation();
        }
    }

    internal void CancelPending()
    {
        ReconciliationCycle? cycle;
        lock (_sync)
        {
            cycle = _pending;
            _pending = null;
        }

        cycle?.Cancel();
    }
}

internal sealed class ReconciliationCycle
{
    private readonly TaskCompletionSource _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);

    internal Task Completion => _completion.Task;

    internal void Complete() => _completion.TrySetResult();

    internal void Fail(Exception exception) => _completion.TrySetException(exception);

    internal void Cancel(CancellationToken cancellationToken = default)
    {
        if (cancellationToken.CanBeCanceled)
        {
            _completion.TrySetCanceled(cancellationToken);
        }
        else
        {
            _completion.TrySetCanceled();
        }
    }
}

internal sealed class MonitorLifecycle
{
    private readonly object _sync = new();
    private CancellationTokenSource? _cancellation;
    private Task? _monitorTask;
    private Task? _stopTask;

    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                return _monitorTask is { IsCompleted: false } ||
                       _stopTask is { IsCompleted: false };
            }
        }
    }

    public CancellationToken CancellationToken
    {
        get
        {
            lock (_sync)
            {
                return _cancellation?.Token ?? System.Threading.CancellationToken.None;
            }
        }
    }

    public bool TryStart(
        Func<CancellationToken, Task> monitorFactory,
        Action<CancellationToken>? onStarted = null)
    {
        ArgumentNullException.ThrowIfNull(monitorFactory);
        lock (_sync)
        {
            if (_monitorTask is { IsCompleted: false } ||
                _stopTask is { IsCompleted: false })
            {
                return false;
            }

            _stopTask = null;
            var cancellation = new CancellationTokenSource();
            _cancellation = cancellation;
            try
            {
                var startGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                // Publish the running task first, commit synchronous startup state, then release
                // the worker without inheriting the WPF synchronization context.
                _monitorTask = Task.Run(async () =>
                {
                    await startGate.Task.ConfigureAwait(false);
                    await monitorFactory(cancellation.Token).ConfigureAwait(false);
                });
                try
                {
                    onStarted?.Invoke(cancellation.Token);
                    startGate.TrySetResult();
                }
                catch
                {
                    startGate.TrySetCanceled();
                    throw;
                }
                return true;
            }
            catch
            {
                cancellation.Cancel();
                _monitorTask = null;
                _cancellation = null;
                cancellation.Dispose();
                throw;
            }
        }
    }

    public Task StopAsync(
        Func<Task?, Task> stopOperation,
        Action? onStopping = null)
    {
        ArgumentNullException.ThrowIfNull(stopOperation);
        lock (_sync)
        {
            if (_stopTask is not null)
            {
                return _stopTask;
            }

            onStopping?.Invoke();
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var cancellation = _cancellation;
            var monitorTask = _monitorTask;
            _stopTask = completion.Task;
            cancellation?.Cancel();
            _ = CompleteStopAsync(stopOperation, monitorTask, cancellation, completion);
            return completion.Task;
        }
    }

    private async Task CompleteStopAsync(
        Func<Task?, Task> stopOperation,
        Task? monitorTask,
        CancellationTokenSource? cancellation,
        TaskCompletionSource completion)
    {
        Exception? failure = null;
        try
        {
            await stopOperation(monitorTask).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        lock (_sync)
        {
            if (ReferenceEquals(_monitorTask, monitorTask))
            {
                _monitorTask = null;
            }

            if (ReferenceEquals(_cancellation, cancellation))
            {
                _cancellation = null;
            }
        }

        cancellation?.Dispose();
        if (failure is null)
        {
            completion.TrySetResult();
        }
        else
        {
            completion.TrySetException(failure);
        }
    }
}

public sealed record EngineStatusEventArgs(string State, string Detail, bool IsOnline);
