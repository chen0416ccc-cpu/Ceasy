using CodexGuardian.Control;

namespace CodexGuardian.Services;

internal interface ICodexCdpRuntimeConnection : IAsyncDisposable
{
    ICdpCommandTransport Transport { get; }

    int ProcessId { get; }
}

internal interface ICodexCdpRuntimeHost : IAsyncDisposable
{
    Task<ICodexCdpRuntimeConnection> StartAsync(CancellationToken cancellationToken = default);
}

internal sealed class CodexCdpObservationService :
    IRecoveryInterferenceGuard,
    IEnhancedObservationStatus,
    ICodexDeepObservationSource,
    IAsyncDisposable
{
    private readonly ICodexCdpRuntimeHost _host;
    private readonly CodexCdpRuntimeResources _resources;
    private readonly CodexDeepObservationStateStore _state;
    private readonly CodexCdpRendererRegistry _registry;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private CodexCdpObservationSession? _session;
    private ICodexCdpRuntimeConnection? _connection;
    private int _publishedAvailability;
    private int _started;
    private int _disposed;

    internal CodexCdpObservationService(
        ICodexCdpRuntimeHost host,
        CodexCdpRuntimeResources? resources = null)
    {
        _host = host;
        _resources = resources ?? CodexCdpRuntimeResources.Load();
        _state = new CodexDeepObservationStateStore(
            CodexDeepObservationService.ProtocolVersion,
            CodexDeepObservationService.ContractId,
            CodexDeepObservationService.SnapshotMaxAge);
        _registry = new CodexCdpRendererRegistry(_state);
        _state.StateChanged += OnStateChanged;
        _state.ThreadChanged += OnThreadChanged;
    }

    public bool IsAvailable =>
        Volatile.Read(ref _disposed) == 0 &&
        _session is { Failure: null } &&
        _registry.IsFullyVerified(DateTimeOffset.UtcNow);

    public EnhancedObservationMode Mode => IsAvailable
        ? EnhancedObservationMode.CodexDeep
        : EnhancedObservationMode.Unavailable;

    public event EventHandler<EventArgs>? AvailabilityChanged;

    public event EventHandler<CodexDeepThreadChangedEventArgs>? ThreadChanged;

    internal int? OwnedProcessId => _connection?.ProcessId;

    internal async Task<bool> StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Interlocked.Exchange(ref _started, 1) != 0)
            {
                return IsAvailable;
            }

            try
            {
                _connection = await _host.StartAsync(cancellationToken).ConfigureAwait(false);
                _session = new CodexCdpObservationSession(
                    _connection.Transport,
                    _resources,
                    _registry);
                await _session.StartAsync(cancellationToken).ConfigureAwait(false);
                PublishAvailabilityIfChanged();
                return IsAvailable;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await DisposeRuntimeAsync().ConfigureAwait(false);
                PublishAvailabilityIfChanged();
                throw;
            }
            catch
            {
                await DisposeRuntimeAsync().ConfigureAwait(false);
                PublishAvailabilityIfChanged();
                return false;
            }
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task<RecoveryInterferenceSnapshot> CheckAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var session = _session;
        if (session is null || session.Failure is not null)
        {
            return _state.CheckInterference(threadId, DateTimeOffset.UtcNow);
        }

        if (!await session.ForceFreshSnapshotsAsync(cancellationToken).ConfigureAwait(false))
        {
            var stale = _state.CheckInterference(threadId, DateTimeOffset.UtcNow);
            return stale with
            {
                Status = RecoveryInterferenceStatus.Unknown,
                Detail = "Codex CDP observation could not refresh every active renderer.",
                HasFocusedDraft = false,
                ObservedAt = DateTimeOffset.UtcNow
            };
        }

        PublishAvailabilityIfChanged();
        return _state.CheckInterference(threadId, DateTimeOffset.UtcNow);
    }

    public Task WaitForChangeAsync(long observedVersion, CancellationToken cancellationToken) =>
        _state.WaitForChangeAsync(observedVersion, cancellationToken);

    public bool TryGetThreadSnapshot(string threadId, out CodexDeepThreadSnapshot? snapshot) =>
        _state.TryGetThreadSnapshot(threadId, DateTimeOffset.UtcNow, out snapshot);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            _state.StateChanged -= OnStateChanged;
            _state.ThreadChanged -= OnThreadChanged;
            await DisposeRuntimeAsync().ConfigureAwait(false);
            _state.DisconnectAll();
            _registry.ReplaceTargets([], discoveryComplete: false);
            PublishAvailabilityIfChanged();
            await _host.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _lifecycleGate.Release();
            _lifecycleGate.Dispose();
        }
    }

    private async Task DisposeRuntimeAsync()
    {
        var session = Interlocked.Exchange(ref _session, null);
        if (session is not null)
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }

        var connection = Interlocked.Exchange(ref _connection, null);
        if (connection is not null)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void OnStateChanged(object? sender, EventArgs eventArgs) => PublishAvailabilityIfChanged();

    private void OnThreadChanged(object? sender, CodexDeepThreadChangedEventArgs eventArgs) =>
        EventSubscriberDispatcher.Invoke(ThreadChanged, this, eventArgs);

    private void PublishAvailabilityIfChanged()
    {
        var next = IsAvailable ? 1 : 0;
        if (Interlocked.Exchange(ref _publishedAvailability, next) != next)
        {
            EventSubscriberDispatcher.Invoke(AvailabilityChanged, this, EventArgs.Empty);
        }
    }
}
