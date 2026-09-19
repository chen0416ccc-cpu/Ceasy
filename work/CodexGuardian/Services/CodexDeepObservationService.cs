using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using CodexGuardian.Control;

namespace CodexGuardian.Services;

public enum EnhancedObservationMode
{
    Unavailable,
    WindowsComposer,
    CodexDeep
}

internal enum CodexDeepThreadPhase
{
    Unknown,
    Idle,
    Running,
    Reasoning,
    Tool,
    Reconnecting,
    Completed,
    Failed,
    Interrupted
}

internal enum CodexDeepChangeKind
{
    ThreadState,
    Turn,
    Item,
    StreamError,
    Expired
}

internal sealed record CodexDeepThreadSnapshot(
    string ThreadId,
    string? TurnId,
    CodexDeepThreadPhase Phase,
    string? ItemType,
    string? ErrorKind,
    int? HttpStatusCode,
    bool WillRetry,
    int? ReconnectAttempt,
    int? ReconnectMaxAttempts,
    DateTimeOffset ObservedAt);

internal sealed class CodexDeepThreadChangedEventArgs(
    string threadId,
    string? turnId,
    CodexDeepThreadPhase phase,
    CodexDeepChangeKind kind) : EventArgs
{
    public string ThreadId { get; } = threadId;

    public string? TurnId { get; } = turnId;

    public CodexDeepThreadPhase Phase { get; } = phase;

    public CodexDeepChangeKind Kind { get; } = kind;
}

internal interface ICodexDeepObservationSource
{
    event EventHandler<CodexDeepThreadChangedEventArgs>? ThreadChanged;

    bool TryGetThreadSnapshot(string threadId, out CodexDeepThreadSnapshot? snapshot);
}

internal sealed class CompositeRecoveryInterferenceGuard :
    IRecoveryInterferenceGuard,
    IEnhancedObservationStatus
{
    private readonly CodexDeepObservationService _deep;
    private readonly WindowsCodexInteractionHook _windows;

    internal CompositeRecoveryInterferenceGuard(
        CodexDeepObservationService deep,
        WindowsCodexInteractionHook windows)
    {
        _deep = deep;
        _windows = windows;
        _deep.AvailabilityChanged += OnAvailabilityChanged;
        _windows.AvailabilityChanged += OnAvailabilityChanged;
    }

    public bool IsAvailable => Mode != EnhancedObservationMode.Unavailable;

    public EnhancedObservationMode Mode => _deep.IsAvailable
        ? EnhancedObservationMode.CodexDeep
        : _windows.IsAvailable
            ? EnhancedObservationMode.WindowsComposer
            : EnhancedObservationMode.Unavailable;

    public event EventHandler<EventArgs>? AvailabilityChanged;

    public async Task<RecoveryInterferenceSnapshot> CheckAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        var deep = await _deep.CheckAsync(threadId, cancellationToken).ConfigureAwait(false);
        if (deep.Status != RecoveryInterferenceStatus.Unknown)
        {
            return deep with { Version = EncodeVersion(deep.Version, deep: true) };
        }

        var windows = await _windows.CheckAsync(threadId, cancellationToken).ConfigureAwait(false);
        return windows with { Version = EncodeVersion(windows.Version, deep: false) };
    }

    public Task WaitForChangeAsync(long observedVersion, CancellationToken cancellationToken)
    {
        var deep = (observedVersion & 1) != 0;
        var childVersion = observedVersion < 0 ? 0 : observedVersion >> 1;
        return deep
            ? _deep.WaitForChangeAsync(childVersion, cancellationToken)
            : _windows.WaitForChangeAsync(childVersion, cancellationToken);
    }

    private static long EncodeVersion(long version, bool deep) =>
        checked(Math.Max(0, version) << 1) | (deep ? 1L : 0L);

    private void OnAvailabilityChanged(object? sender, EventArgs eventArgs) =>
        EventSubscriberDispatcher.Invoke(AvailabilityChanged, this, EventArgs.Empty);
}

internal sealed class CodexDeepObservationService :
    IRecoveryInterferenceGuard,
    IEnhancedObservationStatus,
    ICodexDeepObservationSource,
    IAsyncDisposable
{
    internal const int ProtocolVersion = 1;
    internal const string ContractId = CodexCdpObservationProtocol.ContractId;
    internal const string PipeHelloSource = "codex-preload-pipe";
    internal static readonly TimeSpan SnapshotMaxAge = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan WatchdogInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan ShutdownWait = TimeSpan.FromSeconds(2);
    private const int MaximumLineCharacters = 16 * 1024;
    private const int MaximumClients = 8;
    private readonly GuardianLog _log;
    private readonly CodexDeepObservationStateStore _state;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _clientsSync = new();
    private readonly HashSet<Task> _clients = [];
    private Task? _acceptLoop;
    private Task? _watchdog;
    private int _started;
    private int _disposed;
    private int _publishedAvailability;

    internal CodexDeepObservationService(GuardianLog log)
    {
        _log = log;
        _state = new CodexDeepObservationStateStore(
            ProtocolVersion,
            ContractId,
            SnapshotMaxAge);
        _state.StateChanged += OnStateChanged;
        _state.ThreadChanged += OnThreadChanged;
    }

    public bool IsAvailable =>
        Volatile.Read(ref _disposed) == 0 && _state.IsAvailable(DateTimeOffset.UtcNow);

    public EnhancedObservationMode Mode => IsAvailable
        ? EnhancedObservationMode.CodexDeep
        : EnhancedObservationMode.Unavailable;

    public event EventHandler<EventArgs>? AvailabilityChanged;

    public event EventHandler<CodexDeepThreadChangedEventArgs>? ThreadChanged;

    internal static string PipeName =>
        "CodexGuardian.DeepObservation.v1-" + SanitizePipeComponent(Environment.UserName);

    internal bool Start()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            return _acceptLoop is { IsCompleted: false };
        }

        _acceptLoop = AcceptLoopAsync(_lifetime.Token);
        _watchdog = WatchdogAsync(_lifetime.Token);
        _log.Info("Started the version-pinned Codex deep-observation endpoint in read-only mode.");
        return true;
    }

    public Task<RecoveryInterferenceSnapshot> CheckAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_state.CheckInterference(threadId, DateTimeOffset.UtcNow));
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

        _lifetime.Cancel();
        _state.StateChanged -= OnStateChanged;
        _state.ThreadChanged -= OnThreadChanged;
        _state.DisconnectAll();
        PublishAvailabilityIfChanged();

        Task[] tasks;
        lock (_clientsSync)
        {
            var pending = new List<Task>(_clients);
            if (_acceptLoop is not null)
            {
                pending.Add(_acceptLoop);
            }

            if (_watchdog is not null)
            {
                pending.Add(_watchdog);
            }

            tasks = pending.ToArray();
        }

        try
        {
            await Task.WhenAll(tasks).WaitAsync(ShutdownWait).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or TimeoutException)
        {
        }

        _lifetime.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.InOut,
                    MaximumClients,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                    4096,
                    4096);
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                var clientTask = HandleClientAsync(pipe, cancellationToken);
                pipe = null;
                lock (_clientsSync)
                {
                    _clients.Add(clientTask);
                }

                _ = clientTask.ContinueWith(
                    completed =>
                    {
                        lock (_clientsSync)
                        {
                            _clients.Remove(completed);
                        }
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                pipe?.Dispose();
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                pipe?.Dispose();
                _log.Trace(
                    "Codex deep-observation endpoint accept failed (" +
                    exception.GetType().Name + "); retrying.");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using var ownedPipe = pipe;
        var clientId = Guid.NewGuid().ToString("N");
        try
        {
            if (!TryValidateClientProcess(pipe, out var processId))
            {
                _log.Warning("Rejected an unverified deep-observation pipe client.");
                return;
            }

            using var reader = new StreamReader(
                pipe,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 1024,
                leaveOpen: true);
            using var writer = new StreamWriter(
                pipe,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                bufferSize: 1024,
                leaveOpen: true)
            {
                AutoFlush = true,
                NewLine = "\n"
            };

            var helloLine = await ReadBoundedLineAsync(reader, cancellationToken).ConfigureAwait(false);
            var reason = helloLine is null ? "missing-hello" : "invalid";
            if (helloLine is null || !_state.TryConnect(clientId, helloLine, DateTimeOffset.UtcNow, out reason))
            {
                _log.Warning(
                    "Rejected a deep-observation client with an incompatible handshake (" +
                    GuardianLog.SanitizeIdentifier(reason) + ").");
                return;
            }

            await writer.WriteLineAsync(
                    JsonSerializer.Serialize(new
                    {
                        kind = "helloAck",
                        protocol = ProtocolVersion,
                        accepted = true
                    }).AsMemory(),
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Info(
                "Connected a verified Codex deep-observation renderer (PID " + processId + ").");

            while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
            {
                var line = await ReadBoundedLineAsync(reader, cancellationToken).ConfigureAwait(false);
                if (line is null)
                {
                    break;
                }

                _state.Apply(clientId, line, DateTimeOffset.UtcNow);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (
            exception is IOException or JsonException or DecoderFallbackException or InvalidDataException)
        {
            _log.Trace(
                "Codex deep-observation client disconnected after a protocol error (" +
                exception.GetType().Name + ").");
        }
        finally
        {
            _state.Disconnect(clientId);
        }
    }

    private async Task WatchdogAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(WatchdogInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                _state.PruneStale(DateTimeOffset.UtcNow);
                PublishAvailabilityIfChanged();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private void OnStateChanged(object? sender, EventArgs eventArgs) => PublishAvailabilityIfChanged();

    private void OnThreadChanged(object? sender, CodexDeepThreadChangedEventArgs eventArgs) =>
        EventSubscriberDispatcher.Invoke(ThreadChanged, this, eventArgs);

    private void PublishAvailabilityIfChanged()
    {
        var next = IsAvailable ? 1 : 0;
        if (Interlocked.Exchange(ref _publishedAvailability, next) == next)
        {
            return;
        }

        EventSubscriberDispatcher.Invoke(AvailabilityChanged, this, EventArgs.Empty);
    }

    private static async Task<string?> ReadBoundedLineAsync(
        StreamReader reader,
        CancellationToken cancellationToken)
    {
        var builder = new StringBuilder(Math.Min(1024, MaximumLineCharacters));
        var buffer = new char[1];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return builder.Length == 0 ? null : builder.ToString();
            }

            var character = buffer[0];
            if (character == '\n')
            {
                return builder.ToString();
            }

            if (character != '\r')
            {
                builder.Append(character);
                if (builder.Length > MaximumLineCharacters)
                {
                    throw new InvalidDataException("Deep-observation message exceeded the bounded line size.");
                }
            }
        }
    }

    private static bool TryValidateClientProcess(NamedPipeServerStream pipe, out int processId)
    {
        processId = 0;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var nativeProcessId) || nativeProcessId == 0)
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(checked((int)nativeProcessId));
            var executable = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(executable))
            {
                return false;
            }

            var fileName = Path.GetFileName(executable);
            var isCodexExecutable =
                string.Equals(fileName, "ChatGPT.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileName, "Codex.exe", StringComparison.OrdinalIgnoreCase);
            var isCodexPackage = executable.Contains(
                "\\WindowsApps\\OpenAI.Codex_",
                StringComparison.OrdinalIgnoreCase);
            if (!isCodexExecutable || !isCodexPackage)
            {
                return false;
            }

            processId = checked((int)nativeProcessId);
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static string SanitizePipeComponent(string value)
    {
        var sanitized = new string(value
            .Where(static character => char.IsLetterOrDigit(character) || character is '-' or '_')
            .Take(48)
            .ToArray());
        return string.IsNullOrWhiteSpace(sanitized) ? "user" : sanitized;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        Microsoft.Win32.SafeHandles.SafePipeHandle pipe,
        out uint clientProcessId);
}

internal sealed class CodexDeepObservationStateStore
{
    private readonly int _expectedProtocol;
    private readonly string _expectedContractId;
    private readonly TimeSpan _maxAge;
    private readonly object _sync = new();
    private readonly Dictionary<string, ClientState> _clients = new(StringComparer.Ordinal);
    private readonly HashSet<string> _expectedRendererIds = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CodexDeepThreadSnapshot> _threads =
        new(StringComparer.OrdinalIgnoreCase);
    private TaskCompletionSource _changed = NewCompletion();
    private long _version;
    private bool _rendererDiscoveryComplete;

    internal CodexDeepObservationStateStore(
        int expectedProtocol,
        string expectedContractId,
        TimeSpan maxAge)
    {
        _expectedProtocol = expectedProtocol;
        _expectedContractId = string.IsNullOrWhiteSpace(expectedContractId)
            ? throw new ArgumentException("A capability contract id is required.", nameof(expectedContractId))
            : expectedContractId;
        _maxAge = maxAge;
    }

    internal event EventHandler<EventArgs>? StateChanged;

    internal event EventHandler<CodexDeepThreadChangedEventArgs>? ThreadChanged;

    internal void ReplaceExpectedRenderers(
        IEnumerable<string> rendererIds,
        bool discoveryComplete)
    {
        ArgumentNullException.ThrowIfNull(rendererIds);
        var supplied = rendererIds.ToArray();
        var validInventory = supplied.Length <= CodexCdpRendererRegistry.MaximumRenderers &&
                             supplied.All(static rendererId =>
                                 !string.IsNullOrWhiteSpace(rendererId) &&
                                 IsIdentifier(rendererId.Trim()));
        var expected = (validInventory ? supplied : [])
            .Select(static rendererId => rendererId.Trim())
            .ToHashSet(StringComparer.Ordinal);
        discoveryComplete &= validInventory;
        TaskCompletionSource? changed = null;
        lock (_sync)
        {
            if (_rendererDiscoveryComplete == discoveryComplete &&
                _expectedRendererIds.SetEquals(expected))
            {
                return;
            }

            _rendererDiscoveryComplete = discoveryComplete;
            _expectedRendererIds.Clear();
            _expectedRendererIds.UnionWith(expected);
            foreach (var unexpectedClient in _clients.Keys
                         .Where(clientId => !_expectedRendererIds.Contains(clientId))
                         .ToArray())
            {
                _clients.Remove(unexpectedClient);
            }

            changed = IncrementVersionLocked();
        }

        changed.TrySetResult();
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    internal bool ConnectVerifiedRenderer(
        string clientId,
        long initialSequence,
        DateTimeOffset observedAt,
        out string reason)
    {
        reason = "renderer-set-unverified";
        if (!IsIdentifier(clientId) || initialSequence != 1)
        {
            reason = "invalid-hello";
            return false;
        }

        TaskCompletionSource changed;
        lock (_sync)
        {
            if (!_rendererDiscoveryComplete || !_expectedRendererIds.Contains(clientId))
            {
                return false;
            }

            _clients[clientId] = new ClientState("cdp-app", observedAt)
            {
                LastSequence = initialSequence
            };
            changed = IncrementVersionLocked();
        }

        changed.TrySetResult();
        StateChanged?.Invoke(this, EventArgs.Empty);
        reason = "accepted";
        return true;
    }

    internal bool TryConnect(
        string clientId,
        string json,
        DateTimeOffset observedAt,
        out string reason)
    {
        reason = "invalid";
        try
        {
            using var document = JsonDocument.Parse(json, JsonOptions);
            var root = document.RootElement;
            if (!HasExactProperties(
                    root,
                    "kind",
                    "seq",
                    "protocol",
                    "contractId",
                    "source",
                    "windowKind") ||
                !TryGetString(root, "kind", out var kind) || kind != "hello" ||
                !TryGetInt64(root, "seq", out var sequence) || sequence != 0 ||
                !TryGetInt32(root, "protocol", out var protocol) ||
                !TryGetString(root, "contractId", out var contractId) ||
                !TryGetString(root, "source", out var source) ||
                !TryGetString(root, "windowKind", out var parsedWindowKind) ||
                !IsIdentifier(parsedWindowKind))
            {
                reason = "invalid-hello";
                return false;
            }

            if (protocol != _expectedProtocol ||
                !string.Equals(contractId, _expectedContractId, StringComparison.Ordinal) ||
                !string.Equals(source, CodexDeepObservationService.PipeHelloSource, StringComparison.Ordinal))
            {
                reason = "contract-mismatch";
                return false;
            }

            var windowKind = NormalizeIdentifier(parsedWindowKind, 32);
            TaskCompletionSource changed;
            lock (_sync)
            {
                if (!_rendererDiscoveryComplete || !_expectedRendererIds.Contains(clientId))
                {
                    reason = "renderer-set-unverified";
                    return false;
                }

                _clients[clientId] = new ClientState(windowKind, observedAt);
                changed = IncrementVersionLocked();
            }

            changed.TrySetResult();
            StateChanged?.Invoke(this, EventArgs.Empty);
            reason = "accepted";
            return true;
        }
        catch (JsonException)
        {
            reason = "invalid-json";
            return false;
        }
    }

    internal bool Apply(string clientId, string json, DateTimeOffset observedAt)
    {
        try
        {
            using var document = JsonDocument.Parse(json, JsonOptions);
            var root = document.RootElement;
            if (!TryGetString(root, "kind", out var kind) ||
                !TryGetInt64(root, "seq", out var sequence) || sequence <= 0)
            {
                return false;
            }

            CodexDeepThreadChangedEventArgs? threadEvent = null;
            TaskCompletionSource? changed = null;
            var accepted = true;
            lock (_sync)
            {
                if (!_clients.TryGetValue(clientId, out var client))
                {
                    return false;
                }

                var fullSnapshot = kind == "snapshot";
                var invalidSequence = fullSnapshot
                    ? sequence <= client.LastSequence
                    : client.LastSequence == long.MaxValue || sequence != client.LastSequence + 1;
                if (invalidSequence)
                {
                    client.Synchronized = false;
                    client.LastObservedAt = observedAt;
                    changed = IncrementVersionLocked();
                    accepted = false;
                }
                else
                {
                    client.LastSequence = sequence;
                    client.LastObservedAt = observedAt;
                    if (fullSnapshot)
                    {
                        client.Synchronized = true;
                        client.CurrentThreadId = TryReadThreadId(root, "threadId");
                        client.RouteKnown =
                            TryGetBoolean(root, "routeKnown", out var routeKnown) &&
                            routeKnown &&
                            client.CurrentThreadId is not null;
                        client.ComposerKnown =
                            TryGetBoolean(root, "composerKnown", out var composerKnown) &&
                            composerKnown &&
                            TryGetBoolean(root, "editorPresent", out var editorPresent) &&
                            editorPresent;
                        client.ComposerFocused = TryGetBoolean(root, "composerFocused", out var focused) && focused;
                        client.HasDraft = TryGetBoolean(root, "hasDraft", out var hasDraft) && hasDraft;
                        client.LastSnapshotAt = observedAt;
                    }
                    else if (!client.Synchronized)
                    {
                        return false;
                    }
                    else if (kind == "threadState")
                    {
                        threadEvent = ApplyThreadStateLocked(root, observedAt);
                    }
                    else if (kind == "turn")
                    {
                        threadEvent = ApplyTurnLocked(root, observedAt);
                    }
                    else if (kind == "item")
                    {
                        threadEvent = ApplyItemLocked(root, observedAt);
                    }
                    else if (kind == "streamError")
                    {
                        threadEvent = ApplyStreamErrorLocked(root, observedAt);
                    }
                    else if (kind != "heartbeat" && kind != "appServerConnection")
                    {
                        return false;
                    }

                    changed = IncrementVersionLocked();
                }
            }

            return CompleteApply(accepted, changed, threadEvent);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    internal RecoveryInterferenceSnapshot CheckInterference(string threadId, DateTimeOffset observedAt)
    {
        lock (_sync)
        {
            if (!HasCompleteRendererSetLocked(observedAt))
            {
                return new RecoveryInterferenceSnapshot(
                    RecoveryInterferenceStatus.Unknown,
                    "Codex deep observation has not verified every active renderer.",
                    false,
                    observedAt,
                    _version);
            }

            var fresh = _expectedRendererIds
                .Select(rendererId => _clients[rendererId])
                .ToArray();

            var target = fresh.Where(client => string.Equals(
                    client.CurrentThreadId,
                    threadId,
                    StringComparison.OrdinalIgnoreCase))
                .ToArray();
            var editing = target
                .Where(client => client.ComposerFocused || client.HasDraft)
                .ToArray();
            if (editing.Length > 0)
            {
                return new RecoveryInterferenceSnapshot(
                    RecoveryInterferenceStatus.Editing,
                    "The target Codex task has a focused composer or an unsent draft; recovery dispatch is deferred.",
                    editing.Any(client => client.HasDraft),
                    editing.Max(client => client.LastSnapshotAt),
                    _version);
            }

            if (fresh.Any(client => !client.RouteKnown))
            {
                return new RecoveryInterferenceSnapshot(
                    RecoveryInterferenceStatus.Unknown,
                    "At least one verified Codex renderer has no authoritative task route.",
                    false,
                    fresh.Min(client => client.LastSnapshotAt),
                    _version);
            }

            if (target.Length > 0 && target.All(client => client.ComposerKnown))
            {
                return new RecoveryInterferenceSnapshot(
                    RecoveryInterferenceStatus.Clear,
                    "The target Codex task is visible but its composer is not being edited.",
                    false,
                    target.Min(client => client.LastSnapshotAt),
                    _version);
            }

            return new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Unknown,
                "Codex deep observation is connected, but no task route is currently authoritative.",
                false,
                observedAt,
                _version);
        }
    }

    internal bool TryGetThreadSnapshot(
        string threadId,
        DateTimeOffset observedAt,
        out CodexDeepThreadSnapshot? snapshot)
    {
        lock (_sync)
        {
            if (HasCompleteRendererSetLocked(observedAt) &&
                _threads.TryGetValue(threadId, out var value) &&
                observedAt - value.ObservedAt <= _maxAge)
            {
                snapshot = value;
                return true;
            }
        }

        snapshot = null;
        return false;
    }

    internal bool IsAvailable(DateTimeOffset observedAt)
    {
        lock (_sync)
        {
            return HasCompleteRendererSetLocked(observedAt);
        }
    }

    internal Task WaitForChangeAsync(long observedVersion, CancellationToken cancellationToken)
    {
        Task task;
        lock (_sync)
        {
            if (_version != observedVersion)
            {
                return Task.CompletedTask;
            }

            task = _changed.Task;
        }

        return task.WaitAsync(cancellationToken);
    }

    internal void Disconnect(string clientId)
    {
        TaskCompletionSource? changed = null;
        lock (_sync)
        {
            if (_clients.Remove(clientId))
            {
                changed = IncrementVersionLocked();
            }
        }

        if (changed is not null)
        {
            changed.TrySetResult();
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    internal void DisconnectAll()
    {
        TaskCompletionSource? changed = null;
        lock (_sync)
        {
            if (_clients.Count > 0)
            {
                _clients.Clear();
                changed = IncrementVersionLocked();
            }
        }

        if (changed is not null)
        {
            changed.TrySetResult();
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    internal void PruneStale(DateTimeOffset observedAt)
    {
        TaskCompletionSource? changed = null;
        CodexDeepThreadChangedEventArgs[] expiredEvents = [];
        lock (_sync)
        {
            var stale = _clients
                .Where(pair => !IsFresh(pair.Value, observedAt))
                .Select(pair => pair.Key)
                .ToArray();
            foreach (var clientId in stale)
            {
                _clients.Remove(clientId);
            }

            var staleThreads = _threads
                .Where(pair => observedAt - pair.Value.ObservedAt > _maxAge)
                .Select(pair => pair.Key)
                .ToArray();
            foreach (var threadId in staleThreads)
            {
                _threads.Remove(threadId);
            }

            expiredEvents = staleThreads
                .Select(threadId => new CodexDeepThreadChangedEventArgs(
                    threadId,
                    null,
                    CodexDeepThreadPhase.Unknown,
                    CodexDeepChangeKind.Expired))
                .ToArray();

            if (stale.Length > 0 || staleThreads.Length > 0)
            {
                changed = IncrementVersionLocked();
            }
        }

        if (changed is not null)
        {
            changed.TrySetResult();
            StateChanged?.Invoke(this, EventArgs.Empty);
        }


        foreach (var expiredEvent in expiredEvents)
        {
            ThreadChanged?.Invoke(this, expiredEvent);
        }
    }

    private CodexDeepThreadChangedEventArgs? ApplyThreadStateLocked(JsonElement root, DateTimeOffset observedAt)
    {
        var threadId = TryReadThreadId(root, "threadId");
        if (threadId is null || !TryGetString(root, "status", out var status))
        {
            return null;
        }

        var phase = status switch
        {
            "active" => CodexDeepThreadPhase.Running,
            "idle" => CodexDeepThreadPhase.Idle,
            "systemError" => CodexDeepThreadPhase.Failed,
            _ => CodexDeepThreadPhase.Unknown
        };
        var previous = _threads.GetValueOrDefault(threadId);
        _threads[threadId] = new CodexDeepThreadSnapshot(
            threadId,
            previous?.TurnId,
            phase,
            previous?.ItemType,
            previous?.ErrorKind,
            previous?.HttpStatusCode,
            previous?.WillRetry ?? false,
            previous?.ReconnectAttempt,
            previous?.ReconnectMaxAttempts,
            observedAt);
        return new CodexDeepThreadChangedEventArgs(
            threadId,
            previous?.TurnId,
            phase,
            CodexDeepChangeKind.ThreadState);
    }

    private CodexDeepThreadChangedEventArgs? ApplyTurnLocked(JsonElement root, DateTimeOffset observedAt)
    {
        var threadId = TryReadThreadId(root, "threadId");
        var turnId = TryReadTurnId(root, "turnId");
        if (threadId is null || turnId is null || !TryGetString(root, "phase", out var phaseValue))
        {
            return null;
        }

        var status = TryGetString(root, "status", out var parsedStatus) ? parsedStatus : "unknown";
        var phase = phaseValue == "started"
            ? CodexDeepThreadPhase.Running
            : status switch
            {
                "completed" => CodexDeepThreadPhase.Completed,
                "failed" => CodexDeepThreadPhase.Failed,
                "interrupted" => CodexDeepThreadPhase.Interrupted,
                "inProgress" => CodexDeepThreadPhase.Running,
                _ => CodexDeepThreadPhase.Unknown
            };
        _threads[threadId] = new CodexDeepThreadSnapshot(
            threadId,
            turnId,
            phase,
            null,
            TryGetString(root, "errorKind", out var errorKind) ? NormalizeIdentifier(errorKind, 64) : null,
            TryGetNullableInt32(root, "httpStatusCode"),
            TryGetBoolean(root, "willRetry", out var willRetry) && willRetry,
            null,
            null,
            observedAt);
        return new CodexDeepThreadChangedEventArgs(
            threadId,
            turnId,
            phase,
            CodexDeepChangeKind.Turn);
    }

    private CodexDeepThreadChangedEventArgs? ApplyItemLocked(JsonElement root, DateTimeOffset observedAt)
    {
        var threadId = TryReadThreadId(root, "threadId");
        var turnId = TryReadTurnId(root, "turnId");
        if (threadId is null || turnId is null ||
            !TryGetString(root, "phase", out var phaseValue) ||
            !TryGetString(root, "itemType", out var itemTypeValue))
        {
            return null;
        }

        var itemType = NormalizeIdentifier(itemTypeValue, 64);
        var phase = phaseValue == "started"
            ? itemType == "reasoning"
                ? CodexDeepThreadPhase.Reasoning
                : IsToolItem(itemType)
                    ? CodexDeepThreadPhase.Tool
                    : CodexDeepThreadPhase.Running
            : CodexDeepThreadPhase.Running;
        var previous = _threads.GetValueOrDefault(threadId);
        _threads[threadId] = new CodexDeepThreadSnapshot(
            threadId,
            turnId,
            phase,
            itemType,
            previous?.ErrorKind,
            previous?.HttpStatusCode,
            previous?.WillRetry ?? false,
            previous?.ReconnectAttempt,
            previous?.ReconnectMaxAttempts,
            observedAt);
        return new CodexDeepThreadChangedEventArgs(
            threadId,
            turnId,
            phase,
            CodexDeepChangeKind.Item);
    }

    private CodexDeepThreadChangedEventArgs? ApplyStreamErrorLocked(JsonElement root, DateTimeOffset observedAt)
    {
        var threadId = TryReadThreadId(root, "threadId");
        var turnId = TryReadTurnId(root, "turnId");
        if (threadId is null || turnId is null)
        {
            return null;
        }

        var willRetry = TryGetBoolean(root, "willRetry", out var parsedWillRetry) && parsedWillRetry;
        var phase = willRetry ? CodexDeepThreadPhase.Reconnecting : CodexDeepThreadPhase.Failed;
        _threads[threadId] = new CodexDeepThreadSnapshot(
            threadId,
            turnId,
            phase,
            null,
            TryGetString(root, "errorKind", out var errorKind) ? NormalizeIdentifier(errorKind, 64) : null,
            TryGetNullableInt32(root, "httpStatusCode"),
            willRetry,
            TryGetNullableInt32(root, "reconnectAttempt"),
            TryGetNullableInt32(root, "reconnectMaxAttempts"),
            observedAt);
        return new CodexDeepThreadChangedEventArgs(
            threadId,
            turnId,
            phase,
            CodexDeepChangeKind.StreamError);
    }

    private bool CompleteApply(
        bool accepted,
        TaskCompletionSource? changed,
        CodexDeepThreadChangedEventArgs? threadEvent)
    {
        changed?.TrySetResult();
        if (changed is not null)
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }

        if (threadEvent is not null)
        {
            ThreadChanged?.Invoke(this, threadEvent);
        }

        return accepted;
    }

    private TaskCompletionSource IncrementVersionLocked()
    {
        _version = checked(_version + 1);
        var previous = _changed;
        _changed = NewCompletion();
        return previous;
    }

    private bool IsFresh(ClientState client, DateTimeOffset observedAt) =>
        IsFreshTimestamp(client.LastObservedAt, observedAt) &&
        IsFreshTimestamp(client.LastSnapshotAt, observedAt);

    private bool HasCompleteRendererSetLocked(DateTimeOffset observedAt) =>
        _rendererDiscoveryComplete &&
        _expectedRendererIds.Count > 0 &&
        _expectedRendererIds.All(rendererId =>
            _clients.TryGetValue(rendererId, out var client) &&
            client.Synchronized &&
            IsFresh(client, observedAt));

    private bool IsFreshTimestamp(DateTimeOffset value, DateTimeOffset observedAt) =>
        value != DateTimeOffset.MinValue &&
        value <= observedAt + TimeSpan.FromSeconds(1) &&
        observedAt - value <= _maxAge;

    private static bool IsToolItem(string itemType) => itemType is
        "commandExecution" or "fileChange" or "mcpToolCall" or "dynamicToolCall" or
        "webSearch" or "imageGeneration" or "collabAgentToolCall";

    private static string? TryReadThreadId(JsonElement root, string propertyName) =>
        TryGetString(root, propertyName, out var value) && IsIdentifier(value) ? value : null;

    private static string? TryReadTurnId(JsonElement root, string propertyName) =>
        TryGetString(root, propertyName, out var value) && IsIdentifier(value) ? value : null;

    private static bool IsIdentifier(string value) =>
        value.Length is >= 8 and <= 80 &&
        value.All(static character => char.IsLetterOrDigit(character) || character is '-' or '_');

    private static bool HasExactProperties(JsonElement root, params string[] expected)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var allowed = expected.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!allowed.Contains(property.Name) || !seen.Add(property.Name))
            {
                return false;
            }
        }

        return seen.SetEquals(allowed);
    }

    private static string NormalizeIdentifier(string value, int maximumLength) =>
        new(value
            .Where(static character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.')
            .Take(maximumLength)
            .ToArray());

    private static bool TryGetString(JsonElement root, string propertyName, out string value)
    {
        value = string.Empty;
        return root.ValueKind == JsonValueKind.Object &&
               root.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.String &&
               (value = property.GetString() ?? string.Empty).Length > 0;
    }

    private static bool TryGetBoolean(JsonElement root, string propertyName, out bool value)
    {
        value = false;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty(propertyName, out var property) ||
            property.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            return false;
        }

        value = property.GetBoolean();
        return true;
    }

    private static bool TryGetInt32(JsonElement root, string propertyName, out int value)
    {
        value = 0;
        return root.ValueKind == JsonValueKind.Object &&
               root.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.Number &&
               property.TryGetInt32(out value);
    }

    private static bool TryGetInt64(JsonElement root, string propertyName, out long value)
    {
        value = 0;
        return root.ValueKind == JsonValueKind.Object &&
               root.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.Number &&
               property.TryGetInt64(out value);
    }

    private static int? TryGetNullableInt32(JsonElement root, string propertyName) =>
        TryGetInt32(root, propertyName, out var value) ? value : null;

    private static TaskCompletionSource NewCompletion() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 12
    };

    private sealed class ClientState(string windowKind, DateTimeOffset observedAt)
    {
        internal string WindowKind { get; } = windowKind;

        internal long LastSequence { get; set; }

        internal DateTimeOffset LastObservedAt { get; set; } = observedAt;

        internal DateTimeOffset LastSnapshotAt { get; set; } = DateTimeOffset.MinValue;

        internal bool Synchronized { get; set; }

        internal bool RouteKnown { get; set; }

        internal bool ComposerKnown { get; set; }

        internal string? CurrentThreadId { get; set; }

        internal bool ComposerFocused { get; set; }

        internal bool HasDraft { get; set; }
    }
}
