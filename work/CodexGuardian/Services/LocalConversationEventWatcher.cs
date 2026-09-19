using System.IO;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace CodexGuardian.Services;

public sealed class LocalConversationEventWatcher : IAsyncDisposable
{
    private const string TaskCompleteMarker = "\"type\":\"task_complete\"";
    private const string TurnAbortedMarker = "\"type\":\"turn_aborted\"";

    // Codex writes task_started into the rollout the moment a turn begins running, in the same
    // event_msg envelope and with the same turn_id as the two terminal markers. It is the earliest
    // local evidence that a task is working, it arrives without asking the app-server anything, and
    // it costs nothing extra here because the watcher already streams every appended line.
    private const string TaskStartedMarker = "\"type\":\"task_started\"";
    private const string TaskStartedType = "task_started";
    private const int ChangeQueueCapacity = 1024;
    internal const int MaximumAppendBytes = 256 * 1024;
    private static readonly TimeSpan NewFileTimestampTolerance = TimeSpan.FromSeconds(5);
    private readonly GuardianLog _log;
    private readonly string _sessionsRoot;
    private readonly ConcurrentDictionary<string, FileCursor> _cursors = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lifecycleSync = new();
    private FileSystemWatcher? _watcher;
    private Channel<string>? _changes;
    private CancellationTokenSource? _cancellation;
    private Task? _worker;
    private DateTimeOffset _startedAt;
    private int _dataLossReported;

    public LocalConversationEventWatcher(GuardianLog log, string? sessionsRoot = null)
    {
        _log = log;
        _sessionsRoot = sessionsRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "sessions");
    }

    public bool IsRunning => _worker is { IsCompleted: false };

    public event EventHandler<LocalConversationTerminalDetectedEventArgs>? TerminalDetected;

    public event EventHandler<LocalConversationRunningDetectedEventArgs>? RunningDetected;

    public event EventHandler<LocalConversationThreadTouchedEventArgs>? ThreadTouched;

    public event EventHandler<LocalConversationWatcherFaultedEventArgs>? Faulted;

    public void Start()
    {
        lock (_lifecycleSync)
        {
            if (IsRunning || !Directory.Exists(_sessionsRoot))
            {
                return;
            }

            _cursors.Clear();
            _startedAt = DateTimeOffset.UtcNow;
            Interlocked.Exchange(ref _dataLossReported, 0);
            _changes = Channel.CreateBounded<string>(new BoundedChannelOptions(ChangeQueueCapacity)
            {
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false,
                FullMode = BoundedChannelFullMode.Wait
            });
            _cancellation = new CancellationTokenSource();
            _worker = ProcessChangesAsync(_changes.Reader, _cancellation.Token);

            _watcher = new FileSystemWatcher(_sessionsRoot, "*.jsonl")
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
                EnableRaisingEvents = false
            };
            _watcher.Changed += OnFileChanged;
            _watcher.Created += OnFileChanged;
            _watcher.Renamed += OnFileRenamed;
            _watcher.Error += OnWatcherError;
            _watcher.EnableRaisingEvents = true;
        }
    }

    public async Task StopAsync()
    {
        FileSystemWatcher? watcher;
        Channel<string>? changes;
        CancellationTokenSource? cancellation;
        Task? worker;
        lock (_lifecycleSync)
        {
            watcher = _watcher;
            _watcher = null;
            changes = _changes;
            _changes = null;
            cancellation = _cancellation;
            _cancellation = null;
            worker = _worker;
            _worker = null;
        }

        if (watcher is not null)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Changed -= OnFileChanged;
            watcher.Created -= OnFileChanged;
            watcher.Renamed -= OnFileRenamed;
            watcher.Error -= OnWatcherError;
            watcher.Dispose();
        }

        changes?.Writer.TryComplete();
        cancellation?.Cancel();
        if (worker is not null)
        {
            try
            {
                await worker.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        cancellation?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
    }

    private void OnFileChanged(object sender, FileSystemEventArgs eventArgs)
    {
        if (eventArgs.ChangeType == WatcherChangeTypes.Created)
        {
            SeedNewFileCursor(eventArgs.FullPath);
            PublishThreadTouched(eventArgs.FullPath);
        }

        QueueChange(eventArgs.FullPath);
    }

    private void OnFileRenamed(object sender, RenamedEventArgs eventArgs)
    {
        _cursors.TryRemove(eventArgs.OldFullPath, out _);
        SeedNewFileCursor(eventArgs.FullPath);
        PublishThreadTouched(eventArgs.FullPath);
        QueueChange(eventArgs.FullPath);
    }

    private void SeedNewFileCursor(string path)
    {
        _cursors.TryAdd(
            path,
            new FileCursor(
                position: 0,
                minimumEventTimestamp: DateTimeOffset.UtcNow - NewFileTimestampTolerance,
                isSubAgent: null));
    }

    private bool PublishThreadTouched(string path)
    {
        if (TryGetThreadId(path, out var threadId))
        {
            EventSubscriberDispatcher.Invoke(
                ThreadTouched,
                this,
                new LocalConversationThreadTouchedEventArgs(threadId, path),
                exception => _log.Trace(
                    "A local watcher subscriber failed (" + exception.GetType().Name + ")."));
            return true;
        }

        return false;
    }

    private void OnWatcherError(object sender, ErrorEventArgs eventArgs)
    {
        _log.Warning("Real-time local conversation watcher reported an error; a one-time state resync was queued: " +
                     eventArgs.GetException().Message);
        EventSubscriberDispatcher.Invoke(
            Faulted,
            this,
            new LocalConversationWatcherFaultedEventArgs(eventArgs.GetException()),
            exception => _log.Trace(
                "A local watcher fault subscriber failed (" + exception.GetType().Name + ")."));
    }

    private void QueueChange(string path)
    {
        var changes = _changes;
        if (changes is not null && !changes.Writer.TryWrite(path))
        {
            ReportDataLossOnce("The local conversation event queue reached its bounded capacity.");
        }
    }

    private void ReportDataLossOnce(string detail)
    {
        if (Interlocked.Exchange(ref _dataLossReported, 1) != 0)
        {
            return;
        }

        var exception = new InternalBufferOverflowException(detail);
        _log.Warning(detail + " A one-time state reconciliation was queued.");
        EventSubscriberDispatcher.Invoke(
            Faulted,
            this,
            new LocalConversationWatcherFaultedEventArgs(exception),
            subscriberException => _log.Trace(
                "A local watcher fault subscriber failed (" + subscriberException.GetType().Name + ")."));
    }

    private async Task ProcessChangesAsync(ChannelReader<string> reader, CancellationToken cancellationToken)
    {
        var pending = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            while (reader.TryRead(out var path))
            {
                pending.Add(path);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken).ConfigureAwait(false);
            while (reader.TryRead(out var path))
            {
                pending.Add(path);
            }

            foreach (var path in pending)
            {
                await ProcessFileAppendAsync(path, cancellationToken).ConfigureAwait(false);
            }

            pending.Clear();
            Interlocked.Exchange(ref _dataLossReported, 0);
        }
    }

    private async Task ProcessFileAppendAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            _cursors.TryRemove(path, out _);
            return;
        }

        _cursors.TryGetValue(path, out var cursor);

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (cursor is null)
            {
                cursor = new FileCursor(
                    position: Math.Max(0, stream.Length - MaximumAppendBytes),
                    minimumEventTimestamp: _startedAt - NewFileTimestampTolerance,
                    isSubAgent: null);
            }

            if (stream.Length < cursor.Position)
            {
                _cursors[path] = new FileCursor(stream.Length, DateTimeOffset.UtcNow, isSubAgent: null);
                return;
            }

            if (stream.Length - cursor.Position > MaximumAppendBytes)
            {
                cursor.Position = Math.Max(0, stream.Length - MaximumAppendBytes);
                cursor.Carry = string.Empty;
                if (!PublishThreadTouched(path))
                {
                    ReportDataLossOnce(
                        "A local conversation append exceeded the bounded tail window and its task id could not be determined.");
                }
            }

            stream.Seek(cursor.Position, SeekOrigin.Begin);
            using var reader = new StreamReader(
                stream,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 16 * 1024,
                leaveOpen: true);
            var appended = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            cursor.Position = stream.Position;
            if (appended.Length == 0)
            {
                _cursors[path] = cursor;
                return;
            }

            var completeText = cursor.Carry + appended;
            var lines = completeText.Split('\n');
            cursor.Carry = completeText.EndsWith('\n') ? string.Empty : lines[^1];
            var completeLineCount = completeText.EndsWith('\n') ? lines.Length : lines.Length - 1;
            for (var index = 0; index < completeLineCount; index++)
            {
                var line = lines[index].TrimEnd('\r');
                if (cursor.IsSubAgent is null && TryParseSubAgentSource(line, out var isSubAgent))
                {
                    cursor.IsSubAgent = isSubAgent;
                }

                if ((line.Contains(TaskCompleteMarker, StringComparison.Ordinal) ||
                     line.Contains(TurnAbortedMarker, StringComparison.Ordinal) ||
                     line.Contains(TaskStartedMarker, StringComparison.Ordinal)) &&
                    TryReadThreadEvent(line, path, out var threadEvent) &&
                    cursor.ShouldEmit(threadEvent.RecordedAt))
                {
                    if (string.Equals(threadEvent.PayloadType, TaskStartedType, StringComparison.Ordinal))
                    {
                        EventSubscriberDispatcher.Invoke(
                            RunningDetected,
                            this,
                            new LocalConversationRunningDetectedEventArgs(
                                threadEvent.ThreadId,
                                threadEvent.TurnId,
                                path,
                                threadEvent.RecordedAt,
                                cursor.IsSubAgent),
                            exception => _log.Trace(
                                "A local running subscriber failed (" + exception.GetType().Name + ")."));
                    }
                    else
                    {
                        EventSubscriberDispatcher.Invoke(
                            TerminalDetected,
                            this,
                            new LocalConversationTerminalDetectedEventArgs(
                                threadEvent.ThreadId,
                                threadEvent.TurnId,
                                threadEvent.HasError,
                                path,
                                threadEvent.RecordedAt,
                                cursor.IsSubAgent),
                            exception => _log.Trace(
                                "A local terminal subscriber failed (" + exception.GetType().Name + ")."));
                    }
                }
            }

            _cursors[path] = cursor;
        }
        catch (IOException exception)
        {
            _log.Trace("Unable to read a local conversation append event: " + exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            _log.Trace("Unable to read a local conversation append event: " + exception.Message);
        }
    }

    // One parse for all three tracked markers. The running and terminal events share an envelope,
    // a turn_id and a timestamp, so splitting them into two parsers would only mean deserializing
    // the same line twice and letting the two copies drift apart.
    private static bool TryReadThreadEvent(
        string line,
        string sourceFile,
        out ThreadEventEnvelope threadEvent)
    {
        threadEvent = default;
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (!root.TryGetProperty("type", out var envelopeType) ||
                !string.Equals(envelopeType.GetString(), "event_msg", StringComparison.Ordinal) ||
                !root.TryGetProperty("payload", out var payload) ||
                payload.ValueKind != JsonValueKind.Object ||
                !payload.TryGetProperty("type", out var eventType) ||
                eventType.GetString() is not { Length: > 0 } payloadType ||
                !IsTrackedEventType(payloadType) ||
                !payload.TryGetProperty("turn_id", out var turnIdElement) ||
                turnIdElement.GetString() is not { Length: > 0 } turnId)
            {
                return false;
            }

            if (!TryGetThreadId(sourceFile, out var threadId))
            {
                return false;
            }

            threadEvent = new ThreadEventEnvelope(
                payloadType,
                threadId,
                turnId,
                payload.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object,
                ReadTimestamp(root));
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsTrackedEventType(string? eventType) =>
        string.Equals(eventType, "task_complete", StringComparison.Ordinal) ||
        string.Equals(eventType, "turn_aborted", StringComparison.Ordinal) ||
        string.Equals(eventType, TaskStartedType, StringComparison.Ordinal);

    internal static bool TryGetThreadId(string path, out string threadId)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);
        const int guidLength = 36;
        for (var offset = 0; offset <= fileName.Length - guidLength; offset++)
        {
            var candidate = fileName.Substring(offset, guidLength);
            if (!Guid.TryParseExact(candidate, "D", out _))
            {
                continue;
            }

            // Rollout names are `rollout-<timestamp>-<threadId>.jsonl` and, for an
            // in-place retry, `rollout-<timestamp>-<threadId>_<sessionId>.jsonl`.
            // The first UUID is the stable Codex thread id; the optional trailing
            // UUID identifies only that rollout file and must never drive a task
            // refresh or recovery lookup.
            threadId = candidate;
            return true;
        }

        threadId = string.Empty;
        return false;
    }

    internal static bool TryParseSubAgentSource(string line, out bool isSubAgent)
    {
        isSubAgent = false;
        if (!line.Contains("\"type\":\"session_meta\"", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (!root.TryGetProperty("type", out var type) ||
                !string.Equals(type.GetString(), "session_meta", StringComparison.Ordinal) ||
                !root.TryGetProperty("payload", out var payload) ||
                payload.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (payload.TryGetProperty("thread_source", out var threadSource) &&
                threadSource.ValueKind == JsonValueKind.String)
            {
                isSubAgent = string.Equals(
                    threadSource.GetString(),
                    "subagent",
                    StringComparison.OrdinalIgnoreCase);
                return true;
            }

            isSubAgent = payload.TryGetProperty("source", out var source) &&
                         source.ValueKind == JsonValueKind.Object &&
                         source.TryGetProperty("subAgent", out _);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static DateTimeOffset? ReadTimestamp(JsonElement root)
    {
        return root.TryGetProperty("timestamp", out var timestamp) &&
               timestamp.ValueKind == JsonValueKind.String &&
               DateTimeOffset.TryParse(timestamp.GetString(), out var parsed)
            ? parsed
            : null;
    }

    private readonly record struct ThreadEventEnvelope(
        string PayloadType,
        string ThreadId,
        string TurnId,
        bool HasError,
        DateTimeOffset? RecordedAt);

    private sealed class FileCursor(
        long position,
        DateTimeOffset? minimumEventTimestamp,
        bool? isSubAgent)
    {
        public long Position { get; set; } = position;

        public string Carry { get; set; } = string.Empty;

        // Guards running and terminal events alike: without it, the first append after startup would
        // replay every historical task_started in the tail window and paint finished tasks as running.
        public DateTimeOffset? MinimumEventTimestamp { get; } = minimumEventTimestamp;

        public bool? IsSubAgent { get; set; } = isSubAgent;

        public bool ShouldEmit(DateTimeOffset? recordedAt) =>
            MinimumEventTimestamp is null ||
            recordedAt is not null && recordedAt >= MinimumEventTimestamp;
    }
}

public sealed class LocalConversationRunningDetectedEventArgs(
    string threadId,
    string turnId,
    string sourceFile,
    DateTimeOffset? recordedAt = null,
    bool? isSubAgent = null) : EventArgs
{
    public string ThreadId { get; } = threadId;

    public string TurnId { get; } = turnId;

    public string SourceFile { get; } = sourceFile;

    public DateTimeOffset? RecordedAt { get; } = recordedAt;

    public bool? IsSubAgent { get; } = isSubAgent;
}

public sealed class LocalConversationWatcherFaultedEventArgs(Exception exception) : EventArgs
{
    public Exception Exception { get; } = exception;
}

public sealed class LocalConversationThreadTouchedEventArgs(string threadId, string sourceFile) : EventArgs
{
    public string ThreadId { get; } = threadId;

    public string SourceFile { get; } = sourceFile;
}

public sealed class LocalConversationTerminalDetectedEventArgs(
    string threadId,
    string turnId,
    bool hasError,
    string sourceFile,
    DateTimeOffset? recordedAt = null,
    bool? isSubAgent = null) : EventArgs
{
    public string ThreadId { get; } = threadId;

    public string TurnId { get; } = turnId;

    public bool HasError { get; } = hasError;

    public string SourceFile { get; } = sourceFile;

    public DateTimeOffset? RecordedAt { get; } = recordedAt;

    public bool? IsSubAgent { get; } = isSubAgent;
}
