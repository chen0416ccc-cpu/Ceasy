using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodexGuardian.Models;
using Microsoft.Win32.SafeHandles;

namespace CodexGuardian.Services;

public sealed class AppServerClient : IAsyncDisposable
{
    internal const int LatestTurnPageSize = 1;
    internal const string SummaryItemsView = "summary";
    // Recovery eligibility can request the canonical user-message and item evidence only for an
    // exact failed candidate. Ordinary monitoring and recent-turn reconciliation stay summary-only.
    internal const string FullItemsView = "full";
    // Reuse the helper across recovery backoff scans instead of spawning one process per check.
    internal static readonly TimeSpan ReadSessionIdleDelay = TimeSpan.FromSeconds(5);

    private static readonly string[] InteractiveThreadSourceKinds =
    [
        "cli",
        "vscode",
        "exec",
        "appServer",
        "unknown"
    ];

    private static readonly string[] AllThreadSourceKinds =
    [
        .. InteractiveThreadSourceKinds,
        "subAgent",
        "subAgentReview",
        "subAgentCompact",
        "subAgentThreadSpawn",
        "subAgentOther"
    ];

    private readonly CodexCliLocator _locator;
    private readonly GuardianLog _log;
    private readonly SemaphoreSlim _sessionGate = new(1, 1);
    private readonly SemaphoreSlim _connectGate = new(1, 1);
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly IdleDisconnectScheduler _idleDisconnect;
    private ConcurrentDictionary<long, TaskCompletionSource<JsonElement>>? _pending;
    private CancellationTokenSource? _connectionCancellation;
    private ClientWebSocket? _socket;
    private Process? _process;
    private SafeJobHandle? _processJob;
    private Task? _receiveTask;
    private Task[] _drainTasks = [];
    private long _nextRequestId;
    private long _processStartCount;
    private long _requestCount;
    private long _threadListRequestCount;
    private long _targetedReadRequestCount;
    private int _lastStartedProcessId;
    private int _connectionSuccessLogged;
    private int _publishedConnectionState;
    private int _monitoringLeaseCount;
    private int _disposed;

    public AppServerClient(CodexCliLocator locator, GuardianLog log)
    {
        _locator = locator;
        _log = log;
        _idleDisconnect = new IdleDisconnectScheduler(
            ReadSessionIdleDelay,
            DisconnectAfterReadIdleAsync);
    }

    public bool IsConnected => _socket?.State == WebSocketState.Open;

    public string ServerVersion { get; private set; } = "Not connected";

    internal long ProcessStartCount => Interlocked.Read(ref _processStartCount);

    internal long RequestCount => Interlocked.Read(ref _requestCount);

    internal long ThreadListRequestCount => Interlocked.Read(ref _threadListRequestCount);

    internal long TargetedReadRequestCount => Interlocked.Read(ref _targetedReadRequestCount);

    internal int LastStartedProcessId => Volatile.Read(ref _lastStartedProcessId);

    internal Task WaitForIdleDisconnectAsync() => _idleDisconnect.PendingTask;

    internal int MonitoringLeaseCount => Volatile.Read(ref _monitoringLeaseCount);

    internal IAsyncDisposable AcquireMonitoringLease()
    {
        ThrowIfDisposed();
        Interlocked.Increment(ref _monitoringLeaseCount);
        _ = _idleDisconnect.CancelPending();
        return new MonitoringLease(this);
    }

    internal AppServerProcessSnapshot CaptureProcessSnapshot() => CaptureProcessSnapshot(_process);

    internal static AppServerProcessSnapshot CaptureProcessSnapshot(Process? process)
    {
        if (process is null)
        {
            return AppServerProcessSnapshot.Stopped;
        }

        try
        {
            process.Refresh();
            if (process.HasExited)
            {
                return new AppServerProcessSnapshot(process.Id, false, false, TimeSpan.Zero, 0, 0);
            }

            var io = default(IO_COUNTERS);
            var hasIoCounters = GetProcessIoCounters(process.SafeHandle, out io);
            return new AppServerProcessSnapshot(
                process.Id,
                true,
                hasIoCounters,
                process.TotalProcessorTime,
                io.ReadTransferCount,
                io.WriteTransferCount);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ObjectDisposedException or Win32Exception)
        {
            return AppServerProcessSnapshot.Stopped;
        }
    }

    public event EventHandler<bool>? ConnectionChanged;

    public event EventHandler<AppServerNotificationEventArgs>? NotificationReceived;

    public async ValueTask<IAsyncDisposable> OpenReadSessionAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            _ = _idleDisconnect.CancelPending();
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            return new ReadSessionLease(this);
        }
        catch
        {
            _sessionGate.Release();
            throw;
        }
    }

    public async Task EnsureConnectedAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (IsConnected)
        {
            return;
        }

        await _connectGate.WaitAsync(cancellationToken);
        try
        {
            ThrowIfDisposed();
            if (IsConnected)
            {
                return;
            }

            await ResetConnectionAsync();
            var executable = _locator.Find()
                ?? throw new FileNotFoundException("A runnable local codex.exe was not found under LocalAppData.");
            var port = ReserveLoopbackPort();

            var startInfo = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            };
            startInfo.ArgumentList.Add("app-server");
            startInfo.ArgumentList.Add("--listen");
            startInfo.ArgumentList.Add($"ws://127.0.0.1:{port}");

            var processJob = CreateKillOnCloseJob();
            Process? process = null;
            try
            {
                process = Process.Start(startInfo)
                    ?? throw new InvalidOperationException("Unable to launch the Codex app-server process.");
                Volatile.Write(ref _lastStartedProcessId, process.Id);
                Interlocked.Increment(ref _processStartCount);
                AssignProcessToKillOnCloseJob(processJob, process);
            }
            catch
            {
                await TerminateProcessTreeAsync(process, processJob);
                throw;
            }

            _process = process;
            _processJob = processJob;
            _connectionCancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
            _drainTasks =
            [
                DrainProcessOutputAsync(
                    _process.StandardOutput,
                    LogLevel.Trace,
                    _connectionCancellation.Token),
                DrainProcessOutputAsync(
                    _process.StandardError,
                    LogLevel.Trace,
                    _connectionCancellation.Token)
            ];

            _socket = await ConnectWithRetryAsync(port, cancellationToken);
            _pending = new ConcurrentDictionary<long, TaskCompletionSource<JsonElement>>();
            _receiveTask = ReceiveLoopAsync(_socket, _pending, _connectionCancellation.Token);

            var initializeResult = await SendRequestAsync(
                "initialize",
                new
                {
                    clientInfo = new
                    {
                        name = "codex-guardian",
                        title = "Codex Guardian",
                        version = "2.0.0"
                    },
                    capabilities = new
                    {
                        experimentalApi = true,
                        requestAttestation = false,
                        optOutNotificationMethods = new[]
                        {
                            "thread/tokenUsage/updated",
                            "turn/diff/updated",
                            "turn/plan/updated",
                            "item/started",
                            "item/completed",
                            "hook/started",
                            "hook/completed",
                            "item/mcpToolCall/progress",
                            "rawResponseItem/completed",
                            "rawResponse/completed",
                            "item/agentMessage/delta",
                            "item/reasoning/textDelta",
                            "item/reasoning/summaryTextDelta",
                            "command/exec/outputDelta"
                        }
                    }
                },
                cancellationToken);

            if (initializeResult.TryGetProperty("userAgent", out var userAgent))
            {
                ServerVersion = userAgent.GetString() ?? "Connected";
            }

            await SendNotificationAsync("initialized", null, cancellationToken);
            PublishConnectionTransition(connected: true);
            if (Interlocked.Exchange(ref _connectionSuccessLogged, 1) == 0)
            {
                _log.Success("Connected to the read-only Codex state service.");
            }
            else
            {
                _log.Trace("Reconnected to the read-only Codex state service.");
            }
        }
        catch
        {
            PublishConnectionTransition(connected: false);
            await ResetConnectionAsync();
            throw;
        }
        finally
        {
            _connectGate.Release();
        }
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        _ = _idleDisconnect.CancelPending();
        await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                await DisconnectConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _sessionGate.Release();
        }
    }

    public async Task<IReadOnlyList<ThreadSummary>> ListThreadsAsync(
        int limit,
        bool includeSubAgents,
        CancellationToken cancellationToken = default)
        => await ListThreadsAsync(limit, includeSubAgents, archived: false, cancellationToken);

    public async Task<IReadOnlyList<ThreadSummary>> ListThreadsAsync(
        int limit,
        bool includeSubAgents,
        bool archived,
        CancellationToken cancellationToken = default)
    {
        await EnsureConnectedAsync(cancellationToken);
        return await ListThreadsCoreAsync(
            limit,
            includeSubAgents,
            archived,
            (parameters, token) => SendRequestAsync("thread/list", parameters, token),
            cancellationToken);
    }

    public async Task<ThreadSummary> ReadThreadForRecoveryAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        await EnsureConnectedAsync(cancellationToken);
        return await ReadThreadForRecoveryCoreAsync(
            threadId,
            (parameters, token) => SendRequestAsync("thread/read", parameters, token),
            cancellationToken);
    }

    internal static async Task<ThreadSummary> ReadThreadForRecoveryCoreAsync(
        string threadId,
        Func<object, CancellationToken, Task<JsonElement>> sendRequestAsync,
        CancellationToken cancellationToken = default,
        Func<string, bool>? rolloutExists = null)
    {
        if (string.IsNullOrWhiteSpace(threadId))
        {
            throw new ArgumentException("A thread ID is required.", nameof(threadId));
        }

        var result = await sendRequestAsync(
            new
            {
                threadId,
                includeTurns = false
            },
            cancellationToken);
        if (!result.TryGetProperty("thread", out var item) || item.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("thread/read did not return thread metadata.");
        }

        var returnedId = ReadString(item, "id");
        if (!string.Equals(returnedId, threadId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("thread/read returned metadata for a different task.");
        }

        var metadata = ParseThreadSummary(item, archived: false);
        if (metadata.IsEphemeral)
        {
            return metadata;
        }

        var rolloutPath = ReadNullableString(item, "path");
        var archived = ClassifyThreadArchivedPath(rolloutPath);
        if (archived is null)
        {
            throw new InvalidDataException(
                "thread/read did not return a rollout path with a verifiable active or archived scope.");
        }

        if (!archived.Value && !(rolloutExists ?? File.Exists)(rolloutPath!))
        {
            throw new InvalidDataException(
                "thread/read returned an active rollout path that no longer exists.");
        }

        return metadata with { IsArchived = archived.Value };
    }

    internal static async Task<IReadOnlyList<ThreadSummary>> ListThreadsCoreAsync(
        int pageSize,
        bool includeSubAgents,
        bool archived,
        Func<object, CancellationToken, Task<JsonElement>> sendRequestAsync,
        CancellationToken cancellationToken = default)
    {
        var threads = new List<ThreadSummary>();
        var seenCursors = new HashSet<string>(StringComparer.Ordinal);
        var seenThreadIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenRolloutPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? cursor = null;

        do
        {
            var result = await sendRequestAsync(
                new
                {
                    cursor,
                    limit = Math.Clamp(pageSize, 1, 200),
                    archived,
                    sortKey = "updated_at",
                    sortDirection = "desc",
                    modelProviders = Array.Empty<string>(),
                    sourceKinds = includeSubAgents
                        ? AllThreadSourceKinds
                        : InteractiveThreadSourceKinds,
                    useStateDbOnly = true
                },
                cancellationToken);

            if (!result.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            {
                break;
            }

            foreach (var item in data.EnumerateArray())
            {
                var isSubAgent = IsSubAgentThread(item);
                if (isSubAgent && !includeSubAgents)
                {
                    continue;
                }

                var id = ReadString(item, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    continue;
                }

                var rolloutPath = ReadNullableString(item, "path");
                if (!seenThreadIds.Add(id) ||
                    (!string.IsNullOrWhiteSpace(rolloutPath) &&
                     !seenRolloutPaths.Add(NormalizeRolloutPath(rolloutPath))))
                {
                    continue;
                }

                threads.Add(ParseThreadSummary(item, archived));
            }

            cursor = ReadNullableString(result, "nextCursor");
        }
        while (!string.IsNullOrWhiteSpace(cursor) && seenCursors.Add(cursor));

        return threads;
    }

    public async Task<TurnSnapshot?> ReadLatestTurnAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        var turns = await ReadTurnsAsync(
            threadId,
            LatestTurnPageSize,
            SummaryItemsView,
            cancellationToken);
        return turns.FirstOrDefault();
    }

    internal async Task<TurnSnapshot?> ReadLatestTurnWithFullItemsAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        var turns = await ReadTurnsAsync(
            threadId,
            LatestTurnPageSize,
            FullItemsView,
            cancellationToken);
        return turns.FirstOrDefault();
    }

    public async Task<IReadOnlyList<TurnSnapshot>> ReadRecentTurnsAsync(
        string threadId,
        int limit = 10,
        CancellationToken cancellationToken = default) =>
        await ReadTurnsAsync(threadId, limit, SummaryItemsView, cancellationToken);

    public async Task<TurnSnapshot?> FindRecentTurnByClientMessageIdAsync(
        string threadId,
        string clientMessageId,
        int limit = 20,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientMessageId))
        {
            return null;
        }

        var turns = await ReadTurnsAsync(
            threadId,
            Math.Clamp(limit, 1, 20),
            SummaryItemsView,
            cancellationToken);
        return turns.FirstOrDefault(turn =>
            turn.UserMessageClientIds?.Contains(clientMessageId, StringComparer.OrdinalIgnoreCase) == true);
    }

    private async Task<IReadOnlyList<TurnSnapshot>> ReadTurnsAsync(
        string threadId,
        int limit,
        string itemsView,
        CancellationToken cancellationToken)
    {
        await EnsureConnectedAsync(cancellationToken);
        var requested = Math.Clamp(limit, 1, 200);
        var turns = new List<TurnSnapshot>(requested);
        var seenCursors = new HashSet<string>(StringComparer.Ordinal);
        string? cursor = null;

        do
        {
            var result = await SendRequestAsync(
                "thread/turns/list",
                new
                {
                    threadId,
                    cursor,
                    limit = Math.Min(50, requested - turns.Count),
                    sortDirection = "desc",
                    itemsView
                },
                cancellationToken);

            if (!result.TryGetProperty("data", out var data) ||
                data.ValueKind != JsonValueKind.Array ||
                data.GetArrayLength() == 0)
            {
                break;
            }

            foreach (var turn in data.EnumerateArray())
            {
                turns.Add(ParseTurn(turn));
                if (turns.Count == requested)
                {
                    break;
                }
            }

            cursor = ReadNullableString(result, "nextCursor");
        }
        while (!string.IsNullOrWhiteSpace(cursor) && seenCursors.Add(cursor) && turns.Count < requested);

        return turns;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _ = _idleDisconnect.CancelPending();
        await _sessionGate.WaitAsync().ConfigureAwait(false);
        try
        {
            _lifetime.Cancel();
            await DisconnectConnectionAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _sessionGate.Release();
        }

        await _idleDisconnect.DisposeAsync().ConfigureAwait(false);
        _sendGate.Dispose();
        _connectGate.Dispose();
        _sessionGate.Dispose();
        _lifetime.Dispose();
    }

    private async ValueTask ReleaseReadSessionAsync()
    {
        try
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                switch (DetermineReadSessionReleaseAction(IsConnected, MonitoringLeaseCount > 0))
                {
                    case ReadSessionReleaseAction.KeepConnected:
                        break;
                    case ReadSessionReleaseAction.ScheduleIdleDisconnect:
                        _idleDisconnect.Schedule();
                        break;
                    case ReadSessionReleaseAction.DisconnectBrokenConnection:
                        await DisconnectConnectionAsync(CancellationToken.None).ConfigureAwait(false);
                        break;
                }
            }
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to release the on-demand Codex state service: " + exception.Message);
        }
        finally
        {
            _sessionGate.Release();
        }
    }

    private async Task DisconnectAfterReadIdleAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (Volatile.Read(ref _disposed) == 0 && MonitoringLeaseCount == 0)
                {
                    await DisconnectConnectionAsync(CancellationToken.None).ConfigureAwait(false);
                }
            }
            finally
            {
                _sessionGate.Release();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to stop the idle Codex state service: " + exception.Message);
        }
    }

    internal static ReadSessionReleaseAction DetermineReadSessionReleaseAction(
        bool isConnected,
        bool monitoringPinned = false) => !isConnected
            ? ReadSessionReleaseAction.DisconnectBrokenConnection
            : monitoringPinned
                ? ReadSessionReleaseAction.KeepConnected
                : ReadSessionReleaseAction.ScheduleIdleDisconnect;

    private ValueTask ReleaseMonitoringLeaseAsync()
    {
        var remaining = Interlocked.Decrement(ref _monitoringLeaseCount);
        if (remaining < 0)
        {
            Interlocked.Exchange(ref _monitoringLeaseCount, 0);
            remaining = 0;
        }

        if (remaining == 0 && Volatile.Read(ref _disposed) == 0 && IsConnected)
        {
            _idleDisconnect.Schedule();
        }

        return ValueTask.CompletedTask;
    }

    private async Task DisconnectConnectionAsync(CancellationToken cancellationToken)
    {
        await _connectGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await ResetConnectionAsync().ConfigureAwait(false);
            PublishConnectionTransition(connected: false);
        }
        finally
        {
            _connectGate.Release();
        }
    }

    internal static TurnSnapshot ParseTurn(JsonElement turn)
    {
        var errorMessage = default(string);
        var errorCode = default(string);
        int? httpStatusCode = null;
        if (turn.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object)
        {
            errorMessage = ReadNullableString(error, "message");
            if (error.TryGetProperty("codexErrorInfo", out var info) && info.ValueKind != JsonValueKind.Null)
            {
                errorCode = ReadErrorCode(info);
                // Current Desktop payloads put the provider's status beside the
                // codexErrorInfo discriminator (for example, { codexErrorInfo:
                // "rateLimitExceeded", httpStatusCode: 429 }). Older builds used
                // "responseTooManyFailedAttempts" for the same rate-limit family.
                // Older payloads can instead nest httpStatusCode in an object;
                // accept both shapes without weakening the failure allowlist.
                httpStatusCode = ReadHttpStatusCode(error) ?? ReadHttpStatusCode(info);
            }
            else
            {
                httpStatusCode = ReadHttpStatusCode(error);
            }
        }

        var userTextParts = new List<string>();
        var userMessageClientIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var rawUserInputParts = new List<JsonElement>();
        var assistantTextParts = new List<string>();
        var workFingerprintParts = new List<string>();
        var userMessageCount = 0;
        var textInputPartCount = 0;
        var hasAttachments = false;
        var hasWorkOutput = false;
        var hasUserMessage = false;
        var hasFinalAssistantOutput = false;
        var hasCommentaryOutput = false;
        var hasReasoningOutput = false;
        var hasToolActivity = false;
        var hasAmbiguousActivity = false;
        var hasCompleteItemEvidence =
            turn.TryGetProperty("items", out var items) &&
            items.ValueKind == JsonValueKind.Array &&
            (!turn.TryGetProperty("itemsView", out var itemsView) ||
             string.Equals(itemsView.GetString(), FullItemsView, StringComparison.OrdinalIgnoreCase));

        if (hasCompleteItemEvidence)
        {
            foreach (var item in items.EnumerateArray())
            {
                var type = ReadString(item, "type");
                switch (type)
                {
                    case "userMessage":
                        hasUserMessage = true;
                        userMessageCount++;
                        var clientId = ReadNullableString(item, "clientId");
                        if (!string.IsNullOrWhiteSpace(clientId))
                        {
                            userMessageClientIds.Add(clientId);
                        }

                        if (item.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var part in content.EnumerateArray())
                            {
                                rawUserInputParts.Add(part.Clone());
                                var partType = ReadString(part, "type");
                                if (partType == "text")
                                {
                                    textInputPartCount++;
                                    var text = ReadString(part, "text");
                                    if (!string.IsNullOrWhiteSpace(text))
                                    {
                                        userTextParts.Add(text);
                                    }
                                }
                                else
                                {
                                    hasAttachments = true;
                                }
                            }
                        }
                        break;

                    case "agentMessage":
                        var assistantText = ReadString(item, "text");
                        if (!string.IsNullOrWhiteSpace(assistantText))
                        {
                            assistantTextParts.Add(assistantText);
                            var phase = ReadNullableString(item, "phase");
                            if (string.Equals(phase, "commentary", StringComparison.OrdinalIgnoreCase))
                            {
                                hasCommentaryOutput = true;
                            }
                            else if (string.IsNullOrWhiteSpace(phase) ||
                                     string.Equals(phase, "final_answer", StringComparison.OrdinalIgnoreCase))
                            {
                                // Legacy providers omit phase; a completed non-commentary message remains
                                // the compatibility signal for a final answer.
                                hasFinalAssistantOutput = true;
                            }
                            else
                            {
                                // Future phases must not silently upgrade partial output into a final answer.
                                hasAmbiguousActivity = true;
                            }
                        }
                        break;

                    case "plan":
                        var planText = ReadString(item, "text");
                        if (!string.IsNullOrWhiteSpace(planText))
                        {
                            assistantTextParts.Add(planText);
                            hasCommentaryOutput = true;
                        }
                        break;

                    case "reasoning":
                        hasWorkOutput = true;
                        hasReasoningOutput = true;
                        workFingerprintParts.Add("reasoning:" + ReadString(item, "id"));
                        break;

                    case "commandExecution":
                    case "fileChange":
                    case "functionCallOutput":
                    case "mcpToolCall":
                    case "dynamicToolCall":
                    case "collabAgentToolCall":
                    case "webSearch":
                    case "imageView":
                    case "sleep":
                    case "imageGeneration":
                    case "enteredReviewMode":
                    case "exitedReviewMode":
                        hasWorkOutput = true;
                        hasToolActivity = true;
                        workFingerprintParts.Add(type + ":" + ReadString(item, "id"));
                        break;

                    case "hookPrompt":
                    case "contextCompaction":
                    case "subAgentActivity":
                        // Context injection, compaction, and inherited child status are not proof
                        // that this root turn performed replay-sensitive work.
                        break;

                    default:
                        hasAmbiguousActivity = true;
                        break;
                }
            }

            if (userMessageCount > 1)
            {
                hasAmbiguousActivity = true;
            }
        }

        var fingerprintInput = string.Join("\n", assistantTextParts.Concat(workFingerprintParts));
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintInput)))[..16];

        return new TurnSnapshot(
            ReadString(turn, "id"),
            ReadString(turn, "status"),
            errorMessage,
            errorCode,
            httpStatusCode,
            string.Join("\n", userTextParts),
            hasAttachments,
            assistantTextParts.Count > 0,
            hasWorkOutput,
            fingerprint,
            ReadNullableLong(turn, "startedAt"),
            ReadNullableLong(turn, "completedAt"),
            rawUserInputParts.Count == 0 ? null : JsonSerializer.Serialize(rawUserInputParts),
            UserMessageClientIds: userMessageClientIds.ToArray(),
            HasUserMessage: hasUserMessage,
            HasFinalAssistantOutput: hasFinalAssistantOutput,
            HasCommentaryOutput: hasCommentaryOutput,
            HasReasoningOutput: hasReasoningOutput,
            HasToolActivity: hasToolActivity,
            HasAmbiguousActivity: hasAmbiguousActivity,
            HasCompleteItemEvidence: hasCompleteItemEvidence,
            IsSingleTextUserInput:
                userMessageCount == 1 &&
                rawUserInputParts.Count == 1 &&
                textInputPartCount == 1 &&
                !hasAttachments);
    }

    internal static string CreateRecoveryMessageId(
        string threadId,
        string failedTurnId,
        RecoveryActionKind action)
    {
        var value = $"codex-guardian|{threadId}|{failedTurnId}|{action}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value))[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes).ToString("D");
    }

    private async Task<JsonElement> SendRequestAsync(
        string method,
        object? parameters,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _requestCount);
        if (string.Equals(method, "thread/list", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _threadListRequestCount);
        }
        else if (method is "thread/read" or "thread/turns/list")
        {
            Interlocked.Increment(ref _targetedReadRequestCount);
        }

        var socket = _socket;
        var pending = _pending;
        if (socket?.State != WebSocketState.Open || pending is null)
        {
            throw new InvalidOperationException("The Codex app-server connection is not open.");
        }

        var requestId = Interlocked.Increment(ref _nextRequestId);
        var completion = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pending.TryAdd(requestId, completion))
        {
            throw new InvalidOperationException("Unable to allocate a protocol request id.");
        }

        try
        {
            await SendPayloadAsync(
                JsonSerializer.SerializeToUtf8Bytes(new { id = requestId, method, @params = parameters }),
                socket,
                cancellationToken);

            using var registration = cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
            return await completion.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
        }
        finally
        {
            pending.TryRemove(requestId, out _);
        }
    }

    private Task SendNotificationAsync(string method, object? parameters, CancellationToken cancellationToken)
    {
        var socket = _socket;
        if (socket?.State != WebSocketState.Open)
        {
            throw new InvalidOperationException("The Codex app-server connection is not open.");
        }

        var bytes = parameters is null
            ? JsonSerializer.SerializeToUtf8Bytes(new { method })
            : JsonSerializer.SerializeToUtf8Bytes(new { method, @params = parameters });
        return SendPayloadAsync(bytes, socket, cancellationToken);
    }

    private async Task SendPayloadAsync(byte[] payload, ClientWebSocket socket, CancellationToken cancellationToken)
    {
        await _sendGate.WaitAsync(cancellationToken);
        try
        {
            await socket.SendAsync(payload, WebSocketMessageType.Text, true, cancellationToken);
        }
        finally
        {
            _sendGate.Release();
        }
    }

    private async Task ReceiveLoopAsync(
        ClientWebSocket socket,
        ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> pending,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        try
        {
            while (!cancellationToken.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                using var stream = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await socket.ReceiveAsync(buffer, cancellationToken);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        _log.Trace(
                            $"The read-only app-server requested WebSocket close: {result.CloseStatus} " +
                            $"{result.CloseStatusDescription ?? string.Empty}.");
                        await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "closing", cancellationToken);
                        return;
                    }

                    stream.Write(buffer, 0, result.Count);
                }
                while (!result.EndOfMessage);

                using var document = stream.TryGetBuffer(out var payload)
                    ? JsonDocument.Parse(payload.AsMemory(0, checked((int)stream.Length)))
                    : JsonDocument.Parse(stream.ToArray());
                var root = document.RootElement;
                if (!root.TryGetProperty("id", out var idElement) ||
                    idElement.ValueKind != JsonValueKind.Number ||
                    !idElement.TryGetInt64(out var id))
                {
                    if (ParseNotification(root) is { } notification)
                    {
                        EventSubscriberDispatcher.Invoke(
                            NotificationReceived,
                            this,
                            notification,
                            exception => _log.Trace(
                                "An app-server notification subscriber failed (" +
                                exception.GetType().Name + ")."));
                    }

                    continue;
                }

                if (!pending.TryGetValue(id, out var completion))
                {
                    continue;
                }

                if (root.TryGetProperty("result", out var response))
                {
                    completion.TrySetResult(response.Clone());
                }
                else if (root.TryGetProperty("error", out var error))
                {
                    completion.TrySetException(new AppServerRequestException(
                        ReadProtocolErrorCode(error),
                        FormatProtocolError(error)));
                }
                else
                {
                    completion.TrySetException(new InvalidOperationException("The app-server returned an empty response."));
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _log.Warning($"The app-server receive loop stopped: {exception.Message}");
        }
        finally
        {
            _log.Trace($"The read-only app-server receive loop ended: socket={socket.State}.");
            foreach (var completion in pending.Values)
            {
                completion.TrySetException(new IOException("The Codex app-server connection closed."));
            }

            if (ReferenceEquals(_socket, socket))
            {
                PublishConnectionTransition(connected: false);
                _ = CleanupClosedConnectionAsync(socket);
            }
        }
    }

    private async Task CleanupClosedConnectionAsync(ClientWebSocket socket)
    {
        try
        {
            await _sessionGate.WaitAsync(_lifetime.Token).ConfigureAwait(false);
            try
            {
                if (!ReferenceEquals(_socket, socket))
                {
                    return;
                }

                _ = _idleDisconnect.CancelPending();
                await DisconnectConnectionAsync(CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                _sessionGate.Release();
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to clean up the failed Codex state connection: " + exception.Message);
        }
    }

    private async Task<ClientWebSocket> ConnectWithRetryAsync(int port, CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        for (var attempt = 0; attempt < 30; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var socket = new ClientWebSocket();
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromMilliseconds(700));
                await socket.ConnectAsync(new Uri($"ws://127.0.0.1:{port}"), timeout.Token);
                return socket;
            }
            catch (Exception exception) when (exception is WebSocketException or OperationCanceledException)
            {
                lastError = exception;
                socket.Dispose();
                await Task.Delay(200, cancellationToken);
            }
        }

        throw new IOException("Timed out while connecting to the local Codex app-server.", lastError);
    }

    private async Task ResetConnectionAsync()
    {
        var socket = _socket;
        _socket = null;
        var pending = _pending;
        _pending = null;
        var receiveTask = _receiveTask;
        _receiveTask = null;
        var connectionCancellation = _connectionCancellation;
        _connectionCancellation = null;
        var drainTasks = _drainTasks;
        _drainTasks = [];

        connectionCancellation?.Cancel();
        if (pending is not null)
        {
            foreach (var completion in pending.Values)
            {
                completion.TrySetException(new IOException("The Codex app-server connection closed."));
            }
        }

        if (socket is not null)
        {
            try
            {
                if (socket.State == WebSocketState.Open)
                {
                    using var closeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await socket.CloseOutputAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "reset",
                        closeTimeout.Token);
                }
            }
            catch
            {
            }
            finally
            {
                socket.Dispose();
            }
        }

        var process = _process;
        _process = null;
        var processJob = _processJob;
        _processJob = null;
        await TerminateProcessTreeAsync(process, processJob).ConfigureAwait(false);

        if (receiveTask is not null)
        {
            try
            {
                await receiveTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        if (drainTasks.Length > 0)
        {
            try
            {
                await Task.WhenAll(drainTasks).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        connectionCancellation?.Dispose();

        ServerVersion = "Not connected";
    }

    private static SafeJobHandle CreateKillOnCloseJob()
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            job.Dispose();
            throw new Win32Exception(error, "Unable to create a Windows Job Object for the Codex app-server.");
        }

        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            }
        };

        if (SetInformationJobObject(
                job,
                JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation,
                ref limits,
                checked((uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())))
        {
            return job;
        }

        var setInformationError = Marshal.GetLastWin32Error();
        job.Dispose();
        throw new Win32Exception(
            setInformationError,
            "Unable to configure the Codex app-server Job Object for kill-on-close cleanup.");
    }

    private static void AssignProcessToKillOnCloseJob(SafeJobHandle job, Process process)
    {
        if (AssignProcessToJobObject(job, process.SafeHandle))
        {
            return;
        }

        throw new Win32Exception(
            Marshal.GetLastWin32Error(),
            "Unable to bind the Codex app-server process to its cleanup Job Object.");
    }

    private static async Task TerminateProcessTreeAsync(Process? process, SafeJobHandle? job)
    {
        try
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                }
            }
        }
        finally
        {
            // Closing the last Job handle is the final guarantee that the complete child tree exits.
            job?.Dispose();
        }

        if (process is null)
        {
            return;
        }

        try
        {
            if (!process.HasExited)
            {
                using var exitTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await process.WaitForExitAsync(exitTimeout.Token);
            }
        }
        catch
        {
        }
        finally
        {
            process.Dispose();
        }
    }

    private async Task DrainProcessOutputAsync(
        StreamReader reader,
        LogLevel level,
        CancellationToken cancellationToken)
    {
        var outputObserved = false;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    return;
                }

                if (!string.IsNullOrWhiteSpace(line))
                {
                    outputObserved = true;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            if (outputObserved)
            {
                _log.Write(level, "app-server emitted diagnostic output; raw content was omitted.");
            }
        }
    }

    private void PublishConnectionTransition(bool connected)
    {
        if (DesktopIpcClient.TryTransitionConnectionState(ref _publishedConnectionState, connected))
        {
            EventSubscriberDispatcher.Invoke(
                ConnectionChanged,
                this,
                connected,
                exception => _log.Trace(
                    "An app-server connection subscriber failed (" + exception.GetType().Name + ")."));
        }
    }

    private static int ReserveLoopbackPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static ThreadSummary ParseThreadSummary(JsonElement item, bool archived)
    {
        var preview = ReadString(item, "preview");
        var name = ReadNullableString(item, "name");
        if (string.IsNullOrWhiteSpace(name) || IsUnsafeConversationTitle(name))
        {
            name = CompactTitle(preview);
        }

        return new ThreadSummary(
            ReadString(item, "id"),
            name,
            preview,
            ReadString(item, "cwd"),
            ReadSource(item),
            ReadLong(item, "createdAt"),
            ReadLong(item, "updatedAt"),
            IsSubAgentThread(item),
            ReadBool(item, "ephemeral"),
            ReadThreadRuntimeStatus(item),
            archived,
            ReadCodexPinnedState(item));
    }

    private static bool IsUnsafeConversationTitle(string value) =>
        value.StartsWith('<') ||
        value.StartsWith('[') ||
        value.StartsWith('【') ||
        value.Contains("source_thread", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("turnRef", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("taskRef", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("D:\\", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("C:\\Users\\", StringComparison.OrdinalIgnoreCase);

    private static bool? ReadCodexPinnedState(JsonElement item)
    {
        if (!item.TryGetProperty("section", out var section))
        {
            return null;
        }

        if (section.ValueKind != JsonValueKind.Object ||
            !section.TryGetProperty("name", out var name) ||
            name.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        return string.Equals(name.GetString(), "Pinned", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool? ClassifyThreadArchivedPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var segments = NormalizeRolloutPath(path)
            .Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var index = segments.Length - 2; index >= 0; index--)
        {
            if (string.Equals(segments[index], "archived_sessions", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(segments[index], "sessions", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return null;
    }

    private static string ReadSource(JsonElement item)
    {
        if (!item.TryGetProperty("source", out var source))
        {
            return "unknown";
        }

        if (source.ValueKind == JsonValueKind.String)
        {
            return source.GetString() ?? "unknown";
        }

        if (source.ValueKind == JsonValueKind.Object)
        {
            return source.EnumerateObject().FirstOrDefault().Name ?? "subAgent";
        }

        return "unknown";
    }

    private static bool IsSubAgentThread(JsonElement item)
    {
        if (item.TryGetProperty("parentThreadId", out var parent) &&
            parent.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(parent.GetString()))
        {
            return true;
        }

        if (!item.TryGetProperty("source", out var source))
        {
            return false;
        }

        if (source.ValueKind == JsonValueKind.Object)
        {
            return source.EnumerateObject().Any(property =>
                string.Equals(property.Name, "subAgent", StringComparison.OrdinalIgnoreCase));
        }

        return source.ValueKind == JsonValueKind.String &&
               (source.GetString()?.StartsWith("subAgent", StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private static string NormalizeRolloutPath(string path)
    {
        var normalized = path.Trim().Replace('/', '\\');
        const string extendedUncPrefix = @"\\?\UNC\";
        const string extendedPathPrefix = @"\\?\";
        if (normalized.StartsWith(extendedUncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            normalized = @"\\" + normalized[extendedUncPrefix.Length..];
        }
        else if (normalized.StartsWith(extendedPathPrefix, StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[extendedPathPrefix.Length..];
        }

        return normalized.TrimEnd('\\');
    }

    internal static string ReadThreadRuntimeStatus(JsonElement item)
    {
        if (!item.TryGetProperty("status", out var status))
        {
            return "unknown";
        }

        if (status.ValueKind == JsonValueKind.String)
        {
            return status.GetString() ?? "unknown";
        }

        return status.ValueKind == JsonValueKind.Object
            ? ReadNullableString(status, "type") ?? "unknown"
            : "unknown";
    }

    internal static AppServerNotificationEventArgs? ParseNotification(JsonElement root)
    {
        if (!root.TryGetProperty("method", out var methodElement) ||
            methodElement.ValueKind != JsonValueKind.String ||
            methodElement.GetString() is not { Length: > 0 } method)
        {
            return null;
        }

        return new AppServerNotificationEventArgs(
            method,
            ReadNotificationThreadId(root),
            ReadNotificationTurnId(root));
    }

    private static string? ReadNotificationThreadId(JsonElement root)
    {
        if (!root.TryGetProperty("params", out var parameters) ||
            parameters.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var direct = ReadNullableString(parameters, "threadId");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        return parameters.TryGetProperty("thread", out var thread) &&
               thread.ValueKind == JsonValueKind.Object
            ? ReadNullableString(thread, "id")
            : null;
    }

    private static string? ReadNotificationTurnId(JsonElement root)
    {
        if (!root.TryGetProperty("params", out var parameters) ||
            parameters.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var direct = ReadNullableString(parameters, "turnId");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        return parameters.TryGetProperty("turn", out var turn) &&
               turn.ValueKind == JsonValueKind.Object
            ? ReadNullableString(turn, "id")
            : null;
    }

    private static string ReadErrorCode(JsonElement info)
    {
        if (info.ValueKind == JsonValueKind.String)
        {
            return info.GetString() ?? "other";
        }

        if (info.ValueKind == JsonValueKind.Object)
        {
            return info.EnumerateObject().FirstOrDefault().Name ?? "other";
        }

        return "other";
    }

    private static int? ReadHttpStatusCode(JsonElement info)
    {
        if (info.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (info.TryGetProperty("httpStatusCode", out var directStatus) &&
            directStatus.ValueKind == JsonValueKind.Number &&
            directStatus.TryGetInt32(out var directValue))
        {
            return directValue;
        }

        foreach (var outer in info.EnumerateObject())
        {
            if (outer.Value.ValueKind == JsonValueKind.Object &&
                outer.Value.TryGetProperty("httpStatusCode", out var status) &&
                status.ValueKind == JsonValueKind.Number &&
                status.TryGetInt32(out var value))
            {
                return value;
            }
        }

        return null;
    }

    internal static string FormatProtocolError(JsonElement error)
    {
        if (error.TryGetProperty("code", out var code))
        {
            var normalized = code.ValueKind == JsonValueKind.String
                ? code.GetString()
                : code.GetRawText();
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return "The read-only app-server rejected a request (code " +
                       GuardianLog.SanitizeIdentifier(normalized) + ").";
            }
        }

        return "The read-only app-server rejected a request.";
    }

    internal static string ReadProtocolErrorCode(JsonElement error)
    {
        if (!error.TryGetProperty("code", out var code))
        {
            return "unknown";
        }

        var value = code.ValueKind == JsonValueKind.String
            ? code.GetString()
            : code.GetRawText();
        return GuardianLog.SanitizeIdentifier(value);
    }

    private static string CompactTitle(string preview)
    {
        var value = preview
            .Replace('\r', '\n')
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(line =>
                !line.StartsWith('<') &&
                !line.StartsWith('[') &&
                !line.StartsWith('【') &&
                !line.Contains("source_thread", StringComparison.OrdinalIgnoreCase) &&
                !line.Contains("turnRef", StringComparison.OrdinalIgnoreCase) &&
                !line.Contains("taskRef", StringComparison.OrdinalIgnoreCase) &&
                !line.Contains("D:\\", StringComparison.OrdinalIgnoreCase) &&
                !line.Contains("C:\\Users\\", StringComparison.OrdinalIgnoreCase) &&
                !(line.StartsWith("-", StringComparison.Ordinal) && line.Contains('\\')))
            ?.Trim() ?? string.Empty;
        return value.Length <= 44 ? value : value[..43] + "...";
    }

    private static string ReadString(JsonElement element, string propertyName)
    {
        return ReadNullableString(element, propertyName) ?? string.Empty;
    }

    private static string? ReadNullableString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static long ReadLong(JsonElement element, string propertyName)
    {
        return ReadNullableLong(element, propertyName) ?? 0;
    }

    private static long? ReadNullableLong(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) &&
               value.ValueKind == JsonValueKind.Number &&
               value.TryGetInt64(out var number)
            ? number
            : null;
    }

    private static bool ReadBool(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) &&
               value.ValueKind is JsonValueKind.True or JsonValueKind.False &&
               value.GetBoolean();
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    }

    private sealed class ReadSessionLease(AppServerClient owner) : IAsyncDisposable
    {
        private AppServerClient? _owner = owner;

        public ValueTask DisposeAsync()
        {
            var current = Interlocked.Exchange(ref _owner, null);
            return current is null
                ? ValueTask.CompletedTask
                : current.ReleaseReadSessionAsync();
        }
    }

    private sealed class MonitoringLease(AppServerClient owner) : IAsyncDisposable
    {
        private AppServerClient? _owner = owner;

        public ValueTask DisposeAsync()
        {
            var current = Interlocked.Exchange(ref _owner, null);
            return current is null
                ? ValueTask.CompletedTask
                : current.ReleaseMonitoringLeaseAsync();
        }
    }

    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    private enum JOBOBJECTINFOCLASS
    {
        JobObjectExtendedLimitInformation = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    private sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeJobHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeJobHandle CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeJobHandle job,
        JOBOBJECTINFOCLASS jobObjectInformationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobObjectInformation,
        uint jobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeJobHandle job, SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(SafeProcessHandle process, out IO_COUNTERS ioCounters);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

internal sealed class IdleDisconnectScheduler : IAsyncDisposable
{
    private readonly object _sync = new();
    private readonly TimeSpan _delay;
    private readonly Func<CancellationToken, Task> _disconnectAsync;
    private CancellationTokenSource? _pendingCancellation;
    private Task _pendingTask = Task.CompletedTask;
    private int _disposed;

    internal IdleDisconnectScheduler(
        TimeSpan delay,
        Func<CancellationToken, Task> disconnectAsync)
    {
        if (delay < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(delay));
        }

        _delay = delay;
        _disconnectAsync = disconnectAsync ?? throw new ArgumentNullException(nameof(disconnectAsync));
    }

    internal bool HasPending
    {
        get
        {
            lock (_sync)
            {
                return _pendingCancellation is not null;
            }
        }
    }

    internal Task PendingTask
    {
        get
        {
            lock (_sync)
            {
                return _pendingTask;
            }
        }
    }

    internal void Schedule()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            TryCancel(_pendingCancellation);
            var cancellation = new CancellationTokenSource();
            _pendingCancellation = cancellation;
            _pendingTask = RunAsync(cancellation);
        }
    }

    internal Task CancelPending()
    {
        lock (_sync)
        {
            TryCancel(_pendingCancellation);
            return _pendingTask;
        }
    }

    public async ValueTask DisposeAsync()
    {
        Task pendingTask;
        lock (_sync)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            TryCancel(_pendingCancellation);
            pendingTask = _pendingTask;
        }

        await pendingTask.ConfigureAwait(false);
    }

    private async Task RunAsync(CancellationTokenSource cancellation)
    {
        try
        {
            await Task.Delay(_delay, cancellation.Token).ConfigureAwait(false);
            cancellation.Token.ThrowIfCancellationRequested();
            await _disconnectAsync(cancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
        }
        finally
        {
            lock (_sync)
            {
                if (ReferenceEquals(_pendingCancellation, cancellation))
                {
                    _pendingCancellation = null;
                }
            }

            cancellation.Dispose();
        }
    }

    private static void TryCancel(CancellationTokenSource? cancellation)
    {
        try
        {
            cancellation?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }
}

public sealed class AppServerNotificationEventArgs(
    string method,
    string? threadId = null,
    string? turnId = null) : EventArgs
{
    public string Method { get; } = method;

    public string? ThreadId { get; } = threadId;

    public string? TurnId { get; } = turnId;
}

internal sealed class AppServerRequestException(string code, string message) : InvalidOperationException(message)
{
    internal string Code { get; } = code;
}

internal readonly record struct AppServerProcessSnapshot(
    int ProcessId,
    bool IsRunning,
    bool HasIoCounters,
    TimeSpan TotalProcessorTime,
    ulong ReadTransferBytes,
    ulong WriteTransferBytes)
{
    internal static AppServerProcessSnapshot Stopped => new(0, false, false, TimeSpan.Zero, 0, 0);
}

internal enum ReadSessionReleaseAction
{
    KeepConnected,
    ScheduleIdleDisconnect,
    DisconnectBrokenConnection
}
