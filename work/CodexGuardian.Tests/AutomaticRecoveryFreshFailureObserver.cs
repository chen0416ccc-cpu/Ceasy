using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

internal sealed record AutomaticRecoveryFreshFailureObserverOptions(
    string ObserverId,
    string DataDirectory,
    TimeSpan Timeout,
    RecoveryActionKind RequiredAction);

internal sealed record AutomaticRecoveryFreshFailureObserverEvaluation(
    bool IsCandidate,
    string Code,
    ThreadSummary? Thread,
    TurnSnapshot? FailedTurn,
    RecoveryDecision? Decision)
{
    internal bool RequiresStructuredReplay =>
        FailedTurn is not null &&
        Decision is not null &&
        RecoveryService.RequiresStructuredInputReplay(FailedTurn, Decision.Action);
}

internal sealed record AutomaticRecoveryFreshFailureObserverLogRecord(
    int Schema,
    long Sequence,
    string EventType,
    DateTimeOffset TimestampUtc,
    string ObserverId,
    string? TaskRef = null,
    string? TurnRef = null,
    string? Code = null,
    string? Action = null,
    bool? HasAttachments = null,
    bool RealSend = false);

internal sealed record AutomaticRecoveryFreshFailureObserverCandidateManifest(
    int Schema,
    string ObserverId,
    string TargetThreadId,
    string FailedTurnId,
    RecoveryActionKind Action,
    DateTimeOffset ObservedAtUtc,
    string EvidenceDigest,
    string Checksum);

internal sealed class AutomaticRecoveryFreshFailureObserverEvidenceWriter : IDisposable
{
    internal const int MaximumRecords = 256;
    internal const int MaximumRecordBytes = 8 * 1024;
    internal const long MaximumBytes = 512 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    private readonly FileStream _stream;
    private readonly string _dataDirectory;
    private long _bytesWritten;
    private int _recordCount;
    private int _disposed;

    internal AutomaticRecoveryFreshFailureObserverEvidenceWriter(string dataDirectory)
    {
        _dataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, JsonlPath);
        _stream = new FileStream(
            JsonlPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough);
    }

    internal string JsonlPath => Path.Combine(_dataDirectory, "fresh-failure-observer.jsonl");

    internal int RecordCount => _recordCount;

    internal long BytesWritten => _bytesWritten;

    internal void Append(AutomaticRecoveryFreshFailureObserverLogRecord record)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        ArgumentNullException.ThrowIfNull(record);
        if (_recordCount >= MaximumRecords)
        {
            throw new InvalidOperationException("observer-evidence-record-bound-exceeded");
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(record, JsonOptions);
        var line = new byte[payload.Length + 1];
        payload.CopyTo(line, 0);
        line[^1] = (byte)'\n';
        if (line.Length > MaximumRecordBytes || _bytesWritten + line.Length > MaximumBytes)
        {
            throw new InvalidOperationException("observer-evidence-byte-bound-exceeded");
        }

        _stream.Write(line, 0, line.Length);
        _stream.Flush(flushToDisk: true);
        _bytesWritten += line.Length;
        _recordCount++;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _stream.Dispose();
        }
    }
}

internal static class AutomaticRecoveryFreshFailureObserver
{
    internal const string ObserverArgument = "--automatic-recovery-fresh-failure-observer";
    internal const string ObserverIdArgument = "--observer-id";
    internal const string DataDirectoryArgument = "--data-directory";
    internal const string TimeoutArgument = "--timeout-seconds";
    internal const string RequiredActionArgument = "--required-action";
    internal const string DataRoot = @"D:\CodexData\CodexGuardian";
    internal const string TempRoot = @"D:\CodexTemp\CodexGuardian\fresh-failure-observer";
    internal const string CandidateFileName = "fresh-failure-candidate.json";

    private static readonly JsonSerializerOptions CandidateJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    internal static bool IsRequested(IReadOnlyList<string> arguments) =>
        arguments.Any(argument => string.Equals(
            argument,
            ObserverArgument,
            StringComparison.OrdinalIgnoreCase));

    internal static AutomaticRecoveryFreshFailureObserverOptions Parse(
        IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var allowedFlags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ObserverArgument
        };
        var allowedValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ObserverIdArgument,
            DataDirectoryArgument,
            TimeoutArgument,
            RequiredActionArgument
        };

        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (allowedFlags.Contains(argument))
            {
                if (!flags.Add(argument))
                {
                    throw new ArgumentException("The fresh-failure observer contains a duplicate flag.");
                }

                continue;
            }

            if (!allowedValues.Contains(argument) ||
                index + 1 >= arguments.Count ||
                arguments[index + 1].StartsWith("--", StringComparison.Ordinal) ||
                !values.TryAdd(argument, arguments[++index]))
            {
                throw new ArgumentException("The fresh-failure observer argument matrix is invalid.");
            }
        }

        if (!flags.Contains(ObserverArgument) ||
            values.Count != 4 ||
            !values.TryGetValue(ObserverIdArgument, out var observerId) ||
            !values.TryGetValue(DataDirectoryArgument, out var dataDirectory) ||
            !values.TryGetValue(TimeoutArgument, out var timeoutText) ||
            !values.TryGetValue(RequiredActionArgument, out var requiredActionText))
        {
            throw new ArgumentException(
                "The fresh-failure observer requires one id, data directory, timeout, and required action.");
        }

        observerId = NormalizeId(observerId, ObserverIdArgument);
        dataDirectory = NormalizeDataDirectory(dataDirectory, observerId);
        if (!int.TryParse(timeoutText, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) ||
            seconds is < 30 or > 3600)
        {
            throw new ArgumentException("The fresh-failure observer timeout must be between 30 and 3600 seconds.");
        }

        if (!Enum.TryParse<RecoveryActionKind>(
                requiredActionText,
                ignoreCase: true,
                out var requiredAction) ||
            !Enum.IsDefined(requiredAction) ||
            requiredAction == RecoveryActionKind.None)
        {
            throw new ArgumentException(
                "The fresh-failure observer required action must be a concrete recovery action.");
        }

        return new AutomaticRecoveryFreshFailureObserverOptions(
            observerId,
            dataDirectory,
            TimeSpan.FromSeconds(seconds),
            requiredAction);
    }

    internal static bool MatchesRequiredAction(
        RecoveryDecision? decision,
        RecoveryActionKind requiredAction) =>
        decision is not null &&
        decision.Action == requiredAction &&
        requiredAction != RecoveryActionKind.None;

    internal static AutomaticRecoveryFreshFailureObserverEvaluation Evaluate(
        DateTimeOffset baselineUtc,
        LocalConversationTerminalDetectedEventArgs watcherEvent,
        ThreadSummary? thread,
        TurnSnapshot? appServerTurn,
        LocalConversationTerminalEvent? localTerminal)
    {
        ArgumentNullException.ThrowIfNull(watcherEvent);
        baselineUtc = baselineUtc.ToUniversalTime();
        if (watcherEvent.RecordedAt is not { } recordedAt ||
            recordedAt.ToUniversalTime() < baselineUtc)
        {
            return Rejected("event-before-baseline");
        }

        if (!IsCanonicalId(watcherEvent.ThreadId) || !IsCanonicalId(watcherEvent.TurnId))
        {
            return Rejected("event-identity-invalid");
        }

        if (watcherEvent.IsSubAgent == true)
        {
            return Rejected("subagent-event");
        }

        if (thread is null)
        {
            return Rejected("target-thread-missing");
        }

        if (!string.Equals(thread.Id, watcherEvent.ThreadId, StringComparison.OrdinalIgnoreCase))
        {
            return Rejected("target-thread-mismatch");
        }

        if (thread.IsArchived || thread.IsEphemeral || thread.IsSubAgent)
        {
            return Rejected("target-not-active-root");
        }

        if (RecoveryService.ValidateTargetThreadEligibility(
                watcherEvent.ThreadId,
                includeSubAgents: false,
                thread) is not null)
        {
            return Rejected("target-eligibility-invalid");
        }

        if (appServerTurn is null)
        {
            return Rejected("appserver-latest-missing");
        }

        if (!string.Equals(appServerTurn.Id, watcherEvent.TurnId, StringComparison.OrdinalIgnoreCase))
        {
            return Rejected("appserver-turn-mismatch");
        }

        if (localTerminal is null)
        {
            return Rejected("local-terminal-missing");
        }

        if (!string.Equals(localTerminal.ThreadId, watcherEvent.ThreadId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(localTerminal.TurnId, watcherEvent.TurnId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(localTerminal.SourceFile, watcherEvent.SourceFile, StringComparison.OrdinalIgnoreCase) ||
            localTerminal.RecordedAt is not { } localRecordedAt ||
            localRecordedAt.ToUniversalTime() < baselineUtc)
        {
            return Rejected("local-terminal-mismatch");
        }

        var failedTurn = LocalConversationHistoryReader.ReconcileLatestTurn(appServerTurn, localTerminal);
        if (failedTurn is null ||
            !failedTurn.HasConfirmedLocalTerminal)
        {
            return Rejected("local-terminal-unconfirmed");
        }

        if (RecoveryService.ValidateLatestTurn(failedTurn, watcherEvent.TurnId) is not null)
        {
            return Rejected("latest-turn-not-abnormal");
        }

        var decision = new RecoveryClassifier().Classify(failedTurn);
        if (decision.Action == RecoveryActionKind.None)
        {
            return new AutomaticRecoveryFreshFailureObserverEvaluation(
                false,
                "failed-turn-not-recoverable",
                thread,
                failedTurn,
                decision);
        }

        if (RecoveryService.RequiresStructuredInputReplay(failedTurn, decision.Action))
        {
            return new AutomaticRecoveryFreshFailureObserverEvaluation(
                false,
                "attachment-replay-live-gate-required",
                thread,
                failedTurn,
                decision);
        }

        return new AutomaticRecoveryFreshFailureObserverEvaluation(
            true,
            "candidate",
            thread,
            failedTurn,
            decision);
    }

    internal static string CreateOpaqueReference(string prefix, string value) =>
        GuardianLog.CreateOpaqueReference(prefix, value) ?? "unknown";

    internal static string ComputeEvidenceDigest(
        string observerId,
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        RecoveryDecision decision,
        DateTimeOffset observedAtUtc)
    {
        var input = string.Join(
            "\n",
            observerId,
            thread.Id,
            failedTurn.Id,
            failedTurn.Status,
            failedTurn.HasAttachments,
            failedTurn.OutputFingerprint,
            decision.Action,
            observedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }

    internal static string ComputeCandidateChecksum(
        AutomaticRecoveryFreshFailureObserverCandidateManifest manifest) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(
            manifest with { Checksum = string.Empty },
            CandidateJsonOptions)));

    internal static async Task<int> RunAsync(IReadOnlyList<string> arguments)
    {
        AutomaticRecoveryFreshFailureObserverOptions options;
        string runtimeDirectory;
        try
        {
            options = Parse(arguments);
            runtimeDirectory = BuildRuntimeDirectory(options.ObserverId);
            ValidateFreshDataDirectory(options.DataDirectory);
            ValidateFreshDataDirectory(runtimeDirectory);
            EnsureNoGuardianProcess();
            CreateProtectedDirectory(options.DataDirectory);
            CreateProtectedDirectory(runtimeDirectory);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or IOException or
                UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException)
        {
            Console.WriteLine(
                "OBSERVER_FAILED code=argument-or-environment-" +
                GuardianLog.SanitizeIdentifier(exception.GetType().Name));
            return 2;
        }

        var result = 1;
        Exception? runFailure = null;
        try
        {
            result = await RunCoreAsync(options, runtimeDirectory).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            runFailure = exception;
        }

        if (!TryDeleteRuntimeDirectory(runtimeDirectory, out var cleanupCode))
        {
            Console.WriteLine(
                "OBSERVER_FAILED code=" + cleanupCode + " realSend=False");
            return 1;
        }

        if (runFailure is OperationCanceledException)
        {
            Console.WriteLine(
                "OBSERVER_TIMEOUT observer=" + options.ObserverId + " candidate=false realSend=False");
            return 3;
        }

        if (runFailure is not null)
        {
            Console.WriteLine(
                "OBSERVER_FAILED code=unexpected-" +
                GuardianLog.SanitizeIdentifier(runFailure.GetType().Name) +
                " realSend=False");
            return 1;
        }

        if (result == 0)
        {
            Console.WriteLine(
                "OBSERVER_COMPLETE observer=" + options.ObserverId +
                " candidate=true realSend=False");
        }

        return result;
    }

    internal static void CreateProtectedDirectory(string directoryPath)
        => DataDirectorySafety.CreateProtectedDirectory(directoryPath);

    private static async Task<int> RunCoreAsync(
        AutomaticRecoveryFreshFailureObserverOptions options,
        string runtimeDirectory)
    {
        using var log = new GuardianLog(runtimeDirectory);
        using var evidence = new AutomaticRecoveryFreshFailureObserverEvidenceWriter(
            options.DataDirectory);
        await using var appServer = new AppServerClient(new CodexCliLocator(), log);
        var localHistory = new LocalConversationHistoryReader();
        var signals = Channel.CreateBounded<ObserverSignal>(
            new BoundedChannelOptions(64)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false
            });
        var signalOverflow = 0;
        var baselineUtc = DateTimeOffset.UtcNow;
        await using var watcher = new LocalConversationEventWatcher(log);
        watcher.TerminalDetected += (_, terminal) =>
        {
            if (!signals.Writer.TryWrite(new TerminalSignal(terminal)))
            {
                Interlocked.Exchange(ref signalOverflow, 1);
            }
        };
        watcher.Faulted += (_, fault) =>
        {
            if (!signals.Writer.TryWrite(new FaultSignal(
                    "watcher-fault-" + GuardianLog.SanitizeIdentifier(fault.Exception.GetType().Name))))
            {
                Interlocked.Exchange(ref signalOverflow, 1);
            }
        };
        watcher.Start();
        if (!watcher.IsRunning)
        {
            throw new InvalidOperationException("sessions-root-unavailable");
        }

        long sequence = 0;
        AppendAndPrint(
            evidence,
            ref sequence,
            new AutomaticRecoveryFreshFailureObserverLogRecord(
                1,
                sequence,
                "ready",
                DateTimeOffset.UtcNow,
                options.ObserverId,
                Code: "baseline-frozen",
                RealSend: false));
        Console.WriteLine(
            "OBSERVER_READY observer=" + options.ObserverId +
            " baseline=" + baselineUtc.ToString("O", CultureInfo.InvariantCulture) +
            " timeoutSeconds=" + options.Timeout.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) +
            " realSend=False");

        using var timeout = new CancellationTokenSource(options.Timeout);
        try
        {
            while (true)
            {
                bool canRead;
                try
                {
                    canRead = await signals.Reader.WaitToReadAsync(timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    return RecordTimeout(evidence, ref sequence, options.ObserverId);
                }

                if (!canRead)
                {
                    break;
                }

                if (Volatile.Read(ref signalOverflow) != 0)
                {
                    AppendAndPrint(
                        evidence,
                        ref sequence,
                        new AutomaticRecoveryFreshFailureObserverLogRecord(
                            1,
                            sequence,
                            "failed",
                            DateTimeOffset.UtcNow,
                            options.ObserverId,
                            Code: "event-queue-overflow",
                            RealSend: false));
                    Console.WriteLine(
                        "OBSERVER_FAILED code=event-queue-overflow realSend=False");
                    return 1;
                }

                while (signals.Reader.TryRead(out var signal))
                {
                if (signal is FaultSignal fault)
                {
                    AppendAndPrint(
                        evidence,
                        ref sequence,
                        new AutomaticRecoveryFreshFailureObserverLogRecord(
                            1,
                            sequence,
                            "failed",
                            DateTimeOffset.UtcNow,
                            options.ObserverId,
                            Code: fault.Code,
                            RealSend: false));
                    Console.WriteLine(
                        "OBSERVER_FAILED code=" + fault.Code + " realSend=False");
                    return 1;
                }

                var terminal = ((TerminalSignal)signal).Event;
                var taskRef = CreateOpaqueReference("task", terminal.ThreadId);
                var turnRef = CreateOpaqueReference("turn", terminal.TurnId);
                AppendAndPrint(
                    evidence,
                    ref sequence,
                    new AutomaticRecoveryFreshFailureObserverLogRecord(
                        1,
                        sequence,
                        "terminalSeen",
                        DateTimeOffset.UtcNow,
                        options.ObserverId,
                        taskRef,
                        turnRef,
                        Code: terminal.HasError ? "error" : "terminal",
                        RealSend: false));
                Console.WriteLine(
                    "OBSERVER_TERMINAL_SEEN taskRef=" + taskRef +
                    " turnRef=" + turnRef +
                    " hasError=" + terminal.HasError.ToString(CultureInfo.InvariantCulture));

                localHistory.RegisterSourceFile(terminal.ThreadId, terminal.SourceFile);
                var localTerminal = await ReadFreshLocalTerminalAsync(
                        localHistory,
                        terminal,
                        baselineUtc,
                        timeout.Token)
                    .ConfigureAwait(false);
                ThreadSummary? thread = null;
                TurnSnapshot? remote = null;
                try
                {
                    await using var readSession = await appServer.OpenReadSessionAsync(timeout.Token)
                        .ConfigureAwait(false);
                    thread = await appServer.ReadThreadForRecoveryAsync(
                            terminal.ThreadId,
                            timeout.Token)
                        .ConfigureAwait(false);
                    remote = await appServer.ReadLatestTurnWithFullItemsAsync(
                            terminal.ThreadId,
                            timeout.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    var code = "fact-read-" + GuardianLog.SanitizeIdentifier(exception.GetType().Name);
                    AppendAndPrint(
                        evidence,
                        ref sequence,
                        new AutomaticRecoveryFreshFailureObserverLogRecord(
                            1,
                            sequence,
                            "failed",
                            DateTimeOffset.UtcNow,
                            options.ObserverId,
                            taskRef,
                            turnRef,
                            code,
                            RealSend: false));
                    Console.WriteLine("OBSERVER_FAILED code=" + code + " realSend=False");
                    return 1;
                }

                var evaluation = Evaluate(
                    baselineUtc,
                    terminal,
                    thread,
                    remote,
                    localTerminal);
                if (!evaluation.IsCandidate)
                {
                    AppendAndPrint(
                        evidence,
                        ref sequence,
                        new AutomaticRecoveryFreshFailureObserverLogRecord(
                            1,
                            sequence,
                            "skipped",
                            DateTimeOffset.UtcNow,
                            options.ObserverId,
                            taskRef,
                            turnRef,
                            evaluation.Code,
                            evaluation.Decision?.Action.ToString(),
                            evaluation.FailedTurn?.HasAttachments,
                            false));
                    Console.WriteLine(
                        "OBSERVER_SKIPPED code=" + evaluation.Code +
                        " taskRef=" + taskRef +
                        " turnRef=" + turnRef +
                        " realSend=False");
                    continue;
                }

                if (!MatchesRequiredAction(evaluation.Decision, options.RequiredAction))
                {
                    AppendAndPrint(
                        evidence,
                        ref sequence,
                        new AutomaticRecoveryFreshFailureObserverLogRecord(
                            1,
                            sequence,
                            "skipped",
                            DateTimeOffset.UtcNow,
                            options.ObserverId,
                            taskRef,
                            turnRef,
                            "candidate-action-mismatch",
                            evaluation.Decision?.Action.ToString(),
                            evaluation.FailedTurn?.HasAttachments,
                            false));
                    Console.WriteLine(
                        "OBSERVER_SKIPPED code=candidate-action-mismatch" +
                        " taskRef=" + taskRef +
                        " turnRef=" + turnRef +
                        " observedAction=" + (evaluation.Decision?.Action.ToString() ?? "None") +
                        " requiredAction=" + options.RequiredAction +
                        " realSend=False");
                    continue;
                }

                var candidate = evaluation.Thread!;
                var failedTurn = evaluation.FailedTurn!;
                var decision = evaluation.Decision!;
                var observedAtUtc = DateTimeOffset.UtcNow;
                var evidenceDigest = ComputeEvidenceDigest(
                    options.ObserverId,
                    candidate,
                    failedTurn,
                    decision,
                    observedAtUtc);
                WriteCandidateManifest(
                    options,
                    candidate,
                    failedTurn,
                    decision,
                    observedAtUtc,
                    evidenceDigest);
                AppendAndPrint(
                    evidence,
                    ref sequence,
                    new AutomaticRecoveryFreshFailureObserverLogRecord(
                        1,
                        sequence,
                        "candidate",
                        observedAtUtc,
                        options.ObserverId,
                        taskRef,
                        turnRef,
                        "candidate",
                        decision.Action.ToString(),
                        failedTurn.HasAttachments,
                        false));
                Console.WriteLine(
                    "OBSERVER_CANDIDATE taskRef=" + taskRef +
                    " turnRef=" + turnRef +
                    " action=" + decision.Action +
                    " attachments=" + failedTurn.HasAttachments.ToString(CultureInfo.InvariantCulture) +
                    " candidateFile=" + CandidateFileName +
                    " realSend=False");
                    return 0;
                }
            }
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            return RecordTimeout(evidence, ref sequence, options.ObserverId);
        }

        return RecordTimeout(evidence, ref sequence, options.ObserverId);
    }

    private static async Task<LocalConversationTerminalEvent?> ReadFreshLocalTerminalAsync(
        LocalConversationHistoryReader history,
        LocalConversationTerminalDetectedEventArgs terminal,
        DateTimeOffset baselineUtc,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var local = await history.ReadLatestTerminalEventAsync(
                    terminal.ThreadId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (local is not null &&
                local.RecordedAt is { } recordedAt &&
                recordedAt.ToUniversalTime() >= baselineUtc &&
                string.Equals(local.TurnId, terminal.TurnId, StringComparison.OrdinalIgnoreCase))
            {
                return local;
            }

            if (attempt < 3)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
            }
        }

        return null;
    }

    private static void AppendAndPrint(
        AutomaticRecoveryFreshFailureObserverEvidenceWriter evidence,
        ref long sequence,
        AutomaticRecoveryFreshFailureObserverLogRecord record)
    {
        sequence++;
        evidence.Append(record with { Sequence = sequence });
    }

    private static int RecordTimeout(
        AutomaticRecoveryFreshFailureObserverEvidenceWriter evidence,
        ref long sequence,
        string observerId)
    {
        AppendAndPrint(
            evidence,
            ref sequence,
            new AutomaticRecoveryFreshFailureObserverLogRecord(
                1,
                sequence,
                "timeout",
                DateTimeOffset.UtcNow,
                observerId,
                Code: "bounded-timeout",
                RealSend: false));
        Console.WriteLine(
            "OBSERVER_TIMEOUT observer=" + observerId + " candidate=false realSend=False");
        return 3;
    }

    private static void WriteCandidateManifest(
        AutomaticRecoveryFreshFailureObserverOptions options,
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        RecoveryDecision decision,
        DateTimeOffset observedAtUtc,
        string evidenceDigest)
    {
        var path = Path.Combine(options.DataDirectory, CandidateFileName);
        DataDirectorySafety.RevalidateWriteTarget(options.DataDirectory, path);
        var unsigned = new AutomaticRecoveryFreshFailureObserverCandidateManifest(
            1,
            options.ObserverId,
            thread.Id,
            failedTurn.Id,
            decision.Action,
            observedAtUtc.ToUniversalTime(),
            evidenceDigest,
            string.Empty);
        var manifest = unsigned with { Checksum = ComputeCandidateChecksum(unsigned) };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, CandidateJsonOptions);
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private static AutomaticRecoveryFreshFailureObserverEvaluation Rejected(string code) =>
        new(false, code, null, null, null);

    private static string NormalizeDataDirectory(string value, string observerId)
    {
        var normalized = DataDirectorySafety.NormalizeAndValidate(value);
        var root = Path.GetFullPath(DataRoot).TrimEnd(Path.DirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        var leaf = Path.GetFileName(normalized.TrimEnd(Path.DirectorySeparatorChar));
        if (!normalized.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(leaf, observerId, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The observer data directory must be a D-drive child named by the observer id.",
                nameof(value));
        }

        return normalized;
    }

    private static string BuildRuntimeDirectory(string observerId)
    {
        var normalized = DataDirectorySafety.NormalizeAndValidate(
            Path.Combine(TempRoot, observerId));
        var root = Path.GetFullPath(TempRoot).TrimEnd(Path.DirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        if (!normalized.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(normalized.TrimEnd(Path.DirectorySeparatorChar)),
                observerId,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("observer-runtime-directory-invalid");
        }

        return normalized;
    }

    private static void ValidateFreshDataDirectory(string dataDirectory)
    {
        if (Directory.Exists(dataDirectory) || File.Exists(dataDirectory))
        {
            throw new InvalidOperationException("data-directory-not-fresh");
        }
    }

    private static bool TryDeleteRuntimeDirectory(string runtimeDirectory, out string code)
    {
        code = "runtime-cleanup-failed";
        try
        {
            if (!Directory.Exists(runtimeDirectory))
            {
                return true;
            }

            DataDirectorySafety.Revalidate(runtimeDirectory);
            if (Directory.EnumerateFileSystemEntries(runtimeDirectory, "*", SearchOption.AllDirectories)
                .Any(path => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0))
            {
                code = "runtime-cleanup-reparse-point";
                return false;
            }

            Directory.Delete(runtimeDirectory, recursive: true);
            return !Directory.Exists(runtimeDirectory);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException or
                NotSupportedException)
        {
            code = "runtime-cleanup-" + GuardianLog.SanitizeIdentifier(exception.GetType().Name);
            return false;
        }
    }

    private static void EnsureNoGuardianProcess()
    {
        var processes = System.Diagnostics.Process.GetProcessesByName("CodexGuardian");
        try
        {
            if (processes.Any(process => process.Id != Environment.ProcessId))
            {
                throw new InvalidOperationException("guardian-process-running");
            }
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }
    }

    private static string NormalizeId(string value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private static bool IsCanonicalId(string? value) =>
        Guid.TryParseExact(value, "D", out var parsed) &&
        parsed != Guid.Empty &&
        string.Equals(value, parsed.ToString("D"), StringComparison.OrdinalIgnoreCase);

    private abstract record ObserverSignal;

    private sealed record TerminalSignal(
        LocalConversationTerminalDetectedEventArgs Event) : ObserverSignal;

    private sealed record FaultSignal(string Code) : ObserverSignal;
}
