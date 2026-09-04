using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text.Json;
using CodexGuardian.Models;
using CodexGuardian.WindowMotion;

namespace CodexGuardian.Services;

public sealed class GuardianLog : IDisposable
{
    internal const long MaximumLogBytes = 4 * 1024 * 1024;
    internal const long MaximumDiagnosticBytes = 2 * 1024 * 1024;
    internal const int MaximumPersistedMessageCharacters = 2048;
    private static readonly Regex BearerPattern = new(
        @"\bBearer\s+[A-Za-z0-9._~+/=-]+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex SecretPattern = new(
        @"\bsk-[A-Za-z0-9_-]{8,}\b|(?<name>(?:[A-Za-z][A-Za-z0-9_-]{0,31}[_-])?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|secret|password|token))(?<separator>\s*[:=]\s*)(?<value>[^\s,;&]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex UrlSecretPattern = new(
        @"(?<prefix>[?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|secret|password|token)=)[^&#\s]+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex JsonContentMarkerPattern = new(
        "\\\"(?:input|content|messages?|text)\\\"\\s*:",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private readonly object _sync = new();
    private readonly string _dataDirectory;
    private readonly string _logPath;
    private readonly string _diagnosticPath;
    private StreamWriter? _writer;
    private StreamWriter? _diagnosticWriter;

    public GuardianLog(string dataDirectory)
    {
        _dataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        DataDirectorySafety.Revalidate(_dataDirectory);
        Directory.CreateDirectory(_dataDirectory);
        DataDirectorySafety.Revalidate(_dataDirectory);
        _logPath = Path.Combine(_dataDirectory, "guardian.log");
        _diagnosticPath = Path.Combine(_dataDirectory, "guardian-diagnostics.jsonl");
        RotateIfNeeded();
        OpenWriter();
        RotateDiagnosticIfNeeded();
        OpenDiagnosticWriter();
    }

    public string LogPath => _logPath;

    /// <summary>
    /// The validated data directory this log writes into, for services that need to persist a small
    /// amount of their own state beside it.
    /// </summary>
    public string DataDirectory => _dataDirectory;

    public string DiagnosticPath => _diagnosticPath;

    public event EventHandler<LogEntry>? EntryWritten;

    public void Trace(string message, string? threadId = null) => Write(LogLevel.Trace, message, threadId);

    public void Info(string message, string? threadId = null) => Write(LogLevel.Info, message, threadId);

    public void Success(string message, string? threadId = null) => Write(LogLevel.Success, message, threadId);

    public void Warning(string message, string? threadId = null) => Write(LogLevel.Warning, message, threadId);

    public void Error(string message, string? threadId = null) => Write(LogLevel.Error, message, threadId);

    public void Write(LogLevel level, string message, string? threadId = null)
    {
        var persistedMessage = SanitizeForPersistence(message);
        var persistedThread = CreateThreadReference(threadId);
        var entry = new LogEntry(DateTimeOffset.Now, level, persistedMessage, persistedThread);
        lock (_sync)
        {
            try
            {
                var line = string.Format(
                    System.Globalization.CultureInfo.InvariantCulture,
                    "{0:O}\t{1}\t{2}\t{3}",
                    entry.Timestamp,
                    entry.Level,
                    persistedThread ?? "-",
                    persistedMessage);
                EnsureWriterCapacity(Encoding.UTF8.GetByteCount(line + Environment.NewLine));
                _writer?.WriteLine(line);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                _writer?.Dispose();
                _writer = null;
            }
        }

        EventSubscriberDispatcher.Invoke(EntryWritten, this, entry);
    }

    internal void WriteClassification(
        string threadId,
        TurnSnapshot? turn,
        RecoveryDecision decision)
    {
        WriteDiagnostic(new
        {
            schema = 1,
            timestamp = DateTimeOffset.Now,
            eventType = "classification",
            taskRef = CreateOpaqueReference("task", threadId),
            turnRef = CreateOpaqueReference("turn", turn?.Id),
            protocolStatus = SanitizeIdentifier(turn?.Status),
            hasUserMessage = turn?.HasUserMessage ?? false,
            hasAttachments = turn?.HasAttachments ?? false,
            hasAssistantOutput = turn?.HasAssistantOutput ?? false,
            hasFinalAssistantOutput = turn?.HasFinalAssistantOutput ?? false,
            hasCommentaryOutput = turn?.HasCommentaryOutput ?? false,
            hasReasoningOutput = turn?.HasReasoningOutput ?? false,
            hasToolActivity = turn?.HasToolActivity ?? false,
            hasAmbiguousActivity = turn?.HasAmbiguousActivity ?? false,
            hasCompleteItemEvidence = turn?.HasCompleteItemEvidence ?? false,
            hasConfirmedLocalTerminal = turn?.HasConfirmedLocalTerminal ?? false,
            action = decision.Action.ToString(),
            health = decision.Health.ToString()
        });
    }

    internal void WriteDispatchGate(
        string threadId,
        string turnId,
        string stage,
        string outcome,
        bool allowed)
    {
        WriteDiagnostic(new
        {
            schema = 1,
            timestamp = DateTimeOffset.Now,
            eventType = "dispatchGate",
            taskRef = CreateOpaqueReference("task", threadId),
            turnRef = CreateOpaqueReference("turn", turnId),
            stage = SanitizeIdentifier(stage),
            outcome = SanitizeIdentifier(outcome),
            allowed
        });
    }

    internal void WriteRecoveryResult(
        string threadId,
        string turnId,
        RecoveryActionKind action,
        RecoveryExecutionResult result)
    {
        WriteDiagnostic(new
        {
            schema = 1,
            timestamp = DateTimeOffset.Now,
            eventType = "recoveryResult",
            taskRef = CreateOpaqueReference("task", threadId),
            turnRef = CreateOpaqueReference("turn", turnId),
            successorRef = CreateOpaqueReference("turn", result.NewTurnId),
            action = action.ToString(),
            success = result.Success,
            userBlocked = result.IsUserBlocked,
            failureKind = result.FailureKind.ToString()
        });
    }

    internal void WriteMonitorCycle(
        string cycleKind,
        string trigger,
        string outcome,
        TimeSpan duration,
        int taskCount,
        long helperStarts,
        long protocolRequests,
        long threadListRequests,
        long targetedReadRequests,
        int fileIndexRefreshes)
    {
        WriteDiagnostic(new
        {
            schema = 1,
            timestamp = DateTimeOffset.Now,
            eventType = "monitorCycle",
            cycleKind = SanitizeIdentifier(cycleKind),
            trigger = SanitizeIdentifier(trigger),
            outcome = SanitizeIdentifier(outcome),
            durationMs = Math.Max(0, Math.Round(duration.TotalMilliseconds)),
            taskCount = Math.Max(0, taskCount),
            helperStarts = Math.Max(0, helperStarts),
            protocolRequests = Math.Max(0, protocolRequests),
            threadListRequests = Math.Max(0, threadListRequests),
            targetedReadRequests = Math.Max(0, targetedReadRequests),
            fileIndexRefreshes = Math.Max(0, fileIndexRefreshes)
        });
    }

    internal void WriteInteractionObservationSummary(
        long winEvents,
        long coalescedEvents,
        long observations,
        long timeouts,
        string status,
        bool available)
    {
        WriteDiagnostic(new
        {
            schema = 1,
            timestamp = DateTimeOffset.Now,
            eventType = "interactionObservation",
            winEvents = Math.Max(0, winEvents),
            coalescedEvents = Math.Max(0, coalescedEvents),
            observations = Math.Max(0, observations),
            timeouts = Math.Max(0, timeouts),
            status = SanitizeIdentifier(status),
            available
        });
    }

    internal void WriteWindowMotion(
        WindowMotionKind kind,
        WindowMotionResult result)
    {
        WriteDiagnostic(new
        {
            schema = 1,
            timestamp = DateTimeOffset.Now,
            eventType = "windowMotion",
            kind = kind.ToString(),
            generation = Math.Max(0, result.Generation),
            completion = result.Completion.ToString(),
            stage = result.Stage.ToString(),
            failureReason = result.FailureReason.ToString(),
            errorDomain = result.ErrorDomain.ToString(),
            errorCode = result.ErrorCode,
            errorType = SanitizeIdentifier(result.ErrorType),
            stateCommitted = result.StateCommitted,
            frameCount = Math.Max(0, result.FrameCount),
            elapsedMs = Math.Max(0, result.ElapsedMilliseconds),
            startWidth = result.StartBounds?.Width,
            startHeight = result.StartBounds?.Height,
            endWidth = result.EndBounds?.Width,
            endHeight = result.EndBounds?.Height,
            surfaceIsWindow = result.SurfaceState?.IsWindow,
            surfaceVisible = result.SurfaceState?.IsVisible,
            surfaceCloaked = result.SurfaceState?.IsCloaked,
            surfaceAboveSource = result.SurfaceState?.IsAboveSource,
            sourceIsWindow = result.SourceState?.IsWindow,
            sourceEnabled = result.SourceState?.IsEnabled,
            sourceMinimized = result.SourceState?.IsMinimized,
            sourceMaximized = result.SourceState?.IsMaximized,
            optionalFailureStage = result.OptionalFailureStage?.ToString(),
            optionalErrorDomain = result.OptionalErrorDomain.ToString(),
            optionalErrorCode = result.OptionalErrorCode
        });
    }

    internal static string SanitizeForPersistence(string? value)
    {
        var normalized = (value ?? string.Empty).Replace('\r', ' ').Replace('\n', ' ');
        normalized = BearerPattern.Replace(normalized, "Bearer [REDACTED]");
        normalized = SecretPattern.Replace(normalized, match =>
            match.Groups["name"].Success
                ? match.Groups["name"].Value + match.Groups["separator"].Value + "[REDACTED]"
                : "[REDACTED]");
        normalized = UrlSecretPattern.Replace(normalized, "${prefix}[REDACTED]");
        var contentMarker = JsonContentMarkerPattern.Match(normalized);
        if (contentMarker.Success)
        {
            normalized = normalized[..contentMarker.Index] + contentMarker.Value + " [REDACTED CONTENT]";
        }
        return normalized.Length <= MaximumPersistedMessageCharacters
            ? normalized
            : normalized[..MaximumPersistedMessageCharacters] + " [TRUNCATED]";
    }

    internal static string SanitizeIdentifier(string? value)
    {
        var normalized = new string((value ?? string.Empty)
            .Where(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.')
            .Take(80)
            .ToArray());
        return string.IsNullOrWhiteSpace(normalized) ? "unknown" : normalized;
    }

    // The argument must be the exact thread id, never the conversation title: titles collide
    // across distinct threads, which makes a label unable to attribute a log line to one task.
    // Delegating keeps this label byte-identical to the diagnostic taskRef for the same thread,
    // so guardian.log and guardian-diagnostics.jsonl can be joined on it.
    internal static string? CreateThreadReference(string? threadId) =>
        CreateOpaqueReference("task", threadId);

    internal static string? CreateOpaqueReference(string prefix, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return SanitizeIdentifier(prefix) + "-" + Convert.ToHexString(hash[..6]);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _writer?.Dispose();
            _writer = null;
            _diagnosticWriter?.Dispose();
            _diagnosticWriter = null;
        }
    }

    private void RotateIfNeeded(bool force = false)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _logPath);
        var file = new FileInfo(_logPath);
        if (!file.Exists || !force && file.Length < MaximumLogBytes)
        {
            return;
        }

        var archive = Path.Combine(file.DirectoryName!, "guardian.previous.log");
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _logPath);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, archive);
        File.Move(_logPath, archive, overwrite: true);
    }

    private void EnsureWriterCapacity(int additionalBytes)
    {
        if (_writer is null || _writer.BaseStream.Length + additionalBytes < MaximumLogBytes)
        {
            return;
        }

        _writer.Dispose();
        _writer = null;
        RotateIfNeeded(force: true);
        OpenWriter();
    }

    private void OpenWriter()
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _logPath);
        _writer = new StreamWriter(
            new FileStream(_logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true
        };
    }

    private void WriteDiagnostic<T>(T value)
    {
        lock (_sync)
        {
            try
            {
                var line = JsonSerializer.Serialize(value);
                EnsureDiagnosticWriterCapacity(Encoding.UTF8.GetByteCount(line + Environment.NewLine));
                _diagnosticWriter?.WriteLine(line);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                _ = exception;
                _diagnosticWriter?.Dispose();
                _diagnosticWriter = null;
            }
        }
    }

    private void RotateDiagnosticIfNeeded(bool force = false)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _diagnosticPath);
        var file = new FileInfo(_diagnosticPath);
        if (!file.Exists || !force && file.Length < MaximumDiagnosticBytes)
        {
            return;
        }

        var archive = Path.Combine(file.DirectoryName!, "guardian-diagnostics.previous.jsonl");
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, archive);
        File.Move(_diagnosticPath, archive, overwrite: true);
    }

    private void EnsureDiagnosticWriterCapacity(int additionalBytes)
    {
        if (_diagnosticWriter is null ||
            _diagnosticWriter.BaseStream.Length + additionalBytes < MaximumDiagnosticBytes)
        {
            return;
        }

        _diagnosticWriter.Dispose();
        _diagnosticWriter = null;
        RotateDiagnosticIfNeeded(force: true);
        OpenDiagnosticWriter();
    }

    private void OpenDiagnosticWriter()
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _diagnosticPath);
        _diagnosticWriter = new StreamWriter(
            new FileStream(_diagnosticPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true
        };
    }
}
