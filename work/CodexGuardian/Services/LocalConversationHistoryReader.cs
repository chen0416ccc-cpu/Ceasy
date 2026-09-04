using CodexGuardian.Models;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CodexGuardian.Services;

/// <summary>
/// Reads the bounded tail of local Codex rollouts without making protocol
/// requests or interacting with the Codex window.
/// </summary>
public sealed class LocalConversationHistoryReader
{
    private const int InitialTailBytes = 256 * 1024;
    private const int MaximumTailBytes = 8 * 1024 * 1024;
    private const int MaximumRecoveredUserTextBytes = 1024 * 1024;
    private const long MaximumLogicalIncidentBytes = 32L * 1024 * 1024;
    private const int MaximumLogicalIncidentLines = 100_000;
    private const string TaskCompleteMarker = "\"type\":\"task_complete\"";
    private const string TurnAbortedMarker = "\"type\":\"turn_aborted\"";

    private static readonly HashSet<string> ToolResponseItemTypes = new(StringComparer.Ordinal)
    {
        "computer_call",
        "computer_call_output",
        "custom_tool_call",
        "custom_tool_call_output",
        "file_search_call",
        "function_call",
        "function_call_output",
        "image_generation_call",
        "local_shell_call",
        "local_shell_call_output",
        "mcp_call",
        "mcp_list_tools",
        "web_search_call"
    };

    private static readonly HashSet<string> IgnoredResponseItemTypes = new(StringComparer.Ordinal)
    {
        "compaction",
        "context_compaction",
        "ghost_snapshot",
        "hook_prompt"
    };

    private static readonly Regex HttpStatusPattern = new(
        @"\b(?<status>[45]\d{2})\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly string _sessionsRoot;
    private readonly ConcurrentDictionary<string, string[]> _matchingFileCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, TailCacheEntry> _tailCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _fileIndexSync = new();
    private bool _fileIndexInitialized;
    private int _fileIndexRefreshCount;

    public LocalConversationHistoryReader(string? sessionsRoot = null)
    {
        _sessionsRoot = sessionsRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "sessions");
    }

    public string SessionsRoot => _sessionsRoot;

    internal int FileIndexRefreshCount => Volatile.Read(ref _fileIndexRefreshCount);

    internal void RegisterSourceFile(string threadId, string sourceFile)
    {
        ValidateThreadId(threadId);
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_sessionsRoot));
        var normalizedSource = Path.GetFullPath(sourceFile);
        if (!normalizedSource.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !ReadThreadIdsFromFileName(normalizedSource).Contains(threadId, StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        _matchingFileCache.AddOrUpdate(
            threadId,
            [normalizedSource],
            (_, existing) => existing.Contains(normalizedSource, StringComparer.OrdinalIgnoreCase)
                ? existing
                : existing.Append(normalizedSource)
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                    .ToArray());
        _tailCache.TryRemove(normalizedSource, out _);
    }

    internal void InvalidateFileIndex()
    {
        lock (_fileIndexSync)
        {
            _matchingFileCache.Clear();
            _fileIndexInitialized = false;
        }
    }

    public async Task<LocalConversationTerminalEvent?> ReadLatestTerminalEventAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        ValidateThreadId(threadId);
        var files = GetMatchingFiles(threadId);
        var terminals = new List<LocalConversationTerminalEvent>(files.Length);
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var terminal = await ReadLatestTerminalFromFileAsync(file, threadId, cancellationToken).ConfigureAwait(false);
            if (terminal is not null)
            {
                terminals.Add(terminal);
            }
        }

        return terminals
            .OrderByDescending(item => item.RecordedAt ?? DateTimeOffset.MinValue)
            .ThenByDescending(item => item.Turn.CompletedAt ?? item.Turn.StartedAt ?? 0)
            .FirstOrDefault();
    }

    public static TurnSnapshot? ReconcileLatestTurn(
        TurnSnapshot? appServerTurn,
        LocalConversationTerminalEvent? localTerminal,
        bool allowActiveLocalTerminal = false)
    {
        if (appServerTurn is null ||
            localTerminal is null ||
            !string.Equals(appServerTurn.Id, localTerminal.TurnId, StringComparison.OrdinalIgnoreCase))
        {
            return appServerTurn;
        }

        var localTurn = localTerminal.Turn;
        appServerTurn = MergeMissingLocalUserInput(appServerTurn, localTurn);
        var appStatus = appServerTurn.Status;
        var localStatus = localTurn.Status;

        // A live Desktop turn always wins. A completed app-server snapshot does not: stock Desktop
        // reports provider-side failures as completed/error=null, so the matching local task_complete
        // event is the authoritative terminal outcome unless Desktop has a strictly newer terminal.
        if (string.Equals(appStatus, "inProgress", StringComparison.OrdinalIgnoreCase) &&
            !allowActiveLocalTerminal)
        {
            return appServerTurn;
        }

        // An exact user abort is a durable opt-out from automatic recovery. A later failed
        // projection for the same turn must not turn that user action into a retry.
        if (string.Equals(localStatus, "aborted", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(appStatus, "completed", StringComparison.OrdinalIgnoreCase) &&
                appServerTurn.HasReliableFinalOutput)
            {
                return appServerTurn;
            }

            return appServerTurn with
            {
                Status = "aborted",
                ErrorMessage = null,
                ErrorCode = null,
                HttpStatusCode = null,
                StartedAt = localTurn.StartedAt ?? appServerTurn.StartedAt,
                CompletedAt = localTurn.CompletedAt ?? appServerTurn.CompletedAt,
                HasConfirmedLocalTerminal = true
            };
        }

        if (string.Equals(
                localStatus,
                RecoveryClassifier.UnverifiedAbortStatus,
                StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(appStatus, "completed", StringComparison.OrdinalIgnoreCase) &&
                appServerTurn.HasReliableFinalOutput)
            {
                return appServerTurn;
            }

            return appServerTurn with
            {
                Status = RecoveryClassifier.UnverifiedAbortStatus,
                ErrorMessage = null,
                ErrorCode = null,
                HttpStatusCode = null,
                StartedAt = localTurn.StartedAt ?? appServerTurn.StartedAt,
                CompletedAt = localTurn.CompletedAt ?? appServerTurn.CompletedAt,
                HasConfirmedLocalTerminal = false
            };
        }

        if (IsLocalTerminalOlderThanAppServerTurn(appServerTurn, localTerminal))
        {
            return appServerTurn;
        }

        if (string.Equals(localStatus, "completed", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(appStatus, "failed", StringComparison.OrdinalIgnoreCase))
            {
                return appServerTurn;
            }

            var reconciledCompleted = appServerTurn with
            {
                Status = "completed",
                ErrorMessage = null,
                ErrorCode = null,
                HttpStatusCode = null,
                StartedAt = localTurn.StartedAt ?? appServerTurn.StartedAt,
                CompletedAt = localTurn.CompletedAt ?? appServerTurn.CompletedAt,
                HasAssistantOutput = appServerTurn.HasAssistantOutput || localTurn.HasAssistantOutput,
                HasFinalAssistantOutput =
                    appServerTurn.HasFinalAssistantOutput || localTurn.HasAssistantOutput,
                HasConfirmedLocalTerminal = true
            };

            return !reconciledCompleted.HasReliableFinalOutput &&
                   reconciledCompleted.HasUserMessage &&
                   reconciledCompleted.HasCompleteItemEvidence
                ? reconciledCompleted with { Status = RecoveryClassifier.IncompleteTerminalStatus }
                : reconciledCompleted;
        }

        if (!string.Equals(localStatus, "failed", StringComparison.OrdinalIgnoreCase))
        {
            return appServerTurn;
        }

        return appServerTurn with
        {
            Status = "failed",
            // The rollout terminal is authoritative for the failed state, but it often carries
            // only the generic task_complete error. Preserve richer app-server provider evidence
            // (notably the sibling HTTP 429 and codexErrorInfo) when the local event omits it.
            ErrorMessage = localTurn.ErrorMessage ?? appServerTurn.ErrorMessage,
            ErrorCode = localTurn.ErrorCode ?? appServerTurn.ErrorCode,
            HttpStatusCode = localTurn.HttpStatusCode ?? appServerTurn.HttpStatusCode,
            StartedAt = localTurn.StartedAt ?? appServerTurn.StartedAt,
            CompletedAt = localTurn.CompletedAt ?? appServerTurn.CompletedAt,
            HasConfirmedLocalTerminal = true
        };
    }

    private static TurnSnapshot MergeMissingLocalUserInput(
        TurnSnapshot appServerTurn,
        TurnSnapshot localTurn)
    {
        if (appServerTurn.HasUserMessage ||
            appServerTurn.HasAttachments ||
            !localTurn.HasUserMessage ||
            localTurn.HasAttachments ||
            !localTurn.IsSingleTextUserInput ||
            string.IsNullOrWhiteSpace(localTurn.UserText) ||
            string.IsNullOrWhiteSpace(localTurn.RawUserInputJson))
        {
            return appServerTurn;
        }

        return appServerTurn with
        {
            UserText = localTurn.UserText,
            RawUserInputJson = localTurn.RawUserInputJson,
            UserMessageClientIds = localTurn.UserMessageClientIds,
            HasUserMessage = true,
            IsSingleTextUserInput = true,
            HasAssistantOutput = appServerTurn.HasAssistantOutput || localTurn.HasAssistantOutput,
            HasWorkOutput = appServerTurn.HasWorkOutput || localTurn.HasWorkOutput,
            HasCommentaryOutput = appServerTurn.HasCommentaryOutput || localTurn.HasCommentaryOutput,
            HasReasoningOutput = appServerTurn.HasReasoningOutput || localTurn.HasReasoningOutput,
            HasToolActivity = appServerTurn.HasToolActivity || localTurn.HasToolActivity,
            HasAmbiguousActivity = appServerTurn.HasAmbiguousActivity || localTurn.HasAmbiguousActivity
        };
    }

    private static bool IsLocalTerminalOlderThanAppServerTurn(
        TurnSnapshot appServerTurn,
        LocalConversationTerminalEvent localTerminal)
    {
        var localTerminalAt = localTerminal.Turn.CompletedAt ??
                              localTerminal.RecordedAt?.ToUnixTimeSeconds();
        var appServerTerminalAt = appServerTurn.CompletedAt ?? appServerTurn.StartedAt;
        return localTerminalAt is not null &&
               appServerTerminalAt is not null &&
               appServerTerminalAt > localTerminalAt;
    }

    private string[] GetMatchingFiles(string threadId)
    {
        if (TryGetCachedFiles(threadId, out var cached))
        {
            return cached;
        }

        lock (_fileIndexSync)
        {
            if (TryGetCachedFiles(threadId, out cached))
            {
                return cached;
            }

            if (!_fileIndexInitialized)
            {
                RefreshFileIndex();
                _fileIndexInitialized = true;
            }

            if (TryGetCachedFiles(threadId, out cached))
            {
                return cached;
            }

            _matchingFileCache.TryAdd(threadId, []);
            return [];
        }
    }

    private bool TryGetCachedFiles(string threadId, out string[] files)
    {
        files = [];
        if (!_matchingFileCache.TryGetValue(threadId, out var cached) || cached.Length == 0)
        {
            return false;
        }

        var existing = cached.Where(File.Exists).ToArray();
        if (existing.Length == 0)
        {
            _matchingFileCache.TryRemove(threadId, out _);
            return false;
        }

        if (existing.Length != cached.Length)
        {
            _matchingFileCache[threadId] = existing;
        }

        files = existing;
        return true;
    }

    private async Task<LocalConversationTerminalEvent?> ReadLatestTerminalFromFileAsync(
        string sourceFile,
        string threadId,
        CancellationToken cancellationToken)
    {
        var fileInfo = new FileInfo(sourceFile);
        if (!fileInfo.Exists)
        {
            return null;
        }

        if (_tailCache.TryGetValue(sourceFile, out var cached) &&
            cached.Length == fileInfo.Length &&
            cached.LastWriteTimeUtc == fileInfo.LastWriteTimeUtc)
        {
            return cached.Terminal;
        }

        var observedLength = fileInfo.Length;
        var observedLastWriteTimeUtc = fileInfo.LastWriteTimeUtc;
        var terminal = await ReadTerminalFromTailAsync(sourceFile, threadId, cancellationToken).ConfigureAwait(false);
        fileInfo.Refresh();
        if (fileInfo.Exists &&
            fileInfo.Length == observedLength &&
            fileInfo.LastWriteTimeUtc == observedLastWriteTimeUtc)
        {
            _tailCache[sourceFile] = new TailCacheEntry(observedLength, observedLastWriteTimeUtc, terminal);
        }
        else
        {
            _tailCache.TryRemove(sourceFile, out _);
        }

        return terminal;
    }

    private static async Task<LocalConversationTerminalEvent?> ReadTerminalFromTailAsync(
        string sourceFile,
        string threadId,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            sourceFile,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        if (stream.Length == 0)
        {
            return null;
        }

        var bytesToRead = Math.Min((long)InitialTailBytes, stream.Length);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var offset = stream.Length - bytesToRead;
            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[(int)bytesToRead];
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(totalRead), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                totalRead += read;
            }

            var text = Encoding.UTF8.GetString(buffer, 0, totalRead);
            var searchBefore = text.Length;
            var needsEarlierBytes = false;
            while (searchBefore > 0)
            {
                var taskCompleteIndex = text.LastIndexOf(
                    TaskCompleteMarker,
                    searchBefore - 1,
                    StringComparison.Ordinal);
                var turnAbortedIndex = text.LastIndexOf(
                    TurnAbortedMarker,
                    searchBefore - 1,
                    StringComparison.Ordinal);
                var markerIndex = Math.Max(taskCompleteIndex, turnAbortedIndex);
                if (markerIndex < 0)
                {
                    break;
                }

                var lineBreakBefore = text.LastIndexOf('\n', markerIndex);
                if (lineBreakBefore < 0 && offset > 0)
                {
                    needsEarlierBytes = true;
                    break;
                }

                var lineStart = lineBreakBefore < 0 ? 0 : lineBreakBefore + 1;
                var lineBreakAfter = text.IndexOf('\n', markerIndex);
                var lineEnd = lineBreakAfter < 0 ? text.Length : lineBreakAfter;
                var line = text[lineStart..lineEnd].TrimEnd('\r');
                var byteOffset = offset + Encoding.UTF8.GetByteCount(text.AsSpan(0, lineStart));
                if (TryParseTerminalLine(line, threadId, sourceFile, byteOffset, out var terminal))
                {
                    var inputSearch = ReadExactTurnUserInput(
                        text,
                        lineStart,
                        terminal!.TurnId,
                        hasEarlierBytes: offset > 0);
                    if (inputSearch.NeedsEarlierBytes &&
                        bytesToRead < stream.Length &&
                        bytesToRead < MaximumTailBytes)
                    {
                        needsEarlierBytes = true;
                        break;
                    }

                    if (RecoveryClassifier.IsExplicitUnsentProviderRejection(terminal!.Turn))
                    {
                        var incidentSearch = await ReadLogicalRetryIncidentAsync(
                                sourceFile,
                                terminal.TurnId,
                                cancellationToken)
                            .ConfigureAwait(false);
                        terminal = ApplyLogicalIncidentEvidence(terminal, incidentSearch);
                    }
                    else if (inputSearch.Evidence is not null)
                    {
                        terminal = terminal with
                        {
                            Turn = terminal.Turn with
                            {
                                UserText = inputSearch.Evidence.Text,
                                HasAttachments = false,
                                RawUserInputJson = inputSearch.Evidence.CanonicalInputJson,
                                HasUserMessage = true,
                                IsSingleTextUserInput = true
                            }
                        };
                    }
                    else if (inputSearch.IsAmbiguous)
                    {
                        terminal = terminal with
                        {
                            Turn = terminal.Turn with { HasAmbiguousActivity = true }
                        };
                    }

                    return terminal;
                }

                searchBefore = markerIndex;
            }

            if (bytesToRead >= stream.Length || bytesToRead >= MaximumTailBytes)
            {
                return null;
            }

            var expanded = Math.Min(stream.Length, bytesToRead * 2);
            if (!needsEarlierBytes && expanded == bytesToRead)
            {
                return null;
            }

            bytesToRead = expanded;
        }
    }

    private static LocalUserInputSearchResult ReadExactTurnUserInput(
        string tailText,
        int terminalLineStart,
        string turnId,
        bool hasEarlierBytes)
    {
        RolloutUserInputEvidence? evidence = null;
        var ambiguous = false;
        var foundTurnBoundary = false;
        var cursor = terminalLineStart;
        while (cursor > 0)
        {
            if (tailText[cursor - 1] == '\n')
            {
                cursor--;
            }

            var lineEnd = cursor;
            var previousBreak = lineEnd > 0
                ? tailText.LastIndexOf('\n', lineEnd - 1)
                : -1;
            var lineStart = previousBreak + 1;
            if (lineStart == 0 && hasEarlierBytes)
            {
                break;
            }

            var line = tailText[lineStart..lineEnd].TrimEnd('\r');
            cursor = lineStart;
            if (line.Length == 0)
            {
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var envelopeType = ReadString(root, "type");
                if (string.Equals(envelopeType, "event_msg", StringComparison.Ordinal) &&
                    root.TryGetProperty("payload", out var eventPayload) &&
                    eventPayload.ValueKind == JsonValueKind.Object)
                {
                    var eventType = ReadString(eventPayload, "type");
                    var eventTurnId = FirstNonEmptyString(eventPayload, "turn_id", "turnId");
                    if (string.Equals(eventType, "task_started", StringComparison.Ordinal) &&
                        string.Equals(eventTurnId, turnId, StringComparison.OrdinalIgnoreCase))
                    {
                        foundTurnBoundary = true;
                        break;
                    }

                    if (string.Equals(eventType, "task_complete", StringComparison.Ordinal) &&
                        !string.IsNullOrWhiteSpace(eventTurnId) &&
                        !string.Equals(eventTurnId, turnId, StringComparison.OrdinalIgnoreCase))
                    {
                        foundTurnBoundary = true;
                        break;
                    }
                }

                if (!string.Equals(envelopeType, "response_item", StringComparison.Ordinal) ||
                    !root.TryGetProperty("payload", out var payload) ||
                    payload.ValueKind != JsonValueKind.Object ||
                    !string.Equals(ReadString(payload, "type"), "message", StringComparison.Ordinal) ||
                    !string.Equals(ReadString(payload, "role"), "user", StringComparison.Ordinal) ||
                    !TryReadResponseItemTurnId(payload, out var itemTurnId) ||
                    !string.Equals(itemTurnId, turnId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var candidate = ParseRolloutUserInput(payload);
                switch (candidate.Kind)
                {
                    case RolloutUserInputKind.InjectedContext:
                        break;
                    case RolloutUserInputKind.ReplayableText when evidence is null:
                        evidence = candidate.Evidence;
                        break;
                    case RolloutUserInputKind.ReplayableText:
                    case RolloutUserInputKind.Ambiguous:
                        ambiguous = true;
                        break;
                }
            }
            catch (JsonException)
            {
                if (line.Contains(turnId, StringComparison.OrdinalIgnoreCase))
                {
                    ambiguous = true;
                }
            }
        }

        if (!foundTurnBoundary && hasEarlierBytes)
        {
            return new LocalUserInputSearchResult(null, NeedsEarlierBytes: true);
        }

        return new LocalUserInputSearchResult(
            ambiguous ? null : evidence,
            NeedsEarlierBytes: false,
            IsAmbiguous: ambiguous);
    }

    private static bool TryReadResponseItemTurnId(JsonElement payload, out string turnId)
    {
        turnId = string.Empty;
        if (!payload.TryGetProperty("internal_chat_message_metadata_passthrough", out var metadata) ||
            metadata.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        turnId = FirstNonEmptyString(metadata, "turn_id", "turnId") ?? string.Empty;
        return turnId.Length > 0;
    }

    private static ParsedRolloutUserInput ParseRolloutUserInput(JsonElement payload)
    {
        if (!payload.TryGetProperty("content", out var content) ||
            content.ValueKind != JsonValueKind.Array ||
            content.GetArrayLength() != 1)
        {
            return ParsedRolloutUserInput.Ambiguous;
        }

        var part = content[0];
        if (part.ValueKind != JsonValueKind.Object ||
            !string.Equals(ReadString(part, "type"), "input_text", StringComparison.Ordinal) ||
            !part.TryGetProperty("text", out var textElement) ||
            textElement.ValueKind != JsonValueKind.String)
        {
            return ParsedRolloutUserInput.Ambiguous;
        }

        var text = textElement.GetString() ?? string.Empty;
        var trimmed = text.Trim();
        if (trimmed.StartsWith("<environment_context>", StringComparison.Ordinal) &&
            trimmed.EndsWith("</environment_context>", StringComparison.Ordinal))
        {
            return ParsedRolloutUserInput.InjectedContext;
        }

        if (string.IsNullOrWhiteSpace(text) ||
            Encoding.UTF8.GetByteCount(text) > MaximumRecoveredUserTextBytes)
        {
            return ParsedRolloutUserInput.Ambiguous;
        }

        var canonical = JsonSerializer.Serialize(new[]
        {
            new
            {
                type = "text",
                text,
                text_elements = Array.Empty<object>()
            }
        });
        return new ParsedRolloutUserInput(
            RolloutUserInputKind.ReplayableText,
            new RolloutUserInputEvidence(text, canonical));
    }

    private static async Task<LogicalIncidentSearchResult> ReadLogicalRetryIncidentAsync(
        string sourceFile,
        string targetTurnId,
        CancellationToken cancellationToken)
    {
        var fileInfo = new FileInfo(sourceFile);
        if (!fileInfo.Exists || fileInfo.Length <= 0 || fileInfo.Length > MaximumLogicalIncidentBytes)
        {
            return LogicalIncidentSearchResult.Ambiguous;
        }

        try
        {
            await using var stream = new FileStream(
                sourceFile,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var reader = new StreamReader(
                stream,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 64 * 1024,
                leaveOpen: false);

            PendingRolloutUserInput? pendingInput = null;
            LogicalIncidentState? incident = null;
            var userBoundaryAmbiguous = false;
            var lineCount = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (line is null)
                {
                    break;
                }

                lineCount++;
                if (lineCount > MaximumLogicalIncidentLines)
                {
                    return LogicalIncidentSearchResult.Ambiguous;
                }

                JsonDocument? document = null;
                try
                {
                    document = JsonDocument.Parse(line);
                    var root = document.RootElement;
                    var envelopeType = ReadString(root, "type");
                    if (string.Equals(envelopeType, "event_msg", StringComparison.Ordinal) &&
                        root.TryGetProperty("payload", out var eventPayload) &&
                        eventPayload.ValueKind == JsonValueKind.Object)
                    {
                        var eventType = ReadString(eventPayload, "type");
                        var eventTurnId = FirstNonEmptyString(eventPayload, "turn_id", "turnId");
                        if ((string.Equals(eventType, "task_complete", StringComparison.Ordinal) ||
                             string.Equals(eventType, "turn_aborted", StringComparison.Ordinal)) &&
                            string.Equals(eventTurnId, targetTurnId, StringComparison.OrdinalIgnoreCase))
                        {
                            if (pendingInput is not null || userBoundaryAmbiguous || incident is null)
                            {
                                return new LogicalIncidentSearchResult(
                                    Evidence: null,
                                    IsAmbiguous: pendingInput is not null || userBoundaryAmbiguous,
                                    ReachedTarget: true);
                            }

                            return new LogicalIncidentSearchResult(
                                incident.ToEvidence(),
                                incident.HasAmbiguousActivity,
                                ReachedTarget: true);
                        }

                        switch (eventType)
                        {
                            case "user_message":
                            {
                                var eventText = FirstNonEmptyString(eventPayload, "message", "text");
                                var clientId = FirstNonEmptyString(eventPayload, "client_id", "clientId");
                                if (pendingInput is not null &&
                                    string.Equals(eventText, pendingInput.Evidence.Text, StringComparison.Ordinal) &&
                                    Guid.TryParse(clientId, out _))
                                {
                                    incident = new LogicalIncidentState(pendingInput.Evidence, clientId!);
                                    pendingInput = null;
                                    userBoundaryAmbiguous = false;
                                }
                                else
                                {
                                    incident = null;
                                    pendingInput = null;
                                    userBoundaryAmbiguous = true;
                                }

                                break;
                            }

                            case "thread_rolled_back":
                                incident?.ResetWork();
                                break;

                            case "agent_reasoning" when incident is not null:
                                incident.HasWorkOutput = true;
                                incident.HasReasoningOutput = true;
                                break;

                            case "agent_message" when incident is not null:
                                incident.HasAssistantOutput = true;
                                break;

                            case "task_complete" when incident is not null:
                                if (!TryReadError(eventPayload, out _, out _, out _) &&
                                    !string.IsNullOrWhiteSpace(FirstNonEmptyString(
                                        eventPayload,
                                        "last_agent_message",
                                        "lastAgentMessage")))
                                {
                                    incident = null;
                                    pendingInput = null;
                                    userBoundaryAmbiguous = false;
                                }

                                break;
                        }

                        continue;
                    }

                    if (!string.Equals(envelopeType, "response_item", StringComparison.Ordinal) ||
                        !root.TryGetProperty("payload", out var payload) ||
                        payload.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var itemType = ReadString(payload, "type");
                    if (string.Equals(itemType, "message", StringComparison.Ordinal))
                    {
                        var role = ReadString(payload, "role");
                        if (string.Equals(role, "user", StringComparison.Ordinal))
                        {
                            var candidate = ParseRolloutUserInput(payload);
                            if (candidate.Kind == RolloutUserInputKind.InjectedContext)
                            {
                                continue;
                            }

                            incident = null;
                            if (candidate.Kind != RolloutUserInputKind.ReplayableText ||
                                candidate.Evidence is null ||
                                !TryReadResponseItemTurnId(payload, out var itemTurnId))
                            {
                                pendingInput = null;
                                userBoundaryAmbiguous = true;
                                continue;
                            }

                            if (pendingInput is not null)
                            {
                                pendingInput = null;
                                userBoundaryAmbiguous = true;
                                continue;
                            }

                            pendingInput = new PendingRolloutUserInput(itemTurnId, candidate.Evidence);
                            userBoundaryAmbiguous = false;
                            continue;
                        }

                        if (string.Equals(role, "assistant", StringComparison.Ordinal) && incident is not null)
                        {
                            incident.HasAssistantOutput = true;
                            if (string.Equals(ReadString(payload, "phase"), "commentary", StringComparison.OrdinalIgnoreCase))
                            {
                                incident.HasCommentaryOutput = true;
                            }
                        }
                        else if (!string.Equals(role, "developer", StringComparison.Ordinal) &&
                                 !string.Equals(role, "system", StringComparison.Ordinal) &&
                                 incident is not null)
                        {
                            incident.HasAmbiguousActivity = true;
                        }

                        continue;
                    }

                    if (incident is null)
                    {
                        continue;
                    }

                    if (string.Equals(itemType, "reasoning", StringComparison.Ordinal))
                    {
                        incident.HasWorkOutput = true;
                        incident.HasReasoningOutput = true;
                    }
                    else if (ToolResponseItemTypes.Contains(itemType))
                    {
                        incident.HasWorkOutput = true;
                        incident.HasToolActivity = true;
                    }
                    else if (!IgnoredResponseItemTypes.Contains(itemType))
                    {
                        incident.HasAmbiguousActivity = true;
                    }
                }
                catch (JsonException)
                {
                    if (incident is not null)
                    {
                        incident.HasAmbiguousActivity = true;
                    }
                    else if (pendingInput is not null)
                    {
                        pendingInput = null;
                        userBoundaryAmbiguous = true;
                    }
                }
                finally
                {
                    document?.Dispose();
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DecoderFallbackException)
        {
            _ = exception;
            return LogicalIncidentSearchResult.Ambiguous;
        }

        return LogicalIncidentSearchResult.Ambiguous;
    }

    private static LocalConversationTerminalEvent ApplyLogicalIncidentEvidence(
        LocalConversationTerminalEvent terminal,
        LogicalIncidentSearchResult search)
    {
        if (!search.ReachedTarget || search.Evidence is null || search.IsAmbiguous)
        {
            return terminal with
            {
                Turn = terminal.Turn with
                {
                    HasAmbiguousActivity = terminal.Turn.HasAmbiguousActivity || search.IsAmbiguous
                }
            };
        }

        var evidence = search.Evidence;
        return terminal with
        {
            Turn = terminal.Turn with
            {
                UserText = evidence.Input.Text,
                HasAttachments = false,
                RawUserInputJson = evidence.Input.CanonicalInputJson,
                UserMessageClientIds = [evidence.ClientId],
                HasUserMessage = true,
                IsSingleTextUserInput = true,
                HasAssistantOutput = terminal.Turn.HasAssistantOutput || evidence.HasAssistantOutput,
                HasWorkOutput = terminal.Turn.HasWorkOutput || evidence.HasWorkOutput,
                HasCommentaryOutput = terminal.Turn.HasCommentaryOutput || evidence.HasCommentaryOutput,
                HasReasoningOutput = terminal.Turn.HasReasoningOutput || evidence.HasReasoningOutput,
                HasToolActivity = terminal.Turn.HasToolActivity || evidence.HasToolActivity,
                HasAmbiguousActivity = terminal.Turn.HasAmbiguousActivity || evidence.HasAmbiguousActivity
            }
        };
    }

    private static bool TryParseTerminalLine(
        string line,
        string threadId,
        string sourceFile,
        long byteOffset,
        out LocalConversationTerminalEvent? terminal)
    {
        terminal = null;
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var envelopeType = ReadString(root, "type");
            var payload = root;
            var eventType = envelopeType;
            if (string.Equals(envelopeType, "event_msg", StringComparison.Ordinal))
            {
                if (!root.TryGetProperty("payload", out payload) || payload.ValueKind != JsonValueKind.Object)
                {
                    return false;
                }

                eventType = ReadString(payload, "type");
            }

            var isTaskComplete = string.Equals(eventType, "task_complete", StringComparison.Ordinal);
            var isAbort = string.Equals(eventType, "turn_aborted", StringComparison.Ordinal);
            var isConfirmedUserAbort =
                isAbort &&
                string.Equals(ReadString(payload, "reason"), "interrupted", StringComparison.Ordinal);
            if (!isTaskComplete && !isAbort)
            {
                return false;
            }

            string? errorMessage = null;
            string? errorCode = null;
            int? httpStatusCode = null;
            var hasError = isTaskComplete &&
                           TryReadError(payload, out errorMessage, out errorCode, out httpStatusCode);

            var turnId = FirstNonEmptyString(payload, "turn_id", "turnId");
            if (string.IsNullOrWhiteSpace(turnId))
            {
                return false;
            }

            var lastAgentMessage = FirstNonEmptyString(payload, "last_agent_message", "lastAgentMessage") ?? string.Empty;
            var status = isConfirmedUserAbort
                ? "aborted"
                : isAbort
                    ? RecoveryClassifier.UnverifiedAbortStatus
                    : hasError
                        ? "failed"
                        : "completed";
            var fingerprintText = string.Join('|', turnId, status, errorMessage, lastAgentMessage);
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintText)))[..16];
            var turn = new TurnSnapshot(
                turnId,
                status,
                errorMessage,
                errorCode,
                httpStatusCode,
                UserText: string.Empty,
                HasAttachments: false,
                HasAssistantOutput: !string.IsNullOrWhiteSpace(lastAgentMessage),
                HasWorkOutput: false,
                fingerprint,
                ReadNullableLong(payload, "started_at") ?? ReadNullableLong(payload, "startedAt"),
                ReadNullableLong(payload, "completed_at") ?? ReadNullableLong(payload, "completedAt"),
                HasUserMessage: false,
                HasFinalAssistantOutput: !string.IsNullOrWhiteSpace(lastAgentMessage),
                HasCompleteItemEvidence: false);
            terminal = new LocalConversationTerminalEvent(
                threadId,
                turnId,
                sourceFile,
                byteOffset,
                ReadTimestamp(root),
                turn);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private void RefreshFileIndex()
    {
        Interlocked.Increment(ref _fileIndexRefreshCount);
        if (!Directory.Exists(_sessionsRoot))
        {
            return;
        }

        try
        {
            var indexed = Directory
                .EnumerateFiles(_sessionsRoot, "*.jsonl", SearchOption.AllDirectories)
                .SelectMany(path => ReadThreadIdsFromFileName(path)
                    .Select(threadId => (Path: path, ThreadId: threadId)))
                .GroupBy(item => item.ThreadId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            foreach (var group in indexed)
            {
                _matchingFileCache[group.Key] = group
                    .Select(item => item.Path)
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _ = exception;
        }
    }

    // Codex names a rollout `rollout-<timestamp>-<threadId>.jsonl`, but a task whose last user turn was
    // edited in place gets a fresh rollout named `rollout-<timestamp>-<threadId>_<sessionId>.jsonl`. The
    // thread id stays first; the trailing id is that file's own session id. Reading only the trailing 36
    // characters indexed those files under an id no observed task ever reports, so the local terminal for
    // an in-place retry was invisible and recovery stalled on "no confirmed local terminal" forever. Both
    // ids are indexed: whichever one an observation reports, the file is found.
    private static IReadOnlyList<string> ReadThreadIdsFromFileName(string path)
    {
        var fileName = Path.GetFileName(path);
        const int threadIdLength = 36;
        const string extension = ".jsonl";
        if (!fileName.StartsWith("rollout-", StringComparison.OrdinalIgnoreCase) ||
            !fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase) ||
            fileName.Length < threadIdLength + extension.Length)
        {
            return [];
        }

        var stem = fileName[..^extension.Length];
        var ids = new List<string>(2);
        foreach (var segment in stem.Split('_', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment.Length < threadIdLength)
            {
                continue;
            }

            var candidate = segment[^threadIdLength..];
            if (Guid.TryParse(candidate, out _) &&
                !ids.Contains(candidate, StringComparer.OrdinalIgnoreCase))
            {
                ids.Add(candidate);
            }
        }

        return ids;
    }

    private static bool TryReadError(
        JsonElement payload,
        out string? errorMessage,
        out string? errorCode,
        out int? httpStatusCode)
    {
        errorMessage = null;
        errorCode = null;
        httpStatusCode = null;

        if (!payload.TryGetProperty("error", out var error) ||
            error.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return false;
        }

        if (error.ValueKind == JsonValueKind.String)
        {
            errorMessage = error.GetString();
        }
        else if (error.ValueKind == JsonValueKind.Object)
        {
            errorMessage = FirstNonEmptyString(error, "message", "error", "description");
            errorCode = FirstNonEmptyString(error, "codex_error_info", "codexErrorInfo", "code", "error_code", "errorCode", "type");
            httpStatusCode = FirstHttpStatus(error, "http_status_code", "httpStatusCode", "status", "status_code");
        }
        else
        {
            errorMessage = error.ToString();
        }

        errorMessage ??= FirstNonEmptyString(payload, "error_message", "errorMessage");
        errorCode ??= FirstNonEmptyString(payload, "codex_error_info", "codexErrorInfo", "error_code", "errorCode");
        httpStatusCode ??= FirstHttpStatus(payload, "http_status_code", "httpStatusCode", "status", "status_code");
        httpStatusCode ??= ParseHttpStatus(errorMessage);

        return !string.IsNullOrWhiteSpace(errorMessage) || !string.IsNullOrWhiteSpace(errorCode) || httpStatusCode is not null;
    }

    private static DateTimeOffset? ReadTimestamp(JsonElement root)
    {
        var value = ReadString(root, "timestamp");
        return DateTimeOffset.TryParse(value, out var timestamp) ? timestamp : null;
    }

    private static string ReadString(JsonElement item, string propertyName) =>
        item.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static string? FirstNonEmptyString(JsonElement item, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            if (!item.TryGetProperty(propertyName, out var value) ||
                value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            {
                continue;
            }

            var text = value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
            if (!string.IsNullOrWhiteSpace(text))
            {
                return text;
            }
        }

        return null;
    }

    private static long? ReadNullableLong(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number))
        {
            return number;
        }

        return value.ValueKind == JsonValueKind.String && long.TryParse(value.GetString(), out number)
            ? number
            : null;
    }

    private static int? FirstHttpStatus(JsonElement item, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            var value = ReadNullableLong(item, propertyName);
            if (value is >= 400 and <= 599)
            {
                return (int)value.Value;
            }
        }

        return null;
    }

    private static int? ParseHttpStatus(string? errorMessage)
    {
        if (string.IsNullOrWhiteSpace(errorMessage))
        {
            return null;
        }

        var match = HttpStatusPattern.Match(errorMessage);
        return match.Success && int.TryParse(match.Groups["status"].Value, out var statusCode)
            ? statusCode
            : null;
    }

    private static void ValidateThreadId(string threadId)
    {
        if (string.IsNullOrWhiteSpace(threadId))
        {
            throw new ArgumentException("A Codex thread id is required.", nameof(threadId));
        }

        if (threadId.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            threadId.Contains(Path.DirectorySeparatorChar) ||
            threadId.Contains(Path.AltDirectorySeparatorChar))
        {
            throw new ArgumentException("The Codex thread id contains an invalid file name character.", nameof(threadId));
        }
    }

    private sealed record TailCacheEntry(
        long Length,
        DateTime LastWriteTimeUtc,
        LocalConversationTerminalEvent? Terminal);

    private sealed record RolloutUserInputEvidence(string Text, string CanonicalInputJson);

    private sealed record LocalUserInputSearchResult(
        RolloutUserInputEvidence? Evidence,
        bool NeedsEarlierBytes,
        bool IsAmbiguous = false);

    private sealed record PendingRolloutUserInput(
        string TurnId,
        RolloutUserInputEvidence Evidence);

    private sealed record LogicalIncidentEvidence(
        RolloutUserInputEvidence Input,
        string ClientId,
        bool HasAssistantOutput,
        bool HasWorkOutput,
        bool HasCommentaryOutput,
        bool HasReasoningOutput,
        bool HasToolActivity,
        bool HasAmbiguousActivity);

    private sealed record LogicalIncidentSearchResult(
        LogicalIncidentEvidence? Evidence,
        bool IsAmbiguous,
        bool ReachedTarget)
    {
        internal static LogicalIncidentSearchResult Ambiguous { get; } =
            new(null, IsAmbiguous: true, ReachedTarget: false);
    }

    private sealed class LogicalIncidentState(
        RolloutUserInputEvidence input,
        string clientId)
    {
        internal RolloutUserInputEvidence Input { get; } = input;

        internal string ClientId { get; } = clientId;

        internal bool HasAssistantOutput { get; set; }

        internal bool HasWorkOutput { get; set; }

        internal bool HasCommentaryOutput { get; set; }

        internal bool HasReasoningOutput { get; set; }

        internal bool HasToolActivity { get; set; }

        internal bool HasAmbiguousActivity { get; set; }

        internal void ResetWork()
        {
            HasAssistantOutput = false;
            HasWorkOutput = false;
            HasCommentaryOutput = false;
            HasReasoningOutput = false;
            HasToolActivity = false;
            HasAmbiguousActivity = false;
        }

        internal LogicalIncidentEvidence ToEvidence() => new(
            Input,
            ClientId,
            HasAssistantOutput,
            HasWorkOutput,
            HasCommentaryOutput,
            HasReasoningOutput,
            HasToolActivity,
            HasAmbiguousActivity);
    }

    private enum RolloutUserInputKind
    {
        InjectedContext,
        ReplayableText,
        Ambiguous
    }

    private sealed record ParsedRolloutUserInput(
        RolloutUserInputKind Kind,
        RolloutUserInputEvidence? Evidence)
    {
        internal static ParsedRolloutUserInput InjectedContext { get; } =
            new(RolloutUserInputKind.InjectedContext, null);

        internal static ParsedRolloutUserInput Ambiguous { get; } =
            new(RolloutUserInputKind.Ambiguous, null);
    }
}
