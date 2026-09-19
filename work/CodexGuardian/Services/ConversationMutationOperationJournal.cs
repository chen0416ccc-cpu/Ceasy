using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CodexGuardian.Services;

internal enum ConversationMutationKind
{
    Unarchive,
    Delete
}

internal enum ConversationMutationOperationState
{
    Prepared,
    Committing,
    Retryable,
    Uncertain,
    Confirmed,
    Abandoned
}

internal enum ConversationMutationJournalReadStatus
{
    Missing,
    Healthy,
    RecoveredFromBackup,
    Corrupted,
    UnsupportedSchema
}

internal sealed record ConversationMutationOperationRecord(
    string OperationId,
    string ThreadId,
    ConversationMutationKind Kind,
    long ExpectedUpdatedAt,
    string ExpectedLatestTurnId,
    string OwnerHostId,
    string OwnerClientId,
    long OwnerRevision,
    ConversationMutationOperationState State,
    string? ReceiptId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    int AttemptCount);

internal sealed record ConversationMutationJournalSnapshot(
    ConversationMutationJournalReadStatus ReadStatus,
    long Generation,
    bool RequiresConservativeRecovery,
    IReadOnlyList<ConversationMutationOperationRecord> Records);

internal sealed record ConversationMutationJournalPrepareResult(
    ConversationMutationOperationRecord Record,
    bool Created,
    bool RequiresReconciliation);

internal sealed record ConversationMutationJournalTransitionResult(
    bool Changed,
    ConversationMutationOperationRecord? Record,
    long Generation);

internal sealed class ConversationMutationOperationJournal
{
    internal const int CurrentSchemaVersion = 1;
    internal const int DefaultMaximumRecords = 1024;
    internal const long DefaultMaximumFileBytes = 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly int _maximumRecords;
    private readonly long _maximumFileBytes;
    private readonly List<ConversationMutationOperationRecord> _records = [];
    private bool _loaded;
    private bool _requiresConservativeRecovery;
    private bool _unsupportedSchema;
    private long _generation;
    private ConversationMutationJournalReadStatus _readStatus =
        ConversationMutationJournalReadStatus.Missing;

    internal ConversationMutationOperationJournal(
        string dataDirectory,
        int maximumRecords = DefaultMaximumRecords,
        long maximumFileBytes = DefaultMaximumFileBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        if (maximumRecords < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        if (maximumFileBytes < 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFileBytes));
        }

        DataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        JournalPath = Path.Combine(DataDirectory, "conversation-mutations.json");
        BackupPath = Path.Combine(DataDirectory, "conversation-mutations.previous.json");
        InitializationMarkerPath = Path.Combine(DataDirectory, "conversation-mutations.initialized");
        _maximumRecords = maximumRecords;
        _maximumFileBytes = maximumFileBytes;
    }

    internal string DataDirectory { get; }

    internal string JournalPath { get; }

    internal string BackupPath { get; }

    internal string InitializationMarkerPath { get; }

    internal async Task<ConversationMutationJournalSnapshot> ReadAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return CreateSnapshot();
        }
        finally
        {
            _gate.Release();
        }
    }

    internal async Task<ConversationMutationOperationRecord?> FindLatestAsync(
        string threadId,
        ConversationMutationKind kind,
        CancellationToken cancellationToken = default)
    {
        threadId = NormalizeUuid(threadId, nameof(threadId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return _records
                .Where(record =>
                    record.Kind == kind &&
                    string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(static record => record.UpdatedAt)
                .FirstOrDefault();
        }
        finally
        {
            _gate.Release();
        }
    }

    internal async Task<ConversationMutationJournalPrepareResult> GetOrCreateAsync(
        ConversationMutationOperationRecord requested,
        CancellationToken cancellationToken = default)
    {
        requested = NormalizeRequested(requested);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();

            var existingIndex = FindIndex(requested.OperationId);
            if (existingIndex >= 0)
            {
                var existing = _records[existingIndex];
                EnsureSameIdentity(existing, requested);
                return new(
                    existing,
                    Created: false,
                    RequiresReconciliation: existing.State is
                        ConversationMutationOperationState.Committing or
                        ConversationMutationOperationState.Uncertain);
            }

            var blocking = _records
                .Select((record, index) => (record, index))
                .Where(candidate =>
                    candidate.record.Kind == requested.Kind &&
                    string.Equals(
                        candidate.record.ThreadId,
                        requested.ThreadId,
                        StringComparison.OrdinalIgnoreCase) &&
                    candidate.record.State is not ConversationMutationOperationState.Confirmed and not
                        ConversationMutationOperationState.Abandoned)
                .ToArray();
            if (blocking.Any(candidate => candidate.record.State is
                    ConversationMutationOperationState.Committing or
                    ConversationMutationOperationState.Uncertain))
            {
                throw new InvalidOperationException(
                    "A prior conversation mutation may have committed and must be reconciled first.");
            }

            var now = DateTimeOffset.UtcNow;
            var record = requested with
            {
                State = _requiresConservativeRecovery
                    ? ConversationMutationOperationState.Uncertain
                    : ConversationMutationOperationState.Prepared,
                ReceiptId = null,
                CreatedAt = now,
                UpdatedAt = now,
                AttemptCount = 0
            };
            var candidate = new List<ConversationMutationOperationRecord>(_records);
            foreach (var stale in blocking)
            {
                candidate[stale.index] = stale.record with
                {
                    State = ConversationMutationOperationState.Abandoned,
                    UpdatedAt = now
                };
            }

            candidate.Add(record);
            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return new(
                record,
                Created: true,
                RequiresReconciliation: record.State == ConversationMutationOperationState.Uncertain);
        }
        finally
        {
            _gate.Release();
        }
    }

    internal async Task<ConversationMutationJournalTransitionResult> TryTransitionAsync(
        string operationId,
        ConversationMutationOperationState expectedState,
        ConversationMutationOperationState nextState,
        string? receiptId = null,
        CancellationToken cancellationToken = default)
    {
        operationId = NormalizeUuid(operationId, nameof(operationId));
        receiptId = NormalizeOptionalBounded(receiptId, nameof(receiptId), 256);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var index = FindIndex(operationId);
            if (index < 0 || _records[index].State != expectedState)
            {
                return new(false, index < 0 ? null : _records[index], _generation);
            }

            var current = _records[index];
            ValidateTransition(current.State, nextState);
            if (current.ReceiptId is not null && receiptId is not null &&
                !string.Equals(current.ReceiptId, receiptId, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "A persisted mutation receipt cannot be changed.",
                    nameof(receiptId));
            }

            var updated = current with
            {
                State = nextState,
                ReceiptId = current.ReceiptId ?? receiptId,
                UpdatedAt = DateTimeOffset.UtcNow,
                AttemptCount = nextState == ConversationMutationOperationState.Committing
                    ? checked(current.AttemptCount + 1)
                    : current.AttemptCount
            };
            var candidate = new List<ConversationMutationOperationRecord>(_records);
            candidate[index] = updated;
            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return new(true, updated, _generation);
        }
        finally
        {
            _gate.Release();
        }
    }

    internal static string CreateOperationId(
        string threadId,
        ConversationMutationKind kind,
        long expectedUpdatedAt,
        string expectedLatestTurnId,
        string ownerHostId,
        string ownerClientId,
        long ownerRevision)
    {
        threadId = NormalizeUuid(threadId, nameof(threadId));
        expectedLatestTurnId = NormalizeUuid(expectedLatestTurnId, nameof(expectedLatestTurnId));
        ownerHostId = NormalizeBounded(ownerHostId, nameof(ownerHostId), 128);
        ownerClientId = NormalizeBounded(ownerClientId, nameof(ownerClientId), 256);
        if (expectedUpdatedAt < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedUpdatedAt));
        }

        if (ownerRevision < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ownerRevision));
        }

        var value = string.Join(
            '|',
            "codexfree-conversation-mutation-v1",
            threadId,
            kind.ToString(),
            expectedUpdatedAt.ToString(System.Globalization.CultureInfo.InvariantCulture),
            expectedLatestTurnId,
            ownerHostId,
            ownerClientId,
            ownerRevision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value))[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes).ToString("D");
    }

    private async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_loaded)
        {
            return;
        }

        _loaded = true;
        DataDirectorySafety.Revalidate(DataDirectory);
        CleanupTemporaryFiles();
        try
        {
            var primary = await TryReadDocumentAsync(JournalPath, cancellationToken).ConfigureAwait(false);
            if (primary.Status == ConversationMutationJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (primary.Status == ConversationMutationJournalReadStatus.Healthy)
            {
                LoadDocument(
                    primary.Document!,
                    ConversationMutationJournalReadStatus.Healthy,
                    promoteAllPending: false);
                return;
            }

            var backup = await TryReadDocumentAsync(BackupPath, cancellationToken).ConfigureAwait(false);
            if (backup.Status == ConversationMutationJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (backup.Status == ConversationMutationJournalReadStatus.Healthy)
            {
                LoadDocument(
                    backup.Document!,
                    ConversationMutationJournalReadStatus.RecoveredFromBackup,
                    promoteAllPending: true);
                return;
            }

            if (primary.Status == ConversationMutationJournalReadStatus.Missing &&
                backup.Status == ConversationMutationJournalReadStatus.Missing &&
                !File.Exists(InitializationMarkerPath))
            {
                _readStatus = ConversationMutationJournalReadStatus.Missing;
                return;
            }

            MarkCorrupted();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _loaded = false;
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            MarkCorrupted();
        }
    }

    private async Task<JournalLoadResult> TryReadDocumentAsync(
        string path,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (!File.Exists(path))
        {
            return new(ConversationMutationJournalReadStatus.Missing, null);
        }

        try
        {
            var file = new FileInfo(path);
            if (file.Length <= 0 || file.Length > _maximumFileBytes)
            {
                return new(ConversationMutationJournalReadStatus.Corrupted, null);
            }

            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (json.RootElement.ValueKind != JsonValueKind.Object ||
                !json.RootElement.TryGetProperty("schemaVersion", out var schemaElement) ||
                schemaElement.ValueKind != JsonValueKind.Number ||
                !schemaElement.TryGetInt32(out var schemaVersion))
            {
                return new(ConversationMutationJournalReadStatus.Corrupted, null);
            }

            if (schemaVersion != CurrentSchemaVersion)
            {
                return new(ConversationMutationJournalReadStatus.UnsupportedSchema, null);
            }

            var document = json.RootElement.Deserialize<JournalDocument>(JsonOptions);
            return document is not null && ValidateDocument(document)
                ? new(ConversationMutationJournalReadStatus.Healthy, document)
                : new(ConversationMutationJournalReadStatus.Corrupted, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new(ConversationMutationJournalReadStatus.Corrupted, null);
        }
    }

    private void LoadDocument(
        JournalDocument document,
        ConversationMutationJournalReadStatus status,
        bool promoteAllPending)
    {
        var now = DateTimeOffset.UtcNow;
        var promoted = false;
        var records = document.Records!.Select(record =>
        {
            var shouldPromote = record.State == ConversationMutationOperationState.Committing ||
                                promoteAllPending && record.State is
                                    ConversationMutationOperationState.Prepared or
                                    ConversationMutationOperationState.Retryable;
            if (!shouldPromote)
            {
                return record;
            }

            promoted = true;
            return record with
            {
                State = ConversationMutationOperationState.Uncertain,
                UpdatedAt = now
            };
        }).ToArray();

        _records.AddRange(records);
        _generation = document.Generation;
        _requiresConservativeRecovery = document.RequiresConservativeRecovery || promoted;
        _readStatus = status;
    }

    private bool ValidateDocument(JournalDocument document)
    {
        if (document.Generation < 0 || document.Records is null ||
            document.Records.Count > _maximumRecords || string.IsNullOrWhiteSpace(document.Checksum))
        {
            return false;
        }

        var operationIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in document.Records)
        {
            if (!ValidateRecord(record) || !operationIds.Add(record.OperationId))
            {
                return false;
            }
        }

        var expected = ComputeChecksum(
            document.SchemaVersion,
            document.Generation,
            document.RequiresConservativeRecovery,
            document.Records);
        return IsSha256(document.Checksum) && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(document.Checksum));
    }

    private async Task<PersistedCandidate> PersistCandidateAsync(
        List<ConversationMutationOperationRecord> candidate,
        CancellationToken cancellationToken)
    {
        var nextGeneration = checked(_generation + 1);
        PruneTerminalRecords(candidate);
        byte[] bytes;
        while (true)
        {
            bytes = SerializeDocument(nextGeneration, candidate);
            if (bytes.LongLength <= _maximumFileBytes)
            {
                break;
            }

            var terminalIndex = FindOldestTerminalIndex(candidate);
            if (terminalIndex < 0)
            {
                throw new InvalidOperationException(
                    "The conversation mutation journal exceeds its durable disk limit.");
            }

            candidate.RemoveAt(terminalIndex);
        }

        DataDirectorySafety.Revalidate(DataDirectory);
        Directory.CreateDirectory(DataDirectory);
        DataDirectorySafety.Revalidate(DataDirectory);
        EnsureInitializationMarker();
        var tempPath = Path.Combine(
            DataDirectory,
            $".{Path.GetFileName(JournalPath)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        try
        {
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            await using (var stream = new FileStream(
                             tempPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, JournalPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, BackupPath);
            if (File.Exists(JournalPath))
            {
                File.Replace(
                    tempPath,
                    JournalPath,
                    _readStatus == ConversationMutationJournalReadStatus.Healthy ? BackupPath : null,
                    ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, JournalPath);
            }

            return new(candidate, nextGeneration);
        }
        finally
        {
            TryDeleteTemporaryFile(tempPath);
        }
    }

    private byte[] SerializeDocument(
        long generation,
        IReadOnlyList<ConversationMutationOperationRecord> records)
    {
        var checksum = ComputeChecksum(
            CurrentSchemaVersion,
            generation,
            _requiresConservativeRecovery,
            records);
        return JsonSerializer.SerializeToUtf8Bytes(
            new JournalDocument(
                CurrentSchemaVersion,
                generation,
                _requiresConservativeRecovery,
                checksum,
                records.ToList()),
            JsonOptions);
    }

    private void EnsureInitializationMarker()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, InitializationMarkerPath);
        if (File.Exists(InitializationMarkerPath))
        {
            return;
        }

        var tempPath = Path.Combine(
            DataDirectory,
            $".{Path.GetFileName(InitializationMarkerPath)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        try
        {
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            using (var stream = new FileStream(
                       tempPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       128,
                       FileOptions.WriteThrough))
            {
                stream.Write("schema=1\n"u8);
                stream.Flush(flushToDisk: true);
            }

            try
            {
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, InitializationMarkerPath);
                File.Move(tempPath, InitializationMarkerPath);
            }
            catch (IOException) when (File.Exists(InitializationMarkerPath))
            {
            }
        }
        finally
        {
            TryDeleteTemporaryFile(tempPath);
        }
    }

    private void CleanupTemporaryFiles()
    {
        if (!Directory.Exists(DataDirectory))
        {
            return;
        }

        try
        {
            foreach (var pattern in new[]
                     {
                         $".{Path.GetFileName(JournalPath)}.*.tmp",
                         $".{Path.GetFileName(InitializationMarkerPath)}.*.tmp"
                     })
            {
                foreach (var path in Directory.EnumerateFiles(
                             DataDirectory,
                             pattern,
                             SearchOption.TopDirectoryOnly))
                {
                    TryDeleteTemporaryFile(path);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private void TryDeleteTemporaryFile(string path)
    {
        try
        {
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static ConversationMutationOperationRecord NormalizeRequested(
        ConversationMutationOperationRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!Enum.IsDefined(record.Kind))
        {
            throw new ArgumentOutOfRangeException(nameof(record));
        }

        if (record.ExpectedUpdatedAt < 0 || record.OwnerRevision < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(record));
        }

        return record with
        {
            OperationId = NormalizeUuid(record.OperationId, nameof(record.OperationId)),
            ThreadId = NormalizeUuid(record.ThreadId, nameof(record.ThreadId)),
            ExpectedLatestTurnId = NormalizeUuid(
                record.ExpectedLatestTurnId,
                nameof(record.ExpectedLatestTurnId)),
            OwnerHostId = NormalizeBounded(record.OwnerHostId, nameof(record.OwnerHostId), 128),
            OwnerClientId = NormalizeBounded(record.OwnerClientId, nameof(record.OwnerClientId), 256),
            ReceiptId = NormalizeOptionalBounded(record.ReceiptId, nameof(record.ReceiptId), 256)
        };
    }

    private static bool ValidateRecord(ConversationMutationOperationRecord record)
    {
        try
        {
            var normalized = NormalizeRequested(record);
            return normalized == record &&
                   record.AttemptCount >= 0 &&
                   record.CreatedAt <= record.UpdatedAt &&
                   Enum.IsDefined(record.State);
        }
        catch (Exception exception) when (
            exception is ArgumentException or ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static void EnsureSameIdentity(
        ConversationMutationOperationRecord existing,
        ConversationMutationOperationRecord requested)
    {
        if (!string.Equals(existing.ThreadId, requested.ThreadId, StringComparison.OrdinalIgnoreCase) ||
            existing.Kind != requested.Kind ||
            existing.ExpectedUpdatedAt != requested.ExpectedUpdatedAt ||
            !string.Equals(
                existing.ExpectedLatestTurnId,
                requested.ExpectedLatestTurnId,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.OwnerHostId, requested.OwnerHostId, StringComparison.Ordinal) ||
            !string.Equals(existing.OwnerClientId, requested.OwnerClientId, StringComparison.Ordinal) ||
            existing.OwnerRevision != requested.OwnerRevision)
        {
            throw new InvalidOperationException(
                "The conversation mutation operation id belongs to a different authority boundary.");
        }
    }

    private static void ValidateTransition(
        ConversationMutationOperationState current,
        ConversationMutationOperationState next)
    {
        if (current == next)
        {
            throw new InvalidOperationException("A conversation mutation transition must change state.");
        }

        var allowed = current switch
        {
            ConversationMutationOperationState.Prepared =>
                next is ConversationMutationOperationState.Committing or
                    ConversationMutationOperationState.Abandoned,
            ConversationMutationOperationState.Committing =>
                next is ConversationMutationOperationState.Retryable or
                    ConversationMutationOperationState.Uncertain or
                    ConversationMutationOperationState.Confirmed or
                    ConversationMutationOperationState.Abandoned,
            ConversationMutationOperationState.Retryable =>
                next is ConversationMutationOperationState.Committing or
                    ConversationMutationOperationState.Abandoned,
            ConversationMutationOperationState.Uncertain =>
                next is ConversationMutationOperationState.Confirmed or
                    ConversationMutationOperationState.Abandoned,
            _ => false
        };
        if (!allowed)
        {
            throw new InvalidOperationException($"Invalid conversation mutation transition: {current} -> {next}.");
        }
    }

    private static string ComputeChecksum(
        int schemaVersion,
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<ConversationMutationOperationRecord> records)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new JournalIntegrityPayload(
                schemaVersion,
                generation,
                requiresConservativeRecovery,
                records),
            JsonOptions);
        return Convert.ToHexString(SHA256.HashData(payload));
    }

    private void PruneTerminalRecords(List<ConversationMutationOperationRecord> candidate)
    {
        while (candidate.Count > _maximumRecords)
        {
            var index = FindOldestTerminalIndex(candidate);
            if (index < 0)
            {
                throw new InvalidOperationException(
                    "The conversation mutation journal has too many non-terminal operations.");
            }

            candidate.RemoveAt(index);
        }
    }

    private static int FindOldestTerminalIndex(
        IReadOnlyList<ConversationMutationOperationRecord> records)
    {
        var selected = -1;
        for (var index = 0; index < records.Count; index++)
        {
            if (records[index].State is not ConversationMutationOperationState.Confirmed and not
                ConversationMutationOperationState.Abandoned)
            {
                continue;
            }

            if (selected < 0 || records[index].UpdatedAt < records[selected].UpdatedAt)
            {
                selected = index;
            }
        }

        return selected;
    }

    private int FindIndex(string operationId)
    {
        for (var index = 0; index < _records.Count; index++)
        {
            if (string.Equals(
                    _records[index].OperationId,
                    operationId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return -1;
    }

    private ConversationMutationJournalSnapshot CreateSnapshot() => new(
        _readStatus,
        _generation,
        _requiresConservativeRecovery,
        _records.ToArray());

    private void Commit(PersistedCandidate persisted)
    {
        _records.Clear();
        _records.AddRange(persisted.Records);
        _generation = persisted.Generation;
        _readStatus = ConversationMutationJournalReadStatus.Healthy;
    }

    private void MarkCorrupted()
    {
        _records.Clear();
        _requiresConservativeRecovery = true;
        _readStatus = ConversationMutationJournalReadStatus.Corrupted;
    }

    private void MarkUnsupportedSchema()
    {
        _records.Clear();
        _requiresConservativeRecovery = true;
        _unsupportedSchema = true;
        _readStatus = ConversationMutationJournalReadStatus.UnsupportedSchema;
    }

    private void ThrowIfUnsupportedSchema()
    {
        if (_unsupportedSchema)
        {
            throw new NotSupportedException(
                "The conversation mutation journal schema is newer than this Ceasy build.");
        }
    }

    private static string NormalizeUuid(string value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed))
        {
            throw new ArgumentException("A UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private static string NormalizeBounded(string value, string parameterName, int maximumLength)
    {
        value = value?.Trim() ?? string.Empty;
        if (value.Length == 0 || value.Length > maximumLength ||
            value.Any(static character => char.IsControl(character)))
        {
            throw new ArgumentException("A bounded non-empty identifier is required.", parameterName);
        }

        return value;
    }

    private static string? NormalizeOptionalBounded(
        string? value,
        string parameterName,
        int maximumLength) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : NormalizeBounded(value, parameterName, maximumLength);

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(static character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private sealed record PersistedCandidate(
        List<ConversationMutationOperationRecord> Records,
        long Generation);

    private sealed record JournalLoadResult(
        ConversationMutationJournalReadStatus Status,
        JournalDocument? Document);

    private sealed record JournalDocument(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        List<ConversationMutationOperationRecord>? Records);

    private sealed record JournalIntegrityPayload(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<ConversationMutationOperationRecord> Records);
}
