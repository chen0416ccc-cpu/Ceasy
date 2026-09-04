using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodexGuardian.Models;

namespace CodexGuardian.Services;

public enum RecoveryOperationState
{
    Prepared,
    Dispatching,
    Retryable,
    Uncertain,
    Accepted,
    Confirmed,
    Abandoned
}

public enum RecoveryJournalReadStatus
{
    Missing,
    Healthy,
    RecoveredFromBackup,
    Corrupted,
    UnsupportedSchema
}

public sealed record RecoveryOperationRecord(
    string OperationId,
    string ThreadId,
    string FailedTurnId,
    RecoveryActionKind Action,
    string InputHash,
    RecoveryOperationState State,
    string? ClientMessageId,
    string? NewTurnId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    int AttemptCount,
    string? IncidentId = null,
    string? RootFailedTurnId = null,
    string? ParentOperationId = null,
    RecoveryCountingMode CountingMode = RecoveryCountingMode.OriginalFailedTurnOnly,
    int MaximumAttempts = 1,
    bool UnlimitedAttempts = false,
    long PolicyVersion = 0,
    string? FailureSignature = null,
    int NoProgressCount = 0);

public sealed record RecoveryIncidentPolicy(
    string IncidentId,
    string RootFailedTurnId,
    string? ParentOperationId,
    RecoveryCountingMode CountingMode,
    int MaximumAttempts,
    bool UnlimitedAttempts,
    long PolicyVersion,
    string FailureSignature,
    int NoProgressCount)
{
    public static RecoveryIncidentPolicy CreateNew(
        string failedTurnId,
        RecoveryCountingMode countingMode,
        int maximumAttempts,
        bool unlimitedAttempts,
        long policyVersion,
        string failureSignature) =>
        new(
            Guid.NewGuid().ToString("D"),
            failedTurnId,
            ParentOperationId: null,
            countingMode,
            maximumAttempts,
            unlimitedAttempts,
            policyVersion,
            failureSignature,
            NoProgressCount: 0);
}

public sealed record RecoveryJournalSnapshot(
    RecoveryJournalReadStatus ReadStatus,
    long Generation,
    bool RequiresConservativeRecovery,
    IReadOnlyList<RecoveryOperationRecord> Records);

public sealed record RecoveryJournalPrepareResult(
    RecoveryOperationRecord Record,
    bool Created,
    bool RequiresReconciliation);

public sealed record RecoveryJournalTransitionResult(
    bool Changed,
    RecoveryOperationRecord? Record,
    long Generation);

public sealed record RecoveryCurrentTurnReconciliation(
    RecoveryOperationRecord? RecoverySuccessor,
    bool IsExactSuccessorMatch,
    bool RecoverySuccessorClosed,
    int AbandonedCount);

public sealed class RecoveryOperationJournal
{
    internal const int CurrentSchemaVersion = 2;
    internal const int LegacySchemaVersion = 1;
    internal const int DefaultMaximumRecords = 256;
    internal const long DefaultMaximumFileBytes = 256 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly int _maximumRecords;
    private readonly long _maximumFileBytes;
    private readonly List<RecoveryOperationRecord> _records = new();
    private bool _loaded;
    private bool _requiresConservativeRecovery;
    private bool _unsupportedSchema;
    private long _generation;
    private RecoveryJournalReadStatus _readStatus = RecoveryJournalReadStatus.Missing;

    public RecoveryOperationJournal(
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
        JournalPath = Path.Combine(DataDirectory, "recovery-operations.json");
        BackupPath = Path.Combine(DataDirectory, "recovery-operations.previous.json");
        InitializationMarkerPath = Path.Combine(DataDirectory, "recovery-operations.initialized");
        _maximumRecords = maximumRecords;
        _maximumFileBytes = maximumFileBytes;
    }

    public string DataDirectory { get; }

    public string JournalPath { get; }

    public string BackupPath { get; }

    public string InitializationMarkerPath { get; }

    public static string ComputeInputHash(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }

    public async Task<RecoveryJournalSnapshot> ReadAsync(
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

    public async Task<IReadOnlyList<RecoveryOperationRecord>> ReadIncidentAsync(
        string incidentId,
        CancellationToken cancellationToken = default)
    {
        incidentId = NormalizeRequiredId(incidentId, nameof(incidentId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return _records
                .Where(record => string.Equals(
                    record.IncidentId,
                    incidentId,
                    StringComparison.OrdinalIgnoreCase))
                .OrderBy(record => record.CreatedAt)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RecoveryOperationRecord?> FindAsync(
        string threadId,
        string failedTurnId,
        CancellationToken cancellationToken = default)
    {
        var key = NormalizeKey(threadId, failedTurnId);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return FindCore(key.ThreadId, key.FailedTurnId);
        }
        finally
        {
            _gate.Release();
        }
    }

    // A record keeps its `NewTurnId` after it is abandoned, because abandonment only means the
    // failed turn it targeted is no longer current — not that the dispatch never happened. Counting
    // records that carry a successor turn is therefore the durable answer to "has Guardian ever
    // actually resent this task", which no in-memory attempt counter can survive a restart to give.
    public async Task<GuardianRecoveryLedger> ReadThreadLedgerAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        threadId = NormalizeRequiredId(threadId, nameof(threadId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            var confirmed = 0;
            DateTimeOffset? lastConfirmedAt = null;
            foreach (var record in _records)
            {
                if (!string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) ||
                    string.IsNullOrWhiteSpace(record.NewTurnId))
                {
                    continue;
                }

                confirmed++;
                if (lastConfirmedAt is null || record.UpdatedAt > lastConfirmedAt)
                {
                    lastConfirmedAt = record.UpdatedAt;
                }
            }

            return new GuardianRecoveryLedger(confirmed, lastConfirmedAt);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RecoveryCurrentTurnReconciliation> ReconcileCurrentTurnAsync(
        string threadId,
        string currentTurnId,
        IReadOnlyCollection<string>? currentTurnClientMessageIds,
        bool closeRecoverySuccessor,
        CancellationToken cancellationToken = default)
    {
        threadId = NormalizeRequiredId(threadId, nameof(threadId));
        currentTurnId = NormalizeRequiredId(currentTurnId, nameof(currentTurnId));
        var normalizedClientMessageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (currentTurnClientMessageIds is not null)
        {
            foreach (var value in currentTurnClientMessageIds)
            {
                if (Guid.TryParse(value, out var parsed))
                {
                    normalizedClientMessageIds.Add(parsed.ToString("D"));
                }
            }
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();

            var exactMatches = _records
                .Where(record =>
                    string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(record.FailedTurnId, currentTurnId, StringComparison.OrdinalIgnoreCase) &&
                    !IsClosedForLineage(record.State) &&
                    (string.Equals(record.NewTurnId, currentTurnId, StringComparison.OrdinalIgnoreCase) ||
                     record.ClientMessageId is not null &&
                     normalizedClientMessageIds.Contains(record.ClientMessageId)))
                .ToArray();
            if (exactMatches.Length > 1)
            {
                throw new InvalidOperationException(
                    "The current turn matches more than one durable recovery operation.");
            }

            var recoverySuccessor = exactMatches.SingleOrDefault();
            var isExactSuccessorMatch = recoverySuccessor is not null;
            recoverySuccessor ??= _records
                .Where(record =>
                    string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(record.FailedTurnId, currentTurnId, StringComparison.OrdinalIgnoreCase) &&
                    !IsPrunable(record.State) &&
                    record.State is RecoveryOperationState.Dispatching or
                        RecoveryOperationState.Uncertain or RecoveryOperationState.Accepted)
                .OrderByDescending(record => record.UpdatedAt)
                .FirstOrDefault();

            if (recoverySuccessor is not null && !closeRecoverySuccessor)
            {
                return new(
                    recoverySuccessor,
                    isExactSuccessorMatch,
                    RecoverySuccessorClosed: false,
                    AbandonedCount: 0);
            }

            // This loop is the one place a lineage is deliberately closed, so it asks the lineage question
            // and not the pruning one: a Confirmed record is a tombstone that stays visible until either
            // its successor turn proves the recovery landed or an unrelated later failure supersedes it,
            // and both of those arrive here. Skipping it as prunable left the tombstone Confirmed forever,
            // so a thread accumulated one per successful recovery and every one of them kept answering
            // successor queries for turns it had nothing to do with.
            var changed = 0;
            var now = DateTimeOffset.UtcNow;
            var candidate = new List<RecoveryOperationRecord>(_records);
            for (var index = 0; index < candidate.Count; index++)
            {
                var record = candidate[index];
                if (!string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(record.FailedTurnId, currentTurnId, StringComparison.OrdinalIgnoreCase) ||
                    IsClosedForLineage(record.State))
                {
                    continue;
                }

                candidate[index] = record with
                {
                    State = RecoveryOperationState.Abandoned,
                    UpdatedAt = now
                };
                changed++;
            }

            if (changed > 0)
            {
                var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
                Commit(persisted);
            }

            return new(
                recoverySuccessor,
                isExactSuccessorMatch,
                RecoverySuccessorClosed: recoverySuccessor is not null && closeRecoverySuccessor,
                AbandonedCount: changed);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<int> AbandonSupersededAsync(
        string threadId,
        string currentTurnId,
        CancellationToken cancellationToken = default)
    {
        threadId = NormalizeRequiredId(threadId, nameof(threadId));
        currentTurnId = NormalizeRequiredId(currentTurnId, nameof(currentTurnId));
        return AbandonPendingCoreAsync(
            threadId,
            record => !string.Equals(
                record.FailedTurnId,
                currentTurnId,
                StringComparison.OrdinalIgnoreCase),
            cancellationToken);
    }

    public async Task<RecoveryJournalPrepareResult> GetOrCreateAsync(
        string operationId,
        string threadId,
        string failedTurnId,
        RecoveryActionKind action,
        string inputHash,
        string? clientMessageId = null,
        CancellationToken cancellationToken = default)
    {
        var conservativePolicy = new RecoveryIncidentPolicy(
            operationId,
            failedTurnId,
            ParentOperationId: null,
            RecoveryCountingMode.OriginalFailedTurnOnly,
            MaximumAttempts: 1,
            UnlimitedAttempts: false,
            PolicyVersion: 0,
            FailureSignature: inputHash,
            NoProgressCount: 0);
        return await GetOrCreateAsync(
                operationId,
                threadId,
                failedTurnId,
                action,
                inputHash,
                clientMessageId,
                conservativePolicy,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<RecoveryJournalPrepareResult> GetOrCreateAsync(
        string operationId,
        string threadId,
        string failedTurnId,
        RecoveryActionKind action,
        string inputHash,
        string? clientMessageId,
        RecoveryIncidentPolicy incidentPolicy,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(incidentPolicy);
        var normalized = NormalizeNewRecord(
            operationId,
            threadId,
            failedTurnId,
            action,
            inputHash,
            clientMessageId,
            incidentPolicy);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();

            var existing = FindCore(normalized.ThreadId, normalized.FailedTurnId);
            if (existing is not null)
            {
                EnsureSameOperation(existing, normalized);
                return new(
                    existing,
                    Created: false,
                    RequiresReconciliation: existing.State is RecoveryOperationState.Dispatching or RecoveryOperationState.Uncertain);
            }

            if (_records.Any(record => string.Equals(
                    record.OperationId,
                    normalized.OperationId,
                    StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException(
                    "The recovery operation id already belongs to a different failed turn.");
            }

            var initialState = _requiresConservativeRecovery
                ? RecoveryOperationState.Uncertain
                : RecoveryOperationState.Prepared;
            var now = DateTimeOffset.UtcNow;
            var record = normalized with
            {
                State = initialState,
                ClientMessageId = normalized.ClientMessageId ?? normalized.OperationId,
                CreatedAt = now,
                UpdatedAt = now
            };
            var candidate = new List<RecoveryOperationRecord>(_records) { record };
            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return new(
                record,
                Created: true,
                RequiresReconciliation: initialState == RecoveryOperationState.Uncertain);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RecoveryJournalTransitionResult> TryTransitionAsync(
        string threadId,
        string failedTurnId,
        RecoveryOperationState expectedState,
        RecoveryOperationState nextState,
        string? clientMessageId = null,
        string? newTurnId = null,
        CancellationToken cancellationToken = default)
    {
        var key = NormalizeKey(threadId, failedTurnId);
        clientMessageId = NormalizeOptionalId(clientMessageId, nameof(clientMessageId));
        newTurnId = NormalizeOptionalId(newTurnId, nameof(newTurnId));

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();

            var index = FindIndex(key.ThreadId, key.FailedTurnId);
            if (index < 0 || _records[index].State != expectedState)
            {
                return new(false, index < 0 ? null : _records[index], _generation);
            }

            var current = _records[index];
            if (current.ClientMessageId is null && clientMessageId is not null)
            {
                throw new InvalidOperationException(
                    "A legacy recovery operation without a stable client message id cannot be assigned one during transition.");
            }

            ValidateTransition(current, nextState, clientMessageId, newTurnId);
            var effectiveClientMessageId = MergeStableId(
                current.ClientMessageId,
                clientMessageId,
                nameof(clientMessageId));
            var effectiveNewTurnId = MergeStableId(
                current.NewTurnId,
                newTurnId,
                nameof(newTurnId));
            var updated = current with
            {
                State = nextState,
                ClientMessageId = effectiveClientMessageId,
                NewTurnId = effectiveNewTurnId,
                UpdatedAt = DateTimeOffset.UtcNow,
                AttemptCount = nextState == RecoveryOperationState.Dispatching
                    ? checked(current.AttemptCount + 1)
                    : current.AttemptCount
            };
            var candidate = new List<RecoveryOperationRecord>(_records);
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

    private async Task<int> AbandonPendingCoreAsync(
        string threadId,
        Func<RecoveryOperationRecord, bool> predicate,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();

            var changed = 0;
            var now = DateTimeOffset.UtcNow;
            var candidate = new List<RecoveryOperationRecord>(_records);
            for (var index = 0; index < candidate.Count; index++)
            {
                var record = candidate[index];
                if (!string.Equals(record.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) ||
                    IsPrunable(record.State) ||
                    !predicate(record))
                {
                    continue;
                }

                candidate[index] = record with
                {
                    State = RecoveryOperationState.Abandoned,
                    UpdatedAt = now
                };
                changed++;
            }

            if (changed == 0)
            {
                return 0;
            }

            var persisted = await PersistCandidateAsync(candidate, cancellationToken).ConfigureAwait(false);
            Commit(persisted);
            return changed;
        }
        finally
        {
            _gate.Release();
        }
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
            if (primary.Status == RecoveryJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (primary.Status == RecoveryJournalReadStatus.Healthy)
            {
                LoadDocument(primary.Document!, RecoveryJournalReadStatus.Healthy, promotePending: false);
                return;
            }

            var backup = await TryReadDocumentAsync(BackupPath, cancellationToken).ConfigureAwait(false);
            if (backup.Status == RecoveryJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (backup.Status == RecoveryJournalReadStatus.Healthy)
            {
                LoadDocument(
                    backup.Document!,
                    RecoveryJournalReadStatus.RecoveredFromBackup,
                    promotePending: true);
                return;
            }

            if (primary.Status == RecoveryJournalReadStatus.Missing &&
                backup.Status == RecoveryJournalReadStatus.Missing &&
                !File.Exists(InitializationMarkerPath))
            {
                _readStatus = RecoveryJournalReadStatus.Missing;
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
            return new(RecoveryJournalReadStatus.Missing, null);
        }

        try
        {
            var file = new FileInfo(path);
            if (file.Length <= 0 || file.Length > _maximumFileBytes)
            {
                return new(RecoveryJournalReadStatus.Corrupted, null);
            }

            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var jsonDocument = await JsonDocument.ParseAsync(
                    stream,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (jsonDocument.RootElement.ValueKind != JsonValueKind.Object ||
                !jsonDocument.RootElement.TryGetProperty("schemaVersion", out var schemaVersionElement) ||
                schemaVersionElement.ValueKind != JsonValueKind.Number ||
                !schemaVersionElement.TryGetInt32(out var schemaVersion))
            {
                return new(RecoveryJournalReadStatus.Corrupted, null);
            }

            if (schemaVersion is not CurrentSchemaVersion and not LegacySchemaVersion)
            {
                return new(RecoveryJournalReadStatus.UnsupportedSchema, null);
            }

            if (schemaVersion == LegacySchemaVersion)
            {
                var legacy = jsonDocument.RootElement.Deserialize<LegacyJournalDocument>(JsonOptions);
                return legacy is not null && ValidateLegacyDocument(legacy)
                    ? new(
                        RecoveryJournalReadStatus.Healthy,
                        UpgradeLegacyDocument(legacy))
                    : new(RecoveryJournalReadStatus.Corrupted, null);
            }

            var document = jsonDocument.RootElement.Deserialize<JournalDocument>(JsonOptions);
            return document is not null && ValidateDocument(document)
                ? new(RecoveryJournalReadStatus.Healthy, document)
                : new(RecoveryJournalReadStatus.Corrupted, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new(RecoveryJournalReadStatus.Corrupted, null);
        }
    }

    private void LoadDocument(
        JournalDocument document,
        RecoveryJournalReadStatus status,
        bool promotePending)
    {
        var records = document.Records!;
        var hasIdlessPending = records.Any(record =>
            string.IsNullOrWhiteSpace(record.ClientMessageId) &&
            record.State is RecoveryOperationState.Prepared or RecoveryOperationState.Dispatching or
                RecoveryOperationState.Retryable);
        if (promotePending || hasIdlessPending)
        {
            var now = DateTimeOffset.UtcNow;
            records = records.Select(record =>
                    (promotePending || string.IsNullOrWhiteSpace(record.ClientMessageId)) &&
                    record.State is RecoveryOperationState.Prepared or RecoveryOperationState.Dispatching or
                        RecoveryOperationState.Retryable
                    ? record with { State = RecoveryOperationState.Uncertain, UpdatedAt = now }
                    : record)
                .ToList();
        }

        _records.AddRange(records);
        _generation = document.Generation;
        // An id-less legacy record is quarantined per record. Do not let one historical
        // operation force unrelated new operations into conservative recovery.
        _requiresConservativeRecovery = document.RequiresConservativeRecovery;
        _readStatus = status;
    }

    private bool ValidateDocument(JournalDocument document)
    {
        if (document.Generation < 0 ||
            document.Records is null ||
            document.Records.Count > _maximumRecords ||
            string.IsNullOrWhiteSpace(document.Checksum))
        {
            return false;
        }

        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var operationIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in document.Records)
        {
            if (!ValidateRecord(record) ||
                !keys.Add(CreateKey(record.ThreadId, record.FailedTurnId)) ||
                !operationIds.Add(record.OperationId))
            {
                return false;
            }
        }

        var expectedChecksum = ComputeChecksum(
            document.SchemaVersion,
            document.Generation,
            document.RequiresConservativeRecovery,
            document.Records);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expectedChecksum),
            Encoding.ASCII.GetBytes(document.Checksum));
    }

    private bool ValidateLegacyDocument(LegacyJournalDocument document)
    {
        if (document.SchemaVersion != LegacySchemaVersion ||
            document.Generation < 0 ||
            document.Records is null ||
            document.Records.Count > _maximumRecords ||
            string.IsNullOrWhiteSpace(document.Checksum))
        {
            return false;
        }

        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var operationIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in document.Records)
        {
            if (!ValidateLegacyRecord(record) ||
                !keys.Add(CreateKey(record.ThreadId, record.FailedTurnId)) ||
                !operationIds.Add(record.OperationId))
            {
                return false;
            }
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new LegacyJournalIntegrityPayload(
                document.SchemaVersion,
                document.Generation,
                document.RequiresConservativeRecovery,
                document.Records),
            JsonOptions);
        var expectedChecksum = Convert.ToHexString(SHA256.HashData(payload));
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expectedChecksum),
            Encoding.ASCII.GetBytes(document.Checksum));
    }

    private static JournalDocument UpgradeLegacyDocument(LegacyJournalDocument legacy)
    {
        var upgraded = legacy.Records!
            .Select(record => new RecoveryOperationRecord(
                record.OperationId,
                record.ThreadId,
                record.FailedTurnId,
                record.Action,
                record.InputHash,
                record.State,
                record.ClientMessageId,
                record.NewTurnId,
                record.CreatedAt,
                record.UpdatedAt,
                record.AttemptCount,
                IncidentId: record.OperationId,
                RootFailedTurnId: record.FailedTurnId,
                ParentOperationId: null,
                CountingMode: RecoveryCountingMode.OriginalFailedTurnOnly,
                MaximumAttempts: Math.Max(1, record.AttemptCount),
                UnlimitedAttempts: false,
                PolicyVersion: 0,
                FailureSignature: RecoveryOperationJournal.ComputeInputHash(
                    record.Action + "|legacy"),
                NoProgressCount: 0))
            .ToList();
        var checksum = ComputeChecksum(
            CurrentSchemaVersion,
            legacy.Generation,
            legacy.RequiresConservativeRecovery,
            upgraded);
        return new JournalDocument(
            CurrentSchemaVersion,
            legacy.Generation,
            legacy.RequiresConservativeRecovery,
            checksum,
            upgraded);
    }

    private async Task<PersistedCandidate> PersistCandidateAsync(
        List<RecoveryOperationRecord> candidate,
        CancellationToken cancellationToken)
    {
        var nextGeneration = checked(_generation + 1);
        PruneTerminalRecordsByCount(candidate);
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
                    "The recovery journal contains too many pending operations to fit within its disk limit.");
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
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            await using (var stream = new FileStream(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
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
                var backupPath = _readStatus == RecoveryJournalReadStatus.Healthy
                    ? BackupPath
                    : null;
                File.Replace(tempPath, JournalPath, backupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, JournalPath);
            }

            return new(candidate, nextGeneration);
        }
        finally
        {
            try
            {
                DataDirectorySafety.Revalidate(DataDirectory);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
                File.Delete(tempPath);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private byte[] SerializeDocument(long generation, IReadOnlyList<RecoveryOperationRecord> records)
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
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
            using (var stream = new FileStream(
                       tempPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 128,
                       FileOptions.WriteThrough))
            {
                stream.Write("schema=2\n"u8);
                stream.Flush(flushToDisk: true);
            }

            try
            {
                DataDirectorySafety.Revalidate(DataDirectory);
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
            try
            {
                DataDirectorySafety.Revalidate(DataDirectory);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, tempPath);
                File.Delete(tempPath);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private void CleanupTemporaryFiles()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        if (!Directory.Exists(DataDirectory))
        {
            return;
        }

        try
        {
            var journalPattern = $".{Path.GetFileName(JournalPath)}.*.tmp";
            var markerPattern = $".{Path.GetFileName(InitializationMarkerPath)}.*.tmp";
            foreach (var path in Directory.EnumerateFiles(DataDirectory, journalPattern, SearchOption.TopDirectoryOnly)
                         .Concat(Directory.EnumerateFiles(
                             DataDirectory,
                             markerPattern,
                             SearchOption.TopDirectoryOnly)))
            {
                try
                {
                    DataDirectorySafety.Revalidate(DataDirectory);
                    DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
                    File.Delete(path);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string ComputeChecksum(
        int schemaVersion,
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<RecoveryOperationRecord> records)
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

    private void PruneTerminalRecordsByCount(List<RecoveryOperationRecord> candidate)
    {
        while (candidate.Count > _maximumRecords)
        {
            var terminalIndex = FindOldestTerminalIndex(candidate);
            if (terminalIndex < 0)
            {
                throw new InvalidOperationException(
                    "The recovery journal contains more pending operations than its record limit permits.");
            }

            candidate.RemoveAt(terminalIndex);
        }
    }

    private static int FindOldestTerminalIndex(IReadOnlyList<RecoveryOperationRecord> records)
    {
        var selectedIndex = -1;
        for (var index = 0; index < records.Count; index++)
        {
            if (!IsPrunable(records[index].State))
            {
                continue;
            }

            if (selectedIndex < 0 || records[index].UpdatedAt < records[selectedIndex].UpdatedAt)
            {
                selectedIndex = index;
            }
        }

        return selectedIndex;
    }

    private static void ValidateTransition(
        RecoveryOperationRecord current,
        RecoveryOperationState nextState,
        string? clientMessageId,
        string? newTurnId)
    {
        if (current.State == nextState)
        {
            throw new InvalidOperationException("A recovery journal transition must change state.");
        }

        var allowed = current.State switch
        {
            RecoveryOperationState.Prepared =>
                nextState is RecoveryOperationState.Dispatching or RecoveryOperationState.Abandoned,
            RecoveryOperationState.Dispatching =>
                nextState is RecoveryOperationState.Retryable or RecoveryOperationState.Uncertain or
                    RecoveryOperationState.Accepted or RecoveryOperationState.Confirmed or
                    RecoveryOperationState.Abandoned,
            RecoveryOperationState.Retryable =>
                nextState is RecoveryOperationState.Dispatching or RecoveryOperationState.Abandoned,
            RecoveryOperationState.Uncertain =>
                nextState is RecoveryOperationState.Confirmed or RecoveryOperationState.Abandoned ||
                    (nextState == RecoveryOperationState.Retryable && IsInPlaceRetryAction(current.Action)),
            RecoveryOperationState.Accepted or RecoveryOperationState.Confirmed =>
                nextState == RecoveryOperationState.Abandoned,
            _ => false
        };
        if (!allowed)
        {
            throw new InvalidOperationException(
                $"Recovery journal transition {current.State} -> {nextState} is not allowed for {current.Action}.");
        }

        if (current.ClientMessageId is null &&
            nextState is RecoveryOperationState.Dispatching or RecoveryOperationState.Accepted or
                RecoveryOperationState.Confirmed)
        {
            throw new InvalidOperationException(
                "A legacy recovery operation without a stable client message id may only be quarantined or closed.");
        }

        if (nextState == RecoveryOperationState.Confirmed && string.IsNullOrWhiteSpace(newTurnId) &&
            string.IsNullOrWhiteSpace(current.NewTurnId))
        {
            throw new InvalidOperationException("A confirmed recovery operation must identify its committed turn.");
        }
    }

    private static RecoveryOperationRecord NormalizeNewRecord(
        string operationId,
        string threadId,
        string failedTurnId,
        RecoveryActionKind action,
        string inputHash,
        string? clientMessageId,
        RecoveryIncidentPolicy incidentPolicy)
    {
        if (!Enum.IsDefined(action) || action == RecoveryActionKind.None)
        {
            throw new ArgumentOutOfRangeException(nameof(action));
        }

        operationId = NormalizeRequiredId(operationId, nameof(operationId));
        var key = NormalizeKey(threadId, failedTurnId);
        inputHash = NormalizeInputHash(inputHash);
        clientMessageId = NormalizeOptionalId(clientMessageId, nameof(clientMessageId));

        var incidentId = NormalizeRequiredId(incidentPolicy.IncidentId, nameof(incidentPolicy));
        var rootFailedTurnId = NormalizeRequiredId(
            incidentPolicy.RootFailedTurnId,
            nameof(incidentPolicy));
        var parentOperationId = NormalizeOptionalId(
            incidentPolicy.ParentOperationId,
            nameof(incidentPolicy));
        if (!Enum.IsDefined(incidentPolicy.CountingMode) ||
            incidentPolicy.MaximumAttempts is < 1 or > RecoveryAttemptPolicyLimits.MaximumFiniteAttempts ||
            incidentPolicy.PolicyVersion < 0 ||
            !IsSha256(incidentPolicy.FailureSignature) ||
            incidentPolicy.NoProgressCount is < 0 or > 3)
        {
            throw new ArgumentException(
                "The recovery incident policy is invalid.",
                nameof(incidentPolicy));
        }

        if (incidentPolicy.CountingMode == RecoveryCountingMode.OriginalFailedTurnOnly &&
            !string.Equals(rootFailedTurnId, key.FailedTurnId, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Original-only recovery cannot prepare a successor failure.",
                nameof(incidentPolicy));
        }

        return new RecoveryOperationRecord(
            operationId,
            key.ThreadId,
            key.FailedTurnId,
            action,
            inputHash,
            RecoveryOperationState.Prepared,
            clientMessageId,
            NewTurnId: null,
            CreatedAt: default,
            UpdatedAt: default,
            AttemptCount: 0,
            IncidentId: incidentId,
            RootFailedTurnId: rootFailedTurnId,
            ParentOperationId: parentOperationId,
            CountingMode: incidentPolicy.CountingMode,
            MaximumAttempts: incidentPolicy.MaximumAttempts,
            UnlimitedAttempts: incidentPolicy.UnlimitedAttempts,
            PolicyVersion: incidentPolicy.PolicyVersion,
            FailureSignature: incidentPolicy.FailureSignature.ToUpperInvariant(),
            NoProgressCount: incidentPolicy.NoProgressCount);
    }

    private static bool ValidateRecord(RecoveryOperationRecord record)
    {
        if (record is null ||
            !Guid.TryParseExact(record.OperationId, "D", out _) ||
            !Guid.TryParseExact(record.ThreadId, "D", out _) ||
            !Guid.TryParseExact(record.FailedTurnId, "D", out _) ||
            !Enum.IsDefined(record.Action) ||
            record.Action == RecoveryActionKind.None ||
            !Enum.IsDefined(record.State) ||
            !IsSha256(record.InputHash) ||
            record.AttemptCount < 0 ||
            !Guid.TryParseExact(record.IncidentId, "D", out _) ||
            !Guid.TryParseExact(record.RootFailedTurnId, "D", out _) ||
            record.ParentOperationId is not null &&
                !Guid.TryParseExact(record.ParentOperationId, "D", out _) ||
            !Enum.IsDefined(record.CountingMode) ||
            record.MaximumAttempts is < 1 or > RecoveryAttemptPolicyLimits.MaximumFiniteAttempts ||
            record.PolicyVersion < 0 ||
            !IsSha256(record.FailureSignature) ||
            record.NoProgressCount is < 0 or > 3 ||
            record.CreatedAt == default ||
            record.UpdatedAt < record.CreatedAt ||
            record.ClientMessageId is not null && !Guid.TryParseExact(record.ClientMessageId, "D", out _) ||
            record.NewTurnId is not null && !Guid.TryParseExact(record.NewTurnId, "D", out _))
        {
            return false;
        }

        if (record.Action == RecoveryActionKind.SendContinue && record.ClientMessageId is null)
        {
            return false;
        }

        if (record.CountingMode == RecoveryCountingMode.OriginalFailedTurnOnly &&
            !string.Equals(
                record.RootFailedTurnId,
                record.FailedTurnId,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return record.State != RecoveryOperationState.Confirmed || record.NewTurnId is not null;
    }

    private static bool ValidateLegacyRecord(LegacyRecoveryOperationRecord record)
    {
        if (record is null ||
            !Guid.TryParseExact(record.OperationId, "D", out _) ||
            !Guid.TryParseExact(record.ThreadId, "D", out _) ||
            !Guid.TryParseExact(record.FailedTurnId, "D", out _) ||
            !Enum.IsDefined(record.Action) ||
            record.Action == RecoveryActionKind.None ||
            !Enum.IsDefined(record.State) ||
            !IsSha256(record.InputHash) ||
            record.AttemptCount < 0 ||
            record.CreatedAt == default ||
            record.UpdatedAt < record.CreatedAt ||
            record.ClientMessageId is not null &&
                !Guid.TryParseExact(record.ClientMessageId, "D", out _) ||
            record.NewTurnId is not null && !Guid.TryParseExact(record.NewTurnId, "D", out _))
        {
            return false;
        }

        if (record.Action == RecoveryActionKind.SendContinue && record.ClientMessageId is null)
        {
            return false;
        }

        return record.State != RecoveryOperationState.Confirmed || record.NewTurnId is not null;
    }

    private static void EnsureSameOperation(
        RecoveryOperationRecord existing,
        RecoveryOperationRecord requested)
    {
        if (!string.Equals(existing.OperationId, requested.OperationId, StringComparison.OrdinalIgnoreCase) ||
            existing.Action != requested.Action ||
            !string.Equals(existing.InputHash, requested.InputHash, StringComparison.OrdinalIgnoreCase) ||
            existing.ClientMessageId is not null && requested.ClientMessageId is not null &&
                !string.Equals(existing.ClientMessageId, requested.ClientMessageId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.IncidentId, requested.IncidentId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.RootFailedTurnId, requested.RootFailedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.ParentOperationId, requested.ParentOperationId, StringComparison.OrdinalIgnoreCase) ||
            existing.CountingMode != requested.CountingMode ||
            existing.MaximumAttempts != requested.MaximumAttempts ||
            existing.UnlimitedAttempts != requested.UnlimitedAttempts ||
            existing.PolicyVersion != requested.PolicyVersion ||
            !string.Equals(existing.FailureSignature, requested.FailureSignature, StringComparison.OrdinalIgnoreCase) ||
            existing.NoProgressCount != requested.NoProgressCount)
        {
            throw new InvalidOperationException(
                "The failed turn already belongs to a different recovery operation.");
        }
    }

    private static string? MergeStableId(string? existing, string? requested, string parameterName)
    {
        if (existing is not null && requested is not null &&
            !string.Equals(existing, requested, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("A persisted stable id cannot be changed.", parameterName);
        }

        return existing ?? requested;
    }

    private RecoveryOperationRecord? FindCore(string threadId, string failedTurnId)
    {
        var index = FindIndex(threadId, failedTurnId);
        return index < 0 ? null : _records[index];
    }

    private int FindIndex(string threadId, string failedTurnId)
    {
        for (var index = 0; index < _records.Count; index++)
        {
            if (string.Equals(_records[index].ThreadId, threadId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(_records[index].FailedTurnId, failedTurnId, StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return -1;
    }

    private RecoveryJournalSnapshot CreateSnapshot() =>
        new(
            _readStatus,
            _generation,
            _requiresConservativeRecovery,
            _records.ToArray());

    private void Commit(PersistedCandidate persisted)
    {
        _records.Clear();
        _records.AddRange(persisted.Records);
        _generation = persisted.Generation;
        _readStatus = RecoveryJournalReadStatus.Healthy;
    }

    private void MarkCorrupted()
    {
        _records.Clear();
        _generation = 0;
        _requiresConservativeRecovery = true;
        _readStatus = RecoveryJournalReadStatus.Corrupted;
    }

    private void MarkUnsupportedSchema()
    {
        _records.Clear();
        _generation = 0;
        _requiresConservativeRecovery = true;
        _unsupportedSchema = true;
        _readStatus = RecoveryJournalReadStatus.UnsupportedSchema;
    }

    private void ThrowIfUnsupportedSchema()
    {
        if (_unsupportedSchema)
        {
            throw new NotSupportedException(
                "The recovery journal was written by an unsupported schema and was left unchanged.");
        }
    }

    private static (string ThreadId, string FailedTurnId) NormalizeKey(
        string threadId,
        string failedTurnId) =>
        (
            NormalizeRequiredId(threadId, nameof(threadId)),
            NormalizeRequiredId(failedTurnId, nameof(failedTurnId))
        );

    private static string NormalizeRequiredId(string value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed))
        {
            throw new ArgumentException("A UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private static string? NormalizeOptionalId(string? value, string parameterName) =>
        string.IsNullOrWhiteSpace(value) ? null : NormalizeRequiredId(value, parameterName);

    private static string NormalizeInputHash(string value)
    {
        if (!IsSha256(value))
        {
            throw new ArgumentException("A SHA-256 input hash is required.", nameof(value));
        }

        return value.ToUpperInvariant();
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static string CreateKey(string threadId, string failedTurnId) =>
        threadId + "/" + failedTurnId;

    // Both terminal states are prunable. Only Abandoned used to be, which made the record limit a hard
    // stop on success: every confirmed in-place retry adds a Confirmed record, and a task retried for
    // hours fills the journal with them. Once 250 of the 256 records were Confirmed, the six Abandoned
    // ones were pruned and the next prepare threw "more pending operations than its record limit
    // permits" -- recovery stopped working precisely because it had been working. A Confirmed record has
    // already been reconciled and recorded its successor turn id; its only later use is successor
    // matching for the current turn, and pruning takes the oldest UpdatedAt first, so live chains stay.
    // In-flight states (Prepared, Dispatching, Retryable, Uncertain, Accepted) are never prunable,
    // because dropping one would forfeit the at-most-once guarantee.
    private static bool IsPrunable(RecoveryOperationState state) =>
        state is RecoveryOperationState.Abandoned or RecoveryOperationState.Confirmed;

    // Pruning eligibility and lineage visibility are different questions, and answering both with
    // IsPrunable broke the second one when Confirmed became prunable. A Confirmed record is finished with
    // its own reconciliation, but it is precisely the record that carries the incident id, the frozen
    // attempt policy and the no-progress count that the next failure in the same incident inherits --
    // successor matching is the one later use the pruning comment above already names. Hiding it there
    // gave every failure after a successful recovery a brand-new incident and a fresh budget, which
    // defeats the shared-incident budget, the durable frozen policy and the three-strike no-progress
    // circuit at the same time, all without a single visible error. Only an abandoned operation is closed
    // for lineage, and that is not a second definition of "finished": Abandoned is exactly the state
    // ReconcileCurrentTurnAsync moves a tombstone into once its successor turn proved the recovery landed
    // or an unrelated later failure superseded it, so a record reaches it only after its lineage really
    // has ended. Confirmed means the successor turn was recorded, not that anyone has confirmed it ran.
    private static bool IsClosedForLineage(RecoveryOperationState state) =>
        state is RecoveryOperationState.Abandoned;

    // An in-place retry edits the failed turn under an expected-turn compare-and-swap, so re-dispatching one
    // whose failed turn is still last cannot duplicate a message: the owner either applies the edit or
    // rejects it as stale. That makes Uncertain -> Retryable safe for these actions only. Append actions
    // keep the stricter rule, because a lost acknowledgement there could mean a message did land.
    internal static bool IsInPlaceRetryAction(RecoveryActionKind action) =>
        action is RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue;

    private sealed record JournalDocument(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        List<RecoveryOperationRecord>? Records);

    private sealed record LegacyRecoveryOperationRecord(
        string OperationId,
        string ThreadId,
        string FailedTurnId,
        RecoveryActionKind Action,
        string InputHash,
        RecoveryOperationState State,
        string? ClientMessageId,
        string? NewTurnId,
        DateTimeOffset CreatedAt,
        DateTimeOffset UpdatedAt,
        int AttemptCount);

    private sealed record LegacyJournalDocument(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        List<LegacyRecoveryOperationRecord>? Records);

    private sealed record JournalIntegrityPayload(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<RecoveryOperationRecord> Records);

    private sealed record LegacyJournalIntegrityPayload(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<LegacyRecoveryOperationRecord> Records);

    private sealed record PersistedCandidate(
        IReadOnlyList<RecoveryOperationRecord> Records,
        long Generation);

    private sealed record JournalLoadResult(
        RecoveryJournalReadStatus Status,
        JournalDocument? Document);
}
