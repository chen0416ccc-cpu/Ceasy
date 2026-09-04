using CodexGuardian.Models;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CodexGuardian.Services;

internal enum WorkflowRuleStoreReadStatus
{
    Missing,
    Healthy,
    RecoveredFromBackup,
    Corrupted,
    UnsupportedSchema
}

internal sealed record WorkflowRuleStoreSnapshot(
    WorkflowRuleStoreReadStatus ReadStatus,
    long Generation,
    bool RequiresConservativeRecovery,
    IReadOnlyList<WorkflowRuleDefinition> Rules,
    WorkflowRuleGraphValidationResult Validation);

internal sealed record WorkflowRuleStoreDurableSnapshot(
    WorkflowRuleStoreSnapshot LogicalState,
    byte[]? PrimaryBytes,
    byte[]? BackupBytes,
    byte[]? MarkerBytes);

internal sealed class WorkflowRuleStore
{
    internal const int CurrentSchemaVersion = 1;
    internal const long DefaultMaximumFileBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly WorkflowRuleGraphCapabilities _capabilities;
    private readonly long _maximumFileBytes;
    private readonly List<WorkflowRuleDefinition> _rules = [];
    private bool _loaded;
    private bool _requiresConservativeRecovery;
    private bool _unsupportedSchema;
    private long _generation;
    private WorkflowRuleStoreReadStatus _readStatus = WorkflowRuleStoreReadStatus.Missing;
    private WorkflowRuleGraphValidationResult _validation =
        WorkflowRuleGraphValidator.Validate([]);

    internal WorkflowRuleStore(
        string dataDirectory,
        WorkflowRuleGraphCapabilities? capabilities = null,
        long maximumFileBytes = DefaultMaximumFileBytes)
    {
        if (maximumFileBytes < 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFileBytes));
        }

        DataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        RulePath = Path.Combine(DataDirectory, "workflow-rules.json");
        BackupPath = Path.Combine(DataDirectory, "workflow-rules.previous.json");
        InitializationMarkerPath = Path.Combine(DataDirectory, "workflow-rules.initialized");
        _capabilities = capabilities ?? WorkflowRuleGraphCapabilities.Conservative;
        _maximumFileBytes = maximumFileBytes;
    }

    internal string DataDirectory { get; }

    internal string RulePath { get; }

    internal string BackupPath { get; }

    internal string InitializationMarkerPath { get; }

    internal async Task<WorkflowRuleStoreSnapshot> ReadAsync(
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

    internal async Task<WorkflowRuleStoreSnapshot> SaveAsync(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var canonical = rules
            .OrderBy(rule => rule?.RuleId, StringComparer.Ordinal)
            .ToArray();
        var validation = WorkflowRuleGraphValidator.Validate(canonical!, _capabilities);
        if (HasBlockingIssues(validation))
        {
            throw new InvalidOperationException(
                "The workflow rule set contains a structural identity, bound, or cycle error.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            if (_requiresConservativeRecovery)
            {
                throw new InvalidOperationException(
                    "Recovered workflow rules require explicit review before replacement.");
            }

            var generation = checked(_generation + 1);
            var document = CreateDocument(generation, canonical!);
            if (!TryValidateDocument(document, out var materialized, out var persistedValidation))
            {
                throw new InvalidDataException("The workflow rule document candidate is invalid.");
            }

            var bytes = JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
            if (bytes.LongLength > _maximumFileBytes)
            {
                throw new InvalidOperationException("The workflow rule store exceeds its byte bound.");
            }

            await PersistAsync(document, bytes, cancellationToken).ConfigureAwait(false);
            _rules.Clear();
            _rules.AddRange(materialized);
            _generation = generation;
            _validation = persistedValidation;
            _readStatus = WorkflowRuleStoreReadStatus.Healthy;
            return CreateSnapshot();
        }
        finally
        {
            _gate.Release();
        }
    }

    internal async Task<WorkflowRuleStoreDurableSnapshot> CaptureDurableSnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return new WorkflowRuleStoreDurableSnapshot(
                CreateSnapshot(),
                await ReadDurableFileAsync(RulePath, _maximumFileBytes, cancellationToken)
                    .ConfigureAwait(false),
                await ReadDurableFileAsync(BackupPath, _maximumFileBytes, cancellationToken)
                    .ConfigureAwait(false),
                await ReadDurableFileAsync(InitializationMarkerPath, 64, cancellationToken)
                    .ConfigureAwait(false));
        }
        finally
        {
            _gate.Release();
        }
    }

    internal async Task RestoreDurableSnapshotAsync(
        WorkflowRuleStoreDurableSnapshot snapshot,
        long expectedCurrentGeneration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(snapshot.LogicalState);
        if (expectedCurrentGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedCurrentGeneration));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var currentPrimary = await ReadDurableFileAsync(
                    RulePath,
                    _maximumFileBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            var currentBackup = await ReadDurableFileAsync(
                    BackupPath,
                    _maximumFileBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            var currentMarker = await ReadDurableFileAsync(
                    InitializationMarkerPath,
                    64,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!DurableBytesEqual(snapshot.PrimaryBytes, currentPrimary) ||
                !DurableBytesEqual(snapshot.BackupBytes, currentBackup) ||
                !DurableBytesEqual(snapshot.MarkerBytes, currentMarker))
            {
                var current = await TryReadDocumentAsync(RulePath, cancellationToken)
                    .ConfigureAwait(false);
                if (current.Status != WorkflowRuleStoreReadStatus.Healthy ||
                    current.Document!.Generation != expectedCurrentGeneration)
                {
                    throw new InvalidOperationException(
                        "The workflow rule store changed after the rollback target was captured.");
                }
            }

            await RestoreDurableFileAsync(
                    RulePath,
                    snapshot.PrimaryBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            await RestoreDurableFileAsync(
                    BackupPath,
                    snapshot.BackupBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            await RestoreDurableFileAsync(
                    InitializationMarkerPath,
                    snapshot.MarkerBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            var restoredPrimary = await ReadDurableFileAsync(
                    RulePath,
                    _maximumFileBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            var restoredBackup = await ReadDurableFileAsync(
                    BackupPath,
                    _maximumFileBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            var restoredMarker = await ReadDurableFileAsync(
                    InitializationMarkerPath,
                    64,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!DurableBytesEqual(snapshot.PrimaryBytes, restoredPrimary) ||
                !DurableBytesEqual(snapshot.BackupBytes, restoredBackup) ||
                !DurableBytesEqual(snapshot.MarkerBytes, restoredMarker))
            {
                throw new IOException("The workflow rule rollback readback did not match its snapshot.");
            }

            _rules.Clear();
            _rules.AddRange(snapshot.LogicalState.Rules);
            _generation = snapshot.LogicalState.Generation;
            _requiresConservativeRecovery = snapshot.LogicalState.RequiresConservativeRecovery;
            _unsupportedSchema = snapshot.LogicalState.ReadStatus ==
                                 WorkflowRuleStoreReadStatus.UnsupportedSchema;
            _readStatus = snapshot.LogicalState.ReadStatus;
            _validation = snapshot.LogicalState.Validation;
            _loaded = true;
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch
        {
            MarkCorrupted();
            throw;
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
        try
        {
            var primary = await TryReadDocumentAsync(RulePath, cancellationToken).ConfigureAwait(false);
            if (primary.Status == WorkflowRuleStoreReadStatus.UnsupportedSchema)
            {
                MarkUnsupported();
                return;
            }

            if (primary.Status == WorkflowRuleStoreReadStatus.Healthy)
            {
                Load(primary.Document!, WorkflowRuleStoreReadStatus.Healthy, recovered: false);
                return;
            }

            var backup = await TryReadDocumentAsync(BackupPath, cancellationToken).ConfigureAwait(false);
            if (backup.Status == WorkflowRuleStoreReadStatus.UnsupportedSchema)
            {
                MarkUnsupported();
                return;
            }

            if (backup.Status == WorkflowRuleStoreReadStatus.Healthy)
            {
                Load(backup.Document!, WorkflowRuleStoreReadStatus.RecoveredFromBackup, recovered: true);
                return;
            }

            if (primary.Status == WorkflowRuleStoreReadStatus.Missing &&
                backup.Status == WorkflowRuleStoreReadStatus.Missing &&
                !File.Exists(InitializationMarkerPath))
            {
                _readStatus = WorkflowRuleStoreReadStatus.Missing;
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
            exception is IOException or UnauthorizedAccessException or JsonException or
                NotSupportedException or ArgumentException or InvalidOperationException)
        {
            MarkCorrupted();
        }
    }

    private async Task<byte[]?> ReadDurableFileAsync(
        string path,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (!File.Exists(path))
        {
            return null;
        }

        var item = new FileInfo(path);
        var attributes = File.GetAttributes(path);
        if (item.Length <= 0 || item.Length > maximumBytes ||
            (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                           FileAttributes.Device)) != 0)
        {
            throw new InvalidDataException("The workflow rule durable snapshot is unsafe.");
        }

        return await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
    }

    private async Task RestoreDurableFileAsync(
        string path,
        byte[]? bytes,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        Directory.CreateDirectory(DataDirectory);
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (bytes is null)
        {
            File.Delete(path);
            if (File.Exists(path) || Directory.Exists(path))
            {
                throw new IOException("A workflow rule rollback target remained after deletion.");
            }

            return;
        }

        var temporaryPath = Path.Combine(
            DataDirectory,
            ".workflow-rules.restore." + Environment.ProcessId + "." +
            Guid.NewGuid().ToString("N") + ".tmp");
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
        try
        {
            await using (var stream = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
            if (File.Exists(path))
            {
                File.Replace(
                    temporaryPath,
                    path,
                    destinationBackupFileName: null,
                    ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, path);
            }
        }
        finally
        {
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
            File.Delete(temporaryPath);
        }
    }

    private static bool DurableBytesEqual(byte[]? expected, byte[]? actual) =>
        expected is null
            ? actual is null
            : actual is not null && expected.AsSpan().SequenceEqual(actual);

    private async Task<RuleReadResult> TryReadDocumentAsync(
        string path,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (!File.Exists(path))
        {
            return new RuleReadResult(WorkflowRuleStoreReadStatus.Missing, null);
        }

        try
        {
            var item = new FileInfo(path);
            var attributes = File.GetAttributes(path);
            if (item.Length <= 0 || item.Length > _maximumFileBytes ||
                (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                               FileAttributes.Device)) != 0)
            {
                return new RuleReadResult(WorkflowRuleStoreReadStatus.Corrupted, null);
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
                !schemaElement.TryGetInt32(out var schemaVersion))
            {
                return new RuleReadResult(WorkflowRuleStoreReadStatus.Corrupted, null);
            }

            if (schemaVersion != CurrentSchemaVersion)
            {
                return new RuleReadResult(WorkflowRuleStoreReadStatus.UnsupportedSchema, null);
            }

            var document = json.RootElement.Deserialize<RuleDocument>(JsonOptions);
            return document is not null && TryValidateDocument(document, out _, out _)
                ? new RuleReadResult(WorkflowRuleStoreReadStatus.Healthy, document)
                : new RuleReadResult(WorkflowRuleStoreReadStatus.Corrupted, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
                NotSupportedException or ArgumentException or InvalidOperationException)
        {
            return new RuleReadResult(WorkflowRuleStoreReadStatus.Corrupted, null);
        }
    }

    private void Load(
        RuleDocument document,
        WorkflowRuleStoreReadStatus readStatus,
        bool recovered)
    {
        if (!TryValidateDocument(document, out var rules, out var validation))
        {
            MarkCorrupted();
            return;
        }

        _rules.AddRange(rules);
        _generation = document.Generation;
        _requiresConservativeRecovery = document.RequiresConservativeRecovery || recovered;
        _validation = validation;
        _readStatus = readStatus;
    }

    private async Task PersistAsync(
        RuleDocument document,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        Directory.CreateDirectory(DataDirectory);
        DataDirectorySafety.Revalidate(DataDirectory);
        var temporaryPath = Path.Combine(
            DataDirectory,
            ".workflow-rules." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".tmp");
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
        try
        {
            await using (var stream = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, RulePath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, BackupPath);
            if (File.Exists(RulePath))
            {
                File.Replace(temporaryPath, RulePath, BackupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, RulePath);
            }

            EnsureInitializationMarker();
        }
        finally
        {
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
            File.Delete(temporaryPath);
        }

        var readback = await TryReadDocumentAsync(RulePath, cancellationToken).ConfigureAwait(false);
        if (readback.Status != WorkflowRuleStoreReadStatus.Healthy ||
            readback.Document!.Generation != document.Generation ||
            !string.Equals(readback.Document.Checksum, document.Checksum, StringComparison.Ordinal))
        {
            throw new IOException("The workflow rule store readback failed.");
        }
    }

    private void EnsureInitializationMarker()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, InitializationMarkerPath);
        if (File.Exists(InitializationMarkerPath))
        {
            var attributes = File.GetAttributes(InitializationMarkerPath);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                               FileAttributes.Device)) != 0)
            {
                throw new IOException("The workflow rule initialization marker is unsafe.");
            }

            return;
        }

        using var stream = new FileStream(
            InitializationMarkerPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            16,
            FileOptions.WriteThrough);
        stream.WriteByte(CurrentSchemaVersion);
        stream.Flush(flushToDisk: true);
    }

    private bool TryValidateDocument(
        RuleDocument document,
        out IReadOnlyList<WorkflowRuleDefinition> rules,
        out WorkflowRuleGraphValidationResult validation)
    {
        rules = [];
        validation = WorkflowRuleGraphValidator.Validate([]);
        if (document.SchemaVersion != CurrentSchemaVersion ||
            document.Generation <= 0 ||
            document.Rules is null ||
            document.Rules.Count > WorkflowRuleGraphValidator.MaximumRules ||
            !IsSha256(document.Checksum))
        {
            return false;
        }

        var materialized = new List<WorkflowRuleDefinition>(document.Rules.Count);
        string? previousRuleId = null;
        foreach (var record in document.Rules)
        {
            if (!TryMaterialize(record, out var rule) ||
                previousRuleId is not null && string.CompareOrdinal(previousRuleId, rule.RuleId) >= 0)
            {
                return false;
            }

            previousRuleId = rule.RuleId;
            materialized.Add(rule);
        }

        validation = WorkflowRuleGraphValidator.Validate(materialized, _capabilities);
        if (HasBlockingIssues(validation))
        {
            return false;
        }

        var expected = ComputeChecksum(
            document.SchemaVersion,
            document.Generation,
            document.RequiresConservativeRecovery,
            document.Rules);
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(expected),
                Convert.FromHexString(document.Checksum)))
        {
            return false;
        }

        rules = materialized.AsReadOnly();
        return true;
    }

    private static bool TryMaterialize(RuleRecord record, out WorkflowRuleDefinition rule)
    {
        rule = null!;
        try
        {
            if (record is null || record.Trigger is null || record.Destination is null ||
                record.Conditions is null || record.Actions is null)
            {
                return false;
            }

            var trigger = new WorkflowTriggerDefinition
            {
                Kind = (WorkflowTriggerKind)record.Trigger.Kind,
                SourceConversationId = record.Trigger.SourceConversationId,
                SourcePresetMessageId = record.Trigger.SourcePresetMessageId,
                ScheduledAtUtc = record.Trigger.ScheduledAtUtcTicks is { } scheduledTicks
                    ? new DateTimeOffset(scheduledTicks, TimeSpan.Zero)
                    : null
            };
            var destination = new WorkflowDestinationDefinition
            {
                Kind = (WorkflowDestinationKind)record.Destination.Kind,
                ConversationId = record.Destination.ConversationId
            };
            var actions = record.Actions.Select(action => new WorkflowActionDefinition
            {
                Kind = (WorkflowActionKind)action.Kind,
                PresetOwnerConversationId = action.PresetOwnerConversationId,
                PresetMessageId = action.PresetMessageId,
                Order = action.Order
            }).ToArray();
            rule = WorkflowRuleDefinition.Create(
                record.RuleId,
                record.Revision,
                record.OwnerConversationId,
                record.IsEnabled,
                new DateTimeOffset(record.ActivatedAtUtcTicks, TimeSpan.Zero),
                trigger,
                destination,
                record.Conditions.Select(value => (WorkflowConditionKind)value),
                actions);
            return record.RuleSchemaVersion == WorkflowRuleDefinition.CurrentSchemaVersion &&
                   string.Equals(rule.DefinitionDigest, record.DefinitionDigest, StringComparison.Ordinal);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or OverflowException)
        {
            return false;
        }
    }

    private static RuleDocument CreateDocument(
        long generation,
        IReadOnlyList<WorkflowRuleDefinition> rules)
    {
        var records = rules.Select(ToRecord).ToList();
        var checksum = ComputeChecksum(
            CurrentSchemaVersion,
            generation,
            requiresConservativeRecovery: false,
            records);
        return new RuleDocument(
            CurrentSchemaVersion,
            generation,
            RequiresConservativeRecovery: false,
            checksum,
            records);
    }

    private static RuleRecord ToRecord(WorkflowRuleDefinition rule) =>
        new(
            rule.SchemaVersion,
            rule.RuleId,
            rule.Revision,
            rule.OwnerConversationId,
            rule.IsEnabled,
            rule.ActivatedAtUtc.UtcTicks,
            new TriggerRecord(
                (int)rule.Trigger.Kind,
                rule.Trigger.SourceConversationId,
                rule.Trigger.SourcePresetMessageId,
                rule.Trigger.ScheduledAtUtc?.UtcTicks),
            new DestinationRecord(
                (int)rule.Destination.Kind,
                rule.Destination.ConversationId),
            rule.Conditions.Select(value => (int)value).ToList(),
            rule.Actions.Select(action => new ActionRecord(
                (int)action.Kind,
                action.PresetOwnerConversationId,
                action.PresetMessageId,
                action.Order)).ToList(),
            rule.DefinitionDigest);

    private static string ComputeChecksum(
        int schemaVersion,
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<RuleRecord> rules)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new RuleIntegrityPayload(
                schemaVersion,
                generation,
                requiresConservativeRecovery,
                rules),
            JsonOptions);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static bool HasBlockingIssues(WorkflowRuleGraphValidationResult validation) =>
        validation.Issues.Any(issue =>
            issue.Code != WorkflowRuleValidationIssueCode.NewConversationUnavailable);

    private WorkflowRuleStoreSnapshot CreateSnapshot() =>
        new(
            _readStatus,
            _generation,
            _requiresConservativeRecovery,
            _rules.ToArray(),
            _validation);

    private void MarkCorrupted()
    {
        _rules.Clear();
        _requiresConservativeRecovery = true;
        _validation = WorkflowRuleGraphValidator.Validate([]);
        _readStatus = WorkflowRuleStoreReadStatus.Corrupted;
    }

    private void MarkUnsupported()
    {
        _rules.Clear();
        _requiresConservativeRecovery = true;
        _unsupportedSchema = true;
        _validation = WorkflowRuleGraphValidator.Validate([]);
        _readStatus = WorkflowRuleStoreReadStatus.UnsupportedSchema;
    }

    private void ThrowIfUnsupportedSchema()
    {
        if (_unsupportedSchema)
        {
            throw new NotSupportedException("The workflow rule schema is newer than this build.");
        }
    }

    private static bool IsSha256(string? value) =>
        value is { Length: SHA256.HashSizeInBytes * 2 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private sealed record RuleReadResult(
        WorkflowRuleStoreReadStatus Status,
        RuleDocument? Document);

    private sealed record RuleDocument(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        List<RuleRecord>? Rules);

    private sealed record RuleIntegrityPayload(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<RuleRecord> Rules);

    private sealed record RuleRecord(
        int RuleSchemaVersion,
        string RuleId,
        int Revision,
        string OwnerConversationId,
        bool IsEnabled,
        long ActivatedAtUtcTicks,
        TriggerRecord? Trigger,
        DestinationRecord? Destination,
        List<int>? Conditions,
        List<ActionRecord>? Actions,
        string DefinitionDigest);

    private sealed record TriggerRecord(
        int Kind,
        string? SourceConversationId,
        string? SourcePresetMessageId,
        long? ScheduledAtUtcTicks);

    private sealed record DestinationRecord(
        int Kind,
        string? ConversationId);

    private sealed record ActionRecord(
        int Kind,
        string? PresetOwnerConversationId,
        string? PresetMessageId,
        int Order);
}
