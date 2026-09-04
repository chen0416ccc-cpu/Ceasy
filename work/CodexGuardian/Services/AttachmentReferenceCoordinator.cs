using CodexGuardian.Models;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CodexGuardian.Services;

public enum AttachmentOperationReferenceState
{
    Prepared,
    Dispatching,
    Retryable,
    Uncertain,
    Confirmed
}

public sealed record AttachmentOperationReference(
    string ContentId,
    AttachmentOperationReferenceState State,
    bool SuccessorCompletedNormally,
    bool RecoveryLineageClosed);

public sealed record AttachmentReferenceAuthoritySnapshot(
    bool IsHealthy,
    long FollowUpJournalGeneration,
    long RecoveryJournalGeneration,
    long DraftVersion,
    long LeaseVersion,
    long TransactionVersion,
    IReadOnlyList<string> DraftContentIds,
    IReadOnlyList<string> LeaseContentIds,
    IReadOnlyList<string> TransactionContentIds,
    IReadOnlyList<AttachmentOperationReference> Operations);

public interface IAttachmentReferenceAuthorityReader
{
    Task<AttachmentReferenceAuthoritySnapshot> ReadAsync(
        CancellationToken cancellationToken);
}

internal enum AttachmentCleanupStatus
{
    ProofStale,
    CleanupPending,
    Deleted
}

internal sealed record AttachmentCleanupResult(
    AttachmentCleanupStatus Status,
    string CleanupMarkerPath);

internal sealed record AttachmentCleanupBatchResult(
    bool IsHealthy,
    int DeletedCount,
    int CleanupPendingCount,
    int ProofStaleCount);

internal static class AttachmentMutationLeaseRegistry
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> RootGates =
        new(StringComparer.OrdinalIgnoreCase);

    internal static SemaphoreSlim Get(string dataDirectory)
    {
        var normalized = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        var key = Path.TrimEndingDirectorySeparator(normalized);
        return RootGates.GetOrAdd(key, static _ => new SemaphoreSlim(1, 1));
    }
}

internal sealed class AttachmentReferenceCoordinator
{
    private const int CleanupMarkerSchemaVersion = 1;
    private static readonly TimeSpan ProcessMutexPollInterval = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan CleanupRetryDelay = TimeSpan.FromMinutes(5);

    private readonly string _dataDirectory;
    private readonly string _cleanupRoot;
    private readonly string _processMutexName;
    private readonly ManagedAttachmentStore _store;
    private readonly SettingsService _settingsService;
    private readonly IAttachmentReferenceAuthorityReader _authorityReader;
    private readonly SemaphoreSlim _attachmentMutationGate;

    public AttachmentReferenceCoordinator(
        string dataDirectory,
        ManagedAttachmentStore store,
        SettingsService settingsService,
        IAttachmentReferenceAuthorityReader authorityReader)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(settingsService);
        ArgumentNullException.ThrowIfNull(authorityReader);

        _dataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        if (!PathsEqual(_dataDirectory, store.DataDirectory) ||
            !PathsEqual(_dataDirectory, settingsService.DataDirectory))
        {
            throw new ArgumentException(
                "The attachment coordinator, store, and settings service must share one data root.",
                nameof(dataDirectory));
        }

        _store = store;
        _settingsService = settingsService;
        _authorityReader = authorityReader;
        _attachmentMutationGate = AttachmentMutationLeaseRegistry.Get(_dataDirectory);
        _cleanupRoot = Path.Combine(_store.AttachmentRoot, "cleanup");
        _processMutexName = CreateProcessMutexName(_dataDirectory);
    }

    internal string DataDirectory => _dataDirectory;

    public Task<ZeroReferenceProof?> TryCreateZeroReferenceProofAsync(
        string contentId,
        CancellationToken cancellationToken)
    {
        EnsureCanonicalContentId(contentId);
        return ExecuteWithProcessMutexAsync(
            async () =>
            {
                await _attachmentMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var state = await TryReadReferenceStateAsync(contentId, cancellationToken)
                        .ConfigureAwait(false);
                    return state?.CreateProof(contentId);
                }
                finally
                {
                    _attachmentMutationGate.Release();
                }
            },
            cancellationToken);
    }

    public Task<AttachmentCleanupResult> DeleteAsync(
        ZeroReferenceProof proof,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proof);
        EnsureCanonicalContentId(proof.ContentId);
        var cleanupMarkerPath = GetCleanupMarkerPath(proof.ContentId);
        return ExecuteWithProcessMutexAsync(
            async () =>
            {
                await _attachmentMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var current = await TryReadReferenceStateAsync(
                            proof.ContentId,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (current is null || !current.Matches(proof))
                    {
                        return new AttachmentCleanupResult(
                            AttachmentCleanupStatus.ProofStale,
                            cleanupMarkerPath);
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    var physicalResult = _store.Delete(proof, cancellationToken);
                    if (!physicalResult.Deleted)
                    {
                        await WriteCleanupMarkerAsync(
                                cleanupMarkerPath,
                                proof.ContentId,
                                physicalResult.FailureClass,
                                CancellationToken.None)
                            .ConfigureAwait(false);
                        return new AttachmentCleanupResult(
                            AttachmentCleanupStatus.CleanupPending,
                            cleanupMarkerPath);
                    }

                    try
                    {
                        DeleteCleanupMarker(cleanupMarkerPath);
                    }
                    catch (Exception exception) when (
                        exception is IOException or UnauthorizedAccessException or NotSupportedException)
                    {
                        await WriteCleanupMarkerAsync(
                                cleanupMarkerPath,
                                proof.ContentId,
                                "MarkerCleanupFailed",
                                CancellationToken.None)
                            .ConfigureAwait(false);
                        return new AttachmentCleanupResult(
                            AttachmentCleanupStatus.CleanupPending,
                            cleanupMarkerPath);
                    }

                    return new AttachmentCleanupResult(
                        AttachmentCleanupStatus.Deleted,
                        cleanupMarkerPath);
                }
                finally
                {
                    _attachmentMutationGate.Release();
                }
            },
            cancellationToken);
    }

    internal async Task RequestZeroReferenceCleanupAsync(
        IReadOnlyList<string> contentIds,
        CancellationToken cancellationToken)
    {
        _ = await RequestZeroReferenceCleanupWithResultAsync(contentIds, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<AttachmentCleanupBatchResult> RequestZeroReferenceCleanupWithResultAsync(
        IReadOnlyList<string> contentIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(contentIds);
        var deletedCount = 0;
        var cleanupPendingCount = 0;
        var proofStaleCount = 0;
        foreach (var contentId in contentIds.Distinct(StringComparer.Ordinal))
        {
            EnsureCanonicalContentId(contentId);
            cancellationToken.ThrowIfCancellationRequested();
            var proof = await TryCreateZeroReferenceProofAsync(contentId, cancellationToken)
                .ConfigureAwait(false);
            if (proof is null)
            {
                proofStaleCount++;
                continue;
            }

            var cleanup = await DeleteAsync(proof, cancellationToken).ConfigureAwait(false);
            switch (cleanup.Status)
            {
                case AttachmentCleanupStatus.Deleted:
                    deletedCount++;
                    break;
                case AttachmentCleanupStatus.CleanupPending:
                    cleanupPendingCount++;
                    break;
                default:
                    proofStaleCount++;
                    break;
            }
        }

        return new AttachmentCleanupBatchResult(
            IsHealthy: cleanupPendingCount == 0 && proofStaleCount == 0,
            deletedCount,
            cleanupPendingCount,
            proofStaleCount);
    }

    private async Task<CapturedReferenceState?> TryReadReferenceStateAsync(
        string contentId,
        CancellationToken cancellationToken)
    {
        try
        {
            var settings = await _settingsService
                .ReadAttachmentReferenceSnapshotUnderMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var authority = await _authorityReader.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!settings.IsHealthy ||
                !IsAuthoritySnapshotValid(authority) ||
                settings.CurrentContentIds.Contains(contentId, StringComparer.Ordinal) ||
                settings.PreviousContentIds.Contains(contentId, StringComparer.Ordinal) ||
                authority.DraftContentIds.Contains(contentId, StringComparer.Ordinal) ||
                authority.LeaseContentIds.Contains(contentId, StringComparer.Ordinal) ||
                authority.TransactionContentIds.Contains(contentId, StringComparer.Ordinal) ||
                authority.Operations.Any(operation => IsPinned(operation, contentId)))
            {
                return null;
            }

            return new CapturedReferenceState(
                settings.SettingsGeneration,
                settings.PreviousSettingsGeneration,
                authority.FollowUpJournalGeneration,
                authority.RecoveryJournalGeneration,
                authority.DraftVersion,
                authority.LeaseVersion,
                authority.TransactionVersion);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                JsonException or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    private static bool IsAuthoritySnapshotValid(AttachmentReferenceAuthoritySnapshot? snapshot)
    {
        if (snapshot is null ||
            !snapshot.IsHealthy ||
            snapshot.FollowUpJournalGeneration < 0 ||
            snapshot.RecoveryJournalGeneration < 0 ||
            snapshot.DraftVersion < 0 ||
            snapshot.LeaseVersion < 0 ||
            snapshot.TransactionVersion < 0 ||
            snapshot.DraftContentIds is null ||
            snapshot.LeaseContentIds is null ||
            snapshot.TransactionContentIds is null ||
            snapshot.Operations is null)
        {
            return false;
        }

        if (snapshot.DraftContentIds
                .Concat(snapshot.LeaseContentIds)
                .Concat(snapshot.TransactionContentIds)
                .Any(contentId => !AttachmentIdentity.IsCanonicalContentId(contentId)))
        {
            return false;
        }

        return snapshot.Operations.All(operation =>
            operation is not null &&
            AttachmentIdentity.IsCanonicalContentId(operation.ContentId));
    }

    private static bool IsPinned(AttachmentOperationReference operation, string contentId)
    {
        if (!string.Equals(operation.ContentId, contentId, StringComparison.Ordinal))
        {
            return false;
        }

        return operation.State switch
        {
            AttachmentOperationReferenceState.Prepared => true,
            AttachmentOperationReferenceState.Dispatching => true,
            AttachmentOperationReferenceState.Retryable => true,
            AttachmentOperationReferenceState.Uncertain => true,
            AttachmentOperationReferenceState.Confirmed =>
                !operation.SuccessorCompletedNormally && !operation.RecoveryLineageClosed,
            _ => true
        };
    }

    internal static bool IsOperationReferencePinned(
        AttachmentOperationReference operation,
        string contentId)
    {
        ArgumentNullException.ThrowIfNull(operation);
        EnsureCanonicalContentId(contentId);
        return IsPinned(operation, contentId);
    }

    private Task<T> ExecuteWithProcessMutexAsync<T>(
        Func<Task<T>> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        return Task.Factory.StartNew(
            () =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var processMutex = new Mutex(initiallyOwned: false, _processMutexName);
                var acquired = false;
                try
                {
                    while (!acquired)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        try
                        {
                            acquired = processMutex.WaitOne(ProcessMutexPollInterval);
                        }
                        catch (AbandonedMutexException)
                        {
                            acquired = true;
                        }
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    return action().GetAwaiter().GetResult();
                }
                finally
                {
                    if (acquired)
                    {
                        processMutex.ReleaseMutex();
                    }
                }
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
    }

    private async Task WriteCleanupMarkerAsync(
        string markerPath,
        string contentId,
        string failureClass,
        CancellationToken cancellationToken)
    {
        var opaqueContentId = CreateOpaqueContentId(contentId);
        var marker = new CleanupMarker(
            CleanupMarkerSchemaVersion,
            opaqueContentId,
            NormalizeFailureClass(failureClass),
            DateTimeOffset.UtcNow.Add(CleanupRetryDelay));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(marker);
        if (bytes.LongLength > 512)
        {
            throw new InvalidDataException("The attachment cleanup marker exceeded its hard bound.");
        }

        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _cleanupRoot);
        Directory.CreateDirectory(_cleanupRoot);
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _cleanupRoot);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, markerPath);

        var temporaryPath = Path.Combine(
            _cleanupRoot,
            $".cleanup.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        try
        {
            DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, temporaryPath);
            await using (var stream = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             bufferSize: 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            DataDirectorySafety.Revalidate(_dataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, temporaryPath);
            DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, markerPath);
            if (File.Exists(markerPath))
            {
                File.Replace(
                    temporaryPath,
                    markerPath,
                    destinationBackupFileName: null,
                    ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, markerPath);
            }
        }
        finally
        {
            DataDirectorySafety.Revalidate(_dataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, temporaryPath);
            File.Delete(temporaryPath);
        }
    }

    private void DeleteCleanupMarker(string markerPath)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, _cleanupRoot);
        if (File.Exists(_cleanupRoot))
        {
            throw new IOException("The attachment cleanup root is not a directory.");
        }

        if (!Directory.Exists(_cleanupRoot))
        {
            return;
        }

        var rootAttributes = File.GetAttributes(_cleanupRoot);
        if ((rootAttributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
        {
            throw new IOException("The attachment cleanup root is unsafe.");
        }

        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, markerPath);
        File.Delete(markerPath);
        if (File.Exists(markerPath) || Directory.Exists(markerPath))
        {
            throw new IOException("The attachment cleanup marker remained after deletion.");
        }
    }

    private string GetCleanupMarkerPath(string contentId) =>
        Path.Combine(_cleanupRoot, CreateOpaqueContentId(contentId) + ".json");

    private string CreateOpaqueContentId(string contentId)
    {
        var bytes = Encoding.UTF8.GetBytes(
            "CodexFree.AttachmentCleanup\0" + _dataDirectory + "\0" + contentId);
        return Convert.ToHexString(SHA256.HashData(bytes).AsSpan(0, 16));
    }

    private static string CreateProcessMutexName(string dataDirectory)
    {
        var normalized = Path.TrimEndingDirectorySeparator(dataDirectory).ToUpperInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return @"Local\CodexFree.AttachmentReferences." +
               Convert.ToHexString(hash.AsSpan(0, 16));
    }

    private static string NormalizeFailureClass(string? failureClass) =>
        failureClass switch
        {
            "AccessDenied" => "AccessDenied",
            "MarkerCleanupFailed" => "MarkerCleanupFailed",
            "ObjectBusy" => "ObjectBusy",
            "StorageUnavailable" => "StorageUnavailable",
            "UnsafeObject" => "UnsafeObject",
            _ => "StorageUnavailable"
        };

    private static void EnsureCanonicalContentId(string contentId)
    {
        if (!AttachmentIdentity.IsCanonicalContentId(contentId))
        {
            throw new ArgumentException(
                "The attachment content identity must be canonical SHA-256.",
                nameof(contentId));
        }
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(left),
            Path.TrimEndingDirectorySeparator(right),
            StringComparison.OrdinalIgnoreCase);

    private sealed record CleanupMarker(
        int SchemaVersion,
        string OpaqueContentId,
        string FailureClass,
        DateTimeOffset RetryAfterUtc);

    private sealed record CapturedReferenceState(
        long SettingsGeneration,
        long PreviousSettingsGeneration,
        long FollowUpJournalGeneration,
        long RecoveryJournalGeneration,
        long DraftVersion,
        long LeaseVersion,
        long TransactionVersion)
    {
        internal ZeroReferenceProof CreateProof(string contentId) =>
            new(
                contentId,
                SettingsGeneration,
                PreviousSettingsGeneration,
                FollowUpJournalGeneration,
                RecoveryJournalGeneration,
                DraftVersion,
                LeaseVersion,
                TransactionVersion);

        internal bool Matches(ZeroReferenceProof proof) =>
            SettingsGeneration == proof.SettingsGeneration &&
            PreviousSettingsGeneration == proof.PreviousSettingsGeneration &&
            FollowUpJournalGeneration == proof.FollowUpJournalGeneration &&
            RecoveryJournalGeneration == proof.RecoveryJournalGeneration &&
            DraftVersion == proof.DraftVersion &&
            LeaseVersion == proof.LeaseVersion &&
            TransactionVersion == proof.TransactionVersion;
    }
}
