using CodexGuardian.Models;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Services;

internal sealed record AttachmentPresentationRequirements(
    bool SupportsSeparateDisplayName,
    bool RequiresFileNameSuffix,
    bool AllowHardLinks);

internal sealed record AttachmentPresentationCleanupAuthorization(
    bool RecoveryLineageClosed,
    bool ZeroReferenceProven);

internal enum AttachmentPresentationCleanupStatus
{
    Retained,
    CleanupPending,
    Deleted
}

internal sealed record AttachmentPresentationCleanupResult(
    AttachmentPresentationCleanupStatus Status,
    string LeaseId);

internal sealed record AttachmentPresentationLease(
    string LeaseId,
    string OperationId,
    string PayloadDigest,
    long Generation,
    string LeaseDirectory,
    IReadOnlyList<string> ContentIds,
    IReadOnlyDictionary<string, string> PresentationPaths);

internal sealed record AttachmentRecoveryReplayItem(
    int Order,
    string ContentId,
    long ByteLength,
    string DetectedType,
    string OwnerInputKind,
    string PresentationPath);

internal sealed class AttachmentRecoveryReplayLease : IAsyncDisposable
{
    private IReadOnlyList<FileStream>? _lockedHandles;

    internal AttachmentRecoveryReplayLease(
        string leaseId,
        string operationId,
        string payloadDigest,
        long generation,
        IReadOnlyList<AttachmentRecoveryReplayItem> items,
        IReadOnlyList<FileStream> lockedHandles)
    {
        LeaseId = leaseId;
        OperationId = operationId;
        PayloadDigest = payloadDigest;
        Generation = generation;
        Items = items;
        _lockedHandles = lockedHandles;
    }

    internal string LeaseId { get; }

    internal string OperationId { get; }

    internal string PayloadDigest { get; }

    internal long Generation { get; }

    internal IReadOnlyList<AttachmentRecoveryReplayItem> Items { get; }

    internal bool IsCurrent => Volatile.Read(ref _lockedHandles) is not null;

    public async ValueTask DisposeAsync()
    {
        var handles = Interlocked.Exchange(ref _lockedHandles, null);
        if (handles is null)
        {
            return;
        }

        for (var index = handles.Count - 1; index >= 0; index--)
        {
            await handles[index].DisposeAsync().ConfigureAwait(false);
        }
    }
}

internal enum AttachmentPresentationReferenceState
{
    Materializing,
    Ready,
    CleanupPending
}

internal sealed record AttachmentPresentationReference(
    string LeaseId,
    string OperationId,
    string PayloadDigest,
    long Generation,
    AttachmentPresentationReferenceState State,
    IReadOnlyList<string> ContentIds);

internal sealed record AttachmentPresentationReferenceSnapshot(
    bool IsHealthy,
    long LeaseVersion,
    long TransactionVersion,
    IReadOnlyList<AttachmentPresentationReference> References);

internal sealed class AttachmentPresentationException : IOException
{
    internal AttachmentPresentationException(string code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal sealed class AttachmentPresentationLeaseService
{
    private const int TransactionSchemaVersion = 1;
    private const int MaximumTransactionBytes = 64 * 1024;
    private const int MaximumAuthorityLeaseCount = 4096;
    private const int CopyBufferBytes = 128 * 1024;
    private const int MaximumPresentationPathLength = 240;
    private const int MaximumStemLength = 48;
    private const int MaximumExtensionLength = 12;
    private const string CurrentTransactionName = "transaction.json";
    private const string PreviousTransactionName = "transaction.previous.json";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 32
    };
    private static readonly HashSet<string> ReservedDeviceNames = new(
        new[]
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        },
        StringComparer.OrdinalIgnoreCase);

    private readonly string _dataDirectory;
    private readonly ManagedAttachmentStore _store;
    private readonly SemaphoreSlim _mutationGate;

    internal AttachmentPresentationLeaseService(
        string dataDirectory,
        ManagedAttachmentStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _dataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        if (!PathsEqual(_dataDirectory, store.DataDirectory))
        {
            throw new ArgumentException(
                "The presentation service and managed attachment store must share one data root.",
                nameof(dataDirectory));
        }

        _store = store;
        _mutationGate = AttachmentMutationLeaseRegistry.Get(_dataDirectory);
        PresentationRoot = Path.Combine(_store.AttachmentRoot, "presentation-leases");
    }

    internal string PresentationRoot { get; }

    internal string DataDirectory => _dataDirectory;

    internal async Task<AttachmentPresentationReferenceSnapshot> ReadReferenceSnapshotAsync(
        CancellationToken cancellationToken)
    {
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return ReadReferenceSnapshotUnderMutationLease();
        }
        finally
        {
            _mutationGate.Release();
        }
    }

    internal AttachmentPresentationReferenceSnapshot ReadReferenceSnapshotUnderMutationLease()
    {
        try
        {
            DataDirectorySafety.Revalidate(_dataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, PresentationRoot);
            if (!Directory.Exists(PresentationRoot))
            {
                return EmptyReferenceSnapshot(isHealthy: true);
            }

            var rootAttributes = File.GetAttributes(PresentationRoot);
            if ((rootAttributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
                Directory.EnumerateFiles(PresentationRoot, "*", SearchOption.TopDirectoryOnly).Any())
            {
                return EmptyReferenceSnapshot(isHealthy: false);
            }

            var leaseDirectories = Directory
                .EnumerateDirectories(PresentationRoot, "*", SearchOption.TopDirectoryOnly)
                .Take(MaximumAuthorityLeaseCount + 1)
                .Order(StringComparer.Ordinal)
                .ToArray();
            if (leaseDirectories.Length > MaximumAuthorityLeaseCount)
            {
                return EmptyReferenceSnapshot(isHealthy: false);
            }

            var references = new List<AttachmentPresentationReference>(leaseDirectories.Length);
            var operationIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var leaseDirectory in leaseDirectories)
            {
                var attributes = File.GetAttributes(leaseDirectory);
                var leaseId = Path.GetFileName(leaseDirectory);
                if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
                    !IsCanonicalLeaseId(leaseId))
                {
                    return EmptyReferenceSnapshot(isHealthy: false);
                }

                var envelope = ReadConsistentEnvelope(leaseDirectory);
                var transaction = envelope.Transaction;
                if (!string.Equals(transaction.LeaseId, leaseId, StringComparison.Ordinal) ||
                    !operationIds.Add(transaction.OperationId))
                {
                    return EmptyReferenceSnapshot(isHealthy: false);
                }

                references.Add(new AttachmentPresentationReference(
                    transaction.LeaseId,
                    transaction.OperationId,
                    transaction.PayloadDigest,
                    envelope.Generation,
                    transaction.State switch
                    {
                        PresentationTransactionState.Materializing =>
                            AttachmentPresentationReferenceState.Materializing,
                        PresentationTransactionState.Ready =>
                            AttachmentPresentationReferenceState.Ready,
                        PresentationTransactionState.CleanupPending =>
                            AttachmentPresentationReferenceState.CleanupPending,
                        _ => throw Failure(
                            "transaction-state",
                            "The presentation transaction state is invalid.")
                    },
                    Array.AsReadOnly(transaction.Entries
                        .OrderBy(entry => entry.Order)
                        .Select(entry => entry.ContentId)
                        .Distinct(StringComparer.Ordinal)
                        .ToArray())));
            }

            return new AttachmentPresentationReferenceSnapshot(
                IsHealthy: true,
                LeaseVersion: ComputeReferenceVersion(
                    references.Where(reference =>
                        reference.State == AttachmentPresentationReferenceState.Ready)),
                TransactionVersion: ComputeReferenceVersion(
                    references.Where(reference =>
                        reference.State != AttachmentPresentationReferenceState.Ready)),
                References: references.AsReadOnly());
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                JsonException or NotSupportedException or ArgumentException)
        {
            return EmptyReferenceSnapshot(isHealthy: false);
        }
    }

    internal async Task<AttachmentPresentationLease> AcquireAsync(
        string operationId,
        StructuredPresetPayload payload,
        IReadOnlyDictionary<string, ManagedAttachmentObject> managedObjects,
        AttachmentPresentationRequirements requirements,
        CancellationToken cancellationToken)
    {
        ValidateOperationId(operationId);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(managedObjects);
        ArgumentNullException.ThrowIfNull(requirements);
        if (!payload.HasValidIdentity() || payload.Attachments.Count == 0)
        {
            throw Failure(
                "payload-identity-invalid",
                "A valid structured payload with attachments is required for presentation.");
        }

        var leaseId = CreateLeaseId(operationId, payload.PayloadDigest);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsurePresentationRoot();
            var leaseDirectory = GetLeaseDirectory(leaseId);
            var currentPath = Path.Combine(leaseDirectory, CurrentTransactionName);
            if (Directory.Exists(leaseDirectory))
            {
                var existing = ReadConsistentEnvelope(leaseDirectory);
                ValidateTransactionIdentity(existing.Transaction, leaseId, operationId, payload);
                if (existing.Transaction.State == PresentationTransactionState.Ready)
                {
                    var restored = BuildLease(existing, leaseDirectory);
                    if (!await VerifyCoreAsync(restored, payload, cancellationToken).ConfigureAwait(false))
                    {
                        throw Failure(
                            "lease-verification-failed",
                            "The existing presentation lease no longer matches its managed content.");
                    }

                    return restored;
                }

                if (existing.Transaction.State == PresentationTransactionState.CleanupPending)
                {
                    throw Failure(
                        "lease-cleanup-pending",
                        "A presentation lease already authorized for cleanup cannot be reacquired.");
                }

                DeleteIncompleteLeaseDirectory(leaseDirectory);
            }

            CreateValidatedDirectory(leaseDirectory);
            var entries = BuildEntries(payload, requirements, leaseDirectory);
            var materializing = new PresentationTransaction(
                TransactionSchemaVersion,
                leaseId,
                operationId,
                payload.PayloadDigest,
                PresentationTransactionState.Materializing,
                requirements,
                entries);
            WriteEnvelope(currentPath, materializing, generation: 1);

            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var reference = payload.Attachments[entry.Order];
                if (!managedObjects.TryGetValue(reference.ContentId, out var managedObject) ||
                    !ManagedObjectMatches(reference, managedObject) ||
                    !PathsEqual(
                        managedObject.ObjectPath,
                        GetManagedObjectPath(reference.ContentId)) ||
                    !await _store.VerifyAsync(reference, cancellationToken).ConfigureAwait(false))
                {
                    throw Failure(
                        "managed-object-invalid",
                        "The managed attachment object could not be reverified for presentation.");
                }

                if (!entry.UsesManagedObjectPath)
                {
                    var destinationPath = Path.Combine(leaseDirectory, entry.RelativeFileName!);
                    await CopyAndVerifyAsync(
                            managedObject.ObjectPath,
                            destinationPath,
                            reference.ContentId,
                            reference.ByteLength,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            var ready = materializing with { State = PresentationTransactionState.Ready };
            WriteEnvelope(currentPath, ready, generation: 2);
            var envelope = ReadEnvelope(currentPath);
            var lease = BuildLease(envelope, leaseDirectory);
            if (!await VerifyCoreAsync(lease, payload, cancellationToken).ConfigureAwait(false))
            {
                throw Failure(
                    "lease-verification-failed",
                    "The completed presentation lease failed final verification.");
            }

            return lease;
        }
        finally
        {
            _mutationGate.Release();
        }
    }

    internal async Task<bool> VerifyAsync(
        AttachmentPresentationLease lease,
        StructuredPresetPayload payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(payload);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await VerifyCoreAsync(lease, payload, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                JsonException or ArgumentException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            _mutationGate.Release();
        }
    }

    internal async Task<AttachmentRecoveryReplayLease> AcquireRecoveryReplayLeaseAsync(
        string leaseId,
        CancellationToken cancellationToken)
    {
        ValidateLeaseId(leaseId);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var lockedHandles = new List<FileStream>();
        try
        {
            DataDirectorySafety.Revalidate(_dataDirectory);
            var leaseDirectory = GetLeaseDirectory(leaseId);
            DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, leaseDirectory);
            if (!Directory.Exists(leaseDirectory) ||
                (File.GetAttributes(leaseDirectory) &
                 (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            {
                throw Failure("replay-lease-unavailable", "The replay lease is unavailable.");
            }

            var currentPath = Path.Combine(leaseDirectory, CurrentTransactionName);
            var previousPath = Path.Combine(leaseDirectory, PreviousTransactionName);
            lockedHandles.Add(OpenLockedReadHandle(currentPath));
            lockedHandles.Add(OpenLockedReadHandle(previousPath));

            var envelope = ReadConsistentEnvelope(leaseDirectory);
            var transaction = envelope.Transaction;
            if (transaction.State != PresentationTransactionState.Ready ||
                !string.Equals(transaction.LeaseId, leaseId, StringComparison.Ordinal))
            {
                throw Failure("replay-lease-state", "The replay lease is not ready.");
            }

            var items = new List<AttachmentRecoveryReplayItem>(transaction.Entries.Count);
            foreach (var entry in transaction.Entries.OrderBy(static entry => entry.Order))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var path = entry.UsesManagedObjectPath
                    ? GetManagedObjectPath(entry.ContentId)
                    : Path.Combine(leaseDirectory, entry.RelativeFileName!);
                DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, path);
                var attributes = File.GetAttributes(path);
                if ((attributes &
                     (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                {
                    throw Failure("replay-file-unsafe", "A replay attachment path is unsafe.");
                }

                var handle = OpenLockedReadHandle(path);
                lockedHandles.Add(handle);
                if (!await VerifyLockedFileAsync(
                        handle,
                        entry.ContentId,
                        entry.ByteLength,
                        cancellationToken)
                    .ConfigureAwait(false))
                {
                    throw Failure("replay-file-mismatch", "A replay attachment changed.");
                }

                items.Add(new AttachmentRecoveryReplayItem(
                    entry.Order,
                    entry.ContentId,
                    entry.ByteLength,
                    entry.DetectedType,
                    entry.OwnerInputKind,
                    path));
            }

            var lease = new AttachmentRecoveryReplayLease(
                transaction.LeaseId,
                transaction.OperationId,
                transaction.PayloadDigest,
                envelope.Generation,
                Array.AsReadOnly(items.ToArray()),
                Array.AsReadOnly(lockedHandles.ToArray()));
            lockedHandles = [];
            return lease;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AttachmentPresentationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                JsonException or NotSupportedException or ArgumentException)
        {
            throw Failure(
                "replay-lease-unavailable",
                "The replay presentation lease could not be locked.",
                exception);
        }
        finally
        {
            foreach (var handle in lockedHandles)
            {
                await handle.DisposeAsync().ConfigureAwait(false);
            }

            _mutationGate.Release();
        }
    }

    internal async Task<AttachmentPresentationCleanupResult> CleanupAsync(
        string leaseId,
        AttachmentPresentationCleanupAuthorization authorization,
        CancellationToken cancellationToken)
    {
        ValidateLeaseId(leaseId);
        ArgumentNullException.ThrowIfNull(authorization);
        if (!authorization.RecoveryLineageClosed || !authorization.ZeroReferenceProven)
        {
            return new AttachmentPresentationCleanupResult(
                AttachmentPresentationCleanupStatus.Retained,
                leaseId);
        }

        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return CleanupUnderMutationLease(leaseId, authorization);
        }
        finally
        {
            _mutationGate.Release();
        }
    }

    internal AttachmentPresentationCleanupResult CleanupUnderMutationLease(
        string leaseId,
        AttachmentPresentationCleanupAuthorization authorization)
    {
        ValidateLeaseId(leaseId);
        ArgumentNullException.ThrowIfNull(authorization);
        if (!authorization.RecoveryLineageClosed || !authorization.ZeroReferenceProven)
        {
            return new AttachmentPresentationCleanupResult(
                AttachmentPresentationCleanupStatus.Retained,
                leaseId);
        }

        var leaseDirectory = GetLeaseDirectory(leaseId);
        if (!Directory.Exists(leaseDirectory))
        {
            return new AttachmentPresentationCleanupResult(
                AttachmentPresentationCleanupStatus.Deleted,
                leaseId);
        }

        try
        {
            DataDirectorySafety.Revalidate(_dataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, leaseDirectory);
            var currentPath = Path.Combine(leaseDirectory, CurrentTransactionName);
            var envelope = ReadConsistentEnvelope(leaseDirectory);
            if (!string.Equals(
                    envelope.Transaction.LeaseId,
                    leaseId,
                    StringComparison.Ordinal))
            {
                throw Failure("lease-identity-mismatch", "The cleanup lease identity changed.");
            }

            if (envelope.Transaction.State != PresentationTransactionState.CleanupPending)
            {
                var cleanupPending = envelope.Transaction with
                {
                    State = PresentationTransactionState.CleanupPending
                };
                WriteEnvelope(currentPath, cleanupPending, checked(envelope.Generation + 1));
            }

            DeleteLeaseFilesInSafeOrder(leaseDirectory);
            if (Directory.Exists(leaseDirectory))
            {
                throw new IOException("The presentation lease directory remained after cleanup.");
            }

            return new AttachmentPresentationCleanupResult(
                AttachmentPresentationCleanupStatus.Deleted,
                leaseId);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                JsonException or NotSupportedException or ArgumentException)
        {
            return new AttachmentPresentationCleanupResult(
                AttachmentPresentationCleanupStatus.CleanupPending,
                leaseId);
        }
    }

    private async Task<bool> VerifyCoreAsync(
        AttachmentPresentationLease lease,
        StructuredPresetPayload payload,
        CancellationToken cancellationToken)
    {
        if (!payload.HasValidIdentity() ||
            !IsCanonicalLeaseId(lease.LeaseId) ||
            !IsCanonicalOperationId(lease.OperationId) ||
            !string.Equals(lease.PayloadDigest, payload.PayloadDigest, StringComparison.Ordinal) ||
            !string.Equals(lease.LeaseDirectory, GetLeaseDirectory(lease.LeaseId), StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(lease.LeaseDirectory))
        {
            return false;
        }

        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, lease.LeaseDirectory);
        var envelope = ReadConsistentEnvelope(lease.LeaseDirectory);
        var transaction = envelope.Transaction;
        if (transaction.State != PresentationTransactionState.Ready ||
            envelope.Generation != lease.Generation ||
            !string.Equals(transaction.LeaseId, lease.LeaseId, StringComparison.Ordinal) ||
            !string.Equals(transaction.OperationId, lease.OperationId, StringComparison.Ordinal) ||
            !string.Equals(transaction.PayloadDigest, payload.PayloadDigest, StringComparison.Ordinal) ||
            transaction.Entries.Count != payload.Attachments.Count ||
            lease.PresentationPaths.Count != payload.Attachments.Count)
        {
            return false;
        }

        for (var index = 0; index < transaction.Entries.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = transaction.Entries[index];
            var reference = payload.Attachments[index];
            if (!EntryMatches(entry, reference) ||
                !lease.PresentationPaths.TryGetValue(reference.Id, out var leasedPath))
            {
                return false;
            }

            var expectedPath = entry.UsesManagedObjectPath
                ? GetManagedObjectPath(reference.ContentId)
                : Path.Combine(lease.LeaseDirectory, entry.RelativeFileName!);
            if (!string.Equals(leasedPath, expectedPath, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (entry.UsesManagedObjectPath)
            {
                if (!await _store.VerifyAsync(reference, cancellationToken).ConfigureAwait(false))
                {
                    return false;
                }
            }
            else if (!await VerifyFileAsync(
                           expectedPath,
                           reference.ContentId,
                           reference.ByteLength,
                           cancellationToken)
                       .ConfigureAwait(false))
            {
                return false;
            }
        }

        return lease.ContentIds.SequenceEqual(
            payload.Attachments.Select(reference => reference.ContentId).Distinct(StringComparer.Ordinal),
            StringComparer.Ordinal);
    }

    private List<PresentationEntry> BuildEntries(
        StructuredPresetPayload payload,
        AttachmentPresentationRequirements requirements,
        string leaseDirectory)
    {
        var useManagedObjectPath =
            requirements.SupportsSeparateDisplayName && !requirements.RequiresFileNameSuffix;
        var entries = new List<PresentationEntry>(payload.Attachments.Count);
        foreach (var reference in payload.Attachments)
        {
            string? relativeFileName = null;
            if (!useManagedObjectPath)
            {
                relativeFileName = CreatePresentationFileName(reference);
                var presentationPath = Path.Combine(leaseDirectory, relativeFileName);
                if (presentationPath.Length > MaximumPresentationPathLength)
                {
                    relativeFileName = CreateCompactPresentationFileName(reference);
                    presentationPath = Path.Combine(leaseDirectory, relativeFileName);
                }

                if (presentationPath.Length > MaximumPresentationPathLength)
                {
                    throw Failure(
                        "presentation-path-too-long",
                        "The deterministic presentation path exceeds the Desktop path bound.");
                }
            }

            entries.Add(new PresentationEntry(
                reference.Order,
                reference.Id,
                reference.ContentId,
                reference.ByteLength,
                reference.DetectedType,
                reference.OwnerInputKind,
                useManagedObjectPath,
                relativeFileName));
        }

        if (entries.Where(entry => entry.RelativeFileName is not null)
            .Select(entry => entry.RelativeFileName!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count() != entries.Count(entry => entry.RelativeFileName is not null))
        {
            throw Failure("presentation-name-collision", "Presentation filenames collided.");
        }

        return entries;
    }

    private AttachmentPresentationLease BuildLease(
        PresentationEnvelope envelope,
        string leaseDirectory)
    {
        var transaction = envelope.Transaction;
        var paths = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in transaction.Entries.OrderBy(value => value.Order))
        {
            paths.Add(
                entry.ReferenceId,
                entry.UsesManagedObjectPath
                    ? GetManagedObjectPath(entry.ContentId)
                    : Path.Combine(leaseDirectory, entry.RelativeFileName!));
        }

        return new AttachmentPresentationLease(
            transaction.LeaseId,
            transaction.OperationId,
            transaction.PayloadDigest,
            envelope.Generation,
            leaseDirectory,
            Array.AsReadOnly(transaction.Entries
                .OrderBy(value => value.Order)
                .Select(value => value.ContentId)
                .Distinct(StringComparer.Ordinal)
                .ToArray()),
            new ReadOnlyDictionary<string, string>(paths));
    }

    private void WriteEnvelope(
        string currentPath,
        PresentationTransaction transaction,
        long generation)
    {
        ValidateTransaction(transaction);
        if (generation <= 0)
        {
            throw Failure("transaction-generation", "The presentation generation is invalid.");
        }

        var checksum = ComputeChecksum(generation, transaction);
        var envelope = new PresentationEnvelope(
            TransactionSchemaVersion,
            generation,
            transaction,
            checksum);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (bytes.Length > MaximumTransactionBytes)
        {
            throw Failure("transaction-size", "The presentation transaction exceeded its bound.");
        }

        var directory = Path.GetDirectoryName(currentPath)!;
        var previousPath = Path.Combine(directory, PreviousTransactionName);
        var temporaryPath = Path.Combine(
            directory,
            ".transaction." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".tmp");
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, directory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, currentPath);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, previousPath);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, temporaryPath);
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(currentPath))
            {
                File.Replace(temporaryPath, currentPath, previousPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, currentPath);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        var readback = ReadConsistentEnvelope(directory);
        if (readback.Generation != generation ||
            !string.Equals(readback.Checksum, checksum, StringComparison.Ordinal))
        {
            throw Failure("transaction-readback", "The presentation transaction readback failed.");
        }
    }

    private PresentationEnvelope ReadEnvelope(string path)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, path);
        var item = new FileInfo(path);
        if (!item.Exists || item.Length is <= 0 or > MaximumTransactionBytes)
        {
            throw Failure("transaction-unavailable", "The presentation transaction is unavailable or unbounded.");
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
        {
            throw Failure("transaction-unsafe", "The presentation transaction path is unsafe.");
        }

        try
        {
            var bytes = File.ReadAllBytes(path);
            var envelope = JsonSerializer.Deserialize<PresentationEnvelope>(bytes, JsonOptions)
                ?? throw Failure("transaction-json", "The presentation transaction is empty.");
            if (envelope.SchemaVersion != TransactionSchemaVersion ||
                envelope.Generation <= 0 ||
                !IsCanonicalSha256(envelope.Checksum))
            {
                throw Failure("transaction-schema", "The presentation transaction schema is invalid.");
            }

            ValidateTransaction(envelope.Transaction);
            var checksum = ComputeChecksum(envelope.Generation, envelope.Transaction);
            if (!string.Equals(checksum, envelope.Checksum, StringComparison.Ordinal))
            {
                throw Failure("transaction-checksum", "The presentation transaction checksum is invalid.");
            }

            return envelope;
        }
        catch (AttachmentPresentationException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw Failure("transaction-json", "The presentation transaction JSON is invalid.", exception);
        }
    }

    private PresentationEnvelope ReadConsistentEnvelope(string leaseDirectory)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, leaseDirectory);
        var currentPath = Path.Combine(leaseDirectory, CurrentTransactionName);
        var previousPath = Path.Combine(leaseDirectory, PreviousTransactionName);
        var current = ReadEnvelope(currentPath);
        if (current.Generation == 1)
        {
            if (current.Transaction.State != PresentationTransactionState.Materializing ||
                File.Exists(previousPath))
            {
                throw Failure(
                    "transaction-history",
                    "The presentation transaction history is inconsistent.");
            }

            return current;
        }

        if (!File.Exists(previousPath))
        {
            throw Failure(
                "transaction-history",
                "The previous presentation transaction is unavailable.");
        }

        var previous = ReadEnvelope(previousPath);
        if (previous.Generation != current.Generation - 1 ||
            !HasSameTransactionIdentity(previous.Transaction, current.Transaction) ||
            !IsValidTransactionTransition(previous.Transaction.State, current.Transaction.State))
        {
            throw Failure(
                "transaction-history",
                "The presentation transaction history is inconsistent.");
        }

        return current;
    }

    private static bool HasSameTransactionIdentity(
        PresentationTransaction previous,
        PresentationTransaction current) =>
        previous.SchemaVersion == current.SchemaVersion &&
        string.Equals(previous.LeaseId, current.LeaseId, StringComparison.Ordinal) &&
        string.Equals(previous.OperationId, current.OperationId, StringComparison.Ordinal) &&
        string.Equals(previous.PayloadDigest, current.PayloadDigest, StringComparison.Ordinal) &&
        previous.Requirements == current.Requirements &&
        previous.Entries.SequenceEqual(current.Entries);

    private static bool IsValidTransactionTransition(
        PresentationTransactionState previous,
        PresentationTransactionState current) =>
        current switch
        {
            PresentationTransactionState.Ready =>
                previous == PresentationTransactionState.Materializing,
            PresentationTransactionState.CleanupPending =>
                previous is PresentationTransactionState.Materializing or
                    PresentationTransactionState.Ready,
            _ => false
        };

    private static string ComputeChecksum(long generation, PresentationTransaction transaction)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new PresentationChecksumPayload(TransactionSchemaVersion, generation, transaction),
            JsonOptions);
        return Convert.ToHexString(SHA256.HashData(payload));
    }

    private static AttachmentPresentationReferenceSnapshot EmptyReferenceSnapshot(bool isHealthy) =>
        new(
            isHealthy,
            LeaseVersion: 0,
            TransactionVersion: 0,
            References: Array.Empty<AttachmentPresentationReference>());

    private static long ComputeReferenceVersion(
        IEnumerable<AttachmentPresentationReference> references)
    {
        var canonical = string.Join(
            "\n",
            references
                .OrderBy(reference => reference.LeaseId, StringComparer.Ordinal)
                .Select(reference => string.Join(
                    "|",
                    reference.LeaseId,
                    reference.OperationId,
                    reference.PayloadDigest,
                    reference.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ((int)reference.State).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    string.Join(",", reference.ContentIds))));
        if (canonical.Length == 0)
        {
            return 0;
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        var version = BinaryPrimitives.ReadUInt64BigEndian(hash) & 0x7FFF_FFFF_FFFF_FFFFUL;
        return version == 0 ? 1 : checked((long)version);
    }

    private static void ValidateTransaction(PresentationTransaction? transaction)
    {
        if (transaction is null ||
            transaction.SchemaVersion != TransactionSchemaVersion ||
            !IsCanonicalLeaseId(transaction.LeaseId) ||
            !IsCanonicalOperationId(transaction.OperationId) ||
            !IsCanonicalSha256(transaction.PayloadDigest) ||
            !Enum.IsDefined(transaction.State) ||
            transaction.Requirements is null ||
            transaction.Entries is null ||
            transaction.Entries.Count is < 1 or > 1000)
        {
            throw Failure("transaction-invalid", "The presentation transaction is invalid.");
        }

        var seenReferences = new HashSet<string>(StringComparer.Ordinal);
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < transaction.Entries.Count; index++)
        {
            var entry = transaction.Entries[index];
            if (entry is null ||
                entry.Order != index ||
                !AttachmentIdentity.IsCanonicalReferenceId(entry.ReferenceId) ||
                !seenReferences.Add(entry.ReferenceId) ||
                !AttachmentIdentity.IsCanonicalContentId(entry.ContentId) ||
                entry.ByteLength <= 0 ||
                string.IsNullOrWhiteSpace(entry.DetectedType) ||
                string.IsNullOrWhiteSpace(entry.OwnerInputKind) ||
                entry.DetectedType.Length > 128 ||
                entry.OwnerInputKind.Length > 64 ||
                entry.UsesManagedObjectPath == (entry.RelativeFileName is not null) ||
                entry.RelativeFileName is not null &&
                (!string.Equals(
                     Path.GetFileName(entry.RelativeFileName),
                     entry.RelativeFileName,
                     StringComparison.Ordinal) ||
                 entry.RelativeFileName.Length > 128 ||
                 !seenNames.Add(entry.RelativeFileName)))
            {
                throw Failure("transaction-entry", "A presentation transaction entry is invalid.");
            }
        }
    }

    private static void ValidateTransactionIdentity(
        PresentationTransaction transaction,
        string leaseId,
        string operationId,
        StructuredPresetPayload payload)
    {
        if (!string.Equals(transaction.LeaseId, leaseId, StringComparison.Ordinal) ||
            !string.Equals(transaction.OperationId, operationId, StringComparison.Ordinal) ||
            !string.Equals(transaction.PayloadDigest, payload.PayloadDigest, StringComparison.Ordinal) ||
            transaction.Entries.Count != payload.Attachments.Count)
        {
            throw Failure("lease-identity-mismatch", "The existing presentation lease identity changed.");
        }

        for (var index = 0; index < transaction.Entries.Count; index++)
        {
            if (!EntryMatches(transaction.Entries[index], payload.Attachments[index]))
            {
                throw Failure("lease-identity-mismatch", "The existing presentation references changed.");
            }
        }
    }

    private static bool EntryMatches(PresentationEntry entry, PresetAttachmentReference reference) =>
        entry.Order == reference.Order &&
        string.Equals(entry.ReferenceId, reference.Id, StringComparison.Ordinal) &&
        string.Equals(entry.ContentId, reference.ContentId, StringComparison.Ordinal) &&
        entry.ByteLength == reference.ByteLength &&
        string.Equals(entry.DetectedType, reference.DetectedType, StringComparison.Ordinal) &&
        string.Equals(entry.OwnerInputKind, reference.OwnerInputKind, StringComparison.Ordinal);

    private static bool ManagedObjectMatches(
        PresetAttachmentReference reference,
        ManagedAttachmentObject managedObject) =>
        string.Equals(reference.ContentId, managedObject.ContentId, StringComparison.Ordinal) &&
        reference.ByteLength == managedObject.ByteLength &&
        string.Equals(reference.DetectedType, managedObject.DetectedType, StringComparison.Ordinal);

    private async Task CopyAndVerifyAsync(
        string sourcePath,
        string destinationPath,
        string expectedContentId,
        long expectedLength,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, sourcePath);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, destinationPath);
        var temporaryPath = destinationPath + ".tmp-" + Guid.NewGuid().ToString("N");
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferBytes);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long totalBytes = 0;
            await using (var source = new FileStream(
                             sourcePath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read,
                             CopyBufferBytes,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var destination = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             CopyBufferBytes,
                             FileOptions.Asynchronous | FileOptions.SequentialScan |
                             FileOptions.WriteThrough))
            {
                while (true)
                {
                    var read = await source.ReadAsync(
                            buffer.AsMemory(0, CopyBufferBytes),
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    if (totalBytes > expectedLength - read)
                    {
                        throw Failure("presentation-size", "The managed object exceeded its expected size.");
                    }

                    hash.AppendData(buffer, 0, read);
                    await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                        .ConfigureAwait(false);
                    totalBytes += read;
                }

                destination.Flush(flushToDisk: true);
            }

            if (totalBytes != expectedLength ||
                !string.Equals(
                    Convert.ToHexString(hash.GetHashAndReset()),
                    expectedContentId,
                    StringComparison.Ordinal))
            {
                throw Failure("presentation-hash", "The presentation copy failed content verification.");
            }

            File.Move(temporaryPath, destinationPath);
            File.SetAttributes(destinationPath, File.GetAttributes(destinationPath) | FileAttributes.ReadOnly);
            if (!await VerifyFileAsync(
                    destinationPath,
                    expectedContentId,
                    expectedLength,
                    cancellationToken).ConfigureAwait(false))
            {
                throw Failure("presentation-readback", "The presentation copy failed readback verification.");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static FileStream OpenLockedReadHandle(string path) => new(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        CopyBufferBytes,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static async Task<bool> VerifyLockedFileAsync(
        FileStream stream,
        string expectedContentId,
        long expectedLength,
        CancellationToken cancellationToken)
    {
        if (stream.Length != expectedLength)
        {
            return false;
        }

        stream.Position = 0;
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferBytes);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            while (true)
            {
                var read = await stream.ReadAsync(
                        buffer.AsMemory(0, CopyBufferBytes),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
            }

            stream.Position = 0;
            return string.Equals(
                Convert.ToHexString(hash.GetHashAndReset()),
                expectedContentId,
                StringComparison.Ordinal);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private async Task<bool> VerifyFileAsync(
        string path,
        string expectedContentId,
        long expectedLength,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, path);
        if (!File.Exists(path))
        {
            return false;
        }

        var attributes = File.GetAttributes(path);
        var item = new FileInfo(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            item.Length != expectedLength)
        {
            return false;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferBytes);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            long totalBytes = 0;
            while (true)
            {
                var read = await stream.ReadAsync(
                        buffer.AsMemory(0, CopyBufferBytes),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
                totalBytes += read;
            }

            return totalBytes == expectedLength &&
                   string.Equals(
                       Convert.ToHexString(hash.GetHashAndReset()),
                       expectedContentId,
                       StringComparison.Ordinal);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private void DeleteIncompleteLeaseDirectory(string leaseDirectory)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, leaseDirectory);
        ClearReadOnlyFiles(leaseDirectory);
        Directory.Delete(leaseDirectory, recursive: true);
        if (Directory.Exists(leaseDirectory))
        {
            throw Failure("incomplete-cleanup", "An incomplete presentation lease could not be reset.");
        }
    }

    private void DeleteLeaseFilesInSafeOrder(string leaseDirectory)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, leaseDirectory);
        if (Directory.EnumerateDirectories(leaseDirectory, "*", SearchOption.TopDirectoryOnly).Any())
        {
            throw Failure("lease-layout", "The presentation lease contains an unexpected directory.");
        }

        var currentPath = Path.Combine(leaseDirectory, CurrentTransactionName);
        var previousPath = Path.Combine(leaseDirectory, PreviousTransactionName);
        foreach (var path in Directory.EnumerateFiles(leaseDirectory, "*", SearchOption.TopDirectoryOnly)
                     .Where(path =>
                         !string.Equals(path, currentPath, StringComparison.OrdinalIgnoreCase) &&
                         !string.Equals(path, previousPath, StringComparison.OrdinalIgnoreCase)))
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            {
                throw Failure("lease-layout", "The presentation lease contains an unsafe file.");
            }

            File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
            File.Delete(path);
        }

        if (File.Exists(previousPath))
        {
            File.Delete(previousPath);
        }

        File.Delete(currentPath);
        Directory.Delete(leaseDirectory, recursive: false);
    }

    private static void ClearReadOnlyFiles(string root)
    {
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw Failure("lease-layout", "The incomplete lease contains a reparse point.");
            }

            if ((attributes & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
            }
        }
    }

    private void EnsurePresentationRoot()
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        CreateValidatedDirectory(_dataDirectory);
        CreateValidatedDirectory(_store.AttachmentRoot);
        CreateValidatedDirectory(PresentationRoot);
    }

    private void CreateValidatedDirectory(string path)
    {
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, path);
        Directory.CreateDirectory(path);
        DataDirectorySafety.Revalidate(_dataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, path);
    }

    private string GetLeaseDirectory(string leaseId)
    {
        ValidateLeaseId(leaseId);
        var path = Path.Combine(PresentationRoot, leaseId);
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, path);
        return path;
    }

    private string GetManagedObjectPath(string contentId)
    {
        if (!AttachmentIdentity.IsCanonicalContentId(contentId))
        {
            throw Failure("managed-object-identity", "The managed object identity is invalid.");
        }

        var path = Path.Combine(
            _store.ObjectsRoot,
            contentId[..2].ToLowerInvariant(),
            contentId + ".blob");
        DataDirectorySafety.RevalidateWriteTarget(_dataDirectory, path);
        return path;
    }

    private static string CreateLeaseId(string operationId, string payloadDigest)
    {
        var bytes = Encoding.UTF8.GetBytes(
            "CodexFree.AttachmentPresentation\0" + operationId + "\0" + payloadDigest);
        return Convert.ToHexString(SHA256.HashData(bytes).AsSpan(0, 16));
    }

    private static string CreatePresentationFileName(PresetAttachmentReference reference)
    {
        var extension = NormalizeExtension(Path.GetExtension(reference.OriginalFileName));
        var stem = NormalizeStem(Path.GetFileNameWithoutExtension(reference.OriginalFileName));
        return $"{reference.Order:D3}-{stem}-{reference.Id.Replace("-", string.Empty, StringComparison.Ordinal)[..8]}{extension}";
    }

    private static string CreateCompactPresentationFileName(PresetAttachmentReference reference) =>
        $"{reference.Order:D3}-{reference.Id.Replace("-", string.Empty, StringComparison.Ordinal)[..8]}" +
        NormalizeExtension(Path.GetExtension(reference.OriginalFileName));

    private static string NormalizeStem(string value)
    {
        var builder = new StringBuilder(Math.Min(value.Length, MaximumStemLength));
        foreach (var character in value)
        {
            if (builder.Length >= MaximumStemLength)
            {
                break;
            }

            builder.Append(char.IsLetterOrDigit(character) || character is '-' or '_'
                ? character
                : '_');
        }

        var normalized = builder.ToString().Trim(' ', '.', '_');
        if (normalized.Length == 0 || ReservedDeviceNames.Contains(normalized))
        {
            return "attachment";
        }

        return normalized;
    }

    private static string NormalizeExtension(string extension)
    {
        if (string.IsNullOrEmpty(extension) ||
            extension.Length > MaximumExtensionLength + 1 ||
            extension[0] != '.' ||
            extension.AsSpan(1).ContainsAnyExceptInRange('0', 'z'))
        {
            return string.Empty;
        }

        foreach (var character in extension.AsSpan(1))
        {
            if (!char.IsAsciiLetterOrDigit(character))
            {
                return string.Empty;
            }
        }

        return extension.ToLowerInvariant();
    }

    private static void ValidateOperationId(string value)
    {
        if (!IsCanonicalOperationId(value))
        {
            throw new ArgumentException("A canonical operation UUID is required.", nameof(value));
        }
    }

    private static bool IsCanonicalOperationId(string? value) =>
        Guid.TryParseExact(value, "D", out var parsed) &&
        string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static void ValidateLeaseId(string value)
    {
        if (!IsCanonicalLeaseId(value))
        {
            throw new ArgumentException("A canonical opaque presentation lease id is required.", nameof(value));
        }
    }

    private static bool IsCanonicalLeaseId(string? value)
    {
        if (value is null || value.Length != 32)
        {
            return false;
        }

        return value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');
    }

    private static bool IsCanonicalSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(left),
            Path.TrimEndingDirectorySeparator(right),
            StringComparison.OrdinalIgnoreCase);

    private static AttachmentPresentationException Failure(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private enum PresentationTransactionState
    {
        Materializing,
        Ready,
        CleanupPending
    }

    private sealed record PresentationEntry(
        int Order,
        string ReferenceId,
        string ContentId,
        long ByteLength,
        string DetectedType,
        string OwnerInputKind,
        bool UsesManagedObjectPath,
        string? RelativeFileName);

    private sealed record PresentationTransaction(
        int SchemaVersion,
        string LeaseId,
        string OperationId,
        string PayloadDigest,
        PresentationTransactionState State,
        AttachmentPresentationRequirements Requirements,
        IReadOnlyList<PresentationEntry> Entries);

    private sealed record PresentationEnvelope(
        int SchemaVersion,
        long Generation,
        PresentationTransaction Transaction,
        string Checksum);

    private sealed record PresentationChecksumPayload(
        int SchemaVersion,
        long Generation,
        PresentationTransaction Transaction);
}
