using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CodexGuardian.Broker;

internal enum BrokerConsentLedgerStoreStateV1
{
    NoAuthority,
    HealthyGenesis,
    ReceiptPendingVerification,
    Quarantined
}

internal enum BrokerConsentLedgerStoreWriteStateV1
{
    Written,
    Unchanged,
    Conflict,
    Quarantined
}

internal enum BrokerConsentLedgerReplicaStateV1
{
    Missing,
    Canonical,
    Invalid
}

internal enum BrokerConsentLedgerStoreFaultPointV1
{
    TemporaryCreated,
    PartialWrite,
    FullWrite,
    FileFlushed,
    TemporaryReadbackVerified,
    BeforePublish,
    AfterPublish,
    DirectoryBarrierCompleted,
    BeforeInMemoryCommit
}

internal sealed record BrokerConsentLedgerStoreDiagnosticsV1(
    BrokerConsentLedgerReplicaStateV1 Primary,
    BrokerConsentLedgerReplicaStateV1 Previous,
    string Code);

internal sealed record BrokerConsentLedgerStoreSnapshotV1(
    BrokerConsentLedgerStoreStateV1 State,
    BrokerConsentLedgerDocumentV1? Primary,
    BrokerConsentLedgerStoreDiagnosticsV1 Diagnostics);

internal sealed record BrokerConsentLedgerStoreWriteResultV1(
    BrokerConsentLedgerStoreWriteStateV1 State,
    BrokerConsentLedgerStoreSnapshotV1 Snapshot);

internal sealed class BrokerConsentLedgerStoreException : Exception
{
    internal BrokerConsentLedgerStoreException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal sealed class BrokerConsentLedgerStore : IDisposable
{
    internal const int MaximumReplicaBytes = BrokerConsentLedgerV1.MaximumDocumentBytes;

    private const string PrimaryFileName = "broker-consent-ledger.json";
    private const string PreviousFileName = "broker-consent-ledger.previous.json";
    private const string LockFileName = ".broker-consent-ledger.lock";
    private const string TemporaryPrefix = ".broker-consent-ledger.json.tmp-";
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint OpenAlways = 4;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint MoveFileWriteThrough = 0x00000008;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;
    private const int MaximumPathCharacters = 32768;
    private const int MaximumOrphanTemporaryFiles = 32;
    private const int MaximumOrphanScanEntries = 128;

    private static readonly Action<BrokerConsentLedgerStoreFaultPointV1> IgnoreFault =
        static _ => { };
    private readonly object _gate = new();
    private readonly Action<BrokerConsentLedgerStoreFaultPointV1> _faultCallback;
    private readonly SafeFileHandle _directoryHandle;
    private readonly NativeDirectoryObservation _directoryIdentity;
    private readonly SafeFileHandle _lockHandle;
    private bool _disposed;

    internal BrokerConsentLedgerStore(string dataDirectory)
        : this(dataDirectory, IgnoreFault)
    {
    }

    internal BrokerConsentLedgerStore(
        string dataDirectory,
        Action<BrokerConsentLedgerStoreFaultPointV1> faultCallback)
    {
        ArgumentNullException.ThrowIfNull(faultCallback);
        _faultCallback = faultCallback;
        SafeFileHandle? directoryHandle = null;
        SafeFileHandle? lockHandle = null;
        try
        {
            DataDirectory = PrepareDataDirectory(dataDirectory);
            PrimaryPath = Path.Combine(DataDirectory, PrimaryFileName);
            PreviousPath = Path.Combine(DataDirectory, PreviousFileName);
            LockPath = Path.Combine(DataDirectory, LockFileName);

            directoryHandle = OpenDirectoryHandle(DataDirectory);
            _ = ReadDirectoryIdentity(directoryHandle, DataDirectory);
            lockHandle = OpenLockHandle(LockPath);
            ValidateLockHandle(lockHandle, LockPath);
            CleanupOrphanTemporaryFiles(directoryHandle);
            var directoryIdentity = ReadDirectoryIdentity(directoryHandle, DataDirectory);

            _directoryHandle = directoryHandle;
            _directoryIdentity = directoryIdentity;
            _lockHandle = lockHandle;
            directoryHandle = null;
            lockHandle = null;
        }
        catch (BrokerConsentLedgerStoreException)
        {
            directoryHandle?.Dispose();
            lockHandle?.Dispose();
            throw;
        }
        catch (Exception exception) when (IsStorageFailure(exception))
        {
            directoryHandle?.Dispose();
            lockHandle?.Dispose();
            throw new BrokerConsentLedgerStoreException(
                "consent-ledger-store-open-failed",
                "The Broker consent ledger store could not be opened safely.",
                exception);
        }
    }

    internal string DataDirectory { get; }

    internal string PrimaryPath { get; }

    internal string PreviousPath { get; }

    internal string LockPath { get; }

    internal BrokerConsentLedgerStoreSnapshotV1 Read()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return ReadCore().Snapshot;
        }
    }

    internal BrokerConsentLedgerStoreWriteResultV1 Write(
        BrokerConsentLedgerDocumentV1 candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        lock (_gate)
        {
            ThrowIfDisposed();
            var current = ReadCore();
            if (current.Snapshot.State == BrokerConsentLedgerStoreStateV1.Quarantined)
            {
                return new BrokerConsentLedgerStoreWriteResultV1(
                    BrokerConsentLedgerStoreWriteStateV1.Quarantined,
                    current.Snapshot);
            }

            var candidateBytes = BrokerConsentLedgerV1.Serialize(candidate);
            if (current.Primary.Document is null)
            {
                if (candidate.Revision != 0 ||
                    candidate.Entry is not BrokerConsentGenesisEntryV1 ||
                    current.Primary.State != BrokerConsentLedgerReplicaStateV1.Missing ||
                    current.Previous.State != BrokerConsentLedgerReplicaStateV1.Missing)
                {
                    return new BrokerConsentLedgerStoreWriteResultV1(
                        BrokerConsentLedgerStoreWriteStateV1.Conflict,
                        current.Snapshot);
                }
            }
            else
            {
                if (current.Primary.Bytes is not null &&
                    candidateBytes.AsSpan().SequenceEqual(current.Primary.Bytes))
                {
                    return new BrokerConsentLedgerStoreWriteResultV1(
                        BrokerConsentLedgerStoreWriteStateV1.Unchanged,
                        current.Snapshot);
                }

                try
                {
                    BrokerConsentLedgerV1.ValidateSuccessor(current.Primary.Document, candidate);
                }
                catch (BrokerConsentLedgerFormatException)
                {
                    return new BrokerConsentLedgerStoreWriteResultV1(
                        BrokerConsentLedgerStoreWriteStateV1.Conflict,
                        current.Snapshot);
                }
            }

            return PersistCandidate(current, candidateBytes);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _lockHandle.Dispose();
            _directoryHandle.Dispose();
        }
    }

    private BrokerConsentLedgerStoreWriteResultV1 PersistCandidate(
        StoreRead current,
        byte[] candidateBytes)
    {
        EnsureDirectoryStable();
        var temporaryPath = Path.Combine(
            DataDirectory,
            TemporaryPrefix + Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.ReadWrite,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough | FileOptions.SequentialScan))
            {
                _faultCallback(BrokerConsentLedgerStoreFaultPointV1.TemporaryCreated);
                var firstLength = Math.Max(1, candidateBytes.Length / 2);
                stream.Write(candidateBytes.AsSpan(0, firstLength));
                _faultCallback(BrokerConsentLedgerStoreFaultPointV1.PartialWrite);
                stream.Write(candidateBytes.AsSpan(firstLength));
                _faultCallback(BrokerConsentLedgerStoreFaultPointV1.FullWrite);
                stream.Flush(flushToDisk: true);
                _faultCallback(BrokerConsentLedgerStoreFaultPointV1.FileFlushed);
                var verified = ReadCanonicalReplicaFromHandle(
                    stream.SafeFileHandle,
                    temporaryPath);
                if (verified.Bytes is null ||
                    !verified.Bytes.AsSpan().SequenceEqual(candidateBytes))
                {
                    throw new IOException("The temporary consent ledger readback changed bytes.");
                }
                _faultCallback(BrokerConsentLedgerStoreFaultPointV1.TemporaryReadbackVerified);
            }

            EnsureDirectoryStable();
            _faultCallback(BrokerConsentLedgerStoreFaultPointV1.BeforePublish);
            if (current.Primary.Document is null)
            {
                if (!MoveFileExW(
                        ToExtendedLocalPath(temporaryPath),
                        ToExtendedLocalPath(PrimaryPath),
                        MoveFileWriteThrough))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The first consent ledger publication failed.");
                }
            }
            else
            {
                File.Replace(
                    temporaryPath,
                    PrimaryPath,
                    PreviousPath,
                    ignoreMetadataErrors: false);
            }
            _faultCallback(BrokerConsentLedgerStoreFaultPointV1.AfterPublish);

            FlushPublishedReplica(PrimaryPath);
            if (current.Primary.Document is not null)
            {
                FlushPublishedReplica(PreviousPath);
            }
            FlushDirectoryBarrier();
            _faultCallback(BrokerConsentLedgerStoreFaultPointV1.DirectoryBarrierCompleted);

            var published = ReadCore();
            if (published.Snapshot.State == BrokerConsentLedgerStoreStateV1.Quarantined ||
                published.Primary.Bytes is null ||
                !published.Primary.Bytes.AsSpan().SequenceEqual(candidateBytes) ||
                (current.Primary.Document is null &&
                 published.Previous.State != BrokerConsentLedgerReplicaStateV1.Missing) ||
                (current.Primary.Document is not null &&
                 (published.Previous.Bytes is null ||
                  current.Primary.Bytes is null ||
                  !published.Previous.Bytes.AsSpan().SequenceEqual(current.Primary.Bytes))))
            {
                return new BrokerConsentLedgerStoreWriteResultV1(
                    BrokerConsentLedgerStoreWriteStateV1.Quarantined,
                    QuarantinedSnapshot(
                        published.Primary.State,
                        published.Previous.State,
                        "store-post-publish-mismatch"));
            }

            _faultCallback(BrokerConsentLedgerStoreFaultPointV1.BeforeInMemoryCommit);
            return new BrokerConsentLedgerStoreWriteResultV1(
                BrokerConsentLedgerStoreWriteStateV1.Written,
                published.Snapshot);
        }
        catch (BrokerConsentLedgerStoreException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageFailure(exception))
        {
            throw new BrokerConsentLedgerStoreException(
                "consent-ledger-store-write-failed",
                "The Broker consent ledger store could not publish the candidate safely.",
                exception);
        }
    }

    private StoreRead ReadCore()
    {
        try
        {
            EnsureDirectoryStable();
            var primary = ReadReplica(PrimaryPath);
            var previous = ReadReplica(PreviousPath);
            if (primary.State == BrokerConsentLedgerReplicaStateV1.Missing)
            {
                if (previous.State == BrokerConsentLedgerReplicaStateV1.Missing)
                {
                    return new StoreRead(
                        new BrokerConsentLedgerStoreSnapshotV1(
                            BrokerConsentLedgerStoreStateV1.NoAuthority,
                            null,
                            new BrokerConsentLedgerStoreDiagnosticsV1(
                                primary.State,
                                previous.State,
                                "store-empty")),
                        primary,
                        previous);
                }

                return new StoreRead(
                    QuarantinedSnapshot(primary.State, previous.State, "store-primary-missing"),
                    primary,
                    previous);
            }

            if (primary.State == BrokerConsentLedgerReplicaStateV1.Invalid ||
                primary.Document is null)
            {
                return new StoreRead(
                    QuarantinedSnapshot(primary.State, previous.State, "store-primary-invalid"),
                    primary,
                    previous);
            }

            if (primary.Document.Entry is BrokerConsentGenesisEntryV1)
            {
                if (previous.State != BrokerConsentLedgerReplicaStateV1.Missing)
                {
                    return new StoreRead(
                        QuarantinedSnapshot(primary.State, previous.State, "store-unexpected-previous"),
                        primary,
                        previous);
                }

                return new StoreRead(
                    new BrokerConsentLedgerStoreSnapshotV1(
                        BrokerConsentLedgerStoreStateV1.HealthyGenesis,
                        primary.Document,
                        new BrokerConsentLedgerStoreDiagnosticsV1(
                            primary.State,
                            previous.State,
                            "store-healthy-genesis")),
                    primary,
                    previous);
            }

            if (previous.State != BrokerConsentLedgerReplicaStateV1.Canonical ||
                previous.Document is null)
            {
                return new StoreRead(
                    QuarantinedSnapshot(primary.State, previous.State, "store-previous-required"),
                    primary,
                    previous);
            }

            try
            {
                BrokerConsentLedgerV1.ValidateSuccessor(previous.Document, primary.Document);
            }
            catch (BrokerConsentLedgerFormatException)
            {
                return new StoreRead(
                    QuarantinedSnapshot(primary.State, previous.State, "store-chain-invalid"),
                    primary,
                    previous);
            }

            var state = primary.Document.Entry switch
            {
                BrokerConsentGrantEntryV1 =>
                    BrokerConsentLedgerStoreStateV1.ReceiptPendingVerification,
                BrokerConsentRevokeEntryV1 => BrokerConsentLedgerStoreStateV1.NoAuthority,
                _ => BrokerConsentLedgerStoreStateV1.Quarantined
            };
            if (state == BrokerConsentLedgerStoreStateV1.Quarantined)
            {
                return new StoreRead(
                    QuarantinedSnapshot(primary.State, previous.State, "store-entry-unsupported"),
                    primary,
                    previous);
            }

            return new StoreRead(
                new BrokerConsentLedgerStoreSnapshotV1(
                    state,
                    primary.Document,
                    new BrokerConsentLedgerStoreDiagnosticsV1(
                        primary.State,
                        previous.State,
                        state == BrokerConsentLedgerStoreStateV1.ReceiptPendingVerification
                            ? "store-receipt-pending-verification"
                            : "store-no-authority-revoked")),
                primary,
                previous);
        }
        catch (Exception exception) when (IsStorageFailure(exception))
        {
            _ = exception;
            var invalid = new ReplicaRead(
                BrokerConsentLedgerReplicaStateV1.Invalid,
                null,
                null);
            return new StoreRead(
                QuarantinedSnapshot(
                    BrokerConsentLedgerReplicaStateV1.Invalid,
                    BrokerConsentLedgerReplicaStateV1.Invalid,
                    "store-directory-unavailable"),
                invalid,
                invalid);
        }
    }

    private ReplicaRead ReadReplica(string path)
    {
        var handle = CreateFileW(
            ToExtendedLocalPath(path),
            GenericRead,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            return error is ErrorFileNotFound or ErrorPathNotFound
                ? new ReplicaRead(BrokerConsentLedgerReplicaStateV1.Missing, null, null)
                : new ReplicaRead(BrokerConsentLedgerReplicaStateV1.Invalid, null, null);
        }

        using (handle)
        {
            try
            {
                return ReadCanonicalReplicaFromHandle(handle, path);
            }
            catch (Exception exception) when (IsStorageFailure(exception))
            {
                _ = exception;
                return new ReplicaRead(BrokerConsentLedgerReplicaStateV1.Invalid, null, null);
            }
        }
    }

    private static ReplicaRead ReadCanonicalReplicaFromHandle(
        SafeFileHandle handle,
        string expectedPath)
    {
        var before = ReadRegularFileObservation(handle, expectedPath);
        var buffer = new byte[MaximumReplicaBytes + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = RandomAccess.Read(
                handle,
                buffer.AsSpan(total, buffer.Length - total),
                total);
            if (read == 0)
            {
                break;
            }

            total = checked(total + read);
        }

        var after = ReadRegularFileObservation(handle, expectedPath);
        if (!before.Equals(after) ||
            total <= 0 ||
            total > MaximumReplicaBytes ||
            total != before.Standard.EndOfFile)
        {
            throw new IOException("The retained consent ledger replica changed or exceeded its bound.");
        }

        var bytes = buffer.AsSpan(0, total).ToArray();
        var document = BrokerConsentLedgerV1.Parse(bytes);
        return new ReplicaRead(
            BrokerConsentLedgerReplicaStateV1.Canonical,
            bytes,
            document);
    }

    private void FlushPublishedReplica(string path)
    {
        using var handle = CreateFileW(
            ToExtendedLocalPath(path),
            GenericRead | GenericWrite,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagWriteThrough,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Unable to open a published consent ledger replica.");
        }

        _ = ReadCanonicalReplicaFromHandle(handle, path);
        if (!FlushFileBuffers(handle))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to flush a published consent ledger replica.");
        }
    }

    private void FlushDirectoryBarrier()
    {
        EnsureDirectoryStable();
        if (!FlushFileBuffers(_directoryHandle))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to flush the consent ledger directory barrier.");
        }

        EnsureDirectoryStable();
    }

    private void EnsureDirectoryStable()
    {
        RejectReparseComponents(DataDirectory);
        var current = ReadDirectoryIdentity(_directoryHandle, DataDirectory);
        if (!_directoryIdentity.Equals(current))
        {
            throw new IOException("The consent ledger directory identity changed.");
        }
    }

    private void CleanupOrphanTemporaryFiles(SafeFileHandle directoryHandle)
    {
        var candidates = new List<string>(MaximumOrphanTemporaryFiles);
        var scanned = 0;
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     DataDirectory,
                     TemporaryPrefix + "*",
                     SearchOption.TopDirectoryOnly))
        {
            scanned++;
            if (scanned > MaximumOrphanScanEntries)
            {
                throw new BrokerConsentLedgerStoreException(
                    "consent-ledger-store-orphan-limit",
                    "The Broker consent ledger orphan scan exceeded its bound.");
            }

            if (!IsStrictOrphanTemporaryName(Path.GetFileName(path)))
            {
                continue;
            }

            candidates.Add(path);
            if (candidates.Count > MaximumOrphanTemporaryFiles)
            {
                throw new BrokerConsentLedgerStoreException(
                    "consent-ledger-store-orphan-limit",
                    "The Broker consent ledger orphan set exceeded its bound.");
            }
        }

        foreach (var path in candidates)
        {
            DeleteOrphanTemporaryFile(path);
        }

        if (candidates.Count > 0 && !FlushFileBuffers(directoryHandle))
        {
            throw new BrokerConsentLedgerStoreException(
                "consent-ledger-store-orphan-invalid",
                "The Broker consent ledger orphan cleanup was not durable.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    private static bool IsStrictOrphanTemporaryName(string name)
    {
        if (!name.StartsWith(TemporaryPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var suffix = name.AsSpan(TemporaryPrefix.Length);
        var separator = suffix.IndexOf('-');
        if (separator <= 0 ||
            separator != suffix.LastIndexOf('-') ||
            separator > 10 ||
            suffix.Length - separator - 1 != 32)
        {
            return false;
        }

        var processId = suffix[..separator];
        foreach (var character in processId)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }

        if (!int.TryParse(
                processId,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var parsedProcessId) ||
            parsedProcessId <= 0)
        {
            return false;
        }

        foreach (var character in suffix[(separator + 1)..])
        {
            if (!((character >= '0' && character <= '9') ||
                  (character >= 'a' && character <= 'f')))
            {
                return false;
            }
        }

        return true;
    }

    private static void DeleteOrphanTemporaryFile(string path)
    {
        using (var handle = CreateFileW(
                   ToExtendedLocalPath(path),
                   GenericRead | GenericWrite | DeleteAccess,
                   0,
                   IntPtr.Zero,
                   OpenExisting,
                   FileFlagOpenReparsePoint | FileFlagWriteThrough,
                   IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new BrokerConsentLedgerStoreException(
                    "consent-ledger-store-orphan-invalid",
                    "A Broker consent ledger orphan could not be retained safely.",
                    new Win32Exception(error));
            }

            var basic = ReadBasicInformation(handle);
            var standard = ReadStandardInformation(handle);
            var attributes = (FileAttributes)basic.FileAttributes;
            if ((attributes &
                 (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
                standard.Directory ||
                standard.DeletePending ||
                standard.NumberOfLinks != 1 ||
                standard.EndOfFile < 0 ||
                standard.EndOfFile > MaximumReplicaBytes ||
                !SamePath(ReadFinalPath(handle), path))
            {
                throw new BrokerConsentLedgerStoreException(
                    "consent-ledger-store-orphan-invalid",
                    "A Broker consent ledger orphan is not a bounded single-link regular file.");
            }

            _ = ReadFileId(handle);
            var disposition = new NativeFileDispositionInformation { DeleteFile = true };
            if (!SetFileDispositionInformation(
                    handle,
                    FileInformationClass.FileDispositionInfo,
                    ref disposition,
                    (uint)Marshal.SizeOf<NativeFileDispositionInformation>()))
            {
                throw new BrokerConsentLedgerStoreException(
                    "consent-ledger-store-orphan-invalid",
                    "A Broker consent ledger orphan could not be deleted by retained handle.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }

        using var verification = CreateFileW(
            ToExtendedLocalPath(path),
            GenericRead,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!verification.IsInvalid)
        {
            throw new BrokerConsentLedgerStoreException(
                "consent-ledger-store-orphan-invalid",
                "A Broker consent ledger orphan remained after retained-handle deletion.");
        }

        var verificationError = Marshal.GetLastWin32Error();
        verification.Dispose();
        if (verificationError is not ErrorFileNotFound and not ErrorPathNotFound)
        {
            throw new BrokerConsentLedgerStoreException(
                "consent-ledger-store-orphan-invalid",
                "A Broker consent ledger orphan deletion could not be verified.",
                new Win32Exception(verificationError));
        }
    }

    private static BrokerConsentLedgerStoreSnapshotV1 QuarantinedSnapshot(
        BrokerConsentLedgerReplicaStateV1 primary,
        BrokerConsentLedgerReplicaStateV1 previous,
        string code) =>
        new(
            BrokerConsentLedgerStoreStateV1.Quarantined,
            null,
            new BrokerConsentLedgerStoreDiagnosticsV1(primary, previous, code));

    private static string PrepareDataDirectory(string value)
    {
        try
        {
            var normalized = NormalizeLocalPath(value, rejectDevicePrefix: true);
            var root = Path.GetPathRoot(normalized)!;
            if (string.Equals(
                    Path.TrimEndingDirectorySeparator(normalized),
                    Path.TrimEndingDirectorySeparator(root),
                    StringComparison.OrdinalIgnoreCase) ||
                normalized.AsSpan(root.Length).Contains(':'))
            {
                throw new IOException("The consent ledger data path is not a regular directory path.");
            }

            RejectCodexSessionPath(normalized);
            RejectNearestExistingReparseComponents(normalized);
            Directory.CreateDirectory(normalized);
            RejectReparseComponents(normalized);
            return normalized;
        }
        catch (BrokerConsentLedgerStoreException)
        {
            throw;
        }
        catch (Exception exception) when (IsStorageFailure(exception))
        {
            throw new BrokerConsentLedgerStoreException(
                "consent-ledger-store-path-invalid",
                "The Broker consent ledger data directory is unsafe.",
                exception);
        }
    }

    private static void RejectCodexSessionPath(string candidate)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (var root in new[]
        {
            Path.Combine(userProfile, ".codex", "sessions"),
            Path.Combine(userProfile, ".codex", "archived_sessions")
        })
        {
            if (IsSameOrDescendant(candidate, NormalizeLocalPath(root, rejectDevicePrefix: true)))
            {
                throw new IOException("The consent ledger data path cannot enter Codex task data.");
            }
        }

        var codexHome = Environment.GetEnvironmentVariable("CODEX_HOME");
        if (!string.IsNullOrWhiteSpace(codexHome))
        {
            var root = NormalizeLocalPath(
                Path.Combine(codexHome, "sessions"),
                rejectDevicePrefix: true);
            if (IsSameOrDescendant(candidate, root))
            {
                throw new IOException("The consent ledger data path cannot enter Codex task data.");
            }
        }
    }

    private static void RejectNearestExistingReparseComponents(string path)
    {
        var current = path;
        while (!Directory.Exists(current))
        {
            var parent = Directory.GetParent(current);
            if (parent is null)
            {
                throw new DirectoryNotFoundException("No safe ancestor exists for the consent ledger path.");
            }

            current = parent.FullName;
        }

        RejectReparseComponents(current);
    }

    private static void RejectReparseComponents(string path)
    {
        var normalized = NormalizeLocalPath(path, rejectDevicePrefix: true);
        var root = Path.GetPathRoot(normalized)!;
        var relative = Path.GetRelativePath(root, normalized);
        var current = root;
        if (relative == ".")
        {
            ValidatePathAttributes(current);
            return;
        }

        foreach (var component in relative.Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            ValidatePathAttributes(current);
        }
    }

    private static void ValidatePathAttributes(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
        {
            throw new IOException("The consent ledger path contains a reparse or device component.");
        }
    }

    private static SafeFileHandle OpenDirectoryHandle(string path)
    {
        var handle = CreateFileW(
            ToExtendedLocalPath(path),
            GenericRead | GenericWrite,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Unable to retain the consent ledger directory.");
        }

        return handle;
    }

    private static SafeFileHandle OpenLockHandle(string path)
    {
        var handle = CreateFileW(
            ToExtendedLocalPath(path),
            GenericRead | GenericWrite,
            0,
            IntPtr.Zero,
            OpenAlways,
            FileAttributeNormal | FileFlagWriteThrough | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (error is ErrorSharingViolation or ErrorLockViolation)
            {
                throw new BrokerConsentLedgerStoreException(
                    "consent-ledger-store-locked",
                    "Another Broker owns the consent ledger lifecycle lock.");
            }

            throw new Win32Exception(error, "Unable to retain the consent ledger lock.");
        }

        return handle;
    }

    private static void ValidateLockHandle(SafeFileHandle handle, string expectedPath)
    {
        var basic = ReadBasicInformation(handle);
        var standard = ReadStandardInformation(handle);
        var attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            standard.Directory ||
            standard.DeletePending ||
            standard.NumberOfLinks != 1 ||
            standard.EndOfFile != 0 ||
            !SamePath(ReadFinalPath(handle), expectedPath))
        {
            throw new IOException("The consent ledger lock file is unsafe.");
        }

        _ = ReadFileId(handle);
    }

    private static NativeDirectoryObservation ReadDirectoryIdentity(
        SafeFileHandle handle,
        string expectedPath)
    {
        var basic = ReadBasicInformation(handle);
        var standard = ReadStandardInformation(handle);
        var attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & FileAttributes.Directory) == 0 ||
            (attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            !standard.Directory ||
            standard.DeletePending)
        {
            throw new IOException("The retained consent ledger directory is unsafe.");
        }

        var finalPath = ReadFinalPath(handle);
        if (!SamePath(finalPath, expectedPath))
        {
            throw new IOException("The retained consent ledger directory resolved elsewhere.");
        }

        return new NativeDirectoryObservation(
            finalPath,
            attributes,
            ReadFileId(handle));
    }

    private static NativeRegularFileObservation ReadRegularFileObservation(
        SafeFileHandle handle,
        string expectedPath)
    {
        var basic = ReadBasicInformation(handle);
        var standard = ReadStandardInformation(handle);
        var attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            standard.Directory ||
            standard.DeletePending ||
            standard.NumberOfLinks != 1 ||
            standard.EndOfFile <= 0 ||
            standard.EndOfFile > MaximumReplicaBytes)
        {
            throw new IOException("The retained consent ledger replica is unsafe or unbounded.");
        }

        var finalPath = ReadFinalPath(handle);
        if (!SamePath(finalPath, expectedPath))
        {
            throw new IOException("The retained consent ledger replica resolved elsewhere.");
        }

        return new NativeRegularFileObservation(
            finalPath,
            basic,
            standard,
            ReadFileId(handle));
    }

    private static NativeBasicInformation ReadBasicInformation(SafeFileHandle handle)
    {
        if (!GetFileBasicInformation(
                handle,
                FileInformationClass.FileBasicInfo,
                out var information,
                (uint)Marshal.SizeOf<NativeBasicInformation>()))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read consent ledger path attributes.");
        }

        return information;
    }

    private static NativeStandardInformation ReadStandardInformation(SafeFileHandle handle)
    {
        if (!GetFileStandardInformation(
                handle,
                FileInformationClass.FileStandardInfo,
                out var information,
                (uint)Marshal.SizeOf<NativeStandardInformation>()))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read consent ledger size and link state.");
        }

        return information;
    }

    private static NativeFileId ReadFileId(SafeFileHandle handle)
    {
        if (!GetFileIdInformation(
                handle,
                FileInformationClass.FileIdInfo,
                out var information,
                (uint)Marshal.SizeOf<NativeFileIdInformation>()))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the consent ledger FILE_ID_128 identity.");
        }

        if (information.VolumeSerialNumber == 0 ||
            (information.FileId.Low == 0 && information.FileId.High == 0))
        {
            throw new IOException("Windows returned an empty consent ledger file identity.");
        }

        return new NativeFileId(
            information.VolumeSerialNumber,
            information.FileId.Low,
            information.FileId.High);
    }

    private static string ReadFinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(512);
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to resolve a retained consent ledger path.");
        }

        if (length >= buffer.Capacity)
        {
            if (length >= MaximumPathCharacters)
            {
                throw new PathTooLongException("A retained consent ledger path is too long.");
            }

            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to resolve a complete consent ledger path.");
            }
        }

        return NormalizeLocalPath(buffer.ToString(), rejectDevicePrefix: false);
    }

    private static string NormalizeLocalPath(string value, bool rejectDevicePrefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith(@"\\.\", StringComparison.Ordinal) ||
            (rejectDevicePrefix && value.StartsWith(@"\\?\", StringComparison.Ordinal)) ||
            (!value.StartsWith(@"\\?\", StringComparison.Ordinal) &&
             value.StartsWith(@"\\", StringComparison.Ordinal)))
        {
            throw new IOException("The consent ledger path cannot use a network or device namespace.");
        }

        if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        var fullPath = Path.GetFullPath(value);
        var root = Path.GetPathRoot(fullPath);
        if (root is null || root.Length < 3 || root[1] != ':')
        {
            throw new IOException("The consent ledger path is not on a canonical local drive.");
        }

        return string.Equals(
            Path.TrimEndingDirectorySeparator(fullPath),
            Path.TrimEndingDirectorySeparator(root),
            StringComparison.OrdinalIgnoreCase)
            ? root
            : Path.TrimEndingDirectorySeparator(fullPath);
    }

    private static string ToExtendedLocalPath(string value)
    {
        var normalized = NormalizeLocalPath(value, rejectDevicePrefix: true);
        var root = Path.GetPathRoot(normalized)!;
        if (normalized.AsSpan(root.Length).Contains(':'))
        {
            throw new IOException(
                "The consent ledger native path cannot address an alternate data stream.");
        }
        if (checked(normalized.Length + 4) >= MaximumPathCharacters)
        {
            throw new PathTooLongException(
                "The consent ledger native path exceeds the Windows extended-path bound.");
        }

        return @"\\?\" + normalized;
    }

    private static bool SamePath(string first, string second) => string.Equals(
        NormalizeLocalPath(first, rejectDevicePrefix: false),
        NormalizeLocalPath(second, rejectDevicePrefix: false),
        StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrDescendant(string candidate, string root) =>
        SamePath(candidate, root) ||
        NormalizeLocalPath(candidate, rejectDevicePrefix: false).StartsWith(
            Path.TrimEndingDirectorySeparator(
                NormalizeLocalPath(root, rejectDevicePrefix: false)) +
            Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);

    private static bool IsStorageFailure(Exception exception) =>
        exception is IOException or
        UnauthorizedAccessException or
        Win32Exception or
        BrokerConsentLedgerFormatException or
        ArgumentException or
        NotSupportedException;

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private sealed record StoreRead(
        BrokerConsentLedgerStoreSnapshotV1 Snapshot,
        ReplicaRead Primary,
        ReplicaRead Previous);

    private sealed record ReplicaRead(
        BrokerConsentLedgerReplicaStateV1 State,
        byte[]? Bytes,
        BrokerConsentLedgerDocumentV1? Document);

    private sealed record NativeDirectoryObservation(
        string FinalPath,
        FileAttributes Attributes,
        NativeFileId FileId);

    private sealed record NativeRegularFileObservation(
        string FinalPath,
        NativeBasicInformation Basic,
        NativeStandardInformation Standard,
        NativeFileId FileId);

    private readonly record struct NativeFileId(
        ulong VolumeSerialNumber,
        ulong Low,
        ulong High);

    private enum FileInformationClass
    {
        FileBasicInfo = 0,
        FileStandardInfo = 1,
        FileDispositionInfo = 4,
        FileIdInfo = 18
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeBasicInformation : IEquatable<NativeBasicInformation>
    {
        internal readonly long CreationTime;
        internal readonly long LastAccessTime;
        internal readonly long LastWriteTime;
        internal readonly long ChangeTime;
        internal readonly uint FileAttributes;

        public bool Equals(NativeBasicInformation other) =>
            CreationTime == other.CreationTime &&
            LastWriteTime == other.LastWriteTime &&
            ChangeTime == other.ChangeTime &&
            FileAttributes == other.FileAttributes;

        public override bool Equals(object? value) =>
            value is NativeBasicInformation other && Equals(other);

        public override int GetHashCode() =>
            HashCode.Combine(CreationTime, LastWriteTime, ChangeTime, FileAttributes);
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeStandardInformation : IEquatable<NativeStandardInformation>
    {
        internal readonly long AllocationSize;
        internal readonly long EndOfFile;
        internal readonly uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] internal readonly bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] internal readonly bool Directory;

        public bool Equals(NativeStandardInformation other) =>
            AllocationSize == other.AllocationSize &&
            EndOfFile == other.EndOfFile &&
            NumberOfLinks == other.NumberOfLinks &&
            DeletePending == other.DeletePending &&
            Directory == other.Directory;

        public override bool Equals(object? value) =>
            value is NativeStandardInformation other && Equals(other);

        public override int GetHashCode() =>
            HashCode.Combine(AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory);
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeFileId128
    {
        internal readonly ulong Low;
        internal readonly ulong High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeFileIdInformation
    {
        internal readonly ulong VolumeSerialNumber;
        internal readonly NativeFileId128 FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileDispositionInformation
    {
        [MarshalAs(UnmanagedType.Bool)] internal bool DeleteFile;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileBasicInformation(
        SafeFileHandle file,
        FileInformationClass informationClass,
        out NativeBasicInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileStandardInformation(
        SafeFileHandle file,
        FileInformationClass informationClass,
        out NativeStandardInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileIdInformation(
        SafeFileHandle file,
        FileInformationClass informationClass,
        out NativeFileIdInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileDispositionInformation(
        SafeFileHandle file,
        FileInformationClass informationClass,
        ref NativeFileDispositionInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(
        string existingPath,
        string destinationPath,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle handle);
}
