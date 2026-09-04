using CodexGuardian.Models;
using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace CodexGuardian.Services;

internal enum AttachmentImportFailureCode
{
    InvalidSource,
    SourceNotFound,
    SourceIsDirectory,
    SourceIsReparsePoint,
    InvalidFileName,
    InvalidLimits,
    FileTooLarge,
    TooManyAttachments,
    MessageTooLarge,
    LibraryCapacityExceeded,
    InsufficientFreeSpace,
    InvalidContent,
    DamagedObject,
    StorageUnavailable
}

internal sealed class AttachmentImportException : IOException
{
    private AttachmentImportException(
        AttachmentImportFailureCode code,
        string message,
        Exception? innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    public AttachmentImportFailureCode Code { get; }

    internal static AttachmentImportException Create(
        AttachmentImportFailureCode code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);
}

internal sealed record AttachmentPhysicalDeleteResult(
    bool Deleted,
    string FailureClass);

internal static class AttachmentImportLimitGuard
{
    internal const int MaximumAttachmentCountHardLimit = 100;
    internal const long MaximumFileBytesHardLimit = 2L * 1024 * 1024 * 1024;
    internal const long MaximumMessageBytesHardLimit = 10L * 1024 * 1024 * 1024;
    internal const long MaximumLibraryBytesHardLimit = 1024L * 1024 * 1024 * 1024;

    internal static void EnsureValidLimits(AttachmentLimitSettings limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (limits.MaximumAttachmentsPerMessage is < 1 or > MaximumAttachmentCountHardLimit ||
            limits.MaximumBytesPerFile is < 1 or > MaximumFileBytesHardLimit ||
            limits.MaximumBytesPerMessage < limits.MaximumBytesPerFile ||
            limits.MaximumBytesPerMessage > MaximumMessageBytesHardLimit ||
            limits.MaximumLibraryBytes < limits.MaximumBytesPerMessage ||
            limits.MaximumLibraryBytes > MaximumLibraryBytesHardLimit)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidLimits,
                "The attachment limits are outside the implementation hard bounds.");
        }
    }

    internal static void EnsureMessageWithinLimits(
        IReadOnlyList<long> byteLengths,
        AttachmentLimitSettings limits)
    {
        ArgumentNullException.ThrowIfNull(byteLengths);
        EnsureValidLimits(limits);
        if (byteLengths.Count > limits.MaximumAttachmentsPerMessage)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.TooManyAttachments,
                "The attachment count exceeds the message limit.");
        }

        long totalBytes = 0;
        foreach (var byteLength in byteLengths)
        {
            if (byteLength <= 0 || byteLength > limits.MaximumBytesPerFile)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.FileTooLarge,
                    "An attachment length is outside the configured file limit.");
            }

            if (totalBytes > limits.MaximumBytesPerMessage - byteLength)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.MessageTooLarge,
                    "The attachment bytes exceed the message limit.");
            }

            totalBytes += byteLength;
        }
    }
}

internal sealed class ManagedAttachmentStore : IManagedAttachmentStore
{
    private const int CopyBufferBytes = 64 * 1024;
    private const long MinimumFreeSpaceReserveBytes = 1024L * 1024 * 1024;
    private const string TemporaryCleanupFailureDataKey =
        "AttachmentStoreTemporaryCleanupFailure";
    private const uint FileReadAttributes = 0x0080;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private readonly AttachmentTypeDetector _typeDetector;
    private readonly SemaphoreSlim _gate;

    public ManagedAttachmentStore(string dataDirectory)
        : this(dataDirectory, new AttachmentTypeDetector())
    {
    }

    internal ManagedAttachmentStore(
        string dataDirectory,
        AttachmentTypeDetector typeDetector)
    {
        ArgumentNullException.ThrowIfNull(typeDetector);
        DataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        AttachmentRoot = Path.Combine(DataDirectory, "attachments");
        ObjectsRoot = Path.Combine(AttachmentRoot, "objects");
        StagingRoot = Path.Combine(AttachmentRoot, "staging");
        _typeDetector = typeDetector;
        _gate = AttachmentMutationLeaseRegistry.Get(DataDirectory);
    }

    internal string DataDirectory { get; }

    internal string AttachmentRoot { get; }

    internal string ObjectsRoot { get; }

    internal string StagingRoot { get; }

    public async Task<ManagedAttachmentObject> ImportAsync(
        string sourcePath,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        AttachmentImportLimitGuard.EnsureValidLimits(limits);
        cancellationToken.ThrowIfCancellationRequested();
        var normalizedSourcePath = NormalizeAndValidateSourcePath(sourcePath);
        var originalFileName = Path.GetFileName(normalizedSourcePath);
        try
        {
            await using var source = new FileStream(
                normalizedSourcePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: CopyBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            _ = NormalizeAndValidateSourcePath(normalizedSourcePath);
            if (source.Length > limits.MaximumBytesPerFile)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.FileTooLarge,
                    "The source file exceeds the configured file limit.");
            }

            return await ImportBytesAsync(
                    source,
                    originalFileName,
                    limits,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (AttachmentImportException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (FileNotFoundException exception)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.SourceNotFound,
                "The source file no longer exists.",
                exception);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidSource,
                "The source file could not be opened safely.",
                exception);
        }
    }

    public async Task<ManagedAttachmentObject> ImportBytesAsync(
        Stream source,
        string originalFileName,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        AttachmentImportLimitGuard.EnsureValidLimits(limits);
        if (!source.CanRead)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidSource,
                "The attachment source is not readable.");
        }

        var normalizedFileName = NormalizeOriginalFileName(originalFileName);
        cancellationToken.ThrowIfCancellationRequested();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string? stagingPath = null;
        Exception? primaryFailure = null;
        try
        {
            EnsureStorageDirectories();
            stagingPath = Path.Combine(
                StagingRoot,
                $".{Environment.ProcessId}.{Guid.NewGuid():N}.part");
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, stagingPath);
            var copied = await CopyToStagingAsync(
                    source,
                    stagingPath,
                    limits.MaximumBytesPerFile,
                    cancellationToken)
                .ConfigureAwait(false);
            var detectedType = await _typeDetector.DetectAsync(
                    stagingPath,
                    normalizedFileName,
                    copied.ByteLength,
                    cancellationToken)
                .ConfigureAwait(false);
            var objectPath = GetObjectPath(copied.ContentId);
            if (File.Exists(objectPath))
            {
                if (!await VerifyObjectAsync(
                        copied.ContentId,
                        copied.ByteLength,
                        detectedType,
                        normalizedFileName,
                        objectPath,
                        cancellationToken)
                    .ConfigureAwait(false))
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.DamagedObject,
                        "An existing content-addressed object failed verification.");
                }

                return new ManagedAttachmentObject(
                    copied.ContentId,
                    copied.ByteLength,
                    detectedType,
                    objectPath);
            }

            EnsureLibraryCapacity(copied.ByteLength, limits);
            EnsureVolumeReserve();
            var objectDirectory = Path.GetDirectoryName(objectPath)!;
            CreateValidatedDirectory(objectDirectory);
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, stagingPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, objectPath);
            try
            {
                File.Move(stagingPath, objectPath);
            }
            catch (IOException) when (File.Exists(objectPath))
            {
                if (!await VerifyObjectAsync(
                        copied.ContentId,
                        copied.ByteLength,
                        detectedType,
                        normalizedFileName,
                        objectPath,
                        cancellationToken)
                    .ConfigureAwait(false))
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.DamagedObject,
                        "A concurrently published object failed verification.");
                }
            }

            return new ManagedAttachmentObject(
                copied.ContentId,
                copied.ByteLength,
                detectedType,
                objectPath);
        }
        catch (Exception exception)
        {
            primaryFailure = exception;
            throw;
        }
        finally
        {
            try
            {
                if (stagingPath is not null)
                {
                    DataDirectorySafety.Revalidate(DataDirectory);
                    DataDirectorySafety.RevalidateWriteTarget(DataDirectory, stagingPath);
                    File.Delete(stagingPath);
                }
            }
            catch (Exception cleanupFailure)
            {
                if (primaryFailure is null)
                {
                    throw;
                }

                primaryFailure.Data[TemporaryCleanupFailureDataKey] = cleanupFailure;
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    public async Task<bool> VerifyAsync(
        PresetAttachmentReference reference,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();
        if (!AttachmentIdentity.IsCanonicalContentId(reference.ContentId) ||
            reference.ByteLength <= 0 ||
            string.IsNullOrWhiteSpace(reference.DetectedType) ||
            string.IsNullOrWhiteSpace(reference.OriginalFileName))
        {
            return false;
        }

        try
        {
            var normalizedFileName = NormalizeOriginalFileName(reference.OriginalFileName);
            var objectPath = GetObjectPath(reference.ContentId);
            return await VerifyObjectAsync(
                    reference.ContentId,
                    reference.ByteLength,
                    reference.DetectedType,
                    normalizedFileName,
                    objectPath,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is AttachmentImportException or IOException or UnauthorizedAccessException or
                NotSupportedException)
        {
            return false;
        }
    }

    internal async Task<ManagedAttachmentObject?> ResolveVerifiedAsync(
        PresetAttachmentReference reference,
        CancellationToken cancellationToken)
    {
        if (!await VerifyAsync(reference, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        return new ManagedAttachmentObject(
            reference.ContentId,
            reference.ByteLength,
            reference.DetectedType,
            GetObjectPath(reference.ContentId));
    }

    internal AttachmentPhysicalDeleteResult Delete(
        ZeroReferenceProof proof,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proof);
        if (!AttachmentIdentity.IsCanonicalContentId(proof.ContentId))
        {
            throw new ArgumentException(
                "The attachment deletion proof has an invalid content identity.",
                nameof(proof));
        }

        cancellationToken.ThrowIfCancellationRequested();
        var objectPath = GetObjectPath(proof.ContentId);
        try
        {
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, objectPath);
            if (Directory.Exists(objectPath))
            {
                return new AttachmentPhysicalDeleteResult(false, "UnsafeObject");
            }

            if (!File.Exists(objectPath))
            {
                return new AttachmentPhysicalDeleteResult(true, string.Empty);
            }

            var attributes = File.GetAttributes(objectPath);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                               FileAttributes.Device)) != 0)
            {
                return new AttachmentPhysicalDeleteResult(false, "UnsafeObject");
            }

            var objectDirectory = Path.GetDirectoryName(objectPath)!;
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, objectDirectory);
            using var directoryHandle = OpenDirectoryForFlush(objectDirectory);
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, objectPath);
            cancellationToken.ThrowIfCancellationRequested();
            using (var deleteHandle = new FileStream(
                       objectPath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.DeleteOnClose | FileOptions.SequentialScan))
            {
                _ = deleteHandle.Length;
            }

            if (!FlushFileBuffers(directoryHandle))
            {
                throw CreateWin32IOException(
                    "The managed attachment object directory could not be flushed.");
            }

            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, objectPath);
            if (File.Exists(objectPath) || Directory.Exists(objectPath))
            {
                throw new IOException(
                    "The managed attachment object remained after exclusive deletion.");
            }

            return new AttachmentPhysicalDeleteResult(true, string.Empty);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return new AttachmentPhysicalDeleteResult(false, "AccessDenied");
        }
        catch (IOException)
        {
            return new AttachmentPhysicalDeleteResult(false, "ObjectBusy");
        }
        catch (NotSupportedException)
        {
            return new AttachmentPhysicalDeleteResult(false, "StorageUnavailable");
        }
    }

    private async Task<CopiedObject> CopyToStagingAsync(
        Stream source,
        string stagingPath,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferBytes);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long totalBytes = 0;
            await using (var staging = new FileStream(
                             stagingPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             bufferSize: CopyBufferBytes,
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

                    if (totalBytes > maximumBytes - read)
                    {
                        throw AttachmentImportException.Create(
                            AttachmentImportFailureCode.FileTooLarge,
                            "The attachment exceeded the configured file limit while streaming.");
                    }

                    hash.AppendData(buffer, 0, read);
                    await staging.WriteAsync(
                            buffer.AsMemory(0, read),
                            cancellationToken)
                        .ConfigureAwait(false);
                    totalBytes += read;
                }

                if (totalBytes == 0)
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.InvalidContent,
                        "An empty attachment is not accepted.");
                }

                cancellationToken.ThrowIfCancellationRequested();
                staging.Flush(flushToDisk: true);
            }

            return new CopiedObject(
                Convert.ToHexString(hash.GetHashAndReset()),
                totalBytes);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private async Task<bool> VerifyObjectAsync(
        string contentId,
        long expectedLength,
        string expectedType,
        string originalFileName,
        string objectPath,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, objectPath);
        if (!File.Exists(objectPath))
        {
            return false;
        }

        var attributes = File.GetAttributes(objectPath);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                           FileAttributes.Device)) != 0 ||
            new FileInfo(objectPath).Length != expectedLength)
        {
            return false;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferBytes);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using var stream = new FileStream(
                objectPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: CopyBufferBytes,
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

            if (totalBytes != expectedLength ||
                !string.Equals(
                    Convert.ToHexString(hash.GetHashAndReset()),
                    contentId,
                    StringComparison.Ordinal))
            {
                return false;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        var detectedType = await _typeDetector.DetectAsync(
                objectPath,
                originalFileName,
                expectedLength,
                cancellationToken)
            .ConfigureAwait(false);
        return string.Equals(detectedType, expectedType, StringComparison.Ordinal);
    }

    private void EnsureStorageDirectories()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        CreateValidatedDirectory(DataDirectory);
        CreateValidatedDirectory(AttachmentRoot);
        CreateValidatedDirectory(ObjectsRoot);
        CreateValidatedDirectory(StagingRoot);
    }

    private void CreateValidatedDirectory(string path)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        Directory.CreateDirectory(path);
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
    }

    private void EnsureLibraryCapacity(long candidateBytes, AttachmentLimitSettings limits)
    {
        var currentBytes = ComputeLibraryBytes();
        if (currentBytes > limits.MaximumLibraryBytes - candidateBytes)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.LibraryCapacityExceeded,
                "The managed attachment library has no capacity for this unique object.");
        }
    }

    private long ComputeLibraryBytes()
    {
        if (!Directory.Exists(ObjectsRoot))
        {
            return 0;
        }

        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, ObjectsRoot);
        long totalBytes = 0;
        foreach (var prefixDirectory in Directory.EnumerateDirectories(
                     ObjectsRoot,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, prefixDirectory);
            var prefixName = Path.GetFileName(prefixDirectory);
            if (!IsCanonicalPrefix(prefixName) ||
                Directory.EnumerateDirectories(prefixDirectory, "*", SearchOption.TopDirectoryOnly).Any())
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.DamagedObject,
                    "The managed object tree contains an invalid directory.");
            }

            foreach (var objectPath in Directory.EnumerateFiles(
                         prefixDirectory,
                         "*",
                         SearchOption.TopDirectoryOnly))
            {
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, objectPath);
                var attributes = File.GetAttributes(objectPath);
                var fileName = Path.GetFileName(objectPath);
                var contentId = Path.GetFileNameWithoutExtension(fileName);
                if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                                   FileAttributes.Device)) != 0 ||
                    !string.Equals(Path.GetExtension(fileName), ".blob", StringComparison.Ordinal) ||
                    !AttachmentIdentity.IsCanonicalContentId(contentId) ||
                    !string.Equals(prefixName, contentId[..2].ToLowerInvariant(), StringComparison.Ordinal))
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.DamagedObject,
                        "The managed object tree contains an invalid object.");
                }

                var length = new FileInfo(objectPath).Length;
                if (length <= 0 || totalBytes > long.MaxValue - length)
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.DamagedObject,
                        "The managed object tree has an invalid byte count.");
                }

                totalBytes += length;
            }
        }

        if (Directory.EnumerateFiles(ObjectsRoot, "*", SearchOption.TopDirectoryOnly).Any())
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.DamagedObject,
                "The managed object root contains an unexpected file.");
        }

        return totalBytes;
    }

    private void EnsureVolumeReserve()
    {
        var driveRoot = Path.GetPathRoot(DataDirectory)!;
        var drive = new DriveInfo(driveRoot);
        var reserve = Math.Max(MinimumFreeSpaceReserveBytes, drive.TotalSize / 20);
        if (drive.AvailableFreeSpace < reserve)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InsufficientFreeSpace,
                "The attachment import would violate the free-space reserve on the data volume.");
        }
    }

    private string GetObjectPath(string contentId)
    {
        if (!AttachmentIdentity.IsCanonicalContentId(contentId))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.DamagedObject,
                "The managed object identity is not canonical SHA-256.");
        }

        return Path.Combine(
            ObjectsRoot,
            contentId[..2].ToLowerInvariant(),
            contentId + ".blob");
    }

    private static string NormalizeOriginalFileName(string originalFileName)
    {
        var normalized = originalFileName?.Trim() ?? string.Empty;
        if (normalized.Length is 0 or > 255 ||
            normalized is "." or ".." ||
            !string.Equals(Path.GetFileName(normalized), normalized, StringComparison.Ordinal) ||
            normalized.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidFileName,
                "The original attachment filename is invalid.");
        }

        return normalized;
    }

    private static string NormalizeAndValidateSourcePath(string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidSource,
                "The attachment source path is empty.");
        }

        try
        {
            var candidate = sourcePath.Trim().Replace('/', '\\');
            if (candidate.StartsWith(@"\\", StringComparison.Ordinal) ||
                candidate.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase) ||
                candidate.StartsWith(@"\\??\", StringComparison.OrdinalIgnoreCase) ||
                candidate.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
                candidate.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.InvalidSource,
                    "Device, UNC, and extended source paths are not accepted.");
            }

            var fullPath = Path.GetFullPath(candidate);
            var root = Path.GetPathRoot(fullPath);
            if (root is not { Length: 3 } ||
                !char.IsAsciiLetter(root[0]) ||
                root[1] != ':' ||
                root[2] != Path.DirectorySeparatorChar ||
                new DriveInfo(root).DriveType != DriveType.Fixed)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.InvalidSource,
                    "The attachment source must be on a local fixed drive.");
            }

            if (Directory.Exists(fullPath))
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.SourceIsDirectory,
                    "Directories cannot be imported as attachments.");
            }

            if (!File.Exists(fullPath))
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.SourceNotFound,
                    "The attachment source file does not exist.");
            }

            var current = fullPath;
            while (true)
            {
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.SourceIsReparsePoint,
                        "Attachment source paths cannot traverse a reparse point.");
                }

                if ((attributes & FileAttributes.Device) != 0)
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.InvalidSource,
                        "Device sources cannot be imported as attachments.");
                }

                if (string.Equals(
                        Path.TrimEndingDirectorySeparator(current),
                        Path.TrimEndingDirectorySeparator(root),
                        StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(current));
                if (string.IsNullOrWhiteSpace(parent) ||
                    string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
                {
                    throw AttachmentImportException.Create(
                        AttachmentImportFailureCode.InvalidSource,
                        "The attachment source path could not be validated completely.");
                }

                current = parent;
            }

            return fullPath;
        }
        catch (AttachmentImportException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException or
                NotSupportedException)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidSource,
                "The attachment source path is invalid.",
                exception);
        }
    }

    private static bool IsCanonicalPrefix(string value) =>
        value.Length == 2 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static SafeFileHandle OpenDirectoryForFlush(string directoryPath)
    {
        var handle = CreateFile(
            directoryPath,
            GenericWrite | FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw CreateWin32IOException(
                "The managed attachment object directory could not be opened for flushing.");
        }

        return handle;
    }

    private static IOException CreateWin32IOException(string message) =>
        new(message, new Win32Exception(Marshal.GetLastWin32Error()));

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);

    private sealed record CopiedObject(string ContentId, long ByteLength);
}
