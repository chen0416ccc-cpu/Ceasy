using CodexGuardian.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Services;

internal sealed record AttachmentImportResult(
    string? Text,
    IReadOnlyList<PresetAttachmentReference> Attachments);

internal sealed class AttachmentImportService
{
    private const string CleanupRequestFailureDataKey =
        "AttachmentImportCleanupRequestFailure";

    private readonly IManagedAttachmentStore _store;
    private readonly Func<IReadOnlyList<string>, CancellationToken, Task>
        _requestZeroReferenceCleanupAsync;
    private readonly Func<string, long> _sourceLengthProvider;
    private readonly Func<string> _referenceIdFactory;

    public AttachmentImportService(
        IManagedAttachmentStore store,
        Func<IReadOnlyList<string>, CancellationToken, Task> requestZeroReferenceCleanupAsync)
        : this(
            store,
            requestZeroReferenceCleanupAsync,
            ProbeSourceLength,
            static () => Guid.NewGuid().ToString("D"))
    {
    }

    internal AttachmentImportService(
        IManagedAttachmentStore store,
        Func<IReadOnlyList<string>, CancellationToken, Task> requestZeroReferenceCleanupAsync,
        Func<string, long> sourceLengthProvider,
        Func<string> referenceIdFactory)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(requestZeroReferenceCleanupAsync);
        ArgumentNullException.ThrowIfNull(sourceLengthProvider);
        ArgumentNullException.ThrowIfNull(referenceIdFactory);
        _store = store;
        _requestZeroReferenceCleanupAsync = requestZeroReferenceCleanupAsync;
        _sourceLengthProvider = sourceLengthProvider;
        _referenceIdFactory = referenceIdFactory;
    }

    public async Task<AttachmentImportResult> ImportClipboardAsync(
        ClipboardAttachmentSource source,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        return await ImportClipboardAsync(
                source,
                Array.Empty<PresetAttachmentReference>(),
                limits,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AttachmentImportResult> ImportClipboardAsync(
        ClipboardAttachmentSource source,
        IReadOnlyList<PresetAttachmentReference> existingAttachments,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(existingAttachments);
        cancellationToken.ThrowIfCancellationRequested();

        switch (source)
        {
            case ClipboardTextSource textSource:
                return new AttachmentImportResult(
                    textSource.Text,
                    Array.Empty<PresetAttachmentReference>());
            case ClipboardEmptySource:
                return new AttachmentImportResult(
                    null,
                    Array.Empty<PresetAttachmentReference>());
            case ClipboardFileListSource fileListSource:
                return new AttachmentImportResult(
                    null,
                    await ImportFilesAsync(
                            fileListSource.FilePaths,
                            existingAttachments,
                            limits,
                            cancellationToken)
                        .ConfigureAwait(false));
            case ClipboardPngSource pngSource:
                return new AttachmentImportResult(
                    null,
                    await ImportPngAsync(
                            pngSource,
                            existingAttachments,
                            limits,
                            cancellationToken)
                        .ConfigureAwait(false));
            default:
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.InvalidSource,
                    "The clipboard attachment source is not supported.");
        }
    }

    public async Task<IReadOnlyList<PresetAttachmentReference>> ImportFilesAsync(
        IReadOnlyList<string> sourcePaths,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        return await ImportFilesAsync(
                sourcePaths,
                Array.Empty<PresetAttachmentReference>(),
                limits,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PresetAttachmentReference>> ImportFilesAsync(
        IReadOnlyList<string> sourcePaths,
        IReadOnlyList<PresetAttachmentReference> existingAttachments,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourcePaths);
        ArgumentNullException.ThrowIfNull(existingAttachments);
        AttachmentImportLimitGuard.EnsureValidLimits(limits);
        cancellationToken.ThrowIfCancellationRequested();

        var paths = sourcePaths.ToArray();
        var existingByteLengths = ValidateExistingAttachments(existingAttachments);
        AttachmentImportLimitGuard.EnsureMessageWithinLimits(
            existingByteLengths
                .Concat(Enumerable.Repeat(1L, paths.Length))
                .ToArray(),
            limits);
        if (paths.Length == 0)
        {
            return Array.Empty<PresetAttachmentReference>();
        }

        var pending = new PendingImport[paths.Length];
        var expectedLengths = new long[paths.Length];
        for (var index = 0; index < paths.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sourcePath = paths[index];
            var originalFileName = GetOriginalFileName(sourcePath);
            var expectedLength = ReadExpectedLength(sourcePath);
            expectedLengths[index] = expectedLength;
            pending[index] = new PendingImport(
                originalFileName,
                expectedLength,
                token => _store.ImportAsync(sourcePath, limits, token));
        }

        AttachmentImportLimitGuard.EnsureMessageWithinLimits(
            existingByteLengths.Concat(expectedLengths).ToArray(),
            limits);
        return await ImportBatchAsync(
                pending,
                existingByteLengths,
                limits,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private Task<IReadOnlyList<PresetAttachmentReference>> ImportPngAsync(
        ClipboardPngSource source,
        IReadOnlyList<PresetAttachmentReference> existingAttachments,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        if (source.PngBytes is null || source.PngBytes.Length == 0)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidContent,
                "The clipboard PNG is empty.");
        }

        var immutableBytes = source.PngBytes.ToArray();
        var pending = new PendingImport(
            source.OriginalFileName,
            immutableBytes.LongLength,
            async token =>
            {
                await using var stream = new MemoryStream(immutableBytes, writable: false);
                return await _store.ImportBytesAsync(
                        stream,
                        source.OriginalFileName,
                        limits,
                        token)
                    .ConfigureAwait(false);
            });
        return ImportBatchAsync(
            [pending],
            ValidateExistingAttachments(existingAttachments),
            limits,
            cancellationToken);
    }

    private async Task<IReadOnlyList<PresetAttachmentReference>> ImportBatchAsync(
        IReadOnlyList<PendingImport> pending,
        IReadOnlyList<long> existingByteLengths,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken)
    {
        AttachmentImportLimitGuard.EnsureMessageWithinLimits(
            existingByteLengths
                .Concat(pending.Select(item => item.ExpectedByteLength))
                .ToArray(),
            limits);

        var durable = new List<DurableImport>(pending.Count);
        try
        {
            foreach (var item in pending)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var imported = await item.ImportAsync(cancellationToken).ConfigureAwait(false);
                ValidateImportedObject(imported);
                durable.Add(new DurableImport(item.OriginalFileName, imported));
            }

            AttachmentImportLimitGuard.EnsureMessageWithinLimits(
                existingByteLengths
                    .Concat(durable.Select(item => item.Object.ByteLength))
                    .ToArray(),
                limits);
            cancellationToken.ThrowIfCancellationRequested();

            var referenceIds = new HashSet<string>(StringComparer.Ordinal);
            var references = new PresetAttachmentReference[durable.Count];
            for (var index = 0; index < durable.Count; index++)
            {
                var imported = durable[index];
                var referenceId = _referenceIdFactory();
                if (!AttachmentIdentity.IsCanonicalReferenceId(referenceId) ||
                    !referenceIds.Add(referenceId))
                {
                    throw new InvalidOperationException(
                        "The attachment reference ID factory returned an invalid or duplicate UUID.");
                }

                references[index] = new PresetAttachmentReference
                {
                    Id = referenceId,
                    ContentId = imported.Object.ContentId,
                    OriginalFileName = imported.OriginalFileName,
                    DetectedType = imported.Object.DetectedType,
                    OwnerInputKind = string.Equals(
                        imported.Object.DetectedType,
                        "image/png",
                        StringComparison.Ordinal)
                        ? "local_image"
                        : "local_file",
                    ByteLength = imported.Object.ByteLength,
                    Order = checked(existingByteLengths.Count + index)
                };
            }

            return Array.AsReadOnly(references);
        }
        catch (Exception exception)
        {
            await RequestZeroReferenceCleanupAsync(durable, exception).ConfigureAwait(false);
            throw;
        }
    }

    private static long[] ValidateExistingAttachments(
        IReadOnlyList<PresetAttachmentReference> existingAttachments)
    {
        var referenceIds = new HashSet<string>(StringComparer.Ordinal);
        var lengths = new long[existingAttachments.Count];
        for (var index = 0; index < existingAttachments.Count; index++)
        {
            var reference = existingAttachments[index];
            if (reference is null ||
                !AttachmentIdentity.IsCanonicalReferenceId(reference.Id) ||
                !referenceIds.Add(reference.Id) ||
                !AttachmentIdentity.IsCanonicalContentId(reference.ContentId) ||
                string.IsNullOrWhiteSpace(reference.OriginalFileName) ||
                string.IsNullOrWhiteSpace(reference.DetectedType) ||
                reference.ByteLength <= 0)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.DamagedObject,
                    "The existing attachment draft contains an invalid reference.");
            }

            lengths[index] = reference.ByteLength;
        }

        return lengths;
    }

    private async Task RequestZeroReferenceCleanupAsync(
        IReadOnlyList<DurableImport> durable,
        Exception primaryFailure)
    {
        var contentIds = durable
            .Select(item => item.Object.ContentId)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (contentIds.Length == 0)
        {
            return;
        }

        try
        {
            await _requestZeroReferenceCleanupAsync(contentIds, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception cleanupFailure)
        {
            primaryFailure.Data[CleanupRequestFailureDataKey] = cleanupFailure;
        }
    }

    private long ReadExpectedLength(string sourcePath)
    {
        try
        {
            return _sourceLengthProvider(sourcePath);
        }
        catch (AttachmentImportException)
        {
            throw;
        }
        catch (FileNotFoundException exception)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.SourceNotFound,
                "An attachment source no longer exists.",
                exception);
        }
        catch (DirectoryNotFoundException exception)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.SourceNotFound,
                "An attachment source directory no longer exists.",
                exception);
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException or
                NotSupportedException)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidSource,
                "An attachment source could not be inspected safely.",
                exception);
        }
    }

    private static long ProbeSourceLength(string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidSource,
                "The attachment source path is empty.");
        }

        var candidate = sourcePath.Trim();
        if (Directory.Exists(candidate))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.SourceIsDirectory,
                "Directories cannot be imported as attachments.");
        }

        var file = new FileInfo(candidate);
        if (!file.Exists)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.SourceNotFound,
                "The attachment source file does not exist.");
        }

        return file.Length;
    }

    private static string GetOriginalFileName(string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidSource,
                "The attachment source path is empty.");
        }

        var fileName = Path.GetFileName(sourcePath.Trim().Replace('/', '\\'));
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidFileName,
                "The attachment source has no valid filename.");
        }

        return fileName;
    }

    private static void ValidateImportedObject(ManagedAttachmentObject imported)
    {
        if (!AttachmentIdentity.IsCanonicalContentId(imported.ContentId) ||
            imported.ByteLength <= 0 ||
            string.IsNullOrWhiteSpace(imported.DetectedType) ||
            string.IsNullOrWhiteSpace(imported.ObjectPath))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.DamagedObject,
                "The managed attachment store returned an invalid object identity.");
        }
    }

    private sealed record PendingImport(
        string OriginalFileName,
        long ExpectedByteLength,
        Func<CancellationToken, Task<ManagedAttachmentObject>> ImportAsync);

    private sealed record DurableImport(
        string OriginalFileName,
        ManagedAttachmentObject Object);
}
