using CodexGuardian.Models;
using System.Windows.Media.Imaging;

namespace CodexGuardian.Services;

internal sealed record ManagedAttachmentThumbnail(
    BitmapSource Image,
    int PixelWidth,
    int PixelHeight);

internal sealed class ManagedAttachmentThumbnailService
{
    private const int MaximumThumbnailDimension = 2048;
    private readonly ManagedAttachmentStore _store;

    public ManagedAttachmentThumbnailService(ManagedAttachmentStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    public async Task<ManagedAttachmentThumbnail?> LoadAsync(
        PresetAttachmentReference reference,
        int maximumPixelWidth,
        int maximumPixelHeight,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (maximumPixelWidth is < 1 or > MaximumThumbnailDimension)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumPixelWidth));
        }

        if (maximumPixelHeight is < 1 or > MaximumThumbnailDimension)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumPixelHeight));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(reference.DetectedType, "image/png", StringComparison.Ordinal) ||
            !await _store.VerifyAsync(reference, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var objectPath = Path.Combine(
            _store.ObjectsRoot,
            reference.ContentId[..2].ToLowerInvariant(),
            reference.ContentId + ".blob");
        DataDirectorySafety.Revalidate(_store.DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(_store.DataDirectory, objectPath);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            await using var stream = new FileStream(
                objectPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 16 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (stream.Length != reference.ByteLength)
            {
                return null;
            }

            var image = new BitmapImage();
            image.BeginInit();
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.CreateOptions = BitmapCreateOptions.PreservePixelFormat;
            image.DecodePixelWidth = maximumPixelWidth;
            image.DecodePixelHeight = maximumPixelHeight;
            image.StreamSource = stream;
            image.EndInit();
            cancellationToken.ThrowIfCancellationRequested();
            if (image.PixelWidth is < 1 || image.PixelWidth > maximumPixelWidth ||
                image.PixelHeight is < 1 || image.PixelHeight > maximumPixelHeight)
            {
                return null;
            }

            image.Freeze();
            return new ManagedAttachmentThumbnail(
                image,
                image.PixelWidth,
                image.PixelHeight);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                InvalidOperationException or NotSupportedException or ArgumentException or
                FormatException)
        {
            return null;
        }
    }
}
