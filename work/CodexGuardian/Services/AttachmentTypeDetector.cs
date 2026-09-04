using System.Buffers.Binary;
using System.Text;
using System.Windows.Media.Imaging;

namespace CodexGuardian.Services;

internal sealed class AttachmentTypeDetector
{
    private const long MaximumDecodedImagePixels = 100_000_000;
    private static readonly byte[] PngSignature =
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal async Task<string> DetectAsync(
        string path,
        string originalFileName,
        long byteLength,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(originalFileName);
        cancellationToken.ThrowIfCancellationRequested();
        if (byteLength <= 0)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidContent,
                "An empty file cannot be imported as an attachment.");
        }

        var extension = Path.GetExtension(originalFileName).ToLowerInvariant();
        var header = new byte[24];
        var headerLength = await ReadHeaderAsync(path, header, cancellationToken).ConfigureAwait(false);
        var hasPngSignature = headerLength >= PngSignature.Length &&
                              header.AsSpan(0, PngSignature.Length).SequenceEqual(PngSignature);
        if (hasPngSignature || string.Equals(extension, ".png", StringComparison.Ordinal))
        {
            if (!hasPngSignature || headerLength < header.Length)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.InvalidContent,
                    "The PNG signature or header is incomplete.");
            }

            ValidatePngHeader(header);
            await ValidatePngDecodabilityAsync(path, cancellationToken).ConfigureAwait(false);
            return "image/png";
        }

        if (string.Equals(extension, ".pdf", StringComparison.Ordinal))
        {
            if (headerLength < 5 || !header.AsSpan(0, 5).SequenceEqual("%PDF-"u8))
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.InvalidContent,
                    "The PDF signature does not match its filename.");
            }

            return "application/pdf";
        }

        var isDeclaredText = extension is ".txt" or ".md" or ".csv" or ".log" or
            ".json" or ".xml" or ".yaml" or ".yml";
        var isUtf8Text = await IsUtf8TextAsync(path, cancellationToken).ConfigureAwait(false);
        if (isDeclaredText && !isUtf8Text)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidContent,
                "The text attachment is not valid UTF-8 text.");
        }

        return isUtf8Text ? "text/plain" : "application/octet-stream";
    }

    private static async Task<int> ReadHeaderAsync(
        string path,
        Memory<byte> header,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var total = 0;
        while (total < header.Length)
        {
            var read = await stream.ReadAsync(header[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static void ValidatePngHeader(ReadOnlySpan<byte> header)
    {
        if (BinaryPrimitives.ReadUInt32BigEndian(header[8..12]) != 13 ||
            !header[12..16].SequenceEqual("IHDR"u8))
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidContent,
                "The PNG does not begin with a canonical IHDR chunk.");
        }

        var width = BinaryPrimitives.ReadUInt32BigEndian(header[16..20]);
        var height = BinaryPrimitives.ReadUInt32BigEndian(header[20..24]);
        if (width == 0 || height == 0 ||
            width > MaximumDecodedImagePixels ||
            height > MaximumDecodedImagePixels ||
            width > MaximumDecodedImagePixels / height)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidContent,
                "The PNG dimensions exceed the bounded decoder budget.");
        }
    }

    private static async Task ValidatePngDecodabilityAsync(
        string path,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var decoder = new PngBitmapDecoder(
                stream,
                BitmapCreateOptions.PreservePixelFormat,
                BitmapCacheOption.OnLoad);
            if (decoder.Frames.Count == 0 ||
                decoder.Frames[0].PixelWidth <= 0 ||
                decoder.Frames[0].PixelHeight <= 0)
            {
                throw new InvalidDataException("The PNG decoder returned no bounded frame.");
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or InvalidDataException or InvalidOperationException or
                NotSupportedException or ArgumentException or FormatException)
        {
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.InvalidContent,
                "The PNG body is not decodable.",
                exception);
        }
    }

    private static async Task<bool> IsUtf8TextAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var reader = new StreamReader(
                stream,
                StrictUtf8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 4096,
                leaveOpen: false);
            var buffer = new char[4096];
            while (true)
            {
                var read = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return true;
                }

                if (buffer.AsSpan(0, read).Contains('\0'))
                {
                    return false;
                }
            }
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
