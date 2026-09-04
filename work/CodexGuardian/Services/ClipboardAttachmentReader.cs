using CodexGuardian.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;

namespace CodexGuardian.Services;

internal abstract record ClipboardAttachmentSource;

internal sealed record ClipboardFileListSource(
    IReadOnlyList<string> FilePaths) : ClipboardAttachmentSource;

internal sealed record ClipboardPngSource(
    byte[] PngBytes,
    string OriginalFileName) : ClipboardAttachmentSource;

internal sealed record ClipboardTextSource(
    string Text) : ClipboardAttachmentSource;

internal sealed record ClipboardEmptySource : ClipboardAttachmentSource;

internal sealed class ClipboardAttachmentReader
{
    private const string ClipboardPngFileName = "clipboard.png";

    private readonly Action<BitmapSource, Stream> _encodeBitmapPng;

    public ClipboardAttachmentReader()
        : this(EncodeBitmapPng)
    {
    }

    internal ClipboardAttachmentReader(Action<BitmapSource, Stream> encodeBitmapPng)
    {
        ArgumentNullException.ThrowIfNull(encodeBitmapPng);
        _encodeBitmapPng = encodeBitmapPng;
    }

    public ClipboardAttachmentSource Read(
        IReadOnlyList<string>? filePaths,
        Func<BitmapSource?> bitmapProvider,
        string? text,
        AttachmentLimitSettings limits)
    {
        ArgumentNullException.ThrowIfNull(bitmapProvider);

        if (filePaths is { Count: > 0 })
        {
            return new ClipboardFileListSource(filePaths.ToArray());
        }

        var bitmap = bitmapProvider();
        if (bitmap is not null)
        {
            AttachmentImportLimitGuard.EnsureValidLimits(limits);
            using var encoded = new BoundedMemoryStream(limits.MaximumBytesPerFile);
            _encodeBitmapPng(bitmap, encoded);
            if (encoded.Length == 0)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.InvalidContent,
                    "The clipboard bitmap produced an empty PNG.");
            }

            var pngBytes = encoded.ToArray();
            AttachmentImportLimitGuard.EnsureMessageWithinLimits(
                [pngBytes.LongLength],
                limits);
            return new ClipboardPngSource(pngBytes, ClipboardPngFileName);
        }

        return text is not null
            ? new ClipboardTextSource(text)
            : new ClipboardEmptySource();
    }

    private static void EncodeBitmapPng(BitmapSource bitmap, Stream destination)
    {
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        encoder.Save(destination);
    }

    private sealed class BoundedMemoryStream(long maximumBytes) : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        {
            EnsureWriteFits(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            EnsureWriteFits(buffer.Length);
            base.Write(buffer);
        }

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            EnsureWriteFits(count);
            return base.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            EnsureWriteFits(buffer.Length);
            return base.WriteAsync(buffer, cancellationToken);
        }

        public override void WriteByte(byte value)
        {
            EnsureWriteFits(1);
            base.WriteByte(value);
        }

        public override void SetLength(long value)
        {
            if (value > maximumBytes)
            {
                ThrowTooLarge();
            }

            base.SetLength(value);
        }

        private void EnsureWriteFits(int count)
        {
            if (count < 0 || Position > maximumBytes - count)
            {
                ThrowTooLarge();
            }
        }

        private static void ThrowTooLarge() =>
            throw AttachmentImportException.Create(
                AttachmentImportFailureCode.FileTooLarge,
                "The clipboard PNG exceeds the configured file limit.");
    }
}
