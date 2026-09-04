using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml;

namespace CodexGuardian.Control;

internal sealed record CodexAppxBlockMapFileObservation(
    string RelativePath,
    long Length,
    IReadOnlyList<string> BlockSha256);

internal sealed record CodexAppxBlockMapCoverage(
    int SelectedFileCount,
    int SelectedBlockCount);

internal sealed class CodexAppxBlockMapException : IOException
{
    internal CodexAppxBlockMapException(string message)
        : base(message)
    {
    }

    internal CodexAppxBlockMapException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal static class CodexAppxBlockMapVerifier
{
    internal const int BlockSizeBytes = 64 * 1024;
    internal const int MaximumBlockMapBytes = 8 * 1024 * 1024;
    internal const string BlockMapNamespace =
        "http://schemas.microsoft.com/appx/2010/blockmap";
    internal const string Sha256HashMethod =
        "http://www.w3.org/2001/04/xmlenc#sha256";

    private static readonly string[] RequiredSelectedPaths =
    [
        CodexPackageGenerationV1.ManifestRelativePath,
        CodexPackageGenerationV1.ChatGptExecutableRelativePath,
        CodexPackageGenerationV1.CodexExecutableRelativePath,
        CodexPackageGenerationV1.AppAsarRelativePath
    ];

    private static readonly long[] MaximumSelectedLengths =
    [
        4L * 1024 * 1024,
        512L * 1024 * 1024,
        512L * 1024 * 1024,
        1024L * 1024 * 1024
    ];

    internal static CodexAppxBlockMapCoverage Verify(
        byte[] blockMapContents,
        IReadOnlyList<CodexAppxBlockMapFileObservation> selectedFiles)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(blockMapContents);
            ArgumentNullException.ThrowIfNull(selectedFiles);
            if (blockMapContents.Length is <= 0 or > MaximumBlockMapBytes)
            {
                throw Failure("The AppX block map is empty or exceeds its byte bound.");
            }

            var normalized = NormalizeSelectedFiles(selectedFiles);
            var seen = new bool[normalized.Length];
            var selectedBlockCount = 0;
            var settings = new XmlReaderSettings
            {
                CheckCharacters = true,
                ConformanceLevel = ConformanceLevel.Document,
                DtdProcessing = DtdProcessing.Prohibit,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
                IgnoreWhitespace = true,
                MaxCharactersFromEntities = 0,
                MaxCharactersInDocument = MaximumBlockMapBytes,
                XmlResolver = null
            };

            using var stream = new MemoryStream(blockMapContents, writable: false);
            using var reader = XmlReader.Create(stream, settings);
            if (reader.MoveToContent() != XmlNodeType.Element ||
                reader.LocalName != "BlockMap" ||
                reader.NamespaceURI != BlockMapNamespace ||
                reader.IsEmptyElement ||
                !string.Equals(
                    reader.GetAttribute("HashMethod"),
                    Sha256HashMethod,
                    StringComparison.Ordinal))
            {
                throw Failure("The AppX block-map root or SHA-256 method is unexpected.");
            }

            var rootDepth = reader.Depth;
            var currentSelectedIndex = -1;
            var currentFileDepth = -1;
            var currentBlockIndex = 0;
            var rootClosed = false;
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.EndElement &&
                    reader.Depth == rootDepth &&
                    reader.LocalName == "BlockMap" &&
                    reader.NamespaceURI == BlockMapNamespace)
                {
                    if (currentSelectedIndex >= 0)
                    {
                        throw Failure("A selected AppX block-map file was not closed.");
                    }

                    rootClosed = true;
                    break;
                }

                if (reader.NodeType == XmlNodeType.Element &&
                    reader.Depth == rootDepth + 1 &&
                    reader.LocalName == "File" &&
                    reader.NamespaceURI == BlockMapNamespace)
                {
                    var name = reader.GetAttribute("Name");
                    if (string.IsNullOrEmpty(name) ||
                        name.Length > 1024 ||
                        name.Any(char.IsControl))
                    {
                        throw Failure("An AppX block-map file name is invalid.");
                    }

                    var selectedIndex = FindSelectedPath(name);
                    if (selectedIndex == -2)
                    {
                        throw Failure("A selected AppX block-map path is not ordinal canonical.");
                    }

                    if (selectedIndex < 0)
                    {
                        continue;
                    }

                    if (seen[selectedIndex])
                    {
                        throw Failure("A selected AppX block-map path appears more than once.");
                    }

                    var selected = normalized[selectedIndex];
                    if (!string.Equals(
                            reader.GetAttribute("Size"),
                            selected.Length.ToString(CultureInfo.InvariantCulture),
                            StringComparison.Ordinal))
                    {
                        throw Failure("A selected AppX block-map size does not match the file.");
                    }

                    seen[selectedIndex] = true;
                    currentSelectedIndex = selectedIndex;
                    currentFileDepth = reader.Depth;
                    currentBlockIndex = 0;
                    if (reader.IsEmptyElement)
                    {
                        CompleteSelectedFile(selected, currentBlockIndex);
                        currentSelectedIndex = -1;
                        currentFileDepth = -1;
                    }

                    continue;
                }

                if (currentSelectedIndex < 0)
                {
                    continue;
                }

                var current = normalized[currentSelectedIndex];
                if (reader.NodeType == XmlNodeType.EndElement &&
                    reader.Depth == currentFileDepth &&
                    reader.LocalName == "File" &&
                    reader.NamespaceURI == BlockMapNamespace)
                {
                    CompleteSelectedFile(current, currentBlockIndex);
                    selectedBlockCount = checked(selectedBlockCount + currentBlockIndex);
                    currentSelectedIndex = -1;
                    currentFileDepth = -1;
                    currentBlockIndex = 0;
                    continue;
                }

                if (reader.NodeType != XmlNodeType.Element ||
                    reader.Depth != currentFileDepth + 1)
                {
                    continue;
                }

                if (reader.NamespaceURI == BlockMapNamespace && reader.LocalName == "Block")
                {
                    if (!reader.IsEmptyElement || currentBlockIndex >= current.BlockSha256.Count)
                    {
                        throw Failure("A selected AppX block-map block count is invalid.");
                    }

                    var hash = reader.GetAttribute("Hash");
                    RequireCanonicalSha256Base64(hash, "block-map hash");
                    if (!string.Equals(
                            hash,
                            current.BlockSha256[currentBlockIndex],
                            StringComparison.Ordinal))
                    {
                        throw Failure("A selected AppX block hash does not match the file bytes.");
                    }

                    currentBlockIndex++;
                }
                else if (reader.NamespaceURI == BlockMapNamespace)
                {
                    throw Failure("A selected AppX block-map file has an unexpected base element.");
                }
            }

            if (!rootClosed || seen.Any(value => !value))
            {
                throw Failure("The AppX block map does not contain every selected file exactly once.");
            }

            while (reader.Read())
            {
                if (reader.NodeType is XmlNodeType.Element or XmlNodeType.Text or
                    XmlNodeType.CDATA or XmlNodeType.EntityReference)
                {
                    throw Failure("The AppX block map contains content after its root element.");
                }
            }

            return new CodexAppxBlockMapCoverage(normalized.Length, selectedBlockCount);
        }
        catch (CodexAppxBlockMapException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            IOException or
            InvalidOperationException or
            OverflowException or
            XmlException)
        {
            throw new CodexAppxBlockMapException(
                "The bounded AppX block map could not be safely verified.",
                exception);
        }
    }

    private static CodexAppxBlockMapFileObservation[] NormalizeSelectedFiles(
        IReadOnlyList<CodexAppxBlockMapFileObservation> selectedFiles)
    {
        if (selectedFiles.Count != RequiredSelectedPaths.Length)
        {
            throw Failure("The exact selected AppX file set is required.");
        }

        var normalized = new CodexAppxBlockMapFileObservation[selectedFiles.Count];
        for (var index = 0; index < selectedFiles.Count; index++)
        {
            var selected = selectedFiles[index] ??
                throw Failure("A selected AppX file observation is missing.");
            if (!string.Equals(
                    selected.RelativePath,
                    RequiredSelectedPaths[index],
                    StringComparison.Ordinal) ||
                selected.Length <= 0 ||
                selected.Length > MaximumSelectedLengths[index])
            {
                throw Failure("A selected AppX file path or length is invalid.");
            }

            ArgumentNullException.ThrowIfNull(selected.BlockSha256);
            var expectedBlockCount = checked((int)(
                (selected.Length + BlockSizeBytes - 1) / BlockSizeBytes));
            if (selected.BlockSha256.Count != expectedBlockCount)
            {
                throw Failure("A selected AppX file has an invalid observed block count.");
            }

            var hashes = new string[selected.BlockSha256.Count];
            for (var blockIndex = 0; blockIndex < hashes.Length; blockIndex++)
            {
                var hash = selected.BlockSha256[blockIndex];
                RequireCanonicalSha256Base64(hash, "observed block hash");
                hashes[blockIndex] = hash;
            }

            normalized[index] = new CodexAppxBlockMapFileObservation(
                selected.RelativePath,
                selected.Length,
                Array.AsReadOnly(hashes));
        }

        return normalized;
    }

    private static int FindSelectedPath(string path)
    {
        for (var index = 0; index < RequiredSelectedPaths.Length; index++)
        {
            if (string.Equals(path, RequiredSelectedPaths[index], StringComparison.Ordinal))
            {
                return index;
            }
        }

        var slashNormalized = path.Replace('/', '\\');
        for (var index = 0; index < RequiredSelectedPaths.Length; index++)
        {
            if (string.Equals(
                    slashNormalized,
                    RequiredSelectedPaths[index],
                    StringComparison.OrdinalIgnoreCase))
            {
                return -2;
            }
        }

        return -1;
    }

    private static void CompleteSelectedFile(
        CodexAppxBlockMapFileObservation selected,
        int blockCount)
    {
        if (blockCount != selected.BlockSha256.Count)
        {
            throw Failure("A selected AppX block-map block count does not match the file.");
        }
    }

    private static void RequireCanonicalSha256Base64(string? value, string description)
    {
        if (value is null)
        {
            throw Failure("A canonical SHA-256 " + description + " is required.");
        }

        Span<byte> decoded = stackalloc byte[32];
        if (!Convert.TryFromBase64String(value, decoded, out var bytesWritten) ||
            bytesWritten != decoded.Length ||
            !string.Equals(
                Convert.ToBase64String(decoded),
                value,
                StringComparison.Ordinal))
        {
            throw Failure("A canonical SHA-256 " + description + " is required.");
        }
    }

    private static CodexAppxBlockMapException Failure(string message) => new(message);
}
