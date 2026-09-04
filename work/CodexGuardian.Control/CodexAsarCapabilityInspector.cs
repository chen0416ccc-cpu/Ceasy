using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CodexGuardian.Control;

internal interface ICodexAsarRandomAccessSource
{
    long Length { get; }

    void ReadExactly(long offset, Span<byte> destination);
}

internal sealed record CodexAsarSelectedEntry(
    string Path,
    long Offset,
    long Size,
    string Sha256);

internal sealed record CodexAsarCapabilitySnapshot(
    string ContractId,
    string PackageName,
    string ProductName,
    string PackageVersion,
    string MainPath,
    CodexAsarSelectedEntry PackageJson,
    CodexAsarSelectedEntry Main,
    CodexAsarSelectedEntry Preload);

internal sealed record CodexAsarCapabilityPolicy
{
    internal CodexAsarCapabilityPolicy(
        string contractId,
        string packageName,
        string productName,
        string mainPath,
        string mainSha256,
        string preloadPath,
        string preloadSha256,
        IReadOnlyList<string> preloadMarkers)
    {
        ContractId = RequireBounded(contractId, nameof(contractId), 128);
        PackageName = RequireBounded(packageName, nameof(packageName), 128);
        ProductName = RequireBounded(productName, nameof(productName), 128);
        MainPath = RequireCanonicalPath(mainPath, nameof(mainPath));
        MainSha256 = RequireSha256(mainSha256, nameof(mainSha256));
        PreloadPath = RequireCanonicalPath(preloadPath, nameof(preloadPath));
        PreloadSha256 = RequireSha256(preloadSha256, nameof(preloadSha256));
        ArgumentNullException.ThrowIfNull(preloadMarkers);
        var markers = new List<string>(preloadMarkers.Count);
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var marker in preloadMarkers)
        {
            var value = RequireBounded(marker, nameof(preloadMarkers), 256);
            if (!unique.Add(value))
            {
                throw new ArgumentException("Preload markers must be unique.", nameof(preloadMarkers));
            }

            markers.Add(value);
        }

        if (markers.Count is < 1 or > 32)
        {
            throw new ArgumentException("A bounded preload marker set is required.", nameof(preloadMarkers));
        }

        PreloadMarkers = markers.AsReadOnly();
    }

    internal string ContractId { get; }

    internal string PackageName { get; }

    internal string ProductName { get; }

    internal string MainPath { get; }

    internal string MainSha256 { get; }

    internal string PreloadPath { get; }

    internal string PreloadSha256 { get; }

    internal IReadOnlyList<string> PreloadMarkers { get; }

    private static string RequireBounded(string value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            throw new ArgumentException("A bounded non-empty value is required.", parameterName);
        }

        return value;
    }

    private static string RequireSha256(string value, string parameterName)
    {
        if (value is null || value.Length != 64)
        {
            throw new ArgumentException("A SHA-256 value is required.", parameterName);
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                throw new ArgumentException("A SHA-256 value is required.", parameterName);
            }
        }

        return value.ToUpperInvariant();
    }

    private static string RequireCanonicalPath(string value, string parameterName)
    {
        if (!CodexAsarCapabilityInspector.IsCanonicalPath(value))
        {
            throw new ArgumentException("A canonical ASAR path is required.", parameterName);
        }

        return value;
    }
}

internal sealed class CodexAsarCapabilityException : IOException
{
    internal CodexAsarCapabilityException(string code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal static class CodexAsarCapabilityInspector
{
    internal const long MaximumArchiveBytes = 1024L * 1024 * 1024;
    internal const int MaximumHeaderBytes = 32 * 1024 * 1024;
    internal const int MaximumPackageJsonBytes = 1024 * 1024;
    internal const int MaximumSelectedScriptBytes = 16 * 1024 * 1024;
    private const int MaximumJsonDepth = 64;
    private const int MaximumJsonValues = 1_000_000;
    private const int MaximumPathLength = 512;
    private const int MaximumPathSegments = 32;
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = MaximumJsonDepth
    };

    internal static CodexAsarCapabilitySnapshot Inspect(
        ICodexAsarRandomAccessSource source,
        CodexAsarCapabilityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(policy);
        if (source.Length is < 16 or > MaximumArchiveBytes)
        {
            throw Failure("asar-size", "The ASAR archive has an invalid bounded length.");
        }

        Span<byte> prefix = stackalloc byte[16];
        ReadExactly(source, 0, prefix);
        var sizePicklePayload = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        var headerPickleTotal = BinaryPrimitives.ReadUInt32LittleEndian(prefix[4..]);
        var headerPicklePayload = BinaryPrimitives.ReadUInt32LittleEndian(prefix[8..]);
        var jsonLength = BinaryPrimitives.ReadUInt32LittleEndian(prefix[12..]);
        uint alignedJsonLength;
        try
        {
            alignedJsonLength = checked((jsonLength + 3u) & ~3u);
        }
        catch (OverflowException exception)
        {
            throw Failure("asar-header", "The ASAR JSON length overflowed its alignment.", exception);
        }

        if (sizePicklePayload != sizeof(uint) ||
            headerPickleTotal is < 8 or > MaximumHeaderBytes ||
            (headerPickleTotal & 3) != 0 ||
            headerPicklePayload != headerPickleTotal - sizeof(uint) ||
            headerPicklePayload != checked(sizeof(uint) + alignedJsonLength) ||
            headerPickleTotal != checked(2u * sizeof(uint) + alignedJsonLength) ||
            jsonLength == 0)
        {
            throw Failure("asar-header", "The ASAR Pickle header is not canonical.");
        }

        long dataBase;
        try
        {
            dataBase = checked(8L + headerPickleTotal);
        }
        catch (OverflowException exception)
        {
            throw Failure("asar-header", "The ASAR data base overflowed.", exception);
        }

        if (dataBase > source.Length || jsonLength > int.MaxValue)
        {
            throw Failure("asar-header", "The ASAR header extends beyond the archive.");
        }

        var jsonBytes = new byte[checked((int)jsonLength)];
        ReadExactly(source, 16, jsonBytes);
        var paddingLength = checked((int)(alignedJsonLength - jsonLength));
        if (paddingLength > 0)
        {
            Span<byte> padding = stackalloc byte[3];
            var usedPadding = padding[..paddingLength];
            ReadExactly(source, checked(16L + jsonLength), usedPadding);
            foreach (var value in usedPadding)
            {
                if (value != 0)
                {
                    throw Failure("asar-header", "The ASAR header padding is not zero-filled.");
                }
            }
        }

        try
        {
            using var headerDocument = JsonDocument.Parse(jsonBytes, JsonOptions);
            var valueCount = 0;
            ValidateJsonShape(headerDocument.RootElement, 0, ref valueCount, "asar-json-duplicate");
            var root = headerDocument.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw Failure("asar-json", "The ASAR header root is not an object.");
            }

            JsonElement files = default;
            var rootPropertyCount = 0;
            foreach (var property in root.EnumerateObject())
            {
                rootPropertyCount++;
                if (property.NameEquals("files"))
                {
                    files = property.Value;
                }
            }

            if (rootPropertyCount != 1 || files.ValueKind != JsonValueKind.Object)
            {
                throw Failure("asar-json", "The ASAR header must contain only one files object.");
            }

            var packageEntry = ResolvePackedEntry(
                files,
                "package.json",
                dataBase,
                source.Length);
            var packageBytes = ReadEntry(
                source,
                packageEntry,
                MaximumPackageJsonBytes,
                "package.json");
            var packageMetadata = ReadPackageMetadata(packageBytes);
            if (!string.Equals(packageMetadata.Name, policy.PackageName, StringComparison.Ordinal) ||
                !string.Equals(packageMetadata.ProductName, policy.ProductName, StringComparison.Ordinal) ||
                !string.Equals(packageMetadata.MainPath, policy.MainPath, StringComparison.Ordinal))
            {
                throw Failure("asar-package", "The ASAR package metadata is incompatible.");
            }

            var mainEntry = ResolvePackedEntry(
                files,
                packageMetadata.MainPath,
                dataBase,
                source.Length);
            var preloadEntry = ResolvePackedEntry(
                files,
                policy.PreloadPath,
                dataBase,
                source.Length);
            EnsureDisjoint(packageEntry, mainEntry, preloadEntry);
            var mainBytes = ReadEntry(
                source,
                mainEntry,
                MaximumSelectedScriptBytes,
                "main entry");
            var preloadBytes = ReadEntry(
                source,
                preloadEntry,
                MaximumSelectedScriptBytes,
                "preload entry");
            var mainHash = Hash(mainBytes);
            var preloadHash = Hash(preloadBytes);
            if (!string.Equals(mainHash, policy.MainSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw Failure("asar-capability-hash", "The ASAR main entry hash is incompatible.");
            }

            if (!string.Equals(preloadHash, policy.PreloadSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw Failure("asar-capability-hash", "The ASAR preload entry hash is incompatible.");
            }

            string preloadSource;
            try
            {
                preloadSource = StrictUtf8.GetString(preloadBytes);
            }
            catch (DecoderFallbackException exception)
            {
                throw Failure("asar-capability-marker", "The ASAR preload is not strict UTF-8.", exception);
            }

            foreach (var marker in policy.PreloadMarkers)
            {
                if (!preloadSource.Contains(marker, StringComparison.Ordinal))
                {
                    throw Failure(
                        "asar-capability-marker",
                        "The ASAR preload is missing a required bridge capability marker.");
                }
            }

            return new CodexAsarCapabilitySnapshot(
                policy.ContractId,
                packageMetadata.Name,
                packageMetadata.ProductName,
                packageMetadata.Version,
                packageMetadata.MainPath,
                ToSnapshot(packageEntry, Hash(packageBytes)),
                ToSnapshot(mainEntry, mainHash),
                ToSnapshot(preloadEntry, preloadHash));
        }
        catch (CodexAsarCapabilityException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw Failure("asar-json", "The ASAR header contains invalid JSON.", exception);
        }
    }

    internal static bool IsCanonicalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            path.Length > MaximumPathLength ||
            path[0] == '/' ||
            path.IndexOfAny(['\\', ':', '\0']) >= 0)
        {
            return false;
        }

        var parts = path.Split('/', StringSplitOptions.None);
        if (parts.Length is < 1 or > MaximumPathSegments)
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length is < 1 or > 255 || part is "." or "..")
            {
                return false;
            }
        }

        return true;
    }

    private static PackedEntry ResolvePackedEntry(
        JsonElement rootFiles,
        string path,
        long dataBase,
        long archiveLength)
    {
        if (!IsCanonicalPath(path))
        {
            throw Failure("asar-path", "A selected ASAR path is not canonical.");
        }

        var parts = path.Split('/');
        var files = rootFiles;
        JsonElement node = default;
        for (var index = 0; index < parts.Length; index++)
        {
            if (!files.TryGetProperty(parts[index], out node) ||
                node.ValueKind != JsonValueKind.Object)
            {
                throw Failure("asar-entry", "A selected ASAR entry is missing.");
            }

            if (node.TryGetProperty("link", out _) || node.TryGetProperty("unpacked", out _))
            {
                throw Failure("asar-entry", "A selected ASAR path uses link or unpacked semantics.");
            }

            if (index < parts.Length - 1)
            {
                if (!node.TryGetProperty("files", out files) ||
                    files.ValueKind != JsonValueKind.Object ||
                    node.TryGetProperty("size", out _) ||
                    node.TryGetProperty("offset", out _))
                {
                    throw Failure("asar-entry", "A selected ASAR ancestor is not a canonical directory.");
                }
            }
        }

        if (node.TryGetProperty("files", out _) ||
            !node.TryGetProperty("size", out var sizeProperty) ||
            !node.TryGetProperty("offset", out var offsetProperty) ||
            sizeProperty.ValueKind != JsonValueKind.Number ||
            offsetProperty.ValueKind != JsonValueKind.String)
        {
            throw Failure("asar-entry", "A selected ASAR entry is not a canonical packed file.");
        }

        var size = ParseCanonicalDecimal(sizeProperty.GetRawText(), "asar-entry");
        var offset = ParseCanonicalDecimal(offsetProperty.GetString(), "asar-entry");
        if (size <= 0)
        {
            throw Failure("asar-entry", "A selected ASAR entry is empty.");
        }

        long absoluteOffset;
        long absoluteEnd;
        try
        {
            absoluteOffset = checked(dataBase + offset);
            absoluteEnd = checked(absoluteOffset + size);
        }
        catch (OverflowException exception)
        {
            throw Failure("asar-range", "A selected ASAR entry range overflowed.", exception);
        }

        if (absoluteOffset < dataBase || absoluteEnd > archiveLength)
        {
            throw Failure("asar-range", "A selected ASAR entry extends beyond the archive.");
        }

        return new PackedEntry(path, offset, absoluteOffset, absoluteEnd, size);
    }

    private static PackageMetadata ReadPackageMetadata(byte[] packageBytes)
    {
        try
        {
            using var document = JsonDocument.Parse(packageBytes, JsonOptions);
            var valueCount = 0;
            ValidateJsonShape(document.RootElement, 0, ref valueCount, "asar-package-duplicate");
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw Failure("asar-package", "The embedded package.json root is invalid.");
            }

            var name = ReadBoundedString(root, "name", 128);
            var productName = ReadBoundedString(root, "productName", 128);
            var version = ReadBoundedString(root, "version", 128);
            var mainPath = ReadBoundedString(root, "main", MaximumPathLength);
            if (!IsCanonicalPath(mainPath))
            {
                throw Failure("asar-package", "The embedded package.json main path is invalid.");
            }

            return new PackageMetadata(name, productName, version, mainPath);
        }
        catch (CodexAsarCapabilityException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw Failure("asar-package", "The embedded package.json is invalid JSON.", exception);
        }
    }

    private static string ReadBoundedString(JsonElement root, string name, int maximumLength)
    {
        if (!root.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String ||
            property.GetString() is not { Length: > 0 } value ||
            value.Length > maximumLength)
        {
            throw Failure("asar-package", "The embedded package.json metadata is missing or unbounded.");
        }

        return value;
    }

    private static void ValidateJsonShape(
        JsonElement value,
        int depth,
        ref int valueCount,
        string duplicateCode)
    {
        if (depth > MaximumJsonDepth || ++valueCount > MaximumJsonValues)
        {
            throw Failure("asar-json-bounds", "The ASAR JSON structure exceeds its bounds.");
        }

        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw Failure(duplicateCode, "The ASAR JSON structure contains duplicate properties.");
                }

                ValidateJsonShape(property.Value, depth + 1, ref valueCount, duplicateCode);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                ValidateJsonShape(item, depth + 1, ref valueCount, duplicateCode);
            }
        }
    }

    private static long ParseCanonicalDecimal(string? value, string code)
    {
        if (string.IsNullOrEmpty(value) ||
            value.Length > 19 ||
            value.Length > 1 && value[0] == '0')
        {
            throw Failure(code, "An ASAR numeric field is not canonical decimal.");
        }

        long result = 0;
        try
        {
            foreach (var character in value)
            {
                if (character is < '0' or > '9')
                {
                    throw Failure(code, "An ASAR numeric field is not canonical decimal.");
                }

                result = checked(result * 10 + character - '0');
            }
        }
        catch (OverflowException exception)
        {
            throw Failure(code, "An ASAR numeric field overflowed.", exception);
        }

        return result;
    }

    private static byte[] ReadEntry(
        ICodexAsarRandomAccessSource source,
        PackedEntry entry,
        int maximumBytes,
        string description)
    {
        if (entry.Size > maximumBytes || entry.Size > int.MaxValue)
        {
            throw Failure("asar-entry-bounds", "The selected ASAR " + description + " exceeds its bound.");
        }

        var bytes = new byte[checked((int)entry.Size)];
        ReadExactly(source, entry.AbsoluteOffset, bytes);
        return bytes;
    }

    private static void ReadExactly(
        ICodexAsarRandomAccessSource source,
        long offset,
        Span<byte> destination)
    {
        try
        {
            source.ReadExactly(offset, destination);
        }
        catch (Exception exception) when (
            exception is IOException or ArgumentException or InvalidOperationException or OverflowException)
        {
            throw Failure("asar-read", "The ASAR source could not satisfy a bounded read.", exception);
        }
    }

    private static void EnsureDisjoint(params PackedEntry[] entries)
    {
        for (var first = 0; first < entries.Length; first++)
        {
            for (var second = first + 1; second < entries.Length; second++)
            {
                if (entries[first].AbsoluteOffset < entries[second].AbsoluteEnd &&
                    entries[second].AbsoluteOffset < entries[first].AbsoluteEnd)
                {
                    throw Failure("asar-range", "Selected ASAR entry ranges overlap.");
                }
            }
        }
    }

    private static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes));

    private static CodexAsarSelectedEntry ToSnapshot(PackedEntry entry, string hash) =>
        new(entry.Path, entry.Offset, entry.Size, hash);

    private static CodexAsarCapabilityException Failure(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private sealed record PackedEntry(
        string Path,
        long Offset,
        long AbsoluteOffset,
        long AbsoluteEnd,
        long Size);

    private sealed record PackageMetadata(
        string Name,
        string ProductName,
        string Version,
        string MainPath);
}
