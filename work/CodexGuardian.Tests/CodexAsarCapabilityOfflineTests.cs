using CodexGuardian.Control;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class CodexAsarCapabilityOfflineTests
{
    private const string MainPath = ".vite/build/early-bootstrap.js";
    private const string PreloadPath = ".vite/build/preload.js";
    private static readonly byte[] MainBytes = Encoding.UTF8.GetBytes(
        "require(\"./bootstrap-capability.js\");");
    private static readonly byte[] PreloadBytes = Encoding.UTF8.GetBytes(
        "electronBridge codex_desktop:message-for-view " +
        "contextBridge.exposeInMainWorld MessageEvent");
    private static readonly string[] Markers =
    [
        "electronBridge",
        "codex_desktop:message-for-view",
        "contextBridge.exposeInMainWorld",
        "MessageEvent"
    ];

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase("ASAR capability inspector accepts one canonical archive", TestCanonicalArchive, assert);
        RunCase("ASAR capability inspector ignores unrelated packed content", TestUnrelatedContent, assert);
        RunCase("ASAR capability inspector rejects changed capability bytes and markers", TestCapabilityChanges, assert);
        RunCase("ASAR capability inspector validates package semantics", TestPackageMetadata, assert);
        RunCase("ASAR capability inspector rejects malformed Pickle envelopes", TestMalformedEnvelope, assert);
        RunCase("ASAR capability inspector rejects unsafe selected entries", TestUnsafeEntries, assert);
        return Task.CompletedTask;
    }

    private static void TestCanonicalArchive()
    {
        var archive = BuildArchive();
        var snapshot = CodexAsarCapabilityInspector.Inspect(
            new ByteArraySource(archive),
            CreatePolicy());
        Ensure(snapshot.ContractId == "codex-cdp-observation-v1", "the capability contract id was lost");
        Ensure(snapshot.PackageName == "openai-codex-electron", "the package name was lost");
        Ensure(snapshot.ProductName == "Codex", "the product name was lost");
        Ensure(snapshot.PackageVersion == "26.731.1", "the diagnostic package version was lost");
        Ensure(snapshot.MainPath == MainPath, "the declared main path was lost");
        Ensure(snapshot.Main.Sha256 == Hash(MainBytes), "the main hash was not observed");
        Ensure(snapshot.Preload.Sha256 == Hash(PreloadBytes), "the preload hash was not observed");
        Ensure(snapshot.PackageJson.Size > 0, "the package.json entry was not bounded");
    }

    private static void TestUnrelatedContent()
    {
        var first = BuildArchive(unrelatedContents: "unrelated-alpha");
        var second = BuildArchive(unrelatedContents: "unrelated-bravo");
        Ensure(Hash(first) != Hash(second), "the whole-ASAR fixture hash did not change");
        var policy = CreatePolicy();
        var firstSnapshot = CodexAsarCapabilityInspector.Inspect(new ByteArraySource(first), policy);
        var secondSnapshot = CodexAsarCapabilityInspector.Inspect(new ByteArraySource(second), policy);
        Ensure(firstSnapshot == secondSnapshot, "unrelated packed content changed the capability snapshot");
    }

    private static void TestCapabilityChanges()
    {
        var changedMain = Encoding.UTF8.GetBytes("require(\"./different-bootstrap.js\");");
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(mainBytes: changedMain)),
                CreatePolicy()),
            "asar-capability-hash");

        var changedPreload = Encoding.UTF8.GetBytes(
            "electronBridge codex_desktop:message-for-view contextBridge.exposeInMainWorld");
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(preloadBytes: changedPreload)),
                CreatePolicy(preloadBytes: changedPreload)),
            "asar-capability-marker");
    }

    private static void TestPackageMetadata()
    {
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(packageName: "other-electron")),
                CreatePolicy()),
            "asar-package");
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(productName: "Other")),
                CreatePolicy()),
            "asar-package");
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(declaredMain: "../escape.js")),
                CreatePolicy()),
            "asar-package");
    }

    private static void TestMalformedEnvelope()
    {
        var archive = BuildArchive();
        var wrongSizePickle = archive.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(wrongSizePickle, 5);
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(new ByteArraySource(wrongSizePickle), CreatePolicy()),
            "asar-header");

        var wrongInnerPickle = archive.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(
            wrongInnerPickle.AsSpan(8),
            BinaryPrimitives.ReadUInt32LittleEndian(wrongInnerPickle.AsSpan(8)) - 4);
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(new ByteArraySource(wrongInnerPickle), CreatePolicy()),
            "asar-header");

        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(archive.AsSpan(0, 15).ToArray()),
                CreatePolicy()),
            "asar-size");

        var duplicateRoot = DuplicateRootFilesProperty(archive);
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(new ByteArraySource(duplicateRoot), CreatePolicy()),
            "asar-json-duplicate");

        var padded = FindArchiveWithPadding();
        var jsonLength = BinaryPrimitives.ReadUInt32LittleEndian(padded.AsSpan(12));
        padded[checked(16 + (int)jsonLength)] = 1;
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(new ByteArraySource(padded), CreatePolicy()),
            "asar-header");
    }

    private static void TestUnsafeEntries()
    {
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(preloadUnpacked: true)),
                CreatePolicy()),
            "asar-entry");
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(preloadLink: true)),
                CreatePolicy()),
            "asar-entry");
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(preloadOffset: "999999999999")),
                CreatePolicy()),
            "asar-range");
        ExpectCode(
            () => CodexAsarCapabilityInspector.Inspect(
                new ByteArraySource(BuildArchive(preloadOffset: "00")),
                CreatePolicy()),
            "asar-entry");
    }

    internal static CodexAsarCapabilityPolicy CreatePolicy(
        byte[]? mainBytes = null,
        byte[]? preloadBytes = null) =>
        new(
            "codex-cdp-observation-v1",
            "openai-codex-electron",
            "Codex",
            MainPath,
            Hash(mainBytes ?? MainBytes),
            PreloadPath,
            Hash(preloadBytes ?? PreloadBytes),
            Markers);

    internal static byte[] BuildArchive(
        string packageName = "openai-codex-electron",
        string productName = "Codex",
        string packageVersion = "26.731.1",
        string declaredMain = MainPath,
        byte[]? mainBytes = null,
        byte[]? preloadBytes = null,
        string unrelatedContents = "unrelated-alpha",
        bool preloadUnpacked = false,
        bool preloadLink = false,
        string? preloadOffset = null,
        IReadOnlyDictionary<string, byte[]>? additionalEntries = null)
    {
        mainBytes ??= MainBytes;
        preloadBytes ??= PreloadBytes;
        var packageBytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            name = packageName,
            productName,
            version = packageVersion,
            main = declaredMain
        });
        var entries = new List<EntrySpec>
        {
            new("package.json", packageBytes),
            new(MainPath, mainBytes),
            new(
                PreloadPath,
                preloadBytes,
                OffsetOverride: preloadOffset,
                Unpacked: preloadUnpacked,
                Link: preloadLink),
            new("assets/unrelated.txt", Encoding.UTF8.GetBytes(unrelatedContents))
        };
        if (additionalEntries is not null)
        {
            var existing = entries.Select(entry => entry.Path).ToHashSet(StringComparer.Ordinal);
            foreach (var entry in additionalEntries.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                if (!CodexAsarCapabilityInspector.IsCanonicalPath(entry.Key) ||
                    entry.Value is not { Length: > 0 } ||
                    !existing.Add(entry.Key))
                {
                    throw new ArgumentException(
                        "Additional ASAR fixture entries must be unique canonical non-empty files.",
                        nameof(additionalEntries));
                }

                entries.Add(new EntrySpec(entry.Key, entry.Value));
            }
        }
        var rootFiles = new JsonObject();
        using var payload = new MemoryStream();
        foreach (var entry in entries)
        {
            var offset = payload.Position;
            payload.Write(entry.Contents);
            JsonObject node;
            if (entry.Link)
            {
                node = new JsonObject { ["link"] = "assets/unrelated.txt" };
            }
            else
            {
                node = new JsonObject
                {
                    ["size"] = entry.Contents.LongLength,
                    ["offset"] = entry.OffsetOverride ?? offset.ToString(System.Globalization.CultureInfo.InvariantCulture)
                };
                if (entry.Unpacked)
                {
                    node["unpacked"] = true;
                }
            }

            AddNode(rootFiles, entry.Path, node);
        }

        var root = new JsonObject { ["files"] = rootFiles };
        return BuildEnvelope(JsonSerializer.SerializeToUtf8Bytes(root), payload.ToArray());
    }

    private static void AddNode(JsonObject rootFiles, string path, JsonObject fileNode)
    {
        var parts = path.Split('/');
        var files = rootFiles;
        for (var index = 0; index < parts.Length - 1; index++)
        {
            if (files[parts[index]] is not JsonObject directory)
            {
                directory = new JsonObject { ["files"] = new JsonObject() };
                files[parts[index]] = directory;
            }

            files = (JsonObject)directory["files"]!;
        }

        files[parts[^1]] = fileNode;
    }

    private static byte[] BuildEnvelope(byte[] jsonBytes, byte[] payload)
    {
        var alignedJsonLength = checked((jsonBytes.Length + 3) & ~3);
        var headerPicklePayload = checked(4 + alignedJsonLength);
        var headerPickleTotal = checked(8 + alignedJsonLength);
        var archive = new byte[checked(8 + headerPickleTotal + payload.Length)];
        BinaryPrimitives.WriteUInt32LittleEndian(archive, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(4), checked((uint)headerPickleTotal));
        BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(8), checked((uint)headerPicklePayload));
        BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(12), checked((uint)jsonBytes.Length));
        jsonBytes.CopyTo(archive.AsSpan(16));
        payload.CopyTo(archive.AsSpan(8 + headerPickleTotal));
        return archive;
    }

    private static byte[] DuplicateRootFilesProperty(byte[] archive)
    {
        var jsonLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(12)));
        var json = StrictUtf8(archive.AsSpan(16, jsonLength));
        var property = json[1..^1];
        var duplicateJson = Encoding.UTF8.GetBytes("{" + property + "," + property + "}");
        var headerTotal = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(4)));
        var payload = archive.AsSpan(8 + headerTotal).ToArray();
        return BuildEnvelope(duplicateJson, payload);
    }

    private static byte[] FindArchiveWithPadding()
    {
        for (var index = 0; index < 8; index++)
        {
            var archive = BuildArchive(unrelatedContents: new string('x', index + 1));
            var jsonLength = BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(12));
            if ((jsonLength & 3) != 0)
            {
                return archive;
            }
        }

        throw new InvalidOperationException("A padded ASAR fixture could not be generated.");
    }

    private static string StrictUtf8(ReadOnlySpan<byte> value) =>
        new UTF8Encoding(false, true).GetString(value);

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value));

    private static void ExpectCode(Action action, string expectedCode)
    {
        try
        {
            action();
        }
        catch (CodexAsarCapabilityException exception)
        {
            Ensure(exception.Code == expectedCode,
                "expected " + expectedCode + " but received " + exception.Code);
            return;
        }

        throw new InvalidOperationException("Expected ASAR failure code " + expectedCode + ".");
    }

    private static void RunCase(string name, Action test, Action<bool, string> assert)
    {
        try
        {
            test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record EntrySpec(
        string Path,
        byte[] Contents,
        string? OffsetOverride = null,
        bool Unpacked = false,
        bool Link = false);

    private sealed class ByteArraySource(byte[] bytes) : ICodexAsarRandomAccessSource
    {
        private readonly byte[] _bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));

        public long Length => _bytes.LongLength;

        public void ReadExactly(long offset, Span<byte> destination)
        {
            if (offset < 0 || offset > _bytes.LongLength - destination.Length)
            {
                throw new EndOfStreamException("The in-memory ASAR source was truncated.");
            }

            _bytes.AsSpan(checked((int)offset), destination.Length).CopyTo(destination);
        }
    }
}
