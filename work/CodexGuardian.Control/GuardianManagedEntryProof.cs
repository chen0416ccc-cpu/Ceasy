using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed record GuardianManagedEntryMetadataIdentityV1
{
    internal const string ExpectedAppHostFileName = "CodexGuardian.exe";
    internal const string ExpectedManagedEntryRelativePath = "CodexGuardian.dll";
    internal const string ExpectedAssemblyName = "CodexGuardian";
    internal const string ExpectedEntryPointDeclaringType = "CodexGuardian.Program";
    internal const string ExpectedEntryPointMethod = "Main";

    internal GuardianManagedEntryMetadataIdentityV1(
        string appHostFileName,
        string managedEntryRelativePath,
        string assemblyName,
        Guid moduleVersionId,
        int entryPointMetadataToken,
        string entryPointDeclaringType,
        string entryPointMethod)
    {
        RequireExact(appHostFileName, ExpectedAppHostFileName, nameof(appHostFileName));
        RequireExact(
            managedEntryRelativePath,
            ExpectedManagedEntryRelativePath,
            nameof(managedEntryRelativePath));
        RequireExact(assemblyName, ExpectedAssemblyName, nameof(assemblyName));
        if (moduleVersionId == Guid.Empty)
        {
            throw new ArgumentException(
                "A non-empty Guardian managed-entry module identifier is required.",
                nameof(moduleVersionId));
        }

        if ((entryPointMetadataToken & unchecked((int)0xFF000000)) != 0x06000000 ||
            (entryPointMetadataToken & 0x00FFFFFF) == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(entryPointMetadataToken),
                "A managed MethodDef entry-point token is required.");
        }

        RequireExact(
            entryPointDeclaringType,
            ExpectedEntryPointDeclaringType,
            nameof(entryPointDeclaringType));
        RequireExact(entryPointMethod, ExpectedEntryPointMethod, nameof(entryPointMethod));
        AppHostFileName = appHostFileName;
        ManagedEntryRelativePath = managedEntryRelativePath;
        AssemblyName = assemblyName;
        ModuleVersionId = moduleVersionId;
        EntryPointMetadataToken = entryPointMetadataToken;
        EntryPointDeclaringType = entryPointDeclaringType;
        EntryPointMethod = entryPointMethod;
    }

    internal string AppHostFileName { get; }

    internal string ManagedEntryRelativePath { get; }

    internal string AssemblyName { get; }

    internal Guid ModuleVersionId { get; }

    internal int EntryPointMetadataToken { get; }

    internal string EntryPointDeclaringType { get; }

    internal string EntryPointMethod { get; }

    internal static GuardianManagedEntryMetadataIdentityV1 ReadFromAssemblyFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A managed-entry assembly path is required.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(
                Path.GetFileName(fullPath),
                ExpectedManagedEntryRelativePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The verified Guardian managed entry has an unexpected file name.");
        }

        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        if (!peReader.HasMetadata || peReader.PEHeaders.CorHeader is null ||
            (peReader.PEHeaders.CorHeader.Flags & CorFlags.NativeEntryPoint) != 0)
        {
            throw new InvalidDataException(
                "The verified Guardian managed entry is not a managed assembly entry point.");
        }

        var reader = peReader.GetMetadataReader();
        if (!reader.IsAssembly)
        {
            throw new InvalidDataException(
                "The verified Guardian managed entry has no assembly definition.");
        }

        var assemblyName = reader.GetString(reader.GetAssemblyDefinition().Name);
        var moduleVersionId = reader.GetGuid(reader.GetModuleDefinition().Mvid);
        var entryPointToken = peReader.PEHeaders.CorHeader.EntryPointTokenOrRelativeVirtualAddress;
        var entryPointHandle = System.Reflection.Metadata.Ecma335.MetadataTokens.MethodDefinitionHandle(
            entryPointToken);
        if (entryPointHandle.IsNil)
        {
            throw new InvalidDataException(
                "The verified Guardian managed entry has no MethodDef entry point.");
        }

        var method = reader.GetMethodDefinition(entryPointHandle);
        var signature = reader.GetBlobBytes(method.Signature);
        ReadOnlySpan<byte> expectedSignature = [0x00, 0x01, 0x08, 0x1D, 0x0E];
        if ((method.Attributes & MethodAttributes.Static) == 0 ||
            (method.Attributes & MethodAttributes.MemberAccessMask) != MethodAttributes.Public ||
            !signature.AsSpan().SequenceEqual(expectedSignature))
        {
            throw new InvalidDataException(
                "The verified Guardian managed entry is not public static int Main(string[]).");
        }

        var methodName = reader.GetString(method.Name);
        var declaringTypeName = ReadDeclaringTypeName(reader, entryPointHandle);
        return new GuardianManagedEntryMetadataIdentityV1(
            ExpectedAppHostFileName,
            ExpectedManagedEntryRelativePath,
            assemblyName,
            moduleVersionId,
            entryPointToken,
            declaringTypeName,
            methodName);
    }

    private static string ReadDeclaringTypeName(
        MetadataReader reader,
        MethodDefinitionHandle methodHandle)
    {
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var type = reader.GetTypeDefinition(typeHandle);
            if (!type.GetMethods().Contains(methodHandle))
            {
                continue;
            }

            var name = reader.GetString(type.Name);
            var @namespace = reader.GetString(type.Namespace);
            return string.IsNullOrEmpty(@namespace) ? name : @namespace + "." + name;
        }

        throw new InvalidDataException(
            "The verified Guardian managed entry point has no declaring type.");
    }

    private static void RequireExact(string actual, string expected, string parameterName)
    {
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The Guardian managed-entry identity requires exact value '{expected}'.",
                parameterName);
        }
    }
}

internal sealed record GuardianManagedEntryReceiptV1
{
    internal GuardianManagedEntryReceiptV1(
        string challengeSha256,
        uint processId,
        uint sessionId,
        DateTimeOffset creationTimeUtc,
        GuardianManagedEntryMetadataIdentityV1 metadata)
    {
        if (!GuardianManagedEntryProofProtocolV1.IsCanonicalSha256(challengeSha256))
        {
            throw new ArgumentException(
                "A canonical managed-entry challenge SHA-256 is required.",
                nameof(challengeSha256));
        }

        if (processId == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId));
        }

        if (sessionId == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sessionId));
        }

        if (creationTimeUtc == default || creationTimeUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "A non-default UTC process creation time is required.",
                nameof(creationTimeUtc));
        }

        ChallengeSha256 = challengeSha256;
        ProcessId = processId;
        SessionId = sessionId;
        CreationTimeUtc = creationTimeUtc;
        Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
    }

    internal string ChallengeSha256 { get; }

    internal uint ProcessId { get; }

    internal uint SessionId { get; }

    internal DateTimeOffset CreationTimeUtc { get; }

    internal GuardianManagedEntryMetadataIdentityV1 Metadata { get; }
}

internal static class GuardianManagedEntryProofV1
{
    internal static GuardianManagedEntryReceiptV1 CreateCurrent(
        ReadOnlySpan<byte> challenge,
        Assembly expectedEntryAssembly)
    {
        GuardianManagedEntryProofProtocolV1.ValidateChallenge(challenge);
        ArgumentNullException.ThrowIfNull(expectedEntryAssembly);
        var entryAssembly = Assembly.GetEntryAssembly() ?? throw new InvalidOperationException(
            "The Guardian process has no managed entry assembly.");
        if (!ReferenceEquals(entryAssembly, expectedEntryAssembly) ||
            !string.Equals(
                entryAssembly.GetName().Name,
                GuardianManagedEntryMetadataIdentityV1.ExpectedAssemblyName,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The current process managed entry is not CodexGuardian.dll.");
        }

        var entryPoint = entryAssembly.EntryPoint ?? throw new InvalidOperationException(
            "The Guardian managed entry assembly has no entry point.");
        var parameters = entryPoint.GetParameters();
        if (!entryPoint.IsStatic || entryPoint.ReturnType != typeof(int) ||
            parameters.Length != 1 || parameters[0].ParameterType != typeof(string[]) ||
            !string.Equals(
                entryPoint.DeclaringType?.FullName,
                GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointDeclaringType,
                StringComparison.Ordinal) ||
            !string.Equals(
                entryPoint.Name,
                GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointMethod,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The Guardian managed entry point does not match Program.Main(string[]).");
        }

        var baseDirectory = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(AppContext.BaseDirectory));
        var assemblyLocation = Path.GetFullPath(entryAssembly.Location);
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            throw new InvalidOperationException("The Guardian apphost path is unavailable.");
        }

        processPath = Path.GetFullPath(processPath);
        if (!string.Equals(
                Path.GetDirectoryName(assemblyLocation),
                baseDirectory,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetDirectoryName(processPath),
                baseDirectory,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(assemblyLocation),
                GuardianManagedEntryMetadataIdentityV1.ExpectedManagedEntryRelativePath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(processPath),
                GuardianManagedEntryMetadataIdentityV1.ExpectedAppHostFileName,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The Guardian apphost and managed entry are not colocated in the runtime root.");
        }

        var metadata = new GuardianManagedEntryMetadataIdentityV1(
            GuardianManagedEntryMetadataIdentityV1.ExpectedAppHostFileName,
            GuardianManagedEntryMetadataIdentityV1.ExpectedManagedEntryRelativePath,
            entryAssembly.GetName().Name!,
            entryAssembly.ManifestModule.ModuleVersionId,
            entryPoint.MetadataToken,
            entryPoint.DeclaringType!.FullName!,
            entryPoint.Name);
        using var process = Process.GetCurrentProcess();
        var creationTimeUtc = new DateTimeOffset(
            process.StartTime.ToUniversalTime(),
            TimeSpan.Zero);
        return new GuardianManagedEntryReceiptV1(
            GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(challenge),
            checked((uint)process.Id),
            checked((uint)process.SessionId),
            creationTimeUtc,
            metadata);
    }
}

internal static class GuardianManagedEntryProofProtocolV1
{
    internal const int ProtocolVersion = 1;
    internal const int ChallengeBytes = 32;
    internal const int MaximumReceiptBytes = 2048;
    internal const string Schema = "codex-guardian-managed-entry-proof-v1";

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static string ComputeChallengeSha256(ReadOnlySpan<byte> challenge)
    {
        ValidateChallenge(challenge);
        return Convert.ToHexString(SHA256.HashData(challenge));
    }

    internal static void ValidateChallenge(ReadOnlySpan<byte> challenge)
    {
        if (challenge.Length != ChallengeBytes)
        {
            throw new ArgumentException(
                $"A {ChallengeBytes}-byte managed-entry challenge is required.",
                nameof(challenge));
        }
    }

    internal static byte[] Serialize(GuardianManagedEntryReceiptV1 receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        using var stream = new MemoryStream(capacity: 512);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("schema", Schema);
            writer.WriteNumber("protocol", ProtocolVersion);
            writer.WriteString("challengeSha256", receipt.ChallengeSha256);
            writer.WriteNumber("processId", receipt.ProcessId);
            writer.WriteNumber("sessionId", receipt.SessionId);
            writer.WriteNumber("creationTimeUtcTicks", receipt.CreationTimeUtc.UtcDateTime.Ticks);
            writer.WriteString("appHost", receipt.Metadata.AppHostFileName);
            writer.WriteString("managedEntry", receipt.Metadata.ManagedEntryRelativePath);
            writer.WriteString("assemblyName", receipt.Metadata.AssemblyName);
            writer.WriteString("moduleVersionId", receipt.Metadata.ModuleVersionId.ToString("D"));
            writer.WriteNumber("entryPointMetadataToken", receipt.Metadata.EntryPointMetadataToken);
            writer.WriteString("entryPointDeclaringType", receipt.Metadata.EntryPointDeclaringType);
            writer.WriteString("entryPointMethod", receipt.Metadata.EntryPointMethod);
            writer.WriteEndObject();
        }

        var payload = stream.ToArray();
        if (payload.Length is < 1 or > MaximumReceiptBytes)
        {
            throw new InvalidOperationException(
                "The managed-entry receipt exceeds its bounded protocol size.");
        }

        return payload;
    }

    internal static bool TryParse(
        ReadOnlyMemory<byte> utf8Json,
        out GuardianManagedEntryReceiptV1? receipt,
        out string reason)
    {
        receipt = null;
        reason = "managed-entry-proof-invalid";
        if (utf8Json.Length is < 1 or > MaximumReceiptBytes)
        {
            reason = "managed-entry-proof-size";
            return false;
        }

        var span = utf8Json.Span;
        if (span.Length >= 3 && span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF)
        {
            reason = "managed-entry-proof-bom";
            return false;
        }

        try
        {
            _ = StrictUtf8.GetCharCount(span);
            using var document = JsonDocument.Parse(
                utf8Json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 4,
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !HasExactProperties(root))
            {
                reason = "managed-entry-proof-shape";
                return false;
            }

            if (!TryReadExactString(root, "schema", Schema, out _) ||
                !root.GetProperty("protocol").TryGetInt32(out var protocol) ||
                protocol != ProtocolVersion ||
                !TryReadString(root, "challengeSha256", out var challengeSha256) ||
                !IsCanonicalSha256(challengeSha256) ||
                !root.GetProperty("processId").TryGetUInt32(out var processId) ||
                processId == 0 ||
                !root.GetProperty("sessionId").TryGetUInt32(out var sessionId) ||
                sessionId == 0 ||
                !root.GetProperty("creationTimeUtcTicks").TryGetInt64(out var creationTicks) ||
                creationTicks <= 0 ||
                !TryReadExactString(
                    root,
                    "appHost",
                    GuardianManagedEntryMetadataIdentityV1.ExpectedAppHostFileName,
                    out var appHost) ||
                !TryReadExactString(
                    root,
                    "managedEntry",
                    GuardianManagedEntryMetadataIdentityV1.ExpectedManagedEntryRelativePath,
                    out var managedEntry) ||
                !TryReadExactString(
                    root,
                    "assemblyName",
                    GuardianManagedEntryMetadataIdentityV1.ExpectedAssemblyName,
                    out var assemblyName) ||
                !TryReadString(root, "moduleVersionId", out var mvidText) ||
                !Guid.TryParseExact(mvidText, "D", out var moduleVersionId) ||
                moduleVersionId == Guid.Empty ||
                !string.Equals(mvidText, moduleVersionId.ToString("D"), StringComparison.Ordinal) ||
                !root.GetProperty("entryPointMetadataToken").TryGetInt32(out var entryPointToken) ||
                !TryReadExactString(
                    root,
                    "entryPointDeclaringType",
                    GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointDeclaringType,
                    out var entryPointType) ||
                !TryReadExactString(
                    root,
                    "entryPointMethod",
                    GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointMethod,
                    out var entryPointMethod))
            {
                reason = "managed-entry-proof-value";
                return false;
            }

            DateTimeOffset creationTimeUtc;
            try
            {
                creationTimeUtc = new DateTimeOffset(
                    new DateTime(creationTicks, DateTimeKind.Utc));
            }
            catch (ArgumentOutOfRangeException)
            {
                reason = "managed-entry-proof-time";
                return false;
            }

            var metadata = new GuardianManagedEntryMetadataIdentityV1(
                appHost,
                managedEntry,
                assemblyName,
                moduleVersionId,
                entryPointToken,
                entryPointType,
                entryPointMethod);
            var parsed = new GuardianManagedEntryReceiptV1(
                challengeSha256,
                processId,
                sessionId,
                creationTimeUtc,
                metadata);
            if (!Serialize(parsed).AsSpan().SequenceEqual(span))
            {
                reason = "managed-entry-proof-noncanonical";
                return false;
            }

            receipt = parsed;
            reason = "accepted";
            return true;
        }
        catch (Exception exception) when (
            exception is JsonException or DecoderFallbackException or
            ArgumentException or InvalidOperationException)
        {
            reason = "managed-entry-proof-invalid";
            return false;
        }
    }

    internal static bool IsCanonicalSha256(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character) && character is not (>= 'A' and <= 'F'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasExactProperties(JsonElement root)
    {
        string[] expected =
        [
            "schema",
            "protocol",
            "challengeSha256",
            "processId",
            "sessionId",
            "creationTimeUtcTicks",
            "appHost",
            "managedEntry",
            "assemblyName",
            "moduleVersionId",
            "entryPointMetadataToken",
            "entryPointDeclaringType",
            "entryPointMethod",
        ];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!seen.Add(property.Name) || Array.IndexOf(expected, property.Name) < 0)
            {
                return false;
            }
        }

        return seen.Count == expected.Length;
    }

    private static bool TryReadString(
        JsonElement root,
        string name,
        out string value)
    {
        value = string.Empty;
        var element = root.GetProperty(name);
        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = element.GetString() ?? string.Empty;
        return value.Length is > 0 and <= 128;
    }

    private static bool TryReadExactString(
        JsonElement root,
        string name,
        string expected,
        out string value) =>
        TryReadString(root, name, out value) &&
        string.Equals(value, expected, StringComparison.Ordinal);
}
