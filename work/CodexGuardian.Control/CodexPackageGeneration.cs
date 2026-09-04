using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed record CodexPackageGenerationPackageV1(
    string FullName,
    string FamilyName,
    string Name,
    string Version,
    string Publisher,
    string PublisherId,
    string ResourceId,
    string Architecture,
    uint Origin);

internal sealed record CodexPackageGenerationSignerV1(
    string Subject,
    string Issuer,
    string CertificateSha256,
    string SubjectPublicKeyInfoSha256,
    string CertificateThumbprint,
    long NotBeforeUtcTicks,
    long NotAfterUtcTicks);

internal sealed record CodexPackageGenerationArtifactV1(
    string RelativePath,
    long Length,
    string Sha256);

internal sealed record CodexPackageGenerationManifestV1(
    string Name,
    string Publisher,
    string Version,
    string Architecture,
    string Executable,
    string EntryPoint);

internal sealed record CodexPackageGenerationAsarEntryV1(
    string Path,
    long Length,
    string Sha256);

internal sealed record CodexPackageGenerationAsarV1(
    string ContractId,
    string PackageName,
    string ProductName,
    string PackageVersion,
    string MainPath,
    CodexPackageGenerationAsarEntryV1 PackageJson,
    CodexPackageGenerationAsarEntryV1 Main,
    CodexPackageGenerationAsarEntryV1 Preload);

internal sealed class CodexPackageGenerationV1 : IEquatable<CodexPackageGenerationV1>
{
    internal const string SchemaName = "codex-package-generation-v1";
    internal const string AppxSignatureRelativePath = "AppxSignature.p7x";
    internal const string AppxBlockMapRelativePath = "AppxBlockMap.xml";
    internal const string ManifestRelativePath = "AppxManifest.xml";
    internal const string ChatGptExecutableRelativePath = "app\\ChatGPT.exe";
    internal const string CodexExecutableRelativePath = "app\\resources\\codex.exe";
    internal const string AppAsarRelativePath = "app\\resources\\app.asar";

    private static readonly string[] RequiredArtifactPaths =
    [
        AppxSignatureRelativePath,
        AppxBlockMapRelativePath,
        ManifestRelativePath,
        ChatGptExecutableRelativePath,
        CodexExecutableRelativePath,
        AppAsarRelativePath
    ];

    private CodexPackageGenerationV1(
        CodexPackageGenerationPackageV1 package,
        CodexPackageGenerationSignerV1 signer,
        IReadOnlyList<CodexPackageGenerationArtifactV1> artifacts,
        CodexPackageGenerationManifestV1 manifest,
        CodexPackageGenerationAsarV1 asar,
        string canonicalJson,
        string generationSha256)
    {
        Package = package;
        Signer = signer;
        Artifacts = artifacts;
        Manifest = manifest;
        Asar = asar;
        CanonicalJson = canonicalJson;
        GenerationSha256 = generationSha256;
    }

    internal string Schema => SchemaName;

    internal CodexPackageGenerationPackageV1 Package { get; }

    internal CodexPackageGenerationSignerV1 Signer { get; }

    internal IReadOnlyList<CodexPackageGenerationArtifactV1> Artifacts { get; }

    internal CodexPackageGenerationManifestV1 Manifest { get; }

    internal CodexPackageGenerationAsarV1 Asar { get; }

    internal string CanonicalJson { get; }

    internal string GenerationSha256 { get; }

    internal static CodexPackageGenerationV1 Create(
        CodexPackageGenerationPackageV1 package,
        CodexPackageGenerationSignerV1 signer,
        IReadOnlyList<CodexPackageGenerationArtifactV1> artifacts,
        CodexPackageGenerationManifestV1 manifest,
        CodexPackageGenerationAsarV1 asar)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(artifacts);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(asar);

        var normalizedPackage = NormalizePackage(package);
        var normalizedSigner = NormalizeSigner(signer);
        var normalizedArtifacts = NormalizeArtifacts(artifacts);
        var normalizedManifest = NormalizeManifest(manifest);
        var normalizedAsar = NormalizeAsar(asar);
        var canonicalBytes = WriteCanonicalJson(
            normalizedPackage,
            normalizedSigner,
            normalizedArtifacts,
            normalizedManifest,
            normalizedAsar);
        return new CodexPackageGenerationV1(
            normalizedPackage,
            normalizedSigner,
            Array.AsReadOnly(normalizedArtifacts),
            normalizedManifest,
            normalizedAsar,
            Encoding.UTF8.GetString(canonicalBytes),
            Convert.ToHexString(SHA256.HashData(canonicalBytes)));
    }

    public bool Equals(CodexPackageGenerationV1? other) =>
        other is not null &&
        string.Equals(GenerationSha256, other.GenerationSha256, StringComparison.Ordinal) &&
        string.Equals(CanonicalJson, other.CanonicalJson, StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as CodexPackageGenerationV1);

    public override int GetHashCode() =>
        StringComparer.Ordinal.GetHashCode(GenerationSha256);

    private static CodexPackageGenerationPackageV1 NormalizePackage(
        CodexPackageGenerationPackageV1 value) =>
        new(
            RequireBounded(value.FullName, nameof(value.FullName), 256),
            RequireBounded(value.FamilyName, nameof(value.FamilyName), 256),
            RequireBounded(value.Name, nameof(value.Name), 128),
            RequireBounded(value.Version, nameof(value.Version), 64),
            RequireBounded(value.Publisher, nameof(value.Publisher), 512),
            RequireBounded(value.PublisherId, nameof(value.PublisherId), 128),
            RequireOptionalBounded(value.ResourceId, nameof(value.ResourceId), 128),
            RequireBounded(value.Architecture, nameof(value.Architecture), 32),
            value.Origin != 0
                ? value.Origin
                : throw new ArgumentException("A known package origin is required.", nameof(value.Origin)));

    private static CodexPackageGenerationSignerV1 NormalizeSigner(
        CodexPackageGenerationSignerV1 value)
    {
        if (value.NotBeforeUtcTicks <= 0 || value.NotAfterUtcTicks <= value.NotBeforeUtcTicks)
        {
            throw new ArgumentException("A valid signer certificate interval is required.", nameof(value));
        }

        return new CodexPackageGenerationSignerV1(
            RequireBounded(value.Subject, nameof(value.Subject), 512),
            RequireBounded(value.Issuer, nameof(value.Issuer), 512),
            RequireSha256(value.CertificateSha256, nameof(value.CertificateSha256)),
            RequireSha256(
                value.SubjectPublicKeyInfoSha256,
                nameof(value.SubjectPublicKeyInfoSha256)),
            RequireHex(
                value.CertificateThumbprint,
                nameof(value.CertificateThumbprint),
                minimumLength: 40,
                maximumLength: 128),
            value.NotBeforeUtcTicks,
            value.NotAfterUtcTicks);
    }

    private static CodexPackageGenerationArtifactV1[] NormalizeArtifacts(
        IReadOnlyList<CodexPackageGenerationArtifactV1> artifacts)
    {
        if (artifacts.Count != RequiredArtifactPaths.Length)
        {
            throw new ArgumentException("The exact package generation artifact set is required.", nameof(artifacts));
        }

        var result = new CodexPackageGenerationArtifactV1[artifacts.Count];
        for (var index = 0; index < artifacts.Count; index++)
        {
            var artifact = artifacts[index] ?? throw new ArgumentException(
                "A package generation artifact is missing.",
                nameof(artifacts));
            if (!string.Equals(
                    artifact.RelativePath,
                    RequiredArtifactPaths[index],
                    StringComparison.Ordinal) ||
                artifact.Length <= 0)
            {
                throw new ArgumentException(
                    "The package generation artifact order or length is invalid.",
                    nameof(artifacts));
            }

            result[index] = new CodexPackageGenerationArtifactV1(
                artifact.RelativePath,
                artifact.Length,
                RequireSha256(artifact.Sha256, nameof(artifact.Sha256)));
        }

        return result;
    }

    private static CodexPackageGenerationManifestV1 NormalizeManifest(
        CodexPackageGenerationManifestV1 value) =>
        new(
            RequireBounded(value.Name, nameof(value.Name), 128),
            RequireBounded(value.Publisher, nameof(value.Publisher), 512),
            RequireBounded(value.Version, nameof(value.Version), 64),
            RequireBounded(value.Architecture, nameof(value.Architecture), 32),
            RequireBounded(value.Executable, nameof(value.Executable), 256),
            RequireBounded(value.EntryPoint, nameof(value.EntryPoint), 128));

    private static CodexPackageGenerationAsarV1 NormalizeAsar(
        CodexPackageGenerationAsarV1 value) =>
        new(
            RequireBounded(value.ContractId, nameof(value.ContractId), 128),
            RequireBounded(value.PackageName, nameof(value.PackageName), 128),
            RequireBounded(value.ProductName, nameof(value.ProductName), 128),
            RequireBounded(value.PackageVersion, nameof(value.PackageVersion), 64),
            RequireAsarPath(value.MainPath, nameof(value.MainPath)),
            NormalizeAsarEntry(value.PackageJson, nameof(value.PackageJson)),
            NormalizeAsarEntry(value.Main, nameof(value.Main)),
            NormalizeAsarEntry(value.Preload, nameof(value.Preload)));

    private static CodexPackageGenerationAsarEntryV1 NormalizeAsarEntry(
        CodexPackageGenerationAsarEntryV1 value,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length <= 0)
        {
            throw new ArgumentException("A positive ASAR entry length is required.", parameterName);
        }

        return new CodexPackageGenerationAsarEntryV1(
            RequireAsarPath(value.Path, parameterName),
            value.Length,
            RequireSha256(value.Sha256, parameterName));
    }

    private static byte[] WriteCanonicalJson(
        CodexPackageGenerationPackageV1 package,
        CodexPackageGenerationSignerV1 signer,
        IReadOnlyList<CodexPackageGenerationArtifactV1> artifacts,
        CodexPackageGenerationManifestV1 manifest,
        CodexPackageGenerationAsarV1 asar)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(
            buffer,
            new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.Default,
                Indented = false,
                SkipValidation = false
            });
        writer.WriteStartObject();
        writer.WriteString("schema", SchemaName);

        writer.WritePropertyName("package");
        writer.WriteStartObject();
        writer.WriteString("fullName", package.FullName);
        writer.WriteString("familyName", package.FamilyName);
        writer.WriteString("name", package.Name);
        writer.WriteString("version", package.Version);
        writer.WriteString("publisher", package.Publisher);
        writer.WriteString("publisherId", package.PublisherId);
        writer.WriteString("resourceId", package.ResourceId);
        writer.WriteString("architecture", package.Architecture);
        writer.WriteNumber("origin", package.Origin);
        writer.WriteEndObject();

        writer.WritePropertyName("signer");
        writer.WriteStartObject();
        writer.WriteString("subject", signer.Subject);
        writer.WriteString("issuer", signer.Issuer);
        writer.WriteString("certificateSha256", signer.CertificateSha256);
        writer.WriteString("subjectPublicKeyInfoSha256", signer.SubjectPublicKeyInfoSha256);
        writer.WriteString("certificateThumbprint", signer.CertificateThumbprint);
        writer.WriteNumber("notBeforeUtcTicks", signer.NotBeforeUtcTicks);
        writer.WriteNumber("notAfterUtcTicks", signer.NotAfterUtcTicks);
        writer.WriteEndObject();

        writer.WritePropertyName("artifacts");
        writer.WriteStartArray();
        foreach (var artifact in artifacts)
        {
            writer.WriteStartObject();
            writer.WriteString("relativePath", artifact.RelativePath);
            writer.WriteNumber("length", artifact.Length);
            writer.WriteString("sha256", artifact.Sha256);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.WritePropertyName("manifest");
        writer.WriteStartObject();
        writer.WriteString("name", manifest.Name);
        writer.WriteString("publisher", manifest.Publisher);
        writer.WriteString("version", manifest.Version);
        writer.WriteString("architecture", manifest.Architecture);
        writer.WriteString("executable", manifest.Executable);
        writer.WriteString("entryPoint", manifest.EntryPoint);
        writer.WriteEndObject();

        writer.WritePropertyName("asar");
        writer.WriteStartObject();
        writer.WriteString("contractId", asar.ContractId);
        writer.WriteString("packageName", asar.PackageName);
        writer.WriteString("productName", asar.ProductName);
        writer.WriteString("packageVersion", asar.PackageVersion);
        writer.WriteString("mainPath", asar.MainPath);
        WriteAsarEntry(writer, "packageJson", asar.PackageJson);
        WriteAsarEntry(writer, "main", asar.Main);
        WriteAsarEntry(writer, "preload", asar.Preload);
        writer.WriteEndObject();

        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteAsarEntry(
        Utf8JsonWriter writer,
        string propertyName,
        CodexPackageGenerationAsarEntryV1 entry)
    {
        writer.WritePropertyName(propertyName);
        writer.WriteStartObject();
        writer.WriteString("path", entry.Path);
        writer.WriteNumber("length", entry.Length);
        writer.WriteString("sha256", entry.Sha256);
        writer.WriteEndObject();
    }

    private static string RequireBounded(string value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            throw new ArgumentException("A bounded non-empty value is required.", parameterName);
        }

        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("Control characters are not permitted.", parameterName);
            }
        }

        return value;
    }

    private static string RequireOptionalBounded(
        string value,
        string parameterName,
        int maximumLength)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > maximumLength)
        {
            throw new ArgumentException("The value exceeds its bound.", parameterName);
        }

        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("Control characters are not permitted.", parameterName);
            }
        }

        return value;
    }

    private static string RequireSha256(string value, string parameterName) =>
        RequireHex(value, parameterName, minimumLength: 64, maximumLength: 64);

    private static string RequireHex(
        string value,
        string parameterName,
        int minimumLength,
        int maximumLength)
    {
        if (value is null || value.Length < minimumLength || value.Length > maximumLength)
        {
            throw new ArgumentException("A bounded hexadecimal value is required.", parameterName);
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                throw new ArgumentException("A bounded hexadecimal value is required.", parameterName);
            }
        }

        return value.ToUpperInvariant();
    }

    private static string RequireAsarPath(string value, string parameterName) =>
        CodexAsarCapabilityInspector.IsCanonicalPath(value)
            ? value
            : throw new ArgumentException("A canonical ASAR path is required.", parameterName);
}
