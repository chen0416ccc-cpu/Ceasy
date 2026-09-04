using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed record CodexStructuredInputAsarFileObservation(
    string RequestedPath,
    string FinalPath,
    FileAttributes Attributes,
    long Length,
    DateTimeOffset LastWriteTimeUtc,
    uint VolumeSerialNumber,
    ulong FileId,
    CodexStructuredInputAsarSnapshot Snapshot);

internal sealed record CodexStructuredInputPackageEvidence(
    CodexAppModelPackageIdentity Package,
    string RegisteredInstallPath,
    string FinalInstallPath,
    CodexPathObservation PackageDirectory,
    CodexPackageSignerIdentity Signer,
    CodexStructuredInputAsarFileObservation AppAsar,
    long Epoch);

internal interface ICodexStructuredInputPackagePlatform
{
    IReadOnlyList<CodexPackageFamilyMember> ReadCurrentUserPackageFamilyInventory(
        string packageFamilyName);

    CodexAppModelPackageIdentity ReadRegisteredPackageIdentity(string packageFullName);

    string ReadRegisteredPackagePath(string packageFullName);

    CodexPathObservation InspectDirectory(string path);

    CodexVerifiedPackageSignatureObservation ReadAndVerifyPackageSignature(
        string path,
        long maximumBytes);

    CodexStructuredInputAsarFileObservation ReadStructuredInputAppAsar(
        string path,
        long maximumBytes,
        CodexStructuredInputAsarInspectionLimits limits);
}

internal sealed record CodexStructuredInputPackagePolicy
{
    internal const string DefaultPackageName = "OpenAI.Codex";
    internal const string DefaultPackageFamilyName = "OpenAI.Codex_2p2nqsd0c76g0";
    internal const string DefaultPublisher = "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B";
    internal const string DefaultArchitecture = "x64";

    internal CodexStructuredInputPackagePolicy(
        string packageName,
        string packageFamilyName,
        string publisher,
        string architecture,
        string appAsarRelativePath,
        string signatureRelativePath,
        long maximumAppAsarBytes,
        long maximumSignatureBytes)
    {
        PackageName = RequireBounded(packageName, nameof(packageName), 128);
        PackageFamilyName = RequireBounded(packageFamilyName, nameof(packageFamilyName), 192);
        Publisher = RequireBounded(publisher, nameof(publisher), 512);
        Architecture = RequireBounded(architecture, nameof(architecture), 32);
        AppAsarRelativePath = RequireRelativePath(appAsarRelativePath, nameof(appAsarRelativePath));
        SignatureRelativePath = RequireRelativePath(signatureRelativePath, nameof(signatureRelativePath));
        if (maximumAppAsarBytes is < 16 or > 2L * 1024 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAppAsarBytes));
        }

        if (maximumSignatureBytes is < 128 or > 16L * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumSignatureBytes));
        }

        MaximumAppAsarBytes = maximumAppAsarBytes;
        MaximumSignatureBytes = maximumSignatureBytes;
    }

    internal static CodexStructuredInputPackagePolicy Default { get; } = new(
        DefaultPackageName,
        DefaultPackageFamilyName,
        DefaultPublisher,
        DefaultArchitecture,
        CodexPackageBaselineVerifier.AppAsarRelativePath,
        CodexPackageBaselineVerifier.AppxSignatureRelativePath,
        maximumAppAsarBytes: 1024L * 1024 * 1024,
        maximumSignatureBytes: 4L * 1024 * 1024);

    internal string PackageName { get; }

    internal string PackageFamilyName { get; }

    internal string Publisher { get; }

    internal string Architecture { get; }

    internal string AppAsarRelativePath { get; }

    internal string SignatureRelativePath { get; }

    internal long MaximumAppAsarBytes { get; }

    internal long MaximumSignatureBytes { get; }

    private static string RequireBounded(string value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            throw new ArgumentException("A bounded non-empty value is required.", parameterName);
        }

        return value;
    }

    private static string RequireRelativePath(string value, string parameterName)
    {
        var normalized = value?.Replace('/', '\\');
        if (string.IsNullOrWhiteSpace(normalized) ||
            normalized.Length > 512 ||
            Path.IsPathFullyQualified(normalized) ||
            normalized.IndexOf('\0') >= 0 ||
            normalized.Split('\\').Any(part => part is "" or "." or ".."))
        {
            throw new ArgumentException("A canonical bounded relative path is required.", parameterName);
        }

        return normalized;
    }
}

internal sealed class CodexStructuredInputPackageException : InvalidOperationException
{
    internal CodexStructuredInputPackageException(
        string code,
        bool isCompatibilityFailure,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
        IsCompatibilityFailure = isCompatibilityFailure;
    }

    internal string Code { get; }

    internal bool IsCompatibilityFailure { get; }
}

internal sealed class CodexStructuredInputPackageEvidenceReader
{
    private readonly ICodexStructuredInputPackagePlatform _platform;
    private readonly CodexStructuredInputPackagePolicy _policy;
    private readonly CodexStructuredInputAsarInspectionLimits _asarLimits;

    internal CodexStructuredInputPackageEvidenceReader(
        ICodexStructuredInputPackagePlatform? platform = null,
        CodexStructuredInputPackagePolicy? policy = null,
        CodexStructuredInputAsarInspectionLimits? asarLimits = null)
    {
        _platform = platform ?? new WindowsCodexPackageBaselinePlatform();
        _policy = policy ?? CodexStructuredInputPackagePolicy.Default;
        _asarLimits = asarLimits ?? CodexStructuredInputAsarInspectionLimits.Default;
    }

    internal CodexStructuredInputPackageEvidence Read()
    {
        try
        {
            var first = CaptureRegistration();
            var signaturePath = GetExpectedArtifactPath(
                first.FinalInstallPath,
                _policy.SignatureRelativePath);
            var signature = _platform.ReadAndVerifyPackageSignature(
                signaturePath,
                _policy.MaximumSignatureBytes);
            var signatureFile = ValidatePinnedFile(
                first,
                signaturePath,
                signature.File,
                _policy.MaximumSignatureBytes,
                "structured-package-signature");
            ValidateSigner(first.Package, signature.Signer);

            var asarPath = GetExpectedArtifactPath(
                first.FinalInstallPath,
                _policy.AppAsarRelativePath);
            CodexStructuredInputAsarFileObservation asar;
            try
            {
                asar = _platform.ReadStructuredInputAppAsar(
                    asarPath,
                    _policy.MaximumAppAsarBytes,
                    _asarLimits);
            }
            catch (CodexStructuredInputAsarException exception)
            {
                throw Failure(
                    exception.Code,
                    exception.IsCompatibilityFailure,
                    exception.Message,
                    exception);
            }

            asar = ValidateAsar(first, asarPath, asar);
            if (signatureFile.VolumeSerialNumber == asar.VolumeSerialNumber &&
                signatureFile.FileId == asar.FileId)
            {
                throw Failure(
                    "structured-package-artifact-alias",
                    isCompatibilityFailure: false,
                    "The package signature and app.asar resolve to the same file identity.");
            }

            var second = CaptureRegistration();
            if (!SameRegistration(first, second))
            {
                throw Failure(
                    "structured-package-registration-drift",
                    isCompatibilityFailure: false,
                    "The registered Codex package changed during semantic evidence capture.");
            }

            return new CodexStructuredInputPackageEvidence(
                first.Package,
                first.RegisteredInstallPath,
                first.FinalInstallPath,
                first.PackageDirectory,
                signature.Signer,
                asar,
                ComputeEpoch(first, signature.Signer, asar));
        }
        catch (CodexStructuredInputPackageException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(
                "structured-package-evidence-unavailable",
                isCompatibilityFailure: false,
                "The installed Codex structured-input evidence is unavailable.",
                exception);
        }
    }

    private RegistrationCapture CaptureRegistration()
    {
        var inventory = _platform.ReadCurrentUserPackageFamilyInventory(_policy.PackageFamilyName);
        if (inventory.Count != 1 ||
            inventory[0] is not { Properties: 0 } member ||
            string.IsNullOrWhiteSpace(member.FullName) ||
            member.FullName.Length > 256)
        {
            throw Failure(
                "structured-package-family-multiplicity",
                isCompatibilityFailure: false,
                "Exactly one current-user Codex main package is required.");
        }

        var package = _platform.ReadRegisteredPackageIdentity(member.FullName);
        ValidatePackageIdentity(package, member.FullName);
        var registeredPath = NormalizeAbsolutePath(
            _platform.ReadRegisteredPackagePath(package.FullName),
            "structured-package-path");
        if (!IsDriveQualifiedPath(registeredPath) ||
            !string.Equals(Path.GetFileName(registeredPath), package.FullName, StringComparison.Ordinal))
        {
            throw Failure(
                "structured-package-path",
                isCompatibilityFailure: false,
                "The registered Codex path is not its exact drive-qualified package directory.");
        }

        var windowsAppsPath = Path.GetDirectoryName(registeredPath);
        if (string.IsNullOrWhiteSpace(windowsAppsPath) ||
            !string.Equals(
                new DirectoryInfo(windowsAppsPath).Name,
                "WindowsApps",
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                "structured-package-windowsapps",
                isCompatibilityFailure: false,
                "The registered Codex package is not an exact WindowsApps child.");
        }

        var directory = NormalizeDirectoryObservation(
            _platform.InspectDirectory(registeredPath),
            "structured-package-directory");
        if (!string.Equals(directory.RequestedPath, registeredPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(directory.FinalPath, registeredPath, StringComparison.OrdinalIgnoreCase) ||
            (directory.Attributes & FileAttributes.Directory) == 0 ||
            (directory.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            directory.VolumeSerialNumber == 0 ||
            directory.FileId == 0 ||
            !string.Equals(
                new DirectoryInfo(directory.FinalPath).Parent?.FullName,
                NormalizeAbsolutePath(windowsAppsPath, "structured-package-windowsapps"),
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                "structured-package-directory",
                isCompatibilityFailure: false,
                "The registered Codex package directory is redirected or not a regular WindowsApps directory.");
        }

        return new RegistrationCapture(package, registeredPath, directory.FinalPath, directory);
    }

    private void ValidatePackageIdentity(
        CodexAppModelPackageIdentity package,
        string discoveredFullName)
    {
        ArgumentNullException.ThrowIfNull(package);
        if (!string.Equals(package.FullName, discoveredFullName, StringComparison.Ordinal) ||
            !string.Equals(package.FamilyName, _policy.PackageFamilyName, StringComparison.Ordinal) ||
            !string.Equals(package.Name, _policy.PackageName, StringComparison.Ordinal) ||
            !string.Equals(package.Publisher, _policy.Publisher, StringComparison.Ordinal) ||
            !string.Equals(package.Architecture, _policy.Architecture, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(package.Version) ||
            package.Version.Length > 64 ||
            string.IsNullOrWhiteSpace(package.PublisherId) ||
            package.PublisherId.Length > 128 ||
            !string.IsNullOrEmpty(package.ResourceId) ||
            !string.Equals(
                package.Name + "_" + package.PublisherId,
                package.FamilyName,
                StringComparison.Ordinal) ||
            package.Origin is not CodexPackageOrigin.Store and not CodexPackageOrigin.DeveloperSigned)
        {
            throw Failure(
                "structured-package-identity",
                isCompatibilityFailure: true,
                "The registered Codex package identity is not an allowed compatible package.");
        }
    }

    private static CodexPinnedFileObservation ValidatePinnedFile(
        RegistrationCapture registration,
        string expectedPath,
        CodexPinnedFileObservation observation,
        long maximumBytes,
        string code)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var requested = NormalizeAbsolutePath(observation.RequestedPath, code);
        var final = NormalizeAbsolutePath(observation.FinalPath, code);
        if (!string.Equals(requested, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(final, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            (observation.Attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            observation.Length is <= 0 ||
            observation.Length > maximumBytes ||
            observation.VolumeSerialNumber != registration.PackageDirectory.VolumeSerialNumber ||
            observation.FileId == 0 ||
            !IsSha256(observation.Sha256))
        {
            throw Failure(
                code,
                isCompatibilityFailure: false,
                "A pinned installed Codex artifact is redirected, aliased, or unbounded.");
        }

        return observation with { RequestedPath = requested, FinalPath = final, Contents = null };
    }

    private CodexStructuredInputAsarFileObservation ValidateAsar(
        RegistrationCapture registration,
        string expectedPath,
        CodexStructuredInputAsarFileObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var requested = NormalizeAbsolutePath(observation.RequestedPath, "structured-package-asar");
        var final = NormalizeAbsolutePath(observation.FinalPath, "structured-package-asar");
        if (!string.Equals(requested, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(final, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            (observation.Attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            observation.Length is < 16 ||
            observation.Length > _policy.MaximumAppAsarBytes ||
            observation.LastWriteTimeUtc == default ||
            observation.LastWriteTimeUtc.Offset != TimeSpan.Zero ||
            observation.VolumeSerialNumber != registration.PackageDirectory.VolumeSerialNumber ||
            observation.FileId == 0 ||
            observation.Snapshot is null ||
            !IsSha256(observation.Snapshot.HeaderSha256))
        {
            throw Failure(
                "structured-package-asar",
                isCompatibilityFailure: false,
                "The pinned installed app.asar evidence is redirected, aliased, or unbounded.");
        }

        return observation with { RequestedPath = requested, FinalPath = final };
    }

    private static void ValidateSigner(
        CodexAppModelPackageIdentity package,
        CodexPackageSignerIdentity signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (string.IsNullOrWhiteSpace(signer.Subject) || signer.Subject.Length > 512 ||
            string.IsNullOrWhiteSpace(signer.Issuer) || signer.Issuer.Length > 512 ||
            !IsSha256(signer.CertificateSha256) ||
            !IsSha256(signer.SubjectPublicKeyInfoSha256) ||
            string.IsNullOrWhiteSpace(signer.CertificateThumbprint) ||
            signer.CertificateThumbprint.Length > 128 ||
            !signer.CertificateThumbprint.All(Uri.IsHexDigit) ||
            signer.NotBeforeUtc == default || signer.NotBeforeUtc.Offset != TimeSpan.Zero ||
            signer.NotAfterUtc == default || signer.NotAfterUtc.Offset != TimeSpan.Zero ||
            signer.VerifiedAtUtc == default || signer.VerifiedAtUtc.Offset != TimeSpan.Zero ||
            signer.NotAfterUtc <= signer.NotBeforeUtc ||
            signer.VerifiedAtUtc < signer.NotBeforeUtc ||
            signer.VerifiedAtUtc > signer.NotAfterUtc ||
            package.Origin == CodexPackageOrigin.DeveloperSigned &&
            !string.Equals(signer.Subject, package.Publisher, StringComparison.Ordinal))
        {
            throw Failure(
                "structured-package-signer",
                isCompatibilityFailure: false,
                "The compatible installed Codex package signer could not be proved.");
        }
    }

    private static string GetExpectedArtifactPath(string installPath, string relativePath)
    {
        var combined = NormalizeAbsolutePath(
            Path.Combine(installPath, relativePath),
            "structured-package-artifact-path");
        if (!combined.StartsWith(
                installPath + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                "structured-package-artifact-path",
                isCompatibilityFailure: false,
                "A selected package artifact escapes the registered package directory.");
        }

        return combined;
    }

    private static long ComputeEpoch(
        RegistrationCapture registration,
        CodexPackageSignerIdentity signer,
        CodexStructuredInputAsarFileObservation asar)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
               {
                   Indented = false,
                   SkipValidation = false
               }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("contractVersion", 1);
            writer.WriteString("packageFullName", registration.Package.FullName);
            writer.WriteString("packageVersion", registration.Package.Version);
            writer.WriteNumber("packageOrigin", (uint)registration.Package.Origin);
            writer.WriteString("installPath", registration.FinalInstallPath);
            writer.WriteNumber("directoryVolume", registration.PackageDirectory.VolumeSerialNumber);
            writer.WriteString(
                "directoryFileId",
                registration.PackageDirectory.FileId.ToString("X16", CultureInfo.InvariantCulture));
            writer.WriteString("signerCertificateSha256", signer.CertificateSha256);
            writer.WriteNumber("asarLength", asar.Length);
            writer.WriteNumber("asarLastWriteTicks", asar.LastWriteTimeUtc.UtcDateTime.Ticks);
            writer.WriteNumber("asarVolume", asar.VolumeSerialNumber);
            writer.WriteString("asarFileId", asar.FileId.ToString("X16", CultureInfo.InvariantCulture));
            writer.WriteString("headerSha256", asar.Snapshot.HeaderSha256);
            writer.WritePropertyName("selectedEntries");
            writer.WriteStartArray();
            foreach (var entry in SelectedEntries(asar.Snapshot))
            {
                writer.WriteStartObject();
                writer.WriteString("path", entry.Path);
                writer.WriteNumber("size", entry.Size);
                writer.WriteString("sha256", entry.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        var hash = SHA256.HashData(stream.GetBuffer().AsSpan(0, checked((int)stream.Length)));
        var epoch = BinaryPrimitives.ReadInt64BigEndian(hash) & long.MaxValue;
        return epoch == 0 ? 1 : epoch;
    }

    private static IReadOnlyList<CodexStructuredInputAsarSelectedEntry> SelectedEntries(
        CodexStructuredInputAsarSnapshot snapshot) =>
        new[]
            {
                snapshot.PackageJson,
                snapshot.WebviewIndex
            }
            .Concat(snapshot.ModuleEntries)
            .DistinctBy(entry => entry.Path, StringComparer.Ordinal)
            .OrderBy(entry => entry.Path, StringComparer.Ordinal)
            .ToArray();

    private static bool SameRegistration(RegistrationCapture first, RegistrationCapture second) =>
        first.Package == second.Package &&
        string.Equals(
            first.RegisteredInstallPath,
            second.RegisteredInstallPath,
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            first.FinalInstallPath,
            second.FinalInstallPath,
            StringComparison.OrdinalIgnoreCase) &&
        first.PackageDirectory.Attributes == second.PackageDirectory.Attributes &&
        first.PackageDirectory.VolumeSerialNumber == second.PackageDirectory.VolumeSerialNumber &&
        first.PackageDirectory.FileId == second.PackageDirectory.FileId &&
        string.Equals(
            first.PackageDirectory.FinalPath,
            second.PackageDirectory.FinalPath,
            StringComparison.OrdinalIgnoreCase);

    private static CodexPathObservation NormalizeDirectoryObservation(
        CodexPathObservation observation,
        string code)
    {
        ArgumentNullException.ThrowIfNull(observation);
        return observation with
        {
            RequestedPath = NormalizeAbsolutePath(observation.RequestedPath, code),
            FinalPath = NormalizeAbsolutePath(observation.FinalPath, code)
        };
    }

    private static string NormalizeAbsolutePath(string path, string code)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0)
        {
            throw Failure(code, isCompatibilityFailure: false, "An absolute Windows path is required.");
        }

        path = path.Trim().Replace('/', '\\');
        if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            path = "\\\\" + path[8..];
        }
        else if (path.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
        {
            path = path[4..];
        }

        if (!Path.IsPathFullyQualified(path) ||
            path.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                code,
                isCompatibilityFailure: false,
                "A supported fully qualified Windows path is required.");
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    private static bool IsDriveQualifiedPath(string path) =>
        path.Length >= 3 &&
        char.IsAsciiLetter(path[0]) &&
        path[1] == ':' &&
        path[2] == '\\';

    private static bool IsSha256(string? value) =>
        value is { Length: SHA256.HashSizeInBytes * 2 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static CodexStructuredInputPackageException Failure(
        string code,
        bool isCompatibilityFailure,
        string message,
        Exception? innerException = null) =>
        new(code, isCompatibilityFailure, message, innerException);

    private sealed record RegistrationCapture(
        CodexAppModelPackageIdentity Package,
        string RegisteredInstallPath,
        string FinalInstallPath,
        CodexPathObservation PackageDirectory);
}
