using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Principal;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;

namespace CodexGuardian.Control;

internal sealed class CodexPackageBaselineVerifier
{
    internal const string ManifestRelativePath = CodexPackageGenerationV1.ManifestRelativePath;
    internal const string AppxSignatureRelativePath =
        CodexPackageGenerationV1.AppxSignatureRelativePath;
    internal const string AppxBlockMapRelativePath =
        CodexPackageGenerationV1.AppxBlockMapRelativePath;
    internal const string ChatGptExecutableRelativePath =
        CodexPackageGenerationV1.ChatGptExecutableRelativePath;
    internal const string CodexExecutableRelativePath =
        CodexPackageGenerationV1.CodexExecutableRelativePath;
    internal const string AppAsarRelativePath = CodexPackageGenerationV1.AppAsarRelativePath;
    private const string ManifestNamespace =
        "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
    private const string FullTrustEntryPoint = "Windows.FullTrustApplication";
    private const long MaximumManifestBytes = 4L * 1024 * 1024;
    private const long MaximumAppxSignatureBytes = 4L * 1024 * 1024;
    private const long MaximumAppxBlockMapBytes = CodexAppxBlockMapVerifier.MaximumBlockMapBytes;
    private const long MaximumExecutableBytes = 512L * 1024 * 1024;
    private const long MaximumAppAsarBytes = 1024L * 1024 * 1024;
    private readonly CodexCdpRuntimeProfile _profile;
    private readonly CodexPackageCompatibilityPolicy _compatibilityPolicy;
    private readonly CodexPackageTrustMode _trustMode;
    private readonly CodexAsarCapabilityPolicy _asarCapabilityPolicy;
    private readonly ICodexPackageBaselinePlatform _platform;
    private readonly object _snapshotOwner = new();

    internal CodexPackageBaselineVerifier(
        CodexCdpRuntimeProfile profile,
        ICodexPackageBaselinePlatform? platform = null)
        : this(
            profile,
            CodexPackageTrustMode.StoreOnly,
            CreateDefaultAsarCapabilityPolicy(profile),
            platform)
    {
    }

    internal CodexPackageBaselineVerifier(
        CodexCdpRuntimeProfile profile,
        CodexPackageTrustMode trustMode,
        ICodexPackageBaselinePlatform? platform = null)
        : this(profile, trustMode, CreateDefaultAsarCapabilityPolicy(profile), platform)
    {
    }

    internal CodexPackageBaselineVerifier(
        CodexCdpRuntimeProfile profile,
        CodexPackageTrustMode trustMode,
        CodexAsarCapabilityPolicy asarCapabilityPolicy,
        ICodexPackageBaselinePlatform? platform = null)
    {
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
        if (!Enum.IsDefined(trustMode))
        {
            throw new ArgumentOutOfRangeException(nameof(trustMode));
        }

        _compatibilityPolicy = new CodexPackageCompatibilityPolicy(
            profile.PackageName,
            profile.PackageFamilyName,
            profile.PackagePublisher,
            profile.PackageArchitecture);
        _trustMode = trustMode;
        _asarCapabilityPolicy = asarCapabilityPolicy ??
            throw new ArgumentNullException(nameof(asarCapabilityPolicy));
        _platform = platform ?? new WindowsCodexPackageBaselinePlatform();
    }

    private static CodexAsarCapabilityPolicy CreateDefaultAsarCapabilityPolicy(
        CodexCdpRuntimeProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return new CodexAsarCapabilityPolicy(
            profile.ContractId,
            profile.AsarPackageName,
            profile.AsarProductName,
            profile.AsarMainPath,
            profile.AsarMainSha256,
            profile.PreloadPath,
            profile.PreloadSha256,
            profile.PreloadMarkers);
    }

    internal CodexPackageBaselineSnapshot VerifyPreLaunch()
    {
        try
        {
            ValidateProfile();
            var capture = CaptureInstalledBaseline();
            VerifyRegistrationStillCurrent(capture);
            var generation = CreatePackageGeneration(capture);

            var currentUserSid = _platform.ReadCurrentUserSid();
            ValidateSid(currentUserSid, "current-user-sid");
            var currentSessionId = _platform.ReadCurrentSessionId();
            var reservationUtc = _platform.UtcNow.ToUniversalTime();
            if (reservationUtc < DateTimeOffset.UnixEpoch)
            {
                throw Failure(
                    "invalid-launch-reservation",
                    "The launch reservation timestamp is invalid.");
            }

            return new CodexPackageBaselineSnapshot(
                _snapshotOwner,
                _profile,
                capture.Package,
                capture.TrustDecision,
                capture.RegisteredInstallPath,
                capture.FinalInstallPath,
                capture.WindowsAppsPath,
                capture.PackageDirectory,
                capture.Manifest,
                capture.ManifestMetadata,
                capture.AppxSignature,
                capture.SignerIdentity,
                capture.AppxBlockMap,
                capture.ChatGptExecutable,
                capture.CodexExecutable,
                capture.AppAsar,
                capture.AsarCapabilities,
                generation,
                currentUserSid,
                currentSessionId,
                reservationUtc);
        }
        catch (CodexPackageBaselineException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(
                "prelaunch-verification-failed",
                "The installed Codex package baseline could not be verified.",
                exception);
        }
    }

    internal void RevalidateBaseline(CodexPackageBaselineSnapshot baseline)
    {
        try
        {
            ValidateOwnedBaseline(baseline);
            var capture = CaptureInstalledBaseline();
            VerifyRegistrationStillCurrent(capture);
            var generation = CreatePackageGeneration(capture);
            if (!SamePackageIdentity(capture.Package, baseline.Package) ||
                capture.TrustDecision != baseline.TrustDecision ||
                !string.Equals(
                    capture.RegisteredInstallPath,
                    baseline.RegisteredInstallPath,
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    capture.FinalInstallPath,
                    baseline.FinalInstallPath,
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    capture.WindowsAppsPath,
                    baseline.WindowsAppsPath,
                    StringComparison.OrdinalIgnoreCase) ||
                !SameDirectory(capture.PackageDirectory, baseline.PackageDirectory) ||
                !SameArtifact(capture.Manifest, baseline.Manifest) ||
                capture.ManifestMetadata != baseline.ManifestMetadata ||
                !SameArtifact(capture.AppxSignature, baseline.AppxSignature) ||
                !SameSignerIdentity(baseline.SignerIdentity, capture.SignerIdentity) ||
                !SameArtifact(capture.AppxBlockMap, baseline.AppxBlockMap) ||
                !SameArtifact(capture.ChatGptExecutable, baseline.ChatGptExecutable) ||
                !SameArtifact(capture.CodexExecutable, baseline.CodexExecutable) ||
                !SameArtifact(capture.AppAsar, baseline.AppAsar) ||
                capture.AsarCapabilities != baseline.AsarCapabilities ||
                !generation.Equals(baseline.Generation))
            {
                throw Failure(
                    "package-baseline-drift",
                    "The installed Codex package changed after the launch baseline was captured.");
            }

            var currentUserSid = _platform.ReadCurrentUserSid();
            ValidateSid(currentUserSid, "current-user-sid");
            if (!string.Equals(
                    currentUserSid,
                    baseline.CurrentUserSid,
                    StringComparison.OrdinalIgnoreCase) ||
                _platform.ReadCurrentSessionId() != baseline.CurrentSessionId)
            {
                throw Failure(
                    "launch-context-drift",
                    "The current Windows user or session changed after baseline capture.");
            }
        }
        catch (CodexPackageBaselineException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(
                "baseline-revalidation-failed",
                "The installed Codex package baseline could not be revalidated.",
                exception);
        }
    }

    internal CodexVerifiedProcessSnapshot VerifyPostLaunch(
        CodexPackageBaselineSnapshot baseline,
        int expectedProcessId,
        SafeProcessHandle retainedProcessHandle)
    {
        try
        {
            ValidateOwnedBaseline(baseline);
            ArgumentNullException.ThrowIfNull(retainedProcessHandle);
            if (expectedProcessId <= 0 ||
                retainedProcessHandle.IsInvalid ||
                retainedProcessHandle.IsClosed)
            {
                throw Failure(
                    "invalid-process-handle",
                    "An exact PID and a retained live process handle are required.");
            }

            var first = CaptureProcessIdentity(
                baseline,
                checked((uint)expectedProcessId),
                retainedProcessHandle);
            RevalidateBaseline(baseline);
            var second = CaptureProcessIdentity(
                baseline,
                checked((uint)expectedProcessId),
                retainedProcessHandle);
            if (!SameProcessIdentity(first, second))
            {
                throw Failure(
                    "process-identity-drift",
                    "The retained Codex process identity changed during package revalidation.");
            }

            return new CodexVerifiedProcessSnapshot(
                expectedProcessId,
                second.UserSid,
                second.SessionId,
                second.PackageFullName,
                second.PackageFamilyName,
                second.ImagePath,
                second.CreationTimeUtc,
                second.ObservedAtUtc);
        }
        catch (CodexPackageBaselineException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(
                "postlaunch-verification-failed",
                "The launched Codex process baseline could not be verified.",
                exception);
        }
    }

    private CodexInstalledBaselineCapture CaptureInstalledBaseline()
    {
        var familyMember = ValidatePackageFamilyInventory(
            _platform.ReadCurrentUserPackageFamilyInventory(
                _compatibilityPolicy.PackageFamilyName));
        var package = _platform.ReadRegisteredPackageIdentity(familyMember.FullName);
        var trustDecision = ValidatePackageIdentity(package, familyMember.FullName);

        var registeredPath = NormalizeAbsolutePath(
            _platform.ReadRegisteredPackagePath(package.FullName),
            "registered-package-path");
        if (!IsDriveQualifiedPath(registeredPath))
        {
            throw Failure(
                "registered-package-path",
                "The registered Codex package must be on a local drive-qualified path.");
        }

        var windowsAppsPath = DeriveWindowsAppsPath(registeredPath, package.FullName);

        var packageDirectory = NormalizeDirectoryObservation(
            _platform.InspectDirectory(registeredPath),
            "registered-package-path");
        ValidateInstallDirectory(
            registeredPath,
            windowsAppsPath,
            package.FullName,
            packageDirectory);
        var finalInstallPath = packageDirectory.FinalPath;

        var manifestResult = VerifyManifest(finalInstallPath, package);
        var signatureResult = VerifyPackageSignature(
            finalInstallPath,
            package,
            trustDecision);
        var appxBlockMap = ReadAndValidateArtifact(
            finalInstallPath,
            AppxBlockMapRelativePath,
            MaximumAppxBlockMapBytes,
            captureContents: true);
        var chatGptExecutable = VerifyBlockMappedArtifact(
            finalInstallPath,
            ChatGptExecutableRelativePath,
            MaximumExecutableBytes);
        var codexExecutable = VerifyBlockMappedArtifact(
            finalInstallPath,
            CodexExecutableRelativePath,
            MaximumExecutableBytes);
        var appAsar = VerifyAppAsar(
            finalInstallPath,
            AppAsarRelativePath,
            MaximumAppAsarBytes);
        VerifyAppxBlockMapCoverage(
            appxBlockMap,
            manifestResult.BlockMapFile,
            chatGptExecutable.BlockMapFile,
            codexExecutable.BlockMapFile,
            appAsar.BlockMapFile);

        var artifacts = new[]
        {
            manifestResult.Artifact,
            signatureResult.Artifact,
            appxBlockMap.File,
            chatGptExecutable.Artifact,
            codexExecutable.Artifact,
            appAsar.Artifact
        };
        if (artifacts.Any(
                item => item.VolumeSerialNumber != packageDirectory.VolumeSerialNumber))
        {
            throw Failure(
                "artifact-volume-mismatch",
                "A pinned Codex artifact is not on the verified package directory volume.");
        }

        if (artifacts.Select(item => item.FinalPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count() != artifacts.Length ||
            artifacts.Select(item => (item.VolumeSerialNumber, item.FileId))
                .Distinct()
                .Count() != artifacts.Length)
        {
            throw Failure(
                "artifact-alias",
                "Two or more pinned Codex artifacts resolve to the same file identity.");
        }

        return new CodexInstalledBaselineCapture(
            package,
            trustDecision,
            registeredPath,
            finalInstallPath,
            windowsAppsPath,
            packageDirectory,
            manifestResult.Artifact,
            manifestResult.Metadata,
            signatureResult.Artifact,
            signatureResult.Signer,
            appxBlockMap.File,
            chatGptExecutable.Artifact,
            codexExecutable.Artifact,
            appAsar.Artifact,
            appAsar.Capabilities);
    }

    private static CodexPackageGenerationV1 CreatePackageGeneration(
        CodexInstalledBaselineCapture capture)
    {
        var package = capture.Package;
        var signer = capture.SignerIdentity;
        var manifest = capture.ManifestMetadata;
        var asar = capture.AsarCapabilities;
        return CodexPackageGenerationV1.Create(
            new CodexPackageGenerationPackageV1(
                package.FullName,
                package.FamilyName,
                package.Name,
                package.Version,
                package.Publisher,
                package.PublisherId,
                package.ResourceId,
                package.Architecture,
                (uint)package.Origin),
            new CodexPackageGenerationSignerV1(
                signer.Subject,
                signer.Issuer,
                signer.CertificateSha256,
                signer.SubjectPublicKeyInfoSha256,
                signer.CertificateThumbprint,
                signer.NotBeforeUtc.UtcDateTime.Ticks,
                signer.NotAfterUtc.UtcDateTime.Ticks),
            [
                ToGenerationArtifact(capture.AppxSignature),
                ToGenerationArtifact(capture.AppxBlockMap),
                ToGenerationArtifact(capture.Manifest),
                ToGenerationArtifact(capture.ChatGptExecutable),
                ToGenerationArtifact(capture.CodexExecutable),
                ToGenerationArtifact(capture.AppAsar)
            ],
            new CodexPackageGenerationManifestV1(
                manifest.Name,
                manifest.Publisher,
                manifest.Version,
                manifest.Architecture,
                manifest.Executable,
                manifest.EntryPoint),
            new CodexPackageGenerationAsarV1(
                asar.ContractId,
                asar.PackageName,
                asar.ProductName,
                asar.PackageVersion,
                asar.MainPath,
                ToGenerationAsarEntry(asar.PackageJson),
                ToGenerationAsarEntry(asar.Main),
                ToGenerationAsarEntry(asar.Preload)));
    }

    private static CodexPackageGenerationArtifactV1 ToGenerationArtifact(
        CodexPinnedArtifactSnapshot artifact) =>
        new(artifact.RelativePath, artifact.Length, artifact.Sha256);

    private static CodexPackageGenerationAsarEntryV1 ToGenerationAsarEntry(
        CodexAsarSelectedEntry entry) =>
        new(entry.Path, entry.Size, entry.Sha256);

    private void VerifyRegistrationStillCurrent(CodexInstalledBaselineCapture capture)
    {
        var familyMember = ValidatePackageFamilyInventory(
            _platform.ReadCurrentUserPackageFamilyInventory(
                _compatibilityPolicy.PackageFamilyName));
        var package = _platform.ReadRegisteredPackageIdentity(familyMember.FullName);
        _ = ValidatePackageIdentity(package, familyMember.FullName);
        var registeredPath = NormalizeAbsolutePath(
            _platform.ReadRegisteredPackagePath(package.FullName),
            "registered-package-path");
        var windowsAppsPath = DeriveWindowsAppsPath(registeredPath, package.FullName);
        var packageDirectory = NormalizeDirectoryObservation(
            _platform.InspectDirectory(registeredPath),
            "registered-package-path");
        ValidateInstallDirectory(
            registeredPath,
            windowsAppsPath,
            package.FullName,
            packageDirectory);

        if (!SamePackageIdentity(package, capture.Package) ||
            !string.Equals(
                registeredPath,
                capture.RegisteredInstallPath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                windowsAppsPath,
                capture.WindowsAppsPath,
                StringComparison.OrdinalIgnoreCase) ||
            !SameDirectory(packageDirectory, capture.PackageDirectory))
        {
            throw Failure(
                "package-registration-drift",
                "The current-user Codex package registration changed during verification.");
        }
    }

    private CodexProcessIdentityObservation CaptureProcessIdentity(
        CodexPackageBaselineSnapshot baseline,
        uint expectedProcessId,
        SafeProcessHandle retainedProcessHandle)
    {
        if (!_platform.IsRetainedProcessAlive(retainedProcessHandle))
        {
            throw Failure(
                "process-not-alive",
                "The retained Codex process exited before identity verification completed.");
        }

        var processId = _platform.ReadRetainedProcessId(retainedProcessHandle);
        if (processId != expectedProcessId)
        {
            throw Failure(
                "process-pid-mismatch",
                "The retained process handle does not identify the expected PID.");
        }

        var creationTimeUtc = _platform
            .ReadProcessCreationTimeUtc(retainedProcessHandle)
            .ToUniversalTime();
        var processUserSid = _platform.ReadProcessUserSid(retainedProcessHandle);
        ValidateSid(processUserSid, "process-user-sid");
        if (!string.Equals(
                processUserSid,
                baseline.CurrentUserSid,
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                "process-user-mismatch",
                "The launched Codex process does not belong to the current Windows user.");
        }

        var processSessionId = _platform.ReadProcessSessionId(processId);
        if (processSessionId != baseline.CurrentSessionId)
        {
            throw Failure(
                "process-session-mismatch",
                "The launched Codex process is not in the current Windows session.");
        }

        var packageFullName = _platform.ReadProcessPackageFullName(retainedProcessHandle);
        RequireExact(
            packageFullName,
            baseline.Package.FullName,
            "process-package-full-name",
            "The launched Codex process has an unexpected package full name.");
        var packageFamilyName = _platform.ReadProcessPackageFamilyName(retainedProcessHandle);
        RequireExact(
            packageFamilyName,
            baseline.Package.FamilyName,
            "process-package-family",
            "The launched Codex process has an unexpected package family.");

        var processImagePath = NormalizeAbsolutePath(
            _platform.ReadProcessImagePath(retainedProcessHandle),
            "process-image-path");
        if (!string.Equals(
                processImagePath,
                baseline.ChatGptExecutable.FinalPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                "process-image-mismatch",
                "The retained process is not the exact pinned final ChatGPT.exe image.");
        }

        var observedAtUtc = _platform.UtcNow.ToUniversalTime();
        if (creationTimeUtc < baseline.LaunchReservationUtc)
        {
            throw Failure(
                "process-created-before-reservation",
                "The retained process predates the verified launch reservation.");
        }

        if (creationTimeUtc > observedAtUtc)
        {
            throw Failure(
                "process-creation-in-future",
                "The retained process creation time is later than the verification time.");
        }

        if (!_platform.IsRetainedProcessAlive(retainedProcessHandle) ||
            _platform.ReadRetainedProcessId(retainedProcessHandle) != expectedProcessId)
        {
            throw Failure(
                "process-handle-drift",
                "The retained Codex process handle changed or exited during identity capture.");
        }

        return new CodexProcessIdentityObservation(
            expectedProcessId,
            processUserSid,
            processSessionId,
            packageFullName,
            packageFamilyName,
            processImagePath,
            creationTimeUtc,
            observedAtUtc);
    }

    private void ValidateProfile()
    {
        if (_profile.Schema != 2 ||
            !string.Equals(_profile.Mode, "read-only-cdp-pipe-runtime", StringComparison.Ordinal) ||
            !string.Equals(_profile.Transport, "remote-debugging-io-pipes", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(_profile.PackageFamilyName) ||
            string.IsNullOrWhiteSpace(_profile.PackageName) ||
            string.IsNullOrWhiteSpace(_profile.PackagePublisher) ||
            string.IsNullOrWhiteSpace(_profile.PackageArchitecture) ||
            string.IsNullOrWhiteSpace(_profile.ContractId) ||
            string.IsNullOrWhiteSpace(_profile.AsarPackageName) ||
            string.IsNullOrWhiteSpace(_profile.AsarProductName) ||
            string.IsNullOrWhiteSpace(_profile.AsarMainPath) ||
            string.IsNullOrWhiteSpace(_profile.PreloadPath) ||
            _profile.PreloadMarkers.Length == 0)
        {
            throw Failure(
                "invalid-runtime-profile",
                "The CDP runtime profile is not an exact capability-based pipe-runtime contract.");
        }

        foreach (var hash in new[]
                 {
                     _profile.AsarMainSha256,
                     _profile.PreloadSha256,
                     _profile.HookSha256
                 })
        {
            if (string.IsNullOrWhiteSpace(hash) ||
                hash.Length != 64 ||
                !hash.All(Uri.IsHexDigit))
            {
                throw Failure(
                    "invalid-runtime-profile-hash",
                    "The CDP runtime profile contains an invalid capability or owned-resource hash.");
            }
        }
    }

    private CodexPackageTrustDecision ValidatePackageIdentity(
        CodexAppModelPackageIdentity package,
        string discoveredFullName)
    {
        ArgumentNullException.ThrowIfNull(package);
        RequireExact(
            package.FullName,
            discoveredFullName,
            "package-full-name",
            "The registered Codex package full name does not match the discovered family head.");
        RequireExact(
            package.FamilyName,
            _compatibilityPolicy.PackageFamilyName,
            "package-family-name",
            "The registered Codex package family does not match the runtime profile.");
        RequireExact(
            package.Name,
            _compatibilityPolicy.PackageName,
            "package-name",
            "The registered Codex package name does not match the runtime profile.");
        if (string.IsNullOrWhiteSpace(package.Version) || package.Version.Length > 64)
        {
            throw Failure(
                "package-version",
                "The registered Codex package has no bounded observed version.");
        }
        RequireExact(
            package.Publisher,
            _compatibilityPolicy.PackagePublisher,
            "package-publisher",
            "The registered Codex package publisher does not match the runtime profile.");
        RequireExact(
            package.Architecture,
            _compatibilityPolicy.PackageArchitecture,
            "package-architecture",
            "The registered Codex package architecture does not match the runtime profile.");
        if (string.IsNullOrWhiteSpace(package.PublisherId) ||
            !string.IsNullOrEmpty(package.ResourceId))
        {
            throw Failure(
                "invalid-main-package-identity",
                "The parsed AppModel identity is not an exact main-package identity.");
        }

        RequireExact(
            package.Name + "_" + package.PublisherId,
            package.FamilyName,
            "package-family-derivation",
            "The package family does not match the PackageIdFromFullName publisher id.");
        return ResolveTrustDecision(package.Origin);
    }

    private CodexPackageTrustDecision ResolveTrustDecision(CodexPackageOrigin origin)
    {
        if (origin == CodexPackageOrigin.Store)
        {
            return new CodexPackageTrustDecision(
                CodexPackageTrustClass.OfficialStore,
                _trustMode);
        }

        if (_trustMode == CodexPackageTrustMode.AllowCompatibleSignedPatch &&
            origin == CodexPackageOrigin.DeveloperSigned)
        {
            return new CodexPackageTrustDecision(
                CodexPackageTrustClass.SignedPatchCandidate,
                _trustMode);
        }

        if (_trustMode == CodexPackageTrustMode.StoreOnly)
        {
            throw Failure(
                "package-origin-not-store",
                "GetStagedPackageOrigin did not prove that the Codex package came from Store.");
        }

        throw Failure(
            "package-origin-not-compatible-signed",
            "The observed package origin is not an explicitly supported signed patch class.");
    }

    private CodexPackageFamilyMember ValidatePackageFamilyInventory(
        IReadOnlyList<CodexPackageFamilyMember> inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        if (inventory.Count != 1)
        {
            throw Failure(
                "package-family-multiplicity",
                "The current user must have exactly one head package in the pinned Codex family.");
        }

        var member = inventory[0] ?? throw Failure(
            "package-family-member-invalid",
            "The current-user Codex package family inventory contains an invalid member.");
        if (string.IsNullOrWhiteSpace(member.FullName) || member.FullName.Length > 256)
        {
            throw Failure(
                "package-family-member-invalid",
                "The current-user Codex package family head has no bounded full name.");
        }
        if (member.Properties != 0)
        {
            throw Failure(
                "package-family-member-not-main",
                "The discovered Codex family member is not a normal main package.");
        }

        return member;
    }

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

    private string DeriveWindowsAppsPath(string registeredPath, string observedPackageFullName)
    {
        var windowsAppsPath = Path.GetDirectoryName(registeredPath);
        if (string.IsNullOrWhiteSpace(windowsAppsPath))
        {
            throw Failure(
                "package-not-under-windowsapps",
                "The registered Codex package has no WindowsApps parent directory.");
        }

        windowsAppsPath = NormalizeAbsolutePath(windowsAppsPath, "windowsapps-path");
        if (!IsDriveQualifiedPath(windowsAppsPath) ||
            !string.Equals(
                new DirectoryInfo(windowsAppsPath).Name,
                "WindowsApps",
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(registeredPath),
                observedPackageFullName,
                StringComparison.Ordinal))
        {
            throw Failure(
                "package-not-under-windowsapps",
                "The registered Codex package is not the exact expected WindowsApps child directory.");
        }

        return windowsAppsPath;
    }

    private void ValidateInstallDirectory(
        string registeredPath,
        string windowsAppsPath,
        string observedPackageFullName,
        CodexPathObservation packageDirectory)
    {
        if (!string.Equals(
                registeredPath,
                packageDirectory.RequestedPath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                registeredPath,
                packageDirectory.FinalPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                "package-path-redirection",
                "The registered Codex package path resolves to a different final location.");
        }

        if ((packageDirectory.Attributes & FileAttributes.Directory) == 0 ||
            (packageDirectory.Attributes &
             (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            packageDirectory.VolumeSerialNumber == 0 ||
            packageDirectory.FileId == 0)
        {
            throw Failure(
                "invalid-package-directory",
                "The registered Codex package path is not a regular non-reparse WindowsApps directory.");
        }

        var directory = new DirectoryInfo(packageDirectory.FinalPath);
        if (!string.Equals(
                directory.Name,
                observedPackageFullName,
                StringComparison.Ordinal) ||
            !string.Equals(
                directory.Parent?.FullName,
                windowsAppsPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(
                "package-not-under-windowsapps",
                "The registered Codex package is not the exact expected WindowsApps child directory.");
        }
    }

    private CodexManifestVerificationResult VerifyManifest(
        string finalInstallPath,
        CodexAppModelPackageIdentity package)
    {
        var expectedPath = GetExpectedArtifactPath(finalInstallPath, ManifestRelativePath);
        var observation = _platform.ReadAndHashBlockMappedRegularFile(
            expectedPath,
            MaximumManifestBytes,
            captureContents: true);
        var capture = ValidateArtifactObservation(
            finalInstallPath,
            ManifestRelativePath,
            expectedPath,
            MaximumManifestBytes,
            captureContents: true,
            observation.File);
        if (capture.Contents is not { Length: > 0 } contents ||
            contents.LongLength != capture.File.Length ||
            contents.LongLength > MaximumManifestBytes)
        {
            throw Failure(
                "manifest-content-unavailable",
                "The bounded AppxManifest.xml content was not captured with its pinned file handle.");
        }

        var metadata = ParseAndValidateManifest(contents, package);
        return new CodexManifestVerificationResult(
            capture.File,
            metadata,
            ToBlockMapFile(capture.File, observation.BlockSha256));
    }

    private CodexPackageSignatureVerificationResult VerifyPackageSignature(
        string finalInstallPath,
        CodexAppModelPackageIdentity package,
        CodexPackageTrustDecision trustDecision)
    {
        var expectedPath = GetExpectedArtifactPath(
            finalInstallPath,
            AppxSignatureRelativePath);
        var verified = _platform.ReadAndVerifyPackageSignature(
            expectedPath,
            MaximumAppxSignatureBytes);
        var artifact = ValidateArtifactObservation(
            finalInstallPath,
            AppxSignatureRelativePath,
            expectedPath,
            MaximumAppxSignatureBytes,
            captureContents: false,
            verified.File).File;
        ValidateSignerIdentity(verified.Signer);
        if (trustDecision.TrustClass == CodexPackageTrustClass.SignedPatchCandidate &&
            !string.Equals(
                verified.Signer.Subject,
                package.Publisher,
                StringComparison.Ordinal))
        {
            throw Failure(
                "package-signer-publisher-mismatch",
                "The signed patch certificate subject does not match the package publisher.");
        }

        return new CodexPackageSignatureVerificationResult(artifact, verified.Signer);
    }

    private static void ValidateSignerIdentity(CodexPackageSignerIdentity signer)
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
            signer.VerifiedAtUtc > signer.NotAfterUtc)
        {
            throw Failure(
                "invalid-package-signer",
                "The package signer identity is incomplete or outside its certificate validity window.");
        }
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private CodexBlockMappedArtifactVerificationResult VerifyBlockMappedArtifact(
        string finalInstallPath,
        string relativePath,
        long maximumBytes)
    {
        var expectedPath = GetExpectedArtifactPath(finalInstallPath, relativePath);
        var observation = _platform.ReadAndHashBlockMappedRegularFile(
            expectedPath,
            maximumBytes,
            captureContents: false);
        var capture = ValidateArtifactObservation(
            finalInstallPath,
            relativePath,
            expectedPath,
            maximumBytes,
            captureContents: false,
            observation.File);
        return new CodexBlockMappedArtifactVerificationResult(
            capture.File,
            ToBlockMapFile(capture.File, observation.BlockSha256));
    }

    private static void VerifyAppxBlockMapCoverage(
        CodexPinnedFileCapture blockMap,
        params CodexAppxBlockMapFileObservation[] selectedFiles)
    {
        try
        {
            if (blockMap.Contents is not { Length: > 0 } contents ||
                contents.LongLength != blockMap.File.Length ||
                contents.LongLength > MaximumAppxBlockMapBytes)
            {
                throw new CodexAppxBlockMapException(
                    "The bounded AppxBlockMap.xml content was not captured with its pinned handle.");
            }

            _ = CodexAppxBlockMapVerifier.Verify(contents, selectedFiles);
        }
        catch (CodexAppxBlockMapException exception)
        {
            throw Failure(
                "package-block-map-coverage",
                "The installed AppX block map does not cover the selected Codex package files.",
                exception);
        }
    }

    private CodexAppAsarVerificationResult VerifyAppAsar(
        string finalInstallPath,
        string relativePath,
        long maximumBytes)
    {
        var expectedPath = GetExpectedArtifactPath(finalInstallPath, relativePath);
        CodexInspectedAsarObservation inspected;
        try
        {
            inspected = _platform.ReadAndInspectAppAsar(
                expectedPath,
                maximumBytes,
                _asarCapabilityPolicy);
        }
        catch (CodexAsarCapabilityException exception)
        {
            throw Failure(
                "package-asar-capability",
                "The installed Codex ASAR capability contract is incompatible.",
                exception);
        }

        var artifact = ValidateArtifactObservation(
            finalInstallPath,
            relativePath,
            expectedPath,
            maximumBytes,
            captureContents: false,
            inspected.File.File).File;
        return new CodexAppAsarVerificationResult(
            artifact,
            inspected.Capabilities,
            ToBlockMapFile(artifact, inspected.File.BlockSha256));
    }

    private CodexPinnedFileCapture ReadAndValidateArtifact(
        string finalInstallPath,
        string relativePath,
        long maximumBytes,
        bool captureContents)
    {
        var expectedPath = GetExpectedArtifactPath(finalInstallPath, relativePath);
        var observation = _platform.ReadAndHashRegularFile(
            expectedPath,
            maximumBytes,
            captureContents);
        return ValidateArtifactObservation(
            finalInstallPath,
            relativePath,
            expectedPath,
            maximumBytes,
            captureContents,
            observation);
    }

    private static CodexAppxBlockMapFileObservation ToBlockMapFile(
        CodexPinnedArtifactSnapshot artifact,
        IReadOnlyList<string> blockSha256) =>
        new(artifact.RelativePath, artifact.Length, blockSha256);

    private static string GetExpectedArtifactPath(string finalInstallPath, string relativePath)
    {
        var expectedPath = NormalizeAbsolutePath(
            Path.Combine(finalInstallPath, relativePath),
            "artifact-path");
        if (!IsSameOrDescendant(expectedPath, finalInstallPath))
        {
            throw Failure("artifact-path-escape", "A pinned artifact path escapes the package root.");
        }

        return expectedPath;
    }

    private static CodexPinnedFileCapture ValidateArtifactObservation(
        string finalInstallPath,
        string relativePath,
        string expectedPath,
        long maximumBytes,
        bool captureContents,
        CodexPinnedFileObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var requestedPath = NormalizeAbsolutePath(
            observation.RequestedPath,
            "artifact-requested-path");
        var finalPath = NormalizeAbsolutePath(observation.FinalPath, "artifact-final-path");
        if (!string.Equals(requestedPath, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !IsSameOrDescendant(finalPath, finalInstallPath))
        {
            throw Failure(
                "artifact-path-redirection",
                "A pinned Codex artifact resolves outside its exact expected package path.");
        }

        if ((observation.Attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            observation.Length is <= 0 ||
            observation.Length > maximumBytes ||
            observation.VolumeSerialNumber == 0 ||
            observation.FileId == 0)
        {
            throw Failure(
                "invalid-artifact-file",
                "A pinned Codex artifact is not a bounded regular non-reparse file.");
        }

        if (string.IsNullOrWhiteSpace(observation.Sha256) ||
            observation.Sha256.Length != 64 ||
            !observation.Sha256.All(Uri.IsHexDigit))
        {
            throw Failure(
                "invalid-artifact-hash",
                "A Codex artifact did not produce a valid observed SHA-256 value.");
        }

        if (!captureContents && observation.Contents is not null)
        {
            throw Failure(
                "unexpected-artifact-content",
                "A non-manifest artifact unexpectedly retained file contents in memory.");
        }

        var snapshot = new CodexPinnedArtifactSnapshot(
            relativePath,
            expectedPath,
            finalPath,
            observation.Attributes,
            observation.Length,
            observation.Sha256.ToUpperInvariant(),
            observation.VolumeSerialNumber,
            observation.FileId);
        return new CodexPinnedFileCapture(snapshot, observation.Contents);
    }

    private CodexManifestMetadata ParseAndValidateManifest(
        byte[] contents,
        CodexAppModelPackageIdentity packageIdentity)
    {
        XDocument document;
        try
        {
            var settings = new XmlReaderSettings
            {
                CheckCharacters = true,
                DtdProcessing = DtdProcessing.Prohibit,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
                MaxCharactersFromEntities = 0,
                MaxCharactersInDocument = MaximumManifestBytes * 2,
                XmlResolver = null
            };
            using var stream = new MemoryStream(contents, writable: false);
            using var reader = XmlReader.Create(stream, settings);
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (Exception exception) when (
            exception is XmlException or InvalidOperationException or IOException)
        {
            throw Failure(
                "invalid-manifest-xml",
                "The bounded AppxManifest.xml is not safe valid XML.",
                exception);
        }

        var package = document.Root;
        if (package is null ||
            package.Name.LocalName != "Package" ||
            package.Name.NamespaceName != ManifestNamespace)
        {
            throw Failure(
                "invalid-manifest-root",
                "The AppxManifest.xml package root or namespace is unexpected.");
        }

        XNamespace manifestNamespace = ManifestNamespace;
        var identities = package.Elements(manifestNamespace + "Identity").ToArray();
        if (identities.Length != 1)
        {
            throw Failure(
                "invalid-manifest-identity",
                "The AppxManifest.xml must contain exactly one package Identity element.");
        }

        var identity = identities[0];
        var name = ReadRequiredAttribute(identity, "Name");
        var publisher = ReadRequiredAttribute(identity, "Publisher");
        var version = ReadRequiredAttribute(identity, "Version");
        var architecture = ReadRequiredAttribute(identity, "ProcessorArchitecture");
        RequireExact(
            name,
            _compatibilityPolicy.PackageName,
            "manifest-package-name",
            "The manifest package name does not match the runtime profile.");
        RequireExact(
            publisher,
            _compatibilityPolicy.PackagePublisher,
            "manifest-package-publisher",
            "The manifest publisher does not match the runtime profile.");
        RequireExact(
            version,
            packageIdentity.Version,
            "manifest-package-version",
            "The manifest version does not match the observed AppModel package.");
        RequireExact(
            architecture,
            _compatibilityPolicy.PackageArchitecture,
            "manifest-package-architecture",
            "The manifest architecture does not match the runtime profile.");

        var applications = package.Element(manifestNamespace + "Applications")?
            .Elements(manifestNamespace + "Application")
            .ToArray() ?? [];
        if (applications.Length != 1)
        {
            throw Failure(
                "invalid-manifest-application",
                "The AppxManifest.xml must contain exactly one full-trust application.");
        }

        var executable = NormalizeManifestRelativePath(
            ReadRequiredAttribute(applications[0], "Executable"));
        var entryPoint = ReadRequiredAttribute(applications[0], "EntryPoint");
        RequireExact(
            executable,
            ChatGptExecutableRelativePath,
            "manifest-executable",
            "The manifest executable is not the pinned ChatGPT.exe path.");
        RequireExact(
            entryPoint,
            FullTrustEntryPoint,
            "manifest-entry-point",
            "The manifest application is not the expected full-trust entry point.");

        return new CodexManifestMetadata(
            name,
            publisher,
            version,
            architecture,
            executable,
            entryPoint);
    }

    private void ValidateOwnedBaseline(CodexPackageBaselineSnapshot baseline)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        if (!ReferenceEquals(baseline.OwnerToken, _snapshotOwner) ||
            baseline.Profile != _profile)
        {
            throw Failure(
                "foreign-baseline",
                "The check requires a baseline created by this exact verifier profile.");
        }
    }

    private static string ReadRequiredAttribute(XElement element, string name) =>
        element.Attribute(name)?.Value is { Length: > 0 } value
            ? value
            : throw Failure(
                "manifest-metadata-missing",
                "The AppxManifest.xml is missing required bounded metadata: " + name + ".");

    private static string NormalizeManifestRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0)
        {
            throw Failure(
                "invalid-manifest-path",
                "The AppxManifest.xml contains an invalid executable path.");
        }

        var parts = path.Trim()
            .Replace('/', '\\')
            .Split('\\', StringSplitOptions.None);
        if (parts.Length == 0 ||
            parts.Any(part =>
                string.IsNullOrEmpty(part) ||
                part is "." or ".." ||
                part.Contains(':', StringComparison.Ordinal)))
        {
            throw Failure(
                "invalid-manifest-path",
                "The AppxManifest.xml executable path is not a canonical relative path.");
        }

        return string.Join('\\', parts);
    }

    private static void RequireExact(
        string actual,
        string expected,
        string code,
        string message)
    {
        if (string.IsNullOrWhiteSpace(actual) ||
            !string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw Failure(code, message);
        }
    }

    private static void ValidateSid(string sid, string code)
    {
        try
        {
            var parsed = new SecurityIdentifier(sid);
            if (!string.Equals(parsed.Value, sid, StringComparison.OrdinalIgnoreCase))
            {
                throw Failure(code, "A canonical Windows user SID is required.");
            }
        }
        catch (Exception exception) when (
            exception is ArgumentException or ArgumentNullException or SystemException)
        {
            throw Failure(code, "A valid Windows user SID is required.", exception);
        }
    }

    private static string NormalizeAbsolutePath(string path, string code)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0)
        {
            throw Failure(code, "An absolute Windows path is required.");
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
            throw Failure(code, "A supported fully qualified Windows path is required.");
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    private static bool IsDriveQualifiedPath(string path) =>
        path.Length >= 3 &&
        char.IsAsciiLetter(path[0]) &&
        path[1] == ':' &&
        path[2] == '\\';

    private static bool IsSameOrDescendant(string candidate, string root) =>
        string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase) ||
        candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static bool SamePackageIdentity(
        CodexAppModelPackageIdentity first,
        CodexAppModelPackageIdentity second) =>
        first.Origin == second.Origin &&
        string.Equals(first.FullName, second.FullName, StringComparison.Ordinal) &&
        string.Equals(first.FamilyName, second.FamilyName, StringComparison.Ordinal) &&
        string.Equals(first.Name, second.Name, StringComparison.Ordinal) &&
        string.Equals(first.Version, second.Version, StringComparison.Ordinal) &&
        string.Equals(first.Publisher, second.Publisher, StringComparison.Ordinal) &&
        string.Equals(first.PublisherId, second.PublisherId, StringComparison.Ordinal) &&
        string.Equals(first.ResourceId, second.ResourceId, StringComparison.Ordinal) &&
        string.Equals(first.Architecture, second.Architecture, StringComparison.Ordinal);

    private static bool SameDirectory(
        CodexPathObservation first,
        CodexPathObservation second) =>
        first.Attributes == second.Attributes &&
        first.VolumeSerialNumber == second.VolumeSerialNumber &&
        first.FileId == second.FileId &&
        string.Equals(first.RequestedPath, second.RequestedPath, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(first.FinalPath, second.FinalPath, StringComparison.OrdinalIgnoreCase);

    private static bool SameArtifact(
        CodexPinnedArtifactSnapshot first,
        CodexPinnedArtifactSnapshot second) =>
        first.Attributes == second.Attributes &&
        first.Length == second.Length &&
        first.VolumeSerialNumber == second.VolumeSerialNumber &&
        first.FileId == second.FileId &&
        string.Equals(first.RelativePath, second.RelativePath, StringComparison.Ordinal) &&
        string.Equals(first.RequestedPath, second.RequestedPath, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(first.FinalPath, second.FinalPath, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(first.Sha256, second.Sha256, StringComparison.OrdinalIgnoreCase);

    private static bool SameSignerIdentity(
        CodexPackageSignerIdentity earlier,
        CodexPackageSignerIdentity later) =>
        later.VerifiedAtUtc >= earlier.VerifiedAtUtc &&
        earlier.NotBeforeUtc == later.NotBeforeUtc &&
        earlier.NotAfterUtc == later.NotAfterUtc &&
        string.Equals(earlier.Subject, later.Subject, StringComparison.Ordinal) &&
        string.Equals(earlier.Issuer, later.Issuer, StringComparison.Ordinal) &&
        string.Equals(
            earlier.CertificateSha256,
            later.CertificateSha256,
            StringComparison.Ordinal) &&
        string.Equals(
            earlier.SubjectPublicKeyInfoSha256,
            later.SubjectPublicKeyInfoSha256,
            StringComparison.Ordinal) &&
        string.Equals(
            earlier.CertificateThumbprint,
            later.CertificateThumbprint,
            StringComparison.Ordinal);

    private static bool SameProcessIdentity(
        CodexProcessIdentityObservation first,
        CodexProcessIdentityObservation second) =>
        first.ProcessId == second.ProcessId &&
        first.SessionId == second.SessionId &&
        first.CreationTimeUtc == second.CreationTimeUtc &&
        second.ObservedAtUtc >= first.ObservedAtUtc &&
        string.Equals(first.UserSid, second.UserSid, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(first.PackageFullName, second.PackageFullName, StringComparison.Ordinal) &&
        string.Equals(first.PackageFamilyName, second.PackageFamilyName, StringComparison.Ordinal) &&
        string.Equals(first.ImagePath, second.ImagePath, StringComparison.OrdinalIgnoreCase);

    private static CodexPackageBaselineException Failure(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private sealed record CodexInstalledBaselineCapture(
        CodexAppModelPackageIdentity Package,
        CodexPackageTrustDecision TrustDecision,
        string RegisteredInstallPath,
        string FinalInstallPath,
        string WindowsAppsPath,
        CodexPathObservation PackageDirectory,
        CodexPinnedArtifactSnapshot Manifest,
        CodexManifestMetadata ManifestMetadata,
        CodexPinnedArtifactSnapshot AppxSignature,
        CodexPackageSignerIdentity SignerIdentity,
        CodexPinnedArtifactSnapshot AppxBlockMap,
        CodexPinnedArtifactSnapshot ChatGptExecutable,
        CodexPinnedArtifactSnapshot CodexExecutable,
        CodexPinnedArtifactSnapshot AppAsar,
        CodexAsarCapabilitySnapshot AsarCapabilities);

    private sealed record CodexManifestVerificationResult(
        CodexPinnedArtifactSnapshot Artifact,
        CodexManifestMetadata Metadata,
        CodexAppxBlockMapFileObservation BlockMapFile);

    private sealed record CodexPackageSignatureVerificationResult(
        CodexPinnedArtifactSnapshot Artifact,
        CodexPackageSignerIdentity Signer);

    private sealed record CodexAppAsarVerificationResult(
        CodexPinnedArtifactSnapshot Artifact,
        CodexAsarCapabilitySnapshot Capabilities,
        CodexAppxBlockMapFileObservation BlockMapFile);

    private sealed record CodexBlockMappedArtifactVerificationResult(
        CodexPinnedArtifactSnapshot Artifact,
        CodexAppxBlockMapFileObservation BlockMapFile);

    private sealed record CodexPinnedFileCapture(
        CodexPinnedArtifactSnapshot File,
        byte[]? Contents);

    private sealed record CodexProcessIdentityObservation(
        uint ProcessId,
        string UserSid,
        uint SessionId,
        string PackageFullName,
        string PackageFamilyName,
        string ImagePath,
        DateTimeOffset CreationTimeUtc,
        DateTimeOffset ObservedAtUtc);
}

internal sealed class CodexPackageBaselineSnapshot
{
    internal CodexPackageBaselineSnapshot(
        object ownerToken,
        CodexCdpRuntimeProfile profile,
        CodexAppModelPackageIdentity package,
        CodexPackageTrustDecision trustDecision,
        string registeredInstallPath,
        string finalInstallPath,
        string windowsAppsPath,
        CodexPathObservation packageDirectory,
        CodexPinnedArtifactSnapshot manifest,
        CodexManifestMetadata manifestMetadata,
        CodexPinnedArtifactSnapshot appxSignature,
        CodexPackageSignerIdentity signerIdentity,
        CodexPinnedArtifactSnapshot appxBlockMap,
        CodexPinnedArtifactSnapshot chatGptExecutable,
        CodexPinnedArtifactSnapshot codexExecutable,
        CodexPinnedArtifactSnapshot appAsar,
        CodexAsarCapabilitySnapshot asarCapabilities,
        CodexPackageGenerationV1 generation,
        string currentUserSid,
        uint currentSessionId,
        DateTimeOffset launchReservationUtc)
    {
        OwnerToken = ownerToken;
        Profile = profile;
        Package = package;
        TrustDecision = trustDecision;
        RegisteredInstallPath = registeredInstallPath;
        FinalInstallPath = finalInstallPath;
        WindowsAppsPath = windowsAppsPath;
        PackageDirectory = packageDirectory;
        Manifest = manifest;
        ManifestMetadata = manifestMetadata;
        AppxSignature = appxSignature;
        SignerIdentity = signerIdentity;
        AppxBlockMap = appxBlockMap;
        ChatGptExecutable = chatGptExecutable;
        CodexExecutable = codexExecutable;
        AppAsar = appAsar;
        AsarCapabilities = asarCapabilities;
        Generation = generation;
        CurrentUserSid = currentUserSid;
        CurrentSessionId = currentSessionId;
        LaunchReservationUtc = launchReservationUtc;
    }

    internal object OwnerToken { get; }

    internal CodexCdpRuntimeProfile Profile { get; }

    internal CodexAppModelPackageIdentity Package { get; }

    internal CodexPackageTrustDecision TrustDecision { get; }

    internal string RegisteredInstallPath { get; }

    internal string FinalInstallPath { get; }

    internal string WindowsAppsPath { get; }

    internal CodexPathObservation PackageDirectory { get; }

    internal CodexPinnedArtifactSnapshot Manifest { get; }

    internal CodexManifestMetadata ManifestMetadata { get; }

    internal CodexPinnedArtifactSnapshot AppxSignature { get; }

    internal CodexPackageSignerIdentity SignerIdentity { get; }

    internal CodexPinnedArtifactSnapshot AppxBlockMap { get; }

    internal CodexPinnedArtifactSnapshot ChatGptExecutable { get; }

    internal CodexPinnedArtifactSnapshot CodexExecutable { get; }

    internal CodexPinnedArtifactSnapshot AppAsar { get; }

    internal CodexAsarCapabilitySnapshot AsarCapabilities { get; }

    internal CodexPackageGenerationV1 Generation { get; }

    internal string CurrentUserSid { get; }

    internal uint CurrentSessionId { get; }

    internal DateTimeOffset LaunchReservationUtc { get; }
}

internal enum CodexPackageOrigin : uint
{
    Unknown = 0,
    Unsigned = 1,
    Inbox = 2,
    Store = 3,
    DeveloperUnsigned = 4,
    DeveloperSigned = 5,
    LineOfBusiness = 6,
    SignedSbom = 7
}

internal sealed record CodexAppModelPackageIdentity(
    string FullName,
    string FamilyName,
    string Name,
    string Version,
    string Publisher,
    string PublisherId,
    string ResourceId,
    string Architecture,
    CodexPackageOrigin Origin);

internal sealed record CodexPackageFamilyMember(
    string FullName,
    uint Properties);

internal sealed record CodexPathObservation(
    string RequestedPath,
    string FinalPath,
    FileAttributes Attributes,
    uint VolumeSerialNumber,
    ulong FileId);

internal sealed record CodexPinnedFileObservation(
    string RequestedPath,
    string FinalPath,
    FileAttributes Attributes,
    long Length,
    string Sha256,
    uint VolumeSerialNumber,
    ulong FileId,
    byte[]? Contents);

internal sealed record CodexBlockMappedFileObservation(
    CodexPinnedFileObservation File,
    IReadOnlyList<string> BlockSha256);

internal sealed record CodexInspectedAsarObservation(
    CodexBlockMappedFileObservation File,
    CodexAsarCapabilitySnapshot Capabilities);

internal sealed record CodexPackageSignerIdentity(
    string Subject,
    string Issuer,
    string CertificateSha256,
    string SubjectPublicKeyInfoSha256,
    string CertificateThumbprint,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    DateTimeOffset VerifiedAtUtc);

internal sealed record CodexVerifiedPackageSignatureObservation(
    CodexPinnedFileObservation File,
    CodexPackageSignerIdentity Signer);

internal sealed record CodexPinnedArtifactSnapshot(
    string RelativePath,
    string RequestedPath,
    string FinalPath,
    FileAttributes Attributes,
    long Length,
    string Sha256,
    uint VolumeSerialNumber,
    ulong FileId);

internal sealed record CodexManifestMetadata(
    string Name,
    string Publisher,
    string Version,
    string Architecture,
    string Executable,
    string EntryPoint);

internal sealed record CodexVerifiedProcessSnapshot(
    int ProcessId,
    string UserSid,
    uint SessionId,
    string PackageFullName,
    string PackageFamilyName,
    string ImagePath,
    DateTimeOffset CreationTimeUtc,
    DateTimeOffset VerifiedAtUtc);

internal interface ICodexPackageBaselinePlatform
{
    DateTimeOffset UtcNow { get; }

    CodexAppModelPackageIdentity ReadRegisteredPackageIdentity(string packageFullName);

    IReadOnlyList<CodexPackageFamilyMember> ReadCurrentUserPackageFamilyInventory(
        string packageFamilyName);

    string ReadRegisteredPackagePath(string packageFullName);

    CodexPathObservation InspectDirectory(string path);

    CodexPinnedFileObservation ReadAndHashRegularFile(
        string path,
        long maximumBytes,
        bool captureContents);

    CodexBlockMappedFileObservation ReadAndHashBlockMappedRegularFile(
        string path,
        long maximumBytes,
        bool captureContents);

    CodexInspectedAsarObservation ReadAndInspectAppAsar(
        string path,
        long maximumBytes,
        CodexAsarCapabilityPolicy policy);

    CodexVerifiedPackageSignatureObservation ReadAndVerifyPackageSignature(
        string path,
        long maximumBytes);

    string ReadCurrentUserSid();

    uint ReadCurrentSessionId();

    bool IsRetainedProcessAlive(SafeProcessHandle processHandle);

    uint ReadRetainedProcessId(SafeProcessHandle processHandle);

    string ReadProcessUserSid(SafeProcessHandle processHandle);

    uint ReadProcessSessionId(uint processId);

    string ReadProcessPackageFullName(SafeProcessHandle processHandle);

    string ReadProcessPackageFamilyName(SafeProcessHandle processHandle);

    string ReadProcessImagePath(SafeProcessHandle processHandle);

    DateTimeOffset ReadProcessCreationTimeUtc(SafeProcessHandle processHandle);
}

internal sealed class WindowsCodexPackageBaselinePlatform :
    ICodexPackageBaselinePlatform,
    ICodexStructuredInputPackagePlatform
{
    private const int ErrorSuccess = 0;
    private const int ErrorInsufficientBuffer = 122;
    private const uint FileReadAttributes = 0x0080;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagRandomAccess = 0x10000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint PackageInformationFull = 0x00000100;
    private const uint PackageFilterHead = 0x00000010;
    private const uint TokenQuery = 0x0008;
    private const int TokenUserInformationClass = 1;
    private const int MaximumWindowsPathCharacters = 32768;
    private const uint MaximumFamilyPackageCount = 16;
    private const uint MaximumFamilyBufferCharacters = 64 * 1024;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xFFFFFFFF;

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public CodexAppModelPackageIdentity ReadRegisteredPackageIdentity(string packageFullName)
    {
        uint bufferLength = 0;
        var result = PackageIdFromFullName(
            packageFullName,
            PackageInformationFull,
            ref bufferLength,
            IntPtr.Zero);
        if (result != ErrorInsufficientBuffer || bufferLength == 0)
        {
            throw new Win32Exception(result, "Unable to size the Codex AppModel package identity.");
        }

        var buffer = Marshal.AllocHGlobal(checked((int)bufferLength));
        try
        {
            result = PackageIdFromFullName(
                packageFullName,
                PackageInformationFull,
                ref bufferLength,
                buffer);
            if (result != ErrorSuccess)
            {
                throw new Win32Exception(result, "Unable to read the Codex AppModel package identity.");
            }

            var packageId = Marshal.PtrToStructure<PACKAGE_ID>(buffer);
            var name = ReadRequiredString(packageId.name, "package name");
            var publisher = ReadRequiredString(packageId.publisher, "package publisher");
            var publisherId = ReadRequiredString(packageId.publisherId, "package publisher id");
            var resourceId = Marshal.PtrToStringUni(packageId.resourceId) ?? string.Empty;
            var familyName = ReadPackageFamilyName(packageFullName);
            var version = string.Join(
                '.',
                packageId.version.Major,
                packageId.version.Minor,
                packageId.version.Build,
                packageId.version.Revision);
            result = GetStagedPackageOrigin(packageFullName, out var origin);
            if (result != ErrorSuccess)
            {
                throw new Win32Exception(result, "Unable to read the staged Codex package origin.");
            }

            return new CodexAppModelPackageIdentity(
                packageFullName,
                familyName,
                name,
                version,
                publisher,
                publisherId,
                resourceId,
                FormatArchitecture(packageId.processorArchitecture),
                (CodexPackageOrigin)origin);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public IReadOnlyList<CodexPackageFamilyMember> ReadCurrentUserPackageFamilyInventory(
        string packageFamilyName)
    {
        uint count = 0;
        uint bufferLength = 0;
        var result = FindPackagesByPackageFamily(
            packageFamilyName,
            PackageFilterHead,
            ref count,
            IntPtr.Zero,
            ref bufferLength,
            IntPtr.Zero,
            IntPtr.Zero);
        if (result == ErrorSuccess && count == 0 && bufferLength == 0)
        {
            return Array.Empty<CodexPackageFamilyMember>();
        }

        if (result != ErrorInsufficientBuffer ||
            count == 0 ||
            count > MaximumFamilyPackageCount ||
            bufferLength == 0 ||
            bufferLength > MaximumFamilyBufferCharacters)
        {
            throw new Win32Exception(
                result,
                "Unable to size a bounded current-user Codex package family inventory.");
        }

        var allocatedCount = count;
        var allocatedCharacters = bufferLength;
        var packageFullNames = Marshal.AllocHGlobal(
            checked((int)(allocatedCount * (uint)IntPtr.Size)));
        var buffer = Marshal.AllocHGlobal(checked((int)(allocatedCharacters * sizeof(char))));
        var properties = Marshal.AllocHGlobal(checked((int)(allocatedCount * sizeof(uint))));
        try
        {
            result = FindPackagesByPackageFamily(
                packageFamilyName,
                PackageFilterHead,
                ref count,
                packageFullNames,
                ref bufferLength,
                buffer,
                properties);
            if (result != ErrorSuccess ||
                count == 0 ||
                count > allocatedCount ||
                bufferLength > allocatedCharacters)
            {
                throw new Win32Exception(
                    result,
                    "Unable to read a stable bounded current-user Codex package family inventory.");
            }

            var resultItems = new List<CodexPackageFamilyMember>(checked((int)count));
            var bufferStart = buffer.ToInt64();
            var bufferEnd = checked(bufferStart + (long)allocatedCharacters * sizeof(char));
            for (var index = 0; index < count; index++)
            {
                var pointer = Marshal.ReadIntPtr(
                    packageFullNames,
                    checked((int)(index * (uint)IntPtr.Size)));
                var pointerValue = pointer.ToInt64();
                if (pointer == IntPtr.Zero ||
                    pointerValue < bufferStart ||
                    pointerValue >= bufferEnd ||
                    ((pointerValue - bufferStart) & 1) != 0)
                {
                    throw new InvalidDataException(
                        "The current-user package family inventory returned an invalid name pointer.");
                }

                var maximumCharacters = checked((int)((bufferEnd - pointerValue) / sizeof(char)));
                var fullName = ReadBoundedNullTerminatedString(pointer, maximumCharacters);
                var propertyValue = unchecked((uint)Marshal.ReadInt32(
                    properties,
                    checked((int)(index * sizeof(uint)))));
                resultItems.Add(new CodexPackageFamilyMember(fullName, propertyValue));
            }

            return resultItems;
        }
        finally
        {
            Marshal.FreeHGlobal(properties);
            Marshal.FreeHGlobal(buffer);
            Marshal.FreeHGlobal(packageFullNames);
        }
    }

    public string ReadRegisteredPackagePath(string packageFullName)
    {
        uint length = 0;
        var result = GetPackagePathByFullName(packageFullName, ref length, null);
        if (result != ErrorInsufficientBuffer || length == 0)
        {
            throw new Win32Exception(result, "Unable to size the registered Codex package path.");
        }

        var value = new StringBuilder(checked((int)length));
        result = GetPackagePathByFullName(packageFullName, ref length, value);
        if (result != ErrorSuccess || value.Length == 0)
        {
            throw new Win32Exception(result, "Unable to read the registered Codex package path.");
        }

        return value.ToString();
    }

    public CodexPathObservation InspectDirectory(string path)
    {
        using var handle = OpenPath(
            path,
            desiredAccess: 0,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint);
        var information = ReadFileInformation(handle);
        return new CodexPathObservation(
            path,
            ReadFinalPath(handle),
            (FileAttributes)information.FileAttributes,
            information.VolumeSerialNumber,
            Combine(information.FileIndexHigh, information.FileIndexLow));
    }

    public CodexPinnedFileObservation ReadAndHashRegularFile(
        string path,
        long maximumBytes,
        bool captureContents) =>
        ReadRegularFile(
            path,
            maximumBytes,
            captureContents,
            captureBlockHashes: false,
            asarPolicy: null).File;

    public CodexBlockMappedFileObservation ReadAndHashBlockMappedRegularFile(
        string path,
        long maximumBytes,
        bool captureContents)
    {
        var capture = ReadRegularFile(
            path,
            maximumBytes,
            captureContents,
            captureBlockHashes: true,
            asarPolicy: null);
        return new CodexBlockMappedFileObservation(
            capture.File,
            capture.BlockSha256 ?? throw new InvalidOperationException(
                "The block-mapped file capture did not return SHA-256 blocks."));
    }

    public CodexInspectedAsarObservation ReadAndInspectAppAsar(
        string path,
        long maximumBytes,
        CodexAsarCapabilityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var capture = ReadRegularFile(
            path,
            maximumBytes,
            captureContents: false,
            captureBlockHashes: true,
            asarPolicy: policy);
        return new CodexInspectedAsarObservation(
            new CodexBlockMappedFileObservation(
                capture.File,
                capture.BlockSha256 ?? throw new InvalidOperationException(
                    "The ASAR block-mapped capture did not return SHA-256 blocks.")),
            capture.Capabilities ?? throw new InvalidOperationException(
                "The ASAR capability inspection did not return a snapshot."));
    }

    public CodexStructuredInputAsarFileObservation ReadStructuredInputAppAsar(
        string path,
        long maximumBytes,
        CodexStructuredInputAsarInspectionLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        using var handle = OpenPath(
            path,
            GenericRead,
            FileFlagOpenReparsePoint | FileFlagRandomAccess);
        var before = ReadFileInformation(handle);
        var attributes = (FileAttributes)before.FileAttributes;
        var beforeLength = Combine(before.FileSizeHigh, before.FileSizeLow);
        if ((attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            beforeLength < 16 ||
            beforeLength > checked((ulong)maximumBytes) ||
            beforeLength > long.MaxValue)
        {
            throw new IOException("The pinned Codex app.asar is not a bounded regular file.");
        }

        CodexStructuredInputAsarSnapshot snapshot;
        string finalPath;
        using (var stream = new FileStream(
                   handle,
                   FileAccess.Read,
                   bufferSize: 64 * 1024,
                   isAsync: false))
        {
            snapshot = CodexStructuredInputAsarInspector.Inspect(
                new FileStreamAsarSource(stream, checked((long)beforeLength)),
                limits);
            var after = ReadFileInformation(handle);
            if (!SameFile(before, after))
            {
                throw new IOException(
                    "The pinned Codex app.asar changed during semantic inspection.");
            }

            finalPath = ReadFinalPath(handle);
        }

        var lastWriteFileTime = checked((long)Combine(
            before.LastWriteTime.High,
            before.LastWriteTime.Low));
        return new CodexStructuredInputAsarFileObservation(
            path,
            finalPath,
            attributes,
            checked((long)beforeLength),
            DateTimeOffset.FromFileTime(lastWriteFileTime).ToUniversalTime(),
            before.VolumeSerialNumber,
            Combine(before.FileIndexHigh, before.FileIndexLow),
            snapshot);
    }

    public CodexVerifiedPackageSignatureObservation ReadAndVerifyPackageSignature(
        string path,
        long maximumBytes)
    {
        var capture = ReadRegularFile(
            path,
            maximumBytes,
            captureContents: true,
            captureBlockHashes: false,
            asarPolicy: null);
        var contents = capture.File.Contents ??
            throw new InvalidOperationException("The package signature content was not retained.");
        try
        {
            if (contents.Length <= 4 ||
                contents[0] != (byte)'P' ||
                contents[1] != (byte)'K' ||
                contents[2] != (byte)'C' ||
                contents[3] != (byte)'X')
            {
                throw new CryptographicException("The package signature has an invalid PKCX envelope.");
            }

            var signedCms = new SignedCms();
            signedCms.Decode(contents.AsSpan(4).ToArray());
            if (signedCms.SignerInfos.Count != 1)
            {
                throw new CryptographicException("Exactly one package signer is required.");
            }

            signedCms.CheckSignature(verifySignatureOnly: false);
            var certificate = signedCms.SignerInfos[0].Certificate ??
                throw new CryptographicException("The package signer certificate is missing.");
            var verifiedAtUtc = DateTimeOffset.UtcNow;
            if (verifiedAtUtc < certificate.NotBefore.ToUniversalTime() ||
                verifiedAtUtc > certificate.NotAfter.ToUniversalTime())
            {
                throw new CryptographicException("The package signer certificate is not currently valid.");
            }

            var signer = new CodexPackageSignerIdentity(
                certificate.Subject,
                certificate.Issuer,
                Convert.ToHexString(SHA256.HashData(certificate.RawData)),
                Convert.ToHexString(SHA256.HashData(
                    certificate.PublicKey.ExportSubjectPublicKeyInfo())),
                certificate.Thumbprint?.ToUpperInvariant() ?? string.Empty,
                new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
                verifiedAtUtc);
            return new CodexVerifiedPackageSignatureObservation(
                capture.File with { Contents = null },
                signer);
        }
        catch (CryptographicException exception)
        {
            throw new IOException("The installed package signature could not be verified.", exception);
        }
    }

    private static CodexRegularFileCapture ReadRegularFile(
        string path,
        long maximumBytes,
        bool captureContents,
        bool captureBlockHashes,
        CodexAsarCapabilityPolicy? asarPolicy)
    {
        using var handle = OpenPath(
            path,
            GenericRead,
            FileFlagOpenReparsePoint | FileFlagSequentialScan);
        var before = ReadFileInformation(handle);
        var attributes = (FileAttributes)before.FileAttributes;
        var beforeLength = Combine(before.FileSizeHigh, before.FileSizeLow);
        if ((attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            beforeLength == 0 ||
            beforeLength > checked((ulong)maximumBytes) ||
            beforeLength > long.MaxValue ||
            (captureContents && beforeLength > int.MaxValue))
        {
            throw new IOException("The pinned Codex artifact is not a bounded regular file.");
        }

        string hashValue;
        string finalPath;
        long bytesRead = 0;
        byte[]? contents;
        List<string>? blockSha256 = captureBlockHashes ? [] : null;
        CodexAsarCapabilitySnapshot? capabilities = null;
        using (var stream = new FileStream(
                   handle,
                   FileAccess.Read,
                   bufferSize: 1024 * 1024,
                   isAsync: false))
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        using (var contentStream = captureContents
                   ? new MemoryStream(checked((int)beforeLength))
                   : null)
        {
            var buffer = new byte[CodexAppxBlockMapVerifier.BlockSizeBytes];
            while (true)
            {
                var blockLength = 0;
                while (blockLength < buffer.Length)
                {
                    var read = stream.Read(buffer, blockLength, buffer.Length - blockLength);
                    if (read == 0)
                    {
                        break;
                    }

                    blockLength = checked(blockLength + read);
                }

                if (blockLength == 0)
                {
                    break;
                }

                bytesRead = checked(bytesRead + blockLength);
                if (bytesRead > maximumBytes)
                {
                    throw new IOException("The pinned Codex artifact grew beyond its size limit.");
                }

                hash.AppendData(buffer, 0, blockLength);
                blockSha256?.Add(Convert.ToBase64String(SHA256.HashData(
                    buffer.AsSpan(0, blockLength))));
                contentStream?.Write(buffer, 0, blockLength);
                if (blockLength < buffer.Length)
                {
                    break;
                }
            }

            hashValue = Convert.ToHexString(hash.GetHashAndReset());
            if (asarPolicy is not null)
            {
                capabilities = CodexAsarCapabilityInspector.Inspect(
                    new FileStreamAsarSource(stream, checked((long)beforeLength)),
                    asarPolicy);
            }

            var after = ReadFileInformation(handle);
            if (!SameFile(before, after) || checked((ulong)bytesRead) != beforeLength)
            {
                throw new IOException("The pinned Codex artifact changed while it was being hashed.");
            }

            finalPath = ReadFinalPath(handle);
            contents = contentStream?.ToArray();
        }

        return new CodexRegularFileCapture(
            new CodexPinnedFileObservation(
                path,
                finalPath,
                attributes,
                checked((long)beforeLength),
                hashValue,
                before.VolumeSerialNumber,
                Combine(before.FileIndexHigh, before.FileIndexLow),
                contents),
            blockSha256 is null
                ? null
                : Array.AsReadOnly(blockSha256.ToArray()),
            capabilities);
    }

    private sealed record CodexRegularFileCapture(
        CodexPinnedFileObservation File,
        IReadOnlyList<string>? BlockSha256,
        CodexAsarCapabilitySnapshot? Capabilities);

    private sealed class FileStreamAsarSource(FileStream stream, long length)
        : ICodexAsarRandomAccessSource
    {
        private readonly FileStream _stream = stream ?? throw new ArgumentNullException(nameof(stream));

        public long Length { get; } = length;

        public void ReadExactly(long offset, Span<byte> destination)
        {
            if (offset < 0 || offset > Length - destination.Length)
            {
                throw new EndOfStreamException("The retained ASAR file is shorter than requested.");
            }

            _stream.Position = offset;
            var total = 0;
            while (total < destination.Length)
            {
                var read = _stream.Read(destination[total..]);
                if (read == 0)
                {
                    throw new EndOfStreamException("The retained ASAR file ended during a bounded read.");
                }

                total = checked(total + read);
            }
        }
    }

    public string ReadCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        return identity.User?.Value ?? throw new InvalidOperationException(
            "The current Windows user SID is unavailable.");
    }

    public uint ReadCurrentSessionId()
    {
        if (!ProcessIdToSessionId(checked((uint)Environment.ProcessId), out var sessionId))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the current Windows session id.");
        }

        return sessionId;
    }

    public bool IsRetainedProcessAlive(SafeProcessHandle processHandle)
    {
        var result = WaitForSingleObject(processHandle, 0);
        return result switch
        {
            WaitTimeout => true,
            WaitObject0 => false,
            WaitFailed => throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to query the retained Codex process state."),
            _ => throw new Win32Exception(
                "Windows returned an unexpected retained-process wait result.")
        };
    }

    public uint ReadRetainedProcessId(SafeProcessHandle processHandle)
    {
        var processId = GetProcessId(processHandle);
        if (processId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the retained Codex process id.");
        }

        return processId;
    }

    public string ReadProcessUserSid(SafeProcessHandle processHandle)
    {
        if (!OpenProcessToken(processHandle, TokenQuery, out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (token)
        {
            if (GetTokenInformation(
                    token,
                    TokenUserInformationClass,
                    IntPtr.Zero,
                    0,
                    out var requiredLength) ||
                Marshal.GetLastWin32Error() != ErrorInsufficientBuffer ||
                requiredLength <= 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var tokenInformation = Marshal.AllocHGlobal(requiredLength);
            try
            {
                if (!GetTokenInformation(
                        token,
                        TokenUserInformationClass,
                        tokenInformation,
                        requiredLength,
                        out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var sidPointer = Marshal.ReadIntPtr(tokenInformation);
                if (sidPointer == IntPtr.Zero)
                {
                    throw new InvalidOperationException("The Codex process user SID is missing.");
                }

                return new SecurityIdentifier(sidPointer).Value;
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInformation);
            }
        }
    }

    public uint ReadProcessSessionId(uint processId)
    {
        if (!ProcessIdToSessionId(processId, out var sessionId))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the Codex process session id.");
        }

        return sessionId;
    }

    public string ReadProcessPackageFullName(SafeProcessHandle processHandle) =>
        ReadProcessPackageString(processHandle, familyName: false);

    public string ReadProcessPackageFamilyName(SafeProcessHandle processHandle) =>
        ReadProcessPackageString(processHandle, familyName: true);

    public string ReadProcessImagePath(SafeProcessHandle processHandle)
    {
        var capacity = (uint)MaximumWindowsPathCharacters;
        var path = new StringBuilder((int)capacity);
        if (!QueryFullProcessImageName(processHandle, 0, path, ref capacity) || capacity == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the Codex process image path.");
        }

        return path.ToString();
    }

    public DateTimeOffset ReadProcessCreationTimeUtc(SafeProcessHandle processHandle)
    {
        if (!GetProcessTimes(
                processHandle,
                out var creationTime,
                out _,
                out _,
                out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the Codex process creation time.");
        }

        var fileTime = checked((long)Combine(creationTime.High, creationTime.Low));
        return DateTimeOffset.FromFileTime(fileTime).ToUniversalTime();
    }

    private static string ReadPackageFamilyName(string packageFullName)
    {
        uint length = 0;
        var result = PackageFamilyNameFromFullName(packageFullName, ref length, null);
        if (result != ErrorInsufficientBuffer || length == 0)
        {
            throw new Win32Exception(result, "Unable to size the Codex package family name.");
        }

        var value = new StringBuilder(checked((int)length));
        result = PackageFamilyNameFromFullName(packageFullName, ref length, value);
        if (result != ErrorSuccess || value.Length == 0)
        {
            throw new Win32Exception(result, "Unable to read the Codex package family name.");
        }

        return value.ToString();
    }

    private static string ReadProcessPackageString(
        SafeProcessHandle processHandle,
        bool familyName)
    {
        uint length = 0;
        var result = familyName
            ? GetPackageFamilyName(processHandle, ref length, null)
            : GetPackageFullName(processHandle, ref length, null);
        if (result != ErrorInsufficientBuffer || length == 0)
        {
            throw new Win32Exception(result);
        }

        var value = new StringBuilder(checked((int)length));
        result = familyName
            ? GetPackageFamilyName(processHandle, ref length, value)
            : GetPackageFullName(processHandle, ref length, value);
        if (result != ErrorSuccess || value.Length == 0)
        {
            throw new Win32Exception(result);
        }

        return value.ToString();
    }

    private static SafeFileHandle OpenPath(string path, uint desiredAccess, uint flags)
    {
        var handle = CreateFileW(
            path,
            desiredAccess,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            var component = Path.GetFileName(Path.TrimEndingDirectorySeparator(path));
            throw new Win32Exception(
                error,
                "Unable to open pinned Codex package component '" + component + "'.");
        }

        return handle;
    }

    private static BY_HANDLE_FILE_INFORMATION ReadFileInformation(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to inspect a pinned Codex package path.");
        }

        return information;
    }

    private static string ReadFinalPath(SafeFileHandle handle)
    {
        var path = new StringBuilder(512);
        var length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
        if (length == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to resolve a pinned Codex package path.");
        }

        if (length >= path.Capacity)
        {
            if (length >= MaximumWindowsPathCharacters)
            {
                throw new IOException("A pinned Codex package path is too long.");
            }

            path = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
            if (length == 0 || length >= path.Capacity)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to resolve the complete pinned Codex package path.");
            }
        }

        return path.ToString();
    }

    private static string ReadBoundedNullTerminatedString(
        IntPtr pointer,
        int maximumCharacters)
    {
        if (maximumCharacters <= 1)
        {
            throw new InvalidDataException("A bounded AppModel string has no usable capacity.");
        }

        for (var index = 0; index < maximumCharacters; index++)
        {
            if (Marshal.ReadInt16(pointer, checked(index * sizeof(char))) != 0)
            {
                continue;
            }

            if (index == 0)
            {
                throw new InvalidDataException("A bounded AppModel string is empty.");
            }

            return Marshal.PtrToStringUni(pointer, index) ?? throw new InvalidDataException(
                "A bounded AppModel string could not be decoded.");
        }

        throw new InvalidDataException("A bounded AppModel string is not NUL-terminated.");
    }

    private static bool SameFile(
        BY_HANDLE_FILE_INFORMATION first,
        BY_HANDLE_FILE_INFORMATION second) =>
        first.FileAttributes == second.FileAttributes &&
        first.VolumeSerialNumber == second.VolumeSerialNumber &&
        first.FileSizeHigh == second.FileSizeHigh &&
        first.FileSizeLow == second.FileSizeLow &&
        first.LastWriteTime.High == second.LastWriteTime.High &&
        first.LastWriteTime.Low == second.LastWriteTime.Low &&
        first.FileIndexHigh == second.FileIndexHigh &&
        first.FileIndexLow == second.FileIndexLow;

    private static ulong Combine(uint high, uint low) => ((ulong)high << 32) | low;

    private static string ReadRequiredString(IntPtr pointer, string description) =>
        Marshal.PtrToStringUni(pointer) is { Length: > 0 } value
            ? value
            : throw new InvalidDataException("The AppModel " + description + " is missing.");

    private static string FormatArchitecture(uint value) => value switch
    {
        0 => "x86",
        5 => "arm",
        6 => "ia64",
        9 => "x64",
        11 => "neutral",
        12 => "arm64",
        _ => "unknown-" + value
    };

    [StructLayout(LayoutKind.Explicit)]
    private struct PACKAGE_VERSION
    {
        [FieldOffset(0)]
        internal ulong Version;

        [FieldOffset(0)]
        internal ushort Revision;

        [FieldOffset(2)]
        internal ushort Build;

        [FieldOffset(4)]
        internal ushort Minor;

        [FieldOffset(6)]
        internal ushort Major;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PACKAGE_ID
    {
        internal uint reserved;
        internal uint processorArchitecture;
        internal PACKAGE_VERSION version;
        internal IntPtr name;
        internal IntPtr publisher;
        internal IntPtr resourceId;
        internal IntPtr publisherId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NATIVE_FILETIME
    {
        internal uint Low;
        internal uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        internal uint FileAttributes;
        internal NATIVE_FILETIME CreationTime;
        internal NATIVE_FILETIME LastAccessTime;
        internal NATIVE_FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int PackageIdFromFullName(
        string packageFullName,
        uint flags,
        ref uint bufferLength,
        IntPtr buffer);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int PackageFamilyNameFromFullName(
        string packageFullName,
        ref uint packageFamilyNameLength,
        StringBuilder? packageFamilyName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int FindPackagesByPackageFamily(
        string packageFamilyName,
        uint packageFilters,
        ref uint count,
        IntPtr packageFullNames,
        ref uint bufferLength,
        IntPtr buffer,
        IntPtr packageProperties);

    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetStagedPackageOrigin(
        string packageFullName,
        out uint origin);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackagePathByFullName(
        string packageFullName,
        ref uint pathLength,
        StringBuilder? path);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(
        SafeProcessHandle processHandle,
        ref uint packageFamilyNameLength,
        StringBuilder? packageFamilyName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFullName(
        SafeProcessHandle processHandle,
        ref uint packageFullNameLength,
        StringBuilder? packageFullName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathSize,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out BY_HANDLE_FILE_INFORMATION fileInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        SafeProcessHandle processHandle,
        uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle processHandle,
        uint flags,
        StringBuilder executablePath,
        ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle processHandle,
        out NATIVE_FILETIME creationTime,
        out NATIVE_FILETIME exitTime,
        out NATIVE_FILETIME kernelTime,
        out NATIVE_FILETIME userTime);
}

internal sealed class CodexPackageBaselineException : InvalidOperationException
{
    internal CodexPackageBaselineException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}
