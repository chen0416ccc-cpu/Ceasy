using CodexGuardian.Services;
using CodexGuardian.Control;
using Microsoft.Win32.SafeHandles;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal static class CodexPackageBaselineVerifierOfflineTests
{
    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase("package verifier accepts one exact Store main package", TestHappyPath, assert);
        RunCase(
            "package verifier freezes one canonical content generation",
            TestPackageGenerationIdentity,
            assert);
        RunCase(
            "package generation ignores observation time and binds the block map",
            TestPackageGenerationStability,
            assert);
        RunCase(
            "package verifier accepts one coherently advanced Store family head",
            TestCoherentPackageVersionAdvance,
            assert);
        RunCase(
            "package verifier accepts an unpinned whole-ASAR hash and freezes it",
            TestUnrelatedAppAsarHash,
            assert);
        RunCase("package verifier rejects a non-Store staged origin", TestNonStoreOrigin, assert);
        RunCase(
            "package verifier classifies a DeveloperSigned package as an opt-in candidate",
            TestCompatibleSignedPatchOptIn,
            assert);
        RunCase(
            "package verifier rejects an opt-in signed candidate with incompatible ASAR capabilities",
            TestSignedPatchCapabilityRejection,
            assert);
        RunCase(
            "package verifier rejects a signed candidate whose certificate subject differs",
            TestSignedPatchSignerSubject,
            assert);
        RunCase(
            "package verifier detects signer certificate and SPKI drift",
            TestSignerIdentityDrift,
            assert);
        RunCase(
            "package verifier accepts a later verification of the same signer",
            TestSignerVerificationTimeAdvance,
            assert);
        RunCase(
            "package verifier rejects a signer verification time rollback",
            TestSignerVerificationTimeRollback,
            assert);
        RunCase(
            "package verifier rejects DeveloperUnsigned even with signed-patch opt-in",
            TestUnsignedPatchRejection,
            assert);
        RunCase("package verifier rejects an empty current-user family", TestEmptyFamily, assert);
        RunCase("package verifier rejects duplicate current-user heads", TestDuplicateFamily, assert);
        RunCase("package verifier rejects old and new family coexistence", TestVersionCoexistence, assert);
        RunCase("package verifier rejects a non-main family member", TestNonMainFamilyMember, assert);
        RunCase("package verifier rejects an unknown family property bit", TestUnknownFamilyProperty, assert);
        RunCase("package verifier rejects a reparse package directory", TestReparsePackageDirectory, assert);
        RunCase("package verifier requires an exact WindowsApps parent", TestWindowsAppsParent, assert);
        RunCase("package verifier requires the exact package directory basename", TestPackageDirectoryName, assert);
        RunCase("package verifier rejects a redirected package directory", TestPackageDirectoryRedirection, assert);
        RunCase("package verifier validates bounded manifest identity metadata", TestManifestIdentity, assert);
        RunCase("package verifier prohibits manifest DTD processing", TestManifestDtd, assert);
        RunCase(
            "package verifier rejects an AppX selected-block hash mismatch",
            TestAppxBlockMapHashMismatch,
            assert);
        RunCase(
            "package verifier prohibits AppX block-map DTD processing",
            TestAppxBlockMapDtd,
            assert);
        RunCase(
            "package verifier rejects a duplicate AppX selected path",
            TestAppxBlockMapDuplicateSelectedPath,
            assert);
        RunCase("package verifier rejects redirected pinned artifacts", TestArtifactRedirection, assert);
        RunCase("package verifier binds artifacts to the package volume", TestArtifactVolume, assert);
        RunCase("package verifier detects package-family update drift", TestBaselineUpdateDrift, assert);
        RunCase("package verifier detects package directory identity drift", TestPackageDirectoryDrift, assert);
        RunCase("package verifier binds the retained handle to the exact PID", TestProcessPid, assert);
        RunCase("package verifier rejects a pre-reservation process", TestProcessCreationTime, assert);
        RunCase("package verifier binds the process user SID", TestProcessUser, assert);
        RunCase("package verifier binds the process Windows session", TestProcessSession, assert);
        RunCase("package verifier binds the process package identity", TestProcessPackage, assert);
        RunCase("package verifier binds the exact final ChatGPT image", TestProcessImage, assert);
        RunCase("package verifier revalidates process creation identity", TestProcessIdentityDrift, assert);
        RunCase("package verifier rejects an exited retained process", TestExitedProcess, assert);
        return Task.CompletedTask;
    }

    // This intentionally performs only registered-package reads and file hashing.
    internal static Task RunLiveInstalledPackageReadOnlyAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        const string name = "live installed Store package baseline is read-only verified";
        if (!OperatingSystem.IsWindows())
        {
            assert(false, name + ": Windows is required");
            return Task.CompletedTask;
        }

        try
        {
            var resources = CodexCdpRuntimeResources.Load();
            var verifier = new CodexPackageBaselineVerifier(resources.Profile);
            var baseline = verifier.VerifyPreLaunch();
            verifier.RevalidateBaseline(baseline);
            Ensure(
                baseline.Package.Origin == CodexPackageOrigin.Store,
                "GetStagedPackageOrigin did not return Store");
            Ensure(
                string.Equals(
                    baseline.ManifestMetadata.Executable,
                    CodexPackageBaselineVerifier.ChatGptExecutableRelativePath,
                    StringComparison.Ordinal),
                "the live manifest executable was not pinned");
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + DescribeException(exception));
        }

        return Task.CompletedTask;
    }

    // This mode only classifies and inspects the installed signed patch. It never launches Codex.
    internal static Task RunLiveInstalledPackageCandidateReadOnlyAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        const string name =
            "live installed signed patch is capability-compatible without launch authority";
        if (!OperatingSystem.IsWindows())
        {
            assert(false, name + ": Windows is required");
            return Task.CompletedTask;
        }

        try
        {
            var resources = CodexCdpRuntimeResources.Load();
            var verifier = new CodexPackageBaselineVerifier(
                resources.Profile,
                CodexPackageTrustMode.AllowCompatibleSignedPatch);
            var baseline = verifier.VerifyPreLaunch();
            verifier.RevalidateBaseline(baseline);
            Ensure(
                baseline.TrustDecision.TrustClass == CodexPackageTrustClass.SignedPatchCandidate &&
                baseline.TrustDecision.TrustMode ==
                    CodexPackageTrustMode.AllowCompatibleSignedPatch,
                "the installed package was not frozen as a signed-patch candidate");
            Ensure(
            baseline.AsarCapabilities.ContractId == resources.Profile.ContractId &&
                baseline.AsarCapabilities.Main.Path == resources.Profile.AsarMainPath &&
                baseline.AsarCapabilities.Main.Sha256 == resources.Profile.AsarMainSha256 &&
                baseline.AsarCapabilities.Preload.Path == resources.Profile.PreloadPath &&
                baseline.AsarCapabilities.Preload.Sha256 == resources.Profile.PreloadSha256,
                "the installed signed patch does not satisfy the schema 2 ASAR capability policy");
            Ensure(
                baseline.AppxSignature.RelativePath ==
                    CodexPackageBaselineVerifier.AppxSignatureRelativePath &&
                baseline.SignerIdentity.CertificateSha256.Length == 64 &&
                baseline.SignerIdentity.SubjectPublicKeyInfoSha256.Length == 64,
                "the installed signed patch signer binding was not frozen");
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + DescribeException(exception));
        }

        return Task.CompletedTask;
    }

    private static void TestHappyPath()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Verifier.RevalidateBaseline(baseline);
        using var handle = CreateFakeProcessHandle();
        var process = fixture.Verifier.VerifyPostLaunch(
            baseline,
            checked((int)fixture.Platform.ProcessId),
            handle);
        Ensure(process.ProcessId == fixture.Platform.ProcessId, "the verified PID was lost");
        Ensure(
            process.CreationTimeUtc == fixture.Platform.DefaultProcessCreationTimeUtc,
            "the process creation identity was lost");
        Ensure(
            baseline.TrustDecision.TrustClass == CodexPackageTrustClass.OfficialStore &&
            baseline.TrustDecision.TrustMode == CodexPackageTrustMode.StoreOnly,
            "the default Store trust decision was not frozen");
        Ensure(
            baseline.AsarCapabilities.ContractId == "codex-cdp-observation-v1" &&
            baseline.AsarCapabilities.PackageName == "openai-codex-electron",
            "the package ASAR capability snapshot was not frozen");
        Ensure(
            baseline.AppxSignature.RelativePath ==
                CodexPackageBaselineVerifier.AppxSignatureRelativePath &&
            baseline.AppxBlockMap.RelativePath ==
                CodexPackageBaselineVerifier.AppxBlockMapRelativePath &&
            baseline.SignerIdentity.CertificateSha256 == Fixture.CertificateSha256 &&
            baseline.SignerIdentity.SubjectPublicKeyInfoSha256 == Fixture.SpkiSha256,
            "the package signer and block-map identity were not frozen");
        Ensure(
            fixture.Platform.MaximumBytesSeen[fixture.CodexExecutablePath] == 512L * 1024 * 1024,
            "the large codex.exe bound was not explicit");
        Ensure(
            fixture.Platform.MaximumBytesSeen[fixture.AppxBlockMapPath] == 8L * 1024 * 1024,
            "the AppxBlockMap.xml bound was not explicit");
        Ensure(
            fixture.Platform.CaptureContentsSeen.SetEquals(
                [fixture.ManifestPath, fixture.AppxBlockMapPath]),
            "only AppxManifest.xml and AppxBlockMap.xml may be captured in baseline memory");
        Ensure(
            fixture.Platform.BlockHashesSeen.SetEquals(
            [
                fixture.ManifestPath,
                fixture.ChatGptExecutablePath,
                fixture.CodexExecutablePath,
                fixture.AppAsarPath
            ]),
            "the exact selected AppX package files were not block-hashed");
        Ensure(
            fixture.Platform.InspectedDirectories.Count > 0 &&
            fixture.Platform.InspectedDirectories.All(
                path => string.Equals(path, fixture.InstallPath, StringComparison.OrdinalIgnoreCase)),
            "the verifier must not require a handle to the protected WindowsApps parent");
    }

    private static void TestPackageGenerationIdentity()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        var generation = baseline.Generation;
        var expectedArtifacts = new[]
        {
            CodexPackageBaselineVerifier.AppxSignatureRelativePath,
            CodexPackageBaselineVerifier.AppxBlockMapRelativePath,
            CodexPackageBaselineVerifier.ManifestRelativePath,
            CodexPackageBaselineVerifier.ChatGptExecutableRelativePath,
            CodexPackageBaselineVerifier.CodexExecutableRelativePath,
            CodexPackageBaselineVerifier.AppAsarRelativePath
        };

        Ensure(
            generation.Schema == CodexPackageGenerationV1.SchemaName &&
            generation.Artifacts.Select(item => item.RelativePath).SequenceEqual(expectedArtifacts),
            "the canonical generation artifact order is incomplete");
        Ensure(
            generation.GenerationSha256 == Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes(generation.CanonicalJson))),
            "the generation hash does not bind its canonical UTF-8 JSON");
        Ensure(
            !generation.CanonicalJson.Contains(fixture.WindowsAppsPath, StringComparison.OrdinalIgnoreCase) &&
            !generation.CanonicalJson.Contains(
                fixture.Platform.CurrentUserSid,
                StringComparison.Ordinal) &&
            !generation.CanonicalJson.Contains("verifiedAtUtc", StringComparison.Ordinal),
            "ephemeral baseline observations leaked into the content generation");
    }

    private static void TestPackageGenerationStability()
    {
        var fixture = Fixture.Create();
        var first = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.SignerIdentity = fixture.Platform.SignerIdentity with
        {
            VerifiedAtUtc = first.SignerIdentity.VerifiedAtUtc.AddSeconds(1)
        };

        var laterObservation = fixture.Verifier.VerifyPreLaunch();
        Ensure(
            laterObservation.Generation.Equals(first.Generation),
            "a later observation of identical package content changed the generation");

        fixture.RewriteBlockMap(addInsignificantWhitespace: true);
        var changedBlockMap = fixture.Verifier.VerifyPreLaunch();
        Ensure(
            !changedBlockMap.Generation.Equals(first.Generation),
            "an AppxBlockMap.xml change did not change the generation");
    }

    private static void TestCoherentPackageVersionAdvance()
    {
        var fixture = Fixture.Create();
        const string observedVersion = "26.731.1.0";
        var observedFullName = fixture.RetargetObservedPackageVersion(observedVersion);

        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Verifier.RevalidateBaseline(baseline);

        Ensure(baseline.Package.FullName == observedFullName, "the observed full name was not frozen");
        Ensure(baseline.Package.Version == observedVersion, "the observed version was not frozen");
        Ensure(
            baseline.ManifestMetadata.Version == observedVersion,
            "the observed manifest version was not frozen");
        Ensure(
            fixture.Platform.IdentityFullNameRequests.Count > 0 &&
            fixture.Platform.IdentityFullNameRequests.All(value => value == observedFullName),
            "identity lookup did not use the discovered family head");
        Ensure(
            fixture.Platform.PackagePathFullNameRequests.Count > 0 &&
            fixture.Platform.PackagePathFullNameRequests.All(value => value == observedFullName),
            "path lookup did not use the discovered family head");
        Ensure(
            fixture.Platform.RegistrationReadOrder.FirstOrDefault() == "family",
            "the unique family head was not discovered before full-name lookup");
    }

    private static void TestUnrelatedAppAsarHash()
    {
        var fixture = Fixture.Create();
        var firstBytes = CodexAsarCapabilityOfflineTests.BuildArchive(
            unrelatedContents: "unrelated-zlpha");
        var firstHash = Convert.ToHexString(SHA256.HashData(firstBytes));
        var defaultHash = Convert.ToHexString(SHA256.HashData(
            CodexAsarCapabilityOfflineTests.BuildArchive()));
        fixture.Platform.AddFile(
            fixture.AppAsarPath,
            firstBytes,
            fileId: 104,
            retainContents: false);
        fixture.RewriteBlockMap();
        Ensure(
            firstHash != defaultHash,
            "the test ASAR must differ from the default fixture hash");

        var baseline = fixture.Verifier.VerifyPreLaunch();
        Ensure(baseline.AppAsar.Sha256 == firstHash, "the observed ASAR hash was not frozen");
        Ensure(
            baseline.AppAsar.Length == firstBytes.LongLength,
            "the observed ASAR length was not frozen");
        fixture.Verifier.RevalidateBaseline(baseline);

        var secondBytes = CodexAsarCapabilityOfflineTests.BuildArchive(
            unrelatedContents: "unrelated-ylpha");
        fixture.Platform.AddFile(
            fixture.AppAsarPath,
            secondBytes,
            fileId: 104,
            retainContents: false);
        fixture.RewriteBlockMap();
        ExpectCode(
            () => fixture.Verifier.RevalidateBaseline(baseline),
            "package-baseline-drift");
    }

    private static void TestNonStoreOrigin()
    {
        var fixture = Fixture.Create();
        fixture.Platform.PackageIdentity = fixture.Platform.PackageIdentity with
        {
            Origin = CodexPackageOrigin.DeveloperSigned
        };
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-origin-not-store");
    }

    private static void TestCompatibleSignedPatchOptIn()
    {
        var fixture = Fixture.Create(
            trustMode: CodexPackageTrustMode.AllowCompatibleSignedPatch);
        fixture.Platform.PackageIdentity = fixture.Platform.PackageIdentity with
        {
            Origin = CodexPackageOrigin.DeveloperSigned
        };

        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Verifier.RevalidateBaseline(baseline);
        Ensure(
            baseline.TrustDecision.TrustClass == CodexPackageTrustClass.SignedPatchCandidate &&
            baseline.TrustDecision.TrustMode == CodexPackageTrustMode.AllowCompatibleSignedPatch,
            "the explicit signed-patch candidate decision was not frozen");
    }

    private static void TestSignedPatchCapabilityRejection()
    {
        var fixture = Fixture.Create(
            trustMode: CodexPackageTrustMode.AllowCompatibleSignedPatch);
        fixture.Platform.PackageIdentity = fixture.Platform.PackageIdentity with
        {
            Origin = CodexPackageOrigin.DeveloperSigned
        };
        var changedPreload = Encoding.UTF8.GetBytes(
            "electronBridge codex_desktop:message-for-view contextBridge.exposeInMainWorld");
        fixture.Platform.AddFile(
            fixture.AppAsarPath,
            CodexAsarCapabilityOfflineTests.BuildArchive(preloadBytes: changedPreload),
            fileId: 104,
            retainContents: false);
        fixture.RewriteBlockMap();
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-asar-capability");
    }

    private static void TestSignedPatchSignerSubject()
    {
        var fixture = Fixture.Create(
            trustMode: CodexPackageTrustMode.AllowCompatibleSignedPatch);
        fixture.Platform.PackageIdentity = fixture.Platform.PackageIdentity with
        {
            Origin = CodexPackageOrigin.DeveloperSigned
        };
        fixture.Platform.SignerIdentity = fixture.Platform.SignerIdentity with
        {
            Subject = "CN=00000000-0000-0000-0000-000000000000"
        };
        ExpectCode(
            fixture.Verifier.VerifyPreLaunch,
            "package-signer-publisher-mismatch");
    }

    private static void TestSignerIdentityDrift()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.SignerIdentity = fixture.Platform.SignerIdentity with
        {
            CertificateSha256 = new string('D', 64),
            SubjectPublicKeyInfoSha256 = new string('E', 64),
            CertificateThumbprint = new string('F', 40)
        };
        ExpectCode(
            () => fixture.Verifier.RevalidateBaseline(baseline),
            "package-baseline-drift");
    }

    private static void TestSignerVerificationTimeAdvance()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.SignerIdentity = fixture.Platform.SignerIdentity with
        {
            VerifiedAtUtc = baseline.SignerIdentity.VerifiedAtUtc.AddSeconds(1)
        };

        fixture.Verifier.RevalidateBaseline(baseline);
    }

    private static void TestSignerVerificationTimeRollback()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.SignerIdentity = fixture.Platform.SignerIdentity with
        {
            VerifiedAtUtc = baseline.SignerIdentity.VerifiedAtUtc.AddTicks(-1)
        };

        ExpectCode(
            () => fixture.Verifier.RevalidateBaseline(baseline),
            "package-baseline-drift");
    }

    private static void TestUnsignedPatchRejection()
    {
        var fixture = Fixture.Create(
            trustMode: CodexPackageTrustMode.AllowCompatibleSignedPatch);
        fixture.Platform.PackageIdentity = fixture.Platform.PackageIdentity with
        {
            Origin = CodexPackageOrigin.DeveloperUnsigned
        };
        ExpectCode(
            fixture.Verifier.VerifyPreLaunch,
            "package-origin-not-compatible-signed");
    }

    private static void TestEmptyFamily()
    {
        var fixture = Fixture.Create();
        fixture.Platform.FamilyInventory = [];
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-family-multiplicity");
    }

    private static void TestDuplicateFamily()
    {
        var fixture = Fixture.Create();
        var member = fixture.Platform.FamilyInventory.Single();
        fixture.Platform.FamilyInventory = [member, member];
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-family-multiplicity");
    }

    private static void TestVersionCoexistence()
    {
        var fixture = Fixture.Create();
        fixture.Platform.FamilyInventory =
        [
            new CodexPackageFamilyMember(
                "OpenAI.Codex_26.727.4816.0_x64__2p2nqsd0c76g0",
                0),
            new CodexPackageFamilyMember(fixture.PackageFullName, 0)
        ];
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-family-multiplicity");
    }

    private static void TestNonMainFamilyMember()
    {
        var fixture = Fixture.Create();
        fixture.Platform.FamilyInventory =
        [new CodexPackageFamilyMember(fixture.PackageFullName, 0x00000001)];
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-family-member-not-main");
    }

    private static void TestUnknownFamilyProperty()
    {
        var fixture = Fixture.Create();
        fixture.Platform.FamilyInventory =
        [new CodexPackageFamilyMember(fixture.PackageFullName, 0x80000000)];
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-family-member-not-main");
    }

    private static void TestReparsePackageDirectory()
    {
        var fixture = Fixture.Create();
        fixture.Platform.Directories[fixture.InstallPath] =
            fixture.Platform.Directories[fixture.InstallPath] with
            {
                Attributes = FileAttributes.Directory | FileAttributes.ReparsePoint
            };
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "invalid-package-directory");
    }

    private static void TestWindowsAppsParent()
    {
        var fixture = Fixture.Create();
        fixture.Platform.RegisteredPackagePath = Path.Combine(
            "C:\\Program Files\\NotWindowsApps",
            fixture.PackageFullName);
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-not-under-windowsapps");
    }

    private static void TestPackageDirectoryName()
    {
        var fixture = Fixture.Create();
        fixture.Platform.RegisteredPackagePath = Path.Combine(
            fixture.WindowsAppsPath,
            "OpenAI.Codex_wrong_x64__2p2nqsd0c76g0");
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-not-under-windowsapps");
    }

    private static void TestPackageDirectoryRedirection()
    {
        var fixture = Fixture.Create();
        fixture.Platform.Directories[fixture.InstallPath] =
            fixture.Platform.Directories[fixture.InstallPath] with
            {
                FinalPath = Path.Combine(
                    fixture.WindowsAppsPath,
                    "OpenAI.Codex_redirected_x64__2p2nqsd0c76g0")
            };
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-path-redirection");
    }

    private static void TestManifestIdentity()
    {
        var baseProfile = CodexCdpRuntimeResources.Load().Profile;
        var manifest = Fixture.BuildManifest(
            baseProfile,
            publisher: "CN=00000000-0000-0000-0000-000000000000");
        var fixture = Fixture.Create(manifest);
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "manifest-package-publisher");
    }

    private static void TestManifestDtd()
    {
        var baseProfile = CodexCdpRuntimeResources.Load().Profile;
        var manifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<!DOCTYPE Package [<!ENTITY probe \"forbidden\">]>" +
            Fixture.BuildManifest(baseProfile, includeDeclaration: false);
        var fixture = Fixture.Create(manifest);
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "invalid-manifest-xml");
    }

    private static void TestAppxBlockMapHashMismatch()
    {
        var fixture = Fixture.Create();
        fixture.RewriteBlockMap(corruptFirstHash: true);
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-block-map-coverage");
    }

    private static void TestAppxBlockMapDtd()
    {
        var fixture = Fixture.Create();
        fixture.RewriteBlockMap(includeDtd: true);
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-block-map-coverage");
    }

    private static void TestAppxBlockMapDuplicateSelectedPath()
    {
        var fixture = Fixture.Create();
        fixture.RewriteBlockMap(duplicateManifest: true);
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "package-block-map-coverage");
    }

    private static void TestArtifactRedirection()
    {
        var fixture = Fixture.Create();
        fixture.Platform.Files[fixture.AppAsarPath] =
            fixture.Platform.Files[fixture.AppAsarPath] with
            {
                FinalPath = "C:\\Program Files\\WindowsApps\\other\\app.asar"
            };
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "artifact-path-redirection");
    }

    private static void TestArtifactVolume()
    {
        var fixture = Fixture.Create();
        fixture.Platform.Files[fixture.AppAsarPath] =
            fixture.Platform.Files[fixture.AppAsarPath] with
            {
                VolumeSerialNumber = 18
            };
        ExpectCode(fixture.Verifier.VerifyPreLaunch, "artifact-volume-mismatch");
    }

    private static void TestBaselineUpdateDrift()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.FamilyInventory =
        [
            new CodexPackageFamilyMember(fixture.PackageFullName, 0),
            new CodexPackageFamilyMember(
                "OpenAI.Codex_26.728.1.0_x64__2p2nqsd0c76g0",
                0)
        ];
        ExpectCode(
            () => fixture.Verifier.RevalidateBaseline(baseline),
            "package-family-multiplicity");
    }

    private static void TestPackageDirectoryDrift()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.Directories[fixture.InstallPath] =
            fixture.Platform.Directories[fixture.InstallPath] with
            {
                FileId = 3
            };
        ExpectCode(
            () => fixture.Verifier.RevalidateBaseline(baseline),
            "package-baseline-drift");
    }

    private static void TestProcessPid()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId + 1),
                handle),
            "process-pid-mismatch");
    }

    private static void TestProcessCreationTime()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.ProcessCreationTimes.Enqueue(baseline.LaunchReservationUtc.AddTicks(-1));
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId),
                handle),
            "process-created-before-reservation");
    }

    private static void TestProcessUser()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.ProcessUserSid = "S-1-5-21-9-8-7-1001";
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId),
                handle),
            "process-user-mismatch");
    }

    private static void TestProcessSession()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.ProcessSessionId++;
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId),
                handle),
            "process-session-mismatch");
    }

    private static void TestProcessPackage()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.ProcessPackageFullName =
            "OpenAI.Codex_26.728.1.0_x64__2p2nqsd0c76g0";
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId),
                handle),
            "process-package-full-name");
    }

    private static void TestProcessImage()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.ProcessImagePath =
            "C:\\Program Files\\WindowsApps\\OpenAI.Codex_fake\\app\\ChatGPT.exe";
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId),
                handle),
            "process-image-mismatch");
    }

    private static void TestProcessIdentityDrift()
    {
        var fixture = Fixture.Create();
        var start = fixture.Platform.DefaultNowUtc;
        fixture.Platform.UtcNowValues.Enqueue(start);
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.UtcNowValues.Enqueue(start.AddSeconds(2));
        fixture.Platform.UtcNowValues.Enqueue(start.AddSeconds(3));
        fixture.Platform.ProcessCreationTimes.Enqueue(start.AddSeconds(1));
        fixture.Platform.ProcessCreationTimes.Enqueue(start.AddSeconds(1).AddTicks(1));
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId),
                handle),
            "process-identity-drift");
    }

    private static void TestExitedProcess()
    {
        var fixture = Fixture.Create();
        var baseline = fixture.Verifier.VerifyPreLaunch();
        fixture.Platform.ProcessAlive = false;
        using var handle = CreateFakeProcessHandle();
        ExpectCode(
            () => fixture.Verifier.VerifyPostLaunch(
                baseline,
                checked((int)fixture.Platform.ProcessId),
                handle),
            "process-not-alive");
    }

    private static SafeProcessHandle CreateFakeProcessHandle() =>
        new(new IntPtr(0x1234), ownsHandle: false);

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

    private static void ExpectCode(Action action, string expectedCode)
    {
        try
        {
            action();
        }
        catch (CodexPackageBaselineException exception)
        {
            Ensure(
                string.Equals(exception.Code, expectedCode, StringComparison.Ordinal),
                "expected " + expectedCode + " but received " + exception.Code);
            return;
        }

        throw new InvalidOperationException(
            "Expected CodexPackageBaselineException code " + expectedCode + ".");
    }

    private static void ExpectCode<T>(Func<T> action, string expectedCode) =>
        ExpectCode(
            () =>
            {
                _ = action();
            },
            expectedCode);

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static string DescribeException(Exception exception)
    {
        var descriptions = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            var code = current is CodexPackageBaselineException baselineException
                ? "[" + baselineException.Code + "] "
                : string.Empty;
            descriptions.Add(code + current.GetType().Name + ": " + current.Message);
        }

        return string.Join(" -> ", descriptions);
    }

    private sealed class Fixture
    {
        private const string DefaultPackageVersion = "26.730.8199.0";
        internal const string CertificateSha256 =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        internal const string SpkiSha256 =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        private Fixture(
            CodexCdpRuntimeProfile profile,
            FakePlatform platform,
            string windowsAppsPath,
            string installPath,
            CodexPackageTrustMode trustMode)
        {
            Profile = profile;
            Platform = platform;
            WindowsAppsPath = windowsAppsPath;
            InstallPath = installPath;
            ManifestPath = Path.Combine(installPath, CodexPackageBaselineVerifier.ManifestRelativePath);
            AppxSignaturePath = Path.Combine(
                installPath,
                CodexPackageBaselineVerifier.AppxSignatureRelativePath);
            AppxBlockMapPath = Path.Combine(
                installPath,
                CodexPackageBaselineVerifier.AppxBlockMapRelativePath);
            ChatGptExecutablePath = Path.Combine(
                installPath,
                CodexPackageBaselineVerifier.ChatGptExecutableRelativePath);
            CodexExecutablePath = Path.Combine(
                installPath,
                CodexPackageBaselineVerifier.CodexExecutableRelativePath);
            AppAsarPath = Path.Combine(
                installPath,
                CodexPackageBaselineVerifier.AppAsarRelativePath);
            Verifier = new CodexPackageBaselineVerifier(
                profile,
                trustMode,
                CodexAsarCapabilityOfflineTests.CreatePolicy(),
                platform);
        }

        internal CodexCdpRuntimeProfile Profile { get; }

        internal string PackageFullName => Platform.PackageIdentity.FullName;

        internal FakePlatform Platform { get; }

        internal CodexPackageBaselineVerifier Verifier { get; }

        internal string WindowsAppsPath { get; }

        internal string InstallPath { get; private set; }

        internal string ManifestPath { get; private set; }

        internal string AppxSignaturePath { get; private set; }

        internal string AppxBlockMapPath { get; private set; }

        internal string ChatGptExecutablePath { get; private set; }

        internal string CodexExecutablePath { get; private set; }

        internal string AppAsarPath { get; private set; }

        internal static Fixture Create(
            string? manifest = null,
            CodexPackageTrustMode trustMode = CodexPackageTrustMode.StoreOnly)
        {
            var embeddedProfile = CodexCdpRuntimeResources.Load().Profile;
            manifest ??= BuildManifest(embeddedProfile);
            var manifestBytes = Encoding.UTF8.GetBytes(manifest);
            var signatureBytes = Encoding.ASCII.GetBytes("synthetic-appx-signature");
            var chatBytes = Encoding.ASCII.GetBytes("synthetic-chatgpt-executable");
            var codexBytes = Encoding.ASCII.GetBytes("synthetic-codex-executable");
            var asarBytes = CodexAsarCapabilityOfflineTests.BuildArchive();
            var blockMapBytes = BuildBlockMap(
                manifestBytes,
                chatBytes,
                codexBytes,
                asarBytes);
            var profile = embeddedProfile;
            var windowsAppsPath = "C:\\Program Files\\WindowsApps";
            var packageFullName = BuildPackageFullName(profile, DefaultPackageVersion);
            var installPath = Path.Combine(windowsAppsPath, packageFullName);
            var publisherId = profile.PackageFamilyName[
                (profile.PackageFamilyName.LastIndexOf('_') + 1)..];
            var now = new DateTimeOffset(2026, 8, 1, 12, 0, 0, TimeSpan.Zero);
            var platform = new FakePlatform
            {
                DefaultNowUtc = now,
                PackageIdentity = new CodexAppModelPackageIdentity(
                    packageFullName,
                    profile.PackageFamilyName,
                    profile.PackageName,
                    DefaultPackageVersion,
                    profile.PackagePublisher,
                    publisherId,
                    string.Empty,
                    profile.PackageArchitecture,
                    CodexPackageOrigin.Store),
                FamilyInventory = [new CodexPackageFamilyMember(packageFullName, 0)],
                RegisteredPackagePath = installPath,
                SignerIdentity = new CodexPackageSignerIdentity(
                    profile.PackagePublisher,
                    profile.PackagePublisher,
                    CertificateSha256,
                    SpkiSha256,
                    new string('C', 40),
                    now.AddYears(-1),
                    now.AddYears(1),
                    now),
                CurrentUserSid = "S-1-5-21-1-2-3-1001",
                CurrentSessionId = 7,
                ProcessAlive = true,
                ProcessId = 4242,
                ProcessUserSid = "S-1-5-21-1-2-3-1001",
                ProcessSessionId = 7,
                ProcessPackageFullName = packageFullName,
                ProcessPackageFamilyName = profile.PackageFamilyName,
                ProcessImagePath = Path.Combine(
                    installPath,
                    CodexPackageBaselineVerifier.ChatGptExecutableRelativePath),
                DefaultProcessCreationTimeUtc = now
            };
            platform.Directories[installPath] = new CodexPathObservation(
                installPath,
                installPath,
                FileAttributes.Directory,
                17,
                2);
            platform.AddFile(
                Path.Combine(installPath, CodexPackageBaselineVerifier.ManifestRelativePath),
                manifestBytes,
                101,
                retainContents: true);
            platform.AddFile(
                Path.Combine(installPath, CodexPackageBaselineVerifier.AppxSignatureRelativePath),
                signatureBytes,
                105,
                retainContents: false);
            platform.AddFile(
                Path.Combine(installPath, CodexPackageBaselineVerifier.AppxBlockMapRelativePath),
                blockMapBytes,
                106,
                retainContents: false);
            platform.AddFile(
                Path.Combine(installPath, CodexPackageBaselineVerifier.ChatGptExecutableRelativePath),
                chatBytes,
                102,
                retainContents: false);
            platform.AddFile(
                Path.Combine(installPath, CodexPackageBaselineVerifier.CodexExecutableRelativePath),
                codexBytes,
                103,
                retainContents: false);
            platform.AddFile(
                Path.Combine(installPath, CodexPackageBaselineVerifier.AppAsarRelativePath),
                asarBytes,
                104,
                retainContents: false);
            return new Fixture(profile, platform, windowsAppsPath, installPath, trustMode);
        }

        internal string RetargetObservedPackageVersion(string observedVersion)
        {
            Ensure(!string.IsNullOrWhiteSpace(observedVersion), "the observed version is required");
            var publisherId = Profile.PackageFamilyName[
                (Profile.PackageFamilyName.LastIndexOf('_') + 1)..];
            var observedFullName =
                Profile.PackageName + "_" + observedVersion + "_" +
                Profile.PackageArchitecture + "__" + publisherId;
            var observedInstallPath = Path.Combine(WindowsAppsPath, observedFullName);
            var observedManifestPath = Path.Combine(
                observedInstallPath,
                CodexPackageBaselineVerifier.ManifestRelativePath);
            var observedSignaturePath = Path.Combine(
                observedInstallPath,
                CodexPackageBaselineVerifier.AppxSignatureRelativePath);
            var observedBlockMapPath = Path.Combine(
                observedInstallPath,
                CodexPackageBaselineVerifier.AppxBlockMapRelativePath);
            var observedChatPath = Path.Combine(
                observedInstallPath,
                CodexPackageBaselineVerifier.ChatGptExecutableRelativePath);
            var observedCodexPath = Path.Combine(
                observedInstallPath,
                CodexPackageBaselineVerifier.CodexExecutableRelativePath);
            var observedAppAsarPath = Path.Combine(
                observedInstallPath,
                CodexPackageBaselineVerifier.AppAsarRelativePath);
            if (!Platform.Directories.Remove(InstallPath, out var directory) || directory is null)
            {
                throw new InvalidOperationException("The original package directory fixture was missing.");
            }
            Platform.Directories[observedInstallPath] = directory with
            {
                RequestedPath = observedInstallPath,
                FinalPath = observedInstallPath
            };
            MoveFile(ChatGptExecutablePath, observedChatPath);
            MoveFile(CodexExecutablePath, observedCodexPath);
            MoveFile(AppAsarPath, observedAppAsarPath);
            MoveFile(AppxSignaturePath, observedSignaturePath);
            MoveFile(AppxBlockMapPath, observedBlockMapPath);
            Ensure(
                Platform.Files.Remove(ManifestPath),
                "the original manifest fixture was missing");
            Ensure(
                Platform.FileContents.Remove(ManifestPath),
                "the original manifest content fixture was missing");
            Platform.AddFile(
                observedManifestPath,
                Encoding.UTF8.GetBytes(BuildManifest(Profile, version: observedVersion)),
                fileId: 101,
                retainContents: true);

            Platform.PackageIdentity = Platform.PackageIdentity with
            {
                FullName = observedFullName,
                Version = observedVersion
            };
            Platform.FamilyInventory = [new CodexPackageFamilyMember(observedFullName, 0)];
            Platform.RegisteredPackagePath = observedInstallPath;
            Platform.ProcessPackageFullName = observedFullName;
            Platform.ProcessImagePath = observedChatPath;

            InstallPath = observedInstallPath;
            ManifestPath = observedManifestPath;
            AppxSignaturePath = observedSignaturePath;
            AppxBlockMapPath = observedBlockMapPath;
            ChatGptExecutablePath = observedChatPath;
            CodexExecutablePath = observedCodexPath;
            AppAsarPath = observedAppAsarPath;
            RewriteBlockMap();
            return observedFullName;
        }

        internal void RewriteBlockMap(
            bool corruptFirstHash = false,
            bool includeDtd = false,
            bool duplicateManifest = false,
            bool addInsignificantWhitespace = false)
        {
            Platform.AddFile(
                AppxBlockMapPath,
                BuildBlockMap(
                    Platform.FileContents[ManifestPath],
                    Platform.FileContents[ChatGptExecutablePath],
                    Platform.FileContents[CodexExecutablePath],
                    Platform.FileContents[AppAsarPath],
                    corruptFirstHash,
                    includeDtd,
                    duplicateManifest,
                    addInsignificantWhitespace),
                fileId: 106,
                retainContents: false);
        }

        private void MoveFile(string sourcePath, string destinationPath)
        {
            if (!Platform.Files.Remove(sourcePath, out var file) || file is null)
            {
                throw new InvalidOperationException(
                    "The original artifact fixture was missing: " + sourcePath);
            }
            Platform.Files[destinationPath] = file with
            {
                RequestedPath = destinationPath,
                FinalPath = destinationPath
            };
            if (!Platform.FileContents.Remove(sourcePath, out var contents) || contents is null)
            {
                throw new InvalidOperationException(
                    "The original artifact content fixture was missing: " + sourcePath);
            }

            Platform.FileContents[destinationPath] = contents;
        }

        internal static string BuildManifest(
            CodexCdpRuntimeProfile profile,
            string? publisher = null,
            bool includeDeclaration = true,
            string version = DefaultPackageVersion)
        {
            var declaration = includeDeclaration
                ? "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                : string.Empty;
            return declaration +
                "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\">" +
                "<Identity Name=\"" + profile.PackageName +
                "\" ProcessorArchitecture=\"" + profile.PackageArchitecture +
                "\" Version=\"" + version +
                "\" Publisher=\"" + (publisher ?? profile.PackagePublisher) + "\" />" +
                "<Applications><Application Id=\"App\" Executable=\"app/ChatGPT.exe\" " +
                "EntryPoint=\"Windows.FullTrustApplication\" /></Applications>" +
                "</Package>";
        }

        private static byte[] BuildBlockMap(
            byte[] manifest,
            byte[] chatGpt,
            byte[] codex,
            byte[] appAsar,
            bool corruptFirstHash = false,
            bool includeDtd = false,
            bool duplicateManifest = false,
            bool addInsignificantWhitespace = false)
        {
            var separator = addInsignificantWhitespace ? "\r\n  " : string.Empty;
            var builder = new StringBuilder();
            if (includeDtd)
            {
                builder.Append("<!DOCTYPE BlockMap [<!ENTITY probe \"forbidden\">]>");
            }

            builder.Append(
                "<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" " +
                "HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">");
            builder.Append(separator);
            AppendBlockMapFile(
                builder,
                CodexPackageBaselineVerifier.ManifestRelativePath,
                manifest,
                corruptFirstHash);
            if (duplicateManifest)
            {
                builder.Append(separator);
                AppendBlockMapFile(
                    builder,
                    CodexPackageBaselineVerifier.ManifestRelativePath,
                    manifest,
                    corruptFirstHash: false);
            }

            builder.Append(separator);
            AppendBlockMapFile(
                builder,
                CodexPackageBaselineVerifier.ChatGptExecutableRelativePath,
                chatGpt,
                corruptFirstHash: false);
            builder.Append(separator);
            AppendBlockMapFile(
                builder,
                CodexPackageBaselineVerifier.CodexExecutableRelativePath,
                codex,
                corruptFirstHash: false);
            builder.Append(separator);
            AppendBlockMapFile(
                builder,
                CodexPackageBaselineVerifier.AppAsarRelativePath,
                appAsar,
                corruptFirstHash: false);
            builder.Append(addInsignificantWhitespace ? "\r\n" : string.Empty);
            builder.Append("</BlockMap>");
            return Encoding.UTF8.GetBytes(builder.ToString());
        }

        private static void AppendBlockMapFile(
            StringBuilder builder,
            string relativePath,
            byte[] contents,
            bool corruptFirstHash)
        {
            builder.Append("<File Name=\"");
            builder.Append(relativePath);
            builder.Append("\" Size=\"");
            builder.Append(contents.LongLength.ToString(CultureInfo.InvariantCulture));
            builder.Append("\" LfhSize=\"0\">");
            var blockIndex = 0;
            for (var offset = 0; offset < contents.Length; offset += 64 * 1024)
            {
                var length = Math.Min(64 * 1024, contents.Length - offset);
                var hash = Convert.ToBase64String(SHA256.HashData(
                    contents.AsSpan(offset, length)));
                if (corruptFirstHash && blockIndex == 0)
                {
                    hash = (hash[0] == 'A' ? 'B' : 'A') + hash[1..];
                }

                builder.Append("<Block Hash=\"");
                builder.Append(hash);
                builder.Append("\" />");
                blockIndex++;
            }

            builder.Append("</File>");
        }

        private static string BuildPackageFullName(
            CodexCdpRuntimeProfile profile,
            string version)
        {
            var publisherId = profile.PackageFamilyName[
                (profile.PackageFamilyName.LastIndexOf('_') + 1)..];
            return profile.PackageName + "_" + version + "_" +
                profile.PackageArchitecture + "__" + publisherId;
        }
    }

    private sealed class FakePlatform : ICodexPackageBaselinePlatform
    {
        internal DateTimeOffset DefaultNowUtc { get; set; }

        internal Queue<DateTimeOffset> UtcNowValues { get; } = new();

        internal required CodexAppModelPackageIdentity PackageIdentity { get; set; }

        internal required IReadOnlyList<CodexPackageFamilyMember> FamilyInventory { get; set; }

        internal List<string> IdentityFullNameRequests { get; } = [];

        internal List<string> PackagePathFullNameRequests { get; } = [];

        internal List<string> FamilyNameRequests { get; } = [];

        internal List<string> RegistrationReadOrder { get; } = [];

        internal required string RegisteredPackagePath { get; set; }

        internal required CodexPackageSignerIdentity SignerIdentity { get; set; }

        internal Dictionary<string, CodexPathObservation> Directories { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal List<string> InspectedDirectories { get; } = new();

        internal Dictionary<string, CodexPinnedFileObservation> Files { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal Dictionary<string, byte[]> FileContents { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal Dictionary<string, long> MaximumBytesSeen { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal HashSet<string> CaptureContentsSeen { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal HashSet<string> BlockHashesSeen { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal required string CurrentUserSid { get; set; }

        internal uint CurrentSessionId { get; set; }

        internal bool ProcessAlive { get; set; }

        internal uint ProcessId { get; set; }

        internal required string ProcessUserSid { get; set; }

        internal uint ProcessSessionId { get; set; }

        internal required string ProcessPackageFullName { get; set; }

        internal required string ProcessPackageFamilyName { get; set; }

        internal required string ProcessImagePath { get; set; }

        internal DateTimeOffset DefaultProcessCreationTimeUtc { get; set; }

        internal Queue<DateTimeOffset> ProcessCreationTimes { get; } = new();

        public DateTimeOffset UtcNow => UtcNowValues.Count > 0
            ? UtcNowValues.Dequeue()
            : DefaultNowUtc;

        public CodexAppModelPackageIdentity ReadRegisteredPackageIdentity(string packageFullName)
        {
            RegistrationReadOrder.Add("identity");
            IdentityFullNameRequests.Add(packageFullName);
            return PackageIdentity;
        }

        public IReadOnlyList<CodexPackageFamilyMember> ReadCurrentUserPackageFamilyInventory(
            string packageFamilyName)
        {
            RegistrationReadOrder.Add("family");
            FamilyNameRequests.Add(packageFamilyName);
            return FamilyInventory;
        }

        public string ReadRegisteredPackagePath(string packageFullName)
        {
            RegistrationReadOrder.Add("path");
            PackagePathFullNameRequests.Add(packageFullName);
            return RegisteredPackagePath;
        }

        public CodexPathObservation InspectDirectory(string path)
        {
            InspectedDirectories.Add(path);
            return Directories.TryGetValue(path, out var observation)
                ? observation
                : throw new DirectoryNotFoundException(path);
        }

        public CodexPinnedFileObservation ReadAndHashRegularFile(
            string path,
            long maximumBytes,
            bool captureContents)
        {
            if (!Files.TryGetValue(path, out var observation))
            {
                throw new FileNotFoundException(path);
            }

            Ensure(observation.Length <= maximumBytes, "the verifier supplied an invalid file bound");
            MaximumBytesSeen[path] = maximumBytes;
            if (captureContents)
            {
                CaptureContentsSeen.Add(path);
            }

            byte[]? contents = null;
            if (captureContents)
            {
                if (!FileContents.TryGetValue(path, out var retainedContents))
                {
                    throw new FileNotFoundException(path);
                }

                contents = retainedContents.ToArray();
            }

            return observation with
            {
                Contents = contents
            };
        }

        public CodexBlockMappedFileObservation ReadAndHashBlockMappedRegularFile(
            string path,
            long maximumBytes,
            bool captureContents)
        {
            var file = ReadAndHashRegularFile(path, maximumBytes, captureContents);
            if (!FileContents.TryGetValue(path, out var contents))
            {
                throw new FileNotFoundException(path);
            }

            BlockHashesSeen.Add(path);
            var blocks = new List<string>();
            for (var offset = 0; offset < contents.Length; offset += CodexAppxBlockMapVerifier.BlockSizeBytes)
            {
                var length = Math.Min(
                    CodexAppxBlockMapVerifier.BlockSizeBytes,
                    contents.Length - offset);
                blocks.Add(Convert.ToBase64String(SHA256.HashData(
                    contents.AsSpan(offset, length))));
            }

            return new CodexBlockMappedFileObservation(
                file,
                Array.AsReadOnly(blocks.ToArray()));
        }

        public CodexInspectedAsarObservation ReadAndInspectAppAsar(
            string path,
            long maximumBytes,
            CodexAsarCapabilityPolicy policy)
        {
            ArgumentNullException.ThrowIfNull(policy);
            var file = ReadAndHashBlockMappedRegularFile(
                path,
                maximumBytes,
                captureContents: false);
            if (!FileContents.TryGetValue(path, out var contents))
            {
                throw new FileNotFoundException(path);
            }

            var capabilities = CodexAsarCapabilityInspector.Inspect(
                new ByteArrayAsarSource(contents),
                policy);
            return new CodexInspectedAsarObservation(file, capabilities);
        }

        public CodexVerifiedPackageSignatureObservation ReadAndVerifyPackageSignature(
            string path,
            long maximumBytes) =>
            new(
                ReadAndHashRegularFile(path, maximumBytes, captureContents: false),
                SignerIdentity);

        public string ReadCurrentUserSid() => CurrentUserSid;

        public uint ReadCurrentSessionId() => CurrentSessionId;

        public bool IsRetainedProcessAlive(SafeProcessHandle processHandle) => ProcessAlive;

        public uint ReadRetainedProcessId(SafeProcessHandle processHandle) => ProcessId;

        public string ReadProcessUserSid(SafeProcessHandle processHandle) => ProcessUserSid;

        public uint ReadProcessSessionId(uint processId) => ProcessSessionId;

        public string ReadProcessPackageFullName(SafeProcessHandle processHandle) =>
            ProcessPackageFullName;

        public string ReadProcessPackageFamilyName(SafeProcessHandle processHandle) =>
            ProcessPackageFamilyName;

        public string ReadProcessImagePath(SafeProcessHandle processHandle) => ProcessImagePath;

        public DateTimeOffset ReadProcessCreationTimeUtc(SafeProcessHandle processHandle) =>
            ProcessCreationTimes.Count > 0
                ? ProcessCreationTimes.Dequeue()
                : DefaultProcessCreationTimeUtc;

        internal void AddFile(
            string path,
            byte[] contents,
            ulong fileId,
            bool retainContents)
        {
            FileContents[path] = contents.ToArray();
            Files[path] = new CodexPinnedFileObservation(
                path,
                path,
                FileAttributes.Archive,
                contents.LongLength,
                Convert.ToHexString(SHA256.HashData(contents)),
                17,
                fileId,
                retainContents ? contents.ToArray() : null);
        }

        private sealed class ByteArrayAsarSource(byte[] bytes) : ICodexAsarRandomAccessSource
        {
            private readonly byte[] _bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));

            public long Length => _bytes.LongLength;

            public void ReadExactly(long offset, Span<byte> destination)
            {
                if (offset < 0 || offset > _bytes.LongLength - destination.Length)
                {
                    throw new EndOfStreamException("The synthetic ASAR fixture was truncated.");
                }

                _bytes.AsSpan(checked((int)offset), destination.Length).CopyTo(destination);
            }
        }
    }
}
