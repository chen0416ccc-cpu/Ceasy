using CodexGuardian.Trust;
using System.Diagnostics;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

internal static class VerifiedLocalReleaseManifestOfflineTests
{
    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        if (!OperatingSystem.IsWindows())
        {
            assert(true, "verified local release manifest tests are Windows-only");
            return Task.CompletedTask;
        }

        RunCase(
            "verified local release factory publishes one exact retained dual-role lease",
            TestSuccessfulLease,
            assert);
        RunCase(
            "verified local release lease moves ownership and leaves source aliases inert",
            TestLeaseOwnershipMove,
            assert);
        RunCase(
            "verified local release peer authority stays lease-backed without exposing master handles",
            TestPeerAuthoritySurface,
            assert);
        RunCase(
            "verified local release factory rejects a coherent Guardian-only formal runtime",
            TestGuardianOnlyRejected,
            assert);
        RunCase(
            "verified local release factory rejects journal and transient exchange state read-only",
            TestUnsettledWorkspaceRejected,
            assert);
        RunCase(
            "verified local release factory rejects noncanonical and unsupported commit bytes",
            TestStrictCommitRejected,
            assert);
        RunCase(
            "verified local release factory rejects impossible committed tree bounds before scanning",
            TestCommittedTreeBoundsRejected,
            assert);
        RunCase(
            "verified local release factory applies committed tree and file budgets before hashing drift",
            TestCommittedArtifactBudgets,
            assert);
        RunCase(
            "verified local release factory rejects committed runtime and source tree drift",
            TestTreeDriftRejected,
            assert);
        RunCase(
            "verified local release tree capture enforces discovery and pre-hash byte bounds",
            TestTreeCaptureOperationalBounds,
            assert);
        RunCase(
            "verified local release factory rejects archive and checksum coherence drift",
            TestArchiveAndChecksumRejected,
            assert);
        RunCase(
            "verified local release factory bounds raw ZIP metadata before archive materialization",
            TestCanonicalArchivePreflightRejected,
            assert);
        RunCase(
            "verified local release factory requires Trust in both fixed role directories",
            TestRoleDependencyRejected,
            assert);
        RunCase(
            "verified local release factory requires exact closed runtimeconfig.dev bytes",
            TestRuntimeConfigDevRejected,
            assert);
        RunCase(
            "verified local release factory rejects hard-linked runtime files without leaking handles",
            TestRuntimeHardLinkRejected,
            assert);
        RunCase(
            "verified local release production overload refuses an arbitrary build directory",
            TestProductionRootRejected,
            assert);
        return Task.CompletedTask;
    }

    private static void TestSuccessfulLease()
    {
        using var fixture = ReleaseFixture.Create(includeBroker: true);
        var expectedCommitHash = ComputeSha256(fixture.CommitPath);
        var brokerManagedEntry = Path.Combine(
            fixture.RuntimeRoot,
            "Broker",
            "CodexGuardian.Broker.dll");
        var committedRuntimeFiles = Directory.EnumerateFiles(
                fixture.RuntimeRoot,
                "*",
                SearchOption.AllDirectories)
            .Select(path => new WindowsRetainedReleaseTreeFileV1(
                Path.GetRelativePath(fixture.RuntimeRoot, path).Replace('\\', '/'),
                new FileInfo(path).Length,
                ComputeSha256(path)))
            .OrderBy(file => file.RelativePath, StringComparer.Ordinal)
            .ToArray();
        VerifiedLocalReleaseLeaseV1? lease = null;
        try
        {
            lease = WindowsVerifiedLocalReleaseManifestFactory
                .OpenFromOutputsRootForTests(fixture.Root);
            Ensure(
                lease.Commit.GenerationId == ReleaseFixture.GenerationId &&
                lease.Commit.CommitSha256 == expectedCommitHash &&
                lease.Manifest.ReleaseId == ReleaseFixture.GenerationId &&
                lease.Manifest.ManifestSha256 == expectedCommitHash,
                "the verified lease did not bind the exact formal commit bytes");
            var guardian = lease.GetRelease(BrokerPeerRole.Guardian);
            var broker = lease.GetRelease(BrokerPeerRole.Broker);
            Ensure(
                guardian.AppHostRelativePath == "CodexGuardian.exe" &&
                broker.AppHostRelativePath == Path.Combine("Broker", "CodexGuardian.Broker.exe") &&
                guardian.Artifacts.Count == 8 &&
                broker.Artifacts.Count == 8 &&
                guardian.Artifacts.Any(artifact =>
                    artifact.Kind == ReleaseArtifactKind.RuntimeDependency &&
                    artifact.RelativePath == "CodexGuardian.runtimeconfig.dev.json") &&
                broker.Artifacts.Any(artifact =>
                    artifact.Kind == ReleaseArtifactKind.RuntimeDependency &&
                    artifact.RelativePath ==
                        Path.Combine("Broker", "CodexGuardian.Broker.runtimeconfig.dev.json")),
                "the verified lease did not publish the fixed dual-role artifact plan");
            Ensure(
                lease.GetRetainedArtifacts(BrokerPeerRole.Guardian).Artifacts.Count == 8 &&
                lease.GetRetainedArtifacts(BrokerPeerRole.Broker).Artifacts.Count == 8,
                "the verified lease lost its retained native artifact owners");
            var retainedRuntimeFiles = lease.GetRetainedRuntimeFiles()
                .OrderBy(file => file.RelativePath, StringComparer.Ordinal)
                .ToArray();
            Ensure(
                retainedRuntimeFiles.SequenceEqual(committedRuntimeFiles) &&
                retainedRuntimeFiles.LongLength == lease.Commit.RuntimeFileCount,
                "the verified lease did not retain the entire committed runtime tree");
            Ensure(
                IsExclusiveOpenBlocked(fixture.LockPath) &&
                IsExclusiveOpenBlocked(fixture.CommitPath) &&
                IsWriteBlocked(brokerManagedEntry) &&
                IsWriteBlocked(fixture.GuardianRuntimeConfigDevPath) &&
                IsDeleteBlocked(fixture.GuardianRuntimeConfigDevPath) &&
                IsMoveBlocked(fixture.GuardianRuntimeConfigDevPath) &&
                IsWriteBlocked(fixture.BrokerRuntimeConfigDevPath) &&
                IsDeleteBlocked(fixture.BrokerRuntimeConfigDevPath) &&
                IsMoveBlocked(fixture.BrokerRuntimeConfigDevPath) &&
                IsWriteBlocked(fixture.UnlistedRuntimeDependencyPath) &&
                IsDeleteBlocked(fixture.UnlistedRuntimeDependencyPath) &&
                IsMoveBlocked(fixture.UnlistedRuntimeDependencyPath),
                "the verified lease did not retain its lock commit and complete runtime tree");
        }
        finally
        {
            lease?.Dispose();
        }

        Ensure(
            CanOpenExclusive(fixture.LockPath) &&
            CanOpenExclusive(fixture.CommitPath) &&
            CanMoveRoundTrip(fixture.GuardianRuntimeConfigDevPath) &&
            CanMoveRoundTrip(fixture.BrokerRuntimeConfigDevPath) &&
            CanMoveRoundTrip(fixture.UnlistedRuntimeDependencyPath) &&
            CanAppend(brokerManagedEntry) &&
            CanAppend(fixture.UnlistedRuntimeDependencyPath),
            "verified local release disposal did not release ownership in reverse order");
    }

    private static void TestGuardianOnlyRejected()
    {
        using var fixture = ReleaseFixture.Create(includeBroker: false);
        ExpectCode(
            fixture,
            "release-broker-runtime-missing",
            "a coherent Guardian-only release unexpectedly became a production peer manifest");
    }

    private static void TestRuntimeConfigDevRejected()
    {
        ExpectMutation(
            fixture => File.Delete(fixture.GuardianRuntimeConfigDevPath),
            "release-guardian-runtime-missing",
            "a coherent runtime without the Guardian dev config was accepted");
        ExpectMutation(
            fixture => File.Delete(fixture.BrokerRuntimeConfigDevPath),
            "release-broker-runtime-missing",
            "a coherent runtime without the Broker dev config was accepted");
        ExpectMutation(
            fixture => File.WriteAllText(
                fixture.GuardianRuntimeConfigDevPath,
                "{\"runtimeOptions\":{\"additionalProbingPaths\":[\"D:\\\\untrusted\"]}}\r\n",
                StrictUtf8),
            "release-runtime-config-dev-invalid",
            "a coherent runtime with an added probing path was accepted");
        ExpectMutation(
            fixture => File.WriteAllText(
                fixture.BrokerRuntimeConfigDevPath,
                "{\"runtimeOptions\":{}}\n",
                StrictUtf8),
            "release-runtime-config-dev-invalid",
            "a coherent runtime with noncanonical dev-config line endings was accepted");

        static void ExpectMutation(
            Action<ReleaseFixture> mutation,
            string expectedCode,
            string message)
        {
            using var fixture = ReleaseFixture.Create(includeBroker: true);
            mutation(fixture);
            fixture.WriteRuntimeArchiveFrom(fixture.RuntimeRoot);
            fixture.RewriteChecksum();
            fixture.RewriteCommit();
            ExpectCode(fixture, expectedCode, message);
        }
    }

    private static void TestLeaseOwnershipMove()
    {
        using var fixture = ReleaseFixture.Create(includeBroker: true);
        var source = WindowsVerifiedLocalReleaseManifestFactory
            .OpenFromOutputsRootForTests(fixture.Root);
        var successor = source.TakeOwnership();
        try
        {
            source.Dispose();
            Expect<ObjectDisposedException>(() => source.GetRelease(BrokerPeerRole.Guardian));
            Expect<ObjectDisposedException>(() => source.TakeOwnership());
            Ensure(
                IsExclusiveOpenBlocked(fixture.LockPath) &&
                IsExclusiveOpenBlocked(fixture.CommitPath) &&
                IsWriteBlocked(fixture.UnlistedRuntimeDependencyPath),
                "disposing the moved source alias released successor-owned authority");
        }
        finally
        {
            successor.Dispose();
        }

        Ensure(
            CanOpenExclusive(fixture.LockPath) &&
            CanOpenExclusive(fixture.CommitPath) &&
            CanAppend(fixture.UnlistedRuntimeDependencyPath),
            "disposing the successor did not release moved authority exactly once");
    }

    private static void TestPeerAuthoritySurface()
    {
        var authorityType = typeof(WindowsVerifiedLocalReleasePeerAuthorityV1);
        var publicMethods = authorityType.GetMethods(
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.Static |
                System.Reflection.BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName)
            .ToArray();
        Ensure(
            authorityType.IsPublic && authorityType.IsAbstract && authorityType.IsSealed &&
            publicMethods.Select(method => method.Name).OrderBy(name => name, StringComparer.Ordinal)
                .SequenceEqual(new[]
                {
                    "ConnectToLaunchedBrokerServer",
                    "OpenRetainedProcess",
                    "TakeConnectedGuardianClient"
                }) &&
            publicMethods.All(method =>
                method.ReturnType != typeof(WindowsRetainedReleaseArtifacts) &&
                method.GetParameters().All(parameter =>
                    parameter.ParameterType != typeof(WindowsRetainedReleaseArtifacts))),
            "the release peer authority exposed a retained master artifact alias");

        using var fixture = ReleaseFixture.Create(includeBroker: true);
        var source = WindowsVerifiedLocalReleaseManifestFactory
            .OpenFromOutputsRootForTests(fixture.Root);
        var successor = source.TakeOwnership();
        using var current = Process.GetCurrentProcess();
        try
        {
            source.Dispose();
            Expect<ObjectDisposedException>(() =>
                WindowsVerifiedLocalReleasePeerAuthorityV1.OpenRetainedProcess(
                    source,
                    BrokerPeerRole.Guardian,
                    current.SafeHandle));
            BrokerPeerTrustException? mismatch = null;
            try
            {
                WindowsVerifiedLocalReleasePeerAuthorityV1.OpenRetainedProcess(
                    successor,
                    BrokerPeerRole.Guardian,
                    current.SafeHandle);
            }
            catch (BrokerPeerTrustException exception)
            {
                mismatch = exception;
            }
            Ensure(
                mismatch?.Code == "peer-image-mapping-mismatch",
                "the peer authority did not compare against the lease-retained apphost object");
        }
        finally
        {
            successor.Dispose();
        }

        Expect<ObjectDisposedException>(() =>
            WindowsVerifiedLocalReleasePeerAuthorityV1.OpenRetainedProcess(
                successor,
                BrokerPeerRole.Guardian,
                current.SafeHandle));
    }

    private static void TestUnsettledWorkspaceRejected()
    {
        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            File.WriteAllText(fixture.JournalPath, "{}", StrictUtf8);
            ExpectCode(
                fixture,
                "release-transaction-in-progress",
                "a release journal was treated as an alternate read authority");
            Ensure(File.Exists(fixture.JournalPath), "the read-only factory removed the release journal");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            var transient = Path.Combine(fixture.Root, "CodexGuardian-win-x64.next");
            Directory.CreateDirectory(transient);
            ExpectCode(
                fixture,
                "release-workspace-unsettled",
                "a next-generation directory was ignored");
            Ensure(Directory.Exists(transient), "the read-only factory removed transient state");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            var pending = Path.Combine(
                fixture.Root,
                ".CODEXGUARDIAN-RELEASE-MANIFEST.PENDING." + ReleaseFixture.GenerationId + ".JSON");
            File.WriteAllText(pending, "{}", StrictUtf8);
            ExpectCode(
                fixture,
                "release-workspace-unsettled",
                "case-variant pending state was ignored");
        }
    }

    private static void TestStrictCommitRejected()
    {
        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            var original = File.ReadAllBytes(fixture.CommitPath);
            File.WriteAllBytes(fixture.CommitPath, new byte[] { 0xEF, 0xBB, 0xBF }.Concat(original).ToArray());
            ExpectCode(
                fixture,
                "release-commit-invalid",
                "a BOM-prefixed release commit was accepted");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            var text = File.ReadAllText(fixture.CommitPath, StrictUtf8);
            File.WriteAllText(
                fixture.CommitPath,
                text.Replace("{\"marker\"", "{\"extra\":1,\"marker\"", StringComparison.Ordinal),
                StrictUtf8);
            ExpectCode(
                fixture,
                "release-commit-invalid",
                "a release commit with an extra property was accepted");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            var text = File.ReadAllText(fixture.CommitPath, StrictUtf8);
            File.WriteAllText(
                fixture.CommitPath,
                text.Replace("{\"marker\"", "{ \"marker\"", StringComparison.Ordinal),
                StrictUtf8);
            ExpectCode(
                fixture,
                "release-commit-noncanonical",
                "a semantically equivalent noncanonical release commit was accepted");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            fixture.RewriteCommit(projectVersion: "2.0.1");
            ExpectCode(
                fixture,
                "release-commit-unsupported",
                "an unsupported product release version was accepted as the current commit schema");
        }
    }

    private static void TestTreeDriftRejected()
    {
        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            MutateFirstByteWithoutChangingLength(
                Path.Combine(fixture.RuntimeRoot, "CodexGuardian.Control.dll"));
            ExpectCode(
                fixture,
                "release-runtime-identity-mismatch",
                "runtime tree drift was ignored");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            MutateFirstByteWithoutChangingLength(
                Path.Combine(fixture.SourceRoot, "src", "guardian.cs"));
            ExpectCode(
                fixture,
                "release-source-identity-mismatch",
                "source tree drift was ignored");
        }
    }

    private static void TestCommittedTreeBoundsRejected()
    {
        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            fixture.RewriteCommit(runtimeFileCountOverride: 4097);
            using var blockedRuntime = new FileStream(
                fixture.UnlistedRuntimeDependencyPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);
            ExpectCode(
                fixture,
                "release-commit-invalid",
                "an impossible committed runtime file count reached disk scanning");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            fixture.RewriteCommit(sourceTotalBytesOverride: 2L * 1024 * 1024 * 1024 + 1);
            using var blockedRuntime = new FileStream(
                fixture.UnlistedRuntimeDependencyPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);
            ExpectCode(
                fixture,
                "release-commit-invalid",
                "an impossible committed source byte count reached disk scanning");
        }
    }

    private static void TestTreeCaptureOperationalBounds()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "CodexGuardian-release-tree-bounds-" + Guid.NewGuid().ToString("N"));
        try
        {
            var directoryRoot = Path.Combine(root, "directories");
            Directory.CreateDirectory(directoryRoot);
            var firstDirectory = Directory.CreateDirectory(Path.Combine(directoryRoot, "first"));
            var secondDirectory = Directory.CreateDirectory(Path.Combine(directoryRoot, "second"));
            var enumeratedPastBound = false;

            IEnumerable<FileSystemInfo> EnumerateWithTripwire(string directory)
            {
                if (!string.Equals(
                        Path.GetFullPath(directory),
                        Path.GetFullPath(directoryRoot),
                        StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var child in new DirectoryInfo(directory).EnumerateFileSystemInfos())
                    {
                        yield return child;
                    }

                    yield break;
                }

                yield return firstDirectory;
                yield return secondDirectory;
                enumeratedPastBound = true;
                throw new InvalidOperationException("directory enumeration crossed its discovery bound");
            }

            var directoryFailure = ExpectCode(
                () => WindowsVerifiedLocalReleaseManifestFactory.CaptureTreeSnapshotForTests(
                    directoryRoot,
                    maximumFiles: 1,
                    maximumDirectories: 2,
                    maximumTreeBytes: 1,
                    maximumSingleFileBytes: 1,
                    enumerateDirectory: EnumerateWithTripwire),
                "release-tree-test-invalid",
                "tree capture enumerated sibling entries after its directory bound");
            Ensure(
                directoryFailure.Message.Contains("directory bound", StringComparison.Ordinal) &&
                !enumeratedPastBound,
                "tree capture materialized sibling entries before enforcing its directory bound");

            var byteRoot = Path.Combine(root, "bytes");
            Directory.CreateDirectory(byteRoot);
            var firstFile = Path.Combine(byteRoot, "a.bin");
            var secondFile = Path.Combine(byteRoot, "b.bin");
            File.WriteAllBytes(firstFile, new byte[8]);
            File.WriteAllBytes(secondFile, new byte[8]);
            var firstFileInfo = new FileInfo(firstFile);
            var secondFileInfo = new FileInfo(secondFile);
            var enumeratedFilesPastBound = false;

            IEnumerable<FileSystemInfo> EnumerateFilesWithTripwire(string directory)
            {
                yield return firstFileInfo;
                yield return secondFileInfo;
                enumeratedFilesPastBound = true;
                throw new InvalidOperationException("file enumeration crossed its discovery bound");
            }

            var fileCountFailure = ExpectCode(
                () => WindowsVerifiedLocalReleaseManifestFactory.CaptureTreeSnapshotForTests(
                    byteRoot,
                    maximumFiles: 1,
                    maximumDirectories: 1,
                    maximumTreeBytes: 8,
                    maximumSingleFileBytes: 8,
                    enumerateDirectory: EnumerateFilesWithTripwire),
                "release-tree-test-invalid",
                "tree capture enumerated sibling files after its file-count bound");
            Ensure(
                fileCountFailure.Message.Contains("file-count bound", StringComparison.Ordinal) &&
                !enumeratedFilesPastBound,
                "tree capture materialized sibling files before enforcing its file-count bound");

            var hashStarts = new List<string>();
            _ = ExpectCode(
                () => WindowsVerifiedLocalReleaseManifestFactory.CaptureTreeSnapshotForTests(
                    byteRoot,
                    maximumFiles: 2,
                    maximumDirectories: 1,
                    maximumTreeBytes: 8,
                    maximumSingleFileBytes: 8,
                    hashStarted: path => hashStarts.Add(path)),
                "release-tree-test-invalid",
                "tree capture hashed a file after exhausting its total-byte budget");
            Ensure(
                hashStarts.Count == 1,
                "tree capture did not reject the over-budget file before SHA-256 hashing");

            var captured = WindowsVerifiedLocalReleaseManifestFactory.CaptureTreeSnapshotForTests(
                    byteRoot,
                    maximumFiles: 2,
                    maximumDirectories: 1,
                    maximumTreeBytes: 16,
                    maximumSingleFileBytes: 8)
                .OrderBy(file => file.RelativePath, StringComparer.Ordinal)
                .ToArray();
            var expected = new[]
                {
                    new WindowsRetainedReleaseTreeFileV1("a.bin", 8, ComputeSha256(firstFile)),
                    new WindowsRetainedReleaseTreeFileV1("b.bin", 8, ComputeSha256(secondFile))
                }
                .OrderBy(file => file.RelativePath, StringComparer.Ordinal)
                .ToArray();
            Ensure(
                captured.SequenceEqual(expected),
                "bounded tree capture lost exact path, length, or SHA-256 metadata");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void TestCommittedArtifactBudgets()
    {
        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            File.AppendAllText(
                fixture.UnlistedRuntimeDependencyPath,
                "runtime-over-committed-budget",
                StrictUtf8);
            var failure = ExpectCode(
                () => WindowsVerifiedLocalReleaseManifestFactory
                    .OpenFromOutputsRootForTests(fixture.Root).Dispose(),
                "release-runtime-invalid",
                "runtime drift was hashed under the global budget instead of the committed budget");
            Ensure(
                failure.Message.Contains("byte bound", StringComparison.Ordinal),
                "runtime drift did not fail at the committed pre-hash byte budget");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            File.AppendAllText(
                Path.Combine(fixture.SourceRoot, "src", "guardian.cs"),
                "source-over-committed-budget",
                StrictUtf8);
            var failure = ExpectCode(
                () => WindowsVerifiedLocalReleaseManifestFactory
                    .OpenFromOutputsRootForTests(fixture.Root).Dispose(),
                "release-source-invalid",
                "source drift was hashed under the global budget instead of the committed budget");
            Ensure(
                failure.Message.Contains("byte bound", StringComparison.Ordinal),
                "source drift did not fail at the committed pre-hash byte budget");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            using (var stream = new FileStream(
                       fixture.RuntimeZipPath,
                       FileMode.Append,
                       FileAccess.Write,
                       FileShare.None))
            {
                stream.WriteByte(0x5A);
            }
            var failure = ExpectCode(
                () => WindowsVerifiedLocalReleaseManifestFactory
                    .OpenFromOutputsRootForTests(fixture.Root).Dispose(),
                "release-runtime-zip-invalid",
                "runtime ZIP drift was hashed under the global archive budget");
            Ensure(
                failure.Message.Contains("byte bound", StringComparison.Ordinal),
                "runtime ZIP drift did not fail at the committed pre-hash length budget");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            fixture.RewriteCommit(runtimeZipLengthOverride: 0);
            using var blockedRuntime = new FileStream(
                fixture.UnlistedRuntimeDependencyPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);
            ExpectCode(
                fixture,
                "release-commit-invalid",
                "an invalid committed runtime ZIP length reached tree scanning");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            fixture.RewriteCommit(sourceZipLengthOverride: 1024L * 1024 * 1024 + 1);
            using var blockedRuntime = new FileStream(
                fixture.UnlistedRuntimeDependencyPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);
            ExpectCode(
                fixture,
                "release-commit-invalid",
                "an oversized committed source ZIP length reached tree scanning");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            fixture.RewriteCommit(checksumLengthOverride: 64L * 1024 + 1);
            using var blockedRuntime = new FileStream(
                fixture.UnlistedRuntimeDependencyPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);
            ExpectCode(
                fixture,
                "release-commit-invalid",
                "an oversized committed checksum length reached tree scanning");
        }
    }

    private static void TestArchiveAndChecksumRejected()
    {
        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            fixture.WriteRuntimeArchiveFrom(fixture.SourceRoot);
            fixture.RewriteChecksum();
            fixture.RewriteCommit();
            ExpectCode(
                fixture,
                "release-runtime-archive-mismatch",
                "a commit-consistent runtime ZIP with source-tree contents was accepted");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            File.WriteAllText(fixture.ChecksumPath, "not-the-two-committed-archives\r\n", StrictUtf8);
            fixture.RewriteCommit();
            ExpectCode(
                fixture,
                "release-checksum-mismatch",
                "a commit-consistent but semantically invalid checksum file was accepted");
        }
    }

    private static void TestCanonicalArchivePreflightRejected()
    {
        ExpectRawArchiveFailure(
            sourceArchive: false,
            static (_, layout) =>
            {
                var raw = CreateEndRecord(layout.EntryCount);
                BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(8, 2), 4097);
                BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(10, 2), 4097);
                return raw;
            },
            "entry count",
            "an over-limit raw ZIP entry count reached central-directory materialization");
        ExpectRawArchiveFailure(
            sourceArchive: true,
            static (_, layout) =>
            {
                var raw = CreateEndRecord(layout.EntryCount);
                BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(10, 2), ushort.MaxValue);
                return raw;
            },
            "ZIP64",
            "a raw ZIP64 sentinel was accepted");
        ExpectRawArchiveFailure(
            sourceArchive: false,
            static (_, layout) =>
            {
                var raw = CreateEndRecord(layout.EntryCount);
                BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(4, 2), 1);
                return raw;
            },
            "multiple disks",
            "a raw multi-disk ZIP record was accepted");
        ExpectRawArchiveFailure(
            sourceArchive: true,
            static (_, layout) =>
            {
                var raw = CreateEndRecord(layout.EntryCount);
                BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(12, 4), 16_965_633);
                return raw;
            },
            "central directory byte bound",
            "an oversized raw central directory reached archive materialization");
        ExpectRawArchiveFailure(
            sourceArchive: false,
            static (bytes, layout) =>
            {
                BinaryPrimitives.WriteUInt16LittleEndian(
                    bytes.AsSpan(layout.CentralHeaderOffset + 28, 2),
                    4097);
                return bytes;
            },
            "name exceeds its byte bound",
            "an over-limit raw central-directory name was accepted");
        ExpectRawArchiveFailure(
            sourceArchive: true,
            static (bytes, layout) =>
            {
                BinaryPrimitives.WriteUInt16LittleEndian(
                    bytes.AsSpan(layout.CentralHeaderOffset + 30, 2),
                    1);
                return bytes;
            },
            "variable entry metadata",
            "raw variable central-directory metadata was accepted");
        ExpectRawArchiveFailure(
            sourceArchive: false,
            static (bytes, layout) =>
            {
                BinaryPrimitives.WriteUInt16LittleEndian(
                    bytes.AsSpan(layout.CentralHeaderOffset + 8, 2),
                    0x0008);
                return bytes;
            },
            "flags",
            "raw data-descriptor flags were accepted");
        ExpectRawArchiveFailure(
            sourceArchive: true,
            static (bytes, layout) =>
            {
                var centralSize = BinaryPrimitives.ReadUInt32LittleEndian(
                    bytes.AsSpan(layout.EndRecordOffset + 12, 4));
                BinaryPrimitives.WriteUInt32LittleEndian(
                    bytes.AsSpan(layout.EndRecordOffset + 12, 4),
                    checked(centralSize - 1));
                return bytes;
            },
            "central directory extent",
            "a malformed raw central-directory extent was accepted");
        ExpectRawArchiveFailure(
            sourceArchive: false,
            static (bytes, layout) =>
            {
                var crc32 = BinaryPrimitives.ReadUInt32LittleEndian(
                    bytes.AsSpan(layout.LocalHeaderOffset + 14, 4));
                BinaryPrimitives.WriteUInt32LittleEndian(
                    bytes.AsSpan(layout.LocalHeaderOffset + 14, 4),
                    crc32 ^ 1);
                return bytes;
            },
            "local-header layout",
            "a raw local-header identity mismatch was accepted");
        ExpectRawArchiveFailure(
            sourceArchive: true,
            static (bytes, layout) =>
            {
                var secondLocalOffset = BinaryPrimitives.ReadUInt32LittleEndian(
                    bytes.AsSpan(layout.SecondCentralHeaderOffset + 42, 4));
                BinaryPrimitives.WriteUInt32LittleEndian(
                    bytes.AsSpan(layout.SecondCentralHeaderOffset + 42, 4),
                    checked(secondLocalOffset + 1));
                return bytes;
            },
            "local-header layout",
            "a raw gap between local entries was accepted");
    }

    private static void ExpectRawArchiveFailure(
        bool sourceArchive,
        Func<byte[], RawZipLayout, byte[]> mutate,
        string expectedMessageFragment,
        string assertionMessage)
    {
        using var fixture = ReleaseFixture.Create(includeBroker: true);
        var archivePath = sourceArchive ? fixture.SourceZipPath : fixture.RuntimeZipPath;
        var bytes = File.ReadAllBytes(archivePath);
        var layout = ReadRawZipLayout(bytes);
        var malformed = mutate(bytes, layout);
        File.WriteAllBytes(archivePath, malformed);
        fixture.RewriteChecksum();
        fixture.RewriteCommit();

        var expectedCode = sourceArchive
            ? "release-source-archive-mismatch"
            : "release-runtime-archive-mismatch";
        var failure = ExpectCode(
            () => WindowsVerifiedLocalReleaseManifestFactory
                .OpenFromOutputsRootForTests(fixture.Root)
                .Dispose(),
            expectedCode,
            assertionMessage);
        Ensure(
            failure.Message.Contains(expectedMessageFragment, StringComparison.Ordinal),
            assertionMessage + "; actual message=" + failure.Message);
    }

    private static RawZipLayout ReadRawZipLayout(byte[] bytes)
    {
        const uint endRecordSignature = 0x06054B50;
        const uint centralHeaderSignature = 0x02014B50;
        const uint localHeaderSignature = 0x04034B50;
        const int endRecordBytes = 22;
        const int centralHeaderBytes = 46;
        const int localHeaderBytes = 30;

        Ensure(bytes.Length >= endRecordBytes, "the raw ZIP fixture has no end record");
        var endRecordOffset = bytes.Length - endRecordBytes;
        Ensure(
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(endRecordOffset, 4)) ==
            endRecordSignature &&
            BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(endRecordOffset + 20, 2)) == 0,
            "the raw ZIP fixture end record is not canonical");

        var entryCount = BinaryPrimitives.ReadUInt16LittleEndian(
            bytes.AsSpan(endRecordOffset + 10, 2));
        var centralHeaderOffset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(
            bytes.AsSpan(endRecordOffset + 16, 4)));
        var centralSize = BinaryPrimitives.ReadUInt32LittleEndian(
            bytes.AsSpan(endRecordOffset + 12, 4));
        Ensure(
            entryCount >= 2 &&
            checked((long)centralHeaderOffset + centralSize) == endRecordOffset &&
            centralHeaderOffset >= 0 &&
            centralHeaderOffset + centralHeaderBytes <= endRecordOffset &&
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(centralHeaderOffset, 4)) ==
            centralHeaderSignature,
            "the raw ZIP fixture central directory is not canonical");

        var localHeaderOffset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(
            bytes.AsSpan(centralHeaderOffset + 42, 4)));
        Ensure(
            localHeaderOffset >= 0 &&
            localHeaderOffset + localHeaderBytes <= centralHeaderOffset &&
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(localHeaderOffset, 4)) ==
            localHeaderSignature,
            "the raw ZIP fixture local header is not canonical");

        var firstNameLength = BinaryPrimitives.ReadUInt16LittleEndian(
            bytes.AsSpan(centralHeaderOffset + 28, 2));
        var firstExtraLength = BinaryPrimitives.ReadUInt16LittleEndian(
            bytes.AsSpan(centralHeaderOffset + 30, 2));
        var firstCommentLength = BinaryPrimitives.ReadUInt16LittleEndian(
            bytes.AsSpan(centralHeaderOffset + 32, 2));
        var secondCentralHeaderOffset = checked(
            centralHeaderOffset + centralHeaderBytes +
            firstNameLength + firstExtraLength + firstCommentLength);
        Ensure(
            secondCentralHeaderOffset + centralHeaderBytes <= endRecordOffset &&
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(secondCentralHeaderOffset, 4)) ==
            centralHeaderSignature,
            "the raw ZIP fixture has no canonical second central-directory entry");

        return new RawZipLayout(
            endRecordOffset,
            centralHeaderOffset,
            localHeaderOffset,
            secondCentralHeaderOffset,
            entryCount);
    }

    private static byte[] CreateEndRecord(ushort entryCount)
    {
        var bytes = new byte[22];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0, 4), 0x06054B50);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8, 2), entryCount);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(10, 2), entryCount);
        return bytes;
    }

    private static void TestRoleDependencyRejected()
    {
        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            File.Delete(Path.Combine(fixture.RuntimeRoot, "CodexGuardian.Trust.dll"));
            fixture.WriteRuntimeArchiveFrom(fixture.RuntimeRoot);
            fixture.RewriteChecksum();
            fixture.RewriteCommit();
            ExpectCode(
                fixture,
                "release-guardian-runtime-missing",
                "Guardian was allowed to omit its local Trust dependency");
        }

        using (var fixture = ReleaseFixture.Create(includeBroker: true))
        {
            File.Delete(Path.Combine(fixture.RuntimeRoot, "Broker", "CodexGuardian.Trust.dll"));
            fixture.WriteRuntimeArchiveFrom(fixture.RuntimeRoot);
            fixture.RewriteChecksum();
            fixture.RewriteCommit();
            ExpectCode(
                fixture,
                "release-broker-runtime-missing",
                "Broker was allowed to borrow Trust from the Guardian directory");
        }
    }

    private static void TestRuntimeHardLinkRejected()
    {
        using var fixture = ReleaseFixture.Create(includeBroker: true);
        var alias = Path.Combine(fixture.RuntimeRoot, "hostfxr-hardlink.dll");
        if (!CreateHardLinkW(alias, fixture.UnlistedRuntimeDependencyPath, IntPtr.Zero))
        {
            throw new InvalidOperationException(
                "Unable to create the runtime hard-link fixture; error=" +
                Marshal.GetLastWin32Error());
        }

        fixture.WriteRuntimeArchiveFrom(fixture.RuntimeRoot);
        fixture.RewriteChecksum();
        fixture.RewriteCommit();
        ExpectCode(
            fixture,
            "release-runtime-invalid",
            "a committed hard-linked runtime file was accepted");
        Ensure(
            CanOpenExclusive(fixture.LockPath) &&
            CanOpenExclusive(fixture.CommitPath) &&
            CanOpenExclusive(fixture.UnlistedRuntimeDependencyPath) &&
            CanOpenExclusive(alias),
            "failed complete-tree retention leaked lock, commit, or runtime handles");
    }

    private static void TestProductionRootRejected()
    {
        try
        {
            using var lease = WindowsVerifiedLocalReleaseManifestFactory.OpenCurrentRelease();
            throw new InvalidOperationException(
                "the production factory accepted the Tests build directory as formal outputs");
        }
        catch (VerifiedLocalReleaseException exception)
        {
            Ensure(
                exception.Code == "release-runtime-root-invalid",
                "the production factory failed with an unexpected root classification");
        }
    }

    private static void ExpectCode(ReleaseFixture fixture, string code, string message)
    {
        try
        {
            using var lease = WindowsVerifiedLocalReleaseManifestFactory
                .OpenFromOutputsRootForTests(fixture.Root);
            throw new InvalidOperationException(message);
        }
        catch (VerifiedLocalReleaseException exception)
        {
            Ensure(exception.Code == code, message + "; actual code=" + exception.Code);
        }
    }

    private static VerifiedLocalReleaseException ExpectCode(
        Action action,
        string code,
        string message)
    {
        try
        {
            action();
            throw new InvalidOperationException(message);
        }
        catch (VerifiedLocalReleaseException exception)
        {
            Ensure(exception.Code == code, message + "; actual code=" + exception.Code);
            return exception;
        }
    }

    private static void RunCase(string name, Action body, Action<bool, string> assert)
    {
        try
        {
            body();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + Describe(exception));
        }
    }

    private static string Describe(Exception exception)
    {
        var parts = new List<string>();
        for (Exception? current = exception; current is not null && parts.Count < 8; current = current.InnerException)
        {
            var code = current is VerifiedLocalReleaseException release
                ? ",code=" + release.Code
                : string.Empty;
            parts.Add(current.GetType().Name + code + ":" + current.Message);
        }

        return string.Join(" -> ", parts);
    }

    private static bool IsExclusiveOpenBlocked(string path)
    {
        try
        {
            using var ignored = new FileStream(
                path,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
    }

    private static bool IsWriteBlocked(string path)
    {
        try
        {
            using var ignored = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Write,
                FileShare.ReadWrite | FileShare.Delete);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
    }

    private static bool IsDeleteBlocked(string path)
    {
        try
        {
            File.Delete(path);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
    }

    private static bool IsMoveBlocked(string path)
    {
        var destination = path + ".move-probe";
        try
        {
            File.Move(path, destination);
            File.Move(destination, path);
            return false;
        }
        catch (IOException)
        {
            if (File.Exists(destination) && !File.Exists(path))
            {
                File.Move(destination, path);
            }

            return true;
        }
    }

    private static bool CanOpenExclusive(string path)
    {
        try
        {
            using var ignored = new FileStream(
                path,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.None);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool CanAppend(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.None);
            stream.WriteByte(0x5A);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool CanMoveRoundTrip(string path)
    {
        var destination = path + ".move-probe";
        try
        {
            File.Move(path, destination);
            File.Move(destination, path);
            return true;
        }
        catch
        {
            try
            {
                if (File.Exists(destination) && !File.Exists(path))
                {
                    File.Move(destination, path);
                }
            }
            catch
            {
            }

            return false;
        }
    }

    private static void MutateFirstByteWithoutChangingLength(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None);
        var originalLength = stream.Length;
        var original = stream.ReadByte();
        Ensure(original >= 0, "the release drift fixture file was empty");
        stream.Position = 0;
        stream.WriteByte((byte)(original ^ 0x01));
        stream.Flush(flushToDisk: true);
        Ensure(stream.Length == originalLength, "the release drift fixture changed file length");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void Expect<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            throw new InvalidOperationException(
                "Expected exception was not observed: " + typeof(TException).Name);
        }
        catch (TException)
        {
        }
    }

    private static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    internal sealed class ReleaseFixture : IDisposable
    {
        internal const string GenerationId = "0123456789abcdef0123456789abcdef";
        private const string CommittedUtc = "2026-08-07T00:00:00.0000000+00:00";
        private bool _disposed;

        private ReleaseFixture(string root)
        {
            Root = root;
            RuntimeRoot = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.RuntimeDirectoryLeaf);
            SourceRoot = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.SourceDirectoryLeaf);
            RuntimeZipPath = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.RuntimeZipLeaf);
            SourceZipPath = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.SourceZipLeaf);
            ChecksumPath = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.ChecksumLeaf);
            CommitPath = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.CommitLeaf);
            JournalPath = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.JournalLeaf);
            LockPath = Path.Combine(root, WindowsVerifiedLocalReleaseManifestFactory.ExchangeLockLeaf);
            GuardianRuntimeConfigDevPath = Path.Combine(
                RuntimeRoot,
                "CodexGuardian.runtimeconfig.dev.json");
            BrokerRuntimeConfigDevPath = Path.Combine(
                RuntimeRoot,
                "Broker",
                "CodexGuardian.Broker.runtimeconfig.dev.json");
            UnlistedRuntimeDependencyPath = Path.Combine(RuntimeRoot, "hostfxr.dll");
        }

        internal string Root { get; }

        internal string RuntimeRoot { get; }

        internal string SourceRoot { get; }

        internal string RuntimeZipPath { get; }

        internal string SourceZipPath { get; }

        internal string ChecksumPath { get; }

        internal string CommitPath { get; }

        internal string JournalPath { get; }

        internal string LockPath { get; }

        internal string GuardianRuntimeConfigDevPath { get; }

        internal string BrokerRuntimeConfigDevPath { get; }

        internal string UnlistedRuntimeDependencyPath { get; }

        internal static ReleaseFixture Create(bool includeBroker)
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                "CodexGuardian-release-factory-" + Guid.NewGuid().ToString("N"));
            var fixture = new ReleaseFixture(root);
            try
            {
                Directory.CreateDirectory(fixture.RuntimeRoot);
                Directory.CreateDirectory(fixture.SourceRoot);
                File.WriteAllBytes(fixture.LockPath, Array.Empty<byte>());
                fixture.WriteRuntime(includeBroker);
                fixture.WriteSource();
                fixture.WriteRuntimeArchiveFrom(fixture.RuntimeRoot);
                WriteArchive(fixture.SourceRoot, fixture.SourceZipPath);
                fixture.RewriteChecksum();
                fixture.RewriteCommit();
                return fixture;
            }
            catch
            {
                fixture.Dispose();
                throw;
            }
        }

        internal void WriteRuntimeArchiveFrom(string sourceRoot) =>
            WriteArchive(sourceRoot, RuntimeZipPath);

        internal void RewriteChecksum()
        {
            var text =
                ComputeSha256(RuntimeZipPath).ToLowerInvariant() + "  " +
                WindowsVerifiedLocalReleaseManifestFactory.RuntimeZipLeaf + Environment.NewLine +
                ComputeSha256(SourceZipPath).ToLowerInvariant() + "  " +
                WindowsVerifiedLocalReleaseManifestFactory.SourceZipLeaf + Environment.NewLine;
            File.WriteAllText(ChecksumPath, text, StrictUtf8);
        }

        internal void RewriteCommit(
            string projectVersion = "2.0.0",
            long? runtimeFileCountOverride = null,
            long? runtimeTotalBytesOverride = null,
            long? sourceFileCountOverride = null,
            long? sourceTotalBytesOverride = null,
            long? runtimeZipLengthOverride = null,
            long? sourceZipLengthOverride = null,
            long? checksumLengthOverride = null)
        {
            var runtime = CaptureTree(RuntimeRoot);
            var source = CaptureTree(SourceRoot);
            var runtimeZip = CaptureFile(RuntimeZipPath);
            var sourceZip = CaptureFile(SourceZipPath);
            var checksum = CaptureFile(ChecksumPath);
            runtimeZip = runtimeZip with
            {
                Length = runtimeZipLengthOverride ?? runtimeZip.Length
            };
            sourceZip = sourceZip with
            {
                Length = sourceZipLengthOverride ?? sourceZip.Length
            };
            checksum = checksum with
            {
                Length = checksumLengthOverride ?? checksum.Length
            };
            var runtimeIdentity = runtime.Identity with
            {
                FileCount = runtimeFileCountOverride ?? runtime.Identity.FileCount,
                TotalBytes = runtimeTotalBytesOverride ?? runtime.Identity.TotalBytes
            };
            var sourceIdentity = source.Identity with
            {
                FileCount = sourceFileCountOverride ?? source.Identity.FileCount,
                TotalBytes = sourceTotalBytesOverride ?? source.Identity.TotalBytes
            };
            var buffer = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(
                       buffer,
                       new JsonWriterOptions
                       {
                           Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                           Indented = false,
                           SkipValidation = false
                       }))
            {
                writer.WriteStartObject();
                writer.WriteString("marker", "CODEXGUARDIAN_RELEASE_COMMIT_V1");
                writer.WriteNumber("schemaVersion", 1);
                writer.WriteString("generationId", GenerationId);
                writer.WriteString("transactionId", GenerationId);
                writer.WriteString("committedUtc", CommittedUtc);
                writer.WriteString("projectVersion", projectVersion);
                writer.WriteStartArray("artifacts");
                WriteTreeArtifact(
                    writer,
                    "runtime-directory",
                    WindowsVerifiedLocalReleaseManifestFactory.RuntimeDirectoryLeaf,
                    runtimeIdentity);
                WriteTreeArtifact(
                    writer,
                    "source-directory",
                    WindowsVerifiedLocalReleaseManifestFactory.SourceDirectoryLeaf,
                    sourceIdentity);
                WriteFileArtifact(
                    writer,
                    "runtime-zip",
                    WindowsVerifiedLocalReleaseManifestFactory.RuntimeZipLeaf,
                    runtimeZip);
                WriteFileArtifact(
                    writer,
                    "source-zip",
                    WindowsVerifiedLocalReleaseManifestFactory.SourceZipLeaf,
                    sourceZip);
                WriteFileArtifact(
                    writer,
                    "checksum",
                    WindowsVerifiedLocalReleaseManifestFactory.ChecksumLeaf,
                    checksum);
                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.Flush();
            }

            using var stream = new FileStream(
                CommitPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None);
            stream.Write(buffer.WrittenSpan);
            stream.Write(StrictUtf8.GetBytes(Environment.NewLine));
            stream.Flush(flushToDisk: true);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private void WriteRuntime(bool includeBroker)
        {
            foreach (var path in new[]
                     {
                         "CodexGuardian.exe",
                         "CodexGuardian.dll",
                         "CodexGuardian.deps.json",
                         "CodexGuardian.runtimeconfig.json",
                         "CodexGuardian.Control.dll",
                         "CodexGuardian.Trust.dll",
                         "System.Security.Cryptography.Pkcs.dll"
                     })
            {
                WriteFixtureFile(Path.Combine(RuntimeRoot, path), "guardian:" + path);
            }
            WriteCanonicalRuntimeConfigDev(GuardianRuntimeConfigDevPath);
            WriteFixtureFile(UnlistedRuntimeDependencyPath, "guardian:hostfxr.dll");

            if (!includeBroker)
            {
                return;
            }

            foreach (var path in new[]
                     {
                         "CodexGuardian.Broker.exe",
                         "CodexGuardian.Broker.dll",
                         "CodexGuardian.Broker.deps.json",
                         "CodexGuardian.Broker.runtimeconfig.json",
                         "CodexGuardian.Control.dll",
                         "CodexGuardian.Trust.dll",
                         "System.Security.Cryptography.Pkcs.dll"
                     })
            {
                WriteFixtureFile(
                    Path.Combine(RuntimeRoot, "Broker", path),
                    "broker:" + path);
            }
            WriteCanonicalRuntimeConfigDev(BrokerRuntimeConfigDevPath);
        }

        private void WriteSource()
        {
            WriteFixtureFile(Path.Combine(SourceRoot, "src", "guardian.cs"), "guardian-source");
            WriteFixtureFile(Path.Combine(SourceRoot, "src", "broker.cs"), "broker-source");
            WriteFixtureFile(Path.Combine(SourceRoot, "package-release.ps1"), "release-source");
        }

        private static void WriteFixtureFile(string path, string content)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content + Environment.NewLine, StrictUtf8);
        }

        private static void WriteCanonicalRuntimeConfigDev(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, StrictUtf8.GetBytes("{\"runtimeOptions\":{}}\r\n"));
        }

        private static void WriteArchive(string sourceRoot, string destination)
        {
            if (File.Exists(destination))
            {
                File.Delete(destination);
            }

            var tree = CaptureTree(sourceRoot);
            using var stream = new FileStream(
                destination,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: false);
            foreach (var file in tree.Entries)
            {
                var entry = archive.CreateEntry(file.Path, CompressionLevel.Optimal);
                entry.LastWriteTime = new DateTimeOffset(
                    1980,
                    1,
                    1,
                    0,
                    0,
                    0,
                    TimeSpan.Zero);
                using var input = new FileStream(
                    Path.Combine(sourceRoot, file.Path.Replace('/', Path.DirectorySeparatorChar)),
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read);
                using var output = entry.Open();
                input.CopyTo(output);
            }
        }

        private static TreeSnapshot CaptureTree(string root)
        {
            var entries = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Select(path =>
                {
                    var identity = CaptureFile(path);
                    return new TreeEntry(
                        Path.GetRelativePath(root, path).Replace('\\', '/'),
                        identity.Length,
                        identity.Sha256);
                })
                .OrderBy(entry => entry.Path, StringComparer.Ordinal)
                .ToArray();
            long totalBytes = 0;
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var pathLength = new byte[sizeof(int)];
            var fileLength = new byte[sizeof(long)];
            foreach (var entry in entries)
            {
                totalBytes = checked(totalBytes + entry.Length);
                var pathBytes = StrictUtf8.GetBytes(entry.Path);
                BinaryPrimitives.WriteInt32BigEndian(pathLength, pathBytes.Length);
                BinaryPrimitives.WriteInt64BigEndian(fileLength, entry.Length);
                digest.AppendData(pathLength);
                digest.AppendData(pathBytes);
                digest.AppendData(fileLength);
                digest.AppendData(Convert.FromHexString(entry.Sha256));
            }

            return new TreeSnapshot(
                entries,
                new TreeIdentity(
                    Convert.ToHexString(digest.GetHashAndReset()),
                    entries.LongLength,
                    totalBytes));
        }

        private static FileIdentity CaptureFile(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return new FileIdentity(Convert.ToHexString(SHA256.HashData(stream)), stream.Length);
        }

        private static void WriteTreeArtifact(
            Utf8JsonWriter writer,
            string id,
            string leaf,
            TreeIdentity identity)
        {
            writer.WriteStartObject();
            writer.WriteString("id", id);
            writer.WriteString("leaf", leaf);
            writer.WriteString("kind", "tree");
            writer.WriteStartObject("identity");
            writer.WriteString("kind", "tree");
            writer.WriteString("manifestSha256", identity.ManifestSha256);
            writer.WriteNumber("fileCount", identity.FileCount);
            writer.WriteNumber("totalBytes", identity.TotalBytes);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        private static void WriteFileArtifact(
            Utf8JsonWriter writer,
            string id,
            string leaf,
            FileIdentity identity)
        {
            writer.WriteStartObject();
            writer.WriteString("id", id);
            writer.WriteString("leaf", leaf);
            writer.WriteString("kind", "file");
            writer.WriteStartObject("identity");
            writer.WriteString("kind", "file");
            writer.WriteString("sha256", identity.Sha256);
            writer.WriteNumber("length", identity.Length);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        private sealed record TreeEntry(string Path, long Length, string Sha256);

        private sealed record TreeIdentity(
            string ManifestSha256,
            long FileCount,
            long TotalBytes);

        private sealed record FileIdentity(string Sha256, long Length);

        private sealed record TreeSnapshot(
            IReadOnlyList<TreeEntry> Entries,
            TreeIdentity Identity);
    }

    private readonly record struct RawZipLayout(
        int EndRecordOffset,
        int CentralHeaderOffset,
        int LocalHeaderOffset,
        int SecondCentralHeaderOffset,
        ushort EntryCount);
}
