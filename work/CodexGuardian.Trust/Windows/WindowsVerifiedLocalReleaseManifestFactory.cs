using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;

namespace CodexGuardian.Trust;

internal sealed class VerifiedLocalReleaseException : Exception
{
    internal VerifiedLocalReleaseException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    internal VerifiedLocalReleaseException(string code, string message, Exception innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal sealed record LocalReleaseCommitIdentityV1(
    string GenerationId,
    string CommitSha256,
    string RuntimeManifestSha256,
    long RuntimeFileCount,
    long RuntimeTotalBytes,
    string SourceManifestSha256,
    long SourceFileCount,
    long SourceTotalBytes);

public sealed class VerifiedLocalReleaseLeaseV1 : IDisposable
{
    private readonly object _sync = new();
    private FileStream? _exchangeLock;
    private FileStream? _commitHandle;
    private WindowsRetainedReleaseTreeV1? _runtimeTree;
    private WindowsRetainedReleaseArtifacts? _guardianArtifacts;
    private WindowsRetainedReleaseArtifacts? _brokerArtifacts;
    private Exception? _disposeFailure;
    private bool _disposed;
#if CODEXGUARDIAN_TEST_FRIEND
    private Action? _testDisposeCallback;
#endif

    internal VerifiedLocalReleaseLeaseV1(
        VerifiedReleaseManifest manifest,
        LocalReleaseCommitIdentityV1 commit,
        FileStream exchangeLock,
        FileStream commitHandle,
        WindowsRetainedReleaseTreeV1 runtimeTree,
        WindowsRetainedReleaseArtifacts guardianArtifacts,
        WindowsRetainedReleaseArtifacts brokerArtifacts)
    {
        Manifest = manifest ?? throw new ArgumentNullException(nameof(manifest));
        Commit = commit ?? throw new ArgumentNullException(nameof(commit));
        _exchangeLock = exchangeLock ?? throw new ArgumentNullException(nameof(exchangeLock));
        _commitHandle = commitHandle ?? throw new ArgumentNullException(nameof(commitHandle));
        _runtimeTree = runtimeTree ?? throw new ArgumentNullException(nameof(runtimeTree));
        _guardianArtifacts = guardianArtifacts ??
            throw new ArgumentNullException(nameof(guardianArtifacts));
        _brokerArtifacts = brokerArtifacts ?? throw new ArgumentNullException(nameof(brokerArtifacts));
    }

    public VerifiedReleaseManifest Manifest { get; }

    internal LocalReleaseCommitIdentityV1 Commit { get; }

    internal VerifiedReleaseArtifactSet GetRelease(BrokerPeerRole role)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return Manifest.GetArtifactSet(role);
        }
    }

    internal WindowsRetainedReleaseArtifacts GetRetainedArtifacts(BrokerPeerRole role)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return role switch
            {
                BrokerPeerRole.Guardian => _guardianArtifacts!,
                BrokerPeerRole.Broker => _brokerArtifacts!,
                _ => throw new ArgumentOutOfRangeException(nameof(role))
            };
        }
    }

    internal IReadOnlyList<WindowsRetainedReleaseTreeFileV1> GetRetainedRuntimeFiles()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return _runtimeTree!.Files;
        }
    }

    public VerifiedLocalReleaseLeaseV1 TakeOwnership()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var successor = new VerifiedLocalReleaseLeaseV1(
                Manifest,
                Commit,
                _exchangeLock!,
                _commitHandle!,
                _runtimeTree!,
                _guardianArtifacts!,
                _brokerArtifacts!);
#if CODEXGUARDIAN_TEST_FRIEND
            successor._testDisposeCallback = _testDisposeCallback;
            _testDisposeCallback = null;
#endif
            _exchangeLock = null;
            _commitHandle = null;
            _runtimeTree = null;
            _guardianArtifacts = null;
            _brokerArtifacts = null;
            _disposed = true;
            return successor;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                if (_disposeFailure is not null)
                {
                    ExceptionDispatchInfo.Capture(_disposeFailure).Throw();
                }

                return;
            }

            _disposed = true;
            var failures = new List<Exception>();
            DisposeOwned(_brokerArtifacts, failures);
            _brokerArtifacts = null;
            DisposeOwned(_guardianArtifacts, failures);
            _guardianArtifacts = null;
            DisposeOwned(_runtimeTree, failures);
            _runtimeTree = null;
            DisposeOwned(_commitHandle, failures);
            _commitHandle = null;
            DisposeOwned(_exchangeLock, failures);
            _exchangeLock = null;
#if CODEXGUARDIAN_TEST_FRIEND
            if (_testDisposeCallback is not null)
            {
                try
                {
                    _testDisposeCallback();
                }
                catch (Exception exception)
                {
                    failures.Add(exception);
                }

                _testDisposeCallback = null;
            }
#endif
            _disposeFailure = failures.Count switch
            {
                0 => null,
                1 => failures[0],
                _ => new AggregateException("Verified local release cleanup failed.", failures)
            };
            if (_disposeFailure is not null)
            {
                ExceptionDispatchInfo.Capture(_disposeFailure).Throw();
            }
        }
    }

#if CODEXGUARDIAN_TEST_FRIEND
    internal void ConfigureDisposalForTests(Action callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_testDisposeCallback is not null)
            {
                throw new InvalidOperationException(
                    "The verified release test disposal callback was already configured.");
            }

            _testDisposeCallback = callback;
        }
    }
#endif

    private static void DisposeOwned(IDisposable? value, ICollection<Exception> failures)
    {
        if (value is null)
        {
            return;
        }

        try
        {
            value.Dispose();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

public static class WindowsVerifiedLocalReleasePeerAuthorityV1
{
    public static IRetainedPeerIdentityLease OpenRetainedProcess(
        VerifiedLocalReleaseLeaseV1 authority,
        BrokerPeerRole role,
        SafeProcessHandle exactProcessHandle)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(exactProcessHandle);
        if (!Enum.IsDefined(role))
        {
            throw new ArgumentOutOfRangeException(nameof(role));
        }

        var release = authority.GetRelease(role);
        var retained = authority.GetRetainedArtifacts(role);
        SafeProcessHandle? process = null;
        WindowsRetainedReleaseHandleLease? releaseHandles = null;
        try
        {
            process = WindowsPeerNative.DuplicateRestrictedProcessHandle(exactProcessHandle);
            releaseHandles = retained.DuplicateFor(release);
            var ownedProcess = process;
            var ownedReleaseHandles = releaseHandles;
            process = null;
            releaseHandles = null;
            return new WindowsRetainedPeerIdentityLease(
                ownedProcess,
                ownedReleaseHandles,
                release);
        }
        finally
        {
            releaseHandles?.Dispose();
            process?.Dispose();
        }
    }

    public static WindowsConnectedClientPeerTrustPlatform TakeConnectedGuardianClient(
        VerifiedLocalReleaseLeaseV1 authority,
        WindowsSameLogonNamedPipeServer connectedServer,
        SafeProcessHandle exactGuardianHandle)
    {
        ArgumentNullException.ThrowIfNull(authority);
        _ = authority.GetRelease(BrokerPeerRole.Guardian);
        return WindowsConnectedClientPeerTrustPlatform
            .TakeConnectedClientForBrokerFirstHandshake(
                connectedServer,
                exactGuardianHandle,
                authority.GetRetainedArtifacts(BrokerPeerRole.Guardian));
    }

    public static WindowsNamedPipePeerTrustPlatform ConnectToLaunchedBrokerServer(
        VerifiedLocalReleaseLeaseV1 authority,
        string endpointName,
        SafeProcessHandle exactBrokerHandle,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        _ = authority.GetRelease(BrokerPeerRole.Broker);
        return WindowsNamedPipePeerTrustPlatform.ConnectToLaunchedServer(
            endpointName,
            exactBrokerHandle,
            authority.GetRetainedArtifacts(BrokerPeerRole.Broker),
            timeout,
            cancellationToken);
    }
}

public static class WindowsVerifiedLocalReleaseManifestFactory
{
    internal const string RuntimeDirectoryLeaf = "CodexGuardian-win-x64";
    internal const string SourceDirectoryLeaf = "CodexGuardian-source";
    internal const string RuntimeZipLeaf = "CodexGuardian-win-x64.zip";
    internal const string SourceZipLeaf = "CodexGuardian-source.zip";
    internal const string ChecksumLeaf = "SHA256SUMS.txt";
    internal const string CommitLeaf = "CodexGuardian-release-manifest.json";
    internal const string JournalLeaf = ".CodexGuardian-release-transaction.json";
    internal const string ExchangeLockLeaf = ".CodexGuardian-release-exchange.lock";

    private const string CommitMarker = "CODEXGUARDIAN_RELEASE_COMMIT_V1";
    private const string ExpectedProjectVersion = "2.0.0";
    internal const string GuardianRuntimeConfigDevRelativePath =
        "CodexGuardian.runtimeconfig.dev.json";
    internal const string BrokerRuntimeConfigDevRelativePath =
        "Broker/CodexGuardian.Broker.runtimeconfig.dev.json";
    internal const int CanonicalRuntimeConfigDevLength = 23;
    internal const string CanonicalRuntimeConfigDevSha256 =
        "65F2DFF132AEC14731F86C569B5EC96691CACA7D822D02A18B79ACAEB5DC96D7";
    private const int MaximumCommitBytes = 64 * 1024;
    private const int MaximumTreeFiles = 4096;
    private const int MaximumTreeDirectories = 4096;
    private const int MaximumRelativePathBytes = 4096;
    private const long MaximumTreeBytes = 2L * 1024 * 1024 * 1024;
    private const long MaximumSingleTreeFileBytes = 512L * 1024 * 1024;
    private const long MaximumArchiveBytes = 1024L * 1024 * 1024;
    private const uint ZipEndOfCentralDirectorySignature = 0x06054B50;
    private const uint Zip64EndOfCentralDirectoryLocatorSignature = 0x07064B50;
    private const uint ZipCentralDirectoryHeaderSignature = 0x02014B50;
    private const uint ZipLocalFileHeaderSignature = 0x04034B50;
    private const int ZipEndOfCentralDirectoryFixedBytes = 22;
    private const int ZipEndOfCentralDirectoryMaximumSearchBytes =
        ZipEndOfCentralDirectoryFixedBytes + ushort.MaxValue;
    private const int ZipCentralDirectoryHeaderFixedBytes = 46;
    private const int ZipLocalFileHeaderFixedBytes = 30;
    private const ushort ZipUtf8Flag = 0x0800;
    private const ushort ZipDeflateMethod = 8;
    private const ushort ZipCanonicalDosTime = 0;
    private const ushort ZipCanonicalDosDate = 0x0021;
    private const long MaximumArchiveCentralDirectoryBytes =
        (long)MaximumTreeFiles * (ZipCentralDirectoryHeaderFixedBytes + MaximumRelativePathBytes);
    private const FileAttributes UnsafeAttributes =
        FileAttributes.ReparsePoint | FileAttributes.Device | FileAttributes.Directory;

    private static readonly TreeCaptureLimits DefaultTreeCaptureLimits = new(
        MaximumTreeFiles,
        MaximumTreeDirectories,
        MaximumTreeBytes,
        MaximumSingleTreeFileBytes);

    private static readonly ArtifactDescriptor[] ArtifactPlan =
    {
        new("runtime-directory", RuntimeDirectoryLeaf, ArtifactIdentityKind.Tree),
        new("source-directory", SourceDirectoryLeaf, ArtifactIdentityKind.Tree),
        new("runtime-zip", RuntimeZipLeaf, ArtifactIdentityKind.File),
        new("source-zip", SourceZipLeaf, ArtifactIdentityKind.File),
        new("checksum", ChecksumLeaf, ArtifactIdentityKind.File)
    };

    private static readonly RoleArtifactPlan GuardianPlan = new(
        BrokerPeerRole.Guardian,
        "CodexGuardian.exe",
        "CodexGuardian.dll",
        "CodexGuardian.deps.json",
        "CodexGuardian.runtimeconfig.json",
        new[]
        {
            new WindowsReleaseArtifactPath(ReleaseArtifactKind.AppHostExe, "CodexGuardian.exe"),
            new WindowsReleaseArtifactPath(ReleaseArtifactKind.ManagedEntryDll, "CodexGuardian.dll"),
            new WindowsReleaseArtifactPath(ReleaseArtifactKind.DepsJson, "CodexGuardian.deps.json"),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeConfigJson,
                "CodexGuardian.runtimeconfig.json"),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                GuardianRuntimeConfigDevRelativePath),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                "CodexGuardian.Control.dll"),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                "CodexGuardian.Trust.dll"),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                "System.Security.Cryptography.Pkcs.dll")
        });

    private static readonly RoleArtifactPlan BrokerPlan = new(
        BrokerPeerRole.Broker,
        Path.Combine("Broker", "CodexGuardian.Broker.exe"),
        Path.Combine("Broker", "CodexGuardian.Broker.dll"),
        Path.Combine("Broker", "CodexGuardian.Broker.deps.json"),
        Path.Combine("Broker", "CodexGuardian.Broker.runtimeconfig.json"),
        new[]
        {
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.AppHostExe,
                Path.Combine("Broker", "CodexGuardian.Broker.exe")),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.ManagedEntryDll,
                Path.Combine("Broker", "CodexGuardian.Broker.dll")),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.DepsJson,
                Path.Combine("Broker", "CodexGuardian.Broker.deps.json")),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeConfigJson,
                Path.Combine("Broker", "CodexGuardian.Broker.runtimeconfig.json")),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                BrokerRuntimeConfigDevRelativePath.Replace('/', Path.DirectorySeparatorChar)),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine("Broker", "CodexGuardian.Control.dll")),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine("Broker", "CodexGuardian.Trust.dll")),
            new WindowsReleaseArtifactPath(
                ReleaseArtifactKind.RuntimeDependency,
                Path.Combine("Broker", "System.Security.Cryptography.Pkcs.dll"))
        });

    public static VerifiedLocalReleaseLeaseV1 OpenCurrentRelease()
    {
        EnsureWindows();
        var baseDirectory = CanonicalizeLocalPath(AppContext.BaseDirectory, "release-runtime-root");
        string runtimeRoot;
        if (string.Equals(
                Path.GetFileName(baseDirectory),
                RuntimeDirectoryLeaf,
                StringComparison.Ordinal))
        {
            runtimeRoot = baseDirectory;
        }
        else if (string.Equals(
                     Path.GetFileName(baseDirectory),
                     "Broker",
                     StringComparison.Ordinal) &&
                 string.Equals(
                     Path.GetFileName(Path.GetDirectoryName(baseDirectory)),
                     RuntimeDirectoryLeaf,
                     StringComparison.Ordinal))
        {
            runtimeRoot = Path.GetDirectoryName(baseDirectory)!;
        }
        else
        {
            throw Failure(
                "release-runtime-root-invalid",
                "The current executable is not inside the fixed formal runtime layout.");
        }

        var outputsRoot = Path.GetDirectoryName(runtimeRoot) ?? throw Failure(
            "release-runtime-root-invalid",
            "The formal runtime has no outputs parent.");
        return OpenCore(outputsRoot, runtimeRoot);
    }

#if CODEXGUARDIAN_TEST_FRIEND
    internal static VerifiedLocalReleaseLeaseV1 OpenFromOutputsRootForTests(string outputsRoot)
    {
        EnsureWindows();
        return OpenCore(outputsRoot, expectedRuntimeRoot: null);
    }

    internal static IReadOnlyList<WindowsRetainedReleaseTreeFileV1> CaptureTreeSnapshotForTests(
        string root,
        int maximumFiles,
        int maximumDirectories,
        long maximumTreeBytes,
        long maximumSingleFileBytes,
        Action<string>? hashStarted = null,
        Func<string, IEnumerable<FileSystemInfo>>? enumerateDirectory = null)
    {
        EnsureWindows();
        var limits = CreateTreeCaptureLimits(
            maximumFiles,
            maximumDirectories,
            maximumTreeBytes,
            maximumSingleFileBytes);
        var snapshot = CaptureTreeSnapshot(
            root,
            "release-tree-test-invalid",
            limits,
            hashStarted,
            enumerateDirectory);
        return Array.AsReadOnly(snapshot.Entries.Select(entry =>
                new WindowsRetainedReleaseTreeFileV1(
                    entry.Path,
                    entry.Length,
                    entry.Sha256))
            .ToArray());
    }
#endif

    private static VerifiedLocalReleaseLeaseV1 OpenCore(
        string outputsRoot,
        string? expectedRuntimeRoot)
    {
        FileStream? exchangeLock = null;
        FileStream? commitHandle = null;
        WindowsRetainedReleaseTreeV1? runtimeTree = null;
        WindowsRetainedReleaseArtifacts? guardianArtifacts = null;
        WindowsRetainedReleaseArtifacts? brokerArtifacts = null;
        VerifiedLocalReleaseLeaseV1? result = null;
        ExceptionDispatchInfo? primaryFailure = null;
        try
        {
            var root = ValidateExistingDirectory(outputsRoot, "release-outputs-root-invalid");
            var runtimeRoot = ValidateExistingDirectory(
                Path.Combine(root, RuntimeDirectoryLeaf),
                "release-runtime-missing");
            if (expectedRuntimeRoot is not null &&
                !WindowsPeerNative.SamePath(runtimeRoot, expectedRuntimeRoot))
            {
                throw Failure(
                    "release-runtime-root-invalid",
                    "The current executable runtime does not match the fixed formal runtime sibling.");
            }

            var sourceRoot = ValidateExistingDirectory(
                Path.Combine(root, SourceDirectoryLeaf),
                "release-source-missing");
            var runtimeZip = GetFixedChild(root, RuntimeZipLeaf);
            var sourceZip = GetFixedChild(root, SourceZipLeaf);
            var checksumPath = GetFixedChild(root, ChecksumLeaf);
            var commitPath = GetFixedChild(root, CommitLeaf);
            var journalPath = GetFixedChild(root, JournalLeaf);
            var lockPath = GetFixedChild(root, ExchangeLockLeaf);

            exchangeLock = OpenReadLease(lockPath, allowEmpty: true, "release-lock-unavailable");
            AssertSettled(root, journalPath);

            commitHandle = OpenReadLease(commitPath, allowEmpty: false, "release-commit-missing");
            var commitBytes = ReadBoundedBytes(
                commitHandle,
                MaximumCommitBytes,
                "release-commit-invalid");
            var commit = ParseCommit(commitBytes);
            var committedRuntimeTree = commit.GetTree("runtime-directory");
            var committedSourceTree = commit.GetTree("source-directory");
            var committedRuntimeZip = commit.GetFile("runtime-zip");
            var committedSourceZip = commit.GetFile("source-zip");
            var committedChecksum = commit.GetFile("checksum");
            AssertCommittedTreeBounds(committedRuntimeTree, "runtime-directory");
            AssertCommittedTreeBounds(committedSourceTree, "source-directory");
            AssertCommittedFileBounds(committedRuntimeZip, MaximumArchiveBytes, "runtime-zip");
            AssertCommittedFileBounds(committedSourceZip, MaximumArchiveBytes, "source-zip");
            AssertCommittedFileBounds(committedChecksum, MaximumCommitBytes, "checksum");

            var runtimeCaptureLimits = CreateCommittedTreeCaptureLimits(committedRuntimeTree);
            var sourceCaptureLimits = CreateCommittedTreeCaptureLimits(committedSourceTree);

            var runtimeSnapshot = CaptureTreeSnapshot(
                runtimeRoot,
                "release-runtime-invalid",
                runtimeCaptureLimits);
            AssertTreeIdentity(
                runtimeSnapshot,
                committedRuntimeTree,
                "release-runtime-identity-mismatch");
            runtimeTree = CaptureRuntimeTree(runtimeRoot, runtimeSnapshot);

            var sourceSnapshot = CaptureTreeSnapshot(
                sourceRoot,
                "release-source-invalid",
                sourceCaptureLimits);
            AssertTreeIdentity(
                sourceSnapshot,
                committedSourceTree,
                "release-source-identity-mismatch");

            EnsureRolePlanPresent(runtimeSnapshot, GuardianPlan, "release-guardian-runtime-missing");
            EnsureRolePlanPresent(runtimeSnapshot, BrokerPlan, "release-broker-runtime-missing");
            EnsureCanonicalRuntimeConfigDevFiles(runtimeSnapshot);

            var runtimeZipIdentity = CaptureFileIdentity(
                runtimeZip,
                committedRuntimeZip.Length,
                "release-runtime-zip-invalid");
            var sourceZipIdentity = CaptureFileIdentity(
                sourceZip,
                committedSourceZip.Length,
                "release-source-zip-invalid");
            var checksumIdentity = CaptureFileIdentity(
                checksumPath,
                committedChecksum.Length,
                "release-checksum-invalid");
            AssertFileIdentity(
                runtimeZipIdentity,
                committedRuntimeZip,
                "release-runtime-zip-identity-mismatch");
            AssertFileIdentity(
                sourceZipIdentity,
                committedSourceZip,
                "release-source-zip-identity-mismatch");
            AssertFileIdentity(
                checksumIdentity,
                committedChecksum,
                "release-checksum-identity-mismatch");
            VerifyChecksum(checksumPath, runtimeZipIdentity, sourceZipIdentity);
            VerifyArchive(runtimeZip, runtimeSnapshot, "release-runtime-archive-mismatch");
            VerifyArchive(sourceZip, sourceSnapshot, "release-source-archive-mismatch");

            guardianArtifacts = CaptureRole(runtimeRoot, GuardianPlan, "release-guardian-runtime-invalid");
            brokerArtifacts = CaptureRole(runtimeRoot, BrokerPlan, "release-broker-runtime-invalid");
            AssertCapturedRoleMatchesSnapshot(
                guardianArtifacts,
                runtimeSnapshot,
                "release-guardian-runtime-identity-mismatch");
            AssertCapturedRoleMatchesSnapshot(
                brokerArtifacts,
                runtimeSnapshot,
                "release-broker-runtime-identity-mismatch");
            AssertSameReleaseRoot(guardianArtifacts.Root, brokerArtifacts.Root);

            AssertSettled(root, journalPath);
            var secondCommitBytes = ReadBoundedBytes(
                commitHandle,
                MaximumCommitBytes,
                "release-commit-changed");
            if (!commitBytes.AsSpan().SequenceEqual(secondCommitBytes))
            {
                throw Failure(
                    "release-commit-changed",
                    "The formal release commit changed during local verification.");
            }

            var secondRuntimeSnapshot = CaptureTreeSnapshot(
                runtimeRoot,
                "release-runtime-changed",
                runtimeCaptureLimits);
            var secondSourceSnapshot = CaptureTreeSnapshot(
                sourceRoot,
                "release-source-changed",
                sourceCaptureLimits);
            if (!runtimeSnapshot.EqualsExact(secondRuntimeSnapshot) ||
                !sourceSnapshot.EqualsExact(secondSourceSnapshot) ||
                runtimeZipIdentity != CaptureFileIdentity(
                    runtimeZip,
                    committedRuntimeZip.Length,
                    "release-runtime-zip-changed") ||
                sourceZipIdentity != CaptureFileIdentity(
                    sourceZip,
                    committedSourceZip.Length,
                    "release-source-zip-changed") ||
                checksumIdentity != CaptureFileIdentity(
                    checksumPath,
                    committedChecksum.Length,
                    "release-checksum-changed"))
            {
                throw Failure(
                    "release-snapshot-changed",
                    "The formal release changed during local verification.");
            }

            var manifest = VerifiedReleaseManifest.CreateFromVerifiedPayload(
                commit.GenerationId,
                commit.CommitSha256,
                guardianArtifacts.Root,
                CreateRoleDefinition(guardianArtifacts),
                CreateRoleDefinition(brokerArtifacts));
            var commitIdentity = new LocalReleaseCommitIdentityV1(
                commit.GenerationId,
                commit.CommitSha256,
                runtimeSnapshot.Identity.ManifestSha256,
                runtimeSnapshot.Identity.FileCount,
                runtimeSnapshot.Identity.TotalBytes,
                sourceSnapshot.Identity.ManifestSha256,
                sourceSnapshot.Identity.FileCount,
                sourceSnapshot.Identity.TotalBytes);
            result = new VerifiedLocalReleaseLeaseV1(
                manifest,
                commitIdentity,
                exchangeLock,
                commitHandle,
                runtimeTree,
                guardianArtifacts,
                brokerArtifacts);
            exchangeLock = null;
            commitHandle = null;
            runtimeTree = null;
            guardianArtifacts = null;
            brokerArtifacts = null;
        }
        catch (Exception exception)
        {
            primaryFailure = ExceptionDispatchInfo.Capture(exception);
        }

        var cleanupFailures = new List<Exception>();
        DisposeOwned(brokerArtifacts, cleanupFailures);
        DisposeOwned(guardianArtifacts, cleanupFailures);
        DisposeOwned(runtimeTree, cleanupFailures);
        DisposeOwned(commitHandle, cleanupFailures);
        DisposeOwned(exchangeLock, cleanupFailures);
        if (primaryFailure is not null)
        {
            if (cleanupFailures.Count != 0)
            {
                throw new AggregateException(
                    "Verified local release verification and cleanup failed.",
                    new[] { primaryFailure.SourceException }.Concat(cleanupFailures));
            }

            primaryFailure.Throw();
        }

        if (cleanupFailures.Count != 0)
        {
            throw cleanupFailures.Count == 1
                ? cleanupFailures[0]
                : new AggregateException("Verified local release cleanup failed.", cleanupFailures);
        }

        return result ?? throw Failure(
            "release-publication-failed",
            "The verified local release lease was not published.");
    }

    private static ParsedCommit ParseCommit(byte[] bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            throw Failure("release-commit-invalid", "The release commit must be UTF-8 without BOM.");
        }

        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw Failure("release-commit-invalid", "The release commit is not strict UTF-8.", exception);
        }

        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 12
                });
            var root = RequireObject(document.RootElement, "release-commit-invalid");
            var properties = RequireExactProperties(
                root,
                new[]
                {
                    "marker",
                    "schemaVersion",
                    "generationId",
                    "transactionId",
                    "committedUtc",
                    "projectVersion",
                    "artifacts"
                },
                "release-commit-invalid");
            if (!string.Equals(
                    ReadString(properties["marker"], 64, "release-commit-invalid"),
                    CommitMarker,
                    StringComparison.Ordinal) ||
                ReadNonnegativeInt64(properties["schemaVersion"], "release-commit-invalid") != 1)
            {
                throw Failure(
                    "release-commit-unsupported",
                    "The release commit marker or schema is unsupported.");
            }

            var generationId = ReadIdentifier(properties["generationId"]);
            var transactionId = ReadIdentifier(properties["transactionId"]);
            if (!string.Equals(generationId, transactionId, StringComparison.Ordinal))
            {
                throw Failure(
                    "release-commit-invalid",
                    "The release generation and transaction identifiers differ.");
            }

            var committedUtc = ReadCanonicalTimestamp(properties["committedUtc"]);
            var projectVersion = ReadString(
                properties["projectVersion"],
                64,
                "release-commit-invalid");
            if (!string.Equals(projectVersion, ExpectedProjectVersion, StringComparison.Ordinal))
            {
                throw Failure(
                    "release-commit-unsupported",
                    "The release project version is unsupported by this factory.");
            }

            if (properties["artifacts"].ValueKind != JsonValueKind.Array ||
                properties["artifacts"].GetArrayLength() != ArtifactPlan.Length)
            {
                throw Failure(
                    "release-commit-invalid",
                    "The release commit does not contain the fixed five-artifact plan.");
            }

            var artifacts = new List<CommitArtifact>(ArtifactPlan.Length);
            var index = 0;
            foreach (var element in properties["artifacts"].EnumerateArray())
            {
                var descriptor = ArtifactPlan[index];
                var artifactObject = RequireObject(element, "release-commit-invalid");
                var artifactProperties = RequireExactProperties(
                    artifactObject,
                    new[] { "id", "leaf", "kind", "identity" },
                    "release-commit-invalid");
                var id = ReadString(artifactProperties["id"], 64, "release-commit-invalid");
                var leaf = ReadString(artifactProperties["leaf"], 128, "release-commit-invalid");
                var kindText = ReadString(
                    artifactProperties["kind"],
                    16,
                    "release-commit-invalid");
                var expectedKindText = descriptor.Kind == ArtifactIdentityKind.Tree ? "tree" : "file";
                if (!string.Equals(id, descriptor.Id, StringComparison.Ordinal) ||
                    !string.Equals(leaf, descriptor.Leaf, StringComparison.Ordinal) ||
                    !string.Equals(kindText, expectedKindText, StringComparison.Ordinal))
                {
                    throw Failure(
                        "release-commit-invalid",
                        "A release commit artifact does not match the fixed plan at index " + index + ".");
                }

                artifacts.Add(new CommitArtifact(
                    id,
                    leaf,
                    descriptor.Kind,
                    ReadArtifactIdentity(artifactProperties["identity"], descriptor.Kind)));
                index++;
            }

            var commit = new CommitDocument(
                generationId,
                transactionId,
                committedUtc,
                projectVersion,
                artifacts);
            var canonical = WriteCanonicalCommit(commit);
            if (!bytes.AsSpan().SequenceEqual(canonical))
            {
                throw Failure(
                    "release-commit-noncanonical",
                    "The release commit is not canonical or contains unsupported JSON data.");
            }

            return new ParsedCommit(
                commit,
                Convert.ToHexString(SHA256.HashData(bytes)));
        }
        catch (VerifiedLocalReleaseException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw Failure("release-commit-invalid", "The release commit is not valid JSON.", exception);
        }
    }

    private static ArtifactIdentity ReadArtifactIdentity(
        JsonElement value,
        ArtifactIdentityKind kind)
    {
        var objectValue = RequireObject(value, "release-commit-invalid");
        if (kind == ArtifactIdentityKind.Tree)
        {
            var properties = RequireExactProperties(
                objectValue,
                new[] { "kind", "manifestSha256", "fileCount", "totalBytes" },
                "release-commit-invalid");
            if (!string.Equals(
                    ReadString(properties["kind"], 16, "release-commit-invalid"),
                    "tree",
                    StringComparison.Ordinal))
            {
                throw Failure("release-commit-invalid", "A tree identity has an invalid kind.");
            }

            return new TreeIdentity(
                ReadSha256(properties["manifestSha256"]),
                ReadNonnegativeInt64(properties["fileCount"], "release-commit-invalid"),
                ReadNonnegativeInt64(properties["totalBytes"], "release-commit-invalid"));
        }

        var fileProperties = RequireExactProperties(
            objectValue,
            new[] { "kind", "sha256", "length" },
            "release-commit-invalid");
        if (!string.Equals(
                ReadString(fileProperties["kind"], 16, "release-commit-invalid"),
                "file",
                StringComparison.Ordinal))
        {
            throw Failure("release-commit-invalid", "A file identity has an invalid kind.");
        }

        return new FileIdentity(
            ReadSha256(fileProperties["sha256"]),
            ReadNonnegativeInt64(fileProperties["length"], "release-commit-invalid"));
    }

    private static byte[] WriteCanonicalCommit(CommitDocument commit)
    {
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
            writer.WriteString("marker", CommitMarker);
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("generationId", commit.GenerationId);
            writer.WriteString("transactionId", commit.TransactionId);
            writer.WriteString("committedUtc", commit.CommittedUtc);
            writer.WriteString("projectVersion", commit.ProjectVersion);
            writer.WriteStartArray("artifacts");
            foreach (var artifact in commit.Artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("id", artifact.Id);
                writer.WriteString("leaf", artifact.Leaf);
                writer.WriteString(
                    "kind",
                    artifact.Kind == ArtifactIdentityKind.Tree ? "tree" : "file");
                writer.WritePropertyName("identity");
                writer.WriteStartObject();
                if (artifact.Identity is TreeIdentity tree)
                {
                    writer.WriteString("kind", "tree");
                    writer.WriteString("manifestSha256", tree.ManifestSha256);
                    writer.WriteNumber("fileCount", tree.FileCount);
                    writer.WriteNumber("totalBytes", tree.TotalBytes);
                }
                else if (artifact.Identity is FileIdentity file)
                {
                    writer.WriteString("kind", "file");
                    writer.WriteString("sha256", file.Sha256);
                    writer.WriteNumber("length", file.Length);
                }
                else
                {
                    throw Failure("release-commit-invalid", "A release identity kind is invalid.");
                }

                writer.WriteEndObject();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        var newline = Encoding.UTF8.GetBytes(Environment.NewLine);
        var result = new byte[checked(buffer.WrittenCount + newline.Length)];
        buffer.WrittenSpan.CopyTo(result);
        newline.CopyTo(result.AsSpan(buffer.WrittenCount));
        return result;
    }

    private static TreeSnapshot CaptureTreeSnapshot(
        string root,
        string code,
        TreeCaptureLimits? requestedLimits = null,
        Action<string>? hashStarted = null,
        Func<string, IEnumerable<FileSystemInfo>>? enumerateDirectory = null)
    {
        var limits = requestedLimits ?? DefaultTreeCaptureLimits;
        Func<string, IEnumerable<FileSystemInfo>> enumerate = enumerateDirectory ??
            (static directory => new DirectoryInfo(directory).EnumerateFileSystemInfos());
        var fullRoot = ValidateExistingDirectory(root, code);
        var directories = new Stack<string>();
        directories.Push(fullRoot);
        var directoryCount = 1;
        var entries = new List<TreeEntry>();
        var ordinalPaths = new HashSet<string>(StringComparer.Ordinal);
        var ignoreCasePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalBytes = 0;
        while (directories.Count != 0)
        {
            var directory = directories.Pop();
            try
            {
                foreach (var child in enumerate(directory))
                {
                    FileAttributes attributes;
                    try
                    {
                        attributes = child.Attributes;
                    }
                    catch (Exception exception)
                    {
                        throw Failure(code, "A release tree entry could not be inspected.", exception);
                    }

                    if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                    {
                        throw Failure(code, "The release tree contains a reparse or device entry.");
                    }

                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (directoryCount >= limits.MaximumDirectories)
                        {
                            throw Failure(code, "The release tree exceeds its directory bound.");
                        }

                        directoryCount++;
                        directories.Push(child.FullName);
                        continue;
                    }

                    if (entries.Count >= limits.MaximumFiles)
                    {
                        throw Failure(code, "The release tree exceeds its file-count bound.");
                    }

                    var relativePath = Path.GetRelativePath(fullRoot, child.FullName).Replace('\\', '/');
                    ValidateContentPath(relativePath, code);
                    if (!ordinalPaths.Add(relativePath) || !ignoreCasePaths.Add(relativePath))
                    {
                        throw Failure(code, "The release tree contains a duplicate or case-colliding path.");
                    }

                    var remainingTreeBytes = checked(limits.MaximumTreeBytes - totalBytes);
                    var maximumFileBytes = Math.Min(
                        limits.MaximumSingleFileBytes,
                        remainingTreeBytes);
                    var identity = CaptureFileIdentity(
                        child.FullName,
                        maximumFileBytes,
                        code,
                        hashStarted);
                    totalBytes = checked(totalBytes + identity.Length);
                    entries.Add(new TreeEntry(relativePath, identity.Length, identity.Sha256));
                }
            }
            catch (VerifiedLocalReleaseException)
            {
                throw;
            }
            catch (Exception exception)
            {
                throw Failure(code, "The release tree could not be enumerated.", exception);
            }
        }

        entries.Sort((left, right) => StringComparer.Ordinal.Compare(left.Path, right.Path));
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var pathLength = new byte[sizeof(int)];
        var fileLength = new byte[sizeof(long)];
        foreach (var entry in entries)
        {
            var pathBytes = Encoding.UTF8.GetBytes(entry.Path);
            if (pathBytes.Length is <= 0 or > MaximumRelativePathBytes)
            {
                throw Failure(code, "A release tree path exceeds its UTF-8 bound.");
            }

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
                entries.Count,
                totalBytes));
    }

    private static FileIdentity CaptureFileIdentity(
        string path,
        long maximumBytes,
        string code,
        Action<string>? hashStarted = null)
    {
        FileStream? stream = null;
        try
        {
            stream = OpenReadLease(path, allowEmpty: false, code);
            if (stream.Length > maximumBytes)
            {
                throw Failure(code, "A release file exceeds its byte bound.");
            }

            var length = stream.Length;
            stream.Position = 0;
            hashStarted?.Invoke(path);
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            if (stream.Length != length || stream.Position != length)
            {
                throw Failure(code, "A release file changed while it was being hashed.");
            }

            return new FileIdentity(hash, length);
        }
        catch (VerifiedLocalReleaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(code, "A release file could not be verified.", exception);
        }
        finally
        {
            stream?.Dispose();
        }
    }

    private static void VerifyArchive(string path, TreeSnapshot expected, string code)
    {
        var expectedByPath = expected.Entries.ToDictionary(entry => entry.Path, StringComparer.Ordinal);

        try
        {
            using var file = OpenReadLease(path, allowEmpty: false, code);
            PreflightCanonicalArchive(file, expected, code);
            using var archive = new ZipArchive(file, ZipArchiveMode.Read, leaveOpen: false);
            if (archive.Entries.Count != expected.Entries.Count)
            {
                throw Failure(code, "The release archive entry count differs from its committed tree.");
            }

            var rawNames = new HashSet<string>(StringComparer.Ordinal);
            var rawNamesIgnoreCase = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var entryPathsIgnoreCase = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenFiles = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in archive.Entries)
            {
                var rawName = entry.FullName;
                if (string.IsNullOrEmpty(rawName) ||
                    rawName.Contains('\\') ||
                    rawName.Contains(':') ||
                    rawName.IndexOf('\0') >= 0 ||
                    rawName.StartsWith("/", StringComparison.Ordinal) ||
                    !rawNames.Add(rawName) ||
                    !rawNamesIgnoreCase.Add(rawName))
                {
                    throw Failure(code, "The release archive contains a noncanonical entry.");
                }

                if (rawName.EndsWith("/", StringComparison.Ordinal))
                {
                    throw Failure(code, "The release archive contains an unexpected directory.");
                }

                var entryPath = rawName;
                ValidateContentPath(entryPath, code);
                if (!entryPathsIgnoreCase.Add(entryPath))
                {
                    throw Failure(code, "The release archive contains a case-colliding entry.");
                }

                if (!seenFiles.Add(entryPath) ||
                    !expectedByPath.TryGetValue(entryPath, out var expectedEntry) ||
                    entry.Length != expectedEntry.Length)
                {
                    throw Failure(code, "The release archive file membership or length differs.");
                }

                using var stream = entry.Open();
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[64 * 1024];
                long total = 0;
                while (true)
                {
                    var read = stream.Read(buffer, 0, buffer.Length);
                    if (read == 0)
                    {
                        break;
                    }

                    total = checked(total + read);
                    if (total > expectedEntry.Length)
                    {
                        throw Failure(code, "A release archive entry exceeds its committed length.");
                    }

                    hash.AppendData(buffer, 0, read);
                }

                var actualHash = Convert.ToHexString(hash.GetHashAndReset());
                if (total != expectedEntry.Length ||
                    !string.Equals(actualHash, expectedEntry.Sha256, StringComparison.Ordinal))
                {
                    throw Failure(code, "A release archive entry differs from its committed tree.");
                }
            }

            if (seenFiles.Count != expected.Entries.Count)
            {
                throw Failure(code, "The release archive file count differs from its committed tree.");
            }
        }
        catch (VerifiedLocalReleaseException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException)
        {
            throw Failure(code, "The release archive could not be verified.", exception);
        }
    }

    private static void PreflightCanonicalArchive(
        FileStream file,
        TreeSnapshot expected,
        string code)
    {
        try
        {
            if (expected.Entries.Count is <= 0 or > MaximumTreeFiles ||
                file.Length < ZipEndOfCentralDirectoryFixedBytes)
            {
                throw Failure(code, "The release archive has an invalid entry count or length.");
            }

            var tailLength = checked((int)Math.Min(
                file.Length,
                ZipEndOfCentralDirectoryMaximumSearchBytes));
            var tail = ArrayPool<byte>.Shared.Rent(tailLength);
            long endRecordOffset;
            ushort entryCount;
            uint centralDirectorySize;
            uint centralDirectoryOffset;
            try
            {
                file.Position = checked(file.Length - tailLength);
                file.ReadExactly(tail.AsSpan(0, tailLength));
                var endRecordIndex = -1;
                for (var index = tailLength - ZipEndOfCentralDirectoryFixedBytes;
                     index >= 0;
                     index--)
                {
                    var candidate = tail.AsSpan(
                        index,
                        ZipEndOfCentralDirectoryFixedBytes);
                    if (BinaryPrimitives.ReadUInt32LittleEndian(candidate) !=
                        ZipEndOfCentralDirectorySignature)
                    {
                        continue;
                    }

                    var candidateCommentLength =
                        BinaryPrimitives.ReadUInt16LittleEndian(candidate[20..]);
                    if (index + ZipEndOfCentralDirectoryFixedBytes + candidateCommentLength ==
                        tailLength)
                    {
                        endRecordIndex = index;
                        break;
                    }
                }

                if (endRecordIndex < 0)
                {
                    throw Failure(code, "The release archive has no bounded end record.");
                }

                var endRecord = tail.AsSpan(
                    endRecordIndex,
                    ZipEndOfCentralDirectoryFixedBytes);
                var diskNumber = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[4..]);
                var centralDirectoryDisk = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[6..]);
                var entriesOnDisk = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[8..]);
                entryCount = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[10..]);
                centralDirectorySize = BinaryPrimitives.ReadUInt32LittleEndian(endRecord[12..]);
                centralDirectoryOffset = BinaryPrimitives.ReadUInt32LittleEndian(endRecord[16..]);
                var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(endRecord[20..]);
                endRecordOffset = checked(file.Length - tailLength + endRecordIndex);

                if (commentLength != 0)
                {
                    throw Failure(code, "The release archive contains a comment or trailing bytes.");
                }
                if (entriesOnDisk == ushort.MaxValue || entryCount == ushort.MaxValue ||
                    centralDirectorySize == uint.MaxValue || centralDirectoryOffset == uint.MaxValue)
                {
                    throw Failure(code, "The release archive uses unsupported ZIP64 metadata.");
                }
                if (diskNumber != 0 || centralDirectoryDisk != 0 || entriesOnDisk != entryCount)
                {
                    throw Failure(code, "The release archive spans multiple disks.");
                }
                if (entryCount != expected.Entries.Count || entryCount > MaximumTreeFiles)
                {
                    throw Failure(code, "The release archive has an invalid entry count.");
                }
                if (centralDirectorySize > MaximumArchiveCentralDirectoryBytes)
                {
                    throw Failure(code, "The release archive exceeds its central directory byte bound.");
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tail, clearArray: true);
            }

            if (endRecordOffset >= 20)
            {
                var locatorSignature = new byte[sizeof(uint)];
                file.Position = endRecordOffset - 20;
                file.ReadExactly(locatorSignature);
                if (BinaryPrimitives.ReadUInt32LittleEndian(locatorSignature) ==
                    Zip64EndOfCentralDirectoryLocatorSignature)
                {
                    throw Failure(code, "The release archive uses unsupported ZIP64 metadata.");
                }
            }

            var centralDirectoryEnd = checked(
                (long)centralDirectoryOffset + centralDirectorySize);
            if (centralDirectoryEnd != endRecordOffset)
            {
                throw Failure(code, "The release archive has a noncanonical central directory extent.");
            }

            var centralEntries = new ArchiveCentralEntry[entryCount];
            var centralHeader = new byte[ZipCentralDirectoryHeaderFixedBytes];
            var nameBuffer = ArrayPool<byte>.Shared.Rent(MaximumRelativePathBytes);
            try
            {
                file.Position = centralDirectoryOffset;
                uint previousLocalHeaderOffset = 0;
                for (var index = 0; index < centralEntries.Length; index++)
                {
                    if (checked(file.Position + ZipCentralDirectoryHeaderFixedBytes) >
                        centralDirectoryEnd)
                    {
                        throw Failure(code, "The release archive central directory ended early.");
                    }

                    file.ReadExactly(centralHeader);
                    var header = centralHeader.AsSpan();
                    if (BinaryPrimitives.ReadUInt32LittleEndian(header) !=
                        ZipCentralDirectoryHeaderSignature)
                    {
                        throw Failure(code, "The release archive central directory header is invalid.");
                    }

                    var versionNeeded = BinaryPrimitives.ReadUInt16LittleEndian(header[6..]);
                    var flags = BinaryPrimitives.ReadUInt16LittleEndian(header[8..]);
                    var method = BinaryPrimitives.ReadUInt16LittleEndian(header[10..]);
                    var dosTime = BinaryPrimitives.ReadUInt16LittleEndian(header[12..]);
                    var dosDate = BinaryPrimitives.ReadUInt16LittleEndian(header[14..]);
                    var crc32 = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
                    var compressedSize = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);
                    var uncompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(header[24..]);
                    var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(header[28..]);
                    var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(header[30..]);
                    var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(header[32..]);
                    var startingDisk = BinaryPrimitives.ReadUInt16LittleEndian(header[34..]);
                    var localHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(header[42..]);
                    var expectedEntry = expected.Entries[index];
                    var expectedName = Encoding.UTF8.GetBytes(expectedEntry.Path);
                    var expectedFlags = expectedEntry.Path.Any(character => character > 0x7F)
                        ? ZipUtf8Flag
                        : (ushort)0;

                    if (versionNeeded != 20 || flags != expectedFlags)
                    {
                        throw Failure(code, "The release archive central directory has invalid flags or version.");
                    }
                    if (method != ZipDeflateMethod || dosTime != ZipCanonicalDosTime ||
                        dosDate != ZipCanonicalDosDate)
                    {
                        throw Failure(code, "The release archive entry is not canonically compressed or timestamped.");
                    }
                    if (nameLength is <= 0 or > MaximumRelativePathBytes)
                    {
                        throw Failure(code, "The release archive entry name exceeds its byte bound.");
                    }
                    if (extraLength != 0 || commentLength != 0)
                    {
                        throw Failure(code, "The release archive contains variable entry metadata.");
                    }
                    if (startingDisk != 0)
                    {
                        throw Failure(code, "The release archive entry spans multiple disks.");
                    }
                    if (compressedSize == uint.MaxValue || uncompressedSize == uint.MaxValue ||
                        localHeaderOffset == uint.MaxValue)
                    {
                        throw Failure(code, "The release archive uses unsupported ZIP64 entry metadata.");
                    }
                    if (nameLength != expectedName.Length ||
                        uncompressedSize != expectedEntry.Length)
                    {
                        throw Failure(code, "The release archive entry identity differs from its committed tree.");
                    }
                    if (localHeaderOffset >= centralDirectoryOffset ||
                        index == 0 && localHeaderOffset != 0 ||
                        index > 0 && localHeaderOffset <= previousLocalHeaderOffset)
                    {
                        throw Failure(code, "The release archive local-header order is invalid.");
                    }
                    if (checked(file.Position + nameLength) > centralDirectoryEnd)
                    {
                        throw Failure(code, "The release archive central directory entry exceeds its extent.");
                    }

                    file.ReadExactly(nameBuffer.AsSpan(0, nameLength));
                    if (!nameBuffer.AsSpan(0, nameLength).SequenceEqual(expectedName))
                    {
                        throw Failure(code, "The release archive entry name differs from its committed path.");
                    }

                    centralEntries[index] = new ArchiveCentralEntry(
                        flags,
                        crc32,
                        compressedSize,
                        uncompressedSize,
                        localHeaderOffset,
                        nameLength);
                    previousLocalHeaderOffset = localHeaderOffset;
                }

                if (file.Position != centralDirectoryEnd)
                {
                    throw Failure(code, "The release archive has a noncanonical central directory extent.");
                }

                var localHeader = new byte[ZipLocalFileHeaderFixedBytes];
                for (var index = 0; index < centralEntries.Length; index++)
                {
                    var centralEntry = centralEntries[index];
                    var expectedEntry = expected.Entries[index];
                    var expectedName = Encoding.UTF8.GetBytes(expectedEntry.Path);
                    file.Position = centralEntry.LocalHeaderOffset;
                    if (checked(file.Position + ZipLocalFileHeaderFixedBytes) >
                        centralDirectoryOffset)
                    {
                        throw Failure(code, "The release archive local-header layout is invalid.");
                    }

                    file.ReadExactly(localHeader);
                    var header = localHeader.AsSpan();
                    if (BinaryPrimitives.ReadUInt32LittleEndian(header) !=
                        ZipLocalFileHeaderSignature ||
                        BinaryPrimitives.ReadUInt16LittleEndian(header[4..]) != 20 ||
                        BinaryPrimitives.ReadUInt16LittleEndian(header[6..]) != centralEntry.Flags ||
                        BinaryPrimitives.ReadUInt16LittleEndian(header[8..]) != ZipDeflateMethod ||
                        BinaryPrimitives.ReadUInt16LittleEndian(header[10..]) != ZipCanonicalDosTime ||
                        BinaryPrimitives.ReadUInt16LittleEndian(header[12..]) != ZipCanonicalDosDate ||
                        BinaryPrimitives.ReadUInt32LittleEndian(header[14..]) != centralEntry.Crc32 ||
                        BinaryPrimitives.ReadUInt32LittleEndian(header[18..]) != centralEntry.CompressedSize ||
                        BinaryPrimitives.ReadUInt32LittleEndian(header[22..]) != centralEntry.UncompressedSize ||
                        BinaryPrimitives.ReadUInt16LittleEndian(header[26..]) != centralEntry.NameLength ||
                        BinaryPrimitives.ReadUInt16LittleEndian(header[28..]) != 0)
                    {
                        throw Failure(code, "The release archive local-header layout is invalid.");
                    }

                    file.ReadExactly(nameBuffer.AsSpan(0, centralEntry.NameLength));
                    if (!nameBuffer.AsSpan(0, centralEntry.NameLength).SequenceEqual(expectedName))
                    {
                        throw Failure(code, "The release archive local-header name is invalid.");
                    }

                    var nextOffset = checked(
                        (long)centralEntry.LocalHeaderOffset +
                        ZipLocalFileHeaderFixedBytes +
                        centralEntry.NameLength +
                        centralEntry.CompressedSize);
                    var expectedNextOffset = index + 1 < centralEntries.Length
                        ? centralEntries[index + 1].LocalHeaderOffset
                        : centralDirectoryOffset;
                    if (nextOffset != expectedNextOffset)
                    {
                        throw Failure(code, "The release archive local-header layout is invalid.");
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(nameBuffer, clearArray: true);
            }
        }
        catch (OverflowException exception)
        {
            throw Failure(code, "The release archive layout exceeds its numeric bounds.", exception);
        }
        finally
        {
            file.Position = 0;
        }
    }

    private static void VerifyChecksum(
        string path,
        FileIdentity runtimeZip,
        FileIdentity sourceZip)
    {
        var expected =
            runtimeZip.Sha256.ToLowerInvariant() + "  " + RuntimeZipLeaf + Environment.NewLine +
            sourceZip.Sha256.ToLowerInvariant() + "  " + SourceZipLeaf + Environment.NewLine;
        byte[] bytes;
        try
        {
            using var stream = OpenReadLease(path, allowEmpty: false, "release-checksum-invalid");
            bytes = ReadBoundedBytes(stream, MaximumCommitBytes, "release-checksum-invalid");
        }
        catch (VerifiedLocalReleaseException)
        {
            throw;
        }

        var expectedBytes = new UTF8Encoding(false, true).GetBytes(expected);
        if (!bytes.AsSpan().SequenceEqual(expectedBytes))
        {
            throw Failure(
                "release-checksum-mismatch",
                "The release checksum file does not identify the two committed archives.");
        }
    }

    private static WindowsRetainedReleaseArtifacts CaptureRole(
        string runtimeRoot,
        RoleArtifactPlan plan,
        string code)
    {
        try
        {
            return WindowsRetainedReleaseArtifacts.Capture(
                runtimeRoot,
                plan.Role,
                plan.AppHostRelativePath,
                plan.ManagedEntryRelativePath,
                plan.DepsRelativePath,
                plan.RuntimeConfigRelativePath,
                plan.Artifacts);
        }
        catch (Exception exception)
        {
            throw Failure(code, "The release role artifacts could not be retained.", exception);
        }
    }

    private static WindowsRetainedReleaseTreeV1 CaptureRuntimeTree(
        string runtimeRoot,
        TreeSnapshot snapshot)
    {
        try
        {
            return WindowsRetainedReleaseTreeV1.Capture(
                runtimeRoot,
                snapshot.Entries.Select(entry =>
                        new WindowsRetainedReleaseTreeFileV1(
                            entry.Path,
                            entry.Length,
                            entry.Sha256))
                    .ToArray());
        }
        catch (Exception exception)
        {
            throw Failure(
                "release-runtime-invalid",
                "The complete runtime tree could not be retained.",
                exception);
        }
    }

    private static void EnsureRolePlanPresent(TreeSnapshot snapshot, RoleArtifactPlan plan, string code)
    {
        var paths = snapshot.Entries.Select(entry => entry.Path).ToHashSet(StringComparer.Ordinal);
        foreach (var artifact in plan.Artifacts)
        {
            if (!paths.Contains(artifact.RelativePath.Replace('\\', '/')))
            {
                throw Failure(code, "The formal runtime lacks the fixed " + plan.Role + " artifact set.");
            }
        }
    }

    private static void EnsureCanonicalRuntimeConfigDevFiles(TreeSnapshot snapshot)
    {
        foreach (var relativePath in new[]
                 {
                     GuardianRuntimeConfigDevRelativePath,
                     BrokerRuntimeConfigDevRelativePath
                 })
        {
            var matches = snapshot.Entries
                .Where(entry => string.Equals(entry.Path, relativePath, StringComparison.Ordinal))
                .ToArray();
            if (matches.Length != 1 ||
                matches[0].Length != CanonicalRuntimeConfigDevLength ||
                !string.Equals(
                    matches[0].Sha256,
                    CanonicalRuntimeConfigDevSha256,
                    StringComparison.Ordinal))
            {
                throw Failure(
                    "release-runtime-config-dev-invalid",
                    "The formal runtime does not contain the exact closed runtimeconfig.dev.json bytes.");
            }
        }
    }

    private static void AssertCapturedRoleMatchesSnapshot(
        WindowsRetainedReleaseArtifacts captured,
        TreeSnapshot snapshot,
        string code)
    {
        var expected = snapshot.Entries.ToDictionary(entry => entry.Path, StringComparer.Ordinal);
        foreach (var artifact in captured.Artifacts)
        {
            var path = artifact.RelativePath.Replace('\\', '/');
            if (!expected.TryGetValue(path, out var entry) ||
                artifact.Length != entry.Length ||
                !string.Equals(artifact.Sha256, entry.Sha256, StringComparison.Ordinal))
            {
                throw Failure(code, "A retained role artifact differs from the committed runtime tree.");
            }
        }
    }

    private static VerifiedReleaseRoleArtifacts CreateRoleDefinition(
        WindowsRetainedReleaseArtifacts artifacts) =>
        new(
            artifacts.Role,
            artifacts.AppHostRelativePath,
            artifacts.ManagedEntryRelativePath,
            artifacts.DepsRelativePath,
            artifacts.RuntimeConfigRelativePath,
            artifacts.Artifacts);

    private static void AssertSameReleaseRoot(
        WindowsReleaseRootIdentity guardian,
        WindowsReleaseRootIdentity broker)
    {
        if (!WindowsPeerNative.SamePath(guardian.FinalPath, broker.FinalPath) ||
            guardian.Attributes != broker.Attributes ||
            guardian.VolumeSerialNumber != broker.VolumeSerialNumber ||
            !string.Equals(guardian.FileId, broker.FileId, StringComparison.OrdinalIgnoreCase) ||
            !guardian.TraversalIsReparseFree ||
            !broker.TraversalIsReparseFree)
        {
            throw Failure(
                "release-role-root-mismatch",
                "Guardian and Broker were not retained from one exact formal runtime root.");
        }
    }

    private static void AssertSettled(string outputsRoot, string journalPath)
    {
        if (File.Exists(journalPath) || Directory.Exists(journalPath))
        {
            throw Failure(
                "release-transaction-in-progress",
                "A formal release transaction journal is present.");
        }

        foreach (var entry in new DirectoryInfo(outputsRoot).EnumerateFileSystemInfos())
        {
            var name = entry.Name;
            if (IsTransientName(name))
            {
                throw Failure(
                    "release-workspace-unsettled",
                    "The formal outputs contain pending release state: " + name);
            }
        }
    }

    private static bool IsTransientName(string name) =>
        name.StartsWith(
            ".CodexGuardian-release-manifest.pending.",
            StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith(
            ".CodexGuardian-release-transaction.json.tmp-",
            StringComparison.OrdinalIgnoreCase) ||
        name.Contains(".discard.", StringComparison.OrdinalIgnoreCase) ||
        new[]
        {
            "CodexGuardian-win-x64.next",
            "CodexGuardian-win-x64.previous",
            "CodexGuardian-source.next",
            "CodexGuardian-source.previous",
            "CodexGuardian-win-x64.next.zip",
            "CodexGuardian-win-x64.previous.zip",
            "CodexGuardian-source.next.zip",
            "CodexGuardian-source.previous.zip",
            "SHA256SUMS.next.txt",
            "SHA256SUMS.previous.txt"
        }.Contains(name, StringComparer.OrdinalIgnoreCase);

    private static FileStream OpenReadLease(string path, bool allowEmpty, string code)
    {
        var fullPath = ValidateRegularFile(path, code);
        try
        {
            var stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.SequentialScan);
            if (!allowEmpty && stream.Length <= 0)
            {
                stream.Dispose();
                throw Failure(code, "A required release file is empty.");
            }

            return stream;
        }
        catch (VerifiedLocalReleaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(code, "A required release file could not be opened read-only.", exception);
        }
    }

    private static byte[] ReadBoundedBytes(FileStream stream, int maximumBytes, string code)
    {
        if (stream.Length <= 0 || stream.Length > maximumBytes)
        {
            throw Failure(code, "A release state file is outside its byte bound.");
        }

        stream.Position = 0;
        var bytes = new byte[checked((int)stream.Length)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read == 0)
            {
                throw Failure(code, "A release state file ended before its bounded length.");
            }

            offset += read;
        }

        if (stream.Length != bytes.Length)
        {
            throw Failure(code, "A release state file changed while it was read.");
        }

        return bytes;
    }

    private static string ValidateExistingDirectory(string path, string code)
    {
        var fullPath = CanonicalizeLocalPath(path, code);
        try
        {
            var attributes = File.GetAttributes(fullPath);
            if ((attributes & FileAttributes.Directory) == 0 ||
                (attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            {
                throw Failure(code, "A release directory is not a regular non-reparse directory.");
            }

            AssertNoReparseTraversal(fullPath, code);
            return fullPath;
        }
        catch (VerifiedLocalReleaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(code, "A required release directory is unavailable.", exception);
        }
    }

    private static string ValidateRegularFile(string path, string code)
    {
        var fullPath = CanonicalizeLocalPath(path, code);
        try
        {
            var attributes = File.GetAttributes(fullPath);
            if ((attributes & UnsafeAttributes) != 0)
            {
                throw Failure(code, "A release file is not a regular non-reparse file.");
            }

            AssertNoReparseTraversal(fullPath, code);
            return fullPath;
        }
        catch (VerifiedLocalReleaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(code, "A required release file is unavailable.", exception);
        }
    }

    private static string CanonicalizeLocalPath(string path, string code)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32767)
        {
            throw Failure(code, "A release path is empty or unbounded.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception)
        {
            throw Failure(code, "A release path is invalid.", exception);
        }

        var volumeRoot = Path.GetPathRoot(fullPath);
        if (fullPath.StartsWith("\\\\", StringComparison.Ordinal) ||
            volumeRoot is null ||
            volumeRoot.Length != 3 ||
            volumeRoot[1] != Path.VolumeSeparatorChar ||
            string.Equals(
                Path.TrimEndingDirectorySeparator(fullPath),
                Path.TrimEndingDirectorySeparator(volumeRoot),
                StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(code, "A release path must be a non-root local-drive path.");
        }

        return Path.TrimEndingDirectorySeparator(fullPath);
    }

    private static void AssertNoReparseTraversal(string path, string code)
    {
        FileSystemInfo? current = Directory.Exists(path)
            ? new DirectoryInfo(path)
            : new FileInfo(path);
        while (current is not null)
        {
            if ((current.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            {
                throw Failure(code, "A release path traverses a reparse or device entry.");
            }

            current = current switch
            {
                FileInfo file => file.Directory,
                DirectoryInfo directory => directory.Parent,
                _ => null
            };
        }
    }

    private static string GetFixedChild(string root, string leaf)
    {
        var path = Path.GetFullPath(Path.Combine(root, leaf));
        if (!string.Equals(
                Path.GetDirectoryName(path),
                root,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(path), leaf, StringComparison.Ordinal))
        {
            throw Failure("release-layout-invalid", "A fixed release path escaped its outputs root.");
        }

        return path;
    }

    private static void ValidateContentPath(string path, string code)
    {
        if (string.IsNullOrEmpty(path) ||
            path.StartsWith("/", StringComparison.Ordinal) ||
            path.EndsWith("/", StringComparison.Ordinal) ||
            path.Contains('\\') ||
            path.Contains(':') ||
            path.IndexOf('\0') >= 0 ||
            path.Split('/').Any(component => component is "" or "." or ".."))
        {
            throw Failure(code, "A release content path is not canonical.");
        }
    }

    private static JsonElement RequireObject(JsonElement value, string code)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Failure(code, "A release JSON value is not an object.");
        }

        return value;
    }

    private static Dictionary<string, JsonElement> RequireExactProperties(
        JsonElement value,
        IReadOnlyCollection<string> expected,
        string code)
    {
        var properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!properties.TryAdd(property.Name, property.Value))
            {
                throw Failure(code, "A release JSON property is duplicated.");
            }
        }

        if (properties.Count != expected.Count ||
            !properties.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(expected))
        {
            throw Failure(code, "A release JSON object has an unsupported property set.");
        }

        return properties;
    }

    private static string ReadString(JsonElement value, int maximumLength, string code)
    {
        if (value.ValueKind != JsonValueKind.String)
        {
            throw Failure(code, "A release JSON property is not a string.");
        }

        var text = value.GetString();
        if (string.IsNullOrEmpty(text) || text.Length > maximumLength || text.Any(character => character > 0x7F))
        {
            throw Failure(code, "A release JSON string is empty, non-ASCII, or unbounded.");
        }

        return text;
    }

    private static string ReadIdentifier(JsonElement value)
    {
        var text = ReadString(value, 32, "release-commit-invalid");
        if (text.Length != 32 || text.Any(character =>
                !(character is >= '0' and <= '9') &&
                !(character is >= 'a' and <= 'f')))
        {
            throw Failure("release-commit-invalid", "A release identifier is not canonical.");
        }

        return text;
    }

    private static string ReadSha256(JsonElement value)
    {
        var text = ReadString(value, 64, "release-commit-invalid");
        if (text.Length != 64 || text.Any(character =>
                !(character is >= '0' and <= '9') &&
                !(character is >= 'A' and <= 'F')))
        {
            throw Failure("release-commit-invalid", "A release SHA-256 value is not canonical.");
        }

        return text;
    }

    private static long ReadNonnegativeInt64(JsonElement value, string code)
    {
        if (value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt64(out var result) ||
            result < 0)
        {
            throw Failure(code, "A release JSON integer is invalid or negative.");
        }

        return result;
    }

    private static string ReadCanonicalTimestamp(JsonElement value)
    {
        var text = ReadString(value, 64, "release-commit-invalid");
        if (!DateTimeOffset.TryParseExact(
                text,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var parsed) ||
            !string.Equals(
                parsed.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                text,
                StringComparison.Ordinal))
        {
            throw Failure("release-commit-invalid", "The release timestamp is not canonical UTC.");
        }

        return text;
    }

    private static void AssertTreeIdentity(TreeSnapshot actual, TreeIdentity expected, string code)
    {
        if (actual.Identity != expected)
        {
            throw Failure(code, "A formal release tree does not match its commit identity.");
        }
    }

    private static void AssertCommittedTreeBounds(TreeIdentity identity, string id)
    {
        if (identity.FileCount is < 1 or > MaximumTreeFiles ||
            identity.TotalBytes is < 1 or > MaximumTreeBytes ||
            identity.TotalBytes < identity.FileCount)
        {
            throw Failure(
                "release-commit-invalid",
                "The committed " + id + " identity is outside the fixed tree bounds.");
        }
    }

    private static void AssertCommittedFileBounds(
        FileIdentity identity,
        long maximumBytes,
        string id)
    {
        if (identity.Length is < 1 || identity.Length > maximumBytes)
        {
            throw Failure(
                "release-commit-invalid",
                "The committed " + id + " identity is outside the fixed file bound.");
        }
    }

    private static TreeCaptureLimits CreateCommittedTreeCaptureLimits(TreeIdentity identity) =>
        new(
            checked((int)identity.FileCount),
            MaximumTreeDirectories,
            identity.TotalBytes,
            Math.Min(identity.TotalBytes, MaximumSingleTreeFileBytes));

    private static TreeCaptureLimits CreateTreeCaptureLimits(
        int maximumFiles,
        int maximumDirectories,
        long maximumTreeBytes,
        long maximumSingleFileBytes)
    {
        if (maximumFiles is < 1 or > MaximumTreeFiles ||
            maximumDirectories is < 1 or > MaximumTreeDirectories ||
            maximumTreeBytes is < 1 or > MaximumTreeBytes ||
            maximumSingleFileBytes is < 1 or > MaximumSingleTreeFileBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumFiles),
                "Tree capture test bounds must stay within the production limits.");
        }

        return new TreeCaptureLimits(
            maximumFiles,
            maximumDirectories,
            maximumTreeBytes,
            maximumSingleFileBytes);
    }

    private static void AssertFileIdentity(FileIdentity actual, FileIdentity expected, string code)
    {
        if (actual != expected)
        {
            throw Failure(code, "A formal release file does not match its commit identity.");
        }
    }

    private static void DisposeOwned(IDisposable? value, ICollection<Exception> failures)
    {
        if (value is null)
        {
            return;
        }

        try
        {
            value.Dispose();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Verified local release identity requires Windows native file identities.");
        }
    }

    private static VerifiedLocalReleaseException Failure(
        string code,
        string message,
        Exception? innerException = null) =>
        innerException is null
            ? new VerifiedLocalReleaseException(code, message)
            : new VerifiedLocalReleaseException(code, message, innerException);

    private enum ArtifactIdentityKind
    {
        Tree,
        File
    }

    private abstract record ArtifactIdentity;

    private sealed record TreeIdentity(
        string ManifestSha256,
        long FileCount,
        long TotalBytes) : ArtifactIdentity;

    private sealed record FileIdentity(string Sha256, long Length) : ArtifactIdentity;

    private sealed record ArtifactDescriptor(
        string Id,
        string Leaf,
        ArtifactIdentityKind Kind);

    private sealed record CommitArtifact(
        string Id,
        string Leaf,
        ArtifactIdentityKind Kind,
        ArtifactIdentity Identity);

    private sealed record CommitDocument(
        string GenerationId,
        string TransactionId,
        string CommittedUtc,
        string ProjectVersion,
        IReadOnlyList<CommitArtifact> Artifacts);

    private sealed class ParsedCommit
    {
        internal ParsedCommit(CommitDocument document, string commitSha256)
        {
            Document = document;
            CommitSha256 = commitSha256;
        }

        internal CommitDocument Document { get; }

        internal string GenerationId => Document.GenerationId;

        internal string CommitSha256 { get; }

        internal TreeIdentity GetTree(string id) =>
            Document.Artifacts.Single(artifact => artifact.Id == id).Identity as TreeIdentity ??
            throw Failure("release-commit-invalid", "A committed tree identity is missing.");

        internal FileIdentity GetFile(string id) =>
            Document.Artifacts.Single(artifact => artifact.Id == id).Identity as FileIdentity ??
            throw Failure("release-commit-invalid", "A committed file identity is missing.");
    }

    private sealed record TreeEntry(string Path, long Length, string Sha256);

    private readonly record struct ArchiveCentralEntry(
        ushort Flags,
        uint Crc32,
        uint CompressedSize,
        uint UncompressedSize,
        uint LocalHeaderOffset,
        ushort NameLength);

    private sealed record TreeCaptureLimits(
        int MaximumFiles,
        int MaximumDirectories,
        long MaximumTreeBytes,
        long MaximumSingleFileBytes);

    private sealed class TreeSnapshot
    {
        internal TreeSnapshot(IReadOnlyList<TreeEntry> entries, TreeIdentity identity)
        {
            Entries = entries;
            Identity = identity;
        }

        internal IReadOnlyList<TreeEntry> Entries { get; }

        internal TreeIdentity Identity { get; }

        internal bool EqualsExact(TreeSnapshot other) =>
            Identity == other.Identity && Entries.SequenceEqual(other.Entries);
    }

    private sealed record RoleArtifactPlan(
        BrokerPeerRole Role,
        string AppHostRelativePath,
        string ManagedEntryRelativePath,
        string DepsRelativePath,
        string RuntimeConfigRelativePath,
        IReadOnlyList<WindowsReleaseArtifactPath> Artifacts);
}
