using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace CodexGuardian.Trust;

public sealed record WindowsReleaseArtifactPath(
    ReleaseArtifactKind Kind,
    string RelativePath);

public sealed class WindowsRetainedReleaseArtifacts : IDisposable
{
    private const long MaximumArtifactBytes = 256L * 1024 * 1024;
    private readonly object _sync = new();
    private Dictionary<string, SafeFileHandle>? _directoryHandles;
    private Dictionary<string, SafeFileHandle>? _artifactHandles;

    private WindowsRetainedReleaseArtifacts(
        BrokerPeerRole role,
        string appHostRelativePath,
        string managedEntryRelativePath,
        string depsRelativePath,
        string runtimeConfigRelativePath,
        WindowsReleaseRootIdentity root,
        IReadOnlyList<WindowsArtifactIdentity> artifacts,
        Dictionary<string, SafeFileHandle> directoryHandles,
        Dictionary<string, SafeFileHandle> artifactHandles)
    {
        Role = role;
        AppHostRelativePath = appHostRelativePath;
        ManagedEntryRelativePath = managedEntryRelativePath;
        DepsRelativePath = depsRelativePath;
        RuntimeConfigRelativePath = runtimeConfigRelativePath;
        Root = root;
        Artifacts = Array.AsReadOnly(artifacts.ToArray());
        _directoryHandles = directoryHandles;
        _artifactHandles = artifactHandles;
    }

    public BrokerPeerRole Role { get; }

    public string AppHostRelativePath { get; }

    public string ManagedEntryRelativePath { get; }

    public string DepsRelativePath { get; }

    public string RuntimeConfigRelativePath { get; }

    public WindowsReleaseRootIdentity Root { get; }

    public IReadOnlyList<WindowsArtifactIdentity> Artifacts { get; }

    public static WindowsRetainedReleaseArtifacts Capture(
        string releaseRootPath,
        BrokerPeerRole role,
        string appHostRelativePath,
        string managedEntryRelativePath,
        string depsRelativePath,
        string runtimeConfigRelativePath,
        IReadOnlyList<WindowsReleaseArtifactPath> artifacts)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Native peer identity capture requires Windows.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(releaseRootPath);
        ArgumentNullException.ThrowIfNull(artifacts);
        if (!Enum.IsDefined(role))
        {
            throw new ArgumentOutOfRangeException(nameof(role));
        }

        var rootPath = WindowsPeerNative.CanonicalizeLocalPath(releaseRootPath);
        var driveRoot = Path.GetPathRoot(rootPath) ?? throw new IOException(
            "The release root does not have a local drive root.");
        if (string.Equals(
                Path.TrimEndingDirectorySeparator(rootPath),
                Path.TrimEndingDirectorySeparator(driveRoot),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("The retained release root cannot be a drive root.");
        }

        var definitions = artifacts.ToArray();
        if (definitions.Length is < 4 or > 128)
        {
            throw new IOException("The retained release artifact set is outside its bounded size.");
        }

        var directoryHandles = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
        var artifactHandles = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
        try
        {
            RetainDirectoryChain(rootPath, directoryHandles);
            var rootHandle = directoryHandles[rootPath];
            var rootObservation = WindowsPeerNative.ReadDirectoryIdentity(rootHandle, rootPath);
            var root = new WindowsReleaseRootIdentity(
                rootObservation.FinalPath,
                rootObservation.Attributes,
                rootObservation.VolumeSerialNumber,
                rootObservation.FileId,
                true);

            var observedArtifacts = new List<WindowsArtifactIdentity>(definitions.Length);
            var seenRelativePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var definition in definitions)
            {
                ArgumentNullException.ThrowIfNull(definition);
                ValidateRelativePath(definition.RelativePath);
                if (!Enum.IsDefined(definition.Kind) || !seenRelativePaths.Add(definition.RelativePath))
                {
                    throw new IOException("The retained release artifact definition is invalid or duplicated.");
                }

                var fullPath = WindowsPeerNative.CanonicalizeLocalPath(
                    Path.Combine(rootPath, definition.RelativePath));
                var rootPrefix = Path.TrimEndingDirectorySeparator(rootPath) + Path.DirectorySeparatorChar;
                if (!fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException("A retained release artifact escaped the release root.");
                }

                var parent = Path.GetDirectoryName(fullPath) ?? throw new IOException(
                    "A retained release artifact has no parent directory.");
                RetainDirectoryChain(parent, directoryHandles);
                var handle = definition.Kind == ReleaseArtifactKind.AppHostExe
                    ? WindowsPeerNative.OpenExecutableFilePinned(fullPath)
                    : WindowsPeerNative.OpenRegularFilePinned(fullPath);
                artifactHandles.Add(definition.RelativePath, handle);
                var observation = WindowsPeerNative.ReadRegularFileIdentityAndHash(
                    handle,
                    fullPath,
                    MaximumArtifactBytes);
                if (observation.VolumeSerialNumber != root.VolumeSerialNumber ||
                    observation.LinkCount != 1)
                {
                    throw new IOException(
                        "A retained release artifact is not a single-link file on the release volume.");
                }

                observedArtifacts.Add(new WindowsArtifactIdentity(
                    definition.Kind,
                    definition.RelativePath,
                    observation.FinalPath,
                    observation.Attributes,
                    observation.Length,
                    observation.Sha256,
                    observation.VolumeSerialNumber,
                    observation.FileId,
                    observation.LinkCount,
                    true));
            }

            return new WindowsRetainedReleaseArtifacts(
                role,
                appHostRelativePath,
                managedEntryRelativePath,
                depsRelativePath,
                runtimeConfigRelativePath,
                root,
                observedArtifacts,
                directoryHandles,
                artifactHandles);
        }
        catch
        {
            WindowsPeerNative.DisposeHandles(artifactHandles.Values);
            WindowsPeerNative.DisposeHandles(directoryHandles.Values);
            throw;
        }
    }

    internal WindowsRetainedReleaseHandleLease DuplicateFor(
        VerifiedReleaseArtifactSet expectedRelease)
    {
        ArgumentNullException.ThrowIfNull(expectedRelease);
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(
                _directoryHandles is null || _artifactHandles is null,
                this);
            ValidateExpectedRelease(expectedRelease);
            var directories = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
            var artifacts = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var pair in _directoryHandles)
                {
                    directories.Add(pair.Key, WindowsPeerNative.DuplicateFileHandle(pair.Value));
                }

                foreach (var pair in _artifactHandles)
                {
                    artifacts.Add(pair.Key, WindowsPeerNative.DuplicateFileHandle(pair.Value));
                }

                return new WindowsRetainedReleaseHandleLease(
                    expectedRelease,
                    directories,
                    artifacts);
            }
            catch
            {
                WindowsPeerNative.DisposeHandles(artifacts.Values);
                WindowsPeerNative.DisposeHandles(directories.Values);
                throw;
            }
        }
    }

    internal void ValidateProcessImageMapping(SafeProcessHandle processHandle)
    {
        ArgumentNullException.ThrowIfNull(processHandle);
        lock (_sync)
        {
            var handles = _artifactHandles ?? throw new ObjectDisposedException(
                nameof(WindowsRetainedReleaseArtifacts));
            if (!handles.TryGetValue(AppHostRelativePath, out var appHost))
            {
                throw new BrokerPeerTrustException(
                    "peer-retained-handles-invalid",
                    "The retained release does not contain its exact apphost handle.");
            }

            WindowsPeerNative.ValidateProcessImageMapping(processHandle, appHost);
        }
    }

    public void Dispose()
    {
        Dictionary<string, SafeFileHandle>? directories;
        Dictionary<string, SafeFileHandle>? artifacts;
        lock (_sync)
        {
            directories = _directoryHandles;
            artifacts = _artifactHandles;
            _directoryHandles = null;
            _artifactHandles = null;
        }

        WindowsPeerNative.DisposeHandles(artifacts?.Values);
        WindowsPeerNative.DisposeHandles(directories?.Values);
    }

    internal static void RetainDirectoryChain(
        string targetPath,
        IDictionary<string, SafeFileHandle> handles)
    {
        var canonicalTarget = WindowsPeerNative.CanonicalizeLocalPath(targetPath);
        var root = Path.GetPathRoot(canonicalTarget) ?? throw new IOException(
            "The retained directory has no local drive root.");
        var current = WindowsPeerNative.CanonicalizeLocalPath(root);
        RetainDirectory(current, handles);
        var relative = Path.GetRelativePath(root, canonicalTarget);
        if (relative == ".")
        {
            return;
        }

        foreach (var component in relative.Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = WindowsPeerNative.CanonicalizeLocalPath(Path.Combine(current, component));
            RetainDirectory(current, handles);
        }
    }

    private static void RetainDirectory(
        string path,
        IDictionary<string, SafeFileHandle> handles)
    {
        if (handles.ContainsKey(path))
        {
            return;
        }

        var handle = WindowsPeerNative.OpenDirectoryPinned(path);
        try
        {
            _ = WindowsPeerNative.ReadDirectoryIdentity(handle, path);
            handles.Add(path, handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private void ValidateExpectedRelease(VerifiedReleaseArtifactSet expected)
    {
        if (expected.Role != Role ||
            !WindowsPeerNative.SamePath(expected.Root.FinalPath, Root.FinalPath) ||
            expected.Root.VolumeSerialNumber != Root.VolumeSerialNumber ||
            !string.Equals(expected.Root.FileId, Root.FileId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.AppHostRelativePath, AppHostRelativePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.ManagedEntryRelativePath, ManagedEntryRelativePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.DepsRelativePath, DepsRelativePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.RuntimeConfigRelativePath, RuntimeConfigRelativePath, StringComparison.OrdinalIgnoreCase) ||
            expected.Artifacts.Count != Artifacts.Count)
        {
            throw new BrokerPeerTrustException(
                "peer-retained-handles-invalid",
                "The retained native release does not match the verified release capability.");
        }

        var observed = Artifacts.ToDictionary(
            artifact => artifact.RelativePath,
            StringComparer.OrdinalIgnoreCase);
        foreach (var artifact in expected.Artifacts)
        {
            if (!observed.TryGetValue(artifact.RelativePath, out var actual) || actual != artifact)
            {
                throw new BrokerPeerTrustException(
                    "peer-retained-handles-invalid",
                    "A retained native artifact does not match the verified release capability.");
            }
        }
    }

    internal static void ValidateRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            Path.IsPathFullyQualified(value) ||
            value.Contains('/') ||
            value.Contains(':') ||
            value.Split('\\').Any(component => component is "" or "." or ".."))
        {
            throw new IOException("A retained release artifact path is invalid.");
        }
    }
}

internal sealed record WindowsRetainedReleaseTreeFileV1(
    string RelativePath,
    long Length,
    string Sha256);

internal sealed class WindowsRetainedReleaseTreeV1 : IDisposable
{
    private const int MaximumFiles = 4096;
    private const long MaximumFileBytes = 512L * 1024 * 1024;
    private readonly object _sync = new();
    private Dictionary<string, SafeFileHandle>? _directoryHandles;
    private Dictionary<string, SafeFileHandle>? _fileHandles;

    private WindowsRetainedReleaseTreeV1(
        WindowsReleaseRootIdentity root,
        IReadOnlyList<WindowsRetainedReleaseTreeFileV1> files,
        Dictionary<string, SafeFileHandle> directoryHandles,
        Dictionary<string, SafeFileHandle> fileHandles)
    {
        Root = root;
        Files = Array.AsReadOnly(files.ToArray());
        _directoryHandles = directoryHandles;
        _fileHandles = fileHandles;
    }

    internal WindowsReleaseRootIdentity Root { get; }

    internal IReadOnlyList<WindowsRetainedReleaseTreeFileV1> Files { get; }

    internal int FileCount => Files.Count;

    internal static WindowsRetainedReleaseTreeV1 Capture(
        string releaseRootPath,
        IReadOnlyList<WindowsRetainedReleaseTreeFileV1> expectedFiles)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Native release-tree retention requires Windows.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(releaseRootPath);
        ArgumentNullException.ThrowIfNull(expectedFiles);
        var definitions = expectedFiles.ToArray();
        if (definitions.Length is < 1 or > MaximumFiles)
        {
            throw new IOException("The retained release tree is outside its file-count bound.");
        }

        var rootPath = WindowsPeerNative.CanonicalizeLocalPath(releaseRootPath);
        var driveRoot = Path.GetPathRoot(rootPath) ?? throw new IOException(
            "The retained release tree does not have a local drive root.");
        if (string.Equals(
                Path.TrimEndingDirectorySeparator(rootPath),
                Path.TrimEndingDirectorySeparator(driveRoot),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("The retained release tree cannot be a drive root.");
        }

        var directoryHandles = new Dictionary<string, SafeFileHandle>(
            StringComparer.OrdinalIgnoreCase);
        var fileHandles = new Dictionary<string, SafeFileHandle>(
            StringComparer.OrdinalIgnoreCase);
        try
        {
            WindowsRetainedReleaseArtifacts.RetainDirectoryChain(rootPath, directoryHandles);
            var rootObservation = WindowsPeerNative.ReadDirectoryIdentity(
                directoryHandles[rootPath],
                rootPath);
            var root = new WindowsReleaseRootIdentity(
                rootObservation.FinalPath,
                rootObservation.Attributes,
                rootObservation.VolumeSerialNumber,
                rootObservation.FileId,
                true);
            var ordinalPaths = new HashSet<string>(StringComparer.Ordinal);
            var ignoreCasePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var definition in definitions)
            {
                ArgumentNullException.ThrowIfNull(definition);
                var nativeRelativePath = definition.RelativePath.Replace(
                    '/',
                    Path.DirectorySeparatorChar);
                if (definition.RelativePath.Contains('\\') ||
                    !string.Equals(
                        definition.Sha256,
                        definition.Sha256.ToUpperInvariant(),
                        StringComparison.Ordinal) ||
                    !IsSha256(definition.Sha256) ||
                    definition.Length is <= 0 or > MaximumFileBytes)
                {
                    throw new IOException("A retained release-tree file identity is invalid.");
                }

                WindowsRetainedReleaseArtifacts.ValidateRelativePath(nativeRelativePath);
                if (!ordinalPaths.Add(definition.RelativePath) ||
                    !ignoreCasePaths.Add(definition.RelativePath))
                {
                    throw new IOException(
                        "The retained release tree contains a duplicate or case-colliding path.");
                }

                var fullPath = WindowsPeerNative.CanonicalizeLocalPath(
                    Path.Combine(rootPath, nativeRelativePath));
                var rootPrefix = Path.TrimEndingDirectorySeparator(rootPath) +
                    Path.DirectorySeparatorChar;
                if (!fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException("A retained release-tree file escaped its root.");
                }

                var parent = Path.GetDirectoryName(fullPath) ?? throw new IOException(
                    "A retained release-tree file has no parent directory.");
                WindowsRetainedReleaseArtifacts.RetainDirectoryChain(parent, directoryHandles);
                var handle = WindowsPeerNative.OpenRegularFilePinned(fullPath);
                fileHandles.Add(definition.RelativePath, handle);
                var observation = WindowsPeerNative.ReadRegularFileIdentityAndHash(
                    handle,
                    fullPath,
                    MaximumFileBytes);
                if (observation.VolumeSerialNumber != root.VolumeSerialNumber ||
                    observation.LinkCount != 1 ||
                    observation.Length != definition.Length ||
                    !string.Equals(
                        observation.Sha256,
                        definition.Sha256,
                        StringComparison.Ordinal))
                {
                    throw new IOException(
                        "A retained release-tree file differs from the committed tree.");
                }
            }

            return new WindowsRetainedReleaseTreeV1(
                root,
                definitions,
                directoryHandles,
                fileHandles);
        }
        catch
        {
            WindowsPeerNative.DisposeHandles(fileHandles.Values);
            WindowsPeerNative.DisposeHandles(directoryHandles.Values);
            throw;
        }
    }

    public void Dispose()
    {
        Dictionary<string, SafeFileHandle>? directories;
        Dictionary<string, SafeFileHandle>? files;
        lock (_sync)
        {
            directories = _directoryHandles;
            files = _fileHandles;
            _directoryHandles = null;
            _fileHandles = null;
        }

        WindowsPeerNative.DisposeHandles(files?.Values);
        WindowsPeerNative.DisposeHandles(directories?.Values);
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');
}

internal sealed class WindowsRetainedReleaseHandleLease : IDisposable
{
    private readonly object _sync = new();
    private readonly VerifiedReleaseArtifactSet _release;
    private Dictionary<string, SafeFileHandle>? _directoryHandles;
    private Dictionary<string, SafeFileHandle>? _artifactHandles;

    internal WindowsRetainedReleaseHandleLease(
        VerifiedReleaseArtifactSet release,
        Dictionary<string, SafeFileHandle> directoryHandles,
        Dictionary<string, SafeFileHandle> artifactHandles)
    {
        _release = release;
        _directoryHandles = directoryHandles;
        _artifactHandles = artifactHandles;
    }

    internal WindowsReleaseRootIdentity CaptureRoot()
    {
        lock (_sync)
        {
            var directories = _directoryHandles ?? throw new ObjectDisposedException(
                nameof(WindowsRetainedReleaseHandleLease));
            var rootPath = WindowsPeerNative.CanonicalizeLocalPath(_release.Root.FinalPath);
            var observation = WindowsPeerNative.ReadDirectoryIdentity(
                directories[rootPath],
                rootPath);
            return new WindowsReleaseRootIdentity(
                observation.FinalPath,
                observation.Attributes,
                observation.VolumeSerialNumber,
                observation.FileId,
                true);
        }
    }

    internal IReadOnlyList<WindowsArtifactIdentity> CaptureArtifacts()
    {
        lock (_sync)
        {
            var handles = _artifactHandles ?? throw new ObjectDisposedException(
                nameof(WindowsRetainedReleaseHandleLease));
            return _release.Artifacts.Select(expected =>
            {
                var observation = WindowsPeerNative.ReadRegularFileIdentityAndHash(
                    handles[expected.RelativePath],
                    expected.FinalPath,
                    256L * 1024 * 1024);
                return new WindowsArtifactIdentity(
                    expected.Kind,
                    expected.RelativePath,
                    observation.FinalPath,
                    observation.Attributes,
                    observation.Length,
                    observation.Sha256,
                    observation.VolumeSerialNumber,
                    observation.FileId,
                    observation.LinkCount,
                    true);
            }).ToArray();
        }
    }

    internal void ValidateProcessImageMapping(SafeProcessHandle processHandle)
    {
        ArgumentNullException.ThrowIfNull(processHandle);
        lock (_sync)
        {
            var handles = _artifactHandles ?? throw new ObjectDisposedException(
                nameof(WindowsRetainedReleaseHandleLease));
            var appHost = _release.Artifacts.Single(
                artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe);
            WindowsPeerNative.ValidateProcessImageMapping(
                processHandle,
                handles[appHost.RelativePath]);
        }
    }

    public void Dispose()
    {
        Dictionary<string, SafeFileHandle>? directories;
        Dictionary<string, SafeFileHandle>? artifacts;
        lock (_sync)
        {
            directories = _directoryHandles;
            artifacts = _artifactHandles;
            _directoryHandles = null;
            _artifactHandles = null;
        }

        WindowsPeerNative.DisposeHandles(artifacts?.Values);
        WindowsPeerNative.DisposeHandles(directories?.Values);
    }
}

internal sealed record WindowsLaunchedPeerIdentity(
    uint ProcessId,
    DateTimeOffset CreationTimeUtc,
    uint SessionId,
    WindowsTokenIdentity Token,
    WindowsAppModelIdentity AppModel,
    string FinalImagePath);

internal sealed class WindowsRetainedPeerIdentityLease : IRetainedPeerIdentityLease
{
    private readonly object _sync = new();
    private SafeProcessHandle? _processHandle;
    private SafeAccessTokenHandle? _tokenHandle;
    private WindowsRetainedReleaseHandleLease? _releaseHandles;
    private readonly VerifiedReleaseArtifactSet _release;

    internal WindowsRetainedPeerIdentityLease(
        SafeProcessHandle processHandle,
        WindowsRetainedReleaseHandleLease releaseHandles,
        VerifiedReleaseArtifactSet release)
    {
        _processHandle = processHandle;
        _releaseHandles = releaseHandles;
        _release = release;
        try
        {
            if (!WindowsPeerNative.IsProcessAlive(processHandle))
            {
                throw new BrokerPeerTrustException(
                    "peer-process-exited",
                    "The retained named pipe peer exited before its identity lease was established.");
            }

            releaseHandles.ValidateProcessImageMapping(processHandle);
            _tokenHandle = WindowsPeerNative.OpenQueryToken(processHandle);
            RetainedHandles = new RetainedReleaseHandleSet(
                release.Root,
                release.Artifacts.Select(artifact => artifact.RelativePath).ToArray());
        }
        catch
        {
            processHandle.Dispose();
            releaseHandles.Dispose();
            throw;
        }
    }

    public bool IsAlive
    {
        get
        {
            lock (_sync)
            {
                return WindowsPeerNative.IsProcessAlive(
                    _processHandle ?? throw new ObjectDisposedException(
                        nameof(WindowsRetainedPeerIdentityLease)));
            }
        }
    }

    public RetainedReleaseHandleSet RetainedHandles { get; }

    public WindowsProcessIdentity Capture()
    {
        lock (_sync)
        {
            var process = _processHandle ?? throw new ObjectDisposedException(
                nameof(WindowsRetainedPeerIdentityLease));
            var token = _tokenHandle ?? throw new ObjectDisposedException(
                nameof(WindowsRetainedPeerIdentityLease));
            var release = _releaseHandles ?? throw new ObjectDisposedException(
                nameof(WindowsRetainedPeerIdentityLease));
            release.ValidateProcessImageMapping(process);
            var processId = WindowsPeerNative.ReadProcessId(process);
            var sessionId = WindowsPeerNative.ReadProcessSessionId(processId);
            return new WindowsProcessIdentity(
                processId,
                WindowsPeerNative.ReadProcessCreationTimeUtc(process),
                sessionId,
                WindowsPeerNative.ReadTokenIdentity(token),
                WindowsPeerNative.ReadAppModelIdentity(process),
                WindowsPeerNative.ReadProcessImagePath(process),
                true,
                release.CaptureRoot(),
                release.CaptureArtifacts());
        }
    }

    public void Dispose()
    {
        SafeProcessHandle? process;
        SafeAccessTokenHandle? token;
        WindowsRetainedReleaseHandleLease? release;
        lock (_sync)
        {
            process = _processHandle;
            token = _tokenHandle;
            release = _releaseHandles;
            _processHandle = null;
            _tokenHandle = null;
            _releaseHandles = null;
        }

        token?.Dispose();
        release?.Dispose();
        process?.Dispose();
    }
}

internal static class WindowsPeerNative
{
    internal const uint GenericRead = 0x80000000;
    internal const uint GenericWrite = 0x40000000;
    internal const uint FileExecute = 0x00000020;
    internal const uint FileReadAttributes = 0x00000080;
    internal const uint FileShareRead = 0x00000001;
    internal const uint OpenExisting = 3;
    internal const uint FileFlagBackupSemantics = 0x02000000;
    internal const uint FileFlagOpenReparsePoint = 0x00200000;
    internal const uint FileFlagSequentialScan = 0x08000000;
    internal const uint FileFlagOverlapped = 0x40000000;
    internal const uint SecuritySqosPresent = 0x00100000;
    internal const uint SecurityIdentification = 0x00010000;
    internal const uint ProcessQueryInformation = 0x00000400;
    internal const uint ProcessQueryLimitedInformation = 0x00001000;
    internal const uint Synchronize = 0x00100000;
    internal const uint TokenQuery = 0x00000008;
    internal const uint RestrictedProcessGrantedAccess =
        ProcessQueryInformation | ProcessQueryLimitedInformation | Synchronize;
    internal const int ErrorInsufficientBuffer = 122;
    internal const int ErrorNoPackage = 15700;
    internal const int ErrorNotFound = 1168;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const uint SeGroupLogonId = 0xC0000000;
    private const int ObjectBasicInformation = 0;
    private const int ProcessImageFileMapping = 44;
    private const int MaximumPathCharacters = 32767;

    internal static WindowsLaunchedPeerIdentity CaptureLaunchedPeer(
        SafeProcessHandle launchHandle)
    {
        using var process = DuplicateRestrictedProcessHandle(launchHandle);
        using var token = OpenQueryToken(process);
        var processId = ReadProcessId(process);
        return new WindowsLaunchedPeerIdentity(
            processId,
            ReadProcessCreationTimeUtc(process),
            ReadProcessSessionId(processId),
            ReadTokenIdentity(token),
            ReadAppModelIdentity(process),
            ReadProcessImagePath(process));
    }

    internal static SafeProcessHandle DuplicateRestrictedProcessHandle(
        SafeProcessHandle source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (source.IsInvalid || source.IsClosed)
        {
            throw new ObjectDisposedException(nameof(source));
        }

        if (!DuplicateProcessHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                out var duplicate,
                ProcessQueryInformation | Synchronize,
                false,
                0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to duplicate the exact launched peer process handle.");
        }

        try
        {
            var grantedAccess = ReadGrantedAccess(duplicate);
            if (grantedAccess != RestrictedProcessGrantedAccess)
            {
                throw new BrokerPeerTrustException(
                    "peer-process-handle-rights-invalid",
                    "The retained peer process handle access mask is not exact: 0x" +
                    grantedAccess.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
            }

            return duplicate;
        }
        catch
        {
            duplicate.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle DuplicateFileHandle(SafeFileHandle source)
    {
        if (source.IsInvalid || source.IsClosed)
        {
            throw new ObjectDisposedException(nameof(source));
        }

        if (!DuplicateFileHandleNative(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                out var duplicate,
                0,
                false,
                DuplicateSameAccess))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to duplicate a retained release handle.");
        }

        return duplicate;
    }

    internal static SafeAccessTokenHandle OpenQueryToken(SafeProcessHandle processHandle)
    {
        if (!OpenProcessToken(processHandle, TokenQuery, out var token))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to retain the peer primary token.");
        }

        try
        {
            var grantedAccess = ReadGrantedAccess(token);
            if (grantedAccess != TokenQuery)
            {
                throw new BrokerPeerTrustException(
                    "peer-token-handle-rights-invalid",
                    "The retained peer token handle access mask is not exact: 0x" +
                    grantedAccess.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
            }

            return token;
        }
        catch
        {
            token.Dispose();
            throw;
        }
    }

    internal static WindowsTokenIdentity ReadCurrentPrimaryToken()
    {
        using var process = new SafeProcessHandle(GetCurrentProcess(), ownsHandle: false);
        using var token = OpenQueryToken(process);
        return ReadTokenIdentity(token);
    }

    internal static WindowsTokenIdentity ReadTokenIdentity(SafeAccessTokenHandle token)
    {
        using var user = QueryTokenBuffer(token, TokenInformationClass.TokenUser);
        var userSidPointer = Marshal.ReadIntPtr(user.DangerousGetHandle());
        var userSid = ReadSid(userSidPointer, "The peer token user SID is missing.");

        using var groups = QueryTokenBuffer(token, TokenInformationClass.TokenGroups);
        var groupBase = groups.DangerousGetHandle();
        var groupCount = checked((uint)Marshal.ReadInt32(groupBase));
        var groupOffset = IntPtr.Size == 8 ? 8 : 4;
        var groupSize = Marshal.SizeOf<SidAndAttributes>();
        var logonSids = new List<string>();
        for (var index = 0U; index < groupCount; index++)
        {
            var entry = Marshal.PtrToStructure<SidAndAttributes>(
                IntPtr.Add(groupBase, checked(groupOffset + (int)index * groupSize)));
            if ((entry.Attributes & SeGroupLogonId) == SeGroupLogonId)
            {
                logonSids.Add(ReadSid(entry.Sid, "The peer token logon SID is missing."));
            }
        }

        if (logonSids.Count != 1)
        {
            throw new IOException("The peer token does not expose exactly one logon SID.");
        }

        using var statisticsBuffer = QueryTokenBuffer(token, TokenInformationClass.TokenStatistics);
        var statistics = Marshal.PtrToStructure<TokenStatistics>(
            statisticsBuffer.DangerousGetHandle());
        var sessionId = ReadTokenUInt32(token, TokenInformationClass.TokenSessionId);
        using var integrity = QueryTokenBuffer(token, TokenInformationClass.TokenIntegrityLevel);
        var integritySid = Marshal.ReadIntPtr(integrity.DangerousGetHandle());
        var integrityRid = ReadSidLastSubAuthority(integritySid);
        var elevationType = (WindowsTokenElevationType)ReadTokenUInt32(
            token,
            TokenInformationClass.TokenElevationType);
        var elevated = ReadTokenUInt32(token, TokenInformationClass.TokenElevation) != 0;
        var isAppContainer = ReadTokenUInt32(
            token,
            TokenInformationClass.TokenIsAppContainer) != 0;
        string? appContainerSid = null;
        if (isAppContainer)
        {
            using var appContainer = QueryTokenBuffer(
                token,
                TokenInformationClass.TokenAppContainerSid);
            appContainerSid = ReadSid(
                Marshal.ReadIntPtr(appContainer.DangerousGetHandle()),
                "The AppContainer peer token is missing its SID.");
        }

        var uiAccess = ReadTokenUInt32(token, TokenInformationClass.TokenUIAccess) != 0;
        var tokenType = (WindowsTokenType)statistics.TokenType;
        WindowsSecurityImpersonationLevel? impersonationLevel = tokenType == WindowsTokenType.Impersonation
            ? (WindowsSecurityImpersonationLevel)ReadTokenUInt32(
                token,
                TokenInformationClass.TokenImpersonationLevel)
            : null;
        return new WindowsTokenIdentity(
            userSid,
            logonSids[0],
            logonSids.Count,
            ToUInt64(statistics.AuthenticationId),
            sessionId,
            integrityRid,
            elevationType,
            elevated,
            isAppContainer,
            appContainerSid,
            uiAccess,
            tokenType,
            impersonationLevel);
    }

    internal static WindowsAppModelIdentity ReadAppModelIdentity(
        SafeProcessHandle processHandle)
    {
        var fullName = ReadPackageString(processHandle, familyName: false);
        var familyName = ReadPackageString(processHandle, familyName: true);
        if (fullName is null && familyName is null)
        {
            return WindowsAppModelIdentity.Unpackaged;
        }

        if (fullName is null || familyName is null)
        {
            throw new IOException("The peer process exposes an inconsistent AppModel identity.");
        }

        return new WindowsAppModelIdentity(
            WindowsAppModelKind.Packaged,
            fullName,
            familyName);
    }

    internal static uint ReadProcessId(SafeProcessHandle processHandle)
    {
        var processId = GetProcessId(processHandle);
        if (processId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the retained peer process id.");
        }

        return processId;
    }

    internal static uint ReadProcessSessionId(uint processId)
    {
        if (!ProcessIdToSessionId(processId, out var sessionId) || sessionId == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the retained peer session id.");
        }

        return sessionId;
    }

    internal static DateTimeOffset ReadProcessCreationTimeUtc(
        SafeProcessHandle processHandle)
    {
        if (!GetProcessTimes(
                processHandle,
                out var creation,
                out _,
                out _,
                out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the retained peer creation time.");
        }

        return DateTimeOffset.FromFileTime(creation.ToInt64()).ToUniversalTime();
    }

    internal static string ReadProcessImagePath(SafeProcessHandle processHandle)
    {
        var capacity = (uint)MaximumPathCharacters;
        var value = new StringBuilder((int)capacity);
        if (!QueryFullProcessImageNameW(processHandle, 0, value, ref capacity) || capacity == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the retained peer image path.");
        }

        return CanonicalizeLocalPath(value.ToString());
    }

    internal static bool IsProcessAlive(SafeProcessHandle processHandle)
    {
        var result = WaitForSingleObject(processHandle, 0);
        return result switch
        {
            WaitTimeout => true,
            WaitObject0 => false,
            WaitFailed => throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to query retained peer liveness."),
            _ => throw new IOException("Windows returned an unexpected peer liveness result.")
        };
    }

    internal static SafeFileHandle OpenDirectoryPinned(string path) => OpenPath(
        path,
        FileReadAttributes,
        FileFlagBackupSemantics | FileFlagOpenReparsePoint);

    internal static SafeFileHandle OpenRegularFilePinned(string path) => OpenPath(
        path,
        GenericRead,
        FileFlagOpenReparsePoint | FileFlagSequentialScan);

    internal static SafeFileHandle OpenExecutableFilePinned(string path) => OpenPath(
        path,
        GenericRead | FileExecute,
        FileFlagOpenReparsePoint | FileFlagSequentialScan);

    internal static void ValidateProcessImageMapping(
        SafeProcessHandle processHandle,
        SafeFileHandle appHostHandle)
    {
        ArgumentNullException.ThrowIfNull(processHandle);
        ArgumentNullException.ThrowIfNull(appHostHandle);
        if (processHandle.IsInvalid || processHandle.IsClosed ||
            appHostHandle.IsInvalid || appHostHandle.IsClosed)
        {
            throw new ObjectDisposedException("process or apphost handle");
        }

        var addedRef = false;
        try
        {
            appHostHandle.DangerousAddRef(ref addedRef);
            var rawFileHandle = appHostHandle.DangerousGetHandle();
            var status = NtQueryInformationProcessImageFileMapping(
                processHandle,
                ProcessImageFileMapping,
                ref rawFileHandle,
                checked((uint)IntPtr.Size),
                IntPtr.Zero);
            if (status != 0)
            {
                throw new BrokerPeerTrustException(
                    "peer-image-mapping-mismatch",
                    "Windows did not bind the retained apphost to the exact peer image file object; NTSTATUS=0x" +
                    unchecked((uint)status).ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        finally
        {
            if (addedRef)
            {
                appHostHandle.DangerousRelease();
            }
        }
    }

    internal static uint ReadGrantedAccess(SafeHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid || handle.IsClosed)
        {
            throw new ObjectDisposedException(nameof(handle));
        }

        var addedRef = false;
        try
        {
            handle.DangerousAddRef(ref addedRef);
            var status = NtQueryObjectBasicInformation(
                handle.DangerousGetHandle(),
                ObjectBasicInformation,
                out var information,
                checked((uint)Marshal.SizeOf<NativeObjectBasicInformation>()),
                IntPtr.Zero);
            if (status != 0)
            {
                throw new IOException(
                    "Unable to query the retained handle access mask; NTSTATUS=0x" +
                    unchecked((uint)status).ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
            }

            return information.GrantedAccess;
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
            }
        }
    }

    internal static NativeDirectoryObservation ReadDirectoryIdentity(
        SafeFileHandle handle,
        string expectedPath)
    {
        var basic = ReadBasicInformation(handle);
        var attributes = (FileAttributes)basic.FileAttributes;
        if ((attributes & FileAttributes.Directory) == 0 ||
            (attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
        {
            throw new IOException("A retained release directory is reparse-backed or invalid.");
        }

        var finalPath = ReadFinalPath(handle);
        if (!SamePath(finalPath, expectedPath))
        {
            throw new IOException("A retained release directory resolved to an unexpected path.");
        }

        var fileId = ReadFileId(handle);
        return new NativeDirectoryObservation(
            finalPath,
            attributes,
            fileId.VolumeSerialNumber,
            fileId.FileId);
    }

    internal static NativeFileObservation ReadRegularFileIdentityAndHash(
        SafeFileHandle handle,
        string expectedPath,
        long maximumBytes)
    {
        var basicBefore = ReadBasicInformation(handle);
        var standardBefore = ReadStandardInformation(handle);
        var idBefore = ReadFileId(handle);
        var attributes = (FileAttributes)basicBefore.FileAttributes;
        if ((attributes &
             (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            standardBefore.Directory ||
            standardBefore.EndOfFile is <= 0 ||
            standardBefore.EndOfFile > maximumBytes)
        {
            throw new IOException("A retained release artifact is not a bounded regular file.");
        }

        var finalPath = ReadFinalPath(handle);
        if (!SamePath(finalPath, expectedPath))
        {
            throw new IOException("A retained release artifact resolved to an unexpected path.");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long offset = 0;
        while (offset < standardBefore.EndOfFile)
        {
            var requested = checked((int)Math.Min(buffer.Length, standardBefore.EndOfFile - offset));
            var read = RandomAccess.Read(handle, buffer.AsSpan(0, requested), offset);
            if (read <= 0)
            {
                throw new EndOfStreamException("A retained release artifact ended during hashing.");
            }

            hash.AppendData(buffer, 0, read);
            offset = checked(offset + read);
        }

        var basicAfter = ReadBasicInformation(handle);
        var standardAfter = ReadStandardInformation(handle);
        var idAfter = ReadFileId(handle);
        if (!basicBefore.Equals(basicAfter) ||
            !standardBefore.Equals(standardAfter) ||
            !idBefore.Equals(idAfter) ||
            offset != standardBefore.EndOfFile)
        {
            throw new IOException("A retained release artifact changed while it was captured.");
        }

        return new NativeFileObservation(
            finalPath,
            attributes,
            standardBefore.EndOfFile,
            Convert.ToHexString(hash.GetHashAndReset()),
            idBefore.VolumeSerialNumber,
            idBefore.FileId,
            standardBefore.NumberOfLinks);
    }

    internal static string CanonicalizeLocalPath(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("A native peer path cannot be a network path.");
        }

        if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            value = value[4..];
        }
        else if (value.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new IOException("A native peer path cannot be a network path.");
        }

        var fullPath = Path.GetFullPath(value);
        if (Path.GetPathRoot(fullPath) is not { Length: >= 3 } root || root[1] != ':')
        {
            throw new IOException("A native peer path is not a canonical local-drive path.");
        }

        return string.Equals(
            Path.TrimEndingDirectorySeparator(fullPath),
            Path.TrimEndingDirectorySeparator(root),
            StringComparison.OrdinalIgnoreCase)
            ? root
            : Path.TrimEndingDirectorySeparator(fullPath);
    }

    internal static bool SamePath(string first, string second) => string.Equals(
        CanonicalizeLocalPath(first),
        CanonicalizeLocalPath(second),
        StringComparison.OrdinalIgnoreCase);

    internal static void DisposeHandles(IEnumerable<IDisposable>? handles)
    {
        if (handles is null)
        {
            return;
        }

        foreach (var handle in handles.Reverse())
        {
            handle.Dispose();
        }
    }

    private static SafeFileHandle OpenPath(string path, uint access, uint flags)
    {
        var handle = CreateFileW(
            CanonicalizeLocalPath(path),
            access,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Unable to pin a native peer release path.");
        }

        return handle;
    }

    private static NativeBasicInformation ReadBasicInformation(SafeFileHandle handle)
    {
        if (!GetFileBasicInformation(
                handle,
                FileInformationClass.FileBasicInfo,
                out var information,
                (uint)Marshal.SizeOf<NativeBasicInformation>()))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read retained path attributes.");
        }

        return information;
    }

    private static NativeStandardInformation ReadStandardInformation(SafeFileHandle handle)
    {
        if (!GetFileStandardInformation(
                handle,
                FileInformationClass.FileStandardInfo,
                out var information,
                (uint)Marshal.SizeOf<NativeStandardInformation>()))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read retained file size and link count.");
        }

        return information;
    }

    private static NativeFileIdObservation ReadFileId(SafeFileHandle handle)
    {
        if (!GetFileIdInformation(
                handle,
                FileInformationClass.FileIdInfo,
                out var information,
                (uint)Marshal.SizeOf<NativeFileIdInformation>()))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the retained FILE_ID_128 identity.");
        }

        Span<byte> bytes = stackalloc byte[16];
        BitConverter.TryWriteBytes(bytes[..8], information.FileId.Low);
        BitConverter.TryWriteBytes(bytes[8..], information.FileId.High);
        var fileId = Convert.ToHexString(bytes);
        if (fileId.All(character => character == '0'))
        {
            throw new IOException("Windows returned an empty FILE_ID_128 identity.");
        }

        return new NativeFileIdObservation(information.VolumeSerialNumber, fileId);
    }

    private static string ReadFinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(512);
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to resolve a retained native peer path.");
        }

        if (length >= buffer.Capacity)
        {
            if (length >= MaximumPathCharacters)
            {
                throw new PathTooLongException("A retained native peer path is too long.");
            }

            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to resolve the complete retained native peer path.");
            }
        }

        return CanonicalizeLocalPath(buffer.ToString());
    }

    private static SafeTokenBuffer QueryTokenBuffer(
        SafeAccessTokenHandle token,
        TokenInformationClass informationClass)
    {
        _ = GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out var required);
        var sizingError = Marshal.GetLastWin32Error();
        if (required <= 0 ||
            sizingError is not 0 and not ErrorInsufficientBuffer)
        {
            throw new Win32Exception(
                sizingError,
                "Unable to size peer token information " + informationClass +
                " (required=" + required + ").");
        }

        var buffer = new SafeTokenBuffer(required);
        if (!GetTokenInformation(
                token,
                informationClass,
                buffer.DangerousGetHandle(),
                required,
                out _))
        {
            var error = Marshal.GetLastWin32Error();
            buffer.Dispose();
            throw new Win32Exception(error, "Unable to read peer token information.");
        }

        return buffer;
    }

    private static uint ReadTokenUInt32(
        SafeAccessTokenHandle token,
        TokenInformationClass informationClass)
    {
        using var buffer = new SafeTokenBuffer(sizeof(uint));
        if (!GetTokenInformation(
                token,
                informationClass,
                buffer.DangerousGetHandle(),
                sizeof(uint),
                out var returned) ||
            returned < sizeof(uint))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read scalar peer token information " + informationClass + ".");
        }

        return checked((uint)Marshal.ReadInt32(buffer.DangerousGetHandle()));
    }

    private static string ReadSid(IntPtr sid, string message)
    {
        if (sid == IntPtr.Zero || !IsValidSid(sid))
        {
            throw new IOException(message);
        }

        return new SecurityIdentifier(sid).Value;
    }

    private static uint ReadSidLastSubAuthority(IntPtr sid)
    {
        if (sid == IntPtr.Zero || !IsValidSid(sid))
        {
            throw new IOException("The peer integrity SID is invalid.");
        }

        var countPointer = GetSidSubAuthorityCount(sid);
        if (countPointer == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var count = Marshal.ReadByte(countPointer);
        if (count == 0)
        {
            throw new IOException("The peer integrity SID has no RID.");
        }

        var ridPointer = GetSidSubAuthority(sid, checked((uint)(count - 1)));
        if (ridPointer == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return checked((uint)Marshal.ReadInt32(ridPointer));
    }

    private static string? ReadPackageString(
        SafeProcessHandle processHandle,
        bool familyName)
    {
        uint length = 0;
        var result = familyName
            ? GetPackageFamilyName(processHandle, ref length, null)
            : GetPackageFullName(processHandle, ref length, null);
        if (result == ErrorNoPackage)
        {
            return null;
        }

        if (result != ErrorInsufficientBuffer || length == 0)
        {
            throw new Win32Exception(result, "Unable to size peer AppModel identity.");
        }

        var value = new StringBuilder(checked((int)length));
        result = familyName
            ? GetPackageFamilyName(processHandle, ref length, value)
            : GetPackageFullName(processHandle, ref length, value);
        if (result != 0 || value.Length == 0)
        {
            throw new Win32Exception(result, "Unable to read peer AppModel identity.");
        }

        return value.ToString();
    }

    private static ulong ToUInt64(NativeLuid value) =>
        ((ulong)unchecked((uint)value.HighPart) << 32) | value.LowPart;

    internal sealed record NativeDirectoryObservation(
        string FinalPath,
        FileAttributes Attributes,
        ulong VolumeSerialNumber,
        string FileId);

    internal sealed record NativeFileObservation(
        string FinalPath,
        FileAttributes Attributes,
        long Length,
        string Sha256,
        ulong VolumeSerialNumber,
        string FileId,
        uint LinkCount);

    private readonly record struct NativeFileIdObservation(
        ulong VolumeSerialNumber,
        string FileId);

    private sealed class SafeTokenBuffer : SafeHandle
    {
        internal SafeTokenBuffer(int length)
            : base(IntPtr.Zero, ownsHandle: true)
        {
            SetHandle(Marshal.AllocHGlobal(length));
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    private enum FileInformationClass
    {
        FileBasicInfo = 0,
        FileStandardInfo = 1,
        FileIdInfo = 18
    }

    private enum TokenInformationClass
    {
        TokenUser = 1,
        TokenGroups = 2,
        TokenImpersonationLevel = 9,
        TokenStatistics = 10,
        TokenSessionId = 12,
        TokenElevationType = 18,
        TokenElevation = 20,
        TokenIntegrityLevel = 25,
        TokenUIAccess = 26,
        TokenIsAppContainer = 29,
        TokenAppContainerSid = 31
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeFileTime
    {
        internal readonly uint Low;
        internal readonly uint High;

        internal long ToInt64() => unchecked((long)(((ulong)High << 32) | Low));
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeBasicInformation : IEquatable<NativeBasicInformation>
    {
        internal readonly long CreationTime;
        internal readonly long LastAccessTime;
        internal readonly long LastWriteTime;
        internal readonly long ChangeTime;
        internal readonly uint FileAttributes;

        public bool Equals(NativeBasicInformation other) =>
            CreationTime == other.CreationTime &&
            LastWriteTime == other.LastWriteTime &&
            ChangeTime == other.ChangeTime &&
            FileAttributes == other.FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeStandardInformation : IEquatable<NativeStandardInformation>
    {
        internal readonly long AllocationSize;
        internal readonly long EndOfFile;
        internal readonly uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] internal readonly bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] internal readonly bool Directory;

        public bool Equals(NativeStandardInformation other) =>
            AllocationSize == other.AllocationSize &&
            EndOfFile == other.EndOfFile &&
            NumberOfLinks == other.NumberOfLinks &&
            DeletePending == other.DeletePending &&
            Directory == other.Directory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeFileId128
    {
        internal readonly ulong Low;
        internal readonly ulong High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeFileIdInformation
    {
        internal readonly ulong VolumeSerialNumber;
        internal readonly NativeFileId128 FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeLuid
    {
        internal readonly uint LowPart;
        internal readonly int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct SidAndAttributes
    {
        internal readonly IntPtr Sid;
        internal readonly uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct TokenStatistics
    {
        internal readonly NativeLuid TokenId;
        internal readonly NativeLuid AuthenticationId;
        internal readonly long ExpirationTime;
        internal readonly int TokenType;
        internal readonly int ImpersonationLevel;
        internal readonly uint DynamicCharged;
        internal readonly uint DynamicAvailable;
        internal readonly uint GroupCount;
        internal readonly uint PrivilegeCount;
        internal readonly NativeLuid ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeObjectBasicInformation
    {
        internal readonly uint Attributes;
        internal readonly uint GrantedAccess;
        internal readonly uint HandleCount;
        internal readonly uint PointerCount;
        internal readonly uint PagedPoolCharge;
        internal readonly uint NonPagedPoolCharge;
        internal readonly uint Reserved1;
        internal readonly uint Reserved2;
        internal readonly uint Reserved3;
        internal readonly uint NameInfoSize;
        internal readonly uint TypeInfoSize;
        internal readonly uint SecurityDescriptorSize;
        internal readonly long CreationTime;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileBasicInformation(
        SafeFileHandle file,
        FileInformationClass informationClass,
        out NativeBasicInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileStandardInformation(
        SafeFileHandle file,
        FileInformationClass informationClass,
        out NativeStandardInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileIdInformation(
        SafeFileHandle file,
        FileInformationClass informationClass,
        out NativeFileIdInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder path,
        uint pathLength,
        uint flags);

    [DllImport("kernel32.dll", EntryPoint = "DuplicateHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateProcessHandle(
        IntPtr sourceProcess,
        SafeProcessHandle sourceHandle,
        IntPtr targetProcess,
        out SafeProcessHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll", EntryPoint = "DuplicateHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateFileHandleNative(
        IntPtr sourceProcess,
        SafeFileHandle sourceHandle,
        IntPtr targetProcess,
        out SafeFileHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle processHandle,
        out NativeFileTime creationTime,
        out NativeFileTime exitTime,
        out NativeFileTime kernelTime,
        out NativeFileTime userTime);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(
        SafeProcessHandle processHandle,
        uint flags,
        StringBuilder executablePath,
        ref uint size);

    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    private static extern int NtQueryInformationProcessImageFileMapping(
        SafeProcessHandle processHandle,
        int processInformationClass,
        ref IntPtr processInformation,
        uint processInformationLength,
        IntPtr returnLength);

    [DllImport("ntdll.dll", EntryPoint = "NtQueryObject")]
    private static extern int NtQueryObjectBasicInformation(
        IntPtr handle,
        int objectInformationClass,
        out NativeObjectBasicInformation objectInformation,
        uint objectInformationLength,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        SafeProcessHandle processHandle,
        uint milliseconds);

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
        TokenInformationClass tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFullName(
        SafeProcessHandle processHandle,
        ref uint packageFullNameLength,
        StringBuilder? packageFullName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(
        SafeProcessHandle processHandle,
        ref uint packageFamilyNameLength,
        StringBuilder? packageFamilyName);
}
