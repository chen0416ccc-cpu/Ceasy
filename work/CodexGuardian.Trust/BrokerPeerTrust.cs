using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Trust;

public enum BrokerPeerRole
{
    Guardian,
    Broker
}

public enum NamedPipePeerKind
{
    Client,
    Server
}

public enum WindowsTokenElevationType
{
    Default = 1,
    Full = 2,
    Limited = 3
}

public enum WindowsTokenType
{
    Primary = 1,
    Impersonation = 2
}

public enum WindowsSecurityImpersonationLevel
{
    Anonymous,
    Identification,
    Impersonation,
    Delegation
}

public enum WindowsAppModelKind
{
    Unpackaged,
    Packaged
}

public enum ReleaseArtifactKind
{
    AppHostExe,
    ManagedEntryDll,
    DepsJson,
    RuntimeConfigJson,
    RuntimeDependency
}

public sealed record WindowsTokenIdentity(
    string UserSid,
    string LogonSid,
    int LogonSidGroupCount,
    ulong AuthenticationId,
    uint SessionId,
    uint IntegrityLevelRid,
    WindowsTokenElevationType ElevationType,
    bool IsElevated,
    bool IsAppContainer,
    string? AppContainerSid,
    bool UiAccess,
    WindowsTokenType TokenType,
    WindowsSecurityImpersonationLevel? ImpersonationLevel);

public sealed record WindowsAppModelIdentity(
    WindowsAppModelKind Kind,
    string? FullName,
    string? FamilyName)
{
    public static WindowsAppModelIdentity Unpackaged { get; } = new(
        WindowsAppModelKind.Unpackaged,
        null,
        null);
}

public sealed record WindowsArtifactIdentity(
    ReleaseArtifactKind Kind,
    string RelativePath,
    string FinalPath,
    FileAttributes Attributes,
    long Length,
    string Sha256,
    ulong VolumeSerialNumber,
    string FileId,
    uint LinkCount,
    bool TraversalIsReparseFree);

public sealed record WindowsReleaseRootIdentity(
    string FinalPath,
    FileAttributes Attributes,
    ulong VolumeSerialNumber,
    string FileId,
    bool TraversalIsReparseFree);

internal sealed record VerifiedReleaseRoleArtifacts(
    BrokerPeerRole Role,
    string AppHostRelativePath,
    string ManagedEntryRelativePath,
    string DepsRelativePath,
    string RuntimeConfigRelativePath,
    IReadOnlyList<WindowsArtifactIdentity> Artifacts);

public sealed class VerifiedReleaseManifest
{
    private readonly VerifiedReleaseArtifactSet _guardian;
    private readonly VerifiedReleaseArtifactSet _broker;

    private VerifiedReleaseManifest(
        string releaseId,
        string manifestSha256,
        WindowsReleaseRootIdentity root,
        VerifiedReleaseRoleArtifacts guardian,
        VerifiedReleaseRoleArtifacts broker)
    {
        ReleaseId = releaseId;
        ManifestSha256 = manifestSha256;
        Root = root;
        _guardian = new VerifiedReleaseArtifactSet(this, releaseId, manifestSha256, root, guardian);
        _broker = new VerifiedReleaseArtifactSet(this, releaseId, manifestSha256, root, broker);
        BrokerPeerTrustRules.ValidateVerifiedReleaseArtifactSet(
            _guardian,
            "invalid-verified-release");
        BrokerPeerTrustRules.ValidateVerifiedReleaseArtifactSet(
            _broker,
            "invalid-verified-release");
    }

    public string ReleaseId { get; }

    public string ManifestSha256 { get; }

    public WindowsReleaseRootIdentity Root { get; }

    public VerifiedReleaseArtifactSet GetArtifactSet(BrokerPeerRole role) =>
        role switch
        {
            BrokerPeerRole.Guardian => _guardian,
            BrokerPeerRole.Broker => _broker,
            _ => throw new ArgumentOutOfRangeException(nameof(role))
        };

    internal static VerifiedReleaseManifest CreateFromVerifiedPayload(
        string releaseId,
        string manifestSha256,
        WindowsReleaseRootIdentity root,
        VerifiedReleaseRoleArtifacts guardian,
        VerifiedReleaseRoleArtifacts broker) =>
        new(releaseId, manifestSha256, root, guardian, broker);
}

public sealed class VerifiedReleaseArtifactSet
{
    private readonly VerifiedReleaseManifest _owner;

    internal VerifiedReleaseArtifactSet(
        VerifiedReleaseManifest owner,
        string releaseId,
        string manifestSha256,
        WindowsReleaseRootIdentity root,
        VerifiedReleaseRoleArtifacts definition)
    {
        _owner = owner;
        Role = definition.Role;
        ReleaseId = releaseId;
        ManifestSha256 = manifestSha256;
        Root = root;
        AppHostRelativePath = definition.AppHostRelativePath;
        ManagedEntryRelativePath = definition.ManagedEntryRelativePath;
        DepsRelativePath = definition.DepsRelativePath;
        RuntimeConfigRelativePath = definition.RuntimeConfigRelativePath;
        Artifacts = Array.AsReadOnly(
            definition.Artifacts?.ToArray() ??
            throw new BrokerPeerTrustException(
                "invalid-verified-release",
                "The verified release artifact set is missing."));
    }

    public BrokerPeerRole Role { get; }

    public string ReleaseId { get; }

    public string ManifestSha256 { get; }

    public WindowsReleaseRootIdentity Root { get; }

    public string AppHostRelativePath { get; }

    public string ManagedEntryRelativePath { get; }

    public string DepsRelativePath { get; }

    public string RuntimeConfigRelativePath { get; }

    public IReadOnlyList<WindowsArtifactIdentity> Artifacts { get; }

    internal bool HasVerifiedManifestAuthority =>
        ReferenceEquals(_owner.GetArtifactSet(Role), this);
}

public sealed class RetainedReleaseHandleSet
{
    public RetainedReleaseHandleSet(
        WindowsReleaseRootIdentity root,
        IReadOnlyList<string> artifactRelativePaths)
    {
        Root = root;
        ArtifactRelativePaths = Array.AsReadOnly(
            artifactRelativePaths?.ToArray() ??
            throw new ArgumentNullException(nameof(artifactRelativePaths)));
    }

    public WindowsReleaseRootIdentity Root { get; }

    public IReadOnlyList<string> ArtifactRelativePaths { get; }
}

public sealed class WindowsProcessIdentity
{
    public WindowsProcessIdentity(
        uint processId,
        DateTimeOffset creationTimeUtc,
        uint kernelSessionId,
        WindowsTokenIdentity token,
        WindowsAppModelIdentity appModel,
        string finalImagePath,
        bool imageFileObjectIsExact,
        WindowsReleaseRootIdentity releaseRoot,
        IReadOnlyList<WindowsArtifactIdentity> artifacts)
    {
        ProcessId = processId;
        CreationTimeUtc = creationTimeUtc;
        KernelSessionId = kernelSessionId;
        Token = token;
        AppModel = appModel;
        FinalImagePath = finalImagePath;
        ImageFileObjectIsExact = imageFileObjectIsExact;
        ReleaseRoot = releaseRoot;
        Artifacts = Array.AsReadOnly(
            artifacts?.ToArray() ?? throw new ArgumentNullException(nameof(artifacts)));
    }

    public uint ProcessId { get; }

    public DateTimeOffset CreationTimeUtc { get; }

    public uint KernelSessionId { get; }

    public WindowsTokenIdentity Token { get; }

    public WindowsAppModelIdentity AppModel { get; }

    public string FinalImagePath { get; }

    public bool ImageFileObjectIsExact { get; }

    public WindowsReleaseRootIdentity ReleaseRoot { get; }

    public IReadOnlyList<WindowsArtifactIdentity> Artifacts { get; }
}

public sealed record BrokerPeerHello(
    int Protocol,
    BrokerPeerRole Role,
    uint ProcessId,
    uint SessionId,
    DateTimeOffset CreationTimeUtc,
    string ConnectionNonce,
    string ReleaseId,
    string ManifestSha256);

public sealed record BrokerPeerExpectation(
    WindowsTokenIdentity Token,
    WindowsAppModelIdentity AppModel,
    VerifiedReleaseArtifactSet Release,
    string ConnectionNonce,
    uint ProcessId,
    DateTimeOffset CreationTimeUtc)
{
    public BrokerPeerRole Role => Release.Role;

    public string ReleaseId => Release.ReleaseId;

    public string ManifestSha256 => Release.ManifestSha256;
}

public readonly record struct PipePeerKernelIdentity(
    uint ProcessId,
    uint SessionId);

public sealed class PipePeerHelloReadEvidence : IDisposable
{
    private readonly byte[] _helloUtf8;
    private int _disposed;

    internal PipePeerHelloReadEvidence(
        ReadOnlySpan<byte> helloUtf8,
        long readGeneration,
        PipePeerKernelIdentity kernelIdentityBeforeTokenCapture,
        PipePeerKernelIdentity kernelIdentityAfterTokenCapture,
        WindowsTokenIdentity? impersonatedClientToken)
    {
        _helloUtf8 = helloUtf8.ToArray();
        ReadGeneration = readGeneration;
        KernelIdentityBeforeTokenCapture = kernelIdentityBeforeTokenCapture;
        KernelIdentityAfterTokenCapture = kernelIdentityAfterTokenCapture;
        ImpersonatedClientToken = impersonatedClientToken;
    }

    public long ReadGeneration { get; }

    public PipePeerKernelIdentity KernelIdentityBeforeTokenCapture { get; }

    public PipePeerKernelIdentity KernelIdentityAfterTokenCapture { get; }

    public WindowsTokenIdentity? ImpersonatedClientToken { get; }

    internal ReadOnlyMemory<byte> GetHelloUtf8()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _helloUtf8;
    }

    internal bool IsCleared => _helloUtf8.All(value => value == 0);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            CryptographicOperations.ZeroMemory(_helloUtf8);
        }
    }
}

public interface IRetainedPeerIdentityLease : IDisposable
{
    bool IsAlive { get; }

    RetainedReleaseHandleSet RetainedHandles { get; }

    WindowsProcessIdentity Capture();
}

public interface INamedPipePeerTrustPlatform : IDisposable
{
    DateTimeOffset UtcNow { get; }

    long ReadGeneration { get; }

    PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind);

    IRetainedPeerIdentityLease OpenRetainedPeer(
        uint processId,
        VerifiedReleaseArtifactSet release);

    ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
        NamedPipePeerKind peerKind,
        int maximumHelloBytes,
        CancellationToken cancellationToken);

    void AbortHandshake(string boundedFailureCode);
}

internal sealed class OwnedPipePeerResources : IDisposable
{
    private static readonly TimeSpan DisposeFollowerWaitTimeout = TimeSpan.FromSeconds(2);
    private readonly object _sync = new();
    private readonly PeerConnectionAdmission _admission;
    private readonly AsyncLocal<OwnedPipePeerResources?> _activeDispose = new();
    private readonly TaskCompletionSource<Exception?> _disposeCompletion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private IRetainedPeerIdentityLease? _peerLease;
    private bool _disposeStarted;
    private bool _disposeReleasesAdmission;
    private int _connectionMarkedUnusable;

    internal OwnedPipePeerResources(
        INamedPipePeerTrustPlatform platform,
        PeerConnectionAdmission admission)
    {
        Platform = platform;
        _admission = admission;
    }

    internal INamedPipePeerTrustPlatform Platform { get; }

    internal long ConnectionSlotId => _admission.SlotId;

    internal IRetainedPeerIdentityLease PeerLease
    {
        get
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposeStarted, this);
                return _peerLease ?? throw new InvalidOperationException(
                    "The retained peer identity lease has not been attached.");
            }
        }
    }

    internal void AttachPeerLease(IRetainedPeerIdentityLease peerLease)
    {
        ArgumentNullException.ThrowIfNull(peerLease);
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            if (_peerLease is not null)
            {
                throw new InvalidOperationException(
                    "The retained peer identity lease was already attached.");
            }

            _peerLease = peerLease;
        }
    }

    internal void MarkConnectionUnusable()
    {
        Interlocked.Exchange(ref _connectionMarkedUnusable, 1);
    }

    public void Dispose() => DisposeCore(releaseAdmission: true);

    internal void DisposeQuarantinedResources() =>
        DisposeCore(releaseAdmission: false);

    internal void ReleaseQuarantineAdmission() => _admission.Dispose();

    private void DisposeCore(bool releaseAdmission)
    {
        Task<Exception?>? waitForCompletion = null;
        IRetainedPeerIdentityLease? peerLease = null;
        var winner = false;
        lock (_sync)
        {
            if (!_disposeStarted)
            {
                _disposeStarted = true;
                _disposeReleasesAdmission = releaseAdmission;
                peerLease = _peerLease;
                winner = true;
            }
            else
            {
                if (_disposeReleasesAdmission != releaseAdmission)
                {
                    throw new InvalidOperationException(
                        "peer-resource-dispose-mode-mismatch");
                }

                if (!_disposeCompletion.Task.IsCompleted &&
                    ReferenceEquals(_activeDispose.Value, this))
                {
                    throw new InvalidOperationException(
                        "peer-resource-dispose-reentrant");
                }

                waitForCompletion = _disposeCompletion.Task;
            }
        }

        if (!winner)
        {
            Exception? observedFailure;
            try
            {
                observedFailure = waitForCompletion!
                    .WaitAsync(DisposeFollowerWaitTimeout)
                    .GetAwaiter()
                    .GetResult();
            }
            catch (TimeoutException exception)
            {
                throw new InvalidOperationException(
                    "peer-resource-dispose-wait-timeout",
                    exception);
            }

            if (observedFailure is not null)
            {
                ExceptionDispatchInfo.Capture(observedFailure).Throw();
            }

            return;
        }

        var previousDispose = _activeDispose.Value;
        _activeDispose.Value = this;
        Exception? failure = null;
        try
        {
            try
            {
                // Keep the retained identity handles until the connection is proven closed.
                Platform.Dispose();
            }
            catch (Exception exception)
            {
                failure = exception;
            }

            if (failure is null)
            {
                try
                {
                    peerLease?.Dispose();
                }
                catch (Exception exception)
                {
                    failure = exception;
                }
            }

            if (failure is null && releaseAdmission)
            {
                try
                {
                    _admission.Dispose();
                }
                catch (Exception exception)
                {
                    failure = exception;
                }
            }
        }
        finally
        {
            _activeDispose.Value = previousDispose;
            lock (_sync)
            {
                if (failure is null)
                {
                    _peerLease = null;
                }
            }

            _disposeCompletion.TrySetResult(failure);
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }

    }
}

internal sealed record PeerReadQuarantineState(
    Task<PipePeerHelloReadEvidence>? ReadTask,
    Exception? AbortFailure);

internal sealed class PeerAbortAttemptTimeoutException : TimeoutException
{
    internal PeerAbortAttemptTimeoutException(
        Exception innerException,
        Task abortTask)
        : base("The bounded named pipe abort attempt did not return in time.", innerException)
    {
        AbortTask = abortTask;
    }

    internal Task AbortTask { get; }
}

public readonly record struct NamedPipePeerTrustHealth(
    bool IsUnhealthy,
    bool RejectNewHandshakes,
    int ActiveConnectionCount,
    int QuarantinedHandshakeCount,
    int Capacity);

internal sealed class PeerConnectionAdmission : IDisposable
{
    private readonly PeerReadQuarantineRegistry _registry;
    private readonly INamedPipePeerTrustPlatform _platform;
    private int _disposed;

    internal PeerConnectionAdmission(
        PeerReadQuarantineRegistry registry,
        INamedPipePeerTrustPlatform platform,
        long slotId)
    {
        _registry = registry;
        _platform = platform;
        SlotId = slotId;
    }

    internal long SlotId { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _registry.ReleaseAdmission(_platform, SlotId);
        }
    }
}

internal sealed class PeerReadQuarantineRegistry
{
    internal const int DefaultCapacity = 8;

    private sealed class Entry
    {
        internal Entry(
            OwnedPipePeerResources resources,
            PeerReadQuarantineState state)
        {
            Resources = resources;
            State = state;
        }

        internal OwnedPipePeerResources Resources { get; }

        internal PeerReadQuarantineState State { get; }

        internal Task? WorkerTask { get; set; }

        internal Exception? WorkerStartFailure { get; set; }
    }

    private static int _globalCount;
    private static readonly ConcurrentDictionary<INamedPipePeerTrustPlatform, byte> GlobalAdmissions = new(
        ReferenceEqualityComparer.Instance);
    private readonly object _sync = new();
    private readonly Dictionary<INamedPipePeerTrustPlatform, long> _admissions = new(
        ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<long, Entry> _entries = new();
    private readonly int _capacity;
    private bool _unhealthy;
    private long _nextSlotId;

    internal PeerReadQuarantineRegistry(int capacity = DefaultCapacity)
    {
        if (capacity < 1 || capacity > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        _capacity = capacity;
    }

    internal static int GlobalCount => Volatile.Read(ref _globalCount);

    internal NamedPipePeerTrustHealth Health
    {
        get
        {
            lock (_sync)
            {
                return new NamedPipePeerTrustHealth(
                    _unhealthy,
                    _unhealthy || _admissions.Count >= _capacity,
                    _admissions.Count,
                    _entries.Count,
                    _capacity);
            }
        }
    }

    internal OwnedPipePeerResources Reserve(
        INamedPipePeerTrustPlatform platform)
    {
        lock (_sync)
        {
            if (_unhealthy)
            {
                throw new BrokerPeerTrustException(
                    "peer-trust-quarantine-active",
                    "A prior named pipe peer could not be closed; new handshakes are disabled.");
            }

            if (_admissions.ContainsKey(platform))
            {
                throw new BrokerPeerTrustException(
                    "peer-trust-connection-already-owned",
                    "The exact named pipe connection is already owned by this verifier.");
            }

            if (_admissions.Count >= _capacity)
            {
                throw new BrokerPeerTrustException(
                    "peer-trust-capacity-exceeded",
                    "The bounded named pipe peer connection capacity is exhausted.");
            }

            if (!GlobalAdmissions.TryAdd(platform, 0))
            {
                throw new BrokerPeerTrustException(
                    "peer-trust-connection-already-owned",
                    "The exact named pipe connection is already owned by this verifier.");
            }

            var slotId = ++_nextSlotId;
            try
            {
                _admissions.Add(platform, slotId);
                return new OwnedPipePeerResources(
                    platform,
                    new PeerConnectionAdmission(this, platform, slotId));
            }
            catch
            {
                GlobalAdmissions.TryRemove(platform, out _);
                throw;
            }
        }
    }

    internal void ReleaseAdmission(
        INamedPipePeerTrustPlatform platform,
        long slotId)
    {
        lock (_sync)
        {
            if (!_admissions.TryGetValue(platform, out var currentSlotId) ||
                currentSlotId != slotId ||
                !_admissions.Remove(platform) ||
                !GlobalAdmissions.TryRemove(platform, out _))
            {
                Environment.FailFast(
                    "The named pipe peer connection admission was released by the wrong owner.");
            }
        }
    }

    internal void Register(
        OwnedPipePeerResources resources,
        PeerReadQuarantineState state)
    {
        resources.MarkConnectionUnusable();
        var id = resources.ConnectionSlotId;
        var entry = new Entry(resources, state);
        lock (_sync)
        {
            if (!_admissions.TryGetValue(resources.Platform, out var admittedId) ||
                admittedId != id ||
                !_entries.TryAdd(id, entry))
            {
                Environment.FailFast(
                    "The named pipe peer quarantine received invalid connection ownership.");
            }

            _unhealthy = true;
            Interlocked.Increment(ref _globalCount);
        }

        try
        {
            entry.WorkerTask = Task.Run(
                () => DrainSafelyAsync(id, entry),
                CancellationToken.None);
        }
        catch (Exception exception)
        {
            entry.WorkerStartFailure = exception;
        }
    }

    private async Task DrainSafelyAsync(long id, Entry entry)
    {
        try
        {
            await DrainAsync(id, entry).ConfigureAwait(false);
        }
        catch
        {
            // The retained entry intentionally remains unhealthy for process-level fail-stop.
        }
    }

    private async Task DrainAsync(long id, Entry entry)
    {
        var readObservationTask = ObserveLateReadAsync(entry.State.ReadTask);
        var canReleaseResources = true;
        if (entry.State.AbortFailure is PeerAbortAttemptTimeoutException abortTimeout)
        {
            canReleaseResources = await ObserveAbortOutcomeAsync(
                abortTimeout.AbortTask).ConfigureAwait(false);
        }
        else if (entry.State.AbortFailure is not null)
        {
            var retryFailure = WindowsNamedPipePeerVerifier.TryAbortHandshake(
                entry.Resources.Platform,
                "peer-handshake-quarantine");
            canReleaseResources = retryFailure switch
            {
                null => true,
                PeerAbortAttemptTimeoutException retryTimeout =>
                    await ObserveAbortOutcomeAsync(retryTimeout.AbortTask).ConfigureAwait(false),
                _ => false
            };
        }

        await readObservationTask.ConfigureAwait(false);

        if (!canReleaseResources)
        {
            return;
        }

        try
        {
            entry.Resources.DisposeQuarantinedResources();
        }
        catch
        {
            return;
        }

        lock (_sync)
        {
            if (_entries.TryRemove(id, out _))
            {
                entry.Resources.ReleaseQuarantineAdmission();
                Interlocked.Decrement(ref _globalCount);
            }
        }
    }

    private static async Task<bool> ObserveAbortOutcomeAsync(Task abortTask)
    {
        try
        {
            await abortTask.ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task ObserveLateReadAsync(
        Task<PipePeerHelloReadEvidence>? readTask)
    {
        if (readTask is null)
        {
            return;
        }

        try
        {
            var lateEvidence = await readTask.ConfigureAwait(false);
            lateEvidence.Dispose();
        }
        catch
        {
        }
    }
}

public sealed class BrokerPeerTrustException : InvalidOperationException
{
    public BrokerPeerTrustException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public BrokerPeerTrustException(string code, string message, Exception innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    public string Code { get; }

    internal PeerReadQuarantineState? QuarantineState { get; set; }
}

public static class BrokerPeerHelloProtocol
{
    public const int ProtocolVersion = 3;
    public const int MaximumHelloBytes = 4096;

    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 4
    };

    public static byte[] Serialize(BrokerPeerHello hello)
    {
        ArgumentNullException.ThrowIfNull(hello);
        BrokerPeerTrustRules.ValidateHelloShape(hello);
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false
        }))
        {
            writer.WriteStartObject();
            writer.WriteString("kind", "peerHello");
            writer.WriteNumber("protocol", hello.Protocol);
            writer.WriteString("role", SerializeRole(hello.Role));
            writer.WriteNumber("processId", hello.ProcessId);
            writer.WriteNumber("sessionId", hello.SessionId);
            writer.WriteString("creationTimeFileTime", FormatFileTime(hello.CreationTimeUtc));
            writer.WriteString("connectionNonce", hello.ConnectionNonce);
            writer.WriteString("releaseId", hello.ReleaseId);
            writer.WriteString("manifestSha256", hello.ManifestSha256);
            writer.WriteEndObject();
        }

        if (output.Length > MaximumHelloBytes)
        {
            throw new BrokerPeerTrustException(
                "peer-hello-too-large",
                "The broker peer hello exceeded the bounded size.");
        }

        return output.ToArray();
    }

    public static BrokerPeerHello Parse(ReadOnlyMemory<byte> utf8Json)
    {
        if (utf8Json.Length is < 2 or > MaximumHelloBytes)
        {
            throw new BrokerPeerTrustException(
                "invalid-peer-hello",
                "The broker peer hello length is invalid.");
        }

        try
        {
            using var document = JsonDocument.Parse(utf8Json, JsonOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !HasExactProperties(
                    root,
                    "kind",
                    "protocol",
                    "role",
                    "processId",
                    "sessionId",
                    "creationTimeFileTime",
                    "connectionNonce",
                    "releaseId",
                    "manifestSha256") ||
                !TryGetString(root, "kind", out var kind) ||
                !string.Equals(kind, "peerHello", StringComparison.Ordinal) ||
                !root.TryGetProperty("protocol", out var protocolElement) ||
                !protocolElement.TryGetInt32(out var protocol) ||
                !TryGetString(root, "role", out var roleText) ||
                !TryParseRole(roleText, out var role) ||
                !root.TryGetProperty("processId", out var processIdElement) ||
                !processIdElement.TryGetUInt32(out var processId) ||
                !root.TryGetProperty("sessionId", out var sessionIdElement) ||
                !sessionIdElement.TryGetUInt32(out var sessionId) ||
                !TryGetString(root, "creationTimeFileTime", out var creationTimeFileTime) ||
                !TryGetString(root, "connectionNonce", out var connectionNonce) ||
                !TryGetString(root, "releaseId", out var releaseId) ||
                !TryGetString(root, "manifestSha256", out var manifestSha256))
            {
                throw new BrokerPeerTrustException(
                    "invalid-peer-hello",
                    "The broker peer hello shape is invalid.");
            }

            var hello = new BrokerPeerHello(
                protocol,
                role,
                processId,
                sessionId,
                ParseFileTime(creationTimeFileTime),
                connectionNonce,
                releaseId,
                manifestSha256);
            BrokerPeerTrustRules.ValidateHelloShape(hello);
            return hello;
        }
        catch (BrokerPeerTrustException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new BrokerPeerTrustException(
                "invalid-peer-hello",
                "The broker peer hello is not valid bounded JSON.",
                exception);
        }
    }

    private static string FormatFileTime(DateTimeOffset creationTimeUtc)
    {
        try
        {
            return creationTimeUtc.ToFileTime().ToString("X16", CultureInfo.InvariantCulture);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new BrokerPeerTrustException(
                "invalid-peer-hello",
                "The broker peer hello creation time is invalid.",
                exception);
        }
    }

    private static DateTimeOffset ParseFileTime(string value)
    {
        if (value.Length != 16 ||
            value.Any(character => !char.IsAsciiDigit(character) && character is < 'A' or > 'F') ||
            !long.TryParse(
                value,
                NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture,
                out var fileTime))
        {
            throw new BrokerPeerTrustException(
                "invalid-peer-hello",
                "The broker peer hello FILETIME is not canonical.");
        }

        try
        {
            return DateTimeOffset.FromFileTime(fileTime).ToUniversalTime();
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new BrokerPeerTrustException(
                "invalid-peer-hello",
                "The broker peer hello creation time is invalid.",
                exception);
        }
    }

    private static bool HasExactProperties(JsonElement root, params string[] expected)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var property in root.EnumerateObject())
        {
            count++;
            if (!seen.Add(property.Name))
            {
                return false;
            }
        }

        return count == expected.Length && expected.All(seen.Contains);
    }

    private static bool TryGetString(JsonElement root, string name, out string value)
    {
        value = string.Empty;
        return root.TryGetProperty(name, out var element) &&
               element.ValueKind == JsonValueKind.String &&
               element.GetString() is { } parsed &&
               (value = parsed) is not null;
    }

    private static string SerializeRole(BrokerPeerRole role) =>
        role switch
        {
            BrokerPeerRole.Guardian => "guardian",
            BrokerPeerRole.Broker => "broker",
            _ => throw new BrokerPeerTrustException(
                "invalid-peer-hello",
                "The broker peer hello role is invalid.")
        };

    private static bool TryParseRole(string value, out BrokerPeerRole role)
    {
        if (string.Equals(value, "guardian", StringComparison.Ordinal))
        {
            role = BrokerPeerRole.Guardian;
            return true;
        }

        if (string.Equals(value, "broker", StringComparison.Ordinal))
        {
            role = BrokerPeerRole.Broker;
            return true;
        }

        role = default;
        return false;
    }
}

internal sealed record CompletedPipePeerVerification(
    BrokerPeerHello Hello,
    WindowsProcessIdentity Identity);

internal sealed record PendingVerificationTerminalResult(
    Exception? CleanupFailure);

public sealed class PendingPipePeerVerification : IAsyncDisposable
{
    private const int Pending = 0;
    private const int Completing = 1;
    private const int TransferCommitting = 2;
    private const int Transferred = 3;
    private const int Finalizing = 4;
    private const int Terminal = 5;

    private readonly object _abortSync = new();
    private readonly object _resourceSync = new();
    private readonly WindowsNamedPipePeerVerifier _verifier;
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly TaskCompletionSource<PendingVerificationTerminalResult> _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly INamedPipePeerTrustPlatform _platform;
    private Exception? _abortFailure;
    private OwnedPipePeerResources? _resources;
    private bool _abortSignaled;
    private int _lifetimeDisposed;
    private int _state;

    internal PendingPipePeerVerification(
        WindowsNamedPipePeerVerifier verifier,
        OwnedPipePeerResources resources,
        NamedPipePeerKind peerKind,
        BrokerPeerExpectation expectation,
        PipePeerKernelIdentity initialKernelIdentity,
        long initialReadGeneration,
        WindowsProcessIdentity initialIdentity)
    {
        _verifier = verifier;
        _platform = resources.Platform;
        _resources = resources;
        PeerKind = peerKind;
        Expectation = expectation;
        InitialKernelIdentity = initialKernelIdentity;
        InitialReadGeneration = initialReadGeneration;
        InitialIdentity = initialIdentity;
    }

    public PipePeerKernelIdentity InitialKernelIdentity { get; }

    public long InitialReadGeneration { get; }

    public WindowsProcessIdentity InitialIdentity { get; }

    internal INamedPipePeerTrustPlatform Platform => _platform;

    internal NamedPipePeerKind PeerKind { get; }

    internal BrokerPeerExpectation Expectation { get; }

    internal CancellationToken LifetimeCancellation => _lifetimeCancellation.Token;

    internal IRetainedPeerIdentityLease PeerLease
    {
        get
        {
            return GetOwnedResources().PeerLease;
        }
    }

    public async ValueTask<VerifiedPipePeerIdentity> CompleteAsync(
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _state, Completing, Pending) != Pending)
        {
            throw new ObjectDisposedException(nameof(PendingPipePeerVerification));
        }

        OwnedPipePeerResources? transferResources = null;
        VerifiedPipePeerIdentity peer;
        try
        {
            var completed = await _verifier.CompleteVerificationAsync(
                this,
                cancellationToken).ConfigureAwait(false);
            _verifier.BeforeAuthorityTransfer();
            if (Interlocked.CompareExchange(
                    ref _state,
                    TransferCommitting,
                    Completing) != Completing)
            {
                throw new BrokerPeerTrustException(
                    "peer-handshake-cancelled",
                    "The peer verification was disposed before authority transfer completed.");
            }

            transferResources = TakeOwnedResources();
            peer = new VerifiedPipePeerIdentity(
                _verifier,
                transferResources,
                PeerKind,
                completed.Hello,
                Expectation,
                completed.Identity);
            _verifier.AfterAuthorityTransfer();
            transferResources = null;
        }
        catch (Exception exception)
        {
            Volatile.Write(ref _state, Terminal);
            var ownedResources = transferResources ?? TakeOwnedResourcesOrNull();
            if (ownedResources is null)
            {
                var ownershipFailure = new InvalidOperationException(
                    "The failed pending verification no longer owned its connection resources.");
                exception.Data["peer-trust-ownership-failure"] = ownershipFailure;
                PublishTerminal(exception);
                DisposeLifetimeCancellation();
                throw;
            }

            ownedResources.MarkConnectionUnusable();
            var abortFailure = AbortHandshakeOnce(
                WindowsNamedPipePeerVerifier.GetFailureCode(exception));
            var failure = _verifier.FinalizeAfterAbort(
                ownedResources,
                exception,
                abortFailure);
            var cleanupFailure = WindowsNamedPipePeerVerifier.IsAbortFailed(failure)
                ? failure
                : null;
            PublishTerminal(cleanupFailure);
            DisposeLifetimeCancellation();

            if (ReferenceEquals(failure, exception))
            {
                throw;
            }

            throw failure;
        }

        Volatile.Write(ref _state, Transferred);
        PublishTerminal(cleanupFailure: null);
        DisposeLifetimeCancellation();
        return peer;
    }

    public async ValueTask<AuthenticatedPipePeerConnection> CompleteConnectionAsync(
        CancellationToken cancellationToken = default)
    {
        var peer = await CompleteAsync(cancellationToken).ConfigureAwait(false);
        if (_platform is not INamedPipePeerMessageTransport transport)
        {
            var failure = new BrokerPeerTrustException(
                "peer-message-transport-unsupported",
                "The verified named pipe platform does not provide an authenticated message channel.");
            DisposePeerAfterConnectionFailure(peer, failure);
            throw failure;
        }

        try
        {
            return new AuthenticatedPipePeerConnection(
                peer,
                transport,
                Expectation.Role);
        }
        catch (Exception exception)
        {
            DisposePeerAfterConnectionFailure(peer, exception);
            throw;
        }
    }

    internal bool WasCreatedBy(WindowsNamedPipePeerVerifier verifier) =>
        ReferenceEquals(_verifier, verifier);

    private static void DisposePeerAfterConnectionFailure(
        VerifiedPipePeerIdentity peer,
        Exception originalFailure)
    {
        try
        {
            peer.Dispose();
        }
        catch (Exception cleanupFailure)
        {
            throw new BrokerPeerTrustException(
                "peer-connection-transfer-failed",
                "The verified peer could not be closed after connection authority transfer failed.",
                new AggregateException(originalFailure, cleanupFailure));
        }
    }

    public async ValueTask DisposeAsync()
    {
        while (true)
        {
            var state = Volatile.Read(ref _state);
            if (state == Transferred)
            {
                return;
            }

            if (state == Terminal ||
                state == Finalizing ||
                state == TransferCommitting)
            {
                await AwaitTerminalCleanupAsync().ConfigureAwait(false);
                return;
            }

            if (state == Pending &&
                Interlocked.CompareExchange(ref _state, Finalizing, Pending) == Pending)
            {
                CancelLifetimeNoThrow();
                var resources = TakeOwnedResources();
                resources.MarkConnectionUnusable();
                var abortFailure = AbortHandshakeOnce("peer-verification-abandoned");
                Exception? cleanupFailure = null;
                try
                {
                    var abandonmentFailure = new BrokerPeerTrustException(
                        "peer-verification-abandoned",
                        "The pending peer verification was abandoned.");
                    if (abortFailure is null)
                    {
                        try
                        {
                            resources.Dispose();
                        }
                        catch (Exception resourceCleanupFailure)
                        {
                            abandonmentFailure.Data["peer-trust-cleanup-failure"] = resourceCleanupFailure;
                            var failure = WindowsNamedPipePeerVerifier.CreateAbortFailedException(
                                new AggregateException(abandonmentFailure, resourceCleanupFailure),
                                abortFailure: null,
                                readTask: null);
                            _verifier.RegisterQuarantine(
                                resources,
                                failure.QuarantineState!);
                            cleanupFailure = failure;
                            throw failure;
                        }
                    }
                    else
                    {
                        var failure = WindowsNamedPipePeerVerifier.CreateAbortFailedException(
                            abandonmentFailure,
                            abortFailure,
                            readTask: null);
                        _verifier.RegisterQuarantine(
                            resources,
                            failure.QuarantineState!);
                        cleanupFailure = failure;
                        throw failure;
                    }
                }
                catch (Exception exception) when (cleanupFailure is null)
                {
                    cleanupFailure = exception;
                    throw;
                }
                finally
                {
                    Volatile.Write(ref _state, Terminal);
                    PublishTerminal(cleanupFailure);
                    DisposeLifetimeCancellation();
                }

                return;
            }

            if (Interlocked.CompareExchange(ref _state, Finalizing, Completing) == Completing)
            {
                CancelLifetimeNoThrow();
                AbortHandshakeOnce("peer-verification-cancelled");
                await AwaitTerminalCleanupAsync().ConfigureAwait(false);
                return;
            }
        }
    }

    private OwnedPipePeerResources GetOwnedResources()
    {
        lock (_resourceSync)
        {
            return _resources ??
                throw new ObjectDisposedException(nameof(PendingPipePeerVerification));
        }
    }

    private OwnedPipePeerResources TakeOwnedResources()
    {
        lock (_resourceSync)
        {
            var resources = _resources ??
                throw new ObjectDisposedException(nameof(PendingPipePeerVerification));
            _resources = null;
            return resources;
        }
    }

    private OwnedPipePeerResources? TakeOwnedResourcesOrNull()
    {
        lock (_resourceSync)
        {
            var resources = _resources;
            _resources = null;
            return resources;
        }
    }

    private void CancelLifetimeNoThrow()
    {
        try
        {
            _lifetimeCancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception)
        {
        }
    }

    internal Exception? AbortHandshakeOnce(string failureCode)
    {
        lock (_abortSync)
        {
            if (_abortSignaled)
            {
                return _abortFailure;
            }

            _abortSignaled = true;
            lock (_resourceSync)
            {
                _resources?.MarkConnectionUnusable();
            }

            _abortFailure = WindowsNamedPipePeerVerifier.TryAbortHandshake(
                Platform,
                failureCode);
            return _abortFailure;
        }
    }

    private void PublishTerminal(Exception? cleanupFailure) =>
        _completion.TrySetResult(new PendingVerificationTerminalResult(cleanupFailure));

    private async ValueTask AwaitTerminalCleanupAsync()
    {
        var terminal = await _completion.Task.ConfigureAwait(false);
        if (terminal.CleanupFailure is not null)
        {
            ExceptionDispatchInfo.Capture(terminal.CleanupFailure).Throw();
        }
    }

    private void DisposeLifetimeCancellation()
    {
        if (Interlocked.Exchange(ref _lifetimeDisposed, 1) == 0)
        {
            _lifetimeCancellation.Dispose();
        }
    }
}

public sealed class VerifiedPipePeerIdentity : IDisposable
{
    private readonly object _sync = new();
    private readonly WindowsNamedPipePeerVerifier _verifier;
    private readonly NamedPipePeerKind _peerKind;
    private readonly BrokerPeerHello _hello;
    private readonly BrokerPeerExpectation _expectation;
    private Exception? _disposeFailure;
    private OwnedPipePeerResources? _resources;
    private int _disposed;

    internal VerifiedPipePeerIdentity(
        WindowsNamedPipePeerVerifier verifier,
        OwnedPipePeerResources resources,
        NamedPipePeerKind peerKind,
        BrokerPeerHello hello,
        BrokerPeerExpectation expectation,
        WindowsProcessIdentity initialIdentity)
    {
        _verifier = verifier;
        _resources = resources;
        _peerKind = peerKind;
        _hello = hello;
        _expectation = expectation;
        InitialIdentity = initialIdentity;
    }

    public WindowsProcessIdentity InitialIdentity { get; }

    public WindowsProcessIdentity Revalidate()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var resources = _resources ??
                throw new ObjectDisposedException(nameof(VerifiedPipePeerIdentity));
            try
            {
                return _verifier.Revalidate(
                    resources.Platform,
                    resources.PeerLease,
                    _peerKind,
                    _hello,
                    _expectation,
                    InitialIdentity);
            }
            catch (BrokerPeerTrustException exception)
            {
                var failure = Invalidate(exception);
                if (ReferenceEquals(failure, exception))
                {
                    throw;
                }

                throw failure;
            }
            catch (Exception exception)
            {
                var wrapped = new BrokerPeerTrustException(
                    "peer-platform-failure",
                    "The named pipe peer revalidation failed closed.",
                    exception);
                throw Invalidate(wrapped);
            }
        }
    }

    private Exception Invalidate(Exception failure)
    {
        _disposed = 1;
        var resources = _resources ??
            throw new ObjectDisposedException(nameof(VerifiedPipePeerIdentity));
        _resources = null;
        resources.MarkConnectionUnusable();
        var abortFailure = WindowsNamedPipePeerVerifier.TryAbortHandshake(
            resources.Platform,
            WindowsNamedPipePeerVerifier.GetFailureCode(failure));
        var terminalFailure = _verifier.FinalizeAfterAbort(
            resources,
            failure,
            abortFailure);
        if (WindowsNamedPipePeerVerifier.IsAbortFailed(terminalFailure))
        {
            _disposeFailure = terminalFailure;
        }

        return terminalFailure;
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed != 0)
            {
                if (_disposeFailure is not null)
                {
                    ExceptionDispatchInfo.Capture(_disposeFailure).Throw();
                }

                return;
            }

            _disposed = 1;
            var resources = _resources ??
                throw new ObjectDisposedException(nameof(VerifiedPipePeerIdentity));
            _resources = null;
            try
            {
                resources.Dispose();
            }
            catch (Exception cleanupFailure)
            {
                var originalFailure = new BrokerPeerTrustException(
                    "peer-verified-dispose-failed",
                    "The verified named pipe peer resources could not be released.",
                    cleanupFailure);
                resources.MarkConnectionUnusable();
                _disposeFailure = _verifier.FinalizeAfterAbort(
                    resources,
                    originalFailure,
                    WindowsNamedPipePeerVerifier.TryAbortHandshake(
                        resources.Platform,
                        originalFailure.Code));
                throw _disposeFailure;
            }
        }
    }
}

public sealed class WindowsNamedPipePeerVerifier
{
    private readonly Action? _afterAuthorityTransfer;
    private readonly Action? _beforeAuthorityTransfer;
    private readonly PeerReadQuarantineRegistry _quarantineRegistry;

    public static TimeSpan DefaultHandshakeTimeout { get; } = TimeSpan.FromSeconds(10);

    public static TimeSpan AbortDrainTimeout { get; } = TimeSpan.FromSeconds(2);

    public static TimeSpan AbortAttemptTimeout { get; } = TimeSpan.FromSeconds(2);

    public static int QuarantinedHandshakeCount => PeerReadQuarantineRegistry.GlobalCount;

    public static int DefaultConnectionCapacity => PeerReadQuarantineRegistry.DefaultCapacity;

    public NamedPipePeerTrustHealth Health => _quarantineRegistry.Health;

    public WindowsNamedPipePeerVerifier()
        : this(DefaultHandshakeTimeout, null, null)
    {
    }

    public WindowsNamedPipePeerVerifier(TimeSpan handshakeTimeout)
        : this(handshakeTimeout, null, null)
    {
    }

    internal WindowsNamedPipePeerVerifier(
        TimeSpan handshakeTimeout,
        Action? beforeAuthorityTransfer,
        Action? afterAuthorityTransfer)
        : this(
            handshakeTimeout,
            beforeAuthorityTransfer,
            afterAuthorityTransfer,
            PeerReadQuarantineRegistry.DefaultCapacity)
    {
    }

    internal WindowsNamedPipePeerVerifier(
        TimeSpan handshakeTimeout,
        Action? beforeAuthorityTransfer,
        Action? afterAuthorityTransfer,
        int maximumConnections)
    {
        if (handshakeTimeout < TimeSpan.FromMilliseconds(50) ||
            handshakeTimeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(handshakeTimeout));
        }

        HandshakeTimeout = handshakeTimeout;
        _beforeAuthorityTransfer = beforeAuthorityTransfer;
        _afterAuthorityTransfer = afterAuthorityTransfer;
        _quarantineRegistry = new PeerReadQuarantineRegistry(maximumConnections);
    }

    public TimeSpan HandshakeTimeout { get; }

    internal void AfterAuthorityTransfer() => _afterAuthorityTransfer?.Invoke();

    internal void BeforeAuthorityTransfer() => _beforeAuthorityTransfer?.Invoke();

    private static CancellationTokenRegistration RegisterCancellationForwarder(
        CancellationToken source,
        CancellationTokenSource destination) =>
        source.CanBeCanceled
            ? source.Register(
                static state => CancelNoThrow((CancellationTokenSource)state!),
                destination)
            : default;

    private static void CancelNoThrow(CancellationTokenSource cancellation)
    {
        try
        {
            cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception)
        {
        }
    }

    public PendingPipePeerVerification BeginVerification(
        INamedPipePeerTrustPlatform platform,
        NamedPipePeerKind peerKind,
        BrokerPeerExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(expectation);
        var resources = _quarantineRegistry.Reserve(platform);
        try
        {
            var frozenExpectation = BrokerPeerTrustRules.FreezeAndValidateExpectation(
                expectation,
                peerKind);
            var initialReadGeneration = platform.ReadGeneration;
            BrokerPeerTrustRules.Require(
                initialReadGeneration == 0,
                "peer-hello-read-order-invalid",
                "The peer hello was not the first logical frame on this pipe instance.");
            var kernelBefore = platform.CaptureKernelPeer(peerKind);
            BrokerPeerTrustRules.ValidateKernelPeer(
                kernelBefore,
                frozenExpectation,
                "peer-kernel-identity-mismatch");
            var peerLease = platform.OpenRetainedPeer(
                kernelBefore.ProcessId,
                frozenExpectation.Release);
            resources.AttachPeerLease(peerLease);
            BrokerPeerTrustRules.ValidateRetainedHandles(
                peerLease,
                frozenExpectation.Release);
            var first = CaptureAndValidate(
                platform,
                peerLease,
                kernelBefore,
                frozenExpectation);
            var kernelAfter = platform.CaptureKernelPeer(peerKind);
            BrokerPeerTrustRules.RequireStableKernelPeer(
                kernelBefore,
                kernelAfter,
                "peer-kernel-identity-changed");
            var second = CaptureAndValidate(
                platform,
                peerLease,
                kernelAfter,
                frozenExpectation);
            BrokerPeerTrustRules.ValidateStableProcessIdentity(first, second);
            return new PendingPipePeerVerification(
                this,
                resources,
                peerKind,
                frozenExpectation,
                kernelAfter,
                initialReadGeneration,
                second);
        }
        catch (BrokerPeerTrustException exception)
        {
            resources.MarkConnectionUnusable();
            var failure = FinalizeAfterAbort(
                resources,
                exception,
                TryAbortHandshake(platform, exception.Code));
            if (ReferenceEquals(failure, exception))
            {
                throw;
            }

            throw failure;
        }
        catch (Exception exception)
        {
            var wrapped = new BrokerPeerTrustException(
                "peer-platform-failure",
                "The named pipe peer platform verification failed closed.",
                exception);
            resources.MarkConnectionUnusable();
            throw FinalizeAfterAbort(
                resources,
                wrapped,
                TryAbortHandshake(platform, wrapped.Code));
        }
    }

    internal async ValueTask<CompletedPipePeerVerification> CompleteVerificationAsync(
        PendingPipePeerVerification pending,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pending);
        if (!pending.WasCreatedBy(this))
        {
            throw new BrokerPeerTrustException(
                "pending-peer-owner-mismatch",
                "The pending pipe peer verification belongs to another verifier.");
        }

        using var timeoutCancellation = new CancellationTokenSource(HandshakeTimeout);
        using var completionCancellation = new CancellationTokenSource();
        using var callerCancellationForwarder = RegisterCancellationForwarder(
            cancellationToken,
            completionCancellation);
        using var lifetimeCancellationForwarder = RegisterCancellationForwarder(
            pending.LifetimeCancellation,
            completionCancellation);
        using var timeoutCancellationForwarder = RegisterCancellationForwarder(
            timeoutCancellation.Token,
            completionCancellation);
        try
        {
            using var evidence = await ReadHelloWithCancellationAsync(
                pending,
                completionCancellation.Token).ConfigureAwait(false);
            BrokerPeerTrustRules.ValidateHelloReadEvidence(
                evidence,
                pending.PeerKind,
                pending.InitialKernelIdentity,
                pending.InitialReadGeneration,
                pending.Platform.ReadGeneration);
            var hello = BrokerPeerHelloProtocol.Parse(evidence.GetHelloUtf8());
            BrokerPeerTrustRules.ValidateHelloAgainstExpectation(
                hello,
                pending.Expectation,
                pending.PeerKind);
            completionCancellation.Token.ThrowIfCancellationRequested();
            var first = CaptureAndValidate(
                pending.Platform,
                pending.PeerLease,
                evidence.KernelIdentityAfterTokenCapture,
                pending.Expectation);
            completionCancellation.Token.ThrowIfCancellationRequested();
            var kernelMiddle = pending.Platform.CaptureKernelPeer(pending.PeerKind);
            BrokerPeerTrustRules.RequireStableKernelPeer(
                pending.InitialKernelIdentity,
                kernelMiddle,
                "peer-kernel-identity-changed");
            var second = CaptureAndValidate(
                pending.Platform,
                pending.PeerLease,
                kernelMiddle,
                pending.Expectation);
            completionCancellation.Token.ThrowIfCancellationRequested();
            var kernelAfter = pending.Platform.CaptureKernelPeer(pending.PeerKind);
            BrokerPeerTrustRules.RequireStableKernelPeer(
                pending.InitialKernelIdentity,
                kernelAfter,
                "peer-kernel-identity-changed");
            BrokerPeerTrustRules.Require(
                pending.Platform.ReadGeneration == evidence.ReadGeneration,
                "peer-hello-read-order-invalid",
                "Another pipe frame was read before peer hello verification completed.");
            BrokerPeerTrustRules.ValidateHelloProcessBinding(
                hello,
                pending.Expectation,
                kernelAfter,
                second);
            BrokerPeerTrustRules.ValidateHelloImpersonationBinding(
                pending.PeerKind,
                evidence.ImpersonatedClientToken,
                first.Token,
                second.Token);
            BrokerPeerTrustRules.ValidateStableProcessIdentity(first, second);
            BrokerPeerTrustRules.ValidateStableProcessIdentity(
                pending.InitialIdentity,
                second);
            completionCancellation.Token.ThrowIfCancellationRequested();
            return new CompletedPipePeerVerification(hello, second);
        }
        catch (OperationCanceledException exception) when (
            timeoutCancellation.IsCancellationRequested &&
            !cancellationToken.IsCancellationRequested &&
            !pending.LifetimeCancellation.IsCancellationRequested)
        {
            throw new BrokerPeerTrustException(
                "peer-handshake-timeout",
                "The named pipe peer did not complete its hello within the bounded deadline.",
                exception);
        }
        catch (OperationCanceledException exception)
        {
            throw new BrokerPeerTrustException(
                "peer-handshake-cancelled",
                "The named pipe peer hello verification was cancelled.",
                exception);
        }
        catch (BrokerPeerTrustException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new BrokerPeerTrustException(
                "peer-platform-failure",
                "The named pipe peer hello completion failed closed.",
                exception);
        }
    }

    private static async ValueTask<PipePeerHelloReadEvidence> ReadHelloWithCancellationAsync(
        PendingPipePeerVerification pending,
        CancellationToken cancellationToken)
    {
        var readTask = Task.Run(
            async () => await pending.Platform.ReadBoundedHelloAndCaptureIdentityAsync(
                pending.PeerKind,
                BrokerPeerHelloProtocol.MaximumHelloBytes,
                cancellationToken).ConfigureAwait(false),
            CancellationToken.None);
        try
        {
            return await readTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception originalFailure)
        {
            var abortFailure = pending.AbortHandshakeOnce("peer-handshake-read-aborted");
            try
            {
                var lateEvidence = await readTask
                    .WaitAsync(AbortDrainTimeout)
                    .ConfigureAwait(false);
                lateEvidence.Dispose();
            }
            catch (TimeoutException drainFailure)
            {
                throw CreateAbortFailedException(
                    new AggregateException(originalFailure, drainFailure),
                    abortFailure,
                    readTask);
            }
            catch
            {
            }

            if (abortFailure is not null)
            {
                throw CreateAbortFailedException(
                    originalFailure,
                    abortFailure,
                    readTask);
            }

            ExceptionDispatchInfo.Capture(originalFailure).Throw();
            throw new InvalidOperationException("Unreachable peer hello read failure path.");
        }
    }

    internal WindowsProcessIdentity Revalidate(
        INamedPipePeerTrustPlatform platform,
        IRetainedPeerIdentityLease peerLease,
        NamedPipePeerKind peerKind,
        BrokerPeerHello hello,
        BrokerPeerExpectation expectation,
        WindowsProcessIdentity initialIdentity)
    {
        var kernelBefore = platform.CaptureKernelPeer(peerKind);
        BrokerPeerTrustRules.ValidateKernelPeer(
            kernelBefore,
            expectation,
            "peer-kernel-identity-mismatch");
        var first = CaptureAndValidate(platform, peerLease, kernelBefore, expectation);
        var kernelAfter = platform.CaptureKernelPeer(peerKind);
        BrokerPeerTrustRules.RequireStableKernelPeer(
            kernelBefore,
            kernelAfter,
            "peer-kernel-identity-changed");
        var second = CaptureAndValidate(platform, peerLease, kernelAfter, expectation);
        BrokerPeerTrustRules.ValidateHelloProcessBinding(
            hello,
            expectation,
            kernelAfter,
            second);
        BrokerPeerTrustRules.ValidateStableProcessIdentity(first, second);
        BrokerPeerTrustRules.ValidateStableProcessIdentity(initialIdentity, second);
        return second;
    }

    private static WindowsProcessIdentity CaptureAndValidate(
        INamedPipePeerTrustPlatform platform,
        IRetainedPeerIdentityLease peerLease,
        PipePeerKernelIdentity kernelIdentity,
        BrokerPeerExpectation expectation)
    {
        BrokerPeerTrustRules.ValidateRetainedHandles(peerLease, expectation.Release);
        BrokerPeerTrustRules.Require(
            peerLease.IsAlive,
            "peer-process-exited",
            "The retained named pipe peer process has exited.");
        var identity = peerLease.Capture();
        BrokerPeerTrustRules.ValidateProcessIdentity(
            identity,
            kernelIdentity,
            expectation,
            platform.UtcNow);
        BrokerPeerTrustRules.Require(
            peerLease.IsAlive,
            "peer-process-exited",
            "The retained named pipe peer process exited during verification.");
        BrokerPeerTrustRules.ValidateRetainedHandles(peerLease, expectation.Release);
        return identity;
    }

    internal static string GetFailureCode(Exception exception) =>
        exception is BrokerPeerTrustException trustException
            ? trustException.Code
            : "peer-platform-failure";

    internal static BrokerPeerTrustException CreateAbortFailedException(
        Exception originalFailure,
        Exception? abortFailure,
        Task<PipePeerHelloReadEvidence>? readTask)
    {
        var failures = abortFailure is null
            ? new[] { originalFailure }
            : new[] { originalFailure, abortFailure };
        return new BrokerPeerTrustException(
            "peer-handshake-abort-failed",
            "The peer handshake slot could not be closed within the bounded abort contract.",
            new AggregateException(failures))
        {
            QuarantineState = new PeerReadQuarantineState(readTask, abortFailure)
        };
    }

    internal Exception FinalizeAfterAbort(
        OwnedPipePeerResources resources,
        Exception originalFailure,
        Exception? abortFailure)
    {
        Exception failure = originalFailure;
        if (abortFailure is not null &&
            (originalFailure as BrokerPeerTrustException)?.QuarantineState is null)
        {
            failure = CreateAbortFailedException(
                originalFailure,
                abortFailure,
                readTask: null);
        }

        if ((failure as BrokerPeerTrustException)?.QuarantineState is { } quarantineState)
        {
            _quarantineRegistry.Register(resources, quarantineState);
        }
        else
        {
            try
            {
                resources.Dispose();
            }
            catch (Exception cleanupFailure)
            {
                originalFailure.Data["peer-trust-cleanup-failure"] = cleanupFailure;
                failure = CreateAbortFailedException(
                    new AggregateException(originalFailure, cleanupFailure),
                    abortFailure: null,
                    readTask: null);
                _quarantineRegistry.Register(
                    resources,
                    ((BrokerPeerTrustException)failure).QuarantineState!);
            }
        }

        return failure;
    }

    internal void RegisterQuarantine(
        OwnedPipePeerResources resources,
        PeerReadQuarantineState state) =>
        _quarantineRegistry.Register(resources, state);

    internal static bool IsAbortFailed(Exception exception) =>
        exception is BrokerPeerTrustException
        {
            Code: "peer-handshake-abort-failed"
        };

    internal static Exception? TryAbortHandshake(
        INamedPipePeerTrustPlatform platform,
        string failureCode)
    {
        Task abortTask;
        try
        {
            abortTask = Task.Run(
                () => platform.AbortHandshake(failureCode),
                CancellationToken.None);
        }
        catch (Exception exception)
        {
            return exception;
        }

        try
        {
            abortTask.WaitAsync(AbortAttemptTimeout).GetAwaiter().GetResult();
            return null;
        }
        catch (TimeoutException exception)
        {
            _ = abortTask.ContinueWith(
                static task => _ = task.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted |
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            return new PeerAbortAttemptTimeoutException(exception, abortTask);
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    internal static void DisposePreservingFailure(
        IDisposable? disposable,
        Exception failure)
    {
        if (disposable is null)
        {
            return;
        }

        try
        {
            disposable.Dispose();
        }
        catch (Exception cleanupFailure)
        {
            failure.Data["peer-trust-cleanup-failure"] = cleanupFailure;
        }
    }
}

internal static class BrokerPeerTrustRules
{
    private const uint MediumIntegrityRid = 0x2000;
    private const uint HighIntegrityRid = 0x3000;
    private const int MaximumArtifacts = 128;
    private const long MaximumArtifactBytes = 256L * 1024 * 1024;
    private const FileAttributes UnsafeFileAttributes =
        FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device;

    internal static BrokerPeerExpectation FreezeAndValidateExpectation(
        BrokerPeerExpectation expectation,
        NamedPipePeerKind peerKind)
    {
        Require(
            expectation.Release is not null &&
            expectation.Release.HasVerifiedManifestAuthority,
            "invalid-peer-expectation",
            "The peer release expectation is not backed by a verified manifest capability.");
        Require(
            (peerKind == NamedPipePeerKind.Client &&
             expectation.Role == BrokerPeerRole.Guardian) ||
            (peerKind == NamedPipePeerKind.Server &&
             expectation.Role == BrokerPeerRole.Broker),
            "invalid-peer-expectation",
            "The named pipe peer role does not match the connection side.");
        ValidateProcessTokenPolicy(expectation.Token, "invalid-peer-expectation");
        ValidateUnpackagedAppModel(expectation.AppModel, "invalid-peer-expectation");
        ValidateNonce(expectation.ConnectionNonce, "invalid-peer-expectation");
        Require(
            expectation.ProcessId != 0,
            "invalid-peer-expectation",
            "An expected peer process id cannot be zero.");
        ValidateCreationTime(expectation.CreationTimeUtc, "invalid-peer-expectation");
        ValidateVerifiedReleaseArtifactSet(
            expectation.Release,
            "invalid-peer-expectation");
        return expectation;
    }

    internal static void ValidateVerifiedReleaseArtifactSet(
        VerifiedReleaseArtifactSet release,
        string code)
    {
        Require(
            release is not null && release.HasVerifiedManifestAuthority,
            code,
            "The release artifact set lacks verified manifest authority.");
        Require(Enum.IsDefined(release.Role), code, "The release role is invalid.");
        ValidateControlIdentifier(release.ReleaseId, code);
        ValidateSha256(release.ManifestSha256, code);
        ValidateReleaseRoot(release.Root, code);
        ValidateArtifactCollection(
            release.Role,
            release.Root,
            release.Artifacts,
            release.AppHostRelativePath,
            release.ManagedEntryRelativePath,
            release.DepsRelativePath,
            release.RuntimeConfigRelativePath,
            code);
    }

    internal static void ValidateHelloShape(BrokerPeerHello hello)
    {
        Require(
            hello.Protocol == BrokerPeerHelloProtocol.ProtocolVersion,
            "invalid-peer-hello",
            "The broker peer hello protocol is unsupported.");
        Require(Enum.IsDefined(hello.Role), "invalid-peer-hello", "The peer role is invalid.");
        Require(hello.ProcessId != 0, "invalid-peer-hello", "The peer process id is invalid.");
        Require(hello.SessionId != 0, "invalid-peer-hello", "The peer session id is invalid.");
        ValidateCreationTime(hello.CreationTimeUtc, "invalid-peer-hello");
        ValidateNonce(hello.ConnectionNonce, "invalid-peer-hello");
        ValidateControlIdentifier(hello.ReleaseId, "invalid-peer-hello");
        ValidateSha256(hello.ManifestSha256, "invalid-peer-hello");
    }

    internal static void ValidateHelloAgainstExpectation(
        BrokerPeerHello hello,
        BrokerPeerExpectation expectation,
        NamedPipePeerKind peerKind)
    {
        ValidateHelloShape(hello);
        Require(
            hello.Role == expectation.Role &&
            hello.SessionId == expectation.Token.SessionId &&
            hello.CreationTimeUtc == expectation.CreationTimeUtc &&
            string.Equals(
                hello.ConnectionNonce,
                expectation.ConnectionNonce,
                StringComparison.Ordinal) &&
            string.Equals(hello.ReleaseId, expectation.ReleaseId, StringComparison.Ordinal) &&
            string.Equals(
                NormalizeHex(hello.ManifestSha256),
                NormalizeHex(expectation.ManifestSha256),
                StringComparison.Ordinal),
            "peer-hello-mismatch",
            "The broker peer hello does not match the locally verified release identity.");
        Require(
            (peerKind == NamedPipePeerKind.Client && hello.Role == BrokerPeerRole.Guardian) ||
            (peerKind == NamedPipePeerKind.Server && hello.Role == BrokerPeerRole.Broker),
            "peer-hello-mismatch",
            "The broker peer hello role is not valid for this connection side.");
    }

    internal static void ValidateHelloReadEvidence(
        PipePeerHelloReadEvidence evidence,
        NamedPipePeerKind peerKind,
        PipePeerKernelIdentity initialKernelIdentity,
        long initialReadGeneration,
        long currentReadGeneration)
    {
        Require(evidence is not null, "peer-hello-read-invalid", "The peer hello read failed.");
        Require(
            evidence.ReadGeneration == initialReadGeneration + 1 &&
            currentReadGeneration == evidence.ReadGeneration,
            "peer-hello-read-order-invalid",
            "The peer hello was not read in the expected exclusive read generation.");
        RequireStableKernelPeer(
            initialKernelIdentity,
            evidence.KernelIdentityBeforeTokenCapture,
            "peer-kernel-identity-changed");
        RequireStableKernelPeer(
            initialKernelIdentity,
            evidence.KernelIdentityAfterTokenCapture,
            "peer-kernel-identity-changed");
        Require(
            peerKind == NamedPipePeerKind.Client
                ? evidence.ImpersonatedClientToken is not null
                : evidence.ImpersonatedClientToken is null,
            "peer-hello-read-invalid",
            "The hello evidence does not match the connection direction.");
    }

    internal static void ValidateHelloProcessBinding(
        BrokerPeerHello hello,
        BrokerPeerExpectation expectation,
        PipePeerKernelIdentity kernelIdentity,
        WindowsProcessIdentity processIdentity)
    {
        Require(
            hello.ProcessId == expectation.ProcessId &&
            hello.ProcessId == kernelIdentity.ProcessId &&
            hello.ProcessId == processIdentity.ProcessId,
            "peer-process-id-mismatch",
            "The hello, pipe, expected, and retained process ids do not match.");
        Require(
            hello.SessionId == expectation.Token.SessionId &&
            hello.SessionId == kernelIdentity.SessionId &&
            hello.SessionId == processIdentity.KernelSessionId &&
            hello.SessionId == processIdentity.Token.SessionId,
            "peer-session-mismatch",
            "The hello, pipe, process, and token sessions do not match.");
        Require(
            hello.CreationTimeUtc == expectation.CreationTimeUtc &&
            hello.CreationTimeUtc == processIdentity.CreationTimeUtc,
            "peer-creation-time-mismatch",
            "The hello creation time does not match the retained launch identity.");
    }

    internal static void ValidateHelloImpersonationBinding(
        NamedPipePeerKind peerKind,
        WindowsTokenIdentity? impersonatedClientToken,
        WindowsTokenIdentity firstProcessToken,
        WindowsTokenIdentity secondProcessToken)
    {
        if (peerKind == NamedPipePeerKind.Server)
        {
            Require(
                impersonatedClientToken is null,
                "peer-hello-read-invalid",
                "A connected server cannot provide client impersonation evidence.");
            return;
        }

        Require(
            impersonatedClientToken is not null,
            "peer-hello-read-invalid",
            "The accepted client hello lacks impersonation evidence.");
        ValidateImpersonatedClientToken(firstProcessToken, impersonatedClientToken);
        ValidateImpersonatedClientToken(secondProcessToken, impersonatedClientToken);
    }

    internal static void ValidateKernelPeer(
        PipePeerKernelIdentity kernelIdentity,
        BrokerPeerExpectation expectation,
        string code)
    {
        Require(
            kernelIdentity.ProcessId != 0 &&
            kernelIdentity.ProcessId == expectation.ProcessId,
            code,
            "The named pipe peer process id does not match the launch identity.");
        Require(
            kernelIdentity.SessionId != 0 &&
            kernelIdentity.SessionId == expectation.Token.SessionId,
            code,
            "The named pipe peer session does not match the expected token session.");
    }

    internal static void RequireStableKernelPeer(
        PipePeerKernelIdentity first,
        PipePeerKernelIdentity second,
        string code)
    {
        Require(
            first.ProcessId == second.ProcessId &&
            first.SessionId == second.SessionId,
            code,
            "The named pipe kernel peer identity changed during verification.");
    }

    internal static void ValidateRetainedHandles(
        IRetainedPeerIdentityLease peerLease,
        VerifiedReleaseArtifactSet release)
    {
        Require(
            peerLease is not null,
            "peer-retained-handles-invalid",
            "The retained peer identity lease is missing.");
        var handles = peerLease.RetainedHandles;
        ValidateReleaseRoot(handles.Root, "peer-retained-handles-invalid");
        ValidateExpectedReleaseRoot(
            release.Root,
            handles.Root,
            "peer-retained-handles-invalid");
        var expectedPaths = release.Artifacts
            .Select(artifact => artifact.RelativePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var retainedPaths = handles.ArtifactRelativePaths
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Require(
            handles.ArtifactRelativePaths.Count == expectedPaths.Count &&
            retainedPaths.Count == handles.ArtifactRelativePaths.Count &&
            expectedPaths.SetEquals(retainedPaths),
            "peer-retained-handles-invalid",
            "The retained peer handles do not cover the exact verified artifact set.");
    }

    internal static void ValidateProcessIdentity(
        WindowsProcessIdentity identity,
        PipePeerKernelIdentity kernelIdentity,
        BrokerPeerExpectation expectation,
        DateTimeOffset utcNow)
    {
        Require(identity is not null, "peer-process-identity-invalid", "The process identity is missing.");
        Require(
            identity.ProcessId == kernelIdentity.ProcessId &&
            identity.ProcessId == expectation.ProcessId,
            "peer-process-id-mismatch",
            "The retained process handle does not identify the named pipe peer.");
        ValidateCreationTime(identity.CreationTimeUtc, "peer-creation-time-invalid");
        Require(
            identity.CreationTimeUtc <= utcNow.AddSeconds(5),
            "peer-creation-time-invalid",
            "The named pipe peer creation time is in the future.");
        Require(
            identity.CreationTimeUtc == expectation.CreationTimeUtc,
            "peer-creation-time-mismatch",
            "The named pipe peer creation time does not match the launch identity.");
        Require(
            identity.KernelSessionId == kernelIdentity.SessionId &&
            identity.KernelSessionId == identity.Token.SessionId &&
            identity.KernelSessionId == expectation.Token.SessionId,
            "peer-session-mismatch",
            "The peer process, pipe, and token session identities do not match.");
        ValidateProcessTokenPolicy(identity.Token, "peer-token-policy");
        ValidateExpectedToken(expectation.Token, identity.Token);
        ValidateUnpackagedAppModel(identity.AppModel, "peer-appmodel-mismatch");
        Require(
            identity.AppModel == expectation.AppModel,
            "peer-appmodel-mismatch",
            "The named pipe peer AppModel identity does not match.");
        Require(
            identity.ImageFileObjectIsExact,
            "peer-image-mapping-mismatch",
            "The retained apphost is not the exact file object mapped as the peer image.");
        ValidateObservedReleaseIdentity(
            expectation.Release,
            identity.ReleaseRoot,
            identity.Artifacts,
            "peer-artifact-invalid");
        ValidateExpectedArtifacts(
            expectation.Release.Artifacts,
            identity.Artifacts,
            expectation.Release.AppHostRelativePath,
            identity.FinalImagePath);
    }

    internal static void ValidateStableProcessIdentity(
        WindowsProcessIdentity first,
        WindowsProcessIdentity second)
    {
        Require(
            first.ProcessId == second.ProcessId &&
            first.CreationTimeUtc == second.CreationTimeUtc &&
            first.KernelSessionId == second.KernelSessionId &&
            first.Token == second.Token &&
            first.AppModel == second.AppModel &&
            first.ImageFileObjectIsExact &&
            second.ImageFileObjectIsExact &&
            SamePath(first.FinalImagePath, second.FinalImagePath),
            "peer-process-identity-changed",
            "The retained named pipe peer identity changed during verification.");
        ValidateExpectedReleaseRoot(
            first.ReleaseRoot,
            second.ReleaseRoot,
            "peer-process-identity-changed");
        var imageRelativePath = first.Artifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe).RelativePath;
        ValidateExpectedArtifacts(
            first.Artifacts,
            second.Artifacts,
            imageRelativePath,
            second.FinalImagePath,
            "peer-process-identity-changed");
    }

    internal static void ValidateImpersonatedClientToken(
        WindowsTokenIdentity processToken,
        WindowsTokenIdentity impersonatedToken)
    {
        ValidateImpersonationTokenPolicy(impersonatedToken);
        Require(
            SameSid(processToken.UserSid, impersonatedToken.UserSid) &&
            SameSid(processToken.LogonSid, impersonatedToken.LogonSid) &&
            processToken.LogonSidGroupCount == impersonatedToken.LogonSidGroupCount &&
            processToken.AuthenticationId == impersonatedToken.AuthenticationId &&
            processToken.SessionId == impersonatedToken.SessionId &&
            processToken.IntegrityLevelRid == impersonatedToken.IntegrityLevelRid &&
            processToken.ElevationType == impersonatedToken.ElevationType &&
            processToken.IsElevated == impersonatedToken.IsElevated &&
            processToken.IsAppContainer == impersonatedToken.IsAppContainer &&
            SameNullableSid(processToken.AppContainerSid, impersonatedToken.AppContainerSid) &&
            processToken.UiAccess == impersonatedToken.UiAccess,
            "impersonated-peer-mismatch",
            "The impersonated pipe token does not match the retained client process token.");
    }

    internal static void Require(
        [DoesNotReturnIf(false)] bool condition,
        string code,
        string message)
    {
        if (!condition)
        {
            throw new BrokerPeerTrustException(code, message);
        }
    }

    private static void ValidateExpectedToken(
        WindowsTokenIdentity expected,
        WindowsTokenIdentity actual)
    {
        Require(SameSid(expected.UserSid, actual.UserSid), "peer-user-mismatch", "The peer user SID does not match.");
        Require(
            SameSid(expected.LogonSid, actual.LogonSid) &&
            expected.LogonSidGroupCount == actual.LogonSidGroupCount &&
            expected.AuthenticationId == actual.AuthenticationId,
            "peer-logon-mismatch",
            "The peer logon identity does not match.");
        Require(expected.SessionId == actual.SessionId, "peer-session-mismatch", "The peer token session does not match.");
        Require(
            expected.IntegrityLevelRid == actual.IntegrityLevelRid,
            "peer-integrity-mismatch",
            "The peer integrity level does not match.");
        Require(
            expected.ElevationType == actual.ElevationType &&
            expected.IsElevated == actual.IsElevated,
            "peer-elevation-mismatch",
            "The peer elevation state does not match.");
        Require(
            expected.IsAppContainer == actual.IsAppContainer &&
            SameNullableSid(expected.AppContainerSid, actual.AppContainerSid),
            "peer-appcontainer-mismatch",
            "The peer AppContainer state does not match.");
        Require(
            expected.UiAccess == actual.UiAccess &&
            expected.TokenType == actual.TokenType &&
            expected.ImpersonationLevel == actual.ImpersonationLevel,
            "peer-token-mismatch",
            "The peer token type or UIAccess state does not match.");
    }

    private static void ValidateProcessTokenPolicy(
        WindowsTokenIdentity token,
        string code)
    {
        Require(token is not null, code, "The peer token is missing.");
        ValidateSid(token.UserSid, code);
        ValidateLogonSid(token.LogonSid, token.LogonSidGroupCount, code);
        Require(token.AuthenticationId != 0, code, "The peer authentication id is missing.");
        Require(token.SessionId != 0, code, "The peer token session is invalid.");
        Require(
            token.IntegrityLevelRid >= MediumIntegrityRid &&
            token.IntegrityLevelRid < HighIntegrityRid,
            code,
            "The peer token is outside the non-elevated desktop integrity range.");
        Require(Enum.IsDefined(token.ElevationType), code, "The peer elevation type is invalid.");
        Require(
            !token.IsElevated && token.ElevationType != WindowsTokenElevationType.Full,
            code,
            "The peer token is elevated.");
        Require(
            !token.IsAppContainer && string.IsNullOrEmpty(token.AppContainerSid),
            code,
            "The peer token is unexpectedly AppContainer packaged.");
        Require(!token.UiAccess, code, "The peer token unexpectedly has UIAccess.");
        Require(Enum.IsDefined(token.TokenType), code, "The peer token type is invalid.");
        Require(
            token.TokenType == WindowsTokenType.Primary &&
            token.ImpersonationLevel is null,
            code,
            "The retained peer process did not expose a primary token.");
    }

    private static void ValidateImpersonationTokenPolicy(WindowsTokenIdentity token)
    {
        Require(token is not null, "impersonated-token-policy", "The impersonation token is missing.");
        ValidateSid(token.UserSid, "impersonated-token-policy");
        ValidateLogonSid(
            token.LogonSid,
            token.LogonSidGroupCount,
            "impersonated-token-policy");
        Require(
            token.AuthenticationId != 0 &&
            token.SessionId != 0 &&
            token.IntegrityLevelRid >= MediumIntegrityRid &&
            token.IntegrityLevelRid < HighIntegrityRid &&
            Enum.IsDefined(token.ElevationType) &&
            !token.IsElevated &&
            token.ElevationType != WindowsTokenElevationType.Full &&
            !token.IsAppContainer &&
            string.IsNullOrEmpty(token.AppContainerSid) &&
            !token.UiAccess &&
            Enum.IsDefined(token.TokenType) &&
            token.TokenType == WindowsTokenType.Impersonation &&
            token.ImpersonationLevel is not null &&
            Enum.IsDefined(token.ImpersonationLevel.Value) &&
            token.ImpersonationLevel == WindowsSecurityImpersonationLevel.Identification,
            "impersonated-token-policy",
            "The pipe client impersonation token violates the identification-only policy.");
    }

    private static void ValidateUnpackagedAppModel(
        WindowsAppModelIdentity appModel,
        string code)
    {
        Require(
            appModel is not null &&
            appModel.Kind == WindowsAppModelKind.Unpackaged &&
            string.IsNullOrEmpty(appModel.FullName) &&
            string.IsNullOrEmpty(appModel.FamilyName),
            code,
            "Guardian and broker peers must be explicitly verified as unpackaged.");
    }

    private static void ValidateObservedReleaseIdentity(
        VerifiedReleaseArtifactSet release,
        WindowsReleaseRootIdentity actualRoot,
        IReadOnlyList<WindowsArtifactIdentity> actualArtifacts,
        string code)
    {
        ValidateReleaseRoot(actualRoot, code);
        ValidateExpectedReleaseRoot(release.Root, actualRoot, "peer-artifact-mismatch");
        ValidateArtifactCollection(
            release.Role,
            actualRoot,
            actualArtifacts,
            release.AppHostRelativePath,
            release.ManagedEntryRelativePath,
            release.DepsRelativePath,
            release.RuntimeConfigRelativePath,
            code);
    }

    private static void ValidateExpectedReleaseRoot(
        WindowsReleaseRootIdentity expected,
        WindowsReleaseRootIdentity actual,
        string code)
    {
        Require(
            SamePath(expected.FinalPath, actual.FinalPath) &&
            expected.VolumeSerialNumber == actual.VolumeSerialNumber &&
            string.Equals(
                NormalizeHex(expected.FileId),
                NormalizeHex(actual.FileId),
                StringComparison.Ordinal) &&
            actual.TraversalIsReparseFree &&
            (actual.Attributes & UnsafeFileAttributes) == FileAttributes.Directory,
            code,
            "The retained release root identity changed.");
    }

    private static void ValidateExpectedArtifacts(
        IReadOnlyList<WindowsArtifactIdentity> expected,
        IReadOnlyList<WindowsArtifactIdentity> actual,
        string imageArtifactRelativePath,
        string actualImagePath,
        string code = "peer-artifact-mismatch")
    {
        Require(expected.Count == actual.Count, code, "The peer artifact set count changed.");
        var expectedByPath = expected.ToDictionary(
            artifact => artifact.RelativePath,
            StringComparer.OrdinalIgnoreCase);
        var actualByPath = actual.ToDictionary(
            artifact => artifact.RelativePath,
            StringComparer.OrdinalIgnoreCase);
        Require(
            expectedByPath.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase)
                .SetEquals(actualByPath.Keys),
            code,
            "The peer artifact set membership changed.");
        foreach (var pair in expectedByPath)
        {
            var expectedArtifact = pair.Value;
            var actualArtifact = actualByPath[pair.Key];
            Require(
                expectedArtifact.Kind == actualArtifact.Kind &&
                SamePath(expectedArtifact.FinalPath, actualArtifact.FinalPath) &&
                expectedArtifact.Length == actualArtifact.Length &&
                string.Equals(
                    NormalizeHex(expectedArtifact.Sha256),
                    NormalizeHex(actualArtifact.Sha256),
                    StringComparison.Ordinal) &&
                expectedArtifact.VolumeSerialNumber == actualArtifact.VolumeSerialNumber &&
                string.Equals(
                    NormalizeHex(expectedArtifact.FileId),
                    NormalizeHex(actualArtifact.FileId),
                    StringComparison.Ordinal) &&
                expectedArtifact.LinkCount == actualArtifact.LinkCount &&
                expectedArtifact.TraversalIsReparseFree ==
                    actualArtifact.TraversalIsReparseFree,
                code,
                "A peer artifact identity changed.");
        }

        Require(
            actualByPath.TryGetValue(imageArtifactRelativePath, out var imageArtifact) &&
            imageArtifact.Kind == ReleaseArtifactKind.AppHostExe &&
            SamePath(imageArtifact.FinalPath, actualImagePath),
            code,
            "The process image is not the expected peer apphost.");
    }

    private static void ValidateArtifactCollection(
        BrokerPeerRole role,
        WindowsReleaseRootIdentity root,
        IReadOnlyList<WindowsArtifactIdentity> artifacts,
        string appHostRelativePath,
        string managedEntryRelativePath,
        string depsRelativePath,
        string runtimeConfigRelativePath,
        string code)
    {
        Require(
            artifacts is not null && artifacts.Count is >= 4 and <= MaximumArtifacts,
            code,
            "The peer artifact set size is invalid.");
        ValidateRequiredRuntimePaths(
            role,
            appHostRelativePath,
            managedEntryRelativePath,
            depsRelativePath,
            runtimeConfigRelativePath,
            code);
        var requiredPaths = new Dictionary<ReleaseArtifactKind, string>
        {
            [ReleaseArtifactKind.AppHostExe] = appHostRelativePath,
            [ReleaseArtifactKind.ManagedEntryDll] = managedEntryRelativePath,
            [ReleaseArtifactKind.DepsJson] = depsRelativePath,
            [ReleaseArtifactKind.RuntimeConfigJson] = runtimeConfigRelativePath
        };
        var relativePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var finalPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var fileIdentities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var requiredCounts = requiredPaths.Keys.ToDictionary(kind => kind, _ => 0);
        foreach (var artifact in artifacts)
        {
            Require(Enum.IsDefined(artifact.Kind), code, "A peer artifact kind is invalid.");
            ValidateRelativePath(artifact.RelativePath, code);
            var finalPath = NormalizeLocalFinalPath(artifact.FinalPath, code, allowDriveRoot: false);
            var expectedFinalPath = Path.GetFullPath(
                Path.Combine(root.FinalPath, artifact.RelativePath));
            Require(
                string.Equals(finalPath, expectedFinalPath, StringComparison.OrdinalIgnoreCase),
                code,
                "A peer artifact final path is not the exact child of the verified release root.");
            Require(relativePaths.Add(artifact.RelativePath), code, "A peer artifact path is duplicated.");
            Require(finalPaths.Add(finalPath), code, "Two peer artifacts resolve to one path.");
            Require(
                artifact.Length is > 0 and <= MaximumArtifactBytes,
                code,
                "A peer artifact length is outside the bounded range.");
            Require(
                (artifact.Attributes & UnsafeFileAttributes) == 0,
                code,
                "A peer artifact is not a regular non-reparse file.");
            ValidateSha256(artifact.Sha256, code);
            ValidateFileId(artifact.FileId, code);
            Require(
                artifact.VolumeSerialNumber == root.VolumeSerialNumber,
                code,
                "A peer artifact is not on the verified release volume.");
            Require(artifact.LinkCount == 1, code, "A peer artifact is hard-linked or invalid.");
            Require(
                artifact.TraversalIsReparseFree,
                code,
                "The peer artifact path traversal was not proven reparse-free.");
            Require(
                fileIdentities.Add(
                    artifact.VolumeSerialNumber.ToString("X16", CultureInfo.InvariantCulture) +
                    ":" + NormalizeHex(artifact.FileId)),
                code,
                "Two peer artifacts alias the same file identity.");
            if (requiredCounts.ContainsKey(artifact.Kind))
            {
                requiredCounts[artifact.Kind]++;
                Require(
                    string.Equals(
                        artifact.RelativePath,
                        requiredPaths[artifact.Kind],
                        StringComparison.OrdinalIgnoreCase),
                    code,
                    "A required runtime artifact path is invalid.");
            }
        }

        Require(
            requiredCounts.All(pair => pair.Value == 1),
            code,
            "The peer release does not contain exactly one of every required runtime artifact.");
    }

    private static void ValidateRequiredRuntimePaths(
        BrokerPeerRole role,
        string appHostRelativePath,
        string managedEntryRelativePath,
        string depsRelativePath,
        string runtimeConfigRelativePath,
        string code)
    {
        ValidateRelativePath(appHostRelativePath, code);
        ValidateRelativePath(managedEntryRelativePath, code);
        ValidateRelativePath(depsRelativePath, code);
        ValidateRelativePath(runtimeConfigRelativePath, code);
        var stem = role switch
        {
            BrokerPeerRole.Guardian => "CodexGuardian",
            BrokerPeerRole.Broker => "CodexGuardian.Broker",
            _ => throw new BrokerPeerTrustException(code, "The peer release role is invalid.")
        };
        var directory = Path.GetDirectoryName(appHostRelativePath) ?? string.Empty;
        string Expected(string suffix) =>
            string.IsNullOrEmpty(directory)
                ? stem + suffix
                : Path.Combine(directory, stem + suffix);
        Require(
            string.Equals(appHostRelativePath, Expected(".exe"), StringComparison.OrdinalIgnoreCase) &&
            string.Equals(managedEntryRelativePath, Expected(".dll"), StringComparison.OrdinalIgnoreCase) &&
            string.Equals(depsRelativePath, Expected(".deps.json"), StringComparison.OrdinalIgnoreCase) &&
            string.Equals(runtimeConfigRelativePath, Expected(".runtimeconfig.json"), StringComparison.OrdinalIgnoreCase),
            code,
            "The required framework-dependent runtime artifact paths are invalid.");
    }

    private static void ValidateReleaseRoot(
        WindowsReleaseRootIdentity root,
        string code)
    {
        Require(root is not null, code, "The verified release root is missing.");
        _ = NormalizeLocalFinalPath(root.FinalPath, code, allowDriveRoot: false);
        Require(
            (root.Attributes & FileAttributes.Directory) != 0 &&
            (root.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) == 0,
            code,
            "The verified release root is not a regular non-reparse directory.");
        Require(root.VolumeSerialNumber != 0, code, "The release root volume identity is missing.");
        ValidateFileId(root.FileId, code);
        Require(
            root.TraversalIsReparseFree,
            code,
            "The release root path traversal was not proven reparse-free.");
    }

    private static void ValidateCreationTime(DateTimeOffset value, string code)
    {
        Require(
            value != default && value.Offset == TimeSpan.Zero,
            code,
            "The peer creation time is invalid.");
        try
        {
            _ = value.ToFileTime();
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new BrokerPeerTrustException(code, "The peer creation time is invalid.", exception);
        }
    }

    private static void ValidateControlIdentifier(string value, string code)
    {
        Require(
            !string.IsNullOrEmpty(value) &&
            value.Length is >= 8 and <= 64 &&
            value.All(character =>
                char.IsAsciiLetterOrDigit(character) ||
                character is '-' or '_' or '.'),
            code,
            "A peer control identifier is invalid.");
    }

    private static void ValidateNonce(string value, string code)
    {
        Require(
            !string.IsNullOrEmpty(value) &&
            value.Length == 64 && value.All(Uri.IsHexDigit),
            code,
            "The peer connection nonce is invalid.");
    }

    private static void ValidateSha256(string value, string code)
    {
        Require(
            !string.IsNullOrEmpty(value) &&
            value.Length == 64 && value.All(Uri.IsHexDigit),
            code,
            "A peer SHA-256 value is invalid.");
    }

    private static void ValidateFileId(string value, string code)
    {
        Require(
            !string.IsNullOrEmpty(value) &&
            value.Length == 32 &&
            value.All(Uri.IsHexDigit) &&
            value.Any(character => character != '0'),
            code,
            "A peer FILE_ID_128 value is invalid.");
    }

    private static void ValidateRelativePath(string value, string code)
    {
        Require(
            !string.IsNullOrWhiteSpace(value) &&
            value.Length <= 240 &&
            !Path.IsPathFullyQualified(value) &&
            !value.Contains('/') &&
            !value.Contains(':') &&
            value.IndexOf('\0') < 0,
            code,
            "A peer artifact relative path is invalid.");
        var segments = value.Split('\\');
        Require(
            segments.All(segment =>
                segment.Length > 0 &&
                segment is not "." and not ".." &&
                !segment.EndsWith(' ') &&
                !segment.EndsWith('.') &&
                segment.All(character =>
                    char.IsAsciiLetterOrDigit(character) ||
                    character is '-' or '_' or '.') &&
                !IsReservedWindowsComponent(segment)),
            code,
            "A peer artifact relative path segment is invalid.");
    }

    private static bool IsReservedWindowsComponent(string segment)
    {
        var stem = segment.Split('.')[0];
        return stem.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
               Enumerable.Range(1, 9).Any(index =>
                   stem.Equals("COM" + index, StringComparison.OrdinalIgnoreCase) ||
                   stem.Equals("LPT" + index, StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeLocalFinalPath(
        string value,
        string code,
        bool allowDriveRoot)
    {
        Require(
            !string.IsNullOrWhiteSpace(value) &&
            value.Length >= 3 &&
            char.IsAsciiLetter(value[0]) &&
            value[1] == ':' &&
            value[2] == '\\' &&
            !value.StartsWith(@"\\", StringComparison.Ordinal) &&
            Path.IsPathFullyQualified(value),
            code,
            "A peer final path is not a canonical local-drive path.");
        string fullPath;
        try
        {
            fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new BrokerPeerTrustException(code, "A peer final path is invalid.", exception);
        }

        Require(
            string.Equals(
                fullPath,
                Path.TrimEndingDirectorySeparator(value),
                StringComparison.OrdinalIgnoreCase),
            code,
            "A peer final path contains unresolved traversal.");
        if (!allowDriveRoot)
        {
            Require(
                !string.Equals(
                    fullPath,
                    Path.TrimEndingDirectorySeparator(Path.GetPathRoot(fullPath)!),
                    StringComparison.OrdinalIgnoreCase),
                code,
                "A peer final path cannot be a drive root.");
        }

        return fullPath;
    }

    private static void ValidateSid(string value, string code)
    {
        Require(!string.IsNullOrWhiteSpace(value), code, "A peer SID is missing.");
        try
        {
            var parsed = new SecurityIdentifier(value);
            Require(
                string.Equals(parsed.Value, value, StringComparison.OrdinalIgnoreCase),
                code,
                "A peer SID is not canonical.");
        }
        catch (ArgumentException exception)
        {
            throw new BrokerPeerTrustException(code, "A peer SID is invalid.", exception);
        }
    }

    private static void ValidateLogonSid(string value, int groupCount, string code)
    {
        ValidateSid(value, code);
        var parts = value.Split('-');
        Require(
            groupCount == 1 &&
            parts.Length == 6 &&
            parts[0] == "S" &&
            parts[1] == "1" &&
            parts[2] == "5" &&
            parts[3] == "5" &&
            uint.TryParse(parts[4], NumberStyles.None, CultureInfo.InvariantCulture, out _) &&
            uint.TryParse(parts[5], NumberStyles.None, CultureInfo.InvariantCulture, out _),
            code,
            "The peer token does not contain exactly one canonical logon SID group.");
    }

    private static bool SameSid(string first, string second) =>
        string.Equals(
            new SecurityIdentifier(first).Value,
            new SecurityIdentifier(second).Value,
            StringComparison.OrdinalIgnoreCase);

    private static bool SameNullableSid(string? first, string? second) =>
        string.IsNullOrEmpty(first) && string.IsNullOrEmpty(second) ||
        !string.IsNullOrEmpty(first) &&
        !string.IsNullOrEmpty(second) &&
        SameSid(first, second);

    private static bool SamePath(string first, string second) =>
        string.Equals(
            NormalizeLocalFinalPath(first, "peer-artifact-invalid", allowDriveRoot: false),
            NormalizeLocalFinalPath(second, "peer-artifact-invalid", allowDriveRoot: false),
            StringComparison.OrdinalIgnoreCase);

    private static string NormalizeHex(string value) => value.ToUpperInvariant();
}
