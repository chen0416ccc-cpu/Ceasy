using CodexGuardian.Trust;
using System.Collections.Concurrent;
using System.IO;
using System.Reflection;

internal static class AuthenticatedPipePeerConnectionOfflineTests
{
    private const uint ProcessId = 4321;
    private const uint SessionId = 4;
    private const ulong VolumeSerial = 0x1234;
    private const string UserSid = "S-1-5-21-111-222-333-1001";
    private const string LogonSid = "S-1-5-5-1-2";
    private const string ConnectionNonce =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string ReleaseId = "release-20260804";
    private const string ManifestSha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string ReleaseRoot = @"D:\CodexGuardian\release-20260804";
    private static readonly DateTimeOffset CreationTime =
        new DateTimeOffset(2026, 8, 4, 12, 0, 0, TimeSpan.Zero).AddTicks(7);
    private static readonly DateTimeOffset UtcNow = CreationTime.AddMinutes(5);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "authenticated peer exposes one non-detachable capability surface",
            TestCapabilitySurfaceAsync,
            assert);
        await RunCaseAsync(
            "authenticated peer owns message transport and identity for one lifetime",
            TestPositiveOwnershipAsync,
            assert);
        await RunCaseAsync(
            "platform without a message transport fails closed after verification",
            TestUnsupportedTransportAsync,
            assert);
        await RunCaseAsync(
            "double completion transfers connection authority exactly once",
            TestDoubleCompletionAsync,
            assert);
        await RunCaseAsync(
            "concurrent read write and dispose release one connection",
            TestConcurrentReadWriteDisposeAsync,
            assert);
        await RunCaseAsync(
            "transport completion cancels active authenticated message IO",
            TestTransportCompletionCancelsActiveIoAsync,
            assert);
        await RunCaseAsync(
            "message EOF oversize and IO failures are sticky terminal",
            TestStickyTerminalFailuresAsync,
            assert);
        await RunCaseAsync(
            "transport completion closes the authenticated connection terminally",
            TestTransportCompletionAsync,
            assert);
    }

    private static Task TestCapabilitySurfaceAsync()
    {
        var type = typeof(AuthenticatedPipePeerConnection);
        Ensure(
            type.GetConstructors(BindingFlags.Instance | BindingFlags.Public).Length == 0,
            "authenticated connection unexpectedly has a public constructor");
        Ensure(
            !typeof(IDisposable).IsAssignableFrom(type) &&
            typeof(IAsyncDisposable).IsAssignableFrom(type),
            "authenticated connection does not have one async disposal authority");
        Ensure(
            typeof(INamedPipePeerMessageTransport).IsNotPublic,
            "platform message transport escaped the Trust assembly");
        Ensure(
            type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly).Length == 0,
            "authenticated connection exposes a detachable public field");

        var properties = type
            .GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        Ensure(
            properties.SetEquals(new[] { "PeerRole", "InitialIdentity", "Completion" }),
            "authenticated connection property surface drifted");
        var methods = type
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName)
            .Select(method => method.Name)
            .ToHashSet(StringComparer.Ordinal);
        Ensure(
            methods.SetEquals(new[]
            {
                "Revalidate",
                "ReadMessageAsync",
                "WriteMessageAsync",
                "DisposeAsync"
            }),
            "authenticated connection method surface drifted");
        Ensure(
            type.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
                .All(property =>
                    property.PropertyType != typeof(VerifiedPipePeerIdentity) &&
                    property.PropertyType != typeof(INamedPipePeerMessageTransport)),
            "authenticated connection exposes independently disposable authority");
        return Task.CompletedTask;
    }

    private static async Task TestPositiveOwnershipAsync()
    {
        var fixture = CreateMessageFixture();
        fixture.Platform.EnqueueRead(new byte[] { 1, 2, 3, 4 });
        var connection = await fixture.Pending.CompleteConnectionAsync();
        await fixture.Pending.DisposeAsync();
        Ensure(
            connection.PeerRole == BrokerPeerRole.Broker &&
            ReferenceEquals(connection.InitialIdentity, fixture.Identity),
            "connection did not retain its verified role and initial identity");

        var message = await connection.ReadMessageAsync(4);
        Ensure(message.Span.SequenceEqual(new byte[] { 1, 2, 3, 4 }), "bounded message read changed bytes");
        await connection.WriteMessageAsync(new byte[] { 5, 6, 7 });
        Ensure(
            fixture.Platform.Writes.Count == 1 &&
            fixture.Platform.Writes[0].SequenceEqual(new byte[] { 5, 6, 7 }),
            "bounded message write changed bytes");
        Ensure(
            ReferenceEquals(connection.Revalidate(), fixture.Identity),
            "connection identity did not revalidate through its retained lease");

        await connection.DisposeAsync();
        await connection.DisposeAsync();
        await connection.Completion;
        AssertReleasedOnce(fixture);
    }

    private static async Task TestUnsupportedTransportAsync()
    {
        var fixture = CreateTrustOnlyFixture();
        var failure = await ExpectCodeAsync(
            "peer-message-transport-unsupported",
            () => fixture.Pending.CompleteConnectionAsync().AsTask());
        await fixture.Pending.DisposeAsync();
        Ensure(failure.InnerException is null, "unsupported transport was replaced by a platform error");
        AssertReleasedOnce(fixture);
    }

    private static async Task TestDoubleCompletionAsync()
    {
        var fixture = CreateMessageFixture();
        var firstTask = fixture.Pending.CompleteConnectionAsync().AsTask();
        var secondTask = fixture.Pending.CompleteConnectionAsync().AsTask();
        var first = await ObserveAsync(firstTask);
        var second = await ObserveAsync(secondTask);
        Ensure(
            (first.Result is not null) != (second.Result is not null),
            "double completion did not produce exactly one connection owner");
        Ensure(
            first.Failure is ObjectDisposedException || second.Failure is ObjectDisposedException,
            "double completion loser was not terminal");

        var connection = first.Result ?? second.Result!;
        await fixture.Pending.DisposeAsync();
        Ensure(
            fixture.Platform.DisposeCallCount == 0 && fixture.Lease.DisposeCallCount == 0,
            "pending disposal stole transferred connection resources");
        await connection.DisposeAsync();
        AssertReleasedOnce(fixture);
    }

    private static async Task TestConcurrentReadWriteDisposeAsync()
    {
        var fixture = CreateMessageFixture();
        fixture.Platform.BlockReads = true;
        fixture.Platform.BlockWrites = true;
        var connection = await fixture.Pending.CompleteConnectionAsync();
        var read = connection.ReadMessageAsync(32).AsTask();
        var write = connection.WriteMessageAsync(new byte[] { 9, 8, 7 }).AsTask();
        Ensure(
            fixture.Platform.ReadEntered.Wait(TimeSpan.FromSeconds(5)) &&
            fixture.Platform.WriteEntered.Wait(TimeSpan.FromSeconds(5)),
            "concurrent message operations did not enter the transport");

        var dispose = connection.DisposeAsync().AsTask();
        var readResult = await ObserveAsync(read.WaitAsync(TimeSpan.FromSeconds(5)));
        var writeResult = await ObserveAsync(write.WaitAsync(TimeSpan.FromSeconds(5)));
        await dispose.WaitAsync(TimeSpan.FromSeconds(5));
        Ensure(
            readResult.Failure is ObjectDisposedException &&
            writeResult.Failure is ObjectDisposedException,
            "dispose did not close active read and write with one clean authority result");
        await connection.Completion;
        await connection.DisposeAsync();
        AssertReleasedOnce(fixture);
    }

    private static async Task TestTransportCompletionCancelsActiveIoAsync()
    {
        var fixture = CreateMessageFixture();
        fixture.Platform.BlockReads = true;
        var connection = await fixture.Pending.CompleteConnectionAsync();
        var read = connection.ReadMessageAsync(32).AsTask();
        Ensure(
            fixture.Platform.ReadEntered.Wait(TimeSpan.FromSeconds(5)),
            "the active message read did not enter the transport");

        fixture.Platform.CompleteTransport();
        var completionFailure = await ExpectCodeAsync(
            "peer-message-eof",
            () => connection.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        var readFailure = await ExpectCodeAsync(
            "peer-message-eof",
            () => read.WaitAsync(TimeSpan.FromSeconds(5)));
        Ensure(
            ReferenceEquals(completionFailure, readFailure),
            "transport completion did not cancel active IO with the sticky terminal failure");
        await connection.DisposeAsync();
        AssertReleasedOnce(fixture);
    }

    private static async Task TestStickyTerminalFailuresAsync()
    {
        await AssertStickyFailureAsync(
            "peer-message-eof",
            fixture => fixture.Platform.EnqueueRead(Array.Empty<byte>()),
            connection => connection.ReadMessageAsync(16).AsTask());
        await AssertStickyFailureAsync(
            "peer-message-too-large",
            fixture => fixture.Platform.EnqueueRead(new byte[5]),
            connection => connection.ReadMessageAsync(4).AsTask());
        await AssertStickyFailureAsync(
            "peer-message-read-failed",
            fixture => fixture.Platform.ReadFailure = new IOException("test read failure"),
            connection => connection.ReadMessageAsync(16).AsTask());
        await AssertStickyFailureAsync(
            "peer-message-write-failed",
            fixture => fixture.Platform.WriteFailure = new IOException("test write failure"),
            connection => connection.WriteMessageAsync(new byte[] { 1 }).AsTask());
    }

    private static async Task TestTransportCompletionAsync()
    {
        var fixture = CreateMessageFixture();
        var connection = await fixture.Pending.CompleteConnectionAsync();
        fixture.Platform.CompleteTransport();
        var failure = await ExpectCodeAsync("peer-message-eof", () => connection.Completion);
        var repeated = await ExpectCodeAsync(
            "peer-message-eof",
            () => connection.ReadMessageAsync(16).AsTask());
        Ensure(ReferenceEquals(failure, repeated), "transport completion failure was not sticky");
        await connection.DisposeAsync();
        AssertReleasedOnce(fixture);
    }

    private static async Task AssertStickyFailureAsync(
        string expectedCode,
        Action<MessageFixture> arrange,
        Func<AuthenticatedPipePeerConnection, Task> fail)
    {
        var fixture = CreateMessageFixture();
        arrange(fixture);
        var connection = await fixture.Pending.CompleteConnectionAsync();
        var first = await ExpectCodeAsync(expectedCode, () => fail(connection));
        var readAgain = await ExpectCodeAsync(
            expectedCode,
            () => connection.ReadMessageAsync(16).AsTask());
        var writeAgain = await ExpectCodeAsync(
            expectedCode,
            () => connection.WriteMessageAsync(new byte[] { 2 }).AsTask());
        var revalidateAgain = ExpectCode(expectedCode, () => connection.Revalidate());
        var completion = await ExpectCodeAsync(expectedCode, () => connection.Completion);
        Ensure(
            ReferenceEquals(first, readAgain) &&
            ReferenceEquals(first, writeAgain) &&
            ReferenceEquals(first, revalidateAgain) &&
            ReferenceEquals(first, completion),
            "terminal message failure changed across later operations");
        await connection.DisposeAsync();
        await connection.DisposeAsync();
        AssertReleasedOnce(fixture);
    }

    private static MessageFixture CreateMessageFixture()
    {
        var core = CreateFixtureCore();
        var platform = new FakeMessagePlatform(core.Release, core.Lease);
        var verifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            beforeAuthorityTransfer: null,
            afterAuthorityTransfer: null,
            maximumConnections: 1);
        var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Server,
            CreateExpectation(core.Release));
        return new MessageFixture(verifier, platform, core.Lease, core.Identity, pending);
    }

    private static TrustOnlyFixture CreateTrustOnlyFixture()
    {
        var core = CreateFixtureCore();
        var platform = new FakeTrustPlatform(core.Release, core.Lease);
        var verifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            beforeAuthorityTransfer: null,
            afterAuthorityTransfer: null,
            maximumConnections: 1);
        var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Server,
            CreateExpectation(core.Release));
        return new TrustOnlyFixture(verifier, platform, core.Lease, pending);
    }

    private static FixtureCore CreateFixtureCore()
    {
        var release = CreateManifest().GetArtifactSet(BrokerPeerRole.Broker);
        var identity = CreateIdentity(release);
        var lease = new FakePeerLease(
            identity,
            new RetainedReleaseHandleSet(
                release.Root,
                release.Artifacts.Select(artifact => artifact.RelativePath).ToArray()));
        return new FixtureCore(release, identity, lease);
    }

    private static void AssertReleasedOnce(MessageFixture fixture)
    {
        Ensure(
            fixture.Platform.DisposeCallCount == 1 &&
            fixture.Lease.DisposeCallCount == 1 &&
            fixture.Verifier.Health is
            {
                IsUnhealthy: false,
                ActiveConnectionCount: 0,
                QuarantinedHandshakeCount: 0,
                Capacity: 1
            },
            "authenticated connection did not release its exact resources and slot once");
    }

    private static void AssertReleasedOnce(TrustOnlyFixture fixture)
    {
        Ensure(
            fixture.Platform.DisposeCallCount == 1 &&
            fixture.Lease.DisposeCallCount == 1 &&
            fixture.Verifier.Health is
            {
                IsUnhealthy: false,
                ActiveConnectionCount: 0,
                QuarantinedHandshakeCount: 0,
                Capacity: 1
            },
            "unsupported platform did not release its exact resources and slot once");
    }

    private static BrokerPeerExpectation CreateExpectation(VerifiedReleaseArtifactSet release) =>
        new(
            CreateProcessToken(),
            WindowsAppModelIdentity.Unpackaged,
            release,
            ConnectionNonce,
            ProcessId,
            CreationTime);

    private static BrokerPeerHello CreateHello() =>
        new(
            BrokerPeerHelloProtocol.ProtocolVersion,
            BrokerPeerRole.Broker,
            ProcessId,
            SessionId,
            CreationTime,
            ConnectionNonce,
            ReleaseId,
            ManifestSha256);

    private static VerifiedReleaseManifest CreateManifest() =>
        VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId,
            ManifestSha256,
            CreateReleaseRoot(),
            CreateRoleDefinition(BrokerPeerRole.Guardian),
            CreateRoleDefinition(BrokerPeerRole.Broker));

    private static WindowsReleaseRootIdentity CreateReleaseRoot() =>
        new(
            ReleaseRoot,
            FileAttributes.Directory | FileAttributes.Archive,
            VolumeSerial,
            new string('a', 32),
            true);

    private static VerifiedReleaseRoleArtifacts CreateRoleDefinition(BrokerPeerRole role)
    {
        var stem = RoleStem(role);
        return new VerifiedReleaseRoleArtifacts(
            role,
            stem + ".exe",
            stem + ".dll",
            stem + ".deps.json",
            stem + ".runtimeconfig.json",
            CreateArtifacts(role));
    }

    private static IReadOnlyList<WindowsArtifactIdentity> CreateArtifacts(BrokerPeerRole role)
    {
        var stem = RoleStem(role);
        var seed = role == BrokerPeerRole.Guardian ? '1' : '5';
        return new[]
        {
            CreateArtifact(ReleaseArtifactKind.AppHostExe, stem + ".exe", seed, 128 * 1024),
            CreateArtifact(ReleaseArtifactKind.ManagedEntryDll, stem + ".dll", (char)(seed + 1), 512 * 1024),
            CreateArtifact(ReleaseArtifactKind.DepsJson, stem + ".deps.json", (char)(seed + 2), 64 * 1024),
            CreateArtifact(ReleaseArtifactKind.RuntimeConfigJson, stem + ".runtimeconfig.json", (char)(seed + 3), 4 * 1024)
        };
    }

    private static WindowsArtifactIdentity CreateArtifact(
        ReleaseArtifactKind kind,
        string relativePath,
        char seed,
        long length) =>
        new(
            kind,
            relativePath,
            Path.Combine(ReleaseRoot, relativePath),
            FileAttributes.Archive,
            length,
            new string(seed, 64),
            VolumeSerial,
            new string(seed, 32),
            1,
            true);

    private static string RoleStem(BrokerPeerRole role) =>
        role == BrokerPeerRole.Broker ? "CodexGuardian.Broker" : "CodexGuardian";

    private static WindowsProcessIdentity CreateIdentity(VerifiedReleaseArtifactSet release)
    {
        var appHost = release.Artifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe);
        return new WindowsProcessIdentity(
            ProcessId,
            CreationTime,
            SessionId,
            CreateProcessToken(),
            WindowsAppModelIdentity.Unpackaged,
            appHost.FinalPath,
            true,
            release.Root,
            release.Artifacts);
    }

    private static WindowsTokenIdentity CreateProcessToken() =>
        new(
            UserSid,
            LogonSid,
            1,
            0x0000000100000002,
            SessionId,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Primary,
            null);

    private static async Task<BrokerPeerTrustException> ExpectCodeAsync(
        string code,
        Func<Task> action)
    {
        var exception = await ExpectAsync<BrokerPeerTrustException>(action);
        Ensure(exception.Code == code, $"expected {code}, received {exception.Code}");
        return exception;
    }

    private static BrokerPeerTrustException ExpectCode(string code, Action action)
    {
        var exception = Expect<BrokerPeerTrustException>(action);
        Ensure(exception.Code == code, $"expected {code}, received {exception.Code}");
        return exception;
    }

    private static async Task<TException> ExpectAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name} was not thrown.");
    }

    private static TException Expect<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name} was not thrown.");
    }

    private static async Task<ObservedConnection> ObserveAsync(
        Task<AuthenticatedPipePeerConnection> task)
    {
        try
        {
            return new ObservedConnection(await task, null);
        }
        catch (Exception exception)
        {
            return new ObservedConnection(null, exception);
        }
    }

    private static async Task<ObservedTask> ObserveAsync(Task task)
    {
        try
        {
            await task;
            return new ObservedTask(null);
        }
        catch (Exception exception)
        {
            return new ObservedTask(exception);
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record FixtureCore(
        VerifiedReleaseArtifactSet Release,
        WindowsProcessIdentity Identity,
        FakePeerLease Lease);

    private sealed record MessageFixture(
        WindowsNamedPipePeerVerifier Verifier,
        FakeMessagePlatform Platform,
        FakePeerLease Lease,
        WindowsProcessIdentity Identity,
        PendingPipePeerVerification Pending);

    private sealed record TrustOnlyFixture(
        WindowsNamedPipePeerVerifier Verifier,
        FakeTrustPlatform Platform,
        FakePeerLease Lease,
        PendingPipePeerVerification Pending);

    private sealed record ObservedConnection(
        AuthenticatedPipePeerConnection? Result,
        Exception? Failure);

    private sealed record ObservedTask(Exception? Failure);

    private class FakeTrustPlatform : INamedPipePeerTrustPlatform
    {
        private readonly VerifiedReleaseArtifactSet _release;
        private readonly FakePeerLease _lease;
        private int _disposeCallCount;
        private long _readGeneration;

        internal FakeTrustPlatform(
            VerifiedReleaseArtifactSet release,
            FakePeerLease lease)
        {
            _release = release;
            _lease = lease;
        }

        public DateTimeOffset UtcNow => AuthenticatedPipePeerConnectionOfflineTests.UtcNow;

        public long ReadGeneration => Volatile.Read(ref _readGeneration);

        internal int DisposeCallCount => Volatile.Read(ref _disposeCallCount);

        public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
        {
            Ensure(peerKind == NamedPipePeerKind.Server, "fake platform received the wrong direction");
            return new PipePeerKernelIdentity(ProcessId, SessionId);
        }

        public IRetainedPeerIdentityLease OpenRetainedPeer(
            uint processId,
            VerifiedReleaseArtifactSet release)
        {
            Ensure(processId == ProcessId, "fake platform received the wrong process id");
            Ensure(ReferenceEquals(release, _release), "fake platform received another release capability");
            return _lease;
        }

        public ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
            NamedPipePeerKind peerKind,
            int maximumHelloBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hello = BrokerPeerHelloProtocol.Serialize(CreateHello());
            Ensure(hello.Length <= maximumHelloBytes, "fake hello exceeded the verifier bound");
            var kernel = CaptureKernelPeer(peerKind);
            return ValueTask.FromResult(new PipePeerHelloReadEvidence(
                hello,
                Interlocked.Increment(ref _readGeneration),
                kernel,
                kernel,
                impersonatedClientToken: null));
        }

        public void AbortHandshake(string boundedFailureCode)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(boundedFailureCode);
        }

        public virtual void Dispose()
        {
            Interlocked.Increment(ref _disposeCallCount);
        }
    }

    private sealed class FakeMessagePlatform :
        FakeTrustPlatform,
        INamedPipePeerMessageTransport
    {
        private readonly ConcurrentQueue<byte[]> _reads = new();
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _allowRead = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _allowWrite = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal FakeMessagePlatform(
            VerifiedReleaseArtifactSet release,
            FakePeerLease lease)
            : base(release, lease)
        {
        }

        public Task Completion => _completion.Task;

        internal bool BlockReads { get; set; }

        internal bool BlockWrites { get; set; }

        internal Exception? ReadFailure { get; set; }

        internal Exception? WriteFailure { get; set; }

        internal ManualResetEventSlim ReadEntered { get; } = new(false);

        internal ManualResetEventSlim WriteEntered { get; } = new(false);

        internal List<byte[]> Writes { get; } = new();

        public async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
            int maximumMessageBytes,
            CancellationToken cancellationToken)
        {
            ReadEntered.Set();
            if (BlockReads)
            {
                await _allowRead.Task.WaitAsync(cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (ReadFailure is not null)
            {
                throw ReadFailure;
            }

            return _reads.TryDequeue(out var message)
                ? message
                : ReadOnlyMemory<byte>.Empty;
        }

        public async ValueTask WriteMessageAsync(
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken)
        {
            WriteEntered.Set();
            if (BlockWrites)
            {
                await _allowWrite.Task.WaitAsync(cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (WriteFailure is not null)
            {
                throw WriteFailure;
            }

            lock (Writes)
            {
                Writes.Add(message.ToArray());
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            _completion.TrySetResult();
        }

        internal void EnqueueRead(byte[] message) => _reads.Enqueue(message.ToArray());

        internal void CompleteTransport() => _completion.TrySetResult();
    }

    private sealed class FakePeerLease : IRetainedPeerIdentityLease
    {
        private readonly WindowsProcessIdentity _identity;
        private int _disposeCallCount;
        private int _disposed;

        internal FakePeerLease(
            WindowsProcessIdentity identity,
            RetainedReleaseHandleSet retainedHandles)
        {
            _identity = identity;
            RetainedHandles = retainedHandles;
        }

        public bool IsAlive
        {
            get
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                return true;
            }
        }

        public RetainedReleaseHandleSet RetainedHandles { get; }

        internal int DisposeCallCount => Volatile.Read(ref _disposeCallCount);

        public WindowsProcessIdentity Capture()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _identity;
        }

        public void Dispose()
        {
            Interlocked.Increment(ref _disposeCallCount);
            Interlocked.Exchange(ref _disposed, 1);
        }
    }
}
