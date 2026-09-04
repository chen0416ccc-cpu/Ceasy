using CodexGuardian.Control;
using CodexGuardian.Trust;
using System;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal interface IBrokerOwnedGuardianProcessLeaseV1 : IDisposable, IAsyncDisposable
{
    bool CleanEnvironmentVerified { get; }

    bool RuntimeNamespaceClosed { get; }

    Task<BrokerGuardianProcessExitV1> Completion { get; }

    WindowsProcessIdentity Revalidate();

    IBrokerOwnedGuardianProcessLeaseV1 TakeOwnership();

    Task StopAsync(BrokerGuardianProcessStopRequestV1 stopRequest);
}

internal sealed class BrokerGuardianCleanLaunchClaimV1 : IDisposable, IAsyncDisposable
{
    private readonly object _gate = new();
    private IBrokerOwnedGuardianProcessLeaseV1? _processLease;
    private byte[]? _challenge;
    private Task? _stopTask;
    private bool _disposed;

    internal BrokerGuardianCleanLaunchClaimV1(
        IBrokerOwnedGuardianProcessLeaseV1 processLease,
        WindowsProcessIdentity initialIdentity,
        GuardianManagedEntryMetadataIdentityV1 expectedMetadata,
        byte[] challenge)
    {
        _processLease = processLease ?? throw new ArgumentNullException(nameof(processLease));
        ProcessCompletion = processLease.Completion;
        InitialIdentity = initialIdentity ?? throw new ArgumentNullException(nameof(initialIdentity));
        ExpectedMetadata = expectedMetadata ?? throw new ArgumentNullException(nameof(expectedMetadata));
        _challenge = challenge ?? throw new ArgumentNullException(nameof(challenge));
    }

    internal WindowsProcessIdentity InitialIdentity { get; }

    internal Task<BrokerGuardianProcessExitV1> ProcessCompletion { get; }

    internal GuardianManagedEntryMetadataIdentityV1 ExpectedMetadata { get; }

    internal ReadOnlyMemory<byte> Challenge
    {
        get
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                return _challenge!;
            }
        }
    }

    internal WindowsProcessIdentity Revalidate()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return _processLease!.Revalidate();
        }
    }

    internal Task StopAsync(BrokerGuardianProcessStopRequestV1 stopRequest)
    {
        if (stopRequest == BrokerGuardianProcessStopRequestV1.None)
        {
            throw new ArgumentOutOfRangeException(nameof(stopRequest));
        }

        lock (_gate)
        {
            if (_stopTask is not null)
            {
                return _stopTask;
            }

            _disposed = true;
            var challenge = _challenge;
            _challenge = null;
            var processLease = _processLease;
            _processLease = null;
            if (challenge is not null)
            {
                CryptographicOperations.ZeroMemory(challenge);
            }

            _stopTask = processLease?.StopAsync(stopRequest) ?? Task.CompletedTask;
            return _stopTask;
        }
    }

    public void Dispose() =>
        StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)
            .GetAwaiter()
            .GetResult();

    public ValueTask DisposeAsync() =>
        new(StopAsync(BrokerGuardianProcessStopRequestV1.Disposal));

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal sealed class BrokerGuardianCleanLaunchAuthorityV1 : IDisposable, IAsyncDisposable
{
    private readonly object _gate = new();
    private IBrokerOwnedGuardianProcessLeaseV1? _processLease;
    private byte[]? _challenge;
    private Task? _stopTask;
    private bool _claimed;
    private bool _disposed;

    private BrokerGuardianCleanLaunchAuthorityV1(
        IBrokerOwnedGuardianProcessLeaseV1 processLease,
        WindowsProcessIdentity initialIdentity,
        GuardianManagedEntryMetadataIdentityV1 expectedMetadata,
        byte[] challenge)
    {
        _processLease = processLease;
        ProcessCompletion = processLease.Completion;
        InitialIdentity = initialIdentity;
        ExpectedMetadata = expectedMetadata;
        _challenge = challenge;
    }

    internal WindowsProcessIdentity InitialIdentity { get; }

    internal Task<BrokerGuardianProcessExitV1> ProcessCompletion { get; }

    internal GuardianManagedEntryMetadataIdentityV1 ExpectedMetadata { get; }

    internal static BrokerGuardianCleanLaunchAuthorityV1 Create(
        IBrokerOwnedGuardianProcessLeaseV1 processLease,
        GuardianManagedEntryMetadataIdentityV1 expectedMetadata,
        ReadOnlySpan<byte> challenge)
    {
        ArgumentNullException.ThrowIfNull(processLease);
        IBrokerOwnedGuardianProcessLeaseV1? ownedProcessLease = null;
        byte[]? challengeCopy = null;
        try
        {
            ownedProcessLease = processLease.TakeOwnership();
            if (ownedProcessLease is null || ReferenceEquals(ownedProcessLease, processLease))
            {
                throw Fail(
                    "managed-entry-launch-authority-invalid",
                    "The Broker-owned Guardian process lease did not transfer exclusive ownership.");
            }

            ArgumentNullException.ThrowIfNull(expectedMetadata);
            challengeCopy = challenge.ToArray();
            if (!ownedProcessLease.CleanEnvironmentVerified ||
                !ownedProcessLease.RuntimeNamespaceClosed ||
                challengeCopy.Length != GuardianManagedEntryProofProtocolV1.ChallengeBytes)
            {
                throw Fail(
                    "managed-entry-launch-authority-invalid",
                    "Managed-entry admission requires one Broker-owned clean launch with a closed runtime namespace.");
            }

            var identity = ownedProcessLease.Revalidate();
            if (!identity.ImageFileObjectIsExact ||
                !identity.ReleaseRoot.TraversalIsReparseFree ||
                identity.Artifacts.Count == 0 ||
                !identity.Artifacts.All(artifact => artifact.TraversalIsReparseFree))
            {
                throw Fail(
                    "managed-entry-launch-authority-invalid",
                    "The Broker-owned Guardian launch does not retain an exact verified release identity.");
            }

            return new BrokerGuardianCleanLaunchAuthorityV1(
                ownedProcessLease,
                identity,
                expectedMetadata,
                challengeCopy);
        }
        catch (Exception failure)
        {
            if (challengeCopy is not null)
            {
                CryptographicOperations.ZeroMemory(challengeCopy);
            }

            try
            {
                (ownedProcessLease ?? processLease)
                    .StopAsync(BrokerGuardianProcessStopRequestV1.AdmissionFailure)
                    .GetAwaiter()
                    .GetResult();
            }
            catch (Exception cleanupFailure)
            {
                BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    cleanupFailure);
            }

            ExceptionDispatchInfo.Capture(failure).Throw();
            throw;
        }
    }

    internal BrokerGuardianCleanLaunchClaimV1 ClaimForManagedEntryVerification()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_claimed)
            {
                throw Fail(
                    "managed-entry-launch-authority-claimed",
                    "The Broker-owned Guardian launch authority was already consumed.");
            }

            var claim = new BrokerGuardianCleanLaunchClaimV1(
                _processLease!,
                InitialIdentity,
                ExpectedMetadata,
                _challenge!);
            _processLease = null;
            _challenge = null;
            _claimed = true;
            return claim;
        }
    }

    internal Task StopAsync(BrokerGuardianProcessStopRequestV1 stopRequest)
    {
        if (stopRequest == BrokerGuardianProcessStopRequestV1.None)
        {
            throw new ArgumentOutOfRangeException(nameof(stopRequest));
        }

        lock (_gate)
        {
            if (_stopTask is not null)
            {
                return _stopTask;
            }

            _disposed = true;
            var challenge = _challenge;
            _challenge = null;
            var processLease = _processLease;
            _processLease = null;
            if (challenge is not null)
            {
                CryptographicOperations.ZeroMemory(challenge);
            }

            _stopTask = processLease?.StopAsync(stopRequest) ?? Task.CompletedTask;
            return _stopTask;
        }
    }

    public void Dispose() =>
        StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)
            .GetAwaiter()
            .GetResult();

    public ValueTask DisposeAsync() =>
        new(StopAsync(BrokerGuardianProcessStopRequestV1.Disposal));

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private static BrokerControlSessionException Fail(string code, string message) =>
        new(code, message);
}

internal sealed class VerifiedGuardianManagedEntryConnectionV1 : IAsyncDisposable
{
    private readonly object _gate = new();
    private AuthenticatedPipePeerConnection? _connection;
    private BrokerGuardianCleanLaunchClaimV1? _launchClaim;
    private Task? _disposeTask;
    private bool _claimed;
    private bool _ownerStopInitiated;

    private VerifiedGuardianManagedEntryConnectionV1(
        AuthenticatedPipePeerConnection connection,
        GuardianManagedEntryReceiptV1 receipt,
        BrokerGuardianCleanLaunchClaimV1 launchClaim)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _launchClaim = launchClaim ?? throw new ArgumentNullException(nameof(launchClaim));
        Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
        InitialIdentity = connection.InitialIdentity;
        ProcessCompletion = launchClaim.ProcessCompletion;
        Completion = CreateCompletionArbitrationTask(
            connection.Completion,
            ProcessCompletion);
    }

    internal WindowsProcessIdentity InitialIdentity { get; }

    internal Task Completion { get; }

    internal Task<BrokerGuardianProcessExitV1> ProcessCompletion { get; }

    internal GuardianManagedEntryReceiptV1 Receipt { get; }

    internal static async ValueTask<VerifiedGuardianManagedEntryConnectionV1> VerifyAsync(
        AuthenticatedPipePeerConnection connection,
        BrokerGuardianCleanLaunchAuthorityV1 launchAuthority,
        CancellationToken cancellationToken = default)
    {
        BrokerGuardianCleanLaunchClaimV1? launch = null;
        ManagedEntryVerificationAbortV1? verificationOwner = null;
        try
        {
            ArgumentNullException.ThrowIfNull(connection);
            ArgumentNullException.ThrowIfNull(launchAuthority);
            launch = launchAuthority.ClaimForManagedEntryVerification();
            verificationOwner = new ManagedEntryVerificationAbortV1(connection, launch);
            launch = null;
            verificationOwner.RegisterCancellation(cancellationToken);
            ThrowIfAbortRequested(verificationOwner, cancellationToken);
            ThrowIfProcessCompletedBeforeAbort(verificationOwner);
            var expectedChallengeSha256 =
                GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(
                    verificationOwner.LaunchChallenge.Span);
            if (connection.PeerRole != BrokerPeerRole.Guardian ||
                connection.Completion.IsCompleted)
            {
                throw Fail(
                    "managed-entry-peer-invalid",
                    "Managed-entry admission requires one live authenticated Guardian peer.");
            }

            var initialIdentity = connection.InitialIdentity;
            RequireExactProcessIdentity(verificationOwner.LaunchInitialIdentity, initialIdentity);
            RequireExactProcessIdentity(
                verificationOwner.LaunchInitialIdentity,
                verificationOwner.RevalidateLaunch());
            var before = connection.Revalidate();
            RequireExactProcessIdentity(initialIdentity, before);
            ThrowIfAbortRequested(verificationOwner, cancellationToken);
            ThrowIfProcessCompletedBeforeAbort(verificationOwner);
            if (!verificationOwner.TryStartReceiptRead(out var readTask))
            {
                throw CreateVerificationCancellation(cancellationToken);
            }

            var readWinner = await Task.WhenAny(
                    verificationOwner.ProcessCompletion,
                    readTask,
                    verificationOwner.AbortRequested)
                .ConfigureAwait(false);
            if (ReferenceEquals(readWinner, verificationOwner.AbortRequested))
            {
                throw CreateVerificationCancellation(cancellationToken);
            }

            if (ReferenceEquals(readWinner, verificationOwner.ProcessCompletion))
            {
                throw ReadProcessFailure(verificationOwner.ProcessCompletion);
            }

            var payload = await readTask.ConfigureAwait(false);
            ThrowIfAbortRequested(verificationOwner, cancellationToken);
            ThrowIfProcessCompletedBeforeAbort(verificationOwner);
            if (!GuardianManagedEntryProofProtocolV1.TryParse(
                    payload,
                    out var receipt,
                    out var reason) ||
                receipt is null)
            {
                throw Fail(
                    "managed-entry-proof-invalid",
                    "The Guardian managed-entry receipt was rejected: " + reason + ".");
            }

            if (!string.Equals(
                receipt.ChallengeSha256,
                    expectedChallengeSha256,
                    StringComparison.Ordinal) ||
                receipt.ProcessId != initialIdentity.ProcessId ||
                receipt.SessionId != initialIdentity.KernelSessionId ||
                receipt.CreationTimeUtc != initialIdentity.CreationTimeUtc ||
                receipt.Metadata != verificationOwner.ExpectedMetadata)
            {
                throw Fail(
                    "managed-entry-proof-mismatch",
                    "The Guardian managed-entry receipt does not match the exact peer and release metadata.");
            }

            var after = connection.Revalidate();
            RequireExactProcessIdentity(initialIdentity, after);
            RequireExactProcessIdentity(
                verificationOwner.LaunchInitialIdentity,
                verificationOwner.RevalidateLaunch());
            ThrowIfAbortRequested(verificationOwner, cancellationToken);
            ThrowIfProcessCompletedBeforeAbort(verificationOwner);
            if (connection.Completion.IsCompleted)
            {
                throw Fail(
                    "managed-entry-peer-invalid",
                    "The authenticated Guardian peer closed during managed-entry admission.");
            }

            if (!verificationOwner.TryCommitSuccess(receipt, out var verified))
            {
                throw CreateVerificationCancellation(cancellationToken);
            }

            return verified;
        }
        catch (Exception failure)
        {
            if (verificationOwner is not null)
            {
                var primary = await verificationOwner
                    .AbortAndSettleFailureAsync(failure, cancellationToken)
                    .ConfigureAwait(false);
                ExceptionDispatchInfo.Capture(primary).Throw();
                throw;
            }

            try
            {
                if (launch is not null)
                {
                    await launch.StopAsync(BrokerGuardianProcessStopRequestV1.AdmissionFailure)
                        .ConfigureAwait(false);
                }
                else if (launchAuthority is not null)
                {
                    await launchAuthority
                        .StopAsync(BrokerGuardianProcessStopRequestV1.AdmissionFailure)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception cleanupFailure)
            {
                BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    cleanupFailure);
            }

            if (connection is not null)
            {
                try
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception cleanupFailure)
                {
                    BrokerControlFailureArbitration.PreserveCleanupFailure(
                        failure,
                        cleanupFailure);
                }
            }

            ExceptionDispatchInfo.Capture(failure).Throw();
            throw;
        }
    }

    private sealed class ManagedEntryVerificationAbortV1
    {
        private const int Active = 0;
        private const int Aborting = 1;
        private const int Committed = 2;

        private readonly object _gate = new();
        private readonly CancellationTokenSource _receiptCancellation = new();
        private readonly TaskCompletionSource<ManagedEntryVerificationAbortSnapshotV1>
            _abortRequested = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private AuthenticatedPipePeerConnection? _connection;
        private BrokerGuardianCleanLaunchClaimV1? _launch;
        private CancellationTokenRegistration _cancellationRegistration;
        private Task<ReadOnlyMemory<byte>>? _readTask;
        private Task? _stopTask;
        private Task? _connectionDisposeTask;
        private ManagedEntryVerificationAbortSnapshotV1 _abortSnapshot;
        private bool _cancellationRegistrationAssigned;
        private bool _receiptReadStarting;
        private int _state;

        internal ManagedEntryVerificationAbortV1(
            AuthenticatedPipePeerConnection connection,
            BrokerGuardianCleanLaunchClaimV1 launch)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            _launch = launch ?? throw new ArgumentNullException(nameof(launch));
            ProcessCompletion = launch.ProcessCompletion;
        }

        internal Task<ManagedEntryVerificationAbortSnapshotV1> AbortRequested =>
            _abortRequested.Task;

        internal ReadOnlyMemory<byte> LaunchChallenge => GetLaunch().Challenge;

        internal WindowsProcessIdentity LaunchInitialIdentity => GetLaunch().InitialIdentity;

        internal GuardianManagedEntryMetadataIdentityV1 ExpectedMetadata =>
            GetLaunch().ExpectedMetadata;

        internal Task<BrokerGuardianProcessExitV1> ProcessCompletion { get; }

        internal void RegisterCancellation(CancellationToken cancellationToken)
        {
            CancellationTokenRegistration registration = default;
            if (cancellationToken.CanBeCanceled)
            {
                registration = cancellationToken.UnsafeRegister(
                    static state =>
                        ((ManagedEntryVerificationAbortV1)state!).RequestAbortNoThrow(),
                    this);
            }

            lock (_gate)
            {
                if (_cancellationRegistrationAssigned)
                {
                    registration.Dispose();
                    throw new InvalidOperationException(
                        "Managed-entry verification cancellation was registered twice.");
                }

                _cancellationRegistration = registration;
                _cancellationRegistrationAssigned = true;
            }
        }

        internal WindowsProcessIdentity RevalidateLaunch() => GetLaunch().Revalidate();

        internal Exception? CaptureProcessFailureBeforeAbort()
        {
            lock (_gate)
            {
                return _state == Aborting
                    ? _abortSnapshot.ProcessFailureBeforeAbort
                    : _state == Active
                        ? CaptureProcessFailureNoThrow(ProcessCompletion)
                        : null;
            }
        }

        internal bool TryStartReceiptRead(
            out Task<ReadOnlyMemory<byte>> readTask)
        {
            AuthenticatedPipePeerConnection connection;
            lock (_gate)
            {
                if (_state != Active)
                {
                    readTask = Task.FromCanceled<ReadOnlyMemory<byte>>(
                        new CancellationToken(canceled: true));
                    return false;
                }

                if (_receiptReadStarting || _readTask is not null)
                {
                    throw new InvalidOperationException(
                        "The managed-entry receipt read was already started.");
                }

                _receiptReadStarting = true;
                connection = _connection!;
            }

            Task<ReadOnlyMemory<byte>> startedRead;
            try
            {
                startedRead = connection
                    .ReadMessageAsync(
                        GuardianManagedEntryProofProtocolV1.MaximumReceiptBytes,
                        _receiptCancellation.Token)
                    .AsTask();
            }
            catch (Exception exception)
            {
                startedRead = Task.FromException<ReadOnlyMemory<byte>>(exception);
            }

            lock (_gate)
            {
                _readTask = startedRead;
                _receiptReadStarting = false;
            }

            readTask = startedRead;
            return true;
        }

        internal bool TryCommitSuccess(
            GuardianManagedEntryReceiptV1 receipt,
            out VerifiedGuardianManagedEntryConnectionV1 verified)
        {
            lock (_gate)
            {
                if (_state != Active)
                {
                    verified = null!;
                    return false;
                }

                verified = new VerifiedGuardianManagedEntryConnectionV1(
                    _connection!,
                    receipt,
                    _launch!);
                _connection = null;
                _launch = null;
                _state = Committed;
            }

            DisposeCancellationInfrastructureNoThrow();
            return true;
        }

        internal async Task<Exception> AbortAndSettleFailureAsync(
            Exception failure,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(failure);
            RequestAbortNoThrow();
            var snapshot = await _abortRequested.Task.ConfigureAwait(false);
            var primary = SelectAbortPrimary(failure, cancellationToken, snapshot);

            Task? stopTask;
            Task? connectionDisposeTask;
            Task<ReadOnlyMemory<byte>>? readTask;
            lock (_gate)
            {
                stopTask = _stopTask;
                connectionDisposeTask = _connectionDisposeTask;
                readTask = _readTask;
            }

            Exception? cleanupFailure = null;
            var stopFailure = await CaptureTaskFailureAsync(stopTask).ConfigureAwait(false);
            if (stopFailure is not null)
            {
                cleanupFailure = BrokerControlFailureArbitration.CombineCleanupFailures(
                    cleanupFailure,
                    stopFailure);
            }

            var connectionDisposeFailure = await CaptureTaskFailureAsync(
                    connectionDisposeTask)
                .ConfigureAwait(false);
            if (connectionDisposeFailure is not null)
            {
                cleanupFailure = BrokerControlFailureArbitration.CombineCleanupFailures(
                    cleanupFailure,
                    connectionDisposeFailure);
            }

            if (readTask is not null)
            {
                try
                {
                    _ = await readTask.ConfigureAwait(false);
                }
                catch (Exception readFailure)
                {
                    if (snapshot.ReadCompletedBeforeAbort ||
                        !IsExpectedAbortReadFailure(readFailure))
                    {
                        BrokerControlFailureArbitration.PreserveSecondaryFailure(
                            primary,
                            readFailure,
                            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                    }
                }
            }

            var cancellationInfrastructureFailure = DisposeCancellationInfrastructure();
            if (cancellationInfrastructureFailure is not null)
            {
                cleanupFailure = BrokerControlFailureArbitration.CombineCleanupFailures(
                    cleanupFailure,
                    cancellationInfrastructureFailure);
            }

            BrokerControlFailureArbitration.PreserveCleanupFailure(
                primary,
                cleanupFailure);
            return primary;
        }

        private BrokerGuardianCleanLaunchClaimV1 GetLaunch()
        {
            lock (_gate)
            {
                if (_state != Active)
                {
                    throw new ObjectDisposedException(
                        nameof(ManagedEntryVerificationAbortV1));
                }

                return _launch ?? throw new ObjectDisposedException(
                    nameof(ManagedEntryVerificationAbortV1));
            }
        }

        private void RequestAbortNoThrow()
        {
            BrokerGuardianCleanLaunchClaimV1? launch;
            AuthenticatedPipePeerConnection? connection;
            ManagedEntryVerificationAbortSnapshotV1 snapshot;
            lock (_gate)
            {
                if (_state != Active)
                {
                    return;
                }

                snapshot = new ManagedEntryVerificationAbortSnapshotV1(
                    CaptureProcessFailureNoThrow(ProcessCompletion),
                    _readTask?.IsCompleted == true);
                _abortSnapshot = snapshot;
                _state = Aborting;
                launch = _launch;
                connection = _connection;
            }

            var stopTask = StartStopNoThrow(launch);
            var connectionDisposeTask = StartDisposeNoThrow(connection);
            lock (_gate)
            {
                _stopTask = stopTask;
                _connectionDisposeTask = connectionDisposeTask;
            }

            CancelNoThrow(_receiptCancellation);
            _abortRequested.TrySetResult(snapshot);
        }

        private Exception SelectAbortPrimary(
            Exception failure,
            CancellationToken cancellationToken,
            ManagedEntryVerificationAbortSnapshotV1 snapshot)
        {
            if (snapshot.ProcessFailureBeforeAbort is Exception processFailure)
            {
                if (!IsManagedEntryProcessFailure(failure) &&
                    (failure is not OperationCanceledException canceled ||
                     canceled.CancellationToken != cancellationToken))
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        processFailure,
                        failure,
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        processFailure,
                        CreateVerificationCancellation(cancellationToken),
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                }

                return processFailure;
            }

            if (!cancellationToken.IsCancellationRequested)
            {
                return failure;
            }

            var cancellationFailure = CreateVerificationCancellation(cancellationToken);
            if (ShouldPreserveBehindCancellation(failure, snapshot))
            {
                BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    cancellationFailure,
                    failure,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey);
            }

            return cancellationFailure;
        }

        private static bool ShouldPreserveBehindCancellation(
            Exception failure,
            ManagedEntryVerificationAbortSnapshotV1 snapshot)
        {
            if (failure is OperationCanceledException ||
                IsManagedEntryProcessFailure(failure))
            {
                return false;
            }

            return snapshot.ReadCompletedBeforeAbort ||
                !IsExpectedAbortReadFailure(failure);
        }

        private static Task StartStopNoThrow(
            BrokerGuardianCleanLaunchClaimV1? launch)
        {
            try
            {
                return launch?.StopAsync(BrokerGuardianProcessStopRequestV1.AdmissionFailure) ??
                    Task.CompletedTask;
            }
            catch (Exception exception)
            {
                return Task.FromException(exception);
            }
        }

        private static Task StartDisposeNoThrow(
            AuthenticatedPipePeerConnection? connection)
        {
            try
            {
                return connection?.DisposeAsync().AsTask() ?? Task.CompletedTask;
            }
            catch (Exception exception)
            {
                return Task.FromException(exception);
            }
        }

        private static async Task<Exception?> CaptureTaskFailureAsync(Task? task)
        {
            if (task is null)
            {
                return null;
            }

            try
            {
                await task.ConfigureAwait(false);
                return null;
            }
            catch (Exception exception)
            {
                return exception;
            }
        }

        private Exception? DisposeCancellationInfrastructure()
        {
            Exception? failure = null;
            try
            {
                if (_cancellationRegistrationAssigned)
                {
                    _cancellationRegistration.Dispose();
                }
            }
            catch (Exception exception)
            {
                failure = exception;
            }

            try
            {
                _receiptCancellation.Dispose();
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.CombineCleanupFailures(
                    failure,
                    exception);
            }

            return failure;
        }

        private void DisposeCancellationInfrastructureNoThrow()
        {
            try
            {
                _ = DisposeCancellationInfrastructure();
            }
            catch (Exception)
            {
            }
        }
    }

    private readonly record struct ManagedEntryVerificationAbortSnapshotV1(
        Exception? ProcessFailureBeforeAbort,
        bool ReadCompletedBeforeAbort);

    internal void ClaimForControlSession()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            RequireProcessPending(ProcessCompletion);
            if (_claimed)
            {
                throw Fail(
                    "managed-entry-already-claimed",
                    "The verified Guardian managed-entry connection was already claimed.");
            }

            _claimed = true;
        }
    }

    internal WindowsProcessIdentity Revalidate()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            RequireProcessPending(ProcessCompletion);
            var connection = _connection ?? throw new ObjectDisposedException(
                nameof(VerifiedGuardianManagedEntryConnectionV1));
            var launch = _launchClaim ?? throw new ObjectDisposedException(
                nameof(VerifiedGuardianManagedEntryConnectionV1));
            var peerIdentity = connection.Revalidate();
            RequireExactProcessIdentity(InitialIdentity, peerIdentity);
            RequireExactProcessIdentity(InitialIdentity, launch.Revalidate());
            return peerIdentity;
        }
    }

    internal ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
        int maximumMessageBytes,
        CancellationToken cancellationToken = default) =>
        GetConnection().ReadMessageAsync(maximumMessageBytes, cancellationToken);

    internal ValueTask WriteMessageAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default) =>
        GetConnection().WriteMessageAsync(message, cancellationToken);

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposeTask is null)
            {
                _ownerStopInitiated = true;
                _disposeTask = DisposeCoreAsync();
            }

            return new ValueTask(_disposeTask);
        }
    }

    private async Task DisposeCoreAsync()
    {
        await Task.Yield();
        AuthenticatedPipePeerConnection? connection;
        BrokerGuardianCleanLaunchClaimV1? launchClaim;
        lock (_gate)
        {
            connection = _connection;
            _connection = null;
            launchClaim = _launchClaim;
            _launchClaim = null;
        }

        Task? launchStopTask = null;
        Exception? launchStopFailure = null;
        try
        {
            if (launchClaim is not null)
            {
                launchStopTask = launchClaim.StopAsync(
                    BrokerGuardianProcessStopRequestV1.Disposal);
            }
        }
        catch (Exception exception)
        {
            launchStopFailure = exception;
        }

        Exception? connectionFailure = null;
        if (connection is not null)
        {
            try
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                connectionFailure = exception;
            }
        }

        if (launchStopTask is not null)
        {
            try
            {
                await launchStopTask.ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                launchStopFailure = BrokerControlFailureArbitration.CombineCleanupFailures(
                    launchStopFailure,
                    exception);
            }
        }

        var failure = connectionFailure is null
            ? launchStopFailure
            : BrokerControlFailureArbitration.CombineCleanupFailures(
                launchStopFailure,
                connectionFailure);
        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private AuthenticatedPipePeerConnection GetConnection()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            return _connection ?? throw new ObjectDisposedException(
                nameof(VerifiedGuardianManagedEntryConnectionV1));
        }
    }

    private static void RequireExactProcessIdentity(
        WindowsProcessIdentity expected,
        WindowsProcessIdentity actual)
    {
        if (expected.ProcessId != actual.ProcessId ||
            expected.CreationTimeUtc != actual.CreationTimeUtc ||
            expected.KernelSessionId != actual.KernelSessionId ||
            !Equals(expected.Token, actual.Token) ||
            !Equals(expected.AppModel, actual.AppModel) ||
            !string.Equals(expected.FinalImagePath, actual.FinalImagePath, StringComparison.Ordinal) ||
            expected.ImageFileObjectIsExact != actual.ImageFileObjectIsExact ||
            !Equals(expected.ReleaseRoot, actual.ReleaseRoot) ||
            !expected.Artifacts.SequenceEqual(actual.Artifacts))
        {
            throw Fail(
                "managed-entry-peer-invalid",
                "The authenticated Guardian identity changed during managed-entry admission.");
        }
    }

    private static void ThrowIfAbortRequested(
        ManagedEntryVerificationAbortV1 verificationOwner,
        CancellationToken cancellationToken)
    {
        if (verificationOwner.AbortRequested.IsCompleted ||
            cancellationToken.IsCancellationRequested)
        {
            throw CreateVerificationCancellation(cancellationToken);
        }
    }

    private static void ThrowIfProcessCompletedBeforeAbort(
        ManagedEntryVerificationAbortV1 verificationOwner)
    {
        var processFailure = verificationOwner.CaptureProcessFailureBeforeAbort();
        if (processFailure is not null)
        {
            ExceptionDispatchInfo.Capture(processFailure).Throw();
        }
    }

    private static Exception? CaptureProcessFailureNoThrow(
        Task<BrokerGuardianProcessExitV1> processCompletion)
    {
        if (!processCompletion.IsCompleted)
        {
            return null;
        }

        try
        {
            return ReadProcessFailure(processCompletion);
        }
        catch (Exception exception)
        {
            return new BrokerControlSessionException(
                "managed-entry-process-observation-failed",
                "The exact Guardian process completion could not be captured during managed-entry arbitration.",
                exception);
        }
    }

    private static Exception ReadProcessFailure(
        Task<BrokerGuardianProcessExitV1> processCompletion)
    {
        try
        {
            RequireProcessPending(processCompletion);
        }
        catch (Exception exception)
        {
            return exception;
        }

        return Fail(
            "managed-entry-process-observation-failed",
            "The exact Guardian process completion winner was not complete.");
    }

    private static bool IsManagedEntryProcessFailure(Exception failure) =>
        failure is BrokerControlSessionException processFailure &&
        processFailure.Code is
            "managed-entry-process-observation-failed" or
            "managed-entry-process-exited";

    private static bool IsExpectedAbortReadFailure(Exception failure)
    {
        if (failure is OperationCanceledException or ObjectDisposedException)
        {
            return true;
        }

        if (failure is BrokerPeerTrustException peerFailure &&
            peerFailure.Code is "peer-message-read-cancelled" or "peer-message-eof")
        {
            return true;
        }

        if (failure is AggregateException aggregate)
        {
            return aggregate.InnerExceptions.Count > 0 &&
                aggregate.InnerExceptions.All(IsExpectedAbortReadFailure);
        }

        return failure.InnerException is not null &&
            IsExpectedAbortReadFailure(failure.InnerException);
    }

    private static OperationCanceledException CreateVerificationCancellation(
        CancellationToken cancellationToken) =>
        new(
            "The Guardian managed-entry verification was canceled before authority transfer.",
            cancellationToken);

    private static void RequireProcessPending(
        Task<BrokerGuardianProcessExitV1> processCompletion)
    {
        ArgumentNullException.ThrowIfNull(processCompletion);
        if (!processCompletion.IsCompleted)
        {
            return;
        }

        if (processCompletion.IsFaulted)
        {
            throw new BrokerControlSessionException(
                "managed-entry-process-observation-failed",
                "The exact Guardian process exit observation failed during the verified managed-entry lifetime.",
                processCompletion.Exception?.InnerException ?? processCompletion.Exception);
        }

        if (processCompletion.IsCanceled)
        {
            throw new BrokerControlSessionException(
                "managed-entry-process-observation-failed",
                "The exact Guardian process exit observation was canceled during the verified managed-entry lifetime.");
        }

        var exit = processCompletion.GetAwaiter().GetResult();
        throw new BrokerControlSessionException(
            "managed-entry-process-exited",
            "The exact Guardian process exited during the verified managed-entry lifetime with code 0x" +
            exit.ExitCode.ToString("X8") + ".");
    }

    private Task CreateCompletionArbitrationTask(
        Task connectionCompletion,
        Task<BrokerGuardianProcessExitV1> processCompletion)
    {
        ArgumentNullException.ThrowIfNull(connectionCompletion);
        ArgumentNullException.ThrowIfNull(processCompletion);
        var completion = ObserveCompletionArbitrationAsync(
            connectionCompletion,
            processCompletion);
        ObserveFault(completion);
        return completion;
    }

    private async Task ObserveCompletionArbitrationAsync(
        Task connectionCompletion,
        Task<BrokerGuardianProcessExitV1> processCompletion)
    {
        if (processCompletion.IsCompleted)
        {
            RequireProcessPending(processCompletion);
        }

        var first = await Task.WhenAny(
                processCompletion,
                connectionCompletion)
            .ConfigureAwait(false);
        if (ReferenceEquals(first, processCompletion))
        {
            if (ReadOwnerStopInitiated())
            {
                await connectionCompletion.ConfigureAwait(false);
                return;
            }

            RequireProcessPending(processCompletion);
        }

        try
        {
            await connectionCompletion.ConfigureAwait(false);
        }
        catch (Exception connectionFailure)
        {
            if (processCompletion.IsCompleted && !ReadOwnerStopInitiated())
            {
                try
                {
                    RequireProcessPending(processCompletion);
                }
                catch (Exception processFailure)
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        processFailure,
                        connectionFailure,
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                    ExceptionDispatchInfo.Capture(processFailure).Throw();
                }
            }

            throw;
        }

        if (processCompletion.IsCompleted && !ReadOwnerStopInitiated())
        {
            RequireProcessPending(processCompletion);
        }
    }

    private bool ReadOwnerStopInitiated()
    {
        lock (_gate)
        {
            return _ownerStopInitiated;
        }
    }

    private static void CancelNoThrow(CancellationTokenSource? cancellation)
    {
        if (cancellation is null)
        {
            return;
        }

        try
        {
            cancellation.Cancel();
        }
        catch (Exception)
        {
        }
    }

    private static void ObserveFault(Task task) =>
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously |
                TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);

    private static BrokerControlSessionException Fail(string code, string message) =>
        new(code, message);
}
