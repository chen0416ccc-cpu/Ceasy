using CodexGuardian.Control;
using CodexGuardian.Trust;
using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal sealed class WindowsGuardianProductionAdmissionV1 :
    IBrokerGuardianAdmissionSourceV1
{
    private static readonly TimeSpan ReleaseBootstrapConnectionTimeout =
        TimeSpan.FromMinutes(15);
    private static readonly TimeSpan StageTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan StageDrainTimeout = TimeSpan.FromSeconds(10);

    private readonly object _gate = new();
    private readonly Func<CancellationToken, ValueTask<VerifiedGuardianManagedEntryConnectionV1>>
        _acceptCore;
    private readonly WindowsNamedPipePeerVerifier _verifier;
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly WindowsGuardianCleanLauncherV1? _launcher;
    private readonly VerifiedReleaseArtifactSet? _guardianRelease;
    private readonly VerifiedReleaseArtifactSet? _brokerRelease;
    private readonly GuardianManagedEntryMetadataIdentityV1? _expectedMetadata;
    private readonly WindowsProcessIdentity? _brokerIdentity;
    private Task<VerifiedGuardianManagedEntryConnectionV1>? _acceptTask;
    private Task? _disposeTask;
    private bool _acceptStarted;
    private bool _disposeStarted;

    private WindowsGuardianProductionAdmissionV1(
        BrokerProductionReleaseBindingV1 releaseBinding,
        WindowsGuardianCleanLauncherV1 launcher,
        WindowsNamedPipePeerVerifier verifier,
        VerifiedReleaseArtifactSet guardianRelease,
        VerifiedReleaseArtifactSet brokerRelease,
        GuardianManagedEntryMetadataIdentityV1 expectedMetadata,
        WindowsProcessIdentity brokerIdentity)
    {
        ReleaseBinding = releaseBinding;
        _launcher = launcher;
        _verifier = verifier;
        _guardianRelease = guardianRelease;
        _brokerRelease = brokerRelease;
        _expectedMetadata = expectedMetadata;
        _brokerIdentity = brokerIdentity;
        _acceptCore = AcceptProductionAsync;
    }

#if CODEXGUARDIAN_TEST_FRIEND
    internal WindowsGuardianProductionAdmissionV1(
        BrokerProductionReleaseBindingV1 releaseBinding,
        WindowsNamedPipePeerVerifier verifier,
        Func<CancellationToken, ValueTask<VerifiedGuardianManagedEntryConnectionV1>>
            acceptCore)
    {
        ReleaseBinding = releaseBinding ?? throw new ArgumentNullException(nameof(releaseBinding));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _acceptCore = acceptCore ?? throw new ArgumentNullException(nameof(acceptCore));
    }
#endif

    public BrokerProductionReleaseBindingV1 ReleaseBinding { get; }

    public NamedPipePeerTrustHealth Health => _verifier.Health;

    public bool AllowsSuccessorAdmission => false;

    internal static WindowsGuardianProductionAdmissionV1 Create(
        BrokerProductionReleaseBindingV1 releaseBinding)
    {
        ArgumentNullException.ThrowIfNull(releaseBinding);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The production Guardian admission source is Windows-only.");
        }

        var guardianRelease = releaseBinding.Manifest.GetArtifactSet(BrokerPeerRole.Guardian);
        var brokerRelease = releaseBinding.Manifest.GetArtifactSet(BrokerPeerRole.Broker);
        var managedEntryPath = guardianRelease.Artifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.ManagedEntryDll).FinalPath;
        var expectedMetadata = GuardianManagedEntryMetadataIdentityV1.ReadFromAssemblyFile(
            managedEntryPath);
        var brokerIdentity = CaptureCurrentBrokerIdentity(releaseBinding);
        RequireCurrentBrokerIdentity(brokerIdentity, brokerRelease);
        var verifier = new WindowsNamedPipePeerVerifier();
        return new WindowsGuardianProductionAdmissionV1(
            releaseBinding,
            WindowsGuardianCleanLauncherV1.Create(releaseBinding),
            verifier,
            guardianRelease,
            brokerRelease,
            expectedMetadata,
            brokerIdentity);
    }

    public ValueTask<VerifiedGuardianManagedEntryConnectionV1> AcceptAsync(
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_disposeStarted || _acceptStarted)
            {
                return new ValueTask<VerifiedGuardianManagedEntryConnectionV1>(
                    Task.FromException<VerifiedGuardianManagedEntryConnectionV1>(
                        ConsumedFailure()));
            }

            _acceptStarted = true;
            var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetimeCancellation.Token);
            _acceptTask = RunAcceptCoreAsync(cancellationToken, linkedCancellation);
            return new ValueTask<VerifiedGuardianManagedEntryConnectionV1>(_acceptTask);
        }
    }

    public BrokerGuardianAdmissionFailureDispositionV1 ClassifyFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return BrokerGuardianAdmissionFailureDispositionV1.Terminal;
    }

    public BrokerGuardianConnectionFailureDispositionV1 ClassifyConnectionFailure(
        Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return BrokerGuardianConnectionFailureDispositionV1.Terminal;
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposeTask is null)
            {
                _disposeStarted = true;
                _disposeTask = DisposeCoreAsync();
            }

            return new ValueTask(_disposeTask);
        }
    }

    private async Task<VerifiedGuardianManagedEntryConnectionV1> RunAcceptCoreAsync(
        CancellationToken callerCancellation,
        CancellationTokenSource linkedCancellation)
    {
        await Task.Yield();
        VerifiedGuardianManagedEntryConnectionV1? lateConnection = null;
        try
        {
            var connection = await _acceptCore(linkedCancellation.Token).ConfigureAwait(false) ??
                throw Failure(
                    "guardian-admission-result-invalid",
                    "The production Guardian admission operation returned no connection authority.");

            Exception? transferFailure = null;
            if (connection.ProcessCompletion.IsCompleted)
            {
                transferFailure = ReadProcessFailure(connection.ProcessCompletion);
            }
            else
            {
                try
                {
                    _ = connection.Revalidate();
                }
                catch (Exception exception)
                {
                    transferFailure = exception;
                }
            }

            if (transferFailure is null && connection.Completion.IsCompleted)
            {
                try
                {
                    await connection.Completion.ConfigureAwait(false);
                    transferFailure = Failure(
                        "guardian-admission-connection-closed",
                        "The verified Guardian connection closed before authority transfer.");
                }
                catch (Exception exception)
                {
                    transferFailure = exception;
                }
            }

            if (callerCancellation.IsCancellationRequested)
            {
                lateConnection = connection;
                var cancellationFailure = new OperationCanceledException(
                    "The production Guardian admission was canceled before authority transfer.",
                    callerCancellation);
                if (transferFailure is not null)
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        transferFailure,
                        cancellationFailure,
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                    ExceptionDispatchInfo.Capture(transferFailure).Throw();
                }

                throw cancellationFailure;
            }

            if (transferFailure is not null)
            {
                lateConnection = connection;
                ExceptionDispatchInfo.Capture(transferFailure).Throw();
            }

            lock (_gate)
            {
                if (!_disposeStarted)
                {
                    return connection;
                }
            }

            lateConnection = connection;
            var disposalFailure = new OperationCanceledException(
                "The production Guardian admission source was disposed before authority transfer.",
                _lifetimeCancellation.Token);
            if (connection.ProcessCompletion.IsCompleted)
            {
                var processFailure = ReadProcessFailure(connection.ProcessCompletion);
                BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    processFailure,
                    disposalFailure,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                ExceptionDispatchInfo.Capture(processFailure).Throw();
            }

            throw disposalFailure;
        }
        catch (Exception exception)
        {
            Exception failure = exception;
            if (exception is OperationCanceledException canceled &&
                canceled.CancellationToken == linkedCancellation.Token)
            {
                if (callerCancellation.IsCancellationRequested)
                {
                    failure = new OperationCanceledException(
                        "The production Guardian admission was canceled by its caller.",
                        exception,
                        callerCancellation);
                }
                else if (_lifetimeCancellation.IsCancellationRequested)
                {
                    failure = new OperationCanceledException(
                        "The production Guardian admission source was disposed.",
                        exception,
                        _lifetimeCancellation.Token);
                }
            }

            if (lateConnection is not null)
            {
                try
                {
                    await lateConnection.DisposeAsync().ConfigureAwait(false);
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
        finally
        {
            linkedCancellation.Dispose();
        }
    }

    private async Task DisposeCoreAsync()
    {
        await Task.Yield();
        Task<VerifiedGuardianManagedEntryConnectionV1>? acceptTask;
        lock (_gate)
        {
            acceptTask = _acceptTask;
        }

        Exception? failure = null;
        try
        {
            _lifetimeCancellation.Cancel();
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        if (acceptTask is not null)
        {
            try
            {
                _ = await acceptTask.ConfigureAwait(false);
            }
            catch
            {
                // The accept caller owns the primary admission failure. Disposal only
                // waits for its reverse cleanup and reports cancellation infrastructure.
            }
        }

        try
        {
            _lifetimeCancellation.Dispose();
        }
        catch (Exception cleanupFailure)
        {
            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                failure,
                cleanupFailure);
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private async ValueTask<VerifiedGuardianManagedEntryConnectionV1> AcceptProductionAsync(
        CancellationToken cancellationToken)
    {
        var launcher = _launcher ?? throw new InvalidOperationException(
            "The production Guardian launcher is unavailable.");
        var guardianRelease = _guardianRelease ?? throw new InvalidOperationException(
            "The verified Guardian release is unavailable.");
        var brokerRelease = _brokerRelease ?? throw new InvalidOperationException(
            "The verified Broker release is unavailable.");
        var expectedMetadata = _expectedMetadata ?? throw new InvalidOperationException(
            "The Guardian managed-entry metadata is unavailable.");
        var brokerIdentity = _brokerIdentity ?? throw new InvalidOperationException(
            "The exact Broker identity is unavailable.");

        WindowsSameLogonNamedPipeServer? server = null;
        WindowsGuardianCleanLaunchCandidateV1? candidate = null;
        SafeProcessHandle? exactGuardianHandle = null;
        BrokerGuardianCleanLaunchAuthorityV1? launchAuthority = null;
        WindowsConnectedClientPeerTrustPlatform? platform = null;
        PendingPipePeerVerification? pendingVerification = null;
        AuthenticatedPipePeerConnection? authenticatedConnection = null;
        byte[]? challenge = null;
        byte[]? readyPayload = null;
        Exception? failure = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var endpointName = CreateEndpointName();
            var connectionNonce = CreateConnectionNonce();
            challenge = RandomNumberGenerator.GetBytes(
                GuardianManagedEntryProofProtocolV1.ChallengeBytes);

            // The protected first-instance server must exist before the clean launcher
            // can resume any Guardian instruction.
            server = WindowsSameLogonNamedPipeServer.Create(endpointName);
            cancellationToken.ThrowIfCancellationRequested();
            candidate = launcher.Launch(endpointName, connectionNonce, challenge);
            var guardianIdentity = candidate.InitialIdentity;
            exactGuardianHandle = candidate.DuplicateExactProcessHandle();
            launchAuthority = candidate.CreateManagedEntryAuthority(
                expectedMetadata,
                challenge);
            var processCompletion = launchAuthority.ProcessCompletion;
            candidate.Dispose();
            candidate = null;

            var acceptingServer = server;
            await AwaitStageOrProcessAsync(
                    token => acceptingServer.WaitForConnectionAsync(token),
                    processCompletion,
                    cancellationToken,
                    ReleaseBootstrapConnectionTimeout,
                    "guardian-admission-connect-timeout",
                    "The clean-launched Guardian did not connect to its protected endpoint.")
                .ConfigureAwait(false);

            var peerBindingHandle = exactGuardianHandle;
            platform = ReleaseBinding.TakeConnectedGuardianClient(
                acceptingServer,
                peerBindingHandle);
            server = null;
            peerBindingHandle.Dispose();
            exactGuardianHandle = null;

            var brokerHello = new BrokerPeerHello(
                BrokerPeerHelloProtocol.ProtocolVersion,
                BrokerPeerRole.Broker,
                brokerIdentity.ProcessId,
                brokerIdentity.KernelSessionId,
                brokerIdentity.CreationTimeUtc,
                connectionNonce,
                brokerRelease.ReleaseId,
                brokerRelease.ManifestSha256);
            var brokerHelloPlatform = platform;
            await AwaitStageOrProcessAsync(
                    token => brokerHelloPlatform
                        .WriteBrokerHelloBeforePeerAuthenticationAsync(brokerHello, token)
                        .AsTask(),
                    processCompletion,
                    cancellationToken,
                    StageTimeout,
                    "guardian-admission-broker-hello-timeout",
                    "The exact-bound Broker hello write did not complete.")
                .ConfigureAwait(false);

            var expectation = new BrokerPeerExpectation(
                guardianIdentity.Token,
                guardianIdentity.AppModel,
                guardianRelease,
                connectionNonce,
                guardianIdentity.ProcessId,
                guardianIdentity.CreationTimeUtc);
            var guardianVerification = _verifier.BeginVerification(
                brokerHelloPlatform,
                NamedPipePeerKind.Client,
                expectation);
            pendingVerification = guardianVerification;
            platform = null;
            authenticatedConnection = await AwaitStageOrProcessAsync(
                    token => guardianVerification.CompleteConnectionAsync(token).AsTask(),
                    processCompletion,
                    cancellationToken,
                    StageTimeout,
                    "guardian-admission-guardian-hello-timeout",
                    "The clean-launched Guardian hello was not authenticated in time.",
                    lateConnection => DisposeAsync(lateConnection))
                .ConfigureAwait(false);
            await guardianVerification.DisposeAsync().ConfigureAwait(false);
            pendingVerification = null;

            var challengeBytes = challenge;
            var ready = new GuardianBrokerAdmissionReadyV1(
                connectionNonce,
                GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(challengeBytes),
                brokerIdentity.ProcessId,
                guardianIdentity.ProcessId,
                brokerRelease.ReleaseId,
                brokerRelease.ManifestSha256);
            readyPayload = GuardianBrokerAdmissionProtocolV1.SerializeReady(ready);
            CryptographicOperations.ZeroMemory(challengeBytes);
            challenge = null;
            var readyBytes = readyPayload;
            var managedEntryConnection = authenticatedConnection;
            await AwaitStageOrProcessAsync(
                    token => managedEntryConnection
                        .WriteMessageAsync(readyBytes, token)
                        .AsTask(),
                    processCompletion,
                    cancellationToken,
                    StageTimeout,
                    "guardian-admission-ready-timeout",
                    "The authenticated managed-entry ready frame was not delivered in time.")
                .ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(readyBytes);
            readyPayload = null;

            var connectionForVerification = managedEntryConnection;
            var authorityForVerification = launchAuthority;
            return await AwaitStageOrProcessAsync(
                    token =>
                    {
                        var verification = VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            connectionForVerification,
                            authorityForVerification,
                            token);
                        authenticatedConnection = null;
                        launchAuthority = null;
                        return verification.AsTask();
                    },
                    processCompletion,
                    cancellationToken,
                    StageTimeout,
                    "guardian-admission-receipt-timeout",
                    "The Guardian managed-entry receipt was not verified in time.",
                    lateConnection => DisposeAsync(lateConnection),
                    stageOwnsProcessFailureArbitration: true)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = IsExactProcessFailure(exception)
                ? exception
                : PromoteExactProcessFailure(
                    launchAuthority?.ProcessCompletion,
                    exception);
        }
        finally
        {
            if (readyPayload is not null)
            {
                CryptographicOperations.ZeroMemory(readyPayload);
            }

            if (challenge is not null)
            {
                CryptographicOperations.ZeroMemory(challenge);
            }
        }

        if (failure is not null &&
            !IsExactProcessFailure(failure) &&
            launchAuthority?.ProcessCompletion.IsCompleted == true)
        {
            failure = PromoteExactProcessFailure(
                launchAuthority.ProcessCompletion,
                failure);
        }

        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            await StopLaunchAsync(launchAuthority).ConfigureAwait(false));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            await DisposeAsync(authenticatedConnection).ConfigureAwait(false));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            await DisposeAsync(pendingVerification).ConfigureAwait(false));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            Dispose(platform));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            Dispose(exactGuardianHandle));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            Dispose(candidate));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            Dispose(server));

        ExceptionDispatchInfo.Capture(failure ?? Failure(
            "guardian-admission-failed",
            "The production Guardian admission failed without an exception.")).Throw();
        throw new InvalidOperationException();
    }

    private static async Task AwaitStageOrProcessAsync(
        Func<CancellationToken, Task> startStage,
        Task<BrokerGuardianProcessExitV1> processCompletion,
        CancellationToken cancellationToken,
        TimeSpan timeout,
        string timeoutCode,
        string timeoutMessage)
    {
        await AwaitStageOrProcessAsync(
                async token =>
                {
                    await startStage(token).ConfigureAwait(false);
                    return true;
                },
                processCompletion,
                cancellationToken,
                timeout,
                timeoutCode,
                timeoutMessage)
            .ConfigureAwait(false);
    }

    private static async Task<T> AwaitStageOrProcessAsync<T>(
        Func<CancellationToken, Task<T>> startStage,
        Task<BrokerGuardianProcessExitV1> processCompletion,
        CancellationToken cancellationToken,
        TimeSpan timeout,
        string timeoutCode,
        string timeoutMessage,
        Func<T, Task<Exception?>>? lateResultCleanup = null,
        bool stageOwnsProcessFailureArbitration = false)
    {
        ArgumentNullException.ThrowIfNull(startStage);
        ArgumentNullException.ThrowIfNull(processCompletion);
        ThrowIfProcessCompleted(processCompletion);
        cancellationToken.ThrowIfCancellationRequested();
        var stageCancellation = new CancellationTokenSource();
        var stageToken = stageCancellation.Token;
        var cancellationTransferredToQuarantine = false;
        try
        {
            Task<T> stageTask;
            try
            {
                stageTask = startStage(stageToken) ?? throw Failure(
                    "guardian-admission-stage-invalid",
                    "A production Guardian admission stage returned no task.");
            }
            catch (Exception exception)
            {
                throw PromoteExactProcessFailure(processCompletion, exception);
            }

            var callerCancellationSignal = cancellationToken.CanBeCanceled
                ? Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                : Task.Delay(Timeout.InfiniteTimeSpan);
            var timeoutSignal = Task.Delay(timeout);
            var winner = await Task.WhenAny(
                    stageTask,
                    processCompletion,
                    callerCancellationSignal,
                    timeoutSignal)
                .ConfigureAwait(false);
            if (ReferenceEquals(winner, processCompletion))
            {
                var processFailure = ReadProcessFailure(processCompletion);
                var cancellationFailure = CancelAndCapture(stageCancellation);
                var drain = await DrainStageFailureAsync(
                        stageTask,
                        lateResultCleanup,
                        stageCancellation)
                    .ConfigureAwait(false);
                cancellationTransferredToQuarantine = drain.CancellationTransferred;
                processFailure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    processFailure,
                    drain.Failure,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey)!;
                processFailure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    processFailure,
                    cancellationFailure)!;
                ExceptionDispatchInfo.Capture(processFailure).Throw();
            }

            if (ReferenceEquals(winner, callerCancellationSignal) ||
                ReferenceEquals(winner, timeoutSignal))
            {
                Exception primary = ReferenceEquals(winner, callerCancellationSignal)
                    ? new OperationCanceledException(
                        "The production Guardian admission stage was canceled.",
                        cancellationToken)
                    : Failure(timeoutCode, timeoutMessage);
                var processFailureBeforeCleanup = processCompletion.IsCompleted
                    ? ReadProcessFailure(processCompletion)
                    : null;
                if (processFailureBeforeCleanup is not null)
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        processFailureBeforeCleanup,
                        primary,
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                    primary = processFailureBeforeCleanup;
                }

                var cancellationFailure = CancelAndCapture(stageCancellation);
                var drain = await DrainStageFailureAsync(
                        stageTask,
                        lateResultCleanup,
                        stageCancellation)
                    .ConfigureAwait(false);
                cancellationTransferredToQuarantine = drain.CancellationTransferred;
                if (stageOwnsProcessFailureArbitration &&
                    drain.Failure is Exception stageFailure &&
                    IsManagedEntryProcessFailure(stageFailure))
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        stageFailure,
                        primary,
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                    BrokerControlFailureArbitration.PreserveCleanupFailure(
                        stageFailure,
                        cancellationFailure);
                    ExceptionDispatchInfo.Capture(stageFailure).Throw();
                }

                if (!IsExpectedStageCancellation(
                        drain.Failure,
                        stageToken))
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        primary,
                        drain.Failure,
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                }

                BrokerControlFailureArbitration.PreserveCleanupFailure(
                    primary,
                    cancellationFailure);
                ExceptionDispatchInfo.Capture(primary).Throw();
            }

            T result;
            try
            {
                result = await stageTask.ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                if (!stageOwnsProcessFailureArbitration &&
                    processCompletion.IsCompleted &&
                    !IsExactProcessFailure(exception))
                {
                    throw PromoteExactProcessFailure(processCompletion, exception);
                }

                throw;
            }

            Exception? boundaryFailure = processCompletion.IsCompleted
                ? ReadProcessFailure(processCompletion)
                : null;
            if (cancellationToken.IsCancellationRequested)
            {
                var cancellationFailure = new OperationCanceledException(
                    "The production Guardian admission stage was canceled after completion.",
                    cancellationToken);
                boundaryFailure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    boundaryFailure,
                    cancellationFailure,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey);
            }

            if (boundaryFailure is not null)
            {
                var cleanupFailure = await CleanupLateStageResultAsync(
                        result,
                        lateResultCleanup)
                    .ConfigureAwait(false);
                BrokerControlFailureArbitration.PreserveCleanupFailure(
                    boundaryFailure,
                    cleanupFailure);
                ExceptionDispatchInfo.Capture(boundaryFailure).Throw();
            }

            return result;
        }
        finally
        {
            if (!cancellationTransferredToQuarantine)
            {
                stageCancellation.Dispose();
            }
        }
    }

    private static Exception PromoteExactProcessFailure(
        Task<BrokerGuardianProcessExitV1>? processCompletion,
        Exception concurrentFailure)
    {
        ArgumentNullException.ThrowIfNull(concurrentFailure);
        if (processCompletion is null || !processCompletion.IsCompleted)
        {
            return concurrentFailure;
        }

        var processFailure = ReadProcessFailure(processCompletion);
        return BrokerControlFailureArbitration.PreserveSecondaryFailure(
            processFailure,
            concurrentFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey)!;
    }

    private static bool IsExactProcessFailure(Exception exception) =>
        exception is BrokerProductionHostException productionFailure &&
        productionFailure.Code is
            "guardian-admission-process-observation-failed" or
            "guardian-admission-process-exited";

    private static bool IsManagedEntryProcessFailure(Exception exception) =>
        exception is BrokerControlSessionException managedEntryFailure &&
        managedEntryFailure.Code is
            "managed-entry-process-observation-failed" or
            "managed-entry-process-exited";

    private static void ThrowIfProcessCompleted(
        Task<BrokerGuardianProcessExitV1> processCompletion)
    {
        if (processCompletion.IsCompleted)
        {
            ExceptionDispatchInfo.Capture(ReadProcessFailure(processCompletion)).Throw();
        }
    }

    private static Exception ReadProcessFailure(
        Task<BrokerGuardianProcessExitV1> processCompletion)
    {
        if (processCompletion.IsFaulted)
        {
            return Failure(
                "guardian-admission-process-observation-failed",
                "The exact Guardian process observation failed during admission.",
                processCompletion.Exception?.InnerException ?? processCompletion.Exception);
        }

        if (processCompletion.IsCanceled)
        {
            return Failure(
                "guardian-admission-process-observation-failed",
                "The exact Guardian process observation was canceled during admission.");
        }

        var exit = processCompletion.GetAwaiter().GetResult();
        return Failure(
            "guardian-admission-process-exited",
            "The exact Guardian process exited during admission with code 0x" +
            exit.ExitCode.ToString("X8") + ".");
    }

    private readonly record struct StageDrainResult(
        Exception? Failure,
        bool CancellationTransferred);

    private static async Task<StageDrainResult> DrainStageFailureAsync<T>(
        Task<T> stageTask,
        Func<T, Task<Exception?>>? lateResultCleanup,
        CancellationTokenSource stageCancellation)
    {
        try
        {
            var result = await stageTask.WaitAsync(StageDrainTimeout).ConfigureAwait(false);
            var cleanupFailure = await CleanupLateStageResultAsync(
                    result,
                    lateResultCleanup)
                .ConfigureAwait(false);
            return new StageDrainResult(cleanupFailure, CancellationTransferred: false);
        }
        catch (TimeoutException drainTimeoutFailure)
        {
            return await ResolveTimedOutStageDrainAsync(
                    stageTask,
                    lateResultCleanup,
                    stageCancellation,
                    drainTimeoutFailure)
                .ConfigureAwait(false);
        }
        catch (Exception exactStageFailure)
        {
            return new StageDrainResult(
                exactStageFailure,
                CancellationTransferred: false);
        }
    }

    private static async Task<StageDrainResult> ResolveTimedOutStageDrainAsync<T>(
        Task<T> stageTask,
        Func<T, Task<Exception?>>? lateResultCleanup,
        CancellationTokenSource stageCancellation,
        TimeoutException drainTimeoutFailure)
    {
        if (!stageTask.IsCompleted)
        {
            var quarantine = QuarantineLateStageResultAsync(
                stageTask,
                lateResultCleanup,
                stageCancellation);
            drainTimeoutFailure.Data["guardian-admission-late-stage-quarantine"] = quarantine;
            return new StageDrainResult(
                drainTimeoutFailure,
                CancellationTransferred: true);
        }

        try
        {
            var result = await stageTask.ConfigureAwait(false);
            var cleanupFailure = await CleanupLateStageResultAsync(
                    result,
                    lateResultCleanup)
                .ConfigureAwait(false);
            BrokerControlFailureArbitration.PreserveCleanupFailure(
                drainTimeoutFailure,
                cleanupFailure);
            return new StageDrainResult(
                drainTimeoutFailure,
                CancellationTransferred: false);
        }
        catch (Exception exactStageFailure)
        {
            if (!ReferenceEquals(exactStageFailure, drainTimeoutFailure))
            {
                BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    exactStageFailure,
                    drainTimeoutFailure,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey);
            }

            return new StageDrainResult(
                exactStageFailure,
                CancellationTransferred: false);
        }
    }

    private static async Task<Exception?> CleanupLateStageResultAsync<T>(
        T result,
        Func<T, Task<Exception?>>? cleanup)
    {
        if (cleanup is null)
        {
            return null;
        }

        try
        {
            return await cleanup(result).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static async Task<Exception?> QuarantineLateStageResultAsync<T>(
        Task<T> stageTask,
        Func<T, Task<Exception?>>? cleanup,
        CancellationTokenSource stageCancellation)
    {
        try
        {
            var result = await stageTask.ConfigureAwait(false);
            return await CleanupLateStageResultAsync(result, cleanup).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return exception;
        }
        finally
        {
            stageCancellation.Dispose();
        }
    }

    private static Exception? CancelAndCapture(CancellationTokenSource cancellation)
    {
        try
        {
            cancellation.Cancel();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static bool IsExpectedStageCancellation(
        Exception? failure,
        CancellationToken stageToken) =>
        failure is OperationCanceledException canceled &&
        canceled.CancellationToken == stageToken &&
        !HasAttachedArbitrationFailure(canceled);

    private static bool HasAttachedArbitrationFailure(Exception failure)
    {
        if (failure.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] is Exception ||
            failure.Data[BrokerControlFailureArbitration.ConcurrentFailureDataKey] is Exception)
        {
            return true;
        }

        if (failure is AggregateException aggregate &&
            aggregate.InnerExceptions.Any(HasAttachedArbitrationFailure))
        {
            return true;
        }

        return failure.InnerException is not null &&
            HasAttachedArbitrationFailure(failure.InnerException);
    }

    private static async Task<Exception?> StopLaunchAsync(
        BrokerGuardianCleanLaunchAuthorityV1? authority)
    {
        if (authority is null)
        {
            return null;
        }

        try
        {
            await authority.StopAsync(BrokerGuardianProcessStopRequestV1.AdmissionFailure)
                .ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static async Task<Exception?> DisposeAsync(IAsyncDisposable? disposable)
    {
        if (disposable is null)
        {
            return null;
        }

        try
        {
            await disposable.DisposeAsync().ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static Exception? Dispose(IDisposable? disposable)
    {
        if (disposable is null)
        {
            return null;
        }

        try
        {
            disposable.Dispose();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static WindowsProcessIdentity CaptureCurrentBrokerIdentity(
        BrokerProductionReleaseBindingV1 releaseBinding)
    {
        using var process = Process.GetCurrentProcess();
        using var retained = releaseBinding.OpenBrokerProcess(process.SafeHandle);
        return retained.Capture();
    }

    private static void RequireCurrentBrokerIdentity(
        WindowsProcessIdentity identity,
        VerifiedReleaseArtifactSet brokerRelease)
    {
        if (identity.ProcessId != checked((uint)Environment.ProcessId) ||
            !identity.ImageFileObjectIsExact ||
            !Equals(identity.ReleaseRoot, brokerRelease.Root) ||
            !identity.Artifacts.SequenceEqual(brokerRelease.Artifacts))
        {
            throw Failure(
                "guardian-admission-broker-identity-invalid",
                "The current Broker process is not the exact pinned Broker release.");
        }
    }

    private static string CreateEndpointName()
    {
        var entropy = RandomNumberGenerator.GetBytes(16);
        try
        {
            return GuardianBrokerBootstrapProtocolV1.EndpointPrefix +
                Convert.ToHexString(entropy).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    private static string CreateConnectionNonce()
    {
        var entropy = RandomNumberGenerator.GetBytes(32);
        try
        {
            return Convert.ToHexString(entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    private static BrokerProductionHostException ConsumedFailure() =>
        Failure(
            "guardian-admission-consumed",
            "The one-shot production Guardian admission source was already consumed.");

    private static BrokerProductionHostException Failure(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

}
