using CodexGuardian.Control;
using CodexGuardian.Trust;
using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian;

internal static class GuardianBrokerManagedBootstrapV1
{
    internal const string ManagedBootstrapArgument = "--guardian-broker-bootstrap-v1";
    internal const string BootstrapHandleArgument = "--bootstrap-handle";

    private const uint HandleFlagInherit = 0x00000001;
    private static readonly TimeSpan ReleaseBootstrapConnectionTimeout = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan StageTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan StageDrainTimeout = TimeSpan.FromSeconds(5);

    internal static bool ContainsBootstrapPrefix(IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        return arguments.Any(argument => argument.StartsWith(
            "--guardian-broker-bootstrap",
            StringComparison.OrdinalIgnoreCase));
    }

    internal static bool TryParseArguments(
        IReadOnlyList<string> arguments,
        out ulong bootstrapHandle)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        bootstrapHandle = 0;
        return arguments.Count == 3 &&
            string.Equals(arguments[0], ManagedBootstrapArgument, StringComparison.Ordinal) &&
            string.Equals(arguments[1], BootstrapHandleArgument, StringComparison.Ordinal) &&
            TryParseCanonicalHandle(arguments[2], out bootstrapHandle);
    }

    internal static async Task<GuardianBrokerBootstrapLifetime> BootstrapAsync(
        ulong bootstrapHandleValue,
        Assembly expectedEntryAssembly)
    {
        ArgumentNullException.ThrowIfNull(expectedEntryAssembly);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Guardian Broker managed bootstrap is Windows-only.");
        }

        SafeFileHandle? bootstrapReadHandle = null;
        SafeProcessHandle? inheritedBrokerHandle = null;
        VerifiedLocalReleaseLeaseV1? releaseLease = null;
        IGuardianBrokerProcessObserverV1? processObserver = null;
        WindowsNamedPipePeerTrustPlatform? platform = null;
        PendingPipePeerVerification? pendingVerification = null;
        AuthenticatedPipePeerConnection? authenticatedConnection = null;
        GuardianBrokerBootstrapV1? bootstrap = null;
        byte[]? challenge = null;
        byte[]? guardianHelloPayload = null;
        ReadOnlyMemory<byte> readyPayload = default;
        byte[]? receiptPayload = null;
        Exception? failure = null;
        try
        {
            bootstrapReadHandle = CreateFileHandle(bootstrapHandleValue);
            ClearInheritedHandleFlag(bootstrapReadHandle, "bootstrap pipe");
            var ownedBootstrapRead = bootstrapReadHandle;
            bootstrapReadHandle = null;
            using (var stream = new FileStream(
                       ownedBootstrapRead,
                       FileAccess.Read,
                       bufferSize: 1,
                       isAsync: false))
            {
                bootstrap = ReadBootstrapFrame(stream);
            }

            var parsedBootstrap = bootstrap ?? throw Failure(
                "guardian-broker-bootstrap-invalid",
                "The inherited bootstrap frame returned no parsed bootstrap authority.");

            if (parsedBootstrap.BrokerProcessHandle == bootstrapHandleValue)
            {
                throw Failure(
                    "guardian-broker-bootstrap-handle-alias",
                    "The bootstrap pipe and inherited Broker process handle unexpectedly alias.");
            }

            inheritedBrokerHandle = CreateProcessHandle(parsedBootstrap.BrokerProcessHandle);
            if (ToUnsignedHandleValue(inheritedBrokerHandle.DangerousGetHandle()) !=
                parsedBootstrap.BrokerProcessHandle)
            {
                throw Failure(
                    "guardian-broker-bootstrap-handle-mismatch",
                    "The inherited Broker process handle did not preserve its bootstrap value.");
            }

            ClearInheritedHandleFlag(inheritedBrokerHandle, "Broker process");
            challenge = parsedBootstrap.TakeManagedEntryChallenge();
            GuardianManagedEntryProofProtocolV1.ValidateChallenge(challenge);

            releaseLease = WindowsVerifiedLocalReleaseManifestFactory.OpenCurrentRelease();
            var guardianRelease = releaseLease.Manifest.GetArtifactSet(BrokerPeerRole.Guardian);
            var brokerRelease = releaseLease.Manifest.GetArtifactSet(BrokerPeerRole.Broker);
            var guardianIdentity = CaptureCurrentGuardianIdentity(releaseLease);
            RequireCurrentGuardianIdentity(guardianIdentity, guardianRelease);
            var brokerIdentity = CaptureBrokerIdentity(releaseLease, inheritedBrokerHandle);
            RequireBrokerIdentity(brokerIdentity, brokerRelease);
            processObserver = WindowsGuardianBrokerProcessObserverV1.Create(
                inheritedBrokerHandle,
                brokerIdentity.ProcessId);

            ThrowIfBrokerCompleted(processObserver.Completion);
            using var connectCancellation = new CancellationTokenSource(
                ReleaseBootstrapConnectionTimeout);
            try
            {
                platform = WindowsVerifiedLocalReleasePeerAuthorityV1
                    .ConnectToLaunchedBrokerServer(
                        releaseLease,
                        parsedBootstrap.EndpointName,
                        inheritedBrokerHandle,
                        ReleaseBootstrapConnectionTimeout,
                        connectCancellation.Token);
            }
            catch (Exception exception)
            {
                throw PromoteExactBrokerFailure(processObserver.Completion, exception);
            }

            ThrowIfBrokerCompleted(processObserver.Completion);
            var expectation = new BrokerPeerExpectation(
                brokerIdentity.Token,
                brokerIdentity.AppModel,
                brokerRelease,
                parsedBootstrap.ConnectionNonce,
                brokerIdentity.ProcessId,
                brokerIdentity.CreationTimeUtc);
            var verifier = new WindowsNamedPipePeerVerifier();
            pendingVerification = verifier.BeginVerification(
                platform,
                NamedPipePeerKind.Server,
                expectation);
            platform = null;
            authenticatedConnection = await AwaitStageOrBrokerAsync(
                    token => pendingVerification.CompleteConnectionAsync(token).AsTask(),
                    processObserver.Completion,
                    CancellationToken.None,
                    StageTimeout,
                    "guardian-broker-hello-timeout",
                    "The exact-bound Broker hello was not authenticated in time.",
                    lateResultCleanup: lateConnection => DisposeAsync(lateConnection))
                .ConfigureAwait(false);
            await pendingVerification.DisposeAsync().ConfigureAwait(false);
            pendingVerification = null;

            var guardianHello = new BrokerPeerHello(
                BrokerPeerHelloProtocol.ProtocolVersion,
                BrokerPeerRole.Guardian,
                guardianIdentity.ProcessId,
                guardianIdentity.KernelSessionId,
                guardianIdentity.CreationTimeUtc,
                parsedBootstrap.ConnectionNonce,
                guardianRelease.ReleaseId,
                guardianRelease.ManifestSha256);
            guardianHelloPayload = BrokerPeerHelloProtocol.Serialize(guardianHello);
            await AwaitStageOrBrokerAsync(
                    token => authenticatedConnection
                        .WriteMessageAsync(guardianHelloPayload, token)
                        .AsTask(),
                    processObserver.Completion,
                    CancellationToken.None,
                    StageTimeout,
                    "guardian-hello-write-timeout",
                    "The authenticated Guardian hello was not delivered in time.")
                .ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(guardianHelloPayload);
            guardianHelloPayload = null;

            readyPayload = await AwaitStageOrBrokerAsync(
                    token => authenticatedConnection
                        .ReadMessageAsync(
                            GuardianBrokerAdmissionProtocolV1.MaximumReadyBytes,
                            token)
                        .AsTask(),
                    processObserver.Completion,
                    CancellationToken.None,
                    StageTimeout,
                    "guardian-broker-ready-timeout",
                    "The Broker managed-entry ready frame was not received in time.",
                    lateResultCleanup: ClearLateReadyPayloadAsync)
                .ConfigureAwait(false);
            if (!GuardianBrokerAdmissionProtocolV1.TryParseReady(
                    readyPayload,
                    out var ready,
                    out var readyReason) ||
                ready is null)
            {
                throw Failure(
                    "guardian-broker-ready-invalid",
                    "The Broker managed-entry ready frame was rejected: " + readyReason + ".");
            }

            ValidateReady(
                ready,
                parsedBootstrap.ConnectionNonce,
                GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(challenge),
                brokerIdentity.ProcessId,
                guardianIdentity.ProcessId,
                brokerRelease.ReleaseId,
                brokerRelease.ManifestSha256);
            ZeroMemory(readyPayload);
            readyPayload = default;

            var receipt = GuardianManagedEntryProofV1.CreateCurrent(
                challenge,
                expectedEntryAssembly);
            receiptPayload = GuardianManagedEntryProofProtocolV1.Serialize(receipt);
            await AwaitStageOrBrokerAsync(
                    token => authenticatedConnection
                        .WriteMessageAsync(receiptPayload, token)
                        .AsTask(),
                    processObserver.Completion,
                    CancellationToken.None,
                    StageTimeout,
                    "guardian-managed-entry-receipt-timeout",
                    "The Guardian managed-entry receipt was not delivered in time.")
                .ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(receiptPayload);
            receiptPayload = null;
            ThrowIfBrokerCompleted(processObserver.Completion);

            var lifetime = new GuardianBrokerBootstrapLifetime(
                releaseLease,
                authenticatedConnection,
                inheritedBrokerHandle,
                processObserver);
            releaseLease = null;
            authenticatedConnection = null;
            inheritedBrokerHandle = null;
            processObserver = null;
            return lifetime;
        }
        catch (Exception exception)
        {
            failure = PromoteExactBrokerFailure(processObserver?.Completion, exception);
        }
        finally
        {
            if (challenge is not null)
            {
                CryptographicOperations.ZeroMemory(challenge);
            }

            if (guardianHelloPayload is not null)
            {
                CryptographicOperations.ZeroMemory(guardianHelloPayload);
            }

            if (!readyPayload.IsEmpty)
            {
                ZeroMemory(readyPayload);
            }

            if (receiptPayload is not null)
            {
                CryptographicOperations.ZeroMemory(receiptPayload);
            }

            bootstrap?.Dispose();
        }

        failure = PreserveCleanupFailure(
            failure,
            await DisposeAsync(pendingVerification).ConfigureAwait(false));
        failure = PreserveCleanupFailure(failure, Dispose(platform));
        failure = PreserveCleanupFailure(
            failure,
            await DisposeAsync(authenticatedConnection).ConfigureAwait(false));
        failure = PromoteExactBrokerFailure(processObserver?.Completion, failure);
        failure = PreserveCleanupFailure(
            failure,
            await DisposeAsync(processObserver).ConfigureAwait(false));
        failure = PreserveCleanupFailure(failure, Dispose(inheritedBrokerHandle));
        failure = PreserveCleanupFailure(failure, Dispose(releaseLease));
        failure = PreserveCleanupFailure(failure, Dispose(bootstrapReadHandle));
        ExceptionDispatchInfo.Capture(failure ?? Failure(
            "guardian-broker-bootstrap-failed",
            "The Guardian Broker managed bootstrap failed without an exception.")).Throw();
        throw new InvalidOperationException();
    }

    internal static GuardianBrokerBootstrapV1 ReadBootstrapFrame(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("The bootstrap stream is not readable.", nameof(stream));
        }

        Span<byte> prefix = stackalloc byte[GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes];
        if (!ReadExact(stream, prefix))
        {
            throw Failure(
                "guardian-broker-bootstrap-truncated",
                "The inherited bootstrap pipe ended before its length prefix.");
        }

        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        if (payloadLength is 0 or > GuardianBrokerBootstrapProtocolV1.MaximumPayloadBytes)
        {
            throw Failure(
                "guardian-broker-bootstrap-size",
                "The inherited bootstrap frame declared an invalid bounded size.");
        }

        var frame = new byte[checked(
            GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes + (int)payloadLength)];
        try
        {
            prefix.CopyTo(frame);
            if (!ReadExact(
                    stream,
                    frame.AsSpan(GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes)))
            {
                throw Failure(
                    "guardian-broker-bootstrap-truncated",
                    "The inherited bootstrap pipe ended before its exact payload completed.");
            }

            if (stream.ReadByte() != -1)
            {
                throw Failure(
                    "guardian-broker-bootstrap-trailing-data",
                    "The inherited bootstrap pipe contained data after its single frame.");
            }

            if (!GuardianBrokerBootstrapProtocolV1.TryParseFrame(
                    frame,
                    out var bootstrap,
                    out var reason) ||
                bootstrap is null)
            {
                throw Failure(
                    "guardian-broker-bootstrap-invalid",
                    "The inherited bootstrap frame was rejected: " + reason + ".");
            }

            return bootstrap;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
            CryptographicOperations.ZeroMemory(prefix);
        }
    }

    internal static void ValidateReady(
        GuardianBrokerAdmissionReadyV1 ready,
        string expectedConnectionNonce,
        string expectedChallengeSha256,
        uint expectedBrokerProcessId,
        uint expectedGuardianProcessId,
        string expectedReleaseId,
        string expectedManifestSha256)
    {
        ArgumentNullException.ThrowIfNull(ready);
        if (!string.Equals(
                ready.ConnectionNonce,
                expectedConnectionNonce,
                StringComparison.Ordinal) ||
            !string.Equals(
                ready.ChallengeSha256,
                expectedChallengeSha256,
                StringComparison.Ordinal) ||
            ready.BrokerProcessId != expectedBrokerProcessId ||
            ready.GuardianProcessId != expectedGuardianProcessId ||
            !string.Equals(ready.ReleaseId, expectedReleaseId, StringComparison.Ordinal) ||
            !string.Equals(
                ready.ManifestSha256,
                expectedManifestSha256,
                StringComparison.Ordinal))
        {
            throw Failure(
                "guardian-broker-ready-mismatch",
                "The Broker ready frame did not match the exact launch, challenge, or release.");
        }
    }

    private static async Task AwaitStageOrBrokerAsync(
        Func<CancellationToken, Task> startStage,
        Task<GuardianBrokerProcessExitV1> processCompletion,
        CancellationToken cancellationToken,
        TimeSpan timeout,
        string timeoutCode,
        string timeoutMessage)
    {
        await AwaitStageOrBrokerAsync(
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

    internal static async Task<T> AwaitStageOrBrokerAsync<T>(
        Func<CancellationToken, Task<T>> startStage,
        Task<GuardianBrokerProcessExitV1> processCompletion,
        CancellationToken cancellationToken,
        TimeSpan timeout,
        string timeoutCode,
        string timeoutMessage,
        Func<T, Task<Exception?>>? lateResultCleanup = null,
        TimeSpan? drainTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(startStage);
        ArgumentNullException.ThrowIfNull(processCompletion);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(15))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var boundedDrainTimeout = drainTimeout ?? StageDrainTimeout;
        if (boundedDrainTimeout <= TimeSpan.Zero ||
            boundedDrainTimeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(drainTimeout));
        }

        ThrowIfBrokerCompleted(processCompletion);
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
                    "guardian-broker-stage-invalid",
                    "A Guardian Broker bootstrap stage returned no task.");
            }
            catch (Exception exception)
            {
                throw PromoteExactBrokerFailure(processCompletion, exception);
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
                var processFailure = ReadBrokerProcessFailure(processCompletion);
                var cancellationFailure = CancelAndCapture(stageCancellation);
                var drain = await DrainStageFailureAsync(
                        stageTask,
                        lateResultCleanup,
                        stageCancellation,
                        boundedDrainTimeout)
                    .ConfigureAwait(false);
                cancellationTransferredToQuarantine = drain.CancellationTransferred;
                processFailure = WithConcurrentFailure(processFailure, drain.Failure);
                processFailure = WithConcurrentFailure(processFailure, cancellationFailure);
                ExceptionDispatchInfo.Capture(processFailure).Throw();
            }

            if (ReferenceEquals(winner, callerCancellationSignal) ||
                ReferenceEquals(winner, timeoutSignal))
            {
                Exception primary = ReferenceEquals(winner, callerCancellationSignal)
                    ? new OperationCanceledException(
                        "The Guardian Broker bootstrap stage was canceled.",
                        cancellationToken)
                    : Failure(timeoutCode, timeoutMessage);
                if (processCompletion.IsCompleted)
                {
                    primary = WithConcurrentFailure(
                        ReadBrokerProcessFailure(processCompletion),
                        primary);
                }

                var cancellationFailure = CancelAndCapture(stageCancellation);
                var drain = await DrainStageFailureAsync(
                        stageTask,
                        lateResultCleanup,
                        stageCancellation,
                        boundedDrainTimeout)
                    .ConfigureAwait(false);
                cancellationTransferredToQuarantine = drain.CancellationTransferred;
                if (!IsExpectedStageCancellation(drain.Failure, stageToken))
                {
                    primary = PreserveConcurrentFailure(primary, drain.Failure);
                }

                primary = PreserveCleanupFailure(primary, cancellationFailure);
                ExceptionDispatchInfo.Capture(primary).Throw();
            }

            T result;
            try
            {
                result = await stageTask.ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                if (processCompletion.IsCompleted)
                {
                    throw PromoteExactBrokerFailure(processCompletion, exception);
                }

                throw;
            }

            Exception? boundaryFailure = processCompletion.IsCompleted
                ? ReadBrokerProcessFailure(processCompletion)
                : null;
            if (cancellationToken.IsCancellationRequested)
            {
                var cancellationFailure = new OperationCanceledException(
                    "The Guardian Broker bootstrap stage was canceled after completion.",
                    cancellationToken);
                boundaryFailure = boundaryFailure is GuardianBrokerBootstrapFailureV1 processFailure
                    ? WithConcurrentFailure(processFailure, cancellationFailure)
                    : cancellationFailure;
            }

            if (boundaryFailure is not null)
            {
                var cleanupFailure = await CleanupLateStageResultAsync(
                        result,
                        lateResultCleanup)
                    .ConfigureAwait(false);
                boundaryFailure = PreserveCleanupFailure(boundaryFailure, cleanupFailure);
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

    private readonly record struct StageDrainResult(
        Exception? Failure,
        bool CancellationTransferred);

    private static async Task<StageDrainResult> DrainStageFailureAsync<T>(
        Task<T> stageTask,
        Func<T, Task<Exception?>>? lateResultCleanup,
        CancellationTokenSource stageCancellation,
        TimeSpan drainTimeout)
    {
        try
        {
            var result = await stageTask.WaitAsync(drainTimeout).ConfigureAwait(false);
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
            drainTimeoutFailure.Data["GuardianBrokerBootstrapLateStageQuarantine"] = quarantine;
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
            return new StageDrainResult(
                PreserveCleanupFailure(drainTimeoutFailure, cleanupFailure),
                CancellationTransferred: false);
        }
        catch (Exception exactStageFailure)
        {
            var failure = ReferenceEquals(exactStageFailure, drainTimeoutFailure)
                ? exactStageFailure
                : PreserveConcurrentFailure(
                    exactStageFailure,
                    drainTimeoutFailure);
            return new StageDrainResult(
                failure,
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

    private static Task<Exception?> ClearLateReadyPayloadAsync(ReadOnlyMemory<byte> payload)
    {
        ZeroMemory(payload);
        return Task.FromResult<Exception?>(null);
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
        !HasAttachedBootstrapFailure(canceled);

    private static bool HasAttachedBootstrapFailure(Exception failure)
    {
        if (failure.Data["GuardianBrokerBootstrapCleanupFailure"] is Exception ||
            failure.Data["GuardianBrokerBootstrapConcurrentFailure"] is Exception)
        {
            return true;
        }

        if (failure is GuardianBrokerBootstrapFailureV1 bootstrapFailure &&
            bootstrapFailure.ConcurrentFailure is not null)
        {
            return true;
        }

        if (failure is AggregateException aggregate &&
            aggregate.InnerExceptions.Any(HasAttachedBootstrapFailure))
        {
            return true;
        }

        return failure.InnerException is not null &&
            HasAttachedBootstrapFailure(failure.InnerException);
    }

    private static WindowsProcessIdentity CaptureCurrentGuardianIdentity(
        VerifiedLocalReleaseLeaseV1 releaseLease)
    {
        using var process = Process.GetCurrentProcess();
        using var retained = WindowsVerifiedLocalReleasePeerAuthorityV1.OpenRetainedProcess(
            releaseLease,
            BrokerPeerRole.Guardian,
            process.SafeHandle);
        return retained.Capture();
    }

    private static WindowsProcessIdentity CaptureBrokerIdentity(
        VerifiedLocalReleaseLeaseV1 releaseLease,
        SafeProcessHandle exactBrokerHandle)
    {
        using var retained = WindowsVerifiedLocalReleasePeerAuthorityV1.OpenRetainedProcess(
            releaseLease,
            BrokerPeerRole.Broker,
            exactBrokerHandle);
        return retained.Capture();
    }

    private static void RequireCurrentGuardianIdentity(
        WindowsProcessIdentity identity,
        VerifiedReleaseArtifactSet release)
    {
        if (identity.ProcessId != checked((uint)Environment.ProcessId) ||
            !identity.ImageFileObjectIsExact ||
            !Equals(identity.ReleaseRoot, release.Root) ||
            !identity.Artifacts.SequenceEqual(release.Artifacts))
        {
            throw Failure(
                "guardian-current-release-invalid",
                "The current Guardian process is not the exact pinned Guardian release.");
        }
    }

    private static void RequireBrokerIdentity(
        WindowsProcessIdentity identity,
        VerifiedReleaseArtifactSet release)
    {
        if (identity.ProcessId == 0 ||
            !identity.ImageFileObjectIsExact ||
            !Equals(identity.ReleaseRoot, release.Root) ||
            !identity.Artifacts.SequenceEqual(release.Artifacts))
        {
            throw Failure(
                "guardian-broker-release-invalid",
                "The inherited Broker process is not the exact pinned Broker release.");
        }
    }

    private static SafeFileHandle CreateFileHandle(ulong value)
    {
        var handle = new SafeFileHandle(ToIntPtr(value), ownsHandle: true);
        if (handle.IsInvalid || handle.IsClosed)
        {
            handle.Dispose();
            throw Failure(
                "guardian-broker-bootstrap-handle-invalid",
                "The canonical bootstrap handle is not a valid inherited file handle.");
        }

        return handle;
    }

    private static SafeProcessHandle CreateProcessHandle(ulong value)
    {
        var handle = new SafeProcessHandle(ToIntPtr(value), ownsHandle: true);
        if (handle.IsInvalid || handle.IsClosed)
        {
            handle.Dispose();
            throw Failure(
                "guardian-broker-process-handle-invalid",
                "The bootstrap Broker handle is not a valid inherited process handle.");
        }

        return handle;
    }

    private static void ClearInheritedHandleFlag(SafeHandle handle, string description)
    {
        if (!GetHandleInformation(handle.DangerousGetHandle(), out var beforeFlags))
        {
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to inspect the inherited " + description + " handle.");
        }

        if ((beforeFlags & HandleFlagInherit) == 0)
        {
            throw Failure(
                "guardian-broker-handle-not-inherited",
                "The " + description + " handle was not marked as inherited.");
        }

        if (!SetHandleInformation(
                handle.DangerousGetHandle(),
                HandleFlagInherit,
                flags: 0))
        {
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to clear inheritance on the " + description + " handle.");
        }

        if (!GetHandleInformation(handle.DangerousGetHandle(), out var afterFlags) ||
            (afterFlags & HandleFlagInherit) != 0)
        {
            throw Failure(
                "guardian-broker-handle-inheritance-retained",
                "The " + description + " handle remained inheritable.");
        }
    }

    private static void ThrowIfBrokerCompleted(
        Task<GuardianBrokerProcessExitV1> processCompletion)
    {
        if (processCompletion.IsCompleted)
        {
            ExceptionDispatchInfo.Capture(ReadBrokerProcessFailure(processCompletion)).Throw();
        }
    }

    private static Exception PromoteExactBrokerFailure(
        Task<GuardianBrokerProcessExitV1>? processCompletion,
        Exception concurrentFailure)
    {
        ArgumentNullException.ThrowIfNull(concurrentFailure);
        if (processCompletion is null || !processCompletion.IsCompleted)
        {
            return concurrentFailure;
        }

        return WithConcurrentFailure(
            ReadBrokerProcessFailure(processCompletion),
            concurrentFailure);
    }

    private static GuardianBrokerBootstrapFailureV1 ReadBrokerProcessFailure(
        Task<GuardianBrokerProcessExitV1> processCompletion)
    {
        if (processCompletion.IsFaulted)
        {
            return Failure(
                "guardian-broker-process-observation-failed",
                "The exact Broker process observer failed during bootstrap.",
                processCompletion.Exception?.InnerException ?? processCompletion.Exception);
        }

        if (processCompletion.IsCanceled)
        {
            return Failure(
                "guardian-broker-process-observation-failed",
                "The exact Broker process observer was canceled during bootstrap.");
        }

        var exit = processCompletion.GetAwaiter().GetResult();
        return Failure(
            "guardian-broker-process-exited",
            "The exact Broker process exited during bootstrap with code 0x" +
            exit.ExitCode.ToString("X8") + ".");
    }

    private static GuardianBrokerBootstrapFailureV1 WithConcurrentFailure(
        GuardianBrokerBootstrapFailureV1 primary,
        Exception? concurrentFailure) =>
        concurrentFailure is null
            ? primary
            : new GuardianBrokerBootstrapFailureV1(
                primary.Code,
                primary.Message,
                primary.InnerException,
                primary.ConcurrentFailure is null
                    ? concurrentFailure
                    : new AggregateException(primary.ConcurrentFailure, concurrentFailure));

    private static Exception PreserveConcurrentFailure(
        Exception primary,
        Exception? concurrentFailure)
    {
        if (concurrentFailure is null)
        {
            return primary;
        }

        if (primary is GuardianBrokerBootstrapFailureV1 bootstrapFailure)
        {
            return WithConcurrentFailure(bootstrapFailure, concurrentFailure);
        }

        const string concurrentKey = "GuardianBrokerBootstrapConcurrentFailure";
        primary.Data[concurrentKey] = primary.Data[concurrentKey] is Exception existing
            ? new AggregateException(existing, concurrentFailure)
            : concurrentFailure;
        return primary;
    }

    private static Exception PreserveCleanupFailure(
        Exception? primary,
        Exception? cleanupFailure)
    {
        if (primary is null)
        {
            return cleanupFailure ?? Failure(
                "guardian-broker-bootstrap-failed",
                "The Guardian Broker bootstrap failed without a primary exception.");
        }

        if (cleanupFailure is null)
        {
            return primary;
        }

        const string cleanupKey = "GuardianBrokerBootstrapCleanupFailure";
        primary.Data[cleanupKey] = primary.Data[cleanupKey] is Exception existing
            ? new AggregateException(existing, cleanupFailure)
            : cleanupFailure;
        return primary;
    }

    private static async Task<Exception?> DisposeAsync(IAsyncDisposable? value)
    {
        if (value is null)
        {
            return null;
        }

        try
        {
            await value.DisposeAsync().ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static Exception? Dispose(IDisposable? value)
    {
        if (value is null)
        {
            return null;
        }

        try
        {
            value.Dispose();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static bool ReadExact(Stream stream, Span<byte> destination)
    {
        var total = 0;
        while (total < destination.Length)
        {
            var read = stream.Read(destination[total..]);
            if (read == 0)
            {
                return false;
            }

            total = checked(total + read);
        }

        return true;
    }

    private static bool TryParseCanonicalHandle(string value, out ulong handle)
    {
        handle = 0;
        return !string.IsNullOrEmpty(value) &&
            value.Length <= 20 &&
            value[0] != '0' &&
            value.All(char.IsAsciiDigit) &&
            ulong.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out handle) &&
            handle <= (ulong)nuint.MaxValue;
    }

    private static IntPtr ToIntPtr(ulong value) =>
        IntPtr.Size == sizeof(long)
            ? new IntPtr(unchecked((long)value))
            : new IntPtr(unchecked((int)(uint)value));

    private static ulong ToUnsignedHandleValue(IntPtr value) =>
        IntPtr.Size == sizeof(long)
            ? unchecked((ulong)value.ToInt64())
            : unchecked((uint)value.ToInt32());

    private static void ZeroMemory(ReadOnlyMemory<byte> memory)
    {
        if (memory.IsEmpty)
        {
            return;
        }

        if (!MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment) ||
            segment.Array is null)
        {
            throw Failure(
                "guardian-broker-payload-owner-invalid",
                "The authenticated bootstrap payload is not backed by an owned clearable array.");
        }

        CryptographicOperations.ZeroMemory(
            segment.Array.AsSpan(segment.Offset, segment.Count));
    }

    private static GuardianBrokerBootstrapFailureV1 Failure(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetHandleInformation(
        IntPtr handle,
        out uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        IntPtr handle,
        uint mask,
        uint flags);
}
