using CodexGuardian.Broker;
using CodexGuardian.Trust;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

internal static class WindowsGuardianProductionAdmissionOfflineTests
{
    private static readonly TimeSpan CaseTimeout = TimeSpan.FromSeconds(10);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "Production Guardian admission consumes its only attempt after failure",
            TestFailureConsumesAdmissionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Concurrent admission and disposal cancel and drain one operation",
            TestConcurrentDisposeAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Disposal before admission prevents every production side effect",
            TestDisposeBeforeAcceptAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "A missing admission authority fails closed and remains consumed",
            TestNullAdmissionResultAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "One-shot production admission classifies every failure as terminal",
            TestTerminalClassificationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Admission expected-cancellation classification rejects attached arbitration failures",
            TestExpectedStageCancellationAttachmentsAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Admission preserves a stage-owned pre-abort process failure over caller cancellation",
            TestStageOwnedProcessFailurePromotionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Admission resolves the exact stage at the drain-timeout completion boundary",
            TestTimedOutStageCompletionBoundaryAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Production admission source preserves bootstrap budget and handshake ordering",
            TestProductionSourceBoundaryAsync,
            assert).ConfigureAwait(false);
    }

    private static async Task TestFailureConsumesAdmissionAsync()
    {
        using var release = ReleaseBindingFixture.Create();
        var invocationCount = 0;
        var primary = new InvalidOperationException("synthetic-admission-failure");
        await using var admission = new WindowsGuardianProductionAdmissionV1(
            release.Binding,
            new WindowsNamedPipePeerVerifier(),
            _ =>
            {
                Interlocked.Increment(ref invocationCount);
                return ValueTask.FromException<VerifiedGuardianManagedEntryConnectionV1>(primary);
            });

        var observed = await ExpectAsync<InvalidOperationException>(
            () => admission.AcceptAsync(CancellationToken.None).AsTask()).ConfigureAwait(false);
        Ensure(ReferenceEquals(observed, primary), "the admission source replaced its primary failure");
        var consumed = await ExpectAsync<BrokerProductionHostException>(
            () => admission.AcceptAsync(CancellationToken.None).AsTask()).ConfigureAwait(false);
        Ensure(
            consumed.Code == "guardian-admission-consumed",
            "a failed one-shot admission reopened its launcher opportunity");
        Ensure(invocationCount == 1, "the one-shot admission invoked its core more than once");
    }

    private static async Task TestConcurrentDisposeAsync()
    {
        using var release = ReleaseBindingFixture.Create();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var invocationCount = 0;
        var admission = new WindowsGuardianProductionAdmissionV1(
            release.Binding,
            new WindowsNamedPipePeerVerifier(),
            async token =>
            {
                Interlocked.Increment(ref invocationCount);
                entered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token).ConfigureAwait(false);
                throw new InvalidOperationException("unreachable-admission-continuation");
            });

        var accept = admission.AcceptAsync(CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        var dispose = admission.DisposeAsync().AsTask();
        await ExpectAsync<OperationCanceledException>(
            async () => await accept.WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);
        await dispose.WaitAsync(CaseTimeout).ConfigureAwait(false);
        await admission.DisposeAsync().AsTask().WaitAsync(CaseTimeout).ConfigureAwait(false);
        Ensure(invocationCount == 1, "concurrent disposal restarted the admission operation");
        var consumed = await ExpectAsync<BrokerProductionHostException>(
            () => admission.AcceptAsync(CancellationToken.None).AsTask()).ConfigureAwait(false);
        Ensure(
            consumed.Code == "guardian-admission-consumed",
            "disposed admission did not remain terminal");
    }

    private static async Task TestDisposeBeforeAcceptAsync()
    {
        using var release = ReleaseBindingFixture.Create();
        var invocationCount = 0;
        var admission = new WindowsGuardianProductionAdmissionV1(
            release.Binding,
            new WindowsNamedPipePeerVerifier(),
            _ =>
            {
                Interlocked.Increment(ref invocationCount);
                return ValueTask.FromException<VerifiedGuardianManagedEntryConnectionV1>(
                    new InvalidOperationException("unexpected-admission-side-effect"));
            });

        await admission.DisposeAsync().ConfigureAwait(false);
        var consumed = await ExpectAsync<BrokerProductionHostException>(
            () => admission.AcceptAsync(CancellationToken.None).AsTask()).ConfigureAwait(false);
        Ensure(
            consumed.Code == "guardian-admission-consumed" && invocationCount == 0,
            "dispose-before-accept allowed a production side effect");
    }

    private static async Task TestNullAdmissionResultAsync()
    {
        using var release = ReleaseBindingFixture.Create();
        var invocationCount = 0;
        await using var admission = new WindowsGuardianProductionAdmissionV1(
            release.Binding,
            new WindowsNamedPipePeerVerifier(),
            _ =>
            {
                Interlocked.Increment(ref invocationCount);
                return ValueTask.FromResult<VerifiedGuardianManagedEntryConnectionV1>(null!);
            });

        var invalid = await ExpectAsync<BrokerProductionHostException>(
            () => admission.AcceptAsync(CancellationToken.None).AsTask()).ConfigureAwait(false);
        Ensure(
            invalid.Code == "guardian-admission-result-invalid",
            "a missing verified connection did not fail closed");
        _ = await ExpectAsync<BrokerProductionHostException>(
            () => admission.AcceptAsync(CancellationToken.None).AsTask()).ConfigureAwait(false);
        Ensure(invocationCount == 1, "a null result reopened the one-shot admission");
    }

    private static Task TestTerminalClassificationAsync()
    {
        using var release = ReleaseBindingFixture.Create();
        var admission = new WindowsGuardianProductionAdmissionV1(
            release.Binding,
            new WindowsNamedPipePeerVerifier(),
            _ => ValueTask.FromException<VerifiedGuardianManagedEntryConnectionV1>(
                new InvalidOperationException("unused")));
        try
        {
            var failure = new InvalidOperationException("classification-fixture");
            Ensure(
                admission.ClassifyFailure(failure) ==
                    BrokerGuardianAdmissionFailureDispositionV1.Terminal &&
                admission.ClassifyConnectionFailure(failure) ==
                    BrokerGuardianConnectionFailureDispositionV1.Terminal,
                "a one-shot production source advertised a retryable failure");
            return Task.CompletedTask;
        }
        finally
        {
            admission.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    private static Task TestExpectedStageCancellationAttachmentsAsync()
    {
        var method = typeof(WindowsGuardianProductionAdmissionV1).GetMethod(
            "IsExpectedStageCancellation",
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new InvalidOperationException(
                "The production admission cancellation classifier was not found.");
        using var cancellation = new CancellationTokenSource();
        var stageToken = cancellation.Token;
        cancellation.Cancel();
        cancellation.Dispose();
        var disposedSourceRejected = false;
        try
        {
            _ = cancellation.Token;
        }
        catch (ObjectDisposedException)
        {
            disposedSourceRejected = true;
        }

        bool Invoke(Exception failure) =>
            (bool)(method.Invoke(null, new object?[] { failure, stageToken }) ?? false);

        var pureCancellation = new OperationCanceledException(
            "pure-stage-cancellation",
            stageToken);
        Ensure(
            disposedSourceRejected && Invoke(pureCancellation),
            "a pure same-token stage cancellation was not recognized");

        var cleanupFailure = new IOException("attached-stage-cleanup-failure");
        var attachedCleanup = new OperationCanceledException(
            "stage-cancellation-with-cleanup",
            stageToken);
        attachedCleanup.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] =
            cleanupFailure;
        Ensure(
            !Invoke(attachedCleanup),
            "same-token stage cancellation swallowed an attached cleanup failure");

        var concurrentFailure = new IOException("attached-stage-concurrent-failure");
        var attachedConcurrent = new OperationCanceledException(
            "stage-cancellation-with-concurrent-failure",
            stageToken);
        attachedConcurrent.Data[BrokerControlFailureArbitration.ConcurrentFailureDataKey] =
            concurrentFailure;
        Ensure(
            !Invoke(attachedConcurrent),
            "same-token stage cancellation swallowed an attached concurrent failure");

        var nestedCleanup = new IOException("nested-stage-cleanup-failure");
        var nested = new InvalidOperationException("nested-stage-failure");
        nested.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] = nestedCleanup;
        var nestedCancellation = new OperationCanceledException(
            "stage-cancellation-with-nested-cleanup",
            nested,
            stageToken);
        Ensure(
            !Invoke(nestedCancellation),
            "same-token stage cancellation swallowed nested cleanup evidence");
        return Task.CompletedTask;
    }

    private static async Task TestStageOwnedProcessFailurePromotionAsync()
    {
        var method = typeof(WindowsGuardianProductionAdmissionV1)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .Single(candidate =>
                candidate.Name == "AwaitStageOrProcessAsync" &&
                candidate.IsGenericMethodDefinition &&
                candidate.GetParameters().Length == 8)
            .MakeGenericMethod(typeof(bool));
        using var callerCancellation = new CancellationTokenSource();
        var stageEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var processCompletion = new TaskCompletionSource<BrokerGuardianProcessExitV1>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var processFailure = new BrokerControlSessionException(
            "managed-entry-process-exited",
            "synthetic pre-abort process failure");
        Func<CancellationToken, Task<bool>> stage = async stageToken =>
        {
            stageEntered.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, stageToken).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException cancellationFailure)
                when (stageToken.IsCancellationRequested)
            {
                BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    processFailure,
                    cancellationFailure,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                throw processFailure;
            }
        };

        var admissionStage = (Task<bool>)(method.Invoke(
            null,
            new object?[]
            {
                stage,
                processCompletion.Task,
                callerCancellation.Token,
                TimeSpan.FromSeconds(5),
                "guardian-admission-test-timeout",
                "The synthetic admission stage timed out.",
                null,
                true
            }) ?? throw new InvalidOperationException(
                "The production admission stage helper returned no task."));
        await stageEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        callerCancellation.Cancel();
        var observed = await ExpectAsync<BrokerControlSessionException>(
                () => admissionStage)
            .ConfigureAwait(false);
        Ensure(
            ReferenceEquals(observed, processFailure) &&
            observed.Data[BrokerControlFailureArbitration.ConcurrentFailureDataKey]
                is Exception,
            "caller cancellation displaced the stage-owned pre-abort process failure");
    }

    private static async Task TestTimedOutStageCompletionBoundaryAsync()
    {
        var cleanupCount = 0;
        var cleanupFailure = new IOException("synthetic boundary cleanup failure");
        var payload = Enumerable.Repeat((byte)0x5A, 32).ToArray();
        var timeout = new TimeoutException("synthetic admission drain timeout");
        using (var stageCancellation = new CancellationTokenSource())
        {
            var resolved = await ResolveTimedOutStageDrainAsync(
                    Task.FromResult(payload),
                    result =>
                    {
                        Interlocked.Increment(ref cleanupCount);
                        CryptographicOperations.ZeroMemory(result);
                        return Task.FromResult<Exception?>(cleanupFailure);
                    },
                    stageCancellation,
                    timeout)
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(resolved.Failure, timeout) &&
                !resolved.CancellationTransferred &&
                cleanupCount == 1 &&
                payload.All(value => value == 0) &&
                ReferenceEquals(
                    timeout.Data[BrokerControlFailureArbitration.CleanupFailureDataKey],
                    cleanupFailure),
                "a completed admission stage lost its result cleanup at the timeout boundary");
        }

        var exactStageFailure = new BrokerControlSessionException(
            "managed-entry-process-exited",
            "synthetic boundary process failure");
        var faultTimeout = new TimeoutException("synthetic admission fault timeout");
        using (var stageCancellation = new CancellationTokenSource())
        {
            var resolved = await ResolveTimedOutStageDrainAsync(
                    Task.FromException<byte[]>(exactStageFailure),
                    cleanup: null,
                    stageCancellation,
                    faultTimeout)
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(resolved.Failure, exactStageFailure) &&
                !resolved.CancellationTransferred &&
                BrokerControlFailureArbitration.ContainsFailure(
                    exactStageFailure.Data[
                        BrokerControlFailureArbitration.ConcurrentFailureDataKey] as Exception,
                    faultTimeout),
                "the admission timeout boundary replaced its exact stage failure");
        }

        var sameTimeout = new TimeoutException("synthetic self timeout");
        using (var stageCancellation = new CancellationTokenSource())
        {
            var resolved = await ResolveTimedOutStageDrainAsync(
                    Task.FromException<byte[]>(sameTimeout),
                    cleanup: null,
                    stageCancellation,
                    sameTimeout)
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(resolved.Failure, sameTimeout) &&
                sameTimeout.Data[
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey] is null,
                "the admission boundary attached a timeout exception to itself");
        }

        var pending = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var pendingTimeout = new TimeoutException("synthetic pending timeout");
        var pendingCancellation = new CancellationTokenSource();
        var pendingCleanupCount = 0;
        var pendingResolved = await ResolveTimedOutStageDrainAsync(
                pending.Task,
                result =>
                {
                    Interlocked.Increment(ref pendingCleanupCount);
                    CryptographicOperations.ZeroMemory(result);
                    return Task.FromResult<Exception?>(null);
                },
                pendingCancellation,
                pendingTimeout)
            .ConfigureAwait(false);
        var quarantine = pendingTimeout.Data[
            "guardian-admission-late-stage-quarantine"] as Task<Exception?>;
        Ensure(
            pendingResolved.CancellationTransferred &&
            ReferenceEquals(pendingResolved.Failure, pendingTimeout) &&
            quarantine is not null,
            "a pending admission stage did not transfer exact quarantine ownership");
        var pendingPayload = Enumerable.Repeat((byte)0xA5, 32).ToArray();
        pending.TrySetResult(pendingPayload);
        Ensure(
            await quarantine!.WaitAsync(CaseTimeout).ConfigureAwait(false) is null &&
            pendingCleanupCount == 1 &&
            pendingPayload.All(value => value == 0),
            "admission quarantine did not clean its eventual result exactly once");
    }

    private static async Task<(Exception? Failure, bool CancellationTransferred)>
        ResolveTimedOutStageDrainAsync(
            Task<byte[]> stageTask,
            Func<byte[], Task<Exception?>>? cleanup,
            CancellationTokenSource stageCancellation,
            TimeoutException timeout)
    {
        var method = typeof(WindowsGuardianProductionAdmissionV1)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .Single(candidate =>
                candidate.Name == "ResolveTimedOutStageDrainAsync" &&
                candidate.IsGenericMethodDefinition)
            .MakeGenericMethod(typeof(byte[]));
        var operation = (Task)(method.Invoke(
            null,
            new object?[] { stageTask, cleanup, stageCancellation, timeout }) ??
            throw new InvalidOperationException("The admission drain resolver returned no task."));
        await operation.WaitAsync(CaseTimeout).ConfigureAwait(false);
        var result = operation.GetType().GetProperty("Result")?.GetValue(operation) ??
            throw new InvalidOperationException("The admission drain resolver returned no result.");
        var resultType = result.GetType();
        return (
            resultType.GetProperty("Failure")?.GetValue(result) as Exception,
            (bool)(resultType.GetProperty("CancellationTransferred")?.GetValue(result) ?? false));
    }

    private static Task TestProductionSourceBoundaryAsync()
    {
        var source = File.ReadAllText(FindProductionAdmissionSource());
        var server = source.IndexOf(
            "WindowsSameLogonNamedPipeServer.Create(endpointName)",
            StringComparison.Ordinal);
        var launch = source.IndexOf(
            "candidate = launcher.Launch(endpointName, connectionNonce, challenge)",
            StringComparison.Ordinal);
        var brokerHello = source.IndexOf(
            "WriteBrokerHelloBeforePeerAuthenticationAsync",
            StringComparison.Ordinal);
        var guardianHello = source.IndexOf(
            "_verifier.BeginVerification",
            StringComparison.Ordinal);
        var ready = source.IndexOf(
            "GuardianBrokerAdmissionProtocolV1.SerializeReady",
            StringComparison.Ordinal);
        var receipt = source.IndexOf(
            "VerifiedGuardianManagedEntryConnectionV1.VerifyAsync",
            StringComparison.Ordinal);
        Ensure(
            server >= 0 && server < launch && launch < brokerHello &&
            brokerHello < guardianHello && guardianHello < ready && ready < receipt,
            "production admission no longer creates server then performs Broker-first authentication");
        Ensure(
            source.Contains(
                "ReleaseBootstrapConnectionTimeout",
                StringComparison.Ordinal) &&
            source.Contains(
                "TimeSpan.FromMinutes(15)",
                StringComparison.Ordinal) &&
            source.Contains(
                "StageTimeout = TimeSpan.FromSeconds(10)",
                StringComparison.Ordinal) &&
            source.Contains(
                "ReleaseBootstrapConnectionTimeout,",
                StringComparison.Ordinal) &&
            source.Contains(
                "stageOwnsProcessFailureArbitration: true",
                StringComparison.Ordinal) &&
            source.Contains(
                "stageOwnsProcessFailureArbitration &&",
                StringComparison.Ordinal) &&
            source.Contains(
                "IsManagedEntryProcessFailure(stageFailure)",
                StringComparison.Ordinal) &&
            source.Contains(
                "var stageToken = stageCancellation.Token;",
                StringComparison.Ordinal) &&
            source.Contains("stageTask = startStage(stageToken)", StringComparison.Ordinal) &&
            source.Contains(
                "IsExpectedStageCancellation(\n                        drain.Failure,\n                        stageToken)",
                StringComparison.Ordinal) &&
            source.Split(
                "stageCancellation.Token",
                StringSplitOptions.None).Length - 1 == 1,
            "release bootstrap and authenticated stage budgets were not kept separate");
        Ensure(
            source.Contains("public bool AllowsSuccessorAdmission => false;", StringComparison.Ordinal) &&
            source.Contains("#if CODEXGUARDIAN_TEST_FRIEND", StringComparison.Ordinal),
            "production admission reopened successor admission or exposed its test constructor");
        return Task.CompletedTask;
    }

    private static string FindProductionAdmissionSource()
    {
        for (var current = new DirectoryInfo(Environment.CurrentDirectory);
             current is not null;
             current = current.Parent)
        {
            var candidate = Path.Combine(
                current.FullName,
                "work",
                "CodexGuardian.Broker",
                "WindowsGuardianProductionAdmission.cs");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new DirectoryNotFoundException(
            "The production Guardian admission source root was not found.");
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().WaitAsync(CaseTimeout).ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception);
        }
    }

    private static async Task<TException> ExpectAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().WaitAsync(CaseTimeout).ConfigureAwait(false);
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException(
            "Expected " + typeof(TException).Name + " was not observed.");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class ReleaseBindingFixture : IDisposable
    {
        private readonly VerifiedLocalReleaseManifestOfflineTests.ReleaseFixture _fixture;
        private readonly BrokerProductionReleaseAuthorityV1 _authority;

        private ReleaseBindingFixture(
            VerifiedLocalReleaseManifestOfflineTests.ReleaseFixture fixture,
            BrokerProductionReleaseAuthorityV1 authority)
        {
            _fixture = fixture;
            _authority = authority;
            Binding = authority.Binding;
        }

        internal BrokerProductionReleaseBindingV1 Binding { get; }

        internal static ReleaseBindingFixture Create()
        {
            var fixture = VerifiedLocalReleaseManifestOfflineTests.ReleaseFixture.Create(
                includeBroker: true);
            VerifiedLocalReleaseLeaseV1? lease = null;
            BrokerProductionReleaseAuthorityV1? authority = null;
            try
            {
                lease = WindowsVerifiedLocalReleaseManifestFactory
                    .OpenFromOutputsRootForTests(fixture.Root);
                authority = BrokerProductionReleaseAuthorityV1.TakeOwnership(lease);
                lease.Dispose();
                lease = null;
                var result = new ReleaseBindingFixture(fixture, authority);
                authority = null;
                return result;
            }
            catch
            {
                authority?.Dispose();
                lease?.Dispose();
                fixture.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            try
            {
                _authority.Dispose();
            }
            finally
            {
                _fixture.Dispose();
            }
        }
    }
}
