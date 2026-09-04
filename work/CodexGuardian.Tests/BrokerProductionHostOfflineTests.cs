using CodexGuardian.Broker;
using CodexGuardian.Control;
using CodexGuardian.Trust;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using BrokerProgram = CodexGuardian.Broker.Program;

internal static class BrokerProductionHostOfflineTests
{
    private const string UserSid = "S-1-5-21-1000-2000-3000-4000";
    private const string LogonSid = "S-1-5-5-100-200";
    private const string ReleaseId = "broker-production-host-offline-release-v1";
    private const string ManifestSha256 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string ConnectionNonce =
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string ReleaseRoot = @"D:\CodexData\CodexGuardian\production-host-offline";
    private const uint GuardianProcessId = 42001;
    private const uint GuardianSessionId = 7;
    private const ulong VolumeSerial = 0x00000000A1B2C3D4;
    private static readonly DateTimeOffset GuardianCreationTime =
        new(2026, 8, 7, 5, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan CaseTimeout = TimeSpan.FromSeconds(10);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "Production host parser accepts only one exact ordinal argument",
            TestProductionHostArgumentParserAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker apphost rejects only malformed non-production argument matrices",
            TestMalformedBrokerAppHostArgumentsAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Host cancellation waits for async owner authority transfer before cleanup",
            TestAsyncOwnerFactoryCancellationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Async owner factory rejects every failure vector and remains one-shot",
            TestAsyncOwnerFactoryFailureVectorsAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Runtime owner factory preserves primary failures and disposes one owner chain",
            TestRuntimeOwnerFactoryFailureArbitrationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Production host acquires singleton first and cleans resources in reverse order",
            TestFactoryAndCleanupOrderAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Production accept loop keeps one owner across two serial Guardian admissions",
            TestSerialAdmissionsAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "One-shot admission exits after one normal Guardian session",
            TestOneShotAdmissionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Owner fault wins a concurrent host cancellation",
            TestOwnerFaultCancellationArbitrationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Unhealthy peer trust terminates and preserves reverse cleanup failures",
            TestTrustUnhealthyCleanupAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Production components must bind the exact pinned release authority",
            TestReleaseAuthorityBindingAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Host cancellation interrupts a blocked startup wait and releases authority",
            TestBlockedStartupCancellationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Host cancellation preserves attached cleanup and concurrent failures",
            TestHostCancellationAttachedFailureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Foreign-token cancellation remains terminal across owner completion",
            TestForeignTokenCancellationArbitrationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Linked cancellation callback failures enter terminal arbitration",
            TestCancellationCallbackFailureArbitrationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Admission cleanup evidence is terminal even when trust remains healthy",
            TestAdmissionAttachedCleanupFailureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Classified connection failures reconnect only after exact cleanup",
            TestClassifiedConnectionFailureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Unexpected session failures terminate instead of reopening admission",
            TestUnexpectedSessionFailureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Concurrent host cancellation cannot suppress a terminal session cancellation",
            TestTerminalSessionCancellationArbitrationAsync,
            assert).ConfigureAwait(false);
    }

    private static Task TestProductionHostArgumentParserAsync()
    {
        const string productionArgument = "--guardian-broker-production-host-v1";
        Ensure(
            BrokerProgram.ClassifyInvocation(
                new[] { productionArgument },
                out var productionMode,
                out var productionRoot) == BrokerInvocationKindV1.ProductionHost &&
            string.IsNullOrEmpty(productionMode) &&
            string.IsNullOrEmpty(productionRoot),
            "the exact production argument was not recognized");
        Ensure(
            BrokerProgram.ClassifyInvocation(
                new[] { "--native-peer-child-probe-server" },
                out _,
                out _) == BrokerInvocationKindV1.NativePeerProbe,
            "the exact native peer probe argument was not preserved");
        Ensure(
            BrokerProgram.ClassifyInvocation(
                new[]
                {
                    "--native-user-presence-capability-probe",
                    "--native-user-presence-evidence-root",
                    @"D:\CodexData\CodexGuardian\webauthn-offline"
                },
                out var capabilityMode,
                out var capabilityRoot) == BrokerInvocationKindV1.UserPresenceProbe &&
            capabilityMode == "capability" &&
            capabilityRoot == @"D:\CodexData\CodexGuardian\webauthn-offline",
            "the exact user-presence probe argument contract was not preserved");
        foreach (var rejected in new[]
                 {
                     Array.Empty<string>(),
                     new[] { string.Empty },
                     new[] { "--Guardian-broker-production-host-v1" },
                     new[] { productionArgument + "-suffix" },
                     new[] { "prefix-" + productionArgument },
                     new[] { productionArgument, "extra" },
                     new[] { "extra", productionArgument }
                 })
        {
            Ensure(
                BrokerProgram.ClassifyInvocation(rejected, out _, out _) ==
                    BrokerInvocationKindV1.Invalid,
                "a malformed argument vector was accepted before the side-effect boundary");
        }

        return Task.CompletedTask;
    }

    private static async Task TestMalformedBrokerAppHostArgumentsAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Broker malformed-argument apphost matrix requires Windows.");
        }

        const string productionArgument = "--guardian-broker-production-host-v1";
        var brokerExecutable = Path.Combine(
            AppContext.BaseDirectory,
            "CodexGuardian.Broker.exe");
        Ensure(File.Exists(brokerExecutable), "the fresh Broker apphost is unavailable");
        var cases = new[]
        {
            Array.Empty<string>(),
            new[] { string.Empty },
            new[] { "--unknown-broker-mode" },
            new[] { "--Guardian-broker-production-host-v1" },
            new[] { productionArgument + "-suffix" },
            new[] { productionArgument, productionArgument },
            new[] { productionArgument, string.Empty },
            new[] { productionArgument, "extra" },
            new[] { "extra", productionArgument },
            new[] { productionArgument, "--native-peer-child-probe-server" },
            new[] { "--native-peer-child-probe-server", productionArgument },
            new[]
            {
                productionArgument,
                "--native-user-presence-capability-probe",
                "--native-user-presence-evidence-root"
            },
            new[]
            {
                "--native-user-presence-capability-probe",
                "--native-user-presence-evidence-root",
                productionArgument
            },
            new[] { "--guardian-broker-bootstrap-handle" },
            new[] { "--guardian-broker-bootstrap-handle", "not-a-handle" },
            new[] { "--connection-nonce" },
            new[] { "--connection-nonce", "not-canonical" },
            new[] { "--challenge" },
            new[] { "--challenge", "not-canonical" },
            new[] { "--release-id" },
            new[] { "--release-id", "not-canonical" },
            new[] { "--manifest-sha256" },
            new[] { "--manifest-sha256", "not-canonical" },
            new[] { "--guardian-managed-entry-v1", productionArgument },
            new[] { productionArgument, "--guardian-managed-entry-v1" }
        };

        foreach (var arguments in cases)
        {
            Ensure(
                BrokerProgram.ClassifyInvocation(arguments, out _, out _) ==
                    BrokerInvocationKindV1.Invalid,
                "the malformed apphost matrix included the exact production invocation");
            var result = await RunBrokerAppHostAsync(brokerExecutable, arguments)
                .ConfigureAwait(false);
            Ensure(
                result.ExitCode == 64 &&
                string.IsNullOrEmpty(result.StandardOutput) &&
                string.IsNullOrEmpty(result.StandardError),
                "a malformed Broker invocation did not fail closed with silent exit 64");
        }
    }

    private static async Task TestAsyncOwnerFactoryCancellationAsync()
    {
        var events = new List<string>();
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var factoryEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var factoryCompletion = new TaskCompletionSource<IBrokerProductionRuntimeOwnerV1>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var host = CreateHost(
            events,
            owner,
            admissions,
            createOwnerAsync: _ =>
            {
                factoryEntered.TrySetResult();
                return new ValueTask<IBrokerProductionRuntimeOwnerV1>(factoryCompletion.Task);
            });
        using var cancellation = new CancellationTokenSource();
        var run = host.RunAsync(cancellation.Token);
        await factoryEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        cancellation.Cancel();
        var premature = await Task.WhenAny(run, Task.Delay(TimeSpan.FromMilliseconds(100)))
            .ConfigureAwait(false);
        Ensure(
            !ReferenceEquals(premature, run),
            "host cancellation abandoned the in-flight owner authority factory");

        factoryCompletion.TrySetResult(owner);
        await run.WaitAsync(CaseTimeout).ConfigureAwait(false);
        Ensure(
            owner.StartCount == 0 &&
            !events.Contains("admission-create", StringComparer.Ordinal) &&
            events.TakeLast(3).SequenceEqual(new[]
            {
                "owner-dispose",
                "release-dispose",
                "singleton-dispose"
            }),
            "late owner authority was started or escaped fixed reverse cleanup");
    }

    private static async Task TestAsyncOwnerFactoryFailureVectorsAsync()
    {
        var synchronousFailure = new IOException("synthetic-owner-factory-sync-failure");
        var synchronousObserved = await RunOwnerFactoryFailureVectorAsync(
            _ => throw synchronousFailure).ConfigureAwait(false);
        Ensure(
            ReferenceEquals(synchronousObserved, synchronousFailure),
            "a synchronous owner factory failure was replaced");

        var asynchronousFailure = new IOException("synthetic-owner-factory-async-failure");
        var asynchronousObserved = await RunOwnerFactoryFailureVectorAsync(
            _ => new ValueTask<IBrokerProductionRuntimeOwnerV1>(
                Task.FromException<IBrokerProductionRuntimeOwnerV1>(asynchronousFailure)))
            .ConfigureAwait(false);
        Ensure(
            ReferenceEquals(asynchronousObserved, asynchronousFailure),
            "an asynchronous owner factory failure was replaced");

        using var foreignCancellation = new CancellationTokenSource();
        foreignCancellation.Cancel();
        var foreignFailure = new OperationCanceledException(
            "synthetic-owner-factory-foreign-cancellation",
            foreignCancellation.Token);
        var foreignObserved = await RunOwnerFactoryFailureVectorAsync(
            _ => new ValueTask<IBrokerProductionRuntimeOwnerV1>(
                Task.FromException<IBrokerProductionRuntimeOwnerV1>(foreignFailure)))
            .ConfigureAwait(false);
        Ensure(
            ReferenceEquals(foreignObserved, foreignFailure) &&
            ((OperationCanceledException)foreignObserved).CancellationToken ==
                foreignCancellation.Token,
            "foreign owner factory cancellation was suppressed as host cancellation");

        var nullObserved = await RunOwnerFactoryFailureVectorAsync(
            _ => ValueTask.FromResult<IBrokerProductionRuntimeOwnerV1>(null!))
            .ConfigureAwait(false);
        Ensure(
            nullObserved is BrokerProductionHostException nullFailure &&
            nullFailure.Code == "broker-runtime-owner-invalid",
            "a null async owner factory result did not fail closed");

        var events = new List<string>();
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var factoryCount = 0;
        var host = CreateHost(
            events,
            owner,
            admissions,
            createOwnerAsync: _ =>
            {
                Interlocked.Increment(ref factoryCount);
                return ValueTask.FromResult<IBrokerProductionRuntimeOwnerV1>(owner);
            });
        var firstRun = host.RunAsync();
        await admissions.AcceptEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        var secondFailure = await ExpectAsync<InvalidOperationException>(
            () => host.RunAsync()).ConfigureAwait(false);
        owner.Complete();
        await firstRun.WaitAsync(CaseTimeout).ConfigureAwait(false);
        Ensure(
            factoryCount == 1 &&
            secondFailure.Message.Contains("only once", StringComparison.Ordinal),
            "a second host run reinvoked the async owner authority factory");
    }

    private static async Task<Exception> RunOwnerFactoryFailureVectorAsync(
        Func<
            BrokerProductionReleaseBindingV1,
            ValueTask<IBrokerProductionRuntimeOwnerV1>> factory)
    {
        var events = new List<string>();
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var factoryCount = 0;
        var host = CreateHost(
            events,
            owner,
            admissions,
            createOwnerAsync: binding =>
            {
                Interlocked.Increment(ref factoryCount);
                return factory(binding);
            });
        Exception? observed = null;
        try
        {
            await host.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            observed = exception;
        }

        Ensure(
            observed is not null &&
            factoryCount == 1 &&
            !events.Contains("owner-start", StringComparer.Ordinal) &&
            !events.Contains("admission-create", StringComparer.Ordinal) &&
            events.TakeLast(2).SequenceEqual(new[]
            {
                "release-dispose",
                "singleton-dispose"
            }),
            "an async owner factory failure escaped one-shot reverse cleanup");
        return observed!;
    }

    private static async Task TestRuntimeOwnerFactoryFailureArbitrationAsync()
    {
        await WithReleaseBindingAsync(async binding =>
        {
            var runtimeConstructionFailure = new InvalidOperationException(
                "synthetic-runtime-construction-failure");
            var runtimeObserved = await ExpectAsync<InvalidOperationException>(
                () => BrokerProductionRuntimeOwnerFactoryV1.CreateForTestsAsync(
                    binding,
                    () => throw runtimeConstructionFailure,
                    _ => throw new InvalidOperationException("owner factory must not run"),
                    (_, _) => throw new InvalidOperationException("adapter factory must not run"))
                    .AsTask()).ConfigureAwait(false);
            Ensure(
                ReferenceEquals(runtimeObserved, runtimeConstructionFailure),
                "runtime construction failure was replaced");

            var ownerConstructionFailure = new InvalidOperationException(
                "synthetic-owner-construction-failure");
            var runtimeCleanupFailure = new IOException("synthetic-runtime-cleanup-failure");
            var runtimeCleanupEntered = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseRuntimeCleanup = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var provisionalRuntime = new FakeFactoryResource(
                disposeFailure: runtimeCleanupFailure,
                disposeEntered: runtimeCleanupEntered,
                releaseDispose: releaseRuntimeCleanup);
            var ownerOperation = BrokerProductionRuntimeOwnerFactoryV1.CreateForTestsAsync(
                    binding,
                    () => provisionalRuntime,
                    candidate =>
                    {
                        Ensure(
                            ReferenceEquals(candidate, provisionalRuntime),
                            "owner factory received the wrong provisional runtime");
                        throw ownerConstructionFailure;
                    },
                    (_, _) => throw new InvalidOperationException("adapter factory must not run"))
                .AsTask();
            await runtimeCleanupEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                !ownerOperation.IsCompleted,
                "the owner factory did not await asynchronous provisional runtime cleanup");
            releaseRuntimeCleanup.TrySetResult();
            var ownerObserved = await ExpectAsync<InvalidOperationException>(
                () => ownerOperation).ConfigureAwait(false);
            Ensure(
                ReferenceEquals(ownerObserved, ownerConstructionFailure) &&
                provisionalRuntime.DisposeCount == 1 &&
                ReferenceEquals(
                    ownerObserved.Data[BrokerControlFailureArbitration.CleanupFailureDataKey],
                    runtimeCleanupFailure),
                "owner construction failure did not retain one runtime cleanup failure");

            var adapterConstructionFailure = new InvalidOperationException(
                "synthetic-adapter-construction-failure");
            var ownerCleanupFailure = new IOException("synthetic-owner-cleanup-failure");
            var transferredRuntime = new FakeFactoryResource();
            var provisionalOwner = new FakeFactoryResource(
                owned: transferredRuntime,
                disposeFailure: ownerCleanupFailure);
            var adapterObserved = await ExpectAsync<InvalidOperationException>(
                () => BrokerProductionRuntimeOwnerFactoryV1.CreateForTestsAsync(
                    binding,
                    () => transferredRuntime,
                    candidate =>
                    {
                        Ensure(
                            ReferenceEquals(candidate, transferredRuntime),
                            "adapter test owner received the wrong runtime");
                        return provisionalOwner;
                    },
                    (candidate, exactBinding) =>
                    {
                        Ensure(
                            ReferenceEquals(candidate, provisionalOwner) &&
                            ReferenceEquals(exactBinding, binding),
                            "adapter factory received the wrong owner or release binding");
                        throw adapterConstructionFailure;
                    })
                    .AsTask()).ConfigureAwait(false);
            Ensure(
                ReferenceEquals(adapterObserved, adapterConstructionFailure) &&
                provisionalOwner.DisposeCount == 1 &&
                transferredRuntime.DisposeCount == 1 &&
                ReferenceEquals(
                    adapterObserved.Data[BrokerControlFailureArbitration.CleanupFailureDataKey],
                    ownerCleanupFailure),
                "adapter construction failure double-disposed or replaced owner cleanup evidence");
        }).ConfigureAwait(false);
    }

    private static async Task TestFactoryAndCleanupOrderAsync()
    {
        var events = new List<string>();
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(events, Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var host = CreateHost(events, owner, admissions);
        var run = host.RunAsync();
        await admissions.AcceptEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        owner.Complete();
        await run.WaitAsync(CaseTimeout).ConfigureAwait(false);

        Ensure(owner.StartCount == 1, "the production owner did not start exactly once");
        Ensure(events.SequenceEqual(new[]
        {
            "singleton-acquire",
            "release-open",
            "owner-create",
            "owner-start",
            "admission-create",
            "accept-enter",
            "admission-dispose",
            "owner-dispose",
            "release-dispose",
            "singleton-dispose"
        }), "the production resource order was not singleton-first and reverse-cleaned");
    }

    private static async Task TestSerialAdmissionsAsync()
    {
        var events = new List<string>();
        var first = await CreateVerifiedGuardianAsync(1).ConfigureAwait(false);
        var second = await CreateVerifiedGuardianAsync(2).ConfigureAwait(false);
        var owner = new FakeOwner(events, completeOwnerOnAttach: 2);
        var admissions = new FakeAdmissionSource(events, new[] { first, second });
        var host = CreateHost(events, owner, admissions);

        await host.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false);

        Ensure(owner.StartCount == 1, "serial reconnect restarted the production owner");
        Ensure(owner.AttachCount == 2, "the accept loop did not attach two Guardian admissions");
        Ensure(owner.MaximumActiveSessions == 1, "more than one Guardian session was active");
        var firstDispose = events.IndexOf("session-dispose-1");
        var secondAccept = events.IndexOf("accept-2");
        Ensure(
            firstDispose >= 0 && secondAccept > firstDispose,
            "the second admission began before exact first-session cleanup");
        Ensure(
            events.Count(value => value == "owner-start") == 1 &&
            events.IndexOf("owner-dispose") > events.IndexOf("admission-dispose"),
            "disconnect or reconnect changed the owner lifetime ordering");
        Ensure(
            ReferenceEquals(owner.ReleaseBinding, admissions.ReleaseBinding) &&
            ReferenceEquals(
                owner.ReleaseBinding.Manifest,
                admissions.ReleaseBinding.Manifest) &&
            (object)owner.ReleaseBinding is not IDisposable,
            "runtime owner and admissions did not retain the exact non-disposable release binding");
    }

    private static async Task TestOneShotAdmissionAsync()
    {
        var events = new List<string>();
        var guardian = await CreateVerifiedGuardianAsync(10).ConfigureAwait(false);
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(
            events,
            new[] { guardian },
            allowsSuccessorAdmission: false);
        var host = CreateHost(events, owner, admissions);

        await host.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false);

        Ensure(admissions.AcceptCount == 1, "the one-shot source was accepted more than once");
        Ensure(owner.AttachCount == 1, "the one-shot Guardian session was not attached exactly once");
        Ensure(
            events.IndexOf("session-dispose-1") < events.IndexOf("admission-dispose") &&
            events.IndexOf("admission-dispose") < events.IndexOf("owner-dispose"),
            "the one-shot session did not settle before reverse host cleanup");
    }

    private static async Task TestOwnerFaultCancellationArbitrationAsync()
    {
        var events = new List<string>();
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(events, Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var host = CreateHost(events, owner, admissions);
        using var cancellation = new CancellationTokenSource();
        var run = host.RunAsync(cancellation.Token);
        await admissions.AcceptEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        var ownerFailure = new InvalidOperationException("synthetic-owner-terminal-failure");
        owner.Fail(ownerFailure);
        cancellation.Cancel();

        var observed = await ExpectAsync<InvalidOperationException>(
            async () => await run.WaitAsync(CaseTimeout).ConfigureAwait(false)).ConfigureAwait(false);
        Ensure(
            ReferenceEquals(observed, ownerFailure),
            "host cancellation replaced the already-published owner failure");
        Ensure(
            events.IndexOf("admission-dispose") < events.IndexOf("owner-dispose"),
            "owner cleanup ran before the cancelled admission source settled");
    }

    private static async Task TestTrustUnhealthyCleanupAsync()
    {
        var events = new List<string>();
        var admissionCleanup = new IOException("synthetic-admission-cleanup");
        var ownerCleanup = new IOException("synthetic-owner-cleanup");
        var releaseCleanup = new IOException("synthetic-release-cleanup");
        var singletonCleanup = new IOException("synthetic-singleton-cleanup");
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0)
        {
            DisposeFailure = ownerCleanup
        };
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>(),
            failFirstAdmission: true)
        {
            DisposeFailure = admissionCleanup
        };
        var host = CreateHost(
            events,
            owner,
            admissions,
            releaseCleanup,
            singletonCleanup);

        var failure = await ExpectAsync<BrokerProductionHostException>(
            async () => await host.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);
        Ensure(
            failure.Code == "broker-peer-trust-unhealthy",
            "the unhealthy verifier did not retain its stable terminal code");
        Ensure(
            failure.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] is Exception,
            "secondary cleanup failures replaced or disappeared from the trust failure");
        Ensure(events.TakeLast(4).SequenceEqual(new[]
        {
            "admission-dispose",
            "owner-dispose",
            "release-dispose",
            "singleton-dispose"
        }), "terminal trust cleanup did not retain the fixed reverse order");
    }

    private static async Task TestReleaseAuthorityBindingAsync()
    {
        var ownerEvents = new List<string>();
        var owner = new FakeOwner(ownerEvents, completeOwnerOnAttach: 0);
        var ownerAdmissions = new FakeAdmissionSource(
            ownerEvents,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var ownerMismatch = CreateHost(
            ownerEvents,
            owner,
            ownerAdmissions,
            bindOwnerRelease: false);
        var ownerFailure = await ExpectAsync<BrokerProductionHostException>(
            async () => await ownerMismatch.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);
        Ensure(
            ownerFailure.Code == "broker-runtime-owner-release-mismatch" &&
            !ownerEvents.Contains("admission-create", StringComparer.Ordinal),
            "an owner bound to no exact release authority reached admission startup");

        var admissionEvents = new List<string>();
        var admissionOwner = new FakeOwner(admissionEvents, completeOwnerOnAttach: 0);
        var admissionSource = new FakeAdmissionSource(
            admissionEvents,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var admissionMismatch = CreateHost(
            admissionEvents,
            admissionOwner,
            admissionSource,
            bindAdmissionRelease: false);
        var admissionFailure = await ExpectAsync<BrokerProductionHostException>(
            async () => await admissionMismatch.RunAsync().WaitAsync(CaseTimeout)
                .ConfigureAwait(false)).ConfigureAwait(false);
        Ensure(
            admissionFailure.Code == "broker-admission-release-mismatch" &&
            admissionEvents.IndexOf("admission-dispose") < admissionEvents.IndexOf("owner-dispose"),
            "an admission source bound to no exact release authority escaped reverse cleanup");
    }

    private static async Task TestBlockedStartupCancellationAsync()
    {
        var events = new List<string>();
        var owner = new FakeOwner(
            events,
            completeOwnerOnAttach: 0,
            blockStartUntilDispose: true);
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var host = CreateHost(events, owner, admissions);
        using var cancellation = new CancellationTokenSource();
        var run = host.RunAsync(cancellation.Token);
        await owner.StartEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        cancellation.Cancel();
        await run.WaitAsync(CaseTimeout).ConfigureAwait(false);

        Ensure(
            !owner.StartTokenCanBeCanceled && !events.Contains("admission-create", StringComparer.Ordinal),
            "host cancellation was delegated into or escaped the shared owner startup task");
        Ensure(events.TakeLast(3).SequenceEqual(new[]
        {
            "owner-dispose",
            "release-dispose",
            "singleton-dispose"
        }), "blocked startup cancellation did not release authority in reverse order");
    }

    private static async Task TestHostCancellationAttachedFailureAsync()
    {
        var cleanupEvents = new List<string>();
        var guardian = await CreateVerifiedGuardianAsync(9).ConfigureAwait(false);
        var sessionCleanup = new IOException("synthetic-session-cleanup");
        var cleanupOwner = new FakeOwner(
            cleanupEvents,
            completeOwnerOnAttach: 0,
            blockFirstSessionUntilCancellation: true,
            firstSessionDisposeFailure: sessionCleanup);
        var cleanupAdmissions = new FakeAdmissionSource(cleanupEvents, new[] { guardian });
        var cleanupHost = CreateHost(cleanupEvents, cleanupOwner, cleanupAdmissions);
        using var cleanupCancellation = new CancellationTokenSource();
        var cleanupRun = cleanupHost.RunAsync(cleanupCancellation.Token);
        await cleanupOwner.FirstSessionRunEntered.Task.WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        cleanupCancellation.Cancel();

        var cleanupObserved = await ExpectAsync<OperationCanceledException>(
            async () => await cleanupRun.WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);
        Ensure(
            cleanupObserved.CancellationToken == cleanupCancellation.Token &&
            ReferenceEquals(
                cleanupObserved.Data[BrokerControlFailureArbitration.CleanupFailureDataKey],
                sessionCleanup),
            "host cancellation suppressed the attached session cleanup failure");

        var concurrentEvents = new List<string>();
        using var concurrentCancellation = new CancellationTokenSource();
        var concurrentFailure = new IOException("synthetic-cancellation-concurrent");
        var concurrentCancellationFailure = new OperationCanceledException(
            "synthetic-host-cancellation-with-concurrent-failure",
            concurrentCancellation.Token);
        concurrentCancellationFailure.Data[
            BrokerControlFailureArbitration.ConcurrentFailureDataKey] = concurrentFailure;
        var concurrentOwner = new FakeOwner(
            concurrentEvents,
            completeOwnerOnAttach: 0,
            startFailure: concurrentCancellationFailure,
            beforeStart: concurrentCancellation.Cancel);
        var concurrentAdmissions = new FakeAdmissionSource(
            concurrentEvents,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>());
        var concurrentHost = CreateHost(
            concurrentEvents,
            concurrentOwner,
            concurrentAdmissions);

        var concurrentObserved = await ExpectAsync<OperationCanceledException>(
            async () => await concurrentHost.RunAsync(concurrentCancellation.Token)
                .WaitAsync(CaseTimeout)
                .ConfigureAwait(false)).ConfigureAwait(false);
        Ensure(
            ReferenceEquals(concurrentObserved, concurrentCancellationFailure) &&
            ReferenceEquals(
                concurrentObserved.Data[
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey],
                concurrentFailure),
            "host cancellation suppressed an attached concurrent failure");
    }

    private static async Task TestForeignTokenCancellationArbitrationAsync()
    {
        var events = new List<string>();
        using var foreignCancellation = new CancellationTokenSource();
        foreignCancellation.Cancel();
        var admissionFailure = new OperationCanceledException(
            "synthetic-foreign-admission-cancellation",
            foreignCancellation.Token);
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>(),
            cancellationReplacementFailure: admissionFailure);
        var host = CreateHost(events, owner, admissions);
        var run = host.RunAsync();
        await admissions.AcceptEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        owner.Complete();

        var observed = await ExpectAsync<OperationCanceledException>(
            async () => await run.WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);

        Ensure(
            ReferenceEquals(observed, admissionFailure) &&
            observed.CancellationToken == foreignCancellation.Token &&
            admissions.AcceptCount == 1 &&
            owner.AttachCount == 0,
            "a foreign canceled token was mistaken for loop-owned cancellation");

        var faultEvents = new List<string>();
        using var faultCancellation = new CancellationTokenSource();
        faultCancellation.Cancel();
        var concurrentAdmissionFailure = new OperationCanceledException(
            "synthetic-concurrent-foreign-admission-cancellation",
            faultCancellation.Token);
        var ownerFailure = new InvalidOperationException("synthetic-owner-fault");
        var faultOwner = new FakeOwner(faultEvents, completeOwnerOnAttach: 0);
        var faultAdmissions = new FakeAdmissionSource(
            faultEvents,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>(),
            cancellationReplacementFailure: concurrentAdmissionFailure);
        var faultHost = CreateHost(faultEvents, faultOwner, faultAdmissions);
        var faultRun = faultHost.RunAsync();
        await faultAdmissions.AcceptEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        faultOwner.Fail(ownerFailure);

        var faultObserved = await ExpectAsync<InvalidOperationException>(
            async () => await faultRun.WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);
        Ensure(
            ReferenceEquals(faultObserved, ownerFailure) &&
            ReferenceEquals(
                faultObserved.Data[BrokerControlFailureArbitration.ConcurrentFailureDataKey],
                concurrentAdmissionFailure) &&
            faultAdmissions.AcceptCount == 1 &&
            faultOwner.AttachCount == 0,
            "an owner fault did not retain the foreign admission failure as concurrent evidence");
    }

    private static async Task TestCancellationCallbackFailureArbitrationAsync()
    {
        var events = new List<string>();
        var callbackFailure = new IOException("synthetic-cancellation-callback");
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>(),
            cancellationCallbackFailure: callbackFailure);
        var host = CreateHost(events, owner, admissions);
        var run = host.RunAsync();
        await admissions.AcceptEntered.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
        owner.Complete();

        var observed = await ExpectAsync<AggregateException>(
            async () => await run.WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);
        Ensure(
            BrokerControlFailureArbitration.ContainsFailure(observed, callbackFailure),
            "the linked-token cancellation callback failure disappeared from arbitration");
    }

    private static async Task TestClassifiedConnectionFailureAsync()
    {
        var events = new List<string>();
        var first = await CreateVerifiedGuardianAsync(3).ConfigureAwait(false);
        var second = await CreateVerifiedGuardianAsync(4).ConfigureAwait(false);
        var owner = new FakeOwner(
            events,
            completeOwnerOnAttach: 2,
            firstSessionFailure: new IOException("synthetic-connection-disconnect"));
        var admissions = new FakeAdmissionSource(events, new[] { first, second });
        var host = CreateHost(events, owner, admissions);

        await host.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false);

        Ensure(
            owner.AttachCount == 2 &&
            admissions.AcceptCount == 2 &&
            events.IndexOf("session-dispose-1") < events.IndexOf("accept-2"),
            "a classified connection failure reconnected before cleanup or failed to reconnect");
    }

    private static async Task TestAdmissionAttachedCleanupFailureAsync()
    {
        var events = new List<string>();
        var cleanupFailure = new IOException("synthetic-admission-attached-cleanup");
        var admissionFailure = new IOException("synthetic-admission-primary");
        admissionFailure.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] =
            cleanupFailure;
        var owner = new FakeOwner(events, completeOwnerOnAttach: 0);
        var admissions = new FakeAdmissionSource(
            events,
            Array.Empty<VerifiedGuardianManagedEntryConnectionV1>(),
            firstAdmissionFailure: admissionFailure,
            secondAdmissionFailure: new InvalidOperationException(
                "admission loop incorrectly accepted after cleanup evidence"));
        var host = CreateHost(events, owner, admissions);

        var observed = await ExpectAsync<IOException>(
            async () => await host.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);

        Ensure(
            ReferenceEquals(observed, admissionFailure) &&
            ReferenceEquals(
                observed.Data[BrokerControlFailureArbitration.CleanupFailureDataKey],
                cleanupFailure) &&
            admissions.AcceptCount == 1 &&
            owner.AttachCount == 0,
            "admission cleanup evidence was dropped or reopened acceptance");
    }

    private static async Task TestUnexpectedSessionFailureAsync()
    {
        var events = new List<string>();
        var first = await CreateVerifiedGuardianAsync(5).ConfigureAwait(false);
        var second = await CreateVerifiedGuardianAsync(6).ConfigureAwait(false);
        var sessionFailure = new InvalidOperationException("synthetic-session-invariant");
        var owner = new FakeOwner(
            events,
            completeOwnerOnAttach: 0,
            firstSessionFailure: sessionFailure);
        var admissions = new FakeAdmissionSource(events, new[] { first, second });
        var host = CreateHost(events, owner, admissions);

        var observed = await ExpectAsync<InvalidOperationException>(
            async () => await host.RunAsync().WaitAsync(CaseTimeout).ConfigureAwait(false))
            .ConfigureAwait(false);

        Ensure(
            ReferenceEquals(observed, sessionFailure) &&
            owner.AttachCount == 1 &&
            admissions.AcceptCount == 1,
            "an unexpected session invariant failure reopened Guardian admission");
    }

    private static async Task TestTerminalSessionCancellationArbitrationAsync()
    {
        var events = new List<string>();
        var first = await CreateVerifiedGuardianAsync(7).ConfigureAwait(false);
        var second = await CreateVerifiedGuardianAsync(8).ConfigureAwait(false);
        using var hostCancellation = new CancellationTokenSource();
        var sessionFailure = new OperationCanceledException(
            "synthetic-terminal-session-cancellation");
        var owner = new FakeOwner(
            events,
            completeOwnerOnAttach: 0,
            firstSessionFailure: sessionFailure,
            beforeFirstSessionFailure: hostCancellation.Cancel);
        var admissions = new FakeAdmissionSource(events, new[] { first, second });
        var host = CreateHost(events, owner, admissions);

        var observed = await ExpectAsync<OperationCanceledException>(
            async () => await host.RunAsync(hostCancellation.Token)
                .WaitAsync(CaseTimeout)
                .ConfigureAwait(false)).ConfigureAwait(false);

        Ensure(
            ReferenceEquals(observed, sessionFailure) &&
            owner.AttachCount == 1 &&
            admissions.AcceptCount == 1,
            "concurrent host cancellation suppressed or retried a terminal session cancellation");
    }

    private static BrokerProductionHostV1 CreateHost(
        List<string> events,
        FakeOwner owner,
        FakeAdmissionSource admissions,
        Exception? releaseDisposeFailure = null,
        Exception? singletonDisposeFailure = null,
        bool bindOwnerRelease = true,
        bool bindAdmissionRelease = true,
        Func<
            BrokerProductionReleaseBindingV1,
            ValueTask<IBrokerProductionRuntimeOwnerV1>>? createOwnerAsync = null) =>
        new(new BrokerProductionHostFactoriesV1(
            AcquireSingleInstance: () =>
            {
                events.Add("singleton-acquire");
                return new FakeSingletonLease(events, singletonDisposeFailure);
            },
            OpenReleaseLease: () =>
            {
                events.Add("release-open");
                var fixture = VerifiedLocalReleaseManifestOfflineTests.ReleaseFixture.Create(
                    includeBroker: true);
                try
                {
                    var lease = WindowsVerifiedLocalReleaseManifestFactory
                        .OpenFromOutputsRootForTests(fixture.Root);
                    lease.ConfigureDisposalForTests(() =>
                    {
                        events.Add("release-dispose");
                        try
                        {
                            if (releaseDisposeFailure is not null)
                            {
                                ExceptionDispatchInfo.Capture(releaseDisposeFailure).Throw();
                            }
                        }
                        finally
                        {
                            fixture.Dispose();
                        }
                    });
                    return lease;
                }
                catch
                {
                    fixture.Dispose();
                    throw;
                }
            },
            CreateOwnerAsync: binding =>
            {
                events.Add("owner-create");
                if (bindOwnerRelease)
                {
                    owner.BindReleaseBinding(binding);
                }

                return createOwnerAsync is null
                    ? ValueTask.FromResult<IBrokerProductionRuntimeOwnerV1>(owner)
                    : createOwnerAsync(binding);
            },
            CreateAdmissionSource: binding =>
            {
                events.Add("admission-create");
                if (bindAdmissionRelease)
                {
                    admissions.BindReleaseBinding(binding);
                }

                return admissions;
            }));

    private static async Task WithReleaseBindingAsync(
        Func<BrokerProductionReleaseBindingV1, Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        var fixture = VerifiedLocalReleaseManifestOfflineTests.ReleaseFixture.Create(
            includeBroker: true);
        VerifiedLocalReleaseLeaseV1? source = null;
        BrokerProductionReleaseAuthorityV1? authority = null;
        try
        {
            source = WindowsVerifiedLocalReleaseManifestFactory
                .OpenFromOutputsRootForTests(fixture.Root);
            authority = BrokerProductionReleaseAuthorityV1.TakeOwnership(source);
            source.Dispose();
            source = null;
            await action(authority.Binding).ConfigureAwait(false);
        }
        finally
        {
            authority?.Dispose();
            source?.Dispose();
            fixture.Dispose();
        }
    }

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)>
        RunBrokerAppHostAsync(
            string brokerExecutable,
            IReadOnlyList<string> arguments)
    {
        var startInfo = new ProcessStartInfo(brokerExecutable)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException(
            "The malformed Broker apphost probe could not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync().WaitAsync(CaseTimeout).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().ConfigureAwait(false);
            throw new TimeoutException("A malformed Broker apphost invocation did not exit.");
        }

        return (process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    private static async Task<VerifiedGuardianManagedEntryConnectionV1>
        CreateVerifiedGuardianAsync(int discriminator)
    {
        var release = CreateManifest(discriminator).GetArtifactSet(BrokerPeerRole.Guardian);
        var identity = CreateGuardianIdentity(release, discriminator);
        var peerLease = new FakePeerLease(
            identity,
            new RetainedReleaseHandleSet(
                release.Root,
                release.Artifacts.Select(artifact => artifact.RelativePath).ToArray()));
        var platform = new FakeMessagePlatform(release, peerLease, discriminator);
        var verifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            beforeAuthorityTransfer: null,
            afterAuthorityTransfer: null,
            maximumConnections: 1);
        await using var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Client,
            new BrokerPeerExpectation(
                CreateProcessToken(discriminator),
                WindowsAppModelIdentity.Unpackaged,
                release,
                ConnectionNonceFor(discriminator),
                checked(GuardianProcessId + (uint)discriminator),
                GuardianCreationTime.AddSeconds(discriminator)));
        var connection = await pending.CompleteConnectionAsync().ConfigureAwait(false);
        return GuardianManagedEntryProofOfflineTests.CreateVerifiedConnectionFixture(connection);
    }

    private static VerifiedReleaseManifest CreateManifest(int discriminator) =>
        VerifiedReleaseManifest.CreateFromVerifiedPayload(
            ReleaseId + "-" + discriminator,
            ManifestSha256,
            new WindowsReleaseRootIdentity(
                ReleaseRoot + "-" + discriminator,
                FileAttributes.Directory | FileAttributes.Archive,
                checked(VolumeSerial + (ulong)discriminator),
                discriminator.ToString("X32"),
                true),
            CreateRoleDefinition(BrokerPeerRole.Guardian, discriminator),
            CreateRoleDefinition(BrokerPeerRole.Broker, discriminator));

    private static VerifiedReleaseRoleArtifacts CreateRoleDefinition(
        BrokerPeerRole role,
        int discriminator)
    {
        var stem = role == BrokerPeerRole.Broker ? "CodexGuardian.Broker" : "CodexGuardian";
        var root = ReleaseRoot + "-" + discriminator;
        var seed = role == BrokerPeerRole.Guardian ? '1' : '5';
        var artifacts = new[]
        {
            CreateArtifact(root, ReleaseArtifactKind.AppHostExe, stem + ".exe", seed, 128 * 1024, discriminator),
            CreateArtifact(root, ReleaseArtifactKind.ManagedEntryDll, stem + ".dll", (char)(seed + 1), 512 * 1024, discriminator),
            CreateArtifact(root, ReleaseArtifactKind.DepsJson, stem + ".deps.json", (char)(seed + 2), 64 * 1024, discriminator),
            CreateArtifact(root, ReleaseArtifactKind.RuntimeConfigJson, stem + ".runtimeconfig.json", (char)(seed + 3), 4 * 1024, discriminator)
        };
        return new VerifiedReleaseRoleArtifacts(
            role,
            stem + ".exe",
            stem + ".dll",
            stem + ".deps.json",
            stem + ".runtimeconfig.json",
            artifacts);
    }

    private static WindowsArtifactIdentity CreateArtifact(
        string root,
        ReleaseArtifactKind kind,
        string relativePath,
        char seed,
        long length,
        int discriminator) =>
        new(
            kind,
            relativePath,
            Path.Combine(root, relativePath),
            FileAttributes.Archive,
            length,
            new string(seed, 64),
            checked(VolumeSerial + (ulong)discriminator),
            new string(seed, 31) + discriminator.ToString("X1"),
            1,
            true);

    private static WindowsProcessIdentity CreateGuardianIdentity(
        VerifiedReleaseArtifactSet release,
        int discriminator)
    {
        var appHost = release.Artifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe);
        return new WindowsProcessIdentity(
            checked(GuardianProcessId + (uint)discriminator),
            GuardianCreationTime.AddSeconds(discriminator),
            GuardianSessionId,
            CreateProcessToken(discriminator),
            WindowsAppModelIdentity.Unpackaged,
            appHost.FinalPath,
            true,
            release.Root,
            release.Artifacts);
    }

    private static WindowsTokenIdentity CreateProcessToken(int discriminator) =>
        new(
            UserSid,
            LogonSid,
            1,
            checked(0x0000000100000002UL + (ulong)discriminator),
            GuardianSessionId,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Primary,
            null);

    private static WindowsTokenIdentity CreateImpersonationToken(int discriminator) =>
        CreateProcessToken(discriminator) with
        {
            TokenType = WindowsTokenType.Impersonation,
            ImpersonationLevel = WindowsSecurityImpersonationLevel.Identification
        };

    private static BrokerPeerHello CreateGuardianHello(int discriminator) =>
        new(
            BrokerPeerHelloProtocol.ProtocolVersion,
            BrokerPeerRole.Guardian,
            checked(GuardianProcessId + (uint)discriminator),
            GuardianSessionId,
            GuardianCreationTime.AddSeconds(discriminator),
            ConnectionNonceFor(discriminator),
            ReleaseId + "-" + discriminator,
            ManifestSha256);

    private static string ConnectionNonceFor(int discriminator) =>
        ConnectionNonce[..63] + discriminator.ToString("X1");

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().WaitAsync(CaseTimeout + CaseTimeout).ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static async Task<TException> ExpectAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("Expected " + typeof(TException).Name + ".");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeSingletonLease : IBrokerSingleInstanceLeaseV1
    {
        private readonly List<string> _events;
        private readonly Exception? _disposeFailure;
        private int _disposed;

        internal FakeSingletonLease(List<string> events, Exception? disposeFailure)
        {
            _events = events;
            _disposeFailure = disposeFailure;
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _events.Add("singleton-dispose");
                if (_disposeFailure is not null)
                {
                    return ValueTask.FromException(_disposeFailure);
                }
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeFactoryResource : IAsyncDisposable
    {
        private readonly IAsyncDisposable? _owned;
        private readonly Exception? _disposeFailure;
        private readonly TaskCompletionSource? _disposeEntered;
        private readonly TaskCompletionSource? _releaseDispose;
        private int _disposeCount;

        internal FakeFactoryResource(
            IAsyncDisposable? owned = null,
            Exception? disposeFailure = null,
            TaskCompletionSource? disposeEntered = null,
            TaskCompletionSource? releaseDispose = null)
        {
            _owned = owned;
            _disposeFailure = disposeFailure;
            _disposeEntered = disposeEntered;
            _releaseDispose = releaseDispose;
        }

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Increment(ref _disposeCount) != 1)
            {
                return;
            }

            _disposeEntered?.TrySetResult();
            if (_releaseDispose is not null)
            {
                await _releaseDispose.Task.ConfigureAwait(false);
            }

            Exception? failure = null;
            if (_owned is not null)
            {
                try
                {
                    await _owned.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    failure = exception;
                }
            }

            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                failure,
                _disposeFailure);
            if (failure is not null)
            {
                ExceptionDispatchInfo.Capture(failure).Throw();
            }
        }
    }

    private sealed class FakeOwner : IBrokerProductionRuntimeOwnerV1
    {
        private readonly List<string> _events;
        private readonly int _completeOwnerOnAttach;
        private readonly bool _blockStartUntilDispose;
        private readonly bool _blockFirstSessionUntilCancellation;
        private readonly Exception? _firstSessionFailure;
        private readonly Action? _beforeFirstSessionFailure;
        private readonly Exception? _firstSessionDisposeFailure;
        private readonly Exception? _startFailure;
        private readonly Action? _beforeStart;
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _startCompletion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private BrokerProductionReleaseBindingV1? _releaseBinding;
        private int _activeSessions;
        private int _disposed;

        internal FakeOwner(
            List<string> events,
            int completeOwnerOnAttach,
            bool blockStartUntilDispose = false,
            bool blockFirstSessionUntilCancellation = false,
            Exception? firstSessionFailure = null,
            Action? beforeFirstSessionFailure = null,
            Exception? firstSessionDisposeFailure = null,
            Exception? startFailure = null,
            Action? beforeStart = null)
        {
            _events = events;
            _completeOwnerOnAttach = completeOwnerOnAttach;
            _blockStartUntilDispose = blockStartUntilDispose;
            _blockFirstSessionUntilCancellation = blockFirstSessionUntilCancellation;
            _firstSessionFailure = firstSessionFailure;
            _beforeFirstSessionFailure = beforeFirstSessionFailure;
            _firstSessionDisposeFailure = firstSessionDisposeFailure;
            _startFailure = startFailure;
            _beforeStart = beforeStart;
        }

        internal int AttachCount { get; private set; }

        internal int MaximumActiveSessions { get; private set; }

        internal int StartCount { get; private set; }

        internal TaskCompletionSource StartEntered { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal TaskCompletionSource FirstSessionRunEntered { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal bool StartTokenCanBeCanceled { get; private set; }

        internal Exception? DisposeFailure { get; init; }

        public BrokerProductionReleaseBindingV1 ReleaseBinding => _releaseBinding!;

        public Task Completion => _completion.Task;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StartCount++;
            StartTokenCanBeCanceled = cancellationToken.CanBeCanceled;
            _events.Add("owner-start");
            StartEntered.TrySetResult();
            _beforeStart?.Invoke();
            if (_startFailure is not null)
            {
                ExceptionDispatchInfo.Capture(_startFailure).Throw();
            }

            return _blockStartUntilDispose ? _startCompletion.Task : Task.CompletedTask;
        }

        public ValueTask<IBrokerProductionControlSessionV1> AttachGuardianAsync(
            VerifiedGuardianManagedEntryConnectionV1 guardianConnection,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(guardianConnection);
            cancellationToken.ThrowIfCancellationRequested();
            AttachCount++;
            _events.Add("attach-" + AttachCount);
            _activeSessions++;
            MaximumActiveSessions = Math.Max(MaximumActiveSessions, _activeSessions);
            var sessionFailure = AttachCount == 1 ? _firstSessionFailure : null;
            var beforeSessionFailure = AttachCount == 1 ? _beforeFirstSessionFailure : null;
            var session = new FakeSession(
                _events,
                AttachCount,
                guardianConnection,
                completeImmediately: AttachCount == 1 &&
                    sessionFailure is null &&
                    !_blockFirstSessionUntilCancellation,
                failure: sessionFailure,
                beforeFailure: beforeSessionFailure,
                runEntered: AttachCount == 1 ? FirstSessionRunEntered : null,
                disposeFailure: AttachCount == 1 ? _firstSessionDisposeFailure : null,
                onDispose: () => _activeSessions--);
            if (_completeOwnerOnAttach == AttachCount)
            {
                Complete();
            }

            return ValueTask.FromResult<IBrokerProductionControlSessionV1>(session);
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _events.Add("owner-dispose");
                _startCompletion.TrySetCanceled();
                if (DisposeFailure is not null)
                {
                    return ValueTask.FromException(DisposeFailure);
                }
            }

            return ValueTask.CompletedTask;
        }

        internal void Complete() => _completion.TrySetResult();

        internal void Fail(Exception failure) => _completion.TrySetException(failure);

        internal void BindReleaseBinding(BrokerProductionReleaseBindingV1 releaseBinding)
        {
            ArgumentNullException.ThrowIfNull(releaseBinding);
            if (_releaseBinding is not null)
            {
                throw new InvalidOperationException("The fake owner release authority was bound twice.");
            }

            _releaseBinding = releaseBinding;
        }
    }

    private sealed class FakeSession : IBrokerProductionControlSessionV1
    {
        private readonly List<string> _events;
        private readonly int _ordinal;
        private readonly VerifiedGuardianManagedEntryConnectionV1 _guardian;
        private readonly bool _completeImmediately;
        private readonly Exception? _failure;
        private readonly Action? _beforeFailure;
        private readonly TaskCompletionSource? _runEntered;
        private readonly Exception? _disposeFailure;
        private readonly Action _onDispose;
        private int _disposed;

        internal FakeSession(
            List<string> events,
            int ordinal,
            VerifiedGuardianManagedEntryConnectionV1 guardian,
            bool completeImmediately,
            Exception? failure,
            Action? beforeFailure,
            TaskCompletionSource? runEntered,
            Exception? disposeFailure,
            Action onDispose)
        {
            _events = events;
            _ordinal = ordinal;
            _guardian = guardian;
            _completeImmediately = completeImmediately;
            _failure = failure;
            _beforeFailure = beforeFailure;
            _runEntered = runEntered;
            _disposeFailure = disposeFailure;
            _onDispose = onDispose;
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            _events.Add("session-run-" + _ordinal);
            _runEntered?.TrySetResult();
            if (_failure is not null)
            {
                _beforeFailure?.Invoke();
                ExceptionDispatchInfo.Capture(_failure).Throw();
            }

            if (_completeImmediately)
            {
                return;
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _events.Add("session-dispose-" + _ordinal);
            Exception? failure = null;
            try
            {
                await _guardian.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = exception;
            }
            finally
            {
                _onDispose();
            }

            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                failure,
                _disposeFailure);
            if (failure is not null)
            {
                ExceptionDispatchInfo.Capture(failure).Throw();
            }
        }
    }

    private sealed class FakeAdmissionSource : IBrokerGuardianAdmissionSourceV1
    {
        private readonly List<string> _events;
        private readonly Queue<VerifiedGuardianManagedEntryConnectionV1> _guardians;
        private readonly bool _failFirstAdmission;
        private readonly Exception? _cancellationCallbackFailure;
        private readonly Exception? _cancellationReplacementFailure;
        private readonly Exception? _firstAdmissionFailure;
        private readonly Exception? _secondAdmissionFailure;
        private readonly bool _allowsSuccessorAdmission;
        private BrokerProductionReleaseBindingV1? _releaseBinding;
        private int _acceptCount;
        private int _disposed;
        private bool _unhealthy;

        internal FakeAdmissionSource(
            List<string> events,
            IEnumerable<VerifiedGuardianManagedEntryConnectionV1> guardians,
            bool failFirstAdmission = false,
            Exception? cancellationCallbackFailure = null,
            Exception? cancellationReplacementFailure = null,
            Exception? firstAdmissionFailure = null,
            Exception? secondAdmissionFailure = null,
            bool allowsSuccessorAdmission = true)
        {
            _events = events;
            _guardians = new Queue<VerifiedGuardianManagedEntryConnectionV1>(guardians);
            _failFirstAdmission = failFirstAdmission;
            _cancellationCallbackFailure = cancellationCallbackFailure;
            _cancellationReplacementFailure = cancellationReplacementFailure;
            _firstAdmissionFailure = firstAdmissionFailure;
            _secondAdmissionFailure = secondAdmissionFailure;
            _allowsSuccessorAdmission = allowsSuccessorAdmission;
        }

        internal TaskCompletionSource AcceptEntered { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal Exception? DisposeFailure { get; init; }

        internal int AcceptCount => Volatile.Read(ref _acceptCount);

        public BrokerProductionReleaseBindingV1 ReleaseBinding => _releaseBinding!;

        public NamedPipePeerTrustHealth Health => new(
            IsUnhealthy: _unhealthy,
            RejectNewHandshakes: _unhealthy,
            ActiveConnectionCount: 0,
            QuarantinedHandshakeCount: _unhealthy ? 1 : 0,
            Capacity: 1);

        public bool AllowsSuccessorAdmission => _allowsSuccessorAdmission;

        public async ValueTask<VerifiedGuardianManagedEntryConnectionV1> AcceptAsync(
            CancellationToken cancellationToken)
        {
            var ordinal = Interlocked.Increment(ref _acceptCount);
            _events.Add("accept-" + ordinal);
            if (ordinal == 1)
            {
                _events[_events.Count - 1] = "accept-enter";
                AcceptEntered.TrySetResult();
            }

            if (_failFirstAdmission && ordinal == 1)
            {
                _unhealthy = true;
                throw new IOException("synthetic-admission-rejected");
            }

            if (ordinal == 1 && _firstAdmissionFailure is not null)
            {
                ExceptionDispatchInfo.Capture(_firstAdmissionFailure).Throw();
            }
            if (ordinal == 2 && _secondAdmissionFailure is not null)
            {
                ExceptionDispatchInfo.Capture(_secondAdmissionFailure).Throw();
            }

            if (_guardians.Count > 0)
            {
                return _guardians.Dequeue();
            }

            using var cancellationRegistration = _cancellationCallbackFailure is null
                ? default
                : cancellationToken.UnsafeRegister(
                    static state => throw (Exception)state!,
                    _cancellationCallbackFailure);
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_cancellationReplacementFailure is not null)
            {
                ExceptionDispatchInfo.Capture(_cancellationReplacementFailure).Throw();
            }

            throw new InvalidOperationException("Unreachable blocked admission.");
        }

        public BrokerGuardianAdmissionFailureDispositionV1 ClassifyFailure(Exception exception) =>
            exception is IOException
                ? BrokerGuardianAdmissionFailureDispositionV1.RejectConnection
                : BrokerGuardianAdmissionFailureDispositionV1.Terminal;

        public BrokerGuardianConnectionFailureDispositionV1 ClassifyConnectionFailure(
            Exception exception) =>
            exception is IOException
                ? BrokerGuardianConnectionFailureDispositionV1.Disconnect
                : BrokerGuardianConnectionFailureDispositionV1.Terminal;

        internal void BindReleaseBinding(BrokerProductionReleaseBindingV1 releaseBinding)
        {
            ArgumentNullException.ThrowIfNull(releaseBinding);
            if (_releaseBinding is not null)
            {
                throw new InvalidOperationException(
                    "The fake admission release authority was bound twice.");
            }

            _releaseBinding = releaseBinding;
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _events.Add("admission-dispose");
            Exception? failure = null;
            while (_guardians.TryDequeue(out var guardian))
            {
                try
                {
                    await guardian.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                        failure,
                        exception);
                }
            }

            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                failure,
                DisposeFailure);
            if (failure is not null)
            {
                throw failure;
            }
        }
    }

    private sealed class FakeMessagePlatform :
        INamedPipePeerTrustPlatform,
        INamedPipePeerMessageTransport
    {
        private readonly VerifiedReleaseArtifactSet _release;
        private readonly FakePeerLease _peerLease;
        private readonly int _discriminator;
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private long _readGeneration;
        private int _disposed;

        internal FakeMessagePlatform(
            VerifiedReleaseArtifactSet release,
            FakePeerLease peerLease,
            int discriminator)
        {
            _release = release;
            _peerLease = peerLease;
            _discriminator = discriminator;
        }

        public DateTimeOffset UtcNow => GuardianCreationTime.AddMinutes(1);

        public long ReadGeneration => Volatile.Read(ref _readGeneration);

        public Task Completion => _completion.Task;

        public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
        {
            Ensure(peerKind == NamedPipePeerKind.Client, "fake platform used the wrong direction");
            return new PipePeerKernelIdentity(
                checked(GuardianProcessId + (uint)_discriminator),
                GuardianSessionId);
        }

        public IRetainedPeerIdentityLease OpenRetainedPeer(
            uint processId,
            VerifiedReleaseArtifactSet release)
        {
            Ensure(
                processId == GuardianProcessId + (uint)_discriminator &&
                ReferenceEquals(release, _release),
                "fake platform opened the wrong retained peer");
            return _peerLease;
        }

        public ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
            NamedPipePeerKind peerKind,
            int maximumHelloBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hello = BrokerPeerHelloProtocol.Serialize(CreateGuardianHello(_discriminator));
            Ensure(hello.Length <= maximumHelloBytes, "fake hello exceeded the bound");
            var kernel = CaptureKernelPeer(peerKind);
            return ValueTask.FromResult(new PipePeerHelloReadEvidence(
                hello,
                Interlocked.Increment(ref _readGeneration),
                kernel,
                kernel,
                CreateImpersonationToken(_discriminator)));
        }

        public void AbortHandshake(string boundedFailureCode) =>
            ArgumentException.ThrowIfNullOrWhiteSpace(boundedFailureCode);

        public async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
            int maximumMessageBytes,
            CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            return ReadOnlyMemory<byte>.Empty;
        }

        public ValueTask WriteMessageAsync(
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _completion.TrySetResult();
            }
        }
    }

    private sealed class FakePeerLease : IRetainedPeerIdentityLease
    {
        private readonly WindowsProcessIdentity _identity;
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

        public WindowsProcessIdentity Capture()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _identity;
        }

        public void Dispose() => Interlocked.Exchange(ref _disposed, 1);
    }
}
