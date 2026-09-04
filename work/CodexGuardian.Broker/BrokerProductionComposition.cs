using CodexGuardian.Control;
using CodexGuardian.Trust;
using System;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal static class BrokerProductionCompositionV1
{
    internal static BrokerProductionHostV1 CreateHost() =>
        new(new BrokerProductionHostFactoriesV1(
            AcquireSingleInstance,
            WindowsVerifiedLocalReleaseManifestFactory.OpenCurrentRelease,
            BrokerProductionRuntimeOwnerFactoryV1.CreateAsync,
            WindowsGuardianProductionAdmissionV1.Create));

    private static IBrokerSingleInstanceLeaseV1 AcquireSingleInstance()
    {
        var platform = new WindowsCodexPackageBaselinePlatform();
        var currentUserSid = platform.ReadCurrentUserSid();
        var currentSessionId = platform.ReadCurrentSessionId();
        if (currentSessionId == 0)
        {
            throw new BrokerProductionHostException(
                "broker-session-id-invalid",
                "The production Broker cannot own the Windows service session.");
        }

        return BrokerSingleInstanceLeaseV1.Acquire(currentUserSid, currentSessionId);
    }
}

internal static class BrokerProductionRuntimeOwnerFactoryV1
{
    internal static ValueTask<IBrokerProductionRuntimeOwnerV1> CreateAsync(
        BrokerProductionReleaseBindingV1 releaseBinding)
    {
        ArgumentNullException.ThrowIfNull(releaseBinding);
        return CreateCoreAsync(
            static () => new WindowsCodexCdpRuntimeControlHostV1(),
            static runtime => new BrokerRuntimeOwnerV1(
                runtime,
                CodexCdpBrokerProtocol.CreateBrokerEpoch()),
            owner => (IBrokerProductionRuntimeOwnerV1)
                new BrokerRuntimeOwnerProductionAdapterV1(owner, releaseBinding));
    }

#if CODEXGUARDIAN_TEST_FRIEND
    internal static ValueTask<IBrokerProductionRuntimeOwnerV1> CreateForTestsAsync(
        BrokerProductionReleaseBindingV1 releaseBinding,
        Func<IAsyncDisposable> createRuntime,
        Func<IAsyncDisposable, IAsyncDisposable> createOwner,
        Func<
            IAsyncDisposable,
            BrokerProductionReleaseBindingV1,
            IBrokerProductionRuntimeOwnerV1> createAdapter)
    {
        ArgumentNullException.ThrowIfNull(releaseBinding);
        ArgumentNullException.ThrowIfNull(createRuntime);
        ArgumentNullException.ThrowIfNull(createOwner);
        ArgumentNullException.ThrowIfNull(createAdapter);
        return CreateCoreAsync(
            createRuntime,
            createOwner,
            owner => createAdapter(owner, releaseBinding));
    }
#endif

    private static async ValueTask<TResult> CreateCoreAsync<TRuntime, TOwner, TResult>(
        Func<TRuntime> createRuntime,
        Func<TRuntime, TOwner> createOwner,
        Func<TOwner, TResult> createAdapter)
        where TRuntime : class, IAsyncDisposable
        where TOwner : class, IAsyncDisposable
        where TResult : class
    {
        TRuntime? runtime = null;
        TOwner? owner = null;
        try
        {
            runtime = createRuntime() ?? throw new InvalidOperationException(
                "The production runtime factory returned no runtime authority.");
            owner = createOwner(runtime) ?? throw new InvalidOperationException(
                "The production owner factory returned no runtime owner.");
            runtime = null;
            var adapter = createAdapter(owner) ?? throw new InvalidOperationException(
                "The production owner adapter factory returned no owner adapter.");
            owner = null;
            return adapter;
        }
        catch (Exception constructionFailure)
        {
            var cleanupFailure = owner is not null
                ? await CaptureDisposeFailureAsync(owner).ConfigureAwait(false)
                : runtime is not null
                    ? await CaptureDisposeFailureAsync(runtime).ConfigureAwait(false)
                    : null;
            var failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                constructionFailure,
                cleanupFailure)!;
            ExceptionDispatchInfo.Capture(failure).Throw();
            throw new InvalidOperationException("Unreachable production owner factory failure.");
        }
    }

    private static async ValueTask<Exception?> CaptureDisposeFailureAsync(
        IAsyncDisposable disposable)
    {
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
}
