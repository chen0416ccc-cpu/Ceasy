using CodexGuardian.Control;
using CodexGuardian.Trust;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal sealed class BrokerProductionHostException : InvalidOperationException
{
    internal BrokerProductionHostException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(code))
        {
            throw new ArgumentException(
                "A bounded Broker production-host failure code is required.",
                nameof(code));
        }

        Code = code;
    }

    internal string Code { get; }
}

internal sealed class BrokerProductionReleaseBindingV1
{
    private readonly VerifiedLocalReleaseLeaseV1 _authority;

    internal BrokerProductionReleaseBindingV1(VerifiedLocalReleaseLeaseV1 authority)
    {
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
        Manifest = authority.Manifest;
        _ = Manifest.GetArtifactSet(BrokerPeerRole.Guardian);
        _ = Manifest.GetArtifactSet(BrokerPeerRole.Broker);
    }

    internal VerifiedReleaseManifest Manifest { get; }

    internal IRetainedPeerIdentityLease OpenGuardianProcess(
        SafeProcessHandle exactProcessHandle) =>
        WindowsVerifiedLocalReleasePeerAuthorityV1.OpenRetainedProcess(
            _authority,
            BrokerPeerRole.Guardian,
            exactProcessHandle);

    internal IRetainedPeerIdentityLease OpenBrokerProcess(
        SafeProcessHandle exactProcessHandle) =>
        WindowsVerifiedLocalReleasePeerAuthorityV1.OpenRetainedProcess(
            _authority,
            BrokerPeerRole.Broker,
            exactProcessHandle);

    internal WindowsConnectedClientPeerTrustPlatform TakeConnectedGuardianClient(
        WindowsSameLogonNamedPipeServer connectedServer,
        SafeProcessHandle exactProcessHandle) =>
        WindowsVerifiedLocalReleasePeerAuthorityV1.TakeConnectedGuardianClient(
            _authority,
            connectedServer,
            exactProcessHandle);
}

internal sealed class BrokerProductionReleaseAuthorityV1 : IDisposable
{
    private readonly object _gate = new();
    private VerifiedLocalReleaseLeaseV1? _releaseLease;
    private Exception? _disposeFailure;
    private bool _disposed;

    private BrokerProductionReleaseAuthorityV1(VerifiedLocalReleaseLeaseV1 releaseLease)
    {
        _releaseLease = releaseLease ?? throw new ArgumentNullException(nameof(releaseLease));
        Binding = new BrokerProductionReleaseBindingV1(releaseLease);
    }

    internal BrokerProductionReleaseBindingV1 Binding { get; }

    internal static BrokerProductionReleaseAuthorityV1 TakeOwnership(
        VerifiedLocalReleaseLeaseV1 source)
    {
        ArgumentNullException.ThrowIfNull(source);
        _ = source.Manifest.GetArtifactSet(BrokerPeerRole.Guardian);
        _ = source.Manifest.GetArtifactSet(BrokerPeerRole.Broker);
        var owned = source.TakeOwnership();
        try
        {
            return new BrokerProductionReleaseAuthorityV1(owned);
        }
        catch
        {
            owned.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        lock (_gate)
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
            var releaseLease = _releaseLease;
            _releaseLease = null;
            try
            {
                releaseLease?.Dispose();
            }
            catch (Exception exception)
            {
                _disposeFailure = exception;
                ExceptionDispatchInfo.Capture(exception).Throw();
            }
        }
    }
}

internal sealed record BrokerProductionHostFactoriesV1(
    Func<IBrokerSingleInstanceLeaseV1> AcquireSingleInstance,
    Func<VerifiedLocalReleaseLeaseV1> OpenReleaseLease,
    Func<
        BrokerProductionReleaseBindingV1,
        ValueTask<IBrokerProductionRuntimeOwnerV1>> CreateOwnerAsync,
    Func<BrokerProductionReleaseBindingV1, IBrokerGuardianAdmissionSourceV1>
        CreateAdmissionSource)
{
    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(AcquireSingleInstance);
        ArgumentNullException.ThrowIfNull(OpenReleaseLease);
        ArgumentNullException.ThrowIfNull(CreateOwnerAsync);
        ArgumentNullException.ThrowIfNull(CreateAdmissionSource);
    }
}

internal sealed class BrokerProductionHostV1
{
    private readonly BrokerProductionHostFactoriesV1 _factories;
    private int _runStarted;

    internal BrokerProductionHostV1(BrokerProductionHostFactoriesV1 factories)
    {
        _factories = factories ?? throw new ArgumentNullException(nameof(factories));
        _factories.Validate();
    }

    internal Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _runStarted, 1) != 0)
        {
            return Task.FromException(new InvalidOperationException(
                "The Broker production host can run only once."));
        }

        return RunCoreAsync(cancellationToken);
    }

    private async Task RunCoreAsync(CancellationToken cancellationToken)
    {
        IBrokerSingleInstanceLeaseV1? singleton = null;
        VerifiedLocalReleaseLeaseV1? releaseLease = null;
        BrokerProductionReleaseAuthorityV1? releaseAuthority = null;
        IBrokerProductionRuntimeOwnerV1? owner = null;
        IBrokerGuardianAdmissionSourceV1? admissions = null;
        Exception? failure = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // The singleton is deliberately acquired before every release, runtime,
            // listener, or reconciliation side effect.
            singleton = _factories.AcquireSingleInstance() ??
                throw FactoryFailure(
                    "broker-singleton-factory-invalid",
                    "The Broker singleton factory returned no lifetime authority.");
            releaseLease = _factories.OpenReleaseLease() ??
                throw FactoryFailure(
                    "broker-release-authority-invalid",
                    "The Broker release factory returned no pinned authority.");
            releaseAuthority = BrokerProductionReleaseAuthorityV1.TakeOwnership(releaseLease);
            releaseLease.Dispose();
            releaseLease = null;
            var releaseBinding = releaseAuthority.Binding;
            owner = await _factories.CreateOwnerAsync(releaseBinding).ConfigureAwait(false);
            if (owner is null)
            {
                throw FactoryFailure(
                    "broker-runtime-owner-invalid",
                    "The Broker runtime owner factory returned no owner.");
            }

            if (!ReferenceEquals(owner.ReleaseBinding, releaseBinding))
            {
                throw FactoryFailure(
                    "broker-runtime-owner-release-mismatch",
                    "The Broker runtime owner is not bound to the pinned release authority.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            // Startup belongs to the owner. The host bounds only its wait so cancellation
            // always reaches reverse cleanup, which then cancels the owner's lifetime.
            await owner.StartAsync(CancellationToken.None)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            if (owner.Completion.IsCompleted)
            {
                await owner.Completion.ConfigureAwait(false);
            }
            else
            {
                cancellationToken.ThrowIfCancellationRequested();
                admissions = _factories.CreateAdmissionSource(releaseBinding) ??
                    throw FactoryFailure(
                        "broker-admission-source-invalid",
                        "The Broker admission factory returned no source.");
                if (!ReferenceEquals(admissions.ReleaseBinding, releaseBinding))
                {
                    throw FactoryFailure(
                        "broker-admission-release-mismatch",
                        "The Broker admission source is not bound to the pinned release authority.");
                }

                var acceptLoop = new BrokerGuardianAcceptLoopV1(owner, admissions);
                await acceptLoop.RunAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException exception) when (
            IsHostCancellation(exception, cancellationToken))
        {
            if (owner?.Completion.IsFaulted == true)
            {
                failure = await CaptureFailureAsync(
                        async () => await owner.Completion.ConfigureAwait(false))
                    .ConfigureAwait(false);
                failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    failure,
                    exception,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey);
            }
            else if (HasAttachedArbitrationFailure(exception))
            {
                // Host cancellation is graceful only when it carries no evidence that
                // session settlement or another concurrent operation failed.
                failure = exception;
            }
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        // Fixed reverse cleanup: admission/session transport, runtime owner, pinned
        // release authority, and finally the process-lifetime singleton.
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            await DisposeAsync(admissions).ConfigureAwait(false));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            await DisposeAsync(owner).ConfigureAwait(false));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            Dispose(releaseAuthority));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            Dispose(releaseLease));
        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            await DisposeAsync(singleton).ConfigureAwait(false));

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
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

    private static async Task<Exception?> CaptureFailureAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static bool IsHostCancellation(
        OperationCanceledException exception,
        CancellationToken cancellationToken) =>
        cancellationToken.IsCancellationRequested &&
        exception.CancellationToken == cancellationToken;

    private static bool HasAttachedArbitrationFailure(Exception failure)
    {
        if (failure.Data[BrokerControlFailureArbitration.CleanupFailureDataKey] is Exception ||
            failure.Data[BrokerControlFailureArbitration.ConcurrentFailureDataKey] is Exception)
        {
            return true;
        }

        if (failure is AggregateException aggregate)
        {
            foreach (var inner in aggregate.InnerExceptions)
            {
                if (HasAttachedArbitrationFailure(inner))
                {
                    return true;
                }
            }
        }

        return failure.InnerException is not null &&
            HasAttachedArbitrationFailure(failure.InnerException);
    }

    private static BrokerProductionHostException FactoryFailure(
        string code,
        string message) => new(code, message);
}
