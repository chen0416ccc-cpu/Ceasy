using CodexGuardian.Trust;
using System;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal enum BrokerGuardianAdmissionFailureDispositionV1
{
    RejectConnection,
    Terminal
}

internal enum BrokerGuardianConnectionFailureDispositionV1
{
    Disconnect,
    Terminal
}

internal interface IBrokerGuardianAdmissionSourceV1 : IAsyncDisposable
{
    BrokerProductionReleaseBindingV1 ReleaseBinding { get; }

    NamedPipePeerTrustHealth Health { get; }

    bool AllowsSuccessorAdmission { get; }

    ValueTask<VerifiedGuardianManagedEntryConnectionV1> AcceptAsync(
        CancellationToken cancellationToken);

    BrokerGuardianAdmissionFailureDispositionV1 ClassifyFailure(Exception exception);

    BrokerGuardianConnectionFailureDispositionV1 ClassifyConnectionFailure(
        Exception exception);
}

internal interface IBrokerProductionControlSessionV1 : IAsyncDisposable
{
    Task RunAsync(CancellationToken cancellationToken);
}

internal interface IBrokerProductionRuntimeOwnerV1 : IAsyncDisposable
{
    BrokerProductionReleaseBindingV1 ReleaseBinding { get; }

    Task Completion { get; }

    Task StartAsync(CancellationToken cancellationToken);

    ValueTask<IBrokerProductionControlSessionV1> AttachGuardianAsync(
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection,
        CancellationToken cancellationToken);
}

internal sealed class BrokerRuntimeOwnerProductionAdapterV1 : IBrokerProductionRuntimeOwnerV1
{
    private readonly BrokerRuntimeOwnerV1 _owner;

    internal BrokerRuntimeOwnerProductionAdapterV1(
        BrokerRuntimeOwnerV1 owner,
        BrokerProductionReleaseBindingV1 releaseBinding)
    {
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));
        ReleaseBinding = releaseBinding ?? throw new ArgumentNullException(nameof(releaseBinding));
    }

    public BrokerProductionReleaseBindingV1 ReleaseBinding { get; }

    public Task Completion => _owner.Completion;

    public Task StartAsync(CancellationToken cancellationToken) =>
        _owner.StartAsync(cancellationToken);

    public async ValueTask<IBrokerProductionControlSessionV1> AttachGuardianAsync(
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(guardianConnection);
        var session = await _owner.AttachGuardianAsync(
                guardianConnection,
                cancellationToken)
            .ConfigureAwait(false);
        return new BrokerControlSessionProductionAdapterV1(session);
    }

    public ValueTask DisposeAsync() => _owner.DisposeAsync();
}

internal sealed class BrokerControlSessionProductionAdapterV1 : IBrokerProductionControlSessionV1
{
    private readonly BrokerControlSessionV1 _session;

    internal BrokerControlSessionProductionAdapterV1(BrokerControlSessionV1 session)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
    }

    public Task RunAsync(CancellationToken cancellationToken) =>
        _session.RunAsync(cancellationToken);

    public ValueTask DisposeAsync() => _session.DisposeAsync();
}

internal sealed class BrokerGuardianAcceptLoopV1
{
    private readonly IBrokerProductionRuntimeOwnerV1 _owner;
    private readonly IBrokerGuardianAdmissionSourceV1 _admissions;
    private int _runStarted;

    internal BrokerGuardianAcceptLoopV1(
        IBrokerProductionRuntimeOwnerV1 owner,
        IBrokerGuardianAdmissionSourceV1 admissions)
    {
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));
        _admissions = admissions ?? throw new ArgumentNullException(nameof(admissions));
    }

    internal async Task RunAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _runStarted, 1) != 0)
        {
            throw new InvalidOperationException(
                "The Broker Guardian accept loop can run only once.");
        }

        while (true)
        {
            var terminal = await ReadOwnerTerminalAsync().ConfigureAwait(false);
            if (terminal.IsTerminal)
            {
                ThrowTerminalFailure(terminal.Failure);
                return;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                terminal = await ReadOwnerTerminalAsync().ConfigureAwait(false);
                if (terminal.IsTerminal)
                {
                    ThrowTerminalFailure(terminal.Failure);
                }

                return;
            }

            ThrowIfTrustUnhealthy();
            VerifiedGuardianManagedEntryConnectionV1? guardian = null;
            try
            {
                guardian = await AwaitAdmissionOrOwnerAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (guardian is null)
                {
                    return;
                }
            }
            catch (Exception exception)
            {
                terminal = await ReadOwnerTerminalAsync().ConfigureAwait(false);
                if (terminal.IsTerminal)
                {
                    throw CombinePrimaryAndSecondary(terminal.Failure, exception) ?? exception;
                }

                if (IsExpectedHostCancellation(exception, cancellationToken))
                {
                    return;
                }

                if (HasAttachedArbitrationFailure(exception))
                {
                    ExceptionDispatchInfo.Capture(exception).Throw();
                }

                if (_admissions.Health.RejectNewHandshakes)
                {
                    throw TrustUnhealthy(exception);
                }

                if (_admissions.ClassifyFailure(exception) ==
                    BrokerGuardianAdmissionFailureDispositionV1.RejectConnection)
                {
                    continue;
                }

                throw;
            }

            if (_admissions.Health.RejectNewHandshakes)
            {
                var unhealthy = TrustUnhealthy(innerException: null);
                var rejectedGuardian = guardian!;
                var admissionCleanup = await CaptureFailureAsync(
                        () => rejectedGuardian.DisposeAsync().AsTask())
                    .ConfigureAwait(false);
                throw BrokerControlFailureArbitration.PreserveCleanupFailure(
                    unhealthy,
                    admissionCleanup)!;
            }
            IBrokerProductionControlSessionV1? session = null;
            Exception? connectionFailure = null;
            try
            {
                // Attach consumes the verified wrapper on every success or failure path.
                var transferredGuardian = guardian!;
                guardian = null;
                session = await _owner.AttachGuardianAsync(
                        transferredGuardian,
                        cancellationToken)
                    .ConfigureAwait(false);
                connectionFailure = await AwaitSessionOrOwnerAsync(
                        session,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                connectionFailure = exception;
            }

            Exception? cleanupFailure = null;
            if (guardian is not null)
            {
                var untransferredGuardian = guardian;
                cleanupFailure = await CaptureFailureAsync(
                        () => untransferredGuardian.DisposeAsync().AsTask())
                    .ConfigureAwait(false);
            }

            if (session is not null)
            {
                var sessionCleanup = await CaptureFailureAsync(
                        () => session.DisposeAsync().AsTask())
                    .ConfigureAwait(false);
                if (!BrokerControlFailureArbitration.ContainsFailure(
                        connectionFailure,
                        sessionCleanup))
                {
                    cleanupFailure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                        cleanupFailure,
                        sessionCleanup);
                }
            }

            terminal = await ReadOwnerTerminalAsync().ConfigureAwait(false);
            if (terminal.IsTerminal)
            {
                var failure = CombinePrimaryAndSecondary(
                    terminal.Failure,
                    SelectUnexpectedHostCancellation(
                        connectionFailure,
                        cancellationToken));
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    cleanupFailure);
                ThrowTerminalFailure(failure);
                return;
            }

            if (cleanupFailure is not null)
            {
                throw BrokerControlFailureArbitration.PreserveCleanupFailure(
                    connectionFailure,
                    cleanupFailure)!;
            }

            if (connectionFailure is not null)
            {
                if (IsExpectedHostCancellation(connectionFailure, cancellationToken))
                {
                    return;
                }

                if (HasAttachedArbitrationFailure(connectionFailure))
                {
                    ExceptionDispatchInfo.Capture(connectionFailure).Throw();
                }
            }

            if (_admissions.Health.RejectNewHandshakes)
            {
                throw TrustUnhealthy(connectionFailure);
            }

            if (connectionFailure is not null)
            {
                if (_admissions.ClassifyConnectionFailure(connectionFailure) ==
                    BrokerGuardianConnectionFailureDispositionV1.Disconnect)
                {
                    continue;
                }

                ExceptionDispatchInfo.Capture(connectionFailure).Throw();
            }

            if (!_admissions.AllowsSuccessorAdmission)
            {
                return;
            }

            // An isolated Guardian disconnect or protocol failure must not cancel the
            // Broker owner. The next admission starts only after exact session cleanup.
        }
    }

    private async ValueTask<VerifiedGuardianManagedEntryConnectionV1?>
        AwaitAdmissionOrOwnerAsync(CancellationToken cancellationToken)
    {
        using var operationCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var admissionTask = _admissions.AcceptAsync(operationCancellation.Token).AsTask();
        var first = await Task.WhenAny(admissionTask, _owner.Completion).ConfigureAwait(false);
        if (ReferenceEquals(first, admissionTask))
        {
            try
            {
                return await admissionTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException exception) when (
                cancellationToken.IsCancellationRequested &&
                exception.CancellationToken == operationCancellation.Token)
            {
                throw new OperationCanceledException(
                    "The Broker Guardian admission was canceled by the production host.",
                    exception,
                    cancellationToken);
            }
        }

        var cancellationFailure = CancelAndCaptureFailure(operationCancellation);
        var admissionFailure = await CaptureFailureAsync(async () =>
        {
            var lateAdmission = await admissionTask.ConfigureAwait(false);
            await lateAdmission.DisposeAsync().ConfigureAwait(false);
        }).ConfigureAwait(false);
        admissionFailure = SelectUnexpectedCancellation(
            admissionFailure,
            operationCancellation.Token,
            cancellationToken);
        admissionFailure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            admissionFailure,
            cancellationFailure);
        var ownerFailure = await CaptureFailureAsync(
                async () => await _owner.Completion.ConfigureAwait(false))
            .ConfigureAwait(false);
        ownerFailure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            ownerFailure,
            admissionFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        ThrowTerminalFailure(ownerFailure);
        return null;
    }

    private async Task<Exception?> AwaitSessionOrOwnerAsync(
        IBrokerProductionControlSessionV1 session,
        CancellationToken cancellationToken)
    {
        using var operationCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var sessionTask = session.RunAsync(operationCancellation.Token);
        var first = await Task.WhenAny(sessionTask, _owner.Completion).ConfigureAwait(false);
        if (ReferenceEquals(first, sessionTask))
        {
            var sessionFailure = await CaptureFailureAsync(async () =>
                    await sessionTask.ConfigureAwait(false))
                .ConfigureAwait(false);
            return NormalizeHostCancellation(
                sessionFailure,
                operationCancellation.Token,
                cancellationToken);
        }

        var cancellationFailure = CancelAndCaptureFailure(operationCancellation);
        var failure = await CaptureFailureAsync(async () =>
                await sessionTask.ConfigureAwait(false))
            .ConfigureAwait(false);
        failure = SelectUnexpectedCancellation(
            failure,
            operationCancellation.Token,
            cancellationToken);
        return BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            cancellationFailure);
    }

    private async ValueTask<BrokerOwnerTerminalV1> ReadOwnerTerminalAsync()
    {
        if (!_owner.Completion.IsCompleted)
        {
            return new BrokerOwnerTerminalV1(false, null);
        }

        var failure = await CaptureFailureAsync(
                async () => await _owner.Completion.ConfigureAwait(false))
            .ConfigureAwait(false);
        return new BrokerOwnerTerminalV1(true, failure);
    }

    private void ThrowIfTrustUnhealthy()
    {
        if (_admissions.Health.RejectNewHandshakes)
        {
            throw TrustUnhealthy(innerException: null);
        }
    }

    private static BrokerProductionHostException TrustUnhealthy(Exception? innerException) =>
        new(
            "broker-peer-trust-unhealthy",
            "The Broker peer verifier cannot prove cleanup and rejected new handshakes.",
            innerException);

    private static bool IsExpectedHostCancellation(
        Exception failure,
        CancellationToken cancellationToken) =>
        cancellationToken.IsCancellationRequested &&
        failure is OperationCanceledException cancellation &&
        cancellation.CancellationToken == cancellationToken &&
        !HasAttachedArbitrationFailure(failure);

    private static Exception? SelectUnexpectedHostCancellation(
        Exception? failure,
        CancellationToken hostCancellationToken) =>
        failure is not null &&
        IsExpectedHostCancellation(failure, hostCancellationToken)
            ? null
            : failure;

    private static Exception? SelectUnexpectedCancellation(
        Exception? failure,
        CancellationToken operationCancellationToken,
        CancellationToken hostCancellationToken)
    {
        if (failure is not OperationCanceledException cancellation ||
            HasAttachedArbitrationFailure(failure))
        {
            return failure;
        }

        var expectedOperationCancellation =
            operationCancellationToken.IsCancellationRequested &&
            cancellation.CancellationToken == operationCancellationToken;
        var expectedHostCancellation =
            hostCancellationToken.IsCancellationRequested &&
            cancellation.CancellationToken == hostCancellationToken;
        return expectedOperationCancellation || expectedHostCancellation
            ? null
            : failure;
    }

    private static Exception? NormalizeHostCancellation(
        Exception? failure,
        CancellationToken operationCancellationToken,
        CancellationToken hostCancellationToken)
    {
        if (hostCancellationToken.IsCancellationRequested &&
            failure is OperationCanceledException cancellation &&
            cancellation.CancellationToken == operationCancellationToken &&
            !HasAttachedArbitrationFailure(failure))
        {
            return new OperationCanceledException(
                "The Broker Guardian session was canceled by the production host.",
                cancellation,
                hostCancellationToken);
        }

        return failure;
    }

    private static Exception? CombinePrimaryAndSecondary(
        Exception? primary,
        Exception? secondary)
    {
        if (primary is null)
        {
            return secondary;
        }

        return BrokerControlFailureArbitration.PreserveSecondaryFailure(
            primary,
            secondary,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
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

    private static Exception? CancelAndCaptureFailure(
        CancellationTokenSource cancellation)
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

    private static void ThrowTerminalFailure(Exception? failure)
    {
        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private sealed record BrokerOwnerTerminalV1(bool IsTerminal, Exception? Failure);
}
