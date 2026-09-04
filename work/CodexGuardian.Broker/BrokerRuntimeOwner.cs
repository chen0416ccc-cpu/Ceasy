using CodexGuardian.Control;
using CodexGuardian.Trust;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal sealed record BrokerOwnerCommandExecutionV1(
    CodexCdpBrokerApplyResult Result,
    CodexCdpBrokerSnapshot? InitiatingSessionSnapshot);

internal sealed class BrokerRuntimeOwnerV1 : IAsyncDisposable
{
    private const int MaximumPublicationBacklog = 1024;
    private const string RuntimeExitFailureCodeDataKey =
        "runtime-exit-failure-code";

    private readonly object _lifecycleGate = new();
    private readonly object _publicationGate = new();
    private readonly ICodexCdpRuntimeControlHost _runtimeHost;
    private readonly CodexCdpBrokerStateMachine _stateMachine;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly SemaphoreSlim _publicationSignal = new(0);
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly HashSet<BrokerControlSessionV1> _sessions = new();
    private readonly Queue<BrokerSnapshotPublicationV1> _publicationBacklog = new();
    private readonly TaskCompletionSource _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly int _subscriptionCapacity;
    private readonly Action<CodexCdpBrokerSnapshot>? _publicationCheckpoint;
    private readonly Action<Exception>? _terminalFailureCheckpoint;
    private readonly Action? _disposalCheckpoint;
    private readonly Task _publicationPump;
    private ICodexCdpHandleLease? _failedLeaseCleanup;
    private ICodexCdpHandleLease? _runtimeLease;
    private Exception? _backgroundFailure;
    private bool _publicationWakePending;
    private bool _publicationStopped;
    private Task? _disposeTask;
    private Task? _initializationTask;
    private Task? _reconciliationTask;
    private Task? _managedStartTask;
    private Task? _exitObserverTask;
    private bool _disposing;

    internal BrokerRuntimeOwnerV1(
        ICodexCdpRuntimeControlHost runtimeHost,
        string brokerEpoch,
        int maximumOperationHistory = 128,
        int maximumConnectedClients = 16,
        int subscriptionCapacity = 64,
        Action<CodexCdpBrokerSnapshot>? publicationCheckpoint = null,
        Action<Exception>? terminalFailureCheckpoint = null,
        Action? disposalCheckpoint = null)
    {
        _runtimeHost = runtimeHost ?? throw new ArgumentNullException(nameof(runtimeHost));
        if (subscriptionCapacity is < 1 or > CodexCdpBrokerSubscriptionQueue.MaximumCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(subscriptionCapacity));
        }

        _stateMachine = new CodexCdpBrokerStateMachine(
            brokerEpoch,
            maximumOperationHistory,
            maximumConnectedClients);
        _subscriptionCapacity = subscriptionCapacity;
        _publicationCheckpoint = publicationCheckpoint;
        _terminalFailureCheckpoint = terminalFailureCheckpoint;
        _disposalCheckpoint = disposalCheckpoint;
        ObserveFault(_completion.Task);
        _publicationPump = PublishSnapshotsAsync();
    }

    internal string BrokerEpoch => _stateMachine.Current.BrokerEpoch;

    internal CodexCdpBrokerSnapshot Current => _stateMachine.Current;

    internal Task Completion => _completion.Task;

    internal Task StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lifecycleGate)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            _initializationTask ??= RunReconciliationCycleAsync();
            return _initializationTask;
        }
    }

    internal async ValueTask<BrokerControlSessionV1> AttachGuardianAsync(
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(guardianConnection);
        try
        {
            await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfControlPlaneUnavailableLocked();
                if (guardianConnection.Completion.IsCompleted)
                {
                    throw new BrokerControlSessionException(
                        "control-peer-role-invalid",
                        "The Broker control session requires one live Guardian peer.");
                }

                RevalidateGuardianLocked(guardianConnection);
                guardianConnection.ClaimForControlSession();
                var session = new BrokerControlSessionV1(
                    this,
                    guardianConnection,
                    CreateClientId(),
                    _subscriptionCapacity);
                if (!_sessions.Add(session))
                {
                    throw new InvalidOperationException(
                        "The Broker control session was registered more than once.");
                }

                return session;
            }
            finally
            {
                _operationGate.Release();
            }
        }
        catch (Exception attachFailure)
        {
            try
            {
                await guardianConnection.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception cleanupFailure)
            {
                BrokerControlFailureArbitration.PreserveCleanupFailure(
                    attachFailure,
                    cleanupFailure);
            }

            ExceptionDispatchInfo.Capture(attachFailure).Throw();
            throw;
        }
    }

    internal async ValueTask<CodexCdpBrokerApplyResult> ConnectSessionAsync(
        BrokerControlSessionV1 session,
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection,
        CancellationToken cancellationToken)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfControlPlaneUnavailableLocked(session);
            RequireRegisteredSessionLocked(session, guardianConnection);
            RevalidateGuardianLocked(guardianConnection);
            var connected = _stateMachine.ConnectClient(session.ClientId);
            if (connected.Disposition != CodexCdpBrokerApplyDisposition.Accepted)
            {
                throw new BrokerControlSessionException(
                    connected.Code,
                    "The authenticated Guardian could not enter the Broker control plane.");
            }

            if (!session.TryCommitConnected())
            {
                _sessions.Remove(session);
                var rolledBack = _stateMachine.DisconnectClient(session.ClientId);
                if (rolledBack.Disposition == CodexCdpBrokerApplyDisposition.Accepted)
                {
                    QueuePublicationLocked(rolledBack.Snapshot, excludedSession: session);
                }

                throw new BrokerControlSessionException(
                    "control-session-stopped",
                    "The Guardian session stopped before Broker connection commit.");
            }

            QueuePublicationLocked(connected.Snapshot, session);
            return new CodexCdpBrokerApplyResult(
                CodexCdpBrokerApplyDisposition.Accepted,
                "hello",
                connected.Snapshot);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    internal async ValueTask<BrokerOwnerCommandExecutionV1> ExecuteCommandAsync(
        BrokerControlSessionV1 session,
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection,
        CodexCdpBrokerCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfControlPlaneUnavailableLocked(session);
            RequireRegisteredSessionLocked(session, guardianConnection);
            RevalidateGuardianLocked(guardianConnection);
            var result = _stateMachine.ApplyCommand(command);
            CodexCdpBrokerSnapshot? initiatingSnapshot = null;
            if (command.Kind == CodexCdpBrokerCommandKind.StartManagedCodex &&
                result.Disposition == CodexCdpBrokerApplyDisposition.Accepted)
            {
                if (_managedStartTask is { IsCompleted: false })
                {
                    throw new InvalidOperationException(
                        "The state machine accepted a second concurrent runtime start.");
                }

                var launching = _stateMachine.ApplySignal(
                    CodexCdpBrokerSignal.BeginCandidateLaunch,
                    command.OperationId);
                RequireAccepted(launching, "begin-candidate-launch-rejected");
                initiatingSnapshot = launching.Snapshot;
                QueuePublicationLocked(launching.Snapshot, session);
                _managedStartTask = RunManagedStartAsync(command.OperationId!);
            }
            else if (result.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
                     command.Kind is CodexCdpBrokerCommandKind.RetireAfterCodexExit or
                         CodexCdpBrokerCommandKind.RestartForUpgrade)
            {
                initiatingSnapshot = result.Snapshot;
                QueuePublicationLocked(result.Snapshot, session);
                if (result.Snapshot.State == CodexCdpBrokerState.Retiring)
                {
                    _completion.TrySetResult();
                }
            }

            return new BrokerOwnerCommandExecutionV1(result, initiatingSnapshot);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    internal async ValueTask DisconnectSessionAsync(
        BrokerControlSessionV1 session,
        bool connected)
    {
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_sessions.Remove(session))
            {
                return;
            }

            if (!connected)
            {
                return;
            }

            var disconnected = _stateMachine.DisconnectClient(session.ClientId);
            if (disconnected.Disposition == CodexCdpBrokerApplyDisposition.Accepted)
            {
                QueuePublicationLocked(disconnected.Snapshot, excludedSession: null);
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_lifecycleGate)
        {
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    private async Task RunReconciliationCycleAsync()
    {
        await Task.Yield();
        CodexCdpRuntimeReconciliationKind observation;
        try
        {
            await _operationGate.WaitAsync(_lifetimeCancellation.Token).ConfigureAwait(false);
            try
            {
                if (_disposing)
                {
                    return;
                }

                var reconciling = _stateMachine.ApplySignal(
                    CodexCdpBrokerSignal.BeginReconciliation);
                RequireAccepted(reconciling, "begin-reconciliation-rejected");
                QueuePublicationLocked(reconciling.Snapshot, excludedSession: null);
            }
            finally
            {
                _operationGate.Release();
            }

            observation = await _runtimeHost.ReconcileAsync(_lifetimeCancellation.Token)
                .ConfigureAwait(false);
            await _operationGate.WaitAsync(_lifetimeCancellation.Token).ConfigureAwait(false);
            try
            {
                if (_disposing)
                {
                    return;
                }

                var reconciled = _stateMachine.ApplySignal(
                    observation == CodexCdpRuntimeReconciliationKind.NoCodex
                        ? CodexCdpBrokerSignal.NoCodexObserved
                        : CodexCdpBrokerSignal.ExternalCodexObserved);
                RequireAccepted(reconciled, "reconciliation-result-rejected");
                QueuePublicationLocked(reconciled.Snapshot, excludedSession: null);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
        }
        catch
        {
            try
            {
                await ApplyFaultIfActiveAsync().ConfigureAwait(false);
            }
            catch (Exception faultException)
            {
                RecordBackgroundFailure(faultException);
            }
        }
    }

    private async Task RunManagedStartAsync(string operationId)
    {
        await Task.Yield();
        CodexCdpRuntimeStartResultV1? startResult = null;
        ICodexCdpHandleLease? uncommittedLease = null;
        ICodexCdpHandleLease? committedLease = null;
        try
        {
            startResult = await _runtimeHost.StartManagedAsync(
                    operationId,
                    _lifetimeCancellation.Token)
                .ConfigureAwait(false);
            if (startResult.Kind == CodexCdpRuntimeStartKind.RaceLost)
            {
                await _operationGate.WaitAsync(_lifetimeCancellation.Token).ConfigureAwait(false);
                try
                {
                    if (_disposing)
                    {
                        return;
                    }

                    var raceLost = _stateMachine.ApplySignal(
                        CodexCdpBrokerSignal.SingleInstanceRaceLost,
                        operationId);
                    RequireAccepted(raceLost, "single-instance-race-result-rejected");
                    QueuePublicationLocked(raceLost.Snapshot, excludedSession: null);
                    ScheduleReconciliationLocked();
                }
                finally
                {
                    _operationGate.Release();
                }

                return;
            }

            uncommittedLease = startResult.TakeOwnedLease();
            await _operationGate.WaitAsync(_lifetimeCancellation.Token).ConfigureAwait(false);
            try
            {
                if (_disposing)
                {
                    return;
                }

                if (_runtimeLease is not null ||
                    !uncommittedLease.IsAlive ||
                    uncommittedLease.Exit.IsCompleted ||
                    !string.Equals(
                        uncommittedLease.Identity.LaunchOperationId,
                        operationId,
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "The managed runtime start returned conflicting ownership.");
                }

                var processStarted = _stateMachine.ApplySignal(
                    CodexCdpBrokerSignal.CandidateProcessStarted,
                    operationId);
                RequireAccepted(processStarted, "candidate-process-result-rejected");
                var ownership = _stateMachine.ApplySignal(
                    CodexCdpBrokerSignal.CandidateOwnershipVerified,
                    operationId);
                RequireAccepted(ownership, "candidate-ownership-result-rejected");
                committedLease = uncommittedLease;
                var exitObserver = ObserveRuntimeExitAsync(committedLease);
                _runtimeLease = committedLease;
                _exitObserverTask = exitObserver;
                uncommittedLease = null;
                var ready = _stateMachine.ApplySignal(
                    CodexCdpBrokerSignal.CdpHandshakeCompleted,
                    operationId);
                RequireAccepted(ready, "candidate-handshake-result-rejected");
                QueuePublicationLocked(ready.Snapshot, excludedSession: null);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            RecordBackgroundFailure(exception);
            try
            {
                if (committedLease is null)
                {
                    await ApplyFaultIfActiveAsync().ConfigureAwait(false);
                }
                else
                {
                    await TerminalizeControlPlaneFailureAsync(exception).ConfigureAwait(false);
                }
            }
            catch (Exception faultException)
            {
                RecordBackgroundFailure(faultException);
            }
        }
        finally
        {
            if (startResult is not null)
            {
                try
                {
                    await startResult.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    RecordBackgroundFailure(exception);
                }
            }

            if (uncommittedLease is not null)
            {
                try
                {
                    await uncommittedLease.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    await RetainFailedLeaseCleanupAsync(uncommittedLease).ConfigureAwait(false);
                    RecordBackgroundFailure(exception);
                    await TerminalizeControlPlaneFailureAsync(exception).ConfigureAwait(false);
                }
            }
        }
    }

    private async Task ObserveRuntimeExitAsync(ICodexCdpHandleLease lease)
    {
        try
        {
            var exit = await lease.Exit
                .WaitAsync(_lifetimeCancellation.Token)
                .ConfigureAwait(false);
            if (exit.Kind == CodexCdpRuntimeExitKind.Faulted)
            {
                var failure = new BrokerControlSessionException(
                    "runtime-exit-observation-failed",
                    "The Broker lost the exact managed runtime exit observation authority.");
                failure.Data[RuntimeExitFailureCodeDataKey] = exit.FailureCode;
                await TerminalizeExitObservationFailureAsync(lease, failure)
                    .ConfigureAwait(false);
                return;
            }

            await FinalizeNaturalRuntimeExitAsync(lease).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            try
            {
                await TerminalizeControlPlaneFailureAsync(exception).ConfigureAwait(false);
            }
            catch (Exception faultException)
            {
                RecordBackgroundFailure(faultException);
            }
        }
    }

    private async Task FinalizeNaturalRuntimeExitAsync(ICodexCdpHandleLease lease)
    {
        ICodexCdpHandleLease? exitedLease = null;
        Exception? publicationFailure = null;
        var reconcile = false;
        var retiring = false;
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposing || !ReferenceEquals(_runtimeLease, lease))
            {
                return;
            }

            var exited = _stateMachine.ApplySignal(CodexCdpBrokerSignal.OwnedCodexExited);
            RequireAccepted(exited, "owned-runtime-exit-rejected");
            exitedLease = _runtimeLease;
            _runtimeLease = null;
            reconcile = exited.Snapshot.State == CodexCdpBrokerState.OwnedCodexExited;
            retiring = exited.Snapshot.State == CodexCdpBrokerState.Retiring;
            try
            {
                QueuePublicationLocked(
                    exited.Snapshot,
                    excludedSession: null,
                    deferTerminalCompletion: true);
            }
            catch (Exception exception)
            {
                publicationFailure = exception;
            }
        }
        finally
        {
            _operationGate.Release();
        }

        Exception? cleanupFailure = null;
        if (exitedLease is not null)
        {
            try
            {
                await exitedLease.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                cleanupFailure = exception;
                try
                {
                    await RetainFailedLeaseCleanupAsync(exitedLease).ConfigureAwait(false);
                }
                catch (Exception retainFailure)
                {
                    cleanupFailure = BrokerControlFailureArbitration.CombineCleanupFailures(
                        cleanupFailure,
                        retainFailure);
                }
            }
        }

        var terminalFailure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            publicationFailure,
            cleanupFailure);
        if (terminalFailure is null && _completion.Task.IsFaulted)
        {
            terminalFailure = ReadBackgroundFailure() ??
                new BrokerControlSessionException(
                    "control-plane-failed",
                    "The Broker control plane failed before runtime exit finalization.");
        }

        if (terminalFailure is not null)
        {
            await TerminalizeControlPlaneFailureAsync(terminalFailure).ConfigureAwait(false);
            return;
        }

        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposing)
            {
                return;
            }

            if (retiring)
            {
                _completion.TrySetResult();
            }
            else if (reconcile &&
                     _stateMachine.Current.State == CodexCdpBrokerState.OwnedCodexExited)
            {
                ScheduleReconciliationLocked();
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private async Task RetainFailedLeaseCleanupAsync(ICodexCdpHandleLease lease)
    {
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_failedLeaseCleanup is not null && !ReferenceEquals(_failedLeaseCleanup, lease))
            {
                throw new InvalidOperationException(
                    "The Broker already retains another failed lease cleanup.");
            }

            _failedLeaseCleanup = lease;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private void RecordBackgroundFailure(Exception exception)
    {
        lock (_lifecycleGate)
        {
            _backgroundFailure ??= exception;
        }
    }

    private async Task TerminalizeExitObservationFailureAsync(
        ICodexCdpHandleLease lease,
        Exception failure)
    {
        try
        {
            _terminalFailureCheckpoint?.Invoke(failure);
        }
        catch (Exception checkpointFailure)
        {
            BrokerControlFailureArbitration.PreserveSecondaryFailure(
                failure,
                checkpointFailure,
                BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        }

        BrokerControlSessionV1[] sessions = Array.Empty<BrokerControlSessionV1>();
        var exactLease = false;
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!ReferenceEquals(_runtimeLease, lease))
            {
                return;
            }

            exactLease = true;
            if (!_disposing)
            {
                var faulted = _stateMachine.ApplySignal(CodexCdpBrokerSignal.FaultDetected);
                RequireFaultAcceptedOrReplayed(
                    faulted,
                    "runtime-exit-observation-fault-rejected");
                sessions = StopControlPlaneLocked();
            }
        }
        finally
        {
            _operationGate.Release();
        }

        if (exactLease)
        {
            CompleteTerminalFailure(failure, sessions);
        }
    }

    private async Task TerminalizeControlPlaneFailureAsync(Exception failure)
    {
        StopPublication();
        PublishTerminalFailure(failure);
        BrokerControlSessionV1[] sessions = Array.Empty<BrokerControlSessionV1>();
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposing)
            {
                return;
            }

            var faulted = _stateMachine.ApplySignal(CodexCdpBrokerSignal.FaultDetected);
            RequireFaultAcceptedOrReplayed(faulted, "control-plane-fault-rejected");
            sessions = StopControlPlaneLocked();
        }
        finally
        {
            _operationGate.Release();
        }

        RequestStopSessions(failure, sessions);
    }

    private BrokerControlSessionV1[] StopControlPlaneLocked()
    {
        StopPublication();
        return _sessions.ToArray();
    }

    private void StopPublication()
    {
        lock (_publicationGate)
        {
            _publicationStopped = true;
            _publicationBacklog.Clear();
            _publicationWakePending = false;
        }
    }

    private void CompleteTerminalFailure(
        Exception failure,
        IEnumerable<BrokerControlSessionV1> sessions)
    {
        PublishTerminalFailure(failure);
        RequestStopSessions(failure, sessions);
    }

    private void PublishTerminalFailure(Exception failure)
    {
        RecordBackgroundFailure(failure);
        _completion.TrySetException(failure);
    }

    private static void RequestStopSessions(
        Exception failure,
        IEnumerable<BrokerControlSessionV1> sessions)
    {
        foreach (var session in sessions)
        {
            try
            {
                session.RequestStopFromOwner();
            }
            catch (Exception stopFailure)
            {
                BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    stopFailure);
            }
        }
    }

    private static void RequireFaultAcceptedOrReplayed(
        CodexCdpBrokerApplyResult result,
        string code)
    {
        if (result.Disposition is not CodexCdpBrokerApplyDisposition.Accepted and
            not CodexCdpBrokerApplyDisposition.Replayed)
        {
            throw new InvalidOperationException(code + ": " + result.Code);
        }
    }

    private async Task ApplyFaultIfActiveAsync()
    {
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposing)
            {
                return;
            }

            var faulted = _stateMachine.ApplySignal(CodexCdpBrokerSignal.FaultDetected);
            if (faulted.Disposition == CodexCdpBrokerApplyDisposition.Accepted)
            {
                QueuePublicationLocked(faulted.Snapshot, excludedSession: null);
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private void ScheduleReconciliationLocked()
    {
        if (_disposing || _reconciliationTask is { IsCompleted: false })
        {
            return;
        }

        _reconciliationTask = RunReconciliationCycleAsync();
    }

    private void QueuePublicationLocked(
        CodexCdpBrokerSnapshot snapshot,
        BrokerControlSessionV1? excludedSession,
        bool deferTerminalCompletion = false)
    {
        lock (_publicationGate)
        {
            if (_publicationStopped)
            {
                return;
            }
        }

        var recipients = _sessions
            .Where(session => !ReferenceEquals(session, excludedSession))
            .ToArray();
        if (recipients.Length == 0)
        {
            return;
        }

        try
        {
            _publicationCheckpoint?.Invoke(snapshot);
            var signal = false;
            lock (_publicationGate)
            {
                if (_publicationStopped)
                {
                    return;
                }

                if (_publicationBacklog.Count >= MaximumPublicationBacklog)
                {
                    _publicationBacklog.Clear();
                    _publicationBacklog.Enqueue(new BrokerSnapshotPublicationV1(
                        snapshot,
                        recipients,
                        RequireResync: true));
                }
                else
                {
                    _publicationBacklog.Enqueue(new BrokerSnapshotPublicationV1(
                        snapshot,
                        recipients,
                        RequireResync: false));
                }

                if (!_publicationWakePending)
                {
                    _publicationWakePending = true;
                    signal = true;
                }
            }

            if (signal)
            {
                _publicationSignal.Release();
            }
        }
        catch (Exception exception)
        {
            try
            {
                var faulted = _stateMachine.ApplySignal(CodexCdpBrokerSignal.FaultDetected);
                RequireFaultAcceptedOrReplayed(
                    faulted,
                    "publication-fault-rejected");
            }
            catch (Exception faultFailure)
            {
                BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    exception,
                    faultFailure,
                    BrokerControlFailureArbitration.ConcurrentFailureDataKey);
            }

            var sessions = StopControlPlaneLocked();
            if (deferTerminalCompletion)
            {
                RecordBackgroundFailure(exception);
                RequestStopSessions(exception, sessions);
            }
            else
            {
                CompleteTerminalFailure(exception, sessions);
            }

            throw;
        }
    }

    private async Task PublishSnapshotsAsync()
    {
        try
        {
            while (true)
            {
                await _publicationSignal.WaitAsync(_lifetimeCancellation.Token)
                    .ConfigureAwait(false);
                while (true)
                {
                    BrokerSnapshotPublicationV1? publication;
                    lock (_publicationGate)
                    {
                        if (_publicationBacklog.Count == 0)
                        {
                            _publicationWakePending = false;
                            publication = null;
                        }
                        else
                        {
                            publication = _publicationBacklog.Dequeue();
                        }
                    }

                    if (publication is null)
                    {
                        break;
                    }

                    foreach (var session in publication.Recipients)
                    {
                        try
                        {
                            session.ObserveSnapshot(
                                publication.Snapshot,
                                publication.RequireResync);
                        }
                        catch
                        {
                            session.RequestStopFromOwner();
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            try
            {
                await TerminalizeControlPlaneFailureAsync(exception).ConfigureAwait(false);
            }
            catch (Exception faultException)
            {
                RecordBackgroundFailure(faultException);
            }
        }
    }

    private async Task DisposeCoreAsync()
    {
        // Publish the one-shot dispose task before any cancellation callbacks can reenter us.
        await Task.Yield();

        BrokerControlSessionV1[] sessions;
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposing)
            {
                return;
            }

            _disposing = true;
            sessions = _sessions.ToArray();
        }
        finally
        {
            _operationGate.Release();
        }

        Exception? failure = null;
        try
        {
            _disposalCheckpoint?.Invoke();
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        lock (_publicationGate)
        {
            _publicationStopped = true;
            _publicationBacklog.Clear();
            _publicationWakePending = false;
        }

        failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
            failure,
            CancelLifetimeNoThrow(_lifetimeCancellation));
        foreach (var session in sessions)
        {
            try
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    exception);
            }
        }

        var taskFailure = await AwaitBackgroundTaskAsync(_initializationTask).ConfigureAwait(false);
        failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            failure,
            taskFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        taskFailure = await AwaitBackgroundTaskAsync(_reconciliationTask).ConfigureAwait(false);
        failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            failure,
            taskFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        taskFailure = await AwaitBackgroundTaskAsync(_managedStartTask).ConfigureAwait(false);
        failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            failure,
            taskFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        taskFailure = await AwaitBackgroundTaskAsync(_exitObserverTask).ConfigureAwait(false);
        failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            failure,
            taskFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        taskFailure = await AwaitBackgroundTaskAsync(_publicationPump).ConfigureAwait(false);
        failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            failure,
            taskFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        var backgroundFailure = ReadBackgroundFailure();
        if (backgroundFailure is not null)
        {
            failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
                backgroundFailure,
                failure,
                BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        }

        ICodexCdpHandleLease? failedLeaseCleanup;
        ICodexCdpHandleLease? lease;
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            failedLeaseCleanup = _failedLeaseCleanup;
            _failedLeaseCleanup = null;
            lease = _runtimeLease;
            _runtimeLease = null;
            _sessions.Clear();
        }
        finally
        {
            _operationGate.Release();
        }

        if (lease is not null)
        {
            try
            {
                await lease.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    exception);
            }
        }

        if (failedLeaseCleanup is not null && !ReferenceEquals(failedLeaseCleanup, lease))
        {
            try
            {
                await failedLeaseCleanup.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    exception);
            }
        }

        try
        {
            await _runtimeHost.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                failure,
                exception);
        }

        lock (_publicationGate)
        {
            _publicationBacklog.Clear();
            _publicationWakePending = false;
        }

        try
        {
            _publicationSignal.Dispose();
            _lifetimeCancellation.Dispose();
        }
        catch (Exception exception)
        {
            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                failure,
                exception);
        }

        if (failure is null)
        {
            _completion.TrySetResult();
            return;
        }

        _completion.TrySetException(failure);
        ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private async Task<Exception?> AwaitBackgroundTaskAsync(Task? task)
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
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private Exception? ReadBackgroundFailure()
    {
        lock (_lifecycleGate)
        {
            return _backgroundFailure;
        }
    }

    private static Exception? CancelLifetimeNoThrow(CancellationTokenSource cancellation)
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

    private static void ObserveFault(Task task) =>
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously |
                TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);

    private void RequireRegisteredSessionLocked(
        BrokerControlSessionV1 session,
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(guardianConnection);
        if (!_sessions.Contains(session) ||
            !ReferenceEquals(session.GuardianConnection, guardianConnection))
        {
            throw new BrokerControlSessionException(
                "control-session-not-registered",
                "The Guardian control session is not owned by this Broker.");
        }
    }

    private static void RevalidateGuardianLocked(
        VerifiedGuardianManagedEntryConnectionV1 guardianConnection)
    {
        var current = guardianConnection.Revalidate();
        if (guardianConnection.Completion.IsCompleted ||
            !IsExactProcessIdentity(guardianConnection.InitialIdentity, current))
        {
            throw new BrokerControlSessionException(
                "control-peer-identity-changed",
                "The authenticated Guardian identity changed.");
        }
    }

    private static bool IsExactProcessIdentity(
        WindowsProcessIdentity expected,
        WindowsProcessIdentity actual) =>
        expected.ProcessId == actual.ProcessId &&
        expected.CreationTimeUtc == actual.CreationTimeUtc &&
        expected.KernelSessionId == actual.KernelSessionId &&
        Equals(expected.Token, actual.Token) &&
        Equals(expected.AppModel, actual.AppModel) &&
        string.Equals(expected.FinalImagePath, actual.FinalImagePath, StringComparison.Ordinal) &&
        expected.ImageFileObjectIsExact == actual.ImageFileObjectIsExact &&
        Equals(expected.ReleaseRoot, actual.ReleaseRoot) &&
        expected.Artifacts.SequenceEqual(actual.Artifacts);

    private void ThrowIfControlPlaneUnavailableLocked(
        BrokerControlSessionV1? session = null)
    {
        if (_disposing)
        {
            if (session is not null)
            {
                throw new OperationCanceledException(
                    "The Broker owner is stopping its registered control session.",
                    new CancellationToken(canceled: true));
            }

            throw new ObjectDisposedException(nameof(BrokerRuntimeOwnerV1));
        }

        lock (_publicationGate)
        {
            if (_publicationStopped)
            {
                throw new BrokerControlSessionException(
                    "control-publication-failed",
                    "The Broker control publication channel is unavailable.");
            }
        }
    }

    private static void RequireAccepted(CodexCdpBrokerApplyResult result, string code)
    {
        if (result.Disposition != CodexCdpBrokerApplyDisposition.Accepted)
        {
            throw new InvalidOperationException(code + ": " + result.Code);
        }
    }

    private static string CreateClientId() =>
        "guardian-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    private sealed record BrokerSnapshotPublicationV1(
        CodexCdpBrokerSnapshot Snapshot,
        BrokerControlSessionV1[] Recipients,
        bool RequireResync);
}
