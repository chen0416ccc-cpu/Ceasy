using System;
using System.Collections.Generic;

namespace CodexGuardian.Control;

internal enum CodexCdpBrokerState
{
    Booting,
    Reconciling,
    ExternalCodexPresent,
    IdleNoCodex,
    LaunchReserved,
    LaunchingCandidate,
    VerifyingCandidate,
    RaceLost,
    CdpHandshake,
    ManagedUnverified,
    ManagedReady,
    OwnedCodexExited,
    Retiring,
    FaultedNoOwner
}

internal enum CodexCdpBrokerRetirementIntent
{
    None,
    RetireAfterCodexExit,
    RestartForUpgrade
}

internal enum CodexCdpBrokerSignal
{
    BeginReconciliation,
    ExternalCodexObserved,
    NoCodexObserved,
    BeginCandidateLaunch,
    CandidateProcessStarted,
    CandidateOwnershipVerified,
    SingleInstanceRaceLost,
    CdpHandshakeCompleted,
    OwnedCodexExited,
    FaultDetected
}

internal enum CodexCdpBrokerApplyDisposition
{
    Accepted,
    Replayed,
    Rejected
}

internal sealed record CodexCdpBrokerSnapshot(
    string BrokerEpoch,
    long Sequence,
    CodexCdpBrokerState State,
    int ConnectedClients,
    bool OwnsManagedCodex,
    CodexCdpBrokerRetirementIntent RetirementIntent,
    bool BrokerExitIntent,
    bool ManagedCodexExitIntent,
    string? ActiveLaunchOperationId,
    int AcceptedOperationCount);

internal sealed record CodexCdpBrokerApplyResult(
    CodexCdpBrokerApplyDisposition Disposition,
    string Code,
    CodexCdpBrokerSnapshot Snapshot);

internal sealed class CodexCdpBrokerStateMachine
{
    internal const int MaximumOperationHistory = 1024;
    internal const int MaximumConnectedClients = 64;

    private readonly object _gate = new();
    private readonly string _brokerEpoch;
    private readonly int _maximumOperationHistory;
    private readonly int _maximumConnectedClients;
    private readonly Dictionary<string, CodexCdpBrokerCommandKind> _acceptedOperations =
        new(StringComparer.Ordinal);
    private readonly HashSet<string> _connectedClients = new(StringComparer.Ordinal);
    private long _sequence = 1;
    private CodexCdpBrokerState _state = CodexCdpBrokerState.Booting;
    private bool _ownsManagedCodex;
    private CodexCdpBrokerRetirementIntent _retirementIntent;
    private string? _activeLaunchOperationId;

    internal CodexCdpBrokerStateMachine(
        string brokerEpoch,
        int maximumOperationHistory = 128,
        int maximumConnectedClients = 16)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(brokerEpoch))
        {
            throw new ArgumentException("A valid broker epoch is required.", nameof(brokerEpoch));
        }

        if (maximumOperationHistory is < 1 or > MaximumOperationHistory)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumOperationHistory));
        }

        if (maximumConnectedClients is < 1 or > MaximumConnectedClients)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumConnectedClients));
        }

        _brokerEpoch = brokerEpoch;
        _maximumOperationHistory = maximumOperationHistory;
        _maximumConnectedClients = maximumConnectedClients;
    }

    internal CodexCdpBrokerSnapshot Current
    {
        get
        {
            lock (_gate)
            {
                return SnapshotLocked();
            }
        }
    }

    internal CodexCdpBrokerApplyResult ConnectClient(string clientId)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(clientId))
        {
            return Rejected("invalid-client-id");
        }

        lock (_gate)
        {
            if (_connectedClients.Contains(clientId))
            {
                return ResultLocked(
                    CodexCdpBrokerApplyDisposition.Replayed,
                    "client-already-connected");
            }

            if (_connectedClients.Count >= _maximumConnectedClients)
            {
                return ResultLocked(
                    CodexCdpBrokerApplyDisposition.Rejected,
                    "client-capacity-exceeded");
            }

            CommitMutationLocked(() => _connectedClients.Add(clientId));
            return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "client-connected");
        }
    }

    internal CodexCdpBrokerApplyResult DisconnectClient(string clientId)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(clientId))
        {
            return Rejected("invalid-client-id");
        }

        lock (_gate)
        {
            if (!_connectedClients.Contains(clientId))
            {
                return ResultLocked(
                    CodexCdpBrokerApplyDisposition.Rejected,
                    "client-not-connected");
            }

            // Client lifetime is deliberately independent from the owned Codex lifetime.
            CommitMutationLocked(() => _connectedClients.Remove(clientId));
            return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "client-disconnected");
        }
    }

    internal CodexCdpBrokerApplyResult ApplyCommand(CodexCdpBrokerCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        lock (_gate)
        {
            if (command.Kind == CodexCdpBrokerCommandKind.Hello)
            {
                return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "hello");
            }

            if (!string.Equals(command.BrokerEpoch, _brokerEpoch, StringComparison.Ordinal))
            {
                return ResultLocked(
                    CodexCdpBrokerApplyDisposition.Rejected,
                    "broker-epoch-mismatch");
            }

            switch (command.Kind)
            {
                case CodexCdpBrokerCommandKind.GetStatus:
                    return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "status");

                case CodexCdpBrokerCommandKind.GetFullSnapshot:
                    return ResultLocked(
                        CodexCdpBrokerApplyDisposition.Accepted,
                        "full-snapshot");

                case CodexCdpBrokerCommandKind.Subscribe:
                    if (command.AfterSequence is null ||
                        command.AfterSequence < 0 ||
                        command.AfterSequence > _sequence)
                    {
                        return ResultLocked(
                            CodexCdpBrokerApplyDisposition.Rejected,
                            "invalid-subscription-sequence");
                    }

                    return ResultLocked(
                        CodexCdpBrokerApplyDisposition.Accepted,
                        command.AfterSequence == _sequence ? "subscribed" : "resync-required");

                case CodexCdpBrokerCommandKind.StartManagedCodex:
                case CodexCdpBrokerCommandKind.RetireAfterCodexExit:
                case CodexCdpBrokerCommandKind.RestartForUpgrade:
                    return ApplyOperationLocked(command);

                default:
                    return ResultLocked(
                        CodexCdpBrokerApplyDisposition.Rejected,
                        "unsupported-command");
            }
        }
    }

    internal CodexCdpBrokerApplyResult ApplySignal(
        CodexCdpBrokerSignal signal,
        string? launchOperationId = null)
    {
        lock (_gate)
        {
            if (signal == CodexCdpBrokerSignal.FaultDetected)
            {
                return ApplyFaultLocked();
            }

            return signal switch
            {
                CodexCdpBrokerSignal.BeginReconciliation =>
                    ApplySimpleTransitionLocked(
                        signal,
                        CodexCdpBrokerState.Reconciling,
                        CodexCdpBrokerState.Booting,
                        CodexCdpBrokerState.ExternalCodexPresent,
                        CodexCdpBrokerState.IdleNoCodex,
                        CodexCdpBrokerState.RaceLost,
                        CodexCdpBrokerState.OwnedCodexExited,
                        CodexCdpBrokerState.FaultedNoOwner),

                CodexCdpBrokerSignal.ExternalCodexObserved =>
                    ApplySimpleTransitionLocked(
                        signal,
                        CodexCdpBrokerState.ExternalCodexPresent,
                        CodexCdpBrokerState.Reconciling),

                CodexCdpBrokerSignal.NoCodexObserved =>
                    ApplySimpleTransitionLocked(
                        signal,
                        CodexCdpBrokerState.IdleNoCodex,
                        CodexCdpBrokerState.Reconciling),

                CodexCdpBrokerSignal.BeginCandidateLaunch =>
                    ApplyLaunchTransitionLocked(
                        signal,
                        launchOperationId,
                        CodexCdpBrokerState.LaunchReserved,
                        CodexCdpBrokerState.LaunchingCandidate),

                CodexCdpBrokerSignal.CandidateProcessStarted =>
                    ApplyLaunchTransitionLocked(
                        signal,
                        launchOperationId,
                        CodexCdpBrokerState.LaunchingCandidate,
                        CodexCdpBrokerState.VerifyingCandidate),

                CodexCdpBrokerSignal.CandidateOwnershipVerified =>
                    ApplyOwnershipTransitionLocked(launchOperationId),

                CodexCdpBrokerSignal.SingleInstanceRaceLost =>
                    ApplyRaceLostLocked(launchOperationId),

                CodexCdpBrokerSignal.CdpHandshakeCompleted =>
                    ApplyHandshakeCompletedLocked(launchOperationId),

                CodexCdpBrokerSignal.OwnedCodexExited => ApplyOwnedExitLocked(),

                _ => ResultLocked(
                    CodexCdpBrokerApplyDisposition.Rejected,
                    "unsupported-signal")
            };
        }
    }

    private CodexCdpBrokerApplyResult ApplyOperationLocked(CodexCdpBrokerCommand command)
    {
        var operationId = command.OperationId;
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(operationId))
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Rejected,
                "invalid-operation-id");
        }

        if (_acceptedOperations.TryGetValue(operationId!, out var previousKind))
        {
            return previousKind == command.Kind
                ? ResultLocked(CodexCdpBrokerApplyDisposition.Replayed, "operation-replayed")
                : ResultLocked(
                    CodexCdpBrokerApplyDisposition.Rejected,
                    "operation-id-conflict");
        }

        if (!CanApplyOperationLocked(command.Kind, out var rejectionCode))
        {
            return ResultLocked(CodexCdpBrokerApplyDisposition.Rejected, rejectionCode);
        }

        // Never evict old entries: exhaustion fails closed until a new broker epoch.
        if (_acceptedOperations.Count >= _maximumOperationHistory)
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Rejected,
                "operation-capacity-exceeded");
        }

        CommitMutationLocked(() =>
        {
            _acceptedOperations.Add(operationId!, command.Kind);
            if (command.Kind == CodexCdpBrokerCommandKind.StartManagedCodex)
            {
                _activeLaunchOperationId = operationId;
                _state = CodexCdpBrokerState.LaunchReserved;
                return;
            }

            _retirementIntent = command.Kind == CodexCdpBrokerCommandKind.RestartForUpgrade
                ? CodexCdpBrokerRetirementIntent.RestartForUpgrade
                : CodexCdpBrokerRetirementIntent.RetireAfterCodexExit;
            if (!_ownsManagedCodex)
            {
                _state = CodexCdpBrokerState.Retiring;
            }
        });
        if (command.Kind == CodexCdpBrokerCommandKind.StartManagedCodex)
        {
            return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "launch-reserved");
        }

        return ResultLocked(
            CodexCdpBrokerApplyDisposition.Accepted,
            _ownsManagedCodex ? "retirement-armed" : "retiring");
    }

    private bool CanApplyOperationLocked(
        CodexCdpBrokerCommandKind kind,
        out string rejectionCode)
    {
        rejectionCode = "illegal-operation-state";
        if (kind == CodexCdpBrokerCommandKind.StartManagedCodex)
        {
            return _state == CodexCdpBrokerState.IdleNoCodex &&
                   _retirementIntent == CodexCdpBrokerRetirementIntent.None;
        }

        if (_retirementIntent != CodexCdpBrokerRetirementIntent.None)
        {
            rejectionCode = "retirement-already-requested";
            return false;
        }

        return _state is
            CodexCdpBrokerState.ExternalCodexPresent or
            CodexCdpBrokerState.IdleNoCodex or
            CodexCdpBrokerState.RaceLost or
            CodexCdpBrokerState.CdpHandshake or
            CodexCdpBrokerState.ManagedUnverified or
            CodexCdpBrokerState.ManagedReady or
            CodexCdpBrokerState.OwnedCodexExited or
            CodexCdpBrokerState.FaultedNoOwner;
    }

    private CodexCdpBrokerApplyResult ApplySimpleTransitionLocked(
        CodexCdpBrokerSignal signal,
        CodexCdpBrokerState destination,
        params CodexCdpBrokerState[] allowedSources)
    {
        if (Array.IndexOf(allowedSources, _state) < 0 || _ownsManagedCodex)
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Rejected,
                "illegal-transition-" + signal);
        }

        CommitMutationLocked(() =>
        {
            _state = destination;
            _activeLaunchOperationId = null;
        });
        return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "transitioned");
    }

    private CodexCdpBrokerApplyResult ApplyLaunchTransitionLocked(
        CodexCdpBrokerSignal signal,
        string? operationId,
        CodexCdpBrokerState source,
        CodexCdpBrokerState destination)
    {
        if (_state != source || !MatchesActiveLaunchOperationLocked(operationId))
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Rejected,
                "illegal-transition-" + signal);
        }

        CommitMutationLocked(() => _state = destination);
        return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "transitioned");
    }

    private CodexCdpBrokerApplyResult ApplyOwnershipTransitionLocked(string? operationId)
    {
        if (_state != CodexCdpBrokerState.VerifyingCandidate ||
            !MatchesActiveLaunchOperationLocked(operationId))
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Rejected,
                "illegal-transition-CandidateOwnershipVerified");
        }

        CommitMutationLocked(() =>
        {
            _ownsManagedCodex = true;
            _state = CodexCdpBrokerState.CdpHandshake;
        });
        return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "ownership-verified");
    }

    private CodexCdpBrokerApplyResult ApplyRaceLostLocked(string? operationId)
    {
        if (_state is not CodexCdpBrokerState.LaunchingCandidate and
            not CodexCdpBrokerState.VerifyingCandidate ||
            !MatchesActiveLaunchOperationLocked(operationId))
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Rejected,
                "illegal-transition-SingleInstanceRaceLost");
        }

        CommitMutationLocked(() =>
        {
            _state = CodexCdpBrokerState.RaceLost;
            _ownsManagedCodex = false;
            _activeLaunchOperationId = null;
        });
        return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "single-instance-race-lost");
    }

    private CodexCdpBrokerApplyResult ApplyHandshakeCompletedLocked(string? operationId)
    {
        if (_state == CodexCdpBrokerState.CdpHandshake)
        {
            if (!MatchesActiveLaunchOperationLocked(operationId))
            {
                return ResultLocked(
                    CodexCdpBrokerApplyDisposition.Rejected,
                    "launch-operation-mismatch");
            }

            CommitMutationLocked(() => _state = CodexCdpBrokerState.ManagedReady);
            return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "managed-ready");
        }

        if (_state == CodexCdpBrokerState.ManagedUnverified &&
            _ownsManagedCodex)
        {
            if (!MatchesActiveLaunchOperationLocked(operationId))
            {
                return ResultLocked(
                    CodexCdpBrokerApplyDisposition.Rejected,
                    "launch-operation-mismatch");
            }

            CommitMutationLocked(() => _state = CodexCdpBrokerState.ManagedReady);
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Accepted,
                "managed-verification-restored");
        }

        return ResultLocked(
            CodexCdpBrokerApplyDisposition.Rejected,
            "illegal-transition-CdpHandshakeCompleted");
    }

    private CodexCdpBrokerApplyResult ApplyOwnedExitLocked()
    {
        if (!_ownsManagedCodex ||
            _state is not CodexCdpBrokerState.CdpHandshake and
            not CodexCdpBrokerState.ManagedUnverified and
            not CodexCdpBrokerState.ManagedReady)
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Rejected,
                "illegal-transition-OwnedCodexExited");
        }

        CommitMutationLocked(() =>
        {
            _ownsManagedCodex = false;
            _activeLaunchOperationId = null;
            _state = _retirementIntent == CodexCdpBrokerRetirementIntent.None
                ? CodexCdpBrokerState.OwnedCodexExited
                : CodexCdpBrokerState.Retiring;
        });
        return ResultLocked(
            CodexCdpBrokerApplyDisposition.Accepted,
            _state == CodexCdpBrokerState.Retiring ? "retiring" : "owned-codex-exited");
    }

    private CodexCdpBrokerApplyResult ApplyFaultLocked()
    {
        if (_ownsManagedCodex)
        {
            if (_state != CodexCdpBrokerState.ManagedUnverified)
            {
                CommitMutationLocked(() => _state = CodexCdpBrokerState.ManagedUnverified);
                return ResultLocked(
                    CodexCdpBrokerApplyDisposition.Accepted,
                    "managed-observation-unverified");
            }

            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Replayed,
                "managed-observation-already-unverified");
        }

        if (_state == CodexCdpBrokerState.Retiring)
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Replayed,
                "already-retiring");
        }

        if (_state == CodexCdpBrokerState.FaultedNoOwner)
        {
            return ResultLocked(
                CodexCdpBrokerApplyDisposition.Replayed,
                "already-faulted-no-owner");
        }

        CommitMutationLocked(() =>
        {
            _state = CodexCdpBrokerState.FaultedNoOwner;
            _activeLaunchOperationId = null;
        });
        return ResultLocked(CodexCdpBrokerApplyDisposition.Accepted, "faulted-no-owner");
    }

    private bool MatchesActiveLaunchOperationLocked(string? operationId) =>
        CodexCdpBrokerProtocol.IsControlIdentifier(operationId) &&
        string.Equals(operationId, _activeLaunchOperationId, StringComparison.Ordinal);

    private CodexCdpBrokerApplyResult Rejected(string code)
    {
        lock (_gate)
        {
            return ResultLocked(CodexCdpBrokerApplyDisposition.Rejected, code);
        }
    }

    private void CommitMutationLocked(Action mutation)
    {
        if (_sequence >= CodexCdpBrokerProtocol.MaximumSequence)
        {
            throw new InvalidOperationException("The broker sequence space is exhausted.");
        }

        mutation();
        _sequence++;
        ValidateInvariantsLocked();
    }

    private CodexCdpBrokerApplyResult ResultLocked(
        CodexCdpBrokerApplyDisposition disposition,
        string code) => new(disposition, code, SnapshotLocked());

    private CodexCdpBrokerSnapshot SnapshotLocked() => new(
        _brokerEpoch,
        _sequence,
        _state,
        _connectedClients.Count,
        _ownsManagedCodex,
        _retirementIntent,
        BrokerExitIntent: _state == CodexCdpBrokerState.Retiring,
        ManagedCodexExitIntent: false,
        _activeLaunchOperationId,
        _acceptedOperations.Count);

    private void ValidateInvariantsLocked()
    {
        var ownershipState = _state is
            CodexCdpBrokerState.CdpHandshake or
            CodexCdpBrokerState.ManagedUnverified or
            CodexCdpBrokerState.ManagedReady;
        if (_ownsManagedCodex != ownershipState)
        {
            throw new InvalidOperationException("Broker ownership state is inconsistent.");
        }

        var launchState = _state is
            CodexCdpBrokerState.LaunchReserved or
            CodexCdpBrokerState.LaunchingCandidate or
            CodexCdpBrokerState.VerifyingCandidate or
            CodexCdpBrokerState.CdpHandshake or
            CodexCdpBrokerState.ManagedUnverified or
            CodexCdpBrokerState.ManagedReady;
        if ((_activeLaunchOperationId is not null) != launchState)
        {
            throw new InvalidOperationException("Broker launch operation state is inconsistent.");
        }

        if (_state == CodexCdpBrokerState.Retiring &&
            _retirementIntent == CodexCdpBrokerRetirementIntent.None)
        {
            throw new InvalidOperationException("Broker retirement requires an explicit intent.");
        }
    }
}
