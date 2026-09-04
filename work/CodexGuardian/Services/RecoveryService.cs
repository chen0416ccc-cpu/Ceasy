using System.Globalization;
using CodexGuardian.Models;

namespace CodexGuardian.Services;

public sealed class RecoveryService
{
    internal const string RecoveryChainBlockedMessage =
        "A Guardian-created recovery turn failed; automatic recovery chaining is blocked for manual review.";

    internal const string RecoverySuccessorUncertainMessage =
        "A prior recovery dispatch could not be attributed to this failed turn; automatic recovery is blocked for manual review.";

    private static readonly TimeSpan DurableResultWriteTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DesktopCommitTimeout = TimeSpan.FromSeconds(40);
    private static readonly TimeSpan ScopeValidationTimeout = TimeSpan.FromSeconds(10);
    internal const int ExistingOperationReconciliationTurnLimit = 20;
    internal static readonly TimeSpan DispatchObservationMaxAge = TimeSpan.FromSeconds(2);

    private readonly AppServerClient _stateReader;
    private readonly DesktopIpcClient _desktop;
    private readonly DesktopThreadOwnerActivator _ownerActivator;
    private readonly RecoveryOperationJournal _journal;
    private readonly GuardianLog _log;
    private readonly IRecoveryInterferenceGuard? _interferenceGuard;
    private readonly IRecoveryStructuredInputReplayAuthority? _structuredInputReplayAuthority;
    private readonly IDesktopStructuredInputCapabilityProvider? _transportSemanticCapabilities;
    private readonly bool _requireCurrentNativeChannel;
    private readonly bool _requireExplicitInterferenceClear;
    private readonly ThreadActionCoordinator? _threadActions;
    private readonly RecoveryClassifier _classifier = new();
    private readonly object _policySync = new();
    private RecoveryCountingMode _defaultCountingMode;
    private int _defaultMaximumAttempts;
    private bool _defaultUnlimitedAttempts;
    private readonly Func<string, int, CancellationToken, Task<IReadOnlyList<TurnSnapshot>>>
        _readRecentTurns;
    private readonly SemaphoreSlim[] _operationLeases = Enumerable.Range(0, 64)
        .Select(static _ => new SemaphoreSlim(1, 1))
        .ToArray();
    private long _scopeGeneration;

    public RecoveryService(
        AppServerClient stateReader,
        DesktopIpcClient desktop,
        DesktopThreadOwnerActivator ownerActivator,
        RecoveryOperationJournal journal,
        GuardianLog log)
        : this(stateReader, desktop, ownerActivator, journal, log, null)
    {
    }

    internal RecoveryService(
        AppServerClient stateReader,
        DesktopIpcClient desktop,
        DesktopThreadOwnerActivator ownerActivator,
        RecoveryOperationJournal journal,
        GuardianLog log,
        IRecoveryInterferenceGuard? interferenceGuard = null,
        Func<string, int, CancellationToken, Task<IReadOnlyList<TurnSnapshot>>>? readRecentTurns = null,
        IRecoveryStructuredInputReplayAuthority? structuredInputReplayAuthority = null,
        IDesktopStructuredInputCapabilityProvider? transportSemanticCapabilities = null,
        bool requireCurrentNativeChannel = false,
        bool requireExplicitInterferenceClear = false,
        ThreadActionCoordinator? threadActions = null,
        RecoveryCountingMode defaultCountingMode = RecoveryCountingMode.PerFailedTurn,
        int defaultMaximumAttempts = RecoveryAttemptPolicyLimits.DefaultMaximumAttempts,
        bool defaultUnlimitedAttempts = false)
    {
        _stateReader = stateReader;
        _desktop = desktop;
        _ownerActivator = ownerActivator;
        _journal = journal;
        _log = log;
        _interferenceGuard = interferenceGuard;
        _readRecentTurns = readRecentTurns ?? stateReader.ReadRecentTurnsAsync;
        _structuredInputReplayAuthority = structuredInputReplayAuthority;
        _transportSemanticCapabilities = transportSemanticCapabilities;
        _requireCurrentNativeChannel = requireCurrentNativeChannel;
        _requireExplicitInterferenceClear = requireExplicitInterferenceClear;
        _threadActions = threadActions;
        _defaultCountingMode = Enum.IsDefined(defaultCountingMode)
            ? defaultCountingMode
            : RecoveryCountingMode.PerFailedTurn;
        _defaultMaximumAttempts = Math.Clamp(
            defaultMaximumAttempts,
            1,
            RecoveryAttemptPolicyLimits.MaximumFiniteAttempts);
        _defaultUnlimitedAttempts = defaultUnlimitedAttempts;
    }

    internal void SetDefaultRecoveryPolicy(
        RecoveryCountingMode countingMode,
        int maximumAttempts,
        bool unlimitedAttempts)
    {
        lock (_policySync)
        {
            _defaultCountingMode = Enum.IsDefined(countingMode)
                ? countingMode
                : RecoveryCountingMode.PerFailedTurn;
            _defaultMaximumAttempts = Math.Clamp(
                maximumAttempts,
                1,
                RecoveryAttemptPolicyLimits.MaximumFiniteAttempts);
            _defaultUnlimitedAttempts = unlimitedAttempts;
        }
    }

    public Task<RecoveryOperationRecord?> FindOperationAsync(
        string threadId,
        string failedTurnId,
        CancellationToken cancellationToken = default) =>
        _journal.FindAsync(threadId, failedTurnId, cancellationToken);

    public Task<RecoveryCurrentTurnReconciliation> ReconcileCurrentTurnAsync(
        string threadId,
        TurnSnapshot currentTurn,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentTurn);

        // A turn the app-server reported without an id cannot be reconciled: the journal is keyed by
        // turn id, so there is nothing to match and the honest answer is an empty reconciliation. The
        // journal rejects a non-UUID id with ArgumentException, and GuardianEngine caught that as a
        // journal outage -- it blocked the task and flipped the follow-up journal to conservative
        // recovery, so one id-less turn stalled recovery for every task in that scan.
        if (!Guid.TryParse(currentTurn.Id, out _))
        {
            return Task.FromResult(new RecoveryCurrentTurnReconciliation(
                RecoverySuccessor: null,
                IsExactSuccessorMatch: false,
                RecoverySuccessorClosed: false,
                AbandonedCount: 0));
        }

        var hasConfirmedSuccessfulTerminal =
            string.Equals(currentTurn.Status, "completed", StringComparison.OrdinalIgnoreCase) &&
            currentTurn.HasConfirmedLocalTerminal;
        return _journal.ReconcileCurrentTurnAsync(
            threadId,
            currentTurn.Id,
            currentTurn.UserMessageClientIds,
            closeRecoverySuccessor: hasConfirmedSuccessfulTerminal,
            cancellationToken);
    }

    public Task<int> AbandonSupersededOperationsAsync(
        string threadId,
        string currentTurnId,
        CancellationToken cancellationToken = default) =>
        _journal.AbandonSupersededAsync(threadId, currentTurnId, cancellationToken);

    // The engine seeds its in-memory attempt counters from this so a resend that happened before the
    // last restart still shows up in the UI. A thread id that is not a UUID cannot have a journal
    // record at all, so an empty ledger is the correct answer rather than an exception on a path that
    // only exists to describe history.
    public async Task<GuardianRecoveryLedger> ReadRecoveryLedgerAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(threadId, out _))
        {
            return GuardianRecoveryLedger.Empty;
        }

        try
        {
            return await _journal.ReadThreadLedgerAsync(threadId, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return GuardianRecoveryLedger.Empty;
        }
    }

    public async Task<RecoveryOperationRecord?> ReconcileExistingOperationAsync(
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(thread);
        ArgumentNullException.ThrowIfNull(failedTurn);

        var operationLease = GetOperationLease(thread.Id);
        await operationLease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var operation = await _journal.FindAsync(thread.Id, failedTurn.Id, cancellationToken)
                .ConfigureAwait(false);
            if (operation is null)
            {
                return null;
            }

            if (operation.State == RecoveryOperationState.Dispatching)
            {
                operation = await TransitionBeforeSendingAsync(
                        operation,
                        RecoveryOperationState.Uncertain,
                        cancellationToken)
                    .ConfigureAwait(false) ??
                    await _journal.FindAsync(thread.Id, failedTurn.Id, cancellationToken)
                        .ConfigureAwait(false) ??
                    operation;
            }

            if (operation.State != RecoveryOperationState.Uncertain)
            {
                return operation;
            }

            var reconciliation = await ReconcilePersistedOperationAsync(
                    thread,
                    failedTurn,
                    operation,
                    cancellationToken)
                .ConfigureAwait(false);
            return reconciliation.Record;
        }
        finally
        {
            operationLease.Release();
        }
    }

    public long BeginScopeValidationGeneration()
        => Interlocked.Increment(ref _scopeGeneration);

    public async Task WaitForRecoveryInterferenceToClearAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        while (_interferenceGuard is not null)
        {
            var observation = await _interferenceGuard.CheckAsync(threadId, cancellationToken)
                .ConfigureAwait(false);

            // Keyboard focus alone is not interference. A foreground Codex window keeps focus parked in its
            // composer, so waiting for Status == Clear held every retry back for as long as Codex was
            // foreground. Only an unsent draft in that composer is worth yielding to.
            if (observation.Status != RecoveryInterferenceStatus.Editing ||
                !observation.HasFocusedDraft)
            {
                return;
            }

            try
            {
                await _interferenceGuard.WaitForChangeAsync(observation.Version, cancellationToken)
                    .WaitAsync(TimeSpan.FromSeconds(1), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                // A fresh direct observation closes any gap from a dropped WinEvent.
            }
        }

        await _ownerActivator.WaitForMinimumIdleAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<RecoveryExecutionResult> ExecuteAsync(
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        RecoveryDecision decision,
        string continueMessage,
        bool includeSubAgents,
        long scopeGeneration,
        Func<bool> isDispatchAllowed,
        CancellationToken cancellationToken = default)
    {
        await using var threadActionLease = _threadActions is null
            ? null
            : await _threadActions.AcquireAsync(thread.Id, cancellationToken)
                .ConfigureAwait(false);
        var operationLease = GetOperationLease(thread.Id);
        await operationLease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ExecuteCoreAsync(
                    thread,
                    failedTurn,
                    decision,
                    continueMessage,
                    includeSubAgents,
                    scopeGeneration,
                    isDispatchAllowed,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            operationLease.Release();
        }
    }

    private async Task<RecoveryExecutionResult> ExecuteCoreAsync(
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        RecoveryDecision decision,
        string continueMessage,
        bool includeSubAgents,
        long scopeGeneration,
        Func<bool> isDispatchAllowed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(isDispatchAllowed);
        var currentDecision = _classifier.Classify(failedTurn);
        if (decision.Action == RecoveryActionKind.None ||
            currentDecision.Action == RecoveryActionKind.None ||
            currentDecision.Action != decision.Action ||
            !currentDecision.IsTransient ||
            !decision.IsTransient)
        {
            return RecoveryExecutionResult.Failed(
                "The failed turn no longer has an exact, explicitly recoverable classification; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged);
        }

        RecoveryOperationRecord? existingOperation;
        try
        {
            // A durable operation is the at-most-once authority for this exact failed turn.
            // Resolve it before capability or transport gates so old terminal/uncertain records
            // are read and reconciled rather than being mistaken for a new send attempt.
            existingOperation = await _journal.FindAsync(
                    thread.Id,
                    failedTurn.Id,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidOperationException or
                NotSupportedException or ArgumentException)
        {
            _log.Error("Recovery operation lookup failed; no message was sent: " + exception.Message, thread.Id);
            return PersistenceFailure(
                "Recovery operation lookup failed; automatic recovery was cancelled before sending.");
        }

        if (existingOperation is not null)
        {
            if (existingOperation.Action != decision.Action)
            {
                return RecoveryExecutionResult.Failed(
                    "This failed turn already has a different durable recovery action; no second operation was created.",
                    isUserBlocked: true,
                    RecoveryFailureKind.StateChanged);
            }

            if (existingOperation.State == RecoveryOperationState.Confirmed)
            {
                return existingOperation.NewTurnId is not null
                    ? RecoveryExecutionResult.Ok(
                        $"The recovery operation was already confirmed by the durable journal: {existingOperation.NewTurnId}",
                        existingOperation.NewTurnId)
                    : PersistenceFailure(
                        "The durable recovery operation is confirmed without a committed turn id; no message was sent.");
            }

            if (existingOperation.State == RecoveryOperationState.Accepted)
            {
                return RecoveryExecutionResult.Ok(
                    "The durable journal retains a legacy Desktop acknowledgement and will not dispatch it again.");
            }

            if (existingOperation.State == RecoveryOperationState.Abandoned)
            {
                return RecoveryExecutionResult.Failed(
                    "This failed turn has a closed recovery operation and will not be sent again.",
                    isUserBlocked: true,
                    RecoveryFailureKind.StateChanged);
            }

            if (existingOperation.State == RecoveryOperationState.Dispatching)
            {
                existingOperation = await TransitionBeforeSendingAsync(
                        existingOperation,
                        RecoveryOperationState.Uncertain,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (existingOperation is null)
                {
                    return PersistenceFailure(
                        "The previous dispatch could not be placed into conservative reconciliation; nothing was sent.");
                }
            }

            if (existingOperation.State == RecoveryOperationState.Uncertain)
            {
                var reconciliation = await ReconcilePersistedOperationAsync(
                        thread,
                        failedTurn,
                        existingOperation,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (reconciliation.Result is not null)
                {
                    return reconciliation.Result;
                }

                // Reconciliation may hand an in-place retry back as retryable when the failed turn is still
                // last: that edit provably never landed, and its expected-turn compare-and-swap makes
                // another attempt idempotent. Anything still uncertain keeps the conservative refusal.
                if (reconciliation.Record.State != RecoveryOperationState.Retryable)
                {
                    return RecoveryExecutionResult.Failed(
                        "The prior recovery operation remains uncertain and cannot be attributed by its stable client id; no message was sent.",
                        isUserBlocked: true,
                        RecoveryFailureKind.DesktopUnavailable);
                }

                existingOperation = reconciliation.Record;
            }

            if ((existingOperation.State is RecoveryOperationState.Prepared or RecoveryOperationState.Retryable) &&
                string.IsNullOrWhiteSpace(existingOperation.ClientMessageId))
            {
                return RecoveryExecutionResult.Failed(
                    "The persisted recovery operation has no stable client id; manual review is required and no id was fabricated.",
                    isUserBlocked: true,
                    RecoveryFailureKind.DesktopUnavailable);
            }
        }

        RecoveryCurrentTurnReconciliation lineage;
        try
        {
            lineage = await _journal.ReconcileCurrentTurnAsync(
                    thread.Id,
                    failedTurn.Id,
                    failedTurn.UserMessageClientIds,
                    closeRecoverySuccessor: false,
                    cancellationToken)
                .ConfigureAwait(false);
            if (lineage.RecoverySuccessor is not null && !lineage.IsExactSuccessorMatch)
            {
                // A non-exact successor is a residual record that never confirmed a new turn id -- the
                // edit-last-user-turn contract does not read one back, so a confirmation timeout leaves
                // exactly that. Blocking on it stranded the task forever: the flag outlived every later
                // failure and no new failed turn could clear it. An in-place retry is safe to dispatch
                // anyway, because the owner applies the expected-turn compare-and-swap or rejects it as
                // stale, so it cannot duplicate a message. The residual record is archived first so it
                // stops acting as the inexact fallback on the next reconcile.
                if (!RecoveryOperationJournal.IsInPlaceRetryAction(decision.Action))
                {
                    _log.Warning(RecoverySuccessorUncertainMessage, thread.Id);
                    return RecoveryExecutionResult.Failed(
                        RecoverySuccessorUncertainMessage,
                        isUserBlocked: true,
                        RecoveryFailureKind.StateChanged);
                }

                var abandoned = await _journal
                    .AbandonSupersededAsync(thread.Id, failedTurn.Id, cancellationToken)
                    .ConfigureAwait(false);
                _log.Info(
                    "Archived " + abandoned.ToString(CultureInfo.InvariantCulture) +
                    " unconfirmed recovery operation(s) so the in-place retry is not blocked by an " +
                    "inexact successor.",
                    thread.Id);
                lineage = await _journal.ReconcileCurrentTurnAsync(
                        thread.Id,
                        failedTurn.Id,
                        failedTurn.UserMessageClientIds,
                        closeRecoverySuccessor: false,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (lineage.RecoverySuccessor is not null &&
                lineage.RecoverySuccessor.CountingMode == RecoveryCountingMode.OriginalFailedTurnOnly)
            {
                _log.Warning(RecoveryChainBlockedMessage, thread.Id);
                return RecoveryExecutionResult.Failed(
                    RecoveryChainBlockedMessage,
                    isUserBlocked: true,
                    RecoveryFailureKind.StateChanged);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidOperationException or
                NotSupportedException or ArgumentException)
        {
            _log.Error("Recovery lineage validation failed; no message was sent: " + exception.Message, thread.Id);
            return PersistenceFailure(
                "Recovery lineage validation failed; automatic recovery was cancelled before sending.");
        }

        var policyCheck = ValidateDispatchPolicy(isDispatchAllowed);
        if (policyCheck is not null)
        {
            return policyCheck;
        }

        RecoveryStructuredInputReplayLease? structuredReplayLease = null;
        if (RequiresStructuredInputReplay(failedTurn, decision.Action))
        {
            if (_structuredInputReplayAuthority is null)
            {
                return RecoveryExecutionResult.Failed(
                    "Exact structured attachment replay authority is unavailable; nothing was sent.",
                    isUserBlocked: true,
                    RecoveryFailureKind.DesktopIncompatible);
            }

            try
            {
                structuredReplayLease = await _structuredInputReplayAuthority.AcquireAsync(
                        thread.Id,
                        failedTurn,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (RecoveryStructuredInputReplayException exception)
            {
                _log.Trace(
                    "Structured recovery replay was blocked: " + exception.Code,
                    thread.Id);
                return RecoveryExecutionResult.Failed(
                    "The exact structured attachment input could not be revalidated; nothing was sent.",
                    isUserBlocked: true,
                    RecoveryFailureKind.StateChanged);
            }
        }

        await using var structuredReplayLifetime = structuredReplayLease;

        var normalizedContinueMessage = SettingsService.NormalizeContinueMessage(continueMessage);
        var normalizedOriginalMessage = RecoveryClassifier.NormalizeRecoveryInput(failedTurn.UserText);
        var dispatchMessage = decision.Action is RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue
            ? normalizedOriginalMessage
            : normalizedContinueMessage;
        // Structured replay proves only exact payload authority. It does not grant dispatch
        // capability; native resend is checked independently below.
        var transportPayload = StructuredPresetPayload.Create(
            dispatchMessage.Length == 0 ? SettingsService.DefaultContinueMessage : dispatchMessage,
            Array.Empty<PresetAttachmentReference>());
        DesktopStructuredInputCapabilityLease? transportSemanticLease = null;
        var requiresInstalledStructuredInputProof = RequiresStructuredInputReplay(
            failedTurn,
            decision.Action);
        if (requiresInstalledStructuredInputProof && _transportSemanticCapabilities is not null)
        {
            var semanticCheck = await AcquireTransportSemanticLeaseAsync(
                    transportPayload,
                    cancellationToken)
                .ConfigureAwait(false);
            if (semanticCheck.Result is not null)
            {
                return semanticCheck.Result;
            }

            transportSemanticLease = semanticCheck.Lease;
        }
        else if (requiresInstalledStructuredInputProof && _requireCurrentNativeChannel)
        {
            return RecoveryExecutionResult.Failed(
                "The installed Codex Desktop recovery semantics are not proven; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopIncompatible);
        }

        var operationId = existingOperation?.OperationId ?? AppServerClient.CreateRecoveryMessageId(
            thread.Id,
            failedTurn.Id,
            decision.Action);
        var clientMessageId = existingOperation?.ClientMessageId ?? operationId;
        var inputHash = existingOperation?.InputHash ?? BuildRecoveryPayloadHash(
            decision.Action,
            dispatchMessage,
            structuredReplayLease?.InputDigest);

        RecoveryIncidentPolicy incidentPolicy;
        try
        {
            incidentPolicy = await ResolveIncidentPolicyAsync(
                    thread.Id,
                    failedTurn,
                    decision,
                    lineage,
                    scopeGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (RecoveryPolicyBlockedException exception)
        {
            return RecoveryExecutionResult.Failed(
                exception.Message,
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged);
        }

        var provenUnsentOriginalReplay = RecoveryClassifier.IsProvenUnsentOriginalReplay(
            failedTurn,
            decision);
        var capabilityCheck = ValidateGuardedAutomaticRecoveryCapability(
            _desktop.GetRecoveryTransportCapabilities(decision.Action, provenUnsentOriginalReplay),
            decision.Action,
            provenUnsentOriginalReplay);
        if (capabilityCheck is not null)
        {
            return capabilityCheck;
        }

        if (_requireCurrentNativeChannel &&
            (!_desktop.IsConnected || !_desktop.IsNativeChannelAvailable))
        {
            // An unproven channel is transient, not a version verdict: Guardian starting before Codex
            // Desktop, or Desktop restarting, lands here every time. Reporting DesktopIncompatible made
            // it permanent -- that kind locks until a new failed turn arrives, carries no retry time, and
            // is not a desktop-event-driven failure, so a task failed this way was never retried even
            // after the channel connected and proved itself seconds later. DesktopUnavailable is the
            // kind that already waits on the desktop signal and retries the moment it arrives.
            return RecoveryExecutionResult.Failed(
                "The Codex Desktop native owner channel is not ready yet; the retry waits for it and " +
                "nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopUnavailable);
        }

        RecoveryOperationRecord operation;
        if (existingOperation is not null)
        {
            operation = existingOperation;
        }
        else
        {
            try
            {
                var prepared = await _journal.GetOrCreateAsync(
                        operationId,
                        thread.Id,
                        failedTurn.Id,
                        decision.Action,
                        inputHash,
                        clientMessageId,
                        incidentPolicy,
                        cancellationToken)
                    .ConfigureAwait(false);
                operation = prepared.Record;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or InvalidOperationException or
                    NotSupportedException or ArgumentException)
            {
                _log.Error("Recovery journal preparation failed; no message was sent: " + exception.Message, thread.Id);
                return PersistenceFailure(
                    "Recovery journal preparation failed; automatic recovery was cancelled before sending.");
            }
        }

        policyCheck = ValidateDispatchPolicy(isDispatchAllowed);
        if (policyCheck is not null)
        {
            return policyCheck;
        }

        await _stateReader.EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
        var latest = ReconcileLatestTurnForDispatch(
            await _stateReader.ReadLatestTurnAsync(thread.Id, cancellationToken).ConfigureAwait(false),
            failedTurn);
        var stateCheck = ValidateLatestTurn(latest, failedTurn.Id);
        if (stateCheck is not null)
        {
            await AbandonIfStateChangedAsync(operation, stateCheck, thread.Id, cancellationToken)
                .ConfigureAwait(false);
            return stateCheck;
        }

        var eligibilityCheck = await RevalidateThreadEligibilityAsync(
                thread.Id,
                includeSubAgents,
                scopeGeneration,
                cancellationToken)
            .ConfigureAwait(false);
        if (eligibilityCheck is not null)
        {
            return eligibilityCheck;
        }

        var ownerActivation = await _ownerActivator.EnsureOwnerAsync(thread.Id, cancellationToken)
            .ConfigureAwait(false);
        _log.WriteDispatchGate(
            thread.Id,
            failedTurn.Id,
            "ownerActivation",
            ownerActivation.Status.ToString(),
            ownerActivation.IsAvailable);
        if (!ownerActivation.IsAvailable)
        {
            return ownerActivation.Status == DesktopThreadOwnerActivationStatus.Incompatible
                ? RecoveryExecutionResult.Failed(
                    ownerActivation.Detail,
                    isUserBlocked: true,
                    RecoveryFailureKind.DesktopIncompatible)
                : RecoveryExecutionResult.Failed(
                    ownerActivation.Detail,
                    isUserBlocked:
                        ownerActivation.Status == DesktopThreadOwnerActivationStatus.DeferredForUserActivity,
                    failureKind: ownerActivation.Status == DesktopThreadOwnerActivationStatus.DeferredForUserActivity
                        ? RecoveryFailureKind.UserActive
                        : RecoveryFailureKind.DesktopOwnerUnavailable);
        }

        var ownerStateGuardResult = await _desktop.AcquireThreadOwnerStateGuardAsync(
                thread.Id,
                cancellationToken)
            .ConfigureAwait(false);
        _log.WriteDispatchGate(
            thread.Id,
            failedTurn.Id,
            "ownerSnapshot",
            ownerStateGuardResult.Status.ToString(),
            ownerStateGuardResult.IsAvailable);
        if (!ownerStateGuardResult.IsAvailable)
        {
            return ownerStateGuardResult.Status == DesktopThreadOwnerStateGuardStatus.Incompatible
                ? RecoveryExecutionResult.Failed(
                    ownerStateGuardResult.Detail,
                    isUserBlocked: true,
                    RecoveryFailureKind.DesktopIncompatible)
                : RecoveryExecutionResult.Failed(
                    ownerStateGuardResult.Detail,
                    failureKind: RecoveryFailureKind.DesktopOwnerUnavailable);
        }

        await using var ownerStateGuard = ownerStateGuardResult.Guard!;
        // 108 of the 110 dispatch attempts in the 2026-08-29 evening run ended inside
        // ValidateOwnerStateSnapshot, which returns before any gate record is written — the diagnostics
        // showed a gate that simply stopped after `ownerSnapshot: Available`, with no way to tell a
        // busy owner apart from a crashed dispatcher. Record the owner's real runtime status here,
        // whether or not the check passes, so the wait is attributable.
        _log.WriteDispatchGate(
            thread.Id,
            failedTurn.Id,
            "ownerRuntimeStatus",
            ownerStateGuard.Snapshot.RuntimeStatus,
            IsOwnerRuntimeStatusDispatchable(ownerStateGuard.Snapshot.RuntimeStatus));
        var ownerStateCheck = ValidateOwnerStateSnapshot(ownerStateGuard.Snapshot, failedTurn);
        if (ownerStateCheck is not null)
        {
            await AbandonIfStateChangedAsync(operation, ownerStateCheck, thread.Id, cancellationToken)
                .ConfigureAwait(false);
            return ownerStateCheck;
        }

        policyCheck = ValidateDispatchPolicy(isDispatchAllowed);
        if (policyCheck is not null)
        {
            return policyCheck;
        }

        // Revalidate immediately before the Desktop owner enters the commit path.
        latest = ReconcileLatestTurnForDispatch(
            await _stateReader.ReadLatestTurnAsync(thread.Id, cancellationToken).ConfigureAwait(false),
            failedTurn);
        stateCheck = ValidateLatestTurn(latest, failedTurn.Id);
        if (stateCheck is not null)
        {
            await AbandonIfStateChangedAsync(operation, stateCheck, thread.Id, cancellationToken)
                .ConfigureAwait(false);
            return stateCheck;
        }

        eligibilityCheck = await RevalidateTargetThreadEligibilityAsync(
                thread.Id,
                includeSubAgents,
                cancellationToken)
            .ConfigureAwait(false);
        if (eligibilityCheck is not null)
        {
            return eligibilityCheck;
        }

        policyCheck = ValidateDispatchPolicy(isDispatchAllowed);
        if (policyCheck is not null)
        {
            return policyCheck;
        }

        if (!ownerStateGuard.IsCurrent)
        {
            return RecoveryExecutionResult.Failed(
                "The Desktop owner state changed during final validation; nothing was sent.",
                failureKind: RecoveryFailureKind.DesktopOwnerUnavailable);
        }

        var userActivityCheck = await ValidateUserIdleForDispatchAsync(
                thread.Id,
                failedTurn.Id,
                "beforeDispatchIntent",
                cancellationToken)
            .ConfigureAwait(false);
        if (userActivityCheck is not null)
        {
            return userActivityCheck;
        }

        if (structuredReplayLease is not null && !structuredReplayLease.IsCurrent)
        {
            return RecoveryExecutionResult.Failed(
                "The structured attachment replay lease changed before dispatch; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged);
        }

        var semanticLeaseCheck = await ValidateTransportSemanticLeaseAsync(
                transportSemanticLease,
                transportPayload,
                cancellationToken)
            .ConfigureAwait(false);
        if (semanticLeaseCheck is not null)
        {
            return semanticLeaseCheck;
        }

        var dispatchTransition = await TransitionBeforeSendingAsync(
                operation,
                RecoveryOperationState.Dispatching,
                cancellationToken)
            .ConfigureAwait(false);
        if (dispatchTransition is null)
        {
            return PersistenceFailure(
                "The recovery dispatch intent could not be committed to disk; no message was sent.");
        }

        operation = dispatchTransition;
        policyCheck = ValidateDispatchPolicy(isDispatchAllowed);
        if (cancellationToken.IsCancellationRequested || policyCheck is not null)
        {
            var retryable = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retryable.State != RecoveryOperationState.Retryable)
            {
                return PersistenceFailure(
                    "The recovery policy changed before Desktop dispatch, but the unsent operation could not be marked retryable. Guardian will not send it.");
            }

            return policyCheck ?? RecoveryExecutionResult.Failed(
                "Monitoring stopped before Desktop dispatch; the unsent operation remains retryable.",
                isUserBlocked: true,
                RecoveryFailureKind.PolicyChanged);
        }

        if (!ownerStateGuard.IsCurrent)
        {
            var retryable = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retryable.State != RecoveryOperationState.Retryable)
            {
                return PersistenceFailure(
                    "The Desktop owner state changed before sending, but the unsent operation could not be marked retryable. Guardian will not send it.");
            }

            return RecoveryExecutionResult.Failed(
                "The Desktop owner state changed before the start-turn request; the unsent recovery remains retryable.",
                failureKind: RecoveryFailureKind.DesktopOwnerUnavailable);
        }

        semanticLeaseCheck = await ValidateTransportSemanticLeaseAsync(
                transportSemanticLease,
                transportPayload,
                cancellationToken)
            .ConfigureAwait(false);
        if (semanticLeaseCheck is not null)
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return semanticLeaseCheck;
        }

        RecoveryInterferenceSnapshot? finalObservation = null;
        try
        {
            userActivityCheck = await ValidateUserIdleForDispatchAsync(
                    thread.Id,
                    failedTurn.Id,
                    "beforeStartTurn",
                    cancellationToken,
                    observation => finalObservation = observation)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            var retryable = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retryable.State != RecoveryOperationState.Retryable)
            {
                return PersistenceFailure(
                    "Monitoring stopped during the final editor observation, but the unsent operation could not be marked retryable. Guardian will not send it.");
            }

            return RecoveryExecutionResult.Failed(
                "Monitoring stopped during the final editor observation; the unsent recovery remains retryable.",
                isUserBlocked: true,
                RecoveryFailureKind.PolicyChanged);
        }

        if (userActivityCheck is not null)
        {
            var retryable = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retryable.State != RecoveryOperationState.Retryable)
            {
                return PersistenceFailure(
                    "The user became active before Desktop dispatch, but the unsent operation could not be marked retryable. Guardian will not send it.");
            }

            return userActivityCheck;
        }

        policyCheck = ValidateDispatchPolicy(isDispatchAllowed);
        if (cancellationToken.IsCancellationRequested || policyCheck is not null)
        {
            var retryable = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retryable.State != RecoveryOperationState.Retryable)
            {
                return PersistenceFailure(
                    "The recovery policy changed after the final editor observation, but the unsent operation could not be marked retryable. Guardian will not send it.");
            }

            return policyCheck ?? RecoveryExecutionResult.Failed(
                "Monitoring stopped after the final editor observation; the unsent recovery remains retryable.",
                isUserBlocked: true,
                RecoveryFailureKind.PolicyChanged);
        }

        if (!ownerStateGuard.IsCurrent)
        {
            var retryable = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retryable.State != RecoveryOperationState.Retryable)
            {
                return PersistenceFailure(
                    "The Desktop owner changed after the final editor observation, but the unsent operation could not be marked retryable. Guardian will not send it.");
            }

            return RecoveryExecutionResult.Failed(
                "The verified Desktop owner changed after the final editor observation; the unsent recovery remains retryable.",
                failureKind: RecoveryFailureKind.DesktopOwnerUnavailable);
        }

        using var desktopCommit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        desktopCommit.CancelAfter(DesktopCommitTimeout);
        using var dispatchGuardLifetime = new CancellationTokenSource();
        var interferenceWatch = WatchDispatchInterferenceAsync(
            finalObservation,
            desktopCommit,
            dispatchGuardLifetime.Token);
        try
        {
            bool CanStartWrite() => !cancellationToken.IsCancellationRequested &&
                ValidateDispatchPolicy(isDispatchAllowed) is null &&
                (!_requireCurrentNativeChannel || _desktop.IsNativeChannelAvailable) &&
                ownerStateGuard.IsCurrent &&
                (structuredReplayLease is null || structuredReplayLease.IsCurrent);
            var isInPlaceRetry = IsInPlaceRetryAction(decision.Action);
            string startedTurnId;
            if (isInPlaceRetry)
            {
                // The owner rolls the failed turn back by one and resubmits the same input, so the
                // task keeps a single user message instead of gaining a duplicate. It acknowledges
                // with {"ok":true} and no turn id, so the replacement turn is read back from
                // observed task state below.
                await _desktop.RetryFailedTurnInPlaceAsync(
                        thread.Id,
                        failedTurn.Id,
                        normalizedOriginalMessage,
                        failedTurn.HasAttachments,
                        desktopCommit.Token,
                        canStartWrite: CanStartWrite)
                    .ConfigureAwait(false);
                startedTurnId = await ResolveInPlaceRetrySuccessorAsync(
                        thread.Id,
                        failedTurn.Id,
                        cancellationToken)
                    .ConfigureAwait(false) ?? string.Empty;
            }
            else
            {
                var started = await _desktop.AppendRecoverySuccessorAsync(
                        thread.Id,
                        decision.Action,
                        structuredReplayLease?.CanonicalInputJson ?? failedTurn.RawUserInputJson,
                        normalizedOriginalMessage,
                        failedTurn.HasAttachments,
                        normalizedContinueMessage,
                        clientMessageId,
                        desktopCommit.Token,
                        canStartWrite: CanStartWrite,
                        provenUnsentOriginalReplay: provenUnsentOriginalReplay)
                    .ConfigureAwait(false);
                startedTurnId = started.TurnId;
            }

            if (string.IsNullOrWhiteSpace(startedTurnId) ||
                string.Equals(startedTurnId, failedTurn.Id, StringComparison.OrdinalIgnoreCase))
            {
                operation = await TransitionAfterDispatchAsync(
                        operation,
                        RecoveryOperationState.Uncertain,
                        thread.Id,
                        cancellationToken)
                    .ConfigureAwait(false);
                return RecoveryExecutionResult.Failed(
                    isInPlaceRetry
                        ? "Codex Desktop confirmed the in-place retry, but its replacement turn has not been observed yet. Guardian will reconcile without resending."
                        : "Codex Desktop accepted the request, but the committed replacement turn could not be identified. Guardian will reconcile without redispatching the uncertain request.",
                    isUserBlocked: true,
                    RecoveryFailureKind.DesktopUnavailable);
            }

            var confirmed = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Confirmed,
                    thread.Id,
                    cancellationToken,
                    newTurnId: startedTurnId)
                .ConfigureAwait(false);
            if (confirmed.State != RecoveryOperationState.Confirmed)
            {
                return PersistenceFailure(
                    "The recovery was accepted, but its durable confirmation could not be saved. Guardian will reconcile without redispatching the uncertain request.");
            }

            var actionDescription = isInPlaceRetry
                ? "Retried the failed turn in place through the native Codex Desktop channel"
                : "Appended a continue successor through the native Codex Desktop channel";
            return RecoveryExecutionResult.Ok(
                $"{actionDescription}; new turn: {startedTurnId}",
                startedTurnId);
        }
        catch (OperationCanceledException) when (desktopCommit.IsCancellationRequested)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return await ReconcileUncertainDeliveryAsync(
                    thread,
                    failedTurn,
                    operation,
                    "The bounded Desktop commit window elapsed after dispatch began.",
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DesktopIpcProtocolException exception) when (
            string.Equals(exception.Code, "guardian-state-changed", StringComparison.Ordinal))
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Abandoned,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return RecoveryExecutionResult.Failed(
                "The task state changed inside Codex Desktop; the stale recovery action was cancelled.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged);
        }
        catch (DesktopIpcProtocolException exception) when (
            exception.Code is "guardian-original-input-unavailable" or "request-version-mismatch" or
                "no-handler-for-request" or "invalid-initialize-response")
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Abandoned,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Error("Codex Desktop rejected an incompatible recovery request: " + exception.Code, thread.Id);
            return RecoveryExecutionResult.Failed(
                "Codex Desktop rejected this recovery action as incompatible; nothing will be resent for this failed turn.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopIncompatible);
        }
        catch (DesktopIpcProtocolException exception) when (
            exception.Code is "no-client-found" or "guardian-owner-unavailable")
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return RecoveryExecutionResult.Failed(
                "Waiting for the Codex Desktop task owner; the recovery request was explicitly rejected before commit.",
                failureKind: RecoveryFailureKind.DesktopOwnerUnavailable);
        }
        catch (DesktopIpcProtocolException exception) when (
            exception.Stage is DesktopIpcDeliveryStage.DispatchedUnknown or DesktopIpcDeliveryStage.Acknowledged)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return await ReconcileUncertainDeliveryAsync(
                    thread,
                    failedTurn,
                    operation,
                    exception.Message,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        // Refusing the edit because the turn is no longer last is permanent for this operation: the
        // conversation has moved past that message and it can never become the last one again. Leaving
        // the record Retryable would make Guardian re-send a request that is certain to be refused
        // every scan, so the operation is closed instead and the next scan classifies the thread's new
        // last turn on its own merits — which is the turn the user is actually waiting on.
        catch (DesktopIpcProtocolException exception) when (
            DesktopIpcClient.IsStaleEditRefusal(exception.Code))
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Abandoned,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Warning(
                "The failed turn is no longer the last message, so the in-place edit was refused and the " +
                "recovery operation was closed; the next scan will classify the current last turn.",
                thread.Id);
            return RecoveryExecutionResult.Failed(
                exception.Message,
                failureKind: RecoveryFailureKind.StateChanged);
        }
        catch (DesktopIpcProtocolException exception) when (
            exception.Stage == DesktopIpcDeliveryStage.NotDispatched)
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Warning("Codex Desktop rejected the recovery request: " + exception.Code, thread.Id);
            return RecoveryExecutionResult.Failed(
                "Codex Desktop failed before the recovery request was dispatched: " + exception.Message,
                failureKind: RecoveryFailureKind.DesktopUnavailable);
        }
        catch (DesktopIpcProtocolException exception)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return await ReconcileUncertainDeliveryAsync(
                    thread,
                    failedTurn,
                    operation,
                    exception.Message,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DesktopIpcDeliveryException exception) when (
            exception.Stage == DesktopIpcDeliveryStage.NotDispatched)
        {
            await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return RecoveryExecutionResult.Failed(
                "Codex Desktop was unavailable before the recovery request was dispatched.",
                failureKind: RecoveryFailureKind.DesktopUnavailable);
        }
        catch (Exception exception) when (
            exception is DesktopIpcDeliveryException or IOException or TimeoutException)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            return await ReconcileUncertainDeliveryAsync(
                    thread,
                    failedTurn,
                    operation,
                    exception.Message,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            operation = await TransitionAfterDispatchAsync(
                    operation,
                    RecoveryOperationState.Uncertain,
                    thread.Id,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Warning("Codex Desktop recovery failed after dispatch began: " + exception.Message, thread.Id);
            return RecoveryExecutionResult.Failed(
                "Recovery failed after dispatch began; Guardian will reconcile without redispatching the uncertain request.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopUnavailable);
        }
        finally
        {
            dispatchGuardLifetime.Cancel();
            await interferenceWatch.ConfigureAwait(false);
        }
    }

    private async Task<RecoveryExecutionResult?> RevalidateThreadEligibilityAsync(
        string threadId,
        bool includeSubAgents,
        long scopeGeneration,
        CancellationToken cancellationToken)
    {
        if (scopeGeneration != Volatile.Read(ref _scopeGeneration))
        {
            return RecoveryExecutionResult.Failed(
                "The monitoring scope changed before recovery validation; nothing was sent.",
                isUserBlocked: true,
                failureKind: RecoveryFailureKind.PolicyChanged);
        }

        return await RevalidateTargetThreadEligibilityAsync(
                threadId,
                includeSubAgents,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<RecoveryExecutionResult?> RevalidateTargetThreadEligibilityAsync(
        string threadId,
        bool includeSubAgents,
        CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ScopeValidationTimeout);
            var current = await _stateReader.ReadThreadForRecoveryAsync(threadId, timeout.Token)
                .ConfigureAwait(false);
            return ValidateTargetThreadEligibility(threadId, includeSubAgents, current);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to revalidate the target recovery task: " + exception.Message, threadId);
            return RecoveryExecutionResult.Failed(
                "The target task's current storage and source metadata could not be revalidated; nothing was sent.",
                failureKind: RecoveryFailureKind.TransportFailed);
        }
    }

    internal static RecoveryExecutionResult? ValidateThreadEligibility(
        string threadId,
        bool includeSubAgents,
        IReadOnlyCollection<ThreadSummary> activeThreads,
        IReadOnlyCollection<ThreadSummary> archivedThreads)
    {
        if (archivedThreads.Any(thread =>
                string.Equals(thread.Id, threadId, StringComparison.OrdinalIgnoreCase)))
        {
            return RecoveryExecutionResult.Failed(
                "The task is archived; automatic recovery was cancelled before Desktop dispatch.",
                isUserBlocked: true,
                RecoveryFailureKind.PolicyChanged);
        }

        var activeMatches = activeThreads
            .Where(thread => string.Equals(thread.Id, threadId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (activeMatches.Length != 1)
        {
            return RecoveryExecutionResult.Failed(
                "The task is no longer uniquely present in the active task scope; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.PolicyChanged);
        }

        var active = activeMatches[0];
        if (active.IsArchived || active.IsEphemeral ||
            active.IsSubAgent && !includeSubAgents)
        {
            return RecoveryExecutionResult.Failed(
                "The task is outside the configured automatic recovery scope; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.PolicyChanged);
        }

        return null;
    }

    internal static RecoveryExecutionResult? ValidateTargetThreadEligibility(
        string threadId,
        bool includeSubAgents,
        ThreadSummary current) =>
        ValidateThreadEligibility(
            threadId,
            includeSubAgents,
            current.IsArchived ? [] : [current],
            current.IsArchived ? [current] : []);

    private static RecoveryExecutionResult? ValidateDispatchPolicy(Func<bool> isDispatchAllowed)
    {
        try
        {
            if (isDispatchAllowed())
            {
                return null;
            }
        }
        catch
        {
        }

        return RecoveryExecutionResult.Failed(
            "Automatic recovery policy changed before Desktop dispatch; nothing was sent.",
            isUserBlocked: true,
            RecoveryFailureKind.PolicyChanged);
    }

    private async Task<(RecoveryExecutionResult? Result, RecoveryOperationRecord Record)>
        ReconcilePersistedOperationAsync(
            ThreadSummary thread,
            TurnSnapshot failedTurn,
            RecoveryOperationRecord operation,
            CancellationToken cancellationToken)
    {
        IReadOnlyList<TurnSnapshot> recentTurns;
        try
        {
            recentTurns = await _readRecentTurns(
                    thread.Id,
                    ExistingOperationReconciliationTurnLimit,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace("Unable to reconcile the persisted recovery operation: " + exception.Message, thread.Id);
            return (
                RecoveryExecutionResult.Failed(
                    "The prior recovery dispatch is uncertain and task state is unavailable; nothing was resent.",
                    isUserBlocked: true,
                    RecoveryFailureKind.DesktopUnavailable),
                operation);
        }

        // A recovery record without its stable id cannot be attributed to any observed turn.
        // Keep it uncertain rather than inferring ownership from an unrelated newer turn.
        if (string.IsNullOrWhiteSpace(operation.ClientMessageId))
        {
            return (null, operation);
        }

        var boundedRecentTurns = recentTurns.Count > ExistingOperationReconciliationTurnLimit
            ? recentTurns.Take(ExistingOperationReconciliationTurnLimit).ToArray()
            : recentTurns;
        var matchingTurns = boundedRecentTurns
            .Where(turn =>
                turn.UserMessageClientIds?.Contains(
                    operation.ClientMessageId,
                    StringComparer.OrdinalIgnoreCase) == true &&
                !string.Equals(turn.Id, failedTurn.Id, StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        if (matchingTurns.Length > 1)
        {
            _log.Warning(
                "The stable recovery message id appeared in multiple recent turns; reconciliation remains uncertain.",
                thread.Id);
            return (null, operation);
        }

        var matchingTurn = matchingTurns.SingleOrDefault();
        if (matchingTurn is not null)
        {
            var confirmed = await TransitionBeforeSendingAsync(
                    operation,
                    RecoveryOperationState.Confirmed,
                    cancellationToken,
                    newTurnId: matchingTurn.Id)
                .ConfigureAwait(false);
            if (confirmed is null)
            {
                return (PersistenceFailure(
                    "A matching recovery turn was found, but durable confirmation could not be saved."), operation);
            }

            return (
                RecoveryExecutionResult.Ok(
                    $"The stable recovery message id matched an existing turn: {matchingTurn.Id}",
                    matchingTurn.Id),
                confirmed);
        }

        var latest = boundedRecentTurns.FirstOrDefault();
        if (latest is null)
        {
            return (
                RecoveryExecutionResult.Failed(
                    "The prior recovery dispatch is uncertain and no latest turn could be confirmed; nothing was resent.",
                    isUserBlocked: true,
                    RecoveryFailureKind.DesktopUnavailable),
                operation);
        }

        if (!string.Equals(latest.Id, failedTurn.Id, StringComparison.OrdinalIgnoreCase))
        {
            var isReopenableInPlaceRetry =
                operation.State == RecoveryOperationState.Uncertain &&
                IsInPlaceRetryAction(operation.Action) &&
                string.IsNullOrWhiteSpace(operation.NewTurnId);

            // An in-place retry replaces the failed turn instead of appending a successor, so it has
            // no stable client message id to match. Its expected-turn compare-and-swap means the owner
            // only accepts the edit while the failed turn is still last, so a newer latest turn is the
            // replacement this uncertain operation produced. Ordering is verified because an observed
            // latest turn that predates the failed turn is a stale read, not a replacement.
            if (isReopenableInPlaceRetry && IsPlausibleReplacementTurn(latest.Id, failedTurn.Id))
            {
                var reconciled = await TransitionBeforeSendingAsync(
                        operation,
                        RecoveryOperationState.Confirmed,
                        cancellationToken,
                        newTurnId: latest.Id)
                    .ConfigureAwait(false);
                if (reconciled is null)
                {
                    return (PersistenceFailure(
                        "The in-place retry's replacement turn was observed, but durable confirmation could not be saved."), operation);
                }

                return (
                    RecoveryExecutionResult.Ok(
                        $"The in-place retry replaced the failed turn; observed replacement turn: {latest.Id}",
                        latest.Id),
                    reconciled);
            }

            // A reopenable in-place retry that lands here saw a stale observation rather than a
            // supersession, so it falls through to the bounded reopen below instead of being closed.
            if (!isReopenableInPlaceRetry)
            {
                var abandoned = await TransitionBeforeSendingAsync(
                        operation,
                        RecoveryOperationState.Abandoned,
                        cancellationToken)
                    .ConfigureAwait(false) ?? operation;
                return (
                    RecoveryExecutionResult.Failed(
                        "A newer turn exists, but it cannot be attributed to this recovery operation; the old failure was superseded without resending.",
                        isUserBlocked: true,
                        RecoveryFailureKind.StateChanged),
                    abandoned);
            }
        }

        // The failed turn is still the last turn, so an in-place retry's edit never landed. Its
        // expected-turn compare-and-swap makes another attempt idempotent — the owner either applies the
        // edit or rejects it as stale with no side effect — so refusing forever strands the retry the user
        // is waiting on. Append actions keep the strict refusal below, and the bounded attempt count stops
        // a genuinely broken operation from reopening without end.
        if (operation.State == RecoveryOperationState.Uncertain &&
            IsInPlaceRetryAction(operation.Action) &&
            string.IsNullOrWhiteSpace(operation.NewTurnId) &&
            operation.AttemptCount < UncertainInPlaceRetryAttemptLimit)
        {
            var reopened = await TransitionBeforeSendingAsync(
                    operation,
                    RecoveryOperationState.Retryable,
                    cancellationToken)
                .ConfigureAwait(false);
            if (reopened is null)
            {
                return (PersistenceFailure(
                    "The uncertain in-place retry could not be durably reopened; nothing was sent."), operation);
            }

            _log.Info(
                "The failed turn is still last, so the uncertain in-place retry was reopened for another attempt.",
                thread.Id);
            return (null, reopened);
        }

        return (
            RecoveryExecutionResult.Failed(
                "The prior start-turn request may have been dispatched. The stable client id is used for reconciliation only; without proven receiver deduplication Guardian will not send it again.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopUnavailable),
            operation);
    }

    // An in-place retry may be reopened from Uncertain only while the failed turn is still last, but a
    // persistent owner fault could keep producing that shape. This ceiling turns that into a bounded
    // number of attempts per failed turn instead of an endless reopen loop.
    private const int UncertainInPlaceRetryAttemptLimit = 5;

    private const int InPlaceRetrySuccessorPollAttempts = 8;

    private static readonly TimeSpan InPlaceRetrySuccessorPollInterval = TimeSpan.FromMilliseconds(400);

    private static bool IsInPlaceRetryAction(RecoveryActionKind action) =>
        action is RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue;

    // The in-place retry contract acknowledges without a turn id, so the replacement turn is resolved
    // from observed task state. The expected-turn compare-and-swap already proved the failed turn was
    // still the last user turn when the owner accepted the edit, so a newer latest turn is the turn
    // this retry produced.
    private async Task<string?> ResolveInPlaceRetrySuccessorAsync(
        string threadId,
        string failedTurnId,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < InPlaceRetrySuccessorPollAttempts; attempt++)
        {
            if (attempt > 0)
            {
                await Task.Delay(InPlaceRetrySuccessorPollInterval, cancellationToken).ConfigureAwait(false);
            }

            IReadOnlyList<TurnSnapshot> recentTurns;
            try
            {
                recentTurns = await _readRecentTurns(
                        threadId,
                        ExistingOperationReconciliationTurnLimit,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _log.Trace(
                    "Unable to observe the in-place retry replacement turn: " + exception.Message,
                    threadId);
                return null;
            }

            var replacement = recentTurns
                .Select(turn => turn.Id)
                .Where(id => !string.IsNullOrWhiteSpace(id) && IsPlausibleReplacementTurn(id, failedTurnId))
                .OrderByDescending(id => id, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
            if (replacement is not null)
            {
                return replacement;
            }
        }

        return null;
    }

    // The owner acknowledges an in-place retry without a turn id, so the replacement turn is read back from
    // observed state. Turn ids are UUIDv7, whose leading hex digits are a millisecond timestamp, so a
    // candidate ordering before the failed turn is a stale observation rather than the replacement. The
    // journal recorded exactly that inversion once — a replacement id older than the turn it replaced — so
    // ordering is checked instead of trusting the observed list to be newest-first.
    private static bool IsPlausibleReplacementTurn(string candidateId, string failedTurnId)
    {
        if (string.Equals(candidateId, failedTurnId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // A non-canonical id carries no ordering, so it keeps the older behaviour of accepting any turn
        // that is not the failed one rather than being rejected outright.
        return !IsCanonicalUuid(candidateId) ||
            !IsCanonicalUuid(failedTurnId) ||
            string.Compare(candidateId, failedTurnId, StringComparison.OrdinalIgnoreCase) > 0;
    }

    private static bool IsCanonicalUuid(string value) =>
        value.Length == 36 && Guid.TryParseExact(value, "D", out _);

    private async Task<RecoveryExecutionResult> ReconcileUncertainDeliveryAsync(
        ThreadSummary thread,
        TurnSnapshot failedTurn,
        RecoveryOperationRecord operation,
        string transportError,
        CancellationToken cancellationToken)
    {
        _log.Warning(
            "Codex Desktop delivery acknowledgement was lost; checking bounded summary state without redispatching: " +
            transportError,
            thread.Id);
        var reconciliation = await ReconcilePersistedOperationAsync(
                thread,
                failedTurn,
                operation,
                cancellationToken)
            .ConfigureAwait(false);
        if (reconciliation.Result is not null)
        {
            return reconciliation.Result;
        }

        return RecoveryExecutionResult.Failed(
            "Desktop delivery could not yet be confirmed. Guardian will wait for a task or connection event and will not redispatch an uncertain request.",
            isUserBlocked: true,
            RecoveryFailureKind.DesktopUnavailable);
    }

    private async Task<RecoveryIncidentPolicy> ResolveIncidentPolicyAsync(
        string threadId,
        TurnSnapshot failedTurn,
        RecoveryDecision decision,
        RecoveryCurrentTurnReconciliation lineage,
        long policyVersion,
        CancellationToken cancellationToken)
    {
        var snapshot = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        RecoveryCountingMode mode;
        int maximumAttempts;
        bool unlimited;
        lock (_policySync)
        {
            mode = _defaultCountingMode;
            maximumAttempts = _defaultMaximumAttempts;
            unlimited = _defaultUnlimitedAttempts;
        }

        return ResolveIncidentPolicySnapshot(
            snapshot.Records,
            threadId,
            failedTurn,
            decision,
            lineage,
            policyVersion,
            mode,
            maximumAttempts,
            unlimited);
    }

    internal static RecoveryIncidentPolicy ResolveIncidentPolicySnapshot(
        IReadOnlyCollection<RecoveryOperationRecord> records,
        string threadId,
        TurnSnapshot failedTurn,
        RecoveryDecision decision,
        RecoveryCurrentTurnReconciliation lineage,
        long policyVersion,
        RecoveryCountingMode defaultCountingMode,
        int defaultMaximumAttempts,
        bool defaultUnlimitedAttempts)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(failedTurn);
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(lineage);

        var threadRecords = records
            .Where(record => string.Equals(
                record.ThreadId,
                threadId,
                StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(record => record.UpdatedAt)
            .ToArray();
        var existing = threadRecords.FirstOrDefault(record =>
            string.Equals(record.FailedTurnId, failedTurn.Id, StringComparison.OrdinalIgnoreCase));
        var provenUnsentOriginalReplay = RecoveryClassifier.IsProvenUnsentOriginalReplay(
            failedTurn,
            decision);
        if (existing is not null)
        {
            var existingPolicy = PolicyFromRecord(existing);
            if (existing.State == RecoveryOperationState.Retryable)
            {
                EnsureBudgetAvailable(
                    threadRecords,
                    existingPolicy,
                    failedTurn.Id);
            }

            return existingPolicy;
        }

        var signature = BuildFailureSignature(failedTurn, decision);
        var mode = Enum.IsDefined(defaultCountingMode)
            ? defaultCountingMode
            : RecoveryCountingMode.PerFailedTurn;
        // An explicit provider 429 with no local work proves this request was rejected before
        // execution. Count its append-only replays as one incident rather than one budget per
        // successor turn.
        if (provenUnsentOriginalReplay)
        {
            mode = RecoveryCountingMode.SharedIncidentBudget;
        }
        var maximumAttempts = Math.Clamp(
            defaultMaximumAttempts,
            1,
            RecoveryAttemptPolicyLimits.MaximumFiniteAttempts);
        var unlimited = defaultUnlimitedAttempts;
        var incidentId = Guid.NewGuid().ToString("D");
        var rootFailedTurnId = failedTurn.Id;
        string? parentOperationId = null;
        var noProgressCount = 0;

        if (lineage.RecoverySuccessor is not null)
        {
            if (!lineage.IsExactSuccessorMatch)
            {
                throw new RecoveryPolicyBlockedException(RecoverySuccessorUncertainMessage);
            }

            var parent = lineage.RecoverySuccessor;
            if (parent.CountingMode == RecoveryCountingMode.OriginalFailedTurnOnly)
            {
                throw new RecoveryPolicyBlockedException(RecoveryChainBlockedMessage);
            }

            incidentId = parent.IncidentId ??
                throw new RecoveryPolicyBlockedException(RecoverySuccessorUncertainMessage);
            rootFailedTurnId = parent.RootFailedTurnId ??
                throw new RecoveryPolicyBlockedException(RecoverySuccessorUncertainMessage);
            parentOperationId = parent.OperationId;
            mode = parent.CountingMode;
            maximumAttempts = parent.MaximumAttempts;
            unlimited = parent.UnlimitedAttempts;
            noProgressCount = !provenUnsentOriginalReplay &&
                !failedTurn.HasKnownWorkEvidence &&
                parent.Action == decision.Action &&
                string.Equals(
                    parent.FailureSignature,
                    signature,
                    StringComparison.OrdinalIgnoreCase)
                ? checked(parent.NoProgressCount + 1)
                : 0;
        }

        if (provenUnsentOriginalReplay)
        {
            noProgressCount = 0;
        }

        if (noProgressCount >= 3)
        {
            throw new RecoveryPolicyBlockedException(
                "Three Guardian-created recovery successors made no observable progress; manual review is required.");
        }

        var policy = new RecoveryIncidentPolicy(
            incidentId,
            rootFailedTurnId,
            parentOperationId,
            mode,
            maximumAttempts,
            unlimited,
            lineage.RecoverySuccessor is null ? policyVersion :
                lineage.RecoverySuccessor.PolicyVersion,
            signature,
            noProgressCount);
        EnsureBudgetAvailable(threadRecords, policy, failedTurn.Id);
        return policy;
    }

    private static RecoveryIncidentPolicy PolicyFromRecord(RecoveryOperationRecord record) =>
        new(
            record.IncidentId ?? throw new RecoveryPolicyBlockedException(RecoverySuccessorUncertainMessage),
            record.RootFailedTurnId ?? throw new RecoveryPolicyBlockedException(RecoverySuccessorUncertainMessage),
            record.ParentOperationId,
            record.CountingMode,
            record.MaximumAttempts,
            record.UnlimitedAttempts,
            record.PolicyVersion,
            record.FailureSignature ?? throw new RecoveryPolicyBlockedException(RecoverySuccessorUncertainMessage),
            record.NoProgressCount);

    private static void EnsureBudgetAvailable(
        IReadOnlyCollection<RecoveryOperationRecord> threadRecords,
        RecoveryIncidentPolicy policy,
        string failedTurnId)
    {
        if (policy.UnlimitedAttempts)
        {
            return;
        }

        var consumed = policy.CountingMode switch
        {
            RecoveryCountingMode.SharedIncidentBudget => threadRecords
                .Where(record => string.Equals(
                    record.IncidentId,
                    policy.IncidentId,
                    StringComparison.OrdinalIgnoreCase))
                .Sum(record => record.AttemptCount),
            RecoveryCountingMode.PerFailedTurn => threadRecords
                .Where(record => string.Equals(
                    record.FailedTurnId,
                    failedTurnId,
                    StringComparison.OrdinalIgnoreCase))
                .Sum(record => record.AttemptCount),
            RecoveryCountingMode.OriginalFailedTurnOnly => threadRecords
                .Where(record => string.Equals(
                    record.FailedTurnId,
                    policy.RootFailedTurnId,
                    StringComparison.OrdinalIgnoreCase))
                .Sum(record => record.AttemptCount),
            _ => policy.MaximumAttempts
        };
        if (consumed >= policy.MaximumAttempts)
        {
            throw new RecoveryPolicyBlockedException(
                "The automatic recovery budget is exhausted; manual review is required.");
        }
    }

    internal static string BuildFailureSignature(
        TurnSnapshot failedTurn,
        RecoveryDecision decision)
    {
        var canonical = string.Join(
            "|",
            decision.Action,
            failedTurn.Status,
            failedTurn.ErrorCode ?? string.Empty,
            failedTurn.HttpStatusCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            failedTurn.HasKnownWorkEvidence ? "work" : "no-work",
            failedTurn.HasAttachments ? "attachments" : "text");
        return RecoveryOperationJournal.ComputeInputHash(canonical);
    }

    private sealed class RecoveryPolicyBlockedException(string message) : Exception(message);

    private async Task<RecoveryOperationRecord?> TransitionBeforeSendingAsync(
        RecoveryOperationRecord operation,
        RecoveryOperationState nextState,
        CancellationToken cancellationToken,
        string? newTurnId = null)
    {
        try
        {
            var transition = await _journal.TryTransitionAsync(
                    operation.ThreadId,
                    operation.FailedTurnId,
                    operation.State,
                    nextState,
                    operation.ClientMessageId,
                    newTurnId,
                    cancellationToken)
                .ConfigureAwait(false);
            return transition.Changed ? transition.Record : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidOperationException or
                NotSupportedException or ArgumentException)
        {
            _log.Error("Recovery journal transition failed before sending: " + exception.Message);
            return null;
        }
    }

    private async Task<RecoveryOperationRecord> TransitionAfterDispatchAsync(
        RecoveryOperationRecord operation,
        RecoveryOperationState nextState,
        string threadId,
        CancellationToken cancellationToken,
        string? newTurnId = null)
    {
        _ = cancellationToken;
        using var durableWrite = new CancellationTokenSource(DurableResultWriteTimeout);
        try
        {
            var transition = await _journal.TryTransitionAsync(
                    operation.ThreadId,
                    operation.FailedTurnId,
                    operation.State,
                    nextState,
                    operation.ClientMessageId,
                    newTurnId,
                    durableWrite.Token)
                .ConfigureAwait(false);
            return transition.Record ?? operation;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidOperationException or
                OperationCanceledException or
                NotSupportedException or ArgumentException)
        {
            _log.Error(
                "Recovery journal transition failed after dispatch; the operation remains conservatively pending: " +
                exception.Message,
                threadId);
            return operation;
        }
    }

    private async Task AbandonIfStateChangedAsync(
        RecoveryOperationRecord operation,
        RecoveryExecutionResult stateCheck,
        string threadId,
        CancellationToken cancellationToken)
    {
        if (stateCheck.FailureKind != RecoveryFailureKind.StateChanged)
        {
            return;
        }

        await TransitionAfterDispatchAsync(
                operation,
                RecoveryOperationState.Abandoned,
                threadId,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private SemaphoreSlim GetOperationLease(string threadId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(threadId);
        return _operationLeases[
            (int)((uint)StringComparer.OrdinalIgnoreCase.GetHashCode(threadId) % _operationLeases.Length)];
    }

    internal static string BuildRecoveryPayloadHash(RecoveryActionKind action, string message) =>
        BuildRecoveryPayloadHash(action, message, structuredInputDigest: null);

    internal static bool RequiresStructuredInputReplay(
        TurnSnapshot failedTurn,
        RecoveryActionKind action)
    {
        ArgumentNullException.ThrowIfNull(failedTurn);
        return failedTurn.HasAttachments &&
               action is RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue;
    }

    internal static string BuildRecoveryPayloadHash(
        RecoveryActionKind action,
        string message,
        string? structuredInputDigest) =>
        RecoveryOperationJournal.ComputeInputHash(
            structuredInputDigest is null
                ? $"{action}\n{message}"
                : $"{action}\nstructured\n{structuredInputDigest}");

    private static RecoveryExecutionResult PersistenceFailure(string message) =>
        RecoveryExecutionResult.Failed(
            message,
            isUserBlocked: true,
            RecoveryFailureKind.TransportFailed);

    private async Task<RecoveryExecutionResult?> ValidateUserIdleForDispatchAsync(
        string threadId,
        string turnId,
        string stage,
        CancellationToken cancellationToken,
        Action<RecoveryInterferenceSnapshot?>? captureObservation = null)
    {
        RecoveryInterferenceSnapshot? observation = null;
        if (_interferenceGuard is not null)
        {
            try
            {
                observation = await _interferenceGuard.CheckAsync(threadId, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _log.Trace(_requireExplicitInterferenceClear
                    ? "Codex editor observation failed at the dispatch gate (" +
                      exception.GetType().Name + "); dispatch was blocked."
                    : "Codex editor observation failed at the dispatch gate (" +
                      exception.GetType().Name + "); Windows idle fallback was used.");
            }
        }

        captureObservation?.Invoke(observation);
        var activity = ResolveDispatchActivity(
            observation,
            _ownerActivator.CheckUserActivity,
            requireExplicitClear: _requireExplicitInterferenceClear);
        _log.WriteDispatchGate(
            threadId,
            turnId,
            stage,
            activity.Status.ToString(),
            activity.IsIdle);
        return activity.IsIdle
            ? null
            : RecoveryExecutionResult.Failed(
                activity.Detail,
                isUserBlocked: true,
                RecoveryFailureKind.UserActive);
    }

    private async Task WatchDispatchInterferenceAsync(
        RecoveryInterferenceSnapshot? observation,
        CancellationTokenSource commit,
        CancellationToken cancellationToken)
    {
        if (_interferenceGuard is null || observation is null)
        {
            return;
        }

        try
        {
            await _interferenceGuard.WaitForChangeAsync(observation.Version, cancellationToken)
                .ConfigureAwait(false);
            if (!cancellationToken.IsCancellationRequested)
            {
                commit.Cancel();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _log.Trace("Recovery editor change tracking failed closed: " + exception.Message);
            commit.Cancel();
        }
    }

    internal static DesktopUserActivityResult ResolveDispatchActivity(
        RecoveryInterferenceSnapshot? observation,
        Func<DesktopUserActivityResult> fallback,
        DateTimeOffset? now = null,
        bool requireExplicitClear = false)
    {
        ArgumentNullException.ThrowIfNull(fallback);
        var observedAt = now ?? DateTimeOffset.UtcNow;
        var isFresh = observation is not null &&
                      observation.ObservedAt != DateTimeOffset.MinValue &&
                      observation.ObservedAt <= observedAt + TimeSpan.FromSeconds(1) &&
                      observedAt - observation.ObservedAt <= DispatchObservationMaxAge;
        return observation?.Status switch
        {
            RecoveryInterferenceStatus.Clear when isFresh => new DesktopUserActivityResult(
                DesktopUserActivityStatus.Idle,
                observation.Detail),
            RecoveryInterferenceStatus.Editing => new DesktopUserActivityResult(
                DesktopUserActivityStatus.Active,
                observation.Detail),
            _ when requireExplicitClear => new DesktopUserActivityResult(
                DesktopUserActivityStatus.Unknown,
                observation?.Detail ??
                "A fresh clear Codex composer observation is required; nothing was sent."),
            _ => fallback()
        };
    }

    private async Task<(DesktopStructuredInputCapabilityLease? Lease, RecoveryExecutionResult? Result)>
        AcquireTransportSemanticLeaseAsync(
            StructuredPresetPayload payload,
            CancellationToken cancellationToken)
    {
        try
        {
            var current = await _transportSemanticCapabilities!
                .ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            return (current.AcquireLease(payload), null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (DesktopStructuredInputCapabilityException exception)
        {
            _log.Trace("Recovery transport semantic proof was blocked: " + exception.Code);
            return (null, RecoveryExecutionResult.Failed(
                "The installed Codex Desktop recovery semantics are not compatible; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopIncompatible));
        }
        catch (Exception exception)
        {
            _log.Trace(
                "Recovery transport semantic proof was unavailable (" +
                exception.GetType().Name + ").");
            return (null, RecoveryExecutionResult.Failed(
                "The installed Codex Desktop recovery semantics could not be proven; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopIncompatible));
        }
    }

    private async Task<RecoveryExecutionResult?> ValidateTransportSemanticLeaseAsync(
        DesktopStructuredInputCapabilityLease? lease,
        StructuredPresetPayload payload,
        CancellationToken cancellationToken)
    {
        if (lease is null)
        {
            return null;
        }

        try
        {
            var current = await _transportSemanticCapabilities!
                .ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            return current.Matches(lease, payload)
                ? null
                : RecoveryExecutionResult.Failed(
                    "The installed Codex Desktop recovery semantics changed before dispatch; nothing was sent.",
                    isUserBlocked: true,
                    RecoveryFailureKind.StateChanged);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace(
                "Recovery transport semantic lease validation failed (" +
                exception.GetType().Name + ").");
            return RecoveryExecutionResult.Failed(
                "The installed Codex Desktop recovery semantics could not be revalidated; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.DesktopIncompatible);
        }
    }

    internal static RecoveryExecutionResult? ValidateLatestTurn(
        TurnSnapshot? latest,
        string expectedFailedTurnId)
    {
        if (latest is null)
        {
            return RecoveryExecutionResult.Failed(
                "The read-only state service could not confirm the latest turn; nothing was sent.",
                failureKind: RecoveryFailureKind.TransportFailed);
        }

        if (!string.Equals(latest.Id, expectedFailedTurnId, StringComparison.OrdinalIgnoreCase))
        {
            return RecoveryExecutionResult.Failed(
                "The task already has a newer turn; the stale recovery action was cancelled.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged);
        }

        if (string.Equals(latest.Status, "inProgress", StringComparison.OrdinalIgnoreCase))
        {
            return RecoveryExecutionResult.Failed(
                "The task is already running; no recovery message was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged);
        }

        return !string.Equals(latest.Status, "failed", StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(latest.Status, "interrupted", StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(
                   latest.Status,
                   RecoveryClassifier.IncompleteTerminalStatus,
                   StringComparison.OrdinalIgnoreCase)
            ? RecoveryExecutionResult.Failed(
                "The latest turn is no longer an abnormal terminal state; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged)
            : null;
    }

    // The stock Desktop reports exactly three thread runtime states — `active`, `idle` and
    // `systemError` (see CodexDeepObservationService, which already maps them to Running/Idle/Failed).
    // Only `active` means something is running. `systemError` is the terminal state a turn lands in
    // after a provider failure such as a 429, which is precisely the state a recovery exists to leave:
    // requiring `idle` kept this gate permanently shut on the only failures worth resending. The live
    // AR27 slice proved it — 13 of 13 dispatch attempts refused with `systemError` and not one reached
    // the dispatch intent, while the journal shows 28 resends that all had to wait for an `idle` owner.
    // Safety does not rest on this check: the two that follow require the owner's latest turn to still
    // be the failed turn we are recovering and to still be in an abnormal terminal state, so an owner
    // that has moved on is refused there. Unknown states stay refused so a protocol change fails closed.
    internal static bool IsOwnerRuntimeStatusDispatchable(string? runtimeStatus) =>
        string.Equals(runtimeStatus, "idle", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(runtimeStatus, "systemError", StringComparison.OrdinalIgnoreCase);

    internal static RecoveryExecutionResult? ValidateOwnerStateSnapshot(
        DesktopThreadOwnerStateSnapshot snapshot,
        string expectedFailedTurnId) =>
        ValidateOwnerStateSnapshot(
            snapshot,
            expectedFailedTurnId,
            allowConfirmedProviderFailureReportedCompleted: false);

    internal static RecoveryExecutionResult? ValidateOwnerStateSnapshot(
        DesktopThreadOwnerStateSnapshot snapshot,
        TurnSnapshot expectedFailedTurn)
    {
        ArgumentNullException.ThrowIfNull(expectedFailedTurn);
        var hasConfirmedProviderFailure =
            expectedFailedTurn.HasConfirmedLocalTerminal &&
            (string.Equals(expectedFailedTurn.Status, "failed", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(expectedFailedTurn.Status, "interrupted", StringComparison.OrdinalIgnoreCase)) &&
            (!string.IsNullOrWhiteSpace(expectedFailedTurn.ErrorMessage) ||
             !string.IsNullOrWhiteSpace(expectedFailedTurn.ErrorCode) ||
             expectedFailedTurn.HttpStatusCode is not null);
        var hasConfirmedIncompleteTerminal =
            expectedFailedTurn.HasConfirmedLocalTerminal &&
            string.Equals(
                expectedFailedTurn.Status,
                RecoveryClassifier.IncompleteTerminalStatus,
                StringComparison.OrdinalIgnoreCase) &&
            expectedFailedTurn.HasUserMessage &&
            expectedFailedTurn.HasCompleteItemEvidence &&
            !expectedFailedTurn.HasReliableFinalOutput;
        return ValidateOwnerStateSnapshot(
            snapshot,
            expectedFailedTurn.Id,
            allowConfirmedProviderFailureReportedCompleted:
                hasConfirmedProviderFailure || hasConfirmedIncompleteTerminal);
    }

    private static RecoveryExecutionResult? ValidateOwnerStateSnapshot(
        DesktopThreadOwnerStateSnapshot snapshot,
        string expectedFailedTurnId,
        bool allowConfirmedProviderFailureReportedCompleted)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!IsOwnerRuntimeStatusDispatchable(snapshot.RuntimeStatus))
        {
            // Name the status the owner actually reported. A bare "not idle" cannot distinguish a task
            // still streaming its previous retry from an owner parked in a non-terminal state, and that
            // distinction is the entire content of the wait the user is staring at. It also lets the
            // engine's repeated-failure suppression lift by itself when the status changes.
            var ownerRuntimeStatus = GuardianLog.SanitizeIdentifier(snapshot.RuntimeStatus);
            return RecoveryExecutionResult.OwnerBusy(
                "The Desktop owner reports a runtime status that cannot accept a recovery dispatch " +
                "(runtime status: " +
                ownerRuntimeStatus +
                "); no recovery message was sent.",
                ownerRuntimeStatus);
        }

        if (!string.Equals(snapshot.LatestTurnId, expectedFailedTurnId, StringComparison.OrdinalIgnoreCase))
        {
            return RecoveryExecutionResult.Failed(
                "The Desktop owner has a different latest turn; the stale recovery action was cancelled.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged);
        }

        var isAbnormalTerminal =
            string.Equals(snapshot.LatestTurnStatus, "failed", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(snapshot.LatestTurnStatus, "interrupted", StringComparison.OrdinalIgnoreCase);
        var isConfirmedProviderFailure =
            allowConfirmedProviderFailureReportedCompleted &&
            string.Equals(snapshot.LatestTurnStatus, "completed", StringComparison.OrdinalIgnoreCase);
        return !isAbnormalTerminal && !isConfirmedProviderFailure
            ? RecoveryExecutionResult.Failed(
                "The Desktop owner no longer reports an abnormal terminal turn; nothing was sent.",
                isUserBlocked: true,
                RecoveryFailureKind.StateChanged)
            : null;
    }

    internal static TurnSnapshot? ReconcileLatestTurnForDispatch(
        TurnSnapshot? latest,
        TurnSnapshot expectedFailedTurn)
    {
        if (latest is null ||
            !expectedFailedTurn.HasConfirmedLocalTerminal ||
            !string.Equals(latest.Id, expectedFailedTurn.Id, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(latest.Status, "completed", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedFailedTurn.Status, "failed", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(expectedFailedTurn.Status, "interrupted", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(
                expectedFailedTurn.Status,
                RecoveryClassifier.IncompleteTerminalStatus,
                StringComparison.OrdinalIgnoreCase))
        {
            return latest;
        }

        var latestTerminalAt = latest.CompletedAt ?? latest.StartedAt;
        var confirmedFailureAt = expectedFailedTurn.CompletedAt ?? expectedFailedTurn.StartedAt;
        if (latestTerminalAt is not null &&
            confirmedFailureAt is not null &&
            latestTerminalAt > confirmedFailureAt)
        {
            return latest;
        }

        return expectedFailedTurn;
    }

    internal static RecoveryExecutionResult? ValidateGuardedAutomaticRecoveryCapability(
        RecoveryTransportCapabilities capabilities,
        RecoveryActionKind action,
        bool provenUnsentOriginalReplay = false)
    {
        if (action == RecoveryActionKind.None ||
            capabilities.Action == action && capabilities.IsGuardedAutomaticRecoveryEligible)
        {
            return null;
        }

        var detail = action is RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue
            ? "The installed Codex Desktop channel could not prove the in-place retry contract that replaces the failed turn. Nothing was sent, and the original input was not appended as a duplicate successor."
            : "Codex Desktop does not expose the guarded action contract required for this recovery action. Best-effort automatic recovery was not attempted.";
        return RecoveryExecutionResult.Failed(
            detail,
            isUserBlocked: true,
            RecoveryFailureKind.DesktopIncompatible);
    }

    internal static RecoveryExecutionResult? ValidateAtomicRecoveryCapability(
        bool supportsAtomicRecoveryPrecondition,
        RecoveryActionKind action)
    {
        if (action == RecoveryActionKind.None || supportsAtomicRecoveryPrecondition)
        {
            return null;
        }

        return RecoveryExecutionResult.Failed(
            "Codex Desktop does not provide a strict atomic failed-turn compare-and-start contract; no recovery message was sent.",
            isUserBlocked: true,
            RecoveryFailureKind.AtomicGuardUnavailable);
    }

}
