using CodexGuardian.Models;
using System.Text.Json;

namespace CodexGuardian.Services;

internal sealed record ConversationMutationTransportCapabilities(
    bool SupportsUnarchive,
    bool SupportsDelete,
    bool SupportsExpectedStateValidation,
    bool SupportsAtMostOnceOperationId,
    bool ReturnsOwnerReceipt,
    bool ExecutesThroughDesktopOwner,
    bool IsTrustedDesktopProtocol,
    string Detail)
{
    internal bool IsEligible(ConversationMutationKind kind) =>
        (kind == ConversationMutationKind.Unarchive ? SupportsUnarchive : SupportsDelete) &&
        SupportsExpectedStateValidation &&
        SupportsAtMostOnceOperationId &&
        ReturnsOwnerReceipt &&
        ExecutesThroughDesktopOwner &&
        IsTrustedDesktopProtocol;

    internal static ConversationMutationTransportCapabilities CurrentCodexIpcUnavailable { get; } = new(
        SupportsUnarchive: false,
        SupportsDelete: false,
        SupportsExpectedStateValidation: false,
        SupportsAtMostOnceOperationId: false,
        ReturnsOwnerReceipt: false,
        ExecutesThroughDesktopOwner: false,
        IsTrustedDesktopProtocol: false,
        Detail:
            "The current stock Codex Desktop owner protocol does not expose guarded unarchive or delete requests.");
}

internal sealed record ConversationMutationAuthoritySnapshot(
    bool Exists,
    ThreadSummary? Thread,
    TurnSnapshot? LatestTurn)
{
    internal static ConversationMutationAuthoritySnapshot Absent { get; } = new(false, null, null);
}

internal interface IConversationMutationStateReader
{
    Task<ConversationMutationAuthoritySnapshot> ReadAuthorityAsync(
        string threadId,
        CancellationToken cancellationToken);
}

internal interface IConversationMutationOwnerGuard : IAsyncDisposable
{
    DesktopThreadOwnerStateSnapshot Snapshot { get; }

    bool IsCurrent { get; }
}

internal sealed record ConversationMutationOwnerGuardAcquireResult(
    DesktopThreadOwnerStateGuardStatus Status,
    IConversationMutationOwnerGuard? Guard,
    string Detail)
{
    internal bool IsAvailable =>
        Status == DesktopThreadOwnerStateGuardStatus.Available && Guard is not null;
}

internal sealed record ConversationMutationCommitRequest(
    string OperationId,
    string ThreadId,
    ConversationMutationKind Kind,
    long ExpectedUpdatedAt,
    string ExpectedLatestTurnId,
    string OwnerHostId,
    string OwnerClientId,
    long OwnerRevision,
    bool DeleteConfirmed);

internal sealed record ConversationMutationCommitResult(
    bool Acknowledged,
    string OperationId,
    string OwnerHostId,
    string OwnerClientId,
    string ReceiptId);

internal interface IConversationMutationDesktopChannel
{
    ConversationMutationTransportCapabilities Capabilities { get; }

    Task<ConversationMutationOwnerGuardAcquireResult> AcquireOwnerGuardAsync(
        string threadId,
        CancellationToken cancellationToken);

    Task<ConversationMutationCommitResult> CommitAsync(
        ConversationMutationCommitRequest request,
        Func<bool> canCommit,
        CancellationToken cancellationToken);
}

internal interface IConversationMutationOwnerActivator
{
    Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
        string threadId,
        CancellationToken cancellationToken);

    DesktopUserActivityResult CheckUserActivity();
}

internal sealed class AppServerConversationMutationStateReader(AppServerClient inner)
    : IConversationMutationStateReader
{
    public async Task<ConversationMutationAuthoritySnapshot> ReadAuthorityAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(threadId, out var parsedThreadId))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(threadId));
        }

        var canonicalThreadId = parsedThreadId.ToString("D");
        var activeTask = inner.ListThreadsAsync(
            200,
            includeSubAgents: true,
            archived: false,
            cancellationToken);
        var archivedTask = inner.ListThreadsAsync(
            200,
            includeSubAgents: true,
            archived: true,
            cancellationToken);
        await Task.WhenAll(activeTask, archivedTask).ConfigureAwait(false);
        var matches = activeTask.Result
            .Concat(archivedTask.Result)
            .Where(thread => string.Equals(
                thread.Id,
                canonicalThreadId,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matches.Length == 0)
        {
            return ConversationMutationAuthoritySnapshot.Absent;
        }

        if (matches.Length != 1)
        {
            throw new InvalidDataException(
                "The read-only active and archived scopes did not identify one unique conversation.");
        }

        var latest = await inner.ReadLatestTurnAsync(canonicalThreadId, cancellationToken)
            .ConfigureAwait(false);
        return new ConversationMutationAuthoritySnapshot(true, matches[0], latest);
    }
}

internal sealed class DesktopConversationMutationChannel(DesktopIpcClient inner)
    : IConversationMutationDesktopChannel
{
    public ConversationMutationTransportCapabilities Capabilities =>
        ConversationMutationTransportCapabilities.CurrentCodexIpcUnavailable;

    public async Task<ConversationMutationOwnerGuardAcquireResult> AcquireOwnerGuardAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        var result = await inner.AcquireThreadOwnerStateGuardAsync(threadId, cancellationToken)
            .ConfigureAwait(false);
        return new ConversationMutationOwnerGuardAcquireResult(
            result.Status,
            result.Guard is null ? null : new DesktopConversationMutationOwnerGuard(result.Guard),
            result.Detail);
    }

    public Task<ConversationMutationCommitResult> CommitAsync(
        ConversationMutationCommitRequest request,
        Func<bool> canCommit,
        CancellationToken cancellationToken)
    {
        _ = request;
        _ = canCommit;
        _ = cancellationToken;
        throw new NotSupportedException(Capabilities.Detail);
    }

    private sealed class DesktopConversationMutationOwnerGuard(DesktopThreadOwnerStateGuard innerGuard)
        : IConversationMutationOwnerGuard
    {
        public DesktopThreadOwnerStateSnapshot Snapshot => innerGuard.Snapshot;

        public bool IsCurrent => innerGuard.IsCurrent;

        public ValueTask DisposeAsync() => innerGuard.DisposeAsync();
    }
}

internal sealed class ConversationMutationOwnerActivator(DesktopThreadOwnerActivator inner)
    : IConversationMutationOwnerActivator
{
    public Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
        string threadId,
        CancellationToken cancellationToken) =>
        inner.EnsureOwnerAsync(threadId, cancellationToken);

    public DesktopUserActivityResult CheckUserActivity() => inner.CheckUserActivity();
}

internal enum ConversationMutationFailureKind
{
    None,
    CapabilityUnavailable,
    InvalidTarget,
    ConfirmationRequired,
    DirtyDraft,
    StateChanged,
    OwnerUnavailable,
    UserActive,
    PersistenceFailed,
    Rejected,
    Uncertain
}

internal sealed record ConversationMutationResult(
    bool Success,
    bool Applied,
    string Message,
    ConversationMutationFailureKind FailureKind = ConversationMutationFailureKind.None,
    ThreadSummary? AuthoritativeThread = null)
{
    internal static ConversationMutationResult Completed(
        string message,
        ThreadSummary? authoritativeThread = null) =>
        new(true, true, message, AuthoritativeThread: authoritativeThread);

    internal static ConversationMutationResult Failed(
        string message,
        ConversationMutationFailureKind failureKind) =>
        new(false, false, message, failureKind);
}

internal sealed record ConversationMutationRequest(
    ThreadSummary Thread,
    ConversationMutationKind Kind,
    string ExpectedLatestTurnId,
    bool DeleteConfirmed,
    bool HasDirtyDraft,
    Func<bool> IsStillAllowed);

internal sealed class ConversationMutationService
{
    private static readonly TimeSpan DesktopCommitTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan AuthoritativeReadbackTimeout = TimeSpan.FromSeconds(15);

    private readonly IConversationMutationStateReader _stateReader;
    private readonly IConversationMutationDesktopChannel _desktop;
    private readonly IConversationMutationOwnerActivator _ownerActivator;
    private readonly ConversationMutationOperationJournal _journal;
    private readonly GuardianLog _log;
    private readonly IRecoveryInterferenceGuard? _interferenceGuard;
    private readonly SemaphoreSlim[] _operationLeases = Enumerable.Range(0, 64)
        .Select(static _ => new SemaphoreSlim(1, 1))
        .ToArray();

    internal ConversationMutationService(
        AppServerClient stateReader,
        DesktopIpcClient desktop,
        DesktopThreadOwnerActivator ownerActivator,
        ConversationMutationOperationJournal journal,
        GuardianLog log,
        IRecoveryInterferenceGuard? interferenceGuard = null)
        : this(
            new AppServerConversationMutationStateReader(stateReader),
            new DesktopConversationMutationChannel(desktop),
            new ConversationMutationOwnerActivator(ownerActivator),
            journal,
            log,
            interferenceGuard)
    {
    }

    internal ConversationMutationService(
        IConversationMutationStateReader stateReader,
        IConversationMutationDesktopChannel desktop,
        IConversationMutationOwnerActivator ownerActivator,
        ConversationMutationOperationJournal journal,
        GuardianLog log,
        IRecoveryInterferenceGuard? interferenceGuard = null)
    {
        _stateReader = stateReader ?? throw new ArgumentNullException(nameof(stateReader));
        _desktop = desktop ?? throw new ArgumentNullException(nameof(desktop));
        _ownerActivator = ownerActivator ?? throw new ArgumentNullException(nameof(ownerActivator));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _interferenceGuard = interferenceGuard;
    }

    internal ConversationMutationTransportCapabilities Capabilities => _desktop.Capabilities;

    internal bool CanExecute(ConversationMutationKind kind) => Capabilities.IsEligible(kind);

    internal Task<ConversationMutationJournalSnapshot> ReadJournalAsync(
        CancellationToken cancellationToken = default) =>
        _journal.ReadAsync(cancellationToken);

    internal async Task<ConversationMutationResult> ExecuteAsync(
        ConversationMutationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Thread);
        ArgumentNullException.ThrowIfNull(request.IsStillAllowed);
        if (!Guid.TryParse(request.Thread.Id, out _))
        {
            return ConversationMutationResult.Failed(
                "The selected conversation does not have a valid UUID.",
                ConversationMutationFailureKind.InvalidTarget);
        }

        var lease = _operationLeases[
            (int)((uint)StringComparer.OrdinalIgnoreCase.GetHashCode(request.Thread.Id) %
                  _operationLeases.Length)];
        await lease.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ExecuteCoreAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            lease.Release();
        }
    }

    private async Task<ConversationMutationResult> ExecuteCoreAsync(
        ConversationMutationRequest request,
        CancellationToken cancellationToken)
    {
        var staticValidation = ValidateStaticRequest(request);
        if (staticValidation is not null)
        {
            return staticValidation;
        }

        if (!Capabilities.IsEligible(request.Kind))
        {
            return ConversationMutationResult.Failed(
                Capabilities.Detail,
                ConversationMutationFailureKind.CapabilityUnavailable);
        }

        ConversationMutationOperationRecord? prior;
        try
        {
            prior = await _journal.FindLatestAsync(
                    request.Thread.Id,
                    request.Kind,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (IsPersistenceException(exception))
        {
            _log.Error("Conversation mutation journal could not be read; no owner action was attempted.");
            return ConversationMutationResult.Failed(
                "The durable mutation journal is unavailable; nothing changed.",
                ConversationMutationFailureKind.PersistenceFailed);
        }

        if (prior?.State == ConversationMutationOperationState.Committing)
        {
            prior = await TransitionAfterCommitAsync(
                    prior,
                    ConversationMutationOperationState.Uncertain,
                    prior.ReceiptId,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (prior?.State == ConversationMutationOperationState.Uncertain)
        {
            return await ReconcileUncertainAsync(prior, cancellationToken).ConfigureAwait(false);
        }

        ConversationMutationAuthoritySnapshot authority;
        try
        {
            authority = await _stateReader.ReadAuthorityAsync(request.Thread.Id, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace(
                "Conversation mutation target readback failed before owner activation (" +
                exception.GetType().Name + ").");
            return ConversationMutationResult.Failed(
                "The selected conversation could not be revalidated.",
                ConversationMutationFailureKind.StateChanged);
        }

        var authorityValidation = ValidateAuthority(request, authority);
        if (authorityValidation is not null)
        {
            return authorityValidation;
        }

        var activation = await _ownerActivator.EnsureOwnerAsync(request.Thread.Id, cancellationToken)
            .ConfigureAwait(false);
        _log.WriteDispatchGate(
            request.Thread.Id,
            request.ExpectedLatestTurnId,
            "conversationMutationOwnerActivation",
            activation.Status.ToString(),
            activation.IsAvailable);
        if (!activation.IsAvailable)
        {
            return ConversationMutationResult.Failed(
                activation.Detail,
                activation.Status == DesktopThreadOwnerActivationStatus.DeferredForUserActivity
                    ? ConversationMutationFailureKind.UserActive
                    : ConversationMutationFailureKind.OwnerUnavailable);
        }

        var guardResult = await _desktop.AcquireOwnerGuardAsync(
                request.Thread.Id,
                cancellationToken)
            .ConfigureAwait(false);
        _log.WriteDispatchGate(
            request.Thread.Id,
            request.ExpectedLatestTurnId,
            "conversationMutationOwnerSnapshot",
            guardResult.Status.ToString(),
            guardResult.IsAvailable);
        if (!guardResult.IsAvailable)
        {
            return ConversationMutationResult.Failed(
                guardResult.Detail,
                ConversationMutationFailureKind.OwnerUnavailable);
        }

        await using var ownerGuard = guardResult.Guard!;
        var ownerValidation = ValidateOwnerSnapshot(
            ownerGuard.Snapshot,
            request.Thread.Id,
            request.ExpectedLatestTurnId);
        if (ownerValidation is not null)
        {
            return ownerValidation;
        }

        var activity = await ValidateUserActivityAsync(
                request.Thread.Id,
                request.ExpectedLatestTurnId,
                "conversationMutationBeforeIntent",
                cancellationToken)
            .ConfigureAwait(false);
        if (activity is not null)
        {
            return activity;
        }

        if (!IsAllowed(request.IsStillAllowed) || !ownerGuard.IsCurrent)
        {
            return ConversationMutationResult.Failed(
                "The selected route or Desktop owner changed before the mutation intent was saved.",
                ConversationMutationFailureKind.StateChanged);
        }

        var snapshot = ownerGuard.Snapshot;
        var operationId = ConversationMutationOperationJournal.CreateOperationId(
            request.Thread.Id,
            request.Kind,
            request.Thread.UpdatedAt,
            request.ExpectedLatestTurnId,
            snapshot.HostId,
            snapshot.OwnerClientId,
            snapshot.Revision);
        ConversationMutationOperationRecord operation;
        try
        {
            operation = (await _journal.GetOrCreateAsync(
                    new ConversationMutationOperationRecord(
                        operationId,
                        request.Thread.Id,
                        request.Kind,
                        request.Thread.UpdatedAt,
                        request.ExpectedLatestTurnId,
                        snapshot.HostId,
                        snapshot.OwnerClientId,
                        snapshot.Revision,
                        ConversationMutationOperationState.Prepared,
                        ReceiptId: null,
                        CreatedAt: default,
                        UpdatedAt: default,
                        AttemptCount: 0),
                    cancellationToken)
                .ConfigureAwait(false)).Record;
        }
        catch (Exception exception) when (IsPersistenceException(exception))
        {
            _log.Error("Conversation mutation intent could not be persisted; no owner action was attempted.");
            return ConversationMutationResult.Failed(
                "The durable mutation intent could not be saved; nothing changed.",
                ConversationMutationFailureKind.PersistenceFailed);
        }

        if (operation.State == ConversationMutationOperationState.Confirmed)
        {
            return await ReconcileConfirmedAsync(operation, cancellationToken).ConfigureAwait(false);
        }

        if (operation.State == ConversationMutationOperationState.Uncertain)
        {
            return await ReconcileUncertainAsync(operation, cancellationToken).ConfigureAwait(false);
        }

        authority = await _stateReader.ReadAuthorityAsync(request.Thread.Id, cancellationToken)
            .ConfigureAwait(false);
        authorityValidation = ValidateAuthority(request, authority);
        if (authorityValidation is not null ||
            !IsAllowed(request.IsStillAllowed) ||
            !ownerGuard.IsCurrent)
        {
            await AbandonBeforeCommitAsync(operation, cancellationToken).ConfigureAwait(false);
            return authorityValidation ?? ConversationMutationResult.Failed(
                "The selected conversation changed before the owner commit.",
                ConversationMutationFailureKind.StateChanged);
        }

        var committing = await TransitionBeforeCommitAsync(operation, cancellationToken).ConfigureAwait(false);
        if (committing is null)
        {
            return ConversationMutationResult.Failed(
                "The durable owner-commit boundary could not be saved; nothing changed.",
                ConversationMutationFailureKind.PersistenceFailed);
        }

        operation = committing;
        activity = await ValidateUserActivityAsync(
                request.Thread.Id,
                request.ExpectedLatestTurnId,
                "conversationMutationBeforeOwnerWrite",
                cancellationToken)
            .ConfigureAwait(false);
        if (activity is not null || !IsAllowed(request.IsStillAllowed) || !ownerGuard.IsCurrent)
        {
            await ReturnRetryableAsync(operation, cancellationToken).ConfigureAwait(false);
            return activity ?? ConversationMutationResult.Failed(
                "The selected route or Desktop owner changed before the owner write.",
                ConversationMutationFailureKind.StateChanged);
        }

        var commitRequest = new ConversationMutationCommitRequest(
            operation.OperationId,
            operation.ThreadId,
            operation.Kind,
            operation.ExpectedUpdatedAt,
            operation.ExpectedLatestTurnId,
            operation.OwnerHostId,
            operation.OwnerClientId,
            operation.OwnerRevision,
            request.DeleteConfirmed);
        using var commit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        commit.CancelAfter(DesktopCommitTimeout);
        try
        {
            var receipt = await _desktop.CommitAsync(
                    commitRequest,
                    () => IsAllowed(request.IsStillAllowed) && ownerGuard.IsCurrent,
                    commit.Token)
                .ConfigureAwait(false);
            if (!ValidateReceipt(operation, receipt))
            {
                operation = await TransitionAfterCommitAsync(
                        operation,
                        ConversationMutationOperationState.Uncertain,
                        receipt.ReceiptId,
                        cancellationToken)
                    .ConfigureAwait(false);
                return ConversationMutationResult.Failed(
                    "Desktop returned an incompatible owner receipt; the operation will not be retried.",
                    ConversationMutationFailureKind.Uncertain);
            }

            using var readback = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readback.CancelAfter(AuthoritativeReadbackTimeout);
            var final = await _stateReader.ReadAuthorityAsync(operation.ThreadId, readback.Token)
                .ConfigureAwait(false);
            if (!IsApplied(operation.Kind, final))
            {
                await TransitionAfterCommitAsync(
                        operation,
                        ConversationMutationOperationState.Uncertain,
                        receipt.ReceiptId,
                        cancellationToken)
                    .ConfigureAwait(false);
                return ConversationMutationResult.Failed(
                    "Desktop acknowledged the owner action, but authoritative state did not settle in time.",
                    ConversationMutationFailureKind.Uncertain);
            }

            var confirmed = await TransitionAfterCommitAsync(
                    operation,
                    ConversationMutationOperationState.Confirmed,
                    receipt.ReceiptId,
                    cancellationToken)
                .ConfigureAwait(false);
            return confirmed.State == ConversationMutationOperationState.Confirmed
                ? ConversationMutationResult.Completed(
                    operation.Kind == ConversationMutationKind.Unarchive
                        ? "The conversation was unarchived through the stock Desktop owner."
                        : "The archived conversation was deleted through the stock Desktop owner.",
                    final.Thread)
                : ConversationMutationResult.Failed(
                    "The owner action completed, but durable confirmation failed; it will not be retried.",
                    ConversationMutationFailureKind.Uncertain);
        }
        catch (OperationCanceledException) when (commit.IsCancellationRequested)
        {
            operation = await TransitionAfterCommitAsync(
                    operation,
                    ConversationMutationOperationState.Uncertain,
                    operation.ReceiptId,
                    cancellationToken)
                .ConfigureAwait(false);
            return await ReconcileUncertainAsync(operation, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsDefinitelyNotDispatched(exception))
        {
            await ReturnRetryableAsync(operation, cancellationToken).ConfigureAwait(false);
            return ConversationMutationResult.Failed(
                "Desktop rejected the owner action before dispatch; nothing changed.",
                ConversationMutationFailureKind.Rejected);
        }
        catch (Exception exception) when (
            exception is DesktopIpcProtocolException or DesktopIpcDeliveryException or
                IOException or TimeoutException)
        {
            operation = await TransitionAfterCommitAsync(
                    operation,
                    ConversationMutationOperationState.Uncertain,
                    operation.ReceiptId,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Warning("Conversation mutation delivery is uncertain and will not be retried automatically.");
            return await ReconcileUncertainAsync(operation, cancellationToken).ConfigureAwait(false);
        }
    }

    private static ConversationMutationResult? ValidateStaticRequest(ConversationMutationRequest request)
    {
        if (!request.Thread.IsArchived || request.Thread.IsSubAgent || request.Thread.IsEphemeral ||
            !Guid.TryParse(request.ExpectedLatestTurnId, out _))
        {
            return ConversationMutationResult.Failed(
                "Only one archived root conversation with a verified latest turn can be changed.",
                ConversationMutationFailureKind.InvalidTarget);
        }

        if (request.Kind == ConversationMutationKind.Delete && !request.DeleteConfirmed)
        {
            return ConversationMutationResult.Failed(
                "Permanent deletion requires explicit confirmation.",
                ConversationMutationFailureKind.ConfirmationRequired);
        }

        return request.HasDirtyDraft
            ? ConversationMutationResult.Failed(
                "Save or discard the open preset-message draft before changing this conversation.",
                ConversationMutationFailureKind.DirtyDraft)
            : null;
    }

    private static ConversationMutationResult? ValidateAuthority(
        ConversationMutationRequest request,
        ConversationMutationAuthoritySnapshot authority)
    {
        if (!authority.Exists || authority.Thread is not { } thread || authority.LatestTurn is not { } latest ||
            !string.Equals(thread.Id, request.Thread.Id, StringComparison.OrdinalIgnoreCase) ||
            !thread.IsArchived || thread.IsSubAgent || thread.IsEphemeral ||
            thread.UpdatedAt != request.Thread.UpdatedAt ||
            !string.Equals(latest.Id, request.ExpectedLatestTurnId, StringComparison.OrdinalIgnoreCase))
        {
            return ConversationMutationResult.Failed(
                "The archived conversation changed since it was selected.",
                ConversationMutationFailureKind.StateChanged);
        }

        return null;
    }

    internal static ConversationMutationResult? ValidateOwnerSnapshot(
        DesktopThreadOwnerStateSnapshot snapshot,
        string expectedThreadId,
        string expectedLatestTurnId)
    {
        if (!string.Equals(snapshot.ConversationId, expectedThreadId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.HostId, "local", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(snapshot.OwnerClientId) || snapshot.Revision < 0 ||
            !string.Equals(snapshot.RuntimeStatus, "idle", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.LatestTurnId, expectedLatestTurnId, StringComparison.OrdinalIgnoreCase) ||
            snapshot.LatestTurnStatus is not ("completed" or "failed" or "interrupted"))
        {
            return ConversationMutationResult.Failed(
                "The stock Desktop owner does not match the selected idle conversation boundary.",
                ConversationMutationFailureKind.OwnerUnavailable);
        }

        return null;
    }

    private async Task<ConversationMutationResult?> ValidateUserActivityAsync(
        string threadId,
        string latestTurnId,
        string stage,
        CancellationToken cancellationToken)
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
                _log.Trace(
                    "Conversation mutation editor observation failed (" +
                    exception.GetType().Name + "); Windows idle fallback was used.");
            }
        }

        var activity = RecoveryService.ResolveDispatchActivity(
            observation,
            _ownerActivator.CheckUserActivity);
        _log.WriteDispatchGate(threadId, latestTurnId, stage, activity.Status.ToString(), activity.IsIdle);
        return activity.IsIdle
            ? null
            : ConversationMutationResult.Failed(
                activity.Detail,
                ConversationMutationFailureKind.UserActive);
    }

    private async Task<ConversationMutationResult> ReconcileConfirmedAsync(
        ConversationMutationOperationRecord operation,
        CancellationToken cancellationToken)
    {
        var authority = await _stateReader.ReadAuthorityAsync(operation.ThreadId, cancellationToken)
            .ConfigureAwait(false);
        return IsApplied(operation.Kind, authority)
            ? ConversationMutationResult.Completed(
                "The durable journal and authoritative conversation state already agree.",
                authority.Thread)
            : ConversationMutationResult.Failed(
                "The previous mutation is confirmed, but the conversation has since changed again.",
                ConversationMutationFailureKind.StateChanged);
    }

    private async Task<ConversationMutationResult> ReconcileUncertainAsync(
        ConversationMutationOperationRecord operation,
        CancellationToken cancellationToken)
    {
        try
        {
            var authority = await _stateReader.ReadAuthorityAsync(operation.ThreadId, cancellationToken)
                .ConfigureAwait(false);
            if (IsApplied(operation.Kind, authority))
            {
                var confirmed = await _journal.TryTransitionAsync(
                        operation.OperationId,
                        ConversationMutationOperationState.Uncertain,
                        ConversationMutationOperationState.Confirmed,
                        operation.ReceiptId,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (confirmed.Record?.State == ConversationMutationOperationState.Confirmed)
                {
                    return ConversationMutationResult.Completed(
                        "Authoritative state confirmed the prior owner action.",
                        authority.Thread);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Trace(
                "An uncertain conversation mutation could not be reconciled (" +
                exception.GetType().Name + ").");
        }

        return ConversationMutationResult.Failed(
            "A prior owner action may have committed. Ceasy will not retry it without proof.",
            ConversationMutationFailureKind.Uncertain);
    }

    private async Task<ConversationMutationOperationRecord?> TransitionBeforeCommitAsync(
        ConversationMutationOperationRecord operation,
        CancellationToken cancellationToken)
    {
        try
        {
            var transition = await _journal.TryTransitionAsync(
                    operation.OperationId,
                    operation.State,
                    ConversationMutationOperationState.Committing,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return transition.Changed ? transition.Record : null;
        }
        catch (Exception exception) when (IsPersistenceException(exception))
        {
            _log.Error("Conversation mutation commit boundary could not be persisted.");
            return null;
        }
    }

    private async Task<ConversationMutationOperationRecord> TransitionAfterCommitAsync(
        ConversationMutationOperationRecord operation,
        ConversationMutationOperationState nextState,
        string? receiptId,
        CancellationToken cancellationToken)
    {
        try
        {
            var transition = await _journal.TryTransitionAsync(
                    operation.OperationId,
                    operation.State,
                    nextState,
                    receiptId,
                    cancellationToken)
                .ConfigureAwait(false);
            return transition.Record ?? operation;
        }
        catch (Exception exception) when (IsPersistenceException(exception))
        {
            _log.Error("Conversation mutation terminal state could not be persisted.");
            return operation with { State = ConversationMutationOperationState.Uncertain };
        }
    }

    private async Task ReturnRetryableAsync(
        ConversationMutationOperationRecord operation,
        CancellationToken cancellationToken)
    {
        _ = await TransitionAfterCommitAsync(
                operation,
                ConversationMutationOperationState.Retryable,
                operation.ReceiptId,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task AbandonBeforeCommitAsync(
        ConversationMutationOperationRecord operation,
        CancellationToken cancellationToken)
    {
        try
        {
            _ = await _journal.TryTransitionAsync(
                    operation.OperationId,
                    operation.State,
                    ConversationMutationOperationState.Abandoned,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (IsPersistenceException(exception))
        {
            _log.Error("A stale conversation mutation could not be closed durably.");
        }
    }

    private static bool ValidateReceipt(
        ConversationMutationOperationRecord operation,
        ConversationMutationCommitResult receipt) =>
        receipt.Acknowledged &&
        string.Equals(receipt.OperationId, operation.OperationId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(receipt.OwnerHostId, operation.OwnerHostId, StringComparison.Ordinal) &&
        string.Equals(receipt.OwnerClientId, operation.OwnerClientId, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(receipt.ReceiptId) &&
        receipt.ReceiptId.Length <= 256;

    private static bool IsApplied(
        ConversationMutationKind kind,
        ConversationMutationAuthoritySnapshot authority) =>
        kind switch
        {
            ConversationMutationKind.Unarchive =>
                authority.Exists && authority.Thread is { IsArchived: false },
            ConversationMutationKind.Delete => !authority.Exists,
            _ => false
        };

    private static bool IsAllowed(Func<bool> isStillAllowed)
    {
        try
        {
            return isStillAllowed();
        }
        catch
        {
            return false;
        }
    }

    private static bool IsDefinitelyNotDispatched(Exception exception) => exception switch
    {
        DesktopIpcDeliveryException delivery =>
            delivery.Stage == DesktopIpcDeliveryStage.NotDispatched,
        DesktopIpcProtocolException protocol =>
            protocol.Stage == DesktopIpcDeliveryStage.Rejected,
        _ => false
    };

    private static bool IsPersistenceException(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or JsonException or
            InvalidDataException or InvalidOperationException or NotSupportedException;
}
