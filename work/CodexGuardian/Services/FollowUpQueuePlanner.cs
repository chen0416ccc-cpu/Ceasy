using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal enum FollowUpQueueDecisionKind
{
    None,
    NeedsCompletionAnchor,
    ReconcilePending,
    Waiting,
    Ready,
    Blocked
}

internal sealed record FollowUpQueueDecision(
    FollowUpQueueDecisionKind Kind,
    FollowUpMessageDefinition? Message,
    string Detail,
    DateTimeOffset? NextScheduledAtUtc = null,
    FollowUpOperationRecord? PendingOperation = null);

internal enum FollowUpCompletionArmKind
{
    Unknown,
    AwaitNextNormalCompletion,
    AnchoredToCurrentCompletion
}

internal sealed record FollowUpCompletionArmDecision(
    FollowUpCompletionArmKind Kind,
    string? AnchorTurnId)
{
    internal bool CanArm => Kind != FollowUpCompletionArmKind.Unknown;
}

internal static class FollowUpQueuePlanner
{
    internal static FollowUpQueueDecision Evaluate(
        ThreadFollowUpSettings? settings,
        TurnSnapshot? currentTurn,
        IReadOnlyCollection<FollowUpOperationRecord> operations,
        DateTimeOffset nowUtc,
        string? recoveredFromTurnId = null)
    {
        var pending = operations
            .Where(operation => operation.State is
                FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain)
            .OrderBy(operation => operation.CreatedAt)
            .ThenBy(operation => operation.OperationId, StringComparer.Ordinal)
            .ToArray();
        if (pending.Length > 1)
        {
            return new(
                FollowUpQueueDecisionKind.Blocked,
                null,
                "This task has multiple pending follow-up dispatches and requires manual review.");
        }

        if (pending.Length == 1)
        {
            var operation = pending[0];
            var message = settings?.Messages.FirstOrDefault(candidate => string.Equals(
                candidate.Id,
                operation.MessageId,
                StringComparison.OrdinalIgnoreCase));
            return new(
                FollowUpQueueDecisionKind.ReconcilePending,
                message,
                "A durable follow-up dispatch requires read-only reconciliation before the queue can advance.",
                PendingOperation: operation);
        }

        if (settings is null || !settings.IsEnabled)
        {
            return new(FollowUpQueueDecisionKind.None, null, "Follow-up messages are disabled.");
        }

        // Keep disabled definitions in the walk: an already-confirmed predecessor still
        // owns a successor turn and must not be skipped merely because it was later disabled.
        var ordered = settings.Messages
            .OrderBy(message => message.Order)
            .ThenBy(message => message.Id, StringComparer.Ordinal)
            .ToArray();
        if (ordered.Length == 0)
        {
            return new(FollowUpQueueDecisionKind.None, null, "No enabled follow-up message is queued.");
        }

        string? requiredSuccessorTurnId = null;
        foreach (var message in ordered)
        {
            var messageOperations = operations
                .Where(operation => string.Equals(
                    operation.MessageId,
                    message.Id,
                    StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(operation => operation.UpdatedAt)
                .ToArray();
            var confirmed = messageOperations.FirstOrDefault(operation =>
                operation.State == FollowUpOperationState.Confirmed);
            if (confirmed is not null)
            {
                if (string.IsNullOrWhiteSpace(confirmed.NewTurnId))
                {
                    return new(
                        FollowUpQueueDecisionKind.Blocked,
                        message,
                        "A confirmed follow-up operation has no successor turn id.");
                }

                requiredSuccessorTurnId = confirmed.CompletionTurnId ?? confirmed.NewTurnId;
                continue;
            }

            if (messageOperations.Any(operation => operation.State is
                    FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain))
            {
                return new(
                    FollowUpQueueDecisionKind.Blocked,
                    message,
                    "A prior follow-up dispatch is uncertain and will not be sent again automatically.");
            }

            // Disabled or workflow-owned unsent items are intentionally skipped. Any item that
            // already produced a turn was handled above and remains a queue barrier.
            if (!message.IsEnabled || message.UseWorkflowAutomation)
            {
                continue;
            }

            var retryable = messageOperations.FirstOrDefault(operation =>
                operation.State == FollowUpOperationState.Retryable);
            if (retryable is not null && FollowUpRetryPolicy.IsExhausted(
                    message,
                    retryable.AttemptCount))
            {
                return new(
                    FollowUpQueueDecisionKind.Blocked,
                    message,
                    "The follow-up exhausted its configured error retry allowance.");
            }

            if (requiredSuccessorTurnId is not null &&
                !string.Equals(currentTurn?.Id, requiredSuccessorTurnId, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(recoveredFromTurnId, requiredSuccessorTurnId, StringComparison.OrdinalIgnoreCase))
            {
                return new(
                    FollowUpQueueDecisionKind.Waiting,
                    message,
                    "Waiting for the preceding follow-up turn to become the verified latest turn.");
            }

            if (!IsNormalCompletion(currentTurn))
            {
                return new(
                    FollowUpQueueDecisionKind.Waiting,
                    message,
                    "The latest turn is not a confirmed normal completion; recovery retains priority.");
            }

            var normalCompletion = currentTurn!;

            if (message.Trigger == FollowUpTriggerKind.ScheduledAt)
            {
                if (message.ScheduledAtUtc is not { } scheduledAtUtc)
                {
                    return new(
                        FollowUpQueueDecisionKind.Blocked,
                        message,
                        "The scheduled follow-up has no valid UTC send time.");
                }

                scheduledAtUtc = scheduledAtUtc.ToUniversalTime();
                return scheduledAtUtc <= nowUtc
                    ? new(FollowUpQueueDecisionKind.Ready, message, "The scheduled follow-up is due.")
                    : new(
                        FollowUpQueueDecisionKind.Waiting,
                        message,
                        "The scheduled follow-up is waiting for its due time.",
                        scheduledAtUtc);
            }

            if (requiredSuccessorTurnId is null &&
                string.IsNullOrWhiteSpace(settings.CompletionAnchorTurnId))
            {
                return new(
                    FollowUpQueueDecisionKind.Ready,
                    message,
                    "The first observed normal completion makes the queued follow-up eligible.");
            }

            if (requiredSuccessorTurnId is null &&
                string.Equals(
                    normalCompletion.Id,
                    settings.CompletionAnchorTurnId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return new(
                    FollowUpQueueDecisionKind.Waiting,
                    message,
                    "Waiting for a turn newer than the configured completion baseline.");
            }

            return new(
                FollowUpQueueDecisionKind.Ready,
                message,
                "A new normal completion makes the next queued follow-up eligible.");
        }

        return new(FollowUpQueueDecisionKind.None, null, "All enabled follow-up messages were sent.");
    }

    internal static FollowUpQueueRuntimeSnapshot DescribeRuntime(
        ThreadFollowUpSettings? settings,
        FollowUpQueueDecision decision,
        IReadOnlyCollection<FollowUpOperationRecord> operations)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(operations);
        if (settings is null || settings.Messages.Count == 0)
        {
            return new(FollowUpQueueRuntimeKind.None, 0, 0, 0);
        }

        var messageIds = settings.Messages
            .Select(message => message.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var enabledIds = settings.Messages
            .Where(message => message.IsEnabled)
            .Select(message => message.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var matchingOperations = operations
            .Where(operation => messageIds.Contains(operation.MessageId))
            .ToArray();
        var confirmedIds = matchingOperations
            .Where(operation => operation.State == FollowUpOperationState.Confirmed)
            .Select(operation => operation.MessageId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var kind = !settings.IsEnabled
            ? FollowUpQueueRuntimeKind.Paused
            : matchingOperations.Any(operation => operation.State == FollowUpOperationState.Uncertain)
                ? FollowUpQueueRuntimeKind.Uncertain
                : matchingOperations.Any(operation => operation.State == FollowUpOperationState.Dispatching)
                    ? FollowUpQueueRuntimeKind.Dispatching
                    : decision.Kind switch
                    {
                        FollowUpQueueDecisionKind.Blocked or
                            FollowUpQueueDecisionKind.NeedsCompletionAnchor =>
                            FollowUpQueueRuntimeKind.Blocked,
                        FollowUpQueueDecisionKind.Ready => FollowUpQueueRuntimeKind.Ready,
                        FollowUpQueueDecisionKind.Waiting
                            when decision.Message?.Trigger == FollowUpTriggerKind.ScheduledAt =>
                            FollowUpQueueRuntimeKind.Scheduled,
                        FollowUpQueueDecisionKind.Waiting =>
                            FollowUpQueueRuntimeKind.WaitingForCompletion,
                        FollowUpQueueDecisionKind.ReconcilePending =>
                            FollowUpQueueRuntimeKind.Uncertain,
                        FollowUpQueueDecisionKind.None
                            when enabledIds.Count == 0 => FollowUpQueueRuntimeKind.Blocked,
                        FollowUpQueueDecisionKind.None
                            when enabledIds.All(confirmedIds.Contains) =>
                            FollowUpQueueRuntimeKind.Exhausted,
                        _ => FollowUpQueueRuntimeKind.Configured
                    };
        var nextScheduledAtUtc = kind == FollowUpQueueRuntimeKind.Scheduled
            ? decision.NextScheduledAtUtc ?? decision.Message?.ScheduledAtUtc?.ToUniversalTime()
            : null;
        return new(
            kind,
            settings.Messages.Count,
            enabledIds.Count,
            confirmedIds.Count,
            nextScheduledAtUtc);
    }

    internal static DateTimeOffset? FindNextScheduledAtUtc(
        IReadOnlyDictionary<string, ThreadFollowUpSettings> settings,
        IReadOnlyCollection<FollowUpOperationRecord> operations,
        IReadOnlySet<string>? suppressedThreadIds = null)
    {
        DateTimeOffset? next = null;
        foreach (var pair in settings)
        {
            if (suppressedThreadIds?.Contains(pair.Key) == true || !pair.Value.IsEnabled)
            {
                continue;
            }

            if (operations.Any(operation =>
                    string.Equals(operation.ThreadId, pair.Key, StringComparison.OrdinalIgnoreCase) &&
                    operation.State is FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain))
            {
                continue;
            }

            foreach (var message in pair.Value.Messages
                         .OrderBy(message => message.Order)
                         .ThenBy(message => message.Id, StringComparer.Ordinal))
            {
                var messageOperations = operations.Where(operation =>
                    string.Equals(operation.ThreadId, pair.Key, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(operation.MessageId, message.Id, StringComparison.OrdinalIgnoreCase)).ToArray();
                var confirmed = messageOperations.FirstOrDefault(operation =>
                    operation.State == FollowUpOperationState.Confirmed);
                if (confirmed is not null)
                {
                    // Until the successor is observed as a normal completion, no later
                    // scheduled item may bypass the confirmed predecessor.
                    if (confirmed.CompletionTurnId is null)
                    {
                        break;
                    }

                    continue;
                }

                if (messageOperations.Any(operation => operation.State is
                        FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain))
                {
                    break;
                }

                if (!message.IsEnabled || message.UseWorkflowAutomation)
                {
                    continue;
                }

                if (message.Trigger == FollowUpTriggerKind.ScheduledAt &&
                    message.ScheduledAtUtc is { } scheduledAtUtc)
                {
                    var utc = scheduledAtUtc.ToUniversalTime();
                    next = next is null || utc < next ? utc : next;
                }

                break;
            }
        }

        return next;
    }

    internal static IReadOnlyList<string> FindDueScheduledThreadIds(
        IReadOnlyDictionary<string, ThreadFollowUpSettings> settings,
        IReadOnlyCollection<FollowUpOperationRecord> operations,
        DateTimeOffset nowUtc,
        IReadOnlySet<string>? suppressedThreadIds = null)
    {
        var due = new List<string>();
        foreach (var pair in settings)
        {
            if (suppressedThreadIds?.Contains(pair.Key) == true || !pair.Value.IsEnabled)
            {
                continue;
            }

            if (operations.Any(operation =>
                    string.Equals(operation.ThreadId, pair.Key, StringComparison.OrdinalIgnoreCase) &&
                    operation.State is FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain))
            {
                continue;
            }

            foreach (var message in pair.Value.Messages
                         .OrderBy(message => message.Order)
                         .ThenBy(message => message.Id, StringComparer.Ordinal))
            {
                var messageOperations = operations.Where(operation =>
                    string.Equals(operation.ThreadId, pair.Key, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(operation.MessageId, message.Id, StringComparison.OrdinalIgnoreCase)).ToArray();
                var confirmed = messageOperations.FirstOrDefault(operation =>
                    operation.State == FollowUpOperationState.Confirmed);
                if (confirmed is not null)
                {
                    if (confirmed.CompletionTurnId is null)
                    {
                        break;
                    }

                    continue;
                }

                if (messageOperations.Any(operation => operation.State is
                        FollowUpOperationState.Dispatching or FollowUpOperationState.Uncertain))
                {
                    break;
                }

                if (!message.IsEnabled || message.UseWorkflowAutomation)
                {
                    continue;
                }

                if (message.Trigger == FollowUpTriggerKind.ScheduledAt &&
                    message.ScheduledAtUtc is { } scheduledAtUtc &&
                    scheduledAtUtc.ToUniversalTime() <= nowUtc)
                {
                    due.Add(pair.Key);
                }

                break;
            }
        }

        return due;
    }

    internal static bool IsNormalCompletion(TurnSnapshot? turn) =>
        turn is not null &&
        string.Equals(turn.Status, "completed", StringComparison.OrdinalIgnoreCase) &&
        turn.HasConfirmedLocalTerminal &&
        turn.HasReliableFinalOutput &&
        turn.HasCompleteItemEvidence &&
        !turn.HasAmbiguousActivity;

    internal static bool RequiresCompletionAnchor(
        bool queueEnabled,
        IEnumerable<FollowUpMessageDefinition>? messages) =>
        queueEnabled && messages?.Any(message =>
            message is not null &&
            message.IsEnabled &&
            !message.UseWorkflowAutomation &&
            message.Trigger == FollowUpTriggerKind.AfterNormalCompletion) == true;

    internal static FollowUpCompletionArmDecision EvaluateCompletionArm(
        TurnSnapshot? currentTurn,
        string? runtimeStatus)
    {
        if (IsNormalCompletion(currentTurn))
        {
            return new(
                FollowUpCompletionArmKind.AnchoredToCurrentCompletion,
                currentTurn!.Id);
        }

        if (currentTurn is not null)
        {
            if (string.Equals(currentTurn.Status, "completed", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(currentTurn.Status) ||
                string.Equals(currentTurn.Status, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                return new(FollowUpCompletionArmKind.Unknown, null);
            }

            return new(FollowUpCompletionArmKind.AwaitNextNormalCompletion, null);
        }

        return string.Equals(runtimeStatus, "active", StringComparison.OrdinalIgnoreCase)
            ? new(FollowUpCompletionArmKind.AwaitNextNormalCompletion, null)
            : new(FollowUpCompletionArmKind.Unknown, null);
    }
}
