using CodexGuardian.Models;
using System.Globalization;

namespace CodexGuardian.Services;

internal enum WorkflowConversationAuthorityStatus
{
    Available,
    Missing,
    Ambiguous,
    Unavailable
}

internal sealed record WorkflowConversationReadRequest(
    string ConversationId,
    string? RequiredTurnId = null);

internal sealed record WorkflowConversationAuthoritySnapshot(
    WorkflowConversationAuthorityStatus Status,
    ThreadSummary? Thread,
    TurnSnapshot? LatestTurn,
    TurnSnapshot? RequiredTurn)
{
    internal bool IsActiveRoot =>
        Status == WorkflowConversationAuthorityStatus.Available &&
        Thread is { IsArchived: false, IsSubAgent: false, IsEphemeral: false };

    internal static WorkflowConversationAuthoritySnapshot Missing { get; } =
        new(WorkflowConversationAuthorityStatus.Missing, null, null, null);

    internal static WorkflowConversationAuthoritySnapshot Ambiguous { get; } =
        new(WorkflowConversationAuthorityStatus.Ambiguous, null, null, null);

    internal static WorkflowConversationAuthoritySnapshot Unavailable(ThreadSummary? thread = null) =>
        new(WorkflowConversationAuthorityStatus.Unavailable, thread, null, null);
}

internal interface IWorkflowConversationAuthorityReader
{
    Task<IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot>> ReadAsync(
        IReadOnlyList<WorkflowConversationReadRequest> requests,
        CancellationToken cancellationToken);
}

internal sealed class AppServerWorkflowConversationAuthorityReader
    : IWorkflowConversationAuthorityReader
{
    private readonly AppServerClient _inner;
    private readonly LocalConversationHistoryReader _localHistory;

    internal AppServerWorkflowConversationAuthorityReader(
        AppServerClient inner,
        LocalConversationHistoryReader? localHistory = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _localHistory = localHistory ?? new LocalConversationHistoryReader();
    }

    public async Task<IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot>> ReadAsync(
        IReadOnlyList<WorkflowConversationReadRequest> requests,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requests);
        var normalized = NormalizeRequests(requests);
        if (normalized.Count == 0)
        {
            return new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
                StringComparer.OrdinalIgnoreCase);
        }

        IReadOnlyList<ThreadSummary> active;
        IReadOnlyList<ThreadSummary> archived;
        try
        {
            var activeTask = _inner.ListThreadsAsync(
                200,
                includeSubAgents: true,
                archived: false,
                cancellationToken);
            var archivedTask = _inner.ListThreadsAsync(
                200,
                includeSubAgents: true,
                archived: true,
                cancellationToken);
            await Task.WhenAll(activeTask, archivedTask).ConfigureAwait(false);
            active = activeTask.Result;
            archived = archivedTask.Result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return normalized.Keys.ToDictionary(
                static id => id,
                static _ => WorkflowConversationAuthoritySnapshot.Unavailable(),
                StringComparer.OrdinalIgnoreCase);
        }

        var result = new Dictionary<string, WorkflowConversationAuthoritySnapshot>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var request in normalized.Values.OrderBy(
                     static request => request.ConversationId,
                     StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = ResolveExactDirectoryEntry(
                request.ConversationId,
                active,
                archived);
            if (directory.Status != WorkflowConversationAuthorityStatus.Available ||
                directory.Thread is null)
            {
                result.Add(request.ConversationId, directory);
                continue;
            }

            try
            {
                if (request.RequiredTurnId is null)
                {
                    var latestTask = _inner.ReadLatestTurnAsync(
                            request.ConversationId,
                            cancellationToken);
                    var localTask = _localHistory.ReadLatestTerminalEventAsync(
                        request.ConversationId,
                        cancellationToken);
                    await Task.WhenAll(latestTask, localTask).ConfigureAwait(false);
                    var reconciled = ReconcileTurns(
                        latestTask.Result is null ? [] : [latestTask.Result],
                        requiredTurnId: null,
                        localTask.Result);
                    result.Add(
                        request.ConversationId,
                        directory with { LatestTurn = reconciled.LatestTurn });
                    continue;
                }

                var turnsTask = _inner.ReadRecentTurnsAsync(
                        request.ConversationId,
                        limit: 20,
                        cancellationToken);
                var terminalTask = _localHistory.ReadLatestTerminalEventAsync(
                    request.ConversationId,
                    cancellationToken);
                await Task.WhenAll(turnsTask, terminalTask).ConfigureAwait(false);
                var turns = ReconcileTurns(
                    turnsTask.Result,
                    request.RequiredTurnId,
                    terminalTask.Result);
                result.Add(
                    request.ConversationId,
                    directory with
                    {
                        LatestTurn = turns.LatestTurn,
                        RequiredTurn = turns.RequiredTurn
                    });
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                result.Add(
                    request.ConversationId,
                    WorkflowConversationAuthoritySnapshot.Unavailable(directory.Thread));
            }
        }

        return result;
    }

    internal static (TurnSnapshot? LatestTurn, TurnSnapshot? RequiredTurn) ReconcileTurns(
        IReadOnlyList<TurnSnapshot> appServerTurns,
        string? requiredTurnId,
        LocalConversationTerminalEvent? localTerminal)
    {
        ArgumentNullException.ThrowIfNull(appServerTurns);
        var latest = LocalConversationHistoryReader.ReconcileLatestTurn(
            appServerTurns.FirstOrDefault(),
            localTerminal);
        if (requiredTurnId is null)
        {
            return (latest, null);
        }

        var required = appServerTurns.SingleOrDefault(turn => string.Equals(
            turn.Id,
            requiredTurnId,
            StringComparison.OrdinalIgnoreCase));
        if (required is not null && localTerminal is not null && string.Equals(
                required.Id,
                localTerminal.TurnId,
                StringComparison.OrdinalIgnoreCase))
        {
            required = LocalConversationHistoryReader.ReconcileLatestTurn(
                required,
                localTerminal);
        }

        if (required is not null && latest is not null && string.Equals(
                required.Id,
                latest.Id,
                StringComparison.OrdinalIgnoreCase))
        {
            required = latest;
        }

        return (latest, required);
    }

    internal static WorkflowConversationAuthoritySnapshot ResolveExactDirectoryEntry(
        string conversationId,
        IEnumerable<ThreadSummary> active,
        IEnumerable<ThreadSummary> archived)
    {
        conversationId = NormalizeId(conversationId, nameof(conversationId));
        ArgumentNullException.ThrowIfNull(active);
        ArgumentNullException.ThrowIfNull(archived);
        var matches = active
            .Concat(archived)
            .Where(thread => string.Equals(
                thread.Id,
                conversationId,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return matches.Length switch
        {
            0 => WorkflowConversationAuthoritySnapshot.Missing,
            1 => new WorkflowConversationAuthoritySnapshot(
                WorkflowConversationAuthorityStatus.Available,
                matches[0],
                LatestTurn: null,
                RequiredTurn: null),
            _ => WorkflowConversationAuthoritySnapshot.Ambiguous
        };
    }

    private static IReadOnlyDictionary<string, WorkflowConversationReadRequest> NormalizeRequests(
        IReadOnlyList<WorkflowConversationReadRequest> requests)
    {
        var normalized = new Dictionary<string, WorkflowConversationReadRequest>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var request in requests)
        {
            ArgumentNullException.ThrowIfNull(request);
            var conversationId = NormalizeId(request.ConversationId, nameof(requests));
            var requiredTurnId = request.RequiredTurnId is null
                ? null
                : NormalizeId(request.RequiredTurnId, nameof(requests));
            if (normalized.TryGetValue(conversationId, out var existing))
            {
                if (existing.RequiredTurnId is not null && requiredTurnId is not null &&
                    !string.Equals(
                        existing.RequiredTurnId,
                        requiredTurnId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException(
                        "One conversation cannot request two different workflow source turns.",
                        nameof(requests));
                }

                if (existing.RequiredTurnId is null && requiredTurnId is not null)
                {
                    normalized[conversationId] = new WorkflowConversationReadRequest(
                        conversationId,
                        requiredTurnId);
                }

                continue;
            }

            normalized.Add(
                conversationId,
                new WorkflowConversationReadRequest(conversationId, requiredTurnId));
        }

        return normalized;
    }

    private static string NormalizeId(string? value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty conversation UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }
}

internal sealed record WorkflowSettingsAuthoritySnapshot(
    bool IsAvailable,
    AppSettings? Settings);

internal interface IWorkflowSettingsAuthorityReader
{
    Task<WorkflowSettingsAuthoritySnapshot> ReadAsync(CancellationToken cancellationToken);
}

internal sealed class SettingsWorkflowSettingsAuthorityReader(SettingsService inner)
    : IWorkflowSettingsAuthorityReader
{
    public async Task<WorkflowSettingsAuthoritySnapshot> ReadAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var settings = await inner.LoadAsync(cancellationToken).ConfigureAwait(false);
            return new WorkflowSettingsAuthoritySnapshot(
                settings.ReadStatus != SettingsReadStatus.ConservativeDefaults,
                settings);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new WorkflowSettingsAuthoritySnapshot(false, null);
        }
    }
}

internal sealed record WorkflowRuleRevisionAuthoritySnapshot(
    bool IsAvailable,
    bool IsCurrentEnabled,
    long RuleStoreGeneration);

internal interface IWorkflowRuleRevisionAuthorityReader
{
    Task<WorkflowRuleRevisionAuthoritySnapshot> ReadAsync(
        WorkflowRuleDefinition rule,
        CancellationToken cancellationToken);
}

internal sealed class StoreWorkflowRuleRevisionAuthorityReader(WorkflowRuleStore inner)
    : IWorkflowRuleRevisionAuthorityReader
{
    public async Task<WorkflowRuleRevisionAuthoritySnapshot> ReadAsync(
        WorkflowRuleDefinition rule,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rule);
        try
        {
            var snapshot = await inner.ReadAsync(cancellationToken).ConfigureAwait(false);
            var available = !snapshot.RequiresConservativeRecovery &&
                            snapshot.ReadStatus is WorkflowRuleStoreReadStatus.Missing or
                                WorkflowRuleStoreReadStatus.Healthy;
            var current = available && snapshot.Rules.Any(candidate =>
                candidate.IsEnabled &&
                string.Equals(candidate.RuleId, rule.RuleId, StringComparison.OrdinalIgnoreCase) &&
                candidate.Revision == rule.Revision &&
                string.Equals(
                    candidate.DefinitionDigest,
                    rule.DefinitionDigest,
                    StringComparison.Ordinal));
            return new WorkflowRuleRevisionAuthoritySnapshot(
                available,
                current,
                Math.Max(0, snapshot.Generation));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new WorkflowRuleRevisionAuthoritySnapshot(false, false, 0);
        }
    }
}

internal sealed record WorkflowOperationAuthoritySnapshot(
    bool IsAvailable,
    IReadOnlySet<string> BusyConversationIds,
    WorkflowActionOperationRecord? SourceDispatchAction)
{
    internal IReadOnlyList<WorkflowActionOperationRecord> CurrentTriggerActions { get; init; } = [];
}

internal interface IWorkflowOperationAuthorityReader
{
    Task<WorkflowOperationAuthoritySnapshot> ReadAsync(
        WorkflowTriggerEventRecord triggerEvent,
        CancellationToken cancellationToken);
}

internal sealed class JournalWorkflowOperationAuthorityReader(
    WorkflowOperationJournal workflowJournal,
    FollowUpOperationJournal followUpJournal) : IWorkflowOperationAuthorityReader
{
    public async Task<WorkflowOperationAuthoritySnapshot> ReadAsync(
        WorkflowTriggerEventRecord triggerEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(triggerEvent);
        try
        {
            var workflowTask = workflowJournal.ReadAsync(cancellationToken);
            var followUpTask = followUpJournal.ReadAsync(cancellationToken);
            await Task.WhenAll(workflowTask, followUpTask).ConfigureAwait(false);
            var workflow = workflowTask.Result;
            var followUp = followUpTask.Result;
            var workflowAvailable = !workflow.RequiresConservativeRecovery &&
                                    workflow.ReadStatus is WorkflowJournalReadStatus.Missing or
                                        WorkflowJournalReadStatus.Healthy;
            var followUpAvailable = !followUp.RequiresConservativeRecovery &&
                                    followUp.ReadStatus is FollowUpJournalReadStatus.Missing or
                                        FollowUpJournalReadStatus.Healthy;
            if (!workflowAvailable || !followUpAvailable)
            {
                return new WorkflowOperationAuthoritySnapshot(
                    false,
                    new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                    SourceDispatchAction: null);
            }

            var currentTriggerActions = workflow.Actions
                .Where(action => string.Equals(
                    action.TriggerEventId,
                    triggerEvent.TriggerEventId,
                    StringComparison.OrdinalIgnoreCase))
                .OrderBy(static action => action.ActionIndex)
                .ToArray();
            var currentTriggerActionIds = currentTriggerActions
                .Select(static action => action.ActionOperationId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var busy = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var action in workflow.Actions.Where(action =>
                         !string.Equals(
                             action.TriggerEventId,
                             triggerEvent.TriggerEventId,
                             StringComparison.OrdinalIgnoreCase) &&
                         action.TargetConversationId is not null &&
                         action.State is WorkflowActionOperationState.Prepared or
                             WorkflowActionOperationState.Dispatching or
                             WorkflowActionOperationState.Retryable or
                             WorkflowActionOperationState.Uncertain))
            {
                busy.Add(action.TargetConversationId!);
            }

            foreach (var operation in followUp.Records.Where(operation =>
                         !currentTriggerActionIds.Contains(operation.OperationId) &&
                         operation.State is FollowUpOperationState.Prepared or
                             FollowUpOperationState.Dispatching or
                             FollowUpOperationState.Retryable or FollowUpOperationState.Uncertain))
            {
                busy.Add(operation.ThreadId);
            }

            var sourceAction = workflow.Actions.SingleOrDefault(action => string.Equals(
                action.ActionOperationId,
                triggerEvent.SourceTurnOrOperationId,
                StringComparison.OrdinalIgnoreCase));
            return new WorkflowOperationAuthoritySnapshot(
                true,
                busy,
                sourceAction)
            {
                CurrentTriggerActions = currentTriggerActions
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new WorkflowOperationAuthoritySnapshot(
                false,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                SourceDispatchAction: null);
        }
    }
}

internal interface IWorkflowAttachmentAvailabilityReader
{
    Task<bool> IsAvailableAsync(
        StructuredPresetPayload payload,
        CancellationToken cancellationToken);
}

internal sealed class ManagedWorkflowAttachmentAvailabilityReader(
    IManagedAttachmentStore store,
    IDesktopStructuredInputCapabilityProvider capabilities)
    : IWorkflowAttachmentAvailabilityReader
{
    public async Task<bool> IsAvailableAsync(
        StructuredPresetPayload payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.HasValidIdentity())
        {
            return false;
        }

        if (payload.Attachments.Count == 0)
        {
            return true;
        }

        try
        {
            var current = await capabilities.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!current.Evaluate(payload).IsSatisfied)
            {
                return false;
            }

            foreach (var attachment in payload.Attachments)
            {
                if (!await store.VerifyAsync(attachment, cancellationToken).ConfigureAwait(false))
                {
                    return false;
                }
            }

            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }
}

internal sealed record WorkflowResolvedPreset(
    string OwnerConversationId,
    string MessageId,
    bool OwnerConversationAvailable,
    bool QueueAvailable,
    bool QueueEnabled,
    FollowUpMessageDefinition? Definition,
    bool RuleBindingCurrent,
    StructuredPresetPayload? Payload,
    bool ManagedAttachmentsAvailable)
{
    internal bool IsEnabled => PresetAutomationPolicy.IsWorkflowMessageAuthorized(this);
}

internal sealed record WorkflowExecutionResolution(
    WorkflowRuleDefinition Rule,
    WorkflowTriggerEventRecord TriggerEvent,
    WorkflowConversationAuthoritySnapshot SourceConversation,
    WorkflowConversationAuthoritySnapshot? TargetConversation,
    IReadOnlyDictionary<int, WorkflowResolvedPreset> Presets,
    bool SettingsAvailable,
    long SettingsGeneration,
    long RuleStoreGeneration,
    bool SourceEventAfterActivation,
    bool TargetHasPendingOperation,
    bool OperationAuthorityAvailable,
    bool SourceConversationExists,
    bool TargetConversationExists,
    bool RuleAndPresetEnabled,
    bool TargetIdle,
    bool TargetPolicyAllowsAction,
    bool ManagedAttachmentsAvailable)
{
    internal IReadOnlyList<WorkflowActionOperationRecord> CurrentTriggerActions { get; init; } = [];

    internal bool IsConditionSatisfied(WorkflowConditionKind condition) => condition switch
    {
        WorkflowConditionKind.SourceConversationExists => SourceConversationExists,
        WorkflowConditionKind.TargetConversationExists => TargetConversationExists,
        WorkflowConditionKind.RuleAndPresetEnabled => RuleAndPresetEnabled,
        WorkflowConditionKind.SourceEventAfterActivation => SourceEventAfterActivation,
        WorkflowConditionKind.TargetIdle => TargetIdle,
        WorkflowConditionKind.TargetPolicyAllowsAction => TargetPolicyAllowsAction,
        WorkflowConditionKind.ManagedAttachmentsAvailable => ManagedAttachmentsAvailable,
        _ => false
    };
}

internal sealed class WorkflowExecutionResolver
{
    private readonly IWorkflowConversationAuthorityReader _conversations;
    private readonly IWorkflowSettingsAuthorityReader _settings;
    private readonly IWorkflowRuleRevisionAuthorityReader _rules;
    private readonly IWorkflowOperationAuthorityReader _operations;
    private readonly IWorkflowAttachmentAvailabilityReader? _attachments;

    internal WorkflowExecutionResolver(
        IWorkflowConversationAuthorityReader conversations,
        IWorkflowSettingsAuthorityReader settings,
        IWorkflowRuleRevisionAuthorityReader rules,
        IWorkflowOperationAuthorityReader operations,
        IWorkflowAttachmentAvailabilityReader? attachments = null)
    {
        _conversations = conversations ?? throw new ArgumentNullException(nameof(conversations));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        _operations = operations ?? throw new ArgumentNullException(nameof(operations));
        _attachments = attachments;
    }

    internal async Task<WorkflowExecutionResolution> ResolveAsync(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(triggerEvent);
        if (!rule.HasValidIdentity())
        {
            throw new ArgumentException("A canonical workflow rule is required.", nameof(rule));
        }

        var requests = BuildConversationRequests(rule, triggerEvent);
        var conversationsTask = _conversations.ReadAsync(requests, cancellationToken);
        var settingsTask = _settings.ReadAsync(cancellationToken);
        var rulesTask = _rules.ReadAsync(rule, cancellationToken);
        var operationsTask = _operations.ReadAsync(triggerEvent, cancellationToken);
        await Task.WhenAll(conversationsTask, settingsTask, rulesTask, operationsTask)
            .ConfigureAwait(false);

        var conversations = conversationsTask.Result;
        var settingsAuthority = settingsTask.Result;
        var ruleAuthority = rulesTask.Result;
        var operationAuthority = operationsTask.Result;
        var source = ReadConversation(conversations, triggerEvent.SourceConversationId);
        var targetId = rule.ResolveKnownDestinationConversationId();
        var target = targetId is null
            ? null
            : ReadConversation(conversations, targetId);
        var resolvedPresets = await ResolvePresetsAsync(
                rule,
                conversations,
                settingsAuthority,
                cancellationToken)
            .ConfigureAwait(false);

        var sourceExists = source.IsActiveRoot;
        var targetExists = rule.Destination.Kind == WorkflowDestinationKind.NewConversation ||
                           target?.IsActiveRoot == true;
        var ruleOwnerExists = ReadConversation(
            conversations,
            rule.OwnerConversationId).IsActiveRoot;
        var ruleAndPresetEnabled = rule.IsEnabled &&
                                   ruleAuthority.IsAvailable &&
                                   ruleAuthority.IsCurrentEnabled &&
                                   ruleOwnerExists &&
                                   settingsAuthority.IsAvailable &&
                                   resolvedPresets.Values.All(static preset => preset.IsEnabled);
        var sourceAfterActivation = IsSourceEventAfterActivation(
            rule,
            triggerEvent,
            source,
            operationAuthority.SourceDispatchAction);
        var targetPending = targetId is not null &&
                            operationAuthority.BusyConversationIds.Contains(targetId);
        var targetIdle = rule.Destination.Kind == WorkflowDestinationKind.NewConversation ||
                         target?.Thread is { RuntimeStatus: var runtimeStatus } &&
                         string.Equals(runtimeStatus, "idle", StringComparison.OrdinalIgnoreCase) &&
                         target.LatestTurn is { } latest &&
                         FollowUpQueuePlanner.IsNormalCompletion(latest) &&
                         operationAuthority.IsAvailable &&
                         !targetPending;
        var targetPolicyAllows = ResolveTargetPolicy(
            rule,
            target,
            resolvedPresets,
            settingsAuthority);
        var managedAttachmentsAvailable = resolvedPresets.Values.All(static preset =>
            preset.Payload is not null && preset.ManagedAttachmentsAvailable);

        return new WorkflowExecutionResolution(
            rule,
            triggerEvent,
            source,
            target,
            resolvedPresets,
            settingsAuthority.IsAvailable,
            settingsAuthority.Settings?.SettingsGeneration ?? 0,
            ruleAuthority.RuleStoreGeneration,
            sourceAfterActivation,
            targetPending,
            operationAuthority.IsAvailable,
            sourceExists,
            targetExists,
            ruleAndPresetEnabled,
            targetIdle,
            targetPolicyAllows,
            managedAttachmentsAvailable)
        {
            CurrentTriggerActions = operationAuthority.CurrentTriggerActions
        };
    }

    private async Task<IReadOnlyDictionary<int, WorkflowResolvedPreset>> ResolvePresetsAsync(
        WorkflowRuleDefinition rule,
        IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot> conversations,
        WorkflowSettingsAuthoritySnapshot settingsAuthority,
        CancellationToken cancellationToken)
    {
        var resolved = new Dictionary<int, WorkflowResolvedPreset>();
        foreach (var action in rule.Actions.Where(static action =>
                     action.Kind == WorkflowActionKind.SendPresetMessage))
        {
            var ownerId = action.PresetOwnerConversationId!;
            var messageId = action.PresetMessageId!;
            var ownerAvailable = ReadConversation(conversations, ownerId).IsActiveRoot;
            ThreadFollowUpSettings? queue = null;
            FollowUpMessageDefinition? definition = null;
            if (settingsAuthority.IsAvailable && settingsAuthority.Settings is not null &&
                settingsAuthority.Settings.ThreadFollowUps.TryGetValue(ownerId, out queue))
            {
                definition = queue.Messages.SingleOrDefault(message => string.Equals(
                    message.Id,
                    messageId,
                    StringComparison.OrdinalIgnoreCase));
            }

            StructuredPresetPayload? payload = null;
            var attachmentsAvailable = false;
            var ruleBindingCurrent = definition is not null &&
                                     IsRuleBindingCurrent(rule, ownerId, definition);
            if (definition is not null)
            {
                try
                {
                    payload = StructuredPresetPayload.Create(
                        definition.Message,
                        definition.Attachments);
                    attachmentsAvailable = payload.Attachments.Count == 0 ||
                                           _attachments is not null &&
                                           await _attachments.IsAvailableAsync(
                                                   payload,
                                                   cancellationToken)
                                               .ConfigureAwait(false);
                }
                catch (ArgumentException)
                {
                    payload = null;
                    attachmentsAvailable = false;
                }
            }

            resolved.Add(
                action.Order,
                new WorkflowResolvedPreset(
                    ownerId,
                    messageId,
                    ownerAvailable,
                    queue is not null,
                    queue?.IsEnabled == true,
                    definition,
                    ruleBindingCurrent,
                    payload,
                    attachmentsAvailable));
        }

        return resolved;
    }

    private static bool IsRuleBindingCurrent(
        WorkflowRuleDefinition rule,
        string presetOwnerConversationId,
        FollowUpMessageDefinition definition)
    {
        if (!definition.UseWorkflowAutomation)
        {
            return false;
        }

        if (!WorkflowRuleEditor.IsManagedRuleForOwner(rule, presetOwnerConversationId))
        {
            return true;
        }

        return definition.WorkflowRuleRevision == rule.Revision &&
               string.Equals(
                   definition.WorkflowRuleDigest,
                   rule.DefinitionDigest,
                   StringComparison.Ordinal);
    }

    private static bool ResolveTargetPolicy(
        WorkflowRuleDefinition rule,
        WorkflowConversationAuthoritySnapshot? target,
        IReadOnlyDictionary<int, WorkflowResolvedPreset> presets,
        WorkflowSettingsAuthoritySnapshot settingsAuthority)
    {
        if (rule.Destination.Kind == WorkflowDestinationKind.NewConversation ||
            target?.IsActiveRoot != true ||
            target.Thread is null ||
            !settingsAuthority.IsAvailable ||
            settingsAuthority.Settings is null)
        {
            return false;
        }

        var settings = settingsAuthority.Settings;
        foreach (var action in rule.Actions)
        {
            if (action.Kind == WorkflowActionKind.EnableConversationProtection)
            {
                continue;
            }

            if (!PresetAutomationPolicy.IsTargetProtectionAuthorized(
                    settings,
                    target.Thread.Id) ||
                !presets.TryGetValue(action.Order, out var preset) ||
                !PresetAutomationPolicy.IsWorkflowMessageAuthorized(preset))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSourceEventAfterActivation(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        WorkflowConversationAuthoritySnapshot source,
        WorkflowActionOperationRecord? sourceDispatchAction)
    {
        if (triggerEvent.TriggerKind != rule.Trigger.Kind ||
            triggerEvent.ObservedAtUtc < rule.ActivatedAtUtc)
        {
            return false;
        }

        return rule.Trigger.Kind switch
        {
            WorkflowTriggerKind.ScheduledAt =>
                rule.Trigger.ScheduledAtUtc is { } scheduledAtUtc &&
                scheduledAtUtc >= rule.ActivatedAtUtc &&
                triggerEvent.ObservedAtUtc >= scheduledAtUtc &&
                string.Equals(
                    triggerEvent.SourceConversationId,
                    rule.OwnerConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(triggerEvent.SourceId, rule.RuleId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    triggerEvent.SourceTurnOrOperationId,
                    rule.RuleId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    triggerEvent.Occurrence,
                    "scheduled:" + scheduledAtUtc.UtcTicks.ToString(CultureInfo.InvariantCulture),
                    StringComparison.Ordinal),
            WorkflowTriggerKind.ConversationCompletedNormally =>
                IsNormalCompletionSourceEventAfterActivation(rule, triggerEvent, source),
            WorkflowTriggerKind.PresetDispatchConfirmed =>
                string.Equals(
                    triggerEvent.SourceConversationId,
                    rule.Trigger.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    triggerEvent.SourceId,
                    rule.Trigger.SourcePresetMessageId,
                    StringComparison.OrdinalIgnoreCase) &&
                sourceDispatchAction is
                {
                    State: WorkflowActionOperationState.Confirmed,
                    ActionKind: WorkflowActionKind.SendPresetMessage,
                    GeneratedTurnId: not null
                } &&
                string.Equals(
                    sourceDispatchAction.ActionOperationId,
                    triggerEvent.SourceTurnOrOperationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    sourceDispatchAction.PresetOwnerConversationId,
                    rule.Trigger.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    sourceDispatchAction.PresetMessageId,
                    rule.Trigger.SourcePresetMessageId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    sourceDispatchAction.GeneratedTurnId,
                    triggerEvent.Occurrence,
                    StringComparison.OrdinalIgnoreCase) &&
                sourceDispatchAction.UpdatedAtUtc >= rule.ActivatedAtUtc &&
                triggerEvent.ObservedAtUtc >= sourceDispatchAction.UpdatedAtUtc,
            _ => false
        };
    }

    private static bool IsNormalCompletionSourceEventAfterActivation(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        WorkflowConversationAuthoritySnapshot source)
    {
        if (!string.Equals(
                triggerEvent.SourceConversationId,
                rule.Trigger.SourceConversationId,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                triggerEvent.SourceId,
                rule.Trigger.SourceConversationId,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        DateTimeOffset completedAtUtc;
        var hasDurableOccurrence = TryReadCompletionOccurrence(
            triggerEvent.Occurrence,
            out completedAtUtc);
        if (!hasDurableOccurrence &&
            (source.RequiredTurn is not { } fallbackTurn ||
             !string.Equals(
                 fallbackTurn.Id,
                 triggerEvent.SourceTurnOrOperationId,
                 StringComparison.OrdinalIgnoreCase) ||
             !FollowUpQueuePlanner.IsNormalCompletion(fallbackTurn) ||
             !TryReadCompletedAtUtc(fallbackTurn, out completedAtUtc)))
        {
            return false;
        }

        if (source.RequiredTurn is { } currentTurn &&
            (!string.Equals(
                 currentTurn.Id,
                 triggerEvent.SourceTurnOrOperationId,
                 StringComparison.OrdinalIgnoreCase) ||
             !FollowUpQueuePlanner.IsNormalCompletion(currentTurn) ||
             !TryReadCompletedAtUtc(currentTurn, out var currentCompletedAtUtc) ||
             currentCompletedAtUtc != completedAtUtc))
        {
            return false;
        }

        return completedAtUtc >= rule.ActivatedAtUtc &&
               triggerEvent.ObservedAtUtc >= completedAtUtc;
    }

    private static bool TryReadCompletionOccurrence(
        string occurrence,
        out DateTimeOffset completedAtUtc)
    {
        completedAtUtc = default;
        const string prefix = "normal-completion:";
        if (!occurrence.StartsWith(prefix, StringComparison.Ordinal) ||
            !long.TryParse(
                occurrence.AsSpan(prefix.Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var completedAt))
        {
            return false;
        }

        try
        {
            completedAtUtc = DateTimeOffset.FromUnixTimeSeconds(completedAt);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool TryReadCompletedAtUtc(
        TurnSnapshot turn,
        out DateTimeOffset completedAtUtc)
    {
        completedAtUtc = default;
        if (turn.CompletedAt is not { } completedAt)
        {
            return false;
        }

        try
        {
            completedAtUtc = DateTimeOffset.FromUnixTimeSeconds(completedAt);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static IReadOnlyList<WorkflowConversationReadRequest> BuildConversationRequests(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent)
    {
        var requiredTurns = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            [triggerEvent.SourceConversationId] =
                triggerEvent.TriggerKind == WorkflowTriggerKind.ConversationCompletedNormally
                    ? triggerEvent.SourceTurnOrOperationId
                    : null
        };
        requiredTurns.TryAdd(rule.OwnerConversationId, null);
        if (rule.ResolveKnownDestinationConversationId() is { } targetId)
        {
            requiredTurns.TryAdd(targetId, null);
        }

        foreach (var action in rule.Actions.Where(static action =>
                     action.Kind == WorkflowActionKind.SendPresetMessage))
        {
            requiredTurns.TryAdd(action.PresetOwnerConversationId!, null);
        }

        return requiredTurns
            .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
            .Select(static pair => new WorkflowConversationReadRequest(pair.Key, pair.Value))
            .ToArray();
    }

    private static WorkflowConversationAuthoritySnapshot ReadConversation(
        IReadOnlyDictionary<string, WorkflowConversationAuthoritySnapshot> conversations,
        string conversationId) =>
        conversations.TryGetValue(conversationId, out var snapshot)
            ? snapshot
            : WorkflowConversationAuthoritySnapshot.Unavailable();
}

internal sealed class WorkflowFiniteConditionEvaluator(WorkflowExecutionResolver resolver)
    : IWorkflowConditionEvaluator
{
    public async Task<WorkflowConditionEvaluationResult> EvaluateAsync(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent,
        CancellationToken cancellationToken)
    {
        var resolution = await resolver.ResolveAsync(rule, triggerEvent, cancellationToken)
            .ConfigureAwait(false);
        var failed = rule.Conditions
            .Where(condition => !resolution.IsConditionSatisfied(condition))
            .Distinct()
            .Order()
            .ToArray();
        return new WorkflowConditionEvaluationResult(
            failed.Length == 0,
            Array.AsReadOnly(failed));
    }
}
