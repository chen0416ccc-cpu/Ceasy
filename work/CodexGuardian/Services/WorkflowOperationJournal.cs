using CodexGuardian.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CodexGuardian.Services;

public enum WorkflowActionOperationState
{
    Prepared,
    Dispatching,
    Retryable,
    Uncertain,
    Confirmed,
    Exhausted,
    Canceled,
    Blocked
}

public enum WorkflowJournalReadStatus
{
    Missing,
    Healthy,
    RecoveredFromBackup,
    Corrupted,
    UnsupportedSchema
}

public sealed record WorkflowTriggerEventRecord(
    string TriggerEventId,
    WorkflowTriggerKind TriggerKind,
    string SourceConversationId,
    string SourceId,
    string SourceTurnOrOperationId,
    string Occurrence,
    string CorrelationId,
    string? CausationId,
    int CorrelationDepth,
    DateTimeOffset ObservedAtUtc);

public sealed record WorkflowActionOperationRecord(
    string ActionOperationId,
    string RuleId,
    int RuleRevision,
    string DefinitionDigest,
    string TriggerEventId,
    string CorrelationId,
    string CausationId,
    int ActionIndex,
    int CorrelationDepth,
    WorkflowActionKind ActionKind,
    WorkflowDestinationKind DestinationKind,
    string? TargetConversationId,
    string? PresetOwnerConversationId,
    string? PresetMessageId,
    string? ClientMessageId,
    WorkflowActionOperationState State,
    int AttemptCount,
    string? FailureClass,
    string? ConfirmedTargetConversationId,
    string? GeneratedTurnId,
    long? ProtectionSettingsGeneration,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc)
{
    public string? ExecutionFingerprint { get; init; }

    public long? AuthoritativeTargetGeneration { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<DateTimeOffset>? DispatchAttemptTimesUtc { get; init; }
}

public sealed record WorkflowActionReceipt(
    string TargetConversationId,
    string? GeneratedTurnId,
    long? ProtectionSettingsGeneration);

public sealed record WorkflowJournalSnapshot(
    WorkflowJournalReadStatus ReadStatus,
    long Generation,
    bool RequiresConservativeRecovery,
    IReadOnlyList<WorkflowTriggerEventRecord> TriggerEvents,
    IReadOnlyList<WorkflowActionOperationRecord> Actions);

public sealed record WorkflowTriggerEventPrepareResult(
    WorkflowTriggerEventRecord Record,
    bool Created);

public sealed record WorkflowActionPrepareResult(
    WorkflowActionOperationRecord Record,
    bool Created);

public sealed record WorkflowActionTransitionResult(
    bool Changed,
    WorkflowActionOperationRecord? Record,
    long Generation);

public enum WorkflowExecutionBindingStatus
{
    Bound,
    AlreadyBound,
    NoProgress,
    NotFound,
    InvalidState
}

public sealed record WorkflowExecutionBindingResult(
    WorkflowExecutionBindingStatus Status,
    WorkflowActionOperationRecord? Record,
    long Generation);

public sealed class WorkflowOperationJournal
{
    internal const int CurrentSchemaVersion = 2;
    internal const int DefaultMaximumTriggerEvents = 4096;
    internal const int DefaultMaximumActions = 4096;
    internal const int MaximumCorrelationDepth = 32;
    internal const int MaximumActionsPerCorrelation = 256;
    internal const int MaximumActionsPerRulePerCorrelation = 32;
    internal static readonly TimeSpan MaximumCorrelationLifetime = TimeSpan.FromHours(24);
    internal const int MaximumDispatchAttemptsPerCorrelationPerHour = 64;
    internal const int MaximumRecordedDispatchAttemptsPerCorrelation = 2048;
    private static readonly TimeSpan DispatchBudgetWindow = TimeSpan.FromHours(1);
    internal const long DefaultMaximumFileBytes = 4 * 1024 * 1024;
    private const int MaximumOccurrenceLength = 128;
    private const int MaximumFailureClassLength = 64;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly int _maximumTriggerEvents;
    private readonly int _maximumActions;
    private readonly long _maximumFileBytes;
    private readonly TimeProvider _timeProvider;
    private readonly List<WorkflowTriggerEventRecord> _triggerEvents = [];
    private readonly List<WorkflowActionOperationRecord> _actions = [];
    private bool _loaded;
    private bool _requiresConservativeRecovery;
    private bool _unsupportedSchema;
    private long _generation;
    private WorkflowJournalReadStatus _readStatus = WorkflowJournalReadStatus.Missing;

    public WorkflowOperationJournal(
        string dataDirectory,
        int maximumTriggerEvents = DefaultMaximumTriggerEvents,
        int maximumActions = DefaultMaximumActions,
        long maximumFileBytes = DefaultMaximumFileBytes,
        TimeProvider? timeProvider = null)
    {
        if (maximumTriggerEvents < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumTriggerEvents));
        }

        if (maximumActions < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumActions));
        }

        if (maximumFileBytes < 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFileBytes));
        }

        DataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        JournalPath = Path.Combine(DataDirectory, "workflow-operations.json");
        BackupPath = Path.Combine(DataDirectory, "workflow-operations.previous.json");
        InitializationMarkerPath = Path.Combine(DataDirectory, "workflow-operations.initialized");
        _maximumTriggerEvents = maximumTriggerEvents;
        _maximumActions = maximumActions;
        _maximumFileBytes = maximumFileBytes;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string DataDirectory { get; }

    public string JournalPath { get; }

    public string BackupPath { get; }

    public string InitializationMarkerPath { get; }

    public async Task<WorkflowJournalSnapshot> ReadAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            return CreateSnapshot();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<WorkflowTriggerEventPrepareResult> GetOrCreateTriggerEventAsync(
        WorkflowTriggerKind triggerKind,
        string sourceConversationId,
        string sourceId,
        string sourceTurnOrOperationId,
        string occurrence,
        DateTimeOffset observedAtUtc,
        string? correlationId = null,
        string? causationId = null,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(triggerKind))
        {
            throw new ArgumentOutOfRangeException(nameof(triggerKind));
        }

        sourceConversationId = NormalizeId(sourceConversationId, nameof(sourceConversationId));
        sourceId = NormalizeId(sourceId, nameof(sourceId));
        sourceTurnOrOperationId = NormalizeId(
            sourceTurnOrOperationId,
            nameof(sourceTurnOrOperationId));
        occurrence = NormalizeOccurrence(occurrence);
        if (observedAtUtc == default)
        {
            throw new ArgumentException("A trigger observation time is required.", nameof(observedAtUtc));
        }

        observedAtUtc = observedAtUtc.ToUniversalTime();
        var triggerEventId = CreateTriggerEventId(
            triggerKind,
            sourceConversationId,
            sourceId,
            sourceTurnOrOperationId,
            occurrence);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            WorkflowActionOperationRecord? parent = null;
            int correlationDepth;
            if (causationId is null)
            {
                if (correlationId is not null)
                {
                    throw new ArgumentException(
                        "An external trigger cannot supply a separate correlation id.",
                        nameof(correlationId));
                }

                correlationId = triggerEventId;
                correlationDepth = 0;
            }
            else
            {
                causationId = NormalizeId(causationId, nameof(causationId));
                parent = FindAction(causationId) ?? throw new InvalidOperationException(
                    "A downstream trigger must identify an existing parent action.");
                if (parent.State != WorkflowActionOperationState.Confirmed)
                {
                    throw new InvalidOperationException(
                        "Only a confirmed workflow action can emit a downstream trigger.");
                }

                correlationId = correlationId is null
                    ? parent.CorrelationId
                    : NormalizeId(correlationId, nameof(correlationId));
                if (!string.Equals(
                        correlationId,
                        parent.CorrelationId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "A downstream trigger cannot change its inherited correlation identity.");
                }

                correlationDepth = parent.CorrelationDepth;
            }

            var candidate = new WorkflowTriggerEventRecord(
                triggerEventId,
                triggerKind,
                sourceConversationId,
                sourceId,
                sourceTurnOrOperationId,
                occurrence,
                correlationId,
                causationId,
                correlationDepth,
                observedAtUtc);
            var existing = FindTriggerEvent(triggerEventId);
            if (existing is not null)
            {
                EnsureSameTriggerIdentity(existing, candidate);
                return new WorkflowTriggerEventPrepareResult(existing, Created: false);
            }

            if (parent is not null)
            {
                var root = FindTriggerEvent(correlationId) ?? throw new InvalidOperationException(
                    "A downstream trigger correlation root is not durable.");
                if (observedAtUtc < root.ObservedAtUtc)
                {
                    throw new InvalidOperationException(
                        "A downstream trigger observation cannot precede its correlation root.");
                }
            }

            ThrowIfConservativeForNewOperation();
            if (_triggerEvents.Count >= _maximumTriggerEvents)
            {
                throw new InvalidOperationException("The workflow trigger ledger is at capacity.");
            }

            var triggerEvents = new List<WorkflowTriggerEventRecord>(_triggerEvents) { candidate };
            var persisted = await PersistCandidateAsync(triggerEvents, _actions, cancellationToken)
                .ConfigureAwait(false);
            Commit(persisted);
            return new WorkflowTriggerEventPrepareResult(candidate, Created: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<WorkflowActionPrepareResult> GetOrCreateActionAsync(
        WorkflowRuleDefinition rule,
        string triggerEventId,
        int actionIndex,
        string? resolvedTargetConversationId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (!rule.HasValidIdentity() || !rule.IsEnabled)
        {
            throw new ArgumentException("An enabled canonical workflow rule is required.", nameof(rule));
        }

        triggerEventId = NormalizeId(triggerEventId, nameof(triggerEventId));
        if (actionIndex < 0 || actionIndex >= rule.Actions.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(actionIndex));
        }

        var actionDefinition = rule.Actions[actionIndex];
        if (actionDefinition.Order != actionIndex)
        {
            throw new ArgumentException("The workflow action index does not match canonical order.", nameof(rule));
        }

        var actionOperationId = CreateActionOperationId(
            rule.RuleId,
            rule.Revision,
            triggerEventId,
            actionIndex);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var triggerEvent = FindTriggerEvent(triggerEventId) ?? throw new InvalidOperationException(
                "A workflow action cannot be prepared before its trigger event is durable.");
            EnsureRuleMatchesTrigger(rule, triggerEvent);
            var correlationRoot = FindTriggerEvent(triggerEvent.CorrelationId) ?? throw new InvalidOperationException(
                "A workflow action correlation root is not durable.");
            if (triggerEvent.ObservedAtUtc < rule.ActivatedAtUtc)
            {
                throw new InvalidOperationException(
                    "A workflow event older than the rule activation boundary cannot prepare an action.");
            }

            var targetConversationId = ResolveTargetConversationId(
                rule,
                actionDefinition,
                resolvedTargetConversationId);
            var now = ReadNow();
            var lifetimeFailure = CorrelationLifetimeFailure(correlationRoot.ObservedAtUtc, now);
            var candidate = new WorkflowActionOperationRecord(
                actionOperationId,
                rule.RuleId,
                rule.Revision,
                rule.DefinitionDigest,
                triggerEvent.TriggerEventId,
                triggerEvent.CorrelationId,
                triggerEvent.TriggerEventId,
                actionIndex,
                checked(triggerEvent.CorrelationDepth + 1),
                actionDefinition.Kind,
                rule.Destination.Kind,
                targetConversationId,
                actionDefinition.PresetOwnerConversationId,
                actionDefinition.PresetMessageId,
                actionDefinition.Kind == WorkflowActionKind.SendPresetMessage
                    ? CreateClientMessageId(actionOperationId)
                    : null,
                lifetimeFailure is null
                    ? WorkflowActionOperationState.Prepared
                    : WorkflowActionOperationState.Blocked,
                AttemptCount: 0,
                FailureClass: lifetimeFailure,
                ConfirmedTargetConversationId: null,
                GeneratedTurnId: null,
                ProtectionSettingsGeneration: null,
                now,
                now);
            var existing = FindAction(actionOperationId);
            if (existing is not null)
            {
                EnsureSameActionIdentity(existing, candidate);
                return new WorkflowActionPrepareResult(existing, Created: false);
            }

            ThrowIfConservativeForNewOperation();
            EnsureCorrelationLimits(candidate);
            if (_actions.Count >= _maximumActions)
            {
                throw new InvalidOperationException("The workflow action ledger is at capacity.");
            }

            var actions = new List<WorkflowActionOperationRecord>(_actions) { candidate };
            var persisted = await PersistCandidateAsync(_triggerEvents, actions, cancellationToken)
                .ConfigureAwait(false);
            Commit(persisted);
            return new WorkflowActionPrepareResult(candidate, Created: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<WorkflowActionTransitionResult> TryStartDispatchAsync(
        string actionOperationId,
        CancellationToken cancellationToken = default) =>
        TryStartDispatchCoreAsync(actionOperationId, cancellationToken);

    private async Task<WorkflowActionTransitionResult> TryStartDispatchCoreAsync(
        string actionOperationId,
        CancellationToken cancellationToken)
    {
        actionOperationId = NormalizeId(actionOperationId, nameof(actionOperationId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var index = FindActionIndex(actionOperationId);
            if (index < 0)
            {
                return new WorkflowActionTransitionResult(false, null, _generation);
            }

            var current = _actions[index];
            if (current.State is not WorkflowActionOperationState.Prepared and not
                WorkflowActionOperationState.Retryable)
            {
                return new WorkflowActionTransitionResult(false, current, _generation);
            }

            var now = ReadNow();
            var failureClass = DispatchGateFailure(current, now);
            WorkflowActionOperationRecord updated;
            if (failureClass is not null)
            {
                updated = current with
                {
                    State = WorkflowActionOperationState.Blocked,
                    FailureClass = failureClass,
                    UpdatedAtUtc = LaterOf(current.UpdatedAtUtc, now)
                };
            }
            else
            {
                var attempts = current.DispatchAttemptTimesUtc?.ToList() ?? [];
                attempts.Add(now);
                updated = current with
                {
                    State = WorkflowActionOperationState.Dispatching,
                    AttemptCount = checked(current.AttemptCount + 1),
                    FailureClass = null,
                    UpdatedAtUtc = now,
                    DispatchAttemptTimesUtc = attempts.AsReadOnly()
                };
            }

            var actions = new List<WorkflowActionOperationRecord>(_actions);
            actions[index] = updated;
            var persisted = await PersistCandidateAsync(_triggerEvents, actions, cancellationToken)
                .ConfigureAwait(false);
            Commit(persisted);
            return new WorkflowActionTransitionResult(true, updated, _generation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<WorkflowExecutionBindingResult> TryBindExecutionAsync(
        string actionOperationId,
        string executionFingerprint,
        long authoritativeTargetGeneration,
        CancellationToken cancellationToken = default)
    {
        actionOperationId = NormalizeId(actionOperationId, nameof(actionOperationId));
        executionFingerprint = NormalizeExecutionFingerprint(executionFingerprint);
        if (authoritativeTargetGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(authoritativeTargetGeneration));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var index = FindActionIndex(actionOperationId);
            if (index < 0)
            {
                return new WorkflowExecutionBindingResult(
                    WorkflowExecutionBindingStatus.NotFound,
                    null,
                    _generation);
            }

            var current = _actions[index];
            if (current.ExecutionFingerprint is not null ||
                current.AuthoritativeTargetGeneration is not null)
            {
                if (!string.Equals(
                        current.ExecutionFingerprint,
                        executionFingerprint,
                        StringComparison.Ordinal) ||
                    current.AuthoritativeTargetGeneration != authoritativeTargetGeneration)
                {
                    throw new InvalidOperationException(
                        "A workflow action cannot change its bound execution identity.");
                }

                return new WorkflowExecutionBindingResult(
                    WorkflowExecutionBindingStatus.AlreadyBound,
                    current,
                    _generation);
            }

            if (current.State is not WorkflowActionOperationState.Prepared and not
                WorkflowActionOperationState.Retryable)
            {
                return new WorkflowExecutionBindingResult(
                    WorkflowExecutionBindingStatus.InvalidState,
                    current,
                    _generation);
            }

            var now = ReadNow();
            if (now < current.CreatedAtUtc || now < current.UpdatedAtUtc)
            {
                var blocked = current with
                {
                    State = WorkflowActionOperationState.Blocked,
                    FailureClass = "correlation-clock-invalid",
                    UpdatedAtUtc = current.UpdatedAtUtc
                };
                var blockedActions = new List<WorkflowActionOperationRecord>(_actions);
                blockedActions[index] = blocked;
                var blockedCandidate = await PersistCandidateAsync(
                        _triggerEvents,
                        blockedActions,
                        cancellationToken)
                    .ConfigureAwait(false);
                Commit(blockedCandidate);
                return new WorkflowExecutionBindingResult(
                    WorkflowExecutionBindingStatus.InvalidState,
                    blocked,
                    _generation);
            }

            var noProgress = _actions.Any(action =>
                !string.Equals(
                    action.ActionOperationId,
                    current.ActionOperationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(action.CorrelationId, current.CorrelationId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(action.RuleId, current.RuleId, StringComparison.OrdinalIgnoreCase) &&
                action.RuleRevision == current.RuleRevision &&
                string.Equals(
                    action.TargetConversationId,
                    current.TargetConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(action.ExecutionFingerprint, executionFingerprint, StringComparison.Ordinal) &&
                action.AuthoritativeTargetGeneration == authoritativeTargetGeneration);
            var updated = current with
            {
                ExecutionFingerprint = executionFingerprint,
                AuthoritativeTargetGeneration = authoritativeTargetGeneration,
                State = noProgress ? WorkflowActionOperationState.Blocked : current.State,
                FailureClass = noProgress ? "no-progress" : current.FailureClass,
                UpdatedAtUtc = now
            };
            var actions = new List<WorkflowActionOperationRecord>(_actions);
            actions[index] = updated;
            var persisted = await PersistCandidateAsync(_triggerEvents, actions, cancellationToken)
                .ConfigureAwait(false);
            Commit(persisted);
            return new WorkflowExecutionBindingResult(
                noProgress
                    ? WorkflowExecutionBindingStatus.NoProgress
                    : WorkflowExecutionBindingStatus.Bound,
                updated,
                _generation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<WorkflowActionTransitionResult> TryMarkRetryableProvenUnsentAsync(
        string actionOperationId,
        string failureClass,
        CancellationToken cancellationToken = default)
    {
        failureClass = NormalizeFailureClass(failureClass);
        return MutateActionAsync(
            actionOperationId,
            current => current.State == WorkflowActionOperationState.Dispatching
                ? current with
                {
                    State = WorkflowActionOperationState.Retryable,
                    FailureClass = failureClass,
                    UpdatedAtUtc = NextTimestamp(current)
                }
                : null,
            cancellationToken);
    }

    public Task<WorkflowActionTransitionResult> TryMarkUncertainAsync(
        string actionOperationId,
        string failureClass,
        CancellationToken cancellationToken = default)
    {
        failureClass = NormalizeFailureClass(failureClass);
        return MutateActionAsync(
            actionOperationId,
            current => current.State == WorkflowActionOperationState.Dispatching
                ? current with
                {
                    State = WorkflowActionOperationState.Uncertain,
                    FailureClass = failureClass,
                    UpdatedAtUtc = NextTimestamp(current)
                }
                : null,
            cancellationToken);
    }

    public Task<WorkflowActionTransitionResult> TryMarkConfirmedAsync(
        string actionOperationId,
        WorkflowActionReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        return MutateActionAsync(
            actionOperationId,
            current => CreateConfirmedRecord(current, receipt),
            cancellationToken);
    }

    public Task<WorkflowActionTransitionResult> TryMarkTerminalAsync(
        string actionOperationId,
        WorkflowActionOperationState terminalState,
        string failureClass,
        CancellationToken cancellationToken = default)
    {
        if (terminalState is not WorkflowActionOperationState.Exhausted and not
            WorkflowActionOperationState.Canceled and not WorkflowActionOperationState.Blocked)
        {
            throw new ArgumentOutOfRangeException(nameof(terminalState));
        }

        failureClass = NormalizeFailureClass(failureClass);
        return MutateActionAsync(
            actionOperationId,
            current => current.State is WorkflowActionOperationState.Prepared or
                    WorkflowActionOperationState.Retryable or WorkflowActionOperationState.Uncertain
                ? current with
                {
                    State = terminalState,
                    FailureClass = failureClass,
                    UpdatedAtUtc = NextTimestamp(current)
                }
                : null,
            cancellationToken);
    }

    public static string CreateTriggerEventId(
        WorkflowTriggerKind triggerKind,
        string sourceConversationId,
        string sourceId,
        string sourceTurnOrOperationId,
        string occurrence)
    {
        if (!Enum.IsDefined(triggerKind))
        {
            throw new ArgumentOutOfRangeException(nameof(triggerKind));
        }

        sourceConversationId = NormalizeId(sourceConversationId, nameof(sourceConversationId));
        sourceId = NormalizeId(sourceId, nameof(sourceId));
        sourceTurnOrOperationId = NormalizeId(sourceTurnOrOperationId, nameof(sourceTurnOrOperationId));
        occurrence = NormalizeOccurrence(occurrence);
        return CreateDeterministicId(string.Join(
            "|",
            "CodexFree.Workflow.TriggerEvent.v1",
            ((int)triggerKind).ToString(System.Globalization.CultureInfo.InvariantCulture),
            sourceConversationId,
            sourceId,
            sourceTurnOrOperationId,
            occurrence));
    }

    public static string CreateActionOperationId(
        string ruleId,
        int ruleRevision,
        string triggerEventId,
        int actionIndex)
    {
        ruleId = NormalizeId(ruleId, nameof(ruleId));
        triggerEventId = NormalizeId(triggerEventId, nameof(triggerEventId));
        if (ruleRevision <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ruleRevision));
        }

        if (actionIndex is < 0 or >= WorkflowRuleDefinition.MaximumActions)
        {
            throw new ArgumentOutOfRangeException(nameof(actionIndex));
        }

        return CreateDeterministicId(string.Join(
            "|",
            "CodexFree.Workflow.ActionOperation.v1",
            ruleId,
            ruleRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
            triggerEventId,
            actionIndex.ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    public static string CreateClientMessageId(string actionOperationId) =>
        CreateDeterministicId(
            "CodexFree.Workflow.ClientMessage.v1|" + NormalizeId(
                actionOperationId,
                nameof(actionOperationId)));

    private async Task<WorkflowActionTransitionResult> MutateActionAsync(
        string actionOperationId,
        Func<WorkflowActionOperationRecord, WorkflowActionOperationRecord?> mutation,
        CancellationToken cancellationToken)
    {
        actionOperationId = NormalizeId(actionOperationId, nameof(actionOperationId));
        ArgumentNullException.ThrowIfNull(mutation);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
            ThrowIfUnsupportedSchema();
            var index = FindActionIndex(actionOperationId);
            if (index < 0)
            {
                return new WorkflowActionTransitionResult(false, null, _generation);
            }

            var current = _actions[index];
            var updated = mutation(current);
            if (updated is null)
            {
                return new WorkflowActionTransitionResult(false, current, _generation);
            }

            var actions = new List<WorkflowActionOperationRecord>(_actions);
            actions[index] = updated;
            var persisted = await PersistCandidateAsync(_triggerEvents, actions, cancellationToken)
                .ConfigureAwait(false);
            Commit(persisted);
            return new WorkflowActionTransitionResult(true, updated, _generation);
        }
        finally
        {
            _gate.Release();
        }
    }

    private WorkflowActionOperationRecord? CreateConfirmedRecord(
        WorkflowActionOperationRecord current,
        WorkflowActionReceipt receipt)
    {
        if (current.State == WorkflowActionOperationState.Confirmed)
        {
            var normalizedExisting = NormalizeReceipt(current, receipt);
            return string.Equals(
                       current.ConfirmedTargetConversationId,
                       normalizedExisting.TargetConversationId,
                       StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(
                       current.GeneratedTurnId,
                       normalizedExisting.GeneratedTurnId,
                       StringComparison.OrdinalIgnoreCase) &&
                   current.ProtectionSettingsGeneration ==
                   normalizedExisting.ProtectionSettingsGeneration
                ? null
                : throw new InvalidOperationException(
                    "A confirmed workflow receipt cannot be replaced.");
        }

        if (current.State is not WorkflowActionOperationState.Dispatching and not
            WorkflowActionOperationState.Uncertain)
        {
            return null;
        }

        var normalized = NormalizeReceipt(current, receipt);
        return current with
        {
            State = WorkflowActionOperationState.Confirmed,
            TargetConversationId = current.TargetConversationId ?? normalized.TargetConversationId,
            FailureClass = null,
            ConfirmedTargetConversationId = normalized.TargetConversationId,
            GeneratedTurnId = normalized.GeneratedTurnId,
            ProtectionSettingsGeneration = normalized.ProtectionSettingsGeneration,
            UpdatedAtUtc = NextTimestamp(current)
        };
    }

    private static WorkflowActionReceipt NormalizeReceipt(
        WorkflowActionOperationRecord current,
        WorkflowActionReceipt receipt)
    {
        var targetConversationId = NormalizeId(
            receipt.TargetConversationId,
            nameof(receipt.TargetConversationId));
        if (current.TargetConversationId is not null && !string.Equals(
                current.TargetConversationId,
                targetConversationId,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The workflow receipt changed its prepared target.");
        }

        return current.ActionKind switch
        {
            WorkflowActionKind.SendPresetMessage when
                receipt.ProtectionSettingsGeneration is null => new WorkflowActionReceipt(
                targetConversationId,
                NormalizeId(receipt.GeneratedTurnId, nameof(receipt.GeneratedTurnId)),
                ProtectionSettingsGeneration: null),
            WorkflowActionKind.EnableConversationProtection when
                receipt.GeneratedTurnId is null && receipt.ProtectionSettingsGeneration is > 0 =>
                new WorkflowActionReceipt(
                    targetConversationId,
                    GeneratedTurnId: null,
                    receipt.ProtectionSettingsGeneration),
            _ => throw new ArgumentException(
                "The workflow receipt does not match its typed action.",
                nameof(receipt))
        };
    }

    private static string? ResolveTargetConversationId(
        WorkflowRuleDefinition rule,
        WorkflowActionDefinition action,
        string? resolvedTargetConversationId)
    {
        var expected = rule.ResolveKnownDestinationConversationId();
        if (expected is not null)
        {
            if (resolvedTargetConversationId is not null && !string.Equals(
                    NormalizeId(resolvedTargetConversationId, nameof(resolvedTargetConversationId)),
                    expected,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The prepared workflow target does not match the rule destination.");
            }

            return expected;
        }

        var resolved = string.IsNullOrWhiteSpace(resolvedTargetConversationId)
            ? null
            : NormalizeId(resolvedTargetConversationId, nameof(resolvedTargetConversationId));
        if (action.Kind == WorkflowActionKind.EnableConversationProtection && resolved is null)
        {
            throw new InvalidOperationException(
                "Protection for a new conversation requires its confirmed created conversation id.");
        }

        return resolved;
    }

    private static void EnsureRuleMatchesTrigger(
        WorkflowRuleDefinition rule,
        WorkflowTriggerEventRecord triggerEvent)
    {
        var matches = rule.Trigger.Kind switch
        {
            WorkflowTriggerKind.ScheduledAt =>
                triggerEvent.TriggerKind == WorkflowTriggerKind.ScheduledAt &&
                string.Equals(
                    triggerEvent.SourceConversationId,
                    rule.OwnerConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(triggerEvent.SourceId, rule.RuleId, StringComparison.OrdinalIgnoreCase),
            WorkflowTriggerKind.ConversationCompletedNormally =>
                triggerEvent.TriggerKind == WorkflowTriggerKind.ConversationCompletedNormally &&
                string.Equals(
                    triggerEvent.SourceConversationId,
                    rule.Trigger.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    triggerEvent.SourceId,
                    rule.Trigger.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase),
            WorkflowTriggerKind.PresetDispatchConfirmed =>
                triggerEvent.TriggerKind == WorkflowTriggerKind.PresetDispatchConfirmed &&
                string.Equals(
                    triggerEvent.SourceConversationId,
                    rule.Trigger.SourceConversationId,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    triggerEvent.SourceId,
                    rule.Trigger.SourcePresetMessageId,
                    StringComparison.OrdinalIgnoreCase),
            _ => false
        };
        if (!matches)
        {
            throw new InvalidOperationException(
                "The durable trigger event does not match the workflow rule trigger.");
        }
    }

    private void EnsureCorrelationLimits(WorkflowActionOperationRecord candidate)
    {
        if (candidate.CorrelationDepth is < 1 or > MaximumCorrelationDepth)
        {
            throw new InvalidOperationException("The workflow correlation depth bound was exceeded.");
        }

        var correlationActions = _actions.Where(action => string.Equals(
                action.CorrelationId,
                candidate.CorrelationId,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (correlationActions.Length >= MaximumActionsPerCorrelation ||
            correlationActions.Count(action => string.Equals(
                action.RuleId,
                candidate.RuleId,
                StringComparison.OrdinalIgnoreCase)) >= MaximumActionsPerRulePerCorrelation)
        {
            throw new InvalidOperationException("The workflow correlation action bound was exceeded.");
        }
    }

    private async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_loaded)
        {
            return;
        }

        _loaded = true;
        DataDirectorySafety.Revalidate(DataDirectory);
        try
        {
            var primary = await TryReadDocumentAsync(JournalPath, cancellationToken).ConfigureAwait(false);
            if (primary.Status == WorkflowJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (primary.Status == WorkflowJournalReadStatus.Healthy)
            {
                LoadDocument(primary.Document!, WorkflowJournalReadStatus.Healthy, recoveredBackup: false);
                return;
            }

            var backup = await TryReadDocumentAsync(BackupPath, cancellationToken).ConfigureAwait(false);
            if (backup.Status == WorkflowJournalReadStatus.UnsupportedSchema)
            {
                MarkUnsupportedSchema();
                return;
            }

            if (backup.Status == WorkflowJournalReadStatus.Healthy)
            {
                LoadDocument(
                    backup.Document!,
                    WorkflowJournalReadStatus.RecoveredFromBackup,
                    recoveredBackup: true);
                return;
            }

            if (primary.Status == WorkflowJournalReadStatus.Missing &&
                backup.Status == WorkflowJournalReadStatus.Missing &&
                !File.Exists(InitializationMarkerPath))
            {
                _readStatus = WorkflowJournalReadStatus.Missing;
                return;
            }

            MarkCorrupted();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _loaded = false;
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            MarkCorrupted();
        }
    }

    private async Task<JournalReadResult> TryReadDocumentAsync(
        string path,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (!File.Exists(path))
        {
            return new JournalReadResult(WorkflowJournalReadStatus.Missing, null);
        }

        try
        {
            var item = new FileInfo(path);
            var attributes = File.GetAttributes(path);
            if (item.Length <= 0 || item.Length > _maximumFileBytes ||
                (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                               FileAttributes.Device)) != 0)
            {
                return new JournalReadResult(WorkflowJournalReadStatus.Corrupted, null);
            }

            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (json.RootElement.ValueKind != JsonValueKind.Object ||
                !json.RootElement.TryGetProperty("schemaVersion", out var schemaElement) ||
                !schemaElement.TryGetInt32(out var schemaVersion))
            {
                return new JournalReadResult(WorkflowJournalReadStatus.Corrupted, null);
            }

            if (schemaVersion != CurrentSchemaVersion)
            {
                return new JournalReadResult(WorkflowJournalReadStatus.UnsupportedSchema, null);
            }

            var document = json.RootElement.Deserialize<JournalDocument>(JsonOptions);
            return document is not null && ValidateDocument(document)
                ? new JournalReadResult(WorkflowJournalReadStatus.Healthy, document)
                : new JournalReadResult(WorkflowJournalReadStatus.Corrupted, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new JournalReadResult(WorkflowJournalReadStatus.Corrupted, null);
        }
    }

    private void LoadDocument(
        JournalDocument document,
        WorkflowJournalReadStatus status,
        bool recoveredBackup)
    {
        var now = ReadNow();
        var actions = document.Actions!.Select(action =>
        {
            var promote = recoveredBackup
                ? action.State is WorkflowActionOperationState.Prepared or
                    WorkflowActionOperationState.Dispatching or WorkflowActionOperationState.Retryable
                : action.State == WorkflowActionOperationState.Dispatching;
            if (!promote)
            {
                return action;
            }

            var attempts = action.DispatchAttemptTimesUtc;
            if (action.AttemptCount == 0)
            {
                attempts = Array.AsReadOnly([action.UpdatedAtUtc]);
            }

            return action with
            {
                State = WorkflowActionOperationState.Uncertain,
                AttemptCount = Math.Max(action.AttemptCount, 1),
                FailureClass = "restart-uncertain",
                UpdatedAtUtc = LaterOf(action.UpdatedAtUtc, now),
                DispatchAttemptTimesUtc = attempts
            };
        }).ToArray();
        _triggerEvents.AddRange(document.TriggerEvents!);
        _actions.AddRange(actions.Select(FreezeAction));
        _generation = document.Generation;
        _requiresConservativeRecovery = document.RequiresConservativeRecovery || recoveredBackup;
        _readStatus = status;
    }

    private async Task<PersistedCandidate> PersistCandidateAsync(
        IReadOnlyList<WorkflowTriggerEventRecord> triggerEvents,
        IReadOnlyList<WorkflowActionOperationRecord> actions,
        CancellationToken cancellationToken)
    {
        var generation = checked(_generation + 1);
        var document = CreateDocument(
            generation,
            _requiresConservativeRecovery,
            triggerEvents,
            actions);
        if (!ValidateDocument(document))
        {
            throw new InvalidDataException("The workflow journal candidate is invalid.");
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
        if (bytes.LongLength > _maximumFileBytes)
        {
            throw new InvalidOperationException("The workflow journal exceeds its byte bound.");
        }

        DataDirectorySafety.Revalidate(DataDirectory);
        Directory.CreateDirectory(DataDirectory);
        DataDirectorySafety.Revalidate(DataDirectory);
        var temporaryPath = Path.Combine(
            DataDirectory,
            ".workflow-operations." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".tmp");
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
        try
        {
            await using (var stream = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, JournalPath);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, BackupPath);
            if (File.Exists(JournalPath))
            {
                File.Replace(temporaryPath, JournalPath, BackupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, JournalPath);
            }

            EnsureInitializationMarker();
        }
        finally
        {
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
            File.Delete(temporaryPath);
        }

        var readback = await TryReadDocumentAsync(JournalPath, cancellationToken).ConfigureAwait(false);
        if (readback.Status != WorkflowJournalReadStatus.Healthy ||
            readback.Document!.Generation != generation ||
            !string.Equals(readback.Document.Checksum, document.Checksum, StringComparison.Ordinal))
        {
            throw new IOException("The workflow journal readback failed.");
        }

        return new PersistedCandidate(
            triggerEvents.ToList(),
            actions.ToList(),
            generation);
    }

    private void EnsureInitializationMarker()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, InitializationMarkerPath);
        if (File.Exists(InitializationMarkerPath))
        {
            var attributes = File.GetAttributes(InitializationMarkerPath);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                               FileAttributes.Device)) != 0)
            {
                throw new IOException("The workflow journal initialization marker is unsafe.");
            }

            return;
        }

        using var stream = new FileStream(
            InitializationMarkerPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            16,
            FileOptions.WriteThrough);
        stream.WriteByte(CurrentSchemaVersion);
        stream.Flush(flushToDisk: true);
    }

    private bool ValidateDocument(JournalDocument document)
    {
        if (document.SchemaVersion != CurrentSchemaVersion ||
            document.Generation <= 0 ||
            document.TriggerEvents is null ||
            document.Actions is null ||
            document.TriggerEvents.Count > _maximumTriggerEvents ||
            document.Actions.Count > _maximumActions ||
            !IsSha256(document.Checksum))
        {
            return false;
        }

        var eventIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var eventsById = new Dictionary<string, WorkflowTriggerEventRecord>(StringComparer.OrdinalIgnoreCase);
        foreach (var triggerEvent in document.TriggerEvents)
        {
            if (!ValidateTriggerEvent(triggerEvent) || !eventIds.Add(triggerEvent.TriggerEventId))
            {
                return false;
            }

            eventsById.Add(triggerEvent.TriggerEventId, triggerEvent);
        }

        var actionIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var actionsById = new Dictionary<string, WorkflowActionOperationRecord>(StringComparer.OrdinalIgnoreCase);
        foreach (var action in document.Actions)
        {
            if (!ValidateAction(action) || !actionIds.Add(action.ActionOperationId))
            {
                return false;
            }

            actionsById.Add(action.ActionOperationId, action);
        }

        foreach (var triggerEvent in document.TriggerEvents)
        {
            if (triggerEvent.CausationId is null)
            {
                if (triggerEvent.CorrelationDepth != 0 || !string.Equals(
                        triggerEvent.CorrelationId,
                        triggerEvent.TriggerEventId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                continue;
            }

            if (!actionsById.TryGetValue(triggerEvent.CausationId, out var parent) ||
                parent.State != WorkflowActionOperationState.Confirmed ||
                !string.Equals(
                    triggerEvent.CorrelationId,
                    parent.CorrelationId,
                    StringComparison.OrdinalIgnoreCase) ||
                triggerEvent.CorrelationDepth != parent.CorrelationDepth)
            {
                return false;
            }
        }

        foreach (var action in document.Actions)
        {
            if (!eventsById.TryGetValue(action.TriggerEventId, out var triggerEvent) ||
                !string.Equals(action.CorrelationId, triggerEvent.CorrelationId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(action.CausationId, triggerEvent.TriggerEventId, StringComparison.OrdinalIgnoreCase) ||
                action.CorrelationDepth != triggerEvent.CorrelationDepth + 1)
            {
                return false;
            }
        }

        foreach (var group in document.TriggerEvents.GroupBy(
                     triggerEvent => triggerEvent.CorrelationId,
                     StringComparer.OrdinalIgnoreCase))
        {
            var root = eventsById.TryGetValue(group.Key, out var rootEvent)
                ? rootEvent
                : null;
            if (root is null || group.Any(triggerEvent =>
                    triggerEvent.ObservedAtUtc < root.ObservedAtUtc))
            {
                return false;
            }
        }

        if (document.Actions.GroupBy(action => action.CorrelationId, StringComparer.OrdinalIgnoreCase)
                .Any(group => group.Count() > MaximumActionsPerCorrelation) ||
            document.Actions.GroupBy(
                    action => action.CorrelationId + "|" + action.RuleId,
                    StringComparer.OrdinalIgnoreCase)
                .Any(group => group.Count() > MaximumActionsPerRulePerCorrelation) ||
            document.Actions.GroupBy(action => action.CorrelationId, StringComparer.OrdinalIgnoreCase)
                .Any(group => group.Sum(action => action.DispatchAttemptTimesUtc?.Count ?? 0) >
                    MaximumRecordedDispatchAttemptsPerCorrelation))
        {
            return false;
        }

        var expected = ComputeChecksum(
            document.SchemaVersion,
            document.Generation,
            document.RequiresConservativeRecovery,
            document.TriggerEvents,
            document.Actions);
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(expected),
            Convert.FromHexString(document.Checksum));
    }

    private static bool ValidateTriggerEvent(WorkflowTriggerEventRecord triggerEvent)
    {
        if (triggerEvent is null ||
            !IsCanonicalId(triggerEvent.TriggerEventId) ||
            !Enum.IsDefined(triggerEvent.TriggerKind) ||
            !IsCanonicalId(triggerEvent.SourceConversationId) ||
            !IsCanonicalId(triggerEvent.SourceId) ||
            !IsCanonicalId(triggerEvent.SourceTurnOrOperationId) ||
            !IsCanonicalOccurrence(triggerEvent.Occurrence) ||
            !IsCanonicalId(triggerEvent.CorrelationId) ||
            triggerEvent.CausationId is not null && !IsCanonicalId(triggerEvent.CausationId) ||
            triggerEvent.CorrelationDepth is < 0 or > MaximumCorrelationDepth ||
            triggerEvent.ObservedAtUtc == default || triggerEvent.ObservedAtUtc.Offset != TimeSpan.Zero)
        {
            return false;
        }

        return string.Equals(
            triggerEvent.TriggerEventId,
            CreateTriggerEventId(
                triggerEvent.TriggerKind,
                triggerEvent.SourceConversationId,
                triggerEvent.SourceId,
                triggerEvent.SourceTurnOrOperationId,
                triggerEvent.Occurrence),
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool ValidateAction(WorkflowActionOperationRecord action)
    {
        if (action is null ||
            !IsCanonicalId(action.ActionOperationId) ||
            !IsCanonicalId(action.RuleId) ||
            action.RuleRevision <= 0 ||
            !IsSha256(action.DefinitionDigest) ||
            !IsCanonicalId(action.TriggerEventId) ||
            !IsCanonicalId(action.CorrelationId) ||
            !IsCanonicalId(action.CausationId) ||
            action.ActionIndex is < 0 or >= WorkflowRuleDefinition.MaximumActions ||
            action.CorrelationDepth is < 1 or > MaximumCorrelationDepth ||
            !Enum.IsDefined(action.ActionKind) ||
            !Enum.IsDefined(action.DestinationKind) ||
            action.TargetConversationId is not null && !IsCanonicalId(action.TargetConversationId) ||
            !Enum.IsDefined(action.State) ||
            action.AttemptCount < 0 ||
            action.FailureClass is not null && !IsCanonicalFailureClass(action.FailureClass) ||
            action.ConfirmedTargetConversationId is not null &&
            !IsCanonicalId(action.ConfirmedTargetConversationId) ||
            action.GeneratedTurnId is not null && !IsCanonicalId(action.GeneratedTurnId) ||
            action.ProtectionSettingsGeneration is <= 0 ||
            (action.ExecutionFingerprint is null) !=
            (action.AuthoritativeTargetGeneration is null) ||
            action.ExecutionFingerprint is not null && !IsSha256(action.ExecutionFingerprint) ||
            action.AuthoritativeTargetGeneration is < 0 ||
            action.CreatedAtUtc == default || action.CreatedAtUtc.Offset != TimeSpan.Zero ||
            action.UpdatedAtUtc < action.CreatedAtUtc || action.UpdatedAtUtc.Offset != TimeSpan.Zero ||
            !ValidateDispatchAttemptTimes(action) ||
            !string.Equals(
                action.ActionOperationId,
                CreateActionOperationId(
                    action.RuleId,
                    action.RuleRevision,
                    action.TriggerEventId,
                    action.ActionIndex),
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (action.ActionKind == WorkflowActionKind.SendPresetMessage)
        {
            if (!IsCanonicalId(action.PresetOwnerConversationId) ||
                !IsCanonicalId(action.PresetMessageId) ||
                !IsCanonicalId(action.ClientMessageId) ||
                !string.Equals(
                    action.ClientMessageId,
                    CreateClientMessageId(action.ActionOperationId),
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }
        else if (action.PresetOwnerConversationId is not null ||
                 action.PresetMessageId is not null ||
                 action.ClientMessageId is not null)
        {
            return false;
        }

        if (action.DestinationKind is WorkflowDestinationKind.CurrentConversation or
                WorkflowDestinationKind.ExistingConversation && action.TargetConversationId is null ||
            action.ActionKind == WorkflowActionKind.EnableConversationProtection &&
            action.TargetConversationId is null)
        {
            return false;
        }

        var hasReceipt = action.ConfirmedTargetConversationId is not null ||
                         action.GeneratedTurnId is not null ||
                         action.ProtectionSettingsGeneration is not null;
        if (action.State == WorkflowActionOperationState.Confirmed)
        {
            if (!IsCanonicalId(action.ConfirmedTargetConversationId) ||
                action.TargetConversationId is not null && !string.Equals(
                    action.TargetConversationId,
                    action.ConfirmedTargetConversationId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (action.ActionKind == WorkflowActionKind.SendPresetMessage)
            {
                if (!IsCanonicalId(action.GeneratedTurnId) || action.ProtectionSettingsGeneration is not null)
                {
                    return false;
                }
            }
            else if (action.GeneratedTurnId is not null || action.ProtectionSettingsGeneration is not > 0)
            {
                return false;
            }
        }
        else if (hasReceipt)
        {
            return false;
        }

        return action.State switch
        {
            WorkflowActionOperationState.Prepared =>
                action.AttemptCount == 0 && action.FailureClass is null,
            WorkflowActionOperationState.Dispatching =>
                action.AttemptCount > 0 && action.FailureClass is null,
            WorkflowActionOperationState.Retryable or WorkflowActionOperationState.Uncertain =>
                action.AttemptCount > 0 && action.FailureClass is not null,
            WorkflowActionOperationState.Confirmed => action.AttemptCount > 0,
            WorkflowActionOperationState.Exhausted or WorkflowActionOperationState.Canceled or
                WorkflowActionOperationState.Blocked => action.FailureClass is not null,
            _ => false
        };
    }

    private static JournalDocument CreateDocument(
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<WorkflowTriggerEventRecord> triggerEvents,
        IReadOnlyList<WorkflowActionOperationRecord> actions)
    {
        var events = triggerEvents.ToList();
        var actionRecords = actions.ToList();
        var checksum = ComputeChecksum(
            CurrentSchemaVersion,
            generation,
            requiresConservativeRecovery,
            events,
            actionRecords);
        return new JournalDocument(
            CurrentSchemaVersion,
            generation,
            requiresConservativeRecovery,
            checksum,
            events,
            actionRecords);
    }

    private static string ComputeChecksum(
        int schemaVersion,
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<WorkflowTriggerEventRecord> triggerEvents,
        IReadOnlyList<WorkflowActionOperationRecord> actions)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new JournalIntegrityPayload(
                schemaVersion,
                generation,
                requiresConservativeRecovery,
                triggerEvents,
                actions),
            JsonOptions);
        return Convert.ToHexString(SHA256.HashData(payload));
    }

    private static void EnsureSameTriggerIdentity(
        WorkflowTriggerEventRecord existing,
        WorkflowTriggerEventRecord requested)
    {
        if (existing.TriggerKind != requested.TriggerKind ||
            !string.Equals(existing.SourceConversationId, requested.SourceConversationId, StringComparison.Ordinal) ||
            !string.Equals(existing.SourceId, requested.SourceId, StringComparison.Ordinal) ||
            !string.Equals(
                existing.SourceTurnOrOperationId,
                requested.SourceTurnOrOperationId,
                StringComparison.Ordinal) ||
            !string.Equals(existing.Occurrence, requested.Occurrence, StringComparison.Ordinal) ||
            !string.Equals(existing.CorrelationId, requested.CorrelationId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.CausationId, requested.CausationId, StringComparison.OrdinalIgnoreCase) ||
            existing.CorrelationDepth != requested.CorrelationDepth)
        {
            throw new InvalidOperationException("The trigger event id belongs to a different lineage identity.");
        }
    }

    private static void EnsureSameActionIdentity(
        WorkflowActionOperationRecord existing,
        WorkflowActionOperationRecord requested)
    {
        if (!string.Equals(existing.RuleId, requested.RuleId, StringComparison.OrdinalIgnoreCase) ||
            existing.RuleRevision != requested.RuleRevision ||
            !string.Equals(existing.DefinitionDigest, requested.DefinitionDigest, StringComparison.Ordinal) ||
            !string.Equals(existing.TriggerEventId, requested.TriggerEventId, StringComparison.OrdinalIgnoreCase) ||
            existing.ActionIndex != requested.ActionIndex ||
            existing.ActionKind != requested.ActionKind ||
            existing.DestinationKind != requested.DestinationKind ||
            !string.Equals(
                existing.TargetConversationId,
                requested.TargetConversationId,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                existing.PresetOwnerConversationId,
                requested.PresetOwnerConversationId,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.PresetMessageId, requested.PresetMessageId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.ClientMessageId, requested.ClientMessageId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.CorrelationId, requested.CorrelationId, StringComparison.OrdinalIgnoreCase) ||
            existing.CorrelationDepth != requested.CorrelationDepth)
        {
            throw new InvalidOperationException("The action operation id belongs to different rule inputs.");
        }
    }

    private WorkflowTriggerEventRecord? FindTriggerEvent(string triggerEventId) =>
        _triggerEvents.FirstOrDefault(value => string.Equals(
            value.TriggerEventId,
            triggerEventId,
            StringComparison.OrdinalIgnoreCase));

    private WorkflowActionOperationRecord? FindAction(string actionOperationId)
    {
        var index = FindActionIndex(actionOperationId);
        return index < 0 ? null : _actions[index];
    }

    private int FindActionIndex(string actionOperationId)
    {
        for (var index = 0; index < _actions.Count; index++)
        {
            if (string.Equals(
                    _actions[index].ActionOperationId,
                    actionOperationId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return -1;
    }

    private WorkflowJournalSnapshot CreateSnapshot() => new(
        _readStatus,
        _generation,
        _requiresConservativeRecovery,
        _triggerEvents.ToArray(),
        _actions.Select(FreezeAction).ToArray());

    private void Commit(PersistedCandidate persisted)
    {
        _triggerEvents.Clear();
        _triggerEvents.AddRange(persisted.TriggerEvents);
        _actions.Clear();
        _actions.AddRange(persisted.Actions.Select(FreezeAction));
        _generation = persisted.Generation;
        _readStatus = WorkflowJournalReadStatus.Healthy;
    }

    private void MarkCorrupted()
    {
        _triggerEvents.Clear();
        _actions.Clear();
        _requiresConservativeRecovery = true;
        _readStatus = WorkflowJournalReadStatus.Corrupted;
    }

    private void MarkUnsupportedSchema()
    {
        _triggerEvents.Clear();
        _actions.Clear();
        _requiresConservativeRecovery = true;
        _unsupportedSchema = true;
        _readStatus = WorkflowJournalReadStatus.UnsupportedSchema;
    }

    private void ThrowIfUnsupportedSchema()
    {
        if (_unsupportedSchema)
        {
            throw new NotSupportedException("The workflow journal schema is newer than this build.");
        }
    }

    private void ThrowIfConservativeForNewOperation()
    {
        if (_requiresConservativeRecovery)
        {
            throw new InvalidOperationException(
                "The workflow journal requires conservative reconciliation before new operations.");
        }
    }

    private string? DispatchGateFailure(
        WorkflowActionOperationRecord current,
        DateTimeOffset now)
    {
        var root = FindTriggerEvent(current.CorrelationId);
        if (root is null)
        {
            return "correlation-authority-unavailable";
        }

        if (now < current.CreatedAtUtc || now < current.UpdatedAtUtc)
        {
            return "correlation-clock-invalid";
        }

        var lifetimeFailure = CorrelationLifetimeFailure(root.ObservedAtUtc, now);
        if (lifetimeFailure is not null)
        {
            return lifetimeFailure;
        }

        var windowStart = now - DispatchBudgetWindow;
        var attempts = 0;
        foreach (var action in _actions)
        {
            if (!string.Equals(action.CorrelationId, current.CorrelationId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var attemptedAtUtc in action.DispatchAttemptTimesUtc ?? [])
            {
                if (attemptedAtUtc > now)
                {
                    return "correlation-clock-invalid";
                }

                if (attemptedAtUtc >= windowStart)
                {
                    attempts++;
                    if (attempts >= MaximumDispatchAttemptsPerCorrelationPerHour)
                    {
                        return "dispatch-budget-exhausted";
                    }
                }
            }
        }

        return null;
    }

    private static string? CorrelationLifetimeFailure(
        DateTimeOffset rootObservedAtUtc,
        DateTimeOffset now)
    {
        if (now < rootObservedAtUtc)
        {
            return "correlation-clock-invalid";
        }

        return now - rootObservedAtUtc > MaximumCorrelationLifetime
            ? "correlation-lifetime-exhausted"
            : null;
    }

    private static bool ValidateDispatchAttemptTimes(WorkflowActionOperationRecord action)
    {
        var attempts = action.DispatchAttemptTimesUtc;
        if (action.AttemptCount == 0)
        {
            return attempts is null or { Count: 0 };
        }

        if (attempts is null || attempts.Count != action.AttemptCount ||
            attempts.Count > MaximumRecordedDispatchAttemptsPerCorrelation)
        {
            return false;
        }

        DateTimeOffset? previous = null;
        foreach (var attemptedAtUtc in attempts)
        {
            if (attemptedAtUtc == default || attemptedAtUtc.Offset != TimeSpan.Zero ||
                attemptedAtUtc < action.CreatedAtUtc || attemptedAtUtc > action.UpdatedAtUtc ||
                previous is not null && attemptedAtUtc < previous.Value)
            {
                return false;
            }

            previous = attemptedAtUtc;
        }

        return true;
    }

    private DateTimeOffset ReadNow()
    {
        var now = _timeProvider.GetUtcNow();
        if (now == default)
        {
            throw new InvalidOperationException("The workflow journal clock is unavailable.");
        }

        return now.ToUniversalTime();
    }

    private DateTimeOffset NextTimestamp(WorkflowActionOperationRecord current) =>
        LaterOf(current.UpdatedAtUtc, ReadNow());

    private static DateTimeOffset LaterOf(DateTimeOffset left, DateTimeOffset right) =>
        left >= right ? left : right;

    private static WorkflowActionOperationRecord FreezeAction(
        WorkflowActionOperationRecord action) =>
        action.DispatchAttemptTimesUtc is null
            ? action
            : action with
            {
                DispatchAttemptTimesUtc = Array.AsReadOnly(
                    action.DispatchAttemptTimesUtc.ToArray())
            };

    private static string CreateDeterministicId(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value))[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes).ToString("D");
    }

    private static string NormalizeId(string? value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private static string NormalizeOccurrence(string? value)
    {
        value = value?.Trim() ?? string.Empty;
        if (!IsCanonicalOccurrence(value))
        {
            throw new ArgumentException("A bounded opaque workflow occurrence is required.", nameof(value));
        }

        return value;
    }

    private static string NormalizeFailureClass(string? value)
    {
        value = value?.Trim().ToLowerInvariant() ?? string.Empty;
        if (!IsCanonicalFailureClass(value))
        {
            throw new ArgumentException("A bounded workflow failure class is required.", nameof(value));
        }

        return value;
    }

    private static string NormalizeExecutionFingerprint(string? value)
    {
        value = value?.Trim().ToUpperInvariant() ?? string.Empty;
        if (!IsSha256(value))
        {
            throw new ArgumentException(
                "A canonical workflow execution fingerprint is required.",
                nameof(value));
        }

        return value;
    }

    private static bool IsCanonicalId(string? value) =>
        Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty &&
        string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool IsCanonicalOccurrence(string? value) =>
        value is { Length: > 0 and <= MaximumOccurrenceLength } && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or ':' or '.');

    private static bool IsCanonicalFailureClass(string? value) =>
        value is { Length: > 0 and <= MaximumFailureClassLength } && value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool IsSha256(string? value) =>
        value is { Length: SHA256.HashSizeInBytes * 2 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private sealed record PersistedCandidate(
        List<WorkflowTriggerEventRecord> TriggerEvents,
        List<WorkflowActionOperationRecord> Actions,
        long Generation);

    private sealed record JournalReadResult(
        WorkflowJournalReadStatus Status,
        JournalDocument? Document);

    private sealed record JournalDocument(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        List<WorkflowTriggerEventRecord>? TriggerEvents,
        List<WorkflowActionOperationRecord>? Actions);

    private sealed record JournalIntegrityPayload(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<WorkflowTriggerEventRecord> TriggerEvents,
        IReadOnlyList<WorkflowActionOperationRecord> Actions);
}
