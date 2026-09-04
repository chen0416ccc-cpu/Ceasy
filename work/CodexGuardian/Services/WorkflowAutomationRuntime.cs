using CodexGuardian.Models;
using System.Threading.Channels;

namespace CodexGuardian.Services;

internal enum WorkflowAutomationRuntimeStatus
{
    Healthy,
    Empty,
    RulesUnavailable,
    JournalUnavailable,
    ConservativeRecovery
}

internal sealed record WorkflowAutomationRuntimeResult(
    WorkflowAutomationRuntimeStatus Status,
    IReadOnlyList<WorkflowTriggeredRuleResult> TriggeredRules,
    IReadOnlyList<WorkflowActionExecutionResult> ReconciledActions,
    int ReplayedConfirmations,
    DateTimeOffset? NextScheduledWakeAtUtc,
    string Message);

internal enum WorkflowAutomationResultOrigin
{
    Startup,
    ScheduledWake,
    ConversationCompletion,
    PresetDispatchConfirmation,
    PolicyOrCapabilityReconciliation,
    OverflowReconciliation
}

internal sealed class WorkflowAutomationAdapterStateChangedEventArgs(
    WorkflowAutomationResultOrigin origin,
    WorkflowAutomationRuntimeResult? result,
    Exception? failure) : EventArgs
{
    internal WorkflowAutomationResultOrigin Origin { get; } = origin;

    internal WorkflowAutomationRuntimeResult? Result { get; } = result;

    internal Exception? Failure { get; } = failure;
}

internal sealed class WorkflowAutomationRuntime
{
    private readonly WorkflowRuleStore _rules;
    private readonly WorkflowOperationJournal _journal;
    private readonly WorkflowTriggerCoordinator _coordinator;
    private readonly IWorkflowRuleActionRunner _runner;
    private readonly SemaphoreSlim _gate = new(1, 1);

    internal WorkflowAutomationRuntime(
        WorkflowRuleStore rules,
        WorkflowOperationJournal journal,
        WorkflowTriggerCoordinator coordinator,
        IWorkflowRuleActionRunner runner)
    {
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
    }

    internal Task<WorkflowAutomationRuntimeResult> ReconcileStartupAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default) =>
        SerializeAsync(
            token => ReconcileAllCoreAsync(
                RequireUtc(observedAtUtc, nameof(observedAtUtc)),
                startup: true,
                token),
            cancellationToken);

    internal Task<WorkflowAutomationRuntimeResult> ReconcilePendingAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default) =>
        SerializeAsync(
            token => ReconcileAllCoreAsync(
                RequireUtc(observedAtUtc, nameof(observedAtUtc)),
                startup: false,
                token),
            cancellationToken);

    internal Task<WorkflowAutomationRuntimeResult> ProcessScheduledWakeAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default) =>
        SerializeAsync(
            token => ProcessScheduledWakeCoreAsync(
                RequireUtc(observedAtUtc, nameof(observedAtUtc)),
                token),
            cancellationToken);

    internal Task<WorkflowAutomationRuntimeResult> ProcessConversationCompletedAsync(
        WorkflowAuthoritativeCompletionEventArgs completion,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(completion);
        return SerializeAsync(
            token => ProcessConversationCompletedCoreAsync(completion, token),
            cancellationToken);
    }

    internal Task<WorkflowAutomationRuntimeResult> ProcessPresetDispatchConfirmedAsync(
        WorkflowActionOperationRecord action,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        return SerializeAsync(
            token => ProcessPresetDispatchConfirmedCoreAsync(action, token),
            cancellationToken);
    }

    internal Task<DateTimeOffset?> FindNextScheduledWakeAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default) =>
        SerializeAsync(
            async token =>
            {
                var authority = await ReadAuthorityAsync(token).ConfigureAwait(false);
                return authority.Status is WorkflowAutomationRuntimeStatus.Healthy or
                    WorkflowAutomationRuntimeStatus.Empty
                    ? FindNextScheduledWake(
                        authority.Rules,
                        authority.Journal,
                        RequireUtc(observedAtUtc, nameof(observedAtUtc)))
                    : null;
            },
            cancellationToken);

    private async Task<WorkflowAutomationRuntimeResult> ReconcileAllCoreAsync(
        DateTimeOffset observedAtUtc,
        bool startup,
        CancellationToken cancellationToken)
    {
        var authority = await ReadAuthorityAsync(cancellationToken).ConfigureAwait(false);
        if (authority.Status == WorkflowAutomationRuntimeStatus.Empty)
        {
            return Result(authority.Status, message: "No workflow rules are configured.");
        }

        if (authority.Status is WorkflowAutomationRuntimeStatus.RulesUnavailable or
            WorkflowAutomationRuntimeStatus.JournalUnavailable)
        {
            return Result(authority.Status, message: authority.Message);
        }

        if (authority.Status == WorkflowAutomationRuntimeStatus.ConservativeRecovery)
        {
            var reconciled = await ReconcileConservativeUncertainAsync(
                    authority.Rules,
                    authority.Journal,
                    cancellationToken)
                .ConfigureAwait(false);
            return new WorkflowAutomationRuntimeResult(
                WorkflowAutomationRuntimeStatus.ConservativeRecovery,
                Array.Empty<WorkflowTriggeredRuleResult>(),
                reconciled,
                ReplayedConfirmations: 0,
                NextScheduledWakeAtUtc: null,
                startup
                    ? "Startup recovered conservative workflow state; only existing uncertain actions were reconciled."
                    : "Conservative workflow state permits receipt reconciliation only.");
        }

        var triggered = new List<WorkflowTriggeredRuleResult>();
        foreach (var triggerEvent in authority.Journal.TriggerEvents
                     .OrderBy(value => value.ObservedAtUtc)
                     .ThenBy(value => value.TriggerEventId, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            triggered.AddRange(await _coordinator.ResumeDurableTriggerAsync(
                    authority.Rules,
                    triggerEvent,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        var refreshed = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        var replayed = await CascadeConfirmedAsync(
                triggered,
                refreshed.Actions.Where(IsConfirmedPresetSend),
                cancellationToken)
            .ConfigureAwait(false);
        var scheduled = await _coordinator.ProcessScheduledAsync(
                authority.Rules,
                observedAtUtc,
                cancellationToken)
            .ConfigureAwait(false);
        triggered.AddRange(scheduled);
        replayed += await CascadeConfirmedAsync(
                triggered,
                ReadConfirmedActions(scheduled),
                cancellationToken)
            .ConfigureAwait(false);

        refreshed = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        return new WorkflowAutomationRuntimeResult(
            WorkflowAutomationRuntimeStatus.Healthy,
            triggered.AsReadOnly(),
            Array.Empty<WorkflowActionExecutionResult>(),
            replayed,
            FindNextScheduledWake(authority.Rules, refreshed, observedAtUtc),
            startup
                ? "Workflow startup reconciliation completed."
                : "Pending workflow reconciliation completed.");
    }

    private async Task<WorkflowAutomationRuntimeResult> ProcessScheduledWakeCoreAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken)
    {
        var authority = await ReadAuthorityAsync(cancellationToken).ConfigureAwait(false);
        if (authority.Status != WorkflowAutomationRuntimeStatus.Healthy)
        {
            return Result(authority.Status, message: authority.Message);
        }

        var triggered = (await _coordinator.ProcessScheduledAsync(
                authority.Rules,
                observedAtUtc,
                cancellationToken)
            .ConfigureAwait(false)).ToList();
        var replayed = await CascadeConfirmedAsync(
                triggered,
                ReadConfirmedActions(triggered),
                cancellationToken)
            .ConfigureAwait(false);
        var refreshed = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        return new WorkflowAutomationRuntimeResult(
            WorkflowAutomationRuntimeStatus.Healthy,
            triggered.AsReadOnly(),
            Array.Empty<WorkflowActionExecutionResult>(),
            replayed,
            FindNextScheduledWake(authority.Rules, refreshed, observedAtUtc),
            "The scheduled workflow wake was processed.");
    }

    private async Task<WorkflowAutomationRuntimeResult> ProcessConversationCompletedCoreAsync(
        WorkflowAuthoritativeCompletionEventArgs completion,
        CancellationToken cancellationToken)
    {
        var observedAtUtc = RequireUtc(completion.ObservedAtUtc, nameof(completion));
        var authority = await ReadAuthorityAsync(cancellationToken).ConfigureAwait(false);
        if (authority.Status != WorkflowAutomationRuntimeStatus.Healthy)
        {
            return Result(authority.Status, message: authority.Message);
        }

        var triggered = (await _coordinator.ProcessConversationCompletedAsync(
                authority.Rules,
                completion.Conversation,
                completion.CompletedTurn,
                observedAtUtc,
                cancellationToken)
            .ConfigureAwait(false)).ToList();
        var replayed = await CascadeConfirmedAsync(
                triggered,
                ReadConfirmedActions(triggered),
                cancellationToken)
            .ConfigureAwait(false);

        var pending = await ResumePendingTargetAsync(
                authority.Rules,
                completion.Conversation.Id,
                cancellationToken)
            .ConfigureAwait(false);
        triggered.AddRange(pending);
        replayed += await CascadeConfirmedAsync(
                triggered,
                ReadConfirmedActions(pending),
                cancellationToken)
            .ConfigureAwait(false);

        var refreshed = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        return new WorkflowAutomationRuntimeResult(
            WorkflowAutomationRuntimeStatus.Healthy,
            triggered.AsReadOnly(),
            Array.Empty<WorkflowActionExecutionResult>(),
            replayed,
            FindNextScheduledWake(authority.Rules, refreshed, observedAtUtc),
            "The authoritative normal-completion event was processed.");
    }

    private async Task<WorkflowAutomationRuntimeResult> ProcessPresetDispatchConfirmedCoreAsync(
        WorkflowActionOperationRecord action,
        CancellationToken cancellationToken)
    {
        var confirmedAtUtc = RequireUtc(action.UpdatedAtUtc, nameof(action));
        var authority = await ReadAuthorityAsync(cancellationToken).ConfigureAwait(false);
        if (authority.Status != WorkflowAutomationRuntimeStatus.Healthy)
        {
            return Result(authority.Status, message: authority.Message);
        }

        var triggered = (await _coordinator.ProcessPresetDispatchConfirmedAsync(
                authority.Rules,
                action.ActionOperationId,
                confirmedAtUtc,
                cancellationToken)
            .ConfigureAwait(false)).ToList();
        var replayed = await CascadeConfirmedAsync(
                triggered,
                ReadConfirmedActions(triggered),
                cancellationToken)
            .ConfigureAwait(false);
        var refreshed = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        return new WorkflowAutomationRuntimeResult(
            WorkflowAutomationRuntimeStatus.Healthy,
            triggered.AsReadOnly(),
            Array.Empty<WorkflowActionExecutionResult>(),
            replayed,
            FindNextScheduledWake(authority.Rules, refreshed, confirmedAtUtc),
            "The confirmed preset-dispatch event was processed.");
    }

    private async Task<IReadOnlyList<WorkflowTriggeredRuleResult>> ResumePendingTargetAsync(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        string targetConversationId,
        CancellationToken cancellationToken)
    {
        var journal = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        var pendingTriggerIds = journal.Actions.Where(action =>
                (action.State is WorkflowActionOperationState.Prepared or
                    WorkflowActionOperationState.Retryable or
                    WorkflowActionOperationState.Uncertain) &&
                string.Equals(
                    action.TargetConversationId,
                    targetConversationId,
                    StringComparison.OrdinalIgnoreCase))
            .Select(action => action.TriggerEventId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (pendingTriggerIds.Count == 0)
        {
            return Array.Empty<WorkflowTriggeredRuleResult>();
        }

        var results = new List<WorkflowTriggeredRuleResult>();
        foreach (var triggerEvent in journal.TriggerEvents.Where(value =>
                     pendingTriggerIds.Contains(value.TriggerEventId)))
        {
            results.AddRange(await _coordinator.ResumeDurableTriggerAsync(
                    rules,
                    triggerEvent,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return results.AsReadOnly();
    }

    private async Task<IReadOnlyList<WorkflowActionExecutionResult>>
        ReconcileConservativeUncertainAsync(
            IReadOnlyList<WorkflowRuleDefinition> rules,
            WorkflowJournalSnapshot journal,
            CancellationToken cancellationToken)
    {
        var currentRules = rules.ToDictionary(
            rule => (rule.RuleId, rule.Revision, rule.DefinitionDigest),
            rule => rule,
            WorkflowRuleIdentityComparer.Instance);
        var triggers = journal.TriggerEvents.ToDictionary(
            trigger => trigger.TriggerEventId,
            StringComparer.OrdinalIgnoreCase);
        var results = new List<WorkflowActionExecutionResult>();
        foreach (var action in journal.Actions.Where(action =>
                     action.State == WorkflowActionOperationState.Uncertain)
                 .OrderBy(action => action.CreatedAtUtc)
                 .ThenBy(action => action.ActionIndex))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!currentRules.TryGetValue(
                    (action.RuleId, action.RuleRevision, action.DefinitionDigest),
                    out var rule) ||
                !triggers.TryGetValue(action.TriggerEventId, out var triggerEvent) ||
                !PreviousActionsAreConfirmed(journal.Actions, action))
            {
                continue;
            }

            results.Add(await _runner.RunAsync(
                    rule,
                    triggerEvent,
                    action.ActionIndex,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return results.AsReadOnly();
    }

    private async Task<int> CascadeConfirmedAsync(
        List<WorkflowTriggeredRuleResult> aggregate,
        IEnumerable<WorkflowActionOperationRecord> seeds,
        CancellationToken cancellationToken)
    {
        var queue = new Queue<WorkflowActionOperationRecord>(seeds.Where(IsConfirmedPresetSend));
        var processed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var replayed = 0;
        while (queue.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = queue.Dequeue();
            if (!processed.Add(source.ActionOperationId))
            {
                continue;
            }

            var ruleSnapshot = await _rules.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!CanExecuteRules(ruleSnapshot))
            {
                break;
            }

            var nested = await _coordinator.ProcessPresetDispatchConfirmedAsync(
                    ruleSnapshot.Rules,
                    source.ActionOperationId,
                    source.UpdatedAtUtc,
                    cancellationToken)
                .ConfigureAwait(false);
            replayed++;
            aggregate.AddRange(nested);
            foreach (var confirmed in ReadConfirmedActions(nested))
            {
                queue.Enqueue(confirmed);
            }
        }

        return replayed;
    }

    private async Task<WorkflowRuntimeAuthority> ReadAuthorityAsync(
        CancellationToken cancellationToken)
    {
        var rules = await _rules.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (rules.ReadStatus == WorkflowRuleStoreReadStatus.Missing && rules.Rules.Count == 0)
        {
            return new WorkflowRuntimeAuthority(
                WorkflowAutomationRuntimeStatus.Empty,
                Array.Empty<WorkflowRuleDefinition>(),
                EmptyJournal(),
                "No workflow rules are configured.");
        }

        if (!CanReadRules(rules))
        {
            return new WorkflowRuntimeAuthority(
                WorkflowAutomationRuntimeStatus.RulesUnavailable,
                Array.Empty<WorkflowRuleDefinition>(),
                EmptyJournal(),
                "Workflow rules are corrupt, unsupported, or structurally invalid.");
        }

        var journal = await _journal.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (journal.ReadStatus is WorkflowJournalReadStatus.Corrupted or
            WorkflowJournalReadStatus.UnsupportedSchema)
        {
            return new WorkflowRuntimeAuthority(
                WorkflowAutomationRuntimeStatus.JournalUnavailable,
                rules.Rules,
                journal,
                "The workflow operation journal is corrupt or unsupported.");
        }

        if (rules.RequiresConservativeRecovery ||
            rules.ReadStatus == WorkflowRuleStoreReadStatus.RecoveredFromBackup ||
            journal.RequiresConservativeRecovery ||
            journal.ReadStatus == WorkflowJournalReadStatus.RecoveredFromBackup)
        {
            return new WorkflowRuntimeAuthority(
                WorkflowAutomationRuntimeStatus.ConservativeRecovery,
                rules.Rules,
                journal,
                "Workflow authority recovered conservatively; new operations are blocked.");
        }

        return new WorkflowRuntimeAuthority(
            WorkflowAutomationRuntimeStatus.Healthy,
            rules.Rules,
            journal,
            "Workflow authority is healthy.");
    }

    private static DateTimeOffset? FindNextScheduledWake(
        IReadOnlyList<WorkflowRuleDefinition> rules,
        WorkflowJournalSnapshot journal,
        DateTimeOffset observedAtUtc)
    {
        var existing = journal.TriggerEvents.Select(value => value.TriggerEventId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        DateTimeOffset? next = null;
        foreach (var rule in rules.Where(rule =>
                     rule.IsEnabled &&
                     rule.Trigger.Kind == WorkflowTriggerKind.ScheduledAt &&
                     rule.Trigger.ScheduledAtUtc is not null))
        {
            var scheduledAtUtc = rule.Trigger.ScheduledAtUtc!.Value.ToUniversalTime();
            if (scheduledAtUtc < rule.ActivatedAtUtc)
            {
                continue;
            }

            var occurrence = "scheduled:" + scheduledAtUtc.UtcTicks;
            var triggerEventId = WorkflowOperationJournal.CreateTriggerEventId(
                WorkflowTriggerKind.ScheduledAt,
                rule.OwnerConversationId,
                rule.RuleId,
                rule.RuleId,
                occurrence);
            if (existing.Contains(triggerEventId))
            {
                continue;
            }

            var candidate = scheduledAtUtc <= observedAtUtc ? observedAtUtc : scheduledAtUtc;
            next = next is null || candidate < next ? candidate : next;
        }

        return next;
    }

    private async Task<TResult> SerializeAsync<TResult>(
        Func<CancellationToken, Task<TResult>> operation,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await operation(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private static IReadOnlyList<WorkflowActionOperationRecord> ReadConfirmedActions(
        IEnumerable<WorkflowTriggeredRuleResult> results) =>
        results.SelectMany(result => result.Actions)
            .Where(action => action.Status == WorkflowActionExecutionStatus.Confirmed)
            .Select(action => action.Record)
            .Where(action => action is not null && IsConfirmedPresetSend(action))
            .Cast<WorkflowActionOperationRecord>()
            .ToArray();

    private static bool IsConfirmedPresetSend(WorkflowActionOperationRecord action) =>
        action.State == WorkflowActionOperationState.Confirmed &&
        action.ActionKind == WorkflowActionKind.SendPresetMessage &&
        action.GeneratedTurnId is not null;

    private static bool PreviousActionsAreConfirmed(
        IReadOnlyList<WorkflowActionOperationRecord> actions,
        WorkflowActionOperationRecord candidate)
    {
        for (var index = 0; index < candidate.ActionIndex; index++)
        {
            if (!actions.Any(action =>
                    action.ActionIndex == index &&
                    action.State == WorkflowActionOperationState.Confirmed &&
                    string.Equals(
                        action.RuleId,
                        candidate.RuleId,
                        StringComparison.OrdinalIgnoreCase) &&
                    action.RuleRevision == candidate.RuleRevision &&
                    string.Equals(
                        action.TriggerEventId,
                        candidate.TriggerEventId,
                        StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        return true;
    }

    private static bool CanReadRules(WorkflowRuleStoreSnapshot snapshot) =>
        (snapshot.ReadStatus is WorkflowRuleStoreReadStatus.Healthy or
            WorkflowRuleStoreReadStatus.RecoveredFromBackup) &&
        !snapshot.Validation.Issues.Any(issue =>
            issue.Code != WorkflowRuleValidationIssueCode.NewConversationUnavailable);

    private static bool CanExecuteRules(WorkflowRuleStoreSnapshot snapshot) =>
        snapshot.ReadStatus == WorkflowRuleStoreReadStatus.Healthy &&
        !snapshot.RequiresConservativeRecovery &&
        !snapshot.Validation.Issues.Any(issue =>
            issue.Code != WorkflowRuleValidationIssueCode.NewConversationUnavailable);

    private static WorkflowJournalSnapshot EmptyJournal() => new(
        WorkflowJournalReadStatus.Missing,
        Generation: 0,
        RequiresConservativeRecovery: false,
        TriggerEvents: Array.Empty<WorkflowTriggerEventRecord>(),
        Actions: Array.Empty<WorkflowActionOperationRecord>());

    private static WorkflowAutomationRuntimeResult Result(
        WorkflowAutomationRuntimeStatus status,
        string message) => new(
        status,
        Array.Empty<WorkflowTriggeredRuleResult>(),
        Array.Empty<WorkflowActionExecutionResult>(),
        ReplayedConfirmations: 0,
        NextScheduledWakeAtUtc: null,
        message);

    private static DateTimeOffset RequireUtc(DateTimeOffset value, string parameterName)
    {
        if (value == default)
        {
            throw new ArgumentException("A workflow runtime observation time is required.", parameterName);
        }

        return value.ToUniversalTime();
    }

    private sealed record WorkflowRuntimeAuthority(
        WorkflowAutomationRuntimeStatus Status,
        IReadOnlyList<WorkflowRuleDefinition> Rules,
        WorkflowJournalSnapshot Journal,
        string Message);

    private sealed class WorkflowRuleIdentityComparer :
        IEqualityComparer<(string RuleId, int Revision, string Digest)>
    {
        internal static WorkflowRuleIdentityComparer Instance { get; } = new();

        public bool Equals(
            (string RuleId, int Revision, string Digest) x,
            (string RuleId, int Revision, string Digest) y) =>
            x.Revision == y.Revision &&
            string.Equals(x.RuleId, y.RuleId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Digest, y.Digest, StringComparison.Ordinal);

        public int GetHashCode((string RuleId, int Revision, string Digest) value) =>
            HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(value.RuleId),
                value.Revision,
                StringComparer.Ordinal.GetHashCode(value.Digest));
    }
}

internal sealed class WorkflowAutomationEventAdapter : IAsyncDisposable
{
    internal const int QueueCapacity = 256;

    private readonly WorkflowAutomationRuntime _runtime;
    private readonly IWorkflowAuthoritativeCompletionSource _completions;
    private readonly IWorkflowPresetDispatchConfirmationSource _confirmations;
    private readonly Channel<WorkflowAutomationSignal> _signals;
    private readonly object _stateSync = new();
    private CancellationTokenSource? _lifetime;
    private Task? _worker;
    private DateTimeOffset? _nextScheduledWakeAtUtc;
    private WorkflowAutomationRuntimeResult? _lastResult;
    private Exception? _lastFailure;
    private int _overflowed;
    private int _started;
    private int _disposed;

    internal WorkflowAutomationEventAdapter(
        WorkflowAutomationRuntime runtime,
        IWorkflowAuthoritativeCompletionSource completions,
        IWorkflowPresetDispatchConfirmationSource confirmations,
        int queueCapacity = QueueCapacity)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _completions = completions ?? throw new ArgumentNullException(nameof(completions));
        _confirmations = confirmations ?? throw new ArgumentNullException(nameof(confirmations));
        if (queueCapacity <= 0 || queueCapacity > QueueCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(queueCapacity));
        }

        _signals = Channel.CreateBounded<WorkflowAutomationSignal>(new BoundedChannelOptions(
            queueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    internal event EventHandler<WorkflowAutomationAdapterStateChangedEventArgs>? StateChanged;

    internal DateTimeOffset? NextScheduledWakeAtUtc
    {
        get
        {
            lock (_stateSync)
            {
                return _nextScheduledWakeAtUtc;
            }
        }
    }

    internal Exception? LastFailure
    {
        get
        {
            lock (_stateSync)
            {
                return _lastFailure;
            }
        }
    }

    internal WorkflowAutomationRuntimeResult? LastResult
    {
        get
        {
            lock (_stateSync)
            {
                return _lastResult;
            }
        }
    }

    internal async Task StartAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The workflow event adapter is already started.");
        }

        _lifetime = new CancellationTokenSource();
        _completions.CompletionObserved += OnCompletionObserved;
        _confirmations.PresetDispatchConfirmed += OnPresetDispatchConfirmed;
        _worker = RunAsync(_lifetime.Token);
        await EnqueueAndWaitAsync(
                new WorkflowAutomationSignal(
                    WorkflowAutomationSignalKind.Startup,
                    RequireUtc(observedAtUtc),
                    Completion: null,
                    ConfirmedAction: null,
                    CreateCompletion()),
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal Task<WorkflowAutomationRuntimeResult> NotifyScheduledWakeAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default) =>
        EnqueueAndWaitAsync(
            new WorkflowAutomationSignal(
                WorkflowAutomationSignalKind.ScheduledWake,
                RequireUtc(observedAtUtc),
                Completion: null,
                ConfirmedAction: null,
                CreateCompletion()),
            cancellationToken);

    internal Task<WorkflowAutomationRuntimeResult> NotifyPolicyOrCapabilityChangedAsync(
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default) =>
        EnqueueAndWaitAsync(
            new WorkflowAutomationSignal(
                WorkflowAutomationSignalKind.Reconcile,
                RequireUtc(observedAtUtc),
                Completion: null,
                ConfirmedAction: null,
                CreateCompletion()),
            cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _completions.CompletionObserved -= OnCompletionObserved;
        _confirmations.PresetDispatchConfirmed -= OnPresetDispatchConfirmed;
        _signals.Writer.TryComplete();
        _lifetime?.Cancel();
        if (_worker is not null)
        {
            try
            {
                await _worker.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _lifetime?.Dispose();
    }

    private void OnCompletionObserved(
        object? sender,
        WorkflowAuthoritativeCompletionEventArgs eventArgs)
    {
        _ = sender;
        TryEnqueueEvent(new WorkflowAutomationSignal(
            WorkflowAutomationSignalKind.Completion,
            eventArgs.ObservedAtUtc,
            eventArgs,
            ConfirmedAction: null,
            CompletionSource: null));
    }

    private void OnPresetDispatchConfirmed(
        object? sender,
        WorkflowPresetDispatchConfirmedEventArgs eventArgs)
    {
        _ = sender;
        TryEnqueueEvent(new WorkflowAutomationSignal(
            WorkflowAutomationSignalKind.PresetConfirmed,
            eventArgs.Action.UpdatedAtUtc,
            Completion: null,
            eventArgs.Action,
            CompletionSource: null));
    }

    private void TryEnqueueEvent(WorkflowAutomationSignal signal)
    {
        if (Volatile.Read(ref _disposed) != 0 || !_signals.Writer.TryWrite(signal))
        {
            Interlocked.Exchange(ref _overflowed, 1);
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        await foreach (var signal in _signals.Reader.ReadAllAsync(cancellationToken)
                           .ConfigureAwait(false))
        {
            await ProcessSignalAsync(signal, cancellationToken).ConfigureAwait(false);
            if (Interlocked.Exchange(ref _overflowed, 0) != 0)
            {
                try
                {
                    SetResult(
                        await _runtime.ReconcilePendingAsync(
                                DateTimeOffset.UtcNow,
                                cancellationToken)
                            .ConfigureAwait(false),
                        WorkflowAutomationResultOrigin.OverflowReconciliation);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    SetFailure(
                        exception,
                        WorkflowAutomationResultOrigin.OverflowReconciliation);
                }
            }
        }
    }

    private async Task ProcessSignalAsync(
        WorkflowAutomationSignal signal,
        CancellationToken cancellationToken)
    {
        try
        {
            WorkflowAutomationRuntimeResult result;
            WorkflowAutomationResultOrigin origin;
            switch (signal.Kind)
            {
                case WorkflowAutomationSignalKind.Startup:
                    origin = WorkflowAutomationResultOrigin.Startup;
                    result = await _runtime.ReconcileStartupAsync(
                            signal.ObservedAtUtc,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
                case WorkflowAutomationSignalKind.ScheduledWake:
                    origin = WorkflowAutomationResultOrigin.ScheduledWake;
                    result = await _runtime.ProcessScheduledWakeAsync(
                            signal.ObservedAtUtc,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
                case WorkflowAutomationSignalKind.Completion:
                    origin = WorkflowAutomationResultOrigin.ConversationCompletion;
                    result = await _runtime.ProcessConversationCompletedAsync(
                            signal.Completion!,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
                case WorkflowAutomationSignalKind.PresetConfirmed:
                    origin = WorkflowAutomationResultOrigin.PresetDispatchConfirmation;
                    result = await _runtime.ProcessPresetDispatchConfirmedAsync(
                            signal.ConfirmedAction!,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
                case WorkflowAutomationSignalKind.Reconcile:
                    origin = WorkflowAutomationResultOrigin.PolicyOrCapabilityReconciliation;
                    result = await _runtime.ReconcilePendingAsync(
                            signal.ObservedAtUtc,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
                default:
                    throw new InvalidDataException("The workflow automation signal is invalid.");
            }

            SetResult(result, origin);
            signal.CompletionSource?.TrySetResult(result);
        }
        catch (Exception exception) when (
            exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            SetFailure(exception, ToResultOrigin(signal.Kind));
            signal.CompletionSource?.TrySetException(exception);
        }
    }

    private async Task<WorkflowAutomationRuntimeResult> EnqueueAndWaitAsync(
        WorkflowAutomationSignal signal,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Volatile.Read(ref _started) == 0)
        {
            throw new InvalidOperationException("The workflow event adapter is not started.");
        }

        await _signals.Writer.WriteAsync(signal, cancellationToken).ConfigureAwait(false);
        return await signal.CompletionSource!.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private void SetResult(
        WorkflowAutomationRuntimeResult result,
        WorkflowAutomationResultOrigin origin)
    {
        lock (_stateSync)
        {
            _nextScheduledWakeAtUtc = result.NextScheduledWakeAtUtc;
            _lastResult = result;
            _lastFailure = null;
        }

        EventSubscriberDispatcher.Invoke(
            StateChanged,
            this,
            new WorkflowAutomationAdapterStateChangedEventArgs(origin, result, failure: null));
    }

    private void SetFailure(
        Exception exception,
        WorkflowAutomationResultOrigin origin)
    {
        lock (_stateSync)
        {
            _lastFailure = exception;
        }

        EventSubscriberDispatcher.Invoke(
            StateChanged,
            this,
            new WorkflowAutomationAdapterStateChangedEventArgs(
                origin,
                result: null,
                failure: exception));
    }

    private static WorkflowAutomationResultOrigin ToResultOrigin(
        WorkflowAutomationSignalKind kind) => kind switch
    {
        WorkflowAutomationSignalKind.Startup => WorkflowAutomationResultOrigin.Startup,
        WorkflowAutomationSignalKind.ScheduledWake => WorkflowAutomationResultOrigin.ScheduledWake,
        WorkflowAutomationSignalKind.Completion => WorkflowAutomationResultOrigin.ConversationCompletion,
        WorkflowAutomationSignalKind.PresetConfirmed =>
            WorkflowAutomationResultOrigin.PresetDispatchConfirmation,
        WorkflowAutomationSignalKind.Reconcile =>
            WorkflowAutomationResultOrigin.PolicyOrCapabilityReconciliation,
        _ => throw new InvalidDataException("The workflow automation signal is invalid.")
    };

    private static TaskCompletionSource<WorkflowAutomationRuntimeResult> CreateCompletion() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static DateTimeOffset RequireUtc(DateTimeOffset value)
    {
        if (value == default)
        {
            throw new ArgumentException("A workflow event time is required.", nameof(value));
        }

        return value.ToUniversalTime();
    }

    private enum WorkflowAutomationSignalKind
    {
        Startup,
        ScheduledWake,
        Completion,
        PresetConfirmed,
        Reconcile
    }

    private sealed record WorkflowAutomationSignal(
        WorkflowAutomationSignalKind Kind,
        DateTimeOffset ObservedAtUtc,
        WorkflowAuthoritativeCompletionEventArgs? Completion,
        WorkflowActionOperationRecord? ConfirmedAction,
        TaskCompletionSource<WorkflowAutomationRuntimeResult>? CompletionSource);
}
