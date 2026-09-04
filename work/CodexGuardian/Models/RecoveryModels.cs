using CodexGuardian.Infrastructure;
using CodexGuardian.ViewModels;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;

namespace CodexGuardian.Models;

public enum TaskHealth
{
    Unknown,
    NoHistory,
    Healthy,
    Processing,
    NeedsAttention,
    WaitingForIdle,
    WaitingForDesktop,
    CoolingDown,
    Recovering,
    Paused,
    ManualReview
}

public enum TaskVisualTone
{
    Neutral,
    Healthy,
    Active,
    Attention
}

public enum ConversationNavigationEntryKind
{
    Section,
    Conversation,
    Project
}

public sealed class ConversationNavigationEntry : ObservableObject
{
    private string _title = string.Empty;
    private string _detail = string.Empty;
    private int _count;
    private bool _isExpanded = true;
    private bool _isHealthy;
    private bool _isAttention;

    public required string Key { get; init; }

    public required ConversationNavigationEntryKind Kind { get; init; }

    public string? ConversationId { get; init; }

    public GuardianTaskItem? Task { get; init; }

    public bool IsArchived { get; init; }

    // Root navigation rows project only the small amount of task state needed for a scan.
    // The task itself remains the authoritative selection object.
    //
    // These two carry change notification and are deliberately excluded from the entry equality check.
    // As init-only properties they could only be updated by rebuilding the entry, which meant one
    // conversation starting or finishing a run rebuilt the whole collection — and a collection Reset
    // rebinds every virtualized row, which used to stop every running spinner in the list.
    public bool IsHealthy
    {
        get => _isHealthy;
        set => SetProperty(ref _isHealthy, value);
    }

    public bool IsSectionHeader => Kind == ConversationNavigationEntryKind.Section;

    public bool IsConversation => Kind == ConversationNavigationEntryKind.Conversation;

    public bool IsProject => Kind == ConversationNavigationEntryKind.Project;

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (SetProperty(ref _isExpanded, value))
            {
                OnPropertyChanged(nameof(ExpandGlyph));
            }
        }
    }

    public string ExpandGlyph => IsExpanded ? "\uE70D" : "\uE70E";


    public string Title
    {
        get => _title;
        set => SetProperty(ref _title, value ?? string.Empty);
    }

    public string Detail
    {
        get => _detail;
        set => SetProperty(ref _detail, value ?? string.Empty);
    }

    public int Count
    {
        get => _count;
        set => SetProperty(ref _count, value);
    }

    public bool IsAttention
    {
        get => _isAttention;
        set => SetProperty(ref _isAttention, value);
    }
}

public enum GuardianObservedPhase
{
    Unknown,
    Idle,
    Running,
    Reasoning,
    Tool,
    Reconnecting,
    Completed,
    Failed,
    Interrupted
}

public sealed record GuardianTaskObservation(
    GuardianObservedPhase Phase,
    string? ItemType,
    string? ErrorKind,
    int? HttpStatusCode,
    bool WillRetry,
    int? ReconnectAttempt,
    int? ReconnectMaxAttempts,
    DateTimeOffset ObservedAt);

public enum RecoveryActionKind
{
    None,
    ResendOriginal,
    SendContinue,
    ResendContinue
}

public sealed record RecoveryTransportCapabilities(
    RecoveryActionKind Action,
    bool SupportsExpectedFailedTurnCompareAndStart,
    bool SupportsExpectedFailedTurnOwnerValidation,
    bool SupportsReceiverIdempotency,
    bool PreservesStructuredOriginalInput,
    bool ReturnsCommittedTurnId,
    bool ExecutesThroughDesktopOwner,
    bool IsTrustedDesktopProtocol,
    bool SupportsNativeResend = false,
    bool SupportsProvenUnsentReplay = false,
    bool SupportsNativeInPlaceRetry = false)
{
    // In-place retry replaces the failed turn instead of appending a successor, so it never
    // returns a committed turn id. The owner's synchronous acknowledgement plus the expected-turn
    // compare-and-swap give the same guarantee: the request cannot land twice, and the successor
    // turn id is read back from the observed task state instead of the transport response.
    public bool IsInPlaceRetryConfirmable =>
        SupportsNativeInPlaceRetry &&
        SupportsExpectedFailedTurnCompareAndStart &&
        SupportsReceiverIdempotency;

    public bool HasCommittedTurnEvidence => ReturnsCommittedTurnId || IsInPlaceRetryConfirmable;

    public bool IsStrictAtomicRecoveryEligible =>
        Action != RecoveryActionKind.None &&
        SupportsExpectedFailedTurnCompareAndStart &&
        SupportsReceiverIdempotency &&
        HasCommittedTurnEvidence &&
        ExecutesThroughDesktopOwner &&
        IsTrustedDesktopProtocol &&
        (Action switch
        {
            RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue =>
                PreservesStructuredOriginalInput &&
                (SupportsNativeResend || SupportsProvenUnsentReplay),
            RecoveryActionKind.SendContinue => true,
            _ => false
        });

    public bool IsGuardedAutomaticRecoveryEligible =>
        Action != RecoveryActionKind.None &&
        ExecutesThroughDesktopOwner &&
        IsTrustedDesktopProtocol &&
        HasCommittedTurnEvidence &&
        (Action switch
        {
            RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue =>
                PreservesStructuredOriginalInput &&
                (SupportsNativeResend || SupportsProvenUnsentReplay),
            RecoveryActionKind.SendContinue => true,
            _ => false
        });

    public static RecoveryTransportCapabilities Unavailable(RecoveryActionKind action) =>
        new(action, false, false, false, false, false, false, false);
}

public enum RecoveryFailureKind
{
    None,
    StateChanged,
    AtomicGuardUnavailable,
    DesktopUnavailable,
    DesktopOwnerUnavailable,
    UserActive,
    DesktopIncompatible,
    PolicyChanged,
    TransportFailed
}

public sealed record ThreadSummary(
    string Id,
    string Name,
    string Preview,
    string Cwd,
    string Source,
    long CreatedAt,
    long UpdatedAt,
    bool IsSubAgent,
    bool IsEphemeral,
    string RuntimeStatus = "unknown",
    bool IsArchived = false,
    // Null means the observation surface did not expose a pin section (for example, an
    // isolated fixture). A non-null value is authoritative Codex Desktop state.
    bool? IsPinned = null);

public sealed record TurnSnapshot(
    string Id,
    string Status,
    string? ErrorMessage,
    string? ErrorCode,
    int? HttpStatusCode,
    string UserText,
    bool HasAttachments,
    bool HasAssistantOutput,
    bool HasWorkOutput,
    string OutputFingerprint,
    long? StartedAt,
    long? CompletedAt,
    string? RawUserInputJson = null,
    bool HasConfirmedLocalTerminal = false,
    IReadOnlyList<string>? UserMessageClientIds = null,
    bool HasUserMessage = false,
    bool HasFinalAssistantOutput = false,
    bool HasCommentaryOutput = false,
    bool HasReasoningOutput = false,
    bool HasToolActivity = false,
    bool HasAmbiguousActivity = false,
    bool HasCompleteItemEvidence = false,
    bool IsSingleTextUserInput = false)
{
    public bool HasReliableFinalOutput => HasFinalAssistantOutput;

    public bool HasKnownWorkEvidence =>
        HasAssistantOutput || HasWorkOutput || HasReasoningOutput || HasToolActivity;

    public bool HasReplayableInput =>
        HasUserMessage &&
        (!string.IsNullOrWhiteSpace(RawUserInputJson) || !string.IsNullOrWhiteSpace(UserText));
}

public sealed record RecoveryDecision(
    RecoveryActionKind Action,
    TaskHealth Health,
    string Reason,
    bool IsTransient)
{
    public static RecoveryDecision None(TaskHealth health, string reason) =>
        new(RecoveryActionKind.None, health, reason, false);
}

public sealed record RecoveryExecutionResult(
    bool Success,
    string Message,
    bool IsUserBlocked = false,
    string? NewTurnId = null,
    RecoveryFailureKind FailureKind = RecoveryFailureKind.None,
    string? OwnerRuntimeStatus = null)
{
    public static RecoveryExecutionResult Ok(string message, string? newTurnId = null) =>
        new(true, message, NewTurnId: newTurnId);

    public static RecoveryExecutionResult Failed(
        string message,
        bool isUserBlocked = false,
        RecoveryFailureKind failureKind = RecoveryFailureKind.TransportFailed) =>
        new(false, message, isUserBlocked, FailureKind: failureKind);

    // A busy owner is the one refusal expected to clear by itself, so it is worth telling apart from
    // a missing or incompatible owner even though all three share DesktopOwnerUnavailable: it is the
    // difference between "waiting" and "stuck", and only the caller that carries the owner's runtime
    // status can make that call.
    public static RecoveryExecutionResult OwnerBusy(string message, string ownerRuntimeStatus) =>
        new(
            false,
            message,
            FailureKind: RecoveryFailureKind.DesktopOwnerUnavailable,
            OwnerRuntimeStatus: string.IsNullOrWhiteSpace(ownerRuntimeStatus) ? "unknown" : ownerRuntimeStatus);
}

// A recovery that was dispatched and then blocked downstream looks exactly like a recovery that was
// never attempted: both leave the task sitting on a spinner. `Attempts` cannot close that gap
// because it is in-memory and resets whenever Guardian restarts, so a resend proven in the journal
// disappears from the UI. This ledger is the durable projection — `ConfirmedDispatches` counts the
// operations that actually reached the stock Desktop channel and returned a successor turn, so the
// activity panel can state "resent N times" across restarts, and `OwnerBusyRefusals` /
// `OwnerBusySince` say how long the current wait has been stuck behind a non-idle owner.
public sealed record GuardianRecoveryLedger(
    int ConfirmedDispatches,
    DateTimeOffset? LastConfirmedAt,
    int OwnerBusyRefusals = 0,
    DateTimeOffset? OwnerBusySince = null)
{
    public static readonly GuardianRecoveryLedger Empty = new(0, null);

    public bool HasEverDispatched => ConfirmedDispatches > 0;

    public bool IsOwnerBusyStalled => OwnerBusyRefusals > 0 && OwnerBusySince is not null;

    public TimeSpan OwnerBusyDuration(DateTimeOffset now) =>
        OwnerBusySince is { } since && now > since ? now - since : TimeSpan.Zero;
}

public sealed record GuardianTaskState(
    ThreadSummary Thread,
    TurnSnapshot? Turn,
    RecoveryDecision Decision,
    bool IsEnabled,
    TaskHealth Health,
    string StatusText,
    string LastEvent,
    int Attempts,
    DateTimeOffset? NextAttemptAt,
    bool IsGuardianManagedActivity = false,
    GuardianTaskObservation? Observation = null,
    FollowUpQueueRuntimeSnapshot? FollowUpQueue = null,
    GuardianRecoveryLedger? RecoveryLedger = null,
    bool IsRunningNow = false);

public sealed record GuardianSnapshotStatistics(
    int DisplayedSessionCount,
    int? TotalSessionCount = null,
    int? ArchivedSessionCount = null,
    int? FilteredSessionCount = null,
    bool? IsTruncated = null,
    bool IncludesArchived = false)
{
    public static GuardianSnapshotStatistics FromLegacy(
        int displayedSessionCount,
        bool includesArchived = false) =>
        new(Math.Max(0, displayedSessionCount), IncludesArchived: includesArchived);
}

public sealed record GuardianTaskSnapshot(
    IReadOnlyList<GuardianTaskState> States,
    GuardianSnapshotStatistics Statistics)
{
    public static GuardianTaskSnapshot FromLegacy(IReadOnlyList<GuardianTaskState> states)
    {
        ArgumentNullException.ThrowIfNull(states);
        return new(states, GuardianSnapshotStatistics.FromLegacy(states.Count));
    }
}

public enum FollowUpQueueVisualState
{
    Absent,
    Configured,
    Paused,
    Scheduled,
    WaitingForCompletion,
    Ready,
    Dispatching,
    Blocked,
    Uncertain,
    Exhausted
}

public enum FollowUpQueueRuntimeKind
{
    None,
    Configured,
    Paused,
    Scheduled,
    WaitingForCompletion,
    Ready,
    Dispatching,
    Uncertain,
    Blocked,
    Exhausted
}

public sealed record FollowUpQueueRuntimeSnapshot(
    FollowUpQueueRuntimeKind Kind,
    int TotalMessageCount,
    int EnabledMessageCount,
    int ConfirmedMessageCount,
    DateTimeOffset? NextScheduledAtUtc = null);

public sealed class GuardianTaskItem : ObservableObject
{
    private string _name = string.Empty;
    private string _preview = string.Empty;
    private string _cwd = string.Empty;
    private string _rawSource = string.Empty;
    private string _source = string.Empty;
    private DateTimeOffset _createdAt;
    private DateTimeOffset _updatedAt;
    private bool _isEnabled = true;
    private TaskHealth _health;
    private string _statusText = "等待首次扫描";
    private string _lastEvent = "暂无事件";
    private string _healthText = "未知";
    private string _protectionText = string.Empty;
    private string _observationText = string.Empty;
    private string _readyText = "已就绪";
    private int _attempts;
    private DateTimeOffset? _nextAttemptAt;
    private GuardianRecoveryLedger _recoveryLedger = GuardianRecoveryLedger.Empty;
    private string _recoveryLedgerText = string.Empty;
    private string _turnStatus = "unknown";
    private bool _isGuardianManagedActivity;
    private bool _isArchived;
    private bool _isProtectionAvailable;
    private bool _isConversationMutationPending;
    private bool _isConversationMutationUnavailable;
    private bool _isDeleteConfirmationOpen;
    private string _conversationMutationStatusText = string.Empty;
    private string _unarchiveActionHint = string.Empty;
    private string _deleteActionHint = string.Empty;
    private string _latestTurnId = string.Empty;
    private bool _canArmCompletionFollowUps;
    private string? _completionAnchorTurnId;
    private FollowUpQueueVisualState _followUpQueueState;
    private string _followUpQueueStatusText = string.Empty;
    private string _followUpQueueActionText = string.Empty;
    private int _followUpMessageCount;
    private FollowUpQueueRuntimeSnapshot? _followUpQueueRuntime;
    private bool _isPinned;
    private string _pinActionText = string.Empty;
    private string _projectName = string.Empty;
    private string _conversationSectionTitle = string.Empty;
    private bool _isDragSource;
    private bool _showDropBefore;
    private bool _showDropAfter;
    private bool _hasFinalAssistantOutput;
    private bool _isRunningNow;
    private bool? _codexPinnedState;

    public required string Id { get; init; }

    // The same opaque reference the log and the diagnostics stream use for this thread, so a value
    // read off the screen can be matched against `guardian.log` and `recovery-operations.json`
    // without ever putting a raw thread id — or a task title — in front of anyone. Surfaced through
    // automation only; the detail panel renders it at zero height.
    public string DiagnosticReference =>
        CodexGuardian.Services.GuardianLog.CreateThreadReference(Id) ?? string.Empty;

    public string LatestTurnId
    {
        get => _latestTurnId;
        set
        {
            if (SetProperty(ref _latestTurnId, value))
            {
                OnPropertyChanged(nameof(LatestTurnText));
            }
        }
    }

    // Absent turns arrive as an empty string, not null, so XAML TargetNullValue never fired and the row
    // rendered blank. There is a real case behind it: while a guarded turn is running the engine
    // deliberately reports no turn at all, so the panel needs a word for that rather than a gap.
    public string LatestTurnText => string.IsNullOrEmpty(_latestTurnId) ? "--" : _latestTurnId;

    public bool CanArmCompletionFollowUps
    {
        get => _canArmCompletionFollowUps;
        set => SetProperty(ref _canArmCompletionFollowUps, value);
    }

    public string? CompletionAnchorTurnId
    {
        get => _completionAnchorTurnId;
        set => SetProperty(ref _completionAnchorTurnId, value);
    }

    public FollowUpQueueVisualState FollowUpQueueState
    {
        get => _followUpQueueState;
        set => SetProperty(ref _followUpQueueState, value);
    }

    public string FollowUpQueueStatusText
    {
        get => _followUpQueueStatusText;
        set => SetProperty(ref _followUpQueueStatusText, value);
    }

    public string FollowUpQueueActionText
    {
        get => _followUpQueueActionText;
        set => SetProperty(ref _followUpQueueActionText, value);
    }

    public int FollowUpMessageCount
    {
        get => _followUpMessageCount;
        set => SetProperty(ref _followUpMessageCount, value);
    }

    public FollowUpQueueRuntimeSnapshot? FollowUpQueueRuntime
    {
        get => _followUpQueueRuntime;
        set => SetProperty(ref _followUpQueueRuntime, value);
    }

    public bool IsPinned
    {
        get => _isPinned;
        set => SetProperty(ref _isPinned, value);
    }

    public bool? CodexPinnedState
    {
        get => _codexPinnedState;
        set => SetProperty(ref _codexPinnedState, value);
    }

    public string PinActionText
    {
        get => _pinActionText;
        set => SetProperty(ref _pinActionText, value ?? string.Empty);
    }

    public string ProjectName
    {
        get => _projectName;
        set => SetProperty(ref _projectName, value ?? string.Empty);
    }

    public string ConversationSectionTitle
    {
        get => _conversationSectionTitle;
        set => SetProperty(ref _conversationSectionTitle, value ?? string.Empty);
    }

    public bool IsDragSource
    {
        get => _isDragSource;
        set => SetProperty(ref _isDragSource, value);
    }

    public bool ShowDropBefore
    {
        get => _showDropBefore;
        set => SetProperty(ref _showDropBefore, value);
    }

    public bool ShowDropAfter
    {
        get => _showDropAfter;
        set => SetProperty(ref _showDropAfter, value);
    }

    public void SetDragVisualState(bool isSource, bool showBefore, bool showAfter)
    {
        IsDragSource = isSource;
        ShowDropBefore = showBefore;
        ShowDropAfter = showAfter;
    }

    public required string Name
    {
        get => _name;
        set => SetProperty(ref _name, value);
    }

    public required string Preview
    {
        get => _preview;
        set => SetProperty(ref _preview, value);
    }

    public required string Cwd
    {
        get => _cwd;
        set => SetProperty(ref _cwd, value);
    }

    public required string RawSource
    {
        get => _rawSource;
        set => SetProperty(ref _rawSource, value);
    }

    public string Source
    {
        get => _source;
        set => SetProperty(ref _source, value);
    }

    public required DateTimeOffset CreatedAt
    {
        get => _createdAt;
        set => SetProperty(ref _createdAt, value);
    }

    public required DateTimeOffset UpdatedAt
    {
        get => _updatedAt;
        set
        {
            if (SetProperty(ref _updatedAt, value))
            {
                OnPropertyChanged(nameof(UpdatedText));
            }
        }
    }

    public bool IsEnabled
    {
        get => _isEnabled;
        set
        {
            if (SetProperty(ref _isEnabled, value))
            {
                EnabledChanged?.Invoke(this, value);
            }
        }
    }

    public void SetEnabledFromSnapshot(bool value) =>
        SetProperty(ref _isEnabled, value, nameof(IsEnabled));

    public bool IsArchived
    {
        get => _isArchived;
        set
        {
            if (SetProperty(ref _isArchived, value))
            {
                OnPropertyChanged(nameof(CanToggleProtection));
                OnPropertyChanged(nameof(VisualTone));
                OnPropertyChanged(nameof(ShouldPulseStatus));
            }
        }
    }

    public bool IsSubAgent { get; set; }

    public bool IsEphemeral { get; set; }

    public bool IsConversationMutationPending
    {
        get => _isConversationMutationPending;
        set
        {
            if (SetProperty(ref _isConversationMutationPending, value))
            {
                OnPropertyChanged(nameof(HasConversationMutationStatus));
            }
        }
    }

    public bool IsConversationMutationUnavailable
    {
        get => _isConversationMutationUnavailable;
        set => SetProperty(ref _isConversationMutationUnavailable, value);
    }

    public bool IsDeleteConfirmationOpen
    {
        get => _isDeleteConfirmationOpen;
        set => SetProperty(ref _isDeleteConfirmationOpen, value);
    }

    public string ConversationMutationStatusText
    {
        get => _conversationMutationStatusText;
        set
        {
            if (SetProperty(ref _conversationMutationStatusText, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(HasConversationMutationStatus));
            }
        }
    }

    public bool HasConversationMutationStatus =>
        !IsConversationMutationPending &&
        !string.IsNullOrWhiteSpace(ConversationMutationStatusText);

    public string UnarchiveActionHint
    {
        get => _unarchiveActionHint;
        set => SetProperty(ref _unarchiveActionHint, value ?? string.Empty);
    }

    public string DeleteActionHint
    {
        get => _deleteActionHint;
        set => SetProperty(ref _deleteActionHint, value ?? string.Empty);
    }

    internal string ConversationMutationStatusResourceKey { get; set; } = string.Empty;

    public bool IsProtectionAvailable
    {
        get => _isProtectionAvailable;
        set
        {
            if (SetProperty(ref _isProtectionAvailable, value))
            {
                OnPropertyChanged(nameof(CanToggleProtection));
            }
        }
    }

    public bool CanToggleProtection => !IsArchived && IsProtectionAvailable;

    public TaskHealth Health
    {
        get => _health;
        set
        {
            if (SetProperty(ref _health, value))
            {
                OnPropertyChanged(nameof(VisualTone));
                OnPropertyChanged(nameof(ShouldPulseStatus));
                OnPropertyChanged(nameof(IsRetryCountVisible));
                OnPropertyChanged(nameof(IsRunningSpinnerVisible));
            }
        }
    }

    public bool HasFinalAssistantOutput
    {
        get => _hasFinalAssistantOutput;
        set
        {
            if (SetProperty(ref _hasFinalAssistantOutput, value))
            {
                OnPropertyChanged(nameof(VisualTone));
                OnPropertyChanged(nameof(ShouldPulseStatus));
            }
        }
    }

    // Set from the local rollout watcher's task_started / task_complete events, so it flips within
    // roughly a tenth of a second of Codex itself starting or finishing the turn -- no app-server
    // round trip and no scan cycle in between.
    public bool IsRunningNow
    {
        get => _isRunningNow;
        set
        {
            if (SetProperty(ref _isRunningNow, value))
            {
                OnPropertyChanged(nameof(VisualTone));
                OnPropertyChanged(nameof(IsRunningSpinnerVisible));
            }
        }
    }

    // "Retrying" means Guardian owns the next move on a failed turn: it has tried at least once and is
    // either dispatching or parked on the desktop, the user, or a backoff. Those rows show the attempt
    // count instead of the spinner, by request -- a number that climbs is the honest signal for "still
    // fighting the 429", where a spinner only says "something is moving".
    public bool IsRetryCountVisible =>
        Attempts > 0 &&
        Health is TaskHealth.Recovering
            or TaskHealth.CoolingDown
            or TaskHealth.WaitingForDesktop
            or TaskHealth.WaitingForIdle
            or TaskHealth.NeedsAttention;

    public bool IsRunningSpinnerVisible => IsRunningNow && !IsRetryCountVisible;

    public string RetryCountText => Attempts.ToString(CultureInfo.InvariantCulture);

    // Three tones, by request: a task Codex is running right now is amber and spins, a task with a
    // final answer is green, everything else (including archived or unknown) is red. Running wins
    // over the other two because it is the one state that is about to change on its own -- judging a
    // turn that is still producing output by whether it has finished producing it says nothing.
    public TaskVisualTone VisualTone => IsRunningNow
        ? TaskVisualTone.Active
        : HasFinalAssistantOutput
            ? TaskVisualTone.Healthy
            : TaskVisualTone.Attention;

    // List rows use a static semantic aura. Per-row infinite storyboards made scrolling expensive.
    public bool ShouldPulseStatus => false;

    public string HealthText
    {
        get => _healthText;
        set => SetProperty(ref _healthText, value);
    }

    public string HealthResourceKey { get; set; } = "Health.Unknown";

    public string ProtectionText
    {
        get => _protectionText;
        set => SetProperty(ref _protectionText, value);
    }

    public GuardianTaskObservation? Observation { get; set; }

    public string ObservationText
    {
        get => _observationText;
        set => SetProperty(ref _observationText, value);
    }

    public bool IsGuardianManagedActivity
    {
        get => _isGuardianManagedActivity;
        set => SetProperty(ref _isGuardianManagedActivity, value);
    }

    public string RawStatusText { get; set; } = string.Empty;

    public string RawLastEvent { get; set; } = string.Empty;

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string LastEvent
    {
        get => _lastEvent;
        set => SetProperty(ref _lastEvent, value);
    }

    public int Attempts
    {
        get => _attempts;
        set
        {
            if (SetProperty(ref _attempts, value))
            {
                OnPropertyChanged(nameof(IsRetryCountVisible));
                OnPropertyChanged(nameof(IsRunningSpinnerVisible));
                OnPropertyChanged(nameof(RetryCountText));
            }
        }
    }

    public DateTimeOffset? NextAttemptAt
    {
        get => _nextAttemptAt;
        set
        {
            if (SetProperty(ref _nextAttemptAt, value))
            {
                OnPropertyChanged(nameof(NextAttemptText));
            }
        }
    }

    // The durable resend history, kept on the item so the view can state it without the user having to
    // read guardian.log. `RecoveryLedgerText` is composed by the view model because it is localized.
    public GuardianRecoveryLedger RecoveryLedger
    {
        get => _recoveryLedger;
        set => SetProperty(ref _recoveryLedger, value ?? GuardianRecoveryLedger.Empty);
    }

    public string RecoveryLedgerText
    {
        get => _recoveryLedgerText;
        set
        {
            if (SetProperty(ref _recoveryLedgerText, value))
            {
                OnPropertyChanged(nameof(HasRecoveryLedgerText));
            }
        }
    }

    public bool HasRecoveryLedgerText => !string.IsNullOrWhiteSpace(_recoveryLedgerText);

    public string TurnStatus
    {
        get => _turnStatus;
        set
        {
            if (SetProperty(ref _turnStatus, value))
            {
                OnPropertyChanged(nameof(VisualTone));
                OnPropertyChanged(nameof(ShouldPulseStatus));
            }
        }
    }

    public string UpdatedText => UpdatedAt.LocalDateTime.ToString(
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "zh" ? "MM月dd日 HH:mm" : "MMM dd, HH:mm",
        CultureInfo.CurrentUICulture);

    public string ReadyText
    {
        get => _readyText;
        set
        {
            if (SetProperty(ref _readyText, value))
            {
                OnPropertyChanged(nameof(NextAttemptText));
            }
        }
    }

    public string NextAttemptText => NextAttemptAt is null
        ? "--"
        : NextAttemptAt.Value <= DateTimeOffset.Now
            ? ReadyText
            : NextAttemptAt.Value.LocalDateTime.ToString("HH:mm:ss");

    public void RefreshLocalizedText()
    {
        OnPropertyChanged(nameof(UpdatedText));
        OnPropertyChanged(nameof(NextAttemptText));
    }

    public event EventHandler<bool>? EnabledChanged;
}

public sealed record FollowUpAutomationModeOption(
    bool UseWorkflowAutomation,
    string DisplayName,
    bool IsAvailable);

public sealed record WorkflowTriggerOption(WorkflowTriggerKind Kind, string DisplayName);

public sealed record RecoveryCountingModeOption(
    RecoveryCountingMode Mode,
    string DisplayName);

public sealed record WorkflowDestinationOption(
    WorkflowDestinationKind Kind,
    string DisplayName,
    bool IsAvailable,
    string StatusText);

public sealed record WorkflowConversationOption(
    string Id,
    string Name,
    string StatusText,
    bool IsSelectable,
    bool IsArchived,
    bool IsBusy,
    bool IsMissing);

public sealed record WorkflowPresetOption(
    string OwnerConversationId,
    string MessageId,
    string Preview,
    string StatusText,
    bool IsSelectable,
    bool IsMissing);

public sealed class FollowUpMessageItem : ObservableObject, IDataErrorInfo
{
    private string _message = string.Empty;
    private FollowUpTriggerKind _trigger;
    private DateTime? _scheduledDateLocal;
    private string _scheduledTimeText = string.Empty;
    private string _maximumErrorRetriesText = string.Empty;
    private bool _retryIndefinitely;
    private bool _isEnabled = true;
    private bool _useWorkflowAutomation;
    private WorkflowTriggerKind _workflowTrigger = WorkflowTriggerKind.ConversationCompletedNormally;
    private DateTime? _workflowScheduledDateLocal;
    private string _workflowScheduledTimeText = string.Empty;
    private string? _workflowSourceConversationId;
    private string? _workflowSourcePresetMessageId;
    private WorkflowDestinationKind _workflowDestination = WorkflowDestinationKind.CurrentConversation;
    private string? _workflowTargetConversationId;
    private bool _workflowEnableTargetProtection;
    private string _workflowTriggerText = string.Empty;
    private string _workflowDestinationText = string.Empty;
    private string _workflowActionText = string.Empty;
    private string _workflowRuleStatusText = string.Empty;
    private string _workflowRuleId = string.Empty;
    private string _workflowRuleDigest = string.Empty;
    private int _workflowRuleRevision;
    private bool _workflowRuleBindingCurrent;
    private bool _isEditing;
    private int _order;
    private bool _isDragSource;
    private bool _showDropBefore;
    private bool _showDropAfter;
    private int _maximumAttachmentCount = 20;
    private long _maximumAttachmentBytes = 500L * 1024 * 1024;
    private readonly HashSet<AttachmentItemViewModel> _observedAttachments = [];

    public FollowUpMessageItem()
    {
        Attachments.CollectionChanged += OnAttachmentsChanged;
    }

    public required string Id { get; init; }

    public string Message
    {
        get => _message;
        set
        {
            if (SetProperty(ref _message, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(MessagePreview));
                OnPropertyChanged(nameof(ContentPreview));
            }
        }
    }

    public string MessagePreview
    {
        get
        {
            var normalized = string.Join(
                " ",
                Message.Split(
                    ['\r', '\n', '\t'],
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            return normalized.Length <= 120 ? normalized : normalized[..119] + "…";
        }
    }

    public string ContentPreview => MessagePreview.Length > 0
        ? MessagePreview
        : Attachments.FirstOrDefault() is { } first
            ? Attachments.Count == 1
                ? first.OriginalFileName
                : $"{first.OriginalFileName} +{Attachments.Count - 1}"
            : string.Empty;

    public ObservableCollection<AttachmentItemViewModel> Attachments { get; } = [];

    public ObservableCollection<WorkflowPresetOption> WorkflowSourcePresetOptions { get; } = [];

    public bool HasAttachments => Attachments.Count > 0;

    public int AttachmentCount => Attachments.Count;

    public long AttachmentByteLength => Attachments.Sum(attachment => attachment.ByteLength);

    public string AttachmentLimitStatus =>
        $"{AttachmentCount}/{_maximumAttachmentCount} · " +
        $"{AttachmentItemViewModel.FormatByteLength(AttachmentByteLength)}/" +
        AttachmentItemViewModel.FormatByteLength(_maximumAttachmentBytes);

    public bool HasAttachmentLimitError =>
        AttachmentCount > _maximumAttachmentCount ||
        AttachmentByteLength > _maximumAttachmentBytes;

    public bool HasInvalidAttachments =>
        HasAttachmentLimitError ||
        Attachments.Any(attachment => attachment.HasValidationError);

    internal bool ConfigureAttachmentLimits(AttachmentLimitSettings limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        _maximumAttachmentCount = Math.Max(1, limits.MaximumAttachmentsPerMessage);
        _maximumAttachmentBytes = Math.Max(1, limits.MaximumBytesPerMessage);
        RefreshAttachmentProjection();
        return !HasAttachmentLimitError;
    }

    internal void RefreshAttachmentText()
    {
        foreach (var attachment in Attachments)
        {
            attachment.RefreshLocalizedText();
        }

        OnPropertyChanged(nameof(AttachmentLimitStatus));
    }

    public FollowUpTriggerKind Trigger
    {
        get => _trigger;
        set
        {
            if (SetProperty(ref _trigger, value))
            {
                OnPropertyChanged(nameof(IsScheduled));
                OnPropertyChanged(nameof(ScheduleSummary));
                if (value == FollowUpTriggerKind.ScheduledAt && ScheduledDateLocal is null)
                {
                    var suggested = DateTime.Now.AddHours(1);
                    ScheduledDateLocal = suggested.Date;
                    ScheduledTimeText = suggested.ToString("HH:mm", CultureInfo.InvariantCulture);
                }
            }
        }
    }

    public bool IsScheduled => Trigger == FollowUpTriggerKind.ScheduledAt;

    public DateTime? ScheduledDateLocal
    {
        get => _scheduledDateLocal;
        set
        {
            if (SetProperty(ref _scheduledDateLocal, value?.Date))
            {
                OnPropertyChanged(nameof(ScheduleSummary));
            }
        }
    }

    public string ScheduledTimeText
    {
        get => _scheduledTimeText;
        set
        {
            if (SetProperty(ref _scheduledTimeText, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(ScheduleSummary));
            }
        }
    }

    public string ScheduleSummary => ScheduledDateLocal is { } date
        ? $"{date:yyyy-MM-dd} {ScheduledTimeText.Trim()}".TrimEnd()
        : ScheduledTimeText.Trim();

    public string MaximumErrorRetriesText
    {
        get => _maximumErrorRetriesText;
        set
        {
            if (SetProperty(ref _maximumErrorRetriesText, value?.Trim() ?? string.Empty))
            {
                OnPropertyChanged(nameof(EffectiveMaximumErrorRetries));
                OnPropertyChanged(nameof(HasValidMaximumErrorRetries));
            }
        }
    }

    public bool RetryIndefinitely
    {
        get => _retryIndefinitely;
        set
        {
            if (SetProperty(ref _retryIndefinitely, value))
            {
                OnPropertyChanged(nameof(IsFiniteRetry));
                OnPropertyChanged(nameof(EffectiveMaximumErrorRetries));
                OnPropertyChanged(nameof(HasValidMaximumErrorRetries));
            }
        }
    }

    public bool IsFiniteRetry => !RetryIndefinitely;

    public int EffectiveMaximumErrorRetries =>
        TryGetMaximumErrorRetries(out var configured)
            ? FollowUpRetryPolicy.GetEffectiveMaximumErrorRetries(configured)
            : FollowUpRetryPolicy.DefaultMaximumErrorRetries;

    public bool HasValidMaximumErrorRetries => TryGetMaximumErrorRetries(out _);

    string IDataErrorInfo.Error => string.Empty;

    string IDataErrorInfo.this[string columnName] =>
        string.Equals(columnName, nameof(MaximumErrorRetriesText), StringComparison.Ordinal) &&
        !HasValidMaximumErrorRetries
            ? "Invalid error retry count."
            : string.Empty;

    public bool TryGetMaximumErrorRetries(out int? configured)
    {
        configured = null;
        if (RetryIndefinitely)
        {
            return true;
        }

        if (MaximumErrorRetriesText.Length == 0)
        {
            return true;
        }

        if (!int.TryParse(
                MaximumErrorRetriesText,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsed) ||
            parsed < 0 ||
            parsed > FollowUpRetryPolicy.MaximumErrorRetriesLimit)
        {
            return false;
        }

        configured = parsed;
        return true;
    }

    public bool IsEnabled
    {
        get => _isEnabled;
        set => SetProperty(ref _isEnabled, value);
    }

    public bool UseWorkflowAutomation
    {
        get => _useWorkflowAutomation;
        set
        {
            if (SetProperty(ref _useWorkflowAutomation, value))
            {
                OnPropertyChanged(nameof(IsLegacyQueueMessage));
                OnPropertyChanged(nameof(HasWorkflowSummary));
            }
        }
    }

    public bool IsLegacyQueueMessage => !UseWorkflowAutomation;

    public bool HasWorkflowSummary => UseWorkflowAutomation;

    public WorkflowTriggerKind WorkflowTrigger
    {
        get => _workflowTrigger;
        set
        {
            if (SetProperty(ref _workflowTrigger, value))
            {
                OnPropertyChanged(nameof(IsWorkflowScheduled));
                OnPropertyChanged(nameof(WorkflowNeedsSourceConversation));
                OnPropertyChanged(nameof(WorkflowNeedsSourcePreset));
            }
        }
    }

    public bool IsWorkflowScheduled => WorkflowTrigger == WorkflowTriggerKind.ScheduledAt;

    public DateTime? WorkflowScheduledDateLocal
    {
        get => _workflowScheduledDateLocal;
        set
        {
            if (SetProperty(ref _workflowScheduledDateLocal, value?.Date))
            {
                OnPropertyChanged(nameof(WorkflowScheduleSummary));
            }
        }
    }

    public string WorkflowScheduledTimeText
    {
        get => _workflowScheduledTimeText;
        set
        {
            if (SetProperty(ref _workflowScheduledTimeText, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(WorkflowScheduleSummary));
            }
        }
    }

    public string WorkflowScheduleSummary => WorkflowScheduledDateLocal is { } date
        ? $"{date:yyyy-MM-dd} {WorkflowScheduledTimeText.Trim()}".TrimEnd()
        : WorkflowScheduledTimeText.Trim();

    public bool WorkflowNeedsSourceConversation =>
        WorkflowTrigger is WorkflowTriggerKind.ConversationCompletedNormally or
            WorkflowTriggerKind.PresetDispatchConfirmed;

    public bool WorkflowNeedsSourcePreset =>
        WorkflowTrigger == WorkflowTriggerKind.PresetDispatchConfirmed;

    public string? WorkflowSourceConversationId
    {
        get => _workflowSourceConversationId;
        set => SetProperty(ref _workflowSourceConversationId, NormalizeOptionalId(value));
    }

    public string? WorkflowSourcePresetMessageId
    {
        get => _workflowSourcePresetMessageId;
        set => SetProperty(ref _workflowSourcePresetMessageId, NormalizeOptionalId(value));
    }

    public WorkflowDestinationKind WorkflowDestination
    {
        get => _workflowDestination;
        set
        {
            if (SetProperty(ref _workflowDestination, value))
            {
                OnPropertyChanged(nameof(WorkflowTargetsCurrentConversation));
                OnPropertyChanged(nameof(WorkflowTargetsExistingConversation));
                OnPropertyChanged(nameof(WorkflowTargetsNewConversation));
            }
        }
    }

    public bool WorkflowTargetsCurrentConversation =>
        WorkflowDestination == WorkflowDestinationKind.CurrentConversation;

    public bool WorkflowTargetsExistingConversation =>
        WorkflowDestination == WorkflowDestinationKind.ExistingConversation;

    public bool WorkflowTargetsNewConversation =>
        WorkflowDestination == WorkflowDestinationKind.NewConversation;

    public string? WorkflowTargetConversationId
    {
        get => _workflowTargetConversationId;
        set => SetProperty(ref _workflowTargetConversationId, NormalizeOptionalId(value));
    }

    public bool WorkflowEnableTargetProtection
    {
        get => _workflowEnableTargetProtection;
        set
        {
            if (SetProperty(ref _workflowEnableTargetProtection, value))
            {
                OnPropertyChanged(nameof(WorkflowActionCount));
            }
        }
    }

    public int WorkflowActionCount => WorkflowEnableTargetProtection ? 2 : 1;

    public string WorkflowTriggerText
    {
        get => _workflowTriggerText;
        set => SetProperty(ref _workflowTriggerText, value ?? string.Empty);
    }

    public string WorkflowDestinationText
    {
        get => _workflowDestinationText;
        set => SetProperty(ref _workflowDestinationText, value ?? string.Empty);
    }

    public string WorkflowActionText
    {
        get => _workflowActionText;
        set => SetProperty(ref _workflowActionText, value ?? string.Empty);
    }

    public string WorkflowRuleStatusText
    {
        get => _workflowRuleStatusText;
        set
        {
            if (SetProperty(ref _workflowRuleStatusText, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(HasWorkflowRuleStatus));
            }
        }
    }

    public bool HasWorkflowRuleStatus => !string.IsNullOrWhiteSpace(WorkflowRuleStatusText);

    public string WorkflowRuleId
    {
        get => _workflowRuleId;
        set => SetProperty(ref _workflowRuleId, value ?? string.Empty);
    }

    public string WorkflowRuleDigest
    {
        get => _workflowRuleDigest;
        set => SetProperty(ref _workflowRuleDigest, value ?? string.Empty);
    }

    public int WorkflowRuleRevision
    {
        get => _workflowRuleRevision;
        set => SetProperty(ref _workflowRuleRevision, Math.Max(0, value));
    }

    public bool WorkflowRuleBindingCurrent
    {
        get => _workflowRuleBindingCurrent;
        set => SetProperty(ref _workflowRuleBindingCurrent, value);
    }

    public bool HasStoredWorkflowRule => WorkflowRuleRevision > 0 && WorkflowRuleId.Length > 0;

    public bool IsEditing
    {
        get => _isEditing;
        set => SetProperty(ref _isEditing, value);
    }

    public int Order
    {
        get => _order;
        set
        {
            if (SetProperty(ref _order, value))
            {
                OnPropertyChanged(nameof(DisplayOrder));
            }
        }
    }

    public int DisplayOrder => Order + 1;

    public bool IsDragSource
    {
        get => _isDragSource;
        set => SetProperty(ref _isDragSource, value);
    }

    public bool ShowDropBefore
    {
        get => _showDropBefore;
        set => SetProperty(ref _showDropBefore, value);
    }

    public bool ShowDropAfter
    {
        get => _showDropAfter;
        set => SetProperty(ref _showDropAfter, value);
    }

    private static string? NormalizeOptionalId(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private void OnAttachmentsChanged(object? sender, NotifyCollectionChangedEventArgs eventArgs)
    {
        SynchronizeAttachmentSubscriptions();
        RefreshAttachmentProjection();
    }

    private void SynchronizeAttachmentSubscriptions()
    {
        foreach (var attachment in _observedAttachments
                     .Where(attachment => !Attachments.Contains(attachment))
                     .ToArray())
        {
            attachment.PropertyChanged -= OnAttachmentPropertyChanged;
            _observedAttachments.Remove(attachment);
        }

        foreach (var attachment in Attachments)
        {
            if (_observedAttachments.Add(attachment))
            {
                attachment.PropertyChanged += OnAttachmentPropertyChanged;
            }
        }
    }

    private void OnAttachmentPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (string.IsNullOrEmpty(eventArgs.PropertyName) ||
            eventArgs.PropertyName is nameof(AttachmentItemViewModel.ValidationState) or
                nameof(AttachmentItemViewModel.HasValidationError))
        {
            OnPropertyChanged(nameof(HasInvalidAttachments));
        }
    }

    private void RefreshAttachmentProjection()
    {
        OnPropertyChanged(nameof(ContentPreview));
        OnPropertyChanged(nameof(HasAttachments));
        OnPropertyChanged(nameof(AttachmentCount));
        OnPropertyChanged(nameof(AttachmentByteLength));
        OnPropertyChanged(nameof(AttachmentLimitStatus));
        OnPropertyChanged(nameof(HasAttachmentLimitError));
        OnPropertyChanged(nameof(HasInvalidAttachments));
    }
}

public sealed record FollowUpTriggerOption(FollowUpTriggerKind Kind, string DisplayName);
