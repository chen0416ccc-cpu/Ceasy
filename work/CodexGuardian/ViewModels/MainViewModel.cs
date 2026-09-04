using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using CodexGuardian.Infrastructure;
using CodexGuardian.Localization;
using CodexGuardian.Models;
using CodexGuardian.Services;

namespace CodexGuardian.ViewModels;

public enum ConversationScopeKind
{
    All,
    NeedsAttention,
    Archived
}

public sealed class MainViewModel : ObservableObject, IAsyncDisposable
{
    private const string PinnedConversationGroupKey = "__codexfree_pinned__";
    private const string RecentConversationGroupKey = "__codexfree_recent__";
    private const string ArchivedConversationGroupKey = "__codexfree_archived__";
    private const string ProjectConversationGroupPrefix = "__codexfree_project__:";
    private static readonly ConcurrentDictionary<string, string> RecognizedProjectRootCache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly SettingsService _settingsService;
    private readonly StartupService _startupService;
    private readonly GuardianLog _log;
    private readonly GuardianEngine _engine;
    private readonly AppServerClient _appServer;
    private readonly DesktopIpcClient _desktopIpc;
    private readonly RecoveryClassifier _classifier;
    private readonly SystemSleepGuard? _sleepGuard;
    // Null in isolated preview mode. The preview renders the shell for screenshots and must not reach the
    // network, and a null service is a stronger guarantee of that than a flag every call site has to remember.
    private readonly UpdateCheckService? _updateCheck;
    private readonly LocalizationService _localization;
    private readonly IEnhancedObservationStatus? _enhancedObservationStatus;
    private readonly bool _previewIsolationMode;
    private readonly FollowUpAttachmentCompositionService? _attachmentComposition;
    private readonly AttachmentDraftAuthority? _attachmentDraftAuthority;
    private readonly ConversationMutationService? _conversationMutations;
    private readonly WorkflowRuleStore _workflowRuleStore;
    private readonly WorkflowAutomationHost? _workflowAutomationHost;
    private readonly IWorkflowLineageReader? _workflowLineageReader;
    private readonly CancellationTokenSource _workflowLineageLifetime = new();
    // Its own lifetime rather than the lineage one: cancelling on dispose has to abandon an in-flight HTTP
    // request, and borrowing a token named for something else would make that dependency invisible.
    private readonly CancellationTokenSource _updateCheckLifetime = new();
    private readonly SemaphoreSlim _workflowLineageRefreshGate = new(1, 1);
    private readonly ResettableObservableCollection<WorkflowLineageDisplayItem>
        _workflowLineageItems = [];
    private readonly Dictionary<string, WorkflowLineageDisplayItem> _workflowLineageByRef =
        new(StringComparer.Ordinal);
    private readonly HashSet<string> _uncertainConversationMutations = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _protectionInitializationInFlight =
        new(StringComparer.OrdinalIgnoreCase);
    private long _attachmentDraftVersion;
    private readonly Dictionary<string, GuardianTaskItem> _tasksById = new(StringComparer.Ordinal);
    private readonly Dictionary<string, bool> _conversationSectionExpansion =
        new(StringComparer.Ordinal);
    private readonly object _snapshotDispatchSync = new();
    private readonly SemaphoreSlim _saveGate = new(1, 1);
    private readonly SemaphoreSlim _automaticRecoveryMutationGate = new(1, 1);
    private int _startupPublished;
    private int _disposeStarted;
    private int _automaticRecoveryIntentVersion;
    private bool _automaticRecoveryDesired;
    private readonly AsyncRelayCommand _scanNowCommand;
    private readonly AsyncRelayCommand _probeDesktopChannelCommand;
    private readonly AsyncRelayCommand _runReadOnlyDiagnosticCommand;
    private readonly RelayCommand _addFollowUpMessageCommand;
    private readonly RelayCommand _removeFollowUpMessageCommand;
    private readonly RelayCommand _editFollowUpMessageCommand;
    private readonly RelayCommand _closeFollowUpMessageEditorCommand;
    private readonly RelayCommand _requestFollowUpAttachmentPickerCommand;
    private readonly RelayCommand _removeFollowUpAttachmentCommand;
    private readonly RelayCommand _openFollowUpEditorCommand;
    private readonly RelayCommand _backToTasksCommand;
    private readonly RelayCommand _setConversationScopeCommand;
    private readonly RelayCommand _clearTaskSearchCommand;
    private readonly RelayCommand _toggleConversationPinCommand;
    private readonly RelayCommand _openConversationGroupCommand;
    private readonly RelayCommand _toggleConversationSectionCommand;
    private readonly RelayCommand _backToConversationNavigationCommand;
    private readonly RelayCommand _toggleThemeCommand;
    private readonly AsyncRelayCommand _saveFollowUpMessagesCommand;
    private readonly AsyncRelayCommand _refreshWorkflowLineageCommand;
    private readonly AsyncRelayCommand _checkForUpdateCommand;
    private readonly RelayCommand _unarchiveConversationCommand;
    private readonly RelayCommand _requestDeleteConversationCommand;
    private readonly RelayCommand _confirmDeleteConversationCommand;
    private readonly RelayCommand _cancelDeleteConversationCommand;
    private bool _isMonitoring;
    private bool _isOnline;
    private bool _isDesktopConnected;
    private string _selectedPage = "Tasks";
    private string _rawEngineState = "Starting";
    private string _rawEngineDetail = "Preparing local services...";
    private string _engineState = string.Empty;
    private string _engineDetail = string.Empty;
    private string _keepAliveStatusText = string.Empty;
    private string _keepAliveSearchText = string.Empty;
    private bool _keepAliveShowHeldOnly;
    private string _keepAliveHeldCountText = "0";
    private string _keepAliveNextDueText = "--";
    private string _keepAliveNextDueDetailText = string.Empty;
    private string _keepAliveWaitingCountText = "0";
    private string _keepAliveSentinelStateText = string.Empty;
    // The countdown ticks off these three, not off a fresh engine snapshot. Re-capturing the runtime once a
    // second would walk the whole state cache to redraw one string, and this app does not poll.
    private DateTimeOffset? _keepAliveNextDueAt;
    private string _keepAliveNextDueBlockedReason = string.Empty;
    private DispatcherTimer? _keepAliveCountdownTimer;
    // The update check's conclusion, kept here so the brand mark and the settings page read the same thing.
    // Version text rather than the result record: nothing in the UI needs the parsed Version. The state is
    // held raw and localized on read, the way the engine state is, so switching language re-renders it.
    private bool _hasUpdateAvailable;
    private string _updateLatestVersionText = string.Empty;
    private string _updateStatusText = string.Empty;
    private UpdateCheckDisplayState _updateState = UpdateCheckDisplayState.Unknown;
    private string _lastScanText = string.Empty;
    private string _serverVersion = string.Empty;
    private string _diagnosticTitle = string.Empty;
    private string _diagnosticDetail = string.Empty;
    private string _diagnosticRawError = string.Empty;
    private string _diagnosticTaskName = "—";
    private string _diagnosticCheckedAt = "—";
    private string _diagnosticSource = "—";
    private int _taskCount;
    private int _protectedCount;
    private int _attentionCount;
    private int _recoveryCount;
    private string? _lastResendLedgerSignature;
    private GuardianSnapshotStatistics _snapshotStatistics = GuardianSnapshotStatistics.FromLegacy(0);
    private string _taskSearchText = string.Empty;
    private bool _showArchived;
    private ConversationScopeKind _conversationScope = ConversationScopeKind.All;
    private string? _conversationGroupKey;
    private string _conversationGroupTitle = string.Empty;
    private int _conversationNavigationMotionRevision;
    private DiagnosticViewState _diagnosticState = DiagnosticViewState.Idle;
    private RecoveryActionKind _diagnosticAction = RecoveryActionKind.None;
    private string _diagnosticFailureMessage = string.Empty;
    private string? _diagnosticSourceKey;
    private GuardianTaskSnapshot? _pendingSnapshot;
    private bool _snapshotDispatchScheduled;
    private GuardianTaskItem? _selectedTask;
    private FollowUpMessageItem? _selectedFollowUpMessage;
    private bool _selectedFollowUpsEnabled = true;
    private string _followUpEditorStatus = string.Empty;
    private bool _isFollowUpEditorDirty;
    private bool _isLoadingFollowUpEditor;
    private ConversationMutationUiLease? _activeConversationMutation;
    private WorkflowRuleStoreSnapshot? _workflowRuleSnapshot;
    private bool _workflowRuleLoadFailed;
    private WorkflowLineageSnapshot? _workflowLineageSnapshot;
    private string _workflowLineageStatusText = string.Empty;
    private string _workflowLineageEmptyText = string.Empty;
    private int _workflowLineageDirty = 1;
    private long _workflowLineageHighestGeneration;

    public MainViewModel(
        AppSettings settings,
        SettingsService settingsService,
        StartupService startupService,
        GuardianLog log,
        GuardianEngine engine,
        AppServerClient appServer,
        DesktopIpcClient desktopIpc,
        RecoveryClassifier classifier,
        LocalizationService localization,
        IEnhancedObservationStatus? enhancedObservationStatus = null,
        bool previewIsolationMode = false)
        : this(
            settings,
            settingsService,
            startupService,
            log,
            engine,
            appServer,
            desktopIpc,
            classifier,
            localization,
            enhancedObservationStatus,
            previewIsolationMode,
            attachmentComposition: null,
            attachmentDraftAuthority: null,
            conversationMutations: null)
    {
    }

    internal MainViewModel(
        AppSettings settings,
        SettingsService settingsService,
        StartupService startupService,
        GuardianLog log,
        GuardianEngine engine,
        AppServerClient appServer,
        DesktopIpcClient desktopIpc,
        RecoveryClassifier classifier,
        LocalizationService localization,
        IEnhancedObservationStatus? enhancedObservationStatus,
        bool previewIsolationMode,
        FollowUpAttachmentCompositionService? attachmentComposition = null,
        AttachmentDraftAuthority? attachmentDraftAuthority = null,
        ConversationMutationService? conversationMutations = null,
        WorkflowRuleStore? workflowRuleStore = null,
        WorkflowRuleStoreSnapshot? workflowRuleSnapshot = null,
        WorkflowAutomationHost? workflowAutomationHost = null,
        IWorkflowLineageReader? workflowLineageReader = null)
    {
        Settings = settings;
        _settingsService = settingsService;
        _startupService = startupService;
        _log = log;
        _engine = engine;
        _appServer = appServer;
        _desktopIpc = desktopIpc;
        _classifier = classifier;
        _localization = localization;
        _enhancedObservationStatus = enhancedObservationStatus;
        _previewIsolationMode = previewIsolationMode;
        _attachmentComposition = attachmentComposition;
        _attachmentDraftAuthority = attachmentDraftAuthority;
        _workflowRuleStore = workflowRuleStore ?? new WorkflowRuleStore(settingsService.DataDirectory);
        _workflowRuleSnapshot = workflowRuleSnapshot;
        _workflowAutomationHost = workflowAutomationHost;
        _workflowLineageReader = workflowLineageReader;
        if (_previewIsolationMode && conversationMutations is not null)
        {
            throw new InvalidOperationException(
                "Isolated preview cannot construct a conversation mutation service.");
        }

        if (_previewIsolationMode &&
            (workflowAutomationHost is not null || workflowLineageReader is not null))
        {
            throw new InvalidOperationException(
                "Isolated preview cannot construct live workflow runtime dependencies.");
        }

        _conversationMutations = conversationMutations;

        // Not a constructor parameter: every call site would have to thread it through, and the only
        // thing it needs is a dispatcher that outlives the app. Isolated preview and headless test runs
        // get no guard at all — neither should touch the machine's real power state.
        _sleepGuard = _previewIsolationMode || Application.Current?.Dispatcher is not { } dispatcher
            ? null
            : new SystemSleepGuard(log, dispatcher);

        // Same reasoning, and the same isolation: the preview must not open a socket, and a headless test run
        // has nothing to show an update badge on.
        _updateCheck = _previewIsolationMode ? null : new UpdateCheckService(log);

        if (_previewIsolationMode)
        {
            Settings.MonitoringEnabled = false;
            Settings.MonitorOnly = true;
            Settings.AutomaticRecoveryEnabled = false;
            Settings.GlobalProtectionEnabled = false;
            Settings.MinimizeToTray = false;
            Settings.StartWithWindows = false;
        }

        if (_previewIsolationMode || !_desktopIpc.SupportsGuardedAutomaticRecovery)
        {
            _engine.SetMonitorOnly(true);
        }

        _automaticRecoveryDesired = Settings.AutomaticRecoveryEnabled;

        TasksView = CollectionViewSource.GetDefaultView(Tasks);
        TasksView.Filter = MatchesTaskFilter;
        _scanNowCommand = new AsyncRelayCommand(ScanNowAsync, CanUseLiveControls);
        _probeDesktopChannelCommand = new AsyncRelayCommand(ProbeDesktopChannelAsync, CanUseLiveControls);
        _runReadOnlyDiagnosticCommand = new AsyncRelayCommand(RunReadOnlyDiagnosticAsync, CanUseLiveControls);
        _addFollowUpMessageCommand = new RelayCommand(AddFollowUpMessage, CanEditFollowUps);
        _removeFollowUpMessageCommand = new RelayCommand(
            RemoveFollowUpMessage,
            parameter => CanEditFollowUps() &&
                         (parameter is FollowUpMessageItem || SelectedFollowUpMessage is not null));
        _editFollowUpMessageCommand = new RelayCommand(
            EditFollowUpMessage,
            parameter => CanEditFollowUps() && parameter is FollowUpMessageItem);
        _closeFollowUpMessageEditorCommand = new RelayCommand(
            CloseFollowUpMessageEditor,
            parameter => parameter is FollowUpMessageItem);
        _requestFollowUpAttachmentPickerCommand = new RelayCommand(
            RequestFollowUpAttachmentPicker,
            CanRequestFollowUpAttachments);
        _removeFollowUpAttachmentCommand = new RelayCommand(
            RemoveFollowUpAttachment,
            CanRemoveFollowUpAttachment);
        _openFollowUpEditorCommand = new RelayCommand(
            OpenFollowUpEditor,
            parameter => parameter is GuardianTaskItem);
        _backToTasksCommand = new RelayCommand(
            BackToTasks,
            () => IsFollowUpDetailPage);
        _setConversationScopeCommand = new RelayCommand(SetConversationScope);
        _clearTaskSearchCommand = new RelayCommand(
            () => TaskSearchText = string.Empty,
            () => HasTaskSearchText);
        _toggleConversationPinCommand = new RelayCommand(
            ToggleConversationPin,
            parameter => parameter is GuardianTaskItem { IsArchived: false });
        _openConversationGroupCommand = new RelayCommand(
            OpenConversationGroup,
            parameter => parameter is ConversationNavigationEntry);
        _toggleConversationSectionCommand = new RelayCommand(
            ToggleConversationSection,
            parameter => parameter is ConversationNavigationEntry { IsSectionHeader: true });
        _backToConversationNavigationCommand = new RelayCommand(
            BackToConversationNavigation,
            () => !IsConversationNavigationRoot);
        _toggleThemeCommand = new RelayCommand(ToggleTheme);
        _saveFollowUpMessagesCommand = new AsyncRelayCommand(SaveFollowUpMessagesAsync, CanSaveFollowUps);
        _refreshWorkflowLineageCommand = new AsyncRelayCommand(
            () => RefreshWorkflowLineageAsync(force: true),
            () => _workflowLineageReader is not null);
        _unarchiveConversationCommand = new RelayCommand(
            ExecuteUnarchiveConversation,
            CanUnarchiveConversation);
        _requestDeleteConversationCommand = new RelayCommand(
            RequestDeleteConversation,
            CanRequestDeleteConversation);
        _confirmDeleteConversationCommand = new RelayCommand(
            ConfirmDeleteConversation,
            CanConfirmDeleteConversation);
        _cancelDeleteConversationCommand = new RelayCommand(
            CancelDeleteConversation,
            CanCancelDeleteConversation);

        ScanNowCommand = _scanNowCommand;
        ProbeDesktopChannelCommand = _probeDesktopChannelCommand;
        RunReadOnlyDiagnosticCommand = _runReadOnlyDiagnosticCommand;
        AddFollowUpMessageCommand = _addFollowUpMessageCommand;
        RemoveFollowUpMessageCommand = _removeFollowUpMessageCommand;
        EditFollowUpMessageCommand = _editFollowUpMessageCommand;
        CloseFollowUpMessageEditorCommand = _closeFollowUpMessageEditorCommand;
        RequestFollowUpAttachmentPickerCommand = _requestFollowUpAttachmentPickerCommand;
        RemoveFollowUpAttachmentCommand = _removeFollowUpAttachmentCommand;
        OpenFollowUpEditorCommand = _openFollowUpEditorCommand;
        BackToTasksCommand = _backToTasksCommand;
        SetConversationScopeCommand = _setConversationScopeCommand;
        ClearTaskSearchCommand = _clearTaskSearchCommand;
        ToggleConversationPinCommand = _toggleConversationPinCommand;
        OpenConversationGroupCommand = _openConversationGroupCommand;
        ToggleConversationSectionCommand = _toggleConversationSectionCommand;
        BackToConversationNavigationCommand = _backToConversationNavigationCommand;
        ToggleThemeCommand = _toggleThemeCommand;
        SaveFollowUpMessagesCommand = _saveFollowUpMessagesCommand;
        UnarchiveConversationCommand = _unarchiveConversationCommand;
        RequestDeleteConversationCommand = _requestDeleteConversationCommand;
        ConfirmDeleteConversationCommand = _confirmDeleteConversationCommand;
        CancelDeleteConversationCommand = _cancelDeleteConversationCommand;
        ClearEventsCommand = new RelayCommand(() => Events.Clear());
        OpenDataFolderCommand = new RelayCommand(OpenDataFolder, () => !_previewIsolationMode);
        OpenProjectPageCommand = new RelayCommand(OpenProjectPage, () => !_previewIsolationMode);
        _checkForUpdateCommand = new AsyncRelayCommand(
            () => CheckForUpdateAsync(force: true),
            () => _updateCheck is not null);
        CheckForUpdateCommand = _checkForUpdateCommand;
        OpenUserGuideCommand = new RelayCommand(OpenUserGuide);
        NavigateCommand = new RelayCommand(Navigate);

        _engine.SnapshotUpdated += OnSnapshotUpdated;
        _engine.StatusChanged += OnStatusChanged;
        _log.EntryWritten += OnLogEntry;
        _desktopIpc.ConnectionChanged += OnDesktopConnectionChanged;
        _localization.LanguageChanged += OnLanguageChanged;
        if (_workflowAutomationHost is not null)
        {
            _workflowAutomationHost.LineageInvalidated += OnWorkflowLineageInvalidated;
        }
        if (_enhancedObservationStatus is not null)
        {
            _enhancedObservationStatus.AvailabilityChanged += OnEnhancedObservationAvailabilityChanged;
        }

        EngineState = DisplayEngineState(_rawEngineState);
        EngineDetail = DisplayEngineDetail(_rawEngineState, _rawEngineDetail);
        LastScanText = L("Value.Never");
        ServerVersion = L("Status.NotConnected");
        IsDesktopConnected = _desktopIpc.IsConnected && _desktopIpc.IsNativeChannelAvailable;
        RefreshDiagnosticDisplay();
        RefreshWorkflowLineageDisplay();
        _updateState = Settings.UpdateCheckEnabled
            ? UpdateCheckDisplayState.Unknown
            : UpdateCheckDisplayState.Disabled;
        RefreshUpdateDisplay();
    }

    public AppSettings Settings { get; }

    public ObservableCollection<GuardianTaskItem> Tasks { get; } = [];

    public ICollectionView TasksView { get; }

    public ObservableCollection<ConversationNavigationEntry> ConversationNavigationEntries { get; } =
        new ResettableObservableCollection<ConversationNavigationEntry>();

    public ObservableCollection<LogEntry> Events { get; } = [];

    public ObservableCollection<WorkflowLineageDisplayItem> WorkflowLineageItems =>
        _workflowLineageItems;

    public ObservableCollection<FollowUpMessageItem> FollowUpMessages { get; } = [];

    public ObservableCollection<WorkflowConversationOption> WorkflowConversationOptions { get; } = [];

    public IReadOnlyList<FollowUpTriggerOption> FollowUpTriggerOptions =>
    [
        new(FollowUpTriggerKind.AfterNormalCompletion, L("FollowUp.TriggerCompletion")),
        new(FollowUpTriggerKind.ScheduledAt, L("FollowUp.TriggerScheduled"))
    ];

    public IReadOnlyList<FollowUpAutomationModeOption> FollowUpAutomationModeOptions =>
    [
        new(false, L("Workflow.ModeSequence"), true),
        new(true, L("Workflow.ModeWorkflow"), CanEditWorkflowRules)
    ];

    public IReadOnlyList<WorkflowTriggerOption> WorkflowTriggerOptions =>
    [
        new(WorkflowTriggerKind.ScheduledAt, L("Workflow.TriggerScheduled")),
        new(
            WorkflowTriggerKind.ConversationCompletedNormally,
            L("Workflow.TriggerConversationCompleted")),
        new(WorkflowTriggerKind.PresetDispatchConfirmed, L("Workflow.TriggerPresetConfirmed"))
    ];

    public IReadOnlyList<WorkflowDestinationOption> WorkflowDestinationOptions =>
    [
        new(
            WorkflowDestinationKind.CurrentConversation,
            L("Workflow.DestinationCurrent"),
            true,
            string.Empty),
        new(
            WorkflowDestinationKind.ExistingConversation,
            L("Workflow.DestinationExisting"),
            true,
            string.Empty),
        new(
            WorkflowDestinationKind.NewConversation,
            L("Workflow.DestinationNew"),
            IsNewConversationWorkflowAvailable,
            IsNewConversationWorkflowAvailable
                ? string.Empty
                : L("Workflow.CapabilityUnavailable"))
    ];

    public IReadOnlyList<RecoveryCountingModeOption> RecoveryCountingModeOptions =>
    [
        new(
            RecoveryCountingMode.PerFailedTurn,
            L("Recovery.CountingPerFailedTurn")),
        new(
            RecoveryCountingMode.SharedIncidentBudget,
            L("Recovery.CountingSharedIncident")),
        new(
            RecoveryCountingMode.OriginalFailedTurnOnly,
            L("Recovery.CountingOriginalOnly"))
    ];

    public bool IsNewConversationWorkflowAvailable => false;

    public bool CanEditWorkflowRules =>
        _workflowRuleSnapshot is
        {
            RequiresConservativeRecovery: false,
            ReadStatus: WorkflowRuleStoreReadStatus.Missing or WorkflowRuleStoreReadStatus.Healthy
        };

    public bool HasWorkflowRuleStoreIssue => !CanEditWorkflowRules;

    public string WorkflowRuleStoreStatusText => _workflowRuleSnapshot?.ReadStatus switch
    {
        WorkflowRuleStoreReadStatus.RecoveredFromBackup => L("Workflow.StoreReview"),
        WorkflowRuleStoreReadStatus.Corrupted => L("Workflow.StoreCorrupt"),
        WorkflowRuleStoreReadStatus.UnsupportedSchema => L("Workflow.StoreUnsupported"),
        WorkflowRuleStoreReadStatus.Missing or WorkflowRuleStoreReadStatus.Healthy => string.Empty,
        _ when _workflowRuleLoadFailed => L("Workflow.StoreUnavailable"),
        _ => L("Workflow.StoreLoading")
    };

    internal WorkflowRuleStoreSnapshot? WorkflowRuleSnapshot => _workflowRuleSnapshot;

    public IReadOnlyList<LanguageOption> AvailableLanguages => _localization.AvailableLanguages;

    public ICommand ScanNowCommand { get; }

    public ICommand ProbeDesktopChannelCommand { get; }

    public ICommand RunReadOnlyDiagnosticCommand { get; }

    public ICommand AddFollowUpMessageCommand { get; }

    public ICommand RemoveFollowUpMessageCommand { get; }

    public ICommand EditFollowUpMessageCommand { get; }

    public ICommand CloseFollowUpMessageEditorCommand { get; }

    public ICommand RequestFollowUpAttachmentPickerCommand { get; }

    public ICommand RemoveFollowUpAttachmentCommand { get; }

    public ICommand OpenFollowUpEditorCommand { get; }

    public ICommand BackToTasksCommand { get; }

    public ICommand SetConversationScopeCommand { get; }

    public ICommand ClearTaskSearchCommand { get; }

    public ICommand ToggleConversationPinCommand { get; }

    public ICommand OpenConversationGroupCommand { get; }

    public ICommand ToggleConversationSectionCommand { get; }

    public ICommand BackToConversationNavigationCommand { get; }

    public ICommand ToggleThemeCommand { get; }

    public ICommand SaveFollowUpMessagesCommand { get; }

    public ICommand RefreshWorkflowLineageCommand => _refreshWorkflowLineageCommand;

    public ICommand UnarchiveConversationCommand { get; }

    public ICommand RequestDeleteConversationCommand { get; }

    public ICommand ConfirmDeleteConversationCommand { get; }

    public ICommand CancelDeleteConversationCommand { get; }

    public ICommand ClearEventsCommand { get; }

    public ICommand OpenDataFolderCommand { get; }

    /// <summary>Opens the project on GitHub — the releases page when an update is waiting, the repository otherwise.</summary>
    public ICommand OpenProjectPageCommand { get; }

    /// <summary>Checks for a newer release now, ignoring the daily interval.</summary>
    public ICommand CheckForUpdateCommand { get; }

    public ICommand OpenUserGuideCommand { get; }

    public ICommand NavigateCommand { get; }

    public string WorkflowLineageStatusText
    {
        get => _workflowLineageStatusText;
        private set => SetProperty(ref _workflowLineageStatusText, value);
    }

    public string WorkflowLineageEmptyText
    {
        get => _workflowLineageEmptyText;
        private set => SetProperty(ref _workflowLineageEmptyText, value);
    }

    public bool HasWorkflowLineageItems => WorkflowLineageItems.Count > 0;

    public GuardianTaskItem? SelectedTask
    {
        get => _selectedTask;
        set
        {
            if (!ReferenceEquals(_selectedTask, value) && _isFollowUpEditorDirty)
            {
                FollowUpEditorStatus = L("FollowUp.SaveBeforeTaskSwitch");
                RestoreSelectedTaskBinding();
                return;
            }

            if (!SetProperty(ref _selectedTask, value))
            {
                return;
            }

            LoadSelectedTaskFollowUps();
            OnPropertyChanged(nameof(HasSelectedTask));
            OnPropertyChanged(nameof(CanEditSelectedFollowUps));
            OnPropertyChanged(nameof(SelectedTaskFollowUpTitle));
            OnPropertyChanged(nameof(SelectedPageTitle));
            RaiseFollowUpCommandCanExecuteChanged();
            RaiseConversationMutationCommandCanExecuteChanged();
        }
    }

    public bool HasSelectedTask => SelectedTask is not null;

    public bool CanEditSelectedFollowUps => SelectedTask is { IsArchived: false };

    public string SelectedTaskFollowUpTitle => SelectedTask?.Name ?? L("FollowUp.NoTaskSelected");

    public FollowUpMessageItem? SelectedFollowUpMessage
    {
        get => _selectedFollowUpMessage;
        set
        {
            if (SetProperty(ref _selectedFollowUpMessage, value))
            {
                RaiseFollowUpCommandCanExecuteChanged();
            }
        }
    }

    public bool SelectedFollowUpsEnabled
    {
        get => _selectedFollowUpsEnabled;
        set
        {
            if (SetProperty(ref _selectedFollowUpsEnabled, value) &&
                SelectedTask is not null &&
                !_isLoadingFollowUpEditor)
            {
                MarkFollowUpEditorDirty();
            }
        }
    }

    public string FollowUpEditorStatus
    {
        get => _followUpEditorStatus;
        private set => SetProperty(ref _followUpEditorStatus, value);
    }

    public bool HasUnsavedFollowUpChanges => _isFollowUpEditorDirty;

    internal event Action<FollowUpMessageItem, bool>? FollowUpMessageFocusRequested;

    internal event Action<FollowUpMessageItem>? FollowUpAttachmentPickerRequested;

    internal FollowUpAttachmentCompositionService? AttachmentComposition => _attachmentComposition;

    internal void SetFollowUpAttachmentImportStatus(bool success, int importedCount = 0) =>
        FollowUpEditorStatus = success
            ? L("FollowUp.AttachmentsImported", importedCount)
            : L("FollowUp.AttachmentImportFailed");

    internal async Task<FollowUpAttachmentCompositionResult> ImportFollowUpFilesAsync(
        FollowUpMessageItem item,
        IReadOnlyList<string> sourcePaths,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (_attachmentComposition is null ||
            SelectedTask is not { } task ||
            !IsFollowUpDetailPage ||
            !FollowUpMessages.Contains(item))
        {
            throw new InvalidOperationException("Attachment import is unavailable for the current draft.");
        }

        var target = new FollowUpAttachmentDraftTarget(task.Id, item.Id, ++_attachmentDraftVersion);
        var existing = item.Attachments.Select(static attachment => attachment.ToReference()).ToArray();
        return await _attachmentComposition.ComposeFilesAsync(
                target,
                existing,
                sourcePaths,
                Settings.AttachmentLimits,
                TryCommitImportedAttachmentsAsync,
                cancellationToken)
            .ConfigureAwait(true);
    }

    internal async Task<FollowUpAttachmentCompositionResult> ImportFollowUpClipboardAsync(
        FollowUpMessageItem item,
        ClipboardAttachmentSource source,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(source);
        if (_attachmentComposition is null ||
            SelectedTask is not { } task ||
            !IsFollowUpDetailPage ||
            !FollowUpMessages.Contains(item))
        {
            throw new InvalidOperationException("Attachment import is unavailable for the current draft.");
        }

        var target = new FollowUpAttachmentDraftTarget(task.Id, item.Id, ++_attachmentDraftVersion);
        var existing = item.Attachments.Select(static attachment => attachment.ToReference()).ToArray();
        return await _attachmentComposition.ComposeClipboardAsync(
                target,
                existing,
                source,
                Settings.AttachmentLimits,
                TryCommitImportedAttachmentsAsync,
                cancellationToken)
            .ConfigureAwait(true);
    }

    private Task<bool> TryCommitImportedAttachmentsAsync(
        FollowUpAttachmentDraftTarget target,
        IReadOnlyList<PresetAttachmentReference> attachments,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsFollowUpDetailPage ||
            SelectedTask is not { } task ||
            !string.Equals(task.Id, target.ThreadId, StringComparison.OrdinalIgnoreCase) ||
            FollowUpMessages.FirstOrDefault(item => string.Equals(item.Id, target.MessageId, StringComparison.Ordinal)) is not { } item ||
            target.Version != _attachmentDraftVersion)
        {
            return Task.FromResult(false);
        }

        item.Attachments.Clear();
        foreach (var reference in attachments.OrderBy(static reference => reference.Order))
        {
            item.Attachments.Add(new AttachmentItemViewModel(reference));
        }
        RenumberFollowUpAttachments(item);
        SelectedFollowUpMessage = item;
        MarkFollowUpEditorDirty();
        PublishVisibleAttachmentDrafts(incrementVersion: false);
        return Task.FromResult(true);
    }

    internal event Action<string>? UiThemeChanged;

    public bool IsMonitoring
    {
        get => _isMonitoring;
        private set
        {
            if (SetProperty(ref _isMonitoring, value))
            {
                OnPropertyChanged(nameof(MonitoringSummaryText));
                ApplySleepPolicy();
            }
        }
    }

    /// <summary>
    /// Whether Windows is asked to stay awake while monitoring runs.
    /// </summary>
    /// <remarks>
    /// Tied to monitoring rather than held unconditionally: the switch exists so guarding is not cut
    /// short by sleep, and once monitoring stops there is nothing left to protect. Leaving the request
    /// standing after that would keep the machine awake for no reason.
    /// </remarks>
    public bool PreventSystemSleep
    {
        get => Settings.PreventSystemSleep;
        set
        {
            if (Settings.PreventSystemSleep == value)
            {
                return;
            }

            Settings.PreventSystemSleep = value;
            ApplySleepPolicy();
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    private void ApplySleepPolicy() =>
        _sleepGuard?.Apply(Settings.PreventSystemSleep && IsMonitoring);

    /// <summary>
    /// Whether the app may ask GitHub, at most once a day, for the newest release tag.
    /// </summary>
    /// <remarks>
    /// Turning it on checks straight away rather than waiting for the next launch: a user who just enabled it
    /// wants an answer, and the daily interval is there to spare the rate limit, not to make the switch inert.
    /// Turning it off clears the conclusion, so a badge cannot outlive the setting that produced it.
    /// </remarks>
    public bool UpdateCheckEnabled
    {
        get => Settings.UpdateCheckEnabled;
        set
        {
            if (Settings.UpdateCheckEnabled == value)
            {
                return;
            }

            Settings.UpdateCheckEnabled = value;
            OnPropertyChanged();
            if (value)
            {
                _updateState = UpdateCheckDisplayState.Unknown;
                _ = CheckForUpdateAsync(force: false);
            }
            else
            {
                HasUpdateAvailable = false;
                _updateLatestVersionText = string.Empty;
                _updateState = UpdateCheckDisplayState.Disabled;
            }

            RefreshUpdateDisplay();
            _ = SaveSettingsAsync();
        }
    }

    /// <summary>True when a published release is newer than this build.</summary>
    public bool HasUpdateAvailable
    {
        get => _hasUpdateAvailable;
        private set
        {
            if (SetProperty(ref _hasUpdateAvailable, value))
            {
                OnPropertyChanged(nameof(BrandToolTipText));
            }
        }
    }

    /// <summary>This build's version, as shown on the settings page.</summary>
    public string CurrentVersionText => ProductIdentity.CurrentVersionText;

    /// <summary>The version line under the update status, localized on read so it survives a language switch.</summary>
    public string CurrentVersionLabelText => string.Format(
        CultureInfo.CurrentCulture,
        L("Settings.CurrentVersion"),
        ProductIdentity.CurrentVersionText);

    /// <summary>What the brand mark says on hover: where it goes, and whether an update is waiting.</summary>
    public string BrandToolTipText => HasUpdateAvailable && _updateLatestVersionText.Length > 0
        ? string.Format(
            CultureInfo.CurrentCulture,
            L("Shell.BrandToolTipUpdate"),
            _updateLatestVersionText,
            ProductIdentity.CurrentVersionText)
        : string.Format(
            CultureInfo.CurrentCulture,
            L("Shell.BrandToolTip"),
            ProductIdentity.CurrentVersionText);

    /// <summary>The one-line conclusion of the last check, for the settings page.</summary>
    public string UpdateStatusText
    {
        get => _updateStatusText;
        private set => SetProperty(ref _updateStatusText, value);
    }

    public bool IsOnline
    {
        get => _isOnline;
        private set
        {
            if (SetProperty(ref _isOnline, value))
            {
                ServerVersion = value ? L("Status.LocalServiceConnected") : L("Status.NotConnected");
            }
        }
    }

    public bool IsDesktopConnected
    {
        get => _isDesktopConnected;
        private set
        {
            if (SetProperty(ref _isDesktopConnected, value))
            {
                OnPropertyChanged(nameof(DesktopChannelText));
                OnPropertyChanged(nameof(CanEnableAutoRecovery));
                OnPropertyChanged(nameof(CanToggleAutoRecovery));
                OnPropertyChanged(nameof(ProtectionModeText));
                OnPropertyChanged(nameof(ProtectionModeDescription));
            }
        }
    }

    public string DesktopChannelText => IsDesktopConnected
        ? L("Status.DesktopChannelConnected")
        : _desktopIpc.IsConnected
            ? L("Status.DesktopChannelUnavailable")
            : L("Status.DesktopChannelDisconnected");

    public bool IsEnhancedObservationAvailable => _enhancedObservationStatus?.IsAvailable == true;

    public EnhancedObservationMode ObservationMode =>
        _enhancedObservationStatus?.Mode ?? EnhancedObservationMode.Unavailable;

    public bool IsDeepObservationAvailable => ObservationMode == EnhancedObservationMode.CodexDeep;

    public string EnhancedObservationText => ObservationMode switch
    {
        EnhancedObservationMode.CodexDeep => L("Status.DeepObservationAvailable"),
        EnhancedObservationMode.WindowsComposer => L("Status.EnhancedObservationAvailable"),
        _ => L("Status.EnhancedObservationFallback")
    };

    public string EnhancedObservationDetail => ObservationMode switch
    {
        EnhancedObservationMode.CodexDeep => L("Recovery.DeepObservationHint"),
        EnhancedObservationMode.WindowsComposer => L("Recovery.EnhancedObservationHint"),
        _ => L("Recovery.EnhancedObservationFallbackHint")
    };

    public bool AutoRecoveryEnabled
    {
        get => !_previewIsolationMode && Settings.AutomaticRecoveryEnabled;
        set
        {
            if (value && !CanEnableAutoRecovery)
            {
                OnPropertyChanged();
                return;
            }

            SetAutomaticRecoveryEnabled(value);
        }
    }

    public bool CanEnableAutoRecovery =>
        !_previewIsolationMode &&
        _desktopIpc.SupportsGuardedAutomaticRecovery &&
        IsDesktopConnected &&
        IsEnhancedObservationAvailable;

    public bool CanToggleAutoRecovery => AutoRecoveryEnabled || CanEnableAutoRecovery;

    public bool CanEnableConversationProtection => !_previewIsolationMode;

    public string TaskSearchText
    {
        get => _taskSearchText;
        set
        {
            if (SetProperty(ref _taskSearchText, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(HasTaskSearchText));
                OnPropertyChanged(nameof(TaskEmptyHintText));
                _clearTaskSearchCommand.RaiseCanExecuteChanged();
                RefreshTaskFilter();
            }
        }
    }

    public bool HasTaskSearchText => !string.IsNullOrWhiteSpace(TaskSearchText);

    public bool IsConversationNavigationRoot => _conversationGroupKey is null;

    public bool IsConversationNavigationDetail => !IsConversationNavigationRoot;

    public string ConversationGroupTitle => _conversationGroupTitle;

    public int ConversationNavigationMotionRevision => _conversationNavigationMotionRevision;

    public ConversationScopeKind ConversationScope
    {
        get => _conversationScope;
        set
        {
            if (!SetProperty(ref _conversationScope, value))
            {
                return;
            }

            var includeArchived = value == ConversationScopeKind.Archived;
            if (_showArchived != includeArchived)
            {
                _showArchived = includeArchived;
                OnPropertyChanged(nameof(ShowArchived));
            }

            OnPropertyChanged(nameof(IsAllConversationScope));
            OnPropertyChanged(nameof(IsNeedsAttentionConversationScope));
            OnPropertyChanged(nameof(IsArchivedConversationScope));
            OnPropertyChanged(nameof(ConversationScopeText));
            OnPropertyChanged(nameof(TaskEmptyHintText));
            RequestConversationNavigationTransition();
            RefreshTaskFilter();
        }
    }

    public bool IsAllConversationScope => ConversationScope == ConversationScopeKind.All;

    public bool IsNeedsAttentionConversationScope =>
        ConversationScope == ConversationScopeKind.NeedsAttention;

    public bool IsArchivedConversationScope => ConversationScope == ConversationScopeKind.Archived;

    public string ConversationScopeText => ConversationScope switch
    {
        ConversationScopeKind.NeedsAttention => L("Shell.AttentionConversations"),
        ConversationScopeKind.Archived => L("Tasks.ScopeArchived"),
        _ => L("Shell.AllConversations")
    };

    public bool ShowArchived
    {
        get => _showArchived;
        set
        {
            if (SetProperty(ref _showArchived, value))
            {
                RefreshTaskFilter();
            }
        }
    }

    public string ProtectionMetricTitle => CanEnableConversationProtection
        ? L("Stats.ProtectionEnabled")
        : L("Stats.RealtimeMonitored");

    public string ProtectionMetricHint => CanEnableConversationProtection
        ? L("Overview.ProtectedHint")
        : L("Overview.MonitoredHint");

    public string TaskProtectionHint => CanEnableConversationProtection
        ? L("Tasks.ToggleHint")
        : L("Tasks.ToggleLockedHint");

    public string ContinueMessage
    {
        get => Settings.ContinueMessage;
        set
        {
            var enteredValue = value;
            var normalizedValue = SettingsService.NormalizeContinueMessage(value);
            if (string.Equals(Settings.ContinueMessage, normalizedValue, StringComparison.Ordinal))
            {
                if (!string.Equals(enteredValue, normalizedValue, StringComparison.Ordinal))
                {
                    OnPropertyChanged();
                }

                return;
            }

            Settings.ContinueMessage = normalizedValue;
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    public bool IncludeSubAgents
    {
        get => Settings.IncludeSubAgents;
        set
        {
            if (Settings.IncludeSubAgents == value)
            {
                return;
            }

            _engine.SetIncludeSubAgents(value);
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    public bool KeepAliveEnabled
    {
        get => Settings.KeepAliveEnabled;
        set
        {
            if (Settings.KeepAliveEnabled == value)
            {
                return;
            }

            _engine.SetKeepAliveEnabled(value);
            OnPropertyChanged();
            OnPropertyChanged(nameof(KeepAliveStatusText));
            RefreshKeepAliveRuntime();
            _ = SaveSettingsAsync();
        }
    }

    /// <summary>
    /// The global sentinel: any conversation answering normally arms it, and it then holds one
    /// nominated conversation.
    /// </summary>
    public bool KeepAliveSentinelEnabled
    {
        get => Settings.KeepAliveSentinelEnabled;
        set
        {
            if (Settings.KeepAliveSentinelEnabled == value)
            {
                return;
            }

            _engine.SetKeepAliveSentinelEnabled(value);
            OnPropertyChanged();
            RefreshKeepAliveRuntime();
            _ = SaveSettingsAsync();
        }
    }

    /// <summary>
    /// The conversation the sentinel sends into, or empty when none is nominated.
    /// </summary>
    /// <remarks>
    /// An existing conversation rather than a fresh one: the native channel validates the target as a
    /// conversation UUID and cannot open a new conversation, and driving Desktop's own new-conversation
    /// button would be UI injection. Nominating one deliberately keeps heartbeats out of the
    /// conversations the user is actually reading.
    /// </remarks>
    public string KeepAliveSentinelThreadId
    {
        get => Settings.KeepAliveSentinelThreadId;
        set
        {
            var normalized = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
            if (string.Equals(Settings.KeepAliveSentinelThreadId, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _engine.SetKeepAliveSentinelThreadId(normalized);
            OnPropertyChanged();
            OnPropertyChanged(nameof(KeepAliveSentinelDestinationName));
            RefreshKeepAliveRuntime();
            _ = SaveSettingsAsync();
        }
    }

    /// <summary>
    /// The nominated conversation's title, or a "none chosen" caption.
    /// </summary>
    /// <remarks>
    /// Resolved against `Tasks` rather than stored alongside the id, so a renamed conversation shows its
    /// current name. A stored copy would go stale and the user would be looking at a name that no longer
    /// exists anywhere else in the app.
    /// </remarks>
    public string KeepAliveSentinelDestinationName
    {
        get
        {
            var threadId = Settings.KeepAliveSentinelThreadId;
            if (string.IsNullOrWhiteSpace(threadId))
            {
                return L("KeepAlive.SentinelNoDestination");
            }

            var match = Tasks.FirstOrDefault(task =>
                string.Equals(task.Id, threadId, StringComparison.OrdinalIgnoreCase));
            return string.IsNullOrWhiteSpace(match?.Name)
                ? L("KeepAlive.SentinelDestinationMissing")
                : match!.Name;
        }
    }

    public int KeepAliveIntervalMinutes
    {
        get => Settings.KeepAliveIntervalMinutes;
        set
        {
            var normalized = Math.Clamp(
                value,
                AppSettings.MinimumKeepAliveIntervalMinutes,
                AppSettings.MaximumKeepAliveIntervalMinutes);
            if (Settings.KeepAliveIntervalMinutes == normalized)
            {
                return;
            }

            _engine.SetKeepAliveIntervalMinutes(normalized);
            OnPropertyChanged();
            RefreshKeepAliveRuntime();
            _ = SaveSettingsAsync();
        }
    }

    public string KeepAliveMessage
    {
        get => Settings.KeepAliveMessage;
        set
        {
            var normalized = SettingsService.NormalizeKeepAliveMessage(value);
            if (string.Equals(Settings.KeepAliveMessage, normalized, StringComparison.Ordinal))
            {
                return;
            }

            _engine.SetKeepAliveMessage(normalized);
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasKeepAliveMessage));
            _ = SaveSettingsAsync();
        }
    }

    public bool HasKeepAliveMessage => !string.IsNullOrWhiteSpace(Settings.KeepAliveMessage);

    /// <summary>
    /// Section headings and conversation rows in one list, in conversation-index order.
    /// </summary>
    /// <remarks>
    /// Loosely typed because the two row kinds share no useful base: a heading carries collapse state and
    /// a count, a conversation row carries the hold choice. The XAML selects a template per type, which is
    /// how the conversation index handles the same mix.
    /// </remarks>
    public ObservableCollection<object> KeepAliveThreads { get; } = [];

    /// <summary>
    /// Collapse state per section key, kept outside the rows so it survives a rebuild.
    /// </summary>
    /// <remarks>
    /// The list is rebuilt on every monitor pass. Holding this on the row objects meant a section the user
    /// collapsed sprang back open seconds later.
    /// </remarks>
    private readonly Dictionary<string, bool> _keepAliveSectionExpanded = new(StringComparer.Ordinal);

    /// <summary>Filters the keep-alive list, so a specific conversation can be found and held.</summary>
    public string KeepAliveSearchText
    {
        get => _keepAliveSearchText;
        set
        {
            if (SetProperty(ref _keepAliveSearchText, value ?? string.Empty))
            {
                OnPropertyChanged(nameof(HasKeepAliveSearchText));
                RefreshKeepAliveRuntime();
            }
        }
    }

    public bool KeepAliveShowHeldOnly
    {
        get => _keepAliveShowHeldOnly;
        set
        {
            if (SetProperty(ref _keepAliveShowHeldOnly, value))
            {
                RefreshKeepAliveRuntime();
            }
        }
    }

    public bool HasKeepAliveSearchText => KeepAliveSearchText.Length > 0;

    /// <summary>
    /// True when no conversation row is showing. Headings alone do not count as content.
    /// </summary>
    public bool HasNoKeepAliveRows => !KeepAliveThreads.OfType<KeepAliveThreadViewModel>().Any();

    public string KeepAliveStatusText
    {
        get => _keepAliveStatusText;
        private set => SetProperty(ref _keepAliveStatusText, value);
    }

    /// <summary>
    /// The heartbeats actually sent, newest first, across every held conversation.
    /// </summary>
    /// <remarks>
    /// This is the page's answer to "is it doing anything". <see cref="KeepAliveStatusText"/> degrades the
    /// whole runtime down to one line by design — it has one line to work with — and what that line cannot
    /// carry is evidence. A held conversation with a plausible next-due time looks identical whether it has
    /// sent five heartbeats or none.
    /// </remarks>
    public ObservableCollection<KeepAliveSendViewModel> KeepAliveRecentSends { get; } = [];

    /// <summary>Collapses the send list in favour of an empty-state line.</summary>
    public bool HasKeepAliveRecentSends => KeepAliveRecentSends.Count > 0;

    /// <summary>Held conversation count, as a bindable string.</summary>
    public string KeepAliveHeldCountText
    {
        get => _keepAliveHeldCountText;
        private set => SetProperty(ref _keepAliveHeldCountText, value);
    }

    /// <summary>When the next heartbeat is due, or a dash when nothing is scheduled.</summary>
    public string KeepAliveNextDueText
    {
        get => _keepAliveNextDueText;
        private set => SetProperty(ref _keepAliveNextDueText, value);
    }

    /// <summary>
    /// The line under the due time: how long until it fires, or why nothing is scheduled.
    /// </summary>
    /// <remarks>
    /// A bare clock time answers "when" but not "is this thing actually running", and the dash it degrades to
    /// answers neither — it reads as "not due yet" whether the schedule is minutes away or the master switch
    /// is off. The reported case was exactly that: keep-alive off, so no schedule, so a dash, while the panel
    /// above it still counted a held conversation and called the sentinel armed. Both were true of their own
    /// switch and neither was sending anything.
    /// </remarks>
    public string KeepAliveNextDueDetailText
    {
        get => _keepAliveNextDueDetailText;
        private set
        {
            if (SetProperty(ref _keepAliveNextDueDetailText, value))
            {
                OnPropertyChanged(nameof(HasKeepAliveNextDueDetail));
            }
        }
    }

    /// <summary>Collapses the detail line rather than leaving a gap under the due time.</summary>
    public bool HasKeepAliveNextDueDetail => KeepAliveNextDueDetailText.Length > 0;

    /// <summary>How many held conversations are parked until recovery finishes.</summary>
    public string KeepAliveWaitingCountText
    {
        get => _keepAliveWaitingCountText;
        private set => SetProperty(ref _keepAliveWaitingCountText, value);
    }

    /// <summary>
    /// The sentinel's state in its own words, since it has three ways of being on and idle that a count
    /// of held conversations reports identically as zero.
    /// </summary>
    public string KeepAliveSentinelStateText
    {
        get => _keepAliveSentinelStateText;
        private set => SetProperty(ref _keepAliveSentinelStateText, value);
    }

    /// <summary>
    /// Rebuilds the keep-alive page from engine state.
    /// </summary>
    /// <remarks>
    /// Only while the page is open. Enrolment and last-send times change on every monitor pass, and
    /// rewriting a collection nobody is looking at would churn the dispatcher for nothing.
    /// </remarks>
    private void RefreshKeepAliveRuntime()
    {
        if (!IsKeepAlivePage)
        {
            // Leaving the page also parks the countdown. It is the only thing in this view model that wakes
            // the dispatcher on a schedule rather than on an event.
            StopKeepAliveCountdown();
            return;
        }

        var runtime = _engine.CaptureKeepAliveRuntime();
        // Driven by `Tasks`, which is the same ordered collection the conversation index is built from, so
        // this page shows conversations in the order Codex itself has them: running first, then pinned,
        // then projects and recents by last activity, honouring any manual order. Ordering this list by
        // name instead — which it did at first — meant the two pages disagreed about where a conversation
        // sits, and the user has to recognise the same conversation on both.
        //
        // The engine snapshot is only consulted for keep-alive state. Its own thread cache also holds
        // sub-agent and ephemeral threads with no title, and its `Thread.Name` is blank for most
        // conversations because the real title arrives later on the authoritative-thread path and is
        // written onto the task item; reading names from the snapshot gave a page of untitled rows.
        var keepAliveByThread = runtime.Threads.ToDictionary(
            thread => thread.ThreadId,
            StringComparer.OrdinalIgnoreCase);
        var needle = KeepAliveSearchText.Trim();
        var ordered = BuildKeepAliveEntries(keepAliveByThread, needle);
        // Existing conversation rows are reused rather than rebuilt. The row hosts a focusable selector,
        // and replacing the object under the pointer would drop the click the user is in the middle of.
        var existing = KeepAliveThreads
            .OfType<KeepAliveThreadViewModel>()
            .ToDictionary(row => row.ThreadId, StringComparer.OrdinalIgnoreCase);
        var live = new List<object>(ordered.Count);
        foreach (var incoming in ordered)
        {
            if (incoming is KeepAliveThreadRuntime thread)
            {
                var lastSentText = DescribeKeepAliveLastSent(thread.LastSentAt);
                if (existing.TryGetValue(thread.ThreadId, out var row))
                {
                    row.Update(thread, lastSentText);
                    live.Add(row);
                    continue;
                }

                live.Add(new KeepAliveThreadViewModel(
                    thread,
                    ApplyKeepAliveThreadHold,
                    ToggleKeepAliveSentinelDestination,
                    lastSentText));
                continue;
            }

            live.Add(incoming);
        }

        ApplyKeepAliveEntries(live);

        KeepAliveStatusText = DescribeKeepAliveRuntime(runtime);
        ApplyKeepAliveRuntimeFacts(runtime);
        OnPropertyChanged(nameof(HasNoKeepAliveRows));
    }

    /// <summary>
    /// Spreads the runtime snapshot across the side panel's individual readings.
    /// </summary>
    /// <remarks>
    /// Deliberately separate from <see cref="DescribeKeepAliveRuntime"/>, which collapses the same snapshot
    /// into one sentence and has to drop most of it to fit. Both are wanted: the sentence sits under the
    /// page title where it is read at a glance, and these are the numbers behind it.
    /// </remarks>
    private void ApplyKeepAliveRuntimeFacts(KeepAliveRuntimeSnapshot runtime)
    {
        KeepAliveHeldCountText = runtime.HeldCount.ToString(CultureInfo.CurrentCulture);
        KeepAliveWaitingCountText = runtime.WaitingForRecoveryCount.ToString(CultureInfo.CurrentCulture);
        KeepAliveNextDueText = runtime.NextDueAt is { } dueAt
            ? dueAt.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture)
            : "--";
        _keepAliveNextDueAt = runtime.NextDueAt;
        _keepAliveNextDueBlockedReason = DescribeKeepAliveNextDueBlocked(runtime);
        RefreshKeepAliveCountdown();
        KeepAliveSentinelStateText = DescribeKeepAliveSentinelState(runtime);
        ApplyKeepAliveRecentSends(runtime.RecentSends);
    }

    /// <summary>
    /// Why no heartbeat is scheduled, or empty when one is.
    /// </summary>
    /// <remarks>
    /// Ordered the way the engine itself gates: the master switch decides whether keep-alive runs at all,
    /// monitor-only overrides it even when on, and only then does having something to hold matter. Reporting
    /// the innermost reason first would tell a user with the switch off to go pick a conversation.
    /// </remarks>
    private string DescribeKeepAliveNextDueBlocked(KeepAliveRuntimeSnapshot runtime)
    {
        if (!runtime.Enabled)
        {
            return L("KeepAlive.NextDueReasonMasterOff");
        }

        if (runtime.MonitorOnly)
        {
            return L("KeepAlive.NextDueReasonMonitorOnly");
        }

        if (runtime.HeldCount == 0)
        {
            return L("KeepAlive.NextDueReasonNoHold");
        }

        // Held but nothing due: every held conversation is parked behind its own failed turn. Keep-alive stays
        // out of those on purpose, so this is a real schedule-less state rather than a missing reading.
        return runtime.WaitingForRecoveryCount >= runtime.HeldCount
            ? L("KeepAlive.NextDueReasonWaitingRecovery")
            : string.Empty;
    }

    /// <summary>
    /// Redraws the countdown from the cached due time.
    /// </summary>
    /// <remarks>
    /// Called both on a snapshot and on every timer tick, so it must stay free of engine calls and I/O.
    /// </remarks>
    private void RefreshKeepAliveCountdown()
    {
        if (_keepAliveNextDueAt is not { } dueAt)
        {
            KeepAliveNextDueDetailText = _keepAliveNextDueBlockedReason;
            StopKeepAliveCountdown();
            return;
        }

        var remaining = dueAt - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            // The engine clamps a past due time to now, so this is "the send is being attempted", not a
            // negative countdown. It stays on this reading until the next snapshot moves the due time.
            KeepAliveNextDueDetailText = L("KeepAlive.NextDueImminent");
            StartKeepAliveCountdown();
            return;
        }

        // Seconds are rounded up so the last second reads "in 1 s" rather than "in 0 s".
        var totalSeconds = (int)Math.Ceiling(remaining.TotalSeconds);
        var hours = totalSeconds / 3600;
        var minutes = totalSeconds % 3600 / 60;
        var seconds = totalSeconds % 60;
        KeepAliveNextDueDetailText = hours > 0
            ? string.Format(CultureInfo.CurrentCulture, L("KeepAlive.NextDueCountdownHours"), hours, minutes)
            : totalSeconds >= 60
                ? string.Format(CultureInfo.CurrentCulture, L("KeepAlive.NextDueCountdownMinutes"), minutes, seconds)
                : string.Format(CultureInfo.CurrentCulture, L("KeepAlive.NextDueCountdownSeconds"), totalSeconds);
        StartKeepAliveCountdown();
    }

    /// <summary>
    /// Runs the one-second tick, and only while it has something to count down to.
    /// </summary>
    /// <remarks>
    /// Gated on the page being open as well as on a due time existing. The tick touches nothing but two
    /// strings, but a timer left running behind a closed page would wake the dispatcher once a second for the
    /// life of the process, and this app's whole monitoring design is event-driven for that reason.
    /// </remarks>
    private void StartKeepAliveCountdown()
    {
        if (_previewIsolationMode || !IsKeepAlivePage || _keepAliveNextDueAt is null)
        {
            StopKeepAliveCountdown();
            return;
        }

        if (_keepAliveCountdownTimer is { } existing)
        {
            existing.Start();
            return;
        }

        var timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        timer.Tick += OnKeepAliveCountdownTick;
        _keepAliveCountdownTimer = timer;
        timer.Start();
    }

    private void StopKeepAliveCountdown() => _keepAliveCountdownTimer?.Stop();

    private void OnKeepAliveCountdownTick(object? sender, EventArgs e)
    {
        if (!IsKeepAlivePage)
        {
            StopKeepAliveCountdown();
            return;
        }

        RefreshKeepAliveCountdown();
    }

    /// <summary>
    /// The sentinel sub-mode's state, subordinated to the keep-alive master switch.
    /// </summary>
    /// <remarks>
    /// The master switch has to be checked first even though it belongs to the outer feature. Without it this
    /// read "Armed" whenever a healthy reply had ever been seen — true of the sub-mode, and the engine does
    /// track it independently — while the page title said keep-alive was off and nothing was being sent. The
    /// user in that state reasonably concluded the sentinel was broken.
    /// </remarks>
    private string DescribeKeepAliveSentinelState(KeepAliveRuntimeSnapshot runtime)
    {
        if (!runtime.SentinelEnabled)
        {
            return L("KeepAlive.SentinelStateOff");
        }

        if (!runtime.Enabled)
        {
            return L("KeepAlive.SentinelStateMasterOff");
        }

        if (!runtime.SentinelHasDestination)
        {
            return L("KeepAlive.SentinelStateNoDestination");
        }

        return runtime.SentinelArmed
            ? L("KeepAlive.SentinelStateArmed")
            : L("KeepAlive.SentinelStateWaiting");
    }

    /// <summary>
    /// Mirrors the engine's send history into bindable rows, resolving each thread id to its title.
    /// </summary>
    /// <remarks>
    /// Titles come from <c>Tasks</c> rather than the engine snapshot for the reason the row list already
    /// documents: the snapshot's own thread names are blank for most conversations, because the real title
    /// lands later on the authoritative-thread path.
    ///
    /// A conversation that has since left the index degrades to a placeholder rather than showing its id.
    /// The send is still worth listing — a heartbeat did go somewhere — but a raw thread id is kept off the
    /// screen throughout this app, and this panel is no place to make the first exception.
    /// </remarks>
    private void ApplyKeepAliveRecentSends(IReadOnlyList<KeepAliveSendRecord> records)
    {
        KeepAliveRecentSends.Clear();
        foreach (var record in records)
        {
            var name = Tasks.FirstOrDefault(task =>
                string.Equals(task.Id, record.ThreadId, StringComparison.OrdinalIgnoreCase))?.Name;
            KeepAliveRecentSends.Add(new KeepAliveSendViewModel(
                string.IsNullOrWhiteSpace(name) ? L("KeepAlive.SendUnknownThread") : name,
                record.Message,
                record.SentAt.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture)));
        }

        OnPropertyChanged(nameof(HasKeepAliveRecentSends));
    }

    /// <summary>
    /// Lays out section headings and conversation rows in conversation-index order.
    /// </summary>
    /// <remarks>
    /// Sections are the ones the conversation index uses, and for the same reason: a conversation should
    /// be in the place the user already knows. Running conversations are hoisted above every heading, as
    /// they are there — the list is long, and a row that sorts into the middle of a collapsed section is
    /// not reachable in any colour. Empty sections emit no heading at all, so filtering down to one match
    /// does not leave a page of headers behind.
    /// </remarks>
    private IReadOnlyList<object> BuildKeepAliveEntries(
        IReadOnlyDictionary<string, KeepAliveThreadRuntime> keepAliveByThread,
        string needle)
    {
        var running = new List<KeepAliveThreadRuntime>();
        var pinned = new List<KeepAliveThreadRuntime>();
        var recent = new List<KeepAliveThreadRuntime>();
        var archived = new List<KeepAliveThreadRuntime>();
        // Insertion-ordered: `Tasks` already has projects in most-recent-activity order, so first
        // appearance is the order to keep.
        var projects = new List<(string Key, string Title, List<KeepAliveThreadRuntime> Threads)>();
        var projectIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var task in Tasks)
        {
            if (string.IsNullOrWhiteSpace(task.Name) ||
                !keepAliveByThread.TryGetValue(task.Id, out var snapshot))
            {
                continue;
            }

            var thread = snapshot with { Name = task.Name };
            if (KeepAliveShowHeldOnly && !thread.IsHeld)
            {
                continue;
            }

            if (needle.Length > 0 &&
                !thread.Name.Contains(needle, StringComparison.CurrentCultureIgnoreCase))
            {
                continue;
            }

            if (task.IsRunningNow)
            {
                running.Add(thread);
                continue;
            }

            if (task.IsArchived)
            {
                archived.Add(thread);
                continue;
            }

            if (task.IsPinned)
            {
                pinned.Add(thread);
                continue;
            }

            var projectKey = GetRecognizedConversationProjectKey(task.Cwd);
            if (projectKey is null)
            {
                recent.Add(thread);
                continue;
            }

            if (!projectIndex.TryGetValue(projectKey, out var slot))
            {
                slot = projects.Count;
                projectIndex[projectKey] = slot;
                projects.Add((projectKey, DisplayProjectName(task.Cwd), []));
            }

            projects[slot].Threads.Add(thread);
        }

        return ComposeKeepAliveEntries(running, pinned, projects, recent, archived);
    }

    private IReadOnlyList<object> ComposeKeepAliveEntries(
        List<KeepAliveThreadRuntime> running,
        List<KeepAliveThreadRuntime> pinned,
        List<(string Key, string Title, List<KeepAliveThreadRuntime> Threads)> projects,
        List<KeepAliveThreadRuntime> recent,
        List<KeepAliveThreadRuntime> archived)
    {
        var entries = new List<object>();

        // No heading for the running rows, matching the index: they are a temporary state, not a place a
        // conversation lives, and a heading that appears and vanishes as turns start would churn the list.
        entries.AddRange(running);

        AppendKeepAliveSection(entries, PinnedConversationGroupKey, L("Tasks.PinnedSection"), pinned);

        if (projects.Count > 0)
        {
            var section = ResolveKeepAliveSection(
                "__codexfree_keepalive_projects__",
                L("Tasks.ProjectsSection"),
                isProject: false);
            section.Count = projects.Sum(project => project.Threads.Count);
            section.HeldCount = projects.Sum(project => project.Threads.Count(thread => thread.IsHeld));
            entries.Add(section);
            if (section.IsExpanded)
            {
                foreach (var project in projects)
                {
                    AppendKeepAliveSection(
                        entries,
                        ProjectConversationGroupPrefix + project.Key,
                        project.Title,
                        project.Threads,
                        isProject: true);
                }
            }
        }

        AppendKeepAliveSection(entries, RecentConversationGroupKey, L("Tasks.RecentSection"), recent);
        AppendKeepAliveSection(
            entries,
            ArchivedConversationGroupKey,
            L("Tasks.ArchivedSection"),
            archived);
        return entries;
    }

    private void AppendKeepAliveSection(
        List<object> entries,
        string key,
        string title,
        List<KeepAliveThreadRuntime> threads,
        bool isProject = false)
    {
        if (threads.Count == 0)
        {
            return;
        }

        var section = ResolveKeepAliveSection(key, title, isProject);
        section.Count = threads.Count;
        section.HeldCount = threads.Count(thread => thread.IsHeld);
        entries.Add(section);
        if (section.IsExpanded)
        {
            entries.AddRange(threads);
        }
    }

    /// <summary>
    /// Reuses the existing heading object for a key so its collapse state and identity survive a rebuild.
    /// </summary>
    private KeepAliveSectionViewModel ResolveKeepAliveSection(string key, string title, bool isProject)
    {
        var existing = KeepAliveThreads
            .OfType<KeepAliveSectionViewModel>()
            .FirstOrDefault(section => string.Equals(section.Key, key, StringComparison.Ordinal));
        if (existing is not null)
        {
            return existing;
        }

        var expanded = !_keepAliveSectionExpanded.TryGetValue(key, out var stored) || stored;
        return new KeepAliveSectionViewModel(
            key,
            title,
            isProject,
            expanded,
            (sectionKey, isExpanded) =>
            {
                _keepAliveSectionExpanded[sectionKey] = isExpanded;
                RefreshKeepAliveRuntime();
            });
    }

    /// <summary>
    /// Moves the live list into place with the fewest collection changes.
    /// </summary>
    /// <remarks>
    /// In-place reconciliation rather than clear-and-refill: a reset scrolls the list back to the top and
    /// drops focus, which on a page the user is clicking through is worse than the cost of the diff.
    /// </remarks>
    private void ApplyKeepAliveEntries(List<object> live)
    {
        for (var index = 0; index < live.Count; index++)
        {
            var incoming = live[index];
            var currentIndex = KeepAliveThreads.IndexOf(incoming);
            if (currentIndex < 0)
            {
                KeepAliveThreads.Insert(Math.Min(index, KeepAliveThreads.Count), incoming);
                continue;
            }

            if (currentIndex != index)
            {
                KeepAliveThreads.Move(currentIndex, index);
            }
        }

        while (KeepAliveThreads.Count > live.Count)
        {
            KeepAliveThreads.RemoveAt(KeepAliveThreads.Count - 1);
        }
    }

    private void ApplyKeepAliveThreadHold(string threadId, bool enabled)
    {
        _engine.SetKeepAliveThreadEnabled(threadId, enabled);
        RefreshKeepAliveRuntime();
        _ = SaveSettingsAsync();
    }

    /// <summary>
    /// Nominates the conversation under the pointer as the sentinel's destination, or clears it when it
    /// already is.
    /// </summary>
    /// <remarks>
    /// Set from the row rather than from a dropdown in the settings drawer. The destination is one of the
    /// conversations already listed on this page, and asking the user to find it again in a second list —
    /// one that would have to repeat the same grouping to be usable — is work the row can absorb.
    /// </remarks>
    private void ToggleKeepAliveSentinelDestination(string threadId)
    {
        if (string.IsNullOrWhiteSpace(threadId))
        {
            return;
        }

        KeepAliveSentinelThreadId =
            string.Equals(Settings.KeepAliveSentinelThreadId, threadId, StringComparison.OrdinalIgnoreCase)
                ? string.Empty
                : threadId;
    }

    /// <summary>
    /// Describes the last keep-alive send, or nothing at all when there has not been one.
    /// </summary>
    /// <remarks>
    /// Empty rather than a "not sent yet" caption on purpose. Before the first send that caption sat
    /// under every one of a hundred-odd rows, saying the same thing on each and turning the list into a
    /// wall of repeated text; absence already carries the same meaning.
    /// </remarks>
    private string DescribeKeepAliveLastSent(DateTimeOffset? lastSentAt) =>
        lastSentAt is { } sentAt
            ? string.Format(
                CultureInfo.CurrentCulture,
                L("KeepAlive.LastSentFormat"),
                sentAt.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture))
            : string.Empty;

    private string DescribeKeepAliveRuntime(KeepAliveRuntimeSnapshot runtime)
    {
        if (!runtime.Enabled)
        {
            return L("KeepAlive.StatusOff");
        }

        // MonitorOnly outranks the keep-alive switch, and saying so beats leaving the user to wonder why
        // an enabled feature sends nothing.
        if (runtime.MonitorOnly)
        {
            return L("KeepAlive.StatusMonitorOnly");
        }

        // The sentinel's own two ways of being on but idle. Both are silent from the outside, and a
        // status line that just counted held conversations would report zero for either without saying
        // which, leaving the user to guess whether to pick a destination or wait for a reply.
        if (runtime.SentinelEnabled && runtime.HeldCount == 0)
        {
            if (!runtime.SentinelHasDestination)
            {
                return L("KeepAlive.StatusSentinelNoDestination");
            }

            if (!runtime.SentinelArmed)
            {
                return L("KeepAlive.StatusSentinelWaiting");
            }
        }

        var held = runtime.HeldCount.ToString(CultureInfo.CurrentCulture);
        if (runtime.WaitingForRecoveryCount > 0)
        {
            return string.Format(
                CultureInfo.CurrentCulture,
                L("KeepAlive.StatusHeldWithRecovery"),
                held,
                runtime.WaitingForRecoveryCount.ToString(CultureInfo.CurrentCulture));
        }

        return runtime.NextDueAt is { } dueAt
            ? string.Format(
                CultureInfo.CurrentCulture,
                L("KeepAlive.StatusHeldWithNext"),
                held,
                dueAt.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture))
            : string.Format(CultureInfo.CurrentCulture, L("KeepAlive.StatusHeld"), held);
    }

    public bool ProtectNewThreadsByDefault
    {
        get => Settings.ProtectNewThreadsByDefault;
        set
        {
            if (Settings.ProtectNewThreadsByDefault == value)
            {
                return;
            }

            _engine.SetProtectNewThreadsByDefault(value);
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    public bool StartWithWindows
    {
        get => !_previewIsolationMode && Settings.StartWithWindows;
        set
        {
            if (_previewIsolationMode)
            {
                Settings.StartWithWindows = false;
                return;
            }

            if (Settings.StartWithWindows == value)
            {
                return;
            }

            try
            {
                _startupService.SetEnabled(value);
                Settings.StartWithWindows = value;
                OnPropertyChanged();
                _ = SaveSettingsAsync();
            }
            catch (Exception exception)
            {
                _log.Error("无法更新开机启动设置：" + exception.Message);
            }
        }
    }

    public bool MinimizeToTray
    {
        get => !_previewIsolationMode && Settings.MinimizeToTray;
        set
        {
            if (_previewIsolationMode)
            {
                Settings.MinimizeToTray = false;
                return;
            }

            if (Settings.MinimizeToTray == value)
            {
                return;
            }

            Settings.MinimizeToTray = value;
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    public int BaseBackoffSeconds
    {
        get => Settings.BaseBackoffSeconds;
        set
        {
            value = Math.Clamp(value, 5, 600);
            if (Settings.BaseBackoffSeconds == value)
            {
                return;
            }

            Settings.BaseBackoffSeconds = value;
            if (Settings.MaximumBackoffSeconds < value)
            {
                Settings.MaximumBackoffSeconds = value;
                OnPropertyChanged(nameof(MaximumBackoffSeconds));
            }

            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    public int MaximumBackoffSeconds
    {
        get => Settings.MaximumBackoffSeconds;
        set
        {
            value = Math.Clamp(value, Settings.BaseBackoffSeconds, 3600);
            if (Settings.MaximumBackoffSeconds == value)
            {
                return;
            }

            Settings.MaximumBackoffSeconds = value;
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    /// <summary>
    /// How many conversations the scan brings back.
    /// </summary>
    /// <remarks>
    /// Clamped to the same 5..100 range <see cref="SettingsService"/> enforces on load, so a value typed
    /// here and a value read from disk cannot disagree.
    ///
    /// Worth reaching, not just worth storing: the conversation count reads as truncated once the scan hits
    /// this limit, and until now the limit itself was not adjustable from anywhere in the app.
    /// </remarks>
    public int RecentThreadLimit
    {
        get => Settings.RecentThreadLimit;
        set
        {
            value = Math.Clamp(value, 5, 100);
            if (Settings.RecentThreadLimit == value)
            {
                return;
            }

            Settings.RecentThreadLimit = value;
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    /// <summary>How far back the scan looks, in days. Clamped to 1..365, as on load.</summary>
    public int RecentThreadLookbackDays
    {
        get => Settings.RecentThreadLookbackDays;
        set
        {
            value = Math.Clamp(value, 1, 365);
            if (Settings.RecentThreadLookbackDays == value)
            {
                return;
            }

            Settings.RecentThreadLookbackDays = value;
            OnPropertyChanged();
            _ = SaveSettingsAsync();
        }
    }

    public int MaximumAttempts
    {
        get => Settings.MaximumRecoveryAttempts;
        set
        {
            value = Math.Clamp(value, 1, RecoveryAttemptPolicyLimits.MaximumFiniteAttempts);
            if (Settings.MaximumRecoveryAttempts == value &&
                Settings.MaximumAttemptsPerFailure == value)
            {
                return;
            }

            Settings.MaximumRecoveryAttempts = value;
            Settings.MaximumAttemptsPerFailure = value;
            OnPropertyChanged();
            PersistRecoveryAttemptPolicy();
        }
    }

    public bool UnlimitedRecoveryAttempts
    {
        get => Settings.UnlimitedRecoveryAttempts;
        set
        {
            if (Settings.UnlimitedRecoveryAttempts == value)
            {
                return;
            }

            Settings.UnlimitedRecoveryAttempts = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsFiniteRecoveryAttempts));
            PersistRecoveryAttemptPolicy();
        }
    }

    public bool IsFiniteRecoveryAttempts => !UnlimitedRecoveryAttempts;

    public RecoveryCountingMode RecoveryCountingMode
    {
        get => Settings.RecoveryCountingMode;
        set
        {
            if (!Enum.IsDefined(value) || Settings.RecoveryCountingMode == value)
            {
                return;
            }

            Settings.RecoveryCountingMode = value;
            OnPropertyChanged();
            PersistRecoveryAttemptPolicy();
        }
    }

    private void PersistRecoveryAttemptPolicy()
    {
        _engine.SetRecoveryAttemptPolicy(
            Settings.MaximumRecoveryAttempts,
            Settings.UnlimitedRecoveryAttempts,
            Settings.RecoveryCountingMode);
        _ = SaveSettingsAsync();
    }

    public string UiLanguage
    {
        get => Settings.UiLanguage;
        set => _localization.SetLanguage(value);
    }

    public string UiTheme => UiThemes.Normalize(Settings.UiTheme);

    public bool IsDarkTheme => string.Equals(
        UiTheme,
        UiThemes.Dark,
        StringComparison.Ordinal);

    public bool IsMotionEnabled => SystemParameters.ClientAreaAnimation;

    public string ThemeToggleText => IsDarkTheme
        ? L("Shell.SwitchToLight")
        : L("Shell.SwitchToDark");

    public string SelectedPage
    {
        get => _selectedPage;
        private set
        {
            if (SetProperty(ref _selectedPage, value))
            {
                OnPropertyChanged(nameof(IsOverviewPage));
                OnPropertyChanged(nameof(IsTasksPage));
                OnPropertyChanged(nameof(IsTasksNavigationSelected));
                OnPropertyChanged(nameof(IsFollowUpDetailPage));
                OnPropertyChanged(nameof(IsRecoveryPage));
                OnPropertyChanged(nameof(IsKeepAlivePage));
                OnPropertyChanged(nameof(IsSettingsPage));
                OnPropertyChanged(nameof(IsUserGuidePage));
                OnPropertyChanged(nameof(SelectedPageTitle));
                _backToTasksCommand.RaiseCanExecuteChanged();
                if (IsKeepAlivePage)
                {
                    RefreshKeepAliveRuntime();
                }
                else
                {
                    StopKeepAliveCountdown();
                }
                if (IsOverviewPage)
                {
                    Interlocked.Exchange(ref _workflowLineageDirty, 1);
                    _ = RefreshWorkflowLineageAsync(force: true);
                }
            }
        }
    }

    public bool IsOverviewPage => SelectedPage == "Overview";

    public bool IsTasksPage => SelectedPage == "Tasks";

    public bool IsTasksNavigationSelected => IsTasksPage || IsFollowUpDetailPage;

    public bool IsFollowUpDetailPage => SelectedPage == "FollowUpDetail";

    public bool IsRecoveryPage => SelectedPage == "Recovery";

    public bool IsKeepAlivePage => SelectedPage == "KeepAlive";

    public bool IsSettingsPage => SelectedPage == "Settings";

    public bool IsUserGuidePage => SelectedPage == "UserGuide";

    public string SelectedPageTitle => SelectedPage switch
    {
        "Tasks" => L("Shell.Conversations"),
        "FollowUpDetail" => SelectedTaskFollowUpTitle,
        "Recovery" => L("Shell.Guardrails"),
        "KeepAlive" => L("Shell.KeepAlive"),
        "Settings" => L("Shell.Preferences"),
        "UserGuide" => L("Page.UserGuide.Title"),
        _ => L("Shell.Activity")
    };

    public string EngineState
    {
        get => _engineState;
        private set => SetProperty(ref _engineState, value);
    }

    public string EngineDetail
    {
        get => _engineDetail;
        private set => SetProperty(ref _engineDetail, value);
    }

    public string LastScanText
    {
        get => _lastScanText;
        private set => SetProperty(ref _lastScanText, value);
    }

    public string ServerVersion
    {
        get => _serverVersion;
        private set => SetProperty(ref _serverVersion, value);
    }

    public int TaskCount
    {
        get => _taskCount;
        private set => SetProperty(ref _taskCount, value);
    }

    public int ProtectedCount
    {
        get => _protectedCount;
        private set => SetProperty(ref _protectedCount, value);
    }

    public int AttentionCount
    {
        get => _attentionCount;
        private set => SetProperty(ref _attentionCount, value);
    }

    public int AllConversationCount => Tasks.Count(task => !task.IsArchived);

    public int NeedsAttentionConversationCount => Tasks.Count(IsTaskNeedingAttention);

    public int ArchivedConversationCount => Tasks.Count(task => task.IsArchived);

    // The two numbers behind the resend banner. They are deliberately taken from the durable ledger
    // rather than from this session's activity, so restarting the app does not reset the answer to
    // "has it ever resent anything" back to zero.
    public int ConfirmedResendTotal =>
        Tasks.Sum(task => task.RecoveryLedger.ConfirmedDispatches);

    public int ConfirmedResendConversationCount =>
        Tasks.Count(task => task.RecoveryLedger.HasEverDispatched);

    public bool HasAnyConfirmedResend => ConfirmedResendTotal > 0;

    public string RecoveryLedgerSummaryText => L(
        "Tasks.ResendTally",
        ConfirmedResendTotal,
        ConfirmedResendConversationCount);

    public bool HasVisibleTasks => TaskCount > 0;

    public string ConversationIndexSummaryText => L(
        "Tasks.IndexSummary",
        TaskCount,
        NeedsAttentionConversationCount,
        ArchivedConversationCount);

    public string TaskEmptyTitleText => Tasks.Count == 0
        ? L("Tasks.NoSessions")
        : L("Tasks.NoMatchingSessions");

    public string TaskEmptyHintText => Tasks.Count == 0
        ? L("Tasks.NoSessionsHint")
        : L("Tasks.AdjustFilter");

    public int RecoveryCount
    {
        get => _recoveryCount;
        private set => SetProperty(ref _recoveryCount, value);
    }

    public string TaskSessionSummaryText
    {
        get
        {
            var total = _snapshotStatistics.TotalSessionCount is int totalCount
                ? totalCount.ToString(_localization.CurrentCulture)
                : L("Value.NotProvided");
            var archived = _snapshotStatistics.IncludesArchived
                ? _snapshotStatistics.ArchivedSessionCount is int archivedCount
                    ? archivedCount.ToString(_localization.CurrentCulture)
                    : L("Value.NotProvided")
                : L("Value.NotIncluded");
            var filtered = _snapshotStatistics.FilteredSessionCount is int filteredCount
                ? filteredCount.ToString(_localization.CurrentCulture)
                : L("Value.NotProvided");

            return L(
                "Tasks.SessionSummary",
                total,
                _snapshotStatistics.DisplayedSessionCount,
                archived,
                filtered);
        }
    }

    public string TaskFilterSummaryText
    {
        get
        {
            var truncation = _snapshotStatistics.IsTruncated switch
            {
                true => L("Tasks.Truncated"),
                false => L("Tasks.NotTruncated"),
                null when _snapshotStatistics.DisplayedSessionCount >= Settings.RecentThreadLimit =>
                    L("Tasks.PossiblyTruncated"),
                _ => L("Tasks.TruncationUnknown")
            };

            var scope = _snapshotStatistics.IncludesArchived
                ? L("Tasks.ScopeAllWithArchived")
                : L("Tasks.ScopeActiveOnly");

            return L(
                "Tasks.FilterSummary",
                scope,
                truncation);
        }
    }

    public string MonitoringSummaryText => IsMonitoring ? L("Status.Monitoring") : L("Status.MonitoringUnavailable");

    public string ProtectionModeText => !CanToggleAutoRecovery
        ? L("Status.AtomicGuardLocked")
        : AutoRecoveryEnabled
            ? L("Status.ConversationProtection")
            : L("Status.MonitorOnly");

    public string ProtectionModeDescription => !CanToggleAutoRecovery
        ? L("Hint.AtomicGuardUnavailable")
        : AutoRecoveryEnabled
            ? L("Hint.ConversationProtection")
            : L("Hint.MonitorOnly");

    public string DiagnosticTitle
    {
        get => _diagnosticTitle;
        private set => SetProperty(ref _diagnosticTitle, value);
    }

    public string DiagnosticDetail
    {
        get => _diagnosticDetail;
        private set => SetProperty(ref _diagnosticDetail, value);
    }

    public string DiagnosticRawError
    {
        get => _diagnosticRawError;
        private set => SetProperty(ref _diagnosticRawError, value);
    }

    public string DiagnosticTaskName
    {
        get => _diagnosticTaskName;
        private set => SetProperty(ref _diagnosticTaskName, value);
    }

    public string DiagnosticCheckedAt
    {
        get => _diagnosticCheckedAt;
        private set => SetProperty(ref _diagnosticCheckedAt, value);
    }

    public string DiagnosticSource
    {
        get => _diagnosticSource;
        private set => SetProperty(ref _diagnosticSource, value);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await InitializeCoreAsync(
                cancellationToken,
                ImmediateSettingsWriteAuthority.Instance,
                startup: null);
        MarkApplicationStartupPublished();
    }

    internal Task InitializeForApplicationStartupAsync(
        CancellationToken cancellationToken,
        GuardianApplicationStartupOwnerV1.StartupLease startup)
    {
        ArgumentNullException.ThrowIfNull(startup);
        return InitializeCoreAsync(cancellationToken, startup, startup);
    }

    internal void MarkApplicationStartupPublished()
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposeStarted) != 0,
            this);
        Volatile.Write(ref _startupPublished, 1);
    }

    private async Task InitializeCoreAsync(
        CancellationToken cancellationToken,
        ISettingsWriteAuthority writeAuthority,
        GuardianApplicationStartupOwnerV1.StartupLease? startup)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ApplyCulture();
        await EnsureWorkflowRulesLoadedAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        await LoadConversationMutationJournalAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var startEngine = false;
        if (_previewIsolationMode)
        {
            Settings.MonitoringEnabled = false;
            Settings.MonitorOnly = true;
            Settings.AutomaticRecoveryEnabled = false;
            Settings.StartWithWindows = false;
            Settings.MinimizeToTray = false;
            IsMonitoring = false;
            SetEngineDisplay("Paused", "Isolated preview mode; live monitoring is disabled.");
        }
        else
        {
            cancellationToken.ThrowIfCancellationRequested();
            Settings.StartWithWindows = _startupService.IsEnabled();
            cancellationToken.ThrowIfCancellationRequested();
            OnPropertyChanged(nameof(StartWithWindows));
            Settings.MonitoringEnabled = true;
            startEngine = true;
        }

        cancellationToken.ThrowIfCancellationRequested();
        await SaveSettingsForApplicationStartupAsync(
            cancellationToken,
            writeAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        if (startEngine && _workflowAutomationHost is not null)
        {
            await _workflowAutomationHost.StartAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
        }

        if (startEngine)
        {
            var engineStarted = false;
            try
            {
                void PublishEngine()
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    _engine.Start();
                    engineStarted = true;
                    cancellationToken.ThrowIfCancellationRequested();
                    IsMonitoring = true;
                }

                if (startup is null)
                {
                    PublishEngine();
                }
                else
                {
                    startup.RunTrackedPublication(PublishEngine);
                }
            }
            catch (OperationCanceledException)
            {
                if (engineStarted)
                {
                    await _engine.StopAsync();
                }

                throw;
            }
        }
    }

    internal void LoadFollowUpPreviewFixture(FollowUpPreviewFixtureState fixture)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        if (!_previewIsolationMode || !ReferenceEquals(Settings, fixture.Settings))
        {
            throw new InvalidOperationException(
                "The follow-up preview fixture can be loaded only into its isolated preview view model.");
        }

        ApplySnapshot(fixture.Snapshot);
        SelectedTask = Tasks.FirstOrDefault(task => string.Equals(
            task.Id,
            fixture.SelectedTaskId,
            StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("The follow-up preview task was not materialized.");
        ApplyWorkflowLineageSnapshot(fixture.WorkflowLineage);
        OpenFollowUpEditorCommand.Execute(SelectedTask);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            return;
        }

        // Released here rather than left to process teardown: a keep-awake request that outlives the app
        // would keep the machine from sleeping for the rest of the login session.
        _sleepGuard?.Dispose();
        if (_keepAliveCountdownTimer is { } countdown)
        {
            countdown.Stop();
            countdown.Tick -= OnKeepAliveCountdownTick;
            _keepAliveCountdownTimer = null;
        }
        Volatile.Read(ref _activeConversationMutation)?.Invalidate();
        _workflowLineageLifetime.Cancel();
        // Cancelled before the service is disposed: an in-flight GET holds a socket for up to the client's
        // timeout, and disposing the client underneath it would surface as an exception on the way out.
        _updateCheckLifetime.Cancel();
        if (_workflowAutomationHost is not null)
        {
            _workflowAutomationHost.LineageInvalidated -= OnWorkflowLineageInvalidated;
        }
        DetachFollowUpMessageSubscriptions();
        _engine.SnapshotUpdated -= OnSnapshotUpdated;
        _engine.StatusChanged -= OnStatusChanged;
        _log.EntryWritten -= OnLogEntry;
        _desktopIpc.ConnectionChanged -= OnDesktopConnectionChanged;
        _localization.LanguageChanged -= OnLanguageChanged;
        if (_enhancedObservationStatus is not null)
        {
            _enhancedObservationStatus.AvailabilityChanged -= OnEnhancedObservationAvailabilityChanged;
        }
        await SaveSettingsDuringDisposeAsync().ConfigureAwait(false);
        await _engine.DisposeAsync().ConfigureAwait(false);
        await _workflowLineageRefreshGate.WaitAsync().ConfigureAwait(false);
        _workflowLineageRefreshGate.Release();
        _workflowLineageRefreshGate.Dispose();
        _workflowLineageLifetime.Dispose();
        _updateCheck?.Dispose();
        _updateCheckLifetime.Dispose();
    }

    private async Task ScanNowAsync()
    {
        if (_previewIsolationMode)
        {
            return;
        }

        await _engine.ScanOnceAsync();
    }

    private async Task ProbeDesktopChannelAsync()
    {
        if (_previewIsolationMode)
        {
            return;
        }

        try
        {
            var available = await _desktopIpc.ProbeNativeDesktopChannelAsync();
            IsDesktopConnected = _desktopIpc.IsConnected && available;
            OnPropertyChanged(nameof(DesktopChannelText));
            if (IsDesktopConnected)
            {
                _log.Success(L("Recovery.DesktopChannelReady"));
            }
            else
            {
                _log.Warning(L("Recovery.DesktopChannelUnavailable"));
            }
        }
        catch (Exception exception)
        {
            IsDesktopConnected = false;
            OnPropertyChanged(nameof(DesktopChannelText));
            _log.Trace("Native Codex Desktop channel check failed: " + exception.Message);
            _log.Warning(L("Recovery.DesktopChannelCheckFailed"));
        }
    }

    private async Task RunReadOnlyDiagnosticAsync()
    {
        if (_previewIsolationMode)
        {
            return;
        }

        DiagnosticRawError = string.Empty;
        DiagnosticTaskName = "—";
        DiagnosticCheckedAt = DateTime.Now.ToString("HH:mm:ss", _localization.CurrentCulture);
        _diagnosticSourceKey = null;
        SetDiagnosticState(DiagnosticViewState.Reading);

        try
        {
            await using var readSession = await _appServer.OpenReadSessionAsync();
            const int maximumDiagnosticItems = 20;
            var threads = await _appServer.ListThreadsAsync(
                Math.Min(Settings.RecentThreadLimit, maximumDiagnosticItems),
                Settings.IncludeSubAgents);
            ThreadSummary? fallbackThread = null;
            TurnSnapshot? fallbackTurn = null;
            ThreadSummary? selectedThread = null;
            TurnSnapshot? selectedTurn = null;

            var candidates = threads.Take(maximumDiagnosticItems).ToArray();
            var diagnosticSourceKey = "Value.DiagnosticAppServer";
            foreach (var thread in candidates)
            {
                var recentTurns = await _appServer.ReadRecentTurnsAsync(thread.Id, maximumDiagnosticItems);
                if (recentTurns.Count == 0)
                {
                    continue;
                }

                fallbackThread ??= thread;
                fallbackTurn ??= recentTurns[0];
                var forbiddenTurn = recentTurns.FirstOrDefault(turn =>
                {
                    var error = turn.ErrorMessage ?? string.Empty;
                    return turn.HttpStatusCode == 403 ||
                           error.Contains("paid balance insufficient", StringComparison.OrdinalIgnoreCase) ||
                           error.Contains("可用额度不足", StringComparison.OrdinalIgnoreCase);
                });
                if (forbiddenTurn is not null)
                {
                    selectedThread = thread;
                    selectedTurn = forbiddenTurn;
                    break;
                }
            }

            selectedThread ??= fallbackThread;
            selectedTurn ??= fallbackTurn;
            if (selectedThread is null || selectedTurn is null)
            {
                SetDiagnosticState(DiagnosticViewState.NoTurn);
                return;
            }

            DiagnosticTaskName = selectedThread.Name;
            DiagnosticRawError = selectedTurn.ErrorMessage ?? string.Empty;
            _diagnosticSourceKey = diagnosticSourceKey;
            var decision = _classifier.Classify(selectedTurn);
            if (selectedTurn.HttpStatusCode == 403 ||
                DiagnosticRawError.Contains("paid balance insufficient", StringComparison.OrdinalIgnoreCase) ||
                DiagnosticRawError.Contains("可用额度不足", StringComparison.OrdinalIgnoreCase))
            {
                SetDiagnosticState(DiagnosticViewState.Forbidden403);
            }
            else if (decision.Action == RecoveryActionKind.None)
            {
                SetDiagnosticState(DiagnosticViewState.ManualReview);
            }
            else
            {
                SetDiagnosticState(DiagnosticViewState.Transient, decision.Action);
            }

            _log.Info("已完成只读异常检查：只读取任务摘要，未创建恢复轮次。", selectedThread.Name);
        }
        catch (Exception exception)
        {
            SetDiagnosticState(DiagnosticViewState.Failed, failureMessage: exception.Message);
            _log.Warning("只读异常检查失败：" + exception.Message);
        }
    }

    private Task<bool> SaveSettingsAsync(
        CancellationToken cancellationToken = default) =>
        SaveSettingsAsync(
            cancellationToken,
            ImmediateSettingsWriteAuthority.Instance);

    private async Task<bool> SaveSettingsAsync(
        CancellationToken cancellationToken,
        ISettingsWriteAuthority writeAuthority)
    {
        if (Volatile.Read(ref _disposeStarted) != 0)
        {
            return false;
        }

        await _saveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _disposeStarted) != 0)
            {
                return false;
            }

            await _settingsService.SaveAsync(
                    Settings,
                    cancellationToken,
                    writeAuthority)
                .ConfigureAwait(false);
            _workflowAutomationHost?.NotifyPolicyOrCapabilityChanged();
            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Error("无法保存设置：" + exception.Message);
            return false;
        }
        finally
        {
            _saveGate.Release();
        }
    }

    private async Task SaveSettingsForApplicationStartupAsync(
        CancellationToken cancellationToken,
        ISettingsWriteAuthority writeAuthority)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposeStarted) != 0,
            this);

        // A future or unrecoverable settings envelope is projected as conservative defaults.
        // Startup may continue in read-only mode, but must not replace the unknown document
        // with those defaults. An explicit reset/recovery flow is required to authorize a write.
        if (Settings.ReadStatus == SettingsReadStatus.ConservativeDefaults)
        {
            _log.Warning(
                "Settings are conservative; startup persistence is skipped until an explicit reset.");
            return;
        }

        await _saveGate.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(
                Volatile.Read(ref _disposeStarted) != 0,
                this);
            await _settingsService.SaveAsync(
                Settings,
                cancellationToken,
                writeAuthority);
        }
        finally
        {
            _saveGate.Release();
        }
    }

    private async Task SaveSettingsDuringDisposeAsync()
    {
        await _saveGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _startupPublished) == 0)
            {
                return;
            }

            try
            {
                await _settingsService.SaveAsync(Settings).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                _log.Error("无法保存设置：" + exception.Message);
            }
        }
        finally
        {
            _saveGate.Release();
        }
    }

    private bool CanUseLiveControls() => !_previewIsolationMode;

    private bool CanEditFollowUps() => CanEditSelectedFollowUps;

    private bool CanSaveFollowUps() => CanEditFollowUps() && _isFollowUpEditorDirty;

    private async Task EnsureWorkflowRulesLoadedAsync(CancellationToken cancellationToken)
    {
        if (_workflowRuleSnapshot is null)
        {
            try
            {
                _workflowRuleSnapshot = await _workflowRuleStore
                    .ReadAsync(cancellationToken)
                    .ConfigureAwait(true);
                _workflowRuleLoadFailed = false;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _workflowRuleLoadFailed = true;
                _log.Warning(
                    "Workflow rule store initialization failed (" +
                    exception.GetType().Name + ").");
            }
        }

        RaiseWorkflowRuleStorePropertiesChanged();
        if (SelectedTask is not null)
        {
            LoadSelectedTaskFollowUps();
        }
    }

    private void RaiseWorkflowRuleStorePropertiesChanged()
    {
        OnPropertyChanged(nameof(FollowUpAutomationModeOptions));
        OnPropertyChanged(nameof(WorkflowTriggerOptions));
        OnPropertyChanged(nameof(WorkflowDestinationOptions));
        OnPropertyChanged(nameof(CanEditWorkflowRules));
        OnPropertyChanged(nameof(HasWorkflowRuleStoreIssue));
        OnPropertyChanged(nameof(WorkflowRuleStoreStatusText));
    }

    private void LoadSelectedTaskFollowUps()
    {
        _isLoadingFollowUpEditor = true;
        try
        {
            DetachFollowUpMessageSubscriptions();
            FollowUpMessages.Clear();
            SelectedFollowUpMessage = null;
            if (SelectedTask is null)
            {
                SelectedFollowUpsEnabled = true;
                FollowUpEditorStatus = L("FollowUp.SelectTaskHint");
                return;
            }

            if (!Settings.ThreadFollowUps.TryGetValue(SelectedTask.Id, out var configured))
            {
                SelectedFollowUpsEnabled = true;
                FollowUpEditorStatus = L("FollowUp.EmptyHint");
                return;
            }

            SelectedFollowUpsEnabled = configured.IsEnabled;
            foreach (var definition in configured.Messages.OrderBy(message => message.Order))
            {
                var item = new FollowUpMessageItem
                {
                    Id = definition.Id,
                    Message = definition.Message,
                    Trigger = definition.Trigger,
                    ScheduledDateLocal = definition.ScheduledAtUtc?.LocalDateTime.Date,
                    ScheduledTimeText = definition.ScheduledAtUtc?.LocalDateTime.ToString(
                        "HH:mm",
                        CultureInfo.InvariantCulture) ?? string.Empty,
                    MaximumErrorRetriesText = definition.MaximumErrorRetries?.ToString(
                        CultureInfo.InvariantCulture) ?? string.Empty,
                    RetryIndefinitely = definition.RetryIndefinitely,
                    IsEnabled = definition.IsEnabled,
                    UseWorkflowAutomation = definition.UseWorkflowAutomation,
                    WorkflowSourceConversationId = SelectedTask.Id,
                    WorkflowDestination = WorkflowDestinationKind.CurrentConversation,
                    WorkflowRuleId = WorkflowRuleEditor.CreateManagedRuleId(
                        SelectedTask.Id,
                        definition.Id),
                    Order = definition.Order
                };
                var storedRule = WorkflowRuleEditor.FindManagedRule(
                    _workflowRuleSnapshot,
                    SelectedTask.Id,
                    definition.Id);
                if (storedRule is not null)
                {
                    ApplyStoredWorkflowRule(item, storedRule);
                    item.WorkflowRuleBindingCurrent =
                        definition.WorkflowRuleRevision == storedRule.Revision &&
                        string.Equals(
                            definition.WorkflowRuleDigest,
                            storedRule.DefinitionDigest,
                            StringComparison.Ordinal);
                }

                item.ConfigureAttachmentLimits(Settings.AttachmentLimits);
                foreach (var attachment in definition.Attachments.OrderBy(reference => reference.Order))
                {
                    item.Attachments.Add(new AttachmentItemViewModel(attachment));
                }

                AttachFollowUpMessage(item);
                FollowUpMessages.Add(item);
            }

            SelectedFollowUpMessage = FollowUpMessages.FirstOrDefault();
            FollowUpEditorStatus = L("FollowUp.Loaded", FollowUpMessages.Count);
        }
        finally
        {
            RefreshWorkflowConversationOptions();
            foreach (var item in FollowUpMessages)
            {
                RefreshWorkflowPresetOptions(item);
                RefreshWorkflowItemProjection(item);
            }

            _isLoadingFollowUpEditor = false;
            SetFollowUpEditorDirty(false);
            RaiseFollowUpCommandCanExecuteChanged();
        }
    }

    private static void ApplyStoredWorkflowRule(
        FollowUpMessageItem item,
        WorkflowRuleDefinition rule)
    {
        item.WorkflowRuleId = rule.RuleId;
        item.WorkflowRuleRevision = rule.Revision;
        item.WorkflowRuleDigest = rule.DefinitionDigest;
        item.WorkflowTrigger = rule.Trigger.Kind;
        item.WorkflowSourceConversationId = rule.Trigger.SourceConversationId;
        item.WorkflowSourcePresetMessageId = rule.Trigger.SourcePresetMessageId;
        item.WorkflowScheduledDateLocal = rule.Trigger.ScheduledAtUtc?.LocalDateTime.Date;
        item.WorkflowScheduledTimeText = rule.Trigger.ScheduledAtUtc?.LocalDateTime.ToString(
            "HH:mm",
            CultureInfo.InvariantCulture) ?? string.Empty;
        item.WorkflowDestination = rule.Destination.Kind;
        item.WorkflowTargetConversationId = rule.Destination.ConversationId;
        item.WorkflowEnableTargetProtection = rule.Actions.Any(action =>
            action.Kind == WorkflowActionKind.EnableConversationProtection);
    }

    private void AddFollowUpMessage()
    {
        if (!CanEditFollowUps() || FollowUpMessages.Count >= SettingsService.MaximumFollowUpMessagesPerThread)
        {
            return;
        }

        var item = new FollowUpMessageItem
        {
            Id = Guid.NewGuid().ToString("D"),
            Message = string.Empty,
            Trigger = FollowUpTriggerKind.AfterNormalCompletion,
            MaximumErrorRetriesText = string.Empty,
            RetryIndefinitely = false,
            IsEnabled = true,
            WorkflowSourceConversationId = SelectedTask?.Id,
            WorkflowDestination = WorkflowDestinationKind.CurrentConversation,
            IsEditing = true,
            Order = FollowUpMessages.Count
        };
        if (SelectedTask is not null)
        {
            item.WorkflowRuleId = WorkflowRuleEditor.CreateManagedRuleId(
                SelectedTask.Id,
                item.Id);
        }

        item.ConfigureAttachmentLimits(Settings.AttachmentLimits);
        CollapseFollowUpEditorsExcept(item);
        AttachFollowUpMessage(item);
        FollowUpMessages.Add(item);
        RefreshWorkflowPresetOptions(item);
        RefreshWorkflowItemProjection(item);
        SelectedFollowUpMessage = item;
        MarkFollowUpEditorDirty();
        FollowUpMessageFocusRequested?.Invoke(item, true);
    }

    private void EditFollowUpMessage(object? parameter)
    {
        if (!CanEditFollowUps() || parameter is not FollowUpMessageItem item)
        {
            return;
        }

        CollapseFollowUpEditorsExcept(item);
        item.IsEditing = true;
        SelectedFollowUpMessage = item;
        FollowUpMessageFocusRequested?.Invoke(item, true);
    }

    private void CloseFollowUpMessageEditor(object? parameter)
    {
        if (parameter is not FollowUpMessageItem item)
        {
            return;
        }

        item.IsEditing = false;
        SelectedFollowUpMessage = item;
        FollowUpMessageFocusRequested?.Invoke(item, false);
    }

    private bool CanRequestFollowUpAttachments(object? parameter) =>
        CanEditFollowUps() &&
        parameter is FollowUpMessageItem item &&
        FollowUpMessages.Contains(item) &&
        item.AttachmentCount < Settings.AttachmentLimits.MaximumAttachmentsPerMessage &&
        !item.HasAttachmentLimitError;

    private void RequestFollowUpAttachmentPicker(object? parameter)
    {
        if (!CanRequestFollowUpAttachments(parameter) || parameter is not FollowUpMessageItem item)
        {
            return;
        }

        SelectedFollowUpMessage = item;
        FollowUpAttachmentPickerRequested?.Invoke(item);
    }

    private bool CanRemoveFollowUpAttachment(object? parameter) =>
        CanEditFollowUps() &&
        parameter is AttachmentItemViewModel attachment &&
        FollowUpMessages.Any(message => message.Attachments.Contains(attachment));

    private void RemoveFollowUpAttachment(object? parameter)
    {
        if (!CanRemoveFollowUpAttachment(parameter) || parameter is not AttachmentItemViewModel attachment)
        {
            return;
        }

        var owner = FollowUpMessages.First(message => message.Attachments.Contains(attachment));
        owner.Attachments.Remove(attachment);
        RenumberFollowUpAttachments(owner);
        SelectedFollowUpMessage = owner;
    }

    private void CollapseFollowUpEditorsExcept(FollowUpMessageItem? item)
    {
        foreach (var candidate in FollowUpMessages)
        {
            if (!ReferenceEquals(candidate, item))
            {
                candidate.IsEditing = false;
            }
        }
    }

    private void RemoveFollowUpMessage(object? parameter)
    {
        var item = parameter as FollowUpMessageItem ?? SelectedFollowUpMessage;
        if (!CanEditFollowUps() || item is null)
        {
            return;
        }

        var index = FollowUpMessages.IndexOf(item);
        DetachFollowUpMessage(item);
        FollowUpMessages.Remove(item);
        RenumberFollowUpMessages();
        SelectedFollowUpMessage = FollowUpMessages.Count == 0
            ? null
            : FollowUpMessages[Math.Min(index, FollowUpMessages.Count - 1)];
        MarkFollowUpEditorDirty();
        if (SelectedFollowUpMessage is not null)
        {
            FollowUpMessageFocusRequested?.Invoke(SelectedFollowUpMessage, true);
        }
    }

    internal bool MoveFollowUpMessage(FollowUpMessageItem item, int targetIndex)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (!CanEditFollowUps())
        {
            return false;
        }

        var current = FollowUpMessages.IndexOf(item);
        if (current < 0 || targetIndex < 0 || targetIndex >= FollowUpMessages.Count ||
            current == targetIndex)
        {
            return false;
        }

        FollowUpMessages.Move(current, targetIndex);
        SelectedFollowUpMessage = item;
        RenumberFollowUpMessages();
        MarkFollowUpEditorDirty();
        return true;
    }

    internal static bool MoveFollowUpAttachmentDraft(
        FollowUpMessageItem message,
        AttachmentItemViewModel attachment,
        int targetIndex)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(attachment);

        var currentIndex = message.Attachments.IndexOf(attachment);
        if (currentIndex < 0 || targetIndex < 0 || targetIndex >= message.Attachments.Count ||
            currentIndex == targetIndex)
        {
            return false;
        }

        message.Attachments.Move(currentIndex, targetIndex);
        RenumberFollowUpAttachments(message);
        return true;
    }

    private async Task SaveFollowUpMessagesAsync()
    {
        var task = SelectedTask;
        if (task is null || task.IsArchived)
        {
            return;
        }

        var definitions = new List<FollowUpMessageDefinition>(FollowUpMessages.Count);
        var attachmentSaveCandidates =
            new List<FollowUpAttachmentSaveCandidate>(FollowUpMessages.Count);
        var workflowDrafts = new List<WorkflowRuleEditorDraft>(FollowUpMessages.Count);
        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < FollowUpMessages.Count; index++)
        {
            var item = FollowUpMessages[index];
            var message = SettingsService.NormalizeFollowUpMessage(item.Message);
            if (!HasSaveableFollowUpContent(item) || !Guid.TryParse(item.Id, out var parsedId) ||
                !seenIds.Add(parsedId.ToString("D")))
            {
                FollowUpEditorStatus = L("FollowUp.InvalidMessage", index + 1);
                return;
            }

            var attachments = item.Attachments
                .Select((attachment, attachmentOrder) =>
                    attachment.ToReference() with { Order = attachmentOrder })
                .ToList();
            var normalizedAttachments = SettingsService.NormalizeAttachments(
                attachments,
                Settings.AttachmentLimits);
            if (item.HasInvalidAttachments ||
                attachments.Count != normalizedAttachments.Count ||
                !attachments.SequenceEqual(normalizedAttachments))
            {
                CollapseFollowUpEditorsExcept(item);
                item.IsEditing = true;
                SelectedFollowUpMessage = item;
                FollowUpEditorStatus = L("FollowUp.InvalidAttachments", index + 1);
                FollowUpMessageFocusRequested?.Invoke(item, true);
                return;
            }

            if (attachments.Count > 0)
            {
                try
                {
                    attachmentSaveCandidates.Add(new FollowUpAttachmentSaveCandidate(
                        index + 1,
                        StructuredPresetPayload.Create(
                            message,
                            attachments,
                            Settings.AttachmentLimits)));
                }
                catch (ArgumentException)
                {
                    CollapseFollowUpEditorsExcept(item);
                    item.IsEditing = true;
                    SelectedFollowUpMessage = item;
                    FollowUpEditorStatus = L("FollowUp.InvalidAttachments", index + 1);
                    FollowUpMessageFocusRequested?.Invoke(item, true);
                    return;
                }
            }

            DateTimeOffset? legacyScheduledAtUtc = null;
            if (item.Trigger == FollowUpTriggerKind.ScheduledAt)
            {
                if (!TryConvertLocalScheduleToUtc(
                        item.ScheduledDateLocal,
                        item.ScheduledTimeText,
                        TimeZoneInfo.Local,
                        out var convertedSchedule))
                {
                    FollowUpEditorStatus = L("FollowUp.InvalidSchedule", index + 1);
                    return;
                }

                legacyScheduledAtUtc = convertedSchedule;
            }

            DateTimeOffset? workflowScheduledAtUtc = null;
            if (item.UseWorkflowAutomation)
            {
                if (!CanEditWorkflowRules)
                {
                    CollapseFollowUpEditorsExcept(item);
                    item.IsEditing = true;
                    SelectedFollowUpMessage = item;
                    FollowUpEditorStatus = L("Workflow.StoreCannotSave");
                    FollowUpMessageFocusRequested?.Invoke(item, true);
                    return;
                }

                if (item.IsWorkflowScheduled)
                {
                    if (!TryConvertLocalScheduleToUtc(
                            item.WorkflowScheduledDateLocal,
                            item.WorkflowScheduledTimeText,
                            TimeZoneInfo.Local,
                            out var convertedWorkflowSchedule))
                    {
                        CollapseFollowUpEditorsExcept(item);
                        item.IsEditing = true;
                        SelectedFollowUpMessage = item;
                        FollowUpEditorStatus = L("Workflow.InvalidSchedule", index + 1);
                        FollowUpMessageFocusRequested?.Invoke(item, true);
                        return;
                    }

                    workflowScheduledAtUtc = convertedWorkflowSchedule;
                }
                else if (!IsSelectableWorkflowConversation(item.WorkflowSourceConversationId))
                {
                    CollapseFollowUpEditorsExcept(item);
                    item.IsEditing = true;
                    SelectedFollowUpMessage = item;
                    FollowUpEditorStatus = L("Workflow.InvalidSource", index + 1);
                    FollowUpMessageFocusRequested?.Invoke(item, true);
                    return;
                }

                if (item.WorkflowNeedsSourcePreset &&
                    !item.WorkflowSourcePresetOptions.Any(option =>
                        option.IsSelectable &&
                        string.Equals(
                            option.MessageId,
                            item.WorkflowSourcePresetMessageId,
                            StringComparison.OrdinalIgnoreCase)))
                {
                    CollapseFollowUpEditorsExcept(item);
                    item.IsEditing = true;
                    SelectedFollowUpMessage = item;
                    FollowUpEditorStatus = L("Workflow.InvalidSourcePreset", index + 1);
                    FollowUpMessageFocusRequested?.Invoke(item, true);
                    return;
                }

                if (item.WorkflowTargetsExistingConversation &&
                    !IsSelectableWorkflowConversation(item.WorkflowTargetConversationId))
                {
                    CollapseFollowUpEditorsExcept(item);
                    item.IsEditing = true;
                    SelectedFollowUpMessage = item;
                    FollowUpEditorStatus = L("Workflow.InvalidTarget", index + 1);
                    FollowUpMessageFocusRequested?.Invoke(item, true);
                    return;
                }

                if (item.WorkflowTargetsNewConversation &&
                    !IsNewConversationWorkflowAvailable &&
                    !item.HasStoredWorkflowRule)
                {
                    CollapseFollowUpEditorsExcept(item);
                    item.IsEditing = true;
                    SelectedFollowUpMessage = item;
                    FollowUpEditorStatus = L("Workflow.NewConversationUnavailable");
                    FollowUpMessageFocusRequested?.Invoke(item, true);
                    return;
                }

                workflowDrafts.Add(new WorkflowRuleEditorDraft(
                    parsedId.ToString("D"),
                    item.IsEnabled,
                    item.WorkflowTrigger,
                    item.WorkflowSourceConversationId,
                    item.WorkflowSourcePresetMessageId,
                    workflowScheduledAtUtc,
                    item.WorkflowDestination,
                    item.WorkflowTargetConversationId,
                    item.WorkflowEnableTargetProtection));
            }

            if (!item.TryGetMaximumErrorRetries(out var maximumErrorRetries))
            {
                CollapseFollowUpEditorsExcept(item);
                item.IsEditing = true;
                SelectedFollowUpMessage = item;
                FollowUpEditorStatus = L(
                    "FollowUp.InvalidRetry",
                    index + 1,
                    FollowUpRetryPolicy.MaximumErrorRetriesLimit);
                FollowUpMessageFocusRequested?.Invoke(item, true);
                return;
            }

            definitions.Add(new FollowUpMessageDefinition
            {
                Id = parsedId.ToString("D"),
                Message = message,
                Attachments = attachments,
                Trigger = item.Trigger,
                ScheduledAtUtc = legacyScheduledAtUtc,
                IsEnabled = item.IsEnabled,
                UseWorkflowAutomation = item.UseWorkflowAutomation,
                RetryIndefinitely = item.RetryIndefinitely,
                MaximumErrorRetries = maximumErrorRetries,
                Order = index
            });
        }

        var needsCompletionAnchor = SelectedFollowUpsEnabled && definitions.Any(definition =>
            definition.IsEnabled &&
            !definition.UseWorkflowAutomation &&
            definition.Trigger == FollowUpTriggerKind.AfterNormalCompletion);
        var completionAnchor = needsCompletionAnchor
            ? task.CompletionAnchorTurnId
            : null;
        if (needsCompletionAnchor && !task.CanArmCompletionFollowUps)
        {
            FollowUpEditorStatus = L("FollowUp.NoCompletionBaseline");
            return;
        }

        if (attachmentSaveCandidates.Count > 0)
        {
            var capabilityResult = _attachmentComposition is null
                ? FollowUpAttachmentSaveCapabilityResult.Waiting(
                    attachmentSaveCandidates[0].MessageNumber,
                    "capability-provider-unavailable")
                : await _attachmentComposition.ValidateSaveAsync(
                    Settings,
                    attachmentSaveCandidates,
                    CancellationToken.None);
            if (!capabilityResult.CanSave)
            {
                var messageIndex = capabilityResult.MessageNumber - 1;
                if (messageIndex >= 0 && messageIndex < FollowUpMessages.Count)
                {
                    var item = FollowUpMessages[messageIndex];
                    CollapseFollowUpEditorsExcept(item);
                    item.IsEditing = true;
                    SelectedFollowUpMessage = item;
                    FollowUpMessageFocusRequested?.Invoke(item, true);
                }

                FollowUpEditorStatus = capabilityResult.Status ==
                    FollowUpAttachmentSaveCapabilityStatus.Waiting
                    ? L("FollowUp.AttachmentCapabilityWaiting", capabilityResult.MessageNumber)
                    : L("FollowUp.AttachmentCapabilityUnsupported", capabilityResult.MessageNumber);
                return;
            }
        }

        var configured = definitions.Count == 0
            ? null
            : new ThreadFollowUpSettings
            {
                IsEnabled = SelectedFollowUpsEnabled,
                CompletionAnchorTurnId = completionAnchor,
                Messages = definitions
            };

        WorkflowRuleStoreDurableSnapshot? workflowStoreBeforeSave = null;
        long? workflowStoreCommittedGeneration = null;
        if (_workflowRuleSnapshot is { } currentWorkflowSnapshot && CanEditWorkflowRules)
        {
            IReadOnlyList<WorkflowRuleDefinition> replacement;
            try
            {
                replacement = WorkflowRuleEditor.BuildReplacement(
                    currentWorkflowSnapshot,
                    task.Id,
                    workflowDrafts,
                    DateTimeOffset.UtcNow);
            }
            catch (Exception exception) when (
                exception is ArgumentException or InvalidOperationException or OverflowException)
            {
                FollowUpEditorStatus = L("Workflow.InvalidRule");
                return;
            }

            var validation = WorkflowRuleGraphValidator.Validate(replacement);
            var blockingIssue = validation.Issues.FirstOrDefault(issue =>
                issue.Code != WorkflowRuleValidationIssueCode.NewConversationUnavailable);
            if (blockingIssue is not null)
            {
                FollowUpEditorStatus = blockingIssue.Code == WorkflowRuleValidationIssueCode.CycleDetected
                    ? L("Workflow.CycleRejected")
                    : L("Workflow.InvalidRule");
                return;
            }

            if (!WorkflowRuleSetsEqual(currentWorkflowSnapshot.Rules, replacement))
            {
                try
                {
                    workflowStoreBeforeSave = await _workflowRuleStore
                        .CaptureDurableSnapshotAsync(CancellationToken.None);
                    _workflowRuleSnapshot = await _workflowRuleStore.SaveAsync(replacement);
                    workflowStoreCommittedGeneration = _workflowRuleSnapshot.Generation;
                    _workflowRuleLoadFailed = false;
                    RaiseWorkflowRuleStorePropertiesChanged();
                }
                catch (Exception exception) when (
                    exception is not OperationCanceledException)
                {
                    if (workflowStoreBeforeSave is not null)
                    {
                        var expectedGeneration = workflowStoreCommittedGeneration ??
                            (workflowStoreBeforeSave.LogicalState.Generation == long.MaxValue
                                ? long.MaxValue
                                : workflowStoreBeforeSave.LogicalState.Generation + 1);
                        await TryRestoreWorkflowRuleStoreAsync(
                            workflowStoreBeforeSave,
                            expectedGeneration);
                    }

                    _log.Warning(
                        "Workflow rule save failed (" + exception.GetType().Name + ").");
                    FollowUpEditorStatus = L("Workflow.SaveFailed");
                    return;
                }
            }
        }
        else if (workflowDrafts.Count > 0)
        {
            FollowUpEditorStatus = L("Workflow.StoreCannotSave");
            return;
        }

        for (var index = 0; index < definitions.Count; index++)
        {
            var definition = definitions[index];
            if (!definition.UseWorkflowAutomation)
            {
                continue;
            }

            var boundRule = WorkflowRuleEditor.FindManagedRule(
                _workflowRuleSnapshot,
                task.Id,
                definition.Id);
            if (boundRule is null)
            {
                if (workflowStoreBeforeSave is not null)
                {
                    await TryRestoreWorkflowRuleStoreAsync(
                        workflowStoreBeforeSave,
                        workflowStoreCommittedGeneration ?? workflowStoreBeforeSave.LogicalState.Generation);
                }

                FollowUpEditorStatus = L("Workflow.InvalidRule");
                return;
            }

            definitions[index] = definition with
            {
                WorkflowRuleRevision = boundRule.Revision,
                WorkflowRuleDigest = boundRule.DefinitionDigest
            };
        }

        var hadPrevious = Settings.ThreadFollowUps.TryGetValue(task.Id, out var previous);
        if (configured is null)
        {
            Settings.ThreadFollowUps.TryRemove(task.Id, out _);
        }
        else
        {
            Settings.ThreadFollowUps[task.Id] = configured;
        }

        if (!await SaveSettingsAsync())
        {
            if (hadPrevious && previous is not null)
            {
                Settings.ThreadFollowUps[task.Id] = previous;
            }
            else
            {
                Settings.ThreadFollowUps.TryRemove(task.Id, out _);
            }

            if (workflowStoreBeforeSave is not null)
            {
                await TryRestoreWorkflowRuleStoreAsync(
                    workflowStoreBeforeSave,
                    workflowStoreCommittedGeneration ?? workflowStoreBeforeSave.LogicalState.Generation);
            }

            FollowUpEditorStatus = L("FollowUp.SaveFailed");
            return;
        }

        if (!_previewIsolationMode)
        {
            _engine.SetThreadFollowUps(task.Id, configured);
        }

        task.FollowUpQueueRuntime = null;
        UpdateTaskFollowUpDisplay(task);
        LoadSelectedTaskFollowUps();
        FollowUpEditorStatus = L("FollowUp.Saved", definitions.Count);
    }

    private async Task<bool> TryRestoreWorkflowRuleStoreAsync(
        WorkflowRuleStoreDurableSnapshot snapshot,
        long expectedCurrentGeneration)
    {
        try
        {
            await _workflowRuleStore.RestoreDurableSnapshotAsync(
                    snapshot,
                    expectedCurrentGeneration,
                    CancellationToken.None)
                .ConfigureAwait(true);
            _workflowRuleSnapshot = snapshot.LogicalState;
            _workflowRuleLoadFailed = false;
            RaiseWorkflowRuleStorePropertiesChanged();
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _workflowRuleLoadFailed = true;
            _log.Error(
                "Workflow rule rollback failed (" + exception.GetType().Name + ").");
            RaiseWorkflowRuleStorePropertiesChanged();
            return false;
        }
    }

    private bool IsSelectableWorkflowConversation(string? conversationId) =>
        WorkflowConversationOptions.Any(option =>
            option.IsSelectable &&
            string.Equals(option.Id, conversationId, StringComparison.OrdinalIgnoreCase));

    private static bool WorkflowRuleSetsEqual(
        IReadOnlyList<WorkflowRuleDefinition> first,
        IReadOnlyList<WorkflowRuleDefinition> second) =>
        first.Count == second.Count &&
        first.OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
            .Select(rule => rule.DefinitionDigest)
            .SequenceEqual(
                second.OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
                    .Select(rule => rule.DefinitionDigest),
                StringComparer.Ordinal);

    internal static bool TryConvertLocalScheduleToUtc(
        DateTime? scheduledDate,
        string? scheduledTimeText,
        TimeZoneInfo timeZone,
        out DateTimeOffset scheduledAtUtc)
    {
        ArgumentNullException.ThrowIfNull(timeZone);
        scheduledAtUtc = default;
        if (scheduledDate is null ||
            !TimeSpan.TryParseExact(
                scheduledTimeText?.Trim(),
                @"hh\:mm",
                CultureInfo.InvariantCulture,
                out var scheduledTime))
        {
            return false;
        }

        try
        {
            var local = DateTime.SpecifyKind(
                scheduledDate.Value.Date.Add(scheduledTime),
                DateTimeKind.Unspecified);
            if (timeZone.IsInvalidTime(local) || timeZone.IsAmbiguousTime(local))
            {
                return false;
            }

            scheduledAtUtc = new DateTimeOffset(
                TimeZoneInfo.ConvertTimeToUtc(local, timeZone),
                TimeSpan.Zero);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool HasSaveableFollowUpContent(FollowUpMessageItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return SettingsService.NormalizeFollowUpMessage(item.Message).Length > 0 ||
               item.Attachments.Count > 0;
    }

    private void RenumberFollowUpMessages()
    {
        for (var index = 0; index < FollowUpMessages.Count; index++)
        {
            FollowUpMessages[index].Order = index;
        }
    }

    private static void RenumberFollowUpAttachments(FollowUpMessageItem message)
    {
        for (var index = 0; index < message.Attachments.Count; index++)
        {
            message.Attachments[index].Order = index;
        }
    }

    private void AttachFollowUpMessage(FollowUpMessageItem item) =>
        item.PropertyChanged += OnFollowUpMessagePropertyChanged;

    private void DetachFollowUpMessage(FollowUpMessageItem item) =>
        item.PropertyChanged -= OnFollowUpMessagePropertyChanged;

    private void DetachFollowUpMessageSubscriptions()
    {
        foreach (var item in FollowUpMessages)
        {
            DetachFollowUpMessage(item);
        }
    }

    private void RefreshWorkflowConversationOptions()
    {
        var referencedIds = FollowUpMessages
            .SelectMany(item => new[]
            {
                item.WorkflowSourceConversationId,
                item.WorkflowTargetConversationId
            })
            .Where(static id => !string.IsNullOrWhiteSpace(id))
            .Select(static id => id!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var options = new List<WorkflowConversationOption>(Tasks.Count + referencedIds.Count);
        var observedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var task in Tasks)
        {
            if (!Guid.TryParse(task.Id, out var parsedId) || parsedId == Guid.Empty)
            {
                continue;
            }

            var id = parsedId.ToString("D");
            if (!observedIds.Add(id))
            {
                continue;
            }

            var unavailable = task.IsSubAgent || task.IsEphemeral;
            var busy = IsWorkflowConversationBusy(task);
            var selectable = !task.IsArchived && !unavailable;
            var status = task.IsArchived
                ? L("Workflow.ConversationArchived")
                : unavailable
                    ? L("Workflow.ConversationUnavailable")
                    : busy
                        ? L("Workflow.ConversationBusy")
                        : L("Workflow.ConversationReady");
            options.Add(new WorkflowConversationOption(
                id,
                task.Name,
                status,
                selectable,
                task.IsArchived,
                busy,
                IsMissing: false));
        }

        foreach (var missingId in referencedIds
                     .Where(id => !observedIds.Contains(id))
                     .Order(StringComparer.Ordinal))
        {
            options.Add(new WorkflowConversationOption(
                missingId,
                L("Workflow.MissingConversation"),
                L("Workflow.ConversationMissing"),
                IsSelectable: false,
                IsArchived: false,
                IsBusy: false,
                IsMissing: true));
        }

        WorkflowConversationOptions.Clear();
        foreach (var option in options)
        {
            WorkflowConversationOptions.Add(option);
        }
    }

    private static bool IsWorkflowConversationBusy(GuardianTaskItem task) =>
        task.Health is TaskHealth.Processing or TaskHealth.Recovering ||
        task.TurnStatus is "active" or "inProgress" or "running";

    private void RefreshWorkflowPresetOptions(FollowUpMessageItem item)
    {
        var selectedId = item.WorkflowSourcePresetMessageId;
        var options = new List<WorkflowPresetOption>();
        var observedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sourceId = item.WorkflowSourceConversationId;
        if (!string.IsNullOrWhiteSpace(sourceId) &&
            SelectedTask is { } selectedTask &&
            string.Equals(sourceId, selectedTask.Id, StringComparison.OrdinalIgnoreCase))
        {
            foreach (var candidate in FollowUpMessages)
            {
                if (!observedIds.Add(candidate.Id))
                {
                    continue;
                }

                var hasContent = HasSaveableFollowUpContent(candidate);
                var selectable = candidate.UseWorkflowAutomation && hasContent;
                options.Add(new WorkflowPresetOption(
                    selectedTask.Id,
                    candidate.Id,
                    hasContent ? candidate.ContentPreview : L("Workflow.EmptyPreset"),
                    !candidate.UseWorkflowAutomation
                        ? L("Workflow.PresetSequenceOnly")
                        : !candidate.IsEnabled
                            ? L("Workflow.PresetDisabled")
                            : L("Workflow.PresetReady"),
                    selectable,
                    IsMissing: false));
            }
        }
        else if (!string.IsNullOrWhiteSpace(sourceId) &&
                 Settings.ThreadFollowUps.TryGetValue(sourceId, out var configured))
        {
            foreach (var candidate in configured.Messages.OrderBy(message => message.Order))
            {
                if (!observedIds.Add(candidate.Id))
                {
                    continue;
                }

                var preview = CreatePresetPreview(candidate);
                options.Add(new WorkflowPresetOption(
                    sourceId,
                    candidate.Id,
                    preview,
                    !candidate.UseWorkflowAutomation
                        ? L("Workflow.PresetSequenceOnly")
                        : !candidate.IsEnabled
                            ? L("Workflow.PresetDisabled")
                            : L("Workflow.PresetReady"),
                    candidate.UseWorkflowAutomation,
                    IsMissing: false));
            }
        }

        if (!string.IsNullOrWhiteSpace(selectedId) && !observedIds.Contains(selectedId))
        {
            options.Add(new WorkflowPresetOption(
                sourceId ?? string.Empty,
                selectedId,
                L("Workflow.MissingPreset"),
                L("Workflow.PresetMissing"),
                IsSelectable: false,
                IsMissing: true));
        }

        item.WorkflowSourcePresetOptions.Clear();
        foreach (var option in options)
        {
            item.WorkflowSourcePresetOptions.Add(option);
        }
    }

    private static string CreatePresetPreview(FollowUpMessageDefinition definition)
    {
        var normalized = string.Join(
            " ",
            (definition.Message ?? string.Empty).Split(
                ['\r', '\n', '\t'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        if (normalized.Length > 0)
        {
            return normalized.Length <= 80 ? normalized : normalized[..79] + "…";
        }

        return definition.Attachments.FirstOrDefault()?.OriginalFileName ?? string.Empty;
    }

    private void RefreshAllWorkflowPresetOptions()
    {
        foreach (var candidate in FollowUpMessages)
        {
            RefreshWorkflowPresetOptions(candidate);
            RefreshWorkflowItemProjection(candidate);
        }
    }

    private void RefreshWorkflowItemProjection(FollowUpMessageItem item)
    {
        if (!item.UseWorkflowAutomation)
        {
            item.WorkflowTriggerText = string.Empty;
            item.WorkflowDestinationText = string.Empty;
            item.WorkflowActionText = string.Empty;
            item.WorkflowRuleStatusText = string.Empty;
            return;
        }

        var source = WorkflowConversationOptions.FirstOrDefault(option => string.Equals(
            option.Id,
            item.WorkflowSourceConversationId,
            StringComparison.OrdinalIgnoreCase));
        var sourcePreset = item.WorkflowSourcePresetOptions.FirstOrDefault(option => string.Equals(
            option.MessageId,
            item.WorkflowSourcePresetMessageId,
            StringComparison.OrdinalIgnoreCase));
        item.WorkflowTriggerText = item.WorkflowTrigger switch
        {
            WorkflowTriggerKind.ScheduledAt => item.WorkflowScheduleSummary.Length > 0
                ? item.WorkflowScheduleSummary
                : L("Workflow.TriggerScheduled"),
            WorkflowTriggerKind.ConversationCompletedNormally => L(
                "Workflow.TriggerCompletionChip",
                source?.Name ?? L("Workflow.SelectConversation")),
            WorkflowTriggerKind.PresetDispatchConfirmed => L(
                "Workflow.TriggerPresetChip",
                sourcePreset?.Preview ?? L("Workflow.SelectPreset")),
            _ => L("Workflow.InvalidRule")
        };
        item.WorkflowDestinationText = item.WorkflowDestination switch
        {
            WorkflowDestinationKind.CurrentConversation => L("Workflow.DestinationCurrent"),
            WorkflowDestinationKind.ExistingConversation =>
                WorkflowConversationOptions.FirstOrDefault(option => string.Equals(
                    option.Id,
                    item.WorkflowTargetConversationId,
                    StringComparison.OrdinalIgnoreCase))?.Name ?? L("Workflow.SelectConversation"),
            WorkflowDestinationKind.NewConversation => L("Workflow.DestinationNew"),
            _ => L("Workflow.InvalidRule")
        };
        item.WorkflowActionText = item.WorkflowEnableTargetProtection
            ? L("Workflow.ActionSendAndProtect")
            : L("Workflow.ActionSend");
        item.WorkflowRuleStatusText = !CanEditWorkflowRules
            ? WorkflowRuleStoreStatusText
            : !item.WorkflowRuleBindingCurrent
                ? L("Workflow.RulePending")
                : item.WorkflowTargetsNewConversation && !IsNewConversationWorkflowAvailable
                    ? L("Workflow.CapabilityUnavailable")
                    : item.WorkflowNeedsSourceConversation && source?.IsSelectable != true
                        ? L("Workflow.SelectConversation")
                        : item.WorkflowNeedsSourcePreset && sourcePreset?.IsSelectable != true
                            ? L("Workflow.SelectPreset")
                            : item.WorkflowTargetsExistingConversation &&
                              !IsSelectableWorkflowConversation(item.WorkflowTargetConversationId)
                                ? L("Workflow.SelectTarget")
                                : string.Empty;
    }

    private void OnFollowUpMessagePropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (_isLoadingFollowUpEditor || sender is not FollowUpMessageItem item)
        {
            return;
        }

        if (string.IsNullOrEmpty(eventArgs.PropertyName) ||
            eventArgs.PropertyName is nameof(FollowUpMessageItem.Message) or
                nameof(FollowUpMessageItem.Trigger) or
                nameof(FollowUpMessageItem.ScheduledDateLocal) or
                nameof(FollowUpMessageItem.ScheduledTimeText) or
                nameof(FollowUpMessageItem.MaximumErrorRetriesText) or
                nameof(FollowUpMessageItem.RetryIndefinitely) or
                nameof(FollowUpMessageItem.IsEnabled) or
                nameof(FollowUpMessageItem.UseWorkflowAutomation) or
                nameof(FollowUpMessageItem.WorkflowTrigger) or
                nameof(FollowUpMessageItem.WorkflowScheduledDateLocal) or
                nameof(FollowUpMessageItem.WorkflowScheduledTimeText) or
                nameof(FollowUpMessageItem.WorkflowSourceConversationId) or
                nameof(FollowUpMessageItem.WorkflowSourcePresetMessageId) or
                nameof(FollowUpMessageItem.WorkflowDestination) or
                nameof(FollowUpMessageItem.WorkflowTargetConversationId) or
                nameof(FollowUpMessageItem.WorkflowEnableTargetProtection) or
                nameof(FollowUpMessageItem.AttachmentCount))
        {
            MarkFollowUpEditorDirty();
        }

        if (eventArgs.PropertyName == nameof(FollowUpMessageItem.WorkflowTrigger) &&
            item.IsWorkflowScheduled && item.WorkflowScheduledDateLocal is null)
        {
            var suggested = DateTime.Now.AddHours(1);
            item.WorkflowScheduledDateLocal = suggested.Date;
            item.WorkflowScheduledTimeText = suggested.ToString("HH:mm", CultureInfo.InvariantCulture);
        }

        if (eventArgs.PropertyName == nameof(FollowUpMessageItem.UseWorkflowAutomation) &&
            item.UseWorkflowAutomation && string.IsNullOrWhiteSpace(item.WorkflowSourceConversationId))
        {
            item.WorkflowSourceConversationId = SelectedTask?.Id;
        }

        if (eventArgs.PropertyName == nameof(FollowUpMessageItem.WorkflowSourceConversationId))
        {
            RefreshWorkflowPresetOptions(item);
            if (item.WorkflowNeedsSourcePreset &&
                !item.WorkflowSourcePresetOptions.Any(option => string.Equals(
                    option.MessageId,
                    item.WorkflowSourcePresetMessageId,
                    StringComparison.OrdinalIgnoreCase)))
            {
                item.WorkflowSourcePresetMessageId = item.WorkflowSourcePresetOptions
                    .FirstOrDefault(option => option.IsSelectable)?.MessageId;
            }
        }

        if (eventArgs.PropertyName == nameof(FollowUpMessageItem.WorkflowTrigger) &&
            item.WorkflowNeedsSourcePreset &&
            string.IsNullOrWhiteSpace(item.WorkflowSourcePresetMessageId))
        {
            RefreshWorkflowPresetOptions(item);
            item.WorkflowSourcePresetMessageId = item.WorkflowSourcePresetOptions
                .FirstOrDefault(option => option.IsSelectable)?.MessageId;
        }

        if (eventArgs.PropertyName == nameof(FollowUpMessageItem.WorkflowDestination) &&
            item.WorkflowTargetsExistingConversation &&
            !IsSelectableWorkflowConversation(item.WorkflowTargetConversationId))
        {
            item.WorkflowTargetConversationId = WorkflowConversationOptions
                .FirstOrDefault(option => option.IsSelectable)?.Id;
        }

        if (eventArgs.PropertyName is nameof(FollowUpMessageItem.Message) or
            nameof(FollowUpMessageItem.IsEnabled) or
            nameof(FollowUpMessageItem.UseWorkflowAutomation) or
            nameof(FollowUpMessageItem.AttachmentCount))
        {
            RefreshAllWorkflowPresetOptions();
        }
        else
        {
            RefreshWorkflowItemProjection(item);
        }

        if (string.IsNullOrEmpty(eventArgs.PropertyName) ||
            eventArgs.PropertyName is nameof(FollowUpMessageItem.AttachmentCount) or
                nameof(FollowUpMessageItem.HasAttachmentLimitError))
        {
            RaiseFollowUpCommandCanExecuteChanged();
        }
    }

    private void MarkFollowUpEditorDirty()
    {
        if (_isLoadingFollowUpEditor || SelectedTask is null)
        {
            return;
        }

        SetFollowUpEditorDirty(true);
        PublishVisibleAttachmentDrafts(incrementVersion: true);
        FollowUpEditorStatus = L("FollowUp.Unsaved");
    }

    private void PublishVisibleAttachmentDrafts(bool incrementVersion)
    {
        if (incrementVersion)
        {
            _attachmentDraftVersion = checked(_attachmentDraftVersion + 1);
        }

        _attachmentDraftAuthority?.ReplaceVisibleDrafts(
            _attachmentDraftVersion,
            FollowUpMessages
                .SelectMany(static message => message.Attachments)
                .Select(static attachment => attachment.ToReference())
                .ToArray());
    }

    private void SetFollowUpEditorDirty(bool value)
    {
        if (_isFollowUpEditorDirty == value)
        {
            return;
        }

        _isFollowUpEditorDirty = value;
        OnPropertyChanged(nameof(HasUnsavedFollowUpChanges));
        RaiseFollowUpCommandCanExecuteChanged();
        RaiseConversationMutationCommandCanExecuteChanged();
    }

    internal void DiscardFollowUpChanges()
    {
        LoadSelectedTaskFollowUps();
    }

    private void RestoreSelectedTaskBinding()
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.HasShutdownStarted || dispatcher.HasShutdownFinished)
        {
            OnPropertyChanged(nameof(SelectedTask));
            return;
        }

        _ = dispatcher.BeginInvoke(
            DispatcherPriority.DataBind,
            new Action(() => OnPropertyChanged(nameof(SelectedTask))));
    }

    private void RaiseFollowUpCommandCanExecuteChanged()
    {
        _addFollowUpMessageCommand.RaiseCanExecuteChanged();
        _removeFollowUpMessageCommand.RaiseCanExecuteChanged();
        _editFollowUpMessageCommand.RaiseCanExecuteChanged();
        _closeFollowUpMessageEditorCommand.RaiseCanExecuteChanged();
        _requestFollowUpAttachmentPickerCommand.RaiseCanExecuteChanged();
        _removeFollowUpAttachmentCommand.RaiseCanExecuteChanged();
        _saveFollowUpMessagesCommand.RaiseCanExecuteChanged();
    }

    private void OnSnapshotUpdated(object? sender, GuardianTaskSnapshot snapshot)
    {
        lock (_snapshotDispatchSync)
        {
            _pendingSnapshot = snapshot;
            if (_snapshotDispatchScheduled)
            {
                return;
            }

            _snapshotDispatchScheduled = true;
        }

        Dispatch(ApplyPendingSnapshot);
    }

    private void ApplyPendingSnapshot()
    {
        GuardianTaskSnapshot? snapshot;
        lock (_snapshotDispatchSync)
        {
            snapshot = _pendingSnapshot;
            _pendingSnapshot = null;
            _snapshotDispatchScheduled = false;
        }

        if (snapshot is not null)
        {
            ApplySnapshot(snapshot);
        }
    }

    internal void ApplySnapshot(GuardianTaskSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(snapshot.States);
        ArgumentNullException.ThrowIfNull(snapshot.Statistics);

        var statesById = new Dictionary<string, GuardianTaskState>(StringComparer.Ordinal);
        var incomingStates = new List<GuardianTaskState>(snapshot.States.Count);
        foreach (var state in snapshot.States)
        {
            if (statesById.TryAdd(state.Thread.Id, state))
            {
                incomingStates.Add(state);
            }
        }
        QueueConversationProtectionInitialization(incomingStates);
        var orderedStates = ApplyConversationOrder(incomingStates);
        var incomingIds = statesById.Keys.ToHashSet(StringComparer.Ordinal);

        for (var index = Tasks.Count - 1; index >= 0; index--)
        {
            var item = Tasks[index];
            if (incomingIds.Contains(item.Id))
            {
                continue;
            }

            item.EnabledChanged -= OnTaskEnabledChanged;
            InvalidateConversationMutation(item.Id);
            Tasks.RemoveAt(index);
            _tasksById.Remove(item.Id);
        }

        for (var targetIndex = 0; targetIndex < orderedStates.Count; targetIndex++)
        {
            var state = orderedStates[targetIndex];
            if (!_tasksById.TryGetValue(state.Thread.Id, out var item))
            {
                item = CreateTaskItem(state);
                item.EnabledChanged += OnTaskEnabledChanged;
                _tasksById.Add(item.Id, item);
                Tasks.Insert(Math.Min(targetIndex, Tasks.Count), item);
            }
            else
            {
                if (ConversationMutationBoundaryChanged(item, state))
                {
                    InvalidateConversationMutation(item.Id);
                    item.IsDeleteConfirmationOpen = false;
                    ClearConversationMutationStatus(item);
                }

                UpdateTaskItem(item, state);
                var currentIndex = Tasks.IndexOf(item);
                if (currentIndex != targetIndex)
                {
                    Tasks.Move(currentIndex, targetIndex);
                }
            }
        }

        _snapshotStatistics = snapshot.Statistics;
        RefreshWorkflowConversationOptions();
        RefreshAllWorkflowPresetOptions();
        RefreshKeepAliveRuntime();
        RefreshTaskFilter();
        UpdateTaskMetrics();
        OnPropertyChanged(nameof(CanEditSelectedFollowUps));
        OnPropertyChanged(nameof(SelectedTaskFollowUpTitle));
        RaiseFollowUpCommandCanExecuteChanged();
        RaiseConversationMutationCommandCanExecuteChanged();
        OnPropertyChanged(nameof(TaskSessionSummaryText));
        OnPropertyChanged(nameof(TaskFilterSummaryText));
        LastScanText = _engine.LastScanAt?.ToString("HH:mm:ss", _localization.CurrentCulture) ?? L("Value.Never");
        ServerVersion = IsOnline ? L("Status.LocalServiceConnected") : L("Status.NotConnected");
        if (_workflowLineageSnapshot is not null)
        {
            ApplyWorkflowLineageSnapshot(
                _workflowLineageSnapshot,
                forceLocalizedRefresh: true);
        }

        // Counterpart to the engine's "Published a task snapshot" line. If the engine reports N tasks
        // carrying a resend ledger and this reports 0, the loss is in the window, not the engine; if
        // both report the same number while the panel still shows nothing, the loss is in the binding.
        _log.Trace(
            "Applied a task snapshot: " +
            Tasks.Count.ToString(CultureInfo.InvariantCulture) +
            " task(s), " +
            Tasks.Count(task => task.RecoveryLedger.ConfirmedDispatches > 0)
                .ToString(CultureInfo.InvariantCulture) +
            " carrying a non-zero resend ledger.");
    }

    private void QueueConversationProtectionInitialization(
        IReadOnlyCollection<GuardianTaskState> states)
    {
        if (_previewIsolationMode || !CanEnableConversationProtection)
        {
            return;
        }

        var candidates = states
            .Where(state =>
                !state.Thread.IsArchived &&
                !state.Thread.IsEphemeral &&
                (!state.Thread.IsSubAgent || Settings.IncludeSubAgents) &&
                Guid.TryParse(state.Thread.Id, out var parsed) &&
                parsed != Guid.Empty)
            .Select(state => Guid.Parse(state.Thread.Id).ToString("D"))
            .Where(threadId => !Settings.ThreadProtectionEnabled.ContainsKey(threadId))
            .Where(threadId => _protectionInitializationInFlight.Add(threadId))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (candidates.Length == 0)
        {
            return;
        }

        _ = PersistConversationProtectionDefaultsAsync(
            candidates,
            Settings.ProtectNewThreadsByDefault);
    }

    private async Task PersistConversationProtectionDefaultsAsync(
        IReadOnlyList<string> conversationIds,
        bool defaultEnabled)
    {
        try
        {
            var committed = await _settingsService
                .InitializeConversationProtectionDefaultsAsync(
                    conversationIds,
                    defaultEnabled)
                .ConfigureAwait(false);
            Dispatch(() =>
            {
                foreach (var conversationId in conversationIds)
                {
                    _protectionInitializationInFlight.Remove(conversationId);
                    if (!committed.ThreadProtectionEnabled.TryGetValue(
                            conversationId,
                            out var selected))
                    {
                        continue;
                    }

                    // A user can change the switch while the first-discovery write is in
                    // flight. Only the owner that successfully filled a still-missing map
                    // entry may project the default back into the item; a false result means
                    // the user (or another authority) already selected a value.
                    if (!_engine.TryInitializeThreadProtection(conversationId, selected))
                    {
                        continue;
                    }

                    if (_tasksById.TryGetValue(conversationId, out var item))
                    {
                        item.SetEnabledFromSnapshot(selected);
                        item.ProtectionText = item.IsArchived || selected
                            ? string.Empty
                            : L("Tasks.ProtectionPaused");
                    }
                }

                Settings.ReadStatus = committed.ReadStatus;
                Settings.SettingsGeneration = committed.SettingsGeneration;
                Settings.PreviousSettingsGeneration = committed.PreviousSettingsGeneration;
                UpdateTaskMetrics();
            });
        }
        catch (Exception exception)
        {
            Dispatch(() =>
            {
                foreach (var conversationId in conversationIds)
                {
                    _protectionInitializationInFlight.Remove(conversationId);
                }
            });
            _log.Error("无法初始化新对话保护设置：" + exception.Message);
        }
    }

    private async Task LoadConversationMutationJournalAsync(CancellationToken cancellationToken)
    {
        if (_conversationMutations is null)
        {
            return;
        }

        try
        {
            var snapshot = await _conversationMutations.ReadJournalAsync(cancellationToken);
            _uncertainConversationMutations.Clear();
            foreach (var record in snapshot.Records)
            {
                if (record.State == ConversationMutationOperationState.Uncertain)
                {
                    _uncertainConversationMutations.Add(record.ThreadId);
                }
            }

            foreach (var task in Tasks)
            {
                UpdateConversationMutationDisplay(task);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _log.Warning(
                "Conversation mutation journal initialization failed (" +
                exception.GetType().Name + ").");
        }
    }

    private void ExecuteUnarchiveConversation(object? parameter)
    {
        if (parameter is GuardianTaskItem item && CanUnarchiveConversation(item))
        {
            _ = ExecuteConversationMutationAsync(
                item,
                ConversationMutationKind.Unarchive,
                deleteConfirmed: false);
        }
    }

    private void RequestDeleteConversation(object? parameter)
    {
        if (parameter is not GuardianTaskItem item || !CanRequestDeleteConversation(item))
        {
            return;
        }

        ClearConversationMutationStatus(item);
        item.IsDeleteConfirmationOpen = true;
        RaiseConversationMutationCommandCanExecuteChanged();
    }

    private void ConfirmDeleteConversation(object? parameter)
    {
        if (parameter is GuardianTaskItem item && CanConfirmDeleteConversation(item))
        {
            _ = ExecuteConversationMutationAsync(
                item,
                ConversationMutationKind.Delete,
                deleteConfirmed: true);
        }
    }

    private void CancelDeleteConversation(object? parameter)
    {
        if (parameter is not GuardianTaskItem item || !CanCancelDeleteConversation(item))
        {
            return;
        }

        item.IsDeleteConfirmationOpen = false;
        ClearConversationMutationStatus(item);
        RaiseConversationMutationCommandCanExecuteChanged();
    }

    private bool CanUnarchiveConversation(object? parameter) =>
        parameter is GuardianTaskItem { IsDeleteConfirmationOpen: false } item &&
        CanStartConversationMutation(item, ConversationMutationKind.Unarchive);

    private bool CanRequestDeleteConversation(object? parameter) =>
        parameter is GuardianTaskItem { IsDeleteConfirmationOpen: false } item &&
        CanStartConversationMutation(item, ConversationMutationKind.Delete);

    private bool CanConfirmDeleteConversation(object? parameter) =>
        parameter is GuardianTaskItem { IsDeleteConfirmationOpen: true } item &&
        CanStartConversationMutation(item, ConversationMutationKind.Delete);

    private bool CanCancelDeleteConversation(object? parameter) =>
        parameter is GuardianTaskItem
        {
            IsArchived: true,
            IsDeleteConfirmationOpen: true,
            IsConversationMutationPending: false
        } item &&
        _tasksById.TryGetValue(item.Id, out var current) &&
        ReferenceEquals(current, item);

    private bool CanStartConversationMutation(
        GuardianTaskItem item,
        ConversationMutationKind kind) =>
        !_previewIsolationMode &&
        Volatile.Read(ref _disposeStarted) == 0 &&
        Volatile.Read(ref _activeConversationMutation) is null &&
        _conversationMutations is not null &&
        _conversationMutations.CanExecute(kind) &&
        item.IsArchived &&
        !item.IsSubAgent &&
        !item.IsEphemeral &&
        !item.IsConversationMutationPending &&
        Guid.TryParse(item.Id, out _) &&
        Guid.TryParse(item.LatestTurnId, out _) &&
        _tasksById.TryGetValue(item.Id, out var current) &&
        ReferenceEquals(current, item) &&
        !(ReferenceEquals(SelectedTask, item) && _isFollowUpEditorDirty);

    private async Task ExecuteConversationMutationAsync(
        GuardianTaskItem item,
        ConversationMutationKind kind,
        bool deleteConfirmed)
    {
        var service = _conversationMutations;
        if (service is null || !CanStartConversationMutation(item, kind))
        {
            return;
        }

        var thread = new ThreadSummary(
            item.Id,
            item.Name,
            item.Preview,
            item.Cwd,
            item.RawSource,
            item.CreatedAt.ToUnixTimeSeconds(),
            item.UpdatedAt.ToUnixTimeSeconds(),
            item.IsSubAgent,
            item.IsEphemeral,
            IsArchived: item.IsArchived);
        var lease = new ConversationMutationUiLease(
            item.Id,
            thread.UpdatedAt,
            item.LatestTurnId);
        if (Interlocked.CompareExchange(
                ref _activeConversationMutation,
                lease,
                comparand: null) is not null)
        {
            return;
        }

        item.IsDeleteConfirmationOpen = false;
        item.IsConversationMutationPending = true;
        SetConversationMutationStatus(item, "Tasks.MutationPending");
        RaiseConversationMutationCommandCanExecuteChanged();

        try
        {
            var result = await service.ExecuteAsync(
                new ConversationMutationRequest(
                    thread,
                    kind,
                    item.LatestTurnId,
                    deleteConfirmed,
                    HasDirtyDraft: ReferenceEquals(SelectedTask, item) && _isFollowUpEditorDirty,
                    IsStillAllowed: lease.IsAllowed),
                CancellationToken.None);
            if (result.Success && result.Applied)
            {
                ApplyConversationMutationSuccess(item, kind, result);
            }
            else
            {
                ApplyConversationMutationFailure(item, kind, result.FailureKind);
            }
        }
        catch (Exception exception)
        {
            _log.Warning(
                "Conversation mutation UI operation failed (" +
                exception.GetType().Name + ").",
                item.Id);
            SetConversationMutationStatus(item, "Tasks.MutationFailed");
        }
        finally
        {
            lease.Invalidate();
            _ = Interlocked.CompareExchange(
                ref _activeConversationMutation,
                value: null,
                comparand: lease);
            if (_tasksById.TryGetValue(item.Id, out var current) &&
                ReferenceEquals(current, item))
            {
                item.IsConversationMutationPending = false;
                UpdateConversationMutationDisplay(item);
            }

            RaiseConversationMutationCommandCanExecuteChanged();
        }
    }

    private void ApplyConversationMutationSuccess(
        GuardianTaskItem item,
        ConversationMutationKind kind,
        ConversationMutationResult result)
    {
        _uncertainConversationMutations.Remove(item.Id);
        if (kind == ConversationMutationKind.Unarchive &&
            result.AuthoritativeThread is { IsArchived: false } active)
        {
            item.Name = active.Name;
            item.Preview = DisplayConversationPreview(active.Preview, active.Name);
            item.Cwd = active.Cwd;
            item.RawSource = active.Source;
            item.Source = DisplaySource(active.Source);
            item.CreatedAt = DateTimeOffset.FromUnixTimeSeconds(active.CreatedAt);
            item.UpdatedAt = DateTimeOffset.FromUnixTimeSeconds(active.UpdatedAt);
            item.IsArchived = false;
            item.CodexPinnedState = active.IsPinned;
            item.IsPinned = active.IsPinned ?? Settings.PinnedConversationIds.Contains(
                item.Id,
                StringComparer.OrdinalIgnoreCase);
            item.PinActionText = item.IsPinned ? L("Tasks.Unpin") : L("Tasks.Pin");
            item.ProjectName = DisplayProjectName(active.Cwd);
            item.ConversationSectionTitle = ResolveConversationSectionTitle(item);
            item.IsDeleteConfirmationOpen = false;
            item.ProtectionText = !CanEnableConversationProtection || item.IsEnabled
                ? string.Empty
                : L("Tasks.ProtectionPaused");
            ClearConversationMutationStatus(item);
            if (ConversationScope == ConversationScopeKind.Archived &&
                ReferenceEquals(SelectedTask, item))
            {
                SelectedTask = null;
            }
        }
        else if (kind == ConversationMutationKind.Delete &&
                 result.AuthoritativeThread is null)
        {
            item.IsConversationMutationPending = false;
            item.EnabledChanged -= OnTaskEnabledChanged;
            if (ReferenceEquals(SelectedTask, item))
            {
                SelectedTask = null;
            }

            _tasksById.Remove(item.Id);
            Tasks.Remove(item);
        }
        else
        {
            SetConversationMutationStatus(item, "Tasks.MutationChanged");
            return;
        }

        RefreshTaskFilter();
        UpdateTaskMetrics();
        OnPropertyChanged(nameof(CanEditSelectedFollowUps));
        OnPropertyChanged(nameof(SelectedTaskFollowUpTitle));
        RaiseFollowUpCommandCanExecuteChanged();
    }

    private void ApplyConversationMutationFailure(
        GuardianTaskItem item,
        ConversationMutationKind kind,
        ConversationMutationFailureKind failureKind)
    {
        if (failureKind == ConversationMutationFailureKind.Uncertain)
        {
            _uncertainConversationMutations.Add(item.Id);
        }

        var resourceKey = failureKind switch
        {
            ConversationMutationFailureKind.CapabilityUnavailable =>
                kind == ConversationMutationKind.Unarchive
                    ? "Tasks.UnarchiveUnavailable"
                    : "Tasks.DeleteUnavailable",
            ConversationMutationFailureKind.InvalidTarget or
                ConversationMutationFailureKind.StateChanged or
                ConversationMutationFailureKind.ConfirmationRequired =>
                "Tasks.MutationChanged",
            ConversationMutationFailureKind.DirtyDraft =>
                "Tasks.MutationDraftBusy",
            ConversationMutationFailureKind.OwnerUnavailable or
                ConversationMutationFailureKind.UserActive =>
                "Tasks.MutationOwnerUnavailable",
            ConversationMutationFailureKind.PersistenceFailed =>
                "Tasks.MutationPersistenceFailed",
            ConversationMutationFailureKind.Rejected =>
                "Tasks.MutationRejected",
            ConversationMutationFailureKind.Uncertain =>
                "Tasks.MutationUncertain",
            _ => "Tasks.MutationFailed"
        };
        SetConversationMutationStatus(item, resourceKey);
    }

    private void UpdateConversationMutationDisplay(GuardianTaskItem item)
    {
        if (!item.IsArchived)
        {
            item.IsDeleteConfirmationOpen = false;
            item.ConversationMutationStatusResourceKey = string.Empty;
            item.ConversationMutationStatusText = string.Empty;
        }
        else if (string.IsNullOrWhiteSpace(item.ConversationMutationStatusResourceKey) &&
                 _uncertainConversationMutations.Contains(item.Id))
        {
            item.ConversationMutationStatusResourceKey = "Tasks.MutationUncertain";
        }

        var mutationUnavailable = item.IsArchived &&
            (_previewIsolationMode ||
             _conversationMutations is null ||
             !_conversationMutations.CanExecute(ConversationMutationKind.Unarchive) ||
             !_conversationMutations.CanExecute(ConversationMutationKind.Delete));
        if (!mutationUnavailable && IsUnavailableMutationResourceKey(item.ConversationMutationStatusResourceKey))
        {
            item.ConversationMutationStatusResourceKey = string.Empty;
            item.ConversationMutationStatusText = string.Empty;
        }
        if (mutationUnavailable && string.IsNullOrWhiteSpace(item.ConversationMutationStatusResourceKey))
        {
            item.ConversationMutationStatusResourceKey = _previewIsolationMode
                ? "Tasks.MutationUnavailableInPreview"
                : "Tasks.MutationUnavailable";
        }

        item.IsConversationMutationUnavailable = mutationUnavailable;

        if (!string.IsNullOrWhiteSpace(item.ConversationMutationStatusResourceKey))
        {
            item.ConversationMutationStatusText = L(
                item.ConversationMutationStatusResourceKey);
        }

        var statusHint = item.HasConversationMutationStatus
            ? item.ConversationMutationStatusText
            : null;
        item.UnarchiveActionHint = statusHint ??
            (_previewIsolationMode
                ? L("Tasks.MutationUnavailableInPreview")
                : _conversationMutations?.CanExecute(ConversationMutationKind.Unarchive) == true
                    ? L("Tasks.Unarchive")
                    : L("Tasks.UnarchiveUnavailable"));
        item.DeleteActionHint = statusHint ??
            (_previewIsolationMode
                ? L("Tasks.MutationUnavailableInPreview")
                : _conversationMutations?.CanExecute(ConversationMutationKind.Delete) == true
                    ? L("Tasks.Delete")
                    : L("Tasks.DeleteUnavailable"));
    }

    private void SetConversationMutationStatus(GuardianTaskItem item, string resourceKey)
    {
        item.ConversationMutationStatusResourceKey = resourceKey;
        item.ConversationMutationStatusText = L(resourceKey);
        UpdateConversationMutationDisplay(item);
    }

    private void ClearConversationMutationStatus(GuardianTaskItem item)
    {
        item.ConversationMutationStatusResourceKey = string.Empty;
        item.ConversationMutationStatusText = string.Empty;
        UpdateConversationMutationDisplay(item);
    }

    private static bool IsUnavailableMutationResourceKey(string resourceKey) =>
        resourceKey is "Tasks.MutationUnavailable" or
            "Tasks.MutationUnavailableInPreview" or
            "Tasks.UnarchiveUnavailable" or
            "Tasks.DeleteUnavailable";

    private static bool ConversationMutationBoundaryChanged(
        GuardianTaskItem item,
        GuardianTaskState state) =>
        item.IsArchived != state.Thread.IsArchived ||
        item.UpdatedAt.ToUnixTimeSeconds() != state.Thread.UpdatedAt ||
        !string.Equals(
            item.LatestTurnId,
            state.Turn?.Id ?? string.Empty,
            StringComparison.OrdinalIgnoreCase);

    private void InvalidateConversationMutation(string threadId)
    {
        var lease = Volatile.Read(ref _activeConversationMutation);
        if (lease is not null &&
            string.Equals(lease.ThreadId, threadId, StringComparison.OrdinalIgnoreCase))
        {
            lease.Invalidate();
        }
    }

    private void RaiseConversationMutationCommandCanExecuteChanged()
    {
        _unarchiveConversationCommand.RaiseCanExecuteChanged();
        _requestDeleteConversationCommand.RaiseCanExecuteChanged();
        _confirmDeleteConversationCommand.RaiseCanExecuteChanged();
        _cancelDeleteConversationCommand.RaiseCanExecuteChanged();
    }

    private sealed class ConversationMutationUiLease(
        string threadId,
        long expectedUpdatedAt,
        string expectedLatestTurnId)
    {
        private int _allowed = 1;

        internal string ThreadId { get; } = threadId;

        internal long ExpectedUpdatedAt { get; } = expectedUpdatedAt;

        internal string ExpectedLatestTurnId { get; } = expectedLatestTurnId;

        internal bool IsAllowed() => Volatile.Read(ref _allowed) != 0;

        internal void Invalidate() => Interlocked.Exchange(ref _allowed, 0);
    }

    internal async Task<bool> MoveConversationAsync(
        GuardianTaskItem item,
        int visibleTargetIndex,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        var visibleItems = TasksView.Cast<GuardianTaskItem>().ToList();
        var oldVisibleIndex = visibleItems.IndexOf(item);
        if (oldVisibleIndex < 0 || visibleItems.Count < 2)
        {
            return false;
        }

        var samePinIndices = visibleItems
            .Select((candidate, index) => (candidate, index))
            .Where(candidate => candidate.candidate.IsPinned == item.IsPinned)
            .Select(candidate => candidate.index)
            .ToArray();
        if (samePinIndices.Length < 2)
        {
            return false;
        }

        var targetIndex = Math.Clamp(
            visibleTargetIndex,
            samePinIndices[0],
            samePinIndices[^1]);
        if (targetIndex == oldVisibleIndex)
        {
            return false;
        }

        var previousTaskOrder = Tasks.Select(task => task.Id).ToArray();
        var previousPersistedOrder = Settings.ConversationOrder?.ToArray() ?? [];
        var previousManualOrderMode = Settings.UseManualConversationOrder;
        visibleItems.RemoveAt(oldVisibleIndex);
        visibleItems.Insert(targetIndex, item);

        var visibleIds = visibleItems
            .Select(task => task.Id)
            .ToHashSet(StringComparer.Ordinal);
        var visibleSlots = Enumerable.Range(0, Tasks.Count)
            .Where(index => visibleIds.Contains(Tasks[index].Id))
            .ToArray();
        if (visibleSlots.Length != visibleItems.Count)
        {
            return false;
        }

        var reordered = Tasks.ToArray();
        for (var index = 0; index < visibleSlots.Length; index++)
        {
            reordered[visibleSlots[index]] = visibleItems[index];
        }

        ApplyTaskOrder(reordered.Select(task => task.Id));
        Settings.ConversationOrder = Tasks.Select(task => task.Id).ToList();
        Settings.UseManualConversationOrder = true;
        if (await SaveSettingsAsync(cancellationToken))
        {
            return true;
        }

        Settings.ConversationOrder = previousPersistedOrder.ToList();
        Settings.UseManualConversationOrder = previousManualOrderMode;
        ApplyTaskOrder(previousTaskOrder);
        RefreshTaskFilter();
        return false;
    }

    private IReadOnlyList<GuardianTaskState> ApplyConversationOrder(
        IReadOnlyList<GuardianTaskState> incomingStates)
    {
        return OrderConversations(
            incomingStates,
            Settings.PinnedConversationIds,
            Settings.UseManualConversationOrder,
            Settings.ConversationOrder);
    }

    internal static IReadOnlyList<GuardianTaskState> OrderConversations(
        IReadOnlyList<GuardianTaskState> incomingStates,
        IEnumerable<string>? pinnedConversationIds,
        bool useManualOrder,
        IReadOnlyList<string>? manualOrder)
    {
        ArgumentNullException.ThrowIfNull(incomingStates);
        var pinned = pinnedConversationIds?.ToHashSet(StringComparer.OrdinalIgnoreCase) ??
                     new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var pinnedStates = incomingStates
            .Where(state => !state.Thread.IsArchived &&
                            (state.Thread.IsPinned ?? pinned.Contains(state.Thread.Id)))
            .ToList();
        var activeUnpinnedStates = incomingStates
            .Where(state => !state.Thread.IsArchived &&
                            !(state.Thread.IsPinned ?? pinned.Contains(state.Thread.Id)))
            .ToList();
        var archivedStates = incomingStates
            .Where(state => state.Thread.IsArchived)
            .ToList();

        static IEnumerable<GuardianTaskState> OrderProjectStates(
            IEnumerable<GuardianTaskState> states) => states
            .GroupBy(
                state => GetConversationProjectKey(state.Thread.Cwd),
                StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Max(state => state.Thread.UpdatedAt))
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .SelectMany(group => group
                .OrderByDescending(state => state.Thread.UpdatedAt)
                .ThenBy(state => state.Thread.Id, StringComparer.Ordinal));

        static IEnumerable<GuardianTaskState> OrderRecentStates(
            IEnumerable<GuardianTaskState> states) => states
            .OrderByDescending(state => state.Thread.UpdatedAt)
            .ThenBy(state => state.Thread.Id, StringComparer.Ordinal);

        // A conversation that is running right now goes to the very top, and everything else keeps the
        // position it already had. A stable partition is what makes the second half of that true: it
        // reorders nothing except by lifting the running rows out, so pinned/project/recent grouping and
        // any manual order survive untouched underneath. Painting the row yellow was not enough on its
        // own — the index is virtualized over more than a hundred conversations, so a running row that
        // sorts into the middle is not visible in any colour.
        static IReadOnlyList<GuardianTaskState> RunningFirst(IEnumerable<GuardianTaskState> states)
        {
            var ordered = states.ToList();
            var running = ordered.Where(state => state.IsRunningNow).ToList();
            return running.Count == 0
                ? ordered
                : running.Concat(ordered.Where(state => !state.IsRunningNow)).ToArray();
        }

        if (!useManualOrder || manualOrder is not { Count: > 0 })
        {
            return RunningFirst(pinnedStates
                .OrderByDescending(state => state.Thread.UpdatedAt)
                .ThenBy(state => state.Thread.Id, StringComparer.Ordinal)
                .Concat(OrderProjectStates(activeUnpinnedStates.Where(
                    state => !string.IsNullOrWhiteSpace(state.Thread.Cwd))))
                .Concat(OrderRecentStates(activeUnpinnedStates.Where(
                    state => string.IsNullOrWhiteSpace(state.Thread.Cwd))))
                .Concat(OrderRecentStates(archivedStates)));
        }

        var rank = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < manualOrder.Count; index++)
        {
            rank.TryAdd(manualOrder[index], index);
        }

        var manualRank = new Func<string, int>(id =>
            rank.TryGetValue(id, out var value) ? value : int.MinValue);
        var orderedProjects = activeUnpinnedStates
            .Where(state => !string.IsNullOrWhiteSpace(state.Thread.Cwd))
            .GroupBy(
                state => GetConversationProjectKey(state.Thread.Cwd),
                StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Min(state => manualRank(state.Thread.Id)))
            .ThenByDescending(group => group.Max(state => state.Thread.UpdatedAt))
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .SelectMany(group => group
                .OrderBy(state => manualRank(state.Thread.Id))
                .ThenByDescending(state => state.Thread.UpdatedAt)
                .ThenBy(state => state.Thread.Id, StringComparer.Ordinal));
        var orderedRecent = activeUnpinnedStates
            .Where(state => string.IsNullOrWhiteSpace(state.Thread.Cwd))
            .OrderBy(state => manualRank(state.Thread.Id))
            .ThenByDescending(state => state.Thread.UpdatedAt)
            .ThenBy(state => state.Thread.Id, StringComparer.Ordinal);
        return RunningFirst(pinnedStates
            .OrderBy(state => manualRank(state.Thread.Id))
            .ThenByDescending(state => state.Thread.UpdatedAt)
            .ThenBy(state => state.Thread.Id, StringComparer.Ordinal)
            .Concat(orderedProjects)
            .Concat(orderedRecent)
            .Concat(archivedStates
                .OrderBy(state => manualRank(state.Thread.Id))
                .ThenByDescending(state => state.Thread.UpdatedAt)
                .ThenBy(state => state.Thread.Id, StringComparer.Ordinal)));
    }

    internal static string GetConversationProjectKey(string? cwd)
    {
        var value = cwd?.Trim() ?? string.Empty;
        if (value.Length == 0)
        {
            return "~";
        }

        try
        {
            var fullPath = Path.GetFullPath(value)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return fullPath.Length == 0 ? value : fullPath;
        }
        catch
        {
            return value.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
    }

    internal static string? GetRecognizedConversationProjectKey(string? cwd)
    {
        var canonical = GetConversationProjectKey(cwd);
        if (canonical == "~")
        {
            return null;
        }

        if (RecognizedProjectRootCache.TryGetValue(canonical, out var cached))
        {
            return cached.Length == 0 ? null : cached;
        }

        var resolved = ResolveRecognizedProjectRoot(canonical) ?? string.Empty;
        RecognizedProjectRootCache[canonical] = resolved;
        return resolved.Length == 0 ? null : resolved;
    }

    private static string? ResolveRecognizedProjectRoot(string canonicalPath)
    {
        if (IsCodexHistoryWorkspace(canonicalPath) || !Directory.Exists(canonicalPath))
        {
            return null;
        }

        var current = new DirectoryInfo(canonicalPath);
        string? projectRoot = null;
        for (var depth = 0; current is not null && depth < 12; depth++)
        {
            if (HasProjectMarker(current.FullName))
            {
                projectRoot = current.FullName;
            }

            current = current.Parent;
        }

        return projectRoot is null ? null : GetConversationProjectKey(projectRoot);
    }

    private static bool HasProjectMarker(string directory)
    {
        if (Directory.Exists(Path.Combine(directory, ".git")) ||
            Directory.Exists(Path.Combine(directory, ".codex")) ||
            File.Exists(Path.Combine(directory, "package.json")) ||
            File.Exists(Path.Combine(directory, "pyproject.toml")) ||
            File.Exists(Path.Combine(directory, "Cargo.toml")) ||
            File.Exists(Path.Combine(directory, "go.mod")))
        {
            return true;
        }

        return Directory.EnumerateFiles(directory, "*.sln", SearchOption.TopDirectoryOnly).Any() ||
               Directory.EnumerateFiles(directory, "*.csproj", SearchOption.TopDirectoryOnly).Any();
    }

    private static bool IsCodexHistoryWorkspace(string canonicalPath)
    {
        var normalized = canonicalPath.Replace(
            Path.AltDirectorySeparatorChar,
            Path.DirectorySeparatorChar);
        var marker = string.Concat(
            Path.DirectorySeparatorChar,
            "Documents",
            Path.DirectorySeparatorChar,
            "Codex",
            Path.DirectorySeparatorChar);
        var index = normalized.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return false;
        }

        var remainder = normalized[(index + marker.Length)..];
        var segment = remainder.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        return segment is not null &&
               DateTime.TryParseExact(
                   segment,
                   "yyyy-MM-dd",
                   CultureInfo.InvariantCulture,
                   DateTimeStyles.None,
                   out _);
    }

    private void ApplyTaskOrder(IEnumerable<string> orderedIds)
    {
        var targetIndex = 0;
        foreach (var taskId in orderedIds)
        {
            if (!_tasksById.TryGetValue(taskId, out var item))
            {
                continue;
            }

            var currentIndex = Tasks.IndexOf(item);
            if (currentIndex < 0)
            {
                continue;
            }

            if (currentIndex != targetIndex)
            {
                Tasks.Move(currentIndex, targetIndex);
            }
            targetIndex++;
        }
    }

    private GuardianTaskItem CreateTaskItem(GuardianTaskState state)
    {
        var item = new GuardianTaskItem
        {
            Id = state.Thread.Id,
            Name = DisplayConversationTitle(state.Thread.Name, state.Thread.Preview),
            Preview = DisplayConversationPreview(
                state.Thread.Preview,
                DisplayConversationTitle(state.Thread.Name, state.Thread.Preview)),
            Cwd = state.Thread.Cwd,
            RawSource = state.Thread.Source,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(state.Thread.CreatedAt),
            UpdatedAt = DateTimeOffset.FromUnixTimeSeconds(state.Thread.UpdatedAt)
        };
        UpdateTaskItem(item, state);
        return item;
    }

    private void UpdateTaskItem(GuardianTaskItem item, GuardianTaskState state)
    {
        var displayTitle = DisplayConversationTitle(state.Thread.Name, state.Thread.Preview);
        item.Name = displayTitle;
        item.Preview = DisplayConversationPreview(state.Thread.Preview, displayTitle);
        item.Cwd = state.Thread.Cwd;
        item.RawSource = state.Thread.Source;
        item.Source = DisplaySource(state.Thread.Source);
        item.CreatedAt = DateTimeOffset.FromUnixTimeSeconds(state.Thread.CreatedAt);
        item.UpdatedAt = DateTimeOffset.FromUnixTimeSeconds(state.Thread.UpdatedAt);
        item.CodexPinnedState = state.Thread.IsPinned;
        item.IsPinned = state.Thread.IsPinned ?? Settings.PinnedConversationIds.Contains(
            item.Id,
            StringComparer.OrdinalIgnoreCase);
        item.PinActionText = item.IsPinned ? L("Tasks.Unpin") : L("Tasks.Pin");
        item.ProjectName = DisplayProjectName(state.Thread.Cwd);
        item.IsArchived = state.Thread.IsArchived;
        item.ConversationSectionTitle = ResolveConversationSectionTitle(item);
        item.IsSubAgent = state.Thread.IsSubAgent;
        item.IsEphemeral = state.Thread.IsEphemeral;
        item.IsProtectionAvailable = CanEnableConversationProtection;
        item.SetEnabledFromSnapshot(CanEnableConversationProtection && state.IsEnabled);
        item.Health = state.Health;
        item.HealthResourceKey = ResolveHealthResourceKey(state);
        item.HealthText = DisplayHealth(item.HealthResourceKey);
        item.ProtectionText = state.Thread.IsArchived
            ? L("Tasks.ArchivedReadOnly")
            : !CanEnableConversationProtection || state.IsEnabled
                ? string.Empty
                : L("Tasks.ProtectionPaused");
        item.IsGuardianManagedActivity = state.IsGuardianManagedActivity;
        item.RawStatusText = state.StatusText;
        item.StatusText = DisplayRuntimeText(state.StatusText);
        item.Observation = state.Observation;
        item.ObservationText = DisplayObservation(state.Observation);
        item.RawLastEvent = state.LastEvent;
        item.LastEvent = DisplayRuntimeText(state.LastEvent);
        item.Attempts = state.Attempts;
        item.NextAttemptAt = state.NextAttemptAt;
        item.RecoveryLedger = state.RecoveryLedger ?? GuardianRecoveryLedger.Empty;
        UpdateTaskRecoveryLedgerDisplay(item);
        item.ReadyText = L("Value.Ready");
        // Keep the canonical status on the item so status colors and workflow busy checks do not
        // depend on the current UI language.
        item.TurnStatus = state.Turn?.Status ?? "unknown";
        item.HasFinalAssistantOutput = state.Turn?.HasReliableFinalOutput == true;
        item.IsRunningNow = state.IsRunningNow;
        item.LatestTurnId = state.Turn?.Id ?? string.Empty;
        var followUpArm = FollowUpQueuePlanner.EvaluateCompletionArm(
            state.Turn,
            state.Thread.RuntimeStatus);
        item.CanArmCompletionFollowUps = followUpArm.CanArm;
        item.CompletionAnchorTurnId = followUpArm.AnchorTurnId;
        item.FollowUpQueueRuntime = state.FollowUpQueue;
        UpdateTaskFollowUpDisplay(item);
        UpdateConversationMutationDisplay(item);
    }

    // The one line that answers "has it ever actually resent this?" without opening guardian.log. Empty
    // when there is nothing to report, so ordinary healthy tasks stay uncluttered; when a wait is stuck
    // behind a busy owner it also says for how long, because that wait is otherwise indistinguishable
    // from a guardian that stopped trying.
    private void UpdateTaskRecoveryLedgerDisplay(GuardianTaskItem task)
    {
        ArgumentNullException.ThrowIfNull(task);
        var ledger = task.RecoveryLedger;
        var history = ledger.HasEverDispatched
            ? L(
                "Recovery.LedgerConfirmed",
                ledger.ConfirmedDispatches,
                ledger.LastConfirmedAt is { } confirmedAt
                    ? confirmedAt.LocalDateTime.ToString("MM-dd HH:mm:ss", CultureInfo.CurrentUICulture)
                    : L("Value.Never"))
            : string.Empty;
        var stall = ledger.IsOwnerBusyStalled
            ? L(
                "Recovery.LedgerOwnerBusy",
                ledger.OwnerBusyRefusals,
                GuardianEngine.FormatStallDuration(ledger.OwnerBusyDuration(DateTimeOffset.Now)))
            : string.Empty;
        if (history.Length == 0 && stall.Length == 0)
        {
            task.RecoveryLedgerText = string.Empty;
            return;
        }

        if (history.Length == 0)
        {
            history = L("Recovery.LedgerNever");
        }

        task.RecoveryLedgerText = stall.Length == 0 ? history : history + " · " + stall;
    }

    private void UpdateTaskFollowUpDisplay(GuardianTaskItem task)
    {
        task.FollowUpQueueActionText = L("FollowUp.OpenQueue", task.Name);
        if (task.FollowUpQueueRuntime is { } runtime)
        {
            ApplyTaskFollowUpRuntimeDisplay(task, runtime);
            return;
        }

        if (!Settings.ThreadFollowUps.TryGetValue(task.Id, out var configured) ||
            configured.Messages.Count == 0)
        {
            task.FollowUpMessageCount = 0;
            task.FollowUpQueueState = FollowUpQueueVisualState.Absent;
            task.FollowUpQueueStatusText = L("FollowUp.StatusNone");
            return;
        }

        task.FollowUpMessageCount = configured.Messages.Count;
        if (!configured.IsEnabled)
        {
            task.FollowUpQueueState = FollowUpQueueVisualState.Paused;
            task.FollowUpQueueStatusText = L("FollowUp.StatusPaused", configured.Messages.Count);
            return;
        }

        var enabled = configured.Messages
            .Where(message => message.IsEnabled)
            .OrderBy(message => message.Order)
            .ThenBy(message => message.Id, StringComparer.Ordinal)
            .ToArray();
        if (enabled.Length == 0)
        {
            task.FollowUpQueueState = FollowUpQueueVisualState.Blocked;
            task.FollowUpQueueStatusText = L("FollowUp.StatusNoEnabledMessages");
            return;
        }

        var next = enabled[0];
        if (next.Trigger == FollowUpTriggerKind.ScheduledAt)
        {
            if (next.ScheduledAtUtc is null)
            {
                task.FollowUpQueueState = FollowUpQueueVisualState.Blocked;
                task.FollowUpQueueStatusText = L("FollowUp.StatusBlocked");
                return;
            }

            var localSchedule = next.ScheduledAtUtc.Value.ToLocalTime().ToString(
                _localization.CurrentCulture.TwoLetterISOLanguageName == "zh"
                    ? "MM-dd HH:mm"
                    : "MMM dd HH:mm",
                _localization.CurrentCulture);
            task.FollowUpQueueState = FollowUpQueueVisualState.Scheduled;
            task.FollowUpQueueStatusText = L(
                "FollowUp.StatusScheduled",
                configured.Messages.Count,
                localSchedule);
            return;
        }

        if (!task.CanArmCompletionFollowUps &&
            string.IsNullOrWhiteSpace(configured.CompletionAnchorTurnId))
        {
            task.FollowUpQueueState = FollowUpQueueVisualState.Blocked;
            task.FollowUpQueueStatusText = L("FollowUp.StatusBlocked");
            return;
        }

        task.FollowUpQueueState = FollowUpQueueVisualState.WaitingForCompletion;
        task.FollowUpQueueStatusText = L(
            "FollowUp.StatusWaiting",
            configured.Messages.Count);
    }

    private void ApplyTaskFollowUpRuntimeDisplay(
        GuardianTaskItem task,
        FollowUpQueueRuntimeSnapshot runtime)
    {
        task.FollowUpMessageCount = runtime.TotalMessageCount;
        switch (runtime.Kind)
        {
            case FollowUpQueueRuntimeKind.None:
                task.FollowUpQueueState = FollowUpQueueVisualState.Absent;
                task.FollowUpQueueStatusText = L("FollowUp.StatusNone");
                break;
            case FollowUpQueueRuntimeKind.Paused:
                task.FollowUpQueueState = FollowUpQueueVisualState.Paused;
                task.FollowUpQueueStatusText = L(
                    "FollowUp.StatusPaused",
                    runtime.TotalMessageCount);
                break;
            case FollowUpQueueRuntimeKind.Scheduled:
                task.FollowUpQueueState = FollowUpQueueVisualState.Scheduled;
                task.FollowUpQueueStatusText = runtime.NextScheduledAtUtc is { } scheduledAtUtc
                    ? L(
                        "FollowUp.StatusScheduled",
                        runtime.TotalMessageCount,
                        scheduledAtUtc.ToLocalTime().ToString(
                            _localization.CurrentCulture.TwoLetterISOLanguageName == "zh"
                                ? "MM-dd HH:mm"
                                : "MMM dd HH:mm",
                            _localization.CurrentCulture))
                    : L("FollowUp.StatusConfigured", runtime.TotalMessageCount);
                break;
            case FollowUpQueueRuntimeKind.WaitingForCompletion:
                task.FollowUpQueueState = FollowUpQueueVisualState.WaitingForCompletion;
                task.FollowUpQueueStatusText = L(
                    "FollowUp.StatusWaiting",
                    runtime.TotalMessageCount);
                break;
            case FollowUpQueueRuntimeKind.Ready:
                task.FollowUpQueueState = FollowUpQueueVisualState.Ready;
                task.FollowUpQueueStatusText = L("FollowUp.StatusReady");
                break;
            case FollowUpQueueRuntimeKind.Dispatching:
                task.FollowUpQueueState = FollowUpQueueVisualState.Dispatching;
                task.FollowUpQueueStatusText = L("FollowUp.StatusDispatching");
                break;
            case FollowUpQueueRuntimeKind.Uncertain:
                task.FollowUpQueueState = FollowUpQueueVisualState.Uncertain;
                task.FollowUpQueueStatusText = L("FollowUp.StatusUncertain");
                break;
            case FollowUpQueueRuntimeKind.Blocked:
                task.FollowUpQueueState = FollowUpQueueVisualState.Blocked;
                task.FollowUpQueueStatusText = L("FollowUp.StatusBlocked");
                break;
            case FollowUpQueueRuntimeKind.Exhausted:
                task.FollowUpQueueState = FollowUpQueueVisualState.Exhausted;
                task.FollowUpQueueStatusText = L("FollowUp.StatusExhausted");
                break;
            default:
                task.FollowUpQueueState = FollowUpQueueVisualState.Configured;
                task.FollowUpQueueStatusText = L(
                    "FollowUp.StatusConfigured",
                    runtime.TotalMessageCount);
                break;
        }
    }

    private bool MatchesTaskFilter(object item)
    {
        return item is GuardianTaskItem task &&
               MatchesTaskScopeAndSearch(task) &&
               (_conversationGroupKey is null || MatchesConversationGroup(task));
    }

    private bool MatchesTaskScopeAndSearch(GuardianTaskItem task)
    {
        if (ConversationScope == ConversationScopeKind.Archived)
        {
            if (!task.IsArchived)
            {
                return false;
            }
        }
        else
        {
            if (task.IsArchived ||
                ConversationScope == ConversationScopeKind.NeedsAttention &&
                !IsTaskNeedingAttention(task))
            {
                return false;
            }
        }

        var query = TaskSearchText.Trim();
        return query.Length == 0 ||
               task.Name.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
               task.Preview.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
               task.Cwd.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
               task.Source.Contains(query, StringComparison.CurrentCultureIgnoreCase);
    }

    private bool MatchesConversationGroup(GuardianTaskItem task)
    {
        if (_conversationGroupKey is null)
        {
            return true;
        }

        if (string.Equals(_conversationGroupKey, PinnedConversationGroupKey, StringComparison.Ordinal))
        {
            return task.IsPinned && !task.IsArchived;
        }

        if (string.Equals(_conversationGroupKey, RecentConversationGroupKey, StringComparison.Ordinal))
        {
            return !task.IsPinned && !task.IsArchived &&
                   GetRecognizedConversationProjectKey(task.Cwd) is null;
        }

        if (string.Equals(_conversationGroupKey, ArchivedConversationGroupKey, StringComparison.Ordinal))
        {
            return task.IsArchived;
        }

        if (_conversationGroupKey.StartsWith(ProjectConversationGroupPrefix, StringComparison.Ordinal))
        {
            var projectKey = _conversationGroupKey[ProjectConversationGroupPrefix.Length..];
            return !task.IsPinned &&
                   !task.IsArchived &&
                   string.Equals(
                        GetRecognizedConversationProjectKey(task.Cwd),
                       projectKey,
                       StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private void RebuildConversationNavigationEntries()
    {
        var allCandidates = Tasks
            .Where(MatchesTaskScopeAndSearch)
            .ToArray();
        var entries = new List<ConversationNavigationEntry>();

        // "Running first" has to mean first in the whole index, not first inside a section. The index
        // opens with section headers (pinned, projects, recent), so a conversation sorted to the top of
        // its own section still lands below the fold when that section does — and the index is
        // virtualized over more than a hundred rows, which is the whole reason the running row was hard
        // to find. Running conversations are therefore hoisted above every section and taken out of
        // their normal group so they appear exactly once. The moment a conversation stops running it
        // falls back into the position Codex itself gives it.
        var running = allCandidates.Where(task => task.IsRunningNow).ToArray();
        var candidates = running.Length == 0
            ? allCandidates
            : allCandidates.Where(task => !task.IsRunningNow).ToArray();
        if (running.Length > 0)
        {
            entries.AddRange(running
                .OrderByDescending(task => task.UpdatedAt)
                .ThenBy(task => task.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(task => CreateConversationNavigationConversation(task)));
        }

        if (ConversationScope == ConversationScopeKind.Archived)
        {
            if (candidates.Length > 0)
            {
                var section = CreateConversationNavigationSection(
                    ArchivedConversationGroupKey,
                    L("Tasks.ArchivedSection"));
                entries.Add(section);
                if (section.IsExpanded)
                {
                    entries.AddRange(candidates
                        .OrderByDescending(task => task.UpdatedAt)
                        .ThenBy(task => task.Name, StringComparer.CurrentCultureIgnoreCase)
                        .Select(task => CreateConversationNavigationConversation(task)));
                }
            }
        }
        else
        {
            var pinned = candidates.Where(task => task.IsPinned).ToArray();
            if (pinned.Length > 0)
            {
                var section = CreateConversationNavigationSection(
                    PinnedConversationGroupKey,
                    L("Tasks.PinnedSection"));
                entries.Add(section);
                if (section.IsExpanded)
                {
                    entries.AddRange(pinned
                        .OrderByDescending(task => task.UpdatedAt)
                        .ThenBy(task => task.Name, StringComparer.CurrentCultureIgnoreCase)
                        .Select(task => CreateConversationNavigationConversation(task)));
                }
            }

            var projects = candidates
                .Where(task => !task.IsPinned && GetRecognizedConversationProjectKey(task.Cwd) is not null)
                .GroupBy(task => GetRecognizedConversationProjectKey(task.Cwd)!, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(group => group.Max(task => task.UpdatedAt))
                .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (projects.Length > 0)
            {
                var section = CreateConversationNavigationSection(
                    "__codexfree_projects__",
                    L("Tasks.ProjectsSection"));
                entries.Add(section);
                if (section.IsExpanded)
                {
                    entries.AddRange(projects.Select(group => CreateConversationNavigationProject(
                        ProjectConversationGroupPrefix + group.Key,
                        DisplayProjectName(group.Key),
                        group.Count(),
                        group.Any(task => task.VisualTone == TaskVisualTone.Attention))));
                }
            }

            var recent = candidates
                .Where(task => !task.IsPinned && GetRecognizedConversationProjectKey(task.Cwd) is null)
                .ToArray();
            if (recent.Length > 0)
            {
                var section = CreateConversationNavigationSection(
                    RecentConversationGroupKey,
                    L("Tasks.RecentSection"));
                entries.Add(section);
                if (section.IsExpanded)
                {
                    // In the Attention scope the most-resent conversations come first. The list is
                    // virtualized, so an entry that sorts below the viewport is effectively invisible;
                    // ordering by ledger depth is what puts the resend history within one click of the
                    // banner instead of somewhere in a list of well over a hundred.
                    var ordered = ConversationScope == ConversationScopeKind.NeedsAttention
                        ? recent
                            .OrderByDescending(task => task.RecoveryLedger.ConfirmedDispatches)
                            .ThenByDescending(task => task.UpdatedAt)
                            .ThenBy(task => task.Name, StringComparer.CurrentCultureIgnoreCase)
                        : recent
                            .OrderByDescending(task => task.UpdatedAt)
                            .ThenBy(task => task.Name, StringComparer.CurrentCultureIgnoreCase);
                    entries.AddRange(ordered
                        .Select(task => CreateConversationNavigationConversation(task)));
                }
            }
        }

        if (!ConversationNavigationEntriesMatch(entries))
        {
            ((ResettableObservableCollection<ConversationNavigationEntry>)ConversationNavigationEntries)
                .ReplaceAll(entries);
        }

        if (_conversationGroupKey is not null)
        {
            var activeEntry = entries.FirstOrDefault(entry =>
                entry.IsProject &&
                string.Equals(entry.Key, _conversationGroupKey, StringComparison.Ordinal));
            var activeProjectStillExists =
                !_conversationGroupKey.StartsWith(ProjectConversationGroupPrefix, StringComparison.Ordinal) ||
                candidates.Any(task =>
                    !task.IsPinned &&
                    !task.IsArchived &&
                    string.Equals(
                        GetRecognizedConversationProjectKey(task.Cwd),
                        _conversationGroupKey[ProjectConversationGroupPrefix.Length..],
                        StringComparison.OrdinalIgnoreCase));
            if (!_conversationGroupKey.StartsWith(ProjectConversationGroupPrefix, StringComparison.Ordinal) ||
                !activeProjectStillExists)
            {
                _conversationGroupKey = null;
                _conversationGroupTitle = string.Empty;
                OnPropertyChanged(nameof(IsConversationNavigationRoot));
                OnPropertyChanged(nameof(IsConversationNavigationDetail));
                OnPropertyChanged(nameof(ConversationGroupTitle));
                _backToConversationNavigationCommand.RaiseCanExecuteChanged();
            }
            else if (activeEntry is not null &&
                     !string.Equals(_conversationGroupTitle, activeEntry.Title, StringComparison.Ordinal))
            {
                _conversationGroupTitle = activeEntry.Title;
                OnPropertyChanged(nameof(ConversationGroupTitle));
            }
        }
    }

    private ConversationNavigationEntry CreateConversationNavigationSection(
        string key,
        string title)
    {
        return new()
        {
            Key = key,
            Kind = ConversationNavigationEntryKind.Section,
            Title = title,
            IsExpanded = GetConversationSectionExpanded(key)
        };
    }

    private bool GetConversationSectionExpanded(string key) =>
        !_conversationSectionExpansion.TryGetValue(key, out var expanded) || expanded;

    private static ConversationNavigationEntry CreateConversationNavigationConversation(
        GuardianTaskItem task) =>
        new()
        {
            Key = "__codexfree_conversation__:" + task.Id,
            Kind = ConversationNavigationEntryKind.Conversation,
            ConversationId = task.Id,
            Task = task,
            IsArchived = task.IsArchived,
            Title = task.Name,
            Detail = task.Preview,
            IsAttention = task.VisualTone == TaskVisualTone.Attention,
            IsHealthy = task.VisualTone == TaskVisualTone.Healthy
        };

    private static ConversationNavigationEntry CreateConversationNavigationProject(
        string key,
        string title,
        int count,
        bool isAttention) =>
        new()
        {
            Key = key,
            Kind = ConversationNavigationEntryKind.Project,
            Title = title,
            Count = count,
            IsAttention = isAttention
        };

    // Tone (attention / healthy) is intentionally not part of this comparison. It changes every time a
    // conversation starts or finishes a run, and treating it as a structural difference meant rebuilding
    // the whole collection for a colour change — which rebinds every virtualized row and stopped every
    // running spinner. Both properties raise change notification instead, so they are pushed onto the
    // existing entries here and the collection is left alone.
    private bool ConversationNavigationEntriesMatch(
        IReadOnlyList<ConversationNavigationEntry> entries)
    {
        if (ConversationNavigationEntries.Count != entries.Count)
        {
            return false;
        }

        for (var index = 0; index < entries.Count; index++)
        {
            var current = ConversationNavigationEntries[index];
            var next = entries[index];
            if (!string.Equals(current.Key, next.Key, StringComparison.Ordinal) ||
                current.Kind != next.Kind ||
                !string.Equals(current.ConversationId, next.ConversationId, StringComparison.Ordinal) ||
                !ReferenceEquals(current.Task, next.Task) ||
                current.IsArchived != next.IsArchived ||
                !string.Equals(current.Title, next.Title, StringComparison.Ordinal) ||
                !string.Equals(current.Detail, next.Detail, StringComparison.Ordinal) ||
                current.Count != next.Count ||
                current.IsExpanded != next.IsExpanded)
            {
                return false;
            }
        }

        for (var index = 0; index < entries.Count; index++)
        {
            ConversationNavigationEntries[index].IsAttention = entries[index].IsAttention;
            ConversationNavigationEntries[index].IsHealthy = entries[index].IsHealthy;
        }

        return true;
    }

    private void RefreshTaskFilter()
    {
        RebuildConversationNavigationEntries();
        // DataGrid can briefly retain an edit transaction while a checkbox click is committing.
        // Skipping that one refresh is safer than turning a harmless UI race into a failed scan.
        if (TasksView is IEditableCollectionView editable &&
            (editable.IsAddingNew || editable.IsEditingItem))
        {
            UpdateFilterStatistics(TasksView.Cast<object>().Count());
            return;
        }

        // Refresh is intentionally outside a DeferRefresh scope. WPF forbids an explicit
        // Refresh while a defer token is active; the navigation collection is already batched
        // with one Reset, which removes the layout churn this path used to create.
        TasksView.Refresh();
        UpdateFilterStatistics(TasksView.Cast<object>().Count());
    }

    private void UpdateFilterStatistics(int displayedCount)
    {
        TaskCount = displayedCount;
        var totalCount = _snapshotStatistics.TotalSessionCount ?? Tasks.Count;
        _snapshotStatistics = _snapshotStatistics with
        {
            DisplayedSessionCount = displayedCount,
            FilteredSessionCount = Math.Max(0, totalCount - displayedCount)
        };
        OnPropertyChanged(nameof(HasVisibleTasks));
        OnPropertyChanged(nameof(TaskEmptyTitleText));
        OnPropertyChanged(nameof(TaskEmptyHintText));
        OnPropertyChanged(nameof(ConversationIndexSummaryText));
        OnPropertyChanged(nameof(TaskSessionSummaryText));
        OnPropertyChanged(nameof(TaskFilterSummaryText));
    }

    private void UpdateTaskMetrics()
    {
        ProtectedCount = CanEnableConversationProtection
            ? Tasks.Count(task => task.IsEnabled && !task.IsArchived)
            : Tasks.Count(task => !task.IsArchived);
        AttentionCount = CanEnableConversationProtection
            ? Tasks.Count(task => task.IsEnabled && !task.IsArchived && task.Health is
                TaskHealth.NeedsAttention or TaskHealth.WaitingForIdle or
                TaskHealth.WaitingForDesktop or TaskHealth.CoolingDown)
            : 0;
        RecoveryCount = Tasks.Count(task => task.IsGuardianManagedActivity);
        OnPropertyChanged(nameof(AllConversationCount));
        OnPropertyChanged(nameof(NeedsAttentionConversationCount));
        OnPropertyChanged(nameof(ArchivedConversationCount));
        OnPropertyChanged(nameof(ConfirmedResendTotal));
        OnPropertyChanged(nameof(ConfirmedResendConversationCount));
        OnPropertyChanged(nameof(HasAnyConfirmedResend));
        OnPropertyChanged(nameof(RecoveryLedgerSummaryText));
        OnPropertyChanged(nameof(ConversationIndexSummaryText));
        OnPropertyChanged(nameof(TaskEmptyTitleText));
        OnPropertyChanged(nameof(TaskEmptyHintText));
        LogResendLedgerDistribution();
    }

    // Where the resend history actually sits. The banner reports the totals; this reports whether the
    // conversations behind those totals are reachable at all, because an archived conversation is
    // excluded from every non-archived scope no matter what its ledger says.
    private void LogResendLedgerDistribution()
    {
        var ledgerBearing = Tasks
            .Where(task => task.RecoveryLedger.ConfirmedDispatches > 0)
            .ToArray();
        if (ledgerBearing.Length == 0)
        {
            return;
        }

        var signature = string.Join(
            ",",
            ledgerBearing
                .OrderByDescending(task => task.RecoveryLedger.ConfirmedDispatches)
                .Select(task =>
                    (GuardianLog.CreateThreadReference(task.Id) ?? "task-unknown") +
                    "=" +
                    task.RecoveryLedger.ConfirmedDispatches.ToString(CultureInfo.InvariantCulture) +
                    (task.IsArchived ? "/archived" : "/live:" + task.Health)));
        if (string.Equals(signature, _lastResendLedgerSignature, StringComparison.Ordinal))
        {
            return;
        }

        _lastResendLedgerSignature = signature;
        _log.Trace(
            "Resend ledger distribution: " +
            ledgerBearing.Length.ToString(CultureInfo.InvariantCulture) +
            " conversation(s), " +
            ledgerBearing.Count(task => !task.IsArchived).ToString(CultureInfo.InvariantCulture) +
            " reachable outside the archived scope; scope=" + ConversationScope +
            ", attentionScopeCount=" +
            NeedsAttentionConversationCount.ToString(CultureInfo.InvariantCulture) +
            ", navEntries=" +
            ConversationNavigationEntries.Count.ToString(CultureInfo.InvariantCulture) +
            ", searchLen=" +
            TaskSearchText.Trim().Length.ToString(CultureInfo.InvariantCulture) +
            "; " + signature);
    }

    private static bool IsTaskNeedingAttention(GuardianTaskItem task) =>
        !task.IsArchived && (
            task.Health is
                TaskHealth.NeedsAttention or
                TaskHealth.WaitingForIdle or
                TaskHealth.WaitingForDesktop or
                TaskHealth.CoolingDown or
                TaskHealth.ManualReview

            // A conversation that has actually been resent belongs in this scope even after it goes
            // back to a healthy state. Without this the resend history is only reachable by finding
            // one specific conversation in a list of well over a hundred, which is how the app could
            // hold seventeen threads with a non-zero ledger and still never show one of them.
            || task.RecoveryLedger.HasEverDispatched
            || task.RecoveryLedger.IsOwnerBusyStalled);

    private void OnStatusChanged(object? sender, EngineStatusEventArgs eventArgs)
    {
        Dispatch(() =>
        {
            SetEngineDisplay(eventArgs.State, eventArgs.Detail);
            IsOnline = eventArgs.IsOnline;
            IsMonitoring = _engine.IsRunning;
        });
    }

    private void OnWorkflowLineageInvalidated(object? sender, EventArgs eventArgs)
    {
        _ = sender;
        _ = eventArgs;
        Interlocked.Exchange(ref _workflowLineageDirty, 1);
        if (!IsOverviewPage || Volatile.Read(ref _disposeStarted) != 0)
        {
            return;
        }

        Dispatch(() => _ = RefreshWorkflowLineageAsync(force: false));
    }

    private async Task RefreshWorkflowLineageAsync(bool force)
    {
        if (_workflowLineageReader is null || Volatile.Read(ref _disposeStarted) != 0)
        {
            return;
        }

        if (!force && !IsOverviewPage)
        {
            Interlocked.Exchange(ref _workflowLineageDirty, 1);
            return;
        }

        Interlocked.Exchange(ref _workflowLineageDirty, 1);
        var cancellationToken = _workflowLineageLifetime.Token;
        bool entered;
        try
        {
            entered = await _workflowLineageRefreshGate.WaitAsync(0, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        if (!entered)
        {
            return;
        }

        try
        {
            do
            {
                Interlocked.Exchange(ref _workflowLineageDirty, 0);
                WorkflowLineageSnapshot snapshot;
                try
                {
                    snapshot = await _workflowLineageReader.ReadAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                catch
                {
                    snapshot = new WorkflowLineageSnapshot(
                        WorkflowLineageHealth.Unavailable,
                        WorkflowLineageUnavailableReason.ReadFailed,
                        Generation: 0,
                        TotalCorrelationCount: 0,
                        TotalTriggerCount: 0,
                        TotalActionCount: 0,
                        IsTruncated: false,
                        Array.Empty<WorkflowLineageItem>());
                }

                if (Volatile.Read(ref _disposeStarted) != 0)
                {
                    return;
                }

                try
                {
                    await ApplyWorkflowLineageOnDispatcherAsync(snapshot, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
            }
            while (Volatile.Read(ref _workflowLineageDirty) != 0 && IsOverviewPage);
        }
        finally
        {
            _workflowLineageRefreshGate.Release();
        }
    }

    private Task ApplyWorkflowLineageOnDispatcherAsync(
        WorkflowLineageSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            cancellationToken.ThrowIfCancellationRequested();
            ApplyWorkflowLineageSnapshot(snapshot);
            return Task.CompletedTask;
        }

        return dispatcher.InvokeAsync(
                () => ApplyWorkflowLineageSnapshot(snapshot),
                DispatcherPriority.DataBind,
                cancellationToken)
            .Task;
    }

    internal void ApplyWorkflowLineageSnapshot(
        WorkflowLineageSnapshot snapshot,
        bool forceLocalizedRefresh = false)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!forceLocalizedRefresh &&
            snapshot.Health is WorkflowLineageHealth.Healthy or WorkflowLineageHealth.Conservative &&
            snapshot.Generation < _workflowLineageHighestGeneration)
        {
            return;
        }

        if (snapshot.Health is WorkflowLineageHealth.Healthy or WorkflowLineageHealth.Conservative)
        {
            _workflowLineageHighestGeneration = Math.Max(
                _workflowLineageHighestGeneration,
                snapshot.Generation);
        }

        _workflowLineageSnapshot = snapshot;
        var projected = ProjectWorkflowLineageDisplayItems(snapshot.Items);
        if (projected.Select(static item => item.StableRef).Distinct(StringComparer.Ordinal).Count() !=
            projected.Count)
        {
            _workflowLineageSnapshot = new WorkflowLineageSnapshot(
                WorkflowLineageHealth.Unavailable,
                WorkflowLineageUnavailableReason.InvalidSnapshot,
                Generation: 0,
                TotalCorrelationCount: 0,
                TotalTriggerCount: 0,
                TotalActionCount: 0,
                IsTruncated: false,
                Array.Empty<WorkflowLineageItem>());
            projected = [];
        }

        ReconcileWorkflowLineageItems(projected);
        RefreshWorkflowLineageDisplay();
    }

    private IReadOnlyList<WorkflowLineageDisplayProjection> ProjectWorkflowLineageDisplayItems(
        IReadOnlyList<WorkflowLineageItem> items)
    {
        var taskLabels = _tasksById.Values.ToDictionary(
            static task => WorkflowJournalLineageReader.CreateOpaqueReference("task", task.Id),
            static task => task.Name,
            StringComparer.Ordinal);
        var presetLabels = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var queue in Settings.ThreadFollowUps.OrderBy(
                     static pair => pair.Key,
                     StringComparer.OrdinalIgnoreCase))
        {
            var ordered = queue.Value.Messages
                .OrderBy(static message => message.Order)
                .ThenBy(static message => message.Id, StringComparer.Ordinal)
                .ToArray();
            for (var index = 0; index < ordered.Length; index++)
            {
                presetLabels.TryAdd(
                    WorkflowJournalLineageReader.CreateOpaqueReference("preset", ordered[index].Id),
                    L("Activity.PresetOrdinal", index + 1));
            }
        }

        var projected = new List<WorkflowLineageDisplayProjection>(items.Count);
        string? previousCorrelation = null;
        foreach (var item in items)
        {
            var isCorrelationStart = !string.Equals(
                previousCorrelation,
                item.CorrelationRef,
                StringComparison.Ordinal);
            projected.Add(ProjectWorkflowLineageDisplayItem(
                item,
                isCorrelationStart,
                taskLabels,
                presetLabels));
            previousCorrelation = item.CorrelationRef;
        }

        return projected;
    }

    private WorkflowLineageDisplayProjection ProjectWorkflowLineageDisplayItem(
        WorkflowLineageItem item,
        bool isCorrelationStart,
        IReadOnlyDictionary<string, string> taskLabels,
        IReadOnlyDictionary<string, string> presetLabels)
    {
        var kindText = item.Kind == WorkflowLineageItemKind.TriggerOnly
            ? L("Activity.TriggerObserved")
            : item.ActionKind switch
            {
                WorkflowActionKind.SendPresetMessage => L("Activity.ActionSend"),
                WorkflowActionKind.EnableConversationProtection => L("Activity.ActionProtect"),
                _ => L("Activity.TriggerObserved")
            };
        var source = DisplayWorkflowLineageTask(item.SourceConversationRef, taskLabels);
        var routeText = item.TargetConversationRef is null
            ? source
            : L(
                "Activity.Route",
                source,
                DisplayWorkflowLineageTask(item.TargetConversationRef, taskLabels));
        var metaParts = new List<string>();
        if (item.PresetRef is not null)
        {
            metaParts.Add(presetLabels.TryGetValue(item.PresetRef, out var presetLabel)
                ? presetLabel
                : L("Activity.PresetRef", OpaqueSuffix(item.PresetRef)));
        }

        metaParts.Add(DisplayWorkflowTrigger(item.TriggerKind));
        if (item.ActionIndex is { } actionIndex)
        {
            metaParts.Add(L("Activity.ActionOrdinal", actionIndex + 1));
        }

        if (item.AttemptCount > 0)
        {
            metaParts.Add(L("Activity.AttemptRecorded", item.AttemptCount));
        }

        var stateText = DisplayWorkflowLineageState(item.State);
        var failureText = DisplayWorkflowLineageFailure(item.FailureReason);
        var nextActionText = L(
            "Activity.NextAction",
            DisplayWorkflowLineageNextAction(item.State));
        var timestamp = item.UpdatedAtUtc ?? item.CreatedAtUtc ?? item.ObservedAtUtc;
        var timeText = timestamp.ToLocalTime().ToString("MM-dd HH:mm", _localization.CurrentCulture);
        var correlationText = isCorrelationStart
            ? L("Activity.CorrelationRef", OpaqueSuffix(item.CorrelationRef))
            : string.Empty;
        var metaText = string.Join("  ·  ", metaParts);
        var automationName = L(
            "Activity.AutomationLineageName",
            kindText,
            stateText,
            routeText,
            metaText,
            failureText,
            nextActionText,
            timeText);
        return new WorkflowLineageDisplayProjection(
            item.ItemRef,
            "WorkflowLineageItem-" + OpaqueSuffix(item.ItemRef),
            automationName,
            kindText,
            routeText,
            metaText,
            stateText,
            failureText,
            nextActionText,
            timeText,
            correlationText,
            Math.Min(Math.Max(item.CorrelationDepth - 1, 0), 6) * 12d,
            isCorrelationStart,
            WorkflowLineageToneFor(item));
    }

    private void ReconcileWorkflowLineageItems(
        IReadOnlyList<WorkflowLineageDisplayProjection> projected)
    {
        var hadItems = _workflowLineageItems.Count > 0;
        if (_workflowLineageItems.Count == 0 && projected.Count > 0)
        {
            var initial = projected.Select(static value => new WorkflowLineageDisplayItem(value))
                .ToArray();
            foreach (var item in initial)
            {
                _workflowLineageByRef.Add(item.StableRef, item);
            }

            _workflowLineageItems.Initialize(initial);
        }
        else
        {
            var targetRefs = projected.Select(static item => item.StableRef)
                .ToHashSet(StringComparer.Ordinal);
            for (var index = _workflowLineageItems.Count - 1; index >= 0; index--)
            {
                var item = _workflowLineageItems[index];
                if (targetRefs.Contains(item.StableRef))
                {
                    continue;
                }

                _workflowLineageItems.RemoveAt(index);
                _workflowLineageByRef.Remove(item.StableRef);
            }

            for (var targetIndex = 0; targetIndex < projected.Count; targetIndex++)
            {
                var projection = projected[targetIndex];
                if (_workflowLineageByRef.TryGetValue(projection.StableRef, out var item))
                {
                    item.UpdateFrom(projection);
                    var currentIndex = _workflowLineageItems.IndexOf(item);
                    if (currentIndex != targetIndex)
                    {
                        _workflowLineageItems.Move(currentIndex, targetIndex);
                    }

                    continue;
                }

                item = new WorkflowLineageDisplayItem(projection);
                _workflowLineageItems.Insert(targetIndex, item);
                _workflowLineageByRef.Add(item.StableRef, item);
            }
        }

        if (hadItems != (_workflowLineageItems.Count > 0))
        {
            OnPropertyChanged(nameof(HasWorkflowLineageItems));
        }
    }

    private string DisplayWorkflowLineageTask(
        string opaqueReference,
        IReadOnlyDictionary<string, string> taskLabels) =>
        taskLabels.TryGetValue(opaqueReference, out var taskName) &&
        !string.IsNullOrWhiteSpace(taskName)
            ? taskName
            : L("Activity.TaskRef", OpaqueSuffix(opaqueReference));

    private string DisplayWorkflowLineageNextAction(WorkflowActionOperationState? state) =>
        state switch
        {
            null => L("Activity.NextEvaluate"),
            WorkflowActionOperationState.Prepared => L("Activity.NextDispatch"),
            WorkflowActionOperationState.Dispatching => L("Activity.NextVerifyReceipt"),
            WorkflowActionOperationState.Retryable => L("Activity.NextRetry"),
            WorkflowActionOperationState.Uncertain => L("Activity.NextVerifyAuthority"),
            WorkflowActionOperationState.Confirmed => L("Activity.NextAwaitTrigger"),
            _ => L("Activity.NextStopped")
        };

    private void RefreshWorkflowLineageDisplay()
    {
        var snapshot = _workflowLineageSnapshot;
        if (snapshot is null || snapshot.Health == WorkflowLineageHealth.Empty)
        {
            WorkflowLineageStatusText = L("Activity.LineageEmpty");
            WorkflowLineageEmptyText = L("Activity.LineageEmpty");
            return;
        }

        if (snapshot.Health == WorkflowLineageHealth.Unavailable)
        {
            WorkflowLineageStatusText = L("Activity.LineageUnavailable");
            WorkflowLineageEmptyText = L("Activity.LineageUnavailable");
            return;
        }

        WorkflowLineageStatusText = snapshot.Health == WorkflowLineageHealth.Conservative
            ? L("Activity.LineageConservative")
            : snapshot.IsTruncated
                ? L(
                    "Activity.LineageSummaryTruncated",
                    snapshot.Items.Count,
                    snapshot.TotalActionCount)
                : L(
                    "Activity.LineageSummary",
                    snapshot.TotalCorrelationCount,
                    snapshot.TotalActionCount);
        WorkflowLineageEmptyText = snapshot.Health == WorkflowLineageHealth.Conservative
            ? L("Activity.LineageConservative")
            : L("Activity.LineageEmpty");
    }

    private string DisplayWorkflowTrigger(WorkflowTriggerKind triggerKind) => triggerKind switch
    {
        WorkflowTriggerKind.ScheduledAt => L("Workflow.TriggerScheduled"),
        WorkflowTriggerKind.ConversationCompletedNormally =>
            L("Workflow.TriggerConversationCompleted"),
        WorkflowTriggerKind.PresetDispatchConfirmed => L("Workflow.TriggerPresetConfirmed"),
        _ => L("Activity.TriggerObserved")
    };

    private string DisplayWorkflowLineageState(WorkflowActionOperationState? state) => state switch
    {
        WorkflowActionOperationState.Prepared => L("Activity.StatePrepared"),
        WorkflowActionOperationState.Dispatching => L("Activity.StateDispatching"),
        WorkflowActionOperationState.Retryable => L("Activity.StateRetryable"),
        WorkflowActionOperationState.Uncertain => L("Activity.StateUncertain"),
        WorkflowActionOperationState.Confirmed => L("Activity.StateConfirmed"),
        WorkflowActionOperationState.Blocked => L("Activity.StateBlocked"),
        WorkflowActionOperationState.Exhausted => L("Activity.StateExhausted"),
        WorkflowActionOperationState.Canceled => L("Activity.StateCanceled"),
        _ => L("Activity.TriggerObserved")
    };

    private string DisplayWorkflowLineageFailure(WorkflowLineageFailureReason reason) => reason switch
    {
        WorkflowLineageFailureReason.None => string.Empty,
        WorkflowLineageFailureReason.SourceInvalid => L("Activity.FailureSourceInvalid"),
        WorkflowLineageFailureReason.TargetUnavailable => L("Activity.FailureTargetUnavailable"),
        WorkflowLineageFailureReason.PresetUnavailable => L("Activity.FailurePresetUnavailable"),
        WorkflowLineageFailureReason.PolicyBlocked => L("Activity.FailurePolicyBlocked"),
        WorkflowLineageFailureReason.UserActive => L("Activity.FailureUserActive"),
        WorkflowLineageFailureReason.DesktopUnavailable => L("Activity.FailureDesktopUnavailable"),
        WorkflowLineageFailureReason.DesktopIncompatible =>
            L("Activity.FailureDesktopIncompatible"),
        WorkflowLineageFailureReason.PersistenceFailed => L("Activity.FailurePersistence"),
        WorkflowLineageFailureReason.ReceiptUnavailable => L("Activity.FailureReceipt"),
        WorkflowLineageFailureReason.StateChanged => L("Activity.FailureStateChanged"),
        WorkflowLineageFailureReason.SettingsUnavailable => L("Activity.FailureSettings"),
        WorkflowLineageFailureReason.Uncertain => L("Activity.FailureUncertain"),
        WorkflowLineageFailureReason.RetryExhausted => L("Activity.FailureRetryExhausted"),
        WorkflowLineageFailureReason.NewConversationUnavailable =>
            L("Activity.FailureNewConversation"),
        WorkflowLineageFailureReason.NoProgress => L("Activity.FailureNoProgress"),
        WorkflowLineageFailureReason.CorrelationLifetimeExhausted =>
            L("Activity.FailureLifetime"),
        WorkflowLineageFailureReason.CorrelationClockInvalid => L("Activity.FailureClock"),
        WorkflowLineageFailureReason.DispatchBudgetExhausted => L("Activity.FailureBudget"),
        WorkflowLineageFailureReason.CorrelationAuthorityUnavailable =>
            L("Activity.FailureAuthority"),
        _ => L("Activity.FailureOther")
    };

    private static WorkflowLineageTone WorkflowLineageToneFor(WorkflowLineageItem item) =>
        item.State switch
        {
            WorkflowActionOperationState.Dispatching => WorkflowLineageTone.Active,
            WorkflowActionOperationState.Confirmed => WorkflowLineageTone.Success,
            WorkflowActionOperationState.Retryable or WorkflowActionOperationState.Uncertain or
                WorkflowActionOperationState.Canceled => WorkflowLineageTone.Warning,
            WorkflowActionOperationState.Blocked or WorkflowActionOperationState.Exhausted =>
                WorkflowLineageTone.Danger,
            _ => WorkflowLineageTone.Neutral
        };

    private static string OpaqueSuffix(string opaqueReference)
    {
        var separator = opaqueReference.IndexOf('-', StringComparison.Ordinal);
        var suffix = separator >= 0 && separator + 1 < opaqueReference.Length
            ? opaqueReference[(separator + 1)..]
            : opaqueReference;
        return suffix.Length > 6 ? suffix[..6] : suffix;
    }

    private void OnLogEntry(object? sender, LogEntry entry)
    {
        if (entry.Level == LogLevel.Trace)
        {
            return;
        }

        Dispatch(() =>
        {
            Events.Insert(0, entry with { Message = DisplayRuntimeText(entry.Message) });
            while (Events.Count > 120)
            {
                Events.RemoveAt(Events.Count - 1);
            }
        });
    }

    private void OnDesktopConnectionChanged(object? sender, bool connected)
    {
        Dispatch(() =>
        {
            IsDesktopConnected = connected && _desktopIpc.IsNativeChannelAvailable;
            OnPropertyChanged(nameof(DesktopChannelText));
            RaiseConversationMutationCommandCanExecuteChanged();
        });
    }

    private void OnTaskEnabledChanged(object? sender, bool enabled)
    {
        if (sender is not GuardianTaskItem item)
        {
            return;
        }

        if (item.IsArchived)
        {
            item.SetEnabledFromSnapshot(false);
            return;
        }

        _engine.SetThreadEnabled(item.Id, enabled);
        item.ProtectionText = enabled ? string.Empty : L("Tasks.ProtectionPaused");
        UpdateTaskMetrics();
        _ = PersistConversationProtectionAsync(item, enabled);
    }

    private void OnLanguageChanged(object? sender, LanguageChangedEventArgs eventArgs)
    {
        Dispatch(() =>
        {
            Settings.UiLanguage = eventArgs.LanguageCode;
            ApplyCulture();
            RefreshLocalizedDisplay();
            _ = SaveSettingsAsync();
        });
    }

    private void OnEnhancedObservationAvailabilityChanged(object? sender, EventArgs eventArgs)
    {
        Dispatch(() =>
        {
            OnPropertyChanged(nameof(IsEnhancedObservationAvailable));
            OnPropertyChanged(nameof(ObservationMode));
            OnPropertyChanged(nameof(IsDeepObservationAvailable));
            OnPropertyChanged(nameof(EnhancedObservationText));
            OnPropertyChanged(nameof(EnhancedObservationDetail));
            OnPropertyChanged(nameof(CanEnableAutoRecovery));
            OnPropertyChanged(nameof(CanToggleAutoRecovery));
            OnPropertyChanged(nameof(ProtectionModeText));
            OnPropertyChanged(nameof(ProtectionModeDescription));
        });
    }

    private void RefreshLocalizedDisplay()
    {
        OnPropertyChanged(nameof(UiLanguage));
        OnPropertyChanged(nameof(ThemeToggleText));
        OnPropertyChanged(nameof(AvailableLanguages));
        OnPropertyChanged(nameof(SelectedPageTitle));
        OnPropertyChanged(nameof(FollowUpTriggerOptions));
        RaiseWorkflowRuleStorePropertiesChanged();
        OnPropertyChanged(nameof(SelectedTaskFollowUpTitle));
        OnPropertyChanged(nameof(MonitoringSummaryText));
        OnPropertyChanged(nameof(ProtectionModeText));
        OnPropertyChanged(nameof(ProtectionModeDescription));
        OnPropertyChanged(nameof(ProtectionMetricTitle));
        OnPropertyChanged(nameof(ProtectionMetricHint));
        OnPropertyChanged(nameof(TaskProtectionHint));
        OnPropertyChanged(nameof(TaskSearchText));
        OnPropertyChanged(nameof(HasTaskSearchText));
        OnPropertyChanged(nameof(ShowArchived));
        OnPropertyChanged(nameof(ConversationScope));
        OnPropertyChanged(nameof(ConversationScopeText));
        OnPropertyChanged(nameof(TaskEmptyTitleText));
        OnPropertyChanged(nameof(TaskEmptyHintText));
        OnPropertyChanged(nameof(ConversationIndexSummaryText));
        OnPropertyChanged(nameof(RecoveryLedgerSummaryText));
        OnPropertyChanged(nameof(TaskSessionSummaryText));
        OnPropertyChanged(nameof(TaskFilterSummaryText));
        _clearTaskSearchCommand.RaiseCanExecuteChanged();
        EngineState = DisplayEngineState(_rawEngineState);
        EngineDetail = DisplayEngineDetail(_rawEngineState, _rawEngineDetail);
        LastScanText = _engine.LastScanAt?.ToString("HH:mm:ss", _localization.CurrentCulture) ?? L("Value.Never");
        ServerVersion = IsOnline ? L("Status.LocalServiceConnected") : L("Status.NotConnected");
        OnPropertyChanged(nameof(DesktopChannelText));
        OnPropertyChanged(nameof(EnhancedObservationText));
        OnPropertyChanged(nameof(EnhancedObservationDetail));
        RefreshDiagnosticDisplay();

        foreach (var task in Tasks)
        {
            task.Source = DisplaySource(task.RawSource);
            task.HealthText = DisplayHealth(task.HealthResourceKey);
            task.PinActionText = task.IsPinned ? L("Tasks.Unpin") : L("Tasks.Pin");
            task.ConversationSectionTitle = ResolveConversationSectionTitle(task);
            task.ProtectionText = task.IsArchived
                ? L("Tasks.ArchivedReadOnly")
                : !CanEnableConversationProtection || task.IsEnabled
                    ? string.Empty
                    : L("Tasks.ProtectionPaused");
            task.StatusText = DisplayRuntimeText(task.RawStatusText);
            task.ObservationText = DisplayObservation(task.Observation);
            task.LastEvent = DisplayRuntimeText(task.RawLastEvent);
            task.ReadyText = L("Value.Ready");
            UpdateTaskFollowUpDisplay(task);
            UpdateTaskRecoveryLedgerDisplay(task);
            UpdateConversationMutationDisplay(task);
            task.RefreshLocalizedText();
        }

        RefreshWorkflowConversationOptions();
        foreach (var message in FollowUpMessages)
        {
            message.RefreshAttachmentText();
            RefreshWorkflowPresetOptions(message);
            RefreshWorkflowItemProjection(message);
        }

        if (_workflowLineageSnapshot is not null)
        {
            ApplyWorkflowLineageSnapshot(
                _workflowLineageSnapshot,
                forceLocalizedRefresh: true);
        }
        else
        {
            RefreshWorkflowLineageDisplay();
        }

        RefreshTaskFilter();
        // The keep-alive readings hold formatted strings rather than raw values, including the countdown's
        // reason line, so they stay in the old language until the next snapshot without this. The call is free
        // off that page — it returns at the IsKeepAlivePage check.
        RefreshKeepAliveRuntime();
        // Same reason: the update line and the brand mark's tooltip are formatted strings, and nothing else
        // re-renders them until the next check — which may be a day away.
        RefreshUpdateDisplay();
    }

    private void SetDiagnosticState(
        DiagnosticViewState state,
        RecoveryActionKind action = RecoveryActionKind.None,
        string? failureMessage = null)
    {
        _diagnosticState = state;
        _diagnosticAction = action;
        _diagnosticFailureMessage = failureMessage ?? string.Empty;
        RefreshDiagnosticDisplay();
    }

    private void RefreshDiagnosticDisplay()
    {
        (DiagnosticTitle, DiagnosticDetail) = _diagnosticState switch
        {
            DiagnosticViewState.Reading => (
                L("Status.DiagnosticReading"),
                L("Hint.DiagnosticReading")),
            DiagnosticViewState.Forbidden403 => (
                L("Status.Diagnostic403"),
                L("Hint.Diagnostic403")),
            DiagnosticViewState.ManualReview => (
                L("Status.DiagnosticManualReview"),
                L("Hint.DiagnosticNoAction")),
            DiagnosticViewState.NoTurn => (
                L("Status.DiagnosticNoTurn"),
                L("Hint.DiagnosticNoTurn")),
            DiagnosticViewState.Transient => (
                L("Status.DiagnosticTransient"),
                L("Hint.DiagnosticTransient", DescribeAction(_diagnosticAction))),
            DiagnosticViewState.Failed => (
                L("Status.DiagnosticFailed"),
                L("Hint.DiagnosticFailed", _diagnosticFailureMessage)),
            _ => (
                L("Status.DiagnosticIdle"),
                L("Hint.DiagnosticIdle"))
        };

        DiagnosticSource = _diagnosticSourceKey is null ? "—" : L(_diagnosticSourceKey);
    }

    private void OpenFollowUpEditor(object? parameter)
    {
        if (parameter is not GuardianTaskItem task)
        {
            return;
        }

        if (_isFollowUpEditorDirty && !ReferenceEquals(SelectedTask, task))
        {
            FollowUpEditorStatus = L("FollowUp.SaveBeforeTaskSwitch");
            SelectedPage = "FollowUpDetail";
            return;
        }

        SelectedTask = task;
        if (ReferenceEquals(SelectedTask, task))
        {
            SelectedPage = "FollowUpDetail";
        }
    }

    private void BackToTasks()
    {
        SelectedPage = "Tasks";
    }

    private void SetConversationScope(object? parameter)
    {
        ResetConversationNavigation();
        if (parameter is ConversationScopeKind scope)
        {
            ConversationScope = scope;
            return;
        }

        if (parameter is string value &&
            Enum.TryParse(value, ignoreCase: false, out ConversationScopeKind parsed))
        {
            ConversationScope = parsed;
        }
    }

    private void ToggleConversationSection(object? parameter)
    {
        if (parameter is not ConversationNavigationEntry { IsSectionHeader: true } entry)
        {
            return;
        }

        var expanded = !GetConversationSectionExpanded(entry.Key);
        _conversationSectionExpansion[entry.Key] = expanded;
        RequestConversationNavigationTransition();
        RefreshTaskFilter();
    }

    private void RequestConversationNavigationTransition()
    {
        unchecked
        {
            _conversationNavigationMotionRevision++;
        }

        OnPropertyChanged(nameof(ConversationNavigationMotionRevision));
    }

    private void OpenConversationGroup(object? parameter)
    {
        if (parameter is not ConversationNavigationEntry entry)
        {
            return;
        }

        if (entry.IsSectionHeader)
        {
            return;
        }

        if (entry.IsConversation)
        {
            if (entry.ConversationId is { Length: > 0 } conversationId &&
                _tasksById.TryGetValue(conversationId, out var conversation))
            {
                SelectedTask = conversation;
                SelectedPage = "Tasks";
            }

            return;
        }

        if (!entry.IsProject)
        {
            return;
        }

        _conversationGroupKey = entry.Key;
        _conversationGroupTitle = entry.Title;
        OnPropertyChanged(nameof(IsConversationNavigationRoot));
        OnPropertyChanged(nameof(IsConversationNavigationDetail));
        OnPropertyChanged(nameof(ConversationGroupTitle));
        _backToConversationNavigationCommand.RaiseCanExecuteChanged();
        RequestConversationNavigationTransition();
        RefreshTaskFilter();
    }

    private void BackToConversationNavigation() => ResetConversationNavigation();

    private void ResetConversationNavigation()
    {
        if (_conversationGroupKey is null)
        {
            return;
        }

        _conversationGroupKey = null;
        _conversationGroupTitle = string.Empty;
        OnPropertyChanged(nameof(IsConversationNavigationRoot));
        OnPropertyChanged(nameof(IsConversationNavigationDetail));
        OnPropertyChanged(nameof(ConversationGroupTitle));
        _backToConversationNavigationCommand.RaiseCanExecuteChanged();
        RequestConversationNavigationTransition();
        RefreshTaskFilter();
    }

    private void ToggleConversationPin(object? parameter)
    {
        if (parameter is not GuardianTaskItem { IsArchived: false } item)
        {
            return;
        }

        var previousPinned = Settings.PinnedConversationIds.ToArray();
        var nextPinned = previousPinned.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!nextPinned.Add(item.Id))
        {
            nextPinned.Remove(item.Id);
        }

        Settings.PinnedConversationIds = Tasks
            .Select(task => task.Id)
            .Where(nextPinned.Contains)
            .Concat(nextPinned.OrderBy(id => id, StringComparer.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        UpdatePinnedConversationProjection();
        ApplyTaskOrder(OrderTaskItems(Tasks).Select(task => task.Id));
        RefreshTaskFilter();
        _ = PersistConversationPinsAsync(previousPinned);
    }

    private IEnumerable<GuardianTaskItem> OrderTaskItems(IEnumerable<GuardianTaskItem> items)
    {
        var source = items.ToArray();
        var pinned = source
            .Where(task => task.IsPinned && !task.IsArchived)
            .OrderByDescending(task => task.UpdatedAt)
            .ThenBy(task => task.Id, StringComparer.Ordinal);
        var activeUnpinned = source.Where(task => !task.IsPinned && !task.IsArchived).ToArray();
        var archived = source.Where(task => task.IsArchived).ToArray();
        if (Settings.UseManualConversationOrder)
        {
            var rank = Settings.ConversationOrder
                .Select((id, index) => (id, index))
                .ToDictionary(pair => pair.id, pair => pair.index, StringComparer.OrdinalIgnoreCase);
            int ManualRank(string id) => rank.TryGetValue(id, out var value) ? value : int.MinValue;
            var projects = activeUnpinned
                .Where(task => GetRecognizedConversationProjectKey(task.Cwd) is not null)
                .GroupBy(task => GetRecognizedConversationProjectKey(task.Cwd)!, StringComparer.OrdinalIgnoreCase)
                .OrderBy(group => group.Min(task => ManualRank(task.Id)))
                .ThenByDescending(group => group.Max(task => task.UpdatedAt))
                .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .SelectMany(group => group
                    .OrderBy(task => ManualRank(task.Id))
                    .ThenByDescending(task => task.UpdatedAt)
                    .ThenBy(task => task.Id, StringComparer.Ordinal));
            var recent = activeUnpinned
                .Where(task => GetRecognizedConversationProjectKey(task.Cwd) is null)
                .OrderBy(task => ManualRank(task.Id))
                .ThenByDescending(task => task.UpdatedAt)
                .ThenBy(task => task.Id, StringComparer.Ordinal);
            return pinned
                .OrderBy(task => ManualRank(task.Id))
                .ThenByDescending(task => task.UpdatedAt)
                .Concat(projects)
                .Concat(recent)
                .Concat(archived
                    .OrderBy(task => ManualRank(task.Id))
                    .ThenByDescending(task => task.UpdatedAt)
                    .ThenBy(task => task.Id, StringComparer.Ordinal));
        }

        return pinned.Concat(activeUnpinned
            .Where(task => GetRecognizedConversationProjectKey(task.Cwd) is not null)
            .GroupBy(task => GetRecognizedConversationProjectKey(task.Cwd)!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Max(task => task.UpdatedAt))
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .SelectMany(group => group
                .OrderByDescending(task => task.UpdatedAt)
                .ThenBy(task => task.Id, StringComparer.Ordinal)))
            .Concat(activeUnpinned
                .Where(task => GetRecognizedConversationProjectKey(task.Cwd) is null)
                .OrderByDescending(task => task.UpdatedAt)
                .ThenBy(task => task.Id, StringComparer.Ordinal))
            .Concat(archived
                .OrderByDescending(task => task.UpdatedAt)
                .ThenBy(task => task.Id, StringComparer.Ordinal));
    }

    private void UpdatePinnedConversationProjection()
    {
        var pinned = Settings.PinnedConversationIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var task in Tasks)
        {
            task.IsPinned = task.CodexPinnedState ?? pinned.Contains(task.Id);
            task.PinActionText = task.IsPinned ? L("Tasks.Unpin") : L("Tasks.Pin");
            task.ConversationSectionTitle = ResolveConversationSectionTitle(task);
        }
    }

    // Keep-alive sends an arithmetic question and asks for the bare number back, so the newest turn in a
    // kept-alive conversation is often just "9". Upstream names a thread from its content, which turns the
    // whole sidebar into a column of digits. A name that carries no words is treated as unusable and the
    // first meaningful preview line is shown instead; the digit name is never what the user was working on.
    internal static string DisplayConversationTitle(string? title, string? preview)
    {
        var candidate = FirstSafeConversationLine(title);
        if (!LooksLikeKeepAliveAnswer(candidate))
        {
            return candidate.Length > 0 ? candidate : (title?.Trim() ?? string.Empty);
        }

        var raw = preview?.Replace('\r', '\n') ?? string.Empty;
        foreach (var line in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fallback = FirstSafeConversationLine(line);
            if (fallback.Length > 0 && !LooksLikeKeepAliveAnswer(fallback))
            {
                return TruncateConversationPreview(fallback);
            }
        }

        return candidate;
    }

    // Matches both halves of the keep-alive exchange: the bare answer ("9", "-12", "1,024") and the question
    // itself ("73 × 6 = ? (只写答案)"), either of which can end up as the upstream thread name.
    private static bool LooksLikeKeepAliveAnswer(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        if (value.Contains("只写答案", StringComparison.Ordinal))
        {
            return true;
        }

        var digits = 0;
        foreach (var ch in value)
        {
            if (char.IsDigit(ch))
            {
                digits++;
                continue;
            }

            if (ch is ' ' or ',' or '.' or '-' or '+' or '=' or '?' or '×' or '？')
            {
                continue;
            }

            return false;
        }

        return digits > 0;
    }

    internal static string DisplayConversationPreview(string? preview, string? title)
    {
        var raw = preview?.Replace('\r', '\n') ?? string.Empty;
        var safeTitle = FirstSafeConversationLine(title);
        if (LooksLikeStructuredHandoff(raw))
        {
            return string.Empty;
        }

        foreach (var line in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = FirstSafeConversationLine(line);
            if (candidate.Length > 0)
            {
                return string.Equals(candidate, safeTitle, StringComparison.CurrentCultureIgnoreCase)
                    ? string.Empty
                    : TruncateConversationPreview(candidate);
            }
        }

        return string.Empty;
    }

    private static bool LooksLikeStructuredHandoff(string value) =>
        value.Contains("source_thread_id", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("<codex", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("【来源与目录】", StringComparison.Ordinal) ||
        value.Contains("[来源与目录]", StringComparison.Ordinal) ||
        value.Contains("[产品真实目标]", StringComparison.Ordinal) ||
        value.Contains("[不可妥协的安全边界]", StringComparison.Ordinal);

    private static string FirstSafeConversationLine(string? value)
    {
        var candidate = value?.Trim() ?? string.Empty;
        if (candidate.Length == 0 ||
            candidate.StartsWith("<", StringComparison.Ordinal) ||
            candidate.StartsWith("[", StringComparison.Ordinal) ||
            candidate.StartsWith("【", StringComparison.Ordinal) ||
            candidate.Contains("source_thread", StringComparison.OrdinalIgnoreCase) ||
            candidate.Contains("turnRef", StringComparison.OrdinalIgnoreCase) ||
            candidate.Contains("taskRef", StringComparison.OrdinalIgnoreCase) ||
            candidate.Contains("<input>", StringComparison.OrdinalIgnoreCase) ||
            candidate.Contains("D:\\", StringComparison.OrdinalIgnoreCase) ||
            candidate.Contains("C:\\Users\\", StringComparison.OrdinalIgnoreCase) ||
            (candidate.StartsWith("-", StringComparison.Ordinal) &&
             candidate.Contains('\\')))
        {
            return string.Empty;
        }

        return string.Join(
            " ",
            candidate.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries));
    }

    private static string TruncateConversationPreview(string value)
    {
        const int maximumLength = 96;
        return value.Length <= maximumLength ? value : value[..(maximumLength - 1)] + "...";
    }

    private int CompareConversationSections(string? left, string? right)
    {
        var leftRank = ConversationSectionRank(left);
        var rightRank = ConversationSectionRank(right);
        return leftRank != rightRank
            ? leftRank.CompareTo(rightRank)
            : StringComparer.CurrentCulture.Compare(left, right);
    }

    private int ConversationSectionRank(string? value)
    {
        if (string.Equals(value, L("Tasks.PinnedSection"), StringComparison.CurrentCulture))
        {
            return 0;
        }

        if (string.Equals(value, L("Tasks.ProjectsSection"), StringComparison.CurrentCulture))
        {
            return 1;
        }

        if (string.Equals(value, L("Tasks.RecentSection"), StringComparison.CurrentCulture))
        {
            return 2;
        }

        if (string.Equals(value, L("Tasks.ArchivedSection"), StringComparison.CurrentCulture))
        {
            return 3;
        }

        return 4;
    }

    private async Task PersistConversationPinsAsync(IReadOnlyList<string> previousPinned)
    {
        if (await SaveSettingsAsync())
        {
            return;
        }

        Dispatch(() =>
        {
            Settings.PinnedConversationIds = previousPinned.ToList();
            UpdatePinnedConversationProjection();
            ApplyTaskOrder(OrderTaskItems(Tasks).Select(task => task.Id));
            RefreshTaskFilter();
        });
    }

    private static string DisplayProjectName(string? cwd)
    {
        var projectKey = GetRecognizedConversationProjectKey(cwd);
        if (projectKey is null)
        {
            return string.Empty;
        }

        return Path.GetFileName(projectKey.TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar));
    }

    private string ResolveConversationSectionTitle(GuardianTaskItem task)
    {
        if (task.IsArchived)
        {
            return L("Tasks.ArchivedSection");
        }

        if (task.IsPinned)
        {
            return L("Tasks.PinnedSection");
        }

        return string.IsNullOrWhiteSpace(task.ProjectName)
            ? L("Tasks.RecentSection")
            : L("Tasks.ProjectsSection");
    }

    private void ToggleTheme()
    {
        var next = IsDarkTheme ? UiThemes.Light : UiThemes.Dark;
        if (string.Equals(Settings.UiTheme, next, StringComparison.Ordinal))
        {
            return;
        }

        Settings.UiTheme = next;
        OnPropertyChanged(nameof(UiTheme));
        OnPropertyChanged(nameof(IsDarkTheme));
        OnPropertyChanged(nameof(ThemeToggleText));
        UiThemeChanged?.Invoke(next);
        _ = SaveSettingsAsync();
    }

    private void Navigate(object? parameter)
    {
        if (parameter is string page &&
            page is "Overview" or "Tasks" or "Recovery" or "KeepAlive" or "Settings" or "UserGuide")
        {
            SelectedPage = page;
        }
    }

    private async Task PersistConversationProtectionAsync(
        GuardianTaskItem item,
        bool enabled)
    {
        try
        {
            var committed = await _settingsService.SetConversationProtectionFromUserAsync(
                    item.Id,
                    enabled)
                .ConfigureAwait(false);
            Dispatch(() =>
            {
                if (item.IsEnabled != enabled)
                {
                    return;
                }

                ApplyCommittedSettingsProjection(committed);
                item.SetEnabledFromSnapshot(
                    committed.ThreadProtectionEnabled.TryGetValue(item.Id, out var protectedValue) &&
                    protectedValue);
                item.ProtectionText = item.IsArchived || item.IsEnabled
                    ? string.Empty
                    : L("Tasks.ProtectionPaused");
                UpdateTaskMetrics();
            });
        }
        catch (Exception exception)
        {
            _log.Error("无法保存对话保护设置：" + exception.Message, item.Id);
        }
    }

    private async Task PersistAutomaticRecoveryAsync(int intentVersion, bool enabled)
    {
        await _automaticRecoveryMutationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (intentVersion != Volatile.Read(ref _automaticRecoveryIntentVersion) ||
                Volatile.Read(ref _disposeStarted) != 0)
            {
                return;
            }

            var committed = await _settingsService.SetAutomaticRecoveryFromUserAsync(enabled)
                .ConfigureAwait(false);
            Dispatch(() =>
            {
                if (intentVersion != Volatile.Read(ref _automaticRecoveryIntentVersion) ||
                    Volatile.Read(ref _disposeStarted) != 0)
                {
                    return;
                }

                _engine.SetAutomaticRecoveryPolicy(
                    committed.AutomaticRecoveryEnabled,
                    committed.GlobalProtectionEnabled);
                ApplyCommittedSettingsProjection(committed);
                OnPropertyChanged(nameof(AutoRecoveryEnabled));
                OnPropertyChanged(nameof(CanToggleAutoRecovery));
                OnPropertyChanged(nameof(ProtectionModeText));
                OnPropertyChanged(nameof(ProtectionModeDescription));
                _workflowAutomationHost?.NotifyPolicyOrCapabilityChanged();
            });
        }
        catch (Exception exception)
        {
            _log.Error("无法保存自动恢复设置：" + exception.Message);
            Dispatch(() =>
            {
                if (intentVersion != Volatile.Read(ref _automaticRecoveryIntentVersion))
                {
                    return;
                }

                _automaticRecoveryDesired = false;
                _engine.SetAutomaticRecoveryPolicy(
                    enabled: false,
                    Settings.GlobalProtectionEnabled);
                OnPropertyChanged(nameof(AutoRecoveryEnabled));
                OnPropertyChanged(nameof(CanToggleAutoRecovery));
                OnPropertyChanged(nameof(ProtectionModeText));
                OnPropertyChanged(nameof(ProtectionModeDescription));
            });
        }
        finally
        {
            _automaticRecoveryMutationGate.Release();
        }
    }

    private void ApplyCommittedSettingsProjection(AppSettings committed)
    {
        Settings.AutomaticRecoveryEnabled = committed.AutomaticRecoveryEnabled;
        Settings.MonitorOnly = committed.MonitorOnly;
        Settings.GlobalProtectionEnabled = committed.GlobalProtectionEnabled;
        Settings.ThreadProtectionEnabled = new ConcurrentDictionary<string, bool>(
            committed.ThreadProtectionEnabled,
            StringComparer.OrdinalIgnoreCase);
        Settings.ThreadEnabled = new ConcurrentDictionary<string, bool>(
            committed.ThreadEnabled,
            StringComparer.OrdinalIgnoreCase);
        Settings.ConversationOrder = committed.ConversationOrder.ToList();
        Settings.UseManualConversationOrder = committed.UseManualConversationOrder;
        Settings.PinnedConversationIds = committed.PinnedConversationIds.ToList();
        Settings.ReadStatus = committed.ReadStatus;
        Settings.SettingsGeneration = committed.SettingsGeneration;
        Settings.PreviousSettingsGeneration = committed.PreviousSettingsGeneration;
    }

    private void SetAutomaticRecoveryEnabled(bool enabled)
    {
        if (_previewIsolationMode && enabled)
        {
            Settings.AutomaticRecoveryEnabled = false;
            Settings.MonitorOnly = true;
            return;
        }

        if (enabled && !CanEnableAutoRecovery || _automaticRecoveryDesired == enabled)
        {
            return;
        }

        _automaticRecoveryDesired = enabled;
        var intentVersion = Interlocked.Increment(ref _automaticRecoveryIntentVersion);
        if (!enabled)
        {
            _engine.SetAutomaticRecoveryPolicy(
                enabled: false,
                Settings.GlobalProtectionEnabled);
        }

        OnPropertyChanged(nameof(AutoRecoveryEnabled));
        OnPropertyChanged(nameof(CanToggleAutoRecovery));
        OnPropertyChanged(nameof(ProtectionModeText));
        OnPropertyChanged(nameof(ProtectionModeDescription));
        _log.Info(enabled
            ? "Automatic recovery enablement is waiting for a durable settings commit."
            : "Automatic recovery disabled; preset automation keeps its independent authorization.");
        _ = PersistAutomaticRecoveryAsync(intentVersion, enabled);
    }

    private void OpenDataFolder()
    {
        if (_previewIsolationMode)
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(_settingsService.DataDirectory);
            Process.Start(new ProcessStartInfo("explorer.exe", _settingsService.DataDirectory)
            {
                UseShellExecute = true
            });
        }
        catch (Exception exception)
        {
            _log.Warning("无法打开数据目录：" + exception.Message);
        }
    }

    /// <summary>
    /// Opens the project on GitHub in the user's browser.
    /// </summary>
    /// <remarks>
    /// The target is a compile-time constant from <see cref="ProductIdentity"/>, never a URL that arrived over
    /// the network: this call ends in a shell execute, and the update check's response is not trusted with that.
    /// When an update is waiting it goes to the releases page instead of the repository root, because that is
    /// what a user clicking a "new version" badge is asking for.
    /// </remarks>
    private void OpenProjectPage()
    {
        if (_previewIsolationMode)
        {
            return;
        }

        var target = HasUpdateAvailable
            ? ProductIdentity.ReleasesUrl
            : ProductIdentity.RepositoryUrl;
        try
        {
            Process.Start(new ProcessStartInfo(target)
            {
                UseShellExecute = true
            });
        }
        catch (Exception exception)
        {
            _log.Warning("无法打开项目主页：" + exception.Message);
        }
    }

    /// <summary>
    /// Runs the first update check of this session, once the shell is up.
    /// </summary>
    /// <remarks>
    /// Called after the window is loaded rather than from initialization: the check is the least urgent thing
    /// the app does, and a slow DNS lookup should not sit in front of the engine starting.
    /// </remarks>
    internal void BeginStartupUpdateCheck()
    {
        if (_updateCheck is null || !Settings.UpdateCheckEnabled)
        {
            if (!Settings.UpdateCheckEnabled)
            {
                _updateState = UpdateCheckDisplayState.Disabled;
                RefreshUpdateDisplay();
            }

            return;
        }

        _ = CheckForUpdateAsync(force: false);
    }

    private async Task CheckForUpdateAsync(bool force)
    {
        if (_updateCheck is null)
        {
            return;
        }

        if (!Settings.UpdateCheckEnabled && !force)
        {
            _updateState = UpdateCheckDisplayState.Disabled;
            RefreshUpdateDisplay();
            return;
        }

        _updateState = UpdateCheckDisplayState.Checking;
        RefreshUpdateDisplay();

        UpdateCheckResult? result;
        try
        {
            result = await _updateCheck
                .CheckAsync(force, _updateCheckLifetime.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The app is closing. Leaving the display on "checking" is fine; nothing will read it again.
            return;
        }

        Dispatch(() => ApplyUpdateCheckResult(result));
    }

    private void ApplyUpdateCheckResult(UpdateCheckResult? result)
    {
        if (result is null)
        {
            // Every failure mode lands here: offline, rate-limited, proxy, unparseable, no release yet. The
            // service has already logged which one. The UI says only that it did not get an answer, because a
            // failed check is not news the user has to act on.
            _updateState = UpdateCheckDisplayState.Failed;
            RefreshUpdateDisplay();
            return;
        }

        _updateLatestVersionText = result.LatestVersionText;
        _updateState = result.IsNewerThanCurrent
            ? UpdateCheckDisplayState.UpdateAvailable
            : UpdateCheckDisplayState.UpToDate;
        HasUpdateAvailable = result.IsNewerThanCurrent;
        RefreshUpdateDisplay();
        if (result.IsNewerThanCurrent)
        {
            _log.Info("检测到新版本 " + result.LatestVersionText + "，当前版本 " + ProductIdentity.CurrentVersionText + "。");
        }
    }

    /// <summary>Re-renders the update strings from the raw state, so a language switch reaches them too.</summary>
    private void RefreshUpdateDisplay()
    {
        UpdateStatusText = _updateState switch
        {
            UpdateCheckDisplayState.Disabled => L("Update.StatusDisabled"),
            UpdateCheckDisplayState.Checking => L("Update.StatusChecking"),
            UpdateCheckDisplayState.Failed => L("Update.StatusFailed"),
            UpdateCheckDisplayState.UpToDate => string.Format(
                CultureInfo.CurrentCulture,
                L("Update.StatusUpToDate"),
                _updateLatestVersionText),
            UpdateCheckDisplayState.UpdateAvailable => string.Format(
                CultureInfo.CurrentCulture,
                L("Update.StatusAvailable"),
                _updateLatestVersionText),
            _ => L("Update.StatusUnknown")
        };
        OnPropertyChanged(nameof(BrandToolTipText));
        OnPropertyChanged(nameof(CurrentVersionLabelText));
        _checkForUpdateCommand.RaiseCanExecuteChanged();
    }

    private void OpenUserGuide()
    {
        SelectedPage = "UserGuide";
    }

    private void ApplyCulture()
    {
        CultureInfo.DefaultThreadCurrentCulture = _localization.CurrentCulture;
        CultureInfo.DefaultThreadCurrentUICulture = _localization.CurrentCulture;
    }

    private void SetEngineDisplay(string rawState, string rawDetail)
    {
        _rawEngineState = rawState;
        _rawEngineDetail = rawDetail;
        EngineState = DisplayEngineState(rawState);
        EngineDetail = DisplayEngineDetail(rawState, rawDetail);
    }

    private string L(string key, params object?[] values) => values.Length == 0
        ? _localization[key]
        : _localization.Format(key, values);

    private bool IsChinese => _localization.LanguageCode == UiLanguages.SimplifiedChinese;

    private string DisplaySource(string source)
    {
        if (!IsChinese)
        {
            return source;
        }

        return source switch
        {
            "cli" => "命令行",
            "vscode" => "编辑器",
            "exec" => "执行任务",
            "appServer" => "本地服务",
            "subAgent" => "子任务",
            "subAgentReview" => "子任务审查",
            "subAgentCompact" => "子任务摘要",
            "unknown" => "未知来源",
            _ => "其他来源"
        };
    }

    private static string ResolveHealthResourceKey(GuardianTaskState state)
    {
        if (state.Health == TaskHealth.ManualReview &&
            state.Turn is { HasConfirmedLocalTerminal: true } abortedTurn &&
            string.Equals(abortedTurn.Status, "aborted", StringComparison.OrdinalIgnoreCase))
        {
            return IsKnownSingleTextContinue(abortedTurn)
                ? "Health.ContinueUserAborted"
                : "Health.UserAborted";
        }

        if (state.Health == TaskHealth.Unknown &&
            state.Turn is { HasConfirmedLocalTerminal: false } unverifiedAbortTurn &&
            string.Equals(
                unverifiedAbortTurn.Status,
                RecoveryClassifier.UnverifiedAbortStatus,
                StringComparison.OrdinalIgnoreCase))
        {
            return IsKnownSingleTextContinue(unverifiedAbortTurn)
                ? "Health.ContinueAbortReasonUnverified"
                : "Health.AbortReasonUnverified";
        }

        if (state.Health == TaskHealth.Unknown &&
            state.Turn is { HasConfirmedLocalTerminal: false } interruptedTurn &&
            string.Equals(interruptedTurn.Status, "interrupted", StringComparison.OrdinalIgnoreCase))
        {
            return IsKnownSingleTextContinue(interruptedTurn)
                ? "Health.ContinueInterruptedUnverified"
                : "Health.InterruptedUnverified";
        }

        if (state.Health == TaskHealth.NeedsAttention)
        {
            return state.Decision.Action switch
            {
                RecoveryActionKind.ResendOriginal => "Health.MessageUnanswered",
                RecoveryActionKind.ResendContinue => "Health.ContinueUnanswered",
                RecoveryActionKind.SendContinue when state.Turn?.HasToolActivity == true =>
                    "Health.ToolWorkInterrupted",
                RecoveryActionKind.SendContinue when state.Turn?.HasReasoningOutput == true =>
                    "Health.ReasoningInterrupted",
                RecoveryActionKind.SendContinue => "Health.ResponseInterrupted",
                _ => "Health.NeedsAttention"
            };
        }

        if (state.Health == TaskHealth.ManualReview &&
            (state.Turn?.HasAmbiguousActivity == true || state.Turn?.HasCompleteItemEvidence == false))
        {
            return "Health.EvidenceIncomplete";
        }

        return "Health." + state.Health;
    }

    private static bool IsKnownSingleTextContinue(TurnSnapshot turn) =>
        turn.HasUserMessage &&
        turn.IsSingleTextUserInput &&
        !turn.HasAttachments &&
        RecoveryClassifier.IsContinueInput(turn.UserText);

    private string DisplayHealth(string resourceKey) => L(resourceKey);

    private string DisplayObservation(GuardianTaskObservation? observation)
    {
        if (observation is null || observation.Phase == GuardianObservedPhase.Unknown)
        {
            return string.Empty;
        }

        var detail = observation.Phase switch
        {
            GuardianObservedPhase.Idle => L("Observation.Idle"),
            GuardianObservedPhase.Running => L("Observation.Running"),
            GuardianObservedPhase.Reasoning => L("Observation.Reasoning"),
            GuardianObservedPhase.Tool => DisplayObservedTool(observation.ItemType),
            GuardianObservedPhase.Reconnecting when
                observation.ReconnectAttempt is int attempt &&
                observation.ReconnectMaxAttempts is int maximum =>
                L("Observation.ReconnectingProgress", attempt, maximum),
            GuardianObservedPhase.Reconnecting => L("Observation.Reconnecting"),
            GuardianObservedPhase.Completed => L("Observation.Completed"),
            GuardianObservedPhase.Failed => L("Observation.Failed"),
            GuardianObservedPhase.Interrupted => L("Observation.Interrupted"),
            _ => string.Empty
        };

        if (detail.Length == 0)
        {
            return string.Empty;
        }

        if (observation.HttpStatusCode is int statusCode)
        {
            detail = L("Observation.WithHttpStatus", detail, statusCode);
        }

        return L("Observation.Format", detail);
    }

    private string DisplayObservedTool(string? itemType) => itemType switch
    {
        "commandExecution" => L("Observation.CommandExecution"),
        "fileChange" => L("Observation.FileChange"),
        "mcpToolCall" or "dynamicToolCall" => L("Observation.ToolCall"),
        "webSearch" => L("Observation.WebSearch"),
        "imageGeneration" => L("Observation.ImageGeneration"),
        "collabAgentToolCall" => L("Observation.Collaboration"),
        _ => L("Observation.Tool")
    };

    private string DisplayTurnStatus(string status)
    {
        if (!IsChinese)
        {
            if (string.Equals(
                    status,
                    RecoveryClassifier.IncompleteTerminalStatus,
                    StringComparison.OrdinalIgnoreCase))
            {
                return "Incomplete terminal";
            }

            if (string.Equals(status, "aborted", StringComparison.OrdinalIgnoreCase))
            {
                return "Stopped by user";
            }

            return string.Equals(
                status,
                RecoveryClassifier.UnverifiedAbortStatus,
                StringComparison.OrdinalIgnoreCase)
                ? "Abort reason unverified"
                : status;
        }

        return status switch
        {
            "completed" => "已完成",
            "inProgress" => "处理中",
            "failed" => "失败",
            "interrupted" => "已中断",
            "aborted" => "用户中止",
            RecoveryClassifier.UnverifiedAbortStatus => "中止原因待确认",
            RecoveryClassifier.IncompleteTerminalStatus => "未正常收尾",
            _ => "未知"
        };
    }

    private string DisplayEngineState(string state)
    {
        if (!IsChinese)
        {
            return state;
        }

        return state switch
        {
            "Starting" or "正在准备" => "正在准备",
            "Paused" or "已暂停" => "已暂停",
            "Scanning" or "正在扫描" or "正在检查" => "正在检查",
            "Monitor only" or "仅监测" => "仅监测恢复",
            "Protected" or "自动恢复" => "自动恢复",
            "Offline" or "离线" => "离线",
            _ => state
        };
    }

    private string DisplayEngineDetail(string state, string detail)
    {
        if (IsChinese && string.Equals(state, "Offline", StringComparison.Ordinal))
        {
            return "本地监测服务暂时不可用，详细原因已记录到本地日志。";
        }

        return DisplayRuntimeText(detail);
    }

    private string DisplayRuntimeText(string value)
    {
        if (!IsChinese || string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var exact = value switch
        {
            "Connecting to Codex app-server..." => "正在连接 Codex 本地服务…",
            "Preparing local services..." => "正在准备本地服务…",
            "Monitoring is paused." => "监测已暂停。",
            "Reading recent task state..." => "正在读取近期任务状态…",
            "Synchronizing recent task state..." => "正在同步近期任务状态…",
            "Synchronizing the complete task directory..." => "正在同步完整会话目录…",
            "No turn history is available yet." => "暂无对话轮次记录。",
            "No turn history is available for this historical task." => "该历史任务暂无可读取的轮次记录。",
            "Codex is still processing this task." => "Codex 正在处理该任务。",
            "The latest turn completed normally." => "最近一轮已正常完成。",
            "The latest turn completed with a final response." => "最近一轮已产生最终回答并正常完成。",
            "Codex reported completion, but a matching local terminal and final response are not both available." =>
                "Codex 报告已完成，但本地终态与最终回答证据尚未同时确认。",
            "The independent state reader cannot prove that this turn ended; waiting for a local terminal event." => "独立状态读取无法证明该轮次已经结束，正在等待本地终态事件。",
            "The local rollout contains an abort event with an unrecognized reason; automatic recovery is blocked." =>
                "本地记录包含原因无法识别的中止事件，已阻止自动恢复。",
            "The latest turn failed with an explicitly non-recoverable error." => "最近一轮发生明确不可自动恢复的错误。",
            "The task was explicitly stopped and will not be resumed automatically." => "任务已被用户明确停止，不会自动恢复。",
            "Codex activity stack reports that this task is still running." => "Codex 活动状态显示该任务仍在运行。",
            "The Codex Desktop state stream missed an update; targeted verification is pending." =>
                L("Status.DesktopStreamGap"),
            "Guardian recovery turn is running in the background." => L("Engine.GuardianBackgroundRunning"),
            "Waiting for Codex Desktop to own this task; no hidden session will be used." => "正在等待 Codex 桌面端接管该任务，不会使用桌面不可见的独立会话。",
            "The continue message ended before output; classify as ResendContinue for a native in-place retry of the failed turn." =>
                "继续消息在产生输出前异常结束，将通过 Codex 桌面端原生通道就地重试该轮次。",
            "The user message reached Codex but ended without a final response or work evidence; classify as ResendOriginal for a native in-place retry of the failed turn." =>
                "用户消息没有最终回答或工作证据，将通过 Codex 桌面端原生通道就地重试该轮次。",
            "The task ended after tool or file work started; append continue to avoid repeating side effects." =>
                "任务已有工具或文件工作，将通过 Codex 桌面端追加 continue。",
            "The task ended while reasoning was underway; append continue instead of replaying the prompt." =>
                "任务在思考途中中断，将通过 Codex 桌面端追加 continue。",
            "The task ended after assistant output started but before a final response; append continue." =>
                "任务已有助手输出，将通过 Codex 桌面端追加 continue。",
            "The task ended abnormally after output started; send continue through the background protocol." =>
                "任务已有输出后异常结束，将通过 Codex 桌面端追加 continue。",
            "The turn activity evidence is incomplete or contains an unknown item type; automatic recovery is blocked." =>
                "轮次活动证据不完整或包含未知类型，已阻止自动恢复。",
            "The failed turn has no safely replayable user input and no proven work to continue." =>
                "失败轮次既没有可安全重放的用户输入，也没有可确认的工作进度，需人工检查。",
            "Protection is disabled for this task." => "该任务的保护已暂停。",
            "Recovery was sent; waiting for Codex to create or finish the next turn." => "恢复请求已发送，正在等待 Codex 创建或完成下一轮。",
            "Automatic attempt limit reached; manual review is required." => "已达到自动尝试上限，需要人工检查。",
            "Archived task is shown for history only and is not eligible for recovery." => "该会话已归档，仅用于历史查看，不参与自动恢复。",
            "Archived task is not monitored for recovery." => "归档会话不参与恢复监测。",
            "Latest turn completed normally." => "最近一轮已正常完成。",
            "Not connected" => "未连接",
            "Connected" => "已连接",
            "Guardian started in monitor-only mode." => "守护已按只监测模式启动。",
            "Guardian started with automatic recovery enabled." => "守护已启动，并启用自动恢复。",
            "Guardian monitoring paused." => "守护监测已暂停。",
            "Connected to the local Codex service; background recovery is available." => "已连接 Codex 本地服务，后台恢复通道可用。",
            "Connected to the read-only Codex state service." => "已连接 Codex 只读状态服务。",
            "Task protection enabled." => "已启用任务保护。",
            "Task protection paused." => "已暂停任务保护。",
            "Automatic recovery enabled; background protocol safeguards remain active." => "已启用自动恢复，后台协议安全检查已生效。",
            "Monitor-only mode enabled; automatic recovery is disabled. Preset automation keeps its own authorization gates." =>
                "已启用仅监测恢复；预制自动化仍按独立授权门禁执行。",
            "Unable to read latest turn" => "无法读取最新对话轮次。",
            "The local rollout terminal corrected an app-server turn that had lost its failure state." => "已从本地会话终态补回本地服务丢失的失败状态。",
            "A recoverable failure was detected. A Codex composer is being edited, so the retry waits for that draft to be released, bounded by a 20 second patience window." =>
                "已检测到可恢复错误；因为 Codex 输入栏中有正在编辑的内容，重发暂缓等待该草稿释放，最多等待 20 秒后仍会提交恢复。",
            "A Codex composer is being edited; the retry waits for the draft to be released." =>
                "Codex 输入栏中有正在编辑的内容，重发正在等待该草稿释放。",
            "No Codex composer is being edited, so the retry proceeds immediately." =>
                "Codex 输入栏中没有正在编辑的内容，立即执行重发。",
            "A Codex composer stayed busy past the recovery patience window; Guardian stopped waiting so the retry is not delayed indefinitely." =>
                "Codex 输入栏持续处于编辑状态并超过等待上限，守护已停止等待，避免重发被无限期拖延。",
            "A Codex composer stayed busy past the recovery patience window; Guardian navigated to the task anyway so the retry is not delayed indefinitely." =>
                "Codex 输入栏持续处于编辑状态并超过等待上限，守护已直接切换到该任务，避免重发被无限期拖延。",
            "Waiting for 3 seconds without Windows user input." =>
                "增强观察不可用，回退为等待 Windows 连续 3 秒无输入后提交恢复。",
            "Windows has been idle for at least 3 seconds." =>
                "增强观察不可用，已确认 Windows 连续 3 秒无输入。",
            "No recovery action is available." => "没有可执行的恢复动作。",
            "Codex Desktop does not expose an atomic failed-turn precondition. Automatic recovery is safety-locked; no message was sent." => "当前 Codex 桌面端未提供原子失败轮次前置校验；自动恢复已安全锁定，本次没有发送任何消息。",
            "The background protocol could not confirm the latest turn; nothing was sent." => "后台协议无法确认最新轮次，本次没有发送。",
            "The task already has a newer turn; the stale recovery action was cancelled." => "任务已经产生更新轮次，已取消过时的恢复动作。",
            "The task is already running; no recovery message was sent." => "任务已经在运行，本次没有重复发送。",
            "The background protocol resumed a different task; nothing was sent." => "后台协议恢复了其他任务，本次没有发送。",
            "The task changed while the background session was being prepared; nothing was sent." => "后台会话准备期间任务状态已变化，本次没有发送。",
            "Codex accepted the request but did not return a new turn id." => "Codex 已接受请求，但没有返回新轮次编号。",
            "Codex did not create a new turn; the recovery action was not committed." => "Codex 没有创建新轮次，恢复动作未提交。",
            "The original message has attachments, but no replayable payload was returned by the local protocol." => "原消息包含附件，但本地协议没有返回可安全重放的附件载荷。",
            "The original message is empty and cannot be retried safely." => "原消息内容为空，无法安全重试。",
            "The read-only state service could not confirm the latest turn; nothing was sent." => "只读状态服务无法确认最新轮次，本次没有发送。",
            "The latest turn is no longer an abnormal terminal state; nothing was sent." => "最近一轮已不再处于异常终态，本次没有发送。",
            "Waiting for Codex Desktop to own this task; nothing was sent through a hidden session." => "正在等待 Codex 桌面端接管该任务，本次没有通过不可见会话发送。",
            "Waiting for the Codex Desktop task owner; no recovery message was sent." => "正在等待 Codex 桌面端接管该任务，本次没有发送恢复消息。",
            "The task state changed inside Codex Desktop; the stale recovery action was cancelled." => "Codex 桌面端内的任务状态已经变化，已取消过时的恢复动作。",
            "Codex Desktop rejected an invalid recovery payload; nothing was sent." => "Codex 桌面端拒绝了无效的恢复载荷，本次没有发送。",
            "Codex Desktop could not recover the original structured input; nothing was sent." => "Codex 桌面端无法恢复原消息的完整结构，本次没有发送。",
            "This Codex Desktop version does not expose the compatible native task channel; nothing was sent." => "当前 Codex 桌面端版本不支持兼容的原生任务通道，本次没有发送。",
            "Codex Desktop real-time delivery is temporarily unavailable; no recovery message was sent." => "Codex 桌面端实时发送通道暂时不可用，本次没有发送恢复消息。",
            "Codex Desktop real-time delivery is temporarily unavailable; nothing was sent through a hidden session." => "Codex 桌面端实时发送通道暂时不可用，本次没有通过不可见会话发送。",
            "Connected to the Codex Desktop real-time delivery channel." => "已连接 Codex 桌面端实时发送通道。",
            "Connected to the native Codex Desktop task channel." => "已连接 Codex 桌面端原生任务通道。",
            "Connected to Codex Desktop, but its native task channel is not compatible." => "Codex 桌面端已连接，但当前版本的原生任务通道不兼容。",
            "A matching local terminal event is required before automatic recovery can be considered." =>
                "需要先在本地记录中确认该轮次已经结束，才能考虑自动恢复。",
            "The turn has no confirmed user-message input; automatic recovery is blocked." =>
                "该轮次没有可确认的用户消息输入，已阻止自动恢复。",
            "The terminal failure is not an explicitly supported transient network, stream, overload, rate-limit, or server error." =>
                "该终态错误不属于明确支持的网络、流式、过载、限流或服务端临时错误。",
            "The failed turn no longer has an exact, explicitly recoverable classification; nothing was sent." =>
                "失败轮次已不再具备明确可恢复的分类，本次没有发送。",
            "This failed turn already has a different durable recovery action; no second operation was created." =>
                "该失败轮次已有另一个持久化恢复动作，没有再创建第二个操作。",
            "This failed turn has a closed recovery operation and will not be sent again." =>
                "该失败轮次的恢复操作已关闭，不会再次发送。",
            "The prior recovery operation remains uncertain and cannot be attributed by its stable client id; no message was sent." =>
                "上一次恢复操作仍处于状态待确认，且无法通过稳定客户端编号归属，本次没有发送。",
            "The persisted recovery operation has no stable client id; manual review is required and no id was fabricated." =>
                "持久化的恢复操作缺少稳定客户端编号，需要人工检查；程序不会伪造编号。",
            "Exact structured attachment replay authority is unavailable; nothing was sent." =>
                "无法取得附件精确重放的授权，本次没有发送。",
            "The exact structured attachment input could not be revalidated; nothing was sent." =>
                "无法重新校验附件的精确结构，本次没有发送。",
            "The installed Codex Desktop recovery semantics are not proven; nothing was sent." =>
                "当前安装的 Codex 桌面端恢复语义尚未得到证明，本次没有发送。",
            "The installed Codex Desktop recovery semantics are not compatible; nothing was sent." =>
                "当前安装的 Codex 桌面端恢复语义不兼容，本次没有发送。",
            "The installed Codex Desktop recovery semantics could not be proven; nothing was sent." =>
                "无法证明当前 Codex 桌面端的恢复语义，本次没有发送。",
            "The installed Codex Desktop recovery semantics changed before dispatch; nothing was sent." =>
                "发送前 Codex 桌面端的恢复语义发生变化，本次没有发送。",
            "The installed Codex Desktop recovery semantics could not be revalidated; nothing was sent." =>
                "无法重新校验当前 Codex 桌面端的恢复语义，本次没有发送。",
            "The current Codex Desktop native owner channel is not proven; nothing was sent." =>
                "当前 Codex 桌面端的原生接管通道尚未得到证明，本次没有发送。",
            "The Codex Desktop native owner channel is not ready yet; the retry waits for it and nothing was sent." =>
                "Codex 桌面端的原生接管通道尚未就绪，重发正在等待它连上，本次没有发送。",
            "The Codex Desktop native owner channel is ready; pending retries resume now." =>
                "Codex 桌面端的原生接管通道已就绪，正在恢复执行待处理的重发。",
            "The Desktop owner state changed during final validation; nothing was sent." =>
                "最终校验期间桌面端接管状态发生变化，本次没有发送。",
            "The structured attachment replay lease changed before dispatch; nothing was sent." =>
                "发送前附件重放租约发生变化，本次没有发送。",
            "Monitoring stopped before Desktop dispatch; the unsent operation remains retryable." =>
                "发送前监测已停止，这次未发出的操作仍可重试。",
            "The Desktop owner state changed before the start-turn request; the unsent recovery remains retryable." =>
                "提交新轮次请求前桌面端接管状态发生变化，这次未发出的恢复仍可重试。",
            "Monitoring stopped during the final editor observation; the unsent recovery remains retryable." =>
                "最终编辑器观察期间监测已停止，这次未发出的恢复仍可重试。",
            "Monitoring stopped after the final editor observation; the unsent recovery remains retryable." =>
                "最终编辑器观察之后监测已停止，这次未发出的恢复仍可重试。",
            "The verified Desktop owner changed after the final editor observation; the unsent recovery remains retryable." =>
                "最终编辑器观察之后已核实的桌面端接管方发生变化，这次未发出的恢复仍可重试。",
            "The bounded Desktop commit window elapsed after dispatch began." =>
                "发送开始后，桌面端提交确认的等待窗口已超时。",
            "Codex Desktop rejected this recovery action as incompatible; nothing will be resent for this failed turn." =>
                "Codex 桌面端判定该恢复动作不兼容，该失败轮次不会再次发送。",
            "Waiting for the Codex Desktop task owner; the recovery request was explicitly rejected before commit." =>
                "正在等待 Codex 桌面端接管该任务；恢复请求在提交前被明确拒绝。",
            "Codex Desktop was unavailable before the recovery request was dispatched." =>
                "恢复请求发送前 Codex 桌面端不可用。",
            "Recovery failed after dispatch began; Guardian will reconcile without redispatching the uncertain request." =>
                "发送开始后恢复失败；守护会核对状态，不会重复发送这次状态待确认的请求。",
            "The monitoring scope changed before recovery validation; nothing was sent." =>
                "恢复校验前监测范围发生变化，本次没有发送。",
            "The target task's current storage and source metadata could not be revalidated; nothing was sent." =>
                "无法重新校验目标任务当前的存储与来源信息，本次没有发送。",
            "The task is archived; automatic recovery was cancelled before Desktop dispatch." =>
                "该任务已归档，自动恢复在发送前被取消。",
            "The task is no longer uniquely present in the active task scope; nothing was sent." =>
                "该任务已不在活动任务范围内唯一存在，本次没有发送。",
            "The task is outside the configured automatic recovery scope; nothing was sent." =>
                "该任务不在已配置的自动恢复范围内，本次没有发送。",
            "Automatic recovery policy changed before Desktop dispatch; nothing was sent." =>
                "发送前自动恢复策略发生变化，本次没有发送。",
            "The prior recovery dispatch is uncertain and task state is unavailable; nothing was resent." =>
                "上一次恢复发送状态待确认，且当前无法读取任务状态，本次没有重发。",
            "The stable recovery message id appeared in multiple recent turns; reconciliation remains uncertain." =>
                "稳定恢复消息编号出现在多个近期轮次中，核对结果仍不确定。",
            "The prior recovery dispatch is uncertain and no latest turn could be confirmed; nothing was resent." =>
                "上一次恢复发送状态待确认，且无法确认最新轮次，本次没有重发。",
            "A newer turn exists, but it cannot be attributed to this recovery operation; the old failure was superseded without resending." =>
                "已存在更新的轮次，但无法归属到本次恢复操作；旧的失败已被取代，没有重发。",
            "The failed turn is still last, so the uncertain in-place retry was reopened for another attempt." =>
                "失败轮次仍是最后一轮，这次状态待确认的就地重试已重新开放，准备再试一次。",
            "The uncertain in-place retry could not be durably reopened; nothing was sent." =>
                "无法持久化地重新开放这次就地重试，本次没有发送。",
            "The prior start-turn request may have been dispatched. The stable client id is used for reconciliation only; without proven receiver deduplication Guardian will not send it again." =>
                "上一次新轮次请求可能已经发出。稳定客户端编号只用于核对；在接收端去重未获证明前，守护不会重复发送。",
            "Desktop delivery could not yet be confirmed. Guardian will wait for a task or connection event and will not redispatch an uncertain request." =>
                "桌面端投递尚未确认。守护会等待任务或连接事件，不会重复发送状态待确认的请求。",
            "The Desktop owner has a different latest turn; the stale recovery action was cancelled." =>
                "桌面端接管方的最新轮次与预期不一致，已取消过时的恢复动作。",
            "The Desktop owner no longer reports an abnormal terminal turn; nothing was sent." =>
                "桌面端接管方已不再报告异常终态轮次，本次没有发送。",
            "Codex Desktop does not provide a strict atomic failed-turn compare-and-start contract; no recovery message was sent." =>
                "Codex 桌面端未提供严格的原子失败轮次比对并启动契约，本次没有发送恢复消息。",
            "Windows stayed busy past the recovery patience window; Guardian navigated to the task anyway so the retry is not delayed indefinitely." =>
                "Windows 持续有输入并超过了等待上限，守护已直接切到该任务，避免恢复被无限期推迟。",
            "Windows stayed busy past the recovery patience window; Guardian stopped waiting for idle input so the retry is not delayed indefinitely." =>
                "Windows 持续有输入并超过了等待上限，守护已停止等待空闲，避免恢复被无限期推迟。",
            "Opened the task through the registered stock Codex deep link." =>
                "已通过注册的 Codex 原生深链打开该任务。",
            "Unable to verify Windows user idle time; automatic recovery was deferred." =>
                "无法确认 Windows 用户空闲时长，本次自动恢复已推迟。",
            "The failed turn is no longer the last user turn, so Codex Desktop refused the in-place retry and nothing was resent." =>
                "失败轮次已不是最后一条用户消息，Codex 桌面端拒绝了就地重试，本次没有重发。",
            "Codex Desktop answered the in-place retry without confirming it." =>
                "Codex 桌面端回应了就地重试，但没有给出确认。",
            "Codex Desktop's in-place retry contract cannot carry attachments, and Guardian will not append a duplicate message instead." =>
                "Codex 桌面端的就地重试通道无法携带附件，守护也不会改为追加一条重复消息。",
            "The original user text for the failed turn is unavailable, so it cannot be retried in place." =>
                "失败轮次的原始用户文本不可用，无法就地重试。",
            "The original user text exceeds the Desktop channel limit for an in-place retry." =>
                "原始用户文本超出桌面端就地重试通道的长度上限。",
            "Codex Desktop resend recovery runs through the in-place retry contract; Guardian does not append a duplicate of the failed message." =>
                "Codex 桌面端的重发恢复走就地重试通道；守护不会追加失败消息的副本。",
            "The expected failed turn id is required for an in-place retry." =>
                "就地重试需要提供预期的失败轮次编号。",
            "Codex Desktop accepted the request but did not return a new turn id." =>
                "Codex 桌面端已接受请求，但没有返回新轮次编号。",
            "Codex Desktop has not proved the native recovery channel." =>
                "Codex 桌面端尚未证明原生恢复通道可用。",
            "The durable recovery operation is closed; this failed turn will not be sent again." =>
                "该持久化恢复操作已关闭，这个失败轮次不会再次发送。",
            "Codex Desktop connection was cancelled before the recovery request was dispatched." =>
                "恢复请求发送前，与 Codex 桌面端的连接被取消。",
            "The Codex Desktop IPC server identity could not be verified." =>
                "无法验证 Codex 桌面端 IPC 服务的身份。",
            "The durable recovery operation is confirmed without a committed turn id; no message was sent." =>
                "持久化恢复操作已确认，但没有已提交的轮次编号，本次没有发送。",
            "The durable journal retains a legacy Desktop acknowledgement and will not dispatch it again." =>
                "持久化台账保留了旧版桌面端确认记录，不会再次发送。",
            _ => null
        };
        if (exact is not null)
        {
            return exact;
        }

        const string permanentFailurePrefix =
            "The latest turn failed with an explicitly non-recoverable error.";
        if (value.StartsWith(permanentFailurePrefix, StringComparison.Ordinal))
        {
            var evidence = value[permanentFailurePrefix.Length..].Trim();
            if (evidence.StartsWith('(') && evidence.EndsWith(").", StringComparison.Ordinal))
            {
                var localizedEvidence = evidence[1..^2]
                    .Replace(", ", "，", StringComparison.Ordinal)
                    .Replace("code ", "错误代码 ", StringComparison.Ordinal);
                return $"最近一轮发生明确不可自动恢复的错误（{localizedEvidence}）。";
            }

            return "最近一轮发生明确不可自动恢复的错误。";
        }

        if (value.StartsWith("Monitor-only: ", StringComparison.Ordinal))
        {
            return "仅监测：" + DisplayRuntimeText(value[14..]);
        }

        const string archivedInexactPrefix = "Archived ";
        const string archivedInexactSuffix =
            " unconfirmed recovery operation(s) so the in-place retry is not blocked by an inexact successor.";
        if (value.StartsWith(archivedInexactPrefix, StringComparison.Ordinal) &&
            value.EndsWith(archivedInexactSuffix, StringComparison.Ordinal))
        {
            var archivedCount = value[
                archivedInexactPrefix.Length..^archivedInexactSuffix.Length];
            return $"已归档 {archivedCount} 条未确认的恢复记录，避免它继续阻塞本轮就地重发。";
        }

        if (value.StartsWith("Detected ", StringComparison.Ordinal) && value.EndsWith("; retrying now.", StringComparison.Ordinal))
        {
            return "已检测到可恢复异常，正在立即重发。";
        }

        const string scanSeparator = " tasks synchronized at ";
        var scanSeparatorIndex = value.IndexOf(scanSeparator, StringComparison.Ordinal);
        if (scanSeparatorIndex > 0 &&
            int.TryParse(value[..scanSeparatorIndex], NumberStyles.None, CultureInfo.InvariantCulture, out var scannedTaskCount))
        {
            var scannedAt = value[(scanSeparatorIndex + scanSeparator.Length)..];
            return $"已同步 {scannedTaskCount} 个任务，时间 {scannedAt}。";
        }

        if (value.StartsWith("Executing ", StringComparison.Ordinal) && value.EndsWith(".", StringComparison.Ordinal))
        {
            var rawAction = value[10..^1];
            return Enum.TryParse<RecoveryActionKind>(rawAction, ignoreCase: false, out var action)
                ? "正在执行：" + DescribeAction(action) + "。"
                : "正在执行恢复操作。";
        }

        if (value.StartsWith("Unable to inspect task state:", StringComparison.Ordinal))
        {
            return "无法检查任务状态，详细原因已记录到本地日志。";
        }

        if (value.StartsWith("Unable to reconcile the latest local terminal event:", StringComparison.Ordinal))
        {
            return "无法核对本地会话的最新终态，已继续使用本地服务状态。";
        }

        const string protocolSuccessPrefix = "Sent the ";
        const string protocolSuccessSeparator = " through the native Codex Desktop channel; new turn: ";
        if (value.StartsWith(protocolSuccessPrefix, StringComparison.Ordinal) &&
            value.IndexOf(protocolSuccessSeparator, StringComparison.Ordinal) is var separatorIndex &&
            separatorIndex > protocolSuccessPrefix.Length)
        {
            var action = value[protocolSuccessPrefix.Length..separatorIndex];
            var turnId = value[(separatorIndex + protocolSuccessSeparator.Length)..];
            var actionText = action switch
            {
                "original message" => "原消息",
                "failed continue input" => "失败的 continue 原输入",
                _ => "新的 continue 消息"
            };
            return $"已通过 Codex 桌面端发送{actionText}，新轮次：{turnId}";
        }

        if (value.StartsWith("Background protocol send failed:", StringComparison.Ordinal))
        {
            return "后台协议发送失败，程序会在退避后重新核对任务状态。";
        }

        const string inPlaceRetrySentPrefix =
            "Retried the failed turn in place through the native Codex Desktop channel; new turn: ";
        if (value.StartsWith(inPlaceRetrySentPrefix, StringComparison.Ordinal))
        {
            return "已通过 Codex 桌面端原生通道就地重试该失败轮次，新轮次：" +
                value[inPlaceRetrySentPrefix.Length..];
        }

        const string appendSuccessorSentPrefix =
            "Appended a continue successor through the native Codex Desktop channel; new turn: ";
        if (value.StartsWith(appendSuccessorSentPrefix, StringComparison.Ordinal))
        {
            return "已通过 Codex 桌面端原生通道追加 continue 后继轮次，新轮次：" +
                value[appendSuccessorSentPrefix.Length..];
        }

        const string inPlaceRetryObservedPrefix =
            "The in-place retry replaced the failed turn; observed replacement turn: ";
        if (value.StartsWith(inPlaceRetryObservedPrefix, StringComparison.Ordinal))
        {
            return "就地重试已替换该失败轮次，观察到的替换轮次：" +
                value[inPlaceRetryObservedPrefix.Length..];
        }

        const string stableIdMatchedPrefix = "The stable recovery message id matched an existing turn: ";
        if (value.StartsWith(stableIdMatchedPrefix, StringComparison.Ordinal))
        {
            return "稳定恢复消息编号已匹配到既有轮次：" + value[stableIdMatchedPrefix.Length..];
        }

        const string durableConfirmedPrefix = "Durable recovery confirmed: ";
        if (value.StartsWith(durableConfirmedPrefix, StringComparison.Ordinal))
        {
            return "恢复已持久化确认，新轮次：" + value[durableConfirmedPrefix.Length..];
        }

        const string journalConfirmedPrefix =
            "The recovery operation was already confirmed by the durable journal: ";
        if (value.StartsWith(journalConfirmedPrefix, StringComparison.Ordinal))
        {
            return "该恢复操作已由持久化台账确认，新轮次：" + value[journalConfirmedPrefix.Length..];
        }

        if (value.StartsWith("Codex Desktop real-time delivery failed:", StringComparison.Ordinal))
        {
            return "Codex 桌面端实时发送失败，程序会在退避后重新核对任务状态。";
        }

        if (value.StartsWith("Monitoring synchronization failed:", StringComparison.Ordinal))
        {
            return "状态同步失败，详细原因已记录到本地日志。";
        }

        if (value.StartsWith("Codex Desktop IPC is incompatible:", StringComparison.Ordinal))
        {
            return "当前 Codex 桌面端版本不支持原生任务通道。";
        }

        if (value.Contains("paid balance insufficient", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("可用额度不足", StringComparison.OrdinalIgnoreCase))
        {
            return "检测到 403 可用额度不足；此错误不可自动恢复。";
        }

        return value;
    }

    private string DescribeAction(RecoveryActionKind action) => action switch
    {
        RecoveryActionKind.ResendOriginal => L("Action.ResendOriginal"),
        RecoveryActionKind.SendContinue => L("Action.SendContinue"),
        RecoveryActionKind.ResendContinue => L("Action.ResendContinue"),
        _ => L("Action.NoAutomaticAction")
    };

    /// <summary>What the update check has concluded, before it is turned into text.</summary>
    private enum UpdateCheckDisplayState
    {
        /// <summary>No check has concluded yet this run.</summary>
        Unknown,
        Checking,
        /// <summary>The check ran and got no usable answer. The modes are deliberately not distinguished.</summary>
        Failed,
        UpToDate,
        UpdateAvailable,
        /// <summary>The user turned the check off.</summary>
        Disabled
    }

    private enum DiagnosticViewState
    {
        Idle,
        Reading,
        Forbidden403,
        ManualReview,
        NoTurn,
        Transient,
        Failed
    }

    private static void Dispatch(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            dispatcher.BeginInvoke(DispatcherPriority.Background, action);
        }
    }
}
