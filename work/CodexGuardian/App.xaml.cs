using System.Threading;
using System.Windows;
using System.Windows.Threading;
using CodexGuardian.Localization;
using CodexGuardian.Models;
using CodexGuardian.Services;
using CodexGuardian.ViewModels;

namespace CodexGuardian;

internal sealed class GuardianApplicationStartupOwnerV1 : IDisposable
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _cancellation = new();
    private readonly TaskCompletionSource _settlement = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private long _generation;
    private int _activePublications;
    private bool _started;
    private bool _revoked;
    private bool _startupCompleted;
    private bool _settled;
    private bool _disposed;

    internal Task Settlement => _settlement.Task;

    internal bool TryBegin(out StartupLease lease)
    {
        lock (_gate)
        {
            if (_disposed || _started || _revoked || _startupCompleted || _settled)
            {
                lease = null!;
                return false;
            }

            _started = true;
            _generation = checked(_generation + 1);
            lease = new StartupLease(this, _generation, _cancellation.Token);
            return true;
        }
    }

    internal void Revoke()
    {
        var settle = false;
        lock (_gate)
        {
            if (_disposed || _revoked)
            {
                return;
            }

            _revoked = true;
            if (!_started && !_settled)
            {
                _settled = true;
                settle = true;
            }
        }

        CancelNoThrow(_cancellation);
        if (settle)
        {
            _settlement.TrySetResult();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        CancelNoThrow(_cancellation);
        if (_settlement.Task.IsCompleted)
        {
            _cancellation.Dispose();
        }
    }

    private void Gate(long generation)
    {
        lock (_gate)
        {
            ValidateActiveGenerationNoLock(generation);
        }

        _cancellation.Token.ThrowIfCancellationRequested();
    }

    private void RunTrackedPublication(long generation, Action publication)
    {
        ArgumentNullException.ThrowIfNull(publication);
        lock (_gate)
        {
            ValidateActiveGenerationNoLock(generation);
            _activePublications = checked(_activePublications + 1);
        }

        try
        {
            publication();
        }
        finally
        {
            CompletePublication(generation);
        }
    }

    private void PublishAtomic(long generation, Action atomicPublication)
    {
        ArgumentNullException.ThrowIfNull(atomicPublication);
        lock (_gate)
        {
            ValidateActiveGenerationNoLock(generation);
            atomicPublication();
        }
    }

    private void Complete(long generation)
    {
        var settle = false;
        lock (_gate)
        {
            if (!_started || generation != _generation)
            {
                throw new InvalidOperationException(
                    "The Guardian application startup lease generation is invalid.");
            }

            if (_startupCompleted)
            {
                return;
            }

            _startupCompleted = true;
            settle = TrySettleNoLock();
        }

        if (settle)
        {
            _settlement.TrySetResult();
        }
    }

    private void CompletePublication(long generation)
    {
        var settle = false;
        lock (_gate)
        {
            if (!_started || generation != _generation || _activePublications <= 0)
            {
                throw new InvalidOperationException(
                    "The Guardian application startup publication is invalid.");
            }

            _activePublications--;
            settle = TrySettleNoLock();
        }

        if (settle)
        {
            _settlement.TrySetResult();
        }
    }

    private bool TrySettleNoLock()
    {
        if (_settled || !_startupCompleted || _activePublications != 0)
        {
            return false;
        }

        _settled = true;
        return true;
    }

    private void ValidateActiveGenerationNoLock(long generation)
    {
        if (_disposed || !_started || generation != _generation ||
            _startupCompleted || _settled)
        {
            throw new InvalidOperationException(
                "The Guardian application startup lease is not active.");
        }

        if (_revoked)
        {
            throw new OperationCanceledException(
                "The Guardian application startup authority was revoked.",
                _cancellation.Token);
        }
    }

    private static void CancelNoThrow(CancellationTokenSource cancellation)
    {
        try
        {
            cancellation.Cancel();
        }
        catch
        {
        }
    }

    internal sealed class StartupLease : ISettingsWriteAuthority
    {
        private readonly GuardianApplicationStartupOwnerV1 _owner;
        private readonly long _generation;
        private int _completed;

        internal StartupLease(
            GuardianApplicationStartupOwnerV1 owner,
            long generation,
            CancellationToken cancellationToken)
        {
            _owner = owner;
            _generation = generation;
            CancellationToken = cancellationToken;
        }

        internal CancellationToken CancellationToken { get; }

        internal void Gate()
        {
            ObjectDisposedException.ThrowIf(
                Volatile.Read(ref _completed) != 0,
                this);
            _owner.Gate(_generation);
        }

        internal void RunTrackedPublication(Action publication)
        {
            ObjectDisposedException.ThrowIf(
                Volatile.Read(ref _completed) != 0,
                this);
            _owner.RunTrackedPublication(_generation, publication);
        }

        internal void PublishAtomic(Action atomicPublication)
        {
            ObjectDisposedException.ThrowIf(
                Volatile.Read(ref _completed) != 0,
                this);
            _owner.PublishAtomic(_generation, atomicPublication);
        }

        void ISettingsWriteAuthority.Publish(Action atomicPublication)
        {
            PublishAtomic(atomicPublication);
        }

        internal void Complete()
        {
            if (Interlocked.Exchange(ref _completed, 1) == 0)
            {
                _owner.Complete(_generation);
            }
        }
    }
}

public partial class App : System.Windows.Application
{
    private const string SingleInstanceMutexName = "Local\\CodexGuardian.SingleInstance";
    private const string ReleaseExchangeMutexName = "Local\\CodexGuardian.ReleaseExchange";

    private sealed record StartupNotice(
        string Message,
        string Title,
        MessageBoxImage Image);

    private readonly record struct StartupOutcome(
        int? ExitCode,
        StartupNotice? Notice);

    private Mutex? _singleInstance;
    private bool _ownsSingleInstance;
    private Mutex? _releaseExchange;
    private bool _ownsReleaseExchange;
    private GuardianLog? _log;
    private CodexDeepObservationService? _deepObservation;
    private WindowsCodexInteractionHook? _interactionHook;
    private CompositeRecoveryInterferenceGuard? _interactionGuard;
    private MainViewModel? _viewModel;
    private WorkflowAutomationHost? _workflowAutomationHost;
    private MainWindow? _mainWindow;
    private GuardianBrokerBootstrapLifetime? _brokerBootstrapLifetime;
    private readonly GuardianApplicationStartupOwnerV1 _startupOwner = new();
    private readonly object _exitGate = new();
    private Task? _exitTask;
    private int _requestedExitCode;
    private int _exitRequested;

    public bool ExitRequested => Volatile.Read(ref _exitRequested) != 0;

    private void OnDispatcherUnhandledException(
        object sender,
        System.Windows.Threading.DispatcherUnhandledExceptionEventArgs eventArgs)
    {
        _log?.Error("Unhandled dispatcher exception (process kept alive): " + eventArgs.Exception);
        eventArgs.Handled = true;
    }

    internal void AttachBrokerBootstrapLifetime(
        GuardianBrokerBootstrapLifetime brokerBootstrapLifetime)
    {
        ArgumentNullException.ThrowIfNull(brokerBootstrapLifetime);
        if (_brokerBootstrapLifetime is not null)
        {
            throw new InvalidOperationException(
                "The Guardian Broker bootstrap lifetime was already attached.");
        }

        _brokerBootstrapLifetime = brokerBootstrapLifetime;
        brokerBootstrapLifetime.AttachFailClosedShutdown(
            RequestBrokerFailClosedShutdown);
    }

    protected override async void OnStartup(StartupEventArgs eventArgs)
    {
        base.OnStartup(eventArgs);
        // A rendering fault must never take the watchdog offline. Losing the process means resends
        // stop entirely, which is the one failure this app exists to prevent, so a UI-thread
        // exception is logged and swallowed instead of terminating the runtime.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        if (!_startupOwner.TryBegin(out var startup))
        {
            await RequestExitCoreAsync(exitCode: 1);
            return;
        }

        LocalizationService? localization = null;
        StartupOutcome outcome = default;
        try
        {
            localization = (LocalizationService)Resources["Loc"];
            outcome = await StartupCoreAsync(eventArgs, startup, localization);
        }
        catch (OperationCanceledException) when (
            startup.CancellationToken.IsCancellationRequested || ExitRequested)
        {
        }
        catch (Exception exception)
        {
            _log?.Error("Startup failed: " + exception);
            outcome = new StartupOutcome(
                ExitCode: 1,
                Notice: localization is null
                    ? null
                    : new StartupNotice(
                    localization.Format("App.StartFailedMessage", exception.Message),
                    localization["App.StartFailedTitle"],
                    MessageBoxImage.Error));
        }
        finally
        {
            startup.Complete();
        }

        ShowStartupNoticeIfAllowed(outcome.Notice);
        if (outcome.ExitCode.HasValue || ExitRequested)
        {
            await RequestExitCoreAsync(outcome.ExitCode ?? 0);
        }
    }

    private async Task<StartupOutcome> StartupCoreAsync(
        StartupEventArgs eventArgs,
        GuardianApplicationStartupOwnerV1.StartupLease startup,
        LocalizationService localization)
    {
        startup.Gate();
        var launchOptions = GuardianLaunchOptions.Parse(eventArgs.Args);
        _singleInstance = new Mutex(
            initiallyOwned: true,
            launchOptions.ResolveStartupMutexName(SingleInstanceMutexName),
            out _ownsSingleInstance);
        if (!_ownsSingleInstance)
        {
            return new StartupOutcome(
                ExitCode: 0,
                Notice: new StartupNotice(
                    localization["App.AlreadyRunningMessage"],
                    localization["App.AlreadyRunningTitle"],
                    MessageBoxImage.Information));
        }

        startup.Gate();
        _releaseExchange = new Mutex(
            initiallyOwned: false,
            launchOptions.ResolveStartupMutexName(ReleaseExchangeMutexName));
        try
        {
            _ownsReleaseExchange = _releaseExchange.WaitOne(0);
        }
        catch (AbandonedMutexException)
        {
            _ownsReleaseExchange = true;
        }
        if (!_ownsReleaseExchange)
        {
            _releaseExchange.Dispose();
            _releaseExchange = null;
            return new StartupOutcome(ExitCode: 0, Notice: null);
        }

        startup.Gate();
        var settingsService = new SettingsService(
            launchOptions.DataDirectory,
            monitoringEnabledAfterNormalization: !launchOptions.SafePreview);
        var persistedSettings = await settingsService.LoadAsync(startup.CancellationToken);
        startup.Gate();
        var previewFixture = launchOptions.FollowUpPreviewFixture
            ? FollowUpPreviewFixture.Create(DateTimeOffset.UtcNow, persistedSettings)
            : null;
        var settings = previewFixture?.Settings ?? persistedSettings;
        startup.Gate();
        if (launchOptions.SafePreview)
        {
            settings.MonitoringEnabled = false;
            settings.MonitorOnly = true;
            settings.AutomaticRecoveryEnabled = false;
            settings.MinimizeToTray = false;
            settings.StartWithWindows = false;
            settings.ThreadEnabled.Clear();
            settings.ThreadProtectionEnabled.Clear();
            if (previewFixture is null)
            {
                settings.ThreadFollowUps.Clear();
            }
        }

        startup.Gate();
        localization.SetLanguage(settings.UiLanguage);
        startup.RunTrackedPublication(() =>
            _log = new GuardianLog(settingsService.DataDirectory));
        var log = _log ?? throw new InvalidOperationException(
            "The Guardian startup log was not published.");
        if (launchOptions.AllowsLiveIntegration)
        {
            _deepObservation = new CodexDeepObservationService(log);
            _interactionHook = new WindowsCodexInteractionHook(log);
            _interactionGuard = new CompositeRecoveryInterferenceGuard(
                _deepObservation,
                _interactionHook);
        }

        var locator = new CodexCliLocator();
        var appServer = new AppServerClient(locator, log);
        var desktopIpc = new DesktopIpcClient(log);
        var desktopOwnerActivator = new DesktopThreadOwnerActivator(desktopIpc, log);
        if (_interactionHook is not null)
        {
            // Deferring a retry on Windows-wide idle time delayed every recovery even when nobody was
            // typing. The interaction hook answers the only question that matters: is a Codex composer
            // actually being edited right now.
            var interactionHook = _interactionHook;
            desktopOwnerActivator = desktopOwnerActivator.WithComposerProbe(
                interactionHook.IsComposerBeingEdited);
        }

        var recoveryJournal = new RecoveryOperationJournal(settingsService.DataDirectory);
        if (launchOptions.AllowsLiveIntegration)
        {
            startup.Gate();
            var journalSnapshot = await recoveryJournal.ReadAsync(startup.CancellationToken);
            startup.Gate();
            if (journalSnapshot.ReadStatus is RecoveryJournalReadStatus.RecoveredFromBackup or
                RecoveryJournalReadStatus.Corrupted or
                RecoveryJournalReadStatus.UnsupportedSchema)
            {
                log.Warning(
                    "The recovery journal requires conservative reconciliation: " +
                    journalSnapshot.ReadStatus);
            }
        }

        ConversationMutationService? conversationMutations = null;
        if (launchOptions.AllowsLiveIntegration)
        {
            var conversationMutationJournal = new ConversationMutationOperationJournal(
                settingsService.DataDirectory);
            startup.Gate();
            var conversationMutationSnapshot = await conversationMutationJournal.ReadAsync(
                startup.CancellationToken);
            startup.Gate();
            if (conversationMutationSnapshot.ReadStatus is
                ConversationMutationJournalReadStatus.RecoveredFromBackup or
                ConversationMutationJournalReadStatus.Corrupted or
                ConversationMutationJournalReadStatus.UnsupportedSchema)
            {
                log.Warning(
                    "The conversation mutation journal requires conservative reconciliation: " +
                    conversationMutationSnapshot.ReadStatus);
            }

            conversationMutations = new ConversationMutationService(
                appServer,
                desktopIpc,
                desktopOwnerActivator,
                conversationMutationJournal,
                log,
                _interactionGuard);
        }
        FollowUpOperationJournal? followUpJournal = null;
        if (launchOptions.AllowsLiveIntegration)
        {
            followUpJournal = new FollowUpOperationJournal(settingsService.DataDirectory);
            startup.Gate();
            var followUpJournalSnapshot = await followUpJournal.ReadAsync(
                startup.CancellationToken);
            startup.Gate();
            if (followUpJournalSnapshot.ReadStatus is FollowUpJournalReadStatus.RecoveredFromBackup or
                FollowUpJournalReadStatus.Corrupted or FollowUpJournalReadStatus.UnsupportedSchema)
            {
                log.Warning(
                    "The follow-up journal requires conservative reconciliation: " +
                    followUpJournalSnapshot.ReadStatus);
            }
        }

        var structuredCapabilities = launchOptions.AllowsLiveIntegration
            ? new InstalledCodexStructuredInputCapabilityProvider(settings.AttachmentLimits)
            : null;
        var attachmentRuntime = new FollowUpAttachmentRuntime(
            settingsService.DataDirectory,
            settingsService,
            launchOptions.AllowsLiveIntegration ? followUpJournal : null,
            launchOptions.AllowsLiveIntegration ? recoveryJournal : null,
            structuredCapabilities);
        attachmentRuntime.DraftAuthority.ReplaceVisibleDrafts(
            version: 0,
            settings.ThreadFollowUps.Values);

        var structuredDispatchReady = false;
        if (launchOptions.AllowsLiveIntegration)
        {
            startup.Gate();
            var reconciliation = attachmentRuntime.Reconciliation is null
                ? null
                : await attachmentRuntime.Reconciliation.ReconcileAsync(
                    settings,
                    startup.CancellationToken);
            startup.Gate();
            structuredDispatchReady = reconciliation?.IsHealthy == true;
            if (!structuredDispatchReady)
            {
                log.Warning(
                    "Attachment presentation reconciliation blocked structured sending: " +
                    (reconciliation?.Status.ToString() ?? "Unavailable"));
            }
        }

        IRecoveryStructuredInputReplayAuthority? recoveryStructuredInputReplay =
            launchOptions.AllowsLiveIntegration && structuredDispatchReady
                ? new RecoveryStructuredInputReplayAuthority(
                    followUpJournal!,
                    attachmentRuntime.Presentation)
                : null;
        var threadActions = launchOptions.AllowsLiveIntegration
            ? new ThreadActionCoordinator()
            : null;
        var recovery = launchOptions.AllowsLiveIntegration
            ? ProductionRecoveryServiceFactory.CreateLive(
                appServer,
                desktopIpc,
                desktopOwnerActivator,
                recoveryJournal,
                log,
                _interactionGuard!,
                structuredCapabilities!,
                recoveryStructuredInputReplay,
                threadActions!,
                settings)
            : new RecoveryService(
                appServer,
                desktopIpc,
                desktopOwnerActivator,
                recoveryJournal,
                log,
                defaultCountingMode: settings.RecoveryCountingMode,
                defaultMaximumAttempts: settings.MaximumRecoveryAttempts,
                defaultUnlimitedAttempts: settings.UnlimitedRecoveryAttempts);

        FollowUpDispatchService? followUps = null;
        if (launchOptions.AllowsLiveIntegration)
        {
            followUps = new FollowUpDispatchService(
                appServer,
                desktopIpc,
                desktopOwnerActivator,
                followUpJournal!,
                log,
                _interactionGuard,
                structuredCapabilities: structuredDispatchReady
                    ? attachmentRuntime.StructuredCapabilities
                    : null,
                attachmentStore: structuredDispatchReady ? attachmentRuntime.Store : null,
                presentationLeases: structuredDispatchReady ? attachmentRuntime.Presentation : null,
                attachmentPins: structuredDispatchReady ? attachmentRuntime.DraftAuthority : null,
                threadActions: threadActions);
        }

        if (launchOptions.AllowsLiveIntegration)
        {
            startup.RunTrackedPublication(() => _deepObservation!.Start());
            startup.RunTrackedPublication(() => _interactionHook!.Start());
        }

        var classifier = new RecoveryClassifier();
        var localHistory = launchOptions.SafePreview
            ? new LocalConversationHistoryReader(Path.Combine(
                settingsService.DataDirectory,
                "preview-sessions"))
            : new LocalConversationHistoryReader();
        var startupService = new StartupService();
        var engine = new GuardianEngine(
            settings,
            appServer,
            desktopIpc,
            recovery,
            classifier,
            localHistory,
            log,
            _deepObservation,
            followUps,
            launchOptions.SafePreview);
        startup.Gate();
        var workflowRuleStore = new WorkflowRuleStore(settingsService.DataDirectory);
        WorkflowRuleStoreSnapshot? workflowRuleSnapshot = null;
        if (previewFixture is not null)
        {
            try
            {
                workflowRuleSnapshot = await workflowRuleStore.ReadAsync(startup.CancellationToken);
                startup.Gate();
                if (!workflowRuleSnapshot.RequiresConservativeRecovery &&
                    (workflowRuleSnapshot.ReadStatus is
                        WorkflowRuleStoreReadStatus.Missing or WorkflowRuleStoreReadStatus.Healthy) &&
                    !workflowRuleSnapshot.Rules
                        .OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
                        .Select(rule => rule.DefinitionDigest)
                        .SequenceEqual(
                            previewFixture.WorkflowRules
                                .OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
                                .Select(rule => rule.DefinitionDigest),
                            StringComparer.Ordinal))
                {
                    workflowRuleSnapshot = await workflowRuleStore.SaveAsync(
                        previewFixture.WorkflowRules,
                        startup.CancellationToken);
                    startup.Gate();
                }
            }
            catch (OperationCanceledException) when (startup.CancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                log.Warning(
                    "Preview workflow fixture initialization failed (" +
                    exception.GetType().Name + ").");
            }
        }

        WorkflowOperationJournal? workflowJournal = null;
        WorkflowAutomationHost? workflowAutomationHost = null;
        if (launchOptions.AllowsLiveIntegration)
        {
            startup.Gate();
            workflowJournal = new WorkflowOperationJournal(settingsService.DataDirectory);
            var workflowExecutor = new WorkflowActionExecutor(
                workflowJournal,
                new FollowUpWorkflowPresetDispatcher(followUps!),
                new SettingsWorkflowConversationProtectionService(settingsService));
            IWorkflowAttachmentAvailabilityReader? workflowAttachments = structuredDispatchReady
                ? new ManagedWorkflowAttachmentAvailabilityReader(
                    attachmentRuntime.Store,
                    attachmentRuntime.StructuredCapabilities!)
                : null;
            var workflowResolver = new WorkflowExecutionResolver(
                new AppServerWorkflowConversationAuthorityReader(appServer, localHistory),
                new SettingsWorkflowSettingsAuthorityReader(settingsService),
                new StoreWorkflowRuleRevisionAuthorityReader(workflowRuleStore),
                new JournalWorkflowOperationAuthorityReader(
                    workflowJournal,
                    followUpJournal!),
                workflowAttachments);
            var workflowRunner = new WorkflowRuleActionRunner(
                workflowResolver,
                workflowExecutor,
                new WorkflowDispatchPolicyAuthority(settingsService));
            var workflowRuntime = new WorkflowAutomationRuntime(
                workflowRuleStore,
                workflowJournal,
                new WorkflowTriggerCoordinator(
                    workflowJournal,
                    new WorkflowFiniteConditionEvaluator(workflowResolver),
                    workflowRunner),
                workflowRunner);
            workflowAutomationHost = new WorkflowAutomationHost(
                new WorkflowAutomationEventAdapter(
                    workflowRuntime,
                    new GuardianEngineWorkflowCompletionSource(engine),
                    workflowExecutor),
                new GuardianWorkflowAutomationAuthorityChangeSource(engine, desktopIpc),
                log);
            startup.RunTrackedPublication(() =>
                _workflowAutomationHost = workflowAutomationHost);
        }

        var viewModel = new MainViewModel(
            settings,
            settingsService,
            startupService,
            log,
            engine,
            appServer,
            desktopIpc,
            classifier,
            localization,
            _interactionGuard,
            launchOptions.SafePreview,
            attachmentRuntime.Composition,
            attachmentRuntime.DraftAuthority,
            conversationMutations: conversationMutations,
            workflowRuleStore: workflowRuleStore,
            workflowRuleSnapshot: workflowRuleSnapshot,
            workflowAutomationHost: workflowAutomationHost,
            workflowLineageReader: workflowJournal is null
                ? null
                : new WorkflowJournalLineageReader(workflowJournal));
        _viewModel = viewModel;
        if (previewFixture is not null)
        {
            startup.Gate();
            viewModel.LoadFollowUpPreviewFixture(previewFixture);
        }

        startup.Gate();
        await viewModel.InitializeForApplicationStartupAsync(
            startup.CancellationToken,
            startup);
        startup.Gate();
        var window = new MainWindow(
            viewModel,
            enableTray: !launchOptions.SafePreview,
            attachmentRuntime,
            launchOptions.SafePreview,
            log);
        _mainWindow = window;
        startup.RunTrackedPublication(() =>
        {
            MainWindow = window;
            window.ActivateForStartup(showWindow: !launchOptions.Background);
        });
        startup.PublishAtomic(viewModel.MarkApplicationStartupPublished);
        return new StartupOutcome(ExitCode: null, Notice: null);
    }

    private void ShowStartupNoticeIfAllowed(StartupNotice? notice)
    {
        if (notice is null || _brokerBootstrapLifetime is not null || ExitRequested ||
            Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
        {
            return;
        }

        MessageBox.Show(
            notice.Message,
            notice.Title,
            MessageBoxButton.OK,
            notice.Image);
    }

    public async Task RequestExitAsync()
    {
        await RequestExitCoreAsync(exitCode: 0);
    }

    private Task RequestExitCoreAsync(int exitCode)
    {
        RecordExitRequest(exitCode);
        TaskCompletionSource? exitOwner = null;
        Task exitTask;
        lock (_exitGate)
        {
            if (_exitTask is null)
            {
                exitOwner = new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                _exitTask = exitOwner.Task;
            }

            exitTask = _exitTask;
        }

        if (exitOwner is not null)
        {
            _ = FinishExitCoreAsync(exitOwner);
        }

        return exitTask;
    }

    private void RecordExitRequest(int exitCode)
    {
        lock (_exitGate)
        {
            _requestedExitCode = Math.Max(_requestedExitCode, exitCode);
            Volatile.Write(ref _exitRequested, 1);
        }

        _startupOwner.Revoke();
    }

    private async Task FinishExitCoreAsync(TaskCompletionSource exitOwner)
    {
        await _startupOwner.Settlement;
        if (_mainWindow is not null)
        {
            var window = _mainWindow;
            _mainWindow = null;
            MainWindow = null;
            try
            {
                window.DeactivateForExit();
            }
            catch (Exception exception)
            {
                _log?.Error("Main window cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }

        if (_workflowAutomationHost is not null)
        {
            var workflowAutomationHost = _workflowAutomationHost;
            _workflowAutomationHost = null;
            try
            {
                await workflowAutomationHost.DisposeAsync();
            }
            catch (Exception exception)
            {
                _log?.Error(
                    "Workflow automation host cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }

        if (_viewModel is not null)
        {
            var viewModel = _viewModel;
            _viewModel = null;
            try
            {
                await viewModel.DisposeAsync();
            }
            catch (Exception exception)
            {
                _log?.Error("View model cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }

        if (_interactionHook is not null)
        {
            var interactionHook = _interactionHook;
            _interactionHook = null;
            try
            {
                await interactionHook.DisposeAsync();
            }
            catch (Exception exception)
            {
                _log?.Error("Interaction hook cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }
        if (_deepObservation is not null)
        {
            var deepObservation = _deepObservation;
            _deepObservation = null;
            try
            {
                await deepObservation.DisposeAsync();
            }
            catch (Exception exception)
            {
                _log?.Error("Deep observation cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }
        _interactionGuard = null;

        if (_brokerBootstrapLifetime is not null)
        {
            var brokerBootstrapLifetime = _brokerBootstrapLifetime;
            _brokerBootstrapLifetime = null;
            try
            {
                await brokerBootstrapLifetime.DisposeAsync();
            }
            catch (Exception exception)
            {
                _log?.Error("Broker bootstrap lifetime cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }

        if (_log is not null)
        {
            var log = _log;
            _log = null;
            try
            {
                log.Dispose();
            }
            catch
            {
                RecordExitRequest(1);
            }
        }

        int finalExitCode;
        lock (_exitGate)
        {
            finalExitCode = _requestedExitCode;
        }

        try
        {
            Shutdown(finalExitCode);
            exitOwner.TrySetResult();
        }
        catch (Exception exception)
        {
            exitOwner.TrySetException(exception);
        }
    }

    protected override void OnExit(ExitEventArgs eventArgs)
    {
        RecordExitRequest(eventArgs.ApplicationExitCode);
        if (_mainWindow is not null)
        {
            var window = _mainWindow;
            _mainWindow = null;
            MainWindow = null;
            try
            {
                window.DeactivateForExit();
            }
            catch (Exception exception)
            {
                _log?.Error("Main window exit cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }

        if (_workflowAutomationHost is not null)
        {
            var workflowAutomationHost = _workflowAutomationHost;
            _workflowAutomationHost = null;
            DisposeOnExitNoThrow(workflowAutomationHost, "workflow automation host");
        }

        if (_viewModel is not null)
        {
            var viewModel = _viewModel;
            _viewModel = null;
            DisposeOnExitNoThrow(viewModel, "view model");
        }

        if (_interactionHook is not null)
        {
            var interactionHook = _interactionHook;
            _interactionHook = null;
            DisposeOnExitNoThrow(interactionHook, "interaction hook");
        }
        if (_deepObservation is not null)
        {
            var deepObservation = _deepObservation;
            _deepObservation = null;
            DisposeOnExitNoThrow(deepObservation, "deep observation");
        }
        _interactionGuard = null;

        if (_brokerBootstrapLifetime is not null)
        {
            var brokerBootstrapLifetime = _brokerBootstrapLifetime;
            _brokerBootstrapLifetime = null;
            try
            {
                brokerBootstrapLifetime.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            catch (Exception exception)
            {
                _log?.Error("Broker bootstrap lifetime exit cleanup failed: " + exception.GetType().Name);
                RecordExitRequest(1);
            }
        }

        if (_log is not null)
        {
            var log = _log;
            _log = null;
            try
            {
                log.Dispose();
            }
            catch
            {
                RecordExitRequest(1);
            }
        }

        try
        {
            if (_ownsReleaseExchange)
            {
                _releaseExchange?.ReleaseMutex();
            }
            _releaseExchange?.Dispose();
        }
        catch
        {
            RecordExitRequest(1);
        }

        try
        {
            if (_ownsSingleInstance)
            {
                _singleInstance?.ReleaseMutex();
            }
            _singleInstance?.Dispose();
        }
        catch
        {
            RecordExitRequest(1);
        }

        _startupOwner.Dispose();
        lock (_exitGate)
        {
            Environment.ExitCode = Math.Max(Environment.ExitCode, _requestedExitCode);
        }
        base.OnExit(eventArgs);
    }

    private void DisposeOnExitNoThrow(IAsyncDisposable value, string label)
    {
        try
        {
            value.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        catch (Exception exception)
        {
            _log?.Error(label + " exit cleanup failed: " + exception.GetType().Name);
            RecordExitRequest(1);
        }
    }

    private static string? ReadArgumentValue(string[] arguments, string name)
    {
        var index = Array.FindIndex(
            arguments,
            argument => string.Equals(argument, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < arguments.Length
            ? arguments[index + 1]
            : null;
    }

    private void RequestBrokerFailClosedShutdown(Exception failure)
    {
        RecordExitRequest(1);
        if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished)
        {
            Environment.ExitCode = 1;
            return;
        }

        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Send,
            new Action(BeginBrokerFailClosedExit));
    }

    private async void BeginBrokerFailClosedExit()
    {
        try
        {
            await RequestExitCoreAsync(exitCode: 1);
        }
        catch
        {
            RecordExitRequest(1);
            await _startupOwner.Settlement;
            if (!Dispatcher.HasShutdownStarted && !Dispatcher.HasShutdownFinished)
            {
                Shutdown(1);
            }
        }
    }
}
