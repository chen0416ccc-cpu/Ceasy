using CodexGuardian;
using CodexGuardian.Control;
using CodexGuardian.Localization;
using CodexGuardian.Models;
using CodexGuardian.Services;
using CodexGuardian.Trust;
using CodexGuardian.ViewModels;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

internal static class GuardianBrokerManagedBootstrapOfflineTests
{
    private const string StartupSettingsTestDataRootEnvironmentVariable =
        "CODEX_GUARDIAN_TEST_DATA_ROOT";

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "Guardian Broker bootstrap CLI dispatch is exact and fail-closed",
            TestExactArguments,
            assert);
        RunCase(
            "Guardian Broker bootstrap reads one exact bounded frame",
            TestExactBootstrapRead,
            assert);
        RunCase(
            "Guardian Broker ready validation binds launch challenge and release",
            TestReadyBinding,
            assert);
        await RunCaseAsync(
            "Guardian application startup owner revokes and settles one exact generation",
            TestApplicationStartupOwnerAsync,
            assert);
        RunCase(
            "Guardian application startup and fail-closed exit share one authority barrier",
            TestApplicationStartupSourceBoundary,
            assert);
        await RunCaseAsync(
            "Guardian startup settings use read-only load and atomic authority publication",
            TestStartupSettingsAuthorityAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Canceled Guardian startup disposal cannot resave unpublished settings",
            TestCanceledStartupViewModelDisposalAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Guardian Broker process winner cleans a late successful stage result",
            TestLateStageResultCleanupAsync,
            assert);
        await RunCaseAsync(
            "Guardian Broker stage drain timeout quarantines late authority cleanup",
            TestLateStageQuarantineAsync,
            assert);
        await RunCaseAsync(
            "Guardian Broker stage quarantine observes a late fault",
            TestLateStageFaultAsync,
            assert);
        await RunCaseAsync(
            "Guardian Broker resolves the exact stage at the drain-timeout completion boundary",
            TestTimedOutStageCompletionBoundaryAsync,
            assert);
        RunCase(
            "Guardian Broker stage cancellation classification survives CTS ownership transfer",
            TestDisposedStageCancellationToken,
            assert);
        await RunCaseAsync(
            "Guardian Broker lifetime gives exact process failure priority",
            TestProcessPriorityAsync,
            assert);
        await RunCaseAsync(
            "Guardian Broker lifetime treats an isolated pipe failure as terminal",
            TestPipeFailureAsync,
            assert);
        RunCase(
            "Guardian Broker production lifetime has one four-authority constructor",
            TestProductionLifetimeSurface,
            assert);
    }

    private static void TestExactArguments()
    {
        var canonical = new[]
        {
            GuardianBrokerManagedBootstrapV1.ManagedBootstrapArgument,
            GuardianBrokerManagedBootstrapV1.BootstrapHandleArgument,
            "424242"
        };
        Ensure(
            GuardianBrokerManagedBootstrapV1.ContainsBootstrapPrefix(canonical) &&
            GuardianBrokerManagedBootstrapV1.TryParseArguments(canonical, out var handle) &&
            handle == 424242,
            "the canonical bootstrap command line was rejected");
        Ensure(
            !GuardianBrokerManagedBootstrapV1.ContainsBootstrapPrefix(
                new[] { "--safe-preview" }),
            "an ordinary WPF command line entered the bootstrap branch");

        var malformed = new[]
        {
            new[] { "--guardian-broker-bootstrap-v1" },
            new[] { "--guardian-broker-bootstrap-v1", "--bootstrap-handle", "0" },
            new[] { "--guardian-broker-bootstrap-v1", "--bootstrap-handle", "0424242" },
            new[] { "--guardian-broker-bootstrap-v1", "--bootstrap-handle", "+424242" },
            new[] { "--guardian-broker-bootstrap-v1", "--bootstrap-handle", "424242", "extra" },
            new[] { "--GUARDIAN-BROKER-BOOTSTRAP-V1", "--bootstrap-handle", "424242" },
            new[] { "--guardian-broker-bootstrap-v1x", "--bootstrap-handle", "424242" },
            new[] { "--guardian-broker-bootstrap-v1", "--bootstrap-handle", "18446744073709551616" }
        };
        Ensure(
            malformed.All(arguments =>
                GuardianBrokerManagedBootstrapV1.ContainsBootstrapPrefix(arguments) &&
                !GuardianBrokerManagedBootstrapV1.TryParseArguments(arguments, out _)),
            "a malformed same-prefix command line could enter WPF");
    }

    private static void TestExactBootstrapRead()
    {
        using var expected = new GuardianBrokerBootstrapV1(
            GuardianBrokerBootstrapProtocolV1.EndpointPrefix + new string('a', 32),
            new string('A', 64),
            Convert.FromHexString(new string('b', 64)),
            424242);
        var frame = GuardianBrokerBootstrapProtocolV1.SerializeFrame(expected);
        using var chunked = new ChunkedReadStream(frame, maximumChunk: 3);
        using var parsed = GuardianBrokerManagedBootstrapV1.ReadBootstrapFrame(chunked);
        Ensure(
            string.Equals(parsed.EndpointName, expected.EndpointName, StringComparison.Ordinal) &&
            string.Equals(parsed.ConnectionNonce, expected.ConnectionNonce, StringComparison.Ordinal) &&
            parsed.ManagedEntryChallenge.Span.SequenceEqual(
                expected.ManagedEntryChallenge.Span) &&
            parsed.BrokerProcessHandle == expected.BrokerProcessHandle,
            "a partial-read canonical bootstrap frame did not round-trip");

        ExpectCode(
            "guardian-broker-bootstrap-trailing-data",
            () => GuardianBrokerManagedBootstrapV1.ReadBootstrapFrame(
                new MemoryStream([.. frame, 0x01], writable: false)));
        ExpectCode(
            "guardian-broker-bootstrap-truncated",
            () => GuardianBrokerManagedBootstrapV1.ReadBootstrapFrame(
                new MemoryStream(frame[..^1], writable: false)));
        var oversized = new byte[GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(
            oversized,
            checked((uint)GuardianBrokerBootstrapProtocolV1.MaximumPayloadBytes + 1));
        ExpectCode(
            "guardian-broker-bootstrap-size",
            () => GuardianBrokerManagedBootstrapV1.ReadBootstrapFrame(
                new MemoryStream(oversized, writable: false)));
    }

    private static void TestReadyBinding()
    {
        var ready = new GuardianBrokerAdmissionReadyV1(
            new string('A', 64),
            new string('B', 64),
            101,
            202,
            "release-v1",
            new string('C', 64));
        GuardianBrokerManagedBootstrapV1.ValidateReady(
            ready,
            ready.ConnectionNonce,
            ready.ChallengeSha256,
            ready.BrokerProcessId,
            ready.GuardianProcessId,
            ready.ReleaseId,
            ready.ManifestSha256);
        ExpectCode(
            "guardian-broker-ready-mismatch",
            () => GuardianBrokerManagedBootstrapV1.ValidateReady(
                ready with { GuardianProcessId = 203 },
                ready.ConnectionNonce,
                ready.ChallengeSha256,
                ready.BrokerProcessId,
                ready.GuardianProcessId,
                ready.ReleaseId,
                ready.ManifestSha256));
    }

    private static async Task TestApplicationStartupOwnerAsync()
    {
        using (var revokedBeforeStart = new GuardianApplicationStartupOwnerV1())
        {
            revokedBeforeStart.Revoke();
            await revokedBeforeStart.Settlement.WaitAsync(TimeSpan.FromSeconds(2));
            Ensure(
                !revokedBeforeStart.TryBegin(out _),
                "a startup revoked before begin still issued a lease");
        }

        using (var owner = new GuardianApplicationStartupOwnerV1())
        {
            Ensure(owner.TryBegin(out var startup), "the startup owner did not issue its first lease");
            startup.Gate();
            owner.Revoke();
            var gateRejected = false;
            var rejectedPublicationCount = 0;
            var rejectedAtomicPublicationCount = 0;
            try
            {
                startup.Gate();
            }
            catch (OperationCanceledException exception)
                when (exception.CancellationToken == startup.CancellationToken)
            {
                gateRejected = true;
            }

            try
            {
                startup.RunTrackedPublication(() =>
                    Interlocked.Increment(ref rejectedPublicationCount));
            }
            catch (OperationCanceledException exception)
                when (exception.CancellationToken == startup.CancellationToken)
            {
            }

            try
            {
                startup.PublishAtomic(() =>
                    Interlocked.Increment(ref rejectedAtomicPublicationCount));
            }
            catch (OperationCanceledException exception)
                when (exception.CancellationToken == startup.CancellationToken)
            {
            }

            Ensure(
                startup.CancellationToken.IsCancellationRequested &&
                gateRejected &&
                rejectedPublicationCount == 0 &&
                rejectedAtomicPublicationCount == 0 &&
                !owner.Settlement.IsCompleted,
                "revocation did not reject a later publication or wait for startup completion");
            startup.Complete();
            startup.Complete();
            await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2));
            Ensure(
                !owner.TryBegin(out _),
                "a settled startup owner reopened a second generation");
        }

        using (var owner = new GuardianApplicationStartupOwnerV1())
        {
            Ensure(owner.TryBegin(out var startup), "the publication fixture has no startup lease");
            var publicationEntered = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var releasePublication = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var publication = Task.Run(() => startup.RunTrackedPublication(() =>
            {
                publicationEntered.TrySetResult();
                releasePublication.Task.GetAwaiter().GetResult();
            }));
            await publicationEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await Task.Run(owner.Revoke).WaitAsync(TimeSpan.FromSeconds(2));
            var rejectedAtomicPublicationCount = 0;
            try
            {
                startup.PublishAtomic(() =>
                    Interlocked.Increment(ref rejectedAtomicPublicationCount));
            }
            catch (OperationCanceledException exception)
                when (exception.CancellationToken == startup.CancellationToken)
            {
            }

            startup.Complete();
            Ensure(
                startup.CancellationToken.IsCancellationRequested &&
                rejectedAtomicPublicationCount == 0 &&
                !owner.Settlement.IsCompleted,
                "settlement completed while an admitted publication was still active");
            releasePublication.TrySetResult();
            await publication.WaitAsync(TimeSpan.FromSeconds(2));
            await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2));
        }

        using (var owner = new GuardianApplicationStartupOwnerV1())
        {
            Ensure(owner.TryBegin(out var startup), "the fault fixture has no startup lease");
            var publicationFailure = new IOException("startup publication failure");
            Exception? observed = null;
            try
            {
                startup.RunTrackedPublication(() => throw publicationFailure);
            }
            catch (Exception exception)
            {
                observed = exception;
            }

            startup.Complete();
            await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2));
            Ensure(
                ReferenceEquals(observed, publicationFailure),
                "a faulted publication did not drain or preserve its exact failure");
        }

        using (var owner = new GuardianApplicationStartupOwnerV1())
        {
            Ensure(owner.TryBegin(out var startup), "the reentrant fixture has no startup lease");
            startup.RunTrackedPublication(owner.Revoke);
            var laterPublicationCount = 0;
            try
            {
                startup.RunTrackedPublication(() =>
                    Interlocked.Increment(ref laterPublicationCount));
            }
            catch (OperationCanceledException exception)
                when (exception.CancellationToken == startup.CancellationToken)
            {
            }

            startup.Complete();
            await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2));
            Ensure(
                startup.CancellationToken.IsCancellationRequested && laterPublicationCount == 0,
                "reentrant revocation deadlocked or reopened publication authority");
        }

        using (var owner = new GuardianApplicationStartupOwnerV1())
        {
            Ensure(owner.TryBegin(out var startup), "the atomic fixture has no startup lease");
            var atomicPublicationCount = 0;
            startup.PublishAtomic(() => Interlocked.Increment(ref atomicPublicationCount));
            owner.Revoke();
            startup.Complete();
            await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2));
            Ensure(
                atomicPublicationCount == 1 && startup.CancellationToken.IsCancellationRequested,
                "an atomic startup publication was rolled back after its linearization point");
        }
    }

    private static void TestApplicationStartupSourceBoundary()
    {
        var appXaml = File.ReadAllText(FindWorkspaceSource("CodexGuardian", "App.xaml"))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        var app = File.ReadAllText(FindWorkspaceSource("CodexGuardian", "App.xaml.cs"))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        var viewModel = File.ReadAllText(FindWorkspaceSource(
                "CodexGuardian",
                "ViewModels",
                "MainViewModel.cs"))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        var mainWindow = File.ReadAllText(FindWorkspaceSource(
                "CodexGuardian",
                "MainWindow.xaml.cs"))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        var attachmentRuntimeSource = File.ReadAllText(FindWorkspaceSource(
                "CodexGuardian",
                "Services",
                "FollowUpAttachmentRuntime.cs"))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        var callback = app.IndexOf(
            "private void RequestBrokerFailClosedShutdown(Exception failure)",
            StringComparison.Ordinal);
        var callbackRevoke = callback < 0
            ? -1
            : app.IndexOf("RecordExitRequest(1);", callback, StringComparison.Ordinal);
        var dispatcherCheck = callback < 0
            ? -1
            : app.IndexOf("Dispatcher.HasShutdownStarted", callback, StringComparison.Ordinal);
        var exitCore = app.IndexOf(
            "private async Task FinishExitCoreAsync(TaskCompletionSource exitOwner)",
            StringComparison.Ordinal);
        var startupSettlement = exitCore < 0
            ? -1
            : app.IndexOf(
                "await _startupOwner.Settlement;",
                exitCore,
                StringComparison.Ordinal);
        var firstCleanup = exitCore < 0
            ? -1
            : app.IndexOf("if (_mainWindow is not null)", exitCore, StringComparison.Ordinal);
        var brokerCleanup = exitCore < 0
            ? -1
            : app.IndexOf(
                "await brokerBootstrapLifetime.DisposeAsync();",
                exitCore,
                StringComparison.Ordinal);
        var shutdown = exitCore < 0
            ? -1
            : app.IndexOf("Shutdown(finalExitCode);", exitCore, StringComparison.Ordinal);
        var startupCore = Slice(
            app,
            "private async Task<StartupOutcome> StartupCoreAsync(",
            "private void ShowStartupNoticeIfAllowed(");
        var initializeCore = Slice(
            viewModel,
            "private async Task InitializeCoreAsync(",
            "internal void LoadFollowUpPreviewFixture(");
        var windowConstructor = Slice(
            mainWindow,
            "public MainWindow(MainViewModel viewModel, bool enableTray = true)",
            "internal void ActivateForStartup(bool showWindow)");
        var windowActivation = Slice(
            mainWindow,
            "internal void ActivateForStartup(bool showWindow)",
            "internal void DeactivateForExit()");
        var windowDeactivation = Slice(
            mainWindow,
            "internal void DeactivateForExit()",
            "private Forms.ContextMenuStrip BuildTrayMenu()");
        var windowClosing = Slice(
            mainWindow,
            "private async void Window_Closing(object? sender, CancelEventArgs eventArgs)",
            "private async Task RequestExitAsync()");
        var windowExitRequest = Slice(
            mainWindow,
            "private async Task RequestExitAsync()",
            "private void CleanupTrayResources(ref Exception? failure)");
        var livePublicationBlock = Slice(
            startupCore,
            "if (launchOptions.AllowsLiveIntegration)\n        {\n" +
            "            startup.RunTrackedPublication(() => _deepObservation!.Start());",
            "\n        var classifier = new RecoveryClassifier();");
        var recoveryJournalLiveBlock = Slice(
            startupCore,
            "if (launchOptions.AllowsLiveIntegration)\n        {\n" +
            "            startup.Gate();\n" +
            "            var journalSnapshot = await recoveryJournal.ReadAsync(",
            "\n        ConversationMutationService? conversationMutations = null;");
        var conversationMutationJournalLiveBlock = Slice(
            startupCore,
            "if (launchOptions.AllowsLiveIntegration)\n        {\n" +
            "            var conversationMutationJournal = new ConversationMutationOperationJournal(",
            "\n        FollowUpOperationJournal? followUpJournal = null;");
        var followUpJournalLiveBlock = Slice(
            startupCore,
            "if (launchOptions.AllowsLiveIntegration)\n        {\n" +
            "            followUpJournal = new FollowUpOperationJournal(",
            "\n        var structuredCapabilities = launchOptions.AllowsLiveIntegration");
        var structuredCompositionBlock = Slice(
            startupCore,
            "var structuredCapabilities = launchOptions.AllowsLiveIntegration",
            "\n        if (launchOptions.AllowsLiveIntegration)\n        {\n" +
            "            startup.RunTrackedPublication(() => _deepObservation!.Start());");
        var engineComposition = Slice(
            startupCore,
            "var engine = new GuardianEngine(",
            "\n        startup.Gate();\n        var workflowRuleStore = new WorkflowRuleStore(");
        var viewModelComposition = Slice(
            startupCore,
            "var viewModel = new MainViewModel(",
            "\n        _viewModel = viewModel;");
        var windowPublicationBlock = Slice(
            startupCore,
            "startup.RunTrackedPublication(() =>\n        {\n            MainWindow = window;",
            "\n        startup.PublishAtomic(viewModel.MarkApplicationStartupPublished);");
        const string expectedWindowPublicationBlock =
            "startup.RunTrackedPublication(() =>\n" +
            "        {\n" +
            "            MainWindow = window;\n" +
            "            window.ActivateForStartup(showWindow: !launchOptions.Background);\n" +
            "        });";
        const string expectedViewModelAttachmentSuffix =
            "launchOptions.SafePreview,\n" +
            "            attachmentRuntime.Composition,\n" +
            "            attachmentRuntime.DraftAuthority,\n" +
            "            conversationMutations: conversationMutations,\n" +
            "            workflowRuleStore: workflowRuleStore,\n" +
            "            workflowRuleSnapshot: workflowRuleSnapshot,\n" +
            "            workflowAutomationHost: workflowAutomationHost,\n" +
            "            workflowLineageReader: workflowJournal is null\n" +
            "                ? null\n" +
            "                : new WorkflowJournalLineageReader(workflowJournal));";
        const string expectedWindowCreation =
            "var window = new MainWindow(\n" +
            "            viewModel,\n" +
            "            enableTray: !launchOptions.SafePreview,\n" +
            "            attachmentRuntime,\n" +
            "            launchOptions.SafePreview,\n" +
            "            log);";
        var recoveryJournalRead = startupCore.IndexOf(
            "recoveryJournal.ReadAsync(startup.CancellationToken)",
            StringComparison.Ordinal);
        var conversationMutationJournalRead = startupCore.IndexOf(
            "conversationMutationJournal.ReadAsync(\n                startup.CancellationToken)",
            StringComparison.Ordinal);
        var followUpJournalRead = startupCore.IndexOf(
            "followUpJournal.ReadAsync(\n                startup.CancellationToken)",
            StringComparison.Ordinal);
        var engineCreation = startupCore.IndexOf(
            "var engine = new GuardianEngine(",
            StringComparison.Ordinal);
        var workflowRuleStoreCreation = startupCore.IndexOf(
            "var workflowRuleStore = new WorkflowRuleStore(settingsService.DataDirectory);",
            StringComparison.Ordinal);
        var workflowRulePreviewBlock = Slice(
            startupCore,
            "var workflowRuleStore = new WorkflowRuleStore(settingsService.DataDirectory);",
            "\n        WorkflowOperationJournal? workflowJournal = null;");
        var workflowHostComposition = Slice(
            startupCore,
            "WorkflowOperationJournal? workflowJournal = null;",
            "\n        var viewModel = new MainViewModel(");
        var workflowRuleRead = workflowRulePreviewBlock.IndexOf(
            "workflowRuleStore.ReadAsync(startup.CancellationToken)",
            StringComparison.Ordinal);
        var workflowRuleSave = workflowRulePreviewBlock.IndexOf(
            "workflowRuleStore.SaveAsync(",
            StringComparison.Ordinal);
        var observationStart = startupCore.IndexOf(
            "startup.RunTrackedPublication(() => _deepObservation!.Start());",
            StringComparison.Ordinal);
        var hookStart = startupCore.IndexOf(
            "startup.RunTrackedPublication(() => _interactionHook!.Start());",
            StringComparison.Ordinal);
        var structuredProviderCreation = startupCore.IndexOf(
            "new InstalledCodexStructuredInputCapabilityProvider(settings.AttachmentLimits)",
            StringComparison.Ordinal);
        var attachmentRuntimeCreation = startupCore.IndexOf(
            "var attachmentRuntime = new FollowUpAttachmentRuntime(",
            StringComparison.Ordinal);
        var followUpServiceCreation = startupCore.IndexOf(
            "followUps = new FollowUpDispatchService(",
            StringComparison.Ordinal);
        var draftPublication = startupCore.IndexOf(
            "attachmentRuntime.DraftAuthority.ReplaceVisibleDrafts(",
            StringComparison.Ordinal);
        var presentationReconciliation = startupCore.IndexOf(
            "attachmentRuntime.Reconciliation.ReconcileAsync(",
            StringComparison.Ordinal);
        var recoveryReplayCreation = startupCore.IndexOf(
            "IRecoveryStructuredInputReplayAuthority? recoveryStructuredInputReplay =",
            StringComparison.Ordinal);
        var recoveryServiceCreation = startupCore.IndexOf(
            "ProductionRecoveryServiceFactory.CreateLive(",
            StringComparison.Ordinal);
        var previewLoad = startupCore.IndexOf(
            "viewModel.LoadFollowUpPreviewFixture(previewFixture);",
            StringComparison.Ordinal);
        var viewModelInitialize = startupCore.IndexOf(
            "await viewModel.InitializeForApplicationStartupAsync(",
            StringComparison.Ordinal);
        var windowCreate = startupCore.IndexOf(
            expectedWindowCreation,
            StringComparison.Ordinal);
        var mainWindowPublication = windowCreate < 0
            ? -1
            : startupCore.IndexOf(
                "MainWindow = window;",
                windowCreate,
                StringComparison.Ordinal);
        var windowActivate = mainWindowPublication < 0
            ? -1
            : startupCore.IndexOf(
                "window.ActivateForStartup(showWindow: !launchOptions.Background);",
                mainWindowPublication,
                StringComparison.Ordinal);
        var startupPublished = windowActivate < 0
            ? -1
            : startupCore.IndexOf(
                "startup.PublishAtomic(viewModel.MarkApplicationStartupPublished);",
                windowActivate,
                StringComparison.Ordinal);
        var gateAfterPublication = startupPublished < 0
            ? -2
            : startupCore.IndexOf("startup.Gate();", startupPublished, StringComparison.Ordinal);
        var engineStart = initializeCore.IndexOf("_engine.Start();", StringComparison.Ordinal);
        var engineStop = initializeCore.IndexOf("await _engine.StopAsync();", StringComparison.Ordinal);
        var startupComplete = app.IndexOf(
            "startup.Complete();",
            StringComparison.Ordinal);
        var startupNotice = app.IndexOf(
            "ShowStartupNoticeIfAllowed(outcome.Notice);",
            StringComparison.Ordinal);
        var trackedPublicationMethod = typeof(GuardianApplicationStartupOwnerV1.StartupLease).GetMethod(
            "RunTrackedPublication",
            BindingFlags.Instance | BindingFlags.NonPublic);
        var atomicPublicationMethod = typeof(GuardianApplicationStartupOwnerV1.StartupLease).GetMethod(
            "PublishAtomic",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Ensure(
            callback >= 0 && callbackRevoke > callback && callbackRevoke < dispatcherCheck &&
            exitCore >= 0 && startupSettlement > exitCore && startupSettlement < firstCleanup &&
            brokerCleanup > firstCleanup && shutdown > brokerCleanup &&
            startupComplete >= 0 && startupNotice > startupComplete &&
            appXaml.Contains("ShutdownMode=\"OnExplicitShutdown\"", StringComparison.Ordinal) &&
            startupCore.Contains(
                "settingsService.LoadAsync(startup.CancellationToken)",
                StringComparison.Ordinal) &&
            recoveryJournalRead >= 0 &&
            conversationMutationJournalRead > recoveryJournalRead &&
            followUpJournalRead > conversationMutationJournalRead &&
            recoveryJournalLiveBlock.StartsWith(
                "if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            recoveryJournalLiveBlock.Contains(
                "await recoveryJournal.ReadAsync(startup.CancellationToken);",
                StringComparison.Ordinal) &&
            recoveryJournalLiveBlock.Split(
                "startup.Gate();",
                StringSplitOptions.None).Length - 1 == 2 &&
            recoveryJournalLiveBlock.Contains(
                "RecoveryJournalReadStatus.RecoveredFromBackup",
                StringComparison.Ordinal) &&
            conversationMutationJournalLiveBlock.StartsWith(
                "if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            conversationMutationJournalLiveBlock.Contains(
                "await conversationMutationJournal.ReadAsync(\n                startup.CancellationToken);",
                StringComparison.Ordinal) &&
            conversationMutationJournalLiveBlock.Split(
                "startup.Gate();",
                StringSplitOptions.None).Length - 1 == 2 &&
            conversationMutationJournalLiveBlock.Contains(
                "ConversationMutationJournalReadStatus.RecoveredFromBackup",
                StringComparison.Ordinal) &&
            conversationMutationJournalLiveBlock.Contains(
                "conversationMutations = new ConversationMutationService(",
                StringComparison.Ordinal) &&
            followUpJournalLiveBlock.StartsWith(
                "if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            followUpJournalLiveBlock.Contains(
                "await followUpJournal.ReadAsync(\n                startup.CancellationToken);",
                StringComparison.Ordinal) &&
            followUpJournalLiveBlock.Split(
                "startup.Gate();",
                StringSplitOptions.None).Length - 1 == 2 &&
            followUpJournalLiveBlock.Contains(
                "FollowUpJournalReadStatus.RecoveredFromBackup",
                StringComparison.Ordinal) &&
            startupCore.Split(
                "recoveryJournal.ReadAsync(",
                StringSplitOptions.None).Length - 1 == 1 &&
            startupCore.Split(
                "conversationMutationJournal.ReadAsync(",
                StringSplitOptions.None).Length - 1 == 1 &&
            startupCore.Split(
                "followUpJournal.ReadAsync(",
                StringSplitOptions.None).Length - 1 == 1 &&
            structuredProviderCreation > followUpJournalRead &&
            attachmentRuntimeCreation > structuredProviderCreation &&
            draftPublication > attachmentRuntimeCreation &&
            presentationReconciliation > draftPublication &&
            recoveryReplayCreation > presentationReconciliation &&
            recoveryServiceCreation > recoveryReplayCreation &&
            followUpServiceCreation > recoveryServiceCreation &&
            observationStart > followUpServiceCreation && hookStart > observationStart &&
            startupCore.Split(
                "new InstalledCodexStructuredInputCapabilityProvider(",
                StringSplitOptions.None).Length - 1 == 1 &&
            structuredCompositionBlock.Contains(
                "var structuredCapabilities = launchOptions.AllowsLiveIntegration\n" +
                "            ? new InstalledCodexStructuredInputCapabilityProvider(settings.AttachmentLimits)\n" +
                "            : null;",
                StringComparison.Ordinal) &&
            structuredCompositionBlock.Contains(
                "structuredCapabilities: structuredDispatchReady\n" +
                "                    ? attachmentRuntime.StructuredCapabilities\n" +
                "                    : null,\n" +
                "                attachmentStore: structuredDispatchReady ? attachmentRuntime.Store : null,\n" +
                "                presentationLeases: structuredDispatchReady ? attachmentRuntime.Presentation : null,\n" +
                "                attachmentPins: structuredDispatchReady ? attachmentRuntime.DraftAuthority : null",
                StringComparison.Ordinal) &&
            structuredCompositionBlock.Contains(
                "var structuredDispatchReady = false;\n" +
                "        if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            structuredCompositionBlock.Contains(
                "var reconciliation = attachmentRuntime.Reconciliation is null\n" +
                "                ? null\n" +
                "                : await attachmentRuntime.Reconciliation.ReconcileAsync(",
                StringComparison.Ordinal) &&
            structuredCompositionBlock.Contains(
                "IRecoveryStructuredInputReplayAuthority? recoveryStructuredInputReplay =\n" +
                "            launchOptions.AllowsLiveIntegration && structuredDispatchReady\n" +
                "                ? new RecoveryStructuredInputReplayAuthority(\n" +
                "                    followUpJournal!,\n" +
                "                    attachmentRuntime.Presentation)\n" +
                "                : null;",
                StringComparison.Ordinal) &&
            structuredCompositionBlock.Contains(
                "recoveryStructuredInputReplay,",
                StringComparison.Ordinal) &&
            attachmentRuntimeSource.Contains(
                "Reconciliation = followUpJournal is not null && recoveryJournal is not null\n" +
                "            ? new AttachmentPresentationReconciliationService(",
                StringComparison.Ordinal) &&
            livePublicationBlock.StartsWith(
                "if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            livePublicationBlock.Split(
                "startup.RunTrackedPublication(",
                StringSplitOptions.None).Length - 1 == 2 &&
            livePublicationBlock.Contains(
                "startup.RunTrackedPublication(() => _deepObservation!.Start());\n" +
                "            startup.RunTrackedPublication(() => _interactionHook!.Start());",
                StringComparison.Ordinal) &&
            engineComposition.TrimEnd().EndsWith(
                "launchOptions.SafePreview);",
                StringComparison.Ordinal) &&
            engineCreation >= 0 && workflowRuleStoreCreation > engineCreation &&
            startupCore.Contains(
                "launchOptions.SafePreview);\n" +
                "        startup.Gate();\n" +
                "        var workflowRuleStore = new WorkflowRuleStore(settingsService.DataDirectory);",
                StringComparison.Ordinal) &&
            workflowRulePreviewBlock.Contains(
                "if (previewFixture is not null)",
                StringComparison.Ordinal) &&
            workflowRuleRead >= 0 && workflowRuleSave > workflowRuleRead &&
            workflowRulePreviewBlock.Split(
                "startup.Gate();",
                StringSplitOptions.None).Length - 1 == 2 &&
            workflowRulePreviewBlock.Contains(
                "previewFixture.WorkflowRules,\n" +
                "                        startup.CancellationToken",
                StringComparison.Ordinal) &&
            workflowHostComposition.StartsWith(
                "WorkflowOperationJournal? workflowJournal = null;\n" +
                "        WorkflowAutomationHost? workflowAutomationHost = null;\n" +
                "        if (launchOptions.AllowsLiveIntegration)",
                StringComparison.Ordinal) &&
            workflowHostComposition.Contains(
                "workflowJournal = new WorkflowOperationJournal(settingsService.DataDirectory);",
                StringComparison.Ordinal) &&
            workflowHostComposition.Contains(
                "var workflowRuntime = new WorkflowAutomationRuntime(",
                StringComparison.Ordinal) &&
            workflowHostComposition.Contains(
                "var workflowRunner = new WorkflowRuleActionRunner(",
                StringComparison.Ordinal) &&
            workflowHostComposition.Contains(
                "new WorkflowDispatchPolicyAuthority(settingsService)",
                StringComparison.Ordinal) &&
            workflowHostComposition.Contains(
                "new GuardianWorkflowAutomationAuthorityChangeSource(engine, desktopIpc)",
                StringComparison.Ordinal) &&
            viewModelComposition.TrimEnd().EndsWith(
                expectedViewModelAttachmentSuffix,
                StringComparison.Ordinal) &&
            startupCore.Contains(
                "var attachmentRuntime = new FollowUpAttachmentRuntime(\n" +
                "            settingsService.DataDirectory,\n" +
                "            settingsService,\n" +
                "            launchOptions.AllowsLiveIntegration ? followUpJournal : null,\n" +
                "            launchOptions.AllowsLiveIntegration ? recoveryJournal : null,\n" +
                "            structuredCapabilities);",
                StringComparison.Ordinal) &&
            startupCore.Contains(
                "attachmentRuntime.DraftAuthority.ReplaceVisibleDrafts(",
                StringComparison.Ordinal) &&
            previewLoad > hookStart && viewModelInitialize > previewLoad &&
            windowCreate > viewModelInitialize && mainWindowPublication > windowCreate &&
            windowActivate > mainWindowPublication && startupPublished > windowActivate &&
            string.Equals(
                windowPublicationBlock,
                expectedWindowPublicationBlock,
                StringComparison.Ordinal) &&
            startupCore.Contains(
                expectedWindowPublicationBlock +
                "\n        startup.PublishAtomic(viewModel.MarkApplicationStartupPublished);",
                StringComparison.Ordinal) &&
            gateAfterPublication == -1 &&
            !startupCore.Contains("MessageBox.Show", StringComparison.Ordinal) &&
            !startupCore.Contains("Shutdown(", StringComparison.Ordinal) &&
            viewModel.Contains(
                "public async Task InitializeAsync(CancellationToken cancellationToken = default)",
                StringComparison.Ordinal) &&
            initializeCore.Contains(
                "await SaveSettingsForApplicationStartupAsync(",
                StringComparison.Ordinal) &&
            initializeCore.Contains(
                "startup.RunTrackedPublication(PublishEngine);",
                StringComparison.Ordinal) &&
            engineStart >= 0 && engineStop > engineStart &&
            !windowConstructor.Contains("CreateTrayIcon", StringComparison.Ordinal) &&
            !windowConstructor.Contains("NotifyIcon", StringComparison.Ordinal) &&
            !windowConstructor.Contains("Show(", StringComparison.Ordinal) &&
            windowActivation.Contains("CreateTrayIcon();", StringComparison.Ordinal) &&
            windowActivation.Contains("_notifyIcon.Visible = true;", StringComparison.Ordinal) &&
            windowActivation.Contains("Show();", StringComparison.Ordinal) &&
            windowDeactivation.Contains("CleanupTrayResources(ref failure);", StringComparison.Ordinal) &&
            windowDeactivation.Contains("TryCleanup(Close, ref failure);", StringComparison.Ordinal) &&
            windowClosing.Contains("if (_allowClose)", StringComparison.Ordinal) &&
            windowClosing.Contains("eventArgs.Cancel = true;", StringComparison.Ordinal) &&
            windowClosing.Contains("ExitRequested == true", StringComparison.Ordinal) &&
            !windowExitRequest.Contains("DeactivateForExit", StringComparison.Ordinal) &&
            app.Contains(
                "notice is null || _brokerBootstrapLifetime is not null || ExitRequested",
                StringComparison.Ordinal) &&
            !app.Contains("ForTests", StringComparison.Ordinal) &&
            !typeof(GuardianApplicationStartupOwnerV1).IsPublic &&
            typeof(GuardianApplicationStartupOwnerV1.StartupLease).IsNestedAssembly &&
            trackedPublicationMethod?.IsAssembly == true &&
            atomicPublicationMethod?.IsAssembly == true,
            "Guardian startup can outlive Broker authority or bypass fail-closed cleanup");
    }

    private static async Task TestStartupSettingsAuthorityAsync()
    {
        var uncRejected = false;
        try
        {
            _ = new SettingsService(@"\\server\share\codex-guardian");
        }
        catch (ArgumentException)
        {
            uncRejected = true;
        }

        Ensure(uncRejected, "settings accepted a non-local data directory");
        await WithIsolatedStartupSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            var missing = await service.LoadAsync().ConfigureAwait(false);
            Ensure(
                !Directory.Exists(root) && missing.MonitorOnly,
                "settings load created a missing data directory");

            Directory.CreateDirectory(root);
            var invalidBytes = "{invalid-settings"u8.ToArray();
            await File.WriteAllBytesAsync(service.SettingsPath, invalidBytes).ConfigureAwait(false);
            var invalidHash = SHA256.HashData(invalidBytes);
            _ = await service.LoadAsync().ConfigureAwait(false);
            Ensure(
                File.ReadAllBytes(service.SettingsPath).SequenceEqual(invalidBytes) &&
                SHA256.HashData(File.ReadAllBytes(service.SettingsPath)).SequenceEqual(invalidHash) &&
                !Directory.EnumerateFiles(root, "*.invalid-*", SearchOption.TopDirectoryOnly).Any() &&
                !Directory.EnumerateFiles(root, ".settings.json.*.tmp", SearchOption.TopDirectoryOnly).Any(),
                "read-only settings load moved or rewrote an invalid primary");

            File.Delete(service.SettingsPath);
            var oldSettings = new AppSettings
            {
                MonitorOnly = true,
                MonitoringEnabled = false,
                RecentThreadLimit = 17
            };
            await service.SaveAsync(oldSettings).ConfigureAwait(false);
            var oldPrimary = File.ReadAllBytes(service.SettingsPath);

            using (var owner = new GuardianApplicationStartupOwnerV1())
            {
                Ensure(owner.TryBegin(out var startup), "the settings revoke fixture has no startup lease");
                var inner = (ISettingsWriteAuthority)startup;
                var commitReady = new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                var releaseCommit = new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                var publicationCount = 0;
                var authority = new DelegatingSettingsWriteAuthority(publication =>
                {
                    if (Interlocked.Increment(ref publicationCount) == 1)
                    {
                        commitReady.TrySetResult();
                        releaseCommit.Task.GetAwaiter().GetResult();
                    }

                    inner.Publish(publication);
                });
                var replacement = new AppSettings
                {
                    MonitorOnly = true,
                    MonitoringEnabled = false,
                    RecentThreadLimit = 29
                };
                var save = Task.Run(() => service.SaveAsync(
                    replacement,
                    startup.CancellationToken,
                    authority));
                await commitReady.Task.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                owner.Revoke();
                releaseCommit.TrySetResult();
                _ = await ExpectCancellationAsync(save, startup.CancellationToken)
                    .ConfigureAwait(false);
                startup.Complete();
                await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                Ensure(
                    publicationCount == 1 &&
                    File.ReadAllBytes(service.SettingsPath).SequenceEqual(oldPrimary) &&
                    !Directory.EnumerateFiles(root, ".settings.json.*.tmp", SearchOption.TopDirectoryOnly).Any(),
                    "revoke-before-commit changed the primary or retained a settings temp file");
            }

            using (var owner = new GuardianApplicationStartupOwnerV1())
            {
                Ensure(owner.TryBegin(out var startup), "the settings publication fixture has no startup lease");
                var inner = (ISettingsWriteAuthority)startup;
                var publicationCount = 0;
                var authority = new DelegatingSettingsWriteAuthority(publication =>
                {
                    var ordinal = Interlocked.Increment(ref publicationCount);
                    inner.Publish(publication);
                    if (ordinal == 1)
                    {
                        owner.Revoke();
                    }
                });
                var replacement = new AppSettings
                {
                    MonitorOnly = true,
                    MonitoringEnabled = false,
                    RecentThreadLimit = 37
                };
                await Task.Run(() => service.SaveAsync(
                        replacement,
                        startup.CancellationToken,
                        authority))
                    .ConfigureAwait(false);
                startup.Complete();
                await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                var loaded = await service.LoadAsync().ConfigureAwait(false);
                Ensure(
                    publicationCount == 1 &&
                    startup.CancellationToken.IsCancellationRequested &&
                    loaded.RecentThreadLimit == 37 &&
                    !Directory.EnumerateFiles(root, ".settings.json.*.tmp", SearchOption.TopDirectoryOnly).Any(),
                    "commit-before-revoke was reported as canceled or left an incomplete generation");
            }

            var retainedGeneration = File.ReadAllBytes(service.SettingsPath);
            await using (var retainedHandle = new FileStream(
                             service.SettingsPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read | FileShare.Delete))
            {
                await service.SaveAsync(new AppSettings
                {
                    MonitorOnly = true,
                    MonitoringEnabled = false,
                    RecentThreadLimit = 43
                }).ConfigureAwait(false);
                using var retainedCopy = new MemoryStream();
                await retainedHandle.CopyToAsync(retainedCopy).ConfigureAwait(false);
                var loadedReplacement = await service.LoadAsync().ConfigureAwait(false);
                Ensure(
                    retainedCopy.ToArray().SequenceEqual(retainedGeneration) &&
                    !File.ReadAllBytes(service.SettingsPath).SequenceEqual(retainedGeneration) &&
                    loadedReplacement.RecentThreadLimit == 43,
                    "settings save truncated an open generation instead of replacing the namespace atomically");
            }

            var settingsSource = File.ReadAllText(FindWorkspaceSource(
                    "CodexGuardian",
                    "Services",
                    "SettingsService.cs"))
                .Replace("\r\n", "\n", StringComparison.Ordinal);
            var loadSource = Slice(
                settingsSource,
                "public async Task<AppSettings> LoadAsync(",
                "public Task SaveAsync(");
            var saveSource = Slice(
                settingsSource,
                "public Task SaveAsync(",
                "private AppSettings Normalize(");
            var publicationStart = saveSource.IndexOf(
                "writeAuthority.Publish(() =>",
                StringComparison.Ordinal);
            var publicationEnd = publicationStart < 0
                ? -1
                : saveSource.IndexOf(
                    "            });",
                    publicationStart,
                    StringComparison.Ordinal);
            var publicationSource =
                publicationStart >= 0 && publicationEnd > publicationStart
                    ? saveSource[publicationStart..publicationEnd]
                    : string.Empty;
            var afterPublication = publicationEnd < 0
                ? string.Empty
                : saveSource[publicationEnd..];
            Ensure(
                !loadSource.Contains("Directory.CreateDirectory", StringComparison.Ordinal) &&
                !loadSource.Contains("File.Move", StringComparison.Ordinal) &&
                !loadSource.Contains(".invalid-", StringComparison.Ordinal) &&
                saveSource.Contains("var normalizedSettings = Normalize(settings);", StringComparison.Ordinal) &&
                settingsSource.Contains(
                    "private readonly bool _monitoringEnabledAfterNormalization;",
                    StringComparison.Ordinal) &&
                settingsSource.Contains("private AppSettings Normalize(", StringComparison.Ordinal) &&
                saveSource.Contains("FileMode.CreateNew", StringComparison.Ordinal) &&
                saveSource.Contains("FileOptions.Asynchronous | FileOptions.WriteThrough", StringComparison.Ordinal) &&
                saveSource.Contains("Flush(flushToDisk: true)", StringComparison.Ordinal) &&
                saveSource.Contains("File.Delete(temporaryPath)", StringComparison.Ordinal) &&
                saveSource.Split(
                    "writeAuthority.Publish(",
                    StringSplitOptions.None).Length - 1 == 1 &&
                saveSource.IndexOf("Directory.CreateDirectory", StringComparison.Ordinal) < publicationStart &&
                saveSource.IndexOf("new FileStream(", StringComparison.Ordinal) < publicationStart &&
                publicationSource.Contains("File.Replace(", StringComparison.Ordinal) &&
                publicationSource.Contains("File.Move(preparedTemporaryPath, SettingsPath);", StringComparison.Ordinal) &&
                !afterPublication.Contains(
                    "cancellationToken.ThrowIfCancellationRequested();",
                    StringComparison.Ordinal),
                "settings load or atomic publication source boundary regressed");
        }).ConfigureAwait(false);
    }

    private static async Task TestCanceledStartupViewModelDisposalAsync()
    {
        await WithIsolatedStartupSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            await service.SaveAsync(new AppSettings
            {
                MonitorOnly = true,
                MonitoringEnabled = false,
                RecentThreadLimit = 19
            }).ConfigureAwait(false);
            var baseline = File.ReadAllBytes(service.SettingsPath);
            var settings = new AppSettings
            {
                MonitorOnly = true,
                MonitoringEnabled = false,
                RecentThreadLimit = 31
            };
            using var log = new GuardianLog(root);
            var viewModel = CreatePreviewViewModel(root, settings, service, log);
            using var owner = new GuardianApplicationStartupOwnerV1();
            Ensure(owner.TryBegin(out var startup), "the canceled view model fixture has no startup lease");
            owner.Revoke();
            _ = await ExpectCancellationAsync(
                    viewModel.InitializeForApplicationStartupAsync(
                        startup.CancellationToken,
                        startup),
                    startup.CancellationToken)
                .ConfigureAwait(false);
            settings.RecentThreadLimit = 47;
            await viewModel.DisposeAsync().AsTask().ConfigureAwait(false);
            startup.Complete();
            await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            Ensure(
                File.ReadAllBytes(service.SettingsPath).SequenceEqual(baseline),
                "canceled startup disposal performed an unscoped final settings save");
        }).ConfigureAwait(false);

        await WithIsolatedStartupSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            var settings = new AppSettings
            {
                MonitorOnly = true,
                MonitoringEnabled = false,
                RecentThreadLimit = 23
            };
            using var log = new GuardianLog(root);
            var viewModel = CreatePreviewViewModel(root, settings, service, log);
            using var owner = new GuardianApplicationStartupOwnerV1();
            Ensure(owner.TryBegin(out var startup), "the published view model fixture has no startup lease");
            await viewModel.InitializeForApplicationStartupAsync(
                    startup.CancellationToken,
                    startup)
                .ConfigureAwait(false);
            startup.PublishAtomic(viewModel.MarkApplicationStartupPublished);
            startup.Complete();
            owner.Revoke();
            settings.RecentThreadLimit = 53;
            await viewModel.DisposeAsync().AsTask().ConfigureAwait(false);
            await owner.Settlement.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            Ensure(
                (await service.LoadAsync().ConfigureAwait(false)).RecentThreadLimit == 53,
                "a published startup lost normal final settings persistence");
        }).ConfigureAwait(false);
    }

    private static MainViewModel CreatePreviewViewModel(
        string root,
        AppSettings settings,
        SettingsService settingsService,
        GuardianLog log)
    {
        var appServer = new AppServerClient(new CodexCliLocator(), log);
        var desktop = new DesktopIpcClient(log);
        var classifier = new RecoveryClassifier();
        var recovery = new RecoveryService(
            appServer,
            desktop,
            new DesktopThreadOwnerActivator(desktop, log),
            new RecoveryOperationJournal(root),
            log);
        var engine = new GuardianEngine(
            settings,
            appServer,
            desktop,
            recovery,
            classifier,
            new LocalConversationHistoryReader(Path.Combine(root, "preview-sessions")),
            log,
            null,
            null,
            previewIsolationMode: true);
        return new MainViewModel(
            settings,
            settingsService,
            new StartupService(),
            log,
            engine,
            appServer,
            desktop,
            classifier,
            new LocalizationService(),
            null,
            previewIsolationMode: true);
    }

    private static async Task TestProcessPriorityAsync()
    {
        var pipe = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var process = new TaskCompletionSource<GuardianBrokerProcessExitV1>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var observation = GuardianBrokerBootstrapLifetime.ObserveTerminalFailureAsync(
            pipe.Task,
            process.Task,
            CancellationToken.None,
            TimeSpan.FromMilliseconds(100));
        pipe.TrySetException(new IOException("pipe failed"));
        process.TrySetResult(new GuardianBrokerProcessExitV1(101, 0x55));
        var failure = await observation.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(
            failure is GuardianBrokerBootstrapFailureV1 typed &&
            typed.Code == "guardian-broker-process-exited" &&
            typed.ConcurrentFailure is GuardianBrokerBootstrapFailureV1 concurrent &&
            concurrent.Code == "guardian-broker-pipe-failed",
            "a concurrent pipe failure displaced the exact process exit");
    }

    private static async Task TestLateStageResultCleanupAsync()
    {
        var stageStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationObserved = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var process = new TaskCompletionSource<GuardianBrokerProcessExitV1>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var payload = Enumerable.Range(1, 32).Select(value => checked((byte)value)).ToArray();
        var cleanupCount = 0;
        var operation = GuardianBrokerManagedBootstrapV1.AwaitStageOrBrokerAsync(
            async token =>
            {
                using var registration = token.Register(
                    () => cancellationObserved.TrySetResult());
                stageStarted.TrySetResult();
                return await release.Task.ConfigureAwait(false);
            },
            process.Task,
            CancellationToken.None,
            TimeSpan.FromSeconds(1),
            "test-timeout",
            "test timeout",
            lateResultCleanup: result =>
            {
                Interlocked.Increment(ref cleanupCount);
                CryptographicOperations.ZeroMemory(result);
                return Task.FromResult<Exception?>(null);
            },
            drainTimeout: TimeSpan.FromSeconds(1));
        await stageStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        process.TrySetResult(new GuardianBrokerProcessExitV1(101, 0x71));
        await cancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(2));
        release.TrySetResult(payload);
        var failure = await ExpectCodeAsync(
            "guardian-broker-process-exited",
            operation).ConfigureAwait(false);
        Ensure(
            failure.ConcurrentFailure is null &&
            cleanupCount == 1 &&
            payload.All(value => value == 0),
            "a process-winning stage lost or failed to clear its late result");
    }

    private static async Task TestLateStageQuarantineAsync()
    {
        var stageStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var process = new TaskCompletionSource<GuardianBrokerProcessExitV1>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var payload = Enumerable.Repeat((byte)0x5A, 32).ToArray();
        var cleanupCount = 0;
        var operation = GuardianBrokerManagedBootstrapV1.AwaitStageOrBrokerAsync(
            async token =>
            {
                stageStarted.TrySetResult();
                return await release.Task.ConfigureAwait(false);
            },
            process.Task,
            CancellationToken.None,
            TimeSpan.FromSeconds(1),
            "test-timeout",
            "test timeout",
            lateResultCleanup: result =>
            {
                Interlocked.Increment(ref cleanupCount);
                CryptographicOperations.ZeroMemory(result);
                return Task.FromResult<Exception?>(null);
            },
            drainTimeout: TimeSpan.FromMilliseconds(20));
        await stageStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        process.TrySetResult(new GuardianBrokerProcessExitV1(101, 0x72));
        var failure = await ExpectCodeAsync(
            "guardian-broker-process-exited",
            operation).ConfigureAwait(false);
        var quarantine = FindQuarantineTask(failure);
        Ensure(
            quarantine is not null && cleanupCount == 0,
            "a timed-out late stage did not transfer cleanup ownership to quarantine");
        release.TrySetResult(payload);
        var quarantineFailure = await quarantine!.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(
            quarantineFailure is null &&
            cleanupCount == 1 &&
            payload.All(value => value == 0),
            "late quarantine did not clear its eventual successful result exactly once");
    }

    private static async Task TestLateStageFaultAsync()
    {
        var stageStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var process = new TaskCompletionSource<GuardianBrokerProcessExitV1>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var lateFault = new IOException("late stage fault");
        var operation = GuardianBrokerManagedBootstrapV1.AwaitStageOrBrokerAsync(
            async token =>
            {
                stageStarted.TrySetResult();
                return await release.Task.ConfigureAwait(false);
            },
            process.Task,
            CancellationToken.None,
            TimeSpan.FromSeconds(1),
            "test-timeout",
            "test timeout",
            lateResultCleanup: _ => Task.FromResult<Exception?>(null),
            drainTimeout: TimeSpan.FromMilliseconds(20));
        await stageStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        process.TrySetResult(new GuardianBrokerProcessExitV1(101, 0x73));
        var failure = await ExpectCodeAsync(
            "guardian-broker-process-exited",
            operation).ConfigureAwait(false);
        var quarantine = FindQuarantineTask(failure);
        Ensure(quarantine is not null, "a late fault had no quarantine observer");
        release.TrySetException(lateFault);
        Ensure(
            ReferenceEquals(
                await quarantine!.WaitAsync(TimeSpan.FromSeconds(2)),
                lateFault),
            "late quarantine replaced or failed to observe the exact stage fault");
    }

    private static async Task TestTimedOutStageCompletionBoundaryAsync()
    {
        var cleanupCount = 0;
        var cleanupFailure = new IOException("synthetic bootstrap boundary cleanup failure");
        var payload = Enumerable.Repeat((byte)0x5A, 32).ToArray();
        var timeout = new TimeoutException("synthetic bootstrap drain timeout");
        using (var stageCancellation = new CancellationTokenSource())
        {
            var resolved = await ResolveTimedOutStageDrainAsync(
                    Task.FromResult(payload),
                    result =>
                    {
                        Interlocked.Increment(ref cleanupCount);
                        CryptographicOperations.ZeroMemory(result);
                        return Task.FromResult<Exception?>(cleanupFailure);
                    },
                    stageCancellation,
                    timeout)
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(resolved.Failure, timeout) &&
                !resolved.CancellationTransferred &&
                cleanupCount == 1 &&
                payload.All(value => value == 0) &&
                ReferenceEquals(
                    timeout.Data["GuardianBrokerBootstrapCleanupFailure"],
                    cleanupFailure),
                "a completed bootstrap stage lost its result cleanup at the timeout boundary");
        }

        var exactStageFailure = new IOException("synthetic exact bootstrap stage failure");
        var faultTimeout = new TimeoutException("synthetic bootstrap fault timeout");
        using (var stageCancellation = new CancellationTokenSource())
        {
            var resolved = await ResolveTimedOutStageDrainAsync(
                    Task.FromException<byte[]>(exactStageFailure),
                    cleanup: null,
                    stageCancellation,
                    faultTimeout)
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(resolved.Failure, exactStageFailure) &&
                !resolved.CancellationTransferred &&
                ReferenceEquals(
                    exactStageFailure.Data["GuardianBrokerBootstrapConcurrentFailure"],
                    faultTimeout),
                "the bootstrap timeout boundary replaced its exact stage failure");
        }

        var sameTimeout = new TimeoutException("synthetic bootstrap self timeout");
        using (var stageCancellation = new CancellationTokenSource())
        {
            var resolved = await ResolveTimedOutStageDrainAsync(
                    Task.FromException<byte[]>(sameTimeout),
                    cleanup: null,
                    stageCancellation,
                    sameTimeout)
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(resolved.Failure, sameTimeout) &&
                sameTimeout.Data["GuardianBrokerBootstrapConcurrentFailure"] is null,
                "the bootstrap boundary attached a timeout exception to itself");
        }
    }

    private static void TestDisposedStageCancellationToken()
    {
        var method = typeof(GuardianBrokerManagedBootstrapV1).GetMethod(
            "IsExpectedStageCancellation",
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new InvalidOperationException(
                "The Guardian Broker bootstrap cancellation classifier was not found.");
        var cancellation = new CancellationTokenSource();
        var stageToken = cancellation.Token;
        cancellation.Cancel();
        cancellation.Dispose();
        var disposedSourceRejected = false;
        try
        {
            _ = cancellation.Token;
        }
        catch (ObjectDisposedException)
        {
            disposedSourceRejected = true;
        }

        var pureCancellation = new OperationCanceledException(
            "disposed-source-stage-cancellation",
            stageToken);
        Ensure(
            disposedSourceRejected &&
            (bool)(method.Invoke(null, new object?[] { pureCancellation, stageToken }) ?? false),
            "a cached stage token became unusable after CTS ownership transfer");

        var source = File.ReadAllText(FindWorkspaceSource(
                "CodexGuardian",
                "GuardianBrokerManagedBootstrap.cs"))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        Ensure(
            source.Contains(
                "var stageToken = stageCancellation.Token;",
                StringComparison.Ordinal) &&
            source.Contains("stageTask = startStage(stageToken)", StringComparison.Ordinal) &&
            source.Contains(
                "IsExpectedStageCancellation(drain.Failure, stageToken)",
                StringComparison.Ordinal) &&
            source.Split(
                "stageCancellation.Token",
                StringSplitOptions.None).Length - 1 == 1,
            "bootstrap arbitration dereferences a transferred stage cancellation source");
    }

    private static async Task<(Exception? Failure, bool CancellationTransferred)>
        ResolveTimedOutStageDrainAsync(
            Task<byte[]> stageTask,
            Func<byte[], Task<Exception?>>? cleanup,
            CancellationTokenSource stageCancellation,
            TimeoutException timeout)
    {
        var method = typeof(GuardianBrokerManagedBootstrapV1)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .Single(candidate =>
                candidate.Name == "ResolveTimedOutStageDrainAsync" &&
                candidate.IsGenericMethodDefinition)
            .MakeGenericMethod(typeof(byte[]));
        var operation = (Task)(method.Invoke(
            null,
            new object?[] { stageTask, cleanup, stageCancellation, timeout }) ??
            throw new InvalidOperationException("The bootstrap drain resolver returned no task."));
        await operation.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        var result = operation.GetType().GetProperty("Result")?.GetValue(operation) ??
            throw new InvalidOperationException("The bootstrap drain resolver returned no result.");
        var resultType = result.GetType();
        return (
            resultType.GetProperty("Failure")?.GetValue(result) as Exception,
            (bool)(resultType.GetProperty("CancellationTransferred")?.GetValue(result) ?? false));
    }

    private static async Task TestPipeFailureAsync()
    {
        var pipe = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var process = new TaskCompletionSource<GuardianBrokerProcessExitV1>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var observation = GuardianBrokerBootstrapLifetime.ObserveTerminalFailureAsync(
            pipe.Task,
            process.Task,
            CancellationToken.None,
            TimeSpan.FromMilliseconds(20));
        pipe.TrySetException(new IOException("pipe failed"));
        var failure = await observation.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(
            failure is GuardianBrokerBootstrapFailureV1 typed &&
            typed.Code == "guardian-broker-pipe-failed" &&
            typed.ConcurrentFailure is null,
            "an isolated pipe failure was not classified as the terminal cause");
    }

    private static void TestProductionLifetimeSurface()
    {
        var type = typeof(GuardianBrokerBootstrapLifetime);
        var constructors = type.GetConstructors(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        var parameters = constructors.Single().GetParameters();
        Ensure(
            constructors.Length == 1 &&
            parameters.Length == 4 &&
            parameters[0].ParameterType == typeof(VerifiedLocalReleaseLeaseV1) &&
            parameters[1].ParameterType == typeof(AuthenticatedPipePeerConnection) &&
            parameters[2].ParameterType == typeof(Microsoft.Win32.SafeHandles.SafeProcessHandle) &&
            parameters[3].ParameterType == typeof(IGuardianBrokerProcessObserverV1) &&
            type.Assembly.GetType(
                "CodexGuardian.IGuardianBrokerBootstrapLifetimeResourcesV1",
                throwOnError: false) is null,
            "friend-false lifetime retained a test-only authority bypass surface");
    }

    private static void ExpectCode(string expectedCode, Action action)
    {
        try
        {
            action();
        }
        catch (GuardianBrokerBootstrapFailureV1 exception)
        {
            Ensure(exception.Code == expectedCode, "unexpected failure code: " + exception.Code);
            return;
        }

        throw new InvalidOperationException("the expected bootstrap failure was not thrown");
    }

    private static async Task<GuardianBrokerBootstrapFailureV1> ExpectCodeAsync<T>(
        string expectedCode,
        Task<T> action)
    {
        try
        {
            _ = await action.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch (GuardianBrokerBootstrapFailureV1 exception)
        {
            Ensure(exception.Code == expectedCode, "unexpected failure code: " + exception.Code);
            return exception;
        }

        throw new InvalidOperationException("the expected bootstrap failure was not thrown");
    }

    private static async Task<OperationCanceledException> ExpectCancellationAsync(
        Task action,
        CancellationToken expectedToken)
    {
        try
        {
            await action.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            Ensure(
                exception.CancellationToken == expectedToken,
                "an operation returned the wrong cancellation token");
            return exception;
        }

        throw new InvalidOperationException("the expected cancellation was not thrown");
    }

    private static async Task WithIsolatedStartupSettingsRootAsync(
        Func<string, Task> action)
    {
        var configuredTestDataRoot = Environment.GetEnvironmentVariable(
            StartupSettingsTestDataRootEnvironmentVariable);
        Ensure(
            !string.IsNullOrWhiteSpace(configuredTestDataRoot),
            "the startup settings test-data root environment variable is missing");
        var testDataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            configuredTestDataRoot!));
        EnsureExistingLocalDDriveDirectoryWithoutReparse(testDataRoot);
        var root = Path.GetFullPath(Path.Combine(
            testDataRoot,
            "task17-startup-settings-" + Guid.NewGuid().ToString("N")));
        Ensure(
            string.Equals(
                Path.GetDirectoryName(root),
                testDataRoot,
                StringComparison.OrdinalIgnoreCase) &&
            FindExactTestRootEntry(testDataRoot, root) is null,
            "the startup settings test root is not a fresh D-drive path");
        try
        {
            await action(root).ConfigureAwait(false);
        }
        finally
        {
            var entry = FindExactTestRootEntry(testDataRoot, root);
            if (entry is not null)
            {
                var attributes = entry.Attributes;
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    entry.Delete();
                }
                else if ((attributes & FileAttributes.Directory) != 0)
                {
                    EnsureTreeContainsNoReparsePoints(root);
                    Directory.Delete(root, recursive: true);
                }
                else
                {
                    File.Delete(root);
                }
            }

            Ensure(
                FindExactTestRootEntry(testDataRoot, root) is null,
                "the startup settings test root was not removed");
        }
    }

    private static FileSystemInfo? FindExactTestRootEntry(
        string trustedParent,
        string exactPath)
    {
        Ensure(
            string.Equals(
                Path.GetDirectoryName(exactPath),
                trustedParent,
                StringComparison.OrdinalIgnoreCase),
            "the startup settings cleanup target escaped its trusted parent");
        var leaf = Path.GetFileName(exactPath);
        var matches = new DirectoryInfo(trustedParent)
            .EnumerateFileSystemInfos(leaf, SearchOption.TopDirectoryOnly)
            .Where(entry => string.Equals(
                entry.Name,
                leaf,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Ensure(
            matches.Length <= 1,
            "the startup settings cleanup target resolved to multiple exact leaves");
        return matches.SingleOrDefault();
    }

    private static void EnsureExistingLocalDDriveDirectoryWithoutReparse(string root)
    {
        var volumeRoot = Path.GetPathRoot(root);
        Ensure(
            string.Equals(volumeRoot, @"D:\", StringComparison.OrdinalIgnoreCase) &&
            Directory.Exists(root),
            "the startup settings test-data root is not an existing local D-drive directory");
        var current = volumeRoot!;
        foreach (var segment in Path.GetRelativePath(volumeRoot!, root).Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            var attributes = File.GetAttributes(current);
            Ensure(
                (attributes & FileAttributes.Directory) != 0 &&
                (attributes & FileAttributes.ReparsePoint) == 0,
                "the startup settings test-data root traverses a reparse point");
        }
    }

    private static void EnsureTreeContainsNoReparsePoints(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            var currentAttributes = File.GetAttributes(current);
            Ensure(
                (currentAttributes & FileAttributes.Directory) != 0 &&
                (currentAttributes & FileAttributes.ReparsePoint) == 0,
                "the startup settings test root contains a reparse point");
            foreach (var entry in Directory.EnumerateFileSystemEntries(
                         current,
                         "*",
                         SearchOption.TopDirectoryOnly))
            {
                var attributes = File.GetAttributes(entry);
                Ensure(
                    (attributes & FileAttributes.ReparsePoint) == 0,
                    "the startup settings test root contains a reparse point");
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(entry);
                }
            }
        }
    }

    private static Task<Exception?>? FindQuarantineTask(Exception failure)
    {
        if (failure.Data["GuardianBrokerBootstrapLateStageQuarantine"] is
            Task<Exception?> quarantine)
        {
            return quarantine;
        }

        if (failure is GuardianBrokerBootstrapFailureV1 bootstrapFailure &&
            bootstrapFailure.ConcurrentFailure is not null)
        {
            var nested = FindQuarantineTask(bootstrapFailure.ConcurrentFailure);
            if (nested is not null)
            {
                return nested;
            }
        }

        if (failure is AggregateException aggregate)
        {
            foreach (var inner in aggregate.InnerExceptions)
            {
                var nested = FindQuarantineTask(inner);
                if (nested is not null)
                {
                    return nested;
                }
            }
        }

        return failure.InnerException is null
            ? null
            : FindQuarantineTask(failure.InnerException);
    }

    private static string FindWorkspaceSource(params string[] relativePath)
    {
        for (var current = new DirectoryInfo(Environment.CurrentDirectory);
             current is not null;
             current = current.Parent)
        {
            var candidate = Path.Combine(
                new[] { current.FullName, "work" }.Concat(relativePath).ToArray());
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new DirectoryNotFoundException(
            "The Guardian application source root was not found.");
    }

    private static string Slice(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        var end = start < 0
            ? -1
            : source.IndexOf(endMarker, start, StringComparison.Ordinal);
        return start >= 0 && end > start ? source[start..end] : string.Empty;
    }

    private static void RunCase(string name, Action action, Action<bool, string> assert)
    {
        try
        {
            action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> action,
        Action<bool, string> assert)
    {
        try
        {
            await action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class DelegatingSettingsWriteAuthority : ISettingsWriteAuthority
    {
        private readonly Action<Action> _publish;

        internal DelegatingSettingsWriteAuthority(Action<Action> publish) =>
            _publish = publish ?? throw new ArgumentNullException(nameof(publish));

        public void Publish(Action atomicPublication) => _publish(atomicPublication);
    }

    private sealed class ChunkedReadStream : Stream
    {
        private readonly byte[] _bytes;
        private readonly int _maximumChunk;
        private int _offset;

        internal ChunkedReadStream(byte[] bytes, int maximumChunk)
        {
            _bytes = bytes.ToArray();
            _maximumChunk = maximumChunk;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _bytes.Length;
        public override long Position
        {
            get => _offset;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_offset >= _bytes.Length)
            {
                return 0;
            }

            var count = Math.Min(
                Math.Min(buffer.Length, _maximumChunk),
                _bytes.Length - _offset);
            _bytes.AsSpan(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
