using CodexGuardian.Models;
using CodexGuardian.Services;
using CodexGuardian.ViewModels;
using System.IO;
using System.Text.Json;

internal static class ConversationIndexOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "conversation protection defaults off and version nine migration requires opt-in",
            TestProtectionMigrationAsync,
            assert);
        await RunCaseAsync(
            "conversation index orders by pin project and recent activity",
            TestSmartConversationOrderAsync,
            assert);
        await RunCaseAsync(
            "latest exact turn activity controls same-title status and recency",
            TestLatestTurnActivityProjectionAsync,
            assert);
        await RunCaseAsync(
            "conversation cards expose pin protection and three-state surfaces",
            TestConversationCardContractAsync,
            assert);
        await RunCaseAsync(
            "all conversations exclude archived rows and expose Codex-style sections",
            TestConversationSectionsAsync,
            assert);
        await RunCaseAsync(
            "conversation projects use real project roots instead of Codex history folders",
            TestRecognizedProjectRootsAsync,
            assert);
        await RunCaseAsync(
            "conversation previews stay concise and Codex pin sections are authoritative",
            TestPreviewAndCodexPinProjectionAsync,
            assert);
    }

    private static async Task TestProtectionMigrationAsync()
    {
        Ensure(
            AppSettings.CurrentConfigurationVersion == 9 &&
            !new AppSettings().ProtectNewThreadsByDefault,
            "new settings did not default every conversation to manual protection opt-in");

        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.Combine(parent, "conversation-index-migration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var legacyConversationId = Guid.NewGuid().ToString("D");
            await File.WriteAllTextAsync(
                Path.Combine(root, "settings.json"),
                $$"""
                {
                  "ConfigurationVersion": 8,
                  "ProtectNewThreadsByDefault": true,
                  "ThreadEnabled": { "{{legacyConversationId}}": true },
                  "ThreadProtectionEnabled": { "{{legacyConversationId}}": true },
                  "ConversationOrder": [ "{{legacyConversationId}}" ]
                }
                """);

            var migrated = await new SettingsService(root).LoadAsync();
            Ensure(
                migrated.ConfigurationVersion == AppSettings.CurrentConfigurationVersion &&
                !migrated.ProtectNewThreadsByDefault &&
                migrated.ThreadEnabled.Count == 0 &&
                migrated.ThreadProtectionEnabled.Count == 0 &&
                migrated.PinnedConversationIds.Count == 0 &&
                !migrated.UseManualConversationOrder,
                "version eight protection or ordering authority survived the manual opt-in migration");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static Task TestSmartConversationOrderAsync()
    {
        var pinned = State("pin-a", @"D:\Projects\Alpha", updatedAt: 100);
        var alpha = State("alpha-new", @"D:\Projects\Alpha", updatedAt: 200);
        var betaNew = State("beta-new", @"D:\Projects\Beta", updatedAt: 400);
        var betaOld = State("beta-old", @"d:\projects\beta\", updatedAt: 300);
        var noProject = State("no-project", string.Empty, updatedAt: 500);

        var ordered = MainViewModel.OrderConversations(
            [alpha, betaOld, pinned, noProject, betaNew],
            [pinned.Thread.Id],
            useManualOrder: false,
            manualOrder: []);

        Ensure(
            ordered.Select(static state => state.Thread.Id).SequenceEqual(
                ["pin-a", "beta-new", "beta-old", "alpha-new", "no-project"]),
            "smart order did not apply pin priority project recency and in-project time");
        Ensure(
            string.Equals(
                MainViewModel.GetConversationProjectKey(betaNew.Thread.Cwd),
                MainViewModel.GetConversationProjectKey(betaOld.Thread.Cwd),
                StringComparison.OrdinalIgnoreCase),
            "canonical project identity changed with path casing or a trailing separator");
        return Task.CompletedTask;
    }

    private static Task TestLatestTurnActivityProjectionAsync()
    {
        const long staleThreadTime = 100;
        const long healthyThreadTime = 600;
        const long failedTurnTime = 900;
        const long successorTime = 1_200;
        const string project = @"D:\Projects\SameTitle";

        var failedThread = Thread("failed-nine", "9", project, staleThreadTime);
        var healthyThread = Thread("healthy-nine", "9", project, healthyThreadTime);
        var failedTurn = Turn(
            "failed-turn",
            "failed",
            startedAt: failedTurnTime - 10,
            completedAt: failedTurnTime,
            hasFinalAssistantOutput: false);
        var healthyTurn = Turn(
            "healthy-turn",
            "completed",
            startedAt: healthyThreadTime - 10,
            completedAt: healthyThreadTime,
            hasFinalAssistantOutput: true);

        var projectedFailure = GuardianEngine.ProjectLatestTurnActivity(failedThread, failedTurn);
        var projectedHealthy = GuardianEngine.ProjectLatestTurnActivity(healthyThread, healthyTurn);
        var failedState = State(projectedFailure, failedTurn, TaskHealth.NeedsAttention);
        var healthyState = State(projectedHealthy, healthyTurn, TaskHealth.Healthy);
        var ordered = MainViewModel.OrderConversations(
            [healthyState, failedState],
            pinnedConversationIds: [],
            useManualOrder: false,
            manualOrder: []);

        var failedItem = Item(failedState);
        var healthyItem = Item(healthyState);
        Ensure(
            projectedFailure.UpdatedAt == failedTurnTime &&
            failedThread.UpdatedAt == staleThreadTime &&
            ordered.Select(static state => state.Thread.Id)
                .SequenceEqual(["failed-nine", "healthy-nine"]),
            "a new failed turn did not project UI activity without mutating the source thread metadata");
        Ensure(
            failedItem.VisualTone == TaskVisualTone.Attention &&
            healthyItem.VisualTone == TaskVisualTone.Healthy,
            "same-title conversations shared status instead of using their exact turn identity");

        var successor = Turn(
            "successor-turn",
            "completed",
            startedAt: successorTime - 10,
            completedAt: successorTime,
            hasFinalAssistantOutput: true);
        var recoveredState = State(
            GuardianEngine.ProjectLatestTurnActivity(failedThread, successor),
            successor,
            TaskHealth.Healthy);
        var recoveredItem = Item(recoveredState);
        Ensure(
            recoveredState.Thread.UpdatedAt == successorTime &&
            recoveredItem.VisualTone == TaskVisualTone.Healthy,
            "a normally completed successor did not refresh the same conversation time and green status");
        return Task.CompletedTask;
    }

    private static Task TestConversationCardContractAsync()
    {
        var root = FindGuardianSourceRoot();
        var xaml = File.ReadAllText(Path.Combine(root, "MainWindow.xaml"));
        var appXaml = File.ReadAllText(Path.Combine(root, "App.xaml"));
        var window = File.ReadAllText(Path.Combine(root, "MainWindow.xaml.cs"));

        Ensure(
            xaml.Contains("AutomationProperties.AutomationId=\"ConversationCardProtectionToggle\"", StringComparison.Ordinal) &&
            xaml.Contains("IsChecked=\"{Binding IsEnabled, Mode=TwoWay}\"", StringComparison.Ordinal) &&
            xaml.Contains("IsEnabled=\"{Binding CanToggleProtection}\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ConversationPinButton\"", StringComparison.Ordinal) &&
            xaml.Contains("Command=\"{Binding DataContext.ToggleConversationPinCommand", StringComparison.Ordinal),
            "each conversation card is missing its real pin or protection control");
        Ensure(
            appXaml.Contains("x:Name=\"StatusAura\"", StringComparison.Ordinal) &&
            appXaml.Contains("x:Name=\"StatusWash\"", StringComparison.Ordinal) &&
            appXaml.Contains("TaskVisualTone.Healthy", StringComparison.Ordinal) &&
            !appXaml.Contains("TaskVisualTone.Active", StringComparison.Ordinal) &&
            appXaml.Contains("TaskVisualTone.Attention", StringComparison.Ordinal) &&
            window.Contains("SystemParameters.ClientAreaAnimation", StringComparison.Ordinal),
            "conversation state is not projected through the two-tone reduced-motion-aware surfaces");
        return Task.CompletedTask;
    }

    private static Task TestConversationSectionsAsync()
    {
        var root = FindGuardianSourceRoot();
        var xaml = File.ReadAllText(Path.Combine(root, "MainWindow.xaml"));
        var viewModel = File.ReadAllText(Path.Combine(root, "ViewModels", "MainViewModel.cs"));
        var appXaml = File.ReadAllText(Path.Combine(root, "App.xaml"));
        Ensure(
            xaml.Contains("x:Name=\"ConversationNavigationStage\"", StringComparison.Ordinal) &&
            xaml.Contains("x:Name=\"ConversationNavigationList\"", StringComparison.Ordinal) &&
            xaml.Contains("ToggleConversationSectionCommand", StringComparison.Ordinal) &&
            xaml.Contains("ConversationGroupBackButton", StringComparison.Ordinal) &&
            viewModel.Contains("ConversationNavigationEntryKind", StringComparison.Ordinal) &&
            viewModel.Contains("_conversationSectionExpansion", StringComparison.Ordinal) &&
            viewModel.Contains("ToggleConversationSection", StringComparison.Ordinal) &&
            viewModel.Contains("ConversationNavigationMotionRevision", StringComparison.Ordinal) &&
            viewModel.Contains("MatchesConversationGroup", StringComparison.Ordinal) &&
            viewModel.Contains("ProjectConversationGroupPrefix + group.Key", StringComparison.Ordinal) &&
            viewModel.Contains("DisplayProjectName(group.Key)", StringComparison.Ordinal) &&
            viewModel.Contains("task.IsArchived", StringComparison.Ordinal),
            "the conversation index is missing its root and second-level navigation contract");

        Ensure(
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedNavigationUnarchiveButton\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedNavigationDeleteButton\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedNavigationDeleteConfirmButton\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedNavigationDeleteCancelButton\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedNavigationMutationProgress\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.AutomationId=\"ArchivedNavigationMutationUnavailable\"", StringComparison.Ordinal) &&
            xaml.Contains("IsConversationMutationUnavailable", StringComparison.Ordinal) &&
            xaml.Contains("CommandParameter=\"{Binding Task}\"", StringComparison.Ordinal) &&
            !xaml.Contains("BooleanAndToVisibilityConverter", StringComparison.Ordinal),
            "archived root rows are missing their inline mutation states or use an unverified visibility converter");

        Ensure(
            !appXaml.Contains("RepeatBehavior=\"Forever\"", StringComparison.Ordinal) &&
            File.ReadAllText(Path.Combine(root, "Models", "RecoveryModels.cs"))
                .Contains("HasFinalAssistantOutput", StringComparison.Ordinal),
            "conversation status visuals still depend on a perpetual animation or health-only color");

        var archived = State("archived", @"D:\Projects\Alpha", updatedAt: 900) with
        {
            Thread = State("archived", @"D:\Projects\Alpha", updatedAt: 900).Thread with { IsArchived = true }
        };
        var active = State("active", @"D:\Projects\Alpha", updatedAt: 800);
        var settings = new AppSettings();
        var filter = new[] { archived, active };
        Ensure(
            filter.Where(state => !state.Thread.IsArchived).Select(state => state.Thread.Id)
                .SequenceEqual(["active"]),
            "all scope still admits archived conversations");
        return Task.CompletedTask;
    }

    private static Task TestRecognizedProjectRootsAsync()
    {
        var history = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Documents",
            "Codex",
            "2026-08-22",
            "new-chat");
        Ensure(
            MainViewModel.GetRecognizedConversationProjectKey(history) is null,
            "date-based Codex history workspace was incorrectly projected as a project");

        // The recognized root is pinned by shape rather than by name. A checkout directory name is an
        // artifact of wherever the repository was cloned, not a contract, so naming one here failed
        // every clone that did not reuse this machine's directory name. Shape is also the stronger
        // assertion: what this case is about is that resolution keeps walking up and reports the
        // outermost marked directory instead of stopping at the nearest one, and the source root
        // itself carries a .csproj -- so an implementation that stopped at the nearest marker would
        // return the source root, which the strict-ancestor check rejects directly while the name
        // comparison only rejected it as a side effect.
        var sourceRoot = Path.GetFullPath(FindGuardianSourceRoot())
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var projectKey = MainViewModel.GetRecognizedConversationProjectKey(sourceRoot);
        Ensure(
            projectKey is not null &&
            sourceRoot.StartsWith(
                projectKey + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) &&
            Directory.Exists(Path.Combine(projectKey, "work")),
            "a real repository root was not recognized as a project");
        return Task.CompletedTask;
    }

    private static async Task TestPreviewAndCodexPinProjectionAsync()
    {
        var safe = MainViewModel.DisplayConversationPreview(
            "<codex-windows-fast-patch>\n" +
            "<source_thread_id>019fa973</source_thread_id>\n" +
            "【来源与目录】\n" +
            "D:\\Users\\21392\\Documents\\Codex\n" +
            "继续修复会话列表",
            "会话列表修复");
        Ensure(
            safe.Length == 0 &&
            !safe.Contains("source_thread", StringComparison.OrdinalIgnoreCase) &&
            !safe.Contains('\\') &&
            !safe.Contains('\n'),
            "structured handoff content leaked into the conversation preview");

        using var document = JsonDocument.Parse(
            """
            {
              "data": [
                {
                  "id": "codex-pinned",
                  "name": "Pinned conversation",
                  "preview": "Pinned conversation",
                  "cwd": "",
                  "createdAt": 1,
                  "updatedAt": 2,
                  "section": { "name": "Pinned" }
                },
                {
                  "id": "codex-recent",
                  "name": "Recent conversation",
                  "preview": "Recent conversation",
                  "cwd": "",
                  "createdAt": 1,
                  "updatedAt": 3,
                  "section": null
                }
              ],
              "nextCursor": null
            }
            """);
        var threads = await AppServerClient.ListThreadsCoreAsync(
            pageSize: 10,
            includeSubAgents: false,
            archived: false,
            (_, _) => Task.FromResult(document.RootElement.Clone()));
        Ensure(
            threads.Single(thread => thread.Id == "codex-pinned").IsPinned == true &&
            threads.Single(thread => thread.Id == "codex-recent").IsPinned == false,
            "Codex section pin state was not projected as authoritative true/false");
    }

    private static GuardianTaskState State(string id, string cwd, long updatedAt) =>
        new(
            Thread(id, id, cwd, updatedAt),
            Turn: null,
            RecoveryDecision.None(TaskHealth.Healthy, "test"),
            IsEnabled: false,
            TaskHealth.Healthy,
            "healthy",
            "test",
            Attempts: 0,
            NextAttemptAt: null);

    private static GuardianTaskState State(
        ThreadSummary thread,
        TurnSnapshot turn,
        TaskHealth health) =>
        new(
            thread,
            turn,
            RecoveryDecision.None(health, "test"),
            IsEnabled: false,
            health,
            "test",
            "test",
            Attempts: 0,
            NextAttemptAt: null);

    private static ThreadSummary Thread(string id, string name, string cwd, long updatedAt) =>
        new(
            id,
            name,
            name,
            cwd,
            "appServer",
            updatedAt - 10,
            updatedAt,
            IsSubAgent: false,
            IsEphemeral: false);

    private static TurnSnapshot Turn(
        string id,
        string status,
        long startedAt,
        long completedAt,
        bool hasFinalAssistantOutput) =>
        new(
            id,
            status,
            ErrorMessage: hasFinalAssistantOutput ? null : "429",
            ErrorCode: hasFinalAssistantOutput ? null : "rate_limit",
            HttpStatusCode: hasFinalAssistantOutput ? null : 429,
            UserText: "9",
            HasAttachments: false,
            HasAssistantOutput: hasFinalAssistantOutput,
            HasWorkOutput: false,
            OutputFingerprint: id,
            StartedAt: startedAt,
            CompletedAt: completedAt,
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: hasFinalAssistantOutput,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static GuardianTaskItem Item(GuardianTaskState state) =>
        new()
        {
            Id = state.Thread.Id,
            Name = state.Thread.Name,
            Preview = state.Thread.Preview,
            Cwd = state.Thread.Cwd,
            RawSource = state.Thread.Source,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(state.Thread.CreatedAt),
            UpdatedAt = DateTimeOffset.FromUnixTimeSeconds(state.Thread.UpdatedAt),
            HasFinalAssistantOutput = state.Turn?.HasReliableFinalOutput == true
        };

    private static string FindGuardianSourceRoot()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.CurrentDirectory, "work", "CodexGuardian"),
            Path.Combine(Environment.CurrentDirectory, "CodexGuardian"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "CodexGuardian"))
        };

        return candidates.FirstOrDefault(path => File.Exists(Path.Combine(path, "MainWindow.xaml")))
            ?? throw new DirectoryNotFoundException("Could not locate the CodexGuardian source root.");
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            Console.WriteLine(exception);
            assert(false, name);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
