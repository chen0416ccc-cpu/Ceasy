using CodexGuardian.Control;
using CodexGuardian.Localization;
using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Security.Cryptography;
using System.Text;

namespace CodexGuardian;

public static class Program
{
    private const string ManagedEntryProofArgument = "--guardian-managed-entry-proof-v1";
    private const string ManagedEntryChallengeArgument = "--challenge";

    [STAThread]
    public static int Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (ContainsManagedEntryProofPrefix(args))
        {
            return TryRunManagedEntryProof(args);
        }

        var brokerBootstrapRequested =
            GuardianBrokerManagedBootstrapV1.ContainsBootstrapPrefix(args);
        ulong bootstrapHandle = 0;
        if (brokerBootstrapRequested &&
            !GuardianBrokerManagedBootstrapV1.TryParseArguments(
                args,
                out bootstrapHandle))
        {
            return 64;
        }

        EnsureWindowsEnvironment();
        GuardianBrokerBootstrapLifetime? brokerLifetime = null;
        if (brokerBootstrapRequested)
        {
            try
            {
                brokerLifetime = GuardianBrokerManagedBootstrapV1.BootstrapAsync(
                        bootstrapHandle,
                        typeof(Program).Assembly)
                    .GetAwaiter()
                    .GetResult();
            }
            catch
            {
                return 1;
            }
        }

        App? application = null;
        try
        {
            application = new App();
            if (brokerLifetime is not null)
            {
                application.AttachBrokerBootstrapLifetime(brokerLifetime);
                brokerLifetime = null;
            }

            application.InitializeComponent();
            return application.Run();
        }
        catch when (brokerBootstrapRequested)
        {
            try
            {
                if (application is not null)
                {
                    application.RequestExitAsync().GetAwaiter().GetResult();
                }
                else if (brokerLifetime is not null)
                {
                    brokerLifetime.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            }
            catch
            {
            }

            return 1;
        }
    }

    private static int TryRunManagedEntryProof(string[] args)
    {
        if (args.Length != 3 ||
            !string.Equals(args[0], ManagedEntryProofArgument, StringComparison.Ordinal) ||
            !string.Equals(args[1], ManagedEntryChallengeArgument, StringComparison.Ordinal) ||
            !TryParseCanonicalChallenge(args[2], out var challenge))
        {
            return 64;
        }

        try
        {
            var receipt = GuardianManagedEntryProofV1.CreateCurrent(
                challenge,
                typeof(Program).Assembly);
            var payload = GuardianManagedEntryProofProtocolV1.Serialize(receipt);
            using var output = Console.OpenStandardOutput();
            output.Write(payload);
            output.Flush();
            return 0;
        }
        catch
        {
            return 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static bool ContainsManagedEntryProofPrefix(IEnumerable<string> args) =>
        args.Any(argument => argument.StartsWith(
            "--guardian-managed-entry-proof",
            StringComparison.OrdinalIgnoreCase));

    private static bool TryParseCanonicalChallenge(string value, out byte[] challenge)
    {
        challenge = Array.Empty<byte>();
        if (value.Length != GuardianManagedEntryProofProtocolV1.ChallengeBytes * 2)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character) && character is not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        try
        {
            challenge = Convert.FromHexString(value);
            return challenge.Length == GuardianManagedEntryProofProtocolV1.ChallengeBytes;
        }
        catch (FormatException)
        {
            challenge = Array.Empty<byte>();
            return false;
        }
    }

    private static void EnsureWindowsEnvironment()
    {
        var windowsDirectory = Environment.GetEnvironmentVariable("WINDIR");
        if (string.IsNullOrWhiteSpace(windowsDirectory))
        {
            windowsDirectory = Directory.GetParent(Environment.SystemDirectory)?.FullName ?? @"C:\Windows";
            Environment.SetEnvironmentVariable("WINDIR", windowsDirectory, EnvironmentVariableTarget.Process);
        }

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SystemRoot")))
        {
            Environment.SetEnvironmentVariable("SystemRoot", windowsDirectory, EnvironmentVariableTarget.Process);
        }
    }
}

internal sealed record GuardianLaunchOptions(
    bool SafePreview,
    bool FollowUpPreviewFixture,
    bool Background,
    string? DataDirectory)
{
    internal const string PreviewDataRoot = @"D:\CodexData\CodexGuardian";

    internal bool AllowsLiveIntegration => !SafePreview;

    internal string ResolveStartupMutexName(string sharedName)
    {
        if (string.IsNullOrWhiteSpace(sharedName))
        {
            throw new ArgumentException("A startup mutex name is required.", nameof(sharedName));
        }

        if (!SafePreview)
        {
            return sharedName;
        }

        var dataDirectory = DataDirectory ?? throw new InvalidOperationException(
            "A safe preview must have a normalized data directory before startup ownership is acquired.");
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(dataDirectory.ToUpperInvariant()));
        return $"{sharedName}.SafePreview.{Convert.ToHexString(digest)}";
    }

    internal static GuardianLaunchOptions Parse(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var safePreview = HasFlag(arguments, "--safe-preview");
        var followUpPreviewFixture = HasFlag(arguments, "--follow-up-preview-fixture");
        var background = HasFlag(arguments, "--background");
        var dataDirectory = ReadSingleValue(arguments, "--data-directory");

        if (followUpPreviewFixture && !safePreview)
        {
            throw new ArgumentException(
                "--follow-up-preview-fixture requires --safe-preview.",
                nameof(arguments));
        }

        if (safePreview)
        {
            if (background)
            {
                throw new ArgumentException(
                    "--safe-preview must remain visible and cannot be combined with --background.",
                    nameof(arguments));
            }

            dataDirectory = NormalizePreviewDataDirectory(dataDirectory);
        }

        return new(safePreview, followUpPreviewFixture, background, dataDirectory);
    }

    private static bool HasFlag(IEnumerable<string> arguments, string name) =>
        arguments.Any(argument => string.Equals(argument, name, StringComparison.OrdinalIgnoreCase));

    private static string? ReadSingleValue(IReadOnlyList<string> arguments, string name)
    {
        var indexes = Enumerable.Range(0, arguments.Count)
            .Where(index => string.Equals(arguments[index], name, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (indexes.Length == 0)
        {
            return null;
        }

        if (indexes.Length != 1 || indexes[0] + 1 >= arguments.Count ||
            arguments[indexes[0] + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{name} requires exactly one value.", nameof(arguments));
        }

        return arguments[indexes[0] + 1];
    }

    private static string NormalizePreviewDataDirectory(string? dataDirectory)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory) || !Path.IsPathFullyQualified(dataDirectory))
        {
            throw new ArgumentException(
                "--safe-preview requires an explicit fully-qualified D-drive --data-directory.",
                nameof(dataDirectory));
        }

        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataDirectory.Trim()));
        var requiredRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(PreviewDataRoot));
        if (normalized.StartsWith(@"\\", StringComparison.Ordinal) ||
            !normalized.StartsWith(requiredRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"--safe-preview data must be a phase child below {PreviewDataRoot}.",
                nameof(dataDirectory));
        }

        return normalized;
    }
}

internal sealed record FollowUpPreviewFixtureState(
    AppSettings Settings,
    GuardianTaskSnapshot Snapshot,
    string SelectedTaskId,
    IReadOnlyList<WorkflowRuleDefinition> WorkflowRules,
    WorkflowLineageSnapshot WorkflowLineage);

internal static class FollowUpPreviewFixture
{
    internal const string TaskId = "13000000-0000-4000-8000-000000000001";
    internal const string TurnId = "13000000-0000-4000-8000-000000000002";
    internal const string ProcessingTaskId = "13000000-0000-4000-8000-000000000003";
    internal const string AttentionTaskId = "13000000-0000-4000-8000-000000000004";
    internal const string ArchivedTaskId = "13000000-0000-4000-8000-000000000005";
    internal const string CompletionMessageId = "13000000-0000-4000-8000-000000000101";
    internal const string ScheduledMessageId = "13000000-0000-4000-8000-000000000102";
    internal const string ImageAttachmentId = "13000000-0000-4000-8000-000000000201";
    internal const string FileAttachmentId = "13000000-0000-4000-8000-000000000202";

    internal static FollowUpPreviewFixtureState Create(
        DateTimeOffset now,
        AppSettings? persistedAppearance = null)
    {
        var nowUtc = now.ToUniversalTime();
        var settings = new AppSettings
        {
            UiLanguage = UiLanguages.Normalize(persistedAppearance?.UiLanguage),
            UiTheme = UiThemes.Normalize(persistedAppearance?.UiTheme),
            MonitoringEnabled = false,
            MonitorOnly = true,
            MinimizeToTray = false,
            StartWithWindows = false
        };
        var isChinese = string.Equals(
            settings.UiLanguage,
            UiLanguages.SimplifiedChinese,
            StringComparison.Ordinal);
        var previewTitle = isChinese ? "预制消息预览" : "Preset message preview";
        var previewSummary = isChinese ? "隔离预览" : "Isolated preview";
        var previewSource = isChinese ? "预览" : "Preview";
        var previewCompletion = isChinese ? "已完成" : "Completed";
        var previewReadOnly = isChinese ? "只读预览" : "Read-only preview";
        settings.ThreadFollowUps[TaskId] = new ThreadFollowUpSettings
        {
            IsEnabled = true,
            CompletionAnchorTurnId = TurnId,
            Messages =
            [
                new FollowUpMessageDefinition
                {
                    Id = CompletionMessageId,
                    Message = isChinese ? "复核已完成回合。" : "Review the completed turn.",
                    Attachments =
                    [
                        new PresetAttachmentReference
                        {
                            Id = ImageAttachmentId,
                            ContentId = "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
                            OriginalFileName = "layout-reference.png",
                            DetectedType = "image/png",
                            OwnerInputKind = "local_image",
                            ByteLength = 2048,
                            Order = 0
                        },
                        new PresetAttachmentReference
                        {
                            Id = FileAttachmentId,
                            ContentId = "B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2",
                            OriginalFileName = "acceptance-notes.txt",
                            DetectedType = "text/plain",
                            OwnerInputKind = "local_file",
                            ByteLength = 3072,
                            Order = 1
                        }
                    ],
                    Trigger = FollowUpTriggerKind.AfterNormalCompletion,
                    IsEnabled = true,
                    Order = 0
                },
                new FollowUpMessageDefinition
                {
                    Id = ScheduledMessageId,
                    Message = isChinese ? "明日检查结果。" : "Check tomorrow's result.",
                    Trigger = FollowUpTriggerKind.ScheduledAt,
                    ScheduledAtUtc = nowUtc.AddDays(1),
                    IsEnabled = true,
                    UseWorkflowAutomation = true,
                    Order = 1
                }
            ]
        };
        var fixtureTaskIds = new[]
        {
            TaskId,
            ProcessingTaskId,
            AttentionTaskId,
            ArchivedTaskId
        };
        var persistedFixtureOrder = SettingsService
            .NormalizeConversationOrder(persistedAppearance?.ConversationOrder)
            .Where(candidate => fixtureTaskIds.Contains(candidate, StringComparer.OrdinalIgnoreCase))
            .ToList();
        foreach (var taskId in fixtureTaskIds)
        {
            if (!persistedFixtureOrder.Contains(taskId, StringComparer.OrdinalIgnoreCase))
            {
                persistedFixtureOrder.Add(taskId);
            }
        }
        settings.ConversationOrder = persistedFixtureOrder;

        var completedAt = nowUtc.ToUnixTimeSeconds();
        var turn = new TurnSnapshot(
            TurnId,
            "completed",
            null,
            null,
            null,
            string.Empty,
            false,
            true,
            true,
            "preview-fixture-output",
            completedAt - 60,
            completedAt,
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);
        var thread = new ThreadSummary(
            TaskId,
            previewTitle,
            previewSummary,
            @"D:\CodexData\CodexGuardian\preview-fixture",
            previewSource,
            completedAt - 300,
            completedAt,
            false,
            false,
            RuntimeStatus: "idle");
        var state = new GuardianTaskState(
            thread,
            turn,
            RecoveryDecision.None(TaskHealth.Healthy, previewSummary),
            false,
            TaskHealth.Healthy,
            previewCompletion,
            previewReadOnly,
            0,
            null);
        GuardianTaskState AuxiliaryState(
            string id,
            string chineseTitle,
            string englishTitle,
            string chineseSummary,
            string englishSummary,
            string chineseStatus,
            string englishStatus,
            TaskHealth health,
            long updatedOffsetSeconds,
            string runtimeStatus,
            bool archived = false)
        {
            var title = isChinese ? chineseTitle : englishTitle;
            var summary = isChinese ? chineseSummary : englishSummary;
            var status = isChinese ? chineseStatus : englishStatus;
            var auxiliaryThread = new ThreadSummary(
                id,
                title,
                summary,
                @"D:\CodexData\CodexGuardian\preview-fixture",
                previewSource,
                completedAt - 900,
                completedAt - updatedOffsetSeconds,
                false,
                false,
                RuntimeStatus: runtimeStatus,
                IsArchived: archived);
            return new GuardianTaskState(
                auxiliaryThread,
                null,
                RecoveryDecision.None(health, summary),
                false,
                health,
                status,
                previewReadOnly,
                0,
                null);
        }

        var processingState = AuxiliaryState(
            ProcessingTaskId,
            "终端任务执行中",
            "Active terminal task",
            "终端步骤进行中",
            "Terminal step in progress",
            "执行中",
            "In progress",
            TaskHealth.Processing,
            120,
            "inProgress");
        var attentionState = AuxiliaryState(
            AttentionTaskId,
            "恢复待复核",
            "Recovery review",
            "恢复已被策略拦截",
            "Recovery blocked by policy",
            "待复核",
            "Review",
            TaskHealth.ManualReview,
            240,
            "idle");
        var archivedState = AuxiliaryState(
            ArchivedTaskId,
            "已归档记录",
            "Archived reference",
            "只读归档",
            "Read-only archive",
            "已归档",
            "Archived",
            TaskHealth.Healthy,
            3600,
            "idle",
            archived: true);
        var workflowRule = WorkflowRuleDefinition.Create(
            WorkflowRuleEditor.CreateManagedRuleId(TaskId, ScheduledMessageId),
            revision: 1,
            TaskId,
            isEnabled: true,
            nowUtc.AddMinutes(-10),
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                SourceConversationId = ProcessingTaskId
            },
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation,
                ConversationId = AttentionTaskId
            },
            Enum.GetValues<WorkflowConditionKind>(),
            [
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.SendPresetMessage,
                    PresetOwnerConversationId = TaskId,
                    PresetMessageId = ScheduledMessageId,
                    Order = 0
                },
                new WorkflowActionDefinition
                {
                    Kind = WorkflowActionKind.EnableConversationProtection,
                    Order = 1
                }
            ]);
        var previewQueue = settings.ThreadFollowUps[TaskId];
        settings.ThreadFollowUps[TaskId] = previewQueue with
        {
            Messages = previewQueue.Messages.Select(message =>
                string.Equals(
                    message.Id,
                    ScheduledMessageId,
                    StringComparison.OrdinalIgnoreCase)
                    ? message with
                    {
                        WorkflowRuleRevision = workflowRule.Revision,
                        WorkflowRuleDigest = workflowRule.DefinitionDigest
                    }
                    : message).ToArray()
        };
        var previewFlowA = WorkflowJournalLineageReader.CreateOpaqueReference(
            "flow",
            "preview-flow-a");
        var previewFlowB = WorkflowJournalLineageReader.CreateOpaqueReference(
            "flow",
            "preview-flow-b");
        var confirmedActionRef = WorkflowJournalLineageReader.CreateOpaqueReference(
            "action",
            "preview-confirmed-action");
        var presetRef = WorkflowJournalLineageReader.CreateOpaqueReference(
            "preset",
            ScheduledMessageId);
        var workflowLineage = new WorkflowLineageSnapshot(
            WorkflowLineageHealth.Healthy,
            WorkflowLineageUnavailableReason.None,
            Generation: 3,
            TotalCorrelationCount: 2,
            TotalTriggerCount: 3,
            TotalActionCount: 3,
            IsTruncated: false,
            [
                new WorkflowLineageItem(
                    WorkflowLineageItemKind.Action,
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "action",
                        "preview-uncertain-action"),
                    previewFlowB,
                    ParentActionRef: null,
                    CorrelationDepth: 1,
                    WorkflowTriggerKind.ScheduledAt,
                    WorkflowJournalLineageReader.CreateOpaqueReference("task", TaskId),
                    nowUtc.AddMinutes(-7),
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "rule",
                        workflowRule.RuleId),
                    RuleRevision: 1,
                    ActionIndex: 0,
                    WorkflowActionKind.SendPresetMessage,
                    WorkflowDestinationKind.ExistingConversation,
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "task",
                        AttentionTaskId),
                    presetRef,
                    WorkflowActionOperationState.Uncertain,
                    WorkflowLineageFailureReason.Uncertain,
                    AttemptCount: 1,
                    CreatedAtUtc: nowUtc.AddMinutes(-6),
                    UpdatedAtUtc: nowUtc.AddMinutes(-5),
                    LastRecordedAttemptAtUtc: nowUtc.AddMinutes(-5)),
                new WorkflowLineageItem(
                    WorkflowLineageItemKind.Action,
                    confirmedActionRef,
                    previewFlowA,
                    ParentActionRef: null,
                    CorrelationDepth: 1,
                    WorkflowTriggerKind.ConversationCompletedNormally,
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "task",
                        ProcessingTaskId),
                    nowUtc.AddMinutes(-12),
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "rule",
                        workflowRule.RuleId),
                    RuleRevision: 1,
                    ActionIndex: 0,
                    WorkflowActionKind.SendPresetMessage,
                    WorkflowDestinationKind.ExistingConversation,
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "task",
                        AttentionTaskId),
                    presetRef,
                    WorkflowActionOperationState.Confirmed,
                    WorkflowLineageFailureReason.None,
                    AttemptCount: 1,
                    CreatedAtUtc: nowUtc.AddMinutes(-11),
                    UpdatedAtUtc: nowUtc.AddMinutes(-10),
                    LastRecordedAttemptAtUtc: nowUtc.AddMinutes(-10)),
                new WorkflowLineageItem(
                    WorkflowLineageItemKind.Action,
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "action",
                        "preview-blocked-action"),
                    previewFlowA,
                    ParentActionRef: confirmedActionRef,
                    CorrelationDepth: 2,
                    WorkflowTriggerKind.PresetDispatchConfirmed,
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "task",
                        AttentionTaskId),
                    nowUtc.AddMinutes(-9),
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "rule",
                        workflowRule.RuleId),
                    RuleRevision: 1,
                    ActionIndex: 1,
                    WorkflowActionKind.EnableConversationProtection,
                    WorkflowDestinationKind.ExistingConversation,
                    WorkflowJournalLineageReader.CreateOpaqueReference(
                        "task",
                        AttentionTaskId),
                    PresetRef: null,
                    WorkflowActionOperationState.Blocked,
                    WorkflowLineageFailureReason.DispatchBudgetExhausted,
                    AttemptCount: 0,
                    CreatedAtUtc: nowUtc.AddMinutes(-8),
                    UpdatedAtUtc: nowUtc.AddMinutes(-8),
                    LastRecordedAttemptAtUtc: null)
            ]);
        return new(
            settings,
            GuardianTaskSnapshot.FromLegacy([state, processingState, attentionState, archivedState]),
            TaskId,
            [workflowRule],
            workflowLineage);
    }
}
