using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

internal static class AutomaticRecoveryFreshFailureObserverOfflineTests
{
    private const string TestDataRootEnvironmentVariable = "CODEX_GUARDIAN_TEST_DATA_ROOT";

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase("fresh-failure observer accepts only its exact CLI matrix", TestArgumentMatrix, assert);
        RunCase("fresh-failure observer accepts an exact new failed terminal", TestCandidate, assert);
        RunCase("fresh-failure observer rejects stale and mismatched evidence", TestStaleAndMismatch, assert);
        RunCase("fresh-failure observer rejects non-root and non-recoverable targets", TestTargetEligibility, assert);
        RunCase("fresh-failure observer skips attachment replay until its live gate exists", TestAttachmentBoundary, assert);
        RunCase("fresh-failure observer evidence is bounded and redacted", TestEvidenceWriter, assert);
        RunCase("fresh-failure observer evidence ACL is current-user scoped", TestEvidenceAcl, assert);
        RunCase("fresh-failure observer has no owner or dispatch path", TestSourceContract, assert);
        return Task.CompletedTask;
    }

    private static void TestArgumentMatrix()
    {
        var observerId = "019fb89b-9db1-7d70-9225-091ec086f06e";
        var dataDirectory = Path.Combine(
            AutomaticRecoveryFreshFailureObserver.DataRoot,
            observerId);
        var parsed = AutomaticRecoveryFreshFailureObserver.Parse(
        [
            AutomaticRecoveryFreshFailureObserver.ObserverArgument,
            AutomaticRecoveryFreshFailureObserver.ObserverIdArgument,
            observerId,
            AutomaticRecoveryFreshFailureObserver.DataDirectoryArgument,
            dataDirectory,
            AutomaticRecoveryFreshFailureObserver.TimeoutArgument,
            "120",
            AutomaticRecoveryFreshFailureObserver.RequiredActionArgument,
            nameof(RecoveryActionKind.SendContinue)
        ]);
        Ensure(parsed.ObserverId == observerId, "observer id was not canonicalized");
        Ensure(parsed.DataDirectory == Path.GetFullPath(dataDirectory), "observer data directory changed");
        Ensure(parsed.Timeout == TimeSpan.FromSeconds(120), "observer timeout was not bounded");
        Ensure(parsed.RequiredAction == RecoveryActionKind.SendContinue, "observer required action was not parsed");
        Ensure(
            Throws(() => AutomaticRecoveryFreshFailureObserver.Parse(
                [
                    AutomaticRecoveryFreshFailureObserver.ObserverArgument,
                    AutomaticRecoveryFreshFailureObserver.ObserverIdArgument,
                    observerId,
                    AutomaticRecoveryFreshFailureObserver.DataDirectoryArgument,
                    dataDirectory,
                    AutomaticRecoveryFreshFailureObserver.TimeoutArgument,
                    "29",
                    AutomaticRecoveryFreshFailureObserver.RequiredActionArgument,
                    nameof(RecoveryActionKind.SendContinue)
                ])),
            "observer accepted a timeout below its lower bound");
        Ensure(
            Throws(() => AutomaticRecoveryFreshFailureObserver.Parse(
                [
                    AutomaticRecoveryFreshFailureObserver.ObserverArgument,
                    AutomaticRecoveryFreshFailureObserver.ObserverArgument,
                    AutomaticRecoveryFreshFailureObserver.ObserverIdArgument,
                    observerId,
                    AutomaticRecoveryFreshFailureObserver.DataDirectoryArgument,
                    dataDirectory,
                    AutomaticRecoveryFreshFailureObserver.TimeoutArgument,
                    "120",
                    AutomaticRecoveryFreshFailureObserver.RequiredActionArgument,
                    nameof(RecoveryActionKind.SendContinue)
                ])),
            "observer accepted a duplicate flag");
        Ensure(
            Throws(() => AutomaticRecoveryFreshFailureObserver.Parse(
                [
                    AutomaticRecoveryFreshFailureObserver.ObserverArgument,
                    AutomaticRecoveryFreshFailureObserver.ObserverIdArgument,
                    observerId,
                    AutomaticRecoveryFreshFailureObserver.DataDirectoryArgument,
                    @"C:\Temp\observer",
                    AutomaticRecoveryFreshFailureObserver.TimeoutArgument,
                    "120",
                    AutomaticRecoveryFreshFailureObserver.RequiredActionArgument,
                    nameof(RecoveryActionKind.SendContinue)
                ])),
            "observer accepted a non-D-drive data directory");
        Ensure(
            Throws(() => AutomaticRecoveryFreshFailureObserver.Parse(
                [
                    AutomaticRecoveryFreshFailureObserver.ObserverArgument,
                    AutomaticRecoveryFreshFailureObserver.ObserverIdArgument,
                    observerId,
                    AutomaticRecoveryFreshFailureObserver.DataDirectoryArgument,
                    dataDirectory,
                    AutomaticRecoveryFreshFailureObserver.TimeoutArgument,
                    "120",
                    AutomaticRecoveryFreshFailureObserver.RequiredActionArgument,
                    nameof(RecoveryActionKind.SendContinue),
                    "--unknown"
                ])),
            "observer accepted an unknown argument");
        Ensure(
            Throws(() => AutomaticRecoveryFreshFailureObserver.Parse(
                [
                    AutomaticRecoveryFreshFailureObserver.ObserverArgument,
                    AutomaticRecoveryFreshFailureObserver.ObserverIdArgument,
                    observerId,
                    AutomaticRecoveryFreshFailureObserver.DataDirectoryArgument,
                    dataDirectory,
                    AutomaticRecoveryFreshFailureObserver.TimeoutArgument,
                    "120",
                    AutomaticRecoveryFreshFailureObserver.RequiredActionArgument,
                    nameof(RecoveryActionKind.None)
                ])),
            "observer accepted an empty required action");
    }

    private static void TestCandidate()
    {
        var baseline = DateTimeOffset.UtcNow.AddMinutes(-1);
        var fixture = CreateFixture(baseline);
        var evaluation = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            fixture.Event,
            fixture.Thread,
            fixture.AppServerTurn,
            fixture.LocalTerminal);
        Ensure(evaluation.IsCandidate, "an exact fresh failed terminal was not accepted");
        Ensure(
            evaluation.Decision?.Action == RecoveryActionKind.ResendOriginal,
            "a failed text-only turn did not classify as resend original");
        Ensure(evaluation.Code == "candidate", "candidate code was not stable");
        Ensure(
            AutomaticRecoveryFreshFailureObserver.MatchesRequiredAction(
                evaluation.Decision,
                RecoveryActionKind.ResendOriginal),
            "observer did not recognize the observed action");
        Ensure(
            !AutomaticRecoveryFreshFailureObserver.MatchesRequiredAction(
                evaluation.Decision,
                RecoveryActionKind.SendContinue),
            "observer treated a resend-original candidate as SendContinue");
    }

    private static void TestStaleAndMismatch()
    {
        var baseline = DateTimeOffset.UtcNow;
        var fixture = CreateFixture(baseline);
        var staleEvent = new LocalConversationTerminalDetectedEventArgs(
            fixture.Event.ThreadId,
            fixture.Event.TurnId,
            fixture.Event.HasError,
            fixture.Event.SourceFile,
            baseline.AddTicks(-1),
            fixture.Event.IsSubAgent);
        var stale = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            staleEvent,
            fixture.Thread,
            fixture.AppServerTurn,
            fixture.LocalTerminal);
        Ensure(stale.Code == "event-before-baseline", "a pre-baseline event was accepted");

        var wrongRemote = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            fixture.Event,
            fixture.Thread,
            fixture.AppServerTurn with { Id = "019fb89b-9db1-7d70-9225-091ec086f070" },
            fixture.LocalTerminal);
        Ensure(wrongRemote.Code == "appserver-turn-mismatch", "a different app-server latest turn was accepted");

        var wrongLocal = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            fixture.Event,
            fixture.Thread,
            fixture.AppServerTurn,
            fixture.LocalTerminal with { SourceFile = @"D:\sessions\other.jsonl" });
        Ensure(wrongLocal.Code == "local-terminal-mismatch", "a different local rollout was accepted");

        var missingLocal = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            fixture.Event,
            fixture.Thread,
            fixture.AppServerTurn,
            null);
        Ensure(missingLocal.Code == "local-terminal-missing", "a missing local terminal was accepted");
    }

    private static void TestTargetEligibility()
    {
        var baseline = DateTimeOffset.UtcNow;
        var fixture = CreateFixture(baseline);
        Ensure(
            AutomaticRecoveryFreshFailureObserver.Evaluate(
                    baseline,
                    fixture.Event,
                    fixture.Thread with { IsArchived = true },
                    fixture.AppServerTurn,
                    fixture.LocalTerminal)
                .Code == "target-not-active-root",
            "an archived target was accepted");
        Ensure(
            AutomaticRecoveryFreshFailureObserver.Evaluate(
                    baseline,
                    fixture.Event,
                    fixture.Thread with { IsEphemeral = true },
                    fixture.AppServerTurn,
                    fixture.LocalTerminal)
                .Code == "target-not-active-root",
            "an ephemeral target was accepted");
        Ensure(
            AutomaticRecoveryFreshFailureObserver.Evaluate(
                    baseline,
                    new LocalConversationTerminalDetectedEventArgs(
                        fixture.Event.ThreadId,
                        fixture.Event.TurnId,
                        fixture.Event.HasError,
                        fixture.Event.SourceFile,
                        fixture.Event.RecordedAt,
                        isSubAgent: true),
                    fixture.Thread,
                    fixture.AppServerTurn,
                    fixture.LocalTerminal)
                .Code == "subagent-event",
            "a subagent event was accepted");

        var unrecoverable = fixture.AppServerTurn with
        {
            HttpStatusCode = 401,
            ErrorCode = "unauthorized"
        };
        var unrecoverableLocal = fixture.LocalTerminal with
        {
            Turn = fixture.LocalTerminal.Turn with
            {
                HttpStatusCode = 401,
                ErrorCode = "unauthorized"
            }
        };
        var evaluation = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            fixture.Event,
            fixture.Thread,
            unrecoverable,
            unrecoverableLocal);
        Ensure(evaluation.Code == "failed-turn-not-recoverable", "a permanent failure became a candidate");
        Ensure(!evaluation.IsCandidate, "a permanent failure was marked candidate");
    }

    private static void TestAttachmentBoundary()
    {
        var baseline = DateTimeOffset.UtcNow;
        var fixture = CreateFixture(baseline);
        var attachmentTurn = fixture.AppServerTurn with
        {
            HasAttachments = true,
            IsSingleTextUserInput = false,
            RawUserInputJson = "{\"kind\":\"localImage\"}"
        };
        var attachmentLocal = fixture.LocalTerminal with
        {
            Turn = fixture.LocalTerminal.Turn with { HasAttachments = true }
        };
        var skipped = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            fixture.Event,
            fixture.Thread,
            attachmentTurn,
            attachmentLocal);
        Ensure(
            skipped.Code == "attachment-replay-live-gate-required" &&
            skipped.RequiresStructuredReplay,
            "attachment resend was not held for the structured live gate");

        var workTurn = attachmentTurn with
        {
            HasToolActivity = true,
            HasCompleteItemEvidence = true
        };
        var work = AutomaticRecoveryFreshFailureObserver.Evaluate(
            baseline,
            fixture.Event,
            fixture.Thread,
            workTurn,
            attachmentLocal with { Turn = attachmentLocal.Turn with { HasToolActivity = true } });
        Ensure(
            work.IsCandidate && work.Decision?.Action == RecoveryActionKind.SendContinue,
            "attachment-bearing work failure was incorrectly blocked instead of using continue");
    }

    private static void TestEvidenceWriter()
    {
        var testDataRoot = Environment.GetEnvironmentVariable(TestDataRootEnvironmentVariable);
        Ensure(
            !string.IsNullOrWhiteSpace(testDataRoot),
            TestDataRootEnvironmentVariable + " is required");
        var root = Path.Combine(
            Path.GetFullPath(testDataRoot!),
            "fresh-failure-observer-evidence",
            Guid.NewGuid().ToString("D"));
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(root)!);
            AutomaticRecoveryFreshFailureObserver.CreateProtectedDirectory(root);
            using (var writer = new AutomaticRecoveryFreshFailureObserverEvidenceWriter(root))
            {
                writer.Append(new AutomaticRecoveryFreshFailureObserverLogRecord(
                    1,
                    1,
                    "terminalSeen",
                    DateTimeOffset.UtcNow,
                    "019fb89b-9db1-7d70-9225-091ec086f06e",
                    TaskRef: "task-AAAA",
                    TurnRef: "turn-BBBB",
                    Code: "error",
                    Action: null,
                    HasAttachments: false,
                    RealSend: false));
                Ensure(writer.RecordCount == 1, "evidence record count was not tracked");
                Ensure(writer.BytesWritten <= AutomaticRecoveryFreshFailureObserverEvidenceWriter.MaximumBytes,
                    "evidence byte bound was not enforced");
            }

            var line = File.ReadAllText(Path.Combine(root, "fresh-failure-observer.jsonl"));
            using var document = JsonDocument.Parse(line);
            var json = document.RootElement.GetRawText();
            Ensure(!json.Contains("sourceFile", StringComparison.OrdinalIgnoreCase), "source path leaked into evidence");
            Ensure(!json.Contains("errorMessage", StringComparison.OrdinalIgnoreCase), "provider error text field leaked");
            Ensure(!json.Contains("userText", StringComparison.OrdinalIgnoreCase), "prompt field leaked");
            Ensure(!json.Contains("rawUserInput", StringComparison.OrdinalIgnoreCase), "raw input field leaked");
            Ensure(line.EndsWith('\n'), "evidence was not JSONL terminated");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void TestSourceContract()
    {
        var sourceRoot = FindSourceRoot();
        var observer = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Tests",
            "AutomaticRecoveryFreshFailureObserver.cs"));
        var program = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Tests",
            "Program.cs"));
        var createDataDirectory = observer.IndexOf(
            "CreateProtectedDirectory(options.DataDirectory)",
            StringComparison.Ordinal);
        var createRuntimeDirectory = observer.IndexOf(
            "CreateProtectedDirectory(runtimeDirectory)",
            StringComparison.Ordinal);
        var runCore = observer.IndexOf(
            "result = await RunCoreAsync(options, runtimeDirectory)",
            StringComparison.Ordinal);
        Ensure(
            observer.Contains("LocalConversationEventWatcher", StringComparison.Ordinal) &&
            observer.Contains("LocalConversationHistoryReader", StringComparison.Ordinal) &&
            observer.Contains("ReadThreadForRecoveryAsync", StringComparison.Ordinal) &&
            observer.Contains("ReadLatestTurnWithFullItemsAsync", StringComparison.Ordinal) &&
            observer.Contains("RecoveryService.ValidateLatestTurn", StringComparison.Ordinal) &&
            observer.Contains("RecoveryService.ValidateTargetThreadEligibility", StringComparison.Ordinal) &&
            observer.Contains("new RecoveryClassifier", StringComparison.Ordinal) &&
            observer.Contains("new GuardianLog(runtimeDirectory)", StringComparison.Ordinal) &&
            observer.Contains("TryDeleteRuntimeDirectory", StringComparison.Ordinal) &&
            observer.Contains("FileOptions.WriteThrough", StringComparison.Ordinal) &&
            observer.Contains("MaximumBytes = 512 * 1024", StringComparison.Ordinal) &&
            createDataDirectory >= 0 &&
            createRuntimeDirectory > createDataDirectory &&
            runCore > createRuntimeDirectory &&
            !observer.Contains("Directory.CreateDirectory(options.DataDirectory)", StringComparison.Ordinal) &&
            !observer.Contains("ProtectDirectoryAcl(", StringComparison.Ordinal) &&
            !observer.Contains("new GuardianLog(options.DataDirectory)", StringComparison.Ordinal) &&
            !observer.Contains("DesktopIpcClient", StringComparison.Ordinal) &&
            !observer.Contains("ExecuteAsync(", StringComparison.Ordinal) &&
            !observer.Contains("thread/rollback", StringComparison.Ordinal) &&
            !observer.Contains("SettingsService.SaveAsync", StringComparison.Ordinal) &&
            !observer.Contains("RecoveryOperationJournal", StringComparison.Ordinal) &&
            !observer.Contains("CodexCdp", StringComparison.Ordinal) &&
            !observer.Contains("HookPayload", StringComparison.Ordinal),
            "fresh-failure observer escaped its read-only tests-only boundary");
        var dispatch = program.IndexOf(
            "AutomaticRecoveryFreshFailureObserver.IsRequested(args)",
            StringComparison.Ordinal);
        var matrix = program.IndexOf("var failures = new List<string>();", StringComparison.Ordinal);
        Ensure(dispatch >= 0 && matrix > dispatch, "observer CLI dispatch was placed after the test matrix");
    }

    private static void TestEvidenceAcl()
    {
        var testDataRoot = Environment.GetEnvironmentVariable(TestDataRootEnvironmentVariable);
        Ensure(
            !string.IsNullOrWhiteSpace(testDataRoot),
            TestDataRootEnvironmentVariable + " is required");
        var root = Path.Combine(
            Path.GetFullPath(testDataRoot!),
            "fresh-failure-observer-acl",
            Guid.NewGuid().ToString("D"));
        Directory.CreateDirectory(Path.GetDirectoryName(root)!);
        try
        {
            AutomaticRecoveryFreshFailureObserver.CreateProtectedDirectory(root);
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            var currentUser = identity.User ??
                throw new UnauthorizedAccessException("Current user SID is unavailable.");
            var expected = new HashSet<string>(StringComparer.Ordinal)
            {
                currentUser.Value,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value
            };
            var security = FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(root),
                AccessControlSections.Access | AccessControlSections.Owner);
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier ??
                throw new UnauthorizedAccessException("Observer evidence owner SID is invalid.");
            var rules = security
                .GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToArray();
            var actual = rules
                .Select(rule =>
                    (rule.IdentityReference as SecurityIdentifier ??
                        throw new UnauthorizedAccessException("Observer evidence rule SID is invalid.")).Value)
                .ToHashSet(StringComparer.Ordinal);
            Ensure(security.AreAccessRulesProtected, "observer evidence ACL still inherited parent grants");
            Ensure(owner.Value == currentUser.Value, "observer evidence owner changed");
            Ensure(expected.SetEquals(actual), "observer evidence ACL retained an unexpected principal");
            Ensure(
                rules.All(rule =>
                    rule.AccessControlType == AccessControlType.Allow &&
                    (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl),
                "observer evidence ACL did not grant exact full control");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static (ThreadSummary Thread,
        TurnSnapshot AppServerTurn,
        LocalConversationTerminalEvent LocalTerminal,
        LocalConversationTerminalDetectedEventArgs Event) CreateFixture(
        DateTimeOffset baseline)
    {
        var threadId = "019fb89b-9db1-7d70-9225-091ec086f06e";
        var turnId = "019fb89b-9db1-7d70-9225-091ec086f06f";
        var sourceFile = @"D:\sessions\rollout-019fb89b-9db1-7d70-9225-091ec086f06e.jsonl";
        var thread = new ThreadSummary(
            threadId,
            "fixture",
            "fixture",
            @"D:\work",
            "cli",
            1,
            2,
            false,
            false,
            "idle",
            false);
        var turn = new TurnSnapshot(
            turnId,
            "failed",
            "server failed",
            "internal_server_error",
            500,
            "retry this",
            false,
            false,
            false,
            "fingerprint",
            1,
            2,
            RawUserInputJson: "{\"type\":\"text\"}",
            HasConfirmedLocalTerminal: false,
            UserMessageClientIds: ["019fb89b-9db1-7d70-9225-091ec086f060"],
            HasUserMessage: true,
            HasFinalAssistantOutput: false,
            HasCommentaryOutput: false,
            HasReasoningOutput: false,
            HasToolActivity: false,
            HasAmbiguousActivity: false,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);
        var localTurn = turn with { HasConfirmedLocalTerminal = true };
        var localTerminal = new LocalConversationTerminalEvent(
            threadId,
            turnId,
            sourceFile,
            42,
            baseline.AddSeconds(1),
            localTurn);
        var watcherEvent = new LocalConversationTerminalDetectedEventArgs(
            threadId,
            turnId,
            hasError: true,
            sourceFile,
            baseline.AddSeconds(1),
            isSubAgent: false);
        return (thread, turn, localTerminal, watcherEvent);
    }

    private static string FindSourceRoot()
    {
        var current = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "work", "CodexGuardian.Tests", "Program.cs")))
            {
                return Path.Combine(current.FullName, "work");
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("The Ceasy source root could not be located.");
    }

    private static void RunCase(string name, Action test, Action<bool, string> assert)
    {
        try
        {
            test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name);
        }
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch
        {
            return true;
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
