using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

/// <summary>
/// Covers the one keep-alive failure that is invisible from the UI: after a restart the hold looks
/// armed on the page while nothing is ever sent again.
/// </summary>
/// <remarks>
/// The stall needs two things at once, so a test that only checks one of them passes while the bug is
/// live. An unanswered heartbeat leaves a turn with a user message and no final assistant output, which
/// reads as unsettled work that recovery owns — so eligibility falls back to "is this turn one of ours",
/// and the only record of that used to live in memory. Restart the process and the answer became no
/// forever.
/// </remarks>
internal static class KeepAliveScheduleOfflineTests
{
    private const string ThreadId = "01a05db2-cdde-71e2-93a2-3d2092d4a33c";

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "keep-alive carries its schedule and its own wording across a restart",
            TestScheduleSurvivesRestartAsync,
            assert);
        await RunCaseAsync(
            "an unanswered heartbeat is still due after a restart",
            TestUnansweredHeartbeatStaysDueAsync,
            assert);
        await RunCaseAsync(
            "a healthy reply arms the sentinel target for its scheduled message",
            TestHealthyReplyArmsSentinelAsync,
            assert);
        await RunCaseAsync(
            "a restarted coordinator claims only the wording it sent to that conversation",
            TestForeignTextKeepsRecoveryAsync,
            assert);
        await RunCaseAsync(
            "forgetting a conversation drops it from the persisted schedule",
            TestForgetClearsPersistedStateAsync,
            assert);
        await RunCaseAsync(
            "a configured wording pool still avoids the phrasing it used last, across a restart",
            TestConfiguredPoolRotatesAsync,
            assert);
    }

    private static Task TestScheduleSurvivesRestartAsync()
    {
        var root = CreateDataRoot("keepalive-restart");
        var sentAt = DateTimeOffset.UtcNow.AddMinutes(-4);
        string message;
        using (var log = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(log);
            message = coordinator.SelectMessage(ThreadId, string.Empty);
            Ensure(
                message.Contains("= ?", StringComparison.Ordinal),
                "the default wording is a generated arithmetic question");
            coordinator.NoteSent(ThreadId, sentAt, Guid.NewGuid().ToString("D"), message);
        }

        Ensure(
            File.Exists(Path.Combine(root, "keepalive-state.json")),
            "the schedule is persisted beside the log");

        using (var restarted = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(restarted);
            Ensure(
                coordinator.LastSentAt(ThreadId) is { } recovered &&
                (recovered - sentAt).Duration() < TimeSpan.FromSeconds(1),
                "the last send time survives the restart");

            // Client ids are what the running process matches on, but a turn that drew no reply comes
            // back from the observation surface without them. The wording is the fallback that has to
            // carry this case.
            Ensure(
                coordinator.IsKeepAliveTurn(ThreadId, CreateUnansweredTurn(message)),
                "a restarted coordinator still recognises its own unanswered heartbeat");
        }

        return Task.CompletedTask;
    }

    private static Task TestHealthyReplyArmsSentinelAsync()
    {
        var root = CreateDataRoot("keepalive-sentinel");
        using var log = new GuardianLog(root);
        var coordinator = new KeepAliveCoordinator(log);
        var state = CreateState(CreateCompletedTurn());
        var policy = CreateSentinelPolicy();
        var now = DateTimeOffset.UtcNow;

        Ensure(
            KeepAliveCoordinator.IsSettled(state),
            "the fixture represents a reliable final reply");
        Ensure(
            GuardianEngine.IsHealthyKeepAliveSignal(state),
            "a settled live conversation is a keep-alive health signal");
        Ensure(
            coordinator.SelectDue([state], policy, now).Count == 0,
            "the sentinel remains idle until a healthy reply is observed");

        coordinator.NoteHealthyConversation(ThreadId, now.AddMinutes(-1));
        var due = coordinator.SelectDue([state], policy, now);
        Ensure(
            due.Count == 1 && string.Equals(due[0].ThreadId, ThreadId, StringComparison.Ordinal),
            "the sentinel target becomes due after the healthy reply arms it");

        Ensure(
            !GuardianEngine.IsHealthyKeepAliveSignal(state with { IsRunningNow = true }),
            "a running conversation cannot arm the sentinel");
        Ensure(
            !GuardianEngine.IsHealthyKeepAliveSignal(state with
            {
                Health = TaskHealth.NeedsAttention,
                Decision = RecoveryDecision.None(TaskHealth.NeedsAttention, "failed")
            }),
            "a failed conversation cannot arm the sentinel");
        Ensure(
            !GuardianEngine.IsHealthyKeepAliveSignal(state with
            {
                Thread = state.Thread with { IsArchived = true }
            }),
            "an archived conversation cannot arm the sentinel");
        Ensure(
            !GuardianEngine.IsHealthyKeepAliveSignal(state with { Turn = CreateUnansweredTurn("pending") }),
            "a conversation without reliable final output cannot arm the sentinel");
        return Task.CompletedTask;
    }

    private static Task TestUnansweredHeartbeatStaysDueAsync()
    {
        var root = CreateDataRoot("keepalive-due");
        var sentAt = DateTimeOffset.UtcNow.AddMinutes(-9);
        string message;
        using (var log = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(log);
            message = coordinator.SelectMessage(ThreadId, string.Empty);
            coordinator.NoteSent(ThreadId, sentAt, Guid.NewGuid().ToString("D"), message);
        }

        using (var restarted = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(restarted);
            var state = CreateState(CreateUnansweredTurn(message));
            Ensure(
                !KeepAliveCoordinator.IsSettled(state),
                "an unanswered heartbeat reads as unsettled, which is what forced the fallback");

            var due = coordinator.SelectDue([state], CreatePolicy(), DateTimeOffset.UtcNow);
            Ensure(
                due.Count == 1 && string.Equals(due[0].ThreadId, ThreadId, StringComparison.Ordinal),
                "the held conversation is due again rather than stalled forever");
        }

        return Task.CompletedTask;
    }

    private static Task TestForeignTextKeepsRecoveryAsync()
    {
        var root = CreateDataRoot("keepalive-foreign");
        using (var log = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(log);
            var message = coordinator.SelectMessage(ThreadId, string.Empty);
            coordinator.NoteSent(ThreadId, DateTimeOffset.UtcNow.AddMinutes(-6), null, message);
        }

        using (var restarted = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(restarted);
            Ensure(
                !coordinator.IsKeepAliveTurn(ThreadId, CreateUnansweredTurn("7 + 8 = ?")),
                "a user's own arithmetic question keeps recovery");
            Ensure(
                !coordinator.IsKeepAliveTurn(ThreadId, CreateUnansweredTurn(string.Empty)),
                "an empty turn is never claimed as a heartbeat");
            Ensure(
                !coordinator.IsKeepAliveTurn("other-thread", CreateUnansweredTurn("7 + 8 = ?")),
                "a conversation that was never held is never claimed");
        }

        return Task.CompletedTask;
    }

    private static Task TestForgetClearsPersistedStateAsync()
    {
        var root = CreateDataRoot("keepalive-forget");
        using (var log = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(log);
            var message = coordinator.SelectMessage(ThreadId, string.Empty);
            coordinator.NoteSent(ThreadId, DateTimeOffset.UtcNow.AddMinutes(-3), null, message);
            coordinator.Forget(ThreadId);
        }

        using (var restarted = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(restarted);
            Ensure(
                coordinator.LastSentAt(ThreadId) is null,
                "a forgotten conversation does not come back from disk");
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// The wording is recorded where a heartbeat goes out rather than where it is chosen, so this pins
    /// the rotation that reads the same record: a two-line pool has to alternate, and it has to keep
    /// alternating across a restart now that the record comes off disk.
    /// </summary>
    private static Task TestConfiguredPoolRotatesAsync()
    {
        const string pool = "早上好\n忙吗";
        var root = CreateDataRoot("keepalive-pool");
        string first;
        string second;
        using (var log = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(log);
            first = coordinator.SelectMessage(ThreadId, pool);
            coordinator.NoteSent(ThreadId, DateTimeOffset.UtcNow.AddMinutes(-10), null, first);
            second = coordinator.SelectMessage(ThreadId, pool);
            Ensure(
                !string.Equals(first, second, StringComparison.Ordinal),
                "the second heartbeat uses the other phrasing");
            coordinator.NoteSent(ThreadId, DateTimeOffset.UtcNow.AddMinutes(-5), null, second);
        }

        using (var restarted = new GuardianLog(root))
        {
            var coordinator = new KeepAliveCoordinator(restarted);
            Ensure(
                string.Equals(coordinator.SelectMessage(ThreadId, pool), first, StringComparison.Ordinal),
                "a restarted coordinator still knows which phrasing it used last");
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// A heartbeat turn that completed without a reply: a user message, no assistant output, and no
    /// client ids — the exact shape observed on the sentinel destination on 2026-09-02.
    /// </summary>
    private static TurnSnapshot CreateUnansweredTurn(string userText) =>
        new(
            "turn-" + Guid.NewGuid().ToString("N")[..8],
            "completed",
            null,
            null,
            null,
            userText,
            HasAttachments: false,
            HasAssistantOutput: false,
            HasWorkOutput: false,
            OutputFingerprint: string.Empty,
            StartedAt: null,
            CompletedAt: null,
            HasUserMessage: true,
            HasFinalAssistantOutput: false,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static TurnSnapshot CreateCompletedTurn() =>
        new(
            "turn-" + Guid.NewGuid().ToString("N")[..8],
            "completed",
            null,
            null,
            null,
            "original request",
            HasAttachments: false,
            HasAssistantOutput: true,
            HasWorkOutput: true,
            OutputFingerprint: "complete",
            StartedAt: 1,
            CompletedAt: 2,
            HasUserMessage: true,
            HasFinalAssistantOutput: true,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static GuardianTaskState CreateState(TurnSnapshot turn) =>
        new(
            new ThreadSummary(
                ThreadId,
                "keep-alive destination",
                string.Empty,
                @"D:\Workspace",
                "appServer",
                1,
                2,
                false,
                false),
            turn,
            RecoveryDecision.None(TaskHealth.Healthy, "idle"),
            IsEnabled: true,
            TaskHealth.Healthy,
            StatusText: "idle",
            LastEvent: "idle",
            Attempts: 0,
            NextAttemptAt: null);

    private static KeepAlivePolicySnapshot CreatePolicy() =>
        new(
            Enabled: true,
            SentinelEnabled: false,
            SentinelThreadId: string.Empty,
            Interval: TimeSpan.FromMinutes(5),
            Message: string.Empty,
            ThreadEnabled: new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
            {
                [ThreadId] = true
            });

    private static KeepAlivePolicySnapshot CreateSentinelPolicy() =>
        new(
            Enabled: true,
            SentinelEnabled: true,
            SentinelThreadId: ThreadId,
            Interval: TimeSpan.FromMinutes(5),
            Message: "configured keep-alive message",
            ThreadEnabled: new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase));

    private static string CreateDataRoot(string label)
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        var root = Path.GetFullPath(Path.Combine(parent, label + "-" + Guid.NewGuid().ToString("N")));
        Ensure(
            root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase),
            "keep-alive schedule tests use D-drive data");
        Directory.CreateDirectory(root);
        return root;
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name} - {exception.Message}");
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
