using CodexGuardian.Localization;
using System.Collections.Concurrent;
using System.Text.Json.Serialization;

namespace CodexGuardian.Models;

public enum SettingsReadStatus
{
    Missing,
    Legacy,
    Healthy,
    RecoveredFromPrevious,
    ConservativeDefaults
}

public enum RecoveryCountingMode
{
    SharedIncidentBudget,
    PerFailedTurn,
    OriginalFailedTurnOnly
}

public static class RecoveryAttemptPolicyLimits
{
    public const int DefaultMaximumAttempts = 500;

    public const int MaximumFiniteAttempts = 1_000_000;
}

public sealed class AppSettings
{
    public const int CurrentConfigurationVersion = 9;

    public const int DefaultKeepAliveIntervalMinutes = 5;

    public const int MinimumKeepAliveIntervalMinutes = 1;

    // A slot is not held by sending faster; it is held by not going quiet. An hour is well past any
    // plausible idle window, so anything longer would be indistinguishable from off.
    public const int MaximumKeepAliveIntervalMinutes = 60;

    // One phrasing per line; a heartbeat picks a line, avoiding the one before it.
    //
    // Three properties matter, in this order. First, nothing may name the mechanism: the previous default
    // opened with "保活检测", which any content audit matches on the first pass - no amount of timing care
    // survives a message that announces itself. Second, no two consecutive sends may be byte-identical,
    // which is what the rotation is for. Third, each line has to read like something a person actually
    // typed mid-task, which rules out both bare punctuation and instructions like "reply with only the
    // digit 1" - a real user does not talk that way, and the instruction stays in the transcript and is
    // carried by every later turn.
    //
    // A fixed pool of natural phrasings — even pause-semantic ones that do not trigger tool use — is
    // still a fixed pool: rotate through it enough times and the pattern becomes "this user says 先别动
    // a lot", which is a statistical signature one layer above byte-hash matching. The only way to break
    // the ceiling is generative content: questions with answers that vary every time.
    //
    // Simple arithmetic problems ("17 + 34 = ?" / "82 - 19 = ?" / "6 × 8 = ?") never repeat if the
    // operands are random, cost a handful of input tokens, return one or two output tokens (the answer),
    // never trigger tool use (unambiguous and self-contained), and are hard to flag as automation — to
    // recognize the pattern an auditor has to notice that arithmetic appears periodically, then prove the
    // problems are machine-generated rather than a user who happens to use their agent as a calculator.
    // That is orders of magnitude harder than matching a fixed string.
    //
    // The brevity instruction is inlined in the question ("只写答案" / "only the answer") so it does not
    // stay in context and does not read as machinery by itself — a person asking a quick arithmetic
    // question reasonably says "just the number". The default below is a template: the engine replaces
    // {0}, {1}, {2} with random operands and the operator at send time.
    //
    // Migration note: users who edited the field keep their custom wording. This default only applies to
    // new installs and to anyone still on a retired shipped default (the instruction-style "保活检测…" or
    // the acknowledgement-set "好，我先看看\n…" or the pause-set "先别动\n…"). The point is to retire
    // defaults we shipped that would trigger detection, not to overwrite someone's choice.
    //
    // Empty is the default and means "generate". A non-empty field is still honoured as a literal pool,
    // one phrasing per line, so a user who wants exact control over what gets sent can have it - the
    // generator is the default, not the only option.
    public const string DefaultKeepAliveMessage = "";

    /// <summary>
    /// The default this replaced, kept only so an existing settings file can be migrated off it.
    /// </summary>
    /// <remarks>
    /// Changing the default does nothing for anyone who already ran the previous build: the default only
    /// applies when the field is missing or blank, so the old wording stays on disk and keeps being sent.
    /// That wording named the mechanism outright and never varied, which is the whole reason it was
    /// replaced, so leaving it in place would make the change cosmetic.
    ///
    /// Matched byte-for-byte and only against this one string. A user who edited the field keeps whatever
    /// they typed - the point is to retire a default we shipped, not to overwrite someone's choice.
    /// </remarks>
    public const string RetiredKeepAliveMessage = "保活检测，只回复数字 1，不要任何其他内容。";

    /// <summary>
    /// The acknowledgement-semantic default shipped in AR58 before the pause-semantic correction.
    /// </summary>
    /// <remarks>
    /// This set read naturally but carried an approval-to-proceed semantic in an agentic context: "好，我先看看"
    /// can be understood as permission to continue reading files, which defeats the point of a heartbeat.
    /// Retired in favor of pause-semantic phrasings that explicitly mean "do not act yet".
    /// </remarks>
    public const string RetiredAcknowledgementMessage =
        "好，我先看看\n" +
        "收到\n" +
        "嗯，我这边再确认一下\n" +
        "行，稍等\n" +
        "明白了\n" +
        "我先记下来";

    /// <summary>
    /// The pause-semantic default shipped in AR58d before the arithmetic-question correction.
    /// </summary>
    /// <remarks>
    /// This set avoided the agentic-trigger problem of acknowledgements ("好，我先看看" reads as approval
    /// to proceed), but it is still a fixed pool: rotate through it enough times and the statistical
    /// signature is "this user says 先别动 a lot". Retired in favor of generative arithmetic questions
    /// that never repeat.
    /// </remarks>
    public const string RetiredPauseMessage =
        "先别动\n" +
        "暂停一下\n" +
        "等等再说\n" +
        "不着急\n" +
        "稍后继续\n" +
        "还在看";

    public int ConfigurationVersion { get; set; } = CurrentConfigurationVersion;

    public string UiLanguage { get; set; } = UiLanguages.SimplifiedChinese;

    public string UiTheme { get; set; } = UiThemes.Dark;

    public bool MonitoringEnabled { get; set; } = true;

    public bool MonitorOnly { get; set; } = true;

    // Recovery authorization is intentionally a separate positive capability. Missing or
    // migrated settings remain disabled until the user explicitly enables it.
    public bool AutomaticRecoveryEnabled { get; set; }

    public bool GlobalProtectionEnabled { get; set; }

    public AttachmentLimitSettings AttachmentLimits { get; set; } = new();

    public int BaseBackoffSeconds { get; set; } = 20;

    public int MaximumBackoffSeconds { get; set; } = 300;

    // The legacy name is retained as a read/write compatibility field for older settings
    // snapshots. New persistence uses MaximumRecoveryAttempts and UnlimitedRecoveryAttempts.
    public int MaximumAttemptsPerFailure { get; set; } =
        RecoveryAttemptPolicyLimits.DefaultMaximumAttempts;

    public int MaximumRecoveryAttempts { get; set; } =
        RecoveryAttemptPolicyLimits.DefaultMaximumAttempts;

    public bool UnlimitedRecoveryAttempts { get; set; }

    public RecoveryCountingMode RecoveryCountingMode { get; set; } = RecoveryCountingMode.PerFailedTurn;

    public string ContinueMessage { get; set; } = "continue";

    public int RecentThreadLimit { get; set; } = 30;

    public int RecentThreadLookbackDays { get; set; } = 14;

    public bool IncludeSubAgents { get; set; }

    public bool ProtectNewThreadsByDefault { get; set; }

    public bool MinimizeToTray { get; set; } = true;

    public bool StartWithWindows { get; set; }

    public ConcurrentDictionary<string, bool> ThreadEnabled { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public ConcurrentDictionary<string, bool> ThreadProtectionEnabled { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public List<string> ConversationOrder { get; set; } = [];

    public bool UseManualConversationOrder { get; set; }

    public List<string> PinnedConversationIds { get; set; } = [];

    public ConcurrentDictionary<string, ThreadFollowUpSettings> ThreadFollowUps { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    // Keep-alive holds a slot that was already won. On a contended endpoint the expensive part is
    // getting in — repeated 429s until one turn lands — so once a conversation answers normally, a
    // small periodic turn keeps that connection warm instead of letting it fall idle and having to
    // fight back in. It is a positive capability like recovery: off until asked for.
    public bool KeepAliveEnabled { get; set; }

    // The sentinel watches every conversation for the one signal that matters on a contended endpoint:
    // any conversation answering normally proves the way in is open right now. It does not hold the
    // conversation that produced the signal — that one is the user's work and a heartbeat would land in
    // the middle of it. It holds one designated conversation instead, so the slot survives after the
    // work conversation goes quiet.
    public bool KeepAliveSentinelEnabled { get; set; }

    // Where the sentinel sends. An existing conversation the user nominates, because the native IPC
    // channel can only start a turn in a conversation that already exists - it validates the id as a
    // UUID - and opening a new one would mean driving Desktop's UI, which is out of bounds. Empty means
    // no destination has been chosen, and the sentinel stays idle rather than guessing one.
    public string KeepAliveSentinelThreadId { get; set; } = string.Empty;

    public int KeepAliveIntervalMinutes { get; set; } = DefaultKeepAliveIntervalMinutes;

    // One phrasing per line. A single line still works and simply never varies.
    public string KeepAliveMessage { get; set; } = DefaultKeepAliveMessage;

    // Per-conversation holds, independent of the sentinel. Presence with true means "hold this one";
    // there is no third "follow the global rule" state, because the global switch now has its own
    // destination and no longer decides anything about these conversations.
    public ConcurrentDictionary<string, bool> KeepAliveThreadEnabled { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    // Sleep suspends the whole machine, which stops monitoring, recovery and keep-alive alike — a
    // conversation waiting on a retry simply sits there until the user comes back. This asks Windows to
    // keep the system awake while monitoring is on. It deliberately does not keep the display awake:
    // holding the screen on all night is a different, more intrusive request than keeping the work
    // running, and the user asked for the latter.
    public bool PreventSystemSleep { get; set; }

    // The one outbound request this app makes: a GET to the GitHub release API, at most once a day, asking
    // nothing but "what is the newest tag". On by default because a guardian that silently runs an old build
    // is the failure this is meant to prevent, and off is one switch away. A missing key in an older settings
    // file lands on this initialiser rather than on false, so upgrading does not quietly disable it.
    public bool UpdateCheckEnabled { get; set; } = true;

    [JsonIgnore]
    public SettingsReadStatus ReadStatus { get; internal set; }

    [JsonIgnore]
    public long SettingsGeneration { get; internal set; }

    [JsonIgnore]
    public long PreviousSettingsGeneration { get; internal set; }
}

public static class UiThemes
{
    public const string Light = "light";

    public const string Dark = "dark";

    public static string Normalize(string? value) =>
        string.Equals(value, Dark, StringComparison.OrdinalIgnoreCase)
            ? Dark
            : Light;
}
