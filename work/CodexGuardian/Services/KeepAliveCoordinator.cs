using CodexGuardian.Models;
using System.Collections.Concurrent;
using System.Text.Json;

namespace CodexGuardian.Services;

/// <summary>
/// Decides which conversations are due for a keep-alive turn.
/// </summary>
/// <remarks>
/// On a contended endpoint the expensive part is getting in: turns fail with 429 until one lands. Once
/// something answers normally the way in is open, and letting it fall idle means fighting back in from
/// scratch. A small periodic turn holds the slot.
///
/// Two independent ways to hold one:
///
/// The sentinel is global. It watches every conversation for a normal reply — that reply is the proof
/// the way in is open — and then sends into one conversation the user nominates. It deliberately does
/// not send into the conversation that produced the signal: that one is the user's live work, and a
/// heartbeat landing in it would be noise in the transcript the user is reading.
///
/// A per-conversation hold is explicit and immediate. Switching one on means "hold this one", and the
/// first turn goes on the next pass rather than an interval later — the user flipped it because they
/// want the slot held now, and a switch that appears to do nothing for five minutes reads as broken.
///
/// The hard constraint on both is that keep-alive must never touch a conversation that has a failed turn
/// waiting on recovery. Codex refuses to edit anything but the last message, so inserting a keep-alive
/// turn ahead of a failed one makes the in-place retry permanently impossible — the exact failure mode
/// that stranded four threads before it was fixed. A conversation that is still fighting its way in
/// does not need holding anyway.
/// </remarks>
public sealed class KeepAliveCoordinator
{
    private readonly GuardianLog _log;

    /// <summary>
    /// Where the schedule survives a restart, or null when it cannot be resolved.
    /// </summary>
    /// <remarks>
    /// Without this the coordinator forgot every heartbeat it had ever sent the moment the process
    /// ended, and the consequence was not a missed beat but a permanent stall. A heartbeat that draws
    /// no reply leaves a turn with a user message and no final assistant output, which
    /// <see cref="IsSettled"/> reads as unsettled work. The only thing that told the two apart was the
    /// in-memory client id, so after a restart the conversation was ineligible forever: keep-alive
    /// refused to send into it, and the row went on showing as held while nothing was sent. Observed
    /// on the sentinel destination after three heartbeats on 2026-09-02, the third of which completed
    /// without a reply.
    ///
    /// Deliberately its own small file rather than a section in settings.json: it is machine state
    /// written on every send, and settings carry a checksum and a generation counter meant for
    /// user-visible configuration.
    /// </remarks>
    private readonly string? _statePath;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastSentAt =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The wording used last time, per conversation, so the next one can differ.</summary>
    private readonly ConcurrentDictionary<string, string> _lastMessage =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The client message ids this coordinator sent, so recovery can tell its own heartbeats apart
    /// from the user's work.
    /// </summary>
    /// <remarks>
    /// A heartbeat that goes unanswered must not be resent. Recovery reads an unanswered user
    /// message as a failed turn and retries it in place, which turned one 5-minute heartbeat into
    /// nine identical sends a minute apart — the exact repetition signature the generated wording
    /// exists to avoid. Matching on the client id rather than the text keeps a user who happens to
    /// type an arithmetic question from losing recovery.
    ///
    /// Only the most recent id per conversation is kept: one heartbeat is outstanding at a time, and
    /// recovery only ever classifies the latest turn.
    /// </remarks>
    private readonly ConcurrentDictionary<string, string> _lastClientMessageId =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The most recent heartbeats actually sent, newest first, across every conversation.
    /// </summary>
    /// <remarks>
    /// The per-conversation maps above answer "when was this one last touched", which is what
    /// scheduling needs. They cannot answer the question the user actually asks — "is this thing
    /// sending anything, and what" — because a heartbeat leaves no trace anywhere the user can see:
    /// it lands in the conversation as an ordinary message among the real work, and the schedule that
    /// produced it is invisible. So the wording is kept here as it goes out.
    ///
    /// Bounded and in memory only. This is a window onto live behaviour, not a record to audit later,
    /// and the ledger already persists what recovery does.
    /// </remarks>
    private readonly List<KeepAliveSendRecord> _recentSends = [];

    private readonly object _recentSendsGate = new();

    private const int RecentSendCapacity = 12;

    private readonly object _stateGate = new();

    private const int StateSchemaVersion = 1;

    /// <summary>
    /// How many conversations the state file keeps, most recently sent first.
    /// </summary>
    /// <remarks>
    /// Bounded because nothing prunes conversations the user stopped holding: entries would accumulate
    /// for every conversation ever held. Far more than the number a person holds at once, so the cap
    /// never costs a live hold its schedule.
    /// </remarks>
    private const int PersistedThreadCapacity = 64;

    /// <remarks>
    /// Unknown members are tolerated rather than rejected — the opposite of the follow-up journal, which
    /// is a ledger whose exact contents matter. Here a member from a newer build is worth ignoring so an
    /// older one keeps its restart guarantee instead of discarding the whole file.
    /// </remarks>
    private static readonly JsonSerializerOptions StateJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false
    };

    private DateTimeOffset? _lastHealthyReplyAt;

    public KeepAliveCoordinator(GuardianLog log)
    {
        _log = log;
        try
        {
            _statePath = Path.Combine(log.DataDirectory, "keepalive-state.json");
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException)
        {
            // A coordinator that cannot find a place to write still schedules correctly for as long as
            // the process lives; losing the file only costs the restart guarantee.
            _statePath = null;
        }

        LoadState();
    }

    /// <summary>
    /// When any conversation was last seen to have answered normally, or null if none has yet.
    /// </summary>
    /// <remarks>
    /// This is the sentinel's trigger. It is a single timestamp rather than a set of enrolled
    /// conversations because the signal is about the endpoint, not about any one conversation: the
    /// question the sentinel answers is "is the way in open", and one normal reply anywhere settles it.
    /// </remarks>
    public DateTimeOffset? LastHealthyReplyAt => _lastHealthyReplyAt;

    public DateTimeOffset? LastSentAt(string threadId) =>
        _lastSentAt.TryGetValue(threadId, out var sentAt) ? sentAt : null;

    public void Forget(string threadId)
    {
        _lastSentAt.TryRemove(threadId, out _);
        _lastMessage.TryRemove(threadId, out _);
        _lastClientMessageId.TryRemove(threadId, out _);
        SaveState();
    }

    public void Reset()
    {
        _lastSentAt.Clear();
        _lastMessage.Clear();
        _lastClientMessageId.Clear();
        _lastHealthyReplyAt = null;
        lock (_recentSendsGate)
        {
            _recentSends.Clear();
        }

        SaveState();
    }

    /// <summary>
    /// Whether this turn is a heartbeat this coordinator sent, which recovery must leave alone.
    /// </summary>
    /// <remarks>
    /// The client id is the primary match. The wording is a fallback for the case the id cannot cover:
    /// after a restart the id of an outstanding heartbeat is known from the state file, but the turn
    /// snapshot exposes client ids only for turns the observation surface still carries them for, and a
    /// heartbeat that drew no reply is exactly the kind of turn that comes back without them.
    ///
    /// The fallback compares against the one string this coordinator last sent to this specific
    /// conversation, not against a shape or a pattern. A user who happens to type an arithmetic
    /// question keeps recovery; they would have to type the previous heartbeat verbatim, into the same
    /// conversation, to lose it.
    /// </remarks>
    public bool IsKeepAliveTurn(string threadId, TurnSnapshot? turn)
    {
        if (turn is null)
        {
            return false;
        }

        if (_lastClientMessageId.TryGetValue(threadId, out var sentId) &&
            turn.UserMessageClientIds is { Count: > 0 } clientIds &&
            clientIds.Contains(sentId, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        return _lastMessage.TryGetValue(threadId, out var sentMessage) &&
               sentMessage.Length > 0 &&
               string.Equals(turn.UserText?.Trim(), sentMessage.Trim(), StringComparison.Ordinal);
    }


    /// <summary>
    /// Records that some conversation answered normally, which is what arms the sentinel.
    /// </summary>
    /// <returns>True the first time a reply is seen, so the caller can log the transition once.</returns>
    public bool NoteHealthyConversation(string threadId, DateTimeOffset seenAt)
    {
        if (string.IsNullOrWhiteSpace(threadId))
        {
            return false;
        }

        var wasArmed = _lastHealthyReplyAt is not null;
        _lastHealthyReplyAt = seenAt;
        if (wasArmed)
        {
            return false;
        }

        _log.Info("Keep-alive sentinel armed: a conversation answered normally.", threadId);
        return true;
    }

    public void NoteSent(
        string threadId,
        DateTimeOffset sentAt,
        string? clientMessageId = null,
        string? message = null)
    {
        _lastSentAt[threadId] = sentAt;
        if (!string.IsNullOrWhiteSpace(clientMessageId))
        {
            _lastClientMessageId[threadId] = clientMessageId;
        }

        if (!string.IsNullOrWhiteSpace(message))
        {
            // Recorded here rather than where the wording is chosen. Selection happens for a heartbeat
            // that is about to be attempted, but this map is read by IsKeepAliveTurn to recognise a turn
            // that already exists in the conversation, so it has to mean "what went out", not "what was
            // picked". The literal-pool rotation in SelectMessage reads the same value and is happy with
            // either meaning.
            _lastMessage[threadId] = message;

            lock (_recentSendsGate)
            {
                _recentSends.Insert(0, new KeepAliveSendRecord(threadId, message, sentAt));
                if (_recentSends.Count > RecentSendCapacity)
                {
                    _recentSends.RemoveRange(
                        RecentSendCapacity,
                        _recentSends.Count - RecentSendCapacity);
                }
            }
        }

        SaveState();
    }

    /// <summary>The heartbeats sent most recently, newest first.</summary>
    public IReadOnlyList<KeepAliveSendRecord> RecentSends()
    {
        lock (_recentSendsGate)
        {
            return [.. _recentSends];
        }
    }

    /// <summary>
    /// Picks the wording for one heartbeat: generates an arithmetic question when configured is empty,
    /// otherwise rotates through the configured set.
    /// </summary>
    /// <remarks>
    /// The configured message is one phrasing per line. Sending a byte-identical string on a schedule is
    /// the easiest automation signature there is to match — one hash, repeated — so the set is rotated.
    /// But a fixed pool is still a fixed pool: rotate through it enough times and the pattern is "this
    /// user says X a lot", which is a statistical signature. The only way to break the ceiling is
    /// generative content: questions with answers that vary every time.
    ///
    /// An empty configuration (the default) generates simple arithmetic: "{operand1} {operator} {operand2} = ?
    /// (只写答案)". The operands are 1-99, the operators are + - ×, the question never repeats, costs a handful
    /// of input tokens, returns 1-3 output tokens (the numeric answer), never triggers tool use (unambiguous
    /// and self-contained), and is hard to flag as automation — recognizing the pattern requires noticing
    /// arithmetic appears periodically and proving the problems are machine-generated rather than a user who
    /// uses their agent as a calculator.
    ///
    /// The operands are derived from (threadId, lastSentAt) via the same FNV-1a hash used for jitter, so the
    /// question is deterministic per heartbeat: the due-selection and wake-scheduling paths see the same
    /// question, and the log entry can be matched back to the sent turn. Random.Shared would give a different
    /// question on each call and break scheduling/logging coherence.
    ///
    /// A non-empty configuration is still honoured as a literal pool, one phrasing per line, rotated to avoid
    /// the previous one. A user who wants exact control over what gets sent keeps it — the generator is the
    /// default, not the only option.
    /// </remarks>
    public string SelectMessage(string threadId, string configured)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return GenerateArithmeticQuestion(threadId);
        }

        var options = SplitMessages(configured);
        if (options.Count <= 1)
        {
            return options.Count == 1 ? options[0] : configured.Trim();
        }

        var previous = _lastMessage.TryGetValue(threadId, out var last) ? last : null;
        var candidates = options.Count > 1 && previous is not null
            ? options.Where(option => !string.Equals(option, previous, StringComparison.Ordinal)).ToArray()
            : [.. options];
        var pool = candidates.Length > 0 ? candidates : [.. options];
        return pool[Random.Shared.Next(pool.Length)];
    }

    /// <summary>
    /// Generates a simple arithmetic question: "17 + 34 = ? (只写答案)".
    /// </summary>
    /// <remarks>
    /// Deterministic per (threadId, lastSentAt) so due-selection, wake-scheduling, sending, and logging all
    /// see the same question. The FNV-1a hash already computed for jitter is reused.
    /// </remarks>
    private string GenerateArithmeticQuestion(string threadId)
    {
        var lastSent = LastSentAt(threadId) ?? DateTimeOffset.MinValue;
        var hash = ComputeHash(threadId, lastSent);

        // Three independent values from one hash. A uint is 32 bits and C# masks the shift count to 5 bits,
        // so `hash >> 32` is a no-op — shifting alone cannot produce decorrelated values here. Each value
        // gets its own FNV-1a round with a distinct salt instead.
        var operatorSeed = Mix(hash, 0x01);
        var firstSeed = Mix(hash, 0x02);
        var secondSeed = Mix(hash, 0x03);

        // Three operators: + - ×. Division is omitted because it introduces fractions and the prompt would
        // need to specify rounding rules, which reads less natural.
        var operators = new[] { "+", "-", "×" };
        var op = operators[(int)(operatorSeed % 3)];

        // Operands 1-99 for + and -, 2-9 for × so the product stays trivial to compute mentally.
        var a = op == "×" ? 2 + (int)(firstSeed % 8) : 1 + (int)(firstSeed % 99);
        var b = op == "×" ? 2 + (int)(secondSeed % 8) : 1 + (int)(secondSeed % 99);

        // Subtraction stays non-negative: a negative answer is fine arithmetically but a person writing a
        // quick sum usually puts the larger number first.
        if (op == "-" && a < b)
        {
            (a, b) = (b, a);
        }

        // The brevity instruction is inlined ("只写答案") so it does not stay in context as a separate turn
        // and does not read as machinery — a person asking a quick arithmetic question reasonably says "just
        // the number".
        return $"{a} {op} {b} = ? (只写答案)";
    }

    /// <summary>
    /// FNV-1a hash over threadId and lastSentAt, reused by both Jitter and GenerateArithmeticQuestion.
    /// </summary>
    private static uint ComputeHash(string threadId, DateTimeOffset lastSentAt)
    {
        var hash = 2166136261u;
        foreach (var character in threadId)
        {
            hash = (hash ^ character) * 16777619u;
        }

        var ticks = (ulong)lastSentAt.UtcTicks;
        for (var shift = 0; shift < 64; shift += 8)
        {
            hash = (hash ^ (uint)((ticks >> shift) & 0xFF)) * 16777619u;
        }

        return hash;
    }

    /// <summary>
    /// Mixes a hash with a salt to produce a decorrelated value. One more FNV-1a round.
    /// </summary>
    private static uint Mix(uint hash, byte salt)
    {
        return (hash ^ salt) * 16777619u;
    }

    /// <summary>One phrasing per line, blanks dropped.</summary>
    internal static IReadOnlyList<string> SplitMessages(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return [];
        }

        return configured
            .Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.Length > 0)
            .ToArray();
    }

    /// <summary>
    /// Returns the conversations whose keep-alive turn is due, most overdue first.
    /// </summary>
    public IReadOnlyList<KeepAliveCandidate> SelectDue(
        IReadOnlyList<GuardianTaskState> states,
        KeepAlivePolicySnapshot policy,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(states);
        if (!policy.Enabled)
        {
            return [];
        }

        var due = new List<KeepAliveCandidate>();
        foreach (var state in states)
        {
            if (ResolveDueAt(state, policy) is not { } dueAt || dueAt > now)
            {
                continue;
            }

            due.Add(new KeepAliveCandidate(state.Thread.Id, dueAt, now - dueAt));
        }

        return due
            .OrderByDescending(candidate => candidate.Overdue)
            .ThenBy(candidate => candidate.ThreadId, StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// The earliest deadline across eligible conversations, for the monitor loop's wake calculation.
    /// </summary>
    public DateTimeOffset? FindNextDueAt(
        IReadOnlyList<GuardianTaskState> states,
        KeepAlivePolicySnapshot policy)
    {
        ArgumentNullException.ThrowIfNull(states);
        if (!policy.Enabled)
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        DateTimeOffset? earliest = null;
        foreach (var state in states)
        {
            if (ResolveDueAt(state, policy) is not { } dueAt)
            {
                continue;
            }

            // Clamped to now. A conversation that has never had a heartbeat resolves to MinValue so it
            // sorts ahead of everything in SelectDue, and handing that straight to the caller made the UI
            // report the next heartbeat as falling due in the year 1: the honest answer is "now".
            if (dueAt < now)
            {
                dueAt = now;
            }

            if (earliest is null || dueAt < earliest)
            {
                earliest = dueAt;
            }
        }

        return earliest;
    }

    /// <summary>
    /// When this conversation's next keep-alive falls due, or null when it is not eligible.
    /// </summary>
    /// <remarks>
    /// Shared by the due-selection and wake-scheduling paths so the two can never disagree about when a
    /// heartbeat is owed — a loop that sleeps on one rule and fires on another either misses deadlines
    /// or spins.
    /// </remarks>
    private DateTimeOffset? ResolveDueAt(GuardianTaskState state, KeepAlivePolicySnapshot policy)
    {
        var threadId = state.Thread.Id;
        if (!IsEligible(state, policy, threadId))
        {
            return null;
        }

        // Once held, the interval runs from the last heartbeat this conversation got. Before the first
        // one it is due immediately: the user turned the hold on because they want the slot held now, and
        // waiting out an interval first would make the switch look like it did nothing. The safety checks
        // in IsEligible are what stop this from landing on live work, not the delay.
        //
        // MinValue rather than `now` for the never-sent case, so a conversation waiting for its first
        // heartbeat sorts ahead of one that is merely overdue. Callers that surface this to the user clamp
        // it; see FindNextDueAt.
        var lastSentAt = LastSentAt(threadId);
        return lastSentAt is { } sent
            ? sent + Jitter(threadId, sent, policy.Interval)
            : DateTimeOffset.MinValue;
    }

    /// <summary>
    /// The interval for one specific heartbeat, spread up to a quarter either side of the configured one.
    /// </summary>
    /// <remarks>
    /// A turn landing every 300.0 seconds is a stronger signal of automation than anything in the message
    /// text: no person sends on a metronome, and periodicity that exact survives any amount of wording
    /// variety. Spreading the interval removes the fixed period without changing the average rate.
    ///
    /// Deliberately derived rather than random. Both the due-selection and the wake-scheduling paths call
    /// through here, and the class contract is that they can never disagree about when a heartbeat is
    /// owed. A `Random` draw would give a different answer on each call: the loop would sleep to one
    /// deadline, wake, compute another, and either spin or sleep past the send. Keying on the conversation
    /// and its last send time makes the answer stable for as long as that pair is, which is exactly until
    /// the next heartbeat.
    /// </remarks>
    private static TimeSpan Jitter(string threadId, DateTimeOffset lastSentAt, TimeSpan interval)
    {
        var hash = ComputeHash(threadId, lastSentAt);

        // Map onto [-25%, +25%]. A quarter is wide enough to break periodicity while keeping the rate
        // close enough to the number the user typed that the setting still means what it says.
        var spread = hash % 1001u / 1000.0 - 0.5;
        var scaled = interval.Ticks * (1.0 + (spread / 2.0));
        return TimeSpan.FromTicks((long)scaled);
    }

    private bool IsEligible(GuardianTaskState state, KeepAlivePolicySnapshot policy, string threadId)
    {
        if (state.Thread.IsArchived)
        {
            return false;
        }

        if (!IsHeld(policy, threadId))
        {
            return false;
        }

        // Never insert a turn ahead of a failed one that recovery still wants to edit in place, and
        // never send while a turn is running — the reply would land on top of live work.
        //
        // A previous heartbeat of our own counts as settled even when it drew no reply. It has no user
        // work behind it for recovery to protect, and treating it as unsettled would leave the
        // conversation ineligible forever after the first send: an unanswered heartbeat has no final
        // assistant output, so IsSettled would stay false and the hold would silently lapse.
        return !state.IsRunningNow &&
               (IsSettled(state) || IsKeepAliveTurn(threadId, state.Turn));
    }

    /// <summary>
    /// True when this conversation should be held: either the user switched it on, or it is the
    /// sentinel's nominated destination and the sentinel is armed.
    /// </summary>
    /// <remarks>
    /// An explicit "off" wins over the sentinel. If the user nominated a conversation as the destination
    /// and then switched that same row off, the switch they can see is the one that should hold.
    ///
    /// Note this no longer consults `state.IsEnabled`. That flag is the automatic-recovery hold for a
    /// conversation, and gating keep-alive on it meant a row could show as held on the keep-alive page
    /// while the engine silently never sent to it, because the page never checked that flag.
    /// </remarks>
    private bool IsHeld(KeepAlivePolicySnapshot policy, string threadId)
    {
        if (policy.ThreadEnabled.TryGetValue(threadId, out var explicitChoice))
        {
            return explicitChoice;
        }

        return IsSentinelDestination(policy, threadId) && _lastHealthyReplyAt is not null;
    }

    /// <summary>True when the sentinel is on and this is the conversation it sends into.</summary>
    internal static bool IsSentinelDestination(KeepAlivePolicySnapshot policy, string threadId) =>
        policy.SentinelEnabled &&
        policy.SentinelThreadId.Length > 0 &&
        string.Equals(policy.SentinelThreadId, threadId, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the conversation has nothing outstanding for recovery to act on.
    /// </summary>
    internal static bool IsSettled(GuardianTaskState state) =>
        state.Health is TaskHealth.Healthy or TaskHealth.NoHistory &&
        state.Turn?.HasReliableFinalOutput != false;

    /// <summary>Reads the persisted schedule, if there is one. Never throws.</summary>
    /// <remarks>
    /// A failed read is not worth surfacing beyond the log. The cost of losing this file is one restart
    /// guarantee, and the alternative — letting the exception out of the constructor — would take the
    /// whole engine down over a state file that is regenerated on the next heartbeat anyway.
    /// </remarks>
    private void LoadState()
    {
        if (_statePath is null)
        {
            return;
        }

        try
        {
            lock (_stateGate)
            {
                DataDirectorySafety.RevalidateWriteTarget(_log.DataDirectory, _statePath);
                if (!File.Exists(_statePath))
                {
                    return;
                }

                // FileShare.ReadWrite so a second instance mid-write cannot make this throw.
                using var stream = new FileStream(
                    _statePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite);
                var document = JsonSerializer.Deserialize<KeepAliveStateDocument>(stream, StateJsonOptions);
                if (document is null || document.Schema != StateSchemaVersion)
                {
                    return;
                }

                var now = DateTimeOffset.UtcNow;
                foreach (var record in document.Threads ?? [])
                {
                    if (string.IsNullOrWhiteSpace(record.ThreadId))
                    {
                        continue;
                    }

                    // A timestamp ahead of the clock would push the next heartbeat that far into the
                    // future and stall the hold for as long as the skew lasts. Reading it as "just sent"
                    // costs at most one interval.
                    _lastSentAt[record.ThreadId] = record.LastSentAt > now ? now : record.LastSentAt;
                    if (!string.IsNullOrWhiteSpace(record.Message))
                    {
                        _lastMessage[record.ThreadId] = record.Message;
                    }

                    if (!string.IsNullOrWhiteSpace(record.ClientMessageId))
                    {
                        _lastClientMessageId[record.ThreadId] = record.ClientMessageId;
                    }
                }
            }
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException
                or NotSupportedException or JsonException)
        {
            _log.Warning($"Keep-alive schedule could not be read: {error.GetType().Name}.");
        }
    }

    /// <summary>Writes the schedule so it survives a restart. Never throws.</summary>
    private void SaveState()
    {
        if (_statePath is null)
        {
            return;
        }

        var threads = _lastSentAt
            .Select(entry => new KeepAliveThreadState(
                entry.Key,
                entry.Value,
                _lastMessage.TryGetValue(entry.Key, out var message) ? message : null,
                _lastClientMessageId.TryGetValue(entry.Key, out var clientId) ? clientId : null))
            .OrderByDescending(record => record.LastSentAt)
            .Take(PersistedThreadCapacity)
            .ToArray();

        // Written through a temporary file and moved into place. A crash partway through a direct write
        // would leave a truncated file, and a file that fails to parse is exactly the state this whole
        // mechanism exists to avoid.
        var tempPath = _statePath + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            lock (_stateGate)
            {
                DataDirectorySafety.RevalidateWriteTarget(_log.DataDirectory, tempPath);
                DataDirectorySafety.RevalidateWriteTarget(_log.DataDirectory, _statePath);
                File.WriteAllBytes(
                    tempPath,
                    JsonSerializer.SerializeToUtf8Bytes(
                        new KeepAliveStateDocument(StateSchemaVersion, threads),
                        StateJsonOptions));
                File.Move(tempPath, _statePath, overwrite: true);
            }
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException
                or NotSupportedException)
        {
            _log.Warning($"Keep-alive schedule could not be written: {error.GetType().Name}.");
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (Exception cleanup) when (
                cleanup is IOException or UnauthorizedAccessException or ArgumentException
                    or NotSupportedException)
            {
                _ = cleanup;
            }
        }
    }

    /// <summary>The persisted form of the schedule.</summary>
    private sealed record KeepAliveStateDocument(
        int Schema,
        IReadOnlyList<KeepAliveThreadState> Threads);

    /// <param name="Message">
    /// The wording last sent, which is what lets a restarted coordinator still recognise its own
    /// unanswered heartbeat when the turn snapshot comes back without client ids.
    /// </param>
    private sealed record KeepAliveThreadState(
        string ThreadId,
        DateTimeOffset LastSentAt,
        string? Message,
        string? ClientMessageId);
}

public readonly record struct KeepAliveCandidate(
    string ThreadId,
    DateTimeOffset DueAt,
    TimeSpan Overdue);

public readonly record struct KeepAlivePolicySnapshot(
    bool Enabled,
    bool SentinelEnabled,
    string SentinelThreadId,
    TimeSpan Interval,
    string Message,
    IReadOnlyDictionary<string, bool> ThreadEnabled);

/// <summary>Keep-alive state for one conversation, as shown on the keep-alive page.</summary>
/// <param name="IsHeldByUser">The user switched this conversation's own hold on.</param>
/// <param name="IsSentinelDestination">
/// This is where the sentinel sends. Shown distinctly because the reason it is held is different, and a
/// user who nominated it should see that on the row rather than having to remember.
/// </param>
/// <param name="IsSettled">
/// False while the conversation has a failed turn awaiting recovery. Keep-alive stays out of those:
/// inserting a turn ahead of the failed one would make its in-place retry permanently impossible.
/// </param>
/// <summary>One heartbeat as it was sent: which conversation, the wording, and when.</summary>
public sealed record KeepAliveSendRecord(string ThreadId, string Message, DateTimeOffset SentAt);

public sealed record KeepAliveThreadRuntime(
    string ThreadId,
    string Name,
    bool IsHeldByUser,
    bool IsSentinelDestination,
    bool IsSentinelArmed,
    bool IsSettled,
    DateTimeOffset? LastSentAt)
{
    public bool IsHeld => IsHeldByUser || (IsSentinelDestination && IsSentinelArmed);

    public bool IsWaitingForRecovery => IsHeld && !IsSettled;

    /// <summary>
    /// True when this row is the sentinel's destination but no normal reply has been seen yet.
    /// </summary>
    /// <remarks>
    /// Its own state, not folded into held or unheld, because "chosen but the endpoint has not proved
    /// itself open yet" is exactly the situation the sentinel exists for and the row should say so.
    /// </remarks>
    public bool IsSentinelWaitingForSignal => IsSentinelDestination && !IsSentinelArmed && !IsHeldByUser;
}

public sealed record KeepAliveRuntimeSnapshot(
    bool Enabled,
    bool MonitorOnly,
    bool SentinelEnabled,
    bool SentinelArmed,
    bool SentinelHasDestination,
    DateTimeOffset? NextDueAt,
    IReadOnlyList<KeepAliveThreadRuntime> Threads,
    IReadOnlyList<KeepAliveSendRecord> RecentSends)
{
    public int HeldCount => Threads.Count(thread => thread.IsHeld);

    public int WaitingForRecoveryCount => Threads.Count(thread => thread.IsWaitingForRecovery);
}
