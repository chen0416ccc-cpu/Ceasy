namespace CodexGuardian.Models;

/// <summary>
/// The latest terminal event recovered from the tail of a local rollout file.
/// It is safe for automatic reconciliation only when its turn id matches the
/// latest turn returned by app-server.
/// </summary>
public sealed record LocalConversationTerminalEvent(
    string ThreadId,
    string TurnId,
    string SourceFile,
    long ByteOffset,
    DateTimeOffset? RecordedAt,
    TurnSnapshot Turn);
