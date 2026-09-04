namespace CodexGuardian.Models;

public enum LogLevel
{
    Trace,
    Info,
    Success,
    Warning,
    Error
}

public sealed record LogEntry(DateTimeOffset Timestamp, LogLevel Level, string Message, string? ThreadName = null)
{
    public string TimeText => Timestamp.LocalDateTime.ToString("HH:mm:ss");
}
