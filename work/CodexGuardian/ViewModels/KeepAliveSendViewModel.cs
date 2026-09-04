namespace CodexGuardian.ViewModels;

/// <summary>
/// One heartbeat that actually went out, as shown on the keep-alive page.
/// </summary>
/// <remarks>
/// Immutable and rebuilt wholesale on each pass, unlike <see cref="KeepAliveThreadViewModel"/>, which is
/// updated in place because it hosts a focusable switch. Nothing here is interactive, so there is no click
/// to drop.
///
/// The wording is carried through verbatim. A heartbeat is indistinguishable from real work once it lands
/// in the conversation, and the schedule that produced it leaves no trace the user can see, so "it sent
/// something at 14:03" is the one claim this page can make that the conversation itself cannot.
/// </remarks>
public sealed class KeepAliveSendViewModel(string threadName, string message, string timeText)
{
    /// <summary>The conversation it went into, resolved to the title the user knows it by.</summary>
    public string ThreadName { get; } = threadName;

    /// <summary>The heartbeat as sent.</summary>
    public string Message { get; } = message;

    public string TimeText { get; } = timeText;
}
