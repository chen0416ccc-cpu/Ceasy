using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CodexGuardian.Services;

public enum DesktopThreadOwnerActivationStatus
{
    AlreadyAvailable,
    Activated,
    DeferredForUserActivity,
    TimedOut,
    Incompatible
}

public sealed record DesktopThreadOwnerActivationResult(
    DesktopThreadOwnerActivationStatus Status,
    string Detail)
{
    public bool IsAvailable =>
        Status is DesktopThreadOwnerActivationStatus.AlreadyAvailable or
            DesktopThreadOwnerActivationStatus.Activated;
}

internal enum DesktopUserActivityStatus
{
    Idle,
    Active,
    Unknown
}

internal sealed record DesktopUserActivityResult(
    DesktopUserActivityStatus Status,
    string Detail)
{
    public bool IsIdle => Status == DesktopUserActivityStatus.Idle;
}

internal interface IDesktopThreadOwnerProbe
{
    Task<DesktopThreadOwnerProbeResult> ProbeThreadOwnerAsync(
        string conversationId,
        CancellationToken cancellationToken = default);
}

internal interface IDesktopThreadOwnerActivationPlatform
{
    TimeSpan GetUserIdleTime();

    void OpenThread(string threadId);
}

internal sealed class WindowsDesktopThreadOwnerActivationPlatform : IDesktopThreadOwnerActivationPlatform
{
    public TimeSpan GetUserIdleTime()
    {
        var input = new LastInputInfo
        {
            Size = checked((uint)Marshal.SizeOf<LastInputInfo>())
        };
        if (!GetLastInputInfo(ref input))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var elapsedMilliseconds = unchecked(Environment.TickCount - (int)input.TickCount);
        return TimeSpan.FromMilliseconds(Math.Max(0, elapsedMilliseconds));
    }

    public void OpenThread(string threadId)
    {
        var uri = DesktopThreadOwnerActivator.BuildThreadUri(threadId);
        var process = Process.Start(new ProcessStartInfo(uri)
        {
            UseShellExecute = true
        });
        process?.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint TickCount;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LastInputInfo lastInputInfo);
}

public sealed class DesktopThreadOwnerActivator
{
    // Windows-wide idle time is the wrong signal for "may Guardian retry now". A user who sits watching a
    // stalled task keeps the idle timer at zero, and a user who is typing in another application is not
    // hurt by a retry either. The only interference that justifies waiting is a Codex composer that is
    // actually being edited, which the interaction hook reports directly. This value is only the fallback
    // for when that hook is unavailable, so it is short rather than the former fifteen seconds.
    internal static readonly TimeSpan DefaultMinimumIdleTime = TimeSpan.FromSeconds(3);
    internal static readonly TimeSpan DefaultActivationTimeout = TimeSpan.FromSeconds(20);
    internal static readonly TimeSpan DefaultProbeInterval = TimeSpan.FromMilliseconds(350);

    // Navigating to a task uses the registered codex:// link, which takes focus, so Guardian yields while a
    // composer is being typed into. Waiting without a bound is worse: a user who leaves a draft parked in
    // the composer would strand the retry forever. After this much continuous interference the retry
    // outweighs the focus change and Guardian goes.
    internal static readonly TimeSpan DefaultUserActivityPatience = TimeSpan.FromSeconds(20);

    private readonly IDesktopThreadOwnerProbe _probe;
    private readonly GuardianLog _log;
    private readonly IDesktopThreadOwnerActivationPlatform _platform;
    private readonly TimeSpan _minimumIdleTime;
    private readonly TimeSpan _activationTimeout;
    private readonly TimeSpan _probeInterval;
    private readonly TimeSpan _userActivityPatience;
    private readonly Func<bool>? _isComposerBeingEdited;
    private readonly SemaphoreSlim _activationGate = new(1, 1);
    private DateTimeOffset? _continuousUserActivitySince;

    public DesktopThreadOwnerActivator(DesktopIpcClient desktop, GuardianLog log)
        : this(
            desktop,
            log,
            new WindowsDesktopThreadOwnerActivationPlatform(),
            DefaultMinimumIdleTime,
            DefaultActivationTimeout,
            DefaultProbeInterval)
    {
    }

    internal DesktopThreadOwnerActivator(
        IDesktopThreadOwnerProbe probe,
        GuardianLog log,
        IDesktopThreadOwnerActivationPlatform platform,
        TimeSpan minimumIdleTime,
        TimeSpan activationTimeout,
        TimeSpan probeInterval,
        TimeSpan? userActivityPatience = null,
        Func<bool>? isComposerBeingEdited = null)
    {
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(platform);
        if (minimumIdleTime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumIdleTime));
        }

        if (activationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(activationTimeout));
        }

        if (probeInterval < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(probeInterval));
        }

        var patience = userActivityPatience ?? DefaultUserActivityPatience;
        if (patience <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(userActivityPatience));
        }

        _probe = probe;
        _log = log;
        _platform = platform;
        _minimumIdleTime = minimumIdleTime;
        _activationTimeout = activationTimeout;
        _probeInterval = probeInterval;
        _userActivityPatience = patience;
        _isComposerBeingEdited = isComposerBeingEdited;
    }

    // The public constructor cannot see the interaction hook, which is created later in startup, so the
    // composer probe is attached once it exists.
    public DesktopThreadOwnerActivator WithComposerProbe(Func<bool> isComposerBeingEdited)
    {
        ArgumentNullException.ThrowIfNull(isComposerBeingEdited);
        return new DesktopThreadOwnerActivator(
            _probe,
            _log,
            _platform,
            _minimumIdleTime,
            _activationTimeout,
            _probeInterval,
            _userActivityPatience,
            isComposerBeingEdited);
    }

    public async Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
        string threadId,
        CancellationToken cancellationToken = default)
    {
        ValidateThreadId(threadId);

        var initialProbe = await _probe.ProbeThreadOwnerAsync(threadId, cancellationToken)
            .ConfigureAwait(false);
        if (initialProbe.Status == DesktopThreadOwnerProbeStatus.Available)
        {
            return new DesktopThreadOwnerActivationResult(
                DesktopThreadOwnerActivationStatus.AlreadyAvailable,
                "The stock Codex Desktop task owner is already available.");
        }

        if (initialProbe.Status == DesktopThreadOwnerProbeStatus.Incompatible)
        {
            return Incompatible(initialProbe.Detail);
        }

        await _activationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var currentProbe = await _probe.ProbeThreadOwnerAsync(threadId, cancellationToken)
                .ConfigureAwait(false);
            if (currentProbe.Status == DesktopThreadOwnerProbeStatus.Available)
            {
                return new DesktopThreadOwnerActivationResult(
                    DesktopThreadOwnerActivationStatus.AlreadyAvailable,
                    "The stock Codex Desktop task owner became available without navigation.");
            }

            if (currentProbe.Status == DesktopThreadOwnerProbeStatus.Incompatible)
            {
                return Incompatible(currentProbe.Detail);
            }

            if (initialProbe.Status != DesktopThreadOwnerProbeStatus.Unavailable ||
                currentProbe.Status != DesktopThreadOwnerProbeStatus.Unavailable)
            {
                return new DesktopThreadOwnerActivationResult(
                    DesktopThreadOwnerActivationStatus.TimedOut,
                    "The task owner probe was transient or inconclusive; Guardian did not navigate to the task.");
            }

            var navigationDeferral = GetUserActivityDeferral();
            if (navigationDeferral is not null)
            {
                return navigationDeferral;
            }

            try
            {
                _platform.OpenThread(threadId);
            }
            catch (Exception exception) when (
                exception is Win32Exception or InvalidOperationException or NotSupportedException)
            {
                _log.Warning("The stock Codex task deep link could not be opened: " + exception.Message);
                return new DesktopThreadOwnerActivationResult(
                    DesktopThreadOwnerActivationStatus.TimedOut,
                    "The registered codex:// task link could not be opened.");
            }

            _log.Info("Opened the task through the registered stock Codex deep link.");
            var deadline = DateTimeOffset.UtcNow + _activationTimeout;
            do
            {
                await Task.Delay(_probeInterval, cancellationToken).ConfigureAwait(false);

                // The deep link already took focus, so bailing out here because the user touched the
                // keyboard would spend the interruption and gain nothing. The bounded activation window
                // runs to completion instead.
                var probe = await _probe.ProbeThreadOwnerAsync(threadId, cancellationToken)
                    .ConfigureAwait(false);
                if (probe.Status == DesktopThreadOwnerProbeStatus.Available)
                {
                    return new DesktopThreadOwnerActivationResult(
                        DesktopThreadOwnerActivationStatus.Activated,
                        "The stock Codex Desktop task owner was established through the registered deep link.");
                }

                if (probe.Status == DesktopThreadOwnerProbeStatus.Incompatible)
                {
                    return Incompatible(probe.Detail);
                }
            }
            while (DateTimeOffset.UtcNow < deadline);

            return new DesktopThreadOwnerActivationResult(
                DesktopThreadOwnerActivationStatus.TimedOut,
                "Codex Desktop did not establish the target task owner within the bounded activation window.");
        }
        finally
        {
            _activationGate.Release();
        }
    }

    // Returns true when interference actually cleared, false when the bounded patience window elapsed first.
    // Callers treat false as "stop waiting and proceed": an unbounded wait here is what made a user who
    // stays at the keyboard never see a retry at all. With the composer probe attached this returns true on
    // the first check unless a draft is genuinely being edited, so a failed turn is retried right away.
    public async Task<bool> WaitForMinimumIdleAsync(CancellationToken cancellationToken = default)
    {
        var deadline = DateTimeOffset.UtcNow + _userActivityPatience;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var activity = CheckUserActivity();
            if (activity.Status != DesktopUserActivityStatus.Active)
            {
                return true;
            }

            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                _log.Info(
                    "A Codex composer stayed busy past the recovery patience window; Guardian stopped " +
                    "waiting so the retry is not delayed indefinitely.");
                return false;
            }

            await Task.Delay(
                    remaining < TimeSpan.FromMilliseconds(250) ? remaining : TimeSpan.FromMilliseconds(250),
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    internal DesktopUserActivityResult CheckUserActivity()
    {
        // A Codex composer being typed into is the only interference a retry has to yield to. When the
        // interaction hook can answer that question, Windows-wide idle time is not consulted at all, so a
        // failed turn is retried immediately instead of sitting out an idle countdown.
        if (_isComposerBeingEdited is not null)
        {
            try
            {
                return _isComposerBeingEdited()
                    ? new DesktopUserActivityResult(
                        DesktopUserActivityStatus.Active,
                        "A Codex composer is being edited; the retry waits for the draft to be released.")
                    : new DesktopUserActivityResult(
                        DesktopUserActivityStatus.Idle,
                        "No Codex composer is being edited, so the retry proceeds immediately.");
            }
            catch (Exception exception) when (
                exception is InvalidOperationException or Win32Exception or ObjectDisposedException)
            {
                _log.Trace("The Codex composer probe was unavailable: " + exception.Message);
            }
        }

        try
        {
            var idleTime = _platform.GetUserIdleTime();
            return idleTime >= _minimumIdleTime
                ? new DesktopUserActivityResult(
                    DesktopUserActivityStatus.Idle,
                    $"Windows has been idle for at least {_minimumIdleTime.TotalSeconds:0} seconds.")
                : new DesktopUserActivityResult(
                    DesktopUserActivityStatus.Active,
                    $"Waiting for {_minimumIdleTime.TotalSeconds:0} seconds without Windows user input.");
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            return new DesktopUserActivityResult(
                DesktopUserActivityStatus.Unknown,
                "Windows user idle time could not be verified safely: " + exception.Message);
        }
    }

    internal static string BuildThreadUri(string threadId)
    {
        ValidateThreadId(threadId);
        return $"codex://threads/{Guid.Parse(threadId):D}";
    }

    private static DesktopThreadOwnerActivationResult Incompatible(string detail) =>
        new(
            DesktopThreadOwnerActivationStatus.Incompatible,
            string.IsNullOrWhiteSpace(detail)
                ? "Codex Desktop does not expose the stock task-follower owner contract."
                : detail);

    private DesktopThreadOwnerActivationResult? GetUserActivityDeferral()
    {
        var activity = CheckUserActivity();

        // An unverifiable probe is not evidence that someone is typing. Deferring on Unknown is what made a
        // failed turn wait out an idle countdown for no reason, so only a confirmed active composer defers.
        if (activity.Status != DesktopUserActivityStatus.Active)
        {
            _continuousUserActivitySince = null;
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        var since = _continuousUserActivitySince ??= now;
        if (now - since < _userActivityPatience)
        {
            return new DesktopThreadOwnerActivationResult(
                DesktopThreadOwnerActivationStatus.DeferredForUserActivity,
                activity.Detail);
        }

        // The patience window elapsed with a composer never releasing its draft. Deferring again would
        // strand the retry indefinitely, so navigate now and restart the window instead of navigating on
        // every probe.
        _continuousUserActivitySince = now;
        _log.Info(
            "A Codex composer stayed busy past the recovery patience window; Guardian navigated to the task " +
            "anyway so the retry is not delayed indefinitely.");
        return null;
    }

    private static void ValidateThreadId(string threadId)
    {
        if (!Guid.TryParse(threadId, out _))
        {
            throw new ArgumentException("A task UUID is required.", nameof(threadId));
        }
    }

}
