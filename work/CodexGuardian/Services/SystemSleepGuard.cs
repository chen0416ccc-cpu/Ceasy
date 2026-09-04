using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace CodexGuardian.Services;

/// <summary>
/// Asks Windows not to sleep the machine while guarding is active.
/// </summary>
/// <remarks>
/// Sleep stops everything this app does: a conversation waiting on a retry stays waiting, keep-alive
/// stops holding its slot, and the endpoint has to be fought for again on wake. The request is made
/// through SetThreadExecutionState with ES_CONTINUOUS, which holds until it is cleared.
///
/// Two constraints shape the implementation. The flag is per-thread — the thread that sets it must
/// stay alive or the request lapses silently — so every call is marshalled onto the UI dispatcher,
/// which lives as long as the app. And ES_DISPLAY_REQUIRED is deliberately not set: keeping the work
/// running is what was asked for, and holding the screen on all night is a louder thing to do than
/// that.
///
/// This cannot defeat a lid close, hibernation on battery, or an administrator's forced sleep policy;
/// it is a request, not a lock.
/// </remarks>
public sealed class SystemSleepGuard(GuardianLog log, Dispatcher dispatcher) : IDisposable
{
    private const uint EsContinuous = 0x80000000;
    private const uint EsSystemRequired = 0x00000001;

    private bool _held;
    private bool _disposed;

    /// <summary>Whether the machine is currently being asked to stay awake.</summary>
    public bool IsHolding => _held;

    /// <summary>
    /// Applies the requested state, acquiring or releasing the request only when it actually changes.
    /// </summary>
    public void Apply(bool keepAwake)
    {
        if (_disposed || keepAwake == _held)
        {
            return;
        }

        if (dispatcher.CheckAccess())
        {
            ApplyOnDispatcher(keepAwake);
            return;
        }

        dispatcher.Invoke(() => ApplyOnDispatcher(keepAwake));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        // Clear before the process exits rather than relying on teardown. Shutdown can reach here after
        // the dispatcher has stopped accepting work, and the flag is per-thread, so it cannot be cleared
        // from anywhere else — swallow that case. Windows drops the request when the process ends.
        try
        {
            Apply(false);
        }
        catch (TaskCanceledException)
        {
        }
        catch (InvalidOperationException)
        {
        }

        _disposed = true;
    }

    private void ApplyOnDispatcher(bool keepAwake)
    {
        if (keepAwake == _held)
        {
            return;
        }

        var requested = keepAwake ? EsContinuous | EsSystemRequired : EsContinuous;
        if (SetThreadExecutionState(requested) == 0)
        {
            log.Warning(
                keepAwake
                    ? "Windows refused the request to keep the system awake; sleep may still interrupt guarding."
                    : "Windows refused the request to release the keep-awake hold.");
            return;
        }

        _held = keepAwake;
        log.Info(
            keepAwake
                ? "Asked Windows to keep the system awake while guarding."
                : "Released the keep-awake request; the system may sleep normally again.");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SetThreadExecutionState(uint flags);
}
