using CodexGuardian.Models;
using System.Text;
using System.Threading;

namespace CodexGuardian.Services;

internal sealed class WorkflowAuthoritativeCompletionEventArgs(
    ThreadSummary conversation,
    TurnSnapshot completedTurn,
    DateTimeOffset observedAtUtc) : EventArgs
{
    internal ThreadSummary Conversation { get; } = conversation ??
        throw new ArgumentNullException(nameof(conversation));

    internal TurnSnapshot CompletedTurn { get; } = completedTurn ??
        throw new ArgumentNullException(nameof(completedTurn));

    internal DateTimeOffset ObservedAtUtc { get; } = observedAtUtc.ToUniversalTime();
}

internal interface IWorkflowAuthoritativeCompletionSource
{
    event EventHandler<WorkflowAuthoritativeCompletionEventArgs>? CompletionObserved;
}

internal sealed class GuardianEngineWorkflowCompletionSource(GuardianEngine inner)
    : IWorkflowAuthoritativeCompletionSource
{
    public event EventHandler<WorkflowAuthoritativeCompletionEventArgs>? CompletionObserved
    {
        add => inner.WorkflowCompletionObserved += value;
        remove => inner.WorkflowCompletionObserved -= value;
    }
}

internal sealed class WorkflowPresetDispatchConfirmedEventArgs(
    WorkflowActionOperationRecord action) : EventArgs
{
    internal WorkflowActionOperationRecord Action { get; } = action ??
        throw new ArgumentNullException(nameof(action));
}

internal interface IWorkflowPresetDispatchConfirmationSource
{
    event EventHandler<WorkflowPresetDispatchConfirmedEventArgs>? PresetDispatchConfirmed;
}

internal interface IWorkflowAutomationAuthorityChangeSource : IDisposable
{
    event EventHandler<EventArgs>? AuthorityChanged;
}

internal sealed class GuardianWorkflowAutomationAuthorityChangeSource :
    IWorkflowAutomationAuthorityChangeSource
{
    private readonly GuardianEngine _engine;
    private readonly DesktopIpcClient _desktopIpc;
    private readonly object _stateSync = new();
    private string? _lastSnapshotFingerprint;
    private int _lastDesktopConnectionState = -1;
    private int _disposed;

    internal GuardianWorkflowAutomationAuthorityChangeSource(
        GuardianEngine engine,
        DesktopIpcClient desktopIpc)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _desktopIpc = desktopIpc ?? throw new ArgumentNullException(nameof(desktopIpc));
        _engine.SnapshotUpdated += OnSnapshotUpdated;
        _desktopIpc.ConnectionChanged += OnDesktopConnectionChanged;
    }

    public event EventHandler<EventArgs>? AuthorityChanged;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _engine.SnapshotUpdated -= OnSnapshotUpdated;
        _desktopIpc.ConnectionChanged -= OnDesktopConnectionChanged;
    }

    private void OnSnapshotUpdated(object? sender, GuardianTaskSnapshot snapshot)
    {
        _ = sender;
        var fingerprint = CreateAuthorityFingerprint(snapshot);
        lock (_stateSync)
        {
            if (string.Equals(_lastSnapshotFingerprint, fingerprint, StringComparison.Ordinal))
            {
                return;
            }

            _lastSnapshotFingerprint = fingerprint;
        }

        PublishChanged();
    }

    private void OnDesktopConnectionChanged(object? sender, bool connected)
    {
        _ = sender;
        var nextState = connected ? 1 : 0;
        if (Interlocked.Exchange(ref _lastDesktopConnectionState, nextState) == nextState)
        {
            return;
        }

        PublishChanged();
    }

    internal static string CreateAuthorityFingerprint(GuardianTaskSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(snapshot.States);
        ArgumentNullException.ThrowIfNull(snapshot.Statistics);

        var builder = new StringBuilder();
        builder.Append(snapshot.Statistics.TotalSessionCount).Append('|')
            .Append(snapshot.Statistics.ArchivedSessionCount).Append('|')
            .Append(snapshot.Statistics.IsTruncated).Append('|')
            .Append(snapshot.Statistics.IncludesArchived).Append('\n');
        foreach (var state in snapshot.States.OrderBy(
                     static state => state.Thread.Id,
                     StringComparer.OrdinalIgnoreCase))
        {
            AppendField(builder, state.Thread.Id);
            AppendField(builder, state.Thread.RuntimeStatus);
            AppendField(builder, state.Thread.IsArchived);
            AppendField(builder, state.Thread.IsSubAgent);
            AppendField(builder, state.Thread.IsEphemeral);
            AppendField(builder, state.IsEnabled);
            AppendField(builder, state.Health);
            AppendField(builder, state.Decision.Action);
            AppendField(builder, state.IsGuardianManagedActivity);
            AppendField(builder, state.Turn?.Id);
            AppendField(builder, state.Turn?.Status);
            AppendField(builder, state.Turn?.HasConfirmedLocalTerminal);
            builder.Append('\n');
        }

        return builder.ToString();
    }

    private static void AppendField<T>(StringBuilder builder, T value)
    {
        var text = value?.ToString() ?? string.Empty;
        builder.Append(text.Length).Append(':').Append(text).Append('|');
    }

    private void PublishChanged()
    {
        if (Volatile.Read(ref _disposed) == 0)
        {
            EventSubscriberDispatcher.Invoke(AuthorityChanged, this, EventArgs.Empty);
        }
    }
}
