using System.Text.Json;

namespace CodexGuardian.Services;

internal enum DesktopThreadOwnerStateGuardStatus
{
    Available,
    Unavailable,
    Incompatible
}

internal sealed record DesktopThreadOwnerStateGuardAcquireResult(
    DesktopThreadOwnerStateGuardStatus Status,
    DesktopThreadOwnerStateGuard? Guard,
    string Detail)
{
    public bool IsAvailable => Status == DesktopThreadOwnerStateGuardStatus.Available && Guard is not null;
}

internal sealed record DesktopThreadOwnerStateSnapshot(
    string ConversationId,
    string HostId,
    string OwnerClientId,
    long Revision,
    string RuntimeStatus,
    string LatestTurnId,
    string LatestTurnStatus)
{
    internal enum ParseStatus
    {
        Available,
        Pending,
        Incompatible
    }

    internal static bool TryParse(
        DesktopIpcActivityEventArgs eventArgs,
        out DesktopThreadOwnerStateSnapshot? snapshot) =>
        Parse(eventArgs, out snapshot) == ParseStatus.Available;

    internal static ParseStatus Parse(
        DesktopIpcActivityEventArgs eventArgs,
        out DesktopThreadOwnerStateSnapshot? snapshot) =>
        Parse(eventArgs, out snapshot, out _);

    // `incompatibleReason` names the exact field that failed the shape check. A bare
    // "incompatible" verdict cannot separate a renamed field from a new history kind or an empty
    // envelope, which leaves a live refusal undiagnosable: the recovery simply stops with no way
    // to learn what the stock Desktop actually sent. Reasons are fixed identifiers, extended only
    // by a protocol token that passed ReportableToken, so no task content can leave through here.
    internal static ParseStatus Parse(
        DesktopIpcActivityEventArgs eventArgs,
        out DesktopThreadOwnerStateSnapshot? snapshot,
        out string incompatibleReason)
    {
        snapshot = null;
        incompatibleReason = string.Empty;
        if (!string.Equals(
                eventArgs.Method,
                DesktopIpcClient.NativeThreadStateMethod,
                StringComparison.Ordinal) ||
            eventArgs.Version != DesktopIpcClient.NativeThreadStateVersion)
        {
            incompatibleReason = "method-or-version";
            return ParseStatus.Incompatible;
        }

        if (!string.Equals(eventArgs.ChangeType, "snapshot", StringComparison.Ordinal))
        {
            return ParseStatus.Pending;
        }

        if (eventArgs.Revision is null)
        {
            incompatibleReason = "revision";
            return ParseStatus.Incompatible;
        }

        if (string.IsNullOrWhiteSpace(eventArgs.ConversationId))
        {
            incompatibleReason = "conversationId";
            return ParseStatus.Incompatible;
        }

        if (string.IsNullOrWhiteSpace(eventArgs.HostId))
        {
            incompatibleReason = "hostId";
            return ParseStatus.Incompatible;
        }

        if (string.IsNullOrWhiteSpace(eventArgs.SourceClientId))
        {
            incompatibleReason = "sourceClientId";
            return ParseStatus.Incompatible;
        }

        if (string.IsNullOrWhiteSpace(eventArgs.RuntimeStatus))
        {
            incompatibleReason = "runtimeStatus";
            return ParseStatus.Incompatible;
        }

        if (eventArgs.Parameters is not { } parameters ||
            !parameters.TryGetProperty("change", out var change) ||
            change.ValueKind != JsonValueKind.Object)
        {
            incompatibleReason = "change";
            return ParseStatus.Incompatible;
        }

        if (!change.TryGetProperty("conversationState", out var state) ||
            state.ValueKind != JsonValueKind.Object)
        {
            incompatibleReason = "conversationState";
            return ParseStatus.Incompatible;
        }

        if (!string.Equals(
                ReadString(state, "id"),
                eventArgs.ConversationId,
                StringComparison.OrdinalIgnoreCase))
        {
            incompatibleReason = "conversationState.id";
            return ParseStatus.Incompatible;
        }

        var latestTurnStatus = TryFindLatestTurn(state, out var latestTurn, out var latestTurnReason);
        if (latestTurnStatus == ParseStatus.Pending)
        {
            return ParseStatus.Pending;
        }

        if (latestTurnStatus != ParseStatus.Available)
        {
            incompatibleReason = latestTurnReason;
            return ParseStatus.Incompatible;
        }

        if (string.IsNullOrWhiteSpace(latestTurn.TurnId) ||
            string.IsNullOrWhiteSpace(latestTurn.Status))
        {
            incompatibleReason = "latestTurn";
            return ParseStatus.Incompatible;
        }

        snapshot = new DesktopThreadOwnerStateSnapshot(
            eventArgs.ConversationId,
            eventArgs.HostId,
            eventArgs.SourceClientId,
            eventArgs.Revision.Value,
            eventArgs.RuntimeStatus,
            latestTurn.TurnId,
            latestTurn.Status);
        return ParseStatus.Available;
    }

    private static ParseStatus TryFindLatestTurn(
        JsonElement state,
        out (string TurnId, string Status) latestTurn,
        out string incompatibleReason)
    {
        latestTurn = default;
        incompatibleReason = string.Empty;
        if (state.TryGetProperty("turnHistory", out var turnHistory))
        {
            if (turnHistory.ValueKind != JsonValueKind.Object)
            {
                incompatibleReason = "turnHistory";
                return ParseStatus.Incompatible;
            }

            var historyKind = ReadString(turnHistory, "kind");
            if (!string.Equals(historyKind, "canonical", StringComparison.Ordinal))
            {
                incompatibleReason = "turnHistory.kind" + ReportableToken(historyKind);
                return ParseStatus.Incompatible;
            }

            if (!turnHistory.TryGetProperty("history", out var history) ||
                history.ValueKind != JsonValueKind.Object)
            {
                incompatibleReason = "turnHistory.history";
                return ParseStatus.Incompatible;
            }

            if (!history.TryGetProperty("islands", out var islands) ||
                islands.ValueKind != JsonValueKind.Array)
            {
                incompatibleReason = "turnHistory.islands";
                return ParseStatus.Incompatible;
            }

            if (islands.GetArrayLength() == 0)
            {
                incompatibleReason = "turnHistory.islands.empty";
                return ParseStatus.Incompatible;
            }

            if (!history.TryGetProperty("entitiesByKey", out var entities) ||
                entities.ValueKind != JsonValueKind.Object)
            {
                incompatibleReason = "turnHistory.entitiesByKey";
                return ParseStatus.Incompatible;
            }

            var newestIsland = islands[islands.GetArrayLength() - 1];
            if (newestIsland.ValueKind != JsonValueKind.Object)
            {
                incompatibleReason = "turnHistory.island";
                return ParseStatus.Incompatible;
            }

            if (!newestIsland.TryGetProperty("newerBoundary", out var newerBoundary) ||
                newerBoundary.ValueKind != JsonValueKind.Object)
            {
                incompatibleReason = "turnHistory.newerBoundary";
                return ParseStatus.Incompatible;
            }

            if (!newestIsland.TryGetProperty("entries", out var entries) ||
                entries.ValueKind != JsonValueKind.Array)
            {
                incompatibleReason = "turnHistory.entries";
                return ParseStatus.Incompatible;
            }

            var newerBoundaryStatus = ReadString(newerBoundary, "status");
            if (string.Equals(newerBoundaryStatus, "available", StringComparison.Ordinal))
            {
                return ParseStatus.Pending;
            }

            if (!string.Equals(newerBoundaryStatus, "exhausted", StringComparison.Ordinal))
            {
                incompatibleReason = "turnHistory.newerBoundary.status" + ReportableToken(newerBoundaryStatus);
                return ParseStatus.Incompatible;
            }

            for (var index = entries.GetArrayLength() - 1; index >= 0; index--)
            {
                var entry = entries[index];
                var key = entry.ValueKind == JsonValueKind.Object
                    ? ReadString(entry, "value")
                    : string.Empty;
                if (string.IsNullOrWhiteSpace(key) ||
                    !entities.TryGetProperty(key, out var entity) ||
                    entity.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var turnId = ReadString(entity, "turnId");
                if (!string.IsNullOrWhiteSpace(turnId))
                {
                    latestTurn = (turnId, ReadString(entity, "status"));
                    if (!string.IsNullOrWhiteSpace(latestTurn.Status))
                    {
                        return ParseStatus.Available;
                    }

                    incompatibleReason = "turnHistory.turnStatus";
                    return ParseStatus.Incompatible;
                }
            }

            incompatibleReason = "turnHistory.tail";
            return ParseStatus.Incompatible;
        }

        if (!state.TryGetProperty("turns", out var turns) || turns.ValueKind != JsonValueKind.Array)
        {
            incompatibleReason = "turns";
            return ParseStatus.Incompatible;
        }

        for (var index = turns.GetArrayLength() - 1; index >= 0; index--)
        {
            var turn = turns[index];
            if (turn.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var turnId = ReadString(turn, "turnId");
            if (!string.IsNullOrWhiteSpace(turnId))
            {
                latestTurn = (turnId, ReadString(turn, "status"));
                if (!string.IsNullOrWhiteSpace(latestTurn.Status))
                {
                    return ParseStatus.Available;
                }

                incompatibleReason = "turns.turnStatus";
                return ParseStatus.Incompatible;
            }
        }

        incompatibleReason = "turns.tail";
        return ParseStatus.Incompatible;
    }

    // Only a short protocol token may ever join a reason. A title, a path, or any prose is
    // dropped instead, so widening the diagnostic cannot turn it into a channel for task content.
    private static string ReportableToken(string value)
    {
        if (value.Length is 0 or > 32)
        {
            return string.Empty;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_' or '.' or ':'))
            {
                return string.Empty;
            }
        }

        return "=" + value;
    }

    private static string ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;
}

internal sealed class DesktopThreadOwnerStateGuard : IAsyncDisposable
{
    private readonly DesktopIpcClient _desktop;
    private readonly string _conversationId;
    private readonly string _hostId;
    private readonly TaskCompletionSource<DesktopThreadOwnerStateSnapshot> _snapshotCompletion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private string _ownerClientId = string.Empty;
    private int _snapshotReceived;
    private int _invalidated;
    private int _disposed;

    private DesktopThreadOwnerStateGuard(
        DesktopIpcClient desktop,
        string conversationId,
        string hostId)
    {
        _desktop = desktop;
        _conversationId = conversationId;
        _hostId = hostId;
    }

    public DesktopThreadOwnerStateSnapshot Snapshot { get; private set; } = null!;

    public bool IsCurrent =>
        Volatile.Read(ref _invalidated) == 0 && Volatile.Read(ref _disposed) == 0 && _desktop.IsConnected;

    internal static async Task<DesktopThreadOwnerStateGuardAcquireResult> AcquireAsync(
        DesktopIpcClient desktop,
        string conversationId,
        string hostId,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var guard = new DesktopThreadOwnerStateGuard(desktop, conversationId, hostId);
        desktop.ActivityReceived += guard.OnActivityReceived;
        desktop.ConnectionChanged += guard.OnConnectionChanged;
        try
        {
            await desktop.SetThreadFollowingAsync(conversationId, hostId, following: true, cancellationToken)
                .ConfigureAwait(false);
            guard.Snapshot = await guard._snapshotCompletion.Task.WaitAsync(timeout, cancellationToken)
                .ConfigureAwait(false);
            return new DesktopThreadOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Available,
                guard,
                "The stock Desktop owner returned a current in-memory task snapshot.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await guard.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        catch (InvalidDataException exception)
        {
            await guard.DisposeAsync().ConfigureAwait(false);
            return new DesktopThreadOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Incompatible,
                null,
                exception.Message);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or OperationCanceledException)
        {
            await guard.DisposeAsync().ConfigureAwait(false);
            return new DesktopThreadOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Unavailable,
                null,
                "The stock Desktop owner snapshot was unavailable: " + exception.Message);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _desktop.ActivityReceived -= OnActivityReceived;
        _desktop.ConnectionChanged -= OnConnectionChanged;
        if (!_desktop.IsConnected)
        {
            return;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            await _desktop.SetThreadFollowingAsync(
                    _conversationId,
                    _hostId,
                    following: false,
                    timeout.Token)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or TimeoutException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }

    private void OnActivityReceived(object? sender, DesktopIpcActivityEventArgs eventArgs)
    {
        if (string.Equals(eventArgs.Method, "ipc-connection-reset", StringComparison.Ordinal))
        {
            _snapshotCompletion.TrySetException(
                new IOException("The Codex Desktop IPC stream epoch was reset."));
            Invalidate();
            return;
        }

        if (string.Equals(eventArgs.Method, "client-status-changed", StringComparison.Ordinal) &&
            string.Equals(eventArgs.ClientStatus, "disconnected", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(eventArgs.ClientId) &&
            !string.IsNullOrWhiteSpace(_ownerClientId) &&
            string.Equals(eventArgs.ClientId, _ownerClientId, StringComparison.OrdinalIgnoreCase))
        {
            _snapshotCompletion.TrySetException(
                new IOException("The verified Codex Desktop task owner disconnected."));
            Invalidate();
            return;
        }

        if (!string.Equals(eventArgs.ConversationId, _conversationId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(eventArgs.HostId, _hostId, StringComparison.Ordinal))
        {
            return;
        }

        if (!string.Equals(
                eventArgs.Method,
                DesktopIpcClient.NativeThreadStateMethod,
                StringComparison.Ordinal))
        {
            return;
        }

        if (eventArgs.Version != DesktopIpcClient.NativeThreadStateVersion)
        {
            _snapshotCompletion.TrySetException(
                new InvalidDataException("Codex Desktop returned an incompatible owner-state version."));
            Invalidate();
            return;
        }

        if (Volatile.Read(ref _snapshotReceived) == 0)
        {
            var parseStatus = DesktopThreadOwnerStateSnapshot.Parse(
                eventArgs,
                out var snapshot,
                out var incompatibleReason);
            if (parseStatus == DesktopThreadOwnerStateSnapshot.ParseStatus.Pending)
            {
                return;
            }

            if (parseStatus != DesktopThreadOwnerStateSnapshot.ParseStatus.Available || snapshot is null)
            {
                // The reason travels in the message because this exception becomes the acquire
                // result Detail, which is the text guardian.log records for the refusal.
                _snapshotCompletion.TrySetException(
                    new InvalidDataException(
                        "Codex Desktop returned an incompatible owner-state snapshot (" +
                        (incompatibleReason.Length == 0 ? "unspecified" : incompatibleReason) +
                        ")."));
                Invalidate();
                return;
            }

            if (Interlocked.CompareExchange(ref _snapshotReceived, 1, 0) == 0)
            {
                _ownerClientId = snapshot.OwnerClientId;
                _snapshotCompletion.TrySetResult(snapshot);
                return;
            }
        }

        Invalidate();
    }

    private void OnConnectionChanged(object? sender, bool connected)
    {
        if (connected)
        {
            return;
        }

        _snapshotCompletion.TrySetException(new IOException("The Codex Desktop IPC connection closed."));
        Invalidate();
    }

    private void Invalidate() => Interlocked.Exchange(ref _invalidated, 1);
}
