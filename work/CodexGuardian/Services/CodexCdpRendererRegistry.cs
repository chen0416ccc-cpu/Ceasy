using CodexGuardian.Control;

namespace CodexGuardian.Services;

internal sealed class CodexCdpRendererRegistry
{
    internal const int MaximumRenderers = 32;
    private readonly object _sync = new();
    private readonly CodexDeepObservationStateStore _stateStore;
    private readonly Dictionary<string, RendererState> _renderers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _targetsBySession = new(StringComparer.Ordinal);
    private bool _discoveryComplete;

    internal CodexCdpRendererRegistry(CodexDeepObservationStateStore stateStore)
    {
        _stateStore = stateStore;
    }

    internal int RendererCount
    {
        get
        {
            lock (_sync)
            {
                return _renderers.Count;
            }
        }
    }

    internal bool ReplaceTargets(IEnumerable<string> targetIds, bool discoveryComplete)
    {
        ArgumentNullException.ThrowIfNull(targetIds);
        var supplied = targetIds.ToArray();
        if (supplied.Length > MaximumRenderers || supplied.Any(targetId => !IsIdentifier(targetId)))
        {
            FailDiscoveryClosed();
            return false;
        }

        var expected = supplied
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        string[] removed;
        lock (_sync)
        {
            removed = _renderers.Keys.Except(expected, StringComparer.Ordinal).ToArray();
            foreach (var targetId in removed)
            {
                if (_renderers.Remove(targetId, out var renderer) && renderer.SessionId is not null)
                {
                    _targetsBySession.Remove(renderer.SessionId);
                }
            }

            foreach (var targetId in expected)
            {
                _renderers.TryAdd(targetId, new RendererState(targetId));
            }

            _discoveryComplete = discoveryComplete;
        }

        foreach (var targetId in removed)
        {
            _stateStore.Disconnect(targetId);
        }

        _stateStore.ReplaceExpectedRenderers(expected, discoveryComplete);
        return true;
    }

    private void FailDiscoveryClosed()
    {
        string[] clients;
        lock (_sync)
        {
            clients = _renderers.Keys.ToArray();
            _renderers.Clear();
            _targetsBySession.Clear();
            _discoveryComplete = false;
        }

        foreach (var client in clients)
        {
            _stateStore.Disconnect(client);
        }
        _stateStore.ReplaceExpectedRenderers([], discoveryComplete: false);
    }

    internal RendererClaimResult ClaimSession(string targetId, string sessionId)
    {
        if (!IsIdentifier(targetId) || !IsIdentifier(sessionId))
        {
            return RendererClaimResult.Invalid;
        }

        lock (_sync)
        {
            if (!_renderers.TryGetValue(targetId, out var renderer))
            {
                return RendererClaimResult.UnexpectedTarget;
            }

            if (renderer.SessionId is not null)
            {
                return string.Equals(renderer.SessionId, sessionId, StringComparison.Ordinal)
                    ? RendererClaimResult.AlreadyClaimed
                    : RendererClaimResult.DuplicateSession;
            }

            if (_targetsBySession.ContainsKey(sessionId))
            {
                return RendererClaimResult.DuplicateSession;
            }

            renderer.SessionId = sessionId;
            _targetsBySession.Add(sessionId, targetId);
            return RendererClaimResult.Accepted;
        }
    }

    internal void MarkInstalled(string sessionId)
    {
        lock (_sync)
        {
            if (TryGetRendererBySessionLocked(sessionId, out var renderer))
            {
                renderer.Installed = true;
            }
        }
    }

    internal void RemoveSession(string sessionId)
    {
        string? targetId = null;
        lock (_sync)
        {
            if (_targetsBySession.Remove(sessionId, out targetId) &&
                _renderers.TryGetValue(targetId, out var renderer))
            {
                renderer.ResetSession();
            }
        }

        if (targetId is not null)
        {
            _stateStore.Disconnect(targetId);
        }
    }

    internal void RemoveTarget(string targetId)
    {
        lock (_sync)
        {
            if (_renderers.Remove(targetId, out var renderer) && renderer.SessionId is not null)
            {
                _targetsBySession.Remove(renderer.SessionId);
            }
        }

        _stateStore.Disconnect(targetId);
        string[] remaining;
        bool complete;
        lock (_sync)
        {
            remaining = _renderers.Keys.ToArray();
            complete = _discoveryComplete;
        }
        _stateStore.ReplaceExpectedRenderers(remaining, complete);
    }

    internal bool ApplyBindingPayload(
        string sessionId,
        int executionContextId,
        string payload,
        DateTimeOffset observedAt,
        out string reason)
    {
        reason = "unknown-session";
        if (executionContextId < 1 ||
            !CodexCdpObservationProtocol.TryValidate(payload, out var observation, out reason) ||
            observation is null)
        {
            return false;
        }

        string targetId;
        RendererState renderer;
        lock (_sync)
        {
            if (!_targetsBySession.TryGetValue(sessionId, out targetId!) ||
                !_renderers.TryGetValue(targetId, out renderer!))
            {
                reason = "unknown-session";
                return false;
            }

            if (!renderer.Installed)
            {
                reason = "not-installed";
                return false;
            }

            if (observation.Kind == "hello")
            {
                renderer.ExecutionContextId = executionContextId;
                renderer.HelloVerified = true;
                renderer.FullSnapshotVerified = false;
            }
            else if (!renderer.HelloVerified || renderer.ExecutionContextId != executionContextId)
            {
                reason = "execution-context";
                return false;
            }
        }

        if (observation.Kind == "hello")
        {
            var connected = _stateStore.ConnectVerifiedRenderer(
                targetId,
                observation.Sequence,
                observedAt,
                out reason);
            if (!connected)
            {
                lock (_sync)
                {
                    renderer.HelloVerified = false;
                }
            }
            return connected;
        }

        if (!_stateStore.Apply(targetId, observation.SanitizedJson, observedAt))
        {
            reason = "sequence";
            lock (_sync)
            {
                renderer.FullSnapshotVerified = false;
            }
            return false;
        }

        if (observation.Kind == "snapshot")
        {
            lock (_sync)
            {
                renderer.FullSnapshotVerified = true;
                renderer.SnapshotGeneration = checked(renderer.SnapshotGeneration + 1);
            }
        }

        reason = "accepted";
        return true;
    }

    internal IReadOnlyList<RendererSession> CaptureSessions()
    {
        lock (_sync)
        {
            return _renderers.Values
                .Where(renderer => renderer.SessionId is not null && renderer.Installed)
                .Select(renderer => new RendererSession(
                    renderer.TargetId,
                    renderer.SessionId!,
                    renderer.HelloVerified,
                    renderer.FullSnapshotVerified,
                    renderer.ExecutionContextId,
                    renderer.SnapshotGeneration))
                .ToArray();
        }
    }

    internal bool IsFullyVerified(DateTimeOffset observedAt)
    {
        lock (_sync)
        {
            return _discoveryComplete &&
                   _renderers.Count > 0 &&
                   _renderers.Values.All(renderer =>
                       renderer.Installed &&
                       renderer.HelloVerified &&
                       renderer.FullSnapshotVerified) &&
                   _stateStore.IsAvailable(observedAt);
        }
    }

    private bool TryGetRendererBySessionLocked(string sessionId, out RendererState renderer)
    {
        renderer = null!;
        if (!_targetsBySession.TryGetValue(sessionId, out var targetId) ||
            !_renderers.TryGetValue(targetId, out var found))
        {
            return false;
        }

        renderer = found;
        return true;
    }

    private static bool IsIdentifier(string? value) =>
        value is { Length: >= 8 and <= 80 } &&
        value.All(static character => char.IsLetterOrDigit(character) || character is '-' or '_');

    private sealed class RendererState(string targetId)
    {
        internal string TargetId { get; } = targetId;
        internal string? SessionId { get; set; }
        internal bool Installed { get; set; }
        internal bool HelloVerified { get; set; }
        internal bool FullSnapshotVerified { get; set; }
        internal int ExecutionContextId { get; set; }
        internal long SnapshotGeneration { get; set; }

        internal void ResetSession()
        {
            SessionId = null;
            Installed = false;
            HelloVerified = false;
            FullSnapshotVerified = false;
            ExecutionContextId = 0;
            SnapshotGeneration = 0;
        }
    }
}

internal enum RendererClaimResult
{
    Accepted,
    AlreadyClaimed,
    DuplicateSession,
    UnexpectedTarget,
    Invalid
}

internal sealed record RendererSession(
    string TargetId,
    string SessionId,
    bool HelloVerified,
    bool FullSnapshotVerified,
    int ExecutionContextId,
    long SnapshotGeneration);
