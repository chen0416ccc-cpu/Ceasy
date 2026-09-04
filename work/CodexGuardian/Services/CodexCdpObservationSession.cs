using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using CodexGuardian.Control;

namespace CodexGuardian.Services;

internal sealed class CodexCdpObservationSession : IAsyncDisposable
{
    internal static readonly TimeSpan RendererVerificationTimeout = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan ForcedSnapshotTimeout = TimeSpan.FromSeconds(1);
    private const int MaximumTargetIdCharacters = 80;
    private const int MaximumSessionIdCharacters = 256;
    private const string ForceSnapshotExpression =
        "globalThis.__codexGuardianCdpObservationRuntime?.requestSnapshot?.()";

    private readonly ICdpCommandTransport _transport;
    private readonly CodexCdpRuntimeResources _resources;
    private readonly CodexCdpRendererRegistry _registry;
    private readonly TimeSpan _rendererVerificationTimeout;
    private readonly TimeSpan _forcedSnapshotTimeout;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _targetsSync = new();
    private readonly Dictionary<string, TargetInfo> _targets = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Task> _installations = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _targetGate = new(1, 1);
    private Task? _notificationLoop;
    private Exception? _failure;
    private int _started;
    private int _disposed;

    internal CodexCdpObservationSession(
        ICdpCommandTransport transport,
        CodexCdpRuntimeResources resources,
        CodexCdpRendererRegistry registry,
        TimeSpan? rendererVerificationTimeout = null,
        TimeSpan? forcedSnapshotTimeout = null)
    {
        _transport = transport;
        _resources = resources;
        _registry = registry;
        _rendererVerificationTimeout = rendererVerificationTimeout ?? RendererVerificationTimeout;
        _forcedSnapshotTimeout = forcedSnapshotTimeout ?? ForcedSnapshotTimeout;
        if (_rendererVerificationTimeout <= TimeSpan.Zero ||
            _forcedSnapshotTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(rendererVerificationTimeout),
                "CDP verification timeouts must be positive.");
        }
    }

    internal Exception? Failure => Volatile.Read(ref _failure);

    internal async Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            throw new InvalidOperationException("The CDP observation session has already started.");
        }

        _notificationLoop = ProcessNotificationsAsync(_lifetime.Token);
        try
        {
            await _transport.SendCommandAsync(
                    "Target.setDiscoverTargets",
                    new { discover = true },
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var result = await _transport.SendCommandAsync(
                    "Target.getTargets",
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var targets = ReadInitialTargets(result);
            lock (_targetsSync)
            {
                foreach (var target in targets)
                {
                    _targets[target.TargetId] = target;
                }
            }

            ApplyExpectedTargets();
            if (targets.Count == 0)
            {
                throw new InvalidDataException("CDP reported no active Codex app renderer.");
            }

            await Task.WhenAll(targets.Select(target => EnsureAttachedAsync(target, cancellationToken)))
                .ConfigureAwait(false);
            await WaitForVerifiedRenderersAsync(_rendererVerificationTimeout, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            MarkFailure(exception);
            throw;
        }
    }

    internal async Task<bool> ForceFreshSnapshotsAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfUnavailable();
        var before = _registry.CaptureSessions();
        if (before.Count == 0 || before.Count != _registry.RendererCount ||
            before.Any(session => !session.HelloVerified || !session.FullSnapshotVerified))
        {
            return false;
        }

        try
        {
            foreach (var session in before)
            {
                var result = await _transport.SendSessionCommandAsync(
                        session.SessionId,
                        "Runtime.evaluate",
                        new
                        {
                            expression = ForceSnapshotExpression,
                            awaitPromise = false,
                            returnByValue = false,
                            userGesture = false
                        },
                        cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                if (result.TryGetProperty("exceptionDetails", out _))
                {
                    throw new InvalidDataException("A renderer rejected the fixed snapshot request.");
                }
            }

            var deadline = DateTimeOffset.UtcNow + _forcedSnapshotTimeout;
            while (DateTimeOffset.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ThrowIfUnavailable();
                var current = _registry.CaptureSessions();
                if (current.Count == before.Count && before.All(previous =>
                        current.Any(next =>
                            next.TargetId == previous.TargetId &&
                            next.SessionId == previous.SessionId &&
                            next.SnapshotGeneration > previous.SnapshotGeneration)))
                {
                    return _registry.IsFullyVerified(DateTimeOffset.UtcNow);
                }

                await Task.Delay(TimeSpan.FromMilliseconds(20), cancellationToken).ConfigureAwait(false);
            }

            return false;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            MarkFailure(exception);
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetime.Cancel();
        _registry.ReplaceTargets([], discoveryComplete: false);
        var pending = _installations.Values.ToList();
        if (_notificationLoop is not null)
        {
            pending.Add(_notificationLoop);
        }

        try
        {
            await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }

        _targetGate.Dispose();
        _lifetime.Dispose();
    }

    private async Task ProcessNotificationsAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var message in _transport.Notifications.ReadAllAsync(cancellationToken)
                               .ConfigureAwait(false))
            {
                if (!TryGetString(message, "method", out var method))
                {
                    throw new InvalidDataException("CDP emitted a notification without a method.");
                }

                if (method is "Target.targetCreated" or "Target.targetInfoChanged")
                {
                    var targetInfo = ReadTargetInfo(message);
                    InvalidateExpectedTargets();
                    ObserveBackground(HandleTargetInfoAsync(targetInfo, cancellationToken));
                }
                else if (method == "Target.targetDestroyed")
                {
                    var targetId = ReadNotificationIdentifier(message, "targetId", MaximumTargetIdCharacters);
                    InvalidateExpectedTargets();
                    ObserveBackground(RemoveTargetAsync(targetId, detachSession: false, cancellationToken));
                }
                else if (method == "Target.detachedFromTarget")
                {
                    var sessionId = ReadNotificationIdentifier(message, "sessionId", MaximumSessionIdCharacters);
                    InvalidateExpectedTargets();
                    HandleDetachedSession(sessionId, cancellationToken);
                }
                else if (method == "Target.attachedToTarget")
                {
                    var targetInfo = ReadTargetInfo(message);
                    var sessionId = ReadNotificationIdentifier(
                        message,
                        "sessionId",
                        MaximumSessionIdCharacters);
                    InvalidateExpectedTargets();
                    ObserveBackground(HandleAttachedTargetAsync(
                        targetInfo,
                        sessionId,
                        cancellationToken));
                }
                else if (method == "Runtime.bindingCalled")
                {
                    ApplyBindingNotification(message);
                }
            }

            if (!cancellationToken.IsCancellationRequested)
            {
                throw new EndOfStreamException("The CDP notification channel closed.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            MarkFailure(exception);
        }
    }

    private IReadOnlyList<TargetInfo> ReadInitialTargets(JsonElement result)
    {
        if (!result.TryGetProperty("targetInfos", out var targetInfos) ||
            targetInfos.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Target.getTargets returned an invalid target inventory.");
        }

        var targets = new List<TargetInfo>();
        foreach (var element in targetInfos.EnumerateArray())
        {
            var target = ReadTargetInfoElement(element);
            if (target.IsCandidate)
            {
                targets.Add(target);
            }
        }

        if (targets.Count > CodexCdpRendererRegistry.MaximumRenderers ||
            targets.Select(target => target.TargetId).Distinct(StringComparer.Ordinal).Count() != targets.Count)
        {
            throw new InvalidDataException("The active Codex renderer inventory is invalid or unbounded.");
        }

        return targets;
    }

    private async Task HandleTargetInfoAsync(TargetInfo target, CancellationToken cancellationToken)
    {
        await _targetGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (target.IsCandidate)
            {
                lock (_targetsSync)
                {
                    _targets[target.TargetId] = target;
                }
                ApplyExpectedTargets();
                await EnsureAttachedAsync(target, cancellationToken).ConfigureAwait(false);
                return;
            }

            await RemoveTargetCoreAsync(target.TargetId, detachSession: true, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _targetGate.Release();
        }
    }

    private async Task RemoveTargetAsync(
        string targetId,
        bool detachSession,
        CancellationToken cancellationToken)
    {
        await _targetGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await RemoveTargetCoreAsync(targetId, detachSession, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _targetGate.Release();
        }
    }

    private async Task RemoveTargetCoreAsync(
        string targetId,
        bool detachSession,
        CancellationToken cancellationToken)
    {
        var session = _registry.CaptureSessions().FirstOrDefault(item => item.TargetId == targetId);
        lock (_targetsSync)
        {
            _targets.Remove(targetId);
        }
        _installations.TryRemove(targetId, out _);
        _registry.RemoveTarget(targetId);
        ApplyExpectedTargets();
        if (detachSession && session is not null)
        {
            await _transport.SendCommandAsync(
                    "Target.detachFromTarget",
                    new { sessionId = session.SessionId },
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private void HandleDetachedSession(string sessionId, CancellationToken cancellationToken)
    {
        var targetId = _registry.CaptureSessions()
            .FirstOrDefault(session => session.SessionId == sessionId)?.TargetId;
        _registry.RemoveSession(sessionId);
        if (targetId is null)
        {
            ApplyExpectedTargets();
            return;
        }

        _installations.TryRemove(targetId, out _);
        ApplyExpectedTargets();
        TargetInfo? target;
        lock (_targetsSync)
        {
            target = _targets.GetValueOrDefault(targetId);
        }
        if (target is not null)
        {
            ObserveBackground(EnsureAttachedAsync(target, cancellationToken));
        }
    }

    private async Task HandleAttachedTargetAsync(
        TargetInfo target,
        string sessionId,
        CancellationToken cancellationToken)
    {
        await _targetGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (target.IsCandidate)
            {
                lock (_targetsSync)
                {
                    _targets[target.TargetId] = target;
                }
            }

            ApplyExpectedTargets();
            await ClaimAndInstallAsync(target, sessionId, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _targetGate.Release();
        }
    }

    private Task EnsureAttachedAsync(TargetInfo target, CancellationToken cancellationToken) =>
        _installations.GetOrAdd(target.TargetId, _ => AttachAndInstallAsync(target, cancellationToken));

    private async Task AttachAndInstallAsync(TargetInfo target, CancellationToken cancellationToken)
    {
        var result = await _transport.SendCommandAsync(
                "Target.attachToTarget",
                new { targetId = target.TargetId, flatten = true },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (!TryGetBoundedIdentifier(result, "sessionId", MaximumSessionIdCharacters, out var sessionId))
        {
            throw new InvalidDataException("Target.attachToTarget did not return a valid session id.");
        }

        await ClaimAndInstallAsync(target, sessionId, cancellationToken).ConfigureAwait(false);
    }

    private async Task ClaimAndInstallAsync(
        TargetInfo target,
        string sessionId,
        CancellationToken cancellationToken)
    {
        if (!target.IsCandidate)
        {
            await DetachSessionAsync(sessionId, cancellationToken).ConfigureAwait(false);
            return;
        }

        var claim = _registry.ClaimSession(target.TargetId, sessionId);
        if (claim == RendererClaimResult.DuplicateSession)
        {
            await DetachSessionAsync(sessionId, cancellationToken).ConfigureAwait(false);
            return;
        }
        if (claim is RendererClaimResult.AlreadyClaimed)
        {
            return;
        }
        if (claim != RendererClaimResult.Accepted)
        {
            throw new InvalidDataException("CDP supplied an invalid target attachment.");
        }

        try
        {
            await _transport.SendSessionCommandAsync(
                    sessionId,
                    "Runtime.enable",
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            await _transport.SendSessionCommandAsync(
                    sessionId,
                    "Page.enable",
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            await _transport.SendSessionCommandAsync(
                    sessionId,
                    "Runtime.addBinding",
                    new { name = CodexCdpObservationProtocol.BindingName },
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var script = await _transport.SendSessionCommandAsync(
                    sessionId,
                    "Page.addScriptToEvaluateOnNewDocument",
                    new { source = _resources.HookSource },
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (!TryGetString(script, "identifier", out _))
            {
                throw new InvalidDataException("The renderer did not accept the fixed runtime Hook.");
            }

            _registry.MarkInstalled(sessionId);
            var evaluation = await _transport.SendSessionCommandAsync(
                    sessionId,
                    "Runtime.evaluate",
                    new
                    {
                        expression = _resources.HookSource,
                        awaitPromise = false,
                        returnByValue = false,
                        userGesture = false
                    },
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (evaluation.TryGetProperty("exceptionDetails", out _))
            {
                throw new InvalidDataException("The renderer rejected the fixed runtime Hook.");
            }
        }
        catch
        {
            _registry.RemoveSession(sessionId);
            throw;
        }
    }

    private Task DetachSessionAsync(string sessionId, CancellationToken cancellationToken) =>
        _transport.SendCommandAsync(
            "Target.detachFromTarget",
            new { sessionId },
            cancellationToken: cancellationToken);

    private void ApplyBindingNotification(JsonElement message)
    {
        var reason = "shape";
        if (!message.TryGetProperty("params", out var parameters) ||
            parameters.ValueKind != JsonValueKind.Object ||
            !TryGetString(parameters, "name", out var name) ||
            name != CodexCdpObservationProtocol.BindingName)
        {
            return;
        }

        if (!TryGetBoundedIdentifier(message, "sessionId", MaximumSessionIdCharacters, out var sessionId) ||
            !TryGetString(parameters, "payload", out var payload) ||
            !parameters.TryGetProperty("executionContextId", out var contextElement) ||
            !contextElement.TryGetInt32(out var executionContextId) ||
            !_registry.ApplyBindingPayload(
                sessionId,
                executionContextId,
                payload,
                DateTimeOffset.UtcNow,
                out reason))
        {
            throw new InvalidDataException(
                "A renderer emitted an invalid observation binding payload (" + reason + ").");
        }
    }

    private async Task WaitForVerifiedRenderersAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfFailed();
            if (_registry.IsFullyVerified(DateTimeOffset.UtcNow))
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(20), cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException("Not every active Codex app renderer completed hello and full snapshot verification.");
    }

    private void ApplyExpectedTargets()
    {
        string[] targets;
        lock (_targetsSync)
        {
            targets = _targets.Values
                .Where(target => target.IsCandidate)
                .Select(target => target.TargetId)
                .ToArray();
        }
        if (!_registry.ReplaceTargets(targets, discoveryComplete: true))
        {
            throw new InvalidDataException("The active Codex renderer inventory is invalid or unbounded.");
        }
    }

    private void InvalidateExpectedTargets()
    {
        string[] targets;
        lock (_targetsSync)
        {
            targets = _targets.Values
                .Where(target => target.IsCandidate)
                .Select(target => target.TargetId)
                .ToArray();
        }
        if (!_registry.ReplaceTargets(targets, discoveryComplete: false))
        {
            throw new InvalidDataException("The active Codex renderer inventory is invalid or unbounded.");
        }
    }

    private TargetInfo ReadTargetInfo(JsonElement message)
    {
        if (!message.TryGetProperty("params", out var parameters) ||
            parameters.ValueKind != JsonValueKind.Object ||
            !parameters.TryGetProperty("targetInfo", out var targetInfo))
        {
            throw new InvalidDataException("CDP emitted an invalid target notification.");
        }

        return ReadTargetInfoElement(targetInfo);
    }

    private static TargetInfo ReadTargetInfoElement(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !TryGetBoundedIdentifier(element, "targetId", MaximumTargetIdCharacters, out var targetId) ||
            !TryGetString(element, "type", out var type) ||
            !TryGetJsonString(element, "url", out var url) ||
            url.Length > 2048)
        {
            throw new InvalidDataException("CDP emitted an invalid target descriptor.");
        }

        return new TargetInfo(
            targetId,
            type,
            type == "page" && url.StartsWith("app://", StringComparison.Ordinal));
    }

    private static string ReadNotificationIdentifier(
        JsonElement message,
        string propertyName,
        int maximumLength)
    {
        if (!message.TryGetProperty("params", out var parameters) ||
            !TryGetBoundedIdentifier(parameters, propertyName, maximumLength, out var value))
        {
            throw new InvalidDataException("CDP emitted an invalid " + propertyName + ".");
        }

        return value;
    }

    private static bool TryGetBoundedIdentifier(
        JsonElement element,
        string propertyName,
        int maximumLength,
        out string value)
    {
        value = string.Empty;
        return TryGetString(element, propertyName, out value) &&
               value.Length is >= 8 &&
               value.Length <= maximumLength &&
               value.All(static character => char.IsLetterOrDigit(character) || character is '-' or '_');
    }

    private static bool TryGetString(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;
        return element.ValueKind == JsonValueKind.Object &&
               element.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.String &&
               (value = property.GetString() ?? string.Empty).Length > 0;
    }

    private static bool TryGetJsonString(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return true;
    }

    private void ObserveBackground(Task task)
    {
        _ = task.ContinueWith(
            completed =>
            {
                if (completed.Exception is { } aggregate)
                {
                    var failure = aggregate.GetBaseException();
                    if (!_lifetime.IsCancellationRequested || failure is not OperationCanceledException)
                    {
                        MarkFailure(failure);
                    }
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private void MarkFailure(Exception exception)
    {
        if (Interlocked.CompareExchange(ref _failure, exception, null) is not null)
        {
            return;
        }

        _registry.ReplaceTargets([], discoveryComplete: false);
        _lifetime.Cancel();
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Volatile.Read(ref _started) == 0)
        {
            throw new InvalidOperationException("The CDP observation session has not started.");
        }
        ThrowIfFailed();
    }

    private void ThrowIfFailed()
    {
        if (Failure is { } failure)
        {
            throw new InvalidOperationException("The CDP observation session failed closed.", failure);
        }
    }

    private sealed record TargetInfo(string TargetId, string Type, bool IsCandidate);
}
