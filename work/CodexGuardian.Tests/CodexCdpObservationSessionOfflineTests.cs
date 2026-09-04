using CodexGuardian.Control;
using CodexGuardian.Services;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;

internal static class CodexCdpObservationSessionOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync("CDP session verifies every renderer and refreshes snapshots", TestHappyPathAsync, assert);
        await RunCaseAsync(
            "CDP protocol accepts the version-free capability hello",
            TestVersionFreeHelloAsync,
            assert);
        await RunCaseAsync(
            "CDP protocol rejects the legacy version-pinned hello",
            TestLegacyVersionHelloAsync,
            assert);
        await RunCaseAsync(
            "CDP runtime profile requires the exact schema 2 capability contract",
            TestStrictRuntimeProfileAsync,
            assert);
        await RunCaseAsync("CDP session fails closed on an incomplete renderer", TestIncompleteRendererAsync, assert);
        await RunCaseAsync("CDP session rejects a mismatched runtime hello", TestMismatchedHelloAsync, assert);
        await RunCaseAsync("CDP session rejects a zero-renderer inventory", TestZeroRendererAsync, assert);
        await RunCaseAsync("CDP observation service refreshes before returning clear", TestServiceCompositionAsync, assert);
    }

    private static async Task TestHappyPathAsync(CancellationToken cancellationToken)
    {
        var script = new RendererScript();
        var state = CreateStateStore();
        var registry = new CodexCdpRendererRegistry(state);
        await using var session = new CodexCdpObservationSession(
            script.Transport,
            CodexCdpRuntimeResources.Load(),
            registry,
            rendererVerificationTimeout: TimeSpan.FromSeconds(2),
            forcedSnapshotTimeout: TimeSpan.FromSeconds(1));
        await session.StartAsync(cancellationToken).ConfigureAwait(false);

        Ensure(registry.RendererCount == 2, "the complete renderer inventory was not retained");
        Ensure(registry.IsFullyVerified(DateTimeOffset.UtcNow), "the complete renderer set was not verified");
        Ensure(
            state.CheckInterference(RendererScript.ThreadA, DateTimeOffset.UtcNow).Status ==
                RecoveryInterferenceStatus.Clear,
            "the clear renderer did not publish target-specific composer state");
        Ensure(
            state.CheckInterference(RendererScript.ThreadB, DateTimeOffset.UtcNow).Status ==
                RecoveryInterferenceStatus.Editing,
            "the edited renderer did not block target-specific dispatch");

        var generations = registry.CaptureSessions()
            .ToDictionary(item => item.TargetId, item => item.SnapshotGeneration, StringComparer.Ordinal);
        Ensure(
            await session.ForceFreshSnapshotsAsync(cancellationToken).ConfigureAwait(false),
            "the fixed runtime snapshot request did not complete");
        Ensure(
            registry.CaptureSessions().All(item => item.SnapshotGeneration > generations[item.TargetId]),
            "the forced snapshot did not advance every renderer");

        var methods = script.Transport.Commands.Select(command => command.Method).ToHashSet(StringComparer.Ordinal);
        Ensure(!methods.Contains("Target.setAutoAttach"), "the session used a second attachment owner");
        Ensure(methods.SetEquals(new[]
        {
            "Target.setDiscoverTargets",
            "Target.getTargets",
            "Target.attachToTarget",
            "Runtime.enable",
            "Page.enable",
            "Runtime.addBinding",
            "Page.addScriptToEvaluateOnNewDocument",
            "Runtime.evaluate"
        }), "the session emitted a command outside the fixed observation allowlist");

        script.Transport.Emit(new
        {
            method = "Target.targetDestroyed",
            @params = new { targetId = RendererScript.TargetB }
        });
        await WaitUntilAsync(() => registry.RendererCount == 1, cancellationToken).ConfigureAwait(false);
        Ensure(
            registry.IsFullyVerified(DateTimeOffset.UtcNow) &&
            state.CheckInterference(RendererScript.ThreadA, DateTimeOffset.UtcNow).Status ==
                RecoveryInterferenceStatus.Clear,
            "destroying a renderer did not atomically replace the expected inventory");

        var nextSequence = script.NextSequence(RendererScript.SessionA);
        script.EmitBinding(
            RendererScript.SessionA,
            contextId: 999,
            JsonSerializer.Serialize(new
            {
                kind = "threadState",
                seq = nextSequence,
                threadId = RendererScript.ThreadA,
                status = "idle",
                notificationEnvelope = "top"
            }));
        await WaitUntilAsync(() => session.Failure is not null, cancellationToken).ConfigureAwait(false);
        Ensure(
            !registry.IsFullyVerified(DateTimeOffset.UtcNow) &&
            state.CheckInterference(RendererScript.ThreadA, DateTimeOffset.UtcNow).Status ==
                RecoveryInterferenceStatus.Unknown,
            "an execution-context change did not invalidate all renderer authority");
    }

    private static Task TestVersionFreeHelloAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var payload = JsonSerializer.Serialize(new
        {
            kind = "hello",
            seq = 1,
            protocol = 1,
            hookVersion = CodexCdpObservationProtocol.HookVersion,
            contractId = CodexCdpObservationProtocol.ContractId,
            source = "cdp-main-world",
            pageProtocol = "app",
            bridgePresent = true
        });

        Ensure(
            CodexCdpObservationProtocol.TryValidate(payload, out var observation, out var reason) &&
            observation is { Kind: "hello", Sequence: 1 } &&
            reason == "accepted",
            "the version-free capability hello was rejected (" + reason + ")");
        return Task.CompletedTask;
    }

    private static Task TestLegacyVersionHelloAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var payload = JsonSerializer.Serialize(new
        {
            kind = "hello",
            seq = 1,
            protocol = 1,
            hookVersion = CodexCdpObservationProtocol.HookVersion,
            packageVersion = "26.730.8199.0",
            appBuild = "26.730.61639",
            source = "cdp-main-world",
            pageProtocol = "app",
            bridgePresent = true
        });
        var mixedPayload = JsonSerializer.Serialize(new
        {
            kind = "hello",
            seq = 1,
            protocol = 1,
            hookVersion = CodexCdpObservationProtocol.HookVersion,
            contractId = CodexCdpObservationProtocol.ContractId,
            packageVersion = "26.730.8199.0",
            appBuild = "26.730.61639",
            source = "cdp-main-world",
            pageProtocol = "app",
            bridgePresent = true
        });

        Ensure(
            !CodexCdpObservationProtocol.TryValidate(payload, out var observation, out var reason) &&
            observation is null &&
            reason == "fields" &&
            !CodexCdpObservationProtocol.TryValidate(mixedPayload, out _, out var mixedReason) &&
            mixedReason == "fields",
            "the legacy version-pinned hello was accepted");
        return Task.CompletedTask;
    }

    private static Task TestStrictRuntimeProfileAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        const string resourceName = "CodexGuardian.HookPayload.cdp-runtime-profile.json";
        using var stream = typeof(CodexCdpRuntimeResources).Assembly
            .GetManifestResourceStream(resourceName) ??
            throw new InvalidOperationException("the embedded runtime profile is missing");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        var profileBytes = memory.ToArray();
        var profileText = Encoding.ASCII.GetString(profileBytes);
        var profile = CodexCdpRuntimeResources.ParseProfile(profileBytes);
        Ensure(
            profile.Schema == 2 &&
            profile.ContractId == CodexCdpObservationProtocol.ContractId &&
            profile.PreloadMarkers.Length == 4,
            "the exact schema 2 capability profile was not accepted");

        var unknown = JsonNode.Parse(profileText)?.AsObject() ??
            throw new InvalidOperationException("the embedded runtime profile is not an object");
        unknown["packageVersion"] = "26.730.8199.0";
        ExpectInvalidProfile(unknown.ToJsonString());

        var missing = JsonNode.Parse(profileText)?.AsObject() ??
            throw new InvalidOperationException("the embedded runtime profile is not an object");
        Ensure(missing.Remove("contractId"), "the contractId fixture was missing");
        ExpectInvalidProfile(missing.ToJsonString());

        ExpectInvalidProfile(profileText.Replace("\"mode\"", "\"Mode\"", StringComparison.Ordinal));
        ExpectInvalidProfile(profileText.Replace(
            "\"mode\": \"read-only-cdp-pipe-runtime\"",
            "\"mode\": \"read-only-cdp-pipe-runtime\", \"\\u006dode\": \"duplicate\"",
            StringComparison.Ordinal));

        var propertyNames = typeof(CodexCdpRuntimeProfile).GetProperties()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        Ensure(
            !propertyNames.Overlaps(
                [
                    "PackageFullName",
                    "PackageVersion",
                    "PackageSignatureKind",
                    "AppBuild",
                    "ManifestSha256",
                    "ChatGptExeSha256",
                    "CodexExeSha256",
                    "AppAsarSha256"
                ]),
            "a mutable package pin remains in the schema 2 runtime profile model");
        return Task.CompletedTask;
    }

    private static void ExpectInvalidProfile(string profile)
    {
        try
        {
            _ = CodexCdpRuntimeResources.ParseProfile(Encoding.ASCII.GetBytes(profile));
        }
        catch (InvalidDataException)
        {
            return;
        }

        throw new InvalidOperationException("an inexact runtime profile was accepted");
    }

    private static async Task TestIncompleteRendererAsync(CancellationToken cancellationToken)
    {
        var script = new RendererScript { OmitSecondSnapshot = true };
        var state = CreateStateStore();
        var registry = new CodexCdpRendererRegistry(state);
        await using var session = new CodexCdpObservationSession(
            script.Transport,
            CodexCdpRuntimeResources.Load(),
            registry,
            rendererVerificationTimeout: TimeSpan.FromMilliseconds(150),
            forcedSnapshotTimeout: TimeSpan.FromMilliseconds(100));
        await ExpectAsync<TimeoutException>(() => session.StartAsync(cancellationToken));
        Ensure(
            session.Failure is not null &&
            !registry.IsFullyVerified(DateTimeOffset.UtcNow) &&
            state.CheckInterference(RendererScript.ThreadA, DateTimeOffset.UtcNow).Status ==
                RecoveryInterferenceStatus.Unknown,
            "an incomplete renderer retained observation authority");
    }

    private static async Task TestMismatchedHelloAsync(CancellationToken cancellationToken)
    {
        var script = new RendererScript { UseMismatchedSecondHello = true };
        var state = CreateStateStore();
        var registry = new CodexCdpRendererRegistry(state);
        await using var session = new CodexCdpObservationSession(
            script.Transport,
            CodexCdpRuntimeResources.Load(),
            registry,
            rendererVerificationTimeout: TimeSpan.FromSeconds(1),
            forcedSnapshotTimeout: TimeSpan.FromMilliseconds(100));
        await ExpectAsync<InvalidOperationException>(() => session.StartAsync(cancellationToken));
        Ensure(
            session.Failure is not null && !registry.IsFullyVerified(DateTimeOffset.UtcNow),
            "a mismatched hello did not fail the observation session closed");
    }

    private static async Task TestZeroRendererAsync(CancellationToken cancellationToken)
    {
        var script = new RendererScript { ReturnNoRenderers = true };
        var state = CreateStateStore();
        var registry = new CodexCdpRendererRegistry(state);
        await using var session = new CodexCdpObservationSession(
            script.Transport,
            CodexCdpRuntimeResources.Load(),
            registry,
            rendererVerificationTimeout: TimeSpan.FromMilliseconds(100),
            forcedSnapshotTimeout: TimeSpan.FromMilliseconds(100));
        await ExpectAsync<InvalidDataException>(() => session.StartAsync(cancellationToken));
        Ensure(registry.RendererCount == 0 && session.Failure is not null,
            "a zero-renderer inventory did not enter a terminal unavailable state");
    }

    private static async Task TestServiceCompositionAsync(CancellationToken cancellationToken)
    {
        var script = new RendererScript();
        var connection = new FakeRuntimeConnection(script.Transport, processId: 4242);
        var host = new FakeRuntimeHost(connection);
        var availabilityChanges = 0;
        await using (var service = new CodexCdpObservationService(host))
        {
            service.AvailabilityChanged += (_, _) => availabilityChanges++;
            Ensure(await service.StartAsync(cancellationToken).ConfigureAwait(false),
                "the service did not start its injected runtime");
            Ensure(service.IsAvailable && service.OwnedProcessId == 4242,
                "the service did not publish its verified owned runtime");
            var before = script.Transport.Commands.Count;
            var observation = await service.CheckAsync(RendererScript.ThreadA, cancellationToken)
                .ConfigureAwait(false);
            var refreshCommands = script.Transport.Commands.Skip(before).ToArray();
            Ensure(
                observation.Status == RecoveryInterferenceStatus.Clear &&
                refreshCommands.Length == 2 &&
                refreshCommands.All(command =>
                    command.Method == "Runtime.evaluate" &&
                    command.Parameters.GetProperty("expression").GetString() ==
                        "globalThis.__codexGuardianCdpObservationRuntime?.requestSnapshot?.()"),
                "clear was returned without one fixed refresh request per renderer");
        }

        Ensure(
            availabilityChanges >= 1 && connection.Disposed && host.Disposed,
            "service disposal did not close its session, connection, and injected host");
    }

    private static CodexDeepObservationStateStore CreateStateStore() => new(
        CodexDeepObservationService.ProtocolVersion,
        CodexDeepObservationService.ContractId,
        CodexDeepObservationService.SnapshotMaxAge);

    private static async Task RunCaseAsync(
        string name,
        Func<CancellationToken, Task> test,
        Action<bool, string> assert)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        try
        {
            await test(timeout.Token).ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static async Task ExpectAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException("Expected " + typeof(TException).Name + ".");
    }

    private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(2);
        while (!condition())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException("The scripted CDP state did not converge.");
            }
            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class RendererScript
    {
        internal const string TargetA = "renderer-target-a";
        internal const string TargetB = "renderer-target-b";
        internal const string SessionA = "renderer-session-a";
        internal const string SessionB = "renderer-session-b";
        internal const string ThreadA = "019fcdef-1000-7000-8000-000000000001";
        internal const string ThreadB = "019fcdef-1000-7000-8000-000000000002";
        private readonly ConcurrentDictionary<string, long> _sequences = new(StringComparer.Ordinal);
        private readonly IReadOnlyDictionary<string, string> _sessionsByTarget =
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [TargetA] = SessionA,
                [TargetB] = SessionB
            };

        internal RendererScript()
        {
            Transport = new ScriptedTransport(HandleCommandAsync);
        }

        internal ScriptedTransport Transport { get; }
        internal bool OmitSecondSnapshot { get; init; }
        internal bool UseMismatchedSecondHello { get; init; }
        internal bool ReturnNoRenderers { get; init; }

        internal long NextSequence(string sessionId) =>
            _sequences.AddOrUpdate(sessionId, 1, static (_, current) => checked(current + 1));

        internal void EmitBinding(string sessionId, int contextId, string payload) =>
            Transport.Emit(new
            {
                method = "Runtime.bindingCalled",
                sessionId,
                @params = new
                {
                    name = CodexCdpObservationProtocol.BindingName,
                    payload,
                    executionContextId = contextId
                }
            });

        private Task<JsonElement> HandleCommandAsync(ScriptedCommand command)
        {
            if (command.Method == "Target.getTargets")
            {
                return Result(ReturnNoRenderers
                    ? new
                    {
                        targetInfos = new[]
                        {
                            new { targetId = "worker-target-1", type = "service_worker", url = "" }
                        }
                    }
                    : new
                    {
                        targetInfos = new[]
                        {
                            new { targetId = TargetA, type = "page", url = "app://-/local/a" },
                            new { targetId = TargetB, type = "page", url = "app://-/local/b" },
                            new { targetId = "worker-target-1", type = "service_worker", url = "" }
                        }
                    });
            }

            if (command.Method == "Target.attachToTarget")
            {
                var targetId = command.Parameters.GetProperty("targetId").GetString()!;
                return Result(new { sessionId = _sessionsByTarget[targetId] });
            }

            if (command.Method == "Page.addScriptToEvaluateOnNewDocument")
            {
                return Result(new { identifier = "runtime-script-1" });
            }

            if (command.Method == "Runtime.evaluate" && command.SessionId is not null)
            {
                var expression = command.Parameters.GetProperty("expression").GetString() ?? string.Empty;
                if (expression.Contains("codex-guardian-cdp-observation-runtime-v1", StringComparison.Ordinal))
                {
                    EmitInitialRendererState(command.SessionId);
                }
                else if (expression.Contains("requestSnapshot", StringComparison.Ordinal))
                {
                    EmitSnapshot(command.SessionId);
                }
                return Result(new { result = new { type = "undefined" } });
            }

            return Result(new { });
        }

        private void EmitInitialRendererState(string sessionId)
        {
            _sequences[sessionId] = 0;
            var mismatched = UseMismatchedSecondHello && sessionId == SessionB;
            EmitBinding(
                sessionId,
                ContextFor(sessionId),
                JsonSerializer.Serialize(new
                {
                    kind = "hello",
                    seq = NextSequence(sessionId),
                    protocol = 1,
                    hookVersion = mismatched ? "wrong-runtime" : CodexCdpObservationProtocol.HookVersion,
                    contractId = CodexCdpObservationProtocol.ContractId,
                    source = "cdp-main-world",
                    pageProtocol = "app",
                    bridgePresent = true
                }));
            if (!OmitSecondSnapshot || sessionId != SessionB)
            {
                EmitSnapshot(sessionId);
            }
        }

        private void EmitSnapshot(string sessionId)
        {
            var isSecond = sessionId == SessionB;
            EmitBinding(
                sessionId,
                ContextFor(sessionId),
                JsonSerializer.Serialize(new
                {
                    kind = "snapshot",
                    seq = NextSequence(sessionId),
                    routeKnown = true,
                    threadId = isSecond ? ThreadB : ThreadA,
                    composerKnown = true,
                    editorPresent = true,
                    composerFocused = isSecond,
                    hasDraft = isSecond
                }));
        }

        private static int ContextFor(string sessionId) => sessionId == SessionB ? 22 : 11;

        private static Task<JsonElement> Result(object value) =>
            Task.FromResult(JsonSerializer.SerializeToElement(value));
    }

    private sealed class ScriptedTransport(
        Func<ScriptedCommand, Task<JsonElement>> handler) : ICdpCommandTransport
    {
        private readonly Channel<JsonElement> _notifications = Channel.CreateUnbounded<JsonElement>();
        private readonly Func<ScriptedCommand, Task<JsonElement>> _handler = handler;

        internal ConcurrentQueue<ScriptedCommand> Commands { get; } = new();
        public ChannelReader<JsonElement> Notifications => _notifications.Reader;

        public Task<JsonElement> SendCommandAsync(
            string method,
            object? parameters = null,
            TimeSpan? timeout = null,
            CancellationToken cancellationToken = default) =>
            SendAsync(sessionId: null, method, parameters, cancellationToken);

        public Task<JsonElement> SendSessionCommandAsync(
            string sessionId,
            string method,
            object? parameters = null,
            TimeSpan? timeout = null,
            CancellationToken cancellationToken = default) =>
            SendAsync(sessionId, method, parameters, cancellationToken);

        internal void Emit(object notification)
        {
            Ensure(
                _notifications.Writer.TryWrite(JsonSerializer.SerializeToElement(notification)),
                "the scripted notification channel was closed");
        }

        private Task<JsonElement> SendAsync(
            string? sessionId,
            string method,
            object? parameters,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var command = new ScriptedCommand(
                sessionId,
                method,
                parameters is null
                    ? JsonSerializer.SerializeToElement(new { })
                    : JsonSerializer.SerializeToElement(parameters, parameters.GetType()));
            Commands.Enqueue(command);
            return _handler(command);
        }
    }

    private sealed record ScriptedCommand(string? SessionId, string Method, JsonElement Parameters);

    private sealed class FakeRuntimeConnection(
        ICdpCommandTransport transport,
        int processId) : ICodexCdpRuntimeConnection
    {
        public ICdpCommandTransport Transport { get; } = transport;
        public int ProcessId { get; } = processId;
        internal bool Disposed { get; private set; }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeRuntimeHost(
        ICodexCdpRuntimeConnection connection) : ICodexCdpRuntimeHost
    {
        private readonly ICodexCdpRuntimeConnection _connection = connection;
        internal bool Disposed { get; private set; }

        public Task<ICodexCdpRuntimeConnection> StartAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_connection);
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
