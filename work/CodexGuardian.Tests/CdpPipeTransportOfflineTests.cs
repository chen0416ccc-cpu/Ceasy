using CodexGuardian.Control;
using CodexGuardian.Services;
using Microsoft.Win32.SafeHandles;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

internal static class CdpPipeTransportOfflineTests
{
    internal const string ChildProbeArgument = "--cdp-direct-handle-child-probe";

    internal static bool IsChildProbeInvocation(IReadOnlyList<string> arguments) =>
        arguments.Count == 3 &&
        arguments.Contains(ChildProbeArgument, StringComparer.Ordinal) &&
        arguments.Contains(
            WindowsCrtPipeProcess.RemoteDebuggingPipeArgument,
            StringComparer.Ordinal) &&
        arguments.Count(argument => argument.StartsWith(
            WindowsCrtPipeProcess.RemoteDebuggingIoPipesArgumentPrefix,
            StringComparison.Ordinal)) == 1;

    private static readonly IReadOnlyList<string> ForbiddenChildEnvironmentNames =
        Array.AsReadOnly(
        [
            "ELECTRON_RUN_AS_NODE",
            "NODE_OPTIONS",
            "COMPlus_ReadyToRun"
        ]);

    // Program.cs must branch to this method before running the normal test suite.
    internal static async Task<int> RunChildProbeAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return 90;
        }

        if (!HasHardenedChildEnvironment())
        {
            return 94;
        }

        var handlesArgument = arguments.Single(argument => argument.StartsWith(
            WindowsCrtPipeProcess.RemoteDebuggingIoPipesArgumentPrefix,
            StringComparison.Ordinal));
        var handleValues = handlesArgument[
                WindowsCrtPipeProcess.RemoteDebuggingIoPipesArgumentPrefix.Length..]
            .Split(',', StringSplitOptions.None);
        if (handleValues.Length != 2 ||
            !uint.TryParse(
                handleValues[0],
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var readHandleValue) ||
            !uint.TryParse(
                handleValues[1],
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var writeHandleValue))
        {
            return 91;
        }

        var readHandle = new IntPtr(checked((long)readHandleValue));
        var writeHandle = new IntPtr(checked((long)writeHandleValue));

        try
        {
            using var readSafeHandle = new SafeFileHandle(readHandle, ownsHandle: false);
            using var writeSafeHandle = new SafeFileHandle(writeHandle, ownsHandle: false);
            await using var readStream = new FileStream(
                readSafeHandle,
                FileAccess.Read,
                bufferSize: 4096,
                isAsync: false);
            await using var writeStream = new FileStream(
                writeSafeHandle,
                FileAccess.Write,
                bufferSize: 4096,
                isAsync: false);
            var requestBytes = await ReadNulFrameAsync(
                readStream,
                maximumBytes: 64 * 1024,
                cancellationToken).ConfigureAwait(false);
            using var request = JsonDocument.Parse(requestBytes);
            if (!request.RootElement.TryGetProperty("id", out var idElement) ||
                !idElement.TryGetInt64(out var requestId) ||
                !request.RootElement.TryGetProperty("method", out var methodElement) ||
                !string.Equals(
                    methodElement.GetString(),
                    "Browser.getVersion",
                    StringComparison.Ordinal))
            {
                return 92;
            }

            var response = Frame(JsonSerializer.Serialize(new
            {
                id = requestId,
                result = new { product = "CodexGuardian.CrtPipeProbe" }
            }));
            var split = Math.Min(7, response.Length);
            await writeStream.WriteAsync(response.AsMemory(0, split), cancellationToken)
                .ConfigureAwait(false);
            await writeStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            await writeStream.WriteAsync(response.AsMemory(split), cancellationToken)
                .ConfigureAwait(false);
            await writeStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception) when (
            exception is IOException or JsonException or OperationCanceledException)
        {
            return 93;
        }
    }

    private static bool HasHardenedChildEnvironment()
    {
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrWhiteSpace(systemRoot) ||
            !Path.IsPathFullyQualified(systemRoot) ||
            systemRoot.Length < 3 ||
            !char.IsAsciiLetter(systemRoot[0]) ||
            systemRoot[1] != ':')
        {
            return false;
        }

        var normalizedRoot = systemRoot.TrimEnd('\\');
        if (normalizedRoot.Length == 2)
        {
            normalizedRoot += '\\';
        }

        var expectedPath = string.Join(
            ";",
            new[]
            {
                normalizedRoot + "\\System32",
                normalizedRoot,
                normalizedRoot + "\\System32\\Wbem",
                normalizedRoot + "\\System32\\WindowsPowerShell\\v1.0"
            });
        var path = Environment.GetEnvironmentVariable("PATH");
        var pathSegments = path?.Split(';', StringSplitOptions.None);
        if (!string.Equals(
                Environment.GetEnvironmentVariable("WINDIR"),
                normalizedRoot,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Environment.GetEnvironmentVariable("ComSpec"),
                normalizedRoot + "\\System32\\cmd.exe",
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(path, expectedPath, StringComparison.OrdinalIgnoreCase) ||
            pathSegments is null ||
            pathSegments.Length != 4 ||
            pathSegments.Any(segment => segment.Length == 0) ||
            pathSegments.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 4 ||
            !string.Equals(
                Environment.GetEnvironmentVariable("PATHEXT"),
                ".COM;.EXE;.BAT;.CMD",
                StringComparison.Ordinal) ||
            !string.Equals(
                Environment.GetEnvironmentVariable("OS"),
                "Windows_NT",
                StringComparison.Ordinal) ||
            !string.Equals(
                Environment.GetEnvironmentVariable("SystemDrive"),
                normalizedRoot[..2],
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return ForbiddenChildEnvironmentNames.All(name =>
            Environment.GetEnvironmentVariable(name) is null);
    }

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync("CDP pipe partial frame", TestPartialFrameAsync, assert);
        await RunCaseAsync("CDP pipe multiple frames", TestMultipleFramesAsync, assert);
        await RunCaseAsync("CDP pipe flat session command", TestSessionCommandAsync, assert);
        await RunCaseAsync("CDP pipe serialized writes", TestSerializedWritesAsync, assert);
        await RunCaseAsync("CDP pipe pending limit", TestPendingLimitAsync, assert);
        await RunCaseAsync("CDP pipe command timeout", TestTimeoutAsync, assert);
        await RunCaseAsync("CDP pipe command cancellation", TestCancellationAsync, assert);
        await RunCaseAsync("CDP pipe EOF", TestEofAsync, assert);
        await RunCaseAsync("CDP pipe truncated EOF", TestTruncatedEofAsync, assert);
        await RunCaseAsync("CDP pipe maximum frame", TestMaximumFrameAsync, assert);
        await RunCaseAsync("CDP pipe invalid UTF-8 JSON", TestInvalidJsonAsync, assert);
        await RunCaseAsync("CDP pipe unknown response", TestUnknownResponseAsync, assert);
        await RunCaseAsync("CDP pipe duplicate response", TestDuplicateResponseAsync, assert);
        await RunCaseAsync("CDP pipe command error", TestCommandErrorAsync, assert);
        await RunCaseAsync("CDP pipe notification framing", TestNotificationsAsync, assert);
        await RunCaseAsync("CDP pipe notification limit", TestNotificationLimitAsync, assert);
        await RunCaseAsync(
            "CDP pipe default terminal fault closes streams",
            TestDefaultFaultClosesStreamsAsync,
            assert);
        await RunCaseAsync(
            "CDP pipe broker fault drains until owner dispose",
            TestBrokerFaultLifelineAsync,
            assert);
        await RunCaseAsync(
            "CDP pipe broker fault survives throwing cancellation callbacks",
            TestBrokerFaultCancelsQueuedWritersAsync,
            assert);
        await RunCaseAsync(
            "CDP pipe broker concurrent dispose waits and closes once",
            TestBrokerConcurrentDisposeAsync,
            assert);
        await RunCaseAsync(
            "CDP pipe broker dispose timeout fails closed",
            TestBrokerDisposeTimeoutAsync,
            assert);
        await RunCaseAsync(
            "CDP pipe broker preserves the first concurrent fault",
            TestBrokerFirstFaultWinsAsync,
            assert);
        await RunCaseAsync(
            "CDP pipe broker fault-dispose race preserves terminal semantics",
            TestBrokerFaultDisposeRaceAsync,
            assert);
    }

    // Call only after Program.cs has wired ChildProbeArgument to RunChildProbeAsync.
    internal static async Task RunWindowsProcessProbeAsync(
        string explicitTestExecutablePath,
        Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "Windows direct-handle CDP process probe",
            cancellationToken => TestWindowsProcessProbeAsync(
                explicitTestExecutablePath,
                cancellationToken),
            assert);
    }

    private static async Task TestPartialFrameAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        var command = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        var request = await ReadRequestAsync(write, cancellationToken);
        var response = Frame($"{{\"id\":{request.Id},\"result\":{{\"ok\":true}}}}");
        read.Feed(response[..3]);
        read.Feed(response[3..^1]);
        read.Feed(response[^1..]);
        var result = await command.ConfigureAwait(false);
        Ensure(result.GetProperty("ok").GetBoolean(), "partial response result was lost");
    }

    private static async Task TestMultipleFramesAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        var first = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        var second = transport.SendCommandAsync(
            "Page.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        var firstRequest = await ReadRequestAsync(write, cancellationToken);
        var secondRequest = await ReadRequestAsync(write, cancellationToken);
        var firstResponse = Frame(
            $"{{\"id\":{firstRequest.Id},\"result\":{{\"value\":1}}}}");
        var secondResponse = Frame(
            $"{{\"id\":{secondRequest.Id},\"result\":{{\"value\":2}}}}");
        read.Feed(Concat(secondResponse, firstResponse));
        Ensure((await first.ConfigureAwait(false)).GetProperty("value").GetInt32() == 1,
            "first coalesced response was mismatched");
        Ensure((await second.ConfigureAwait(false)).GetProperty("value").GetInt32() == 2,
            "second coalesced response was mismatched");
    }

    private static async Task TestSerializedWritesAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream(TimeSpan.FromMilliseconds(15));
        await using var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions { MaximumPendingCommands = 16 });
        var commands = Enumerable.Range(0, 8)
            .Select(index => transport.SendCommandAsync(
                "Runtime.evaluate",
                new { expression = index.ToString() },
                TimeSpan.FromSeconds(3),
                cancellationToken))
            .ToArray();
        var responses = new List<byte[]>();
        for (var index = 0; index < commands.Length; index++)
        {
            var request = await ReadRequestAsync(write, cancellationToken);
            responses.Add(Frame($"{{\"id\":{request.Id},\"result\":{{}}}}"));
        }

        read.Feed(Concat(responses.ToArray()));
        await Task.WhenAll(commands).ConfigureAwait(false);
        Ensure(write.MaximumConcurrentWrites == 1, "outbound CDP writes overlapped");
    }

    private static async Task TestSessionCommandAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        var command = transport.SendSessionCommandAsync(
            "session-12345678",
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        var request = await ReadRequestAsync(write, cancellationToken);
        Ensure(
            request.SessionId == "session-12345678",
            "flat CDP session id was not serialized at the top level");
        read.Feed(Frame($"{{\"id\":{request.Id},\"result\":{{}}}}"));
        await command.ConfigureAwait(false);
    }

    private static async Task TestPendingLimitAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions { MaximumPendingCommands = 1 });
        var first = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        var request = await ReadRequestAsync(write, cancellationToken);
        await ExpectAsync<CdpPipeCapacityException>(() => transport.SendCommandAsync(
            "Page.enable",
            timeout: TimeSpan.FromSeconds(1),
            cancellationToken: cancellationToken));
        read.Feed(Frame($"{{\"id\":{request.Id},\"result\":{{}}}}"));
        await first.ConfigureAwait(false);
    }

    private static async Task TestTimeoutAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        await ExpectAsync<TimeoutException>(() => transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromMilliseconds(40),
            cancellationToken: cancellationToken));
    }

    private static async Task TestCancellationAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var command = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellation.Token);
        _ = await ReadRequestAsync(write, cancellationToken);
        cancellation.Cancel();
        await ExpectAsync<OperationCanceledException>(() => command);
    }

    private static async Task TestEofAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        var command = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        _ = await ReadRequestAsync(write, cancellationToken);
        read.Complete();
        var failure = await ExpectAsync<CdpPipeProtocolException>(() => command);
        Ensure(failure.Code == "unexpected-eof", "clean EOF did not fail closed");
    }

    private static async Task TestMaximumFrameAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions { MaximumFrameBytes = 64, ReadBufferBytes = 64 });
        read.Feed(Enumerable.Repeat((byte)'x', 65).ToArray());
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(failure.Code == "frame-too-large", "oversized frame was not rejected");
    }

    private static async Task TestTruncatedEofAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        read.Feed(Encoding.UTF8.GetBytes("{\"id\":"));
        read.Complete();
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(failure.Code == "truncated-frame", "partial-frame EOF did not fail closed");
    }

    private static async Task TestInvalidJsonAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        read.Feed([0xC3, 0x28, 0x00]);
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(failure.Code == "invalid-json", "invalid UTF-8 JSON was not rejected");
    }

    private static async Task TestUnknownResponseAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        read.Feed(Frame("{\"id\":999,\"result\":{}}"));
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(failure.Code == "unknown-response-id", "unknown response did not fail closed");
    }

    private static async Task TestDuplicateResponseAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        var command = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        var request = await ReadRequestAsync(write, cancellationToken);
        var response = Frame($"{{\"id\":{request.Id},\"result\":{{}}}}");
        read.Feed(Concat(response, response));
        await command.ConfigureAwait(false);
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(failure.Code == "unknown-response-id", "duplicate response did not fail closed");
    }

    private static async Task TestCommandErrorAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(read, write);
        var command = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(2),
            cancellationToken: cancellationToken);
        var request = await ReadRequestAsync(write, cancellationToken);
        read.Feed(Frame(
            $"{{\"id\":{request.Id},\"error\":{{\"code\":-32601,\"message\":\"missing\"}}}}"));
        var failure = await ExpectAsync<CdpCommandException>(() => command);
        Ensure(failure.Code == -32601, "CDP command error code was lost");
    }

    private static async Task TestNotificationsAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions { MaximumBufferedNotifications = 2 });
        var first = Frame("{\"method\":\"Runtime.executionContextCreated\",\"params\":{}}" );
        var second = Frame("{\"method\":\"Page.loadEventFired\",\"params\":{}}" );
        read.Feed(first[..5]);
        read.Feed(Concat(first[5..], second));
        var firstNotification = await transport.Notifications.ReadAsync(cancellationToken);
        var secondNotification = await transport.Notifications.ReadAsync(cancellationToken);
        Ensure(
            firstNotification.GetProperty("method").GetString() ==
                "Runtime.executionContextCreated",
            "first notification was mismatched");
        Ensure(
            secondNotification.GetProperty("method").GetString() == "Page.loadEventFired",
            "second notification was mismatched");
    }

    private static async Task TestNotificationLimitAsync(CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        await using var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions { MaximumBufferedNotifications = 1 });
        read.Feed(Concat(
            Frame("{\"method\":\"Runtime.executionContextCreated\",\"params\":{}}"),
            Frame("{\"method\":\"Page.loadEventFired\",\"params\":{}}")));
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(
            failure.Code == "notification-capacity-exceeded",
            "notification capacity overflow did not fail closed");
    }

    private static async Task TestDefaultFaultClosesStreamsAsync(
        CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        var transport = new CdpPipeTransport(read, write);
        try
        {
            read.Feed([0xC3, 0x28, 0x00]);
            var failure = await ExpectAsync<CdpPipeProtocolException>(
                () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
            Ensure(failure.Code == "invalid-json", "default fault code changed");
            Ensure(read.DisposeCount == 1, "default fault did not close the read stream once");
            Ensure(write.DisposeCount == 1, "default fault did not close the write stream once");
        }
        finally
        {
            await transport.DisposeAsync();
        }

        Ensure(read.DisposeCount == 1, "owner dispose closed the default read stream twice");
        Ensure(write.DisposeCount == 1, "owner dispose closed the default write stream twice");
    }

    private static async Task TestBrokerFaultLifelineAsync(
        CancellationToken cancellationToken)
    {
        const int readBufferBytes = 64;
        var read = new ControlledReadStream();
        var write = new RecordingWriteStream();
        var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions
            {
                ReadBufferBytes = readBufferBytes,
                TerminalFaultMode = CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose
            });
        var malformed = Frame("not-json");
        read.Feed(malformed);
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(failure.Code == "invalid-json", "broker fault code changed");
        Ensure(transport.IsDrainOnly, "broker fault did not enter drain-only mode");
        Ensure(read.DisposeCount == 0, "broker fault closed the read lifeline");
        Ensure(write.DisposeCount == 0, "broker fault closed the write lifeline");

        var parsedBeforeDrain = transport.ParsedFrameCount;
        var drained = Concat(
            Frame("{\"id\":999,\"result\":{}}"),
            Frame("{\"method\":\"Runtime.executionContextCreated\",\"params\":{}}"),
            Enumerable.Range(0, readBufferBytes * 2)
                .Select(index => unchecked((byte)(index + 1)))
                .ToArray());
        var drainedBatches = checked(
            transport.DrainedReadBatchCount +
            (int)Math.Ceiling(drained.Length / (double)readBufferBytes));
        read.Feed(drained);
        await read.WaitForTotalBytesReadAsync(
            malformed.Length + drained.Length,
            cancellationToken);
        while (transport.DrainedReadBatchCount < drainedBatches)
        {
            await Task.Delay(5, cancellationToken).ConfigureAwait(false);
        }
        Ensure(
            read.MaximumRequestedReadBytes == readBufferBytes,
            "drain-only did not retain the fixed read buffer bound");
        Ensure(
            transport.ParsedFrameCount == parsedBeforeDrain,
            "drain-only continued parsing complete post-fault frames");
        Ensure(
            transport.TerminalFailure is CdpPipeProtocolException terminal &&
            terminal.Code == "invalid-json",
            "drain-only replaced the first terminal failure");
        Ensure(!transport.Notifications.TryRead(out _), "drain-only published a notification");
        var unavailable = await ExpectAsync<CdpPipeProtocolException>(() =>
            transport.SendCommandAsync(
                "Runtime.enable",
                timeout: TimeSpan.FromSeconds(1),
                cancellationToken: cancellationToken));
        Ensure(unavailable.Code == "transport-faulted", "drain-only accepted a new command");

        var disposals = Enumerable.Range(0, 8)
            .Select(_ => transport.DisposeAsync().AsTask())
            .ToArray();
        await Task.WhenAll(disposals).ConfigureAwait(false);
        Ensure(read.DisposeCount == 1, "broker owner dispose did not close read exactly once");
        Ensure(write.DisposeCount == 1, "broker owner dispose did not close write exactly once");
    }

    private static async Task TestBrokerFaultCancelsQueuedWritersAsync(
        CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new ThrowingCancellationWriteStream();
        var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions
            {
                TerminalFaultMode = CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose
            });
        var first = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(3),
            cancellationToken: cancellationToken);
        await write.WriteEntered.WaitAsync(cancellationToken).ConfigureAwait(false);
        var second = transport.SendCommandAsync(
            "Page.enable",
            timeout: TimeSpan.FromSeconds(3),
            cancellationToken: cancellationToken);

        read.Feed(Frame("not-json"));
        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(failure.Code == "invalid-json", "inbound fault was lost during callback failure");
        var firstFailure = await ExpectFailureAsync(first).ConfigureAwait(false);
        var secondFailure = await ExpectFailureAsync(second).ConfigureAwait(false);
        Ensure(
            firstFailure is CdpPipeProtocolException or OperationCanceledException,
            "active writer failed with an unrelated exception");
        Ensure(
            secondFailure is CdpPipeProtocolException or OperationCanceledException,
            "queued writer failed with an unrelated exception");
        Ensure(write.WriteCallCount == 1, "queued writer executed after terminal fault");
        Ensure(transport.IsDrainOnly, "callback failure prevented drain-only mode");
        Ensure(read.DisposeCount == 0, "callback failure closed the read lifeline");
        Ensure(write.DisposeCount == 0, "callback failure closed the write lifeline");

        await transport.DisposeAsync();
        Ensure(read.DisposeCount == 1, "callback-fault owner did not close read once");
        Ensure(write.DisposeCount == 1, "callback-fault owner did not close write once");
    }

    private static async Task TestBrokerConcurrentDisposeAsync(
        CancellationToken cancellationToken)
    {
        var read = new GatedDrainReadStream(Frame("not-json"));
        var write = new RecordingWriteStream();
        var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions
            {
                TerminalFaultMode = CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose
            });
        _ = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        await read.BlockedDrainRead.WaitAsync(cancellationToken).ConfigureAwait(false);

        var firstDispose = transport.DisposeAsync().AsTask();
        await read.DisposeCalled.WaitAsync(cancellationToken).ConfigureAwait(false);
        var otherDisposals = Enumerable.Range(0, 7)
            .Select(_ => transport.DisposeAsync().AsTask())
            .ToArray();
        Ensure(!firstDispose.IsCompleted, "first owner dispose did not wait for the drain loop");
        Ensure(
            otherDisposals.All(task => !task.IsCompleted),
            "concurrent owner dispose did not wait for the shared completion");

        read.ReleaseBlockedRead();
        await Task.WhenAll(otherDisposals.Append(firstDispose)).ConfigureAwait(false);
        Ensure(read.DisposeCount == 1, "concurrent owner dispose closed read more than once");
        Ensure(write.DisposeCount == 1, "concurrent owner dispose closed write more than once");
    }

    private static async Task TestBrokerDisposeTimeoutAsync(
        CancellationToken cancellationToken)
    {
        var read = new GatedDrainReadStream(Frame("not-json"));
        var write = new RecordingWriteStream();
        var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions
            {
                TerminalFaultMode = CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose
            });
        _ = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        await read.BlockedDrainRead.WaitAsync(cancellationToken).ConfigureAwait(false);

        _ = await ExpectAsync<TimeoutException>(() => transport.DisposeAsync().AsTask());
        _ = await ExpectAsync<TimeoutException>(() => transport.DisposeAsync().AsTask());
        Ensure(read.DisposeCount == 1, "timed-out owner dispose closed read more than once");
        Ensure(write.DisposeCount == 1, "timed-out owner dispose closed write more than once");
        read.ReleaseBlockedRead();
        await Task.Delay(20, cancellationToken).ConfigureAwait(false);
    }

    private static async Task TestBrokerFirstFaultWinsAsync(
        CancellationToken cancellationToken)
    {
        var gate = new ConcurrentFaultGate();
        var read = new ConcurrentFaultReadStream(gate, Frame("not-json"));
        var write = new ConcurrentFaultWriteStream(gate);
        var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions
            {
                TerminalFaultMode = CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose
            });
        var command = transport.SendCommandAsync(
            "Runtime.enable",
            timeout: TimeSpan.FromSeconds(3),
            cancellationToken: cancellationToken);
        await Task.WhenAll(
            gate.ReadEntered.WaitAsync(cancellationToken),
            gate.WriteEntered.WaitAsync(cancellationToken)).ConfigureAwait(false);
        gate.Release();

        var failure = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
        Ensure(
            failure.Code is "invalid-json" or "outbound-write-failed",
            "concurrent fault produced an unexpected terminal code");
        _ = await ExpectFailureAsync(command).ConfigureAwait(false);
        var firstFailure = transport.TerminalFailure;
        await Task.Delay(20, cancellationToken).ConfigureAwait(false);
        Ensure(
            ReferenceEquals(firstFailure, transport.TerminalFailure),
            "a later concurrent fault replaced the first terminal failure");
        _ = await ExpectAsync<CdpPipeProtocolException>(
            () => transport.Notifications.Completion.WaitAsync(
                TimeSpan.FromSeconds(2),
                cancellationToken));
        Ensure(read.DisposeCount == 0, "concurrent fault closed the read lifeline");
        Ensure(write.DisposeCount == 0, "concurrent fault closed the write lifeline");

        await transport.DisposeAsync();
        Ensure(read.DisposeCount == 1, "concurrent-fault owner did not close read once");
        Ensure(write.DisposeCount == 1, "concurrent-fault owner did not close write once");
    }

    private static async Task TestBrokerFaultDisposeRaceAsync(
        CancellationToken cancellationToken)
    {
        var read = new ControlledReadStream();
        var write = new BlockingCancellationRegistrationWriteStream();
        var transport = new CdpPipeTransport(
            read,
            write,
            new CdpPipeTransportOptions
            {
                TerminalFaultMode = CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose
            });
        Task? dispose = null;
        var stage = "send-command";
        try
        {
            var pending = transport.SendCommandAsync(
                "Runtime.enable",
                timeout: TimeSpan.FromSeconds(3),
                cancellationToken: cancellationToken);
            stage = "wait-write-completed";
            await write.FirstWriteCompleted.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken)
                .ConfigureAwait(false);
            stage = "wait-transport-write-completed";
            while (transport.CompletedFrameWriteCount == 0)
            {
                await Task.Delay(5, cancellationToken).ConfigureAwait(false);
            }

            var activeWrite = transport.SendCommandAsync(
                "Page.enable",
                timeout: TimeSpan.FromSeconds(3),
                cancellationToken: cancellationToken);
            stage = "wait-active-write";
            await write.SecondWriteEntered.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken)
                .ConfigureAwait(false);

            read.Feed(Frame("not-json"));
            stage = "wait-cancellation-callback";
            await write.CancellationCallbackEntered
                .WaitAsync(TimeSpan.FromSeconds(2), cancellationToken)
                .ConfigureAwait(false);
            Ensure(
                transport.TerminalFailure is CdpPipeProtocolException terminal &&
                terminal.Code == "invalid-json",
                "fault-dispose race did not publish the first terminal failure");
            var firstFailure = transport.TerminalFailure!;
            stage = "start-dispose";
            dispose = Task.Factory.StartNew(
                    async () => await transport.DisposeAsync(),
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default)
                .Unwrap();

            stage = "wait-transport-completion";
            var completionFailure = await ExpectAsync<CdpPipeProtocolException>(
                () => transport.Completion.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken));
            stage = "wait-pending-command";
            var pendingFailure = await ExpectAsync<CdpPipeProtocolException>(() => pending);
            stage = "wait-notification-channel";
            var channelFailure = await ExpectAsync<CdpPipeProtocolException>(
                () => transport.Notifications.Completion.WaitAsync(
                    TimeSpan.FromSeconds(2),
                    cancellationToken));
            Ensure(
                ReferenceEquals(firstFailure, completionFailure) &&
                ReferenceEquals(firstFailure, pendingFailure) &&
                ReferenceEquals(firstFailure, channelFailure),
                "fault-dispose race did not preserve one first failure across terminal surfaces");

            stage = "wait-dispose";
            write.ReleaseCancellationCallback();
            _ = await ExpectFailureAsync(activeWrite).ConfigureAwait(false);
            await dispose.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            Ensure(read.DisposeCount == 1, "fault-dispose race closed read more than once");
            Ensure(write.DisposeCount == 1, "fault-dispose race closed write more than once");
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                "fault-dispose race failed at stage " + stage,
                exception);
        }
        finally
        {
            write.ReleaseCancellationCallback();
            if (dispose is not null && !dispose.IsCompleted)
            {
                try
                {
                    await dispose.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                }
                catch
                {
                }
            }
        }
    }

    private static async Task TestWindowsProcessProbeAsync(
        string explicitTestExecutablePath,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException();
        }

        var injectedEnvironment = new Dictionary<string, string?>
        {
            ["ELECTRON_RUN_AS_NODE"] = "1",
            ["NODE_OPTIONS"] = "--require injected.js",
            ["COMPlus_ReadyToRun"] = "0",
            ["PATH"] = @"D:\InjectedPath"
        };
        var previousEnvironment = injectedEnvironment.Keys.ToDictionary(
            name => name,
            name => Environment.GetEnvironmentVariable(name),
            StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var pair in injectedEnvironment)
            {
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }

            await using var process = WindowsCrtPipeProcess.Start(
                explicitTestExecutablePath,
                [
                    ChildProbeArgument,
                    WindowsCrtPipeProcess.RemoteDebuggingPipeArgument,
                    WindowsCrtPipeProcess.RemoteDebuggingIoPipesArgumentPlaceholder
                ],
                disposeBehavior: WindowsCrtPipeProcessDisposeBehavior.TerminateExactRootForTests);
            using (var duplicate = process.DuplicateRetainedProcessHandleForVerification())
            {
                Ensure(!duplicate.IsInvalid, "retained child process duplicate was invalid");
                Ensure(
                    GetProcessId(duplicate) == process.ProcessId,
                    "retained child process duplicate referenced a different PID");
            }

            Ensure(!process.HasExited, "disposing the verification duplicate closed the owner handle");
            using var retainedDuplicate = process.DuplicateRetainedProcessHandleForVerification();
            await using var transport = new CdpPipeTransport(process.ReadStream, process.WriteStream);
            var response = await transport.SendCommandAsync(
                "Browser.getVersion",
                timeout: TimeSpan.FromSeconds(3),
                cancellationToken: cancellationToken).ConfigureAwait(false);
            Ensure(
                response.GetProperty("product").GetString() == "CodexGuardian.CrtPipeProbe",
                "Direct-handle CDP probe response was invalid");
            var exitCode = await process.WaitForExitAsync(TimeSpan.FromSeconds(3), cancellationToken)
                .ConfigureAwait(false);
            Ensure(exitCode == 0, "Direct-handle CDP child probe failed with exit code " + exitCode);
            await transport.DisposeAsync();
            process.Dispose();
            Ensure(
                GetProcessId(retainedDuplicate) == process.ProcessId,
                "owner disposal invalidated the caller-owned verification duplicate");
            Expect<ObjectDisposedException>(() => process.DuplicateRetainedProcessHandleForVerification());
        }
        finally
        {
            foreach (var pair in previousEnvironment)
            {
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }
        }
    }

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

    private static async Task<TException> ExpectAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException(
            "Expected exception was not thrown: " + typeof(TException).Name);
    }

    private static async Task<Exception> ExpectFailureAsync(Task action)
    {
        try
        {
            await action.ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return exception;
        }

        throw new InvalidOperationException("Expected the task to fail.");
    }

    private static TException Expect<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException(
            "Expected exception was not thrown: " + typeof(TException).Name);
    }

    private static async Task<(long Id, string Method, string? SessionId)> ReadRequestAsync(
        RecordingWriteStream stream,
        CancellationToken cancellationToken)
    {
        var frame = await stream.ReadWriteAsync(cancellationToken).ConfigureAwait(false);
        Ensure(frame.Length > 1 && frame[^1] == 0, "outbound command was not NUL framed");
        using var document = JsonDocument.Parse(frame.AsMemory(0, frame.Length - 1));
        return (
            document.RootElement.GetProperty("id").GetInt64(),
            document.RootElement.GetProperty("method").GetString() ?? string.Empty,
            document.RootElement.TryGetProperty("sessionId", out var sessionId)
                ? sessionId.GetString()
                : null);
    }

    private static async Task<byte[]> ReadNulFrameAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var frame = new MemoryStream();
        var buffer = new byte[512];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new EndOfStreamException();
            }

            var terminator = buffer.AsSpan(0, count).IndexOf((byte)0);
            var payloadCount = terminator < 0 ? count : terminator;
            if (frame.Length + payloadCount > maximumBytes)
            {
                throw new IOException("Child probe frame limit exceeded.");
            }

            frame.Write(buffer, 0, payloadCount);
            if (terminator >= 0)
            {
                return frame.ToArray();
            }
        }
    }

    private static byte[] Frame(string json) =>
        Encoding.UTF8.GetBytes(json + "\0");

    private static byte[] Concat(params byte[][] values)
    {
        var length = values.Sum(static value => value.Length);
        var result = new byte[length];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result, offset);
            offset += value.Length;
        }

        return result;
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class ControlledReadStream : Stream
    {
        private readonly Channel<byte[]> _chunks = Channel.CreateUnbounded<byte[]>(
            new UnboundedChannelOptions
            {
                AllowSynchronousContinuations = false,
                SingleReader = true,
                SingleWriter = false
            });
        private byte[]? _current;
        private int _offset;
        private int _disposeCount;
        private int _maximumRequestedReadBytes;
        private int _readCallCount;
        private int _totalBytesRead;
        private int _disposed;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal int MaximumRequestedReadBytes => Volatile.Read(ref _maximumRequestedReadBytes);

        internal int ReadCallCount => Volatile.Read(ref _readCallCount);

        internal int TotalBytesRead => Volatile.Read(ref _totalBytesRead);

        public override bool CanRead => Volatile.Read(ref _disposed) == 0;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        internal void Feed(byte[] chunk)
        {
            if (chunk.Length == 0 || !_chunks.Writer.TryWrite(chunk))
            {
                throw new InvalidOperationException("Unable to feed the controlled read stream.");
            }
        }

        internal void Complete() => _chunks.Writer.TryComplete();

        internal async Task WaitForTotalBytesReadAsync(
            int minimumBytes,
            CancellationToken cancellationToken)
        {
            while (TotalBytesRead < minimumBytes)
            {
                await Task.Delay(5, cancellationToken).ConfigureAwait(false);
            }
        }

        internal async Task WaitForReadCallCountAsync(
            int minimumCalls,
            CancellationToken cancellationToken)
        {
            while (ReadCallCount < minimumCalls)
            {
                await Task.Delay(5, cancellationToken).ConfigureAwait(false);
            }
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _readCallCount);
            UpdateMaximumRequestedReadBytes(buffer.Length);
            while (_current is null || _offset == _current.Length)
            {
                if (!await _chunks.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0;
                }

                if (!_chunks.Reader.TryRead(out _current))
                {
                    continue;
                }

                _offset = 0;
            }

            var count = Math.Min(buffer.Length, _current.Length - _offset);
            _current.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            Interlocked.Add(ref _totalBytesRead, count);
            return count;
        }

        private void UpdateMaximumRequestedReadBytes(int candidate)
        {
            while (true)
            {
                var current = Volatile.Read(ref _maximumRequestedReadBytes);
                if (candidate <= current ||
                    Interlocked.CompareExchange(
                        ref _maximumRequestedReadBytes,
                        candidate,
                        current) == current)
                {
                    return;
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _chunks.Writer.TryComplete();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class RecordingWriteStream(TimeSpan? delay = null) : Stream
    {
        private readonly Channel<byte[]> _writes = Channel.CreateUnbounded<byte[]>(
            new UnboundedChannelOptions
            {
                AllowSynchronousContinuations = false,
                SingleReader = true,
                SingleWriter = false
            });
        private int _activeWrites;
        private int _maximumConcurrentWrites;
        private int _disposeCount;
        private int _disposed;

        internal int MaximumConcurrentWrites => Volatile.Read(ref _maximumConcurrentWrites);

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        internal ValueTask<byte[]> ReadWriteAsync(CancellationToken cancellationToken) =>
            _writes.Reader.ReadAsync(cancellationToken);

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            var active = Interlocked.Increment(ref _activeWrites);
            UpdateMaximum(active);
            try
            {
                if (delay is { } writeDelay)
                {
                    await Task.Delay(writeDelay, cancellationToken).ConfigureAwait(false);
                }

                if (!_writes.Writer.TryWrite(buffer.ToArray()))
                {
                    throw new IOException("Unable to record an outbound test frame.");
                }
            }
            finally
            {
                Interlocked.Decrement(ref _activeWrites);
            }
        }

        private void UpdateMaximum(int candidate)
        {
            while (true)
            {
                var current = Volatile.Read(ref _maximumConcurrentWrites);
                if (candidate <= current ||
                    Interlocked.CompareExchange(
                        ref _maximumConcurrentWrites,
                        candidate,
                        current) == current)
                {
                    return;
                }
            }
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _writes.Writer.TryComplete();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class ThrowingCancellationWriteStream : Stream
    {
        private readonly TaskCompletionSource _writeEntered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _disposeCount;
        private int _writeCallCount;
        private int _disposed;

        internal Task WriteEntered => _writeEntered.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal int WriteCallCount => Volatile.Read(ref _writeCallCount);

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            Interlocked.Increment(ref _writeCallCount);
            _writeEntered.TrySetResult();
            using var registration = cancellationToken.Register(
                static () => throw new InvalidOperationException("test cancellation callback"));
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            Interlocked.Exchange(ref _disposed, 1);
            base.Dispose(disposing);
        }
    }

    private sealed class GatedDrainReadStream(byte[] firstRead) : Stream
    {
        private readonly TaskCompletionSource _blockedDrainRead = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _disposeCalled = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseBlockedRead = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private byte[]? _firstRead = firstRead;
        private int _disposeCount;
        private int _disposed;

        internal Task BlockedDrainRead => _blockedDrainRead.Task;

        internal Task DisposeCalled => _disposeCalled.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal void ReleaseBlockedRead() => _releaseBlockedRead.TrySetResult();

        public override bool CanRead => Volatile.Read(ref _disposed) == 0;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var first = Interlocked.Exchange(ref _firstRead, null);
            if (first is not null)
            {
                first.CopyTo(buffer);
                return first.Length;
            }

            _blockedDrainRead.TrySetResult();
            await _releaseBlockedRead.Task.ConfigureAwait(false);
            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            Interlocked.Exchange(ref _disposed, 1);
            _disposeCalled.TrySetResult();
            base.Dispose(disposing);
        }
    }

    private sealed class BlockingCancellationRegistrationWriteStream : Stream
    {
        private readonly TaskCompletionSource _firstWriteCompleted = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _secondWriteEntered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _cancellationCallbackEntered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ManualResetEventSlim _releaseCancellationCallback = new(false);
        private int _disposeCount;
        private int _disposed;
        private int _writeCallCount;

        internal Task FirstWriteCompleted => _firstWriteCompleted.Task;

        internal Task SecondWriteEntered => _secondWriteEntered.Task;

        internal Task CancellationCallbackEntered => _cancellationCallbackEntered.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal void ReleaseCancellationCallback() => _releaseCancellationCallback.Set();

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (Interlocked.Increment(ref _writeCallCount) == 1)
            {
                _firstWriteCompleted.TrySetResult();
                return;
            }

            _secondWriteEntered.TrySetResult();
            using var registration = cancellationToken.Register(() =>
            {
                _cancellationCallbackEntered.TrySetResult();
                _releaseCancellationCallback.Wait();
            });
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _releaseCancellationCallback.Set();
                _releaseCancellationCallback.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class ConcurrentFaultGate
    {
        private readonly TaskCompletionSource _release = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal TaskCompletionSource ReadEnteredSource { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal TaskCompletionSource WriteEnteredSource { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal Task ReadEntered => ReadEnteredSource.Task;

        internal Task WriteEntered => WriteEnteredSource.Task;

        internal Task ReleaseTask => _release.Task;

        internal void Release() => _release.TrySetResult();
    }

    private sealed class ConcurrentFaultReadStream(
        ConcurrentFaultGate gate,
        byte[] malformedFrame) : Stream
    {
        private int _disposeCount;
        private int _readCount;
        private int _disposed;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        public override bool CanRead => Volatile.Read(ref _disposed) == 0;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _readCount) == 1)
            {
                gate.ReadEnteredSource.TrySetResult();
                await gate.ReleaseTask.ConfigureAwait(false);
                malformedFrame.CopyTo(buffer);
                return malformedFrame.Length;
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            Interlocked.Exchange(ref _disposed, 1);
            base.Dispose(disposing);
        }
    }

    private sealed class ConcurrentFaultWriteStream(ConcurrentFaultGate gate) : Stream
    {
        private int _disposeCount;
        private int _disposed;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            gate.WriteEnteredSource.TrySetResult();
            await gate.ReleaseTask.ConfigureAwait(false);
            throw new IOException("concurrent outbound write failure");
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            Interlocked.Exchange(ref _disposed, 1);
            base.Dispose(disposing);
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle process);

}
