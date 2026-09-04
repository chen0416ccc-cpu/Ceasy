using CodexGuardian.Trust;
using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal enum BrokerInvocationKindV1
{
    Invalid,
    ProductionHost,
    UserPresenceProbe,
    NativePeerProbe
}

internal static class Program
{
    private const string ProbeArgument = "--native-peer-child-probe-server";
    private const string ReadyMarker = "BROKER_NATIVE_PROBE_READY";
    private const string ConnectedMarker = "BROKER_NATIVE_PROBE_CONNECTED";
    private const string HelloMarker = "BROKER_NATIVE_PROBE_HELLO_SENT";
    private const string CompleteMarker = "BROKER_NATIVE_PROBE_COMPLETE";
    private const string UserPresenceCapabilityArgument =
        "--native-user-presence-capability-probe";
    private const string UserPresenceInteractiveArgument =
        "--native-user-presence-interactive-probe";
    private const string UserPresenceEvidenceRootArgument =
        "--native-user-presence-evidence-root";
    private const string CapabilityCompleteMarker =
        "BROKER_USER_PRESENCE_CAPABILITY_COMPLETE";
    private const string InteractiveCompleteMarker =
        "BROKER_USER_PRESENCE_INTERACTIVE_COMPLETE";
    private const string ProductionHostArgument =
        "--guardian-broker-production-host-v1";
    private const string ProductionHostFailureMarker =
        "BROKER_PRODUCTION_HOST_FAILED";
    private const string CapabilityEvidenceFileName = "webauthn-capability-v1.json";
    private const string InteractiveEvidenceFileName = "webauthn-interactive-v1.json";
    private const int MaximumEvidenceBytes = 4096;

    public static async Task<int> Main(string[] args)
    {
        var invocation = ClassifyInvocation(args, out var mode, out var evidenceRoot);
        if (invocation == BrokerInvocationKindV1.Invalid)
        {
            return 64;
        }

        EnsureWindowsEnvironment();
        if (invocation == BrokerInvocationKindV1.ProductionHost)
        {
            return await RunProductionHostAsync().ConfigureAwait(false);
        }

        if (invocation == BrokerInvocationKindV1.UserPresenceProbe)
        {
            try
            {
                return await RunUserPresenceProbeAsync(mode, evidenceRoot).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                var code = exception is BrokerUserPresenceVerificationException verification
                    ? verification.Code
                    : "user-presence-native-failed";
                Console.Error.WriteLine(
                    "BROKER_USER_PRESENCE_PROBE_FAILED " +
                    exception.GetType().Name +
                    " code=" + code);
                return 1;
            }
        }

        try
        {
            var bootstrapLine = await ReadBoundedLineAsync(
                    Console.In,
                    maximumCharacters: 2048,
                    timeout: TimeSpan.FromSeconds(10))
                .ConfigureAwait(false);
            var bootstrap = ParseBootstrap(bootstrapLine);
            using var server = WindowsSameLogonNamedPipeServer.Create(bootstrap.EndpointName);
            Console.WriteLine(ReadyMarker);
            Console.Out.Flush();

            using var connectionTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await server.WaitForConnectionAsync(connectionTimeout.Token).ConfigureAwait(false);
            if (string.Equals(bootstrap.Mode, "stall", StringComparison.Ordinal))
            {
                Console.WriteLine(ConnectedMarker);
                Console.Out.Flush();
                await AwaitExitCommandAsync().ConfigureAwait(false);
                Console.WriteLine(CompleteMarker);
                Console.Out.Flush();
                return 0;
            }

            if (string.Equals(bootstrap.Mode, "exitBeforeHello", StringComparison.Ordinal))
            {
                Console.WriteLine(ConnectedMarker);
                Console.Out.Flush();
                await AwaitControlCommandAsync("EXIT_NOW").ConfigureAwait(false);
                return 0;
            }

            if (string.Equals(bootstrap.Mode, "oversize", StringComparison.Ordinal))
            {
                // The 4097-byte negative frame exceeds the 4096-byte pipe buffer, so the
                // verifier must start reading before the single message write can complete.
                Console.WriteLine(ConnectedMarker);
                Console.Out.Flush();
                await server.WriteMessageAsync(
                        new byte[BrokerPeerHelloProtocol.MaximumHelloBytes + 1],
                        connectionTimeout.Token)
                    .ConfigureAwait(false);
                await AwaitExitCommandAsync().ConfigureAwait(false);
                Console.WriteLine(CompleteMarker);
                Console.Out.Flush();
                return 0;
            }

            if (string.Equals(bootstrap.Mode, "malformed", StringComparison.Ordinal))
            {
                await server.WriteMessageAsync(
                        new byte[] { 0x7B, 0xFF, 0x7D },
                        connectionTimeout.Token)
                    .ConfigureAwait(false);
                Console.WriteLine(HelloMarker);
                Console.Out.Flush();
                await AwaitExitCommandAsync().ConfigureAwait(false);
                Console.WriteLine(CompleteMarker);
                Console.Out.Flush();
                return 0;
            }

            using var currentProcess = Process.GetCurrentProcess();
            var creationTime = new DateTimeOffset(
                currentProcess.StartTime.ToUniversalTime(),
                TimeSpan.Zero);
            var hello = new BrokerPeerHello(
                BrokerPeerHelloProtocol.ProtocolVersion,
                BrokerPeerRole.Broker,
                checked((uint)Environment.ProcessId),
                checked((uint)currentProcess.SessionId),
                creationTime,
                bootstrap.ConnectionNonce,
                bootstrap.ReleaseId,
                bootstrap.ManifestSha256);
            await server.WriteMessageAsync(
                    BrokerPeerHelloProtocol.Serialize(hello),
                    connectionTimeout.Token)
                .ConfigureAwait(false);
            if (string.Equals(bootstrap.Mode, "secondFrame", StringComparison.Ordinal))
            {
                await server.WriteMessageAsync(
                        BrokerPeerHelloProtocol.Serialize(hello),
                        connectionTimeout.Token)
                    .ConfigureAwait(false);
            }

            Console.WriteLine(HelloMarker);
            Console.Out.Flush();
            await AwaitExitCommandAsync().ConfigureAwait(false);
            Console.WriteLine(CompleteMarker);
            Console.Out.Flush();
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("BROKER_NATIVE_PROBE_FAILED " + exception.GetType().Name);
            return 1;
        }
    }

    internal static bool IsProductionHostInvocation(string[] args) =>
        args is { Length: 1 } &&
        string.Equals(args[0], ProductionHostArgument, StringComparison.Ordinal);

    internal static BrokerInvocationKindV1 ClassifyInvocation(
        string[] args,
        out string userPresenceMode,
        out string userPresenceEvidenceRoot)
    {
        ArgumentNullException.ThrowIfNull(args);
        userPresenceMode = string.Empty;
        userPresenceEvidenceRoot = string.Empty;
        if (IsProductionHostInvocation(args))
        {
            return BrokerInvocationKindV1.ProductionHost;
        }

        if (args.Any(argument => string.Equals(
                argument,
                ProductionHostArgument,
                StringComparison.Ordinal)))
        {
            return BrokerInvocationKindV1.Invalid;
        }

        if (TryParseUserPresenceProbe(
                args,
                out userPresenceMode,
                out userPresenceEvidenceRoot))
        {
            return BrokerInvocationKindV1.UserPresenceProbe;
        }

        return args.Length == 1 &&
               string.Equals(args[0], ProbeArgument, StringComparison.Ordinal)
            ? BrokerInvocationKindV1.NativePeerProbe
            : BrokerInvocationKindV1.Invalid;
    }

    private static async Task<int> RunProductionHostAsync()
    {
        using var shutdown = new CancellationTokenSource();
        var cancellationGate = new object();
        var closing = false;
        Exception? cancellationFailure = null;
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            lock (cancellationGate)
            {
                if (closing)
                {
                    return;
                }

                try
                {
                    shutdown.Cancel();
                }
                catch (Exception exception)
                {
                    cancellationFailure =
                        BrokerControlFailureArbitration.PreserveSecondaryFailure(
                            cancellationFailure,
                            exception,
                            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
                }
            }
        };

        Exception? failure = null;
        var cancelHandlerRegistered = false;
        try
        {
            Console.CancelKeyPress += cancelHandler;
            cancelHandlerRegistered = true;
            var host = BrokerProductionCompositionV1.CreateHost();
            await host.RunAsync(shutdown.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = exception;
        }
        finally
        {
            lock (cancellationGate)
            {
                closing = true;
            }

            if (cancelHandlerRegistered)
            {
                try
                {
                    Console.CancelKeyPress -= cancelHandler;
                }
                catch (Exception exception)
                {
                    failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                        failure,
                        exception);
                }
            }
        }

        failure = BrokerControlFailureArbitration.PreserveSecondaryFailure(
            failure,
            cancellationFailure,
            BrokerControlFailureArbitration.ConcurrentFailureDataKey);
        if (failure is null)
        {
            return 0;
        }

        Console.Error.WriteLine(ProductionHostFailureMarker);
        Console.Error.Flush();
        return 1;
    }

    private static bool TryParseUserPresenceProbe(
        string[] args,
        out string mode,
        out string evidenceRoot)
    {
        mode = string.Empty;
        evidenceRoot = string.Empty;
        if (args.Length != 3 ||
            !string.Equals(
                args[1],
                UserPresenceEvidenceRootArgument,
                StringComparison.Ordinal))
        {
            return false;
        }

        if (string.Equals(args[0], UserPresenceCapabilityArgument, StringComparison.Ordinal))
        {
            mode = "capability";
        }
        else if (string.Equals(args[0], UserPresenceInteractiveArgument, StringComparison.Ordinal))
        {
            mode = "interactive";
        }
        else
        {
            return false;
        }

        evidenceRoot = args[2];
        return true;
    }

    private static async Task<int> RunUserPresenceProbeAsync(
        string mode,
        string evidenceRoot)
    {
        evidenceRoot = ValidateEvidenceRoot(evidenceRoot);
        if (string.Equals(mode, "capability", StringComparison.Ordinal))
        {
            var capability = WindowsWebAuthnPlatformV1.ProbeCapability();
            WriteEvidence(
                evidenceRoot,
                CapabilityEvidenceFileName,
                WriteCapabilityEvidence(capability));
            Console.WriteLine(
                "WEBAUTHN_CAPABILITY apiVersion=" + capability.ApiVersion +
                " available=" + capability.PlatformAuthenticatorAvailable.ToString().ToLowerInvariant());
            Console.WriteLine(CapabilityCompleteMarker);
            Console.Out.Flush();
            return 0;
        }

        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        using var window = await BrokerOwnedWindowV1.CreateAsync(cancellation.Token)
            .ConfigureAwait(false);
        var result = await WindowsWebAuthnPlatformV1.RunInteractiveProbeAsync(
                window,
                cancellation.Token)
            .ConfigureAwait(false);
        WriteEvidence(
            evidenceRoot,
            InteractiveEvidenceFileName,
            WriteInteractiveEvidence(result));
        Console.WriteLine(
            "WEBAUTHN_INTERACTIVE apiVersion=" + result.ApiVersion +
            " available=" + result.PlatformAuthenticatorAvailable.ToString().ToLowerInvariant() +
            " window=" + result.WindowValidated.ToString().ToLowerInvariant() +
            " registration=" + result.RegistrationVerified.ToString().ToLowerInvariant() +
            " assertion=" + result.AssertionVerified.ToString().ToLowerInvariant());
        Console.WriteLine(InteractiveCompleteMarker);
        Console.Out.Flush();
        return 0;
    }

    private static string ValidateEvidenceRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 240)
        {
            throw new InvalidDataException("The native WebAuthn evidence root is invalid.");
        }

        var fullPath = Path.GetFullPath(path);
        var driveRoot = Path.GetPathRoot(fullPath);
        if (!string.Equals(driveRoot, @"D:\", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fullPath.TrimEnd('\\'), @"D:", StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(fullPath))
        {
            throw new InvalidDataException(
                "The native WebAuthn evidence root must be an existing non-root D-drive directory.");
        }

        for (var current = new DirectoryInfo(fullPath); current is not null; current = current.Parent)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "The native WebAuthn evidence root traverses a reparse point.");
            }
        }

        return fullPath;
    }

    private static byte[] WriteCapabilityEvidence(WindowsWebAuthnCapabilityV1 capability)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = CreateEvidenceWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("schema", "codex-broker-webauthn-capability-v1");
        writer.WriteNumber("apiVersion", capability.ApiVersion);
        writer.WriteBoolean(
            "platformAuthenticatorAvailable",
            capability.PlatformAuthenticatorAvailable);
        writer.WriteBoolean("interactive", false);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] WriteInteractiveEvidence(
        WindowsWebAuthnInteractiveProbeResultV1 result)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = CreateEvidenceWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("schema", "codex-broker-webauthn-interactive-v1");
        writer.WriteNumber("apiVersion", result.ApiVersion);
        writer.WriteBoolean(
            "platformAuthenticatorAvailable",
            result.PlatformAuthenticatorAvailable);
        writer.WriteBoolean("windowValidated", result.WindowValidated);
        writer.WriteBoolean("registrationVerified", result.RegistrationVerified);
        writer.WriteBoolean("assertionVerified", result.AssertionVerified);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private static Utf8JsonWriter CreateEvidenceWriter(IBufferWriter<byte> buffer) =>
        new(
            buffer,
            new JsonWriterOptions
            {
                Indented = false,
                SkipValidation = false
            });

    private static void WriteEvidence(string root, string fileName, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length is < 1 or > MaximumEvidenceBytes || bytes.Any(value => value > 0x7F))
        {
            throw new InvalidDataException("The native WebAuthn evidence is not bounded ASCII JSON.");
        }

        using (JsonDocument.Parse(bytes, new JsonDocumentOptions
               {
                   AllowTrailingCommas = false,
                   CommentHandling = JsonCommentHandling.Disallow,
                   MaxDepth = 3
               }))
        {
        }

        var finalPath = Path.Combine(root, fileName);
        if (File.Exists(finalPath))
        {
            throw new IOException("The native WebAuthn evidence file already exists.");
        }

        var temporaryPath = finalPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, finalPath);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static ProbeBootstrap ParseBootstrap(string json)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 3
        });
        var root = document.RootElement;
        var expected = new[]
        {
            "kind",
            "mode",
            "endpointName",
            "connectionNonce",
            "releaseId",
            "manifestSha256"
        };
        if (root.ValueKind != JsonValueKind.Object ||
            !root.EnumerateObject().Select(property => property.Name)
                .OrderBy(value => value, StringComparer.Ordinal)
                .SequenceEqual(expected.OrderBy(value => value, StringComparer.Ordinal), StringComparer.Ordinal) ||
            !TryReadString(root, "kind", out var kind) ||
            !string.Equals(kind, "nativePeerProbe", StringComparison.Ordinal) ||
            !TryReadString(root, "mode", out var mode) ||
            mode is not "normal" and not "stall" and not "secondFrame" and
                not "oversize" and not "malformed" and not "exitBeforeHello" ||
            !TryReadString(root, "endpointName", out var endpointName) ||
            !TryReadString(root, "connectionNonce", out var connectionNonce) ||
            !TryReadString(root, "releaseId", out var releaseId) ||
            !TryReadString(root, "manifestSha256", out var manifestSha256))
        {
            throw new InvalidDataException("The native peer probe bootstrap shape is invalid.");
        }

        WindowsSameLogonNamedPipeServer.ValidateEndpointName(endpointName);
        _ = BrokerPeerHelloProtocol.Serialize(new BrokerPeerHello(
            BrokerPeerHelloProtocol.ProtocolVersion,
            BrokerPeerRole.Broker,
            1,
            1,
            DateTimeOffset.UtcNow,
            connectionNonce,
            releaseId,
            manifestSha256));
        return new ProbeBootstrap(
            mode,
            endpointName,
            connectionNonce,
            releaseId,
            manifestSha256);
    }

    private static bool TryReadString(
        JsonElement element,
        string propertyName,
        out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return value.Length > 0;
    }

    private static Task AwaitExitCommandAsync() => AwaitControlCommandAsync("EXIT");

    private static async Task AwaitControlCommandAsync(string expectedCommand)
    {
        var command = await ReadBoundedLineAsync(
                Console.In,
                maximumCharacters: 16,
                timeout: TimeSpan.FromSeconds(30))
            .ConfigureAwait(false);
        if (!string.Equals(command, expectedCommand, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The native probe control command is invalid.");
        }
    }

    private static async Task<string> ReadBoundedLineAsync(
        TextReader reader,
        int maximumCharacters,
        TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        var characters = new char[maximumCharacters + 1];
        var length = 0;
        while (true)
        {
            var read = await reader.ReadAsync(
                    characters.AsMemory(length, 1),
                    cancellation.Token)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The native probe bootstrap channel closed.");
            }

            if (characters[length] == '\n')
            {
                return new string(characters, 0, length).TrimEnd('\r');
            }

            length++;
            if (length > maximumCharacters)
            {
                throw new InvalidDataException("The native probe bootstrap line is too large.");
            }
        }
    }

    private static void EnsureWindowsEnvironment()
    {
        var windowsDirectory = Environment.GetEnvironmentVariable("WINDIR");
        if (string.IsNullOrWhiteSpace(windowsDirectory))
        {
            windowsDirectory = Directory.GetParent(Environment.SystemDirectory)?.FullName ?? @"C:\Windows";
            Environment.SetEnvironmentVariable(
                "WINDIR",
                windowsDirectory,
                EnvironmentVariableTarget.Process);
        }

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SystemRoot")))
        {
            Environment.SetEnvironmentVariable(
                "SystemRoot",
                windowsDirectory,
                EnvironmentVariableTarget.Process);
        }
    }

    private sealed record ProbeBootstrap(
        string Mode,
        string EndpointName,
        string ConnectionNonce,
        string ReleaseId,
        string ManifestSha256);
}
