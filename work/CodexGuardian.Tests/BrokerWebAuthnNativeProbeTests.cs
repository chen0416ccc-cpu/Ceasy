using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

internal static class BrokerWebAuthnNativeProbeTests
{
    internal const string CapabilityArgument = "--native-user-presence-capability-probe";
    internal const string InteractiveArgument = "--native-user-presence-interactive-probe";
    internal const string EvidenceRootArgument = "--native-user-presence-evidence-root";
    internal const string CapabilityCompletionMarker =
        "NATIVE_USER_PRESENCE_CAPABILITY_PROBE_COMPLETE";
    internal const string InteractiveCompletionMarker =
        "NATIVE_USER_PRESENCE_INTERACTIVE_PROBE_COMPLETE";
    internal const string BrokerCapabilityCompletionMarker =
        "BROKER_USER_PRESENCE_CAPABILITY_COMPLETE";
    internal const string BrokerInteractiveCompletionMarker =
        "BROKER_USER_PRESENCE_INTERACTIVE_COMPLETE";

    private const string CapabilityEvidenceFileName = "webauthn-capability-v1.json";
    private const string InteractiveEvidenceFileName = "webauthn-interactive-v1.json";
    private const int MaximumOutputCharacters = 4096;
    private const int MaximumEvidenceBytes = 4096;

    internal static bool IsProbeInvocation(string[] args) =>
        args.Contains(CapabilityArgument, StringComparer.Ordinal) ||
        args.Contains(InteractiveArgument, StringComparer.Ordinal);

    internal static async Task RunIfRequestedAsync(
        string[] args,
        Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(assert);
        var capabilityCount = args.Count(value =>
            string.Equals(value, CapabilityArgument, StringComparison.Ordinal));
        var interactiveCount = args.Count(value =>
            string.Equals(value, InteractiveArgument, StringComparison.Ordinal));
        var evidenceArgumentCount = args.Count(value =>
            string.Equals(value, EvidenceRootArgument, StringComparison.Ordinal));
        var validShape =
            capabilityCount + interactiveCount == 1 &&
            evidenceArgumentCount == 1 &&
            args.Length == 3 &&
            string.Equals(args[1], EvidenceRootArgument, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(args[2]);
        if (!validShape)
        {
            assert(
                false,
                "native user-presence probe requires exactly one mode and one explicit evidence root");
            return;
        }

        var interactive = interactiveCount == 1;
        var evidenceRoot = ValidateEvidenceRoot(args[2]);
        var evidenceFileName = interactive
            ? InteractiveEvidenceFileName
            : CapabilityEvidenceFileName;
        var evidencePath = Path.Combine(evidenceRoot, evidenceFileName);
        if (File.Exists(evidencePath) || Directory.EnumerateFileSystemEntries(evidenceRoot).Any())
        {
            assert(false, "native user-presence evidence root is initially empty");
            return;
        }

        try
        {
            var result = await RunBrokerProbeAsync(
                    interactive,
                    evidenceRoot,
                    evidencePath)
                .ConfigureAwait(false);
            if (interactive)
            {
                ValidateInteractiveResult(result, evidencePath, evidenceRoot);
                assert(
                    true,
                    "interactive Windows WebAuthn registration and assertion use one Broker-owned window");
                Console.WriteLine(InteractiveCompletionMarker);
            }
            else
            {
                ValidateCapabilityResult(result, evidencePath, evidenceRoot);
                assert(
                    true,
                    "Windows WebAuthn capability probe is non-interactive and bounded");
                Console.WriteLine(CapabilityCompletionMarker);
            }
        }
        catch (Exception exception)
        {
            assert(
                false,
                (interactive
                    ? "interactive Windows WebAuthn native probe"
                    : "Windows WebAuthn non-interactive capability probe") +
                ": " + exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static async Task<BrokerProbeResult> RunBrokerProbeAsync(
        bool interactive,
        string evidenceRoot,
        string evidencePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The native WebAuthn probe requires Windows.");
        }

        var brokerExecutable = Path.Combine(
            AppContext.BaseDirectory,
            "CodexGuardian.Broker.exe");
        if (!File.Exists(brokerExecutable))
        {
            throw new FileNotFoundException("The fresh Broker executable is absent.", brokerExecutable);
        }

        var startInfo = new ProcessStartInfo(brokerExecutable)
        {
            CreateNoWindow = !interactive,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = AppContext.BaseDirectory
        };
        startInfo.ArgumentList.Add(interactive ? InteractiveArgument : CapabilityArgument);
        startInfo.ArgumentList.Add(EvidenceRootArgument);
        startInfo.ArgumentList.Add(evidenceRoot);
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException(
            "The fresh Broker WebAuthn probe did not start.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(
            interactive ? TimeSpan.FromMinutes(11) : TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync().ConfigureAwait(false);
            }

            throw;
        }

        var stdout = await standardOutput.ConfigureAwait(false);
        var stderr = await standardError.ConfigureAwait(false);
        if (stdout.Length > MaximumOutputCharacters || stderr.Length > MaximumOutputCharacters)
        {
            throw new InvalidDataException("The Broker WebAuthn probe output exceeded its bound.");
        }

        return new BrokerProbeResult(
            process.ExitCode,
            stdout.Replace("\r\n", "\n", StringComparison.Ordinal),
            stderr.Replace("\r\n", "\n", StringComparison.Ordinal),
            evidencePath);
    }

    private static void ValidateCapabilityResult(
        BrokerProbeResult result,
        string evidencePath,
        string evidenceRoot)
    {
        Ensure(result.ExitCode == 0, "The Broker capability child failed.");
        Ensure(result.StandardError.Length == 0, "The Broker capability child wrote stderr.");
        using var evidence = ReadEvidence(evidencePath);
        var root = evidence.RootElement;
        var properties = root.EnumerateObject().Select(property => property.Name).ToArray();
        var apiVersion = root.GetProperty("apiVersion").TryGetUInt32(out var parsedApiVersion)
            ? parsedApiVersion
            : 0;
        Ensure(
            properties.SequenceEqual(
                new[]
                {
                    "schema",
                    "apiVersion",
                    "platformAuthenticatorAvailable",
                    "interactive"
                },
                StringComparer.Ordinal) &&
            root.GetProperty("schema").GetString() ==
                "codex-broker-webauthn-capability-v1" &&
            apiVersion is > 0 and <= 1024 &&
            root.GetProperty("platformAuthenticatorAvailable").ValueKind is
                JsonValueKind.True or JsonValueKind.False &&
            root.GetProperty("interactive").ValueKind == JsonValueKind.False,
            "The Broker capability evidence shape is invalid.");
        var available = root.GetProperty("platformAuthenticatorAvailable").GetBoolean();
        var expectedOutput =
            "WEBAUTHN_CAPABILITY apiVersion=" + apiVersion +
            " available=" + available.ToString().ToLowerInvariant() + "\n" +
            BrokerCapabilityCompletionMarker + "\n";
        Ensure(
            string.Equals(result.StandardOutput, expectedOutput, StringComparison.Ordinal) &&
            !result.StandardOutput.Contains(
                BrokerInteractiveCompletionMarker,
                StringComparison.Ordinal) &&
            Directory.EnumerateFileSystemEntries(evidenceRoot).SequenceEqual(
                new[] { evidencePath },
                StringComparer.OrdinalIgnoreCase),
            "The Broker capability probe output or evidence closure is invalid.");
    }

    private static void ValidateInteractiveResult(
        BrokerProbeResult result,
        string evidencePath,
        string evidenceRoot)
    {
        Ensure(result.ExitCode == 0, "The Broker interactive child failed.");
        Ensure(result.StandardError.Length == 0, "The Broker interactive child wrote stderr.");
        using var evidence = ReadEvidence(evidencePath);
        var root = evidence.RootElement;
        var properties = root.EnumerateObject().Select(property => property.Name).ToArray();
        var apiVersion = root.GetProperty("apiVersion").TryGetUInt32(out var parsedApiVersion)
            ? parsedApiVersion
            : 0;
        Ensure(
            properties.SequenceEqual(
                new[]
                {
                    "schema",
                    "apiVersion",
                    "platformAuthenticatorAvailable",
                    "windowValidated",
                    "registrationVerified",
                    "assertionVerified"
                },
                StringComparer.Ordinal) &&
            root.GetProperty("schema").GetString() ==
                "codex-broker-webauthn-interactive-v1" &&
            apiVersion is > 0 and <= 1024 &&
            root.GetProperty("platformAuthenticatorAvailable").GetBoolean() &&
            root.GetProperty("windowValidated").GetBoolean() &&
            root.GetProperty("registrationVerified").GetBoolean() &&
            root.GetProperty("assertionVerified").GetBoolean(),
            "The Broker interactive evidence shape is invalid.");
        var expectedOutput =
            "WEBAUTHN_INTERACTIVE apiVersion=" + apiVersion +
            " available=true window=true registration=true assertion=true\n" +
            BrokerInteractiveCompletionMarker + "\n";
        Ensure(
            string.Equals(result.StandardOutput, expectedOutput, StringComparison.Ordinal) &&
            !result.StandardOutput.Contains(
                BrokerCapabilityCompletionMarker,
                StringComparison.Ordinal) &&
            Directory.EnumerateFileSystemEntries(evidenceRoot).SequenceEqual(
                new[] { evidencePath },
                StringComparer.OrdinalIgnoreCase),
            "The Broker interactive probe output or evidence closure is invalid.");
    }

    private static JsonDocument ReadEvidence(string path)
    {
        var bytes = File.ReadAllBytes(path);
        Ensure(
            bytes.Length is > 0 and <= MaximumEvidenceBytes &&
            !bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble) &&
            bytes.All(value => value <= 0x7F),
            "The Broker WebAuthn evidence is not bounded BOM-free ASCII.");
        return JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 3
        });
    }

    private static string ValidateEvidenceRoot(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetPathRoot(fullPath), @"D:\", StringComparison.OrdinalIgnoreCase) ||
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

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record BrokerProbeResult(
        int ExitCode,
        string StandardOutput,
        string StandardError,
        string EvidencePath);
}
