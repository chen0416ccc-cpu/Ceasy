using CodexGuardian.Control;
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

internal static class GuardianBrokerBootstrapOfflineTests
{
    private const string CanonicalChallengeHex =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "Guardian Broker bootstrap frame round-trips one canonical bounded payload",
            TestCanonicalRoundTrip,
            assert);
        RunCase(
            "Guardian Broker bootstrap rejects malformed and noncanonical frames",
            TestStrictRejection,
            assert);
        RunCase(
            "Guardian Broker bootstrap protocol remains an internal Control primitive",
            TestSurface,
            assert);
        return Task.CompletedTask;
    }

    private static void TestCanonicalRoundTrip()
    {
        using var canonicalBootstrap = CreateCanonicalBootstrap();
        var frame = GuardianBrokerBootstrapProtocolV1.SerializeFrame(canonicalBootstrap);
        Ensure(
            frame.Length is > GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes and
                <= GuardianBrokerBootstrapProtocolV1.MaximumFrameBytes &&
            BinaryPrimitives.ReadUInt32LittleEndian(
                frame.AsSpan(0, GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes)) ==
                frame.Length - GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes,
            "the canonical bootstrap did not use one exact little-endian length prefix");
        Ensure(
             GuardianBrokerBootstrapProtocolV1.TryParseFrame(
                 frame,
                 out var parsed,
                 out var reason) &&
            parsed is not null &&
            BootstrapEquals(parsed, canonicalBootstrap) &&
             string.Equals(reason, "accepted", StringComparison.Ordinal) &&
             frame.SequenceEqual(GuardianBrokerBootstrapProtocolV1.SerializeFrame(parsed)),
             "the canonical bootstrap did not round-trip byte-for-byte");
        parsed?.Dispose();

        var payload = Encoding.UTF8.GetString(
            frame.AsSpan(GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes));
        Ensure(
            payload[0] == '{' && payload[^1] == '}' &&
            !payload.Contains('\r') && !payload.Contains('\n') &&
            payload.IndexOf("\"kind\"", StringComparison.Ordinal) <
                payload.IndexOf("\"protocol\"", StringComparison.Ordinal) &&
            payload.IndexOf("\"brokerProcessHandle\"", StringComparison.Ordinal) <
                payload.IndexOf("\"launchMode\"", StringComparison.Ordinal),
            "the canonical bootstrap JSON order or whitespace contract drifted");
    }

    private static void TestStrictRejection()
    {
        using var canonicalBootstrap = CreateCanonicalBootstrap();
        var canonical = GuardianBrokerBootstrapProtocolV1.SerializeFrame(canonicalBootstrap);
        var wrongLength = canonical.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(
            wrongLength.AsSpan(0, GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes),
            checked((uint)wrongLength.Length));
        Reject(wrongLength, "bootstrap-frame-size");

        var payload = canonical.AsSpan(
                GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes)
            .ToArray();
        Reject(BuildFrame([0xEF, 0xBB, 0xBF, .. payload]), "bootstrap-frame-bom");
        Reject(BuildFrame([0xFF]), "bootstrap-frame-invalid");

        var json = Encoding.UTF8.GetString(payload);
        Reject(
            BuildFrame(Encoding.UTF8.GetBytes(json[..^1] + ",\"extra\":true}")),
            "bootstrap-frame-shape");
        Reject(
            BuildFrame(Encoding.UTF8.GetBytes(
                json.Replace(
                    "\"protocol\":1",
                    "\"protocol\":1,\"protocol\":1",
                    StringComparison.Ordinal))),
            "bootstrap-frame-shape");
        Reject(
            BuildFrame(Encoding.UTF8.GetBytes(" " + json)),
            "bootstrap-frame-noncanonical");
        Reject(
             BuildFrame(Encoding.UTF8.GetBytes(json.Replace(
                canonicalBootstrap.EndpointName,
                canonicalBootstrap.EndpointName.ToUpperInvariant(),
                 StringComparison.Ordinal))),
            "bootstrap-frame-value");
        Reject(
             BuildFrame(Encoding.UTF8.GetBytes(json.Replace(
                canonicalBootstrap.ConnectionNonce,
                canonicalBootstrap.ConnectionNonce.ToLowerInvariant(),
                 StringComparison.Ordinal))),
            "bootstrap-frame-value");
        Reject(
             BuildFrame(Encoding.UTF8.GetBytes(json.Replace(
                CanonicalChallengeHex,
                CanonicalChallengeHex.ToUpperInvariant(),
                 StringComparison.Ordinal))),
            "bootstrap-frame-value");
        Reject(
            BuildFrame(Encoding.UTF8.GetBytes(json.Replace(
                "\"brokerProcessHandle\":\"424242\"",
                "\"brokerProcessHandle\":\"0424242\"",
                StringComparison.Ordinal))),
            "bootstrap-frame-value");

        Reject(
            new byte[GuardianBrokerBootstrapProtocolV1.MaximumFrameBytes + 1],
            "bootstrap-frame-size");
    }

    private static void TestSurface()
    {
        var protocol = typeof(GuardianBrokerBootstrapProtocolV1);
        var value = typeof(GuardianBrokerBootstrapV1);
        Ensure(
            protocol.IsNotPublic && protocol.IsAbstract && protocol.IsSealed &&
            value.IsNotPublic && value.IsSealed &&
            protocol.Assembly.GetReferencedAssemblies().All(reference =>
                !string.Equals(reference.Name, "CodexGuardian.Broker", StringComparison.Ordinal) &&
                !string.Equals(reference.Name, "CodexGuardian.Trust", StringComparison.Ordinal)) &&
            GuardianBrokerBootstrapProtocolV1.MaximumPayloadBytes == 2048,
            "the bootstrap primitive escaped Control or gained a higher-layer dependency");
    }

    private static byte[] BuildFrame(byte[] payload)
    {
        var frame = new byte[checked(
            GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes + payload.Length)];
        BinaryPrimitives.WriteUInt32LittleEndian(
            frame.AsSpan(0, GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes),
            checked((uint)payload.Length));
        payload.CopyTo(frame.AsSpan(GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes));
        return frame;
    }

    private static GuardianBrokerBootstrapV1 CreateCanonicalBootstrap() =>
        new(
            GuardianBrokerBootstrapProtocolV1.EndpointPrefix + new string('a', 32),
            new string('A', 64),
            Convert.FromHexString(CanonicalChallengeHex),
            424242UL);

    private static bool BootstrapEquals(
        GuardianBrokerBootstrapV1 left,
        GuardianBrokerBootstrapV1 right) =>
        string.Equals(left.EndpointName, right.EndpointName, StringComparison.Ordinal) &&
        string.Equals(left.ConnectionNonce, right.ConnectionNonce, StringComparison.Ordinal) &&
        left.ManagedEntryChallenge.Span.SequenceEqual(right.ManagedEntryChallenge.Span) &&
        left.BrokerProcessHandle == right.BrokerProcessHandle;

    private static void Reject(byte[] frame, string expectedReason)
    {
        Ensure(
            !GuardianBrokerBootstrapProtocolV1.TryParseFrame(
                frame,
                out var parsed,
                out var reason) &&
            parsed is null &&
            string.Equals(reason, expectedReason, StringComparison.Ordinal),
            "a malformed bootstrap frame was accepted or misclassified: " + reason);
    }

    private static void RunCase(string name, Action action, Action<bool, string> assert)
    {
        try
        {
            action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
