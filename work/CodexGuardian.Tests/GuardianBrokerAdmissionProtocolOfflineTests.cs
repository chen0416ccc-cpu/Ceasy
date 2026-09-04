using CodexGuardian.Control;
using System;
using System.Text;
using System.Threading.Tasks;

internal static class GuardianBrokerAdmissionProtocolOfflineTests
{
    private static readonly GuardianBrokerAdmissionReadyV1 CanonicalReady = new(
        new string('A', 64),
        new string('B', 64),
        1234U,
        5678U,
        "release-ready-v1",
        new string('C', 64));

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "Guardian Broker admission-ready message round-trips canonical strict UTF-8",
            TestCanonicalRoundTrip,
            assert);
        RunCase(
            "Guardian Broker admission-ready message fixes its exact property order",
            TestExactPropertyOrder,
            assert);
        RunCase(
            "Guardian Broker admission-ready message rejects malformed shapes and bytes",
            TestShapeAndEncodingRejection,
            assert);
        RunCase(
            "Guardian Broker admission-ready message rejects noncanonical values",
            TestValueRejection,
            assert);
        RunCase(
            "Guardian Broker admission-ready protocol remains bounded and internal",
            TestSurface,
            assert);
        return Task.CompletedTask;
    }

    private static void TestCanonicalRoundTrip()
    {
        var payload = GuardianBrokerAdmissionProtocolV1.SerializeReady(CanonicalReady);
        Ensure(
            payload.Length is > 0 and <= GuardianBrokerAdmissionProtocolV1.MaximumReadyBytes &&
            (payload.Length < 3 ||
                payload[0] != 0xEF || payload[1] != 0xBB || payload[2] != 0xBF) &&
            GuardianBrokerAdmissionProtocolV1.TryParseReady(
                payload,
                out var parsed,
                out var reason) &&
            parsed is not null &&
            parsed == CanonicalReady &&
            string.Equals(reason, "accepted", StringComparison.Ordinal) &&
            GuardianBrokerAdmissionProtocolV1.SerializeReady(parsed).AsSpan()
                .SequenceEqual(payload),
            "the canonical admission-ready message did not round-trip byte-for-byte");
    }

    private static void TestExactPropertyOrder()
    {
        var payload = GuardianBrokerAdmissionProtocolV1.SerializeReady(CanonicalReady);
        var json = Encoding.UTF8.GetString(payload);
        var expected =
            "{\"kind\":\"guardianBrokerAdmissionReady\",\"protocol\":1," +
            "\"connectionNonce\":\"" + CanonicalReady.ConnectionNonce + "\"," +
            "\"challengeSha256\":\"" + CanonicalReady.ChallengeSha256 + "\"," +
            "\"brokerProcessId\":1234,\"guardianProcessId\":5678," +
            "\"releaseId\":\"release-ready-v1\",\"manifestSha256\":\"" +
            CanonicalReady.ManifestSha256 + "\"}";
        Ensure(
            string.Equals(json, expected, StringComparison.Ordinal),
            "the canonical admission-ready property order or formatting drifted");

        var swapped = json.Replace(
            "\"connectionNonce\":\"" + CanonicalReady.ConnectionNonce + "\"," +
                "\"challengeSha256\":\"" + CanonicalReady.ChallengeSha256 + "\"",
            "\"challengeSha256\":\"" + CanonicalReady.ChallengeSha256 + "\"," +
                "\"connectionNonce\":\"" + CanonicalReady.ConnectionNonce + "\"",
            StringComparison.Ordinal);
        Reject(Encoding.UTF8.GetBytes(swapped), "admission-ready-shape");
    }

    private static void TestShapeAndEncodingRejection()
    {
        var canonical = GuardianBrokerAdmissionProtocolV1.SerializeReady(CanonicalReady);
        var json = Encoding.UTF8.GetString(canonical);

        Reject(Array.Empty<byte>(), "admission-ready-size");
        Reject(
            new byte[GuardianBrokerAdmissionProtocolV1.MaximumReadyBytes + 1],
            "admission-ready-size");
        Reject([0xEF, 0xBB, 0xBF, .. canonical], "admission-ready-bom");
        Reject([0xFF], "admission-ready-invalid");
        Reject(
            Encoding.UTF8.GetBytes(json[..^1] + ",\"extra\":true}"),
            "admission-ready-shape");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                "\"protocol\":1",
                "\"protocol\":1,\"protocol\":1",
                StringComparison.Ordinal)),
            "admission-ready-shape");
    }

    private static void TestValueRejection()
    {
        var canonical = GuardianBrokerAdmissionProtocolV1.SerializeReady(CanonicalReady);
        var json = Encoding.UTF8.GetString(canonical);

        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                CanonicalReady.ConnectionNonce,
                CanonicalReady.ConnectionNonce.ToLowerInvariant(),
                StringComparison.Ordinal)),
            "admission-ready-value");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                CanonicalReady.ChallengeSha256,
                new string('B', 63) + "G",
                StringComparison.Ordinal)),
            "admission-ready-value");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                CanonicalReady.ManifestSha256,
                new string('C', 63),
                StringComparison.Ordinal)),
            "admission-ready-value");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                "\"brokerProcessId\":1234",
                "\"brokerProcessId\":0",
                StringComparison.Ordinal)),
            "admission-ready-value");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                "\"guardianProcessId\":5678",
                "\"guardianProcessId\":4294967296",
                StringComparison.Ordinal)),
            "admission-ready-value");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                CanonicalReady.ReleaseId,
                "short",
                StringComparison.Ordinal)),
            "admission-ready-value");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                CanonicalReady.ReleaseId,
                "release.ready.v1",
                StringComparison.Ordinal)),
            "admission-ready-value");
        Reject(
            Encoding.UTF8.GetBytes(" " + json),
            "admission-ready-noncanonical");
        Reject(
            Encoding.UTF8.GetBytes(json.Replace(
                CanonicalReady.ReleaseId,
                "release\\u002Dready\\u002Dv1",
                StringComparison.Ordinal)),
            "admission-ready-noncanonical");
    }

    private static void TestSurface()
    {
        var protocol = typeof(GuardianBrokerAdmissionProtocolV1);
        var value = typeof(GuardianBrokerAdmissionReadyV1);
        Ensure(
            protocol.IsNotPublic && protocol.IsAbstract && protocol.IsSealed &&
            value.IsNotPublic && value.IsSealed &&
            GuardianBrokerAdmissionProtocolV1.ProtocolVersion == 1 &&
            GuardianBrokerAdmissionProtocolV1.MaximumReadyBytes == 2048,
            "the admission-ready primitive escaped Control or exceeded its size bound");
    }

    private static void Reject(byte[] payload, string expectedReason)
    {
        Ensure(
            !GuardianBrokerAdmissionProtocolV1.TryParseReady(
                payload,
                out var parsed,
                out var reason) &&
            parsed is null &&
            string.Equals(reason, expectedReason, StringComparison.Ordinal),
            "a malformed admission-ready message was accepted or misclassified: " + reason);
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
