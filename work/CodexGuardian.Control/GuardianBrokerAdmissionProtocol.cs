using System;
using System.Buffers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed record GuardianBrokerAdmissionReadyV1(
    string ConnectionNonce,
    string ChallengeSha256,
    uint BrokerProcessId,
    uint GuardianProcessId,
    string ReleaseId,
    string ManifestSha256);

internal static class GuardianBrokerAdmissionProtocolV1
{
    internal const int ProtocolVersion = 1;
    internal const int MaximumReadyBytes = 2048;

    private const string Kind = "guardianBrokerAdmissionReady";
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 4
    };

    internal static byte[] SerializeReady(GuardianBrokerAdmissionReadyV1 ready)
    {
        ArgumentNullException.ThrowIfNull(ready);
        if (!IsCanonicalUpperHex(ready.ConnectionNonce, 64) ||
            !IsCanonicalUpperHex(ready.ChallengeSha256, 64) ||
            ready.BrokerProcessId == 0 ||
            ready.GuardianProcessId == 0 ||
            !CodexCdpBrokerProtocol.IsControlIdentifier(ready.ReleaseId) ||
            !IsCanonicalUpperHex(ready.ManifestSha256, 64))
        {
            throw new ArgumentException(
                "The Guardian Broker admission-ready message contains a noncanonical value.",
                nameof(ready));
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
               {
                   Encoder = JavaScriptEncoder.Default,
                   Indented = false,
                   SkipValidation = false
               }))
        {
            writer.WriteStartObject();
            writer.WriteString("kind", Kind);
            writer.WriteNumber("protocol", ProtocolVersion);
            writer.WriteString("connectionNonce", ready.ConnectionNonce);
            writer.WriteString("challengeSha256", ready.ChallengeSha256);
            writer.WriteNumber("brokerProcessId", ready.BrokerProcessId);
            writer.WriteNumber("guardianProcessId", ready.GuardianProcessId);
            writer.WriteString("releaseId", ready.ReleaseId);
            writer.WriteString("manifestSha256", ready.ManifestSha256);
            writer.WriteEndObject();
        }

        if (buffer.WrittenCount is <= 0 or > MaximumReadyBytes)
        {
            throw new InvalidOperationException(
                "The Guardian Broker admission-ready message exceeds its bounded protocol size.");
        }

        return buffer.WrittenSpan.ToArray();
    }

    internal static bool TryParseReady(
        ReadOnlyMemory<byte> utf8Json,
        out GuardianBrokerAdmissionReadyV1? ready,
        out string reason)
    {
        ready = null;
        reason = "admission-ready-invalid";
        if (utf8Json.Length is < 1 or > MaximumReadyBytes)
        {
            reason = "admission-ready-size";
            return false;
        }

        var span = utf8Json.Span;
        if (span.Length >= 3 &&
            span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF)
        {
            reason = "admission-ready-bom";
            return false;
        }

        try
        {
            _ = StrictUtf8.GetCharCount(span);
            using var document = JsonDocument.Parse(utf8Json, JsonOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !HasExactPropertiesInOrder(root))
            {
                reason = "admission-ready-shape";
                return false;
            }

            if (!TryReadExactString(root, "kind", Kind) ||
                root.GetProperty("protocol").ValueKind != JsonValueKind.Number ||
                !root.GetProperty("protocol").TryGetInt32(out var protocol) ||
                protocol != ProtocolVersion ||
                !TryReadString(root, "connectionNonce", out var connectionNonce) ||
                !IsCanonicalUpperHex(connectionNonce, 64) ||
                !TryReadString(root, "challengeSha256", out var challengeSha256) ||
                !IsCanonicalUpperHex(challengeSha256, 64) ||
                !root.GetProperty("brokerProcessId").TryGetUInt32(out var brokerProcessId) ||
                brokerProcessId == 0 ||
                !root.GetProperty("guardianProcessId").TryGetUInt32(out var guardianProcessId) ||
                guardianProcessId == 0 ||
                !TryReadString(root, "releaseId", out var releaseId) ||
                !CodexCdpBrokerProtocol.IsControlIdentifier(releaseId) ||
                !TryReadString(root, "manifestSha256", out var manifestSha256) ||
                !IsCanonicalUpperHex(manifestSha256, 64))
            {
                reason = "admission-ready-value";
                return false;
            }

            var parsed = new GuardianBrokerAdmissionReadyV1(
                connectionNonce,
                challengeSha256,
                brokerProcessId,
                guardianProcessId,
                releaseId,
                manifestSha256);
            if (!SerializeReady(parsed).AsSpan().SequenceEqual(span))
            {
                reason = "admission-ready-noncanonical";
                return false;
            }

            ready = parsed;
            reason = "accepted";
            return true;
        }
        catch (Exception exception) when (
            exception is JsonException or DecoderFallbackException or
            ArgumentException or InvalidOperationException)
        {
            reason = "admission-ready-invalid";
            return false;
        }
    }

    private static bool HasExactPropertiesInOrder(JsonElement root)
    {
        string[] expectedNames =
        [
            "kind",
            "protocol",
            "connectionNonce",
            "challengeSha256",
            "brokerProcessId",
            "guardianProcessId",
            "releaseId",
            "manifestSha256"
        ];
        var index = 0;
        foreach (var property in root.EnumerateObject())
        {
            if (index >= expectedNames.Length ||
                !string.Equals(
                    property.Name,
                    expectedNames[index],
                    StringComparison.Ordinal))
            {
                return false;
            }

            index++;
        }

        return index == expectedNames.Length;
    }

    private static bool TryReadString(
        JsonElement root,
        string name,
        out string value)
    {
        value = string.Empty;
        var element = root.GetProperty(name);
        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = element.GetString() ?? string.Empty;
        return value.Length > 0;
    }

    private static bool TryReadExactString(
        JsonElement root,
        string name,
        string expected) =>
        TryReadString(root, name, out var value) &&
        string.Equals(value, expected, StringComparison.Ordinal);

    private static bool IsCanonicalUpperHex(string value, int length)
    {
        if (value.Length != length)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character) && character is not (>= 'A' and <= 'F'))
            {
                return false;
            }
        }

        return true;
    }
}
