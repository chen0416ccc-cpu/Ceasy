using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed class GuardianBrokerBootstrapV1 : IDisposable
{
    private byte[]? _managedEntryChallenge;

    internal GuardianBrokerBootstrapV1(
        string endpointName,
        string connectionNonce,
        ReadOnlySpan<byte> managedEntryChallenge,
        ulong brokerProcessHandle)
    {
        EndpointName = endpointName ?? throw new ArgumentNullException(nameof(endpointName));
        ConnectionNonce = connectionNonce ?? throw new ArgumentNullException(nameof(connectionNonce));
        if (managedEntryChallenge.Length != 32)
        {
            throw new ArgumentException(
                "The managed-entry challenge must contain exactly 32 bytes.",
                nameof(managedEntryChallenge));
        }

        _managedEntryChallenge = managedEntryChallenge.ToArray();
        BrokerProcessHandle = brokerProcessHandle;
    }

    internal string EndpointName { get; }

    internal string ConnectionNonce { get; }

    internal ReadOnlyMemory<byte> ManagedEntryChallenge =>
        _managedEntryChallenge ?? throw new ObjectDisposedException(nameof(GuardianBrokerBootstrapV1));

    internal ulong BrokerProcessHandle { get; }

    internal byte[] TakeManagedEntryChallenge() =>
        Interlocked.Exchange(ref _managedEntryChallenge, null) ??
        throw new ObjectDisposedException(nameof(GuardianBrokerBootstrapV1));

    public void Dispose()
    {
        var challenge = Interlocked.Exchange(ref _managedEntryChallenge, null);
        if (challenge is not null)
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }
}

internal static class GuardianBrokerBootstrapProtocolV1
{
    internal const int ProtocolVersion = 1;
    internal const int MaximumPayloadBytes = 2048;
    internal const int LengthPrefixBytes = sizeof(uint);
    internal const int MaximumFrameBytes = LengthPrefixBytes + MaximumPayloadBytes;
    internal const string EndpointPrefix = "codexguardian-broker-v1-";
    internal const string LaunchMode = "foreground";

    private const string Kind = "guardianBrokerManagedBootstrap";
    private static readonly JsonReaderOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 4
    };

    internal static byte[] SerializeFrame(GuardianBrokerBootstrapV1 bootstrap)
    {
        ArgumentNullException.ThrowIfNull(bootstrap);
        var payload = SerializePayload(bootstrap);
        try
        {
            var frame = new byte[checked(LengthPrefixBytes + payload.Length)];
            BinaryPrimitives.WriteUInt32LittleEndian(
                frame.AsSpan(0, LengthPrefixBytes),
                checked((uint)payload.Length));
            payload.CopyTo(frame.AsSpan(LengthPrefixBytes));
            return frame;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    internal static bool TryParseFrame(
        ReadOnlyMemory<byte> frame,
        out GuardianBrokerBootstrapV1? bootstrap,
        out string reason)
    {
        bootstrap = null;
        reason = "bootstrap-frame-invalid";
        if (frame.Length is <= LengthPrefixBytes or > MaximumFrameBytes)
        {
            reason = "bootstrap-frame-size";
            return false;
        }

        var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(
            frame.Span[..LengthPrefixBytes]);
        if (payloadLength is 0 or > MaximumPayloadBytes ||
            payloadLength != frame.Length - LengthPrefixBytes)
        {
            reason = "bootstrap-frame-size";
            return false;
        }

        var payload = frame[LengthPrefixBytes..];
        if (payload.Length >= 3 &&
            payload.Span[0] == 0xEF && payload.Span[1] == 0xBB && payload.Span[2] == 0xBF)
        {
            reason = "bootstrap-frame-bom";
            return false;
        }

        GuardianBrokerBootstrapV1? candidate = null;
        byte[]? challenge = null;
        byte[]? canonical = null;
        try
        {
            var reader = new Utf8JsonReader(payload.Span, JsonOptions);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject ||
                !ReadExactStringProperty(ref reader, "kind", Kind) ||
                !ReadProtocolProperty(ref reader) ||
                !ReadStringProperty(ref reader, "endpoint", out var endpoint) ||
                !ReadStringProperty(ref reader, "connectionNonce", out var nonce) ||
                !ReadHexBytesProperty(
                    ref reader,
                    "managedEntryChallenge",
                    out challenge,
                    out var challengeIsCanonical) ||
                !ReadStringProperty(ref reader, "brokerProcessHandle", out var handleText) ||
                !ReadStringProperty(ref reader, "launchMode", out var launchMode) ||
                !reader.Read() || reader.TokenType != JsonTokenType.EndObject ||
                reader.Read())
            {
                reason = "bootstrap-frame-shape";
                return false;
            }

            if (!IsCanonicalEndpoint(endpoint) ||
                !IsCanonicalUpperHex(nonce, 64) ||
                !challengeIsCanonical ||
                !TryParseCanonicalHandle(handleText, out var handle) ||
                !string.Equals(launchMode, LaunchMode, StringComparison.Ordinal))
            {
                reason = "bootstrap-frame-value";
                return false;
            }

            candidate = new GuardianBrokerBootstrapV1(
                endpoint,
                nonce,
                challenge,
                handle);
            canonical = SerializePayload(candidate);
            if (!payload.Span.SequenceEqual(canonical))
            {
                reason = "bootstrap-frame-noncanonical";
                return false;
            }

            bootstrap = candidate;
            candidate = null;
            reason = "accepted";
            return true;
        }
        catch (JsonException)
        {
            reason = "bootstrap-frame-invalid";
            return false;
        }
        finally
        {
            candidate?.Dispose();
            if (challenge is not null)
            {
                CryptographicOperations.ZeroMemory(challenge);
            }

            if (canonical is not null)
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
        }
    }

    private static byte[] SerializePayload(GuardianBrokerBootstrapV1 bootstrap)
    {
        if (!IsCanonicalEndpoint(bootstrap.EndpointName) ||
            !IsCanonicalUpperHex(bootstrap.ConnectionNonce, 64) ||
            bootstrap.ManagedEntryChallenge.Length != 32 ||
            bootstrap.BrokerProcessHandle == 0 ||
            bootstrap.BrokerProcessHandle > (ulong)nuint.MaxValue)
        {
            throw new ArgumentException(
                "The Guardian Broker bootstrap contains a noncanonical value.",
                nameof(bootstrap));
        }

        var buffer = new ArrayBufferWriter<byte>();
        Span<char> challengeHex = stackalloc char[64];
        try
        {
            WriteLowerHex(bootstrap.ManagedEntryChallenge.Span, challengeHex);
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
                   {
                       Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Default,
                       Indented = false,
                       SkipValidation = false
                   }))
            {
                writer.WriteStartObject();
                writer.WriteString("kind", Kind);
                writer.WriteNumber("protocol", ProtocolVersion);
                writer.WriteString("endpoint", bootstrap.EndpointName);
                writer.WriteString("connectionNonce", bootstrap.ConnectionNonce);
                writer.WriteString("managedEntryChallenge", challengeHex);
                writer.WriteString(
                    "brokerProcessHandle",
                    bootstrap.BrokerProcessHandle.ToString(CultureInfo.InvariantCulture));
                writer.WriteString("launchMode", LaunchMode);
                writer.WriteEndObject();
            }

            if (buffer.WrittenCount is <= 0 or > MaximumPayloadBytes)
            {
                throw new InvalidOperationException(
                    "The Guardian Broker bootstrap exceeds its bounded payload size.");
            }

            return buffer.WrittenSpan.ToArray();
        }
        finally
        {
            challengeHex.Clear();
        }
    }

    private static bool ReadExactStringProperty(
        ref Utf8JsonReader reader,
        string name,
        string expected) =>
        ReadStringProperty(ref reader, name, out var value) &&
        string.Equals(value, expected, StringComparison.Ordinal);

    private static bool ReadProtocolProperty(ref Utf8JsonReader reader)
    {
        if (!reader.Read() || reader.TokenType != JsonTokenType.PropertyName ||
            !reader.ValueTextEquals("protocol") ||
            !reader.Read() || reader.TokenType != JsonTokenType.Number ||
            !reader.TryGetInt32(out var protocol))
        {
            return false;
        }

        return protocol == ProtocolVersion;
    }

    private static bool ReadStringProperty(
        ref Utf8JsonReader reader,
        string name,
        out string value)
    {
        value = string.Empty;
        if (!reader.Read() || reader.TokenType != JsonTokenType.PropertyName ||
            !reader.ValueTextEquals(name) ||
            !reader.Read() || reader.TokenType != JsonTokenType.String)
        {
            return false;
        }

        value = reader.GetString() ?? string.Empty;
        return value.Length > 0;
    }

    private static bool ReadHexBytesProperty(
        ref Utf8JsonReader reader,
        string name,
        out byte[]? value,
        out bool isCanonical)
    {
        value = null;
        isCanonical = false;
        if (!reader.Read() || reader.TokenType != JsonTokenType.PropertyName ||
            !reader.ValueTextEquals(name) ||
            !reader.Read() || reader.TokenType != JsonTokenType.String ||
            reader.HasValueSequence || reader.ValueIsEscaped)
        {
            return false;
        }

        var text = reader.ValueSpan;
        if (text.Length != 64)
        {
            return false;
        }

        value = new byte[32];
        isCanonical = true;
        for (var index = 0; index < text.Length; index++)
        {
            if (!TryHexValue(text[index], out var nibble, out var lowerCanonical))
            {
                CryptographicOperations.ZeroMemory(value);
                value = null;
                isCanonical = false;
                return false;
            }

            isCanonical &= lowerCanonical;
            var byteIndex = index / 2;
            value[byteIndex] = (byte)(index % 2 == 0
                ? nibble << 4
                : value[byteIndex] | nibble);
        }

        return true;
    }

    private static bool IsCanonicalEndpoint(string value) =>
        value.Length == EndpointPrefix.Length + 32 &&
        value.StartsWith(EndpointPrefix, StringComparison.Ordinal) &&
        IsCanonicalLowerHex(value.AsSpan(EndpointPrefix.Length));

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

    private static bool IsCanonicalLowerHex(ReadOnlySpan<char> value)
    {
        if (value.Length != 32)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character) && character is not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryHexValue(
        byte value,
        out int nibble,
        out bool lowerCanonical)
    {
        if (value is >= (byte)'0' and <= (byte)'9')
        {
            nibble = value - (byte)'0';
            lowerCanonical = true;
            return true;
        }

        if (value is >= (byte)'a' and <= (byte)'f')
        {
            nibble = value - (byte)'a' + 10;
            lowerCanonical = true;
            return true;
        }

        if (value is >= (byte)'A' and <= (byte)'F')
        {
            nibble = value - (byte)'A' + 10;
            lowerCanonical = false;
            return true;
        }

        nibble = 0;
        lowerCanonical = false;
        return false;
    }

    private static void WriteLowerHex(ReadOnlySpan<byte> value, Span<char> destination)
    {
        const string digits = "0123456789abcdef";
        for (var index = 0; index < value.Length; index++)
        {
            destination[index * 2] = digits[value[index] >> 4];
            destination[index * 2 + 1] = digits[value[index] & 0x0F];
        }
    }

    private static bool TryParseCanonicalHandle(string value, out ulong handle)
    {
        handle = 0;
        return value.Length is > 0 and <= 20 &&
            value[0] != '0' &&
            IsAsciiDigits(value) &&
            ulong.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out handle) &&
            handle <= (ulong)nuint.MaxValue;
    }

    private static bool IsAsciiDigits(string value)
    {
        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character))
            {
                return false;
            }
        }

        return true;
    }
}
