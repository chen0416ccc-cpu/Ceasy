using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace CodexGuardian.Broker;

internal static class BrokerWebAuthnConstantsV1
{
    internal const string RelyingPartyId = "codexguardian.local";
    internal const string RelyingPartyDisplayName = "CodexGuardian";
    internal const string Origin = "https://codexguardian.local";
    internal const string CredentialType = "public-key";
    internal const string RegistrationClientDataType = "webauthn.create";
    internal const string AssertionClientDataType = "webauthn.get";
    internal const string PlatformAttachment = "platform";
    internal const string UserVerification = "required";
    internal const string ResidentKey = "discouraged";
    internal const string Attestation = "none";
    internal const int Es256Algorithm = -7;
    internal const int Ec2KeyType = 2;
    internal const int P256Curve = 1;
    internal const string HashAlgorithm = "SHA-256";
    internal const string RegistrationDomainSeparator =
        "CodexGuardian\0WebAuthn\0Registration\0v1\0";
    internal const string ConsentDomainSeparator =
        "CodexGuardian\0WebAuthn\0ConsentStatement\0v1\0";
    internal const string FreshPresenceDomainSeparator =
        "CodexGuardian\0WebAuthn\0FreshPresence\0v1\0";
    internal const string RegistrationStatementSchema =
        "codex-broker-webauthn-registration-statement-v1";
}

internal sealed class BrokerWebAuthnRegistrationStatementV1
{
    private readonly byte[] _derivedUserHandle;
    private readonly byte[] _registrationNonce;
    private readonly byte[] _canonicalStatementBytes;

    private BrokerWebAuthnRegistrationStatementV1(
        string brokerEpoch,
        uint windowsSessionId,
        byte[] derivedUserHandle,
        byte[] registrationNonce,
        string userHandleSha256,
        string registrationNonceBase64,
        byte[] canonicalStatementBytes)
    {
        BrokerEpoch = brokerEpoch;
        WindowsSessionId = windowsSessionId;
        _derivedUserHandle = derivedUserHandle;
        _registrationNonce = registrationNonce;
        UserHandleSha256 = userHandleSha256;
        RegistrationNonceBase64 = registrationNonceBase64;
        _canonicalStatementBytes = canonicalStatementBytes;
    }

    internal string Schema => BrokerWebAuthnConstantsV1.RegistrationStatementSchema;

    internal string BrokerEpoch { get; }

    internal uint WindowsSessionId { get; }

    internal byte[] DerivedUserHandle => (byte[])_derivedUserHandle.Clone();

    internal byte[] RegistrationNonce => (byte[])_registrationNonce.Clone();

    internal string UserHandleSha256 { get; }

    internal string RegistrationNonceBase64 { get; }

    internal byte[] CanonicalStatementBytes => (byte[])_canonicalStatementBytes.Clone();

    internal static BrokerWebAuthnRegistrationStatementV1 Create(
        string brokerEpoch,
        uint windowsSessionId,
        ReadOnlySpan<byte> derivedUserHandle,
        ReadOnlySpan<byte> registrationNonce)
    {
        ArgumentNullException.ThrowIfNull(brokerEpoch);
        if (!IsExactBrokerEpoch(brokerEpoch))
        {
            throw new ArgumentException(
                "The Broker epoch must be exactly 32 lowercase hexadecimal characters.",
                nameof(brokerEpoch));
        }

        if (windowsSessionId == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(windowsSessionId),
                "A nonzero Windows session id is required.");
        }

        if (derivedUserHandle.Length != 32)
        {
            throw new ArgumentException(
                "The derived registration user handle must contain exactly 32 bytes.",
                nameof(derivedUserHandle));
        }

        if (registrationNonce.Length != 32)
        {
            throw new ArgumentException(
                "The registration nonce must contain exactly 32 bytes.",
                nameof(registrationNonce));
        }

        var frozenUserHandle = derivedUserHandle.ToArray();
        var frozenNonce = registrationNonce.ToArray();
        var userHandleSha256 = Convert.ToHexString(frozenUserHandle);
        var registrationNonceBase64 = Convert.ToBase64String(frozenNonce);
        var statement = WriteCanonicalStatement(
            brokerEpoch,
            windowsSessionId,
            userHandleSha256,
            registrationNonceBase64);
        return new BrokerWebAuthnRegistrationStatementV1(
            brokerEpoch,
            windowsSessionId,
            frozenUserHandle,
            frozenNonce,
            userHandleSha256,
            registrationNonceBase64,
            statement);
    }

    private static bool IsExactBrokerEpoch(string value)
    {
        if (value.Length != 32)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] WriteCanonicalStatement(
        string brokerEpoch,
        uint windowsSessionId,
        string userHandleSha256,
        string registrationNonceBase64)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = CreateWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("schema", BrokerWebAuthnConstantsV1.RegistrationStatementSchema);
        writer.WriteString("brokerEpoch", brokerEpoch);
        writer.WriteNumber("windowsSessionId", windowsSessionId);
        writer.WriteString("userHandleSha256", userHandleSha256);
        writer.WriteString("registrationNonceBase64", registrationNonceBase64);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private static Utf8JsonWriter CreateWriter(IBufferWriter<byte> buffer) =>
        new(
            buffer,
            new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.Default,
                Indented = false,
                SkipValidation = false
            });
}

internal sealed class BrokerWebAuthnClientDataV1
{
    private readonly byte[] _challengeBytes;
    private readonly byte[] _clientDataJson;
    private readonly byte[] _clientDataHash;

    private BrokerWebAuthnClientDataV1(
        string type,
        byte[] challengeBytes,
        string challengeBase64Url,
        byte[] clientDataJson,
        byte[] clientDataHash)
    {
        Type = type;
        _challengeBytes = challengeBytes;
        ChallengeBase64Url = challengeBase64Url;
        _clientDataJson = clientDataJson;
        _clientDataHash = clientDataHash;
    }

    internal string Type { get; }

    internal string ChallengeBase64Url { get; }

    internal string Origin => BrokerWebAuthnConstantsV1.Origin;

    internal bool CrossOrigin => false;

    internal byte[] ChallengeBytes => (byte[])_challengeBytes.Clone();

    internal byte[] ClientDataJson => (byte[])_clientDataJson.Clone();

    internal byte[] ClientDataHash => (byte[])_clientDataHash.Clone();

    internal static BrokerWebAuthnClientDataV1 CreateRegistration(
        BrokerWebAuthnRegistrationStatementV1 statement)
    {
        ArgumentNullException.ThrowIfNull(statement);
        var statementBytes = statement.CanonicalStatementBytes;
        try
        {
            return Create(
                BrokerWebAuthnConstantsV1.RegistrationDomainSeparator,
                BrokerWebAuthnConstantsV1.RegistrationClientDataType,
                statementBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(statementBytes);
        }
    }

    internal static BrokerWebAuthnClientDataV1 CreateConsent(
        BrokerConsentGrantDraftV1 draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var statementBytes = draft.ConsentStatementBytes;
        try
        {
            return Create(
                BrokerWebAuthnConstantsV1.ConsentDomainSeparator,
                BrokerWebAuthnConstantsV1.AssertionClientDataType,
                statementBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(statementBytes);
        }
    }

    internal static BrokerWebAuthnClientDataV1 CreateFresh(
        BrokerFreshPresenceStatementV1 statement)
    {
        ArgumentNullException.ThrowIfNull(statement);
        var statementBytes = statement.CanonicalStatementBytes;
        try
        {
            return Create(
                BrokerWebAuthnConstantsV1.FreshPresenceDomainSeparator,
                BrokerWebAuthnConstantsV1.AssertionClientDataType,
                statementBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(statementBytes);
        }
    }

    private static BrokerWebAuthnClientDataV1 Create(
        string domainSeparator,
        string type,
        ReadOnlySpan<byte> canonicalStatementBytes)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domainSeparator);
        var challengeInput = GC.AllocateUninitializedArray<byte>(
            checked(domainBytes.Length + canonicalStatementBytes.Length));
        domainBytes.CopyTo(challengeInput, 0);
        canonicalStatementBytes.CopyTo(challengeInput.AsSpan(domainBytes.Length));
        byte[]? challengeBytes = null;
        try
        {
            challengeBytes = SHA256.HashData(challengeInput);
            var challengeBase64Url = BrokerWebAuthnBase64UrlV1.Encode(challengeBytes);
            var clientDataJson = WriteClientData(type, challengeBase64Url);
            var result = new BrokerWebAuthnClientDataV1(
                type,
                challengeBytes,
                challengeBase64Url,
                clientDataJson,
                SHA256.HashData(clientDataJson));
            challengeBytes = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(domainBytes);
            CryptographicOperations.ZeroMemory(challengeInput);
            if (challengeBytes is not null)
            {
                CryptographicOperations.ZeroMemory(challengeBytes);
            }
        }
    }

    private static byte[] WriteClientData(string type, string challengeBase64Url)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(
            buffer,
            new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.Default,
                Indented = false,
                SkipValidation = false
            });
        writer.WriteStartObject();
        writer.WriteString("type", type);
        writer.WriteString("challenge", challengeBase64Url);
        writer.WriteString("origin", BrokerWebAuthnConstantsV1.Origin);
        writer.WriteBoolean("crossOrigin", false);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }
}

internal static class BrokerWebAuthnBase64UrlV1
{
    internal static string Encode(ReadOnlySpan<byte> value)
    {
        var encoded = Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        if (encoded.Contains('+') || encoded.Contains('/') || encoded.Contains('='))
        {
            throw new InvalidOperationException("The base64url encoding is not canonical.");
        }

        return encoded;
    }
}
