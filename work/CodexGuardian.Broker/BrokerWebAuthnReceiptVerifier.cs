using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;

namespace CodexGuardian.Broker;

internal enum BrokerWebAuthnEvidencePurposeV1
{
    Consent,
    PersistedGrant,
    FreshPresence
}

internal sealed class BrokerUserPresenceVerificationException : Exception
{
    internal BrokerUserPresenceVerificationException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!IsKnownCode(code) || string.IsNullOrWhiteSpace(message) || message.Length > 256)
        {
            throw new ArgumentException("The user-presence failure is not bounded and stable.");
        }

        Code = code;
    }

    internal string Code { get; }

    private static bool IsKnownCode(string code) =>
        code is
            "user-presence-platform-unavailable" or
            "user-presence-window-invalid" or
            "user-presence-operation-busy" or
            "user-presence-cancelled" or
            "user-presence-timeout" or
            "user-presence-credential-not-found" or
            "user-presence-credential-invalid" or
            "user-presence-registration-malformed" or
            "user-presence-assertion-malformed" or
            "user-presence-rp-mismatch" or
            "user-presence-up-missing" or
            "user-presence-uv-missing" or
            "user-presence-challenge-mismatch" or
            "user-presence-signature-invalid" or
            "user-presence-proof-noncanonical" or
            "consent-ledger-head-changed" or
            "consent-package-generation-changed" or
            "consent-broker-epoch-changed" or
            "consent-windows-session-changed" or
            "consent-fresh-presence-required" or
            "user-presence-native-failed";
}

internal sealed class WebAuthnAssertionEvidenceV1 : IDisposable
{
    private const int MaximumClientDataBytes = 4096;
    private const int MaximumCredentialIdBytes = 1024;
    private const int MaximumAuthenticatorDataBytes = 4096;
    private const int MaximumNativeSignatureBytes = 128;
    private const int MaximumUserHandleBytes = 1024;
    private readonly byte[] _clientDataJson;
    private readonly byte[] _credentialId;
    private readonly byte[] _authenticatorData;
    private readonly byte[] _nativeDerSignature;
    private readonly byte[]? _userHandle;
    private int _disposed;

    private WebAuthnAssertionEvidenceV1(
        byte[] clientDataJson,
        byte[] credentialId,
        byte[] authenticatorData,
        byte[] nativeDerSignature,
        byte[]? userHandle)
    {
        _clientDataJson = clientDataJson;
        _credentialId = credentialId;
        _authenticatorData = authenticatorData;
        _nativeDerSignature = nativeDerSignature;
        _userHandle = userHandle;
    }

    internal byte[] ClientDataJson => Clone(_clientDataJson);

    internal byte[] CredentialId => Clone(_credentialId);

    internal byte[] AuthenticatorData => Clone(_authenticatorData);

    internal byte[] NativeDerSignature => Clone(_nativeDerSignature);

    internal byte[]? UserHandle => _userHandle is null ? null : Clone(_userHandle);

    internal static WebAuthnAssertionEvidenceV1 Create(
        ReadOnlySpan<byte> clientDataJson,
        ReadOnlySpan<byte> credentialId,
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> nativeDerSignature,
        byte[]? userHandle)
    {
        RequireBound(clientDataJson.Length, 1, MaximumClientDataBytes, nameof(clientDataJson));
        RequireBound(credentialId.Length, 1, MaximumCredentialIdBytes, nameof(credentialId));
        RequireBound(
            authenticatorData.Length,
            1,
            MaximumAuthenticatorDataBytes,
            nameof(authenticatorData));
        RequireBound(
            nativeDerSignature.Length,
            1,
            MaximumNativeSignatureBytes,
            nameof(nativeDerSignature));
        if (userHandle is not null)
        {
            RequireBound(userHandle.Length, 1, MaximumUserHandleBytes, nameof(userHandle));
        }

        return new WebAuthnAssertionEvidenceV1(
            clientDataJson.ToArray(),
            credentialId.ToArray(),
            authenticatorData.ToArray(),
            nativeDerSignature.ToArray(),
            userHandle is null ? null : (byte[])userHandle.Clone());
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_clientDataJson);
        CryptographicOperations.ZeroMemory(_credentialId);
        CryptographicOperations.ZeroMemory(_authenticatorData);
        CryptographicOperations.ZeroMemory(_nativeDerSignature);
        if (_userHandle is not null)
        {
            CryptographicOperations.ZeroMemory(_userHandle);
        }
    }

    private byte[] Clone(byte[] value)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return (byte[])value.Clone();
    }

    private static void RequireBound(int length, int minimum, int maximum, string parameterName)
    {
        if (length < minimum || length > maximum)
        {
            throw new ArgumentException("WebAuthn assertion evidence is outside its bound.", parameterName);
        }
    }
}

internal static class BrokerWebAuthnReceiptVerifierV1
{
    private static readonly object EvidenceFactoryToken = new();

    private static ReadOnlySpan<byte> FixedRpIdHash =>
    [
        0x98, 0xCC, 0x7D, 0x7B, 0x6E, 0xB4, 0x4A, 0xE2,
        0x01, 0xCA, 0x88, 0x95, 0xA5, 0x8B, 0x4F, 0x07,
        0x15, 0xB2, 0x55, 0xC3, 0xAF, 0x04, 0x31, 0x62,
        0xE8, 0xA7, 0x1C, 0x45, 0xFB, 0xEB, 0x34, 0x78
    ];

    internal static VerifiedUserPresenceEvidenceV1 VerifyConsentAssertion(
        BrokerConsentGrantDraftV1 draft,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        WebAuthnAssertionEvidenceV1 assertion)
    {
        ArgumentNullException.ThrowIfNull(draft);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(assertion);
        BrokerWebAuthnClientDataV1? expectedClientData = null;
        byte[]? expectedClientDataJson = null;
        byte[]? expectedClientDataHash = null;
        byte[]? assertionClientDataJson = null;
        byte[]? assertionCredentialId = null;
        byte[]? assertionAuthenticatorData = null;
        byte[]? nativeDerSignature = null;
        byte[]? credentialId = null;
        byte[]? draftCredentialId = null;
        byte[]? subjectPublicKeyInfo = null;
        byte[]? proofEnvelope = null;
        try
        {
            expectedClientData = BrokerWebAuthnClientDataV1.CreateConsent(draft);
            expectedClientDataJson = expectedClientData.ClientDataJson;
            expectedClientDataHash = expectedClientData.ClientDataHash;
            assertionClientDataJson = assertion.ClientDataJson;
            assertionCredentialId = assertion.CredentialId;
            assertionAuthenticatorData = assertion.AuthenticatorData;
            nativeDerSignature = assertion.NativeDerSignature;
            credentialId = credential.CredentialId;
            draftCredentialId = draft.CredentialId;
            subjectPublicKeyInfo = credential.SubjectPublicKeyInfo;
            var actualSubjectPublicKeyInfoSha256 =
                Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
            if (!assertionClientDataJson.AsSpan().SequenceEqual(expectedClientDataJson))
            {
                throw Fail(
                    "user-presence-challenge-mismatch",
                    "The assertion client data does not match the fixed consent challenge.");
            }

            if (!CryptographicOperations.FixedTimeEquals(assertionCredentialId, credentialId) ||
                !CryptographicOperations.FixedTimeEquals(credentialId, draftCredentialId) ||
                !string.Equals(
                    credential.SubjectPublicKeyInfoSha256,
                    actualSubjectPublicKeyInfoSha256,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    actualSubjectPublicKeyInfoSha256,
                    draft.StatementFields.CredentialPublicKeySha256,
                    StringComparison.Ordinal))
            {
                throw Fail(
                    "user-presence-credential-invalid",
                    "The assertion credential does not match the consent draft.");
            }

            ValidateAssertionAuthenticatorData(assertionAuthenticatorData);
            using var proof = CreateProof(
                subjectPublicKeyInfo,
                assertionAuthenticatorData,
                nativeDerSignature,
                "user-presence-assertion-malformed");
            VerifySignature(
                subjectPublicKeyInfo,
                assertionAuthenticatorData,
                expectedClientDataHash,
                proof.SignatureP1363);
            proofEnvelope = proof.Serialize();
            return VerifiedUserPresenceEvidenceV1.Create(
                EvidenceFactoryToken,
                BrokerWebAuthnEvidencePurposeV1.Consent,
                draft,
                proofEnvelope,
                subjectPublicKeyInfo,
                ledgerEntrySha256: null);
        }
        finally
        {
            Clear(expectedClientDataJson);
            Clear(expectedClientDataHash);
            Clear(assertionClientDataJson);
            Clear(assertionCredentialId);
            Clear(assertionAuthenticatorData);
            Clear(nativeDerSignature);
            Clear(credentialId);
            Clear(draftCredentialId);
            Clear(subjectPublicKeyInfo);
            Clear(proofEnvelope);
        }
    }

    internal static VerifiedUserPresenceEvidenceV1 VerifyFreshAssertion(
        BrokerFreshPresenceStatementV1 statement,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        WebAuthnAssertionEvidenceV1 assertion)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(assertion);
        BrokerWebAuthnClientDataV1? expectedClientData = null;
        byte[]? expectedClientDataJson = null;
        byte[]? expectedClientDataHash = null;
        byte[]? assertionClientDataJson = null;
        byte[]? assertionCredentialId = null;
        byte[]? assertionAuthenticatorData = null;
        byte[]? nativeDerSignature = null;
        byte[]? credentialId = null;
        byte[]? statementCredentialId = null;
        byte[]? subjectPublicKeyInfo = null;
        byte[]? statementSubjectPublicKeyInfo = null;
        byte[]? proofEnvelope = null;
        try
        {
            expectedClientData = BrokerWebAuthnClientDataV1.CreateFresh(statement);
            expectedClientDataJson = expectedClientData.ClientDataJson;
            expectedClientDataHash = expectedClientData.ClientDataHash;
            assertionClientDataJson = assertion.ClientDataJson;
            assertionCredentialId = assertion.CredentialId;
            assertionAuthenticatorData = assertion.AuthenticatorData;
            nativeDerSignature = assertion.NativeDerSignature;
            credentialId = credential.CredentialId;
            statementCredentialId = statement.CredentialId;
            subjectPublicKeyInfo = credential.SubjectPublicKeyInfo;
            statementSubjectPublicKeyInfo = statement.SubjectPublicKeyInfo;
            var actualSubjectPublicKeyInfoSha256 =
                Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
            if (!assertionClientDataJson.AsSpan().SequenceEqual(expectedClientDataJson))
            {
                throw Fail(
                    "user-presence-challenge-mismatch",
                    "The assertion client data does not match the fixed fresh-presence challenge.");
            }

            if (!CryptographicOperations.FixedTimeEquals(assertionCredentialId, credentialId) ||
                !CryptographicOperations.FixedTimeEquals(credentialId, statementCredentialId) ||
                !CryptographicOperations.FixedTimeEquals(
                    subjectPublicKeyInfo,
                    statementSubjectPublicKeyInfo) ||
                !string.Equals(
                    credential.SubjectPublicKeyInfoSha256,
                    actualSubjectPublicKeyInfoSha256,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    actualSubjectPublicKeyInfoSha256,
                    statement.CredentialPublicKeySha256,
                    StringComparison.Ordinal))
            {
                throw Fail(
                    "user-presence-credential-invalid",
                    "The assertion credential does not match the fresh-presence statement.");
            }

            ValidateAssertionAuthenticatorData(assertionAuthenticatorData);
            using var proof = CreateProof(
                subjectPublicKeyInfo,
                assertionAuthenticatorData,
                nativeDerSignature,
                "user-presence-assertion-malformed");
            VerifySignature(
                subjectPublicKeyInfo,
                assertionAuthenticatorData,
                expectedClientDataHash,
                proof.SignatureP1363);
            proofEnvelope = proof.Serialize();
            return VerifiedUserPresenceEvidenceV1.Create(
                EvidenceFactoryToken,
                BrokerWebAuthnEvidencePurposeV1.FreshPresence,
                statement,
                proofEnvelope,
                subjectPublicKeyInfo);
        }
        finally
        {
            Clear(expectedClientDataJson);
            Clear(expectedClientDataHash);
            Clear(assertionClientDataJson);
            Clear(assertionCredentialId);
            Clear(assertionAuthenticatorData);
            Clear(nativeDerSignature);
            Clear(credentialId);
            Clear(statementCredentialId);
            Clear(subjectPublicKeyInfo);
            Clear(statementSubjectPublicKeyInfo);
            Clear(proofEnvelope);
        }
    }

    internal static VerifiedUserPresenceEvidenceV1 VerifyPersistedGrant(
        BrokerConsentLedgerDocumentV1 grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        if (grant.ValidationState != BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification ||
            grant.Entry is not BrokerConsentGrantEntryV1 grantEntry)
        {
            throw Fail(
                "user-presence-proof-noncanonical",
                "A canonical pending grant is required for receipt verification.");
        }

        byte[]? proofBytes = null;
        byte[]? subjectPublicKeyInfo = null;
        byte[]? authenticatorData = null;
        byte[]? signatureP1363 = null;
        byte[]? clientDataJson = null;
        byte[]? clientDataHash = null;
        try
        {
            proofBytes = Convert.FromBase64String(grantEntry.Receipt.SignatureBase64);
            using var proof = ParseProof(proofBytes);
            subjectPublicKeyInfo = proof.SubjectPublicKeyInfo;
            authenticatorData = proof.AuthenticatorData;
            signatureP1363 = proof.SignatureP1363;
            var actualSpkiHash = Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
            if (!string.Equals(
                    actualSpkiHash,
                    grantEntry.Receipt.CredentialPublicKeySha256,
                    StringComparison.Ordinal))
            {
                throw Fail(
                    "user-presence-credential-invalid",
                    "The persisted proof public key does not match the receipt.");
            }

            (clientDataJson, clientDataHash) = CreatePersistedConsentClientData(grant);
            VerifySignature(
                subjectPublicKeyInfo,
                authenticatorData,
                clientDataHash,
                signatureP1363);
            return VerifiedUserPresenceEvidenceV1.Create(
                EvidenceFactoryToken,
                BrokerWebAuthnEvidencePurposeV1.PersistedGrant,
                grant,
                proofBytes,
                subjectPublicKeyInfo);
        }
        catch (FormatException exception)
        {
            throw Fail(
                "user-presence-proof-noncanonical",
                "The persisted proof encoding is not canonical.",
                exception);
        }
        finally
        {
            Clear(proofBytes);
            Clear(subjectPublicKeyInfo);
            Clear(authenticatorData);
            Clear(signatureP1363);
            Clear(clientDataJson);
            Clear(clientDataHash);
        }
    }

    private static BrokerWebAuthnAssertionProofV1 CreateProof(
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> nativeDerSignature,
        string failureCode)
    {
        try
        {
            return BrokerWebAuthnAssertionProofV1.Create(
                subjectPublicKeyInfo,
                authenticatorData,
                nativeDerSignature);
        }
        catch (ArgumentException exception)
        {
            throw Fail(failureCode, "The WebAuthn assertion evidence is malformed.", exception);
        }
    }

    private static BrokerWebAuthnAssertionProofV1 ParseProof(byte[] proofBytes)
    {
        try
        {
            return BrokerWebAuthnAssertionProofV1.Parse(proofBytes);
        }
        catch (ArgumentException exception)
        {
            throw Fail(
                "user-presence-proof-noncanonical",
                "The persisted WebAuthn proof is not canonical.",
                exception);
        }
    }

    private static void ValidateAssertionAuthenticatorData(ReadOnlySpan<byte> authenticatorData)
    {
        if (authenticatorData.Length != BrokerWebAuthnAssertionAuthenticatorDataV1.ExactBytes)
        {
            throw Fail(
                "user-presence-assertion-malformed",
                "The assertion authenticator data has the wrong length.");
        }

        if (!CryptographicOperations.FixedTimeEquals(authenticatorData[..32], FixedRpIdHash))
        {
            throw Fail(
                "user-presence-rp-mismatch",
                "The assertion RP ID hash does not match the fixed RP.");
        }

        var flags = authenticatorData[32];
        if ((flags & 0x01) == 0)
        {
            throw Fail("user-presence-up-missing", "The assertion is missing user presence.");
        }

        if ((flags & 0x04) == 0)
        {
            throw Fail("user-presence-uv-missing", "The assertion is missing user verification.");
        }

        if ((flags & 0xE2) != 0)
        {
            throw Fail(
                "user-presence-assertion-malformed",
                "The assertion authenticator flags are unsupported.");
        }
    }

    private static void VerifySignature(
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> clientDataHash,
        ReadOnlySpan<byte> signatureP1363)
    {
        var signedData = new byte[checked(authenticatorData.Length + clientDataHash.Length)];
        authenticatorData.CopyTo(signedData);
        clientDataHash.CopyTo(signedData.AsSpan(authenticatorData.Length));
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length ||
                !key.VerifyData(
                    signedData,
                    signatureP1363,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw Fail(
                    "user-presence-signature-invalid",
                    "The WebAuthn assertion signature is invalid.");
            }
        }
        catch (BrokerUserPresenceVerificationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is CryptographicException or PlatformNotSupportedException)
        {
            throw Fail(
                "user-presence-credential-invalid",
                "The WebAuthn assertion public key is invalid.",
                exception);
        }
        finally
        {
            Clear(signedData);
        }
    }

    private static (byte[] ClientDataJson, byte[] ClientDataHash)
        CreatePersistedConsentClientData(BrokerConsentLedgerDocumentV1 grant)
    {
        var statement = BrokerConsentLedgerV1.CreateConsentStatement(grant);
        var domain = Encoding.ASCII.GetBytes(BrokerWebAuthnConstantsV1.ConsentDomainSeparator);
        var challengeInput = new byte[checked(domain.Length + statement.Length)];
        domain.CopyTo(challengeInput, 0);
        statement.CopyTo(challengeInput, domain.Length);
        var challenge = SHA256.HashData(challengeInput);
        var challengeBase64Url = BrokerWebAuthnBase64UrlV1.Encode(challenge);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(
                   buffer,
                   new JsonWriterOptions
                   {
                       Encoder = JavaScriptEncoder.Default,
                       Indented = false,
                       SkipValidation = false
                   }))
        {
            writer.WriteStartObject();
            writer.WriteString("type", BrokerWebAuthnConstantsV1.AssertionClientDataType);
            writer.WriteString("challenge", challengeBase64Url);
            writer.WriteString("origin", BrokerWebAuthnConstantsV1.Origin);
            writer.WriteBoolean("crossOrigin", false);
            writer.WriteEndObject();
            writer.Flush();
        }

        var clientDataJson = buffer.WrittenSpan.ToArray();
        Clear(statement);
        Clear(domain);
        Clear(challengeInput);
        Clear(challenge);
        return (clientDataJson, SHA256.HashData(clientDataJson));
    }

    private static BrokerUserPresenceVerificationException Fail(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private static void Clear(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    internal sealed class VerifiedUserPresenceEvidenceV1 : IDisposable
    {
        private readonly BrokerWebAuthnEvidencePurposeV1 _purpose;
        private readonly string _statementSha256;
        private readonly Guid _ledgerId;
        private readonly ulong _ledgerRevision;
        private readonly ulong _sequence;
        private readonly string _previousEntrySha256;
        private readonly ulong _revocationGeneration;
        private readonly Guid _receiptId;
        private readonly string _subjectPublicKeyInfoSha256;
        private readonly long _issuedAtUtcTicks;
        private readonly string _generationSha256;
        private readonly string _capability;
        private readonly string? _brokerEpoch;
        private readonly uint? _windowsSessionId;
        private readonly string? _ledgerEntrySha256;
        private readonly byte[] _credentialId;
        private readonly byte[] _subjectPublicKeyInfo;
        private readonly byte[] _proofEnvelope;
        private readonly byte[] _challengeNonce;
        private int _consumed;

        private VerifiedUserPresenceEvidenceV1(
            BrokerWebAuthnEvidencePurposeV1 purpose,
            string statementSha256,
            Guid ledgerId,
            ulong ledgerRevision,
            ulong sequence,
            string previousEntrySha256,
            ulong revocationGeneration,
            Guid receiptId,
            byte[] credentialId,
            byte[] subjectPublicKeyInfo,
            string subjectPublicKeyInfoSha256,
            byte[] proofEnvelope,
            byte[] challengeNonce,
            long issuedAtUtcTicks,
            string generationSha256,
            string capability,
            string? brokerEpoch,
            uint? windowsSessionId,
            string? ledgerEntrySha256)
        {
            _purpose = purpose;
            _statementSha256 = statementSha256;
            _ledgerId = ledgerId;
            _ledgerRevision = ledgerRevision;
            _sequence = sequence;
            _previousEntrySha256 = previousEntrySha256;
            _revocationGeneration = revocationGeneration;
            _receiptId = receiptId;
            _credentialId = credentialId;
            _subjectPublicKeyInfo = subjectPublicKeyInfo;
            _subjectPublicKeyInfoSha256 = subjectPublicKeyInfoSha256;
            _proofEnvelope = proofEnvelope;
            _challengeNonce = challengeNonce;
            _issuedAtUtcTicks = issuedAtUtcTicks;
            _generationSha256 = generationSha256;
            _capability = capability;
            _brokerEpoch = brokerEpoch;
            _windowsSessionId = windowsSessionId;
            _ledgerEntrySha256 = ledgerEntrySha256;
        }

        internal BrokerWebAuthnEvidencePurposeV1 Purpose => Read(_purpose);

        internal string StatementSha256 => Read(_statementSha256);

        internal Guid LedgerId => Read(_ledgerId);

        internal ulong LedgerRevision => Read(_ledgerRevision);

        internal ulong Sequence => Read(_sequence);

        internal string PreviousEntrySha256 => Read(_previousEntrySha256);

        internal ulong RevocationGeneration => Read(_revocationGeneration);

        internal Guid ReceiptId => Read(_receiptId);

        internal string SubjectPublicKeyInfoSha256 => Read(_subjectPublicKeyInfoSha256);

        internal long IssuedAtUtcTicks => Read(_issuedAtUtcTicks);

        internal string GenerationSha256 => Read(_generationSha256);

        internal string Capability => Read(_capability);

        internal string? BrokerEpoch => Read(_brokerEpoch);

        internal uint? WindowsSessionId => Read(_windowsSessionId);

        internal string? LedgerEntrySha256 => Read(_ledgerEntrySha256);

        internal byte[] CredentialId => Clone(_credentialId);

        internal byte[] SubjectPublicKeyInfo => Clone(_subjectPublicKeyInfo);

        internal byte[] ProofEnvelope => Clone(_proofEnvelope);

        internal byte[] ChallengeNonce => Clone(_challengeNonce);

        internal static VerifiedUserPresenceEvidenceV1 Create(
            object factoryToken,
            BrokerWebAuthnEvidencePurposeV1 purpose,
            BrokerConsentGrantDraftV1 draft,
            byte[] proofEnvelope,
            byte[] subjectPublicKeyInfo,
            string? ledgerEntrySha256)
        {
            RequireFactoryToken(factoryToken);
            var fields = draft.StatementFields;
            return new VerifiedUserPresenceEvidenceV1(
                purpose,
                draft.ConsentStatementSha256,
                fields.LedgerId,
                fields.Revision,
                fields.Sequence,
                fields.PreviousEntrySha256,
                fields.RevocationGeneration,
                fields.ReceiptId,
                draft.CredentialId,
                (byte[])subjectPublicKeyInfo.Clone(),
                fields.CredentialPublicKeySha256,
                (byte[])proofEnvelope.Clone(),
                draft.ChallengeNonce,
                fields.IssuedAtUtcTicks,
                fields.GenerationSha256,
                fields.Capability,
                brokerEpoch: null,
                windowsSessionId: null,
                ledgerEntrySha256);
        }

        internal static VerifiedUserPresenceEvidenceV1 Create(
            object factoryToken,
            BrokerWebAuthnEvidencePurposeV1 purpose,
            BrokerConsentLedgerDocumentV1 grant,
            byte[] proofEnvelope,
            byte[] subjectPublicKeyInfo)
        {
            RequireFactoryToken(factoryToken);
            var entry = (BrokerConsentGrantEntryV1)grant.Entry;
            var receipt = entry.Receipt;
            return new VerifiedUserPresenceEvidenceV1(
                purpose,
                BrokerConsentLedgerV1.ComputeConsentStatementSha256(grant),
                grant.LedgerId,
                grant.Revision,
                entry.Sequence,
                entry.PreviousEntrySha256,
                entry.RevocationGeneration,
                entry.ReceiptId,
                Convert.FromBase64String(receipt.CredentialIdBase64),
                (byte[])subjectPublicKeyInfo.Clone(),
                receipt.CredentialPublicKeySha256,
                (byte[])proofEnvelope.Clone(),
                Convert.FromBase64String(receipt.ChallengeNonceBase64),
                entry.IssuedAtUtcTicks,
                entry.GenerationSha256,
                BrokerConsentLedgerV1.CapabilityName,
                brokerEpoch: null,
                windowsSessionId: null,
                grant.EntrySha256);
        }

        internal static VerifiedUserPresenceEvidenceV1 Create(
            object factoryToken,
            BrokerWebAuthnEvidencePurposeV1 purpose,
            BrokerFreshPresenceStatementV1 statement,
            byte[] proofEnvelope,
            byte[] subjectPublicKeyInfo)
        {
            RequireFactoryToken(factoryToken);
            return new VerifiedUserPresenceEvidenceV1(
                purpose,
                statement.StatementSha256,
                statement.LedgerId,
                statement.LedgerRevision,
                statement.LedgerRevision,
                statement.LedgerEntrySha256,
                revocationGeneration: 0,
                statement.ReceiptId,
                statement.CredentialId,
                (byte[])subjectPublicKeyInfo.Clone(),
                statement.CredentialPublicKeySha256,
                (byte[])proofEnvelope.Clone(),
                statement.FreshNonce,
                issuedAtUtcTicks: 0,
                statement.GenerationSha256,
                statement.Capability,
                statement.BrokerEpoch,
                statement.WindowsSessionId,
                statement.LedgerEntrySha256);
        }

        private static void RequireFactoryToken(object factoryToken)
        {
            if (!ReferenceEquals(factoryToken, EvidenceFactoryToken))
            {
                throw new InvalidOperationException(
                    "Verified user-presence evidence can only be created by the verifier.");
            }
        }

        internal void ConsumePersistedGrant(BrokerConsentLedgerDocumentV1 grant)
        {
            ArgumentNullException.ThrowIfNull(grant);
            if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            {
                throw Fail(
                    "consent-fresh-presence-required",
                    "Verified user-presence evidence was already consumed.");
            }

            byte[]? consentStatement = null;
            byte[]? grantCredentialId = null;
            byte[]? grantChallengeNonce = null;
            byte[]? grantProofEnvelope = null;
            try
            {
                if (_purpose != BrokerWebAuthnEvidencePurposeV1.PersistedGrant)
                {
                    throw Fail(
                        "consent-fresh-presence-required",
                        "Only verified persisted receipt evidence can create a fresh statement.");
                }

                if (grant.ValidationState !=
                        BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification ||
                    grant.Entry is not BrokerConsentGrantEntryV1 entry)
                {
                    throw Fail(
                        "consent-ledger-head-changed",
                        "The persisted evidence no longer has a pending grant.");
                }

                var receipt = entry.Receipt;
                consentStatement = BrokerConsentLedgerV1.CreateConsentStatement(grant);
                grantCredentialId = Convert.FromBase64String(receipt.CredentialIdBase64);
                grantChallengeNonce = Convert.FromBase64String(receipt.ChallengeNonceBase64);
                grantProofEnvelope = Convert.FromBase64String(receipt.SignatureBase64);
                var statementSha256 =
                    Convert.ToHexString(SHA256.HashData(consentStatement));
                var actualSubjectPublicKeyInfoSha256 =
                    Convert.ToHexString(SHA256.HashData(_subjectPublicKeyInfo));
                if (!string.Equals(_statementSha256, statementSha256, StringComparison.Ordinal) ||
                    _ledgerId != grant.LedgerId ||
                    _ledgerRevision != grant.Revision ||
                    _sequence != entry.Sequence ||
                    !string.Equals(
                        _previousEntrySha256,
                        entry.PreviousEntrySha256,
                        StringComparison.Ordinal) ||
                    _revocationGeneration != entry.RevocationGeneration ||
                    _receiptId != entry.ReceiptId ||
                    !string.Equals(
                        _generationSha256,
                        entry.GenerationSha256,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        _capability,
                        BrokerConsentLedgerV1.CapabilityName,
                        StringComparison.Ordinal) ||
                    _issuedAtUtcTicks != entry.IssuedAtUtcTicks ||
                    !string.Equals(
                        _ledgerEntrySha256,
                        grant.EntrySha256,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        _subjectPublicKeyInfoSha256,
                        receipt.CredentialPublicKeySha256,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        actualSubjectPublicKeyInfoSha256,
                        receipt.CredentialPublicKeySha256,
                        StringComparison.Ordinal) ||
                    !CryptographicOperations.FixedTimeEquals(_credentialId, grantCredentialId) ||
                    !CryptographicOperations.FixedTimeEquals(_challengeNonce, grantChallengeNonce) ||
                    !CryptographicOperations.FixedTimeEquals(_proofEnvelope, grantProofEnvelope) ||
                    _proofEnvelope.Length != BrokerWebAuthnAssertionProofV1.EnvelopeBytes)
                {
                    throw Fail(
                        "consent-ledger-head-changed",
                        "Verified persisted evidence does not match the exact pending grant.");
                }
            }
            catch (FormatException exception)
            {
                throw Fail(
                    "consent-ledger-head-changed",
                    "The pending grant receipt is no longer canonical.",
                    exception);
            }
            finally
            {
                Clear(consentStatement);
                Clear(grantCredentialId);
                Clear(grantChallengeNonce);
                Clear(grantProofEnvelope);
                ClearOwnedArrays();
            }
        }

        internal void ConsumeFreshPresence(BrokerFreshPresenceStatementV1 statement)
        {
            ArgumentNullException.ThrowIfNull(statement);
            if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            {
                throw Fail(
                    "consent-fresh-presence-required",
                    "Verified user-presence evidence was already consumed.");
            }

            byte[]? statementCredentialId = null;
            byte[]? statementSubjectPublicKeyInfo = null;
            byte[]? statementFreshNonce = null;
            try
            {
                if (_purpose != BrokerWebAuthnEvidencePurposeV1.FreshPresence)
                {
                    throw Fail(
                        "consent-fresh-presence-required",
                        "Historical receipt evidence cannot create a volatile session.");
                }

                statementCredentialId = statement.CredentialId;
                statementSubjectPublicKeyInfo = statement.SubjectPublicKeyInfo;
                statementFreshNonce = statement.FreshNonce;
                var actualSubjectPublicKeyInfoSha256 =
                    Convert.ToHexString(SHA256.HashData(_subjectPublicKeyInfo));
                if (!string.Equals(
                        _statementSha256,
                        statement.StatementSha256,
                        StringComparison.Ordinal) ||
                    _ledgerId != statement.LedgerId ||
                    _ledgerRevision != statement.LedgerRevision ||
                    _receiptId != statement.ReceiptId ||
                    !string.Equals(
                        _generationSha256,
                        statement.GenerationSha256,
                        StringComparison.Ordinal) ||
                    !string.Equals(_capability, statement.Capability, StringComparison.Ordinal) ||
                    !string.Equals(_brokerEpoch, statement.BrokerEpoch, StringComparison.Ordinal) ||
                    _windowsSessionId != statement.WindowsSessionId ||
                    !string.Equals(
                        _ledgerEntrySha256,
                        statement.LedgerEntrySha256,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        _subjectPublicKeyInfoSha256,
                        statement.CredentialPublicKeySha256,
                        StringComparison.Ordinal) ||
                    !string.Equals(
                        actualSubjectPublicKeyInfoSha256,
                        statement.CredentialPublicKeySha256,
                        StringComparison.Ordinal) ||
                    !CryptographicOperations.FixedTimeEquals(
                        _credentialId,
                        statementCredentialId) ||
                    !CryptographicOperations.FixedTimeEquals(
                        _subjectPublicKeyInfo,
                        statementSubjectPublicKeyInfo) ||
                    !CryptographicOperations.FixedTimeEquals(
                        _challengeNonce,
                        statementFreshNonce) ||
                    _proofEnvelope.Length != BrokerWebAuthnAssertionProofV1.EnvelopeBytes)
                {
                    throw Fail(
                        "consent-ledger-head-changed",
                        "Verified fresh-presence evidence does not match its statement.");
                }
            }
            finally
            {
                Clear(statementCredentialId);
                Clear(statementSubjectPublicKeyInfo);
                Clear(statementFreshNonce);
                ClearOwnedArrays();
            }
        }

        internal byte[] ConsumeConsentProof(BrokerConsentGrantDraftV1 draft)
        {
            ArgumentNullException.ThrowIfNull(draft);
            if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
            {
                throw Fail(
                    "consent-fresh-presence-required",
                    "Verified user-presence evidence was already consumed.");
            }

            byte[]? draftCredentialId = null;
            byte[]? draftChallengeNonce = null;
            try
            {
                if (_purpose != BrokerWebAuthnEvidencePurposeV1.Consent)
                {
                    throw Fail(
                        "consent-fresh-presence-required",
                        "Historical user-presence evidence cannot finalize a new consent grant.");
                }

                var fields = draft.StatementFields;
                draftCredentialId = draft.CredentialId;
                draftChallengeNonce = draft.ChallengeNonce;
                if (!string.Equals(_statementSha256, draft.ConsentStatementSha256, StringComparison.Ordinal) ||
                    _ledgerId != fields.LedgerId ||
                    _ledgerRevision != fields.Revision ||
                    _sequence != fields.Sequence ||
                    !string.Equals(_previousEntrySha256, fields.PreviousEntrySha256, StringComparison.Ordinal) ||
                    _revocationGeneration != fields.RevocationGeneration ||
                    _receiptId != fields.ReceiptId ||
                    !string.Equals(_generationSha256, fields.GenerationSha256, StringComparison.Ordinal) ||
                    !string.Equals(_capability, fields.Capability, StringComparison.Ordinal) ||
                    _issuedAtUtcTicks != fields.IssuedAtUtcTicks ||
                    !string.Equals(
                        _subjectPublicKeyInfoSha256,
                        fields.CredentialPublicKeySha256,
                        StringComparison.Ordinal) ||
                    !CryptographicOperations.FixedTimeEquals(_credentialId, draftCredentialId) ||
                    !CryptographicOperations.FixedTimeEquals(_challengeNonce, draftChallengeNonce) ||
                    _proofEnvelope.Length != BrokerWebAuthnAssertionProofV1.EnvelopeBytes)
                {
                    throw Fail(
                        "consent-ledger-head-changed",
                        "Verified user-presence evidence does not match the frozen consent draft.");
                }

                return (byte[])_proofEnvelope.Clone();
            }
            finally
            {
                Clear(draftCredentialId);
                Clear(draftChallengeNonce);
                ClearOwnedArrays();
            }
        }

        public void Dispose()
        {
            _ = Interlocked.Exchange(ref _consumed, 1);
            ClearOwnedArrays();
        }

        private T Read<T>(T value)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _consumed) != 0, this);
            return value;
        }

        private byte[] Clone(byte[] value)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _consumed) != 0, this);
            return (byte[])value.Clone();
        }

        private void ClearOwnedArrays()
        {
            Clear(_credentialId);
            Clear(_subjectPublicKeyInfo);
            Clear(_proofEnvelope);
            Clear(_challengeNonce);
        }
    }
}
