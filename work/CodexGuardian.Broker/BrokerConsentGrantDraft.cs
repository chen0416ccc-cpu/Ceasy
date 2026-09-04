using CodexGuardian.Control;
using System;
using System.Security.Cryptography;

namespace CodexGuardian.Broker;

internal sealed class BrokerConsentStatementFieldsV1
{
    private BrokerConsentStatementFieldsV1(
        Guid ledgerId,
        ulong revision,
        ulong sequence,
        string previousEntrySha256,
        ulong revocationGeneration,
        Guid receiptId,
        string generationSha256,
        long issuedAtUtcTicks,
        string credentialIdBase64,
        string credentialPublicKeySha256,
        string challengeNonceBase64)
    {
        LedgerId = ledgerId;
        Revision = revision;
        Sequence = sequence;
        PreviousEntrySha256 = previousEntrySha256;
        RevocationGeneration = revocationGeneration;
        ReceiptId = receiptId;
        GenerationSha256 = generationSha256;
        IssuedAtUtcTicks = issuedAtUtcTicks;
        CredentialIdBase64 = credentialIdBase64;
        CredentialPublicKeySha256 = credentialPublicKeySha256;
        ChallengeNonceBase64 = challengeNonceBase64;
    }

    internal Guid LedgerId { get; }

    internal ulong Revision { get; }

    internal ulong Sequence { get; }

    internal string PreviousEntrySha256 { get; }

    internal ulong RevocationGeneration { get; }

    internal Guid ReceiptId { get; }

    internal string GenerationSha256 { get; }

    internal string Capability => BrokerConsentLedgerV1.CapabilityName;

    internal long IssuedAtUtcTicks { get; }

    internal string ReceiptFormat => BrokerConsentLedgerV1.ReceiptFormatName;

    internal string CredentialIdBase64 { get; }

    internal string CredentialPublicKeySha256 { get; }

    internal string ChallengeNonceBase64 { get; }

    internal static BrokerConsentStatementFieldsV1 Create(
        Guid ledgerId,
        ulong revision,
        ulong sequence,
        string previousEntrySha256,
        ulong revocationGeneration,
        Guid receiptId,
        string generationSha256,
        long issuedAtUtcTicks,
        string credentialIdBase64,
        string credentialPublicKeySha256,
        string challengeNonceBase64)
    {
        if (ledgerId == Guid.Empty || revision == 0 || revision != sequence)
        {
            throw new BrokerConsentLedgerFormatException(
                "consent-ledger-schema",
                "The consent statement ledger identity is invalid.");
        }

        if (receiptId == Guid.Empty)
        {
            throw BrokerConsentLedgerV1.InvalidReceipt(
                "A non-empty receipt id is required.");
        }

        BrokerConsentLedgerV1.RequireTimestamp(issuedAtUtcTicks, "issuedAtUtcTicks");
        return new BrokerConsentStatementFieldsV1(
            ledgerId,
            revision,
            sequence,
            BrokerConsentLedgerV1.RequireSha256(
                previousEntrySha256,
                "previousEntrySha256"),
            revocationGeneration,
            receiptId,
            BrokerConsentLedgerV1.RequireSha256(generationSha256, "generationSha256"),
            issuedAtUtcTicks,
            BrokerConsentLedgerV1.RequireCanonicalBase64(
                credentialIdBase64,
                minimumBytes: 1,
                maximumBytes: 1024,
                exactBytes: null,
                "credentialIdBase64"),
            BrokerConsentLedgerV1.RequireSha256(
                credentialPublicKeySha256,
                "credentialPublicKeySha256"),
            BrokerConsentLedgerV1.RequireCanonicalBase64(
                challengeNonceBase64,
                minimumBytes: 32,
                maximumBytes: 32,
                exactBytes: 32,
                "challengeNonceBase64"));
    }
}

internal sealed class BrokerConsentGrantDraftV1
{
    private readonly byte[] _credentialId;
    private readonly byte[] _challengeNonce;
    private readonly byte[] _consentStatementBytes;

    private BrokerConsentGrantDraftV1(
        BrokerConsentLedgerDocumentV1 currentLedger,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        BrokerConsentStatementFieldsV1 statementFields,
        byte[] credentialId,
        byte[] challengeNonce,
        byte[] consentStatementBytes,
        string consentStatementSha256)
    {
        CurrentLedger = currentLedger;
        ExpectedRevision = expectedRevision;
        Generation = generation;
        StatementFields = statementFields;
        _credentialId = credentialId;
        _challengeNonce = challengeNonce;
        _consentStatementBytes = consentStatementBytes;
        ConsentStatementSha256 = consentStatementSha256;
    }

    internal BrokerConsentLedgerDocumentV1 CurrentLedger { get; }

    internal ulong ExpectedRevision { get; }

    internal CodexPackageGenerationV1 Generation { get; }

    internal BrokerConsentStatementFieldsV1 StatementFields { get; }

    internal byte[] CredentialId => (byte[])_credentialId.Clone();

    internal byte[] ChallengeNonce => (byte[])_challengeNonce.Clone();

    internal byte[] ConsentStatementBytes => (byte[])_consentStatementBytes.Clone();

    internal string ConsentStatementSha256 { get; }

    internal BrokerConsentLedgerDocumentV1 FinalizeGrant(
        BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1 evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return BrokerConsentLedgerV1.CreateGrant(this, evidence);
    }

    internal static BrokerConsentGrantDraftV1 Create(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        Guid receiptId,
        byte[] credentialId,
        string credentialPublicKeySha256,
        byte[] challengeNonce,
        long issuedAtUtcTicks)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(challengeNonce);
        if (credentialId.Length is < 1 or > 1024)
        {
            throw BrokerConsentLedgerV1.InvalidReceipt(
                "credentialIdBase64 is outside the receipt bound.");
        }

        if (challengeNonce.Length != 32)
        {
            throw BrokerConsentLedgerV1.InvalidReceipt(
                "challengeNonceBase64 is not canonical bounded base64.");
        }

        var frozenCredentialId = (byte[])credentialId.Clone();
        var frozenChallengeNonce = (byte[])challengeNonce.Clone();
        var fields = BrokerConsentLedgerV1.CreateGrantStatementFields(
            current,
            expectedRevision,
            generation,
            receiptId,
            Convert.ToBase64String(frozenCredentialId),
            credentialPublicKeySha256,
            Convert.ToBase64String(frozenChallengeNonce),
            issuedAtUtcTicks);
        var statement = BrokerConsentLedgerV1.CreateConsentStatement(fields);
        return new BrokerConsentGrantDraftV1(
            current,
            expectedRevision,
            generation,
            fields,
            frozenCredentialId,
            frozenChallengeNonce,
            statement,
            Convert.ToHexString(SHA256.HashData(statement)));
    }
}
