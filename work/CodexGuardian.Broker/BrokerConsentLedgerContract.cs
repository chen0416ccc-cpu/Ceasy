using CodexGuardian.Control;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace CodexGuardian.Broker;

internal enum BrokerConsentLedgerValidationStateV1
{
    StructurallyValid,
    ReceiptPendingVerification
}

internal enum BrokerConsentRevokeReasonV1
{
    UserRequested,
    PackageChanged,
    CredentialRotated,
    PolicyChanged
}

internal sealed class BrokerConsentLedgerFormatException : Exception
{
    internal BrokerConsentLedgerFormatException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal sealed class BrokerUserPresenceReceiptV1
{
    private BrokerUserPresenceReceiptV1(
        Guid receiptId,
        string credentialIdBase64,
        string credentialPublicKeySha256,
        string challengeNonceBase64,
        string signatureBase64)
    {
        ReceiptId = receiptId;
        CredentialIdBase64 = credentialIdBase64;
        CredentialPublicKeySha256 = credentialPublicKeySha256;
        ChallengeNonceBase64 = challengeNonceBase64;
        SignatureBase64 = signatureBase64;
    }

    internal Guid ReceiptId { get; }

    internal string ReceiptFormat => BrokerConsentLedgerV1.ReceiptFormatName;

    internal string CredentialIdBase64 { get; }

    internal string CredentialPublicKeySha256 { get; }

    internal string ChallengeNonceBase64 { get; }

    internal string SignatureBase64 { get; }

    internal static BrokerUserPresenceReceiptV1 Create(
        Guid receiptId,
        string credentialIdBase64,
        string credentialPublicKeySha256,
        string challengeNonceBase64,
        string signatureBase64)
    {
        if (receiptId == Guid.Empty)
        {
            throw BrokerConsentLedgerV1.InvalidReceipt("A non-empty receipt id is required.");
        }

        return new BrokerUserPresenceReceiptV1(
            receiptId,
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
                "challengeNonceBase64"),
            BrokerConsentLedgerV1.RequireCanonicalBase64(
                signatureBase64,
                minimumBytes: 1,
                maximumBytes: 4096,
                exactBytes: null,
                "signatureBase64"));
    }

    internal bool ContentEquals(BrokerUserPresenceReceiptV1 other) =>
        other is not null &&
        ReceiptId == other.ReceiptId &&
        string.Equals(CredentialIdBase64, other.CredentialIdBase64, StringComparison.Ordinal) &&
        string.Equals(
            CredentialPublicKeySha256,
            other.CredentialPublicKeySha256,
            StringComparison.Ordinal) &&
        string.Equals(ChallengeNonceBase64, other.ChallengeNonceBase64, StringComparison.Ordinal) &&
        string.Equals(SignatureBase64, other.SignatureBase64, StringComparison.Ordinal);
}

internal abstract class BrokerConsentLedgerEntryV1
{
    protected BrokerConsentLedgerEntryV1(
        ulong sequence,
        string previousEntrySha256,
        ulong revocationGeneration)
    {
        Sequence = sequence;
        PreviousEntrySha256 = previousEntrySha256;
        RevocationGeneration = revocationGeneration;
    }

    internal abstract string Kind { get; }

    internal ulong Sequence { get; }

    internal string PreviousEntrySha256 { get; }

    internal ulong RevocationGeneration { get; }
}

internal sealed class BrokerConsentGenesisEntryV1 : BrokerConsentLedgerEntryV1
{
    internal BrokerConsentGenesisEntryV1()
        : base(0, BrokerConsentLedgerV1.ZeroSha256, 0)
    {
    }

    internal override string Kind => "genesis";
}

internal sealed class BrokerConsentGrantEntryV1 : BrokerConsentLedgerEntryV1
{
    internal BrokerConsentGrantEntryV1(
        ulong sequence,
        string previousEntrySha256,
        ulong revocationGeneration,
        string generationSha256,
        long issuedAtUtcTicks,
        BrokerUserPresenceReceiptV1 receipt)
        : base(sequence, previousEntrySha256, revocationGeneration)
    {
        GenerationSha256 = generationSha256;
        IssuedAtUtcTicks = issuedAtUtcTicks;
        Receipt = receipt;
    }

    internal override string Kind => "grant";

    internal Guid ReceiptId => Receipt.ReceiptId;

    internal string GenerationSha256 { get; }

    internal string Capability => BrokerConsentLedgerV1.CapabilityName;

    internal long IssuedAtUtcTicks { get; }

    internal BrokerUserPresenceReceiptV1 Receipt { get; }
}

internal sealed class BrokerConsentRevokeEntryV1 : BrokerConsentLedgerEntryV1
{
    internal BrokerConsentRevokeEntryV1(
        ulong sequence,
        string previousEntrySha256,
        ulong revocationGeneration,
        Guid revokedReceiptId,
        string revokedGenerationSha256,
        BrokerConsentRevokeReasonV1 reason,
        long revokedAtUtcTicks)
        : base(sequence, previousEntrySha256, revocationGeneration)
    {
        RevokedReceiptId = revokedReceiptId;
        RevokedGenerationSha256 = revokedGenerationSha256;
        Reason = reason;
        RevokedAtUtcTicks = revokedAtUtcTicks;
    }

    internal override string Kind => "revoke";

    internal Guid RevokedReceiptId { get; }

    internal string RevokedGenerationSha256 { get; }

    internal string Capability => BrokerConsentLedgerV1.CapabilityName;

    internal BrokerConsentRevokeReasonV1 Reason { get; }

    internal long RevokedAtUtcTicks { get; }
}

internal sealed class BrokerConsentLedgerDocumentV1
{
    internal BrokerConsentLedgerDocumentV1(
        Guid ledgerId,
        ulong revision,
        BrokerConsentLedgerEntryV1 entry,
        string entrySha256,
        BrokerConsentLedgerValidationStateV1 validationState)
    {
        LedgerId = ledgerId;
        Revision = revision;
        Entry = entry;
        EntrySha256 = entrySha256;
        ValidationState = validationState;
    }

    internal string Schema => BrokerConsentLedgerV1.SchemaName;

    internal Guid LedgerId { get; }

    internal ulong Revision { get; }

    internal BrokerConsentLedgerEntryV1 Entry { get; }

    internal string EntrySha256 { get; }

    internal BrokerConsentLedgerValidationStateV1 ValidationState { get; }
}

internal static class BrokerConsentLedgerTransition
{
    internal static BrokerConsentLedgerDocumentV1 CreateGenesis(Guid ledgerId) =>
        BrokerConsentLedgerV1.CreateGenesis(ledgerId);

    internal static BrokerConsentLedgerDocumentV1 CreateRevoke(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        BrokerConsentRevokeReasonV1 reason,
        long revokedAtUtcTicks) =>
        BrokerConsentLedgerV1.CreateRevoke(
            current,
            expectedRevision,
            reason,
            revokedAtUtcTicks);
}

internal static class BrokerConsentLedgerV1
{
    internal const string SchemaName = "codex-broker-consent-ledger-v1";
    internal const string StatementSchemaName = "codex-broker-consent-statement-v1";
    internal const string CapabilityName = "managed-readonly-cdp-v1";
    internal const string ReceiptFormatName = "windows-user-presence-v1";
    internal const int MaximumDocumentBytes = 64 * 1024;
    internal static readonly string ZeroSha256 = new('0', 64);

    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 6
    };

    internal static BrokerConsentLedgerDocumentV1 Parse(byte[] utf8Json)
    {
        ArgumentNullException.ThrowIfNull(utf8Json);
        if (utf8Json.Length == 0 || utf8Json.Length > MaximumDocumentBytes)
        {
            throw InvalidSize("The consent ledger document size is invalid.");
        }

        if (utf8Json.Length >= 3 &&
            utf8Json[0] == 0xEF &&
            utf8Json[1] == 0xBB &&
            utf8Json[2] == 0xBF)
        {
            throw NonCanonical("A UTF-8 BOM is not canonical ledger JSON.");
        }

        try
        {
            using var document = JsonDocument.Parse(utf8Json, JsonOptions);
            var root = document.RootElement;
            RequireExactProperties(root, "schema", "ledgerId", "revision", "entry", "entrySha256");
            if (!string.Equals(
                    ReadString(root, "schema"),
                    SchemaName,
                    StringComparison.Ordinal))
            {
                throw InvalidSchema("The consent ledger schema is unsupported.");
            }

            var ledgerId = ReadCanonicalGuid(root, "ledgerId");
            var revision = ReadUInt64(root, "revision");
            var entryElement = ReadObject(root, "entry");
            var entry = ParseEntry(entryElement);
            var entrySha256 = RequireSha256(
                ReadString(root, "entrySha256"),
                "entrySha256");
            var parsed = new BrokerConsentLedgerDocumentV1(
                ledgerId,
                revision,
                entry,
                entrySha256,
                entry is BrokerConsentGrantEntryV1
                    ? BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification
                    : BrokerConsentLedgerValidationStateV1.StructurallyValid);
            ValidateDocument(parsed);
            var canonical = Serialize(parsed);
            if (!utf8Json.AsSpan().SequenceEqual(canonical))
            {
                throw NonCanonical("The consent ledger JSON is not canonical.");
            }

            return parsed;
        }
        catch (BrokerConsentLedgerFormatException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new BrokerConsentLedgerFormatException(
                "consent-ledger-invalid-json",
                "The consent ledger JSON is invalid: " + exception.Message);
        }
    }

    internal static byte[] Serialize(BrokerConsentLedgerDocumentV1 document)
    {
        ArgumentNullException.ThrowIfNull(document);
        ValidateDocument(document);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = CreateWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("schema", SchemaName);
        writer.WriteString("ledgerId", CanonicalGuid(document.LedgerId));
        writer.WriteNumber("revision", document.Revision);
        writer.WritePropertyName("entry");
        WriteEntry(writer, document.Entry);
        writer.WriteString("entrySha256", document.EntrySha256);
        writer.WriteEndObject();
        writer.Flush();
        if (buffer.WrittenCount > MaximumDocumentBytes)
        {
            throw InvalidSize("The canonical consent ledger document is too large.");
        }

        return buffer.WrittenSpan.ToArray();
    }

    internal static byte[] CreateConsentStatement(BrokerConsentLedgerDocumentV1 document)
    {
        ArgumentNullException.ThrowIfNull(document);
        ValidateDocument(document);
        if (document.Entry is not BrokerConsentGrantEntryV1 grant)
        {
            throw InvalidTransition("Only a grant has a user-presence consent statement.");
        }

        return CreateConsentStatement(BrokerConsentStatementFieldsV1.Create(
            document.LedgerId,
            document.Revision,
            grant.Sequence,
            grant.PreviousEntrySha256,
            grant.RevocationGeneration,
            grant.ReceiptId,
            grant.GenerationSha256,
            grant.IssuedAtUtcTicks,
            grant.Receipt.CredentialIdBase64,
            grant.Receipt.CredentialPublicKeySha256,
            grant.Receipt.ChallengeNonceBase64));
    }

    internal static byte[] CreateConsentStatement(BrokerConsentStatementFieldsV1 fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = CreateWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("schema", StatementSchemaName);
        writer.WriteString("ledgerId", CanonicalGuid(fields.LedgerId));
        writer.WriteNumber("revision", fields.Revision);
        writer.WriteNumber("sequence", fields.Sequence);
        writer.WriteString("previousEntrySha256", fields.PreviousEntrySha256);
        writer.WriteNumber("revocationGeneration", fields.RevocationGeneration);
        writer.WriteString("receiptId", CanonicalGuid(fields.ReceiptId));
        writer.WriteString("generationSha256", fields.GenerationSha256);
        writer.WriteString("capability", CapabilityName);
        writer.WriteNumber("issuedAtUtcTicks", fields.IssuedAtUtcTicks);
        writer.WriteString("receiptFormat", ReceiptFormatName);
        writer.WriteString("credentialIdBase64", fields.CredentialIdBase64);
        writer.WriteString(
            "credentialPublicKeySha256",
            fields.CredentialPublicKeySha256);
        writer.WriteString("challengeNonceBase64", fields.ChallengeNonceBase64);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    internal static string ComputeConsentStatementSha256(
        BrokerConsentLedgerDocumentV1 document) =>
        Convert.ToHexString(SHA256.HashData(CreateConsentStatement(document)));

    internal static void ValidateSuccessor(
        BrokerConsentLedgerDocumentV1 previous,
        BrokerConsentLedgerDocumentV1 current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        ValidateDocument(previous);
        ValidateDocument(current);
        if (previous.Revision == ulong.MaxValue ||
            current.LedgerId != previous.LedgerId ||
            current.Revision != previous.Revision + 1 ||
            current.Entry.Sequence != current.Revision ||
            !FixedHashEquals(current.Entry.PreviousEntrySha256, previous.EntrySha256) ||
            current.Entry is BrokerConsentGenesisEntryV1)
        {
            throw InvalidChain("The consent ledger successor link is invalid.");
        }

        switch (previous.Entry)
        {
            case BrokerConsentGenesisEntryV1:
                if (current.Entry is not BrokerConsentGrantEntryV1 ||
                    current.Entry.RevocationGeneration != 0)
                {
                    throw InvalidChain("Genesis must be followed by the first grant.");
                }

                break;
            case BrokerConsentGrantEntryV1 previousGrant:
                if (previousGrant.RevocationGeneration == ulong.MaxValue ||
                    current.Entry.RevocationGeneration != previousGrant.RevocationGeneration + 1)
                {
                    throw InvalidChain("A grant replacement must advance revocation generation.");
                }

                if (current.Entry is BrokerConsentRevokeEntryV1 revoke &&
                    (revoke.RevokedReceiptId != previousGrant.ReceiptId ||
                     !FixedHashEquals(
                         revoke.RevokedGenerationSha256,
                         previousGrant.GenerationSha256)))
                {
                    throw InvalidChain("The revoke entry does not identify the previous grant.");
                }

                if (current.Entry is not BrokerConsentGrantEntryV1 and
                    not BrokerConsentRevokeEntryV1)
                {
                    throw InvalidChain("A grant has an unsupported successor kind.");
                }

                break;
            case BrokerConsentRevokeEntryV1 previousRevoke:
                if (current.Entry is not BrokerConsentGrantEntryV1 ||
                    current.Entry.RevocationGeneration != previousRevoke.RevocationGeneration)
                {
                    throw InvalidChain("A revoked ledger can only receive a new grant.");
                }

                break;
            default:
                throw InvalidChain("The previous ledger entry kind is unsupported.");
        }
    }

    internal static BrokerConsentLedgerDocumentV1 CreateGenesis(Guid ledgerId)
    {
        if (ledgerId == Guid.Empty)
        {
            throw InvalidTransition("A non-empty ledger id is required.");
        }

        return CreateDocument(ledgerId, 0, new BrokerConsentGenesisEntryV1());
    }

    internal static BrokerConsentLedgerDocumentV1 CreateGrant(
        BrokerConsentGrantDraftV1 draft,
        BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1 evidence)
    {
        ArgumentNullException.ThrowIfNull(draft);
        ArgumentNullException.ThrowIfNull(evidence);
        var current = draft.CurrentLedger;
        var fields = draft.StatementFields;
        ValidateDocument(current);
        RequireExpectedRevision(current, draft.ExpectedRevision);
        var generationSha256 = RevalidateGeneration(draft.Generation);
        var (revision, revocationGeneration) = CreateNextGrantPosition(current);
        if (fields.LedgerId != current.LedgerId ||
            fields.Revision != revision ||
            fields.Sequence != revision ||
            !FixedHashEquals(fields.PreviousEntrySha256, current.EntrySha256) ||
            fields.RevocationGeneration != revocationGeneration ||
            !FixedHashEquals(fields.GenerationSha256, generationSha256))
        {
            throw InvalidTransition("The consent grant draft no longer matches the ledger head.");
        }

        var proofEnvelope = evidence.ConsumeConsentProof(draft);
        try
        {
            var receipt = BrokerUserPresenceReceiptV1.Create(
                fields.ReceiptId,
                fields.CredentialIdBase64,
                fields.CredentialPublicKeySha256,
                fields.ChallengeNonceBase64,
                Convert.ToBase64String(proofEnvelope));
            var entry = new BrokerConsentGrantEntryV1(
                revision,
                current.EntrySha256,
                revocationGeneration,
                generationSha256,
                fields.IssuedAtUtcTicks,
                receipt);
            var next = CreateDocument(current.LedgerId, revision, entry);
            ValidateSuccessor(current, next);
            var finalizedStatement = CreateConsentStatement(next);
            var draftStatement = draft.ConsentStatementBytes;
            try
            {
                if (!finalizedStatement.AsSpan().SequenceEqual(draftStatement))
                {
                    throw InvalidTransition(
                        "The finalized grant changed the frozen consent statement.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(finalizedStatement);
                CryptographicOperations.ZeroMemory(draftStatement);
            }

            return next;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(proofEnvelope);
        }
    }

    internal static BrokerConsentStatementFieldsV1 CreateGrantStatementFields(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        Guid receiptId,
        string credentialIdBase64,
        string credentialPublicKeySha256,
        string challengeNonceBase64,
        long issuedAtUtcTicks)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(generation);
        ValidateDocument(current);
        RequireExpectedRevision(current, expectedRevision);
        RequireTimestamp(issuedAtUtcTicks, "issuedAtUtcTicks");
        var generationSha256 = RevalidateGeneration(generation);
        var (revision, revocationGeneration) = CreateNextGrantPosition(current);
        return BrokerConsentStatementFieldsV1.Create(
            current.LedgerId,
            revision,
            revision,
            current.EntrySha256,
            revocationGeneration,
            receiptId,
            generationSha256,
            issuedAtUtcTicks,
            credentialIdBase64,
            credentialPublicKeySha256,
            challengeNonceBase64);
    }

    internal static BrokerConsentLedgerDocumentV1 CreateRevoke(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        BrokerConsentRevokeReasonV1 reason,
        long revokedAtUtcTicks)
    {
        ArgumentNullException.ThrowIfNull(current);
        ValidateDocument(current);
        RequireExpectedRevision(current, expectedRevision);
        RequireTimestamp(revokedAtUtcTicks, "revokedAtUtcTicks");
        _ = RevokeReasonName(reason);

        if (current.Entry is BrokerConsentRevokeEntryV1 currentRevoke)
        {
            if (currentRevoke.Reason == reason &&
                currentRevoke.RevokedAtUtcTicks == revokedAtUtcTicks)
            {
                return current;
            }

            throw InvalidTransition("An already-revoked ledger cannot be revoked again.");
        }

        if (current.Entry is not BrokerConsentGrantEntryV1 grant ||
            current.Revision == ulong.MaxValue ||
            grant.RevocationGeneration == ulong.MaxValue)
        {
            throw InvalidTransition("Only a current grant can be revoked.");
        }

        var revision = current.Revision + 1;
        var entry = new BrokerConsentRevokeEntryV1(
            revision,
            current.EntrySha256,
            grant.RevocationGeneration + 1,
            grant.ReceiptId,
            grant.GenerationSha256,
            reason,
            revokedAtUtcTicks);
        var next = CreateDocument(current.LedgerId, revision, entry);
        ValidateSuccessor(current, next);
        return next;
    }

    internal static string RequireSha256(string value, string fieldName)
    {
        if (value is null || value.Length != 64)
        {
            throw InvalidSchema($"{fieldName} must be an uppercase SHA-256 value.");
        }

        foreach (var character in value)
        {
            if (!((character >= '0' && character <= '9') ||
                  (character >= 'A' && character <= 'F')))
            {
                throw InvalidSchema($"{fieldName} must be an uppercase SHA-256 value.");
            }
        }

        return value;
    }

    internal static string RequireCanonicalBase64(
        string value,
        int minimumBytes,
        int maximumBytes,
        int? exactBytes,
        string fieldName)
    {
        if (string.IsNullOrEmpty(value) || value.Length > ((maximumBytes + 2) / 3) * 4)
        {
            throw InvalidReceipt($"{fieldName} is outside the receipt bound.");
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            throw InvalidReceipt($"{fieldName} is not canonical base64.");
        }

        if (decoded.Length < minimumBytes ||
            decoded.Length > maximumBytes ||
            (exactBytes.HasValue && decoded.Length != exactBytes.Value) ||
            !string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))
        {
            throw InvalidReceipt($"{fieldName} is not canonical bounded base64.");
        }

        return value;
    }

    internal static BrokerConsentLedgerFormatException InvalidReceipt(string message) =>
        new("consent-ledger-receipt-invalid", message);

    private static BrokerConsentLedgerDocumentV1 CreateDocument(
        Guid ledgerId,
        ulong revision,
        BrokerConsentLedgerEntryV1 entry)
    {
        var entrySha256 = ComputeEntrySha256(entry);
        var document = new BrokerConsentLedgerDocumentV1(
            ledgerId,
            revision,
            entry,
            entrySha256,
            entry is BrokerConsentGrantEntryV1
                ? BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification
                : BrokerConsentLedgerValidationStateV1.StructurallyValid);
        ValidateDocument(document);
        return document;
    }

    private static BrokerConsentLedgerEntryV1 ParseEntry(JsonElement entry)
    {
        var kind = ReadString(entry, "kind");
        return kind switch
        {
            "genesis" => ParseGenesis(entry),
            "grant" => ParseGrant(entry),
            "revoke" => ParseRevoke(entry),
            _ => throw InvalidSchema("The consent ledger entry kind is unsupported.")
        };
    }

    private static BrokerConsentGenesisEntryV1 ParseGenesis(JsonElement entry)
    {
        RequireExactProperties(
            entry,
            "kind",
            "sequence",
            "previousEntrySha256",
            "revocationGeneration");
        if (ReadUInt64(entry, "sequence") != 0 ||
            !string.Equals(
                RequireSha256(ReadString(entry, "previousEntrySha256"), "previousEntrySha256"),
                ZeroSha256,
                StringComparison.Ordinal) ||
            ReadUInt64(entry, "revocationGeneration") != 0)
        {
            throw InvalidSchema("The genesis entry is invalid.");
        }

        return new BrokerConsentGenesisEntryV1();
    }

    private static BrokerConsentGrantEntryV1 ParseGrant(JsonElement entry)
    {
        RequireExactProperties(
            entry,
            "kind",
            "sequence",
            "previousEntrySha256",
            "revocationGeneration",
            "receiptId",
            "generationSha256",
            "capability",
            "issuedAtUtcTicks",
            "receiptFormat",
            "credentialIdBase64",
            "credentialPublicKeySha256",
            "challengeNonceBase64",
            "signatureBase64");
        if (!string.Equals(ReadString(entry, "capability"), CapabilityName, StringComparison.Ordinal) ||
            !string.Equals(
                ReadString(entry, "receiptFormat"),
                ReceiptFormatName,
                StringComparison.Ordinal))
        {
            throw InvalidSchema("The grant capability or receipt format is invalid.");
        }

        var receipt = BrokerUserPresenceReceiptV1.Create(
            ReadCanonicalGuid(entry, "receiptId"),
            ReadString(entry, "credentialIdBase64"),
            RequireSha256(
                ReadString(entry, "credentialPublicKeySha256"),
                "credentialPublicKeySha256"),
            ReadString(entry, "challengeNonceBase64"),
            ReadString(entry, "signatureBase64"));
        var issuedAtUtcTicks = ReadInt64(entry, "issuedAtUtcTicks");
        RequireTimestamp(issuedAtUtcTicks, "issuedAtUtcTicks");
        return new BrokerConsentGrantEntryV1(
            ReadUInt64(entry, "sequence"),
            RequireSha256(ReadString(entry, "previousEntrySha256"), "previousEntrySha256"),
            ReadUInt64(entry, "revocationGeneration"),
            RequireSha256(ReadString(entry, "generationSha256"), "generationSha256"),
            issuedAtUtcTicks,
            receipt);
    }

    private static BrokerConsentRevokeEntryV1 ParseRevoke(JsonElement entry)
    {
        RequireExactProperties(
            entry,
            "kind",
            "sequence",
            "previousEntrySha256",
            "revocationGeneration",
            "revokedReceiptId",
            "revokedGenerationSha256",
            "capability",
            "reason",
            "revokedAtUtcTicks");
        if (!string.Equals(ReadString(entry, "capability"), CapabilityName, StringComparison.Ordinal))
        {
            throw InvalidSchema("The revoke capability is invalid.");
        }

        var revokedAtUtcTicks = ReadInt64(entry, "revokedAtUtcTicks");
        RequireTimestamp(revokedAtUtcTicks, "revokedAtUtcTicks");
        return new BrokerConsentRevokeEntryV1(
            ReadUInt64(entry, "sequence"),
            RequireSha256(ReadString(entry, "previousEntrySha256"), "previousEntrySha256"),
            ReadUInt64(entry, "revocationGeneration"),
            ReadCanonicalGuid(entry, "revokedReceiptId"),
            RequireSha256(
                ReadString(entry, "revokedGenerationSha256"),
                "revokedGenerationSha256"),
            ParseRevokeReason(ReadString(entry, "reason")),
            revokedAtUtcTicks);
    }

    private static void ValidateDocument(BrokerConsentLedgerDocumentV1 document)
    {
        if (document.LedgerId == Guid.Empty ||
            document.Entry is null ||
            document.Revision != document.Entry.Sequence ||
            !FixedHashEquals(document.EntrySha256, ComputeEntrySha256(document.Entry)))
        {
            throw InvalidSchema("The consent ledger document invariants are invalid.");
        }

        _ = RequireSha256(document.Entry.PreviousEntrySha256, "previousEntrySha256");
        switch (document.Entry)
        {
            case BrokerConsentGenesisEntryV1 when
                document.Revision == 0 &&
                document.Entry.RevocationGeneration == 0 &&
                string.Equals(
                    document.Entry.PreviousEntrySha256,
                    ZeroSha256,
                    StringComparison.Ordinal) &&
                document.ValidationState == BrokerConsentLedgerValidationStateV1.StructurallyValid:
                return;
            case BrokerConsentGrantEntryV1 grant when
                document.Revision > 0 &&
                grant.Receipt is not null &&
                document.ValidationState ==
                    BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification:
                _ = RequireSha256(grant.GenerationSha256, "generationSha256");
                RequireTimestamp(grant.IssuedAtUtcTicks, "issuedAtUtcTicks");
                return;
            case BrokerConsentRevokeEntryV1 revoke when
                document.Revision > 0 &&
                revoke.RevokedReceiptId != Guid.Empty &&
                document.ValidationState == BrokerConsentLedgerValidationStateV1.StructurallyValid:
                _ = RequireSha256(revoke.RevokedGenerationSha256, "revokedGenerationSha256");
                _ = RevokeReasonName(revoke.Reason);
                RequireTimestamp(revoke.RevokedAtUtcTicks, "revokedAtUtcTicks");
                return;
            default:
                throw InvalidSchema("The consent ledger entry state is invalid.");
        }
    }

    private static string ComputeEntrySha256(BrokerConsentLedgerEntryV1 entry)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = CreateWriter(buffer);
        WriteEntry(writer, entry);
        writer.Flush();
        return Convert.ToHexString(SHA256.HashData(buffer.WrittenSpan));
    }

    private static void WriteEntry(Utf8JsonWriter writer, BrokerConsentLedgerEntryV1 entry)
    {
        writer.WriteStartObject();
        writer.WriteString("kind", entry.Kind);
        writer.WriteNumber("sequence", entry.Sequence);
        writer.WriteString("previousEntrySha256", entry.PreviousEntrySha256);
        writer.WriteNumber("revocationGeneration", entry.RevocationGeneration);
        switch (entry)
        {
            case BrokerConsentGenesisEntryV1:
                break;
            case BrokerConsentGrantEntryV1 grant:
                writer.WriteString("receiptId", CanonicalGuid(grant.ReceiptId));
                writer.WriteString("generationSha256", grant.GenerationSha256);
                writer.WriteString("capability", CapabilityName);
                writer.WriteNumber("issuedAtUtcTicks", grant.IssuedAtUtcTicks);
                writer.WriteString("receiptFormat", ReceiptFormatName);
                writer.WriteString("credentialIdBase64", grant.Receipt.CredentialIdBase64);
                writer.WriteString(
                    "credentialPublicKeySha256",
                    grant.Receipt.CredentialPublicKeySha256);
                writer.WriteString("challengeNonceBase64", grant.Receipt.ChallengeNonceBase64);
                writer.WriteString("signatureBase64", grant.Receipt.SignatureBase64);
                break;
            case BrokerConsentRevokeEntryV1 revoke:
                writer.WriteString("revokedReceiptId", CanonicalGuid(revoke.RevokedReceiptId));
                writer.WriteString("revokedGenerationSha256", revoke.RevokedGenerationSha256);
                writer.WriteString("capability", CapabilityName);
                writer.WriteString("reason", RevokeReasonName(revoke.Reason));
                writer.WriteNumber("revokedAtUtcTicks", revoke.RevokedAtUtcTicks);
                break;
            default:
                throw InvalidSchema("The consent ledger entry kind is unsupported.");
        }

        writer.WriteEndObject();
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

    private static string RevalidateGeneration(CodexPackageGenerationV1 generation)
    {
        var canonicalBytes = new UTF8Encoding(false, true).GetBytes(generation.CanonicalJson);
        var actual = Convert.ToHexString(SHA256.HashData(canonicalBytes));
        if (!FixedHashEquals(actual, RequireSha256(
                generation.GenerationSha256,
                "generationSha256")))
        {
            throw new BrokerConsentLedgerFormatException(
                "consent-ledger-generation-invalid",
                "The package generation canonical JSON and digest disagree.");
        }

        return actual;
    }

    private static (ulong Revision, ulong RevocationGeneration) CreateNextGrantPosition(
        BrokerConsentLedgerDocumentV1 current)
    {
        if (current.Revision == ulong.MaxValue)
        {
            throw InvalidTransition("The consent ledger revision is exhausted.");
        }

        var revocationGeneration = current.Entry switch
        {
            BrokerConsentGenesisEntryV1 => 0UL,
            BrokerConsentGrantEntryV1 grant when grant.RevocationGeneration < ulong.MaxValue =>
                grant.RevocationGeneration + 1,
            BrokerConsentRevokeEntryV1 revoke => revoke.RevocationGeneration,
            _ => throw InvalidTransition("The grant transition is invalid.")
        };
        return (current.Revision + 1, revocationGeneration);
    }

    private static void RequireExpectedRevision(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision)
    {
        if (current.Revision != expectedRevision)
        {
            throw InvalidTransition("The expected ledger revision is stale.");
        }
    }

    internal static void RequireTimestamp(long ticks, string fieldName)
    {
        if (ticks < DateTime.UnixEpoch.Ticks || ticks > DateTime.MaxValue.Ticks)
        {
            throw InvalidSchema($"{fieldName} is outside the canonical UTC tick range.");
        }
    }

    private static string CanonicalGuid(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw InvalidSchema("A non-empty canonical GUID is required.");
        }

        return value.ToString("D");
    }

    private static Guid ReadCanonicalGuid(JsonElement element, string propertyName)
    {
        var value = ReadString(element, propertyName);
        if (!Guid.TryParseExact(value, "D", out var parsed) ||
            parsed == Guid.Empty ||
            !string.Equals(parsed.ToString("D"), value, StringComparison.Ordinal))
        {
            throw InvalidSchema($"{propertyName} is not a canonical GUID.");
        }

        return parsed;
    }

    private static JsonElement ReadObject(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Object)
        {
            throw InvalidSchema($"{propertyName} must be an object.");
        }

        return value;
    }

    private static string ReadString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw InvalidSchema($"{propertyName} must be a string.");
        }

        return value.GetString() ?? throw InvalidSchema($"{propertyName} is missing.");
    }

    private static ulong ReadUInt64(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetUInt64(out var result))
        {
            throw InvalidSchema($"{propertyName} must be an unsigned integer.");
        }

        return result;
    }

    private static long ReadInt64(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt64(out var result))
        {
            throw InvalidSchema($"{propertyName} must be a signed integer.");
        }

        return result;
    }

    private static void RequireExactProperties(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw InvalidSchema("A consent ledger object is required.");
        }

        var allowed = new HashSet<string>(expected, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!allowed.Contains(property.Name) || !seen.Add(property.Name))
            {
                throw InvalidSchema("The consent ledger object fields are not exact.");
            }
        }

        if (!seen.SetEquals(allowed))
        {
            throw InvalidSchema("The consent ledger object is missing a required field.");
        }
    }

    private static BrokerConsentRevokeReasonV1 ParseRevokeReason(string value) => value switch
    {
        "userRequested" => BrokerConsentRevokeReasonV1.UserRequested,
        "packageChanged" => BrokerConsentRevokeReasonV1.PackageChanged,
        "credentialRotated" => BrokerConsentRevokeReasonV1.CredentialRotated,
        "policyChanged" => BrokerConsentRevokeReasonV1.PolicyChanged,
        _ => throw InvalidSchema("The revoke reason is unsupported.")
    };

    private static string RevokeReasonName(BrokerConsentRevokeReasonV1 value) => value switch
    {
        BrokerConsentRevokeReasonV1.UserRequested => "userRequested",
        BrokerConsentRevokeReasonV1.PackageChanged => "packageChanged",
        BrokerConsentRevokeReasonV1.CredentialRotated => "credentialRotated",
        BrokerConsentRevokeReasonV1.PolicyChanged => "policyChanged",
        _ => throw InvalidSchema("The revoke reason is unsupported.")
    };

    private static bool FixedHashEquals(string left, string right)
    {
        _ = RequireSha256(left, "leftHash");
        _ = RequireSha256(right, "rightHash");
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));
    }

    private static BrokerConsentLedgerFormatException InvalidSize(string message) =>
        new("consent-ledger-size", message);

    private static BrokerConsentLedgerFormatException InvalidSchema(string message) =>
        new("consent-ledger-schema", message);

    private static BrokerConsentLedgerFormatException NonCanonical(string message) =>
        new("consent-ledger-noncanonical", message);

    private static BrokerConsentLedgerFormatException InvalidChain(string message) =>
        new("consent-ledger-chain-invalid", message);

    private static BrokerConsentLedgerFormatException InvalidTransition(string message) =>
        new("consent-ledger-transition-invalid", message);
}
