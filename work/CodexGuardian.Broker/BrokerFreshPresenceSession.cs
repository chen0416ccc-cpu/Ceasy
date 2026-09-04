using CodexGuardian.Control;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;

namespace CodexGuardian.Broker;

internal sealed class BrokerFreshPresenceStatementV1 : IDisposable
{
    internal const string SchemaName = "codex-broker-fresh-presence-statement-v1";

    private readonly string _brokerEpoch;
    private readonly uint _windowsSessionId;
    private readonly Guid _ledgerId;
    private readonly ulong _ledgerRevision;
    private readonly string _ledgerEntrySha256;
    private readonly Guid _receiptId;
    private readonly string _generationSha256;
    private readonly string _generationCanonicalJson;
    private readonly string _capability;
    private readonly string _credentialIdBase64;
    private readonly string _credentialPublicKeySha256;
    private readonly string _freshNonceBase64;
    private readonly string _statementSha256;
    private readonly byte[] _credentialId;
    private readonly byte[] _subjectPublicKeyInfo;
    private readonly byte[] _freshNonce;
    private readonly byte[] _canonicalStatementBytes;
    private int _disposed;

    private BrokerFreshPresenceStatementV1(
        string brokerEpoch,
        uint windowsSessionId,
        Guid ledgerId,
        ulong ledgerRevision,
        string ledgerEntrySha256,
        Guid receiptId,
        string generationSha256,
        string generationCanonicalJson,
        string capability,
        string credentialIdBase64,
        string credentialPublicKeySha256,
        string freshNonceBase64,
        string statementSha256,
        byte[] credentialId,
        byte[] subjectPublicKeyInfo,
        byte[] freshNonce,
        byte[] canonicalStatementBytes)
    {
        _brokerEpoch = brokerEpoch;
        _windowsSessionId = windowsSessionId;
        _ledgerId = ledgerId;
        _ledgerRevision = ledgerRevision;
        _ledgerEntrySha256 = ledgerEntrySha256;
        _receiptId = receiptId;
        _generationSha256 = generationSha256;
        _generationCanonicalJson = generationCanonicalJson;
        _capability = capability;
        _credentialIdBase64 = credentialIdBase64;
        _credentialPublicKeySha256 = credentialPublicKeySha256;
        _freshNonceBase64 = freshNonceBase64;
        _statementSha256 = statementSha256;
        _credentialId = credentialId;
        _subjectPublicKeyInfo = subjectPublicKeyInfo;
        _freshNonce = freshNonce;
        _canonicalStatementBytes = canonicalStatementBytes;
    }

    internal string Schema => Read(SchemaName);

    internal string BrokerEpoch => Read(_brokerEpoch);

    internal uint WindowsSessionId => Read(_windowsSessionId);

    internal Guid LedgerId => Read(_ledgerId);

    internal ulong LedgerRevision => Read(_ledgerRevision);

    internal string LedgerEntrySha256 => Read(_ledgerEntrySha256);

    internal Guid ReceiptId => Read(_receiptId);

    internal string GenerationSha256 => Read(_generationSha256);

    internal string GenerationCanonicalJson => Read(_generationCanonicalJson);

    internal string Capability => Read(_capability);

    internal string CredentialIdBase64 => Read(_credentialIdBase64);

    internal string CredentialPublicKeySha256 => Read(_credentialPublicKeySha256);

    internal string FreshNonceBase64 => Read(_freshNonceBase64);

    internal string StatementSha256 => Read(_statementSha256);

    internal byte[] CredentialId => Clone(_credentialId);

    internal byte[] SubjectPublicKeyInfo => Clone(_subjectPublicKeyInfo);

    internal byte[] FreshNonce => Clone(_freshNonce);

    internal byte[] CanonicalStatementBytes => Clone(_canonicalStatementBytes);

    internal static BrokerFreshPresenceStatementV1 Create(
        string brokerEpoch,
        uint windowsSessionId,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        string capability,
        BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1 persistedEvidence,
        ReadOnlySpan<byte> freshNonce)
    {
        ArgumentNullException.ThrowIfNull(brokerEpoch);
        ArgumentNullException.ThrowIfNull(ledgerSnapshot);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(persistedEvidence);
        BrokerFreshPresenceValidationV1.RequireBrokerEpoch(brokerEpoch);
        if (windowsSessionId == 0)
        {
            throw BrokerFreshPresenceValidationV1.Fail(
                "consent-windows-session-changed",
                "A nonzero Windows session id is required for fresh presence.");
        }

        if (!string.Equals(
                capability,
                BrokerConsentLedgerV1.CapabilityName,
                StringComparison.Ordinal))
        {
            throw BrokerFreshPresenceValidationV1.Fail(
                "consent-ledger-head-changed",
                "The requested capability is not the fixed Broker capability.");
        }

        if (freshNonce.Length != 32)
        {
            throw new ArgumentException(
                "The fresh-presence nonce must contain exactly 32 bytes.",
                nameof(freshNonce));
        }

        var grantEntry = BrokerFreshPresenceValidationV1.RequirePendingSnapshot(ledgerSnapshot);
        var grant = ledgerSnapshot.Primary!;
        var generationIdentity = BrokerFreshPresenceValidationV1.RequireGeneration(
            generation,
            grantEntry);
        byte[]? credentialId = null;
        byte[]? subjectPublicKeyInfo = null;
        byte[]? ownedFreshNonce = null;
        byte[]? canonicalStatementBytes = null;
        try
        {
            credentialId = persistedEvidence.CredentialId;
            subjectPublicKeyInfo = persistedEvidence.SubjectPublicKeyInfo;
            persistedEvidence.ConsumePersistedGrant(grant);
            var receipt = grantEntry.Receipt;
            var actualCredentialIdBase64 = Convert.ToBase64String(credentialId);
            var actualSubjectPublicKeyInfoSha256 =
                Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
            if (!string.Equals(
                    actualCredentialIdBase64,
                    receipt.CredentialIdBase64,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    actualSubjectPublicKeyInfoSha256,
                    receipt.CredentialPublicKeySha256,
                    StringComparison.Ordinal))
            {
                throw BrokerFreshPresenceValidationV1.Fail(
                    "user-presence-credential-invalid",
                    "The verified persisted credential does not match the pending grant.");
            }

            ownedFreshNonce = freshNonce.ToArray();
            var freshNonceBase64 = Convert.ToBase64String(ownedFreshNonce);
            canonicalStatementBytes = WriteCanonicalStatement(
                brokerEpoch,
                windowsSessionId,
                grant.LedgerId,
                grant.Revision,
                grant.EntrySha256,
                receipt.ReceiptId,
                generationIdentity.Sha256,
                capability,
                receipt.CredentialIdBase64,
                receipt.CredentialPublicKeySha256,
                freshNonceBase64);
            var result = new BrokerFreshPresenceStatementV1(
                brokerEpoch,
                windowsSessionId,
                grant.LedgerId,
                grant.Revision,
                grant.EntrySha256,
                receipt.ReceiptId,
                generationIdentity.Sha256,
                generationIdentity.CanonicalJson,
                capability,
                receipt.CredentialIdBase64,
                receipt.CredentialPublicKeySha256,
                freshNonceBase64,
                Convert.ToHexString(SHA256.HashData(canonicalStatementBytes)),
                credentialId,
                subjectPublicKeyInfo,
                ownedFreshNonce,
                canonicalStatementBytes);
            credentialId = null;
            subjectPublicKeyInfo = null;
            ownedFreshNonce = null;
            canonicalStatementBytes = null;
            return result;
        }
        finally
        {
            BrokerFreshPresenceValidationV1.Clear(credentialId);
            BrokerFreshPresenceValidationV1.Clear(subjectPublicKeyInfo);
            BrokerFreshPresenceValidationV1.Clear(ownedFreshNonce);
            BrokerFreshPresenceValidationV1.Clear(canonicalStatementBytes);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        BrokerFreshPresenceValidationV1.Clear(_credentialId);
        BrokerFreshPresenceValidationV1.Clear(_subjectPublicKeyInfo);
        BrokerFreshPresenceValidationV1.Clear(_freshNonce);
        BrokerFreshPresenceValidationV1.Clear(_canonicalStatementBytes);
    }

    private static byte[] WriteCanonicalStatement(
        string brokerEpoch,
        uint windowsSessionId,
        Guid ledgerId,
        ulong ledgerRevision,
        string ledgerEntrySha256,
        Guid receiptId,
        string generationSha256,
        string capability,
        string credentialIdBase64,
        string credentialPublicKeySha256,
        string freshNonceBase64)
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
        writer.WriteString("schema", SchemaName);
        writer.WriteString("brokerEpoch", brokerEpoch);
        writer.WriteNumber("windowsSessionId", windowsSessionId);
        writer.WriteString("ledgerId", ledgerId.ToString("D"));
        writer.WriteNumber("ledgerRevision", ledgerRevision);
        writer.WriteString("ledgerEntrySha256", ledgerEntrySha256);
        writer.WriteString("receiptId", receiptId.ToString("D"));
        writer.WriteString("generationSha256", generationSha256);
        writer.WriteString("capability", capability);
        writer.WriteString("credentialIdBase64", credentialIdBase64);
        writer.WriteString("credentialPublicKeySha256", credentialPublicKeySha256);
        writer.WriteString("freshNonceBase64", freshNonceBase64);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private T Read<T>(T value)
    {
        ThrowIfDisposed();
        return value;
    }

    private byte[] Clone(byte[] value)
    {
        ThrowIfDisposed();
        return (byte[])value.Clone();
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
}

internal sealed class BrokerFreshPresenceAttemptV1 : IDisposable
{
    private readonly byte[] _freshNonce;
    private readonly BrokerFreshPresenceStatementV1 _statement;
    private int _consumed;

    private BrokerFreshPresenceAttemptV1(
        byte[] freshNonce,
        BrokerFreshPresenceStatementV1 statement)
    {
        _freshNonce = freshNonce;
        _statement = statement;
    }

    internal BrokerFreshPresenceStatementV1 Statement
    {
        get
        {
            ThrowIfConsumed();
            return _statement;
        }
    }

    internal static BrokerFreshPresenceAttemptV1 Create(
        string brokerEpoch,
        uint windowsSessionId,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        string capability,
        BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1 persistedEvidence)
    {
        var freshNonce = new byte[32];
        BrokerFreshPresenceStatementV1? statement = null;
        try
        {
            RandomNumberGenerator.Fill(freshNonce);
            statement = BrokerFreshPresenceStatementV1.Create(
                brokerEpoch,
                windowsSessionId,
                ledgerSnapshot,
                generation,
                capability,
                persistedEvidence,
                freshNonce);
            var result = new BrokerFreshPresenceAttemptV1(freshNonce, statement);
            freshNonce = null!;
            statement = null;
            return result;
        }
        finally
        {
            BrokerFreshPresenceValidationV1.Clear(freshNonce);
            statement?.Dispose();
        }
    }

    internal BrokerFreshPresenceSessionV1 Complete(
        BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1 freshEvidence)
    {
        ArgumentNullException.ThrowIfNull(freshEvidence);
        if (Interlocked.CompareExchange(ref _consumed, 1, 0) != 0)
        {
            throw BrokerFreshPresenceValidationV1.Fail(
                "consent-fresh-presence-required",
                "The fresh-presence attempt is no longer usable.");
        }

        try
        {
            return BrokerFreshPresenceSessionV1.Create(_statement, freshEvidence);
        }
        finally
        {
            BrokerFreshPresenceValidationV1.Clear(_freshNonce);
            _statement.Dispose();
        }
    }

    internal void Cancel() => Dispose();

    public void Dispose()
    {
        _ = Interlocked.Exchange(ref _consumed, 1);
        BrokerFreshPresenceValidationV1.Clear(_freshNonce);
        _statement.Dispose();
    }

    private void ThrowIfConsumed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _consumed) != 0, this);
}

internal sealed class BrokerFreshPresenceSessionV1 : IDisposable
{
    private readonly string _brokerEpoch;
    private readonly uint _windowsSessionId;
    private readonly Guid _ledgerId;
    private readonly ulong _ledgerRevision;
    private readonly string _ledgerEntrySha256;
    private readonly Guid _receiptId;
    private readonly string _generationSha256;
    private readonly string _generationCanonicalJson;
    private readonly string _capability;
    private readonly string _credentialPublicKeySha256;
    private readonly string _statementSha256;
    private readonly long _createdTimestamp;
    private readonly byte[] _credentialId;
    private readonly byte[] _subjectPublicKeyInfo;
    private readonly byte[] _freshNonce;
    private readonly byte[] _sessionId;
    private int _disposed;

    private BrokerFreshPresenceSessionV1(
        string brokerEpoch,
        uint windowsSessionId,
        Guid ledgerId,
        ulong ledgerRevision,
        string ledgerEntrySha256,
        Guid receiptId,
        string generationSha256,
        string generationCanonicalJson,
        string capability,
        string credentialPublicKeySha256,
        string statementSha256,
        long createdTimestamp,
        byte[] credentialId,
        byte[] subjectPublicKeyInfo,
        byte[] freshNonce,
        byte[] sessionId)
    {
        _brokerEpoch = brokerEpoch;
        _windowsSessionId = windowsSessionId;
        _ledgerId = ledgerId;
        _ledgerRevision = ledgerRevision;
        _ledgerEntrySha256 = ledgerEntrySha256;
        _receiptId = receiptId;
        _generationSha256 = generationSha256;
        _generationCanonicalJson = generationCanonicalJson;
        _capability = capability;
        _credentialPublicKeySha256 = credentialPublicKeySha256;
        _statementSha256 = statementSha256;
        _createdTimestamp = createdTimestamp;
        _credentialId = credentialId;
        _subjectPublicKeyInfo = subjectPublicKeyInfo;
        _freshNonce = freshNonce;
        _sessionId = sessionId;
    }

    internal string BrokerEpoch => Read(_brokerEpoch);

    internal uint WindowsSessionId => Read(_windowsSessionId);

    internal Guid LedgerId => Read(_ledgerId);

    internal ulong LedgerRevision => Read(_ledgerRevision);

    internal string LedgerEntrySha256 => Read(_ledgerEntrySha256);

    internal Guid ReceiptId => Read(_receiptId);

    internal string GenerationSha256 => Read(_generationSha256);

    internal string GenerationCanonicalJson => Read(_generationCanonicalJson);

    internal string Capability => Read(_capability);

    internal string CredentialPublicKeySha256 => Read(_credentialPublicKeySha256);

    internal string StatementSha256 => Read(_statementSha256);

    internal long CreatedTimestamp => Read(_createdTimestamp);

    internal byte[] CredentialId => Clone(_credentialId);

    internal byte[] SubjectPublicKeyInfo => Clone(_subjectPublicKeyInfo);

    internal byte[] FreshNonce => Clone(_freshNonce);

    internal byte[] SessionId => Clone(_sessionId);

    internal static BrokerFreshPresenceSessionV1 Create(
        BrokerFreshPresenceStatementV1 statement,
        BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1 freshEvidence)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(freshEvidence);
        freshEvidence.ConsumeFreshPresence(statement);
        BrokerFreshPresenceReplayGuardV1.Register(statement.StatementSha256);

        byte[]? credentialId = null;
        byte[]? subjectPublicKeyInfo = null;
        byte[]? freshNonce = null;
        byte[]? sessionId = null;
        try
        {
            credentialId = statement.CredentialId;
            subjectPublicKeyInfo = statement.SubjectPublicKeyInfo;
            freshNonce = statement.FreshNonce;
            sessionId = new byte[32];
            RandomNumberGenerator.Fill(sessionId);
            var result = new BrokerFreshPresenceSessionV1(
                statement.BrokerEpoch,
                statement.WindowsSessionId,
                statement.LedgerId,
                statement.LedgerRevision,
                statement.LedgerEntrySha256,
                statement.ReceiptId,
                statement.GenerationSha256,
                statement.GenerationCanonicalJson,
                statement.Capability,
                statement.CredentialPublicKeySha256,
                statement.StatementSha256,
                Stopwatch.GetTimestamp(),
                credentialId,
                subjectPublicKeyInfo,
                freshNonce,
                sessionId);
            credentialId = null;
            subjectPublicKeyInfo = null;
            freshNonce = null;
            sessionId = null;
            return result;
        }
        finally
        {
            BrokerFreshPresenceValidationV1.Clear(credentialId);
            BrokerFreshPresenceValidationV1.Clear(subjectPublicKeyInfo);
            BrokerFreshPresenceValidationV1.Clear(freshNonce);
            BrokerFreshPresenceValidationV1.Clear(sessionId);
        }
    }

    internal void Revalidate(
        string brokerEpoch,
        uint windowsSessionId,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        string capability,
        BrokerWebAuthnRegisteredCredentialV1 credential)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(brokerEpoch);
        ArgumentNullException.ThrowIfNull(ledgerSnapshot);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(credential);
        if (!BrokerFreshPresenceValidationV1.IsExactBrokerEpoch(brokerEpoch) ||
            !string.Equals(brokerEpoch, _brokerEpoch, StringComparison.Ordinal))
        {
            Invalidate(
                "consent-broker-epoch-changed",
                "The Broker epoch changed after fresh presence.");
        }

        if (windowsSessionId == 0 || windowsSessionId != _windowsSessionId)
        {
            Invalidate(
                "consent-windows-session-changed",
                "The Windows session changed after fresh presence.");
        }

        if (!string.Equals(capability, _capability, StringComparison.Ordinal) ||
            !string.Equals(
                capability,
                BrokerConsentLedgerV1.CapabilityName,
                StringComparison.Ordinal))
        {
            Invalidate(
                "consent-ledger-head-changed",
                "The fixed capability changed after fresh presence.");
        }

        BrokerConsentGrantEntryV1 grantEntry;
        BrokerFreshPresenceValidationV1.GenerationIdentity generationIdentity;
        try
        {
            grantEntry = BrokerFreshPresenceValidationV1.RequirePendingSnapshot(ledgerSnapshot);
            generationIdentity = BrokerFreshPresenceValidationV1.RequireGeneration(
                generation,
                grantEntry);
        }
        catch (BrokerUserPresenceVerificationException)
        {
            Dispose();
            throw;
        }

        var grant = ledgerSnapshot.Primary!;
        var receipt = grantEntry.Receipt;
        if (grant.LedgerId != _ledgerId ||
            grant.Revision != _ledgerRevision ||
            !string.Equals(grant.EntrySha256, _ledgerEntrySha256, StringComparison.Ordinal) ||
            receipt.ReceiptId != _receiptId ||
            !string.Equals(
                grantEntry.GenerationSha256,
                _generationSha256,
                StringComparison.Ordinal) ||
            !string.Equals(
                receipt.CredentialIdBase64,
                Convert.ToBase64String(_credentialId),
                StringComparison.Ordinal) ||
            !string.Equals(
                receipt.CredentialPublicKeySha256,
                _credentialPublicKeySha256,
                StringComparison.Ordinal))
        {
            Invalidate(
                "consent-ledger-head-changed",
                "The consent-ledger head changed after fresh presence.");
        }

        if (!string.Equals(
                generationIdentity.Sha256,
                _generationSha256,
                StringComparison.Ordinal) ||
            !string.Equals(
                generationIdentity.CanonicalJson,
                _generationCanonicalJson,
                StringComparison.Ordinal))
        {
            Invalidate(
                "consent-package-generation-changed",
                "The package generation changed after fresh presence.");
        }

        byte[]? currentCredentialId = null;
        byte[]? currentSubjectPublicKeyInfo = null;
        try
        {
            currentCredentialId = credential.CredentialId;
            currentSubjectPublicKeyInfo = credential.SubjectPublicKeyInfo;
            var actualSubjectPublicKeyInfoSha256 =
                Convert.ToHexString(SHA256.HashData(currentSubjectPublicKeyInfo));
            if (!CryptographicOperations.FixedTimeEquals(
                    currentCredentialId,
                    _credentialId) ||
                !CryptographicOperations.FixedTimeEquals(
                    currentSubjectPublicKeyInfo,
                    _subjectPublicKeyInfo) ||
                !string.Equals(
                    credential.SubjectPublicKeyInfoSha256,
                    actualSubjectPublicKeyInfoSha256,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    actualSubjectPublicKeyInfoSha256,
                    _credentialPublicKeySha256,
                    StringComparison.Ordinal))
            {
                Invalidate(
                    "user-presence-credential-invalid",
                    "The registered credential changed after fresh presence.");
            }
        }
        catch (BrokerUserPresenceVerificationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ObjectDisposedException or CryptographicException)
        {
            Invalidate(
                "user-presence-credential-invalid",
                "The registered credential is unavailable after fresh presence.",
                exception);
        }
        finally
        {
            BrokerFreshPresenceValidationV1.Clear(currentCredentialId);
            BrokerFreshPresenceValidationV1.Clear(currentSubjectPublicKeyInfo);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        BrokerFreshPresenceValidationV1.Clear(_credentialId);
        BrokerFreshPresenceValidationV1.Clear(_subjectPublicKeyInfo);
        BrokerFreshPresenceValidationV1.Clear(_freshNonce);
        BrokerFreshPresenceValidationV1.Clear(_sessionId);
    }

    private void Invalidate(string code, string message, Exception? innerException = null)
    {
        Dispose();
        throw BrokerFreshPresenceValidationV1.Fail(code, message, innerException);
    }

    private T Read<T>(T value)
    {
        ThrowIfDisposed();
        return value;
    }

    private byte[] Clone(byte[] value)
    {
        ThrowIfDisposed();
        return (byte[])value.Clone();
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
}

internal static class BrokerFreshPresenceReplayGuardV1
{
    private const int MaximumStatementsPerBrokerEpoch = 4096;
    private static readonly object Gate = new();
    private static readonly HashSet<string> StatementHashes = new(StringComparer.Ordinal);

    internal static void Register(string statementSha256)
    {
        ArgumentNullException.ThrowIfNull(statementSha256);
        lock (Gate)
        {
            if (StatementHashes.Count >= MaximumStatementsPerBrokerEpoch ||
                !StatementHashes.Add(statementSha256))
            {
                throw BrokerFreshPresenceValidationV1.Fail(
                    "consent-fresh-presence-required",
                    "The fresh-presence statement was already consumed or the replay bound was reached.");
            }
        }
    }
}

internal static class BrokerFreshPresenceValidationV1
{
    internal readonly record struct GenerationIdentity(string CanonicalJson, string Sha256);

    internal static bool IsExactBrokerEpoch(string value)
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

    internal static void RequireBrokerEpoch(string value)
    {
        if (!IsExactBrokerEpoch(value))
        {
            throw Fail(
                "consent-broker-epoch-changed",
                "The Broker epoch is not an exact lowercase 128-bit identifier.");
        }
    }

    internal static BrokerConsentGrantEntryV1 RequirePendingSnapshot(
        BrokerConsentLedgerStoreSnapshotV1 snapshot)
    {
        if (snapshot.State != BrokerConsentLedgerStoreStateV1.ReceiptPendingVerification ||
            snapshot.Primary is not { } grant ||
            grant.ValidationState != BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification ||
            grant.Entry is not BrokerConsentGrantEntryV1 grantEntry ||
            snapshot.Diagnostics is null ||
            snapshot.Diagnostics.Primary != BrokerConsentLedgerReplicaStateV1.Canonical ||
            snapshot.Diagnostics.Previous != BrokerConsentLedgerReplicaStateV1.Canonical ||
            !string.Equals(
                snapshot.Diagnostics.Code,
                "store-receipt-pending-verification",
                StringComparison.Ordinal))
        {
            throw Fail(
                "consent-ledger-head-changed",
                "An exact canonical pending-verification Store snapshot is required.");
        }

        byte[]? canonical = null;
        try
        {
            canonical = BrokerConsentLedgerV1.Serialize(grant);
        }
        catch (BrokerConsentLedgerFormatException exception)
        {
            throw Fail(
                "consent-ledger-head-changed",
                "The pending Store snapshot is not a valid consent-ledger head.",
                exception);
        }
        finally
        {
            Clear(canonical);
        }

        return grantEntry;
    }

    internal static GenerationIdentity RequireGeneration(
        CodexPackageGenerationV1 generation,
        BrokerConsentGrantEntryV1 grantEntry)
    {
        CodexPackageGenerationV1 rebuilt;
        try
        {
            rebuilt = CodexPackageGenerationV1.Create(
                generation.Package,
                generation.Signer,
                generation.Artifacts,
                generation.Manifest,
                generation.Asar);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or OverflowException)
        {
            throw Fail(
                "consent-package-generation-changed",
                "The package generation cannot be reconstructed canonically.",
                exception);
        }

        if (!string.Equals(
                generation.CanonicalJson,
                rebuilt.CanonicalJson,
                StringComparison.Ordinal) ||
            !string.Equals(
                generation.GenerationSha256,
                rebuilt.GenerationSha256,
                StringComparison.Ordinal) ||
            !string.Equals(
                grantEntry.GenerationSha256,
                rebuilt.GenerationSha256,
                StringComparison.Ordinal))
        {
            throw Fail(
                "consent-package-generation-changed",
                "The package generation does not match the pending consent grant.");
        }

        return new GenerationIdentity(rebuilt.CanonicalJson, rebuilt.GenerationSha256);
    }

    internal static BrokerUserPresenceVerificationException Fail(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    internal static void Clear(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
