using CodexGuardian.Control;
using CodexGuardian.Trust;
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CodexGuardian.Broker;

internal interface IBrokerCapabilityLeaseClockV1
{
    long GetTimestamp();

    TimeSpan GetElapsedTime(long startingTimestamp, long endingTimestamp);
}

internal sealed class BrokerStopwatchCapabilityLeaseClockV1 : IBrokerCapabilityLeaseClockV1
{
    internal static BrokerStopwatchCapabilityLeaseClockV1 Instance { get; } = new();

    private BrokerStopwatchCapabilityLeaseClockV1()
    {
    }

    public long GetTimestamp() => Stopwatch.GetTimestamp();

    public TimeSpan GetElapsedTime(long startingTimestamp, long endingTimestamp) =>
        Stopwatch.GetElapsedTime(startingTimestamp, endingTimestamp);
}

internal sealed class BrokerCapabilityLeaseException : Exception
{
    internal BrokerCapabilityLeaseException(
        string code,
        string message,
        Exception? innerException = null)
        : base(ValidateMessage(message), innerException)
    {
        if (!IsKnownCode(code))
        {
            throw new ArgumentException(
                "A stable Broker capability-lease failure code is required.",
                nameof(code));
        }

        Code = code;
    }

    internal string Code { get; }

    private static bool IsKnownCode(string? code) => code is
        "capability-fresh-presence-invalid" or
        "capability-broker-epoch-changed" or
        "capability-windows-session-changed" or
        "capability-ledger-head-changed" or
        "capability-package-generation-changed" or
        "capability-credential-changed" or
        "capability-peer-changed" or
        "capability-runtime-changed" or
        "capability-clock-invalid" or
        "capability-lease-expired" or
        "capability-lease-consumed";

    private static string ValidateMessage(string message)
    {
        if (string.IsNullOrWhiteSpace(message) || message.Length > 256)
        {
            throw new ArgumentException(
                "A bounded Broker capability-lease failure message is required.",
                nameof(message));
        }

        return message;
    }
}

internal sealed class BrokerCapabilityLeaseV1 : IDisposable
{
    private const int Active = 0;
    private const int Consuming = 1;
    private const int Terminal = 2;
    private static readonly ConditionalWeakTable<BrokerFreshPresenceSessionV1, object>
        FreshSessionGates = new();

    private readonly object _gate = new();
    private readonly IBrokerCapabilityLeaseClockV1 _clock;
    private readonly VerifiedGuardianManagedEntryConnectionV1 _guardianPeer;
    private readonly WindowsProcessIdentity _guardianIdentity;
    private readonly ICodexCdpHandleLease _runtimeLease;
    private readonly CodexCdpRuntimeIdentity _runtimeIdentity;
    private readonly int _brokerProcessId;
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
    private readonly long _freshPresenceTimestamp;
    private readonly long _issuedTimestamp;
    private readonly byte[] _credentialId;
    private readonly byte[] _subjectPublicKeyInfo;
    private readonly byte[] _freshSessionId;
    private readonly byte[] _leaseId;
    private long _lastTimestamp;
    private int _state;

    private BrokerCapabilityLeaseV1(
        IBrokerCapabilityLeaseClockV1 clock,
        VerifiedGuardianManagedEntryConnectionV1 guardianPeer,
        WindowsProcessIdentity guardianIdentity,
        ICodexCdpHandleLease runtimeLease,
        CodexCdpRuntimeIdentity runtimeIdentity,
        int brokerProcessId,
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
        long freshPresenceTimestamp,
        long issuedTimestamp,
        byte[] credentialId,
        byte[] subjectPublicKeyInfo,
        byte[] freshSessionId,
        byte[] leaseId)
    {
        _clock = clock;
        _guardianPeer = guardianPeer;
        _guardianIdentity = guardianIdentity;
        _runtimeLease = runtimeLease;
        _runtimeIdentity = runtimeIdentity;
        _brokerProcessId = brokerProcessId;
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
        _freshPresenceTimestamp = freshPresenceTimestamp;
        _issuedTimestamp = issuedTimestamp;
        _lastTimestamp = issuedTimestamp;
        _credentialId = credentialId;
        _subjectPublicKeyInfo = subjectPublicKeyInfo;
        _freshSessionId = freshSessionId;
        _leaseId = leaseId;
    }

    internal static TimeSpan MaximumLifetime { get; } = TimeSpan.FromSeconds(30);

    internal string BrokerEpoch => Read(_brokerEpoch);

    internal uint WindowsSessionId => Read(_windowsSessionId);

    internal Guid LedgerId => Read(_ledgerId);

    internal ulong LedgerRevision => Read(_ledgerRevision);

    internal string LedgerEntrySha256 => Read(_ledgerEntrySha256);

    internal Guid ReceiptId => Read(_receiptId);

    internal string GenerationSha256 => Read(_generationSha256);

    internal string Capability => Read(_capability);

    internal string CredentialPublicKeySha256 => Read(_credentialPublicKeySha256);

    internal string StatementSha256 => Read(_statementSha256);

    internal long FreshPresenceTimestamp => Read(_freshPresenceTimestamp);

    internal long IssuedTimestamp => Read(_issuedTimestamp);

    internal uint GuardianProcessId => Read(_guardianIdentity.ProcessId);

    internal string RuntimeId => Read(_runtimeIdentity.RuntimeId);

    internal int RuntimeProcessId => Read(_runtimeIdentity.ProcessId);

    internal byte[] FreshSessionId => Clone(_freshSessionId);

    internal byte[] LeaseId => Clone(_leaseId);

    internal static BrokerCapabilityLeaseV1 Create(
        BrokerFreshPresenceSessionV1 freshPresence,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        VerifiedGuardianManagedEntryConnectionV1 guardianPeer,
        CodexCdpBrokerSnapshot brokerSnapshot,
        ICodexCdpHandleLease runtimeLease) =>
        Create(
            freshPresence,
            ledgerSnapshot,
            generation,
            credential,
            guardianPeer,
            brokerSnapshot,
            runtimeLease,
            BrokerStopwatchCapabilityLeaseClockV1.Instance);

    internal static BrokerCapabilityLeaseV1 Create(
        BrokerFreshPresenceSessionV1 freshPresence,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        VerifiedGuardianManagedEntryConnectionV1 guardianPeer,
        CodexCdpBrokerSnapshot brokerSnapshot,
        ICodexCdpHandleLease runtimeLease,
        IBrokerCapabilityLeaseClockV1 clock)
    {
        ArgumentNullException.ThrowIfNull(freshPresence);
        ArgumentNullException.ThrowIfNull(ledgerSnapshot);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(guardianPeer);
        ArgumentNullException.ThrowIfNull(brokerSnapshot);
        ArgumentNullException.ThrowIfNull(runtimeLease);
        ArgumentNullException.ThrowIfNull(clock);

        var sessionGate = FreshSessionGates.GetValue(freshPresence, static _ => new object());
        lock (sessionGate)
        {
            byte[]? credentialId = null;
            byte[]? subjectPublicKeyInfo = null;
            byte[]? freshSessionId = null;
            byte[]? leaseId = null;
            try
            {
                RevalidateFreshPresence(
                    freshPresence,
                    brokerSnapshot.BrokerEpoch,
                    ledgerSnapshot,
                    generation,
                    credential);
                var guardianIdentity = CaptureGuardianIdentity(
                    guardianPeer,
                    freshPresence.WindowsSessionId);
                var runtimeIdentity = CaptureRuntimeIdentity(runtimeLease, brokerSnapshot);
                var issuedTimestamp = ReadTimestamp(clock);
                RequireWithinLifetime(
                    clock,
                    freshPresence.CreatedTimestamp,
                    issuedTimestamp);

                credentialId = freshPresence.CredentialId;
                subjectPublicKeyInfo = freshPresence.SubjectPublicKeyInfo;
                freshSessionId = freshPresence.SessionId;
                leaseId = RandomNumberGenerator.GetBytes(32);
                var result = new BrokerCapabilityLeaseV1(
                    clock,
                    guardianPeer,
                    guardianIdentity,
                    runtimeLease,
                    runtimeIdentity,
                    Environment.ProcessId,
                    freshPresence.BrokerEpoch,
                    freshPresence.WindowsSessionId,
                    freshPresence.LedgerId,
                    freshPresence.LedgerRevision,
                    freshPresence.LedgerEntrySha256,
                    freshPresence.ReceiptId,
                    freshPresence.GenerationSha256,
                    freshPresence.GenerationCanonicalJson,
                    freshPresence.Capability,
                    freshPresence.CredentialPublicKeySha256,
                    freshPresence.StatementSha256,
                    freshPresence.CreatedTimestamp,
                    issuedTimestamp,
                    credentialId,
                    subjectPublicKeyInfo,
                    freshSessionId,
                    leaseId);
                credentialId = null;
                subjectPublicKeyInfo = null;
                freshSessionId = null;
                leaseId = null;
                return result;
            }
            finally
            {
                Clear(credentialId);
                Clear(subjectPublicKeyInfo);
                Clear(freshSessionId);
                Clear(leaseId);
                freshPresence.Dispose();
                _ = FreshSessionGates.Remove(freshPresence);
            }
        }
    }

    internal void Consume(
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        VerifiedGuardianManagedEntryConnectionV1 guardianPeer,
        CodexCdpBrokerSnapshot brokerSnapshot,
        ICodexCdpHandleLease runtimeLease)
    {
        ArgumentNullException.ThrowIfNull(ledgerSnapshot);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(guardianPeer);
        ArgumentNullException.ThrowIfNull(brokerSnapshot);
        ArgumentNullException.ThrowIfNull(runtimeLease);

        lock (_gate)
        {
            if (_state != Active)
            {
                throw Fail(
                    "capability-lease-consumed",
                    "The Broker capability lease is no longer usable.");
            }

            _state = Consuming;
            try
            {
                RequireCurrentClock();
                if (Environment.ProcessId != _brokerProcessId)
                {
                    throw Fail(
                        "capability-broker-epoch-changed",
                        "The Broker process changed after capability issuance.");
                }

                if (!string.Equals(
                        brokerSnapshot.BrokerEpoch,
                        _brokerEpoch,
                        StringComparison.Ordinal))
                {
                    throw Fail(
                        "capability-broker-epoch-changed",
                        "The Broker epoch changed after capability issuance.");
                }

                ValidateBrokerEpochAndRuntimeSnapshot(brokerSnapshot, _runtimeIdentity);
                ValidateConsentContext(ledgerSnapshot, generation, credential);
                ValidateGuardianPeer(guardianPeer);
                ValidateRuntimeLease(runtimeLease, brokerSnapshot);
                RequireCurrentClock();
            }
            finally
            {
                ClearOwnedBytes();
                _state = Terminal;
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_state == Active)
            {
                ClearOwnedBytes();
                _state = Terminal;
            }
        }
    }

    private static void RevalidateFreshPresence(
        BrokerFreshPresenceSessionV1 freshPresence,
        string brokerEpoch,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        BrokerWebAuthnRegisteredCredentialV1 credential)
    {
        try
        {
            freshPresence.Revalidate(
                brokerEpoch,
                freshPresence.WindowsSessionId,
                ledgerSnapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                credential);
        }
        catch (BrokerUserPresenceVerificationException exception)
        {
            throw MapFreshPresenceFailure(exception);
        }
        catch (ObjectDisposedException exception)
        {
            throw Fail(
                "capability-fresh-presence-invalid",
                "The fresh-presence session is unavailable.",
                exception);
        }
    }

    private static WindowsProcessIdentity CaptureGuardianIdentity(
        VerifiedGuardianManagedEntryConnectionV1 guardianPeer,
        uint windowsSessionId)
    {
        if (guardianPeer.Completion.IsCompleted)
        {
            throw Fail(
                "capability-peer-changed",
                "An active authenticated Guardian peer is required.");
        }

        try
        {
            var identity = guardianPeer.Revalidate();
            if (guardianPeer.Completion.IsCompleted ||
                !IsExactProcessIdentity(guardianPeer.InitialIdentity, identity) ||
                identity.KernelSessionId != windowsSessionId ||
                identity.Token.SessionId != windowsSessionId)
            {
                throw Fail(
                    "capability-peer-changed",
                    "The authenticated Guardian peer identity does not match fresh presence.");
            }

            return identity;
        }
        catch (BrokerCapabilityLeaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Fail(
                "capability-peer-changed",
                "The authenticated Guardian peer could not be revalidated.",
                exception);
        }
    }

    private static CodexCdpRuntimeIdentity CaptureRuntimeIdentity(
        ICodexCdpHandleLease runtimeLease,
        CodexCdpBrokerSnapshot brokerSnapshot)
    {
        try
        {
            var identity = runtimeLease.Identity ?? throw new InvalidOperationException(
                "The managed runtime identity is missing.");
            if (!runtimeLease.IsAlive || runtimeLease.Exit.IsCompleted)
            {
                throw new InvalidOperationException("The managed runtime is not alive.");
            }

            ValidateBrokerEpochAndRuntimeSnapshot(brokerSnapshot, identity);
            if (!runtimeLease.IsAlive || runtimeLease.Exit.IsCompleted)
            {
                throw new InvalidOperationException(
                    "The managed runtime changed while ownership was captured.");
            }

            return identity;
        }
        catch (BrokerCapabilityLeaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Fail(
                "capability-runtime-changed",
                "The Broker-managed runtime ownership is unavailable.",
                exception);
        }
    }

    private static void ValidateBrokerEpochAndRuntimeSnapshot(
        CodexCdpBrokerSnapshot snapshot,
        CodexCdpRuntimeIdentity runtimeIdentity)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(snapshot.BrokerEpoch))
        {
            throw Fail(
                "capability-broker-epoch-changed",
                "The Broker epoch is invalid.");
        }

        if (snapshot.State != CodexCdpBrokerState.ManagedReady ||
            !snapshot.OwnsManagedCodex ||
            snapshot.ConnectedClients < 1 ||
            snapshot.RetirementIntent != CodexCdpBrokerRetirementIntent.None ||
            snapshot.BrokerExitIntent ||
            snapshot.ManagedCodexExitIntent ||
            !string.Equals(
                snapshot.ActiveLaunchOperationId,
                runtimeIdentity.LaunchOperationId,
                StringComparison.Ordinal))
        {
            throw Fail(
                "capability-runtime-changed",
                "The Broker no longer owns the exact managed-ready runtime.");
        }
    }

    private void ValidateConsentContext(
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        BrokerWebAuthnRegisteredCredentialV1 credential)
    {
        BrokerConsentGrantEntryV1 grantEntry;
        BrokerFreshPresenceValidationV1.GenerationIdentity generationIdentity;
        try
        {
            grantEntry = BrokerFreshPresenceValidationV1.RequirePendingSnapshot(ledgerSnapshot);
            generationIdentity = BrokerFreshPresenceValidationV1.RequireGeneration(
                generation,
                grantEntry);
        }
        catch (BrokerUserPresenceVerificationException exception)
        {
            throw MapFreshPresenceFailure(exception);
        }

        var grant = ledgerSnapshot.Primary!;
        var receipt = grantEntry.Receipt;
        if (grant.LedgerId != _ledgerId ||
            grant.Revision != _ledgerRevision ||
            !string.Equals(grant.EntrySha256, _ledgerEntrySha256, StringComparison.Ordinal) ||
            receipt.ReceiptId != _receiptId ||
            !string.Equals(grantEntry.GenerationSha256, _generationSha256, StringComparison.Ordinal) ||
            !string.Equals(receipt.CredentialIdBase64, Convert.ToBase64String(_credentialId), StringComparison.Ordinal) ||
            !string.Equals(receipt.CredentialPublicKeySha256, _credentialPublicKeySha256, StringComparison.Ordinal))
        {
            throw Fail(
                "capability-ledger-head-changed",
                "The exact consent-ledger head changed after capability issuance.");
        }

        if (!string.Equals(generationIdentity.Sha256, _generationSha256, StringComparison.Ordinal) ||
            !string.Equals(
                generationIdentity.CanonicalJson,
                _generationCanonicalJson,
                StringComparison.Ordinal))
        {
            throw Fail(
                "capability-package-generation-changed",
                "The exact Codex package generation changed after capability issuance.");
        }

        byte[]? currentCredentialId = null;
        byte[]? currentSubjectPublicKeyInfo = null;
        try
        {
            currentCredentialId = credential.CredentialId;
            currentSubjectPublicKeyInfo = credential.SubjectPublicKeyInfo;
            var currentPublicKeySha256 =
                Convert.ToHexString(SHA256.HashData(currentSubjectPublicKeyInfo));
            if (!CryptographicOperations.FixedTimeEquals(currentCredentialId, _credentialId) ||
                !CryptographicOperations.FixedTimeEquals(
                    currentSubjectPublicKeyInfo,
                    _subjectPublicKeyInfo) ||
                !string.Equals(
                    credential.SubjectPublicKeyInfoSha256,
                    currentPublicKeySha256,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    currentPublicKeySha256,
                    _credentialPublicKeySha256,
                    StringComparison.Ordinal))
            {
                throw Fail(
                    "capability-credential-changed",
                    "The registered user-presence credential changed after capability issuance.");
            }
        }
        catch (BrokerCapabilityLeaseException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ObjectDisposedException or CryptographicException)
        {
            throw Fail(
                "capability-credential-changed",
                "The registered user-presence credential is unavailable.",
                exception);
        }
        finally
        {
            Clear(currentCredentialId);
            Clear(currentSubjectPublicKeyInfo);
        }
    }

    private void ValidateGuardianPeer(VerifiedGuardianManagedEntryConnectionV1 guardianPeer)
    {
        if (!ReferenceEquals(guardianPeer, _guardianPeer) ||
            guardianPeer.Completion.IsCompleted)
        {
            throw Fail(
                "capability-peer-changed",
                "The authenticated Guardian peer changed after capability issuance.");
        }

        try
        {
            var identity = guardianPeer.Revalidate();
            if (guardianPeer.Completion.IsCompleted ||
                !IsExactProcessIdentity(_guardianIdentity, identity) ||
                identity.KernelSessionId != _windowsSessionId ||
                identity.Token.SessionId != _windowsSessionId)
            {
                throw Fail(
                    "capability-peer-changed",
                    "The authenticated Guardian peer identity drifted.");
            }
        }
        catch (BrokerCapabilityLeaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Fail(
                "capability-peer-changed",
                "The authenticated Guardian peer revalidation failed closed.",
                exception);
        }
    }

    private void ValidateRuntimeLease(
        ICodexCdpHandleLease runtimeLease,
        CodexCdpBrokerSnapshot brokerSnapshot)
    {
        if (!ReferenceEquals(runtimeLease, _runtimeLease))
        {
            throw Fail(
                "capability-runtime-changed",
                "The managed runtime ownership handle changed.");
        }

        try
        {
            if (!runtimeLease.IsAlive || runtimeLease.Exit.IsCompleted ||
                !IsExactRuntimeIdentity(_runtimeIdentity, runtimeLease.Identity))
            {
                throw Fail(
                    "capability-runtime-changed",
                    "The exact Broker-managed runtime changed.");
            }

            ValidateBrokerEpochAndRuntimeSnapshot(brokerSnapshot, _runtimeIdentity);
            if (!string.Equals(brokerSnapshot.BrokerEpoch, _brokerEpoch, StringComparison.Ordinal) ||
                !runtimeLease.IsAlive || runtimeLease.Exit.IsCompleted)
            {
                throw Fail(
                    "capability-runtime-changed",
                    "The managed runtime ownership changed during validation.");
            }
        }
        catch (BrokerCapabilityLeaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Fail(
                "capability-runtime-changed",
                "The managed runtime ownership revalidation failed closed.",
                exception);
        }
    }

    private void RequireCurrentClock()
    {
        var current = ReadTimestamp(_clock);
        if (current < _lastTimestamp)
        {
            throw Fail(
                "capability-clock-invalid",
                "The monotonic capability clock moved backwards.");
        }

        RequireWithinLifetime(_clock, _freshPresenceTimestamp, current);
        _lastTimestamp = current;
    }

    private static long ReadTimestamp(IBrokerCapabilityLeaseClockV1 clock)
    {
        try
        {
            var timestamp = clock.GetTimestamp();
            if (timestamp <= 0)
            {
                throw new InvalidOperationException(
                    "The monotonic capability timestamp is not positive.");
            }

            return timestamp;
        }
        catch (BrokerCapabilityLeaseException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Fail(
                "capability-clock-invalid",
                "The monotonic capability clock is unavailable.",
                exception);
        }
    }

    private static void RequireWithinLifetime(
        IBrokerCapabilityLeaseClockV1 clock,
        long startingTimestamp,
        long endingTimestamp)
    {
        if (startingTimestamp <= 0 || endingTimestamp < startingTimestamp)
        {
            throw Fail(
                "capability-clock-invalid",
                "The monotonic capability clock is inconsistent.");
        }

        TimeSpan elapsed;
        try
        {
            elapsed = clock.GetElapsedTime(startingTimestamp, endingTimestamp);
        }
        catch (Exception exception)
        {
            throw Fail(
                "capability-clock-invalid",
                "The monotonic capability duration could not be measured.",
                exception);
        }

        if (elapsed < TimeSpan.Zero)
        {
            throw Fail(
                "capability-clock-invalid",
                "The monotonic capability duration is negative.");
        }

        if (elapsed > MaximumLifetime)
        {
            throw Fail(
                "capability-lease-expired",
                "The Broker capability lease expired.");
        }
    }

    private static bool IsExactRuntimeIdentity(
        CodexCdpRuntimeIdentity expected,
        CodexCdpRuntimeIdentity actual) =>
        string.Equals(expected.RuntimeId, actual.RuntimeId, StringComparison.Ordinal) &&
        string.Equals(
            expected.LaunchOperationId,
            actual.LaunchOperationId,
            StringComparison.Ordinal) &&
        expected.ProcessId == actual.ProcessId &&
        expected.CreationTimeUtc == actual.CreationTimeUtc;

    private static bool IsExactProcessIdentity(
        WindowsProcessIdentity expected,
        WindowsProcessIdentity actual) =>
        expected.ProcessId == actual.ProcessId &&
        expected.CreationTimeUtc == actual.CreationTimeUtc &&
        expected.KernelSessionId == actual.KernelSessionId &&
        Equals(expected.Token, actual.Token) &&
        Equals(expected.AppModel, actual.AppModel) &&
        string.Equals(expected.FinalImagePath, actual.FinalImagePath, StringComparison.Ordinal) &&
        expected.ImageFileObjectIsExact == actual.ImageFileObjectIsExact &&
        Equals(expected.ReleaseRoot, actual.ReleaseRoot) &&
        expected.Artifacts.SequenceEqual(actual.Artifacts);

    private static BrokerCapabilityLeaseException MapFreshPresenceFailure(
        BrokerUserPresenceVerificationException exception) =>
        exception.Code switch
        {
            "consent-broker-epoch-changed" => Fail(
                "capability-broker-epoch-changed",
                "The Broker epoch changed after fresh presence.",
                exception),
            "consent-windows-session-changed" => Fail(
                "capability-windows-session-changed",
                "The Windows session changed after fresh presence.",
                exception),
            "consent-ledger-head-changed" => Fail(
                "capability-ledger-head-changed",
                "The consent-ledger head changed after fresh presence.",
                exception),
            "consent-package-generation-changed" => Fail(
                "capability-package-generation-changed",
                "The Codex package generation changed after fresh presence.",
                exception),
            "user-presence-credential-invalid" => Fail(
                "capability-credential-changed",
                "The registered user-presence credential changed.",
                exception),
            _ => Fail(
                "capability-fresh-presence-invalid",
                "The fresh-presence session cannot issue a capability lease.",
                exception)
        };

    private static BrokerCapabilityLeaseException Fail(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private T Read<T>(T value)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_state != Active, this);
            return value;
        }
    }

    private byte[] Clone(byte[] value)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_state != Active, this);
            return (byte[])value.Clone();
        }
    }

    private void ClearOwnedBytes()
    {
        Clear(_credentialId);
        Clear(_subjectPublicKeyInfo);
        Clear(_freshSessionId);
        Clear(_leaseId);
    }

    private static void Clear(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
