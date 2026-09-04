using CodexGuardian.Control;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal interface IWebAuthnPlatformV1
{
    ValueTask<WebAuthnRegistrationEvidenceV1> RegisterPlatformCredentialAsync(
        FrozenWebAuthnRegistrationRequestV1 request,
        BrokerOwnedWindowHandle owner,
        CancellationToken cancellationToken);

    ValueTask<WebAuthnAssertionEvidenceV1> GetAssertionAsync(
        FrozenWebAuthnAssertionRequestV1 request,
        BrokerOwnedWindowHandle owner,
        CancellationToken cancellationToken);
}

internal sealed class BrokerOwnedWindowHandle
{
    private readonly BrokerOwnedWindowV1? _ownedWindow;

    private BrokerOwnedWindowHandle(
        nint value,
        int ownerProcessId,
        int ownerThreadId,
        BrokerOwnedWindowV1? ownedWindow)
    {
        Value = value;
        OwnerProcessId = ownerProcessId;
        OwnerThreadId = ownerThreadId;
        _ownedWindow = ownedWindow;
    }

    internal nint Value { get; }

    internal int OwnerProcessId { get; }

    internal int OwnerThreadId { get; }

    internal static BrokerOwnedWindowHandle Create(
        nint value,
        int ownerProcessId,
        int ownerThreadId)
    {
        if (value == nint.Zero ||
            ownerProcessId != Environment.ProcessId ||
            ownerThreadId <= 0)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-window-invalid",
                "The Broker-owned window identity is invalid.");
        }

        return new BrokerOwnedWindowHandle(value, ownerProcessId, ownerThreadId, ownedWindow: null);
    }

    internal static BrokerOwnedWindowHandle CreateOwned(
        nint value,
        int ownerProcessId,
        int ownerThreadId,
        BrokerOwnedWindowV1 ownedWindow)
    {
        ArgumentNullException.ThrowIfNull(ownedWindow);
        var handle = Create(value, ownerProcessId, ownerThreadId);
        return new BrokerOwnedWindowHandle(
            handle.Value,
            handle.OwnerProcessId,
            handle.OwnerThreadId,
            ownedWindow);
    }

    internal BrokerOwnedWindowV1 RequireOwnedWindow()
    {
        var ownedWindow = _ownedWindow;
        if (ownedWindow is null)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-window-invalid",
                "The WebAuthn operation requires a live Broker-owned window.");
        }

        ownedWindow.ValidateForCurrentProcess();
        if (!ReferenceEquals(ownedWindow.Handle, this))
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-window-invalid",
                "The Broker-owned window handle does not match its owner.");
        }

        return ownedWindow;
    }

    internal bool ContentEquals(BrokerOwnedWindowHandle other) =>
        other is not null &&
        Value == other.Value &&
        OwnerProcessId == other.OwnerProcessId &&
        OwnerThreadId == other.OwnerThreadId;
}

internal sealed class FrozenWebAuthnRegistrationRequestV1 : IDisposable
{
    private const string UserHandleDomainSeparator =
        "CodexGuardian\0WindowsUserHandle\0v1\0";
    private const string GenericUserName = "codexguardian-user";
    private const string GenericUserDisplayName = "CodexGuardian User";
    private const int MaximumWindowsSidCharacters = 256;

    private readonly string _brokerEpoch;
    private readonly uint _windowsSessionId;
    private readonly string _challengeBase64Url;
    private readonly string _registrationStatementSha256;
    private readonly byte[] _derivedUserHandle;
    private readonly byte[] _registrationNonce;
    private readonly byte[] _registrationStatementBytes;
    private readonly byte[] _relyingPartyIdHash;
    private readonly byte[] _challengeBytes;
    private readonly byte[] _clientDataJson;
    private readonly byte[] _clientDataHash;
    private int _disposed;

    private FrozenWebAuthnRegistrationRequestV1(
        string brokerEpoch,
        uint windowsSessionId,
        string challengeBase64Url,
        string registrationStatementSha256,
        byte[] derivedUserHandle,
        byte[] registrationNonce,
        byte[] registrationStatementBytes,
        byte[] relyingPartyIdHash,
        byte[] challengeBytes,
        byte[] clientDataJson,
        byte[] clientDataHash)
    {
        _brokerEpoch = brokerEpoch;
        _windowsSessionId = windowsSessionId;
        _challengeBase64Url = challengeBase64Url;
        _registrationStatementSha256 = registrationStatementSha256;
        _derivedUserHandle = derivedUserHandle;
        _registrationNonce = registrationNonce;
        _registrationStatementBytes = registrationStatementBytes;
        _relyingPartyIdHash = relyingPartyIdHash;
        _challengeBytes = challengeBytes;
        _clientDataJson = clientDataJson;
        _clientDataHash = clientDataHash;
    }

    internal string BrokerEpoch => Read(_brokerEpoch);

    internal uint WindowsSessionId => Read(_windowsSessionId);

    internal string RelyingPartyId => Read(BrokerWebAuthnConstantsV1.RelyingPartyId);

    internal string RelyingPartyDisplayName =>
        Read(BrokerWebAuthnConstantsV1.RelyingPartyDisplayName);

    internal string Origin => Read(BrokerWebAuthnConstantsV1.Origin);

    internal string CredentialType => Read(BrokerWebAuthnConstantsV1.CredentialType);

    internal string ClientDataType => Read(BrokerWebAuthnConstantsV1.RegistrationClientDataType);

    internal string AuthenticatorAttachment => Read(BrokerWebAuthnConstantsV1.PlatformAttachment);

    internal string UserVerification => Read(BrokerWebAuthnConstantsV1.UserVerification);

    internal string ResidentKey => Read(BrokerWebAuthnConstantsV1.ResidentKey);

    internal string Attestation => Read(BrokerWebAuthnConstantsV1.Attestation);

    internal int Algorithm => Read(BrokerWebAuthnConstantsV1.Es256Algorithm);

    internal bool ExtensionsEnabled => Read(false);

    internal string UserName => Read(GenericUserName);

    internal string UserDisplayName => Read(GenericUserDisplayName);

    internal string ChallengeBase64Url => Read(_challengeBase64Url);

    internal string RegistrationStatementSha256 => Read(_registrationStatementSha256);

    internal byte[] DerivedUserHandle => Clone(_derivedUserHandle);

    internal byte[] RegistrationNonce => Clone(_registrationNonce);

    internal byte[] RegistrationStatementBytes => Clone(_registrationStatementBytes);

    internal byte[] RelyingPartyIdHash => Clone(_relyingPartyIdHash);

    internal byte[] ChallengeBytes => Clone(_challengeBytes);

    internal byte[] ClientDataJson => Clone(_clientDataJson);

    internal byte[] ClientDataHash => Clone(_clientDataHash);

    internal static FrozenWebAuthnRegistrationRequestV1 Create(
        string brokerEpoch,
        uint windowsSessionId,
        string currentWindowsSid,
        ReadOnlySpan<byte> registrationNonce)
    {
        ArgumentNullException.ThrowIfNull(brokerEpoch);
        ArgumentNullException.ThrowIfNull(currentWindowsSid);
        if (!BrokerFreshPresenceValidationV1.IsExactBrokerEpoch(brokerEpoch))
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-broker-epoch-changed",
                "The registration request Broker epoch is invalid.");
        }

        if (windowsSessionId == 0)
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-windows-session-changed",
                "The registration request Windows session is invalid.");
        }

        if (currentWindowsSid.Length is < 5 or > MaximumWindowsSidCharacters ||
            !currentWindowsSid.StartsWith("S-1-", StringComparison.Ordinal) ||
            currentWindowsSid.Any(character => character > 0x7F))
        {
            throw new ArgumentException(
                "The current Windows SID is not a bounded canonical SID string.",
                nameof(currentWindowsSid));
        }

        if (registrationNonce.Length != 32)
        {
            throw new ArgumentException(
                "The registration nonce must contain exactly 32 bytes.",
                nameof(registrationNonce));
        }

        byte[]? sidBytes = null;
        byte[]? userHandleDomain = null;
        byte[]? userHandleInput = null;
        byte[]? derivedUserHandle = null;
        byte[]? ownedRegistrationNonce = null;
        byte[]? registrationStatementBytes = null;
        byte[]? relyingPartyIdHash = null;
        byte[]? challengeBytes = null;
        byte[]? clientDataJson = null;
        byte[]? clientDataHash = null;
        try
        {
            sidBytes = Encoding.UTF8.GetBytes(currentWindowsSid);
            userHandleDomain = Encoding.ASCII.GetBytes(UserHandleDomainSeparator);
            userHandleInput = new byte[checked(userHandleDomain.Length + sidBytes.Length)];
            userHandleDomain.CopyTo(userHandleInput, 0);
            sidBytes.CopyTo(userHandleInput, userHandleDomain.Length);
            derivedUserHandle = SHA256.HashData(userHandleInput);
            ownedRegistrationNonce = registrationNonce.ToArray();
            registrationStatementBytes = WriteRegistrationStatement(
                brokerEpoch,
                windowsSessionId,
                Convert.ToHexString(derivedUserHandle),
                Convert.ToBase64String(ownedRegistrationNonce));
            relyingPartyIdHash = SHA256.HashData(
                Encoding.ASCII.GetBytes(BrokerWebAuthnConstantsV1.RelyingPartyId));
            var clientData = BrokerWebAuthnRequestEncodingV1.CreateClientData(
                BrokerWebAuthnConstantsV1.RegistrationDomainSeparator,
                BrokerWebAuthnConstantsV1.RegistrationClientDataType,
                registrationStatementBytes);
            challengeBytes = clientData.ChallengeBytes;
            clientDataJson = clientData.ClientDataJson;
            clientDataHash = clientData.ClientDataHash;
            var result = new FrozenWebAuthnRegistrationRequestV1(
                brokerEpoch,
                windowsSessionId,
                clientData.ChallengeBase64Url,
                Convert.ToHexString(SHA256.HashData(registrationStatementBytes)),
                derivedUserHandle,
                ownedRegistrationNonce,
                registrationStatementBytes,
                relyingPartyIdHash,
                challengeBytes,
                clientDataJson,
                clientDataHash);
            derivedUserHandle = null;
            ownedRegistrationNonce = null;
            registrationStatementBytes = null;
            relyingPartyIdHash = null;
            challengeBytes = null;
            clientDataJson = null;
            clientDataHash = null;
            return result;
        }
        finally
        {
            BrokerWebAuthnPlatformValidationV1.Clear(sidBytes);
            BrokerWebAuthnPlatformValidationV1.Clear(userHandleDomain);
            BrokerWebAuthnPlatformValidationV1.Clear(userHandleInput);
            BrokerWebAuthnPlatformValidationV1.Clear(derivedUserHandle);
            BrokerWebAuthnPlatformValidationV1.Clear(ownedRegistrationNonce);
            BrokerWebAuthnPlatformValidationV1.Clear(registrationStatementBytes);
            BrokerWebAuthnPlatformValidationV1.Clear(relyingPartyIdHash);
            BrokerWebAuthnPlatformValidationV1.Clear(challengeBytes);
            BrokerWebAuthnPlatformValidationV1.Clear(clientDataJson);
            BrokerWebAuthnPlatformValidationV1.Clear(clientDataHash);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        BrokerWebAuthnPlatformValidationV1.Clear(_derivedUserHandle);
        BrokerWebAuthnPlatformValidationV1.Clear(_registrationNonce);
        BrokerWebAuthnPlatformValidationV1.Clear(_registrationStatementBytes);
        BrokerWebAuthnPlatformValidationV1.Clear(_relyingPartyIdHash);
        BrokerWebAuthnPlatformValidationV1.Clear(_challengeBytes);
        BrokerWebAuthnPlatformValidationV1.Clear(_clientDataJson);
        BrokerWebAuthnPlatformValidationV1.Clear(_clientDataHash);
    }

    private static byte[] WriteRegistrationStatement(
        string brokerEpoch,
        uint windowsSessionId,
        string userHandleSha256,
        string registrationNonceBase64)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = BrokerWebAuthnRequestEncodingV1.CreateWriter(buffer);
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

internal enum BrokerWebAuthnAssertionRequestPurposeV1
{
    Consent,
    FreshPresence
}

internal sealed class FrozenWebAuthnAssertionRequestV1 : IDisposable
{
    private readonly BrokerWebAuthnAssertionRequestPurposeV1 _purpose;
    private readonly string _challengeBase64Url;
    private readonly string _credentialPublicKeySha256;
    private readonly byte[] _credentialId;
    private readonly byte[] _challengeBytes;
    private readonly byte[] _clientDataJson;
    private readonly byte[] _clientDataHash;
    private int _disposed;

    private FrozenWebAuthnAssertionRequestV1(
        BrokerWebAuthnAssertionRequestPurposeV1 purpose,
        string challengeBase64Url,
        string credentialPublicKeySha256,
        byte[] credentialId,
        byte[] challengeBytes,
        byte[] clientDataJson,
        byte[] clientDataHash)
    {
        _purpose = purpose;
        _challengeBase64Url = challengeBase64Url;
        _credentialPublicKeySha256 = credentialPublicKeySha256;
        _credentialId = credentialId;
        _challengeBytes = challengeBytes;
        _clientDataJson = clientDataJson;
        _clientDataHash = clientDataHash;
    }

    internal BrokerWebAuthnAssertionRequestPurposeV1 Purpose => Read(_purpose);

    internal string RelyingPartyId => Read(BrokerWebAuthnConstantsV1.RelyingPartyId);

    internal string Origin => Read(BrokerWebAuthnConstantsV1.Origin);

    internal string CredentialType => Read(BrokerWebAuthnConstantsV1.CredentialType);

    internal string ClientDataType => Read(BrokerWebAuthnConstantsV1.AssertionClientDataType);

    internal string UserVerification => Read(BrokerWebAuthnConstantsV1.UserVerification);

    internal int Algorithm => Read(BrokerWebAuthnConstantsV1.Es256Algorithm);

    internal bool ExtensionsEnabled => Read(false);

    internal string ChallengeBase64Url => Read(_challengeBase64Url);

    internal string CredentialPublicKeySha256 => Read(_credentialPublicKeySha256);

    internal byte[] CredentialId => Clone(_credentialId);

    internal byte[] ChallengeBytes => Clone(_challengeBytes);

    internal byte[] ClientDataJson => Clone(_clientDataJson);

    internal byte[] ClientDataHash => Clone(_clientDataHash);

    internal static FrozenWebAuthnAssertionRequestV1 CreateConsent(
        BrokerConsentGrantDraftV1 draft,
        BrokerWebAuthnRegisteredCredentialV1 credential)
    {
        ArgumentNullException.ThrowIfNull(draft);
        return Create(
            BrokerWebAuthnAssertionRequestPurposeV1.Consent,
            BrokerWebAuthnConstantsV1.ConsentDomainSeparator,
            draft.ConsentStatementBytes,
            draft.CredentialId,
            draft.StatementFields.CredentialPublicKeySha256,
            credential);
    }

    internal static FrozenWebAuthnAssertionRequestV1 CreateFresh(
        BrokerFreshPresenceStatementV1 statement,
        BrokerWebAuthnRegisteredCredentialV1 credential)
    {
        ArgumentNullException.ThrowIfNull(statement);
        return Create(
            BrokerWebAuthnAssertionRequestPurposeV1.FreshPresence,
            BrokerWebAuthnConstantsV1.FreshPresenceDomainSeparator,
            statement.CanonicalStatementBytes,
            statement.CredentialId,
            statement.CredentialPublicKeySha256,
            credential);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        BrokerWebAuthnPlatformValidationV1.Clear(_credentialId);
        BrokerWebAuthnPlatformValidationV1.Clear(_challengeBytes);
        BrokerWebAuthnPlatformValidationV1.Clear(_clientDataJson);
        BrokerWebAuthnPlatformValidationV1.Clear(_clientDataHash);
    }

    private static FrozenWebAuthnAssertionRequestV1 Create(
        BrokerWebAuthnAssertionRequestPurposeV1 purpose,
        string domainSeparator,
        byte[] canonicalStatementBytes,
        byte[] expectedCredentialId,
        string expectedCredentialPublicKeySha256,
        BrokerWebAuthnRegisteredCredentialV1 credential)
    {
        ArgumentNullException.ThrowIfNull(canonicalStatementBytes);
        ArgumentNullException.ThrowIfNull(expectedCredentialId);
        ArgumentNullException.ThrowIfNull(expectedCredentialPublicKeySha256);
        ArgumentNullException.ThrowIfNull(credential);
        byte[]? credentialId = null;
        byte[]? subjectPublicKeyInfo = null;
        byte[]? challengeBytes = null;
        byte[]? clientDataJson = null;
        byte[]? clientDataHash = null;
        try
        {
            credentialId = credential.CredentialId;
            subjectPublicKeyInfo = credential.SubjectPublicKeyInfo;
            var actualSubjectPublicKeyInfoSha256 =
                Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
            if (!CryptographicOperations.FixedTimeEquals(
                    credentialId,
                    expectedCredentialId) ||
                !string.Equals(
                    credential.SubjectPublicKeyInfoSha256,
                    actualSubjectPublicKeyInfoSha256,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    actualSubjectPublicKeyInfoSha256,
                    expectedCredentialPublicKeySha256,
                    StringComparison.Ordinal))
            {
                throw new BrokerUserPresenceVerificationException(
                    "user-presence-credential-invalid",
                    "The registered credential does not match the frozen assertion request.");
            }

            var clientData = BrokerWebAuthnRequestEncodingV1.CreateClientData(
                domainSeparator,
                BrokerWebAuthnConstantsV1.AssertionClientDataType,
                canonicalStatementBytes);
            challengeBytes = clientData.ChallengeBytes;
            clientDataJson = clientData.ClientDataJson;
            clientDataHash = clientData.ClientDataHash;
            var result = new FrozenWebAuthnAssertionRequestV1(
                purpose,
                clientData.ChallengeBase64Url,
                actualSubjectPublicKeyInfoSha256,
                credentialId,
                challengeBytes,
                clientDataJson,
                clientDataHash);
            credentialId = null;
            challengeBytes = null;
            clientDataJson = null;
            clientDataHash = null;
            return result;
        }
        finally
        {
            BrokerWebAuthnPlatformValidationV1.Clear(canonicalStatementBytes);
            BrokerWebAuthnPlatformValidationV1.Clear(expectedCredentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(credentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(subjectPublicKeyInfo);
            BrokerWebAuthnPlatformValidationV1.Clear(challengeBytes);
            BrokerWebAuthnPlatformValidationV1.Clear(clientDataJson);
            BrokerWebAuthnPlatformValidationV1.Clear(clientDataHash);
        }
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

internal sealed class WebAuthnRegistrationEvidenceV1 : IDisposable
{
    private const int MaximumClientDataBytes = 4096;
    private const int MaximumCredentialIdBytes = 1024;
    private const int MaximumAuthenticatorDataBytes = 4096;
    private const int MaximumSignatureBytes = 4096;
    private const int MaximumUserHandleBytes = 1024;

    private readonly byte[] _clientDataJson;
    private readonly byte[] _credentialId;
    private readonly byte[] _authenticatorData;
    private readonly byte[] _nativeSignature;
    private readonly byte[]? _userHandle;
    private int _disposed;

    private WebAuthnRegistrationEvidenceV1(
        byte[] clientDataJson,
        byte[] credentialId,
        byte[] authenticatorData,
        byte[] nativeSignature,
        byte[]? userHandle)
    {
        _clientDataJson = clientDataJson;
        _credentialId = credentialId;
        _authenticatorData = authenticatorData;
        _nativeSignature = nativeSignature;
        _userHandle = userHandle;
    }

    internal byte[] ClientDataJson => Clone(_clientDataJson);

    internal byte[] CredentialId => Clone(_credentialId);

    internal byte[] AuthenticatorData => Clone(_authenticatorData);

    internal byte[] NativeSignature => Clone(_nativeSignature);

    internal byte[]? UserHandle => _userHandle is null ? null : Clone(_userHandle);

    internal static WebAuthnRegistrationEvidenceV1 Create(
        ReadOnlySpan<byte> clientDataJson,
        ReadOnlySpan<byte> credentialId,
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> nativeSignature,
        byte[]? userHandle)
    {
        RequireBound(clientDataJson.Length, 1, MaximumClientDataBytes, nameof(clientDataJson));
        RequireBound(credentialId.Length, 1, MaximumCredentialIdBytes, nameof(credentialId));
        RequireBound(
            authenticatorData.Length,
            1,
            MaximumAuthenticatorDataBytes,
            nameof(authenticatorData));
        RequireBound(nativeSignature.Length, 0, MaximumSignatureBytes, nameof(nativeSignature));
        if (userHandle is not null)
        {
            RequireBound(userHandle.Length, 1, MaximumUserHandleBytes, nameof(userHandle));
        }

        return new WebAuthnRegistrationEvidenceV1(
            clientDataJson.ToArray(),
            credentialId.ToArray(),
            authenticatorData.ToArray(),
            nativeSignature.ToArray(),
            userHandle is null ? null : (byte[])userHandle.Clone());
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        BrokerWebAuthnPlatformValidationV1.Clear(_clientDataJson);
        BrokerWebAuthnPlatformValidationV1.Clear(_credentialId);
        BrokerWebAuthnPlatformValidationV1.Clear(_authenticatorData);
        BrokerWebAuthnPlatformValidationV1.Clear(_nativeSignature);
        BrokerWebAuthnPlatformValidationV1.Clear(_userHandle);
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
            throw new ArgumentException(
                "WebAuthn registration evidence is outside its bound.",
                parameterName);
        }
    }
}

internal readonly record struct WindowsWebAuthnCapabilityV1(
    uint ApiVersion,
    bool PlatformAuthenticatorAvailable);

internal readonly record struct WindowsWebAuthnInteractiveProbeResultV1(
    uint ApiVersion,
    bool PlatformAuthenticatorAvailable,
    bool WindowValidated,
    bool RegistrationVerified,
    bool AssertionVerified);

internal sealed class WindowsWebAuthnPlatformV1 : IWebAuthnPlatformV1
{
    private const uint MinimumConstrainedApiVersion = 3;
    private const uint MaximumReasonableApiVersion = 1024;
    private const uint NativeStructureVersionOne = 1;
    private const uint MakeCredentialOptionsVersionFour = 4;
    private const uint GetAssertionOptionsVersionThree = 3;
    private const uint AuthenticatorAttachmentPlatform = 1;
    private const uint UserVerificationRequired = 1;
    private const uint AttestationNone = 1;
    private const uint EnterpriseAttestationNone = 0;
    private const uint LargeBlobSupportNone = 0;
    private const uint OperationTimeoutMilliseconds = 300_000;
    private const int Es256Algorithm = -7;
    private const int MaximumCredentialIdBytes = 1024;
    private const int MaximumAuthenticatorDataBytes = 4096;
    private const int MaximumAssertionSignatureBytes = 128;
    private const int MaximumUserHandleBytes = 1024;
    private const int HResultCancelled = unchecked((int)0x800704C7);
    private const int HResultTimeout = unchecked((int)0x800705B4);
    private const int NteNotFound = unchecked((int)0x80090011);
    private const int NteDeviceNotFound = unchecked((int)0x80090030);
    private const int NteUserCancelled = unchecked((int)0x80090036);
    private const string InteractiveProbeDomainSeparator =
        "CodexGuardian\0WebAuthnInteractiveProbe\0v1\0";
    private const string InteractiveProbeStatementSchema =
        "codex-broker-webauthn-interactive-probe-v1";

    ValueTask<WebAuthnRegistrationEvidenceV1>
        IWebAuthnPlatformV1.RegisterPlatformCredentialAsync(
            FrozenWebAuthnRegistrationRequestV1 request,
            BrokerOwnedWindowHandle owner,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(owner);
        cancellationToken.ThrowIfCancellationRequested();
        RequireRegistrationPolicy(request);
        var window = owner.RequireOwnedWindow();
        window.UpdateTransactionSummary(BrokerOwnedWindowV1.RegistrationSummary);
        return window.InvokeOnOwnerThreadAsync(
            () =>
            {
                EnsureOwnerThread(owner);
                window.ValidateForCurrentProcess();
                return RegisterCore(request, owner.Value, cancellationToken);
            },
            cancellationToken);
    }

    ValueTask<WebAuthnAssertionEvidenceV1> IWebAuthnPlatformV1.GetAssertionAsync(
        FrozenWebAuthnAssertionRequestV1 request,
        BrokerOwnedWindowHandle owner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(owner);
        cancellationToken.ThrowIfCancellationRequested();
        RequireAssertionPolicy(request);
        var window = owner.RequireOwnedWindow();
        window.UpdateTransactionSummary(BrokerOwnedWindowV1.AssertionSummary);
        return window.InvokeOnOwnerThreadAsync(
            () =>
            {
                EnsureOwnerThread(owner);
                window.ValidateForCurrentProcess();
                return GetAssertionCore(request, owner.Value, cancellationToken);
            },
            cancellationToken);
    }

    internal static WindowsWebAuthnCapabilityV1 ProbeCapability()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw PlatformUnavailable("Windows WebAuthn is unavailable on this platform.");
        }

        try
        {
            var apiVersion = WebAuthNGetApiVersionNumber();
            if (apiVersion == 0 || apiVersion > MaximumReasonableApiVersion)
            {
                throw PlatformUnavailable("Windows WebAuthn returned an invalid API version.");
            }

            var result = WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
                out var available);
            ThrowForHResult(
                result,
                CancellationToken.None,
                "the platform-authenticator capability probe");
            if (available is not 0 and not 1)
            {
                throw NativeFailure(
                    "Windows WebAuthn returned an invalid platform-authenticator state.");
            }

            return new WindowsWebAuthnCapabilityV1(apiVersion, available == 1);
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or
                EntryPointNotFoundException or
                BadImageFormatException)
        {
            throw PlatformUnavailable(
                "The Windows WebAuthn platform API is unavailable.",
                exception);
        }
    }

    internal static async ValueTask<WindowsWebAuthnInteractiveProbeResultV1>
        RunInteractiveProbeAsync(
            BrokerOwnedWindowV1 window,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(window);
        cancellationToken.ThrowIfCancellationRequested();
        var capability = RequireSupportedCapability();
        window.ValidateForCurrentProcess();

        var registrationNonce = RandomNumberGenerator.GetBytes(32);
        var brokerEpoch = Convert.ToHexString(RandomNumberGenerator.GetBytes(16))
            .ToLowerInvariant();
        var sessionId = GetCurrentWindowsSessionId();
        var sid = GetCurrentWindowsSid();
        var adapter = new WindowsWebAuthnPlatformV1();
        byte[]? registrationAuthenticatorData = null;
        byte[]? registrationCredentialId = null;
        byte[]? relyingPartyIdHash = null;
        byte[]? probeNonce = null;
        byte[]? probeStatement = null;
        byte[]? assertionClientDataJson = null;
        byte[]? assertionClientDataHash = null;
        byte[]? assertionCredentialId = null;
        byte[]? assertionAuthenticatorData = null;
        byte[]? assertionSignature = null;
        byte[]? subjectPublicKeyInfo = null;
        try
        {
            using var registrationRequest = FrozenWebAuthnRegistrationRequestV1.Create(
                brokerEpoch,
                sessionId,
                sid,
                registrationNonce);
            using var registration = await ((IWebAuthnPlatformV1)adapter)
                .RegisterPlatformCredentialAsync(
                    registrationRequest,
                    window.Handle,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            registrationAuthenticatorData = registration.AuthenticatorData;
            registrationCredentialId = registration.CredentialId;
            relyingPartyIdHash = registrationRequest.RelyingPartyIdHash;
            using var credential = BrokerWebAuthnRegistrationParserV1.Parse(
                registrationAuthenticatorData,
                relyingPartyIdHash,
                registrationCredentialId);

            probeNonce = RandomNumberGenerator.GetBytes(32);
            probeStatement = WriteInteractiveProbeStatement(probeNonce);
            var clientData = BrokerWebAuthnRequestEncodingV1.CreateClientData(
                InteractiveProbeDomainSeparator,
                BrokerWebAuthnConstantsV1.AssertionClientDataType,
                probeStatement);
            assertionClientDataJson = clientData.ClientDataJson;
            assertionClientDataHash = clientData.ClientDataHash;
            window.UpdateTransactionSummary(BrokerOwnedWindowV1.AssertionSummary);
            using var assertion = await window.InvokeOnOwnerThreadAsync(
                    () =>
                    {
                        EnsureOwnerThread(window.Handle);
                        window.ValidateForCurrentProcess();
                        return GetAssertionNative(
                            window.Handle.Value,
                            registrationCredentialId,
                            assertionClientDataJson,
                            cancellationToken);
                    },
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            assertionCredentialId = assertion.CredentialId;
            assertionAuthenticatorData = assertion.AuthenticatorData;
            assertionSignature = assertion.NativeDerSignature;
            subjectPublicKeyInfo = credential.SubjectPublicKeyInfo;
            VerifyInteractiveAssertion(
                registrationCredentialId,
                relyingPartyIdHash,
                assertionClientDataHash,
                subjectPublicKeyInfo,
                assertionCredentialId,
                assertionAuthenticatorData,
                assertionSignature);

            return new WindowsWebAuthnInteractiveProbeResultV1(
                capability.ApiVersion,
                capability.PlatformAuthenticatorAvailable,
                WindowValidated: true,
                RegistrationVerified: true,
                AssertionVerified: true);
        }
        catch (ArgumentException exception)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-registration-malformed",
                "The interactive native registration evidence is malformed.",
                exception);
        }
        finally
        {
            BrokerWebAuthnPlatformValidationV1.Clear(registrationNonce);
            BrokerWebAuthnPlatformValidationV1.Clear(registrationAuthenticatorData);
            BrokerWebAuthnPlatformValidationV1.Clear(registrationCredentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(relyingPartyIdHash);
            BrokerWebAuthnPlatformValidationV1.Clear(probeNonce);
            BrokerWebAuthnPlatformValidationV1.Clear(probeStatement);
            BrokerWebAuthnPlatformValidationV1.Clear(assertionClientDataJson);
            BrokerWebAuthnPlatformValidationV1.Clear(assertionClientDataHash);
            BrokerWebAuthnPlatformValidationV1.Clear(assertionCredentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(assertionAuthenticatorData);
            BrokerWebAuthnPlatformValidationV1.Clear(assertionSignature);
            BrokerWebAuthnPlatformValidationV1.Clear(subjectPublicKeyInfo);
        }
    }

    private static WebAuthnRegistrationEvidenceV1 RegisterCore(
        FrozenWebAuthnRegistrationRequestV1 request,
        nint owner,
        CancellationToken cancellationToken)
    {
        _ = RequireSupportedCapability();
        cancellationToken.ThrowIfCancellationRequested();
        byte[]? clientDataJson = null;
        byte[]? userHandle = null;
        byte[]? credentialId = null;
        byte[]? authenticatorData = null;
        nint nativeResult = nint.Zero;
        try
        {
            clientDataJson = request.ClientDataJson;
            userHandle = request.DerivedUserHandle;
            using var memory = new NativeMemoryScope();
            using var cancellation = NativeCancellation.Create(cancellationToken);
            var rp = new NativeRpInformation
            {
                Version = NativeStructureVersionOne,
                Id = memory.AllocateUtf16(request.RelyingPartyId),
                Name = memory.AllocateUtf16(request.RelyingPartyDisplayName),
                Icon = nint.Zero
            };
            var user = new NativeUserInformation
            {
                Version = NativeStructureVersionOne,
                IdLength = checked((uint)userHandle.Length),
                Id = memory.AllocateBytes(userHandle),
                Name = memory.AllocateUtf16(request.UserName),
                Icon = nint.Zero,
                DisplayName = memory.AllocateUtf16(request.UserDisplayName)
            };
            var credentialParameter = new NativeCoseCredentialParameter
            {
                Version = NativeStructureVersionOne,
                CredentialType = memory.AllocateUtf16(BrokerWebAuthnConstantsV1.CredentialType),
                Algorithm = Es256Algorithm
            };
            var credentialParameters = new NativeCoseCredentialParameters
            {
                Count = 1,
                Parameters = memory.AllocateStructure(credentialParameter)
            };
            var clientData = new NativeClientData
            {
                Version = NativeStructureVersionOne,
                JsonLength = checked((uint)clientDataJson.Length),
                Json = memory.AllocateBytes(clientDataJson),
                HashAlgorithm = memory.AllocateUtf16("SHA-256")
            };
            var options = new NativeMakeCredentialOptionsV4
            {
                Version = MakeCredentialOptionsVersionFour,
                TimeoutMilliseconds = OperationTimeoutMilliseconds,
                CredentialList = default,
                Extensions = default,
                AuthenticatorAttachment = AuthenticatorAttachmentPlatform,
                RequireResidentKey = 0,
                UserVerificationRequirement = UserVerificationRequired,
                AttestationConveyancePreference = AttestationNone,
                Flags = 0,
                CancellationId = cancellation.Pointer,
                ExcludeCredentialList = nint.Zero,
                EnterpriseAttestation = EnterpriseAttestationNone,
                LargeBlobSupport = LargeBlobSupportNone,
                PreferResidentKey = 0
            };

            var result = WebAuthNAuthenticatorMakeCredential(
                owner,
                ref rp,
                ref user,
                ref credentialParameters,
                ref clientData,
                ref options,
                out nativeResult);
            ThrowForHResult(result, cancellationToken, "credential registration");
            if (nativeResult == nint.Zero)
            {
                throw RegistrationMalformed("Windows WebAuthn returned no registration result.");
            }

            var attestation = Marshal.PtrToStructure<NativeCredentialAttestationV1>(nativeResult);
            if (attestation.Version < NativeStructureVersionOne)
            {
                throw RegistrationMalformed("Windows WebAuthn returned an invalid registration version.");
            }

            credentialId = CopyRequiredBuffer(
                attestation.CredentialId,
                attestation.CredentialIdLength,
                MaximumCredentialIdBytes,
                registration: true,
                "credential id");
            authenticatorData = CopyRequiredBuffer(
                attestation.AuthenticatorData,
                attestation.AuthenticatorDataLength,
                MaximumAuthenticatorDataBytes,
                registration: true,
                "authenticator data");
            return WebAuthnRegistrationEvidenceV1.Create(
                clientDataJson,
                credentialId,
                authenticatorData,
                ReadOnlySpan<byte>.Empty,
                userHandle: null);
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or
                EntryPointNotFoundException or
                BadImageFormatException)
        {
            throw PlatformUnavailable("The Windows WebAuthn registration API is unavailable.", exception);
        }
        finally
        {
            if (nativeResult != nint.Zero)
            {
                WebAuthNFreeCredentialAttestation(nativeResult);
            }

            BrokerWebAuthnPlatformValidationV1.Clear(clientDataJson);
            BrokerWebAuthnPlatformValidationV1.Clear(userHandle);
            BrokerWebAuthnPlatformValidationV1.Clear(credentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(authenticatorData);
        }
    }

    private static WebAuthnAssertionEvidenceV1 GetAssertionCore(
        FrozenWebAuthnAssertionRequestV1 request,
        nint owner,
        CancellationToken cancellationToken)
    {
        byte[]? credentialId = null;
        byte[]? clientDataJson = null;
        try
        {
            credentialId = request.CredentialId;
            clientDataJson = request.ClientDataJson;
            return GetAssertionNative(owner, credentialId, clientDataJson, cancellationToken);
        }
        finally
        {
            BrokerWebAuthnPlatformValidationV1.Clear(credentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(clientDataJson);
        }
    }

    private static WebAuthnAssertionEvidenceV1 GetAssertionNative(
        nint owner,
        byte[] credentialId,
        byte[] clientDataJson,
        CancellationToken cancellationToken)
    {
        _ = RequireSupportedCapability();
        cancellationToken.ThrowIfCancellationRequested();
        byte[]? returnedCredentialId = null;
        byte[]? authenticatorData = null;
        byte[]? signature = null;
        byte[]? userHandle = null;
        nint nativeResult = nint.Zero;
        try
        {
            using var memory = new NativeMemoryScope();
            using var cancellation = NativeCancellation.Create(cancellationToken);
            var credential = new NativeCredential
            {
                Version = NativeStructureVersionOne,
                IdLength = checked((uint)credentialId.Length),
                Id = memory.AllocateBytes(credentialId),
                CredentialType = memory.AllocateUtf16(BrokerWebAuthnConstantsV1.CredentialType)
            };
            var credentials = new NativeCredentials
            {
                Count = 1,
                Credentials = memory.AllocateStructure(credential)
            };
            var clientData = new NativeClientData
            {
                Version = NativeStructureVersionOne,
                JsonLength = checked((uint)clientDataJson.Length),
                Json = memory.AllocateBytes(clientDataJson),
                HashAlgorithm = memory.AllocateUtf16("SHA-256")
            };
            var options = new NativeGetAssertionOptionsV3
            {
                Version = GetAssertionOptionsVersionThree,
                TimeoutMilliseconds = OperationTimeoutMilliseconds,
                CredentialList = credentials,
                Extensions = default,
                AuthenticatorAttachment = AuthenticatorAttachmentPlatform,
                UserVerificationRequirement = UserVerificationRequired,
                Flags = 0,
                U2fAppId = nint.Zero,
                U2fAppIdUsed = nint.Zero,
                CancellationId = cancellation.Pointer
            };

            var result = WebAuthNAuthenticatorGetAssertion(
                owner,
                BrokerWebAuthnConstantsV1.RelyingPartyId,
                ref clientData,
                ref options,
                out nativeResult);
            ThrowForHResult(result, cancellationToken, "credential assertion");
            if (nativeResult == nint.Zero)
            {
                throw AssertionMalformed("Windows WebAuthn returned no assertion result.");
            }

            var assertion = Marshal.PtrToStructure<NativeAssertionV1>(nativeResult);
            if (assertion.Version < NativeStructureVersionOne ||
                !string.Equals(
                    ReadBoundedNativeString(assertion.Credential.CredentialType),
                    BrokerWebAuthnConstantsV1.CredentialType,
                    StringComparison.Ordinal))
            {
                throw AssertionMalformed("Windows WebAuthn returned an invalid assertion shape.");
            }

            returnedCredentialId = CopyRequiredBuffer(
                assertion.Credential.Id,
                assertion.Credential.IdLength,
                MaximumCredentialIdBytes,
                registration: false,
                "credential id");
            authenticatorData = CopyRequiredBuffer(
                assertion.AuthenticatorData,
                assertion.AuthenticatorDataLength,
                MaximumAuthenticatorDataBytes,
                registration: false,
                "authenticator data");
            signature = CopyRequiredBuffer(
                assertion.Signature,
                assertion.SignatureLength,
                MaximumAssertionSignatureBytes,
                registration: false,
                "signature");
            if (assertion.UserIdLength > 0)
            {
                userHandle = CopyRequiredBuffer(
                    assertion.UserId,
                    assertion.UserIdLength,
                    MaximumUserHandleBytes,
                    registration: false,
                    "user handle");
            }

            return WebAuthnAssertionEvidenceV1.Create(
                clientDataJson,
                returnedCredentialId,
                authenticatorData,
                signature,
                userHandle);
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or
                EntryPointNotFoundException or
                BadImageFormatException)
        {
            throw PlatformUnavailable("The Windows WebAuthn assertion API is unavailable.", exception);
        }
        finally
        {
            if (nativeResult != nint.Zero)
            {
                WebAuthNFreeAssertion(nativeResult);
            }

            BrokerWebAuthnPlatformValidationV1.Clear(returnedCredentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(authenticatorData);
            BrokerWebAuthnPlatformValidationV1.Clear(signature);
            BrokerWebAuthnPlatformValidationV1.Clear(userHandle);
        }
    }

    private static WindowsWebAuthnCapabilityV1 RequireSupportedCapability()
    {
        var capability = ProbeCapability();
        if (capability.ApiVersion < MinimumConstrainedApiVersion ||
            !capability.PlatformAuthenticatorAvailable)
        {
            throw PlatformUnavailable(
                "The required Windows platform authenticator is unavailable.");
        }

        return capability;
    }

    private static void RequireRegistrationPolicy(FrozenWebAuthnRegistrationRequestV1 request)
    {
        if (!string.Equals(
                request.RelyingPartyId,
                BrokerWebAuthnConstantsV1.RelyingPartyId,
                StringComparison.Ordinal) ||
            !string.Equals(
                request.AuthenticatorAttachment,
                BrokerWebAuthnConstantsV1.PlatformAttachment,
                StringComparison.Ordinal) ||
            !string.Equals(
                request.UserVerification,
                BrokerWebAuthnConstantsV1.UserVerification,
                StringComparison.Ordinal) ||
            !string.Equals(
                request.ResidentKey,
                BrokerWebAuthnConstantsV1.ResidentKey,
                StringComparison.Ordinal) ||
            !string.Equals(
                request.Attestation,
                BrokerWebAuthnConstantsV1.Attestation,
                StringComparison.Ordinal) ||
            request.Algorithm != Es256Algorithm ||
            request.ExtensionsEnabled)
        {
            throw RegistrationMalformed("The registration request policy is not fixed.");
        }
    }

    private static void RequireAssertionPolicy(FrozenWebAuthnAssertionRequestV1 request)
    {
        if (!string.Equals(
                request.RelyingPartyId,
                BrokerWebAuthnConstantsV1.RelyingPartyId,
                StringComparison.Ordinal) ||
            !string.Equals(
                request.UserVerification,
                BrokerWebAuthnConstantsV1.UserVerification,
                StringComparison.Ordinal) ||
            request.Algorithm != Es256Algorithm ||
            request.ExtensionsEnabled)
        {
            throw AssertionMalformed("The assertion request policy is not fixed.");
        }
    }

    private static void EnsureOwnerThread(BrokerOwnedWindowHandle owner)
    {
        if (owner.OwnerProcessId != Environment.ProcessId ||
            owner.OwnerThreadId <= 0 ||
            checked((int)GetCurrentThreadId()) != owner.OwnerThreadId)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-window-invalid",
                "The WebAuthn native call is not running on the Broker-owned window thread.");
        }
    }

    private static byte[] CopyRequiredBuffer(
        nint source,
        uint length,
        int maximumLength,
        bool registration,
        string name)
    {
        if (source == nint.Zero || length == 0 || length > maximumLength)
        {
            throw registration
                ? RegistrationMalformed("Windows WebAuthn returned an invalid " + name + ".")
                : AssertionMalformed("Windows WebAuthn returned an invalid " + name + ".");
        }

        var result = new byte[checked((int)length)];
        Marshal.Copy(source, result, 0, result.Length);
        return result;
    }

    private static string ReadBoundedNativeString(nint source)
    {
        if (source == nint.Zero)
        {
            return string.Empty;
        }

        var value = Marshal.PtrToStringUni(source) ?? string.Empty;
        return value.Length <= 64 && value.All(character => character <= 0x7F)
            ? value
            : string.Empty;
    }

    private static void ThrowForHResult(
        int hResult,
        CancellationToken cancellationToken,
        string operation)
    {
        if (hResult >= 0)
        {
            return;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        if (hResult is HResultCancelled or NteUserCancelled)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-cancelled",
                "The Windows user-presence operation was cancelled by the user.");
        }

        if (hResult == HResultTimeout)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-timeout",
                "The Windows user-presence operation timed out.");
        }

        if (hResult == NteNotFound)
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-credential-not-found",
                "The required Windows WebAuthn credential was not found.");
        }

        if (hResult == NteDeviceNotFound)
        {
            throw PlatformUnavailable("The Windows platform authenticator was not found.");
        }

        var errorName = GetBoundedErrorName(hResult);
        throw NativeFailure(
            "Windows WebAuthn failed during " + operation +
            (errorName.Length == 0 ? "." : " (" + errorName + ")."));
    }

    private static string GetBoundedErrorName(int hResult)
    {
        try
        {
            var pointer = WebAuthNGetErrorName(hResult);
            var value = pointer == nint.Zero ? string.Empty : Marshal.PtrToStringUni(pointer) ?? string.Empty;
            return value.Length is > 0 and <= 96 &&
                   value.All(character =>
                       character is >= 'A' and <= 'Z' or
                           >= 'a' and <= 'z' or
                           >= '0' and <= '9' or
                           '_' or '-' or '.')
                ? value
                : string.Empty;
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or
                EntryPointNotFoundException or
                BadImageFormatException)
        {
            return string.Empty;
        }
    }

    private static uint GetCurrentWindowsSessionId()
    {
        using var process = Process.GetCurrentProcess();
        if (process.SessionId <= 0)
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-windows-session-changed",
                "The interactive WebAuthn probe has no Windows session.");
        }

        return checked((uint)process.SessionId);
    }

    private static string GetCurrentWindowsSid()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        return identity.User?.Value ?? throw PlatformUnavailable(
            "The current Windows user identity is unavailable.");
    }

    private static byte[] WriteInteractiveProbeStatement(ReadOnlySpan<byte> nonce)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = BrokerWebAuthnRequestEncodingV1.CreateWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("schema", InteractiveProbeStatementSchema);
        writer.WriteString("nonceBase64", Convert.ToBase64String(nonce));
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private static void VerifyInteractiveAssertion(
        byte[] expectedCredentialId,
        byte[] expectedRpIdHash,
        byte[] clientDataHash,
        byte[] subjectPublicKeyInfo,
        byte[] actualCredentialId,
        byte[] authenticatorData,
        byte[] signature)
    {
        if (!CryptographicOperations.FixedTimeEquals(
                expectedCredentialId,
                actualCredentialId) ||
            authenticatorData.Length != 37 ||
            !CryptographicOperations.FixedTimeEquals(
                expectedRpIdHash,
                authenticatorData.AsSpan(0, 32)) ||
            (authenticatorData[32] & 0x05) != 0x05 ||
            (authenticatorData[32] & 0xC0) != 0)
        {
            throw AssertionMalformed(
                "The interactive WebAuthn assertion identity or flags are invalid.");
        }

        var signedBytes = new byte[checked(authenticatorData.Length + clientDataHash.Length)];
        try
        {
            authenticatorData.CopyTo(signedBytes, 0);
            clientDataHash.CopyTo(signedBytes, authenticatorData.Length);
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length ||
                !key.VerifyData(
                    signedBytes,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence))
            {
                throw new BrokerUserPresenceVerificationException(
                    "user-presence-signature-invalid",
                    "The interactive WebAuthn assertion signature is invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedBytes);
        }
    }

    private static BrokerUserPresenceVerificationException PlatformUnavailable(
        string message,
        Exception? innerException = null) =>
        new("user-presence-platform-unavailable", message, innerException);

    private static BrokerUserPresenceVerificationException NativeFailure(
        string message,
        Exception? innerException = null) =>
        new("user-presence-native-failed", message, innerException);

    private static BrokerUserPresenceVerificationException RegistrationMalformed(string message) =>
        new("user-presence-registration-malformed", message);

    private static BrokerUserPresenceVerificationException AssertionMalformed(string message) =>
        new("user-presence-assertion-malformed", message);

    private sealed class NativeMemoryScope : IDisposable
    {
        private readonly List<(nint Address, int Length)> _allocations = [];
        private int _disposed;

        internal nint AllocateBytes(byte[] value)
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Length == 0)
            {
                throw new ArgumentException("A native WebAuthn buffer cannot be empty.", nameof(value));
            }

            var address = Marshal.AllocHGlobal(value.Length);
            Marshal.Copy(value, 0, address, value.Length);
            _allocations.Add((address, value.Length));
            return address;
        }

        internal nint AllocateUtf16(string value)
        {
            ArgumentNullException.ThrowIfNull(value);
            var address = Marshal.StringToHGlobalUni(value);
            _allocations.Add((address, checked((value.Length + 1) * sizeof(char))));
            return address;
        }

        internal nint AllocateStructure<T>(T value)
            where T : struct
        {
            var length = Marshal.SizeOf<T>();
            var address = Marshal.AllocHGlobal(length);
            Marshal.StructureToPtr(value, address, false);
            _allocations.Add((address, length));
            return address;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            for (var index = _allocations.Count - 1; index >= 0; index--)
            {
                var allocation = _allocations[index];
                Marshal.Copy(new byte[allocation.Length], 0, allocation.Address, allocation.Length);
                Marshal.FreeHGlobal(allocation.Address);
            }

            _allocations.Clear();
        }
    }

    private sealed class NativeCancellation : IDisposable
    {
        private readonly Guid _id;
        private readonly nint _pointer;
        private CancellationTokenRegistration _registration;
        private int _disposed;

        private NativeCancellation(Guid id, nint pointer)
        {
            _id = id;
            _pointer = pointer;
        }

        internal nint Pointer => _pointer;

        internal static NativeCancellation Create(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = WebAuthNGetCancellationId(out var id);
            ThrowForHResult(result, cancellationToken, "cancellation setup");
            var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
            Marshal.StructureToPtr(id, pointer, false);
            var cancellation = new NativeCancellation(id, pointer);
            cancellation._registration = cancellationToken.Register(
                static state => ((NativeCancellation)state!).Cancel(),
                cancellation);
            return cancellation;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _registration.Dispose();
            Marshal.Copy(new byte[Marshal.SizeOf<Guid>()], 0, _pointer, Marshal.SizeOf<Guid>());
            Marshal.FreeHGlobal(_pointer);
        }

        private void Cancel()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            try
            {
                var id = _id;
                _ = WebAuthNCancelCurrentOperation(ref id);
            }
            catch (Exception exception) when (
                exception is DllNotFoundException or
                    EntryPointNotFoundException or
                    BadImageFormatException)
            {
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRpInformation
    {
        internal uint Version;
        internal nint Id;
        internal nint Name;
        internal nint Icon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUserInformation
    {
        internal uint Version;
        internal uint IdLength;
        internal nint Id;
        internal nint Name;
        internal nint Icon;
        internal nint DisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeClientData
    {
        internal uint Version;
        internal uint JsonLength;
        internal nint Json;
        internal nint HashAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCoseCredentialParameter
    {
        internal uint Version;
        internal nint CredentialType;
        internal int Algorithm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCoseCredentialParameters
    {
        internal uint Count;
        internal nint Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCredential
    {
        internal uint Version;
        internal uint IdLength;
        internal nint Id;
        internal nint CredentialType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCredentials
    {
        internal uint Count;
        internal nint Credentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeExtensions
    {
        internal uint Count;
        internal nint Extensions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeMakeCredentialOptionsV4
    {
        internal uint Version;
        internal uint TimeoutMilliseconds;
        internal NativeCredentials CredentialList;
        internal NativeExtensions Extensions;
        internal uint AuthenticatorAttachment;
        internal int RequireResidentKey;
        internal uint UserVerificationRequirement;
        internal uint AttestationConveyancePreference;
        internal uint Flags;
        internal nint CancellationId;
        internal nint ExcludeCredentialList;
        internal uint EnterpriseAttestation;
        internal uint LargeBlobSupport;
        internal int PreferResidentKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeGetAssertionOptionsV3
    {
        internal uint Version;
        internal uint TimeoutMilliseconds;
        internal NativeCredentials CredentialList;
        internal NativeExtensions Extensions;
        internal uint AuthenticatorAttachment;
        internal uint UserVerificationRequirement;
        internal uint Flags;
        internal nint U2fAppId;
        internal nint U2fAppIdUsed;
        internal nint CancellationId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCredentialAttestationV1
    {
        internal uint Version;
        internal nint FormatType;
        internal uint AuthenticatorDataLength;
        internal nint AuthenticatorData;
        internal uint AttestationLength;
        internal nint Attestation;
        internal uint AttestationDecodeType;
        internal nint AttestationDecode;
        internal uint AttestationObjectLength;
        internal nint AttestationObject;
        internal uint CredentialIdLength;
        internal nint CredentialId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeAssertionV1
    {
        internal uint Version;
        internal uint AuthenticatorDataLength;
        internal nint AuthenticatorData;
        internal uint SignatureLength;
        internal nint Signature;
        internal NativeCredential Credential;
        internal uint UserIdLength;
        internal nint UserId;
    }

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern uint WebAuthNGetApiVersionNumber();

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
        out int isAvailable);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern int WebAuthNAuthenticatorMakeCredential(
        nint owner,
        ref NativeRpInformation relyingParty,
        ref NativeUserInformation user,
        ref NativeCoseCredentialParameters credentialParameters,
        ref NativeClientData clientData,
        ref NativeMakeCredentialOptionsV4 options,
        out nint credentialAttestation);

    [DllImport("webauthn.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WebAuthNAuthenticatorGetAssertion(
        nint owner,
        string relyingPartyId,
        ref NativeClientData clientData,
        ref NativeGetAssertionOptionsV3 options,
        out nint assertion);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern void WebAuthNFreeCredentialAttestation(nint credentialAttestation);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern void WebAuthNFreeAssertion(nint assertion);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern int WebAuthNGetCancellationId(out Guid cancellationId);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern int WebAuthNCancelCurrentOperation(ref Guid cancellationId);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern nint WebAuthNGetErrorName(int hResult);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
}

internal sealed class BrokerWebAuthnCeremonyContextV1
{
    private BrokerWebAuthnCeremonyContextV1(
        string brokerEpoch,
        uint windowsSessionId,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        string capability,
        string peerBindingSha256,
        BrokerOwnedWindowHandle owner)
    {
        BrokerEpoch = brokerEpoch;
        WindowsSessionId = windowsSessionId;
        LedgerSnapshot = ledgerSnapshot;
        Generation = generation;
        Capability = capability;
        PeerBindingSha256 = peerBindingSha256;
        Owner = owner;
    }

    internal string BrokerEpoch { get; }

    internal uint WindowsSessionId { get; }

    internal BrokerConsentLedgerStoreSnapshotV1 LedgerSnapshot { get; }

    internal CodexPackageGenerationV1 Generation { get; }

    internal string Capability { get; }

    internal string PeerBindingSha256 { get; }

    internal BrokerOwnedWindowHandle Owner { get; }

    internal static BrokerWebAuthnCeremonyContextV1 Create(
        string brokerEpoch,
        uint windowsSessionId,
        BrokerConsentLedgerStoreSnapshotV1 ledgerSnapshot,
        CodexPackageGenerationV1 generation,
        string capability,
        string peerBindingSha256,
        BrokerOwnedWindowHandle owner)
    {
        ArgumentNullException.ThrowIfNull(brokerEpoch);
        ArgumentNullException.ThrowIfNull(ledgerSnapshot);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(peerBindingSha256);
        ArgumentNullException.ThrowIfNull(owner);
        if (!BrokerFreshPresenceValidationV1.IsExactBrokerEpoch(brokerEpoch))
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-broker-epoch-changed",
                "The ceremony context Broker epoch is invalid.");
        }

        if (windowsSessionId == 0)
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-windows-session-changed",
                "The ceremony context Windows session is invalid.");
        }

        if (capability.Length is < 1 or > 128)
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-ledger-head-changed",
                "The ceremony context capability is invalid.");
        }

        _ = BrokerConsentLedgerV1.RequireSha256(peerBindingSha256, "peerBindingSha256");
        BrokerWebAuthnPlatformValidationV1.ValidateGeneration(generation);
        BrokerWebAuthnPlatformValidationV1.ValidateSnapshotStructure(ledgerSnapshot);
        return new BrokerWebAuthnCeremonyContextV1(
            brokerEpoch,
            windowsSessionId,
            ledgerSnapshot,
            generation,
            capability,
            peerBindingSha256,
            owner);
    }

    internal BrokerConsentLedgerDocumentV1 RequireInitialConsentReady()
    {
        BrokerWebAuthnPlatformValidationV1.RequireFixedCapability(Capability);
        var primary = LedgerSnapshot.Primary;
        var validGenesis =
            LedgerSnapshot.State == BrokerConsentLedgerStoreStateV1.HealthyGenesis &&
            primary?.Entry is BrokerConsentGenesisEntryV1 &&
            LedgerSnapshot.Diagnostics.Primary == BrokerConsentLedgerReplicaStateV1.Canonical &&
            LedgerSnapshot.Diagnostics.Previous == BrokerConsentLedgerReplicaStateV1.Missing &&
            string.Equals(
                LedgerSnapshot.Diagnostics.Code,
                "store-healthy-genesis",
                StringComparison.Ordinal);
        var validRevoked =
            LedgerSnapshot.State == BrokerConsentLedgerStoreStateV1.NoAuthority &&
            primary?.Entry is BrokerConsentRevokeEntryV1 &&
            LedgerSnapshot.Diagnostics.Primary == BrokerConsentLedgerReplicaStateV1.Canonical &&
            LedgerSnapshot.Diagnostics.Previous == BrokerConsentLedgerReplicaStateV1.Canonical &&
            string.Equals(
                LedgerSnapshot.Diagnostics.Code,
                "store-no-authority-revoked",
                StringComparison.Ordinal);
        if (!validGenesis && !validRevoked)
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-ledger-head-changed",
                "Initial consent requires an exact canonical genesis or revoked head.");
        }

        return primary!;
    }

    internal BrokerConsentGrantEntryV1 RequireFreshPresenceReady()
    {
        BrokerWebAuthnPlatformValidationV1.RequireFixedCapability(Capability);
        var entry = BrokerFreshPresenceValidationV1.RequirePendingSnapshot(LedgerSnapshot);
        if (!string.Equals(
                entry.GenerationSha256,
                Generation.GenerationSha256,
                StringComparison.Ordinal))
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-package-generation-changed",
                "Fresh presence requires the consented package generation.");
        }

        return entry;
    }

    internal void RequireUnchanged(BrokerWebAuthnCeremonyContextV1 current)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (!string.Equals(BrokerEpoch, current.BrokerEpoch, StringComparison.Ordinal))
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-broker-epoch-changed",
                "The Broker epoch changed during the user-presence ceremony.");
        }

        if (WindowsSessionId != current.WindowsSessionId)
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-windows-session-changed",
                "The Windows session changed during the user-presence ceremony.");
        }

        if (!string.Equals(
                Generation.GenerationSha256,
                current.Generation.GenerationSha256,
                StringComparison.Ordinal) ||
            !string.Equals(
                Generation.CanonicalJson,
                current.Generation.CanonicalJson,
                StringComparison.Ordinal))
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-package-generation-changed",
                "The package generation changed during the user-presence ceremony.");
        }

        if (!SnapshotEquals(LedgerSnapshot, current.LedgerSnapshot) ||
            !string.Equals(Capability, current.Capability, StringComparison.Ordinal) ||
            !string.Equals(
                PeerBindingSha256,
                current.PeerBindingSha256,
                StringComparison.Ordinal))
        {
            throw new BrokerUserPresenceVerificationException(
                "consent-ledger-head-changed",
                "The ledger, peer, or capability changed during the user-presence ceremony.");
        }

        if (!Owner.ContentEquals(current.Owner))
        {
            throw new BrokerUserPresenceVerificationException(
                "user-presence-window-invalid",
                "The Broker-owned window changed during the user-presence ceremony.");
        }
    }

    private static bool SnapshotEquals(
        BrokerConsentLedgerStoreSnapshotV1 left,
        BrokerConsentLedgerStoreSnapshotV1 right) =>
        left.State == right.State &&
        left.Primary?.LedgerId == right.Primary?.LedgerId &&
        left.Primary?.Revision == right.Primary?.Revision &&
        string.Equals(
            left.Primary?.EntrySha256,
            right.Primary?.EntrySha256,
            StringComparison.Ordinal) &&
        left.Diagnostics.Primary == right.Diagnostics.Primary &&
        left.Diagnostics.Previous == right.Diagnostics.Previous &&
        string.Equals(
            left.Diagnostics.Code,
            right.Diagnostics.Code,
            StringComparison.Ordinal);
}

internal sealed class BrokerWebAuthnCeremonyV1 : IDisposable
{
    private static readonly TimeSpan MinimumOperationTimeout = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan MaximumOperationTimeout = TimeSpan.FromMinutes(5);

    private readonly IWebAuthnPlatformV1 _platform;
    private readonly TimeSpan _operationTimeout;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _disposed;

    internal BrokerWebAuthnCeremonyV1(
        IWebAuthnPlatformV1 platform,
        TimeSpan operationTimeout)
    {
        ArgumentNullException.ThrowIfNull(platform);
        if (operationTimeout < MinimumOperationTimeout ||
            operationTimeout > MaximumOperationTimeout)
        {
            throw new ArgumentOutOfRangeException(
                nameof(operationTimeout),
                "The WebAuthn ceremony timeout is outside its fixed operational bound.");
        }

        _platform = platform;
        _operationTimeout = operationTimeout;
    }

    internal ValueTask<BrokerConsentLedgerDocumentV1> CreateInitialConsentAsync(
        BrokerWebAuthnCeremonyContextV1 context,
        string currentWindowsSid,
        Func<CancellationToken, ValueTask<BrokerWebAuthnCeremonyContextV1>> recapture,
        CancellationToken cancellationToken) =>
        ExecuteExclusiveAsync(
            token => CreateInitialConsentCoreAsync(
                context,
                currentWindowsSid,
                recapture,
                token),
            cancellationToken);

    internal ValueTask<BrokerFreshPresenceSessionV1> CreateFreshPresenceAsync(
        BrokerWebAuthnCeremonyContextV1 context,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        Func<CancellationToken, ValueTask<BrokerWebAuthnCeremonyContextV1>> recapture,
        CancellationToken cancellationToken) =>
        ExecuteExclusiveAsync(
            token => CreateFreshPresenceCoreAsync(
                context,
                credential,
                recapture,
                token),
            cancellationToken);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _gate.Dispose();
    }

    private async ValueTask<T> ExecuteExclusiveAsync<T>(
        Func<CancellationToken, ValueTask<T>> operation,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(operation);
        if (cancellationToken.IsCancellationRequested)
        {
            throw BrokerWebAuthnPlatformValidationV1.Fail(
                "user-presence-cancelled",
                "The user-presence operation was cancelled before entry.");
        }

        if (!_gate.Wait(0))
        {
            throw BrokerWebAuthnPlatformValidationV1.Fail(
                "user-presence-operation-busy",
                "Another user-presence operation is already in progress.");
        }

        using var timeout = new CancellationTokenSource(_operationTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeout.Token);
        try
        {
            var result = await operation(linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            return result;
        }
        catch (BrokerUserPresenceVerificationException)
        {
            throw;
        }
        catch (OperationCanceledException exception)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw BrokerWebAuthnPlatformValidationV1.Fail(
                    "user-presence-cancelled",
                    "The user-presence operation was cancelled.",
                    exception);
            }

            if (timeout.IsCancellationRequested)
            {
                throw BrokerWebAuthnPlatformValidationV1.Fail(
                    "user-presence-timeout",
                    "The user-presence operation timed out.",
                    exception);
            }

            throw BrokerWebAuthnPlatformValidationV1.Fail(
                "user-presence-cancelled",
                "The platform cancelled the user-presence operation.",
                exception);
        }
        catch (Exception exception)
        {
            throw BrokerWebAuthnPlatformValidationV1.Fail(
                "user-presence-native-failed",
                "The WebAuthn platform operation failed ambiguously.",
                exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async ValueTask<BrokerConsentLedgerDocumentV1> CreateInitialConsentCoreAsync(
        BrokerWebAuthnCeremonyContextV1 context,
        string currentWindowsSid,
        Func<CancellationToken, ValueTask<BrokerWebAuthnCeremonyContextV1>> recapture,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(currentWindowsSid);
        ArgumentNullException.ThrowIfNull(recapture);
        var currentLedger = context.RequireInitialConsentReady();
        var registrationNonce = new byte[32];
        var challengeNonce = new byte[32];
        RandomNumberGenerator.Fill(registrationNonce);
        RandomNumberGenerator.Fill(challengeNonce);
        try
        {
            using var registrationRequest = FrozenWebAuthnRegistrationRequestV1.Create(
                context.BrokerEpoch,
                context.WindowsSessionId,
                currentWindowsSid,
                registrationNonce);
            using var registrationEvidence =
                await _platform.RegisterPlatformCredentialAsync(
                        registrationRequest,
                        context.Owner,
                        cancellationToken)
                    .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var afterRegistration =
                await recapture(cancellationToken).ConfigureAwait(false);
            context.RequireUnchanged(afterRegistration);
            using var credential = ValidateRegistration(
                registrationRequest,
                registrationEvidence);
            var credentialId = credential.CredentialId;
            try
            {
                var draft = BrokerConsentGrantDraftV1.Create(
                    currentLedger,
                    currentLedger.Revision,
                    context.Generation,
                    Guid.NewGuid(),
                    credentialId,
                    credential.SubjectPublicKeyInfoSha256,
                    challengeNonce,
                    DateTime.UtcNow.Ticks);
                using var assertionRequest =
                    FrozenWebAuthnAssertionRequestV1.CreateConsent(draft, credential);
                using var assertion = await _platform.GetAssertionAsync(
                        assertionRequest,
                        context.Owner,
                        cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                var afterAssertion = await recapture(cancellationToken).ConfigureAwait(false);
                context.RequireUnchanged(afterAssertion);
                using var verified = BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
                    draft,
                    credential,
                    assertion);
                return draft.FinalizeGrant(verified);
            }
            finally
            {
                BrokerWebAuthnPlatformValidationV1.Clear(credentialId);
            }
        }
        finally
        {
            BrokerWebAuthnPlatformValidationV1.Clear(registrationNonce);
            BrokerWebAuthnPlatformValidationV1.Clear(challengeNonce);
        }
    }

    private async ValueTask<BrokerFreshPresenceSessionV1> CreateFreshPresenceCoreAsync(
        BrokerWebAuthnCeremonyContextV1 context,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        Func<CancellationToken, ValueTask<BrokerWebAuthnCeremonyContextV1>> recapture,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(recapture);
        _ = context.RequireFreshPresenceReady();
        var grant = context.LedgerSnapshot.Primary!;
        using var persisted = BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(grant);
        using var attempt = BrokerFreshPresenceAttemptV1.Create(
            context.BrokerEpoch,
            context.WindowsSessionId,
            context.LedgerSnapshot,
            context.Generation,
            context.Capability,
            persisted);
        using var request = FrozenWebAuthnAssertionRequestV1.CreateFresh(
            attempt.Statement,
            credential);
        using var assertion = await _platform.GetAssertionAsync(
                request,
                context.Owner,
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var current = await recapture(cancellationToken).ConfigureAwait(false);
        context.RequireUnchanged(current);
        using var freshEvidence = BrokerWebAuthnReceiptVerifierV1.VerifyFreshAssertion(
            attempt.Statement,
            credential,
            assertion);
        var session = attempt.Complete(freshEvidence);
        try
        {
            session.Revalidate(
                current.BrokerEpoch,
                current.WindowsSessionId,
                current.LedgerSnapshot,
                current.Generation,
                current.Capability,
                credential);
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    private static BrokerWebAuthnRegisteredCredentialV1 ValidateRegistration(
        FrozenWebAuthnRegistrationRequestV1 request,
        WebAuthnRegistrationEvidenceV1 evidence)
    {
        byte[]? expectedClientDataJson = null;
        byte[]? evidenceClientDataJson = null;
        byte[]? credentialId = null;
        byte[]? authenticatorData = null;
        byte[]? expectedUserHandle = null;
        byte[]? returnedUserHandle = null;
        byte[]? expectedRpIdHash = null;
        try
        {
            expectedClientDataJson = request.ClientDataJson;
            evidenceClientDataJson = evidence.ClientDataJson;
            credentialId = evidence.CredentialId;
            authenticatorData = evidence.AuthenticatorData;
            expectedUserHandle = request.DerivedUserHandle;
            returnedUserHandle = evidence.UserHandle;
            expectedRpIdHash = request.RelyingPartyIdHash;
            if (!expectedClientDataJson.AsSpan().SequenceEqual(evidenceClientDataJson) ||
                (returnedUserHandle is not null &&
                 !CryptographicOperations.FixedTimeEquals(
                     returnedUserHandle,
                     expectedUserHandle)))
            {
                throw BrokerWebAuthnPlatformValidationV1.Fail(
                    "user-presence-registration-malformed",
                    "The registration result does not match its frozen request.");
            }

            try
            {
                return BrokerWebAuthnRegistrationParserV1.Parse(
                    authenticatorData,
                    expectedRpIdHash,
                    credentialId);
            }
            catch (ArgumentException exception)
            {
                throw BrokerWebAuthnPlatformValidationV1.Fail(
                    "user-presence-registration-malformed",
                    "The platform registration evidence is malformed.",
                    exception);
            }
        }
        finally
        {
            BrokerWebAuthnPlatformValidationV1.Clear(expectedClientDataJson);
            BrokerWebAuthnPlatformValidationV1.Clear(evidenceClientDataJson);
            BrokerWebAuthnPlatformValidationV1.Clear(credentialId);
            BrokerWebAuthnPlatformValidationV1.Clear(authenticatorData);
            BrokerWebAuthnPlatformValidationV1.Clear(expectedUserHandle);
            BrokerWebAuthnPlatformValidationV1.Clear(returnedUserHandle);
            BrokerWebAuthnPlatformValidationV1.Clear(expectedRpIdHash);
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
}

file static class BrokerWebAuthnPlatformValidationV1
{
    internal static void ValidateGeneration(CodexPackageGenerationV1 generation)
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
                "The ceremony package generation is not canonical.",
                exception);
        }

        if (!string.Equals(
                generation.GenerationSha256,
                rebuilt.GenerationSha256,
                StringComparison.Ordinal) ||
            !string.Equals(
                generation.CanonicalJson,
                rebuilt.CanonicalJson,
                StringComparison.Ordinal))
        {
            throw Fail(
                "consent-package-generation-changed",
                "The ceremony package generation identity was forged.");
        }
    }

    internal static void ValidateSnapshotStructure(BrokerConsentLedgerStoreSnapshotV1 snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot.Diagnostics);
        byte[]? canonical = null;
        try
        {
            if (snapshot.Primary is not null)
            {
                canonical = BrokerConsentLedgerV1.Serialize(snapshot.Primary);
            }
        }
        catch (BrokerConsentLedgerFormatException exception)
        {
            throw Fail(
                "consent-ledger-head-changed",
                "The ceremony ledger snapshot is invalid.",
                exception);
        }
        finally
        {
            Clear(canonical);
        }
    }

    internal static void RequireFixedCapability(string capability)
    {
        if (!string.Equals(
                capability,
                BrokerConsentLedgerV1.CapabilityName,
                StringComparison.Ordinal))
        {
            throw Fail(
                "consent-ledger-head-changed",
                "The ceremony does not target the fixed Broker capability.");
        }
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

file static class BrokerWebAuthnRequestEncodingV1
{
    internal readonly record struct ClientData(
        byte[] ChallengeBytes,
        string ChallengeBase64Url,
        byte[] ClientDataJson,
        byte[] ClientDataHash);

    internal static ClientData CreateClientData(
        string domainSeparator,
        string type,
        ReadOnlySpan<byte> canonicalStatementBytes)
    {
        var domain = Encoding.ASCII.GetBytes(domainSeparator);
        var challengeInput = new byte[checked(domain.Length + canonicalStatementBytes.Length)];
        domain.CopyTo(challengeInput, 0);
        canonicalStatementBytes.CopyTo(challengeInput.AsSpan(domain.Length));
        byte[]? challenge = null;
        byte[]? clientDataJson = null;
        byte[]? clientDataHash = null;
        try
        {
            challenge = SHA256.HashData(challengeInput);
            var challengeBase64Url = BrokerWebAuthnBase64UrlV1.Encode(challenge);
            var buffer = new ArrayBufferWriter<byte>();
            using (var writer = CreateWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("type", type);
                writer.WriteString("challenge", challengeBase64Url);
                writer.WriteString("origin", BrokerWebAuthnConstantsV1.Origin);
                writer.WriteBoolean("crossOrigin", false);
                writer.WriteEndObject();
                writer.Flush();
            }

            clientDataJson = buffer.WrittenSpan.ToArray();
            clientDataHash = SHA256.HashData(clientDataJson);
            var result = new ClientData(
                challenge,
                challengeBase64Url,
                clientDataJson,
                clientDataHash);
            challenge = null;
            clientDataJson = null;
            clientDataHash = null;
            return result;
        }
        finally
        {
            BrokerWebAuthnPlatformValidationV1.Clear(domain);
            BrokerWebAuthnPlatformValidationV1.Clear(challengeInput);
            BrokerWebAuthnPlatformValidationV1.Clear(challenge);
            BrokerWebAuthnPlatformValidationV1.Clear(clientDataJson);
            BrokerWebAuthnPlatformValidationV1.Clear(clientDataHash);
        }
    }

    internal static Utf8JsonWriter CreateWriter(IBufferWriter<byte> buffer) =>
        new(
            buffer,
            new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.Default,
                Indented = false,
                SkipValidation = false
            });
}
