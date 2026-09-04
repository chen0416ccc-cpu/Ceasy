using CodexGuardian.Broker;
using CodexGuardian.Control;
using CodexGuardian.Trust;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

internal static class BrokerWebAuthnReceiptOfflineTests
{
    private static readonly Guid LedgerId =
        Guid.ParseExact("01234567-89ab-cdef-0123-456789abcdef", "D");
    private static readonly Guid ReceiptId =
        Guid.ParseExact("11111111-2222-3333-4444-555555555555", "D");
    private const long IssuedAtUtcTicks = 638900000000000000;

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "Broker grant draft freezes every unsigned consent identity without a proof parameter",
            TestGrantDraftContract,
            assert);
        RunCase(
            "Broker WebAuthn client data has exact fixed bytes and challenge",
            TestWebAuthnClientDataContract,
            assert);
        RunCase(
            "Broker WebAuthn registration accepts only bounded canonical ES256 P-256 evidence",
            TestStrictCoseP256Key,
            assert);
        RunCase(
            "Broker WebAuthn proof is canonical DER-normalized 210-byte evidence",
            TestStrictDerAndProofEnvelope,
            assert);
        RunCase(
            "Broker verifies WebAuthn receipts before one-shot grant finalization",
            TestPersistedReceiptVerificationAndGrantFinalization,
            assert);
        RunCase(
            "Broker assertion evidence is bounded, copied, and cleared on disposal",
            TestAssertionEvidenceBoundsAndOwnership,
            assert);
        RunCase(
            "Broker persisted receipt verification rejects canonical tamper and historical reuse",
            TestPersistedReceiptTamperMatrix,
            assert);
        RunCase(
            "Broker fresh presence pins exact volatile identity and rejects drift",
            TestFreshPresenceSession,
            assert);
        RunCase(
            "Broker capability lease is an isolated volatile one-shot authority",
            TestCapabilityLeaseContract,
            assert);
        RunCase(
            "Broker WebAuthn platform is constrained and ceremonies fail closed",
            TestFakePlatformConcurrencyCancellationAndTimeout,
            assert);
        RunCase(
            "Windows WebAuthn adapter and Broker-owned window are isolated from offline execution",
            TestNativePlatformSourceBoundary,
            assert);
        RunCase(
            "Broker WebAuthn and capability-lease sources have exact release closure",
            TestReleaseSourceClosure,
            assert);
        return Task.CompletedTask;
    }

    private static void TestReleaseSourceClosure()
    {
        var releaseSource = File.ReadAllText(Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "package-release.ps1"));
        var requiredSources = new[]
        {
            "CodexGuardian.Broker\\BrokerConsentGrantDraft.cs",
            "CodexGuardian.Broker\\BrokerWebAuthnClientData.cs",
            "CodexGuardian.Broker\\BrokerWebAuthnCoseKey.cs",
            "CodexGuardian.Broker\\BrokerWebAuthnProof.cs",
            "CodexGuardian.Broker\\BrokerWebAuthnReceiptVerifier.cs",
            "CodexGuardian.Broker\\BrokerFreshPresenceSession.cs",
            "CodexGuardian.Broker\\BrokerCapabilityLease.cs",
            "CodexGuardian.Broker\\BrokerWebAuthnPlatform.cs",
            "CodexGuardian.Broker\\BrokerOwnedWindow.cs",
            "CodexGuardian.Tests\\BrokerWebAuthnReceiptOfflineTests.cs",
            "CodexGuardian.Tests\\BrokerWebAuthnNativeProbeTests.cs"
        };
        Ensure(
            requiredSources.All(source =>
                releaseSource.Split(source, StringSplitOptions.None).Length - 1 == 3),
            "release source closure does not contain every WebAuthn and capability-lease source exactly three times");

        Ensure(
            releaseSource.Split(
                "--native-user-presence-capability-probe",
                StringSplitOptions.None).Length - 1 == 1 &&
            !releaseSource.Contains(
                "--native-user-presence-interactive-probe",
                StringComparison.Ordinal) &&
            releaseSource.Contains(
                "$NativeUserPresenceCapabilityProbeMarker = " +
                "'NATIVE_USER_PRESENCE_CAPABILITY_PROBE_COMPLETE'",
                StringComparison.Ordinal) &&
            releaseSource.Contains(
                "$NativeUserPresenceCapabilityProbeTimeoutSeconds = 60",
                StringComparison.Ordinal) &&
            releaseSource.Contains(
                "'--native-user-presence-evidence-root', $NativeUserPresenceEvidenceRoot",
                StringComparison.Ordinal) &&
            releaseSource.Contains(
                "$BrokerConsentLedgerTestData = Join-Path $TempRoot (",
                StringComparison.Ordinal) &&
            releaseSource.Contains(
                "'l-' + $PID + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 16))",
                StringComparison.Ordinal) &&
            !releaseSource.Contains(
                "$BrokerConsentLedgerTestData = Join-Path $TestDataRoot 'broker-consent-ledger'",
                StringComparison.Ordinal) &&
            releaseSource.Contains(
                "if ($BrokerConsentLedgerTestData.Length -gt 72) {",
                StringComparison.Ordinal) &&
            releaseSource.Contains(
                "New-Item -ItemType Directory -Path $BrokerConsentLedgerTestData -ErrorAction Stop | Out-Null",
                StringComparison.Ordinal) &&
            releaseSource.Split(
                "(Get-CleanupTargetSnapshot $BrokerConsentLedgerTestData)",
                StringSplitOptions.None).Length - 1 == 1 &&
            releaseSource.Split(
                "Remove-TempDirectoryTree $BrokerConsentLedgerTestData",
                StringSplitOptions.None).Length - 1 == 1 &&
            // Cleanup verification asks Get-ExactPathEntry, not Test-Path, and that is the stricter
            // question as well as the one the two sibling targets in the same $cleanupVerified expression
            // already ask. It enumerates every path segment and matches each name exactly, so an 8.3 short
            // name cannot satisfy it, a duplicate entry throws instead of quietly passing, and it refuses
            // to traverse a reparse point -- a junction anywhere under the temp root would otherwise let a
            // directory that still exists read as deleted. Pinning Test-Path here would force one boolean
            // to mix two different definitions of absent, so the exact-entry form is pinned instead.
            releaseSource.Split(
                "$null -eq (Get-ExactPathEntry $BrokerConsentLedgerTestData)",
                StringSplitOptions.None).Length - 1 == 1,
            "release capability gate or cleanup-owned short Store test root is absent");
    }

    private static void TestNativePlatformSourceBoundary()
    {
        var brokerAssembly = typeof(IWebAuthnPlatformV1).Assembly;
        var nativePlatformType = brokerAssembly.GetType(
            "CodexGuardian.Broker.WindowsWebAuthnPlatformV1",
            throwOnError: false,
            ignoreCase: false);
        Ensure(nativePlatformType is not null, "WindowsWebAuthnPlatformV1 is missing");
        var requiredNativePlatformType = nativePlatformType!;

        var ownedWindowType = brokerAssembly.GetType(
            "CodexGuardian.Broker.BrokerOwnedWindowV1",
            throwOnError: false,
            ignoreCase: false);
        Ensure(ownedWindowType is not null, "BrokerOwnedWindowV1 is missing");
        var requiredOwnedWindowType = ownedWindowType!;

        var sourceRoot = Path.Combine(Directory.GetCurrentDirectory(), "work");
        var platformSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Broker",
            "BrokerWebAuthnPlatform.cs"));
        var ownedWindowSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Broker",
            "BrokerOwnedWindow.cs"));
        var brokerProgramSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Broker",
            "Program.cs"));
        var nativeProbeSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Tests",
            "BrokerWebAuthnNativeProbeTests.cs"));
        var offlineTestSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Tests",
            "BrokerWebAuthnReceiptOfflineTests.cs"));
        var testsProgramSource = File.ReadAllText(Path.Combine(
            sourceRoot,
            "CodexGuardian.Tests",
            "Program.cs"));
        var ownedWindowMethods = requiredOwnedWindowType.GetMethods(
            BindingFlags.Instance |
            BindingFlags.Static |
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.DeclaredOnly);
        var nativeForbiddenTokens = new[]
        {
            "WebAuthNGetPlatformCredentialList",
            "WebAuthNDeletePlatformCredential",
            "NCrypt",
            "Cng",
            "CrossPlatform",
            "SignAsync",
            "GetForegroundWindow",
            "SetForegroundWindow",
            "GetActiveWindow",
            "MainWindowHandle",
            "System.Windows.Forms",
            "PresentationFramework"
        };
        var explicitProbeDispatch = testsProgramSource.IndexOf(
            "if (BrokerWebAuthnNativeProbeTests.IsProbeInvocation(args))",
            StringComparison.Ordinal);
        var ordinaryOfflineDispatch = testsProgramSource.IndexOf(
            "await BrokerWebAuthnReceiptOfflineTests.RunAsync(Assert);",
            StringComparison.Ordinal);
        Ensure(
            requiredNativePlatformType.IsSealed &&
            typeof(IWebAuthnPlatformV1).IsAssignableFrom(requiredNativePlatformType) &&
            requiredOwnedWindowType.IsSealed &&
            typeof(IDisposable).IsAssignableFrom(requiredOwnedWindowType) &&
            requiredOwnedWindowType.GetProperty(
                "Handle",
                BindingFlags.Instance | BindingFlags.NonPublic)?.PropertyType ==
                typeof(BrokerOwnedWindowHandle) &&
            new[]
            {
                "CreateAsync",
                "InvokeOnOwnerThreadAsync",
                "UpdateTransactionSummary",
                "ValidateForCurrentProcess",
                "Dispose"
            }.All(name => ownedWindowMethods.Any(method => method.Name == name)) &&
            new[]
            {
                "WebAuthNGetApiVersionNumber",
                "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
                "WebAuthNAuthenticatorMakeCredential",
                "WebAuthNAuthenticatorGetAssertion",
                "WebAuthNFreeCredentialAttestation",
                "WebAuthNFreeAssertion",
                "WebAuthNGetCancellationId",
                "WebAuthNCancelCurrentOperation",
                "WebAuthNGetErrorName",
                "MakeCredentialOptionsVersionFour",
                "GetAssertionOptionsVersionThree",
                "AuthenticatorAttachmentPlatform",
                "UserVerificationRequired",
                "AttestationNone",
                "Es256Algorithm"
            }.All(token => platformSource.Contains(token, StringComparison.Ordinal)) &&
            new[]
            {
                "RegisterClassExW",
                "CreateWindowExW",
                "GetAncestor",
                "GetWindowThreadProcessId",
                "OpenThread",
                "GetCurrentThreadId",
                "ApartmentState.STA",
                "TaskCreationOptions.RunContinuationsAsynchronously",
                "GaRoot",
                "WsCaption | WsSysMenu"
            }.All(token => ownedWindowSource.Contains(token, StringComparison.Ordinal)) &&
            nativeForbiddenTokens.All(token =>
                !platformSource.Contains(token, StringComparison.Ordinal) &&
                !ownedWindowSource.Contains(token, StringComparison.Ordinal)) &&
            brokerProgramSource.Contains(
                "--native-user-presence-capability-probe",
                StringComparison.Ordinal) &&
            brokerProgramSource.Contains(
                "--native-user-presence-interactive-probe",
                StringComparison.Ordinal) &&
            brokerProgramSource.Contains(
                "--native-user-presence-evidence-root",
                StringComparison.Ordinal) &&
            nativeProbeSource.Contains(
                "NATIVE_USER_PRESENCE_CAPABILITY_PROBE_COMPLETE",
                StringComparison.Ordinal) &&
            nativeProbeSource.Contains(
                "NATIVE_USER_PRESENCE_INTERACTIVE_PROBE_COMPLETE",
                StringComparison.Ordinal) &&
            explicitProbeDispatch >= 0 &&
            ordinaryOfflineDispatch > explicitProbeDispatch &&
            !offlineTestSource.Contains(
                "new WindowsWebAuthnPlatform" + "V1",
                StringComparison.Ordinal) &&
            !offlineTestSource.Contains(
                "BrokerOwnedWindowV1." + "CreateAsync",
                StringComparison.Ordinal),
            "ordinary offline WebAuthn execution can construct a native adapter or owned window");
    }

    private static void TestFakePlatformConcurrencyCancellationAndTimeout() =>
        TestFakePlatformConcurrencyCancellationAndTimeoutAsync().GetAwaiter().GetResult();

    private static async Task TestFakePlatformConcurrencyCancellationAndTimeoutAsync()
    {
        const string BrokerEpoch = "0123456789abcdef0123456789abcdef";
        const string OtherBrokerEpoch = "fedcba9876543210fedcba9876543210";
        const uint WindowsSessionId = 42;
        const string WindowsSid = "S-1-5-21-1000-2000-3000-4000";
        var platformType = typeof(IWebAuthnPlatformV1);
        var platformMethods = platformType.GetMethods();
        Ensure(
            platformType.IsInterface &&
            platformMethods.Length == 2 &&
            platformMethods.Any(method =>
                method.Name == "RegisterPlatformCredentialAsync" &&
                method.ReturnType == typeof(ValueTask<WebAuthnRegistrationEvidenceV1>) &&
                method.GetParameters().Select(parameter => parameter.ParameterType)
                    .SequenceEqual(
                        new[]
                        {
                            typeof(FrozenWebAuthnRegistrationRequestV1),
                            typeof(BrokerOwnedWindowHandle),
                            typeof(CancellationToken)
                        })) &&
            platformMethods.Any(method =>
                method.Name == "GetAssertionAsync" &&
                method.ReturnType == typeof(ValueTask<WebAuthnAssertionEvidenceV1>) &&
                method.GetParameters().Select(parameter => parameter.ParameterType)
                    .SequenceEqual(
                        new[]
                        {
                            typeof(FrozenWebAuthnAssertionRequestV1),
                            typeof(BrokerOwnedWindowHandle),
                            typeof(CancellationToken)
                        })) &&
            platformMethods.All(method =>
                !method.Name.Contains("Sign", StringComparison.OrdinalIgnoreCase) &&
                method.GetParameters().All(parameter =>
                    parameter.ParameterType != typeof(byte[]))),
            "IWebAuthnPlatformV1 is not the exact two-operation constrained interface");

        var owner = BrokerOwnedWindowHandle.Create(
            (nint)0x1234,
            Environment.ProcessId,
            Environment.CurrentManagedThreadId);
        Ensure(
            owner.Value == (nint)0x1234 &&
            owner.OwnerProcessId == Environment.ProcessId &&
            owner.OwnerThreadId == Environment.CurrentManagedThreadId &&
            typeof(BrokerOwnedWindowHandle).GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate),
            "Broker-owned window handle identity surface changed");
        ExpectVerificationCode(
            () => BrokerOwnedWindowHandle.Create(
                nint.Zero,
                Environment.ProcessId,
                Environment.CurrentManagedThreadId),
            "user-presence-window-invalid");

        var registrationNonce = BrokerWebAuthnTestVectorsV1.Nonce(0x20);
        var expectedUserHandle = CreateExpectedWindowsUserHandle(WindowsSid);
        var registrationRequest = FrozenWebAuthnRegistrationRequestV1.Create(
            BrokerEpoch,
            WindowsSessionId,
            WindowsSid,
            registrationNonce);
        var registrationRequestOwnedArrays = GetOwnedByteArrays(registrationRequest);
        var returnedUserHandle = registrationRequest.DerivedUserHandle;
        var returnedRegistrationClientData = registrationRequest.ClientDataJson;
        returnedUserHandle[0] ^= 0xFF;
        returnedRegistrationClientData[0] ^= 0xFF;
        Ensure(
            registrationRequest.RelyingPartyId == BrokerWebAuthnConstantsV1.RelyingPartyId &&
            registrationRequest.RelyingPartyDisplayName ==
                BrokerWebAuthnConstantsV1.RelyingPartyDisplayName &&
            registrationRequest.Origin == BrokerWebAuthnConstantsV1.Origin &&
            registrationRequest.CredentialType == BrokerWebAuthnConstantsV1.CredentialType &&
            registrationRequest.ClientDataType ==
                BrokerWebAuthnConstantsV1.RegistrationClientDataType &&
            registrationRequest.AuthenticatorAttachment ==
                BrokerWebAuthnConstantsV1.PlatformAttachment &&
            registrationRequest.UserVerification ==
                BrokerWebAuthnConstantsV1.UserVerification &&
            registrationRequest.ResidentKey == BrokerWebAuthnConstantsV1.ResidentKey &&
            registrationRequest.Attestation == BrokerWebAuthnConstantsV1.Attestation &&
            registrationRequest.Algorithm == BrokerWebAuthnConstantsV1.Es256Algorithm &&
            !registrationRequest.ExtensionsEnabled &&
            registrationRequest.DerivedUserHandle.SequenceEqual(expectedUserHandle) &&
            registrationRequest.RegistrationNonce.SequenceEqual(registrationNonce) &&
            registrationRequestOwnedArrays.Length == 7 &&
            typeof(FrozenWebAuthnRegistrationRequestV1).GetFields(
                    BindingFlags.Instance |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(field => !field.Name.Contains("sid", StringComparison.OrdinalIgnoreCase)),
            "registration request exposed mutable policy, SID, or derived-handle state");
        registrationRequest.Dispose();
        Ensure(
            registrationRequestOwnedArrays.All(array => array.All(value => value == 0)),
            "disposed registration request retained owned bytes");
        ExpectObjectDisposed(() => _ = registrationRequest.DerivedUserHandle);
        ExpectObjectDisposed(() => _ = registrationRequest.RelyingPartyId);

        var evidenceClientData = new byte[] { 0x11 };
        var evidenceCredentialId = new byte[] { 0x22 };
        var evidenceAuthenticatorData = new byte[] { 0x33 };
        var evidenceSignature = new byte[] { 0x44 };
        var evidenceUserHandle = new byte[] { 0x55 };
        var registrationEvidence = WebAuthnRegistrationEvidenceV1.Create(
            evidenceClientData,
            evidenceCredentialId,
            evidenceAuthenticatorData,
            evidenceSignature,
            evidenceUserHandle);
        var registrationEvidenceOwnedArrays = GetOwnedByteArrays(registrationEvidence);
        evidenceClientData[0] = 0xFF;
        evidenceCredentialId[0] = 0xFF;
        evidenceAuthenticatorData[0] = 0xFF;
        evidenceSignature[0] = 0xFF;
        evidenceUserHandle[0] = 0xFF;
        var returnedEvidenceCredential = registrationEvidence.CredentialId;
        returnedEvidenceCredential[0] = 0xEE;
        Ensure(
            registrationEvidence.ClientDataJson.SequenceEqual(new byte[] { 0x11 }) &&
            registrationEvidence.CredentialId.SequenceEqual(new byte[] { 0x22 }) &&
            registrationEvidence.AuthenticatorData.SequenceEqual(new byte[] { 0x33 }) &&
            registrationEvidence.NativeSignature.SequenceEqual(new byte[] { 0x44 }) &&
            registrationEvidence.UserHandle!.SequenceEqual(new byte[] { 0x55 }) &&
            registrationEvidenceOwnedArrays.Length == 5,
            "registration evidence did not deeply copy every bounded buffer");
        registrationEvidence.Dispose();
        Ensure(
            registrationEvidenceOwnedArrays.All(array => array.All(value => value == 0)),
            "disposed registration evidence retained owned bytes");
        ExpectObjectDisposed(() => _ = registrationEvidence.CredentialId);
        using (var maximumRegistrationEvidence = WebAuthnRegistrationEvidenceV1.Create(
                   new byte[4096],
                   new byte[1024],
                   new byte[4096],
                   new byte[4096],
                   new byte[1024]))
        {
            Ensure(
                maximumRegistrationEvidence.ClientDataJson.Length == 4096 &&
                maximumRegistrationEvidence.CredentialId.Length == 1024 &&
                maximumRegistrationEvidence.AuthenticatorData.Length == 4096 &&
                maximumRegistrationEvidence.NativeSignature.Length == 4096 &&
                maximumRegistrationEvidence.UserHandle!.Length == 1024,
                "registration evidence rejected an exact maximum bound");
        }

        var oneByte = new byte[] { 0x01 };
        ExpectArgumentException(() => WebAuthnRegistrationEvidenceV1.Create(
            new byte[4097], oneByte, oneByte, oneByte, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnRegistrationEvidenceV1.Create(
            oneByte, Array.Empty<byte>(), oneByte, oneByte, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnRegistrationEvidenceV1.Create(
            oneByte, new byte[1025], oneByte, oneByte, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnRegistrationEvidenceV1.Create(
            oneByte, oneByte, new byte[4097], oneByte, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnRegistrationEvidenceV1.Create(
            oneByte, oneByte, oneByte, new byte[4097], userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnRegistrationEvidenceV1.Create(
            oneByte, oneByte, oneByte, oneByte, Array.Empty<byte>()).Dispose());
        ExpectArgumentException(() => WebAuthnRegistrationEvidenceV1.Create(
            oneByte, oneByte, oneByte, oneByte, new byte[1025]).Dispose());

        var generation = CreateGeneration("fake-platform-generation");
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var peerBinding = Hash("fake-platform-peer");
        var genesisContext = BrokerWebAuthnCeremonyContextV1.Create(
            BrokerEpoch,
            WindowsSessionId,
            CreateGenesisSnapshot(genesis),
            generation,
            BrokerConsentLedgerV1.CapabilityName,
            peerBinding,
            owner);
        using var successPlatform = new FakeWebAuthnPlatformV1(FakeWebAuthnBehavior.Normal);
        using var successCeremony = new BrokerWebAuthnCeremonyV1(
            successPlatform,
            TimeSpan.FromSeconds(2));
        var grant = await successCeremony.CreateInitialConsentAsync(
            genesisContext,
            WindowsSid,
            token => ReturnContextAsync(genesisContext, token),
            CancellationToken.None);
        Ensure(
            grant.ValidationState == BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification &&
            grant.Entry is BrokerConsentGrantEntryV1 &&
            successPlatform.RegistrationCalls == 1 &&
            successPlatform.AssertionCalls == 1 &&
            successPlatform.FixedPolicyObserved &&
            successPlatform.ObservedRegistrationUserHandle.SequenceEqual(expectedUserHandle) &&
            successPlatform.LastRegistrationRequestCleared &&
            successPlatform.LastRegistrationEvidenceCleared &&
            successPlatform.LastAssertionRequestCleared &&
            successPlatform.LastAssertionEvidenceCleared,
            "initial consent did not require registration plus immediate fixed-policy assertion");
        using (var persisted = BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(grant))
        {
            Ensure(
                persisted.Purpose == BrokerWebAuthnEvidencePurposeV1.PersistedGrant,
                "initial ceremony returned a grant with an unverifiable receipt");
        }

        var platformCredentialId = successPlatform.CredentialId;
        using var registeredCredential = CreateRegisteredCredential(
            platformCredentialId,
            keyVariant: 1);
        var pendingSnapshot = CreatePendingSnapshot(grant);
        var freshContext = BrokerWebAuthnCeremonyContextV1.Create(
            BrokerEpoch,
            WindowsSessionId,
            pendingSnapshot,
            generation,
            BrokerConsentLedgerV1.CapabilityName,
            peerBinding,
            owner);
        using (var session = await successCeremony.CreateFreshPresenceAsync(
                   freshContext,
                   registeredCredential,
                   token => ReturnContextAsync(freshContext, token),
                   CancellationToken.None))
        {
            session.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                pendingSnapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                registeredCredential);
            Ensure(
                successPlatform.RegistrationCalls == 1 &&
                successPlatform.AssertionCalls == 2,
                "fresh presence registered another credential or skipped assertion");
        }

        using (var concurrentPlatform =
               new FakeWebAuthnPlatformV1(FakeWebAuthnBehavior.BlockAssertion))
        using (var concurrentCeremony = new BrokerWebAuthnCeremonyV1(
                   concurrentPlatform,
                   TimeSpan.FromSeconds(2)))
        {
            var first = concurrentCeremony.CreateFreshPresenceAsync(
                    freshContext,
                    registeredCredential,
                    token => ReturnContextAsync(freshContext, token),
                    CancellationToken.None)
                .AsTask();
            await concurrentPlatform.AssertionEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
            await ExpectVerificationCodeAsync(
                () => concurrentCeremony.CreateFreshPresenceAsync(
                        freshContext,
                        registeredCredential,
                        token => ReturnContextAsync(freshContext, token),
                        CancellationToken.None)
                    .AsTask(),
                "user-presence-operation-busy");
            Ensure(
                concurrentPlatform.AssertionCalls == 1,
                "busy rejection entered the platform a second time");
            concurrentPlatform.ReleaseAssertion();
            using var completed = await first.WaitAsync(TimeSpan.FromSeconds(2));
        }

        using (var cancelledPlatform =
               new FakeWebAuthnPlatformV1(FakeWebAuthnBehavior.Normal))
        using (var cancelledCeremony = new BrokerWebAuthnCeremonyV1(
                   cancelledPlatform,
                   TimeSpan.FromSeconds(2)))
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            await ExpectVerificationCodeAsync(
                () => cancelledCeremony.CreateFreshPresenceAsync(
                        freshContext,
                        registeredCredential,
                        token => ReturnContextAsync(freshContext, token),
                        cancelled.Token)
                    .AsTask(),
                "user-presence-cancelled");
            Ensure(
                cancelledPlatform.RegistrationCalls == 0 &&
                cancelledPlatform.AssertionCalls == 0,
                "pre-cancelled ceremony entered the platform");
        }

        await ExpectFreshPlatformFailureAsync(
            FakeWebAuthnBehavior.UserCancelled,
            freshContext,
            registeredCredential,
            "user-presence-cancelled",
            TimeSpan.FromSeconds(2));
        await ExpectFreshPlatformFailureAsync(
            FakeWebAuthnBehavior.WaitForCancellation,
            freshContext,
            registeredCredential,
            "user-presence-timeout",
            TimeSpan.FromMilliseconds(40));
        await ExpectFreshPlatformFailureAsync(
            FakeWebAuthnBehavior.NativeFailure,
            freshContext,
            registeredCredential,
            "user-presence-native-failed",
            TimeSpan.FromSeconds(2));
        await ExpectFreshPlatformFailureAsync(
            FakeWebAuthnBehavior.WrongCredential,
            freshContext,
            registeredCredential,
            "user-presence-credential-invalid",
            TimeSpan.FromSeconds(2));

        using (var latePlatform =
               new FakeWebAuthnPlatformV1(FakeWebAuthnBehavior.LateAssertion))
        using (var lateCeremony = new BrokerWebAuthnCeremonyV1(
                   latePlatform,
                   TimeSpan.FromMilliseconds(40)))
        {
            var late = lateCeremony.CreateFreshPresenceAsync(
                    freshContext,
                    registeredCredential,
                    token => ReturnContextAsync(freshContext, token),
                    CancellationToken.None)
                .AsTask();
            await latePlatform.AssertionEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
            await Task.Delay(100);
            latePlatform.ReleaseAssertion();
            await ExpectVerificationCodeAsync(() => late, "user-presence-timeout");
            Ensure(
                latePlatform.LastAssertionRequestCleared &&
                latePlatform.LastAssertionEvidenceCleared,
                "late assertion result retained request or evidence bytes");
        }

        using (var wrongSpkiCredential = CreateRegisteredCredential(
                   platformCredentialId,
                   keyVariant: 2))
        using (var wrongSpkiPlatform =
               new FakeWebAuthnPlatformV1(FakeWebAuthnBehavior.Normal))
        using (var wrongSpkiCeremony = new BrokerWebAuthnCeremonyV1(
                   wrongSpkiPlatform,
                   TimeSpan.FromSeconds(2)))
        {
            await ExpectVerificationCodeAsync(
                () => wrongSpkiCeremony.CreateFreshPresenceAsync(
                        freshContext,
                        wrongSpkiCredential,
                        token => ReturnContextAsync(freshContext, token),
                        CancellationToken.None)
                    .AsTask(),
                "user-presence-credential-invalid");
            Ensure(
                wrongSpkiPlatform.AssertionCalls == 0,
                "wrong registered SPKI reached the platform");
        }

        var revoke = BrokerConsentLedgerTransition.CreateRevoke(
            grant,
            1,
            BrokerConsentRevokeReasonV1.UserRequested,
            IssuedAtUtcTicks + 100);
        var differentGeneration = CreateGeneration("fake-platform-generation-drift");
        var otherOwner = BrokerOwnedWindowHandle.Create(
            (nint)0x5678,
            Environment.ProcessId,
            Environment.CurrentManagedThreadId);
        var driftContexts = new[]
        {
            (
                BrokerWebAuthnCeremonyContextV1.Create(
                    OtherBrokerEpoch,
                    WindowsSessionId,
                    pendingSnapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    peerBinding,
                    owner),
                "consent-broker-epoch-changed"),
            (
                BrokerWebAuthnCeremonyContextV1.Create(
                    BrokerEpoch,
                    WindowsSessionId + 1,
                    pendingSnapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    peerBinding,
                    owner),
                "consent-windows-session-changed"),
            (
                BrokerWebAuthnCeremonyContextV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    pendingSnapshot,
                    differentGeneration,
                    BrokerConsentLedgerV1.CapabilityName,
                    peerBinding,
                    owner),
                "consent-package-generation-changed"),
            (
                BrokerWebAuthnCeremonyContextV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    CreateRevokedSnapshot(revoke),
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    peerBinding,
                    owner),
                "consent-ledger-head-changed"),
            (
                BrokerWebAuthnCeremonyContextV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    pendingSnapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    Hash("fake-platform-other-peer"),
                    owner),
                "consent-ledger-head-changed"),
            (
                BrokerWebAuthnCeremonyContextV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    pendingSnapshot,
                    generation,
                    "managed-readonly-cdp-v2",
                    peerBinding,
                    owner),
                "consent-ledger-head-changed"),
            (
                BrokerWebAuthnCeremonyContextV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    pendingSnapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    peerBinding,
                    otherOwner),
                "user-presence-window-invalid")
        };
        foreach (var (driftContext, code) in driftContexts)
        {
            await ExpectFreshContextDriftAsync(
                freshContext,
                driftContext,
                registeredCredential,
                code);
        }

        var platformSourcePath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian.Broker",
            "BrokerWebAuthnPlatform.cs");
        var platformSource = File.ReadAllText(platformSourcePath);
        var forbiddenSourceTokens = new[]
        {
            "System.Windows",
            "System.IO",
            "File.",
            "Directory.",
            "new BrokerConsentLedgerStore",
            "store.Write(",
            "PresentationFramework",
            "CapabilityLease",
            "RecoveryService",
            "FollowUp",
            "DesktopIpcClient",
            "NamedPipe",
            "Process.Start"
        };
        var ceremonyMethods = typeof(BrokerWebAuthnCeremonyV1).GetMethods(
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(method => method.Name.StartsWith("Create", StringComparison.Ordinal))
            .Where(method => !method.IsPrivate)
            .ToArray();
        Ensure(
            forbiddenSourceTokens.All(token =>
                !platformSource.Contains(token, StringComparison.Ordinal)) &&
            typeof(FrozenWebAuthnRegistrationRequestV1).GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate) &&
            typeof(FrozenWebAuthnAssertionRequestV1).GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate) &&
            typeof(WebAuthnRegistrationEvidenceV1).GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate) &&
            ceremonyMethods.Length == 2 &&
            ceremonyMethods.Any(method =>
                method.Name == "CreateInitialConsentAsync" &&
                method.ReturnType == typeof(ValueTask<BrokerConsentLedgerDocumentV1>)) &&
            ceremonyMethods.Any(method =>
                method.Name == "CreateFreshPresenceAsync" &&
                method.ReturnType == typeof(ValueTask<BrokerFreshPresenceSessionV1>)) &&
            ceremonyMethods.SelectMany(method => method.GetParameters()).All(parameter =>
                !parameter.ParameterType.Name.Contains("Lease", StringComparison.OrdinalIgnoreCase) &&
                !parameter.ParameterType.Name.Contains("Guardian", StringComparison.OrdinalIgnoreCase)),
            "fake platform phase introduced native, Guardian, lease, send, or mutable construction authority");

        CryptographicOperations.ZeroMemory(registrationNonce);
        CryptographicOperations.ZeroMemory(expectedUserHandle);
        CryptographicOperations.ZeroMemory(returnedUserHandle);
        CryptographicOperations.ZeroMemory(returnedRegistrationClientData);
        CryptographicOperations.ZeroMemory(returnedEvidenceCredential);
        CryptographicOperations.ZeroMemory(platformCredentialId);
    }

    private static void TestCapabilityLeaseContract()
    {
        const string BrokerEpoch = "0123456789abcdef0123456789abcdef";
        const uint WindowsSessionId = 42;
        var leaseType = typeof(BrokerCapabilityLeaseV1);
        Ensure(
            leaseType.IsSealed &&
            typeof(IDisposable).IsAssignableFrom(leaseType) &&
            leaseType.GetCustomAttributesData().All(attribute =>
                attribute.AttributeType != typeof(SerializableAttribute)) &&
            leaseType.GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate) &&
            leaseType.GetFields(
                    BindingFlags.Instance |
                    BindingFlags.Static |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(field =>
                    !field.FieldType.Name.Contains("Store", StringComparison.Ordinal) &&
                    !field.FieldType.Name.Contains("Document", StringComparison.Ordinal) &&
                    !field.FieldType.FullName!.Contains("SafeHandle", StringComparison.Ordinal)) &&
            leaseType.GetMethods(
                    BindingFlags.Instance |
                    BindingFlags.Static |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(method =>
                    !method.Name.Contains("Serialize", StringComparison.OrdinalIgnoreCase) &&
                    !method.Name.Contains("Send", StringComparison.OrdinalIgnoreCase) &&
                    !method.Name.Contains("Recover", StringComparison.OrdinalIgnoreCase) &&
                    !method.Name.Contains("Native", StringComparison.OrdinalIgnoreCase)),
            "Broker capability lease is not sealed, volatile, and disposable");

        using (var consent = CreateCapabilityConsentFixture(
                   "capability-positive",
                   0x81,
                   BrokerEpoch,
                   WindowsSessionId))
        using (var peer = CreateCapabilityPeerFixture(WindowsSessionId))
        using (var runtime = CreateCapabilityRuntimeLease(0x81))
        {
            var sessionOwnedArrays = GetOwnedByteArrays(consent.Session);
            using var clock = new FakeCapabilityLeaseClock(consent.Session.CreatedTimestamp);
            var brokerSnapshot = CreateManagedRuntimeSnapshot(BrokerEpoch, runtime.Identity);
            var lease = BrokerCapabilityLeaseV1.Create(
                consent.Session,
                consent.Snapshot,
                consent.Generation,
                consent.Credential,
                peer.Connection,
                brokerSnapshot,
                runtime,
                clock);
            var leaseOwnedArrays = GetOwnedByteArrays(lease);
            Ensure(
                sessionOwnedArrays.All(array => array.All(value => value == 0)),
                "capability issuance did not clear the consumed fresh-presence session");
            ExpectObjectDisposed(() => _ = consent.Session.SessionId);
            Ensure(
                lease.BrokerEpoch == BrokerEpoch &&
                lease.WindowsSessionId == WindowsSessionId &&
                lease.LedgerId == consent.Grant.LedgerId &&
                lease.LedgerRevision == consent.Grant.Revision &&
                lease.LedgerEntrySha256 == consent.Grant.EntrySha256 &&
                lease.GenerationSha256 == consent.Generation.GenerationSha256 &&
                lease.Capability == BrokerConsentLedgerV1.CapabilityName &&
                lease.GuardianProcessId == CapabilityPeerProcessId &&
                lease.RuntimeId == runtime.Identity.RuntimeId &&
                lease.RuntimeProcessId == runtime.Identity.ProcessId &&
                lease.FreshPresenceTimestamp > 0 &&
                lease.IssuedTimestamp >= lease.FreshPresenceTimestamp &&
                lease.FreshSessionId.Length == 32 &&
                lease.LeaseId.Length == 32 &&
                leaseOwnedArrays.Length == 4,
                "capability lease lost an exact volatile authority binding");
            var returnedLeaseId = lease.LeaseId;
            var returnedSessionId = lease.FreshSessionId;
            returnedLeaseId[0] ^= 0xFF;
            returnedSessionId[0] ^= 0xFF;
            Ensure(
                !lease.LeaseId.SequenceEqual(returnedLeaseId) &&
                !lease.FreshSessionId.SequenceEqual(returnedSessionId),
                "capability lease exposed an owned identity buffer");

            lease.Consume(
                consent.Snapshot,
                consent.Generation,
                consent.Credential,
                peer.Connection,
                brokerSnapshot,
                runtime);
            Ensure(
                leaseOwnedArrays.All(array => array.All(value => value == 0)) &&
                runtime.DisposeCount == 0 &&
                !peer.Connection.Completion.IsCompleted,
                "capability consumption retained bytes or disposed an external owner");
            ExpectObjectDisposed(() => _ = lease.LeaseId);
            ExpectCapabilityLeaseCode(
                () => lease.Consume(
                    consent.Snapshot,
                    consent.Generation,
                    consent.Credential,
                    peer.Connection,
                    brokerSnapshot,
                    runtime),
                "capability-lease-consumed");
            lease.Dispose();
        }

        using (var consent = CreateCapabilityConsentFixture(
                   "capability-double-issue",
                   0x82,
                   BrokerEpoch,
                   WindowsSessionId))
        using (var peer = CreateCapabilityPeerFixture(WindowsSessionId))
        using (var runtime = CreateCapabilityRuntimeLease(0x82))
        {
            var snapshot = CreateManagedRuntimeSnapshot(BrokerEpoch, runtime.Identity);
            using var clock = new FakeCapabilityLeaseClock(consent.Session.CreatedTimestamp);
            using var first = BrokerCapabilityLeaseV1.Create(
                consent.Session,
                consent.Snapshot,
                consent.Generation,
                consent.Credential,
                peer.Connection,
                snapshot,
                runtime,
                clock);
            ExpectCapabilityLeaseCode(
                () => BrokerCapabilityLeaseV1.Create(
                    consent.Session,
                    consent.Snapshot,
                    consent.Generation,
                    consent.Credential,
                    peer.Connection,
                    snapshot,
                    runtime,
                    clock).Dispose(),
                "capability-fresh-presence-invalid");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-expired",
                   0x83,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            fixture.Clock.Advance(BrokerCapabilityLeaseV1.MaximumLifetime + TimeSpan.FromTicks(1));
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Consume(),
                "capability-lease-expired");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-clock-backwards",
                   0x84,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            fixture.Clock.SetTimestamp(fixture.Lease.IssuedTimestamp - 1);
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Consume(),
                "capability-clock-invalid");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-peer-reference",
                   0x85,
                   BrokerEpoch,
                   WindowsSessionId))
        using (var otherPeer = CreateCapabilityPeerFixture(WindowsSessionId))
        {
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Lease.Consume(
                    fixture.Consent.Snapshot,
                    fixture.Consent.Generation,
                    fixture.Consent.Credential,
                    otherPeer.Connection,
                    fixture.BrokerSnapshot,
                    fixture.Runtime),
                "capability-peer-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-peer-drift",
                   0x86,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            fixture.Peer.DriftProcessIdentity();
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Consume(),
                "capability-peer-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-runtime-reference",
                   0x87,
                   BrokerEpoch,
                   WindowsSessionId))
        using (var otherRuntime = CreateCapabilityRuntimeLease(0x99))
        {
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Lease.Consume(
                    fixture.Consent.Snapshot,
                    fixture.Consent.Generation,
                    fixture.Consent.Credential,
                    fixture.Peer.Connection,
                    fixture.BrokerSnapshot,
                    otherRuntime),
                "capability-runtime-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-runtime-drift",
                   0x88,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            fixture.Runtime.DriftIdentity();
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Consume(),
                "capability-runtime-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-runtime-exit",
                   0x89,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            fixture.Runtime.CompleteNaturalExit();
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Consume(),
                "capability-runtime-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-runtime-state",
                   0x8A,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            fixture.BrokerSnapshot = fixture.BrokerSnapshot with
            {
                State = CodexCdpBrokerState.ManagedUnverified
            };
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Consume(),
                "capability-runtime-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-broker-epoch",
                   0x8B,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            fixture.BrokerSnapshot = fixture.BrokerSnapshot with
            {
                BrokerEpoch = "fedcba9876543210fedcba9876543210"
            };
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Consume(),
                "capability-broker-epoch-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-ledger-drift",
                   0x8C,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            var successor = CreateCapabilitySuccessorSnapshot(fixture.Consent, 0xBC);
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Lease.Consume(
                    successor,
                    fixture.Consent.Generation,
                    fixture.Consent.Credential,
                    fixture.Peer.Connection,
                    fixture.BrokerSnapshot,
                    fixture.Runtime),
                "capability-ledger-head-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-generation-drift",
                   0x8D,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Lease.Consume(
                    fixture.Consent.Snapshot,
                    CreateGeneration("capability-generation-different"),
                    fixture.Consent.Credential,
                    fixture.Peer.Connection,
                    fixture.BrokerSnapshot,
                    fixture.Runtime),
                "capability-package-generation-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-credential-drift",
                   0x8E,
                   BrokerEpoch,
                   WindowsSessionId))
        using (var wrongCredential = CreateRegisteredCredential(
                   BrokerWebAuthnTestVectorsV1.CredentialId(0x20),
                   keyVariant: 1))
        {
            ExpectCapabilityLeaseInvalidated(
                fixture.Lease,
                () => fixture.Lease.Consume(
                    fixture.Consent.Snapshot,
                    fixture.Consent.Generation,
                    wrongCredential,
                    fixture.Peer.Connection,
                    fixture.BrokerSnapshot,
                    fixture.Runtime),
                "capability-credential-changed");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-concurrent-consume",
                   0x8F,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            var results = Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
            {
                try
                {
                    fixture.Consume();
                    return "success";
                }
                catch (BrokerCapabilityLeaseException exception)
                {
                    return exception.Code;
                }
            }))).GetAwaiter().GetResult();
            Ensure(
                results.Count(result => result == "success") == 1 &&
                results.Count(result => result == "capability-lease-consumed") == 15 &&
                GetOwnedByteArrays(fixture.Lease).All(array => array.All(value => value == 0)),
                "concurrent capability consumption did not settle exactly once");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-concurrent-dispose",
                   0x90,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            var ownedArrays = GetOwnedByteArrays(fixture.Lease);
            fixture.Clock.BlockNextTimestamp();
            var consumeTask = Task.Run(() => fixture.Consume());
            Task? disposeTask = null;
            try
            {
                Ensure(
                    fixture.Clock.WaitForBlockedTimestamp(TimeSpan.FromSeconds(5)),
                    "capability consumption did not enter the controlled clock boundary");
                disposeTask = Task.Run(() => fixture.Lease.Dispose());
                Ensure(
                    !disposeTask.Wait(TimeSpan.FromMilliseconds(100)),
                    "concurrent capability disposal returned before consumption cleared authority");
            }
            finally
            {
                fixture.Clock.ReleaseBlockedTimestamp();
            }

            Task.WhenAll(
                    consumeTask,
                    disposeTask ?? Task.CompletedTask)
                .GetAwaiter()
                .GetResult();
            Ensure(
                ownedArrays.All(array => array.All(value => value == 0)) &&
                fixture.Runtime.DisposeCount == 0 &&
                !fixture.Peer.Connection.Completion.IsCompleted,
                "concurrent capability disposal retained bytes or disposed an external owner");
        }

        using (var fixture = CreateCapabilityLeaseFixture(
                   "capability-dispose",
                   0x91,
                   BrokerEpoch,
                   WindowsSessionId))
        {
            var ownedArrays = GetOwnedByteArrays(fixture.Lease);
            fixture.Lease.Dispose();
            Ensure(
                ownedArrays.All(array => array.All(value => value == 0)) &&
                fixture.Runtime.DisposeCount == 0 &&
                !fixture.Peer.Connection.Completion.IsCompleted,
                "disposing a capability lease retained bytes or disposed an external owner");
            ExpectObjectDisposed(() => _ = fixture.Lease.LeaseId);
            fixture.Lease.Dispose();
        }
    }

    private static CapabilityConsentFixture CreateCapabilityConsentFixture(
        string generationSeed,
        byte nonceSeed,
        string brokerEpoch,
        uint windowsSessionId)
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generation = CreateGeneration(generationSeed);
        var credentialId = BrokerWebAuthnTestVectorsV1.CredentialId();
        var credential = CreateRegisteredCredential(credentialId, keyVariant: 1);
        try
        {
            var receiptBytes = Enumerable.Repeat(nonceSeed, 16).ToArray();
            var receiptId = new Guid(receiptBytes);
            var grant = BrokerWebAuthnTestVectorsV1.CreateVerifiedGrant(
                genesis,
                0,
                generation,
                receiptId,
                credentialId,
                BrokerWebAuthnTestVectorsV1.Nonce(nonceSeed),
                IssuedAtUtcTicks + nonceSeed);
            var reopened = BrokerConsentLedgerV1.Parse(BrokerConsentLedgerV1.Serialize(grant));
            var snapshot = CreatePendingSnapshot(reopened);
            var session = CreateFreshSession(
                brokerEpoch,
                windowsSessionId,
                snapshot,
                generation,
                nonceSeed);
            return new CapabilityConsentFixture(
                generation,
                reopened,
                snapshot,
                credential,
                session);
        }
        catch
        {
            credential.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credentialId);
        }
    }

    private static CapabilityLeaseFixture CreateCapabilityLeaseFixture(
        string generationSeed,
        byte nonceSeed,
        string brokerEpoch,
        uint windowsSessionId)
    {
        var consent = CreateCapabilityConsentFixture(
            generationSeed,
            nonceSeed,
            brokerEpoch,
            windowsSessionId);
        CapabilityPeerFixture? peer = null;
        FakeCapabilityRuntimeLease? runtime = null;
        BrokerCapabilityLeaseV1? lease = null;
        try
        {
            peer = CreateCapabilityPeerFixture(windowsSessionId);
            runtime = CreateCapabilityRuntimeLease(nonceSeed);
            var brokerSnapshot = CreateManagedRuntimeSnapshot(brokerEpoch, runtime.Identity);
            var clock = new FakeCapabilityLeaseClock(consent.Session.CreatedTimestamp);
            lease = BrokerCapabilityLeaseV1.Create(
                consent.Session,
                consent.Snapshot,
                consent.Generation,
                consent.Credential,
                peer.Connection,
                brokerSnapshot,
                runtime,
                clock);
            var result = new CapabilityLeaseFixture(
                consent,
                peer,
                runtime,
                clock,
                brokerSnapshot,
                lease);
            consent = null!;
            peer = null;
            runtime = null;
            lease = null;
            return result;
        }
        finally
        {
            lease?.Dispose();
            runtime?.Dispose();
            peer?.Dispose();
            consent?.Dispose();
        }
    }

    private static BrokerConsentLedgerStoreSnapshotV1 CreateCapabilitySuccessorSnapshot(
        CapabilityConsentFixture consent,
        byte nonceSeed)
    {
        var credentialId = consent.Credential.CredentialId;
        try
        {
            var receiptId = new Guid(Enumerable.Repeat(nonceSeed, 16).ToArray());
            var successor = BrokerWebAuthnTestVectorsV1.CreateVerifiedGrant(
                consent.Grant,
                consent.Grant.Revision,
                consent.Generation,
                receiptId,
                credentialId,
                BrokerWebAuthnTestVectorsV1.Nonce(nonceSeed),
                IssuedAtUtcTicks + nonceSeed);
            return CreatePendingSnapshot(
                BrokerConsentLedgerV1.Parse(BrokerConsentLedgerV1.Serialize(successor)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credentialId);
        }
    }

    private static CodexCdpBrokerSnapshot CreateManagedRuntimeSnapshot(
        string brokerEpoch,
        CodexCdpRuntimeIdentity runtimeIdentity) =>
        new(
            brokerEpoch,
            Sequence: 10,
            CodexCdpBrokerState.ManagedReady,
            ConnectedClients: 1,
            OwnsManagedCodex: true,
            CodexCdpBrokerRetirementIntent.None,
            BrokerExitIntent: false,
            ManagedCodexExitIntent: false,
            runtimeIdentity.LaunchOperationId,
            AcceptedOperationCount: 1);

    private static FakeCapabilityRuntimeLease CreateCapabilityRuntimeLease(byte seed) =>
        new(
            new CodexCdpRuntimeIdentity(
                "runtime-capability-" + seed.ToString("X2"),
                "operation-capability-" + seed.ToString("X2"),
                5000 + seed,
                CapabilityRuntimeCreationTime.AddTicks(seed)));

    private static void ExpectCapabilityLeaseInvalidated(
        BrokerCapabilityLeaseV1 lease,
        Action action,
        string expectedCode)
    {
        var ownedArrays = GetOwnedByteArrays(lease);
        ExpectCapabilityLeaseCode(action, expectedCode);
        Ensure(
            ownedArrays.All(array => array.All(value => value == 0)),
            "invalidated capability lease retained owned bytes");
        ExpectObjectDisposed(() => _ = lease.LeaseId);
        lease.Dispose();
    }

    private static void ExpectCapabilityLeaseCode(Action action, string expectedCode)
    {
        try
        {
            action();
        }
        catch (BrokerCapabilityLeaseException exception) when (
            string.Equals(exception.Code, expectedCode, StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException(
            "Expected Broker capability-lease code " + expectedCode + ".");
    }

    private const uint CapabilityPeerProcessId = 43210;
    private const ulong CapabilityPeerVolumeSerial = 0x1234;
    private const string CapabilityPeerUserSid = "S-1-5-21-111-222-333-1001";
    private const string CapabilityPeerLogonSid = "S-1-5-5-1-2";
    private const string CapabilityPeerConnectionNonce =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string CapabilityPeerReleaseId = "release-capability-20260806";
    private const string CapabilityPeerManifestSha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string CapabilityPeerReleaseRoot =
        @"D:\CodexGuardian\release-capability-20260806";
    private static readonly DateTimeOffset CapabilityPeerCreationTime =
        new(2026, 8, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset CapabilityRuntimeCreationTime =
        new(2026, 8, 6, 12, 30, 0, TimeSpan.Zero);

    private static CapabilityPeerFixture CreateCapabilityPeerFixture(uint sessionId)
    {
        var release = CreateCapabilityPeerManifest().GetArtifactSet(BrokerPeerRole.Guardian);
        var identity = CreateCapabilityPeerIdentity(
            release,
            CapabilityPeerProcessId,
            sessionId);
        var retained = new MutableCapabilityPeerIdentityLease(
            identity,
            new RetainedReleaseHandleSet(
                release.Root,
                release.Artifacts.Select(artifact => artifact.RelativePath).ToArray()));
        var platform = new CapabilityPeerPlatform(release, retained, identity, sessionId);
        var verifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            beforeAuthorityTransfer: null,
            afterAuthorityTransfer: null,
            maximumConnections: 1);
        try
        {
            var pending = verifier.BeginVerification(
                platform,
                NamedPipePeerKind.Client,
                new BrokerPeerExpectation(
                    identity.Token,
                    WindowsAppModelIdentity.Unpackaged,
                    release,
                    CapabilityPeerConnectionNonce,
                    CapabilityPeerProcessId,
                    CapabilityPeerCreationTime));
            var verified = pending.CompleteAsync().AsTask().GetAwaiter().GetResult();
            var connection = new AuthenticatedPipePeerConnection(
                verified,
                platform,
                BrokerPeerRole.Guardian);
            var managedEntry =
                GuardianManagedEntryProofOfflineTests.CreateVerifiedConnectionFixture(connection);
            return new CapabilityPeerFixture(
                managedEntry,
                retained,
                release,
                sessionId);
        }
        catch
        {
            platform.Dispose();
            throw;
        }
    }

    private static VerifiedReleaseManifest CreateCapabilityPeerManifest() =>
        VerifiedReleaseManifest.CreateFromVerifiedPayload(
            CapabilityPeerReleaseId,
            CapabilityPeerManifestSha256,
            new WindowsReleaseRootIdentity(
                CapabilityPeerReleaseRoot,
                FileAttributes.Directory | FileAttributes.Archive,
                CapabilityPeerVolumeSerial,
                new string('a', 32),
                true),
            CreateCapabilityPeerRoleDefinition(BrokerPeerRole.Guardian),
            CreateCapabilityPeerRoleDefinition(BrokerPeerRole.Broker));

    private static VerifiedReleaseRoleArtifacts CreateCapabilityPeerRoleDefinition(
        BrokerPeerRole role)
    {
        var stem = role == BrokerPeerRole.Guardian
            ? "CodexGuardian"
            : "CodexGuardian.Broker";
        var seed = role == BrokerPeerRole.Guardian ? '1' : '5';
        return new VerifiedReleaseRoleArtifacts(
            role,
            stem + ".exe",
            stem + ".dll",
            stem + ".deps.json",
            stem + ".runtimeconfig.json",
            new[]
            {
                CreateCapabilityPeerArtifact(
                    ReleaseArtifactKind.AppHostExe,
                    stem + ".exe",
                    seed,
                    128 * 1024),
                CreateCapabilityPeerArtifact(
                    ReleaseArtifactKind.ManagedEntryDll,
                    stem + ".dll",
                    (char)(seed + 1),
                    512 * 1024),
                CreateCapabilityPeerArtifact(
                    ReleaseArtifactKind.DepsJson,
                    stem + ".deps.json",
                    (char)(seed + 2),
                    64 * 1024),
                CreateCapabilityPeerArtifact(
                    ReleaseArtifactKind.RuntimeConfigJson,
                    stem + ".runtimeconfig.json",
                    (char)(seed + 3),
                    4 * 1024)
            });
    }

    private static WindowsArtifactIdentity CreateCapabilityPeerArtifact(
        ReleaseArtifactKind kind,
        string relativePath,
        char seed,
        long length) =>
        new(
            kind,
            relativePath,
            Path.Combine(CapabilityPeerReleaseRoot, relativePath),
            FileAttributes.Archive,
            length,
            new string(seed, 64),
            CapabilityPeerVolumeSerial,
            new string(seed, 32),
            1,
            true);

    private static WindowsProcessIdentity CreateCapabilityPeerIdentity(
        VerifiedReleaseArtifactSet release,
        uint processId,
        uint sessionId)
    {
        var token = new WindowsTokenIdentity(
            CapabilityPeerUserSid,
            CapabilityPeerLogonSid,
            1,
            0x0000000100000002,
            sessionId,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Primary,
            null);
        var appHost = release.Artifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe);
        return new WindowsProcessIdentity(
            processId,
            CapabilityPeerCreationTime,
            sessionId,
            token,
            WindowsAppModelIdentity.Unpackaged,
            appHost.FinalPath,
            true,
            release.Root,
            release.Artifacts);
    }

    private sealed class CapabilityConsentFixture : IDisposable
    {
        internal CapabilityConsentFixture(
            CodexPackageGenerationV1 generation,
            BrokerConsentLedgerDocumentV1 grant,
            BrokerConsentLedgerStoreSnapshotV1 snapshot,
            BrokerWebAuthnRegisteredCredentialV1 credential,
            BrokerFreshPresenceSessionV1 session)
        {
            Generation = generation;
            Grant = grant;
            Snapshot = snapshot;
            Credential = credential;
            Session = session;
        }

        internal CodexPackageGenerationV1 Generation { get; }

        internal BrokerConsentLedgerDocumentV1 Grant { get; }

        internal BrokerConsentLedgerStoreSnapshotV1 Snapshot { get; }

        internal BrokerWebAuthnRegisteredCredentialV1 Credential { get; }

        internal BrokerFreshPresenceSessionV1 Session { get; }

        public void Dispose()
        {
            Session.Dispose();
            Credential.Dispose();
        }
    }

    private sealed class CapabilityLeaseFixture : IDisposable
    {
        internal CapabilityLeaseFixture(
            CapabilityConsentFixture consent,
            CapabilityPeerFixture peer,
            FakeCapabilityRuntimeLease runtime,
            FakeCapabilityLeaseClock clock,
            CodexCdpBrokerSnapshot brokerSnapshot,
            BrokerCapabilityLeaseV1 lease)
        {
            Consent = consent;
            Peer = peer;
            Runtime = runtime;
            Clock = clock;
            BrokerSnapshot = brokerSnapshot;
            Lease = lease;
        }

        internal CapabilityConsentFixture Consent { get; }

        internal CapabilityPeerFixture Peer { get; }

        internal FakeCapabilityRuntimeLease Runtime { get; }

        internal FakeCapabilityLeaseClock Clock { get; }

        internal CodexCdpBrokerSnapshot BrokerSnapshot { get; set; }

        internal BrokerCapabilityLeaseV1 Lease { get; }

        internal void Consume() => Lease.Consume(
            Consent.Snapshot,
            Consent.Generation,
            Consent.Credential,
            Peer.Connection,
            BrokerSnapshot,
            Runtime);

        public void Dispose()
        {
            Lease.Dispose();
            Runtime.Dispose();
            Peer.Dispose();
            Consent.Dispose();
            Clock.Dispose();
        }
    }

    private sealed class FakeCapabilityLeaseClock : IBrokerCapabilityLeaseClockV1, IDisposable
    {
        private readonly ManualResetEventSlim _blockedTimestampEntered = new(false);
        private readonly ManualResetEventSlim _releaseBlockedTimestamp = new(false);
        private int _blockNextTimestamp;
        private long _timestamp;

        internal FakeCapabilityLeaseClock(long timestamp)
        {
            _timestamp = timestamp;
        }

        public long GetTimestamp()
        {
            if (Interlocked.Exchange(ref _blockNextTimestamp, 0) != 0)
            {
                _blockedTimestampEntered.Set();
                _releaseBlockedTimestamp.Wait();
            }

            return Volatile.Read(ref _timestamp);
        }

        public TimeSpan GetElapsedTime(long startingTimestamp, long endingTimestamp) =>
            Stopwatch.GetElapsedTime(startingTimestamp, endingTimestamp);

        internal void Advance(TimeSpan duration)
        {
            var delta = checked((long)Math.Ceiling(duration.TotalSeconds * Stopwatch.Frequency));
            Interlocked.Add(ref _timestamp, delta);
        }

        internal void BlockNextTimestamp()
        {
            _blockedTimestampEntered.Reset();
            _releaseBlockedTimestamp.Reset();
            Volatile.Write(ref _blockNextTimestamp, 1);
        }

        internal bool WaitForBlockedTimestamp(TimeSpan timeout) =>
            _blockedTimestampEntered.Wait(timeout);

        internal void ReleaseBlockedTimestamp() => _releaseBlockedTimestamp.Set();

        internal void SetTimestamp(long timestamp) => Volatile.Write(ref _timestamp, timestamp);

        public void Dispose()
        {
            _blockedTimestampEntered.Dispose();
            _releaseBlockedTimestamp.Dispose();
        }
    }

    private sealed class FakeCapabilityRuntimeLease : ICodexCdpHandleLease, IDisposable
    {
        private readonly TaskCompletionSource<CodexCdpRuntimeExitResult> _exit = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private CodexCdpRuntimeIdentity _identity;
        private int _alive = 1;
        private int _disposeCount;

        internal FakeCapabilityRuntimeLease(CodexCdpRuntimeIdentity identity)
        {
            _identity = identity;
        }

        public CodexCdpRuntimeIdentity Identity => Volatile.Read(ref _identity);

        public bool IsAlive => Volatile.Read(ref _alive) != 0;

        public Task<CodexCdpRuntimeExitResult> Exit => _exit.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal void DriftIdentity()
        {
            var current = Identity;
            Volatile.Write(
                ref _identity,
                new CodexCdpRuntimeIdentity(
                    current.RuntimeId + "-changed",
                    current.LaunchOperationId,
                    current.ProcessId,
                    current.CreationTimeUtc));
        }

        internal void CompleteNaturalExit()
        {
            Interlocked.Exchange(ref _alive, 0);
            _exit.TrySetResult(CodexCdpRuntimeExitResult.Natural(
                0,
                Identity.CreationTimeUtc.AddSeconds(1)));
        }

        public ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref _disposeCount);
            return ValueTask.CompletedTask;
        }

        public void Dispose() => DisposeAsync().GetAwaiter().GetResult();
    }

    private sealed class CapabilityPeerFixture : IDisposable
    {
        private readonly MutableCapabilityPeerIdentityLease _retained;
        private readonly VerifiedReleaseArtifactSet _release;
        private readonly uint _sessionId;

        internal CapabilityPeerFixture(
            VerifiedGuardianManagedEntryConnectionV1 connection,
            MutableCapabilityPeerIdentityLease retained,
            VerifiedReleaseArtifactSet release,
            uint sessionId)
        {
            Connection = connection;
            _retained = retained;
            _release = release;
            _sessionId = sessionId;
        }

        internal VerifiedGuardianManagedEntryConnectionV1 Connection { get; }

        internal void DriftProcessIdentity() => _retained.Identity =
            CreateCapabilityPeerIdentity(
                _release,
                CapabilityPeerProcessId + 1,
                _sessionId);

        public void Dispose() => Connection.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private sealed class MutableCapabilityPeerIdentityLease : IRetainedPeerIdentityLease
    {
        private WindowsProcessIdentity _identity;
        private int _disposed;

        internal MutableCapabilityPeerIdentityLease(
            WindowsProcessIdentity identity,
            RetainedReleaseHandleSet retainedHandles)
        {
            _identity = identity;
            RetainedHandles = retainedHandles;
        }

        internal WindowsProcessIdentity Identity
        {
            get => Volatile.Read(ref _identity);
            set => Volatile.Write(ref _identity, value);
        }

        public bool IsAlive
        {
            get
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                return true;
            }
        }

        public RetainedReleaseHandleSet RetainedHandles { get; }

        public WindowsProcessIdentity Capture()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return Identity;
        }

        public void Dispose() => Interlocked.Exchange(ref _disposed, 1);
    }

    private sealed class CapabilityPeerPlatform :
        INamedPipePeerTrustPlatform,
        INamedPipePeerMessageTransport
    {
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly WindowsProcessIdentity _initialIdentity;
        private readonly MutableCapabilityPeerIdentityLease _retained;
        private readonly VerifiedReleaseArtifactSet _release;
        private readonly uint _sessionId;
        private int _disposed;
        private long _readGeneration;

        internal CapabilityPeerPlatform(
            VerifiedReleaseArtifactSet release,
            MutableCapabilityPeerIdentityLease retained,
            WindowsProcessIdentity initialIdentity,
            uint sessionId)
        {
            _release = release;
            _retained = retained;
            _initialIdentity = initialIdentity;
            _sessionId = sessionId;
        }

        public DateTimeOffset UtcNow => CapabilityPeerCreationTime.AddMinutes(1);

        public long ReadGeneration => Volatile.Read(ref _readGeneration);

        public Task Completion => _completion.Task;

        public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
        {
            Ensure(peerKind == NamedPipePeerKind.Client, "capability peer used the wrong pipe direction");
            return new PipePeerKernelIdentity(CapabilityPeerProcessId, _sessionId);
        }

        public IRetainedPeerIdentityLease OpenRetainedPeer(
            uint processId,
            VerifiedReleaseArtifactSet release)
        {
            Ensure(
                processId == CapabilityPeerProcessId && ReferenceEquals(release, _release),
                "capability peer opened a different retained identity");
            return _retained;
        }

        public ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
            NamedPipePeerKind peerKind,
            int maximumHelloBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hello = BrokerPeerHelloProtocol.Serialize(new BrokerPeerHello(
                BrokerPeerHelloProtocol.ProtocolVersion,
                BrokerPeerRole.Guardian,
                CapabilityPeerProcessId,
                _sessionId,
                CapabilityPeerCreationTime,
                CapabilityPeerConnectionNonce,
                CapabilityPeerReleaseId,
                CapabilityPeerManifestSha256));
            Ensure(hello.Length <= maximumHelloBytes, "capability peer hello exceeded its bound");
            var kernel = CaptureKernelPeer(peerKind);
            return ValueTask.FromResult(new PipePeerHelloReadEvidence(
                hello,
                Interlocked.Increment(ref _readGeneration),
                kernel,
                kernel,
                _initialIdentity.Token with
                {
                    TokenType = WindowsTokenType.Impersonation,
                    ImpersonationLevel = WindowsSecurityImpersonationLevel.Identification
                }));
        }

        public ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
            int maximumMessageBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
        }

        public ValueTask WriteMessageAsync(
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }

        public void AbortHandshake(string boundedFailureCode) =>
            ArgumentException.ThrowIfNullOrWhiteSpace(boundedFailureCode);

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _completion.TrySetResult();
            }
        }
    }

    private static void TestFreshPresenceSession()
    {
        const string BrokerEpoch = "0123456789abcdef0123456789abcdef";
        const uint WindowsSessionId = 42;
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generation = CreateGeneration("fresh-presence-generation");
        var credentialId = BrokerWebAuthnTestVectorsV1.CredentialId();
        var grant = BrokerWebAuthnTestVectorsV1.CreateVerifiedGrant(
            genesis,
            0,
            generation,
            ReceiptId,
            credentialId,
            BrokerWebAuthnTestVectorsV1.Nonce(0x40),
            IssuedAtUtcTicks);
        var reopened = BrokerConsentLedgerV1.Parse(BrokerConsentLedgerV1.Serialize(grant));
        var snapshot = CreatePendingSnapshot(reopened);
        var expectedFreshNonce = BrokerWebAuthnTestVectorsV1.Nonce(0x70);
        var mutableFreshNonce = expectedFreshNonce.ToArray();
        var persistedEvidence = BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened);
        var persistedOwnedArrays = GetOwnedByteArrays(persistedEvidence);
        var statement = BrokerFreshPresenceStatementV1.Create(
            BrokerEpoch,
            WindowsSessionId,
            snapshot,
            generation,
            BrokerConsentLedgerV1.CapabilityName,
            persistedEvidence,
            mutableFreshNonce);
        var statementOwnedArrays = GetOwnedByteArrays(statement);
        mutableFreshNonce[0] ^= 0xFF;

        var grantEntry = (BrokerConsentGrantEntryV1)reopened.Entry;
        var receipt = grantEntry.Receipt;
        var expectedStatementJson =
            $"{{\"schema\":\"codex-broker-fresh-presence-statement-v1\"," +
            $"\"brokerEpoch\":\"{BrokerEpoch}\",\"windowsSessionId\":{WindowsSessionId}," +
            $"\"ledgerId\":\"{reopened.LedgerId:D}\",\"ledgerRevision\":{reopened.Revision}," +
            $"\"ledgerEntrySha256\":\"{reopened.EntrySha256}\"," +
            $"\"receiptId\":\"{receipt.ReceiptId:D}\"," +
            $"\"generationSha256\":\"{generation.GenerationSha256}\"," +
            $"\"capability\":\"{BrokerConsentLedgerV1.CapabilityName}\"," +
            $"\"credentialIdBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(receipt.CredentialIdBase64) + "," +
            $"\"credentialPublicKeySha256\":\"{receipt.CredentialPublicKeySha256}\"," +
            $"\"freshNonceBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(Convert.ToBase64String(expectedFreshNonce)) + "}";
        var expectedStatementBytes = Encoding.UTF8.GetBytes(expectedStatementJson);
        var returnedStatement = statement.CanonicalStatementBytes;
        returnedStatement[0] ^= 0xFF;
        var returnedStatementCredential = statement.CredentialId;
        returnedStatementCredential[0] ^= 0xFF;
        var actualStatementBytes = statement.CanonicalStatementBytes;
        Ensure(
            statement.Schema == "codex-broker-fresh-presence-statement-v1" &&
            statement.BrokerEpoch == BrokerEpoch &&
            statement.WindowsSessionId == WindowsSessionId &&
            statement.LedgerId == reopened.LedgerId &&
            statement.LedgerRevision == reopened.Revision &&
            statement.LedgerEntrySha256 == reopened.EntrySha256 &&
            statement.ReceiptId == receipt.ReceiptId &&
            statement.GenerationSha256 == generation.GenerationSha256 &&
            statement.GenerationCanonicalJson == generation.CanonicalJson &&
            statement.Capability == BrokerConsentLedgerV1.CapabilityName,
            "fresh-presence statement changed a scalar identity");
        Ensure(
            statement.CredentialIdBase64 == receipt.CredentialIdBase64 &&
            statement.CredentialPublicKeySha256 == receipt.CredentialPublicKeySha256 &&
            statement.FreshNonceBase64 == Convert.ToBase64String(expectedFreshNonce) &&
            statement.FreshNonce.SequenceEqual(expectedFreshNonce) &&
            statement.CredentialId.SequenceEqual(credentialId) &&
            Convert.ToHexString(SHA256.HashData(statement.SubjectPublicKeyInfo)) ==
                receipt.CredentialPublicKeySha256,
            "fresh-presence statement changed credential or nonce identity");
        var firstCanonicalDifference = Enumerable.Range(
                0,
                Math.Min(actualStatementBytes.Length, expectedStatementBytes.Length))
            .FirstOrDefault(index => actualStatementBytes[index] != expectedStatementBytes[index], -1);
        Ensure(
            actualStatementBytes.SequenceEqual(expectedStatementBytes),
            $"fresh-presence statement canonical bytes changed expectedLength={expectedStatementBytes.Length} actualLength={actualStatementBytes.Length} firstDifference={firstCanonicalDifference} expectedByte={(firstCanonicalDifference < 0 ? -1 : expectedStatementBytes[firstCanonicalDifference])} actualByte={(firstCanonicalDifference < 0 ? -1 : actualStatementBytes[firstCanonicalDifference])}");
        Ensure(
            statement.StatementSha256 ==
                Convert.ToHexString(SHA256.HashData(expectedStatementBytes)),
            "fresh-presence statement canonical hash changed");
        Ensure(
            statementOwnedArrays.Length == 4,
            "fresh-presence statement ownership surface changed");
        Ensure(
            persistedOwnedArrays.All(array => array.All(value => value == 0)),
            "fresh statement did not consume and clear persisted receipt evidence");
        ExpectObjectDisposed(() => _ = persistedEvidence.ProofEnvelope);
        ExpectObjectDisposed(() => _ = persistedEvidence.Purpose);

        using (var invalidEpochEvidence =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            ExpectVerificationCode(
                () => BrokerFreshPresenceStatementV1.Create(
                    "0123456789ABCDEF0123456789ABCDEF",
                    WindowsSessionId,
                    snapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    invalidEpochEvidence,
                    expectedFreshNonce).Dispose(),
                "consent-broker-epoch-changed");
        }

        using (var invalidSessionEvidence =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            ExpectVerificationCode(
                () => BrokerFreshPresenceStatementV1.Create(
                    BrokerEpoch,
                    0,
                    snapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    invalidSessionEvidence,
                    expectedFreshNonce).Dispose(),
                "consent-windows-session-changed");
        }

        using (var invalidCapabilityEvidence =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            ExpectVerificationCode(
                () => BrokerFreshPresenceStatementV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    snapshot,
                    generation,
                    "managed-readonly-cdp-v2",
                    invalidCapabilityEvidence,
                    expectedFreshNonce).Dispose(),
                "consent-ledger-head-changed");
        }

        using (var invalidSnapshotEvidence =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            var invalidSnapshot = new BrokerConsentLedgerStoreSnapshotV1(
                BrokerConsentLedgerStoreStateV1.ReceiptPendingVerification,
                reopened,
                new BrokerConsentLedgerStoreDiagnosticsV1(
                    BrokerConsentLedgerReplicaStateV1.Canonical,
                    BrokerConsentLedgerReplicaStateV1.Missing,
                    "store-receipt-pending-verification"));
            ExpectVerificationCode(
                () => BrokerFreshPresenceStatementV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    invalidSnapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    invalidSnapshotEvidence,
                    expectedFreshNonce).Dispose(),
                "consent-ledger-head-changed");
        }

        using (var forgedGenerationEvidence =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            ExpectVerificationCode(
                () => BrokerFreshPresenceStatementV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    snapshot,
                    CreateForgedGeneration(generation),
                    BrokerConsentLedgerV1.CapabilityName,
                    forgedGenerationEvidence,
                    expectedFreshNonce).Dispose(),
                "consent-package-generation-changed");
        }

        using (var invalidNonceEvidence =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            ExpectArgumentException(
                () => BrokerFreshPresenceStatementV1.Create(
                    BrokerEpoch,
                    WindowsSessionId,
                    snapshot,
                    generation,
                    BrokerConsentLedgerV1.CapabilityName,
                    invalidNonceEvidence,
                    new byte[31]).Dispose());
        }

        var clientData = BrokerWebAuthnClientDataV1.CreateFresh(statement);
        var domain = Encoding.ASCII.GetBytes(BrokerWebAuthnConstantsV1.FreshPresenceDomainSeparator);
        var challengeInput = domain.Concat(expectedStatementBytes).ToArray();
        var expectedChallenge = SHA256.HashData(challengeInput);
        var expectedClientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{BrokerWebAuthnBase64UrlV1.Encode(expectedChallenge)}\"," +
            $"\"origin\":\"{BrokerWebAuthnConstantsV1.Origin}\",\"crossOrigin\":false}}");
        Ensure(
            clientData.Type == BrokerWebAuthnConstantsV1.AssertionClientDataType &&
            clientData.ChallengeBytes.SequenceEqual(expectedChallenge) &&
            clientData.ClientDataJson.SequenceEqual(expectedClientDataJson) &&
            clientData.ClientDataHash.SequenceEqual(SHA256.HashData(expectedClientDataJson)),
            "fresh-presence client data changed its fixed domain or canonical bytes");

        using var freshVector = BrokerWebAuthnTestVectorsV1.CreateSignedAssertionForFresh(
            statement,
            credentialId,
            keyVariant: 1,
            statement.CredentialPublicKeySha256);
        var freshEvidence = BrokerWebAuthnReceiptVerifierV1.VerifyFreshAssertion(
            statement,
            freshVector.Credential,
            freshVector.Assertion);
        var freshEvidenceOwnedArrays = GetOwnedByteArrays(freshEvidence);
        Ensure(
            freshEvidence.Purpose == BrokerWebAuthnEvidencePurposeV1.FreshPresence &&
            freshEvidence.StatementSha256 == statement.StatementSha256 &&
            freshEvidence.LedgerId == statement.LedgerId &&
            freshEvidence.LedgerRevision == statement.LedgerRevision &&
            freshEvidence.LedgerEntrySha256 == statement.LedgerEntrySha256 &&
            freshEvidence.ReceiptId == statement.ReceiptId &&
            freshEvidence.GenerationSha256 == statement.GenerationSha256 &&
            freshEvidence.Capability == statement.Capability &&
            freshEvidence.BrokerEpoch == statement.BrokerEpoch &&
            freshEvidence.WindowsSessionId == statement.WindowsSessionId &&
            freshEvidence.CredentialId.SequenceEqual(statement.CredentialId) &&
            freshEvidence.ChallengeNonce.SequenceEqual(statement.FreshNonce) &&
            freshEvidence.ProofEnvelope.Length == 210,
            "fresh assertion verification lost a statement binding");

        var session = BrokerFreshPresenceSessionV1.Create(statement, freshEvidence);
        var sessionOwnedArrays = GetOwnedByteArrays(session);
        Ensure(
            freshEvidenceOwnedArrays.All(array => array.All(value => value == 0)),
            "session creation did not consume and clear fresh assertion evidence");
        ExpectObjectDisposed(() => _ = freshEvidence.ProofEnvelope);
        ExpectObjectDisposed(() => _ = freshEvidence.Purpose);
        Ensure(
            session.BrokerEpoch == BrokerEpoch &&
            session.WindowsSessionId == WindowsSessionId &&
            session.LedgerId == reopened.LedgerId &&
            session.LedgerRevision == reopened.Revision &&
            session.LedgerEntrySha256 == reopened.EntrySha256 &&
            session.ReceiptId == receipt.ReceiptId &&
            session.GenerationSha256 == generation.GenerationSha256 &&
            session.GenerationCanonicalJson == generation.CanonicalJson &&
            session.Capability == BrokerConsentLedgerV1.CapabilityName &&
            session.CredentialId.SequenceEqual(credentialId) &&
            session.CredentialPublicKeySha256 == receipt.CredentialPublicKeySha256 &&
            session.FreshNonce.SequenceEqual(expectedFreshNonce) &&
            session.SessionId.Length == 32 &&
            !session.SessionId.SequenceEqual(expectedFreshNonce) &&
            session.CreatedTimestamp > 0 &&
            sessionOwnedArrays.Length == 4,
            "volatile fresh-presence session did not pin every approved identity");
        session.Revalidate(
            BrokerEpoch,
            WindowsSessionId,
            snapshot,
            generation,
            BrokerConsentLedgerV1.CapabilityName,
            freshVector.Credential);

        using (var replayEvidence = BrokerWebAuthnReceiptVerifierV1.VerifyFreshAssertion(
                   statement,
                   freshVector.Credential,
                   freshVector.Assertion))
        {
            var replayOwnedArrays = GetOwnedByteArrays(replayEvidence);
            ExpectVerificationCode(
                () => BrokerFreshPresenceSessionV1.Create(statement, replayEvidence).Dispose(),
                "consent-fresh-presence-required");
            Ensure(
                replayOwnedArrays.All(array => array.All(value => value == 0)),
                "replayed fresh assertion evidence retained bytes");
        }

        using (var historicalEvidence =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            ExpectVerificationCode(
                () => BrokerFreshPresenceSessionV1.Create(statement, historicalEvidence).Dispose(),
                "consent-fresh-presence-required");
            ExpectObjectDisposed(() => _ = historicalEvidence.Purpose);
        }

        using (var otherPersisted =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        using (var otherStatement = BrokerFreshPresenceStatementV1.Create(
                   BrokerEpoch,
                   WindowsSessionId,
                   snapshot,
                   generation,
                   BrokerConsentLedgerV1.CapabilityName,
                   otherPersisted,
                   BrokerWebAuthnTestVectorsV1.Nonce(0x71)))
        {
            ExpectVerificationCode(
                () => BrokerWebAuthnReceiptVerifierV1.VerifyFreshAssertion(
                    otherStatement,
                    freshVector.Credential,
                    freshVector.Assertion).Dispose(),
                "user-presence-challenge-mismatch");
        }

        using (var attemptPersisted =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            var attempt = BrokerFreshPresenceAttemptV1.Create(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                attemptPersisted);
            var attemptOwnedArrays = GetOwnedByteArrays(attempt);
            var attemptStatement = attempt.Statement;
            var attemptStatementOwnedArrays = GetOwnedByteArrays(attemptStatement);
            using var attemptVector = BrokerWebAuthnTestVectorsV1.CreateSignedAssertionForFresh(
                attemptStatement,
                credentialId,
                keyVariant: 1,
                attemptStatement.CredentialPublicKeySha256);
            using var attemptFreshEvidence =
                BrokerWebAuthnReceiptVerifierV1.VerifyFreshAssertion(
                    attemptStatement,
                    attemptVector.Credential,
                    attemptVector.Assertion);
            var attemptSession = attempt.Complete(attemptFreshEvidence);
            Ensure(
                attemptOwnedArrays.Length == 1 &&
                attemptOwnedArrays[0].All(value => value == 0) &&
                attemptStatementOwnedArrays.All(array => array.All(value => value == 0)),
                "completed fresh-presence attempt retained nonce or statement bytes");
            ExpectObjectDisposed(() => _ = attemptFreshEvidence.Purpose);
            ExpectObjectDisposed(() => _ = attempt.Statement);
            ExpectVerificationCode(
                () => attempt.Complete(attemptFreshEvidence).Dispose(),
                "consent-fresh-presence-required");
            attemptSession.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                attemptVector.Credential);
            attemptSession.Dispose();
            attempt.Dispose();
        }

        using (var cancelledPersisted =
               BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            var cancelled = BrokerFreshPresenceAttemptV1.Create(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                cancelledPersisted);
            var cancelledOwnedArrays = GetOwnedByteArrays(cancelled);
            var cancelledStatementArrays = GetOwnedByteArrays(cancelled.Statement);
            cancelled.Cancel();
            Ensure(
                cancelledOwnedArrays.All(array => array.All(value => value == 0)) &&
                cancelledStatementArrays.All(array => array.All(value => value == 0)),
                "cancelled fresh-presence attempt retained owned bytes");
            ExpectObjectDisposed(() => _ = cancelled.Statement);
            cancelled.Dispose();
        }

        var successor = BrokerWebAuthnTestVectorsV1.CreateVerifiedGrant(
            reopened,
            1,
            generation,
            Guid.ParseExact("22222222-3333-4444-5555-666666666666", "D"),
            credentialId,
            BrokerWebAuthnTestVectorsV1.Nonce(0x50),
            IssuedAtUtcTicks + 1);
        var revoke = BrokerConsentLedgerTransition.CreateRevoke(
            reopened,
            1,
            BrokerConsentRevokeReasonV1.UserRequested,
            IssuedAtUtcTicks + 1);
        var proofEnvelope = Convert.FromBase64String(receipt.SignatureBase64);
        var receiptDrift = BrokerWebAuthnTestVectorsV1.RebindParsedGrant(
            reopened,
            proofEnvelope,
            receiptId: Guid.ParseExact("33333333-4444-5555-6666-777777777777", "D"));
        var differentGeneration = CreateGeneration("fresh-presence-different-generation");
        var forgedGenerationDigest = CreateForgedGeneration(generation);
        var forgedGenerationCanonical = CreateForgedGeneration(
            generation,
            generation.CanonicalJson + " ",
            generation.GenerationSha256);
        using var wrongCredentialId = CreateRegisteredCredential(
            BrokerWebAuthnTestVectorsV1.CredentialId(0x20),
            keyVariant: 1);
        using var wrongCredentialSpki = CreateRegisteredCredential(credentialId, keyVariant: 2);

        var driftSeed = (byte)0x10;
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                "1123456789abcdef0123456789abcdef",
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-broker-epoch-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId + 1,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-windows-session-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                CreatePendingSnapshot(successor),
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-ledger-head-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                new BrokerConsentLedgerStoreSnapshotV1(
                    BrokerConsentLedgerStoreStateV1.NoAuthority,
                    revoke,
                    new BrokerConsentLedgerStoreDiagnosticsV1(
                        BrokerConsentLedgerReplicaStateV1.Canonical,
                        BrokerConsentLedgerReplicaStateV1.Canonical,
                        "store-no-authority-revoked")),
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-ledger-head-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(
                BrokerEpoch,
                WindowsSessionId,
                CreatePendingSnapshot(successor),
                generation,
                driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-ledger-head-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                differentGeneration,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-package-generation-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                forgedGenerationDigest,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-package-generation-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                forgedGenerationCanonical,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-package-generation-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                "managed-readonly-cdp-v2",
                freshVector.Credential),
            "consent-ledger-head-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                CreatePendingSnapshot(receiptDrift),
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential),
            "consent-ledger-head-changed");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                wrongCredentialId),
            "user-presence-credential-invalid");
        ExpectFreshSessionInvalidated(
            CreateFreshSession(BrokerEpoch, WindowsSessionId, snapshot, generation, driftSeed++),
            candidate => candidate.Revalidate(
                BrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                wrongCredentialSpki),
            "user-presence-credential-invalid");

        const string RestartedBrokerEpoch = "fedcba9876543210fedcba9876543210";
        using (var restartedSession = CreateFreshSession(
                   RestartedBrokerEpoch,
                   WindowsSessionId,
                   snapshot,
                   generation,
                   driftSeed++))
        {
            restartedSession.Revalidate(
                RestartedBrokerEpoch,
                WindowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                freshVector.Credential);
        }

        var sessionIdCopy = session.SessionId;
        sessionIdCopy[0] ^= 0xFF;
        Ensure(
            !session.SessionId.SequenceEqual(sessionIdCopy),
            "fresh-presence session exposed its session id buffer");
        session.Dispose();
        Ensure(
            sessionOwnedArrays.All(array => array.All(value => value == 0)),
            "disposed fresh-presence session retained owned bytes");
        ExpectObjectDisposed(() => _ = session.BrokerEpoch);
        session.Dispose();

        statement.Dispose();
        Ensure(
            statementOwnedArrays.All(array => array.All(value => value == 0)),
            "disposed fresh-presence statement retained owned bytes");
        ExpectObjectDisposed(() => _ = statement.CanonicalStatementBytes);
        ExpectObjectDisposed(() => _ = statement.BrokerEpoch);
        statement.Dispose();

        var sessionType = typeof(BrokerFreshPresenceSessionV1);
        Ensure(
            sessionType.IsSealed &&
            typeof(IDisposable).IsAssignableFrom(sessionType) &&
            sessionType.GetCustomAttributesData().All(attribute =>
                attribute.AttributeType != typeof(SerializableAttribute)) &&
            sessionType.GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate) &&
            sessionType.GetMethods(
                    BindingFlags.Instance |
                    BindingFlags.Static |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(method =>
                    !method.Name.Contains("Lease", StringComparison.OrdinalIgnoreCase) &&
                    !method.Name.Contains("Send", StringComparison.OrdinalIgnoreCase) &&
                    !method.Name.Contains("Recover", StringComparison.OrdinalIgnoreCase) &&
                    !method.Name.Contains("Native", StringComparison.OrdinalIgnoreCase)) &&
            sessionType.GetFields(
                    BindingFlags.Instance |
                    BindingFlags.Static |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(field =>
                    !field.FieldType.FullName!.Contains("SafeHandle", StringComparison.Ordinal) &&
                    !field.FieldType.FullName.Contains("Windows", StringComparison.Ordinal)),
            "fresh-presence session exposed serialization, lease, Guardian, native, or send authority");

        CryptographicOperations.ZeroMemory(expectedFreshNonce);
        CryptographicOperations.ZeroMemory(mutableFreshNonce);
        CryptographicOperations.ZeroMemory(expectedStatementBytes);
        CryptographicOperations.ZeroMemory(returnedStatement);
        CryptographicOperations.ZeroMemory(returnedStatementCredential);
        CryptographicOperations.ZeroMemory(actualStatementBytes);
        CryptographicOperations.ZeroMemory(domain);
        CryptographicOperations.ZeroMemory(challengeInput);
        CryptographicOperations.ZeroMemory(expectedChallenge);
        CryptographicOperations.ZeroMemory(expectedClientDataJson);
        CryptographicOperations.ZeroMemory(proofEnvelope);
    }

    private static void TestPersistedReceiptVerificationAndGrantFinalization()
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generation = CreateGeneration("verified-receipt-generation");
        var credentialId = BrokerWebAuthnTestVectorsV1.CredentialId();
        var nonce = BrokerWebAuthnTestVectorsV1.Nonce(0x40);
        using var vector = BrokerWebAuthnTestVectorsV1.CreateSignedConsent(
            genesis,
            0,
            generation,
            ReceiptId,
            credentialId,
            nonce,
            IssuedAtUtcTicks);
        using var verified = BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
            vector.Draft,
            vector.Credential,
            vector.Assertion);
        Ensure(
            verified.Purpose == BrokerWebAuthnEvidencePurposeV1.Consent &&
            verified.StatementSha256 == vector.Draft.ConsentStatementSha256 &&
            verified.LedgerId == LedgerId &&
            verified.LedgerRevision == 1 &&
            verified.Sequence == 1 &&
            verified.PreviousEntrySha256 == genesis.EntrySha256 &&
            verified.RevocationGeneration == 0 &&
            verified.ReceiptId == ReceiptId &&
            verified.GenerationSha256 == generation.GenerationSha256 &&
            verified.Capability == BrokerConsentLedgerV1.CapabilityName &&
            verified.IssuedAtUtcTicks == IssuedAtUtcTicks &&
            verified.CredentialId.SequenceEqual(credentialId) &&
            verified.ChallengeNonce.SequenceEqual(nonce) &&
            verified.ProofEnvelope.Length == 210,
            "verified consent evidence did not freeze every draft identity");
        var verifiedOwnedArrays = GetOwnedByteArrays(verified);
        var returnedProof = verified.ProofEnvelope;
        returnedProof[0] ^= 0xFF;
        Ensure(
            verified.ProofEnvelope[0] != returnedProof[0] &&
            verifiedOwnedArrays.Length == 4,
            "verified consent evidence exposed an owned buffer");

        var grant = vector.Draft.FinalizeGrant(verified);
        Ensure(
            grant.ValidationState == BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification &&
            grant.Entry is BrokerConsentGrantEntryV1 grantEntry &&
            Convert.FromBase64String(grantEntry.Receipt.SignatureBase64).Length == 210 &&
            BrokerConsentLedgerV1.CreateConsentStatement(grant)
                .SequenceEqual(vector.Draft.ConsentStatementBytes),
            "verified finalization did not produce the exact pending grant");
        Ensure(
            verifiedOwnedArrays.All(array => array.All(value => value == 0)),
            "consumed verified consent evidence retained owned bytes");
        ExpectObjectDisposed(() => _ = verified.ProofEnvelope);
        ExpectVerificationCode(
            () => vector.Draft.FinalizeGrant(verified),
            "consent-fresh-presence-required");

        using var persisted = BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(grant);
        Ensure(
            persisted.Purpose == BrokerWebAuthnEvidencePurposeV1.PersistedGrant &&
            persisted.StatementSha256 == BrokerConsentLedgerV1.ComputeConsentStatementSha256(grant) &&
            persisted.LedgerEntrySha256 == grant.EntrySha256 &&
            persisted.ProofEnvelope.SequenceEqual(
                Convert.FromBase64String(((BrokerConsentGrantEntryV1)grant.Entry).Receipt.SignatureBase64)),
            "persisted grant verification did not return exact historical evidence");

        var clientDataJson = vector.Assertion.ClientDataJson;
        var authenticatorData = vector.Assertion.AuthenticatorData;
        var nativeDerSignature = vector.Assertion.NativeDerSignature;
        var wrongClientData = clientDataJson.ToArray();
        wrongClientData[0] ^= 0x01;
        using (var assertion = WebAuthnAssertionEvidenceV1.Create(
                   wrongClientData,
                   credentialId,
                   authenticatorData,
                   nativeDerSignature,
                   userHandle: null))
        {
            ExpectVerificationCode(
                () => BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
                    vector.Draft,
                    vector.Credential,
                    assertion).Dispose(),
                "user-presence-challenge-mismatch");
        }

        var wrongCredentialId = credentialId.ToArray();
        wrongCredentialId[0] ^= 0xFF;
        using (var assertion = WebAuthnAssertionEvidenceV1.Create(
                   clientDataJson,
                   wrongCredentialId,
                   authenticatorData,
                   nativeDerSignature,
                   userHandle: null))
        {
            ExpectVerificationCode(
                () => BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
                    vector.Draft,
                    vector.Credential,
                    assertion).Dispose(),
                "user-presence-credential-invalid");
        }

        using (var forgedSpki = BrokerWebAuthnTestVectorsV1.CreateSignedAssertionForDraft(
                   vector.Draft,
                   credentialId,
                   keyVariant: 2,
                   vector.Draft.StatementFields.CredentialPublicKeySha256))
        {
            var rejectedForgedSpki = false;
            try
            {
                using var unexpected = BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
                    vector.Draft,
                    forgedSpki.Credential,
                    forgedSpki.Assertion);
            }
            catch (BrokerUserPresenceVerificationException exception) when (
                exception.Code == "user-presence-credential-invalid")
            {
                rejectedForgedSpki = true;
            }

            var verifiedEvidenceFactories =
                typeof(BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1)
                    .GetMethods(
                        BindingFlags.Static |
                        BindingFlags.Public |
                        BindingFlags.NonPublic |
                        BindingFlags.DeclaredOnly)
                    .Where(method => method.Name == "Create")
                    .ToArray();
            var evidenceFactoryToken = typeof(BrokerWebAuthnReceiptVerifierV1).GetField(
                "EvidenceFactoryToken",
                BindingFlags.Static |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly);
            Ensure(
                rejectedForgedSpki &&
                verifiedEvidenceFactories.Length > 0 &&
                evidenceFactoryToken is { IsPrivate: true, IsInitOnly: true } &&
                evidenceFactoryToken.FieldType == typeof(object) &&
                verifiedEvidenceFactories.All(method =>
                    method.IsAssembly && RejectsForgedEvidenceFactory(method)),
                "the verifier trusted a declared SPKI hash or exposed a verified-evidence factory");
        }

        var wrongRp = authenticatorData.ToArray();
        wrongRp[0] ^= 0xFF;
        using (var assertion = WebAuthnAssertionEvidenceV1.Create(
                   clientDataJson,
                   credentialId,
                   wrongRp,
                   nativeDerSignature,
                   userHandle: null))
        {
            ExpectVerificationCode(
                () => BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
                    vector.Draft,
                    vector.Credential,
                    assertion).Dispose(),
                "user-presence-rp-mismatch");
        }

        foreach (var (flags, code) in new[]
                 {
                     ((byte)0x04, "user-presence-up-missing"),
                     ((byte)0x01, "user-presence-uv-missing")
                 })
        {
            var changed = authenticatorData.ToArray();
            changed[32] = flags;
            using var assertion = WebAuthnAssertionEvidenceV1.Create(
                clientDataJson,
                credentialId,
                changed,
                nativeDerSignature,
                userHandle: null);
            ExpectVerificationCode(
                () => BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
                    vector.Draft,
                    vector.Credential,
                    assertion).Dispose(),
                code);
        }

        var wrongSignature = nativeDerSignature.ToArray();
        wrongSignature[^1] ^= 0x01;
        using (var assertion = WebAuthnAssertionEvidenceV1.Create(
                   clientDataJson,
                   credentialId,
                   authenticatorData,
                   wrongSignature,
                   userHandle: null))
        {
            ExpectVerificationCode(
                () => BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
                    vector.Draft,
                    vector.Credential,
                    assertion).Dispose(),
                "user-presence-signature-invalid");
        }

        var rawUserHandle = new byte[] { 0x01, 0x02 };
        using (var raw = WebAuthnAssertionEvidenceV1.Create(
                   clientDataJson,
                   credentialId,
                   authenticatorData,
                   nativeDerSignature,
                   rawUserHandle))
        {
            rawUserHandle[0] ^= 0xFF;
            var returned = raw.UserHandle!;
            returned[1] ^= 0xFF;
            Ensure(
                raw.UserHandle!.SequenceEqual(new byte[] { 0x01, 0x02 }),
                "raw assertion evidence did not defensively copy the optional user handle");
        }

        ExpectArgumentException(
            () => WebAuthnAssertionEvidenceV1.Create(
                new byte[4097],
                credentialId,
                authenticatorData,
                nativeDerSignature,
                userHandle: null).Dispose());
        var failureCodes = new[]
        {
            "user-presence-platform-unavailable",
            "user-presence-window-invalid",
            "user-presence-operation-busy",
            "user-presence-cancelled",
            "user-presence-timeout",
            "user-presence-credential-not-found",
            "user-presence-credential-invalid",
            "user-presence-registration-malformed",
            "user-presence-assertion-malformed",
            "user-presence-rp-mismatch",
            "user-presence-up-missing",
            "user-presence-uv-missing",
            "user-presence-challenge-mismatch",
            "user-presence-signature-invalid",
            "user-presence-proof-noncanonical",
            "consent-ledger-head-changed",
            "consent-package-generation-changed",
            "consent-broker-epoch-changed",
            "consent-windows-session-changed",
            "consent-fresh-presence-required",
            "user-presence-native-failed"
        };
        Ensure(
            failureCodes.Length == 21 &&
            failureCodes.Distinct(StringComparer.Ordinal).Count() == 21 &&
            failureCodes.All(code =>
                new BrokerUserPresenceVerificationException(code, "bounded").Code == code),
            "stable user-presence failure codes changed");
        ExpectArgumentException(
            () => _ = new BrokerUserPresenceVerificationException(
                "user-presence-unknown",
                "bounded"));
        ExpectArgumentException(
            () => _ = new BrokerUserPresenceVerificationException(
                "user-presence-native-failed",
                string.Empty));
        ExpectArgumentException(
            () => _ = new BrokerUserPresenceVerificationException(
                "user-presence-native-failed",
                new string('x', 257)));
        Ensure(
            typeof(BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1)
                .GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate),
            "verified user-presence evidence exposed a constructor");
        Ensure(
            typeof(BrokerConsentLedgerTransition).GetMethods(
                    BindingFlags.Static |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(method => method.Name != "CreateGrant") &&
            typeof(BrokerConsentLedgerV1).GetMethods(
                    BindingFlags.Static |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .Where(method => method.Name == "CreateGrant")
                .All(method => method.GetParameters().All(parameter =>
                    parameter.ParameterType != typeof(BrokerUserPresenceReceiptV1))),
            "ledger finalization still accepts an arbitrary receipt");

        CryptographicOperations.ZeroMemory(clientDataJson);
        CryptographicOperations.ZeroMemory(authenticatorData);
        CryptographicOperations.ZeroMemory(nativeDerSignature);
    }

    private static void TestAssertionEvidenceBoundsAndOwnership()
    {
        var clientData = new byte[] { 0x11 };
        var credentialId = new byte[] { 0x22 };
        var authenticatorData = new byte[] { 0x33 };
        var nativeSignature = new byte[] { 0x44 };
        var userHandle = new byte[] { 0x55 };
        var raw = WebAuthnAssertionEvidenceV1.Create(
            clientData,
            credentialId,
            authenticatorData,
            nativeSignature,
            userHandle);
        var ownedArrays = GetOwnedByteArrays(raw);
        clientData[0] = 0xFF;
        credentialId[0] = 0xFF;
        authenticatorData[0] = 0xFF;
        nativeSignature[0] = 0xFF;
        userHandle[0] = 0xFF;
        var returnedClientData = raw.ClientDataJson;
        var returnedCredentialId = raw.CredentialId;
        var returnedAuthenticatorData = raw.AuthenticatorData;
        var returnedNativeSignature = raw.NativeDerSignature;
        var returnedUserHandle = raw.UserHandle!;
        returnedClientData[0] = 0xEE;
        returnedCredentialId[0] = 0xEE;
        returnedAuthenticatorData[0] = 0xEE;
        returnedNativeSignature[0] = 0xEE;
        returnedUserHandle[0] = 0xEE;
        Ensure(
            raw.ClientDataJson.SequenceEqual(new byte[] { 0x11 }) &&
            raw.CredentialId.SequenceEqual(new byte[] { 0x22 }) &&
            raw.AuthenticatorData.SequenceEqual(new byte[] { 0x33 }) &&
            raw.NativeDerSignature.SequenceEqual(new byte[] { 0x44 }) &&
            raw.UserHandle!.SequenceEqual(new byte[] { 0x55 }) &&
            ownedArrays.Length == 5,
            "raw assertion evidence did not defensively copy every buffer");
        raw.Dispose();
        Ensure(
            ownedArrays.All(array => array.All(value => value == 0)),
            "disposed raw assertion evidence retained owned bytes");
        ExpectObjectDisposed(() => _ = raw.ClientDataJson);
        raw.Dispose();

        using var maximum = WebAuthnAssertionEvidenceV1.Create(
            new byte[4096],
            new byte[1024],
            new byte[4096],
            new byte[128],
            new byte[1024]);
        Ensure(
            maximum.ClientDataJson.Length == 4096 &&
            maximum.CredentialId.Length == 1024 &&
            maximum.AuthenticatorData.Length == 4096 &&
            maximum.NativeDerSignature.Length == 128 &&
            maximum.UserHandle!.Length == 1024,
            "raw assertion evidence rejected an exact maximum bound");

        var valid = new byte[] { 0x01 };
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            Array.Empty<byte>(), valid, valid, valid, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            new byte[4097], valid, valid, valid, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, Array.Empty<byte>(), valid, valid, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, new byte[1025], valid, valid, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, valid, Array.Empty<byte>(), valid, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, valid, new byte[4097], valid, userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, valid, valid, Array.Empty<byte>(), userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, valid, valid, new byte[129], userHandle: null).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, valid, valid, valid, Array.Empty<byte>()).Dispose());
        ExpectArgumentException(() => WebAuthnAssertionEvidenceV1.Create(
            valid, valid, valid, valid, new byte[1025]).Dispose());
    }

    private static void TestPersistedReceiptTamperMatrix()
    {
        const int SubjectPublicKeyInfoOffset = 18;
        const int AuthenticatorDataOffset = 109;
        const int SignatureOffset = 146;
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generation = CreateGeneration("persisted-tamper-generation");
        var credentialId = BrokerWebAuthnTestVectorsV1.CredentialId();
        var nonce = BrokerWebAuthnTestVectorsV1.Nonce(0x40);
        var grant = BrokerWebAuthnTestVectorsV1.CreateVerifiedGrant(
            genesis,
            0,
            generation,
            ReceiptId,
            credentialId,
            nonce,
            IssuedAtUtcTicks);
        var reopened = BrokerConsentLedgerV1.Parse(BrokerConsentLedgerV1.Serialize(grant));
        Ensure(
            reopened.ValidationState == BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification,
            "a reopened verified receipt became persisted authority");
        using (var verified = BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened))
        {
            Ensure(
                verified.Purpose == BrokerWebAuthnEvidencePurposeV1.PersistedGrant &&
                verified.LedgerEntrySha256 == reopened.EntrySha256,
                "reopened persisted receipt verification lost its exact ledger binding");
        }

        var receipt = ((BrokerConsentGrantEntryV1)reopened.Entry).Receipt;
        var proof = Convert.FromBase64String(receipt.SignatureBase64);
        var otherGrant = BrokerWebAuthnTestVectorsV1.CreateVerifiedGrant(
            genesis,
            0,
            generation,
            Guid.ParseExact("22222222-3333-4444-5555-666666666666", "D"),
            credentialId,
            nonce,
            IssuedAtUtcTicks,
            keyVariant: 2);
        var otherProof = Convert.FromBase64String(
            ((BrokerConsentGrantEntryV1)otherGrant.Entry).Receipt.SignatureBase64);
        var wrongHeader = proof.ToArray();
        wrongHeader[0] ^= 0x01;
        var wrongSpki = proof.ToArray();
        var otherSpki = BrokerWebAuthnTestVectorsV1.SubjectPublicKeyInfo(keyVariant: 2);
        otherSpki.CopyTo(wrongSpki, SubjectPublicKeyInfoOffset);
        var wrongSignature = proof.ToArray();
        otherProof.AsSpan(SignatureOffset, 64).CopyTo(wrongSignature.AsSpan(SignatureOffset, 64));
        var wrongRp = proof.ToArray();
        wrongRp[AuthenticatorDataOffset] ^= 0x01;
        var wrongFlags = proof.ToArray();
        wrongFlags[AuthenticatorDataOffset + 32] |= 0x80;
        var tampered = new[]
        {
            (BrokerWebAuthnTestVectorsV1.RebindParsedGrant(reopened, wrongHeader),
                "user-presence-proof-noncanonical"),
            (BrokerWebAuthnTestVectorsV1.RebindParsedGrant(reopened, wrongSpki),
                "user-presence-credential-invalid"),
            (BrokerWebAuthnTestVectorsV1.RebindParsedGrant(reopened, wrongSignature),
                "user-presence-signature-invalid"),
            (BrokerWebAuthnTestVectorsV1.RebindParsedGrant(reopened, wrongRp),
                "user-presence-proof-noncanonical"),
            (BrokerWebAuthnTestVectorsV1.RebindParsedGrant(reopened, wrongFlags),
                "user-presence-proof-noncanonical"),
            (BrokerWebAuthnTestVectorsV1.RebindParsedGrant(
                    reopened,
                    proof,
                    credentialId: BrokerWebAuthnTestVectorsV1.CredentialId(0x20)),
                "user-presence-signature-invalid"),
            (BrokerWebAuthnTestVectorsV1.RebindParsedGrant(
                    reopened,
                    proof,
                    challengeNonce: BrokerWebAuthnTestVectorsV1.Nonce(0x70)),
                "user-presence-signature-invalid")
        };
        foreach (var (document, code) in tampered)
        {
            ExpectVerificationCode(
                () => BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(document).Dispose(),
                code);
        }

        var oneByteProof = BrokerWebAuthnTestVectorsV1.RebindParsedGrant(
            reopened,
            new byte[] { 0x01 });
        var maximumStructuralProof = BrokerWebAuthnTestVectorsV1.RebindParsedGrant(
            reopened,
            new byte[4096]);
        Ensure(
            oneByteProof.ValidationState == BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification &&
            maximumStructuralProof.ValidationState == BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification,
            "the ledger parser stopped preserving the structural 1-through-4096 proof bound");
        ExpectVerificationCode(
            () => BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(oneByteProof).Dispose(),
            "user-presence-proof-noncanonical");
        ExpectVerificationCode(
            () => BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(maximumStructuralProof).Dispose(),
            "user-presence-proof-noncanonical");
        ExpectCode(
            () => BrokerWebAuthnTestVectorsV1.RebindParsedGrant(reopened, Array.Empty<byte>()),
            "consent-ledger-receipt-invalid");
        ExpectCode(
            () => BrokerWebAuthnTestVectorsV1.RebindParsedGrant(reopened, new byte[4097]),
            "consent-ledger-receipt-invalid");

        using var historicalEvidence = BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(reopened);
        var successorDraft = BrokerConsentGrantDraftV1.Create(
            reopened,
            expectedRevision: 1,
            generation,
            Guid.ParseExact("33333333-4444-5555-6666-777777777777", "D"),
            credentialId,
            receipt.CredentialPublicKeySha256,
            BrokerWebAuthnTestVectorsV1.Nonce(0x60),
            IssuedAtUtcTicks + 1);
        ExpectVerificationCode(
            () => successorDraft.FinalizeGrant(historicalEvidence),
            "consent-fresh-presence-required");
        ExpectObjectDisposed(() => _ = historicalEvidence.ProofEnvelope);

        CryptographicOperations.ZeroMemory(proof);
        CryptographicOperations.ZeroMemory(otherProof);
        CryptographicOperations.ZeroMemory(wrongHeader);
        CryptographicOperations.ZeroMemory(wrongSpki);
        CryptographicOperations.ZeroMemory(wrongSignature);
        CryptographicOperations.ZeroMemory(wrongRp);
        CryptographicOperations.ZeroMemory(wrongFlags);
        CryptographicOperations.ZeroMemory(otherSpki);
    }

    private static void TestStrictDerAndProofEnvelope()
    {
        var rpIdHash = Convert.FromHexString(
            "98CC7D7B6EB44AE201CA8895A58B4F0715B255C3AF043162E8A71C45FBEB3478");
        var subjectPublicKeyInfo = Convert.FromHexString(
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004" +
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        var authenticatorData = CreateAssertionAuthenticatorData(
            rpIdHash,
            flags: 0x05,
            counter: 0x01020304);
        var r = new byte[32];
        var s = new byte[32];
        r[0] = 0x80;
        r[^1] = 0x01;
        s[0] = 0x7F;
        s[^1] = 0x02;
        var nativeDerSignature = CreateCanonicalDerSignature(r, s);
        var expectedP1363 = JoinBytes(r, s);

        var normalized = BrokerWebAuthnDerSignatureV1.NormalizeToP1363(nativeDerSignature);
        Ensure(
            normalized.SequenceEqual(expectedP1363),
            "DER signature normalization changed r or s");
        var smallNormalized = BrokerWebAuthnDerSignatureV1.NormalizeToP1363(
            CreateCanonicalDerSignature(new byte[] { 0x01 }, new byte[] { 0x02 }));
        Ensure(
            smallNormalized.Length == 64 &&
            smallNormalized.Take(31).All(value => value == 0) &&
            smallNormalized[31] == 1 &&
            smallNormalized.Skip(32).Take(31).All(value => value == 0) &&
            smallNormalized[63] == 2,
            "DER signature normalization did not left-pad short scalars");
        CryptographicOperations.ZeroMemory(smallNormalized);

        var mutableSubjectPublicKeyInfo = subjectPublicKeyInfo.ToArray();
        var mutableAuthenticatorData = authenticatorData.ToArray();
        var mutableNativeDerSignature = nativeDerSignature.ToArray();
        using var proof = BrokerWebAuthnAssertionProofV1.Create(
            mutableSubjectPublicKeyInfo,
            mutableAuthenticatorData,
            mutableNativeDerSignature);
        mutableSubjectPublicKeyInfo[0] ^= 0xFF;
        mutableAuthenticatorData[0] ^= 0xFF;
        mutableNativeDerSignature[^1] ^= 0xFF;
        Ensure(
            proof.SubjectPublicKeyInfo.SequenceEqual(subjectPublicKeyInfo) &&
            proof.AuthenticatorData.SequenceEqual(authenticatorData) &&
            proof.SignatureP1363.SequenceEqual(expectedP1363),
            "proof did not defensively copy Create inputs");

        var envelope = proof.Serialize();
        Ensure(envelope.Length == 210, "proof envelope length changed");
        Ensure(
            envelope.AsSpan(0, 8).SequenceEqual(
                new byte[] { 0x43, 0x47, 0x57, 0x41, 0x50, 0x46, 0x31, 0x00 }) &&
            envelope[8] == 1 &&
            envelope[9] == 1 &&
            envelope[10] == 0 &&
            envelope[11] == 0 &&
            envelope[12] == 0 && envelope[13] == 91 &&
            envelope[14] == 0 && envelope[15] == 37 &&
            envelope[16] == 0 && envelope[17] == 64,
            "proof envelope header changed");
        Ensure(
            envelope.AsSpan(18, 91).SequenceEqual(subjectPublicKeyInfo) &&
            envelope.AsSpan(109, 37).SequenceEqual(authenticatorData) &&
            envelope.AsSpan(146, 64).SequenceEqual(expectedP1363),
            "proof envelope payload offsets changed");
        Ensure(
            BrokerWebAuthnAssertionAuthenticatorDataV1.ValidateFixedRp(authenticatorData) ==
                0x01020304,
            "assertion sign counter parsing changed");

        var returnedSpki = proof.SubjectPublicKeyInfo;
        var returnedAuthenticatorData = proof.AuthenticatorData;
        var returnedSignature = proof.SignatureP1363;
        var returnedEnvelope = proof.Serialize();
        returnedSpki[0] ^= 0xFF;
        returnedAuthenticatorData[0] ^= 0xFF;
        returnedSignature[0] ^= 0xFF;
        returnedEnvelope[0] ^= 0xFF;
        Ensure(
            proof.SubjectPublicKeyInfo.SequenceEqual(subjectPublicKeyInfo) &&
            proof.AuthenticatorData.SequenceEqual(authenticatorData) &&
            proof.SignatureP1363.SequenceEqual(expectedP1363) &&
            proof.Serialize().SequenceEqual(envelope),
            "proof did not defensively copy returned arrays");

        using (var parsed = BrokerWebAuthnAssertionProofV1.Parse(envelope))
        {
            Ensure(
                parsed.Serialize().SequenceEqual(envelope),
                "proof envelope parse and serialization diverged");
        }

        using (var backupFlagsProof = BrokerWebAuthnAssertionProofV1.Create(
                   subjectPublicKeyInfo,
                   CreateAssertionAuthenticatorData(rpIdHash, 0x1D, 0),
                   nativeDerSignature))
        {
            Ensure(
                backupFlagsProof.AuthenticatorData[32] == 0x1D,
                "proof treated backup flags as device-bound authority");
        }

        var simpleDer = CreateCanonicalDerSignature(
            new byte[] { 0x01 },
            new byte[] { 0x02 });
        ExpectDerRejected(Array.Empty<byte>());
        ExpectDerRejected(new byte[73]);
        var wrongSequenceTag = simpleDer.ToArray();
        wrongSequenceTag[0] = 0x31;
        ExpectDerRejected(wrongSequenceTag);
        var longSequenceLength = JoinBytes(
            new byte[] { 0x30, 0x81, simpleDer[1] },
            simpleDer[2..]);
        ExpectDerRejected(longSequenceLength);
        ExpectDerRejected(JoinBytes(
            new byte[] { 0x30, 0x80 },
            simpleDer[2..],
            new byte[] { 0x00, 0x00 }));
        var wrongSequenceLength = simpleDer.ToArray();
        wrongSequenceLength[1]--;
        ExpectDerRejected(wrongSequenceLength);
        ExpectDerRejected(JoinBytes(simpleDer, new byte[] { 0x00 }));
        ExpectDerRejected(CreateRawDerSequence(
            new byte[] { 0x03, 0x01, 0x01 },
            EncodeRawDerInteger(new byte[] { 0x02 })));
        ExpectDerRejected(CreateRawDerSequence(
            new byte[] { 0x02, 0x81, 0x01, 0x01 },
            EncodeRawDerInteger(new byte[] { 0x02 })));
        ExpectDerRejected(CreateRawDerSequence(
            new byte[] { 0x02, 0x00 },
            EncodeRawDerInteger(new byte[] { 0x02 })));
        ExpectDerRejected(CreateRawDerSequence(
            EncodeRawDerInteger(new byte[] { 0x00 }),
            EncodeRawDerInteger(new byte[] { 0x02 })));
        ExpectDerRejected(CreateRawDerSequence(
            EncodeRawDerInteger(new byte[] { 0x80 }),
            EncodeRawDerInteger(new byte[] { 0x02 })));
        ExpectDerRejected(CreateRawDerSequence(
            EncodeRawDerInteger(new byte[] { 0x00, 0x01 }),
            EncodeRawDerInteger(new byte[] { 0x02 })));
        ExpectDerRejected(CreateRawDerSequence(
            EncodeRawDerInteger(
                JoinBytes(
                    new byte[] { 0x00, 0x80 },
                    new byte[32])),
            EncodeRawDerInteger(new byte[] { 0x02 })));
        ExpectDerRejected(CreateCanonicalDerSignature(
            P256OrderBytes(),
            new byte[] { 0x02 }));
        ExpectDerRejected(CreateCanonicalDerSignature(
            new byte[] { 0x01 },
            P256OrderBytes()));
        ExpectDerRejected(CreateCanonicalDerSignature(
            Enumerable.Repeat((byte)0xFF, 32).ToArray(),
            new byte[] { 0x02 }));
        ExpectDerRejected(CreateRawDerSequence(
            EncodeRawDerInteger(new byte[] { 0x01 })));
        ExpectDerRejected(CreateRawDerSequence(
            EncodeRawDerInteger(new byte[] { 0x01 }),
            EncodeRawDerInteger(new byte[] { 0x02 }),
            EncodeRawDerInteger(new byte[] { 0x03 })));
        var justBelowOrder = P256OrderBytes();
        justBelowOrder[^1]--;
        var maximumValid = BrokerWebAuthnDerSignatureV1.NormalizeToP1363(
            CreateCanonicalDerSignature(justBelowOrder, justBelowOrder));
        Ensure(
            maximumValid.AsSpan(0, 32).SequenceEqual(justBelowOrder) &&
            maximumValid.AsSpan(32, 32).SequenceEqual(justBelowOrder),
            "DER signature rejected a scalar immediately below the P-256 order");
        CryptographicOperations.ZeroMemory(maximumValid);

        ExpectProofCreateRejected(
            subjectPublicKeyInfo,
            authenticatorData[..^1],
            nativeDerSignature);
        ExpectProofCreateRejected(
            subjectPublicKeyInfo,
            JoinBytes(authenticatorData, new byte[] { 0x00 }),
            nativeDerSignature);
        var wrongRpAuthenticatorData = authenticatorData.ToArray();
        wrongRpAuthenticatorData[0] ^= 0xFF;
        ExpectProofCreateRejected(subjectPublicKeyInfo, wrongRpAuthenticatorData, nativeDerSignature);
        foreach (var rejectedFlags in new byte[] { 0x04, 0x01, 0x45, 0x85, 0x07, 0x25 })
        {
            ExpectProofCreateRejected(
                subjectPublicKeyInfo,
                CreateAssertionAuthenticatorData(rpIdHash, rejectedFlags, 0),
                nativeDerSignature);
        }

        ExpectProofCreateRejected(
            subjectPublicKeyInfo[..^1],
            authenticatorData,
            nativeDerSignature);
        ExpectProofCreateRejected(
            JoinBytes(subjectPublicKeyInfo, new byte[] { 0x00 }),
            authenticatorData,
            nativeDerSignature);
        var wrongSpkiPrefix = subjectPublicKeyInfo.ToArray();
        wrongSpkiPrefix[0] = 0x31;
        ExpectProofCreateRejected(wrongSpkiPrefix, authenticatorData, nativeDerSignature);
        var invalidSpkiPoint = subjectPublicKeyInfo.ToArray();
        invalidSpkiPoint.AsSpan(27, 32).Fill(0xFF);
        ExpectProofCreateRejected(invalidSpkiPoint, authenticatorData, nativeDerSignature);

        ExpectEnvelopeRejected(envelope[..^1]);
        ExpectEnvelopeRejected(JoinBytes(envelope, new byte[] { 0x00 }));
        foreach (var (offset, value) in new (int Offset, byte Value)[]
                 {
                     (0, 0x42),
                     (8, 0x02),
                     (9, 0x02),
                     (10, 0x01),
                     (11, 0x01),
                     (13, 90),
                     (15, 36),
                     (17, 63),
                     (18, 0x31),
                     (141, 0x01)
                 })
        {
            var mutation = envelope.ToArray();
            mutation[offset] = value;
            ExpectEnvelopeRejected(mutation);
        }

        var zeroR = envelope.ToArray();
        Array.Clear(zeroR, 146, 32);
        ExpectEnvelopeRejected(zeroR);
        var orderR = envelope.ToArray();
        P256OrderBytes().CopyTo(orderR, 146);
        ExpectEnvelopeRejected(orderR);
        var zeroS = envelope.ToArray();
        Array.Clear(zeroS, 178, 32);
        ExpectEnvelopeRejected(zeroS);
        var orderS = envelope.ToArray();
        P256OrderBytes().CopyTo(orderS, 178);
        ExpectEnvelopeRejected(orderS);

        var disposable = BrokerWebAuthnAssertionProofV1.Parse(envelope);
        var proofFields = new[]
        {
            "_subjectPublicKeyInfo",
            "_authenticatorData",
            "_signatureP1363"
        }.Select(name =>
            (byte[])(typeof(BrokerWebAuthnAssertionProofV1).GetField(
                name,
                BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(disposable) ??
                throw new InvalidOperationException("proof owned storage is missing")))
            .ToArray();
        disposable.Dispose();
        disposable.Dispose();
        Ensure(
            proofFields.All(bytes => bytes.All(value => value == 0)),
            "proof disposal did not clear every owned array");
        ExpectObjectDisposed(() => _ = disposable.Serialize());

        Ensure(
            typeof(BrokerWebAuthnAssertionProofV1).GetConstructors(
                    BindingFlags.Instance |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .All(constructor => constructor.IsPrivate) &&
            HasExactProofFactorySurface() &&
            HasExactAssertionAuthenticatorSurface(),
            "proof construction surface changed");

        CryptographicOperations.ZeroMemory(normalized);
        CryptographicOperations.ZeroMemory(expectedP1363);
    }

    private static void TestStrictCoseP256Key()
    {
        const string expectedRpIdSha256 =
            "98CC7D7B6EB44AE201CA8895A58B4F0715B255C3AF043162E8A71C45FBEB3478";
        const string expectedSubjectPublicKeyInfo =
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004" +
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
        const string expectedSubjectPublicKeyInfoSha256 =
            "5CD252FB0CE8932436FAF8CCD1040981B89EE4AD6B9FE9E2A2B7E71AACB27CD3";
        var rpIdHash = Convert.FromHexString(expectedRpIdSha256);
        var credentialId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var validCoseKey = CreateValidCoseP256Key(1, 3, -1, -2, -3);
        var validAuthenticatorData = CreateRegistrationAuthenticatorData(
            rpIdHash,
            flags: 0x45,
            credentialId,
            validCoseKey);

        var mutableAuthenticatorData = validAuthenticatorData.ToArray();
        var mutableExpectedCredentialId = credentialId.ToArray();
        using var credential = BrokerWebAuthnRegistrationParserV1.Parse(
            mutableAuthenticatorData,
            rpIdHash,
            mutableExpectedCredentialId);
        Ensure(
            credential.CredentialId.SequenceEqual(credentialId),
            "registration parser changed the credential ID");
        Ensure(
            Convert.ToHexString(credential.SubjectPublicKeyInfo) == expectedSubjectPublicKeyInfo,
            "registration parser changed the canonical P-256 SubjectPublicKeyInfo");
        Ensure(
            credential.SubjectPublicKeyInfoSha256 == expectedSubjectPublicKeyInfoSha256,
            "registration parser changed the SubjectPublicKeyInfo hash");

        mutableAuthenticatorData[55] ^= 0xFF;
        mutableExpectedCredentialId[0] ^= 0xFF;
        var returnedCredentialId = credential.CredentialId;
        var returnedSubjectPublicKeyInfo = credential.SubjectPublicKeyInfo;
        returnedCredentialId[0] ^= 0xFF;
        returnedSubjectPublicKeyInfo[0] ^= 0xFF;
        Ensure(
            credential.CredentialId.SequenceEqual(credentialId) &&
            Convert.ToHexString(credential.SubjectPublicKeyInfo) == expectedSubjectPublicKeyInfo,
            "registered credential arrays were not defensively copied");

        using (var reordered = BrokerWebAuthnRegistrationParserV1.Parse(
                   CreateRegistrationAuthenticatorData(
                       rpIdHash,
                       0x45,
                       credentialId,
                       CreateValidCoseP256Key(-3, -2, -1, 3, 1)),
                   rpIdHash,
                   credentialId))
        {
            Ensure(
                reordered.SubjectPublicKeyInfoSha256 == expectedSubjectPublicKeyInfoSha256,
                "registration parser rejected a canonically reordered COSE map");
        }

        using (var backupFlags = BrokerWebAuthnRegistrationParserV1.Parse(
                   CreateRegistrationAuthenticatorData(
                       rpIdHash,
                       0x5D,
                       credentialId,
                       validCoseKey),
                   rpIdHash,
                   ReadOnlySpan<byte>.Empty))
        {
            Ensure(
                backupFlags.CredentialId.SequenceEqual(credentialId),
                "registration parser treated backup flags as device-bound authority");
        }

        var maximumCredentialId = Enumerable.Range(0, 1024)
            .Select(index => checked((byte)(index & byte.MaxValue)))
            .ToArray();
        using (var maximumCredential = BrokerWebAuthnRegistrationParserV1.Parse(
                   CreateRegistrationAuthenticatorData(
                       rpIdHash,
                       0x45,
                       maximumCredentialId,
                       validCoseKey),
                   rpIdHash,
                   maximumCredentialId))
        {
            Ensure(
                maximumCredential.CredentialId.Length == 1024,
                "registration parser rejected the maximum credential ID bound");
        }

        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                validAuthenticatorData,
                new byte[31],
                credentialId).Dispose());
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                validAuthenticatorData,
                new byte[33],
                credentialId).Dispose());
        var wrongRpIdHash = rpIdHash.ToArray();
        wrongRpIdHash[0] ^= 0xFF;
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                validAuthenticatorData,
                wrongRpIdHash,
                credentialId).Dispose());
        ExpectRegistrationRejected(rpIdHash, credentialId, validCoseKey, flags: 0x44);
        ExpectRegistrationRejected(rpIdHash, credentialId, validCoseKey, flags: 0x41);
        ExpectRegistrationRejected(rpIdHash, credentialId, validCoseKey, flags: 0x05);
        ExpectRegistrationRejected(rpIdHash, credentialId, validCoseKey, flags: 0xC5);
        ExpectRegistrationRejected(rpIdHash, credentialId, validCoseKey, flags: 0x47);
        ExpectRegistrationRejected(rpIdHash, credentialId, validCoseKey, flags: 0x65);
        ExpectRegistrationRejected(rpIdHash, Array.Empty<byte>(), validCoseKey, flags: 0x45);
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                CreateRegistrationAuthenticatorData(
                    rpIdHash,
                    0x45,
                    new byte[1025],
                    validCoseKey),
                rpIdHash,
                ReadOnlySpan<byte>.Empty).Dispose());
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                validAuthenticatorData,
                rpIdHash,
                new byte[1025]).Dispose());
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                validAuthenticatorData,
                rpIdHash,
                new byte[] { 0x01, 0x02, 0x03, 0x05 }).Dispose());

        var indefiniteMap = validCoseKey.ToArray();
        indefiniteMap[0] = 0xBF;
        ExpectRegistrationRejected(rpIdHash, credentialId, indefiniteMap, flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseMap(
                CreateValidCoseEntry(1),
                CreateValidCoseEntry(1),
                CreateValidCoseEntry(-1),
                CreateValidCoseEntry(-2),
                CreateValidCoseEntry(-3)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseMap(
                CreateValidCoseEntry(1),
                CreateValidCoseEntry(3),
                CreateValidCoseEntry(-1),
                CreateValidCoseEntry(-2)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseMap(
                CreateValidCoseEntry(1),
                CreateValidCoseEntry(3),
                CreateValidCoseEntry(-1),
                CreateValidCoseEntry(-2),
                CreateCoseEntry(4, EncodeCanonicalCborInteger(1))),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseMap(
                JoinBytes(new byte[] { 0x18, 0x01 }, EncodeCanonicalCborInteger(2)),
                CreateValidCoseEntry(3),
                CreateValidCoseEntry(-1),
                CreateValidCoseEntry(-2),
                CreateValidCoseEntry(-3)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseMap(
                CreateCoseEntry(1, new byte[] { 0x18, 0x02 }),
                CreateValidCoseEntry(3),
                CreateValidCoseEntry(-1),
                CreateValidCoseEntry(-2),
                CreateValidCoseEntry(-3)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseMap(
                CreateValidCoseEntry(1),
                CreateValidCoseEntry(3),
                CreateValidCoseEntry(-1),
                CreateCoseEntry(
                    -2,
                    JoinBytes(new byte[] { 0x59, 0x00, 0x20 }, CoseP256X())),
                CreateValidCoseEntry(-3)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseKeyWithValue(1, EncodeCanonicalCborInteger(3)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseKeyWithValue(3, EncodeCanonicalCborInteger(-6)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseKeyWithValue(-1, EncodeCanonicalCborInteger(2)),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseKeyWithValue(-2, EncodeCanonicalCborByteString(new byte[31])),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseKeyWithValue(-3, EncodeCanonicalCborByteString(new byte[31])),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            CreateCoseKeyWithValue(-2, EncodeCanonicalCborByteString(Enumerable.Repeat((byte)0xFF, 32).ToArray())),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            JoinBytes(validCoseKey, new byte[] { 0x00 }),
            flags: 0x45);
        ExpectRegistrationRejected(
            rpIdHash,
            credentialId,
            validCoseKey[..^1],
            flags: 0x45);

        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                new byte[BrokerWebAuthnRegistrationParserV1.MaximumAuthenticatorDataBytes + 1],
                rpIdHash,
                ReadOnlySpan<byte>.Empty).Dispose());
        var oversizedAuthenticatorData = new byte[1024 * 1024];
        var beforeOversizedRejection = GC.GetAllocatedBytesForCurrentThread();
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                oversizedAuthenticatorData,
                rpIdHash,
                ReadOnlySpan<byte>.Empty).Dispose());
        var oversizedRejectionAllocation =
            GC.GetAllocatedBytesForCurrentThread() - beforeOversizedRejection;
        Ensure(
            oversizedRejectionAllocation < 64 * 1024,
            $"oversized authenticator rejection allocated {oversizedRejectionAllocation} bytes");

        var disposable = BrokerWebAuthnRegistrationParserV1.Parse(
            validAuthenticatorData,
            rpIdHash,
            credentialId);
        var credentialField = typeof(BrokerWebAuthnRegisteredCredentialV1).GetField(
            "_credentialId",
            BindingFlags.Instance | BindingFlags.NonPublic) ??
            throw new InvalidOperationException("registered credential ID storage is missing");
        var publicKeyField = typeof(BrokerWebAuthnRegisteredCredentialV1).GetField(
            "_subjectPublicKeyInfo",
            BindingFlags.Instance | BindingFlags.NonPublic) ??
            throw new InvalidOperationException("registered public-key storage is missing");
        var ownedCredentialId = (byte[])credentialField.GetValue(disposable)!;
        var ownedSubjectPublicKeyInfo = (byte[])publicKeyField.GetValue(disposable)!;
        disposable.Dispose();
        disposable.Dispose();
        Ensure(
            ownedCredentialId.All(value => value == 0) &&
            ownedSubjectPublicKeyInfo.All(value => value == 0),
            "registered credential disposal did not clear owned arrays");
        ExpectObjectDisposed(() => _ = disposable.CredentialId);

        var parseMethod = typeof(BrokerWebAuthnRegistrationParserV1).GetMethod(
            "Parse",
            BindingFlags.Static | BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(ReadOnlySpan<byte>),
                typeof(ReadOnlySpan<byte>),
                typeof(ReadOnlySpan<byte>)
            },
            modifiers: null);
        Ensure(
            parseMethod?.ReturnType == typeof(BrokerWebAuthnRegisteredCredentialV1) &&
            typeof(BrokerWebAuthnRegistrationParserV1).GetMethods(
                    BindingFlags.Static |
                    BindingFlags.Public |
                    BindingFlags.NonPublic |
                    BindingFlags.DeclaredOnly)
                .Count(method => !method.IsPrivate) == 1,
            "registration parser authority surface changed");
    }

    private static void TestWebAuthnClientDataContract()
    {
        const string brokerEpoch = "0123456789abcdef0123456789abcdef";
        const string expectedRegistrationStatement =
            "{\"schema\":\"codex-broker-webauthn-registration-statement-v1\"," +
            "\"brokerEpoch\":\"0123456789abcdef0123456789abcdef\"," +
            "\"windowsSessionId\":42," +
            "\"userHandleSha256\":\"000102030405060708090A0B0C0D0E0F" +
            "101112131415161718191A1B1C1D1E1F\"," +
            "\"registrationNonceBase64\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3" +
            "ODk6Ozw9Pj8=\"}";
        const string expectedRegistrationChallengeHex =
            "6CC77D4B37638E318DE02EA6E716AE8805CAD55BF86F1393694094B7E43C2113";
        const string expectedRegistrationChallengeBase64Url =
            "bMd9SzdjjjGN4C6m5xauiAXK1Vv4bxOTaUCUt-Q8IRM";
        const string expectedRegistrationClientDataJson =
            "{\"type\":\"webauthn.create\",\"challenge\":" +
            "\"bMd9SzdjjjGN4C6m5xauiAXK1Vv4bxOTaUCUt-Q8IRM\"," +
            "\"origin\":\"https://codexguardian.local\",\"crossOrigin\":false}";
        const string expectedRegistrationClientDataHash =
            "ABFF432236D9FCA5EA2D67372A4461F82EF8B5B3C048B0F4BE24CC673D840B89";
        const string expectedConsentStatement =
            "{\"schema\":\"codex-broker-consent-statement-v1\"," +
            "\"ledgerId\":\"01234567-89ab-cdef-0123-456789abcdef\"," +
            "\"revision\":1,\"sequence\":1," +
            "\"previousEntrySha256\":\"2B0FD3270D91A39F7004CBD228F21BF0" +
            "C31B7EC07BD5FA8DCAD1CE51E2CC90ED\",\"revocationGeneration\":0," +
            "\"receiptId\":\"11111111-2222-3333-4444-555555555555\"," +
            "\"generationSha256\":\"6B7D90DB0F82F582ED73A4AFC285A1B" +
            "0A82B51CB72449E07CAE10F510C093FEB\"," +
            "\"capability\":\"managed-readonly-cdp-v1\"," +
            "\"issuedAtUtcTicks\":638900000000000000," +
            "\"receiptFormat\":\"windows-user-presence-v1\"," +
            "\"credentialIdBase64\":\"AQIDBA==\"," +
            "\"credentialPublicKeySha256\":\"0A193477AFB7EAAA8DBDF26FDC1C21B1" +
            "F287D2430E811F0975494C149674E67E\"," +
            "\"challengeNonceBase64\":\"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZX" +
            "WFlaW1xdXl8=\"}";
        const string expectedConsentChallengeHex =
            "995CDC7952EAE441EC398F5853BE7D308EDC4F4A97266228535F6946D41F9E7B";
        const string expectedConsentChallengeBase64Url =
            "mVzceVLq5EHsOY9YU759MI7cT0qXJmIoU19pRtQfnns";
        const string expectedConsentClientDataJson =
            "{\"type\":\"webauthn.get\",\"challenge\":" +
            "\"mVzceVLq5EHsOY9YU759MI7cT0qXJmIoU19pRtQfnns\"," +
            "\"origin\":\"https://codexguardian.local\",\"crossOrigin\":false}";
        const string expectedConsentClientDataHash =
            "DA542980BD4013BD5F56AA39EC894BD9900BD0FD52FB5C2088E346AFD9FE16C2";

        Ensure(BrokerWebAuthnConstantsV1.RelyingPartyId == "codexguardian.local", "RP ID changed");
        Ensure(BrokerWebAuthnConstantsV1.RelyingPartyDisplayName == "CodexGuardian", "RP display changed");
        Ensure(BrokerWebAuthnConstantsV1.Origin == "https://codexguardian.local", "origin changed");
        Ensure(BrokerWebAuthnConstantsV1.CredentialType == "public-key", "credential type changed");
        Ensure(BrokerWebAuthnConstantsV1.RegistrationClientDataType == "webauthn.create", "registration type changed");
        Ensure(BrokerWebAuthnConstantsV1.AssertionClientDataType == "webauthn.get", "assertion type changed");
        Ensure(BrokerWebAuthnConstantsV1.PlatformAttachment == "platform", "attachment changed");
        Ensure(BrokerWebAuthnConstantsV1.UserVerification == "required", "UV policy changed");
        Ensure(BrokerWebAuthnConstantsV1.ResidentKey == "discouraged", "resident-key policy changed");
        Ensure(BrokerWebAuthnConstantsV1.Attestation == "none", "attestation policy changed");
        Ensure(BrokerWebAuthnConstantsV1.Es256Algorithm == -7, "ES256 identifier changed");
        Ensure(BrokerWebAuthnConstantsV1.Ec2KeyType == 2, "EC2 identifier changed");
        Ensure(BrokerWebAuthnConstantsV1.P256Curve == 1, "P-256 identifier changed");
        Ensure(BrokerWebAuthnConstantsV1.HashAlgorithm == "SHA-256", "hash algorithm changed");
        Ensure(
            BrokerWebAuthnConstantsV1.RegistrationDomainSeparator ==
                "CodexGuardian\0WebAuthn\0Registration\0v1\0" &&
            BrokerWebAuthnConstantsV1.ConsentDomainSeparator ==
                "CodexGuardian\0WebAuthn\0ConsentStatement\0v1\0" &&
            BrokerWebAuthnConstantsV1.FreshPresenceDomainSeparator ==
                "CodexGuardian\0WebAuthn\0FreshPresence\0v1\0",
            "WebAuthn domain separator changed");
        Ensure(
            BrokerWebAuthnConstantsV1.RegistrationDomainSeparator !=
                BrokerWebAuthnConstantsV1.ConsentDomainSeparator,
            "registration and consent are not domain-separated");

        var derivedUserHandle = Enumerable.Range(0, 32).Select(index => checked((byte)index)).ToArray();
        var registrationNonce = Enumerable.Range(0, 32).Select(index => checked((byte)(0x20 + index))).ToArray();
        var expectedUserHandle = derivedUserHandle.ToArray();
        var expectedRegistrationNonce = registrationNonce.ToArray();
        var registrationStatement = BrokerWebAuthnRegistrationStatementV1.Create(
            brokerEpoch,
            42,
            derivedUserHandle,
            registrationNonce);
        Ensure(registrationStatement.BrokerEpoch == brokerEpoch, "registration epoch changed");
        Ensure(registrationStatement.WindowsSessionId == 42, "registration session changed");
        Ensure(
            registrationStatement.UserHandleSha256 ==
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "derived user handle was hashed again or changed");
        Ensure(
            registrationStatement.RegistrationNonceBase64 ==
                "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
            "registration nonce base64 changed");
        Ensure(
            Encoding.UTF8.GetString(registrationStatement.CanonicalStatementBytes) ==
                expectedRegistrationStatement,
            "registration statement bytes changed");

        derivedUserHandle[0] ^= 0xFF;
        registrationNonce[0] ^= 0xFF;
        var returnedUserHandle = registrationStatement.DerivedUserHandle;
        var returnedRegistrationNonce = registrationStatement.RegistrationNonce;
        returnedUserHandle[1] ^= 0xFF;
        returnedRegistrationNonce[1] ^= 0xFF;
        Ensure(
            registrationStatement.DerivedUserHandle.SequenceEqual(expectedUserHandle) &&
            registrationStatement.RegistrationNonce.SequenceEqual(expectedRegistrationNonce),
            "registration statement did not defensively copy inputs or outputs");

        var registrationClientData = BrokerWebAuthnClientDataV1.CreateRegistration(
            registrationStatement);
        AssertClientData(
            registrationClientData,
            BrokerWebAuthnConstantsV1.RegistrationClientDataType,
            expectedRegistrationChallengeHex,
            expectedRegistrationChallengeBase64Url,
            expectedRegistrationClientDataJson,
            expectedRegistrationClientDataHash);

        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generation = CreateGeneration("client-data-generation");
        Ensure(
            genesis.EntrySha256 ==
                "2B0FD3270D91A39F7004CBD228F21BF0C31B7EC07BD5FA8DCAD1CE51E2CC90ED",
            "consent fixture genesis changed");
        Ensure(
            generation.GenerationSha256 ==
                "6B7D90DB0F82F582ED73A4AFC285A1B0A82B51CB72449E07CAE10F510C093FEB",
            "consent fixture package generation changed");
        var consentDraft = BrokerConsentGrantDraftV1.Create(
            genesis,
            0,
            generation,
            ReceiptId,
            new byte[] { 0x01, 0x02, 0x03, 0x04 },
            "0A193477AFB7EAAA8DBDF26FDC1C21B1F287D2430E811F0975494C149674E67E",
            Enumerable.Range(0, 32).Select(index => checked((byte)(0x40 + index))).ToArray(),
            IssuedAtUtcTicks);
        Ensure(
            Encoding.UTF8.GetString(consentDraft.ConsentStatementBytes) == expectedConsentStatement,
            "consent statement fixture bytes changed");
        var consentClientData = BrokerWebAuthnClientDataV1.CreateConsent(consentDraft);
        AssertClientData(
            consentClientData,
            BrokerWebAuthnConstantsV1.AssertionClientDataType,
            expectedConsentChallengeHex,
            expectedConsentChallengeBase64Url,
            expectedConsentClientDataJson,
            expectedConsentClientDataHash);
        Ensure(
            !registrationClientData.ChallengeBytes.SequenceEqual(consentClientData.ChallengeBytes),
            "registration and consent produced the same challenge");

        ExpectArgumentNull(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                null!,
                42,
                expectedUserHandle,
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch[..^1],
                42,
                expectedUserHandle,
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch + "0",
                42,
                expectedUserHandle,
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch.ToUpperInvariant(),
                42,
                expectedUserHandle,
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch[..^1] + "g",
                42,
                expectedUserHandle,
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch,
                0,
                expectedUserHandle,
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch,
                42,
                new byte[31],
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch,
                42,
                new byte[33],
                expectedRegistrationNonce));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch,
                42,
                expectedUserHandle,
                new byte[31]));
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationStatementV1.Create(
                brokerEpoch,
                42,
                expectedUserHandle,
                new byte[33]));

        Ensure(
            HasExactWebAuthnFactorySurface(
                typeof(BrokerWebAuthnRegistrationStatementV1),
                (
                    "Create",
                    new[]
                    {
                        typeof(string),
                        typeof(uint),
                        typeof(ReadOnlySpan<byte>),
                        typeof(ReadOnlySpan<byte>)
                    })),
            "registration statement authority surface changed");
        Ensure(
            HasExactWebAuthnFactorySurface(
                typeof(BrokerWebAuthnClientDataV1),
                (
                    "CreateRegistration",
                    new[] { typeof(BrokerWebAuthnRegistrationStatementV1) }),
                (
                    "CreateConsent",
                    new[] { typeof(BrokerConsentGrantDraftV1) }),
                (
                    "CreateFresh",
                    new[] { typeof(BrokerFreshPresenceStatementV1) })),
            "client-data authority surface changed");
        Ensure(
            HasExactWebAuthnStateSurface(
                typeof(BrokerWebAuthnRegistrationStatementV1),
                ("Schema", typeof(string)),
                ("BrokerEpoch", typeof(string)),
                ("WindowsSessionId", typeof(uint)),
                ("DerivedUserHandle", typeof(byte[])),
                ("RegistrationNonce", typeof(byte[])),
                ("UserHandleSha256", typeof(string)),
                ("RegistrationNonceBase64", typeof(string)),
                ("CanonicalStatementBytes", typeof(byte[]))),
            "registration statement property or field surface changed");
        Ensure(
            HasExactWebAuthnStateSurface(
                typeof(BrokerWebAuthnClientDataV1),
                ("Type", typeof(string)),
                ("ChallengeBase64Url", typeof(string)),
                ("Origin", typeof(string)),
                ("CrossOrigin", typeof(bool)),
                ("ChallengeBytes", typeof(byte[])),
                ("ClientDataJson", typeof(byte[])),
                ("ClientDataHash", typeof(byte[]))),
            "client-data property or field surface changed");
        var constantFields = typeof(BrokerWebAuthnConstantsV1).GetFields(
            BindingFlags.Static |
            BindingFlags.Instance |
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.DeclaredOnly);
        var constantProperties = typeof(BrokerWebAuthnConstantsV1).GetProperties(
            BindingFlags.Static |
            BindingFlags.Instance |
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.DeclaredOnly);
        Ensure(
            constantFields.Length == 18 &&
            constantProperties.Length == 0 &&
            constantFields.All(field => field.IsLiteral && !field.IsInitOnly),
            "WebAuthn constants are not an exact literal field and zero-property set");
        Ensure(
            !HasExactWebAuthnFactorySurface(
                typeof(SyntheticConfigurableClientDataV1),
                (
                    "CreateRegistration",
                    new[] { typeof(BrokerWebAuthnRegistrationStatementV1) })),
            "exact authority whitelist accepted a configurable overload");
        Ensure(
            !HasExactWebAuthnStateSurface(typeof(AuthorityControls)),
            "exact authority audit accepted writable state");
        var syntheticReadonlyField = typeof(SyntheticReadonlyMutableStateV1).GetField(
            "SharedControls",
            BindingFlags.Static |
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.DeclaredOnly);
        Ensure(
            !HasExactWebAuthnStateSurface(typeof(SyntheticReadonlyMutableStateV1)) &&
            syntheticReadonlyField is
            {
                IsStatic: true,
                IsInitOnly: true,
                IsLiteral: false,
                FieldType: not null
            } &&
            syntheticReadonlyField.FieldType == typeof(AuthorityControls),
            "exact authority audit accepted static readonly mutable state");
        var syntheticGetterProperty = typeof(SyntheticGetterOnlyMutableStateV1).GetProperty(
            "CurrentControls",
            BindingFlags.Static |
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.DeclaredOnly);
        Ensure(
            !HasExactWebAuthnStateSurface(typeof(SyntheticGetterOnlyMutableStateV1)) &&
            syntheticGetterProperty is not null &&
            syntheticGetterProperty.PropertyType == typeof(AuthorityControls) &&
            syntheticGetterProperty.GetMethod is { IsPrivate: false, IsStatic: true } &&
            syntheticGetterProperty.SetMethod is null,
            "exact authority audit accepted getter-only mutable state");
    }

    private static void AssertClientData(
        BrokerWebAuthnClientDataV1 clientData,
        string expectedType,
        string expectedChallengeHex,
        string expectedChallengeBase64Url,
        string expectedClientDataJson,
        string expectedClientDataHash)
    {
        Ensure(clientData.Type == expectedType, "client-data type changed");
        Ensure(clientData.Origin == "https://codexguardian.local", "client-data origin changed");
        Ensure(!clientData.CrossOrigin, "client-data crossOrigin changed");
        Ensure(
            Convert.ToHexString(clientData.ChallengeBytes) == expectedChallengeHex,
            "challenge bytes changed");
        Ensure(
            clientData.ChallengeBase64Url == expectedChallengeBase64Url,
            "challenge base64url changed");
        Ensure(
            clientData.ChallengeBase64Url.IndexOfAny(['+', '/', '=']) < 0,
            "challenge is not unpadded base64url");
        Ensure(
            Encoding.UTF8.GetString(clientData.ClientDataJson) == expectedClientDataJson,
            "client-data JSON changed");
        Ensure(
            Convert.ToHexString(clientData.ClientDataHash) == expectedClientDataHash,
            "client-data hash changed");

        var challenge = clientData.ChallengeBytes;
        var json = clientData.ClientDataJson;
        var hash = clientData.ClientDataHash;
        challenge[0] ^= 0xFF;
        json[0] ^= 0xFF;
        hash[0] ^= 0xFF;
        Ensure(
            Convert.ToHexString(clientData.ChallengeBytes) == expectedChallengeHex &&
            Encoding.UTF8.GetString(clientData.ClientDataJson) == expectedClientDataJson &&
            Convert.ToHexString(clientData.ClientDataHash) == expectedClientDataHash,
            "client data did not defensively copy returned byte arrays");
    }

    private static void TestGrantDraftContract()
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generation = CreateGeneration("draft-generation");
        var credentialId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var nonce = Enumerable.Range(0, 32).Select(index => checked((byte)(0x20 + index))).ToArray();
        var expectedCredentialId = credentialId.ToArray();
        var expectedNonce = nonce.ToArray();
        using var signedVector = BrokerWebAuthnTestVectorsV1.CreateSignedConsent(
            genesis,
            expectedRevision: 0,
            generation,
            ReceiptId,
            credentialId,
            nonce,
            IssuedAtUtcTicks);
        var draft = signedVector.Draft;
        var credentialPublicKeySha256 = signedVector.Credential.SubjectPublicKeyInfoSha256;
        var fields = draft.StatementFields;
        Ensure(ReferenceEquals(draft.CurrentLedger, genesis), "draft did not retain the exact current ledger");
        Ensure(draft.ExpectedRevision == 0, "draft changed the expected revision");
        Ensure(ReferenceEquals(draft.Generation, generation), "draft did not retain the exact package generation");
        Ensure(fields.LedgerId == LedgerId, "draft changed the ledger id");
        Ensure(fields.Revision == 1 && fields.Sequence == 1, "draft changed the next revision or sequence");
        Ensure(fields.PreviousEntrySha256 == genesis.EntrySha256, "draft changed the previous entry hash");
        Ensure(fields.RevocationGeneration == 0, "draft changed the first revocation generation");
        Ensure(fields.ReceiptId == ReceiptId, "draft changed the receipt id");
        Ensure(fields.GenerationSha256 == generation.GenerationSha256, "draft changed the generation hash");
        Ensure(fields.Capability == BrokerConsentLedgerV1.CapabilityName, "draft changed the fixed capability");
        Ensure(fields.IssuedAtUtcTicks == IssuedAtUtcTicks, "draft changed the issued-at timestamp");
        Ensure(fields.ReceiptFormat == BrokerConsentLedgerV1.ReceiptFormatName, "draft changed the receipt format");
        Ensure(
            fields.CredentialIdBase64 == Convert.ToBase64String(expectedCredentialId),
            "draft changed the canonical credential id");
        Ensure(
            fields.CredentialPublicKeySha256 == credentialPublicKeySha256,
            "draft changed the uppercase credential public-key hash");
        Ensure(
            fields.ChallengeNonceBase64 == Convert.ToBase64String(expectedNonce),
            "draft changed the canonical nonce");

        var expectedStatement =
            $"{{\"schema\":\"{BrokerConsentLedgerV1.StatementSchemaName}\",\"ledgerId\":\"{LedgerId:D}\"," +
            $"\"revision\":1,\"sequence\":1,\"previousEntrySha256\":\"{genesis.EntrySha256}\"," +
            $"\"revocationGeneration\":0,\"receiptId\":\"{ReceiptId:D}\"," +
            $"\"generationSha256\":\"{generation.GenerationSha256}\"," +
            $"\"capability\":\"{BrokerConsentLedgerV1.CapabilityName}\",\"issuedAtUtcTicks\":{IssuedAtUtcTicks}," +
            $"\"receiptFormat\":\"{BrokerConsentLedgerV1.ReceiptFormatName}\"," +
            $"\"credentialIdBase64\":\"{Convert.ToBase64String(expectedCredentialId)}\"," +
            $"\"credentialPublicKeySha256\":\"{credentialPublicKeySha256}\"," +
            $"\"challengeNonceBase64\":\"{Convert.ToBase64String(expectedNonce)}\"}}";
        var expectedStatementBytes = Encoding.UTF8.GetBytes(expectedStatement);
        Ensure(
            draft.ConsentStatementBytes.SequenceEqual(expectedStatementBytes),
            "draft consent statement bytes changed");
        Ensure(
            draft.ConsentStatementSha256 == Convert.ToHexString(SHA256.HashData(expectedStatementBytes)),
            "draft consent statement hash changed");
        Ensure(
            BrokerConsentLedgerV1.CreateConsentStatement(fields).SequenceEqual(expectedStatementBytes),
            "shared consent statement serializer changed draft bytes");

        credentialId[0] ^= 0xFF;
        nonce[0] ^= 0xFF;
        var returnedCredential = draft.CredentialId;
        var returnedNonce = draft.ChallengeNonce;
        var returnedStatement = draft.ConsentStatementBytes;
        returnedCredential[1] ^= 0xFF;
        returnedNonce[1] ^= 0xFF;
        returnedStatement[0] ^= 0xFF;
        Ensure(draft.CredentialId.SequenceEqual(expectedCredentialId), "draft credential id was not deeply frozen");
        Ensure(draft.ChallengeNonce.SequenceEqual(expectedNonce), "draft nonce was not deeply frozen");
        Ensure(
            draft.ConsentStatementBytes.SequenceEqual(expectedStatementBytes),
            "draft statement bytes were not deeply frozen");

        using var verified = BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
            draft,
            signedVector.Credential,
            signedVector.Assertion);
        var grant = draft.FinalizeGrant(verified);
        var statementFromGrant = BrokerConsentLedgerV1.CreateConsentStatement(grant);
        var statementFromFields = BrokerConsentLedgerV1.CreateConsentStatement(fields);
        Ensure(
            statementFromGrant.SequenceEqual(draft.ConsentStatementBytes) &&
            statementFromFields.SequenceEqual(draft.ConsentStatementBytes),
            "grant, draft, and shared-fields consent statement bytes diverged");
        var replacement = BrokerConsentGrantDraftV1.Create(
            grant,
            1,
            generation,
            Guid.ParseExact("22222222-3333-4444-5555-666666666666", "D"),
            expectedCredentialId,
            credentialPublicKeySha256,
            expectedNonce,
            IssuedAtUtcTicks + 1);
        Ensure(
            replacement.StatementFields.Revision == 2 &&
            replacement.StatementFields.RevocationGeneration == 1,
            "a replacement draft did not advance revision and revocation generation");
        var revoke = BrokerConsentLedgerTransition.CreateRevoke(
            grant,
            1,
            BrokerConsentRevokeReasonV1.UserRequested,
            IssuedAtUtcTicks + 1);
        var afterRevoke = BrokerConsentGrantDraftV1.Create(
            revoke,
            2,
            generation,
            Guid.ParseExact("33333333-4444-5555-6666-777777777777", "D"),
            expectedCredentialId,
            credentialPublicKeySha256,
            expectedNonce,
            IssuedAtUtcTicks + 2);
        Ensure(
            afterRevoke.StatementFields.Revision == 3 &&
            afterRevoke.StatementFields.RevocationGeneration == revoke.Entry.RevocationGeneration,
            "a post-revoke draft changed revocation generation twice");

        var invalidCurrent = new BrokerConsentLedgerDocumentV1(
            genesis.LedgerId,
            genesis.Revision,
            genesis.Entry,
            new string('F', 64),
            genesis.ValidationState);
        ExpectCode(
            () => CreateDraft(invalidCurrent, 0, generation, ReceiptId, expectedCredentialId, credentialPublicKeySha256, expectedNonce, IssuedAtUtcTicks),
            "consent-ledger-schema");
        ExpectCode(
            () => CreateDraft(genesis, 1, generation, ReceiptId, expectedCredentialId, credentialPublicKeySha256, expectedNonce, IssuedAtUtcTicks),
            "consent-ledger-transition-invalid");
        ExpectCode(
            () => CreateDraft(genesis, 0, CreateForgedGeneration(generation), ReceiptId, expectedCredentialId, credentialPublicKeySha256, expectedNonce, IssuedAtUtcTicks),
            "consent-ledger-generation-invalid");
        ExpectCode(
            () => CreateDraft(genesis, 0, generation, Guid.Empty, expectedCredentialId, credentialPublicKeySha256, expectedNonce, IssuedAtUtcTicks),
            "consent-ledger-receipt-invalid");
        ExpectCode(
            () => CreateDraft(genesis, 0, generation, ReceiptId, Array.Empty<byte>(), credentialPublicKeySha256, expectedNonce, IssuedAtUtcTicks),
            "consent-ledger-receipt-invalid");
        ExpectCode(
            () => CreateDraft(genesis, 0, generation, ReceiptId, new byte[1025], credentialPublicKeySha256, expectedNonce, IssuedAtUtcTicks),
            "consent-ledger-receipt-invalid");
        ExpectCode(
            () => CreateDraft(genesis, 0, generation, ReceiptId, expectedCredentialId, credentialPublicKeySha256.ToLowerInvariant(), expectedNonce, IssuedAtUtcTicks),
            "consent-ledger-schema");
        ExpectCode(
            () => CreateDraft(genesis, 0, generation, ReceiptId, expectedCredentialId, credentialPublicKeySha256, new byte[31], IssuedAtUtcTicks),
            "consent-ledger-receipt-invalid");
        ExpectCode(
            () => CreateDraft(genesis, 0, generation, ReceiptId, expectedCredentialId, credentialPublicKeySha256, expectedNonce, DateTime.UnixEpoch.Ticks - 1),
            "consent-ledger-schema");
        ExpectArgumentNull(
            () => BrokerConsentGrantDraftV1.Create(
                genesis,
                0,
                generation,
                ReceiptId,
                null!,
                credentialPublicKeySha256,
                expectedNonce,
                IssuedAtUtcTicks));
        ExpectArgumentNull(
            () => BrokerConsentGrantDraftV1.Create(
                genesis,
                0,
                generation,
                ReceiptId,
                expectedCredentialId,
                credentialPublicKeySha256,
                null!,
                IssuedAtUtcTicks));

        var type = typeof(BrokerConsentGrantDraftV1);
        Ensure(
            FindForbiddenDraftAuthorityParameters(type).Length == 0,
            "draft constructor or factory accepted a proof or signature parameter");
        var boundaryProbe = FindForbiddenDraftAuthorityParameters(
            typeof(DraftFactoryBoundaryProbe));
        Ensure(
            boundaryProbe.Length == 2 &&
            boundaryProbe.Any(parameter =>
                parameter.Name == "proofEnvelope" &&
                parameter.Member.Name == "Build") &&
            boundaryProbe.Any(parameter =>
                parameter.Name == "value" &&
                parameter.ParameterType == typeof(SyntheticSignatureEnvelope) &&
                parameter.Member.Name == "Assemble"),
            "draft authority boundary probe did not cover alternate factory names and parameter types");
        var finalizers = type.GetMethods(
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(method => method.Name.Contains("Finalize", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Ensure(
            finalizers.Length == 1 &&
            finalizers[0].Name == "FinalizeGrant" &&
            finalizers[0].IsAssembly &&
            finalizers[0].ReturnType == typeof(BrokerConsentLedgerDocumentV1) &&
            finalizers[0].GetParameters().Select(parameter => parameter.ParameterType)
                .SequenceEqual(
                    new[]
                    {
                        typeof(BrokerWebAuthnReceiptVerifierV1.VerifiedUserPresenceEvidenceV1)
                    }),
            "draft finalization is not restricted to exact verified user-presence evidence");

        _ = MeasureRejectedCredentialAllocation(
            genesis,
            generation,
            credentialPublicKeySha256,
            expectedNonce,
            new byte[1025]);
        _ = MeasureRejectedNonceAllocation(
            genesis,
            generation,
            credentialPublicKeySha256,
            expectedCredentialId,
            new byte[31]);
        var oversizedCredential = new byte[1024 * 1024];
        var oversizedNonce = new byte[1024 * 1024];
        var credentialRejectionAllocation = MeasureRejectedCredentialAllocation(
            genesis,
            generation,
            credentialPublicKeySha256,
            expectedNonce,
            oversizedCredential);
        var nonceRejectionAllocation = MeasureRejectedNonceAllocation(
            genesis,
            generation,
            credentialPublicKeySha256,
            expectedCredentialId,
            oversizedNonce);
        const long RejectionAllocationLimit = 64 * 1024;
        Ensure(
            credentialRejectionAllocation < RejectionAllocationLimit &&
            nonceRejectionAllocation < RejectionAllocationLimit,
            $"oversized draft input rejection allocated credential={credentialRejectionAllocation} nonce={nonceRejectionAllocation} bytes");
    }

    private static ValueTask<BrokerWebAuthnCeremonyContextV1> ReturnContextAsync(
        BrokerWebAuthnCeremonyContextV1 context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(context);
    }

    private static async Task ExpectVerificationCodeAsync(
        Func<Task> action,
        string expectedCode)
    {
        try
        {
            await action();
        }
        catch (BrokerUserPresenceVerificationException exception) when (
            string.Equals(exception.Code, expectedCode, StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException(
            "Expected user-presence verification code " + expectedCode + ".");
    }

    private static async Task ExpectFreshPlatformFailureAsync(
        FakeWebAuthnBehavior behavior,
        BrokerWebAuthnCeremonyContextV1 context,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        string expectedCode,
        TimeSpan timeout)
    {
        using var platform = new FakeWebAuthnPlatformV1(behavior);
        using var ceremony = new BrokerWebAuthnCeremonyV1(platform, timeout);
        await ExpectVerificationCodeAsync(
            () => ceremony.CreateFreshPresenceAsync(
                    context,
                    credential,
                    token => ReturnContextAsync(context, token),
                    CancellationToken.None)
                .AsTask(),
            expectedCode);
        Ensure(
            platform.RegistrationCalls == 0 &&
            platform.AssertionCalls == 1 &&
            platform.LastAssertionRequestCleared &&
            platform.LastAssertionEvidenceCleared,
            behavior + " did not fail closed with cleared request/evidence state");
    }

    private static async Task ExpectFreshContextDriftAsync(
        BrokerWebAuthnCeremonyContextV1 initial,
        BrokerWebAuthnCeremonyContextV1 current,
        BrokerWebAuthnRegisteredCredentialV1 credential,
        string expectedCode)
    {
        using var platform = new FakeWebAuthnPlatformV1(FakeWebAuthnBehavior.Normal);
        using var ceremony = new BrokerWebAuthnCeremonyV1(
            platform,
            TimeSpan.FromSeconds(2));
        await ExpectVerificationCodeAsync(
            () => ceremony.CreateFreshPresenceAsync(
                    initial,
                    credential,
                    token => ReturnContextAsync(current, token),
                    CancellationToken.None)
                .AsTask(),
            expectedCode);
        Ensure(
            platform.RegistrationCalls == 0 &&
            platform.AssertionCalls == 1 &&
            platform.LastAssertionRequestCleared &&
            platform.LastAssertionEvidenceCleared,
            "context drift did not discard and clear the completed assertion");
    }

    private static byte[] CreateExpectedWindowsUserHandle(string windowsSid)
    {
        var domain = Encoding.ASCII.GetBytes(
            "CodexGuardian\0WindowsUserHandle\0v1\0");
        var sid = Encoding.UTF8.GetBytes(windowsSid);
        var input = JoinBytes(domain, sid);
        try
        {
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(domain);
            CryptographicOperations.ZeroMemory(sid);
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static BrokerConsentLedgerStoreSnapshotV1 CreateGenesisSnapshot(
        BrokerConsentLedgerDocumentV1 genesis) =>
        new(
            BrokerConsentLedgerStoreStateV1.HealthyGenesis,
            genesis,
            new BrokerConsentLedgerStoreDiagnosticsV1(
                BrokerConsentLedgerReplicaStateV1.Canonical,
                BrokerConsentLedgerReplicaStateV1.Missing,
                "store-healthy-genesis"));

    private static BrokerConsentLedgerStoreSnapshotV1 CreateRevokedSnapshot(
        BrokerConsentLedgerDocumentV1 revoke) =>
        new(
            BrokerConsentLedgerStoreStateV1.NoAuthority,
            revoke,
            new BrokerConsentLedgerStoreDiagnosticsV1(
                BrokerConsentLedgerReplicaStateV1.Canonical,
                BrokerConsentLedgerReplicaStateV1.Canonical,
                "store-no-authority-revoked"));

    private enum FakeWebAuthnBehavior
    {
        Normal,
        BlockAssertion,
        UserCancelled,
        WaitForCancellation,
        LateAssertion,
        NativeFailure,
        WrongCredential
    }

    private sealed class FakeWebAuthnPlatformV1 : IWebAuthnPlatformV1, IDisposable
    {
        private readonly FakeWebAuthnBehavior _behavior;
        private readonly byte[] _credentialId =
            BrokerWebAuthnTestVectorsV1.CredentialId(0x10);
        private readonly TaskCompletionSource<bool> _releaseAssertion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private byte[] _observedRegistrationUserHandle = Array.Empty<byte>();
        private byte[][]? _lastRegistrationRequestOwned;
        private byte[][]? _lastRegistrationEvidenceOwned;
        private byte[][]? _lastAssertionRequestOwned;
        private byte[][]? _lastAssertionEvidenceOwned;
        private int _registrationCalls;
        private int _assertionCalls;
        private int _disposed;

        internal FakeWebAuthnPlatformV1(FakeWebAuthnBehavior behavior)
        {
            _behavior = behavior;
        }

        internal TaskCompletionSource<bool> AssertionEntered { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal int RegistrationCalls => Volatile.Read(ref _registrationCalls);

        internal int AssertionCalls => Volatile.Read(ref _assertionCalls);

        internal bool FixedPolicyObserved { get; private set; } = true;

        internal byte[] CredentialId
        {
            get
            {
                ThrowIfDisposed();
                return (byte[])_credentialId.Clone();
            }
        }

        internal byte[] ObservedRegistrationUserHandle
        {
            get
            {
                ThrowIfDisposed();
                return (byte[])_observedRegistrationUserHandle.Clone();
            }
        }

        internal bool LastRegistrationRequestCleared => IsCleared(_lastRegistrationRequestOwned);

        internal bool LastRegistrationEvidenceCleared => IsCleared(_lastRegistrationEvidenceOwned);

        internal bool LastAssertionRequestCleared => IsCleared(_lastAssertionRequestOwned);

        internal bool LastAssertionEvidenceCleared => IsCleared(_lastAssertionEvidenceOwned);

        public ValueTask<WebAuthnRegistrationEvidenceV1> RegisterPlatformCredentialAsync(
            FrozenWebAuthnRegistrationRequestV1 request,
            BrokerOwnedWindowHandle owner,
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            _ = Interlocked.Increment(ref _registrationCalls);
            _lastRegistrationRequestOwned = GetOwnedByteArrays(request);
            ObserveRegistrationPolicy(request, owner);
            byte[]? clientDataJson = null;
            byte[]? relyingPartyIdHash = null;
            byte[]? userHandle = null;
            byte[]? coseKey = null;
            byte[]? authenticatorData = null;
            WebAuthnRegistrationEvidenceV1? evidence = null;
            try
            {
                clientDataJson = request.ClientDataJson;
                relyingPartyIdHash = request.RelyingPartyIdHash;
                userHandle = request.DerivedUserHandle;
                coseKey = CreateValidCoseP256Key(1, 3, -1, -2, -3);
                authenticatorData = CreateRegistrationAuthenticatorData(
                    relyingPartyIdHash,
                    flags: 0x45,
                    _credentialId,
                    coseKey);
                CryptographicOperations.ZeroMemory(_observedRegistrationUserHandle);
                _observedRegistrationUserHandle = (byte[])userHandle.Clone();
                evidence = WebAuthnRegistrationEvidenceV1.Create(
                    clientDataJson,
                    _credentialId,
                    authenticatorData,
                    new byte[] { 0x01 },
                    userHandle);
                _lastRegistrationEvidenceOwned = GetOwnedByteArrays(evidence);
                var result = evidence;
                evidence = null;
                return ValueTask.FromResult(result);
            }
            finally
            {
                evidence?.Dispose();
                CryptographicOperations.ZeroMemory(clientDataJson ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(relyingPartyIdHash ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(userHandle ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(coseKey ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(authenticatorData ?? Array.Empty<byte>());
            }
        }

        public async ValueTask<WebAuthnAssertionEvidenceV1> GetAssertionAsync(
            FrozenWebAuthnAssertionRequestV1 request,
            BrokerOwnedWindowHandle owner,
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            _ = Interlocked.Increment(ref _assertionCalls);
            _lastAssertionRequestOwned = GetOwnedByteArrays(request);
            ObserveAssertionPolicy(request, owner);
            AssertionEntered.TrySetResult(true);
            switch (_behavior)
            {
                case FakeWebAuthnBehavior.BlockAssertion:
                    await _releaseAssertion.Task.WaitAsync(cancellationToken);
                    break;
                case FakeWebAuthnBehavior.UserCancelled:
                    throw new BrokerUserPresenceVerificationException(
                        "user-presence-cancelled",
                        "The fake user cancelled verification.");
                case FakeWebAuthnBehavior.WaitForCancellation:
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                    break;
                case FakeWebAuthnBehavior.LateAssertion:
                    await _releaseAssertion.Task;
                    break;
                case FakeWebAuthnBehavior.NativeFailure:
                    throw new InvalidOperationException("synthetic native ambiguity");
            }

            if (_behavior != FakeWebAuthnBehavior.LateAssertion)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }
            var evidence = CreateAssertionEvidence(
                request,
                wrongCredential: _behavior == FakeWebAuthnBehavior.WrongCredential);
            _lastAssertionEvidenceOwned = GetOwnedByteArrays(evidence);
            return evidence;
        }

        internal void ReleaseAssertion() => _releaseAssertion.TrySetResult(true);

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(_credentialId);
            CryptographicOperations.ZeroMemory(_observedRegistrationUserHandle);
            _releaseAssertion.TrySetCanceled();
        }

        private WebAuthnAssertionEvidenceV1 CreateAssertionEvidence(
            FrozenWebAuthnAssertionRequestV1 request,
            bool wrongCredential)
        {
            byte[]? clientDataJson = null;
            byte[]? clientDataHash = null;
            byte[]? credentialId = null;
            byte[]? authenticatorData = null;
            byte[]? signedData = null;
            byte[]? nativeDerSignature = null;
            try
            {
                clientDataJson = request.ClientDataJson;
                clientDataHash = request.ClientDataHash;
                credentialId = request.CredentialId;
                if (wrongCredential)
                {
                    credentialId[0] ^= 0xFF;
                }

                authenticatorData = CreateAssertionAuthenticatorData(
                    SHA256.HashData(
                        Encoding.ASCII.GetBytes(BrokerWebAuthnConstantsV1.RelyingPartyId)),
                    flags: 0x05,
                    counter: 0);
                signedData = JoinBytes(authenticatorData, clientDataHash);
                using var key = BrokerWebAuthnTestVectorsV1.CreateKey(variant: 1);
                nativeDerSignature = key.SignData(
                    signedData,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence);
                return WebAuthnAssertionEvidenceV1.Create(
                    clientDataJson,
                    credentialId,
                    authenticatorData,
                    nativeDerSignature,
                    userHandle: null);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clientDataJson ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(clientDataHash ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(credentialId ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(authenticatorData ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(signedData ?? Array.Empty<byte>());
                CryptographicOperations.ZeroMemory(nativeDerSignature ?? Array.Empty<byte>());
            }
        }

        private void ObserveRegistrationPolicy(
            FrozenWebAuthnRegistrationRequestV1 request,
            BrokerOwnedWindowHandle owner)
        {
            FixedPolicyObserved &=
                request.RelyingPartyId == BrokerWebAuthnConstantsV1.RelyingPartyId &&
                request.Origin == BrokerWebAuthnConstantsV1.Origin &&
                request.Algorithm == BrokerWebAuthnConstantsV1.Es256Algorithm &&
                request.UserVerification == BrokerWebAuthnConstantsV1.UserVerification &&
                request.AuthenticatorAttachment == BrokerWebAuthnConstantsV1.PlatformAttachment &&
                !request.ExtensionsEnabled &&
                owner.OwnerProcessId == Environment.ProcessId;
        }

        private void ObserveAssertionPolicy(
            FrozenWebAuthnAssertionRequestV1 request,
            BrokerOwnedWindowHandle owner)
        {
            FixedPolicyObserved &=
                request.RelyingPartyId == BrokerWebAuthnConstantsV1.RelyingPartyId &&
                request.Origin == BrokerWebAuthnConstantsV1.Origin &&
                request.Algorithm == BrokerWebAuthnConstantsV1.Es256Algorithm &&
                request.UserVerification == BrokerWebAuthnConstantsV1.UserVerification &&
                !request.ExtensionsEnabled &&
                owner.OwnerProcessId == Environment.ProcessId;
        }

        private static bool IsCleared(byte[][]? arrays) =>
            arrays is null || arrays.All(array => array.All(value => value == 0));

        private void ThrowIfDisposed() =>
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    }

    private static BrokerConsentLedgerStoreSnapshotV1 CreatePendingSnapshot(
        BrokerConsentLedgerDocumentV1 grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        Ensure(
            grant.ValidationState == BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification &&
            grant.Entry is BrokerConsentGrantEntryV1,
            "fresh-presence fixture requires a pending grant");
        return new BrokerConsentLedgerStoreSnapshotV1(
            BrokerConsentLedgerStoreStateV1.ReceiptPendingVerification,
            grant,
            new BrokerConsentLedgerStoreDiagnosticsV1(
                BrokerConsentLedgerReplicaStateV1.Canonical,
                BrokerConsentLedgerReplicaStateV1.Canonical,
                "store-receipt-pending-verification"));
    }

    private static BrokerWebAuthnRegisteredCredentialV1 CreateRegisteredCredential(
        byte[] credentialId,
        int keyVariant)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        var subjectPublicKeyInfo = BrokerWebAuthnTestVectorsV1.SubjectPublicKeyInfo(keyVariant);
        try
        {
            return new BrokerWebAuthnRegisteredCredentialV1(
                credentialId,
                subjectPublicKeyInfo,
                Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        }
    }

    private static BrokerFreshPresenceSessionV1 CreateFreshSession(
        string brokerEpoch,
        uint windowsSessionId,
        BrokerConsentLedgerStoreSnapshotV1 snapshot,
        CodexPackageGenerationV1 generation,
        byte nonceSeed)
    {
        var grant = snapshot.Primary ?? throw new InvalidOperationException(
            "fresh-presence fixture snapshot lost its primary grant");
        var receipt = ((BrokerConsentGrantEntryV1)grant.Entry).Receipt;
        var credentialId = Convert.FromBase64String(receipt.CredentialIdBase64);
        try
        {
            using var persisted = BrokerWebAuthnReceiptVerifierV1.VerifyPersistedGrant(grant);
            using var statement = BrokerFreshPresenceStatementV1.Create(
                brokerEpoch,
                windowsSessionId,
                snapshot,
                generation,
                BrokerConsentLedgerV1.CapabilityName,
                persisted,
                BrokerWebAuthnTestVectorsV1.Nonce(nonceSeed));
            using var vector = BrokerWebAuthnTestVectorsV1.CreateSignedAssertionForFresh(
                statement,
                credentialId,
                keyVariant: 1,
                statement.CredentialPublicKeySha256);
            using var fresh = BrokerWebAuthnReceiptVerifierV1.VerifyFreshAssertion(
                statement,
                vector.Credential,
                vector.Assertion);
            return BrokerFreshPresenceSessionV1.Create(statement, fresh);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credentialId);
        }
    }

    private static void ExpectFreshSessionInvalidated(
        BrokerFreshPresenceSessionV1 session,
        Action<BrokerFreshPresenceSessionV1> action,
        string expectedCode)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(action);
        var ownedArrays = GetOwnedByteArrays(session);
        try
        {
            ExpectVerificationCode(() => action(session), expectedCode);
            Ensure(
                ownedArrays.All(array => array.All(value => value == 0)),
                "invalidated fresh-presence session retained owned bytes");
            ExpectObjectDisposed(() => _ = session.SessionId);
        }
        finally
        {
            session.Dispose();
        }
    }

    private static BrokerConsentGrantDraftV1 CreateDraft(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        Guid receiptId,
        byte[] credentialId,
        string credentialPublicKeySha256,
        byte[] nonce,
        long issuedAtUtcTicks) =>
        BrokerConsentGrantDraftV1.Create(
            current,
            expectedRevision,
            generation,
            receiptId,
            credentialId,
            credentialPublicKeySha256,
            nonce,
            issuedAtUtcTicks);

    private static CodexPackageGenerationV1 CreateGeneration(string seed)
    {
        var artifacts = new[]
        {
            new CodexPackageGenerationArtifactV1(CodexPackageGenerationV1.AppxSignatureRelativePath, 10, Hash(seed + "-signature")),
            new CodexPackageGenerationArtifactV1(CodexPackageGenerationV1.AppxBlockMapRelativePath, 20, Hash(seed + "-blockmap")),
            new CodexPackageGenerationArtifactV1(CodexPackageGenerationV1.ManifestRelativePath, 30, Hash(seed + "-manifest")),
            new CodexPackageGenerationArtifactV1(CodexPackageGenerationV1.ChatGptExecutableRelativePath, 40, Hash(seed + "-chatgpt")),
            new CodexPackageGenerationArtifactV1(CodexPackageGenerationV1.CodexExecutableRelativePath, 50, Hash(seed + "-codex")),
            new CodexPackageGenerationArtifactV1(CodexPackageGenerationV1.AppAsarRelativePath, 60, Hash(seed + "-asar"))
        };
        return CodexPackageGenerationV1.Create(
            new CodexPackageGenerationPackageV1(
                "OpenAI.Codex_1.0.0.0_x64__fixture",
                "OpenAI.Codex_fixture",
                "OpenAI.Codex",
                "1.0.0.0",
                "CN=Fixture",
                "fixture",
                string.Empty,
                "x64",
                1),
            new CodexPackageGenerationSignerV1(
                "CN=Fixture",
                "CN=Fixture CA",
                Hash(seed + "-certificate"),
                Hash(seed + "-spki"),
                Hash(seed + "-thumbprint"),
                DateTime.UnixEpoch.Ticks,
                DateTime.UnixEpoch.AddYears(10).Ticks),
            artifacts,
            new CodexPackageGenerationManifestV1(
                "OpenAI.Codex",
                "CN=Fixture",
                "1.0.0.0",
                "x64",
                "app\\ChatGPT.exe",
                "Windows.FullTrustApplication"),
            new CodexPackageGenerationAsarV1(
                "codex-cdp-observation-v1",
                "openai-codex-electron",
                "Codex",
                "1.0.0",
                ".vite/build/early-bootstrap.js",
                new CodexPackageGenerationAsarEntryV1("package.json", 10, Hash(seed + "-package-json")),
                new CodexPackageGenerationAsarEntryV1(".vite/build/early-bootstrap.js", 20, Hash(seed + "-main")),
                new CodexPackageGenerationAsarEntryV1(".vite/build/preload.js", 30, Hash(seed + "-preload"))));
    }

    private static CodexPackageGenerationV1 CreateForgedGeneration(
        CodexPackageGenerationV1 generation,
        string? canonicalJson = null,
        string? generationSha256 = null)
    {
        var constructor = typeof(CodexPackageGenerationV1).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[]
            {
                typeof(CodexPackageGenerationPackageV1),
                typeof(CodexPackageGenerationSignerV1),
                typeof(IReadOnlyList<CodexPackageGenerationArtifactV1>),
                typeof(CodexPackageGenerationManifestV1),
                typeof(CodexPackageGenerationAsarV1),
                typeof(string),
                typeof(string)
            },
            modifiers: null) ?? throw new InvalidOperationException(
                "The exact CodexPackageGenerationV1 constructor is missing.");
        return (CodexPackageGenerationV1)constructor.Invoke(new object[]
        {
            generation.Package,
            generation.Signer,
            generation.Artifacts,
            generation.Manifest,
            generation.Asar,
            canonicalJson ?? generation.CanonicalJson,
            generationSha256 ?? new string('F', 64)
        });
    }

    private static ParameterInfo[] FindForbiddenDraftAuthorityParameters(Type type)
    {
        var constructorParameters = type.GetConstructors(
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .SelectMany(constructor => constructor.GetParameters());
        var factoryParameters = type.GetMethods(
                BindingFlags.Static |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(method => method.ReturnType == typeof(BrokerConsentGrantDraftV1))
            .SelectMany(method => method.GetParameters());
        return constructorParameters.Concat(factoryParameters)
            .Where(parameter =>
                ContainsAuthorityToken(parameter.Name) ||
                ContainsAuthorityToken(parameter.ParameterType.FullName) ||
                ContainsAuthorityToken(parameter.ParameterType.Name))
            .ToArray();
    }

    private static bool HasExactWebAuthnFactorySurface(
        Type type,
        params (string Name, Type[] ParameterTypes)[] expectedFactories)
    {
        var nonPrivateConstructors = type.GetConstructors(
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(constructor => !constructor.IsPrivate)
            .ToArray();
        if (nonPrivateConstructors.Length != 0)
        {
            return false;
        }

        var actualFactories = type.GetMethods(
                BindingFlags.Static |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(method => !method.IsPrivate && method.ReturnType == type)
            .ToList();
        if (actualFactories.Count != expectedFactories.Length)
        {
            return false;
        }

        foreach (var expected in expectedFactories)
        {
            var match = actualFactories.FindIndex(method =>
                method.Name == expected.Name &&
                method.GetParameters()
                    .Select(parameter => parameter.ParameterType)
                    .SequenceEqual(expected.ParameterTypes));
            if (match < 0)
            {
                return false;
            }

            actualFactories.RemoveAt(match);
        }

        return actualFactories.Count == 0;
    }

    private static bool HasExactWebAuthnStateSurface(
        Type type,
        params (string Name, Type PropertyType)[] expectedProperties)
    {
        var nonPrivateFields = type.GetFields(
                BindingFlags.Static |
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(field => !field.IsPrivate)
            .ToArray();
        if (nonPrivateFields.Length != 0)
        {
            return false;
        }

        var actualProperties = type.GetProperties(
                BindingFlags.Static |
                BindingFlags.Instance |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(property =>
                property.GetMethod is { IsPrivate: false } ||
                property.SetMethod is { IsPrivate: false })
            .ToList();
        if (actualProperties.Count != expectedProperties.Length)
        {
            return false;
        }

        foreach (var expected in expectedProperties)
        {
            var match = actualProperties.FindIndex(property =>
                property.Name == expected.Name &&
                property.PropertyType == expected.PropertyType &&
                property.GetMethod is { IsPrivate: false, IsStatic: false } &&
                property.SetMethod is null &&
                property.GetIndexParameters().Length == 0);
            if (match < 0)
            {
                return false;
            }

            actualProperties.RemoveAt(match);
        }

        return actualProperties.Count == 0;
    }

    private static bool ContainsAuthorityToken(string? value) =>
        value?.Contains("proof", StringComparison.OrdinalIgnoreCase) == true ||
        value?.Contains("signature", StringComparison.OrdinalIgnoreCase) == true;

    private static long MeasureRejectedCredentialAllocation(
        BrokerConsentLedgerDocumentV1 current,
        CodexPackageGenerationV1 generation,
        string credentialPublicKeySha256,
        byte[] nonce,
        byte[] oversizedCredential)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        ExpectCode(
            () => CreateDraft(
                current,
                0,
                generation,
                ReceiptId,
                oversizedCredential,
                credentialPublicKeySha256,
                nonce,
                IssuedAtUtcTicks),
            "consent-ledger-receipt-invalid");
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    private static long MeasureRejectedNonceAllocation(
        BrokerConsentLedgerDocumentV1 current,
        CodexPackageGenerationV1 generation,
        string credentialPublicKeySha256,
        byte[] credentialId,
        byte[] oversizedNonce)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        ExpectCode(
            () => CreateDraft(
                current,
                0,
                generation,
                ReceiptId,
                credentialId,
                credentialPublicKeySha256,
                oversizedNonce,
                IssuedAtUtcTicks),
            "consent-ledger-receipt-invalid");
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    private sealed class DraftFactoryBoundaryProbe
    {
        private static BrokerConsentGrantDraftV1 Build(byte[] proofEnvelope) => null!;

        private static BrokerConsentGrantDraftV1 Assemble(
            SyntheticSignatureEnvelope value) => null!;
    }

    private sealed class SyntheticSignatureEnvelope
    {
    }

    private sealed class SyntheticConfigurableClientDataV1
    {
        private SyntheticConfigurableClientDataV1()
        {
        }

        internal static SyntheticConfigurableClientDataV1 CreateRegistration(
            BrokerWebAuthnRegistrationStatementV1 statement) => null!;

        internal static SyntheticConfigurableClientDataV1 CreateRegistration(
            BrokerWebAuthnRegistrationStatementV1 statement,
            AuthorityControls controls) => null!;
    }

    private static class SyntheticGetterOnlyMutableStateV1
    {
        internal static AuthorityControls CurrentControls { get; } = new();
    }

    private static class SyntheticReadonlyMutableStateV1
    {
        internal static readonly AuthorityControls SharedControls = new();
    }

    private sealed class AuthorityControls
    {
        internal int Values { get; set; }
    }

    private static byte[] CreateAssertionAuthenticatorData(
        byte[] rpIdHash,
        byte flags,
        uint counter)
    {
        Ensure(rpIdHash.Length == 32, "assertion fixture RP hash changed");
        return JoinBytes(
            rpIdHash,
            new[]
            {
                flags,
                checked((byte)((counter >> 24) & byte.MaxValue)),
                checked((byte)((counter >> 16) & byte.MaxValue)),
                checked((byte)((counter >> 8) & byte.MaxValue)),
                checked((byte)(counter & byte.MaxValue))
            });
    }

    private static byte[] CreateCanonicalDerSignature(byte[] r, byte[] s) =>
        CreateRawDerSequence(
            EncodeCanonicalDerInteger(r),
            EncodeCanonicalDerInteger(s));

    private static byte[] EncodeCanonicalDerInteger(byte[] scalar)
    {
        Ensure(scalar.Length > 0, "DER fixture scalar is empty");
        var offset = 0;
        while (offset < scalar.Length - 1 && scalar[offset] == 0)
        {
            offset++;
        }

        var magnitude = scalar[offset..];
        return EncodeRawDerInteger(
            (magnitude[0] & 0x80) == 0
                ? magnitude
                : JoinBytes(new byte[] { 0x00 }, magnitude));
    }

    private static byte[] EncodeRawDerInteger(byte[] encodedValue)
    {
        Ensure(encodedValue.Length <= 127, "DER fixture INTEGER is too large");
        return JoinBytes(
            new byte[] { 0x02, checked((byte)encodedValue.Length) },
            encodedValue);
    }

    private static byte[] CreateRawDerSequence(params byte[][] encodedValues)
    {
        var body = JoinBytes(encodedValues);
        Ensure(body.Length <= 127, "DER fixture SEQUENCE is too large");
        return JoinBytes(
            new byte[] { 0x30, checked((byte)body.Length) },
            body);
    }

    private static byte[] P256OrderBytes() =>
        Convert.FromHexString(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    private static void ExpectDerRejected(byte[] nativeDerSignature) =>
        ExpectArgumentException(
            () =>
            {
                var normalized = BrokerWebAuthnDerSignatureV1.NormalizeToP1363(
                    nativeDerSignature);
                CryptographicOperations.ZeroMemory(normalized);
            });

    private static void ExpectProofCreateRejected(
        byte[] subjectPublicKeyInfo,
        byte[] authenticatorData,
        byte[] nativeDerSignature) =>
        ExpectArgumentException(
            () => BrokerWebAuthnAssertionProofV1.Create(
                subjectPublicKeyInfo,
                authenticatorData,
                nativeDerSignature).Dispose());

    private static void ExpectEnvelopeRejected(byte[] envelope) =>
        ExpectArgumentException(
            () => BrokerWebAuthnAssertionProofV1.Parse(envelope).Dispose());

    private static bool HasExactProofFactorySurface() =>
        HasExactWebAuthnFactorySurface(
            typeof(BrokerWebAuthnAssertionProofV1),
            (
                "Create",
                new[]
                {
                    typeof(ReadOnlySpan<byte>),
                    typeof(ReadOnlySpan<byte>),
                    typeof(ReadOnlySpan<byte>)
                }),
            (
                "Parse",
                new[] { typeof(ReadOnlySpan<byte>) }));

    private static bool HasExactAssertionAuthenticatorSurface()
    {
        var methods = typeof(BrokerWebAuthnAssertionAuthenticatorDataV1).GetMethods(
                BindingFlags.Static |
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(method => !method.IsPrivate)
            .ToArray();
        return methods.Length == 1 &&
            methods[0].Name == "ValidateFixedRp" &&
            methods[0].ReturnType == typeof(uint) &&
            methods[0].GetParameters()
                .Select(parameter => parameter.ParameterType)
                .SequenceEqual(new[] { typeof(ReadOnlySpan<byte>) });
    }

    private static void ExpectRegistrationRejected(
        byte[] rpIdHash,
        byte[] credentialId,
        byte[] coseKey,
        byte flags) =>
        ExpectArgumentException(
            () => BrokerWebAuthnRegistrationParserV1.Parse(
                CreateRegistrationAuthenticatorData(
                    rpIdHash,
                    flags,
                    credentialId,
                    coseKey),
                rpIdHash,
                credentialId).Dispose());

    private static byte[] CreateRegistrationAuthenticatorData(
        byte[] rpIdHash,
        byte flags,
        byte[] credentialId,
        byte[] coseKey)
    {
        Ensure(rpIdHash.Length == 32, "registration fixture RP hash changed");
        Ensure(credentialId.Length <= ushort.MaxValue, "registration fixture credential is too large");
        var result = new byte[55 + credentialId.Length + coseKey.Length];
        rpIdHash.CopyTo(result, 0);
        result[32] = flags;
        result[36] = 1;
        for (var index = 0; index < 16; index++)
        {
            result[37 + index] = checked((byte)index);
        }

        result[53] = checked((byte)(credentialId.Length >> 8));
        result[54] = checked((byte)(credentialId.Length & byte.MaxValue));
        credentialId.CopyTo(result, 55);
        coseKey.CopyTo(result, 55 + credentialId.Length);
        return result;
    }

    private static byte[] CreateValidCoseP256Key(params long[] labelOrder)
    {
        Ensure(labelOrder.Length == 5, "COSE fixture label count changed");
        return CreateCoseMap(labelOrder.Select(CreateValidCoseEntry).ToArray());
    }

    private static byte[] CreateCoseKeyWithValue(long replacedLabel, byte[] encodedValue)
    {
        var labels = new long[] { 1, 3, -1, -2, -3 };
        return CreateCoseMap(
            labels.Select(label =>
                    label == replacedLabel
                        ? CreateCoseEntry(label, encodedValue)
                        : CreateValidCoseEntry(label))
                .ToArray());
    }

    private static byte[] CreateValidCoseEntry(long label) =>
        label switch
        {
            1 => CreateCoseEntry(1, EncodeCanonicalCborInteger(2)),
            3 => CreateCoseEntry(3, EncodeCanonicalCborInteger(-7)),
            -1 => CreateCoseEntry(-1, EncodeCanonicalCborInteger(1)),
            -2 => CreateCoseEntry(-2, EncodeCanonicalCborByteString(CoseP256X())),
            -3 => CreateCoseEntry(-3, EncodeCanonicalCborByteString(CoseP256Y())),
            _ => throw new InvalidOperationException("Unsupported COSE fixture label.")
        };

    private static byte[] CreateCoseEntry(long label, byte[] encodedValue) =>
        JoinBytes(EncodeCanonicalCborInteger(label), encodedValue);

    private static byte[] CreateCoseMap(params byte[][] entries)
    {
        Ensure(entries.Length <= 23, "COSE fixture map is too large");
        return JoinBytes(new[] { checked((byte)(0xA0 + entries.Length)) }, JoinBytes(entries));
    }

    private static byte[] EncodeCanonicalCborInteger(long value)
    {
        if (value is >= 0 and <= 23)
        {
            return new[] { checked((byte)value) };
        }

        if (value is >= -24 and < 0)
        {
            return new[] { checked((byte)(0x20 + (-1 - value))) };
        }

        throw new InvalidOperationException("The COSE fixture integer is outside its helper bound.");
    }

    private static byte[] EncodeCanonicalCborByteString(byte[] value)
    {
        if (value.Length <= 23)
        {
            return JoinBytes(new[] { checked((byte)(0x40 + value.Length)) }, value);
        }

        Ensure(value.Length <= byte.MaxValue, "COSE fixture byte string is too large");
        return JoinBytes(new byte[] { 0x58, checked((byte)value.Length) }, value);
    }

    private static byte[] CoseP256X() =>
        Convert.FromHexString(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");

    private static byte[] CoseP256Y() =>
        Convert.FromHexString(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

    private static byte[] JoinBytes(params byte[][] values)
    {
        var length = values.Aggregate(0, (current, value) => checked(current + value.Length));
        var result = new byte[length];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result, offset);
            offset += value.Length;
        }

        return result;
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void ExpectArgumentNull(Action action)
    {
        try
        {
            action();
        }
        catch (ArgumentNullException)
        {
            return;
        }

        throw new InvalidOperationException("Expected ArgumentNullException.");
    }

    private static void ExpectArgumentException(Action action)
    {
        try
        {
            action();
        }
        catch (ArgumentException)
        {
            return;
        }

        throw new InvalidOperationException("Expected ArgumentException.");
    }

    private static void ExpectObjectDisposed(Action action)
    {
        try
        {
            action();
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        throw new InvalidOperationException("Expected ObjectDisposedException.");
    }

    private static void ExpectVerificationCode(Action action, string expectedCode)
    {
        try
        {
            action();
        }
        catch (BrokerUserPresenceVerificationException exception) when (
            string.Equals(exception.Code, expectedCode, StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException(
            "Expected user-presence verification code " + expectedCode + ".");
    }

    private static byte[][] GetOwnedByteArrays(object value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.GetType()
            .GetFields(
                BindingFlags.Instance |
                BindingFlags.NonPublic |
                BindingFlags.DeclaredOnly)
            .Where(field => field.FieldType == typeof(byte[]))
            .Select(field => (byte[]?)field.GetValue(value))
            .Where(array => array is not null)
            .Select(array => array!)
            .ToArray();
    }

    private static bool RejectsForgedEvidenceFactory(MethodInfo method)
    {
        var parameters = method.GetParameters();
        if (parameters.Length == 0 ||
            parameters[0].ParameterType != typeof(object) ||
            parameters[0].Name != "factoryToken")
        {
            return false;
        }

        var arguments = parameters
            .Select(parameter => parameter.ParameterType.IsValueType
                ? Activator.CreateInstance(parameter.ParameterType)
                : null)
            .ToArray();
        arguments[0] = new object();
        try
        {
            _ = method.Invoke(null, arguments);
        }
        catch (TargetInvocationException exception) when (
            exception.InnerException is InvalidOperationException inner &&
            inner.Message ==
                "Verified user-presence evidence can only be created by the verifier.")
        {
            return true;
        }

        return false;
    }

    private static void ExpectCode(Action action, string expectedCode)
    {
        try
        {
            action();
        }
        catch (BrokerConsentLedgerFormatException exception) when (
            string.Equals(exception.Code, expectedCode, StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException("Expected consent ledger code " + expectedCode + ".");
    }

    private static void RunCase(
        string name,
        Action test,
        Action<bool, string> assert)
    {
        try
        {
            test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
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

internal static class BrokerWebAuthnTestVectorsV1
{
    internal static SignedConsentVectorV1 CreateSignedConsent(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        Guid receiptId,
        byte[] credentialId,
        byte[] challengeNonce,
        long issuedAtUtcTicks,
        int keyVariant = 1)
    {
        using var key = CreateKey(keyVariant);
        var subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
        var draft = BrokerConsentGrantDraftV1.Create(
            current,
            expectedRevision,
            generation,
            receiptId,
            credentialId,
            Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)),
            challengeNonce,
            issuedAtUtcTicks);
        var clientData = BrokerWebAuthnClientDataV1.CreateConsent(draft);
        var authenticatorData = CreateAuthenticatorData();
        var clientDataHash = clientData.ClientDataHash;
        var signedData = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(signedData, 0);
        clientDataHash.CopyTo(signedData, authenticatorData.Length);
        var nativeDerSignature = key.SignData(
            signedData,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        var registeredCredential = new BrokerWebAuthnRegisteredCredentialV1(
            credentialId,
            subjectPublicKeyInfo,
            Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)));
        var assertion = WebAuthnAssertionEvidenceV1.Create(
            clientData.ClientDataJson,
            credentialId,
            authenticatorData,
            nativeDerSignature,
            userHandle: null);
        CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        CryptographicOperations.ZeroMemory(authenticatorData);
        CryptographicOperations.ZeroMemory(clientDataHash);
        CryptographicOperations.ZeroMemory(signedData);
        CryptographicOperations.ZeroMemory(nativeDerSignature);
        return new SignedConsentVectorV1(draft, registeredCredential, assertion);
    }

    internal static SignedAssertionVectorV1 CreateSignedAssertionForDraft(
        BrokerConsentGrantDraftV1 draft,
        byte[] credentialId,
        int keyVariant,
        string declaredSubjectPublicKeyInfoSha256)
    {
        ArgumentNullException.ThrowIfNull(draft);
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(declaredSubjectPublicKeyInfoSha256);
        using var key = CreateKey(keyVariant);
        var subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
        var clientData = BrokerWebAuthnClientDataV1.CreateConsent(draft);
        var authenticatorData = CreateAuthenticatorData();
        var clientDataHash = clientData.ClientDataHash;
        var signedData = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(signedData, 0);
        clientDataHash.CopyTo(signedData, authenticatorData.Length);
        var nativeDerSignature = key.SignData(
            signedData,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        BrokerWebAuthnRegisteredCredentialV1? registeredCredential = null;
        WebAuthnAssertionEvidenceV1? assertion = null;
        try
        {
            registeredCredential = new BrokerWebAuthnRegisteredCredentialV1(
                credentialId,
                subjectPublicKeyInfo,
                declaredSubjectPublicKeyInfoSha256);
            assertion = WebAuthnAssertionEvidenceV1.Create(
                clientData.ClientDataJson,
                credentialId,
                authenticatorData,
                nativeDerSignature,
                userHandle: null);
            var result = new SignedAssertionVectorV1(registeredCredential, assertion);
            registeredCredential = null;
            assertion = null;
            return result;
        }
        finally
        {
            registeredCredential?.Dispose();
            assertion?.Dispose();
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            CryptographicOperations.ZeroMemory(authenticatorData);
            CryptographicOperations.ZeroMemory(clientDataHash);
            CryptographicOperations.ZeroMemory(signedData);
            CryptographicOperations.ZeroMemory(nativeDerSignature);
        }
    }

    internal static SignedAssertionVectorV1 CreateSignedAssertionForFresh(
        BrokerFreshPresenceStatementV1 statement,
        byte[] credentialId,
        int keyVariant,
        string declaredSubjectPublicKeyInfoSha256)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(declaredSubjectPublicKeyInfoSha256);
        using var key = CreateKey(keyVariant);
        var subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
        var clientData = BrokerWebAuthnClientDataV1.CreateFresh(statement);
        var authenticatorData = CreateAuthenticatorData();
        var clientDataHash = clientData.ClientDataHash;
        var signedData = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(signedData, 0);
        clientDataHash.CopyTo(signedData, authenticatorData.Length);
        var nativeDerSignature = key.SignData(
            signedData,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        BrokerWebAuthnRegisteredCredentialV1? registeredCredential = null;
        WebAuthnAssertionEvidenceV1? assertion = null;
        try
        {
            registeredCredential = new BrokerWebAuthnRegisteredCredentialV1(
                credentialId,
                subjectPublicKeyInfo,
                declaredSubjectPublicKeyInfoSha256);
            assertion = WebAuthnAssertionEvidenceV1.Create(
                clientData.ClientDataJson,
                credentialId,
                authenticatorData,
                nativeDerSignature,
                userHandle: null);
            var result = new SignedAssertionVectorV1(registeredCredential, assertion);
            registeredCredential = null;
            assertion = null;
            return result;
        }
        finally
        {
            registeredCredential?.Dispose();
            assertion?.Dispose();
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            CryptographicOperations.ZeroMemory(authenticatorData);
            CryptographicOperations.ZeroMemory(clientDataHash);
            CryptographicOperations.ZeroMemory(signedData);
            CryptographicOperations.ZeroMemory(nativeDerSignature);
        }
    }

    internal static BrokerConsentLedgerDocumentV1 CreateVerifiedGrant(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        Guid receiptId,
        byte[] credentialId,
        byte[] challengeNonce,
        long issuedAtUtcTicks,
        int keyVariant = 1)
    {
        using var vector = CreateSignedConsent(
            current,
            expectedRevision,
            generation,
            receiptId,
            credentialId,
            challengeNonce,
            issuedAtUtcTicks,
            keyVariant);
        using var verified = BrokerWebAuthnReceiptVerifierV1.VerifyConsentAssertion(
            vector.Draft,
            vector.Credential,
            vector.Assertion);
        return vector.Draft.FinalizeGrant(verified);
    }

    internal static BrokerConsentLedgerDocumentV1 CreateParsedGrant(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        Guid receiptId,
        byte[] credentialId,
        byte[] challengeNonce,
        long issuedAtUtcTicks,
        int keyVariant = 1)
    {
        using var key = CreateKey(keyVariant);
        var subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
        var draft = BrokerConsentGrantDraftV1.Create(
            current,
            expectedRevision,
            generation,
            receiptId,
            credentialId,
            Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)),
            challengeNonce,
            issuedAtUtcTicks);
        using var proof = BrokerWebAuthnAssertionProofV1.Create(
            subjectPublicKeyInfo,
            CreateAuthenticatorData(),
            new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 });
        var proofBytes = proof.Serialize();
        var fields = draft.StatementFields;
        var entryJson =
            $"{{\"kind\":\"grant\",\"sequence\":{fields.Sequence}," +
            $"\"previousEntrySha256\":\"{fields.PreviousEntrySha256}\"," +
            $"\"revocationGeneration\":{fields.RevocationGeneration}," +
            $"\"receiptId\":\"{fields.ReceiptId:D}\"," +
            $"\"generationSha256\":\"{fields.GenerationSha256}\"," +
            $"\"capability\":\"{fields.Capability}\"," +
            $"\"issuedAtUtcTicks\":{fields.IssuedAtUtcTicks}," +
            $"\"receiptFormat\":\"{fields.ReceiptFormat}\"," +
            $"\"credentialIdBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(fields.CredentialIdBase64) + "," +
            $"\"credentialPublicKeySha256\":\"{fields.CredentialPublicKeySha256}\"," +
            $"\"challengeNonceBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(fields.ChallengeNonceBase64) + "," +
            $"\"signatureBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(Convert.ToBase64String(proofBytes)) + "}";
        var entrySha256 = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(entryJson)));
        var documentJson =
            $"{{\"schema\":\"{BrokerConsentLedgerV1.SchemaName}\"," +
            $"\"ledgerId\":\"{fields.LedgerId:D}\",\"revision\":{fields.Revision}," +
            $"\"entry\":{entryJson},\"entrySha256\":\"{entrySha256}\"}}";
        CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        CryptographicOperations.ZeroMemory(proofBytes);
        return BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(documentJson));
    }

    internal static BrokerConsentLedgerDocumentV1 RebindParsedGrant(
        BrokerConsentLedgerDocumentV1 grant,
        byte[] proofEnvelope,
        byte[]? credentialId = null,
        byte[]? challengeNonce = null,
        string? credentialPublicKeySha256 = null,
        Guid? receiptId = null)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(proofEnvelope);
        if (grant.Entry is not BrokerConsentGrantEntryV1 entry)
        {
            throw new ArgumentException("A grant is required.", nameof(grant));
        }

        var receipt = entry.Receipt;
        var credentialIdBase64 = credentialId is null
            ? receipt.CredentialIdBase64
            : Convert.ToBase64String(credentialId);
        var challengeNonceBase64 = challengeNonce is null
            ? receipt.ChallengeNonceBase64
            : Convert.ToBase64String(challengeNonce);
        var entryJson =
            $"{{\"kind\":\"grant\",\"sequence\":{entry.Sequence}," +
            $"\"previousEntrySha256\":\"{entry.PreviousEntrySha256}\"," +
            $"\"revocationGeneration\":{entry.RevocationGeneration}," +
            $"\"receiptId\":\"{receiptId ?? entry.ReceiptId:D}\"," +
            $"\"generationSha256\":\"{entry.GenerationSha256}\"," +
            $"\"capability\":\"{BrokerConsentLedgerV1.CapabilityName}\"," +
            $"\"issuedAtUtcTicks\":{entry.IssuedAtUtcTicks}," +
            $"\"receiptFormat\":\"{BrokerConsentLedgerV1.ReceiptFormatName}\"," +
            $"\"credentialIdBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(credentialIdBase64) + "," +
            $"\"credentialPublicKeySha256\":\"{credentialPublicKeySha256 ?? receipt.CredentialPublicKeySha256}\"," +
            $"\"challengeNonceBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(challengeNonceBase64) + "," +
            $"\"signatureBase64\":" +
            System.Text.Json.JsonSerializer.Serialize(Convert.ToBase64String(proofEnvelope)) + "}";
        var entrySha256 = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(entryJson)));
        var documentJson =
            $"{{\"schema\":\"{BrokerConsentLedgerV1.SchemaName}\"," +
            $"\"ledgerId\":\"{grant.LedgerId:D}\",\"revision\":{grant.Revision}," +
            $"\"entry\":{entryJson},\"entrySha256\":\"{entrySha256}\"}}";
        return BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(documentJson));
    }

    internal static byte[] SubjectPublicKeyInfo(int keyVariant)
    {
        using var key = CreateKey(keyVariant);
        return key.ExportSubjectPublicKeyInfo();
    }

    internal static byte[] CredentialId(byte seed = 0x01) =>
    [
        seed,
        checked((byte)(seed + 1)),
        checked((byte)(seed + 2)),
        checked((byte)(seed + 3))
    ];

    internal static byte[] Nonce(byte seed = 0x30) =>
        Enumerable.Range(0, 32)
            .Select(index => checked((byte)(seed + index)))
            .ToArray();

    internal static ECDsa CreateKey(int variant)
    {
        var (x, y, d) = variant switch
        {
            1 => (
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                "0000000000000000000000000000000000000000000000000000000000000001"),
            2 => (
                "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
                "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
                "0000000000000000000000000000000000000000000000000000000000000002"),
            _ => throw new ArgumentOutOfRangeException(nameof(variant))
        };
        var key = ECDsa.Create();
        key.ImportParameters(
            new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = Convert.FromHexString(x),
                    Y = Convert.FromHexString(y)
                },
                D = Convert.FromHexString(d)
            });
        return key;
    }

    private static byte[] CreateAuthenticatorData() =>
        Convert.FromHexString(
            "98CC7D7B6EB44AE201CA8895A58B4F0715B255C3AF043162E8A71C45FBEB3478" +
            "05" +
            "00000000");

    internal sealed class SignedConsentVectorV1 : IDisposable
    {
        internal SignedConsentVectorV1(
            BrokerConsentGrantDraftV1 draft,
            BrokerWebAuthnRegisteredCredentialV1 credential,
            WebAuthnAssertionEvidenceV1 assertion)
        {
            Draft = draft;
            Credential = credential;
            Assertion = assertion;
        }

        internal BrokerConsentGrantDraftV1 Draft { get; }

        internal BrokerWebAuthnRegisteredCredentialV1 Credential { get; }

        internal WebAuthnAssertionEvidenceV1 Assertion { get; }

        public void Dispose()
        {
            Assertion.Dispose();
            Credential.Dispose();
        }
    }

    internal sealed class SignedAssertionVectorV1 : IDisposable
    {
        internal SignedAssertionVectorV1(
            BrokerWebAuthnRegisteredCredentialV1 credential,
            WebAuthnAssertionEvidenceV1 assertion)
        {
            Credential = credential;
            Assertion = assertion;
        }

        internal BrokerWebAuthnRegisteredCredentialV1 Credential { get; }

        internal WebAuthnAssertionEvidenceV1 Assertion { get; }

        public void Dispose()
        {
            Assertion.Dispose();
            Credential.Dispose();
        }
    }
}
