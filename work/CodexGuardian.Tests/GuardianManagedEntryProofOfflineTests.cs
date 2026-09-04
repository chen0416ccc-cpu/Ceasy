using CodexGuardian;
using CodexGuardian.Broker;
using CodexGuardian.Control;
using CodexGuardian.Trust;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using GuardianProgram = CodexGuardian.Program;

internal static class GuardianManagedEntryProofOfflineTests
{
    internal const string PublishedAppHostProbeArgument =
        "--guardian-managed-entry-apphost-probe";
    internal const string PublishedRuntimeRootArgument =
        "--guardian-managed-entry-runtime-root";
    internal const string PublishedAppHostSuccessMarker =
        "GUARDIAN_MANAGED_ENTRY_APPHOST_PROOF_VERIFIED";

    private const string FixtureUserSid = "S-1-5-21-1100-2200-3300-4400";
    private const string FixtureLogonSid = "S-1-5-5-110-220";
    private const string FixtureReleaseId = "managed-entry-verification-offline-v1";
    private const string FixtureManifestSha256 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string FixtureConnectionNonce =
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string FixtureReleaseRoot =
        @"D:\CodexData\CodexGuardian\managed-entry-verification-offline";
    private const uint FixtureProcessId = 43101;
    private const uint FixtureSessionId = 11;
    private const ulong FixtureVolumeSerial = 0x00000000B1C2D3E4;
    private static readonly Guid ModuleVersionId =
        Guid.ParseExact("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "D");
    private static readonly DateTimeOffset FixtureCreationTime =
        new(2026, 8, 7, 8, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan CaseTimeout = TimeSpan.FromSeconds(10);
    private static readonly ConstructorInfo VerifiedConnectionFixtureConstructor =
        typeof(VerifiedGuardianManagedEntryConnectionV1).GetConstructors(
                BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(constructor =>
            {
                var parameters = constructor.GetParameters();
                return parameters.Length == 3 &&
                    parameters[0].ParameterType == typeof(AuthenticatedPipePeerConnection) &&
                    parameters[1].ParameterType == typeof(GuardianManagedEntryReceiptV1) &&
                    parameters[2].ParameterType == typeof(BrokerGuardianCleanLaunchClaimV1);
            });

    internal static VerifiedGuardianManagedEntryConnectionV1 CreateVerifiedConnectionFixture(
        AuthenticatedPipePeerConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (connection.PeerRole != BrokerPeerRole.Guardian || connection.Completion.IsCompleted)
        {
            throw new InvalidOperationException(
                "The managed-entry fixture requires one live authenticated Guardian connection.");
        }

        var challenge = Enumerable.Range(0, GuardianManagedEntryProofProtocolV1.ChallengeBytes)
            .Select(index => checked((byte)index))
            .ToArray();
        BrokerGuardianCleanLaunchAuthorityV1? authority = null;
        BrokerGuardianCleanLaunchClaimV1? claim = null;
        try
        {
            var metadata = CreateMetadata();
            authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
                new TestBrokerOwnedGuardianProcessLease(connection.InitialIdentity),
                metadata,
                challenge);
            claim = authority.ClaimForManagedEntryVerification();
            var receipt = new GuardianManagedEntryReceiptV1(
                GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(challenge),
                connection.InitialIdentity.ProcessId,
                connection.InitialIdentity.KernelSessionId,
                connection.InitialIdentity.CreationTimeUtc,
                metadata);
            var result = (VerifiedGuardianManagedEntryConnectionV1)(
                VerifiedConnectionFixtureConstructor.Invoke(
                    new object?[] { connection, receipt, claim }) ??
                throw new InvalidOperationException(
                    "The managed-entry fixture constructor returned null."));
            claim = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            claim?.Dispose();
            authority?.Dispose();
        }
    }

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "Guardian managed-entry receipt is canonical bounded and strict",
            TestReceiptProtocol,
            assert);
        RunCase(
            "Guardian production managed-entry metadata is read from the exact PE entry point",
            TestPublishedGuardianMetadata,
            assert);
        RunCase(
            "Guardian proof factory rejects a Tests managed entry",
            TestCurrentEntryRejection,
            assert);
        RunCase(
            "Broker runtime authority accepts only a verified managed-entry wrapper",
            TestBrokerAuthoritySurface,
            assert);
        RunCase(
            "Guardian proof-only dispatch precedes every WPF and environment side effect",
            TestProgramSourceBoundary,
            assert);
        RunCase(
            "Broker clean-launch authority requires both flags and is consumed once",
            TestCleanLaunchAuthorityContract,
            assert);
        await RunCaseAsync(
            "Broker managed-entry verification retains authority through exact cleanup",
            TestVerificationSuccessRetentionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker managed-entry verification rejects launch and peer identity drift",
            TestVerificationIdentityDriftAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker managed-entry verification rejects peer closure during proof admission",
            TestVerificationPeerClosureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker managed-entry verification rejects exact process exit before and during receipt",
            TestVerificationProcessExitAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker managed-entry verification rejects process observation fault and cancellation",
            TestVerificationProcessObservationFailureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker managed-entry verification cancels and drains a blocked receipt read",
            TestVerificationBlockedReceiptReadAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Managed-entry cancellation latches exact Stop before a cancellation-compliant read closes",
            TestVerificationCancellationStartsAbortAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Managed-entry cancellation starts Stop and close before an uncooperative read drains",
            TestVerificationCancellationDoesNotDependOnReadAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Managed-entry cancellation preserves exact Stop and pipe cleanup failures",
            TestVerificationCancellationCleanupArbitrationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Managed-entry cancellation retains a pre-abort process failure as primary",
            TestVerificationCancellationProcessSnapshotAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Managed-entry success commit remains the sole owner after late cancellation",
            TestVerificationSuccessCommitBoundaryAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker managed-entry verification prioritizes exact process failure over receipt failure",
            TestVerificationSimultaneousFailureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Verified managed-entry lifetime observes process completion after admission",
            TestVerifiedCompletionProcessMonitorAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Verified managed-entry disposal latches launch intent before pipe cleanup",
            TestVerificationDisposalOrderingAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Verified managed-entry disposal preserves exact Stop and pipe cleanup failures",
            TestVerificationDisposalCleanupArbitrationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Verified managed-entry claim and disposal boundaries are serialized",
            TestClaimDisposalRaceAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker managed-entry verification preserves raw and launch cleanup failures",
            TestVerificationCleanupArbitrationAsync,
            assert).ConfigureAwait(false);
    }

    internal static bool IsPublishedAppHostProbeInvocation(IReadOnlyList<string> arguments) =>
        arguments.Contains(PublishedAppHostProbeArgument, StringComparer.OrdinalIgnoreCase);

    internal static async Task RunPublishedAppHostProbeAsync(
        string[] arguments,
        Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(assert);
        const string name =
            "published Guardian apphost emits one exact managed-entry proof without entering WPF";
        try
        {
            var runtimeRoot = ReadPublishedRuntimeRoot(arguments);
            await VerifyPublishedAppHostAsync(runtimeRoot).ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static void TestReceiptProtocol()
    {
        var challenge = Enumerable.Range(0, GuardianManagedEntryProofProtocolV1.ChallengeBytes)
            .Select(index => checked((byte)index))
            .ToArray();
        var metadata = CreateMetadata();
        var receipt = new GuardianManagedEntryReceiptV1(
            GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(challenge),
            processId: 1234,
            sessionId: 42,
            new DateTimeOffset(2026, 8, 7, 1, 2, 3, TimeSpan.Zero),
            metadata);
        var payload = GuardianManagedEntryProofProtocolV1.Serialize(receipt);
        Ensure(
            payload.Length is > 0 and <= GuardianManagedEntryProofProtocolV1.MaximumReceiptBytes &&
            payload[0] == (byte)'{' && payload[^1] == (byte)'}' &&
            GuardianManagedEntryProofProtocolV1.TryParse(
                payload,
                out var parsed,
                out var reason) &&
            reason == "accepted" &&
            parsed == receipt,
            "canonical managed-entry receipt did not round-trip exactly");

        var text = Encoding.UTF8.GetString(payload);
        Reject(Encoding.UTF8.GetBytes(" " + text), "leading whitespace was accepted");
        Reject(Encoding.UTF8.GetBytes(text + "\n"), "trailing whitespace was accepted");
        Reject(
            [0xEF, 0xBB, 0xBF, .. payload],
            "UTF-8 BOM was accepted");
        Reject(
            Encoding.UTF8.GetBytes(text.Replace(
                "\"protocol\":1",
                "\"protocol\":1,\"protocol\":1",
                StringComparison.Ordinal)),
            "duplicate property was accepted");
        Reject(
            Encoding.UTF8.GetBytes(text.Replace(
                "\"protocol\":1",
                "\"protocol\":1,\"extra\":true",
                StringComparison.Ordinal)),
            "unknown property was accepted");
        Reject(
            Encoding.UTF8.GetBytes(text.Replace(
                receipt.ChallengeSha256,
                receipt.ChallengeSha256.ToLowerInvariant(),
                StringComparison.Ordinal)),
            "non-canonical challenge hash was accepted");
        Reject(
            Enumerable.Repeat((byte)'x', GuardianManagedEntryProofProtocolV1.MaximumReceiptBytes + 1)
                .ToArray(),
            "oversized receipt was accepted");

        Expect<ArgumentException>(() => new GuardianManagedEntryMetadataIdentityV1(
            "CodexGuardian.Tests.exe",
            GuardianManagedEntryMetadataIdentityV1.ExpectedManagedEntryRelativePath,
            GuardianManagedEntryMetadataIdentityV1.ExpectedAssemblyName,
            ModuleVersionId,
            0x06000001,
            GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointDeclaringType,
            GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointMethod));
        Expect<ArgumentOutOfRangeException>(() => new GuardianManagedEntryMetadataIdentityV1(
            GuardianManagedEntryMetadataIdentityV1.ExpectedAppHostFileName,
            GuardianManagedEntryMetadataIdentityV1.ExpectedManagedEntryRelativePath,
            GuardianManagedEntryMetadataIdentityV1.ExpectedAssemblyName,
            ModuleVersionId,
            0x02000001,
            GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointDeclaringType,
            GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointMethod));
    }

    private static void TestPublishedGuardianMetadata()
    {
        var guardianPath = Path.Combine(AppContext.BaseDirectory, "CodexGuardian.dll");
        Ensure(File.Exists(guardianPath), "fresh Tests output lacks CodexGuardian.dll");
        var metadata = GuardianManagedEntryMetadataIdentityV1.ReadFromAssemblyFile(guardianPath);
        var guardianAssembly = typeof(GuardianProgram).Assembly;
        var entryPoint = guardianAssembly.EntryPoint ?? throw new InvalidOperationException(
            "CodexGuardian.dll has no managed entry point");
        Ensure(
            metadata.AppHostFileName == "CodexGuardian.exe" &&
            metadata.ManagedEntryRelativePath == "CodexGuardian.dll" &&
            metadata.AssemblyName == guardianAssembly.GetName().Name &&
            metadata.ModuleVersionId == guardianAssembly.ManifestModule.ModuleVersionId &&
            metadata.EntryPointMetadataToken == entryPoint.MetadataToken &&
            metadata.EntryPointDeclaringType == typeof(GuardianProgram).FullName &&
            metadata.EntryPointMethod == "Main",
            "PE metadata identity differs from the referenced production Guardian assembly");
    }

    private static void TestCurrentEntryRejection()
    {
        Ensure(
            !ReferenceEquals(Assembly.GetEntryAssembly(), typeof(GuardianProgram).Assembly),
            "offline test unexpectedly runs under the Guardian production managed entry");
        var challenge = new byte[GuardianManagedEntryProofProtocolV1.ChallengeBytes];
        Expect<InvalidOperationException>(() =>
            GuardianManagedEntryProofV1.CreateCurrent(
                challenge,
                typeof(GuardianProgram).Assembly));
    }

    private static void TestBrokerAuthoritySurface()
    {
        var wrapperType = typeof(VerifiedGuardianManagedEntryConnectionV1);
        Ensure(
            wrapperType.IsSealed && wrapperType.IsNotPublic &&
            typeof(IAsyncDisposable).IsAssignableFrom(wrapperType) &&
            wrapperType.GetConstructors(BindingFlags.Instance | BindingFlags.Public).Length == 0 &&
            wrapperType.GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
                .All(method => !method.Name.EndsWith("ForTesting", StringComparison.Ordinal)) &&
            !wrapperType.IsDefined(typeof(SerializableAttribute), inherit: false),
            "verified managed-entry connection escaped its internal volatile boundary");

        var launchAuthorityType = typeof(BrokerGuardianCleanLaunchAuthorityV1);
        var ownedProcessLeaseType = typeof(IBrokerOwnedGuardianProcessLeaseV1);
        var productionVerify = wrapperType.GetMethods(
                BindingFlags.Static | BindingFlags.NonPublic)
            .Single(method => method.Name == "VerifyAsync");
        var verifyParameters = productionVerify.GetParameters();
        var productionLeaseImplementations = ownedProcessLeaseType.Assembly.GetTypes()
            .Where(type =>
                type != ownedProcessLeaseType &&
                !type.IsAbstract &&
                ownedProcessLeaseType.IsAssignableFrom(type))
            .ToArray();
        var productionLeaseImplementation = productionLeaseImplementations.SingleOrDefault();
        var productionLeaseConstructors = productionLeaseImplementation?.GetConstructors(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic) ??
            Array.Empty<ConstructorInfo>();
        Ensure(
            verifyParameters.Length == 3 &&
            verifyParameters[0].ParameterType == typeof(AuthenticatedPipePeerConnection) &&
            verifyParameters[1].ParameterType == launchAuthorityType &&
            verifyParameters[2].ParameterType == typeof(CancellationToken) &&
            !verifyParameters.Any(parameter =>
                parameter.ParameterType == typeof(GuardianManagedEntryMetadataIdentityV1) ||
                parameter.ParameterType == typeof(ReadOnlyMemory<byte>)) &&
            launchAuthorityType.IsSealed && launchAuthorityType.IsNotPublic &&
            launchAuthorityType.GetConstructors(
                BindingFlags.Instance | BindingFlags.Public).Length == 0 &&
            !launchAuthorityType.IsDefined(typeof(SerializableAttribute), inherit: false) &&
            ownedProcessLeaseType.GetProperty("CleanEnvironmentVerified") is not null &&
            ownedProcessLeaseType.GetProperty("RuntimeNamespaceClosed") is not null &&
            ownedProcessLeaseType.GetProperty("Completion")?.PropertyType ==
                typeof(Task<BrokerGuardianProcessExitV1>) &&
            wrapperType.GetProperty(
                "Completion",
                BindingFlags.Instance | BindingFlags.NonPublic)?.PropertyType == typeof(Task) &&
            wrapperType.GetProperty(
                "ProcessCompletion",
                BindingFlags.Instance | BindingFlags.NonPublic)?.PropertyType ==
                typeof(Task<BrokerGuardianProcessExitV1>) &&
            ownedProcessLeaseType.GetMethod("Revalidate") is not null &&
            ownedProcessLeaseType.GetMethod("TakeOwnership") is not null &&
            ownedProcessLeaseType.GetMethod("StopAsync")?.ReturnType == typeof(Task) &&
            typeof(IDisposable).IsAssignableFrom(typeof(BrokerGuardianCleanLaunchClaimV1)) &&
            typeof(IAsyncDisposable).IsAssignableFrom(typeof(BrokerGuardianCleanLaunchClaimV1)) &&
            typeof(IAsyncDisposable).IsAssignableFrom(launchAuthorityType) &&
            typeof(IAsyncDisposable).IsAssignableFrom(ownedProcessLeaseType) &&
            productionLeaseImplementations.Length == 1 &&
            productionLeaseImplementation is not null &&
            productionLeaseImplementation.IsSealed &&
            !productionLeaseImplementation.IsVisible &&
            productionLeaseImplementation.DeclaringType ==
                typeof(WindowsGuardianCleanLauncherV1) &&
            productionLeaseImplementation.GetConstructors(
                BindingFlags.Instance | BindingFlags.Public).Length == 0 &&
            productionLeaseConstructors.Length == 1 &&
            productionLeaseConstructors[0].GetParameters().Length == 1 &&
            productionLeaseConstructors[0].GetParameters()[0].ParameterType ==
                typeof(WindowsGuardianProcessRootV1),
            "managed-entry verification can bypass Broker-owned clean launch authority");

        var attach = typeof(BrokerRuntimeOwnerV1).GetMethods(
                BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(method => method.Name == "AttachGuardianAsync");
        Ensure(
            attach.GetParameters()[0].ParameterType == wrapperType &&
            typeof(BrokerControlSessionV1).GetFields(
                    BindingFlags.Instance | BindingFlags.NonPublic)
                .Any(field => field.FieldType == wrapperType) &&
            typeof(BrokerControlSessionV1).GetConstructors(
                    BindingFlags.Instance | BindingFlags.NonPublic)
                .SelectMany(constructor => constructor.GetParameters())
                .Any(parameter => parameter.ParameterType == wrapperType),
            "Broker owner or session does not require the verified managed-entry wrapper");

        var capabilityMethods = typeof(BrokerCapabilityLeaseV1).GetMethods(
            BindingFlags.Instance | BindingFlags.Static |
            BindingFlags.Public | BindingFlags.NonPublic);
        Ensure(
            capabilityMethods
                .Where(method => method.Name is "Create" or "Consume")
                .SelectMany(method => method.GetParameters())
                .Any(parameter => parameter.ParameterType == wrapperType) &&
            capabilityMethods
                .Where(method => method.Name is "Create" or "Consume")
                .SelectMany(method => method.GetParameters())
                .All(parameter => parameter.ParameterType != typeof(AuthenticatedPipePeerConnection)),
            "Broker capability lease still accepts a raw authenticated Guardian connection");
    }

    private static void TestCleanLaunchAuthorityContract()
    {
        var identity = CreateFixtureIdentity(
            CreateFixtureManifest().GetArtifactSet(BrokerPeerRole.Guardian));
        var metadata = CreateMetadata();
        var challenge = CreateChallenge();
        try
        {
            foreach (var invalid in new[]
                     {
                         new TestBrokerOwnedGuardianProcessLease(
                             identity,
                             cleanEnvironmentVerified: false),
                         new TestBrokerOwnedGuardianProcessLease(
                             identity,
                             runtimeNamespaceClosed: false)
                     })
            {
                ExpectBrokerCode(
                    "managed-entry-launch-authority-invalid",
                    () => BrokerGuardianCleanLaunchAuthorityV1.Create(
                        invalid,
                        metadata,
                        challenge));
                Ensure(
                    invalid.DisposeCount == 1,
                    "an invalid clean-launch process lease was not released exactly once");
            }

            var missingMetadataLease = new TestBrokerOwnedGuardianProcessLease(identity);
            Expect<ArgumentNullException>(() =>
                BrokerGuardianCleanLaunchAuthorityV1.Create(
                    missingMetadataLease,
                    expectedMetadata: null!,
                    challenge: challenge));
            Ensure(
                missingMetadataLease.DisposeCount == 1,
                "null managed-entry metadata leaked the Broker-owned process lease");

            var processLease = new TestBrokerOwnedGuardianProcessLease(identity);
            using var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
                processLease,
                metadata,
                challenge);
            processLease.Dispose();
            using var claim = authority.ClaimForManagedEntryVerification();
            Ensure(
                ReferenceEquals(claim.InitialIdentity, identity) &&
                claim.ExpectedMetadata == metadata &&
                claim.Challenge.Span.SequenceEqual(challenge),
                "the clean-launch claim did not retain its exact immutable authority");
            ExpectBrokerCode(
                "managed-entry-launch-authority-claimed",
                () => authority.ClaimForManagedEntryVerification());
            Ensure(
                processLease.DisposeCount == 0,
                "moving clean-launch authority released the owned process too early");
            authority.Dispose();
            Ensure(
                processLease.DisposeCount == 0 &&
                ExactIdentityEquals(identity, claim.Revalidate()),
                "disposing a moved authority alias released the claim-owned process");
            claim.Dispose();
            Ensure(
                processLease.DisposeCount == 1,
                "clean-launch claim did not release its process lease exactly once");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static async Task TestVerificationSuccessRetentionAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var receipt = CreateReceipt(fixture.Identity, metadata, challenge);
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        BrokerGuardianCleanLaunchAuthorityV1? authority = null;
        VerifiedGuardianManagedEntryConnectionV1? verified = null;
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(receipt));
            authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
                launchLease,
                metadata,
                challenge);
            launchLease.Dispose();
            verified = await VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority)
                .ConfigureAwait(false);
            authority.Dispose();
            authority = null;
            Ensure(
                verified.Receipt == receipt &&
                ReferenceEquals(verified.InitialIdentity, fixture.Identity) &&
                ReferenceEquals(verified.ProcessCompletion, launchLease.Completion) &&
                !ReferenceEquals(verified.Completion, fixture.Connection.Completion) &&
                ExactIdentityEquals(fixture.Identity, verified.Revalidate()),
                "successful managed-entry verification changed its receipt or process identity");
            Ensure(
                launchLease.DisposeCount == 0 &&
                fixture.PeerLease.DisposeCount == 0 &&
                fixture.Platform.DisposeCount == 0,
                "successful verification released retained authority before wrapper cleanup");

            await verified.DisposeAsync().ConfigureAwait(false);
            await verified.Completion.ConfigureAwait(false);
            var processExit = await launchLease.Completion.ConfigureAwait(false);
            Ensure(
                launchLease.DisposeCount == 1 &&
                launchLease.LastStopRequest == BrokerGuardianProcessStopRequestV1.Disposal &&
                processExit.ProcessId == FixtureProcessId &&
                fixture.PeerLease.DisposeCount == 1 &&
                fixture.Platform.DisposeCount == 1,
                "verified wrapper cleanup did not release raw and launch authority exactly once");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            if (verified is not null)
            {
                await verified.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                try
                {
                    await fixture.Connection.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }

                authority?.Dispose();
            }
        }
    }

    private static async Task TestVerificationIdentityDriftAsync()
    {
        await AssertLaunchIdentityDriftRejectedAsync(afterReceipt: false).ConfigureAwait(false);
        await AssertLaunchIdentityDriftRejectedAsync(afterReceipt: true).ConfigureAwait(false);
        await AssertPeerIdentityDriftRejectedAsync(afterReceipt: false).ConfigureAwait(false);
        await AssertPeerIdentityDriftRejectedAsync(afterReceipt: true).ConfigureAwait(false);
    }

    private static async Task AssertLaunchIdentityDriftRejectedAsync(bool afterReceipt)
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        try
        {
            var drifted = CreateDriftedIdentity(fixture.Identity);
            launchLease.SetRevalidationSequence(
                afterReceipt
                    ? new[] { fixture.Identity, drifted }
                    : new[] { drifted });
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            await ExpectBrokerCodeAsync(
                    "managed-entry-peer-invalid",
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority)
                        .AsTask())
                .ConfigureAwait(false);
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static async Task AssertPeerIdentityDriftRejectedAsync(bool afterReceipt)
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        try
        {
            var drifted = CreateDriftedIdentity(fixture.Identity);
            fixture.PeerLease.SetCaptureSequence(
                afterReceipt
                    ? new[] { fixture.Identity, fixture.Identity, drifted, drifted }
                    : new[] { drifted, drifted });
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            var failure = await ExpectFailureAsync(
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority)
                        .AsTask())
                .ConfigureAwait(false);
            Ensure(
                failure is BrokerPeerTrustException,
                "raw peer identity drift did not fail in the retained peer authority");
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static async Task TestVerificationPeerClosureAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            fixture.Platform.CompleteOnRead = true;
            _ = await ExpectFailureAsync(
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority)
                        .AsTask())
                .ConfigureAwait(false);
            Ensure(
                fixture.Connection.Completion.IsCompleted,
                "peer transport closure did not settle authenticated connection completion");
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static async Task TestVerificationProcessExitAsync()
    {
        await AssertProcessExitRejectedAsync(completeDuringRead: false).ConfigureAwait(false);
        await AssertProcessExitRejectedAsync(completeDuringRead: true).ConfigureAwait(false);
    }

    private static async Task AssertProcessExitRejectedAsync(bool completeDuringRead)
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            if (completeDuringRead)
            {
                fixture.Platform.BeforeReadReturn = () => launchLease.CompleteProcessExit(23);
            }
            else
            {
                launchLease.CompleteProcessExit(17);
            }

            await ExpectBrokerCodeAsync(
                    "managed-entry-process-exited",
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority)
                        .AsTask())
                .ConfigureAwait(false);
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            await authority.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task TestVerificationProcessObservationFailureAsync()
    {
        await AssertProcessObservationRejectedAsync(cancelObservation: false)
            .ConfigureAwait(false);
        await AssertProcessObservationRejectedAsync(cancelObservation: true)
            .ConfigureAwait(false);
    }

    private static async Task AssertProcessObservationRejectedAsync(bool cancelObservation)
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        var observationFailure = new IOException(
            "managed-entry process observation failure");
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            fixture.Platform.BeforeReadStart = cancelObservation
                ? launchLease.CancelProcessObservation
                : () => launchLease.FaultProcessObservation(observationFailure);
            var failure = await ExpectBrokerCodeAsync(
                    "managed-entry-process-observation-failed",
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority)
                        .AsTask())
                .ConfigureAwait(false);
            Ensure(
                cancelObservation || ReferenceEquals(failure.InnerException, observationFailure),
                "process observation failure did not retain its exact inner exception");
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            await authority.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task TestVerificationBlockedReceiptReadAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        try
        {
            fixture.Platform.BlockNextRead = true;
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            var verification = VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority)
                .AsTask();
            await fixture.Platform.ReadStarted.WaitAsync(CaseTimeout).ConfigureAwait(false);
            launchLease.CompleteProcessExit(29);
            await ExpectBrokerCodeAsync(
                    "managed-entry-process-exited",
                    () => verification)
                .ConfigureAwait(false);
            await fixture.Platform.ReadCompleted.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                fixture.Platform.ReadCancellationCount == 1,
                "process-first admission did not cancel the blocked receipt read");
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            await authority.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task TestVerificationCancellationStartsAbortAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var nextOrder = 0L;
        var stopStartedOrder = 0L;
        var readCancellationOrder = 0L;
        var launchLease = new TestBrokerOwnedGuardianProcessLease(
            fixture.Identity,
            stopStartedObserver: () => Volatile.Write(
                ref stopStartedOrder,
                Interlocked.Increment(ref nextOrder)));
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        using var cancellation = new CancellationTokenSource();
        Task? verification = null;
        var readCancellationObserved = new TaskCompletionSource<
            BrokerGuardianProcessStopRequestV1?>(
                TaskCreationOptions.RunContinuationsAsynchronously);
        BrokerGuardianProcessStopRequestV1? stopIntentAtPipeDispose = null;
        try
        {
            fixture.Platform.BlockNextRead = true;
            fixture.Platform.IgnoreReadCancellation = false;
            fixture.Platform.ReleaseBlockedReadOnDispose = false;
            fixture.Platform.OnReadCancellationRequested = () =>
            {
                Volatile.Write(
                    ref readCancellationOrder,
                    Interlocked.Increment(ref nextOrder));
                readCancellationObserved.TrySetResult(launchLease.LastStopRequest);
            };
            fixture.Platform.OnDispose = () =>
                stopIntentAtPipeDispose = launchLease.LastStopRequest;
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            var activeVerification = VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority,
                    cancellation.Token)
                .AsTask();
            verification = activeVerification;
            await fixture.Platform.ReadStarted.WaitAsync(CaseTimeout).ConfigureAwait(false);
            cancellation.Cancel();

            var failure = await ExpectFailureAsync(() => activeVerification).ConfigureAwait(false);
            Ensure(
                failure is OperationCanceledException canceled &&
                canceled.CancellationToken == cancellation.Token,
                "managed-entry cancellation was replaced by its induced process completion");
            await launchLease.StopStarted.WaitAsync(CaseTimeout).ConfigureAwait(false);
            await fixture.Platform.Disposed.WaitAsync(CaseTimeout).ConfigureAwait(false);
            var stopIntentAtReadCancellation = await readCancellationObserved.Task
                .WaitAsync(CaseTimeout)
                .ConfigureAwait(false);
            var observedStopStartedOrder = Volatile.Read(ref stopStartedOrder);
            var observedReadCancellationOrder = Volatile.Read(ref readCancellationOrder);
            Ensure(
                observedStopStartedOrder > 0 &&
                observedReadCancellationOrder > observedStopStartedOrder,
                "the receipt read observed cancellation at ordinal " +
                observedReadCancellationOrder +
                " before Stop was latched at ordinal " +
                observedStopStartedOrder);
            Ensure(
                stopIntentAtReadCancellation == BrokerGuardianProcessStopRequestV1.AdmissionFailure,
                "the cancellation-compliant read observed " +
                (stopIntentAtReadCancellation?.ToString() ?? "null") +
                " before final Stop " +
                (launchLease.LastStopRequest?.ToString() ?? "null"));
            Ensure(
                stopIntentAtPipeDispose == BrokerGuardianProcessStopRequestV1.AdmissionFailure,
                "the pipe closed before exact Stop was latched");
            Ensure(
                launchLease.DisposeCount == 1,
                "managed-entry cancellation did not issue exactly one Stop");
            Ensure(
                fixture.Platform.DisposeCount == 1,
                "managed-entry cancellation did not close the pipe platform exactly once");
            Ensure(
                fixture.Platform.ReadCancellationCount == 1,
                "the cancellation-compliant receipt read did not observe exactly one cancellation");
            Ensure(
                fixture.PeerLease.DisposeCount == 1,
                "managed-entry cancellation did not release the retained peer lease exactly once");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            cancellation.Cancel();
            fixture.Platform.ReleaseBlockedRead();
            if (verification is not null)
            {
                try
                {
                    await verification.WaitAsync(CaseTimeout).ConfigureAwait(false);
                }
                catch (OperationCanceledException canceled)
                    when (canceled.CancellationToken == cancellation.Token)
                {
                }
            }

            await authority.DisposeAsync()
                .AsTask()
                .WaitAsync(CaseTimeout)
                .ConfigureAwait(false);
        }
    }

    private static async Task TestVerificationCancellationDoesNotDependOnReadAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        using var cancellation = new CancellationTokenSource();
        Task? verification = null;
        try
        {
            fixture.Platform.BlockNextRead = true;
            fixture.Platform.IgnoreReadCancellation = true;
            fixture.Platform.ReleaseBlockedReadOnDispose = false;
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            var activeVerification = VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority,
                    cancellation.Token)
                .AsTask();
            verification = activeVerification;
            await fixture.Platform.ReadStarted.WaitAsync(CaseTimeout).ConfigureAwait(false);
            cancellation.Cancel();
            await launchLease.StopStarted.WaitAsync(CaseTimeout).ConfigureAwait(false);
            await fixture.Platform.Disposed.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                !activeVerification.IsCompleted &&
                launchLease.LastStopRequest == BrokerGuardianProcessStopRequestV1.AdmissionFailure &&
                launchLease.DisposeCount == 1 &&
                fixture.Platform.DisposeCount == 1,
                "managed-entry abort waited for receipt return before starting Stop and close");

            fixture.Platform.ReleaseBlockedRead();
            var failure = await ExpectFailureAsync(() => activeVerification).ConfigureAwait(false);
            Ensure(
                failure is OperationCanceledException canceled &&
                canceled.CancellationToken == cancellation.Token,
                "a valid receipt released after abort created a verified wrapper");
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            cancellation.Cancel();
            fixture.Platform.ReleaseBlockedRead();
            if (verification is not null)
            {
                try
                {
                    await verification.ConfigureAwait(false);
                }
                catch
                {
                }
            }

            await authority.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task TestVerificationCancellationCleanupArbitrationAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var stopFailure = new IOException("managed-entry cancellation Stop failure");
        var pipeFailure = new IOException("managed-entry cancellation pipe failure");
        var launchLease = new TestBrokerOwnedGuardianProcessLease(
            fixture.Identity,
            disposeFailure: stopFailure);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        using var cancellation = new CancellationTokenSource();
        Task? verification = null;
        try
        {
            fixture.Platform.BlockNextRead = true;
            fixture.Platform.IgnoreReadCancellation = true;
            fixture.Platform.ReleaseBlockedReadOnDispose = true;
            fixture.Platform.OnDispose = () => throw pipeFailure;
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            var activeVerification = VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority,
                    cancellation.Token)
                .AsTask();
            verification = activeVerification;
            await fixture.Platform.ReadStarted.WaitAsync(CaseTimeout).ConfigureAwait(false);
            cancellation.Cancel();
            var primary = await ExpectFailureAsync(() => activeVerification).ConfigureAwait(false);
            var cleanup = primary.Data[
                BrokerControlFailureArbitration.CleanupFailureDataKey] as Exception;
            Ensure(
                primary is OperationCanceledException canceled &&
                canceled.CancellationToken == cancellation.Token &&
                ContainsExceptionReference(cleanup, stopFailure) &&
                ContainsExceptionReference(cleanup, pipeFailure),
                "managed-entry cancellation lost exact Stop or pipe cleanup evidence");
            Ensure(
                launchLease.DisposeCount == 1 && fixture.Platform.DisposeCount == 1,
                "managed-entry cleanup failure retried an exact authority");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            cancellation.Cancel();
            fixture.Platform.ReleaseBlockedRead();
            if (verification is not null)
            {
                try
                {
                    await verification.ConfigureAwait(false);
                }
                catch
                {
                }
            }

            try
            {
                await authority.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }

    private static async Task TestVerificationCancellationProcessSnapshotAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        using var cancellation = new CancellationTokenSource();
        try
        {
            fixture.Platform.BlockNextRead = true;
            fixture.Platform.IgnoreReadCancellation = true;
            fixture.Platform.ReleaseBlockedReadOnDispose = true;
            fixture.Platform.BeforeReadStart = () =>
            {
                launchLease.CompleteProcessExit(73);
                cancellation.Cancel();
            };
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            var primary = await ExpectBrokerCodeAsync(
                    "managed-entry-process-exited",
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority,
                            cancellation.Token)
                        .AsTask())
                .ConfigureAwait(false);
            var concurrent = primary.Data[
                BrokerControlFailureArbitration.ConcurrentFailureDataKey] as Exception;
            Ensure(
                ContainsCancellation(concurrent, cancellation.Token),
                "pre-abort process completion did not retain caller cancellation as concurrent");
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            fixture.Platform.ReleaseBlockedRead();
            await authority.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task TestVerificationSuccessCommitBoundaryAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        using var cancellation = new CancellationTokenSource();
        VerifiedGuardianManagedEntryConnectionV1? verified = null;
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            verified = await VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority,
                    cancellation.Token)
                .ConfigureAwait(false);
            cancellation.Cancel();
            Ensure(
                launchLease.DisposeCount == 0 &&
                fixture.Platform.DisposeCount == 0 &&
                ExactIdentityEquals(fixture.Identity, verified.Revalidate()),
                "late cancellation stole authority from a committed verified wrapper");

            await verified.DisposeAsync().ConfigureAwait(false);
            Ensure(
                launchLease.DisposeCount == 1 &&
                launchLease.LastStopRequest == BrokerGuardianProcessStopRequestV1.Disposal &&
                fixture.Platform.DisposeCount == 1 &&
                fixture.PeerLease.DisposeCount == 1,
                "success-first cancellation boundary created two cleanup owners");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            if (verified is not null)
            {
                await verified.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                try
                {
                    await fixture.Connection.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }

                await authority.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static async Task TestVerificationSimultaneousFailureAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        var rawReadFailure = new IOException("managed-entry simultaneous receipt failure");
        try
        {
            fixture.Platform.ReadFailure = rawReadFailure;
            fixture.Platform.BeforeReadStart = () => launchLease.CompleteProcessExit(41);
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            var primary = await ExpectBrokerCodeAsync(
                    "managed-entry-process-exited",
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority)
                        .AsTask())
                .ConfigureAwait(false);
            var concurrent = primary.Data[
                BrokerControlFailureArbitration.ConcurrentFailureDataKey] as Exception;
            Ensure(
                ContainsExceptionReference(concurrent, rawReadFailure),
                "simultaneous receipt failure was not retained behind the exact process failure");
            EnsureVerificationFailureReleased(fixture, launchLease);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            await authority.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task TestVerifiedCompletionProcessMonitorAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        BrokerGuardianCleanLaunchAuthorityV1? authority = null;
        VerifiedGuardianManagedEntryConnectionV1? verified = null;
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
                launchLease,
                metadata,
                challenge);
            verified = await VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority)
                .ConfigureAwait(false);
            var verifiedConnection = verified!;
            authority.Dispose();
            authority = null;
            launchLease.CompleteProcessExit(31);
            await ExpectBrokerCodeAsync(
                    "managed-entry-process-exited",
                    () => verifiedConnection.Completion)
                .ConfigureAwait(false);
            Ensure(
                !fixture.Connection.Completion.IsCompleted,
                "raw pipe completion masked the post-admission process monitor case");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            if (verified is not null)
            {
                await verified.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await fixture.Connection.DisposeAsync().ConfigureAwait(false);
                if (authority is not null)
                {
                    await authority.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private static async Task TestVerificationDisposalOrderingAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(
            fixture.Identity,
            completeProcessOnStop: false);
        BrokerGuardianCleanLaunchAuthorityV1? authority = null;
        VerifiedGuardianManagedEntryConnectionV1? verified = null;
        BrokerGuardianProcessStopRequestV1? intentAtPipeDispose = null;
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
                launchLease,
                metadata,
                challenge);
            verified = await VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority)
                .ConfigureAwait(false);
            var verifiedConnection = verified!;
            authority.Dispose();
            authority = null;
            fixture.Platform.OnDispose = () =>
            {
                intentAtPipeDispose = launchLease.LastStopRequest;
                launchLease.CompleteProcessExit(0);
            };
            await verifiedConnection.DisposeAsync().ConfigureAwait(false);
            await verifiedConnection.Completion.ConfigureAwait(false);
            var processExit = await launchLease.Completion.ConfigureAwait(false);
            Ensure(
                intentAtPipeDispose == BrokerGuardianProcessStopRequestV1.Disposal &&
                processExit.ProcessId == FixtureProcessId &&
                launchLease.DisposeCount == 1 &&
                fixture.Platform.DisposeCount == 1,
                "pipe cleanup ran before the owner disposal intent was latched");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            if (verified is not null)
            {
                await verified.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await fixture.Connection.DisposeAsync().ConfigureAwait(false);
                if (authority is not null)
                {
                    await authority.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private static async Task TestVerificationDisposalCleanupArbitrationAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var stopFailure = new IOException("verified owner Stop cleanup failure");
        var pipeFailure = new IOException("verified owner pipe cleanup failure");
        var launchLease = new TestBrokerOwnedGuardianProcessLease(
            fixture.Identity,
            disposeFailure: stopFailure);
        BrokerGuardianCleanLaunchAuthorityV1? authority = null;
        VerifiedGuardianManagedEntryConnectionV1? verified = null;
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
                launchLease,
                metadata,
                challenge);
            verified = await VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority)
                .ConfigureAwait(false);
            authority.Dispose();
            authority = null;
            fixture.Platform.OnDispose = () => throw pipeFailure;
            var first = await ExpectFailureAsync(
                    () => verified.DisposeAsync().AsTask())
                .ConfigureAwait(false);
            var repeated = await ExpectFailureAsync(
                    () => verified.DisposeAsync().AsTask())
                .ConfigureAwait(false);
            Ensure(
                ReferenceEquals(first, repeated) &&
                ContainsExceptionReference(first, stopFailure) &&
                ContainsExceptionReference(first, pipeFailure) &&
                launchLease.DisposeCount == 1 &&
                fixture.Platform.DisposeCount == 1,
                "verified owner disposal lost or retried an exact cleanup failure");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            if (verified is not null)
            {
                try
                {
                    await verified.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }
            }

            if (authority is not null)
            {
                try
                {
                    await authority.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }
            }
        }
    }

    private static async Task TestClaimDisposalRaceAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var launchLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        BrokerGuardianCleanLaunchAuthorityV1? authority = null;
        VerifiedGuardianManagedEntryConnectionV1? verified = null;
        try
        {
            fixture.Platform.EnqueueRead(
                GuardianManagedEntryProofProtocolV1.Serialize(
                    CreateReceipt(fixture.Identity, metadata, challenge)));
            authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
                launchLease,
                metadata,
                challenge);
            verified = await VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                    fixture.Connection,
                    authority)
                .ConfigureAwait(false);
            var verifiedConnection = verified!;
            authority.Dispose();
            authority = null;

            using var start = new Barrier(2);
            var disposalPublished = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var claim = Task.Run<Exception?>(() =>
            {
                start.SignalAndWait();
                try
                {
                    verifiedConnection.ClaimForControlSession();
                    return null;
                }
                catch (Exception exception)
                {
                    return exception;
                }
            });
            var dispose = Task.Run(async () =>
            {
                start.SignalAndWait();
                var pending = verifiedConnection.DisposeAsync().AsTask();
                disposalPublished.TrySetResult();
                await pending.ConfigureAwait(false);
            });
            await disposalPublished.Task.WaitAsync(CaseTimeout).ConfigureAwait(false);
            var publishedDisposeClaimFailure = await ExpectFailureAsync(() => Task.Run(
                    verifiedConnection.ClaimForControlSession))
                .ConfigureAwait(false);
            var claimFailure = await claim.ConfigureAwait(false);
            await dispose.ConfigureAwait(false);
            Ensure(
                claimFailure is null or ObjectDisposedException,
                "claim/dispose race returned an unstable failure type");
            Ensure(
                publishedDisposeClaimFailure is ObjectDisposedException,
                "a published disposal still allowed a new control-session claim");
            var postDisposeFailure = await ExpectFailureAsync(() => Task.Run(
                    verifiedConnection.ClaimForControlSession))
                .ConfigureAwait(false);
            Ensure(
                postDisposeFailure is ObjectDisposedException,
                "a disposed verified connection still accepted a control-session claim");
            Ensure(
                launchLease.DisposeCount == 1 &&
                fixture.Platform.DisposeCount == 1,
                "claim/dispose race did not release each retained authority exactly once");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            if (verified is not null)
            {
                await verified.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await fixture.Connection.DisposeAsync().ConfigureAwait(false);
                if (authority is not null)
                {
                    await authority.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private static async Task TestVerificationCleanupArbitrationAsync()
    {
        var fixture = await CreateVerificationFixtureAsync().ConfigureAwait(false);
        var challenge = CreateChallenge();
        var metadata = CreateMetadata();
        var rawCleanupFailure = new IOException("managed-entry raw cleanup failure");
        var launchCleanupFailure = new IOException("managed-entry launch cleanup failure");
        var nullConnectionLease = new TestBrokerOwnedGuardianProcessLease(fixture.Identity);
        var nullConnectionAuthority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            nullConnectionLease,
            metadata,
            challenge);
        var nullConnectionFailure = await ExpectFailureAsync(
                () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                        connection: null!,
                        launchAuthority: nullConnectionAuthority)
                    .AsTask())
            .ConfigureAwait(false);
        Ensure(
            nullConnectionFailure is ArgumentNullException &&
            nullConnectionLease.DisposeCount == 1,
            "null authenticated connection leaked clean-launch authority");
        fixture.PeerLease.DisposeFailure = rawCleanupFailure;
        fixture.Platform.EnqueueRead(Encoding.UTF8.GetBytes("{}"));
        var launchLease = new TestBrokerOwnedGuardianProcessLease(
            fixture.Identity,
            disposeFailure: launchCleanupFailure);
        var authority = BrokerGuardianCleanLaunchAuthorityV1.Create(
            launchLease,
            metadata,
            challenge);
        try
        {
            var primary = await ExpectBrokerCodeAsync(
                    "managed-entry-proof-invalid",
                    () => VerifiedGuardianManagedEntryConnectionV1.VerifyAsync(
                            fixture.Connection,
                            authority)
                        .AsTask())
                .ConfigureAwait(false);
            var repeatedRawCleanup = await ExpectFailureAsync(
                    () => fixture.Connection.DisposeAsync().AsTask())
                .ConfigureAwait(false);
            var preserved = primary.Data[BrokerControlFailureArbitration.CleanupFailureDataKey]
                as Exception;
            Ensure(
                BrokerControlFailureArbitration.ContainsFailure(
                    preserved,
                    repeatedRawCleanup) &&
                BrokerControlFailureArbitration.ContainsFailure(
                    preserved,
                    launchCleanupFailure),
                "managed-entry primary failure did not preserve both cleanup failures");
            Ensure(
                fixture.Platform.DisposeCount == 1 &&
                fixture.PeerLease.DisposeCount == 1 &&
                launchLease.DisposeCount == 1,
                "managed-entry cleanup arbitration retried or skipped an owned resource");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static void TestProgramSourceBoundary()
    {
        var source = File.ReadAllText(Path.Combine(
            FindSourceRoot(),
            "CodexGuardian",
            "Program.cs"));
        var proofBranch = source.IndexOf(
            "ContainsManagedEntryProofPrefix(args)",
            StringComparison.Ordinal);
        var environment = source.IndexOf("EnsureWindowsEnvironment();", StringComparison.Ordinal);
        var app = source.IndexOf("new App()", StringComparison.Ordinal);
        var proofMethod = source.IndexOf("TryRunManagedEntryProof", StringComparison.Ordinal);
        var proofMethodEnd = proofMethod >= 0
            ? source.IndexOf(
                "private static bool ContainsManagedEntryProofPrefix",
                proofMethod,
                StringComparison.Ordinal)
            : -1;
        var proofDispatch = proofBranch >= 0 && environment > proofBranch
            ? source[proofBranch..environment]
            : string.Empty;
        var proofImplementation = proofMethod >= 0 && proofMethodEnd > proofMethod
            ? source[proofMethod..proofMethodEnd]
            : string.Empty;
        Ensure(
            proofBranch >= 0 && proofBranch < environment && environment < app &&
            proofMethod >= 0 && proofMethodEnd > proofMethod &&
            proofImplementation.Contains("return 64;", StringComparison.Ordinal) &&
            proofImplementation.Contains("Console.OpenStandardOutput()", StringComparison.Ordinal) &&
            !proofDispatch.Contains("SettingsService", StringComparison.Ordinal) &&
            !proofImplementation.Contains("SettingsService", StringComparison.Ordinal) &&
            !proofDispatch.Contains("GuardianLog", StringComparison.Ordinal) &&
            !proofImplementation.Contains("GuardianLog", StringComparison.Ordinal) &&
            !proofDispatch.Contains("--endpoint", StringComparison.OrdinalIgnoreCase) &&
            !proofImplementation.Contains("--endpoint", StringComparison.OrdinalIgnoreCase) &&
            !proofDispatch.Contains("--output-path", StringComparison.OrdinalIgnoreCase) &&
            !proofImplementation.Contains("--output-path", StringComparison.OrdinalIgnoreCase),
            "Guardian proof-only dispatch can enter WPF or accept a writable path/endpoint");
    }

    private static async Task VerifyPublishedAppHostAsync(string runtimeRoot)
    {
        var appHostPath = RequireDirectFile(runtimeRoot, "CodexGuardian.exe");
        var managedEntryPath = RequireDirectFile(runtimeRoot, "CodexGuardian.dll");
        var expectedMetadata =
            GuardianManagedEntryMetadataIdentityV1.ReadFromAssemblyFile(managedEntryPath);
        var challenge = Enumerable.Range(0, GuardianManagedEntryProofProtocolV1.ChallengeBytes)
            .Select(index => checked((byte)index))
            .ToArray();
        try
        {
            var challengeText = Convert.ToHexString(challenge).ToLowerInvariant();
            var startInfo = new ProcessStartInfo(appHostPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = runtimeRoot,
            };
            startInfo.ArgumentList.Add("--guardian-managed-entry-proof-v1");
            startInfo.ArgumentList.Add("--challenge");
            startInfo.ArgumentList.Add(challengeText);

            using var process = Process.Start(startInfo) ??
                throw new InvalidOperationException(
                    "The published Guardian managed-entry apphost could not start.");
            var processId = checked((uint)process.Id);
            var sessionId = checked((uint)process.SessionId);
            var creationTimeUtc = new DateTimeOffset(
                process.StartTime.ToUniversalTime(),
                TimeSpan.Zero);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var stdoutTask = ReadBoundedAsync(
                process.StandardOutput.BaseStream,
                GuardianManagedEntryProofProtocolV1.MaximumReceiptBytes,
                timeout.Token);
            var stderrTask = ReadBoundedAsync(
                process.StandardError.BaseStream,
                maximumBytes: 4096,
                timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }

                throw new TimeoutException(
                    "The published Guardian managed-entry apphost exceeded ten seconds.");
            }

            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);
            Ensure(process.ExitCode == 0, "published Guardian proof-only exit code was not zero");
            Ensure(stderr.Length == 0, "published Guardian proof-only stderr was not empty");
            Ensure(
                GuardianManagedEntryProofProtocolV1.TryParse(
                    stdout,
                    out var receipt,
                    out var reason) &&
                receipt is not null &&
                string.Equals(reason, "accepted", StringComparison.Ordinal),
                "published Guardian proof-only stdout was not one canonical receipt");
            Ensure(
                string.Equals(
                    receipt!.ChallengeSha256,
                    GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(challenge),
                    StringComparison.Ordinal) &&
                receipt.ProcessId == processId &&
                receipt.SessionId == sessionId &&
                receipt.CreationTimeUtc == creationTimeUtc &&
                receipt.Metadata == expectedMetadata,
                "published Guardian proof-only receipt did not bind the exact child and managed entry");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static string ReadPublishedRuntimeRoot(IReadOnlyList<string> arguments)
    {
        if (arguments.Count != 3 ||
            !string.Equals(
                arguments[0],
                PublishedAppHostProbeArgument,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                arguments[1],
                PublishedRuntimeRootArgument,
                StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(arguments[2]))
        {
            throw new ArgumentException(
                "Published Guardian managed-entry probe arguments are invalid.");
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(arguments[2]));
        var volumeRoot = Path.GetPathRoot(root);
        if (root.StartsWith(@"\\", StringComparison.Ordinal) ||
            !string.Equals(volumeRoot, @"D:\", StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(root))
        {
            throw new InvalidDataException(
                "Published Guardian managed-entry probe requires an existing local D-drive runtime root.");
        }

        var trustedVolumeRoot = volumeRoot!;
        var current = trustedVolumeRoot;
        foreach (var segment in Path.GetRelativePath(trustedVolumeRoot, root).Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                (attributes & FileAttributes.Directory) == 0)
            {
                throw new InvalidDataException(
                    "Published Guardian managed-entry runtime root traverses an invalid component.");
            }
        }

        return root;
    }

    private static string RequireDirectFile(string root, string fileName)
    {
        var path = Path.GetFullPath(Path.Combine(root, fileName));
        if (!string.Equals(
                Path.GetDirectoryName(path),
                root,
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
        {
            throw new FileNotFoundException(
                "Published Guardian managed-entry file is missing.",
                path);
        }

        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 ||
            (attributes & FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException(
                "Published Guardian managed-entry file has an invalid identity.");
        }

        return path;
    }

    private static async Task<byte[]> ReadBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[checked(maximumBytes + 1)];
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(
                    buffer.AsMemory(offset, buffer.Length - offset),
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                return buffer[..offset];
            }

            offset += read;
        }

        throw new InvalidDataException(
            $"Published Guardian managed-entry output exceeded {maximumBytes} bytes.");
    }

    private static string FindSourceRoot()
    {
        var candidate = new DirectoryInfo(Environment.CurrentDirectory);
        while (candidate is not null)
        {
            if (File.Exists(Path.Combine(candidate.FullName, "package-release.ps1")) &&
                File.Exists(Path.Combine(
                    candidate.FullName,
                    "CodexGuardian.Tests",
                    "CodexGuardian.Tests.csproj")))
            {
                return candidate.FullName;
            }

            var work = Path.Combine(candidate.FullName, "work");
            if (File.Exists(Path.Combine(work, "package-release.ps1")) &&
                File.Exists(Path.Combine(
                    work,
                    "CodexGuardian.Tests",
                    "CodexGuardian.Tests.csproj")))
            {
                return work;
            }

            candidate = candidate.Parent;
        }

        throw new DirectoryNotFoundException(
            "The authoritative CodexGuardian workspace was not found.");
    }

    private static GuardianManagedEntryMetadataIdentityV1 CreateMetadata() => new(
        GuardianManagedEntryMetadataIdentityV1.ExpectedAppHostFileName,
        GuardianManagedEntryMetadataIdentityV1.ExpectedManagedEntryRelativePath,
        GuardianManagedEntryMetadataIdentityV1.ExpectedAssemblyName,
        ModuleVersionId,
        0x06000001,
        GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointDeclaringType,
        GuardianManagedEntryMetadataIdentityV1.ExpectedEntryPointMethod);

    private static byte[] CreateChallenge() =>
        Enumerable.Range(0, GuardianManagedEntryProofProtocolV1.ChallengeBytes)
            .Select(index => checked((byte)index))
            .ToArray();

    private static GuardianManagedEntryReceiptV1 CreateReceipt(
        WindowsProcessIdentity identity,
        GuardianManagedEntryMetadataIdentityV1 metadata,
        ReadOnlySpan<byte> challenge) =>
        new(
            GuardianManagedEntryProofProtocolV1.ComputeChallengeSha256(challenge),
            identity.ProcessId,
            identity.KernelSessionId,
            identity.CreationTimeUtc,
            metadata);

    private static async Task<VerificationFixture> CreateVerificationFixtureAsync()
    {
        var release = CreateFixtureManifest().GetArtifactSet(BrokerPeerRole.Guardian);
        var identity = CreateFixtureIdentity(release);
        var peerLease = new VerificationPeerLease(
            identity,
            new RetainedReleaseHandleSet(
                release.Root,
                release.Artifacts.Select(artifact => artifact.RelativePath).ToArray()));
        var platform = new VerificationMessagePlatform(release, peerLease);
        var verifier = new WindowsNamedPipePeerVerifier(
            WindowsNamedPipePeerVerifier.DefaultHandshakeTimeout,
            beforeAuthorityTransfer: null,
            afterAuthorityTransfer: null,
            maximumConnections: 1);
        await using var pending = verifier.BeginVerification(
            platform,
            NamedPipePeerKind.Client,
            new BrokerPeerExpectation(
                CreateFixtureToken(),
                WindowsAppModelIdentity.Unpackaged,
                release,
                FixtureConnectionNonce,
                FixtureProcessId,
                FixtureCreationTime));
        var connection = await pending.CompleteConnectionAsync().ConfigureAwait(false);
        platform.BindConnectionCompletion(connection.Completion);
        return new VerificationFixture(
            verifier,
            platform,
            peerLease,
            connection,
            identity);
    }

    private static VerifiedReleaseManifest CreateFixtureManifest() =>
        VerifiedReleaseManifest.CreateFromVerifiedPayload(
            FixtureReleaseId,
            FixtureManifestSha256,
            new WindowsReleaseRootIdentity(
                FixtureReleaseRoot,
                FileAttributes.Directory | FileAttributes.Archive,
                FixtureVolumeSerial,
                new string('a', 32),
                true),
            CreateFixtureRoleDefinition(BrokerPeerRole.Guardian),
            CreateFixtureRoleDefinition(BrokerPeerRole.Broker));

    private static VerifiedReleaseRoleArtifacts CreateFixtureRoleDefinition(
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
                CreateFixtureArtifact(
                    ReleaseArtifactKind.AppHostExe,
                    stem + ".exe",
                    seed,
                    128 * 1024),
                CreateFixtureArtifact(
                    ReleaseArtifactKind.ManagedEntryDll,
                    stem + ".dll",
                    (char)(seed + 1),
                    512 * 1024),
                CreateFixtureArtifact(
                    ReleaseArtifactKind.DepsJson,
                    stem + ".deps.json",
                    (char)(seed + 2),
                    64 * 1024),
                CreateFixtureArtifact(
                    ReleaseArtifactKind.RuntimeConfigJson,
                    stem + ".runtimeconfig.json",
                    (char)(seed + 3),
                    4 * 1024)
            });
    }

    private static WindowsArtifactIdentity CreateFixtureArtifact(
        ReleaseArtifactKind kind,
        string relativePath,
        char seed,
        long length) =>
        new(
            kind,
            relativePath,
            Path.Combine(FixtureReleaseRoot, relativePath),
            FileAttributes.Archive,
            length,
            new string(seed, 64),
            FixtureVolumeSerial,
            new string(seed, 32),
            1,
            true);

    private static WindowsProcessIdentity CreateFixtureIdentity(
        VerifiedReleaseArtifactSet release)
    {
        var appHost = release.Artifacts.Single(
            artifact => artifact.Kind == ReleaseArtifactKind.AppHostExe);
        return new WindowsProcessIdentity(
            FixtureProcessId,
            FixtureCreationTime,
            FixtureSessionId,
            CreateFixtureToken(),
            WindowsAppModelIdentity.Unpackaged,
            appHost.FinalPath,
            true,
            release.Root,
            release.Artifacts);
    }

    private static WindowsProcessIdentity CreateDriftedIdentity(
        WindowsProcessIdentity identity) =>
        new(
            identity.ProcessId,
            identity.CreationTimeUtc,
            identity.KernelSessionId,
            identity.Token,
            identity.AppModel,
            identity.FinalImagePath + ".drift",
            identity.ImageFileObjectIsExact,
            identity.ReleaseRoot,
            identity.Artifacts);

    private static WindowsTokenIdentity CreateFixtureToken() =>
        new(
            FixtureUserSid,
            FixtureLogonSid,
            1,
            0x0000000100000002UL,
            FixtureSessionId,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Primary,
            null);

    private static WindowsTokenIdentity CreateFixtureImpersonationToken() =>
        CreateFixtureToken() with
        {
            TokenType = WindowsTokenType.Impersonation,
            ImpersonationLevel = WindowsSecurityImpersonationLevel.Identification
        };

    private static BrokerPeerHello CreateFixtureHello() =>
        new(
            BrokerPeerHelloProtocol.ProtocolVersion,
            BrokerPeerRole.Guardian,
            FixtureProcessId,
            FixtureSessionId,
            FixtureCreationTime,
            FixtureConnectionNonce,
            FixtureReleaseId,
            FixtureManifestSha256);

    private static bool ExactIdentityEquals(
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

    private static void EnsureVerificationFailureReleased(
        VerificationFixture fixture,
        TestBrokerOwnedGuardianProcessLease launchLease)
    {
        Ensure(
            fixture.Platform.DisposeCount == 1 &&
            fixture.PeerLease.DisposeCount == 1 &&
            launchLease.DisposeCount == 1 &&
            launchLease.LastStopRequest == BrokerGuardianProcessStopRequestV1.AdmissionFailure,
            "failed managed-entry verification did not release raw and launch authority once");
    }

    private static bool ContainsExceptionReference(
        Exception? container,
        Exception candidate)
    {
        if (container is null)
        {
            return false;
        }

        if (ReferenceEquals(container, candidate))
        {
            return true;
        }

        if (container is AggregateException aggregate &&
            aggregate.InnerExceptions.Any(inner =>
                ContainsExceptionReference(inner, candidate)))
        {
            return true;
        }

        return container.InnerException is not null &&
            ContainsExceptionReference(container.InnerException, candidate);
    }

    private static bool ContainsCancellation(
        Exception? container,
        CancellationToken cancellationToken)
    {
        if (container is null)
        {
            return false;
        }

        if (container is OperationCanceledException canceled &&
            canceled.CancellationToken == cancellationToken)
        {
            return true;
        }

        if (container is AggregateException aggregate &&
            aggregate.InnerExceptions.Any(inner =>
                ContainsCancellation(inner, cancellationToken)))
        {
            return true;
        }

        return container.InnerException is not null &&
            ContainsCancellation(container.InnerException, cancellationToken);
    }

    private static void Reject(byte[] payload, string message)
    {
        Ensure(
            !GuardianManagedEntryProofProtocolV1.TryParse(payload, out _, out _),
            message);
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
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().WaitAsync(CaseTimeout).ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static BrokerControlSessionException ExpectBrokerCode(
        string code,
        Action action)
    {
        try
        {
            action();
        }
        catch (BrokerControlSessionException exception)
        {
            Ensure(
                string.Equals(exception.Code, code, StringComparison.Ordinal),
                $"expected Broker failure {code}, received {exception.Code}");
            return exception;
        }

        throw new InvalidOperationException("Expected Broker failure " + code + ".");
    }

    private static async Task<BrokerControlSessionException> ExpectBrokerCodeAsync(
        string code,
        Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (BrokerControlSessionException exception)
        {
            Ensure(
                string.Equals(exception.Code, code, StringComparison.Ordinal),
                $"expected Broker failure {code}, received {exception.Code}");
            return exception;
        }

        throw new InvalidOperationException("Expected Broker failure " + code + ".");
    }

    private static async Task<Exception> ExpectFailureAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return exception;
        }

        throw new InvalidOperationException("Expected an exception.");
    }

    private static void Expect<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException("Expected " + typeof(TException).Name + ".");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record VerificationFixture(
        WindowsNamedPipePeerVerifier Verifier,
        VerificationMessagePlatform Platform,
        VerificationPeerLease PeerLease,
        AuthenticatedPipePeerConnection Connection,
        WindowsProcessIdentity Identity);

    private sealed class VerificationMessagePlatform :
        INamedPipePeerTrustPlatform,
        INamedPipePeerMessageTransport
    {
        private readonly VerifiedReleaseArtifactSet _release;
        private readonly VerificationPeerLease _peerLease;
        private readonly ConcurrentQueue<byte[]> _reads = new();
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _readStarted = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _readCompleted = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _blockedReadRelease = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _disposedSignal = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private long _readGeneration;
        private int _readCancellationCount;
        private int _disposeCount;
        private int _disposed;
        private Task? _connectionCompletion;

        internal VerificationMessagePlatform(
            VerifiedReleaseArtifactSet release,
            VerificationPeerLease peerLease)
        {
            _release = release;
            _peerLease = peerLease;
        }

        public DateTimeOffset UtcNow => FixtureCreationTime.AddMinutes(1);

        public long ReadGeneration => Volatile.Read(ref _readGeneration);

        public Task Completion => _completion.Task;

        internal bool CompleteOnRead { get; set; }

        internal bool BlockNextRead { get; set; }

        internal bool IgnoreReadCancellation { get; set; }

        internal bool ReleaseBlockedReadOnDispose { get; set; }

        internal Action? BeforeReadStart { get; set; }

        internal Action? BeforeReadReturn { get; set; }

        internal Action? OnReadCancellationRequested { get; set; }

        internal Exception? ReadFailure { get; set; }

        internal Action? OnDispose { get; set; }

        internal Task ReadStarted => _readStarted.Task;

        internal Task ReadCompleted => _readCompleted.Task;

        internal Task Disposed => _disposedSignal.Task;

        internal int ReadCancellationCount => Volatile.Read(ref _readCancellationCount);

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        public PipePeerKernelIdentity CaptureKernelPeer(NamedPipePeerKind peerKind)
        {
            Ensure(peerKind == NamedPipePeerKind.Client, "fixture used the wrong pipe direction");
            return new PipePeerKernelIdentity(FixtureProcessId, FixtureSessionId);
        }

        public IRetainedPeerIdentityLease OpenRetainedPeer(
            uint processId,
            VerifiedReleaseArtifactSet release)
        {
            Ensure(
                processId == FixtureProcessId && ReferenceEquals(release, _release),
                "fixture opened the wrong retained Guardian peer");
            return _peerLease;
        }

        public ValueTask<PipePeerHelloReadEvidence> ReadBoundedHelloAndCaptureIdentityAsync(
            NamedPipePeerKind peerKind,
            int maximumHelloBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hello = BrokerPeerHelloProtocol.Serialize(CreateFixtureHello());
            Ensure(hello.Length <= maximumHelloBytes, "fixture hello exceeded its bound");
            var kernel = CaptureKernelPeer(peerKind);
            return ValueTask.FromResult(new PipePeerHelloReadEvidence(
                hello,
                Interlocked.Increment(ref _readGeneration),
                kernel,
                kernel,
                CreateFixtureImpersonationToken()));
        }

        public void AbortHandshake(string boundedFailureCode) =>
            ArgumentException.ThrowIfNullOrWhiteSpace(boundedFailureCode);

        public async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
            int maximumMessageBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_reads.TryDequeue(out var message))
            {
                return ReadOnlyMemory<byte>.Empty;
            }

            Ensure(message.Length <= maximumMessageBytes, "fixture message exceeded its bound");
            var onReadCancellationRequested = OnReadCancellationRequested;
            OnReadCancellationRequested = null;
            var blockRead = BlockNextRead;
            BlockNextRead = false;
            var ignoreReadCancellation = IgnoreReadCancellation;
            var readCancellation = blockRead && !ignoreReadCancellation
                ? new TaskCompletionSource<bool>(
                    TaskCreationOptions.RunContinuationsAsynchronously)
                : null;
            using var readCancellationRegistration = readCancellation is null
                ? default
                : cancellationToken.UnsafeRegister(
                    static state =>
                    {
                        var registration = ((
                            Action? Observer,
                            TaskCompletionSource<bool> Signal,
                            CancellationToken Token))state!;
                        registration.Observer?.Invoke();
                        registration.Signal.TrySetCanceled(registration.Token);
                    },
                    (onReadCancellationRequested, readCancellation, cancellationToken));
            _readStarted.TrySetResult();
            try
            {
                var beforeReadStart = BeforeReadStart;
                BeforeReadStart = null;
                beforeReadStart?.Invoke();

                if (blockRead)
                {
                    if (ignoreReadCancellation)
                    {
                        await _blockedReadRelease.Task.ConfigureAwait(false);
                    }
                    else
                    {
                        var readWinner = await Task.WhenAny(
                                _blockedReadRelease.Task,
                                readCancellation!.Task)
                            .ConfigureAwait(false);
                        await readWinner.ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                }

                var readFailure = ReadFailure;
                ReadFailure = null;
                if (readFailure is not null)
                {
                    throw readFailure;
                }

                if (CompleteOnRead)
                {
                    _completion.TrySetResult();
                    try
                    {
                        await (_connectionCompletion ?? throw new InvalidOperationException(
                                "The fixture transport has no connection completion binding."))
                            .ConfigureAwait(false);
                    }
                    catch
                    {
                        // Closure is expected to fault the authenticated connection.
                    }
                }

                var beforeReadReturn = BeforeReadReturn;
                BeforeReadReturn = null;
                beforeReadReturn?.Invoke();

                return message;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Interlocked.Increment(ref _readCancellationCount);
                throw;
            }
            finally
            {
                _readCompleted.TrySetResult();
            }
        }

        public ValueTask WriteMessageAsync(
            ReadOnlyMemory<byte> message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Interlocked.Increment(ref _disposeCount);
                var onDispose = OnDispose;
                OnDispose = null;
                try
                {
                    if (ReleaseBlockedReadOnDispose)
                    {
                        _blockedReadRelease.TrySetResult();
                    }

                    onDispose?.Invoke();
                }
                finally
                {
                    _disposedSignal.TrySetResult();
                    _completion.TrySetResult();
                }
            }
        }

        internal void BindConnectionCompletion(Task completion) =>
            _connectionCompletion = completion ?? throw new ArgumentNullException(nameof(completion));

        internal void EnqueueRead(byte[] message) => _reads.Enqueue(message.ToArray());

        internal void ReleaseBlockedRead() => _blockedReadRelease.TrySetResult();
    }

    private sealed class VerificationPeerLease : IRetainedPeerIdentityLease
    {
        private readonly object _gate = new();
        private readonly WindowsProcessIdentity _identity;
        private readonly Queue<WindowsProcessIdentity> _captures = new();
        private int _disposeCount;
        private int _disposed;

        internal VerificationPeerLease(
            WindowsProcessIdentity identity,
            RetainedReleaseHandleSet retainedHandles)
        {
            _identity = identity;
            RetainedHandles = retainedHandles;
        }

        public bool IsAlive
        {
            get
            {
                ThrowIfDisposed();
                return true;
            }
        }

        public RetainedReleaseHandleSet RetainedHandles { get; }

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal Exception? DisposeFailure { get; set; }

        public WindowsProcessIdentity Capture()
        {
            ThrowIfDisposed();
            lock (_gate)
            {
                return _captures.Count == 0 ? _identity : _captures.Dequeue();
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Interlocked.Increment(ref _disposeCount);
                if (DisposeFailure is not null)
                {
                    throw DisposeFailure;
                }
            }
        }

        internal void SetCaptureSequence(params WindowsProcessIdentity[] identities)
        {
            ThrowIfDisposed();
            lock (_gate)
            {
                _captures.Clear();
                foreach (var identity in identities)
                {
                    _captures.Enqueue(identity);
                }
            }
        }

        private void ThrowIfDisposed() =>
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    }

        private sealed class TestBrokerOwnedGuardianProcessLease :
            IBrokerOwnedGuardianProcessLeaseV1
        {
            private readonly SharedState _state;
            private Task? _stopTask;
            private bool _owns;

        internal TestBrokerOwnedGuardianProcessLease(
            WindowsProcessIdentity identity,
            bool cleanEnvironmentVerified = true,
            bool runtimeNamespaceClosed = true,
            Exception? disposeFailure = null,
            bool completeProcessOnStop = true,
            Action? stopStartedObserver = null)
        {
            _state = new SharedState(
                identity ?? throw new ArgumentNullException(nameof(identity)),
                cleanEnvironmentVerified,
                runtimeNamespaceClosed,
                disposeFailure,
                completeProcessOnStop,
                stopStartedObserver);
            _owns = true;
        }

        private TestBrokerOwnedGuardianProcessLease(SharedState state)
        {
            _state = state;
            _owns = true;
        }

        public bool CleanEnvironmentVerified => Read(_state.CleanEnvironmentVerified);

        public bool RuntimeNamespaceClosed => Read(_state.RuntimeNamespaceClosed);

        public Task<BrokerGuardianProcessExitV1> Completion =>
            _state.ProcessCompletion.Task;

        internal int DisposeCount
        {
            get
            {
                lock (_state.Gate)
                {
                    return _state.DisposeCount;
                }
            }
        }

        internal BrokerGuardianProcessStopRequestV1? LastStopRequest
        {
            get
            {
                lock (_state.Gate)
                {
                    return _state.LastStopRequest;
                }
            }
        }

        internal Task StopStarted => _state.StopStarted.Task;

        public WindowsProcessIdentity Revalidate()
        {
            lock (_state.Gate)
            {
                EnsureOwned();
                return _state.Revalidations.Count == 0
                    ? _state.Identity
                    : _state.Revalidations.Dequeue();
            }
        }

        public IBrokerOwnedGuardianProcessLeaseV1 TakeOwnership()
        {
            lock (_state.Gate)
            {
                EnsureOwned();
                var successor = new TestBrokerOwnedGuardianProcessLease(_state);
                _owns = false;
                return successor;
            }
        }

        public Task StopAsync(BrokerGuardianProcessStopRequestV1 stopRequest)
        {
            if (stopRequest == BrokerGuardianProcessStopRequestV1.None)
            {
                throw new ArgumentOutOfRangeException(nameof(stopRequest));
            }

            lock (_state.Gate)
            {
                if (_stopTask is not null)
                {
                    return _stopTask;
                }

                if (!_owns)
                {
                    return Task.CompletedTask;
                }

                _owns = false;
                _state.ResourceDisposed = true;
                _state.DisposeCount++;
                _state.LastStopRequest = stopRequest;
                _state.StopStartedObserver?.Invoke();
                _state.StopStarted.TrySetResult();
                if (_state.ConfiguredDisposeFailure is not null)
                {
                    _stopTask = Task.FromException(_state.ConfiguredDisposeFailure);
                    return _stopTask;
                }

                if (_state.CompleteProcessOnStop)
                {
                    _state.ProcessCompletion.TrySetResult(new BrokerGuardianProcessExitV1(
                        checked((uint)_state.Identity.ProcessId),
                        0,
                        BrokerGuardianProcessStopRequestV1.None));
                }

                _stopTask = Task.CompletedTask;
                return _stopTask;
            }
        }

        public void Dispose() =>
            StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)
                .GetAwaiter()
                .GetResult();

        public ValueTask DisposeAsync() =>
            new(StopAsync(BrokerGuardianProcessStopRequestV1.Disposal));

        internal void SetRevalidationSequence(params WindowsProcessIdentity[] identities)
        {
            lock (_state.Gate)
            {
                if (_state.ResourceDisposed)
                {
                    throw new ObjectDisposedException(nameof(TestBrokerOwnedGuardianProcessLease));
                }

                _state.Revalidations.Clear();
                foreach (var identity in identities)
                {
                    _state.Revalidations.Enqueue(identity);
                }
            }
        }

        internal void CompleteProcessExit(uint exitCode) =>
            _state.ProcessCompletion.TrySetResult(new BrokerGuardianProcessExitV1(
                checked((uint)_state.Identity.ProcessId),
                exitCode,
                BrokerGuardianProcessStopRequestV1.None));

        internal void FaultProcessObservation(Exception failure)
        {
            ArgumentNullException.ThrowIfNull(failure);
            _state.ProcessCompletion.TrySetException(failure);
        }

        internal void CancelProcessObservation() =>
            _state.ProcessCompletion.TrySetCanceled();

        private T Read<T>(T value)
        {
            lock (_state.Gate)
            {
                EnsureOwned();
                return value;
            }
        }

        private void EnsureOwned()
        {
            if (!_owns || _state.ResourceDisposed)
            {
                throw new ObjectDisposedException(nameof(TestBrokerOwnedGuardianProcessLease));
            }
        }

        private sealed class SharedState
        {
            internal SharedState(
                WindowsProcessIdentity identity,
                bool cleanEnvironmentVerified,
                bool runtimeNamespaceClosed,
                Exception? configuredDisposeFailure,
                bool completeProcessOnStop,
                Action? stopStartedObserver)
            {
                Identity = identity;
                CleanEnvironmentVerified = cleanEnvironmentVerified;
                RuntimeNamespaceClosed = runtimeNamespaceClosed;
                ConfiguredDisposeFailure = configuredDisposeFailure;
                CompleteProcessOnStop = completeProcessOnStop;
                StopStartedObserver = stopStartedObserver;
            }

            internal object Gate { get; } = new();

            internal WindowsProcessIdentity Identity { get; }

            internal bool CleanEnvironmentVerified { get; }

            internal bool RuntimeNamespaceClosed { get; }

            internal Exception? ConfiguredDisposeFailure { get; }

            internal bool CompleteProcessOnStop { get; }

            internal Action? StopStartedObserver { get; }

            internal Queue<WindowsProcessIdentity> Revalidations { get; } = new();

            internal TaskCompletionSource<BrokerGuardianProcessExitV1> ProcessCompletion { get; } =
                new(TaskCreationOptions.RunContinuationsAsynchronously);

            internal TaskCompletionSource StopStarted { get; } =
                new(TaskCreationOptions.RunContinuationsAsynchronously);

            internal int DisposeCount { get; set; }

            internal BrokerGuardianProcessStopRequestV1? LastStopRequest { get; set; }

            internal bool ResourceDisposed { get; set; }
        }
    }
}
