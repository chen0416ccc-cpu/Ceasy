using CodexGuardian.Broker;
using CodexGuardian.Control;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

internal static class BrokerConsentLedgerStoreOfflineTests
{
    internal const string ChildProbeArgument = "--broker-consent-ledger-store-child";
    internal const string TestDataRootArgument = "--broker-consent-ledger-store-test-data-root";
    private const string HoldLockMode = "hold-lock";
    private const string CrashWriteMode = "crash-write";
    private const string CrashScenarioArgument = "--broker-consent-ledger-store-crash-scenario";
    private const string CrashFaultPointArgument = "--broker-consent-ledger-store-fault-point";
    private const string LockReadyMarker = "BROKER_CONSENT_LEDGER_STORE_LOCK_READY";
    private const string CrashMarkerPrefix = "BROKER_CONSENT_LEDGER_STORE_CRASH_POINT=";
    private const string PrimaryFileName = "broker-consent-ledger.json";
    private const string PreviousFileName = "broker-consent-ledger.previous.json";
    private const string LockFileName = ".broker-consent-ledger.lock";
    private static readonly Guid LedgerId =
        Guid.ParseExact("01234567-89ab-cdef-0123-456789abcdef", "D");
    private static readonly Guid OtherLedgerId =
        Guid.ParseExact("fedcba98-7654-3210-fedc-ba9876543210", "D");
    private static readonly Guid ReceiptId =
        Guid.ParseExact("11111111-2222-3333-4444-555555555555", "D");
    private const long IssuedAtUtcTicks = 638900000000000000;
    private const long RevokedAtUtcTicks = 638900000100000000;
    private const BindingFlags InstanceFlags =
        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;

    internal static bool IsChildProbeInvocation(IReadOnlyList<string> arguments) =>
        arguments.Contains(ChildProbeArgument, StringComparer.Ordinal);

    internal static int RunChildProbe(IReadOnlyList<string> arguments)
    {
        try
        {
            var childIndex = FindUniqueArgument(arguments, ChildProbeArgument);
            Ensure(childIndex + 1 < arguments.Count, "the Store child mode is missing");
            var mode = arguments[childIndex + 1];
            var testDataRoot = ReadRequiredTestDataRoot(arguments);
            if (string.Equals(mode, HoldLockMode, StringComparison.Ordinal))
            {
                using var store = OpenStore(testDataRoot);
                Console.WriteLine(LockReadyMarker);
                Console.Out.Flush();
                _ = Console.ReadLine();
                return 0;
            }

            if (string.Equals(mode, CrashWriteMode, StringComparison.Ordinal))
            {
                var scenario = ReadRequiredArgumentValue(arguments, CrashScenarioArgument);
                var faultPoint = ReadRequiredArgumentValue(arguments, CrashFaultPointArgument);
                var definition = CreateCrashScenario(scenario);
                using var store = OpenStore(testDataRoot, point =>
                {
                    if (!string.Equals(point, faultPoint, StringComparison.Ordinal))
                    {
                        return;
                    }

                    Console.WriteLine(CrashMarkerPrefix + point);
                    Console.Out.Flush();
                    Process.GetCurrentProcess().Kill(entireProcessTree: false);
                    Environment.Exit(197);
                });
                _ = store.Write(definition.Candidate);
                Console.Error.WriteLine("The Store crash fault point was not reached.");
                return 3;
            }

            throw new InvalidOperationException("the Store child mode is unsupported");
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.GetType().Name + ": " + exception.Message);
            return 2;
        }
    }

    internal static async Task RunAsync(
        IReadOnlyList<string> arguments,
        Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "Broker consent ledger durable store contract exists",
            () => TestContractExists(arguments),
            assert);
        await RunCaseAsync(
            "Broker consent ledger durable store is atomic bounded exclusive and zero-authority",
            () => TestDurableStoreAsync(arguments),
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Broker consent ledger native paths survive legacy MAX_PATH limits",
            () => TestLongNativePathsAsync(arguments),
            assert).ConfigureAwait(false);
        RunCase(
            "Broker consent ledger Store orphan cleanup is strict bounded and never promoted",
            () => TestOrphanCleanup(arguments),
            assert);
        await RunCaseAsync(
            "Broker consent ledger durable store crash matrix resolves exact old new or quarantine",
            () => TestCrashMatrixAsync(arguments),
            assert).ConfigureAwait(false);
    }

    private static void TestContractExists(IReadOnlyList<string> arguments)
    {
        var testDataRoot = ReadRequiredTestDataRoot(arguments);
        var sourceRoot = Directory.GetCurrentDirectory();
        Ensure(
            !IsSameOrDescendant(testDataRoot, sourceRoot),
            "the Broker consent ledger test-data root entered the authoritative source tree");
        var liveDataRoot = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CodexGuardian"));
        Ensure(
            !IsSameOrDescendant(testDataRoot, liveDataRoot),
            "the Broker consent ledger tests targeted live Guardian data");

        var storePath = Path.Combine(
            sourceRoot,
            "work",
            "CodexGuardian.Broker",
            "BrokerConsentLedgerStore.cs");
        Ensure(File.Exists(storePath), "the Broker consent ledger store source is missing");
        var source = File.ReadAllText(storePath);
        Ensure(
            source.Contains(
                "internal sealed class BrokerConsentLedgerStore",
                StringComparison.Ordinal),
            "the Broker consent ledger store type is missing");
    }

    private static async Task TestDurableStoreAsync(IReadOnlyList<string> arguments)
    {
        var testDataRoot = ReadRequiredTestDataRoot(arguments);
        Directory.CreateDirectory(testDataRoot);
        AssertTypeContract();
        AssertSourceContract();

        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generationA = CreateGeneration("generation-a");
        var grantA = BrokerWebAuthnTestVectorsV1.CreateParsedGrant(
            genesis,
            0,
            generationA,
            ReceiptId,
            BrokerWebAuthnTestVectorsV1.CredentialId(),
            BrokerWebAuthnTestVectorsV1.Nonce(),
            IssuedAtUtcTicks);
        var generationB = CreateGeneration("generation-b");
        var grantB = BrokerWebAuthnTestVectorsV1.CreateParsedGrant(
            grantA,
            1,
            generationB,
            Guid.ParseExact("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "D"),
            BrokerWebAuthnTestVectorsV1.CredentialId(),
            BrokerWebAuthnTestVectorsV1.Nonce(0x50),
            IssuedAtUtcTicks + 1);
        var revoke = BrokerConsentLedgerTransition.CreateRevoke(
            grantB,
            2,
            BrokerConsentRevokeReasonV1.PackageChanged,
            RevokedAtUtcTicks);

        var normalRoot = CreateCaseRoot(testDataRoot, "normal");
        string primaryPath;
        string previousPath;
        string lockPath;
        byte[] rollbackPrimary;
        byte[] rollbackPrevious;
        using (var store = OpenStore(normalRoot))
        {
            primaryPath = store.GetString("PrimaryPath");
            previousPath = store.GetString("PreviousPath");
            lockPath = store.GetString("LockPath");
            Ensure(
                string.Equals(primaryPath, Path.Combine(normalRoot, PrimaryFileName), StringComparison.OrdinalIgnoreCase) &&
                string.Equals(previousPath, Path.Combine(normalRoot, PreviousFileName), StringComparison.OrdinalIgnoreCase) &&
                string.Equals(lockPath, Path.Combine(normalRoot, LockFileName), StringComparison.OrdinalIgnoreCase),
                "the Store paths are not fixed beneath the data directory");

            AssertSnapshot(
                store.Read(),
                "NoAuthority",
                expectedDocument: null,
                primaryReplica: "Missing",
                previousReplica: "Missing");
            AssertWrite(
                store.Write(genesis),
                "Written",
                "HealthyGenesis",
                genesis,
                "Canonical",
                "Missing");
            Ensure(
                File.ReadAllBytes(primaryPath).AsSpan().SequenceEqual(JsonBytes(genesis)) &&
                !File.Exists(previousPath) &&
                File.Exists(lockPath),
                "the first genesis publish did not create the exact primary-only shape");
            AssertNoTemporaryFiles(normalRoot);

            File.SetLastWriteTimeUtc(primaryPath, new DateTime(637134336000000000, DateTimeKind.Utc));
            var replayBefore = CaptureFile(primaryPath);
            AssertWrite(
                store.Write(genesis),
                "Unchanged",
                "HealthyGenesis",
                genesis,
                "Canonical",
                "Missing");
            Ensure(
                replayBefore == CaptureFile(primaryPath) && !File.Exists(previousPath),
                "an exact replay rewrote the ledger");

            var conflictBefore = CaptureFile(primaryPath);
            AssertWriteState(
                store.Write(BrokerConsentLedgerTransition.CreateGenesis(OtherLedgerId)),
                "Conflict");
            Ensure(
                conflictBefore == CaptureFile(primaryPath) && !File.Exists(previousPath),
                "a conflicting genesis changed the ledger");

            AssertWrite(
                store.Write(grantA),
                "Written",
                "ReceiptPendingVerification",
                grantA,
                "Canonical",
                "Canonical");
            Ensure(
                File.ReadAllBytes(primaryPath).AsSpan().SequenceEqual(JsonBytes(grantA)) &&
                File.ReadAllBytes(previousPath).AsSpan().SequenceEqual(JsonBytes(genesis)),
                "the first grant did not retain exact genesis as previous");
            rollbackPrimary = File.ReadAllBytes(primaryPath);
            rollbackPrevious = File.ReadAllBytes(previousPath);

            AssertWrite(
                store.Write(grantB),
                "Written",
                "ReceiptPendingVerification",
                grantB,
                "Canonical",
                "Canonical");
            Ensure(
                File.ReadAllBytes(primaryPath).AsSpan().SequenceEqual(JsonBytes(grantB)) &&
                File.ReadAllBytes(previousPath).AsSpan().SequenceEqual(JsonBytes(grantA)),
                "grant supersession did not retain exact prior grant");
            AssertWrite(
                store.Write(revoke),
                "Written",
                "NoAuthority",
                revoke,
                "Canonical",
                "Canonical");
            Ensure(
                File.ReadAllBytes(primaryPath).AsSpan().SequenceEqual(JsonBytes(revoke)) &&
                File.ReadAllBytes(previousPath).AsSpan().SequenceEqual(JsonBytes(grantB)),
                "revoke did not retain exact prior grant as diagnostic previous");
            AssertNoTemporaryFiles(normalRoot);
        }

        File.Delete(primaryPath);
        using (var store = OpenStore(normalRoot))
        {
            AssertQuarantined(store.Read(), "a missing primary exposed previous grant data");
        }

        AssertQuarantinedPair(testDataRoot, "previous-only", null, JsonBytes(genesis));
        AssertQuarantinedPair(testDataRoot, "genesis-with-previous", JsonBytes(genesis), JsonBytes(genesis));
        AssertQuarantinedPair(testDataRoot, "grant-without-previous", JsonBytes(grantA), null);
        AssertQuarantinedPair(
            testDataRoot,
            "mismatched-ledger",
            JsonBytes(grantA),
            JsonBytes(BrokerConsentLedgerTransition.CreateGenesis(OtherLedgerId)));
        AssertQuarantinedPair(testDataRoot, "empty-primary", Array.Empty<byte>(), null);
        AssertQuarantinedPair(
            testDataRoot,
            "oversized-primary",
            new byte[BrokerConsentLedgerV1.MaximumDocumentBytes + 1],
            null);
        AssertQuarantinedPair(
            testDataRoot,
            "bom-primary",
            new byte[] { 0xEF, 0xBB, 0xBF }.Concat(JsonBytes(genesis)).ToArray(),
            null);
        AssertQuarantinedPair(
            testDataRoot,
            "noncanonical-primary",
            Encoding.UTF8.GetBytes(" " + Encoding.UTF8.GetString(JsonBytes(genesis))),
            null);
        AssertQuarantinedPair(
            testDataRoot,
            "invalid-previous",
            JsonBytes(grantA),
            Encoding.UTF8.GetBytes("{}"));

        var hardLinkRoot = CreateCaseRoot(testDataRoot, "hard-link");
        var hardLinkPrimary = Path.Combine(hardLinkRoot, PrimaryFileName);
        WriteReplica(hardLinkPrimary, JsonBytes(genesis));
        var hardLinkAlias = Path.Combine(hardLinkRoot, "primary-hard-link.json");
        if (!CreateHardLinkW(hardLinkAlias, hardLinkPrimary, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the Store hard-link fixture.");
        }
        using (var store = OpenStore(hardLinkRoot))
        {
            AssertQuarantined(store.Read(), "a hard-linked primary was accepted");
        }

        var junctionTarget = CreateCaseRoot(testDataRoot, "junction-target");
        var junctionPath = Path.Combine(testDataRoot, "junction-" + Guid.NewGuid().ToString("N"));
        CreateJunction(junctionPath, junctionTarget);
        ExpectStoreCode(() => OpenStore(junctionPath), "consent-ledger-store-path-invalid");
        ExpectStoreCode(
            () => OpenStore(@"\\?\" + CreateCaseRoot(testDataRoot, "device-alias")),
            "consent-ledger-store-path-invalid");
        ExpectStoreCode(
            () => OpenStore(@"\\.\" + CreateCaseRoot(testDataRoot, "dos-device-alias")),
            "consent-ledger-store-path-invalid");
        ExpectStoreCode(
            () => OpenStore(@"\\server\share\broker-consent-ledger"),
            "consent-ledger-store-path-invalid");
        ExpectStoreCode(
            () => OpenStore(CreateCaseRoot(testDataRoot, "ads-alias") + ":stream"),
            "consent-ledger-store-path-invalid");
        var sessionsCandidate = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "sessions",
            "broker-ledger-store-" + Guid.NewGuid().ToString("N"));
        ExpectStoreCode(
            () => OpenStore(sessionsCandidate),
            "consent-ledger-store-path-invalid");

        await AssertCrossProcessLockAsync(testDataRoot).ConfigureAwait(false);

        var rollbackRoot = CreateCaseRoot(testDataRoot, "coherent-rollback");
        WriteReplica(Path.Combine(rollbackRoot, PrimaryFileName), rollbackPrimary);
        WriteReplica(Path.Combine(rollbackRoot, PreviousFileName), rollbackPrevious);
        using (var store = OpenStore(rollbackRoot))
        {
            AssertSnapshot(
                store.Read(),
                "ReceiptPendingVerification",
                grantA,
                "Canonical",
                "Canonical");
        }

        AssertZeroAuthorityBoundary();
        AssertReleaseClosure();
    }

    private static async Task TestLongNativePathsAsync(IReadOnlyList<string> arguments)
    {
        var testDataRoot = ReadRequiredTestDataRoot(arguments);
        var root = CreateCaseRoot(testDataRoot, "long-native-path");
        while (root.Length < 270 ||
               Path.Combine(root, StrictOrphanName(4001, 1)).Length < 300)
        {
            root = Path.Combine(root, "segment-" + new string('x', 64));
            Directory.CreateDirectory(root);
        }

        var toExtendedLocalPath = typeof(BrokerConsentLedgerStore).GetMethod(
            "ToExtendedLocalPath",
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new InvalidOperationException("the native long-path boundary helper is missing");
        Ensure(
            string.Equals(
                (string?)toExtendedLocalPath.Invoke(null, new object[] { root }),
                @"\\?\" + root,
                StringComparison.Ordinal),
            "the native long-path boundary did not preserve the canonical local path");
        try
        {
            _ = toExtendedLocalPath.Invoke(null, new object[] { root + ":stream" });
            throw new InvalidOperationException("the native long-path boundary accepted an ADS path");
        }
        catch (TargetInvocationException exception) when (exception.InnerException is IOException)
        {
        }

        var crash = await RunCrashChildAsync(
                root,
                "first-genesis",
                "TemporaryCreated")
            .ConfigureAwait(false);
        Ensure(
            crash.ExitCode != 0 &&
            crash.Output.Contains(
                CrashMarkerPrefix + "TemporaryCreated",
                StringComparison.Ordinal),
            "the long-path crash child did not prove temporary creation");
        var crashOrphans = Directory.EnumerateFiles(root)
            .Where(path => Path.GetFileName(path).StartsWith(
                ".broker-consent-ledger.json.tmp-",
                StringComparison.Ordinal))
            .ToArray();
        Ensure(
            crashOrphans.Length == 1 && crashOrphans[0].Length >= 300,
            "the long-path crash child did not leave one bounded strict orphan");
        using (var resolved = OpenStore(root))
        {
            AssertSnapshot(resolved.Read(), "NoAuthority", null, "Missing", "Missing");
        }
        AssertNoTemporaryFiles(root);

        var definition = CreateCrashScenario("genesis-to-grant");
        string primaryPath;
        string previousPath;
        string lockPath;
        using (var store = OpenStore(root))
        {
            var dataDirectory = store.GetString("DataDirectory");
            primaryPath = store.GetString("PrimaryPath");
            previousPath = store.GetString("PreviousPath");
            lockPath = store.GetString("LockPath");
            Ensure(
                !dataDirectory.StartsWith(@"\\?\", StringComparison.Ordinal) &&
                !primaryPath.StartsWith(@"\\?\", StringComparison.Ordinal) &&
                !previousPath.StartsWith(@"\\?\", StringComparison.Ordinal) &&
                !lockPath.StartsWith(@"\\?\", StringComparison.Ordinal),
                "the Store exposed an internal extended-length path");
            Ensure(
                string.Equals(dataDirectory, root, StringComparison.OrdinalIgnoreCase) &&
                dataDirectory.Length >= 260 &&
                primaryPath.Length >= 260 &&
                lockPath.Length >= 260,
                "the long native-path fixture did not cross the legacy MAX_PATH boundary");
            AssertWriteState(store.Write(definition.Setup.Single()), "Written");
            AssertWriteState(store.Write(definition.Candidate), "Written");
        }

        var orphanPath = Path.Combine(root, StrictOrphanName(4001, 1));
        Ensure(
            orphanPath.Length >= 300,
            "the long orphan fixture did not exercise an extended-length native path");
        WriteReplica(orphanPath, Array.Empty<byte>());
        using (var reopened = OpenStore(root))
        {
            AssertResolvedCrashSnapshot(reopened.Read(), definition.Candidate);
        }
        Ensure(!File.Exists(orphanPath), "the long-path orphan was not removed by retained handle");
        AssertNoTemporaryFiles(root);
    }

    private static void TestOrphanCleanup(IReadOnlyList<string> arguments)
    {
        var testDataRoot = ReadRequiredTestDataRoot(arguments);
        var cleanupRoot = CreateCaseRoot(testDataRoot, "orphan-cleanup");
        var orphanEmpty = Path.Combine(cleanupRoot, StrictOrphanName(1001, 1));
        var orphanPartial = Path.Combine(cleanupRoot, StrictOrphanName(1002, 2));
        var unrelated = Path.Combine(
            cleanupRoot,
            ".broker-consent-ledger.json.tmp-unrelated.keep");
        WriteReplica(orphanEmpty, Array.Empty<byte>());
        WriteReplica(orphanPartial, new byte[] { 0x7B });
        WriteReplica(unrelated, new byte[] { 0x55 });
        using (var store = OpenStore(cleanupRoot))
        {
            AssertSnapshot(store.Read(), "NoAuthority", null, "Missing", "Missing");
        }
        Ensure(
            !File.Exists(orphanEmpty) &&
            !File.Exists(orphanPartial) &&
            File.Exists(unrelated),
            "strict orphan cleanup deleted the wrong file or retained Store-owned temp files");

        var limitRoot = CreateCaseRoot(testDataRoot, "orphan-limit");
        for (var index = 0; index < 33; index++)
        {
            WriteReplica(
                Path.Combine(limitRoot, StrictOrphanName(2000 + index, index + 1)),
                Array.Empty<byte>());
        }
        ExpectStoreCode(
            () =>
            {
                using var store = OpenStore(limitRoot);
            },
            "consent-ledger-store-orphan-limit");
        Ensure(
            Directory.EnumerateFiles(limitRoot)
                .Count(path => Path.GetFileName(path).StartsWith(
                    ".broker-consent-ledger.json.tmp-",
                    StringComparison.Ordinal)) == 33,
            "the over-limit orphan set was partially deleted before fail-closed rejection");

        var hardLinkRoot = CreateCaseRoot(testDataRoot, "orphan-hard-link");
        var hardLinkedOrphan = Path.Combine(hardLinkRoot, StrictOrphanName(3001, 1));
        WriteReplica(hardLinkedOrphan, new byte[] { 0x7B });
        var hardLinkAlias = Path.Combine(hardLinkRoot, "orphan-hard-link-alias.tmp");
        if (!CreateHardLinkW(hardLinkAlias, hardLinkedOrphan, IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to create the orphan hard-link fixture.");
        }
        ExpectStoreCode(
            () =>
            {
                using var store = OpenStore(hardLinkRoot);
            },
            "consent-ledger-store-orphan-invalid");
        Ensure(
            File.Exists(hardLinkedOrphan) && File.Exists(hardLinkAlias),
            "unsafe orphan cleanup deleted a hard-linked file");
    }

    private static string StrictOrphanName(int processId, int ordinal) =>
        ".broker-consent-ledger.json.tmp-" +
        processId.ToString(System.Globalization.CultureInfo.InvariantCulture) +
        "-" +
        ordinal.ToString("x32", System.Globalization.CultureInfo.InvariantCulture);

    private static async Task TestCrashMatrixAsync(IReadOnlyList<string> arguments)
    {
        var testDataRoot = ReadRequiredTestDataRoot(arguments);
        AssertCrashTypeContract();
        var faultPoints = new[]
        {
            "TemporaryCreated",
            "PartialWrite",
            "FullWrite",
            "FileFlushed",
            "TemporaryReadbackVerified",
            "BeforePublish",
            "AfterPublish",
            "DirectoryBarrierCompleted",
            "BeforeInMemoryCommit"
        };
        var scenarios = new[]
        {
            "first-genesis",
            "genesis-to-grant",
            "grant-to-revoke",
            "grant-a-to-grant-b"
        };
        var childIdentities = new HashSet<string>(StringComparer.Ordinal);
        var completedCases = 0;

        foreach (var scenarioName in scenarios)
        {
            foreach (var faultPoint in faultPoints)
            {
                var definition = CreateCrashScenario(scenarioName);
                var root = CreateCaseRoot(
                    testDataRoot,
                    "crash-" + scenarioName + "-" + faultPoint.ToLowerInvariant());
                if (definition.Setup.Count > 0)
                {
                    using var setupStore = OpenStore(root);
                    foreach (var document in definition.Setup)
                    {
                        AssertWriteState(setupStore.Write(document), "Written");
                    }
                }

                var primaryPath = Path.Combine(root, PrimaryFileName);
                var previousPath = Path.Combine(root, PreviousFileName);
                var oldPrimary = ReadOptionalBytes(primaryPath);
                var oldPrevious = ReadOptionalBytes(previousPath);
                var child = await RunCrashChildAsync(
                        root,
                        scenarioName,
                        faultPoint)
                    .ConfigureAwait(false);
                Ensure(
                    childIdentities.Add(
                        child.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                        ":" +
                        child.StartTimeUtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                    "the crash matrix reused a child process identity");
                Ensure(
                    child.Output.Contains(
                        CrashMarkerPrefix + faultPoint,
                        StringComparison.Ordinal),
                    "the crash child did not prove the requested fault point: " + child.Output + child.Error);
                Ensure(child.ExitCode != 0, "the crash child exited normally at " + faultPoint);

                var published = faultPoint is
                    "AfterPublish" or
                    "DirectoryBarrierCompleted" or
                    "BeforeInMemoryCommit";
                var expectedPrimary = published
                    ? JsonBytes(definition.Candidate)
                    : oldPrimary;
                var expectedPrevious = published && oldPrimary is not null
                    ? oldPrimary
                    : oldPrevious;
                Ensure(
                    OptionalBytesEqual(ReadOptionalBytes(primaryPath), expectedPrimary),
                    "the crash matrix primary was neither exact old nor exact new");
                Ensure(
                    OptionalBytesEqual(ReadOptionalBytes(previousPath), expectedPrevious),
                    "the crash matrix previous was mixed or advanced independently");

                using var resolvedStore = OpenStore(root);
                AssertResolvedCrashSnapshot(
                    resolvedStore.Read(),
                    published ? definition.Candidate : definition.OldPrimary);
                if (published)
                {
                    var primaryBeforeReplay = CaptureFile(primaryPath);
                    var previousBeforeReplay = oldPrimary is null
                        ? null
                        : CaptureFile(previousPath);
                    AssertWriteState(resolvedStore.Write(definition.Candidate), "Unchanged");
                    Ensure(
                        primaryBeforeReplay == CaptureFile(primaryPath) &&
                        (previousBeforeReplay is null ||
                         previousBeforeReplay == CaptureFile(previousPath)),
                        "a post-publish replay rewrote an already committed candidate");
                }

                var storeTemporaryFiles = Directory.EnumerateFiles(root)
                    .Where(path => Path.GetFileName(path).StartsWith(
                        ".broker-consent-ledger.json.tmp-",
                        StringComparison.Ordinal))
                    .ToArray();
                Ensure(
                    storeTemporaryFiles.Length <= 1,
                    "a crash case produced an unbounded temporary-file set");
                if (published)
                {
                    Ensure(
                        storeTemporaryFiles.Length == 0,
                        "a published crash case retained a temporary authority candidate");
                }
                completedCases++;
            }
        }
        Ensure(
            completedCases == 36 && childIdentities.Count == 36,
            "the crash matrix did not complete 36 unique child-process cases");
    }

    private static void AssertCrashTypeContract()
    {
        var assembly = typeof(BrokerConsentLedgerStore).Assembly;
        var faultPointType = RequireType(assembly, "BrokerConsentLedgerStoreFaultPointV1");
        AssertEnum(
            faultPointType,
            "TemporaryCreated",
            "PartialWrite",
            "FullWrite",
            "FileFlushed",
            "TemporaryReadbackVerified",
            "BeforePublish",
            "AfterPublish",
            "DirectoryBarrierCompleted",
            "BeforeInMemoryCommit");
        var callbackType = typeof(Action<>).MakeGenericType(faultPointType);
        Ensure(
            typeof(BrokerConsentLedgerStore).GetConstructor(
                InstanceFlags,
                binder: null,
                new[] { typeof(string), callbackType },
                modifiers: null) is not null,
            "the Store crash-only fault callback constructor is missing");
    }

    private static CrashScenario CreateCrashScenario(string name)
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var grantA = BrokerWebAuthnTestVectorsV1.CreateParsedGrant(
            genesis,
            0,
            CreateGeneration("generation-a"),
            ReceiptId,
            BrokerWebAuthnTestVectorsV1.CredentialId(),
            BrokerWebAuthnTestVectorsV1.Nonce(),
            IssuedAtUtcTicks);
        var grantB = BrokerWebAuthnTestVectorsV1.CreateParsedGrant(
            grantA,
            1,
            CreateGeneration("generation-b"),
            Guid.ParseExact("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "D"),
            BrokerWebAuthnTestVectorsV1.CredentialId(),
            BrokerWebAuthnTestVectorsV1.Nonce(0x50),
            IssuedAtUtcTicks + 1);
        var revoke = BrokerConsentLedgerTransition.CreateRevoke(
            grantA,
            1,
            BrokerConsentRevokeReasonV1.PackageChanged,
            RevokedAtUtcTicks);
        return name switch
        {
            "first-genesis" => new CrashScenario(
                name,
                Array.Empty<BrokerConsentLedgerDocumentV1>(),
                null,
                genesis),
            "genesis-to-grant" => new CrashScenario(
                name,
                new[] { genesis },
                genesis,
                grantA),
            "grant-to-revoke" => new CrashScenario(
                name,
                new[] { genesis, grantA },
                grantA,
                revoke),
            "grant-a-to-grant-b" => new CrashScenario(
                name,
                new[] { genesis, grantA },
                grantA,
                grantB),
            _ => throw new InvalidOperationException("Unsupported Store crash scenario " + name + ".")
        };
    }

    private static void AssertResolvedCrashSnapshot(
        object snapshot,
        BrokerConsentLedgerDocumentV1? expected)
    {
        if (expected is null)
        {
            AssertSnapshot(snapshot, "NoAuthority", null, "Missing", "Missing");
            return;
        }

        var state = expected.Entry switch
        {
            BrokerConsentGenesisEntryV1 => "HealthyGenesis",
            BrokerConsentGrantEntryV1 => "ReceiptPendingVerification",
            BrokerConsentRevokeEntryV1 => "NoAuthority",
            _ => throw new InvalidOperationException("Unsupported resolved crash entry.")
        };
        AssertSnapshot(
            snapshot,
            state,
            expected,
            "Canonical",
            expected.Entry is BrokerConsentGenesisEntryV1 ? "Missing" : "Canonical");
    }

    private static async Task<CrashChildResult> RunCrashChildAsync(
        string root,
        string scenario,
        string faultPoint)
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "CodexGuardian.Tests.exe");
        Ensure(File.Exists(executable), "the fresh Tests apphost is unavailable for the crash matrix");
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Directory.GetCurrentDirectory()
        };
        startInfo.ArgumentList.Add(ChildProbeArgument);
        startInfo.ArgumentList.Add(CrashWriteMode);
        startInfo.ArgumentList.Add(TestDataRootArgument);
        startInfo.ArgumentList.Add(root);
        startInfo.ArgumentList.Add(CrashScenarioArgument);
        startInfo.ArgumentList.Add(scenario);
        startInfo.ArgumentList.Add(CrashFaultPointArgument);
        startInfo.ArgumentList.Add(faultPoint);

        using var process = Process.Start(startInfo) ??
            throw new InvalidOperationException("Unable to start the Store crash child.");
        var processId = process.Id;
        var startTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks;
        try
        {
            await process.WaitForExitAsync()
                .WaitAsync(TimeSpan.FromSeconds(20))
                .ConfigureAwait(false);
            var output = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
            var error = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
            return new CrashChildResult(
                process.ExitCode,
                processId,
                startTimeUtcTicks,
                output,
                error);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync().ConfigureAwait(false);
            }
        }
    }

    private static byte[]? ReadOptionalBytes(string path) =>
        File.Exists(path) ? File.ReadAllBytes(path) : null;

    private static bool OptionalBytesEqual(byte[]? first, byte[]? second) =>
        first is null
            ? second is null
            : second is not null && first.AsSpan().SequenceEqual(second);

    private static void AssertTypeContract()
    {
        var assembly = typeof(BrokerConsentLedgerStore).Assembly;
        AssertEnum(
            RequireType(assembly, "BrokerConsentLedgerStoreStateV1"),
            "NoAuthority",
            "HealthyGenesis",
            "ReceiptPendingVerification",
            "Quarantined");
        AssertEnum(
            RequireType(assembly, "BrokerConsentLedgerStoreWriteStateV1"),
            "Written",
            "Unchanged",
            "Conflict",
            "Quarantined");
        AssertEnum(
            RequireType(assembly, "BrokerConsentLedgerReplicaStateV1"),
            "Missing",
            "Canonical",
            "Invalid");
        _ = RequireType(assembly, "BrokerConsentLedgerStoreDiagnosticsV1");
        _ = RequireType(assembly, "BrokerConsentLedgerStoreSnapshotV1");
        _ = RequireType(assembly, "BrokerConsentLedgerStoreWriteResultV1");
        var exceptionType = RequireType(assembly, "BrokerConsentLedgerStoreException");
        Ensure(
            exceptionType.GetProperty("Code", InstanceFlags) is not null,
            "the Store exception has no fixed diagnostic code");
        Ensure(
            typeof(IDisposable).IsAssignableFrom(typeof(BrokerConsentLedgerStore)),
            "the Store does not retain and dispose its lifecycle lock");
        Ensure(
            typeof(BrokerConsentLedgerStore).GetConstructor(
                InstanceFlags,
                binder: null,
                new[] { typeof(string) },
                modifiers: null) is not null,
            "the Store has no explicit data-directory constructor");
        Ensure(
            typeof(BrokerConsentLedgerStore).GetMethod(
                "Read",
                InstanceFlags,
                binder: null,
                Type.EmptyTypes,
                modifiers: null) is not null,
            "the Store Read contract is missing");
        Ensure(
            typeof(BrokerConsentLedgerStore).GetMethod(
                "Write",
                InstanceFlags,
                binder: null,
                new[] { typeof(BrokerConsentLedgerDocumentV1) },
                modifiers: null) is not null,
            "the Store Write contract is missing");
    }

    private static void AssertSourceContract()
    {
        var storePath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian.Broker",
            "BrokerConsentLedgerStore.cs");
        var source = File.ReadAllText(storePath);
        foreach (var required in new[]
        {
            "FileMode.CreateNew",
            "FileShare.None",
            "FileOptions.WriteThrough",
            "Flush(flushToDisk: true)",
            "RandomAccess.Read",
            "GetFileInformationByHandleEx",
            "GetFinalPathNameByHandleW",
            "MoveFileExW",
            "File.Replace(",
            "FlushFileBuffers",
            "NumberOfLinks != 1",
            "DeletePending"
        })
        {
            Ensure(source.Contains(required, StringComparison.Ordinal), "Store source is missing " + required);
        }
        Ensure(
            !source.Contains("File.ReadAllBytes", StringComparison.Ordinal) &&
            !source.Contains("new FileInfo", StringComparison.Ordinal) &&
            !source.Contains("File.Exists", StringComparison.Ordinal),
            "the Store uses path-based prechecks instead of retained-handle reads");
    }

    private static async Task AssertCrossProcessLockAsync(string testDataRoot)
    {
        var root = CreateCaseRoot(testDataRoot, "cross-process-lock");
        var executable = Path.Combine(AppContext.BaseDirectory, "CodexGuardian.Tests.exe");
        Ensure(File.Exists(executable), "the fresh Tests apphost is unavailable for the Store lock probe");
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Directory.GetCurrentDirectory()
        };
        startInfo.ArgumentList.Add(ChildProbeArgument);
        startInfo.ArgumentList.Add(HoldLockMode);
        startInfo.ArgumentList.Add(TestDataRootArgument);
        startInfo.ArgumentList.Add(root);

        using var child = Process.Start(startInfo) ??
            throw new InvalidOperationException("Unable to start the Store lock child.");
        try
        {
            var marker = await child.StandardOutput.ReadLineAsync()
                .WaitAsync(TimeSpan.FromSeconds(20))
                .ConfigureAwait(false);
            Ensure(
                string.Equals(marker, LockReadyMarker, StringComparison.Ordinal),
                "the Store lock child did not reach readiness: " + marker);
            ExpectStoreCode(() => OpenStore(root), "consent-ledger-store-locked");
            await child.StandardInput.WriteLineAsync().ConfigureAwait(false);
            await child.StandardInput.FlushAsync().ConfigureAwait(false);
            await child.WaitForExitAsync()
                .WaitAsync(TimeSpan.FromSeconds(20))
                .ConfigureAwait(false);
            var error = await child.StandardError.ReadToEndAsync().ConfigureAwait(false);
            Ensure(child.ExitCode == 0, "the Store lock child failed: " + error);
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                await child.WaitForExitAsync().ConfigureAwait(false);
            }
        }
    }

    private static void AssertQuarantinedPair(
        string testDataRoot,
        string name,
        byte[]? primary,
        byte[]? previous)
    {
        var root = CreateCaseRoot(testDataRoot, name);
        if (primary is not null)
        {
            WriteReplica(Path.Combine(root, PrimaryFileName), primary);
        }
        if (previous is not null)
        {
            WriteReplica(Path.Combine(root, PreviousFileName), previous);
        }
        using var store = OpenStore(root);
        AssertQuarantined(store.Read(), name + " was not quarantined");
    }

    private static void AssertQuarantined(object snapshot, string message)
    {
        Ensure(ReadEnum(snapshot, "State") == "Quarantined", message);
        Ensure(GetProperty(snapshot, "Primary") is null, "a quarantined Store exposed primary data");
        var diagnostics = GetRequiredProperty(snapshot, "Diagnostics");
        Ensure(
            !string.IsNullOrWhiteSpace(GetStringProperty(diagnostics, "Code")),
            "a quarantined Store omitted its bounded diagnostic code");
    }

    private static void AssertSnapshot(
        object snapshot,
        string state,
        BrokerConsentLedgerDocumentV1? expectedDocument,
        string primaryReplica,
        string previousReplica)
    {
        Ensure(ReadEnum(snapshot, "State") == state, "unexpected Store state");
        var actualDocument = GetProperty(snapshot, "Primary") as BrokerConsentLedgerDocumentV1;
        if (expectedDocument is null)
        {
            Ensure(actualDocument is null, "a no-document Store state exposed a primary");
        }
        else
        {
            Ensure(actualDocument is not null, "a healthy Store state omitted its primary");
            Ensure(
                JsonBytes(actualDocument!).AsSpan().SequenceEqual(JsonBytes(expectedDocument)),
                "the Store returned different primary bytes");
        }
        var diagnostics = GetRequiredProperty(snapshot, "Diagnostics");
        Ensure(ReadEnum(diagnostics, "Primary") == primaryReplica, "unexpected primary replica state");
        Ensure(ReadEnum(diagnostics, "Previous") == previousReplica, "unexpected previous replica state");
    }

    private static void AssertWrite(
        object result,
        string writeState,
        string snapshotState,
        BrokerConsentLedgerDocumentV1 expectedDocument,
        string primaryReplica,
        string previousReplica)
    {
        AssertWriteState(result, writeState);
        AssertSnapshot(
            GetRequiredProperty(result, "Snapshot"),
            snapshotState,
            expectedDocument,
            primaryReplica,
            previousReplica);
    }

    private static void AssertWriteState(object result, string expected) =>
        Ensure(ReadEnum(result, "State") == expected, "unexpected Store write state");

    private static void AssertNoTemporaryFiles(string root)
    {
        var unexpected = Directory.EnumerateFiles(root)
            .Select(Path.GetFileName)
            .Where(name => name is not PrimaryFileName and not PreviousFileName and not LockFileName)
            .ToArray();
        Ensure(unexpected.Length == 0, "the Store left an unexpected file: " + string.Join(",", unexpected));
    }

    private static void AssertZeroAuthorityBoundary()
    {
        var assembly = typeof(BrokerConsentLedgerStore).Assembly;
        var forbidden = assembly.GetTypes()
            .Where(type => type.Namespace == "CodexGuardian.Broker" &&
                           type.Name.Contains("Consent", StringComparison.Ordinal))
            .SelectMany(type => type.GetMembers(
                BindingFlags.Public |
                BindingFlags.NonPublic |
                BindingFlags.Instance |
                BindingFlags.Static))
            .Select(member => member.Name)
            .Where(name =>
                name.Contains("Authoriz", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Lease", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("CanUse", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("VerifiedGrant", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Promote", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Recover", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Ensure(forbidden.Length == 0, "the Store exposed authority or previous-promotion APIs");
        Ensure(
            Enum.GetNames<BrokerConsentLedgerStoreStateV1>().SequenceEqual(
                new[]
                {
                    "NoAuthority",
                    "HealthyGenesis",
                    "ReceiptPendingVerification",
                    "Quarantined"
                }),
            "the Store exposed an authority-bearing persisted state");

        var root = Directory.GetCurrentDirectory();
        var storeSource = File.ReadAllText(Path.Combine(
            root,
            "work",
            "CodexGuardian.Broker",
            "BrokerConsentLedgerStore.cs"));
        var storeTestSource = File.ReadAllText(Path.Combine(
            root,
            "work",
            "CodexGuardian.Tests",
            "BrokerConsentLedgerStoreOfflineTests.cs"));
        var guardianProject = File.ReadAllText(Path.Combine(root, "work", "CodexGuardian", "CodexGuardian.csproj"));
        var appSource = File.ReadAllText(Path.Combine(root, "work", "CodexGuardian", "App.xaml.cs"));
        Ensure(
            !storeSource.Contains("webAuthn" + ".dll", StringComparison.OrdinalIgnoreCase) &&
            !storeSource.Contains("WebAuthNGet", StringComparison.Ordinal) &&
            !storeSource.Contains("BrokerWebAuthnReceiptVerifierV1", StringComparison.Ordinal) &&
            !storeSource.Contains("VerifiedUserPresenceEvidenceV1", StringComparison.Ordinal) &&
            !storeSource.Contains("BrokerCapabilityLease", StringComparison.Ordinal) &&
            !storeSource.Contains("System.Windows", StringComparison.Ordinal) &&
            !storeSource.Contains("CodexGuardian.Services", StringComparison.Ordinal) &&
            !storeSource.Contains("CodexGuardian.ViewModels", StringComparison.Ordinal),
            "the Store crossed into native receipt, verified evidence, lease, or Guardian runtime code");
        Ensure(
            !storeTestSource.Contains("Create" + "SignedConsent", StringComparison.Ordinal) &&
            !storeTestSource.Contains("Create" + "VerifiedGrant", StringComparison.Ordinal) &&
            !storeTestSource.Contains("Verify" + "ConsentAssertion", StringComparison.Ordinal) &&
            !storeTestSource.Contains("Verify" + "PersistedGrant", StringComparison.Ordinal) &&
            !storeTestSource.Contains("Windows" + "WebAuthnPlatform", StringComparison.Ordinal) &&
            !storeTestSource.Contains("webAuthn" + ".dll", StringComparison.OrdinalIgnoreCase),
            "a Store or crash child fixture can invoke receipt verification or native WebAuthn");
        Ensure(
            !guardianProject.Contains("CodexGuardian.Broker", StringComparison.Ordinal) &&
            !appSource.Contains("ConsentLedger", StringComparison.OrdinalIgnoreCase),
            "the Guardian application was wired to the Broker Store");
    }

    private static void AssertReleaseClosure()
    {
        var root = Directory.GetCurrentDirectory();
        var releaseSource = File.ReadAllText(Path.Combine(root, "work", "package-release.ps1"));
        var programSource = File.ReadAllText(Path.Combine(root, "work", "CodexGuardian.Tests", "Program.cs"));
        Ensure(
            releaseSource.Split("BrokerConsentLedgerStore.cs", StringSplitOptions.None).Length == 4 &&
            releaseSource.Split("BrokerConsentLedgerStoreOfflineTests.cs", StringSplitOptions.None).Length == 4,
            "release source closure does not contain each Store source exactly three times");
        Ensure(
            releaseSource.Contains("$BrokerConsentLedgerTestData", StringComparison.Ordinal) &&
            releaseSource.Contains(TestDataRootArgument, StringComparison.Ordinal),
            "release safe-drill does not pass an isolated Store test-data root");
        Ensure(
            programSource.Contains(
                "BrokerConsentLedgerStoreOfflineTests.RunAsync(args, Assert)",
                StringComparison.Ordinal) &&
            programSource.Contains(
                "BrokerConsentLedgerStoreOfflineTests.IsChildProbeInvocation(args)",
                StringComparison.Ordinal) &&
            programSource.Contains("BrokerConsentLedgerStore.cs", StringComparison.Ordinal) &&
            programSource.Contains("BrokerConsentLedgerStoreOfflineTests.cs", StringComparison.Ordinal),
            "Tests Program does not pin Store execution and release occurrence assertions");
    }

    private static ReflectedStore OpenStore(
        string root,
        Action<string>? faultCallback = null) =>
        new(root, faultCallback);

    private static void ExpectStoreCode(Action action, string expectedCode)
    {
        try
        {
            action();
        }
        catch (Exception exception)
        {
            Ensure(
                string.Equals(
                    GetStringProperty(exception, "Code"),
                    expectedCode,
                    StringComparison.Ordinal),
                "unexpected Store error code: " + exception.GetType().Name + ": " + exception.Message);
            return;
        }
        throw new InvalidOperationException("Expected Store error code " + expectedCode + ".");
    }

    private static Type RequireType(Assembly assembly, string name) =>
        assembly.GetType("CodexGuardian.Broker." + name, throwOnError: false, ignoreCase: false) ??
        throw new InvalidOperationException("Missing Store type " + name + ".");

    private static void AssertEnum(Type type, params string[] expected)
    {
        Ensure(type.IsEnum, type.Name + " is not an enum");
        Ensure(Enum.GetNames(type).SequenceEqual(expected), type.Name + " has unexpected members");
    }

    private static object? GetProperty(object value, string name) =>
        value.GetType().GetProperty(name, InstanceFlags)?.GetValue(value);

    private static object GetRequiredProperty(object value, string name) =>
        GetProperty(value, name) ??
        throw new InvalidOperationException(value.GetType().Name + "." + name + " is missing or null.");

    private static string GetStringProperty(object value, string name) =>
        GetProperty(value, name) as string ?? string.Empty;

    private static string ReadEnum(object value, string name) =>
        GetRequiredProperty(value, name).ToString() ?? string.Empty;

    private static int FindUniqueArgument(IReadOnlyList<string> arguments, string name)
    {
        var indexes = Enumerable.Range(0, arguments.Count)
            .Where(index => string.Equals(arguments[index], name, StringComparison.Ordinal))
            .ToArray();
        Ensure(indexes.Length == 1, name + " is not unique");
        return indexes[0];
    }

    private static string ReadRequiredArgumentValue(
        IReadOnlyList<string> arguments,
        string name)
    {
        var index = FindUniqueArgument(arguments, name);
        Ensure(index + 1 < arguments.Count, name + " value is missing");
        Ensure(!string.IsNullOrWhiteSpace(arguments[index + 1]), name + " value is empty");
        return arguments[index + 1];
    }

    private static string ReadRequiredTestDataRoot(IReadOnlyList<string> arguments)
    {
        var index = FindUniqueArgument(arguments, TestDataRootArgument);
        Ensure(index + 1 < arguments.Count, "the Broker consent ledger test-data root value is missing");
        var value = Path.GetFullPath(arguments[index + 1]);
        Ensure(
            Path.GetPathRoot(value) is { Length: >= 3 } root &&
            root[0] is 'D' or 'd' &&
            root[1] == ':',
            "the Broker consent ledger test-data root is not on D:");
        return Path.TrimEndingDirectorySeparator(value);
    }

    private static string CreateCaseRoot(string testDataRoot, string label)
    {
        var root = Path.Combine(
            testDataRoot,
            label + "-" + Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static void WriteReplica(string path, byte[] bytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private static byte[] JsonBytes(BrokerConsentLedgerDocumentV1 document) =>
        BrokerConsentLedgerV1.Serialize(document);

    private static FileIdentity CaptureFile(string path)
    {
        var item = new FileInfo(path);
        return new FileIdentity(
            item.Length,
            item.LastWriteTimeUtc.Ticks,
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
    }

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

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void CreateJunction(string junctionPath, string targetPath)
    {
        var startInfo = new ProcessStartInfo("cmd.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            Arguments = $"/d /c mklink /J \"{junctionPath}\" \"{targetPath}\""
        };
        using var process = Process.Start(startInfo) ??
            throw new InvalidOperationException("Unable to start the junction fixture process.");
        process.WaitForExit();
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Ensure(process.ExitCode == 0, "Unable to create junction fixture: " + output + error);
    }

    private static bool IsSameOrDescendant(string candidate, string root)
    {
        var normalizedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
               normalizedCandidate.StartsWith(
                   normalizedRoot + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
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

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().ConfigureAwait(false);
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

    private sealed class ReflectedStore : IDisposable
    {
        private readonly object _instance;
        private readonly MethodInfo _read;
        private readonly MethodInfo _write;

        internal ReflectedStore(string root, Action<string>? faultCallback)
        {
            var type = typeof(BrokerConsentLedgerStore);
            if (faultCallback is null)
            {
                var constructor = type.GetConstructor(
                    InstanceFlags,
                    binder: null,
                    new[] { typeof(string) },
                    modifiers: null) ??
                    throw new InvalidOperationException("the Store data-directory constructor is missing");
                _instance = Invoke(() => constructor.Invoke(new object[] { root }));
            }
            else
            {
                var faultPointType = RequireType(type.Assembly, "BrokerConsentLedgerStoreFaultPointV1");
                var callbackType = typeof(Action<>).MakeGenericType(faultPointType);
                var constructor = type.GetConstructor(
                    InstanceFlags,
                    binder: null,
                    new[] { typeof(string), callbackType },
                    modifiers: null) ??
                    throw new InvalidOperationException("the Store fault callback constructor is missing");
                var callback = CreateFaultCallback(faultPointType, callbackType, faultCallback);
                _instance = Invoke(() => constructor.Invoke(new object[] { root, callback }));
            }
            _read = type.GetMethod(
                "Read",
                InstanceFlags,
                binder: null,
                Type.EmptyTypes,
                modifiers: null) ??
                throw new InvalidOperationException("the Store Read method is missing");
            _write = type.GetMethod(
                "Write",
                InstanceFlags,
                binder: null,
                new[] { typeof(BrokerConsentLedgerDocumentV1) },
                modifiers: null) ??
                throw new InvalidOperationException("the Store Write method is missing");
        }

        internal object Read() => Invoke(() => _read.Invoke(_instance, null)!);

        internal object Write(BrokerConsentLedgerDocumentV1 candidate) =>
            Invoke(() => _write.Invoke(_instance, new object[] { candidate })!);

        internal string GetString(string name) => GetStringProperty(_instance, name);

        public void Dispose()
        {
            Ensure(_instance is IDisposable, "the Store instance is not disposable");
            ((IDisposable)_instance).Dispose();
        }

        private static T Invoke<T>(Func<T> action)
        {
            try
            {
                return action();
            }
            catch (TargetInvocationException exception) when (exception.InnerException is not null)
            {
                ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
                throw;
            }
        }

        private static Delegate CreateFaultCallback(
            Type faultPointType,
            Type callbackType,
            Action<string> callback)
        {
            var point = Expression.Parameter(faultPointType, "point");
            var toString = Expression.Call(
                Expression.Convert(point, typeof(object)),
                typeof(object).GetMethod(nameof(ToString), Type.EmptyTypes)!);
            var invoke = Expression.Invoke(Expression.Constant(callback), toString);
            return Expression.Lambda(callbackType, invoke, point).Compile();
        }
    }

    private sealed record CrashScenario(
        string Name,
        IReadOnlyList<BrokerConsentLedgerDocumentV1> Setup,
        BrokerConsentLedgerDocumentV1? OldPrimary,
        BrokerConsentLedgerDocumentV1 Candidate);

    private sealed record CrashChildResult(
        int ExitCode,
        int ProcessId,
        long StartTimeUtcTicks,
        string Output,
        string Error);

    private sealed record FileIdentity(long Length, long LastWriteUtcTicks, string Sha256);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);
}
