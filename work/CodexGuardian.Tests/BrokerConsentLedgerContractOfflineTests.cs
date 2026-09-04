using CodexGuardian.Broker;
using CodexGuardian.Control;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal static class BrokerConsentLedgerContractOfflineTests
{
    private static readonly Guid LedgerId =
        Guid.ParseExact("01234567-89ab-cdef-0123-456789abcdef", "D");
    private static readonly Guid ReceiptId =
        Guid.ParseExact("11111111-2222-3333-4444-555555555555", "D");
    private const long IssuedAtUtcTicks = 638900000000000000;
    private const long RevokedAtUtcTicks = 638900000100000000;

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase("Broker consent ledger has exact canonical genesis, grant, and revoke bytes", TestCanonicalDocuments, assert);
        RunCase("Broker consent ledger rejects non-canonical and malformed JSON", TestStrictParsing, assert);
        RunCase("Broker consent ledger enforces revision, hash-chain, and typed transitions", TestTransitions, assert);
        RunCase("Broker consent statement binds every grant identity field except signature", TestConsentStatement, assert);
        RunCase("Broker consent ledger remains structural and Broker-only without authority APIs", TestBoundary, assert);
        return Task.CompletedTask;
    }

    private static void TestCanonicalDocuments()
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var genesisEntry =
            $"{{\"kind\":\"genesis\",\"sequence\":0,\"previousEntrySha256\":\"{BrokerConsentLedgerV1.ZeroSha256}\",\"revocationGeneration\":0}}";
        var expectedGenesis = DocumentJson(LedgerId, 0, genesisEntry);
        Ensure(Json(genesis) == expectedGenesis, "genesis canonical bytes changed");
        Ensure(
            genesis.ValidationState == BrokerConsentLedgerValidationStateV1.StructurallyValid,
            "genesis claimed a state other than structural validity");
        Ensure(
            Json(BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(expectedGenesis))) ==
            expectedGenesis,
            "genesis canonical round-trip changed bytes");

        var generation = CreateGeneration("generation-a");
        var grant = CreateVerifiedGrant(
            genesis,
            expectedRevision: 0,
            generation,
            IssuedAtUtcTicks);
        var receipt = ((BrokerConsentGrantEntryV1)grant.Entry).Receipt;
        var grantEntry =
            $"{{\"kind\":\"grant\",\"sequence\":1,\"previousEntrySha256\":\"{genesis.EntrySha256}\",\"revocationGeneration\":0," +
            $"\"receiptId\":\"{ReceiptId:D}\",\"generationSha256\":\"{generation.GenerationSha256}\"," +
            $"\"capability\":\"{BrokerConsentLedgerV1.CapabilityName}\",\"issuedAtUtcTicks\":{IssuedAtUtcTicks}," +
            $"\"receiptFormat\":\"{BrokerConsentLedgerV1.ReceiptFormatName}\",\"credentialIdBase64\":{JsonString(receipt.CredentialIdBase64)}," +
            $"\"credentialPublicKeySha256\":\"{receipt.CredentialPublicKeySha256}\"," +
            $"\"challengeNonceBase64\":{JsonString(receipt.ChallengeNonceBase64)},\"signatureBase64\":{JsonString(receipt.SignatureBase64)}}}";
        var expectedGrant = DocumentJson(LedgerId, 1, grantEntry);
        var actualGrant = Json(grant);
        Ensure(
            actualGrant == expectedGrant,
            $"grant canonical bytes changed; expected={expectedGrant}; actual={actualGrant}");
        Ensure(
            grant.ValidationState == BrokerConsentLedgerValidationStateV1.ReceiptPendingVerification,
            "a structural grant claimed verified authority");
        Ensure(
            Json(BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(expectedGrant))) ==
            expectedGrant,
            "grant canonical round-trip changed bytes");

        var revoke = BrokerConsentLedgerTransition.CreateRevoke(
            grant,
            expectedRevision: 1,
            BrokerConsentRevokeReasonV1.UserRequested,
            RevokedAtUtcTicks);
        var revokeEntry =
            $"{{\"kind\":\"revoke\",\"sequence\":2,\"previousEntrySha256\":\"{grant.EntrySha256}\",\"revocationGeneration\":1," +
            $"\"revokedReceiptId\":\"{ReceiptId:D}\",\"revokedGenerationSha256\":\"{generation.GenerationSha256}\"," +
            $"\"capability\":\"{BrokerConsentLedgerV1.CapabilityName}\",\"reason\":\"userRequested\",\"revokedAtUtcTicks\":{RevokedAtUtcTicks}}}";
        var expectedRevoke = DocumentJson(LedgerId, 2, revokeEntry);
        Ensure(Json(revoke) == expectedRevoke, "revoke canonical bytes changed");
        Ensure(
            revoke.ValidationState == BrokerConsentLedgerValidationStateV1.StructurallyValid,
            "revoke claimed a state other than structural validity");
        BrokerConsentLedgerV1.ValidateSuccessor(genesis, grant);
        BrokerConsentLedgerV1.ValidateSuccessor(grant, revoke);
    }

    private static void TestStrictParsing()
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var canonical = Json(genesis);
        var mutations = new[]
        {
            " " + canonical,
            canonical + " ",
            canonical.Replace("\"schema\"", "\"Schema\"", StringComparison.Ordinal),
            canonical.Replace("\"revision\":0", "\"revision\":0e0", StringComparison.Ordinal),
            canonical.Replace(
                "\"revision\":0,",
                "\"revision\":0,\"revision\":0,",
                StringComparison.Ordinal),
            canonical.Replace(
                "\"revision\":0,",
                "\"revision\":0,\"\\u0072evision\":0,",
                StringComparison.Ordinal),
            canonical[..^1] + ",\"unknown\":0}",
            canonical[..^1] + ",}",
            "/*comment*/" + canonical,
            canonical.Replace(LedgerId.ToString("D"), LedgerId.ToString("D").ToUpperInvariant(), StringComparison.Ordinal),
            $"{{\"ledgerId\":\"{LedgerId:D}\",\"schema\":\"{BrokerConsentLedgerV1.SchemaName}\",\"revision\":0,\"entry\":{EntryJson(genesis)},\"entrySha256\":\"{genesis.EntrySha256}\"}}"
        };
        foreach (var mutation in mutations)
        {
            ExpectFailure(() => BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(mutation)));
        }

        var bom = new byte[Encoding.UTF8.GetByteCount(canonical) + 3];
        bom[0] = 0xEF;
        bom[1] = 0xBB;
        bom[2] = 0xBF;
        Encoding.UTF8.GetBytes(canonical).CopyTo(bom, 3);
        ExpectCode(() => BrokerConsentLedgerV1.Parse(bom), "consent-ledger-noncanonical");
        ExpectCode(
            () => BrokerConsentLedgerV1.Parse(new byte[] { 0x7B, 0x22, 0xFF, 0x22, 0x7D }),
            "consent-ledger-invalid-json");
        ExpectCode(
            () => BrokerConsentLedgerV1.Parse(new byte[BrokerConsentLedgerV1.MaximumDocumentBytes + 1]),
            "consent-ledger-size");

        var grant = CreateVerifiedGrant(
            genesis,
            0,
            CreateGeneration("generation-a"),
            IssuedAtUtcTicks);
        var grantJson = Json(grant);
        var receipt = ((BrokerConsentGrantEntryV1)grant.Entry).Receipt;
        var escapedBase64 = grantJson.Replace(
            "\"credentialIdBase64\":\"AQIDBA==\"",
            "\"credentialIdBase64\":\"\\u0041QIDBA==\"",
            StringComparison.Ordinal);
        ExpectCode(
            () => BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(escapedBase64)),
            "consent-ledger-noncanonical");
        var nestedMutations = new[]
        {
            grantJson.Replace("\"kind\":\"grant\"", "\"Kind\":\"grant\"", StringComparison.Ordinal),
            grantJson.Replace("\"sequence\":1,", "\"sequence\":1,\"sequence\":1,", StringComparison.Ordinal),
            grantJson.Replace("\"sequence\":1,", "\"sequence\":1,\"\\u0073equence\":1,", StringComparison.Ordinal),
            grantJson.Replace(
                $",\"signatureBase64\":{JsonString(receipt.SignatureBase64)}",
                string.Empty,
                StringComparison.Ordinal),
            AddEntryProperty(grantJson, "\"unknown\":0"),
            grantJson.Replace("AQIDBA==", "AQIDBA", StringComparison.Ordinal),
            grantJson.Replace(
                receipt.CredentialPublicKeySha256,
                receipt.CredentialPublicKeySha256.ToLowerInvariant(),
                StringComparison.Ordinal),
            grantJson.Replace(
                $"\"receiptId\":\"{ReceiptId:D}\"",
                $"\"receiptId\":\"{{{ReceiptId:D}}}\"",
                StringComparison.Ordinal),
            grantJson.Replace(
                BrokerConsentLedgerV1.ReceiptFormatName,
                "Windows-User-Presence-V1",
                StringComparison.Ordinal)
        };
        foreach (var mutation in nestedMutations)
        {
            ExpectFailure(() => BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(mutation)));
        }

        var hashTamper = grantJson.Replace(
            grant.EntrySha256,
            MutateHash(grant.EntrySha256),
            StringComparison.Ordinal);
        ExpectCode(
            () => BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(hashTamper)),
            "consent-ledger-schema");
    }

    private static void TestTransitions()
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generationA = CreateGeneration("generation-a");
        ExpectCode(
            () => CreateVerifiedGrant(
                genesis,
                1,
                generationA,
                IssuedAtUtcTicks),
            "consent-ledger-transition-invalid");
        ExpectCode(
            () => BrokerConsentLedgerTransition.CreateRevoke(
                genesis,
                0,
                BrokerConsentRevokeReasonV1.UserRequested,
                RevokedAtUtcTicks),
            "consent-ledger-transition-invalid");

        var grantA = CreateVerifiedGrant(
            genesis,
            0,
            generationA,
            IssuedAtUtcTicks);

        var generationB = CreateGeneration("generation-b");
        var grantB = CreateVerifiedGrant(
            grantA,
            1,
            generationB,
            IssuedAtUtcTicks + 1,
            receiptId: Guid.ParseExact("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "D"));
        Ensure(
            grantB.Revision == 2 &&
            grantB.Entry.RevocationGeneration == 1,
            "grant supersession did not advance revision and revocation generation once");
        BrokerConsentLedgerV1.ValidateSuccessor(grantA, grantB);

        var revoke = BrokerConsentLedgerTransition.CreateRevoke(
            grantB,
            2,
            BrokerConsentRevokeReasonV1.PackageChanged,
            RevokedAtUtcTicks);
        Ensure(
            ReferenceEquals(
                revoke,
                BrokerConsentLedgerTransition.CreateRevoke(
                    revoke,
                    3,
                    BrokerConsentRevokeReasonV1.PackageChanged,
                    RevokedAtUtcTicks)),
            "an idempotent revoke replay advanced the ledger");
        ExpectCode(
            () => BrokerConsentLedgerTransition.CreateRevoke(
                revoke,
                3,
                BrokerConsentRevokeReasonV1.UserRequested,
                RevokedAtUtcTicks + 1),
            "consent-ledger-transition-invalid");

        var regrant = CreateVerifiedGrant(
            revoke,
            3,
            generationA,
            RevokedAtUtcTicks + 1,
            receiptId: Guid.ParseExact("bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "D"));
        Ensure(
            regrant.Revision == 4 &&
            regrant.Entry.RevocationGeneration == revoke.Entry.RevocationGeneration,
            "a new grant after revoke changed the revocation generation twice");
        BrokerConsentLedgerV1.ValidateSuccessor(revoke, regrant);

        var otherGenesis = BrokerConsentLedgerTransition.CreateGenesis(
            Guid.ParseExact("99999999-8888-7777-6666-555555555555", "D"));
        ExpectCode(
            () => BrokerConsentLedgerV1.ValidateSuccessor(otherGenesis, grantA),
            "consent-ledger-chain-invalid");

        var wrongPreviousJson = RebindPreviousEntryHash(Json(grantA), new string('F', 64));
        var wrongPrevious = BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(wrongPreviousJson));
        ExpectCode(
            () => BrokerConsentLedgerV1.ValidateSuccessor(genesis, wrongPrevious),
            "consent-ledger-chain-invalid");
    }

    private static void TestConsentStatement()
    {
        var genesis = BrokerConsentLedgerTransition.CreateGenesis(LedgerId);
        var generation = CreateGeneration("generation-a");
        var grant = CreateVerifiedGrant(
            genesis,
            0,
            generation,
            IssuedAtUtcTicks);
        var receipt = ((BrokerConsentGrantEntryV1)grant.Entry).Receipt;
        var statement = Encoding.UTF8.GetString(
            BrokerConsentLedgerV1.CreateConsentStatement(grant));
        Ensure(
            statement.StartsWith(
                $"{{\"schema\":\"{BrokerConsentLedgerV1.StatementSchemaName}\"",
                StringComparison.Ordinal) &&
            statement.Contains($"\"ledgerId\":\"{LedgerId:D}\"", StringComparison.Ordinal) &&
            statement.Contains("\"revision\":1,\"sequence\":1", StringComparison.Ordinal) &&
            statement.Contains(
                $"\"previousEntrySha256\":\"{genesis.EntrySha256}\"",
                StringComparison.Ordinal) &&
            statement.Contains("\"revocationGeneration\":0", StringComparison.Ordinal) &&
            statement.Contains($"\"receiptId\":\"{ReceiptId:D}\"", StringComparison.Ordinal) &&
            statement.Contains($"\"generationSha256\":\"{generation.GenerationSha256}\"", StringComparison.Ordinal) &&
            statement.Contains($"\"capability\":\"{BrokerConsentLedgerV1.CapabilityName}\"", StringComparison.Ordinal) &&
            statement.Contains($"\"issuedAtUtcTicks\":{IssuedAtUtcTicks}", StringComparison.Ordinal) &&
            statement.Contains(
                $"\"receiptFormat\":\"{BrokerConsentLedgerV1.ReceiptFormatName}\"",
                StringComparison.Ordinal) &&
            statement.Contains(
                $"\"credentialIdBase64\":{JsonString(receipt.CredentialIdBase64)}",
                StringComparison.Ordinal) &&
            statement.Contains(
                $"\"credentialPublicKeySha256\":\"{receipt.CredentialPublicKeySha256}\"",
                StringComparison.Ordinal) &&
            statement.Contains(
                $"\"challengeNonceBase64\":{JsonString(receipt.ChallengeNonceBase64)}",
                StringComparison.Ordinal) &&
            !statement.Contains("signatureBase64", StringComparison.Ordinal),
            "the consent statement omitted a bound identity or included the signature: " + statement);

        var baselineHash = BrokerConsentLedgerV1.ComputeConsentStatementSha256(grant);
        var variants = new[]
        {
            CreateVerifiedGrant(
                genesis,
                0,
                CreateGeneration("generation-b"),
                IssuedAtUtcTicks),
            CreateVerifiedGrant(
                genesis,
                0,
                generation,
                IssuedAtUtcTicks,
                receiptId: Guid.ParseExact("22222222-3333-4444-5555-666666666666", "D")),
            CreateVerifiedGrant(
                genesis,
                0,
                generation,
                IssuedAtUtcTicks,
                nonceSeed: 0x70),
            CreateVerifiedGrant(
                genesis,
                0,
                generation,
                IssuedAtUtcTicks,
                credentialSeed: 0x10),
            CreateVerifiedGrant(
                genesis,
                0,
                generation,
                IssuedAtUtcTicks,
                keyVariant: 2),
            CreateVerifiedGrant(
                genesis,
                0,
                generation,
                IssuedAtUtcTicks + 1),
            CreateVerifiedGrant(
                BrokerConsentLedgerTransition.CreateGenesis(
                    Guid.ParseExact("fedcba98-7654-3210-fedc-ba9876543210", "D")),
                0,
                generation,
                IssuedAtUtcTicks)
        };
        Ensure(
            variants.All(variant =>
                !string.Equals(
                    baselineHash,
                    BrokerConsentLedgerV1.ComputeConsentStatementSha256(variant),
                    StringComparison.Ordinal)),
            "a changed grant identity reused the same consent statement hash");
        var signatureOnlyVariant = CreateVerifiedGrant(
            genesis,
            0,
            generation,
            IssuedAtUtcTicks);
        Ensure(
            string.Equals(
                baselineHash,
                BrokerConsentLedgerV1.ComputeConsentStatementSha256(signatureOnlyVariant),
                StringComparison.Ordinal),
            "the consent statement incorrectly included the receipt signature");
        ExpectCode(
            () => BrokerConsentLedgerV1.CreateConsentStatement(genesis),
            "consent-ledger-transition-invalid");
    }

    private static void TestBoundary()
    {
        var assembly = typeof(BrokerConsentLedgerV1).Assembly;
        var forbiddenMembers = assembly.GetTypes()
            .Where(type => type.Namespace == "CodexGuardian.Broker" &&
                           type.Name.Contains("Consent", StringComparison.Ordinal))
            .SelectMany(type => type.GetMembers(
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.Static))
            .Select(member => member.Name)
            .Where(name =>
                name.Contains("Authoriz", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Lease", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        Ensure(forbiddenMembers.Length == 0, "the structural ledger exposed authority or lease APIs");
        Ensure(
            Enum.GetNames<BrokerConsentLedgerValidationStateV1>()
                .SequenceEqual(new[] { "StructurallyValid", "ReceiptPendingVerification" }),
            "the first ledger phase exposed an authority-bearing result state");

        var root = Directory.GetCurrentDirectory();
        var brokerSource = File.ReadAllText(Path.Combine(
            root,
            "work",
            "CodexGuardian.Broker",
            "BrokerConsentLedgerContract.cs"));
        var storeSource = File.ReadAllText(Path.Combine(
            root,
            "work",
            "CodexGuardian.Broker",
            "BrokerConsentLedgerStore.cs"));
        var guardianProject = File.ReadAllText(Path.Combine(
            root,
            "work",
            "CodexGuardian",
            "CodexGuardian.csproj"));
        var appSource = File.ReadAllText(Path.Combine(
            root,
            "work",
            "CodexGuardian",
            "App.xaml.cs"));
        Ensure(
            !brokerSource.Contains("System.IO.File", StringComparison.Ordinal) &&
            !brokerSource.Contains("System.IO.Directory", StringComparison.Ordinal) &&
            !brokerSource.Contains("DllImport", StringComparison.Ordinal) &&
            !brokerSource.Contains("LibraryImport", StringComparison.Ordinal) &&
            !brokerSource.Contains("webAuthn.dll", StringComparison.OrdinalIgnoreCase) &&
            !brokerSource.Contains("WebAuthNGet", StringComparison.Ordinal) &&
            !brokerSource.Contains("WindowsHello", StringComparison.OrdinalIgnoreCase) &&
            !brokerSource.Contains("NCrypt", StringComparison.OrdinalIgnoreCase) &&
            !brokerSource.Contains("BrokerCapabilityLease", StringComparison.Ordinal) &&
            !brokerSource.Contains("IssueLease", StringComparison.OrdinalIgnoreCase) &&
            !brokerSource.Contains("System.Windows", StringComparison.Ordinal) &&
            !brokerSource.Contains("CodexGuardian.Services", StringComparison.Ordinal) &&
            !brokerSource.Contains("CodexGuardian.ViewModels", StringComparison.Ordinal),
            "the structural ledger crossed into storage, native receipt, lease, or Guardian runtime code");
        Ensure(
            !storeSource.Contains("webAuthn.dll", StringComparison.OrdinalIgnoreCase) &&
            !storeSource.Contains("WebAuthNGet", StringComparison.Ordinal) &&
            !storeSource.Contains("BrokerWebAuthnReceiptVerifierV1", StringComparison.Ordinal) &&
            !storeSource.Contains("VerifiedUserPresenceEvidenceV1", StringComparison.Ordinal) &&
            !storeSource.Contains("BrokerCapabilityLease", StringComparison.Ordinal) &&
            !storeSource.Contains("System.Windows", StringComparison.Ordinal) &&
            !storeSource.Contains("CodexGuardian.Services", StringComparison.Ordinal) &&
            !storeSource.Contains("CodexGuardian.ViewModels", StringComparison.Ordinal),
            "the durable Store crossed into native receipt, verified evidence, lease, or Guardian runtime code");
        Ensure(
            !guardianProject.Contains("CodexGuardian.Broker", StringComparison.Ordinal) &&
            !appSource.Contains("ConsentLedger", StringComparison.OrdinalIgnoreCase),
            "the Guardian application was wired to the Broker consent ledger");
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

    private static BrokerConsentLedgerDocumentV1 CreateVerifiedGrant(
        BrokerConsentLedgerDocumentV1 current,
        ulong expectedRevision,
        CodexPackageGenerationV1 generation,
        long issuedAtUtcTicks,
        Guid? receiptId = null,
        byte nonceSeed = 0x30,
        byte credentialSeed = 0x01,
        int keyVariant = 1) =>
        BrokerWebAuthnTestVectorsV1.CreateVerifiedGrant(
            current,
            expectedRevision,
            generation,
            receiptId ?? ReceiptId,
            BrokerWebAuthnTestVectorsV1.CredentialId(credentialSeed),
            BrokerWebAuthnTestVectorsV1.Nonce(nonceSeed),
            issuedAtUtcTicks,
            keyVariant);

    private static string DocumentJson(Guid ledgerId, ulong revision, string entryJson) =>
        $"{{\"schema\":\"{BrokerConsentLedgerV1.SchemaName}\",\"ledgerId\":\"{ledgerId:D}\",\"revision\":{revision},\"entry\":{entryJson},\"entrySha256\":\"{Hash(entryJson)}\"}}";

    private static string EntryJson(BrokerConsentLedgerDocumentV1 document)
    {
        var json = Json(document);
        const string marker = "\"entry\":";
        const string suffix = ",\"entrySha256\":";
        var start = json.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        var end = json.IndexOf(suffix, start, StringComparison.Ordinal);
        return json[start..end];
    }

    private static string RebindPreviousEntryHash(string json, string replacement)
    {
        var entry = EntryJson(BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(json)));
        using var parsed = System.Text.Json.JsonDocument.Parse(entry);
        var previous = parsed.RootElement.GetProperty("previousEntrySha256").GetString()!;
        var reboundEntry = entry.Replace(previous, replacement, StringComparison.Ordinal);
        var hashMarker = ",\"entrySha256\":\"";
        var hashStart = json.IndexOf(hashMarker, StringComparison.Ordinal) + hashMarker.Length;
        var hashEnd = json.IndexOf('"', hashStart);
        var rebound = json.Replace(entry, reboundEntry, StringComparison.Ordinal);
        return rebound[..hashStart] + Hash(reboundEntry) + rebound[hashEnd..];
    }

    private static string AddEntryProperty(string json, string property)
    {
        var entry = EntryJson(BrokerConsentLedgerV1.Parse(Encoding.UTF8.GetBytes(json)));
        var changedEntry = entry[..^1] + "," + property + "}";
        return json.Replace(entry, changedEntry, StringComparison.Ordinal);
    }

    private static string Json(BrokerConsentLedgerDocumentV1 document) =>
        Encoding.UTF8.GetString(BrokerConsentLedgerV1.Serialize(document));

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string JsonString(string value) =>
        System.Text.Json.JsonSerializer.Serialize(value);

    private static string MutateHash(string value) =>
        (value[0] == 'A' ? "B" : "A") + value[1..];

    private static void ExpectFailure(Action action)
    {
        try
        {
            action();
        }
        catch (BrokerConsentLedgerFormatException)
        {
            return;
        }

        throw new InvalidOperationException("Expected a consent ledger failure.");
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
