using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Linq;
using System.Text.Json;

internal static class AutomaticRecoveryStructuredReplayOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "structured recovery canonicalizes only the verified localImage wire shape",
            TestCanonicalizer,
            assert);
        RunCase(
            "structured recovery distinguishes resend actions from work-bearing continue",
            TestReplayActionSelection,
            assert);
        await RunCaseAsync(
            "structured recovery replays the exact confirmed follow-up lineage",
            TestAuthoritySuccessAsync,
            assert);
        await RunCaseAsync(
            "structured recovery rejects a legacy structured record without a wire digest",
            TestMissingDigestAsync,
            assert);
        await RunCaseAsync(
            "structured recovery persists replay digests without invalidating legacy schema two",
            TestReplayDigestPersistenceAsync,
            assert);
        await RunCaseAsync(
            "structured recovery binds replay digests to durable operation identity",
            TestReplayDigestIdentityAsync,
            assert);
        await RunCaseAsync(
            "structured recovery rejects digest and presentation path drift",
            TestDigestAndPathDriftAsync,
            assert);
        await RunCaseAsync(
            "structured recovery rejects missing duplicate and conservative follow-up lineage",
            TestLineageHealthAsync,
            assert);
        await RunCaseAsync(
            "structured recovery rejects presentation operation payload and content drift",
            TestPresentationIdentityDriftAsync,
            assert);
        await RunCaseAsync(
            "structured recovery rejects changed or missing presentation bytes",
            TestPresentationBytesDriftAsync,
            assert);
        await RunCaseAsync(
            "structured recovery holds presentation files until dispatch lease disposal",
            TestReplayLeaseLocksAsync,
            assert);
        await RunCaseAsync(
            "structured recovery authority failure creates no recovery operation or attempt",
            TestRecoveryAuthorityFailureAsync,
            assert);
        RunCase(
            "structured recovery hash preserves text compatibility and binds the wire digest",
            TestRecoveryPayloadHash,
            assert);
    }

    private static void TestCanonicalizer()
    {
        var firstPath = Path.Combine(Path.GetTempPath(), "codexfree-first.png");
        var secondPath = Path.Combine(Path.GetTempPath(), "codexfree-second.png");
        var raw = JsonSerializer.Serialize(new object[]
        {
            new { type = "text", text = "inspect", text_elements = Array.Empty<object>() },
            new { type = "localImage", path = firstPath },
            new { type = "localImage", path = secondPath }
        });
        var canonical = RecoveryStructuredInputCanonicalizer.Parse(raw);
        Ensure(
            canonical.AttachmentPaths.SequenceEqual([firstPath, secondPath], StringComparer.Ordinal),
            "canonicalizer changed the attachment order");
        Ensure(
            canonical.CanonicalJson ==
            $"[{{\"type\":\"text\",\"text\":\"inspect\",\"text_elements\":[]}}," +
            $"{{\"type\":\"localImage\",\"path\":\"{firstPath.Replace("\\", "\\\\")}\"}}," +
            $"{{\"type\":\"localImage\",\"path\":\"{secondPath.Replace("\\", "\\\\")}\"}}]",
            "canonical JSON did not use the stable native property order");
        Ensure(
            canonical.InputDigest == RecoveryStructuredInputCanonicalizer.Parse(canonical.CanonicalJson).InputDigest,
            "canonical digest was not deterministic");

        var relativePathInput = JsonSerializer.Serialize(new object[]
        {
            new { type = "text", text = "inspect", text_elements = Array.Empty<object>() },
            new { type = "localImage", path = "relative.png" }
        });
        foreach (var invalid in new[]
                 {
                     raw.Replace("localImage", "local_image", StringComparison.Ordinal),
                     raw.Replace("localImage", "localFile", StringComparison.Ordinal),
                     raw.Replace("localImage", "unknown", StringComparison.Ordinal),
                     raw.Replace("\"path\":", "\"extra\":1,\"path\":", StringComparison.Ordinal),
                     relativePathInput
                 })
        {
            AssertReplayFailure(
                () => RecoveryStructuredInputCanonicalizer.Parse(invalid),
                "invalid structured input was accepted");
        }

        var tooLongPath = "C:\\" + new string('x', 1020) + ".png";
        AssertReplayFailure(
            () => RecoveryStructuredInputCanonicalizer.Parse(
                JsonSerializer.Serialize(new[]
                {
                    new { type = "localImage", path = tooLongPath }
                })),
            "an overlong structured path was accepted");
    }

    private static void TestReplayActionSelection()
    {
        var failedWithAttachments = CreateTurn(
            hasAttachments: true,
            rawInputJson: "[]",
            hasWorkOutput: false);
        Ensure(
            RecoveryService.RequiresStructuredInputReplay(
                failedWithAttachments,
                RecoveryActionKind.ResendOriginal),
            "ResendOriginal did not require exact structured replay");
        Ensure(
            RecoveryService.RequiresStructuredInputReplay(
                failedWithAttachments,
                RecoveryActionKind.ResendContinue),
            "ResendContinue did not require exact structured replay");
        Ensure(
            !RecoveryService.RequiresStructuredInputReplay(
                failedWithAttachments,
                RecoveryActionKind.SendContinue),
            "work-bearing continue was incorrectly forced through attachment replay");

        var textOnly = failedWithAttachments with { HasAttachments = false };
        Ensure(
            !RecoveryService.RequiresStructuredInputReplay(
                textOnly,
                RecoveryActionKind.ResendOriginal),
            "text-only resend acquired structured replay authority");
    }

    private static async Task TestAuthoritySuccessAsync()
    {
        var fixture = await CreateFixtureAsync().ConfigureAwait(false);
        var authority = new RecoveryStructuredInputReplayAuthority(
            fixture.FollowUpJournal,
            fixture.Presentation);
        await using var lease = await authority.AcquireAsync(
            fixture.ThreadId,
            fixture.FailedTurn,
            CancellationToken.None).ConfigureAwait(false);
        Ensure(lease.IsCurrent, "a verified replay lease was not current");
        Ensure(
            lease.CanonicalInputJson == fixture.Canonical.CanonicalJson &&
            lease.InputDigest == fixture.Canonical.InputDigest,
            "the replay lease did not retain the exact canonical wire input");
    }

    private static async Task TestMissingDigestAsync()
    {
        var fixture = await CreateFixtureAsync(includeReplayDigest: false).ConfigureAwait(false);
        var authority = new RecoveryStructuredInputReplayAuthority(
            fixture.FollowUpJournal,
            fixture.Presentation);
        var exception = await AssertReplayFailureAsync(
                () => authority.AcquireAsync(
                    fixture.ThreadId,
                    fixture.FailedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            exception.Code == "replay-identity-mismatch",
            "a schema-two record without ReplayInputDigest was not rejected conservatively");
    }

    private static async Task TestReplayDigestPersistenceAsync()
    {
        var current = await CreateFixtureAsync().ConfigureAwait(false);
        var currentSnapshot = await new FollowUpOperationJournal(current.Root)
            .ReadAsync(CancellationToken.None)
            .ConfigureAwait(false);
        using (var document = JsonDocument.Parse(
                   await File.ReadAllTextAsync(current.FollowUpJournal.JournalPath)
                       .ConfigureAwait(false)))
        {
            Ensure(
                currentSnapshot.ReadStatus == FollowUpJournalReadStatus.Healthy &&
                currentSnapshot.Records.Single().ReplayInputDigest == current.Canonical.InputDigest &&
                document.RootElement.GetProperty("records")[0]
                    .GetProperty("replayInputDigest").GetString() == current.Canonical.InputDigest,
                "a current schema-two journal lost its structured replay digest");
        }

        var legacy = await CreateFixtureAsync(includeReplayDigest: false).ConfigureAwait(false);
        var legacySnapshot = await new FollowUpOperationJournal(legacy.Root)
            .ReadAsync(CancellationToken.None)
            .ConfigureAwait(false);
        using var legacyDocument = JsonDocument.Parse(
            await File.ReadAllTextAsync(legacy.FollowUpJournal.JournalPath).ConfigureAwait(false));
        Ensure(
            legacySnapshot.ReadStatus == FollowUpJournalReadStatus.Healthy &&
            legacySnapshot.Records.Single().ReplayInputDigest is null &&
            !legacyDocument.RootElement.GetProperty("records")[0]
                .TryGetProperty("replayInputDigest", out _),
            "a legacy schema-two checksum required a replay digest that did not exist");
    }

    private static async Task TestReplayDigestIdentityAsync()
    {
        var fixture = await CreateFixtureAsync().ConfigureAwait(false);
        await AssertThrowsAsync<InvalidOperationException>(() =>
            fixture.FollowUpJournal.GetOrCreateStructuredAsync(
                fixture.OperationId,
                fixture.ThreadId,
                fixture.MessageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                fixture.FailedTurnId,
                scheduledAtUtc: null,
                fixture.Payload,
                fixture.PresentationLeaseId,
                FollowUpPayloadSourceKind.StructuredPreset,
                fixture.ClientMessageId,
                cancellationToken: CancellationToken.None,
                replayInputDigest: new string('B', 64)));
        var snapshot = await fixture.FollowUpJournal.ReadAsync(CancellationToken.None)
            .ConfigureAwait(false);
        Ensure(
            snapshot.ReadStatus == FollowUpJournalReadStatus.Healthy &&
            snapshot.Records.Single().ReplayInputDigest == fixture.Canonical.InputDigest,
            "a conflicting replay digest replaced durable operation identity");
    }

    private static async Task TestDigestAndPathDriftAsync()
    {
        var digestDrift = await CreateFixtureAsync().ConfigureAwait(false);
        var changedRaw = digestDrift.RawInput.Replace(
            "inspect",
            "changed",
            StringComparison.Ordinal);
        var changedTurn = digestDrift.FailedTurn with { RawUserInputJson = changedRaw };
        var authority = new RecoveryStructuredInputReplayAuthority(
            digestDrift.FollowUpJournal,
            digestDrift.Presentation);
        var digestException = await AssertReplayFailureAsync(
                () => authority.AcquireAsync(
                    digestDrift.ThreadId,
                    changedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            digestException.Code == "replay-identity-mismatch",
            "raw structured input digest drift was accepted");

        var pathDrift = await CreateFixtureAsync(
                rawInputOverride: static fixture => BuildRawInput(
                    fixture.Payload.Text,
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [fixture.Payload.Attachments[0].ContentId] =
                            Path.Combine(fixture.Root, "different.png")
                    }))
            .ConfigureAwait(false);
        var pathAuthority = new RecoveryStructuredInputReplayAuthority(
            pathDrift.FollowUpJournal,
            pathDrift.Presentation);
        var pathException = await AssertReplayFailureAsync(
                () => pathAuthority.AcquireAsync(
                    pathDrift.ThreadId,
                    pathDrift.FailedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            pathException.Code == "presentation-item-mismatch",
            "presentation path drift was not rejected after digest revalidation");
    }

    private static async Task TestLineageHealthAsync()
    {
        var missing = await CreateFixtureAsync().ConfigureAwait(false);
        var missingAuthority = new RecoveryStructuredInputReplayAuthority(
            missing.FollowUpJournal,
            missing.Presentation);
        var unrelatedTurn = missing.FailedTurn with
        {
            Id = "00000000-0000-0000-0000-000000000799"
        };
        var missingException = await AssertReplayFailureAsync(() =>
                missingAuthority.AcquireAsync(
                    missing.ThreadId,
                    unrelatedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            missingException.Code == "follow-up-lineage-unavailable",
            "a healthy journal without the exact successor lineage was accepted");

        var duplicate = await CreateFixtureAsync().ConfigureAwait(false);
        await ConfirmStructuredRecordAsync(
                duplicate,
                operationId: "00000000-0000-0000-0000-000000000721",
                messageId: "00000000-0000-0000-0000-000000000722",
                clientMessageId: "00000000-0000-0000-0000-000000000723",
                duplicate.Payload,
                duplicate.PresentationLeaseId,
                duplicate.Canonical.InputDigest)
            .ConfigureAwait(false);
        var duplicateAuthority = new RecoveryStructuredInputReplayAuthority(
            duplicate.FollowUpJournal,
            duplicate.Presentation);
        var duplicateException = await AssertReplayFailureAsync(() =>
                duplicateAuthority.AcquireAsync(
                    duplicate.ThreadId,
                    duplicate.FailedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            duplicateException.Code == "follow-up-lineage-unavailable",
            "ambiguous confirmed successor lineage was accepted");

        var conservative = await CreateFixtureAsync().ConfigureAwait(false);
        await File.WriteAllTextAsync(
                conservative.FollowUpJournal.JournalPath,
                "{corrupt-current-generation")
            .ConfigureAwait(false);
        var conservativeAuthority = new RecoveryStructuredInputReplayAuthority(
            new FollowUpOperationJournal(conservative.Root),
            conservative.Presentation);
        var conservativeException = await AssertReplayFailureAsync(() =>
                conservativeAuthority.AcquireAsync(
                    conservative.ThreadId,
                    conservative.FailedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            conservativeException.Code == "follow-up-authority-unavailable",
            "a recovered or corrupt journal was treated as exact replay authority");
    }

    private static async Task TestPresentationIdentityDriftAsync()
    {
        var operation = await CreateFixtureAsync(createJournal: false).ConfigureAwait(false);
        await ConfirmStructuredRecordAsync(
                operation,
                operationId: "00000000-0000-0000-0000-000000000731",
                operation.MessageId,
                operation.ClientMessageId,
                operation.Payload,
                operation.PresentationLeaseId,
                operation.Canonical.InputDigest)
            .ConfigureAwait(false);
        await AssertReplayCodeAsync(
                operation,
                "presentation-authority-unavailable",
                "presentation operation drift was accepted")
            .ConfigureAwait(false);

        var payload = await CreateFixtureAsync(createJournal: false).ConfigureAwait(false);
        await ConfirmStructuredRecordAsync(
                payload,
                payload.OperationId,
                payload.MessageId,
                payload.ClientMessageId,
                StructuredPresetPayload.Create("changed", payload.Payload.Attachments),
                payload.PresentationLeaseId,
                payload.Canonical.InputDigest)
            .ConfigureAwait(false);
        await AssertReplayCodeAsync(
                payload,
                "presentation-authority-unavailable",
                "presentation payload drift was accepted")
            .ConfigureAwait(false);

        var content = await CreateFixtureAsync(createJournal: false).ConfigureAwait(false);
        var changedAttachment = content.Payload.Attachments[0] with
        {
            Id = "00000000-0000-0000-0000-000000000732",
            ContentId = new string('B', 64)
        };
        await ConfirmStructuredRecordAsync(
                content,
                content.OperationId,
                content.MessageId,
                content.ClientMessageId,
                StructuredPresetPayload.Create(content.Payload.Text, [changedAttachment]),
                content.PresentationLeaseId,
                content.Canonical.InputDigest)
            .ConfigureAwait(false);
        await AssertReplayCodeAsync(
                content,
                "presentation-authority-unavailable",
                "presentation content drift was accepted")
            .ConfigureAwait(false);
    }

    private static async Task TestPresentationBytesDriftAsync()
    {
        var changed = await CreateFixtureAsync().ConfigureAwait(false);
        var changedPath = changed.Canonical.AttachmentPaths[0];
        File.SetAttributes(changedPath, FileAttributes.Normal);
        await File.AppendAllTextAsync(changedPath, "drift").ConfigureAwait(false);
        var changedAuthority = new RecoveryStructuredInputReplayAuthority(
            changed.FollowUpJournal,
            changed.Presentation);
        var changedException = await AssertReplayFailureAsync(
                () => changedAuthority.AcquireAsync(
                    changed.ThreadId,
                    changed.FailedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            changedException.Code == "presentation-replay-unavailable",
            "changed presentation bytes leaked an uncontrolled file exception");

        var missing = await CreateFixtureAsync().ConfigureAwait(false);
        var missingPath = missing.Canonical.AttachmentPaths[0];
        File.SetAttributes(missingPath, FileAttributes.Normal);
        File.Delete(missingPath);
        var missingAuthority = new RecoveryStructuredInputReplayAuthority(
            missing.FollowUpJournal,
            missing.Presentation);
        var missingException = await AssertReplayFailureAsync(
                () => missingAuthority.AcquireAsync(
                    missing.ThreadId,
                    missing.FailedTurn,
                    CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(
            missingException.Code == "presentation-replay-unavailable",
            "missing presentation bytes leaked an uncontrolled file exception");
    }

    private static async Task TestReplayLeaseLocksAsync()
    {
        var fixture = await CreateFixtureAsync().ConfigureAwait(false);
        var authority = new RecoveryStructuredInputReplayAuthority(
            fixture.FollowUpJournal,
            fixture.Presentation);
        var lease = await authority.AcquireAsync(
                fixture.ThreadId,
                fixture.FailedTurn,
                CancellationToken.None)
            .ConfigureAwait(false);
        var path = lease.CanonicalInputJson.Contains("localImage", StringComparison.Ordinal)
            ? fixture.Canonical.AttachmentPaths[0]
            : throw new InvalidOperationException("the fixture did not contain a native image item");
        File.SetAttributes(path, FileAttributes.Normal);
        AssertThrows<IOException>(
            () =>
            {
                using var write = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Write,
                    FileShare.ReadWrite);
            },
            "a presentation file was writable while the replay lease was held");
        await lease.DisposeAsync().ConfigureAwait(false);
        using var afterDispose = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Write,
            FileShare.ReadWrite);
    }

    private static async Task TestRecoveryAuthorityFailureAsync()
    {
        var parent = RequireTestRoot();
        var root = Path.Combine(parent, "recovery-authority-failure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var log = new GuardianLog(root);
        await using var stateReader = new AppServerClient(new CodexCliLocator(), log);
        await using var desktop = new DesktopIpcClient(log);
        var journal = new RecoveryOperationJournal(root);
        var authority = new ThrowingReplayAuthority();
        var recovery = new RecoveryService(
            stateReader,
            desktop,
            new DesktopThreadOwnerActivator(desktop, log),
            journal,
            log,
            structuredInputReplayAuthority: authority);
        var thread = new ThreadSummary(
            "00000000-0000-0000-0000-000000000701",
            "offline recovery",
            "",
            "C:\\",
            "user",
            1,
            1,
            false,
            false,
            "idle");
        var failedTurn = CreateTurn(
            hasAttachments: true,
            rawInputJson: "[{\"type\":\"localImage\",\"path\":\"C:\\\\x.png\"}]",
            hasWorkOutput: false,
            id: "00000000-0000-0000-0000-000000000702");
        var result = await recovery.ExecuteAsync(
                thread,
                failedTurn,
                new RecoveryDecision(
                    RecoveryActionKind.ResendOriginal,
                    TaskHealth.NeedsAttention,
                    "offline fixture",
                    IsTransient: true),
                continueMessage: "continue",
                includeSubAgents: false,
                scopeGeneration: 1,
                isDispatchAllowed: static () => true,
                cancellationToken: CancellationToken.None)
            .ConfigureAwait(false);
        var snapshot = await journal.ReadAsync(CancellationToken.None).ConfigureAwait(false);
        Ensure(!result.Success, "authority failure unexpectedly reported a recovery send");
        Ensure(authority.Calls == 1, "structured replay authority was not consulted exactly once");
        Ensure(
            snapshot.Records.Count == 0,
            "structured replay failure created a durable recovery operation");
        Ensure(
            snapshot.Records.All(record => record.AttemptCount == 0),
            "structured replay failure consumed a recovery attempt");
    }

    private static void TestRecoveryPayloadHash()
    {
        const string message = "inspect";
        var legacy = RecoveryService.BuildRecoveryPayloadHash(
            RecoveryActionKind.ResendOriginal,
            message);
        Ensure(
            legacy == RecoveryOperationJournal.ComputeInputHash(
                $"{RecoveryActionKind.ResendOriginal}\n{message}"),
            "the historical text-only recovery hash changed");

        var firstDigest = new string('A', 64);
        var secondDigest = new string('B', 64);
        var first = RecoveryService.BuildRecoveryPayloadHash(
            RecoveryActionKind.ResendOriginal,
            message,
            firstDigest);
        Ensure(
            first == RecoveryService.BuildRecoveryPayloadHash(
                RecoveryActionKind.ResendOriginal,
                "a display-text change cannot override canonical input",
                firstDigest) &&
            first != RecoveryService.BuildRecoveryPayloadHash(
                RecoveryActionKind.ResendOriginal,
                message,
                secondDigest) &&
            first != RecoveryService.BuildRecoveryPayloadHash(
                RecoveryActionKind.ResendContinue,
                message,
                firstDigest) &&
            first != legacy,
            "the structured recovery hash did not bind action and canonical wire digest");
    }

    private static async Task<ReplayFixture> CreateFixtureAsync(
        bool includeReplayDigest = true,
        Func<ReplayFixture, string>? rawInputOverride = null,
        bool createJournal = true)
    {
        var root = Path.Combine(RequireTestRoot(), "structured-replay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var store = new ManagedAttachmentStore(root);
        var firstObject = await ImportPngAsync(store, fileName: "first.png").ConfigureAwait(false);
        var first = new PresetAttachmentReference
        {
            Id = "00000000-0000-0000-0000-000000000711",
            ContentId = firstObject.ContentId,
            OriginalFileName = "first.png",
            DetectedType = firstObject.DetectedType,
            OwnerInputKind = "local_image",
            ByteLength = firstObject.ByteLength,
            Order = 0
        };
        var payload = StructuredPresetPayload.Create("inspect", [first]);
        var operationId = "00000000-0000-0000-0000-000000000712";
        var threadId = "00000000-0000-0000-0000-000000000713";
        var messageId = "00000000-0000-0000-0000-000000000714";
        var failedTurnId = "00000000-0000-0000-0000-000000000715";
        var clientMessageId = "00000000-0000-0000-0000-000000000716";
        var presentation = new AttachmentPresentationLeaseService(root, store);
        var presentationLease = await presentation.AcquireAsync(
                operationId,
                payload,
                new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
                {
                    [firstObject.ContentId] = firstObject
                },
                new AttachmentPresentationRequirements(
                    SupportsSeparateDisplayName: false,
                    RequiresFileNameSuffix: true,
                    AllowHardLinks: false),
                CancellationToken.None)
            .ConfigureAwait(false);
        var initialRaw = BuildRawInput(payload.Text, presentationLease.PresentationPaths);
        var fixtureWithoutRaw = new ReplayFixture(
            root,
            store,
            presentation,
            new FollowUpOperationJournal(root),
            operationId,
            presentationLease.LeaseId,
            threadId,
            messageId,
            failedTurnId,
            clientMessageId,
            payload,
            initialRaw,
            RecoveryStructuredInputCanonicalizer.Parse(initialRaw),
            CreateTurn(
                hasAttachments: true,
                rawInputJson: initialRaw,
                hasWorkOutput: false,
                id: failedTurnId));
        var raw = rawInputOverride is null
            ? initialRaw
            : rawInputOverride(fixtureWithoutRaw);
        var canonical = RecoveryStructuredInputCanonicalizer.Parse(raw);
        var fixture = fixtureWithoutRaw with
        {
            RawInput = raw,
            Canonical = canonical,
            FailedTurn = fixtureWithoutRaw.FailedTurn with { RawUserInputJson = raw }
        };
        if (createJournal)
        {
            await ConfirmStructuredRecordAsync(
                    fixture,
                    operationId,
                    messageId,
                    clientMessageId,
                    payload,
                    presentationLease.LeaseId,
                    includeReplayDigest ? canonical.InputDigest : null)
                .ConfigureAwait(false);
        }

        return fixture;
    }

    private static async Task ConfirmStructuredRecordAsync(
        ReplayFixture fixture,
        string operationId,
        string messageId,
        string clientMessageId,
        StructuredPresetPayload payload,
        string presentationLeaseId,
        string? replayInputDigest)
    {
        await fixture.FollowUpJournal.GetOrCreateStructuredAsync(
                operationId,
                fixture.ThreadId,
                messageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                fixture.FailedTurnId,
                scheduledAtUtc: null,
                payload,
                presentationLeaseId,
                FollowUpPayloadSourceKind.StructuredPreset,
                clientMessageId,
                cancellationToken: CancellationToken.None,
                replayInputDigest: replayInputDigest)
            .ConfigureAwait(false);
        await fixture.FollowUpJournal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching,
                cancellationToken: CancellationToken.None)
            .ConfigureAwait(false);
        await fixture.FollowUpJournal.TryTransitionAsync(
                operationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Confirmed,
                fixture.FailedTurnId,
                CancellationToken.None)
            .ConfigureAwait(false);
    }

    private static async Task AssertReplayCodeAsync(
        ReplayFixture fixture,
        string expectedCode,
        string message)
    {
        var authority = new RecoveryStructuredInputReplayAuthority(
            fixture.FollowUpJournal,
            fixture.Presentation);
        var exception = await AssertReplayFailureAsync(() => authority.AcquireAsync(
                fixture.ThreadId,
                fixture.FailedTurn,
                CancellationToken.None))
            .ConfigureAwait(false);
        Ensure(exception.Code == expectedCode, message);
    }

    private static string BuildRawInput(
        string text,
        IReadOnlyDictionary<string, string> presentationPaths)
    {
        var items = new List<object>();
        if (!string.IsNullOrWhiteSpace(text))
        {
            items.Add(new { type = "text", text, text_elements = Array.Empty<object>() });
        }

        foreach (var path in presentationPaths.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            items.Add(new { type = "localImage", path = path.Value });
        }

        return JsonSerializer.Serialize(items);
    }

    private static TurnSnapshot CreateTurn(
        bool hasAttachments,
        string rawInputJson,
        bool hasWorkOutput,
        string id = "00000000-0000-0000-0000-000000000701") =>
        new(
            id,
            "failed",
            "transient failure",
            "429",
            429,
            "inspect",
            hasAttachments,
            hasWorkOutput,
            hasWorkOutput,
            "offline-output",
            1,
            2,
            rawInputJson,
            HasConfirmedLocalTerminal: true,
            HasUserMessage: true,
            HasFinalAssistantOutput: hasWorkOutput,
            HasReasoningOutput: hasWorkOutput,
            HasToolActivity: hasWorkOutput,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: !hasAttachments);

    private static async Task<ManagedAttachmentObject> ImportPngAsync(
        ManagedAttachmentStore store,
        string fileName)
    {
        var bytes = Convert.FromBase64String(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
        await using var source = new MemoryStream(bytes, writable: false);
        return await store.ImportBytesAsync(
                source,
                fileName,
                new AttachmentLimitSettings(),
                CancellationToken.None)
            .ConfigureAwait(false);
    }

    private static string RequireTestRoot()
    {
        var root = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return root;
    }

    private static void AssertReplayFailure(Action action, string message)
    {
        try
        {
            action();
        }
        catch (RecoveryStructuredInputReplayException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static async Task<RecoveryStructuredInputReplayException> AssertReplayFailureAsync(
        Func<Task<RecoveryStructuredInputReplayLease>> operation)
    {
        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (RecoveryStructuredInputReplayException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("an invalid structured replay was accepted");
    }

    private static async Task AssertThrowsAsync<TException>(Func<Task> operation)
        where TException : Exception
    {
        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name} was not thrown.");
    }

    private static void AssertThrows<TException>(Action action, string message)
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

        throw new InvalidOperationException(message);
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void RunCase(string name, Action test, Action<bool, string> assert)
    {
        try
        {
            test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name} - {exception.Message}");
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
            assert(false, $"{name}: {exception.GetType().Name} - {exception.Message}");
        }
    }

    private sealed record ReplayFixture(
        string Root,
        ManagedAttachmentStore Store,
        AttachmentPresentationLeaseService Presentation,
        FollowUpOperationJournal FollowUpJournal,
        string OperationId,
        string PresentationLeaseId,
        string ThreadId,
        string MessageId,
        string FailedTurnId,
        string ClientMessageId,
        StructuredPresetPayload Payload,
        string RawInput,
        RecoveryStructuredInputCanonicalForm Canonical,
        TurnSnapshot FailedTurn);

    private sealed class ThrowingReplayAuthority : IRecoveryStructuredInputReplayAuthority
    {
        internal int Calls { get; private set; }

        public Task<RecoveryStructuredInputReplayLease> AcquireAsync(
            string threadId,
            TurnSnapshot failedTurn,
            CancellationToken cancellationToken)
        {
            _ = threadId;
            _ = failedTurn;
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            throw new RecoveryStructuredInputReplayException("fixture-blocked");
        }
    }
}
