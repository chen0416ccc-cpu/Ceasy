using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class AttachmentPresentationReconciliationOfflineTests
{
    private static readonly AttachmentPresentationRequirements PresentationRequirements = new(
        SupportsSeparateDisplayName: false,
        RequiresFileNameSuffix: true,
        AllowHardLinks: false);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "presentation reconciliation removes orphan materializing and ready leases",
            TestOrphanCleanupAsync,
            assert);
        await RunCaseAsync(
            "presentation reconciliation retains prepared dispatching retryable uncertain and open confirmed leases",
            TestActiveRetentionAsync,
            assert);
        await RunCaseAsync(
            "presentation reconciliation removes lineage-closed and abandoned leases before journal prune",
            TestTerminalCleanupAndPruneAsync,
            assert);
        await RunCaseAsync(
            "presentation reconciliation preserves cleanup-pending journal identity until a locked lease deletes",
            TestCleanupPendingProtectionAsync,
            assert);
        await RunCaseAsync(
            "presentation reconciliation keeps managed objects fail-closed when terminal journal prune cannot persist",
            TestJournalPruneFailureCleanupAsync,
            assert);
        await RunCaseAsync(
            "presentation reconciliation fails closed on lease and journal identity mismatch",
            TestIdentityMismatchAsync,
            assert);
        await RunCaseAsync(
            "presentation reconciliation rejects a journal record for crash-left materializing state",
            TestMaterializingJournalConflictAsync,
            assert);
        await RunCaseAsync(
            "presentation reconciliation performs no deletion for corrupt transaction settings or journals",
            TestCorruptAuthoritiesAsync,
            assert);
    }

    private static async Task TestOrphanCleanupAsync()
    {
        var materializingFixture = await Fixture.CreateAsync();
        var materializing = await materializingFixture.CreateMaterializingLeaseAsync(seed: 100);
        var materializingResult = await materializingFixture.Reconciler.ReconcileAsync(
            materializingFixture.Settings,
            CancellationToken.None);
        Ensure(materializingResult.IsHealthy, "orphan materializing reconciliation was not healthy");
        Ensure(materializingResult.DeletedLeaseCount == 1, "orphan materializing lease was not deleted");
        Ensure(!Directory.Exists(materializing.LeaseDirectory), "materializing lease directory remained");
        Ensure(
            materializing.ManagedObjects.All(item => !File.Exists(item.ObjectPath)),
            "materializing orphan managed objects remained after zero-reference cleanup");

        var readyFixture = await Fixture.CreateAsync();
        var ready = await readyFixture.CreateReadyLeaseAsync(seed: 110);
        var readyResult = await readyFixture.Reconciler.ReconcileAsync(
            readyFixture.Settings,
            CancellationToken.None);
        Ensure(readyResult.IsHealthy, "orphan ready reconciliation was not healthy");
        Ensure(readyResult.DeletedLeaseCount == 1, "orphan ready lease was not deleted");
        Ensure(!Directory.Exists(ready.Lease.LeaseDirectory), "orphan ready lease directory remained");
        Ensure(!File.Exists(ready.ManagedObject.ObjectPath), "orphan ready managed object remained");
    }

    private static async Task TestActiveRetentionAsync()
    {
        var fixture = await Fixture.CreateAsync();
        var states = new[]
        {
            FollowUpOperationState.Prepared,
            FollowUpOperationState.Dispatching,
            FollowUpOperationState.Retryable,
            FollowUpOperationState.Uncertain,
            FollowUpOperationState.Confirmed
        };
        var cases = new List<ReadyLeaseCase>();
        for (var index = 0; index < states.Length; index++)
        {
            var item = await fixture.CreateReadyLeaseAsync(seed: 200 + index);
            cases.Add(item);
            _ = await fixture.CreateJournalRecordAsync(item, states[index], completed: false);
        }

        var result = await fixture.Reconciler.ReconcileAsync(fixture.Settings, CancellationToken.None);
        Ensure(result.IsHealthy, "active presentation reconciliation was not healthy");
        Ensure(result.DeletedLeaseCount == 0, "an active presentation lease was deleted");
        Ensure(result.RetainedLeaseCount == states.Length, "active lease retention count changed");
        Ensure(
            cases.All(item => Directory.Exists(item.Lease.LeaseDirectory)),
            "an active presentation lease directory was removed");
        Ensure(
            cases.All(item => File.Exists(item.ManagedObject.ObjectPath)),
            "an active managed attachment object was removed");
        var journal = await fixture.FollowUpJournal.ReadAsync(CancellationToken.None);
        Ensure(journal.Records.Count == states.Length, "active journal records were pruned");
    }

    private static async Task TestTerminalCleanupAndPruneAsync()
    {
        var fixture = await Fixture.CreateAsync();
        var completed = await fixture.CreateReadyLeaseAsync(seed: 300);
        _ = await fixture.CreateJournalRecordAsync(
            completed,
            FollowUpOperationState.Confirmed,
            completed: true);
        var abandoned = await fixture.CreateReadyLeaseAsync(seed: 301);
        _ = await fixture.CreateJournalRecordAsync(
            abandoned,
            FollowUpOperationState.Abandoned,
            completed: false);

        var result = await fixture.Reconciler.ReconcileAsync(fixture.Settings, CancellationToken.None);
        Ensure(result.IsHealthy, "terminal reconciliation was not healthy");
        Ensure(result.DeletedLeaseCount == 2, "terminal presentation leases were not deleted");
        Ensure(result.PrunedJournalRecordCount == 2, "terminal journal records were not pruned");
        Ensure(
            !Directory.Exists(completed.Lease.LeaseDirectory) &&
            !Directory.Exists(abandoned.Lease.LeaseDirectory),
            "terminal lease directories remained");
        Ensure(
            !File.Exists(completed.ManagedObject.ObjectPath) &&
            !File.Exists(abandoned.ManagedObject.ObjectPath),
            "terminal managed objects remained");
        var journal = await fixture.FollowUpJournal.ReadAsync(CancellationToken.None);
        Ensure(journal.Records.Count == 0, "terminal journal records remained after prune");
    }

    private static async Task TestCleanupPendingProtectionAsync()
    {
        var fixture = await Fixture.CreateAsync();
        var item = await fixture.CreateReadyLeaseAsync(seed: 400);
        var record = await fixture.CreateJournalRecordAsync(
            item,
            FollowUpOperationState.Abandoned,
            completed: false);
        var presentationPath = item.Lease.PresentationPaths[item.Reference.Id];
        await using (var locked = new FileStream(
                         presentationPath,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.None))
        {
            var pending = await fixture.Reconciler.ReconcileAsync(
                fixture.Settings,
                CancellationToken.None);
            Ensure(!pending.IsHealthy, "locked presentation cleanup was reported healthy");
            Ensure(
                pending.Status == AttachmentPresentationReconciliationStatus.PresentationCleanupPending,
                "locked presentation did not report cleanup pending");
            Ensure(pending.CleanupPendingLeaseCount == 1, "locked lease pending count changed");
            var presentation = fixture.Presentation.ReadReferenceSnapshotUnderMutationLease();
            Ensure(
                presentation.IsHealthy && presentation.References is
                [
                    {
                        State: AttachmentPresentationReferenceState.CleanupPending
                    }
                ],
                "locked presentation did not retain a healthy cleanup-pending transaction");
            var protectedJournal = await fixture.FollowUpJournal.ReadAsync(CancellationToken.None);
            Ensure(
                protectedJournal.Records.Any(value =>
                    string.Equals(value.OperationId, record.OperationId, StringComparison.OrdinalIgnoreCase)),
                "cleanup-pending presentation record was pruned");
        }

        var retried = await fixture.Reconciler.ReconcileAsync(fixture.Settings, CancellationToken.None);
        Ensure(retried.IsHealthy, "unlocked cleanup retry was not healthy");
        Ensure(retried.DeletedLeaseCount == 1, "unlocked cleanup-pending lease was not deleted");
        Ensure(retried.PrunedJournalRecordCount == 1, "released cleanup-pending record was not pruned");
        Ensure(!Directory.Exists(item.Lease.LeaseDirectory), "cleanup-pending lease directory remained");
        Ensure(!File.Exists(item.ManagedObject.ObjectPath), "cleanup-pending managed object remained");
    }

    private static async Task TestIdentityMismatchAsync()
    {
        var fixture = await Fixture.CreateAsync();
        var item = await fixture.CreateReadyLeaseAsync(seed: 500);
        var mismatchedLeaseId = new string('A', 32);
        if (string.Equals(mismatchedLeaseId, item.Lease.LeaseId, StringComparison.Ordinal))
        {
            mismatchedLeaseId = new string('B', 32);
        }

        _ = await fixture.FollowUpJournal.GetOrCreateStructuredAsync(
            item.OperationId,
            item.ThreadId,
            item.MessageId,
            FollowUpTriggerKind.AfterNormalCompletion,
            item.ExpectedTurnId,
            scheduledAtUtc: null,
            item.Payload,
            mismatchedLeaseId,
            FollowUpPayloadSourceKind.StructuredPreset,
            FollowUpOperationJournal.CreateClientMessageId(item.OperationId),
            CancellationToken.None);

        var result = await fixture.Reconciler.ReconcileAsync(fixture.Settings, CancellationToken.None);
        Ensure(!result.IsHealthy, "mismatched presentation identity was accepted");
        Ensure(
            result.Status == AttachmentPresentationReconciliationStatus.PresentationIdentityMismatch,
            "mismatched presentation identity returned the wrong status");
        Ensure(Directory.Exists(item.Lease.LeaseDirectory), "mismatched presentation lease was deleted");
        Ensure(File.Exists(item.ManagedObject.ObjectPath), "mismatched managed object was deleted");
    }

    private static async Task TestJournalPruneFailureCleanupAsync()
    {
        var fixture = await Fixture.CreateAsync();
        var item = await fixture.CreateReadyLeaseAsync(seed: 450);
        var record = await fixture.CreateJournalRecordAsync(
            item,
            FollowUpOperationState.Abandoned,
            completed: false);
        await using (var locked = new FileStream(
                         fixture.FollowUpJournal.JournalPath,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.None))
        {
            var result = await fixture.Reconciler.ReconcileAsync(
                fixture.Settings,
                CancellationToken.None);
            Ensure(!result.IsHealthy, "locked journal prune was reported healthy");
            Ensure(
                result.Status == AttachmentPresentationReconciliationStatus.JournalPersistenceUnavailable,
                "locked journal prune returned the wrong status");
            Ensure(result.DeletedLeaseCount == 1, "locked journal prevented authorized lease deletion");
            Ensure(result.DeletedManagedObjectCount == 0, "unproven managed object cleanup was reported");
            Ensure(!Directory.Exists(item.Lease.LeaseDirectory), "released lease directory remained");
            Ensure(File.Exists(item.ManagedObject.ObjectPath), "unproven managed object was deleted");
            var retained = await fixture.FollowUpJournal.ReadAsync(CancellationToken.None);
            Ensure(
                retained.Records.Any(value =>
                    string.Equals(value.OperationId, record.OperationId, StringComparison.OrdinalIgnoreCase)),
                "failed journal prune removed its in-memory terminal identity");
        }
    }

    private static async Task TestMaterializingJournalConflictAsync()
    {
        var fixture = await Fixture.CreateAsync();
        var item = await fixture.CreateMaterializingLeaseAsync(seed: 600);
        var reference = fixture.Presentation.ReadReferenceSnapshotUnderMutationLease().References.Single();
        _ = await fixture.FollowUpJournal.GetOrCreateStructuredAsync(
            item.OperationId,
            item.ThreadId,
            item.MessageId,
            FollowUpTriggerKind.AfterNormalCompletion,
            item.ExpectedTurnId,
            scheduledAtUtc: null,
            item.Payload,
            reference.LeaseId,
            FollowUpPayloadSourceKind.StructuredPreset,
            FollowUpOperationJournal.CreateClientMessageId(item.OperationId),
            CancellationToken.None);

        var result = await fixture.Reconciler.ReconcileAsync(fixture.Settings, CancellationToken.None);
        Ensure(!result.IsHealthy, "materializing journal conflict was accepted");
        Ensure(
            result.Status == AttachmentPresentationReconciliationStatus.MaterializingJournalConflict,
            "materializing journal conflict returned the wrong status");
        Ensure(Directory.Exists(item.LeaseDirectory), "conflicting materializing lease was deleted");
    }

    private static async Task TestCorruptAuthoritiesAsync()
    {
        await AssertCorruptionBlocksCleanupAsync(
            seed: 700,
            AttachmentPresentationReconciliationStatus.PresentationAuthorityUnavailable,
            async (fixture, item) =>
                await File.WriteAllTextAsync(
                    Path.Combine(item.Lease.LeaseDirectory, "transaction.json"),
                    "{"));
        await AssertCorruptionBlocksCleanupAsync(
            seed: 701,
            AttachmentPresentationReconciliationStatus.PresentationAuthorityUnavailable,
            async (fixture, item) =>
                await File.WriteAllTextAsync(
                    Path.Combine(item.Lease.LeaseDirectory, "transaction.previous.json"),
                    "{"));
        await AssertCorruptionBlocksCleanupAsync(
            seed: 702,
            AttachmentPresentationReconciliationStatus.SettingsUnavailable,
            async (fixture, _) => await File.WriteAllTextAsync(fixture.SettingsService.SettingsPath, "{"));
        await AssertCorruptionBlocksCleanupAsync(
            seed: 703,
            AttachmentPresentationReconciliationStatus.FollowUpJournalUnavailable,
            async (fixture, _) => await File.WriteAllTextAsync(fixture.FollowUpJournal.JournalPath, "{"));
        await AssertCorruptionBlocksCleanupAsync(
            seed: 704,
            AttachmentPresentationReconciliationStatus.RecoveryJournalUnavailable,
            async (fixture, _) => await File.WriteAllTextAsync(fixture.RecoveryJournal.JournalPath, "{"));
    }

    private static async Task AssertCorruptionBlocksCleanupAsync(
        int seed,
        AttachmentPresentationReconciliationStatus expectedStatus,
        Func<Fixture, ReadyLeaseCase, Task> corrupt)
    {
        var fixture = await Fixture.CreateAsync();
        var item = await fixture.CreateReadyLeaseAsync(seed);
        await corrupt(fixture, item);
        var result = await fixture.Reconciler.ReconcileAsync(fixture.Settings, CancellationToken.None);
        Ensure(!result.IsHealthy, $"corrupt authority {expectedStatus} was accepted");
        Ensure(result.Status == expectedStatus, $"corrupt authority returned {result.Status}");
        Ensure(Directory.Exists(item.Lease.LeaseDirectory), "corrupt authority deleted a presentation lease");
        Ensure(File.Exists(item.ManagedObject.ObjectPath), "corrupt authority deleted a managed object");
    }

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "r-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private static string Id(int value) =>
        $"00000000-0000-0000-0000-{value:D12}";

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name} - {exception.Message}");
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class Fixture
    {
        private Fixture(
            AppSettings settings,
            SettingsService settingsService,
            ManagedAttachmentStore store,
            AttachmentDraftAuthority drafts,
            FollowUpOperationJournal followUpJournal,
            RecoveryOperationJournal recoveryJournal,
            AttachmentPresentationLeaseService presentation,
            AttachmentPresentationReconciliationService reconciler)
        {
            Settings = settings;
            SettingsService = settingsService;
            Store = store;
            Drafts = drafts;
            FollowUpJournal = followUpJournal;
            RecoveryJournal = recoveryJournal;
            Presentation = presentation;
            Reconciler = reconciler;
        }

        internal AppSettings Settings { get; }

        internal SettingsService SettingsService { get; }

        internal ManagedAttachmentStore Store { get; }

        internal AttachmentDraftAuthority Drafts { get; }

        internal FollowUpOperationJournal FollowUpJournal { get; }

        internal RecoveryOperationJournal RecoveryJournal { get; }

        internal AttachmentPresentationLeaseService Presentation { get; }

        internal AttachmentPresentationReconciliationService Reconciler { get; }

        internal static async Task<Fixture> CreateAsync()
        {
            var root = CreateRoot();
            var settingsService = new SettingsService(root);
            await settingsService.SaveAsync(new AppSettings(), CancellationToken.None);
            var settings = await settingsService.LoadAsync(CancellationToken.None);
            var store = new ManagedAttachmentStore(root);
            var drafts = new AttachmentDraftAuthority();
            drafts.ReplaceVisibleDrafts(0, Array.Empty<PresetAttachmentReference>());
            var followUpJournal = new FollowUpOperationJournal(root);
            var recoveryJournal = new RecoveryOperationJournal(root);
            var presentation = new AttachmentPresentationLeaseService(root, store);
            var authority = new FollowUpAttachmentAuthorityReader(
                drafts,
                followUpJournal,
                recoveryJournal,
                presentation);
            var coordinator = new AttachmentReferenceCoordinator(
                root,
                store,
                settingsService,
                authority);
            var reconciler = new AttachmentPresentationReconciliationService(
                root,
                settingsService,
                drafts,
                followUpJournal,
                recoveryJournal,
                presentation,
                coordinator);
            return new Fixture(
                settings,
                settingsService,
                store,
                drafts,
                followUpJournal,
                recoveryJournal,
                presentation,
                reconciler);
        }

        internal async Task<ReadyLeaseCase> CreateReadyLeaseAsync(int seed)
        {
            var managedObject = await ImportPngAsync(seed);
            var reference = CreateReference(managedObject, seed, order: 0);
            var payload = StructuredPresetPayload.Create("inspect", [reference]);
            var operationId = Id(seed * 10 + 1);
            var lease = await Presentation.AcquireAsync(
                operationId,
                payload,
                new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
                {
                    [managedObject.ContentId] = managedObject
                },
                PresentationRequirements,
                CancellationToken.None);
            return new ReadyLeaseCase(
                operationId,
                Id(seed * 10 + 2),
                Id(seed * 10 + 3),
                Id(seed * 10 + 4),
                payload,
                reference,
                managedObject,
                lease);
        }

        internal async Task<MaterializingLeaseCase> CreateMaterializingLeaseAsync(int seed)
        {
            var firstObject = await ImportPngAsync(seed);
            var secondObject = await ImportPngAsync(seed + 1);
            var first = CreateReference(firstObject, seed, order: 0);
            var second = CreateReference(secondObject, seed + 1, order: 1);
            var payload = StructuredPresetPayload.Create("inspect", [first, second]);
            var operationId = Id(seed * 10 + 1);
            try
            {
                _ = await Presentation.AcquireAsync(
                    operationId,
                    payload,
                    new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
                    {
                        [firstObject.ContentId] = firstObject
                    },
                    PresentationRequirements,
                    CancellationToken.None);
            }
            catch (AttachmentPresentationException exception) when (
                string.Equals(exception.Code, "managed-object-invalid", StringComparison.Ordinal))
            {
            }

            var snapshot = Presentation.ReadReferenceSnapshotUnderMutationLease();
            Ensure(
                snapshot.IsHealthy && snapshot.References is
                [
                    {
                        State: AttachmentPresentationReferenceState.Materializing
                    }
                ],
                "materializing fixture was not created");
            var leaseDirectory = Directory.GetDirectories(
                Presentation.PresentationRoot,
                "*",
                SearchOption.TopDirectoryOnly).Single();
            return new MaterializingLeaseCase(
                operationId,
                Id(seed * 10 + 2),
                Id(seed * 10 + 3),
                Id(seed * 10 + 4),
                payload,
                [firstObject, secondObject],
                leaseDirectory);
        }

        internal async Task<FollowUpOperationRecord> CreateJournalRecordAsync(
            ReadyLeaseCase item,
            FollowUpOperationState state,
            bool completed)
        {
            var clientMessageId = FollowUpOperationJournal.CreateClientMessageId(item.OperationId);
            var record = (await FollowUpJournal.GetOrCreateStructuredAsync(
                item.OperationId,
                item.ThreadId,
                item.MessageId,
                FollowUpTriggerKind.AfterNormalCompletion,
                item.ExpectedTurnId,
                scheduledAtUtc: null,
                item.Payload,
                item.Lease.LeaseId,
                FollowUpPayloadSourceKind.StructuredPreset,
                clientMessageId,
                CancellationToken.None)).Record;

            if (state == FollowUpOperationState.Prepared)
            {
                return record;
            }

            if (state == FollowUpOperationState.Abandoned)
            {
                return (await FollowUpJournal.TryTransitionAsync(
                    item.OperationId,
                    FollowUpOperationState.Prepared,
                    FollowUpOperationState.Abandoned,
                    cancellationToken: CancellationToken.None)).Record!;
            }

            record = (await FollowUpJournal.TryTransitionAsync(
                item.OperationId,
                FollowUpOperationState.Prepared,
                FollowUpOperationState.Dispatching,
                cancellationToken: CancellationToken.None)).Record!;
            if (state == FollowUpOperationState.Dispatching)
            {
                return record;
            }

            if (state is FollowUpOperationState.Retryable or FollowUpOperationState.Uncertain)
            {
                return (await FollowUpJournal.TryTransitionAsync(
                    item.OperationId,
                    FollowUpOperationState.Dispatching,
                    state,
                    cancellationToken: CancellationToken.None)).Record!;
            }

            var successorTurnId = Id(int.Parse(item.ExpectedTurnId[^6..]) + 100_000);
            record = (await FollowUpJournal.TryTransitionAsync(
                item.OperationId,
                FollowUpOperationState.Dispatching,
                FollowUpOperationState.Confirmed,
                successorTurnId,
                CancellationToken.None)).Record!;
            if (completed)
            {
                var completionTurnId = Id(int.Parse(item.ExpectedTurnId[^6..]) + 200_000);
                record = await FollowUpJournal.MarkCompletedAsync(
                    item.ThreadId,
                    completionTurnId,
                    successorTurnId,
                    CancellationToken.None) ?? throw new InvalidOperationException(
                    "confirmed fixture completion was not recorded");
            }

            return record;
        }

        private async Task<ManagedAttachmentObject> ImportPngAsync(int seed)
        {
            var sourceBytes = Convert.FromBase64String(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
            var bytes = sourceBytes.Concat(new[] { unchecked((byte)seed) }).ToArray();
            await using var stream = new MemoryStream(bytes, writable: false);
            return await Store.ImportBytesAsync(
                stream,
                $"image-{seed}.png",
                new AttachmentLimitSettings(),
                CancellationToken.None);
        }

        private static PresetAttachmentReference CreateReference(
            ManagedAttachmentObject managedObject,
            int seed,
            int order) =>
            new()
            {
                Id = Id(seed * 10 + 5 + order),
                ContentId = managedObject.ContentId,
                OriginalFileName = $"image-{seed}.png",
                DetectedType = managedObject.DetectedType,
                OwnerInputKind = "local_image",
                ByteLength = managedObject.ByteLength,
                Order = order
            };
    }

    private sealed record ReadyLeaseCase(
        string OperationId,
        string ThreadId,
        string MessageId,
        string ExpectedTurnId,
        StructuredPresetPayload Payload,
        PresetAttachmentReference Reference,
        ManagedAttachmentObject ManagedObject,
        AttachmentPresentationLease Lease);

    private sealed record MaterializingLeaseCase(
        string OperationId,
        string ThreadId,
        string MessageId,
        string ExpectedTurnId,
        StructuredPresetPayload Payload,
        IReadOnlyList<ManagedAttachmentObject> ManagedObjects,
        string LeaseDirectory);
}
