using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

internal static class StructuredFollowUpOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "structured payload digest binds normalized body and ordered attachment semantics",
            TestPayloadDigest,
            assert);
        RunCase(
            "structured payload rejects ambiguous identity and accepts attachment-only input",
            TestPayloadValidation,
            assert);
        RunCase(
            "semantic capability ignores package version and invalidates relevant handler drift",
            TestSemanticCapabilityFingerprint,
            assert);
        RunCase(
            "semantic capability fails closed on incomplete or active-probe evidence",
            TestSemanticCapabilityFailureStates,
            assert);
        RunCase(
            "structured requirements enforce kind attachment-only count and byte capacities",
            TestCapabilityRequirements,
            assert);
        RunCase(
            "capability leases bind epoch semantic fingerprint and payload identity",
            TestCapabilityLease,
            assert);
        RunCase(
            "Desktop encoder emits text then localImage with exact ordered presentation paths",
            TestStructuredEncoder,
            assert);
        RunCase(
            "Desktop encoder omits fake text and rejects unsupported or missing inputs",
            TestStructuredEncoderFailures,
            assert);
        await RunCaseAsync(
            "Desktop typed structured start-turn validates capability leases before native transport",
            TestDesktopStructuredStartTurnContractAsync,
            assert);
        await RunCaseAsync(
            "presentation leases reuse verified objects or materialize deterministic suffix paths",
            TestPresentationLeaseMaterializationAsync,
            assert);
        await RunCaseAsync(
            "presentation cleanup requires lineage and zero-reference proof and remains pending on locks",
            TestPresentationLeaseCleanupAsync,
            assert);
        await RunCaseAsync(
            "presentation acquisition recovers a crash-left materializing transaction without duplication",
            TestPresentationCrashRecoveryAsync,
            assert);
        RunCase(
            "presentation references remain pinned through uncertain and incomplete successor states",
            TestPresentationRetentionStates,
            assert);
        await RunCaseAsync(
            "attachment cleanup authority combines durable leases journals and successor closure",
            TestAttachmentAuthorityCompositionAsync,
            assert);
        await RunCaseAsync(
            "follow-up journal schema two persists structured payload lease and successor identity",
            TestStructuredJournalSchemaTwoAsync,
            assert);
        await RunCaseAsync(
            "follow-up journal migrates schema one text without fabricating structured identity",
            TestLegacyJournalMigrationAsync,
            assert);
    }

    private static void TestPayloadDigest()
    {
        var first = CreateAttachment(
            id: "00000000-0000-0000-0000-000000000001",
            contentId: new string('A', 64),
            fileName: "first.png",
            detectedType: "image/png",
            ownerInputKind: "local_image",
            byteLength: 4,
            order: 0);
        var second = CreateAttachment(
            id: "00000000-0000-0000-0000-000000000002",
            contentId: new string('B', 64),
            fileName: "second.png",
            detectedType: "image/png",
            ownerInputKind: "local_image",
            byteLength: 8,
            order: 1);

        var baseline = StructuredPresetPayload.Create("  inspect  ", [first, second]);
        var repeated = StructuredPresetPayload.Create("inspect", [first, second]);
        Ensure(
            baseline.SchemaVersion == StructuredPresetPayload.CurrentSchemaVersion,
            "payload schema changed");
        Ensure(baseline.Text == "inspect", "payload body was not normalized");
        Ensure(
            baseline.PayloadDigest == repeated.PayloadDigest,
            "stable payload serialization changed");
        Ensure(IsSha256(baseline.PayloadDigest), "payload digest is not canonical SHA-256");

        var reordered = StructuredPresetPayload.Create(
            "inspect",
            [first with { Order = 1 }, second with { Order = 0 }]);
        Ensure(
            baseline.PayloadDigest != reordered.PayloadDigest,
            "attachment order did not change the digest");
        Ensure(
            baseline.PayloadDigest != StructuredPresetPayload.Create("inspect again", [first, second]).PayloadDigest,
            "body did not change the digest");
        Ensure(
            baseline.PayloadDigest != StructuredPresetPayload.Create(
                "inspect",
                [first with { OriginalFileName = "renamed.png" }, second]).PayloadDigest,
            "filename did not change the digest");
        Ensure(
            baseline.PayloadDigest != StructuredPresetPayload.Create(
                "inspect",
                [first with { DetectedType = "image/jpeg" }, second]).PayloadDigest,
            "detected type did not change the digest");
        Ensure(
            baseline.PayloadDigest != StructuredPresetPayload.Create(
                "inspect",
                [first with { ByteLength = 5 }, second]).PayloadDigest,
            "byte length did not change the digest");
        Ensure(
            baseline.PayloadDigest != StructuredPresetPayload.Create(
                "inspect",
                [first with { OwnerInputKind = "local_file" }, second]).PayloadDigest,
            "owner input kind did not change the digest");
    }

    private static void TestPayloadValidation()
    {
        var attachment = CreateImageAttachment();
        var attachmentOnly = StructuredPresetPayload.Create(null, [attachment]);
        Ensure(attachmentOnly.Text.Length == 0, "attachment-only payload fabricated text");
        Ensure(attachmentOnly.Attachments.Count == 1, "attachment-only payload lost its reference");

        AssertThrows<ArgumentException>(
            () => StructuredPresetPayload.Create(" ", []),
            "empty structured payload was accepted");
        AssertThrows<ArgumentException>(
            () => StructuredPresetPayload.Create(
                "inspect",
                [attachment, attachment with { Order = 1 }]),
            "duplicate reference id was accepted");
        AssertThrows<ArgumentException>(
            () => StructuredPresetPayload.Create(
                "inspect",
                [attachment with { ContentId = attachment.ContentId.ToLowerInvariant() }]),
            "noncanonical content id was accepted");
        AssertThrows<ArgumentException>(
            () => StructuredPresetPayload.Create(
                "inspect",
                [attachment with { OriginalFileName = "..\\unsafe.png" }]),
            "unsafe original filename was accepted");
    }

    private static void TestSemanticCapabilityFingerprint()
    {
        var first = CodexStructuredInputCapabilityInspector.Inspect(CreateSemanticSnapshot());
        var versionOnly = CodexStructuredInputCapabilityInspector.Inspect(
            CreateSemanticSnapshot() with { PackageVersion = "99.0.0" });
        Ensure(first.State == StructuredInputCapabilityState.Supported, "semantic profile was not supported");
        Ensure(
            first.SupportedInputKinds.SetEquals(["text", "local_image"]),
            "semantic profile exposed the wrong internal input kinds");
        Ensure(
            first.SemanticFingerprint == versionOnly.SemanticFingerprint,
            "package version changed the semantic fingerprint");

        var changedHandler = CodexStructuredInputCapabilityInspector.Inspect(
            CreateSemanticSnapshot() with
            {
                HandlerShapeSha256 = new string('C', 64)
            });
        Ensure(
            first.SemanticFingerprint != changedHandler.SemanticFingerprint,
            "relevant handler drift did not invalidate the semantic fingerprint");
    }

    private static void TestSemanticCapabilityFailureStates()
    {
        var malformed = CodexStructuredInputCapabilityInspector.Inspect(
            CreateSemanticSnapshot() with { HandlerShapeSha256 = "not-a-hash" });
        Ensure(malformed.State == StructuredInputCapabilityState.Unknown, "malformed evidence did not stay unknown");

        var activeProbe = CodexStructuredInputCapabilityInspector.Inspect(
            CreateSemanticSnapshot() with
            {
                Acquisition = StructuredInputEvidenceAcquisition.ActiveSendProbe
            });
        Ensure(activeProbe.State == StructuredInputCapabilityState.Unknown, "active send evidence granted capability");

        var missingOwner = CodexStructuredInputCapabilityInspector.Inspect(
            CreateSemanticSnapshot() with { StartTurnAssertsOwner = false });
        Ensure(missingOwner.State == StructuredInputCapabilityState.Unsupported, "missing owner assertion was not rejected");

        var missingMethod = CodexStructuredInputCapabilityInspector.Inspect(
            CreateSemanticSnapshot() with
            {
                FollowerMethods = new HashSet<string>(StringComparer.Ordinal)
                {
                    "thread-follower-load-complete-history"
                }
            });
        Ensure(missingMethod.State == StructuredInputCapabilityState.Unsupported, "missing start-turn handler was not rejected");
    }

    private static void TestCapabilityRequirements()
    {
        var image = CreateImageAttachment();
        var localFile = image with { OwnerInputKind = "local_file" };
        var textAndImage = StructuredPresetPayload.Create("inspect", [image]);
        var secondImage = image with
        {
            Id = "00000000-0000-0000-0000-000000000011",
            ContentId = new string('F', 64),
            OriginalFileName = "second.png",
            Order = 1
        };
        var textAndTwoImages = StructuredPresetPayload.Create("inspect", [image, secondImage]);
        var attachmentOnly = StructuredPresetPayload.Create(null, [image]);
        var unsupportedKind = StructuredPresetPayload.Create("inspect", [localFile]);
        var supported = CreateSupportedCapabilities();

        Ensure(supported.Evaluate(textAndImage).IsSatisfied, "valid text and image payload was rejected");
        Ensure(
            supported.Evaluate(unsupportedKind).Code == "unsupported-input-kind",
            "generic local file did not fail closed");
        Ensure(
            (supported with { SupportsAttachmentOnly = false }).Evaluate(attachmentOnly).Code ==
            "attachment-only-unsupported",
            "attachment-only capacity was ignored");
        Ensure(
            (supported with { MaximumAttachmentCount = 0 }).Evaluate(textAndImage).Code ==
            "attachment-count-exceeded",
            "attachment count capacity was ignored");
        Ensure(
            (supported with { MaximumBytesPerFile = image.ByteLength - 1 }).Evaluate(textAndImage).Code ==
            "attachment-file-bytes-exceeded",
            "per-file capacity was ignored");
        Ensure(
            (supported with
            {
                MaximumBytesPerFile = image.ByteLength,
                MaximumBytesPerPayload = image.ByteLength * 2 - 1
            }).Evaluate(textAndTwoImages).Code ==
            "attachment-payload-bytes-exceeded",
            "payload byte capacity was ignored");
        Ensure(
            (supported with { State = StructuredInputCapabilityState.Unknown }).Evaluate(textAndImage).Code ==
            "capability-unknown",
            "unknown capability did not fail closed");
    }

    private static void TestCapabilityLease()
    {
        var payload = StructuredPresetPayload.Create("inspect", [CreateImageAttachment()]);
        var capabilities = CreateSupportedCapabilities();
        var lease = capabilities.AcquireLease(payload);
        Ensure(capabilities.Matches(lease, payload), "fresh capability lease did not match");
        Ensure(
            !(capabilities with { Epoch = capabilities.Epoch + 1 }).Matches(lease, payload),
            "epoch drift did not invalidate the capability lease");
        Ensure(
            !(capabilities with { SemanticFingerprint = new string('D', 64) }).Matches(lease, payload),
            "semantic drift did not invalidate the capability lease");
        Ensure(
            !capabilities.Matches(lease, StructuredPresetPayload.Create("changed", [CreateImageAttachment()])),
            "payload drift did not invalidate the capability lease");
    }

    private static void TestStructuredEncoder()
    {
        var image = CreateImageAttachment();
        var payload = StructuredPresetPayload.Create("inspect", [image]);
        var encoded = new DesktopStructuredInputEncoder().Encode(
            payload,
            CreateSupportedCapabilities(),
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [image.Id] = "D:\\CodexData\\CodexGuardian\\attachments\\image.png"
            });

        Ensure(encoded.ValueKind == JsonValueKind.Array, "native input is not an array");
        Ensure(encoded.GetArrayLength() == 2, "native input item count changed");
        var text = encoded[0];
        Ensure(text.GetProperty("type").GetString() == "text", "body item is not first");
        Ensure(text.GetProperty("text").GetString() == "inspect", "body text changed");
        Ensure(text.GetProperty("text_elements").GetArrayLength() == 0, "body text elements changed");
        var localImage = encoded[1];
        Ensure(localImage.GetProperty("type").GetString() == "localImage", "local_image was not mapped to localImage");
        Ensure(
            localImage.GetProperty("path").GetString() ==
            "D:\\CodexData\\CodexGuardian\\attachments\\image.png",
            "presentation path changed");
    }

    private static void TestStructuredEncoderFailures()
    {
        var image = CreateImageAttachment();
        var attachmentOnly = StructuredPresetPayload.Create(null, [image]);
        var encoder = new DesktopStructuredInputEncoder();
        var paths = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [image.Id] = "D:\\CodexData\\CodexGuardian\\attachments\\image.png"
        };
        var encoded = encoder.Encode(attachmentOnly, CreateSupportedCapabilities(), paths);
        Ensure(encoded.GetArrayLength() == 1, "attachment-only input emitted a fake text item");
        Ensure(encoded[0].GetProperty("type").GetString() == "localImage", "attachment-only item changed kind");

        var unknown = CreateSupportedCapabilities() with { State = StructuredInputCapabilityState.Unknown };
        AssertEncodingFailure(
            "capability-unknown",
            () => encoder.Encode(attachmentOnly, unknown, paths));
        AssertEncodingFailure(
            "presentation-path-missing",
            () => encoder.Encode(
                attachmentOnly,
                CreateSupportedCapabilities(),
                new Dictionary<string, string>(StringComparer.Ordinal)));

        var localFile = StructuredPresetPayload.Create(
            "inspect",
            [image with { OwnerInputKind = "local_file" }]);
        AssertEncodingFailure(
            "unsupported-input-kind",
            () => encoder.Encode(localFile, CreateSupportedCapabilities(), paths));
    }

    private static async Task TestDesktopStructuredStartTurnContractAsync()
    {
        var root = CreatePresentationTestRoot();
        Directory.CreateDirectory(root);
        using var log = new GuardianLog(root);
        var encoder = new RecordingStructuredInputEncoder();
        await using var client = new DesktopIpcClient(log, encoder);
        var image = CreateImageAttachment();
        var payload = StructuredPresetPayload.Create("inspect", [image]);
        var capabilities = CreateSupportedCapabilities();
        var lease = capabilities.AcquireLease(payload);
        var paths = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [image.Id] = "D:\\CodexData\\CodexGuardian\\attachments\\image.png"
        };

        var input = client.EncodeStructuredTurnInput(payload, capabilities, lease, paths);
        Ensure(
            encoder.CallCount == 1 &&
            ReferenceEquals(encoder.LastPayload, payload) &&
            ReferenceEquals(encoder.LastCapabilities, capabilities) &&
            ReferenceEquals(encoder.LastPresentationPaths, paths) &&
            input.ValueKind == JsonValueKind.Array &&
            input.GetArrayLength() == 1,
            "typed Desktop structured input bypassed or changed the encoder contract");

        try
        {
            _ = client.EncodeStructuredTurnInput(
                payload,
                capabilities,
                lease with { Epoch = checked(lease.Epoch + 1) },
                paths);
        }
        catch (DesktopStructuredInputCapabilityException exception)
        {
            Ensure(exception.Code == "capability-lease-stale", "stale lease failure code changed");
            Ensure(encoder.CallCount == 1, "a stale capability lease reached the native encoder");
            return;
        }

        throw new InvalidOperationException("A stale capability lease was accepted.");
    }

    private static async Task TestPresentationLeaseMaterializationAsync()
    {
        var root = CreatePresentationTestRoot();
        var store = new ManagedAttachmentStore(root);
        var imported = await ImportPngAsync(store);
        var first = CreateReference(imported, "CON.png", 0);
        var second = CreateReference(
            imported,
            "CON.png",
            1,
            "00000000-0000-0000-0000-000000000021");
        var payload = StructuredPresetPayload.Create("inspect", [first, second]);
        var objects = new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
        {
            [imported.ContentId] = imported
        };
        var service = new AttachmentPresentationLeaseService(root, store);

        var direct = await service.AcquireAsync(
            "00000000-0000-0000-0000-000000000101",
            payload,
            objects,
            new AttachmentPresentationRequirements(
                SupportsSeparateDisplayName: true,
                RequiresFileNameSuffix: false,
                AllowHardLinks: false),
            CancellationToken.None);
        Ensure(
            direct.PresentationPaths.Values.All(path => path == imported.ObjectPath),
            "display-name-capable owner did not reuse the immutable object path");
        Ensure(await service.VerifyAsync(direct, payload, CancellationToken.None), "direct lease did not reverify");

        var materialized = await service.AcquireAsync(
            "00000000-0000-0000-0000-000000000102",
            payload,
            objects,
            new AttachmentPresentationRequirements(
                SupportsSeparateDisplayName: false,
                RequiresFileNameSuffix: true,
                AllowHardLinks: false),
            CancellationToken.None);
        var materializedPaths = materialized.PresentationPaths.Values.ToArray();
        Ensure(materializedPaths.Length == 2, "materialized lease lost a reference");
        Ensure(
            materializedPaths.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 2,
            "same-name references collided");
        Ensure(
            materializedPaths.All(path =>
                path.StartsWith(service.PresentationRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(Path.GetExtension(path), ".png", StringComparison.OrdinalIgnoreCase) &&
                File.Exists(path)),
            "suffix presentation paths were not bounded under the lease root");
        Ensure(
            materializedPaths.All(path =>
                !Path.GetFileNameWithoutExtension(path).Equals("CON", StringComparison.OrdinalIgnoreCase)),
            "reserved filenames were not normalized");
        Ensure(await service.VerifyAsync(materialized, payload, CancellationToken.None), "materialized lease did not reverify");

        var tamperedPath = materializedPaths[0];
        File.SetAttributes(tamperedPath, FileAttributes.Normal);
        await File.AppendAllTextAsync(tamperedPath, "tamper");
        Ensure(
            !await service.VerifyAsync(materialized, payload, CancellationToken.None),
            "materialized hash drift was accepted");
    }

    private static async Task TestPresentationLeaseCleanupAsync()
    {
        var root = CreatePresentationTestRoot();
        var store = new ManagedAttachmentStore(root);
        var imported = await ImportPngAsync(store);
        var reference = CreateReference(imported, "image.png", 0);
        var payload = StructuredPresetPayload.Create(null, [reference]);
        var service = new AttachmentPresentationLeaseService(root, store);
        var lease = await service.AcquireAsync(
            "00000000-0000-0000-0000-000000000103",
            payload,
            new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
            {
                [imported.ContentId] = imported
            },
            new AttachmentPresentationRequirements(
                SupportsSeparateDisplayName: false,
                RequiresFileNameSuffix: true,
                AllowHardLinks: false),
            CancellationToken.None);

        var retained = await service.CleanupAsync(
            lease.LeaseId,
            new AttachmentPresentationCleanupAuthorization(
                RecoveryLineageClosed: false,
                ZeroReferenceProven: true),
            CancellationToken.None);
        Ensure(retained.Status == AttachmentPresentationCleanupStatus.Retained, "open lineage was cleaned");

        var presentationPath = lease.PresentationPaths[reference.Id];
        await using (var locked = new FileStream(
                         presentationPath,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.None))
        {
            var pending = await service.CleanupAsync(
                lease.LeaseId,
                new AttachmentPresentationCleanupAuthorization(
                    RecoveryLineageClosed: true,
                    ZeroReferenceProven: true),
                CancellationToken.None);
            Ensure(
                pending.Status == AttachmentPresentationCleanupStatus.CleanupPending,
                "locked presentation file reported false deletion");
            Ensure(Directory.Exists(lease.LeaseDirectory), "pending cleanup removed the lease directory");
        }

        var deleted = await service.CleanupAsync(
            lease.LeaseId,
            new AttachmentPresentationCleanupAuthorization(
                RecoveryLineageClosed: true,
                ZeroReferenceProven: true),
            CancellationToken.None);
        Ensure(deleted.Status == AttachmentPresentationCleanupStatus.Deleted, "unlocked lease was not deleted");
        Ensure(!Directory.Exists(lease.LeaseDirectory), "deleted lease directory remained");
        Ensure(File.Exists(imported.ObjectPath), "presentation cleanup deleted the managed object");
    }

    private static async Task TestPresentationCrashRecoveryAsync()
    {
        var root = CreatePresentationTestRoot();
        var store = new ManagedAttachmentStore(root);
        var firstObject = await ImportPngAsync(store);
        var secondObject = await ImportPngAsync(store, appendByte: 0x42, fileName: "second.png");
        var first = CreateReference(firstObject, "first.png", 0);
        var second = CreateReference(
            secondObject,
            "second.png",
            1,
            "00000000-0000-0000-0000-000000000022");
        var payload = StructuredPresetPayload.Create("inspect", [first, second]);
        var service = new AttachmentPresentationLeaseService(root, store);
        var operationId = "00000000-0000-0000-0000-000000000104";
        var requirements = new AttachmentPresentationRequirements(
            SupportsSeparateDisplayName: false,
            RequiresFileNameSuffix: true,
            AllowHardLinks: false);

        await AssertPresentationFailureAsync(
            "managed-object-invalid",
            () => service.AcquireAsync(
                operationId,
                payload,
                new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
                {
                    [firstObject.ContentId] = firstObject
                },
                requirements,
                CancellationToken.None));
        var incompleteDirectories = Directory.GetDirectories(
            service.PresentationRoot,
            "*",
            SearchOption.TopDirectoryOnly);
        Ensure(incompleteDirectories.Length == 1, "materializing failure created duplicate lease directories");
        Ensure(
            File.Exists(Path.Combine(incompleteDirectories[0], "transaction.json")),
            "materializing failure lost its durable transaction");
        var materializingSnapshot = service.ReadReferenceSnapshotUnderMutationLease();
        Ensure(
            materializingSnapshot.IsHealthy &&
            materializingSnapshot.LeaseVersion == 0 &&
            materializingSnapshot.TransactionVersion > 0 &&
            materializingSnapshot.References is
            [
                {
                    State: AttachmentPresentationReferenceState.Materializing,
                    ContentIds.Count: 2
                }
            ],
            "materializing presentation authority was not pinned");

        var recovered = await service.AcquireAsync(
            operationId,
            payload,
            new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
            {
                [firstObject.ContentId] = firstObject,
                [secondObject.ContentId] = secondObject
            },
            requirements,
            CancellationToken.None);
        Ensure(
            Directory.GetDirectories(service.PresentationRoot, "*", SearchOption.TopDirectoryOnly).Length == 1,
            "materializing recovery created a second lease directory");
        Ensure(
            await service.VerifyAsync(recovered, payload, CancellationToken.None),
            "recovered presentation lease did not verify");
        var readySnapshot = service.ReadReferenceSnapshotUnderMutationLease();
        Ensure(
            readySnapshot.IsHealthy &&
            readySnapshot.LeaseVersion > 0 &&
            readySnapshot.TransactionVersion == 0 &&
            readySnapshot.References is
            [
                {
                    State: AttachmentPresentationReferenceState.Ready,
                    ContentIds.Count: 2
                }
            ],
            "ready presentation authority was not projected");
    }

    private static void TestPresentationRetentionStates()
    {
        var contentId = new string('A', 64);
        foreach (var state in new[]
                 {
                     AttachmentOperationReferenceState.Prepared,
                     AttachmentOperationReferenceState.Dispatching,
                     AttachmentOperationReferenceState.Retryable,
                     AttachmentOperationReferenceState.Uncertain
                 })
        {
            Ensure(
                AttachmentReferenceCoordinator.IsOperationReferencePinned(
                    new AttachmentOperationReference(contentId, state, false, false),
                    contentId),
                $"{state} presentation reference was not pinned");
        }

        Ensure(
            AttachmentReferenceCoordinator.IsOperationReferencePinned(
                new AttachmentOperationReference(
                    contentId,
                    AttachmentOperationReferenceState.Confirmed,
                    SuccessorCompletedNormally: false,
                    RecoveryLineageClosed: false),
                contentId),
            "incomplete confirmed successor did not retain its presentation reference");
        Ensure(
            !AttachmentReferenceCoordinator.IsOperationReferencePinned(
                new AttachmentOperationReference(
                    contentId,
                    AttachmentOperationReferenceState.Confirmed,
                    SuccessorCompletedNormally: true,
                    RecoveryLineageClosed: false),
                contentId),
            "normally completed successor retained its presentation reference");
        Ensure(
            !AttachmentReferenceCoordinator.IsOperationReferencePinned(
                new AttachmentOperationReference(
                    contentId,
                    AttachmentOperationReferenceState.Confirmed,
                    SuccessorCompletedNormally: false,
                    RecoveryLineageClosed: true),
                contentId),
            "closed recovery lineage retained its presentation reference");
    }

    private static async Task TestAttachmentAuthorityCompositionAsync()
    {
        var root = CreatePresentationTestRoot();
        var store = new ManagedAttachmentStore(root);
        var imported = await ImportPngAsync(store);
        var attachment = CreateReference(imported, "authority.png", 0);
        var payload = StructuredPresetPayload.Create("inspect", [attachment]);
        var operationId = "00000000-0000-0000-0000-000000000121";
        var threadId = "00000000-0000-0000-0000-000000000122";
        var messageId = "00000000-0000-0000-0000-000000000123";
        var expectedTurnId = "00000000-0000-0000-0000-000000000124";
        var clientMessageId = "00000000-0000-0000-0000-000000000125";
        var successorTurnId = "00000000-0000-0000-0000-000000000126";
        var presentation = new AttachmentPresentationLeaseService(root, store);
        var lease = await presentation.AcquireAsync(
            operationId,
            payload,
            new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
            {
                [imported.ContentId] = imported
            },
            new AttachmentPresentationRequirements(
                SupportsSeparateDisplayName: true,
                RequiresFileNameSuffix: false,
                AllowHardLinks: false),
            CancellationToken.None);
        var followUpJournal = new FollowUpOperationJournal(root);
        var recoveryJournal = new RecoveryOperationJournal(root);
        var drafts = new AttachmentDraftAuthority();
        drafts.ReplaceVisibleDrafts(0, Array.Empty<PresetAttachmentReference>());
        var reader = new FollowUpAttachmentAuthorityReader(
            drafts,
            followUpJournal,
            recoveryJournal,
            presentation);

        var orphan = await reader.ReadAsync(CancellationToken.None);
        Ensure(!orphan.IsHealthy, "an orphan ready presentation lease authorized cleanup");

        await followUpJournal.GetOrCreateStructuredAsync(
            operationId,
            threadId,
            messageId,
            FollowUpTriggerKind.AfterNormalCompletion,
            expectedTurnId,
            scheduledAtUtc: null,
            payload,
            lease.LeaseId,
            FollowUpPayloadSourceKind.StructuredPreset,
            clientMessageId);
        var prepared = await reader.ReadAsync(CancellationToken.None);
        Ensure(
            prepared.IsHealthy &&
            prepared.FollowUpJournalGeneration > 0 &&
            prepared.RecoveryJournalGeneration == 0 &&
            prepared.LeaseVersion > 0 &&
            prepared.TransactionVersion == 0 &&
            prepared.LeaseContentIds.SequenceEqual([imported.ContentId]) &&
            prepared.Operations is
            [
                {
                    State: AttachmentOperationReferenceState.Prepared,
                    SuccessorCompletedNormally: false,
                    RecoveryLineageClosed: false
                }
            ],
            "prepared structured operation was absent from cleanup authority");

        var settingsService = new SettingsService(root);
        var coordinator = new AttachmentReferenceCoordinator(
            root,
            store,
            settingsService,
            reader);
        Ensure(
            await coordinator.TryCreateZeroReferenceProofAsync(
                imported.ContentId,
                CancellationToken.None) is null,
            "a prepared structured operation allowed managed-object cleanup");

        await followUpJournal.TryTransitionAsync(
            operationId,
            FollowUpOperationState.Prepared,
            FollowUpOperationState.Dispatching);
        await followUpJournal.TryTransitionAsync(
            operationId,
            FollowUpOperationState.Dispatching,
            FollowUpOperationState.Confirmed,
            newTurnId: successorTurnId);
        var confirmed = await reader.ReadAsync(CancellationToken.None);
        Ensure(
            confirmed.LeaseContentIds.SequenceEqual([imported.ContentId]) &&
            confirmed.Operations is
            [
                {
                    State: AttachmentOperationReferenceState.Confirmed,
                    SuccessorCompletedNormally: false
                }
            ],
            "an incomplete confirmed successor released its cleanup pin");

        await followUpJournal.MarkCompletedAsync(
            threadId,
            successorTurnId,
            recoveredFromTurnId: null);
        var completed = await reader.ReadAsync(CancellationToken.None);
        Ensure(
            completed.IsHealthy &&
            completed.LeaseContentIds.Count == 0 &&
            completed.Operations is
            [
                {
                    State: AttachmentOperationReferenceState.Confirmed,
                    SuccessorCompletedNormally: true
                }
            ],
            "normal successor completion did not release the journal lease pin");
        Ensure(
            await coordinator.TryCreateZeroReferenceProofAsync(
                imported.ContentId,
                CancellationToken.None) is not null,
            "closed structured lineage did not permit a fresh zero-reference proof");
    }

    private static async Task TestStructuredJournalSchemaTwoAsync()
    {
        var root = CreateJournalTestRoot();
        var journal = new FollowUpOperationJournal(root);
        var threadId = "00000000-0000-0000-0000-000000000201";
        var messageId = "00000000-0000-0000-0000-000000000202";
        var expectedTurnId = "00000000-0000-0000-0000-000000000203";
        var attachment = CreateImageAttachment();
        var payload = StructuredPresetPayload.Create("inspect", [attachment]);
        var operationId = FollowUpOperationJournal.CreateStructuredOperationId(
            threadId,
            messageId,
            expectedTurnId,
            payload.PayloadDigest);
        var clientMessageId = FollowUpOperationJournal.CreateClientMessageId(operationId);
        var leaseId = new string('A', 32);

        var prepared = await journal.GetOrCreateStructuredAsync(
            operationId,
            threadId,
            messageId,
            FollowUpTriggerKind.AfterNormalCompletion,
            expectedTurnId,
            scheduledAtUtc: null,
            payload,
            leaseId,
            FollowUpPayloadSourceKind.StructuredPreset,
            clientMessageId,
            CancellationToken.None);
        Ensure(prepared.Created, "structured journal record was not created");
        Ensure(prepared.Record.MessageHash is null, "structured record retained a legacy message hash");
        Ensure(
            prepared.Record.PayloadSchemaVersion == StructuredPresetPayload.CurrentSchemaVersion &&
            prepared.Record.PayloadDigest == payload.PayloadDigest,
            "structured payload identity was not persisted");
        Ensure(
            prepared.Record.AttachmentContentIds.SequenceEqual([attachment.ContentId]),
            "ordered attachment content ids changed");
        Ensure(prepared.Record.PresentationLeaseId == leaseId, "presentation lease id was not persisted");
        Ensure(
            prepared.Record.SourceKind == FollowUpPayloadSourceKind.StructuredPreset,
            "structured source kind changed");

        using (var document = JsonDocument.Parse(await File.ReadAllTextAsync(journal.JournalPath)))
        {
            Ensure(
                document.RootElement.GetProperty("schemaVersion").GetInt32() == 2,
                "structured journal did not write schema two");
        }

        var changedPayload = StructuredPresetPayload.Create("changed", [attachment]);
        await ThrowsAsync<InvalidOperationException>(() => journal.GetOrCreateStructuredAsync(
            operationId,
            threadId,
            messageId,
            FollowUpTriggerKind.AfterNormalCompletion,
            expectedTurnId,
            scheduledAtUtc: null,
            changedPayload,
            leaseId,
            FollowUpPayloadSourceKind.StructuredPreset,
            clientMessageId,
            CancellationToken.None));

        _ = await journal.TryTransitionAsync(
            operationId,
            FollowUpOperationState.Prepared,
            FollowUpOperationState.Dispatching,
            cancellationToken: CancellationToken.None);
        var newTurnId = "00000000-0000-0000-0000-000000000204";
        var confirmed = await journal.TryTransitionAsync(
            operationId,
            FollowUpOperationState.Dispatching,
            FollowUpOperationState.Confirmed,
            newTurnId,
            CancellationToken.None);
        Ensure(confirmed.Changed && confirmed.Record?.NewTurnId == newTurnId, "successor turn was not persisted");
        var completionTurnId = "00000000-0000-0000-0000-000000000205";
        var completed = await journal.MarkCompletedAsync(
            threadId,
            completionTurnId,
            newTurnId,
            CancellationToken.None);
        Ensure(completed?.CompletionTurnId == completionTurnId, "completion turn was not persisted");

        var restarted = new FollowUpOperationJournal(root);
        var snapshot = await restarted.ReadAsync(CancellationToken.None);
        Ensure(snapshot.ReadStatus == FollowUpJournalReadStatus.Healthy, "schema two did not reload healthy");
        Ensure(
            snapshot.Records.Single().PayloadDigest == payload.PayloadDigest &&
            snapshot.Records.Single().CompletionTurnId == completionTurnId,
            "schema two restart lost structured or successor identity");
    }

    private static async Task TestLegacyJournalMigrationAsync()
    {
        var root = CreateJournalTestRoot();
        Directory.CreateDirectory(root);
        var operationId = "00000000-0000-0000-0000-000000000211";
        var threadId = "00000000-0000-0000-0000-000000000212";
        var messageId = "00000000-0000-0000-0000-000000000213";
        var expectedTurnId = "00000000-0000-0000-0000-000000000214";
        var clientMessageId = "00000000-0000-0000-0000-000000000215";
        var now = DateTimeOffset.Parse("2026-08-15T00:00:00+08:00");
        var legacyRecord = new LegacyFollowUpRecordFixture(
            operationId,
            threadId,
            messageId,
            FollowUpTriggerKind.AfterNormalCompletion,
            expectedTurnId,
            ScheduledAtUtc: null,
            FollowUpOperationJournal.ComputeMessageHash("legacy"),
            FollowUpOperationState.Dispatching,
            clientMessageId,
            NewTurnId: null,
            CompletionTurnId: null,
            CreatedAt: now,
            UpdatedAt: now,
            AttemptCount: 1);
        await WriteLegacyJournalAsync(
            Path.Combine(root, "follow-up-operations.json"),
            generation: 4,
            requiresConservativeRecovery: false,
            [legacyRecord]);

        var journal = new FollowUpOperationJournal(root);
        var snapshot = await journal.ReadAsync(CancellationToken.None);
        Ensure(snapshot.ReadStatus == FollowUpJournalReadStatus.Healthy, "legacy schema did not load healthy");
        var migrated = snapshot.Records.Single();
        Ensure(migrated.SourceKind == FollowUpPayloadSourceKind.LegacyText, "legacy source kind changed");
        Ensure(migrated.PayloadSchemaVersion is null, "legacy record fabricated a payload schema");
        Ensure(migrated.PayloadDigest is null, "legacy record fabricated a payload digest");
        Ensure(migrated.AttachmentContentIds.Count == 0, "legacy record fabricated attachments");
        Ensure(migrated.PresentationLeaseId is null, "legacy record fabricated a presentation lease");
        Ensure(migrated.MessageHash == legacyRecord.MessageHash, "legacy message hash changed");
        Ensure(
            migrated.State == FollowUpOperationState.Uncertain,
            "legacy dispatching state did not migrate conservatively");
    }

    private static string CreateJournalTestRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "journal-" + Guid.NewGuid().ToString("N"));
    }

    private static async Task WriteLegacyJournalAsync(
        string path,
        long generation,
        bool requiresConservativeRecovery,
        IReadOnlyList<LegacyFollowUpRecordFixture> records)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false
        };
        var integrity = new LegacyJournalIntegrityFixture(
            SchemaVersion: 1,
            generation,
            requiresConservativeRecovery,
            records);
        var checksum = Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(integrity, options)));
        var document = new LegacyJournalDocumentFixture(
            SchemaVersion: 1,
            generation,
            requiresConservativeRecovery,
            checksum,
            records);
        await File.WriteAllBytesAsync(path, JsonSerializer.SerializeToUtf8Bytes(document, options));
    }

    private static string CreatePresentationTestRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "presentation-" + Guid.NewGuid().ToString("N"));
    }

    private static async Task<ManagedAttachmentObject> ImportPngAsync(
        ManagedAttachmentStore store,
        byte? appendByte = null,
        string fileName = "image.png")
    {
        var sourceBytes = Convert.FromBase64String(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
        var bytes = appendByte is null
            ? sourceBytes
            : [.. sourceBytes, appendByte.Value];
        await using var source = new MemoryStream(bytes, writable: false);
        return await store.ImportBytesAsync(
            source,
            fileName,
            new AttachmentLimitSettings(),
            CancellationToken.None);
    }

    private static PresetAttachmentReference CreateReference(
        ManagedAttachmentObject attachment,
        string fileName,
        int order,
        string id = "00000000-0000-0000-0000-000000000020") =>
        new()
        {
            Id = id,
            ContentId = attachment.ContentId,
            OriginalFileName = fileName,
            DetectedType = attachment.DetectedType,
            OwnerInputKind = "local_image",
            ByteLength = attachment.ByteLength,
            Order = order
        };

    private static DesktopStructuredInputCapabilities CreateSupportedCapabilities() =>
        CodexStructuredInputCapabilityInspector.Inspect(CreateSemanticSnapshot());

    private static CodexStructuredInputSemanticSnapshot CreateSemanticSnapshot() =>
        new()
        {
            Acquisition = StructuredInputEvidenceAcquisition.ReadOnlyAsar,
            PackageName = "openai-codex-electron",
            ProductName = "Codex",
            PackageVersion = "26.810.41047",
            Epoch = 7,
            FollowerMethods = new HashSet<string>(StringComparer.Ordinal)
            {
                "thread-follower-start-turn",
                "thread-follower-edit-last-user-turn"
            },
            StartTurnHostHandler = "thread-follower-start-turn-for-host",
            StartTurnAssertsOwner = true,
            NativeMethod = "turn/start",
            NativeMethodVersion = 1,
            PreservesInput = true,
            PreservesStableClientUserMessageId = true,
            NativeInputKinds = new HashSet<string>(StringComparer.Ordinal)
            {
                "text",
                "localImage"
            },
            HandlerShapeSha256 = new string('A', 64),
            InputShapeSha256 = new string('B', 64),
            SupportsAttachmentOnly = true,
            MaximumAttachmentCount = 20,
            MaximumBytesPerFile = 100L * 1024 * 1024,
            MaximumBytesPerPayload = 500L * 1024 * 1024
        };

    private static PresetAttachmentReference CreateImageAttachment() =>
        CreateAttachment(
            id: "00000000-0000-0000-0000-000000000010",
            contentId: new string('E', 64),
            fileName: "image.png",
            detectedType: "image/png",
            ownerInputKind: "local_image",
            byteLength: 32,
            order: 0);

    private static PresetAttachmentReference CreateAttachment(
        string id,
        string contentId,
        string fileName,
        string detectedType,
        string ownerInputKind,
        long byteLength,
        int order) =>
        new()
        {
            Id = id,
            ContentId = contentId,
            OriginalFileName = fileName,
            DetectedType = detectedType,
            OwnerInputKind = ownerInputKind,
            ByteLength = byteLength,
            Order = order
        };

    private static void AssertEncodingFailure(string code, Action action)
    {
        try
        {
            action();
        }
        catch (DesktopStructuredInputEncodingException exception)
        {
            Ensure(exception.Code == code, $"encoding failure code changed: {exception.Code}");
            return;
        }

        throw new InvalidOperationException($"Expected encoding failure: {code}");
    }

    private static async Task AssertPresentationFailureAsync(
        string code,
        Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (AttachmentPresentationException exception)
        {
            Ensure(exception.Code == code, $"presentation failure code changed: {exception.Code}");
            return;
        }

        throw new InvalidOperationException($"Expected presentation failure: {code}");
    }

    private static async Task ThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
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

    private static bool IsSha256(string value)
    {
        if (value.Length != SHA256.HashSizeInBytes * 2)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9') and not (>= 'A' and <= 'F'))
            {
                return false;
            }
        }

        return true;
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

    private sealed record LegacyFollowUpRecordFixture(
        string OperationId,
        string ThreadId,
        string MessageId,
        FollowUpTriggerKind Trigger,
        string ExpectedTurnId,
        DateTimeOffset? ScheduledAtUtc,
        string MessageHash,
        FollowUpOperationState State,
        string ClientMessageId,
        string? NewTurnId,
        string? CompletionTurnId,
        DateTimeOffset CreatedAt,
        DateTimeOffset UpdatedAt,
        int AttemptCount);

    private sealed class RecordingStructuredInputEncoder : IDesktopStructuredInputEncoder
    {
        internal int CallCount { get; private set; }

        internal StructuredPresetPayload? LastPayload { get; private set; }

        internal DesktopStructuredInputCapabilities? LastCapabilities { get; private set; }

        internal IReadOnlyDictionary<string, string>? LastPresentationPaths { get; private set; }

        public JsonElement Encode(
            StructuredPresetPayload payload,
            DesktopStructuredInputCapabilities capabilities,
            IReadOnlyDictionary<string, string> presentationPaths)
        {
            CallCount++;
            LastPayload = payload;
            LastCapabilities = capabilities;
            LastPresentationPaths = presentationPaths;
            return JsonSerializer.SerializeToElement(new[]
            {
                new
                {
                    type = "text",
                    text = "encoded",
                    text_elements = Array.Empty<object>()
                }
            });
        }
    }

    private sealed record LegacyJournalIntegrityFixture(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        IReadOnlyList<LegacyFollowUpRecordFixture> Records);

    private sealed record LegacyJournalDocumentFixture(
        int SchemaVersion,
        long Generation,
        bool RequiresConservativeRecovery,
        string Checksum,
        IReadOnlyList<LegacyFollowUpRecordFixture> Records);
}
