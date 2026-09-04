using CodexGuardian.Models;
using CodexGuardian.Services;
using CodexGuardian.ViewModels;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Xml.Linq;

internal static class AttachmentInteractionOfflineTests
{
    private const string TestDataRootEnvironmentVariable = "CODEX_GUARDIAN_TEST_DATA_ROOT";

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "attachment rail drag is horizontal cancellable and commits exactly one valid move",
            TestHorizontalAttachmentDragContractAsync,
            assert);
        await RunCaseAsync(
            "combined attachment definitions fail closed before text-only Desktop dispatch",
            TestAttachmentDefinitionDispatchFailsClosedAsync,
            assert);
        await RunCaseAsync(
            "attachment save reads one fresh capability and blocks unsupported durable state",
            TestAttachmentSaveCapabilityGateAsync,
            assert);
        await RunCaseAsync(
            "attachment import preflights the existing draft before any managed object write",
            TestExistingDraftImportPreflightAsync,
            assert);
        await RunCaseAsync(
            "attachment composition keeps stale and cancelled targets free of partial appends",
            TestAttachmentCompositionAtomicityAsync,
            assert);
        await RunCaseAsync(
            "managed thumbnails are bounded frozen memory images without path disclosure",
            TestManagedThumbnailContractAsync,
            assert);
        await RunCaseAsync(
            "attachment UI renders thumbnails and disables real import in isolated preview",
            TestAttachmentPresentationContractAsync,
            assert);
    }

    private static Task TestHorizontalAttachmentDragContractAsync()
    {
        var productRoot = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian");
        var pagePath = Path.Combine(productRoot, "MainWindow.xaml");
        var codeBehindPath = Path.Combine(productRoot, "MainWindow.xaml.cs");
        var page = XDocument.Load(pagePath, LoadOptions.PreserveWhitespace);
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var grip = page.Descendants()
            .SingleOrDefault(element => string.Equals(
                (string?)element.Attributes().SingleOrDefault(attribute => string.Equals(
                    attribute.Name.LocalName,
                    "AutomationProperties.AutomationId",
                    StringComparison.Ordinal)),
                "FollowUpAttachmentDragGrip",
                StringComparison.Ordinal));
        Ensure(grip is not null, "the dedicated attachment drag grip is absent");
        foreach (var eventName in new[]
                 {
                     "PreviewMouseLeftButtonDown",
                     "LostMouseCapture",
                     "PreviewKeyDown"
                 })
        {
            Ensure(
                !string.IsNullOrWhiteSpace((string?)grip!.Attribute(eventName)),
                $"the attachment grip does not wire {eventName}");
        }

        var itemContainer = grip!.Ancestors(presentation + "Border").FirstOrDefault();
        Ensure(
            itemContainer is not null &&
            itemContainer.Attributes().All(attribute =>
                !attribute.Name.LocalName.Contains("Mouse", StringComparison.Ordinal) &&
                !attribute.Name.LocalName.Contains("Drag", StringComparison.Ordinal)),
            "attachment dragging is attached to the whole card instead of the dedicated grip");

        var source = File.ReadAllText(codeBehindPath);
        var window = page.Root ?? throw new InvalidOperationException("MainWindow XAML has no root.");
        Ensure(
            string.Equals(
                (string?)window.Attribute("PreviewMouseMove"),
                "Window_PreviewMouseMove",
                StringComparison.Ordinal) &&
            string.Equals(
                (string?)window.Attribute("PreviewMouseLeftButtonUp"),
                "Window_PreviewMouseLeftButtonUp",
                StringComparison.Ordinal),
            "the top-level window does not retain pointer move and release outside the attachment grip");
        foreach (var required in new[]
                 {
                     "AttachmentDragGrip_PreviewMouseLeftButtonDown",
                     "AttachmentDragGrip_LostMouseCapture",
                     "AttachmentDragGrip_PreviewKeyDown",
                     "CancelAttachmentDrag",
                     "SystemParameters.MinimumHorizontalDragDistance",
                     "SystemParameters.MinimumVerticalDragDistance",
                     "ScrollableWidth",
                     "TranslateTransform.XProperty"
                 })
        {
            Ensure(source.Contains(required, StringComparison.Ordinal), $"missing drag contract marker: {required}");
        }

        Ensure(
            source.Contains("GetCursorPos", StringComparison.Ordinal) &&
            source.Contains("Mouse.Capture", StringComparison.Ordinal) &&
            source.Contains("Key.Escape", StringComparison.Ordinal) &&
            (source.Contains("Width = 4", StringComparison.Ordinal) ||
             File.ReadAllText(pagePath).Contains("Width=\"4\"", StringComparison.Ordinal)) &&
            CountOccurrences(source, "MoveFollowUpAttachmentDraft(") == 1,
            "attachment drag lost its pointer-following surface, four-pixel slot, complete cancel, or unique move commit");

        var first = CreateAttachment("21000000-0000-4000-8000-000000000001", "first.txt", 0);
        var second = CreateAttachment("21000000-0000-4000-8000-000000000002", "second.txt", 1);
        var third = CreateAttachment("21000000-0000-4000-8000-000000000003", "third.txt", 2);
        var message = new FollowUpMessageItem
        {
            Id = "21000000-0000-4000-8000-000000000010",
            Message = "attachment ordering"
        };
        message.Attachments.Add(first);
        message.Attachments.Add(second);
        message.Attachments.Add(third);

        var move = typeof(MainViewModel).GetMethod(
                       "MoveFollowUpAttachmentDraft",
                       BindingFlags.Static | BindingFlags.NonPublic)
                   ?? throw new InvalidOperationException(
                       "MainViewModel.MoveFollowUpAttachmentDraft is absent.");
        Ensure(
            move.Invoke(null, [message, first, -1]) is false &&
            move.Invoke(null, [message, first, 3]) is false &&
            move.Invoke(null, [message, first, 0]) is false &&
            message.Attachments.SequenceEqual([first, second, third]),
            "an invalid or no-op attachment drop changed the draft");
        Ensure(
            move.Invoke(null, [message, first, 2]) is true &&
            message.Attachments.SequenceEqual([second, third, first]) &&
            message.Attachments.Select(item => item.Order).SequenceEqual([0, 1, 2]),
            "one valid attachment drop did not produce one ordered draft move");

        return Task.CompletedTask;
    }

    private static async Task TestAttachmentDefinitionDispatchFailsClosedAsync()
    {
        await WithIsolatedDDriveRootAsync(async root =>
        {
            var thread = new ThreadSummary(
                Guid.NewGuid().ToString("D"),
                "attachment-dispatch-contract",
                string.Empty,
                @"D:\synthetic",
                "appServer",
                1,
                2,
                IsSubAgent: false,
                IsEphemeral: false,
                RuntimeStatus: "idle");
            var completedTurn = new TurnSnapshot(
                Guid.NewGuid().ToString("D"),
                "completed",
                null,
                null,
                null,
                "original request",
                HasAttachments: false,
                HasAssistantOutput: true,
                HasWorkOutput: true,
                OutputFingerprint: "complete",
                StartedAt: 1,
                CompletedAt: 2,
                HasUserMessage: true,
                HasFinalAssistantOutput: true,
                HasCompleteItemEvidence: true,
                IsSingleTextUserInput: true);
            var definition = new FollowUpMessageDefinition
            {
                Id = Guid.NewGuid().ToString("D"),
                Message = "this text must not be sent without its attachment",
                Attachments =
                [
                    new PresetAttachmentReference
                    {
                        Id = Guid.NewGuid().ToString("D"),
                        ContentId = Convert.ToHexString(SHA256.HashData(
                            Encoding.UTF8.GetBytes("combined-definition-object"))),
                        OriginalFileName = "evidence.txt",
                        DetectedType = "text/plain",
                        OwnerInputKind = "local_file",
                        ByteLength = 17,
                        Order = 0
                    }
                ]
            };
            var state = new AttachmentDispatchStateReader(thread, completedTurn);
            var desktop = new AttachmentRejectingDesktopChannel(thread, completedTurn);
            var owner = new AttachmentDispatchOwnerActivator();
            using var log = new GuardianLog(root);
            var journal = new FollowUpOperationJournal(root);
            var service = new FollowUpDispatchService(state, desktop, owner, journal, log);

            var result = await service.ExecuteAsync(
                thread,
                completedTurn,
                definition,
                includeSubAgents: false,
                isDispatchAllowed: static () => true,
                CancellationToken.None);
            var journalSnapshot = await journal.ReadAsync();
            Ensure(
                !result.Success &&
                result.FailureKind == FollowUpDispatchFailureKind.DesktopIncompatible &&
                desktop.StartTextTurnCount == 0 &&
                desktop.AcquireOwnerGuardCount == 0 &&
                state.ReadLatestTurnCount == 0 &&
                journalSnapshot.Records.Count == 0,
                "an attachment-bearing definition entered the text-only owner channel or created a send ledger entry");
        });
    }

    private static async Task TestAttachmentSaveCapabilityGateAsync()
    {
        var authority = new AttachmentDraftAuthority();
        var importer = CreateImporter(new InteractionManagedAttachmentStore(
            new Dictionary<string, long>(StringComparer.Ordinal)));
        var textPayload = StructuredPresetPayload.Create("text only", []);
        var imageReference = CreateReference(
            "21500000-0000-4000-8000-000000000001",
            "reference.png",
            8,
            0) with
        {
            DetectedType = "image/png",
            OwnerInputKind = "local_image"
        };
        var fileReference = CreateReference(
            "21500000-0000-4000-8000-000000000002",
            "notes.txt",
            5,
            0);
        var imagePayload = StructuredPresetPayload.Create("inspect", [imageReference]);
        var secondImagePayload = StructuredPresetPayload.Create("compare", [imageReference]);
        var filePayload = StructuredPresetPayload.Create("read", [fileReference]);
        var attachmentOnlyPayload = StructuredPresetPayload.Create(string.Empty, [imageReference]);
        var supported = CreateStructuredCapabilities(
            StructuredInputCapabilityState.Supported,
            ["text", "local_image"],
            supportsAttachmentOnly: true,
            epoch: 1,
            fingerprintCharacter: 'A');

        var textProvider = new InteractionStructuredCapabilityProvider(_ => supported);
        var textComposition = CreateComposition(importer, authority, textProvider);
        var textResult = await textComposition.ValidateSaveAsync(
            [new FollowUpAttachmentSaveCandidate(1, textPayload)],
            CancellationToken.None);
        Ensure(
            textResult.CanSave && textProvider.ReadCount == 0,
            "text-only Save consulted structured attachment capability");

        var batchProvider = new InteractionStructuredCapabilityProvider(_ => supported);
        var batchComposition = CreateComposition(importer, authority, batchProvider);
        var batchResult = await batchComposition.ValidateSaveAsync(
            [
                new FollowUpAttachmentSaveCandidate(1, imagePayload),
                new FollowUpAttachmentSaveCandidate(2, secondImagePayload)
            ],
            CancellationToken.None);
        Ensure(
            batchResult.CanSave && batchProvider.ReadCount == 1,
            "a supported image batch did not use exactly one fresh capability read");

        var fileProvider = new InteractionStructuredCapabilityProvider(_ => supported);
        var fileResult = await CreateComposition(importer, authority, fileProvider)
            .ValidateSaveAsync(
                [new FollowUpAttachmentSaveCandidate(3, filePayload)],
                CancellationToken.None);
        Ensure(
            !fileResult.CanSave &&
            fileResult.Status == FollowUpAttachmentSaveCapabilityStatus.Unsupported &&
            fileResult.MessageNumber == 3 &&
            fileResult.Code == "unsupported-input-kind" &&
            fileProvider.ReadCount == 1,
            "local_file was accepted by the current text/local_image Save capability");

        var unknownProvider = new InteractionStructuredCapabilityProvider(_ =>
            supported with { State = StructuredInputCapabilityState.Unknown });
        var unknownResult = await CreateComposition(importer, authority, unknownProvider)
            .ValidateSaveAsync(
                [new FollowUpAttachmentSaveCandidate(4, imagePayload)],
                CancellationToken.None);
        Ensure(
            !unknownResult.CanSave &&
            unknownResult.Status == FollowUpAttachmentSaveCapabilityStatus.Waiting &&
            unknownResult.Code == "capability-unknown",
            "unknown capability authorized an attachment Save");

        var unsupportedProvider = new InteractionStructuredCapabilityProvider(_ =>
            supported with { State = StructuredInputCapabilityState.Unsupported });
        var unsupportedResult = await CreateComposition(importer, authority, unsupportedProvider)
            .ValidateSaveAsync(
                [new FollowUpAttachmentSaveCandidate(5, imagePayload)],
                CancellationToken.None);
        Ensure(
            !unsupportedResult.CanSave &&
            unsupportedResult.Status == FollowUpAttachmentSaveCapabilityStatus.Unsupported &&
            unsupportedResult.Code == "capability-unsupported",
            "explicitly unsupported capability authorized an attachment Save");

        var exceptionProvider = new InteractionStructuredCapabilityProvider(_ =>
            throw new InvalidOperationException("synthetic provider failure"));
        var exceptionResult = await CreateComposition(importer, authority, exceptionProvider)
            .ValidateSaveAsync(
                [new FollowUpAttachmentSaveCandidate(6, imagePayload)],
                CancellationToken.None);
        Ensure(
            !exceptionResult.CanSave &&
            exceptionResult.Status == FollowUpAttachmentSaveCapabilityStatus.Waiting &&
            exceptionResult.Code == "capability-read-failed",
            "a capability read failure did not fail closed as waiting");

        var attachmentOnlyProvider = new InteractionStructuredCapabilityProvider(_ =>
            supported with { SupportsAttachmentOnly = false });
        var attachmentOnlyResult = await CreateComposition(
                importer,
                authority,
                attachmentOnlyProvider)
            .ValidateSaveAsync(
                [new FollowUpAttachmentSaveCandidate(7, attachmentOnlyPayload)],
                CancellationToken.None);
        Ensure(
            !attachmentOnlyResult.CanSave &&
            attachmentOnlyResult.Status == FollowUpAttachmentSaveCapabilityStatus.Unsupported &&
            attachmentOnlyResult.Code == "attachment-only-unsupported",
            "attachment-only Save ignored the current owner capability");

        var driftProvider = new InteractionStructuredCapabilityProvider(readCount =>
            readCount == 1
                ? supported
                : CreateStructuredCapabilities(
                    StructuredInputCapabilityState.Supported,
                    ["text"],
                    supportsAttachmentOnly: false,
                    epoch: 2,
                    fingerprintCharacter: 'B'));
        var driftComposition = CreateComposition(importer, authority, driftProvider);
        var beforeDrift = await driftComposition.ValidateSaveAsync(
            [new FollowUpAttachmentSaveCandidate(8, imagePayload)],
            CancellationToken.None);
        var afterDrift = await driftComposition.ValidateSaveAsync(
            [new FollowUpAttachmentSaveCandidate(8, imagePayload)],
            CancellationToken.None);
        Ensure(
            beforeDrift.CanSave &&
            !afterDrift.CanSave &&
            afterDrift.Code == "unsupported-input-kind" &&
            driftProvider.ReadCount == 2,
            "a later Save reused stale capability after semantic epoch drift");

        var previewResult = await CreateComposition(importer, authority, structuredCapabilities: null)
            .ValidateSaveAsync(
                [new FollowUpAttachmentSaveCandidate(9, imagePayload)],
                CancellationToken.None);
        Ensure(
            !previewResult.CanSave &&
            previewResult.Status == FollowUpAttachmentSaveCapabilityStatus.Waiting &&
            previewResult.Code == "capability-provider-unavailable",
            "safe preview or a missing provider claimed attachment Save support");

        var guardianRoot = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian");
        var viewModelSource = File.ReadAllText(
            Path.Combine(guardianRoot, "ViewModels", "MainViewModel.cs"),
            Encoding.UTF8);
        var saveStart = viewModelSource.IndexOf(
            "private async Task SaveFollowUpMessagesAsync()",
            StringComparison.Ordinal);
        var saveEnd = viewModelSource.IndexOf(
            "private bool IsSelectableWorkflowConversation",
            saveStart,
            StringComparison.Ordinal);
        Ensure(saveStart >= 0 && saveEnd > saveStart, "the Save method source boundary is absent");
        var saveSource = viewModelSource[saveStart..saveEnd];
        var capabilityGate = saveSource.IndexOf("ValidateSaveAsync(", StringComparison.Ordinal);
        var ruleStoreWrite = saveSource.IndexOf(
            "_workflowRuleStore.SaveAsync(",
            StringComparison.Ordinal);
        var settingsWrite = saveSource.IndexOf("SaveSettingsAsync()", StringComparison.Ordinal);
        Ensure(
            capabilityGate >= 0 &&
            ruleStoreWrite > capabilityGate &&
            settingsWrite > capabilityGate,
            "attachment capability validation does not precede every durable Save write");

        var runtimeSource = File.ReadAllText(
            Path.Combine(guardianRoot, "Services", "FollowUpAttachmentRuntime.cs"),
            Encoding.UTF8);
        Ensure(
            runtimeSource.Contains(
                "Coordinator.RequestZeroReferenceCleanupAsync,\r\n            structuredCapabilities,\r\n            SaveAuthorityValidator)",
                StringComparison.Ordinal) ||
            runtimeSource.Contains(
                "Coordinator.RequestZeroReferenceCleanupAsync,\n            structuredCapabilities,\n            SaveAuthorityValidator)",
                StringComparison.Ordinal),
            "the runtime did not connect its read-only structured capability provider to Save validation");

        var zhKeys = ReadResourceKeys(Path.Combine(
            guardianRoot,
            "Localization",
            "AppStrings.resx"));
        var enKeys = ReadResourceKeys(Path.Combine(
            guardianRoot,
            "Localization",
            "AppStrings.en.resx"));
        foreach (var key in new[]
                 {
                     "FollowUp.AttachmentCapabilityWaiting",
                     "FollowUp.AttachmentCapabilityUnsupported"
                 })
        {
            Ensure(zhKeys.Contains(key) && enKeys.Contains(key), $"missing localized Save gate key: {key}");
        }
    }

    private static async Task TestExistingDraftImportPreflightAsync()
    {
        var countStore = new InteractionManagedAttachmentStore(new Dictionary<string, long>(
            StringComparer.Ordinal)
        {
            [@"D:\synthetic\count-overflow.txt"] = 1
        });
        var countImporter = CreateImporter(countStore);
        var existing = new[]
        {
            CreateReference("22000000-0000-4000-8000-000000000001", "existing-a.txt", 2, 0),
            CreateReference("22000000-0000-4000-8000-000000000002", "existing-b.txt", 2, 1)
        };
        await ExpectAttachmentFailureAsync(
            "TooManyAttachments",
            () => countImporter.ImportFilesAsync(
                [@"D:\synthetic\count-overflow.txt"],
                existing,
                new AttachmentLimitSettings
                {
                    MaximumAttachmentsPerMessage = 2,
                    MaximumBytesPerFile = 10,
                    MaximumBytesPerMessage = 20,
                    MaximumLibraryBytes = 40
                },
                CancellationToken.None));
        Ensure(
            countStore.LengthProbeCount == 0 && countStore.ImportCallCount == 0,
            "count overflow touched the source or managed store before rejecting the existing draft");

        var byteStore = new InteractionManagedAttachmentStore(new Dictionary<string, long>(
            StringComparer.Ordinal)
        {
            [@"D:\synthetic\byte-overflow.txt"] = 2
        });
        var byteImporter = CreateImporter(byteStore);
        await ExpectAttachmentFailureAsync(
            "MessageTooLarge",
            () => byteImporter.ImportFilesAsync(
                [@"D:\synthetic\byte-overflow.txt"],
                [CreateReference(
                    "22000000-0000-4000-8000-000000000003",
                    "existing-large.txt",
                    9,
                    0)],
                new AttachmentLimitSettings
                {
                    MaximumAttachmentsPerMessage = 2,
                    MaximumBytesPerFile = 10,
                    MaximumBytesPerMessage = 10,
                    MaximumLibraryBytes = 20
                },
                CancellationToken.None));
        Ensure(
            byteStore.LengthProbeCount == 1 && byteStore.ImportCallCount == 0,
            "message-byte overflow wrote a managed object instead of stopping after bounded source preflight");
    }

    private static async Task TestAttachmentCompositionAtomicityAsync()
    {
        var existing = new[]
        {
            CreateReference("23000000-0000-4000-8000-000000000001", "existing.txt", 5, 0)
        };
        var authority = new AttachmentDraftAuthority();
        authority.ReplaceVisibleDrafts(7, existing);
        EnsureThrows<InvalidOperationException>(
            () => authority.ReplaceVisibleDrafts(6, Array.Empty<PresetAttachmentReference>()),
            "a stale visible-draft generation replaced current cleanup pins");
        var transientLease = authority.AcquireTransientPins(
            [CreateReference("23000000-0000-4000-8000-000000000002", "leased.txt", 2, 0)]);
        Ensure(authority.ReadSnapshot().ContentIds.Count == 2,
            "a transient composition pin was not visible to cleanup authority");
        transientLease.Dispose();
        transientLease.Dispose();
        Ensure(authority.ReadSnapshot().ContentIds.SequenceEqual([existing[0].ContentId]),
            "transient pin release was not complete and idempotent");
        var store = new InteractionManagedAttachmentStore(new Dictionary<string, long>(
            StringComparer.Ordinal)
        {
            [@"D:\synthetic\stale.txt"] = 3,
            [@"D:\synthetic\cancelled.txt"] = 4
        });
        var importerCleanup = new List<IReadOnlyList<string>>();
        var importer = CreateImporter(store, importerCleanup);
        var compositionCleanup = new List<IReadOnlyList<string>>();
        var composition = new FollowUpAttachmentCompositionService(
            importer,
            authority,
            (contentIds, token) =>
            {
                Ensure(!token.CanBeCanceled, "composition cleanup inherited the stale target token");
                compositionCleanup.Add(contentIds.ToArray());
                return Task.CompletedTask;
            });
        var target = new FollowUpAttachmentDraftTarget(
            "task-attachment-composition",
            "23000000-0000-4000-8000-000000000010",
            7);
        IReadOnlyList<PresetAttachmentReference> visible = existing;
        IReadOnlyList<PresetAttachmentReference>? proposed = null;
        var stale = await composition.ComposeFilesAsync(
            target,
            existing,
            [@"D:\synthetic\stale.txt"],
            new AttachmentLimitSettings
            {
                MaximumAttachmentsPerMessage = 3,
                MaximumBytesPerFile = 10,
                MaximumBytesPerMessage = 20,
                MaximumLibraryBytes = 40
            },
            (receivedTarget, attachments, token) =>
            {
                token.ThrowIfCancellationRequested();
                Ensure(receivedTarget == target, "composition changed the immutable draft target");
                proposed = attachments.ToArray();
                return Task.FromResult(false);
            },
            CancellationToken.None);
        var staleImported = proposed?.Except(existing).SingleOrDefault()
                            ?? throw new InvalidOperationException(
                                "the stale commit did not receive one complete combined proposal");
        var afterStale = authority.ReadSnapshot();
        Ensure(
            stale.Status == FollowUpAttachmentCompositionStatus.StaleTarget &&
            stale.ImportedCount == 1 &&
            stale.Attachments.SequenceEqual(existing) &&
            visible.SequenceEqual(existing) &&
            compositionCleanup.Count == 1 &&
            compositionCleanup[0].SequenceEqual([staleImported.ContentId]) &&
            importerCleanup.Count == 0 &&
            afterStale.IsHealthy &&
            afterStale.ContentIds.SequenceEqual([existing[0].ContentId]),
            "a stale target appended part of the batch or retained its transient managed-object pin");

        using var cancellation = new CancellationTokenSource();
        proposed = null;
        await ExpectCancellationAsync(async () =>
        {
            _ = await composition.ComposeFilesAsync(
                target with { Version = 8 },
                existing,
                [@"D:\synthetic\cancelled.txt"],
                new AttachmentLimitSettings
                {
                    MaximumAttachmentsPerMessage = 3,
                    MaximumBytesPerFile = 10,
                    MaximumBytesPerMessage = 20,
                    MaximumLibraryBytes = 40
                },
                (_, attachments, token) =>
                {
                    proposed = attachments.ToArray();
                    cancellation.Cancel();
                    token.ThrowIfCancellationRequested();
                    return Task.FromResult(true);
                },
                cancellation.Token);
        });
        var cancelledImported = proposed?.Except(existing).SingleOrDefault()
                                ?? throw new InvalidOperationException(
                                    "the cancelled commit did not receive one complete combined proposal");
        var afterCancel = authority.ReadSnapshot();
        Ensure(
            visible.SequenceEqual(existing) &&
            compositionCleanup.Count == 2 &&
            compositionCleanup[1].SequenceEqual([cancelledImported.ContentId]) &&
            importerCleanup.Count == 0 &&
            afterCancel.IsHealthy &&
            afterCancel.ContentIds.SequenceEqual([existing[0].ContentId]),
            "cancellation exposed a partial append or retained a transient managed-object pin");

        authority.MarkVisibleDraftsUnavailable();
        var unavailable = authority.ReadSnapshot();
        Ensure(
            !unavailable.IsHealthy && unavailable.ContentIds.Count == 0,
            "unavailable draft authority retained path-independent cleanup authorization");
    }

    private static async Task TestManagedThumbnailContractAsync()
    {
        await WithIsolatedDDriveRootAsync(async root =>
        {
            var store = new ManagedAttachmentStore(root);
            var pngBytes = Convert.FromBase64String(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
            await using var png = new MemoryStream(pngBytes, writable: false);
            var imported = await store.ImportBytesAsync(
                png,
                "thumbnail.png",
                new AttachmentLimitSettings(),
                CancellationToken.None);
            var reference = new PresetAttachmentReference
            {
                Id = "24000000-0000-4000-8000-000000000001",
                ContentId = imported.ContentId,
                OriginalFileName = "thumbnail.png",
                DetectedType = imported.DetectedType,
                OwnerInputKind = "local_image",
                ByteLength = imported.ByteLength,
                Order = 0
            };
            var service = new ManagedAttachmentThumbnailService(store);
            var result = await service.LoadAsync(
                reference,
                maximumPixelWidth: 64,
                maximumPixelHeight: 64,
                CancellationToken.None);
            Ensure(result is not null, "the valid managed PNG did not decode");
            var resultProperties = result!.GetType().GetProperties(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Ensure(
                result.Image.IsFrozen &&
                result.PixelWidth is >= 1 and <= 64 &&
                result.PixelHeight is >= 1 and <= 64 &&
                resultProperties.All(property =>
                    property.PropertyType != typeof(string) &&
                    !property.Name.Contains("Path", StringComparison.OrdinalIgnoreCase)),
                "the thumbnail result is unbounded, mutable, or exposes a managed-object path");

            var pixels = new byte[Math.Max(4, result.PixelWidth * result.PixelHeight * 4)];
            result.Image.CopyPixels(pixels, result.PixelWidth * 4, 0);
            Ensure(pixels.Length >= 4, "the frozen thumbnail still depends on its closed source stream");
            Ensure(
                await service.LoadAsync(
                    reference with { DetectedType = "text/plain", OwnerInputKind = "local_file" },
                    64,
                    64,
                    CancellationToken.None) is null,
                "a non-image managed object was decoded as a thumbnail");
        });
    }

    private static Task TestAttachmentPresentationContractAsync()
    {
        var productRoot = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian");
        var pagePath = Path.Combine(productRoot, "MainWindow.xaml");
        var codeBehindPath = Path.Combine(productRoot, "MainWindow.xaml.cs");
        var itemViewModelPath = Path.Combine(productRoot, "ViewModels", "AttachmentItemViewModel.cs");
        var testsProgramPath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian.Tests",
            "Program.cs");
        var zhPath = Path.Combine(productRoot, "Localization", "AppStrings.resx");
        var enPath = Path.Combine(productRoot, "Localization", "AppStrings.en.resx");
        var page = XDocument.Load(pagePath, LoadOptions.PreserveWhitespace);
        var source = File.ReadAllText(codeBehindPath);
        var itemViewModel = File.ReadAllText(itemViewModelPath);
        var testsProgram = File.ReadAllText(testsProgramPath);

        var image = page.Descendants()
            .SingleOrDefault(element =>
                string.Equals(element.Name.LocalName, "Image", StringComparison.Ordinal) &&
                string.Equals((string?)element.Attribute("Source"), "{Binding Thumbnail}", StringComparison.Ordinal));
        Ensure(
            image is not null &&
            string.Equals((string?)image.Attribute("Stretch"), "UniformToFill", StringComparison.Ordinal) &&
            page.ToString(SaveOptions.DisableFormatting).Contains(
                "Binding=\"{Binding HasThumbnail}\" Value=\"True\"",
                StringComparison.Ordinal),
            "the attachment rail does not render a bounded managed thumbnail with a type-icon fallback");

        var picker = page.Descendants()
            .SingleOrDefault(element => string.Equals(
                (string?)element.Attributes().SingleOrDefault(attribute => string.Equals(
                    attribute.Name.LocalName,
                    "AutomationProperties.AutomationId",
                    StringComparison.Ordinal)),
                "FollowUpAttachmentPickerButton",
                StringComparison.Ordinal));
        Ensure(
            picker is not null &&
            string.Equals((string?)picker.Attribute("ToolTipService.ShowOnDisabled"), "True", StringComparison.Ordinal) &&
            picker.ToString(SaveOptions.DisableFormatting).Contains(
                "IsAttachmentImportAvailable",
                StringComparison.Ordinal) &&
            picker.ToString(SaveOptions.DisableFormatting).Contains(
                "IsAttachmentImportInProgress",
                StringComparison.Ordinal) &&
            source.Contains("public bool IsAttachmentImportAvailable", StringComparison.Ordinal) &&
            source.Contains("IsAttachmentImportInProgressPropertyKey", StringComparison.Ordinal) &&
            source.Contains("ScheduleSelectedAttachmentThumbnailLoad", StringComparison.Ordinal) &&
            source.Contains("CancelAttachmentThumbnailLoad", StringComparison.Ordinal) &&
            source.Contains("CancelThumbnailLoad();", StringComparison.Ordinal) &&
            source.Contains("CancelAttachmentImport();", StringComparison.Ordinal) &&
            itemViewModel.Contains("AttachmentThumbnailState.NotRequested", StringComparison.Ordinal) &&
            testsProgram.Contains("CreatePhaseOwnedTestDataDirectory(\"watcher\")", StringComparison.Ordinal) &&
            testsProgram.Contains("CODEX_GUARDIAN_TEST_DATA_ROOT", StringComparison.Ordinal) &&
            !testsProgram.Contains(
                "Path.Combine(AppContext.BaseDirectory, \"test-data\")",
                StringComparison.Ordinal) &&
            ReadResourceKeys(zhPath).Contains("FollowUp.AttachmentImportUnavailableInPreview") &&
            ReadResourceKeys(enPath).Contains("FollowUp.AttachmentImportUnavailableInPreview") &&
            ReadResourceKeys(zhPath).Contains("FollowUp.AttachmentImportInProgress") &&
            ReadResourceKeys(enPath).Contains("FollowUp.AttachmentImportInProgress"),
            "safe preview exposes a fake attachment import action or thumbnail cancellation becomes a false failure");
        return Task.CompletedTask;
    }

    private static AttachmentItemViewModel CreateAttachment(string id, string fileName, int order) =>
        new(CreateReference(id, fileName, order + 1, order));

    private static PresetAttachmentReference CreateReference(
        string id,
        string fileName,
        long byteLength,
        int order) =>
        new()
        {
            Id = id,
            ContentId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(id))),
            OriginalFileName = fileName,
            DetectedType = "text/plain",
            OwnerInputKind = "local_file",
            ByteLength = byteLength,
            Order = order
        };

    private static FollowUpAttachmentCompositionService CreateComposition(
        AttachmentImportService importer,
        AttachmentDraftAuthority authority,
        IDesktopStructuredInputCapabilityProvider? structuredCapabilities) =>
        new(
            importer,
            authority,
            static (_, _) => Task.CompletedTask,
            structuredCapabilities);

    private static DesktopStructuredInputCapabilities CreateStructuredCapabilities(
        StructuredInputCapabilityState state,
        IEnumerable<string> supportedKinds,
        bool supportsAttachmentOnly,
        long epoch,
        char fingerprintCharacter) =>
        new(
            state,
            new HashSet<string>(supportedKinds, StringComparer.Ordinal),
            supportsAttachmentOnly,
            MaximumAttachmentCount: 20,
            MaximumBytesPerFile: 100L * 1024 * 1024,
            MaximumBytesPerPayload: 500L * 1024 * 1024,
            epoch,
            new string(fingerprintCharacter, 64),
            "synthetic capability");

    private static AttachmentImportService CreateImporter(
        InteractionManagedAttachmentStore store,
        List<IReadOnlyList<string>>? cleanupRequests = null) =>
        new(
            store,
            (contentIds, _) =>
            {
                cleanupRequests?.Add(contentIds.ToArray());
                return Task.CompletedTask;
            },
            store.ProbeLength,
            () => Guid.NewGuid().ToString("D"));

    private sealed class InteractionStructuredCapabilityProvider(
        Func<int, DesktopStructuredInputCapabilities> select)
        : IDesktopStructuredInputCapabilityProvider
    {
        internal int ReadCount { get; private set; }

        public Task<DesktopStructuredInputCapabilities> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCount++;
            return Task.FromResult(select(ReadCount));
        }
    }

    private static async Task ExpectAttachmentFailureAsync(
        string expectedCode,
        Func<Task> action)
    {
        try
        {
            await action();
            throw new InvalidOperationException($"expected attachment failure {expectedCode}");
        }
        catch (AttachmentImportException exception)
        {
            Ensure(
                string.Equals(exception.Code.ToString(), expectedCode, StringComparison.Ordinal),
                $"expected attachment failure {expectedCode}, got {exception.Code}");
        }
    }

    private static async Task ExpectCancellationAsync(Func<Task> action)
    {
        try
        {
            await action();
            throw new InvalidOperationException("expected attachment composition cancellation");
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static void EnsureThrows<TException>(Action action, string detail)
        where TException : Exception
    {
        try
        {
            action();
            throw new InvalidOperationException(detail);
        }
        catch (TException)
        {
        }
    }

    private static int CountOccurrences(string source, string value)
    {
        var count = 0;
        var index = 0;
        while ((index = source.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }

        return count;
    }

    private static HashSet<string> ReadResourceKeys(string path) =>
        XDocument.Load(path)
            .Descendants("data")
            .Select(element => (string?)element.Attribute("name"))
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Select(static name => name!)
            .ToHashSet(StringComparer.Ordinal);

    private static async Task WithIsolatedDDriveRootAsync(Func<string, Task> action)
    {
        var configuredRoot = Environment.GetEnvironmentVariable(TestDataRootEnvironmentVariable);
        Ensure(
            !string.IsNullOrWhiteSpace(configuredRoot),
            $"{TestDataRootEnvironmentVariable} is required for attachment interaction tests");
        var testDataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuredRoot!));
        EnsureExistingLocalDDriveDirectoryWithoutReparse(testDataRoot);
        var root = Path.Combine(
            testDataRoot,
            "attachment-interaction-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await action(root);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void EnsureExistingLocalDDriveDirectoryWithoutReparse(string path)
    {
        var volumeRoot = Path.GetPathRoot(path);
        Ensure(
            string.Equals(volumeRoot, @"D:\", StringComparison.OrdinalIgnoreCase) &&
            Directory.Exists(path),
            "the attachment interaction test-data root is not an existing local D-drive directory");
        var current = volumeRoot!;
        foreach (var segment in Path.GetRelativePath(volumeRoot!, path).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            Ensure(
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0,
                "the attachment interaction test-data root crosses a reparse point");
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> action,
        Action<bool, string> assert)
    {
        try
        {
            await action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static void Ensure(bool condition, string detail)
    {
        if (!condition)
        {
            throw new InvalidOperationException(detail);
        }
    }

    private sealed class AttachmentDispatchStateReader(
        ThreadSummary thread,
        TurnSnapshot completedTurn) : IFollowUpStateReader
    {
        internal int ReadLatestTurnCount { get; private set; }

        public Task<TurnSnapshot?> ReadLatestTurnAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "dispatch read a different task");
            ReadLatestTurnCount++;
            return Task.FromResult<TurnSnapshot?>(completedTurn);
        }

        public Task<ThreadSummary> ReadThreadForRecoveryAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "eligibility read a different task");
            return Task.FromResult(thread);
        }

        public Task<TurnSnapshot?> FindRecentTurnByClientMessageIdAsync(
            string threadId,
            string clientMessageId,
            CancellationToken cancellationToken)
        {
            _ = clientMessageId;
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "reconciliation read a different task");
            return Task.FromResult<TurnSnapshot?>(null);
        }
    }

    private sealed class AttachmentRejectingDesktopChannel(
        ThreadSummary thread,
        TurnSnapshot completedTurn) : IFollowUpDesktopChannel
    {
        public bool SupportsGuardedAutomaticSend => true;

        internal int AcquireOwnerGuardCount { get; private set; }

        internal int StartTextTurnCount { get; private set; }

        public Task<FollowUpOwnerStateGuardAcquireResult> AcquireThreadOwnerStateGuardAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "owner guard targeted a different task");
            AcquireOwnerGuardCount++;
            return Task.FromResult(new FollowUpOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Available,
                new AttachmentDispatchOwnerStateGuard(new DesktopThreadOwnerStateSnapshot(
                    thread.Id,
                    "test-host",
                    "test-owner",
                    1,
                    "idle",
                    completedTurn.Id,
                    "completed")),
                "available"));
        }

        public System.Text.Json.JsonElement EncodeStructuredTurnInput(
            StructuredPresetPayload payload,
            DesktopStructuredInputCapabilities capabilities,
            DesktopStructuredInputCapabilityLease capabilityLease,
            IReadOnlyDictionary<string, string> presentationPaths)
        {
            if (!capabilities.Matches(capabilityLease, payload))
            {
                throw new DesktopStructuredInputCapabilityException(
                    "capability-lease-stale",
                    "The fake structured-input capability lease is stale.");
            }

            return new DesktopStructuredInputEncoder().Encode(
                payload,
                capabilities,
                presentationPaths);
        }

        public Task<DesktopStartTurnResult> StartTextTurnAsync(
            string threadId,
            string message,
            string clientMessageId,
            CancellationToken cancellationToken,
            Func<bool> canStartWrite)
        {
            _ = message;
            _ = clientMessageId;
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(string.Equals(threadId, thread.Id, StringComparison.OrdinalIgnoreCase),
                "text-only send targeted a different task");
            Ensure(canStartWrite(), "the guarded write predicate rejected the fixture");
            StartTextTurnCount++;
            return Task.FromResult(new DesktopStartTurnResult(Guid.NewGuid().ToString("D")));
        }

        public Task<DesktopStartTurnResult> StartStructuredTurnAsync(
            string threadId,
            StructuredPresetPayload payload,
            DesktopStructuredInputCapabilities capabilities,
            DesktopStructuredInputCapabilityLease capabilityLease,
            IReadOnlyDictionary<string, string> presentationPaths,
            string clientMessageId,
            CancellationToken cancellationToken,
            Func<bool> canStartWrite)
        {
            _ = payload;
            _ = capabilities;
            _ = capabilityLease;
            _ = presentationPaths;
            return StartTextTurnAsync(
                threadId,
                string.Empty,
                clientMessageId,
                cancellationToken,
                canStartWrite);
        }
    }

    private sealed class AttachmentDispatchOwnerStateGuard(
        DesktopThreadOwnerStateSnapshot snapshot) : IFollowUpOwnerStateGuard
    {
        public DesktopThreadOwnerStateSnapshot Snapshot { get; } = snapshot;

        public bool IsCurrent => true;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class AttachmentDispatchOwnerActivator : IFollowUpOwnerActivator
    {
        public Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            _ = threadId;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new DesktopThreadOwnerActivationResult(
                DesktopThreadOwnerActivationStatus.AlreadyAvailable,
                "available"));
        }

        public DesktopUserActivityResult CheckUserActivity() =>
            new(DesktopUserActivityStatus.Idle, "idle");
    }

    private sealed class InteractionManagedAttachmentStore(
        IReadOnlyDictionary<string, long> sourceLengths) : IManagedAttachmentStore
    {
        internal int LengthProbeCount { get; private set; }

        internal int ImportCallCount { get; private set; }

        internal long ProbeLength(string sourcePath)
        {
            LengthProbeCount++;
            return sourceLengths.TryGetValue(sourcePath, out var length)
                ? length
                : throw new FileNotFoundException("synthetic source is absent", sourcePath);
        }

        public Task<ManagedAttachmentObject> ImportAsync(
            string sourcePath,
            AttachmentLimitSettings limits,
            CancellationToken cancellationToken)
        {
            _ = limits;
            cancellationToken.ThrowIfCancellationRequested();
            ImportCallCount++;
            var length = sourceLengths[sourcePath];
            var contentId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sourcePath)));
            return Task.FromResult(new ManagedAttachmentObject(
                contentId,
                length,
                "text/plain",
                Path.Combine(@"D:\synthetic-managed-objects", contentId + ".blob")));
        }

        public async Task<ManagedAttachmentObject> ImportBytesAsync(
            Stream source,
            string originalFileName,
            AttachmentLimitSettings limits,
            CancellationToken cancellationToken)
        {
            _ = limits;
            ImportCallCount++;
            await using var copy = new MemoryStream();
            await source.CopyToAsync(copy, cancellationToken);
            var bytes = copy.ToArray();
            var contentId = Convert.ToHexString(SHA256.HashData(bytes));
            return new ManagedAttachmentObject(
                contentId,
                bytes.LongLength,
                string.Equals(Path.GetExtension(originalFileName), ".png", StringComparison.OrdinalIgnoreCase)
                    ? "image/png"
                    : "application/octet-stream",
                Path.Combine(@"D:\synthetic-managed-objects", contentId + ".blob"));
        }

        public Task<bool> VerifyAsync(
            PresetAttachmentReference reference,
            CancellationToken cancellationToken)
        {
            _ = reference;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(true);
        }
    }
}
