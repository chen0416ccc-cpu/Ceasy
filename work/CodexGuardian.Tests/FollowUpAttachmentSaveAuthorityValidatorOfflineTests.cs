using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class FollowUpAttachmentSaveAuthorityValidatorOfflineTests
{
    private static readonly AttachmentPresentationRequirements PresentationRequirements = new(
        SupportsSeparateDisplayName: false,
        RequiresFileNameSuffix: true,
        AllowHardLinks: false);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "attachment save authority accepts a verified managed object without writing",
            TestSupportedReadOnlyAsync,
            assert);
        await RunCaseAsync(
            "attachment save authority rejects a missing or damaged managed object",
            TestDamagedObjectAsync,
            assert);
        await RunCaseAsync(
            "attachment save authority rejects a settings generation race",
            TestSettingsGenerationRaceAsync,
            assert);
        await RunCaseAsync(
            "attachment save authority blocks a corrupt journal",
            TestCorruptJournalAsync,
            assert);
        await RunCaseAsync(
            "attachment save authority blocks a materializing presentation transaction",
            TestMaterializingTransactionAsync,
            assert);
        await RunCaseAsync(
            "attachment save authority blocks a pending operation for the same content identity",
            TestPendingOperationConflictAsync,
            assert);
        await RunCaseAsync(
            "attachment save authority rejects a presentation identity mismatch",
            TestPresentationIdentityMismatchAsync,
            assert);
    }

    private static async Task TestSupportedReadOnlyAsync()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var item = await fixture.CreateAttachmentAsync(100);
            var candidate = new FollowUpAttachmentSaveCandidate(3, item.Payload);
            var beforeSettings = ReadBytesIfPresent(fixture.SettingsService.SettingsPath);
            var beforePrevious = ReadBytesIfPresent(fixture.PreviousSettingsPath);
            var beforeCleanup = Directory.Exists(fixture.CleanupRoot)
                ? Directory.GetFileSystemEntries(fixture.CleanupRoot)
                : Array.Empty<string>();

            var result = await fixture.Validator.ValidateAsync(
                fixture.Settings,
                [candidate],
                CancellationToken.None);

            Ensure(result.CanSave, "verified attachment save was rejected");
            Ensure(result.Status == FollowUpAttachmentSaveAuthorityStatus.Supported,
                "verified attachment returned the wrong status");
            Ensure(result.MessageNumber == 0, "successful validation exposed a message number");
            Ensure(beforeSettings.SequenceEqual(ReadBytesIfPresent(fixture.SettingsService.SettingsPath)),
                "settings changed during read-only validation");
            Ensure(beforePrevious.SequenceEqual(ReadBytesIfPresent(fixture.PreviousSettingsPath)),
                "previous settings changed during read-only validation");
            var afterCleanup = Directory.Exists(fixture.CleanupRoot)
                ? Directory.GetFileSystemEntries(fixture.CleanupRoot)
                : Array.Empty<string>();
            Ensure(beforeCleanup.SequenceEqual(afterCleanup, StringComparer.OrdinalIgnoreCase),
                "read-only validation created or removed cleanup entries");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static async Task TestDamagedObjectAsync()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var item = await fixture.CreateAttachmentAsync(110);
            File.Delete(item.ManagedObject.ObjectPath);
            var result = await fixture.Validator.ValidateAsync(
                fixture.Settings,
                [new FollowUpAttachmentSaveCandidate(4, item.Payload)],
                CancellationToken.None);

            Ensure(
                result.Status == FollowUpAttachmentSaveAuthorityStatus.ObjectMissingOrDamaged,
                "damaged managed object was not rejected");
            Ensure(result.MessageNumber == 4, "damaged object reported the wrong message");
            Ensure(result.Code == "managed-object-missing-or-damaged",
                "damaged object returned the wrong code");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static async Task TestSettingsGenerationRaceAsync()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var item = await fixture.CreateAttachmentAsync(120);
            fixture.Settings.SettingsGeneration++;
            var result = await fixture.Validator.ValidateAsync(
                fixture.Settings,
                [new FollowUpAttachmentSaveCandidate(5, item.Payload)],
                CancellationToken.None);

            Ensure(
                result.Status == FollowUpAttachmentSaveAuthorityStatus.AuthorityUnavailable,
                "settings generation race was accepted");
            Ensure(result.MessageNumber == 5, "settings race reported the wrong message");
            Ensure(result.Code == "settings-generation-changed",
                "settings race returned the wrong code");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static async Task TestCorruptJournalAsync()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var item = await fixture.CreateAttachmentAsync(130);
            await File.WriteAllTextAsync(fixture.FollowUpJournal.JournalPath, "{");
            var result = await fixture.Validator.ValidateAsync(
                fixture.Settings,
                [new FollowUpAttachmentSaveCandidate(6, item.Payload)],
                CancellationToken.None);

            Ensure(
                result.Status == FollowUpAttachmentSaveAuthorityStatus.AuthorityUnavailable,
                "corrupt journal was accepted");
            Ensure(result.MessageNumber == 6, "corrupt journal reported the wrong message");
            Ensure(result.Code == "follow-up-journal-unavailable",
                "corrupt journal returned the wrong code");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static async Task TestMaterializingTransactionAsync()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var first = await fixture.CreateAttachmentAsync(140);
            var second = await fixture.CreateAttachmentAsync(141);
            fixture.DraftAuthority.ReplaceVisibleDrafts(2, [first.Reference, second.Reference]);
            var materializingPayload = StructuredPresetPayload.Create(
                "materializing",
                [first.Reference, second.Reference]);
            var operationId = Guid.NewGuid().ToString("D");
            try
            {
                _ = await fixture.Presentation.AcquireAsync(
                    operationId,
                    materializingPayload,
                    new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
                    {
                        [first.ManagedObject.ContentId] = first.ManagedObject
                    },
                    PresentationRequirements,
                    CancellationToken.None);
            }
            catch (AttachmentPresentationException exception) when (
                exception.Code == "managed-object-invalid")
            {
            }

            var result = await fixture.Validator.ValidateAsync(
                fixture.Settings,
                [new FollowUpAttachmentSaveCandidate(7, first.Payload)],
                CancellationToken.None);

            Ensure(
                result.Status == FollowUpAttachmentSaveAuthorityStatus.PendingOperationConflict,
                "materializing presentation transaction was accepted");
            Ensure(result.MessageNumber == 7, "pending transaction reported the wrong message");
            Ensure(result.Code == "presentation-materializing",
                "pending transaction returned the wrong code");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static async Task TestPresentationIdentityMismatchAsync()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var item = await fixture.CreateAttachmentAsync(150);
            var operationId = Guid.NewGuid().ToString("D");
            _ = await fixture.Presentation.AcquireAsync(
                operationId,
                item.Payload,
                new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
                {
                    [item.ManagedObject.ContentId] = item.ManagedObject
                },
                PresentationRequirements,
                CancellationToken.None);
            var wrongLeaseId = Guid.NewGuid().ToString("N");
            _ = await fixture.FollowUpJournal.GetOrCreateStructuredAsync(
                operationId,
                Guid.NewGuid().ToString("D"),
                item.Reference.Id,
                FollowUpTriggerKind.AfterNormalCompletion,
                Guid.NewGuid().ToString("D"),
                scheduledAtUtc: null,
                item.Payload,
                wrongLeaseId,
                FollowUpPayloadSourceKind.StructuredPreset,
                FollowUpOperationJournal.CreateClientMessageId(operationId),
                CancellationToken.None);

            var result = await fixture.Validator.ValidateAsync(
                fixture.Settings,
                [new FollowUpAttachmentSaveCandidate(8, item.Payload)],
                CancellationToken.None);

            Ensure(
                result.Status == FollowUpAttachmentSaveAuthorityStatus.PresentationIdentityMismatch,
                "presentation identity mismatch was accepted");
            Ensure(result.MessageNumber == 8, "identity mismatch reported the wrong message");
            Ensure(result.Code == "presentation-identity-mismatch",
                "identity mismatch returned the wrong code");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static async Task TestPendingOperationConflictAsync()
    {
        var fixture = await Fixture.CreateAsync();
        try
        {
            var item = await fixture.CreateAttachmentAsync(145);
            var operationId = Guid.NewGuid().ToString("D");
            var lease = await fixture.Presentation.AcquireAsync(
                operationId,
                item.Payload,
                new Dictionary<string, ManagedAttachmentObject>(StringComparer.Ordinal)
                {
                    [item.ManagedObject.ContentId] = item.ManagedObject
                },
                PresentationRequirements,
                CancellationToken.None);
            _ = await fixture.FollowUpJournal.GetOrCreateStructuredAsync(
                operationId,
                Guid.NewGuid().ToString("D"),
                item.Reference.Id,
                FollowUpTriggerKind.AfterNormalCompletion,
                Guid.NewGuid().ToString("D"),
                scheduledAtUtc: null,
                item.Payload,
                lease.LeaseId,
                FollowUpPayloadSourceKind.StructuredPreset,
                FollowUpOperationJournal.CreateClientMessageId(operationId),
                CancellationToken.None);

            var result = await fixture.Validator.ValidateAsync(
                fixture.Settings,
                [new FollowUpAttachmentSaveCandidate(9, item.Payload)],
                CancellationToken.None);

            Ensure(
                result.Status == FollowUpAttachmentSaveAuthorityStatus.PendingOperationConflict,
                "pending operation for the same content identity was accepted");
            Ensure(result.MessageNumber == 9, "pending operation reported the wrong message");
            Ensure(result.Code == "pending-operation-conflict",
                "pending operation returned the wrong code");
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static byte[] ReadBytesIfPresent(string path) =>
        File.Exists(path) ? File.ReadAllBytes(path) : Array.Empty<byte>();

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        Directory.CreateDirectory(parent);
        return Path.Combine(parent, "attachment-save-authority-" + Guid.NewGuid().ToString("N"));
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test().WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
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
            string root,
            AppSettings settings,
            SettingsService settingsService,
            ManagedAttachmentStore store,
            AttachmentDraftAuthority draftAuthority,
            FollowUpOperationJournal followUpJournal,
            RecoveryOperationJournal recoveryJournal,
            AttachmentPresentationLeaseService presentation,
            FollowUpAttachmentSaveAuthorityValidator validator)
        {
            Root = root;
            Settings = settings;
            SettingsService = settingsService;
            Store = store;
            DraftAuthority = draftAuthority;
            FollowUpJournal = followUpJournal;
            RecoveryJournal = recoveryJournal;
            Presentation = presentation;
            Validator = validator;
        }

        internal string Root { get; }

        internal AppSettings Settings { get; }

        internal SettingsService SettingsService { get; }

        internal ManagedAttachmentStore Store { get; }

        internal AttachmentDraftAuthority DraftAuthority { get; }

        internal FollowUpOperationJournal FollowUpJournal { get; }

        internal RecoveryOperationJournal RecoveryJournal { get; }

        internal AttachmentPresentationLeaseService Presentation { get; }

        internal FollowUpAttachmentSaveAuthorityValidator Validator { get; }

        internal string CleanupRoot => Path.Combine(Store.AttachmentRoot, "cleanup");

        internal string PreviousSettingsPath => Path.Combine(Root, "settings.previous.json");

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
            var validator = new FollowUpAttachmentSaveAuthorityValidator(
                root,
                settingsService,
                drafts,
                followUpJournal,
                recoveryJournal,
                presentation,
                store);
            return new Fixture(
                root,
                settings,
                settingsService,
                store,
                drafts,
                followUpJournal,
                recoveryJournal,
                presentation,
                validator);
        }

        internal async Task<AttachmentCase> CreateAttachmentAsync(int seed)
        {
            var sourceBytes = Convert.FromBase64String(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
            var bytes = sourceBytes.Concat(new[] { unchecked((byte)seed) }).ToArray();
            await using var stream = new MemoryStream(bytes, writable: false);
            var managedObject = await Store.ImportBytesAsync(
                stream,
                $"image-{seed}.png",
                new AttachmentLimitSettings(),
                CancellationToken.None);
            var reference = new PresetAttachmentReference
            {
                Id = Guid.NewGuid().ToString("D"),
                ContentId = managedObject.ContentId,
                OriginalFileName = $"image-{seed}.png",
                DetectedType = managedObject.DetectedType,
                OwnerInputKind = "local_image",
                ByteLength = managedObject.ByteLength,
                Order = 0
            };
            var payload = StructuredPresetPayload.Create("save", [reference]);
            DraftAuthority.ReplaceVisibleDrafts(1, [reference]);
            return new AttachmentCase(managedObject, reference, payload);
        }

        internal void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                {
                    foreach (var path in Directory.EnumerateFiles(
                                 Root,
                                 "*",
                                 SearchOption.AllDirectories))
                    {
                        var attributes = File.GetAttributes(path);
                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            throw new IOException("attachment save authority fixture contains a reparse point");
                        }

                        if ((attributes & FileAttributes.ReadOnly) != 0)
                        {
                            File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
                        }
                    }

                    Directory.Delete(Root, recursive: true);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException("attachment save authority fixture cleanup failed", exception);
            }
        }
    }

    private sealed record AttachmentCase(
        ManagedAttachmentObject ManagedObject,
        PresetAttachmentReference Reference,
        StructuredPresetPayload Payload);
}
