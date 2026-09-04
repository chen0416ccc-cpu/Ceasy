using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Media;
using System.Windows.Media.Imaging;

internal static class AttachmentFoundationOfflineTests
{
    private const string ContractName =
        "attachment defaults preserve the approved limits and immutable reference shape";

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(ContractName, TestAttachmentDefaults, assert);
        await RunCaseAsync(
            "version nine migration keeps monitoring on and resets legacy protection authority",
            TestVersionSevenMigrationAsync,
            assert);
        await RunCaseAsync(
            "safe preview settings persist monitoring disabled across envelope generations",
            TestPreviewMonitoringPersistenceAsync,
            assert);
        await RunCaseAsync(
            "attachment normalization accepts attachment-only content and rejects ambiguous references",
            TestAttachmentNormalizationAsync,
            assert);
        await RunCaseAsync(
            "settings envelopes preserve primary and previous generations",
            TestSettingsGenerationPersistenceAsync,
            assert);
        await RunCaseAsync(
            "settings checksum recovery fails closed after both generations are corrupt",
            TestSettingsChecksumRecoveryAsync,
            assert);
        await RunCaseAsync(
            "settings cancellation and replacement failure retain the prior primary",
            TestSettingsPublicationFailureAsync,
            assert);
        await RunCaseAsync(
            "managed attachment store streams validates deduplicates and rejects unsafe sources",
            TestManagedAttachmentStoreAsync,
            assert);
        await RunCaseAsync(
            "clipboard and batch import preserve precedence order and atomic visibility",
            TestClipboardAndBatchImportAsync,
            assert);
        await RunCaseAsync(
            "attachment reference proofs block ambiguity and authorize only fresh zero-reference deletion",
            TestAttachmentReferenceCoordinatorAsync,
            assert);
        await RunCaseAsync(
            "attachment drafts preserve ordered attachment-only explicit-save state",
            TestAttachmentDraftViewModelAsync,
            assert);
    }

    private static void TestAttachmentDefaults()
    {
        var modelAssembly = typeof(AppSettings).Assembly;
        var limitsType = modelAssembly.GetType(
            "CodexGuardian.Models.AttachmentLimitSettings",
            throwOnError: false) ?? throw new InvalidOperationException(
                "AttachmentLimitSettings is absent.");
        var limits = Activator.CreateInstance(limitsType) ?? throw new InvalidOperationException(
            "AttachmentLimitSettings has no default instance.");

        Ensure(
            ReadProperty<int>(limits, "MaximumAttachmentsPerMessage") == 20,
            "default attachment count changed");
        Ensure(
            ReadProperty<long>(limits, "MaximumBytesPerFile") == 100L * 1024 * 1024,
            "default file limit changed");
        Ensure(
            ReadProperty<long>(limits, "MaximumBytesPerMessage") == 500L * 1024 * 1024,
            "default message limit changed");
        Ensure(
            ReadProperty<long>(limits, "MaximumLibraryBytes") == 10L * 1024 * 1024 * 1024,
            "default library limit changed");

        var referenceType = modelAssembly.GetType(
            "CodexGuardian.Models.PresetAttachmentReference",
            throwOnError: false) ?? throw new InvalidOperationException(
                "PresetAttachmentReference is absent.");
        Ensure(referenceType.IsSealed, "attachment references must be sealed");
        Ensure(
            referenceType.GetProperty(
                "EqualityContract",
                BindingFlags.Instance | BindingFlags.NonPublic) is not null,
            "attachment references must preserve record value semantics");

        EnsureRequiredInitProperty<string>(referenceType, "Id");
        EnsureRequiredInitProperty<string>(referenceType, "ContentId");
        EnsureRequiredInitProperty<string>(referenceType, "OriginalFileName");
        EnsureRequiredInitProperty<string>(referenceType, "DetectedType");
        EnsureRequiredInitProperty<string>(referenceType, "OwnerInputKind");
        EnsureRequiredInitProperty<long>(referenceType, "ByteLength");
        EnsureInitProperty<int>(referenceType, "Order");
    }

    private static async Task TestVersionSevenMigrationAsync()
    {
        var threadId = Guid.NewGuid().ToString("D");
        var settings = await LoadSettingsAsync(new
        {
            ConfigurationVersion = 6,
            MonitoringEnabled = false,
            MonitorOnly = false,
            GlobalProtectionEnabled = true,
            ThreadEnabled = new Dictionary<string, bool>
            {
                [threadId] = true
            }
        });
        var current = await LoadSettingsAsync(new
        {
            ConfigurationVersion = AppSettings.CurrentConfigurationVersion,
            GlobalProtectionEnabled = true
        });
        var missingVersion = await LoadSettingsAsync(new
        {
            GlobalProtectionEnabled = true
        });
        var future = await LoadSettingsAsync(new
        {
            ConfigurationVersion = AppSettings.CurrentConfigurationVersion + 1,
            GlobalProtectionEnabled = true
        });

        Ensure(AppSettings.CurrentConfigurationVersion == 9, "configuration version is not nine");
        Ensure(settings.ConfigurationVersion == 9, "legacy settings did not migrate to version nine");
        Ensure(settings.MonitoringEnabled, "legacy monitoring state disabled startup monitoring");
        Ensure(settings.MonitorOnly, "legacy settings did not retain the current fail-closed engine gate");
        Ensure(
            !settings.AutomaticRecoveryEnabled &&
            !current.AutomaticRecoveryEnabled && current.MonitorOnly,
            "legacy or field-missing current settings granted automatic recovery authority");
        Ensure(
            !ReadProperty<bool>(settings, "GlobalProtectionEnabled"),
            "legacy MonitorOnly=false granted new global authority");
        Ensure(
            ReadProperty<bool>(current, "GlobalProtectionEnabled"),
            "an explicit current-version global protection choice was discarded");
        Ensure(
            !ReadProperty<bool>(missingVersion, "GlobalProtectionEnabled") &&
            !ReadProperty<bool>(future, "GlobalProtectionEnabled") &&
            ReadProperty<object>(future, "ReadStatus").ToString() == "ConservativeDefaults",
            "missing or future configuration metadata inherited global write authority");
        await WithSettingsRootAsync(async root =>
        {
            var path = Path.Combine(root, "settings.json");
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(
                path,
                JsonSerializer.Serialize(new
                {
                    ConfigurationVersion = AppSettings.CurrentConfigurationVersion + 1,
                    GlobalProtectionEnabled = true
                }));
            var service = new SettingsService(root);
            var conservative = await service.LoadAsync();
            var rawFutureBytes = await File.ReadAllBytesAsync(path);
            Ensure(
                conservative.ReadStatus == SettingsReadStatus.ConservativeDefaults &&
                await ThrowsAsync<InvalidDataException>(() => service.SaveAsync(conservative)),
                "a future settings snapshot was silently replaced by conservative defaults");
            Ensure(
                (await File.ReadAllBytesAsync(path)).SequenceEqual(rawFutureBytes),
                "saving a conservative future snapshot changed the unknown settings bytes");
        });
        var threadProtection = ReadBooleanMap(settings, "ThreadProtectionEnabled");
        Ensure(
            settings.ThreadEnabled.Count == 0 && threadProtection.Count == 0 &&
            !settings.ProtectNewThreadsByDefault,
            "legacy per-thread protection survived the version nine manual opt-in migration");
        var limits = ReadProperty<object>(settings, "AttachmentLimits");
        Ensure(
            ReadProperty<int>(limits, "MaximumAttachmentsPerMessage") == 20 &&
            ReadProperty<long>(limits, "MaximumBytesPerFile") == 100L * 1024 * 1024 &&
            ReadProperty<long>(limits, "MaximumBytesPerMessage") == 500L * 1024 * 1024 &&
            ReadProperty<long>(limits, "MaximumLibraryBytes") == 10L * 1024 * 1024 * 1024,
            "version seven attachment limits did not retain the approved defaults");

        await WithSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            await service.SaveAsync(new AppSettings { GlobalProtectionEnabled = true });
            var roundTrip = await service.LoadAsync();
            Ensure(
                roundTrip.GlobalProtectionEnabled &&
                roundTrip.ReadStatus == SettingsReadStatus.Healthy,
                "the current envelope did not round-trip explicit global protection");
            Ensure(
                await ThrowsAsync<NotSupportedException>(() => service.SaveAsync(new AppSettings
                {
                    ConfigurationVersion = AppSettings.CurrentConfigurationVersion + 1,
                    GlobalProtectionEnabled = true
                })),
                "a future in-memory configuration was silently downgraded and authorized");
        });
    }

    private static async Task TestPreviewMonitoringPersistenceAsync()
    {
        await WithSettingsRootAsync(async root =>
        {
            var productionService = new SettingsService(root);
            await productionService.SaveAsync(new AppSettings
            {
                MonitoringEnabled = false,
                MonitorOnly = true
            });
            using (var productionEnvelope = JsonDocument.Parse(
                       await File.ReadAllTextAsync(productionService.SettingsPath)))
            {
                Ensure(
                    productionEnvelope.RootElement
                        .GetProperty("Settings")
                        .GetProperty("MonitoringEnabled")
                        .GetBoolean(),
                    "the production settings policy stopped normalizing monitoring on");
            }

            var previewService = new SettingsService(
                root,
                monitoringEnabledAfterNormalization: false);
            var previewSettings = await previewService.LoadAsync();
            Ensure(
                !previewSettings.MonitoringEnabled && previewSettings.MonitorOnly,
                "safe preview loading inherited the production monitoring policy");

            await previewService.SaveAsync(previewSettings);
            using var previewEnvelope = JsonDocument.Parse(
                await File.ReadAllTextAsync(previewService.SettingsPath));
            using var priorEnvelope = JsonDocument.Parse(
                await File.ReadAllTextAsync(Path.Combine(root, "settings.previous.json")));
            Ensure(
                !previewEnvelope.RootElement
                    .GetProperty("Settings")
                    .GetProperty("MonitoringEnabled")
                    .GetBoolean() &&
                priorEnvelope.RootElement
                    .GetProperty("Settings")
                    .GetProperty("MonitoringEnabled")
                    .GetBoolean(),
                "safe preview persistence did not retain a disabled current generation and production previous generation");

            var reloadedPreview = await previewService.LoadAsync();
            Ensure(
                !reloadedPreview.MonitoringEnabled && reloadedPreview.MonitorOnly,
                "safe preview settings re-enabled monitoring after an envelope round trip");
            EnsureNoSettingsTemps(root);
        });
    }

    private static async Task TestAttachmentNormalizationAsync()
    {
        var threadId = Guid.NewGuid().ToString("D");
        var attachmentOnlyId = Guid.NewGuid().ToString("D");
        var longTextId = Guid.NewGuid().ToString("D");
        var maximumRetryId = Guid.NewGuid().ToString("D");
        var emptyId = Guid.NewGuid().ToString("D");
        var firstReferenceId = Guid.NewGuid().ToString("D");
        var secondReferenceId = Guid.NewGuid().ToString("D");
        var invalidReferenceId = Guid.NewGuid().ToString("D");
        var firstContentId = new string('A', 64);
        var secondContentId = new string('B', 64);
        var settings = await LoadSettingsAsync(new
        {
            ConfigurationVersion = 7,
            ThreadFollowUps = new Dictionary<string, object>
            {
                [threadId] = new
                {
                    Messages = new object[]
                    {
                        new
                        {
                            Id = attachmentOnlyId,
                            Message = string.Empty,
                            MaximumErrorRetries = (int?)null,
                            Order = 5,
                            Attachments = new object[]
                            {
                                new
                                {
                                    Id = invalidReferenceId,
                                    ContentId = new string('c', 64),
                                    OriginalFileName = "invalid.png",
                                    DetectedType = "image/png",
                                    OwnerInputKind = "local_image",
                                    ByteLength = 3L,
                                    Order = 0
                                },
                                new
                                {
                                    Id = secondReferenceId,
                                    ContentId = secondContentId,
                                    OriginalFileName = "second.png",
                                    DetectedType = "image/png",
                                    OwnerInputKind = "local_image",
                                    ByteLength = 2L,
                                    Order = 1
                                },
                                new
                                {
                                    Id = firstReferenceId,
                                    ContentId = firstContentId,
                                    OriginalFileName = "first.txt",
                                    DetectedType = "text/plain",
                                    OwnerInputKind = "local_file",
                                    ByteLength = 1L,
                                    Order = 9
                                },
                                new
                                {
                                    Id = firstReferenceId,
                                    ContentId = secondContentId,
                                    OriginalFileName = "duplicate.txt",
                                    DetectedType = "text/plain",
                                    OwnerInputKind = "local_file",
                                    ByteLength = 2L,
                                    Order = 10
                                }
                            }
                        },
                        new
                        {
                            Id = longTextId,
                            Message = " " + new string('x', 4001) + " ",
                            MaximumErrorRetries = 0,
                            Order = 1,
                            Attachments = Array.Empty<object>()
                        },
                        new
                        {
                            Id = maximumRetryId,
                            Message = "bounded retry",
                            MaximumErrorRetries = 10_000,
                            Order = 2,
                            Attachments = Array.Empty<object>()
                        },
                        new
                        {
                            Id = emptyId,
                            Message = "   ",
                            Order = 3,
                            Attachments = Array.Empty<object>()
                        }
                    }
                }
            }
        });

        Ensure(
            settings.ThreadFollowUps.TryGetValue(threadId, out var configured) &&
            configured.Messages.Count == 3,
            "attachment-only, text, and empty message validity was not normalized exactly");
        Ensure(
            configured!.Messages[0].Id == longTextId &&
            configured.Messages[0].Order == 0 &&
            configured.Messages[0].Message.Length == 4000 &&
            configured.Messages[0].MaximumErrorRetries == 0,
            "trimmed body or zero retry bounds changed");
        Ensure(
            configured.Messages[1].Id == maximumRetryId &&
            configured.Messages[1].Order == 1 &&
            configured.Messages[1].MaximumErrorRetries == 10_000,
            "maximum finite retry value changed");
        var attachmentOnly = configured.Messages[2];
        Ensure(
            attachmentOnly.Id == attachmentOnlyId &&
            attachmentOnly.Order == 2 &&
            attachmentOnly.Message.Length == 0 &&
            attachmentOnly.MaximumErrorRetries is null &&
            FollowUpRetryPolicy.GetEffectiveMaximumErrorRetries(
                attachmentOnly.MaximumErrorRetries) == 500,
            "attachment-only content or blank retry semantics changed");

        var attachments = ReadSequenceProperty(attachmentOnly, "Attachments");
        Ensure(attachments.Count == 2, "invalid or duplicate attachment references were retained");
        Ensure(
            ReadProperty<string>(attachments[0], "Id") == secondReferenceId &&
            ReadProperty<int>(attachments[0], "Order") == 0 &&
            ReadProperty<string>(attachments[0], "ContentId") == secondContentId &&
            ReadProperty<string>(attachments[1], "Id") == firstReferenceId &&
            ReadProperty<int>(attachments[1], "Order") == 1 &&
            ReadProperty<string>(attachments[1], "ContentId") == firstContentId,
            "attachment order, uppercase content identity, or duplicate rejection changed");
        Ensure(
            configured.Messages.All(message => message.Id != emptyId),
            "an empty body without attachments survived normalization");
    }

    private static async Task TestSettingsGenerationPersistenceAsync()
    {
        await WithSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            var previousPath = Path.Combine(root, "settings.previous.json");
            var markerPath = Path.Combine(root, "settings.initialized");
            Ensure(
                service.DataDirectory == root &&
                service.SettingsPath == Path.Combine(root, "settings.json"),
                "settings persistence escaped the isolated D-drive root");

            await service.SaveAsync(new AppSettings { RecentThreadLimit = 11 });
            Ensure(
                File.Exists(service.SettingsPath) &&
                File.Exists(previousPath) &&
                File.Exists(markerPath),
                "the first version seven save did not publish primary previous and marker files");
            var firstPrimary = ReadEnvelopeProbe(service.SettingsPath);
            var firstPrevious = ReadEnvelopeProbe(previousPath);
            Ensure(
                firstPrimary.SchemaVersion == 1 &&
                firstPrimary.Generation == 1 &&
                firstPrimary.RecentThreadLimit == 11 &&
                firstPrevious.Generation == 1 &&
                firstPrevious.RecentThreadLimit == 11 &&
                firstPrimary.Checksum == firstPrevious.Checksum,
                "the first envelope generation or fallback replica is inconsistent");
            EnsureNoSettingsTemps(root);

            await service.SaveAsync(new AppSettings { RecentThreadLimit = 22 });
            var secondPrimary = ReadEnvelopeProbe(service.SettingsPath);
            var secondPrevious = ReadEnvelopeProbe(previousPath);
            var loaded = await service.LoadAsync();
            Ensure(
                secondPrimary.Generation == 2 &&
                secondPrimary.RecentThreadLimit == 22 &&
                secondPrevious.Generation == 1 &&
                secondPrevious.RecentThreadLimit == 11,
                "the second save did not retain the first healthy generation as previous");
            Ensure(
                ReadProperty<long>(loaded, "SettingsGeneration") == 2 &&
                ReadProperty<long>(loaded, "PreviousSettingsGeneration") == 1 &&
                ReadProperty<object>(loaded, "ReadStatus").ToString() == "Healthy",
                "healthy envelope generation metadata was not projected to the loaded settings");
            EnsureNoSettingsTemps(root);
        });
    }

    private static async Task TestSettingsChecksumRecoveryAsync()
    {
        await WithSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            var previousPath = Path.Combine(root, "settings.previous.json");
            await service.SaveAsync(new AppSettings { RecentThreadLimit = 11 });
            await service.SaveAsync(new AppSettings { RecentThreadLimit = 22 });

            var primaryNode = JsonNode.Parse(await File.ReadAllTextAsync(service.SettingsPath)) ??
                              throw new InvalidOperationException("the primary envelope is not JSON");
            primaryNode["Settings"]!["RecentThreadLimit"] = 99;
            await File.WriteAllTextAsync(service.SettingsPath, primaryNode.ToJsonString());
            var corruptedPrimary = await File.ReadAllBytesAsync(service.SettingsPath);
            var recovered = await service.LoadAsync();
            Ensure(
                recovered.RecentThreadLimit == 11 &&
                ReadProperty<object>(recovered, "ReadStatus").ToString() == "RecoveredFromPrevious" &&
                ReadProperty<long>(recovered, "SettingsGeneration") == 0 &&
                ReadProperty<long>(recovered, "PreviousSettingsGeneration") == 1,
                "a checksum-invalid primary did not recover the marker-bound previous generation");
            Ensure(
                (await File.ReadAllBytesAsync(service.SettingsPath)).SequenceEqual(corruptedPrimary),
                "read-only checksum recovery rewrote the corrupt primary");

            await File.WriteAllTextAsync(previousPath, "{broken-previous");
            var conservative = await service.LoadAsync();
            Ensure(
                conservative.MonitoringEnabled &&
                conservative.MonitorOnly &&
                !ReadProperty<bool>(conservative, "GlobalProtectionEnabled") &&
                conservative.RecentThreadLimit == 30 &&
                ReadProperty<object>(conservative, "ReadStatus").ToString() == "ConservativeDefaults" &&
                ReadProperty<long>(conservative, "SettingsGeneration") == 0 &&
                ReadProperty<long>(conservative, "PreviousSettingsGeneration") == 0,
                "dual corruption did not return conservative non-authorizing defaults");
            EnsureNoSettingsTemps(root);
        });
    }

    private static async Task TestSettingsPublicationFailureAsync()
    {
        await WithSettingsRootAsync(async root =>
        {
            var service = new SettingsService(root);
            var previousPath = Path.Combine(root, "settings.previous.json");
            var markerPath = Path.Combine(root, "settings.initialized");
            await service.SaveAsync(new AppSettings { RecentThreadLimit = 11 });
            await service.SaveAsync(new AppSettings { RecentThreadLimit = 22 });
            var baselinePrimary = await File.ReadAllBytesAsync(service.SettingsPath);
            var baselinePrevious = await File.ReadAllBytesAsync(previousPath);
            var baselineMarker = await File.ReadAllBytesAsync(markerPath);

            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.Cancel();
                Ensure(
                    await ThrowsAsync<OperationCanceledException>(() => service.SaveAsync(
                        new AppSettings { RecentThreadLimit = 33 },
                        cancellation.Token)),
                    "a canceled settings save did not report cancellation");
            }

            EnsureSettingsFilesEqual(
                service.SettingsPath,
                previousPath,
                markerPath,
                baselinePrimary,
                baselinePrevious,
                baselineMarker,
                "cancellation changed a committed settings generation");

            File.Delete(previousPath);
            Directory.CreateDirectory(previousPath);
            try
            {
                Ensure(
                    await ThrowsAsync<Exception>(() => service.SaveAsync(
                        new AppSettings { RecentThreadLimit = 44 })),
                    "an unusable replacement target did not fail publication");
                Ensure(
                    (await File.ReadAllBytesAsync(service.SettingsPath)).SequenceEqual(baselinePrimary),
                    "replacement failure displaced the prior primary");
            }
            finally
            {
                Directory.Delete(previousPath);
                await File.WriteAllBytesAsync(previousPath, baselinePrevious);
            }

            Ensure(
                (await File.ReadAllBytesAsync(markerPath)).SequenceEqual(baselineMarker),
                "replacement failure changed the committed initialization marker");
            EnsureNoSettingsTemps(root);
        });
    }

    private static async Task TestManagedAttachmentStoreAsync()
    {
        var productAssembly = typeof(SettingsService).Assembly;
        _ = productAssembly.GetType(
                "CodexGuardian.Services.AttachmentTypeDetector",
                throwOnError: false)
            ?? throw new InvalidOperationException("AttachmentTypeDetector is absent.");
        var storeType = productAssembly.GetType(
                "CodexGuardian.Services.ManagedAttachmentStore",
                throwOnError: false)
            ?? throw new InvalidOperationException("ManagedAttachmentStore is absent.");
        var limitGuardType = productAssembly.GetType(
                "CodexGuardian.Services.AttachmentImportLimitGuard",
                throwOnError: false)
            ?? throw new InvalidOperationException("AttachmentImportLimitGuard is absent.");

        await WithAttachmentStoreRootAsync(async root =>
        {
            var dataRoot = Path.Combine(root, "data");
            var sourceRoot = Path.Combine(root, "sources");
            Directory.CreateDirectory(sourceRoot);
            var store = Activator.CreateInstance(storeType, dataRoot) as IManagedAttachmentStore
                        ?? throw new InvalidOperationException(
                            "ManagedAttachmentStore does not implement IManagedAttachmentStore.");
            var pngBytes = Convert.FromBase64String(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
            var contentId = Convert.ToHexString(SHA256.HashData(pngBytes));
            var exactLibraryLimits = new AttachmentLimitSettings
            {
                MaximumAttachmentsPerMessage = 2,
                MaximumBytesPerFile = pngBytes.Length,
                MaximumBytesPerMessage = pngBytes.Length,
                MaximumLibraryBytes = pngBytes.Length
            };

            await using var chunked = new ChunkedReadStream(pngBytes, maximumChunk: 3);
            var imported = await store.ImportBytesAsync(
                chunked,
                "pixel.png",
                exactLibraryLimits,
                CancellationToken.None);
            var expectedObjectPath = Path.Combine(
                dataRoot,
                "attachments",
                "objects",
                contentId[..2].ToLowerInvariant(),
                contentId + ".blob");
            Ensure(
                imported.ContentId == contentId &&
                imported.ByteLength == pngBytes.LongLength &&
                imported.DetectedType == "image/png" &&
                string.Equals(imported.ObjectPath, expectedObjectPath, StringComparison.Ordinal) &&
                File.Exists(expectedObjectPath),
                "stream import did not publish the canonical immutable PNG object");
            Ensure(
                Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(expectedObjectPath))) ==
                contentId,
                "independent object verification did not match the streamed SHA-256");

            var sourcePath = Path.Combine(sourceRoot, "pixel.png");
            await File.WriteAllBytesAsync(sourcePath, pngBytes);
            var duplicate = await store.ImportAsync(
                sourcePath,
                exactLibraryLimits,
                CancellationToken.None);
            var objectFiles = Directory.EnumerateFiles(
                    Path.Combine(dataRoot, "attachments", "objects"),
                    "*.blob",
                    SearchOption.AllDirectories)
                .ToArray();
            Ensure(
                duplicate == imported &&
                objectFiles.Length == 1 &&
                new FileInfo(objectFiles[0]).Length == pngBytes.LongLength,
                "reimporting identical content consumed a second object or library allocation");

            var reference = new PresetAttachmentReference
            {
                Id = Guid.NewGuid().ToString("D"),
                ContentId = contentId,
                OriginalFileName = "pixel.png",
                DetectedType = "image/png",
                OwnerInputKind = "local_image",
                ByteLength = pngBytes.LongLength,
                Order = 0
            };
            Ensure(
                await store.VerifyAsync(reference, CancellationToken.None) &&
                !await store.VerifyAsync(
                    reference with { ByteLength = reference.ByteLength + 1 },
                    CancellationToken.None),
                "managed object verification accepted a damaged attachment identity");

            var fileLimit = new AttachmentLimitSettings
            {
                MaximumAttachmentsPerMessage = 2,
                MaximumBytesPerFile = pngBytes.Length - 1,
                MaximumBytesPerMessage = pngBytes.Length * 2L,
                MaximumLibraryBytes = pngBytes.Length * 3L
            };
            await ExpectAttachmentFailureAsync(
                "FileTooLarge",
                async () =>
                {
                    await using var oversized = new ChunkedReadStream(pngBytes, maximumChunk: 2);
                    _ = await store.ImportBytesAsync(
                        oversized,
                        "oversized.png",
                        fileLimit,
                        CancellationToken.None);
                });

            var fakePng = pngBytes[..8]
                .Concat(Encoding.ASCII.GetBytes("not-a-decodable-png"))
                .ToArray();
            await ExpectAttachmentFailureAsync(
                "InvalidContent",
                async () =>
                {
                    await using var invalid = new MemoryStream(fakePng, writable: false);
                    _ = await store.ImportBytesAsync(
                        invalid,
                        "fake.png",
                        new AttachmentLimitSettings(),
                        CancellationToken.None);
                });

            var textBytes = Encoding.UTF8.GetBytes("unique managed text attachment");
            var capacityLimits = new AttachmentLimitSettings
            {
                MaximumAttachmentsPerMessage = 2,
                MaximumBytesPerFile = textBytes.Length,
                MaximumBytesPerMessage = textBytes.Length * 2L,
                MaximumLibraryBytes = pngBytes.LongLength + textBytes.LongLength - 1
            };
            await ExpectAttachmentFailureAsync(
                "LibraryCapacityExceeded",
                async () =>
                {
                    await using var unique = new MemoryStream(textBytes, writable: false);
                    _ = await store.ImportBytesAsync(
                        unique,
                        "unique.txt",
                        capacityLimits,
                        CancellationToken.None);
                });
            Ensure(
                Directory.EnumerateFiles(
                        Path.Combine(dataRoot, "attachments", "objects"),
                        "*.blob",
                        SearchOption.AllDirectories)
                    .Count() == 1 &&
                !Directory.EnumerateFiles(
                        Path.Combine(dataRoot, "attachments", "staging"),
                        "*.part",
                        SearchOption.TopDirectoryOnly)
                    .Any(),
                "a rejected import retained an object or staging file");

            ExpectAttachmentLimitFailure(
                limitGuardType,
                "TooManyAttachments",
                [1L, 1L, 1L],
                new AttachmentLimitSettings
                {
                    MaximumAttachmentsPerMessage = 2,
                    MaximumBytesPerFile = 4,
                    MaximumBytesPerMessage = 8,
                    MaximumLibraryBytes = 16
                });
            ExpectAttachmentLimitFailure(
                limitGuardType,
                "MessageTooLarge",
                [3L, 3L],
                new AttachmentLimitSettings
                {
                    MaximumAttachmentsPerMessage = 2,
                    MaximumBytesPerFile = 4,
                    MaximumBytesPerMessage = 5,
                    MaximumLibraryBytes = 16
                });

            await ExpectAttachmentFailureAsync(
                "SourceNotFound",
                async () =>
                {
                    _ = await store.ImportAsync(
                        Path.Combine(sourceRoot, "missing.png"),
                        new AttachmentLimitSettings(),
                        CancellationToken.None);
                });
            await ExpectAttachmentFailureAsync(
                "SourceIsDirectory",
                async () =>
                {
                    _ = await store.ImportAsync(
                        sourceRoot,
                        new AttachmentLimitSettings(),
                        CancellationToken.None);
                });
            await ExpectAttachmentFailureAsync(
                "InvalidSource",
                async () =>
                {
                    _ = await store.ImportAsync(
                        @"\\.\NUL",
                        new AttachmentLimitSettings(),
                        CancellationToken.None);
                });

            var junctionTarget = Path.Combine(root, "junction-target");
            var junctionPath = Path.Combine(root, "junction-source");
            Directory.CreateDirectory(junctionTarget);
            await File.WriteAllBytesAsync(Path.Combine(junctionTarget, "linked.png"), pngBytes);
            CreateJunction(junctionPath, junctionTarget);
            try
            {
                await ExpectAttachmentFailureAsync(
                    "SourceIsReparsePoint",
                    async () =>
                    {
                        _ = await store.ImportAsync(
                            Path.Combine(junctionPath, "linked.png"),
                            new AttachmentLimitSettings(),
                            CancellationToken.None);
                    });
            }
            finally
            {
                if (Directory.Exists(junctionPath))
                {
                    Directory.Delete(junctionPath);
                }
            }

            var serviceRoot = Path.Combine(
                Directory.GetCurrentDirectory(),
                "work",
                "CodexGuardian",
                "Services");
            var productionSource = File.ReadAllText(
                                       Path.Combine(serviceRoot, "AttachmentTypeDetector.cs")) +
                                   File.ReadAllText(
                                       Path.Combine(serviceRoot, "ManagedAttachmentStore.cs"));
            Ensure(
                productionSource.Contains("FileMode.CreateNew", StringComparison.Ordinal) &&
                productionSource.Contains("FileShare.None", StringComparison.Ordinal) &&
                productionSource.Contains("FileOptions.SequentialScan", StringComparison.Ordinal) &&
                productionSource.Contains(
                    "ArrayPool<byte>.Shared.Rent(CopyBufferBytes)",
                    StringComparison.Ordinal) &&
                productionSource.Contains("Flush(flushToDisk: true)", StringComparison.Ordinal) &&
                productionSource.Contains("File.Move(stagingPath, objectPath)", StringComparison.Ordinal) &&
                !productionSource.Contains("File.ReadAllBytes", StringComparison.Ordinal) &&
                !productionSource.Contains("Process.Start", StringComparison.Ordinal) &&
                !productionSource.Contains("UseShellExecute", StringComparison.Ordinal) &&
                !productionSource.Contains("ShellExecute", StringComparison.Ordinal),
                "attachment import lost bounded streaming or can open an object through shell association");
        });
    }

    private static async Task TestClipboardAndBatchImportAsync()
    {
        var productAssembly = typeof(SettingsService).Assembly;
        var readerType = productAssembly.GetType(
                "CodexGuardian.Services.ClipboardAttachmentReader",
                throwOnError: false)
            ?? throw new InvalidOperationException("ClipboardAttachmentReader is absent.");
        var importServiceType = productAssembly.GetType(
                "CodexGuardian.Services.AttachmentImportService",
                throwOnError: false)
            ?? throw new InvalidOperationException("AttachmentImportService is absent.");

        var limits = new AttachmentLimitSettings
        {
            MaximumAttachmentsPerMessage = 4,
            MaximumBytesPerFile = 1024 * 1024,
            MaximumBytesPerMessage = 4L * 1024 * 1024,
            MaximumLibraryBytes = 8L * 1024 * 1024
        };
        var bitmap = CreateClipboardBitmapFixture();
        var knownPngBytes = Convert.FromBase64String(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");

        var bitmapReads = 0;
        var bitmapEncodes = 0;
        Action<BitmapSource, Stream> recordingEncoder = (_, destination) =>
        {
            bitmapEncodes++;
            destination.Write(knownPngBytes);
        };
        var recordingReader = CreateReflectedInstance(readerType, recordingEncoder);
        var clipboardFiles = new[]
        {
            @"D:\synthetic\second.txt",
            @"D:\synthetic\first.png"
        };
        var fileSource = InvokeReflected(
            recordingReader,
            "Read",
            clipboardFiles,
            (Func<BitmapSource?>)(() =>
            {
                bitmapReads++;
                return bitmap;
            }),
            "ignored clipboard text",
            limits);
        Ensure(
            fileSource.GetType().Name == "ClipboardFileListSource" &&
            ReadSequenceProperty(fileSource, "FilePaths").Cast<string>().SequenceEqual(clipboardFiles) &&
            bitmapReads == 0 &&
            bitmapEncodes == 0,
            "clipboard file-list precedence read or encoded the bitmap representation");

        var pngSource = InvokeReflected(
            recordingReader,
            "Read",
            Array.Empty<string>(),
            (Func<BitmapSource?>)(() =>
            {
                bitmapReads++;
                return bitmap;
            }),
            "ignored clipboard text",
            limits);
        Ensure(
            pngSource.GetType().Name == "ClipboardPngSource" &&
            ReadProperty<string>(pngSource, "OriginalFileName") == "clipboard.png" &&
            ReadProperty<byte[]>(pngSource, "PngBytes").SequenceEqual(knownPngBytes) &&
            bitmapReads == 1 &&
            bitmapEncodes == 1,
            "bitmap-only clipboard input was not encoded exactly once as PNG");

        var defaultReader = CreateReflectedInstance(readerType);
        var deterministicFirst = InvokeReflected(
            defaultReader,
            "Read",
            Array.Empty<string>(),
            (Func<BitmapSource?>)(() => bitmap),
            null,
            limits);
        var deterministicSecond = InvokeReflected(
            defaultReader,
            "Read",
            Array.Empty<string>(),
            (Func<BitmapSource?>)(() => bitmap),
            null,
            limits);
        var firstPngBytes = ReadProperty<byte[]>(deterministicFirst, "PngBytes");
        var secondPngBytes = ReadProperty<byte[]>(deterministicSecond, "PngBytes");
        Ensure(
            firstPngBytes.Length > 8 &&
            firstPngBytes.AsSpan(0, 8).SequenceEqual(
                new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }) &&
            firstPngBytes.SequenceEqual(secondPngBytes),
            "the same clipboard bitmap fixture did not produce deterministic PNG bytes");

        var boundedLimits = new AttachmentLimitSettings
        {
            MaximumAttachmentsPerMessage = 1,
            MaximumBytesPerFile = 64,
            MaximumBytesPerMessage = 64,
            MaximumLibraryBytes = 64
        };
        Action<BitmapSource, Stream> oversizedEncoder = (_, destination) =>
            destination.Write(new byte[65]);
        var boundedReader = CreateReflectedInstance(readerType, oversizedEncoder);
        await ExpectAttachmentFailureAsync(
            "FileTooLarge",
            () =>
            {
                _ = InvokeReflected(
                    boundedReader,
                    "Read",
                    Array.Empty<string>(),
                    (Func<BitmapSource?>)(() => bitmap),
                    null,
                    boundedLimits);
                return Task.CompletedTask;
            });

        var invalidAttachmentLimits = new AttachmentLimitSettings
        {
            MaximumAttachmentsPerMessage = 0
        };
        var textSource = InvokeReflected(
            defaultReader,
            "Read",
            Array.Empty<string>(),
            (Func<BitmapSource?>)(() => null),
            "plain clipboard text",
            invalidAttachmentLimits);
        Ensure(
            textSource.GetType().Name == "ClipboardTextSource" &&
            ReadProperty<string>(textSource, "Text") == "plain clipboard text",
            "plain clipboard text was not separated from attachment input");

        var textStore = new RecordingManagedAttachmentStore();
        var textCleanupRequests = new List<IReadOnlyList<string>>();
        var textImporter = CreateReflectedInstance(
            importServiceType,
            textStore,
            (Func<IReadOnlyList<string>, CancellationToken, Task>)((contentIds, _) =>
            {
                textCleanupRequests.Add(contentIds.ToArray());
                return Task.CompletedTask;
            }),
            (Func<string, long>)textStore.ProbeLength,
            (Func<string>)(() => Guid.NewGuid().ToString("D")));
        var textResult = await InvokeReflectedTaskAsync(
            textImporter,
            "ImportClipboardAsync",
            textSource,
            invalidAttachmentLimits,
            CancellationToken.None);
        Ensure(
            ReadProperty<string>(textResult, "Text") == "plain clipboard text" &&
            ReadSequenceProperty(textResult, "Attachments").Count == 0 &&
            textStore.ImportCallCount == 0 &&
            textCleanupRequests.Count == 0,
            "plain clipboard text entered the managed attachment store");

        var bitmapStore = new RecordingManagedAttachmentStore();
        var bitmapCleanupRequests = new List<IReadOnlyList<string>>();
        var bitmapReferenceId = Guid.NewGuid().ToString("D");
        var bitmapImporter = CreateReflectedInstance(
            importServiceType,
            bitmapStore,
            (Func<IReadOnlyList<string>, CancellationToken, Task>)((contentIds, _) =>
            {
                bitmapCleanupRequests.Add(contentIds.ToArray());
                return Task.CompletedTask;
            }),
            (Func<string, long>)bitmapStore.ProbeLength,
            (Func<string>)(() => bitmapReferenceId));
        var bitmapResult = await InvokeReflectedTaskAsync(
            bitmapImporter,
            "ImportClipboardAsync",
            pngSource,
            limits,
            CancellationToken.None);
        var bitmapReferences = ReadSequenceProperty(bitmapResult, "Attachments")
            .Cast<PresetAttachmentReference>()
            .ToArray();
        Ensure(
            bitmapResult.GetType().GetProperty("Text") is { } bitmapTextProperty &&
            bitmapTextProperty.GetValue(bitmapResult) is null &&
            bitmapReferences.Length == 1 &&
            bitmapReferences[0].Id == bitmapReferenceId &&
            bitmapReferences[0].Order == 0 &&
            bitmapReferences[0].OwnerInputKind == "local_image" &&
            bitmapStore.ImportBytesCallCount == 1 &&
            bitmapStore.ImportedBytes.Single().SequenceEqual(knownPngBytes) &&
            bitmapCleanupRequests.Count == 0,
            "clipboard PNG did not converge on the managed byte-stream import path");

        var countPaths = new[]
        {
            @"D:\synthetic\count-a.txt",
            @"D:\synthetic\count-b.txt"
        };
        var countStore = new RecordingManagedAttachmentStore(new Dictionary<string, FakeAttachmentDescriptor>(
            StringComparer.Ordinal)
        {
            [countPaths[0]] = new(1, "text/plain"),
            [countPaths[1]] = new(1, "text/plain")
        });
        var countCleanupCalls = 0;
        var countIdCalls = 0;
        var countImporter = CreateReflectedInstance(
            importServiceType,
            countStore,
            (Func<IReadOnlyList<string>, CancellationToken, Task>)((_, _) =>
            {
                countCleanupCalls++;
                return Task.CompletedTask;
            }),
            (Func<string, long>)countStore.ProbeLength,
            (Func<string>)(() =>
            {
                countIdCalls++;
                return Guid.NewGuid().ToString("D");
            }));
        await ExpectAttachmentFailureAsync(
            "TooManyAttachments",
            async () =>
            {
                _ = await InvokeReflectedTaskAsync(
                    countImporter,
                    "ImportFilesAsync",
                    countPaths,
                    new AttachmentLimitSettings
                    {
                        MaximumAttachmentsPerMessage = 1,
                        MaximumBytesPerFile = 4,
                        MaximumBytesPerMessage = 4,
                        MaximumLibraryBytes = 8
                    },
                    CancellationToken.None);
            });
        Ensure(
            countStore.LengthProbeCount == 0 &&
            countStore.ImportCallCount == 0 &&
            countCleanupCalls == 0 &&
            countIdCalls == 0,
            "attachment count was not rejected before source probing or copying");

        var totalPaths = new[]
        {
            @"D:\synthetic\total-a.txt",
            @"D:\synthetic\total-b.txt"
        };
        var totalStore = new RecordingManagedAttachmentStore(new Dictionary<string, FakeAttachmentDescriptor>(
            StringComparer.Ordinal)
        {
            [totalPaths[0]] = new(3, "text/plain"),
            [totalPaths[1]] = new(3, "text/plain")
        });
        var totalCleanupCalls = 0;
        var totalIdCalls = 0;
        var totalImporter = CreateReflectedInstance(
            importServiceType,
            totalStore,
            (Func<IReadOnlyList<string>, CancellationToken, Task>)((_, _) =>
            {
                totalCleanupCalls++;
                return Task.CompletedTask;
            }),
            (Func<string, long>)totalStore.ProbeLength,
            (Func<string>)(() =>
            {
                totalIdCalls++;
                return Guid.NewGuid().ToString("D");
            }));
        await ExpectAttachmentFailureAsync(
            "MessageTooLarge",
            async () =>
            {
                _ = await InvokeReflectedTaskAsync(
                    totalImporter,
                    "ImportFilesAsync",
                    totalPaths,
                    new AttachmentLimitSettings
                    {
                        MaximumAttachmentsPerMessage = 2,
                        MaximumBytesPerFile = 4,
                        MaximumBytesPerMessage = 5,
                        MaximumLibraryBytes = 16
                    },
                    CancellationToken.None);
            });
        Ensure(
            totalStore.LengthProbeCount == 2 &&
            totalStore.ImportCallCount == 0 &&
            totalCleanupCalls == 0 &&
            totalIdCalls == 0,
            "attachment byte total was not reserved before copying");

        var orderedPaths = new[]
        {
            @"D:\synthetic\third.pdf",
            @"D:\synthetic\first.png",
            @"D:\synthetic\second.txt"
        };
        var orderedStore = new RecordingManagedAttachmentStore(new Dictionary<string, FakeAttachmentDescriptor>(
            StringComparer.Ordinal)
        {
            [orderedPaths[0]] = new(7, "application/pdf"),
            [orderedPaths[1]] = new(5, "image/png"),
            [orderedPaths[2]] = new(6, "text/plain")
        });
        var orderedCleanupRequests = new List<IReadOnlyList<string>>();
        var orderedIds = new[]
        {
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D")
        };
        var orderedIdIndex = 0;
        var orderedImporter = CreateReflectedInstance(
            importServiceType,
            orderedStore,
            (Func<IReadOnlyList<string>, CancellationToken, Task>)((contentIds, _) =>
            {
                orderedCleanupRequests.Add(contentIds.ToArray());
                return Task.CompletedTask;
            }),
            (Func<string, long>)orderedStore.ProbeLength,
            (Func<string>)(() =>
            {
                Ensure(
                    orderedStore.DurableObjects.Count == orderedPaths.Length,
                    "a visible reference was allocated before every object was durable");
                return orderedIds[orderedIdIndex++];
            }));
        var orderedResult = await InvokeReflectedTaskAsync(
            orderedImporter,
            "ImportFilesAsync",
            orderedPaths,
            limits,
            CancellationToken.None);
        var orderedReferences = ReadSequence(orderedResult, "ordered attachment result")
            .Cast<PresetAttachmentReference>()
            .ToArray();
        Ensure(
            orderedStore.ImportedSourcePaths.SequenceEqual(orderedPaths) &&
            orderedReferences.Length == orderedPaths.Length &&
            orderedReferences.Select(reference => reference.OriginalFileName).SequenceEqual(
                orderedPaths.Select(Path.GetFileName)) &&
            orderedReferences.Select(reference => reference.Order).SequenceEqual(new[] { 0, 1, 2 }) &&
            orderedReferences.Select(reference => reference.Id).SequenceEqual(orderedIds) &&
            orderedReferences.Select(reference => reference.OwnerInputKind).SequenceEqual(
                new[] { "local_file", "local_image", "local_file" }) &&
            orderedReferences.Select(reference => reference.ContentId).SequenceEqual(
                orderedStore.DurableObjects.Select(item => item.ContentId)) &&
            orderedIdIndex == orderedPaths.Length &&
            orderedCleanupRequests.Count == 0,
            "successful multi-file import changed order or published references before durability");

        var failedPaths = new[]
        {
            @"D:\synthetic\durable-before-failure.txt",
            @"D:\synthetic\rejected.png"
        };
        var failedStore = new RecordingManagedAttachmentStore(new Dictionary<string, FakeAttachmentDescriptor>(
            StringComparer.Ordinal)
        {
            [failedPaths[0]] = new(3, "text/plain"),
            [failedPaths[1]] = new(4, "image/png")
        })
        {
            FailOnImportCall = 2
        };
        var failedCleanupRequests = new List<IReadOnlyList<string>>();
        var failedCleanupTokenWasCancelable = false;
        var failedIdCalls = 0;
        var failedImporter = CreateReflectedInstance(
            importServiceType,
            failedStore,
            (Func<IReadOnlyList<string>, CancellationToken, Task>)((contentIds, cleanupToken) =>
            {
                failedCleanupTokenWasCancelable = cleanupToken.CanBeCanceled;
                failedCleanupRequests.Add(contentIds.ToArray());
                return Task.CompletedTask;
            }),
            (Func<string, long>)failedStore.ProbeLength,
            (Func<string>)(() =>
            {
                failedIdCalls++;
                return Guid.NewGuid().ToString("D");
            }));
        await ExpectAttachmentFailureAsync(
            "InvalidContent",
            async () =>
            {
                _ = await InvokeReflectedTaskAsync(
                    failedImporter,
                    "ImportFilesAsync",
                    failedPaths,
                    limits,
                    CancellationToken.None);
            });
        Ensure(
            failedStore.DurableObjects.Count == 1 &&
            failedIdCalls == 0 &&
            failedCleanupRequests.Count == 1 &&
            failedCleanupRequests[0].SequenceEqual(
                new[] { failedStore.DurableObjects[0].ContentId }) &&
            !failedCleanupTokenWasCancelable,
            "failed batch exposed partial references or omitted a cancellation-independent cleanup request");

        var importSourcePath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian",
            "Services",
            "AttachmentImportService.cs");
        var importSource = File.ReadAllText(importSourcePath);
        Ensure(
            importSource.Contains("requestZeroReferenceCleanupAsync", StringComparison.Ordinal) &&
            !importSource.Contains("File.Delete(", StringComparison.Ordinal) &&
            !importSource.Contains("Directory.Delete(", StringComparison.Ordinal),
            "batch rollback bypasses the Task 6 zero-reference proof boundary");
    }

    private static async Task TestAttachmentReferenceCoordinatorAsync()
    {
        var productAssembly = typeof(SettingsService).Assembly;
        var coordinatorType = productAssembly.GetType(
                "CodexGuardian.Services.AttachmentReferenceCoordinator",
                throwOnError: false)
            ?? throw new InvalidOperationException("AttachmentReferenceCoordinator is absent.");
        var authorityReaderType = productAssembly.GetType(
                "CodexGuardian.Services.IAttachmentReferenceAuthorityReader",
                throwOnError: false)
            ?? throw new InvalidOperationException(
                "IAttachmentReferenceAuthorityReader is absent.");
        var authoritySnapshotType = productAssembly.GetType(
                "CodexGuardian.Services.AttachmentReferenceAuthoritySnapshot",
                throwOnError: false)
            ?? throw new InvalidOperationException(
                "AttachmentReferenceAuthoritySnapshot is absent.");
        var operationReferenceType = productAssembly.GetType(
                "CodexGuardian.Services.AttachmentOperationReference",
                throwOnError: false)
            ?? throw new InvalidOperationException("AttachmentOperationReference is absent.");
        var operationStateType = productAssembly.GetType(
                "CodexGuardian.Services.AttachmentOperationReferenceState",
                throwOnError: false)
            ?? throw new InvalidOperationException(
                "AttachmentOperationReferenceState is absent.");

        await WithAttachmentStoreRootAsync(async root =>
        {
            var dataRoot = Path.Combine(root, "reference-authority");
            var store = new ManagedAttachmentStore(dataRoot);
            var settingsService = new SettingsService(dataRoot);
            var imported = await ImportManagedTextObjectAsync(
                store,
                "reference-proof.txt",
                "task6 reference proof sentinel");
            var reference = CreateManagedReference(imported, "reference-proof.txt");
            object currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                isHealthy: true,
                followUpGeneration: 11,
                recoveryGeneration: 12,
                draftVersion: 13,
                leaseVersion: 14,
                transactionVersion: 15);
            var authorityReader = CreateAuthorityReaderProxy(
                authorityReaderType,
                authoritySnapshotType,
                () => currentAuthoritySnapshot);
            var coordinator = CreateReflectedInstance(
                coordinatorType,
                dataRoot,
                store,
                settingsService,
                authorityReader);

            await settingsService.SaveAsync(CreateAttachmentSettings());
            await settingsService.SaveAsync(CreateAttachmentSettings(reference));
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                "a current settings reference permitted zero-reference proof creation");

            await settingsService.SaveAsync(CreateAttachmentSettings());
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                "a previous settings generation reference permitted deletion");

            await settingsService.SaveAsync(CreateAttachmentSettings());
            var baselineProof = await TryCreateZeroReferenceProofAsync(
                coordinator,
                imported.ContentId);
            Ensure(
                baselineProof is not null &&
                baselineProof.SettingsGeneration == 4 &&
                baselineProof.PreviousSettingsGeneration == 3 &&
                baselineProof.FollowUpJournalGeneration == 11 &&
                baselineProof.RecoveryJournalGeneration == 12 &&
                baselineProof.DraftVersion == 13 &&
                baselineProof.LeaseVersion == 14 &&
                baselineProof.TransactionVersion == 15,
                "the zero-reference proof omitted an authority generation");

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                11,
                12,
                16,
                14,
                15,
                draftContentIds: [imported.ContentId]);
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                "an active draft reference permitted deletion");

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                11,
                12,
                16,
                17,
                15,
                leaseContentIds: [imported.ContentId]);
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                "an active send lease permitted deletion");

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                11,
                12,
                16,
                17,
                18,
                transactionContentIds: [imported.ContentId]);
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                "an active attachment transaction permitted deletion");

            foreach (var state in new[] { "Prepared", "Dispatching", "Retryable", "Uncertain" })
            {
                currentAuthoritySnapshot = CreateAuthoritySnapshot(
                    authoritySnapshotType,
                    operationReferenceType,
                    operationStateType,
                    true,
                    21,
                    22,
                    23,
                    24,
                    25,
                    operations:
                    [
                        new OperationReferenceFixture(
                            imported.ContentId,
                            state,
                            SuccessorCompletedNormally: false,
                            RecoveryLineageClosed: false)
                    ]);
                Ensure(
                    await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                    $"a {state} operation reference permitted deletion");
            }

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                21,
                22,
                23,
                24,
                25,
                operations:
                [
                    new OperationReferenceFixture(
                        imported.ContentId,
                        "Confirmed",
                        SuccessorCompletedNormally: false,
                        RecoveryLineageClosed: false)
                ]);
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                "a confirmed operation with an incomplete successor released its attachment");

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                21,
                22,
                23,
                24,
                25,
                operations:
                [
                    new OperationReferenceFixture(
                        imported.ContentId,
                        "Confirmed",
                        SuccessorCompletedNormally: true,
                        RecoveryLineageClosed: false)
                ]);
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is not null,
                "a normally completed confirmed successor retained a journal-only pin");

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                isHealthy: false,
                followUpGeneration: 21,
                recoveryGeneration: 22,
                draftVersion: 23,
                leaseVersion: 24,
                transactionVersion: 25);
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null,
                "a corrupt journal authority produced a deletion proof");

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                31,
                32,
                33,
                34,
                35);
            var staleProof = await TryCreateZeroReferenceProofAsync(
                coordinator,
                imported.ContentId) ?? throw new InvalidOperationException(
                "a healthy zero-reference object did not produce a proof");
            await settingsService.SaveAsync(CreateAttachmentSettings());
            var staleResult = await InvokeReflectedTaskAsync(
                coordinator,
                "DeleteAsync",
                staleProof,
                CancellationToken.None);
            Ensure(
                ReadProperty<object>(staleResult, "Status").ToString() == "ProofStale" &&
                File.Exists(imported.ObjectPath),
                "a changed settings generation did not invalidate the captured proof");

            var freshProof = await TryCreateZeroReferenceProofAsync(
                coordinator,
                imported.ContentId) ?? throw new InvalidOperationException(
                "the refreshed zero-reference proof was not created");
            string cleanupMarkerPath;
            await using (var lockedObject = new FileStream(
                             imported.ObjectPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.None,
                             bufferSize: 4096,
                             FileOptions.SequentialScan))
            {
                var pendingResult = await InvokeReflectedTaskAsync(
                    coordinator,
                    "DeleteAsync",
                    freshProof,
                    CancellationToken.None);
                cleanupMarkerPath = ReadProperty<string>(
                    pendingResult,
                    "CleanupMarkerPath");
                Ensure(
                    ReadProperty<object>(pendingResult, "Status").ToString() == "CleanupPending" &&
                    File.Exists(imported.ObjectPath) &&
                    File.Exists(cleanupMarkerPath),
                    "a locked object was reported deleted or lost its cleanup marker");
            }

            var markerBytes = await File.ReadAllBytesAsync(cleanupMarkerPath);
            var markerText = Encoding.UTF8.GetString(markerBytes);
            using (var markerDocument = JsonDocument.Parse(markerBytes))
            {
                var propertyNames = markerDocument.RootElement
                    .EnumerateObject()
                    .Select(property => property.Name)
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToArray();
                Ensure(
                    propertyNames.SequenceEqual(
                        new[]
                        {
                            "FailureClass",
                            "OpaqueContentId",
                            "RetryAfterUtc",
                            "SchemaVersion"
                        }) &&
                    markerDocument.RootElement.GetProperty("OpaqueContentId").GetString() is
                        { Length: 32 } opaqueId &&
                    opaqueId.All(character =>
                        character is >= '0' and <= '9' or >= 'A' and <= 'F'),
                    "the cleanup marker schema is not bounded to opaque retry metadata");
            }

            Ensure(
                markerBytes.LongLength <= 512 &&
                !markerText.Contains(imported.ContentId, StringComparison.Ordinal) &&
                !markerText.Contains("reference-proof.txt", StringComparison.OrdinalIgnoreCase) &&
                !markerText.Contains("task6 reference proof sentinel", StringComparison.Ordinal) &&
                !markerText.Contains(dataRoot, StringComparison.OrdinalIgnoreCase) &&
                !Path.GetFileName(cleanupMarkerPath).Contains(
                    imported.ContentId,
                    StringComparison.Ordinal),
                "the cleanup marker leaked a hash, filename, source path, or attachment body");

            currentAuthoritySnapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                31,
                32,
                33,
                34,
                36);
            var retryProof = await TryCreateZeroReferenceProofAsync(
                coordinator,
                imported.ContentId) ?? throw new InvalidOperationException(
                "cleanup retry did not regenerate a fresh proof");
            var deletedResult = await InvokeReflectedTaskAsync(
                coordinator,
                "DeleteAsync",
                retryProof,
                CancellationToken.None);
            Ensure(
                ReadProperty<object>(deletedResult, "Status").ToString() == "Deleted" &&
                !File.Exists(imported.ObjectPath) &&
                !File.Exists(cleanupMarkerPath),
                "a fresh zero-reference proof did not delete and recheck the object");
        });

        await WithAttachmentStoreRootAsync(async root =>
        {
            var dataRoot = Path.Combine(root, "corrupt-settings-authority");
            var store = new ManagedAttachmentStore(dataRoot);
            var settingsService = new SettingsService(dataRoot);
            var imported = await ImportManagedTextObjectAsync(
                store,
                "corrupt-settings.txt",
                "task6 corrupt settings sentinel");
            await settingsService.SaveAsync(CreateAttachmentSettings());
            await File.WriteAllTextAsync(settingsService.SettingsPath, "{corrupt-primary");

            var snapshot = CreateAuthoritySnapshot(
                authoritySnapshotType,
                operationReferenceType,
                operationStateType,
                true,
                1,
                1,
                1,
                1,
                1);
            var reader = CreateAuthorityReaderProxy(
                authorityReaderType,
                authoritySnapshotType,
                () => snapshot);
            var coordinator = CreateReflectedInstance(
                coordinatorType,
                dataRoot,
                store,
                settingsService,
                reader);
            Ensure(
                await TryCreateZeroReferenceProofAsync(coordinator, imported.ContentId) is null &&
                File.Exists(imported.ObjectPath),
                "recovered or corrupt settings authorized physical deletion");
        });

        var serviceRoot = Path.Combine(
            Directory.GetCurrentDirectory(),
            "work",
            "CodexGuardian",
            "Services");
        var coordinatorSource = File.ReadAllText(
            Path.Combine(serviceRoot, "AttachmentReferenceCoordinator.cs"));
        var storeSource = File.ReadAllText(Path.Combine(serviceRoot, "ManagedAttachmentStore.cs"));
        var settingsSource = File.ReadAllText(Path.Combine(serviceRoot, "SettingsService.cs"));
        Ensure(
            coordinatorSource.Contains("new Mutex", StringComparison.Ordinal) &&
            coordinatorSource.Contains("AttachmentMutationLeaseRegistry", StringComparison.Ordinal) &&
            storeSource.Contains("FileOptions.DeleteOnClose", StringComparison.Ordinal) &&
            storeSource.Contains("FlushFileBuffers", StringComparison.Ordinal) &&
            settingsSource.Contains("_attachmentMutationGate", StringComparison.Ordinal) &&
            !coordinatorSource.Contains("CreationTime", StringComparison.Ordinal) &&
            !coordinatorSource.Contains("LastWriteTime", StringComparison.Ordinal),
            "reference deletion lost the single-writer, durable-delete, or no-age contracts");
    }

    private static Task TestAttachmentDraftViewModelAsync()
    {
        var productAssembly = typeof(SettingsService).Assembly;
        var attachmentItemType = productAssembly.GetType(
                "CodexGuardian.ViewModels.AttachmentItemViewModel",
                throwOnError: false)
            ?? throw new InvalidOperationException("AttachmentItemViewModel is absent.");
        var mainViewModelType = productAssembly.GetType(
                "CodexGuardian.ViewModels.MainViewModel",
                throwOnError: true)!;
        var firstReference = new PresetAttachmentReference
        {
            Id = "14000000-0000-4000-8000-000000000001",
            ContentId = Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes("task7-image-attachment"))),
            OriginalFileName = "layout-reference.png",
            DetectedType = "image/png",
            OwnerInputKind = "local_image",
            ByteLength = 2048,
            Order = 0
        };
        var secondReference = new PresetAttachmentReference
        {
            Id = "14000000-0000-4000-8000-000000000002",
            ContentId = Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes("task7-file-attachment"))),
            OriginalFileName = "acceptance-notes.txt",
            DetectedType = "text/plain",
            OwnerInputKind = "local_file",
            ByteLength = 3072,
            Order = 1
        };
        var firstItem = CreateReflectedInstance(attachmentItemType, firstReference);
        var secondItem = CreateReflectedInstance(attachmentItemType, secondReference);
        Ensure(
            ReadProperty<string>(firstItem, "Id") == firstReference.Id &&
            ReadProperty<string>(firstItem, "ContentId") == firstReference.ContentId &&
            ReadProperty<string>(firstItem, "OriginalFileName") == firstReference.OriginalFileName &&
            ReadProperty<long>(firstItem, "ByteLength") == firstReference.ByteLength &&
            ReadProperty<bool>(firstItem, "IsImage") &&
            ReadProperty<string>(firstItem, "SizeText").Length > 0 &&
            ReadProperty<string>(firstItem, "AutomationName").Contains(
                firstReference.OriginalFileName,
                StringComparison.Ordinal),
            "the attachment draft item lost immutable identity, size, type, or UIA text");

        var message = new FollowUpMessageItem
        {
            Id = "14000000-0000-4000-8000-000000000010",
            Message = string.Empty
        };
        InvokeReflected(message, "ConfigureAttachmentLimits", new AttachmentLimitSettings());
        var attachments = ReadProperty<object>(message, "Attachments") as IList
                          ?? throw new InvalidOperationException(
                              "FollowUpMessageItem.Attachments is not a mutable draft collection.");
        attachments.Add(firstItem);
        attachments.Add(secondItem);
        Ensure(
            ReadProperty<bool>(message, "HasAttachments") &&
            ReadProperty<int>(message, "AttachmentCount") == 2 &&
            ReadProperty<long>(message, "AttachmentByteLength") == 5120 &&
            ReadProperty<string>(message, "AttachmentLimitStatus")
                .Replace(" ", string.Empty, StringComparison.Ordinal)
                .Contains("2/20", StringComparison.Ordinal),
            "attachment draft totals or configured limits are not projected");

        var hasContentMethod = mainViewModelType.GetMethod(
                                   "HasSaveableFollowUpContent",
                                   BindingFlags.Static | BindingFlags.NonPublic)
                               ?? throw new InvalidOperationException(
                                   "MainViewModel.HasSaveableFollowUpContent is absent.");
        Ensure(
            hasContentMethod.Invoke(null, [message]) is true,
            "an attachment-only draft was rejected as empty");
        var emptyMessage = new FollowUpMessageItem
        {
            Id = "14000000-0000-4000-8000-000000000011",
            Message = string.Empty
        };
        Ensure(
            hasContentMethod.Invoke(null, [emptyMessage]) is false,
            "an empty body without attachments became saveable");

        var moveMethod = mainViewModelType.GetMethod(
                             "MoveFollowUpAttachmentDraft",
                             BindingFlags.Static | BindingFlags.NonPublic)
                         ?? throw new InvalidOperationException(
                             "MainViewModel.MoveFollowUpAttachmentDraft is absent.");
        Ensure(
            moveMethod.Invoke(null, [message, secondItem, 0]) is true &&
            ReferenceEquals(attachments[0], secondItem) &&
            ReadProperty<int>(secondItem, "Order") == 0 &&
            ReadProperty<int>(firstItem, "Order") == 1,
            "attachment draft reorder did not preserve collection and ordinal identity");
        var roundTrippedReference = InvokeReflected(secondItem, "ToReference");
        Ensure(
            ReadProperty<string>(roundTrippedReference, "Id") == secondReference.Id &&
            ReadProperty<string>(roundTrippedReference, "ContentId") == secondReference.ContentId &&
            ReadProperty<int>(roundTrippedReference, "Order") == 0,
            "attachment draft round-trip changed durable identity or order");

        var projectRoot = Directory.GetCurrentDirectory();
        var productRoot = Path.Combine(projectRoot, "work", "CodexGuardian");
        var page = File.ReadAllText(Path.Combine(productRoot, "MainWindow.xaml"));
        var mainViewModelSource = File.ReadAllText(
            Path.Combine(productRoot, "ViewModels", "MainViewModel.cs"));
        var recoveryModelsSource = File.ReadAllText(
            Path.Combine(productRoot, "Models", "RecoveryModels.cs"));
        var previewFixtureSource = File.ReadAllText(Path.Combine(productRoot, "Program.cs"));
        var chineseResources = File.ReadAllText(
            Path.Combine(productRoot, "Localization", "AppStrings.resx"));
        var englishResources = File.ReadAllText(
            Path.Combine(productRoot, "Localization", "AppStrings.en.resx"));
        Ensure(
            page.Contains("FollowUpAttachmentPickerButton", StringComparison.Ordinal) &&
            page.Contains("FollowUpAttachmentRail", StringComparison.Ordinal) &&
            page.Contains("FollowUpAttachmentDragGrip", StringComparison.Ordinal) &&
            page.Contains("FollowUpAttachmentLimitStatus", StringComparison.Ordinal) &&
            page.Contains("ItemsSource=\"{Binding Attachments}\"", StringComparison.Ordinal) &&
            !page.Contains("FollowUpAttachmentMoveUpButton", StringComparison.Ordinal) &&
            !page.Contains("FollowUpAttachmentMoveDownButton", StringComparison.Ordinal),
            "the attachment editor lost its compact picker, rail, grip, limit, or no-button-order contract");
        Ensure(
            mainViewModelSource.Contains("definition.Attachments", StringComparison.Ordinal) &&
            mainViewModelSource.Contains("Attachments = attachments", StringComparison.Ordinal) &&
            mainViewModelSource.Contains("SaveFollowUpMessagesCommand", StringComparison.Ordinal) &&
            recoveryModelsSource.Contains(
                "ObservableCollection<AttachmentItemViewModel> Attachments",
                StringComparison.Ordinal) &&
            previewFixtureSource.Contains("Attachments =", StringComparison.Ordinal),
            "attachment drafts bypassed load, explicit save, model, or isolated preview projection");
        foreach (var key in new[]
                 {
                     "FollowUp.AddAttachment",
                     "FollowUp.RemoveAttachment",
                     "FollowUp.AttachmentDragHandle",
                     "FollowUp.InvalidAttachments"
                 })
        {
            Ensure(
                chineseResources.Contains($"name=\"{key}\"", StringComparison.Ordinal) &&
                englishResources.Contains($"name=\"{key}\"", StringComparison.Ordinal),
                $"attachment localization key parity is missing for {key}");
        }

        return Task.CompletedTask;
    }

    private static async Task<ManagedAttachmentObject> ImportManagedTextObjectAsync(
        ManagedAttachmentStore store,
        string originalFileName,
        string content)
    {
        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content), writable: false);
        return await store.ImportBytesAsync(
            stream,
            originalFileName,
            new AttachmentLimitSettings(),
            CancellationToken.None);
    }

    private static PresetAttachmentReference CreateManagedReference(
        ManagedAttachmentObject imported,
        string originalFileName) =>
        new()
        {
            Id = Guid.NewGuid().ToString("D"),
            ContentId = imported.ContentId,
            OriginalFileName = originalFileName,
            DetectedType = imported.DetectedType,
            OwnerInputKind = string.Equals(
                imported.DetectedType,
                "image/png",
                StringComparison.Ordinal)
                ? "local_image"
                : "local_file",
            ByteLength = imported.ByteLength,
            Order = 0
        };

    private static AppSettings CreateAttachmentSettings(
        params PresetAttachmentReference[] references)
    {
        var settings = new AppSettings();
        if (references.Length == 0)
        {
            return settings;
        }

        settings.ThreadFollowUps[Guid.NewGuid().ToString("D")] = new ThreadFollowUpSettings
        {
            Messages =
            [
                new FollowUpMessageDefinition
                {
                    Id = Guid.NewGuid().ToString("D"),
                    Message = string.Empty,
                    Attachments = references
                        .Select((reference, index) => reference with { Order = index })
                        .ToArray(),
                    Order = 0
                }
            ]
        };
        return settings;
    }

    private static object CreateAuthorityReaderProxy(
        Type authorityReaderType,
        Type authoritySnapshotType,
        Func<object> snapshotFactory)
    {
        var createMethod = typeof(DispatchProxy)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Single(method =>
                method.Name == nameof(DispatchProxy.Create) &&
                method.IsGenericMethodDefinition &&
                method.GetGenericArguments().Length == 2 &&
                method.GetParameters().Length == 0);
        var proxy = createMethod
                        .MakeGenericMethod(authorityReaderType, typeof(RuntimeDispatchProxy))
                        .Invoke(null, null)
                    ?? throw new InvalidOperationException(
                        "the runtime authority reader proxy could not be created");
        ((RuntimeDispatchProxy)proxy).Handler = (method, arguments) =>
        {
            Ensure(method.Name == "ReadAsync", "the coordinator invoked an unknown authority method");
            var cancellationToken = arguments is { Length: > 0 } &&
                                    arguments[0] is CancellationToken token
                ? token
                : CancellationToken.None;
            cancellationToken.ThrowIfCancellationRequested();
            var snapshot = snapshotFactory();
            var fromResult = typeof(Task)
                .GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Single(candidate =>
                    candidate.Name == nameof(Task.FromResult) &&
                    candidate.IsGenericMethodDefinition &&
                    candidate.GetParameters().Length == 1)
                .MakeGenericMethod(authoritySnapshotType);
            return fromResult.Invoke(null, [snapshot]);
        };
        return proxy;
    }

    private static object CreateAuthoritySnapshot(
        Type authoritySnapshotType,
        Type operationReferenceType,
        Type operationStateType,
        bool isHealthy,
        long followUpGeneration,
        long recoveryGeneration,
        long draftVersion,
        long leaseVersion,
        long transactionVersion,
        IReadOnlyList<string>? draftContentIds = null,
        IReadOnlyList<string>? leaseContentIds = null,
        IReadOnlyList<string>? transactionContentIds = null,
        IReadOnlyList<OperationReferenceFixture>? operations = null)
    {
        var operationItems = operations ?? [];
        var operationArray = Array.CreateInstance(operationReferenceType, operationItems.Count);
        for (var index = 0; index < operationItems.Count; index++)
        {
            var fixture = operationItems[index];
            operationArray.SetValue(
                CreateReflectedInstance(
                    operationReferenceType,
                    fixture.ContentId,
                    Enum.Parse(operationStateType, fixture.State, ignoreCase: false),
                    fixture.SuccessorCompletedNormally,
                    fixture.RecoveryLineageClosed),
                index);
        }

        return CreateReflectedInstance(
            authoritySnapshotType,
            isHealthy,
            followUpGeneration,
            recoveryGeneration,
            draftVersion,
            leaseVersion,
            transactionVersion,
            (draftContentIds ?? []).ToArray(),
            (leaseContentIds ?? []).ToArray(),
            (transactionContentIds ?? []).ToArray(),
            operationArray);
    }

    private static async Task<ZeroReferenceProof?> TryCreateZeroReferenceProofAsync(
        object coordinator,
        string contentId) =>
        await InvokeReflectedNullableTaskAsync(
            coordinator,
            "TryCreateZeroReferenceProofAsync",
            contentId,
            CancellationToken.None) as ZeroReferenceProof;

    private sealed record OperationReferenceFixture(
        string ContentId,
        string State,
        bool SuccessorCompletedNormally,
        bool RecoveryLineageClosed);

    private static BitmapSource CreateClipboardBitmapFixture()
    {
        var pixels = new byte[]
        {
            0x10, 0x20, 0x30, 0xFF,
            0xA0, 0xB0, 0xC0, 0xFF
        };
        var bitmap = BitmapSource.Create(
            pixelWidth: 2,
            pixelHeight: 1,
            dpiX: 96,
            dpiY: 96,
            pixelFormat: PixelFormats.Bgra32,
            palette: null,
            pixels: pixels,
            stride: 8);
        bitmap.Freeze();
        return bitmap;
    }

    private static object CreateReflectedInstance(Type type, params object?[] arguments) =>
        Activator.CreateInstance(
            type,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: arguments,
            culture: null) ?? throw new InvalidOperationException(
            $"{type.FullName} could not be constructed.");

    private static object InvokeReflected(
        object target,
        string methodName,
        params object?[] arguments)
    {
        var method = target.GetType()
                         .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                         .Where(candidate => string.Equals(candidate.Name, methodName, StringComparison.Ordinal))
                         .Where(candidate => candidate.GetParameters().Length == arguments.Length)
                         .SingleOrDefault(candidate => candidate.GetParameters()
                             .Zip(arguments)
                             .All(pair => pair.Second is null
                                 ? !pair.First.ParameterType.IsValueType ||
                                   Nullable.GetUnderlyingType(pair.First.ParameterType) is not null
                                 : pair.First.ParameterType.IsInstanceOfType(pair.Second)))
                     ?? throw new InvalidOperationException(
                         $"{target.GetType().FullName}.{methodName} with {arguments.Length} compatible arguments is absent or ambiguous.");
        try
        {
            return method.Invoke(target, arguments) ?? throw new InvalidOperationException(
                $"{target.GetType().FullName}.{methodName} returned null.");
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            throw exception.InnerException;
        }
    }

    private static async Task<object> InvokeReflectedTaskAsync(
        object target,
        string methodName,
        params object?[] arguments)
    {
        var invocation = InvokeReflected(target, methodName, arguments);
        if (invocation is not Task task)
        {
            throw new InvalidOperationException(
                $"{target.GetType().FullName}.{methodName} did not return Task.");
        }

        await task;
        return task.GetType().GetProperty("Result")?.GetValue(task)
               ?? throw new InvalidOperationException(
                   $"{target.GetType().FullName}.{methodName} returned no result.");
    }

    private static async Task<object?> InvokeReflectedNullableTaskAsync(
        object target,
        string methodName,
        params object?[] arguments)
    {
        var invocation = InvokeReflected(target, methodName, arguments);
        if (invocation is not Task task)
        {
            throw new InvalidOperationException(
                $"{target.GetType().FullName}.{methodName} did not return Task.");
        }

        await task;
        var resultProperty = task.GetType().GetProperty("Result") ??
                             throw new InvalidOperationException(
                                 $"{target.GetType().FullName}.{methodName} returned no result property.");
        return resultProperty.GetValue(task);
    }

    private static IReadOnlyList<object> ReadSequence(object? value, string detail) =>
        value is IEnumerable sequence
            ? sequence.Cast<object>().ToArray()
            : throw new InvalidOperationException($"{detail} is not enumerable.");

    private sealed record FakeAttachmentDescriptor(long ByteLength, string DetectedType);

    private sealed class RecordingManagedAttachmentStore : IManagedAttachmentStore
    {
        private readonly IReadOnlyDictionary<string, FakeAttachmentDescriptor> _fileDescriptors;

        internal RecordingManagedAttachmentStore(
            IReadOnlyDictionary<string, FakeAttachmentDescriptor>? fileDescriptors = null)
        {
            _fileDescriptors = fileDescriptors ??
                               new Dictionary<string, FakeAttachmentDescriptor>(StringComparer.Ordinal);
        }

        internal int? FailOnImportCall { get; init; }

        internal int LengthProbeCount { get; private set; }

        internal int ImportCallCount { get; private set; }

        internal int ImportBytesCallCount { get; private set; }

        internal List<string> ImportedSourcePaths { get; } = [];

        internal List<byte[]> ImportedBytes { get; } = [];

        internal List<ManagedAttachmentObject> DurableObjects { get; } = [];

        internal long ProbeLength(string sourcePath)
        {
            LengthProbeCount++;
            return GetDescriptor(sourcePath).ByteLength;
        }

        public Task<ManagedAttachmentObject> ImportAsync(
            string sourcePath,
            AttachmentLimitSettings limits,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ImportedSourcePaths.Add(sourcePath);
            var descriptor = GetDescriptor(sourcePath);
            var identityBytes = Encoding.UTF8.GetBytes(
                sourcePath + "|" + descriptor.ByteLength + "|" + descriptor.DetectedType);
            return Task.FromResult(CompleteImport(
                Path.GetFileName(sourcePath),
                descriptor.ByteLength,
                descriptor.DetectedType,
                identityBytes));
        }

        public async Task<ManagedAttachmentObject> ImportBytesAsync(
            Stream source,
            string originalFileName,
            AttachmentLimitSettings limits,
            CancellationToken cancellationToken)
        {
            ImportBytesCallCount++;
            await using var copy = new MemoryStream();
            await source.CopyToAsync(copy, cancellationToken);
            var bytes = copy.ToArray();
            ImportedBytes.Add(bytes);
            var detectedType = string.Equals(
                Path.GetExtension(originalFileName),
                ".png",
                StringComparison.OrdinalIgnoreCase)
                ? "image/png"
                : "application/octet-stream";
            return CompleteImport(
                originalFileName,
                bytes.LongLength,
                detectedType,
                bytes);
        }

        public Task<bool> VerifyAsync(
            PresetAttachmentReference reference,
            CancellationToken cancellationToken) =>
            Task.FromResult(false);

        private FakeAttachmentDescriptor GetDescriptor(string sourcePath) =>
            _fileDescriptors.TryGetValue(sourcePath, out var descriptor)
                ? descriptor
                : throw new InvalidOperationException(
                    $"No synthetic descriptor exists for {sourcePath}.");

        private ManagedAttachmentObject CompleteImport(
            string originalFileName,
            long byteLength,
            string detectedType,
            byte[] identityBytes)
        {
            ImportCallCount++;
            if (FailOnImportCall == ImportCallCount)
            {
                throw AttachmentImportException.Create(
                    AttachmentImportFailureCode.InvalidContent,
                    $"Synthetic import failure for {originalFileName}.");
            }

            var contentId = Convert.ToHexString(SHA256.HashData(identityBytes));
            var imported = new ManagedAttachmentObject(
                contentId,
                byteLength,
                detectedType,
                Path.Combine(@"D:\synthetic-store", contentId + ".blob"));
            DurableObjects.Add(imported);
            return imported;
        }
    }

    private static async Task WithAttachmentStoreRootAsync(Func<string, Task> action)
    {
        var root = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "CodexGuardian",
            "attachment-store-task4-" + Guid.NewGuid().ToString("N")));
        Ensure(
            root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase),
            "attachment store tests must use the declared D-drive TEMP root");
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

    private static async Task ExpectAttachmentFailureAsync(
        string expectedCode,
        Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception exception)
        {
            EnsureAttachmentFailureCode(exception, expectedCode);
            return;
        }

        throw new InvalidOperationException(
            $"attachment operation did not report {expectedCode}");
    }

    private static void ExpectAttachmentLimitFailure(
        Type guardType,
        string expectedCode,
        IReadOnlyList<long> byteLengths,
        AttachmentLimitSettings limits)
    {
        var method = guardType.GetMethod(
                         "EnsureMessageWithinLimits",
                         BindingFlags.Static | BindingFlags.NonPublic)
                     ?? throw new InvalidOperationException(
                         "AttachmentImportLimitGuard.EnsureMessageWithinLimits is absent.");
        try
        {
            method.Invoke(null, [byteLengths, limits]);
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            EnsureAttachmentFailureCode(exception.InnerException, expectedCode);
            return;
        }

        throw new InvalidOperationException(
            $"attachment limit guard did not report {expectedCode}");
    }

    private static void EnsureAttachmentFailureCode(Exception exception, string expectedCode)
    {
        var code = exception.GetType().GetProperty("Code")?.GetValue(exception)?.ToString();
        Ensure(
            string.Equals(code, expectedCode, StringComparison.Ordinal),
            $"expected attachment failure {expectedCode}, got {exception.GetType().Name}/{code}");
    }

    private static void CreateJunction(string junctionPath, string targetPath)
    {
        var command = Environment.GetEnvironmentVariable("ComSpec") ??
                      Path.Combine(Environment.SystemDirectory, "cmd.exe");
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = command,
            Arguments = $"/d /c mklink /J \"{junctionPath}\" \"{targetPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        }) ?? throw new InvalidOperationException("junction helper did not start");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Ensure(
            process.ExitCode == 0 && Directory.Exists(junctionPath),
            $"junction helper failed: {output} {error}");
    }

    private static async Task WithSettingsRootAsync(Func<string, Task> action)
    {
        var root = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "CodexGuardian",
            "attachment-settings-generation-" + Guid.NewGuid().ToString("N")));
        Ensure(
            root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase),
            "settings generation tests must use the declared D-drive TEMP root");
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

    private static EnvelopeProbe ReadEnvelopeProbe(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var settings = root.GetProperty("Settings");
        var checksum = root.GetProperty("Checksum").GetString() ?? string.Empty;
        Ensure(
            checksum.Length == 64 && checksum.All(character =>
                character is >= '0' and <= '9' or >= 'A' and <= 'F'),
            "the envelope checksum is not canonical uppercase SHA-256");
        return new EnvelopeProbe(
            root.GetProperty("SchemaVersion").GetInt32(),
            root.GetProperty("Generation").GetInt64(),
            settings.GetProperty("RecentThreadLimit").GetInt32(),
            checksum);
    }

    private static void EnsureNoSettingsTemps(string root) =>
        Ensure(
            !Directory.EnumerateFiles(root, ".settings*.*.tmp", SearchOption.TopDirectoryOnly).Any(),
            "settings persistence retained a temporary generation file");

    private static void EnsureSettingsFilesEqual(
        string primaryPath,
        string previousPath,
        string markerPath,
        byte[] expectedPrimary,
        byte[] expectedPrevious,
        byte[] expectedMarker,
        string detail) =>
        Ensure(
            File.ReadAllBytes(primaryPath).SequenceEqual(expectedPrimary) &&
            File.ReadAllBytes(previousPath).SequenceEqual(expectedPrevious) &&
            File.ReadAllBytes(markerPath).SequenceEqual(expectedMarker),
            detail);

    private sealed record EnvelopeProbe(
        int SchemaVersion,
        long Generation,
        int RecentThreadLimit,
        string Checksum);

    private static async Task<AppSettings> LoadSettingsAsync(object document)
    {
        var root = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "CodexGuardian",
            "attachment-foundation-task2-" + Guid.NewGuid().ToString("N")));
        Ensure(
            root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase),
            "attachment settings tests must use the declared D-drive TEMP root");
        try
        {
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(
                Path.Combine(root, "settings.json"),
                JsonSerializer.Serialize(document));
            return await new SettingsService(root).LoadAsync();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static IReadOnlyDictionary<string, bool> ReadBooleanMap(
        object instance,
        string propertyName) =>
        ReadSequenceProperty(instance, propertyName)
            .ToDictionary(
                item => ReadProperty<string>(item, "Key"),
                item => ReadProperty<bool>(item, "Value"),
                StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyList<object> ReadSequenceProperty(
        object instance,
        string propertyName)
    {
        var value = instance.GetType().GetProperty(propertyName)?.GetValue(instance);
        return value is IEnumerable sequence
            ? sequence.Cast<object>().ToArray()
            : throw new InvalidOperationException(
                $"{propertyName} is missing or is not enumerable.");
    }

    private static T ReadProperty<T>(object instance, string propertyName)
    {
        var value = instance.GetType().GetProperty(propertyName)?.GetValue(instance);
        return value is T typed
            ? typed
            : throw new InvalidOperationException(
                $"{propertyName} is missing or does not have type {typeof(T).Name}.");
    }

    private static void EnsureRequiredInitProperty<T>(Type declaringType, string propertyName)
    {
        var property = EnsureInitProperty<T>(declaringType, propertyName);
        Ensure(
            property.GetCustomAttribute<RequiredMemberAttribute>() is not null,
            $"{propertyName} must remain required");
    }

    private static PropertyInfo EnsureInitProperty<T>(Type declaringType, string propertyName)
    {
        var property = declaringType.GetProperty(propertyName) ?? throw new InvalidOperationException(
            $"{propertyName} is missing.");
        Ensure(
            property.PropertyType == typeof(T),
            $"{propertyName} must have type {typeof(T).Name}");
        Ensure(
            property.SetMethod?.ReturnParameter
                .GetRequiredCustomModifiers()
                .Contains(typeof(IsExternalInit)) == true,
            $"{propertyName} must remain init-only");
        return property;
    }

    private static void RunCase(
        string name,
        Action action,
        Action<bool, string> assert)
    {
        try
        {
            action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
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

    private static async Task<bool> ThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private sealed class ChunkedReadStream(byte[] bytes, int maximumChunk) : Stream
    {
        private int _offset;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var count = Math.Min(
                Math.Min(maximumChunk, buffer.Length),
                bytes.Length - _offset);
            if (count <= 0)
            {
                return 0;
            }

            bytes.AsSpan(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private static void Ensure(bool condition, string detail)
    {
        if (!condition)
        {
            throw new InvalidOperationException(detail);
        }
    }
}

public class RuntimeDispatchProxy : DispatchProxy
{
    public Func<MethodInfo, object?[]?, object?>? Handler { get; set; }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        if (targetMethod is null || Handler is null)
        {
            throw new InvalidOperationException("the runtime dispatch proxy is not configured");
        }

        return Handler(targetMethod, args);
    }
}
