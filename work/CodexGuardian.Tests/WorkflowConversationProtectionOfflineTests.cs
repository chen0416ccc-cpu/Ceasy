using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Collections.Concurrent;
using System.IO;

internal static class WorkflowConversationProtectionOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow protection enable is atomic idempotent and preserves global authority",
            TestAtomicIdempotentEnableAsync,
            assert);
        await RunCaseAsync(
            "workflow protection enable rejects stale settings generations without lost updates",
            TestConcurrentGenerationConflictAsync,
            assert);
        await RunCaseAsync(
            "stale full settings saves cannot roll back newer protection authority",
            TestStaleFullSaveCannotRollbackProtectionAsync,
            assert);
        await RunCaseAsync(
            "conversation protection defaults initialize missing entries once",
            TestInitializeDefaultsIsIdempotentAsync,
            assert);
        await RunCaseAsync(
            "conversation protection default initialization serializes by data root",
            TestInitializeDefaultsConcurrencyAsync,
            assert);
        await RunCaseAsync(
            "conversation protection default initialization rejects conservative settings",
            TestInitializeDefaultsRejectsConservativeSettingsAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery authorization is explicit atomic and migration-safe",
            TestAutomaticRecoveryAuthorizationAsync,
            assert);
    }

    private static async Task TestAtomicIdempotentEnableAsync()
    {
        var root = CreateRoot();
        var conversationId = Guid.NewGuid().ToString("D");
        var legacyConversationId = Guid.NewGuid().ToString("D");
        var service = new SettingsService(root);
        await service.SaveAsync(new AppSettings
        {
            RecentThreadLimit = 47,
            GlobalProtectionEnabled = true,
            ThreadEnabled = new ConcurrentDictionary<string, bool>(
                new[] { new KeyValuePair<string, bool>(legacyConversationId, false) },
                StringComparer.OrdinalIgnoreCase),
            ThreadProtectionEnabled = new ConcurrentDictionary<string, bool>(
                new[] { new KeyValuePair<string, bool>(conversationId, false) },
                StringComparer.OrdinalIgnoreCase)
        });
        var staleUiSettings = await service.LoadAsync();
        var before = await service.ReadConversationProtectionAsync(conversationId);
        var enabled = await service.EnableConversationProtectionAsync(
            conversationId,
            before.SettingsGeneration);
        var committed = await service.LoadAsync();
        Ensure(
            enabled.Status == ConversationProtectionEnableStatus.Confirmed &&
            enabled.Changed && enabled.SettingsGeneration == before.SettingsGeneration + 1 &&
            committed.ThreadProtectionEnabled.TryGetValue(conversationId, out var protectedValue) &&
            protectedValue && committed.GlobalProtectionEnabled &&
            committed.RecentThreadLimit == 47 &&
            committed.ThreadEnabled.TryGetValue(legacyConversationId, out var legacyValue) &&
            !legacyValue,
            "workflow protection enable changed unrelated policy or global authority");

        staleUiSettings.RecentThreadLimit = 51;
        await service.SaveAsync(staleUiSettings);
        var merged = await service.LoadAsync();
        Ensure(
            merged.RecentThreadLimit == 51 &&
            merged.ThreadProtectionEnabled.TryGetValue(conversationId, out var mergedProtection) &&
            mergedProtection && merged.GlobalProtectionEnabled,
            "a stale unrelated settings save rolled back the newer workflow protection authority");

        var bytesBeforeNoOp = File.ReadAllBytes(service.SettingsPath);
        var writeTimeBeforeNoOp = File.GetLastWriteTimeUtc(service.SettingsPath);
        var repeated = await service.EnableConversationProtectionAsync(
            conversationId,
            enabled.SettingsGeneration);
        Ensure(
            repeated.Status == ConversationProtectionEnableStatus.GenerationChanged &&
            !repeated.Changed && repeated.SettingsGeneration == merged.SettingsGeneration &&
            File.ReadAllBytes(service.SettingsPath).SequenceEqual(bytesBeforeNoOp) &&
            File.GetLastWriteTimeUtc(service.SettingsPath) == writeTimeBeforeNoOp,
            "a stale protection receipt bypassed generation checks or rewrote settings");

        var currentNoOp = await service.EnableConversationProtectionAsync(
            conversationId,
            merged.SettingsGeneration);
        Ensure(
            currentNoOp.Status == ConversationProtectionEnableStatus.Confirmed &&
            !currentNoOp.Changed && currentNoOp.SettingsGeneration == merged.SettingsGeneration,
            "an already-enabled current protection generation was not idempotent");

        var staleOff = staleUiSettings;
        staleOff.ThreadProtectionEnabled[conversationId] = false;
        staleOff.ThreadEnabled[conversationId] = false;
        await service.SaveAsync(staleOff);
        var preservedAfterStaleOff = await service.LoadAsync();
        Ensure(
            preservedAfterStaleOff.ThreadProtectionEnabled[conversationId] &&
            preservedAfterStaleOff.ThreadEnabled[conversationId],
            "a stale generic save was allowed to disable current protection without a user mutation");

        var userOff = await service.SetConversationProtectionFromUserAsync(
            conversationId,
            enabled: false);
        Ensure(
            !userOff.ThreadProtectionEnabled[conversationId] &&
            !userOff.ThreadEnabled[conversationId],
            "the explicit user protection-off mutation did not override current authority");

        var staleGlobalOn = await service.LoadAsync();
        var userGlobalOff = await service.SetGlobalProtectionFromUserAsync(false);
        staleGlobalOn.GlobalProtectionEnabled = true;
        await service.SaveAsync(staleGlobalOn);
        var preservedAfterStaleGlobal = await service.LoadAsync();
        Ensure(
            !userGlobalOff.GlobalProtectionEnabled &&
            !preservedAfterStaleGlobal.GlobalProtectionEnabled,
            "a stale generic save restored global protection after an explicit user-off mutation");
    }

    private static async Task TestConcurrentGenerationConflictAsync()
    {
        var root = CreateRoot();
        var firstConversationId = Guid.NewGuid().ToString("D");
        var secondConversationId = Guid.NewGuid().ToString("D");
        var firstService = new SettingsService(root);
        var secondService = new SettingsService(root);
        await firstService.SaveAsync(new AppSettings { RecentThreadLimit = 39 });
        var baseline = await firstService.LoadAsync();
        var attempts = await Task.WhenAll(
            firstService.EnableConversationProtectionAsync(
                firstConversationId,
                baseline.SettingsGeneration),
            secondService.EnableConversationProtectionAsync(
                secondConversationId,
                baseline.SettingsGeneration));
        Ensure(
            attempts.Count(result => result.Status == ConversationProtectionEnableStatus.Confirmed) == 1 &&
            attempts.Count(result => result.Status == ConversationProtectionEnableStatus.GenerationChanged) == 1,
            "concurrent workflow protection writes did not serialize on one settings generation");

        var afterFirstCommit = await firstService.LoadAsync();
        var missingConversationId = afterFirstCommit.ThreadProtectionEnabled.ContainsKey(firstConversationId)
            ? secondConversationId
            : firstConversationId;
        var retry = await secondService.EnableConversationProtectionAsync(
            missingConversationId,
            afterFirstCommit.SettingsGeneration);
        var final = await firstService.LoadAsync();
        Ensure(
            retry.Status == ConversationProtectionEnableStatus.Confirmed && retry.Changed &&
            final.ThreadProtectionEnabled.TryGetValue(firstConversationId, out var firstEnabled) &&
            firstEnabled &&
            final.ThreadProtectionEnabled.TryGetValue(secondConversationId, out var secondEnabled) &&
            secondEnabled &&
            !final.GlobalProtectionEnabled && final.RecentThreadLimit == 39,
            "generation retry lost a concurrent protection update or broadened authority");
    }

    private static async Task TestStaleFullSaveCannotRollbackProtectionAsync()
    {
        var root = CreateRoot();
        var conversationId = Guid.NewGuid().ToString("D");
        var service = new SettingsService(root);
        await service.SaveAsync(new AppSettings { RecentThreadLimit = 41 });

        var stale = await service.LoadAsync();
        await service.SetGlobalProtectionFromUserAsync(true);
        var currentProtection = await service.ReadConversationProtectionAsync(conversationId);
        var enabled = await service.EnableConversationProtectionAsync(
            conversationId,
            currentProtection.SettingsGeneration);
        Ensure(
            enabled.Status == ConversationProtectionEnableStatus.Confirmed && enabled.Changed,
            "the protection authority fixture did not commit a newer generation");

        // This object represents an old UI snapshot whose user edits explicitly turn both
        // protection values off. A full save has no reliable field-level intent, so it must
        // preserve the newer owner authority instead of reintroducing an older value.
        stale.GlobalProtectionEnabled = false;
        stale.ThreadProtectionEnabled[conversationId] = false;
        stale.ThreadEnabled[conversationId] = false;
        stale.RecentThreadLimit = 43;
        await service.SaveAsync(stale);

        var preserved = await service.LoadAsync();
        Ensure(
            preserved.GlobalProtectionEnabled &&
            preserved.ThreadProtectionEnabled.TryGetValue(conversationId, out var protectedValue) &&
            protectedValue &&
            preserved.ThreadEnabled.TryGetValue(conversationId, out var legacyValue) &&
            legacyValue &&
            preserved.RecentThreadLimit == 43,
            "a stale full settings save rolled back a newer protection authority");

        // Explicit user mutations use the field-level API and therefore remain authoritative.
        var disabledConversation = await service.SetConversationProtectionFromUserAsync(
            conversationId,
            enabled: false);
        var disabledGlobal = await service.SetGlobalProtectionFromUserAsync(enabled: false);
        var disabledConversationValue = disabledConversation.ThreadProtectionEnabled.TryGetValue(
            conversationId,
            out var disabledValue) && disabledValue;
        Ensure(
            !disabledConversationValue && !disabledGlobal.GlobalProtectionEnabled,
            "the explicit field-level protection disable was not persisted");
    }

    private static async Task TestInitializeDefaultsIsIdempotentAsync()
    {
        var root = CreateRoot();
        var existingConversationId = Guid.NewGuid().ToString("D");
        var partialNewMapId = Guid.NewGuid().ToString("D");
        var partialLegacyMapId = Guid.NewGuid().ToString("D");
        var newConversationId = Guid.NewGuid().ToString("D");
        var service = new SettingsService(root);
        await service.SaveAsync(new AppSettings
        {
            RecentThreadLimit = 37,
            ThreadProtectionEnabled = new ConcurrentDictionary<string, bool>(
                new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
                {
                    [existingConversationId] = true,
                    [partialNewMapId] = false
                },
                StringComparer.OrdinalIgnoreCase),
            ThreadEnabled = new ConcurrentDictionary<string, bool>(
                new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
                {
                    [existingConversationId] = false,
                    [partialLegacyMapId] = true
                },
                StringComparer.OrdinalIgnoreCase)
        });
        var baseline = await service.LoadAsync();

        var initialized = await service.InitializeConversationProtectionDefaultsAsync(
            [existingConversationId, partialNewMapId, partialLegacyMapId, newConversationId],
            defaultEnabled: true);
        Ensure(
            initialized.ReadStatus == SettingsReadStatus.Healthy &&
            initialized.SettingsGeneration == baseline.SettingsGeneration + 1 &&
            initialized.RecentThreadLimit == 37 &&
            initialized.ThreadProtectionEnabled[existingConversationId] &&
            !initialized.ThreadEnabled[existingConversationId] &&
            !initialized.ThreadProtectionEnabled[partialNewMapId] &&
            !initialized.ThreadEnabled[partialNewMapId] &&
            initialized.ThreadProtectionEnabled[partialLegacyMapId] &&
            initialized.ThreadEnabled[partialLegacyMapId] &&
            initialized.ThreadProtectionEnabled[newConversationId] &&
            initialized.ThreadEnabled[newConversationId],
            "default initialization overwrote an existing value or missed an absent map entry");

        var bytesBeforeNoOp = File.ReadAllBytes(service.SettingsPath);
        var writeTimeBeforeNoOp = File.GetLastWriteTimeUtc(service.SettingsPath);
        var repeated = await service.InitializeConversationProtectionDefaultsAsync(
            [newConversationId, partialLegacyMapId, partialNewMapId, existingConversationId],
            defaultEnabled: true);
        var changedDefault = await service.InitializeConversationProtectionDefaultsAsync(
            [existingConversationId, partialNewMapId, partialLegacyMapId, newConversationId],
            defaultEnabled: false);
        Ensure(
            repeated.SettingsGeneration == initialized.SettingsGeneration &&
            changedDefault.SettingsGeneration == initialized.SettingsGeneration &&
            File.ReadAllBytes(service.SettingsPath).SequenceEqual(bytesBeforeNoOp) &&
            File.GetLastWriteTimeUtc(service.SettingsPath) == writeTimeBeforeNoOp &&
            changedDefault.ThreadProtectionEnabled[existingConversationId] &&
            !changedDefault.ThreadEnabled[existingConversationId] &&
            !changedDefault.ThreadProtectionEnabled[partialNewMapId] &&
            !changedDefault.ThreadEnabled[partialNewMapId] &&
            changedDefault.ThreadProtectionEnabled[partialLegacyMapId] &&
            changedDefault.ThreadEnabled[partialLegacyMapId] &&
            changedDefault.ThreadProtectionEnabled[newConversationId] &&
            changedDefault.ThreadEnabled[newConversationId],
            "an idempotent call rewrote settings or a changed default altered initialized values");
    }

    private static async Task TestInitializeDefaultsConcurrencyAsync()
    {
        var root = CreateRoot();
        var sharedConversationId = Guid.NewGuid().ToString("D");
        var enabledConversationId = Guid.NewGuid().ToString("D");
        var disabledConversationId = Guid.NewGuid().ToString("D");
        var firstService = new SettingsService(root);
        var secondService = new SettingsService(root);
        await firstService.SaveAsync(new AppSettings { RecentThreadLimit = 53 });
        var baseline = await firstService.LoadAsync();

        var committed = await Task.WhenAll(
            firstService.InitializeConversationProtectionDefaultsAsync(
                [sharedConversationId, enabledConversationId],
                defaultEnabled: true),
            secondService.InitializeConversationProtectionDefaultsAsync(
                [sharedConversationId, disabledConversationId],
                defaultEnabled: false));
        var final = await firstService.LoadAsync();
        var sharedProtection = final.ThreadProtectionEnabled[sharedConversationId];
        Ensure(
            final.SettingsGeneration == baseline.SettingsGeneration + 2 &&
            committed.Select(settings => settings.SettingsGeneration).Distinct().Count() == 2 &&
            committed.All(settings => settings.ReadStatus == SettingsReadStatus.Healthy) &&
            final.RecentThreadLimit == 53 &&
            final.ThreadProtectionEnabled[enabledConversationId] &&
            final.ThreadEnabled[enabledConversationId] &&
            !final.ThreadProtectionEnabled[disabledConversationId] &&
            !final.ThreadEnabled[disabledConversationId] &&
            final.ThreadEnabled[sharedConversationId] == sharedProtection,
            "concurrent default initialization lost a map update or overwrote the first shared value");
    }

    private static async Task TestInitializeDefaultsRejectsConservativeSettingsAsync()
    {
        var root = CreateRoot();
        var service = new SettingsService(root);
        Directory.CreateDirectory(root);
        await File.WriteAllTextAsync(service.SettingsPath, "{ invalid settings");
        var bytesBefore = File.ReadAllBytes(service.SettingsPath);
        var rejected = false;
        try
        {
            await service.InitializeConversationProtectionDefaultsAsync(
                [Guid.NewGuid().ToString("D")],
                defaultEnabled: true);
        }
        catch (InvalidDataException)
        {
            rejected = true;
        }

        var conservative = await service.LoadAsync();
        Ensure(
            rejected &&
            conservative.ReadStatus == SettingsReadStatus.ConservativeDefaults &&
            File.ReadAllBytes(service.SettingsPath).SequenceEqual(bytesBefore) &&
            !File.Exists(Path.Combine(root, "settings.previous.json")) &&
            !File.Exists(Path.Combine(root, "settings.initialized")),
            "conservative settings were initialized or mutated instead of failing closed");
    }

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "wp-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private static void DeleteRoot(string root)
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
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

    private static async Task TestAutomaticRecoveryAuthorizationAsync()
    {
        var root = CreateRoot();
        try
        {
            var service = new SettingsService(root);
            await service.SaveAsync(new AppSettings
            {
                GlobalProtectionEnabled = true,
                MonitorOnly = true
            });

            var initial = await service.LoadAsync();
            Ensure(
                !initial.AutomaticRecoveryEnabled &&
                initial.GlobalProtectionEnabled &&
                initial.MonitorOnly,
                "fresh settings did not keep automatic recovery explicitly disabled");

            var enabled = await service.SetAutomaticRecoveryFromUserAsync(true);
            Ensure(
                enabled.AutomaticRecoveryEnabled &&
                enabled.GlobalProtectionEnabled &&
                !enabled.MonitorOnly &&
                enabled.SettingsGeneration == initial.SettingsGeneration + 1,
                "the explicit automatic-recovery mutation changed the wrong authority or generation");

            var stale = await service.LoadAsync();
            var disabled = await service.SetAutomaticRecoveryFromUserAsync(false);
            stale.RecentThreadLimit = 61;
            await service.SaveAsync(stale);
            var merged = await service.LoadAsync();
            Ensure(
                !disabled.AutomaticRecoveryEnabled &&
                !merged.AutomaticRecoveryEnabled &&
                merged.GlobalProtectionEnabled &&
                merged.RecentThreadLimit == 61,
                "a stale unrelated save rolled back the explicit recovery authorization");

            var bytesBeforeNoOp = File.ReadAllBytes(service.SettingsPath);
            var generationBeforeNoOp = merged.SettingsGeneration;
            var repeated = await service.SetAutomaticRecoveryFromUserAsync(false);
            Ensure(
                !repeated.AutomaticRecoveryEnabled &&
                repeated.SettingsGeneration == generationBeforeNoOp &&
                File.ReadAllBytes(service.SettingsPath).SequenceEqual(bytesBeforeNoOp),
                "an idempotent recovery authorization mutation rewrote settings");

            var legacyRoot = CreateRoot();
            try
            {
                var legacyService = new SettingsService(legacyRoot);
                Directory.CreateDirectory(legacyRoot);
                await File.WriteAllTextAsync(
                    legacyService.SettingsPath,
                    "{\"ConfigurationVersion\":7,\"MonitorOnly\":false,\"AutomaticRecoveryEnabled\":true,\"GlobalProtectionEnabled\":true}");
                var migrated = await legacyService.LoadAsync();
                Ensure(
                    migrated.ConfigurationVersion == AppSettings.CurrentConfigurationVersion &&
                    !migrated.AutomaticRecoveryEnabled &&
                    migrated.MonitorOnly &&
                    migrated.GlobalProtectionEnabled,
                    "a v7 migration inferred recovery or discarded independent global protection");
            }
            finally
            {
                DeleteRoot(legacyRoot);
            }

            var missingFieldRoot = CreateRoot();
            try
            {
                var currentService = new SettingsService(missingFieldRoot);
                Directory.CreateDirectory(missingFieldRoot);
                await File.WriteAllTextAsync(
                    currentService.SettingsPath,
                    "{\"ConfigurationVersion\":8,\"MonitorOnly\":false,\"GlobalProtectionEnabled\":true}");
                var missingField = await currentService.LoadAsync();
                Ensure(
                    missingField.ConfigurationVersion == AppSettings.CurrentConfigurationVersion &&
                    !missingField.AutomaticRecoveryEnabled &&
                    missingField.MonitorOnly &&
                    !missingField.GlobalProtectionEnabled &&
                    !missingField.ProtectNewThreadsByDefault &&
                    missingField.ThreadProtectionEnabled.Count == 0,
                    "the v8 settings migration retained automatic or conversation protection authority");
            }
            finally
            {
                DeleteRoot(missingFieldRoot);
            }
        }
        finally
        {
            DeleteRoot(root);
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
