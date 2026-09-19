using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodexGuardian.Localization;
using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal sealed record AttachmentSettingsReferenceSnapshot(
    bool IsHealthy,
    long SettingsGeneration,
    long PreviousSettingsGeneration,
    IReadOnlyList<string> CurrentContentIds,
    IReadOnlyList<string> PreviousContentIds);

internal sealed record ConversationProtectionSnapshot(
    bool IsAvailable,
    bool IsEnabled,
    long SettingsGeneration,
    SettingsReadStatus ReadStatus);

internal enum ConversationProtectionEnableStatus
{
    Confirmed,
    GenerationChanged,
    Unavailable
}

internal sealed record ConversationProtectionEnableResult(
    ConversationProtectionEnableStatus Status,
    bool Changed,
    long SettingsGeneration,
    SettingsReadStatus ReadStatus);

internal interface ISettingsWriteAuthority
{
    void Publish(Action atomicPublication);
}

internal sealed class ImmediateSettingsWriteAuthority : ISettingsWriteAuthority
{
    internal static ImmediateSettingsWriteAuthority Instance { get; } = new();

    private ImmediateSettingsWriteAuthority()
    {
    }

    void ISettingsWriteAuthority.Publish(Action atomicPublication)
    {
        ArgumentNullException.ThrowIfNull(atomicPublication);
        atomicPublication();
    }
}

internal static class SettingsMutationLeaseRegistry
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> RootGates =
        new(StringComparer.OrdinalIgnoreCase);

    internal static SemaphoreSlim Get(string dataDirectory)
    {
        var normalized = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        var key = Path.TrimEndingDirectorySeparator(normalized);
        return RootGates.GetOrAdd(key, static _ => new SemaphoreSlim(1, 1));
    }
}

public sealed class SettingsService
{
    internal const string DefaultContinueMessage = "continue";
    internal const int MaximumContinueMessageLength = 1000;
    internal const int MaximumFollowUpMessageLength = 4000;
    internal const int MaximumFollowUpMessagesPerThread = 64;
    internal const int MaximumFollowUpThreadCount = 500;
    internal const int MaximumTotalFollowUpMessages = 2048;
    internal const int MaximumConversationOrderCount = 500;
    internal const int MaximumConversationIdLength = 128;
    internal const string TemporaryCleanupFailureDataKey =
        "SettingsTemporaryCleanupFailure";
    private const int CurrentEnvelopeSchemaVersion = 1;
    private const int CurrentMarkerSchemaVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true
        };
        options.Converters.Add(new OrderedThreadFollowUpsConverter());
        return options;
    }

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _settingsMutationGate;
    private readonly SemaphoreSlim _attachmentMutationGate;
    private readonly bool _monitoringEnabledAfterNormalization;

    public SettingsService(
        string? dataDirectory = null,
        bool monitoringEnabledAfterNormalization = true)
    {
        var resolvedDataDirectory = string.IsNullOrWhiteSpace(dataDirectory)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CodexGuardian")
            : dataDirectory;
        DataDirectory = DataDirectorySafety.NormalizeAndValidate(resolvedDataDirectory);
        SettingsPath = Path.Combine(DataDirectory, "settings.json");
        PreviousSettingsPath = Path.Combine(DataDirectory, "settings.previous.json");
        InitializationMarkerPath = Path.Combine(DataDirectory, "settings.initialized");
        _settingsMutationGate = SettingsMutationLeaseRegistry.Get(DataDirectory);
        _attachmentMutationGate = AttachmentMutationLeaseRegistry.Get(DataDirectory);
        _monitoringEnabledAfterNormalization = monitoringEnabledAfterNormalization;
    }

    public string DataDirectory { get; }

    public string SettingsPath { get; }

    private string PreviousSettingsPath { get; }

    private string InitializationMarkerPath { get; }

    public async Task<AppSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DataDirectorySafety.Revalidate(DataDirectory);
        var persistedState = await ReadPersistedStateAsync(cancellationToken).ConfigureAwait(false);
        return persistedState.Settings;
    }

    internal async Task<AttachmentSettingsReferenceSnapshot>
        ReadAttachmentReferenceSnapshotUnderMutationLeaseAsync(
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var persistedState = await ReadPersistedStateAsync(cancellationToken)
                .ConfigureAwait(false);
            return CreateAttachmentReferenceSnapshot(persistedState);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task SaveAsync(
        AppSettings settings,
        CancellationToken cancellationToken = default) =>
        SaveAsync(
            settings,
            cancellationToken,
            ImmediateSettingsWriteAuthority.Instance);

    internal async Task SaveAsync(
        AppSettings settings,
        CancellationToken cancellationToken,
        ISettingsWriteAuthority writeAuthority)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(writeAuthority);
        cancellationToken.ThrowIfCancellationRequested();
        if (settings.ReadStatus == SettingsReadStatus.ConservativeDefaults)
        {
            throw new InvalidDataException(
                "Conservative settings cannot be overwritten without an explicit reset.");
        }

        var expectedSettingsGeneration = settings.SettingsGeneration;
        var normalizedSettings = Normalize(settings);
        await _settingsMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Workflow protection can be committed by the owner path while the long-lived UI
            // still holds an older settings object. A stale full-object save has no field-level
            // intent information, so it must never mutate the newer protection authority. User
            // changes use the dedicated atomic mutation methods below.
            var current = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (expectedSettingsGeneration > 0 &&
                current.ReadStatus == SettingsReadStatus.Healthy &&
                current.SettingsGeneration > expectedSettingsGeneration)
            {
                normalizedSettings.AutomaticRecoveryEnabled = current.AutomaticRecoveryEnabled;
                normalizedSettings.MonitorOnly = !current.AutomaticRecoveryEnabled;
                normalizedSettings.GlobalProtectionEnabled = current.GlobalProtectionEnabled;
                normalizedSettings.ThreadEnabled = CloneProtectionMap(
                    current.ThreadEnabled);
                normalizedSettings.ThreadProtectionEnabled = CloneProtectionMap(
                    current.ThreadProtectionEnabled);
            }

            await SaveNormalizedSettingsAsync(
                    normalizedSettings,
                    cancellationToken,
                    writeAuthority)
                .ConfigureAwait(false);
        }
        finally
        {
            _settingsMutationGate.Release();
        }
    }

    private async Task SaveNormalizedSettingsAsync(
        AppSettings normalizedSettings,
        CancellationToken cancellationToken,
        ISettingsWriteAuthority writeAuthority)
    {
        await _attachmentMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            string? temporaryPath = null;
            string? previousTemporaryPath = null;
            string? markerTemporaryPath = null;
            Exception? primaryFailure = null;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                DataDirectorySafety.Revalidate(DataDirectory);
                var persistedState = await ReadPersistedStateAsync(cancellationToken).ConfigureAwait(false);
                var rotateCommittedPrimary = persistedState.PrimaryMatchesMarker;
                var recoveredPrevious = persistedState.ReadStatus == SettingsReadStatus.RecoveredFromPrevious
                    ? persistedState.Previous
                    : null;
                var trustedEnvelope = rotateCommittedPrimary
                    ? persistedState.Primary
                    : recoveredPrevious;
                var nextGeneration = trustedEnvelope is null
                    ? 1
                    : checked(trustedEnvelope.Generation + 1);
                var preparedEnvelope = CreateEnvelope(normalizedSettings, nextGeneration);
                var seedPrevious = trustedEnvelope is null;
                var previousGeneration = seedPrevious
                    ? preparedEnvelope.Generation
                    : trustedEnvelope!.Generation;
                var previousChecksum = seedPrevious
                    ? preparedEnvelope.Checksum
                    : trustedEnvelope!.Checksum;
                var preparedMarker = CreateMarker(
                    preparedEnvelope.Generation,
                    preparedEnvelope.Checksum,
                    previousGeneration,
                    previousChecksum);

            Directory.CreateDirectory(DataDirectory);
            DataDirectorySafety.Revalidate(DataDirectory);

            var preparedTemporaryPath = Path.Combine(
                DataDirectory,
                $".{Path.GetFileName(SettingsPath)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
            temporaryPath = preparedTemporaryPath;
            cancellationToken.ThrowIfCancellationRequested();
            DataDirectorySafety.Revalidate(DataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, preparedTemporaryPath);
            await using (var temporaryStream = new FileStream(
                             preparedTemporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             bufferSize: 4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await temporaryStream.WriteAsync(preparedEnvelope.Bytes, cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                temporaryStream.Flush(flushToDisk: true);
            }

            await ValidatePreparedEnvelopeAsync(
                    preparedTemporaryPath,
                    preparedEnvelope.Generation,
                    preparedEnvelope.Checksum,
                    cancellationToken)
                .ConfigureAwait(false);

            if (seedPrevious)
            {
                previousTemporaryPath = CreateTemporaryPath(PreviousSettingsPath);
                await WriteTemporaryFileAsync(
                        previousTemporaryPath,
                        preparedEnvelope.Bytes,
                        cancellationToken)
                    .ConfigureAwait(false);
                await ValidatePreparedEnvelopeAsync(
                        previousTemporaryPath,
                        preparedEnvelope.Generation,
                        preparedEnvelope.Checksum,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            markerTemporaryPath = CreateTemporaryPath(InitializationMarkerPath);
            await WriteTemporaryFileAsync(
                    markerTemporaryPath,
                    preparedMarker.Bytes,
                    cancellationToken)
                .ConfigureAwait(false);
            await ValidatePreparedMarkerAsync(
                    markerTemporaryPath,
                    preparedMarker.Document,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();
            writeAuthority.Publish(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                DataDirectorySafety.Revalidate(DataDirectory);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, preparedTemporaryPath);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, SettingsPath);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, PreviousSettingsPath);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, markerTemporaryPath!);
                DataDirectorySafety.RevalidateWriteTarget(DataDirectory, InitializationMarkerPath);
                if (rotateCommittedPrimary)
                {
                    File.Replace(
                        preparedTemporaryPath,
                        SettingsPath,
                        PreviousSettingsPath,
                        ignoreMetadataErrors: true);
                }
                else if (File.Exists(SettingsPath))
                {
                    File.Replace(
                        preparedTemporaryPath,
                        SettingsPath,
                        destinationBackupFileName: null,
                        ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(preparedTemporaryPath, SettingsPath);
                }

                if (seedPrevious)
                {
                    DataDirectorySafety.RevalidateWriteTarget(DataDirectory, previousTemporaryPath!);
                    if (File.Exists(PreviousSettingsPath))
                    {
                        File.Replace(
                            previousTemporaryPath!,
                            PreviousSettingsPath,
                            destinationBackupFileName: null,
                            ignoreMetadataErrors: true);
                    }
                    else
                    {
                        File.Move(previousTemporaryPath!, PreviousSettingsPath);
                    }
                }

                if (File.Exists(InitializationMarkerPath))
                {
                    File.Replace(
                        markerTemporaryPath!,
                        InitializationMarkerPath,
                        destinationBackupFileName: null,
                        ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(markerTemporaryPath!, InitializationMarkerPath);
                }
            });
        }
            catch (Exception exception)
            {
                primaryFailure = exception;
                throw;
            }
            finally
            {
                try
                {
                    Exception? cleanupFailure = null;
                    try
                    {
                        if (temporaryPath is not null)
                        {
                            DataDirectorySafety.Revalidate(DataDirectory);
                            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
                            File.Delete(temporaryPath);
                        }
                    }
                    catch (Exception exception)
                    {
                        cleanupFailure = exception;
                    }

                    cleanupFailure = CaptureTemporaryCleanupFailure(
                        cleanupFailure,
                        DataDirectory,
                        previousTemporaryPath);
                    cleanupFailure = CaptureTemporaryCleanupFailure(
                        cleanupFailure,
                        DataDirectory,
                        markerTemporaryPath);
                    if (cleanupFailure is not null)
                    {
                        if (primaryFailure is null)
                        {
                            throw cleanupFailure;
                        }

                        primaryFailure.Data[TemporaryCleanupFailureDataKey] =
                            primaryFailure.Data[TemporaryCleanupFailureDataKey] is Exception existing
                                ? new AggregateException(existing, cleanupFailure)
                                : cleanupFailure;
                    }
                }
                finally
                {
                    _gate.Release();
                }
            }
        }
        finally
        {
            _attachmentMutationGate.Release();
        }
    }

    internal async Task<ConversationProtectionSnapshot> ReadConversationProtectionAsync(
        string conversationId,
        CancellationToken cancellationToken = default)
    {
        conversationId = NormalizeConversationId(conversationId);
        var settings = await LoadAsync(cancellationToken).ConfigureAwait(false);
        return CreateConversationProtectionSnapshot(settings, conversationId);
    }

    internal async Task<ConversationProtectionEnableResult> EnableConversationProtectionAsync(
        string conversationId,
        long expectedSettingsGeneration,
        CancellationToken cancellationToken = default)
    {
        conversationId = NormalizeConversationId(conversationId);
        if (expectedSettingsGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedSettingsGeneration));
        }

        await _settingsMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var before = CreateConversationProtectionSnapshot(settings, conversationId);
            if (!before.IsAvailable)
            {
                return new ConversationProtectionEnableResult(
                    ConversationProtectionEnableStatus.Unavailable,
                    Changed: false,
                    before.SettingsGeneration,
                    before.ReadStatus);
            }

            if (before.SettingsGeneration != expectedSettingsGeneration)
            {
                return new ConversationProtectionEnableResult(
                    ConversationProtectionEnableStatus.GenerationChanged,
                    Changed: false,
                    before.SettingsGeneration,
                    before.ReadStatus);
            }

            if (before.IsEnabled && before.SettingsGeneration > 0)
            {
                return new ConversationProtectionEnableResult(
                    ConversationProtectionEnableStatus.Confirmed,
                    Changed: false,
                    before.SettingsGeneration,
                    before.ReadStatus);
            }

            settings.ThreadProtectionEnabled[conversationId] = true;
            settings.ThreadEnabled[conversationId] = true;
            var normalizedSettings = Normalize(settings);
            await SaveNormalizedSettingsAsync(
                    normalizedSettings,
                    cancellationToken,
                    ImmediateSettingsWriteAuthority.Instance)
                .ConfigureAwait(false);
            var committed = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var after = CreateConversationProtectionSnapshot(committed, conversationId);
            if (!after.IsAvailable || !after.IsEnabled || after.SettingsGeneration <= 0 ||
                after.SettingsGeneration <= before.SettingsGeneration)
            {
                throw new InvalidDataException(
                    "Conversation protection did not commit an authoritative settings generation.");
            }

            return new ConversationProtectionEnableResult(
                ConversationProtectionEnableStatus.Confirmed,
                Changed: !before.IsEnabled,
                after.SettingsGeneration,
                after.ReadStatus);
        }
        finally
        {
            _settingsMutationGate.Release();
        }
    }

    internal async Task<AppSettings> SetConversationProtectionFromUserAsync(
        string conversationId,
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        conversationId = NormalizeConversationId(conversationId);
        await _settingsMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (settings.ReadStatus == SettingsReadStatus.ConservativeDefaults)
            {
                throw new InvalidDataException(
                    "Conversation protection cannot be changed while settings are conservative.");
            }

            var alreadyApplied =
                settings.ThreadProtectionEnabled.TryGetValue(conversationId, out var protectedValue) &&
                protectedValue == enabled &&
                settings.ThreadEnabled.TryGetValue(conversationId, out var legacyValue) &&
                legacyValue == enabled;
            if (!alreadyApplied || settings.SettingsGeneration <= 0)
            {
                settings.ThreadProtectionEnabled[conversationId] = enabled;
                settings.ThreadEnabled[conversationId] = enabled;
                await SaveNormalizedSettingsAsync(
                        Normalize(settings),
                        cancellationToken,
                        ImmediateSettingsWriteAuthority.Instance)
                    .ConfigureAwait(false);
            }

            return await LoadAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _settingsMutationGate.Release();
        }
    }

    internal async Task<AppSettings> InitializeConversationProtectionDefaultsAsync(
        IEnumerable<string> conversationIds,
        bool defaultEnabled,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversationIds);
        var normalizedConversationIds = conversationIds
            .Select(NormalizeConversationId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static conversationId => conversationId, StringComparer.Ordinal)
            .ToArray();

        await _settingsMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (settings.ReadStatus == SettingsReadStatus.ConservativeDefaults)
            {
                throw new InvalidDataException(
                    "Conversation protection defaults cannot be initialized while settings are conservative.");
            }

            var changed = false;
            foreach (var conversationId in normalizedConversationIds)
            {
                var hasProtectionValue = settings.ThreadProtectionEnabled.TryGetValue(
                    conversationId,
                    out var protectionValue);
                var hasLegacyValue = settings.ThreadEnabled.TryGetValue(
                    conversationId,
                    out var legacyValue);
                if (!hasProtectionValue && !hasLegacyValue)
                {
                    changed |= settings.ThreadProtectionEnabled.TryAdd(
                        conversationId,
                        defaultEnabled);
                    changed |= settings.ThreadEnabled.TryAdd(
                        conversationId,
                        defaultEnabled);
                }
                else if (!hasProtectionValue)
                {
                    changed |= settings.ThreadProtectionEnabled.TryAdd(
                        conversationId,
                        legacyValue);
                }
                else if (!hasLegacyValue)
                {
                    changed |= settings.ThreadEnabled.TryAdd(
                        conversationId,
                        protectionValue);
                }
            }

            if (!changed)
            {
                return settings;
            }

            await SaveNormalizedSettingsAsync(
                    Normalize(settings),
                    cancellationToken,
                    ImmediateSettingsWriteAuthority.Instance)
                .ConfigureAwait(false);
            return await LoadAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _settingsMutationGate.Release();
        }
    }

    internal async Task<AppSettings> SetGlobalProtectionFromUserAsync(
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        await _settingsMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (settings.ReadStatus == SettingsReadStatus.ConservativeDefaults)
            {
                throw new InvalidDataException(
                    "Global protection cannot be changed while settings are conservative.");
            }

            if (settings.GlobalProtectionEnabled != enabled || settings.SettingsGeneration <= 0)
            {
                settings.GlobalProtectionEnabled = enabled;
                await SaveNormalizedSettingsAsync(
                        Normalize(settings),
                        cancellationToken,
                        ImmediateSettingsWriteAuthority.Instance)
                    .ConfigureAwait(false);
            }

            return await LoadAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _settingsMutationGate.Release();
        }
    }

    internal async Task<AppSettings> SetAutomaticRecoveryFromUserAsync(
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        await _settingsMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (settings.ReadStatus == SettingsReadStatus.ConservativeDefaults)
            {
                throw new InvalidDataException(
                    "Automatic recovery cannot be changed while settings are conservative.");
            }

            var expectedMonitorOnly = !enabled;
            var expectedGlobalProtection = enabled || settings.GlobalProtectionEnabled;
            if (settings.AutomaticRecoveryEnabled != enabled ||
                settings.MonitorOnly != expectedMonitorOnly ||
                settings.GlobalProtectionEnabled != expectedGlobalProtection ||
                settings.SettingsGeneration <= 0)
            {
                settings.AutomaticRecoveryEnabled = enabled;
                settings.MonitorOnly = expectedMonitorOnly;
                settings.GlobalProtectionEnabled = expectedGlobalProtection;
                await SaveNormalizedSettingsAsync(
                        Normalize(settings),
                        cancellationToken,
                        ImmediateSettingsWriteAuthority.Instance)
                    .ConfigureAwait(false);
            }

            return await LoadAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _settingsMutationGate.Release();
        }
    }

    private static ConversationProtectionSnapshot CreateConversationProtectionSnapshot(
        AppSettings settings,
        string conversationId) =>
        new(
            settings.ReadStatus != SettingsReadStatus.ConservativeDefaults,
            settings.ThreadProtectionEnabled.TryGetValue(conversationId, out var enabled) && enabled,
            settings.SettingsGeneration,
            settings.ReadStatus);

    private static string NormalizeConversationId(string? conversationId)
    {
        if (!Guid.TryParse(conversationId, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException(
                "A non-empty conversation UUID is required.",
                nameof(conversationId));
        }

        return parsed.ToString("D");
    }

    private AppSettings Normalize(AppSettings settings, bool? migrateLegacyOverride = null)
    {
        if (settings.ConfigurationVersion > AppSettings.CurrentConfigurationVersion)
        {
            throw new NotSupportedException(
                $"Configuration version {settings.ConfigurationVersion} is newer than the supported version.");
        }

        var migrateLegacy = migrateLegacyOverride ??
                            settings.ConfigurationVersion < AppSettings.CurrentConfigurationVersion;
        var preserveVersionSevenProtection =
            migrateLegacy && settings.ConfigurationVersion == 7;
        var automaticRecoveryEnabled = !migrateLegacy && settings.AutomaticRecoveryEnabled;
        var baseBackoffSeconds = Math.Clamp(settings.BaseBackoffSeconds, 5, 600);
        var maximumBackoffSeconds = Math.Clamp(
            settings.MaximumBackoffSeconds,
            baseBackoffSeconds,
            3600);
        var normalizedThreadEnabled = migrateLegacy
            ? new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
            : NormalizeProtectionMap(settings.ThreadEnabled);
        var normalizedThreadProtection = migrateLegacy
            ? new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
            : NormalizeProtectionMap(settings.ThreadProtectionEnabled);
        var normalizedAttachmentLimits = NormalizeAttachmentLimits(settings.AttachmentLimits);
        var configuredMaximumRecoveryAttempts = migrateLegacy
            ? settings.MaximumAttemptsPerFailure == 5
                // Five was the old implementation default, not an approved user policy.
                ? 500
                : settings.MaximumAttemptsPerFailure
            : settings.MaximumRecoveryAttempts > 0
                ? settings.MaximumRecoveryAttempts
                : settings.MaximumAttemptsPerFailure;
        var maximumRecoveryAttempts = Math.Clamp(
            configuredMaximumRecoveryAttempts,
            1,
            1_000_000);
        var recoveryCountingMode = Enum.IsDefined(settings.RecoveryCountingMode)
            ? settings.RecoveryCountingMode
            : RecoveryCountingMode.PerFailedTurn;

        return new AppSettings
        {
            ConfigurationVersion = AppSettings.CurrentConfigurationVersion,
            UiLanguage = UiLanguages.Normalize(settings.UiLanguage),
            UiTheme = UiThemes.Normalize(settings.UiTheme),
            MonitoringEnabled = _monitoringEnabledAfterNormalization,
            MonitorOnly = !automaticRecoveryEnabled,
            AutomaticRecoveryEnabled = automaticRecoveryEnabled,
            GlobalProtectionEnabled =
                (!migrateLegacy || preserveVersionSevenProtection) &&
                settings.GlobalProtectionEnabled,
            AttachmentLimits = normalizedAttachmentLimits,
            BaseBackoffSeconds = baseBackoffSeconds,
            MaximumBackoffSeconds = maximumBackoffSeconds,
            MaximumAttemptsPerFailure = maximumRecoveryAttempts,
            MaximumRecoveryAttempts = maximumRecoveryAttempts,
            UnlimitedRecoveryAttempts = !migrateLegacy && settings.UnlimitedRecoveryAttempts,
            RecoveryCountingMode = recoveryCountingMode,
            ContinueMessage = NormalizeContinueMessage(settings.ContinueMessage),
            RecentThreadLimit = Math.Clamp(settings.RecentThreadLimit, 5, 100),
            RecentThreadLookbackDays = Math.Clamp(settings.RecentThreadLookbackDays, 1, 365),
            IncludeSubAgents = settings.IncludeSubAgents,
            ProtectNewThreadsByDefault = false,
            MinimizeToTray = settings.MinimizeToTray,
            StartWithWindows = settings.StartWithWindows,
            ThreadEnabled = normalizedThreadEnabled,
            ThreadProtectionEnabled = normalizedThreadProtection,
            ConversationOrder = migrateLegacy
                ? []
                : NormalizeConversationOrder(settings.ConversationOrder),
            UseManualConversationOrder = !migrateLegacy && settings.UseManualConversationOrder,
            PinnedConversationIds = !migrateLegacy
                ? NormalizeConversationOrder(settings.PinnedConversationIds)
                : [],
            ThreadFollowUps = NormalizeThreadFollowUps(
                settings.ThreadFollowUps,
                normalizedAttachmentLimits),
            // Normalization rebuilds the settings field by field, so anything omitted here is silently
            // reset to its default on every save. Leaving keep-alive out meant none of it persisted:
            // the page appeared to accept a per-conversation choice and the flag was gone by the next
            // write.
            KeepAliveEnabled = settings.KeepAliveEnabled,
            KeepAliveSentinelEnabled = settings.KeepAliveSentinelEnabled,
            KeepAliveSentinelThreadId = string.IsNullOrWhiteSpace(settings.KeepAliveSentinelThreadId)
                ? string.Empty
                : settings.KeepAliveSentinelThreadId.Trim(),
            KeepAliveIntervalMinutes = Math.Clamp(
                settings.KeepAliveIntervalMinutes,
                AppSettings.MinimumKeepAliveIntervalMinutes,
                AppSettings.MaximumKeepAliveIntervalMinutes),
            KeepAliveMessage = NormalizeKeepAliveMessage(settings.KeepAliveMessage),
            KeepAliveThreadEnabled = NormalizeProtectionMap(settings.KeepAliveThreadEnabled)
        };
    }

    /// <summary>
    /// Trims the configured wording set, retiring any shipped default that would trigger detection.
    /// </summary>
    /// <remarks>
    /// Only the trailing and leading whitespace goes: the field is one phrasing per line, so the newlines
    /// in the middle are the structure and stripping them would collapse the set to a single phrasing.
    ///
    /// Empty is the default (means "generate arithmetic questions"). A user who clears the field is asking
    /// for the default, and the default is now the generator, so empty is returned as-is rather than being
    /// treated as a migration case.
    /// </remarks>
    internal static string NormalizeKeepAliveMessage(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return AppSettings.DefaultKeepAliveMessage;
        }

        var trimmed = configured.Trim();
        return string.Equals(trimmed, AppSettings.RetiredKeepAliveMessage, StringComparison.Ordinal) ||
               string.Equals(trimmed, AppSettings.RetiredAcknowledgementMessage, StringComparison.Ordinal) ||
               string.Equals(trimmed, AppSettings.RetiredPauseMessage, StringComparison.Ordinal)
            ? AppSettings.DefaultKeepAliveMessage
            : trimmed;
    }

    private async Task<SettingsPersistenceSnapshot> ReadPersistedStateAsync(
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        if (!Directory.Exists(DataDirectory))
        {
            return MissingSnapshot();
        }

        var primaryExists = PathExists(SettingsPath);
        var previousExists = PathExists(PreviousSettingsPath);
        var markerExists = PathExists(InitializationMarkerPath);
        var markerRead = await TryReadMarkerAsync(InitializationMarkerPath, cancellationToken)
            .ConfigureAwait(false);
        if (markerRead.Status == PersistedReadStatus.Missing)
        {
            if (!primaryExists && !previousExists && !markerExists)
            {
                return MissingSnapshot();
            }

            if (primaryExists && !previousExists && !markerExists)
            {
                var legacy = await TryReadLegacySettingsAsync(cancellationToken).ConfigureAwait(false);
                if (legacy is not null)
                {
                    return new SettingsPersistenceSnapshot(
                        SettingsReadStatus.Legacy,
                        ProjectReadMetadata(legacy, SettingsReadStatus.Legacy, 0, 0),
                        null,
                        null,
                        PrimaryMatchesMarker: false);
                }
            }

            return ConservativeSnapshot();
        }

        if (markerRead.Status != PersistedReadStatus.Healthy)
        {
            return ConservativeSnapshot();
        }

        var marker = markerRead.Marker!;
        var primaryRead = await TryReadEnvelopeAsync(SettingsPath, cancellationToken)
            .ConfigureAwait(false);
        var previousRead = await TryReadEnvelopeAsync(PreviousSettingsPath, cancellationToken)
            .ConfigureAwait(false);
        var primaryMatchesMarker =
            primaryRead.Status == PersistedReadStatus.Healthy &&
            MatchesEnvelope(
                primaryRead.Envelope!,
                marker.PrimaryGeneration,
                marker.PrimaryChecksum);
        var previousMatchesExpected =
            previousRead.Status == PersistedReadStatus.Healthy &&
            MatchesEnvelope(
                previousRead.Envelope!,
                marker.PreviousGeneration,
                marker.PreviousChecksum);
        if (primaryMatchesMarker && previousMatchesExpected)
        {
            return new SettingsPersistenceSnapshot(
                SettingsReadStatus.Healthy,
                ProjectReadMetadata(
                    primaryRead.Envelope!.Settings,
                    SettingsReadStatus.Healthy,
                    primaryRead.Envelope.Generation,
                    previousRead.Envelope!.Generation),
                primaryRead.Envelope,
                previousRead.Envelope,
                PrimaryMatchesMarker: true);
        }

        var previousMatchesCommittedBinding =
            previousRead.Status == PersistedReadStatus.Healthy &&
            (MatchesEnvelope(
                 previousRead.Envelope!,
                 marker.PrimaryGeneration,
                 marker.PrimaryChecksum) ||
             previousMatchesExpected);
        if (!primaryMatchesMarker && previousMatchesCommittedBinding)
        {
            return new SettingsPersistenceSnapshot(
                SettingsReadStatus.RecoveredFromPrevious,
                ProjectReadMetadata(
                    previousRead.Envelope!.Settings,
                    SettingsReadStatus.RecoveredFromPrevious,
                    0,
                    previousRead.Envelope.Generation),
                primaryRead.Envelope,
                previousRead.Envelope,
                PrimaryMatchesMarker: false);
        }

        return new SettingsPersistenceSnapshot(
            SettingsReadStatus.ConservativeDefaults,
            ProjectReadMetadata(
                new AppSettings(),
                SettingsReadStatus.ConservativeDefaults,
                0,
                0),
            primaryRead.Envelope,
            previousRead.Envelope,
            primaryMatchesMarker);
    }

    private static AttachmentSettingsReferenceSnapshot CreateAttachmentReferenceSnapshot(
        SettingsPersistenceSnapshot persistedState)
    {
        if (persistedState.ReadStatus == SettingsReadStatus.Missing)
        {
            return new AttachmentSettingsReferenceSnapshot(
                IsHealthy: true,
                SettingsGeneration: 0,
                PreviousSettingsGeneration: 0,
                CurrentContentIds: Array.Empty<string>(),
                PreviousContentIds: Array.Empty<string>());
        }

        var primary = persistedState.Primary;
        var previous = persistedState.Previous;
        var isHealthy = persistedState.ReadStatus == SettingsReadStatus.Healthy &&
                        persistedState.PrimaryMatchesMarker &&
                        primary is { AttachmentReferencesHealthy: true } &&
                        previous is { AttachmentReferencesHealthy: true };
        return new AttachmentSettingsReferenceSnapshot(
            isHealthy,
            primary?.Generation ?? 0,
            previous?.Generation ?? 0,
            primary?.AttachmentContentIds ?? Array.Empty<string>(),
            previous?.AttachmentContentIds ?? Array.Empty<string>());
    }

    private async Task<AppSettings?> TryReadLegacySettingsAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(SettingsPath))
        {
            return null;
        }

        try
        {
            await using var stream = new FileStream(
                SettingsPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var document = await JsonDocument.ParseAsync(
                    stream,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                document.RootElement.EnumerateObject().Any(property =>
                    IsEnvelopePropertyName(property.Name)))
            {
                return null;
            }

            var settings = document.RootElement.Deserialize<AppSettings>(JsonOptions);
            if (settings is null || IsFutureConfigurationVersion(document.RootElement))
            {
                return null;
            }

            return Normalize(settings, ShouldMigrateLegacy(document.RootElement));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return null;
        }
    }

    private async Task<PersistedEnvelopeRead> TryReadEnvelopeAsync(
        string path,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (!File.Exists(path))
        {
            return new PersistedEnvelopeRead(
                PathExists(path) ? PersistedReadStatus.Invalid : PersistedReadStatus.Missing,
                null);
        }

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var document = await JsonDocument.ParseAsync(
                    stream,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var root = document.RootElement;
            if (!HasExactProperties(
                    root,
                    nameof(SettingsEnvelopeDocument.SchemaVersion),
                    nameof(SettingsEnvelopeDocument.Generation),
                    nameof(SettingsEnvelopeDocument.Settings),
                    nameof(SettingsEnvelopeDocument.Checksum)))
            {
                return new PersistedEnvelopeRead(PersistedReadStatus.Invalid, null);
            }

            var schemaVersionElement = root.GetProperty(nameof(SettingsEnvelopeDocument.SchemaVersion));
            if (schemaVersionElement.ValueKind != JsonValueKind.Number ||
                !schemaVersionElement.TryGetInt32(out var schemaVersion) ||
                schemaVersion != CurrentEnvelopeSchemaVersion)
            {
                return new PersistedEnvelopeRead(PersistedReadStatus.Invalid, null);
            }

            var generationElement = root.GetProperty(nameof(SettingsEnvelopeDocument.Generation));
            if (generationElement.ValueKind != JsonValueKind.Number ||
                !generationElement.TryGetInt64(out var generation) ||
                generation <= 0)
            {
                return new PersistedEnvelopeRead(PersistedReadStatus.Invalid, null);
            }

            var settingsElement = root.GetProperty(nameof(SettingsEnvelopeDocument.Settings));
            var checksumElement = root.GetProperty(nameof(SettingsEnvelopeDocument.Checksum));
            var checksum = checksumElement.ValueKind == JsonValueKind.String
                ? checksumElement.GetString()
                : null;
            if (settingsElement.ValueKind != JsonValueKind.Object ||
                !HasCurrentConfigurationVersion(settingsElement) ||
                !IsCanonicalSha256(checksum))
            {
                return new PersistedEnvelopeRead(PersistedReadStatus.Invalid, null);
            }

            var expectedChecksum = ComputeEnvelopeChecksum(schemaVersion, generation, settingsElement);
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expectedChecksum),
                    Encoding.ASCII.GetBytes(checksum!)))
            {
                return new PersistedEnvelopeRead(PersistedReadStatus.Invalid, null);
            }

            var settings = settingsElement.Deserialize<AppSettings>(JsonOptions);
            if (settings is null)
            {
                return new PersistedEnvelopeRead(PersistedReadStatus.Invalid, null);
            }

            var attachmentReferences = InspectAttachmentReferences(settings);
            return new PersistedEnvelopeRead(
                PersistedReadStatus.Healthy,
                new SettingsEnvelope(
                    generation,
                    checksum!,
                    Normalize(
                        settings,
                        migrateLegacyOverride:
                            settings.ConfigurationVersion < AppSettings.CurrentConfigurationVersion),
                    attachmentReferences.IsHealthy,
                    attachmentReferences.ContentIds));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new PersistedEnvelopeRead(PersistedReadStatus.Invalid, null);
        }
    }

    private async Task<PersistedMarkerRead> TryReadMarkerAsync(
        string path,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        if (!File.Exists(path))
        {
            return new PersistedMarkerRead(
                PathExists(path) ? PersistedReadStatus.Invalid : PersistedReadStatus.Missing,
                null);
        }

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var document = await JsonDocument.ParseAsync(
                    stream,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var root = document.RootElement;
            if (!HasExactProperties(
                    root,
                    nameof(SettingsInitializationMarker.SchemaVersion),
                    nameof(SettingsInitializationMarker.PrimaryGeneration),
                    nameof(SettingsInitializationMarker.PrimaryChecksum),
                    nameof(SettingsInitializationMarker.PreviousGeneration),
                    nameof(SettingsInitializationMarker.PreviousChecksum),
                    nameof(SettingsInitializationMarker.Checksum)))
            {
                return new PersistedMarkerRead(PersistedReadStatus.Invalid, null);
            }

            var marker = root.Deserialize<SettingsInitializationMarker>(JsonOptions);
            if (marker is null ||
                marker.SchemaVersion != CurrentMarkerSchemaVersion ||
                marker.PrimaryGeneration <= 0 ||
                marker.PreviousGeneration <= 0 ||
                marker.PreviousGeneration > marker.PrimaryGeneration ||
                !IsCanonicalSha256(marker.PrimaryChecksum) ||
                !IsCanonicalSha256(marker.PreviousChecksum) ||
                !IsCanonicalSha256(marker.Checksum))
            {
                return new PersistedMarkerRead(PersistedReadStatus.Invalid, null);
            }

            var expectedChecksum = ComputeMarkerChecksum(
                marker.SchemaVersion,
                marker.PrimaryGeneration,
                marker.PrimaryChecksum,
                marker.PreviousGeneration,
                marker.PreviousChecksum);
            return CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expectedChecksum),
                    Encoding.ASCII.GetBytes(marker.Checksum))
                ? new PersistedMarkerRead(PersistedReadStatus.Healthy, marker)
                : new PersistedMarkerRead(PersistedReadStatus.Invalid, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new PersistedMarkerRead(PersistedReadStatus.Invalid, null);
        }
    }

    private async Task ValidatePreparedEnvelopeAsync(
        string path,
        long expectedGeneration,
        string expectedChecksum,
        CancellationToken cancellationToken)
    {
        var persisted = await TryReadEnvelopeAsync(path, cancellationToken).ConfigureAwait(false);
        if (persisted.Status != PersistedReadStatus.Healthy ||
            persisted.Envelope!.Generation != expectedGeneration ||
            !string.Equals(persisted.Envelope.Checksum, expectedChecksum, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The prepared settings envelope failed validation.");
        }
    }

    private async Task ValidatePreparedMarkerAsync(
        string path,
        SettingsInitializationMarker expected,
        CancellationToken cancellationToken)
    {
        var persisted = await TryReadMarkerAsync(path, cancellationToken).ConfigureAwait(false);
        if (persisted.Status != PersistedReadStatus.Healthy || persisted.Marker != expected)
        {
            throw new InvalidDataException("The prepared settings marker failed validation.");
        }
    }

    private async Task WriteTemporaryFileAsync(
        string path,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, path);
        await using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        stream.Flush(flushToDisk: true);
    }

    private static PreparedEnvelope CreateEnvelope(AppSettings settings, long generation)
    {
        var settingsElement = JsonSerializer.SerializeToElement(settings, JsonOptions);
        var checksum = ComputeEnvelopeChecksum(
            CurrentEnvelopeSchemaVersion,
            generation,
            settingsElement);
        var document = new SettingsEnvelopeDocument(
            CurrentEnvelopeSchemaVersion,
            generation,
            settingsElement,
            checksum);
        return new PreparedEnvelope(
            generation,
            checksum,
            document,
            JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions));
    }

    private static PreparedMarker CreateMarker(
        long primaryGeneration,
        string primaryChecksum,
        long previousGeneration,
        string previousChecksum)
    {
        var checksum = ComputeMarkerChecksum(
            CurrentMarkerSchemaVersion,
            primaryGeneration,
            primaryChecksum,
            previousGeneration,
            previousChecksum);
        var document = new SettingsInitializationMarker(
            CurrentMarkerSchemaVersion,
            primaryGeneration,
            primaryChecksum,
            previousGeneration,
            previousChecksum,
            checksum);
        return new PreparedMarker(
            document,
            JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions));
    }

    private static string ComputeEnvelopeChecksum(
        int schemaVersion,
        long generation,
        JsonElement settings)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber(nameof(SettingsEnvelopeDocument.SchemaVersion), schemaVersion);
            writer.WriteNumber(nameof(SettingsEnvelopeDocument.Generation), generation);
            writer.WritePropertyName(nameof(SettingsEnvelopeDocument.Settings));
            settings.WriteTo(writer);
            writer.WriteEndObject();
        }

        return Convert.ToHexString(SHA256.HashData(buffer.WrittenSpan));
    }

    private static string ComputeMarkerChecksum(
        int schemaVersion,
        long primaryGeneration,
        string primaryChecksum,
        long previousGeneration,
        string previousChecksum)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber(nameof(SettingsInitializationMarker.SchemaVersion), schemaVersion);
            writer.WriteNumber(
                nameof(SettingsInitializationMarker.PrimaryGeneration),
                primaryGeneration);
            writer.WriteString(
                nameof(SettingsInitializationMarker.PrimaryChecksum),
                primaryChecksum);
            writer.WriteNumber(
                nameof(SettingsInitializationMarker.PreviousGeneration),
                previousGeneration);
            writer.WriteString(
                nameof(SettingsInitializationMarker.PreviousChecksum),
                previousChecksum);
            writer.WriteEndObject();
        }

        return Convert.ToHexString(SHA256.HashData(buffer.WrittenSpan));
    }

    private static bool HasExactProperties(JsonElement root, params string[] expectedNames)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var expected = new HashSet<string>(expectedNames, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!expected.Contains(property.Name) || !seen.Add(property.Name))
            {
                return false;
            }
        }

        return seen.Count == expected.Count;
    }

    private static bool HasCurrentConfigurationVersion(JsonElement settings) =>
        settings.TryGetProperty(nameof(AppSettings.ConfigurationVersion), out var version) &&
        version.ValueKind == JsonValueKind.Number &&
        version.TryGetInt32(out var configurationVersion) &&
        configurationVersion > 0 &&
        configurationVersion <= AppSettings.CurrentConfigurationVersion;

    private static bool ShouldMigrateLegacy(JsonElement settings) =>
        !settings.TryGetProperty(nameof(AppSettings.ConfigurationVersion), out var version) ||
        version.ValueKind != JsonValueKind.Number ||
        !version.TryGetInt32(out var configurationVersion) ||
        configurationVersion < AppSettings.CurrentConfigurationVersion;

    private static bool IsFutureConfigurationVersion(JsonElement settings) =>
        settings.TryGetProperty(nameof(AppSettings.ConfigurationVersion), out var version) &&
        version.ValueKind == JsonValueKind.Number &&
        version.TryGetInt32(out var configurationVersion) &&
        configurationVersion > AppSettings.CurrentConfigurationVersion;

    private static ConcurrentDictionary<string, bool> CloneProtectionMap(
        IReadOnlyDictionary<string, bool> source) =>
        new(source, StringComparer.OrdinalIgnoreCase);

    private static bool IsEnvelopePropertyName(string name) =>
        string.Equals(name, nameof(SettingsEnvelopeDocument.SchemaVersion), StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, nameof(SettingsEnvelopeDocument.Generation), StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, nameof(SettingsEnvelopeDocument.Settings), StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, nameof(SettingsEnvelopeDocument.Checksum), StringComparison.OrdinalIgnoreCase);

    private static bool IsCanonicalSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static AttachmentReferenceInspection InspectAttachmentReferences(AppSettings settings)
    {
        var contentIds = new HashSet<string>(StringComparer.Ordinal);
        if (settings.ThreadFollowUps is null)
        {
            return new AttachmentReferenceInspection(true, Array.Empty<string>());
        }

        foreach (var pair in settings.ThreadFollowUps)
        {
            var thread = pair.Value;
            if (thread is null || thread.Messages is null)
            {
                return new AttachmentReferenceInspection(false, contentIds.ToArray());
            }

            foreach (var message in thread.Messages)
            {
                if (message is null || message.Attachments is null)
                {
                    return new AttachmentReferenceInspection(false, contentIds.ToArray());
                }

                foreach (var attachment in message.Attachments)
                {
                    if (attachment is null ||
                        !AttachmentIdentity.IsCanonicalContentId(attachment.ContentId))
                    {
                        return new AttachmentReferenceInspection(false, contentIds.ToArray());
                    }

                    contentIds.Add(attachment.ContentId);
                }
            }
        }

        return new AttachmentReferenceInspection(
            true,
            contentIds.OrderBy(contentId => contentId, StringComparer.Ordinal).ToArray());
    }

    private static bool MatchesEnvelope(
        SettingsEnvelope envelope,
        long expectedGeneration,
        string expectedChecksum) =>
        envelope.Generation == expectedGeneration &&
        string.Equals(envelope.Checksum, expectedChecksum, StringComparison.Ordinal);

    private static AppSettings ProjectReadMetadata(
        AppSettings settings,
        SettingsReadStatus status,
        long generation,
        long previousGeneration)
    {
        settings.ReadStatus = status;
        settings.SettingsGeneration = generation;
        settings.PreviousSettingsGeneration = previousGeneration;
        return settings;
    }

    private static SettingsPersistenceSnapshot MissingSnapshot() =>
        new(
            SettingsReadStatus.Missing,
            ProjectReadMetadata(new AppSettings(), SettingsReadStatus.Missing, 0, 0),
            null,
            null,
            PrimaryMatchesMarker: false);

    private static SettingsPersistenceSnapshot ConservativeSnapshot() =>
        new(
            SettingsReadStatus.ConservativeDefaults,
            ProjectReadMetadata(
                new AppSettings(),
                SettingsReadStatus.ConservativeDefaults,
                0,
                0),
            null,
            null,
            PrimaryMatchesMarker: false);

    private static bool PathExists(string path) =>
        File.Exists(path) || Directory.Exists(path);

    private static string CreateTemporaryPath(string destinationPath) =>
        Path.Combine(
            Path.GetDirectoryName(destinationPath)!,
            $".{Path.GetFileName(destinationPath)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");

    private static Exception? CaptureTemporaryCleanupFailure(
        Exception? existing,
        string dataDirectory,
        string? path)
    {
        if (path is null)
        {
            return existing;
        }

        try
        {
            DataDirectorySafety.Revalidate(dataDirectory);
            DataDirectorySafety.RevalidateWriteTarget(dataDirectory, path);
            File.Delete(path);
            return existing;
        }
        catch (Exception cleanupFailure)
        {
            return existing is null
                ? cleanupFailure
                : new AggregateException(existing, cleanupFailure);
        }
    }

    private static ConcurrentDictionary<string, bool> NormalizeProtectionMap(
        IReadOnlyDictionary<string, bool>? source)
    {
        var normalized = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        if (source is null)
        {
            return normalized;
        }

        foreach (var pair in source)
        {
            normalized[pair.Key] = normalized.TryGetValue(pair.Key, out var existing)
                ? existing && pair.Value
                : pair.Value;
        }

        return normalized;
    }

    internal static AttachmentLimitSettings NormalizeAttachmentLimits(
        AttachmentLimitSettings? source)
    {
        var defaults = new AttachmentLimitSettings();
        var candidate = source ?? defaults;
        var maximumAttachmentsPerMessage = Math.Clamp(
            candidate.MaximumAttachmentsPerMessage,
            1,
            defaults.MaximumAttachmentsPerMessage);
        var maximumBytesPerFile = Math.Clamp(
            candidate.MaximumBytesPerFile,
            1,
            defaults.MaximumBytesPerFile);
        var maximumBytesPerMessage = Math.Clamp(
            candidate.MaximumBytesPerMessage,
            maximumBytesPerFile,
            defaults.MaximumBytesPerMessage);
        var maximumLibraryBytes = Math.Clamp(
            candidate.MaximumLibraryBytes,
            maximumBytesPerMessage,
            defaults.MaximumLibraryBytes);
        return new AttachmentLimitSettings
        {
            MaximumAttachmentsPerMessage = maximumAttachmentsPerMessage,
            MaximumBytesPerFile = maximumBytesPerFile,
            MaximumBytesPerMessage = maximumBytesPerMessage,
            MaximumLibraryBytes = maximumLibraryBytes
        };
    }

    internal static List<string> NormalizeConversationOrder(IEnumerable<string>? source)
    {
        var normalized = new List<string>();
        if (source is null)
        {
            return normalized;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in source)
        {
            if (normalized.Count >= MaximumConversationOrderCount)
            {
                break;
            }

            var threadId = candidate?.Trim() ?? string.Empty;
            if (threadId.Length == 0 ||
                threadId.Length > MaximumConversationIdLength ||
                !seen.Add(threadId))
            {
                continue;
            }

            normalized.Add(threadId);
        }

        return normalized;
    }

    internal static ConcurrentDictionary<string, ThreadFollowUpSettings> NormalizeThreadFollowUps(
        IReadOnlyDictionary<string, ThreadFollowUpSettings>? source,
        AttachmentLimitSettings? attachmentLimits = null)
    {
        var normalized = new ConcurrentDictionary<string, ThreadFollowUpSettings>(
            StringComparer.OrdinalIgnoreCase);
        if (source is null)
        {
            return normalized;
        }

        var normalizedAttachmentLimits = NormalizeAttachmentLimits(attachmentLimits);
        var orderedThreads = new List<(string ThreadId, string OriginalKey, ThreadFollowUpSettings Settings)>();
        foreach (var pair in source)
        {
            if (!Guid.TryParse(pair.Key, out var parsedThreadId) || pair.Value is null)
            {
                continue;
            }

            orderedThreads.Add((parsedThreadId.ToString("D"), pair.Key, pair.Value));
        }

        var totalMessages = 0;
        foreach (var candidateThread in orderedThreads
                     .OrderBy(candidate => candidate.ThreadId, StringComparer.Ordinal)
                     .ThenBy(candidate => candidate.OriginalKey, StringComparer.Ordinal))
        {
            if (normalized.Count >= MaximumFollowUpThreadCount ||
                totalMessages >= MaximumTotalFollowUpMessages)
            {
                break;
            }

            var threadId = candidateThread.ThreadId;
            if (normalized.ContainsKey(threadId))
            {
                continue;
            }

            var threadSettings = candidateThread.Settings;
            var seenMessageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var messages = new List<FollowUpMessageDefinition>();
            foreach (var candidate in (threadSettings.Messages ?? [])
                         .Where(message => message is not null)
                         .OrderBy(message => message.Order)
                         .ThenBy(message => message.Id ?? string.Empty, StringComparer.Ordinal)
                         .ThenBy(message => message.Message ?? string.Empty, StringComparer.Ordinal)
                         .ThenBy(message => message.Trigger)
                         .ThenBy(message => message.ScheduledAtUtc))
            {
                if (messages.Count >= MaximumFollowUpMessagesPerThread ||
                    totalMessages >= MaximumTotalFollowUpMessages)
                {
                    break;
                }

                if (!Guid.TryParse(candidate.Id, out var parsedMessageId) ||
                    !Enum.IsDefined(candidate.Trigger))
                {
                    continue;
                }

                var messageId = parsedMessageId.ToString("D");
                var content = NormalizeFollowUpMessage(candidate.Message);
                var attachments = NormalizeAttachments(
                    candidate.Attachments,
                    normalizedAttachmentLimits);
                if (content.Length == 0 && attachments.Count == 0 ||
                    !seenMessageIds.Add(messageId))
                {
                    continue;
                }

                var scheduledAtUtc = candidate.Trigger == FollowUpTriggerKind.ScheduledAt
                    ? candidate.ScheduledAtUtc?.ToUniversalTime()
                    : null;
                if (candidate.Trigger == FollowUpTriggerKind.ScheduledAt && scheduledAtUtc is null)
                {
                    continue;
                }

                var workflowBindingValid = candidate.UseWorkflowAutomation &&
                                           candidate.WorkflowRuleRevision is > 0 &&
                                           IsCanonicalSha256(candidate.WorkflowRuleDigest);

                messages.Add(candidate with
                {
                    Id = messageId,
                    Message = content,
                    Attachments = attachments,
                    ScheduledAtUtc = scheduledAtUtc,
                    UseWorkflowAutomation = candidate.UseWorkflowAutomation,
                    WorkflowRuleRevision = workflowBindingValid
                        ? candidate.WorkflowRuleRevision
                        : null,
                    WorkflowRuleDigest = workflowBindingValid
                        ? candidate.WorkflowRuleDigest
                        : null,
                    RetryIndefinitely = candidate.RetryIndefinitely,
                    MaximumErrorRetries = candidate.RetryIndefinitely
                        ? null
                        : FollowUpRetryPolicy.NormalizeMaximumErrorRetries(
                            candidate.MaximumErrorRetries),
                    Order = messages.Count
                });
                totalMessages++;
            }

            if (messages.Count == 0)
            {
                continue;
            }

            var anchor = Guid.TryParse(threadSettings.CompletionAnchorTurnId, out var parsedAnchor)
                ? parsedAnchor.ToString("D")
                : null;
            normalized[threadId] = threadSettings with
            {
                CompletionAnchorTurnId = anchor,
                Messages = messages
            };
        }

        return normalized;
    }

    internal static IReadOnlyList<PresetAttachmentReference> NormalizeAttachments(
        IEnumerable<PresetAttachmentReference>? source,
        AttachmentLimitSettings? limits = null)
    {
        var normalizedLimits = NormalizeAttachmentLimits(limits);
        var normalized = new List<PresetAttachmentReference>();
        if (source is null)
        {
            return normalized;
        }

        var seenReferenceIds = new HashSet<string>(StringComparer.Ordinal);
        long totalBytes = 0;
        foreach (var candidate in source
                     .Where(reference => reference is not null)
                     .OrderBy(reference => reference.Order)
                     .ThenBy(reference => reference.Id ?? string.Empty, StringComparer.Ordinal))
        {
            if (normalized.Count >= normalizedLimits.MaximumAttachmentsPerMessage)
            {
                break;
            }

            var originalFileName = candidate.OriginalFileName?.Trim() ?? string.Empty;
            var detectedType = candidate.DetectedType?.Trim() ?? string.Empty;
            var ownerInputKind = candidate.OwnerInputKind?.Trim() ?? string.Empty;
            if (!AttachmentIdentity.IsCanonicalReferenceId(candidate.Id) ||
                !AttachmentIdentity.IsCanonicalContentId(candidate.ContentId) ||
                originalFileName.Length == 0 ||
                !string.Equals(
                    Path.GetFileName(originalFileName),
                    originalFileName,
                    StringComparison.Ordinal) ||
                detectedType.Length == 0 ||
                ownerInputKind.Length == 0 ||
                candidate.ByteLength <= 0 ||
                candidate.ByteLength > normalizedLimits.MaximumBytesPerFile ||
                totalBytes > normalizedLimits.MaximumBytesPerMessage - candidate.ByteLength ||
                !seenReferenceIds.Add(candidate.Id))
            {
                continue;
            }

            totalBytes += candidate.ByteLength;
            normalized.Add(candidate with
            {
                OriginalFileName = originalFileName,
                DetectedType = detectedType,
                OwnerInputKind = ownerInputKind,
                Order = normalized.Count
            });
        }

        return normalized;
    }

    internal static string NormalizeContinueMessage(string? value)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0)
        {
            return DefaultContinueMessage;
        }

        return normalized.Length <= MaximumContinueMessageLength
            ? normalized
            : normalized[..MaximumContinueMessageLength];
    }

    internal static string NormalizeFollowUpMessage(string? value)
    {
        var normalized = value?.Trim() ?? string.Empty;
        return normalized.Length <= MaximumFollowUpMessageLength
            ? normalized
            : normalized[..MaximumFollowUpMessageLength];
    }

    private sealed class OrderedThreadFollowUpsConverter :
        JsonConverter<ConcurrentDictionary<string, ThreadFollowUpSettings>>
    {
        public override ConcurrentDictionary<string, ThreadFollowUpSettings> Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
            {
                return new ConcurrentDictionary<string, ThreadFollowUpSettings>(
                    StringComparer.OrdinalIgnoreCase);
            }

            var values = JsonSerializer.Deserialize<Dictionary<string, ThreadFollowUpSettings>>(
                ref reader,
                options);
            return new ConcurrentDictionary<string, ThreadFollowUpSettings>(
                values ?? new Dictionary<string, ThreadFollowUpSettings>(),
                StringComparer.OrdinalIgnoreCase);
        }

        public override void Write(
            Utf8JsonWriter writer,
            ConcurrentDictionary<string, ThreadFollowUpSettings> value,
            JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            foreach (var pair in value.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                writer.WritePropertyName(pair.Key);
                JsonSerializer.Serialize(writer, pair.Value, options);
            }

            writer.WriteEndObject();
        }
    }

    private enum PersistedReadStatus
    {
        Missing,
        Healthy,
        Invalid
    }

    private sealed record SettingsPersistenceSnapshot(
        SettingsReadStatus ReadStatus,
        AppSettings Settings,
        SettingsEnvelope? Primary,
        SettingsEnvelope? Previous,
        bool PrimaryMatchesMarker);

    private sealed record SettingsEnvelope(
        long Generation,
        string Checksum,
        AppSettings Settings,
        bool AttachmentReferencesHealthy,
        IReadOnlyList<string> AttachmentContentIds);

    private sealed record AttachmentReferenceInspection(
        bool IsHealthy,
        IReadOnlyList<string> ContentIds);

    private sealed record SettingsEnvelopeDocument(
        int SchemaVersion,
        long Generation,
        JsonElement Settings,
        string Checksum);

    private sealed record SettingsInitializationMarker(
        int SchemaVersion,
        long PrimaryGeneration,
        string PrimaryChecksum,
        long PreviousGeneration,
        string PreviousChecksum,
        string Checksum);

    private sealed record PersistedEnvelopeRead(
        PersistedReadStatus Status,
        SettingsEnvelope? Envelope);

    private sealed record PersistedMarkerRead(
        PersistedReadStatus Status,
        SettingsInitializationMarker? Marker);

    private sealed record PreparedEnvelope(
        long Generation,
        string Checksum,
        SettingsEnvelopeDocument Document,
        byte[] Bytes);

    private sealed record PreparedMarker(
        SettingsInitializationMarker Document,
        byte[] Bytes);
}
