using CodexGuardian.Models;
using CodexGuardian.Services;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal enum AutomaticRecoveryLiveGateAuthorizationState
{
    Prepared,
    Armed,
    Confirmed,
    Uncertain,
    Closed
}

internal sealed record AutomaticRecoveryExistingConversationLiveGateOptions(
    bool PrepareOnly,
    string GateId,
    string TargetThreadId,
    string ExpectedFailedTurnId,
    string RestoreThreadId,
    string DataDirectory,
    string? AuthorizationDigest);

internal sealed record AutomaticRecoveryLiveGatePlan(
    string GateId,
    string TargetThreadId,
    string ExpectedFailedTurnId,
    string RestoreThreadId,
    RecoveryActionKind Action,
    string OperationId,
    string ClientMessageId,
    string PayloadDigest,
    string FailedTurnEvidenceDigest,
    string TargetIdentityDigest,
    long TargetUpdatedAt,
    long SettingsGeneration,
    string SettingsSha256,
    DateTimeOffset PreparedAtUtc,
    DateTimeOffset ExpiresAtUtc);

internal sealed record AutomaticRecoveryLiveGateManifest(
    int SchemaVersion,
    long Generation,
    AutomaticRecoveryLiveGateAuthorizationState State,
    AutomaticRecoveryLiveGatePlan Plan,
    string? NewTurnId,
    string Checksum);

internal sealed record AutomaticRecoveryLiveGateManifestContent(
    int SchemaVersion,
    long Generation,
    AutomaticRecoveryLiveGateAuthorizationState State,
    AutomaticRecoveryLiveGatePlan Plan,
    string? NewTurnId);

internal sealed class AutomaticRecoveryLiveGateManifestStore
{
    internal const int CurrentSchemaVersion = 1;
    internal const string ManifestFileName = "automatic-recovery-live-gate.json";
    private const string LockFileName = "automatic-recovery-live-gate.lock";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal AutomaticRecoveryLiveGateManifestStore(string dataDirectory)
    {
        DataDirectory = DataDirectorySafety.NormalizeAndValidate(dataDirectory);
        ManifestPath = Path.Combine(DataDirectory, ManifestFileName);
        LockPath = Path.Combine(DataDirectory, LockFileName);
    }

    internal string DataDirectory { get; }

    internal string ManifestPath { get; }

    internal string LockPath { get; }

    internal AutomaticRecoveryLiveGateManifest CreatePrepared(
        AutomaticRecoveryLiveGatePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ValidatePlan(plan);
        using var lease = AcquireLease();
        if (File.Exists(ManifestPath))
        {
            throw new InvalidOperationException("The recovery live-gate manifest already exists.");
        }

        var manifest = CreateManifest(
            generation: 1,
            AutomaticRecoveryLiveGateAuthorizationState.Prepared,
            plan,
            newTurnId: null);
        Persist(manifest);
        return manifest;
    }

    internal AutomaticRecoveryLiveGateManifest Read()
    {
        using var lease = AcquireLease();
        return ReadUnderLease();
    }

    internal AutomaticRecoveryLiveGateManifest Transition(
        AutomaticRecoveryLiveGateAuthorizationState expectedState,
        AutomaticRecoveryLiveGateAuthorizationState nextState,
        string expectedAuthorizationDigest,
        string? newTurnId = null)
    {
        using var lease = AcquireLease();
        var current = ReadUnderLease();
        if (current.State != expectedState ||
            !string.Equals(
                ComputeAuthorizationDigest(current.Plan),
                expectedAuthorizationDigest,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The recovery live-gate authority changed.");
        }

        if (expectedState == AutomaticRecoveryLiveGateAuthorizationState.Prepared &&
            nextState == AutomaticRecoveryLiveGateAuthorizationState.Armed &&
            current.Plan.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            throw new InvalidOperationException("The recovery live-gate authorization expired.");
        }

        ValidateTransition(expectedState, nextState, newTurnId);
        var next = CreateManifest(
            checked(current.Generation + 1),
            nextState,
            current.Plan,
            NormalizeOptionalId(newTurnId));
        Persist(next);
        return next;
    }

    internal static string ComputeAuthorizationDigest(AutomaticRecoveryLiveGatePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(plan, JsonOptions)));
    }

    private FileStream AcquireLease()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        try
        {
            DataDirectorySafety.RevalidateWriteTarget(DataDirectory, LockPath);
        }
        catch (Win32Exception exception)
        {
            throw new IOException("The recovery live-gate manifest lease is unavailable.", exception);
        }

        return new FileStream(
            LockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 1,
            FileOptions.WriteThrough);
    }

    private AutomaticRecoveryLiveGateManifest ReadUnderLease()
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, ManifestPath);
        if (!File.Exists(ManifestPath))
        {
            throw new FileNotFoundException("The recovery live-gate manifest is missing.", ManifestPath);
        }

        var bytes = File.ReadAllBytes(ManifestPath);
        AutomaticRecoveryLiveGateManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<AutomaticRecoveryLiveGateManifest>(bytes, JsonOptions)
                ?? throw new InvalidDataException("The recovery live-gate manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The recovery live-gate manifest is malformed.", exception);
        }

        if (manifest.Plan is null || manifest.SchemaVersion != CurrentSchemaVersion ||
            manifest.Generation < 1 || !IsSha256(manifest.Checksum) ||
            !string.Equals(
                manifest.Checksum,
                ComputeChecksum(new AutomaticRecoveryLiveGateManifestContent(
                    manifest.SchemaVersion,
                    manifest.Generation,
                    manifest.State,
                    manifest.Plan,
                    manifest.NewTurnId)),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("The recovery live-gate manifest is invalid.");
        }

        ValidatePlan(manifest.Plan);
        ValidateManifestState(manifest.State, manifest.NewTurnId);

        var canonical = Serialize(manifest);
        if (!bytes.AsSpan().SequenceEqual(canonical))
        {
            throw new InvalidDataException("The recovery live-gate manifest is non-canonical.");
        }

        return manifest;
    }

    private void Persist(AutomaticRecoveryLiveGateManifest manifest)
    {
        DataDirectorySafety.Revalidate(DataDirectory);
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, ManifestPath);
        var temporaryPath = Path.Combine(
            DataDirectory,
            "." + ManifestFileName + "." + Guid.NewGuid().ToString("N") + ".tmp");
        DataDirectorySafety.RevalidateWriteTarget(DataDirectory, temporaryPath);
        try
        {
            var bytes = Serialize(manifest);
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, ManifestPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static AutomaticRecoveryLiveGateManifest CreateManifest(
        long generation,
        AutomaticRecoveryLiveGateAuthorizationState state,
        AutomaticRecoveryLiveGatePlan plan,
        string? newTurnId)
    {
        var content = new AutomaticRecoveryLiveGateManifestContent(
            CurrentSchemaVersion,
            generation,
            state,
            plan,
            newTurnId);
        return new AutomaticRecoveryLiveGateManifest(
            content.SchemaVersion,
            content.Generation,
            content.State,
            content.Plan,
            content.NewTurnId,
            ComputeChecksum(content));
    }

    private static string ComputeChecksum(AutomaticRecoveryLiveGateManifestContent content) =>
        Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(content, JsonOptions)));

    private static byte[] Serialize(AutomaticRecoveryLiveGateManifest manifest)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        var canonical = new byte[payload.Length + 1];
        payload.CopyTo(canonical, 0);
        canonical[^1] = (byte)'\n';
        return canonical;
    }

    private static void ValidateTransition(
        AutomaticRecoveryLiveGateAuthorizationState expectedState,
        AutomaticRecoveryLiveGateAuthorizationState nextState,
        string? newTurnId)
    {
        var valid = expectedState switch
        {
            AutomaticRecoveryLiveGateAuthorizationState.Prepared =>
                nextState == AutomaticRecoveryLiveGateAuthorizationState.Armed,
            AutomaticRecoveryLiveGateAuthorizationState.Armed =>
                nextState is AutomaticRecoveryLiveGateAuthorizationState.Confirmed or
                    AutomaticRecoveryLiveGateAuthorizationState.Uncertain or
                    AutomaticRecoveryLiveGateAuthorizationState.Closed,
            _ => false
        };
        if (!valid ||
            nextState == AutomaticRecoveryLiveGateAuthorizationState.Confirmed !=
            !string.IsNullOrWhiteSpace(newTurnId))
        {
            throw new InvalidOperationException("The recovery live-gate transition is invalid.");
        }
    }

    private static void ValidateManifestState(
        AutomaticRecoveryLiveGateAuthorizationState state,
        string? newTurnId)
    {
        var hasNewTurnId = !string.IsNullOrEmpty(newTurnId);
        if (!Enum.IsDefined(state) ||
            (state == AutomaticRecoveryLiveGateAuthorizationState.Confirmed) != hasNewTurnId ||
            hasNewTurnId && (!Guid.TryParseExact(newTurnId, "D", out var parsed) ||
                parsed == Guid.Empty ||
                !string.Equals(newTurnId, parsed.ToString("D"), StringComparison.Ordinal)))
        {
            throw new InvalidDataException("The recovery live-gate manifest state is invalid.");
        }
    }

    private static void ValidatePlan(AutomaticRecoveryLiveGatePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!IsCanonicalId(plan.GateId) || !IsCanonicalId(plan.TargetThreadId) ||
            !IsCanonicalId(plan.ExpectedFailedTurnId) || !IsCanonicalId(plan.RestoreThreadId) ||
            !IsCanonicalId(plan.OperationId) || !IsCanonicalId(plan.ClientMessageId) ||
            string.Equals(plan.TargetThreadId, plan.RestoreThreadId, StringComparison.OrdinalIgnoreCase) ||
            !Enum.IsDefined(plan.Action) || plan.Action == RecoveryActionKind.None ||
            !IsSha256(plan.PayloadDigest) || !IsSha256(plan.FailedTurnEvidenceDigest) ||
            !IsSha256(plan.TargetIdentityDigest) || !IsSha256(plan.SettingsSha256) ||
            plan.TargetUpdatedAt < 0 || plan.SettingsGeneration < 1 ||
            plan.PreparedAtUtc.Offset != TimeSpan.Zero || plan.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            plan.ExpiresAtUtc - plan.PreparedAtUtc !=
                AutomaticRecoveryExistingConversationLiveGate.AuthorizationLifetime)
        {
            throw new InvalidDataException("The recovery live-gate plan is invalid.");
        }

        var operationId = AppServerClient.CreateRecoveryMessageId(
            plan.TargetThreadId,
            plan.ExpectedFailedTurnId,
            plan.Action);
        if (!string.Equals(plan.OperationId, operationId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.ClientMessageId, operationId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The recovery live-gate operation identity is invalid.");
        }
    }

    private static bool IsCanonicalId(string? value) =>
        Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty &&
        string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static string? NormalizeOptionalId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A valid optional turn identity is required.", nameof(value));
        }

        return parsed.ToString("D");
    }
}

internal sealed class AutomaticRecoveryLiveGatePolicyAuthority(
    AutomaticRecoveryLiveGateManifestStore store,
    string expectedAuthorizationDigest,
    string settingsPath,
    string expectedSettingsSha256,
    Func<DateTimeOffset>? utcNowProvider = null)
{
    private readonly Func<DateTimeOffset> _utcNowProvider =
        utcNowProvider ?? (() => DateTimeOffset.UtcNow);

    internal bool IsCurrent()
    {
        try
        {
            var manifest = store.Read();
            return manifest.State == AutomaticRecoveryLiveGateAuthorizationState.Armed &&
                   manifest.Plan.ExpiresAtUtc > _utcNowProvider().ToUniversalTime() &&
                   string.Equals(
                       AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(
                           manifest.Plan),
                       expectedAuthorizationDigest,
                       StringComparison.Ordinal) &&
                   File.Exists(settingsPath) &&
                   string.Equals(
                       Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(settingsPath))),
                       expectedSettingsSha256,
                       StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }
}

internal static class AutomaticRecoveryExistingConversationLiveGate
{
    internal const string GateArgument = "--automatic-recovery-existing-conversation-live-gate";
    internal const string PrepareArgument = "--prepare-only";
    internal const string ConfirmArgument = "--confirm-real-recovery";
    internal const string GateIdArgument = "--gate-id";
    internal const string TargetArgument = "--target-thread-id";
    internal const string ExpectedTurnArgument = "--expected-failed-turn-id";
    internal const string RestoreArgument = "--restore-thread-id";
    internal const string DataDirectoryArgument = "--data-directory";
    internal const string AuthorizationDigestArgument = "--authorization-digest";
    internal const string DeprecatedExperimentArgument = "--desktop-recovery-experiment";
    internal const string DataRoot = @"D:\CodexData\CodexGuardian";
    internal const string ExecutionSemaphoreName =
        @"Local\CodexFree.Tests.AutomaticRecoveryLiveGate.v1";
    internal static readonly TimeSpan AuthorizationLifetime = TimeSpan.FromMinutes(20);
    private static readonly TimeSpan ExecutionTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan TargetPresentationDelay = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan ReadbackTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ReadbackPollInterval = TimeSpan.FromMilliseconds(500);

    internal static bool IsRequested(IReadOnlyList<string> arguments) =>
        arguments.Any(argument => string.Equals(
            argument,
            GateArgument,
            StringComparison.OrdinalIgnoreCase));

    internal static AutomaticRecoveryExistingConversationLiveGateOptions Parse(
        IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var allowedFlags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            GateArgument,
            PrepareArgument,
            ConfirmArgument
        };
        var allowedValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            GateIdArgument,
            TargetArgument,
            ExpectedTurnArgument,
            RestoreArgument,
            DataDirectoryArgument,
            AuthorizationDigestArgument
        };
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (allowedFlags.Contains(argument))
            {
                if (!flags.Add(argument))
                {
                    throw new ArgumentException("The automatic-recovery gate contains a duplicate flag.");
                }

                continue;
            }

            if (!allowedValues.Contains(argument) || index + 1 >= arguments.Count ||
                arguments[index + 1].StartsWith("--", StringComparison.Ordinal) ||
                !values.TryAdd(argument, arguments[++index]))
            {
                throw new ArgumentException("The automatic-recovery gate argument matrix is invalid.");
            }
        }

        var prepareOnly = flags.Contains(PrepareArgument);
        var confirmed = flags.Contains(ConfirmArgument);
        var requiredValueCount = prepareOnly ? 5 : 6;
        if (!flags.Contains(GateArgument) || prepareOnly == confirmed ||
            values.Count != requiredValueCount ||
            !values.ContainsKey(GateIdArgument) ||
            !values.ContainsKey(TargetArgument) ||
            !values.ContainsKey(ExpectedTurnArgument) ||
            !values.ContainsKey(RestoreArgument) ||
            !values.ContainsKey(DataDirectoryArgument) ||
            prepareOnly == values.ContainsKey(AuthorizationDigestArgument))
        {
            throw new ArgumentException(
                "The automatic-recovery gate requires exactly one prepare or confirm mode and its exact values.");
        }

        var gateId = NormalizeId(values[GateIdArgument], GateIdArgument);
        var targetThreadId = NormalizeId(values[TargetArgument], TargetArgument);
        var expectedTurnId = NormalizeId(values[ExpectedTurnArgument], ExpectedTurnArgument);
        var restoreThreadId = NormalizeId(values[RestoreArgument], RestoreArgument);
        if (string.Equals(targetThreadId, restoreThreadId, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The recovery target and restore task must be distinct.");
        }

        var dataDirectory = NormalizeDataDirectory(values[DataDirectoryArgument], gateId);
        var authorizationDigest = prepareOnly
            ? null
            : NormalizeSha256(values[AuthorizationDigestArgument], AuthorizationDigestArgument);
        return new AutomaticRecoveryExistingConversationLiveGateOptions(
            prepareOnly,
            gateId,
            targetThreadId,
            expectedTurnId,
            restoreThreadId,
            dataDirectory,
            authorizationDigest);
    }

    internal static AutomaticRecoveryLiveGatePlan BuildPlan(
        AutomaticRecoveryExistingConversationLiveGateOptions options,
        ThreadSummary target,
        TurnSnapshot failedTurn,
        RecoveryDecision decision,
        AppSettings settings,
        string settingsSha256,
        DateTimeOffset preparedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(failedTurn);
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(settings);
        if (!string.Equals(target.Id, options.TargetThreadId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(failedTurn.Id, options.ExpectedFailedTurnId, StringComparison.OrdinalIgnoreCase) ||
            target.IsArchived || target.IsEphemeral || target.IsSubAgent ||
            decision.Action == RecoveryActionKind.None ||
            !settings.AutomaticRecoveryEnabled ||
            !settings.GlobalProtectionEnabled || settings.MonitorOnly || settings.IncludeSubAgents ||
            !settings.ThreadProtectionEnabled.TryGetValue(target.Id, out var selected) || !selected ||
            settings.SettingsGeneration < 1)
        {
            throw new InvalidOperationException("The automatic-recovery gate plan is not authorized.");
        }

        var classified = new RecoveryClassifier().Classify(failedTurn);
        if (classified.Action != decision.Action || classified.Health != decision.Health)
        {
            throw new InvalidOperationException("The recovery decision does not match the current failed turn.");
        }

        var dispatchMessage = decision.Action is
            RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue
            ? RecoveryClassifier.NormalizeRecoveryInput(failedTurn.UserText)
            : SettingsService.NormalizeContinueMessage("continue");
        var operationId = AppServerClient.CreateRecoveryMessageId(
            target.Id,
            failedTurn.Id,
            decision.Action);
        return new AutomaticRecoveryLiveGatePlan(
            options.GateId,
            options.TargetThreadId,
            options.ExpectedFailedTurnId,
            options.RestoreThreadId,
            decision.Action,
            operationId,
            operationId,
            RecoveryService.BuildRecoveryPayloadHash(decision.Action, dispatchMessage),
            ComputeFailedTurnEvidenceDigest(failedTurn),
            ComputeTargetIdentityDigest(target),
            target.UpdatedAt,
            settings.SettingsGeneration,
            NormalizeSha256(settingsSha256, nameof(settingsSha256)),
            preparedAtUtc.ToUniversalTime(),
            preparedAtUtc.ToUniversalTime() + AuthorizationLifetime);
    }

    internal static async Task<int> RunAsync(string[] arguments)
    {
        AutomaticRecoveryExistingConversationLiveGateOptions options;
        try
        {
            options = Parse(arguments);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or IOException or
                UnauthorizedAccessException or NotSupportedException or Win32Exception)
        {
            Console.WriteLine("AUTOMATIC_RECOVERY_LIVE_GATE_FAILED code=argument-matrix-invalid");
            return 2;
        }

        using var timeout = new CancellationTokenSource(ExecutionTimeout);
        try
        {
            return options.PrepareOnly
                ? await PrepareAsync(options, timeout.Token).ConfigureAwait(false)
                : await ConfirmAsync(options, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine(
                "AUTOMATIC_RECOVERY_LIVE_GATE_STOPPED code=bounded-timeout confirmMode=" +
                (!options.PrepareOnly).ToString(CultureInfo.InvariantCulture));
            return 3;
        }
        catch (AutomaticRecoveryLiveGateException exception)
        {
            Console.WriteLine(
                "AUTOMATIC_RECOVERY_LIVE_GATE_FAILED code=" + exception.Code + " confirmMode=" +
                (!options.PrepareOnly).ToString(CultureInfo.InvariantCulture));
            return 1;
        }
        catch (Exception exception)
        {
            Console.WriteLine(
                "AUTOMATIC_RECOVERY_LIVE_GATE_FAILED code=unexpected-" +
                GuardianLog.SanitizeIdentifier(exception.GetType().Name) + " confirmMode=" +
                (!options.PrepareOnly).ToString(CultureInfo.InvariantCulture));
            return 1;
        }
    }

    private static async Task<int> PrepareAsync(
        AutomaticRecoveryExistingConversationLiveGateOptions options,
        CancellationToken cancellationToken)
    {
        ValidateExecutionEnvironment(options, requireFreshDirectory: true);
        EnsureNoGuardianProcess();
        DataDirectorySafety.CreateProtectedDirectory(options.DataDirectory);
        using var log = new GuardianLog(options.DataDirectory);
        await using var appServer = new AppServerClient(new CodexCliLocator(), log);
        var localHistory = new LocalConversationHistoryReader();
        var evidence = await ReadExactFailedTargetAsync(
                appServer,
                localHistory,
                options.TargetThreadId,
                options.ExpectedFailedTurnId,
                cancellationToken)
            .ConfigureAwait(false);
        var settingsService = new SettingsService(
            options.DataDirectory,
            monitoringEnabledAfterNormalization: false);
        var settings = new AppSettings
        {
            MonitoringEnabled = false,
            MonitorOnly = false,
            AutomaticRecoveryEnabled = true,
            GlobalProtectionEnabled = true,
            IncludeSubAgents = false,
            ProtectNewThreadsByDefault = false,
            MinimizeToTray = false,
            StartWithWindows = false
        };
        settings.ThreadEnabled[evidence.Thread.Id] = true;
        settings.ThreadProtectionEnabled[evidence.Thread.Id] = true;
        await settingsService.SaveAsync(settings, cancellationToken).ConfigureAwait(false);
        var committedSettings = await settingsService.LoadAsync(cancellationToken).ConfigureAwait(false);
        var settingsSha256 = ComputeFileSha256(settingsService.SettingsPath);
        var plan = BuildPlan(
            options,
            evidence.Thread,
            evidence.FailedTurn,
            evidence.Decision,
            committedSettings,
            settingsSha256,
            DateTimeOffset.UtcNow);
        await EnsureStableClientIdAbsentAsync(
                appServer,
                plan.TargetThreadId,
                plan.ClientMessageId,
                cancellationToken)
            .ConfigureAwait(false);
        var journal = new RecoveryOperationJournal(options.DataDirectory);
        var existing = await journal.FindAsync(
                plan.TargetThreadId,
                plan.ExpectedFailedTurnId,
                cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            throw new AutomaticRecoveryLiveGateException("recovery-operation-already-exists");
        }

        var store = new AutomaticRecoveryLiveGateManifestStore(options.DataDirectory);
        var manifest = store.CreatePrepared(plan);
        var authorizationDigest = AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(plan);
        Console.WriteLine(
            "AUTOMATIC_RECOVERY_LIVE_GATE_PREPARED gate=" + plan.GateId +
            " target=" + plan.TargetThreadId +
            " failedTurn=" + plan.ExpectedFailedTurnId +
            " action=" + plan.Action +
            " operation=" + plan.OperationId +
            " client=" + plan.ClientMessageId +
            " payload=" + plan.PayloadDigest +
            " evidence=" + plan.FailedTurnEvidenceDigest +
            " targetIdentity=" + plan.TargetIdentityDigest +
            " targetUpdatedAt=" + plan.TargetUpdatedAt.ToString(CultureInfo.InvariantCulture) +
            " policyGeneration=" + plan.SettingsGeneration.ToString(CultureInfo.InvariantCulture) +
            " settings=" + plan.SettingsSha256 +
            " expires=" + plan.ExpiresAtUtc.ToString("O", CultureInfo.InvariantCulture) +
            " authorization=" + authorizationDigest +
            " manifestGeneration=" + manifest.Generation.ToString(CultureInfo.InvariantCulture) +
            " priorState=Missing realSend=False");
        return 0;
    }

    private static async Task<int> ConfirmAsync(
        AutomaticRecoveryExistingConversationLiveGateOptions options,
        CancellationToken cancellationToken)
    {
        ValidateExecutionEnvironment(options, requireFreshDirectory: false);
        EnsureNoGuardianProcess();
        var store = new AutomaticRecoveryLiveGateManifestStore(options.DataDirectory);
        var prepared = store.Read();
        ValidateManifestBinding(options, prepared);
        if (prepared.State != AutomaticRecoveryLiveGateAuthorizationState.Prepared ||
            prepared.Plan.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            throw new AutomaticRecoveryLiveGateException("authorization-not-current");
        }

        var authorizationDigest = options.AuthorizationDigest!;
        var platform = new WindowsDesktopThreadOwnerActivationPlatform();
        var restored = false;
        var journal = new RecoveryOperationJournal(options.DataDirectory);
        using var executionLease = AcquireExecutionLease();
        _ = store.Transition(
            AutomaticRecoveryLiveGateAuthorizationState.Prepared,
            AutomaticRecoveryLiveGateAuthorizationState.Armed,
            authorizationDigest);
        try
        {
            using var log = new GuardianLog(options.DataDirectory);
            await using var appServer = new AppServerClient(new CodexCliLocator(), log);
            await using var desktop = new DesktopIpcClient(log);
            await using var windowsObservation = new WindowsCodexInteractionHook(log);
            if (!windowsObservation.Start())
            {
                throw new AutomaticRecoveryLiveGateException("windows-composer-observer-unavailable");
            }

            var settingsService = new SettingsService(
                options.DataDirectory,
                monitoringEnabledAfterNormalization: false);
            var settings = await settingsService.LoadAsync(cancellationToken).ConfigureAwait(false);
            ValidateSettingsAuthority(prepared.Plan, settings, settingsService.SettingsPath);
            await desktop.EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            if (!await desktop.ProbeNativeDesktopChannelAsync(cancellationToken).ConfigureAwait(false) ||
                !desktop.IsNativeChannelAvailable)
            {
                throw new AutomaticRecoveryLiveGateException("stock-owner-channel-unavailable");
            }

            var ownerActivator = new DesktopThreadOwnerActivator(desktop, log);
            await ownerActivator.WaitForMinimumIdleAsync(cancellationToken).ConfigureAwait(false);
            platform.OpenThread(options.TargetThreadId);
            await Task.Delay(TargetPresentationDelay, cancellationToken).ConfigureAwait(false);
            var owner = await ownerActivator.EnsureOwnerAsync(
                    options.TargetThreadId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!owner.IsAvailable)
            {
                throw new AutomaticRecoveryLiveGateException(
                    "target-owner-" + GuardianLog.SanitizeIdentifier(owner.Status.ToString()));
            }

            var evidence = await ReadExactFailedTargetAsync(
                    appServer,
                    new LocalConversationHistoryReader(),
                    options.TargetThreadId,
                    options.ExpectedFailedTurnId,
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateCurrentEvidence(prepared.Plan, evidence, settings);
            await ValidateOwnerSnapshotAsync(
                    desktop,
                    options.TargetThreadId,
                    evidence.FailedTurn,
                    cancellationToken)
                .ConfigureAwait(false);

            var composer = await windowsObservation.CheckAsync(
                    options.TargetThreadId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (composer.Status != RecoveryInterferenceStatus.Clear)
            {
                throw new AutomaticRecoveryLiveGateException(
                    composer.Status == RecoveryInterferenceStatus.Editing
                        ? "target-composer-editing"
                        : "target-composer-unknown");
            }

            if (await journal.FindAsync(
                    prepared.Plan.TargetThreadId,
                    prepared.Plan.ExpectedFailedTurnId,
                    cancellationToken).ConfigureAwait(false) is not null)
            {
                throw new AutomaticRecoveryLiveGateException("recovery-operation-not-pristine");
            }

            await EnsureStableClientIdAbsentAsync(
                    appServer,
                    prepared.Plan.TargetThreadId,
                    prepared.Plan.ClientMessageId,
                    cancellationToken)
                .ConfigureAwait(false);

            var beforeTurns = await appServer.ReadRecentTurnsAsync(
                    options.TargetThreadId,
                    20,
                    cancellationToken)
                .ConfigureAwait(false);
            var policyAuthority = new AutomaticRecoveryLiveGatePolicyAuthority(
                store,
                authorizationDigest,
                settingsService.SettingsPath,
                prepared.Plan.SettingsSha256);
            var semanticCapabilities =
                new InstalledCodexStructuredInputCapabilityProvider(settings.AttachmentLimits);
            var threadActions = new ThreadActionCoordinator();
            var recovery = ProductionRecoveryServiceFactory.CreateLive(
                appServer,
                desktop,
                ownerActivator,
                journal,
                log,
                windowsObservation,
                semanticCapabilities,
                replayAuthority: null,
                threadActions,
                settings);
            var result = await recovery.ExecuteAsync(
                    evidence.Thread,
                    evidence.FailedTurn,
                    evidence.Decision,
                    "continue",
                    includeSubAgents: false,
                    scopeGeneration: recovery.BeginScopeValidationGeneration(),
                    isDispatchAllowed: policyAuthority.IsCurrent,
                    cancellationToken)
                .ConfigureAwait(false);
            var operation = await journal.FindAsync(
                    prepared.Plan.TargetThreadId,
                    prepared.Plan.ExpectedFailedTurnId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!result.Success || result.NewTurnId is null || operation is not
                {
                    State: RecoveryOperationState.Confirmed,
                    AttemptCount: 1,
                    NewTurnId: not null
                } ||
                !string.Equals(operation.OperationId, prepared.Plan.OperationId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(operation.ClientMessageId, prepared.Plan.ClientMessageId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(operation.NewTurnId, result.NewTurnId, StringComparison.OrdinalIgnoreCase))
            {
                throw new AutomaticRecoveryLiveGateException("recovery-not-durably-confirmed");
            }

            var readback = await WaitForReadbackAsync(
                    appServer,
                    prepared.Plan.TargetThreadId,
                    prepared.Plan.ClientMessageId,
                    result.NewTurnId,
                    cancellationToken)
                .ConfigureAwait(false);
            var afterTurns = await appServer.ReadRecentTurnsAsync(
                    options.TargetThreadId,
                    20,
                    cancellationToken)
                .ConfigureAwait(false);
            var beforeIds = beforeTurns.Select(turn => turn.Id).ToHashSet(
                StringComparer.OrdinalIgnoreCase);
            var newIds = afterTurns
                .Select(turn => turn.Id)
                .Where(id => !beforeIds.Contains(id))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (newIds.Length != 1 ||
                !string.Equals(newIds[0], result.NewTurnId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(readback.Id, result.NewTurnId, StringComparison.OrdinalIgnoreCase) ||
                !afterTurns.Any(turn => string.Equals(
                    turn.Id,
                    prepared.Plan.ExpectedFailedTurnId,
                    StringComparison.OrdinalIgnoreCase)))
            {
                throw new AutomaticRecoveryLiveGateException("turn-count-not-exactly-once");
            }

            var confirmed = store.Transition(
                AutomaticRecoveryLiveGateAuthorizationState.Armed,
                AutomaticRecoveryLiveGateAuthorizationState.Confirmed,
                authorizationDigest,
                result.NewTurnId);
            Console.WriteLine(
                "AUTOMATIC_RECOVERY_LIVE_GATE_CONFIRMED gate=" + prepared.Plan.GateId +
                " target=" + prepared.Plan.TargetThreadId +
                " failedTurn=" + prepared.Plan.ExpectedFailedTurnId +
                " action=" + prepared.Plan.Action +
                " operation=" + operation.OperationId +
                " client=" + operation.ClientMessageId +
                " generatedTurn=" + operation.NewTurnId +
                " readbackTurn=" + readback.Id +
                " attempts=" + operation.AttemptCount.ToString(CultureInfo.InvariantCulture) +
                " authorizationState=" + confirmed.State +
                " newTurns=1 realSend=True");
            return 0;
        }
        catch
        {
            CloseConsumedAuthorization(store, journal, prepared.Plan, authorizationDigest);
            throw;
        }
        finally
        {
            try
            {
                platform.OpenThread(options.RestoreThreadId);
                await Task.Delay(TargetPresentationDelay, CancellationToken.None).ConfigureAwait(false);
                restored = true;
            }
            catch
            {
            }

            Console.WriteLine(
                "AUTOMATIC_RECOVERY_LIVE_GATE_RESTORE restored=" +
                restored.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static void CloseConsumedAuthorization(
        AutomaticRecoveryLiveGateManifestStore store,
        RecoveryOperationJournal journal,
        AutomaticRecoveryLiveGatePlan plan,
        string authorizationDigest)
    {
        try
        {
            var operation = journal.FindAsync(plan.TargetThreadId, plan.ExpectedFailedTurnId)
                .GetAwaiter()
                .GetResult();
            var state = operation?.State is RecoveryOperationState.Dispatching or
                RecoveryOperationState.Uncertain or RecoveryOperationState.Accepted or
                RecoveryOperationState.Confirmed
                ? AutomaticRecoveryLiveGateAuthorizationState.Uncertain
                : AutomaticRecoveryLiveGateAuthorizationState.Closed;
            _ = store.Transition(
                AutomaticRecoveryLiveGateAuthorizationState.Armed,
                state,
                authorizationDigest);
        }
        catch
        {
            // An Armed manifest is already consumed and therefore remains fail-closed.
        }
    }

    private static async Task<AutomaticRecoveryLiveGateTargetEvidence> ReadExactFailedTargetAsync(
        AppServerClient appServer,
        LocalConversationHistoryReader localHistory,
        string targetThreadId,
        string expectedFailedTurnId,
        CancellationToken cancellationToken)
    {
        var thread = await appServer.ReadThreadForRecoveryAsync(targetThreadId, cancellationToken)
            .ConfigureAwait(false);
        var remote = await appServer.ReadLatestTurnWithFullItemsAsync(targetThreadId, cancellationToken)
            .ConfigureAwait(false);
        var local = await localHistory.ReadLatestTerminalEventAsync(targetThreadId, cancellationToken)
            .ConfigureAwait(false);
        var failedTurn = LocalConversationHistoryReader.ReconcileLatestTurn(remote, local);
        if (!string.Equals(thread.Id, targetThreadId, StringComparison.OrdinalIgnoreCase) ||
            thread.IsArchived || thread.IsEphemeral || thread.IsSubAgent ||
            remote is null || local is null || failedTurn is null ||
            !string.Equals(remote.Id, expectedFailedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(local.TurnId, expectedFailedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(failedTurn.Id, expectedFailedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !failedTurn.HasConfirmedLocalTerminal ||
            RecoveryService.ValidateLatestTurn(failedTurn, expectedFailedTurnId) is not null ||
            RecoveryService.ValidateTargetThreadEligibility(
                targetThreadId,
                includeSubAgents: false,
                thread) is not null)
        {
            throw new AutomaticRecoveryLiveGateException("exact-failed-target-unavailable");
        }

        var decision = new RecoveryClassifier().Classify(failedTurn);
        if (decision.Action == RecoveryActionKind.None)
        {
            throw new AutomaticRecoveryLiveGateException("failed-turn-not-recoverable");
        }

        return new AutomaticRecoveryLiveGateTargetEvidence(thread, failedTurn, decision);
    }

    private static async Task ValidateOwnerSnapshotAsync(
        DesktopIpcClient desktop,
        string targetThreadId,
        TurnSnapshot failedTurn,
        CancellationToken cancellationToken)
    {
        var ownerState = await desktop.AcquireThreadOwnerStateGuardAsync(
                targetThreadId,
                cancellationToken)
            .ConfigureAwait(false);
        if (!ownerState.IsAvailable)
        {
            throw new AutomaticRecoveryLiveGateException("target-owner-snapshot-unavailable");
        }

        await using var ownerGuard = ownerState.Guard!;
        if (!ownerGuard.IsCurrent ||
            RecoveryService.ValidateOwnerStateSnapshot(ownerGuard.Snapshot, failedTurn) is not null)
        {
            throw new AutomaticRecoveryLiveGateException("target-owner-state-mismatch");
        }
    }

    private static void ValidateManifestBinding(
        AutomaticRecoveryExistingConversationLiveGateOptions options,
        AutomaticRecoveryLiveGateManifest manifest)
    {
        var plan = manifest.Plan;
        if (!string.Equals(plan.GateId, options.GateId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.TargetThreadId, options.TargetThreadId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.ExpectedFailedTurnId, options.ExpectedFailedTurnId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.RestoreThreadId, options.RestoreThreadId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(plan),
                options.AuthorizationDigest,
                StringComparison.Ordinal))
        {
            throw new AutomaticRecoveryLiveGateException("authorization-binding-mismatch");
        }
    }

    private static void ValidateSettingsAuthority(
        AutomaticRecoveryLiveGatePlan plan,
        AppSettings settings,
        string settingsPath)
    {
        if (settings.ReadStatus != SettingsReadStatus.Healthy ||
            settings.SettingsGeneration != plan.SettingsGeneration ||
            !settings.AutomaticRecoveryEnabled ||
            !settings.GlobalProtectionEnabled || settings.MonitorOnly || settings.IncludeSubAgents ||
            !settings.ThreadProtectionEnabled.TryGetValue(plan.TargetThreadId, out var selected) ||
            !selected ||
            !string.Equals(ComputeFileSha256(settingsPath), plan.SettingsSha256, StringComparison.Ordinal))
        {
            throw new AutomaticRecoveryLiveGateException("policy-authority-mismatch");
        }
    }

    private static void ValidateCurrentEvidence(
        AutomaticRecoveryLiveGatePlan plan,
        AutomaticRecoveryLiveGateTargetEvidence evidence,
        AppSettings settings)
    {
        var current = BuildPlan(
            new AutomaticRecoveryExistingConversationLiveGateOptions(
                PrepareOnly: false,
                plan.GateId,
                plan.TargetThreadId,
                plan.ExpectedFailedTurnId,
                plan.RestoreThreadId,
                DataDirectory: DataRoot,
                AuthorizationDigest: AutomaticRecoveryLiveGateManifestStore.ComputeAuthorizationDigest(plan)),
            evidence.Thread,
            evidence.FailedTurn,
            evidence.Decision,
            settings,
            plan.SettingsSha256,
            plan.PreparedAtUtc);
        if (current.Action != plan.Action || current.OperationId != plan.OperationId ||
            current.ClientMessageId != plan.ClientMessageId || current.PayloadDigest != plan.PayloadDigest ||
            current.FailedTurnEvidenceDigest != plan.FailedTurnEvidenceDigest ||
            current.TargetIdentityDigest != plan.TargetIdentityDigest ||
            current.TargetUpdatedAt != plan.TargetUpdatedAt)
        {
            throw new AutomaticRecoveryLiveGateException("prepared-evidence-drift");
        }
    }

    private static async Task<TurnSnapshot> WaitForReadbackAsync(
        AppServerClient appServer,
        string targetThreadId,
        string clientMessageId,
        string expectedNewTurnId,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + ReadbackTimeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var matches = (await appServer.ReadRecentTurnsAsync(
                    targetThreadId,
                    20,
                    cancellationToken).ConfigureAwait(false))
                .Where(turn =>
                    turn.UserMessageClientIds?.Contains(
                        clientMessageId,
                        StringComparer.OrdinalIgnoreCase) == true)
                .Take(2)
                .ToArray();
            if (matches.Length == 1 &&
                string.Equals(matches[0].Id, expectedNewTurnId, StringComparison.OrdinalIgnoreCase))
            {
                return matches[0];
            }

            if (matches.Length > 1)
            {
                throw new AutomaticRecoveryLiveGateException("stable-client-id-not-unique");
            }

            await Task.Delay(ReadbackPollInterval, cancellationToken).ConfigureAwait(false);
        }

        throw new AutomaticRecoveryLiveGateException("successor-readback-timeout");
    }

    private static async Task EnsureStableClientIdAbsentAsync(
        AppServerClient appServer,
        string targetThreadId,
        string clientMessageId,
        CancellationToken cancellationToken)
    {
        var matches = (await appServer.ReadRecentTurnsAsync(
                targetThreadId,
                20,
                cancellationToken).ConfigureAwait(false))
            .Count(turn => turn.UserMessageClientIds?.Contains(
                clientMessageId,
                StringComparer.OrdinalIgnoreCase) == true);
        if (matches != 0)
        {
            throw new AutomaticRecoveryLiveGateException("stable-client-id-already-observed");
        }
    }

    internal static IDisposable AcquireExecutionLease()
    {
        var semaphore = new Semaphore(
            initialCount: 1,
            maximumCount: 1,
            ExecutionSemaphoreName);
        try
        {
            if (!semaphore.WaitOne(TimeSpan.Zero))
            {
                throw new AutomaticRecoveryLiveGateException("another-recovery-gate-is-running");
            }

            return new SemaphoreLease(semaphore);
        }
        catch
        {
            semaphore.Dispose();
            throw;
        }
    }

    private static void ValidateExecutionEnvironment(
        AutomaticRecoveryExistingConversationLiveGateOptions options,
        bool requireFreshDirectory)
    {
        var exists = Directory.Exists(options.DataDirectory) || File.Exists(options.DataDirectory);
        if (requireFreshDirectory == exists)
        {
            throw new AutomaticRecoveryLiveGateException(
                requireFreshDirectory ? "data-directory-not-fresh" : "data-directory-missing");
        }

        if (Directory.Exists(options.DataDirectory))
        {
            DataDirectorySafety.Revalidate(options.DataDirectory);
        }
    }

    private static void EnsureNoGuardianProcess()
    {
        var processes = System.Diagnostics.Process.GetProcessesByName("CodexGuardian");
        try
        {
            if (processes.Any(process => process.Id != Environment.ProcessId))
            {
                throw new AutomaticRecoveryLiveGateException("guardian-process-running");
            }
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }
    }

    private static string NormalizeDataDirectory(string value, string gateId)
    {
        var normalized = DataDirectorySafety.NormalizeAndValidate(value);
        var root = Path.GetFullPath(DataRoot).TrimEnd(Path.DirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        if (!normalized.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(normalized.TrimEnd(Path.DirectorySeparatorChar)),
                gateId,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The automatic-recovery gate data directory must be a gate-named D-drive child.",
                nameof(value));
        }

        return normalized;
    }

    private static string NormalizeId(string value, string parameterName)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("A non-empty UUID is required.", parameterName);
        }

        return parsed.ToString("D");
    }

    private static string NormalizeSha256(string value, string parameterName)
    {
        value = value?.Trim().ToUpperInvariant() ?? string.Empty;
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("An uppercase SHA-256 digest is required.", parameterName);
        }

        return value;
    }

    private static string ComputeFileSha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static string ComputeFailedTurnEvidenceDigest(TurnSnapshot turn) =>
        ComputeDigest(string.Join(
            "\n",
            turn.Id,
            turn.Status,
            turn.ErrorCode,
            turn.HttpStatusCode,
            turn.ErrorMessage,
            turn.HasAttachments,
            turn.RawUserInputJson ?? turn.UserText,
            turn.OutputFingerprint,
            turn.HasConfirmedLocalTerminal,
            turn.HasCompleteItemEvidence,
            turn.HasAssistantOutput,
            turn.HasWorkOutput,
            turn.HasFinalAssistantOutput,
            turn.HasCommentaryOutput,
            turn.HasReasoningOutput,
            turn.HasToolActivity,
            turn.HasAmbiguousActivity));

    private static string ComputeTargetIdentityDigest(ThreadSummary thread) =>
        ComputeDigest(string.Join(
            "\n",
            thread.Id,
            thread.Cwd,
            thread.Source,
            thread.CreatedAt,
            thread.IsSubAgent,
            thread.IsEphemeral,
            thread.IsArchived));

    private static string ComputeDigest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private sealed class SemaphoreLease(Semaphore semaphore) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            semaphore.Release();
            semaphore.Dispose();
        }
    }

}

internal sealed record AutomaticRecoveryLiveGateTargetEvidence(
    ThreadSummary Thread,
    TurnSnapshot FailedTurn,
    RecoveryDecision Decision);

internal sealed class AutomaticRecoveryLiveGateException(string code) : Exception(code)
{
    internal string Code { get; } = GuardianLog.SanitizeIdentifier(code);
}
