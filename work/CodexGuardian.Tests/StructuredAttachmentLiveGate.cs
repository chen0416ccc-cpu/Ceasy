using CodexGuardian.Models;
using CodexGuardian.Services;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

internal static class StructuredAttachmentLiveGate
{
    internal const string Argument = "--structured-attachment-live-gate";
    private const string Message = "\u67e5\u770b\u9644\u4ef6\u56fe\u7247\uff0c\u53ea\u56de\u590d\u5176\u4e2d\u7684\u516d\u4f4d\u6570\u5b57\uff0c\u4e0d\u8c03\u7528\u5de5\u5177\u6216\u4fee\u6539\u6587\u4ef6\u3002";
    private sealed record Options(bool Prepare, string Target, string Turn, string Restore, string Directory, string Image);
    private sealed record Plan(string Target, string Turn, string Restore, string ImageHash,
        string SettingsHash, string PayloadDigest, DateTimeOffset ExpiresAt, FollowUpMessageDefinition Message);

    internal static bool IsRequested(string[] args) => args.Contains(Argument, StringComparer.Ordinal);

    internal static async Task<int> RunAsync(string[] args)
    {
        try
        {
            var options = Parse(args);
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            using var process = Process.GetCurrentProcess();
            var conflicts = Process.GetProcessesByName("CodexGuardian")
                .Concat(Process.GetProcessesByName("CodexGuardian.Tests")).ToArray();
            try { Require(conflicts.All(p => p.Id == process.Id), "process-conflict"); }
            finally { foreach (var conflict in conflicts) conflict.Dispose(); }
            if (options.Prepare) await PrepareAsync(options, timeout.Token);
            else await ConfirmAsync(options, timeout.Token);
            return 0;
        }
        catch (Exception exception)
        {
            Console.WriteLine("ATTACHMENT_LIVE_GATE_FAILED code=" +
                (exception is GateException gate ? gate.Message : exception.GetType().Name));
            return 1;
        }
    }

    private static Options Parse(string[] args)
    {
        Require(args.Length == 12 && args[0] == Argument &&
            args[1] is "--prepare-only" or "--confirm-real-attachment-send", "arguments");
        var names = new[] { "--target-thread-id", "--expected-turn-id", "--restore-thread-id", "--data-directory", "--attachment-path" };
        for (var index = 0; index < names.Length; index++) Require(args[2 + index * 2] == names[index], "arguments");
        string Id(string value) => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty
            ? id.ToString("D") : throw new GateException("identity");
        var target = Id(args[3]);
        var turn = Id(args[5]);
        var restore = Id(args[7]);
        Require(target != restore, "restore-target");
        var directory = DataDirectorySafety.NormalizeAndValidate(args[9]);
        Require(directory.StartsWith(@"D:\CodexData\CodexGuardian\", StringComparison.OrdinalIgnoreCase), "data-root");
        var temp = Environment.GetEnvironmentVariable("TEMP");
        Require(temp is not null && temp.StartsWith(@"D:\CodexTemp\CodexGuardian\", StringComparison.OrdinalIgnoreCase) &&
            temp == Environment.GetEnvironmentVariable("TMP"), "temp-root");
        var image = Path.GetFullPath(args[11]);
        Require(image.StartsWith(@"D:\CodexData\CodexGuardian\", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(Path.GetExtension(image), ".png", StringComparison.OrdinalIgnoreCase), "image-root");
        return new Options(args[1] == "--prepare-only", target, turn, restore, directory, image);
    }

    private static async Task PrepareAsync(Options options, CancellationToken token)
    {
        Require(!Directory.Exists(options.Directory), "data-not-fresh");
        DataDirectorySafety.CreateProtectedDirectory(options.Directory);
        using var log = new GuardianLog(options.Directory);
        await using var reader = new AppServerClient(new CodexCliLocator(), log);
        _ = await ReadTargetAsync(reader, options, token);
        var settingsService = new SettingsService(options.Directory, monitoringEnabledAfterNormalization: false);
        var limits = new AttachmentLimitSettings { MaximumAttachmentsPerMessage = 1, MaximumBytesPerFile = 1024 * 1024,
            MaximumBytesPerMessage = 1024 * 1024, MaximumLibraryBytes = 4 * 1024 * 1024 };
        var provider = new InstalledCodexStructuredInputCapabilityProvider(limits);
        var capabilities = await provider.ReadAsync(token);
        Require(capabilities.State == StructuredInputCapabilityState.Supported &&
            capabilities.SupportedInputKinds.Contains("local_image"), "image-capability");
        var store = new ManagedAttachmentStore(options.Directory);
        var imported = await store.ImportAsync(options.Image, limits, token);
        Require(imported.DetectedType == "image/png" && imported.ByteLength <= 1024 * 1024, "image-type");
        var reference = new PresetAttachmentReference
        {
            Id = Guid.NewGuid().ToString("D"), ContentId = imported.ContentId, ByteLength = imported.ByteLength,
            DetectedType = imported.DetectedType, OwnerInputKind = "local_image", OriginalFileName = "test-image.png", Order = 0
        };
        var definition = new FollowUpMessageDefinition
        {
            Id = Guid.NewGuid().ToString("D"), Message = Message, Attachments = [reference],
            Trigger = FollowUpTriggerKind.AfterNormalCompletion, MaximumErrorRetries = 0, RetryIndefinitely = false
        };
        var settings = new AppSettings
        {
            MonitoringEnabled = false, MonitorOnly = true, AutomaticRecoveryEnabled = false,
            GlobalProtectionEnabled = true, MinimizeToTray = false, StartWithWindows = false,
            AttachmentLimits = limits
        };
        settings.ThreadEnabled[options.Target] = true;
        settings.ThreadProtectionEnabled[options.Target] = true;
        settings.ThreadFollowUps[options.Target] = new ThreadFollowUpSettings
        {
            IsEnabled = true, CompletionAnchorTurnId = options.Turn, Messages = [definition]
        };
        await settingsService.SaveAsync(settings, token);
        var plan = new Plan(options.Target, options.Turn, options.Restore, HashFile(options.Image),
            HashFile(settingsService.SettingsPath), StructuredPresetPayload.Create(Message, [reference]).PayloadDigest,
            DateTimeOffset.UtcNow.AddMinutes(20), definition);
        var path = Path.Combine(options.Directory, "attachment-plan.json");
        DataDirectorySafety.RevalidateWriteTarget(options.Directory, path);
        await using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
        {
            await JsonSerializer.SerializeAsync(file, plan, cancellationToken: token);
            file.Flush(flushToDisk: true);
        }
        Console.WriteLine("ATTACHMENT_LIVE_GATE_PREPARED target=" + options.Target + " expectedTurn=" + options.Turn +
            " content=" + imported.ContentId + " bytes=" + imported.ByteLength + " payload=" + plan.PayloadDigest + " realSend=False");
    }

    private static async Task ConfirmAsync(Options options, CancellationToken token)
    {
        DataDirectorySafety.Revalidate(options.Directory);
        var planPath = Path.Combine(options.Directory, "attachment-plan.json");
        Require(new FileInfo(planPath).Length <= 64 * 1024, "plan-size");
        var plan = JsonSerializer.Deserialize<Plan>(await File.ReadAllTextAsync(planPath, token)) ?? throw new GateException("plan");
        Require(plan.Target == options.Target && plan.Turn == options.Turn && plan.Restore == options.Restore &&
            plan.ExpiresAt > DateTimeOffset.UtcNow && plan.ImageHash == HashFile(options.Image), "plan-binding");
        var settings = new SettingsService(options.Directory, monitoringEnabledAfterNormalization: false);
        Require(plan.SettingsHash == HashFile(settings.SettingsPath), "settings-changed");
        var persisted = await settings.LoadAsync(token);
        Require(persisted.ReadStatus == SettingsReadStatus.Healthy && persisted.MonitorOnly && !persisted.AutomaticRecoveryEnabled &&
            !persisted.MonitoringEnabled && !persisted.KeepAliveEnabled && persisted.GlobalProtectionEnabled &&
            persisted.ThreadProtectionEnabled.Count == 1 && persisted.ThreadProtectionEnabled.TryGetValue(options.Target, out var allowed) && allowed &&
            persisted.ThreadFollowUps.Count == 1 && persisted.ThreadFollowUps.TryGetValue(options.Target, out var queue) && queue.IsEnabled &&
            queue.Messages.Count == 1 && queue.Messages[0].Id == plan.Message.Id && plan.Message.Message == Message &&
            plan.Message.Attachments.Count == 1 && plan.Message.Attachments[0].ContentId == plan.ImageHash,
            "policy-binding");
        var payload = StructuredPresetPayload.Create(plan.Message.Message, plan.Message.Attachments);
        Require(payload.PayloadDigest == plan.PayloadDigest &&
            StructuredPresetPayload.Create(persisted.ThreadFollowUps[options.Target].Messages[0].Message,
                persisted.ThreadFollowUps[options.Target].Messages[0].Attachments).PayloadDigest == payload.PayloadDigest, "payload-binding");
        using var log = new GuardianLog(options.Directory);
        await using var reader = new AppServerClient(new CodexCliLocator(), log);
        await using var desktop = new DesktopIpcClient(log);
        var activator = new DesktopThreadOwnerActivator(desktop, log);
        await using var observation = new WindowsCodexInteractionHook(log);
        Require(observation.Start(), "composer-observer");
        var platform = new WindowsDesktopThreadOwnerActivationPlatform();
        try
        {
            await activator.WaitForMinimumIdleAsync(token);
            platform.OpenThread(options.Target);
            await Task.Delay(1000, token);
            Require((await activator.EnsureOwnerAsync(options.Target, token)).IsAvailable, "target-owner");
            var (thread, turn) = await ReadTargetAsync(reader, options, token);
            var owner = await desktop.AcquireThreadOwnerStateGuardAsync(options.Target, token);
            Require(owner.IsAvailable, "owner-snapshot");
            await using (var guard = owner.Guard!)
                Require(guard.IsCurrent && FollowUpDispatchService.ValidateOwnerNormalCompletion(guard.Snapshot, options.Turn) is null, "owner-state");
            Require((await observation.CheckAsync(options.Target, token)).Status == RecoveryInterferenceStatus.Clear, "composer-active");
            var journal = new FollowUpOperationJournal(options.Directory);
            var provider = new InstalledCodexStructuredInputCapabilityProvider(persisted.AttachmentLimits);
            var store = new ManagedAttachmentStore(options.Directory);
            var presentation = new AttachmentPresentationLeaseService(options.Directory, store);
            var drafts = new AttachmentDraftAuthority();
            drafts.ReplaceVisibleDrafts(0, plan.Message.Attachments);
            var service = new FollowUpDispatchService(reader, desktop, activator, journal, log, observation,
                provider, store, presentation, drafts, new ThreadActionCoordinator());
            var before = await reader.ReadRecentTurnsAsync(options.Target, 20, token);
            var consumedPath = Path.Combine(options.Directory, "consumed");
            DataDirectorySafety.RevalidateWriteTarget(options.Directory, consumedPath);
            using (var consumed = new FileStream(consumedPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1, FileOptions.WriteThrough))
            {
                consumed.WriteByte(1);
                consumed.Flush(true);
            }
            bool PolicyCurrent()
            {
                try { return HashFile(settings.SettingsPath) == plan.SettingsHash && plan.ExpiresAt > DateTimeOffset.UtcNow; }
                catch { return false; }
            }
            var result = await service.ExecuteAsync(thread, turn, plan.Message, false, PolicyCurrent, token);
            Require(result.Success && result.NewTurnId is not null, "send-" + result.FailureKind);
            var record = (await journal.ReadAsync(token)).Records.Single();
            Require(record.State == FollowUpOperationState.Confirmed && record.AttemptCount == 1 &&
                record.NewTurnId == result.NewTurnId && record.AttachmentContentIds.SequenceEqual([plan.ImageHash]) &&
                record.PresentationLeaseId is not null, "journal-confirmation");
            TurnSnapshot? actual = null;
            for (var index = 0; index < 30; index++)
            {
                actual = await reader.ReadLatestTurnWithFullItemsAsync(options.Target, token);
                if (actual?.Id == result.NewTurnId && actual.HasAttachments &&
                    actual.UserMessageClientIds?.Contains(record.ClientMessageId, StringComparer.OrdinalIgnoreCase) == true) break;
                await Task.Delay(500, token);
            }
            Require(actual?.Id == result.NewTurnId && actual.HasAttachments && actual.HasCompleteItemEvidence &&
                actual.UserMessageClientIds?.Contains(record.ClientMessageId, StringComparer.OrdinalIgnoreCase) == true &&
                actual.RawUserInputJson is not null, "image-readback");
            using var input = JsonDocument.Parse(actual!.RawUserInputJson!);
            var images = input.RootElement.EnumerateArray().Where(item =>
                item.GetProperty("type").GetString() is "localImage" or "local_image").ToArray();
            Require(images.Length == 1 && images[0].TryGetProperty("path", out var path) &&
                Path.GetFullPath(path.GetString()!).StartsWith(options.Directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                HashFile(path.GetString()!) == plan.ImageHash, "image-bytes-readback");
            var after = await reader.ReadRecentTurnsAsync(options.Target, 20, token);
            var newTurns = after.Select(t => t.Id).Except(before.Select(t => t.Id), StringComparer.OrdinalIgnoreCase).ToArray();
            Require(newTurns.SequenceEqual([result.NewTurnId]), "turn-count");
            var repeat = await service.ExecuteAsync(thread, turn, plan.Message, false, PolicyCurrent, token);
            var afterRepeat = await reader.ReadRecentTurnsAsync(options.Target, 20, token);
            Require(repeat.Success && repeat.NewTurnId == result.NewTurnId &&
                afterRepeat.Select(t => t.Id).SequenceEqual(after.Select(t => t.Id)) &&
                (await journal.ReadAsync(token)).Records.Single().AttemptCount == 1, "duplicate-dispatch");
            Console.WriteLine("ATTACHMENT_LIVE_GATE_CONFIRMED target=" + options.Target + " turn=" + result.NewTurnId +
                " client=" + record.ClientMessageId + " content=" + plan.ImageHash +
                " attempts=1 attachments=1 newTurns=1 repeatedDispatch=False realSend=True");
        }
        finally
        {
            platform.OpenThread(options.Restore);
            Console.WriteLine("ATTACHMENT_LIVE_GATE_RESTORE requested=True");
        }
    }

    private static async Task<(ThreadSummary, TurnSnapshot)> ReadTargetAsync(AppServerClient reader, Options options, CancellationToken token)
    {
        var thread = await reader.ReadThreadForRecoveryAsync(options.Target, token);
        var remote = await reader.ReadLatestTurnWithFullItemsAsync(options.Target, token);
        var local = await new LocalConversationHistoryReader().ReadLatestTerminalEventAsync(options.Target, token);
        var turn = LocalConversationHistoryReader.ReconcileLatestTurn(remote, local);
        Require(thread.Id == options.Target && !thread.IsArchived && !thread.IsSubAgent && !thread.IsEphemeral &&
            turn?.Id == options.Turn && FollowUpQueuePlanner.IsNormalCompletion(turn), "target-not-normal");
        return (thread, turn!);
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
    private static void Require([DoesNotReturnIf(false)] bool condition, string code) { if (!condition) throw new GateException(code); }
    private sealed class GateException(string code) : Exception(code);
}
