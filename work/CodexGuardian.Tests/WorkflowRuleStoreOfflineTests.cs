using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class WorkflowRuleStoreOfflineTests
{
    private static readonly DateTimeOffset Activation =
        DateTimeOffset.Parse("2026-08-15T08:00:00Z");

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "workflow rule store round-trips canonical rules and truthful unavailable capability",
            TestRoundTripAsync,
            assert);
        await RunCaseAsync(
            "workflow rule store rejects cyclic replacement without overwriting authority",
            TestCycleReplacementRejectedAsync,
            assert);
        await RunCaseAsync(
            "workflow rule store backup recovery is conservative and blocks replacement",
            TestBackupRecoveryAsync,
            assert);
        await RunCaseAsync(
            "workflow rule store fails closed on corrupt and unsupported documents",
            TestCorruptAndUnsupportedAsync,
            assert);
        await RunCaseAsync(
            "workflow rule store restores the exact durable generation after a later save fails",
            TestDurableRollbackAsync,
            assert);
        await RunCaseAsync(
            "workflow rule rollback never overwrites a later durable generation",
            TestDurableRollbackRejectsLaterGenerationAsync,
            assert);
    }

    private static async Task TestRoundTripAsync()
    {
        var root = CreateRoot();
        var store = new WorkflowRuleStore(root);
        var existing = ScheduledSendRule(seed: 100, WorkflowDestinationKind.ExistingConversation);
        var unavailable = ScheduledSendRule(seed: 200, WorkflowDestinationKind.NewConversation);
        var saved = await store.SaveAsync([unavailable, existing]);
        var restarted = await new WorkflowRuleStore(root).ReadAsync();
        Ensure(
            saved.ReadStatus == WorkflowRuleStoreReadStatus.Healthy && saved.Generation == 1 &&
            saved.Rules.Select(rule => rule.RuleId).SequenceEqual(
                saved.Rules.Select(rule => rule.RuleId).Order(StringComparer.Ordinal)) &&
            saved.Validation.Issues.Count(issue =>
                issue.Code == WorkflowRuleValidationIssueCode.NewConversationUnavailable) == 1 &&
            restarted.ReadStatus == WorkflowRuleStoreReadStatus.Healthy &&
            restarted.Rules.Select(rule => rule.DefinitionDigest).SequenceEqual(
                saved.Rules.Select(rule => rule.DefinitionDigest)) &&
            File.Exists(store.BackupPath) == false &&
            new FileInfo(store.RulePath).Length <= WorkflowRuleStore.DefaultMaximumFileBytes,
            "workflow rule store lost canonical identity or unavailable-capability truth");
        var json = await File.ReadAllTextAsync(store.RulePath);
        Ensure(
            !json.Contains("prompt", StringComparison.OrdinalIgnoreCase) &&
            !json.Contains("attachmentPath", StringComparison.OrdinalIgnoreCase) &&
            !json.Contains("cwd", StringComparison.OrdinalIgnoreCase),
            "workflow rule store persisted forbidden task content or paths");
    }

    private static async Task TestCycleReplacementRejectedAsync()
    {
        var root = CreateRoot();
        var store = new WorkflowRuleStore(root);
        var baseline = ScheduledSendRule(seed: 300, WorkflowDestinationKind.ExistingConversation);
        await store.SaveAsync([baseline]);
        var bytes = File.ReadAllBytes(store.RulePath);
        var generation = (await store.ReadAsync()).Generation;

        var conversationA = Id(310);
        var conversationB = Id(311);
        var ruleA = CompletionSendRule(Id(312), conversationA, conversationB, Id(313));
        var ruleB = CompletionSendRule(Id(314), conversationB, conversationA, Id(315));
        await AssertThrowsAsync<InvalidOperationException>(() => store.SaveAsync([ruleA, ruleB]));
        var retained = await store.ReadAsync();
        Ensure(
            retained.Generation == generation && retained.Rules.Single().RuleId == baseline.RuleId &&
            File.ReadAllBytes(store.RulePath).SequenceEqual(bytes),
            "rejected workflow cycle overwrote the previous rule generation");
    }

    private static async Task TestBackupRecoveryAsync()
    {
        var root = CreateRoot();
        var store = new WorkflowRuleStore(root);
        var first = ScheduledSendRule(seed: 400, WorkflowDestinationKind.ExistingConversation);
        var second = ScheduledSendRule(seed: 500, WorkflowDestinationKind.ExistingConversation);
        await store.SaveAsync([first]);
        await store.SaveAsync([second]);
        Ensure(File.Exists(store.BackupPath), "workflow rule backup was not created");
        await File.WriteAllTextAsync(store.RulePath, "{");

        var recoveredStore = new WorkflowRuleStore(root);
        var recovered = await recoveredStore.ReadAsync();
        Ensure(
            recovered.ReadStatus == WorkflowRuleStoreReadStatus.RecoveredFromBackup &&
            recovered.RequiresConservativeRecovery && recovered.Generation == 1 &&
            recovered.Rules.Single().RuleId == first.RuleId,
            "workflow rule backup recovery did not retain the prior canonical generation");
        await AssertThrowsAsync<InvalidOperationException>(() => recoveredStore.SaveAsync([second]));
    }

    private static async Task TestCorruptAndUnsupportedAsync()
    {
        var corruptRoot = CreateRoot();
        Directory.CreateDirectory(corruptRoot);
        await File.WriteAllTextAsync(Path.Combine(corruptRoot, "workflow-rules.json"), "{");
        await File.WriteAllTextAsync(Path.Combine(corruptRoot, "workflow-rules.previous.json"), "{");
        await File.WriteAllBytesAsync(Path.Combine(corruptRoot, "workflow-rules.initialized"), [1]);
        var corrupt = await new WorkflowRuleStore(corruptRoot).ReadAsync();
        Ensure(
            corrupt.ReadStatus == WorkflowRuleStoreReadStatus.Corrupted &&
            corrupt.RequiresConservativeRecovery && corrupt.Rules.Count == 0,
            "corrupt workflow rule documents did not fail closed");

        var unsupportedRoot = CreateRoot();
        Directory.CreateDirectory(unsupportedRoot);
        await File.WriteAllTextAsync(
            Path.Combine(unsupportedRoot, "workflow-rules.json"),
            "{\"schemaVersion\":99}");
        var unsupportedStore = new WorkflowRuleStore(unsupportedRoot);
        var unsupported = await unsupportedStore.ReadAsync();
        Ensure(
            unsupported.ReadStatus == WorkflowRuleStoreReadStatus.UnsupportedSchema &&
            unsupported.RequiresConservativeRecovery,
            "newer workflow rule schema was not retained as unsupported");
        await AssertThrowsAsync<NotSupportedException>(() => unsupportedStore.SaveAsync([]));
    }

    private static async Task TestDurableRollbackAsync()
    {
        var root = CreateRoot();
        var store = new WorkflowRuleStore(root);
        var baseline = ScheduledSendRule(seed: 600, WorkflowDestinationKind.ExistingConversation);
        var replacement = ScheduledSendRule(seed: 700, WorkflowDestinationKind.ExistingConversation);
        await store.SaveAsync([baseline]);
        var durable = await store.CaptureDurableSnapshotAsync();
        var primaryHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            File.ReadAllBytes(store.RulePath)));

        var replacementState = await store.SaveAsync([replacement]);
        await store.RestoreDurableSnapshotAsync(durable, replacementState.Generation);
        var restored = await store.ReadAsync();
        var restarted = await new WorkflowRuleStore(root).ReadAsync();
        var restoredHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            File.ReadAllBytes(store.RulePath)));
        Ensure(
            restored.Generation == durable.LogicalState.Generation &&
            restarted.Generation == durable.LogicalState.Generation &&
            restored.Rules.Single().RuleId == baseline.RuleId &&
            restarted.Rules.Single().RuleId == baseline.RuleId &&
            string.Equals(primaryHash, restoredHash, StringComparison.Ordinal),
            "workflow rule rollback did not restore the original durable generation and bytes");
    }

    private static async Task TestDurableRollbackRejectsLaterGenerationAsync()
    {
        var root = CreateRoot();
        var store = new WorkflowRuleStore(root);
        var baseline = ScheduledSendRule(seed: 800, WorkflowDestinationKind.ExistingConversation);
        var replacement = ScheduledSendRule(seed: 900, WorkflowDestinationKind.ExistingConversation);
        var later = ScheduledSendRule(seed: 1000, WorkflowDestinationKind.ExistingConversation);
        await store.SaveAsync([baseline]);
        var durable = await store.CaptureDurableSnapshotAsync();
        var replacementState = await store.SaveAsync([replacement]);
        var laterState = await store.SaveAsync([later]);

        await AssertThrowsAsync<InvalidOperationException>(() =>
            store.RestoreDurableSnapshotAsync(durable, replacementState.Generation));
        var retained = await store.ReadAsync();
        var restarted = await new WorkflowRuleStore(root).ReadAsync();
        Ensure(
            retained.Generation == laterState.Generation &&
            restarted.Generation == laterState.Generation &&
            retained.Rules.Single().RuleId == later.RuleId &&
            restarted.Rules.Single().RuleId == later.RuleId,
            "a stale workflow rollback overwrote the later durable generation");
    }

    private static WorkflowRuleDefinition ScheduledSendRule(
        int seed,
        WorkflowDestinationKind destinationKind)
    {
        var owner = Id(seed);
        return WorkflowRuleDefinition.Create(
            Id(seed + 1),
            1,
            owner,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ScheduledAt,
                ScheduledAtUtc = Activation.AddHours(1)
            },
            destinationKind == WorkflowDestinationKind.NewConversation
                ? new WorkflowDestinationDefinition { Kind = WorkflowDestinationKind.NewConversation }
                : new WorkflowDestinationDefinition
                {
                    Kind = WorkflowDestinationKind.ExistingConversation,
                    ConversationId = Id(seed + 2)
                },
            [WorkflowConditionKind.RuleAndPresetEnabled],
            [Send(owner, Id(seed + 3), 0)]);
    }

    private static WorkflowRuleDefinition CompletionSendRule(
        string ruleId,
        string sourceConversationId,
        string targetConversationId,
        string presetId) =>
        WorkflowRuleDefinition.Create(
            ruleId,
            1,
            sourceConversationId,
            true,
            Activation,
            new WorkflowTriggerDefinition
            {
                Kind = WorkflowTriggerKind.ConversationCompletedNormally,
                SourceConversationId = sourceConversationId
            },
            new WorkflowDestinationDefinition
            {
                Kind = WorkflowDestinationKind.ExistingConversation,
                ConversationId = targetConversationId
            },
            null,
            [Send(sourceConversationId, presetId, 0)]);

    private static WorkflowActionDefinition Send(
        string ownerConversationId,
        string presetId,
        int order) =>
        new()
        {
            Kind = WorkflowActionKind.SendPresetMessage,
            PresetOwnerConversationId = ownerConversationId,
            PresetMessageId = presetId,
            Order = order
        };

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required.");
        }

        return Path.Combine(parent, "wr-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private static string Id(int value) =>
        $"00000000-0000-0000-0000-{value:000000000000}";

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
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

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
