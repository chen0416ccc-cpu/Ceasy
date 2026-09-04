using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;

internal static class ConversationMutationOfflineTests
{
    private const string ThreadId = "019f2d74-0200-7ff0-9c82-606ce019fd14";
    private const string LatestTurnId = "019f2d74-0200-7ff0-9c82-606ce019fd15";
    private const string OwnerClientId = "test-owner-client";
    private const long UpdatedAt = 1_754_000_000;
    private const long OwnerRevision = 41;

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        await RunCaseAsync(
            "Conversation mutation capability gate has zero side effects",
            TestCapabilityGateAsync,
            assert);
        await RunCaseAsync(
            "Conversation mutation journal promotes interrupted commits to uncertain",
            TestJournalInterruptedCommitAsync,
            assert);
        await RunCaseAsync(
            "Conversation unarchive requires exact owner receipt and authoritative readback",
            TestUnarchiveSuccessAsync,
            assert);
        await RunCaseAsync(
            "Conversation delete requires explicit confirmation before any read or write",
            TestDeleteConfirmationAsync,
            assert);
        await RunCaseAsync(
            "Conversation delete confirms authoritative absence",
            TestDeleteSuccessAsync,
            assert);
        await RunCaseAsync(
            "Uncertain conversation mutation is never blindly retried",
            TestUncertainNoRetryAsync,
            assert);
        await RunCaseAsync(
            "Conversation mutation rejects a mismatched owner boundary",
            TestOwnerMismatchAsync,
            assert);
    }

    private static async Task TestCapabilityGateAsync()
    {
        await WithRootAsync(async root =>
        {
            var state = new FakeStateReader();
            var desktop = new FakeDesktopChannel(
                ConversationMutationTransportCapabilities.CurrentCodexIpcUnavailable,
                CreateOwnerSnapshot());
            var activator = new FakeOwnerActivator();
            using var log = new GuardianLog(root);
            var journal = new ConversationMutationOperationJournal(root);
            var service = new ConversationMutationService(
                state,
                desktop,
                activator,
                journal,
                log);

            var result = await service.ExecuteAsync(CreateRequest(ConversationMutationKind.Unarchive));
            Ensure(
                !result.Success &&
                result.FailureKind == ConversationMutationFailureKind.CapabilityUnavailable &&
                state.ReadCount == 0 &&
                desktop.AcquireCount == 0 &&
                desktop.CommitCount == 0 &&
                activator.EnsureCount == 0 &&
                !File.Exists(journal.JournalPath),
                "an unsupported stock Desktop contract reached state, owner, commit, or journal side effects");
        });
    }

    private static async Task TestJournalInterruptedCommitAsync()
    {
        await WithRootAsync(async root =>
        {
            var journal = new ConversationMutationOperationJournal(root);
            var prepared = await journal.GetOrCreateAsync(CreateJournalRequest(OwnerRevision));
            var committing = await journal.TryTransitionAsync(
                prepared.Record.OperationId,
                ConversationMutationOperationState.Prepared,
                ConversationMutationOperationState.Committing);
            Ensure(
                committing.Changed &&
                committing.Record?.State == ConversationMutationOperationState.Committing &&
                committing.Record.AttemptCount == 1,
                "the durable mutation intent did not enter one committing attempt");

            var restarted = new ConversationMutationOperationJournal(root);
            var snapshot = await restarted.ReadAsync();
            var uncertain = snapshot.Records.Single();
            Ensure(
                snapshot.ReadStatus == ConversationMutationJournalReadStatus.Healthy &&
                snapshot.RequiresConservativeRecovery &&
                uncertain.State == ConversationMutationOperationState.Uncertain,
                "a restarted committing mutation remained retryable");

            var blocked = false;
            try
            {
                await restarted.GetOrCreateAsync(CreateJournalRequest(OwnerRevision + 1));
            }
            catch (InvalidOperationException)
            {
                blocked = true;
            }

            var confirmed = await restarted.TryTransitionAsync(
                uncertain.OperationId,
                ConversationMutationOperationState.Uncertain,
                ConversationMutationOperationState.Confirmed,
                receiptId: "receipt-after-readback");
            Ensure(
                blocked &&
                confirmed.Changed &&
                confirmed.Record?.State == ConversationMutationOperationState.Confirmed,
                "an uncertain mutation allowed a replacement or rejected authoritative confirmation");
        });
    }

    private static async Task TestUnarchiveSuccessAsync()
    {
        await WithRootAsync(async root =>
        {
            var state = new FakeStateReader(
                ArchivedAuthority(),
                ArchivedAuthority(),
                ActiveAuthority());
            var desktop = new FakeDesktopChannel(EligibleCapabilities(), CreateOwnerSnapshot());
            var activator = new FakeOwnerActivator();
            using var log = new GuardianLog(root);
            var journal = new ConversationMutationOperationJournal(root);
            var service = new ConversationMutationService(
                state,
                desktop,
                activator,
                journal,
                log);

            var result = await service.ExecuteAsync(CreateRequest(ConversationMutationKind.Unarchive));
            var snapshot = await journal.ReadAsync();
            var record = snapshot.Records.Single();
            Ensure(
                result.Success &&
                result.Applied &&
                result.AuthoritativeThread is { IsArchived: false } &&
                state.ReadCount == 3 &&
                activator.EnsureCount == 1 &&
                desktop.AcquireCount == 1 &&
                desktop.CommitCount == 1 &&
                desktop.LastCommit is
                {
                    Kind: ConversationMutationKind.Unarchive,
                    ThreadId: ThreadId,
                    ExpectedLatestTurnId: LatestTurnId,
                    OwnerClientId: OwnerClientId,
                    DeleteConfirmed: false
                } &&
                record.State == ConversationMutationOperationState.Confirmed &&
                record.AttemptCount == 1 &&
                record.ReceiptId == "test-owner-receipt",
                "unarchive skipped an authority gate or failed to persist the exact owner receipt");
        });
    }

    private static async Task TestDeleteConfirmationAsync()
    {
        await WithRootAsync(async root =>
        {
            var state = new FakeStateReader(ArchivedAuthority());
            var desktop = new FakeDesktopChannel(EligibleCapabilities(), CreateOwnerSnapshot());
            var activator = new FakeOwnerActivator();
            using var log = new GuardianLog(root);
            var journal = new ConversationMutationOperationJournal(root);
            var service = new ConversationMutationService(
                state,
                desktop,
                activator,
                journal,
                log);

            var result = await service.ExecuteAsync(
                CreateRequest(ConversationMutationKind.Delete, deleteConfirmed: false));
            Ensure(
                !result.Success &&
                result.FailureKind == ConversationMutationFailureKind.ConfirmationRequired &&
                state.ReadCount == 0 &&
                desktop.AcquireCount == 0 &&
                desktop.CommitCount == 0 &&
                activator.EnsureCount == 0 &&
                !File.Exists(journal.JournalPath),
                "an unconfirmed delete crossed a read, owner, journal, or commit boundary");
        });
    }

    private static async Task TestDeleteSuccessAsync()
    {
        await WithRootAsync(async root =>
        {
            var state = new FakeStateReader(
                ArchivedAuthority(),
                ArchivedAuthority(),
                ConversationMutationAuthoritySnapshot.Absent);
            var desktop = new FakeDesktopChannel(EligibleCapabilities(), CreateOwnerSnapshot());
            var activator = new FakeOwnerActivator();
            using var log = new GuardianLog(root);
            var journal = new ConversationMutationOperationJournal(root);
            var service = new ConversationMutationService(
                state,
                desktop,
                activator,
                journal,
                log);

            var result = await service.ExecuteAsync(
                CreateRequest(ConversationMutationKind.Delete, deleteConfirmed: true));
            var record = (await journal.ReadAsync()).Records.Single();
            Ensure(
                result.Success &&
                result.Applied &&
                result.AuthoritativeThread is null &&
                desktop.LastCommit is
                {
                    Kind: ConversationMutationKind.Delete,
                    DeleteConfirmed: true
                } &&
                record.State == ConversationMutationOperationState.Confirmed,
                "delete did not require the confirmed intent and authoritative absence readback");
        });
    }

    private static async Task TestUncertainNoRetryAsync()
    {
        await WithRootAsync(async root =>
        {
            var state = new FakeStateReader(
                ArchivedAuthority(),
                ArchivedAuthority(),
                ArchivedAuthority(),
                ArchivedAuthority());
            var desktop = new FakeDesktopChannel(EligibleCapabilities(), CreateOwnerSnapshot())
            {
                CommitFailure = new DesktopIpcDeliveryException(
                    DesktopIpcDeliveryStage.DispatchedUnknown,
                    "synthetic dispatched-unknown")
            };
            var activator = new FakeOwnerActivator();
            using var log = new GuardianLog(root);
            var journal = new ConversationMutationOperationJournal(root);
            var firstService = new ConversationMutationService(
                state,
                desktop,
                activator,
                journal,
                log);

            var first = await firstService.ExecuteAsync(
                CreateRequest(ConversationMutationKind.Delete, deleteConfirmed: true));
            var restartedService = new ConversationMutationService(
                state,
                desktop,
                activator,
                new ConversationMutationOperationJournal(root),
                log);
            var second = await restartedService.ExecuteAsync(
                CreateRequest(ConversationMutationKind.Delete, deleteConfirmed: true));
            var persisted = await new ConversationMutationOperationJournal(root).ReadAsync();
            Ensure(
                first.FailureKind == ConversationMutationFailureKind.Uncertain &&
                second.FailureKind == ConversationMutationFailureKind.Uncertain &&
                desktop.CommitCount == 1 &&
                persisted.Records.Single().State == ConversationMutationOperationState.Uncertain,
                "a dispatched-unknown delete was resent or lost its uncertain ledger state");
        });
    }

    private static async Task TestOwnerMismatchAsync()
    {
        await WithRootAsync(async root =>
        {
            var state = new FakeStateReader(ArchivedAuthority());
            var mismatched = CreateOwnerSnapshot() with { ConversationId = Guid.NewGuid().ToString("D") };
            var desktop = new FakeDesktopChannel(EligibleCapabilities(), mismatched);
            var activator = new FakeOwnerActivator();
            using var log = new GuardianLog(root);
            var journal = new ConversationMutationOperationJournal(root);
            var service = new ConversationMutationService(
                state,
                desktop,
                activator,
                journal,
                log);

            var result = await service.ExecuteAsync(CreateRequest(ConversationMutationKind.Unarchive));
            Ensure(
                !result.Success &&
                result.FailureKind == ConversationMutationFailureKind.OwnerUnavailable &&
                desktop.CommitCount == 0 &&
                !File.Exists(journal.JournalPath),
                "a mismatched Desktop owner reached durable intent or commit");
        });
    }

    private static ConversationMutationRequest CreateRequest(
        ConversationMutationKind kind,
        bool deleteConfirmed = false) =>
        new(
            ArchivedThread(),
            kind,
            LatestTurnId,
            deleteConfirmed,
            HasDirtyDraft: false,
            IsStillAllowed: static () => true);

    private static ConversationMutationOperationRecord CreateJournalRequest(long ownerRevision)
    {
        var operationId = ConversationMutationOperationJournal.CreateOperationId(
            ThreadId,
            ConversationMutationKind.Delete,
            UpdatedAt,
            LatestTurnId,
            "local",
            OwnerClientId,
            ownerRevision);
        return new ConversationMutationOperationRecord(
            operationId,
            ThreadId,
            ConversationMutationKind.Delete,
            UpdatedAt,
            LatestTurnId,
            "local",
            OwnerClientId,
            ownerRevision,
            ConversationMutationOperationState.Prepared,
            ReceiptId: null,
            CreatedAt: default,
            UpdatedAt: default,
            AttemptCount: 0);
    }

    private static ThreadSummary ArchivedThread() => new(
        ThreadId,
        "Archived fixture",
        "Fixture preview",
        @"D:\fixture",
        "cli",
        UpdatedAt - 100,
        UpdatedAt,
        IsSubAgent: false,
        IsEphemeral: false,
        RuntimeStatus: "idle",
        IsArchived: true);

    private static ThreadSummary ActiveThread() => ArchivedThread() with { IsArchived = false };

    private static TurnSnapshot LatestTurn() => new(
        LatestTurnId,
        "completed",
        ErrorMessage: null,
        ErrorCode: null,
        HttpStatusCode: null,
        UserText: "fixture",
        HasAttachments: false,
        HasAssistantOutput: true,
        HasWorkOutput: true,
        OutputFingerprint: "fixture-output",
        StartedAt: UpdatedAt - 10,
        CompletedAt: UpdatedAt);

    private static ConversationMutationAuthoritySnapshot ArchivedAuthority() =>
        new(true, ArchivedThread(), LatestTurn());

    private static ConversationMutationAuthoritySnapshot ActiveAuthority() =>
        new(true, ActiveThread(), LatestTurn());

    private static DesktopThreadOwnerStateSnapshot CreateOwnerSnapshot() => new(
        ThreadId,
        "local",
        OwnerClientId,
        OwnerRevision,
        "idle",
        LatestTurnId,
        "completed");

    private static ConversationMutationTransportCapabilities EligibleCapabilities() => new(
        SupportsUnarchive: true,
        SupportsDelete: true,
        SupportsExpectedStateValidation: true,
        SupportsAtMostOnceOperationId: true,
        ReturnsOwnerReceipt: true,
        ExecutesThroughDesktopOwner: true,
        IsTrustedDesktopProtocol: true,
        Detail: "synthetic eligible owner transport");

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
            Console.WriteLine(exception);
            assert(false, name);
        }
    }

    private static async Task WithRootAsync(Func<string, Task> action)
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "codexfree-conversation-mutation-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await action(root);
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch
            {
            }
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeStateReader : IConversationMutationStateReader
    {
        private readonly Queue<ConversationMutationAuthoritySnapshot> _snapshots = new();

        internal FakeStateReader(params ConversationMutationAuthoritySnapshot[] snapshots)
        {
            foreach (var snapshot in snapshots)
            {
                _snapshots.Enqueue(snapshot);
            }
        }

        internal int ReadCount { get; private set; }

        public Task<ConversationMutationAuthoritySnapshot> ReadAuthorityAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(
                string.Equals(threadId, ThreadId, StringComparison.OrdinalIgnoreCase),
                "state reader received a different thread");
            ReadCount++;
            if (_snapshots.Count == 0)
            {
                throw new InvalidOperationException("No synthetic authority snapshot remains.");
            }

            return Task.FromResult(
                _snapshots.Count == 1 ? _snapshots.Peek() : _snapshots.Dequeue());
        }
    }

    private sealed class FakeDesktopChannel : IConversationMutationDesktopChannel
    {
        private readonly DesktopThreadOwnerStateSnapshot _snapshot;

        internal FakeDesktopChannel(
            ConversationMutationTransportCapabilities capabilities,
            DesktopThreadOwnerStateSnapshot snapshot)
        {
            Capabilities = capabilities;
            _snapshot = snapshot;
        }

        public ConversationMutationTransportCapabilities Capabilities { get; }

        internal int AcquireCount { get; private set; }

        internal int CommitCount { get; private set; }

        internal ConversationMutationCommitRequest? LastCommit { get; private set; }

        internal Exception? CommitFailure { get; init; }

        public Task<ConversationMutationOwnerGuardAcquireResult> AcquireOwnerGuardAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AcquireCount++;
            return Task.FromResult(new ConversationMutationOwnerGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Available,
                new FakeOwnerGuard(_snapshot),
                "synthetic owner guard"));
        }

        public Task<ConversationMutationCommitResult> CommitAsync(
            ConversationMutationCommitRequest request,
            Func<bool> canCommit,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(canCommit(), "final commit guard rejected a valid synthetic request");
            CommitCount++;
            LastCommit = request;
            if (CommitFailure is not null)
            {
                return Task.FromException<ConversationMutationCommitResult>(CommitFailure);
            }

            return Task.FromResult(new ConversationMutationCommitResult(
                Acknowledged: true,
                request.OperationId,
                request.OwnerHostId,
                request.OwnerClientId,
                ReceiptId: "test-owner-receipt"));
        }
    }

    private sealed class FakeOwnerGuard(DesktopThreadOwnerStateSnapshot snapshot)
        : IConversationMutationOwnerGuard
    {
        public DesktopThreadOwnerStateSnapshot Snapshot { get; } = snapshot;

        public bool IsCurrent => true;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeOwnerActivator : IConversationMutationOwnerActivator
    {
        internal int EnsureCount { get; private set; }

        public Task<DesktopThreadOwnerActivationResult> EnsureOwnerAsync(
            string threadId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureCount++;
            return Task.FromResult(new DesktopThreadOwnerActivationResult(
                DesktopThreadOwnerActivationStatus.AlreadyAvailable,
                "synthetic owner already available"));
        }

        public DesktopUserActivityResult CheckUserActivity() => new(
            DesktopUserActivityStatus.Idle,
            "synthetic idle activity gate");
    }
}
