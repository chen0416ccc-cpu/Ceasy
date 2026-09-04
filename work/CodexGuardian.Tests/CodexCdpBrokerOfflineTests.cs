using CodexGuardian.Control;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;

internal static class CodexCdpBrokerOfflineTests
{
    private const string Epoch = "epoch-0123456789abcdef";
    private const string OtherEpoch = "epoch-fedcba9876543210";
    private const string LaunchOperation = "operation-launch-0001";

    internal static Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase("CDP broker endpoint is per-user per-session without a raw SID", TestEndpointName, assert);
        RunCase("CDP broker accepts only exact content-free commands", TestExactCommands, assert);
        RunCase("CDP broker decodes partial and multiple little-endian frames", TestFrameDecoder, assert);
        RunCase("CDP broker rejects truncated EOF and accepts complete EOF", TestFrameCompletion, assert);
        RunCase("CDP broker frame EOF is concurrent and linearizable", TestFrameConcurrency, assert);
        RunCase("CDP broker rejects oversized malformed command frames", TestInvalidFrames, assert);
        RunCase("CDP broker subscription queue is bounded and requires resync", TestBoundedQueue, assert);
        RunCase("CDP broker rejects illegal fail-closed transitions", TestIllegalTransitions, assert);
        RunCase("CDP broker loses a single-instance race without claiming ownership", TestSingleInstanceRace, assert);
        RunCase("CDP broker validates epochs and bounded operation replay", TestOperationReplay, assert);
        RunCase("CDP broker survives no-client faults without closing managed Codex", TestRetirementAndNoClient, assert);
        return Task.CompletedTask;
    }

    private static void TestEndpointName()
    {
        const string sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        var first = CodexCdpBrokerProtocol.CreateEndpointName(sid, 3);
        var repeat = CodexCdpBrokerProtocol.CreateEndpointName(sid, 3);
        var otherSession = CodexCdpBrokerProtocol.CreateEndpointName(sid, 4);
        var otherUser = CodexCdpBrokerProtocol.CreateEndpointName(
            "S-1-5-21-1111111111-2222222222-3333333333-1002",
            3);

        Ensure(first == repeat, "endpoint naming was not deterministic");
        Ensure(first != otherSession, "endpoint naming did not bind the Windows session");
        Ensure(first != otherUser, "endpoint naming did not bind the Windows user");
        Ensure(!first.Contains(sid, StringComparison.OrdinalIgnoreCase), "endpoint exposed a raw SID");
        Ensure(
            first.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'),
            "endpoint used characters outside the named-pipe-safe contract");
        Expect<ArgumentException>(() => CodexCdpBrokerProtocol.CreateEndpointName("S-1-bad", 3));
    }

    private static void TestExactCommands()
    {
        var accepted = new Dictionary<string, CodexCdpBrokerCommandKind>
        {
            ["{\"command\":\"hello\",\"protocol\":1}"] = CodexCdpBrokerCommandKind.Hello,
            [$"{{\"command\":\"getStatus\",\"brokerEpoch\":\"{Epoch}\"}}"] = CodexCdpBrokerCommandKind.GetStatus,
            [$"{{\"command\":\"subscribe\",\"brokerEpoch\":\"{Epoch}\",\"afterSequence\":0}}"] = CodexCdpBrokerCommandKind.Subscribe,
            [$"{{\"command\":\"getFullSnapshot\",\"brokerEpoch\":\"{Epoch}\"}}"] = CodexCdpBrokerCommandKind.GetFullSnapshot,
            [$"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"operation-start-001\"}}"] = CodexCdpBrokerCommandKind.StartManagedCodex,
            [$"{{\"command\":\"retireAfterCodexExit\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"operation-retire-01\"}}"] = CodexCdpBrokerCommandKind.RetireAfterCodexExit,
            [$"{{\"command\":\"restartForUpgrade\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"operation-upgrade-01\"}}"] = CodexCdpBrokerCommandKind.RestartForUpgrade
        };
        foreach (var pair in accepted)
        {
            Ensure(
                CodexCdpBrokerProtocol.TryParseCommand(pair.Key, out var command, out _) &&
                command?.Kind == pair.Value,
                "an exact allowlisted command was rejected: " + pair.Value);
        }

        var rejected = new[]
        {
            $"{{\"command\":\"getStatus\",\"brokerEpoch\":\"{Epoch}\",\"content\":\"secret\"}}",
            $"{{\"command\":\"startManagedCodex\",\"brokerEpoch\":\"{Epoch}\",\"operationId\":\"operation-start-001\",\"commandText\":\"Get-Date\"}}",
            $"{{\"command\":\"cdp\",\"brokerEpoch\":\"{Epoch}\",\"method\":\"Runtime.evaluate\",\"params\":{{}}}}",
            $"{{\"command\":\"Runtime.evaluate\",\"brokerEpoch\":\"{Epoch}\"}}",
            $"{{\"command\":\"subscribe\",\"brokerEpoch\":\"{Epoch}\",\"afterSequence\":-1}}",
            $"{{\"command\":\"restartForUpgrade\",\"brokerEpoch\":\"{Epoch}\"}}",
            "{\"command\":\"hello\",\"protocol\":1,\"protocol\":1}",
            "{\"command\":\"hello\",\"protocol\":1,\"prompt\":null}"
        };
        foreach (var json in rejected)
        {
            Ensure(
                !CodexCdpBrokerProtocol.TryParseCommand(json, out _, out _),
                "a non-exact or content-bearing command was accepted");
        }

        var machine = new CodexCdpBrokerStateMachine(Epoch);
        var snapshotJson = CodexCdpBrokerProtocol.SerializeSnapshot(machine.Current, fullSnapshot: true);
        using var document = JsonDocument.Parse(snapshotJson);
        var names = document.RootElement.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        Ensure(names.SetEquals(new[]
        {
            "kind", "brokerEpoch", "sequence", "state", "connectedClients",
            "ownsManagedCodex", "retirementIntent", "brokerExitIntent",
            "managedCodexExitIntent"
        }), "snapshot serialization exposed a field outside the metadata contract");
        Ensure(
            !snapshotJson.Contains("content", StringComparison.OrdinalIgnoreCase) &&
            !snapshotJson.Contains("prompt", StringComparison.OrdinalIgnoreCase) &&
            !snapshotJson.Contains("response", StringComparison.OrdinalIgnoreCase) &&
            !snapshotJson.Contains("reasoning", StringComparison.OrdinalIgnoreCase) &&
            !snapshotJson.Contains("toolOutput", StringComparison.OrdinalIgnoreCase) &&
            !snapshotJson.Contains("Runtime.evaluate", StringComparison.Ordinal),
            "snapshot serialization contained forbidden content or raw CDP");
    }

    private static void TestFrameDecoder()
    {
        const string hello = "{\"command\":\"hello\",\"protocol\":1}";
        var status = $"{{\"command\":\"getStatus\",\"brokerEpoch\":\"{Epoch}\"}}";
        var first = CodexCdpBrokerProtocol.EncodeFrame(hello);
        var second = CodexCdpBrokerProtocol.EncodeFrame(status);
        var payloadLength = Encoding.UTF8.GetByteCount(hello);
        Ensure(
            BinaryPrimitives.ReadUInt32LittleEndian(first) == payloadLength &&
            first[0] == (byte)payloadLength &&
            first[1] == 0 && first[2] == 0 && first[3] == 0,
            "frame prefix was not a strict four-byte little-endian length");

        var decoder = new CodexCdpBrokerCommandFrameDecoder();
        Ensure(decoder.Append(first.AsSpan(0, 1)).Count == 0, "partial header emitted a command");
        Ensure(decoder.Append(first.AsSpan(1, 2)).Count == 0, "partial header emitted a command");
        Ensure(decoder.Append(first.AsSpan(3, 7)).Count == 0, "partial payload emitted a command");
        var completed = decoder.Append(first.AsSpan(10));
        Ensure(
            completed.Count == 1 && completed[0].Kind == CodexCdpBrokerCommandKind.Hello,
            "split frame did not decode exactly once");

        var joined = new byte[first.Length + second.Length];
        first.CopyTo(joined, 0);
        second.CopyTo(joined, first.Length);
        var coalesced = new CodexCdpBrokerCommandFrameDecoder().Append(joined);
        Ensure(
            coalesced.Count == 2 &&
            coalesced[0].Kind == CodexCdpBrokerCommandKind.Hello &&
            coalesced[1].Kind == CodexCdpBrokerCommandKind.GetStatus,
            "coalesced frames were not decoded in order");
    }

    private static void TestInvalidFrames()
    {
        var oversized = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(
            oversized,
            CodexCdpBrokerProtocol.MaximumFrameBytes + 1U);
        var oversizedDecoder = new CodexCdpBrokerCommandFrameDecoder();
        var oversizedFailure = Expect<CodexCdpBrokerProtocolException>(
            () => oversizedDecoder.Append(oversized));
        Ensure(
            oversizedFailure.Code == "invalid-frame-length" && oversizedDecoder.IsFaulted,
            "oversized frame did not terminally fail before allocation");

        var invalidJsonDecoder = new CodexCdpBrokerCommandFrameDecoder();
        var invalidJson = Expect<CodexCdpBrokerProtocolException>(
            () => invalidJsonDecoder.Append(CodexCdpBrokerProtocol.EncodeFrame("not-json")));
        Ensure(
            invalidJson.Code == "invalid-json" && invalidJsonDecoder.IsFaulted,
            "invalid JSON did not terminally fail the command decoder");
        var terminal = Expect<CodexCdpBrokerProtocolException>(
            () => invalidJsonDecoder.Append(
                CodexCdpBrokerProtocol.EncodeFrame("{\"command\":\"hello\",\"protocol\":1}")));
        Ensure(terminal.Code == "decoder-faulted", "terminal decoder accepted a later frame");

        var invalidUtf8 = new byte[6];
        BinaryPrimitives.WriteUInt32LittleEndian(invalidUtf8, 2);
        invalidUtf8[4] = 0xC3;
        invalidUtf8[5] = 0x28;
        var utf8Failure = Expect<CodexCdpBrokerProtocolException>(
            () => new CodexCdpBrokerCommandFrameDecoder().Append(invalidUtf8));
        Ensure(utf8Failure.Code == "invalid-utf8", "invalid UTF-8 was accepted");
    }

    private static void TestFrameCompletion()
    {
        var frame = CodexCdpBrokerProtocol.EncodeFrame("{\"command\":\"hello\",\"protocol\":1}");

        var partialHeader = new CodexCdpBrokerCommandFrameDecoder();
        Ensure(partialHeader.Append(frame.AsSpan(0, 2)).Count == 0, "partial header emitted a command");
        var headerFailure = Expect<CodexCdpBrokerProtocolException>(partialHeader.Complete);
        Ensure(
            headerFailure.Code == "truncated-frame" && partialHeader.IsFaulted,
            "partial-header EOF did not terminally fail");

        var partialPayload = new CodexCdpBrokerCommandFrameDecoder();
        Ensure(
            partialPayload.Append(frame.AsSpan(0, frame.Length - 1)).Count == 0,
            "partial payload emitted a command");
        var payloadFailure = Expect<CodexCdpBrokerProtocolException>(partialPayload.Complete);
        Ensure(
            payloadFailure.Code == "truncated-frame" && partialPayload.IsFaulted,
            "partial-payload EOF did not terminally fail");

        var complete = new CodexCdpBrokerCommandFrameDecoder();
        Ensure(complete.Append(frame).Count == 1, "complete frame was not decoded");
        complete.Complete();
        complete.Complete();
        Ensure(complete.IsCompleted && !complete.IsFaulted, "complete-frame EOF did not finish cleanly");
        var afterEof = Expect<CodexCdpBrokerProtocolException>(() => complete.Append(frame));
        Ensure(afterEof.Code == "decoder-completed", "decoder accepted bytes after clean EOF");
    }

    private static void TestFrameConcurrency()
    {
        var frame = CodexCdpBrokerProtocol.EncodeFrame("{\"command\":\"hello\",\"protocol\":1}");

        var immediateEof = new CodexCdpBrokerCommandFrameDecoder();
        immediateEof.Complete();
        Ensure(immediateEof.IsCompleted && !immediateEof.IsFaulted, "empty EOF did not complete cleanly");

        var faulted = new CodexCdpBrokerCommandFrameDecoder();
        _ = Expect<CodexCdpBrokerProtocolException>(
            () => faulted.Append(CodexCdpBrokerProtocol.EncodeFrame("not-json")));
        var afterFault = Expect<CodexCdpBrokerProtocolException>(faulted.Complete);
        Ensure(afterFault.Code == "decoder-faulted", "faulted decoder accepted EOF completion");

        for (var iteration = 0; iteration < 32; iteration++)
        {
            var decoder = new CodexCdpBrokerCommandFrameDecoder();
            using var start = new ManualResetEventSlim(false);
            IReadOnlyList<CodexCdpBrokerCommand>? commands = null;
            CodexCdpBrokerProtocolException? appendFailure = null;
            CodexCdpBrokerProtocolException? completeFailure = null;
            var appendTask = Task.Run(() =>
            {
                start.Wait();
                try
                {
                    commands = decoder.Append(frame);
                }
                catch (CodexCdpBrokerProtocolException exception)
                {
                    appendFailure = exception;
                }
            });
            var completeTask = Task.Run(() =>
            {
                start.Wait();
                try
                {
                    decoder.Complete();
                }
                catch (CodexCdpBrokerProtocolException exception)
                {
                    completeFailure = exception;
                }
            });
            start.Set();
            Task.WaitAll(appendTask, completeTask);

            Ensure(completeFailure is null, "clean concurrent EOF unexpectedly failed");
            if (appendFailure is null)
            {
                Ensure(commands?.Count == 1, "append won EOF race without one decoded command");
            }
            else
            {
                Ensure(
                    appendFailure.Code == "decoder-completed" && commands is null,
                    "append lost EOF race with an unexpected result");
            }

            Ensure(decoder.IsCompleted && !decoder.IsFaulted, "EOF race did not linearize cleanly");
        }

        var repeatedComplete = new CodexCdpBrokerCommandFrameDecoder();
        Parallel.For(0, 32, _ => repeatedComplete.Complete());
        Ensure(
            repeatedComplete.IsCompleted && !repeatedComplete.IsFaulted,
            "concurrent repeated EOF completion was not idempotent");

        var partialRace = new CodexCdpBrokerCommandFrameDecoder();
        using var partialStart = new ManualResetEventSlim(false);
        CodexCdpBrokerProtocolException? partialAppendFailure = null;
        CodexCdpBrokerProtocolException? partialCompleteFailure = null;
        var partialAppend = Task.Run(() =>
        {
            partialStart.Wait();
            try
            {
                partialRace.Append(frame.AsSpan(0, frame.Length - 1));
            }
            catch (CodexCdpBrokerProtocolException exception)
            {
                partialAppendFailure = exception;
            }
        });
        var partialComplete = Task.Run(() =>
        {
            partialStart.Wait();
            try
            {
                partialRace.Complete();
            }
            catch (CodexCdpBrokerProtocolException exception)
            {
                partialCompleteFailure = exception;
            }
        });
        partialStart.Set();
        Task.WaitAll(partialAppend, partialComplete);
        Ensure(
            (partialRace.IsFaulted &&
             partialAppendFailure is null &&
             partialCompleteFailure?.Code == "truncated-frame") ||
            (partialRace.IsCompleted &&
             partialCompleteFailure is null &&
             partialAppendFailure?.Code == "decoder-completed"),
            "partial append/EOF race did not linearize to one valid terminal state");
    }

    private static void TestBoundedQueue()
    {
        var machine = new CodexCdpBrokerStateMachine(Epoch);
        var queue = new CodexCdpBrokerSubscriptionQueue(Epoch, capacity: 2);
        Ensure(queue.Enqueue(machine.Current), "initial snapshot was not queued");
        var reconciling = machine.ApplySignal(CodexCdpBrokerSignal.BeginReconciliation).Snapshot;
        Ensure(queue.Enqueue(reconciling), "second bounded snapshot was not queued");
        var external = machine.ApplySignal(CodexCdpBrokerSignal.ExternalCodexObserved).Snapshot;
        Ensure(!queue.Enqueue(external), "overflow did not replace deltas with resync");
        Ensure(queue.RequiresResync && queue.Count == 1, "overflow was not reduced to one signal");
        var signal = queue.Drain(2).Single();
        Ensure(
            signal.Kind == CodexCdpBrokerNotificationKind.ResyncRequired &&
            signal.Sequence == external.Sequence && signal.Snapshot is null,
            "resync signal did not identify the latest sequence without a snapshot body");

        var newer = machine.ApplySignal(CodexCdpBrokerSignal.BeginReconciliation).Snapshot;
        Ensure(!queue.Enqueue(newer) && queue.Count == 1, "resync mode resumed incremental deltas");
        Ensure(
            !queue.AcknowledgeFullSnapshot(external) && queue.RequiresResync,
            "a stale full snapshot cleared the resync requirement");
        Ensure(
            queue.AcknowledgeFullSnapshot(newer) && !queue.RequiresResync && queue.Count == 0,
            "the exact latest full snapshot did not restore incremental delivery");
        var idle = machine.ApplySignal(CodexCdpBrokerSignal.NoCodexObserved).Snapshot;
        Ensure(queue.Enqueue(idle), "incremental delivery did not resume after full resync");

        var notificationJson = CodexCdpBrokerProtocol.SerializeNotification(new(
            CodexCdpBrokerNotificationKind.ResyncRequired,
            Epoch,
            idle.Sequence,
            null));
        using var document = JsonDocument.Parse(notificationJson);
        Ensure(
            document.RootElement.EnumerateObject().Select(item => item.Name).ToHashSet().SetEquals(
                new[] { "kind", "brokerEpoch", "latestSequence" }),
            "resync signal exposed fields outside the exact contract");
    }

    private static void TestIllegalTransitions()
    {
        var machine = new CodexCdpBrokerStateMachine(Epoch);
        var initial = machine.Current;
        var earlyStart = machine.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            LaunchOperation));
        Ensure(
            earlyStart.Disposition == CodexCdpBrokerApplyDisposition.Rejected &&
            earlyStart.Snapshot == initial,
            "booting broker accepted a managed launch");
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.CdpHandshakeCompleted, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Rejected,
            "broker skipped candidate ownership verification");

        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.BeginReconciliation).Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted,
            "booting broker did not enter reconciliation");
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.NoCodexObserved).Snapshot.State ==
                CodexCdpBrokerState.IdleNoCodex,
            "reconciliation did not reach idle-no-Codex");
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.BeginCandidateLaunch, LaunchOperation)
                .Disposition == CodexCdpBrokerApplyDisposition.Rejected,
            "candidate launch began without an accepted reservation");

        var reserved = machine.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            LaunchOperation));
        Ensure(reserved.Snapshot.State == CodexCdpBrokerState.LaunchReserved, "launch was not reserved");
        Ensure(
            machine.ApplySignal(
                    CodexCdpBrokerSignal.BeginCandidateLaunch,
                    "operation-wrong-0001")
                .Disposition == CodexCdpBrokerApplyDisposition.Rejected,
            "stale operation advanced a reserved launch");
        Ensure(
            machine.Current.State == CodexCdpBrokerState.LaunchReserved &&
            !machine.Current.OwnsManagedCodex &&
            !machine.Current.ManagedCodexExitIntent,
            "illegal transition mutated broker ownership or exit intent");
    }

    private static void TestSingleInstanceRace()
    {
        var machine = CreateIdleMachine(maximumOperations: 4);
        machine.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            LaunchOperation));
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.BeginCandidateLaunch, LaunchOperation)
                .Snapshot.State == CodexCdpBrokerState.LaunchingCandidate,
            "reserved launch did not enter candidate creation");
        Ensure(
            machine.ApplySignal(CodexCdpBrokerSignal.CandidateProcessStarted, LaunchOperation)
                .Snapshot.State == CodexCdpBrokerState.VerifyingCandidate,
            "candidate process did not enter exact verification");
        var lost = machine.ApplySignal(
            CodexCdpBrokerSignal.SingleInstanceRaceLost,
            LaunchOperation);
        Ensure(
            lost.Snapshot.State == CodexCdpBrokerState.RaceLost &&
            !lost.Snapshot.OwnsManagedCodex &&
            !lost.Snapshot.BrokerExitIntent &&
            !lost.Snapshot.ManagedCodexExitIntent &&
            lost.Snapshot.ActiveLaunchOperationId is null,
            "single-instance race loss retained ownership or any exit intent");
    }

    private static void TestOperationReplay()
    {
        var machine = CreateIdleMachine(maximumOperations: 2);
        var first = Operation(CodexCdpBrokerCommandKind.StartManagedCodex, "operation-first-001");
        var accepted = machine.ApplyCommand(first);
        var replay = machine.ApplyCommand(first);
        Ensure(
            accepted.Disposition == CodexCdpBrokerApplyDisposition.Accepted &&
            replay.Disposition == CodexCdpBrokerApplyDisposition.Replayed &&
            replay.Snapshot.Sequence == accepted.Snapshot.Sequence &&
            replay.Snapshot.AcceptedOperationCount == 1,
            "operation replay re-executed or advanced the ledger");
        var conflict = machine.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.RestartForUpgrade,
            "operation-first-001"));
        Ensure(
            conflict.Disposition == CodexCdpBrokerApplyDisposition.Rejected &&
            conflict.Code == "operation-id-conflict",
            "one operation id was reused for a different command");
        Ensure(
            machine.ApplyCommand(first with { BrokerEpoch = OtherEpoch }).Code ==
                "broker-epoch-mismatch",
            "a stale broker epoch was accepted");

        LoseRaceAndReturnIdle(machine, "operation-first-001");
        var second = Operation(CodexCdpBrokerCommandKind.StartManagedCodex, "operation-second-01");
        Ensure(
            machine.ApplyCommand(second).Disposition == CodexCdpBrokerApplyDisposition.Accepted,
            "second bounded operation was rejected");
        LoseRaceAndReturnIdle(machine, "operation-second-01");
        var overflow = machine.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            "operation-third-001"));
        Ensure(
            overflow.Disposition == CodexCdpBrokerApplyDisposition.Rejected &&
            overflow.Code == "operation-capacity-exceeded" &&
            overflow.Snapshot.State == CodexCdpBrokerState.IdleNoCodex &&
            overflow.Snapshot.AcceptedOperationCount == 2,
            "bounded operation ledger evicted history or executed overflow");

        var concurrent = CreateIdleMachine(maximumOperations: 1);
        var repeated = Operation(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            "operation-concurrent-1");
        var results = new ConcurrentBag<CodexCdpBrokerApplyResult>();
        Parallel.For(0, 32, _ => results.Add(concurrent.ApplyCommand(repeated)));
        Ensure(
            results.Count(result => result.Disposition == CodexCdpBrokerApplyDisposition.Accepted) == 1 &&
            results.Count(result => result.Disposition == CodexCdpBrokerApplyDisposition.Replayed) == 31 &&
            concurrent.Current.State == CodexCdpBrokerState.LaunchReserved &&
            concurrent.Current.AcceptedOperationCount == 1,
            "thread-safe duplicate operations executed more than once");
    }

    private static void TestRetirementAndNoClient()
    {
        var machine = CreateManagedReadyMachine();
        Ensure(
            machine.ConnectClient("guardian-client-0001").Disposition ==
                CodexCdpBrokerApplyDisposition.Accepted,
            "Guardian client did not connect");
        var disconnected = machine.DisconnectClient("guardian-client-0001");
        Ensure(
            disconnected.Snapshot.ConnectedClients == 0 &&
            disconnected.Snapshot.State == CodexCdpBrokerState.ManagedReady &&
            disconnected.Snapshot.OwnsManagedCodex &&
            !disconnected.Snapshot.BrokerExitIntent &&
            !disconnected.Snapshot.ManagedCodexExitIntent,
            "last Guardian disconnect affected the managed Codex lifetime");

        var retirement = machine.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.RetireAfterCodexExit,
            "operation-retire-01"));
        Ensure(
            retirement.Snapshot.State == CodexCdpBrokerState.ManagedReady &&
            retirement.Snapshot.RetirementIntent ==
                CodexCdpBrokerRetirementIntent.RetireAfterCodexExit &&
            !retirement.Snapshot.BrokerExitIntent &&
            !retirement.Snapshot.ManagedCodexExitIntent,
            "retirement request attempted to close a live managed Codex");

        var degraded = machine.ApplySignal(CodexCdpBrokerSignal.FaultDetected);
        Ensure(
            degraded.Snapshot.State == CodexCdpBrokerState.ManagedUnverified &&
            degraded.Snapshot.OwnsManagedCodex &&
            !degraded.Snapshot.BrokerExitIntent &&
            !degraded.Snapshot.ManagedCodexExitIntent,
            "owner fault produced an exit intent instead of observation degradation");
        var retiring = machine.ApplySignal(CodexCdpBrokerSignal.OwnedCodexExited);
        Ensure(
            retiring.Snapshot.State == CodexCdpBrokerState.Retiring &&
            !retiring.Snapshot.OwnsManagedCodex &&
            retiring.Snapshot.BrokerExitIntent &&
            !retiring.Snapshot.ManagedCodexExitIntent,
            "broker did not wait for the owned Codex to exit before retiring");

        var upgrade = CreateManagedReadyMachine();
        var normalExit = upgrade.ApplySignal(CodexCdpBrokerSignal.OwnedCodexExited);
        Ensure(
            normalExit.Snapshot.State == CodexCdpBrokerState.OwnedCodexExited &&
            !normalExit.Snapshot.BrokerExitIntent,
            "unarmed owned exit skipped the reconciliation state");
        var restart = upgrade.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.RestartForUpgrade,
            "operation-upgrade-01"));
        Ensure(
            restart.Snapshot.State == CodexCdpBrokerState.Retiring &&
            restart.Snapshot.RetirementIntent ==
                CodexCdpBrokerRetirementIntent.RestartForUpgrade &&
            restart.Snapshot.BrokerExitIntent &&
            !restart.Snapshot.ManagedCodexExitIntent,
            "upgrade restart did not remain broker-only after Codex exit");
    }

    private static CodexCdpBrokerStateMachine CreateIdleMachine(int maximumOperations)
    {
        var machine = new CodexCdpBrokerStateMachine(
            Epoch,
            maximumOperationHistory: maximumOperations);
        machine.ApplySignal(CodexCdpBrokerSignal.BeginReconciliation);
        machine.ApplySignal(CodexCdpBrokerSignal.NoCodexObserved);
        return machine;
    }

    private static CodexCdpBrokerStateMachine CreateManagedReadyMachine()
    {
        var machine = CreateIdleMachine(maximumOperations: 8);
        machine.ApplyCommand(Operation(
            CodexCdpBrokerCommandKind.StartManagedCodex,
            LaunchOperation));
        machine.ApplySignal(CodexCdpBrokerSignal.BeginCandidateLaunch, LaunchOperation);
        machine.ApplySignal(CodexCdpBrokerSignal.CandidateProcessStarted, LaunchOperation);
        machine.ApplySignal(CodexCdpBrokerSignal.CandidateOwnershipVerified, LaunchOperation);
        var ready = machine.ApplySignal(
            CodexCdpBrokerSignal.CdpHandshakeCompleted,
            LaunchOperation);
        Ensure(ready.Snapshot.State == CodexCdpBrokerState.ManagedReady, "test setup did not own Codex");
        return machine;
    }

    private static void LoseRaceAndReturnIdle(
        CodexCdpBrokerStateMachine machine,
        string operationId)
    {
        machine.ApplySignal(CodexCdpBrokerSignal.BeginCandidateLaunch, operationId);
        machine.ApplySignal(CodexCdpBrokerSignal.SingleInstanceRaceLost, operationId);
        machine.ApplySignal(CodexCdpBrokerSignal.BeginReconciliation);
        machine.ApplySignal(CodexCdpBrokerSignal.NoCodexObserved);
    }

    private static CodexCdpBrokerCommand Operation(
        CodexCdpBrokerCommandKind kind,
        string operationId) => new(kind, Epoch, operationId, null);

    private static void RunCase(
        string name,
        Action test,
        Action<bool, string> assert)
    {
        try
        {
            test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static TException Expect<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("Expected " + typeof(TException).Name + ".");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
