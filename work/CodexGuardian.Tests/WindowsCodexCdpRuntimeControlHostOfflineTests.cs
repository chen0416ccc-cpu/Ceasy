using CodexGuardian.Broker;
using CodexGuardian.Control;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

internal static class WindowsCodexCdpRuntimeControlHostOfflineTests
{
    private const string OperationId = "operation-runtime-host-0001";
    private const string RuntimeId = "runtime-host-0123456789abcdef";
    private const string PackageFullName =
        "OpenAI.Codex_26.999.1234.0_x64__2p2nqsd0c76g0";
    private const string PackageFamilyName = "OpenAI.Codex_2p2nqsd0c76g0";
    private const string UserSid = "S-1-5-21-111-222-333-1001";
    private const uint SessionId = 7;
    private const int CandidateProcessId = 41001;
    private const int ExternalProcessId = 42001;
    private const string ExecutablePath =
        @"C:\Program Files\WindowsApps\OpenAI.Codex_26.999.1234.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe";
    private const string CodexExecutablePath =
        @"C:\Program Files\WindowsApps\OpenAI.Codex_26.999.1234.0_x64__2p2nqsd0c76g0\app\resources\codex.exe";
    private static readonly DateTimeOffset BaselineTime =
        new(2026, 8, 7, 1, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset CandidateCreationTime = BaselineTime.AddSeconds(1);
    private static readonly TimeSpan CaseTimeout = TimeSpan.FromSeconds(5);

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "runtime host reconciles only two stable complete inventories",
            TestReconcileMatrixAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime host loses a prelaunch race without launching a candidate",
            TestPreLaunchExternalRaceLostAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime host publishes one exact verified lease in strict call order",
            TestHappyExactStartAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "post-create typed launch failure retains and drains the exact candidate",
            TestPostCreateLaunchFailureRetentionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime host retains postlaunch and final identity failures",
            TestIdentityFailureRetentionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime host retains handshake and final inventory failures",
            TestHandshakeAndFinalInventoryRetentionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime host retains exact authority after cancellation before publication",
            TestCancellationRetentionAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "dead candidate plus independent Codex is one cleaned race loss",
            TestDeadExternalRaceLostAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "race-loss cleanup failure preserves the original startup failure",
            TestRaceLostCleanupFailurePrimaryAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "dead empty descendant and live external failures never become false race losses",
            TestNonRaceFailureClassificationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime lease arbitrates natural exit transport fault and EOF exit races",
            TestExitArbitrationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime lease and host share one concurrent cleanup",
            TestConcurrentDisposeAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "host disposal linearizes before the final lease publication",
            TestDisposeDuringFinalPublicationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "runtime cleanup failures remain sticky while all resources are attempted once",
            TestCleanupFailureAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "production read-only handshake bounds app targets and aliases transport completion",
            TestProductionHandshakeContractAsync,
            assert).ConfigureAwait(false);
    }

    private static async Task TestReconcileMatrixAsync()
    {
        await using (var empty = new HostFixture())
        {
            empty.Inventory.EnqueueStable(EmptyInventory());
            var result = await empty.Host.ReconcileAsync().ConfigureAwait(false);
            Ensure(result == CodexCdpRuntimeReconciliationKind.NoCodex,
                "two stable empty inventories did not reconcile to NoCodex");
            Ensure(
                empty.Inventory.CaptureCount == 2 &&
                empty.Verifier.RevalidateCount == 1 &&
                empty.Inventory.CandidateProcessIds.All(item => item is null),
                "empty reconciliation skipped its exact double-capture baseline barrier");
        }

        await using (var external = new HostFixture())
        {
            external.Inventory.EnqueueStable(ExternalInventory(external.Baseline));
            var result = await external.Host.ReconcileAsync().ConfigureAwait(false);
            Ensure(result == CodexCdpRuntimeReconciliationKind.ExternalCodexPresent,
                "stable external inventory was not classified as external Codex");
            Ensure(external.Launcher.LaunchCount == 0,
                "read-only reconciliation launched a candidate process");
        }

        await using (var codexOnly = new HostFixture())
        {
            codexOnly.Inventory.EnqueueStable(ExternalInventory(
                codexOnly.Baseline,
                useCodexExecutable: true));
            var result = await codexOnly.Host.ReconcileAsync().ConfigureAwait(false);
            Ensure(
                result == CodexCdpRuntimeReconciliationKind.ExternalCodexPresent &&
                codexOnly.Baseline.CodexExecutablePath == CodexExecutablePath,
                "an exact package codex.exe-only inventory was ignored");
        }

        await using (var indeterminate = new HostFixture())
        {
            indeterminate.Inventory.Enqueue(new WindowsCodexRuntimeInventorySnapshotV1(
                Array.Empty<WindowsCodexRuntimeInventoryProcessV1>(),
                Array.Empty<WindowsCodexRuntimeLineageProcessV1>(),
                "runtime-inventory-indeterminate"));
            var failure = await ExpectRuntimeCodeAsync(
                () => indeterminate.Host.ReconcileAsync().AsTask(),
                "runtime-inventory-indeterminate").ConfigureAwait(false);
            Ensure(failure.InnerException is null,
                "indeterminate inventory unexpectedly changed its bounded failure shape");
            Ensure(indeterminate.Inventory.CaptureCount == 1 &&
                   indeterminate.Verifier.RevalidateCount == 0,
                "indeterminate first inventory was revalidated or recaptured");
        }

        await using (var unstable = new HostFixture())
        {
            unstable.Inventory.Enqueue(EmptyInventory());
            unstable.Inventory.Enqueue(ExternalInventory(unstable.Baseline));
            await ExpectRuntimeCodeAsync(
                () => unstable.Host.ReconcileAsync().AsTask(),
                "runtime-inventory-unstable").ConfigureAwait(false);
            Ensure(unstable.Inventory.CaptureCount == 2 &&
                   unstable.Verifier.RevalidateCount == 1,
                "unstable inventory did not fail after one exact revalidation barrier");
        }
    }

    private static async Task TestPreLaunchExternalRaceLostAsync()
    {
        await using var fixture = new HostFixture();
        fixture.Inventory.EnqueueStable(ExternalInventory(fixture.Baseline));
        await using var result = await fixture.Host.StartManagedAsync(OperationId)
            .ConfigureAwait(false);
        Ensure(result.Kind == CodexCdpRuntimeStartKind.RaceLost,
            "prelaunch external Codex did not produce a disjoint race-lost result");
        Ensure(
            fixture.Launcher.LaunchCount == 0 &&
            fixture.ChannelFactory.CreateCount == 0 &&
            fixture.HandshakeFactory.CompleteCount == 0 &&
            fixture.Verifier.VerifyPostLaunchCount == 0,
            "prelaunch race loss created or verified a candidate");
    }

    private static async Task TestHappyExactStartAsync()
    {
        await using var fixture = new HostFixture();
        fixture.PrepareHappyStart();
        var lease = await fixture.StartOwnedLeaseAsync().ConfigureAwait(false);

        Ensure(
            fixture.Launcher.ExecutablePath == fixture.Baseline.ExecutablePath &&
            fixture.Launcher.WorkingDirectory == Path.GetDirectoryName(fixture.Baseline.ExecutablePath),
            "candidate launch did not use the exact pinned image and working directory");
        Ensure(
            fixture.Launcher.Arguments.SequenceEqual(
                new[]
                {
                    WindowsCrtPipeProcess.RemoteDebuggingPipeArgument,
                    WindowsCrtPipeProcess.RemoteDebuggingIoPipesArgumentPlaceholder
                },
                StringComparer.Ordinal),
            "candidate launch arguments escaped the exact two-pipe contract");
        Ensure(
            lease.Identity.RuntimeId == RuntimeId &&
            lease.Identity.LaunchOperationId == OperationId &&
            lease.Identity.ProcessId == fixture.Verified.ProcessId &&
            lease.Identity.CreationTimeUtc == fixture.Verified.CreationTimeUtc,
            "published lease identity was not derived from the final verified process");
        Ensure(
            fixture.Verifier.VerifyPreLaunchCount == 1 &&
            fixture.Verifier.VerifyPostLaunchCount == 2 &&
            fixture.Verifier.RevalidateCount == 4 &&
            fixture.Inventory.CaptureCount == 6 &&
            fixture.Process.DuplicateHandleCount == 2 &&
            fixture.HandshakeFactory.CompleteCount == 1,
            "happy start skipped a package process inventory or handshake authority gate");
        RequireOrdered(
            fixture.Calls.ToArray(),
            "verify-pre",
            "inventory-none-1",
            "revalidate-1",
            "inventory-none-2",
            "launch",
            "channel-create",
            "duplicate-handle-1",
            "verify-post-1",
            "inventory-41001-3",
            "revalidate-2",
            "inventory-41001-4",
            "handshake",
            "revalidate-3",
            "duplicate-handle-2",
            "verify-post-2",
            "inventory-41001-5",
            "revalidate-4",
            "inventory-41001-6",
            "runtime-id",
            "wait-exit-1");

        await lease.DisposeAsync().ConfigureAwait(false);
        Ensure(
            fixture.Handshake.DisposeCount == 1 &&
            fixture.Channel.DisposeCount == 1 &&
            fixture.Process.DisposeCount == 1,
            "successful lease cleanup did not release each exact authority once");
    }

    private static async Task TestPostCreateLaunchFailureRetentionAsync()
    {
        await using var fixture = new HostFixture();
        fixture.Inventory.EnqueueStable(EmptyInventory());
        var publicationFailure = new InvalidOperationException("post-create-publication-failure");
        fixture.Launcher.PostCreateFailure = publicationFailure;

        var observed = await CaptureFailureAsync(
            () => fixture.Host.StartManagedAsync(OperationId).AsTask()).ConfigureAwait(false);
        Ensure(
            observed is WindowsCodexCdpProcessLaunchExceptionV1 launchFailure &&
            ReferenceEquals(launchFailure.InnerException, publicationFailure),
            "typed post-create launch failure lost its original publication failure");
        Ensure(
            fixture.Launcher.LaunchCount == 1 &&
            fixture.ChannelFactory.CreateCount == 1 &&
            fixture.Verifier.VerifyPostLaunchCount == 0 &&
            fixture.Process.DisposeCount == 0,
            "post-create failure did not establish drain authority before retention");
        await AssertRetainedAsync(fixture).ConfigureAwait(false);
        await fixture.Host.DisposeAsync().ConfigureAwait(false);
        AssertCandidateCleanup(fixture, expectedHandshakeDisposals: 0);
    }

    private static async Task TestIdentityFailureRetentionAsync()
    {
        var postFailure = new InvalidOperationException("postlaunch-identity-failure");
        await using (var post = new HostFixture())
        {
            post.Inventory.EnqueueStable(EmptyInventory());
            post.Verifier.EnqueuePostFailure(postFailure);
            var observed = await CaptureFailureAsync(
                () => post.Host.StartManagedAsync(OperationId).AsTask()).ConfigureAwait(false);
            Ensure(ReferenceEquals(observed, postFailure),
                "postlaunch identity failure was wrapped or replaced while candidate remained live");
            await AssertRetainedAsync(post).ConfigureAwait(false);
            Ensure(post.HandshakeFactory.CompleteCount == 0,
                "postlaunch identity failure reached the CDP handshake");
            await post.Host.DisposeAsync().ConfigureAwait(false);
            AssertCandidateCleanup(post, expectedHandshakeDisposals: 0);
        }

        await using (var final = new HostFixture())
        {
            final.Inventory.EnqueueStable(EmptyInventory());
            final.Verifier.EnqueuePostResult(final.Verified);
            final.Inventory.EnqueueStable(CandidateInventory(final.Verified));
            var drifted = final.Verified with
            {
                CreationTimeUtc = final.Verified.CreationTimeUtc.AddSeconds(1),
                VerifiedAtUtc = final.Verified.VerifiedAtUtc.AddSeconds(1)
            };
            final.Verifier.EnqueuePostResult(drifted);
            await ExpectRuntimeCodeAsync(
                () => final.Host.StartManagedAsync(OperationId).AsTask(),
                "runtime-process-identity-drift").ConfigureAwait(false);
            await AssertRetainedAsync(final).ConfigureAwait(false);
            Ensure(final.Inventory.CaptureCount == 4,
                "final process drift continued into a final inventory publication gate");
            await final.Host.DisposeAsync().ConfigureAwait(false);
            AssertCandidateCleanup(final, expectedHandshakeDisposals: 1);
        }
    }

    private static async Task TestHandshakeAndFinalInventoryRetentionAsync()
    {
        var handshakeFailure = new InvalidOperationException("handshake-failure");
        await using (var handshake = new HostFixture())
        {
            handshake.Inventory.EnqueueStable(EmptyInventory());
            handshake.Verifier.EnqueuePostResult(handshake.Verified);
            handshake.Inventory.EnqueueStable(CandidateInventory(handshake.Verified));
            handshake.HandshakeFactory.Failure = handshakeFailure;
            var observed = await CaptureFailureAsync(
                () => handshake.Host.StartManagedAsync(OperationId).AsTask()).ConfigureAwait(false);
            Ensure(ReferenceEquals(observed, handshakeFailure),
                "live handshake failure was replaced before retained cleanup");
            await AssertRetainedAsync(handshake).ConfigureAwait(false);
            await handshake.Host.DisposeAsync().ConfigureAwait(false);
            AssertCandidateCleanup(handshake, expectedHandshakeDisposals: 0);
        }

        await using (var finalInventory = new HostFixture())
        {
            finalInventory.Inventory.EnqueueStable(EmptyInventory());
            finalInventory.Verifier.EnqueuePostResult(finalInventory.Verified);
            finalInventory.Inventory.EnqueueStable(CandidateInventory(finalInventory.Verified));
            finalInventory.Verifier.EnqueuePostResult(finalInventory.Verified);
            finalInventory.Inventory.Enqueue(new WindowsCodexRuntimeInventorySnapshotV1(
                Array.Empty<WindowsCodexRuntimeInventoryProcessV1>(),
                Array.Empty<WindowsCodexRuntimeLineageProcessV1>(),
                "runtime-final-inventory-failed"));
            await ExpectRuntimeCodeAsync(
                () => finalInventory.Host.StartManagedAsync(OperationId).AsTask(),
                "runtime-final-inventory-failed").ConfigureAwait(false);
            await AssertRetainedAsync(finalInventory).ConfigureAwait(false);
            Ensure(finalInventory.Handshake.DisposeCount == 0,
                "final inventory failure eagerly released the retained handshake authority");
            await finalInventory.Host.DisposeAsync().ConfigureAwait(false);
            AssertCandidateCleanup(finalInventory, expectedHandshakeDisposals: 1);
        }
    }

    private static async Task TestCancellationRetentionAsync()
    {
        await using var fixture = new HostFixture();
        fixture.PrepareHappyStart();
        using var cancellation = new CancellationTokenSource();
        fixture.RuntimeIdCallback = cancellation.Cancel;
        await ExpectAsync<OperationCanceledException>(
            () => fixture.Host.StartManagedAsync(OperationId, cancellation.Token).AsTask())
            .ConfigureAwait(false);
        Ensure(
            fixture.Process.DisposeCount == 0 &&
            fixture.Channel.DisposeCount == 0 &&
            fixture.Handshake.DisposeCount == 0,
            "cancellation after lease construction released authority before owner cleanup");
        await AssertRetainedAsync(fixture).ConfigureAwait(false);
        await fixture.Host.DisposeAsync().ConfigureAwait(false);
        AssertCandidateCleanup(fixture, expectedHandshakeDisposals: 1);
    }

    private static async Task TestDeadExternalRaceLostAsync()
    {
        await using var fixture = new HostFixture();
        fixture.Inventory.EnqueueStable(EmptyInventory());
        fixture.Process.CompleteExit(0);
        fixture.Verifier.EnqueuePostFailure(new InvalidOperationException("candidate-exited"));
        fixture.Inventory.EnqueueStable(ExternalInventory(fixture.Baseline));

        await using var result = await fixture.Host.StartManagedAsync(OperationId)
            .ConfigureAwait(false);
        Ensure(result.Kind == CodexCdpRuntimeStartKind.RaceLost,
            "dead candidate plus independent exact Codex was not classified as race lost");
        Ensure(
            fixture.Process.DisposeCount == 1 &&
            fixture.Channel.DisposeCount == 1 &&
            fixture.Handshake.DisposeCount == 0,
            "race-lost candidate was not cleaned exactly once before result publication");
        fixture.Inventory.EnqueueStable(ExternalInventory(fixture.Baseline));
        var reconciliation = await fixture.Host.ReconcileAsync().ConfigureAwait(false);
        Ensure(reconciliation == CodexCdpRuntimeReconciliationKind.ExternalCodexPresent,
            "clean race loss retained stale pre-publication authority");
    }

    private static async Task TestRaceLostCleanupFailurePrimaryAsync()
    {
        var fixture = new HostFixture();
        var original = new InvalidOperationException("candidate-exited-before-verification");
        var cleanup = new IOException("race-lost-channel-cleanup-failure");
        fixture.Inventory.EnqueueStable(EmptyInventory());
        fixture.Process.CompleteExit(5);
        fixture.Verifier.EnqueuePostFailure(original);
        fixture.Inventory.EnqueueStable(ExternalInventory(fixture.Baseline));
        fixture.Channel.DisposeFailure = cleanup;

        var observed = await CaptureFailureAsync(
            () => fixture.Host.StartManagedAsync(OperationId).AsTask()).ConfigureAwait(false);
        Ensure(ReferenceEquals(observed, original),
            "race-lost cleanup failure replaced the original startup failure");
        Ensure(
            ReferenceEquals(original.Data["runtime-control-secondary-failure"], cleanup),
            "race-lost cleanup failure was not retained as bounded secondary evidence");
        Ensure(
            fixture.Channel.DisposeCount == 1 && fixture.Process.DisposeCount == 1,
            "race-lost cleanup failure skipped the exact process authority cleanup attempt");
        var hostFailure = await CaptureFailureAsync(() => fixture.Host.DisposeAsync().AsTask())
            .ConfigureAwait(false);
        Ensure(ReferenceEquals(hostFailure, cleanup),
            "host did not retain the sticky failed cleanup authority");
    }

    private static async Task TestNonRaceFailureClassificationAsync()
    {
        await using (var deadEmpty = new HostFixture())
        {
            deadEmpty.Inventory.EnqueueStable(EmptyInventory());
            deadEmpty.Process.CompleteExit(2);
            deadEmpty.Verifier.EnqueuePostFailure(new InvalidOperationException("dead-empty"));
            deadEmpty.Inventory.EnqueueStable(EmptyInventory());
            await ExpectRuntimeCodeAsync(
                () => deadEmpty.Host.StartManagedAsync(OperationId).AsTask(),
                "runtime-candidate-exited-before-ready").ConfigureAwait(false);
            AssertCandidateCleanup(deadEmpty, expectedHandshakeDisposals: 0);
            deadEmpty.Inventory.EnqueueStable(EmptyInventory());
            var reconciliation = await deadEmpty.Host.ReconcileAsync().ConfigureAwait(false);
            Ensure(reconciliation == CodexCdpRuntimeReconciliationKind.NoCodex,
                "clean early exit retained stale pre-publication authority");
            await deadEmpty.Host.DisposeAsync().ConfigureAwait(false);
            AssertCandidateCleanup(deadEmpty, expectedHandshakeDisposals: 0);
        }

        await using (var descendant = new HostFixture())
        {
            descendant.Inventory.EnqueueStable(EmptyInventory());
            descendant.Process.CompleteExit(3);
            descendant.Verifier.EnqueuePostFailure(new InvalidOperationException("dead-descendant"));
            descendant.Inventory.EnqueueStable(DescendantInventory(descendant.Baseline));
            await ExpectRuntimeCodeAsync(
                () => descendant.Host.StartManagedAsync(OperationId).AsTask(),
                "runtime-candidate-lineage-ambiguous").ConfigureAwait(false);
            await AssertRetainedAsync(descendant).ConfigureAwait(false);
            await descendant.Host.DisposeAsync().ConfigureAwait(false);
            AssertCandidateCleanup(descendant, expectedHandshakeDisposals: 0);
        }

        var liveFailure = new InvalidOperationException("live-external-failure");
        await using (var liveExternal = new HostFixture())
        {
            liveExternal.Inventory.EnqueueStable(EmptyInventory());
            liveExternal.Verifier.EnqueuePostFailure(liveFailure);
            liveExternal.Inventory.EnqueueStable(ExternalInventory(liveExternal.Baseline));
            var observed = await CaptureFailureAsync(
                () => liveExternal.Host.StartManagedAsync(OperationId).AsTask()).ConfigureAwait(false);
            Ensure(ReferenceEquals(observed, liveFailure),
                "live failed candidate was mislabeled as a race loss because another Codex existed");
            Ensure(liveExternal.Inventory.PendingCount == 2,
                "live candidate failure performed dead-lineage race classification");
            await AssertRetainedAsync(liveExternal).ConfigureAwait(false);
            await liveExternal.Host.DisposeAsync().ConfigureAwait(false);
            AssertCandidateCleanup(liveExternal, expectedHandshakeDisposals: 0);
        }
    }

    private static async Task TestExitArbitrationAsync()
    {
        await using (var natural = new HostFixture())
        {
            natural.PrepareHappyStart();
            var lease = await natural.StartOwnedLeaseAsync().ConfigureAwait(false);
            natural.Process.CompleteExit(17);
            var exit = await lease.Exit.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                exit.Kind == CodexCdpRuntimeExitKind.Natural &&
                exit.ExitCode == 17 &&
                exit.FailureCode is null,
                "exact process exit did not win as one natural lease result");
            await lease.DisposeAsync().ConfigureAwait(false);
        }

        await using (var transportFault = new HostFixture())
        {
            transportFault.PrepareHappyStart();
            var lease = await transportFault.StartOwnedLeaseAsync().ConfigureAwait(false);
            transportFault.Channel.Fault(new InvalidDataException("transport-fault"));
            var exit = await lease.Exit.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                exit.Kind == CodexCdpRuntimeExitKind.Faulted &&
                exit.FailureCode == "cdp-transport-faulted" &&
                lease.IsAlive &&
                transportFault.Process.IsAlive,
                "live transport fault ended or naturalized the exact managed process");
            Ensure(transportFault.Delay.CallCount == 1,
                "live transport fault skipped the bounded natural-exit settle window");
            await lease.DisposeAsync().ConfigureAwait(false);
        }

        await using (var eofRace = new HostFixture())
        {
            eofRace.Delay.Block = true;
            eofRace.PrepareHappyStart();
            var lease = await eofRace.StartOwnedLeaseAsync().ConfigureAwait(false);
            eofRace.Channel.Complete();
            await eofRace.Delay.Entered.WaitAsync(CaseTimeout).ConfigureAwait(false);
            eofRace.Process.CompleteExit(19);
            eofRace.Delay.Release();
            var exit = await lease.Exit.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                exit.Kind == CodexCdpRuntimeExitKind.Natural && exit.ExitCode == 19,
                "process exit inside the settle window lost to a false transport fault");
            await lease.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task TestConcurrentDisposeAsync()
    {
        await using var fixture = new HostFixture();
        fixture.Handshake.BlockDispose = true;
        fixture.PrepareHappyStart();
        var lease = await fixture.StartOwnedLeaseAsync().ConfigureAwait(false);

        var first = lease.DisposeAsync().AsTask();
        await fixture.Handshake.DisposeEntered.WaitAsync(CaseTimeout).ConfigureAwait(false);
        var followers = Enumerable.Range(0, 6)
            .Select(_ => lease.DisposeAsync().AsTask())
            .ToArray();
        var hostDispose = fixture.Host.DisposeAsync().AsTask();
        Ensure(!first.IsCompleted && !hostDispose.IsCompleted,
            "concurrent lease or host cleanup reported success before the winner completed");
        fixture.Handshake.ReleaseDispose();
        await Task.WhenAll(followers.Append(first).Append(hostDispose)).WaitAsync(CaseTimeout)
            .ConfigureAwait(false);
        Ensure(
            fixture.Handshake.DisposeCount == 1 &&
            fixture.Channel.DisposeCount == 1 &&
            fixture.Process.DisposeCount == 1,
            "concurrent lease and host disposal duplicated a physical cleanup");
        await fixture.Host.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task TestDisposeDuringFinalPublicationAsync()
    {
        var fixture = new HostFixture();
        fixture.PrepareHappyStart();
        Task? hostDispose = null;
        fixture.RuntimeIdCallback = () => hostDispose = fixture.Host.DisposeAsync().AsTask();

        var observed = await CaptureFailureAsync(
            () => fixture.Host.StartManagedAsync(OperationId).AsTask()).ConfigureAwait(false);
        Ensure(observed is ObjectDisposedException or OperationCanceledException,
            "dispose during final publication returned or published an owned lease");
        Ensure(hostDispose is not null,
            "final-publication fixture did not start host disposal");
        await hostDispose!.WaitAsync(CaseTimeout).ConfigureAwait(false);
        AssertCandidateCleanup(fixture, expectedHandshakeDisposals: 1);
        Ensure(
            fixture.Process.DisposeCount == 1 && fixture.Channel.DisposeCount == 1,
            "late publication cleanup did not remain exact-once");
        await fixture.Host.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task TestCleanupFailureAsync()
    {
        var fixture = new HostFixture();
        var primary = new InvalidOperationException("handshake-cleanup-failure");
        var secondary = new IOException("channel-cleanup-failure");
        var tertiary = new InvalidDataException("process-cleanup-failure");
        fixture.Handshake.DisposeFailure = primary;
        fixture.Channel.DisposeFailure = secondary;
        fixture.Process.DisposeFailure = tertiary;
        fixture.PrepareHappyStart();
        var lease = await fixture.StartOwnedLeaseAsync().ConfigureAwait(false);

        var first = await CaptureFailureAsync(() => lease.DisposeAsync().AsTask())
            .ConfigureAwait(false);
        var second = await CaptureFailureAsync(() => lease.DisposeAsync().AsTask())
            .ConfigureAwait(false);
        var hostFailure = await CaptureFailureAsync(() => fixture.Host.DisposeAsync().AsTask())
            .ConfigureAwait(false);
        var repeatedHostFailure = await CaptureFailureAsync(() => fixture.Host.DisposeAsync().AsTask())
            .ConfigureAwait(false);
        Ensure(
            ReferenceEquals(first, primary) &&
            ReferenceEquals(second, primary) &&
            ReferenceEquals(hostFailure, primary) &&
            ReferenceEquals(repeatedHostFailure, primary),
            "cleanup callers did not observe one sticky primary failure");
        Ensure(primary.Data.Contains("runtime-candidate-cleanup-failure"),
            "candidate cleanup did not retain bounded secondary failure evidence");
        Ensure(
            fixture.Handshake.DisposeCount == 1 &&
            fixture.Channel.DisposeCount == 1 &&
            fixture.Process.DisposeCount == 1,
            "cleanup failure prevented a later resource attempt or duplicated disposal");
    }

    private static async Task TestProductionHandshakeContractAsync()
    {
        var calls = new ConcurrentQueue<string>();
        var commands = new ScriptedCommandTransport();
        commands.Enqueue(
            "Browser.getVersion",
            JsonSerializer.SerializeToElement(new { protocolVersion = "1.3" }));
        commands.Enqueue(
            "Target.getTargets",
            JsonSerializer.SerializeToElement(new { targetInfos = Array.Empty<object>() }));
        commands.Enqueue(
            "Target.getTargets",
            JsonSerializer.SerializeToElement(new
            {
                targetInfos = new[]
                {
                    new { type = "page", url = "app://codex/index.html" }
                }
            }));
        var delay = new FakeDelay(calls);
        var channel = new ScriptedChannel(commands);
        var factory = new ReadOnlyCodexCdpRuntimeHandshakeFactoryV1(delay, "app");
        var handshake = await factory.CompleteAsync(channel, CancellationToken.None)
            .ConfigureAwait(false);
        Ensure(
            commands.Methods.SequenceEqual(
                new[] { "Browser.getVersion", "Target.getTargets", "Target.getTargets" },
                StringComparer.Ordinal) &&
            delay.CallCount == 1 &&
            ReferenceEquals(handshake.Completion, channel.Completion),
            "production handshake skipped its fixed retry or completion binding contract");

        var process = new FakeProcess(CandidateProcessId, calls);
        var resources = new WindowsCodexCdpCandidateResourcesV1(process);
        resources.AttachChannel(channel);
        resources.AttachHandshake(handshake);
        var lease = new WindowsCodexCdpHandleLeaseV1(
            new CodexCdpRuntimeIdentity(
                RuntimeId,
                OperationId,
                CandidateProcessId,
                CandidateCreationTime),
            resources,
            delay,
            () => BaselineTime.AddMinutes(1),
            _ => { });
        channel.Fault(new IOException("production-transport-fault"));
        var exit = await lease.Exit.WaitAsync(CaseTimeout).ConfigureAwait(false);
        Ensure(
            exit.Kind == CodexCdpRuntimeExitKind.Faulted &&
            exit.FailureCode == "cdp-transport-faulted" &&
            lease.IsAlive,
            "shared production completion was mislabeled as a handshake fault");
        await lease.DisposeAsync().ConfigureAwait(false);

        var oversizedCommands = new ScriptedCommandTransport();
        oversizedCommands.Enqueue(
            "Browser.getVersion",
            JsonSerializer.SerializeToElement(new { protocolVersion = "1.3" }));
        oversizedCommands.Enqueue(
            "Target.getTargets",
            JsonSerializer.SerializeToElement(new
            {
                targetInfos = Enumerable.Range(0, 257)
                    .Select(index => new { type = "page", url = "app://codex/" + index })
                    .ToArray()
            }));
        await using (var oversizedChannel = new ScriptedChannel(oversizedCommands))
        {
            await ExpectRuntimeCodeAsync(
                () => factory.CompleteAsync(oversizedChannel, CancellationToken.None).AsTask(),
                "runtime-target-handshake-invalid").ConfigureAwait(false);
        }

        var malformedCommands = new ScriptedCommandTransport();
        malformedCommands.Enqueue(
            "Browser.getVersion",
            JsonSerializer.SerializeToElement(new { protocolVersion = "1.3" }));
        malformedCommands.Enqueue(
            "Target.getTargets",
            JsonSerializer.SerializeToElement(new
            {
                targetInfos = new[] { new { type = "page" } }
            }));
        await using (var malformedChannel = new ScriptedChannel(malformedCommands))
        {
            await ExpectRuntimeCodeAsync(
                () => factory.CompleteAsync(malformedChannel, CancellationToken.None).AsTask(),
                "runtime-target-handshake-invalid").ConfigureAwait(false);
        }
    }

    private static async Task AssertRetainedAsync(HostFixture fixture)
    {
        await ExpectRuntimeCodeAsync(
            () => fixture.Host.ReconcileAsync().AsTask(),
            "runtime-candidate-retained").ConfigureAwait(false);
        Ensure(
            fixture.Process.DisposeCount == 0 &&
            fixture.Channel.DisposeCount == 0,
            "retained authority was released by a later reconciliation attempt");
    }

    private static void AssertCandidateCleanup(
        HostFixture fixture,
        int expectedHandshakeDisposals)
    {
        Ensure(
            fixture.Process.DisposeCount == 1 &&
            fixture.Channel.DisposeCount == 1 &&
            fixture.Handshake.DisposeCount == expectedHandshakeDisposals,
            "retained candidate cleanup count changed");
    }

    private static WindowsCodexRuntimeInventorySnapshotV1 EmptyInventory() =>
        new(
            Array.Empty<WindowsCodexRuntimeInventoryProcessV1>(),
            Array.Empty<WindowsCodexRuntimeLineageProcessV1>());

    private static WindowsCodexRuntimeInventorySnapshotV1 ExternalInventory(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        bool useCodexExecutable = false) =>
        new(
            new[]
            {
                new WindowsCodexRuntimeInventoryProcessV1(
                    ExternalProcessId,
                    ParentProcessId: 100,
                    BaselineTime.Subtract(TimeSpan.FromMinutes(1)),
                    baseline.CurrentUserSid,
                    baseline.CurrentSessionId,
                    baseline.PackageFullName,
                    baseline.PackageFamilyName,
                    useCodexExecutable
                        ? baseline.CodexExecutablePath
                        : baseline.ExecutablePath)
            },
            Array.Empty<WindowsCodexRuntimeLineageProcessV1>());

    private static WindowsCodexRuntimeInventorySnapshotV1 CandidateInventory(
        CodexVerifiedProcessSnapshot verified) =>
        new(
            new[]
            {
                new WindowsCodexRuntimeInventoryProcessV1(
                    verified.ProcessId,
                    ParentProcessId: 100,
                    verified.CreationTimeUtc,
                    verified.UserSid,
                    verified.SessionId,
                    verified.PackageFullName,
                    verified.PackageFamilyName,
                    verified.ImagePath)
            },
            Array.Empty<WindowsCodexRuntimeLineageProcessV1>());

    private static WindowsCodexRuntimeInventorySnapshotV1 CandidateWithCodexChildInventory(
        CodexVerifiedProcessSnapshot verified,
        WindowsCodexRuntimePackageBaselineV1 baseline) =>
        new(
            new[]
            {
                new WindowsCodexRuntimeInventoryProcessV1(
                    verified.ProcessId,
                    ParentProcessId: 100,
                    verified.CreationTimeUtc,
                    verified.UserSid,
                    verified.SessionId,
                    verified.PackageFullName,
                    verified.PackageFamilyName,
                    verified.ImagePath),
                new WindowsCodexRuntimeInventoryProcessV1(
                    verified.ProcessId + 1,
                    ParentProcessId: verified.ProcessId,
                    verified.CreationTimeUtc.AddMilliseconds(1),
                    verified.UserSid,
                    verified.SessionId,
                    verified.PackageFullName,
                    verified.PackageFamilyName,
                    baseline.CodexExecutablePath)
            },
            new[]
            {
                new WindowsCodexRuntimeLineageProcessV1(
                    verified.ProcessId + 1,
                    ParentProcessId: verified.ProcessId,
                    verified.CreationTimeUtc.AddMilliseconds(1),
                    verified.UserSid,
                    verified.SessionId,
                    baseline.CodexExecutablePath)
            });

    private static WindowsCodexRuntimeInventorySnapshotV1 DescendantInventory(
        WindowsCodexRuntimePackageBaselineV1 baseline) =>
        new(
            Array.Empty<WindowsCodexRuntimeInventoryProcessV1>(),
            new[]
            {
                new WindowsCodexRuntimeLineageProcessV1(
                    ProcessId: CandidateProcessId + 1,
                    ParentProcessId: CandidateProcessId,
                    CandidateCreationTime.AddMilliseconds(1),
                    baseline.CurrentUserSid,
                    baseline.CurrentSessionId,
                    baseline.ExecutablePath)
            });

    private static void RequireOrdered(IReadOnlyList<string> calls, params string[] expected)
    {
        var previous = -1;
        foreach (var item in expected)
        {
            var current = IndexOf(calls, item, previous + 1);
            Ensure(current >= 0, "missing ordered runtime-host call: " + item);
            Ensure(current > previous, "runtime-host call order regressed at: " + item);
            previous = current;
        }
    }

    private static int IndexOf(IReadOnlyList<string> items, string value, int start)
    {
        for (var index = start; index < items.Count; index++)
        {
            if (string.Equals(items[index], value, StringComparison.Ordinal))
            {
                return index;
            }
        }

        return -1;
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await Task.Run(test).WaitAsync(CaseTimeout).ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + DescribeException(exception));
        }
    }

    private static async Task<WindowsCodexRuntimeControlException> ExpectRuntimeCodeAsync(
        Func<Task> action,
        string expectedCode)
    {
        var failure = await CaptureFailureAsync(action).ConfigureAwait(false);
        if (failure is not WindowsCodexRuntimeControlException runtime ||
            !string.Equals(runtime.Code, expectedCode, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected runtime code {expectedCode}, observed {DescribeException(failure)}");
        }

        return runtime;
    }

    private static async Task<TException> ExpectAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        var failure = await CaptureFailureAsync(action).ConfigureAwait(false);
        return failure as TException ?? throw new InvalidOperationException(
            $"Expected {typeof(TException).Name}, observed {DescribeException(failure)}");
    }

    private static async Task<Exception> CaptureFailureAsync(Func<Task> action)
    {
        try
        {
            await action().WaitAsync(CaseTimeout).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return exception;
        }

        throw new InvalidOperationException("The expected failure did not occur.");
    }

    private static string DescribeException(Exception exception)
    {
        var items = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            var code = current is WindowsCodexRuntimeControlException runtime
                ? "[" + runtime.Code + "] "
                : string.Empty;
            items.Add(code + current.GetType().Name + ": " + current.Message);
        }

        return string.Join(" -> ", items);
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class HostFixture : IAsyncDisposable
    {
        internal HostFixture()
        {
            Calls = new ConcurrentQueue<string>();
            Baseline = new WindowsCodexRuntimePackageBaselineV1(
                ExecutablePath,
                PackageFullName,
                PackageFamilyName,
                UserSid,
                SessionId,
                BaselineTime,
                verifiedSnapshot: null,
                codexExecutablePath: CodexExecutablePath);
            Verified = new CodexVerifiedProcessSnapshot(
                CandidateProcessId,
                UserSid,
                SessionId,
                PackageFullName,
                PackageFamilyName,
                ExecutablePath,
                CandidateCreationTime,
                CandidateCreationTime.AddMilliseconds(10));
            Verifier = new FakePackageVerifier(Baseline, Calls);
            Inventory = new FakeInventory(Calls);
            Process = new FakeProcess(CandidateProcessId, Calls);
            Launcher = new FakeLauncher(Process, Calls);
            Channel = new FakeChannel(Calls);
            ChannelFactory = new FakeChannelFactory(Channel, Calls);
            Handshake = new FakeHandshakeLease(Calls);
            HandshakeFactory = new FakeHandshakeFactory(Handshake, Calls);
            Delay = new FakeDelay(Calls);
            Host = new WindowsCodexCdpRuntimeControlHostV1(
                Verifier,
                Inventory,
                Launcher,
                ChannelFactory,
                HandshakeFactory,
                Delay,
                () => BaselineTime.AddMinutes(1),
                () =>
                {
                    Calls.Enqueue("runtime-id");
                    RuntimeIdCallback?.Invoke();
                    return RuntimeId;
                });
        }

        internal ConcurrentQueue<string> Calls { get; }

        internal WindowsCodexRuntimePackageBaselineV1 Baseline { get; }

        internal CodexVerifiedProcessSnapshot Verified { get; }

        internal FakePackageVerifier Verifier { get; }

        internal FakeInventory Inventory { get; }

        internal FakeProcess Process { get; }

        internal FakeLauncher Launcher { get; }

        internal FakeChannel Channel { get; }

        internal FakeChannelFactory ChannelFactory { get; }

        internal FakeHandshakeLease Handshake { get; }

        internal FakeHandshakeFactory HandshakeFactory { get; }

        internal FakeDelay Delay { get; }

        internal WindowsCodexCdpRuntimeControlHostV1 Host { get; }

        internal Action? RuntimeIdCallback { get; set; }

        internal void PrepareHappyStart()
        {
            Inventory.EnqueueStable(EmptyInventory());
            Verifier.EnqueuePostResult(Verified);
            Inventory.EnqueueStable(CandidateInventory(Verified));
            Verifier.EnqueuePostResult(Verified);
            Inventory.EnqueueStable(CandidateWithCodexChildInventory(Verified, Baseline));
        }

        internal async Task<WindowsCodexCdpHandleLeaseV1> StartOwnedLeaseAsync()
        {
            await using var result = await Host.StartManagedAsync(OperationId).ConfigureAwait(false);
            Ensure(result.Kind == CodexCdpRuntimeStartKind.Owned,
                "fixture start did not return an owned lease");
            return (WindowsCodexCdpHandleLeaseV1)result.TakeOwnedLease();
        }

        public ValueTask DisposeAsync() => Host.DisposeAsync();
    }

    private sealed class FakePackageVerifier(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        ConcurrentQueue<string> calls) : IWindowsCodexRuntimePackageVerifierV1
    {
        private readonly Queue<Func<CodexVerifiedProcessSnapshot>> _postLaunch = new();
        private int _postLaunchCount;
        private int _preLaunchCount;
        private int _revalidateCount;

        internal int VerifyPreLaunchCount => Volatile.Read(ref _preLaunchCount);

        internal int VerifyPostLaunchCount => Volatile.Read(ref _postLaunchCount);

        internal int RevalidateCount => Volatile.Read(ref _revalidateCount);

        internal Action<int>? RevalidateCallback { get; set; }

        public WindowsCodexRuntimePackageBaselineV1 VerifyPreLaunch()
        {
            Interlocked.Increment(ref _preLaunchCount);
            calls.Enqueue("verify-pre");
            return baseline;
        }

        public void RevalidateBaseline(WindowsCodexRuntimePackageBaselineV1 observed)
        {
            Ensure(ReferenceEquals(observed, baseline), "fake verifier received another baseline");
            var count = Interlocked.Increment(ref _revalidateCount);
            calls.Enqueue("revalidate-" + count);
            RevalidateCallback?.Invoke(count);
        }

        public CodexVerifiedProcessSnapshot VerifyPostLaunch(
            WindowsCodexRuntimePackageBaselineV1 observed,
            int expectedProcessId,
            SafeProcessHandle retainedProcessHandle)
        {
            Ensure(ReferenceEquals(observed, baseline), "postlaunch verifier baseline changed");
            Ensure(expectedProcessId == CandidateProcessId, "postlaunch verifier PID changed");
            ArgumentNullException.ThrowIfNull(retainedProcessHandle);
            var count = Interlocked.Increment(ref _postLaunchCount);
            calls.Enqueue("verify-post-" + count);
            if (_postLaunch.Count == 0)
            {
                throw new InvalidOperationException("fake-postlaunch-result-exhausted");
            }

            return _postLaunch.Dequeue().Invoke();
        }

        internal void EnqueuePostResult(CodexVerifiedProcessSnapshot result) =>
            _postLaunch.Enqueue(() => result);

        internal void EnqueuePostFailure(Exception failure) =>
            _postLaunch.Enqueue(() => throw failure);
    }

    private sealed class FakeInventory(ConcurrentQueue<string> calls)
        : IWindowsCodexRuntimeInventoryV1
    {
        private readonly Queue<WindowsCodexRuntimeInventorySnapshotV1> _snapshots = new();
        private int _captureCount;

        internal int CaptureCount => Volatile.Read(ref _captureCount);

        internal int PendingCount => _snapshots.Count;

        internal List<int?> CandidateProcessIds { get; } = new();

        public ValueTask<WindowsCodexRuntimeInventorySnapshotV1> CaptureAsync(
            WindowsCodexRuntimePackageBaselineV1 baseline,
            int? candidateProcessId,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(baseline);
            cancellationToken.ThrowIfCancellationRequested();
            var count = Interlocked.Increment(ref _captureCount);
            CandidateProcessIds.Add(candidateProcessId);
            calls.Enqueue("inventory-" + (candidateProcessId?.ToString() ?? "none") + "-" + count);
            if (_snapshots.Count == 0)
            {
                throw new InvalidOperationException("fake-inventory-result-exhausted");
            }

            return ValueTask.FromResult(_snapshots.Dequeue());
        }

        internal void Enqueue(WindowsCodexRuntimeInventorySnapshotV1 snapshot) =>
            _snapshots.Enqueue(snapshot);

        internal void EnqueueStable(WindowsCodexRuntimeInventorySnapshotV1 snapshot)
        {
            _snapshots.Enqueue(snapshot);
            _snapshots.Enqueue(snapshot);
        }
    }

    private sealed class FakeLauncher(
        FakeProcess process,
        ConcurrentQueue<string> calls) : IWindowsCodexCdpProcessLauncherV1
    {
        private int _launchCount;

        internal int LaunchCount => Volatile.Read(ref _launchCount);

        internal string? ExecutablePath { get; private set; }

        internal string? WorkingDirectory { get; private set; }

        internal IReadOnlyList<string> Arguments { get; private set; } = Array.Empty<string>();

        internal Exception? PostCreateFailure { get; set; }

        public IWindowsCodexCdpLaunchedProcessV1 Launch(
            string executablePath,
            IReadOnlyList<string> arguments,
            string workingDirectory)
        {
            Interlocked.Increment(ref _launchCount);
            calls.Enqueue("launch");
            ExecutablePath = executablePath;
            WorkingDirectory = workingDirectory;
            Arguments = arguments.ToArray();
            if (PostCreateFailure is not null)
            {
                throw new WindowsCodexCdpProcessLaunchExceptionV1(process, PostCreateFailure);
            }

            return process;
        }
    }

    private sealed class FakeProcess : IWindowsCodexCdpLaunchedProcessV1
    {
        private readonly ConcurrentQueue<string> _calls;
        private readonly TaskCompletionSource<int> _exit = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _disposeSync = new();
        private Task? _disposeTask;
        private int _alive = 1;
        private int _disposeCount;
        private int _duplicateHandleCount;
        private int _waitCount;

        internal FakeProcess(int processId, ConcurrentQueue<string> calls)
        {
            ProcessId = processId;
            _calls = calls;
            ReadStream = new MemoryStream();
            WriteStream = new MemoryStream();
        }

        public int ProcessId { get; }

        public Stream ReadStream { get; }

        public Stream WriteStream { get; }

        public bool IsAlive => Volatile.Read(ref _alive) != 0;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal int DuplicateHandleCount => Volatile.Read(ref _duplicateHandleCount);

        internal Exception? DisposeFailure { get; set; }

        public SafeProcessHandle DuplicateRetainedProcessHandleForVerification()
        {
            var count = Interlocked.Increment(ref _duplicateHandleCount);
            _calls.Enqueue("duplicate-handle-" + count);
            return new SafeProcessHandle(IntPtr.Zero, ownsHandle: false);
        }

        public Task<int> WaitForExitAsync(CancellationToken cancellationToken)
        {
            var count = Interlocked.Increment(ref _waitCount);
            _calls.Enqueue("wait-exit-" + count);
            return _exit.Task.WaitAsync(cancellationToken);
        }

        internal void CompleteExit(int exitCode)
        {
            Interlocked.Exchange(ref _alive, 0);
            _exit.TrySetResult(exitCode);
        }

        public ValueTask DisposeAsync()
        {
            lock (_disposeSync)
            {
                _disposeTask ??= DisposeCoreAsync();
                return new ValueTask(_disposeTask);
            }
        }

        private Task DisposeCoreAsync()
        {
            Interlocked.Increment(ref _disposeCount);
            _calls.Enqueue("process-dispose");
            return DisposeFailure is null
                ? Task.CompletedTask
                : Task.FromException(DisposeFailure);
        }
    }

    private sealed class FakeChannelFactory(
        FakeChannel channel,
        ConcurrentQueue<string> calls) : IWindowsCodexCdpChannelFactoryV1
    {
        private int _createCount;

        internal int CreateCount => Volatile.Read(ref _createCount);

        public IWindowsCodexCdpChannelV1 Create(IWindowsCodexCdpLaunchedProcessV1 process)
        {
            ArgumentNullException.ThrowIfNull(process);
            Interlocked.Increment(ref _createCount);
            calls.Enqueue("channel-create");
            return channel;
        }
    }

    private sealed class FakeChannel(ConcurrentQueue<string> calls) : IWindowsCodexCdpChannelV1
    {
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _disposeSync = new();
        private Task? _disposeTask;
        private int _disposeCount;

        public ICdpCommandTransport Commands { get; } = new RejectingCommandTransport();

        public Task Completion => _completion.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal Exception? DisposeFailure { get; set; }

        internal void Complete() => _completion.TrySetResult();

        internal void Fault(Exception failure) => _completion.TrySetException(failure);

        public ValueTask DisposeAsync()
        {
            lock (_disposeSync)
            {
                _disposeTask ??= DisposeCoreAsync();
                return new ValueTask(_disposeTask);
            }
        }

        private Task DisposeCoreAsync()
        {
            Interlocked.Increment(ref _disposeCount);
            calls.Enqueue("channel-dispose");
            return DisposeFailure is null
                ? Task.CompletedTask
                : Task.FromException(DisposeFailure);
        }
    }

    private sealed class FakeHandshakeFactory(
        FakeHandshakeLease lease,
        ConcurrentQueue<string> calls) : ICodexCdpRuntimeHandshakeFactoryV1
    {
        private int _completeCount;

        internal int CompleteCount => Volatile.Read(ref _completeCount);

        internal Exception? Failure { get; set; }

        public ValueTask<ICodexCdpRuntimeHandshakeLeaseV1> CompleteAsync(
            IWindowsCodexCdpChannelV1 channel,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(channel);
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref _completeCount);
            calls.Enqueue("handshake");
            return Failure is null
                ? ValueTask.FromResult<ICodexCdpRuntimeHandshakeLeaseV1>(lease)
                : ValueTask.FromException<ICodexCdpRuntimeHandshakeLeaseV1>(Failure);
        }
    }

    private sealed class FakeHandshakeLease(ConcurrentQueue<string> calls)
        : ICodexCdpRuntimeHandshakeLeaseV1
    {
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _disposeEntered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseDispose = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _disposeSync = new();
        private Task? _disposeTask;
        private int _disposeCount;

        public Task Completion => _completion.Task;

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal Task DisposeEntered => _disposeEntered.Task;

        internal bool BlockDispose { get; set; }

        internal Exception? DisposeFailure { get; set; }

        internal void Fault(Exception failure) => _completion.TrySetException(failure);

        internal void ReleaseDispose() => _releaseDispose.TrySetResult();

        public ValueTask DisposeAsync()
        {
            lock (_disposeSync)
            {
                _disposeTask ??= DisposeCoreAsync();
                return new ValueTask(_disposeTask);
            }
        }

        private async Task DisposeCoreAsync()
        {
            Interlocked.Increment(ref _disposeCount);
            calls.Enqueue("handshake-dispose");
            _disposeEntered.TrySetResult();
            if (BlockDispose)
            {
                await _releaseDispose.Task.ConfigureAwait(false);
            }

            if (DisposeFailure is not null)
            {
                throw DisposeFailure;
            }
        }
    }

    private sealed class FakeDelay(ConcurrentQueue<string> calls) : IWindowsCodexRuntimeDelayV1
    {
        private readonly TaskCompletionSource _entered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _callCount;

        internal int CallCount => Volatile.Read(ref _callCount);

        internal Task Entered => _entered.Task;

        internal bool Block { get; set; }

        internal void Release() => _release.TrySetResult();

        public async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            Ensure(delay > TimeSpan.Zero, "lease requested a non-positive settle delay");
            Interlocked.Increment(ref _callCount);
            calls.Enqueue("delay");
            _entered.TrySetResult();
            if (Block)
            {
                await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private sealed class ScriptedChannel(ScriptedCommandTransport commands)
        : IWindowsCodexCdpChannelV1
    {
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _disposed;

        public ICdpCommandTransport Commands { get; } = commands;

        public Task Completion => _completion.Task;

        internal void Fault(Exception failure) => _completion.TrySetException(failure);

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _completion.TrySetResult();
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class ScriptedCommandTransport : ICdpCommandTransport
    {
        private readonly Queue<(string Method, JsonElement Result)> _results = new();
        private readonly Channel<JsonElement> _notifications = Channel.CreateUnbounded<JsonElement>();

        internal List<string> Methods { get; } = new();

        public ChannelReader<JsonElement> Notifications => _notifications.Reader;

        internal void Enqueue(string method, JsonElement result) =>
            _results.Enqueue((method, result));

        public Task<JsonElement> SendCommandAsync(
            string method,
            object? parameters = null,
            TimeSpan? timeout = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Ensure(parameters is null, "production handshake sent unexpected CDP parameters");
            Ensure(
                timeout.HasValue && timeout.Value > TimeSpan.Zero,
                "production handshake omitted its bounded timeout");
            Ensure(_results.Count > 0, "production handshake exhausted scripted replies");
            var next = _results.Dequeue();
            Ensure(string.Equals(next.Method, method, StringComparison.Ordinal),
                "production handshake changed its fixed command order");
            Methods.Add(method);
            return Task.FromResult(next.Result);
        }

        public Task<JsonElement> SendSessionCommandAsync(
            string sessionId,
            string method,
            object? parameters = null,
            TimeSpan? timeout = null,
            CancellationToken cancellationToken = default) =>
            Task.FromException<JsonElement>(
                new InvalidOperationException("production handshake used a session command"));
    }

    private sealed class RejectingCommandTransport : ICdpCommandTransport
    {
        private readonly Channel<JsonElement> _notifications = Channel.CreateUnbounded<JsonElement>();

        public ChannelReader<JsonElement> Notifications => _notifications.Reader;

        public Task<JsonElement> SendCommandAsync(
            string method,
            object? parameters = null,
            TimeSpan? timeout = null,
            CancellationToken cancellationToken = default) =>
            Task.FromException<JsonElement>(new NotSupportedException("fake-command-transport"));

        public Task<JsonElement> SendSessionCommandAsync(
            string sessionId,
            string method,
            object? parameters = null,
            TimeSpan? timeout = null,
            CancellationToken cancellationToken = default) =>
            Task.FromException<JsonElement>(new NotSupportedException("fake-command-transport"));
    }
}
