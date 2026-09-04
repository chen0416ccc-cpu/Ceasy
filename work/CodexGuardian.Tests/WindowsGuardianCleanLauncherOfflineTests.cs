using CodexGuardian.Broker;
using CodexGuardian.Control;
using CodexGuardian.Trust;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

internal static class WindowsGuardianCleanLauncherOfflineTests
{
    private const uint HandleFlagInherit = 0x00000001;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const uint SettlementProcessId = 0x1601;
    private const uint SettlementExitCode = 0xC0DE0016;
    private const int ErrorInvalidHandle = 6;
    private const string ChildReceiptKind = "windowsGuardianCleanLaunchChild";
    private static readonly TimeSpan CaseTimeout = TimeSpan.FromSeconds(15);

    internal static bool IsChildProbeInvocation(IReadOnlyList<string> args) =>
        args.Count > 0 &&
        string.Equals(
            args[0],
            WindowsGuardianCleanLauncherV1.ManagedBootstrapArgument,
            StringComparison.Ordinal);

    internal static async Task<int> RunChildProbeAsync(string[] args)
    {
        var failureStage = 70;
        try
        {
            if (args.Length != 3 ||
                !string.Equals(
                    args[1],
                    WindowsGuardianCleanLauncherV1.BootstrapHandleArgument,
                    StringComparison.Ordinal) ||
                !TryParseCanonicalHandle(args[2], out var bootstrapHandleValue))
            {
                return 64;
            }

            failureStage = 71;
            var bootstrapHandle = ToIntPtr(bootstrapHandleValue);
            var bootstrapInherited = IsInheritable(bootstrapHandle);
            ClearInheritance(bootstrapHandle);
            var bootstrapCleared = !IsInheritable(bootstrapHandle);
            byte[] frame;
            using (var handle = new SafeFileHandle(bootstrapHandle, ownsHandle: true))
            using (var stream = new FileStream(
                       handle,
                       FileAccess.Read,
                       bufferSize: 4096,
                       isAsync: false))
            {
                var prefix = new byte[GuardianBrokerBootstrapProtocolV1.LengthPrefixBytes];
                stream.ReadExactly(prefix);
                var payloadLength = System.Buffers.Binary.BinaryPrimitives
                    .ReadUInt32LittleEndian(prefix);
                if (payloadLength is 0 or > GuardianBrokerBootstrapProtocolV1.MaximumPayloadBytes)
                {
                    throw new InvalidDataException("The child bootstrap length is invalid.");
                }

                frame = new byte[checked(prefix.Length + (int)payloadLength)];
                prefix.CopyTo(frame, 0);
                stream.ReadExactly(frame.AsSpan(prefix.Length));
                if (stream.ReadByte() != -1)
                {
                    throw new InvalidDataException("The child bootstrap pipe has trailing bytes.");
                }
            }

            failureStage = 72;
            if (!GuardianBrokerBootstrapProtocolV1.TryParseFrame(
                    frame,
                    out var bootstrap,
                    out var reason) || bootstrap is null)
            {
                throw new InvalidDataException(
                    "The child bootstrap frame was rejected: " + reason + ".");
            }

            using var bootstrapOwner = bootstrap;
            failureStage = 73;
            CryptographicOperations.ZeroMemory(frame);
            var brokerHandleValue = bootstrapOwner.BrokerProcessHandle;
            var brokerHandle = ToIntPtr(brokerHandleValue);
            var brokerInherited = IsInheritable(brokerHandle);
            ClearInheritance(brokerHandle);
            var brokerCleared = !IsInheritable(brokerHandle);
            using var exactBroker = new SafeProcessHandle(brokerHandle, ownsHandle: true);
            var brokerProcessId = GetProcessId(exactBroker);
            if (brokerProcessId == 0)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The child could not resolve its inherited Broker process handle.");
            }

            failureStage = 74;
            var suffix = bootstrap.EndpointName[
                GuardianBrokerBootstrapProtocolV1.EndpointPrefix.Length..];
            var trapValue = ulong.Parse(
                suffix[..16],
                NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture);
            var trapAbsent = !GetHandleInformation(ToIntPtr(trapValue), out _) &&
                Marshal.GetLastWin32Error() == ErrorInvalidHandle;
            var environmentNames = Environment.GetEnvironmentVariables()
                .Keys.Cast<object>()
                .Select(value => value?.ToString() ?? string.Empty)
                .ToArray();
            var environmentClosed = environmentNames.All(name =>
                !name.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) &&
                !name.StartsWith("CORECLR_", StringComparison.OrdinalIgnoreCase) &&
                !name.StartsWith("COMPLUS_", StringComparison.OrdinalIgnoreCase) &&
                !name.StartsWith("NUGET_", StringComparison.OrdinalIgnoreCase) &&
                !name.StartsWith("MSBUILD", StringComparison.OrdinalIgnoreCase) &&
                !name.StartsWith("ELECTRON_", StringComparison.OrdinalIgnoreCase) &&
                !name.StartsWith("NODE_", StringComparison.OrdinalIgnoreCase));

            failureStage = 75;
            using var client = WindowsSameLogonNamedPipeClient.Connect(
                bootstrap.EndpointName,
                TimeSpan.FromSeconds(10),
                CancellationToken.None);
            failureStage = 76;
            var receipt = JsonSerializer.SerializeToUtf8Bytes(new
            {
                kind = ChildReceiptKind,
                childProcessId = Environment.ProcessId,
                brokerProcessId,
                bootstrapInherited,
                bootstrapCleared,
                brokerInherited,
                brokerCleared,
                trapAbsent,
                environmentClosed,
                workingDirectory = Environment.CurrentDirectory,
                argumentCount = args.Length
            });
            await WindowsNamedPipeMessageIO.WriteMessageAsync(
                    client.Stream,
                    receipt,
                    CancellationToken.None)
                .ConfigureAwait(false);
            failureStage = 77;
            _ = await WindowsNamedPipeMessageIO.ReadMessageAsync(
                    client.Stream,
                    64,
                    CancellationToken.None)
                .ConfigureAwait(false);
            return 2;
        }
        catch
        {
            return failureStage;
        }
    }

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "production Guardian clean launcher has one sealed job-owned process lease",
            TestProductionSurface,
            assert);
        RunCase(
            "assigned Guardian settlement terminates the exact job and consumes the epoch",
            TestAssignedSettlement,
            assert);
        RunCase(
            "assigned Guardian settlement accepts a terminate-false exit race",
            TestAssignedTerminationRace,
            assert);
        RunCase(
            "Guardian wait failure attempts termination and quarantines exact authority",
            TestWaitFailureQuarantine,
            assert);
        RunCase(
            "Guardian settlement timeout retains exact authority in quarantine",
            TestTimeoutQuarantine,
            assert);
        RunCase(
            "unassigned suspended Guardian rollback terminates only the exact process",
            TestUnassignedSettlement,
            assert);
        RunCase(
            "exited Guardian root with active descendants terminates the ownership job",
            TestExitedRootWithActiveDescendant,
            assert);
        RunCase(
            "Guardian identity cleanup failure retains process and job authority",
            TestCleanupFailureQuarantine,
            assert);
        RunCase(
            "Guardian exit facts are not relabeled by a later stop intent",
            TestExitFactsDoNotInferStopIntent,
            assert);
        RunCase(
            "Guardian native settlement exceptions enter sticky quarantine",
            TestUnexpectedNativeExceptionQuarantine,
            assert);
        RunCase(
            "Guardian settlement preserves exact process and job handles",
            TestExactHandleSettlement,
            assert);
        RunCase(
            "Guardian observer registration drains before handle release",
            TestObserverRegistrationLifecycle,
            assert);
        RunCase(
            "Guardian observer rejects a missing registered-wait authority",
            TestObserverNullRegistration,
            assert);
        RunCase(
            "Guardian observer registration failure retains authority for retry",
            TestObserverRegistrationFailureRetry,
            assert);
        RunCase(
            "Guardian observer attach rejects invalid completion without losing authority",
            TestObserverCompletionFailure,
            assert);
        await RunCaseAsync(
            "Guardian quarantine worker retries transient cleanup without reopening the epoch",
            TestFlakyCleanupWorkerAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "native Guardian clean launch restricts inheritance environment and job lifetime",
            TestNativeLaunchAsync,
            assert).ConfigureAwait(false);
    }

    private static void TestProductionSurface()
    {
        var leaseType = typeof(IBrokerOwnedGuardianProcessLeaseV1);
        var implementations = leaseType.Assembly.GetTypes()
            .Where(type => !type.IsAbstract && leaseType.IsAssignableFrom(type))
            .ToArray();
        var implementation = implementations.Single();
        var constructors = implementation.GetConstructors(
            System.Reflection.BindingFlags.Instance |
            System.Reflection.BindingFlags.NonPublic |
            System.Reflection.BindingFlags.Public);
        var sourcePath = ResolveAuthoritativeSourcePath(
            "CodexGuardian.Broker\\WindowsGuardianCleanLauncher.cs");
        var source = File.ReadAllText(sourcePath);
        var settlementSource = File.ReadAllText(ResolveAuthoritativeSourcePath(
            "CodexGuardian.Broker\\WindowsGuardianProcessSettlement.cs"));
        var constructorParameters = constructors.Single().GetParameters();
        var rollbackStop = source.IndexOf(
            "processRoot?.StopAsync(BrokerGuardianProcessStopRequestV1.LaunchRollback)",
            StringComparison.Ordinal);
        var candidateCleanup = source.IndexOf(
            "candidate?.Dispose()",
            StringComparison.Ordinal);
        Ensure(
            implementation.IsSealed && !implementation.IsVisible &&
            typeof(IAsyncDisposable).IsAssignableFrom(implementation) &&
            implementation.DeclaringType == typeof(WindowsGuardianCleanLauncherV1) &&
            implementation.GetConstructors(
                System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.Public).Length == 0 &&
            constructors.Length == 1 &&
            constructorParameters.Length == 1 &&
            constructorParameters[0].ParameterType == typeof(WindowsGuardianProcessRootV1) &&
            leaseType.GetProperty("Completion")?.PropertyType ==
                typeof(Task<BrokerGuardianProcessExitV1>) &&
            leaseType.GetMethod("StopAsync")?.ReturnType == typeof(Task) &&
            source.Contains("CreateSuspended", StringComparison.Ordinal) &&
            source.Contains("JobObjectLimitKillOnJobClose", StringComparison.Ordinal) &&
            source.Contains("ProcThreadAttributeHandleList", StringComparison.Ordinal) &&
            source.Contains("InheritedHandleCount = 2", StringComparison.Ordinal) &&
            source.Contains("CanonicalRuntimeConfigDev", StringComparison.Ordinal) &&
            rollbackStop >= 0 && candidateCleanup > rollbackStop &&
            settlementSource.Contains("RegisterWaitForSingleObject", StringComparison.Ordinal) &&
            settlementSource.Contains(
                ".WaitAsync(QuarantineLateObservationWait)",
                StringComparison.Ordinal) &&
            !settlementSource.Contains(
                "await observedExit.ConfigureAwait(false)",
                StringComparison.Ordinal) &&
            settlementSource.Contains("managed-guardian-process-launch-consumed", StringComparison.Ordinal) &&
            !settlementSource.Contains("Task.Delay(20)", StringComparison.Ordinal) &&
            !settlementSource.Contains("GetProcessById", StringComparison.Ordinal) &&
            !source.Contains("TerminateProcess(", StringComparison.Ordinal) &&
            !source.Contains("WaitForSingleObject(", StringComparison.Ordinal) &&
            !source.Contains("would reopen the managed probing namespace", StringComparison.Ordinal) &&
            !source.Contains("ProcessStartInfo", StringComparison.Ordinal) &&
            !source.Contains("GetProcessesByName", StringComparison.Ordinal) &&
            !source.Contains("entireProcessTree", StringComparison.Ordinal),
            "the production clean-launch lease or native transaction surface is bypassable");
    }

    private static string ResolveAuthoritativeSourcePath(string relativePath)
    {
        var currentDirectory = Path.GetFullPath(Directory.GetCurrentDirectory());
        var candidates = new[]
        {
            Path.Combine(currentDirectory, relativePath),
            Path.Combine(currentDirectory, "work", relativePath)
        };
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        throw new FileNotFoundException(
            "The authoritative Guardian source path could not be resolved from the project root or work root.",
            relativePath);
    }

    private static async Task TestNativeLaunchAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var runtimeRoot = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        var appHost = Path.Combine(runtimeRoot, "CodexGuardian.Tests.exe");
        var managedEntry = Path.Combine(runtimeRoot, "CodexGuardian.Tests.dll");
        var deps = Path.Combine(runtimeRoot, "CodexGuardian.Tests.deps.json");
        var runtimeConfig = Path.Combine(runtimeRoot, "CodexGuardian.Tests.runtimeconfig.json");
        var runtimeConfigDev = Path.Combine(
            runtimeRoot,
            "CodexGuardian.Tests.runtimeconfig.dev.json");
        Ensure(
            File.Exists(appHost) && File.Exists(managedEntry) &&
            File.Exists(deps) && File.Exists(runtimeConfig),
            "the fresh Tests apphost runtime is incomplete");
        var createdRuntimeConfigDev = EnsureCanonicalRuntimeConfigDev(runtimeConfigDev);
        try
        {

            using var trap = CreateInheritedEvent();
        var trapValue = checked((ulong)trap.DangerousGetHandle().ToInt64());
        var endpoint = GuardianBrokerBootstrapProtocolV1.EndpointPrefix +
            trapValue.ToString("x16", CultureInfo.InvariantCulture) +
            Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var challenge = Enumerable.Repeat((byte)0xBC, 32).ToArray();
        using var server = WindowsSameLogonNamedPipeServer.Create(endpoint);
        using var environment = new EnvironmentInjectionScope(new Dictionary<string, string>
        {
            ["DOTNET_STARTUP_HOOKS"] = @"D:\synthetic\startup-hook.dll",
            ["CORECLR_ENABLE_PROFILING"] = "1",
            ["COMPlus_ReadyToRun"] = "0",
            ["NUGET_PACKAGES"] = @"D:\synthetic\nuget",
            ["MSBUILDDEBUGONSTART"] = "1",
            ["ELECTRON_RUN_AS_NODE"] = "1",
            ["NODE_OPTIONS"] = "--require synthetic"
        });
        var release = new NativeTestReleaseAuthority(
            runtimeRoot,
            appHost,
             managedEntry,
             deps,
             runtimeConfig,
             runtimeConfigDev);
        var launcher = WindowsGuardianCleanLauncherV1.CreateForTests(release);
        WindowsGuardianCleanLaunchCandidateV1? candidate = null;
        IBrokerOwnedGuardianProcessLeaseV1? sourceLease = null;
        IBrokerOwnedGuardianProcessLeaseV1? successor = null;
        try
        {
            candidate = launcher.Launch(endpoint, nonce, challenge);
            using var timeout = new CancellationTokenSource(CaseTimeout);
            using var child = Process.GetProcessById(
                checked((int)candidate.InitialIdentity.ProcessId));
            var connectTask = server.WaitForConnectionAsync(timeout.Token);
            var exitTask = child.WaitForExitAsync(timeout.Token);
            var first = await Task.WhenAny(connectTask, exitTask).ConfigureAwait(false);
            if (ReferenceEquals(first, exitTask) && !server.IsConnected)
            {
                await exitTask.ConfigureAwait(false);
                throw new InvalidOperationException(
                    "The synthetic Guardian child exited before pipe admission; stage=" +
                    child.ExitCode.ToString(CultureInfo.InvariantCulture));
            }

            await connectTask.ConfigureAwait(false);
            var payload = await WindowsNamedPipeMessageIO.ReadMessageAsync(
                    server.Stream,
                    2048,
                    timeout.Token)
                .ConfigureAwait(false);
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            Ensure(
                root.GetProperty("kind").GetString() == ChildReceiptKind &&
                root.GetProperty("childProcessId").GetInt32() ==
                    checked((int)candidate.InitialIdentity.ProcessId) &&
                root.GetProperty("brokerProcessId").GetUInt32() ==
                    checked((uint)Environment.ProcessId) &&
                root.GetProperty("bootstrapInherited").GetBoolean() &&
                root.GetProperty("bootstrapCleared").GetBoolean() &&
                root.GetProperty("brokerInherited").GetBoolean() &&
                root.GetProperty("brokerCleared").GetBoolean() &&
                root.GetProperty("trapAbsent").GetBoolean() &&
                root.GetProperty("environmentClosed").GetBoolean() &&
                string.Equals(
                    root.GetProperty("workingDirectory").GetString(),
                    runtimeRoot,
                    StringComparison.OrdinalIgnoreCase) &&
                root.GetProperty("argumentCount").GetInt32() == 3,
                "the native child did not prove exact handle environment and working-directory closure");

            sourceLease = candidate.TakeProcessLeaseForTests();
            var processCompletion = sourceLease.Completion;
            Ensure(
                sourceLease.CleanEnvironmentVerified &&
                sourceLease.RuntimeNamespaceClosed &&
                sourceLease.Revalidate().ProcessId == candidate.InitialIdentity.ProcessId,
                "the concrete clean-launch lease did not retain its native proof");
            successor = sourceLease.TakeOwnership();
            Ensure(
                ReferenceEquals(processCompletion, successor.Completion),
                "moving the clean-launch lease changed its exact process completion task");
            sourceLease.Dispose();
            await sourceLease.DisposeAsync().ConfigureAwait(false);
            sourceLease = null;
            Ensure(
                IsProcessAlive(candidate.InitialIdentity.ProcessId),
                "disposing a moved process-lease alias killed the successor-owned child");
            await successor.DisposeAsync().ConfigureAwait(false);
            var exit = await processCompletion.WaitAsync(CaseTimeout).ConfigureAwait(false);
            Ensure(
                exit.ProcessId == candidate.InitialIdentity.ProcessId &&
                exit.ExitCode == SettlementExitCode &&
                exit.StopRequest == BrokerGuardianProcessStopRequestV1.None,
                "the concrete clean-launch lease did not publish exact process exit evidence");
            successor = null;
            await WaitForProcessExitAsync(candidate.InitialIdentity.ProcessId)
                .ConfigureAwait(false);
            Ensure(
                GetHandleInformation(trap, out var trapFlags) &&
                (trapFlags & HandleFlagInherit) != 0,
                "the child launch changed or closed the parent trap handle");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(challenge);
                try { successor?.Dispose(); } catch { }
                try { sourceLease?.Dispose(); } catch { }
                try { candidate?.Dispose(); } catch { }
            }
        }
        finally
        {
            if (createdRuntimeConfigDev && File.Exists(runtimeConfigDev))
            {
                File.Delete(runtimeConfigDev);
            }
        }
    }

    private static void TestAssignedSettlement()
    {
        var native = new FakeSettlementNative();
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitObject0);
        native.EnqueueJobQuery(activeProcesses: 0);
        var fixture = CreateSettlementFixture(native, assignedToJob: true);

        fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)
            .GetAwaiter()
            .GetResult();
        var exit = fixture.Root.Completion.GetAwaiter().GetResult();
        Ensure(
            native.TerminateJobCalls == 1 &&
            native.TerminateProcessCalls == 0 &&
            native.JobQueryCalls == 1 &&
            exit.ProcessId == SettlementProcessId &&
            exit.ExitCode == SettlementExitCode &&
            exit.StopRequest == BrokerGuardianProcessStopRequestV1.None &&
            fixture.Registry.Health == WindowsGuardianProcessRegistryHealthV1.Empty &&
            fixture.Registry.RetainedProcessCount == 0 &&
            fixture.Identity?.DisposeCount == 1 &&
            fixture.ProcessHandle.IsClosed && fixture.JobHandle.IsClosed &&
            native.Observer.DisposeCount == 1,
            "assigned Guardian settlement did not prove and release the entire exact job authority");

        try
        {
            _ = fixture.Registry.ReserveLaunch();
            throw new InvalidOperationException(
                "the capacity-one registry allowed a successor launch in the same Broker epoch");
        }
        catch (BrokerControlSessionException exception)
        {
            Ensure(
                exception.Code == "managed-guardian-process-launch-consumed",
                "the capacity-one registry returned the wrong consumed-launch failure");
        }
    }

    private static void TestAssignedTerminationRace()
    {
        var native = new FakeSettlementNative
        {
            TerminateJobSucceeds = false,
            TerminateJobError = 5
        };
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitObject0);
        native.EnqueueJobQuery(activeProcesses: 0);
        var fixture = CreateSettlementFixture(native, assignedToJob: true);

        fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.OwnerTerminal)
            .GetAwaiter()
            .GetResult();
        Ensure(
            native.TerminateJobCalls == 1 &&
            fixture.Registry.Health == WindowsGuardianProcessRegistryHealthV1.Empty &&
            fixture.Root.Completion.GetAwaiter().GetResult().StopRequest ==
                BrokerGuardianProcessStopRequestV1.None,
            "a terminate-false exact exit race was misclassified as an orphaned Guardian");
    }

    private static void TestWaitFailureQuarantine()
    {
        var native = new FakeSettlementNative
        {
            CompleteObserverOnTerminateJob = false
        };
        native.EnqueueWait(WaitFailed, error: ErrorInvalidHandle);
        native.EnqueueWait(WaitFailed, error: 87);
        var fixture = CreateSettlementFixture(native, assignedToJob: true);

        ExpectQuarantine(fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.HostCancellation));
        Ensure(
            native.TerminateJobCalls == 1 &&
            native.TerminateProcessCalls == 0 &&
            fixture.Registry.Health == WindowsGuardianProcessRegistryHealthV1.Quarantined &&
            fixture.Registry.RetainedProcessCount == 1 &&
            !fixture.ProcessHandle.IsClosed && !fixture.JobHandle.IsClosed &&
            fixture.Identity?.DisposeCount == 0,
            "WAIT_FAILED discarded or failed to use the exact Guardian termination authority");
    }

    private static void TestTimeoutQuarantine()
    {
        var native = new FakeSettlementNative
        {
            CompleteObserverOnTerminateJob = false
        };
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitTimeout);
        var fixture = CreateSettlementFixture(native, assignedToJob: true);

        ExpectQuarantine(fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.SessionEnded));
        Ensure(
            native.TerminateJobCalls == 1 &&
            fixture.Registry.Health == WindowsGuardianProcessRegistryHealthV1.Quarantined &&
            fixture.Registry.RetainedProcessCount == 1 &&
            !fixture.ProcessHandle.IsClosed && !fixture.JobHandle.IsClosed,
            "a bounded Guardian settlement timeout released the last exact authority");
    }

    private static void TestUnassignedSettlement()
    {
        var native = new FakeSettlementNative();
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitObject0);
        var fixture = CreateSettlementFixture(native, assignedToJob: false);

        fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.LaunchRollback)
            .GetAwaiter()
            .GetResult();
        var exit = fixture.Root.Completion.GetAwaiter().GetResult();
        Ensure(
            native.TerminateProcessCalls == 1 &&
            native.TerminateJobCalls == 0 &&
            native.JobQueryCalls == 0 &&
            exit.StopRequest == BrokerGuardianProcessStopRequestV1.None &&
            fixture.Registry.RetainedProcessCount == 0 &&
            fixture.ProcessHandle.IsClosed && fixture.JobHandle.IsClosed,
            "unassigned suspended rollback used anything other than its exact process authority");
    }

    private static void TestExitedRootWithActiveDescendant()
    {
        var native = new FakeSettlementNative();
        native.Observer.TrySetResult(9);
        native.EnqueueWait(WaitObject0);
        native.EnqueueJobQuery(activeProcesses: 1);
        native.EnqueueJobQuery(activeProcesses: 0);
        var fixture = CreateSettlementFixture(native, assignedToJob: true);

        fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)
            .GetAwaiter()
            .GetResult();
        Ensure(
            native.TerminateJobCalls == 1 &&
            native.JobQueryCalls == 2 &&
            fixture.Root.Completion.GetAwaiter().GetResult().ExitCode == 9 &&
            fixture.Registry.RetainedProcessCount == 0,
            "an exited Guardian root was treated as proof that its private job was empty");
    }

    private static void TestCleanupFailureQuarantine()
    {
        var native = new FakeSettlementNative();
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitObject0);
        native.EnqueueJobQuery(activeProcesses: 0);
        var fixture = CreateSettlementFixture(
            native,
            assignedToJob: true,
            identityDisposeFailure: new IOException("synthetic retained identity cleanup failure"));

        ExpectQuarantine(fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.Disposal));
        Ensure(
            fixture.Identity?.DisposeCount == 1 &&
            fixture.Registry.Health == WindowsGuardianProcessRegistryHealthV1.Quarantined &&
            fixture.Registry.RetainedProcessCount == 1 &&
            !fixture.ProcessHandle.IsClosed && !fixture.JobHandle.IsClosed,
            "identity cleanup failure released process or job authority before quarantine");
    }

    private static void TestExitFactsDoNotInferStopIntent()
    {
        var native = new FakeSettlementNative();
        native.Observer.TrySetResult(17);
        native.EnqueueWait(WaitObject0);
        native.EnqueueJobQuery(activeProcesses: 0);
        var fixture = CreateSettlementFixture(native, assignedToJob: true);

        fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.OwnerTerminal)
            .GetAwaiter()
            .GetResult();
        var exit = fixture.Root.Completion.GetAwaiter().GetResult();
        Ensure(
            exit.ExitCode == 17 &&
            exit.StopRequest == BrokerGuardianProcessStopRequestV1.None &&
            fixture.Registry.RetainedProcessCount == 0,
            "a later stop caller relabeled already observed Guardian exit facts");
    }

    private static void TestUnexpectedNativeExceptionQuarantine()
    {
        AssertUnexpectedNativeException(
            "initial wait",
            native => native.WaitException = new IOException("synthetic wait throw"),
            assignedToJob: true);
        AssertUnexpectedNativeException(
            "job termination",
            native =>
            {
                native.EnqueueWait(WaitTimeout);
                native.TerminateJobException = new IOException("synthetic terminate-job throw");
            },
            assignedToJob: true);
        AssertUnexpectedNativeException(
            "job query",
            native =>
            {
                native.Observer.TrySetResult(19);
                native.EnqueueWait(WaitObject0);
                native.JobQueryException = new IOException("synthetic job-query throw");
            },
            assignedToJob: true);
        AssertUnexpectedNativeException(
            "process termination",
            native =>
            {
                native.EnqueueWait(WaitTimeout);
                native.TerminateProcessException = new IOException(
                    "synthetic terminate-process throw");
            },
            assignedToJob: false);
        AssertUnexpectedNativeException(
            "exit code",
            native =>
            {
                native.EnqueueWait(WaitObject0);
                native.EnqueueJobQuery(activeProcesses: 0);
                native.ExitCodeException = new IOException("synthetic exit-code throw");
            },
            assignedToJob: true);
    }

    private static void AssertUnexpectedNativeException(
        string stage,
        Action<FakeSettlementNative> configure,
        bool assignedToJob)
    {
        var native = new FakeSettlementNative();
        configure(native);
        var fixture = CreateSettlementFixture(native, assignedToJob);
        var settlement = fixture.Root.StopAsync(
            BrokerGuardianProcessStopRequestV1.HostCancellation);
        ExpectQuarantine(settlement);
        Ensure(
            ReferenceEquals(
                settlement,
                fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)) &&
            fixture.Registry.Health == WindowsGuardianProcessRegistryHealthV1.Quarantined &&
            fixture.Registry.RetainedProcessCount == 1 &&
            !fixture.ProcessHandle.IsClosed && !fixture.JobHandle.IsClosed,
            stage + " exception bypassed sticky Guardian quarantine");
    }

    private static void TestExactHandleSettlement()
    {
        var native = new FakeSettlementNative();
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitObject0);
        native.EnqueueJobQuery(activeProcesses: 0);
        var fixture = CreateSettlementFixture(native, assignedToJob: true);

        fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)
            .GetAwaiter()
            .GetResult();
        Ensure(
            native.WaitProcessHandles.All(handle =>
                ReferenceEquals(handle, fixture.ProcessHandle)) &&
            ReferenceEquals(native.TerminateJobHandle, fixture.JobHandle) &&
            native.JobQueryHandles.All(handle =>
                ReferenceEquals(handle, fixture.JobHandle)),
            "Guardian settlement substituted a foreign process or job handle");
    }

    private static void TestObserverRegistrationLifecycle()
    {
        var processHandle = new SafeProcessHandle(new IntPtr(0x1611), ownsHandle: false);
        var platform = new FakeObserverPlatform();
        var observer = WindowsGuardianProcessSettlementNativeV1.CreateObserverForTests(
            processHandle,
            platform);
        platform.TriggerExit(31);
        Ensure(
            observer.Completion.GetAwaiter().GetResult() == 31 &&
            platform.Registration.UnregisterCalls == 0 &&
            !processHandle.IsClosed,
            "the Guardian observer callback released its exact handle before Dispose");

        platform.Registration.UnregisterResult = false;
        observer.Dispose();
        Ensure(
            platform.Registration.UnregisterCalls == 1 && processHandle.IsClosed,
            "the Guardian observer did not drain registration before exact handle release");
    }

    private static void TestObserverNullRegistration()
    {
        var processHandle = new SafeProcessHandle(new IntPtr(0x1614), ownsHandle: false);
        var platform = new FakeObserverPlatform
        {
            ReturnNullRegistration = true
        };
        try
        {
            _ = WindowsGuardianProcessSettlementNativeV1.CreateObserverForTests(
                processHandle,
                platform);
            throw new InvalidOperationException(
                "the Guardian observer accepted a missing registration authority");
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("no registration authority", StringComparison.Ordinal))
        {
        }

        Ensure(
            processHandle.IsClosed,
            "a missing observer registration leaked the duplicated Guardian process handle");
    }

    private static void TestObserverRegistrationFailureRetry()
    {
        var processHandle = new SafeProcessHandle(new IntPtr(0x1612), ownsHandle: false);
        var platform = new FakeObserverPlatform();
        var observer = WindowsGuardianProcessSettlementNativeV1.CreateObserverForTests(
            processHandle,
            platform);
        platform.TriggerExit(32);
        platform.Registration.UnregisterFailure = new IOException(
            "synthetic unregister failure");
        try
        {
            observer.Dispose();
            throw new InvalidOperationException(
                "the Guardian observer ignored unregister failure");
        }
        catch (IOException exception) when (
            exception.Message == "synthetic unregister failure")
        {
        }

        Ensure(
            !processHandle.IsClosed,
            "unregister failure released the duplicated Guardian process handle");
        platform.Registration.UnregisterFailure = null;
        observer.Dispose();
        Ensure(
            platform.Registration.UnregisterCalls == 2 && processHandle.IsClosed,
            "the Guardian observer could not retry a failed unregister transaction");
    }

    private static void TestObserverCompletionFailure()
    {
        AssertObserverCompletionFailure(throws: false);
        AssertObserverCompletionFailure(throws: true);
    }

    private static void AssertObserverCompletionFailure(bool throws)
    {
        var invalidObserver = new InvalidCompletionObserver(throws);
        var native = new FakeSettlementNative
        {
            ObserverOverride = invalidObserver
        };
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitObject0);
        var registry = WindowsGuardianProcessRegistryV1.CreateForTests(native);
        var root = registry.ReserveLaunch();
        var jobHandle = new SafeFileHandle(new IntPtr(0x1613), ownsHandle: false);
        var processHandle = new SafeProcessHandle(new IntPtr(0x1614), ownsHandle: false);
        root.AttachJob(jobHandle);
        root.AttachProcess(processHandle, SettlementProcessId);
        var rejected = false;
        try
        {
            root.StartObservation();
        }
        catch (Exception exception) when (
            exception is IOException or InvalidOperationException)
        {
            rejected = true;
        }

        Ensure(rejected, "the Guardian root accepted an invalid observer completion");
        ExpectQuarantine(root.StopAsync(BrokerGuardianProcessStopRequestV1.LaunchRollback));
        Ensure(
            registry.RetainedProcessCount == 1 &&
            invalidObserver.DisposeCount == 0 &&
            !processHandle.IsClosed && !jobHandle.IsClosed,
            "invalid observer completion escaped the quarantined root authority");
    }

    private static async Task TestFlakyCleanupWorkerAsync()
    {
        var native = new FakeSettlementNative();
        native.EnqueueWait(WaitTimeout);
        native.EnqueueWait(WaitObject0);
        native.EnqueueJobQuery(activeProcesses: 0);
        var fixture = CreateSettlementFixture(
            native,
            assignedToJob: true,
            identityDisposeFailure: new IOException("synthetic transient cleanup failure"),
            identityDisposeFailureCount: 1,
            startQuarantineWorker: true);

        ExpectQuarantine(fixture.Root.StopAsync(BrokerGuardianProcessStopRequestV1.Disposal));
        var stopwatch = Stopwatch.StartNew();
        while (fixture.Registry.RetainedProcessCount != 0 && stopwatch.Elapsed < CaseTimeout)
        {
            await Task.Delay(25).ConfigureAwait(false);
        }

        Ensure(
            fixture.Registry.Health == WindowsGuardianProcessRegistryHealthV1.Empty &&
            fixture.Registry.RetainedProcessCount == 0 &&
            fixture.Identity?.DisposeCount == 2 &&
            fixture.ProcessHandle.IsClosed && fixture.JobHandle.IsClosed,
            "the production quarantine worker did not drain transient cleanup failure");
        try
        {
            _ = fixture.Registry.ReserveLaunch();
            throw new InvalidOperationException(
                "late quarantine drain reopened the one-shot Guardian epoch");
        }
        catch (BrokerControlSessionException exception)
        {
            Ensure(
                exception.Code == "managed-guardian-process-launch-consumed",
                "late quarantine drain changed the one-shot launch failure");
        }
    }

    private static SettlementFixture CreateSettlementFixture(
        FakeSettlementNative native,
        bool assignedToJob,
        Exception? identityDisposeFailure = null,
        int identityDisposeFailureCount = int.MaxValue,
        bool startQuarantineWorker = false)
    {
        var registry = WindowsGuardianProcessRegistryV1.CreateForTests(
            native,
            startQuarantineWorker);
        var root = registry.ReserveLaunch();
        var jobHandle = new SafeFileHandle(new IntPtr(0x1601), ownsHandle: false);
        var processHandle = new SafeProcessHandle(new IntPtr(0x1602), ownsHandle: false);
        root.AttachJob(jobHandle);
        root.AttachProcess(processHandle, SettlementProcessId);
        root.StartObservation();

        FakeSettlementIdentityLease? identity = null;
        if (assignedToJob)
        {
            root.MarkAssignedToJob();
            identity = new FakeSettlementIdentityLease(
                CreateSettlementIdentity(),
                identityDisposeFailure,
                identityDisposeFailureCount);
            root.AttachIdentity(identity, identity.Capture());
            root.MarkLaunchVerified();
        }

        return new SettlementFixture(
            registry,
            root,
            jobHandle,
            processHandle,
            identity);
    }

    private static WindowsProcessIdentity CreateSettlementIdentity()
    {
        const string rootPath = @"D:\CodexData\CodexGuardian\synthetic-settlement";
        var releaseRoot = new WindowsReleaseRootIdentity(
            rootPath,
            FileAttributes.Directory,
            0x16011601,
            new string('A', 32),
            true);
        var artifacts = new[]
        {
            new WindowsArtifactIdentity(
                ReleaseArtifactKind.AppHostExe,
                "CodexGuardian.exe",
                Path.Combine(rootPath, "CodexGuardian.exe"),
                FileAttributes.Archive,
                4096,
                new string('B', 64),
                0x16011601,
                new string('B', 32),
                1,
                true)
        };
        var token = new WindowsTokenIdentity(
            "S-1-5-21-1601-1602-1603-1604",
            "S-1-5-5-160-161",
            1,
            0x0000000100001601UL,
            16,
            0x2000,
            WindowsTokenElevationType.Limited,
            false,
            false,
            null,
            false,
            WindowsTokenType.Primary,
            null);
        return new WindowsProcessIdentity(
            SettlementProcessId,
            DateTimeOffset.UnixEpoch.AddHours(16),
            16,
            token,
            WindowsAppModelIdentity.Unpackaged,
            artifacts[0].FinalPath,
            true,
            releaseRoot,
            artifacts);
    }

    private static void ExpectQuarantine(Task settlement)
    {
        try
        {
            settlement.GetAwaiter().GetResult();
        }
        catch (BrokerControlSessionException exception)
        {
            Ensure(
                exception.Code == "managed-guardian-process-quarantined",
                "Guardian settlement returned a non-quarantine failure");
            return;
        }

        throw new InvalidOperationException(
            "Guardian settlement unexpectedly reported cleanup success");
    }

    private static bool EnsureCanonicalRuntimeConfigDev(string path)
    {
        var canonical = new UTF8Encoding(false, true)
            .GetBytes("{\"runtimeOptions\":{}}\r\n");
        if (File.Exists(path))
        {
            Ensure(
                File.ReadAllBytes(path).AsSpan().SequenceEqual(canonical),
                "the existing Tests runtimeconfig.dev.json is not canonical");
            return false;
        }

        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        stream.Write(canonical);
        stream.Flush(flushToDisk: true);
        return true;
    }

    private static async Task WaitForProcessExitAsync(uint processId)
    {
        var deadline = DateTime.UtcNow + CaseTimeout;
        while (DateTime.UtcNow < deadline)
        {
            if (!IsProcessAlive(processId))
            {
                return;
            }

            await Task.Delay(50).ConfigureAwait(false);
        }

        throw new TimeoutException("The job-owned synthetic Guardian child remained alive.");
    }

    private static bool IsProcessAlive(uint processId)
    {
        try
        {
            using var process = Process.GetProcessById(checked((int)processId));
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static SafeWaitHandle CreateInheritedEvent()
    {
        var security = new SECURITY_ATTRIBUTES
        {
            nLength = checked((uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>()),
            bInheritHandle = 1
        };
        var handle = CreateEventW(ref security, manualReset: true, initialState: false, null);
        if (handle.IsInvalid || handle.IsClosed)
        {
            handle.Dispose();
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to create the inheritable trap event.");
        }

        return handle;
    }

    private static bool TryParseCanonicalHandle(string value, out ulong handle)
    {
        handle = 0;
        return value.Length is > 0 and <= 20 && value[0] != '0' &&
            value.All(char.IsAsciiDigit) &&
            ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out handle) &&
            handle <= (ulong)nuint.MaxValue;
    }

    private static IntPtr ToIntPtr(ulong value)
    {
        if (value == 0 || value > (ulong)nuint.MaxValue || value > long.MaxValue)
        {
            throw new InvalidDataException("An inherited handle value is invalid.");
        }

        return new IntPtr(checked((long)value));
    }

    private static bool IsInheritable(IntPtr handle) =>
        GetHandleInformation(handle, out var flags) &&
        (flags & HandleFlagInherit) != 0;

    private static void ClearInheritance(IntPtr handle)
    {
        if (!SetHandleInformation(handle, HandleFlagInherit, flags: 0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to clear child handle inheritance.");
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> action,
        Action<bool, string> assert)
    {
        try
        {
            await action().WaitAsync(CaseTimeout + TimeSpan.FromSeconds(5))
                .ConfigureAwait(false);
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static void RunCase(string name, Action action, Action<bool, string> assert)
    {
        try
        {
            action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record SettlementFixture(
        WindowsGuardianProcessRegistryV1 Registry,
        WindowsGuardianProcessRootV1 Root,
        SafeFileHandle JobHandle,
        SafeProcessHandle ProcessHandle,
        FakeSettlementIdentityLease? Identity);

    private sealed class FakeSettlementNative : IWindowsGuardianProcessSettlementNativeV1
    {
        private readonly Queue<(uint Result, int Error)> _waits = new();
        private readonly Queue<(bool Success, uint ActiveProcesses, int Error)> _jobQueries =
            new();

        internal FakeSettlementObserver Observer { get; } = new();

        internal IWindowsGuardianProcessExitObserverV1? ObserverOverride { get; set; }

        internal Exception? WaitException { get; set; }

        internal Exception? TerminateJobException { get; set; }

        internal Exception? TerminateProcessException { get; set; }

        internal Exception? JobQueryException { get; set; }

        internal Exception? ExitCodeException { get; set; }

        internal bool TerminateJobSucceeds { get; set; } = true;

        internal int TerminateJobError { get; set; }

        internal bool TerminateProcessSucceeds { get; set; } = true;

        internal int TerminateProcessError { get; set; }

        internal bool CompleteObserverOnTerminateJob { get; set; } = true;

        internal bool CompleteObserverOnTerminateProcess { get; set; } = true;

        internal uint ExitCode { get; set; } = SettlementExitCode;

        internal int TerminateJobCalls { get; private set; }

        internal int TerminateProcessCalls { get; private set; }

        internal int JobQueryCalls { get; private set; }

        internal List<SafeProcessHandle> WaitProcessHandles { get; } = new();

        internal List<SafeFileHandle> JobQueryHandles { get; } = new();

        internal SafeProcessHandle? TerminateProcessHandle { get; private set; }

        internal SafeFileHandle? TerminateJobHandle { get; private set; }

        internal SafeProcessHandle? ExitCodeHandle { get; private set; }

        internal void EnqueueWait(uint result, int error = 0) =>
            _waits.Enqueue((result, error));

        internal void EnqueueJobQuery(
            uint activeProcesses,
            bool success = true,
            int error = 0) =>
            _jobQueries.Enqueue((success, activeProcesses, error));

        public IWindowsGuardianProcessExitObserverV1 ObserveExactProcess(
            SafeProcessHandle processHandle) => ObserverOverride ?? Observer;

        public uint WaitProcess(
            SafeProcessHandle processHandle,
            uint milliseconds,
            out int win32Error)
        {
            WaitProcessHandles.Add(processHandle);
            if (WaitException is not null)
            {
                throw WaitException;
            }

            var result = _waits.Count == 0
                ? (WaitObject0, 0)
                : _waits.Dequeue();
            win32Error = result.Item2;
            return result.Item1;
        }

        public bool TryTerminateProcess(
            SafeProcessHandle processHandle,
            uint exitCode,
            out int win32Error)
        {
            TerminateProcessHandle = processHandle;
            TerminateProcessCalls++;
            if (TerminateProcessException is not null)
            {
                throw TerminateProcessException;
            }

            if (CompleteObserverOnTerminateProcess)
            {
                Observer.TrySetResult(ExitCode);
            }

            win32Error = TerminateProcessSucceeds ? 0 : TerminateProcessError;
            return TerminateProcessSucceeds;
        }

        public bool TryTerminateJob(
            SafeFileHandle jobHandle,
            uint exitCode,
            out int win32Error)
        {
            TerminateJobHandle = jobHandle;
            TerminateJobCalls++;
            if (TerminateJobException is not null)
            {
                throw TerminateJobException;
            }

            if (CompleteObserverOnTerminateJob)
            {
                Observer.TrySetResult(ExitCode);
            }

            win32Error = TerminateJobSucceeds ? 0 : TerminateJobError;
            return TerminateJobSucceeds;
        }

        public bool TryReadActiveJobProcessCount(
            SafeFileHandle jobHandle,
            out uint activeProcesses,
            out int win32Error)
        {
            JobQueryHandles.Add(jobHandle);
            JobQueryCalls++;
            if (JobQueryException is not null)
            {
                throw JobQueryException;
            }

            var result = _jobQueries.Count == 0
                ? (true, 0u, 0)
                : _jobQueries.Dequeue();
            activeProcesses = result.Item2;
            win32Error = result.Item3;
            return result.Item1;
        }

        public bool TryGetExitCode(
            SafeProcessHandle processHandle,
            out uint exitCode,
            out int win32Error)
        {
            ExitCodeHandle = processHandle;
            if (ExitCodeException is not null)
            {
                throw ExitCodeException;
            }

            exitCode = ExitCode;
            win32Error = 0;
            return true;
        }
    }

    private sealed class FakeSettlementObserver : IWindowsGuardianProcessExitObserverV1
    {
        private readonly TaskCompletionSource<uint> _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<uint> Completion => _completion.Task;

        internal int DisposeCount { get; private set; }

        internal void TrySetResult(uint exitCode) =>
            _completion.TrySetResult(exitCode);

        public void Dispose()
        {
            if (!Completion.IsCompleted)
            {
                throw new InvalidOperationException(
                    "a pending fake settlement observer cannot release authority");
            }

            DisposeCount++;
        }
    }

    private sealed class InvalidCompletionObserver : IWindowsGuardianProcessExitObserverV1
    {
        private readonly bool _throws;

        internal InvalidCompletionObserver(bool throws)
        {
            _throws = throws;
        }

        public Task<uint> Completion => _throws
            ? throw new IOException("synthetic observer completion failure")
            : null!;

        internal int DisposeCount { get; private set; }

        public void Dispose() => DisposeCount++;
    }

    private sealed class FakeObserverPlatform : IWindowsGuardianProcessObserverPlatformV1
    {
        private WaitOrTimerCallback? _callback;

        internal FakeRegisteredWait Registration { get; } = new();

        internal uint ExitCode { get; private set; }

        internal SafeProcessHandle? ExitCodeHandle { get; private set; }

        internal bool ReturnNullRegistration { get; set; }

        public IWindowsGuardianRegisteredWaitV1 Register(
            WaitHandle waitHandle,
            WaitOrTimerCallback callback)
        {
            _callback = callback ?? throw new ArgumentNullException(nameof(callback));
            Registration.WaitHandle = waitHandle;
            return ReturnNullRegistration ? null! : Registration;
        }

        public bool TryGetExitCode(
            SafeProcessHandle processHandle,
            out uint exitCode,
            out int win32Error)
        {
            ExitCodeHandle = processHandle;
            exitCode = ExitCode;
            win32Error = 0;
            return true;
        }

        internal void TriggerExit(uint exitCode)
        {
            ExitCode = exitCode;
            (_callback ?? throw new InvalidOperationException(
                "the fake observer platform has no registered callback"))(
                state: null,
                timedOut: false);
        }
    }

    private sealed class FakeRegisteredWait : IWindowsGuardianRegisteredWaitV1
    {
        internal WaitHandle? WaitHandle { get; set; }

        internal Exception? UnregisterFailure { get; set; }

        internal bool UnregisterResult { get; set; } = true;

        internal int UnregisterCalls { get; private set; }

        public bool Unregister(WaitHandle completionEvent)
        {
            UnregisterCalls++;
            if (UnregisterFailure is not null)
            {
                throw UnregisterFailure;
            }

            if (completionEvent is not EventWaitHandle eventWaitHandle)
            {
                throw new InvalidOperationException(
                    "the observer unregister completion is not signalable");
            }

            if (UnregisterResult)
            {
                _ = eventWaitHandle.Set();
            }

            return UnregisterResult;
        }
    }

    private sealed class FakeSettlementIdentityLease : IRetainedPeerIdentityLease
    {
        private readonly WindowsProcessIdentity _identity;
        private readonly Exception? _disposeFailure;
        private int _remainingDisposeFailures;
        private bool _disposed;

        internal FakeSettlementIdentityLease(
            WindowsProcessIdentity identity,
            Exception? disposeFailure,
            int disposeFailureCount)
        {
            _identity = identity;
            _disposeFailure = disposeFailure;
            _remainingDisposeFailures = disposeFailureCount;
            RetainedHandles = new RetainedReleaseHandleSet(
                identity.ReleaseRoot,
                identity.Artifacts.Select(artifact => artifact.RelativePath).ToArray());
        }

        public bool IsAlive => !_disposed;

        public RetainedReleaseHandleSet RetainedHandles { get; }

        internal int DisposeCount { get; private set; }

        public WindowsProcessIdentity Capture()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _identity;
        }

        public void Dispose()
        {
            DisposeCount++;
            if (_disposeFailure is not null && _remainingDisposeFailures != 0)
            {
                if (_remainingDisposeFailures != int.MaxValue)
                {
                    _remainingDisposeFailures--;
                }

                throw _disposeFailure;
            }

            _disposed = true;
        }
    }

    private sealed class NativeTestReleaseAuthority :
        IWindowsGuardianLaunchReleaseAuthorityV1
    {
        private readonly WindowsReleaseRootIdentity _root;
        private readonly IReadOnlyList<WindowsArtifactIdentity> _artifacts;

        internal NativeTestReleaseAuthority(
            string runtimeRootPath,
             string appHostPath,
             string managedEntryPath,
             string depsPath,
             string runtimeConfigPath,
             string runtimeConfigDevPath)
        {
            RuntimeRootPath = runtimeRootPath;
            AppHostPath = appHostPath;
            ManagedEntryPath = managedEntryPath;
            DepsPath = depsPath;
            RuntimeConfigPath = runtimeConfigPath;
            _root = new WindowsReleaseRootIdentity(
                runtimeRootPath,
                File.GetAttributes(runtimeRootPath),
                0x12345678,
                new string('A', 32),
                true);
            _artifacts = new[]
            {
                CreateArtifact(ReleaseArtifactKind.AppHostExe, appHostPath, '1'),
                 CreateArtifact(ReleaseArtifactKind.ManagedEntryDll, managedEntryPath, '2'),
                 CreateArtifact(ReleaseArtifactKind.DepsJson, depsPath, '3'),
                 CreateArtifact(ReleaseArtifactKind.RuntimeConfigJson, runtimeConfigPath, '4'),
                 CreateArtifact(ReleaseArtifactKind.RuntimeDependency, runtimeConfigDevPath, '5')
             };
        }

        public string RuntimeRootPath { get; }

        public string AppHostPath { get; }

        public string ManagedEntryPath { get; }

        public string DepsPath { get; }

        public string RuntimeConfigPath { get; }

        public IRetainedPeerIdentityLease OpenRetainedProcess(
            SafeProcessHandle exactProcessHandle) =>
            new NativeTestIdentityLease(
                WindowsPeerNative.DuplicateRestrictedProcessHandle(exactProcessHandle),
                _root,
                _artifacts);

        private static WindowsArtifactIdentity CreateArtifact(
            ReleaseArtifactKind kind,
            string path,
            char seed)
        {
            var item = new FileInfo(path);
            var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
            return new WindowsArtifactIdentity(
                kind,
                item.Name,
                item.FullName,
                item.Attributes,
                item.Length,
                hash,
                0x12345678,
                new string(seed, 32),
                1,
                true);
        }
    }

    private sealed class NativeTestIdentityLease : IRetainedPeerIdentityLease
    {
        private readonly object _gate = new();
        private readonly WindowsReleaseRootIdentity _root;
        private readonly IReadOnlyList<WindowsArtifactIdentity> _artifacts;
        private SafeProcessHandle? _process;

        internal NativeTestIdentityLease(
            SafeProcessHandle process,
            WindowsReleaseRootIdentity root,
            IReadOnlyList<WindowsArtifactIdentity> artifacts)
        {
            _process = process;
            _root = root;
            _artifacts = artifacts;
            RetainedHandles = new RetainedReleaseHandleSet(
                root,
                artifacts.Select(artifact => artifact.RelativePath).ToArray());
        }

        public bool IsAlive
        {
            get
            {
                lock (_gate)
                {
                    return WindowsPeerNative.IsProcessAlive(
                        _process ?? throw new ObjectDisposedException(
                            nameof(NativeTestIdentityLease)));
                }
            }
        }

        public RetainedReleaseHandleSet RetainedHandles { get; }

        public WindowsProcessIdentity Capture()
        {
            lock (_gate)
            {
                var process = _process ?? throw new ObjectDisposedException(
                    nameof(NativeTestIdentityLease));
                var launched = WindowsPeerNative.CaptureLaunchedPeer(process);
                return new WindowsProcessIdentity(
                    launched.ProcessId,
                    launched.CreationTimeUtc,
                    launched.SessionId,
                    launched.Token,
                    launched.AppModel,
                    launched.FinalImagePath,
                    true,
                    _root,
                    _artifacts);
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                _process?.Dispose();
                _process = null;
            }
        }
    }

    private sealed class EnvironmentInjectionScope : IDisposable
    {
        private readonly Dictionary<string, string?> _previous =
            new(StringComparer.OrdinalIgnoreCase);

        internal EnvironmentInjectionScope(IReadOnlyDictionary<string, string> values)
        {
            foreach (var pair in values)
            {
                _previous[pair.Key] = Environment.GetEnvironmentVariable(pair.Key);
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }
        }

        public void Dispose()
        {
            foreach (var pair in _previous)
            {
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        internal uint nLength;
        internal IntPtr lpSecurityDescriptor;
        internal int bInheritHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeWaitHandle CreateEventW(
        ref SECURITY_ATTRIBUTES eventAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState,
        string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetHandleInformation(IntPtr handle, out uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetHandleInformation(SafeHandle handle, out uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle process);
}
