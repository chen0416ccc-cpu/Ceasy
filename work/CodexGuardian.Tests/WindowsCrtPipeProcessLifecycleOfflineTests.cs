using CodexGuardian.Control;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal static class WindowsCrtPipeProcessLifecycleOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "Codex child environment uses one sorted minimal Unicode allowlist",
            TestMinimalEnvironmentBlockAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "Codex child environment rejects ambiguous or unbounded allowed values",
            TestEnvironmentBlockValidationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "post-create publication failure transfers the exact retained candidate",
            TestRetainedLaunchPublicationAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "sync and async process cleanup share one sticky disposal task",
            TestStickyDisposalSuccessAsync,
            assert).ConfigureAwait(false);
        await RunCaseAsync(
            "process cleanup preserves one primary and bounded secondary failures",
            TestStickyDisposalFailureAsync,
            assert).ConfigureAwait(false);
    }

    private static Task TestMinimalEnvironmentBlockAsync()
    {
        var source = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["SystemRoot"] = @"D:\AttackerWindows",
            ["WINDIR"] = @"E:\InjectedWindows",
            ["ComSpec"] = @"D:\Injected\cmd.exe",
            ["PATH"] = @"D:\InjectedPath",
            ["PATHEXT"] = ".INJECTED",
            ["TEMP"] = @"C:\Users\guardian\AppData\Local\Temp",
            ["TMP"] = @"C:\Users\guardian\AppData\Local\Temp",
            ["USERPROFILE"] = @"C:\Users\guardian",
            ["HOMEDRIVE"] = "C:",
            ["HOMEPATH"] = @"\Users\guardian",
            ["APPDATA"] = @"C:\Users\guardian\AppData\Roaming",
            ["LOCALAPPDATA"] = @"C:\Users\guardian\AppData\Local",
            ["ProgramData"] = @"C:\ProgramData",
            ["ProgramFiles"] = @"C:\Program Files",
            ["ProgramFiles(x86)"] = @"C:\Program Files (x86)",
            ["CommonProgramFiles"] = @"C:\Program Files\Common Files",
            ["CommonProgramFiles(x86)"] = @"C:\Program Files (x86)\Common Files",
            ["PUBLIC"] = @"C:\Users\Public",
            ["OS"] = "InjectedOS",
            ["PROCESSOR_ARCHITECTURE"] = "AMD64",
            ["PROCESSOR_IDENTIFIER"] = "Fake64 Family 1 Model 2 Stepping 3",
            ["PROCESSOR_LEVEL"] = "6",
            ["PROCESSOR_REVISION"] = "0001",
            ["NUMBER_OF_PROCESSORS"] = "8",
            ["COMPUTERNAME"] = "GUARDIAN-HOST",
            ["USERNAME"] = "\u7528\u6237",
            ["USERDOMAIN"] = "GUARDIAN-DOMAIN",
            ["SESSIONNAME"] = "Console",
            ["SystemDrive"] = "D:",
            ["DOTNET_STARTUP_HOOKS"] = @"D:\Injected\hook.dll",
            ["DOTNET_DiagnosticPorts"] = @"D:\Injected\diagnostic.sock",
            ["DOTNET_ROOT"] = @"D:\Injected\dotnet",
            ["NUGET_PLUGIN_PATHS"] = @"D:\Injected\nuget",
            ["NUGET_PACKAGES"] = @"D:\Injected\packages",
            ["MSBuildSDKsPath"] = @"D:\Injected\msbuild",
            ["MSBUILD_EXE_PATH"] = @"D:\Injected\msbuild.exe",
            ["ELECTRON_RUN_AS_NODE"] = "1",
            ["ELECTRON_ENABLE_LOGGING"] = "1",
            ["NODE_OPTIONS"] = "--require D:\\Injected\\hook.js",
            ["NODE_PATH"] = @"D:\Injected\node_modules",
            ["VSCODE_CWD"] = @"D:\Injected",
            ["VSCODE_IPC_HOOK_CLI"] = @"D:\Injected\vscode.sock",
            ["COR_ENABLE_PROFILING"] = "1",
            ["COR_PROFILER_PATH"] = @"D:\Injected\profiler.dll",
            ["CORECLR_PROFILER"] = "{00000000-0000-0000-0000-000000000001}",
            ["CORECLR_ENABLE_PROFILING"] = "1",
            ["COMPlus_ReadyToRun"] = "0",
            ["COMPlus_ZapDisable"] = "1",
            ["COREHOST_TRACE"] = "1",
            ["__COMPAT_LAYER"] = "RunAsInvoker"
        };
        var expectedNames = new[]
        {
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATH",
            "PATHEXT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "ProgramData",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "CommonProgramFiles",
            "CommonProgramFiles(x86)",
            "PUBLIC",
            "OS",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_IDENTIFIER",
            "PROCESSOR_LEVEL",
            "PROCESSOR_REVISION",
            "NUMBER_OF_PROCESSORS",
            "COMPUTERNAME",
            "USERNAME",
            "USERDOMAIN",
            "SESSIONNAME",
            "SystemDrive"
        };

        var block = WindowsCrtPipeProcessEnvironment.BuildBlockText(
            source,
            @"C:\Windows");
        var entries = ParseEnvironmentBlock(block);
        var names = entries.Select(entry => entry.Key).ToArray();
        var values = entries.ToDictionary(
            entry => entry.Key,
            entry => entry.Value,
            StringComparer.OrdinalIgnoreCase);
        Ensure(
            names.SequenceEqual(
                names.OrderBy(name => name, StringComparer.OrdinalIgnoreCase),
                StringComparer.Ordinal),
            "environment names were not sorted ordinal-ignore-case");
        Ensure(
            names.Length == expectedNames.Length &&
            names.Distinct(StringComparer.OrdinalIgnoreCase).Count() == names.Length &&
            new HashSet<string>(names, StringComparer.OrdinalIgnoreCase).SetEquals(expectedNames),
            "environment allowlist changed");
        Ensure(
            values["SystemRoot"] == @"C:\Windows" &&
            values["WINDIR"] == @"C:\Windows" &&
            values["ComSpec"] == @"C:\Windows\System32\cmd.exe" &&
            values["PATHEXT"] == ".COM;.EXE;.BAT;.CMD" &&
            values["OS"] == "Windows_NT" &&
            values["SystemDrive"] == "C:",
            "fixed Windows environment values were inherited instead of rebuilt");
        var pathSegments = values["PATH"].Split(';', StringSplitOptions.None);
        Ensure(
            pathSegments.SequenceEqual(
                new[]
                {
                    @"C:\Windows\System32",
                    @"C:\Windows",
                    @"C:\Windows\System32\Wbem",
                    @"C:\Windows\System32\WindowsPowerShell\v1.0"
                },
                StringComparer.Ordinal) &&
            pathSegments.All(segment => segment.Length > 0) &&
            pathSegments.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 4,
            "safe PATH was inherited, reordered, duplicated, or left empty");
        Ensure(values["USERNAME"] == "\u7528\u6237", "Unicode environment value changed");

        foreach (var forbiddenName in new[]
        {
            "DOTNET_STARTUP_HOOKS",
            "DOTNET_DiagnosticPorts",
            "DOTNET_ROOT",
            "NUGET_PLUGIN_PATHS",
            "NUGET_PACKAGES",
            "MSBuildSDKsPath",
            "MSBUILD_EXE_PATH",
            "ELECTRON_RUN_AS_NODE",
            "ELECTRON_ENABLE_LOGGING",
            "NODE_OPTIONS",
            "NODE_PATH",
            "VSCODE_CWD",
            "VSCODE_IPC_HOOK_CLI",
            "COR_ENABLE_PROFILING",
            "COR_PROFILER_PATH",
            "CORECLR_PROFILER",
            "CORECLR_ENABLE_PROFILING",
            "COMPlus_ReadyToRun",
            "COMPlus_ZapDisable",
            "COREHOST_TRACE",
            "__COMPAT_LAYER"
        })
        {
            Ensure(!values.ContainsKey(forbiddenName), "injection variable escaped the allowlist");
        }

        var unicodeBytes = Encoding.Unicode.GetBytes(block);
        Ensure(
            unicodeBytes.Length == checked(block.Length * 2) &&
            unicodeBytes.Length >= 4 &&
            unicodeBytes[0] != 0xFF && unicodeBytes[1] != 0xFE &&
            unicodeBytes[^1] == 0 && unicodeBytes[^2] == 0 &&
            unicodeBytes[^3] == 0 && unicodeBytes[^4] == 0 &&
            string.Equals(Encoding.Unicode.GetString(unicodeBytes), block, StringComparison.Ordinal),
            "environment block was not exact BOM-free UTF-16LE with a double NUL");
        Ensure(
            block.Length <= WindowsCrtPipeProcessEnvironment.MaximumEnvironmentBlockCharacters,
            "environment block exceeded its Windows bound");
        return Task.CompletedTask;
    }

    private static Task TestEnvironmentBlockValidationAsync()
    {
        EnsureThrows<ArgumentException>(
            () => WindowsCrtPipeProcessEnvironment.BuildBlockText(
                new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["SystemRoot"] = @"D:\AttackerWindows",
                    ["systemroot"] = @"E:\AttackerWindows"
                },
                @"C:\Windows"),
            "case-equivalent environment names were accepted");
        EnsureThrows<ArgumentException>(
            () => WindowsCrtPipeProcessEnvironment.BuildBlockText(
                new Dictionary<string, string?>
                {
                    ["USERNAME"] = "unsafe\nvalue"
                },
                @"C:\Windows"),
            "allowed environment value accepted a control character");
        EnsureThrows<ArgumentException>(
            () => WindowsCrtPipeProcessEnvironment.BuildBlockText(
                new Dictionary<string, string?>
                {
                    ["USERNAME"] = "unsafe\0value"
                },
                @"C:\Windows"),
            "allowed environment value accepted NUL");
        EnsureThrows<ArgumentException>(
            () => WindowsCrtPipeProcessEnvironment.BuildBlockText(
                new Dictionary<string, string?>(),
                @"C:\Windows;D:\Injected"),
            "SystemRoot accepted a PATH injection delimiter");
        EnsureThrows<ArgumentException>(
            () => WindowsCrtPipeProcessEnvironment.BuildBlockText(
                new Dictionary<string, string?>(),
                @"C:\Windows\System32\.."),
            "SystemRoot accepted a non-canonical parent segment");
        EnsureThrows<ArgumentException>(
            () => WindowsCrtPipeProcessEnvironment.BuildBlockText(
                new Dictionary<string, string?>
                {
                    ["USERNAME"] = new string(
                        'x',
                        WindowsCrtPipeProcessEnvironment.MaximumEnvironmentBlockCharacters)
                },
                @"C:\Windows"),
            "oversized environment block was accepted");
        EnsureThrows<ArgumentException>(
            () => WindowsCrtPipeProcessEnvironment.BuildBlockText(
                new Dictionary<string, string?>
                {
                    ["NODE_OPTIONS"] = "--require ignored.js"
                },
                "relative-windows"),
            "non-absolute trusted SystemRoot was accepted");
        return Task.CompletedTask;
    }

    private static IReadOnlyList<KeyValuePair<string, string>> ParseEnvironmentBlock(
        string block)
    {
        Ensure(
            block.Length >= 2 && block[^1] == '\0' && block[^2] == '\0',
            "environment block did not end with a double NUL");
        var encodedEntries = block[..^2].Split('\0', StringSplitOptions.None);
        Ensure(
            encodedEntries.Length > 0 && encodedEntries.All(entry => entry.Length > 0),
            "environment block contained an empty entry");
        return encodedEntries.Select(entry =>
        {
            var separator = entry.IndexOf('=');
            Ensure(separator > 0, "environment entry had no name separator");
            return new KeyValuePair<string, string>(
                entry[..separator],
                entry[(separator + 1)..]);
        }).ToArray();
    }

    private static async Task TestRetainedLaunchPublicationAsync()
    {
        var candidate = new FakeRetainedCandidate(processId: 41001);
        var publicationFailure = new InvalidOperationException("publication-failure");
        WindowsCrtPipeProcessStartException? retainedFailure = null;
        try
        {
            _ = WindowsCrtPipeProcessLaunchPublication.Publish<object>(
                candidate,
                () => throw publicationFailure);
        }
        catch (WindowsCrtPipeProcessStartException exception)
        {
            retainedFailure = exception;
        }

        var exactFailure = retainedFailure ??
            throw new InvalidOperationException("publication failure was not typed");
        Ensure(
            ReferenceEquals(exactFailure.InnerException, publicationFailure),
            "publication failure did not preserve its primary exception");
        Ensure(exactFailure.ProcessId == candidate.ProcessId, "retained PID changed");
        var retained = exactFailure.TakeRetainedCandidate();
        Ensure(ReferenceEquals(retained, candidate), "publication lost the exact candidate");
        EnsureThrows<InvalidOperationException>(
            () => exactFailure.TakeRetainedCandidate(),
            "retained candidate transferred more than once");
        await retained.DisposeAsync().ConfigureAwait(false);
        Ensure(candidate.DisposeCount == 1, "retained candidate cleanup was not exact");

        var successfulCandidate = new FakeRetainedCandidate(processId: 41002);
        var published = new object();
        var publicationCount = 0;
        var result = WindowsCrtPipeProcessLaunchPublication.Publish(
            successfulCandidate,
            () =>
            {
                publicationCount++;
                return published;
            });
        Ensure(
            ReferenceEquals(result, published) && publicationCount == 1 &&
            successfulCandidate.DisposeCount == 0,
            "successful publication changed candidate ownership");
        await successfulCandidate.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task TestStickyDisposalSuccessAsync()
    {
        var counts = new int[3];
        var disposal = new WindowsCrtPipeProcessDisposal(
        [
            new WindowsCrtPipeProcessCleanupStep("read-stream", () => counts[0]++),
            new WindowsCrtPipeProcessCleanupStep("write-stream", () => counts[1]++),
            new WindowsCrtPipeProcessCleanupStep("process-handle", () => counts[2]++)
        ]);

        var first = disposal.DisposeAsync().AsTask();
        var follower = disposal.DisposeAsync().AsTask();
        Ensure(ReferenceEquals(first, follower), "async disposers did not share one task");
        await first.ConfigureAwait(false);
        disposal.Dispose();
        var afterSync = disposal.DisposeAsync().AsTask();
        Ensure(ReferenceEquals(first, afterSync), "sync disposal replaced the sticky task");
        Ensure(counts.All(count => count == 1), "a cleanup step ran more than once");

        var syncCounts = new int[2];
        var syncFirst = new WindowsCrtPipeProcessDisposal(
        [
            new WindowsCrtPipeProcessCleanupStep("read-stream", () => syncCounts[0]++),
            new WindowsCrtPipeProcessCleanupStep("process-handle", () => syncCounts[1]++)
        ]);
        syncFirst.Dispose();
        await syncFirst.DisposeAsync().ConfigureAwait(false);
        Ensure(syncCounts.All(count => count == 1), "sync-first cleanup was not sticky");
    }

    private static async Task TestStickyDisposalFailureAsync()
    {
        var failures = Enumerable.Range(0, 6)
            .Select(index => new IOException("cleanup-failure-" + index))
            .ToArray();
        var counts = new int[failures.Length];
        var steps = failures
            .Select((failure, index) => new WindowsCrtPipeProcessCleanupStep(
                "cleanup-step-" + index,
                () =>
                {
                    counts[index]++;
                    throw failure;
                }))
            .ToArray();
        var disposal = new WindowsCrtPipeProcessDisposal(steps);

        var firstTask = disposal.DisposeAsync().AsTask();
        var followerTask = disposal.DisposeAsync().AsTask();
        Ensure(ReferenceEquals(firstTask, followerTask), "faulted disposal task was replaced");
        var firstFailure = await CaptureFailureAsync(firstTask).ConfigureAwait(false);
        var followerFailure = await CaptureFailureAsync(followerTask).ConfigureAwait(false);
        Ensure(
            ReferenceEquals(firstFailure, failures[0]) &&
            ReferenceEquals(followerFailure, failures[0]),
            "sticky disposal did not preserve the exact primary failure");
        Ensure(counts.All(count => count == 1), "a later failure skipped or repeated cleanup");

        var secondary = failures[0].Data[
            WindowsCrtPipeProcessDisposal.SecondaryCleanupFailureDataKey] as AggregateException;
        Ensure(
            secondary?.InnerExceptions.Count ==
                WindowsCrtPipeProcessDisposal.MaximumSecondaryCleanupFailures,
            "secondary cleanup failures were not bounded");
        for (var index = 0; index < secondary!.InnerExceptions.Count; index++)
        {
            var wrapped = secondary.InnerExceptions[index] as
                WindowsCrtPipeProcessSecondaryCleanupException;
            Ensure(
                wrapped?.Code == "cleanup-step-" + (index + 1) &&
                ReferenceEquals(wrapped.InnerException, failures[index + 1]),
                "secondary cleanup failure identity or order changed");
        }

        Ensure(
            failures[0].Data[
                WindowsCrtPipeProcessDisposal.SecondaryCleanupOverflowDataKey] is int overflow &&
            overflow == 1,
            "secondary cleanup overflow was not recorded exactly");

        Exception? syncFailure = null;
        try
        {
            disposal.Dispose();
        }
        catch (Exception exception)
        {
            syncFailure = exception;
        }
        Ensure(
            ReferenceEquals(syncFailure, failures[0]),
            "sync follower did not observe the sticky primary failure");
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
            assert(false, name + ": " + exception.GetType().Name + " " + exception.Message);
        }
    }

    private static async Task<Exception?> CaptureFailureAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static void EnsureThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeRetainedCandidate(int processId) :
        IWindowsCrtPipeProcessRetainedCandidate
    {
        private readonly MemoryStream _read = new();
        private readonly MemoryStream _write = new();
        private int _disposed;

        public int ProcessId { get; } = processId;

        public Stream ReadStream => _read;

        public Stream WriteStream => _write;

        public bool HasExited => false;

        internal int DisposeCount => Volatile.Read(ref _disposed);

        public SafeProcessHandle DuplicateRetainedProcessHandleForVerification() =>
            throw new NotSupportedException();

        public Task<int> WaitForExitAsync(
            TimeSpan timeout,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(0);

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _read.Dispose();
            _write.Dispose();
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
