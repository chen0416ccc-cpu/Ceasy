using CodexGuardian.Control;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal sealed class WindowsCodexRuntimeControlException : InvalidOperationException
{
    internal WindowsCodexRuntimeControlException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(code))
        {
            throw new ArgumentException(
                "A bounded runtime-control failure code is required.",
                nameof(code));
        }

        Code = code;
    }

    internal string Code { get; }
}

internal sealed class WindowsCodexRuntimePackageBaselineV1
{
    internal WindowsCodexRuntimePackageBaselineV1(
        string executablePath,
        string packageFullName,
        string packageFamilyName,
        string currentUserSid,
        uint currentSessionId,
        DateTimeOffset launchReservationUtc,
        CodexPackageBaselineSnapshot? verifiedSnapshot = null,
        string? codexExecutablePath = null)
    {
        if (string.IsNullOrWhiteSpace(executablePath) ||
            !Path.IsPathFullyQualified(executablePath))
        {
            throw new ArgumentException(
                "An absolute pinned ChatGPT executable path is required.",
                nameof(executablePath));
        }

        if (string.IsNullOrWhiteSpace(packageFullName))
        {
            throw new ArgumentException("A package full name is required.", nameof(packageFullName));
        }

        if (string.IsNullOrWhiteSpace(packageFamilyName))
        {
            throw new ArgumentException(
                "A package family name is required.",
                nameof(packageFamilyName));
        }

        if (string.IsNullOrWhiteSpace(currentUserSid))
        {
            throw new ArgumentException("A current-user SID is required.", nameof(currentUserSid));
        }

        if (launchReservationUtc == default || launchReservationUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "A non-default UTC launch reservation is required.",
                nameof(launchReservationUtc));
        }

        if (codexExecutablePath is not null &&
            !Path.IsPathFullyQualified(codexExecutablePath))
        {
            throw new ArgumentException(
                "An absolute pinned Codex executable path is required.",
                nameof(codexExecutablePath));
        }

        ExecutablePath = Path.GetFullPath(executablePath);
        CodexExecutablePath = codexExecutablePath is null
            ? ExecutablePath
            : Path.GetFullPath(codexExecutablePath);

        PackageFullName = packageFullName;
        PackageFamilyName = packageFamilyName;
        CurrentUserSid = currentUserSid;
        CurrentSessionId = currentSessionId;
        LaunchReservationUtc = launchReservationUtc;
        VerifiedSnapshot = verifiedSnapshot;
    }

    internal string ExecutablePath { get; }

    internal string CodexExecutablePath { get; }

    internal string PackageFullName { get; }

    internal string PackageFamilyName { get; }

    internal string CurrentUserSid { get; }

    internal uint CurrentSessionId { get; }

    internal DateTimeOffset LaunchReservationUtc { get; }

    internal CodexPackageBaselineSnapshot? VerifiedSnapshot { get; }
}

internal interface IWindowsCodexRuntimePackageVerifierV1
{
    WindowsCodexRuntimePackageBaselineV1 VerifyPreLaunch();

    void RevalidateBaseline(WindowsCodexRuntimePackageBaselineV1 baseline);

    CodexVerifiedProcessSnapshot VerifyPostLaunch(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        int expectedProcessId,
        SafeProcessHandle retainedProcessHandle);
}

internal sealed class WindowsCodexRuntimePackageVerifierV1
    : IWindowsCodexRuntimePackageVerifierV1
{
    private readonly CodexPackageBaselineVerifier _verifier;

    internal WindowsCodexRuntimePackageVerifierV1(CodexPackageBaselineVerifier verifier)
    {
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
    }

    public WindowsCodexRuntimePackageBaselineV1 VerifyPreLaunch()
    {
        var snapshot = _verifier.VerifyPreLaunch();
        return new WindowsCodexRuntimePackageBaselineV1(
            snapshot.ChatGptExecutable.FinalPath,
            snapshot.Package.FullName,
            snapshot.Package.FamilyName,
            snapshot.CurrentUserSid,
            snapshot.CurrentSessionId,
            snapshot.LaunchReservationUtc,
            snapshot,
            snapshot.CodexExecutable.FinalPath);
    }

    public void RevalidateBaseline(WindowsCodexRuntimePackageBaselineV1 baseline)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        _verifier.RevalidateBaseline(RequireVerifiedSnapshot(baseline));
    }

    public CodexVerifiedProcessSnapshot VerifyPostLaunch(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        int expectedProcessId,
        SafeProcessHandle retainedProcessHandle)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        return _verifier.VerifyPostLaunch(
            RequireVerifiedSnapshot(baseline),
            expectedProcessId,
            retainedProcessHandle);
    }

    private static CodexPackageBaselineSnapshot RequireVerifiedSnapshot(
        WindowsCodexRuntimePackageBaselineV1 baseline) =>
        baseline.VerifiedSnapshot ??
        throw new InvalidOperationException("runtime-package-baseline-is-not-production-verified");
}

internal sealed record WindowsCodexRuntimeInventoryProcessV1(
    int ProcessId,
    int ParentProcessId,
    DateTimeOffset CreationTimeUtc,
    string UserSid,
    uint SessionId,
    string PackageFullName,
    string PackageFamilyName,
    string ImagePath);

internal sealed record WindowsCodexRuntimeLineageProcessV1(
    int ProcessId,
    int ParentProcessId,
    DateTimeOffset CreationTimeUtc,
    string UserSid,
    uint SessionId,
    string ImagePath);

internal sealed class WindowsCodexRuntimeInventorySnapshotV1
{
    internal WindowsCodexRuntimeInventorySnapshotV1(
        IReadOnlyList<WindowsCodexRuntimeInventoryProcessV1> packageProcesses,
        IReadOnlyList<WindowsCodexRuntimeLineageProcessV1> candidateDescendants,
        string? failureCode = null)
    {
        ArgumentNullException.ThrowIfNull(packageProcesses);
        ArgumentNullException.ThrowIfNull(candidateDescendants);
        if (failureCode is not null && !CodexCdpBrokerProtocol.IsControlIdentifier(failureCode))
        {
            throw new ArgumentException(
                "A bounded inventory failure code is required.",
                nameof(failureCode));
        }

        PackageProcesses = packageProcesses
            .OrderBy(item => item.ProcessId)
            .ThenBy(item => item.CreationTimeUtc)
            .ToArray();
        CandidateDescendants = candidateDescendants
            .OrderBy(item => item.ProcessId)
            .ThenBy(item => item.CreationTimeUtc)
            .ToArray();
        FailureCode = failureCode;
    }

    internal IReadOnlyList<WindowsCodexRuntimeInventoryProcessV1> PackageProcesses { get; }

    internal IReadOnlyList<WindowsCodexRuntimeLineageProcessV1> CandidateDescendants { get; }

    internal string? FailureCode { get; }

    internal bool IsComplete => FailureCode is null;

    internal bool EquivalentTo(WindowsCodexRuntimeInventorySnapshotV1 other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return string.Equals(FailureCode, other.FailureCode, StringComparison.Ordinal) &&
               PackageProcesses.SequenceEqual(other.PackageProcesses) &&
               CandidateDescendants.SequenceEqual(other.CandidateDescendants);
    }

    internal bool ContainsExactProcess(CodexVerifiedProcessSnapshot process) =>
        PackageProcesses.Any(item =>
            item.ProcessId == process.ProcessId &&
            item.CreationTimeUtc == process.CreationTimeUtc &&
            string.Equals(item.UserSid, process.UserSid, StringComparison.OrdinalIgnoreCase) &&
            item.SessionId == process.SessionId &&
            string.Equals(
                item.PackageFullName,
                process.PackageFullName,
                StringComparison.Ordinal) &&
            string.Equals(
                item.PackageFamilyName,
                process.PackageFamilyName,
                StringComparison.Ordinal) &&
            string.Equals(item.ImagePath, process.ImagePath, StringComparison.OrdinalIgnoreCase));

    internal bool HasIndependentPackageProcess(int candidateProcessId)
    {
        var candidateLineage = CandidateDescendants
            .Select(item => item.ProcessId)
            .ToHashSet();
        candidateLineage.Add(candidateProcessId);
        return PackageProcesses.Any(item => !candidateLineage.Contains(item.ProcessId));
    }
}

internal interface IWindowsCodexRuntimeInventoryV1
{
    ValueTask<WindowsCodexRuntimeInventorySnapshotV1> CaptureAsync(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        int? candidateProcessId,
        CancellationToken cancellationToken);
}

internal sealed class WindowsCodexRuntimeInventoryV1 : IWindowsCodexRuntimeInventoryV1
{
    private const uint CreateSnapshotProcess = 0x00000002;
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint Synchronize = 0x00100000;
    private const int ErrorNoMoreFiles = 18;
    private const int AppModelErrorNoPackage = 15700;
    private const int MaximumProcessCount = 8192;
    private readonly WindowsCodexPackageBaselinePlatform _platform;

    internal WindowsCodexRuntimeInventoryV1(
        WindowsCodexPackageBaselinePlatform? platform = null)
    {
        _platform = platform ?? new WindowsCodexPackageBaselinePlatform();
    }

    public ValueTask<WindowsCodexRuntimeInventorySnapshotV1> CaptureAsync(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        int? candidateProcessId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows process inventory is Windows-only.");
        }

        try
        {
            return ValueTask.FromResult(Capture(baseline, candidateProcessId, cancellationToken));
        }
        catch (WindowsCodexRuntimeControlException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new WindowsCodexRuntimeControlException(
                "runtime-inventory-capture-failed",
                "The bounded Codex process inventory could not be captured.",
                exception);
        }
    }

    private WindowsCodexRuntimeInventorySnapshotV1 Capture(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        int? candidateProcessId,
        CancellationToken cancellationToken)
    {
        var rawProcesses = ReadProcessSnapshot(cancellationToken);
        var candidateDescendantIds = candidateProcessId is { } candidateId
            ? FindDescendants(rawProcesses, candidateId)
            : new HashSet<int>();
        var executableNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetFileName(baseline.ExecutablePath),
            Path.GetFileName(baseline.CodexExecutablePath)
        };
        var relevant = rawProcesses
            .Where(item =>
                candidateDescendantIds.Contains(item.ProcessId) ||
                executableNames.Contains(item.ExecutableName))
            .OrderBy(item => item.ProcessId)
            .ToArray();
        var packages = new List<WindowsCodexRuntimeInventoryProcessV1>();
        var lineage = new List<WindowsCodexRuntimeLineageProcessV1>();

        foreach (var raw in relevant)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var handle = OpenProcess(
                ProcessQueryLimitedInformation | Synchronize,
                inheritHandle: false,
                checked((uint)raw.ProcessId));
            if (handle.IsInvalid)
            {
                return Incomplete("runtime-inventory-access-denied");
            }

            try
            {
                if (!_platform.IsRetainedProcessAlive(handle) ||
                    _platform.ReadRetainedProcessId(handle) != checked((uint)raw.ProcessId))
                {
                    return Incomplete("runtime-inventory-process-raced");
                }

                var creationTimeUtc = _platform
                    .ReadProcessCreationTimeUtc(handle)
                    .ToUniversalTime();
                var userSid = _platform.ReadProcessUserSid(handle);
                var sessionId = _platform.ReadProcessSessionId(checked((uint)raw.ProcessId));
                var imagePath = Path.GetFullPath(_platform.ReadProcessImagePath(handle));
                if (candidateDescendantIds.Contains(raw.ProcessId))
                {
                    lineage.Add(new WindowsCodexRuntimeLineageProcessV1(
                        raw.ProcessId,
                        raw.ParentProcessId,
                        creationTimeUtc,
                        userSid,
                        sessionId,
                        imagePath));
                }

                if (!executableNames.Contains(raw.ExecutableName))
                {
                    continue;
                }

                string packageFullName;
                string packageFamilyName;
                try
                {
                    packageFullName = _platform.ReadProcessPackageFullName(handle);
                    packageFamilyName = _platform.ReadProcessPackageFamilyName(handle);
                }
                catch (Win32Exception exception)
                    when (exception.NativeErrorCode == AppModelErrorNoPackage)
                {
                    continue;
                }

                var sameFullName = string.Equals(
                    packageFullName,
                    baseline.PackageFullName,
                    StringComparison.Ordinal);
                var sameFamily = string.Equals(
                    packageFamilyName,
                    baseline.PackageFamilyName,
                    StringComparison.Ordinal);
                if (!sameFullName && !sameFamily)
                {
                    continue;
                }

                if (!sameFullName || !sameFamily ||
                    !string.Equals(
                        userSid,
                        baseline.CurrentUserSid,
                        StringComparison.OrdinalIgnoreCase) ||
                    sessionId != baseline.CurrentSessionId ||
                    (!string.Equals(
                         imagePath,
                         baseline.ExecutablePath,
                         StringComparison.OrdinalIgnoreCase) &&
                     !string.Equals(
                         imagePath,
                         baseline.CodexExecutablePath,
                         StringComparison.OrdinalIgnoreCase)))
                {
                    return Incomplete("runtime-inventory-identity-mismatch");
                }

                packages.Add(new WindowsCodexRuntimeInventoryProcessV1(
                    raw.ProcessId,
                    raw.ParentProcessId,
                    creationTimeUtc,
                    userSid,
                    sessionId,
                    packageFullName,
                    packageFamilyName,
                    imagePath));
            }
            catch (Win32Exception)
            {
                return Incomplete("runtime-inventory-process-raced");
            }
        }

        return new WindowsCodexRuntimeInventorySnapshotV1(packages, lineage);
    }

    private static WindowsCodexRuntimeInventorySnapshotV1 Incomplete(string code) =>
        new(
            Array.Empty<WindowsCodexRuntimeInventoryProcessV1>(),
            Array.Empty<WindowsCodexRuntimeLineageProcessV1>(),
            code);

    private static IReadOnlyList<RawProcessEntry> ReadProcessSnapshot(
        CancellationToken cancellationToken)
    {
        using var snapshot = CreateToolhelp32Snapshot(CreateSnapshotProcess, processId: 0);
        if (snapshot.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to create the bounded Windows process snapshot.");
        }

        var entry = new PROCESSENTRY32
        {
            dwSize = checked((uint)Marshal.SizeOf<PROCESSENTRY32>())
        };
        if (!Process32FirstW(snapshot, ref entry))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the first Windows process snapshot entry.");
        }

        var processes = new List<RawProcessEntry>();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.th32ProcessID is > 0 and <= int.MaxValue &&
                entry.th32ParentProcessID <= int.MaxValue)
            {
                processes.Add(new RawProcessEntry(
                    checked((int)entry.th32ProcessID),
                    checked((int)entry.th32ParentProcessID),
                    entry.szExeFile ?? string.Empty));
                if (processes.Count > MaximumProcessCount)
                {
                    throw new WindowsCodexRuntimeControlException(
                        "runtime-inventory-capacity-exceeded",
                        "The bounded Windows process inventory exceeded its capacity.");
                }
            }

            entry.dwSize = checked((uint)Marshal.SizeOf<PROCESSENTRY32>());
            if (Process32NextW(snapshot, ref entry))
            {
                continue;
            }

            var error = Marshal.GetLastWin32Error();
            if (error != ErrorNoMoreFiles)
            {
                throw new Win32Exception(
                    error,
                    "Unable to finish the bounded Windows process snapshot.");
            }

            return processes;
        }
    }

    private static HashSet<int> FindDescendants(
        IReadOnlyList<RawProcessEntry> processes,
        int candidateProcessId)
    {
        var descendants = new HashSet<int>();
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var process in processes)
            {
                if (process.ProcessId == candidateProcessId || descendants.Contains(process.ProcessId))
                {
                    continue;
                }

                if (process.ParentProcessId == candidateProcessId ||
                    descendants.Contains(process.ParentProcessId))
                {
                    if (!descendants.Add(process.ProcessId))
                    {
                        continue;
                    }

                    changed = true;
                }
            }
        }

        return descendants;
    }

    private sealed record RawProcessEntry(
        int ProcessId,
        int ParentProcessId,
        string ExecutableName);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        internal uint dwSize;
        internal uint cntUsage;
        internal uint th32ProcessID;
        internal IntPtr th32DefaultHeapID;
        internal uint th32ModuleID;
        internal uint cntThreads;
        internal uint th32ParentProcessID;
        internal int pcPriClassBase;
        internal uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(
        SafeFileHandle snapshot,
        ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(
        SafeFileHandle snapshot,
        ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);
}

internal interface IWindowsCodexCdpLaunchedProcessV1 : IAsyncDisposable
{
    int ProcessId { get; }

    Stream ReadStream { get; }

    Stream WriteStream { get; }

    bool IsAlive { get; }

    SafeProcessHandle DuplicateRetainedProcessHandleForVerification();

    Task<int> WaitForExitAsync(CancellationToken cancellationToken);
}

internal interface IWindowsCodexCdpProcessLauncherV1
{
    IWindowsCodexCdpLaunchedProcessV1 Launch(
        string executablePath,
        IReadOnlyList<string> arguments,
        string workingDirectory);
}

internal sealed class WindowsCodexCdpProcessLaunchExceptionV1 : IOException
{
    private readonly object _sync = new();
    private IWindowsCodexCdpLaunchedProcessV1? _retainedProcess;

    internal WindowsCodexCdpProcessLaunchExceptionV1(
        IWindowsCodexCdpLaunchedProcessV1 retainedProcess,
        Exception innerException)
        : base(
            "The Codex process was created but its normal launch result could not be published.",
            innerException)
    {
        _retainedProcess = retainedProcess ??
            throw new ArgumentNullException(nameof(retainedProcess));
    }

    internal IWindowsCodexCdpLaunchedProcessV1 TakeRetainedProcess()
    {
        lock (_sync)
        {
            var process = _retainedProcess ??
                throw new InvalidOperationException(
                    "runtime-launch-retained-process-already-transferred");
            _retainedProcess = null;
            return process;
        }
    }
}

internal sealed class WindowsCodexCdpProcessLauncherV1 : IWindowsCodexCdpProcessLauncherV1
{
    public IWindowsCodexCdpLaunchedProcessV1 Launch(
        string executablePath,
        IReadOnlyList<string> arguments,
        string workingDirectory)
    {
        try
        {
            return new WindowsCodexCdpLaunchedProcessV1(
                WindowsCrtPipeProcess.Start(executablePath, arguments, workingDirectory));
        }
        catch (WindowsCrtPipeProcessStartException exception)
        {
            IWindowsCrtPipeProcessRetainedCandidate retained;
            try
            {
                retained = exception.TakeRetainedCandidate();
            }
            catch (Exception transferFailure)
            {
                throw new WindowsCodexRuntimeControlException(
                    "runtime-launch-authority-transfer-failed",
                    "The exact post-create process authority could not be transferred.",
                    new AggregateException(exception, transferFailure));
            }

            throw new WindowsCodexCdpProcessLaunchExceptionV1(
                new WindowsCodexCdpLaunchedProcessV1(retained),
                exception);
        }
    }
}

internal sealed class WindowsCodexCdpLaunchedProcessV1 : IWindowsCodexCdpLaunchedProcessV1
{
    private readonly WindowsCrtPipeProcess? _process;
    private readonly IWindowsCrtPipeProcessRetainedCandidate? _retainedCandidate;

    internal WindowsCodexCdpLaunchedProcessV1(WindowsCrtPipeProcess process)
    {
        _process = process ?? throw new ArgumentNullException(nameof(process));
    }

    internal WindowsCodexCdpLaunchedProcessV1(
        IWindowsCrtPipeProcessRetainedCandidate retainedCandidate)
    {
        _retainedCandidate = retainedCandidate ??
            throw new ArgumentNullException(nameof(retainedCandidate));
    }

    public int ProcessId => _process?.ProcessId ?? _retainedCandidate!.ProcessId;

    public Stream ReadStream => _process?.ReadStream ?? _retainedCandidate!.ReadStream;

    public Stream WriteStream => _process?.WriteStream ?? _retainedCandidate!.WriteStream;

    public bool IsAlive => !(_process?.HasExited ?? _retainedCandidate!.HasExited);

    public SafeProcessHandle DuplicateRetainedProcessHandleForVerification() =>
        _process?.DuplicateRetainedProcessHandleForVerification() ??
        _retainedCandidate!.DuplicateRetainedProcessHandleForVerification();

    public Task<int> WaitForExitAsync(CancellationToken cancellationToken) =>
        _process?.WaitForExitAsync(Timeout.InfiniteTimeSpan, cancellationToken) ??
        _retainedCandidate!.WaitForExitAsync(Timeout.InfiniteTimeSpan, cancellationToken);

    public ValueTask DisposeAsync() =>
        _process?.DisposeAsync() ?? _retainedCandidate!.DisposeAsync();
}

internal interface IWindowsCodexCdpChannelV1 : IAsyncDisposable
{
    ICdpCommandTransport Commands { get; }

    Task Completion { get; }
}

internal interface IWindowsCodexCdpChannelFactoryV1
{
    IWindowsCodexCdpChannelV1 Create(IWindowsCodexCdpLaunchedProcessV1 process);
}

internal sealed class WindowsCodexCdpChannelFactoryV1 : IWindowsCodexCdpChannelFactoryV1
{
    public IWindowsCodexCdpChannelV1 Create(IWindowsCodexCdpLaunchedProcessV1 process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var transport = new CdpPipeTransport(
            process.ReadStream,
            process.WriteStream,
            new CdpPipeTransportOptions
            {
                TerminalFaultMode = CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose
            });
        return new WindowsCodexCdpChannelV1(transport);
    }
}

internal sealed class WindowsCodexCdpChannelV1 : IWindowsCodexCdpChannelV1
{
    private readonly CdpPipeTransport _transport;

    internal WindowsCodexCdpChannelV1(CdpPipeTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    public ICdpCommandTransport Commands => _transport;

    public Task Completion => _transport.Completion;

    public ValueTask DisposeAsync() => _transport.DisposeAsync();
}

internal interface ICodexCdpRuntimeHandshakeLeaseV1 : IAsyncDisposable
{
    Task Completion { get; }
}

internal interface ICodexCdpRuntimeHandshakeFactoryV1
{
    ValueTask<ICodexCdpRuntimeHandshakeLeaseV1> CompleteAsync(
        IWindowsCodexCdpChannelV1 channel,
        CancellationToken cancellationToken);
}

internal sealed class ReadOnlyCodexCdpRuntimeHandshakeFactoryV1
    : ICodexCdpRuntimeHandshakeFactoryV1
{
    private static readonly TimeSpan HandshakeCommandTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TargetRetryDelay = TimeSpan.FromMilliseconds(100);
    private const int MaximumTargetAttempts = 20;
    private const int MaximumTargetCount = 256;
    private readonly IWindowsCodexRuntimeDelayV1 _delay;
    private readonly string _expectedPageScheme;

    internal ReadOnlyCodexCdpRuntimeHandshakeFactoryV1(
        IWindowsCodexRuntimeDelayV1? delay = null,
        string expectedPageScheme = "app")
    {
        _delay = delay ?? new WindowsCodexRuntimeDelayV1();
        if (string.IsNullOrWhiteSpace(expectedPageScheme) ||
            expectedPageScheme.Length > 32 ||
            expectedPageScheme.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '+' and not '-' and not '.'))
        {
            throw new ArgumentException(
                "A bounded expected page URL scheme is required.",
                nameof(expectedPageScheme));
        }

        _expectedPageScheme = expectedPageScheme;
    }

    public async ValueTask<ICodexCdpRuntimeHandshakeLeaseV1> CompleteAsync(
        IWindowsCodexCdpChannelV1 channel,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        var browser = await channel.Commands.SendCommandAsync(
                "Browser.getVersion",
                parameters: null,
                timeout: HandshakeCommandTimeout,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (browser.ValueKind != JsonValueKind.Object)
        {
            throw new WindowsCodexRuntimeControlException(
                "runtime-browser-handshake-invalid",
                "Browser.getVersion returned an invalid bounded response.");
        }

        for (var attempt = 0; attempt < MaximumTargetAttempts; attempt++)
        {
            var targets = await channel.Commands.SendCommandAsync(
                    "Target.getTargets",
                    parameters: null,
                    timeout: HandshakeCommandTimeout,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (ContainsExpectedPageTarget(targets))
            {
                return new ReadOnlyCodexCdpRuntimeHandshakeLeaseV1(channel.Completion);
            }

            if (attempt + 1 < MaximumTargetAttempts)
            {
                await _delay.DelayAsync(TargetRetryDelay, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        throw new WindowsCodexRuntimeControlException(
            "runtime-page-target-not-ready",
            "Target.getTargets did not expose a bounded expected app page in time.");
    }

    private bool ContainsExpectedPageTarget(JsonElement targets)
    {
        if (targets.ValueKind != JsonValueKind.Object ||
            !targets.TryGetProperty("targetInfos", out var targetInfos) ||
            targetInfos.ValueKind != JsonValueKind.Array ||
            targetInfos.GetArrayLength() > MaximumTargetCount)
        {
            throw new WindowsCodexRuntimeControlException(
                "runtime-target-handshake-invalid",
                "Target.getTargets returned an invalid bounded response.");
        }

        foreach (var target in targetInfos.EnumerateArray())
        {
            if (target.ValueKind != JsonValueKind.Object ||
                !target.TryGetProperty("type", out var type) ||
                type.ValueKind != JsonValueKind.String ||
                !target.TryGetProperty("url", out var url) ||
                url.ValueKind != JsonValueKind.String)
            {
                throw new WindowsCodexRuntimeControlException(
                    "runtime-target-handshake-invalid",
                    "Target.getTargets returned an invalid target entry.");
            }

            var typeValue = type.GetString();
            var urlValue = url.GetString();
            if (typeValue is null || typeValue.Length > 64 ||
                urlValue is null || urlValue.Length > 2048)
            {
                throw new WindowsCodexRuntimeControlException(
                    "runtime-target-handshake-invalid",
                    "Target.getTargets returned an unbounded target entry.");
            }

            if (string.Equals(typeValue, "page", StringComparison.Ordinal) &&
                Uri.TryCreate(urlValue, UriKind.Absolute, out var parsed) &&
                string.Equals(parsed.Scheme, _expectedPageScheme, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

internal sealed class ReadOnlyCodexCdpRuntimeHandshakeLeaseV1
    : ICodexCdpRuntimeHandshakeLeaseV1
{
    internal ReadOnlyCodexCdpRuntimeHandshakeLeaseV1(Task completion)
    {
        Completion = completion ?? throw new ArgumentNullException(nameof(completion));
    }

    public Task Completion { get; }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal interface IWindowsCodexRuntimeDelayV1
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

internal sealed class WindowsCodexRuntimeDelayV1 : IWindowsCodexRuntimeDelayV1
{
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

internal sealed class WindowsCodexCdpCandidateResourcesV1 : IAsyncDisposable
{
    private const string CleanupFailureDataKey = "runtime-candidate-cleanup-failure";
    private readonly object _sync = new();
    private readonly AsyncLocal<WindowsCodexCdpCandidateResourcesV1?> _activeDispose = new();
    private readonly IWindowsCodexCdpLaunchedProcessV1 _process;
    private IWindowsCodexCdpChannelV1? _channel;
    private ICodexCdpRuntimeHandshakeLeaseV1? _handshake;
    private Task? _disposeTask;

    internal WindowsCodexCdpCandidateResourcesV1(IWindowsCodexCdpLaunchedProcessV1 process)
    {
        _process = process ?? throw new ArgumentNullException(nameof(process));
    }

    internal IWindowsCodexCdpLaunchedProcessV1 Process => _process;

    internal IWindowsCodexCdpChannelV1 Channel =>
        _channel ?? throw new InvalidOperationException("runtime-candidate-channel-not-attached");

    internal ICodexCdpRuntimeHandshakeLeaseV1 Handshake =>
        _handshake ?? throw new InvalidOperationException("runtime-candidate-handshake-not-attached");

    internal void AttachChannel(IWindowsCodexCdpChannelV1 channel)
    {
        ArgumentNullException.ThrowIfNull(channel);
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (_channel is not null)
            {
                throw new InvalidOperationException("runtime-candidate-channel-already-attached");
            }

            _channel = channel;
        }
    }

    internal void AttachHandshake(ICodexCdpRuntimeHandshakeLeaseV1 handshake)
    {
        ArgumentNullException.ThrowIfNull(handshake);
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (_channel is null || _handshake is not null)
            {
                throw new InvalidOperationException("runtime-candidate-handshake-attachment-invalid");
            }

            _handshake = handshake;
        }
    }

    public ValueTask DisposeAsync()
    {
        Task task;
        lock (_sync)
        {
            if (_disposeTask is not null)
            {
                if (!_disposeTask.IsCompleted && ReferenceEquals(_activeDispose.Value, this))
                {
                    return ValueTask.FromException(
                        new InvalidOperationException("runtime-candidate-dispose-reentrant"));
                }

                return new ValueTask(_disposeTask);
            }

            var completion = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _disposeTask = completion.Task;
            task = _disposeTask;
            _ = DisposeWinnerAsync(completion);
        }

        return new ValueTask(task);
    }

    private async Task DisposeWinnerAsync(TaskCompletionSource completion)
    {
        await Task.Yield();
        var previous = _activeDispose.Value;
        _activeDispose.Value = this;
        Exception? failure = null;
        try
        {
            failure = await CaptureCleanupFailureAsync(
                    _handshake,
                    failure)
                .ConfigureAwait(false);
            failure = await CaptureCleanupFailureAsync(_channel, failure).ConfigureAwait(false);
            failure = await CaptureCleanupFailureAsync(_process, failure).ConfigureAwait(false);
        }
        finally
        {
            _activeDispose.Value = previous;
        }

        if (failure is null)
        {
            completion.TrySetResult();
        }
        else
        {
            completion.TrySetException(failure);
        }
    }

    private static async Task<Exception?> CaptureCleanupFailureAsync(
        IAsyncDisposable? resource,
        Exception? primary)
    {
        if (resource is null)
        {
            return primary;
        }

        try
        {
            await resource.DisposeAsync().ConfigureAwait(false);
            return primary;
        }
        catch (Exception exception)
        {
            return BrokerControlFailureArbitration.PreserveSecondaryFailure(
                primary,
                exception,
                CleanupFailureDataKey);
        }
    }
}

internal sealed class WindowsCodexCdpHandleLeaseV1 : ICodexCdpHandleLease
{
    private static readonly TimeSpan ExitSettleWindow = TimeSpan.FromMilliseconds(100);
    private readonly object _sync = new();
    private readonly AsyncLocal<WindowsCodexCdpHandleLeaseV1?> _activeDispose = new();
    private readonly WindowsCodexCdpCandidateResourcesV1 _resources;
    private readonly IWindowsCodexRuntimeDelayV1 _delay;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Action<WindowsCodexCdpHandleLeaseV1> _released;
    private readonly CancellationTokenSource _observerCancellation = new();
    private readonly TaskCompletionSource<CodexCdpRuntimeExitResult> _exit = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _observerTask;
    private Task? _disposeTask;

    internal WindowsCodexCdpHandleLeaseV1(
        CodexCdpRuntimeIdentity identity,
        WindowsCodexCdpCandidateResourcesV1 resources,
        IWindowsCodexRuntimeDelayV1 delay,
        Func<DateTimeOffset> utcNow,
        Action<WindowsCodexCdpHandleLeaseV1> released)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _resources = resources ?? throw new ArgumentNullException(nameof(resources));
        _delay = delay ?? throw new ArgumentNullException(nameof(delay));
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        _released = released ?? throw new ArgumentNullException(nameof(released));
        _observerTask = ObserveExitAsync();
    }

    public CodexCdpRuntimeIdentity Identity { get; }

    public bool IsAlive
    {
        get
        {
            if (Volatile.Read(ref _disposeTask) is not null)
            {
                return false;
            }

            try
            {
                return _resources.Process.IsAlive;
            }
            catch
            {
                return false;
            }
        }
    }

    public Task<CodexCdpRuntimeExitResult> Exit => _exit.Task;

    public ValueTask DisposeAsync()
    {
        Task task;
        lock (_sync)
        {
            if (_disposeTask is not null)
            {
                if (!_disposeTask.IsCompleted && ReferenceEquals(_activeDispose.Value, this))
                {
                    return ValueTask.FromException(
                        new InvalidOperationException("runtime-lease-dispose-reentrant"));
                }

                return new ValueTask(_disposeTask);
            }

            var completion = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _disposeTask = completion.Task;
            task = _disposeTask;
            _ = DisposeWinnerAsync(completion);
        }

        return new ValueTask(task);
    }

    private async Task ObserveExitAsync()
    {
        var cancellationTask = Task.Delay(
            Timeout.InfiniteTimeSpan,
            _observerCancellation.Token);
        var processTask = _resources.Process.WaitForExitAsync(_observerCancellation.Token);
        var channelTask = _resources.Channel.Completion;
        var handshakeTask = _resources.Handshake.Completion;
        try
        {
            var completed = await Task.WhenAny(
                    processTask,
                    channelTask,
                    handshakeTask,
                    cancellationTask)
                .ConfigureAwait(false);
            if (completed == cancellationTask)
            {
                return;
            }

            if (processTask.IsCompleted)
            {
                PublishProcessExit(processTask);
                return;
            }

            var failureCode = !ReferenceEquals(handshakeTask, channelTask) &&
                              completed == handshakeTask
                ? "cdp-handshake-faulted"
                : "cdp-transport-faulted";
            try
            {
                await completed.ConfigureAwait(false);
            }
            catch
            {
            }

            if (!_resources.Process.IsAlive)
            {
                PublishProcessExit(processTask);
                return;
            }

            await _delay.DelayAsync(ExitSettleWindow, _observerCancellation.Token)
                .ConfigureAwait(false);
            if (processTask.IsCompleted || !_resources.Process.IsAlive)
            {
                PublishProcessExit(processTask);
                return;
            }

            _exit.TrySetResult(CodexCdpRuntimeExitResult.Faulted(failureCode, ReadUtcNow()));
        }
        catch (OperationCanceledException) when (_observerCancellation.IsCancellationRequested)
        {
        }
        catch
        {
            _exit.TrySetResult(CodexCdpRuntimeExitResult.Faulted(
                "process-exit-observation-failed",
                ReadUtcNow()));
        }
    }

    private void PublishProcessExit(Task<int> processTask)
    {
        try
        {
            var exitCode = processTask.GetAwaiter().GetResult();
            _exit.TrySetResult(CodexCdpRuntimeExitResult.Natural(exitCode, ReadUtcNow()));
        }
        catch (OperationCanceledException) when (_observerCancellation.IsCancellationRequested)
        {
        }
        catch
        {
            _exit.TrySetResult(CodexCdpRuntimeExitResult.Faulted(
                "process-exit-observation-failed",
                ReadUtcNow()));
        }
    }

    private async Task DisposeWinnerAsync(TaskCompletionSource completion)
    {
        await Task.Yield();
        var previous = _activeDispose.Value;
        _activeDispose.Value = this;
        Exception? failure = null;
        try
        {
            try
            {
                _observerCancellation.Cancel();
            }
            catch (Exception exception)
            {
                failure = exception;
            }

            try
            {
                await _observerTask.ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    exception);
            }

            try
            {
                await _resources.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    exception);
            }

            try
            {
                _observerCancellation.Dispose();
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    exception);
            }
        }
        finally
        {
            _activeDispose.Value = previous;
        }

        if (failure is null)
        {
            try
            {
                _released(this);
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        }

        if (failure is null)
        {
            completion.TrySetResult();
        }
        else
        {
            completion.TrySetException(failure);
        }
    }

    private DateTimeOffset ReadUtcNow()
    {
        var value = _utcNow().ToUniversalTime();
        return value == default ? DateTimeOffset.UnixEpoch : value;
    }
}

internal sealed class WindowsCodexCdpRuntimeControlHostV1 : ICodexCdpRuntimeControlHost
{
    private const string SecondaryFailureDataKey = "runtime-control-secondary-failure";
    private static readonly IReadOnlyList<string> LaunchArguments = Array.AsReadOnly(
    [
        WindowsCrtPipeProcess.RemoteDebuggingPipeArgument,
        WindowsCrtPipeProcess.RemoteDebuggingIoPipesArgumentPlaceholder
    ]);
    private readonly object _lifecycleSync = new();
    private readonly AsyncLocal<WindowsCodexCdpRuntimeControlHostV1?> _activeDispose = new();
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly IWindowsCodexRuntimePackageVerifierV1 _packageVerifier;
    private readonly IWindowsCodexRuntimeInventoryV1 _inventory;
    private readonly IWindowsCodexCdpProcessLauncherV1 _launcher;
    private readonly IWindowsCodexCdpChannelFactoryV1 _channelFactory;
    private readonly ICodexCdpRuntimeHandshakeFactoryV1 _handshakeFactory;
    private readonly IWindowsCodexRuntimeDelayV1 _delay;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Func<string> _runtimeIdFactory;
    private IAsyncDisposable? _retainedPrePublicationAuthority;
    private WindowsCodexCdpHandleLeaseV1? _publishedLease;
    private Task? _disposeTask;
    private bool _disposing;

    internal WindowsCodexCdpRuntimeControlHostV1()
        : this(CreateProductionDependencies())
    {
    }

    private WindowsCodexCdpRuntimeControlHostV1(ProductionDependencies dependencies)
        : this(
            dependencies.PackageVerifier,
            dependencies.Inventory,
            dependencies.Launcher,
            dependencies.ChannelFactory,
            dependencies.HandshakeFactory,
            dependencies.Delay,
            dependencies.UtcNow,
            dependencies.RuntimeIdFactory)
    {
    }

    internal WindowsCodexCdpRuntimeControlHostV1(
        IWindowsCodexRuntimePackageVerifierV1 packageVerifier,
        IWindowsCodexRuntimeInventoryV1 inventory,
        IWindowsCodexCdpProcessLauncherV1 launcher,
        IWindowsCodexCdpChannelFactoryV1 channelFactory,
        ICodexCdpRuntimeHandshakeFactoryV1 handshakeFactory,
        IWindowsCodexRuntimeDelayV1 delay,
        Func<DateTimeOffset> utcNow,
        Func<string> runtimeIdFactory)
    {
        _packageVerifier = packageVerifier ?? throw new ArgumentNullException(nameof(packageVerifier));
        _inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        _launcher = launcher ?? throw new ArgumentNullException(nameof(launcher));
        _channelFactory = channelFactory ?? throw new ArgumentNullException(nameof(channelFactory));
        _handshakeFactory = handshakeFactory ?? throw new ArgumentNullException(nameof(handshakeFactory));
        _delay = delay ?? throw new ArgumentNullException(nameof(delay));
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        _runtimeIdFactory = runtimeIdFactory ?? throw new ArgumentNullException(nameof(runtimeIdFactory));
    }

    public async ValueTask<CodexCdpRuntimeReconciliationKind> ReconcileAsync(
        CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetimeCancellation.Token);
        await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            ThrowIfUnavailable();
            if (_retainedPrePublicationAuthority is not null)
            {
                throw Failure(
                    "runtime-candidate-retained",
                    "A pre-publication runtime candidate remains under exact Broker authority.");
            }

            if (ReadPublishedLease() is not null)
            {
                return CodexCdpRuntimeReconciliationKind.ExternalCodexPresent;
            }

            var baseline = _packageVerifier.VerifyPreLaunch();
            var inventory = await CaptureStableInventoryAsync(
                    baseline,
                    candidateProcessId: null,
                    linked.Token)
                .ConfigureAwait(false);
            return inventory.PackageProcesses.Count == 0
                ? CodexCdpRuntimeReconciliationKind.NoCodex
                : CodexCdpRuntimeReconciliationKind.ExternalCodexPresent;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async ValueTask<CodexCdpRuntimeStartResultV1> StartManagedAsync(
        string operationId,
        CancellationToken cancellationToken = default)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(operationId))
        {
            throw new ArgumentException("A valid launch operation identifier is required.", nameof(operationId));
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetimeCancellation.Token);
        await _operationGate.WaitAsync(linked.Token).ConfigureAwait(false);
        WindowsCodexCdpCandidateResourcesV1? candidate = null;
        WindowsCodexCdpHandleLeaseV1? uncommittedLease = null;
        WindowsCodexRuntimePackageBaselineV1? launchBaseline = null;
        try
        {
            ThrowIfUnavailable();
            if (_retainedPrePublicationAuthority is not null)
            {
                throw Failure(
                    "runtime-candidate-retained",
                    "A previous pre-publication runtime candidate remains retained.");
            }

            if (ReadPublishedLease() is not null)
            {
                throw Failure(
                    "runtime-lease-already-published",
                    "The runtime host already retains one published exact lease.");
            }

            var baseline = _packageVerifier.VerifyPreLaunch();
            launchBaseline = baseline;
            var preLaunchInventory = await CaptureStableInventoryAsync(
                    baseline,
                    candidateProcessId: null,
                    linked.Token)
                .ConfigureAwait(false);
            if (preLaunchInventory.PackageProcesses.Count != 0)
            {
                return CodexCdpRuntimeStartResultV1.RaceLost();
            }

            linked.Token.ThrowIfCancellationRequested();
            var workingDirectory = Path.GetDirectoryName(baseline.ExecutablePath) ??
                throw Failure(
                    "runtime-working-directory-invalid",
                    "The pinned ChatGPT executable has no absolute working directory.");
            IWindowsCodexCdpLaunchedProcessV1 process;
            try
            {
                process = _launcher.Launch(
                    baseline.ExecutablePath,
                    LaunchArguments,
                    workingDirectory);
                candidate = new WindowsCodexCdpCandidateResourcesV1(process);
                candidate.AttachChannel(_channelFactory.Create(process));
            }
            catch (WindowsCodexCdpProcessLaunchExceptionV1 exception)
            {
                process = exception.TakeRetainedProcess();
                candidate = new WindowsCodexCdpCandidateResourcesV1(process);
                try
                {
                    candidate.AttachChannel(_channelFactory.Create(process));
                }
                catch (Exception channelFailure)
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        exception,
                        channelFailure,
                        SecondaryFailureDataKey);
                }

                throw;
            }
            linked.Token.ThrowIfCancellationRequested();

            var verified = VerifyCandidateProcess(baseline, process);
            var postLaunchInventory = await CaptureStableInventoryAsync(
                    baseline,
                    process.ProcessId,
                    linked.Token)
                .ConfigureAwait(false);
            ValidateOwnedInventory(postLaunchInventory, verified, process.ProcessId);

            var handshake = await _handshakeFactory.CompleteAsync(
                    candidate.Channel,
                    linked.Token)
                .ConfigureAwait(false);
            candidate.AttachHandshake(handshake);

            _packageVerifier.RevalidateBaseline(baseline);
            var finalVerified = VerifyCandidateProcess(baseline, process);
            if (!SameProcessIdentity(verified, finalVerified))
            {
                throw Failure(
                    "runtime-process-identity-drift",
                    "The exact Codex process identity changed before lease publication.");
            }

            var finalInventory = await CaptureStableInventoryAsync(
                    baseline,
                    process.ProcessId,
                    linked.Token)
                .ConfigureAwait(false);
            ValidateOwnedInventory(finalInventory, finalVerified, process.ProcessId);

            var runtimeId = _runtimeIdFactory();
            if (!CodexCdpBrokerProtocol.IsControlIdentifier(runtimeId))
            {
                throw Failure(
                    "runtime-identifier-invalid",
                    "The runtime identifier factory returned an invalid identifier.");
            }

            uncommittedLease = new WindowsCodexCdpHandleLeaseV1(
                new CodexCdpRuntimeIdentity(
                    runtimeId,
                    operationId,
                    finalVerified.ProcessId,
                    finalVerified.CreationTimeUtc),
                candidate,
                _delay,
                _utcNow,
                ReleasePublishedLease);
            candidate = null;
            linked.Token.ThrowIfCancellationRequested();
            if (!uncommittedLease.IsAlive || uncommittedLease.Exit.IsCompleted)
            {
                throw Failure(
                    "runtime-candidate-exited-before-publication",
                    "The exact Codex candidate ended before lease publication.");
            }

            var result = CodexCdpRuntimeStartResultV1.Owned(uncommittedLease);
            PublishLease(uncommittedLease);
            uncommittedLease = null;
            return result;
        }
        catch (OperationCanceledException)
        {
            RetainPrePublicationAuthority(uncommittedLease ?? (IAsyncDisposable?)candidate);
            uncommittedLease = null;
            candidate = null;
            throw;
        }
        catch (Exception exception)
        {
            if (uncommittedLease is not null)
            {
                RetainPrePublicationAuthority(uncommittedLease);
                uncommittedLease = null;
                throw;
            }

            if (candidate is null)
            {
                throw;
            }

            var classification = await ClassifyPostLaunchFailureAsync(
                    launchBaseline ?? throw new InvalidOperationException(
                        "runtime-launch-baseline-missing"),
                    candidate,
                    exception)
                .ConfigureAwait(false);
            if (classification == PostLaunchFailureClassification.RaceLost)
            {
                candidate = null;
                return CodexCdpRuntimeStartResultV1.RaceLost();
            }

            if (classification == PostLaunchFailureClassification.EarlyExit)
            {
                candidate = null;
                throw Failure(
                    "runtime-candidate-exited-before-ready",
                    "The exact Codex candidate exited before the runtime became ready.",
                    exception);
            }

            RetainPrePublicationAuthority(candidate);
            candidate = null;

            if (classification == PostLaunchFailureClassification.AmbiguousLineage)
            {
                throw Failure(
                    "runtime-candidate-lineage-ambiguous",
                    "The candidate lineage could not be released or classified as a race loss.",
                    exception);
            }

            ExceptionDispatchInfo.Capture(exception).Throw();
            throw;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_lifecycleSync)
        {
            if (_disposeTask is not null)
            {
                if (!_disposeTask.IsCompleted && ReferenceEquals(_activeDispose.Value, this))
                {
                    return ValueTask.FromException(
                        new InvalidOperationException("runtime-host-dispose-reentrant"));
                }

                return new ValueTask(_disposeTask);
            }

            _disposing = true;
            _disposeTask = DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    private async Task DisposeCoreAsync()
    {
        await Task.Yield();
        var previousDispose = _activeDispose.Value;
        _activeDispose.Value = this;
        Exception? failure = null;
        try
        {
            _lifetimeCancellation.Cancel();
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        IAsyncDisposable? retained;
        WindowsCodexCdpHandleLeaseV1? published;
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            retained = _retainedPrePublicationAuthority;
            _retainedPrePublicationAuthority = null;
            published = ReadPublishedLease();
        }
        finally
        {
            _operationGate.Release();
        }

        if (published is not null)
        {
            try
            {
                await published.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        }

        if (retained is not null && !ReferenceEquals(retained, published))
        {
            try
            {
                await retained.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                    failure,
                    exception);
            }
        }

        try
        {
            _operationGate.Dispose();
            _lifetimeCancellation.Dispose();
        }
        catch (Exception exception)
        {
            failure = BrokerControlFailureArbitration.PreserveCleanupFailure(
                failure,
                exception);
        }

        if (failure is not null)
        {
            _activeDispose.Value = previousDispose;
            ExceptionDispatchInfo.Capture(failure).Throw();
        }

        _activeDispose.Value = previousDispose;
    }

    private async ValueTask<WindowsCodexRuntimeInventorySnapshotV1> CaptureStableInventoryAsync(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        int? candidateProcessId,
        CancellationToken cancellationToken)
    {
        var first = await _inventory.CaptureAsync(
                baseline,
                candidateProcessId,
                cancellationToken)
            .ConfigureAwait(false);
        RequireCompleteInventory(first);
        _packageVerifier.RevalidateBaseline(baseline);
        cancellationToken.ThrowIfCancellationRequested();
        var second = await _inventory.CaptureAsync(
                baseline,
                candidateProcessId,
                cancellationToken)
            .ConfigureAwait(false);
        RequireCompleteInventory(second);
        if (!first.EquivalentTo(second))
        {
            throw Failure(
                "runtime-inventory-unstable",
                "The relevant Codex process inventory changed during verification.");
        }

        return second;
    }

    private CodexVerifiedProcessSnapshot VerifyCandidateProcess(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        IWindowsCodexCdpLaunchedProcessV1 process)
    {
        using var verificationHandle = process.DuplicateRetainedProcessHandleForVerification();
        return _packageVerifier.VerifyPostLaunch(
            baseline,
            process.ProcessId,
            verificationHandle);
    }

    private static void ValidateOwnedInventory(
        WindowsCodexRuntimeInventorySnapshotV1 inventory,
        CodexVerifiedProcessSnapshot verified,
        int candidateProcessId)
    {
        RequireCompleteInventory(inventory);
        if (!inventory.ContainsExactProcess(verified))
        {
            throw Failure(
                "runtime-candidate-missing-from-inventory",
                "The exact verified Codex candidate is absent from the stable inventory.");
        }

        if (inventory.HasIndependentPackageProcess(candidateProcessId))
        {
            throw Failure(
                "runtime-independent-codex-detected",
                "An independent exact Codex root appeared before lease publication.");
        }
    }

    private async ValueTask<PostLaunchFailureClassification> ClassifyPostLaunchFailureAsync(
        WindowsCodexRuntimePackageBaselineV1 baseline,
        WindowsCodexCdpCandidateResourcesV1 candidate,
        Exception originalFailure)
    {
        bool candidateAlive;
        try
        {
            candidateAlive = candidate.Process.IsAlive;
        }
        catch
        {
            return PostLaunchFailureClassification.AmbiguousLineage;
        }

        if (candidateAlive)
        {
            return PostLaunchFailureClassification.Retained;
        }

        try
        {
            var inventory = await CaptureStableInventoryAsync(
                    baseline,
                    candidate.Process.ProcessId,
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (inventory.CandidateDescendants.Count != 0)
            {
                return PostLaunchFailureClassification.AmbiguousLineage;
            }

            if (!inventory.HasIndependentPackageProcess(candidate.Process.ProcessId))
            {
                try
                {
                    await candidate.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception cleanupFailure)
                {
                    BrokerControlFailureArbitration.PreserveSecondaryFailure(
                        originalFailure,
                        cleanupFailure,
                        SecondaryFailureDataKey);
                    RetainPrePublicationAuthority(candidate);
                    ExceptionDispatchInfo.Capture(originalFailure).Throw();
                }

                return PostLaunchFailureClassification.EarlyExit;
            }

            try
            {
                await candidate.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception cleanupFailure)
            {
                BrokerControlFailureArbitration.PreserveSecondaryFailure(
                    originalFailure,
                    cleanupFailure,
                    SecondaryFailureDataKey);
                RetainPrePublicationAuthority(candidate);
                ExceptionDispatchInfo.Capture(originalFailure).Throw();
            }

            return PostLaunchFailureClassification.RaceLost;
        }
        catch (Exception classificationFailure)
        {
            if (_retainedPrePublicationAuthority is null)
            {
                RetainPrePublicationAuthority(candidate);
            }

            BrokerControlFailureArbitration.PreserveSecondaryFailure(
                classificationFailure,
                originalFailure,
                SecondaryFailureDataKey);
            ExceptionDispatchInfo.Capture(classificationFailure).Throw();
            throw;
        }
    }

    private void RetainPrePublicationAuthority(IAsyncDisposable? authority)
    {
        if (authority is null)
        {
            return;
        }

        if (_retainedPrePublicationAuthority is not null &&
            !ReferenceEquals(_retainedPrePublicationAuthority, authority))
        {
            throw Failure(
                "runtime-retained-authority-conflict",
                "The runtime host already retains another pre-publication authority.");
        }

        _retainedPrePublicationAuthority = authority;
    }

    private void ReleasePublishedLease(WindowsCodexCdpHandleLeaseV1 lease)
    {
        lock (_lifecycleSync)
        {
            if (ReferenceEquals(_publishedLease, lease))
            {
                _publishedLease = null;
            }
        }
    }

    private WindowsCodexCdpHandleLeaseV1? ReadPublishedLease()
    {
        lock (_lifecycleSync)
        {
            return _publishedLease;
        }
    }

    private void PublishLease(WindowsCodexCdpHandleLeaseV1 lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        lock (_lifecycleSync)
        {
            ObjectDisposedException.ThrowIf(_disposing, this);
            if (_publishedLease is not null)
            {
                throw Failure(
                    "runtime-lease-publication-conflict",
                    "The runtime host already published another exact lease.");
            }

            _publishedLease = lease;
        }
    }

    private void ThrowIfUnavailable()
    {
        lock (_lifecycleSync)
        {
            ObjectDisposedException.ThrowIf(_disposing, this);
        }
    }

    private static void RequireCompleteInventory(
        WindowsCodexRuntimeInventorySnapshotV1 inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        if (!inventory.IsComplete)
        {
            throw Failure(
                inventory.FailureCode ?? "runtime-inventory-indeterminate",
                "The relevant Codex process inventory is incomplete.");
        }
    }

    private static bool SameProcessIdentity(
        CodexVerifiedProcessSnapshot left,
        CodexVerifiedProcessSnapshot right) =>
        left.ProcessId == right.ProcessId &&
        left.CreationTimeUtc == right.CreationTimeUtc &&
        string.Equals(left.UserSid, right.UserSid, StringComparison.OrdinalIgnoreCase) &&
        left.SessionId == right.SessionId &&
        string.Equals(left.PackageFullName, right.PackageFullName, StringComparison.Ordinal) &&
        string.Equals(left.PackageFamilyName, right.PackageFamilyName, StringComparison.Ordinal) &&
        string.Equals(left.ImagePath, right.ImagePath, StringComparison.OrdinalIgnoreCase);

    private static WindowsCodexRuntimeControlException Failure(
        string code,
        string message,
        Exception? innerException = null) =>
        new(code, message, innerException);

    private static ProductionDependencies CreateProductionDependencies()
    {
        var resources = CodexCdpRuntimeResources.Load();
        var verifier = new CodexPackageBaselineVerifier(
            resources.Profile,
            CodexPackageTrustMode.StoreOnly);
        var delay = new WindowsCodexRuntimeDelayV1();
        return new ProductionDependencies(
            new WindowsCodexRuntimePackageVerifierV1(verifier),
            new WindowsCodexRuntimeInventoryV1(),
            new WindowsCodexCdpProcessLauncherV1(),
            new WindowsCodexCdpChannelFactoryV1(),
            new ReadOnlyCodexCdpRuntimeHandshakeFactoryV1(
                delay,
                resources.Profile.PageProtocol),
            delay,
            () => DateTimeOffset.UtcNow,
            CreateRuntimeId);
    }

    private static string CreateRuntimeId()
    {
        Span<byte> random = stackalloc byte[16];
        RandomNumberGenerator.Fill(random);
        return "runtime-codex-" + Convert.ToHexString(random).ToLowerInvariant();
    }

    private sealed record ProductionDependencies(
        IWindowsCodexRuntimePackageVerifierV1 PackageVerifier,
        IWindowsCodexRuntimeInventoryV1 Inventory,
        IWindowsCodexCdpProcessLauncherV1 Launcher,
        IWindowsCodexCdpChannelFactoryV1 ChannelFactory,
        ICodexCdpRuntimeHandshakeFactoryV1 HandshakeFactory,
        IWindowsCodexRuntimeDelayV1 Delay,
        Func<DateTimeOffset> UtcNow,
        Func<string> RuntimeIdFactory);

    private enum PostLaunchFailureClassification
    {
        Retained,
        RaceLost,
        EarlyExit,
        AmbiguousLineage
    }
}
