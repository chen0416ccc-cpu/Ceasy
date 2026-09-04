using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CodexGuardian.Control;

internal enum WindowsCrtPipeProcessDisposeBehavior
{
    DisconnectOnly
#if CODEXGUARDIAN_TEST_FRIEND
    ,
    TerminateExactRootForTests
#endif
}

internal interface IWindowsCrtPipeProcessRetainedCandidate : IDisposable, IAsyncDisposable
{
    int ProcessId { get; }

    Stream ReadStream { get; }

    Stream WriteStream { get; }

    bool HasExited { get; }

    SafeProcessHandle DuplicateRetainedProcessHandleForVerification();

    Task<int> WaitForExitAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

internal sealed class WindowsCrtPipeProcessStartException : IOException
{
    private readonly object _gate = new();
    private IWindowsCrtPipeProcessRetainedCandidate? _retainedCandidate;

    internal WindowsCrtPipeProcessStartException(
        IWindowsCrtPipeProcessRetainedCandidate retainedCandidate,
        Exception innerException)
        : base(
            "The direct-handle CDP child was created but its retained process wrapper " +
            "could not be published.",
            innerException)
    {
        _retainedCandidate = retainedCandidate ??
            throw new ArgumentNullException(nameof(retainedCandidate));
    }

    internal int ProcessId
    {
        get
        {
            lock (_gate)
            {
                return _retainedCandidate?.ProcessId ??
                    throw new InvalidOperationException(
                        "The retained direct-handle CDP candidate was already transferred.");
            }
        }
    }

    internal IWindowsCrtPipeProcessRetainedCandidate TakeRetainedCandidate()
    {
        lock (_gate)
        {
            var candidate = _retainedCandidate ??
                throw new InvalidOperationException(
                    "The retained direct-handle CDP candidate can be transferred only once.");
            _retainedCandidate = null;
            return candidate;
        }
    }
}

internal static class WindowsCrtPipeProcessLaunchPublication
{
    internal static TResult Publish<TResult>(
        IWindowsCrtPipeProcessRetainedCandidate retainedCandidate,
        Func<TResult> publisher)
    {
        ArgumentNullException.ThrowIfNull(retainedCandidate);
        ArgumentNullException.ThrowIfNull(publisher);
        try
        {
            return publisher();
        }
        catch (Exception exception)
        {
            throw new WindowsCrtPipeProcessStartException(retainedCandidate, exception);
        }
    }
}

internal static class WindowsCrtPipeProcessEnvironment
{
    internal const int MaximumEnvironmentBlockCharacters = 32767;

    private const string FixedPathExtensionList = ".COM;.EXE;.BAT;.CMD";
    private static readonly IReadOnlyList<string> AllowedNames = Array.AsReadOnly(
    [
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
    ]);
    private static readonly IReadOnlyDictionary<string, string> CanonicalNames =
        AllowedNames.ToDictionary(name => name, StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> FixedNames = new(
        new[]
        {
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATH",
            "PATHEXT",
            "OS",
            "SystemDrive"
        },
        StringComparer.OrdinalIgnoreCase);

    internal static IReadOnlyList<string> AllowedVariableNames => AllowedNames;

    internal static IntPtr BuildUnmanagedBlock()
    {
        var source = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in AllowedNames)
        {
            if (!FixedNames.Contains(name))
            {
                source[name] = Environment.GetEnvironmentVariable(name);
            }
        }

        return BuildUnmanagedBlock(BuildBlockText(source, ReadTrustedSystemRoot()));
    }

    internal static string BuildBlockText(
        IReadOnlyDictionary<string, string?> source,
        string trustedSystemRoot)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(trustedSystemRoot);
        var values = ReadAllowedValues(source);
        var systemRoot = NormalizeSystemRoot(trustedSystemRoot);

        values["SystemRoot"] = systemRoot;
        values["WINDIR"] = systemRoot;
        values["ComSpec"] = CombineSystemRoot(systemRoot, "System32\\cmd.exe");
        values["PATH"] = string.Join(
            ";",
            new[]
            {
                CombineSystemRoot(systemRoot, "System32"),
                systemRoot,
                CombineSystemRoot(systemRoot, "System32\\Wbem"),
                CombineSystemRoot(systemRoot, "System32\\WindowsPowerShell\\v1.0")
            });
        values["PATHEXT"] = FixedPathExtensionList;
        values["OS"] = "Windows_NT";
        values["SystemDrive"] = systemRoot[..2];

        var entries = values
            .Where(pair => pair.Value is not null)
            .Select(pair => new EnvironmentEntry(pair.Key, pair.Value!))
            .ToList();
        entries.Sort(static (left, right) =>
            StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name));

        var block = new StringBuilder();
        foreach (var entry in entries)
        {
            var requiredCharacters = checked(entry.Name.Length + 1 + entry.Value.Length + 1);
            if (block.Length > MaximumEnvironmentBlockCharacters - requiredCharacters)
            {
                throw new ArgumentException(
                    "The explicit Codex child environment block is too large.",
                    nameof(source));
            }

            block.Append(entry.Name);
            block.Append('=');
            block.Append(entry.Value);
            block.Append('\0');
        }

        if (block.Length >= MaximumEnvironmentBlockCharacters)
        {
            throw new ArgumentException(
                "The explicit Codex child environment block is too large.",
                nameof(source));
        }

        block.Append('\0');
        return block.ToString();
    }

    private static IntPtr BuildUnmanagedBlock(string block)
    {
        ArgumentNullException.ThrowIfNull(block);
        var bytes = Encoding.Unicode.GetBytes(block);
        var pointer = Marshal.AllocHGlobal(checked(bytes.Length));
        try
        {
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }
        catch
        {
            Marshal.FreeHGlobal(pointer);
            throw;
        }
    }

    private static Dictionary<string, string?> ReadAllowedValues(
        IReadOnlyDictionary<string, string?> source)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in source)
        {
            if (!CanonicalNames.TryGetValue(pair.Key, out var canonicalName))
            {
                continue;
            }

            if (!seen.Add(canonicalName))
            {
                throw new ArgumentException(
                    "The explicit Codex child environment contains duplicate names.",
                    nameof(source));
            }

            if (FixedNames.Contains(canonicalName))
            {
                continue;
            }

            if (pair.Value is not null)
            {
                RejectEnvironmentText(pair.Value, "An environment value");
            }

            values[canonicalName] = pair.Value;
        }

        return values;
    }

    private static string ReadTrustedSystemRoot()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The explicit Codex child environment is Windows-only.");
        }

        var buffer = new StringBuilder(260);
        var length = GetWindowsDirectoryW(buffer, checked((uint)buffer.Capacity));
        if (length == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to resolve the trusted Windows directory.");
        }

        if (length >= buffer.Capacity)
        {
            if (length > MaximumEnvironmentBlockCharacters)
            {
                throw new Win32Exception("The trusted Windows directory is too long.");
            }

            buffer = new StringBuilder(checked((int)length));
            length = GetWindowsDirectoryW(buffer, checked((uint)buffer.Capacity));
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to resolve the complete trusted Windows directory.");
            }
        }

        var systemRoot = NormalizeSystemRoot(buffer.ToString(0, checked((int)length)));
        if (!Directory.Exists(systemRoot))
        {
            throw new DirectoryNotFoundException(
                "The trusted Windows directory does not exist: " + systemRoot);
        }

        return systemRoot;
    }

    private static string NormalizeSystemRoot(string systemRoot)
    {
        RejectEnvironmentText(systemRoot, "SystemRoot");
        if (systemRoot.Length < 3 ||
            !char.IsAsciiLetter(systemRoot[0]) ||
            systemRoot[1] != ':' ||
            systemRoot[2] is not '\\' and not '/')
        {
            throw new ArgumentException(
                "SystemRoot must be an absolute drive path.",
                nameof(systemRoot));
        }

        var requested = systemRoot.Replace('/', '\\');
        if (requested.IndexOf(';') >= 0 ||
            requested.IndexOf('%') >= 0 ||
            requested.IndexOf('"') >= 0)
        {
            throw new ArgumentException(
                "SystemRoot contains a path-injection character.",
                nameof(systemRoot));
        }

        var canonical = Path.GetFullPath(requested);
        var requestedWithoutTrailingSeparators = requested.TrimEnd('\\');
        var canonicalWithoutTrailingSeparators = canonical.TrimEnd('\\');
        if (!string.Equals(
                requestedWithoutTrailingSeparators,
                canonicalWithoutTrailingSeparators,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "SystemRoot contains a non-canonical path segment.",
                nameof(systemRoot));
        }

        return canonicalWithoutTrailingSeparators.Length == 2
            ? canonicalWithoutTrailingSeparators + '\\'
            : canonicalWithoutTrailingSeparators;
    }

    private static string CombineSystemRoot(string systemRoot, string suffix) =>
        systemRoot.EndsWith('\\')
            ? systemRoot + suffix
            : systemRoot + "\\" + suffix;

    private static void RejectEnvironmentText(string value, string label)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (character < 0x20 || character == 0x7F)
            {
                throw new ArgumentException(
                    label + " contains a forbidden control character.");
            }
        }
    }

    private readonly record struct EnvironmentEntry(string Name, string Value);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true)]
    private static extern uint GetWindowsDirectoryW(StringBuilder buffer, uint size);
}

internal sealed record WindowsCrtPipeProcessCleanupStep(
    string Code,
    Action Cleanup);

internal sealed class WindowsCrtPipeProcessSecondaryCleanupException : IOException
{
    internal WindowsCrtPipeProcessSecondaryCleanupException(
        string code,
        Exception innerException)
        : base("A secondary direct-handle CDP process cleanup step failed.", innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal sealed class WindowsCrtPipeProcessDisposal : IDisposable, IAsyncDisposable
{
    internal const string SecondaryCleanupFailureDataKey =
        "windows-crt-pipe-secondary-cleanup-failure";
    internal const string SecondaryCleanupOverflowDataKey =
        "windows-crt-pipe-secondary-cleanup-overflow";
    internal const int MaximumSecondaryCleanupFailures = 4;
    private const int MaximumCleanupSteps = 8;

    private readonly object _gate = new();
    private readonly WindowsCrtPipeProcessCleanupStep[] _steps;
    private Task? _disposeTask;
    private int _disposeStarted;
    private int _winnerThreadId;

    internal WindowsCrtPipeProcessDisposal(
        IEnumerable<WindowsCrtPipeProcessCleanupStep> steps)
    {
        ArgumentNullException.ThrowIfNull(steps);
        _steps = steps.ToArray();
        if (_steps.Length is < 1 or > MaximumCleanupSteps)
        {
            throw new ArgumentOutOfRangeException(nameof(steps));
        }

        foreach (var step in _steps)
        {
            ArgumentNullException.ThrowIfNull(step);
            ArgumentNullException.ThrowIfNull(step.Cleanup);
            if (!IsCleanupCode(step.Code))
            {
                throw new ArgumentException(
                    "A bounded cleanup step code is required.",
                    nameof(steps));
            }
        }
    }

    internal bool IsDisposeStarted => Volatile.Read(ref _disposeStarted) != 0;

    public void Dispose()
    {
        var task = GetOrStartDisposeTask();
        if (!task.IsCompleted &&
            Volatile.Read(ref _winnerThreadId) == Environment.CurrentManagedThreadId)
        {
            throw new InvalidOperationException(
                "Reentrant direct-handle CDP process disposal is not supported.");
        }

        task.GetAwaiter().GetResult();
    }

    public ValueTask DisposeAsync()
    {
        var task = GetOrStartDisposeTask();
        if (!task.IsCompleted &&
            Volatile.Read(ref _winnerThreadId) == Environment.CurrentManagedThreadId)
        {
            return new ValueTask(Task.FromException(new InvalidOperationException(
                "Reentrant direct-handle CDP process disposal is not supported.")));
        }

        return new ValueTask(task);
    }

    private Task GetOrStartDisposeTask()
    {
        TaskCompletionSource completion;
        lock (_gate)
        {
            if (_disposeTask is not null)
            {
                return _disposeTask;
            }

            completion = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _disposeTask = completion.Task;
            Volatile.Write(ref _disposeStarted, 1);
            Volatile.Write(ref _winnerThreadId, Environment.CurrentManagedThreadId);
        }

        CompleteDisposal(completion);
        return completion.Task;
    }

    private void CompleteDisposal(TaskCompletionSource completion)
    {
        Exception? primary = null;
        var secondary = new List<Exception>();
        var overflow = 0;
        try
        {
            foreach (var step in _steps)
            {
                try
                {
                    step.Cleanup();
                }
                catch (Exception exception)
                {
                    if (primary is null)
                    {
                        primary = exception;
                    }
                    else if (!ReferenceEquals(primary, exception))
                    {
                        if (secondary.Count < MaximumSecondaryCleanupFailures)
                        {
                            secondary.Add(new WindowsCrtPipeProcessSecondaryCleanupException(
                                step.Code,
                                exception));
                        }
                        else
                        {
                            overflow++;
                        }
                    }
                }
            }

            if (primary is null)
            {
                completion.TrySetResult();
                return;
            }

            if (secondary.Count > 0)
            {
                primary.Data[SecondaryCleanupFailureDataKey] =
                    new AggregateException(secondary);
            }
            if (overflow > 0)
            {
                primary.Data[SecondaryCleanupOverflowDataKey] = overflow;
            }

            completion.TrySetException(primary);
        }
        finally
        {
            Volatile.Write(ref _winnerThreadId, 0);
        }
    }

    private static bool IsCleanupCode(string? value)
    {
        if (value is null || value.Length is < 3 or > 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')
            {
                return false;
            }
        }

        return true;
    }
}

internal sealed class WindowsCrtPipeProcess : IDisposable, IAsyncDisposable
{
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint HandleFlagInherit = 0x00000001;
    private const int MaximumCommandLineCharacters = 32767;
    private const uint ProcThreadAttributeHandleList = 0x00020002;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xFFFFFFFF;
#if CODEXGUARDIAN_TEST_FRIEND
    private const uint TestTerminationExitCode = 0xC0DE0001;
#endif

    internal const string RemoteDebuggingPipeArgument = "--remote-debugging-pipe";
    internal const string RemoteDebuggingIoPipesArgumentPlaceholder =
        "--remote-debugging-io-pipes={readHandle},{writeHandle}";
    internal const string RemoteDebuggingIoPipesArgumentPrefix =
        "--remote-debugging-io-pipes=";

    private readonly RetainedCandidate _candidate;

    private WindowsCrtPipeProcess(RetainedCandidate candidate)
    {
        _candidate = candidate;
    }

    internal int ProcessId => _candidate.ProcessId;

    // Parent reads CDP responses and notifications from the child's explicit write handle.
    internal FileStream ReadStream => _candidate.ReadFileStream;

    // Parent writes CDP commands to the child's explicit read handle.
    internal FileStream WriteStream => _candidate.WriteFileStream;

    internal bool HasExited => _candidate.HasExited;

    internal SafeProcessHandle DuplicateRetainedProcessHandleForVerification() =>
        _candidate.DuplicateRetainedProcessHandleForVerification();

    internal static WindowsCrtPipeProcess Start(
        string executablePath,
        IReadOnlyList<string> arguments,
        string? workingDirectory = null,
        WindowsCrtPipeProcessDisposeBehavior disposeBehavior =
            WindowsCrtPipeProcessDisposeBehavior.DisconnectOnly)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("CRT descriptor pipe launch is Windows-only.");
        }

        if (string.IsNullOrWhiteSpace(executablePath) ||
            !Path.IsPathFullyQualified(executablePath) ||
            executablePath.IndexOf('\0') >= 0)
        {
            throw new ArgumentException(
                "An explicit absolute executable path is required.",
                nameof(executablePath));
        }

        var normalizedExecutablePath = Path.GetFullPath(executablePath);
        if (!File.Exists(normalizedExecutablePath))
        {
            throw new FileNotFoundException(
                "The explicitly requested executable was not found.",
                normalizedExecutablePath);
        }

        ArgumentNullException.ThrowIfNull(arguments);
        var remoteDebuggingPipeArgumentCount = 0;
        var remoteDebuggingIoPipesPlaceholderCount = 0;
        for (var index = 0; index < arguments.Count; index++)
        {
            if (arguments[index] is null || arguments[index].IndexOf('\0') >= 0)
            {
                throw new ArgumentException(
                    "Process arguments cannot be null or contain NUL characters.",
                    nameof(arguments));
            }

            if (string.Equals(
                    arguments[index],
                    RemoteDebuggingPipeArgument,
                    StringComparison.Ordinal))
            {
                remoteDebuggingPipeArgumentCount++;
            }

            if (string.Equals(
                    arguments[index],
                    RemoteDebuggingIoPipesArgumentPlaceholder,
                    StringComparison.Ordinal))
            {
                remoteDebuggingIoPipesPlaceholderCount++;
            }
            else if (arguments[index].StartsWith(
                RemoteDebuggingIoPipesArgumentPrefix,
                StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The remote-debugging I/O pipe handles must use the explicit placeholder.",
                    nameof(arguments));
            }
        }
        if (remoteDebuggingPipeArgumentCount != 1 ||
            remoteDebuggingIoPipesPlaceholderCount != 1)
        {
            throw new ArgumentException(
                "The arguments must contain exactly one remote-debugging-pipe flag and one " +
                "remote-debugging I/O handle placeholder.",
                nameof(arguments));
        }

        string? normalizedWorkingDirectory = null;
        if (workingDirectory is not null)
        {
            if (!Path.IsPathFullyQualified(workingDirectory) || workingDirectory.IndexOf('\0') >= 0)
            {
                throw new ArgumentException(
                    "The working directory must be an explicit absolute path.",
                    nameof(workingDirectory));
            }

            normalizedWorkingDirectory = Path.GetFullPath(workingDirectory);
            if (!Directory.Exists(normalizedWorkingDirectory))
            {
                throw new DirectoryNotFoundException(
                    "The explicitly requested working directory was not found: " +
                    normalizedWorkingDirectory);
            }
        }

        if (!Enum.IsDefined(disposeBehavior))
        {
            throw new ArgumentOutOfRangeException(nameof(disposeBehavior));
        }

        SafeFileHandle? childRead = null;
        SafeFileHandle? parentWrite = null;
        SafeFileHandle? parentRead = null;
        SafeFileHandle? childWrite = null;
        FileStream? readStream = null;
        FileStream? writeStream = null;
        RetainedCandidate? retainedCandidate = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr attributeHandles = IntPtr.Zero;
        IntPtr environmentBlock = IntPtr.Zero;
        var attributeListInitialized = false;
        try
        {
            CreateInheritedPipe(out var createdChildRead, out var createdParentWrite);
            childRead = createdChildRead;
            parentWrite = createdParentWrite;
            SetNonInheritable(parentWrite);

            CreateInheritedPipe(out var createdParentRead, out var createdChildWrite);
            parentRead = createdParentRead;
            childWrite = createdChildWrite;
            SetNonInheritable(parentRead);

            var attributeListSize = IntPtr.Zero;
            _ = InitializeProcThreadAttributeList(
                IntPtr.Zero,
                attributeCount: 1,
                flags: 0,
                ref attributeListSize);
            if (attributeListSize == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to size the Windows process attribute list.");
            }

            attributeList = Marshal.AllocHGlobal(attributeListSize);
            if (!InitializeProcThreadAttributeList(
                    attributeList,
                    attributeCount: 1,
                    flags: 0,
                    ref attributeListSize))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to initialize the Windows process attribute list.");
            }

            attributeListInitialized = true;
            attributeHandles = Marshal.AllocHGlobal(checked(IntPtr.Size * 2));
            Marshal.WriteIntPtr(attributeHandles, 0, childRead.DangerousGetHandle());
            Marshal.WriteIntPtr(attributeHandles, IntPtr.Size, childWrite.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(
                    attributeList,
                    flags: 0,
                    new IntPtr(ProcThreadAttributeHandleList),
                    attributeHandles,
                    new IntPtr(checked(IntPtr.Size * 2)),
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to restrict the Windows child handle list.");
            }

            var childReadValue = ToChromiumHandleValue(childRead);
            var childWriteValue = ToChromiumHandleValue(childWrite);
            var effectiveArguments = arguments
                .Select(argument => string.Equals(
                    argument,
                    RemoteDebuggingIoPipesArgumentPlaceholder,
                    StringComparison.Ordinal)
                        ? RemoteDebuggingIoPipesArgumentPrefix +
                            childReadValue.ToString(CultureInfo.InvariantCulture) + "," +
                            childWriteValue.ToString(CultureInfo.InvariantCulture)
                        : argument)
                .ToArray();
            var commandLine = BuildCommandLine(normalizedExecutablePath, effectiveArguments);
            if (commandLine.Length >= MaximumCommandLineCharacters)
            {
                throw new ArgumentException(
                    "The Windows process command line is too long.",
                    nameof(arguments));
            }

            var startupInfo = new STARTUPINFOEX
            {
                StartupInfo = new STARTUPINFO
                {
                    cb = checked((uint)Marshal.SizeOf<STARTUPINFOEX>())
                },
                lpAttributeList = attributeList
            };

            environmentBlock = WindowsCrtPipeProcessEnvironment.BuildUnmanagedBlock();

            // Complete every recoverable managed pipe setup step before the child exists.
            readStream = new FileStream(
                parentRead,
                FileAccess.Read,
                bufferSize: 4096,
                isAsync: false);
            parentRead = null;
            writeStream = new FileStream(
                parentWrite,
                FileAccess.Write,
                bufferSize: 4096,
                isAsync: false);
            parentWrite = null;
            retainedCandidate = new RetainedCandidate(
                readStream,
                writeStream,
                disposeBehavior);
            readStream = null;
            writeStream = null;

            if (!CreateProcessW(
                    normalizedExecutablePath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles: true,
                    ExtendedStartupInfoPresent | CreateUnicodeEnvironment,
                    environmentBlock,
                    normalizedWorkingDirectory,
                    ref startupInfo,
                    out var processInformation))
            {
                var failure = new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The explicitly requested direct-handle CDP child process could not be started.");
                try
                {
                    retainedCandidate.Dispose();
                }
                catch (Exception cleanupFailure)
                {
                    failure.Data[
                        WindowsCrtPipeProcessDisposal.SecondaryCleanupFailureDataKey] =
                        new AggregateException(cleanupFailure);
                }

                retainedCandidate = null;
                throw failure;
            }

            try
            {
                var exactCandidate = retainedCandidate!;
                exactCandidate.AttachCreatedProcess(
                    unchecked((int)processInformation.dwProcessId),
                    processInformation.hProcess);
                return WindowsCrtPipeProcessLaunchPublication.Publish(
                    exactCandidate,
                    () => new WindowsCrtPipeProcess(exactCandidate));
            }
            finally
            {
                if (processInformation.hThread != IntPtr.Zero)
                {
                    _ = CloseHandle(processInformation.hThread);
                }
            }
        }
        finally
        {
            if (environmentBlock != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(environmentBlock);
            }

            readStream?.Dispose();
            writeStream?.Dispose();
            childRead?.Dispose();
            childWrite?.Dispose();
            parentRead?.Dispose();
            parentWrite?.Dispose();
            if (attributeListInitialized)
            {
                DeleteProcThreadAttributeList(attributeList);
            }

            if (attributeList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(attributeList);
            }

            if (attributeHandles != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(attributeHandles);
            }

            GC.KeepAlive(childRead);
            GC.KeepAlive(childWrite);
        }
    }

    internal Task<int> WaitForExitAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        _candidate.WaitForExitAsync(timeout, cancellationToken);

    public void Dispose() => _candidate.Dispose();

    public ValueTask DisposeAsync() => _candidate.DisposeAsync();

    private static void CreateInheritedPipe(
        out SafeFileHandle readHandle,
        out SafeFileHandle writeHandle)
    {
        var securityAttributes = new SECURITY_ATTRIBUTES
        {
            nLength = checked((uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>()),
            bInheritHandle = 1
        };
        if (CreatePipe(out readHandle, out writeHandle, ref securityAttributes, size: 0))
        {
            return;
        }

        readHandle?.Dispose();
        writeHandle?.Dispose();
        throw new Win32Exception(
            Marshal.GetLastWin32Error(),
            "Unable to create a direct-handle CDP child pipe.");
    }

    private static void SetNonInheritable(SafeFileHandle handle)
    {
        if (!SetHandleInformation(handle, HandleFlagInherit, flags: 0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to make a parent pipe handle non-inheritable.");
        }
    }

    private static uint ToChromiumHandleValue(SafeFileHandle handle)
    {
        var value = handle.DangerousGetHandle().ToInt64();
        if (value < 0 || value > uint.MaxValue)
        {
            throw new Win32Exception(
                "A pipe handle cannot be represented by Chromium's uint32 I/O pipe switch.");
        }

        return checked((uint)value);
    }

    private static StringBuilder BuildCommandLine(
        string executablePath,
        IReadOnlyList<string> arguments)
    {
        var commandLine = new StringBuilder();
        AppendQuotedArgument(commandLine, executablePath);
        foreach (var argument in arguments)
        {
            commandLine.Append(' ');
            AppendQuotedArgument(commandLine, argument);
        }

        return commandLine;
    }

    private static void AppendQuotedArgument(StringBuilder commandLine, string argument)
    {
        if (argument.Length > 0 &&
            argument.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0)
        {
            commandLine.Append(argument);
            return;
        }

        commandLine.Append('"');
        var backslashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                commandLine.Append('\\', checked((backslashes * 2) + 1));
                commandLine.Append('"');
                backslashes = 0;
                continue;
            }

            commandLine.Append('\\', backslashes);
            backslashes = 0;
            commandLine.Append(character);
        }

        commandLine.Append('\\', checked(backslashes * 2));
        commandLine.Append('"');
    }

    private sealed class RetainedCandidate : IWindowsCrtPipeProcessRetainedCandidate
    {
        private readonly WindowsCrtPipeProcessDisposal _disposal;
        private SafeProcessHandle? _processHandle;
        private IntPtr _rawProcessHandle;
        private int _processId;

        internal RetainedCandidate(
            FileStream readStream,
            FileStream writeStream,
            WindowsCrtPipeProcessDisposeBehavior disposeBehavior)
        {
            ReadFileStream = readStream;
            WriteFileStream = writeStream;

            var cleanup = new List<WindowsCrtPipeProcessCleanupStep>(4);
#if CODEXGUARDIAN_TEST_FRIEND
            if (disposeBehavior ==
                WindowsCrtPipeProcessDisposeBehavior.TerminateExactRootForTests)
            {
                cleanup.Add(new WindowsCrtPipeProcessCleanupStep(
                    "terminate-test-root",
                    TerminateExactRootForTests));
            }
#endif

            cleanup.Add(new WindowsCrtPipeProcessCleanupStep(
                "read-stream",
                ReadFileStream.Dispose));
            if (!ReferenceEquals(ReadFileStream, WriteFileStream))
            {
                cleanup.Add(new WindowsCrtPipeProcessCleanupStep(
                    "write-stream",
                    WriteFileStream.Dispose));
            }
            cleanup.Add(new WindowsCrtPipeProcessCleanupStep(
                "process-handle",
                DisposeProcessAuthority));
            _disposal = new WindowsCrtPipeProcessDisposal(cleanup);
        }

        public int ProcessId => Volatile.Read(ref _processId);

        internal FileStream ReadFileStream { get; }

        internal FileStream WriteFileStream { get; }

        Stream IWindowsCrtPipeProcessRetainedCandidate.ReadStream => ReadFileStream;

        Stream IWindowsCrtPipeProcessRetainedCandidate.WriteStream => WriteFileStream;

        internal void AttachCreatedProcess(int processId, IntPtr processHandle)
        {
            _processId = processId;
            _rawProcessHandle = processHandle;
            try
            {
                if (processId <= 0 || processHandle == IntPtr.Zero)
                {
                    throw new Win32Exception(
                        "Windows returned an invalid direct-handle CDP child identity.");
                }

                var retainedProcessHandle = new SafeProcessHandle(
                    processHandle,
                    ownsHandle: true);
                if (retainedProcessHandle.IsInvalid)
                {
                    retainedProcessHandle.Dispose();
                    throw new Win32Exception(
                        "Windows returned an invalid direct-handle CDP child process handle.");
                }

                _processHandle = retainedProcessHandle;
                _rawProcessHandle = IntPtr.Zero;
            }
            catch (Exception exception)
            {
                throw new WindowsCrtPipeProcessStartException(this, exception);
            }
        }

        public bool HasExited
        {
            get
            {
                ThrowIfDisposed();
                var waitResult = WaitForProcess(0);
                return waitResult switch
                {
                    WaitObject0 => true,
                    WaitTimeout => false,
                    WaitFailed => throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to query the direct-handle CDP child process."),
                    _ => throw new Win32Exception(
                        "Windows returned an unexpected process wait result.")
                };
            }
        }

        public SafeProcessHandle DuplicateRetainedProcessHandleForVerification()
        {
            ThrowIfDisposed();
            var processHandle = _processHandle ??
                throw new InvalidOperationException(
                    "The retained CDP child process handle was not published.");
            var currentProcess = GetCurrentProcess();
            if (!DuplicateHandle(
                    currentProcess,
                    processHandle,
                    currentProcess,
                    out var duplicate,
                    desiredAccess: 0,
                    inheritHandle: false,
                    DuplicateSameAccess))
            {
                var error = Marshal.GetLastWin32Error();
                duplicate?.Dispose();
                throw new Win32Exception(
                    error,
                    "Unable to duplicate the retained CDP child process handle.");
            }

            if (duplicate.IsInvalid)
            {
                duplicate.Dispose();
                throw new Win32Exception(
                    "Windows returned an invalid duplicate CDP child process handle.");
            }

            return duplicate;
        }

        public async Task<int> WaitForExitAsync(
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (timeout <= TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout));
            }

            var stopwatch = Stopwatch.StartNew();
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var waitResult = WaitForProcess(0);
                if (waitResult == WaitObject0)
                {
                    if (!TryGetExitCode(out var exitCode))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Unable to read the direct-handle CDP child exit code.");
                    }

                    return unchecked((int)exitCode);
                }

                if (waitResult == WaitFailed)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to wait for the direct-handle CDP child process.");
                }

                if (waitResult != WaitTimeout)
                {
                    throw new Win32Exception(
                        "Windows returned an unexpected process wait result.");
                }

                if (timeout != Timeout.InfiniteTimeSpan && stopwatch.Elapsed >= timeout)
                {
                    throw new TimeoutException(
                        "The direct-handle CDP child process did not exit in time.");
                }

                var delay = timeout == Timeout.InfiniteTimeSpan
                    ? TimeSpan.FromMilliseconds(20)
                    : TimeSpan.FromMilliseconds(Math.Min(
                        20,
                        (timeout - stopwatch.Elapsed).TotalMilliseconds));
                if (delay <= TimeSpan.Zero)
                {
                    throw new TimeoutException(
                        "The direct-handle CDP child process did not exit in time.");
                }

                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        public void Dispose() => _disposal.Dispose();

        public ValueTask DisposeAsync() => _disposal.DisposeAsync();

#if CODEXGUARDIAN_TEST_FRIEND
        private void TerminateExactRootForTests()
        {
            if (ProcessId <= 0)
            {
                return;
            }

            var waitResult = WaitForProcess(0);
            if (waitResult == WaitObject0)
            {
                return;
            }
            if (waitResult == WaitFailed)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to query the direct-handle CDP test child before termination.");
            }
            if (waitResult != WaitTimeout)
            {
                throw new Win32Exception(
                    "Windows returned an unexpected test-child process wait result.");
            }
            if (!TryTerminateProcess(TestTerminationExitCode))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to terminate the exact direct-handle CDP test child.");
            }
        }
#endif

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposal.IsDisposeStarted, this);
        }

        private uint WaitForProcess(uint milliseconds)
        {
            var processHandle = _processHandle;
            if (processHandle is not null)
            {
                return WaitForSingleObject(processHandle, milliseconds);
            }

            var rawProcessHandle = _rawProcessHandle;
            if (rawProcessHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "The retained CDP child process handle is unavailable.");
            }

            return WaitForSingleObject(rawProcessHandle, milliseconds);
        }

        private bool TryGetExitCode(out uint exitCode)
        {
            var processHandle = _processHandle;
            return processHandle is not null
                ? GetExitCodeProcess(processHandle, out exitCode)
                : GetExitCodeProcess(_rawProcessHandle, out exitCode);
        }

#if CODEXGUARDIAN_TEST_FRIEND
        private bool TryTerminateProcess(uint exitCode)
        {
            var processHandle = _processHandle;
            return processHandle is not null
                ? TerminateProcess(processHandle, exitCode)
                : TerminateProcess(_rawProcessHandle, exitCode);
        }
#endif

        private void DisposeProcessAuthority()
        {
            var processHandle = Interlocked.Exchange(ref _processHandle, null);
            if (processHandle is not null)
            {
                processHandle.Dispose();
            }

            var rawProcessHandle = Interlocked.Exchange(
                ref _rawProcessHandle,
                IntPtr.Zero);
            if (rawProcessHandle != IntPtr.Zero && !CloseHandle(rawProcessHandle))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to close the retained direct-handle CDP child process handle.");
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

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        internal uint cb;
        internal IntPtr lpReserved;
        internal IntPtr lpDesktop;
        internal IntPtr lpTitle;
        internal uint dwX;
        internal uint dwY;
        internal uint dwXSize;
        internal uint dwYSize;
        internal uint dwXCountChars;
        internal uint dwYCountChars;
        internal uint dwFillAttribute;
        internal uint dwFlags;
        internal ushort wShowWindow;
        internal ushort cbReserved2;
        internal IntPtr lpReserved2;
        internal IntPtr hStdInput;
        internal IntPtr hStdOutput;
        internal IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX
    {
        internal STARTUPINFO StartupInfo;
        internal IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        internal IntPtr hProcess;
        internal IntPtr hThread;
        internal uint dwProcessId;
        internal uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcessHandle,
        SafeProcessHandle sourceHandle,
        IntPtr targetProcessHandle,
        out SafeProcessHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        ref SECURITY_ATTRIBUTES pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        SafeFileHandle handle,
        uint mask,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        IntPtr attribute,
        IntPtr value,
        IntPtr size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref STARTUPINFOEX startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

#if CODEXGUARDIAN_TEST_FRIEND
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
#endif

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
