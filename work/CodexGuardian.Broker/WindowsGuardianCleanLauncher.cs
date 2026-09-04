using CodexGuardian.Control;
using CodexGuardian.Trust;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CodexGuardian.Broker;

internal interface IWindowsGuardianLaunchReleaseAuthorityV1
{
    string RuntimeRootPath { get; }

    string AppHostPath { get; }

    string ManagedEntryPath { get; }

    string DepsPath { get; }

    string RuntimeConfigPath { get; }

    IRetainedPeerIdentityLease OpenRetainedProcess(SafeProcessHandle exactProcessHandle);
}

internal sealed class WindowsGuardianCleanLaunchCandidateV1 : IDisposable
{
    private readonly object _gate = new();
    private IBrokerOwnedGuardianProcessLeaseV1? _processLease;
    private SafeProcessHandle? _exactProcessHandle;
    private Exception? _disposeFailure;
    private bool _disposed;

    internal WindowsGuardianCleanLaunchCandidateV1(
        IBrokerOwnedGuardianProcessLeaseV1 processLease,
        SafeProcessHandle exactProcessHandle,
        WindowsProcessIdentity initialIdentity)
    {
        _processLease = processLease ?? throw new ArgumentNullException(nameof(processLease));
        _exactProcessHandle = exactProcessHandle ??
            throw new ArgumentNullException(nameof(exactProcessHandle));
        InitialIdentity = initialIdentity ?? throw new ArgumentNullException(nameof(initialIdentity));
    }

    internal WindowsProcessIdentity InitialIdentity { get; }

    internal SafeProcessHandle DuplicateExactProcessHandle()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return WindowsGuardianCleanLauncherV1.DuplicateProcessHandle(
                _exactProcessHandle ?? throw new ObjectDisposedException(
                    nameof(WindowsGuardianCleanLaunchCandidateV1)));
        }
    }

    internal BrokerGuardianCleanLaunchAuthorityV1 CreateManagedEntryAuthority(
        GuardianManagedEntryMetadataIdentityV1 expectedMetadata,
        ReadOnlySpan<byte> challenge)
    {
        IBrokerOwnedGuardianProcessLeaseV1 processLease;
        lock (_gate)
        {
            ThrowIfDisposed();
            processLease = _processLease ?? throw new InvalidOperationException(
                "The Guardian clean-launch process authority was already consumed.");
            _processLease = null;
        }

        return BrokerGuardianCleanLaunchAuthorityV1.Create(
            processLease,
            expectedMetadata,
            challenge);
    }

#if CODEXGUARDIAN_TEST_FRIEND
    internal IBrokerOwnedGuardianProcessLeaseV1 TakeProcessLeaseForTests()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var processLease = _processLease ?? throw new InvalidOperationException(
                "The Guardian clean-launch process authority was already consumed.");
            _processLease = null;
            return processLease;
        }
    }
#endif

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                if (_disposeFailure is not null)
                {
                    ExceptionDispatchInfo.Capture(_disposeFailure).Throw();
                }

                return;
            }

            _disposed = true;
            var failures = new List<Exception>();
            DisposeOwned(_processLease, failures);
            _processLease = null;
            DisposeOwned(_exactProcessHandle, failures);
            _exactProcessHandle = null;
            _disposeFailure = failures.Count switch
            {
                0 => null,
                1 => failures[0],
                _ => new AggregateException(
                    "Guardian clean-launch candidate cleanup failed.",
                    failures)
            };
            if (_disposeFailure is not null)
            {
                ExceptionDispatchInfo.Capture(_disposeFailure).Throw();
            }
        }
    }

    private static void DisposeOwned(IDisposable? value, ICollection<Exception> failures)
    {
        if (value is null)
        {
            return;
        }

        try
        {
            value.Dispose();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal sealed class WindowsGuardianCleanLauncherV1
{
    internal const string ManagedBootstrapArgument = "--guardian-broker-bootstrap-v1";
    internal const string BootstrapHandleArgument = "--bootstrap-handle";
    internal const int InheritedHandleCount = 2;

    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateNoWindow = 0x08000000;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const int MaximumCommandLineCharacters = 32767;
    private const uint ProcessQueryInformation = 0x00000400;
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint Synchronize = 0x00100000;
    private const uint ProcThreadAttributeHandleList = 0x00020002;
    private static ReadOnlySpan<byte> CanonicalRuntimeConfigDev =>
        "{\"runtimeOptions\":{}}\r\n"u8;

    private readonly IWindowsGuardianLaunchReleaseAuthorityV1 _release;
    private readonly WindowsGuardianProcessRegistryV1 _processRegistry;

    private WindowsGuardianCleanLauncherV1(
        IWindowsGuardianLaunchReleaseAuthorityV1 release,
        WindowsGuardianProcessRegistryV1 processRegistry)
    {
        _release = release ?? throw new ArgumentNullException(nameof(release));
        _processRegistry = processRegistry ?? throw new ArgumentNullException(nameof(processRegistry));
    }

    internal static WindowsGuardianCleanLauncherV1 Create(
        BrokerProductionReleaseBindingV1 releaseBinding) =>
        new(
            new ProductionReleaseAuthority(releaseBinding),
            WindowsGuardianProcessRegistryV1.Production);

#if CODEXGUARDIAN_TEST_FRIEND
    internal static WindowsGuardianCleanLauncherV1 CreateForTests(
        IWindowsGuardianLaunchReleaseAuthorityV1 release) =>
        new(release, WindowsGuardianProcessRegistryV1.CreateIsolatedForTests());

    internal static WindowsGuardianCleanLauncherV1 CreateForTests(
        IWindowsGuardianLaunchReleaseAuthorityV1 release,
        WindowsGuardianProcessRegistryV1 processRegistry) =>
        new(release, processRegistry);
#endif

    internal WindowsGuardianCleanLaunchCandidateV1 Launch(
        string endpointName,
        string connectionNonce,
        ReadOnlySpan<byte> managedEntryChallenge)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Guardian clean launcher is Windows-only.");
        }

        if (managedEntryChallenge.Length != GuardianManagedEntryProofProtocolV1.ChallengeBytes)
        {
            throw new ArgumentException(
                "The Guardian managed-entry challenge has an invalid length.",
                nameof(managedEntryChallenge));
        }

        var paths = ValidateReleasePaths(_release);
        WindowsGuardianProcessRootV1? processRoot = _processRegistry.ReserveLaunch();
        SafeFileHandle? childBootstrapRead = null;
        SafeFileHandle? parentBootstrapWrite = null;
        SafeProcessHandle? brokerSelfHandle = null;
        SafeFileHandle? jobHandle = null;
        SafeProcessHandle? processHandle = null;
        IRetainedPeerIdentityLease? identityLease = null;
        SafeProcessHandle? peerBindingHandle = null;
        WindowsBrokerOwnedGuardianProcessLeaseV1? processLease = null;
        WindowsGuardianCleanLaunchCandidateV1? candidate = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr attributeHandles = IntPtr.Zero;
        IntPtr environmentBlock = IntPtr.Zero;
        IntPtr primaryThread = IntPtr.Zero;
        byte[]? bootstrapFrame = null;
        var attributeListInitialized = false;
        try
        {
            CreateInheritedPipe(out childBootstrapRead, out parentBootstrapWrite);
            SetNonInheritable(parentBootstrapWrite);
            brokerSelfHandle = OpenProcess(
                ProcessQueryInformation | ProcessQueryLimitedInformation | Synchronize,
                inheritHandle: true,
                checked((uint)Environment.ProcessId));
            if (brokerSelfHandle.IsInvalid || brokerSelfHandle.IsClosed)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to open the real Broker self process handle.");
            }

            RequireInheritable(childBootstrapRead, "bootstrap pipe");
            RequireInheritable(brokerSelfHandle, "Broker process");
            var brokerHandleValue = ToUnsignedHandleValue(brokerSelfHandle);
            using var bootstrap = new GuardianBrokerBootstrapV1(
                endpointName,
                connectionNonce,
                managedEntryChallenge,
                brokerHandleValue);
            bootstrapFrame = GuardianBrokerBootstrapProtocolV1.SerializeFrame(bootstrap);

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
                    "Unable to size the Guardian process attribute list.");
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
                    "Unable to initialize the Guardian process attribute list.");
            }

            attributeListInitialized = true;
            attributeHandles = Marshal.AllocHGlobal(
                checked(IntPtr.Size * InheritedHandleCount));
            Marshal.WriteIntPtr(
                attributeHandles,
                0,
                childBootstrapRead.DangerousGetHandle());
            Marshal.WriteIntPtr(
                attributeHandles,
                IntPtr.Size,
                brokerSelfHandle.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(
                    attributeList,
                    flags: 0,
                    new IntPtr(ProcThreadAttributeHandleList),
                    attributeHandles,
                    new IntPtr(checked(IntPtr.Size * InheritedHandleCount)),
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to restrict the Guardian inherited-handle allowlist.");
            }

            var commandLine = BuildCommandLine(
                paths.AppHostPath,
                [
                    ManagedBootstrapArgument,
                    BootstrapHandleArgument,
                    ToUnsignedHandleValue(childBootstrapRead)
                        .ToString(CultureInfo.InvariantCulture)
                ]);
            if (commandLine.Length >= MaximumCommandLineCharacters)
            {
                throw new ArgumentException(
                    "The Guardian bootstrap command line is too long.",
                    nameof(endpointName));
            }

            jobHandle = CreateJobObjectW(IntPtr.Zero, null);
            if (jobHandle.IsInvalid || jobHandle.IsClosed)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to create the Guardian ownership job.");
            }

            var jobLimits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = JobObjectLimitKillOnJobClose
                }
            };
            if (!SetInformationJobObject(
                    jobHandle,
                    JobObjectExtendedLimitInformation,
                    ref jobLimits,
                    checked((uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to configure kill-on-close Guardian ownership.");
            }
            processRoot.AttachJob(jobHandle);
            jobHandle = null;

            environmentBlock = WindowsCrtPipeProcessEnvironment.BuildUnmanagedBlock();
            var startupInfo = new STARTUPINFOEX
            {
                StartupInfo = new STARTUPINFO
                {
                    cb = checked((uint)Marshal.SizeOf<STARTUPINFOEX>())
                },
                lpAttributeList = attributeList
            };
            if (!CreateProcessW(
                    paths.AppHostPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles: true,
                    CreateSuspended |
                        CreateUnicodeEnvironment |
                        ExtendedStartupInfoPresent |
                        CreateNoWindow,
                    environmentBlock,
                    paths.RuntimeRootPath,
                    ref startupInfo,
                    out var processInformation))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The verified Guardian apphost could not be launched suspended.");
            }

            processHandle = new SafeProcessHandle(processInformation.hProcess, ownsHandle: true);
            processInformation.hProcess = IntPtr.Zero;
            primaryThread = processInformation.hThread;
            processRoot.AttachProcess(processHandle, processInformation.dwProcessId);
            processHandle = null;
            processRoot.StartObservation();
            if (!AssignProcessToJobObject(
                    processRoot.BorrowJobHandle(),
                    processRoot.BorrowProcessHandle()))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The suspended Guardian process could not enter its ownership job.");
            }

            processRoot.MarkAssignedToJob();
            identityLease = _release.OpenRetainedProcess(processRoot.BorrowProcessHandle());
            var initialIdentity = identityLease.Capture();
            RequireInitialIdentity(
                initialIdentity,
                processInformation.dwProcessId,
                paths.AppHostPath);
            processRoot.AttachIdentity(identityLease, initialIdentity);
            identityLease = null;
            peerBindingHandle = DuplicateProcessHandle(processRoot.BorrowProcessHandle());

            using (var bootstrapStream = new FileStream(
                       parentBootstrapWrite,
                       FileAccess.Write,
                       bufferSize: 4096,
                       isAsync: false))
            {
                parentBootstrapWrite = null;
                bootstrapStream.Write(bootstrapFrame);
                bootstrapStream.Flush();
            }

            childBootstrapRead.Dispose();
            childBootstrapRead = null;
            brokerSelfHandle.Dispose();
            brokerSelfHandle = null;
            var previousSuspendCount = ResumeThread(primaryThread);
            if (previousSuspendCount != 1)
            {
                throw new Win32Exception(
                    previousSuspendCount == uint.MaxValue ? Marshal.GetLastWin32Error() : 0,
                    "The verified Guardian primary thread did not resume exactly once.");
            }

            processRoot.MarkLaunchVerified();
            processLease = new WindowsBrokerOwnedGuardianProcessLeaseV1(processRoot);
            candidate = new WindowsGuardianCleanLaunchCandidateV1(
                processLease,
                peerBindingHandle,
                initialIdentity);
            processLease = null;
            peerBindingHandle = null;
            processRoot = null;
            return candidate;
        }
        catch (Exception failure)
        {
            PreserveCleanupFailure(
                failure,
                () => processRoot?.StopAsync(BrokerGuardianProcessStopRequestV1.LaunchRollback)
                    .GetAwaiter()
                    .GetResult());
            PreserveCleanupFailure(failure, () => candidate?.Dispose());
            PreserveCleanupFailure(failure, () => processLease?.Dispose());
            PreserveCleanupFailure(failure, () => identityLease?.Dispose());
            PreserveCleanupFailure(failure, () => peerBindingHandle?.Dispose());
            PreserveCleanupFailure(failure, () => processHandle?.Dispose());
            PreserveCleanupFailure(failure, () => jobHandle?.Dispose());

            ExceptionDispatchInfo.Capture(failure).Throw();
            throw;
        }
        finally
        {
            if (bootstrapFrame is not null)
            {
                CryptographicOperations.ZeroMemory(bootstrapFrame);
            }

            parentBootstrapWrite?.Dispose();
            childBootstrapRead?.Dispose();
            brokerSelfHandle?.Dispose();
            if (primaryThread != IntPtr.Zero)
            {
                _ = CloseHandle(primaryThread);
            }

            if (environmentBlock != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(environmentBlock);
            }

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
        }
    }

    internal static SafeProcessHandle DuplicateProcessHandle(SafeProcessHandle source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                out var duplicate,
                ProcessQueryInformation | ProcessQueryLimitedInformation | Synchronize,
                inheritHandle: false,
                options: 0))
        {
            duplicate?.Dispose();
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to duplicate the exact Guardian process handle.");
        }

        return duplicate;
    }

    private static void PreserveCleanupFailure(Exception primary, Action cleanup)
    {
        try
        {
            cleanup();
        }
        catch (Exception cleanupFailure)
        {
            BrokerControlFailureArbitration.PreserveCleanupFailure(primary, cleanupFailure);
        }
    }

    private static VerifiedLaunchPaths ValidateReleasePaths(
        IWindowsGuardianLaunchReleaseAuthorityV1 release)
    {
        var root = NormalizeDirectory(release.RuntimeRootPath, nameof(release.RuntimeRootPath));
        var appHost = NormalizeFile(release.AppHostPath, nameof(release.AppHostPath));
        var managedEntry = NormalizeFile(
            release.ManagedEntryPath,
            nameof(release.ManagedEntryPath));
        var deps = NormalizeFile(release.DepsPath, nameof(release.DepsPath));
        var runtimeConfig = NormalizeFile(
            release.RuntimeConfigPath,
            nameof(release.RuntimeConfigPath));
        var developmentRuntimeConfig = NormalizeFile(
            Path.Combine(
                root,
                Path.GetFileNameWithoutExtension(runtimeConfig) + ".dev.json"),
            "RuntimeConfigDevPath");
        foreach (var path in new[]
                 {
                     appHost,
                     managedEntry,
                     deps,
                     runtimeConfig,
                     developmentRuntimeConfig
                 })
        {
            if (!string.Equals(
                    Path.GetDirectoryName(path),
                    root,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException(
                    "Every Guardian bootstrap artifact must be an exact child of the retained runtime root.");
            }

            RequireReparseFree(path);
        }

        RequireReparseFree(root);
        RequireCanonicalRuntimeConfigDev(developmentRuntimeConfig);

        return new VerifiedLaunchPaths(
            root,
            appHost,
            managedEntry,
            deps,
            runtimeConfig,
            developmentRuntimeConfig);
    }

    private static void RequireCanonicalRuntimeConfigDev(string path)
    {
        Span<byte> actual = stackalloc byte[23];
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: actual.Length,
            FileOptions.SequentialScan);
        if (stream.Length != actual.Length)
        {
            throw new IOException(
                "The Guardian runtimeconfig.dev.json length is not canonical.");
        }

        stream.ReadExactly(actual);
        if (stream.ReadByte() != -1 || !actual.SequenceEqual(CanonicalRuntimeConfigDev))
        {
            throw new IOException(
                "The Guardian runtimeconfig.dev.json bytes are not canonical.");
        }
    }

    private static string NormalizeDirectory(string path, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) ||
            path.IndexOf('\0') >= 0)
        {
            throw new ArgumentException(
                "An exact absolute Guardian runtime root is required.",
                parameterName);
        }

        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!Directory.Exists(normalized))
        {
            throw new DirectoryNotFoundException(
                "The retained Guardian runtime root is absent: " + normalized);
        }

        return normalized;
    }

    private static string NormalizeFile(string path, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) ||
            path.IndexOf('\0') >= 0)
        {
            throw new ArgumentException(
                "An exact absolute Guardian runtime artifact is required.",
                parameterName);
        }

        var normalized = Path.GetFullPath(path);
        if (!File.Exists(normalized))
        {
            throw new FileNotFoundException(
                "A retained Guardian runtime artifact is absent.",
                normalized);
        }

        return normalized;
    }

    private static void RequireReparseFree(string path)
    {
        var current = new FileInfo(path);
        FileSystemInfo? item = current.Exists ? current : new DirectoryInfo(path);
        while (item is not null)
        {
            if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException(
                    "The Guardian launch path traverses a reparse point.");
            }

            var parent = item switch
            {
                FileInfo file => file.Directory,
                DirectoryInfo directory => directory.Parent,
                _ => null
            };
            item = parent;
        }
    }

    private static void RequireInitialIdentity(
        WindowsProcessIdentity identity,
        uint expectedProcessId,
        string expectedAppHostPath)
    {
        if (identity.ProcessId != expectedProcessId ||
            !identity.ImageFileObjectIsExact ||
            !string.Equals(
                identity.FinalImagePath,
                expectedAppHostPath,
                StringComparison.OrdinalIgnoreCase) ||
            !identity.ReleaseRoot.TraversalIsReparseFree ||
            identity.Artifacts.Count == 0 ||
            identity.Artifacts.Any(artifact => !artifact.TraversalIsReparseFree))
        {
            throw new BrokerControlSessionException(
                "managed-guardian-launch-identity-invalid",
                "The suspended Guardian process did not retain the exact verified apphost identity.");
        }
    }

    private static void CreateInheritedPipe(
        out SafeFileHandle readHandle,
        out SafeFileHandle writeHandle)
    {
        var security = new SECURITY_ATTRIBUTES
        {
            nLength = checked((uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>()),
            bInheritHandle = 1
        };
        if (CreatePipe(out readHandle, out writeHandle, ref security, size: 4096))
        {
            return;
        }

        readHandle?.Dispose();
        writeHandle?.Dispose();
        throw new Win32Exception(
            Marshal.GetLastWin32Error(),
            "Unable to create the Guardian bootstrap pipe.");
    }

    private static void SetNonInheritable(SafeHandle handle)
    {
        if (!SetHandleInformation(handle, HandleFlagInherit, flags: 0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to close a parent Guardian handle to inheritance.");
        }
    }

    private static void RequireInheritable(SafeHandle handle, string description)
    {
        if (!GetHandleInformation(handle, out var flags) ||
            (flags & HandleFlagInherit) == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "The Guardian " + description + " handle is not inheritable.");
        }
    }

    private static ulong ToUnsignedHandleValue(SafeHandle handle)
    {
        var value = handle.DangerousGetHandle().ToInt64();
        if (value <= 0)
        {
            throw new Win32Exception(
                "A Guardian inherited handle cannot be represented canonically.");
        }

        return checked((ulong)value);
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
                commandLine.Append('\\', checked(backslashes * 2 + 1));
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

    private sealed class ProductionReleaseAuthority : IWindowsGuardianLaunchReleaseAuthorityV1
    {
        private readonly BrokerProductionReleaseBindingV1 _binding;
        private readonly VerifiedReleaseArtifactSet _release;

        internal ProductionReleaseAuthority(BrokerProductionReleaseBindingV1 binding)
        {
            _binding = binding ?? throw new ArgumentNullException(nameof(binding));
            _release = binding.Manifest.GetArtifactSet(BrokerPeerRole.Guardian);
        }

        public string RuntimeRootPath => _release.Root.FinalPath;

        public string AppHostPath => GetArtifact(ReleaseArtifactKind.AppHostExe).FinalPath;

        public string ManagedEntryPath => GetArtifact(ReleaseArtifactKind.ManagedEntryDll).FinalPath;

        public string DepsPath => GetArtifact(ReleaseArtifactKind.DepsJson).FinalPath;

        public string RuntimeConfigPath =>
            GetArtifact(ReleaseArtifactKind.RuntimeConfigJson).FinalPath;

        public IRetainedPeerIdentityLease OpenRetainedProcess(
            SafeProcessHandle exactProcessHandle) =>
            _binding.OpenGuardianProcess(exactProcessHandle);

        private WindowsArtifactIdentity GetArtifact(ReleaseArtifactKind kind) =>
            _release.Artifacts.Single(artifact => artifact.Kind == kind);
    }

    private sealed class WindowsBrokerOwnedGuardianProcessLeaseV1 :
        IBrokerOwnedGuardianProcessLeaseV1
    {
        private readonly object _gate = new();
        private readonly Task<BrokerGuardianProcessExitV1> _completion;
        private WindowsGuardianProcessRootV1? _root;
        private Task? _stopTask;

        internal WindowsBrokerOwnedGuardianProcessLeaseV1(
            WindowsGuardianProcessRootV1 root)
        {
            _root = root ?? throw new ArgumentNullException(nameof(root));
            _completion = root.Completion;
        }

        public Task<BrokerGuardianProcessExitV1> Completion => _completion;

        public bool CleanEnvironmentVerified
        {
            get
            {
                lock (_gate)
                {
                    return GetRoot().CleanEnvironmentVerified;
                }
            }
        }

        public bool RuntimeNamespaceClosed
        {
            get
            {
                lock (_gate)
                {
                    return GetRoot().RuntimeNamespaceClosed;
                }
            }
        }

        public WindowsProcessIdentity Revalidate()
        {
            lock (_gate)
            {
                return GetRoot().Revalidate();
            }
        }

        public IBrokerOwnedGuardianProcessLeaseV1 TakeOwnership()
        {
            lock (_gate)
            {
                var root = GetRoot();
                var successor = new WindowsBrokerOwnedGuardianProcessLeaseV1(root);
                _root = null;
                return successor;
            }
        }

        public Task StopAsync(BrokerGuardianProcessStopRequestV1 stopRequest)
        {
            if (stopRequest == BrokerGuardianProcessStopRequestV1.None)
            {
                throw new ArgumentOutOfRangeException(nameof(stopRequest));
            }

            lock (_gate)
            {
                if (_stopTask is not null)
                {
                    return _stopTask;
                }

                if (_root is null)
                {
                    return Task.CompletedTask;
                }

                var root = _root;
                _root = null;
                _stopTask = root.StopAsync(stopRequest);
                return _stopTask;
            }
        }

        public void Dispose() =>
            StopAsync(BrokerGuardianProcessStopRequestV1.Disposal)
                .GetAwaiter()
                .GetResult();

        public ValueTask DisposeAsync() =>
            new(StopAsync(BrokerGuardianProcessStopRequestV1.Disposal));

        private WindowsGuardianProcessRootV1 GetRoot() =>
            _root is not null && _stopTask is null
                ? _root
                : throw new ObjectDisposedException(
                    nameof(WindowsBrokerOwnedGuardianProcessLeaseV1));
    }

    private sealed record VerifiedLaunchPaths(
        string RuntimeRootPath,
        string AppHostPath,
        string ManagedEntryPath,
        string DepsPath,
        string RuntimeConfigPath,
        string RuntimeConfigDevPath);

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        internal uint nLength;
        internal IntPtr lpSecurityDescriptor;
        internal int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        internal uint cb;
        internal string? lpReserved;
        internal string? lpDesktop;
        internal string? lpTitle;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize;
        internal UIntPtr MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        internal IO_COUNTERS IoInfo;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemoryUsed;
        internal UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        ref SECURITY_ATTRIBUTES pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetHandleInformation(SafeHandle handle, out uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        SafeHandle handle,
        uint mask,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

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
        string currentDirectory,
        ref STARTUPINFOEX startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObjectW(
        IntPtr jobAttributes,
        string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(
        SafeFileHandle job,
        SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess,
        SafeProcessHandle sourceHandle,
        IntPtr targetProcess,
        out SafeProcessHandle targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
