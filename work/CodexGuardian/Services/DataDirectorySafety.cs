using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CodexGuardian.Services;

internal static class DataDirectorySafety
{
    private const uint FileReadAttributes = 0x0080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    internal static string NormalizeAndValidate(string dataDirectory)
    {
        var normalized = NormalizeInputPath(dataDirectory, nameof(dataDirectory));
        var resolved = ResolveAllowMissing(normalized, rejectReparseComponents: true);
        ThrowIfInsideSessions(resolved);
        return normalized;
    }

    internal static void Revalidate(string dataDirectory)
    {
        var normalized = NormalizeInputPath(dataDirectory, nameof(dataDirectory));
        var resolved = ResolveAllowMissing(normalized, rejectReparseComponents: true);
        ThrowIfInsideSessions(resolved);
    }

    internal static void CreateProtectedDirectory(string dataDirectory)
    {
        var normalized = NormalizeAndValidate(dataDirectory);
        if (Directory.Exists(normalized) || File.Exists(normalized))
        {
            throw new IOException("A protected data directory must be fresh.");
        }

        var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(normalized));
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new IOException("A protected data directory parent is unavailable.");
        }

        Revalidate(parent);
        Directory.CreateDirectory(parent);
        Revalidate(normalized);

        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var currentUser = identity.User ??
            throw new UnauthorizedAccessException("The current user SID is unavailable.");
        var security = BuildProtectedDirectorySecurity(currentUser);
        _ = FileSystemAclExtensions.CreateDirectory(security, normalized);
        VerifyProtectedDirectoryAcl(normalized, currentUser);
    }

    private static DirectorySecurity BuildProtectedDirectorySecurity(SecurityIdentifier currentUser)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { currentUser, system, administrators })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        return security;
    }

    private static void VerifyProtectedDirectoryAcl(
        string dataDirectory,
        SecurityIdentifier currentUser)
    {
        Revalidate(dataDirectory);
        var directory = new DirectoryInfo(dataDirectory);
        if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("The protected data directory is invalid.");
        }

        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            currentUser.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value
        };
        var security = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier ??
            throw new UnauthorizedAccessException("The protected data directory owner SID is invalid.");
        var rules = security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        var actual = rules
            .Select(rule =>
                (rule.IdentityReference as SecurityIdentifier ??
                    throw new UnauthorizedAccessException(
                        "A protected data directory rule SID is invalid.")).Value)
            .ToHashSet(StringComparer.Ordinal);
        if (!security.AreAccessRulesProtected ||
            !string.Equals(owner.Value, currentUser.Value, StringComparison.Ordinal) ||
            !expected.SetEquals(actual) ||
            rules.Any(rule =>
                rule.AccessControlType != AccessControlType.Allow ||
                (rule.FileSystemRights & FileSystemRights.FullControl) != FileSystemRights.FullControl))
        {
            throw new UnauthorizedAccessException("The protected data directory ACL is invalid.");
        }
    }

    internal static void RevalidateWriteTarget(string dataDirectory, string targetPath)
    {
        var normalizedDirectory = NormalizeInputPath(dataDirectory, nameof(dataDirectory));
        var normalizedTarget = NormalizeInputPath(targetPath, nameof(targetPath));
        if (!IsSameOrDescendant(normalizedTarget, normalizedDirectory))
        {
            throw new ArgumentException(
                "A Codex Guardian write target must remain inside its data directory.",
                nameof(targetPath));
        }

        var resolvedDirectory = ResolveAllowMissing(normalizedDirectory, rejectReparseComponents: true);
        var resolvedTarget = ResolveAllowMissing(normalizedTarget, rejectReparseComponents: true);
        if (!IsSameOrDescendant(resolvedTarget, resolvedDirectory))
        {
            throw new IOException("A Codex Guardian write target resolves outside its data directory.");
        }

        ThrowIfInsideSessions(resolvedDirectory, resolvedTarget);
    }

    private static void ThrowIfInsideSessions(params string[] resolvedCandidates)
    {
        foreach (var sessionRoot in GetSessionRoots())
        {
            var resolvedRoot = ResolveAllowMissing(sessionRoot, rejectReparseComponents: false);
            if (resolvedCandidates.Any(candidate => IsSameOrDescendant(candidate, resolvedRoot)))
            {
                throw new ArgumentException(
                    "Codex Guardian data cannot be stored in a Codex sessions directory.",
                    "dataDirectory");
            }
        }
    }

    private static IEnumerable<string> GetSessionRoots()
    {
        yield return NormalizeInputPath(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".codex",
                "sessions"),
            "sessionRoot");

        var codexHome = Environment.GetEnvironmentVariable("CODEX_HOME");
        if (!string.IsNullOrWhiteSpace(codexHome))
        {
            yield return NormalizeInputPath(Path.Combine(codexHome, "sessions"), "sessionRoot");
        }
    }

    private static string ResolveAllowMissing(string path, bool rejectReparseComponents)
    {
        var existingPath = FindNearestExistingPath(path, out var existingAttributes);
        if (rejectReparseComponents)
        {
            RejectReparseComponents(existingPath);
        }

        var relativeTail = Path.GetRelativePath(existingPath, path);
        if (!string.Equals(relativeTail, ".", StringComparison.Ordinal) &&
            (existingAttributes & FileAttributes.Directory) == 0)
        {
            throw new IOException("A data-directory ancestor is not a directory.");
        }

        var resolvedExisting = GetFinalPath(existingPath);
        return string.Equals(relativeTail, ".", StringComparison.Ordinal)
            ? resolvedExisting
            : Path.GetFullPath(Path.Combine(resolvedExisting, relativeTail));
    }

    private static string FindNearestExistingPath(string path, out FileAttributes attributes)
    {
        var current = path;
        while (true)
        {
            try
            {
                attributes = File.GetAttributes(current);
                return current;
            }
            catch (FileNotFoundException)
            {
            }
            catch (DirectoryNotFoundException)
            {
            }

            var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(current));
            if (string.IsNullOrWhiteSpace(parent) ||
                string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                throw new DirectoryNotFoundException(
                    "No existing ancestor could be resolved for the Codex Guardian data directory.");
            }

            current = parent;
        }
    }

    private static void RejectReparseComponents(string existingPath)
    {
        var current = existingPath;
        while (true)
        {
            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException(
                    $"Codex Guardian data paths cannot contain reparse points: {current}");
            }

            var trimmed = Path.TrimEndingDirectorySeparator(current);
            var root = Path.TrimEndingDirectorySeparator(Path.GetPathRoot(current) ?? string.Empty);
            if (string.Equals(trimmed, root, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var parent = Path.GetDirectoryName(trimmed);
            if (string.IsNullOrWhiteSpace(parent) ||
                string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            current = parent;
        }
    }

    private static string GetFinalPath(string existingPath)
    {
        using var handle = CreateFile(
            existingPath,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to resolve the final data-directory path.");
        }

        var buffer = new StringBuilder(512);
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Unable to read the final data-directory path.");
        }

        if (length >= buffer.Capacity)
        {
            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Unable to read the complete final data-directory path.");
            }
        }

        return NormalizeInputPath(buffer.ToString(), "resolvedPath");
    }

    private static string NormalizeInputPath(string path, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path, parameterName);
        path = path.Trim();
        var prefixCheck = path.Replace('/', '\\');
        if (prefixCheck.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
            prefixCheck.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase) ||
            prefixCheck.StartsWith(@"\\??\", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Windows device path aliases are not accepted.", parameterName);
        }

        if (prefixCheck.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) &&
            !path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Unsupported Windows extended path namespace.", parameterName);
        }

        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            path = @"\\" + path[8..];
        }
        else if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            if (path.Length < 7 || !char.IsAsciiLetter(path[4]) || path[5] != ':' || path[6] != '\\')
            {
                throw new ArgumentException("Unsupported Windows extended path namespace.", parameterName);
            }

            path = path[4..];
        }

        var fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
            fullPath.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase) ||
            fullPath.StartsWith(@"\\??\", StringComparison.OrdinalIgnoreCase) ||
            fullPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Windows device path aliases are not accepted.", parameterName);
        }

        RequireLocalFixedDrive(fullPath, parameterName);
        return fullPath;
    }

    private static void RequireLocalFixedDrive(string path, string parameterName)
    {
        var root = Path.GetPathRoot(path);
        if (path.StartsWith(@"\\", StringComparison.Ordinal) ||
            root is not { Length: 3 } ||
            !char.IsAsciiLetter(root[0]) ||
            root[1] != ':' ||
            root[2] != Path.DirectorySeparatorChar)
        {
            throw new ArgumentException(
                "Codex Guardian data must use a local fixed-drive path.",
                parameterName);
        }

        DriveType driveType;
        try
        {
            driveType = new DriveInfo(root).DriveType;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            throw new ArgumentException(
                "The Codex Guardian data drive could not be validated.",
                parameterName,
                exception);
        }

        if (driveType != DriveType.Fixed)
        {
            throw new ArgumentException(
                "Codex Guardian data must use a local fixed drive.",
                parameterName);
        }
    }

    private static bool IsSameOrDescendant(string candidate, string root)
    {
        candidate = Path.TrimEndingDirectorySeparator(candidate);
        root = Path.TrimEndingDirectorySeparator(root);
        return string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase) ||
               candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathSize,
        uint flags);
}
