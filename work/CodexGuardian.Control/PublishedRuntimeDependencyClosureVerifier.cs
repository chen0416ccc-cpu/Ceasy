using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed record PublishedRuntimeDependencyClosure(
    string RuntimeTarget,
    string RootLibrary,
    string ControlLibrary,
    string PkcsLibrary,
    string ProviderLibrary,
    string PublishedAssetPath,
    string PackageAssetPath,
    string Sha256,
    string AssemblyVersion,
    string FileVersion);

internal static class PublishedRuntimeDependencyClosureVerifier
{
    private static readonly string[] ForbiddenProductionMemberNames =
    {
        "CreateForTesting",
        "OpenFromOutputsRootForTests",
        "CaptureTreeSnapshotForTests",
        "ConfigureDisposalForTests",
        "TerminateExactRootForTests",
        "CreateForTests",
        "CreateIsolatedForTests",
        "CreateObserverForTests",
        "TakeProcessLeaseForTests"
    };

    private sealed record RuntimeAssetClaim(
        string Identity,
        string Section,
        string DeclaredPath,
        JsonElement Metadata);

    internal const string ExpectedRuntimeTarget = ".NETCoreApp,Version=v8.0/win-x64";
    internal const string GuardianRootAssemblyName = "CodexGuardian";
    internal const string BrokerRootAssemblyName = "CodexGuardian.Broker";
    internal const string ExpectedControlLibrary = "CodexGuardian.Control/1.0.0";
    internal const string ExpectedPkcsLibrary = "System.Security.Cryptography.Pkcs/8.0.1";
    internal const string ExpectedGuardianProviderLibrary =
        "runtimepack.Microsoft.WindowsDesktop.App.Runtime.win-x64/8.0.24";
    internal const string ExpectedBrokerProviderLibrary = ExpectedPkcsLibrary;
    internal const string ExpectedGuardianPkcsSha256 =
        "5E6E29F3D858236C1544D625544F61D12ACCB30E8F5764AAF6B9613AD10BFE97";
    internal const string ExpectedBrokerPkcsSha256 =
        "D8E4B733FBAEC1FE0E808FD6391479F190B170DF03E309C5F07DC85445447D22";
    internal const string ExpectedPkcsPackageSha512 =
        "sha512-CoCRHFym33aUSf/NtWSVSZa99dkd0Hm7OCZUxORBjRB16LNhIEOf8THPqzIYlvKM0nNDAPTRBa1FxEECrgaxxA==";
    internal const string PkcsAssetName = "System.Security.Cryptography.Pkcs.dll";
    internal const string ExpectedPkcsPublicKeyToken = "B03F5F7F11D50A3A";

    private const int MaximumDepsBytes = 4 * 1024 * 1024;
    private const long MaximumProductionAssemblyBytes = 64L * 1024 * 1024;

    internal static PublishedRuntimeDependencyClosure Verify(
        string runtimeRoot,
        string nuGetPackagesRoot,
        string rootAssemblyName = GuardianRootAssemblyName,
        bool requireProductionSurface = false)
    {
        ValidateRootAssemblyName(rootAssemblyName);
        var fullRuntimeRoot = ValidateRoot(runtimeRoot, "Published runtime root");
        var fullPackagesRoot = ValidateRoot(nuGetPackagesRoot, "NuGet package root");
        var depsPath = GetDirectChildPath(
            fullRuntimeRoot,
            rootAssemblyName + ".deps.json",
            "Published dependency manifest");
        using var document = ReadStrictDepsDocument(depsPath);
        var root = RequireObject(document.RootElement, "Published dependency manifest");
        var runtimeTarget = RequireObject(
            GetUniqueProperty(root, "runtimeTarget", "Published dependency manifest"),
            "Published runtime target");
        var runtimeTargetName = RequireString(
            GetUniqueProperty(runtimeTarget, "name", "Published runtime target"),
            "Published runtime target name");
        if (!string.Equals(
                runtimeTargetName,
                ExpectedRuntimeTarget,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Published runtime target is '{runtimeTargetName}'; expected '{ExpectedRuntimeTarget}'.");
        }

        var targets = RequireObject(
            GetUniqueProperty(root, "targets", "Published dependency manifest"),
            "Published targets");
        var libraries = RequireObject(
            GetUniqueProperty(root, "libraries", "Published dependency manifest"),
            "Published libraries");
        var currentTarget = RequireObject(
            GetUniqueProperty(targets, runtimeTargetName, "Published targets"),
            "Published current target");

        var targetEntries = ReadUniqueObjectProperties(currentTarget, "Published current target");
        var libraryEntries = ReadUniqueObjectProperties(libraries, "Published libraries");
        if (!targetEntries.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(libraryEntries.Keys))
        {
            throw new InvalidDataException(
                "Published current target and library identities do not form the same closed set.");
        }

        var rootLibrary = FindRootLibrary(libraryEntries, rootAssemblyName);
        RequireProjectLibrary(libraryEntries, rootLibrary, "Published root library");
        RequireProjectLibrary(libraryEntries, ExpectedControlLibrary, "Published Control library");
        VerifyPkcsLibrary(libraryEntries);

        var rootDependencies = ReadDependencies(targetEntries[rootLibrary], rootLibrary);
        if (!rootDependencies.TryGetValue("CodexGuardian.Control", out var controlVersion) ||
            !string.Equals(controlVersion, "1.0.0", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published root library does not depend on CodexGuardian.Control 1.0.0.");
        }
        const string guardianRuntimePackName =
            "runtimepack.Microsoft.WindowsDesktop.App.Runtime.win-x64";
        if (string.Equals(
                rootAssemblyName,
                GuardianRootAssemblyName,
                StringComparison.Ordinal))
        {
            if (!rootDependencies.TryGetValue(
                    guardianRuntimePackName,
                    out var runtimePackVersion) ||
                !string.Equals(runtimePackVersion, "8.0.24", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Published Guardian root does not depend on the pinned WindowsDesktop runtime pack.");
            }
        }
        else if (rootDependencies.ContainsKey(guardianRuntimePackName))
        {
            throw new InvalidDataException(
                "Published Broker root unexpectedly depends on the Guardian WindowsDesktop runtime pack.");
        }

        var controlDependencies = ReadDependencies(
            targetEntries[ExpectedControlLibrary],
            ExpectedControlLibrary);
        if (!controlDependencies.TryGetValue(
                "System.Security.Cryptography.Pkcs",
                out var pkcsVersion) ||
            !string.Equals(pkcsVersion, "8.0.1", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published Control library does not depend on System.Security.Cryptography.Pkcs 8.0.1.");
        }

        var reachable = GetReachableLibraries(rootLibrary, targetEntries);
        if (!reachable.Contains(ExpectedControlLibrary) || !reachable.Contains(ExpectedPkcsLibrary))
        {
            throw new InvalidDataException(
                "Published dependency graph does not reach the required Control and Pkcs libraries.");
        }

        var claims = new List<RuntimeAssetClaim>();
        foreach (var identity in reachable.OrderBy(value => value, StringComparer.Ordinal))
        {
            var targetEntry = RequireObject(targetEntries[identity], $"Published target '{identity}'");
            CollectRuntimeAssetClaims(targetEntry, identity, claims);
        }

        if (claims.Count != 1)
        {
            throw new InvalidDataException(
                $"Published dependency graph has {claims.Count} reachable Pkcs runtime asset claims; expected exactly one.");
        }

        var provider = claims[0];
        var packageAssetPath = ResolveProviderAssetPath(
            rootAssemblyName,
            provider,
            libraryEntries,
            fullPackagesRoot);
        var assemblyVersion = RequireString(
            GetUniqueProperty(provider.Metadata, "assemblyVersion", "Published Pkcs runtime metadata"),
            "Published Pkcs assembly version");
        var fileVersion = RequireString(
            GetUniqueProperty(provider.Metadata, "fileVersion", "Published Pkcs runtime metadata"),
            "Published Pkcs file version");
        if (!Version.TryParse(assemblyVersion, out _) || !Version.TryParse(fileVersion, out _))
        {
            throw new InvalidDataException("Published Pkcs version metadata is invalid.");
        }
        var expectedFileVersion = string.Equals(
            rootAssemblyName,
            GuardianRootAssemblyName,
            StringComparison.Ordinal)
            ? "8.0.2426.7010"
            : "8.0.1024.46610";
        if (!string.Equals(assemblyVersion, "8.0.0.0", StringComparison.Ordinal) ||
            !string.Equals(fileVersion, expectedFileVersion, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published Pkcs version metadata does not match the pinned role provider.");
        }

        var publishedAssetPath = GetDirectChildPath(
            fullRuntimeRoot,
            PkcsAssetName,
            "Published Pkcs runtime asset");
        VerifyAssetFile(publishedAssetPath, assemblyVersion, fileVersion, "Published Pkcs runtime asset");
        VerifyAssetFile(packageAssetPath, assemblyVersion, fileVersion, "NuGet provider Pkcs asset");

        var publishedLength = new FileInfo(publishedAssetPath).Length;
        var packageLength = new FileInfo(packageAssetPath).Length;
        var publishedSha256 = ComputeSha256(publishedAssetPath);
        var packageSha256 = ComputeSha256(packageAssetPath);
        var expectedSha256 = string.Equals(
            rootAssemblyName,
            GuardianRootAssemblyName,
            StringComparison.Ordinal)
            ? ExpectedGuardianPkcsSha256
            : ExpectedBrokerPkcsSha256;
        if (publishedLength != packageLength ||
            !string.Equals(publishedSha256, packageSha256, StringComparison.Ordinal) ||
            !string.Equals(publishedSha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published Pkcs runtime asset does not match the transaction-owned NuGet provider asset.");
        }

        if (requireProductionSurface)
        {
            VerifyProductionRuntimeSurface(fullRuntimeRoot, rootAssemblyName);
        }

        return new PublishedRuntimeDependencyClosure(
            runtimeTargetName,
            rootLibrary,
            ExpectedControlLibrary,
            ExpectedPkcsLibrary,
            provider.Identity,
            publishedAssetPath,
            packageAssetPath,
            publishedSha256,
            assemblyVersion,
            fileVersion);
    }

    internal static void VerifyManagedAssemblyProductionSurface(
        string assemblyPath,
        string expectedAssemblyName)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath) ||
            string.IsNullOrWhiteSpace(expectedAssemblyName))
        {
            throw new ArgumentException("A managed production assembly identity is required.");
        }

        var fullPath = Path.GetFullPath(assemblyPath);
        var attributes = File.GetAttributes(fullPath);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
        {
            throw new InvalidDataException(
                $"Published managed assembly has an invalid file identity: {fullPath}");
        }

        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.RandomAccess);
        if (stream.Length is <= 0 or > MaximumProductionAssemblyBytes)
        {
            throw new InvalidDataException(
                $"Published managed assembly size is outside the fixed bound: {fullPath}");
        }

        using var peReader = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
        if (!peReader.HasMetadata)
        {
            throw new InvalidDataException(
                $"Published managed assembly has no CLI metadata: {fullPath}");
        }

        var metadata = peReader.GetMetadataReader();
        if (!metadata.IsAssembly)
        {
            throw new InvalidDataException(
                $"Published managed artifact is not an assembly: {fullPath}");
        }

        var actualAssemblyName = metadata.GetString(metadata.GetAssemblyDefinition().Name);
        if (!string.Equals(actualAssemblyName, expectedAssemblyName, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Published managed assembly name is '{actualAssemblyName}'; expected '{expectedAssemblyName}'.");
        }

        foreach (var referenceHandle in metadata.AssemblyReferences)
        {
            var referenceName = metadata.GetString(metadata.GetAssemblyReference(referenceHandle).Name);
            if (IsTestsAssemblyName(referenceName))
            {
                throw new InvalidDataException(
                    $"Published {expectedAssemblyName} assembly references CodexGuardian.Tests.");
            }
        }

        var assemblyDefinition = metadata.GetAssemblyDefinition();
        foreach (var attributeHandle in assemblyDefinition.GetCustomAttributes())
        {
            var attribute = metadata.GetCustomAttribute(attributeHandle);
            if (!IsInternalsVisibleToAttribute(metadata, attribute))
            {
                continue;
            }

            var friendAssembly = ReadInternalsVisibleToAssemblyName(metadata, attribute);
            var simpleName = ParseFriendAssemblySimpleName(friendAssembly);
            if (IsTestsAssemblyName(simpleName))
            {
                throw new InvalidDataException(
                    $"Published {expectedAssemblyName} assembly exposes a CodexGuardian.Tests friend surface.");
            }
        }

        foreach (var typeHandle in metadata.TypeDefinitions)
        {
            var type = metadata.GetTypeDefinition(typeHandle);
            foreach (var methodHandle in type.GetMethods())
            {
                var methodName = metadata.GetString(metadata.GetMethodDefinition(methodHandle).Name);
                if (IsForbiddenProductionMemberName(methodName))
                {
                    throw new InvalidDataException(
                        $"Published {expectedAssemblyName} assembly contains test-only member '{methodName}'.");
                }
            }

            foreach (var fieldHandle in type.GetFields())
            {
                var fieldName = metadata.GetString(metadata.GetFieldDefinition(fieldHandle).Name);
                if (IsForbiddenProductionMemberName(fieldName))
                {
                    throw new InvalidDataException(
                        $"Published {expectedAssemblyName} assembly contains test-only member '{fieldName}'.");
                }
            }
        }
    }

    private static void VerifyProductionRuntimeSurface(
        string runtimeRoot,
        string rootAssemblyName)
    {
        foreach (var assemblyName in new[]
                 {
                     rootAssemblyName,
                     ExpectedControlLibrary[..ExpectedControlLibrary.IndexOf('/')],
                     "CodexGuardian.Trust",
                 })
        {
            VerifyManagedAssemblyProductionSurface(
                GetDirectChildPath(
                    runtimeRoot,
                    assemblyName + ".dll",
                    "Published production managed assembly"),
                assemblyName);
        }
    }

    private static bool IsInternalsVisibleToAttribute(
        MetadataReader metadata,
        CustomAttribute attribute)
    {
        if (attribute.Constructor.Kind != HandleKind.MemberReference)
        {
            return false;
        }

        var constructor = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (!string.Equals(metadata.GetString(constructor.Name), ".ctor", StringComparison.Ordinal))
        {
            return false;
        }

        return constructor.Parent.Kind switch
        {
            HandleKind.TypeReference => IsInternalsVisibleToType(
                metadata,
                metadata.GetTypeReference((TypeReferenceHandle)constructor.Parent)),
            HandleKind.TypeDefinition => IsInternalsVisibleToType(
                metadata,
                metadata.GetTypeDefinition((TypeDefinitionHandle)constructor.Parent)),
            _ => false,
        };
    }

    private static bool IsInternalsVisibleToType(MetadataReader metadata, TypeReference type) =>
        string.Equals(
            metadata.GetString(type.Namespace),
            "System.Runtime.CompilerServices",
            StringComparison.Ordinal) &&
        string.Equals(
            metadata.GetString(type.Name),
            nameof(InternalsVisibleToAttribute),
            StringComparison.Ordinal);

    private static bool IsInternalsVisibleToType(MetadataReader metadata, TypeDefinition type) =>
        string.Equals(
            metadata.GetString(type.Namespace),
            "System.Runtime.CompilerServices",
            StringComparison.Ordinal) &&
        string.Equals(
            metadata.GetString(type.Name),
            nameof(InternalsVisibleToAttribute),
            StringComparison.Ordinal);

    private static string ReadInternalsVisibleToAssemblyName(
        MetadataReader metadata,
        CustomAttribute attribute)
    {
        try
        {
            var value = metadata.GetBlobReader(attribute.Value);
            if (value.ReadUInt16() != 1)
            {
                throw new BadImageFormatException(
                    "InternalsVisibleToAttribute has an invalid custom-attribute prolog.");
            }

            var assemblyName = value.ReadSerializedString();
            if (string.IsNullOrWhiteSpace(assemblyName) ||
                value.ReadUInt16() != 0 ||
                value.RemainingBytes != 0)
            {
                throw new BadImageFormatException(
                    "InternalsVisibleToAttribute has a noncanonical payload.");
            }

            return assemblyName;
        }
        catch (BadImageFormatException exception)
        {
            throw new InvalidDataException(
                "Published managed assembly has malformed friend metadata.",
                exception);
        }
    }

    private static string ParseFriendAssemblySimpleName(string displayName)
    {
        try
        {
            return new AssemblyName(displayName).Name ?? throw new FileLoadException(
                "The friend assembly display name has no simple name.");
        }
        catch (Exception exception) when (exception is ArgumentException or FileLoadException)
        {
            throw new InvalidDataException(
                "Published managed assembly has malformed friend metadata.",
                exception);
        }
    }

    private static bool IsTestsAssemblyName(string value) =>
        string.Equals(value, "CodexGuardian.Tests", StringComparison.OrdinalIgnoreCase);

    private static bool IsForbiddenProductionMemberName(string value) =>
        ForbiddenProductionMemberNames.Contains(value, StringComparer.OrdinalIgnoreCase);

    private static void ValidateRootAssemblyName(string rootAssemblyName)
    {
        if (!string.Equals(
                rootAssemblyName,
                GuardianRootAssemblyName,
                StringComparison.Ordinal) &&
            !string.Equals(
                rootAssemblyName,
                BrokerRootAssemblyName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published runtime root assembly is not a supported production role.");
        }
    }

    private static string ValidateRoot(string path, string label)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException($"{label} is required.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{label} must be on a local drive: {fullPath}");
        }

        var volumeRoot = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(volumeRoot) ||
            volumeRoot.Length != 3 ||
            volumeRoot[1] != Path.VolumeSeparatorChar)
        {
            throw new InvalidDataException($"{label} has no supported local volume root: {fullPath}");
        }
        AssertNoReparseTraversal(volumeRoot, fullPath, label, expectDirectory: true);

        return fullPath;
    }

    private static string GetDirectChildPath(string root, string name, string label)
    {
        var path = Path.GetFullPath(Path.Combine(root, name));
        if (!string.Equals(
                Path.GetDirectoryName(path)?.TrimEnd(Path.DirectorySeparatorChar),
                root,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"{label} escaped its expected root.");
        }

        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new FileNotFoundException($"{label} is missing.", path, exception);
        }
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"{label} is a reparse point: {path}");
        }
        if ((attributes & FileAttributes.Directory) != 0)
        {
            throw new InvalidDataException($"{label} is not a file: {path}");
        }

        return path;
    }

    private static JsonDocument ReadStrictDepsDocument(string path)
    {
        byte[] bytes;
        using (var stream = new FileStream(
                   path,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read,
                   64 * 1024,
                   FileOptions.SequentialScan))
        {
            if (stream.Length <= 0 || stream.Length > MaximumDepsBytes)
            {
                throw new InvalidDataException(
                    $"Published dependency manifest size is outside the {MaximumDepsBytes}-byte bound.");
            }

            bytes = new byte[checked((int)stream.Length)];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = stream.Read(bytes, offset, bytes.Length - offset);
                if (read == 0)
                {
                    throw new EndOfStreamException(
                        "Published dependency manifest ended before its bounded length.");
                }

                offset += read;
            }
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            throw new InvalidDataException("Published dependency manifest must be UTF-8 without BOM.");
        }

        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
            return JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 64,
                });
        }
        catch (Exception exception) when (exception is DecoderFallbackException or JsonException)
        {
            throw new InvalidDataException(
                "Published dependency manifest is not strict UTF-8 JSON.",
                exception);
        }
    }

    private static JsonElement RequireObject(JsonElement value, string label)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"{label} is not a JSON object.");
        }

        return value;
    }

    private static string RequireString(JsonElement value, string label)
    {
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"{label} is not a JSON string.");
        }

        var text = value.GetString();
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new InvalidDataException($"{label} is empty.");
        }

        return text;
    }

    private static JsonElement GetUniqueProperty(JsonElement value, string name, string label)
    {
        if (!TryGetUniqueProperty(value, name, out var property))
        {
            throw new InvalidDataException($"{label} is missing unique property '{name}'.");
        }

        return property;
    }

    private static bool TryGetUniqueProperty(JsonElement value, string name, out JsonElement property)
    {
        var found = false;
        property = default;
        foreach (var candidate in value.EnumerateObject())
        {
            if (!string.Equals(candidate.Name, name, StringComparison.Ordinal))
            {
                continue;
            }

            if (found)
            {
                throw new InvalidDataException($"JSON property '{name}' is duplicated.");
            }

            found = true;
            property = candidate.Value;
        }

        return found;
    }

    private static Dictionary<string, JsonElement> ReadUniqueObjectProperties(
        JsonElement value,
        string label)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!result.TryAdd(property.Name, property.Value))
            {
                throw new InvalidDataException($"{label} duplicates identity '{property.Name}'.");
            }
        }

        return result;
    }

    private static string FindRootLibrary(
        IReadOnlyDictionary<string, JsonElement> libraries,
        string rootAssemblyName)
    {
        var prefix = rootAssemblyName + "/";
        var roots = libraries
            .Where(pair =>
                pair.Key.StartsWith(prefix, StringComparison.Ordinal) &&
                IsProjectLibrary(pair.Value))
            .Select(pair => pair.Key)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        if (roots.Length != 1)
        {
            throw new InvalidDataException(
                $"Published dependency manifest has {roots.Length} root {rootAssemblyName} project libraries; expected one.");
        }

        return roots[0];
    }

    private static void RequireProjectLibrary(
        IReadOnlyDictionary<string, JsonElement> libraries,
        string identity,
        string label)
    {
        if (!libraries.TryGetValue(identity, out var library) || !IsProjectLibrary(library))
        {
            throw new InvalidDataException($"{label} identity is missing or is not a project: {identity}");
        }
    }

    private static bool IsProjectLibrary(JsonElement library) =>
        TryReadLibraryType(library, out var type) &&
        string.Equals(type, "project", StringComparison.Ordinal);

    private static bool IsRuntimePackLibrary(JsonElement library) =>
        TryReadLibraryType(library, out var type) &&
        string.Equals(type, "runtimepack", StringComparison.Ordinal);

    private static bool IsPackageLibrary(JsonElement library) =>
        TryReadLibraryType(library, out var type) &&
        string.Equals(type, "package", StringComparison.Ordinal);

    private static bool TryReadLibraryType(JsonElement library, out string? type)
    {
        type = null;
        var objectValue = RequireObject(library, "Published library");
        if (!TryGetUniqueProperty(objectValue, "type", out var typeValue) ||
            typeValue.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        type = typeValue.GetString();
        return type is not null;
    }

    private static void VerifyPkcsLibrary(IReadOnlyDictionary<string, JsonElement> libraries)
    {
        if (!libraries.TryGetValue(ExpectedPkcsLibrary, out var library))
        {
            throw new InvalidDataException("Published Pkcs package library identity is missing.");
        }

        var value = RequireObject(library, "Published Pkcs package library");
        RequireExactProperties(
            value,
            "Published Pkcs package library",
            "type",
            "serviceable",
            "sha512",
            "path",
            "hashPath");
        var type = RequireString(
            GetUniqueProperty(value, "type", "Published Pkcs package library"),
            "Published Pkcs package type");
        var sha512 = RequireString(
            GetUniqueProperty(value, "sha512", "Published Pkcs package library"),
            "Published Pkcs package SHA-512");
        var serviceable = RequireBoolean(
            GetUniqueProperty(value, "serviceable", "Published Pkcs package library"),
            "Published Pkcs package serviceable flag");
        var packagePath = RequireString(
            GetUniqueProperty(value, "path", "Published Pkcs package library"),
            "Published Pkcs package path");
        var hashPath = RequireString(
            GetUniqueProperty(value, "hashPath", "Published Pkcs package library"),
            "Published Pkcs package hash path");
        if (!string.Equals(type, "package", StringComparison.Ordinal) ||
            !serviceable ||
            !string.Equals(sha512, ExpectedPkcsPackageSha512, StringComparison.Ordinal) ||
            !string.Equals(
                packagePath,
                "system.security.cryptography.pkcs/8.0.1",
                StringComparison.Ordinal) ||
            !string.Equals(
                hashPath,
                "system.security.cryptography.pkcs.8.0.1.nupkg.sha512",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published Pkcs package library does not match the locked 8.0.1 package identity.");
        }
    }

    private static Dictionary<string, string> ReadDependencies(
        JsonElement targetEntry,
        string identity)
    {
        var value = RequireObject(targetEntry, $"Published target '{identity}'");
        if (!TryGetUniqueProperty(value, "dependencies", out var dependenciesValue))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        var dependencies = RequireObject(
            dependenciesValue,
            $"Published dependencies for '{identity}'");
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in dependencies.EnumerateObject())
        {
            if (!result.TryAdd(
                    property.Name,
                    RequireString(property.Value, $"Published dependency '{property.Name}'")))
            {
                throw new InvalidDataException(
                    $"Published target '{identity}' duplicates dependency '{property.Name}'.");
            }
        }

        return result;
    }

    private static void CollectRuntimeAssetClaims(
        JsonElement targetEntry,
        string identity,
        ICollection<RuntimeAssetClaim> claims)
    {
        if (TryGetUniqueProperty(targetEntry, "runtime", out var runtimeValue))
        {
            var runtime = RequireObject(runtimeValue, $"Published runtime assets for '{identity}'");
            foreach (var property in runtime.EnumerateObject())
            {
                if (IsPkcsAssetPath(property.Name))
                {
                    claims.Add(new RuntimeAssetClaim(
                        identity,
                        "runtime",
                        property.Name,
                        RequireObject(
                            property.Value,
                            $"Published Pkcs runtime metadata for '{identity}'")));
                }
            }
        }

        if (!TryGetUniqueProperty(targetEntry, "runtimeTargets", out var runtimeTargetsValue))
        {
            return;
        }

        var runtimeTargets = RequireObject(
            runtimeTargetsValue,
            $"Published RID runtime assets for '{identity}'");
        foreach (var property in runtimeTargets.EnumerateObject())
        {
            if (!IsPkcsAssetPath(property.Name))
            {
                continue;
            }

            var metadata = RequireObject(
                property.Value,
                $"Published Pkcs RID runtime metadata for '{identity}'");
            claims.Add(new RuntimeAssetClaim(
                identity,
                "runtimeTargets",
                property.Name,
                metadata));
        }
    }

    private static string ResolveProviderAssetPath(
        string rootAssemblyName,
        RuntimeAssetClaim provider,
        IReadOnlyDictionary<string, JsonElement> libraries,
        string packagesRoot)
    {
        if (!libraries.TryGetValue(provider.Identity, out var providerLibrary))
        {
            throw new InvalidDataException(
                $"Published Pkcs runtime asset claimant has no library identity: {provider.Identity}");
        }

        if (string.Equals(
                rootAssemblyName,
                GuardianRootAssemblyName,
                StringComparison.Ordinal))
        {
            if (!string.Equals(
                    provider.Identity,
                    ExpectedGuardianProviderLibrary,
                    StringComparison.Ordinal) ||
                !IsRuntimePackLibrary(providerLibrary))
            {
                throw new InvalidDataException(
                    $"Published Guardian Pkcs claimant is not the pinned WindowsDesktop runtime pack: {provider.Identity}");
            }

            VerifyGuardianProviderLibrary(providerLibrary);
            ValidateGuardianRuntimeAssetClaim(provider);
            return ResolveGuardianRuntimePackAssetPath(packagesRoot, provider.Identity);
        }

        if (!string.Equals(
                provider.Identity,
                ExpectedBrokerProviderLibrary,
                StringComparison.Ordinal) ||
            !IsPackageLibrary(providerLibrary))
        {
            throw new InvalidDataException(
                $"Published Broker Pkcs claimant is not the locked package provider: {provider.Identity}");
        }

        ValidateBrokerPackageAssetClaim(provider);
        return ResolveBrokerPackageAssetPath(packagesRoot, provider.Identity);
    }

    private static void ValidateGuardianRuntimeAssetClaim(RuntimeAssetClaim claim)
    {
        var normalized = claim.DeclaredPath.Replace('/', '\\');
        if (!string.Equals(claim.Section, "runtime", StringComparison.Ordinal) ||
            !string.Equals(normalized, PkcsAssetName, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published Guardian Pkcs declaration is not the pinned runtime asset.");
        }

        RequireExactProperties(
            claim.Metadata,
            "Published Guardian Pkcs runtime metadata",
            "assemblyVersion",
            "fileVersion");
    }

    private static void ValidateBrokerPackageAssetClaim(RuntimeAssetClaim claim)
    {
        const string expectedPackageAssetPath =
            "runtimes\\win\\lib\\net8.0\\System.Security.Cryptography.Pkcs.dll";
        var normalized = claim.DeclaredPath.Replace('/', '\\');
        if (!string.Equals(claim.Section, "runtime", StringComparison.Ordinal) ||
            !string.Equals(
                normalized,
                expectedPackageAssetPath,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published Broker Pkcs declaration is not the locked win package asset.");
        }

        RequireExactProperties(
            claim.Metadata,
            "Published Broker Pkcs runtime metadata",
            "assemblyVersion",
            "fileVersion");
    }

    private static void VerifyGuardianProviderLibrary(JsonElement library)
    {
        var value = RequireObject(library, "Published Guardian runtime-pack library");
        RequireExactProperties(
            value,
            "Published Guardian runtime-pack library",
            "type",
            "serviceable",
            "sha512");
        var type = RequireString(
            GetUniqueProperty(value, "type", "Published Guardian runtime-pack library"),
            "Published Guardian runtime-pack type");
        var serviceable = RequireBoolean(
            GetUniqueProperty(value, "serviceable", "Published Guardian runtime-pack library"),
            "Published Guardian runtime-pack serviceable flag");
        var sha512 = GetUniqueProperty(
            value,
            "sha512",
            "Published Guardian runtime-pack library");
        if (!string.Equals(type, "runtimepack", StringComparison.Ordinal) ||
            serviceable ||
            sha512.ValueKind != JsonValueKind.String ||
            !string.Equals(sha512.GetString(), string.Empty, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Published Guardian runtime-pack library identity is not exact.");
        }
    }

    private static bool IsPkcsAssetPath(string path)
    {
        var normalized = path.Replace('/', '\\');
        var separator = normalized.LastIndexOf('\\');
        var fileName = separator >= 0 ? normalized[(separator + 1)..] : normalized;
        return string.Equals(fileName, PkcsAssetName, StringComparison.OrdinalIgnoreCase);
    }

    private static string? TryReadOptionalString(JsonElement value, string name)
    {
        if (!TryGetUniqueProperty(value, name, out var property))
        {
            return null;
        }

        if (property.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException($"Published runtime metadata property '{name}' is not a string.");
        }

        return property.GetString();
    }

    private static bool RequireBoolean(JsonElement value, string label)
    {
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException($"{label} is not a JSON boolean.");
        }

        return value.GetBoolean();
    }

    private static HashSet<string> GetReachableLibraries(
        string root,
        IReadOnlyDictionary<string, JsonElement> targetEntries)
    {
        var reachable = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Queue<string>();
        pending.Enqueue(root);
        while (pending.Count > 0)
        {
            var identity = pending.Dequeue();
            if (!reachable.Add(identity))
            {
                continue;
            }

            if (!targetEntries.TryGetValue(identity, out var targetEntry))
            {
                throw new InvalidDataException(
                    $"Published dependency graph references missing target '{identity}'.");
            }

            foreach (var dependency in ReadDependencies(targetEntry, identity))
            {
                var dependencyIdentity = dependency.Key + "/" + dependency.Value;
                if (!targetEntries.ContainsKey(dependencyIdentity))
                {
                    throw new InvalidDataException(
                        $"Published dependency '{identity}' references missing target '{dependencyIdentity}'.");
                }

                pending.Enqueue(dependencyIdentity);
            }
        }

        if (reachable.Count != targetEntries.Count)
        {
            throw new InvalidDataException("Published current target contains unreachable library identities.");
        }

        return reachable;
    }

    private static string ResolveGuardianRuntimePackAssetPath(
        string packagesRoot,
        string providerIdentity)
    {
        var separator = providerIdentity.LastIndexOf('/');
        if (separator <= 0 ||
            separator == providerIdentity.Length - 1 ||
            separator != providerIdentity.IndexOf('/') ||
            providerIdentity.Contains('\\'))
        {
            throw new InvalidDataException(
                $"Published runtime-pack identity is invalid: {providerIdentity}");
        }

        var packageId = providerIdentity[..separator];
        var packageVersion = providerIdentity[(separator + 1)..];
        const string runtimePackPrefix = "runtimepack.";
        if (!packageId.StartsWith(runtimePackPrefix, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Published runtime-pack identity has no runtimepack prefix: {providerIdentity}");
        }

        packageId = packageId[runtimePackPrefix.Length..];
        if (!IsCanonicalNuGetSegment(packageId, allowUnderscore: true) ||
            !IsCanonicalNuGetSegment(packageVersion, allowUnderscore: false))
        {
            throw new InvalidDataException(
                $"Published runtime-pack identity is not canonical: {providerIdentity}");
        }
        var packageRoot = Path.GetFullPath(Path.Combine(
            packagesRoot,
            packageId.ToLowerInvariant(),
            packageVersion.ToLowerInvariant()));
        if (!IsStrictDescendant(packageRoot, packagesRoot))
        {
            throw new InvalidDataException("NuGet runtime-pack directory escaped its package root.");
        }
        AssertNoReparseTraversal(
            packagesRoot,
            packageRoot,
            "NuGet runtime-pack directory",
            expectDirectory: true);

        var assetPath = Path.GetFullPath(Path.Combine(
            packageRoot,
            "runtimes",
            "win-x64",
            "lib",
            "net8.0",
            PkcsAssetName));
        if (!IsStrictDescendant(assetPath, packageRoot))
        {
            throw new InvalidDataException("NuGet runtime-pack Pkcs asset escaped its package directory.");
        }
        AssertNoReparseTraversal(
            packagesRoot,
            assetPath,
            "NuGet runtime-pack Pkcs asset",
            expectDirectory: false);

        return assetPath;
    }

    private static string ResolveBrokerPackageAssetPath(
        string packagesRoot,
        string providerIdentity)
    {
        if (!string.Equals(
                providerIdentity,
                ExpectedBrokerProviderLibrary,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Published Broker package identity is invalid: {providerIdentity}");
        }

        var packageRoot = Path.GetFullPath(Path.Combine(
            packagesRoot,
            "system.security.cryptography.pkcs",
            "8.0.1"));
        if (!IsStrictDescendant(packageRoot, packagesRoot))
        {
            throw new InvalidDataException("NuGet Broker package directory escaped its package root.");
        }
        AssertNoReparseTraversal(
            packagesRoot,
            packageRoot,
            "NuGet Broker package directory",
            expectDirectory: true);

        var assetPath = Path.GetFullPath(Path.Combine(
            packageRoot,
            "runtimes",
            "win",
            "lib",
            "net8.0",
            PkcsAssetName));
        if (!IsStrictDescendant(assetPath, packageRoot))
        {
            throw new InvalidDataException("NuGet Broker Pkcs asset escaped its package directory.");
        }
        AssertNoReparseTraversal(
            packagesRoot,
            assetPath,
            "NuGet Broker Pkcs asset",
            expectDirectory: false);

        return assetPath;
    }

    private static void RequireExactProperties(
        JsonElement value,
        string label,
        params string[] expectedNames)
    {
        var expected = expectedNames.ToHashSet(StringComparer.Ordinal);
        var actual = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in RequireObject(value, label).EnumerateObject())
        {
            if (!actual.Add(property.Name))
            {
                throw new InvalidDataException(
                    $"{label} duplicates property '{property.Name}'.");
            }
        }

        if (!actual.SetEquals(expected))
        {
            throw new InvalidDataException($"{label} does not have the exact property set.");
        }
    }

    private static bool IsCanonicalNuGetSegment(string value, bool allowUnderscore)
    {
        if (value.Length is < 1 or > 128 ||
            !IsAsciiLetterOrDigit(value[0]) ||
            !IsAsciiLetterOrDigit(value[^1]) ||
            value.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var character in value)
        {
            if (IsAsciiLetterOrDigit(character) ||
                character is '.' or '-' ||
                (allowUnderscore && character == '_'))
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static bool IsAsciiLetterOrDigit(char value) =>
        value is >= '0' and <= '9' or >= 'A' and <= 'Z' or >= 'a' and <= 'z';

    private static bool IsStrictDescendant(string path, string root) =>
        path.StartsWith(
            root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);

    private static void AssertNoReparseTraversal(
        string root,
        string path,
        string label,
        bool expectDirectory)
    {
        if (!IsStrictDescendant(path, root))
        {
            throw new InvalidDataException($"{label} escaped its expected root.");
        }

        var relative = Path.GetRelativePath(root, path);
        var current = root;
        var segments = relative.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);
        for (var index = 0; index < segments.Length; index++)
        {
            current = Path.Combine(current, segments[index]);
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(current);
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
            {
                throw new FileNotFoundException(
                    $"{label} traversal component is missing.",
                    current,
                    exception);
            }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"{label} traverses a reparse point: {current}");
            }

            var isDirectory = (attributes & FileAttributes.Directory) != 0;
            var isFinal = index == segments.Length - 1;
            if ((!isFinal && !isDirectory) ||
                (isFinal && isDirectory != expectDirectory))
            {
                throw new InvalidDataException($"{label} traversal component has an invalid type: {current}");
            }
        }
    }

    private static void VerifyAssetFile(
        string path,
        string expectedAssemblyVersion,
        string expectedFileVersion,
        string label)
    {
        var item = new FileInfo(path);
        if (!item.Exists || item.Length <= 0)
        {
            throw new InvalidDataException($"{label} is empty or missing: {path}");
        }

        AssemblyName assemblyName;
        try
        {
            assemblyName = AssemblyName.GetAssemblyName(path);
        }
        catch (Exception exception) when (exception is BadImageFormatException or FileLoadException)
        {
            throw new InvalidDataException($"{label} is not a loadable managed assembly.", exception);
        }

        var versionPath = path.StartsWith(@"\\?\", StringComparison.Ordinal)
            ? path
            : @"\\?\" + path;
        var fileVersion = FileVersionInfo.GetVersionInfo(versionPath).FileVersion;
        var publicKeyToken = Convert.ToHexString(
            assemblyName.GetPublicKeyToken() ?? Array.Empty<byte>());
        if (!string.Equals(
                assemblyName.Name,
                "System.Security.Cryptography.Pkcs",
                StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(assemblyName.CultureName) ||
            !string.Equals(
                publicKeyToken,
                ExpectedPkcsPublicKeyToken,
                StringComparison.Ordinal) ||
            !string.Equals(
                assemblyName.Version?.ToString(),
                expectedAssemblyVersion,
                StringComparison.Ordinal) ||
            !string.Equals(fileVersion, expectedFileVersion, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"{label} version metadata does not match deps.json: " +
                $"assembly={assemblyName.Version} expectedAssembly={expectedAssemblyVersion} " +
                $"file={fileVersion} expectedFile={expectedFileVersion}.");
        }
    }

    private static string ComputeSha256(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
