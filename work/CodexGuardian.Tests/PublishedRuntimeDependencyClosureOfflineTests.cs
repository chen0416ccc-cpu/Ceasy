using CodexGuardian.Broker;
using CodexGuardian.Control;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class PublishedRuntimeDependencyClosureOfflineTests
{
    internal const string VerificationArgument = "--verify-published-runtime-closure";
    internal const string SuccessMarker = "PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_VERIFIED";
    internal const string ProductionSurfaceArgument = "--require-production-runtime-surface";
    internal const string ProductionSurfaceSuccessMarker =
        "PUBLISHED_PRODUCTION_RUNTIME_SURFACE_VERIFIED";
    private const string RuntimeRootArgument = "--published-runtime-root";
    private const string NuGetPackagesRootArgument = "--published-runtime-nuget-packages-root";
    private const string RootAssemblyArgument = "--published-runtime-root-assembly";
    private const string GuardianProviderLibrary =
        PublishedRuntimeDependencyClosureVerifier.ExpectedGuardianProviderLibrary;
    private const string BrokerPackageAssetPath =
        "runtimes/win/lib/net8.0/System.Security.Cryptography.Pkcs.dll";

    internal static bool IsVerificationInvocation(string[] args) =>
        args.Contains(VerificationArgument, StringComparer.OrdinalIgnoreCase);

    internal static int RunVerificationInvocation(string[] args)
    {
        try
        {
            var productionSurfaceCount = args.Count(value => string.Equals(
                value,
                ProductionSurfaceArgument,
                StringComparison.OrdinalIgnoreCase));
            var requireProductionSurface = productionSurfaceCount == 1;
            if (productionSurfaceCount > 1 ||
                args.Length != (requireProductionSurface ? 8 : 7) ||
                !string.Equals(args[0], VerificationArgument, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Published runtime verification arguments are invalid.");
            }

            var runtimeRoot = ReadSingleArgument(args, RuntimeRootArgument);
            var packagesRoot = ReadSingleArgument(args, NuGetPackagesRootArgument);
            var rootAssemblyName = ReadSingleArgument(args, RootAssemblyArgument);
            var result = PublishedRuntimeDependencyClosureVerifier.Verify(
                runtimeRoot,
                packagesRoot,
                rootAssemblyName,
                requireProductionSurface);
            Console.WriteLine(SuccessMarker);
            if (requireProductionSurface)
            {
                Console.WriteLine(ProductionSurfaceSuccessMarker);
            }
            Console.WriteLine(
                "PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_DETAIL " +
                $"target={result.RuntimeTarget} provider={result.ProviderLibrary} " +
                $"sha256={result.Sha256} assemblyVersion={result.AssemblyVersion} " +
                $"fileVersion={result.FileVersion}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                "PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_FAILED " +
                $"type={exception.GetType().Name} message={exception.Message}");
            return 1;
        }
    }

    internal static Task RunAsync(Action<bool, string> assert)
    {
        VerifyMalformedCliFailsClosed(assert);
        VerifyProductionSurfaceMetadata(assert);
        RunCase(
            "published runtime closure accepts the serviced runtime-pack Pkcs provider",
            _ => { },
            expectedSuccess: true,
            assert);
        RunCase(
            "published Broker runtime closure accepts the locked package Pkcs provider",
            _ => { },
            expectedSuccess: true,
            assert,
            PublishedRuntimeDependencyClosureVerifier.BrokerRootAssemblyName);
        RunCase(
            "published Broker runtime closure rejects a runtime-pack provider downgrade",
            ReplaceBrokerProviderWithRuntimePack,
            expectedSuccess: false,
            assert,
            PublishedRuntimeDependencyClosureVerifier.BrokerRootAssemblyName);
        RunCase(
            "published Broker runtime closure rejects a noncanonical package asset path",
            ReplaceBrokerPackageAssetPath,
            expectedSuccess: false,
            assert,
            PublishedRuntimeDependencyClosureVerifier.BrokerRootAssemblyName);
        RunCase(
            "published Broker runtime closure rejects a tampered package-cache asset",
            fixture =>
            {
                using var stream = new FileStream(
                    fixture.PackageAssetPath,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.None);
                stream.WriteByte(0x5A);
            },
            expectedSuccess: false,
            assert,
            PublishedRuntimeDependencyClosureVerifier.BrokerRootAssemblyName);
        RunCase(
            "published Broker runtime closure rejects unknown package metadata",
            AddBrokerUnknownRuntimeMetadata,
            expectedSuccess: false,
            assert,
            PublishedRuntimeDependencyClosureVerifier.BrokerRootAssemblyName);
        RunCase(
            "published Broker runtime closure rejects a compile-asset substitution",
            ReplaceBrokerAssetsWithCompileAsset,
            expectedSuccess: false,
            assert,
            PublishedRuntimeDependencyClosureVerifier.BrokerRootAssemblyName);
        RunCase(
            "published runtime closure rejects an unsupported root stem",
            _ => { },
            expectedSuccess: false,
            assert,
            "CodexGuardian.Tests");
        RunCase(
            "published runtime closure rejects a missing Pkcs output asset",
            fixture => File.Delete(fixture.PublishedAssetPath),
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a missing Control to Pkcs dependency edge",
            fixture =>
            {
                var target = GetCurrentTarget(fixture.Document);
                var control = target[PublishedRuntimeDependencyClosureVerifier.ExpectedControlLibrary]!.AsObject();
                control.Remove("dependencies");
                fixture.WriteDocument();
            },
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a non-win-x64 runtime target",
            fixture =>
            {
                fixture.Document["runtimeTarget"]!["name"] = ".NETCoreApp,Version=v8.0/linux-x64";
                fixture.WriteDocument();
            },
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a missing reachable Pkcs provider",
            fixture =>
            {
                var provider = GetCurrentTarget(fixture.Document)[fixture.ProviderLibrary]!.AsObject();
                provider.Remove("runtime");
                fixture.WriteDocument();
            },
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects duplicate reachable Pkcs providers",
            AddDuplicateProvider,
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a package target Pkcs runtime alias",
            AddPackageRuntimeClaim,
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a duplicate applicable RID runtime claim",
            AddRuntimeTargetsClaim,
            expectedSuccess: false,
            assert);
        RunCase(
            "published Guardian runtime closure rejects a runtimeTargets provider substitution",
            ReplaceGuardianRuntimeWithRuntimeTargets,
            expectedSuccess: false,
            assert);
        RunCase(
            "published Guardian runtime closure rejects extra runtime-pack library fields",
            fixture =>
            {
                fixture.Document["libraries"]![GuardianProviderLibrary]!["path"] =
                    "microsoft.windowsdesktop.app.runtime.win-x64/8.0.24";
                fixture.WriteDocument();
            },
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a tampered Pkcs output asset",
            fixture =>
            {
                using var stream = new FileStream(
                    fixture.PublishedAssetPath,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.None);
                stream.WriteByte(0xA5);
            },
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects an intermediate NuGet junction",
            ReplacePackageRuntimeDirectoryWithJunction,
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a noncanonical runtime-pack identity",
            ReplaceProviderWithNoncanonicalIdentity,
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a wrong managed assembly with matching metadata and hash",
            ReplaceAssetsWithWrongAssembly,
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects mismatched Pkcs version metadata",
            fixture =>
            {
                var provider = GetCurrentTarget(fixture.Document)[fixture.ProviderLibrary]!.AsObject();
                provider["runtime"]![PublishedRuntimeDependencyClosureVerifier.PkcsAssetName]!["fileVersion"] =
                    "0.0.0.0";
                fixture.WriteDocument();
            },
            expectedSuccess: false,
            assert);
        RunCase(
            "published runtime closure rejects a Pkcs package identity outside the lock",
            fixture =>
            {
                fixture.Document["libraries"]![PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary]!["sha512"] =
                    "sha512-invalid";
                fixture.WriteDocument();
            },
            expectedSuccess: false,
            assert);
        return Task.CompletedTask;
    }

    private static void VerifyProductionSurfaceMetadata(Action<bool, string> assert)
    {
        var forbiddenMemberNames =
            (string[]?)typeof(PublishedRuntimeDependencyClosureVerifier)
                .GetField(
                    "ForbiddenProductionMemberNames",
                    BindingFlags.Static | BindingFlags.NonPublic)
                ?.GetValue(null);
        var requiredSettlementTestMembers = new[]
        {
            "CreateForTests",
            "CreateIsolatedForTests",
            "CreateObserverForTests",
            "TakeProcessLeaseForTests"
        };
        assert(
            forbiddenMemberNames is not null &&
            requiredSettlementTestMembers.All(name =>
                forbiddenMemberNames.Contains(name, StringComparer.OrdinalIgnoreCase)),
            "production surface verifier rejects every settlement test-only member name");

        try
        {
            var frameworkAssembly = typeof(JsonDocument).Assembly;
            PublishedRuntimeDependencyClosureVerifier.VerifyManagedAssemblyProductionSurface(
                frameworkAssembly.Location,
                frameworkAssembly.GetName().Name ??
                throw new InvalidDataException("Framework assembly name is missing."));
            assert(
                true,
                "production surface verifier accepts a managed assembly without CodexGuardian test access");
        }
        catch (Exception exception)
        {
            assert(
                false,
                "production surface verifier accepts a managed assembly without CodexGuardian test access: " +
                exception.GetType().Name + " - " + exception.Message);
        }

        try
        {
            var brokerAssembly = typeof(BrokerProductionHostV1).Assembly;
            PublishedRuntimeDependencyClosureVerifier.VerifyManagedAssemblyProductionSurface(
                brokerAssembly.Location,
                brokerAssembly.GetName().Name ??
                throw new InvalidDataException("Broker assembly name is missing."));
            assert(
                false,
                "production surface verifier rejects the explicit test-friend Broker build");
        }
        catch (InvalidDataException exception)
        {
            assert(
                exception.Message.Contains("CodexGuardian.Tests friend surface", StringComparison.Ordinal),
                "production surface verifier rejects the explicit test-friend Broker build");
        }
        catch (Exception exception)
        {
            assert(
                false,
                "production surface verifier rejects the explicit test-friend Broker build: " +
                exception.GetType().Name + " - " + exception.Message);
        }

        VerifyCaseVariantMetadataRejected(assert);
    }

    private static void VerifyCaseVariantMetadataRejected(Action<bool, string> assert)
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "CodexGuardian-production-surface-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var brokerAssembly = typeof(BrokerProductionHostV1).Assembly;
            var assemblyName = brokerAssembly.GetName().Name ??
                throw new InvalidDataException("Broker assembly name is missing.");
            VerifyPatchedMetadataRejected(
                brokerAssembly.Location,
                Path.Combine(root, "friend-case.dll"),
                "CodexGuardian.Tests",
                "cOdExGuardian.Tests",
                assemblyName,
                "CodexGuardian.Tests friend surface",
                "production surface verifier rejects case-variant Tests friend identity",
                assert);
            VerifyPatchedMetadataRejected(
                brokerAssembly.Location,
                Path.Combine(root, "reference-case.dll"),
                "CodexGuardian.Trust",
                "cOdExGuardian.Tests",
                assemblyName,
                "references CodexGuardian.Tests",
                "production surface verifier rejects case-variant Tests assembly reference",
                assert);
            VerifyPatchedMetadataRejected(
                brokerAssembly.Location,
                Path.Combine(root, "friend-malformed.dll"),
                "CodexGuardian.Tests",
                "CodexGuardian.Test,",
                assemblyName,
                "malformed friend metadata",
                "production surface verifier rejects malformed friend display name",
                assert);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void VerifyPatchedMetadataRejected(
        string source,
        string destination,
        string oldValue,
        string newValue,
        string expectedAssemblyName,
        string expectedMessage,
        string assertionName,
        Action<bool, string> assert)
    {
        try
        {
            var bytes = File.ReadAllBytes(source);
            var oldBytes = Encoding.ASCII.GetBytes(oldValue);
            var newBytes = Encoding.ASCII.GetBytes(newValue);
            if (oldBytes.Length != newBytes.Length)
            {
                throw new InvalidOperationException("Metadata replacement must preserve byte length.");
            }

            var replacements = 0;
            for (var offset = 0; offset <= bytes.Length - oldBytes.Length; offset++)
            {
                if (!bytes.AsSpan(offset, oldBytes.Length).SequenceEqual(oldBytes))
                {
                    continue;
                }

                newBytes.CopyTo(bytes.AsSpan(offset, newBytes.Length));
                replacements++;
                offset += oldBytes.Length - 1;
            }

            if (replacements == 0)
            {
                throw new InvalidOperationException("Expected metadata text was not found.");
            }

            File.WriteAllBytes(destination, bytes);
            PublishedRuntimeDependencyClosureVerifier.VerifyManagedAssemblyProductionSurface(
                destination,
                expectedAssemblyName);
            assert(false, assertionName);
        }
        catch (InvalidDataException exception)
        {
            assert(exception.Message.Contains(expectedMessage, StringComparison.Ordinal), assertionName);
        }
        catch (Exception exception)
        {
            assert(
                false,
                assertionName + ": " + exception.GetType().Name + " - " + exception.Message);
        }
    }

    private static void VerifyMalformedCliFailsClosed(Action<bool, string> assert)
    {
        var originalOut = Console.Out;
        var originalError = Console.Error;
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        var passed = false;
        try
        {
            Console.SetOut(stdout);
            Console.SetError(stderr);
            var exitCode = RunVerificationInvocation(new[] { VerificationArgument });
            passed = exitCode == 1 &&
                     !stdout.ToString().Contains(SuccessMarker, StringComparison.Ordinal) &&
                     stderr.ToString().Contains(
                         "PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_FAILED",
                         StringComparison.Ordinal);
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
        assert(
            passed,
            "published runtime closure CLI rejects malformed dispatch without a success marker");
    }

    private static string ReadSingleArgument(string[] args, string name)
    {
        var indexes = args
            .Select((value, index) => (value, index))
            .Where(pair => string.Equals(pair.value, name, StringComparison.OrdinalIgnoreCase))
            .Select(pair => pair.index)
            .ToArray();
        if (indexes.Length != 1 || indexes[0] + 1 >= args.Length)
        {
            throw new ArgumentException($"Required argument is missing or duplicated: {name}");
        }

        var value = args[indexes[0] + 1];
        if (string.IsNullOrWhiteSpace(value) || value.StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"Required argument value is invalid: {name}");
        }

        return value;
    }

    private static void RunCase(
        string name,
        Action<RuntimeClosureFixture> mutate,
        bool expectedSuccess,
        Action<bool, string> assert,
        string rootAssemblyName = PublishedRuntimeDependencyClosureVerifier.GuardianRootAssemblyName)
    {
        RuntimeClosureFixture? fixture = null;
        try
        {
            fixture = RuntimeClosureFixture.Create(rootAssemblyName);
            mutate(fixture);
            var failure = TryVerify(fixture, rootAssemblyName, out var succeeded);
            assert(
                succeeded == expectedSuccess,
                succeeded == expectedSuccess || failure is null
                    ? name
                    : name + ": " + failure.GetType().Name + " - " + failure.Message);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: unexpected {exception.GetType().Name}: {exception.Message}");
        }
        finally
        {
            fixture?.Dispose();
        }
    }

    private static Exception? TryVerify(
        RuntimeClosureFixture fixture,
        string rootAssemblyName,
        out bool succeeded)
    {
        try
        {
            var result = PublishedRuntimeDependencyClosureVerifier.Verify(
                fixture.RuntimeRoot,
                fixture.PackagesRoot,
                rootAssemblyName);
            succeeded = string.Equals(
                            result.ProviderLibrary,
                            fixture.ProviderLibrary,
                            StringComparison.Ordinal) &&
                        string.Equals(
                            result.Sha256,
                            ComputeSha256(fixture.PublishedAssetPath),
                            StringComparison.Ordinal);
            return null;
        }
        catch (Exception exception)
        {
            succeeded = false;
            return exception;
        }
    }

    private static void AddDuplicateProvider(RuntimeClosureFixture fixture)
    {
        const string duplicateProvider =
            "runtimepack.CodexGuardian.Duplicate.Runtime.win-x64/8.0.25";
        var currentTarget = GetCurrentTarget(fixture.Document);
        var provider = currentTarget[fixture.ProviderLibrary]!.DeepClone();
        currentTarget[duplicateProvider] = provider;
        fixture.Document["libraries"]![duplicateProvider] = new JsonObject
        {
            ["type"] = "runtimepack",
            ["serviceable"] = false,
            ["sha512"] = string.Empty,
        };
        currentTarget[fixture.RootLibrary]!["dependencies"]![
            "runtimepack.CodexGuardian.Duplicate.Runtime.win-x64"] = "8.0.25";

        var duplicateAsset = Path.Combine(
            fixture.PackagesRoot,
            "codexguardian.duplicate.runtime.win-x64",
            "8.0.25",
            "runtimes",
            "win-x64",
            "lib",
            "net8.0",
            PublishedRuntimeDependencyClosureVerifier.PkcsAssetName);
        Directory.CreateDirectory(Path.GetDirectoryName(duplicateAsset)!);
        File.Copy(fixture.PackageAssetPath, duplicateAsset);
        fixture.WriteDocument();
    }

    private static void AddPackageRuntimeClaim(RuntimeClosureFixture fixture)
    {
        var currentTarget = GetCurrentTarget(fixture.Document);
        var metadata = currentTarget[GuardianProviderLibrary]!["runtime"]![
            PublishedRuntimeDependencyClosureVerifier.PkcsAssetName]!.DeepClone();
        currentTarget[PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary]!["runtime"] =
            new JsonObject
            {
                ["system.security.cryptography.pkcs.dll"] = metadata,
            };
        fixture.WriteDocument();
    }

    private static void AddRuntimeTargetsClaim(RuntimeClosureFixture fixture)
    {
        var currentTarget = GetCurrentTarget(fixture.Document);
        var metadata = currentTarget[GuardianProviderLibrary]!["runtime"]![
            PublishedRuntimeDependencyClosureVerifier.PkcsAssetName]!.DeepClone().AsObject();
        metadata["rid"] = "WIN-X64";
        metadata["assetType"] = "Runtime";
        currentTarget[PublishedRuntimeDependencyClosureVerifier.ExpectedControlLibrary]!["runtimeTargets"] =
            new JsonObject
            {
                ["runtimes/win-x64/lib/net8.0/system.security.cryptography.pkcs.dll"] = metadata,
            };
        fixture.WriteDocument();
    }

    private static void ReplaceGuardianRuntimeWithRuntimeTargets(RuntimeClosureFixture fixture)
    {
        var provider = GetCurrentTarget(fixture.Document)[GuardianProviderLibrary]!.AsObject();
        var metadata = provider["runtime"]![
            PublishedRuntimeDependencyClosureVerifier.PkcsAssetName]!.DeepClone().AsObject();
        provider.Remove("runtime");
        metadata["rid"] = "win-x64";
        metadata["assetType"] = "runtime";
        provider["runtimeTargets"] = new JsonObject
        {
            ["runtimes/win-x64/lib/net8.0/System.Security.Cryptography.Pkcs.dll"] = metadata,
        };
        fixture.WriteDocument();
    }

    private static void ReplaceBrokerProviderWithRuntimePack(RuntimeClosureFixture fixture)
    {
        var currentTarget = GetCurrentTarget(fixture.Document);
        var packageTarget = currentTarget[
            PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary]!.AsObject();
        var metadata = packageTarget["runtime"]![BrokerPackageAssetPath]!.DeepClone();
        packageTarget.Remove("runtime");
        currentTarget[GuardianProviderLibrary] = new JsonObject
        {
            ["runtime"] = new JsonObject
            {
                [PublishedRuntimeDependencyClosureVerifier.PkcsAssetName] = metadata,
            },
        };
        fixture.Document["libraries"]![GuardianProviderLibrary] = new JsonObject
        {
            ["type"] = "runtimepack",
            ["serviceable"] = false,
            ["sha512"] = string.Empty,
        };
        currentTarget[fixture.RootLibrary]!["dependencies"]![
            "runtimepack.Microsoft.WindowsDesktop.App.Runtime.win-x64"] = "8.0.24";
        fixture.WriteDocument();
    }

    private static void ReplaceBrokerPackageAssetPath(RuntimeClosureFixture fixture)
    {
        var runtime = GetCurrentTarget(fixture.Document)[
            PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary]!["runtime"]!.AsObject();
        var metadata = runtime[BrokerPackageAssetPath]!.DeepClone();
        runtime.Remove(BrokerPackageAssetPath);
        runtime["runtimes/win-x64/lib/net8.0/System.Security.Cryptography.Pkcs.dll"] = metadata;
        fixture.WriteDocument();
    }

    private static void AddBrokerUnknownRuntimeMetadata(RuntimeClosureFixture fixture)
    {
        var metadata = GetCurrentTarget(fixture.Document)[
            PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary]!["runtime"]![
            BrokerPackageAssetPath]!.AsObject();
        metadata["unexpected"] = "value";
        fixture.WriteDocument();
    }

    private static void ReplaceBrokerAssetsWithCompileAsset(RuntimeClosureFixture fixture)
    {
        var packagesRoot = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
        var compileAsset = string.IsNullOrWhiteSpace(packagesRoot)
            ? string.Empty
            : Path.Combine(
                packagesRoot,
                "system.security.cryptography.pkcs",
                "8.0.1",
                "lib",
                "net8.0",
                PublishedRuntimeDependencyClosureVerifier.PkcsAssetName);
        if (!File.Exists(compileAsset))
        {
            throw new FileNotFoundException(
                "The offline test requires the locked Pkcs compile asset.",
                compileAsset);
        }

        File.Copy(compileAsset, fixture.PublishedAssetPath, overwrite: true);
        File.Copy(compileAsset, fixture.PackageAssetPath, overwrite: true);
        var metadata = GetCurrentTarget(fixture.Document)[
            PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary]!["runtime"]![
            BrokerPackageAssetPath]!.AsObject();
        metadata["assemblyVersion"] = AssemblyName.GetAssemblyName(compileAsset).Version?.ToString();
        metadata["fileVersion"] = FileVersionInfo.GetVersionInfo(compileAsset).FileVersion;
        fixture.WriteDocument();
    }

    private static void ReplacePackageRuntimeDirectoryWithJunction(
        RuntimeClosureFixture fixture)
    {
        var runtimeDirectory = Path.Combine(
            fixture.PackagesRoot,
            "microsoft.windowsdesktop.app.runtime.win-x64",
            "8.0.24",
            "runtimes");
        var junctionTarget = Path.Combine(fixture.Root, "junction-target-runtimes");
        Directory.Move(runtimeDirectory, junctionTarget);
        CreateJunction(runtimeDirectory, junctionTarget);
        fixture.RegisterJunction(runtimeDirectory);
    }

    private static void ReplaceProviderWithNoncanonicalIdentity(
        RuntimeClosureFixture fixture)
    {
        const string dependencyName =
            "runtimepack.foo/../Microsoft.WindowsDesktop.App.Runtime.win-x64";
        const string replacementIdentity = dependencyName + "/8.0.24";
        var currentTarget = GetCurrentTarget(fixture.Document);
        var providerTarget = currentTarget[GuardianProviderLibrary]!.DeepClone();
        currentTarget.Remove(GuardianProviderLibrary);
        currentTarget[replacementIdentity] = providerTarget;

        var libraries = fixture.Document["libraries"]!.AsObject();
        var providerLibrary = libraries[GuardianProviderLibrary]!.DeepClone();
        libraries.Remove(GuardianProviderLibrary);
        libraries[replacementIdentity] = providerLibrary;

        var rootDependencies = currentTarget[fixture.RootLibrary]!["dependencies"]!.AsObject();
        rootDependencies.Remove("runtimepack.Microsoft.WindowsDesktop.App.Runtime.win-x64");
        rootDependencies[dependencyName] = "8.0.24";
        fixture.WriteDocument();
    }

    private static void ReplaceAssetsWithWrongAssembly(RuntimeClosureFixture fixture)
    {
        var replacement = typeof(PublishedRuntimeDependencyClosureVerifier).Assembly.Location;
        File.Copy(replacement, fixture.PublishedAssetPath, overwrite: true);
        File.Copy(replacement, fixture.PackageAssetPath, overwrite: true);
        var metadata = GetCurrentTarget(fixture.Document)[fixture.ProviderLibrary]!["runtime"]![
            PublishedRuntimeDependencyClosureVerifier.PkcsAssetName]!.AsObject();
        metadata["assemblyVersion"] = AssemblyName.GetAssemblyName(replacement).Version?.ToString();
        metadata["fileVersion"] = FileVersionInfo.GetVersionInfo(replacement).FileVersion;
        fixture.WriteDocument();
    }

    private static void CreateJunction(string junctionPath, string targetPath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            Arguments = $"/d /c mklink /J \"{junctionPath}\" \"{targetPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        }) ?? throw new InvalidOperationException("Unable to start the junction fixture command.");
        if (!process.WaitForExit(10_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            throw new TimeoutException("The junction fixture command exceeded its bounded timeout.");
        }

        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Unable to create the junction fixture: exit={process.ExitCode} stdout={stdout} stderr={stderr}");
        }
    }

    private static JsonObject GetCurrentTarget(JsonObject document) =>
        document["targets"]![PublishedRuntimeDependencyClosureVerifier.ExpectedRuntimeTarget]!.AsObject();

    private static string ComputeSha256(string path) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));

    private sealed class RuntimeClosureFixture : IDisposable
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
        };

        private RuntimeClosureFixture(
            string root,
            string runtimeRoot,
            string packagesRoot,
            string publishedAssetPath,
            string packageAssetPath,
            JsonObject document)
        {
            Root = root;
            RuntimeRoot = runtimeRoot;
            PackagesRoot = packagesRoot;
            PublishedAssetPath = publishedAssetPath;
            PackageAssetPath = packageAssetPath;
            Document = document;
        }

        internal string Root { get; }

        internal string RuntimeRoot { get; }

        internal string PackagesRoot { get; }

        internal string PublishedAssetPath { get; }

        internal string PackageAssetPath { get; }

        internal string RootAssemblyName { get; private init; } = string.Empty;

        internal string RootLibrary { get; private init; } = string.Empty;

        internal string ProviderLibrary { get; private init; } = string.Empty;

        internal JsonObject Document { get; }

        private List<string> Junctions { get; } = new();

        internal static RuntimeClosureFixture Create(string rootAssemblyName)
        {
            var isBroker = string.Equals(
                rootAssemblyName,
                PublishedRuntimeDependencyClosureVerifier.BrokerRootAssemblyName,
                StringComparison.Ordinal);
            var providerLibrary = isBroker
                ? PublishedRuntimeDependencyClosureVerifier.ExpectedBrokerProviderLibrary
                : GuardianProviderLibrary;
            var nuGetPackagesRoot = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
            var sourceAsset = string.IsNullOrWhiteSpace(nuGetPackagesRoot)
                ? string.Empty
                : isBroker
                    ? Path.Combine(
                        nuGetPackagesRoot,
                        "system.security.cryptography.pkcs",
                        "8.0.1",
                        "runtimes",
                        "win",
                        "lib",
                        "net8.0",
                        PublishedRuntimeDependencyClosureVerifier.PkcsAssetName)
                    : Path.Combine(
                        nuGetPackagesRoot,
                        "microsoft.windowsdesktop.app.runtime.win-x64",
                        "8.0.24",
                        "runtimes",
                        "win-x64",
                        "lib",
                        "net8.0",
                        PublishedRuntimeDependencyClosureVerifier.PkcsAssetName);
            if (!File.Exists(sourceAsset))
            {
                throw new FileNotFoundException(
                    "The offline test requires the transaction-owned role-specific Pkcs assembly.",
                    sourceAsset);
            }

            var root = Path.Combine(
                Path.GetTempPath(),
                "CodexGuardian",
                "published-runtime-closure-" + Guid.NewGuid().ToString("N"));
            var runtimeRoot = Path.Combine(root, "runtime");
            var packagesRoot = Path.Combine(root, "packages");
            Directory.CreateDirectory(runtimeRoot);
            Directory.CreateDirectory(packagesRoot);
            var publishedAssetPath = Path.Combine(
                runtimeRoot,
                PublishedRuntimeDependencyClosureVerifier.PkcsAssetName);
            var packageAssetPath = Path.Combine(
                isBroker
                    ? new[]
                    {
                        packagesRoot,
                        "system.security.cryptography.pkcs",
                        "8.0.1",
                        "runtimes",
                        "win",
                        "lib",
                        "net8.0",
                        PublishedRuntimeDependencyClosureVerifier.PkcsAssetName,
                    }
                    : new[]
                    {
                        packagesRoot,
                        "microsoft.windowsdesktop.app.runtime.win-x64",
                        "8.0.24",
                        "runtimes",
                        "win-x64",
                        "lib",
                        "net8.0",
                        PublishedRuntimeDependencyClosureVerifier.PkcsAssetName,
                    });
            Directory.CreateDirectory(Path.GetDirectoryName(packageAssetPath)!);
            File.Copy(sourceAsset, publishedAssetPath);
            File.Copy(sourceAsset, packageAssetPath);

            var assemblyVersion = AssemblyName.GetAssemblyName(sourceAsset).Version?.ToString()
                ?? throw new InvalidDataException("Offline test Pkcs assembly version is missing.");
            var fileVersion = FileVersionInfo.GetVersionInfo(sourceAsset).FileVersion
                ?? throw new InvalidDataException("Offline test Pkcs file version is missing.");
            var rootLibrary = rootAssemblyName + "/2.0.0";
            var document = CreateDocument(
                rootAssemblyName,
                rootLibrary,
                isBroker,
                assemblyVersion,
                fileVersion);
            var fixture = new RuntimeClosureFixture(
                root,
                runtimeRoot,
                packagesRoot,
                publishedAssetPath,
                packageAssetPath,
                document)
            {
                RootAssemblyName = rootAssemblyName,
                RootLibrary = rootLibrary,
                ProviderLibrary = providerLibrary,
            };
            fixture.WriteDocument();
            return fixture;
        }

        internal void WriteDocument()
        {
            var text = Document.ToJsonString(JsonOptions);
            File.WriteAllText(
                Path.Combine(RuntimeRoot, RootAssemblyName + ".deps.json"),
                text,
                new UTF8Encoding(false, true));
        }

        internal void RegisterJunction(string path) => Junctions.Add(path);

        public void Dispose()
        {
            foreach (var junction in Junctions)
            {
                if (Directory.Exists(junction))
                {
                    Directory.Delete(junction, recursive: false);
                }
            }

            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private static JsonObject CreateDocument(
            string rootAssemblyName,
            string rootLibrary,
            bool isBroker,
            string assemblyVersion,
            string fileVersion)
        {
            var rootDependencies = new JsonObject
            {
                ["CodexGuardian.Control"] = "1.0.0",
            };
            if (!isBroker)
            {
                rootDependencies["runtimepack.Microsoft.WindowsDesktop.App.Runtime.win-x64"] =
                    "8.0.24";
            }

            var currentTarget = new JsonObject
            {
                [rootLibrary] = new JsonObject
                {
                    ["dependencies"] = rootDependencies,
                    ["runtime"] = new JsonObject
                    {
                        [rootAssemblyName + ".dll"] = new JsonObject(),
                    },
                },
                [PublishedRuntimeDependencyClosureVerifier.ExpectedControlLibrary] = new JsonObject
                {
                    ["dependencies"] = new JsonObject
                    {
                        ["System.Security.Cryptography.Pkcs"] = "8.0.1",
                    },
                    ["runtime"] = new JsonObject
                    {
                        ["CodexGuardian.Control.dll"] = new JsonObject
                        {
                            ["assemblyVersion"] = "1.0.0",
                            ["fileVersion"] = "1.0.0.0",
                        },
                    },
                },
            };
            var runtimeMetadata = new JsonObject
            {
                ["assemblyVersion"] = assemblyVersion,
                ["fileVersion"] = fileVersion,
            };
            if (isBroker)
            {
                currentTarget[PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary] =
                    new JsonObject
                    {
                        ["runtime"] = new JsonObject
                        {
                            [BrokerPackageAssetPath] = runtimeMetadata,
                        },
                    };
            }
            else
            {
                currentTarget[GuardianProviderLibrary] = new JsonObject
                {
                    ["runtime"] = new JsonObject
                    {
                        [PublishedRuntimeDependencyClosureVerifier.PkcsAssetName] = runtimeMetadata,
                    },
                };
                currentTarget[PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary] =
                    new JsonObject();
            }

            var libraries = new JsonObject
            {
                [rootLibrary] = new JsonObject
                {
                    ["type"] = "project",
                    ["serviceable"] = false,
                    ["sha512"] = string.Empty,
                },
                [PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsLibrary] = new JsonObject
                {
                    ["type"] = "package",
                    ["serviceable"] = true,
                    ["sha512"] = PublishedRuntimeDependencyClosureVerifier.ExpectedPkcsPackageSha512,
                    ["path"] = "system.security.cryptography.pkcs/8.0.1",
                    ["hashPath"] = "system.security.cryptography.pkcs.8.0.1.nupkg.sha512",
                },
                [PublishedRuntimeDependencyClosureVerifier.ExpectedControlLibrary] = new JsonObject
                {
                    ["type"] = "project",
                    ["serviceable"] = false,
                    ["sha512"] = string.Empty,
                },
            };
            if (!isBroker)
            {
                libraries[GuardianProviderLibrary] = new JsonObject
                {
                    ["type"] = "runtimepack",
                    ["serviceable"] = false,
                    ["sha512"] = string.Empty,
                };
            }

            return new JsonObject
            {
                ["runtimeTarget"] = new JsonObject
                {
                    ["name"] = PublishedRuntimeDependencyClosureVerifier.ExpectedRuntimeTarget,
                    ["signature"] = string.Empty,
                },
                ["targets"] = new JsonObject
                {
                    [PublishedRuntimeDependencyClosureVerifier.ExpectedRuntimeTarget] = currentTarget,
                },
                ["libraries"] = libraries,
            };
        }
    }
}
