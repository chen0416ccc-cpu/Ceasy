using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed record CodexCdpRuntimeProfile(
    int Schema,
    string Mode,
    string Transport,
    string PackageName,
    string PackageFamilyName,
    string PackagePublisher,
    string PackageArchitecture,
    string ContractId,
    string AsarPackageName,
    string AsarProductName,
    string AsarMainPath,
    string AsarMainSha256,
    string PreloadPath,
    string PreloadSha256,
    string[] PreloadMarkers,
    string PageProtocol,
    string NotificationEnvelope,
    string HookSha256);

internal sealed record CodexCdpRuntimeResources(
    CodexCdpRuntimeProfile Profile,
    string HookSource)
{
    private const string ProfileResourceName =
        "CodexGuardian.HookPayload.cdp-runtime-profile.json";
    private const string HookResourceName =
        "CodexGuardian.HookPayload.codex-guardian-cdp-runtime-hook.js";
    private const string ExpectedAsarMainSha256 =
        "DCC940F4ABB9D2D3C84448B42A6499A19AAE7F3C221D853C48D32C9F62CE5CDB";
    private const string ExpectedPreloadSha256 =
        "A976C02AB0F9CF0EB11D5E4DA32C95E9F5DB3790D76505888C6E493F137F6AC9";
    private static readonly string[] ExpectedPreloadMarkers =
    [
        "electronBridge",
        "codex_desktop:message-for-view",
        "contextBridge.exposeInMainWorld",
        "MessageEvent"
    ];

    internal static CodexCdpRuntimeResources Load(Assembly? assembly = null)
    {
        assembly ??= typeof(CodexCdpRuntimeResources).Assembly;
        var profileBytes = ReadResource(assembly, ProfileResourceName);
        var hookBytes = ReadResource(assembly, HookResourceName);
        var profile = ParseProfile(profileBytes);
        RequireAscii(hookBytes, "CDP runtime Hook");

        var hookHash = Convert.ToHexString(SHA256.HashData(hookBytes));
        if (!string.Equals(hookHash, profile.HookSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The embedded CDP runtime Hook hash does not match its profile.");
        }

        var hookSource = Encoding.UTF8.GetString(hookBytes);
        ValidateHook(hookSource);
        return new CodexCdpRuntimeResources(profile, hookSource);
    }

    internal static CodexCdpRuntimeProfile ParseProfile(byte[] profileBytes)
    {
        ArgumentNullException.ThrowIfNull(profileBytes);
        RequireAscii(profileBytes, "CDP runtime profile");
        try
        {
            using var document = JsonDocument.Parse(profileBytes, JsonOptions);
            var root = document.RootElement;
            RequireExactProperties(
                root,
                "schema",
                "mode",
                "transport",
                "packageName",
                "packageFamilyName",
                "packagePublisher",
                "packageArchitecture",
                "contractId",
                "asarPackageName",
                "asarProductName",
                "asarMainPath",
                "asarMainSha256",
                "preloadPath",
                "preloadSha256",
                "preloadMarkers",
                "pageProtocol",
                "notificationEnvelope",
                "hookSha256");

            var profile = new CodexCdpRuntimeProfile(
                ReadInt32(root, "schema"),
                ReadString(root, "mode"),
                ReadString(root, "transport"),
                ReadString(root, "packageName"),
                ReadString(root, "packageFamilyName"),
                ReadString(root, "packagePublisher"),
                ReadString(root, "packageArchitecture"),
                ReadString(root, "contractId"),
                ReadString(root, "asarPackageName"),
                ReadString(root, "asarProductName"),
                ReadString(root, "asarMainPath"),
                ReadString(root, "asarMainSha256"),
                ReadString(root, "preloadPath"),
                ReadString(root, "preloadSha256"),
                ReadStringArray(root, "preloadMarkers"),
                ReadString(root, "pageProtocol"),
                ReadString(root, "notificationEnvelope"),
                ReadString(root, "hookSha256"));
            ValidateProfile(profile);
            return profile;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The embedded CDP runtime profile is invalid JSON.", exception);
        }
    }

    private static byte[] ReadResource(Assembly assembly, string name)
    {
        using var stream = assembly.GetManifestResourceStream(name) ??
            throw new InvalidDataException("Missing embedded runtime resource: " + name);
        if (stream.Length is <= 0 or > 256 * 1024)
        {
            throw new InvalidDataException("The embedded runtime resource has an invalid size: " + name);
        }

        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static void RequireAscii(ReadOnlySpan<byte> bytes, string description)
    {
        if (bytes.ContainsAnyExceptInRange((byte)0, (byte)0x7f))
        {
            throw new InvalidDataException(description + " must contain ASCII only.");
        }
    }

    private static void RequireExactProperties(JsonElement root, params string[] expected)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The embedded CDP runtime profile must be a JSON object.");
        }

        var allowed = expected.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!allowed.Contains(property.Name) || !seen.Add(property.Name))
            {
                throw new InvalidDataException(
                    "The embedded CDP runtime profile contains an unknown or duplicate property.");
            }
        }

        if (!seen.SetEquals(allowed))
        {
            throw new InvalidDataException("The embedded CDP runtime profile is missing a required property.");
        }
    }

    private static int ReadInt32(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var property) || !property.TryGetInt32(out var value))
        {
            throw new InvalidDataException("The CDP runtime profile contains an invalid " + name + ".");
        }

        return value;
    }

    private static string ReadString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("The CDP runtime profile contains an invalid " + name + ".");
        }

        var value = property.GetString();
        if (string.IsNullOrWhiteSpace(value) || value.Length > 256)
        {
            throw new InvalidDataException("The CDP runtime profile contains an invalid " + name + ".");
        }

        return value;
    }

    private static string[] ReadStringArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The CDP runtime profile contains an invalid " + name + ".");
        }

        var values = new List<string>();
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                throw new InvalidDataException("The CDP runtime profile contains an invalid " + name + ".");
            }

            var value = item.GetString();
            if (string.IsNullOrWhiteSpace(value) || value.Length > 256 || !unique.Add(value))
            {
                throw new InvalidDataException("The CDP runtime profile contains an invalid " + name + ".");
            }

            values.Add(value);
        }

        if (values.Count is < 1 or > 32)
        {
            throw new InvalidDataException("The CDP runtime profile contains an invalid " + name + ".");
        }

        return values.ToArray();
    }

    private static void ValidateProfile(CodexCdpRuntimeProfile profile)
    {
        if (profile.Schema != 2 ||
            profile.Mode != "read-only-cdp-pipe-runtime" ||
            profile.Transport != "remote-debugging-io-pipes" ||
            profile.PackageName != "OpenAI.Codex" ||
            profile.PackageFamilyName != "OpenAI.Codex_2p2nqsd0c76g0" ||
            profile.PackagePublisher != "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B" ||
            profile.PackageArchitecture != "x64" ||
            profile.ContractId != CodexCdpObservationProtocol.ContractId ||
            profile.AsarPackageName != "openai-codex-electron" ||
            profile.AsarProductName != "Codex" ||
            profile.AsarMainPath != ".vite/build/early-bootstrap.js" ||
            profile.AsarMainSha256 != ExpectedAsarMainSha256 ||
            profile.PreloadPath != ".vite/build/preload.js" ||
            profile.PreloadSha256 != ExpectedPreloadSha256 ||
            !profile.PreloadMarkers.SequenceEqual(ExpectedPreloadMarkers, StringComparer.Ordinal) ||
            profile.PageProtocol != "app" ||
            profile.NotificationEnvelope != "top")
        {
            throw new InvalidDataException("The embedded CDP runtime profile is incompatible.");
        }

        foreach (var hash in new[]
                 {
                     profile.AsarMainSha256,
                     profile.PreloadSha256,
                     profile.HookSha256
                 })
        {
            if (hash.Length != 64 || !hash.All(Uri.IsHexDigit))
            {
                throw new InvalidDataException("The CDP runtime profile contains an invalid SHA-256 value.");
            }
        }
    }

    private static void ValidateHook(string hookSource)
    {
        var forbidden = new[]
        {
            "messageText",
            "params.item?.content",
            "params.turn?.items",
            "reasoningText",
            "toolOutput",
            "remote-debugging-port",
            "packageVersion",
            "appBuild"
        };
        if (!hookSource.Contains("codex-guardian-cdp-observation-runtime-v1", StringComparison.Ordinal) ||
            !hookSource.Contains("requestSnapshot: () => publishSnapshot(true)", StringComparison.Ordinal) ||
            !hookSource.Contains("hookVersion: \"cdp-runtime-1\"", StringComparison.Ordinal) ||
            !hookSource.Contains(
                "contractId: \"codex-cdp-observation-v1\"",
                StringComparison.Ordinal) ||
            forbidden.Any(value => hookSource.Contains(value, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException("The embedded CDP runtime Hook violates its read-only contract.");
        }
    }

    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 8
    };
}
