using System.Text;
using System.Text.Json;

namespace CodexGuardian.Control;

internal sealed record CodexCdpObservationEnvelope(
    string Kind,
    long Sequence,
    string SanitizedJson);

internal static class CodexCdpObservationProtocol
{
    internal const int MaximumPayloadBytes = 4096;
    internal const string BindingName = "__codexGuardianCdpEmit";
    internal const string RuntimeSlot = "__codexGuardianCdpObservationRuntime";
    internal const string HookVersion = "cdp-runtime-1";
    internal const string ContractId = "codex-cdp-observation-v1";

    private static readonly HashSet<string> ThreadStatuses =
        ["notLoaded", "idle", "systemError", "active", "unknown"];
    private static readonly HashSet<string> TurnStatuses =
        ["completed", "interrupted", "failed", "inProgress", "unknown"];
    private static readonly HashSet<string> Phases = ["started", "completed"];
    private static readonly HashSet<string> ErrorKinds =
    [
        "contextWindowExceeded", "sessionBudgetExceeded", "usageLimitExceeded",
        "serverOverloaded", "cyberPolicy", "httpConnectionFailed",
        "responseStreamConnectionFailed", "internalServerError", "unauthorized",
        "badRequest", "threadRollbackFailed", "sandboxError",
        "responseStreamDisconnected", "responseTooManyFailedAttempts",
        "activeTurnNotSteerable", "other"
    ];
    private static readonly HashSet<string> ItemTypes =
    [
        "userMessage", "hookPrompt", "agentMessage", "plan", "reasoning",
        "commandExecution", "fileChange", "mcpToolCall", "dynamicToolCall",
        "collabAgentToolCall", "subAgentActivity", "webSearch", "imageView", "sleep",
        "imageGeneration", "enteredReviewMode", "exitedReviewMode", "contextCompaction",
        "remoteTaskCreated", "unknown"
    ];
    private static readonly HashSet<string> ConnectionStates =
        ["connecting", "connected", "reconnecting", "restarting", "disconnected", "closed", "failed", "error", "unknown"];
    private static readonly HashSet<string> ConnectionTransports =
        ["local", "remote", "stdio", "websocket", "ipc", "unknown"];
    private static readonly HashSet<string> ConnectionProgress =
        ["starting", "initializing", "waiting-for-device", "confirming-connection", "connecting", "connected", "reconnecting", "ready", "disconnected", "failed", "unknown"];

    internal static bool TryValidate(
        string payload,
        out CodexCdpObservationEnvelope? observation,
        out string reason)
    {
        observation = null;
        reason = "invalid";
        if (string.IsNullOrWhiteSpace(payload) || Encoding.UTF8.GetByteCount(payload) > MaximumPayloadBytes)
        {
            reason = "payload-size";
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(payload, JsonOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !TryGetString(root, "kind", out var kind) ||
                !TryGetInt64(root, "seq", out var sequence) ||
                sequence is < 1 or > 9_007_199_254_740_991)
            {
                reason = "shape";
                return false;
            }

            var accepted = kind switch
            {
                "hello" => ValidateHello(root, sequence),
                "snapshot" => ValidateSnapshot(root),
                "notificationShape" => ValidateNotificationShape(root),
                "threadState" => ValidateThreadState(root),
                "turn" => ValidateTurn(root),
                "item" => ValidateItem(root),
                "streamError" => ValidateStreamError(root),
                "appServerConnection" => ValidateConnection(root),
                _ => false
            };
            if (!accepted)
            {
                reason = "fields";
                return false;
            }

            observation = new CodexCdpObservationEnvelope(kind, sequence, root.GetRawText());
            reason = "accepted";
            return true;
        }
        catch (JsonException)
        {
            reason = "invalid-json";
            return false;
        }
    }

    private static bool ValidateHello(JsonElement root, long sequence) =>
        sequence == 1 &&
        HasExactProperties(root,
            "kind", "seq", "protocol", "hookVersion", "contractId",
            "source", "pageProtocol", "bridgePresent") &&
        TryGetInt32(root, "protocol", out var protocol) && protocol == 1 &&
        HasString(root, "hookVersion", HookVersion) &&
        HasString(root, "contractId", ContractId) &&
        HasString(root, "source", "cdp-main-world") &&
        HasString(root, "pageProtocol", "app") &&
        TryGetBoolean(root, "bridgePresent", out var bridgePresent) && bridgePresent;

    private static bool ValidateSnapshot(JsonElement root)
    {
        if (!HasExactProperties(root,
                "kind", "seq", "routeKnown", "threadId", "composerKnown", "editorPresent",
                "composerFocused", "hasDraft") ||
            !TryGetBoolean(root, "routeKnown", out var routeKnown) ||
            !TryGetBoolean(root, "composerKnown", out var composerKnown) ||
            !TryGetBoolean(root, "editorPresent", out var editorPresent) ||
            editorPresent && !composerKnown)
        {
            return false;
        }

        if (!TryGetOptionalIdentifier(root, "threadId", out var threadId) ||
            routeKnown != (threadId is not null))
        {
            return false;
        }

        if (!TryGetOptionalBoolean(root, "composerFocused", out var focused) ||
            !TryGetOptionalBoolean(root, "hasDraft", out var hasDraft))
        {
            return false;
        }

        return editorPresent ? focused.HasValue && hasDraft.HasValue : focused is null && hasDraft is null;
    }

    private static bool ValidateNotificationShape(JsonElement root) =>
        HasExactProperties(root,
            "kind", "seq", "topMethod", "messageMethod", "requestMethod",
            "notificationMethod", "payloadMethod", "recognizedEnvelope") &&
        TryGetBoolean(root, "topMethod", out _) &&
        TryGetBoolean(root, "messageMethod", out _) &&
        TryGetBoolean(root, "requestMethod", out _) &&
        TryGetBoolean(root, "notificationMethod", out _) &&
        TryGetBoolean(root, "payloadMethod", out _) &&
        TryGetString(root, "recognizedEnvelope", out var envelope) &&
        envelope is "top" or "unknown";

    private static bool ValidateThreadState(JsonElement root) =>
        HasExactProperties(root, "kind", "seq", "threadId", "status", "notificationEnvelope") &&
        HasIdentifier(root, "threadId") &&
        TryGetString(root, "status", out var status) && ThreadStatuses.Contains(status) &&
        HasString(root, "notificationEnvelope", "top");

    private static bool ValidateTurn(JsonElement root) =>
        HasExactProperties(root,
            "kind", "seq", "threadId", "turnId", "phase", "status", "errorKind",
            "httpStatusCode", "willRetry", "notificationEnvelope") &&
        HasIdentifier(root, "threadId") && HasIdentifier(root, "turnId") &&
        TryGetString(root, "phase", out var phase) && Phases.Contains(phase) &&
        TryGetString(root, "status", out var status) && TurnStatuses.Contains(status) &&
        TryGetString(root, "errorKind", out var errorKind) && ErrorKinds.Contains(errorKind) &&
        TryGetOptionalInt32(root, "httpStatusCode", out var httpStatusCode) &&
        (httpStatusCode is null or >= 100 and <= 599) &&
        TryGetBoolean(root, "willRetry", out _) &&
        HasString(root, "notificationEnvelope", "top");

    private static bool ValidateItem(JsonElement root) =>
        HasExactProperties(root,
            "kind", "seq", "threadId", "turnId", "phase", "itemType", "notificationEnvelope") &&
        HasIdentifier(root, "threadId") && HasIdentifier(root, "turnId") &&
        TryGetString(root, "phase", out var phase) && Phases.Contains(phase) &&
        TryGetString(root, "itemType", out var itemType) && ItemTypes.Contains(itemType) &&
        HasString(root, "notificationEnvelope", "top");

    private static bool ValidateStreamError(JsonElement root)
    {
        if (!HasExactProperties(root,
                "kind", "seq", "threadId", "turnId", "willRetry", "errorKind",
                "httpStatusCode", "reconnectAttempt", "reconnectMaxAttempts", "notificationEnvelope") ||
            !HasIdentifier(root, "threadId") || !HasIdentifier(root, "turnId") ||
            !TryGetBoolean(root, "willRetry", out _) ||
            !TryGetString(root, "errorKind", out var errorKind) || !ErrorKinds.Contains(errorKind) ||
            !TryGetOptionalInt32(root, "httpStatusCode", out var httpStatusCode) ||
            httpStatusCode is not null and (< 100 or > 599) ||
            !TryGetOptionalInt32(root, "reconnectAttempt", out var attempt) ||
            !TryGetOptionalInt32(root, "reconnectMaxAttempts", out var maximum) ||
            !HasString(root, "notificationEnvelope", "top"))
        {
            return false;
        }

        return attempt is null && maximum is null ||
               attempt is >= 0 && maximum is >= 1 and <= 100 && attempt <= maximum;
    }

    private static bool ValidateConnection(JsonElement root) =>
        HasExactProperties(root, "kind", "seq", "state", "transport", "progress") &&
        TryGetString(root, "state", out var state) && ConnectionStates.Contains(state) &&
        TryGetString(root, "transport", out var transport) && ConnectionTransports.Contains(transport) &&
        TryGetString(root, "progress", out var progress) && ConnectionProgress.Contains(progress);

    private static bool HasExactProperties(JsonElement root, params string[] expected)
    {
        var allowed = expected.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!allowed.Contains(property.Name) || !seen.Add(property.Name))
            {
                return false;
            }
        }

        return seen.SetEquals(allowed);
    }

    private static bool HasIdentifier(JsonElement root, string name) =>
        TryGetString(root, name, out var value) && IsIdentifier(value);

    private static bool TryGetOptionalIdentifier(JsonElement root, string name, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString();
        return value is not null && IsIdentifier(value);
    }

    private static bool IsIdentifier(string value) =>
        value.Length is >= 8 and <= 80 &&
        value.All(static character => char.IsLetterOrDigit(character) || character is '-' or '_');

    private static bool HasString(JsonElement root, string name, string expected) =>
        TryGetString(root, name, out var value) && value == expected;

    private static bool TryGetString(JsonElement root, string name, out string value)
    {
        value = string.Empty;
        return root.TryGetProperty(name, out var property) &&
               property.ValueKind == JsonValueKind.String &&
               (value = property.GetString() ?? string.Empty).Length > 0;
    }

    private static bool TryGetBoolean(JsonElement root, string name, out bool value)
    {
        value = false;
        if (!root.TryGetProperty(name, out var property) ||
            property.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            return false;
        }

        value = property.GetBoolean();
        return true;
    }

    private static bool TryGetOptionalBoolean(JsonElement root, string name, out bool? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (property.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            return false;
        }

        value = property.GetBoolean();
        return true;
    }

    private static bool TryGetInt32(JsonElement root, string name, out int value)
    {
        value = 0;
        return root.TryGetProperty(name, out var property) && property.TryGetInt32(out value);
    }

    private static bool TryGetInt64(JsonElement root, string name, out long value)
    {
        value = 0;
        return root.TryGetProperty(name, out var property) && property.TryGetInt64(out value);
    }

    private static bool TryGetOptionalInt32(JsonElement root, string name, out int? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (!property.TryGetInt32(out var parsed))
        {
            return false;
        }

        value = parsed;
        return true;
    }

    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 12
    };
}
