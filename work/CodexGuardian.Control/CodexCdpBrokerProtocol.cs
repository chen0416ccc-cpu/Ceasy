using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CodexGuardian.Control;

internal enum CodexCdpBrokerCommandKind
{
    Hello,
    GetStatus,
    Subscribe,
    GetFullSnapshot,
    StartManagedCodex,
    RetireAfterCodexExit,
    RestartForUpgrade
}

internal sealed record CodexCdpBrokerCommand(
    CodexCdpBrokerCommandKind Kind,
    string? BrokerEpoch,
    string? OperationId,
    long? AfterSequence);

internal enum CodexCdpBrokerNotificationKind
{
    StateChanged,
    ResyncRequired
}

internal sealed record CodexCdpBrokerNotification(
    CodexCdpBrokerNotificationKind Kind,
    string BrokerEpoch,
    long Sequence,
    CodexCdpBrokerSnapshot? Snapshot);

internal static class CodexCdpBrokerProtocol
{
    internal const int ProtocolVersion = 1;
    internal const int MaximumFrameBytes = 256 * 1024;
    internal const int MaximumFramesPerAppend = 64;
    internal const long MaximumSequence = 9_007_199_254_740_991;

    private const string EndpointDomain = "CodexGuardian.CdpBroker.v1";
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static string CreateBrokerEpoch() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    internal static string CreateEndpointName(string currentUserSid, uint sessionId)
    {
        var normalizedSid = NormalizeSid(currentUserSid);
        var material = StrictUtf8.GetBytes(
            EndpointDomain + "\0" + normalizedSid + "\0" +
            sessionId.ToString(CultureInfo.InvariantCulture));
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(material, digest);
        return "codexguardian-cdp-broker-v1-s" +
               sessionId.ToString(CultureInfo.InvariantCulture) + "-" +
               Convert.ToHexString(digest[..16]).ToLowerInvariant();
    }

    internal static bool IsControlIdentifier(string? value)
    {
        if (value is null || value.Length is < 16 or > 64)
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

    internal static bool TryParseCommand(
        string json,
        out CodexCdpBrokerCommand? command,
        out string reason)
    {
        command = null;
        reason = "invalid";
        if (string.IsNullOrWhiteSpace(json))
        {
            reason = "empty-frame";
            return false;
        }

        int byteCount;
        try
        {
            byteCount = StrictUtf8.GetByteCount(json);
        }
        catch (EncoderFallbackException)
        {
            reason = "invalid-utf8";
            return false;
        }

        if (byteCount > MaximumFrameBytes)
        {
            reason = "frame-too-large";
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(json, JsonOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !TryGetRequiredString(root, "command", out var commandName))
            {
                reason = "invalid-shape";
                return false;
            }

            switch (commandName)
            {
                case "hello":
                    if (!HasExactProperties(root, "command", "protocol") ||
                        !root.TryGetProperty("protocol", out var protocolElement) ||
                        !protocolElement.TryGetInt32(out var protocol) ||
                        protocol != ProtocolVersion)
                    {
                        reason = "invalid-hello";
                        return false;
                    }

                    command = new CodexCdpBrokerCommand(
                        CodexCdpBrokerCommandKind.Hello,
                        null,
                        null,
                        null);
                    break;

                case "getStatus":
                    if (!TryParseEpochOnly(
                            root,
                            CodexCdpBrokerCommandKind.GetStatus,
                            out command))
                    {
                        reason = "invalid-get-status";
                        return false;
                    }

                    break;

                case "subscribe":
                    if (!HasExactProperties(
                            root,
                            "command",
                            "brokerEpoch",
                            "afterSequence") ||
                        !TryGetControlIdentifier(root, "brokerEpoch", out var subscribeEpoch) ||
                        !root.TryGetProperty("afterSequence", out var sequenceElement) ||
                        !sequenceElement.TryGetInt64(out var afterSequence) ||
                        afterSequence is < 0 or > MaximumSequence)
                    {
                        reason = "invalid-subscribe";
                        return false;
                    }

                    command = new CodexCdpBrokerCommand(
                        CodexCdpBrokerCommandKind.Subscribe,
                        subscribeEpoch,
                        null,
                        afterSequence);
                    break;

                case "getFullSnapshot":
                    if (!TryParseEpochOnly(
                            root,
                            CodexCdpBrokerCommandKind.GetFullSnapshot,
                            out command))
                    {
                        reason = "invalid-full-snapshot";
                        return false;
                    }

                    break;

                case "startManagedCodex":
                    if (!TryParseOperation(
                            root,
                            CodexCdpBrokerCommandKind.StartManagedCodex,
                            out command))
                    {
                        reason = "invalid-start";
                        return false;
                    }

                    break;

                case "retireAfterCodexExit":
                    if (!TryParseOperation(
                            root,
                            CodexCdpBrokerCommandKind.RetireAfterCodexExit,
                            out command))
                    {
                        reason = "invalid-retirement";
                        return false;
                    }

                    break;

                case "restartForUpgrade":
                    if (!TryParseOperation(
                            root,
                            CodexCdpBrokerCommandKind.RestartForUpgrade,
                            out command))
                    {
                        reason = "invalid-upgrade-restart";
                        return false;
                    }

                    break;

                default:
                    reason = "unknown-command";
                    return false;
            }

            reason = "accepted";
            return true;
        }
        catch (JsonException)
        {
            reason = "invalid-json";
            return false;
        }
    }

    internal static byte[] EncodeFrame(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        byte[] payload;
        try
        {
            payload = StrictUtf8.GetBytes(json);
        }
        catch (EncoderFallbackException exception)
        {
            throw new CodexCdpBrokerProtocolException(
                "invalid-utf8",
                "The broker frame is not valid UTF-8.",
                exception);
        }

        if (payload.Length is < 1 or > MaximumFrameBytes)
        {
            throw new CodexCdpBrokerProtocolException(
                "invalid-frame-length",
                "The broker frame length is outside the bounded contract.");
        }

        var frame = new byte[sizeof(uint) + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, checked((uint)payload.Length));
        payload.CopyTo(frame, sizeof(uint));
        return frame;
    }

    internal static string SerializeSnapshot(
        CodexCdpBrokerSnapshot snapshot,
        bool fullSnapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        using var stream = new MemoryStream(capacity: 512);
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteSnapshot(writer, snapshot, fullSnapshot ? "fullSnapshot" : "stateChanged");
        }

        return StrictUtf8.GetString(stream.ToArray());
    }

    internal static string SerializeNotification(CodexCdpBrokerNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);
        if (notification.Kind == CodexCdpBrokerNotificationKind.ResyncRequired)
        {
            using var stream = new MemoryStream(capacity: 160);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteString("kind", "resyncRequired");
                writer.WriteString("brokerEpoch", notification.BrokerEpoch);
                writer.WriteNumber("latestSequence", notification.Sequence);
                writer.WriteEndObject();
            }

            return StrictUtf8.GetString(stream.ToArray());
        }

        if (notification.Snapshot is null ||
            notification.Snapshot.BrokerEpoch != notification.BrokerEpoch ||
            notification.Snapshot.Sequence != notification.Sequence)
        {
            throw new InvalidOperationException(
                "A state notification requires its exact same-epoch snapshot.");
        }

        return SerializeSnapshot(notification.Snapshot, fullSnapshot: false);
    }

    internal static string SerializeCommandResult(
        CodexCdpBrokerCommand command,
        CodexCdpBrokerApplyResult result)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(result);
        if (!IsBoundedResultCode(result.Code))
        {
            throw new ArgumentException(
                "A bounded machine-readable command result code is required.",
                nameof(result));
        }

        using var stream = new MemoryStream(capacity: 256);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("kind", "commandResult");
            writer.WriteString("command", CommandName(command.Kind));
            writer.WriteString("disposition", DispositionName(result.Disposition));
            writer.WriteString("code", result.Code);
            writer.WriteString("brokerEpoch", result.Snapshot.BrokerEpoch);
            writer.WriteNumber("sequence", result.Snapshot.Sequence);
            writer.WriteEndObject();
        }

        return StrictUtf8.GetString(stream.ToArray());
    }

    private static void WriteSnapshot(
        Utf8JsonWriter writer,
        CodexCdpBrokerSnapshot snapshot,
        string kind)
    {
        writer.WriteStartObject();
        writer.WriteString("kind", kind);
        writer.WriteString("brokerEpoch", snapshot.BrokerEpoch);
        writer.WriteNumber("sequence", snapshot.Sequence);
        writer.WriteString("state", StateName(snapshot.State));
        writer.WriteNumber("connectedClients", snapshot.ConnectedClients);
        writer.WriteBoolean("ownsManagedCodex", snapshot.OwnsManagedCodex);
        writer.WriteString("retirementIntent", RetirementName(snapshot.RetirementIntent));
        writer.WriteBoolean("brokerExitIntent", snapshot.BrokerExitIntent);
        writer.WriteBoolean("managedCodexExitIntent", snapshot.ManagedCodexExitIntent);
        writer.WriteEndObject();
    }

    private static string StateName(CodexCdpBrokerState state) => state switch
    {
        CodexCdpBrokerState.Booting => "booting",
        CodexCdpBrokerState.Reconciling => "reconciling",
        CodexCdpBrokerState.ExternalCodexPresent => "externalCodexPresent",
        CodexCdpBrokerState.IdleNoCodex => "idleNoCodex",
        CodexCdpBrokerState.LaunchReserved => "launchReserved",
        CodexCdpBrokerState.LaunchingCandidate => "launchingCandidate",
        CodexCdpBrokerState.VerifyingCandidate => "verifyingCandidate",
        CodexCdpBrokerState.RaceLost => "raceLost",
        CodexCdpBrokerState.CdpHandshake => "cdpHandshake",
        CodexCdpBrokerState.ManagedUnverified => "managedUnverified",
        CodexCdpBrokerState.ManagedReady => "managedReady",
        CodexCdpBrokerState.OwnedCodexExited => "ownedCodexExited",
        CodexCdpBrokerState.Retiring => "retiring",
        CodexCdpBrokerState.FaultedNoOwner => "faultedNoOwner",
        _ => throw new ArgumentOutOfRangeException(nameof(state))
    };

    private static string RetirementName(CodexCdpBrokerRetirementIntent intent) => intent switch
    {
        CodexCdpBrokerRetirementIntent.None => "none",
        CodexCdpBrokerRetirementIntent.RetireAfterCodexExit => "retireAfterCodexExit",
        CodexCdpBrokerRetirementIntent.RestartForUpgrade => "restartForUpgrade",
        _ => throw new ArgumentOutOfRangeException(nameof(intent))
    };

    private static string CommandName(CodexCdpBrokerCommandKind kind) => kind switch
    {
        CodexCdpBrokerCommandKind.Hello => "hello",
        CodexCdpBrokerCommandKind.GetStatus => "getStatus",
        CodexCdpBrokerCommandKind.Subscribe => "subscribe",
        CodexCdpBrokerCommandKind.GetFullSnapshot => "getFullSnapshot",
        CodexCdpBrokerCommandKind.StartManagedCodex => "startManagedCodex",
        CodexCdpBrokerCommandKind.RetireAfterCodexExit => "retireAfterCodexExit",
        CodexCdpBrokerCommandKind.RestartForUpgrade => "restartForUpgrade",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private static string DispositionName(CodexCdpBrokerApplyDisposition disposition) =>
        disposition switch
        {
            CodexCdpBrokerApplyDisposition.Accepted => "accepted",
            CodexCdpBrokerApplyDisposition.Replayed => "replayed",
            CodexCdpBrokerApplyDisposition.Rejected => "rejected",
            _ => throw new ArgumentOutOfRangeException(nameof(disposition))
        };

    private static bool IsBoundedResultCode(string? value)
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

    private static bool TryParseEpochOnly(
        JsonElement root,
        CodexCdpBrokerCommandKind kind,
        out CodexCdpBrokerCommand? command)
    {
        command = null;
        if (!HasExactProperties(root, "command", "brokerEpoch") ||
            !TryGetControlIdentifier(root, "brokerEpoch", out var epoch))
        {
            return false;
        }

        command = new CodexCdpBrokerCommand(kind, epoch, null, null);
        return true;
    }

    private static bool TryParseOperation(
        JsonElement root,
        CodexCdpBrokerCommandKind kind,
        out CodexCdpBrokerCommand? command)
    {
        command = null;
        if (!HasExactProperties(root, "command", "brokerEpoch", "operationId") ||
            !TryGetControlIdentifier(root, "brokerEpoch", out var epoch) ||
            !TryGetControlIdentifier(root, "operationId", out var operationId))
        {
            return false;
        }

        command = new CodexCdpBrokerCommand(kind, epoch, operationId, null);
        return true;
    }

    private static bool HasExactProperties(JsonElement root, params string[] expected)
    {
        var allowed = new HashSet<string>(expected, StringComparer.Ordinal);
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

    private static bool TryGetRequiredString(
        JsonElement root,
        string propertyName,
        out string value)
    {
        value = string.Empty;
        return root.TryGetProperty(propertyName, out var element) &&
               element.ValueKind == JsonValueKind.String &&
               (value = element.GetString() ?? string.Empty).Length > 0;
    }

    private static bool TryGetControlIdentifier(
        JsonElement root,
        string propertyName,
        out string value) =>
        TryGetRequiredString(root, propertyName, out value) &&
        IsControlIdentifier(value);

    private static string NormalizeSid(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        if (sid.Length > 184 || !string.Equals(sid, sid.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException("A canonical bounded Windows SID is required.", nameof(sid));
        }

        var parts = sid.Split('-', StringSplitOptions.None);
        if (parts.Length is < 4 or > 18 ||
            !string.Equals(parts[0], "S", StringComparison.OrdinalIgnoreCase) ||
            !uint.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var revision) ||
            revision != 1 ||
            !ulong.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var authority) ||
            authority > 0x0000FFFFFFFFFFFFUL)
        {
            throw new ArgumentException("A canonical bounded Windows SID is required.", nameof(sid));
        }

        var normalized = new StringBuilder("S-1-");
        normalized.Append(authority.ToString(CultureInfo.InvariantCulture));
        for (var index = 3; index < parts.Length; index++)
        {
            if (!uint.TryParse(
                    parts[index],
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var subAuthority))
            {
                throw new ArgumentException("A canonical bounded Windows SID is required.", nameof(sid));
            }

            normalized.Append('-');
            normalized.Append(subAuthority.ToString(CultureInfo.InvariantCulture));
        }

        return normalized.ToString();
    }

    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 8
    };
}

internal sealed class CodexCdpBrokerCommandFrameDecoder
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private readonly object _sync = new();
    private readonly byte[] _header = new byte[sizeof(uint)];
    private int _headerBytes;
    private byte[]? _payload;
    private int _payloadBytes;
    private int _expectedPayloadBytes = -1;
    private bool _faulted;
    private bool _completed;

    internal bool IsFaulted
    {
        get
        {
            lock (_sync)
            {
                return _faulted;
            }
        }
    }

    internal bool IsCompleted
    {
        get
        {
            lock (_sync)
            {
                return _completed;
            }
        }
    }

    internal IReadOnlyList<CodexCdpBrokerCommand> Append(ReadOnlySpan<byte> bytes)
    {
        lock (_sync)
        {
            return AppendCore(bytes);
        }
    }

    private IReadOnlyList<CodexCdpBrokerCommand> AppendCore(ReadOnlySpan<byte> bytes)
    {
        if (_faulted)
        {
            throw new CodexCdpBrokerProtocolException(
                "decoder-faulted",
                "The broker decoder is already in a terminal failed state.");
        }

        if (_completed)
        {
            throw new CodexCdpBrokerProtocolException(
                "decoder-completed",
                "The broker decoder already reached a complete end of stream.");
        }

        var commands = new List<CodexCdpBrokerCommand>();
        try
        {
            while (!bytes.IsEmpty)
            {
                if (_expectedPayloadBytes < 0)
                {
                    var headerCount = Math.Min(_header.Length - _headerBytes, bytes.Length);
                    bytes[..headerCount].CopyTo(_header.AsSpan(_headerBytes));
                    _headerBytes += headerCount;
                    bytes = bytes[headerCount..];
                    if (_headerBytes != _header.Length)
                    {
                        continue;
                    }

                    var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(_header);
                    if (payloadLength is 0 or > CodexCdpBrokerProtocol.MaximumFrameBytes)
                    {
                        throw new CodexCdpBrokerProtocolException(
                            "invalid-frame-length",
                            "The broker frame length is outside the bounded contract.");
                    }

                    _expectedPayloadBytes = checked((int)payloadLength);
                    _payload = new byte[_expectedPayloadBytes];
                    _payloadBytes = 0;
                }

                var payloadCount = Math.Min(
                    _expectedPayloadBytes - _payloadBytes,
                    bytes.Length);
                bytes[..payloadCount].CopyTo(_payload!.AsSpan(_payloadBytes));
                _payloadBytes += payloadCount;
                bytes = bytes[payloadCount..];
                if (_payloadBytes != _expectedPayloadBytes)
                {
                    continue;
                }

                string json;
                try
                {
                    json = StrictUtf8.GetString(_payload!);
                }
                catch (DecoderFallbackException exception)
                {
                    throw new CodexCdpBrokerProtocolException(
                        "invalid-utf8",
                        "The broker frame is not valid UTF-8.",
                        exception);
                }

                if (!CodexCdpBrokerProtocol.TryParseCommand(
                        json,
                        out var command,
                        out var reason) ||
                    command is null)
                {
                    throw new CodexCdpBrokerProtocolException(
                        reason,
                        "The broker command did not match the exact control-plane schema.");
                }

                commands.Add(command);
                ResetFrame();
                if (commands.Count > CodexCdpBrokerProtocol.MaximumFramesPerAppend)
                {
                    throw new CodexCdpBrokerProtocolException(
                        "too-many-frames",
                        "One broker read contained too many complete frames.");
                }
            }

            return commands;
        }
        catch (Exception exception) when (
            exception is CodexCdpBrokerProtocolException or OverflowException)
        {
            _faulted = true;
            ResetFrame();
            if (exception is CodexCdpBrokerProtocolException protocolException)
            {
                throw protocolException;
            }

            throw new CodexCdpBrokerProtocolException(
                "frame-overflow",
                "The broker frame length overflowed the bounded decoder.",
                exception);
        }
    }

    internal void Complete()
    {
        lock (_sync)
        {
            if (_faulted)
            {
                throw new CodexCdpBrokerProtocolException(
                    "decoder-faulted",
                    "The broker decoder is already in a terminal failed state.");
            }

            if (_completed)
            {
                return;
            }

            if (_headerBytes != 0 || _expectedPayloadBytes >= 0)
            {
                _faulted = true;
                ResetFrame();
                throw new CodexCdpBrokerProtocolException(
                    "truncated-frame",
                    "The broker stream ended in the middle of a frame.");
            }

            _completed = true;
        }
    }

    private void ResetFrame()
    {
        Array.Clear(_header);
        _headerBytes = 0;
        _payload = null;
        _payloadBytes = 0;
        _expectedPayloadBytes = -1;
    }
}

internal sealed class CodexCdpBrokerSubscriptionQueue
{
    internal const int MaximumCapacity = 1024;

    private readonly object _gate = new();
    private readonly string _brokerEpoch;
    private readonly int _capacity;
    private readonly Queue<CodexCdpBrokerNotification> _items = new();
    private long _latestSequence;
    private bool _requiresResync;

    internal CodexCdpBrokerSubscriptionQueue(string brokerEpoch, int capacity)
    {
        if (!CodexCdpBrokerProtocol.IsControlIdentifier(brokerEpoch))
        {
            throw new ArgumentException("A valid broker epoch is required.", nameof(brokerEpoch));
        }

        if (capacity is < 1 or > MaximumCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        _brokerEpoch = brokerEpoch;
        _capacity = capacity;
    }

    internal int Count
    {
        get
        {
            lock (_gate)
            {
                return _items.Count;
            }
        }
    }

    internal bool RequiresResync
    {
        get
        {
            lock (_gate)
            {
                return _requiresResync;
            }
        }
    }

    internal long LatestSequence
    {
        get
        {
            lock (_gate)
            {
                return _latestSequence;
            }
        }
    }

    internal bool BeginSubscription(
        long afterSequence,
        CodexCdpBrokerSnapshot currentSnapshot)
    {
        ArgumentNullException.ThrowIfNull(currentSnapshot);
        lock (_gate)
        {
            if (!string.Equals(
                    currentSnapshot.BrokerEpoch,
                    _brokerEpoch,
                    StringComparison.Ordinal) ||
                afterSequence < 0 ||
                afterSequence > currentSnapshot.Sequence)
            {
                throw new InvalidOperationException(
                    "A subscription requires a same-epoch bounded sequence.");
            }

            _items.Clear();
            _latestSequence = currentSnapshot.Sequence;
            _requiresResync = afterSequence < currentSnapshot.Sequence;
            if (_requiresResync)
            {
                ReplaceWithResyncSignal();
            }

            return !_requiresResync;
        }
    }

    internal bool RequireResync(CodexCdpBrokerSnapshot currentSnapshot)
    {
        ArgumentNullException.ThrowIfNull(currentSnapshot);
        lock (_gate)
        {
            if (!string.Equals(
                    currentSnapshot.BrokerEpoch,
                    _brokerEpoch,
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "A resync signal requires the exact broker epoch.");
            }

            if (currentSnapshot.Sequence < _latestSequence)
            {
                return false;
            }

            _latestSequence = currentSnapshot.Sequence;
            _requiresResync = true;
            ReplaceWithResyncSignal();
            return true;
        }
    }

    internal bool Enqueue(CodexCdpBrokerSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        lock (_gate)
        {
            if (!string.Equals(snapshot.BrokerEpoch, _brokerEpoch, StringComparison.Ordinal) ||
                snapshot.Sequence <= _latestSequence)
            {
                throw new InvalidOperationException(
                    "Subscription updates must be same-epoch and strictly monotonic.");
            }

            _latestSequence = snapshot.Sequence;
            if (_requiresResync || _items.Count >= _capacity)
            {
                _requiresResync = true;
                ReplaceWithResyncSignal();
                return false;
            }

            _items.Enqueue(new CodexCdpBrokerNotification(
                CodexCdpBrokerNotificationKind.StateChanged,
                _brokerEpoch,
                snapshot.Sequence,
                snapshot));
            return true;
        }
    }

    internal IReadOnlyList<CodexCdpBrokerNotification> Drain(int maximumItems)
    {
        if (maximumItems is < 1 or > MaximumCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumItems));
        }

        lock (_gate)
        {
            var count = Math.Min(maximumItems, _items.Count);
            var drained = new CodexCdpBrokerNotification[count];
            for (var index = 0; index < count; index++)
            {
                drained[index] = _items.Dequeue();
            }

            return drained;
        }
    }

    internal bool AcknowledgeFullSnapshot(CodexCdpBrokerSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        lock (_gate)
        {
            if (!_requiresResync ||
                !string.Equals(snapshot.BrokerEpoch, _brokerEpoch, StringComparison.Ordinal) ||
                snapshot.Sequence < _latestSequence)
            {
                return false;
            }

            _items.Clear();
            _requiresResync = false;
            _latestSequence = snapshot.Sequence;
            return true;
        }
    }

    private void ReplaceWithResyncSignal()
    {
        _items.Clear();
        _items.Enqueue(new CodexCdpBrokerNotification(
            CodexCdpBrokerNotificationKind.ResyncRequired,
            _brokerEpoch,
            _latestSequence,
            null));
    }
}

internal sealed class CodexCdpBrokerProtocolException : IOException
{
    internal CodexCdpBrokerProtocolException(
        string code,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}
