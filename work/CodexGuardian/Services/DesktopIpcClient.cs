using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using CodexGuardian.Models;
using Microsoft.Win32.SafeHandles;

namespace CodexGuardian.Services;

public sealed class DesktopIpcClient : IAsyncDisposable, IDesktopThreadOwnerProbe
{
    internal const string PipeName = "codex-ipc";
    internal const int MaximumAcceptedFrameBytes = 16 * 1024 * 1024;
    internal const string NativeStartTurnMethod = "thread-follower-start-turn";
    internal const int NativeStartTurnVersion = 2;
    internal const int LegacyNativeStartTurnVersion = 1;
    internal const string NativeEditLastUserTurnMethod = "thread-follower-edit-last-user-turn";
    internal const int NativeEditLastUserTurnVersion = 2;
    internal const string NativeThreadFollowingMethod = "thread-stream-following-changed";
    internal const int NativeThreadFollowingVersion = 1;
    internal const string NativeThreadStateMethod = "thread-stream-state-changed";
    internal const int NativeThreadStateVersion = 11;
    private const int MaximumOriginalMessageBytes = 1024 * 1024;

    private const string ExpectedPackageFamilyName = "OpenAI.Codex_2p2nqsd0c76g0";
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUserInformationClass = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorSuccess = 0;
    private const int MaximumWindowsPathCharacters = 32768;

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan InitializeTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan NativeChannelProbeTimeout = TimeSpan.FromSeconds(7);
    private static readonly TimeSpan StartTurnTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan OwnerHostDiscoveryTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan OwnerSnapshotTimeout = TimeSpan.FromSeconds(8);

    private readonly GuardianLog _log;
    private readonly IDesktopStructuredInputEncoder _structuredInputEncoder;
    private readonly SemaphoreSlim _connectGate = new(1, 1);
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonElement>> _pending =
        new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _ownerHostIds =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _knownOwnerHostIds =
        new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _lifetime = new();
    private NamedPipeClientStream? _pipe;
    private Task? _receiveTask;
    private string? _clientId;
    private int _publishedConnectionState;
    private int _disposed;

    public DesktopIpcClient(GuardianLog log)
        : this(log, new DesktopStructuredInputEncoder())
    {
    }

    internal DesktopIpcClient(
        GuardianLog log,
        IDesktopStructuredInputEncoder structuredInputEncoder)
    {
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _structuredInputEncoder = structuredInputEncoder ??
                                  throw new ArgumentNullException(nameof(structuredInputEncoder));
    }

    public bool IsConnected =>
        _pipe is { IsConnected: true } && !string.IsNullOrWhiteSpace(_clientId);

    public bool IsNativeChannelAvailable { get; private set; }

    // Resend recovery runs through the owner's edit-last-user-turn contract, which rolls the failed
    // turn back and resubmits the same input in place instead of appending a duplicate successor.
    // SendContinue still appends, because a continue message is new input by definition.
    public bool SupportsAtomicRecoveryPrecondition =>
        GetRecoveryTransportCapabilities(RecoveryActionKind.SendContinue).IsStrictAtomicRecoveryEligible;

    public bool SupportsGuardedAutomaticRecovery =>
        GetRecoveryTransportCapabilities(RecoveryActionKind.SendContinue).IsGuardedAutomaticRecoveryEligible;

    public RecoveryTransportCapabilities GetRecoveryTransportCapabilities(RecoveryActionKind action) =>
        DescribeStockRecoveryCapabilities(action);

    public RecoveryTransportCapabilities GetRecoveryTransportCapabilities(
        RecoveryActionKind action,
        bool provenUnsentOriginalReplay) =>
        provenUnsentOriginalReplay && action == RecoveryActionKind.ResendOriginal
            ? DescribeStockRecoveryCapabilities(action) with
            {
                // A provider's explicit 429 before any turn work proves the request was rejected
                // before execution. In-place retry no longer needs that proof to be safe, but the
                // flag still records why this failure is eligible for an unchanged resubmission.
                SupportsProvenUnsentReplay = true
            }
            : DescribeStockRecoveryCapabilities(action);

    internal static RecoveryTransportCapabilities DescribeStockRecoveryCapabilities(RecoveryActionKind action) =>
        action switch
        {
            // Live probe evidence (2026-08-30, thread 01a00ee0-2185-7fb1-9503-bb65ce0a1389): the
            // owner answers "Turn not found for edit." for any turn id that is not the current last
            // user turn, and {"ok":true} for the exact failed turn. The accepted edit rolls the
            // thread back by one turn and resubmits the same input, so the transcript keeps a single
            // user message instead of gaining a duplicate.
            RecoveryActionKind.ResendOriginal => new RecoveryTransportCapabilities(
                action,
                SupportsExpectedFailedTurnCompareAndStart: true,
                SupportsExpectedFailedTurnOwnerValidation: true,
                SupportsReceiverIdempotency: true,
                // The edit contract carries plain text only. Attachment-bearing turns must be
                // refused by the caller rather than resent with their attachments dropped.
                PreservesStructuredOriginalInput: true,
                // The owner acknowledges with {"ok":true} and no turn id; the successor turn id is
                // read back from observed task state.
                ReturnsCommittedTurnId: false,
                ExecutesThroughDesktopOwner: true,
                IsTrustedDesktopProtocol: true,
                SupportsNativeResend: true,
                SupportsProvenUnsentReplay: false,
                SupportsNativeInPlaceRetry: true),
            RecoveryActionKind.ResendContinue => new RecoveryTransportCapabilities(
                action,
                SupportsExpectedFailedTurnCompareAndStart: true,
                SupportsExpectedFailedTurnOwnerValidation: true,
                SupportsReceiverIdempotency: true,
                PreservesStructuredOriginalInput: true,
                ReturnsCommittedTurnId: false,
                ExecutesThroughDesktopOwner: true,
                IsTrustedDesktopProtocol: true,
                SupportsNativeResend: true,
                SupportsProvenUnsentReplay: false,
                SupportsNativeInPlaceRetry: true),
            RecoveryActionKind.SendContinue => new RecoveryTransportCapabilities(
                action,
                SupportsExpectedFailedTurnCompareAndStart: false,
                SupportsExpectedFailedTurnOwnerValidation: false,
                SupportsReceiverIdempotency: false,
                PreservesStructuredOriginalInput: false,
                ReturnsCommittedTurnId: true,
                ExecutesThroughDesktopOwner: true,
                IsTrustedDesktopProtocol: true),
            _ => RecoveryTransportCapabilities.Unavailable(action)
        };

    public event EventHandler<bool>? ConnectionChanged;

    // A probe can turn the native channel from unavailable to available while the IPC connection itself
    // never changes, so ConnectionChanged cannot carry this: its transition guard has already published
    // "connected" and will not fire again. Recovery treats an unproven channel as a wait, and this is the
    // signal that ends that wait.
    public event EventHandler<EventArgs>? NativeChannelBecameAvailable;

    public event EventHandler<DesktopIpcActivityEventArgs>? ActivityReceived;

    public async Task EnsureConnectedAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (IsConnected)
        {
            return;
        }

        await _connectGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsConnected)
            {
                return;
            }

            await ResetConnectionAsync().ConfigureAwait(false);
            PublishConnectionTransition(connected: false);
            var pipe = new NamedPipeClientStream(
                ".",
                PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
                timeout.CancelAfter(ConnectTimeout);
                await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
                pipe.ReadMode = PipeTransmissionMode.Byte;
                ValidateServerIdentity(pipe);
                _pipe = pipe;
                _receiveTask = ReceiveLoopAsync(pipe, _lifetime.Token);

                var initializeResponse = await SendRequestCoreAsync(
                    method: "initialize",
                    parameters: new { clientType = "codex-guardian" },
                    sourceClientId: "initializing-client",
                    version: 0,
                    timeout: InitializeTimeout,
                    cancellationToken).ConfigureAwait(false);
                if (!initializeResponse.TryGetProperty("clientId", out var clientIdElement) ||
                    clientIdElement.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(clientIdElement.GetString()))
                {
                    throw new DesktopIpcProtocolException(
                        "invalid-initialize-response",
                        "Codex Desktop did not return an IPC client id.");
                }

                _clientId = clientIdElement.GetString();
                await ProbeNativeDesktopChannelCoreAsync(cancellationToken).ConfigureAwait(false);
                PublishConnectionTransition(connected: true);
                if (IsNativeChannelAvailable)
                {
                    _log.Success("Connected to the native Codex Desktop task channel.");
                }
                else
                {
                    _log.Warning(
                        "Connected to Codex Desktop, but its native task channel is not compatible.");
                }
            }
            catch
            {
                if (ReferenceEquals(_pipe, pipe))
                {
                    await ResetConnectionAsync().ConfigureAwait(false);
                }
                else
                {
                    pipe.Dispose();
                }

                PublishConnectionTransition(connected: false);
                throw;
            }
        }
        finally
        {
            _connectGate.Release();
        }
    }

    // Retries the failed turn in place through the owner's edit-last-user-turn contract. The owner
    // rolls the thread back by one turn and resubmits the same input, so the transcript keeps a
    // single user message instead of gaining a duplicate successor. The expected turn id acts as a
    // compare-and-swap: the owner rejects the request when that turn is no longer the last one.
    public async Task<DesktopInPlaceRetryResult> RetryFailedTurnInPlaceAsync(
        string conversationId,
        string expectedFailedTurnId,
        string originalMessage,
        bool originalHasAttachments,
        CancellationToken cancellationToken = default,
        Func<bool>? canStartWrite = null)
    {
        if (!Guid.TryParse(conversationId, out _))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(conversationId));
        }

        if (!Guid.TryParse(expectedFailedTurnId, out _))
        {
            throw new ArgumentException(
                "The expected failed turn id is required for an in-place retry.",
                nameof(expectedFailedTurnId));
        }

        // The edit contract carries plain text only. Resending an attachment-bearing turn through it
        // would silently drop the attachments, and appending a duplicate successor instead is exactly
        // the behaviour in-place retry exists to remove, so refuse both.
        if (originalHasAttachments)
        {
            throw new DesktopIpcProtocolException(
                "guardian-attachment-retry-unsupported",
                "Codex Desktop's in-place retry contract cannot carry attachments, and Guardian will not append a duplicate message instead.",
                DesktopIpcDeliveryStage.NotDispatched);
        }

        if (string.IsNullOrEmpty(originalMessage))
        {
            throw new DesktopIpcProtocolException(
                "guardian-original-input-unavailable",
                "The original user text for the failed turn is unavailable, so it cannot be retried in place.",
                DesktopIpcDeliveryStage.NotDispatched);
        }

        if (Encoding.UTF8.GetByteCount(originalMessage) > MaximumOriginalMessageBytes)
        {
            throw new DesktopIpcProtocolException(
                "guardian-invalid-request",
                "The original user text exceeds the Desktop channel limit for an in-place retry.",
                DesktopIpcDeliveryStage.NotDispatched);
        }

        await EnsureRecoveryChannelReadyAsync(cancellationToken).ConfigureAwait(false);
        return await SendInPlaceRetryAsync(
                conversationId,
                expectedFailedTurnId,
                originalMessage,
                cancellationToken,
                canStartWrite)
            .ConfigureAwait(false);
    }

    public async Task<DesktopStartTurnResult> AppendRecoverySuccessorAsync(
        string conversationId,
        RecoveryActionKind action,
        string? rawOriginalInputJson,
        string? originalMessage,
        bool originalHasAttachments,
        string continueMessage,
        string clientUserMessageId,
        CancellationToken cancellationToken = default,
        Func<bool>? canStartWrite = null,
        bool provenUnsentOriginalReplay = false)
    {
        if (!Guid.TryParse(conversationId, out _))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(conversationId));
        }

        // Resend recovery runs through RetryFailedTurnInPlaceAsync. Appending a duplicate of the
        // failed message is exactly the behaviour that was removed, so this entry point only carries
        // genuinely new input.
        if (action != RecoveryActionKind.SendContinue)
        {
            throw new DesktopIpcProtocolException(
                "native-append-not-applicable",
                "Codex Desktop resend recovery runs through the in-place retry contract; Guardian does not append a duplicate of the failed message.",
                DesktopIpcDeliveryStage.NotDispatched);
        }

        var normalizedContinueMessage = SettingsService.NormalizeContinueMessage(continueMessage);
        if (normalizedContinueMessage.Length > 4096)
        {
            throw new ArgumentException("The continue message exceeds the Desktop channel limit.", nameof(continueMessage));
        }

        if (!Guid.TryParse(clientUserMessageId, out _))
        {
            throw new ArgumentException("A stable UUID client message id is required.", nameof(clientUserMessageId));
        }

        await EnsureRecoveryChannelReadyAsync(cancellationToken).ConfigureAwait(false);

        var input = BuildNativeRecoveryInput(
            action,
            rawOriginalInputJson,
            originalMessage,
            originalHasAttachments,
            normalizedContinueMessage);

        var response = await SendNativeStartTurnCompatibleAsync(
                conversationId,
                input,
                clientUserMessageId,
                cancellationToken,
                canStartWrite)
            .ConfigureAwait(false);

        if (!TryReadTurnId(response, out var turnId))
        {
            throw new DesktopIpcProtocolException(
                "missing-turn-id",
                "Codex Desktop accepted the request but did not return a new turn id.",
                DesktopIpcDeliveryStage.Acknowledged);
        }

        return new DesktopStartTurnResult(turnId);
    }

    private async Task EnsureRecoveryChannelReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            throw new DesktopIpcDeliveryException(
                DesktopIpcDeliveryStage.NotDispatched,
                "Codex Desktop connection was cancelled before the recovery request was dispatched.",
                exception);
        }
        catch (DesktopIpcProtocolException exception)
        {
            throw new DesktopIpcProtocolException(
                exception.Code,
                exception.Message,
                DesktopIpcDeliveryStage.NotDispatched);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException)
        {
            throw new DesktopIpcDeliveryException(
                DesktopIpcDeliveryStage.NotDispatched,
                "Codex Desktop was unavailable before the recovery request was dispatched.",
                exception);
        }

        if (!IsNativeChannelAvailable)
        {
            throw new DesktopIpcProtocolException(
                "native-channel-unavailable",
                "Codex Desktop has not proved the native recovery channel.",
                DesktopIpcDeliveryStage.NotDispatched);
        }
    }

    // Dispatches the owner's edit-last-user-turn request for the failed turn. Cancellation is
    // classified for recovery so a cancelled in-place retry reports NotDispatched or
    // DispatchedUnknown instead of a raw cancellation the ledger cannot reconcile.
    private async Task<DesktopInPlaceRetryResult> SendInPlaceRetryAsync(
        string conversationId,
        string expectedFailedTurnId,
        string originalMessage,
        CancellationToken cancellationToken,
        Func<bool>? canStartWrite)
    {
        JsonElement response;
        try
        {
            response = await SendRequestCoreAsync(
                    method: NativeEditLastUserTurnMethod,
                    parameters: new
                    {
                        conversationId,
                        turnId = expectedFailedTurnId,
                        message = originalMessage,
                        agentMode = (string?)null,
                        shouldSendPermissionOverrides = false,
                        serviceTier = (string?)null
                    },
                    sourceClientId: _clientId!,
                    version: NativeEditLastUserTurnVersion,
                    timeout: StartTurnTimeout,
                    cancellationToken,
                    classifyCancellationForRecovery: true,
                    canStartWrite: canStartWrite)
                .ConfigureAwait(false);
        }
        catch (DesktopIpcProtocolException exception) when (IsInPlaceRetryTurnSuperseded(exception.Code))
        {
            // The owner resolves the edit against the current last user turn, so this answer proves
            // the expected turn is no longer last and that nothing was submitted.
            throw new DesktopIpcProtocolException(
                "guardian-state-changed",
                "The failed turn is no longer the last user turn, so Codex Desktop refused the in-place retry and nothing was resent.",
                DesktopIpcDeliveryStage.NotDispatched);
        }

        if (!TryReadInPlaceRetryAcknowledgement(response))
        {
            throw new DesktopIpcProtocolException(
                "native-edit-rejected",
                "Codex Desktop answered the in-place retry without confirming it.",
                DesktopIpcDeliveryStage.DispatchedUnknown);
        }

        return new DesktopInPlaceRetryResult(true);
    }

    // The owner reports a stale expected turn as a plain-text error rather than a stable code, so the
    // text is matched here and translated into Guardian's state-changed contract.
    internal static bool IsInPlaceRetryTurnSuperseded(string code) =>
        !string.IsNullOrEmpty(code) &&
        code.Contains("Turn not found", StringComparison.OrdinalIgnoreCase);

    private static bool TryReadInPlaceRetryAcknowledgement(JsonElement response)
    {
        if (response.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (response.TryGetProperty("ok", out var ok))
        {
            return ok.ValueKind == JsonValueKind.True;
        }

        // Tolerate a future response shape that nests the acknowledgement or returns a turn id.
        return (response.TryGetProperty("result", out var nested) &&
                TryReadInPlaceRetryAcknowledgement(nested)) ||
               TryReadTurnId(response, out _);
    }

    internal async Task<DesktopStartTurnResult> StartTextTurnAsync(
        string conversationId,
        string message,
        string clientUserMessageId,
        CancellationToken cancellationToken = default,
        Func<bool>? canStartWrite = null)
    {
        if (!Guid.TryParse(conversationId, out _))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(conversationId));
        }

        var normalizedMessage = SettingsService.NormalizeFollowUpMessage(message);
        if (normalizedMessage.Length == 0)
        {
            throw new ArgumentException("A non-empty follow-up message is required.", nameof(message));
        }

        if (!Guid.TryParse(clientUserMessageId, out _))
        {
            throw new ArgumentException("A stable UUID client message id is required.", nameof(clientUserMessageId));
        }

        try
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            throw new DesktopIpcDeliveryException(
                DesktopIpcDeliveryStage.NotDispatched,
                "Codex Desktop connection was cancelled before the follow-up request was dispatched.",
                exception);
        }
        catch (DesktopIpcProtocolException exception)
        {
            throw new DesktopIpcProtocolException(
                exception.Code,
                exception.Message,
                DesktopIpcDeliveryStage.NotDispatched);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException)
        {
            throw new DesktopIpcDeliveryException(
                DesktopIpcDeliveryStage.NotDispatched,
                "Codex Desktop was unavailable before the follow-up request was dispatched.",
                exception);
        }

        var response = await SendNativeStartTurnCompatibleAsync(
                conversationId,
                BuildNativeContinueInput(normalizedMessage),
                clientUserMessageId,
                cancellationToken,
                canStartWrite)
            .ConfigureAwait(false);

        if (!TryReadTurnId(response, out var turnId))
        {
            throw new DesktopIpcProtocolException(
                "missing-turn-id",
                "Codex Desktop accepted the follow-up but did not return a new turn id.",
                DesktopIpcDeliveryStage.Acknowledged);
        }

        return new DesktopStartTurnResult(turnId);
    }

    internal static JsonElement BuildNativeRecoveryInput(
        RecoveryActionKind action,
        string? rawOriginalInputJson,
        string? originalMessage,
        bool originalHasAttachments,
        string normalizedContinueMessage) =>
        action is RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue
            ? BuildNativeOriginalInput(rawOriginalInputJson, originalMessage, originalHasAttachments)
            : BuildNativeContinueInput(normalizedContinueMessage);

    internal static JsonElement BuildNativeContinueInput(string normalizedContinueMessage)
    {
        return JsonSerializer.SerializeToElement(new[]
        {
            new
            {
                type = "text",
                text = normalizedContinueMessage,
                text_elements = Array.Empty<object>()
            }
        });
    }

    internal static bool IsStockOriginalMessageAvailable(string? originalMessage) =>
        !string.IsNullOrWhiteSpace(originalMessage) &&
        Encoding.UTF8.GetByteCount(originalMessage) <= MaximumOriginalMessageBytes;

    internal static JsonElement BuildNativeOriginalInput(
        string? rawOriginalInputJson,
        string? originalMessage,
        bool originalHasAttachments)
    {
        if (originalHasAttachments)
        {
            try
            {
                var canonical = RecoveryStructuredInputCanonicalizer.Parse(rawOriginalInputJson);
                using var canonicalDocument = JsonDocument.Parse(canonical.CanonicalJson);
                return canonicalDocument.RootElement.Clone();
            }
            catch (RecoveryStructuredInputReplayException)
            {
                throw new DesktopIpcProtocolException(
                    "guardian-original-input-unavailable",
                    "The original structured attachment input is unavailable or invalid.");
            }
        }

        // Text-only recovery is a fixed stock Desktop input shape. Never pass through a raw
        // structured array when the failed turn has no attachment authority.
        if (IsStockOriginalMessageAvailable(originalMessage))
        {
            return BuildNativeContinueInput(originalMessage!);
        }

        throw new DesktopIpcProtocolException(
            "guardian-original-input-unavailable",
            "The original structured input is unavailable or invalid.");
    }

    internal JsonElement EncodeStructuredTurnInput(
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        DesktopStructuredInputCapabilityLease capabilityLease,
        IReadOnlyDictionary<string, string> presentationPaths)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(capabilityLease);
        ArgumentNullException.ThrowIfNull(presentationPaths);
        if (!capabilities.Matches(capabilityLease, payload))
        {
            throw new DesktopStructuredInputCapabilityException(
                "capability-lease-stale",
                "The Desktop structured-input capability lease is no longer current.");
        }

        var input = _structuredInputEncoder.Encode(payload, capabilities, presentationPaths);
        if (input.ValueKind != JsonValueKind.Array || input.GetArrayLength() == 0)
        {
            throw new DesktopIpcProtocolException(
                "structured-input-invalid",
                "The Desktop structured-input encoder returned an invalid native input array.");
        }

        return input;
    }

    internal async Task<DesktopStartTurnResult> StartStructuredTurnAsync(
        string conversationId,
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        DesktopStructuredInputCapabilityLease capabilityLease,
        IReadOnlyDictionary<string, string> presentationPaths,
        string clientUserMessageId,
        CancellationToken cancellationToken = default,
        Func<bool>? canStartWrite = null)
    {
        if (!Guid.TryParse(conversationId, out _))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(conversationId));
        }

        if (!Guid.TryParse(clientUserMessageId, out _))
        {
            throw new ArgumentException(
                "A stable UUID client message id is required.",
                nameof(clientUserMessageId));
        }

        var input = EncodeStructuredTurnInput(
            payload,
            capabilities,
            capabilityLease,
            presentationPaths);
        try
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            throw new DesktopIpcDeliveryException(
                DesktopIpcDeliveryStage.NotDispatched,
                "Codex Desktop connection was cancelled before the structured follow-up was dispatched.",
                exception);
        }
        catch (DesktopIpcProtocolException exception)
        {
            throw new DesktopIpcProtocolException(
                exception.Code,
                exception.Message,
                DesktopIpcDeliveryStage.NotDispatched);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException)
        {
            throw new DesktopIpcDeliveryException(
                DesktopIpcDeliveryStage.NotDispatched,
                "Codex Desktop was unavailable before the structured follow-up was dispatched.",
                exception);
        }

        bool IsStructuredWriteCurrent() =>
            capabilities.Matches(capabilityLease, payload) &&
            IsWritePreconditionSatisfied(canStartWrite);

        var response = await SendNativeStartTurnCompatibleAsync(
                conversationId,
                input,
                clientUserMessageId,
                cancellationToken,
                IsStructuredWriteCurrent)
            .ConfigureAwait(false);

        if (!TryReadTurnId(response, out var turnId))
        {
            throw new DesktopIpcProtocolException(
                "missing-turn-id",
                "Codex Desktop accepted the structured follow-up but did not return a new turn id.",
                DesktopIpcDeliveryStage.Acknowledged);
        }

        return new DesktopStartTurnResult(turnId);
    }

    public async Task<bool> ProbeNativeDesktopChannelAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!IsConnected)
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            return IsNativeChannelAvailable;
        }

        var reconnectRequired = false;
        await _connectGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsConnected)
            {
                reconnectRequired = true;
            }
            else
            {
                await ProbeNativeDesktopChannelCoreAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _connectGate.Release();
        }

        if (reconnectRequired)
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
        }

        return IsNativeChannelAvailable;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetime.Cancel();
        await _connectGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await ResetConnectionAsync().ConfigureAwait(false);
        }
        finally
        {
            _connectGate.Release();
        }

        _connectGate.Dispose();
        _writeGate.Dispose();
        _lifetime.Dispose();
    }

    internal static byte[] EncodeFrame(JsonElement message) =>
        EncodeFrame(Encoding.UTF8.GetBytes(message.GetRawText()));

    internal static byte[] EncodeFrame(ReadOnlySpan<byte> payload)
    {
        if (payload.Length is <= 0 or > MaximumAcceptedFrameBytes)
        {
            throw new InvalidDataException("The IPC frame size is outside the accepted range.");
        }

        var frame = new byte[sizeof(uint) + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, checked((uint)payload.Length));
        payload.CopyTo(frame.AsSpan(sizeof(uint)));
        return frame;
    }

    internal static int DecodeFrameLength(ReadOnlySpan<byte> header)
    {
        if (header.Length != sizeof(uint))
        {
            throw new InvalidDataException("The IPC frame header is incomplete.");
        }

        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length is 0 or > MaximumAcceptedFrameBytes)
        {
            throw new InvalidDataException("The IPC frame size is outside the accepted range.");
        }

        return checked((int)length);
    }

    internal static bool TryReadTurnId(JsonElement result, out string turnId)
    {
        turnId = string.Empty;
        var current = result;
        for (var depth = 0; depth < 4 && current.ValueKind == JsonValueKind.Object; depth++)
        {
            if (current.TryGetProperty("turn", out var turn) &&
                turn.ValueKind == JsonValueKind.Object &&
                turn.TryGetProperty("id", out var id) &&
                id.ValueKind == JsonValueKind.String &&
                id.GetString() is { Length: > 0 } value)
            {
                turnId = value;
                return true;
            }

            if (!current.TryGetProperty("result", out var nested))
            {
                break;
            }

            current = nested;
        }

        return false;
    }

    internal static JsonElement BuildNativeStartTurnParameters(
        int version,
        string conversationId,
        JsonElement input,
        string clientUserMessageId) =>
        version switch
        {
            NativeStartTurnVersion => JsonSerializer.SerializeToElement(new
            {
                conversationId,
                turnStart = new
                {
                    request = new
                    {
                        threadId = conversationId,
                        input,
                        clientUserMessageId
                    },
                    context = new
                    {
                        inheritThreadSettings = true
                    }
                }
            }),
            LegacyNativeStartTurnVersion => JsonSerializer.SerializeToElement(new
            {
                conversationId,
                turnStartParams = new
                {
                    input,
                    clientUserMessageId
                }
            }),
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };

    internal static bool ShouldFallbackNativeStartTurn(DesktopIpcProtocolException exception) =>
        string.Equals(exception.Code, "request-version-mismatch", StringComparison.Ordinal) &&
        exception.Stage == DesktopIpcDeliveryStage.Rejected;

    private async Task<JsonElement> SendNativeStartTurnCompatibleAsync(
        string conversationId,
        JsonElement input,
        string clientUserMessageId,
        CancellationToken cancellationToken,
        Func<bool>? canStartWrite)
    {
        try
        {
            return await SendRequestCoreAsync(
                    method: NativeStartTurnMethod,
                    parameters: BuildNativeStartTurnParameters(
                        NativeStartTurnVersion,
                        conversationId,
                        input,
                        clientUserMessageId),
                    sourceClientId: _clientId!,
                    version: NativeStartTurnVersion,
                    timeout: StartTurnTimeout,
                    cancellationToken,
                    classifyCancellationForRecovery: true,
                    canStartWrite: canStartWrite)
                .ConfigureAwait(false);
        }
        catch (DesktopIpcProtocolException exception) when (ShouldFallbackNativeStartTurn(exception))
        {
            return await SendRequestCoreAsync(
                    method: NativeStartTurnMethod,
                    parameters: BuildNativeStartTurnParameters(
                        LegacyNativeStartTurnVersion,
                        conversationId,
                        input,
                        clientUserMessageId),
                    sourceClientId: _clientId!,
                    version: LegacyNativeStartTurnVersion,
                    timeout: StartTurnTimeout,
                    cancellationToken,
                    classifyCancellationForRecovery: true,
                    canStartWrite: canStartWrite)
                .ConfigureAwait(false);
        }
    }

    private async Task ProbeNativeDesktopChannelCoreAsync(CancellationToken cancellationToken)
    {
        IsNativeChannelAvailable = false;
        var conversationId = Guid.NewGuid().ToString("D");
        var turnId = Guid.NewGuid().ToString("D");
        var clientUserMessageId = Guid.NewGuid().ToString("D");
        var startParameters = BuildNativeStartTurnParameters(
            NativeStartTurnVersion,
            conversationId,
            BuildNativeContinueInput("continue"),
            clientUserMessageId);
        var editParameters = new
        {
            conversationId,
            turnId,
            message = "Codex Guardian native channel probe",
            agentMode = (string?)null,
            shouldSendPermissionOverrides = false,
            serviceTier = (string?)null
        };

        var startAvailable = await RequestFailsWithExpectedCodesAsync(
                NativeStartTurnMethod,
                startParameters,
                NativeStartTurnVersion,
                new[] { "no-client-found", "request-version-mismatch" },
                cancellationToken)
            .ConfigureAwait(false);
        var editAvailable = await RequestFailsWithExpectedCodeAsync(
                NativeEditLastUserTurnMethod,
                editParameters,
                NativeEditLastUserTurnVersion,
                "no-client-found",
                cancellationToken)
            .ConfigureAwait(false);
        // The broker discovers an owner before the renderer validates versions, so a fake task can
        // safely prove routing but may return no-client-found even for an intentionally wrong version.
        var versionGuardResult = await RequestFailsWithExpectedCodesAsync(
                NativeStartTurnMethod,
                startParameters,
                int.MaxValue,
                new[] { "request-version-mismatch", "no-client-found" },
                cancellationToken)
            .ConfigureAwait(false);

        var wasAvailable = IsNativeChannelAvailable;
        IsNativeChannelAvailable = startAvailable && editAvailable && versionGuardResult;
        _log.Trace(
            $"Codex Desktop stock native channel probe: start={startAvailable}, edit={editAvailable}, versionGuard={versionGuardResult}.");
        if (!wasAvailable && IsNativeChannelAvailable)
        {
            EventSubscriberDispatcher.Invoke(
                NativeChannelBecameAvailable,
                this,
                EventArgs.Empty,
                exception => _log.Trace(
                    "A native channel availability subscriber failed (" + exception.GetType().Name + ")."));
        }
    }

    public async Task<DesktopThreadOwnerProbeResult> ProbeThreadOwnerAsync(
        string conversationId,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(conversationId, out _))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(conversationId));
        }

        try
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            await SendRequestCoreAsync(
                    NativeEditLastUserTurnMethod,
                    new
                    {
                        conversationId,
                        turnId = Guid.NewGuid().ToString("D"),
                        message = "Codex Guardian owner probe",
                        agentMode = (string?)null,
                        shouldSendPermissionOverrides = false,
                        serviceTier = (string?)null
                    },
                    _clientId!,
                    NativeEditLastUserTurnVersion,
                    NativeChannelProbeTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            return new DesktopThreadOwnerProbeResult(
                DesktopThreadOwnerProbeStatus.Available,
                "The owner handled the non-mutating random-turn probe.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (DesktopIpcProtocolException exception)
        {
            return exception.Code switch
            {
                "no-client-found" => new DesktopThreadOwnerProbeResult(
                    DesktopThreadOwnerProbeStatus.Unavailable,
                    "No Codex Desktop renderer currently owns the task."),
                "request-version-mismatch" or "no-handler-for-request" =>
                    new DesktopThreadOwnerProbeResult(
                        DesktopThreadOwnerProbeStatus.Incompatible,
                        FormatProtocolError(exception.Code)),
                "request-timeout" or "client-disconnected" or "server-closed" =>
                    new DesktopThreadOwnerProbeResult(
                        DesktopThreadOwnerProbeStatus.TransientFailure,
                        FormatProtocolError(exception.Code)),
                _ => new DesktopThreadOwnerProbeResult(
                    DesktopThreadOwnerProbeStatus.Available,
                    "The owner rejected the intentionally nonexistent turn: " + exception.Code)
            };
        }
        catch (Exception exception) when (
            exception is IOException or TimeoutException or DesktopIpcServerValidationException)
        {
            return new DesktopThreadOwnerProbeResult(
                exception is DesktopIpcServerValidationException
                    ? DesktopThreadOwnerProbeStatus.Incompatible
                    : DesktopThreadOwnerProbeStatus.TransientFailure,
                exception.Message);
        }
    }

    internal async Task SetThreadFollowingAsync(
        string conversationId,
        string hostId,
        bool following,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(conversationId, out _))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(conversationId));
        }

        if (string.IsNullOrWhiteSpace(hostId) || hostId.Length > 1024)
        {
            throw new ArgumentException("A bounded Desktop host id is required.", nameof(hostId));
        }

        await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
        var pipe = _pipe;
        if (pipe is not { IsConnected: true })
        {
            throw new IOException("The Codex Desktop IPC connection is not open.");
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "broadcast",
            method = NativeThreadFollowingMethod,
            sourceClientId = _clientId!,
            @params = new
            {
                conversationId,
                hostId,
                following
            },
            version = NativeThreadFollowingVersion
        });
        await WriteFrameAsync(pipe, payload, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<DesktopThreadOwnerStateGuardAcquireResult> AcquireThreadOwnerStateGuardAsync(
        string conversationId,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(conversationId, out _))
        {
            throw new ArgumentException("A conversation UUID is required.", nameof(conversationId));
        }

        try
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var hostId = await WaitForOwnerHostIdAsync(conversationId, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(hostId))
            {
                return new DesktopThreadOwnerStateGuardAcquireResult(
                    DesktopThreadOwnerStateGuardStatus.Unavailable,
                    null,
                    "Codex Desktop did not identify the target task owner host.");
            }

            return await DesktopThreadOwnerStateGuard.AcquireAsync(
                    this,
                    conversationId,
                    hostId,
                    OwnerSnapshotTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (DesktopIpcServerValidationException exception)
        {
            return new DesktopThreadOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Incompatible,
                null,
                exception.Message);
        }
        catch (DesktopIpcProtocolException exception)
        {
            var incompatible = exception.Code is "request-version-mismatch" or "no-handler-for-request" or
                "invalid-initialize-response";
            return new DesktopThreadOwnerStateGuardAcquireResult(
                incompatible
                    ? DesktopThreadOwnerStateGuardStatus.Incompatible
                    : DesktopThreadOwnerStateGuardStatus.Unavailable,
                null,
                exception.Message);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException)
        {
            return new DesktopThreadOwnerStateGuardAcquireResult(
                DesktopThreadOwnerStateGuardStatus.Unavailable,
                null,
                exception.Message);
        }
    }

    private async Task<string?> WaitForOwnerHostIdAsync(
        string conversationId,
        CancellationToken cancellationToken)
    {
        if (_ownerHostIds.TryGetValue(conversationId, out var cachedHostId))
        {
            return cachedHostId;
        }

        if (TryGetOnlyKnownOwnerHostId(out var onlyKnownHostId))
        {
            return onlyKnownHostId;
        }

        var completion = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        void HandleActivity(object? sender, DesktopIpcActivityEventArgs eventArgs)
        {
            if (string.Equals(eventArgs.ConversationId, conversationId, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(eventArgs.HostId))
            {
                completion.TrySetResult(eventArgs.HostId);
            }
        }

        ActivityReceived += HandleActivity;
        try
        {
            if (_ownerHostIds.TryGetValue(conversationId, out cachedHostId))
            {
                return cachedHostId;
            }

            if (TryGetOnlyKnownOwnerHostId(out onlyKnownHostId))
            {
                return onlyKnownHostId;
            }

            try
            {
                return await completion.Task.WaitAsync(OwnerHostDiscoveryTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                return null;
            }
        }
        finally
        {
            ActivityReceived -= HandleActivity;
        }
    }

    private bool TryGetOnlyKnownOwnerHostId(out string? hostId)
    {
        hostId = null;
        foreach (var knownHostId in _knownOwnerHostIds.Keys)
        {
            if (hostId is not null)
            {
                hostId = null;
                return false;
            }

            hostId = knownHostId;
        }

        return hostId is not null;
    }

    private async Task<bool> RequestFailsWithExpectedCodeAsync(
        string method,
        object parameters,
        int version,
        string expectedCode,
        CancellationToken cancellationToken)
    {
        try
        {
            await SendRequestCoreAsync(
                    method,
                    parameters,
                    _clientId!,
                    version,
                    NativeChannelProbeTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Warning($"Codex Desktop native channel probe unexpectedly succeeded for {method} v{version}.");
            return false;
        }
        catch (DesktopIpcProtocolException exception)
        {
            _log.Trace($"Codex Desktop native channel probe {method} v{version}: {exception.Code}.");
            return string.Equals(exception.Code, expectedCode, StringComparison.Ordinal);
        }
    }

    private async Task<bool> RequestFailsWithExpectedCodesAsync(
        string method,
        object parameters,
        int version,
        IReadOnlyCollection<string> expectedCodes,
        CancellationToken cancellationToken)
    {
        try
        {
            await SendRequestCoreAsync(
                    method,
                    parameters,
                    _clientId!,
                    version,
                    NativeChannelProbeTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            _log.Warning($"Codex Desktop native channel diagnostic unexpectedly succeeded for {method} v{version}.");
            return false;
        }
        catch (DesktopIpcProtocolException exception)
        {
            _log.Trace($"Codex Desktop native channel diagnostic {method} v{version}: {exception.Code}.");
            return expectedCodes.Contains(exception.Code, StringComparer.Ordinal);
        }
    }

    private static void ValidateServerIdentity(NamedPipeClientStream pipe)
    {
        try
        {
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverProcessId) ||
                serverProcessId == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            using var process = OpenProcess(ProcessQueryLimitedInformation, false, serverProcessId);
            if (process.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var serverUserSid = ReadProcessUserSid(process);
            using var currentProcess = OpenProcess(
                ProcessQueryLimitedInformation,
                false,
                checked((uint)Environment.ProcessId));
            if (currentProcess.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var currentUserSid = ReadProcessUserSid(currentProcess);
            if (!string.Equals(serverUserSid, currentUserSid, StringComparison.Ordinal))
            {
                throw new DesktopIpcServerValidationException(
                    "The Codex Desktop IPC server does not belong to the current Windows user.");
            }

            var packageFamilyName = ReadPackageFamilyName(process);
            if (!string.Equals(
                    packageFamilyName,
                    ExpectedPackageFamilyName,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new DesktopIpcServerValidationException(
                    "The Codex Desktop IPC server has an unexpected Windows package identity.");
            }

            var packageFullName = ReadPackageFullName(process);
            var packageInstallPath = ReadPackageInstallPath(packageFullName);
            var imagePath = ReadProcessImagePath(process);
            if (!IsProtectedPackageImagePath(imagePath, packageInstallPath, packageFullName))
            {
                throw new DesktopIpcServerValidationException(
                    "The Codex Desktop IPC server is not running from its registered WindowsApps package directory.");
            }

            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var confirmedProcessId) ||
                confirmedProcessId != serverProcessId)
            {
                throw new DesktopIpcServerValidationException(
                    "The Codex Desktop IPC server changed while its identity was being verified.");
            }
        }
        catch (DesktopIpcServerValidationException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new DesktopIpcServerValidationException(
                "The Codex Desktop IPC server identity could not be verified.",
                exception);
        }
    }

    private static string ReadProcessUserSid(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process, TokenQuery, out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (token)
        {
            if (GetTokenInformation(
                    token,
                    TokenUserInformationClass,
                    IntPtr.Zero,
                    0,
                    out var requiredLength) ||
                Marshal.GetLastWin32Error() != ErrorInsufficientBuffer ||
                requiredLength <= 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var tokenInformation = Marshal.AllocHGlobal(requiredLength);
            try
            {
                if (!GetTokenInformation(
                        token,
                        TokenUserInformationClass,
                        tokenInformation,
                        requiredLength,
                        out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var sidPointer = Marshal.ReadIntPtr(tokenInformation);
                if (sidPointer == IntPtr.Zero)
                {
                    throw new DesktopIpcServerValidationException(
                        "The Codex Desktop IPC server user identity is missing.");
                }

                return new SecurityIdentifier(sidPointer).Value;
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInformation);
            }
        }
    }

    private static string ReadProcessImagePath(SafeProcessHandle process)
    {
        var capacity = (uint)MaximumWindowsPathCharacters;
        var path = new StringBuilder((int)capacity);
        if (!QueryFullProcessImageName(process, 0, path, ref capacity) || capacity == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return path.ToString();
    }

    private static string ReadPackageFamilyName(SafeProcessHandle process)
    {
        uint length = 0;
        var result = GetPackageFamilyName(process, ref length, null);
        if (result != ErrorInsufficientBuffer || length == 0)
        {
            throw new Win32Exception(result);
        }

        var value = new StringBuilder(checked((int)length));
        result = GetPackageFamilyName(process, ref length, value);
        if (result != ErrorSuccess || value.Length == 0)
        {
            throw new Win32Exception(result);
        }

        return value.ToString();
    }

    private static string ReadPackageFullName(SafeProcessHandle process)
    {
        uint length = 0;
        var result = GetPackageFullName(process, ref length, null);
        if (result != ErrorInsufficientBuffer || length == 0)
        {
            throw new Win32Exception(result);
        }

        var value = new StringBuilder(checked((int)length));
        result = GetPackageFullName(process, ref length, value);
        if (result != ErrorSuccess || value.Length == 0)
        {
            throw new Win32Exception(result);
        }

        return value.ToString();
    }

    private static string ReadPackageInstallPath(string packageFullName)
    {
        uint length = 0;
        var result = GetPackagePathByFullName(packageFullName, ref length, null);
        if (result != ErrorInsufficientBuffer || length == 0)
        {
            throw new Win32Exception(result);
        }

        var value = new StringBuilder(checked((int)length));
        result = GetPackagePathByFullName(packageFullName, ref length, value);
        if (result != ErrorSuccess || value.Length == 0)
        {
            throw new Win32Exception(result);
        }

        return value.ToString();
    }

    private static bool IsProtectedPackageImagePath(
        string imagePath,
        string packageInstallPath,
        string packageFullName)
    {
        var normalizedImagePath = Path.GetFullPath(imagePath);
        var normalizedPackagePath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(packageInstallPath));
        var packageDirectory = new DirectoryInfo(normalizedPackagePath);
        if (!string.Equals(packageDirectory.Name, packageFullName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(packageDirectory.Parent?.Name, "WindowsApps", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var packagePathPrefix = normalizedPackagePath + Path.DirectorySeparatorChar;
        return normalizedImagePath.StartsWith(packagePathPrefix, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<JsonElement> SendRequestCoreAsync(
        string method,
        object parameters,
        string sourceClientId,
        int version,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        bool classifyCancellationForRecovery = false,
        Func<bool>? canStartWrite = null)
    {
        var pipe = _pipe;
        if (pipe is not { IsConnected: true })
        {
            throw new DesktopIpcDeliveryException(
                DesktopIpcDeliveryStage.NotDispatched,
                "The Codex Desktop IPC connection is not open.");
        }

        var requestId = Guid.NewGuid().ToString("D");
        var completion = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(requestId, completion))
        {
            throw new InvalidOperationException("Unable to allocate a Desktop IPC request id.");
        }

        var dispatchMayHaveStarted = false;
        try
        {
            var payload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "request",
                requestId,
                sourceClientId,
                version,
                method,
                @params = parameters,
                timeoutMs = checked((int)timeout.TotalMilliseconds)
            });
            await WriteFrameAsync(
                    pipe,
                    payload,
                    cancellationToken,
                    () => dispatchMayHaveStarted = true,
                    canStartWrite)
                .ConfigureAwait(false);

            using var registration = cancellationToken.Register(
                static state => ((TaskCompletionSource<JsonElement>)state!).TrySetCanceled(),
                completion);
            var response = await completion.Task.WaitAsync(timeout + TimeSpan.FromSeconds(2), cancellationToken)
                .ConfigureAwait(false);
            var resultType = ReadString(response, "resultType");
            if (string.Equals(resultType, "success", StringComparison.Ordinal))
            {
                return response.TryGetProperty("result", out var result)
                    ? result.Clone()
                    : JsonSerializer.SerializeToElement(new { });
            }

            var code = ReadProtocolError(response);
            throw new DesktopIpcProtocolException(
                code,
                FormatProtocolError(code),
                GetProtocolDeliveryStage(code));
        }
        catch (OperationCanceledException exception) when (classifyCancellationForRecovery)
        {
            throw new DesktopIpcDeliveryException(
                GetRecoveryCancellationDeliveryStage(dispatchMayHaveStarted),
                dispatchMayHaveStarted
                    ? "The recovery request may have been dispatched before cancellation; its acknowledgement is unknown."
                    : "The recovery request was cancelled before it was dispatched.",
                exception);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (DesktopIpcProtocolException)
        {
            throw;
        }
        catch (DesktopIpcDeliveryException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or TimeoutException)
        {
            throw new DesktopIpcDeliveryException(
                dispatchMayHaveStarted
                    ? DesktopIpcDeliveryStage.DispatchedUnknown
                    : DesktopIpcDeliveryStage.NotDispatched,
                dispatchMayHaveStarted
                    ? "The recovery request may have been dispatched, but its acknowledgement was lost."
                    : "The recovery request was not dispatched.",
                exception);
        }
        finally
        {
            _pending.TryRemove(requestId, out _);
        }
    }

    private async Task WriteFrameAsync(
        NamedPipeClientStream pipe,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken,
        Action? onWriteStarting = null,
        Func<bool>? canStartWrite = null)
    {
        var frame = EncodeFrame(payload.Span);
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsWritePreconditionSatisfied(canStartWrite))
            {
                throw new DesktopIpcDeliveryException(
                    DesktopIpcDeliveryStage.NotDispatched,
                    "The guarded Desktop IPC write precondition changed before dispatch.");
            }

            onWriteStarting?.Invoke();
            await pipe.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private static bool IsWritePreconditionSatisfied(Func<bool>? canStartWrite)
    {
        try
        {
            return canStartWrite?.Invoke() ?? true;
        }
        catch
        {
            return false;
        }
    }

    private async Task ReceiveLoopAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
    {
        Exception? failure = null;
        try
        {
            var header = new byte[sizeof(uint)];
            while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
            {
                await ReadExactlyAsync(pipe, header, cancellationToken).ConfigureAwait(false);
                var length = DecodeFrameLength(header);
                var payload = new byte[length];
                await ReadExactlyAsync(pipe, payload, cancellationToken).ConfigureAwait(false);
                using var document = JsonDocument.Parse(payload);
                await HandleIncomingMessageAsync(document.RootElement, pipe, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            failure = exception;
            _log.Warning("Codex Desktop IPC receive loop stopped: " + exception.Message);
        }
        finally
        {
            var ownedConnection = false;
            if (ReferenceEquals(_pipe, pipe))
            {
                ownedConnection = true;
                _pipe = null;
                _clientId = null;
                IsNativeChannelAvailable = false;
                _ownerHostIds.Clear();
                _knownOwnerHostIds.Clear();
            }

            pipe.Dispose();
            var connectionException = failure ?? new IOException("The Codex Desktop IPC connection closed.");
            foreach (var completion in _pending.Values)
            {
                completion.TrySetException(connectionException);
            }

            if (ownedConnection)
            {
                PublishConnectionTransition(connected: false);
            }
        }
    }

    private void PublishConnectionTransition(bool connected)
    {
        if (TryTransitionConnectionState(ref _publishedConnectionState, connected))
        {
            EventSubscriberDispatcher.Invoke(
                ConnectionChanged,
                this,
                connected,
                exception => _log.Trace(
                    "A Desktop connection subscriber failed (" + exception.GetType().Name + ")."));
        }
    }

    internal static bool TryTransitionConnectionState(ref int state, bool connected)
    {
        var next = connected ? 1 : 0;
        return Interlocked.Exchange(ref state, next) != next;
    }

    private async Task HandleIncomingMessageAsync(
        JsonElement message,
        NamedPipeClientStream pipe,
        CancellationToken cancellationToken)
    {
        var type = ReadString(message, "type");
        if (string.Equals(type, "response", StringComparison.Ordinal))
        {
            var requestId = ReadString(message, "requestId");
            if (_pending.TryGetValue(requestId, out var completion))
            {
                completion.TrySetResult(message.Clone());
            }

            return;
        }

        if (string.Equals(type, "client-discovery-request", StringComparison.Ordinal))
        {
            var requestId = ReadString(message, "requestId");
            if (!string.IsNullOrWhiteSpace(requestId))
            {
                var response = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    type = "client-discovery-response",
                    requestId,
                    sourceClientId = _clientId ?? "initializing-client",
                    response = new { canHandle = false }
                });
                await WriteFrameAsync(pipe, response, cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        if (string.Equals(type, "broadcast", StringComparison.Ordinal) ||
            string.Equals(type, "notification", StringComparison.Ordinal))
        {
            _log.Trace($"Received Desktop message: type={type}");
            var activity = ParseActivityEvent(message);
            if (activity is not null)
            {
                _log.Trace($"Parsed activity: method={activity.Method}, conversationId={activity.ConversationId}");
                if (Guid.TryParse(activity.ConversationId, out _) &&
                    !string.IsNullOrWhiteSpace(activity.HostId) &&
                    activity.Method is NativeThreadFollowingMethod or NativeThreadStateMethod or
                        "thread-stream-following-status-requested")
                {
                    _ownerHostIds[activity.ConversationId] = activity.HostId;
                    _knownOwnerHostIds[activity.HostId] = 0;
                }

                EventSubscriberDispatcher.Invoke(
                    ActivityReceived,
                    this,
                    activity,
                    exception => _log.Trace(
                        "A Desktop activity subscriber failed (" + exception.GetType().Name + ")."));
            }
            else
            {
                _log.Warning("Failed to parse Desktop activity event");
            }
        }
    }

    internal static DesktopIpcActivityEventArgs? ParseActivityEvent(JsonElement message)
    {
        var envelope = message;
        if ((!message.TryGetProperty("method", out var topLevelMethod) ||
             topLevelMethod.ValueKind != JsonValueKind.String) &&
            message.TryGetProperty("message", out var nested) &&
            nested.ValueKind == JsonValueKind.Object)
        {
            envelope = nested;
        }

        var method = ReadBroadcastMethod(envelope);
        if (string.IsNullOrWhiteSpace(method))
        {
            return null;
        }

        JsonElement? parameters = null;
        if (envelope.TryGetProperty("params", out var paramsElement) &&
            paramsElement.ValueKind == JsonValueKind.Object)
        {
            parameters = paramsElement.Clone();
        }

        var conversationId = parameters is { } payload
            ? ReadString(payload, "conversationId")
            : string.Empty;
        var hostId = parameters is { } hostPayload
            ? ReadString(hostPayload, "hostId")
            : string.Empty;
        var following = parameters is { } followingPayload &&
                        followingPayload.TryGetProperty("following", out var followingElement) &&
                        followingElement.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? followingElement.GetBoolean()
            : (bool?)null;
        var clientId = parameters is { } clientPayload
            ? ReadString(clientPayload, "clientId")
            : string.Empty;
        var clientStatus = parameters is { } statusPayload
            ? ReadString(statusPayload, "status")
            : string.Empty;

        string changeType = string.Empty;
        long? baseRevision = null;
        long? revision = null;
        string runtimeStatus = string.Empty;
        var hasRelevantStatePatch = false;
        if (parameters is { } changePayload &&
            changePayload.TryGetProperty("change", out var change) &&
            change.ValueKind == JsonValueKind.Object)
        {
            changeType = ReadString(change, "type");
            if (change.TryGetProperty("baseRevision", out var baseRevisionElement) &&
                baseRevisionElement.ValueKind == JsonValueKind.Number &&
                baseRevisionElement.TryGetInt64(out var parsedBaseRevision))
            {
                baseRevision = parsedBaseRevision;
            }

            if (change.TryGetProperty("revision", out var revisionElement) &&
                revisionElement.ValueKind == JsonValueKind.Number &&
                revisionElement.TryGetInt64(out var parsedRevision))
            {
                revision = parsedRevision;
            }

            if (change.TryGetProperty("conversationState", out var conversationState) &&
                conversationState.ValueKind == JsonValueKind.Object &&
                conversationState.TryGetProperty("threadRuntimeStatus", out var status))
            {
                runtimeStatus = status.ValueKind switch
                {
                    JsonValueKind.String => status.GetString() ?? string.Empty,
                    JsonValueKind.Object => ReadString(status, "type"),
                    _ => string.Empty
                };
            }

            if (change.TryGetProperty("patches", out var patches) &&
                patches.ValueKind == JsonValueKind.Array)
            {
                hasRelevantStatePatch = TryReadRelevantStatePatch(patches, out var patchedRuntimeStatus);
                if (!string.IsNullOrWhiteSpace(patchedRuntimeStatus))
                {
                    runtimeStatus = patchedRuntimeStatus;
                }
            }
        }

        var version = envelope.TryGetProperty("version", out var versionElement) &&
                      versionElement.ValueKind == JsonValueKind.Number &&
                      versionElement.TryGetInt32(out var parsedVersion)
            ? parsedVersion
            : 0;
        return new DesktopIpcActivityEventArgs(
            method,
            version,
            ReadString(envelope, "sourceClientId"),
            conversationId,
            hostId,
            following,
            clientId,
            clientStatus,
            changeType,
            baseRevision,
            revision,
            runtimeStatus,
            hasRelevantStatePatch,
            parameters);
    }

    private static bool TryReadRelevantStatePatch(
        JsonElement patches,
        out string runtimeStatus)
    {
        runtimeStatus = string.Empty;
        var relevant = false;
        foreach (var patch in patches.EnumerateArray())
        {
            if (patch.ValueKind != JsonValueKind.Object ||
                !patch.TryGetProperty("path", out var path) ||
                path.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var names = path.EnumerateArray()
                .Where(static segment => segment.ValueKind == JsonValueKind.String)
                .Select(static segment => segment.GetString() ?? string.Empty)
                .Where(static segment => segment.Length > 0)
                .ToArray();
            if (names.Length == 0)
            {
                continue;
            }

            var runtimeIndex = Array.FindIndex(
                names,
                static name => string.Equals(
                    name,
                    "threadRuntimeStatus",
                    StringComparison.OrdinalIgnoreCase));
            if (runtimeIndex >= 0)
            {
                relevant = true;
                if (patch.TryGetProperty("value", out var value))
                {
                    if (runtimeIndex == names.Length - 1)
                    {
                        runtimeStatus = ReadRuntimeStatusValue(value);
                    }
                    else if (runtimeIndex + 1 == names.Length - 1 &&
                             string.Equals(names[^1], "type", StringComparison.OrdinalIgnoreCase) &&
                             value.ValueKind == JsonValueKind.String)
                    {
                        runtimeStatus = value.GetString() ?? string.Empty;
                    }
                }
            }

            if (names.Any(static name =>
                    string.Equals(name, "resumeState", StringComparison.OrdinalIgnoreCase)))
            {
                relevant = true;
            }

            var isLegacyTurnPath = names.Any(static name =>
                string.Equals(name, "turns", StringComparison.OrdinalIgnoreCase));
            var isCanonicalTurnEntity = names.Any(static name =>
                name.StartsWith("turn:", StringComparison.OrdinalIgnoreCase));
            var isTurnPath = isLegacyTurnPath || isCanonicalTurnEntity;
            if (!isTurnPath)
            {
                continue;
            }

            var leaf = names[^1];
            if (string.Equals(leaf, "turnId", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(leaf, "status", StringComparison.OrdinalIgnoreCase))
            {
                relevant = true;
                continue;
            }

            if (patch.TryGetProperty("value", out var turnValue) &&
                turnValue.ValueKind == JsonValueKind.Object &&
                turnValue.TryGetProperty("turnId", out var turnId) &&
                turnId.ValueKind == JsonValueKind.String)
            {
                relevant = true;
            }
        }

        return relevant;
    }

    private static string ReadRuntimeStatusValue(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.Object => ReadString(value, "type"),
        _ => string.Empty
    };

    private async Task ResetConnectionAsync()
    {
        var pipe = _pipe;
        var receiveTask = _receiveTask;
        _pipe = null;
        _clientId = null;
        _receiveTask = null;
        IsNativeChannelAvailable = false;
        _ownerHostIds.Clear();
        _knownOwnerHostIds.Clear();
        if (pipe is not null)
        {
            try
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }

        if (receiveTask is not null)
        {
            try
            {
                await receiveTask.ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new EndOfStreamException("The Codex Desktop IPC pipe closed.");
            }

            read += count;
        }
    }

    private static string ReadProtocolError(JsonElement response)
    {
        if (!response.TryGetProperty("error", out var error))
        {
            return "unknown-ipc-error";
        }

        return error.ValueKind switch
        {
            JsonValueKind.String => error.GetString() ?? "unknown-ipc-error",
            JsonValueKind.Object when error.TryGetProperty("code", out var code) =>
                code.GetString() ?? error.GetRawText(),
            _ => error.GetRawText()
        };
    }

    private static string FormatProtocolError(string code) => code switch
    {
        "no-client-found" => "No Codex Desktop window currently owns this task.",
        "request-timeout" => "Codex Desktop did not answer the recovery request in time.",
        "client-disconnected" => "The Codex Desktop task owner disconnected.",
        "server-closed" => "The Codex Desktop IPC router closed.",
        "request-version-mismatch" => "This Codex Desktop version uses an incompatible IPC request version.",
        "no-handler-for-request" => "This Codex Desktop version does not expose the task follower send handler.",
        "guardian-state-changed" => "The task state changed before Desktop could commit recovery.",
        "guardian-owner-unavailable" => "The Codex Desktop task owner is not ready.",
        "guardian-original-input-unavailable" => "Codex Desktop could not recover the original structured input.",
        "guardian-invalid-request" => "Codex Desktop rejected an invalid Guardian recovery request.",
        "guardian-message-id-conflict" => "Codex Desktop rejected a reused recovery message id with different input.",
        _ when IsStaleEditRefusal(code) =>
            "The failed turn is no longer the last message, so Codex Desktop refused the in-place edit " +
            "and nothing was resent.",
        _ => "Codex Desktop rejected the recovery request: " + code
    };

    // Codex Desktop refuses to edit anything but the last message, and it says so in prose rather than
    // through the `guardian-state-changed` code this client was written to expect. The prose fell to the
    // catch-all below and was recorded as "may have been dispatched", which is the opposite of what
    // happened: the edit was refused outright with no side effect. Live cost of that inversion — with
    // several conversations open, four threads burned all five uncertain-retry attempts on refusals and
    // were abandoned, while the resend the user was waiting for never went out. Matching on the phrase
    // is brittle against future wording changes, so the catch-all stays; a new wording degrades to the
    // old conservative behaviour rather than to a wrong one.
    private static readonly string[] StaleEditRefusalFragments =
    [
        "most recent message can be edited",
        "only the last message can be edited",
        "no longer the last"
    ];

    internal static bool IsStaleEditRefusal(string code) =>
        !string.IsNullOrWhiteSpace(code) &&
        StaleEditRefusalFragments.Any(fragment =>
            code.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    internal static DesktopIpcDeliveryStage GetProtocolDeliveryStage(string code) => code switch
    {
        "request-timeout" or "client-disconnected" or "server-closed" =>
            DesktopIpcDeliveryStage.DispatchedUnknown,
        "no-client-found" or "request-version-mismatch" or "no-handler-for-request" or
            "guardian-state-changed" or "guardian-owner-unavailable" or
            "guardian-original-input-unavailable" or "guardian-invalid-request" or
            "guardian-message-id-conflict" or
            "native-edit-rejected" or "thread-follower-edit-last-user-turn-timeout" => DesktopIpcDeliveryStage.Rejected,
        _ when IsStaleEditRefusal(code) => DesktopIpcDeliveryStage.NotDispatched,
        _ => DesktopIpcDeliveryStage.DispatchedUnknown
    };

    internal static DesktopIpcDeliveryStage GetRecoveryCancellationDeliveryStage(bool writeStarted) =>
        writeStarted
            ? DesktopIpcDeliveryStage.DispatchedUnknown
            : DesktopIpcDeliveryStage.NotDispatched;

    private static string ReadBroadcastMethod(JsonElement message)
    {
        if (message.TryGetProperty("method", out var method) && method.ValueKind == JsonValueKind.String)
        {
            return method.GetString() ?? string.Empty;
        }

        return message.TryGetProperty("message", out var nested) && nested.ValueKind == JsonValueKind.Object
            ? ReadString(nested, "method")
            : string.Empty;
    }

    private static string ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe,
        out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle processHandle,
        uint flags,
        StringBuilder executablePath,
        ref uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(
        SafeProcessHandle processHandle,
        ref uint packageFamilyNameLength,
        StringBuilder? packageFamilyName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFullName(
        SafeProcessHandle processHandle,
        ref uint packageFullNameLength,
        StringBuilder? packageFullName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackagePathByFullName(
        string packageFullName,
        ref uint pathLength,
        StringBuilder? path);
}

public enum DesktopThreadOwnerProbeStatus
{
    Available,
    Unavailable,
    TransientFailure,
    Incompatible
}

public sealed record DesktopThreadOwnerProbeResult(
    DesktopThreadOwnerProbeStatus Status,
    string Detail);

public sealed record DesktopStartTurnResult(string TurnId);

// The owner acknowledges an accepted in-place retry with {"ok":true} and no turn id, so the caller
// resolves the successor turn from observed task state instead of the transport response.
public sealed record DesktopInPlaceRetryResult(bool Accepted);

public enum DesktopIpcDeliveryStage
{
    NotDispatched,
    DispatchedUnknown,
    Rejected,
    Acknowledged
}

public sealed class DesktopIpcDeliveryException : IOException
{
    public DesktopIpcDeliveryException(
        DesktopIpcDeliveryStage stage,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Stage = stage;
    }

    public DesktopIpcDeliveryStage Stage { get; }
}

public sealed class DesktopIpcProtocolException(
    string code,
    string message,
    DesktopIpcDeliveryStage stage = DesktopIpcDeliveryStage.Rejected) : IOException(message)
{
    public string Code { get; } = code;

    public DesktopIpcDeliveryStage Stage { get; } = stage;
}

public sealed class DesktopIpcServerValidationException : IOException
{
    public DesktopIpcServerValidationException(string message)
        : base(message)
    {
    }

    public DesktopIpcServerValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class DesktopIpcActivityEventArgs : EventArgs
{
    public DesktopIpcActivityEventArgs(string method)
        : this(
            method,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            null,
            string.Empty,
            string.Empty,
            string.Empty,
            null,
            null,
            string.Empty,
            false,
            null)
    {
    }

    internal DesktopIpcActivityEventArgs(
        string method,
        int version,
        string sourceClientId,
        string conversationId,
        string hostId,
        bool? following,
        string clientId,
        string clientStatus,
        string changeType,
        long? baseRevision,
        long? revision,
        string runtimeStatus,
        bool hasRelevantStatePatch,
        JsonElement? parameters)
    {
        Method = method;
        Version = version;
        SourceClientId = sourceClientId;
        ConversationId = conversationId;
        HostId = hostId;
        Following = following;
        ClientId = clientId;
        ClientStatus = clientStatus;
        ChangeType = changeType;
        BaseRevision = baseRevision;
        Revision = revision;
        RuntimeStatus = runtimeStatus;
        HasRelevantStatePatch = hasRelevantStatePatch;
        Parameters = parameters;
    }

    public string Method { get; }

    public int Version { get; }

    public string SourceClientId { get; }

    public string ConversationId { get; }

    public string HostId { get; }

    public bool? Following { get; }

    public string ClientId { get; }

    public string ClientStatus { get; }

    public string ChangeType { get; }

    public long? BaseRevision { get; }

    public long? Revision { get; }

    public string RuntimeStatus { get; }

    public bool HasRelevantStatePatch { get; }

    public JsonElement? Parameters { get; }
}
