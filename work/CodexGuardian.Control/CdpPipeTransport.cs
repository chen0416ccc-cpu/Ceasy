using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;

namespace CodexGuardian.Control;

internal enum CdpPipeTerminalFaultMode
{
    CloseStreams,
    BrokerOwnedDrainUntilDispose
}

internal sealed class CdpPipeTransportOptions
{
    internal const int DefaultMaximumFrameBytes = 1024 * 1024;
    internal const int DefaultMaximumPendingCommands = 64;
    internal const int DefaultMaximumBufferedNotifications = 256;
    internal const int DefaultReadBufferBytes = 16 * 1024;

    internal int MaximumFrameBytes { get; init; } = DefaultMaximumFrameBytes;

    internal int MaximumPendingCommands { get; init; } = DefaultMaximumPendingCommands;

    internal int MaximumBufferedNotifications { get; init; } =
        DefaultMaximumBufferedNotifications;

    internal int ReadBufferBytes { get; init; } = DefaultReadBufferBytes;

    internal TimeSpan CommandTimeout { get; init; } = TimeSpan.FromSeconds(10);

    internal CdpPipeTerminalFaultMode TerminalFaultMode { get; init; } =
        CdpPipeTerminalFaultMode.CloseStreams;

    internal void Validate()
    {
        if (MaximumFrameBytes is < 64 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumFrameBytes));
        }

        if (MaximumPendingCommands is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumPendingCommands));
        }

        if (MaximumBufferedNotifications is < 1 or > 16 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumBufferedNotifications));
        }

        if (ReadBufferBytes is < 64 or > 256 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(ReadBufferBytes));
        }

        if (CommandTimeout <= TimeSpan.Zero || CommandTimeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(CommandTimeout));
        }

        if (!Enum.IsDefined(TerminalFaultMode))
        {
            throw new ArgumentOutOfRangeException(nameof(TerminalFaultMode));
        }
    }
}

internal sealed class CdpPipeTransport : ICdpCommandTransport, IAsyncDisposable
{
    private static readonly TimeSpan ShutdownWait = TimeSpan.FromSeconds(2);
    private readonly Stream _readStream;
    private readonly Stream _writeStream;
    private readonly int _maximumFrameBytes;
    private readonly int _readBufferBytes;
    private readonly TimeSpan _commandTimeout;
    private readonly CdpPipeTerminalFaultMode _terminalFaultMode;
    private readonly ConcurrentDictionary<long, PendingCommand> _pending = new();
    private readonly SemaphoreSlim _pendingSlots;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly Channel<JsonElement> _notifications;
    private readonly CancellationTokenSource _commandLifetime = new();
    private readonly CancellationTokenSource _readLifetime = new();
    private readonly TaskCompletionSource _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _disposeCompletion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _terminalSync = new();
    private readonly Task _receiveLoop;
    private Exception? _terminalFailure;
    private long _completedFrameWriteCount;
    private long _drainedReadBatchCount;
    private long _nextRequestId;
    private long _parsedFrameCount;
    private int _streamsClosed;
    private int _drainOnly;
    private int _terminalFinalized;
    private int _disposed;

    internal CdpPipeTransport(
        Stream readStream,
        Stream writeStream,
        CdpPipeTransportOptions? options = null)
    {
        _readStream = readStream ?? throw new ArgumentNullException(nameof(readStream));
        _writeStream = writeStream ?? throw new ArgumentNullException(nameof(writeStream));
        if (!readStream.CanRead)
        {
            throw new ArgumentException("The CDP response stream must be readable.", nameof(readStream));
        }

        if (!writeStream.CanWrite)
        {
            throw new ArgumentException("The CDP command stream must be writable.", nameof(writeStream));
        }

        options ??= new CdpPipeTransportOptions();
        options.Validate();
        _maximumFrameBytes = options.MaximumFrameBytes;
        _readBufferBytes = options.ReadBufferBytes;
        _commandTimeout = options.CommandTimeout;
        _terminalFaultMode = options.TerminalFaultMode;
        _pendingSlots = new SemaphoreSlim(
            options.MaximumPendingCommands,
            options.MaximumPendingCommands);
        _notifications = Channel.CreateBounded<JsonElement>(
            new BoundedChannelOptions(options.MaximumBufferedNotifications)
            {
                AllowSynchronousContinuations = false,
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = false,
                SingleWriter = true
            });
        _receiveLoop = ReceiveLoopAsync();
    }

    internal ChannelReader<JsonElement> Notifications => _notifications.Reader;

    ChannelReader<JsonElement> ICdpCommandTransport.Notifications => Notifications;

    internal Task Completion => _completion.Task;

    internal Exception? TerminalFailure => Volatile.Read(ref _terminalFailure);

    internal bool IsDrainOnly => Volatile.Read(ref _drainOnly) != 0;

    internal long CompletedFrameWriteCount => Interlocked.Read(ref _completedFrameWriteCount);

    internal long DrainedReadBatchCount => Interlocked.Read(ref _drainedReadBatchCount);

    internal long ParsedFrameCount => Interlocked.Read(ref _parsedFrameCount);

    internal Task<JsonElement> SendCommandAsync(
        string method,
        object? parameters = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default) =>
        SendCommandCoreAsync(
            method,
            parameters,
            sessionId: null,
            timeout,
            cancellationToken);

    Task<JsonElement> ICdpCommandTransport.SendCommandAsync(
        string method,
        object? parameters,
        TimeSpan? timeout,
        CancellationToken cancellationToken) =>
        SendCommandAsync(method, parameters, timeout, cancellationToken);

    internal Task<JsonElement> SendSessionCommandAsync(
        string sessionId,
        string method,
        object? parameters = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sessionId) ||
            sessionId.Length > 256 ||
            sessionId.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("A bounded CDP session id is required.", nameof(sessionId));
        }

        return SendCommandCoreAsync(method, parameters, sessionId, timeout, cancellationToken);
    }

    Task<JsonElement> ICdpCommandTransport.SendSessionCommandAsync(
        string sessionId,
        string method,
        object? parameters,
        TimeSpan? timeout,
        CancellationToken cancellationToken) =>
        SendSessionCommandAsync(sessionId, method, parameters, timeout, cancellationToken);

    private async Task<JsonElement> SendCommandCoreAsync(
        string method,
        object? parameters,
        string? sessionId,
        TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(method))
        {
            throw new ArgumentException("A CDP method is required.", nameof(method));
        }

        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();

        var commandTimeout = timeout ?? _commandTimeout;
        if (commandTimeout <= TimeSpan.Zero || commandTimeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var requestId = Interlocked.Increment(ref _nextRequestId);
        if (requestId <= 0)
        {
            var failure = new CdpPipeProtocolException(
                "request-id-exhausted",
                "The CDP command id space was exhausted.");
            Fault(failure);
            throw failure;
        }

        var payload = SerializeCommand(requestId, method, parameters, sessionId);
        if (payload.Length > _maximumFrameBytes)
        {
            throw new ArgumentException(
                "The serialized CDP command exceeds the configured frame limit.",
                nameof(parameters));
        }

        if (!_pendingSlots.Wait(0))
        {
            throw new CdpPipeCapacityException(
                "The CDP pending-command limit has been reached.");
        }

        var pending = new PendingCommand();
        if (!_pending.TryAdd(requestId, pending))
        {
            _pendingSlots.Release();
            var failure = new CdpPipeProtocolException(
                "duplicate-request-id",
                "A duplicate CDP command id was allocated.");
            Fault(failure);
            throw failure;
        }

        try
        {
            await WriteFrameAsync(payload, cancellationToken).ConfigureAwait(false);
            var reply = await pending.Completion.Task
                .WaitAsync(commandTimeout, cancellationToken)
                .ConfigureAwait(false);
            if (reply.Error is { } error)
            {
                throw CreateCommandException(requestId, error);
            }

            return reply.Result?.Clone() ?? JsonSerializer.SerializeToElement(new { });
        }
        finally
        {
            if (_pending.TryRemove(requestId, out _))
            {
                _pendingSlots.Release();
            }
        }
    }

    public ValueTask DisposeAsync() => new(DisposeCoreAsync());

    private async Task DisposeCoreAsync()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
        {
            await _disposeCompletion.Task.ConfigureAwait(false);
            return;
        }

        Exception? disposeFailure = null;
        Exception? terminalFailure;
        lock (_terminalSync)
        {
            terminalFailure = _terminalFailure;
        }

        if (terminalFailure is not null)
        {
            FinalizeTerminalFailure(terminalFailure);
        }
        else
        {
            var disposedFailure = new ObjectDisposedException(nameof(CdpPipeTransport));
            CaptureCleanupFailure(() => FailPending(disposedFailure), ref disposeFailure);
            _notifications.Writer.TryComplete();
        }

        CaptureCleanupFailure(_commandLifetime.Cancel, ref disposeFailure);
        CaptureCleanupFailure(_readLifetime.Cancel, ref disposeFailure);
        CloseStreams();

        try
        {
            await _receiveLoop.WaitAsync(ShutdownWait).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            disposeFailure ??= exception;
        }

        if (TerminalFailure is null)
        {
            if (disposeFailure is null)
            {
                _completion.TrySetResult();
            }
            else
            {
                _completion.TrySetException(disposeFailure);
            }
        }

        if (disposeFailure is null)
        {
            _disposeCompletion.TrySetResult();
        }
        else
        {
            _disposeCompletion.TrySetException(disposeFailure);
        }

        await _disposeCompletion.Task.ConfigureAwait(false);
    }

    private static byte[] SerializeCommand(
        long requestId,
        string method,
        object? parameters,
        string? sessionId)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("id", requestId);
            writer.WriteString("method", method);
            if (parameters is not null)
            {
                writer.WritePropertyName("params");
                JsonSerializer.Serialize(writer, parameters, parameters.GetType());
            }

            if (sessionId is not null)
            {
                writer.WriteString("sessionId", sessionId);
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private async Task WriteFrameAsync(byte[] payload, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _commandLifetime.Token);
        await _writeGate.WaitAsync(linked.Token).ConfigureAwait(false);
        var writeStarted = false;
        try
        {
            ThrowIfUnavailable();
            linked.Token.ThrowIfCancellationRequested();
            var frame = new byte[checked(payload.Length + 1)];
            payload.CopyTo(frame, 0);
            writeStarted = true;
            await _writeStream.WriteAsync(frame, linked.Token).ConfigureAwait(false);
            ThrowIfUnavailable();
            await _writeStream.FlushAsync(linked.Token).ConfigureAwait(false);
            ThrowIfUnavailable();
            Interlocked.Increment(ref _completedFrameWriteCount);
        }
        catch (OperationCanceledException exception) when (
            writeStarted && cancellationToken.IsCancellationRequested)
        {
            Fault(new CdpPipeProtocolException(
                "outbound-write-cancelled",
                "A CDP frame write was cancelled after it may have started.",
                exception));
            throw;
        }
        catch (OperationCanceledException) when (_commandLifetime.IsCancellationRequested)
        {
            ThrowIfUnavailable();
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or ObjectDisposedException or NotSupportedException)
        {
            var failure = new CdpPipeProtocolException(
                "outbound-write-failed",
                "The CDP command stream failed while writing a frame.",
                exception);
            Fault(failure);
            throw failure;
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async Task ReceiveLoopAsync()
    {
        var readBuffer = new byte[_readBufferBytes];
        var frameBuffer = new byte[_maximumFrameBytes];
        var frameLength = 0;
        try
        {
            while (!_readLifetime.IsCancellationRequested)
            {
                if (IsDrainOnly)
                {
                    CryptographicOperations.ZeroMemory(frameBuffer);
                    frameLength = 0;
                    await DrainReadStreamAsync(readBuffer).ConfigureAwait(false);
                    return;
                }

                var count = await _readStream
                    .ReadAsync(readBuffer, _readLifetime.Token)
                    .ConfigureAwait(false);
                if (count == 0)
                {
                    if (IsDrainOnly)
                    {
                        return;
                    }

                    throw new CdpPipeProtocolException(
                        frameLength == 0 ? "unexpected-eof" : "truncated-frame",
                        frameLength == 0
                            ? "The CDP response stream closed."
                            : "The CDP response stream closed in the middle of a frame.");
                }

                if (IsDrainOnly)
                {
                    CryptographicOperations.ZeroMemory(readBuffer.AsSpan(0, count));
                    continue;
                }

                var offset = 0;
                while (offset < count)
                {
                    if (IsDrainOnly)
                    {
                        CryptographicOperations.ZeroMemory(readBuffer.AsSpan(offset, count - offset));
                        break;
                    }

                    var terminator = Array.IndexOf(
                        readBuffer,
                        (byte)0,
                        offset,
                        count - offset);
                    if (terminator < 0)
                    {
                        AppendFrameBytes(
                            readBuffer,
                            offset,
                            count - offset,
                            frameBuffer,
                            ref frameLength);
                        break;
                    }

                    AppendFrameBytes(
                        readBuffer,
                        offset,
                        terminator - offset,
                        frameBuffer,
                        ref frameLength);
                    if (frameLength == 0)
                    {
                        throw new CdpPipeProtocolException(
                            "empty-frame",
                            "The CDP response stream contained an empty frame.");
                    }

                    if (!IsReceiveAuthorityUnavailable())
                    {
                        ProcessFrame(frameBuffer.AsMemory(0, frameLength));
                    }

                    frameLength = 0;
                    offset = terminator + 1;
                }
            }
        }
        catch (OperationCanceledException) when (_readLifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            Fault(exception is CdpPipeProtocolException
                ? exception
                : new CdpPipeProtocolException(
                    "inbound-read-failed",
                    "The CDP response stream failed.",
                    exception));
            if (IsDrainOnly)
            {
                CryptographicOperations.ZeroMemory(frameBuffer);
                CryptographicOperations.ZeroMemory(readBuffer);
                await DrainReadStreamAsync(readBuffer).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frameBuffer);
            CryptographicOperations.ZeroMemory(readBuffer);
        }
    }

    private async Task DrainReadStreamAsync(byte[] readBuffer)
    {
        while (!_readLifetime.IsCancellationRequested)
        {
            try
            {
                var count = await _readStream
                    .ReadAsync(readBuffer, _readLifetime.Token)
                    .ConfigureAwait(false);
                if (count == 0)
                {
                    return;
                }

                CryptographicOperations.ZeroMemory(readBuffer.AsSpan(0, count));
                Interlocked.Increment(ref _drainedReadBatchCount);
            }
            catch (OperationCanceledException) when (_readLifetime.IsCancellationRequested)
            {
                return;
            }
            catch
            {
                return;
            }
        }
    }

    private void AppendFrameBytes(
        byte[] source,
        int sourceOffset,
        int count,
        byte[] frameBuffer,
        ref int frameLength)
    {
        if (count > _maximumFrameBytes - frameLength)
        {
            throw new CdpPipeProtocolException(
                "frame-too-large",
                "A CDP response frame exceeded the configured limit.");
        }

        Buffer.BlockCopy(source, sourceOffset, frameBuffer, frameLength, count);
        frameLength += count;
    }

    private void ProcessFrame(ReadOnlyMemory<byte> payload)
    {
        if (IsReceiveAuthorityUnavailable())
        {
            return;
        }

        Interlocked.Increment(ref _parsedFrameCount);

        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(payload);
            root = document.RootElement.Clone();
        }
        catch (JsonException exception)
        {
            throw new CdpPipeProtocolException(
                "invalid-json",
                "A CDP response frame was not valid JSON.",
                exception);
        }

        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new CdpPipeProtocolException(
                "invalid-envelope",
                "A CDP response frame must contain a JSON object.");
        }

        JsonElement idElement = default;
        JsonElement methodElement = default;
        JsonElement resultElement = default;
        JsonElement errorElement = default;
        var idCount = 0;
        var methodCount = 0;
        var resultCount = 0;
        var errorCount = 0;
        foreach (var property in root.EnumerateObject())
        {
            switch (property.Name)
            {
                case "id":
                    idElement = property.Value;
                    idCount++;
                    break;
                case "method":
                    methodElement = property.Value;
                    methodCount++;
                    break;
                case "result":
                    resultElement = property.Value;
                    resultCount++;
                    break;
                case "error":
                    errorElement = property.Value;
                    errorCount++;
                    break;
            }
        }

        if (idCount == 0)
        {
            ProcessNotification(root, methodElement, methodCount, resultCount, errorCount);
            return;
        }

        if (idCount != 1 ||
            methodCount != 0 ||
            !idElement.TryGetInt64(out var requestId) ||
            requestId <= 0 ||
            resultCount + errorCount != 1 ||
            resultCount > 1 ||
            errorCount > 1 ||
            (errorCount == 1 && errorElement.ValueKind != JsonValueKind.Object))
        {
            throw new CdpPipeProtocolException(
                "invalid-response",
                "A CDP response did not have one valid id and exactly one result or error.");
        }

        lock (_terminalSync)
        {
            if (IsReceiveAuthorityUnavailableLocked())
            {
                return;
            }

            if (!_pending.TryRemove(requestId, out var pending))
            {
                throw new CdpPipeProtocolException(
                    "unknown-response-id",
                    "A CDP response referenced an unknown or already completed command id.");
            }

            _pendingSlots.Release();
            pending.Completion.TrySetResult(resultCount == 1
                ? new CommandReply(resultElement.Clone(), null)
                : new CommandReply(null, errorElement.Clone()));
        }
    }

    private void ProcessNotification(
        JsonElement root,
        JsonElement methodElement,
        int methodCount,
        int resultCount,
        int errorCount)
    {
        if (methodCount != 1 ||
            methodElement.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(methodElement.GetString()) ||
            resultCount != 0 ||
            errorCount != 0)
        {
            throw new CdpPipeProtocolException(
                "invalid-notification",
                "A CDP notification did not have one valid method and no response fields.");
        }

        lock (_terminalSync)
        {
            if (IsReceiveAuthorityUnavailableLocked())
            {
                return;
            }

            if (!_notifications.Writer.TryWrite(root))
            {
                throw new CdpPipeProtocolException(
                    "notification-capacity-exceeded",
                    "The bounded CDP notification buffer is full.");
            }
        }
    }

    private bool IsReceiveAuthorityUnavailable()
    {
        lock (_terminalSync)
        {
            return IsReceiveAuthorityUnavailableLocked();
        }
    }

    private bool IsReceiveAuthorityUnavailableLocked() =>
        _drainOnly != 0 || _terminalFailure is not null || _disposed != 0;

    private static CdpCommandException CreateCommandException(long requestId, JsonElement error)
    {
        int? code = null;
        if (error.TryGetProperty("code", out var codeElement) && codeElement.TryGetInt32(out var value))
        {
            code = value;
        }

        var message = error.TryGetProperty("message", out var messageElement) &&
            messageElement.ValueKind == JsonValueKind.String
                ? messageElement.GetString()
                : null;
        if (string.IsNullOrWhiteSpace(message))
        {
            message = "The CDP command returned an error.";
        }
        else if (message.Length > 512)
        {
            message = message[..512];
        }

        return new CdpCommandException(requestId, code, message);
    }

    private void ThrowIfUnavailable()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(CdpPipeTransport));
        }

        if (TerminalFailure is { } terminalFailure)
        {
            throw new CdpPipeProtocolException(
                "transport-faulted",
                "The CDP pipe transport is in a terminal failure state.",
                terminalFailure);
        }
    }

    private void Fault(Exception failure)
    {
        lock (_terminalSync)
        {
            if (_terminalFailure is not null || Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            Volatile.Write(ref _terminalFailure, failure);
            if (_terminalFaultMode == CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose)
            {
                Volatile.Write(ref _drainOnly, 1);
            }
        }

        CancelWithoutThrowing(_commandLifetime);
        if (_terminalFaultMode == CdpPipeTerminalFaultMode.CloseStreams)
        {
            CancelWithoutThrowing(_readLifetime);
            CloseStreams();
        }

        FinalizeTerminalFailure(failure);
    }

    private void FinalizeTerminalFailure(Exception failure)
    {
        if (Interlocked.CompareExchange(ref _terminalFinalized, 1, 0) != 0)
        {
            return;
        }

        try
        {
            FailPending(failure);
        }
        catch
        {
        }

        while (_notifications.Reader.TryRead(out _))
        {
        }

        _notifications.Writer.TryComplete(failure);
        _completion.TrySetException(failure);
    }

    private static void CancelWithoutThrowing(CancellationTokenSource source)
    {
        try
        {
            source.Cancel();
        }
        catch
        {
        }
    }

    private static void CaptureCleanupFailure(Action action, ref Exception? failure)
    {
        try
        {
            action();
        }
        catch (Exception exception)
        {
            failure ??= exception;
        }
    }

    private void FailPending(Exception failure)
    {
        foreach (var pair in _pending.ToArray())
        {
            if (!_pending.TryRemove(pair.Key, out var pending))
            {
                continue;
            }

            pending.Completion.TrySetException(failure);
            try
            {
                _pendingSlots.Release();
            }
            catch (SemaphoreFullException)
            {
            }
        }
    }

    private void CloseStreams()
    {
        if (Interlocked.Exchange(ref _streamsClosed, 1) != 0)
        {
            return;
        }

        try
        {
            _readStream.Dispose();
        }
        catch
        {
        }

        if (!ReferenceEquals(_readStream, _writeStream))
        {
            try
            {
                _writeStream.Dispose();
            }
            catch
            {
            }
        }
    }

    private sealed class PendingCommand
    {
        internal TaskCompletionSource<CommandReply> Completion { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed record CommandReply(JsonElement? Result, JsonElement? Error);
}

internal sealed class CdpPipeCapacityException : InvalidOperationException
{
    internal CdpPipeCapacityException(string message)
        : base(message)
    {
    }
}

internal sealed class CdpPipeProtocolException : IOException
{
    internal CdpPipeProtocolException(string code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal sealed class CdpCommandException : InvalidOperationException
{
    internal CdpCommandException(long requestId, int? code, string message)
        : base(message)
    {
        RequestId = requestId;
        Code = code;
    }

    internal long RequestId { get; }

    internal int? Code { get; }
}
