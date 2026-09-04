using System.Text.Json;
using System.Threading.Channels;

namespace CodexGuardian.Control;

internal interface ICdpCommandTransport
{
    ChannelReader<JsonElement> Notifications { get; }

    Task<JsonElement> SendCommandAsync(
        string method,
        object? parameters = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default);

    Task<JsonElement> SendSessionCommandAsync(
        string sessionId,
        string method,
        object? parameters = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default);
}
