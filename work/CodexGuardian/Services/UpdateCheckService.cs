using System;
using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Services;

/// <summary>What the update check concluded, once.</summary>
/// <param name="LatestVersion">The newest published release, parsed from its tag.</param>
/// <param name="IsNewerThanCurrent">True only when that release is strictly newer than this build.</param>
internal sealed record UpdateCheckResult(Version LatestVersion, bool IsNewerThanCurrent)
{
    /// <summary>The version as it is shown to the user, three parts.</summary>
    internal string LatestVersionText => LatestVersion.ToString(3);
}

/// <summary>
/// Asks GitHub once whether a newer release exists.
/// </summary>
/// <remarks>
/// This is the only outbound request the app makes, and the whole design follows from that. It is off unless the
/// user leaves it on, it sends a GET with no body and no query, it never carries anything about the machine or
/// the conversations, and every failure is silent — a rate limit, a proxy, or no network at all leaves the shell
/// exactly as it looks with the check turned off.
///
/// The release URL from the response is deliberately not used. Opening a URL that arrived over the network hands
/// a shell-execute target to whatever answered the request; the app only ever opens its own
/// <see cref="ProductIdentity.ReleasesUrl"/>, so a compromised or spoofed response can at most misreport a
/// version number.
/// </remarks>
internal sealed class UpdateCheckService : IDisposable
{
    /// <summary>
    /// How long a result stands before another request is allowed.
    /// </summary>
    /// <remarks>
    /// Anonymous GitHub API calls are limited to 60 per hour per address, shared with anything else on that
    /// address. One a day per run leaves that budget alone. There is no persisted timestamp: a restart is
    /// allowed to check again, which is what a user who just relaunched to pick up a fix expects.
    /// </remarks>
    private static readonly TimeSpan MinimumInterval = TimeSpan.FromHours(24);

    /// <summary>
    /// Cap on the response body actually read.
    /// </summary>
    /// <remarks>
    /// A release's JSON carries its notes, which have no documented ceiling. Only the first few fields are
    /// wanted, so the read stops well before an oversized or hostile body can be buffered.
    /// </remarks>
    private const int MaximumResponseBytes = 256 * 1024;

    private readonly GuardianLog _log;
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DateTimeOffset? _lastAttemptAt;
    private UpdateCheckResult? _lastResult;
    private int _disposed;

    internal UpdateCheckService(GuardianLog log, HttpMessageHandler? handler = null)
    {
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _http = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: true);
        _http.Timeout = TimeSpan.FromSeconds(10);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(ProductIdentity.UserAgent);
        _http.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        // Pinning the API version keeps a future GitHub default from changing the field names underneath a
        // build that is already shipped.
        _http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
    }

    /// <summary>The most recent successful conclusion, or null if none has been reached this run.</summary>
    internal UpdateCheckResult? LastResult => Volatile.Read(ref _lastResult);

    /// <summary>
    /// Checks for a newer release, or returns the cached conclusion when asked again too soon.
    /// </summary>
    /// <param name="force">Bypasses the interval, for a check the user asked for by hand.</param>
    /// <returns>The conclusion, or null when nothing could be established.</returns>
    internal async Task<UpdateCheckResult?> CheckAsync(bool force, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return null;
        }

        if (!await _gate.WaitAsync(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false))
        {
            // Another check is already in flight. Returning its previous conclusion is right: two callers
            // wanting the same fact should not become two requests against a 60-per-hour budget.
            return LastResult;
        }

        try
        {
            if (!force &&
                _lastAttemptAt is { } previous &&
                DateTimeOffset.UtcNow - previous < MinimumInterval)
            {
                return _lastResult;
            }

            _lastAttemptAt = DateTimeOffset.UtcNow;
            var result = await RequestLatestAsync(cancellationToken).ConfigureAwait(false);
            if (result is not null)
            {
                Volatile.Write(ref _lastResult, result);
            }

            return result ?? _lastResult;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<UpdateCheckResult?> RequestLatestAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http
                .GetAsync(
                    ProductIdentity.LatestReleaseApiUrl,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                // No release published yet. A normal state for a repository that exists but has not shipped,
                // and not worth a warning on every check.
                _log.Info("更新检查：仓库还没有发布版本。");
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                _log.Warning(
                    "更新检查失败：HTTP " +
                    ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture));
                return null;
            }

            var payload = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
            if (payload is null)
            {
                return null;
            }

            return ParseLatest(payload);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The client's own timeout surfaces as this rather than as a timeout exception.
            _log.Warning("更新检查超时。");
            return null;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (HttpRequestException exception)
        {
            _log.Warning("更新检查无法连接：" + exception.Message);
            return null;
        }
        catch (JsonException)
        {
            // The body is never logged, so this says only that it did not parse.
            _log.Warning("更新检查收到无法解析的响应。");
            return null;
        }
    }

    /// <summary>Reads at most <see cref="MaximumResponseBytes"/>, without trusting Content-Length.</summary>
    private async Task<byte[]?> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        var buffer = ArrayPool<byte>.Shared.Rent(MaximumResponseBytes);
        try
        {
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await stream
                    .ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            if (total == 0)
            {
                _log.Warning("更新检查收到空响应。");
                return null;
            }

            return buffer.AsSpan(0, total).ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Pulls the version out of a release, refusing anything not fit to offer as an update.
    /// </summary>
    /// <remarks>
    /// Drafts and pre-releases are rejected outright: <c>/releases/latest</c> is documented to exclude both, and
    /// the fields are checked anyway rather than relying on that.
    /// </remarks>
    private UpdateCheckResult? ParseLatest(byte[] payload)
    {
        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            _log.Warning("更新检查收到非预期的响应结构。");
            return null;
        }

        if (root.TryGetProperty("draft", out var draft) &&
            draft.ValueKind == JsonValueKind.True)
        {
            return null;
        }

        if (root.TryGetProperty("prerelease", out var prerelease) &&
            prerelease.ValueKind == JsonValueKind.True)
        {
            return null;
        }

        if (!root.TryGetProperty("tag_name", out var tag) ||
            tag.ValueKind != JsonValueKind.String ||
            tag.GetString() is not { Length: > 0 } tagText)
        {
            _log.Warning("更新检查：发布没有可用的版本标签。");
            return null;
        }

        if (!TryParseReleaseTag(tagText, out var latest))
        {
            // A tag that is not a version is the repository's business, not something to report as an update.
            _log.Warning("更新检查：版本标签无法解析为版本号。");
            return null;
        }

        return new UpdateCheckResult(latest, latest > ProductIdentity.CurrentVersion);
    }

    /// <summary>
    /// Reads a release tag as a version, tolerating the conventional leading "v".
    /// </summary>
    /// <remarks>
    /// Normalised to three fields for the reason <see cref="ProductIdentity.CurrentVersion"/> documents: a tag
    /// of "2.1" parses with Build = -1, which compares below 2.1.0 and would hide a real update.
    /// </remarks>
    private static bool TryParseReleaseTag(string tag, out Version version)
    {
        version = new Version(0, 0, 0);
        var trimmed = tag.Trim();
        if (trimmed.Length > 0 && (trimmed[0] == 'v' || trimmed[0] == 'V'))
        {
            trimmed = trimmed[1..];
        }

        // A tag can carry a suffix the API does not model as a pre-release flag, e.g. "2.1.0-rc1". Anything
        // beyond the numeric version is refused rather than guessed at.
        if (!Version.TryParse(trimmed, out var parsed))
        {
            return false;
        }

        version = new Version(
            parsed.Major,
            parsed.Minor,
            parsed.Build < 0 ? 0 : parsed.Build);
        return true;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _http.Dispose();
        _gate.Dispose();
    }
}
