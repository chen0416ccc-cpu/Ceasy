using CodexGuardian.Services;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

/// <summary>
/// Offline coverage for the only outbound request this program makes. Every case is answered by a stub
/// handler, so the suite never opens a socket: what is under test is the decision the service reaches about
/// a response, not whether GitHub is reachable.
/// </summary>
internal static class UpdateCheckOfflineTests
{
    private const string TestDataRootEnvironmentVariable = "CODEX_GUARDIAN_TEST_DATA_ROOT";

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "update check reads the release tag, tolerates a v prefix, and compares it against this build",
            TestTagParsingAsync,
            assert);
        await RunCaseAsync(
            "update check ignores drafts and prereleases instead of offering them as updates",
            TestDraftAndPrereleaseAsync,
            assert);
        await RunCaseAsync(
            "update check degrades to no answer on 404, on an unusable tag, and on malformed json",
            TestFailureModesAsync,
            assert);
        await RunCaseAsync(
            "update check asks at most once a day, and a forced check bypasses that interval",
            TestThrottleAsync,
            assert);
        await RunCaseAsync(
            "update check identifies itself, asks for the pinned api version, and bounds what it reads",
            TestRequestShapeAsync,
            assert);
        await RunCaseAsync(
            "update check result carries no url from the response, so nothing network-supplied can be launched",
            TestResultCarriesNoUrlAsync,
            assert);
    }

    private static async Task TestTagParsingAsync()
    {
        var current = ProductIdentity.CurrentVersion;
        Ensure(current > new Version(0, 0, 1), "This build's version should be above the floor used below.");
        var newer = new Version(current.Major, current.Minor, current.Build + 1);

        using var fixture = Fixture.Serving(ReleaseJson("v" + newer.ToString(3)));
        var result = await fixture.Service.CheckAsync(force: true, CancellationToken.None);
        Ensure(result is not null, "A well-formed release should produce a result.");
        Ensure(
            result!.LatestVersion == newer,
            "The v prefix should be stripped, giving " + newer.ToString(3) + " but got " + result.LatestVersionText + ".");
        Ensure(result.IsNewerThanCurrent, "A higher tag than this build should count as newer.");

        using var same = Fixture.Serving(ReleaseJson(current.ToString(3)));
        var sameResult = await same.Service.CheckAsync(force: true, CancellationToken.None);
        Ensure(sameResult is not null, "An equal tag is still a usable answer.");
        Ensure(!sameResult!.IsNewerThanCurrent, "An equal tag is not an update.");

        using var older = Fixture.Serving(ReleaseJson("0.0.1"));
        var olderResult = await older.Service.CheckAsync(force: true, CancellationToken.None);
        Ensure(olderResult is not null, "A lower tag is still a usable answer.");
        Ensure(!olderResult!.IsNewerThanCurrent, "A lower tag must never be offered as an update.");

        // Two-part tags are what a repository that tags "2.1" produces. Version.TryParse accepts them and
        // leaves Build at -1, which would compare as lower than any three-part version of the same release.
        using var twoPart = Fixture.Serving(ReleaseJson(current.Major + "." + (current.Minor + 1)));
        var twoPartResult = await twoPart.Service.CheckAsync(force: true, CancellationToken.None);
        Ensure(twoPartResult is not null, "A two-part tag should still parse.");
        Ensure(
            twoPartResult!.LatestVersion.Build == 0,
            "A missing build field should normalize to 0, not stay at -1.");
        Ensure(twoPartResult.IsNewerThanCurrent, "A higher minor version is an update.");
    }

    private static async Task TestDraftAndPrereleaseAsync()
    {
        var current = ProductIdentity.CurrentVersion;
        var newer = new Version(current.Major, current.Minor + 1, 0).ToString(3);

        using var draft = Fixture.Serving(ReleaseJson(newer, draft: true));
        Ensure(
            await draft.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A draft is not published; offering it would send users to a page they cannot download from.");

        using var prerelease = Fixture.Serving(ReleaseJson(newer, prerelease: true));
        Ensure(
            await prerelease.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A prerelease is opt-in; it must not be pushed at everyone as the newest version.");

        // Both flags absent is the shape of a hand-made release payload, and must still be accepted.
        using var bare = Fixture.Serving("{\"tag_name\":\"" + newer + "\"}");
        Ensure(
            await bare.Service.CheckAsync(force: true, CancellationToken.None) is not null,
            "A release with neither flag present is a normal release.");
    }

    private static async Task TestFailureModesAsync()
    {
        using var missing = Fixture.Responding(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        Ensure(
            await missing.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A repository with no releases yet is not an error the user needs to see.");

        using var rateLimited = Fixture.Responding(_ => new HttpResponseMessage(HttpStatusCode.Forbidden));
        Ensure(
            await rateLimited.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A refused request yields no answer rather than a wrong one.");

        using var unusableTag = Fixture.Serving(ReleaseJson("nightly-2026-09-03"));
        Ensure(
            await unusableTag.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A tag that is not a version number cannot be compared, so there is nothing to report.");

        using var emptyTag = Fixture.Serving("{\"tag_name\":\"\",\"draft\":false,\"prerelease\":false}");
        Ensure(
            await emptyTag.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "An empty tag is not a version.");

        using var wrongType = Fixture.Serving("{\"tag_name\":12}");
        Ensure(
            await wrongType.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A tag that is not a string must not be coerced.");

        using var notAnObject = Fixture.Serving("[\"2.9.0\"]");
        Ensure(
            await notAnObject.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "An array where an object was expected is a malformed answer.");

        using var malformed = Fixture.Serving("{\"tag_name\":");
        Ensure(
            await malformed.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "Truncated json must be swallowed, not thrown at the caller.");

        using var empty = Fixture.Serving(string.Empty);
        Ensure(
            await empty.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "An empty body is not an answer.");

        using var thrown = Fixture.Responding(_ => throw new HttpRequestException("offline"));
        Ensure(
            await thrown.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "No network is the normal case on a machine that is offline, not a failure to surface.");
    }

    private static async Task TestThrottleAsync()
    {
        var current = ProductIdentity.CurrentVersion;
        var newer = new Version(current.Major, current.Minor + 1, 0).ToString(3);
        using var fixture = Fixture.Serving(ReleaseJson(newer));

        var first = await fixture.Service.CheckAsync(force: false, CancellationToken.None);
        Ensure(first is not null, "The first check should reach the stub.");
        Ensure(fixture.Handler.RequestCount == 1, "The first check should send exactly one request.");

        var second = await fixture.Service.CheckAsync(force: false, CancellationToken.None);
        Ensure(
            fixture.Handler.RequestCount == 1,
            "A second check inside the daily window must be served from the cached answer.");
        Ensure(
            second is not null && second.LatestVersion == first!.LatestVersion,
            "The cached answer should be the same answer, not an empty one.");
        Ensure(
            fixture.Service.LastResult is not null
                && fixture.Service.LastResult.LatestVersion == first!.LatestVersion,
            "LastResult is what the UI reads when it does not want to trigger a request.");

        var forced = await fixture.Service.CheckAsync(force: true, CancellationToken.None);
        Ensure(fixture.Handler.RequestCount == 2, "A forced check must ignore the interval.");
        Ensure(forced is not null, "A forced check still returns the answer.");

        // A failed forced check still counts as an attempt: otherwise a machine that is offline would retry
        // on every window activation for as long as it stayed offline.
        using var failing = Fixture.Responding(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        Ensure(
            await failing.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A 503 is not an answer.");
        Ensure(
            await failing.Service.CheckAsync(force: false, CancellationToken.None) is null,
            "The unforced retry after a failure stays quiet.");
        Ensure(
            failing.Handler.RequestCount == 1,
            "A failure still starts the daily interval, so an offline machine does not retry in a loop.");
    }

    private static async Task TestRequestShapeAsync()
    {
        var current = ProductIdentity.CurrentVersion;
        var newer = new Version(current.Major, current.Minor + 1, 0).ToString(3);
        using var fixture = Fixture.Serving(ReleaseJson(newer));
        await fixture.Service.CheckAsync(force: true, CancellationToken.None);

        var request = fixture.Handler.LastRequest;
        Ensure(request is not null, "The stub should have seen a request.");
        Ensure(request!.Method == HttpMethod.Get, "Checking for a version is a read.");
        Ensure(
            string.Equals(
                request.RequestUri?.ToString(),
                ProductIdentity.LatestReleaseApiUrl,
                StringComparison.Ordinal),
            "The url must be the compile-time constant, not anything assembled at runtime.");
        Ensure(
            request.RequestUri!.Scheme == Uri.UriSchemeHttps,
            "The request must be over https.");

        var userAgent = request.Headers.UserAgent.ToString();
        Ensure(userAgent.Length > 0, "GitHub answers 403 to an anonymous request with no user agent.");
        Ensure(
            userAgent.Contains(ProductIdentity.RepositoryName, StringComparison.Ordinal)
                && userAgent.Contains(ProductIdentity.CurrentVersionText, StringComparison.Ordinal),
            "The user agent should say what this is and which build.");
        // Exactly the compile-time constant, which is the testable form of "nothing about this machine or
        // its user is in the request": there is no runtime input to the header at all.
        Ensure(
            string.Equals(userAgent, ProductIdentity.UserAgent, StringComparison.Ordinal),
            "The user agent must be exactly the declared product identity, but was: " + userAgent);
        Ensure(
            request.Headers.TryGetValues("X-GitHub-Api-Version", out var pinned)
                && pinned.Contains("2022-11-28"),
            "The api version is pinned so a future default cannot change the response shape underneath us.");
        Ensure(request.Content is null, "A GET carries no body.");

        // A release body has no documented ceiling. The read is bounded, and a body past the bound is
        // truncated mid-token, which lands in the malformed-json path rather than allocating without limit.
        var oversized = "{\"tag_name\":\"" + newer + "\",\"body\":\"" + new string('x', 512 * 1024) + "\"}";
        using var huge = Fixture.Serving(oversized);
        Ensure(
            await huge.Service.CheckAsync(force: true, CancellationToken.None) is null,
            "A body past the read ceiling is truncated and then rejected, not read to the end.");
    }

    private static async Task TestResultCarriesNoUrlAsync()
    {
        var current = ProductIdentity.CurrentVersion;
        var newer = new Version(current.Major, current.Minor + 1, 0).ToString(3);

        // The response deliberately offers a url. Nothing may pick it up: the click target is the compile-time
        // constant, because Process.Start on a url from a response hands the shell-execute target to whoever
        // answered the request.
        using var fixture = Fixture.Serving(
            "{\"tag_name\":\"" + newer + "\",\"draft\":false,\"prerelease\":false,"
                + "\"html_url\":\"file:///C:/Windows/System32/calc.exe\"}");
        var result = await fixture.Service.CheckAsync(force: true, CancellationToken.None);
        Ensure(result is not null, "The release itself is well-formed.");

        foreach (var property in result!.GetType().GetProperties())
        {
            var text = property.GetValue(result)?.ToString() ?? string.Empty;
            Ensure(
                !text.Contains("calc.exe", StringComparison.OrdinalIgnoreCase)
                    && !text.Contains("file:", StringComparison.OrdinalIgnoreCase)
                    && !text.Contains("http", StringComparison.OrdinalIgnoreCase),
                "Property " + property.Name + " carried a url out of the response: " + text);
        }

        Ensure(
            ProductIdentity.ReleasesUrl.StartsWith(
                "https://github.com/" + ProductIdentity.RepositoryOwner + "/" + ProductIdentity.RepositoryName,
                StringComparison.Ordinal),
            "The only url the app opens is built from constants under the configured repository.");
    }

    private static string ReleaseJson(string tag, bool draft = false, bool prerelease = false) =>
        "{\"tag_name\":\"" + tag + "\",\"draft\":" + (draft ? "true" : "false")
            + ",\"prerelease\":" + (prerelease ? "true" : "false") + "}";

    private static string CreateRoot()
    {
        var parent = Environment.GetEnvironmentVariable(TestDataRootEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException(TestDataRootEnvironmentVariable + " is required.");
        }

        return Path.Combine(parent, "u-" + Guid.NewGuid().ToString("N")[..8]);
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name} - {exception.Message}");
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root;

        private Fixture(string root, StubHandler handler, UpdateCheckService service)
        {
            _root = root;
            Handler = handler;
            Service = service;
        }

        internal StubHandler Handler { get; }

        internal UpdateCheckService Service { get; }

        internal static Fixture Serving(string json) => Responding(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });

        internal static Fixture Responding(Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            var root = CreateRoot();
            Directory.CreateDirectory(root);
            var handler = new StubHandler(respond);
            return new Fixture(root, handler, new UpdateCheckService(new GuardianLog(root), handler));
        }

        public void Dispose()
        {
            Service.Dispose();
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
                // The log file may still be held; a leftover directory under the test root is harmless.
            }
        }
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        private int _requestCount;

        internal StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

        internal int RequestCount => Volatile.Read(ref _requestCount);

        internal HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            LastRequest = request;
            return Task.FromResult(_respond(request));
        }
    }
}
