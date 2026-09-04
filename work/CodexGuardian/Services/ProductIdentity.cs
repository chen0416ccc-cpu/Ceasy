using System;
using System.Globalization;
using System.Reflection;

namespace CodexGuardian.Services;

/// <summary>
/// Where this build came from and what it calls itself.
/// </summary>
/// <remarks>
/// One place, because the same two facts are needed by the project link in the shell, the update check, the
/// outbound User-Agent, and the release notes URL. Spelling the repository out at each of those meant a rename
/// would leave some of them pointing at nothing, and the update check would keep succeeding against the old
/// repository rather than failing visibly.
///
/// The version is read from the assembly rather than restated here. <c>CodexGuardian.csproj</c> already owns it
/// as <c>&lt;Version&gt;</c>, and the installer reads that same property, so a constant here would be a third
/// copy able to disagree with both.
/// </remarks>
internal static class ProductIdentity
{
    /// <summary>GitHub account that owns the repository.</summary>
    internal const string RepositoryOwner = "chen0416ccc-cpu";

    /// <summary>Repository name, which is also the product name.</summary>
    internal const string RepositoryName = "Ceasy";

    /// <summary>The project's home page, opened from the shell.</summary>
    internal const string RepositoryUrl = "https://github.com/" + RepositoryOwner + "/" + RepositoryName;

    /// <summary>Where a user lands to download a newer build.</summary>
    internal const string ReleasesUrl = RepositoryUrl + "/releases/latest";

    /// <summary>
    /// The one endpoint this app talks to, and only when the update check is on.
    /// </summary>
    /// <remarks>
    /// The REST API rather than an Atom feed: it reports <c>draft</c> and <c>prerelease</c> as their own fields,
    /// and the feed does not, so a feed reader would offer a pre-release build as an update.
    /// </remarks>
    internal const string LatestReleaseApiUrl =
        "https://api.github.com/repos/" + RepositoryOwner + "/" + RepositoryName + "/releases/latest";

    /// <summary>
    /// This build's version, three parts, no build number.
    /// </summary>
    /// <remarks>
    /// Trimmed to major.minor.patch because that is what release tags carry. Comparing the assembly's four-part
    /// version against a three-part tag made every check report an update: 2.0.0.0 is not 2.0.0 as text, and as
    /// a <see cref="Version"/> the missing fourth field compares as -1 rather than 0.
    /// </remarks>
    internal static Version CurrentVersion { get; } = ResolveCurrentVersion();

    /// <summary>This build's version as it is shown to the user.</summary>
    internal static string CurrentVersionText { get; } = CurrentVersion.ToString(3);

    /// <summary>
    /// The User-Agent GitHub requires. Without one the API answers 403 rather than rate-limiting.
    /// </summary>
    /// <remarks>
    /// Product and version only, plus the repository so an operator reading GitHub's logs can tell what this
    /// is. Nothing about the machine or the user: this is the only outbound request the app makes, and it
    /// carries no more than it must to be served.
    /// </remarks>
    internal static string UserAgent { get; } =
        string.Format(
            CultureInfo.InvariantCulture,
            "{0}/{1} (+{2})",
            RepositoryName,
            CurrentVersionText,
            RepositoryUrl);

    private static Version ResolveCurrentVersion()
    {
        var assembly = typeof(ProductIdentity).Assembly;

        // AssemblyInformationalVersion is what <Version> lands in, and it survives as "2.0.0" rather than being
        // padded to four fields. It can carry a "+sha" suffix from source-link builds, so it is cut at the plus.
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+');
            var trimmed = plus >= 0 ? informational[..plus] : informational;
            if (Version.TryParse(trimmed, out var parsed))
            {
                return Normalize(parsed);
            }
        }

        return Normalize(assembly.GetName().Version ?? new Version(0, 0, 0));
    }

    /// <summary>
    /// Flattens a version to three defined fields so two of them compare on equal terms.
    /// </summary>
    private static Version Normalize(Version version) => new(
        version.Major,
        version.Minor,
        version.Build < 0 ? 0 : version.Build);
}
