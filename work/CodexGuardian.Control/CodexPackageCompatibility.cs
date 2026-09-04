using System;

namespace CodexGuardian.Control;

internal enum CodexPackageTrustMode
{
    StoreOnly,
    AllowCompatibleSignedPatch
}

internal enum CodexPackageTrustClass
{
    OfficialStore,
    SignedPatchCandidate
}

internal sealed record CodexPackageCompatibilityPolicy
{
    internal CodexPackageCompatibilityPolicy(
        string packageName,
        string packageFamilyName,
        string packagePublisher,
        string packageArchitecture)
    {
        PackageName = RequireBounded(packageName, nameof(packageName), 128);
        PackageFamilyName = RequireBounded(packageFamilyName, nameof(packageFamilyName), 192);
        PackagePublisher = RequireBounded(packagePublisher, nameof(packagePublisher), 512);
        PackageArchitecture = RequireBounded(packageArchitecture, nameof(packageArchitecture), 32);
        if (!PackageFamilyName.StartsWith(PackageName + "_", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The package family must be derived from the stable package name.",
                nameof(packageFamilyName));
        }
    }

    internal string PackageName { get; }

    internal string PackageFamilyName { get; }

    internal string PackagePublisher { get; }

    internal string PackageArchitecture { get; }

    private static string RequireBounded(string value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
        {
            throw new ArgumentException("A bounded non-empty value is required.", parameterName);
        }

        return value;
    }
}

internal sealed record CodexPackageTrustDecision
{
    internal CodexPackageTrustDecision(
        CodexPackageTrustClass trustClass,
        CodexPackageTrustMode trustMode)
    {
        if (!Enum.IsDefined(trustClass))
        {
            throw new ArgumentOutOfRangeException(nameof(trustClass));
        }

        if (!Enum.IsDefined(trustMode))
        {
            throw new ArgumentOutOfRangeException(nameof(trustMode));
        }

        TrustClass = trustClass;
        TrustMode = trustMode;
    }

    internal CodexPackageTrustClass TrustClass { get; }

    internal CodexPackageTrustMode TrustMode { get; }
}
