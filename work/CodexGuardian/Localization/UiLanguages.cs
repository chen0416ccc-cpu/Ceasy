namespace CodexGuardian.Localization;

public static class UiLanguages
{
    public const string SimplifiedChinese = "zh-CN";

    public const string English = "en";

    public static IReadOnlyList<string> SupportedCodes { get; } = [SimplifiedChinese, English];

    public static bool IsSupported(string? languageCode)
    {
        if (string.IsNullOrWhiteSpace(languageCode))
        {
            return false;
        }

        var value = languageCode.Trim();
        return value.Equals(SimplifiedChinese, StringComparison.OrdinalIgnoreCase) ||
               value.Equals("zh-Hans", StringComparison.OrdinalIgnoreCase) ||
               value.Equals(English, StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("en-", StringComparison.OrdinalIgnoreCase);
    }

    public static string Normalize(string? languageCode)
    {
        if (string.IsNullOrWhiteSpace(languageCode))
        {
            return SimplifiedChinese;
        }

        var value = languageCode.Trim();
        if (value.Equals(English, StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("en-", StringComparison.OrdinalIgnoreCase))
        {
            return English;
        }

        return SimplifiedChinese;
    }
}
