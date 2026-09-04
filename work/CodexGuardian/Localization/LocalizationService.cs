using System.Globalization;
using System.Resources;
using CodexGuardian.Infrastructure;

namespace CodexGuardian.Localization;

public sealed class LocalizationService : ObservableObject
{
    private static readonly ResourceManager ResourceManager = new(
        "CodexGuardian.Localization.AppStrings",
        typeof(LocalizationService).Assembly);

    private readonly IReadOnlyList<LanguageOption> _availableLanguages;
    private string _languageCode;
    private CultureInfo _currentCulture;

    public LocalizationService()
        : this(UiLanguages.SimplifiedChinese)
    {
    }

    public LocalizationService(string? languageCode)
    {
        _languageCode = UiLanguages.Normalize(languageCode);
        _currentCulture = CultureInfo.GetCultureInfo(_languageCode);
        ApplyCulture(_currentCulture);
        _availableLanguages =
        [
            new LanguageOption(this, UiLanguages.SimplifiedChinese, "Language.SimplifiedChinese"),
            new LanguageOption(this, UiLanguages.English, "Language.English")
        ];
    }

    public event EventHandler<LanguageChangedEventArgs>? LanguageChanged;

    public IReadOnlyList<LanguageOption> AvailableLanguages => _availableLanguages;

    public string LanguageCode
    {
        get => _languageCode;
        set => SetLanguage(value);
    }

    public CultureInfo CurrentCulture => _currentCulture;

    public string this[string key] => GetString(key);

    public bool SetLanguage(string? languageCode)
    {
        var normalized = UiLanguages.Normalize(languageCode);
        if (string.Equals(_languageCode, normalized, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var previousLanguageCode = _languageCode;
        _languageCode = normalized;
        _currentCulture = CultureInfo.GetCultureInfo(normalized);
        ApplyCulture(_currentCulture);

        foreach (var option in _availableLanguages)
        {
            option.Refresh();
        }

        OnPropertyChanged(nameof(LanguageCode));
        OnPropertyChanged(nameof(CurrentCulture));
        OnPropertyChanged("Item[]");
        LanguageChanged?.Invoke(this, new LanguageChangedEventArgs(previousLanguageCode, normalized));
        return true;
    }

    public string GetString(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        return ResourceManager.GetString(key, _currentCulture) ?? key;
    }

    public string Format(string key, params object?[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        return string.Format(_currentCulture, GetString(key), arguments);
    }

    private static void ApplyCulture(CultureInfo culture)
    {
        CultureInfo.DefaultThreadCurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;
    }
}
