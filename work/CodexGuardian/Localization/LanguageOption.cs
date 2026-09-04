using CodexGuardian.Infrastructure;

namespace CodexGuardian.Localization;

public sealed class LanguageOption : ObservableObject
{
    private readonly LocalizationService _localization;
    private readonly string _displayNameKey;

    internal LanguageOption(LocalizationService localization, string code, string displayNameKey)
    {
        _localization = localization;
        Code = code;
        _displayNameKey = displayNameKey;
    }

    public string Code { get; }

    public string DisplayName => _localization[_displayNameKey];

    internal void Refresh() => OnPropertyChanged(nameof(DisplayName));
}
