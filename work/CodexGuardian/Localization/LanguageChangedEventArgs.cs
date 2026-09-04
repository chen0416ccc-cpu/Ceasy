namespace CodexGuardian.Localization;

public sealed class LanguageChangedEventArgs : EventArgs
{
    public LanguageChangedEventArgs(string previousLanguageCode, string languageCode)
    {
        PreviousLanguageCode = previousLanguageCode;
        LanguageCode = languageCode;
    }

    public string PreviousLanguageCode { get; }

    public string LanguageCode { get; }
}
