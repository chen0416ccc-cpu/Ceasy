using CodexGuardian.Infrastructure;

namespace CodexGuardian.ViewModels;

/// <summary>
/// A section heading on the keep-alive page: pinned, one project, recent, or archived.
/// </summary>
/// <remarks>
/// The keep-alive list carries the same grouping as the conversation index because it lists the same
/// conversations, and a user who has learned where a conversation lives on one page should not have to
/// re-learn it on the other. Collapse state is owned here and survives a refresh, so a section the user
/// closed does not reopen on the next monitor pass.
/// </remarks>
public sealed class KeepAliveSectionViewModel : ObservableObject
{
    private readonly Action<string, bool> _applyExpanded;
    private bool _isExpanded;
    private int _count;
    private int _heldCount;

    public KeepAliveSectionViewModel(
        string key,
        string title,
        bool isProject,
        bool isExpanded,
        Action<string, bool> applyExpanded)
    {
        Key = key ?? throw new ArgumentNullException(nameof(key));
        Title = title ?? string.Empty;
        IsProject = isProject;
        _isExpanded = isExpanded;
        _applyExpanded = applyExpanded ?? throw new ArgumentNullException(nameof(applyExpanded));
    }

    public string Key { get; }

    public string Title { get; }

    /// <summary>
    /// True for a project heading, which is indented one level under the projects section.
    /// </summary>
    /// <remarks>
    /// A project is a heading here, not a drill-down row as it is in the navigation index. This page
    /// exists to set a flag per conversation, and making the user open a project first to reach its
    /// conversations would put a navigation step in front of every switch.
    /// </remarks>
    public bool IsProject { get; }

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (_isExpanded == value)
            {
                return;
            }

            _isExpanded = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ExpandGlyph));
            _applyExpanded(Key, value);
        }
    }

    /// <summary>Chevron down when open, right when closed. Matches the conversation index.</summary>
    public string ExpandGlyph => IsExpanded ? "" : "";

    public int Count
    {
        get => _count;
        set
        {
            if (SetProperty(ref _count, value))
            {
                OnPropertyChanged(nameof(CountText));
            }
        }
    }

    /// <summary>How many conversations in this section are currently held.</summary>
    public int HeldCount
    {
        get => _heldCount;
        set
        {
            if (SetProperty(ref _heldCount, value))
            {
                OnPropertyChanged(nameof(CountText));
                OnPropertyChanged(nameof(HasHeld));
            }
        }
    }

    public bool HasHeld => _heldCount > 0;

    /// <summary>
    /// Held-over-total, or just the total when none are held.
    /// </summary>
    /// <remarks>
    /// A bare total says nothing a glance down the rows would not; held-over-total answers the question
    /// the page is for without needing the section open.
    /// </remarks>
    public string CountText => _heldCount > 0
        ? _heldCount.ToString() + "/" + _count.ToString()
        : _count.ToString();
}
