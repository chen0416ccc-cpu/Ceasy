using CodexGuardian.Infrastructure;

namespace CodexGuardian.Models;

public enum WorkflowLineageTone
{
    Neutral,
    Active,
    Success,
    Warning,
    Danger
}

internal sealed record WorkflowLineageDisplayProjection(
    string StableRef,
    string AutomationId,
    string AutomationName,
    string KindText,
    string RouteText,
    string MetaText,
    string StateText,
    string FailureText,
    string NextActionText,
    string TimeText,
    string CorrelationText,
    double IndentWidth,
    bool IsCorrelationStart,
    WorkflowLineageTone Tone);

public sealed class WorkflowLineageDisplayItem : ObservableObject
{
    private WorkflowLineageDisplayProjection _projection;

    internal WorkflowLineageDisplayItem(WorkflowLineageDisplayProjection projection)
    {
        _projection = projection ?? throw new ArgumentNullException(nameof(projection));
    }

    public string StableRef => _projection.StableRef;

    public string AutomationId => _projection.AutomationId;

    public string AutomationName => _projection.AutomationName;

    public string KindText => _projection.KindText;

    public string RouteText => _projection.RouteText;

    public string MetaText => _projection.MetaText;

    public string StateText => _projection.StateText;

    public string FailureText => _projection.FailureText;

    public string NextActionText => _projection.NextActionText;

    public string TimeText => _projection.TimeText;

    public string CorrelationText => _projection.CorrelationText;

    public double IndentWidth => _projection.IndentWidth;

    public bool IsCorrelationStart => _projection.IsCorrelationStart;

    public WorkflowLineageTone Tone => _projection.Tone;

    internal bool UpdateFrom(WorkflowLineageDisplayProjection projection)
    {
        ArgumentNullException.ThrowIfNull(projection);
        if (!string.Equals(StableRef, projection.StableRef, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Lineage display identity cannot change in place.");
        }

        if (_projection == projection)
        {
            return false;
        }

        _projection = projection;
        OnPropertyChanged(string.Empty);
        return true;
    }
}
