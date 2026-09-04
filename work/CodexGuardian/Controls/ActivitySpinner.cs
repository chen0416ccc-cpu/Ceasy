using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

// CodexGuardian.Control is a sibling project, so the unqualified name binds to that namespace instead
// of the WPF base class.
using WpfControl = System.Windows.Controls.Control;

namespace CodexGuardian.Controls;

/// <summary>
/// The rotating arc that marks a conversation as running right now.
/// </summary>
/// <remarks>
/// This exists because the obvious XAML spelling of it does not survive a virtualized list. Driving
/// the rotation from <c>DataTrigger.EnterActions</c> makes spinning an edge, and a recycled container
/// never produces that edge: it keeps its visual tree and swaps DataContext, so a row that scrolls
/// into view already running shows a frozen arc. The same thing happens on a collection Reset, which
/// rebinds every container at once and stops every spinner in the list.
///
/// So rotation is a state instead of an edge. <see cref="IsActive"/> is the state, and the animation
/// is re-applied from whatever that state currently is on every occasion the state and the visual can
/// drift apart: the property changing, the element loading, and the element becoming visible again.
/// Rebinding a recycled container raises none of those on its own, but it does write IsActive through
/// the binding, which is the case that matters.
/// </remarks>
public sealed class ActivitySpinner : WpfControl
{
    private const double RevolutionSeconds = 0.9;

    private readonly RotateTransform _rotation = new();

    public static readonly DependencyProperty IsActiveProperty = DependencyProperty.Register(
        nameof(IsActive),
        typeof(bool),
        typeof(ActivitySpinner),
        new PropertyMetadata(false, OnIsActiveChanged));

    public static readonly DependencyProperty TrackOpacityProperty = DependencyProperty.Register(
        nameof(TrackOpacity),
        typeof(double),
        typeof(ActivitySpinner),
        new PropertyMetadata(0.22));

    static ActivitySpinner() =>
        DefaultStyleKeyProperty.OverrideMetadata(
            typeof(ActivitySpinner),
            new FrameworkPropertyMetadata(typeof(ActivitySpinner)));

    public ActivitySpinner()
    {
        RenderTransformOrigin = new Point(0.5, 0.5);
        RenderTransform = _rotation;
        Loaded += (_, _) => SyncAnimation();
        Unloaded += (_, _) => StopAnimation();
        IsVisibleChanged += (_, _) => SyncAnimation();
    }

    /// <summary>Whether the arc should be turning.</summary>
    public bool IsActive
    {
        get => (bool)GetValue(IsActiveProperty);
        set => SetValue(IsActiveProperty, value);
    }

    /// <summary>Opacity of the static ring the arc travels over.</summary>
    public double TrackOpacity
    {
        get => (double)GetValue(TrackOpacityProperty);
        set => SetValue(TrackOpacityProperty, value);
    }

    private static void OnIsActiveChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args) =>
        ((ActivitySpinner)sender).SyncAnimation();

    private void SyncAnimation()
    {
        // An off-screen spinner still costs a composition tick per frame, so only the ones the user can
        // actually see are left running.
        if (IsActive && IsVisible)
        {
            StartAnimation();
            return;
        }

        StopAnimation();
    }

    private void StartAnimation()
    {
        var spin = new DoubleAnimation
        {
            From = 0,
            To = 360,
            Duration = TimeSpan.FromSeconds(RevolutionSeconds),
            RepeatBehavior = RepeatBehavior.Forever,
        };

        _rotation.BeginAnimation(RotateTransform.AngleProperty, spin);
    }

    private void StopAnimation()
    {
        // Clearing rather than holding the last animated value: leaving a stopped arc at an arbitrary
        // angle reads as an interrupted spinner rather than an idle one.
        _rotation.BeginAnimation(RotateTransform.AngleProperty, null);
        _rotation.Angle = 0;
    }
}
