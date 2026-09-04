using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace CodexGuardian.Controls;

/// <summary>
/// Makes a changing number visible: the element carrying the count swells and settles whenever the
/// watched value changes.
/// </summary>
/// <remarks>
/// The counts in this app move on their own - a monitor pass finds a new conversation needing
/// attention, a resend lands, a queue drains - so the number is often already different by the time
/// the user looks back at it. Nothing in the visual tree marked the moment it changed, which is a
/// large part of why the shell felt static even though page transitions were animated.
///
/// It is an attached property rather than a control because the call sites are plain
/// <c>TextBlock</c>s inside buttons and headers whose foreground is inherited from the button; a
/// wrapper control would break that inheritance chain.
///
/// Do not attach this inside a virtualized list. A recycled container keeps its visual tree and
/// swaps DataContext, which writes a new value through the binding and is indistinguishable from a
/// real change - every row would pulse while the user scrolled. Use it on fixed chrome: filter
/// segments, headers, summary tiles.
/// </remarks>
public static class CountPulse
{
    /// <summary>
    /// Bind this to the same value the element displays. Changes to it drive the pulse; the initial
    /// bind does not.
    /// </summary>
    public static readonly DependencyProperty WatchProperty = DependencyProperty.RegisterAttached(
        "Watch",
        typeof(object),
        typeof(CountPulse),
        new PropertyMetadata(null, OnWatchChanged));

    public static void SetWatch(DependencyObject element, object? value) =>
        element.SetValue(WatchProperty, value);

    public static object? GetWatch(DependencyObject element) => element.GetValue(WatchProperty);

    private static void OnWatchChanged(DependencyObject element, DependencyPropertyChangedEventArgs args)
    {
        // The first write is the binding arriving, not the number moving.
        if (args.OldValue is null || Equals(args.OldValue, args.NewValue))
        {
            return;
        }

        if (element is not FrameworkElement target || !target.IsLoaded)
        {
            return;
        }

        if (!SystemParameters.ClientAreaAnimation)
        {
            return;
        }

        // Identity is a frozen MatrixTransform, so the first pulse installs a live ScaleTransform.
        // Anything else already there is left alone rather than overwritten - a call site with its
        // own transform gets no pulse instead of losing its layout.
        if (target.RenderTransform is not ScaleTransform scale)
        {
            if (target.RenderTransform is not null &&
                !ReferenceEquals(target.RenderTransform, Transform.Identity))
            {
                return;
            }

            scale = new ScaleTransform(1d, 1d);
            target.RenderTransform = scale;
            target.RenderTransformOrigin = new Point(0.5d, 0.5d);
        }

        // FillBehavior.Stop hands the property back to its base value at the end, so a long-lived
        // element does not accumulate held animation values across hundreds of monitor passes.
        var pulse = new DoubleAnimationUsingKeyFrames { FillBehavior = FillBehavior.Stop };
        pulse.KeyFrames.Add(new EasingDoubleKeyFrame(
            1.34d,
            KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(130)),
            new CubicEase { EasingMode = EasingMode.EaseOut }));
        pulse.KeyFrames.Add(new EasingDoubleKeyFrame(
            1d,
            KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(430)),
            new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.5d }));

        scale.BeginAnimation(ScaleTransform.ScaleXProperty, pulse);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, pulse);
    }
}
