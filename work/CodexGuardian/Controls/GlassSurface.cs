using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace CodexGuardian.Controls;

public sealed class GlassSurface : Border
{
    public static readonly DependencyProperty IsInteractiveProperty = DependencyProperty.Register(
        nameof(IsInteractive), typeof(bool), typeof(GlassSurface),
        new PropertyMetadata(false, static (sender, _) => ((GlassSurface)sender).ResetMotion()));

    public static readonly DependencyProperty ElevationProperty = DependencyProperty.Register(
        nameof(Elevation), typeof(double), typeof(GlassSurface),
        new FrameworkPropertyMetadata(12d, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ReflectionBrushProperty = DependencyProperty.Register(
        nameof(ReflectionBrush), typeof(Brush), typeof(GlassSurface),
        new FrameworkPropertyMetadata(Brushes.Transparent, FrameworkPropertyMetadataOptions.AffectsRender));

    private TranslateTransform? _lift;
    private ScaleTransform? _press;

    public GlassSurface()
    {
        Unloaded += (_, _) => ResetMotion();
        IsEnabledChanged += (_, _) => ResetMotion();
    }

    public bool IsInteractive
    {
        get => (bool)GetValue(IsInteractiveProperty);
        set => SetValue(IsInteractiveProperty, value);
    }

    public double Elevation
    {
        get => (double)GetValue(ElevationProperty);
        set => SetValue(ElevationProperty, value);
    }

    public Brush ReflectionBrush
    {
        get => (Brush)GetValue(ReflectionBrushProperty);
        set => SetValue(ReflectionBrushProperty, value);
    }

    protected override void OnMouseEnter(MouseEventArgs args)
    {
        base.OnMouseEnter(args);
        AnimateMotion(pressed: false);
    }

    protected override void OnMouseLeave(MouseEventArgs args)
    {
        base.OnMouseLeave(args);
        AnimateMotion(pressed: false);
    }

    protected override void OnPreviewMouseLeftButtonDown(MouseButtonEventArgs args)
    {
        base.OnPreviewMouseLeftButtonDown(args);
        AnimateMotion(pressed: true);
    }

    protected override void OnPreviewMouseLeftButtonUp(MouseButtonEventArgs args)
    {
        base.OnPreviewMouseLeftButtonUp(args);
        AnimateMotion(pressed: false);
    }

    protected override void OnLostMouseCapture(MouseEventArgs args)
    {
        base.OnLostMouseCapture(args);
        AnimateMotion(pressed: false);
    }

    private void AnimateMotion(bool pressed)
    {
        if (!IsInteractive || !IsEnabled || !IsLoaded || !SystemParameters.ClientAreaAnimation)
        {
            ResetMotion();
            return;
        }

        if (_lift is null || _press is null)
        {
            // Interactive surfaces own this transform; route and drag transforms stay on their containers.
            if (!RenderTransform.Value.IsIdentity)
            {
                return;
            }

            _lift = new TranslateTransform();
            _press = new ScaleTransform(1, 1);
            var group = new TransformGroup();
            group.Children.Add(_press);
            group.Children.Add(_lift);
            SetCurrentValue(RenderTransformProperty, group);
            SetCurrentValue(RenderTransformOriginProperty, new Point(0.5, 0.5));
        }

        var duration = TimeSpan.FromMilliseconds(pressed ? 70 : 400);
        var y = !pressed && IsMouseOver ? -3d : 0d;
        IEasingFunction easing = pressed ? new CubicEase { EasingMode = EasingMode.EaseOut } : new SpringEase();
        _lift.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(y, duration) { EasingFunction = easing }, HandoffBehavior.SnapshotAndReplace);
        _press.BeginAnimation(ScaleTransform.ScaleXProperty,
            new DoubleAnimation(pressed ? 0.99 : 1, duration) { EasingFunction = easing }, HandoffBehavior.SnapshotAndReplace);
        _press.BeginAnimation(ScaleTransform.ScaleYProperty,
            new DoubleAnimation(pressed ? 0.965 : 1, duration) { EasingFunction = easing }, HandoffBehavior.SnapshotAndReplace);
    }

    private void ResetMotion()
    {
        _lift?.BeginAnimation(TranslateTransform.YProperty, null);
        _press?.BeginAnimation(ScaleTransform.ScaleXProperty, null);
        _press?.BeginAnimation(ScaleTransform.ScaleYProperty, null);
        if (_lift is not null) _lift.Y = 0;
        if (_press is not null) _press.ScaleX = _press.ScaleY = 1;
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        var bounds = new Rect(RenderSize);
        if (bounds.Width <= 1 || bounds.Height <= 1)
        {
            base.OnRender(drawingContext);
            return;
        }

        var radius = CornerRadius.TopLeft;
        if (!SystemParameters.HighContrast)
        {
            var elevation = Math.Clamp(Elevation, 0, 28);
            // Draw elevation behind the surface, never apply an Effect to readable content.
            for (var layer = 6; layer > 0 && elevation > 0; layer--)
            {
                var spread = elevation * layer / 12;
                var shadowBounds = bounds;
                shadowBounds.Inflate(spread, spread);
                shadowBounds.Offset(0, elevation / 3);
                var shadow = new SolidColorBrush(Color.FromArgb((byte)(3 + (6 - layer)), 0, 0, 0));
                shadow.Freeze();
                drawingContext.DrawRoundedRectangle(shadow, null, shadowBounds, radius + spread, radius + spread);
            }
        }

        base.OnRender(drawingContext);
        if (SystemParameters.HighContrast || ReflectionBrush is not SolidColorBrush reflection)
        {
            return;
        }

        var color = reflection.Color;
        var sheen = new LinearGradientBrush(
            new GradientStopCollection
            {
                new(color, 0),
                new(Color.FromArgb((byte)(color.A / 6), color.R, color.G, color.B), 0.35),
                new(Colors.Transparent, 0.65),
                new(Color.FromArgb((byte)(color.A / 5), color.R, color.G, color.B), 1)
            }, new Point(0, 0), new Point(0.85, 1));
        sheen.Freeze();
        bounds.Inflate(-0.5, -0.5);
        drawingContext.DrawRoundedRectangle(sheen, new Pen(sheen, 1), bounds, radius, radius);
    }
}
