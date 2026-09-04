using System;

namespace CodexGuardian.WindowMotion;

internal enum WindowMotionKind
{
    Minimize,
    Maximize,
    Restore,
    Expand
}

internal enum WindowMotionCompletion
{
    Animated,
    ReducedMotion,
    NativeFallback,
    Replaced,
    Canceled,
    WatchdogFallback,
    Disposed
}

internal enum WindowMotionStage
{
    None,
    Admission,
    CapabilityCheck,
    ReadStartBounds,
    ResolveOrigin,
    CreateTransitionSurface,
    RegisterThumbnail,
    PrimeThumbnail,
    PlaceTransitionSurface,
    DisableSystemTransitions,
    FreezeSourceRepresentation,
    ShowTransitionSurface,
    VerifyTransitionSurface,
    FlushComposition,
    CloakSource,
    DisableSource,
    EnableSourceForCommit,
    ResolveDestination,
    CommitWindowState,
    VerifyWindowState,
    AnimateFrames,
    CommitMinimize,
    Completed,
    Cleanup
}

internal enum WindowMotionFailureReason
{
    None,
    AnimationsDisabled,
    ClientAreaAnimationDisabled,
    InvalidSourceWindow,
    CompositionQueryFailed,
    CompositionDisabled,
    SourceAlreadyMinimized,
    StartBoundsUnusable,
    OriginBoundsUnusable,
    StateCommitUnconfirmed,
    DestinationBoundsUnchanged,
    NativeFailure,
    RenderLoopTimeout,
    OperationCanceled,
    Replaced,
    Disposed
}

internal enum WindowMotionErrorDomain
{
    None,
    Win32,
    HResult,
    Managed
}

internal enum WindowMotionCapabilityStatus
{
    Ready,
    InvalidSourceWindow,
    CompositionQueryFailed,
    CompositionDisabled,
    SourceAlreadyMinimized
}

internal readonly record struct WindowMotionCapabilityResult(
    WindowMotionCapabilityStatus Status,
    int ErrorCode = 0)
{
    internal bool CanAnimate => Status == WindowMotionCapabilityStatus.Ready;
}

internal readonly record struct WindowMotionSurfaceState(
    bool IsWindow,
    bool IsVisible,
    bool IsCloaked,
    bool IsAboveSource);

internal readonly record struct WindowMotionSourceState(
    bool IsWindow,
    bool IsEnabled,
    bool IsMinimized,
    bool IsMaximized);

internal readonly record struct WindowMotionResult(
    WindowMotionCompletion Completion,
    long Generation,
    bool StateCommitted,
    WindowMotionPhysicalRect? StartBounds,
    WindowMotionPhysicalRect? EndBounds,
    WindowMotionStage Stage = WindowMotionStage.None,
    WindowMotionFailureReason FailureReason = WindowMotionFailureReason.None,
    WindowMotionErrorDomain ErrorDomain = WindowMotionErrorDomain.None,
    int ErrorCode = 0,
    string ErrorType = "none",
    int FrameCount = 0,
    long ElapsedMilliseconds = 0,
    WindowMotionSurfaceState? SurfaceState = null,
    WindowMotionSourceState? SourceState = null,
    WindowMotionStage? OptionalFailureStage = null,
    WindowMotionErrorDomain OptionalErrorDomain = WindowMotionErrorDomain.None,
    int OptionalErrorCode = 0)
{
    internal bool WasAnimated => Completion == WindowMotionCompletion.Animated;
}

internal readonly record struct WindowMotionPhysicalRect(int Left, int Top, int Right, int Bottom)
{
    internal int Width => Math.Max(0, Right - Left);

    internal int Height => Math.Max(0, Bottom - Top);

    internal bool IsUsable => Width > 0 && Height > 0;

    internal static WindowMotionPhysicalRect Interpolate(
        WindowMotionPhysicalRect start,
        WindowMotionPhysicalRect end,
        double progress)
    {
        progress = Math.Clamp(progress, 0, 1);
        return new WindowMotionPhysicalRect(
            Interpolate(start.Left, end.Left, progress),
            Interpolate(start.Top, end.Top, progress),
            Interpolate(start.Right, end.Right, progress),
            Interpolate(start.Bottom, end.Bottom, progress));
    }

    private static int Interpolate(int start, int end, double progress) =>
        checked((int)Math.Round(start + ((long)end - start) * progress));
}

internal sealed record WindowMotionRequest
{
    private static readonly TimeSpan DefaultMinimizeDuration = TimeSpan.FromMilliseconds(180);
    private static readonly TimeSpan DefaultResizeDuration = TimeSpan.FromMilliseconds(210);
    private static readonly TimeSpan DefaultExpandDuration = TimeSpan.FromMilliseconds(220);

    private WindowMotionRequest(
        WindowMotionKind kind,
        Action commitWindowState,
        Action? synchronizeCaption,
        bool animationsEnabled,
        TimeSpan duration,
        WindowMotionPhysicalRect? anchorBounds = null)
    {
        Kind = kind;
        CommitWindowState = commitWindowState ?? throw new ArgumentNullException(nameof(commitWindowState));
        SynchronizeCaption = synchronizeCaption;
        AnimationsEnabled = animationsEnabled;
        AnchorBounds = anchorBounds;
        Duration = duration > TimeSpan.Zero
            ? duration
            : throw new ArgumentOutOfRangeException(nameof(duration));
    }

    internal WindowMotionKind Kind { get; }

    internal Action CommitWindowState { get; }

    internal Action? SynchronizeCaption { get; }

    internal bool AnimationsEnabled { get; }

    /// <summary>
    /// Screen rectangle of the window's home on the shell - its tray icon, or the taskbar
    /// end that holds one. <see cref="WindowMotionKind.Minimize"/> shrinks into it and
    /// <see cref="WindowMotionKind.Expand"/> grows out of it, so the two directions retrace
    /// the same path. Null lets the minimize direction fall back to a geometric guess; the
    /// expand direction cannot run without it.
    /// </summary>
    internal WindowMotionPhysicalRect? AnchorBounds { get; }

    internal TimeSpan Duration { get; }

    internal static WindowMotionRequest Minimize(
        Action commitWindowState,
        Action? synchronizeCaption = null,
        bool animationsEnabled = true,
        WindowMotionPhysicalRect? anchorBounds = null) =>
        new(
            WindowMotionKind.Minimize,
            commitWindowState,
            synchronizeCaption,
            animationsEnabled,
            DefaultMinimizeDuration,
            anchorBounds);

    internal static WindowMotionRequest Maximize(
        Action commitWindowState,
        Action? synchronizeCaption = null,
        bool animationsEnabled = true) =>
        new(
            WindowMotionKind.Maximize,
            commitWindowState,
            synchronizeCaption,
            animationsEnabled,
            DefaultResizeDuration);

    internal static WindowMotionRequest Restore(
        Action commitWindowState,
        Action? synchronizeCaption = null,
        bool animationsEnabled = true) =>
        new(
            WindowMotionKind.Restore,
            commitWindowState,
            synchronizeCaption,
            animationsEnabled,
            DefaultResizeDuration);

    /// <summary>
    /// Grows the window back out of <paramref name="anchorBounds"/> after it was minimized
    /// or hidden to the tray. The commit runs first so the thumbnail has a restored window
    /// to sample, which is why an iconic source is allowed here and nowhere else.
    /// </summary>
    internal static WindowMotionRequest Expand(
        WindowMotionPhysicalRect anchorBounds,
        Action commitWindowState,
        Action? synchronizeCaption = null,
        bool animationsEnabled = true) =>
        new(
            WindowMotionKind.Expand,
            commitWindowState,
            synchronizeCaption,
            animationsEnabled,
            DefaultExpandDuration,
            anchorBounds);
}
