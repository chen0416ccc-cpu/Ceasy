using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace CodexGuardian.WindowMotion;

internal sealed class WindowMotionController : IDisposable
{
    private static readonly TimeSpan WatchdogMargin = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan StateCommitTimeout = TimeSpan.FromMilliseconds(450);
    private static readonly TimeSpan StateCommitPollInterval = TimeSpan.FromMilliseconds(16);

    private readonly IntPtr _sourceWindow;
    private readonly Dispatcher _dispatcher;
    private readonly SemaphoreSlim _transitionGate = new(1, 1);
    private CancellationTokenSource? _activeCancellation;
    private long _generation;
    private bool _disposed;

    internal bool IsTransitioning => Volatile.Read(ref _activeCancellation) is not null;

    internal WindowMotionController(IntPtr sourceWindow, Dispatcher dispatcher)
    {
        if (sourceWindow == IntPtr.Zero)
        {
            throw new ArgumentException("A realized source HWND is required.", nameof(sourceWindow));
        }

        _sourceWindow = sourceWindow;
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
    }

    internal async Task<WindowMotionResult> RequestAsync(
        WindowMotionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        VerifyAccess();

        if (_disposed)
        {
            return new WindowMotionResult(
                WindowMotionCompletion.Disposed,
                _generation,
                false,
                null,
                null);
        }

        var generation = checked(++_generation);
        var operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var replacedCancellation = Interlocked.Exchange(ref _activeCancellation, operationCancellation);
        CancelNoThrow(replacedCancellation);

        try
        {
            await _transitionGate.WaitAsync(operationCancellation.Token);
        }
        catch (OperationCanceledException)
        {
            if (ReferenceEquals(
                    Interlocked.CompareExchange(ref _activeCancellation, null, operationCancellation),
                    operationCancellation))
            {
                operationCancellation.Dispose();
            }
            else
            {
                operationCancellation.Dispose();
            }
            return CanceledResult(generation, cancellationToken.IsCancellationRequested);
        }

        try
        {
            if (_disposed)
            {
                return new WindowMotionResult(
                    WindowMotionCompletion.Disposed,
                    generation,
                    false,
                    null,
                    null);
            }

            if (generation != _generation || operationCancellation.IsCancellationRequested)
            {
                return CanceledResult(generation, cancellationToken.IsCancellationRequested);
            }

            return await RunTransitionAsync(request, generation, operationCancellation.Token);
        }
        finally
        {
            _transitionGate.Release();
            if (ReferenceEquals(
                    Interlocked.CompareExchange(ref _activeCancellation, null, operationCancellation),
                    operationCancellation))
            {
                operationCancellation.Dispose();
            }
            else
            {
                operationCancellation.Dispose();
            }
        }
    }

    internal void Cancel()
    {
        VerifyAccess();
        _generation = checked(_generation + 1);
        CancelNoThrow(Interlocked.Exchange(ref _activeCancellation, null));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (!_dispatcher.CheckAccess())
        {
            _dispatcher.Invoke(Dispose);
            return;
        }

        _disposed = true;
        _generation = checked(_generation + 1);
        var cancellation = Interlocked.Exchange(ref _activeCancellation, null);
        CancelNoThrow(cancellation);
        cancellation?.Dispose();
    }

    private async Task<WindowMotionResult> RunTransitionAsync(
        WindowMotionRequest request,
        long generation,
        CancellationToken operationToken)
    {
        WindowMotionPhysicalRect? startBounds = null;
        WindowMotionPhysicalRect? endBounds = null;
        IntPtr transitionWindow = IntPtr.Zero;
        IntPtr thumbnail = IntPtr.Zero;
        var commitAttempted = false;
        var stateCommitted = false;
        var sourcePrepared = false;
        var surfaceShown = false;
        var sourceWasForeground = false;
        uint sourceLastInputTick = 0;
        var watchdogTriggered = false;
        var stage = WindowMotionStage.Admission;
        var failureReason = WindowMotionFailureReason.None;
        var errorDomain = WindowMotionErrorDomain.None;
        var errorCode = 0;
        var errorType = "none";
        var frameCount = 0;
        WindowMotionSurfaceState? surfaceState = null;
        WindowMotionSourceState? sourceState = null;
        WindowMotionStage? optionalFailureStage = null;
        var optionalErrorDomain = WindowMotionErrorDomain.None;
        var optionalErrorCode = 0;
        var operationStopwatch = Stopwatch.StartNew();
        using var watchdogCancellation = new CancellationTokenSource(request.Duration + WatchdogMargin);
        using var animationCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            operationToken,
            watchdogCancellation.Token);

        async Task<bool> CommitOnceAndVerifyAsync(
            bool requireChangedBounds,
            CancellationToken cancellationToken)
        {
            if (!commitAttempted)
            {
                commitAttempted = true;
                request.CommitWindowState();
            }

            stage = WindowMotionStage.VerifyWindowState;
            var verification = Stopwatch.StartNew();
            while (verification.Elapsed < StateCommitTimeout)
            {
                cancellationToken.ThrowIfCancellationRequested();
                WindowMotionNative.FlushCompositionNoThrow();
                sourceState = WindowMotionNative.ReadSourceState(_sourceWindow);
                if (MatchesRequestedState(request.Kind, sourceState.Value))
                {
                    if (!stateCommitted)
                    {
                        stateCommitted = true;
                        request.SynchronizeCaption?.Invoke();
                    }

                    if (!requireChangedBounds)
                    {
                        return true;
                    }

                    var candidateBounds = WindowMotionNative.ReadWindowRect(_sourceWindow);
                    if (candidateBounds.IsUsable &&
                        startBounds.HasValue &&
                        candidateBounds != startBounds.Value)
                    {
                        endBounds = candidateBounds;
                        return true;
                    }
                }

                await Task.Delay(StateCommitPollInterval, cancellationToken);
            }

            failureReason = stateCommitted && requireChangedBounds
                ? WindowMotionFailureReason.DestinationBoundsUnchanged
                : WindowMotionFailureReason.StateCommitUnconfirmed;
            return false;
        }

        async Task TryCommitAndVerifyNoThrowAsync(CancellationToken cancellationToken)
        {
            var failureStage = stage;
            var preservedFailureReason = failureReason;
            try
            {
                if (!commitAttempted && sourcePrepared)
                {
                    stage = WindowMotionStage.EnableSourceForCommit;
                    WindowMotionNative.SetSourceEnabled(_sourceWindow, enabled: true);
                }

                _ = await CommitOnceAndVerifyAsync(
                    requireChangedBounds: false,
                    cancellationToken);
            }
            catch
            {
                // The original transition failure remains authoritative; cleanup still runs.
            }
            finally
            {
                stage = failureStage;
                failureReason = preservedFailureReason;
            }
        }

        void CreateAndPrimeSurface(WindowMotionPhysicalRect bounds)
        {
            stage = WindowMotionStage.CreateTransitionSurface;
            transitionWindow = WindowMotionNative.CreateTransitionWindow(_sourceWindow, bounds);
            stage = WindowMotionStage.RegisterThumbnail;
            thumbnail = WindowMotionNative.RegisterThumbnail(transitionWindow, _sourceWindow);
            stage = WindowMotionStage.PrimeThumbnail;
            WindowMotionNative.UpdateThumbnail(thumbnail, bounds, byte.MaxValue);
            stage = WindowMotionStage.PlaceTransitionSurface;
            WindowMotionNative.MoveTransitionWindow(
                transitionWindow,
                _sourceWindow,
                bounds,
                show: false);
        }

        // requireAboveSource is waived when the source was cloaked before the surface existed
        // (the expand direction). Z-order against an invisible window carries no information,
        // and DWM does not guarantee an ordering answer for a cloaked HWND.
        void ShowAndVerifySurface(WindowMotionPhysicalRect bounds, bool requireAboveSource)
        {
            stage = WindowMotionStage.ShowTransitionSurface;
            WindowMotionNative.ShowTransitionWindow(transitionWindow);
            WindowMotionNative.MoveTransitionWindow(
                transitionWindow,
                _sourceWindow,
                bounds,
                show: true);
            surfaceShown = true;
            stage = WindowMotionStage.FlushComposition;
            WindowMotionNative.FlushComposition();
            stage = WindowMotionStage.VerifyTransitionSurface;
            surfaceState = WindowMotionNative.ReadSurfaceState(transitionWindow, _sourceWindow);
            if (!surfaceState.Value.IsWindow ||
                !surfaceState.Value.IsVisible ||
                surfaceState.Value.IsCloaked ||
                (requireAboveSource && !surfaceState.Value.IsAboveSource))
            {
                throw new InvalidOperationException(
                    "The window-motion surface was not visibly presented above the source window.");
            }
        }

        // Minimize, Maximize and Restore all start from a window that is already on screen:
        // capture it, hide it behind the surface, then move. Minimize animates before it
        // commits so the frame is still real while it shrinks; the other two commit first so
        // the destination rect is whatever the window actually settled on.
        async Task<bool> PrepareStandardAsync()
        {
            stage = WindowMotionStage.ReadStartBounds;
            startBounds = WindowMotionNative.ReadWindowRect(_sourceWindow);
            sourceWasForeground = WindowMotionNative.IsForegroundWindow(_sourceWindow);
            sourceLastInputTick = WindowMotionNative.ReadLastInputTick();
            if (!startBounds.Value.IsUsable)
            {
                failureReason = WindowMotionFailureReason.StartBoundsUnusable;
                stage = WindowMotionStage.CommitWindowState;
                _ = await CommitOnceAndVerifyAsync(
                    requireChangedBounds: false,
                    operationToken);
                return false;
            }

            CreateAndPrimeSurface(startBounds.Value);

            stage = WindowMotionStage.DisableSystemTransitions;
            WindowMotionNative.SetBooleanWindowAttribute(
                _sourceWindow,
                WindowMotionNative.DwmwaTransitionsForcedDisabled,
                enabled: true);
            stage = WindowMotionStage.FreezeSourceRepresentation;
            if (!WindowMotionNative.TrySetBooleanWindowAttribute(
                _sourceWindow,
                WindowMotionNative.DwmwaFreezeRepresentation,
                enabled: true,
                out var freezeResult))
            {
                optionalFailureStage = stage;
                optionalErrorDomain = WindowMotionErrorDomain.HResult;
                optionalErrorCode = freezeResult;
            }

            ShowAndVerifySurface(startBounds.Value, requireAboveSource: true);
            stage = WindowMotionStage.CloakSource;
            WindowMotionNative.SetBooleanWindowAttribute(
                _sourceWindow,
                WindowMotionNative.DwmwaCloak,
                enabled: true);
            sourcePrepared = true;

            if (request.Kind == WindowMotionKind.Minimize)
            {
                stage = WindowMotionStage.DisableSource;
                WindowMotionNative.SetSourceEnabled(_sourceWindow, enabled: false);
                stage = WindowMotionStage.ResolveDestination;
                endBounds = WindowMotionNative.GetMinimizeDestination(
                    _sourceWindow,
                    startBounds.Value,
                    request.AnchorBounds);
                return true;
            }

            stage = WindowMotionStage.CommitWindowState;
            if (!await CommitOnceAndVerifyAsync(requireChangedBounds: true, operationToken))
            {
                return false;
            }

            stage = WindowMotionStage.DisableSource;
            WindowMotionNative.SetSourceEnabled(_sourceWindow, enabled: false);
            return true;
        }

        // Expand runs the standard order backwards, because there is nothing to capture yet:
        // an iconic window has no usable rect and no thumbnail worth sampling. So cloak the
        // source first, let the restore land invisibly, and only then hang a thumbnail on the
        // now-real window and grow it out of the anchor. Cloaking before the commit is what
        // keeps the restored frame from flashing at full size for one refresh.
        async Task<bool> PrepareExpandAsync()
        {
            stage = WindowMotionStage.ResolveOrigin;
            startBounds = request.AnchorBounds;
            if (!startBounds.HasValue || !startBounds.Value.IsUsable)
            {
                failureReason = WindowMotionFailureReason.OriginBoundsUnusable;
                stage = WindowMotionStage.CommitWindowState;
                _ = await CommitOnceAndVerifyAsync(
                    requireChangedBounds: false,
                    operationToken);
                return false;
            }

            // The caller's commit brings the window forward itself, so no foreground restore
            // is owed here; an iconic source was never the foreground window to begin with.
            sourceWasForeground = false;
            sourceLastInputTick = WindowMotionNative.ReadLastInputTick();

            stage = WindowMotionStage.DisableSystemTransitions;
            WindowMotionNative.SetBooleanWindowAttribute(
                _sourceWindow,
                WindowMotionNative.DwmwaTransitionsForcedDisabled,
                enabled: true);
            stage = WindowMotionStage.CloakSource;
            WindowMotionNative.SetBooleanWindowAttribute(
                _sourceWindow,
                WindowMotionNative.DwmwaCloak,
                enabled: true);
            sourcePrepared = true;

            stage = WindowMotionStage.CommitWindowState;
            // requireChangedBounds is deliberately off here. The shell can restore the window
            // before this request is admitted - a taskbar click does not wait for us - and in
            // that case the commit is a no-op with an unchanged rect. The destination is read
            // straight from the window afterwards instead of being inferred from the change.
            if (!await CommitOnceAndVerifyAsync(requireChangedBounds: false, operationToken))
            {
                return false;
            }

            stage = WindowMotionStage.ResolveDestination;
            endBounds = WindowMotionNative.ReadWindowRect(_sourceWindow);

            CreateAndPrimeSurface(startBounds.Value);
            ShowAndVerifySurface(startBounds.Value, requireAboveSource: false);
            stage = WindowMotionStage.DisableSource;
            WindowMotionNative.SetSourceEnabled(_sourceWindow, enabled: false);
            return true;
        }

        WindowMotionResult CreateResult(WindowMotionCompletion completion) =>
            new(
                completion,
                generation,
                stateCommitted,
                startBounds,
                endBounds,
                stage,
                failureReason,
                errorDomain,
                errorCode,
                errorType,
                frameCount,
                Math.Max(0, operationStopwatch.ElapsedMilliseconds),
                surfaceState,
                sourceState,
                optionalFailureStage,
                optionalErrorDomain,
                optionalErrorCode);

        try
        {
            if (!request.AnimationsEnabled || !SystemParameters.ClientAreaAnimation)
            {
                failureReason = request.AnimationsEnabled
                    ? WindowMotionFailureReason.ClientAreaAnimationDisabled
                    : WindowMotionFailureReason.AnimationsDisabled;
                stage = WindowMotionStage.CommitWindowState;
                return await CommitOnceAndVerifyAsync(
                    requireChangedBounds: false,
                    operationToken)
                    ? CreateResult(WindowMotionCompletion.ReducedMotion)
                    : CreateResult(WindowMotionCompletion.NativeFallback);
            }

            stage = WindowMotionStage.CapabilityCheck;
            var capability = WindowMotionNative.ReadCapability(
                _sourceWindow,
                allowMinimizedSource: request.Kind == WindowMotionKind.Expand);
            if (!capability.CanAnimate)
            {
                failureReason = MapCapabilityFailure(capability.Status);
                if (capability.ErrorCode != 0)
                {
                    errorDomain = WindowMotionErrorDomain.HResult;
                    errorCode = capability.ErrorCode;
                }
                stage = WindowMotionStage.CommitWindowState;
                _ = await CommitOnceAndVerifyAsync(
                    requireChangedBounds: false,
                    operationToken);
                return CreateResult(WindowMotionCompletion.NativeFallback);
            }

            var prepared = request.Kind == WindowMotionKind.Expand
                ? await PrepareExpandAsync()
                : await PrepareStandardAsync();
            if (!prepared)
            {
                return CreateResult(WindowMotionCompletion.NativeFallback);
            }

            if (!endBounds.HasValue || !endBounds.Value.IsUsable)
            {
                failureReason = WindowMotionFailureReason.DestinationBoundsUnchanged;
                return CreateResult(WindowMotionCompletion.NativeFallback);
            }

            // Both preparation paths already refuse to continue without a usable origin. The
            // check restates it here so the animation cannot be entered on a missing rect if a
            // third path is ever added.
            if (!startBounds.HasValue || !startBounds.Value.IsUsable)
            {
                failureReason = request.Kind == WindowMotionKind.Expand
                    ? WindowMotionFailureReason.OriginBoundsUnusable
                    : WindowMotionFailureReason.StartBoundsUnusable;
                return CreateResult(WindowMotionCompletion.NativeFallback);
            }

            var originBounds = startBounds.Value;
            var destinationBounds = endBounds.Value;
            stage = WindowMotionStage.AnimateFrames;
            frameCount = await AnimateAsync(
                transitionWindow,
                thumbnail,
                originBounds,
                destinationBounds,
                request.Kind,
                request.Duration,
                animationCancellation.Token);

            if (request.Kind == WindowMotionKind.Minimize)
            {
                stage = WindowMotionStage.EnableSourceForCommit;
                WindowMotionNative.SetSourceEnabled(_sourceWindow, enabled: true);
                stage = WindowMotionStage.CommitMinimize;
                if (!await CommitOnceAndVerifyAsync(
                        requireChangedBounds: false,
                        operationToken))
                {
                    return CreateResult(WindowMotionCompletion.NativeFallback);
                }
            }

            stage = WindowMotionStage.Completed;
            return CreateResult(WindowMotionCompletion.Animated);
        }
        catch (OperationCanceledException) when (watchdogCancellation.IsCancellationRequested && !operationToken.IsCancellationRequested)
        {
            watchdogTriggered = true;
            failureReason = WindowMotionFailureReason.RenderLoopTimeout;
            await TryCommitAndVerifyNoThrowAsync(operationToken);
            return CreateResult(WindowMotionCompletion.WatchdogFallback);
        }
        catch (OperationCanceledException)
        {
            var replaced = generation != _generation;
            failureReason = replaced
                ? WindowMotionFailureReason.Replaced
                : WindowMotionFailureReason.OperationCanceled;
            return CreateResult(
                replaced
                    ? WindowMotionCompletion.Replaced
                    : WindowMotionCompletion.Canceled);
        }
        catch (TimeoutException exception)
        {
            watchdogTriggered = true;
            failureReason = WindowMotionFailureReason.RenderLoopTimeout;
            CaptureFailure(exception, ref errorDomain, ref errorCode, ref errorType);
            await TryCommitAndVerifyNoThrowAsync(operationToken);
            return CreateResult(WindowMotionCompletion.WatchdogFallback);
        }
        catch (Exception exception)
        {
            failureReason = WindowMotionFailureReason.NativeFailure;
            CaptureFailure(exception, ref errorDomain, ref errorCode, ref errorType);
            await TryCommitAndVerifyNoThrowAsync(operationToken);
            return CreateResult(
                watchdogTriggered
                    ? WindowMotionCompletion.WatchdogFallback
                    : WindowMotionCompletion.NativeFallback);
        }
        finally
        {
            // Cleanup order keeps the committed real HWND behind an exact final thumbnail until
            // the source becomes visible again. Every native state is reset independently.
            if (sourcePrepared)
            {
                _ = WindowMotionNative.TrySetSourceEnabled(_sourceWindow, enabled: true);
                _ = WindowMotionNative.TrySetBooleanWindowAttribute(
                    _sourceWindow,
                    WindowMotionNative.DwmwaFreezeRepresentation,
                    enabled: false);
                _ = WindowMotionNative.TrySetBooleanWindowAttribute(
                    _sourceWindow,
                    WindowMotionNative.DwmwaCloak,
                    enabled: false);
                WindowMotionNative.FlushCompositionNoThrow();
            }

            if (surfaceShown)
            {
                WindowMotionNative.HideTransitionWindow(transitionWindow);
            }

            _ = WindowMotionNative.TrySetBooleanWindowAttribute(
                _sourceWindow,
                WindowMotionNative.DwmwaTransitionsForcedDisabled,
                enabled: false);
            if (!sourcePrepared)
            {
                _ = WindowMotionNative.TrySetSourceEnabled(_sourceWindow, enabled: true);
                _ = WindowMotionNative.TrySetBooleanWindowAttribute(
                    _sourceWindow,
                    WindowMotionNative.DwmwaFreezeRepresentation,
                    enabled: false);
                _ = WindowMotionNative.TrySetBooleanWindowAttribute(
                    _sourceWindow,
                    WindowMotionNative.DwmwaCloak,
                    enabled: false);
            }
            WindowMotionNative.UnregisterThumbnailNoThrow(thumbnail);
            WindowMotionNative.DestroyWindowNoThrow(transitionWindow);
            if (sourcePrepared && sourceWasForeground && !_disposed)
            {
                WindowMotionNative.RestoreForegroundNoThrow(_sourceWindow, sourceLastInputTick);
            }
        }
    }

    private async Task<int> AnimateAsync(
        IntPtr transitionWindow,
        IntPtr thumbnail,
        WindowMotionPhysicalRect startBounds,
        WindowMotionPhysicalRect endBounds,
        WindowMotionKind kind,
        TimeSpan duration,
        CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource();
        var stopwatch = Stopwatch.StartNew();
        EventHandler? renderingHandler = null;
        DispatcherTimer? watchdog = null;
        CancellationTokenRegistration cancellationRegistration = default;
        var frameCount = 0;

        void Complete(Exception? error = null)
        {
            if (error is null)
            {
                completion.TrySetResult();
            }
            else
            {
                completion.TrySetException(error);
            }
        }

        renderingHandler = (_, _) =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var linear = Math.Clamp(stopwatch.Elapsed.TotalMilliseconds / duration.TotalMilliseconds, 0, 1);
                var eased = EaseOutCubic(linear);
                var bounds = WindowMotionPhysicalRect.Interpolate(startBounds, endBounds, eased);
                WindowMotionNative.MoveTransitionWindow(
                    transitionWindow,
                    _sourceWindow,
                    bounds,
                    show: true);
                WindowMotionNative.UpdateThumbnail(thumbnail, bounds, byte.MaxValue);
                frameCount = checked(frameCount + 1);
                if (linear >= 1)
                {
                    Complete();
                }
            }
            catch (OperationCanceledException)
            {
                completion.TrySetCanceled(cancellationToken);
            }
            catch (Exception error)
            {
                Complete(error);
            }
        };

        try
        {
            cancellationRegistration = cancellationToken.Register(() =>
            {
                _ = _dispatcher.BeginInvoke(
                    DispatcherPriority.Send,
                    new Action(() => completion.TrySetCanceled(cancellationToken)));
            });
            watchdog = new DispatcherTimer(DispatcherPriority.Send, _dispatcher)
            {
                Interval = duration + TimeSpan.FromMilliseconds(250)
            };
            watchdog.Tick += OnWatchdogTick;
            CompositionTarget.Rendering += renderingHandler;
            watchdog.Start();
            await completion.Task;
            return frameCount;
        }
        finally
        {
            cancellationRegistration.Dispose();
            if (renderingHandler is not null)
            {
                CompositionTarget.Rendering -= renderingHandler;
            }

            if (watchdog is not null)
            {
                watchdog.Stop();
                watchdog.Tick -= OnWatchdogTick;
            }
        }

        void OnWatchdogTick(object? sender, EventArgs eventArgs) =>
            Complete(new TimeoutException("The window-motion render loop did not complete."));
    }

    private static double EaseOutCubic(double value) => 1 - Math.Pow(1 - value, 3);

    private static bool MatchesRequestedState(
        WindowMotionKind kind,
        WindowMotionSourceState state) =>
        state.IsWindow &&
        (kind switch
        {
            WindowMotionKind.Minimize => state.IsMinimized,
            WindowMotionKind.Maximize => !state.IsMinimized && state.IsMaximized,
            WindowMotionKind.Restore => !state.IsMinimized && !state.IsMaximized,
            // Expanding restores whichever state the window was in before it left the screen,
            // so only leaving the iconic state is required.
            WindowMotionKind.Expand => !state.IsMinimized,
            _ => false
        });

    private static WindowMotionFailureReason MapCapabilityFailure(
        WindowMotionCapabilityStatus status) =>
        status switch
        {
            WindowMotionCapabilityStatus.InvalidSourceWindow =>
                WindowMotionFailureReason.InvalidSourceWindow,
            WindowMotionCapabilityStatus.CompositionQueryFailed =>
                WindowMotionFailureReason.CompositionQueryFailed,
            WindowMotionCapabilityStatus.CompositionDisabled =>
                WindowMotionFailureReason.CompositionDisabled,
            WindowMotionCapabilityStatus.SourceAlreadyMinimized =>
                WindowMotionFailureReason.SourceAlreadyMinimized,
            _ => WindowMotionFailureReason.None
        };

    private static void CaptureFailure(
        Exception exception,
        ref WindowMotionErrorDomain domain,
        ref int errorCode,
        ref string errorType)
    {
        errorType = exception.GetType().Name;
        switch (exception)
        {
            case Win32Exception win32:
                domain = WindowMotionErrorDomain.Win32;
                errorCode = win32.NativeErrorCode;
                break;
            case ExternalException external:
                domain = WindowMotionErrorDomain.HResult;
                errorCode = external.ErrorCode;
                break;
            default:
                domain = WindowMotionErrorDomain.Managed;
                errorCode = exception.HResult;
                break;
        }
    }

    private WindowMotionResult CanceledResult(long generation, bool callerCanceled) =>
        new(
            callerCanceled
                ? WindowMotionCompletion.Canceled
                : WindowMotionCompletion.Replaced,
            generation,
            false,
            null,
            null,
            WindowMotionStage.Admission,
            callerCanceled
                ? WindowMotionFailureReason.OperationCanceled
                : WindowMotionFailureReason.Replaced);

    private void VerifyAccess()
    {
        if (!_dispatcher.CheckAccess())
        {
            throw new InvalidOperationException("Window motion must be requested from the source window dispatcher.");
        }
    }

    private static void CancelNoThrow(CancellationTokenSource? cancellation)
    {
        try
        {
            cancellation?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }
}
