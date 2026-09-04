using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CodexGuardian.WindowMotion;

internal static class WindowMotionNative
{
    internal const int DwmwaTransitionsForcedDisabled = 3;
    internal const int DwmwaExtendedFrameBounds = 9;
    internal const int DwmwaCloak = 13;
    internal const int DwmwaFreezeRepresentation = 15;
    internal const int DwmwaWindowCornerPreference = 33;
    internal const int DwmWindowCornerPreferenceRound = 2;

    internal const uint DwmTnpRectDestination = 0x00000001;
    internal const uint DwmTnpOpacity = 0x00000004;
    internal const uint DwmTnpVisible = 0x00000008;
    internal const uint DwmTnpSourceClientAreaOnly = 0x00000010;

    internal const int GwlExStyle = -20;
    internal const long WsExTopmost = 0x00000008L;
    internal const uint WsPopup = 0x80000000;
    internal const uint WsDisabled = 0x08000000;
    internal const uint WsExToolWindow = 0x00000080;
    internal const uint WsExTransparent = 0x00000020;
    internal const uint WsExNoActivate = 0x08000000;

    internal const int SwHide = 0;
    internal const int SwShowNoActivate = 4;
    internal const uint GwHwndNext = 2;
    internal const uint SwpNoActivate = 0x0010;
    internal const uint SwpNoOwnerZOrder = 0x0200;
    internal const uint SwpShowWindow = 0x0040;

    internal const uint MonitorDefaultToNearest = 0x00000002;
    internal const uint ErrorClassAlreadyExists = 1410;

    private const uint AbmGetTaskbarPos = 0x00000005;
    private const uint AbeLeft = 0;
    private const uint AbeTop = 1;
    private const uint AbeRight = 2;
    private const uint AbeBottom = 3;

    // A shrink target smaller than this reads as a disappearance rather than a landing,
    // and DWM stops scaling the thumbnail meaningfully below a few pixels.
    private const int MinimumAnchorEdge = 16;

    private const string TransitionClassName = "CodexFree.WindowMotionSurface.V1";
    private static readonly object ClassRegistrationLock = new();
    private static readonly WndProc WindowProcedure = DefWindowProcedure;
    private static ushort _classAtom;

    internal static IntPtr CreateTransitionWindow(IntPtr sourceWindow, WindowMotionPhysicalRect bounds)
    {
        EnsureWindowClass();
        var sourceExtendedStyle = GetWindowLongPtr(sourceWindow, GwlExStyle).ToInt64();
        var extendedStyle = WsExToolWindow | WsExNoActivate | WsExTransparent;
        if ((sourceExtendedStyle & WsExTopmost) != 0)
        {
            extendedStyle |= (uint)WsExTopmost;
        }

        var handle = CreateWindowEx(
            extendedStyle,
            TransitionClassName,
            null,
            WsPopup | WsDisabled,
            bounds.Left,
            bounds.Top,
            Math.Max(1, bounds.Width),
            Math.Max(1, bounds.Height),
            IntPtr.Zero,
            IntPtr.Zero,
            GetModuleHandle(null),
            IntPtr.Zero);
        if (handle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the window-motion surface.");
        }

        var glassMargins = new DwmMargins(-1, -1, -1, -1);
        var glassResult = DwmExtendFrameIntoClientArea(handle, ref glassMargins);
        if (glassResult < 0)
        {
            DestroyWindowNoThrow(handle);
            Marshal.ThrowExceptionForHR(glassResult);
        }

        var cornerPreference = DwmWindowCornerPreferenceRound;
        _ = DwmSetWindowAttribute(
            handle,
            DwmwaWindowCornerPreference,
            ref cornerPreference,
            sizeof(int));
        return handle;
    }

    internal static WindowMotionPhysicalRect ReadWindowRect(IntPtr window)
    {
        NativeRect extendedFrame;
        if (DwmGetWindowAttribute(
                window,
                DwmwaExtendedFrameBounds,
                out extendedFrame,
                Marshal.SizeOf<NativeRect>()) >= 0)
        {
            var physicalBounds = extendedFrame.ToPhysicalRect();
            if (physicalBounds.IsUsable)
            {
                return physicalBounds;
            }
        }

        if (!GetWindowRect(window, out var bounds))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not read the source window bounds.");
        }

        return bounds.ToPhysicalRect();
    }

    internal static WindowMotionPhysicalRect GetMinimizeDestination(
        IntPtr sourceWindow,
        WindowMotionPhysicalRect sourceBounds,
        WindowMotionPhysicalRect? anchorBounds = null)
    {
        // An anchor is the actual on-screen home of the window: its tray icon, or failing
        // that the taskbar edge nearest the tray. Landing there is the whole point of the
        // shrink, so it outranks every geometric guess below.
        if (anchorBounds.HasValue && anchorBounds.Value.IsUsable)
        {
            return FitInsideAnchor(sourceBounds, anchorBounds.Value);
        }

        var monitor = MonitorFromWindow(sourceWindow, MonitorDefaultToNearest);
        var monitorInfo = new MonitorInfo
        {
            Size = Marshal.SizeOf<MonitorInfo>()
        };
        if (monitor == IntPtr.Zero || !GetMonitorInfo(monitor, ref monitorInfo))
        {
            return CreateBottomMinimizeDestination(sourceBounds, sourceBounds);
        }

        var monitorBounds = monitorInfo.Monitor.ToPhysicalRect();
        var workBounds = monitorInfo.Work.ToPhysicalRect();
        const int longEdge = 148;
        const int shortEdge = 22;

        if (workBounds.Left > monitorBounds.Left)
        {
            var centerY = Math.Clamp(
                sourceBounds.Top + sourceBounds.Height / 2,
                monitorBounds.Top + longEdge / 2,
                monitorBounds.Bottom - longEdge / 2);
            return FromCenter(
                monitorBounds.Left + Math.Max(1, (workBounds.Left - monitorBounds.Left) / 2),
                centerY,
                shortEdge,
                longEdge);
        }

        if (workBounds.Right < monitorBounds.Right)
        {
            var centerY = Math.Clamp(
                sourceBounds.Top + sourceBounds.Height / 2,
                monitorBounds.Top + longEdge / 2,
                monitorBounds.Bottom - longEdge / 2);
            return FromCenter(
                workBounds.Right + Math.Max(1, (monitorBounds.Right - workBounds.Right) / 2),
                centerY,
                shortEdge,
                longEdge);
        }

        if (workBounds.Top > monitorBounds.Top)
        {
            var centerX = Math.Clamp(
                sourceBounds.Left + sourceBounds.Width / 2,
                monitorBounds.Left + longEdge / 2,
                monitorBounds.Right - longEdge / 2);
            return FromCenter(
                centerX,
                monitorBounds.Top + Math.Max(1, (workBounds.Top - monitorBounds.Top) / 2),
                longEdge,
                shortEdge);
        }

        return CreateBottomMinimizeDestination(sourceBounds, monitorBounds);
    }

    private static WindowMotionPhysicalRect CreateBottomMinimizeDestination(
        WindowMotionPhysicalRect sourceBounds,
        WindowMotionPhysicalRect monitorBounds)
    {
        const int width = 148;
        const int height = 22;
        var centerX = Math.Clamp(
            sourceBounds.Left + sourceBounds.Width / 2,
            monitorBounds.Left + width / 2,
            monitorBounds.Right - width / 2);
        return FromCenter(
            centerX,
            Math.Max(monitorBounds.Top + height / 2, monitorBounds.Bottom - height / 2 - 1),
            width,
            height);
    }

    private static WindowMotionPhysicalRect FromCenter(int x, int y, int width, int height) =>
        new(x - width / 2, y - height / 2, x - width / 2 + width, y - height / 2 + height);

    // Centres the shrink target on the anchor while preserving the source aspect ratio, so
    // the frame never squashes on its way down. A tray icon is square and a window is not,
    // and interpolating straight to the icon rect makes the last frames look sheared.
    private static WindowMotionPhysicalRect FitInsideAnchor(
        WindowMotionPhysicalRect sourceBounds,
        WindowMotionPhysicalRect anchorBounds)
    {
        var anchorEdge = Math.Max(
            MinimumAnchorEdge,
            Math.Max(anchorBounds.Width, anchorBounds.Height));
        var centerX = anchorBounds.Left + anchorBounds.Width / 2;
        var centerY = anchorBounds.Top + anchorBounds.Height / 2;
        if (!sourceBounds.IsUsable)
        {
            return FromCenter(centerX, centerY, anchorEdge, anchorEdge);
        }

        var width = anchorEdge;
        var height = Math.Max(
            1,
            (int)Math.Round(anchorEdge * (double)sourceBounds.Height / sourceBounds.Width));
        if (height > anchorEdge)
        {
            height = anchorEdge;
            width = Math.Max(
                1,
                (int)Math.Round(anchorEdge * (double)sourceBounds.Width / sourceBounds.Height));
        }

        return FromCenter(centerX, centerY, width, height);
    }

    // Shell_NotifyIconGetRect is the only supported way to find a tray icon. When the icon
    // is folded into the overflow flyout the shell answers with the chevron's rect instead,
    // which is the right place to land anyway: that is where the user will look for it.
    internal static bool TryGetTrayIconRect(
        IntPtr iconWindow,
        uint iconId,
        out WindowMotionPhysicalRect anchorBounds)
    {
        anchorBounds = default;
        if (iconWindow == IntPtr.Zero || !IsWindow(iconWindow))
        {
            return false;
        }

        var identifier = new NotifyIconIdentifier
        {
            Size = (uint)Marshal.SizeOf<NotifyIconIdentifier>(),
            Window = iconWindow,
            Id = iconId,
            Item = Guid.Empty
        };
        if (Shell_NotifyIconGetRect(ref identifier, out var iconRect) < 0)
        {
            return false;
        }

        var candidate = iconRect.ToPhysicalRect();
        if (!candidate.IsUsable)
        {
            return false;
        }

        anchorBounds = candidate;
        return true;
    }

    // Fallback anchor when no tray icon is registered or the shell refuses to locate it:
    // the end of the taskbar that holds the notification area. Window buttons live on the
    // opposite end, so this still points the shrink at the correct corner of the screen.
    internal static bool TryGetTaskbarAnchorRect(out WindowMotionPhysicalRect anchorBounds)
    {
        anchorBounds = default;
        var data = new AppBarData
        {
            Size = (uint)Marshal.SizeOf<AppBarData>()
        };
        if (SHAppBarMessage(AbmGetTaskbarPos, ref data) == IntPtr.Zero)
        {
            return false;
        }

        var taskbar = data.Bounds.ToPhysicalRect();
        if (!taskbar.IsUsable)
        {
            return false;
        }

        var thickness = data.Edge is AbeLeft or AbeRight
            ? Math.Max(MinimumAnchorEdge, taskbar.Width)
            : Math.Max(MinimumAnchorEdge, taskbar.Height);
        anchorBounds = data.Edge switch
        {
            AbeLeft or AbeRight => new WindowMotionPhysicalRect(
                taskbar.Left,
                Math.Max(taskbar.Top, taskbar.Bottom - thickness),
                taskbar.Right,
                taskbar.Bottom),
            AbeTop => new WindowMotionPhysicalRect(
                Math.Max(taskbar.Left, taskbar.Right - thickness),
                taskbar.Top,
                taskbar.Right,
                taskbar.Bottom),
            _ => new WindowMotionPhysicalRect(
                Math.Max(taskbar.Left, taskbar.Right - thickness),
                taskbar.Top,
                taskbar.Right,
                taskbar.Bottom)
        };
        return anchorBounds.IsUsable;
    }

    internal static void SetBooleanWindowAttribute(IntPtr window, int attribute, bool enabled)
    {
        var value = enabled ? 1 : 0;
        ThrowIfFailed(DwmSetWindowAttribute(window, attribute, ref value, sizeof(int)));
    }

    internal static bool TrySetBooleanWindowAttribute(IntPtr window, int attribute, bool enabled)
    {
        return TrySetBooleanWindowAttribute(window, attribute, enabled, out _);
    }

    internal static bool TrySetBooleanWindowAttribute(
        IntPtr window,
        int attribute,
        bool enabled,
        out int result)
    {
        var value = enabled ? 1 : 0;
        result = DwmSetWindowAttribute(window, attribute, ref value, sizeof(int));
        return result >= 0;
    }

    internal static IntPtr RegisterThumbnail(IntPtr destinationWindow, IntPtr sourceWindow)
    {
        ThrowIfFailed(DwmRegisterThumbnail(destinationWindow, sourceWindow, out var thumbnail));
        if (thumbnail == IntPtr.Zero)
        {
            throw new InvalidOperationException("DWM returned an empty thumbnail handle.");
        }

        var queryResult = DwmQueryThumbnailSourceSize(thumbnail, out var sourceSize);
        if (queryResult < 0 || sourceSize.Width <= 0 || sourceSize.Height <= 0)
        {
            _ = DwmUnregisterThumbnail(thumbnail);
            if (queryResult < 0)
            {
                Marshal.ThrowExceptionForHR(queryResult);
            }

            throw new InvalidOperationException("DWM returned an unusable thumbnail source size.");
        }

        return thumbnail;
    }

    internal static void UpdateThumbnail(
        IntPtr thumbnail,
        WindowMotionPhysicalRect surfaceBounds,
        byte opacity)
    {
        var properties = new DwmThumbnailProperties
        {
            Flags = DwmTnpRectDestination |
                    DwmTnpOpacity |
                    DwmTnpVisible |
                    DwmTnpSourceClientAreaOnly,
            Destination = NativeRect.FromSize(surfaceBounds.Width, surfaceBounds.Height),
            Opacity = opacity,
            Visible = true,
            SourceClientAreaOnly = false
        };
        ThrowIfFailed(DwmUpdateThumbnailProperties(thumbnail, ref properties));
    }

    internal static void MoveTransitionWindow(
        IntPtr transitionWindow,
        IntPtr sourceWindow,
        WindowMotionPhysicalRect bounds,
        bool show)
    {
        var sourceExtendedStyle = GetWindowLongPtr(sourceWindow, GwlExStyle).ToInt64();
        var insertAfter = (sourceExtendedStyle & WsExTopmost) != 0
            ? new IntPtr(-1)
            : IntPtr.Zero;
        if (!SetWindowPos(
                transitionWindow,
                insertAfter,
                bounds.Left,
                bounds.Top,
                Math.Max(1, bounds.Width),
                Math.Max(1, bounds.Height),
                SwpNoActivate | SwpNoOwnerZOrder | (show ? SwpShowWindow : 0)))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not place the window-motion surface.");
        }
    }

    internal static WindowMotionCapabilityResult ReadCapability(
        IntPtr sourceWindow,
        bool allowMinimizedSource = false)
    {
        var compositionResult = DwmIsCompositionEnabled(out var enabled);
        if (!IsWindow(sourceWindow))
        {
            return new WindowMotionCapabilityResult(
                WindowMotionCapabilityStatus.InvalidSourceWindow);
        }

        if (compositionResult < 0)
        {
            return new WindowMotionCapabilityResult(
                WindowMotionCapabilityStatus.CompositionQueryFailed,
                compositionResult);
        }

        if (!enabled)
        {
            return new WindowMotionCapabilityResult(
                WindowMotionCapabilityStatus.CompositionDisabled);
        }

        // Expanding out of the tray starts from an iconic source on purpose: the controller
        // commits the restore before it registers the thumbnail, so by the time DWM is asked
        // for pixels the window is a real one again.
        return !allowMinimizedSource && IsIconic(sourceWindow)
            ? new WindowMotionCapabilityResult(
                WindowMotionCapabilityStatus.SourceAlreadyMinimized)
            : new WindowMotionCapabilityResult(WindowMotionCapabilityStatus.Ready);
    }

    internal static WindowMotionSurfaceState ReadSurfaceState(
        IntPtr transitionWindow,
        IntPtr sourceWindow)
    {
        var isWindow = transitionWindow != IntPtr.Zero && IsWindow(transitionWindow);
        if (!isWindow)
        {
            return new WindowMotionSurfaceState(false, false, false, false);
        }

        var isCloaked = false;
        int cloakValue;
        var cloakResult = DwmGetWindowAttribute(
            transitionWindow,
            DwmwaCloak,
            out cloakValue,
            sizeof(int));
        if (cloakResult >= 0)
        {
            isCloaked = cloakValue != 0;
        }

        return new WindowMotionSurfaceState(
            true,
            IsWindowVisible(transitionWindow),
            isCloaked,
            IsAboveInZOrder(transitionWindow, sourceWindow));
    }

    internal static WindowMotionSourceState ReadSourceState(IntPtr sourceWindow)
    {
        var isWindow = sourceWindow != IntPtr.Zero && IsWindow(sourceWindow);
        return isWindow
            ? new WindowMotionSourceState(
                true,
                IsWindowEnabled(sourceWindow),
                IsIconic(sourceWindow),
                IsZoomed(sourceWindow))
            : new WindowMotionSourceState(false, false, false, false);
    }

    internal static void ShowTransitionWindow(IntPtr window) => _ = ShowWindow(window, SwShowNoActivate);

    internal static void HideTransitionWindow(IntPtr window) => _ = ShowWindow(window, SwHide);

    internal static void SetSourceEnabled(IntPtr window, bool enabled)
    {
        if (!TrySetSourceEnabled(window, enabled))
        {
            throw new InvalidOperationException("Could not change the source window enabled state.");
        }
    }

    internal static bool TrySetSourceEnabled(IntPtr window, bool enabled)
    {
        if (window == IntPtr.Zero || !IsWindow(window))
        {
            return false;
        }

        _ = EnableWindow(window, enabled);
        return IsWindowEnabled(window) == enabled;
    }

    internal static bool IsForegroundWindow(IntPtr window) =>
        window != IntPtr.Zero && GetForegroundWindow() == window;

    internal static uint ReadLastInputTick()
    {
        var info = new LastInputInfo
        {
            Size = (uint)Marshal.SizeOf<LastInputInfo>()
        };
        return GetLastInputInfo(ref info) ? info.Tick : 0;
    }

    internal static void RestoreForegroundNoThrow(IntPtr window, uint inputTickAtStart)
    {
        var foregroundWindow = GetForegroundWindow();
        if (window == IntPtr.Zero ||
            !IsWindow(window) ||
            IsIconic(window) ||
            (foregroundWindow != window &&
             (inputTickAtStart == 0 || ReadLastInputTick() != inputTickAtStart)))
        {
            return;
        }

        _ = SetForegroundWindow(window);
        _ = SetActiveWindow(window);
        _ = SetFocus(window);
    }

    internal static void UnregisterThumbnailNoThrow(IntPtr thumbnail)
    {
        if (thumbnail != IntPtr.Zero)
        {
            _ = DwmUnregisterThumbnail(thumbnail);
        }
    }

    internal static void DestroyWindowNoThrow(IntPtr window)
    {
        if (window != IntPtr.Zero && IsWindow(window))
        {
            _ = DestroyWindow(window);
        }
    }

    internal static void FlushComposition() => ThrowIfFailed(DwmFlush());

    internal static void FlushCompositionNoThrow() => _ = DwmFlush();

    private static bool IsAboveInZOrder(IntPtr candidate, IntPtr source)
    {
        var current = GetTopWindow(IntPtr.Zero);
        for (var index = 0; current != IntPtr.Zero && index < 4096; index++)
        {
            if (current == candidate)
            {
                return true;
            }
            if (current == source)
            {
                return false;
            }
            current = GetWindow(current, GwHwndNext);
        }
        return false;
    }

    private static void EnsureWindowClass()
    {
        if (_classAtom != 0)
        {
            return;
        }

        lock (ClassRegistrationLock)
        {
            if (_classAtom != 0)
            {
                return;
            }

            var windowClass = new WindowClass
            {
                Size = (uint)Marshal.SizeOf<WindowClass>(),
                WindowProcedure = WindowProcedure,
                Instance = GetModuleHandle(null),
                ClassName = TransitionClassName
            };
            _classAtom = RegisterClassEx(ref windowClass);
            if (_classAtom == 0)
            {
                var error = (uint)Marshal.GetLastWin32Error();
                if (error != ErrorClassAlreadyExists)
                {
                    throw new Win32Exception((int)error, "Could not register the window-motion surface class.");
                }

                _classAtom = 1;
            }
        }
    }

    private static IntPtr DefWindowProcedure(IntPtr window, uint message, IntPtr wParam, IntPtr lParam) =>
        DefWindowProc(window, message, wParam, lParam);

    private static void ThrowIfFailed(int result)
    {
        if (result < 0)
        {
            Marshal.ThrowExceptionForHR(result);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowClass
    {
        internal uint Size;
        internal uint Style;
        [MarshalAs(UnmanagedType.FunctionPtr)]
        internal WndProc WindowProcedure;
        internal int ClassExtraBytes;
        internal int WindowExtraBytes;
        internal IntPtr Instance;
        internal IntPtr Icon;
        internal IntPtr Cursor;
        internal IntPtr BackgroundBrush;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string? MenuName;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string ClassName;
        internal IntPtr SmallIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        internal int Left;
        internal int Top;
        internal int Right;
        internal int Bottom;

        internal readonly WindowMotionPhysicalRect ToPhysicalRect() => new(Left, Top, Right, Bottom);

        internal static NativeRect FromSize(int width, int height) => new()
        {
            Left = 0,
            Top = 0,
            Right = Math.Max(1, width),
            Bottom = Math.Max(1, height)
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        internal int Size;
        internal NativeRect Monitor;
        internal NativeRect Work;
        internal uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeSize
    {
        internal int Width;
        internal int Height;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        internal uint Size;
        internal uint Tick;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DwmMargins
    {
        internal DwmMargins(int leftWidth, int rightWidth, int topHeight, int bottomHeight)
        {
            LeftWidth = leftWidth;
            RightWidth = rightWidth;
            TopHeight = topHeight;
            BottomHeight = bottomHeight;
        }

        internal int LeftWidth { get; }
        internal int RightWidth { get; }
        internal int TopHeight { get; }
        internal int BottomHeight { get; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DwmThumbnailProperties
    {
        internal uint Flags;
        internal NativeRect Destination;
        internal NativeRect Source;
        internal byte Opacity;
        [MarshalAs(UnmanagedType.Bool)]
        internal bool Visible;
        [MarshalAs(UnmanagedType.Bool)]
        internal bool SourceClientAreaOnly;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NotifyIconIdentifier
    {
        internal uint Size;
        internal IntPtr Window;
        internal uint Id;
        internal Guid Item;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AppBarData
    {
        internal uint Size;
        internal IntPtr Window;
        internal uint CallbackMessage;
        internal uint Edge;
        internal NativeRect Bounds;
        internal int Parameter;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr WndProc(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassEx(ref WindowClass windowClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
        uint extendedStyle,
        string className,
        string? windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        IntPtr parent,
        IntPtr menu,
        IntPtr instance,
        IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProc(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr window, out NativeRect bounds);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetWindowLongPtr(IntPtr window, int index);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(
        IntPtr window,
        IntPtr insertAfter,
        int x,
        int y,
        int width,
        int height,
        uint flags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnableWindow(IntPtr window, [MarshalAs(UnmanagedType.Bool)] bool enabled);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowEnabled(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr SetActiveWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr SetFocus(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsZoomed(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr window, uint command);

    [DllImport("user32.dll")]
    private static extern IntPtr GetTopWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr window, uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo monitorInfo);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string? moduleName);

    [DllImport("shell32.dll", PreserveSig = true)]
    private static extern int Shell_NotifyIconGetRect(
        ref NotifyIconIdentifier identifier,
        out NativeRect iconRect);

    [DllImport("shell32.dll")]
    private static extern IntPtr SHAppBarMessage(uint message, ref AppBarData data);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmIsCompositionEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmRegisterThumbnail(
        IntPtr destinationWindow,
        IntPtr sourceWindow,
        out IntPtr thumbnail);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmUnregisterThumbnail(IntPtr thumbnail);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmQueryThumbnailSourceSize(
        IntPtr thumbnail,
        out NativeSize sourceSize);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmUpdateThumbnailProperties(
        IntPtr thumbnail,
        ref DwmThumbnailProperties properties);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr window,
        int attribute,
        ref int value,
        int valueSize);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmGetWindowAttribute(
        IntPtr window,
        int attribute,
        out NativeRect value,
        int valueSize);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmGetWindowAttribute(
        IntPtr window,
        int attribute,
        out int value,
        int valueSize);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmFlush();

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmExtendFrameIntoClientArea(
        IntPtr window,
        ref DwmMargins margins);
}
