using System.ComponentModel;
using System.Collections.Specialized;
using System.Drawing;
using System.Globalization;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using CodexGuardian.Localization;
using CodexGuardian.Models;
using CodexGuardian.Services;
using CodexGuardian.ViewModels;
using CodexGuardian.WindowMotion;
using Forms = System.Windows.Forms;
using BitmapScalingMode = System.Windows.Media.BitmapScalingMode;
using CompositionTarget = System.Windows.Media.CompositionTarget;
using PixelFormats = System.Windows.Media.PixelFormats;
using ScaleTransform = System.Windows.Media.ScaleTransform;
using TranslateTransform = System.Windows.Media.TranslateTransform;
using VisualTreeHelper = System.Windows.Media.VisualTreeHelper;

namespace CodexGuardian;

public partial class MainWindow : Window
{
    private static readonly DependencyPropertyKey IsAttachmentImportInProgressPropertyKey =
        DependencyProperty.RegisterReadOnly(
            nameof(IsAttachmentImportInProgress),
            typeof(bool),
            typeof(MainWindow),
            new PropertyMetadata(false));

    public static readonly DependencyProperty IsAttachmentImportInProgressProperty =
        IsAttachmentImportInProgressPropertyKey.DependencyProperty;

    private const string FollowUpDetailPage = "FollowUpDetail";
    private const int GwlExStyle = -20;
    private const int WsExTransparent = 0x00000020;
    private const int WsExToolWindow = 0x00000080;
    private const int WsExNoActivate = 0x08000000;
    private const int DwmwaNcRenderingPolicy = 2;
    private const int DwmwaWindowCornerPreference = 33;
    private const int DwmwaBorderColor = 34;
    private const int DwmNcRenderingEnabled = 2;
    private const uint SwpNoSize = 0x0001;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpNoActivate = 0x0010;
    private const uint SwpNoOwnerZOrder = 0x0200;

    private static readonly IReadOnlyDictionary<string, string> LightThemePalette =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["CanvasBrush"] = "#FFF2EFE7",
            ["PaperBrush"] = "#F7F8F4EC",
            ["SurfaceSubtleBrush"] = "#EDE9E3D8",
            ["BorderBrush"] = "#5AD2C9BA",
            ["BorderStrongBrush"] = "#8AC1B7A7",
            ["GlassSurfaceBrush"] = "#F0F7F3EB",
            ["GlassSurfaceStrongBrush"] = "#FAFBF8F1",
            ["GlassBorderBrush"] = "#78CEC4B5",
            // The hover veil sits above the lit layer so a switch keeps answering the pointer once it is
            // on, which means this brush has to tint rather than cover: at 94% white it repainted an
            // enabled switch's green fill and outline into near-white the moment the pointer arrived. The
            // light theme darkens on hover everywhere else (see ConversationHoverBrush, ControlHoverBrush),
            // so tint with ink at the same alpha the dark theme lifts with white.
            ["GlassHighlightBrush"] = "#1F28251F",
            ["AmbientGlowBrush"] = "#2E2E9EA2",
            ["WindowEdgeBrush"] = "#665FB0B2",
            ["ConversationSurfaceBrush"] = "#F7FBF8F1",
            ["ConversationHoverBrush"] = "#FFF3EEE4",
            ["ConversationSelectedBrush"] = "#F2DFEFEE",
            ["ConversationPlaceholderBrush"] = "#B8E8E2D7",
            ["FloatingShadowBrush"] = "#59443E35",
            ["ControlSurfaceBrush"] = "#FFF3EFE6",
            ["ControlHoverBrush"] = "#FFE8E1D5",
            ["FieldSurfaceBrush"] = "#FFFBF8F1",
            ["DisabledSurfaceBrush"] = "#FFE7E1D6",
            ["DisabledBorderBrush"] = "#FFD1C8B8",
            ["DisabledInkBrush"] = "#FF777067",
            ["InkBrush"] = "#FF28251F",
            ["InkDimBrush"] = "#FF5E5A52",
            ["InkMutedBrush"] = "#FF5E5A52",
            ["InkSubtleBrush"] = "#FF777168",
            ["ToggleThumbBrush"] = "#FFFFFCF5",
            ["PrimaryBrush"] = "#FF0F7A7E",
            ["PrimaryHoverBrush"] = "#FF0C6467",
            ["PrimarySoftBrush"] = "#330F7A7E",
            ["SignatureBrush"] = "#FF0F7A7E",
            ["SignatureSoftBrush"] = "#330F7A7E",
            ["GreenBrush"] = "#FF2C7A45",
            ["GreenSoftBrush"] = "#D9DEEDE0",
            ["OrangeBrush"] = "#FFA85F17",
            ["OrangeSoftBrush"] = "#D9FBE6CD",
            ["YellowBrush"] = "#FF8A6B1B",
            ["YellowSoftBrush"] = "#D9F7EBCE",
            ["BlueBrush"] = "#FF0F7A7E",
            ["BlueSoftBrush"] = "#330F7A7E",
            ["DangerBrush"] = "#FFB34555",
            ["DangerSoftBrush"] = "#D9F3DEE1"
        };

    private static readonly IReadOnlyDictionary<string, string> DarkThemePalette =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["CanvasBrush"] = "#FF070B14",
            ["PaperBrush"] = "#E6151C2A",
            ["SurfaceSubtleBrush"] = "#B31B2638",
            ["BorderBrush"] = "#2EFFFFFF",
            ["BorderStrongBrush"] = "#47FFFFFF",
            ["GlassSurfaceBrush"] = "#C7141B29",
            ["GlassSurfaceStrongBrush"] = "#E61A2232",
            ["GlassBorderBrush"] = "#33FFFFFF",
            ["GlassHighlightBrush"] = "#1FFFFFFF",
            ["AmbientGlowBrush"] = "#667FD3D5",
            ["WindowEdgeBrush"] = "#497FD3D5",
            ["ConversationSurfaceBrush"] = "#E61A2232",
            ["ConversationHoverBrush"] = "#F0212C3D",
            ["ConversationSelectedBrush"] = "#D91E4247",
            ["ConversationPlaceholderBrush"] = "#8F172235",
            ["FloatingShadowBrush"] = "#A6000000",
            ["ControlSurfaceBrush"] = "#CC1B2433",
            ["ControlHoverBrush"] = "#E6233042",
            ["FieldSurfaceBrush"] = "#E61C2534",
            ["DisabledSurfaceBrush"] = "#99202835",
            ["DisabledBorderBrush"] = "#26FFFFFF",
            ["DisabledInkBrush"] = "#77869A",
            ["InkBrush"] = "#F7FAFF",
            ["InkDimBrush"] = "#A0AFBF",
            ["InkMutedBrush"] = "#B8C4D5",
            ["InkSubtleBrush"] = "#8796AB",
            ["ToggleThumbBrush"] = "#FFF7FAFF",
            ["PrimaryBrush"] = "#7FD3D5",
            ["PrimaryHoverBrush"] = "#A6E3E2",
            ["PrimarySoftBrush"] = "#332C7C80",
            ["SignatureBrush"] = "#7FD3D5",
            ["SignatureSoftBrush"] = "#332C7C80",
            ["GreenBrush"] = "#7BD98C",
            ["GreenSoftBrush"] = "#B31B3D24",
            ["OrangeBrush"] = "#FDB674",
            ["OrangeSoftBrush"] = "#B34A3016",
            ["YellowBrush"] = "#F0CE7E",
            ["YellowSoftBrush"] = "#B3453A1C",
            ["BlueBrush"] = "#7FD3D5",
            ["BlueSoftBrush"] = "#B31E4247",
            ["DangerBrush"] = "#FF8192",
            ["DangerSoftBrush"] = "#B346242E"
        };

    private readonly MainViewModel _viewModel;
    private readonly LocalizationService _localization;
    private readonly bool _enableTray;
    private readonly GuardianLog? _log;
    private Forms.NotifyIcon? _notifyIcon;
    private Icon? _trayIcon;
    private bool _languageChangedSubscribed;
    private bool _viewModelEventsSubscribed;
    private bool _allowClose;
    private WindowMotionController? _windowMotion;
    private readonly FollowUpAttachmentRuntime? _attachmentRuntime;
    private readonly bool _previewIsolationMode;
    private CancellationTokenSource? _attachmentImportCancellation;
    private CancellationTokenSource? _attachmentThumbnailCancellation;
    private FollowUpMessageItem? _attachmentThumbnailOwner;
    private string _lastSelectedPage;
    private double _taskListVerticalOffset;
    private double _taskListHorizontalOffset;
    private bool _restoreTaskListContextPending;
    private GuardianTaskItem? _conversationDragCandidate;
    private GuardianTaskItem? _conversationDragSource;
    private Button? _conversationDragCaptureOwner;
    private ListBoxItem? _conversationDragContainer;
    private FollowUpDragPreviewWindow? _conversationDragPreview;
    private System.Windows.Point _conversationDragStartPoint;
    private System.Windows.Vector _conversationDragPointerOffset;
    private int? _conversationDropInsertionIndex;
    private int? _conversationVisualInsertionIndex;
    private System.Windows.Point _conversationPointer;
    private double _conversationAutoScrollVelocity;
    private DateTime _conversationRenderingTimestampUtc;
    private bool _conversationRenderingSubscribed;
    private ScrollViewer? _inertialScrollViewer;
    private double _inertialScrollVelocity;
    private DateTime _inertialScrollTimestampUtc;
    private bool _inertialScrollSubscribed;
    private bool _statusGlowSubscribed;
    private DateTime _statusGlowTimestampUtc;
    private double _statusGlowPhase;
    // Window_StateChanged fires for maximize and restore as well as for minimize, and only the
    // minimize -> visible edge should replay the entrance animation. WindowState alone cannot tell
    // those apart, so the previous value is carried here.
    private WindowState _lastWindowState = WindowState.Normal;
    // Shell_NotifyIconGetRect needs the HWND and the id that WinForms keeps private inside
    // NotifyIcon. They are stable for the icon's lifetime so they are read once by reflection;
    // the rect itself is re-read on every animation because the notification area reflows
    // whenever an icon appears, hides, or folds into the overflow flyout.
    private (IntPtr Window, uint Id)? _trayIconIdentity;
    private readonly HashSet<ListBoxItem> _conversationDisplacedContainers = new();
    private ListBoxItem? _conversationSettleContainer;
    private DateTime _conversationSettleStartedUtc;
    private bool _conversationIsSettling;
    private bool _conversationDropCommitPending;
    private int _conversationSettleOldIndex;
    private int _conversationSettleNewIndex;
    private bool _releasingConversationDragCapture;
    private FollowUpMessageItem? _followUpDragCandidate;
    private FollowUpMessageItem? _followUpDragSource;
    private Button? _followUpDragCaptureOwner;
    private ListBoxItem? _followUpDragContainer;
    private FollowUpDragPreviewWindow? _followUpDragPreview;
    private System.Windows.Point _followUpDragStartPoint;
    private System.Windows.Vector _followUpDragPointerOffset;
    private int? _followUpDropInsertionIndex;
    private int? _followUpVisualInsertionIndex;
    private System.Windows.Point _followUpPointer;
    private double _followUpAutoScrollVelocity;
    private DateTime _followUpRenderingTimestampUtc;
    private bool _followUpRenderingSubscribed;
    private readonly HashSet<ListBoxItem> _followUpDisplacedContainers = new();
    private ListBoxItem? _followUpSettleContainer;
    private DateTime _followUpSettleStartedUtc;
    private bool _followUpIsSettling;
    private int _followUpSettleOldIndex;
    private int _followUpSettleNewIndex;
    private bool _releasingFollowUpDragCapture;
    private AttachmentItemViewModel? _attachmentDragCandidate;
    private AttachmentItemViewModel? _attachmentDragSource;
    private FollowUpMessageItem? _attachmentDragOwner;
    private Button? _attachmentDragCaptureOwner;
    private ItemsControl? _attachmentDragRail;
    private ScrollViewer? _attachmentDragScrollViewer;
    private FrameworkElement? _attachmentDragContainer;
    private FollowUpDragPreviewWindow? _attachmentDragPreview;
    private System.Windows.Point _attachmentDragStartPoint;
    private System.Windows.Vector _attachmentDragPointerOffset;
    private System.Windows.Point _attachmentPointer;
    private int? _attachmentDropInsertionIndex;
    private int? _attachmentVisualInsertionIndex;
    private double _attachmentAutoScrollVelocity;
    private DateTime _attachmentRenderingTimestampUtc;
    private bool _attachmentRenderingSubscribed;
    private readonly HashSet<FrameworkElement> _attachmentDisplacedContainers = new();
    private FrameworkElement? _attachmentSettleContainer;
    private DateTime _attachmentSettleStartedUtc;
    private bool _attachmentIsSettling;
    private int _attachmentSettleOldIndex;
    private int _attachmentSettleNewIndex;
    private bool _attachmentDropCommitPending;
    private bool _releasingAttachmentDragCapture;
    private int _workspaceTransitionVersion;
    private readonly List<UIElement> _routeRevealElements = new();
    private DispatcherTimer? _routeRevealCompletionTimer;
    private int _conversationContentTransitionVersion;
    private DispatcherTimer? _conversationContentTransitionTimer;
    private readonly List<UIElement> _conversationContentRevealElements = new();
    private DependencyObject? _suppressedToolTipOwner;
    private object _suppressedToolTipIsEnabledLocalValue = DependencyProperty.UnsetValue;
    private UIElement? _activeRouteRoot;
    private int _themeTransitionVersion;
    private System.Windows.Media.EllipseGeometry? _themeTransitionEllipse;
    private System.Windows.Media.CombinedGeometry? _themeTransitionClip;
    private int _activated;
    private int _deactivated;

    public bool IsAttachmentImportAvailable =>
        !_previewIsolationMode && _attachmentRuntime is not null;

    public bool IsAttachmentImportInProgress =>
        (bool)GetValue(IsAttachmentImportInProgressProperty);

    public MainWindow(MainViewModel viewModel, bool enableTray = true)
        : this(
            viewModel,
            enableTray,
            attachmentRuntime: null,
            previewIsolationMode: false,
            log: null)
    {
    }

    internal MainWindow(
        MainViewModel viewModel,
        bool enableTray,
        FollowUpAttachmentRuntime? attachmentRuntime,
        bool previewIsolationMode,
        GuardianLog? log)
    {
        InitializeComponent();
        _viewModel = viewModel;
        _localization = (LocalizationService)Application.Current.Resources["Loc"];
        _enableTray = enableTray;
        _log = log;
        _attachmentRuntime = attachmentRuntime;
        _previewIsolationMode = previewIsolationMode;
        DataContext = viewModel;
        _lastSelectedPage = viewModel.SelectedPage;
        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        _viewModel.Tasks.CollectionChanged += OnConversationCollectionChanged;
        _viewModel.FollowUpMessageFocusRequested += OnFollowUpMessageFocusRequested;
        _viewModel.FollowUpAttachmentPickerRequested += OnFollowUpAttachmentPickerRequested;
        _viewModel.UiThemeChanged += OnUiThemeChanged;
        _viewModelEventsSubscribed = true;
        _localization.LanguageChanged += OnLanguageChanged;
        _languageChangedSubscribed = true;
        ApplyTheme(_viewModel.UiTheme);
        Loaded += OnWindowLoaded;
    }

    internal void ActivateForStartup(bool showWindow)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _deactivated) != 0,
            this);
        if (Interlocked.Exchange(ref _activated, 1) != 0)
        {
            return;
        }

        if (_enableTray)
        {
            Icon? trayIcon = null;
            Forms.ContextMenuStrip? menu = null;
            Forms.NotifyIcon? notifyIcon = null;
            try
            {
                trayIcon = CreateTrayIcon();
                menu = BuildTrayMenu();
                notifyIcon = new Forms.NotifyIcon();
                notifyIcon.Text = _localization["App.Title"];
                notifyIcon.Icon = trayIcon;
                notifyIcon.ContextMenuStrip = menu;
                notifyIcon.DoubleClick += OnNotifyIconDoubleClick;
                _trayIcon = trayIcon;
                trayIcon = null;
                _notifyIcon = notifyIcon;
                notifyIcon = null;
                menu = null;
                _notifyIcon.Visible = true;
            }
            catch (Exception failure)
            {
                Exception? cleanupFailure = failure;
                CleanupTrayResources(ref cleanupFailure);
                TryCleanup(() =>
                {
                    if (notifyIcon is not null)
                    {
                        notifyIcon.ContextMenuStrip = null;
                    }
                }, ref cleanupFailure);
                TryCleanup(() => notifyIcon?.Dispose(), ref cleanupFailure);
                TryCleanup(() => menu?.Dispose(), ref cleanupFailure);
                TryCleanup(() => trayIcon?.Dispose(), ref cleanupFailure);
                ExceptionDispatchInfo.Capture(failure).Throw();
            }
        }

        if (showWindow)
        {
            Show();
        }
    }

    internal void DeactivateForExit()
    {
        if (Interlocked.Exchange(ref _deactivated, 1) != 0)
        {
            return;
        }

        _allowClose = true;
        Exception? failure = null;
        TryCleanup(() => _windowMotion?.Dispose(), ref failure);
        _windowMotion = null;
        CancelAttachmentImport();
        CancelAttachmentThumbnailLoad();
        CancelConversationDrag();
        StopInertialScroll();
        CancelConversationContentTransition();
        CancelFollowUpDrag();
        CancelAttachmentDrag();
        RestoreSuppressedToolTip();
        DetachViewModelEvents();
        CleanupTrayResources(ref failure);
        TryCleanup(() =>
        {
            if (IsVisible)
            {
                Hide();
            }
        }, ref failure);
        TryCleanup(Close, ref failure);
        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private Forms.ContextMenuStrip BuildTrayMenu()
    {
        var menu = new Forms.ContextMenuStrip();
        var showItem = new Forms.ToolStripMenuItem(_localization["Tray.ShowConsole"]);
        showItem.Click += (_, _) => Dispatcher.Invoke(ShowFromTray);

        var scanItem = new Forms.ToolStripMenuItem(_localization["Tray.ScanNow"]);
        scanItem.Click += (_, _) => Dispatcher.Invoke(() =>
        {
            if (!CanRunTrayCallback())
            {
                return;
            }

            if (_viewModel.ScanNowCommand.CanExecute(null))
            {
                _viewModel.ScanNowCommand.Execute(null);
            }
        });

        var exitItem = new Forms.ToolStripMenuItem(_localization["Tray.Exit"]);
        exitItem.Click += async (_, _) =>
        {
            try
            {
                var request = await Dispatcher.InvokeAsync(RequestExitAsync);
                await request;
            }
            catch
            {
                Environment.ExitCode = Math.Max(Environment.ExitCode, 1);
            }
        };

        menu.Items.Add(showItem);
        menu.Items.Add(scanItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(exitItem);
        return menu;
    }

    private void ShowFromTray()
    {
        if (!CanRunTrayCallback())
        {
            return;
        }

        Show();
        var wasMinimized = WindowState == WindowState.Minimized;
        if (wasMinimized)
        {
            // Leaving iconic triggers Window_StateChanged, which runs BeginExpandFromShell and
            // restarts the status dot & halo, so this path needs no further setup.
            WindowState = WindowState.Normal;
        }
        else
        {
            // The window was hidden but never iconic, so Window_StateChanged will not fire and the
            // expand animation has to be started directly. ApplyGuardStatusDot is idempotent - if the
            // dot is already running it does nothing - which is how the two restore paths (this one
            // and the StateChanged path) coexist without restarting each other's work.
            ApplyGuardStatusDot(animate: false);
            BeginExpandFromShell();
        }

        Activate();
        Focus();
    }

    private void OnNotifyIconDoubleClick(object? sender, EventArgs eventArgs)
    {
        if (!CanRunTrayCallback())
        {
            return;
        }

        Dispatcher.Invoke(ShowFromTray);
    }

    /// <summary>
    /// Where on the shell this window lives: its tray icon if the shell will say, otherwise the
    /// end of the taskbar that holds the notification area. The minimize animation shrinks into
    /// this rect and the expand animation grows back out of it, so both directions trace the same
    /// path between the window and the icon the user actually clicks.
    /// </summary>
    private WindowMotionPhysicalRect? ResolveShellAnchorBounds()
    {
        var identity = ResolveTrayIconIdentity();
        if (identity.HasValue &&
            WindowMotionNative.TryGetTrayIconRect(
                identity.Value.Window,
                identity.Value.Id,
                out var iconBounds))
        {
            return iconBounds;
        }

        return WindowMotionNative.TryGetTaskbarAnchorRect(out var taskbarBounds)
            ? taskbarBounds
            : null;
    }

    private (IntPtr Window, uint Id)? ResolveTrayIconIdentity()
    {
        if (_trayIconIdentity.HasValue)
        {
            return _trayIconIdentity;
        }

        var notifyIcon = _notifyIcon;
        if (notifyIcon is null)
        {
            return null;
        }

        // The field names moved from "window"/"id" to "_window"/"_id" between .NET Framework and
        // .NET, and could move again. A miss here costs the icon-accurate anchor and nothing else:
        // the caller falls back to the taskbar end, which is within a few dozen pixels of it.
        try
        {
            const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var type = typeof(Forms.NotifyIcon);
            var windowField = type.GetField("_window", flags) ?? type.GetField("window", flags);
            var idField = type.GetField("_id", flags) ?? type.GetField("id", flags);
            if (windowField?.GetValue(notifyIcon) is Forms.NativeWindow window &&
                idField?.GetValue(notifyIcon) is int id &&
                window.Handle != IntPtr.Zero)
            {
                _trayIconIdentity = (window.Handle, (uint)id);
            }
        }
        catch (Exception failure) when (
            failure is MemberAccessException or
                InvalidOperationException or
                TargetException or
                NotSupportedException)
        {
        }

        return _trayIconIdentity;
    }

    private void OnLanguageChanged(object? sender, LanguageChangedEventArgs eventArgs)
    {
        Dispatcher.Invoke(UpdateCaptionControls);
        var notifyIcon = _notifyIcon;
        if (notifyIcon is null)
        {
            return;
        }

        Dispatcher.Invoke(() =>
        {
            if (!ReferenceEquals(_notifyIcon, notifyIcon) ||
                Volatile.Read(ref _deactivated) != 0)
            {
                return;
            }

            notifyIcon.Text = _localization["App.Title"];
            var previousMenu = notifyIcon.ContextMenuStrip;
            notifyIcon.ContextMenuStrip = BuildTrayMenu();
            previousMenu?.Dispose();
        });
    }

    private void OnWindowLoaded(object sender, RoutedEventArgs eventArgs)
    {
        _windowMotion ??= new WindowMotionController(
            new System.Windows.Interop.WindowInteropHelper(this).Handle,
            Dispatcher);
        ApplyWindowComposition(_viewModel.UiTheme);
        UpdateCaptionControls();
        AnimateWindowIn();
        ApplyRouteVisibility(_viewModel.SelectedPage, immediate: true);
        SettleRailIndicator(_viewModel.SelectedPage);
        SettleConversationScopeIndicator();
        ApplyGuardStatusDot(animate: false);
        StartStatusGlow();
        if (_viewModel.IsFollowUpDetailPage && _viewModel.SelectedFollowUpMessage is not null)
        {
            FocusFollowUpMessage(_viewModel.SelectedFollowUpMessage, focusMessageEditor: false);
        }
        ScheduleSelectedAttachmentThumbnailLoad();
        // Last, and deliberately not awaited: the window is already up, and a slow or unreachable network
        // must not hold the first frame. The check reports itself through the brand mark when it lands.
        _viewModel.BeginStartupUpdateCheck();
    }

    private void Window_Activated(object? sender, EventArgs eventArgs)
    {
        StartStatusGlow();
    }

    private void ApplyWindowComposition(string theme)
    {
        if (PresentationSource.FromVisual(this) is null)
        {
            return;
        }

        try
        {
            var handle = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            var renderingPolicy = DwmNcRenderingEnabled;
            _ = DwmSetWindowAttribute(handle, DwmwaNcRenderingPolicy, ref renderingPolicy, sizeof(int));

            var cornerPreference = 2;
            _ = DwmSetWindowAttribute(
                handle,
                DwmwaWindowCornerPreference,
                ref cornerPreference,
                sizeof(int));

            var edgeColor = string.Equals(theme, UiThemes.Dark, StringComparison.Ordinal)
                ? System.Windows.Media.Color.FromRgb(0x42, 0x58, 0x7A)
                : System.Windows.Media.Color.FromRgb(0xB8, 0xAE, 0x9E);
            var borderColor = ToColorRef(edgeColor);
            _ = DwmSetWindowAttribute(handle, DwmwaBorderColor, ref borderColor, sizeof(int));

            var margins = new DwmMargins(1, 1, 1, 1);
            _ = DwmExtendFrameIntoClientArea(handle, ref margins);
        }
        catch (Exception)
        {
            // Native shadow, rounded corners, and border tint are best-effort shell details.
        }
    }

    private static int ToColorRef(System.Windows.Media.Color color) =>
        color.R | color.G << 8 | color.B << 16;

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName is nameof(MainViewModel.SelectedTask) or
            nameof(MainViewModel.SelectedFollowUpMessage))
        {
            CancelAttachmentDrag();
            CancelAttachmentImport();
            CancelAttachmentThumbnailLoad();
            _ = Dispatcher.BeginInvoke(
                DispatcherPriority.DataBind,
                new Action(ScheduleSelectedAttachmentThumbnailLoad));
            if (eventArgs.PropertyName == nameof(MainViewModel.SelectedTask))
            {
                ScheduleTaskWorkbenchTransition();
            }
        }

        if (eventArgs.PropertyName != nameof(MainViewModel.SelectedPage))
        {
            if (eventArgs.PropertyName == nameof(MainViewModel.ConversationNavigationMotionRevision))
            {
                ScheduleConversationContentTransition();
            }

            if (eventArgs.PropertyName == nameof(MainViewModel.ConversationScope))
            {
                if (Dispatcher.CheckAccess())
                {
                    AnimateConversationScopeIndicator();
                }
                else
                {
                    _ = Dispatcher.BeginInvoke(
                        DispatcherPriority.DataBind,
                        new Action(AnimateConversationScopeIndicator));
                }
            }

            if (eventArgs.PropertyName == nameof(MainViewModel.IsMonitoring))
            {
                // Marshalled inside the method: monitoring flips from the engine thread.
                ApplyGuardStatusDot(animate: true);
            }

            return;
        }

        if (!Dispatcher.CheckAccess())
        {
            _ = Dispatcher.BeginInvoke(
                DispatcherPriority.DataBind,
                new Action(HandleSelectedPageChanged));
            return;
        }

        HandleSelectedPageChanged();
    }

    private void HandleSelectedPageChanged()
    {
        var selectedPage = _viewModel.SelectedPage;
        var previousPage = _lastSelectedPage;
        var pageChanged = !string.Equals(selectedPage, previousPage, StringComparison.Ordinal);
        if (string.Equals(selectedPage, FollowUpDetailPage, StringComparison.Ordinal) &&
            !string.Equals(previousPage, FollowUpDetailPage, StringComparison.Ordinal))
        {
            CaptureTaskListContext();
            _restoreTaskListContextPending = true;
        }

        if (!string.Equals(selectedPage, FollowUpDetailPage, StringComparison.Ordinal))
        {
            CancelFollowUpDrag();
            CancelAttachmentDrag();
            CancelAttachmentImport();
            CancelAttachmentThumbnailLoad();
        }
        if (!string.Equals(selectedPage, "Tasks", StringComparison.Ordinal))
        {
            CancelConversationDrag();
            StopInertialScroll();
            StopStatusGlow();
        }
        else
        {
            StartStatusGlow();
        }

        if (string.Equals(selectedPage, "Tasks", StringComparison.Ordinal) &&
            _restoreTaskListContextPending)
        {
            _restoreTaskListContextPending = false;
            _ = Dispatcher.BeginInvoke(
                DispatcherPriority.Loaded,
                new Action(RestoreTaskListContext));
        }

        if (pageChanged)
        {
            DismissOpenToolTip();
            AnimateRailIndicator(selectedPage);
            var fromY = string.Equals(selectedPage, FollowUpDetailPage, StringComparison.Ordinal)
                ? 10d
                : string.Equals(previousPage, FollowUpDetailPage, StringComparison.Ordinal)
                    ? -8d
                    : 8d;
            ScheduleWorkspaceTransition(previousPage, selectedPage, fromY);
        }

        _lastSelectedPage = selectedPage;
        ScheduleSelectedAttachmentThumbnailLoad();
    }

    // Rail buttons are 40 tall with a 5 margin on each side, so slot n starts at n * 50.
    // The 20-tall indicator is centred in its slot, hence the 15 inset.
    private const double RailIndicatorStride = 50d;
    private const double RailIndicatorInset = 15d;

    private int _railIndicatorSlot = -1;

    // FollowUpDetail is reached from the conversations list and keeps that rail slot lit, so
    // it maps to the same index - otherwise opening a conversation would slide the bar away
    // from the section the user is still inside.
    private static int GetRailIndicatorSlot(string page) => page switch
    {
        "Tasks" or FollowUpDetailPage => 0,
        "Overview" => 1,
        "Recovery" => 2,
        "KeepAlive" => 3,
        "Settings" => 4,
        "UserGuide" => -1,
        _ => -1,
    };

    private void SettleRailIndicator(string selectedPage)
    {
        var slot = GetRailIndicatorSlot(selectedPage);
        if (slot < 0)
        {
            return;
        }

        _railIndicatorSlot = slot;
        RailIndicatorOffset.BeginAnimation(TranslateTransform.YProperty, null);
        RailIndicatorStretch.BeginAnimation(ScaleTransform.ScaleYProperty, null);
        RailSelectionIndicator.BeginAnimation(UIElement.OpacityProperty, null);
        RailIndicatorOffset.Y = slot * RailIndicatorStride + RailIndicatorInset;
        RailIndicatorStretch.ScaleY = 1d;
        RailSelectionIndicator.Opacity = 1d;
    }

    private void AnimateRailIndicator(string selectedPage)
    {
        var slot = GetRailIndicatorSlot(selectedPage);
        if (slot < 0 || slot == _railIndicatorSlot)
        {
            return;
        }

        if (!IsLoaded || !SystemParameters.ClientAreaAnimation)
        {
            SettleRailIndicator(selectedPage);
            return;
        }

        _railIndicatorSlot = slot;
        var slide = new DoubleAnimation(
            slot * RailIndicatorStride + RailIndicatorInset,
            TimeSpan.FromMilliseconds(420))
        {
            EasingFunction = new QuinticEase { EasingMode = EasingMode.EaseOut },
        };
        RailIndicatorOffset.BeginAnimation(TranslateTransform.YProperty, slide);

        // Elongate as it leaves, then settle back with a small overshoot. The bar then reads
        // as one object being pulled across the rail instead of blinking to a new position.
        var stretch = new DoubleAnimationUsingKeyFrames();
        stretch.KeyFrames.Add(new EasingDoubleKeyFrame(
            1.75d,
            KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(150)),
            new CubicEase { EasingMode = EasingMode.EaseOut }));
        stretch.KeyFrames.Add(new EasingDoubleKeyFrame(
            1d,
            KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(430)),
            new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.45d }));
        RailIndicatorStretch.BeginAnimation(ScaleTransform.ScaleYProperty, stretch);

        if (RailSelectionIndicator.Opacity < 1d)
        {
            RailSelectionIndicator.BeginAnimation(
                UIElement.OpacityProperty,
                new DoubleAnimation(1d, TimeSpan.FromMilliseconds(220)));
        }
    }

    private int _conversationScopeSlot = -1;

    private static int GetConversationScopeSlot(ConversationScopeKind scope) => scope switch
    {
        ConversationScopeKind.NeedsAttention => 1,
        ConversationScopeKind.Archived => 2,
        _ => 0,
    };

    // The three segments share the row equally through star columns, so the travel distance is
    // only known once the row has been measured - hence the stride is read live rather than
    // being a constant like the rail's.
    private double ConversationScopeStride => TasksScopeStage.ActualWidth / 3d;

    private void OnTasksScopeStageSizeChanged(object sender, SizeChangedEventArgs eventArgs)
    {
        if (!eventArgs.WidthChanged)
        {
            return;
        }

        // A width change invalidates any in-flight slide, and re-running the animation on every
        // resize frame would fight the drag. Snap instead.
        SettleConversationScopeIndicator();
    }

    private void SettleConversationScopeIndicator()
    {
        var slot = GetConversationScopeSlot(_viewModel.ConversationScope);
        _conversationScopeSlot = slot;
        ConversationScopeOffset.BeginAnimation(TranslateTransform.XProperty, null);
        ConversationScopeStretch.BeginAnimation(ScaleTransform.ScaleXProperty, null);
        ConversationScopeOffset.X = slot * ConversationScopeStride;
        ConversationScopeStretch.ScaleX = 1d;
    }

    private void AnimateConversationScopeIndicator()
    {
        var slot = GetConversationScopeSlot(_viewModel.ConversationScope);
        if (slot == _conversationScopeSlot)
        {
            return;
        }

        var stride = ConversationScopeStride;
        if (!IsLoaded || !SystemParameters.ClientAreaAnimation || stride <= 0d)
        {
            SettleConversationScopeIndicator();
            return;
        }

        _conversationScopeSlot = slot;
        var slide = new DoubleAnimation(slot * stride, TimeSpan.FromMilliseconds(320))
        {
            EasingFunction = new QuinticEase { EasingMode = EasingMode.EaseOut },
        };
        ConversationScopeOffset.BeginAnimation(TranslateTransform.XProperty, slide);

        // Widen along the direction of travel, then settle with a small overshoot, so the bar
        // reads as one pill being dragged across the row rather than re-appearing elsewhere.
        var stretch = new DoubleAnimationUsingKeyFrames();
        stretch.KeyFrames.Add(new EasingDoubleKeyFrame(
            1.06d,
            KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(120)),
            new CubicEase { EasingMode = EasingMode.EaseOut }));
        stretch.KeyFrames.Add(new EasingDoubleKeyFrame(
            1d,
            KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(340)),
            new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.35d }));
        ConversationScopeStretch.BeginAnimation(ScaleTransform.ScaleXProperty, stretch);
    }

    // The title-bar dot is the only guard-state readout visible from every page, so it carries the
    // breathing halo rather than a static fill: a still dot and a lit dot look alike at 7px, but
    // something that pulses reads as running without being read.
    private void ApplyGuardStatusDot(bool animate)
    {
        if (!Dispatcher.CheckAccess())
        {
            _ = Dispatcher.BeginInvoke(
                DispatcherPriority.DataBind,
                new Action(() => ApplyGuardStatusDot(animate)));
            return;
        }

        var monitoring = _viewModel.IsMonitoring;
        var motion = animate && IsLoaded && SystemParameters.ClientAreaAnimation;
        if (!motion)
        {
            GuardStatusLive.BeginAnimation(OpacityProperty, null);
            GuardStatusLive.Opacity = monitoring ? 1d : 0d;
        }
        else
        {
            var fade = new DoubleAnimation(
                monitoring ? 1d : 0d,
                TimeSpan.FromMilliseconds(monitoring ? 240d : 200d))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
            };
            GuardStatusLive.BeginAnimation(OpacityProperty, fade);
        }

        ApplyGuardStatusHalo(monitoring, motion);
    }

    private void ApplyGuardStatusHalo(bool monitoring, bool motion)
    {
        if (!monitoring || !SystemParameters.ClientAreaAnimation)
        {
            // Clearing the animations first: a Forever storyboard holds the property, so assigning
            // the resting values while it still runs would be overwritten on the next frame.
            GuardStatusHalo.BeginAnimation(OpacityProperty, null);
            GuardStatusHaloScale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            GuardStatusHaloScale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            GuardStatusRipple.BeginAnimation(OpacityProperty, null);
            GuardStatusRippleScale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            GuardStatusRippleScale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            GuardStatusHalo.Opacity = 0d;
            GuardStatusHaloScale.ScaleX = 1d;
            GuardStatusHaloScale.ScaleY = 1d;
            GuardStatusRipple.Opacity = 0d;
            GuardStatusRippleScale.ScaleX = 1d;
            GuardStatusRippleScale.ScaleY = 1d;
            return;
        }

        // Brightness and size run in *opposite* directions. Growing brighter while growing bigger on
        // one shared beat is a pulse, and a pulse on a small dot is a blinking lamp - the thing this
        // is meant not to be. Light that spreads gets dimmer as it spreads, so the halo is at its
        // brightest when it is tightest and washes out as it opens up; the eye reads that as glow
        // rather than as on/off. Both animations start together and AutoReverse over the same
        // duration, which is all it takes: at t=0 the pair is (0.62, 0.92), at the turn it is
        // (0.26, 1.30).
        //
        // 2.6s per half-breath, up from 1.7s. At 1.7s the turn arrives often enough to be counted,
        // and anything a viewer can count they read as flashing.
        //
        // The opacity floor is 0.26 rather than something near zero because the caption glass behind
        // the dot samples as #151C2A - blue already outranks green there before any halo is laid
        // down. Just outside the 7px dot the mask is at ~87%, so 0.26 lands at an effective 0.226,
        // which is the point the ring starts reading as green at all; anything dimmer spends that
        // part of the breath indistinguishable from the background.
        var breathe = new DoubleAnimation(0.62d, 0.26d, TimeSpan.FromSeconds(2.6d))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
        };

        var swell = new DoubleAnimation(0.92d, 1.3d, TimeSpan.FromSeconds(2.6d))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
        };

        // The ripple travels one way only - no AutoReverse. A ring that expands and then contracts is
        // a throb; a ring that expands and dissolves is a wave leaving the source, and only the
        // second one says "this is running" without saying "look at me". EaseOut so it leaves fast
        // and coasts to a stop, the way a disturbance actually spreads.
        //
        // 0.5 puts the masked wavefront at ~6px across, just inside the 7px dot, so each wave is born
        // hidden underneath it and the loop's jump back to the start is never visible. 1.75 is where
        // it stops: ~21px across, and by then it is fully transparent, so it never reaches far enough
        // to collide with the summary text or spill out of the caption pill.
        var travel = new DoubleAnimation(0.5d, 1.75d, TimeSpan.FromSeconds(3.4d))
        {
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        // Keyframes rather than a plain fade because peak opacity belongs where the wavefront clears
        // the dot, not at t=0 where it is still behind it. Starting at 0 also means the wave appears
        // to emerge from the dot instead of switching on around it.
        var dissolve = new DoubleAnimationUsingKeyFrames
        {
            Duration = new Duration(TimeSpan.FromSeconds(3.4d)),
            RepeatBehavior = RepeatBehavior.Forever,
        };
        dissolve.KeyFrames.Add(new LinearDoubleKeyFrame(0d, KeyTime.FromPercent(0d)));
        dissolve.KeyFrames.Add(new EasingDoubleKeyFrame(0.52d, KeyTime.FromPercent(0.18d))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        });
        dissolve.KeyFrames.Add(new EasingDoubleKeyFrame(0d, KeyTime.FromPercent(1d))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn },
        });

        // 2.6s against 3.4s is deliberately not a whole-number ratio: 13:17 means the halo's turn and
        // the ripple's birth drift past each other for ~44s before they line up again, so the pair
        // never settles into one countable beat. Two loops on the same period would just be a
        // two-layer blink.
        if (motion)
        {
            // Fade in over the same beat the colour cross-fades on, instead of appearing mid-breath
            // at whatever opacity the loop happens to start at.
            GuardStatusHalo.Opacity = 0d;
            GuardStatusRipple.Opacity = 0d;
            breathe.BeginTime = TimeSpan.FromMilliseconds(140d);
            swell.BeginTime = TimeSpan.FromMilliseconds(140d);
            travel.BeginTime = TimeSpan.FromMilliseconds(140d);
            dissolve.BeginTime = TimeSpan.FromMilliseconds(140d);
        }

        GuardStatusHalo.BeginAnimation(OpacityProperty, breathe);
        GuardStatusHaloScale.BeginAnimation(ScaleTransform.ScaleXProperty, swell);
        GuardStatusHaloScale.BeginAnimation(ScaleTransform.ScaleYProperty, swell);
        GuardStatusRipple.BeginAnimation(OpacityProperty, dissolve);
        GuardStatusRippleScale.BeginAnimation(ScaleTransform.ScaleXProperty, travel);
        GuardStatusRippleScale.BeginAnimation(ScaleTransform.ScaleYProperty, travel);
    }

    private void ScheduleWorkspaceTransition(string previousPage, string selectedPage, double fromY)
    {
        var version = Interlocked.Increment(ref _workspaceTransitionVersion);
        CancelConversationContentTransition();
        CancelRouteRevealAnimations();
        var previousRoot = _activeRouteRoot ?? GetRouteRoot(previousPage);
        var nextRoot = GetRouteRoot(selectedPage);
        if (nextRoot is null)
        {
            return;
        }

        if (!IsLoaded || !SystemParameters.ClientAreaAnimation)
        {
            ApplyRouteVisibility(selectedPage, immediate: true);
            return;
        }

        foreach (var page in RoutePages)
        {
            var root = GetRouteRoot(page);
            if (root is not null && !ReferenceEquals(root, previousRoot) && !ReferenceEquals(root, nextRoot))
            {
                root.Visibility = Visibility.Collapsed;
            }
        }
        if (previousRoot is not null && !ReferenceEquals(previousRoot, nextRoot))
        {
            previousRoot.Visibility = Visibility.Visible;
            previousRoot.IsHitTestVisible = false;
        }
        nextRoot.Visibility = Visibility.Visible;
        // Input is no longer withheld for the length of the reveal. The stages animate Opacity and a
        // TranslateTransform only, so every hit region is already where it will end up - the 12px
        // offset is gone within a frame or two - while blocking input until the completion timer
        // fired meant a click on the page the user had just navigated to was swallowed for ~460ms,
        // and the timer runs at Background priority so that was a floor, not a ceiling. Nothing was
        // busy during that window; it was the single largest source of the app feeling slow.
        nextRoot.IsHitTestVisible = true;
        PrepareRouteReveal(nextRoot, selectedPage);
        _activeRouteRoot = nextRoot;
        // Run inline instead of posting at Render priority. The yield used to give the newly visible
        // page a frame to lay itself out, but PrepareRouteReveal has already set every stage to
        // Opacity 0 by that point, so the frame that got composed was an empty page - the flash that
        // read as a stutter on every route change. The layout work is the same either way; doing it
        // here just keeps a blank frame from reaching the screen. Re-entrancy stays covered by the
        // version check, which is what it was there for.
        AnimateWorkspaceTransition(version, previousRoot, nextRoot, selectedPage, fromY);
    }

    private void AnimateWorkspaceTransition(
        int version,
        UIElement? previousRoot,
        UIElement nextRoot,
        string selectedPage,
        double fromY)
    {
        if (version != Volatile.Read(ref _workspaceTransitionVersion))
        {
            return;
        }

        WorkspaceViewport.Opacity = 1;
        WorkspaceViewportTransform.BeginAnimation(
            System.Windows.Media.TranslateTransform.YProperty,
            null,
            System.Windows.Media.Animation.HandoffBehavior.SnapshotAndReplace);
        WorkspaceViewportTransform.Y = 0;
        if (previousRoot is not null && !ReferenceEquals(previousRoot, nextRoot))
        {
            previousRoot.Visibility = Visibility.Visible;
            previousRoot.IsHitTestVisible = false;
            AnimateRouteExit(previousRoot, fromY, version);
        }

        AnimateRouteReveal(nextRoot, selectedPage, version);
    }

    private void ApplyRouteVisibility(string selectedPage, bool immediate)
    {
        CancelRouteRevealAnimations();
        var selectedRoot = GetRouteRoot(selectedPage);
        if (selectedRoot is null)
        {
            return;
        }

        foreach (var page in RoutePages)
        {
            var root = GetRouteRoot(page);
            if (root is null)
            {
                continue;
            }

            root.Visibility = ReferenceEquals(root, selectedRoot)
                ? Visibility.Visible
                : Visibility.Collapsed;
            root.IsHitTestVisible = ReferenceEquals(root, selectedRoot);
            ResetRouteReveal(root, page);
        }

        _activeRouteRoot = selectedRoot;
        if (immediate)
        {
            FocusRouteEntry(selectedPage);
        }
    }

    // Every route name in one place. This list used to be spelled out at each site that walks the
    // routes, and adding a page meant remembering all of them — miss one and the new page silently
    // never becomes visible, because route visibility is driven from code-behind rather than from the
    // Visibility triggers in the XAML.
    private static readonly string[] RoutePages =
        ["Tasks", "Overview", "Recovery", "KeepAlive", "Settings", "UserGuide", FollowUpDetailPage];

    private UIElement? GetRouteRoot(string page) => page switch
    {
        "Tasks" => TasksPageRoot,
        "Overview" => ActivityPageRoot,
        "Recovery" => GuardrailsPageRoot,
        "KeepAlive" => KeepAlivePageRoot,
        "Settings" => PreferencesPageRoot,
        "UserGuide" => UserGuidePageRoot,
        FollowUpDetailPage => FollowUpEditor,
        _ => null
    };

    private IReadOnlyList<UIElement> GetRouteStages(string page) => page switch
    {
        "Tasks" => new UIElement[]
        {
            TasksIndexHeaderStage,
            TasksSearchStage,
            TasksScopeStage,
            TasksListStage,
            TaskWorkbenchHeaderStage,
            TaskWorkbenchContentStage
        },
        "Overview" => new UIElement[]
        {
            ActivityHeaderStage,
            ActivityStreamStage,
            ActivityLineageStage
        },
        "Recovery" => new UIElement[]
        {
            GuardrailsHeaderStage,
            GuardrailsChannelStage,
            GuardrailsContinuationStage
        },
        "KeepAlive" => new UIElement[]
        {
            KeepAliveHeaderStage,
            KeepAlivePolicyStage,
            KeepAliveThreadStage,
            KeepAliveRuntimeStage
        },
        "Settings" => new UIElement[] { PreferencesHeaderStage, PreferencesInterfaceStage, PreferencesBehaviorStage },
        "UserGuide" => Array.Empty<UIElement>(),
        FollowUpDetailPage => new UIElement[] { FollowUpRouteHeader, FollowUpMessageTimeline },
        _ => Array.Empty<UIElement>()
    };

    private void PrepareRouteReveal(UIElement root, string page)
    {
        ResetRouteReveal(root, page);
        ResetRouteElement(root);
        foreach (var element in GetRouteStages(page))
        {
            if (element.Visibility != Visibility.Visible)
            {
                continue;
            }

            var transform = EnsureRouteTransform(element);
            element.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            transform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
            element.Opacity = 0;
            transform.Y = 12;
            _routeRevealElements.Add(element);
        }
    }

    private void AnimateRouteReveal(UIElement root, string page, int version)
    {
        if (version != Volatile.Read(ref _workspaceTransitionVersion))
        {
            return;
        }

        var stages = GetRouteStages(page).Where(static element => element.Visibility == Visibility.Visible).ToList();
        // The whole reveal has to read as one movement. At 36ms apart over 210ms each, the six stages
        // on the Tasks page finished 410ms after the click and the list rows kept arriving until
        // ~440ms - long enough that a viewer counts the arrivals instead of seeing a page appear, and
        // long enough to be read as the page struggling to draw. Halving the offsets and shortening
        // the travel keeps the same top-to-bottom order inside a window that still registers as a
        // single response.
        var stageDuration = TimeSpan.FromMilliseconds(150);
        for (var index = 0; index < stages.Count; index++)
        {
            AnimateRouteElement(stages[index], 12 + index * 18, stageDuration);
        }

        AnimateVisibleListItems(
            page,
            version,
            page == "Tasks" ? 58 : 46);

        // Only clears the animation handles now that hit-testing is restored up front, so it is timed
        // to the last frame of the longest stage rather than padded past it.
        _routeRevealCompletionTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(300)
        };
        _routeRevealCompletionTimer.Tick += (_, _) =>
        {
            _routeRevealCompletionTimer.Stop();
            if (version != Volatile.Read(ref _workspaceTransitionVersion))
            {
                return;
            }

            CompleteRouteReveal(root, page);
        };
        _routeRevealCompletionTimer.Start();
    }

    private void AnimateVisibleListItems(string page, int version, int initialDelay)
    {
        if (version != Volatile.Read(ref _workspaceTransitionVersion))
        {
            return;
        }

        var list = page switch
        {
            "Tasks" => _viewModel.IsConversationNavigationRoot
                ? ConversationNavigationList
                : TaskList,
            "Overview" => ActivityList,
            FollowUpDetailPage => FollowUpMessageList,
            _ => null
        };
        if (list is null)
        {
            return;
        }

        list.UpdateLayout();
        var visibleItems = new List<UIElement>();
        for (var index = 0; index < list.Items.Count && visibleItems.Count < 6; index++)
        {
            if (list.ItemContainerGenerator.ContainerFromIndex(index) is ListBoxItem container &&
                container.ActualHeight > 0)
            {
                visibleItems.Add(container);
            }
        }

        for (var index = 0; index < visibleItems.Count; index++)
        {
            var element = visibleItems[index];
            var transform = EnsureRouteTransform(element);
            element.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            transform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
            element.Opacity = 0;
            transform.Y = 9;
            _routeRevealElements.Add(element);
            AnimateRouteElement(element, initialDelay + index * 14, TimeSpan.FromMilliseconds(140));
        }
    }

    private void ScheduleConversationContentTransition()
    {
        var version = Interlocked.Increment(ref _conversationContentTransitionVersion);
        CancelConversationContentTransition();
        if (!IsLoaded || !_viewModel.IsTasksPage)
        {
            return;
        }

        if (!SystemParameters.ClientAreaAnimation)
        {
            return;
        }

        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Render,
            new Action(() => AnimateConversationContentTransition(version)));
    }

    private void ScheduleTaskWorkbenchTransition()
    {
        if (!Dispatcher.CheckAccess())
        {
            _ = Dispatcher.BeginInvoke(
                DispatcherPriority.Render,
                new Action(ScheduleTaskWorkbenchTransition));
            return;
        }

        var version = Interlocked.Increment(ref _conversationContentTransitionVersion);
        CancelConversationContentTransition();
        if (!IsLoaded || !_viewModel.IsTasksPage || !SystemParameters.ClientAreaAnimation)
        {
            return;
        }

        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Render,
            new Action(() => AnimateTaskWorkbenchTransition(version)));
    }

    private void AnimateTaskWorkbenchTransition(int version)
    {
        if (version != Volatile.Read(ref _conversationContentTransitionVersion) ||
            !_viewModel.IsTasksPage)
        {
            return;
        }

        var elements = new UIElement[] { TaskWorkbenchHeaderStage, TaskWorkbenchContentStage }
            .Where(static element => element.Visibility == Visibility.Visible)
            .ToArray();
        for (var index = 0; index < elements.Length; index++)
        {
            var element = elements[index];
            var transform = EnsureRouteTransform(element);
            element.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            transform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
            element.Opacity = 0;
            transform.Y = 10;
            _conversationContentRevealElements.Add(element);
            AnimateRouteElement(
                element,
                index * 20,
                TimeSpan.FromMilliseconds(150));
        }

        StartConversationContentCompletionTimer(version, 240);
    }

    private void AnimateConversationContentTransition(int version)
    {
        if (version != Volatile.Read(ref _conversationContentTransitionVersion) ||
            !_viewModel.IsTasksPage ||
            TasksListStage.Visibility != Visibility.Visible)
        {
            return;
        }

        var stage = TasksListStage;
        var transform = EnsureRouteTransform(stage);
        stage.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
        transform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
        stage.Opacity = 0;
        transform.Y = 9;
        _conversationContentRevealElements.Add(stage);
        AnimateRouteElement(stage, 0, TimeSpan.FromMilliseconds(140));

        var list = _viewModel.IsConversationNavigationRoot
            ? ConversationNavigationList
            : TaskList;
        list.UpdateLayout();
        for (var index = 0; index < list.Items.Count && index < 6; index++)
        {
            if (list.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem container ||
                container.ActualHeight <= 0)
            {
                continue;
            }

            var itemTransform = EnsureRouteTransform(container);
            container.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            itemTransform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
            container.Opacity = 0;
            itemTransform.Y = 7;
            _conversationContentRevealElements.Add(container);
            AnimateRouteElement(container, 20 + index * 14, TimeSpan.FromMilliseconds(130));
        }

        StartConversationContentCompletionTimer(version, 280);
    }

    private void StartConversationContentCompletionTimer(int version, int milliseconds)
    {
        _conversationContentTransitionTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(milliseconds)
        };
        _conversationContentTransitionTimer.Tick += (_, _) =>
        {
            _conversationContentTransitionTimer?.Stop();
            if (version == Volatile.Read(ref _conversationContentTransitionVersion))
            {
                foreach (var element in _conversationContentRevealElements)
                {
                    ResetRouteElement(element);
                }

                _conversationContentRevealElements.Clear();
            }
        };
        _conversationContentTransitionTimer.Start();
    }

    private void AnimateRouteElement(UIElement element, int delay, TimeSpan duration)
    {
        var transform = EnsureRouteTransform(element);
        // Cubic rather than quintic. A quintic ease-out is 99.8% done at 70% of its duration, so the
        // last third of every stage was a clock running with nothing visible left to move - harmless
        // alone, but it stretched the perceived length of the reveal well past its real one and made
        // the staggered stages read as trailing rather than settling.
        var opacity = new DoubleAnimation(0, 1, duration)
        {
            BeginTime = TimeSpan.FromMilliseconds(delay),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        var slide = new DoubleAnimation(transform.Y, 0, duration)
        {
            BeginTime = TimeSpan.FromMilliseconds(delay),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        element.BeginAnimation(UIElement.OpacityProperty, opacity, HandoffBehavior.SnapshotAndReplace);
        transform.BeginAnimation(TranslateTransform.YProperty, slide, HandoffBehavior.SnapshotAndReplace);
    }

    private void AnimateRouteExit(UIElement root, double fromY, int version)
    {
        var transform = EnsureRouteTransform(root);
        var opacity = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(110))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
        };
        var slide = new DoubleAnimation(0, -Math.Abs(fromY), TimeSpan.FromMilliseconds(110))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
        };
        opacity.Completed += (_, _) =>
        {
            if (version == Volatile.Read(ref _workspaceTransitionVersion))
            {
                root.Visibility = Visibility.Collapsed;
                ResetRouteElement(root);
            }
        };
        root.BeginAnimation(UIElement.OpacityProperty, opacity, HandoffBehavior.SnapshotAndReplace);
        transform.BeginAnimation(TranslateTransform.YProperty, slide, HandoffBehavior.SnapshotAndReplace);
    }

    private void CompleteRouteReveal(UIElement root, string page)
    {
        ResetRouteReveal(root, page);
        root.IsHitTestVisible = true;
        FocusRouteEntry(page);
    }

    private void FocusRouteEntry(string page)
    {
        if (string.Equals(page, FollowUpDetailPage, StringComparison.Ordinal))
        {
            _ = Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() => FollowUpBackButton.Focus()));
        }
    }

    private void DismissOpenToolTip()
    {
        RestoreSuppressedToolTip();
        var owner = FindToolTipOwner(Mouse.DirectlyOver);
        if (owner is null || !ToolTipService.GetIsEnabled(owner))
        {
            return;
        }

        _suppressedToolTipIsEnabledLocalValue = owner.ReadLocalValue(ToolTipService.IsEnabledProperty);
        _suppressedToolTipOwner = owner;
        switch (owner)
        {
            case UIElement uiElement:
                uiElement.MouseLeave += OnSuppressedToolTipOwnerMouseLeave;
                break;
            case ContentElement contentElement:
                contentElement.MouseLeave += OnSuppressedToolTipOwnerMouseLeave;
                break;
        }
        ToolTipService.SetIsEnabled(owner, false);
    }

    private static DependencyObject? FindToolTipOwner(IInputElement? directlyOver)
    {
        var current = directlyOver as DependencyObject;
        while (current is not null)
        {
            if (current is FrameworkElement or FrameworkContentElement &&
                ToolTipService.GetToolTip(current) is not null)
            {
                return current;
            }

            if (current is System.Windows.Media.Visual or System.Windows.Media.Media3D.Visual3D)
            {
                current = VisualTreeHelper.GetParent(current);
            }
            else if (current is FrameworkContentElement contentElement)
            {
                current = contentElement.Parent;
            }
            else
            {
                current = LogicalTreeHelper.GetParent(current);
            }
        }

        return null;
    }

    private void OnSuppressedToolTipOwnerMouseLeave(object sender, MouseEventArgs eventArgs) =>
        RestoreSuppressedToolTip();

    private void RestoreSuppressedToolTip()
    {
        if (_suppressedToolTipOwner is not { } owner)
        {
            return;
        }

        _suppressedToolTipOwner = null;
        switch (owner)
        {
            case UIElement uiElement:
                uiElement.MouseLeave -= OnSuppressedToolTipOwnerMouseLeave;
                break;
            case ContentElement contentElement:
                contentElement.MouseLeave -= OnSuppressedToolTipOwnerMouseLeave;
                break;
        }
        if (ReferenceEquals(_suppressedToolTipIsEnabledLocalValue, DependencyProperty.UnsetValue))
        {
            owner.ClearValue(ToolTipService.IsEnabledProperty);
        }
        else
        {
            owner.SetValue(ToolTipService.IsEnabledProperty, _suppressedToolTipIsEnabledLocalValue);
        }
        _suppressedToolTipIsEnabledLocalValue = DependencyProperty.UnsetValue;
    }

    private void ResetRouteReveal(UIElement root, string page)
    {
        foreach (var element in GetRouteStages(page).Concat(_routeRevealElements).Distinct())
        {
            ResetRouteElement(element);
        }
        _routeRevealElements.Clear();
    }

    private static TranslateTransform EnsureRouteTransform(UIElement element)
    {
        if (element.RenderTransform is TranslateTransform transform)
        {
            return transform;
        }

        transform = new TranslateTransform();
        element.RenderTransform = transform;
        return transform;
    }

    private static void ResetRouteElement(UIElement element)
    {
        element.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
        element.Opacity = 1;
        var transform = EnsureRouteTransform(element);
        transform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
        transform.Y = 0;
    }

    private void CancelRouteRevealAnimations()
    {
        _routeRevealCompletionTimer?.Stop();
        _routeRevealCompletionTimer = null;
        CancelConversationContentTransition();
        foreach (var element in _routeRevealElements)
        {
            ResetRouteElement(element);
        }
        foreach (var root in new UIElement[]
                 {
                     TasksPageRoot,
                     ActivityPageRoot,
                     GuardrailsPageRoot,
                     KeepAlivePageRoot,
                     PreferencesPageRoot,
                     FollowUpEditor
                 })
        {
            ResetRouteElement(root);
        }
        _routeRevealElements.Clear();
    }

    private void CancelConversationContentTransition()
    {
        _conversationContentTransitionTimer?.Stop();
        _conversationContentTransitionTimer = null;
        foreach (var element in _conversationContentRevealElements)
        {
            ResetRouteElement(element);
        }

        _conversationContentRevealElements.Clear();
    }

    private void CaptureTaskListContext()
    {
        var scrollViewer = FindVisualDescendant<ScrollViewer>(TaskList);
        if (scrollViewer is null)
        {
            return;
        }

        _taskListVerticalOffset = scrollViewer.VerticalOffset;
        _taskListHorizontalOffset = scrollViewer.HorizontalOffset;
    }

    private void RestoreTaskListContext()
    {
        if (!_viewModel.IsTasksPage || _viewModel.SelectedTask is not { } selectedTask)
        {
            return;
        }

        TaskList.ScrollIntoView(selectedTask);
        TaskList.UpdateLayout();
        var scrollViewer = FindVisualDescendant<ScrollViewer>(TaskList);
        scrollViewer?.ScrollToVerticalOffset(_taskListVerticalOffset);
        scrollViewer?.ScrollToHorizontalOffset(_taskListHorizontalOffset);
        TaskList.UpdateLayout();

        if (TaskList.ItemContainerGenerator.ContainerFromItem(selectedTask) is not ListBoxItem row)
        {
            TaskList.Focus();
            return;
        }

        var queueButton = FindVisualDescendant<Button>(
            row,
            static button => string.Equals(
                AutomationProperties.GetAutomationId(button),
                "TaskFollowUpEntryButton",
                StringComparison.Ordinal));
        if (queueButton is not null)
        {
            queueButton.Focus();
            Keyboard.Focus(queueButton);
            return;
        }

        row.Focus();
        Keyboard.Focus(row);
    }

    private void OnFollowUpMessageFocusRequested(
        FollowUpMessageItem item,
        bool focusMessageEditor) =>
        FocusFollowUpMessage(item, focusMessageEditor);

    private void FocusFollowUpMessage(FollowUpMessageItem item, bool focusMessageEditor)
    {
        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Loaded,
            new Action(() =>
            {
                if (!_viewModel.IsFollowUpDetailPage || !FollowUpMessageList.Items.Contains(item))
                {
                    return;
                }

                FollowUpMessageList.ScrollIntoView(item);
                FollowUpMessageList.UpdateLayout();
                if (FollowUpMessageList.ItemContainerGenerator.ContainerFromItem(item) is not ListBoxItem container)
                {
                    return;
                }

                var automationId = focusMessageEditor
                    ? "FollowUpMessageTextBox"
                    : "FollowUpDragGripButton";
                var target = FindVisualDescendant<System.Windows.Controls.Control>(
                    container,
                    control => string.Equals(
                        AutomationProperties.GetAutomationId(control),
                        automationId,
                        StringComparison.Ordinal));
                target?.Focus();
                if (target is not null)
                {
                    Keyboard.Focus(target);
                }
            }));
    }

    private async void OnFollowUpAttachmentPickerRequested(FollowUpMessageItem item)
    {
        if (!IsAttachmentImportAvailable || IsAttachmentImportInProgress)
        {
            return;
        }

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = true,
            DereferenceLinks = false,
            ValidateNames = true
        };
        if (dialog.ShowDialog(this) != true || dialog.FileNames.Length == 0)
        {
            return;
        }

        await ImportAttachmentFilesAsync(item, dialog.FileNames);
    }

    private void FollowUpEditor_PreviewDragOver(object sender, DragEventArgs eventArgs)
    {
        eventArgs.Effects = !_previewIsolationMode &&
                            !IsAttachmentImportInProgress &&
                            _viewModel.SelectedFollowUpMessage is not null &&
                            eventArgs.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        eventArgs.Handled = true;
    }

    private async void FollowUpEditor_PreviewDrop(object sender, DragEventArgs eventArgs)
    {
        eventArgs.Handled = true;
        if (_previewIsolationMode ||
            IsAttachmentImportInProgress ||
            _viewModel.SelectedFollowUpMessage is not { } item ||
            !eventArgs.Data.GetDataPresent(DataFormats.FileDrop) ||
            eventArgs.Data.GetData(DataFormats.FileDrop, autoConvert: false) is not string[] paths ||
            paths.Length == 0)
        {
            return;
        }

        await ImportAttachmentFilesAsync(item, paths);
    }

    private async Task ImportAttachmentFilesAsync(
        FollowUpMessageItem item,
        IReadOnlyList<string> sourcePaths)
    {
        CancelAttachmentImport();
        var cancellation = new CancellationTokenSource();
        _attachmentImportCancellation = cancellation;
        SetValue(IsAttachmentImportInProgressPropertyKey, true);
        try
        {
            var result = await _viewModel.ImportFollowUpFilesAsync(
                item,
                sourcePaths,
                cancellation.Token);
            if (result.Status == FollowUpAttachmentCompositionStatus.Committed)
            {
                _viewModel.SetFollowUpAttachmentImportStatus(true, result.ImportedCount);
                await LoadAttachmentThumbnailsAsync(item, result.Attachments, cancellation.Token);
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
        }
        catch (AttachmentImportException)
        {
            _viewModel.SetFollowUpAttachmentImportStatus(false);
        }
        catch (IOException)
        {
            _viewModel.SetFollowUpAttachmentImportStatus(false);
        }
        finally
        {
            if (ReferenceEquals(_attachmentImportCancellation, cancellation))
            {
                _attachmentImportCancellation = null;
                SetValue(IsAttachmentImportInProgressPropertyKey, false);
            }
            cancellation.Dispose();
        }
    }

    private async Task ImportClipboardAttachmentsAsync(FollowUpMessageItem item)
    {
        if (_previewIsolationMode || _attachmentRuntime is null)
        {
            return;
        }

        ClipboardAttachmentSource source;
        try
        {
            var data = System.Windows.Clipboard.GetDataObject();
            var paths = data?.GetDataPresent(DataFormats.FileDrop) == true
                ? data.GetData(DataFormats.FileDrop, autoConvert: false) as string[]
                : null;
            source = _attachmentRuntime.Clipboard.Read(
                paths,
                () => data?.GetDataPresent(DataFormats.Bitmap) == true
                    ? data.GetData(DataFormats.Bitmap, autoConvert: true) as BitmapSource
                    : null,
                text: null,
                _viewModel.Settings.AttachmentLimits);
        }
        catch (ExternalException)
        {
            _viewModel.SetFollowUpAttachmentImportStatus(false);
            return;
        }

        if (source is ClipboardEmptySource or ClipboardTextSource)
        {
            return;
        }

        CancelAttachmentImport();
        var cancellation = new CancellationTokenSource();
        _attachmentImportCancellation = cancellation;
        SetValue(IsAttachmentImportInProgressPropertyKey, true);
        try
        {
            var result = await _viewModel.ImportFollowUpClipboardAsync(
                item,
                source,
                cancellation.Token);
            if (result.Status == FollowUpAttachmentCompositionStatus.Committed)
            {
                _viewModel.SetFollowUpAttachmentImportStatus(true, result.ImportedCount);
                await LoadAttachmentThumbnailsAsync(item, result.Attachments, cancellation.Token);
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
        }
        catch (AttachmentImportException)
        {
            _viewModel.SetFollowUpAttachmentImportStatus(false);
        }
        catch (IOException)
        {
            _viewModel.SetFollowUpAttachmentImportStatus(false);
        }
        finally
        {
            if (ReferenceEquals(_attachmentImportCancellation, cancellation))
            {
                _attachmentImportCancellation = null;
                SetValue(IsAttachmentImportInProgressPropertyKey, false);
            }
            cancellation.Dispose();
        }
    }

    private async Task LoadAttachmentThumbnailsAsync(
        FollowUpMessageItem item,
        IReadOnlyList<PresetAttachmentReference> references,
        CancellationToken cancellationToken)
    {
        if (_attachmentRuntime is null)
        {
            return;
        }

        foreach (var reference in references.Where(static reference =>
                     string.Equals(reference.DetectedType, "image/png", StringComparison.Ordinal)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var attachment = item.Attachments.FirstOrDefault(candidate =>
                string.Equals(candidate.Id, reference.Id, StringComparison.Ordinal));
            if (attachment is null)
            {
                continue;
            }

            attachment.BeginThumbnailLoad();
            try
            {
                var thumbnail = await _attachmentRuntime.Thumbnails.LoadAsync(
                    reference,
                    maximumPixelWidth: 96,
                    maximumPixelHeight: 96,
                    cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (!item.Attachments.Contains(attachment))
                {
                    continue;
                }

                if (thumbnail is null)
                {
                    attachment.SetThumbnailFailure();
                }
                else
                {
                    attachment.SetThumbnail(thumbnail.Image);
                }
            }
            catch (OperationCanceledException)
            {
                attachment.CancelThumbnailLoad();
                throw;
            }
        }
    }

    private void ScheduleSelectedAttachmentThumbnailLoad()
    {
        if (_attachmentRuntime is null ||
            !_viewModel.IsFollowUpDetailPage ||
            _viewModel.SelectedFollowUpMessage is not { } item)
        {
            CancelAttachmentThumbnailLoad();
            return;
        }

        if (ReferenceEquals(_attachmentThumbnailOwner, item) &&
            _attachmentThumbnailCancellation is not null)
        {
            return;
        }

        CancelAttachmentThumbnailLoad();

        var references = item.Attachments
            .Where(static attachment =>
                attachment.ThumbnailState == AttachmentThumbnailState.NotRequested &&
                string.Equals(attachment.DetectedType, "image/png", StringComparison.Ordinal))
            .Select(static attachment => attachment.ToReference())
            .ToArray();
        if (references.Length == 0)
        {
            return;
        }

        var cancellation = new CancellationTokenSource();
        _attachmentThumbnailCancellation = cancellation;
        _attachmentThumbnailOwner = item;
        _ = HydrateSelectedAttachmentThumbnailsAsync(item, references, cancellation);
    }

    private async Task HydrateSelectedAttachmentThumbnailsAsync(
        FollowUpMessageItem item,
        IReadOnlyList<PresetAttachmentReference> references,
        CancellationTokenSource cancellation)
    {
        try
        {
            await LoadAttachmentThumbnailsAsync(item, references, cancellation.Token);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or
                InvalidOperationException or NotSupportedException or ArgumentException)
        {
            foreach (var attachment in item.Attachments.Where(static attachment =>
                         attachment.ThumbnailState == AttachmentThumbnailState.Loading))
            {
                attachment.SetThumbnailFailure();
            }
        }
        finally
        {
            if (ReferenceEquals(_attachmentThumbnailCancellation, cancellation))
            {
                _attachmentThumbnailCancellation = null;
                _attachmentThumbnailOwner = null;
            }
            cancellation.Dispose();
        }
    }

    private void CancelAttachmentImport()
    {
        var cancellation = Interlocked.Exchange(ref _attachmentImportCancellation, null);
        if (cancellation is null)
        {
            return;
        }

        try
        {
            cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            SetValue(IsAttachmentImportInProgressPropertyKey, false);
        }
    }

    private void CancelAttachmentThumbnailLoad()
    {
        var cancellation = Interlocked.Exchange(ref _attachmentThumbnailCancellation, null);
        _attachmentThumbnailOwner = null;
        if (cancellation is null)
        {
            return;
        }

        try
        {
            cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private void FocusConversation(GuardianTaskItem item)
    {
        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Loaded,
            new Action(() =>
            {
                if (!_viewModel.IsTasksPage || !TaskList.Items.Contains(item))
                {
                    return;
                }

                TaskList.ScrollIntoView(item);
                TaskList.UpdateLayout();
                if (TaskList.ItemContainerGenerator.ContainerFromItem(item) is not ListBoxItem container)
                {
                    return;
                }

                var grip = FindVisualDescendant<System.Windows.Controls.Control>(
                    container,
                    control => string.Equals(
                        AutomationProperties.GetAutomationId(control),
                        "ConversationDragGripButton",
                        StringComparison.Ordinal));
                grip?.Focus();
                if (grip is not null)
                {
                    Keyboard.Focus(grip);
                }
            }));
    }

    private void ConversationDragGrip_PreviewMouseLeftButtonDown(
        object sender,
        MouseButtonEventArgs eventArgs)
    {
        if (sender is not Button grip ||
            grip.DataContext is not GuardianTaskItem item ||
            ItemsControl.ContainerFromElement(TaskList, grip) is not ListBoxItem container ||
            TaskList.Items.Count < 2)
        {
            return;
        }

        CancelConversationDrag();
        CancelFollowUpDrag();
        CancelAttachmentDrag();
        _conversationDragCandidate = item;
        _conversationDragCaptureOwner = grip;
        _conversationDragContainer = container;
        _conversationDragStartPoint = eventArgs.GetPosition(TaskList);
        var containerTopLeft = container.TranslatePoint(new System.Windows.Point(0, 0), TaskList);
        _conversationDragPointerOffset = _conversationDragStartPoint - containerTopLeft;
        grip.Focus();

        // Suppress Button's built-in capture. The window keeps tracking the candidate and
        // capture begins only after the system drag threshold has been crossed.
        eventArgs.Handled = true;
    }

    private void ConversationDragGrip_PreviewMouseMove(object sender, MouseEventArgs eventArgs)
    {
        if (_conversationDragCandidate is null)
        {
            return;
        }

        if (eventArgs.LeftButton != MouseButtonState.Pressed)
        {
            CancelConversationDrag();
            return;
        }

        var pointer = eventArgs.GetPosition(TaskList);
        if (_conversationDragSource is null)
        {
            var horizontalDistance = Math.Abs(pointer.X - _conversationDragStartPoint.X);
            var verticalDistance = Math.Abs(pointer.Y - _conversationDragStartPoint.Y);
            if (horizontalDistance < SystemParameters.MinimumHorizontalDragDistance &&
                verticalDistance < SystemParameters.MinimumVerticalDragDistance)
            {
                return;
            }

            _conversationDragSource = _conversationDragCandidate;
            if (!BeginConversationDrag(_conversationDragSource, pointer))
            {
                CancelConversationDrag();
                return;
            }
        }

        _conversationPointer = pointer;
        UpdateConversationDragPreview();
        if (IsConversationPointerWithinDropCorridor(pointer))
        {
            UpdateConversationAutoScrollVelocity(pointer);
            _conversationDropInsertionIndex = CalculateConversationInsertionIndex(pointer);
            SetConversationDropIndicator(_conversationDropInsertionIndex);
        }
        else
        {
            _conversationAutoScrollVelocity = 0;
            _conversationDropInsertionIndex = null;
            SetConversationDropIndicator(null);
        }
        eventArgs.Handled = _conversationDragSource is not null;
    }

    private void Window_PreviewMouseMove(object sender, MouseEventArgs eventArgs)
    {
        if (_attachmentDragCandidate is not null || _attachmentDragSource is not null)
        {
            FollowUpAttachmentDragGrip_PreviewMouseMove(
                _attachmentDragCaptureOwner ?? sender,
                eventArgs);
            return;
        }

        if (_conversationDragCandidate is not null || _conversationDragSource is not null)
        {
            ConversationDragGrip_PreviewMouseMove(
                _conversationDragCaptureOwner ?? sender,
                eventArgs);
            return;
        }

        if (_followUpDragCandidate is not null || _followUpDragSource is not null)
        {
            FollowUpDragGrip_PreviewMouseMove(
                _followUpDragCaptureOwner ?? sender,
                eventArgs);
        }
    }

    private void Window_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs eventArgs)
    {
        if (_attachmentDragCandidate is not null || _attachmentDragSource is not null)
        {
            FollowUpAttachmentDragGrip_PreviewMouseLeftButtonUp(
                _attachmentDragCaptureOwner ?? sender,
                eventArgs);
            return;
        }

        if (_conversationDragCandidate is not null || _conversationDragSource is not null)
        {
            ConversationDragGrip_PreviewMouseLeftButtonUp(
                _conversationDragCaptureOwner ?? sender,
                eventArgs);
            return;
        }

        if (_followUpDragCandidate is not null || _followUpDragSource is not null)
        {
            FollowUpDragGrip_PreviewMouseLeftButtonUp(
                _followUpDragCaptureOwner ?? sender,
                eventArgs);
        }
    }

    private async void ConversationDragGrip_PreviewMouseLeftButtonUp(
        object sender,
        MouseButtonEventArgs eventArgs)
    {
        var item = _conversationDragSource;
        if (item is null)
        {
            // A click that never crossed the drag threshold must continue through the
            // normal WPF route and must not be treated as a drop.
            CancelConversationDrag();
            return;
        }

        var visibleItems = TaskList.Items.Cast<GuardianTaskItem>().ToList();
        var insertionIndex = _conversationDropInsertionIndex;
        var oldIndex = visibleItems.IndexOf(item);
        var targetIndex = insertionIndex ?? oldIndex;
        var pointer = eventArgs.GetPosition(TaskList);
        var isInsideDropBounds = pointer.X >= -64 &&
                                 pointer.X <= TaskList.ActualWidth + 64 &&
                                 pointer.Y >= -64 &&
                                 pointer.Y <= TaskList.ActualHeight + 64;
        if (targetIndex > oldIndex)
        {
            targetIndex--;
        }

        _conversationDropCommitPending = true;
        _conversationAutoScrollVelocity = 0;
        ReleaseConversationDragCapture();
        var moved = false;
        try
        {
            moved = isInsideDropBounds &&
                    oldIndex >= 0 &&
                    await _viewModel.MoveConversationAsync(
                        item,
                        Math.Clamp(targetIndex, 0, Math.Max(0, visibleItems.Count - 1)));
        }
        catch (OperationCanceledException)
        {
            moved = false;
        }
        finally
        {
            _conversationDropCommitPending = false;
        }

        if (moved)
        {
            BeginConversationSettle(item, oldIndex, targetIndex);
        }
        else
        {
            CancelConversationDrag(releaseCapture: false);
        }

        eventArgs.Handled = true;
    }

    private void ConversationDragGrip_LostMouseCapture(object sender, MouseEventArgs eventArgs)
    {
        if (!_releasingConversationDragCapture && !_conversationDropCommitPending)
        {
            CancelConversationDrag(releaseCapture: false);
        }
    }

    private async void ConversationDragGrip_PreviewKeyDown(object sender, KeyEventArgs eventArgs)
    {
        if (eventArgs.Key == Key.Escape &&
            (_conversationDragCandidate is not null || _conversationDragSource is not null))
        {
            CancelConversationDrag();
            eventArgs.Handled = true;
            return;
        }

        var key = eventArgs.Key == Key.System ? eventArgs.SystemKey : eventArgs.Key;
        if (sender is not Button { DataContext: GuardianTaskItem item } ||
            Keyboard.Modifiers != ModifierKeys.Alt ||
            key is not Key.Up and not Key.Down)
        {
            return;
        }

        var visibleItems = TaskList.Items.Cast<GuardianTaskItem>().ToList();
        var oldIndex = visibleItems.IndexOf(item);
        var targetIndex = key == Key.Up ? oldIndex - 1 : oldIndex + 1;
        if (oldIndex >= 0 &&
            targetIndex >= 0 &&
            targetIndex < visibleItems.Count &&
            await _viewModel.MoveConversationAsync(item, targetIndex))
        {
            AnimateConversationPlacement(item, oldIndex, targetIndex);
            FocusConversation(item);
        }

        eventArgs.Handled = true;
    }

    private bool BeginConversationDrag(
        GuardianTaskItem item,
        System.Windows.Point pointer)
    {
        if (_conversationDragContainer is null ||
            _conversationDragCaptureOwner is null ||
            !Mouse.Capture(_conversationDragCaptureOwner, CaptureMode.Element))
        {
            return false;
        }

        _conversationDragContainer.UpdateLayout();
        var availableWidth = Math.Max(260, TaskList.ActualWidth - 20);
        var previewWidth = Math.Min(
            Math.Max(260, _conversationDragContainer.ActualWidth),
            availableWidth);
        var previewHeight = Math.Max(82, _conversationDragContainer.ActualHeight);
        var fontFamily = TryFindResource("BodyFont") as System.Windows.Media.FontFamily ??
                         new System.Windows.Media.FontFamily("Segoe UI");
        var dpi = VisualTreeHelper.GetDpi(this);
        var preview = new FollowUpDragPreviewWindow(
            this,
            item,
            fontFamily,
            previewWidth,
            previewHeight,
            dpi.DpiScaleX,
            dpi.DpiScaleY,
            SystemParameters.ClientAreaAnimation);
        try
        {
            preview.Show();
        }
        catch
        {
            preview.Close();
            return false;
        }

        _conversationDragPreview = preview;
        item.IsDragSource = true;
        Mouse.OverrideCursor = Cursors.SizeAll;
        _conversationPointer = pointer;
        StartConversationRendering();
        UpdateConversationDragPreview();
        return true;
    }

    private void UpdateConversationDragPreview()
    {
        if (_conversationDragPreview is null || !GetCursorPos(out var cursor))
        {
            return;
        }

        _conversationDragPreview.UpdatePointer(
            new System.Windows.Point(cursor.X, cursor.Y),
            _conversationDragPointerOffset);
    }

    private int? CalculateConversationInsertionIndex(System.Windows.Point pointer)
    {
        var lastVisibleIndex = -1;
        for (var index = 0; index < TaskList.Items.Count; index++)
        {
            if (TaskList.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem container ||
                container.ActualHeight <= 0)
            {
                continue;
            }

            lastVisibleIndex = index;
            var top = container.TranslatePoint(new System.Windows.Point(0, 0), TaskList).Y;
            if (pointer.Y < top + container.ActualHeight / 2)
            {
                return index;
            }
        }

        return lastVisibleIndex < 0
            ? null
            : Math.Min(TaskList.Items.Count, lastVisibleIndex + 1);
    }

    private bool IsConversationPointerWithinDropCorridor(System.Windows.Point pointer) =>
        pointer.X >= -96 && pointer.X <= TaskList.ActualWidth + 96;

    private void SetConversationDropIndicator(int? insertionIndex)
    {
        if (_conversationVisualInsertionIndex == insertionIndex)
        {
            return;
        }

        _conversationVisualInsertionIndex = insertionIndex;
        foreach (var task in _viewModel.Tasks)
        {
            task.ShowDropBefore = false;
            task.ShowDropAfter = false;
        }

        var visibleItems = TaskList.Items.Cast<GuardianTaskItem>().ToList();
        if (insertionIndex is null || visibleItems.Count == 0)
        {
            AnimateConversationNeighborDisplacement(null);
            return;
        }

        if (insertionIndex.Value >= visibleItems.Count)
        {
            visibleItems[^1].ShowDropAfter = true;
            AnimateConversationNeighborDisplacement(insertionIndex);
            return;
        }

        visibleItems[Math.Max(0, insertionIndex.Value)].ShowDropBefore = true;
        AnimateConversationNeighborDisplacement(insertionIndex);
    }

    private void UpdateConversationAutoScrollVelocity(System.Windows.Point pointer)
    {
        var scrollViewer = FindVisualDescendant<ScrollViewer>(TaskList);
        if (scrollViewer is null || scrollViewer.ScrollableHeight <= 0)
        {
            _conversationAutoScrollVelocity = 0;
            return;
        }

        const double edge = 64;
        const double maximumVelocity = 720;
        if (pointer.Y < edge)
        {
            var depth = Math.Clamp((edge - pointer.Y) / edge, 0, 1);
            _conversationAutoScrollVelocity = -maximumVelocity * depth * depth;
        }
        else if (pointer.Y > TaskList.ActualHeight - edge)
        {
            var depth = Math.Clamp(
                (pointer.Y - (TaskList.ActualHeight - edge)) / edge,
                0,
                1);
            _conversationAutoScrollVelocity = maximumVelocity * depth * depth;
        }
        else
        {
            _conversationAutoScrollVelocity = 0;
        }
    }

    private void ConversationList_PreviewMouseWheel(object sender, MouseWheelEventArgs eventArgs)
    {
        if (!SystemParameters.ClientAreaAnimation ||
            sender is not DependencyObject source ||
            FindVisualDescendant<ScrollViewer>(source) is not { } scrollViewer ||
            scrollViewer.ScrollableHeight <= 0)
        {
            return;
        }

        var impulse = -eventArgs.Delta / 120d * 760d;
        if (!ReferenceEquals(_inertialScrollViewer, scrollViewer))
        {
            StopInertialScroll();
            _inertialScrollViewer = scrollViewer;
        }

        _inertialScrollVelocity = Math.Clamp(
            _inertialScrollVelocity + impulse,
            -3200d,
            3200d);
        _inertialScrollTimestampUtc = DateTime.UtcNow;
        if (!_inertialScrollSubscribed)
        {
            CompositionTarget.Rendering += OnInertialScrollRendering;
            _inertialScrollSubscribed = true;
        }

        eventArgs.Handled = true;
    }

    private void OnInertialScrollRendering(object? sender, EventArgs eventArgs)
    {
        var scrollViewer = _inertialScrollViewer;
        if (scrollViewer is null ||
            !scrollViewer.IsVisible ||
            scrollViewer.ScrollableHeight <= 0 ||
            Math.Abs(_inertialScrollVelocity) < 3d)
        {
            StopInertialScroll();
            return;
        }

        var now = DateTime.UtcNow;
        var elapsed = Math.Clamp(
            (now - _inertialScrollTimestampUtc).TotalSeconds,
            1d / 240d,
            1d / 20d);
        _inertialScrollTimestampUtc = now;

        var nextOffset = Math.Clamp(
            scrollViewer.VerticalOffset + _inertialScrollVelocity * elapsed,
            0d,
            scrollViewer.ScrollableHeight);
        if (Math.Abs(nextOffset - scrollViewer.VerticalOffset) > 0.01d)
        {
            scrollViewer.ScrollToVerticalOffset(nextOffset);
        }

        _inertialScrollVelocity *= Math.Exp(-8.5d * elapsed);
        if ((nextOffset <= 0d && _inertialScrollVelocity < 0d) ||
            (nextOffset >= scrollViewer.ScrollableHeight && _inertialScrollVelocity > 0d))
        {
            _inertialScrollVelocity = 0d;
        }
    }

    private void StopInertialScroll()
    {
        if (_inertialScrollSubscribed)
        {
            CompositionTarget.Rendering -= OnInertialScrollRendering;
            _inertialScrollSubscribed = false;
        }

        _inertialScrollViewer = null;
        _inertialScrollVelocity = 0d;
    }

    private void StartStatusGlow()
    {
        if (_statusGlowSubscribed ||
            !SystemParameters.ClientAreaAnimation ||
            !_viewModel.IsTasksPage)
        {
            return;
        }

        _statusGlowTimestampUtc = DateTime.UtcNow;
        CompositionTarget.Rendering += OnStatusGlowRendering;
        _statusGlowSubscribed = true;
    }

    private void OnStatusGlowRendering(object? sender, EventArgs eventArgs)
    {
        if (!_viewModel.IsTasksPage || !TaskList.IsVisible)
        {
            StopStatusGlow();
            return;
        }

        var now = DateTime.UtcNow;
        var elapsed = Math.Clamp(
            (now - _statusGlowTimestampUtc).TotalSeconds,
            1d / 240d,
            1d / 20d);
        _statusGlowTimestampUtc = now;
        _statusGlowPhase = (_statusGlowPhase + elapsed * 1.35d) % (Math.PI * 2d);
        var wave = 0.5d + 0.5d * Math.Sin(_statusGlowPhase);

        for (var index = 0; index < TaskList.Items.Count; index++)
        {
            if (TaskList.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem row ||
                row.DataContext is not GuardianTaskItem task ||
                FindStatusAura(row) is not { } aura)
            {
                continue;
            }

            var baseOpacity = task.VisualTone == TaskVisualTone.Healthy ? 0.24d : 0.42d;
            aura.Opacity = baseOpacity * (0.82d + wave * 0.18d);
        }
    }

    private void StopStatusGlow()
    {
        if (_statusGlowSubscribed)
        {
            CompositionTarget.Rendering -= OnStatusGlowRendering;
            _statusGlowSubscribed = false;
        }

        for (var index = 0; index < TaskList.Items.Count; index++)
        {
            if (TaskList.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem row ||
                row.DataContext is not GuardianTaskItem task ||
                FindStatusAura(row) is not { } aura)
            {
                continue;
            }

            aura.Opacity = task.VisualTone == TaskVisualTone.Healthy ? 0.24d : 0.42d;
        }

        _statusGlowPhase = 0d;
    }

    private static Border? FindStatusAura(ListBoxItem row) =>
        row.Template?.FindName("StatusAura", row) as Border ??
        FindVisualDescendant<Border>(
            row,
            static border => string.Equals(border.Name, "StatusAura", StringComparison.Ordinal));

    private void StartConversationRendering()
    {
        if (_conversationRenderingSubscribed)
        {
            return;
        }

        _conversationRenderingTimestampUtc = DateTime.UtcNow;
        CompositionTarget.Rendering += OnConversationRendering;
        _conversationRenderingSubscribed = true;
    }

    private void StopConversationRendering()
    {
        if (!_conversationRenderingSubscribed)
        {
            return;
        }

        CompositionTarget.Rendering -= OnConversationRendering;
        _conversationRenderingSubscribed = false;
        _conversationAutoScrollVelocity = 0;
    }

    private void OnConversationRendering(object? sender, EventArgs eventArgs)
    {
        if (_conversationDragSource is null || _conversationDragPreview is null)
        {
            StopConversationRendering();
            return;
        }

        var now = DateTime.UtcNow;
        var elapsed = Math.Clamp(
            (now - _conversationRenderingTimestampUtc).TotalSeconds,
            1d / 240d,
            1d / 24d);
        _conversationRenderingTimestampUtc = now;
        _conversationDragPreview.Advance(elapsed);

        if (_conversationIsSettling)
        {
            if (!SystemParameters.ClientAreaAnimation ||
                _conversationDragPreview.IsSettled ||
                now - _conversationSettleStartedUtc >= TimeSpan.FromMilliseconds(650))
            {
                CompleteConversationSettle();
            }
            return;
        }

        if (_conversationDropCommitPending)
        {
            return;
        }

        if (Mouse.LeftButton != MouseButtonState.Pressed)
        {
            CancelConversationDrag();
            return;
        }

        UpdateConversationDragPreview();
        _conversationPointer = Mouse.GetPosition(TaskList);
        if (!IsConversationPointerWithinDropCorridor(_conversationPointer))
        {
            _conversationAutoScrollVelocity = 0;
            _conversationDropInsertionIndex = null;
            SetConversationDropIndicator(null);
            return;
        }
        UpdateConversationAutoScrollVelocity(_conversationPointer);

        if (Math.Abs(_conversationAutoScrollVelocity) < 0.1)
        {
            return;
        }

        var scrollViewer = FindVisualDescendant<ScrollViewer>(TaskList);
        if (scrollViewer is null || scrollViewer.ScrollableHeight <= 0)
        {
            _conversationAutoScrollVelocity = 0;
            return;
        }

        var targetOffset = Math.Clamp(
            scrollViewer.VerticalOffset + _conversationAutoScrollVelocity * elapsed,
            0,
            scrollViewer.ScrollableHeight);
        if (Math.Abs(targetOffset - scrollViewer.VerticalOffset) < 0.05)
        {
            return;
        }

        scrollViewer.ScrollToVerticalOffset(targetOffset);
        TaskList.UpdateLayout();
        _conversationPointer = Mouse.GetPosition(TaskList);
        _conversationDropInsertionIndex = CalculateConversationInsertionIndex(_conversationPointer);
        SetConversationDropIndicator(_conversationDropInsertionIndex);
    }

    private void AnimateConversationNeighborDisplacement(int? insertionIndex)
    {
        var source = _conversationDragSource;
        var visibleItems = TaskList.Items.Cast<GuardianTaskItem>().ToList();
        var sourceIndex = source is null ? -1 : visibleItems.IndexOf(source);
        var sourceHeight = Math.Max(
            0,
            (_conversationDragContainer?.ActualHeight ?? 0) +
            (_conversationDragContainer?.Margin.Top ?? 0) +
            (_conversationDragContainer?.Margin.Bottom ?? 0));
        for (var index = 0; index < TaskList.Items.Count; index++)
        {
            if (TaskList.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem container ||
                index == sourceIndex)
            {
                continue;
            }

            var target = 0d;
            if (insertionIndex is { } insertion && sourceIndex >= 0 && sourceHeight > 0)
            {
                if (insertion < sourceIndex && index >= insertion && index < sourceIndex)
                {
                    target = sourceHeight;
                }
                else if (insertion > sourceIndex && index > sourceIndex && index < insertion)
                {
                    target = -sourceHeight;
                }
            }

            var transform = EnsureRouteTransform(container);
            if (!SystemParameters.ClientAreaAnimation)
            {
                transform.BeginAnimation(
                    TranslateTransform.YProperty,
                    null,
                    HandoffBehavior.SnapshotAndReplace);
                transform.Y = target;
                if (Math.Abs(target) > 0.1)
                {
                    _conversationDisplacedContainers.Add(container);
                }
                continue;
            }

            var animation = new DoubleAnimation(
                transform.Y,
                target,
                TimeSpan.FromMilliseconds(170))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            transform.BeginAnimation(
                TranslateTransform.YProperty,
                animation,
                HandoffBehavior.SnapshotAndReplace);
            if (Math.Abs(target) > 0.1)
            {
                _conversationDisplacedContainers.Add(container);
            }
        }
    }

    private void BeginConversationSettle(GuardianTaskItem item, int oldIndex, int newIndex)
    {
        _conversationAutoScrollVelocity = 0;
        _conversationDropCommitPending = false;
        ReleaseConversationDragCapture();
        foreach (var task in _viewModel.Tasks)
        {
            task.IsDragSource = false;
            task.ShowDropBefore = false;
            task.ShowDropAfter = false;
        }
        ResetConversationNeighborDisplacement();
        TaskList.ScrollIntoView(item);
        TaskList.UpdateLayout();

        if (_conversationDragPreview is null ||
            TaskList.ItemContainerGenerator.ContainerFromItem(item) is not ListBoxItem targetContainer)
        {
            CancelConversationDrag(releaseCapture: false);
            AnimateConversationPlacement(item, oldIndex, newIndex);
            FocusConversation(item);
            return;
        }

        var targetTopLeft = targetContainer.PointToScreen(new System.Windows.Point(0, 0));
        targetContainer.Opacity = 0;
        _conversationSettleContainer = targetContainer;
        _conversationSettleOldIndex = oldIndex;
        _conversationSettleNewIndex = newIndex;
        _conversationSettleStartedUtc = DateTime.UtcNow;
        _conversationIsSettling = true;
        _conversationDragPreview.BeginSettle(targetTopLeft);
        if (!SystemParameters.ClientAreaAnimation)
        {
            CompleteConversationSettle();
        }
    }

    private void CompleteConversationSettle()
    {
        var item = _conversationDragSource;
        var settledContainer = _conversationSettleContainer;
        var oldIndex = _conversationSettleOldIndex;
        var newIndex = _conversationSettleNewIndex;
        _conversationSettleContainer = null;
        _conversationIsSettling = false;
        CancelConversationDrag(releaseCapture: false);
        if (settledContainer is not null)
        {
            AnimateConversationSettlement(settledContainer, oldIndex, newIndex);
        }
        if (item is not null)
        {
            FocusConversation(item);
        }
    }

    private void AnimateConversationSettlement(ListBoxItem container, int oldIndex, int newIndex)
    {
        if (!SystemParameters.ClientAreaAnimation)
        {
            container.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            container.Opacity = 1;
            var immediateTransform = EnsureRouteTransform(container);
            immediateTransform.BeginAnimation(
                TranslateTransform.YProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            immediateTransform.Y = 0;
            return;
        }

        var offset = oldIndex < newIndex ? -12d : 12d;
        var transform = EnsureRouteTransform(container);
        transform.Y = offset;
        container.Opacity = 0;
        var opacityAnimation = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        var placementAnimation = new DoubleAnimation(offset, 0, TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = new BackEase
            {
                Amplitude = 0.18,
                EasingMode = EasingMode.EaseOut
            }
        };
        placementAnimation.Completed += (_, _) =>
        {
            container.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            container.Opacity = 1;
            transform.BeginAnimation(
                TranslateTransform.YProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            transform.Y = 0;
        };
        container.BeginAnimation(
            UIElement.OpacityProperty,
            opacityAnimation,
            HandoffBehavior.SnapshotAndReplace);
        transform.BeginAnimation(
            TranslateTransform.YProperty,
            placementAnimation,
            HandoffBehavior.SnapshotAndReplace);
    }

    private void ReleaseConversationDragCapture()
    {
        var captureOwner = _conversationDragCaptureOwner;
        if (captureOwner?.IsMouseCaptured != true)
        {
            return;
        }

        _releasingConversationDragCapture = true;
        try
        {
            captureOwner.ReleaseMouseCapture();
        }
        finally
        {
            _releasingConversationDragCapture = false;
        }
    }

    private void ResetConversationNeighborDisplacement()
    {
        foreach (var container in _conversationDisplacedContainers)
        {
            var transform = EnsureRouteTransform(container);
            transform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
            transform.Y = 0;
        }
        _conversationDisplacedContainers.Clear();
    }

    private void AnimateConversationPlacement(
        GuardianTaskItem item,
        int oldIndex,
        int newIndex)
    {
        if (!SystemParameters.ClientAreaAnimation)
        {
            return;
        }

        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Render,
            new Action(() =>
            {
                TaskList.UpdateLayout();
                if (TaskList.ItemContainerGenerator.ContainerFromItem(item) is not ListBoxItem container)
                {
                    return;
                }

                var offset = oldIndex < newIndex ? -8d : 8d;
                var transform = EnsureRouteTransform(container);
                transform.Y = offset;
                var animation = new DoubleAnimation(offset, 0, TimeSpan.FromMilliseconds(210))
                {
                    EasingFunction = new BackEase
                    {
                        Amplitude = 0.22,
                        EasingMode = EasingMode.EaseOut
                    }
                };
                animation.Completed += (_, _) =>
                {
                    transform.BeginAnimation(TranslateTransform.YProperty, null);
                    transform.Y = 0;
                };
                transform.BeginAnimation(TranslateTransform.YProperty, animation);
            }));
    }

    private void CancelConversationDrag(bool releaseCapture = true)
    {
        if (_conversationSettleContainer is not null)
        {
            _conversationSettleContainer.BeginAnimation(
                UIElement.OpacityProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            _conversationSettleContainer.Opacity = 1;
            _conversationSettleContainer = null;
        }

        _conversationDragCandidate?.SetDragVisualState(false, false, false);
        _conversationDragSource?.SetDragVisualState(false, false, false);
        foreach (var task in _viewModel.Tasks)
        {
            task.IsDragSource = false;
            task.ShowDropBefore = false;
            task.ShowDropAfter = false;
        }
        ResetConversationNeighborDisplacement();
        StopConversationRendering();

        var captureOwner = _conversationDragCaptureOwner;
        var preview = _conversationDragPreview;
        _conversationDragPreview = null;
        preview?.Close();

        Mouse.OverrideCursor = null;
        _conversationDragCandidate = null;
        _conversationDragSource = null;
        _conversationDragCaptureOwner = null;
        _conversationDragContainer = null;
        _conversationDropInsertionIndex = null;
        _conversationVisualInsertionIndex = null;
        _conversationIsSettling = false;
        _conversationDropCommitPending = false;
        _conversationSettleOldIndex = 0;
        _conversationSettleNewIndex = 0;
        if (!releaseCapture || captureOwner?.IsMouseCaptured != true)
        {
            return;
        }

        _releasingConversationDragCapture = true;
        try
        {
            captureOwner.ReleaseMouseCapture();
        }
        finally
        {
            _releasingConversationDragCapture = false;
        }
    }

    private void OnConversationCollectionChanged(object? sender, NotifyCollectionChangedEventArgs eventArgs)
    {
        if (_conversationDropCommitPending || _conversationIsSettling ||
            _conversationDragCandidate is null && _conversationDragSource is null)
        {
            return;
        }

        if (Dispatcher.CheckAccess())
        {
            CancelConversationDrag();
            return;
        }

        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.DataBind,
            new Action(() => CancelConversationDrag()));
    }

    private void FollowUpDragGrip_PreviewMouseLeftButtonDown(
        object sender,
        MouseButtonEventArgs eventArgs)
    {
        if (sender is not Button grip ||
            grip.DataContext is not FollowUpMessageItem item ||
            ItemsControl.ContainerFromElement(FollowUpMessageList, grip) is not ListBoxItem container ||
            !_viewModel.CanEditSelectedFollowUps)
        {
            return;
        }

        CancelFollowUpDrag();
        CancelConversationDrag();
        CancelAttachmentDrag();
        _viewModel.SelectedFollowUpMessage = item;
        _followUpDragCandidate = item;
        _followUpDragCaptureOwner = grip;
        _followUpDragContainer = container;
        _followUpDragStartPoint = eventArgs.GetPosition(FollowUpMessageList);
        var containerTopLeft = container.TranslatePoint(
            new System.Windows.Point(0, 0),
            FollowUpMessageList);
        _followUpDragPointerOffset = _followUpDragStartPoint - containerTopLeft;
        grip.Focus();

        // Keep ordinary controls available until this gesture becomes a real drag.
        eventArgs.Handled = true;
    }

    private void FollowUpDragGrip_PreviewMouseMove(object sender, MouseEventArgs eventArgs)
    {
        if (_followUpDragCandidate is null)
        {
            return;
        }

        if (eventArgs.LeftButton != MouseButtonState.Pressed)
        {
            CancelFollowUpDrag();
            return;
        }

        var pointer = eventArgs.GetPosition(FollowUpMessageList);
        if (_followUpDragSource is null)
        {
            var horizontalDistance = Math.Abs(pointer.X - _followUpDragStartPoint.X);
            var verticalDistance = Math.Abs(pointer.Y - _followUpDragStartPoint.Y);
            if (horizontalDistance < SystemParameters.MinimumHorizontalDragDistance &&
                verticalDistance < SystemParameters.MinimumVerticalDragDistance)
            {
                return;
            }

            _followUpDragSource = _followUpDragCandidate;
            if (!BeginFollowUpDrag(_followUpDragSource, pointer))
            {
                CancelFollowUpDrag();
                return;
            }
        }

        _followUpPointer = pointer;
        UpdateFollowUpDragPreview();
        if (IsFollowUpPointerWithinDropCorridor(pointer))
        {
            UpdateFollowUpAutoScrollVelocity(pointer);
            _followUpDropInsertionIndex = CalculateFollowUpInsertionIndex(pointer);
            SetFollowUpDropIndicator(_followUpDropInsertionIndex);
        }
        else
        {
            _followUpAutoScrollVelocity = 0;
            _followUpDropInsertionIndex = null;
            SetFollowUpDropIndicator(null);
        }
        eventArgs.Handled = _followUpDragSource is not null;
    }

    private void FollowUpDragGrip_PreviewMouseLeftButtonUp(
        object sender,
        MouseButtonEventArgs eventArgs)
    {
        var item = _followUpDragSource;
        if (item is null)
        {
            // Preserve ordinary click routing when the pointer never became a drag.
            CancelFollowUpDrag();
            return;
        }

        var insertionIndex = _followUpDropInsertionIndex;
        var oldIndex = _viewModel.FollowUpMessages.IndexOf(item);
        var targetIndex = insertionIndex ?? oldIndex;
        var pointer = eventArgs.GetPosition(FollowUpMessageList);
        var isInsideDropBounds = pointer.X >= -48 &&
                                 pointer.X <= FollowUpMessageList.ActualWidth + 48 &&
                                 pointer.Y >= -48 &&
                                 pointer.Y <= FollowUpMessageList.ActualHeight + 48;
        if (targetIndex > oldIndex)
        {
            targetIndex--;
        }

        var moved = isInsideDropBounds &&
                    oldIndex >= 0 &&
                    _viewModel.MoveFollowUpMessage(
                        item,
                        Math.Clamp(targetIndex, 0, _viewModel.FollowUpMessages.Count - 1));
        if (moved)
        {
            BeginFollowUpSettle(item, oldIndex, targetIndex);
        }
        else
        {
            CancelFollowUpDrag();
        }

        eventArgs.Handled = true;
    }

    private void FollowUpDragGrip_LostMouseCapture(object sender, MouseEventArgs eventArgs)
    {
        if (!_releasingFollowUpDragCapture)
        {
            CancelFollowUpDrag(releaseCapture: false);
        }
    }

    private void FollowUpDragGrip_PreviewKeyDown(object sender, KeyEventArgs eventArgs)
    {
        if (eventArgs.Key == Key.Escape &&
            (_followUpDragCandidate is not null || _followUpDragSource is not null))
        {
            CancelFollowUpDrag();
            eventArgs.Handled = true;
            return;
        }

        var key = eventArgs.Key == Key.System ? eventArgs.SystemKey : eventArgs.Key;
        if (sender is not Button { DataContext: FollowUpMessageItem item } ||
            Keyboard.Modifiers != ModifierKeys.Alt ||
            key is not Key.Up and not Key.Down)
        {
            return;
        }

        var oldIndex = _viewModel.FollowUpMessages.IndexOf(item);
        var targetIndex = key == Key.Up ? oldIndex - 1 : oldIndex + 1;
        if (_viewModel.MoveFollowUpMessage(item, targetIndex))
        {
            AnimateFollowUpPlacement(item, oldIndex, targetIndex);
            FocusFollowUpMessage(item, focusMessageEditor: false);
        }

        eventArgs.Handled = true;
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs eventArgs)
    {
        if (!_previewIsolationMode &&
            !IsAttachmentImportInProgress &&
            Keyboard.Modifiers == ModifierKeys.Control &&
            eventArgs.Key == Key.V &&
            _viewModel.IsFollowUpDetailPage &&
            _viewModel.SelectedFollowUpMessage is { } attachmentOwner)
        {
            try
            {
                var data = System.Windows.Clipboard.GetDataObject();
                if (data?.GetDataPresent(DataFormats.FileDrop) == true ||
                    data?.GetDataPresent(DataFormats.Bitmap) == true)
                {
                    eventArgs.Handled = true;
                    _ = ImportClipboardAttachmentsAsync(attachmentOwner);
                    return;
                }
            }
            catch (ExternalException)
            {
                _viewModel.SetFollowUpAttachmentImportStatus(false);
                return;
            }
        }

        if (eventArgs.Key != Key.Escape)
        {
            return;
        }

        var handled = false;
        if (_conversationDragCandidate is not null || _conversationDragSource is not null)
        {
            CancelConversationDrag();
            handled = true;
        }
        if (_followUpDragCandidate is not null || _followUpDragSource is not null)
        {
            CancelFollowUpDrag();
            handled = true;
        }
        if (_attachmentDragCandidate is not null || _attachmentDragSource is not null)
        {
            CancelAttachmentDrag();
            handled = true;
        }
        eventArgs.Handled = handled;
    }

    private void FollowUpAttachmentDragGrip_PreviewMouseLeftButtonDown(
        object sender,
        MouseButtonEventArgs eventArgs)
    {
        if (sender is not Button grip ||
            grip.DataContext is not AttachmentItemViewModel item ||
            FindVisualAncestor<ItemsControl>(grip) is not { } rail ||
            FindVisualAncestor<ScrollViewer>(rail) is not { } scrollViewer ||
            rail.DataContext is not FollowUpMessageItem owner ||
            ItemsControl.ContainerFromElement(rail, grip) is not FrameworkElement container ||
            !_viewModel.CanEditSelectedFollowUps ||
            !owner.Attachments.Contains(item) ||
            owner.Attachments.Count < 2)
        {
            return;
        }

        CancelAttachmentDrag();
        CancelFollowUpDrag();
        CancelConversationDrag();
        _attachmentDragCandidate = item;
        _attachmentDragOwner = owner;
        _attachmentDragCaptureOwner = grip;
        _attachmentDragRail = rail;
        _attachmentDragScrollViewer = scrollViewer;
        _attachmentDragContainer = container;
        _attachmentDragStartPoint = eventArgs.GetPosition(rail);
        var containerTopLeft = container.TranslatePoint(new System.Windows.Point(0, 0), rail);
        _attachmentDragPointerOffset = _attachmentDragStartPoint - containerTopLeft;
        owner.Attachments.CollectionChanged += OnAttachmentOwnerCollectionChanged;
        grip.Focus();
        eventArgs.Handled = true;
    }

    private void FollowUpAttachmentDragGrip_PreviewMouseMove(
        object sender,
        MouseEventArgs eventArgs)
    {
        if (_attachmentDragCandidate is null ||
            _attachmentDragRail is null ||
            _attachmentDragScrollViewer is null)
        {
            return;
        }

        if (eventArgs.LeftButton != MouseButtonState.Pressed)
        {
            CancelAttachmentDrag();
            return;
        }

        var pointer = eventArgs.GetPosition(_attachmentDragRail);
        if (_attachmentDragSource is null)
        {
            var horizontalDistance = Math.Abs(pointer.X - _attachmentDragStartPoint.X);
            var verticalDistance = Math.Abs(pointer.Y - _attachmentDragStartPoint.Y);
            if (horizontalDistance < SystemParameters.MinimumHorizontalDragDistance &&
                verticalDistance < SystemParameters.MinimumVerticalDragDistance)
            {
                return;
            }

            _attachmentDragSource = _attachmentDragCandidate;
            if (!BeginAttachmentDrag(_attachmentDragSource, pointer))
            {
                CancelAttachmentDrag();
                return;
            }
        }

        _attachmentPointer = pointer;
        UpdateAttachmentDragPreview();
        var viewportPointer = eventArgs.GetPosition(_attachmentDragScrollViewer);
        if (IsAttachmentPointerWithinDropCorridor(viewportPointer))
        {
            UpdateAttachmentAutoScrollVelocity(viewportPointer);
            _attachmentDropInsertionIndex = CalculateAttachmentInsertionIndex(pointer);
            SetAttachmentDropIndicator(_attachmentDropInsertionIndex);
        }
        else
        {
            _attachmentAutoScrollVelocity = 0;
            _attachmentDropInsertionIndex = null;
            SetAttachmentDropIndicator(null);
        }

        eventArgs.Handled = true;
    }

    private void FollowUpAttachmentDragGrip_PreviewMouseLeftButtonUp(
        object sender,
        MouseButtonEventArgs eventArgs)
    {
        var item = _attachmentDragSource;
        var owner = _attachmentDragOwner;
        var rail = _attachmentDragRail;
        var scrollViewer = _attachmentDragScrollViewer;
        if (item is null || owner is null || rail is null || scrollViewer is null)
        {
            CancelAttachmentDrag();
            return;
        }

        var oldIndex = owner.Attachments.IndexOf(item);
        var insertionIndex = _attachmentDropInsertionIndex;
        var targetIndex = insertionIndex ?? oldIndex;
        if (targetIndex > oldIndex)
        {
            targetIndex--;
        }

        var viewportPointer = eventArgs.GetPosition(scrollViewer);
        var validDrop = IsAttachmentPointerWithinDropCorridor(viewportPointer) &&
                        insertionIndex is not null &&
                        oldIndex >= 0 &&
                        _viewModel.IsFollowUpDetailPage &&
                        _viewModel.FollowUpMessages.Contains(owner) &&
                        owner.Attachments.Contains(item);
        _attachmentDropCommitPending = true;
        _attachmentAutoScrollVelocity = 0;
        ReleaseAttachmentDragCapture();
        var moved = false;
        try
        {
            moved = validDrop && CommitAttachmentMove(
                owner,
                item,
                Math.Clamp(targetIndex, 0, Math.Max(0, owner.Attachments.Count - 1)));
        }
        finally
        {
            _attachmentDropCommitPending = false;
        }

        if (moved)
        {
            BeginAttachmentSettle(item, oldIndex, targetIndex);
        }
        else
        {
            CancelAttachmentDrag(releaseCapture: false);
        }

        eventArgs.Handled = true;
    }

    private void FollowUpAttachmentDragGrip_LostMouseCapture(
        object sender,
        MouseEventArgs eventArgs)
    {
        if (!_releasingAttachmentDragCapture && !_attachmentDropCommitPending)
        {
            CancelAttachmentDrag(releaseCapture: false);
        }
    }

    private void FollowUpAttachmentDragGrip_PreviewKeyDown(
        object sender,
        KeyEventArgs eventArgs)
    {
        if (eventArgs.Key == Key.Escape &&
            (_attachmentDragCandidate is not null || _attachmentDragSource is not null))
        {
            CancelAttachmentDrag();
            eventArgs.Handled = true;
            return;
        }

        var key = eventArgs.Key == Key.System ? eventArgs.SystemKey : eventArgs.Key;
        if (sender is not Button { DataContext: AttachmentItemViewModel item } grip ||
            Keyboard.Modifiers != ModifierKeys.Alt ||
            key is not Key.Left and not Key.Right ||
            FindVisualAncestor<ItemsControl>(grip) is not { DataContext: FollowUpMessageItem owner })
        {
            return;
        }

        var oldIndex = owner.Attachments.IndexOf(item);
        var targetIndex = key == Key.Left ? oldIndex - 1 : oldIndex + 1;
        if (CommitAttachmentMove(owner, item, targetIndex))
        {
            AnimateAttachmentPlacement(owner, item, oldIndex, targetIndex);
            FocusAttachmentGrip(owner, item);
        }

        eventArgs.Handled = true;
    }

    private static bool CommitAttachmentMove(
        FollowUpMessageItem owner,
        AttachmentItemViewModel item,
        int targetIndex) =>
        MainViewModel.MoveFollowUpAttachmentDraft(owner, item, targetIndex);

    private bool BeginAttachmentDrag(
        AttachmentItemViewModel item,
        System.Windows.Point pointer)
    {
        if (_attachmentDragContainer is null ||
            _attachmentDragCaptureOwner is null ||
            _attachmentDragOwner is null ||
            _attachmentDragRail is null ||
            !_viewModel.IsFollowUpDetailPage ||
            !_viewModel.FollowUpMessages.Contains(_attachmentDragOwner) ||
            !_attachmentDragOwner.Attachments.Contains(item) ||
            !Mouse.Capture(_attachmentDragCaptureOwner, CaptureMode.Element))
        {
            return false;
        }

        _attachmentDragContainer.UpdateLayout();
        var fontFamily = TryFindResource("BodyFont") as System.Windows.Media.FontFamily ??
                         new System.Windows.Media.FontFamily("Segoe UI");
        var dpi = VisualTreeHelper.GetDpi(this);
        var preview = new FollowUpDragPreviewWindow(
            this,
            item,
            fontFamily,
            220,
            46,
            dpi.DpiScaleX,
            dpi.DpiScaleY,
            SystemParameters.ClientAreaAnimation);
        try
        {
            preview.Show();
        }
        catch
        {
            preview.Close();
            return false;
        }

        _attachmentDragPreview = preview;
        item.IsDragSource = true;
        Mouse.OverrideCursor = Cursors.SizeAll;
        _attachmentPointer = pointer;
        StartAttachmentRendering();
        UpdateAttachmentDragPreview();
        return true;
    }

    private void UpdateAttachmentDragPreview()
    {
        if (_attachmentDragPreview is null || !GetCursorPos(out var cursor))
        {
            return;
        }

        _attachmentDragPreview.UpdatePointer(
            new System.Windows.Point(cursor.X, cursor.Y),
            _attachmentDragPointerOffset);
    }

    private int? CalculateAttachmentInsertionIndex(System.Windows.Point pointer)
    {
        if (_attachmentDragRail is null)
        {
            return null;
        }

        var lastVisibleIndex = -1;
        for (var index = 0; index < _attachmentDragRail.Items.Count; index++)
        {
            if (_attachmentDragRail.ItemContainerGenerator.ContainerFromIndex(index) is not FrameworkElement container ||
                container.ActualWidth <= 0)
            {
                continue;
            }

            lastVisibleIndex = index;
            var left = container.TranslatePoint(new System.Windows.Point(0, 0), _attachmentDragRail).X;
            if (pointer.X < left + container.ActualWidth / 2)
            {
                return index;
            }
        }

        return lastVisibleIndex < 0 ? null : Math.Min(_attachmentDragRail.Items.Count, lastVisibleIndex + 1);
    }

    private bool IsAttachmentPointerWithinDropCorridor(System.Windows.Point viewportPointer) =>
        _attachmentDragScrollViewer is { } scrollViewer &&
        viewportPointer.X >= -64 &&
        viewportPointer.X <= scrollViewer.ActualWidth + 64 &&
        viewportPointer.Y >= -48 &&
        viewportPointer.Y <= scrollViewer.ActualHeight + 48;

    private void SetAttachmentDropIndicator(int? insertionIndex)
    {
        if (_attachmentVisualInsertionIndex == insertionIndex)
        {
            return;
        }

        _attachmentVisualInsertionIndex = insertionIndex;
        var attachments = _attachmentDragOwner?.Attachments;
        if (attachments is null)
        {
            return;
        }

        foreach (var attachment in attachments)
        {
            attachment.ShowDropBefore = false;
            attachment.ShowDropAfter = false;
        }

        if (insertionIndex is null || attachments.Count == 0)
        {
            AnimateAttachmentNeighborDisplacement(null);
            return;
        }

        if (insertionIndex.Value >= attachments.Count)
        {
            attachments[^1].ShowDropAfter = true;
        }
        else
        {
            attachments[Math.Max(0, insertionIndex.Value)].ShowDropBefore = true;
        }
        AnimateAttachmentNeighborDisplacement(insertionIndex);
    }

    private void UpdateAttachmentAutoScrollVelocity(System.Windows.Point viewportPointer)
    {
        if (_attachmentDragScrollViewer is not { ScrollableWidth: > 0 } scrollViewer)
        {
            _attachmentAutoScrollVelocity = 0;
            return;
        }

        const double edge = 56;
        const double maximumVelocity = 820;
        if (viewportPointer.X < edge)
        {
            var depth = Math.Clamp((edge - viewportPointer.X) / edge, 0, 1);
            _attachmentAutoScrollVelocity = -maximumVelocity * depth * depth;
        }
        else if (viewportPointer.X > scrollViewer.ActualWidth - edge)
        {
            var depth = Math.Clamp(
                (viewportPointer.X - (scrollViewer.ActualWidth - edge)) / edge,
                0,
                1);
            _attachmentAutoScrollVelocity = maximumVelocity * depth * depth;
        }
        else
        {
            _attachmentAutoScrollVelocity = 0;
        }
    }

    private void StartAttachmentRendering()
    {
        if (_attachmentRenderingSubscribed)
        {
            return;
        }

        _attachmentRenderingTimestampUtc = DateTime.UtcNow;
        CompositionTarget.Rendering += OnAttachmentRendering;
        _attachmentRenderingSubscribed = true;
    }

    private void StopAttachmentRendering()
    {
        if (!_attachmentRenderingSubscribed)
        {
            return;
        }

        CompositionTarget.Rendering -= OnAttachmentRendering;
        _attachmentRenderingSubscribed = false;
        _attachmentAutoScrollVelocity = 0;
    }

    private void OnAttachmentRendering(object? sender, EventArgs eventArgs)
    {
        if (_attachmentDragSource is null ||
            _attachmentDragPreview is null ||
            _attachmentDragScrollViewer is null ||
            _attachmentDragRail is null)
        {
            StopAttachmentRendering();
            return;
        }

        var now = DateTime.UtcNow;
        var elapsed = Math.Clamp(
            (now - _attachmentRenderingTimestampUtc).TotalSeconds,
            1d / 240d,
            1d / 24d);
        _attachmentRenderingTimestampUtc = now;
        _attachmentDragPreview.Advance(elapsed);

        if (_attachmentIsSettling)
        {
            if (!SystemParameters.ClientAreaAnimation ||
                _attachmentDragPreview.IsSettled ||
                now - _attachmentSettleStartedUtc >= TimeSpan.FromMilliseconds(650))
            {
                CompleteAttachmentSettle();
            }
            return;
        }

        if (Mouse.LeftButton != MouseButtonState.Pressed)
        {
            CancelAttachmentDrag();
            return;
        }

        UpdateAttachmentDragPreview();
        var viewportPointer = Mouse.GetPosition(_attachmentDragScrollViewer);
        if (!IsAttachmentPointerWithinDropCorridor(viewportPointer))
        {
            _attachmentAutoScrollVelocity = 0;
            _attachmentDropInsertionIndex = null;
            SetAttachmentDropIndicator(null);
            return;
        }

        UpdateAttachmentAutoScrollVelocity(viewportPointer);
        if (Math.Abs(_attachmentAutoScrollVelocity) >= 0.1)
        {
            var targetOffset = Math.Clamp(
                _attachmentDragScrollViewer.HorizontalOffset + _attachmentAutoScrollVelocity * elapsed,
                0,
                _attachmentDragScrollViewer.ScrollableWidth);
            if (Math.Abs(targetOffset - _attachmentDragScrollViewer.HorizontalOffset) >= 0.05)
            {
                _attachmentDragScrollViewer.ScrollToHorizontalOffset(targetOffset);
                _attachmentDragRail.UpdateLayout();
            }
        }

        _attachmentPointer = Mouse.GetPosition(_attachmentDragRail);
        _attachmentDropInsertionIndex = CalculateAttachmentInsertionIndex(_attachmentPointer);
        SetAttachmentDropIndicator(_attachmentDropInsertionIndex);
    }

    private void AnimateAttachmentNeighborDisplacement(int? insertionIndex)
    {
        var source = _attachmentDragSource;
        var owner = _attachmentDragOwner;
        var rail = _attachmentDragRail;
        if (source is null || owner is null || rail is null)
        {
            return;
        }

        var sourceIndex = owner.Attachments.IndexOf(source);
        for (var index = 0; index < owner.Attachments.Count; index++)
        {
            if (rail.ItemContainerGenerator.ContainerFromIndex(index) is not FrameworkElement container ||
                index == sourceIndex)
            {
                continue;
            }

            var target = 0d;
            if (insertionIndex is { } insertion)
            {
                if (insertion < sourceIndex && index >= insertion && index < sourceIndex)
                {
                    target = 228;
                }
                else if (insertion > sourceIndex && index > sourceIndex && index < insertion)
                {
                    target = -228;
                }
            }

            var transform = EnsureRouteTransform(container);
            if (!SystemParameters.ClientAreaAnimation)
            {
                transform.BeginAnimation(TranslateTransform.XProperty, null, HandoffBehavior.SnapshotAndReplace);
                transform.X = target;
            }
            else
            {
                transform.BeginAnimation(
                    TranslateTransform.XProperty,
                    new DoubleAnimation(transform.X, target, TimeSpan.FromMilliseconds(165))
                    {
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    },
                    HandoffBehavior.SnapshotAndReplace);
            }

            if (Math.Abs(target) > 0.1)
            {
                _attachmentDisplacedContainers.Add(container);
            }
        }
    }

    private void ResetAttachmentNeighborDisplacement()
    {
        foreach (var container in _attachmentDisplacedContainers.ToArray())
        {
            var transform = EnsureRouteTransform(container);
            transform.BeginAnimation(TranslateTransform.XProperty, null, HandoffBehavior.SnapshotAndReplace);
            transform.X = 0;
        }
        _attachmentDisplacedContainers.Clear();
    }

    private void BeginAttachmentSettle(
        AttachmentItemViewModel item,
        int oldIndex,
        int newIndex)
    {
        ReleaseAttachmentDragCapture();
        foreach (var attachment in _attachmentDragOwner?.Attachments ?? [])
        {
            attachment.IsDragSource = false;
            attachment.ShowDropBefore = false;
            attachment.ShowDropAfter = false;
        }
        ResetAttachmentNeighborDisplacement();
        _attachmentDragRail?.UpdateLayout();

        if (_attachmentDragPreview is null ||
            _attachmentDragRail?.ItemContainerGenerator.ContainerFromItem(item) is not FrameworkElement targetContainer)
        {
            CancelAttachmentDrag(releaseCapture: false);
            AnimateAttachmentPlacement(_attachmentDragOwner, item, oldIndex, newIndex);
            return;
        }

        var targetTopLeft = targetContainer.PointToScreen(new System.Windows.Point(0, 0));
        targetContainer.Opacity = 0;
        _attachmentSettleContainer = targetContainer;
        _attachmentSettleOldIndex = oldIndex;
        _attachmentSettleNewIndex = newIndex;
        _attachmentSettleStartedUtc = DateTime.UtcNow;
        _attachmentIsSettling = true;
        _attachmentDragPreview.BeginSettle(targetTopLeft);
    }

    private void CompleteAttachmentSettle()
    {
        if (_attachmentSettleContainer is not null)
        {
            _attachmentSettleContainer.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            _attachmentSettleContainer.Opacity = 1;
            _attachmentSettleContainer = null;
        }

        var owner = _attachmentDragOwner;
        var item = _attachmentDragSource;
        var oldIndex = _attachmentSettleOldIndex;
        var newIndex = _attachmentSettleNewIndex;
        _attachmentIsSettling = false;
        CancelAttachmentDrag(releaseCapture: false);
        if (owner is not null && item is not null)
        {
            AnimateAttachmentPlacement(owner, item, oldIndex, newIndex);
            FocusAttachmentGrip(owner, item);
        }
    }

    private void AnimateAttachmentPlacement(
        FollowUpMessageItem? owner,
        AttachmentItemViewModel item,
        int oldIndex,
        int newIndex)
    {
        var rail = owner is null ? null : FindAttachmentRail(owner);
        if (owner is null || rail is null || !SystemParameters.ClientAreaAnimation)
        {
            return;
        }

        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Render,
            new Action(() =>
            {
                if (rail.ItemContainerGenerator.ContainerFromItem(item) is not FrameworkElement container)
                {
                    return;
                }

                var offset = oldIndex < newIndex ? -10d : 10d;
                var transform = EnsureRouteTransform(container);
                transform.X = offset;
                var animation = new DoubleAnimation(offset, 0, TimeSpan.FromMilliseconds(190))
                {
                    EasingFunction = new QuinticEase { EasingMode = EasingMode.EaseOut }
                };
                animation.Completed += (_, _) =>
                {
                    transform.BeginAnimation(TranslateTransform.XProperty, null);
                    transform.X = 0;
                };
                transform.BeginAnimation(TranslateTransform.XProperty, animation, HandoffBehavior.SnapshotAndReplace);
            }));
    }

    private void FocusAttachmentGrip(FollowUpMessageItem owner, AttachmentItemViewModel item)
    {
        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Loaded,
            new Action(() =>
            {
                var rail = FindAttachmentRail(owner);
                if (rail?.ItemContainerGenerator.ContainerFromItem(item) is not FrameworkElement container)
                {
                    return;
                }

                FindVisualDescendant<System.Windows.Controls.Control>(
                    container,
                    control => string.Equals(
                        AutomationProperties.GetAutomationId(control),
                        "FollowUpAttachmentDragGrip",
                        StringComparison.Ordinal))?.Focus();
            }));
    }

    private void OnAttachmentOwnerCollectionChanged(object? sender, NotifyCollectionChangedEventArgs eventArgs)
    {
        if (_attachmentDropCommitPending || _attachmentIsSettling ||
            _attachmentDragCandidate is null && _attachmentDragSource is null)
        {
            return;
        }

        CancelAttachmentDrag();
    }

    private void ReleaseAttachmentDragCapture()
    {
        var captureOwner = _attachmentDragCaptureOwner;
        if (captureOwner?.IsMouseCaptured != true)
        {
            return;
        }

        _releasingAttachmentDragCapture = true;
        try
        {
            captureOwner.ReleaseMouseCapture();
        }
        finally
        {
            _releasingAttachmentDragCapture = false;
        }
    }

    private void CancelAttachmentDrag(bool releaseCapture = true)
    {
        if (_attachmentSettleContainer is not null)
        {
            _attachmentSettleContainer.BeginAnimation(UIElement.OpacityProperty, null, HandoffBehavior.SnapshotAndReplace);
            _attachmentSettleContainer.Opacity = 1;
            _attachmentSettleContainer = null;
        }

        foreach (var attachment in _attachmentDragOwner?.Attachments ?? [])
        {
            attachment.IsDragSource = false;
            attachment.ShowDropBefore = false;
            attachment.ShowDropAfter = false;
        }
        ResetAttachmentNeighborDisplacement();
        StopAttachmentRendering();
        var owner = _attachmentDragOwner;
        if (owner is not null)
        {
            owner.Attachments.CollectionChanged -= OnAttachmentOwnerCollectionChanged;
        }
        var captureOwner = _attachmentDragCaptureOwner;
        var preview = _attachmentDragPreview;
        _attachmentDragPreview = null;
        preview?.Close();
        Mouse.OverrideCursor = null;
        _attachmentDragCandidate = null;
        _attachmentDragSource = null;
        _attachmentDragOwner = null;
        _attachmentDragCaptureOwner = null;
        _attachmentDragRail = null;
        _attachmentDragScrollViewer = null;
        _attachmentDragContainer = null;
        _attachmentDropInsertionIndex = null;
        _attachmentVisualInsertionIndex = null;
        _attachmentIsSettling = false;
        _attachmentSettleOldIndex = 0;
        _attachmentSettleNewIndex = 0;
        _attachmentDropCommitPending = false;
        if (!releaseCapture || captureOwner?.IsMouseCaptured != true)
        {
            return;
        }

        _releasingAttachmentDragCapture = true;
        try
        {
            captureOwner.ReleaseMouseCapture();
        }
        finally
        {
            _releasingAttachmentDragCapture = false;
        }
    }

    private bool BeginFollowUpDrag(
        FollowUpMessageItem item,
        System.Windows.Point pointer)
    {
        if (_followUpDragContainer is null ||
            _followUpDragCaptureOwner is null ||
            !Mouse.Capture(_followUpDragCaptureOwner, CaptureMode.Element))
        {
            return false;
        }

        item.IsEditing = false;
        _followUpDragContainer.UpdateLayout();
        var availableWidth = Math.Max(280, FollowUpMessageList.ActualWidth);
        var previewWidth = Math.Min(
            Math.Max(280, _followUpDragContainer.ActualWidth),
            availableWidth);
        const double previewHeight = 68;
        var triggerText = _viewModel.FollowUpTriggerOptions
            .FirstOrDefault(option => option.Kind == item.Trigger)
            ?.DisplayName ?? item.Trigger.ToString();
        if (item.IsScheduled && item.ScheduledDateLocal is { } scheduledDate)
        {
            triggerText = $"{triggerText} · {scheduledDate:yyyy-MM-dd} {item.ScheduledTimeText}";
        }
        triggerText = item.RetryIndefinitely
            ? $"{triggerText} · {_localization.GetString("FollowUp.RetryInfinite")}"
            : $"{triggerText} · {_localization.GetString("FollowUp.RetryShort")} " +
              item.EffectiveMaximumErrorRetries.ToString(_localization.CurrentCulture);

        var fontFamily = TryFindResource("BodyFont") as System.Windows.Media.FontFamily ??
                         new System.Windows.Media.FontFamily("Segoe UI");
        var dpi = VisualTreeHelper.GetDpi(this);
        var preview = new FollowUpDragPreviewWindow(
            this,
            item,
            triggerText,
            fontFamily,
            previewWidth,
            previewHeight,
            dpi.DpiScaleX,
            dpi.DpiScaleY,
            SystemParameters.ClientAreaAnimation);
        try
        {
            preview.Show();
        }
        catch
        {
            preview.Close();
            return false;
        }

        _followUpDragPreview = preview;
        item.IsDragSource = true;
        Mouse.OverrideCursor = Cursors.SizeAll;
        _followUpPointer = pointer;
        StartFollowUpRendering();
        UpdateFollowUpDragPreview();
        return true;
    }

    private void UpdateFollowUpDragPreview()
    {
        if (_followUpDragPreview is null || !GetCursorPos(out var cursor))
        {
            return;
        }

        _followUpDragPreview.UpdatePointer(
            new System.Windows.Point(cursor.X, cursor.Y),
            _followUpDragPointerOffset);
    }

    private int? CalculateFollowUpInsertionIndex(System.Windows.Point pointer)
    {
        var lastVisibleIndex = -1;
        for (var index = 0; index < FollowUpMessageList.Items.Count; index++)
        {
            if (FollowUpMessageList.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem container ||
                container.ActualHeight <= 0)
            {
                continue;
            }

            lastVisibleIndex = index;
            var top = container.TranslatePoint(new System.Windows.Point(0, 0), FollowUpMessageList).Y;
            if (pointer.Y < top + container.ActualHeight / 2)
            {
                return index;
            }
        }

        return lastVisibleIndex < 0
            ? null
            : Math.Min(FollowUpMessageList.Items.Count, lastVisibleIndex + 1);
    }

    private bool IsFollowUpPointerWithinDropCorridor(System.Windows.Point pointer) =>
        pointer.X >= -72 && pointer.X <= FollowUpMessageList.ActualWidth + 72;

    private void SetFollowUpDropIndicator(int? insertionIndex)
    {
        if (_followUpVisualInsertionIndex == insertionIndex)
        {
            return;
        }

        _followUpVisualInsertionIndex = insertionIndex;
        foreach (var message in _viewModel.FollowUpMessages)
        {
            message.ShowDropBefore = false;
            message.ShowDropAfter = false;
        }

        if (insertionIndex is null || _viewModel.FollowUpMessages.Count == 0)
        {
            AnimateFollowUpNeighborDisplacement(null);
            return;
        }

        if (insertionIndex.Value >= _viewModel.FollowUpMessages.Count)
        {
            _viewModel.FollowUpMessages[^1].ShowDropAfter = true;
            AnimateFollowUpNeighborDisplacement(insertionIndex);
            return;
        }

        _viewModel.FollowUpMessages[Math.Max(0, insertionIndex.Value)].ShowDropBefore = true;
        AnimateFollowUpNeighborDisplacement(insertionIndex);
    }

    private void UpdateFollowUpAutoScrollVelocity(System.Windows.Point pointer)
    {
        var scrollViewer = FindVisualDescendant<ScrollViewer>(FollowUpMessageList);
        if (scrollViewer is null || scrollViewer.ScrollableHeight <= 0)
        {
            _followUpAutoScrollVelocity = 0;
            return;
        }

        const double edge = 72;
        const double maximumVelocity = 760;
        if (pointer.Y < edge)
        {
            var depth = Math.Clamp((edge - pointer.Y) / edge, 0, 1);
            _followUpAutoScrollVelocity = -maximumVelocity * depth * depth;
        }
        else if (pointer.Y > FollowUpMessageList.ActualHeight - edge)
        {
            var depth = Math.Clamp(
                (pointer.Y - (FollowUpMessageList.ActualHeight - edge)) / edge,
                0,
                1);
            _followUpAutoScrollVelocity = maximumVelocity * depth * depth;
        }
        else
        {
            _followUpAutoScrollVelocity = 0;
        }
    }

    private void StartFollowUpRendering()
    {
        if (_followUpRenderingSubscribed)
        {
            return;
        }

        _followUpRenderingTimestampUtc = DateTime.UtcNow;
        CompositionTarget.Rendering += OnFollowUpRendering;
        _followUpRenderingSubscribed = true;
    }

    private void StopFollowUpRendering()
    {
        if (!_followUpRenderingSubscribed)
        {
            return;
        }

        CompositionTarget.Rendering -= OnFollowUpRendering;
        _followUpRenderingSubscribed = false;
        _followUpAutoScrollVelocity = 0;
    }

    private void OnFollowUpRendering(object? sender, EventArgs eventArgs)
    {
        if (_followUpDragSource is null || _followUpDragPreview is null)
        {
            StopFollowUpRendering();
            return;
        }

        var now = DateTime.UtcNow;
        var elapsed = Math.Clamp((now - _followUpRenderingTimestampUtc).TotalSeconds, 1d / 240d, 1d / 24d);
        _followUpRenderingTimestampUtc = now;
        _followUpDragPreview.Advance(elapsed);

        if (_followUpIsSettling)
        {
            if (!SystemParameters.ClientAreaAnimation ||
                _followUpDragPreview.IsSettled ||
                now - _followUpSettleStartedUtc >= TimeSpan.FromMilliseconds(650))
            {
                CompleteFollowUpSettle();
            }
            return;
        }

        if (Mouse.LeftButton != MouseButtonState.Pressed)
        {
            CancelFollowUpDrag();
            return;
        }

        UpdateFollowUpDragPreview();
        _followUpPointer = Mouse.GetPosition(FollowUpMessageList);
        if (!IsFollowUpPointerWithinDropCorridor(_followUpPointer))
        {
            _followUpAutoScrollVelocity = 0;
            _followUpDropInsertionIndex = null;
            SetFollowUpDropIndicator(null);
            return;
        }
        UpdateFollowUpAutoScrollVelocity(_followUpPointer);

        if (Math.Abs(_followUpAutoScrollVelocity) < 0.1)
        {
            return;
        }

        var scrollViewer = FindVisualDescendant<ScrollViewer>(FollowUpMessageList);
        if (scrollViewer is null || scrollViewer.ScrollableHeight <= 0)
        {
            _followUpAutoScrollVelocity = 0;
            return;
        }

        var targetOffset = Math.Clamp(
            scrollViewer.VerticalOffset + _followUpAutoScrollVelocity * elapsed,
            0,
            scrollViewer.ScrollableHeight);
        if (Math.Abs(targetOffset - scrollViewer.VerticalOffset) < 0.05)
        {
            return;
        }

        scrollViewer.ScrollToVerticalOffset(targetOffset);
        FollowUpMessageList.UpdateLayout();
        _followUpPointer = Mouse.GetPosition(FollowUpMessageList);
        _followUpDropInsertionIndex = CalculateFollowUpInsertionIndex(_followUpPointer);
        SetFollowUpDropIndicator(_followUpDropInsertionIndex);
    }

    private void AnimateFollowUpNeighborDisplacement(int? insertionIndex)
    {
        var source = _followUpDragSource;
        var sourceIndex = source is null ? -1 : _viewModel.FollowUpMessages.IndexOf(source);
        var sourceHeight = Math.Max(0, _followUpDragContainer?.ActualHeight ?? 0);
        for (var index = 0; index < FollowUpMessageList.Items.Count; index++)
        {
            if (FollowUpMessageList.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem container ||
                index == sourceIndex)
            {
                continue;
            }

            var target = 0d;
            if (insertionIndex is { } insertion && sourceIndex >= 0 && sourceHeight > 0)
            {
                if (insertion < sourceIndex && index >= insertion && index < sourceIndex)
                {
                    target = sourceHeight;
                }
                else if (insertion > sourceIndex && index > sourceIndex && index < insertion)
                {
                    target = -sourceHeight;
                }
            }

            var transform = EnsureRouteTransform(container);
            if (!SystemParameters.ClientAreaAnimation)
            {
                transform.BeginAnimation(
                    TranslateTransform.YProperty,
                    null,
                    HandoffBehavior.SnapshotAndReplace);
                transform.Y = target;
                if (Math.Abs(target) > 0.1)
                {
                    _followUpDisplacedContainers.Add(container);
                }
                continue;
            }

            var animation = new DoubleAnimation(
                transform.Y,
                target,
                TimeSpan.FromMilliseconds(165))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            transform.BeginAnimation(
                TranslateTransform.YProperty,
                animation,
                HandoffBehavior.SnapshotAndReplace);
            if (Math.Abs(target) > 0.1)
            {
                _followUpDisplacedContainers.Add(container);
            }
        }
    }

    private void BeginFollowUpSettle(FollowUpMessageItem item, int oldIndex, int newIndex)
    {
        _followUpAutoScrollVelocity = 0;
        ReleaseFollowUpDragCapture();
        foreach (var message in _viewModel.FollowUpMessages)
        {
            message.IsDragSource = false;
            message.ShowDropBefore = false;
            message.ShowDropAfter = false;
        }
        ResetFollowUpNeighborDisplacement();
        FollowUpMessageList.UpdateLayout();

        if (_followUpDragPreview is null ||
            FollowUpMessageList.ItemContainerGenerator.ContainerFromItem(item) is not ListBoxItem targetContainer)
        {
            CancelFollowUpDrag(releaseCapture: false);
            AnimateFollowUpPlacement(item, oldIndex, newIndex);
            FocusFollowUpMessage(item, focusMessageEditor: false);
            return;
        }

        var targetTopLeft = targetContainer.PointToScreen(new System.Windows.Point(0, 0));
        targetContainer.Opacity = 0;
        _followUpSettleContainer = targetContainer;
        _followUpSettleOldIndex = oldIndex;
        _followUpSettleNewIndex = newIndex;
        _followUpSettleStartedUtc = DateTime.UtcNow;
        _followUpIsSettling = true;
        _followUpDragPreview.BeginSettle(targetTopLeft);
        if (!SystemParameters.ClientAreaAnimation)
        {
            CompleteFollowUpSettle();
        }
    }

    private void CompleteFollowUpSettle()
    {
        var item = _followUpDragSource;
        var settledContainer = _followUpSettleContainer;
        var oldIndex = _followUpSettleOldIndex;
        var newIndex = _followUpSettleNewIndex;
        _followUpSettleContainer = null;
        _followUpIsSettling = false;
        CancelFollowUpDrag(releaseCapture: false);
        if (settledContainer is not null)
        {
            AnimateFollowUpSettlement(settledContainer, oldIndex, newIndex);
        }
        if (item is not null)
        {
            FocusFollowUpMessage(item, focusMessageEditor: false);
        }
    }

    private void AnimateFollowUpSettlement(ListBoxItem container, int oldIndex, int newIndex)
    {
        if (!SystemParameters.ClientAreaAnimation)
        {
            container.BeginAnimation(
                UIElement.OpacityProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            container.Opacity = 1;
            var immediateTransform = EnsureRouteTransform(container);
            immediateTransform.BeginAnimation(
                TranslateTransform.YProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            immediateTransform.Y = 0;
            return;
        }

        var offset = oldIndex < newIndex ? -12d : 12d;
        var transform = EnsureRouteTransform(container);
        transform.Y = offset;
        container.Opacity = 0;
        var easing = new BackEase
        {
            Amplitude = 0.18,
            EasingMode = EasingMode.EaseOut
        };
        var opacityAnimation = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        var placementAnimation = new DoubleAnimation(offset, 0, TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = easing
        };
        placementAnimation.Completed += (_, _) =>
        {
            container.BeginAnimation(
                UIElement.OpacityProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            container.Opacity = 1;
            transform.BeginAnimation(
                TranslateTransform.YProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            transform.Y = 0;
        };
        container.BeginAnimation(
            UIElement.OpacityProperty,
            opacityAnimation,
            HandoffBehavior.SnapshotAndReplace);
        transform.BeginAnimation(
            TranslateTransform.YProperty,
            placementAnimation,
            HandoffBehavior.SnapshotAndReplace);
    }

    private void ReleaseFollowUpDragCapture()
    {
        var captureOwner = _followUpDragCaptureOwner;
        if (captureOwner?.IsMouseCaptured != true)
        {
            return;
        }

        _releasingFollowUpDragCapture = true;
        try
        {
            captureOwner.ReleaseMouseCapture();
        }
        finally
        {
            _releasingFollowUpDragCapture = false;
        }
    }

    private void ResetFollowUpNeighborDisplacement()
    {
        foreach (var container in _followUpDisplacedContainers)
        {
            var transform = EnsureRouteTransform(container);
            transform.BeginAnimation(TranslateTransform.YProperty, null, HandoffBehavior.SnapshotAndReplace);
            transform.Y = 0;
        }
        _followUpDisplacedContainers.Clear();
    }

    private void AnimateFollowUpPlacement(
        FollowUpMessageItem item,
        int oldIndex,
        int newIndex)
    {
        if (!SystemParameters.ClientAreaAnimation)
        {
            return;
        }

        _ = Dispatcher.BeginInvoke(
            DispatcherPriority.Render,
            new Action(() =>
            {
                FollowUpMessageList.UpdateLayout();
                if (FollowUpMessageList.ItemContainerGenerator.ContainerFromItem(item) is not ListBoxItem container)
                {
                    return;
                }

                var offset = oldIndex < newIndex ? -8d : 8d;
                var transform = new System.Windows.Media.TranslateTransform(0, offset);
                container.RenderTransform = transform;
                var animation = new DoubleAnimation(
                    offset,
                    0,
                    TimeSpan.FromMilliseconds(200))
                {
                    EasingFunction = new BackEase
                    {
                        Amplitude = 0.22,
                        EasingMode = EasingMode.EaseOut
                    }
                };
                animation.Completed += (_, _) =>
                {
                    transform.BeginAnimation(System.Windows.Media.TranslateTransform.YProperty, null);
                    container.RenderTransform = System.Windows.Media.Transform.Identity;
                };
                transform.BeginAnimation(System.Windows.Media.TranslateTransform.YProperty, animation);
            }));
    }

    private void CancelFollowUpDrag(bool releaseCapture = true)
    {
        if (_followUpSettleContainer is not null)
        {
            _followUpSettleContainer.BeginAnimation(
                UIElement.OpacityProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            _followUpSettleContainer.Opacity = 1;
            _followUpSettleContainer = null;
        }
        foreach (var message in _viewModel.FollowUpMessages)
        {
            message.IsDragSource = false;
            message.ShowDropBefore = false;
            message.ShowDropAfter = false;
        }
        ResetFollowUpNeighborDisplacement();
        StopFollowUpRendering();

        var captureOwner = _followUpDragCaptureOwner;
        var preview = _followUpDragPreview;
        _followUpDragPreview = null;
        preview?.Close();

        Mouse.OverrideCursor = null;
        _followUpDragCandidate = null;
        _followUpDragSource = null;
        _followUpDragCaptureOwner = null;
        _followUpDragContainer = null;
        _followUpDropInsertionIndex = null;
        _followUpVisualInsertionIndex = null;
        _followUpIsSettling = false;
        _followUpSettleOldIndex = 0;
        _followUpSettleNewIndex = 0;
        if (!releaseCapture || captureOwner?.IsMouseCaptured != true)
        {
            return;
        }

        _releasingFollowUpDragCapture = true;
        try
        {
            captureOwner.ReleaseMouseCapture();
        }
        finally
        {
            _releasingFollowUpDragCapture = false;
        }
    }

    private void DetachViewModelEvents()
    {
        if (!_viewModelEventsSubscribed)
        {
            return;
        }

        _viewModelEventsSubscribed = false;
        Loaded -= OnWindowLoaded;
        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        _viewModel.Tasks.CollectionChanged -= OnConversationCollectionChanged;
        _viewModel.FollowUpMessageFocusRequested -= OnFollowUpMessageFocusRequested;
        _viewModel.FollowUpAttachmentPickerRequested -= OnFollowUpAttachmentPickerRequested;
        _viewModel.UiThemeChanged -= OnUiThemeChanged;
    }

    private void OnUiThemeChanged(string theme)
    {
        if (!IsLoaded || !SystemParameters.ClientAreaAnimation)
        {
            CancelThemeTransition();
            ApplyTheme(theme);
            return;
        }

        StartThemeTransition(theme);
    }

    private void StartThemeTransition(string theme)
    {
        CancelThemeTransition();
        var version = Interlocked.Increment(ref _themeTransitionVersion);
        ThemeTransitionOverlay.Visibility = Visibility.Collapsed;
        ThemeTransitionSnapshot.Source = null;
        UpdateLayout();

        System.Windows.Media.Imaging.BitmapSource? snapshot;
        try
        {
            snapshot = CaptureShellSnapshot();
        }
        catch
        {
            ApplyTheme(theme);
            return;
        }

        ApplyTheme(theme);
        if (snapshot is null ||
            ShellRoot.ActualWidth <= 0 ||
            ShellRoot.ActualHeight <= 0 ||
            version != Volatile.Read(ref _themeTransitionVersion))
        {
            return;
        }

        ThemeTransitionSnapshot.Source = snapshot;
        var origin = ThemeUtilityButton.TranslatePoint(
            new System.Windows.Point(
                ThemeUtilityButton.ActualWidth / 2,
                ThemeUtilityButton.ActualHeight / 2),
            ShellRoot);
        var width = ShellRoot.ActualWidth;
        var height = ShellRoot.ActualHeight;
        var farthestCorner = Math.Max(
            Math.Max(
                Distance(origin, new System.Windows.Point(0, 0)),
                Distance(origin, new System.Windows.Point(width, 0))),
            Math.Max(
                Distance(origin, new System.Windows.Point(0, height)),
                Distance(origin, new System.Windows.Point(width, height)))) + 8;
        var ellipse = new System.Windows.Media.EllipseGeometry(origin, 0, 0);
        var windowRect = new System.Windows.Media.RectangleGeometry(
            new System.Windows.Rect(0, 0, width, height));
        var clip = new System.Windows.Media.CombinedGeometry(
            System.Windows.Media.GeometryCombineMode.Exclude,
            windowRect,
            ellipse);
        _themeTransitionEllipse = ellipse;
        _themeTransitionClip = clip;
        ThemeTransitionOverlay.Clip = clip;
        ThemeTransitionOverlay.Visibility = Visibility.Visible;

        var duration = new Duration(TimeSpan.FromMilliseconds(260));
        var radiusX = new DoubleAnimation(0, farthestCorner, duration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        var radiusY = new DoubleAnimation(0, farthestCorner, duration)
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        radiusX.Completed += (_, _) =>
        {
            if (version == Volatile.Read(ref _themeTransitionVersion))
            {
                CompleteThemeTransition();
            }
        };
        ellipse.BeginAnimation(
            System.Windows.Media.EllipseGeometry.RadiusXProperty,
            radiusX,
            System.Windows.Media.Animation.HandoffBehavior.SnapshotAndReplace);
        ellipse.BeginAnimation(
            System.Windows.Media.EllipseGeometry.RadiusYProperty,
            radiusY,
            System.Windows.Media.Animation.HandoffBehavior.SnapshotAndReplace);
    }

    private static double Distance(System.Windows.Point first, System.Windows.Point second)
    {
        var dx = first.X - second.X;
        var dy = first.Y - second.Y;
        return Math.Sqrt(dx * dx + dy * dy);
    }

    private System.Windows.Media.Imaging.BitmapSource? CaptureShellSnapshot()
    {
        var width = Math.Max(1, (int)Math.Ceiling(ShellRoot.ActualWidth));
        var height = Math.Max(1, (int)Math.Ceiling(ShellRoot.ActualHeight));
        var dpi = VisualTreeHelper.GetDpi(ShellRoot);
        var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(
            Math.Max(1, (int)Math.Ceiling(width * dpi.DpiScaleX)),
            Math.Max(1, (int)Math.Ceiling(height * dpi.DpiScaleY)),
            dpi.PixelsPerInchX,
            dpi.PixelsPerInchY,
            System.Windows.Media.PixelFormats.Pbgra32);
        bitmap.Render(ShellRoot);
        bitmap.Freeze();
        return bitmap;
    }

    private void CancelThemeTransition()
    {
        Interlocked.Increment(ref _themeTransitionVersion);
        if (_themeTransitionEllipse is not null)
        {
            _themeTransitionEllipse.BeginAnimation(
                System.Windows.Media.EllipseGeometry.RadiusXProperty,
                null,
                System.Windows.Media.Animation.HandoffBehavior.SnapshotAndReplace);
            _themeTransitionEllipse.BeginAnimation(
                System.Windows.Media.EllipseGeometry.RadiusYProperty,
                null,
                System.Windows.Media.Animation.HandoffBehavior.SnapshotAndReplace);
        }

        ThemeTransitionOverlay.Clip = null;
        ThemeTransitionOverlay.Visibility = Visibility.Collapsed;
        ThemeTransitionSnapshot.Source = null;
        _themeTransitionEllipse = null;
        _themeTransitionClip = null;
    }

    private void CompleteThemeTransition()
    {
        ThemeTransitionOverlay.Clip = null;
        ThemeTransitionOverlay.Visibility = Visibility.Collapsed;
        ThemeTransitionSnapshot.Source = null;
        _themeTransitionEllipse = null;
        _themeTransitionClip = null;
    }

    private void ApplyTheme(string theme)
    {
        ApplyThemePalette(theme);
        ApplyWindowComposition(theme);
    }

    private static void ApplyThemePalette(string theme)
    {
        var palette = string.Equals(theme, UiThemes.Dark, StringComparison.Ordinal)
            ? DarkThemePalette
            : LightThemePalette;
        var resources = Application.Current.Resources;

        resources.BeginInit();
        try
        {
            foreach (var pair in palette)
            {
                if (System.Windows.Media.ColorConverter.ConvertFromString(pair.Value) is not
                    System.Windows.Media.Color color)
                {
                    throw new InvalidOperationException($"Invalid UI theme color: {pair.Key}.");
                }

                if (resources[pair.Key] is not System.Windows.Media.SolidColorBrush brush)
                {
                    throw new InvalidOperationException($"Missing UI theme brush: {pair.Key}.");
                }

                if (brush.IsFrozen)
                {
                    var newBrush = new System.Windows.Media.SolidColorBrush(color);
                    newBrush.Freeze();
                    resources[pair.Key] = newBrush;
                }
                else
                {
                    brush.Color = color;
                }
            }
        }
        finally
        {
            resources.EndInit();
        }
    }

    private static T? FindVisualDescendant<T>(
        DependencyObject root,
        Predicate<T>? predicate = null)
        where T : DependencyObject
    {
        for (var index = 0; index < System.Windows.Media.VisualTreeHelper.GetChildrenCount(root); index++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(root, index);
            if (child is T match && (predicate is null || predicate(match)))
            {
                return match;
            }

            var descendant = FindVisualDescendant(child, predicate);
            if (descendant is not null)
            {
                return descendant;
            }
        }

        return null;
    }

    private static T? FindVisualAncestor<T>(DependencyObject? child)
        where T : DependencyObject
    {
        var current = child;
        while (current is not null)
        {
            if (current is T match)
            {
                return match;
            }

            current = current is System.Windows.Media.Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(current)
                : LogicalTreeHelper.GetParent(current);
        }

        return null;
    }

    private ItemsControl? FindAttachmentRail(FollowUpMessageItem owner)
    {
        if (FollowUpMessageList.ItemContainerGenerator.ContainerFromItem(owner) is not ListBoxItem messageContainer)
        {
            return null;
        }

        return FindVisualDescendant<ItemsControl>(
            messageContainer,
            rail => string.Equals(
                AutomationProperties.GetAutomationId(rail),
                "FollowUpAttachmentRail",
                StringComparison.Ordinal));
    }

    private void AnimateWindowIn()
    {
        ShellRoot.BeginAnimation(
            OpacityProperty,
            null,
            HandoffBehavior.SnapshotAndReplace);
        ShellRootScale.BeginAnimation(
            ScaleTransform.ScaleXProperty,
            null,
            HandoffBehavior.SnapshotAndReplace);
        ShellRootScale.BeginAnimation(
            ScaleTransform.ScaleYProperty,
            null,
            HandoffBehavior.SnapshotAndReplace);
        if (!SystemParameters.ClientAreaAnimation)
        {
            ShellRoot.Opacity = 1;
            ShellRootScale.ScaleX = 1;
            ShellRootScale.ScaleY = 1;
            return;
        }

        ShellRoot.Opacity = 0;
        ShellRootScale.ScaleX = 0.985;
        ShellRootScale.ScaleY = 0.985;
        var easing = new QuinticEase { EasingMode = EasingMode.EaseOut };
        var opacity = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = easing
        };
        var scale = new DoubleAnimation(0.985, 1, TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = easing
        };
        ShellRoot.BeginAnimation(
            OpacityProperty,
            opacity,
            HandoffBehavior.SnapshotAndReplace);
        ShellRootScale.BeginAnimation(
            ScaleTransform.ScaleXProperty,
            scale,
            HandoffBehavior.SnapshotAndReplace);
        ShellRootScale.BeginAnimation(
            ScaleTransform.ScaleYProperty,
            scale,
            HandoffBehavior.SnapshotAndReplace);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs eventArgs)
    {
        if (eventArgs.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        DragMove();
    }

    private async void Minimize_Click(object sender, RoutedEventArgs eventArgs)
    {
        CancelConversationDrag();
        CancelFollowUpDrag();
        CancelAttachmentDrag();
        CancelThemeTransition();
        if (_windowMotion is null)
        {
            if (_notifyIcon is not null && _viewModel.MinimizeToTray)
            {
                // Hide() without setting WindowState=Minimized, so Window_StateChanged never runs
                // and the halo it would have stopped keeps breathing behind a hidden window. Stop it
                // on the way out; ShowFromTray restarts it.
                ApplyGuardStatusHalo(monitoring: false, motion: false);
                Hide();
                ShowTrayMonitoringNotice();
                return;
            }

            SystemCommands.MinimizeWindow(this);
            return;
        }

        // Both destinations - the taskbar button and the tray icon - are reached by the same shrink,
        // so the tray path no longer short-circuits to Hide(). It used to have no animation at all
        // for the plainest of reasons: nothing was ever asked to move. Minimizing first gives the
        // shrink a state to commit, and Window_StateChanged performs the Hide() and the notice once
        // the surface has landed on the icon.
        var result = await _windowMotion.RequestAsync(
            WindowMotionRequest.Minimize(
                () => SystemCommands.MinimizeWindow(this),
                UpdateCaptionControls,
                SystemParameters.ClientAreaAnimation,
                ResolveShellAnchorBounds()));
        _log?.WriteWindowMotion(WindowMotionKind.Minimize, result);
    }

    private void Maximize_Click(object sender, RoutedEventArgs eventArgs)
    {
        ToggleMaximize();
    }

    private void Close_Click(object sender, RoutedEventArgs eventArgs)
    {
        Close();
    }

    private async void ToggleMaximize()
    {
        CancelConversationDrag();
        CancelFollowUpDrag();
        CancelAttachmentDrag();
        CancelThemeTransition();
        var motion = _windowMotion;
        if (WindowState == WindowState.Maximized)
        {
            if (motion is null)
            {
                SystemCommands.RestoreWindow(this);
                return;
            }

            var result = await motion.RequestAsync(
                WindowMotionRequest.Restore(
                    () => SystemCommands.RestoreWindow(this),
                    UpdateCaptionControls,
                    SystemParameters.ClientAreaAnimation));
            _log?.WriteWindowMotion(WindowMotionKind.Restore, result);
        }
        else
        {
            if (motion is null)
            {
                SystemCommands.MaximizeWindow(this);
                return;
            }

            var result = await motion.RequestAsync(
                WindowMotionRequest.Maximize(
                    () => SystemCommands.MaximizeWindow(this),
                    UpdateCaptionControls,
                    SystemParameters.ClientAreaAnimation));
            _log?.WriteWindowMotion(WindowMotionKind.Maximize, result);
        }
    }

    private void Window_StateChanged(object? sender, EventArgs eventArgs)
    {
        var previous = _lastWindowState;
        _lastWindowState = WindowState;
        UpdateCaptionControls();
        if (WindowState != WindowState.Minimized)
        {
            StartStatusGlow();
            ApplyGuardStatusDot(animate: false);

            // Restoring from the taskbar button or the tray icon is the return leg of the shrink,
            // and the frame has to travel back out of the icon for the two to read as one gesture.
            // Nothing in the platform does that here: WindowStyle="None" strips WS_CAPTION, and
            // without it DWM plays no grow animation, so the window used to appear at full size in
            // a single frame with only its contents fading in behind the cut.
            //
            // Gated on the previous state because maximize and restore come through here as well,
            // and re-animating a window that never left the screen would be a flicker.
            if (previous == WindowState.Minimized)
            {
                BeginExpandFromShell();
            }

            return;
        }

        CancelConversationDrag();
        StopStatusGlow();
        // The halo repeats forever, and this app spends most of its life minimized. Left running it
        // would keep waking the render thread to breathe a dot nobody can see.
        ApplyGuardStatusHalo(monitoring: false, motion: false);
        CancelFollowUpDrag();
        CancelAttachmentDrag();
        if (_notifyIcon is not null &&
            _viewModel.MinimizeToTray)
        {
            Hide();
            ShowTrayMonitoringNotice();
        }
    }

    /// <summary>
    /// Plays the frame growing back out of the tray icon after the shell has restored the window.
    /// </summary>
    /// <remarks>
    /// Timing is the whole trick. A taskbar click restores the window without asking, so by the
    /// time Window_StateChanged runs the state is already committed - but WPF has not composed the
    /// restored frame yet, and the controller cloaks the source synchronously before its first
    /// await. That is what keeps the full-size window from being presented for one refresh ahead
    /// of the animation. Anything that made the setup path asynchronous would put the flash back.
    /// </remarks>
    private async void BeginExpandFromShell()
    {
        var motion = _windowMotion;
        var anchor = ResolveShellAnchorBounds();
        if (motion is null || anchor is null || motion.IsTransitioning)
        {
            AnimateWindowIn();
            return;
        }

        var result = await motion.RequestAsync(
            WindowMotionRequest.Expand(
                anchor.Value,
                () =>
                {
                    // Usually a no-op: the shell restored the window before this ran. It is still
                    // issued because ShowFromTray and the tray menu reach the same animation while
                    // the window is genuinely iconic, and the commit is what un-minimizes it there.
                    if (WindowState == WindowState.Minimized)
                    {
                        WindowState = WindowState.Normal;
                    }
                },
                UpdateCaptionControls,
                SystemParameters.ClientAreaAnimation));
        _log?.WriteWindowMotion(WindowMotionKind.Expand, result);
        if (!result.WasAnimated)
        {
            // The surface never played, so the window is sitting there fully drawn having moved not
            // at all. The content fade is the only entrance left to give it.
            AnimateWindowIn();
            return;
        }

        // The source is disabled and cloaked for the length of the animation, so an activation
        // issued before or during it can be dropped on the floor. Re-issue once it is back.
        if (IsVisible && WindowState != WindowState.Minimized)
        {
            Activate();
        }
    }

    private void UpdateCaptionControls()
    {
        var isMaximized = WindowState == WindowState.Maximized;
        MaximizeGlyph.Text = isMaximized ? "\uE923" : "\uE922";
        AutomationProperties.SetName(
            MaximizeButton,
            _localization[isMaximized ? "Window.Restore" : "Window.Maximize"]);
    }

    private void ShowTrayMonitoringNotice()
    {
        _notifyIcon?.ShowBalloonTip(
            1800,
            _localization["App.Title"],
            _localization["Tray.MonitoringMessage"],
            Forms.ToolTipIcon.Info);
    }

    private void Window_Deactivated(object? sender, EventArgs eventArgs)
    {
        StopInertialScroll();
        StopStatusGlow();
        CancelConversationContentTransition();
        if (_conversationDragCandidate is not null || _conversationDragSource is not null)
        {
            CancelConversationDrag();
        }
        if (_followUpDragCandidate is not null || _followUpDragSource is not null)
        {
            CancelFollowUpDrag();
        }
        if (_attachmentDragCandidate is not null || _attachmentDragSource is not null)
        {
            CancelAttachmentDrag();
        }
        if (_windowMotion?.IsTransitioning != true)
        {
            _windowMotion?.Cancel();
        }
    }

    private async void Window_Closing(object? sender, CancelEventArgs eventArgs)
    {
        StopInertialScroll();
        StopStatusGlow();
        CancelConversationContentTransition();
        if (_allowClose)
        {
            CancelAttachmentImport();
            CancelAttachmentThumbnailLoad();
            _windowMotion?.Dispose();
            _windowMotion = null;
            return;
        }

        eventArgs.Cancel = true;
        if ((Application.Current as App)?.ExitRequested == true)
        {
            return;
        }

        if (_viewModel.MinimizeToTray)
        {
            CancelAttachmentDrag();
            CancelAttachmentImport();
            CancelAttachmentThumbnailLoad();
            // Same as the minimize button: this Hide() leaves WindowState at Normal, so nothing else
            // stops the halo.
            ApplyGuardStatusHalo(monitoring: false, motion: false);
            Hide();
            return;
        }

        await RequestExitAsync();
    }

    private async Task RequestExitAsync()
    {
        if (!CanRunTrayCallback())
        {
            return;
        }

        CancelConversationDrag();
        StopInertialScroll();
        CancelFollowUpDrag();
        CancelAttachmentDrag();
        CancelAttachmentImport();
        CancelAttachmentThumbnailLoad();
        if (!ConfirmDiscardUnsavedFollowUps())
        {
            return;
        }

        if (Application.Current is App app)
        {
            await app.RequestExitAsync();
        }
    }

    private bool ConfirmDiscardUnsavedFollowUps()
    {
        if (!_viewModel.HasUnsavedFollowUpChanges)
        {
            return true;
        }

        if (!IsVisible)
        {
            ShowFromTray();
        }

        var result = MessageBox.Show(
            this,
            _localization["FollowUp.UnsavedCloseMessage"],
            _localization["FollowUp.UnsavedCloseTitle"],
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (result == MessageBoxResult.Yes)
        {
            _viewModel.DiscardFollowUpChanges();
            return true;
        }

        if (_viewModel.SelectedTask is { } selectedTask &&
            _viewModel.OpenFollowUpEditorCommand.CanExecute(selectedTask))
        {
            _viewModel.OpenFollowUpEditorCommand.Execute(selectedTask);
        }

        Activate();
        return false;
    }

    private bool CanRunTrayCallback() =>
        Volatile.Read(ref _deactivated) == 0 &&
        !Dispatcher.HasShutdownStarted &&
        !Dispatcher.HasShutdownFinished;

    private void CleanupTrayResources(ref Exception? failure)
    {
        if (_languageChangedSubscribed)
        {
            _languageChangedSubscribed = false;
            TryCleanup(
                () => _localization.LanguageChanged -= OnLanguageChanged,
                ref failure);
        }

        var notifyIcon = _notifyIcon;
        _notifyIcon = null;
        var trayIcon = _trayIcon;
        _trayIcon = null;
        if (notifyIcon is not null)
        {
            TryCleanup(
                () => notifyIcon.DoubleClick -= OnNotifyIconDoubleClick,
                ref failure);
            TryCleanup(() => notifyIcon.Visible = false, ref failure);
            Forms.ContextMenuStrip? menu = null;
            TryCleanup(() =>
            {
                menu = notifyIcon.ContextMenuStrip;
                notifyIcon.ContextMenuStrip = null;
            }, ref failure);
            TryCleanup(() => menu?.Dispose(), ref failure);
            TryCleanup(notifyIcon.Dispose, ref failure);
        }

        TryCleanup(() => trayIcon?.Dispose(), ref failure);
    }

    private static void TryCleanup(Action cleanup, ref Exception? failure)
    {
        try
        {
            cleanup();
        }
        catch (Exception cleanupFailure)
        {
            if (failure is null)
            {
                failure = cleanupFailure;
                return;
            }

            const string key = "MainWindowCleanupFailures";
            failure.Data[key] = failure.Data[key] is AggregateException aggregate
                ? new AggregateException(aggregate, cleanupFailure)
                : new AggregateException(cleanupFailure);
        }
    }

    private sealed class FollowUpDragPreviewWindow : Window
    {
        private const double ShadowInset = 28;

        private readonly Border _surface;
        private readonly ScaleTransform _surfaceScale;
        private readonly DropShadowEffect _surfaceShadow;
        private readonly double _dpiScaleX;
        private readonly double _dpiScaleY;
        private readonly bool _animationsEnabled;
        private IntPtr _handle;
        private double _left;
        private double _top;
        private double _targetLeft;
        private double _targetTop;
        private double _velocityLeft;
        private double _velocityTop;
        private double _settleElapsedSeconds;
        private bool _initialized;
        private bool _settling;

        public FollowUpDragPreviewWindow(
            Window owner,
            FollowUpMessageItem item,
            string triggerText,
            System.Windows.Media.FontFamily fontFamily,
            double previewWidth,
            double previewHeight,
            double dpiScaleX,
            double dpiScaleY,
            bool animationsEnabled)
            : this(
                owner,
                CreatePreviewSurface(item, triggerText, fontFamily, previewWidth, previewHeight),
                previewWidth,
                previewHeight,
                dpiScaleX,
                dpiScaleY,
                animationsEnabled)
        {
        }

        public FollowUpDragPreviewWindow(
            Window owner,
            GuardianTaskItem item,
            System.Windows.Media.FontFamily fontFamily,
            double previewWidth,
            double previewHeight,
            double dpiScaleX,
            double dpiScaleY,
            bool animationsEnabled)
            : this(
                owner,
                CreateConversationPreviewSurface(item, fontFamily, previewWidth, previewHeight),
                previewWidth,
                previewHeight,
                dpiScaleX,
                dpiScaleY,
                animationsEnabled)
        {
        }

        public FollowUpDragPreviewWindow(
            Window owner,
            AttachmentItemViewModel item,
            System.Windows.Media.FontFamily fontFamily,
            double previewWidth,
            double previewHeight,
            double dpiScaleX,
            double dpiScaleY,
            bool animationsEnabled)
            : this(
                owner,
                CreateAttachmentPreviewSurface(item, fontFamily, previewWidth, previewHeight),
                previewWidth,
                previewHeight,
                dpiScaleX,
                dpiScaleY,
                animationsEnabled)
        {
        }

        private FollowUpDragPreviewWindow(
            Window owner,
            Border surface,
            double previewWidth,
            double previewHeight,
            double dpiScaleX,
            double dpiScaleY,
            bool animationsEnabled)
        {
            Owner = owner;
            _dpiScaleX = dpiScaleX;
            _dpiScaleY = dpiScaleY;
            _animationsEnabled = animationsEnabled;
            WindowStyle = WindowStyle.None;
            ResizeMode = ResizeMode.NoResize;
            AllowsTransparency = true;
            Background = System.Windows.Media.Brushes.Transparent;
            ShowInTaskbar = false;
            ShowActivated = false;
            Focusable = false;
            IsHitTestVisible = false;
            Topmost = false;
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = -32000;
            Top = -32000;
            Width = previewWidth + ShadowInset * 2;
            Height = previewHeight + ShadowInset * 2;
            UseLayoutRounding = true;
            SnapsToDevicePixels = true;

            _surfaceShadow = new DropShadowEffect
            {
                BlurRadius = 24,
                ShadowDepth = 9,
                Opacity = 0.34,
                Direction = 270,
                Color = System.Windows.Media.Color.FromRgb(0x00, 0x00, 0x00)
            };
            _surfaceScale = new ScaleTransform(animationsEnabled ? 0.988 : 1, animationsEnabled ? 0.988 : 1);
            _surface = surface;
            _surface.Margin = new Thickness(ShadowInset);
            _surface.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);
            _surface.RenderTransform = _surfaceScale;
            _surface.Effect = _surfaceShadow;
            Content = new Grid
            {
                Background = System.Windows.Media.Brushes.Transparent,
                Children = { _surface }
            };

            SourceInitialized += (_, _) =>
            {
                _handle = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                var extendedStyle = GetWindowLong(_handle, GwlExStyle);
                _ = SetWindowLong(
                    _handle,
                    GwlExStyle,
                    extendedStyle | WsExNoActivate | WsExTransparent | WsExToolWindow);
                if (_initialized)
                {
                    ApplyPhysicalPosition();
                }
            };

            if (animationsEnabled)
            {
                var lift = new DoubleAnimation(0.988, 1.01, TimeSpan.FromMilliseconds(165))
                {
                    EasingFunction = new BackEase
                    {
                        Amplitude = 0.16,
                        EasingMode = EasingMode.EaseOut
                    }
                };
                _surfaceScale.BeginAnimation(
                    ScaleTransform.ScaleXProperty,
                    lift,
                    HandoffBehavior.SnapshotAndReplace);
                _surfaceScale.BeginAnimation(
                    ScaleTransform.ScaleYProperty,
                    lift,
                    HandoffBehavior.SnapshotAndReplace);
            }
        }

        public bool IsSettled =>
            _initialized &&
            Math.Abs(_targetLeft - _left) < 0.8 &&
            Math.Abs(_targetTop - _top) < 0.8 &&
            Math.Abs(_velocityLeft) < 6 &&
            Math.Abs(_velocityTop) < 6 &&
            (!_animationsEnabled || !_settling || _settleElapsedSeconds >= 0.14);

        public void UpdatePointer(
            System.Windows.Point cursorScreenPixels,
            System.Windows.Vector pointerOffset)
        {
            if (_settling)
            {
                return;
            }

            SetTargetSurfaceTopLeft(new System.Windows.Point(
                cursorScreenPixels.X - pointerOffset.X * _dpiScaleX,
                cursorScreenPixels.Y - pointerOffset.Y * _dpiScaleY - 6 * _dpiScaleY));
        }

        public void BeginSettle(System.Windows.Point targetSurfaceTopLeftPixels)
        {
            _settling = true;
            _settleElapsedSeconds = 0;
            SetTargetSurfaceTopLeft(targetSurfaceTopLeftPixels);
            if (!_animationsEnabled)
            {
                _left = _targetLeft;
                _top = _targetTop;
                _velocityLeft = 0;
                _velocityTop = 0;
                _surfaceScale.ScaleX = 1;
                _surfaceScale.ScaleY = 1;
                _surfaceShadow.BlurRadius = 12;
                _surfaceShadow.ShadowDepth = 3;
                _surfaceShadow.Opacity = 0.16;
                ApplyPhysicalPosition();
                return;
            }

            var currentScale = _surfaceScale.ScaleX;
            _surfaceScale.BeginAnimation(
                ScaleTransform.ScaleXProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            _surfaceScale.BeginAnimation(
                ScaleTransform.ScaleYProperty,
                null,
                HandoffBehavior.SnapshotAndReplace);
            _surfaceScale.ScaleX = currentScale;
            _surfaceScale.ScaleY = currentScale;
            var landingEase = new CubicEase { EasingMode = EasingMode.EaseOut };
            _surfaceScale.BeginAnimation(
                ScaleTransform.ScaleXProperty,
                new DoubleAnimation(currentScale, 1, TimeSpan.FromMilliseconds(150))
                {
                    EasingFunction = landingEase
                },
                HandoffBehavior.SnapshotAndReplace);
            _surfaceScale.BeginAnimation(
                ScaleTransform.ScaleYProperty,
                new DoubleAnimation(currentScale, 1, TimeSpan.FromMilliseconds(150))
                {
                    EasingFunction = landingEase
                },
                HandoffBehavior.SnapshotAndReplace);
            _surfaceShadow.BeginAnimation(
                DropShadowEffect.BlurRadiusProperty,
                new DoubleAnimation(_surfaceShadow.BlurRadius, 12, TimeSpan.FromMilliseconds(150))
                {
                    EasingFunction = landingEase
                },
                HandoffBehavior.SnapshotAndReplace);
            _surfaceShadow.BeginAnimation(
                DropShadowEffect.ShadowDepthProperty,
                new DoubleAnimation(_surfaceShadow.ShadowDepth, 3, TimeSpan.FromMilliseconds(150))
                {
                    EasingFunction = landingEase
                },
                HandoffBehavior.SnapshotAndReplace);
            _surfaceShadow.BeginAnimation(
                DropShadowEffect.OpacityProperty,
                new DoubleAnimation(_surfaceShadow.Opacity, 0.16, TimeSpan.FromMilliseconds(150))
                {
                    EasingFunction = landingEase
                },
                HandoffBehavior.SnapshotAndReplace);
        }

        public void Advance(double elapsedSeconds)
        {
            if (!_initialized)
            {
                return;
            }
            if (_settling)
            {
                _settleElapsedSeconds += elapsedSeconds;
            }
            if (!_animationsEnabled)
            {
                _left = _targetLeft;
                _top = _targetTop;
                _velocityLeft = 0;
                _velocityTop = 0;
                ApplyPhysicalPosition();
                return;
            }

            const double stiffness = 250;
            const double damping = 28;
            _velocityLeft += (_targetLeft - _left) * stiffness * elapsedSeconds;
            _velocityTop += (_targetTop - _top) * stiffness * elapsedSeconds;
            var dampingFactor = Math.Exp(-damping * elapsedSeconds);
            _velocityLeft *= dampingFactor;
            _velocityTop *= dampingFactor;
            _left += _velocityLeft * elapsedSeconds;
            _top += _velocityTop * elapsedSeconds;
            if (Math.Abs(_targetLeft - _left) < 0.08 && Math.Abs(_velocityLeft) < 0.8)
            {
                _left = _targetLeft;
                _velocityLeft = 0;
            }
            if (Math.Abs(_targetTop - _top) < 0.08 && Math.Abs(_velocityTop) < 0.8)
            {
                _top = _targetTop;
                _velocityTop = 0;
            }
            ApplyPhysicalPosition();
        }

        private void SetTargetSurfaceTopLeft(System.Windows.Point surfaceTopLeftPixels)
        {
            _targetLeft = surfaceTopLeftPixels.X - ShadowInset * _dpiScaleX;
            _targetTop = surfaceTopLeftPixels.Y - ShadowInset * _dpiScaleY;
            if (_initialized)
            {
                return;
            }

            _left = _targetLeft;
            _top = _targetTop;
            _initialized = true;
            ApplyPhysicalPosition();
        }

        private void ApplyPhysicalPosition()
        {
            if (_handle == IntPtr.Zero)
            {
                return;
            }

            _ = SetWindowPos(
                _handle,
                IntPtr.Zero,
                (int)Math.Round(_left),
                (int)Math.Round(_top),
                0,
                0,
                SwpNoSize | SwpNoZOrder | SwpNoActivate | SwpNoOwnerZOrder);
        }

        private static Border CreatePreviewSurface(
            FollowUpMessageItem item,
            string triggerText,
            System.Windows.Media.FontFamily fontFamily,
            double previewWidth,
            double previewHeight)
        {
            var content = new Grid();
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(48) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) });

            var gripBox = new Border
            {
                Width = 34,
                Height = 34,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6)
            };
            gripBox.SetResourceReference(Border.BackgroundProperty, "PrimarySoftBrush");
            gripBox.SetResourceReference(Border.BorderBrushProperty, "PrimaryBrush");
            var dots = new Grid { Width = 12, Height = 18 };
            dots.ColumnDefinitions.Add(new ColumnDefinition());
            dots.ColumnDefinitions.Add(new ColumnDefinition());
            dots.RowDefinitions.Add(new RowDefinition());
            dots.RowDefinitions.Add(new RowDefinition());
            dots.RowDefinitions.Add(new RowDefinition());
            for (var row = 0; row < 3; row++)
            {
                for (var column = 0; column < 2; column++)
                {
                    var dot = new Border
                    {
                        Width = 3,
                        Height = 3,
                        CornerRadius = new CornerRadius(1.5)
                    };
                    dot.SetResourceReference(Border.BackgroundProperty, "InkMutedBrush");
                    Grid.SetRow(dot, row);
                    Grid.SetColumn(dot, column);
                    dots.Children.Add(dot);
                }
            }
            gripBox.Child = dots;
            content.Children.Add(gripBox);

            var text = new StackPanel
            {
                Margin = new Thickness(12, 0, 12, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(text, 1);
            var message = new TextBlock
            {
                Text = item.Message,
                FontFamily = fontFamily,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                MaxHeight = 46,
                TextWrapping = TextWrapping.Wrap,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            message.SetResourceReference(TextBlock.ForegroundProperty, "InkBrush");
            var trigger = new TextBlock
            {
                Text = triggerText,
                Margin = new Thickness(0, 7, 0, 0),
                FontFamily = fontFamily,
                FontSize = 10,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            trigger.SetResourceReference(TextBlock.ForegroundProperty, "InkMutedBrush");
            text.Children.Add(message);
            text.Children.Add(trigger);
            content.Children.Add(text);

            var state = new Border
            {
                Width = 9,
                Height = 9,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                CornerRadius = new CornerRadius(4.5)
            };
            state.SetResourceReference(
                Border.BackgroundProperty,
                item.IsEnabled ? "GreenBrush" : "DisabledInkBrush");
            Grid.SetColumn(state, 2);
            content.Children.Add(state);

            var surface = new Border
            {
                Width = previewWidth,
                Height = previewHeight,
                Padding = new Thickness(10),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Child = content,
                SnapsToDevicePixels = true
            };
            surface.SetResourceReference(Border.BackgroundProperty, "GlassSurfaceStrongBrush");
            surface.SetResourceReference(Border.BorderBrushProperty, "PrimaryBrush");
            return surface;
        }

        private static Border CreateAttachmentPreviewSurface(
            AttachmentItemViewModel item,
            System.Windows.Media.FontFamily fontFamily,
            double previewWidth,
            double previewHeight)
        {
            var content = new Grid();
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(34) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var gripBox = new Border
            {
                Width = 24,
                Height = 34,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center,
                CornerRadius = new CornerRadius(8)
            };
            gripBox.SetResourceReference(Border.BackgroundProperty, "PrimarySoftBrush");
            var dots = new System.Windows.Controls.Primitives.UniformGrid
            {
                Width = 9,
                Height = 16,
                Rows = 3,
                Columns = 2
            };
            for (var index = 0; index < 6; index++)
            {
                var dot = new System.Windows.Shapes.Ellipse { Width = 2.5, Height = 2.5, Margin = new Thickness(1) };
                dot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, "InkMutedBrush");
                dots.Children.Add(dot);
            }
            gripBox.Child = dots;
            content.Children.Add(gripBox);

            var typeBox = new Border
            {
                Width = 30,
                Height = 30,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center,
                CornerRadius = new CornerRadius(6)
            };
            typeBox.SetResourceReference(Border.BackgroundProperty, "SurfaceSubtleBrush");
            var typeGlyph = new TextBlock
            {
                Text = item.IsImage ? "\uEB9F" : "\uE8A5",
                FontFamily = TryFindIconFont(),
                FontSize = 14,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            typeGlyph.SetResourceReference(TextBlock.ForegroundProperty, "PrimaryBrush");
            typeBox.Child = typeGlyph;
            Grid.SetColumn(typeBox, 1);
            content.Children.Add(typeBox);

            var text = new StackPanel { Margin = new Thickness(6, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center };
            var name = new TextBlock
            {
                Text = item.OriginalFileName,
                FontFamily = fontFamily,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            name.SetResourceReference(TextBlock.ForegroundProperty, "InkBrush");
            var size = new TextBlock
            {
                Text = item.SizeText,
                Margin = new Thickness(0, 2, 0, 0),
                FontFamily = fontFamily,
                FontSize = 10
            };
            size.SetResourceReference(TextBlock.ForegroundProperty, "InkMutedBrush");
            text.Children.Add(name);
            text.Children.Add(size);
            Grid.SetColumn(text, 2);
            content.Children.Add(text);

            var surface = new Border
            {
                Width = previewWidth,
                Height = previewHeight,
                Padding = new Thickness(5),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Child = content,
                SnapsToDevicePixels = true
            };
            surface.SetResourceReference(Border.BackgroundProperty, "GlassSurfaceStrongBrush");
            surface.SetResourceReference(Border.BorderBrushProperty, "PrimaryBrush");
            return surface;
        }

        private static System.Windows.Media.FontFamily TryFindIconFont() =>
            Application.Current.TryFindResource("IconFont") as System.Windows.Media.FontFamily ??
            new System.Windows.Media.FontFamily("Segoe MDL2 Assets");

        private static Border CreateConversationPreviewSurface(
            GuardianTaskItem item,
            System.Windows.Media.FontFamily fontFamily,
            double previewWidth,
            double previewHeight)
        {
            var content = new Grid();
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(38) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            content.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(42) });

            var gripBox = new Border
            {
                Width = 28,
                Height = 38,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(9)
            };
            gripBox.SetResourceReference(Border.BackgroundProperty, "PrimarySoftBrush");
            gripBox.SetResourceReference(Border.BorderBrushProperty, "PrimaryBrush");
            var dots = new Grid { Width = 9, Height = 16 };
            dots.ColumnDefinitions.Add(new ColumnDefinition());
            dots.ColumnDefinitions.Add(new ColumnDefinition());
            dots.RowDefinitions.Add(new RowDefinition());
            dots.RowDefinitions.Add(new RowDefinition());
            dots.RowDefinitions.Add(new RowDefinition());
            for (var row = 0; row < 3; row++)
            {
                for (var column = 0; column < 2; column++)
                {
                    var dot = new Border
                    {
                        Width = 2.5,
                        Height = 2.5,
                        CornerRadius = new CornerRadius(1.25)
                    };
                    dot.SetResourceReference(Border.BackgroundProperty, "InkBrush");
                    Grid.SetRow(dot, row);
                    Grid.SetColumn(dot, column);
                    dots.Children.Add(dot);
                }
            }
            gripBox.Child = dots;
            content.Children.Add(gripBox);

            var stateSpine = new Border
            {
                Width = 3,
                Margin = new Thickness(0, 14, 0, 14),
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                CornerRadius = new CornerRadius(1.5)
            };
            stateSpine.SetResourceReference(
                Border.BackgroundProperty,
                item.Health switch
                {
                    TaskHealth.Healthy => "GreenBrush",
                    TaskHealth.Processing or TaskHealth.Recovering => "BlueBrush",
                    TaskHealth.WaitingForIdle or TaskHealth.WaitingForDesktop => "OrangeBrush",
                    TaskHealth.CoolingDown => "YellowBrush",
                    TaskHealth.NeedsAttention or TaskHealth.ManualReview => "DangerBrush",
                    _ => "InkSubtleBrush"
                });
            Grid.SetColumn(stateSpine, 1);
            content.Children.Add(stateSpine);

            var text = new StackPanel
            {
                Margin = new Thickness(10, 10, 4, 10),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(text, 2);
            var titleRow = new Grid();
            titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var title = new TextBlock
            {
                Text = item.Name,
                FontFamily = fontFamily,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            title.SetResourceReference(TextBlock.ForegroundProperty, "InkBrush");
            titleRow.Children.Add(title);
            var updated = new TextBlock
            {
                Text = item.UpdatedText,
                Margin = new Thickness(8, 0, 0, 0),
                FontFamily = fontFamily,
                FontSize = 10
            };
            updated.SetResourceReference(TextBlock.ForegroundProperty, "InkSubtleBrush");
            Grid.SetColumn(updated, 1);
            titleRow.Children.Add(updated);
            text.Children.Add(titleRow);

            var status = new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(item.FollowUpQueueStatusText)
                    ? item.HealthText
                    : $"{item.HealthText}  /  {item.FollowUpQueueStatusText}",
                Margin = new Thickness(0, 4, 0, 0),
                FontFamily = fontFamily,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            status.SetResourceReference(TextBlock.ForegroundProperty, "InkMutedBrush");
            text.Children.Add(status);
            var preview = new TextBlock
            {
                Text = item.Preview,
                Margin = new Thickness(0, 4, 0, 0),
                FontFamily = fontFamily,
                FontSize = 11,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            preview.SetResourceReference(TextBlock.ForegroundProperty, "InkMutedBrush");
            text.Children.Add(preview);
            content.Children.Add(text);

            var queueSurface = new Border
            {
                Width = 30,
                Height = 30,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10)
            };
            queueSurface.SetResourceReference(Border.BackgroundProperty, "PrimarySoftBrush");
            queueSurface.SetResourceReference(Border.BorderBrushProperty, "PrimaryBrush");
            var queueText = new TextBlock
            {
                Text = item.FollowUpMessageCount > 0
                    ? item.FollowUpMessageCount.ToString(CultureInfo.InvariantCulture)
                    : "--",
                HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                FontFamily = fontFamily,
                FontSize = 10,
                FontWeight = FontWeights.Bold
            };
            queueText.SetResourceReference(TextBlock.ForegroundProperty, "InkBrush");
            queueSurface.Child = queueText;
            Grid.SetColumn(queueSurface, 3);
            content.Children.Add(queueSurface);

            var surface = new Border
            {
                Width = previewWidth,
                Height = previewHeight,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Child = content,
                SnapsToDevicePixels = true
            };
            surface.SetResourceReference(Border.BackgroundProperty, "ConversationSurfaceBrush");
            surface.SetResourceReference(Border.BorderBrushProperty, "PrimaryBrush");
            return surface;
        }
    }

    private static Icon CreateTrayIcon()
    {
        using var bitmap = new Bitmap(32, 32);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);
            using var background = new SolidBrush(Color.FromArgb(23, 32, 31));
            using var accent = new Pen(Color.FromArgb(95, 226, 172), 2.5f)
            {
                LineJoin = System.Drawing.Drawing2D.LineJoin.Round
            };
            graphics.FillRoundedRectangle(background, new RectangleF(2, 2, 28, 28), 8);
            var shield = new[]
            {
                new PointF(16, 7),
                new PointF(23, 10),
                new PointF(22, 19),
                new PointF(16, 25),
                new PointF(10, 19),
                new PointF(9, 10)
            };
            graphics.DrawPolygon(accent, shield);
            graphics.DrawLines(accent, [new PointF(12.5f, 16), new PointF(15, 18.5f), new PointF(20, 13)]);
        }

        var handle = bitmap.GetHicon();
        try
        {
            return (Icon)System.Drawing.Icon.FromHandle(handle).Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DwmMargins
    {
        public DwmMargins(int leftWidth, int rightWidth, int topHeight, int bottomHeight)
        {
            LeftWidth = leftWidth;
            RightWidth = rightWidth;
            TopHeight = topHeight;
            BottomHeight = bottomHeight;
        }

        public int LeftWidth { get; }

        public int RightWidth { get; }

        public int TopHeight { get; }

        public int BottomHeight { get; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out NativePoint point);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetWindowLong(IntPtr window, int index);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int SetWindowLong(IntPtr window, int index, int value);

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

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmExtendFrameIntoClientArea(IntPtr hwnd, ref DwmMargins margins);
}

internal static class GraphicsExtensions
{
    public static void FillRoundedRectangle(
        this Graphics graphics,
        System.Drawing.Brush brush,
        RectangleF rectangle,
        float radius)
    {
        using var path = new System.Drawing.Drawing2D.GraphicsPath();
        var diameter = radius * 2;
        path.AddArc(rectangle.Left, rectangle.Top, diameter, diameter, 180, 90);
        path.AddArc(rectangle.Right - diameter, rectangle.Top, diameter, diameter, 270, 90);
        path.AddArc(rectangle.Right - diameter, rectangle.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(rectangle.Left, rectangle.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        graphics.FillPath(brush, path);
    }
}
