using CodexGuardian.Infrastructure;
using CodexGuardian.Services;

namespace CodexGuardian.ViewModels;

/// <summary>
/// One row on the keep-alive page.
/// </summary>
/// <remarks>
/// <see cref="KeepAliveThreadRuntime"/> is an immutable engine snapshot, so it cannot carry the user's
/// choice back. This wrapper owns the writable switch and hands it straight to the engine, which keeps
/// the row a plain two-way binding instead of a converter plus a code-behind handler.
///
/// The switch is two-state. It was briefly a three-way Auto / On / Off, from a design where the global
/// switch decided the fate of every conversation and a row could defer to it. The global switch now
/// sends into one nominated conversation instead, so there is nothing for a row to defer to: either the
/// user holds this conversation or they do not.
/// </remarks>
public sealed class KeepAliveThreadViewModel : ObservableObject
{
    private readonly Action<string, bool> _applyHold;
    private readonly Action<string> _nominateSentinel;
    private string _name;
    private bool _isHeldByUser;
    private bool _isHeld;
    private bool _isSentinelDestination;
    private bool _isSentinelWaitingForSignal;
    private bool _isWaitingForRecovery;
    private string _lastSentText = string.Empty;

    public KeepAliveThreadViewModel(
        KeepAliveThreadRuntime runtime,
        Action<string, bool> applyHold,
        Action<string> nominateSentinel,
        string lastSentText)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        _applyHold = applyHold ?? throw new ArgumentNullException(nameof(applyHold));
        _nominateSentinel = nominateSentinel ?? throw new ArgumentNullException(nameof(nominateSentinel));
        ThreadId = runtime.ThreadId;
        NominateSentinelCommand = new RelayCommand(() => _nominateSentinel(ThreadId));
        _name = runtime.Name;
        _isHeldByUser = runtime.IsHeldByUser;
        _isHeld = runtime.IsHeld;
        _isSentinelDestination = runtime.IsSentinelDestination;
        _isSentinelWaitingForSignal = runtime.IsSentinelWaitingForSignal;
        _isWaitingForRecovery = runtime.IsWaitingForRecovery;
        _lastSentText = lastSentText;
    }

    public string ThreadId { get; }

    /// <summary>Makes this conversation the sentinel's destination, or clears it if it already is.</summary>
    public RelayCommand NominateSentinelCommand { get; }

    /// <summary>
    /// Settable because titles arrive late: a conversation is often cached before its authoritative
    /// thread lands, so the row is created untitled and named a moment later.
    /// </summary>
    public string Name
    {
        get => _name;
        private set => SetProperty(ref _name, value);
    }

    /// <summary>
    /// The row's own switch. Turning it on starts holding this conversation on the next pass.
    /// </summary>
    public bool IsHeldByUser
    {
        get => _isHeldByUser;
        set
        {
            if (_isHeldByUser == value)
            {
                return;
            }

            _isHeldByUser = value;
            OnPropertyChanged();
            _applyHold(ThreadId, value);
        }
    }

    /// <summary>True when this conversation is being held, whichever switch is responsible.</summary>
    public bool IsHeld
    {
        get => _isHeld;
        private set => SetProperty(ref _isHeld, value);
    }

    /// <summary>True when the global sentinel sends into this conversation.</summary>
    public bool IsSentinelDestination
    {
        get => _isSentinelDestination;
        private set => SetProperty(ref _isSentinelDestination, value);
    }

    /// <summary>
    /// True when this row is the sentinel's destination but no normal reply has been seen yet, so
    /// nothing is being sent into it.
    /// </summary>
    public bool IsSentinelWaitingForSignal
    {
        get => _isSentinelWaitingForSignal;
        private set => SetProperty(ref _isSentinelWaitingForSignal, value);
    }

    public bool IsWaitingForRecovery
    {
        get => _isWaitingForRecovery;
        private set => SetProperty(ref _isWaitingForRecovery, value);
    }

    public string LastSentText
    {
        get => _lastSentText;
        private set
        {
            if (SetProperty(ref _lastSentText, value))
            {
                OnPropertyChanged(nameof(HasLastSent));
            }
        }
    }

    /// <summary>Collapses the second line until there is a send to report.</summary>
    public bool HasLastSent => _lastSentText.Length > 0;

    /// <summary>
    /// Applies a fresh engine snapshot in place.
    /// </summary>
    /// <remarks>
    /// Updating rather than rebuilding the collection matters here: the row hosts a focusable switch, and
    /// replacing the item under the pointer would drop the click the user is in the middle of.
    /// </remarks>
    public void Update(KeepAliveThreadRuntime runtime, string lastSentText)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        Name = runtime.Name;
        IsHeld = runtime.IsHeld;
        IsSentinelDestination = runtime.IsSentinelDestination;
        IsSentinelWaitingForSignal = runtime.IsSentinelWaitingForSignal;
        IsWaitingForRecovery = runtime.IsWaitingForRecovery;
        LastSentText = lastSentText;
        if (runtime.IsHeldByUser == _isHeldByUser)
        {
            return;
        }

        _isHeldByUser = runtime.IsHeldByUser;
        OnPropertyChanged(nameof(IsHeldByUser));
    }
}
