using CodexGuardian.Infrastructure;
using CodexGuardian.Models;
using System.Globalization;
using System.Windows.Media;

namespace CodexGuardian.ViewModels;

public enum AttachmentThumbnailState
{
    NotRequested,
    Loading,
    Ready,
    Failed
}

public enum AttachmentValidationState
{
    Unchecked,
    Valid,
    Invalid
}

public sealed class AttachmentItemViewModel : ObservableObject
{
    private int _order;
    private ImageSource? _thumbnail;
    private AttachmentThumbnailState _thumbnailState;
    private AttachmentValidationState _validationState;
    private string _validationMessage = string.Empty;
    private bool _isDragSource;
    private bool _showDropBefore;
    private bool _showDropAfter;

    public AttachmentItemViewModel(PresetAttachmentReference reference)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (!AttachmentIdentity.IsCanonicalReferenceId(reference.Id) ||
            !AttachmentIdentity.IsCanonicalContentId(reference.ContentId) ||
            string.IsNullOrWhiteSpace(reference.OriginalFileName) ||
            string.IsNullOrWhiteSpace(reference.DetectedType) ||
            reference.OwnerInputKind is not ("local_file" or "local_image") ||
            reference.ByteLength <= 0 ||
            reference.Order < 0)
        {
            throw new ArgumentException(
                "The attachment reference is not a valid managed draft item.",
                nameof(reference));
        }

        Id = reference.Id;
        ContentId = reference.ContentId;
        OriginalFileName = reference.OriginalFileName;
        DetectedType = reference.DetectedType;
        OwnerInputKind = reference.OwnerInputKind;
        ByteLength = reference.ByteLength;
        _order = reference.Order;
    }

    public string Id { get; }

    public string ContentId { get; }

    public string OriginalFileName { get; }

    public string DetectedType { get; }

    public string OwnerInputKind { get; }

    public long ByteLength { get; }

    public int Order
    {
        get => _order;
        set => SetProperty(ref _order, Math.Max(0, value));
    }

    public bool IsImage =>
        string.Equals(OwnerInputKind, "local_image", StringComparison.Ordinal) ||
        string.Equals(DetectedType, "image/png", StringComparison.Ordinal);

    public string SizeText => FormatByteLength(ByteLength);

    public string AutomationName => $"{OriginalFileName}, {SizeText}";

    public ImageSource? Thumbnail
    {
        get => _thumbnail;
        private set
        {
            if (SetProperty(ref _thumbnail, value))
            {
                OnPropertyChanged(nameof(HasThumbnail));
            }
        }
    }

    public bool HasThumbnail => Thumbnail is not null;

    public AttachmentThumbnailState ThumbnailState
    {
        get => _thumbnailState;
        private set => SetProperty(ref _thumbnailState, value);
    }

    public AttachmentValidationState ValidationState
    {
        get => _validationState;
        private set
        {
            if (SetProperty(ref _validationState, value))
            {
                OnPropertyChanged(nameof(HasValidationError));
            }
        }
    }

    public bool HasValidationError => ValidationState == AttachmentValidationState.Invalid;

    public bool IsDragSource
    {
        get => _isDragSource;
        set => SetProperty(ref _isDragSource, value);
    }

    public bool ShowDropBefore
    {
        get => _showDropBefore;
        set => SetProperty(ref _showDropBefore, value);
    }

    public bool ShowDropAfter
    {
        get => _showDropAfter;
        set => SetProperty(ref _showDropAfter, value);
    }

    public string ValidationMessage
    {
        get => _validationMessage;
        private set => SetProperty(ref _validationMessage, value ?? string.Empty);
    }

    internal PresetAttachmentReference ToReference() =>
        new()
        {
            Id = Id,
            ContentId = ContentId,
            OriginalFileName = OriginalFileName,
            DetectedType = DetectedType,
            OwnerInputKind = OwnerInputKind,
            ByteLength = ByteLength,
            Order = Order
        };

    internal void BeginThumbnailLoad()
    {
        Thumbnail = null;
        ThumbnailState = AttachmentThumbnailState.Loading;
    }

    internal void SetThumbnail(ImageSource thumbnail)
    {
        ArgumentNullException.ThrowIfNull(thumbnail);
        Thumbnail = thumbnail;
        ThumbnailState = AttachmentThumbnailState.Ready;
    }

    internal void SetThumbnailFailure()
    {
        Thumbnail = null;
        ThumbnailState = AttachmentThumbnailState.Failed;
    }

    internal void CancelThumbnailLoad()
    {
        if (ThumbnailState != AttachmentThumbnailState.Loading)
        {
            return;
        }

        Thumbnail = null;
        ThumbnailState = AttachmentThumbnailState.NotRequested;
    }

    internal void SetValidation(AttachmentValidationState state, string? message = null)
    {
        ValidationState = state;
        ValidationMessage = message ?? string.Empty;
    }

    internal void RefreshLocalizedText()
    {
        OnPropertyChanged(nameof(SizeText));
        OnPropertyChanged(nameof(AutomationName));
    }

    internal static string FormatByteLength(long byteLength)
    {
        if (byteLength < 1024)
        {
            return $"{byteLength.ToString(CultureInfo.CurrentUICulture)} B";
        }

        var value = byteLength / 1024d;
        var unit = "KB";
        if (value >= 1024)
        {
            value /= 1024;
            unit = "MB";
        }

        if (value >= 1024)
        {
            value /= 1024;
            unit = "GB";
        }

        return $"{value.ToString(value >= 10 ? "0" : "0.#", CultureInfo.CurrentUICulture)} {unit}";
    }
}
