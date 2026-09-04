using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal sealed record AttachmentDraftPinSnapshot(
    bool IsHealthy,
    long Version,
    IReadOnlyList<string> ContentIds);

internal sealed class AttachmentDraftAuthority
{
    private readonly object _sync = new();
    private readonly Dictionary<long, string[]> _transientPins = [];
    private string[] _visibleContentIds = [];
    private long _version;
    private long _visibleVersion = -1;
    private long _nextLeaseId;
    private bool _isHealthy = true;

    internal void ReplaceVisibleDrafts(
        long version,
        IEnumerable<ThreadFollowUpSettings> followUps)
    {
        ArgumentNullException.ThrowIfNull(followUps);
        ReplaceVisibleDrafts(
            version,
            followUps.SelectMany(static settings => settings.Messages)
                .SelectMany(static message => message.Attachments)
                .ToArray());
    }

    public void ReplaceVisibleDrafts(
        long version,
        IReadOnlyList<PresetAttachmentReference> visibleAttachments)
    {
        ArgumentNullException.ThrowIfNull(visibleAttachments);
        if (version < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(version));
        }

        var contentIds = ValidateAndProject(visibleAttachments);
        lock (_sync)
        {
            if (version < _visibleVersion)
            {
                throw new InvalidOperationException(
                    "A stale visible attachment draft cannot replace current pin authority.");
            }

            _visibleContentIds = contentIds;
            _visibleVersion = version;
            _version = checked(_version + 1);
            _isHealthy = true;
        }
    }

    public void MarkVisibleDraftsUnavailable()
    {
        lock (_sync)
        {
            _isHealthy = false;
            _visibleContentIds = [];
            _version = checked(_version + 1);
        }
    }

    public AttachmentDraftPinSnapshot ReadSnapshot()
    {
        lock (_sync)
        {
            var contentIds = _visibleContentIds
                .Concat(_transientPins.Values.SelectMany(static pins => pins))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
            return new AttachmentDraftPinSnapshot(
                _isHealthy,
                _version,
                Array.AsReadOnly(contentIds));
        }
    }

    public IDisposable AcquireTransientPins(
        IReadOnlyList<PresetAttachmentReference> attachments)
    {
        ArgumentNullException.ThrowIfNull(attachments);
        var contentIds = ValidateAndProject(attachments);
        lock (_sync)
        {
            if (!_isHealthy)
            {
                throw new InvalidOperationException(
                    "Transient attachment pins cannot be acquired while draft authority is unavailable.");
            }

            var leaseId = checked(++_nextLeaseId);
            _transientPins.Add(leaseId, contentIds);
            _version = checked(_version + 1);
            return new TransientPinLease(this, leaseId);
        }
    }

    private static string[] ValidateAndProject(
        IReadOnlyList<PresetAttachmentReference> attachments)
    {
        var contentIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var attachment in attachments)
        {
            if (attachment is null ||
                !AttachmentIdentity.IsCanonicalReferenceId(attachment.Id) ||
                !AttachmentIdentity.IsCanonicalContentId(attachment.ContentId) ||
                attachment.ByteLength <= 0)
            {
                throw new ArgumentException(
                    "Draft attachment pins require complete canonical references.",
                    nameof(attachments));
            }

            contentIds.Add(attachment.ContentId);
        }

        return contentIds.Order(StringComparer.Ordinal).ToArray();
    }

    private void Release(long leaseId)
    {
        lock (_sync)
        {
            if (_transientPins.Remove(leaseId))
            {
                _version = checked(_version + 1);
            }
        }
    }

    private sealed class TransientPinLease(
        AttachmentDraftAuthority owner,
        long leaseId) : IDisposable
    {
        private AttachmentDraftAuthority? _owner = owner;

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release(leaseId);
    }
}
