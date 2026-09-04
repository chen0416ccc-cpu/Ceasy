namespace CodexGuardian.Models;

public sealed record PresetAttachmentReference
{
    public required string Id { get; init; }

    public required string ContentId { get; init; }

    public required string OriginalFileName { get; init; }

    public required string DetectedType { get; init; }

    public required string OwnerInputKind { get; init; }

    public required long ByteLength { get; init; }

    public int Order { get; init; }
}

public sealed record AttachmentLimitSettings
{
    public int MaximumAttachmentsPerMessage { get; init; } = 20;

    public long MaximumBytesPerFile { get; init; } = 100L * 1024 * 1024;

    public long MaximumBytesPerMessage { get; init; } = 500L * 1024 * 1024;

    public long MaximumLibraryBytes { get; init; } = 10L * 1024 * 1024 * 1024;
}

internal sealed record ManagedAttachmentObject(
    string ContentId,
    long ByteLength,
    string DetectedType,
    string ObjectPath);

internal interface IManagedAttachmentStore
{
    Task<ManagedAttachmentObject> ImportAsync(
        string sourcePath,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken);

    Task<ManagedAttachmentObject> ImportBytesAsync(
        Stream source,
        string originalFileName,
        AttachmentLimitSettings limits,
        CancellationToken cancellationToken);

    Task<bool> VerifyAsync(
        PresetAttachmentReference reference,
        CancellationToken cancellationToken);
}

internal sealed record ZeroReferenceProof(
    string ContentId,
    long SettingsGeneration,
    long PreviousSettingsGeneration,
    long FollowUpJournalGeneration,
    long RecoveryJournalGeneration,
    long DraftVersion,
    long LeaseVersion,
    long TransactionVersion);

internal static class AttachmentIdentity
{
    internal static bool IsCanonicalReferenceId(string? value) =>
        Guid.TryParseExact(value, "D", out var parsed) &&
        string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    internal static bool IsCanonicalContentId(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9') and not (>= 'A' and <= 'F'))
            {
                return false;
            }
        }

        return true;
    }
}
