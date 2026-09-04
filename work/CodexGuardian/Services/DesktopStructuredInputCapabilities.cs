using CodexGuardian.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian.Services;

internal enum StructuredInputCapabilityState
{
    Supported,
    Unsupported,
    Unknown
}

internal sealed record DesktopStructuredInputRequirementResult(bool IsSatisfied, string Code)
{
    internal static DesktopStructuredInputRequirementResult Satisfied { get; } =
        new(true, "supported");
}

internal sealed record DesktopStructuredInputCapabilityLease(
    long Epoch,
    string SemanticFingerprint,
    string PayloadDigest);

internal sealed record DesktopStructuredInputCapabilities(
    StructuredInputCapabilityState State,
    IReadOnlySet<string> SupportedInputKinds,
    bool SupportsAttachmentOnly,
    int MaximumAttachmentCount,
    long MaximumBytesPerFile,
    long MaximumBytesPerPayload,
    long Epoch,
    string SemanticFingerprint,
    string Detail)
{
    internal DesktopStructuredInputRequirementResult Evaluate(StructuredPresetPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.HasValidIdentity())
        {
            return Failure("payload-identity-invalid");
        }

        if (State == StructuredInputCapabilityState.Unknown)
        {
            return Failure("capability-unknown");
        }

        if (State == StructuredInputCapabilityState.Unsupported)
        {
            return Failure("capability-unsupported");
        }

        if (!HasValidMetadata())
        {
            return Failure("capability-invalid");
        }

        var supportedKinds = new HashSet<string>(SupportedInputKinds, StringComparer.Ordinal);
        if (payload.Text.Length > 0 && !supportedKinds.Contains("text"))
        {
            return Failure("unsupported-input-kind");
        }

        if (payload.Text.Length == 0 && payload.Attachments.Count > 0 && !SupportsAttachmentOnly)
        {
            return Failure("attachment-only-unsupported");
        }

        if (payload.Attachments.Count > MaximumAttachmentCount)
        {
            return Failure("attachment-count-exceeded");
        }

        long totalBytes = 0;
        foreach (var attachment in payload.Attachments)
        {
            if (!supportedKinds.Contains(attachment.OwnerInputKind))
            {
                return Failure("unsupported-input-kind");
            }

            if (attachment.ByteLength > MaximumBytesPerFile)
            {
                return Failure("attachment-file-bytes-exceeded");
            }

            if (totalBytes > MaximumBytesPerPayload - attachment.ByteLength)
            {
                return Failure("attachment-payload-bytes-exceeded");
            }

            totalBytes += attachment.ByteLength;
        }

        return DesktopStructuredInputRequirementResult.Satisfied;
    }

    internal DesktopStructuredInputCapabilityLease AcquireLease(StructuredPresetPayload payload)
    {
        var requirement = Evaluate(payload);
        if (!requirement.IsSatisfied)
        {
            throw new DesktopStructuredInputCapabilityException(
                requirement.Code,
                "The current Desktop structured-input capability does not satisfy the payload.");
        }

        return new DesktopStructuredInputCapabilityLease(
            Epoch,
            SemanticFingerprint,
            payload.PayloadDigest);
    }

    internal bool Matches(
        DesktopStructuredInputCapabilityLease lease,
        StructuredPresetPayload payload)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(payload);
        return Evaluate(payload).IsSatisfied &&
               Epoch == lease.Epoch &&
               string.Equals(
                   SemanticFingerprint,
                   lease.SemanticFingerprint,
                   StringComparison.Ordinal) &&
               string.Equals(payload.PayloadDigest, lease.PayloadDigest, StringComparison.Ordinal);
    }

    private bool HasValidMetadata() =>
        SupportedInputKinds is not null &&
        SupportedInputKinds.Count is > 0 and <= 16 &&
        SupportedInputKinds.All(kind =>
            !string.IsNullOrWhiteSpace(kind) && kind.Length <= 64) &&
        MaximumAttachmentCount is >= 0 and <= 1000 &&
        MaximumBytesPerFile > 0 &&
        MaximumBytesPerPayload > 0 &&
        MaximumBytesPerFile <= MaximumBytesPerPayload &&
        Epoch > 0 &&
        IsCanonicalSha256(SemanticFingerprint) &&
        !string.IsNullOrWhiteSpace(Detail) &&
        Detail.Length <= 256;

    private static DesktopStructuredInputRequirementResult Failure(string code) =>
        new(false, code);

    private static bool IsCanonicalSha256(string? value)
    {
        if (value is null || value.Length != SHA256.HashSizeInBytes * 2)
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

internal sealed class DesktopStructuredInputCapabilityException : InvalidOperationException
{
    internal DesktopStructuredInputCapabilityException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal interface IDesktopStructuredInputCapabilityProvider
{
    Task<DesktopStructuredInputCapabilities> ReadAsync(CancellationToken cancellationToken);
}
