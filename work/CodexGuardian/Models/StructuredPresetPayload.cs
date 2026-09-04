using CodexGuardian.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace CodexGuardian.Models;

public sealed record StructuredPresetPayload
{
    public const int CurrentSchemaVersion = 1;
    private const int MaximumFileNameLength = 255;
    private const int MaximumDetectedTypeLength = 128;
    private const int MaximumOwnerInputKindLength = 64;

    private StructuredPresetPayload(
        int schemaVersion,
        string text,
        IReadOnlyList<PresetAttachmentReference> attachments,
        string payloadDigest)
    {
        SchemaVersion = schemaVersion;
        Text = text;
        Attachments = attachments;
        PayloadDigest = payloadDigest;
    }

    public int SchemaVersion { get; }

    public string Text { get; }

    public IReadOnlyList<PresetAttachmentReference> Attachments { get; }

    public string PayloadDigest { get; }

    public static StructuredPresetPayload Create(
        string? text,
        IEnumerable<PresetAttachmentReference>? attachments,
        AttachmentLimitSettings? limits = null)
    {
        var normalizedText = SettingsService.NormalizeFollowUpMessage(text);
        var normalizedLimits = limits ?? new AttachmentLimitSettings();
        ValidateLimits(normalizedLimits);

        var source = attachments?.ToList() ?? [];
        if (source.Count > normalizedLimits.MaximumAttachmentsPerMessage)
        {
            throw new ArgumentException(
                "The structured payload exceeds the attachment count limit.",
                nameof(attachments));
        }

        var normalized = new List<PresetAttachmentReference>(source.Count);
        var seenReferenceIds = new HashSet<string>(StringComparer.Ordinal);
        long totalBytes = 0;
        foreach (var candidate in source
                     .OrderBy(reference => reference?.Order ?? int.MaxValue)
                     .ThenBy(reference => reference?.Id ?? string.Empty, StringComparer.Ordinal))
        {
            if (candidate is null)
            {
                throw new ArgumentException(
                    "The structured payload contains a null attachment reference.",
                    nameof(attachments));
            }

            var fileName = candidate.OriginalFileName?.Trim() ?? string.Empty;
            var detectedType = candidate.DetectedType?.Trim() ?? string.Empty;
            var ownerInputKind = candidate.OwnerInputKind?.Trim() ?? string.Empty;
            if (!AttachmentIdentity.IsCanonicalReferenceId(candidate.Id) ||
                !seenReferenceIds.Add(candidate.Id))
            {
                throw new ArgumentException(
                    "Attachment reference ids must be unique canonical UUIDs.",
                    nameof(attachments));
            }

            if (!AttachmentIdentity.IsCanonicalContentId(candidate.ContentId))
            {
                throw new ArgumentException(
                    "Attachment content ids must be canonical uppercase SHA-256 values.",
                    nameof(attachments));
            }

            if (!IsSafeFileName(fileName))
            {
                throw new ArgumentException(
                    "Attachment filenames must be bounded basename-only values.",
                    nameof(attachments));
            }

            if (detectedType.Length is < 1 or > MaximumDetectedTypeLength ||
                ownerInputKind.Length is < 1 or > MaximumOwnerInputKindLength)
            {
                throw new ArgumentException(
                    "Attachment type metadata is missing or unbounded.",
                    nameof(attachments));
            }

            if (candidate.ByteLength <= 0 ||
                candidate.ByteLength > normalizedLimits.MaximumBytesPerFile ||
                totalBytes > normalizedLimits.MaximumBytesPerMessage - candidate.ByteLength)
            {
                throw new ArgumentException(
                    "Attachment byte limits are invalid or exceeded.",
                    nameof(attachments));
            }

            totalBytes += candidate.ByteLength;
            normalized.Add(candidate with
            {
                OriginalFileName = fileName,
                DetectedType = detectedType,
                OwnerInputKind = ownerInputKind,
                Order = normalized.Count
            });
        }

        if (normalizedText.Length == 0 && normalized.Count == 0)
        {
            throw new ArgumentException("A structured payload cannot be empty.", nameof(text));
        }

        var frozenAttachments = Array.AsReadOnly(normalized.ToArray());
        return new StructuredPresetPayload(
            CurrentSchemaVersion,
            normalizedText,
            frozenAttachments,
            ComputeDigest(CurrentSchemaVersion, normalizedText, frozenAttachments));
    }

    internal bool HasValidIdentity()
    {
        if (SchemaVersion != CurrentSchemaVersion ||
            !IsCanonicalSha256(PayloadDigest))
        {
            return false;
        }

        try
        {
            var canonical = Create(Text, Attachments);
            return string.Equals(Text, canonical.Text, StringComparison.Ordinal) &&
                   Attachments.SequenceEqual(canonical.Attachments) &&
                   string.Equals(PayloadDigest, canonical.PayloadDigest, StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string ComputeDigest(
        int schemaVersion,
        string text,
        IReadOnlyList<PresetAttachmentReference> attachments)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
               {
                   Indented = false,
                   SkipValidation = false
               }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", schemaVersion);
            writer.WriteString("text", text);
            writer.WritePropertyName("attachments");
            writer.WriteStartArray();
            foreach (var attachment in attachments)
            {
                writer.WriteStartObject();
                writer.WriteNumber("order", attachment.Order);
                writer.WriteString("contentId", attachment.ContentId);
                writer.WriteNumber("byteLength", attachment.ByteLength);
                writer.WriteString("detectedType", attachment.DetectedType);
                writer.WriteString("ownerInputKind", attachment.OwnerInputKind);
                writer.WriteString("originalFileName", attachment.OriginalFileName);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        return Convert.ToHexString(SHA256.HashData(stream.GetBuffer().AsSpan(0, checked((int)stream.Length))));
    }

    private static bool IsSafeFileName(string fileName) =>
        fileName.Length is > 0 and <= MaximumFileNameLength &&
        string.Equals(Path.GetFileName(fileName), fileName, StringComparison.Ordinal) &&
        fileName.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

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

    private static void ValidateLimits(AttachmentLimitSettings limits)
    {
        if (limits.MaximumAttachmentsPerMessage is < 0 or > 1000 ||
            limits.MaximumBytesPerFile <= 0 ||
            limits.MaximumBytesPerMessage <= 0 ||
            limits.MaximumBytesPerFile > limits.MaximumBytesPerMessage)
        {
            throw new ArgumentException("Structured payload attachment limits are invalid.", nameof(limits));
        }
    }
}
