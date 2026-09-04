using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace CodexGuardian.Services;

internal enum StructuredInputEvidenceAcquisition
{
    ReadOnlyAsar,
    ActiveSendProbe
}

internal sealed record CodexStructuredInputSemanticSnapshot
{
    internal required StructuredInputEvidenceAcquisition Acquisition { get; init; }

    internal required string PackageName { get; init; }

    internal required string ProductName { get; init; }

    internal required string PackageVersion { get; init; }

    internal required long Epoch { get; init; }

    internal required IReadOnlySet<string> FollowerMethods { get; init; }

    internal required string StartTurnHostHandler { get; init; }

    internal required bool StartTurnAssertsOwner { get; init; }

    internal required string NativeMethod { get; init; }

    internal required int NativeMethodVersion { get; init; }

    internal required bool PreservesInput { get; init; }

    internal required bool PreservesStableClientUserMessageId { get; init; }

    internal required IReadOnlySet<string> NativeInputKinds { get; init; }

    internal required string HandlerShapeSha256 { get; init; }

    internal required string InputShapeSha256 { get; init; }

    internal required bool SupportsAttachmentOnly { get; init; }

    internal required int MaximumAttachmentCount { get; init; }

    internal required long MaximumBytesPerFile { get; init; }

    internal required long MaximumBytesPerPayload { get; init; }
}

internal static class CodexStructuredInputCapabilityInspector
{
    private const int MaximumSemanticSetSize = 64;
    private const int MaximumSemanticValueLength = 256;

    internal static DesktopStructuredInputCapabilities Inspect(
        CodexStructuredInputSemanticSnapshot? snapshot)
    {
        if (snapshot is null || snapshot.Acquisition != StructuredInputEvidenceAcquisition.ReadOnlyAsar)
        {
            return Unknown(snapshot?.Epoch ?? 0, "semantic-evidence-not-read-only");
        }

        if (!HasBoundedText(snapshot.PackageName, 128) ||
            !HasBoundedText(snapshot.ProductName, 128) ||
            !HasBoundedText(snapshot.PackageVersion, 128) ||
            !HasBoundedText(snapshot.StartTurnHostHandler, 128) ||
            !HasBoundedText(snapshot.NativeMethod, 128) ||
            snapshot.Epoch <= 0 ||
            !IsCanonicalSha256(snapshot.HandlerShapeSha256) ||
            !IsCanonicalSha256(snapshot.InputShapeSha256) ||
            !HasBoundedSet(snapshot.FollowerMethods) ||
            !HasBoundedSet(snapshot.NativeInputKinds) ||
            snapshot.MaximumAttachmentCount is < 0 or > 1000 ||
            snapshot.MaximumBytesPerFile <= 0 ||
            snapshot.MaximumBytesPerPayload <= 0 ||
            snapshot.MaximumBytesPerFile > snapshot.MaximumBytesPerPayload)
        {
            return Unknown(snapshot.Epoch, "semantic-evidence-incomplete");
        }

        if (!string.Equals(
                snapshot.PackageName,
                "openai-codex-electron",
                StringComparison.Ordinal) ||
            !string.Equals(snapshot.ProductName, "Codex", StringComparison.Ordinal))
        {
            return Unsupported(snapshot, "package-semantics-unsupported");
        }

        if (!snapshot.FollowerMethods.Contains("thread-follower-start-turn") ||
            !string.Equals(
                snapshot.StartTurnHostHandler,
                "thread-follower-start-turn-for-host",
                StringComparison.Ordinal) ||
            !snapshot.StartTurnAssertsOwner ||
            !string.Equals(snapshot.NativeMethod, "turn/start", StringComparison.Ordinal) ||
            snapshot.NativeMethodVersion != 1 ||
            !snapshot.PreservesInput ||
            !snapshot.PreservesStableClientUserMessageId ||
            !snapshot.NativeInputKinds.Contains("text"))
        {
            return Unsupported(snapshot, "owner-start-turn-semantics-unsupported");
        }

        var supportedKinds = new HashSet<string>(StringComparer.Ordinal)
        {
            "text"
        };
        if (snapshot.NativeInputKinds.Contains("localImage"))
        {
            supportedKinds.Add("local_image");
        }

        return new DesktopStructuredInputCapabilities(
            StructuredInputCapabilityState.Supported,
            supportedKinds,
            snapshot.SupportsAttachmentOnly,
            snapshot.MaximumAttachmentCount,
            snapshot.MaximumBytesPerFile,
            snapshot.MaximumBytesPerPayload,
            snapshot.Epoch,
            ComputeSemanticFingerprint(snapshot, supportedKinds),
            "read-only-owner-structured-input-semantics-supported");
    }

    private static DesktopStructuredInputCapabilities Unsupported(
        CodexStructuredInputSemanticSnapshot snapshot,
        string detail) =>
        new(
            StructuredInputCapabilityState.Unsupported,
            new HashSet<string>(StringComparer.Ordinal),
            false,
            0,
            0,
            0,
            snapshot.Epoch,
            ComputeSemanticFingerprint(snapshot, new HashSet<string>(StringComparer.Ordinal)),
            detail);

    private static DesktopStructuredInputCapabilities Unknown(long epoch, string detail) =>
        new(
            StructuredInputCapabilityState.Unknown,
            new HashSet<string>(StringComparer.Ordinal),
            false,
            0,
            0,
            0,
            Math.Max(0, epoch),
            string.Empty,
            detail);

    private static string ComputeSemanticFingerprint(
        CodexStructuredInputSemanticSnapshot snapshot,
        IReadOnlySet<string> supportedKinds)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
               {
                   Indented = false,
                   SkipValidation = false
               }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("contractVersion", 1);
            writer.WriteString("packageName", snapshot.PackageName);
            writer.WriteString("productName", snapshot.ProductName);
            writer.WriteBoolean(
                "hasFollowerStartTurn",
                snapshot.FollowerMethods.Contains("thread-follower-start-turn"));
            writer.WriteString("hostHandler", snapshot.StartTurnHostHandler);
            writer.WriteBoolean("assertsOwner", snapshot.StartTurnAssertsOwner);
            writer.WriteString("nativeMethod", snapshot.NativeMethod);
            writer.WriteNumber("nativeMethodVersion", snapshot.NativeMethodVersion);
            writer.WriteBoolean("preservesInput", snapshot.PreservesInput);
            writer.WriteBoolean(
                "preservesStableClientUserMessageId",
                snapshot.PreservesStableClientUserMessageId);
            writer.WriteString("handlerShapeSha256", snapshot.HandlerShapeSha256);
            writer.WriteString("inputShapeSha256", snapshot.InputShapeSha256);
            writer.WritePropertyName("supportedInputKinds");
            writer.WriteStartArray();
            foreach (var kind in supportedKinds.OrderBy(value => value, StringComparer.Ordinal))
            {
                writer.WriteStringValue(kind);
            }

            writer.WriteEndArray();
            writer.WriteBoolean("supportsAttachmentOnly", snapshot.SupportsAttachmentOnly);
            writer.WriteNumber("maximumAttachmentCount", snapshot.MaximumAttachmentCount);
            writer.WriteNumber("maximumBytesPerFile", snapshot.MaximumBytesPerFile);
            writer.WriteNumber("maximumBytesPerPayload", snapshot.MaximumBytesPerPayload);
            writer.WriteEndObject();
            writer.Flush();
        }

        return Convert.ToHexString(
            SHA256.HashData(stream.GetBuffer().AsSpan(0, checked((int)stream.Length))));
    }

    private static bool HasBoundedText(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool HasBoundedSet(IReadOnlySet<string>? values)
    {
        if (values is null || values.Count is < 1 or > MaximumSemanticSetSize)
        {
            return false;
        }

        foreach (var value in values)
        {
            if (!HasBoundedText(value, MaximumSemanticValueLength))
            {
                return false;
            }
        }

        return true;
    }

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
