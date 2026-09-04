using CodexGuardian.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace CodexGuardian.Services;

internal interface IDesktopStructuredInputEncoder
{
    JsonElement Encode(
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        IReadOnlyDictionary<string, string> presentationPaths);
}

internal sealed class DesktopStructuredInputEncoder : IDesktopStructuredInputEncoder
{
    private const int MaximumPresentationPathLength = 1024;

    public JsonElement Encode(
        StructuredPresetPayload payload,
        DesktopStructuredInputCapabilities capabilities,
        IReadOnlyDictionary<string, string> presentationPaths)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(presentationPaths);

        var requirement = capabilities.Evaluate(payload);
        if (!requirement.IsSatisfied)
        {
            throw Failure(
                requirement.Code,
                "The current Desktop structured-input capability does not satisfy the payload.");
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
               {
                   Indented = false,
                   SkipValidation = false
               }))
        {
            writer.WriteStartArray();
            if (payload.Text.Length > 0)
            {
                writer.WriteStartObject();
                writer.WriteString("type", "text");
                writer.WriteString("text", payload.Text);
                writer.WritePropertyName("text_elements");
                writer.WriteStartArray();
                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            foreach (var attachment in payload.Attachments)
            {
                if (!presentationPaths.TryGetValue(attachment.Id, out var presentationPath) ||
                    !IsBoundedAbsolutePath(presentationPath))
                {
                    throw Failure(
                        "presentation-path-missing",
                        "A bounded absolute presentation path is required for every attachment.");
                }

                if (!string.Equals(
                        attachment.OwnerInputKind,
                        "local_image",
                        StringComparison.Ordinal))
                {
                    throw Failure(
                        "unsupported-input-kind",
                        "The attachment input kind has no verified Desktop wire mapping.");
                }

                writer.WriteStartObject();
                writer.WriteString("type", "localImage");
                writer.WriteString("path", presentationPath);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.Flush();
        }

        using var document = JsonDocument.Parse(
            stream.GetBuffer().AsMemory(0, checked((int)stream.Length)));
        return document.RootElement.Clone();
    }

    private static bool IsBoundedAbsolutePath(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= MaximumPresentationPathLength &&
        Path.IsPathFullyQualified(value) &&
        value.IndexOf('\0') < 0;

    private static DesktopStructuredInputEncodingException Failure(string code, string message) =>
        new(code, message);
}

internal sealed class DesktopStructuredInputEncodingException : InvalidOperationException
{
    internal DesktopStructuredInputEncodingException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    internal string Code { get; }
}
