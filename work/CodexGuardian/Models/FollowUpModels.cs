namespace CodexGuardian.Models;

public enum FollowUpTriggerKind
{
    AfterNormalCompletion,
    ScheduledAt
}

public static class FollowUpRetryPolicy
{
    public const int DefaultMaximumErrorRetries = 500;

    public const int MaximumErrorRetriesLimit = 10_000;

    public static int GetEffectiveMaximumErrorRetries(int? configured) =>
        configured ?? DefaultMaximumErrorRetries;

    public static int? NormalizeMaximumErrorRetries(int? configured) =>
        configured is null
            ? null
            : Math.Clamp(configured.Value, 0, MaximumErrorRetriesLimit);

    public static bool IsExhausted(FollowUpMessageDefinition message, int attemptCount)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (attemptCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(attemptCount));
        }

        return !message.RetryIndefinitely &&
               attemptCount > GetEffectiveMaximumErrorRetries(message.MaximumErrorRetries);
    }
}

public sealed record FollowUpMessageDefinition
{
    public required string Id { get; init; }

    public required string Message { get; init; }

    public IReadOnlyList<PresetAttachmentReference> Attachments { get; init; } = [];

    public FollowUpTriggerKind Trigger { get; init; } = FollowUpTriggerKind.AfterNormalCompletion;

    public DateTimeOffset? ScheduledAtUtc { get; init; }

    public bool IsEnabled { get; init; } = true;

    public bool UseWorkflowAutomation { get; init; }

    public int? WorkflowRuleRevision { get; init; }

    public string? WorkflowRuleDigest { get; init; }

    public bool RetryIndefinitely { get; init; }

    public int? MaximumErrorRetries { get; init; }

    public int Order { get; init; }
}

public sealed record ThreadFollowUpSettings
{
    public bool IsEnabled { get; init; } = true;

    public string? CompletionAnchorTurnId { get; init; }

    public IReadOnlyList<FollowUpMessageDefinition> Messages { get; init; } = [];
}
