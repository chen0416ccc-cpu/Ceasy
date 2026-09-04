using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal sealed class WorkflowDispatchPolicyAuthority : IWorkflowDispatchPolicyAuthority
{
    internal static readonly TimeSpan DefaultValidationTimeout = TimeSpan.FromSeconds(2);

    private readonly SettingsService _settings;
    private readonly string _dataDirectory;
    private readonly TimeSpan _validationTimeout;

    internal WorkflowDispatchPolicyAuthority(
        SettingsService settings,
        TimeSpan? validationTimeout = null)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _dataDirectory = settings.DataDirectory;
        _validationTimeout = validationTimeout ?? DefaultValidationTimeout;
        if (_validationTimeout <= TimeSpan.Zero || _validationTimeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(validationTimeout));
        }
    }

    public bool IsCurrent(WorkflowDispatchPolicyToken token)
    {
        try
        {
            using var timeout = new CancellationTokenSource(_validationTimeout);
            return IsCurrentAsync(token, timeout.Token).GetAwaiter().GetResult();
        }
        catch
        {
            return false;
        }
    }

    internal async Task<bool> IsCurrentAsync(
        WorkflowDispatchPolicyToken token,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        cancellationToken.ThrowIfCancellationRequested();
        if (!HasValidTokenIdentity(token))
        {
            return false;
        }

        var settings = await _settings.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (settings.ReadStatus != SettingsReadStatus.Healthy ||
            settings.SettingsGeneration != token.SettingsGeneration ||
            !PresetAutomationPolicy.IsTargetProtectionAuthorized(
                settings,
                token.TargetConversationId) ||
            !TryResolveExactPreset(settings, token, out var preset))
        {
            return false;
        }

        StructuredPresetPayload payload;
        try
        {
            payload = StructuredPresetPayload.Create(preset.Message, preset.Attachments);
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (!string.Equals(payload.PayloadDigest, token.PayloadDigest, StringComparison.Ordinal))
        {
            return false;
        }

        // A fresh store instance forces a bounded disk read instead of trusting a previously loaded
        // in-memory generation when another process or atomic replacement changed the rule file.
        var rules = await new WorkflowRuleStore(_dataDirectory)
            .ReadAsync(cancellationToken)
            .ConfigureAwait(false);
        if (rules.ReadStatus != WorkflowRuleStoreReadStatus.Healthy ||
            rules.RequiresConservativeRecovery ||
            rules.Generation != token.RuleStoreGeneration)
        {
            return false;
        }

        var matchingRules = rules.Rules.Where(rule => string.Equals(
                rule.RuleId,
                token.RuleId,
                StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        if (matchingRules.Length != 1)
        {
            return false;
        }

        var current = matchingRules[0];
        if (!current.IsEnabled || current.Revision != token.RuleRevision ||
            !string.Equals(current.DefinitionDigest, token.DefinitionDigest, StringComparison.Ordinal) ||
            !string.Equals(
                current.ResolveKnownDestinationConversationId(),
                token.TargetConversationId,
                StringComparison.OrdinalIgnoreCase) ||
            token.ActionIndex < 0 || token.ActionIndex >= current.Actions.Count)
        {
            return false;
        }

        var action = current.Actions[token.ActionIndex];
        return action.Order == token.ActionIndex &&
               action.Kind == WorkflowActionKind.SendPresetMessage &&
               string.Equals(
                   action.PresetOwnerConversationId,
                   token.PresetOwnerConversationId,
                   StringComparison.OrdinalIgnoreCase) &&
               string.Equals(
                   action.PresetMessageId,
                   token.PresetMessageId,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryResolveExactPreset(
        AppSettings settings,
        WorkflowDispatchPolicyToken token,
        out FollowUpMessageDefinition preset)
    {
        preset = null!;
        if (!settings.ThreadFollowUps.TryGetValue(token.PresetOwnerConversationId, out var owner) ||
            !owner.IsEnabled)
        {
            return false;
        }

        var matches = owner.Messages.Where(message => string.Equals(
                message.Id,
                token.PresetMessageId,
                StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        if (matches.Length != 1 ||
            !matches[0].IsEnabled ||
            !matches[0].UseWorkflowAutomation)
        {
            return false;
        }

        var candidate = matches[0];
        if (string.Equals(
                WorkflowRuleEditor.CreateManagedRuleId(
                    token.PresetOwnerConversationId,
                    token.PresetMessageId),
                token.RuleId,
                StringComparison.OrdinalIgnoreCase) &&
            (candidate.WorkflowRuleRevision != token.RuleRevision ||
             !string.Equals(
                 candidate.WorkflowRuleDigest,
                 token.DefinitionDigest,
                 StringComparison.Ordinal)))
        {
            return false;
        }

        preset = candidate;
        return true;
    }

    private static bool HasValidTokenIdentity(WorkflowDispatchPolicyToken token) =>
        token.RuleRevision > 0 && token.ActionIndex >= 0 &&
        token.SettingsGeneration > 0 && token.RuleStoreGeneration > 0 &&
        IsId(token.RuleId) && IsId(token.TriggerEventId) &&
        IsId(token.TargetConversationId) && IsId(token.PresetOwnerConversationId) &&
        IsId(token.PresetMessageId) && IsDigest(token.DefinitionDigest) &&
        IsDigest(token.PayloadDigest);

    private static bool IsId(string? value) =>
        Guid.TryParse(value, out var parsed) && parsed != Guid.Empty;

    private static bool IsDigest(string? value) =>
        value is { Length: 64 } && value.All(static character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');
}
