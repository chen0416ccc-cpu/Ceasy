using CodexGuardian.Models;

namespace CodexGuardian.Services;

/// <summary>
/// Keeps preset-message authorization separate from the automatic-recovery monitor gate.
///
/// <see cref="AppSettings.MonitorOnly"/> protects recovery writes only. A preset is an
/// explicit product action when its queue and item are enabled; a workflow preset additionally
/// opts into the typed workflow path. Global and target protection, owner capability, composer
/// state, attachment leases, policy generations, and durable at-most-once checks remain separate
/// gates.
/// </summary>
internal static class PresetAutomationPolicy
{
    internal static bool IsLegacyQueueMessageAuthorized(
        ThreadFollowUpSettings queue,
        FollowUpMessageDefinition message) =>
        queue.IsEnabled && message.IsEnabled && !message.UseWorkflowAutomation;

    internal static bool IsWorkflowMessageAuthorized(WorkflowResolvedPreset preset) =>
        preset.OwnerConversationAvailable &&
        preset.QueueAvailable &&
        preset.QueueEnabled &&
        preset.Definition is { IsEnabled: true, UseWorkflowAutomation: true } &&
        preset.RuleBindingCurrent &&
        preset.Payload is not null;

    internal static bool IsTargetProtectionAuthorized(
        AppSettings settings,
        string targetConversationId)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!Guid.TryParse(targetConversationId, out var parsed) || parsed == Guid.Empty ||
            !settings.GlobalProtectionEnabled)
        {
            return false;
        }

        var targetId = parsed.ToString("D");
        return settings.ThreadProtectionEnabled.TryGetValue(targetId, out var configured) &&
               configured;
    }
}
