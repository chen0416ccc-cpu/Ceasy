using System;
using CodexGuardian.Models;

namespace CodexGuardian.Services;

internal static class ProductionRecoveryServiceFactory
{
    internal static RecoveryService CreateLive(
        AppServerClient appServer,
        DesktopIpcClient desktop,
        DesktopThreadOwnerActivator ownerActivator,
        RecoveryOperationJournal recoveryJournal,
        GuardianLog log,
        IRecoveryInterferenceGuard interferenceGuard,
        IDesktopStructuredInputCapabilityProvider semanticCapabilities,
        IRecoveryStructuredInputReplayAuthority? replayAuthority,
        ThreadActionCoordinator threadActions,
        AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(appServer);
        ArgumentNullException.ThrowIfNull(desktop);
        ArgumentNullException.ThrowIfNull(ownerActivator);
        ArgumentNullException.ThrowIfNull(recoveryJournal);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(interferenceGuard);
        ArgumentNullException.ThrowIfNull(semanticCapabilities);
        ArgumentNullException.ThrowIfNull(threadActions);
        ArgumentNullException.ThrowIfNull(settings);

        return new RecoveryService(
            appServer,
            desktop,
            ownerActivator,
            recoveryJournal,
            log,
            interferenceGuard,
            structuredInputReplayAuthority: replayAuthority,
            transportSemanticCapabilities: semanticCapabilities,
            requireCurrentNativeChannel: true,
            requireExplicitInterferenceClear: true,
            threadActions: threadActions,
            defaultCountingMode: settings.RecoveryCountingMode,
            defaultMaximumAttempts: settings.MaximumRecoveryAttempts,
            defaultUnlimitedAttempts: settings.UnlimitedRecoveryAttempts);
    }
}
