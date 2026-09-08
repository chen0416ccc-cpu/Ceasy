using CodexGuardian.Control;
using CodexGuardian.Models;
using CodexGuardian.Services;
using CodexGuardian.Localization;
using CodexGuardian.ViewModels;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

if (StructuredAttachmentLiveGate.IsRequested(args))
{
    return await StructuredAttachmentLiveGate.RunAsync(args);
}

if (AutomaticRecoveryFreshFailureObserver.IsRequested(args))
{
    return await AutomaticRecoveryFreshFailureObserver.RunAsync(args);
}

if (AutomaticRecoveryExistingConversationLiveGate.IsRequested(args))
{
    return await AutomaticRecoveryExistingConversationLiveGate.RunAsync(args);
}

if (args.Contains(
        AutomaticRecoveryExistingConversationLiveGate.DeprecatedExperimentArgument,
        StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("AUTOMATIC_RECOVERY_LIVE_GATE_FAILED code=deprecated-experiment-entry");
    return 2;
}

if (BrokerConsentLedgerStoreOfflineTests.IsChildProbeInvocation(args))
{
    return BrokerConsentLedgerStoreOfflineTests.RunChildProbe(args);
}

if (WindowsNamedPipePeerTrustOfflineTests.IsTimeoutCancellationChildProbeInvocation(args))
{
    return WindowsNamedPipePeerTrustOfflineTests.RunTimeoutCancellationChildProbe();
}

if (CdpPipeTransportOfflineTests.IsChildProbeInvocation(args))
{
    return await CdpPipeTransportOfflineTests.RunChildProbeAsync(args);
}

if (WindowsConnectedClientPeerTrustNativeTests.IsChildProbeInvocation(args))
{
    return await WindowsConnectedClientPeerTrustNativeTests.RunChildProbeAsync(args);
}

if (WindowsGuardianCleanLauncherOfflineTests.IsChildProbeInvocation(args))
{
    return await WindowsGuardianCleanLauncherOfflineTests.RunChildProbeAsync(args);
}

if (WorkflowExistingConversationLiveGate.IsRequested(args))
{
    return await WorkflowExistingConversationLiveGate.RunAsync(args);
}

if (PublishedRuntimeDependencyClosureOfflineTests.IsVerificationInvocation(args))
{
    return PublishedRuntimeDependencyClosureOfflineTests.RunVerificationInvocation(args);
}

var failures = new List<string>();
const string LocalHistoryFallbackThreadId = "019f2d74-0200-7ff0-9c82-606ce019fd14";

void Assert(bool condition, string name)
{
    if (condition)
    {
        Console.WriteLine("PASS  " + name);
    }
    else
    {
        failures.Add(name);
        Console.WriteLine("FAIL  " + name);
    }
}

if (args.Contains(
        "--automatic-recovery-fresh-failure-observer-offline-only",
        StringComparer.OrdinalIgnoreCase))
{
    await AutomaticRecoveryFreshFailureObserverOfflineTests.RunAsync(Assert);
    Console.WriteLine("AUTOMATIC_RECOVERY_FRESH_FAILURE_OBSERVER_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--structured-follow-up-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await CodexStructuredInputPackageOfflineTests.RunAsync(Assert);
    await AttachmentPresentationReconciliationOfflineTests.RunAsync(Assert);
    await FollowUpAttachmentSaveAuthorityValidatorOfflineTests.RunAsync(Assert);
    await AutomaticRecoveryStructuredReplayOfflineTests.RunAsync(Assert);
    await StructuredFollowUpOfflineTests.RunAsync(Assert);
    Console.WriteLine("STRUCTURED_FOLLOW_UP_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--workflow-automation-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await AutomaticRecoveryClassificationOfflineTests.RunAsync(Assert);
    await RecoveryAttemptPolicyOfflineTests.RunAsync(Assert);
    await AutomaticRecoveryProtectionOfflineTests.RunAsync(Assert);
    await ConversationIndexOfflineTests.RunAsync(Assert);
    await AutomaticRecoveryExistingConversationLiveGateOfflineTests.RunAsync(Assert);
    await AutomaticRecoveryFreshFailureObserverOfflineTests.RunAsync(Assert);
    await AutomaticRecoveryStructuredReplayOfflineTests.RunAsync(Assert);
    await RecoveryReconciliationOfflineTests.RunAsync(Assert);
    await RecoveryVisibilityOfflineTests.RunAsync(Assert);
    await WorkflowAutomationOfflineTests.RunAsync(Assert);
    await WorkflowOperationJournalOfflineTests.RunAsync(Assert);
    await WorkflowConversationProtectionOfflineTests.RunAsync(Assert);
    await WorkflowActionExecutorOfflineTests.RunAsync(Assert);
    await WorkflowRuleStoreOfflineTests.RunAsync(Assert);
    await WorkflowTriggerCoordinatorOfflineTests.RunAsync(Assert);
    await WorkflowExecutionPipelineOfflineTests.RunAsync(Assert);
    await WorkflowAutomationRuntimeOfflineTests.RunAsync(Assert);
    await WorkflowLineageProjectionOfflineTests.RunAsync(Assert);
    await WorkflowLineageViewModelOfflineTests.RunAsync(Assert);
    await WorkflowEditorOfflineTests.RunAsync(Assert);
    await WorkflowExistingConversationLiveGateOfflineTests.RunAsync(Assert);
    Console.WriteLine("WORKFLOW_AUTOMATION_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--follow-up-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await FollowUpOfflineTests.RunAsync(Assert);
    Console.WriteLine("FOLLOW_UP_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--ui-refinement-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await UiRefinementOfflineTests.RunAsync(Assert);
    Console.WriteLine("UI_REFINEMENT_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--update-check-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await UpdateCheckOfflineTests.RunAsync(Assert);
    Console.WriteLine("UPDATE_CHECK_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains(
        "--structured-input-package-live-readonly",
        StringComparer.OrdinalIgnoreCase))
{
    await CodexStructuredInputPackageOfflineTests.RunLiveInstalledPackageReadOnlyAsync(Assert);
    Console.WriteLine("STRUCTURED_INPUT_PACKAGE_READONLY_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--attachment-foundation-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await AttachmentFoundationOfflineTests.RunAsync(Assert);
    await AttachmentInteractionOfflineTests.RunAsync(Assert);
    Console.WriteLine("ATTACHMENT_FOUNDATION_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--keep-alive-schedule-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await KeepAliveScheduleOfflineTests.RunAsync(Assert);
    Console.WriteLine("KEEP_ALIVE_SCHEDULE_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--conversation-mutation-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await ConversationMutationOfflineTests.RunAsync(Assert);
    Console.WriteLine("CONVERSATION_MUTATION_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (GuardianManagedEntryProofOfflineTests.IsPublishedAppHostProbeInvocation(args))
{
    await GuardianManagedEntryProofOfflineTests.RunPublishedAppHostProbeAsync(args, Assert);
    if (failures.Count == 0)
    {
        Console.WriteLine(GuardianManagedEntryProofOfflineTests.PublishedAppHostSuccessMarker);
    }

    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (BrokerWebAuthnNativeProbeTests.IsProbeInvocation(args))
{
    await BrokerWebAuthnNativeProbeTests.RunIfRequestedAsync(args, Assert);
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--broker-webauthn-offline-only", StringComparer.OrdinalIgnoreCase))
{
    await BrokerWebAuthnReceiptOfflineTests.RunAsync(Assert);
    Console.WriteLine("BROKER_WEBAUTHN_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains(
        "--broker-control-session-offline-only",
        StringComparer.OrdinalIgnoreCase))
{
    await CodexCdpRuntimeOwnershipOfflineTests.RunAsync(Assert);
    await BrokerControlSessionOfflineTests.RunAsync(Assert);
    Console.WriteLine("BROKER_CONTROL_SESSION_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains(
        "--broker-runtime-host-offline-only",
        StringComparer.OrdinalIgnoreCase))
{
    await PublishedRuntimeDependencyClosureOfflineTests.RunAsync(Assert);
    await WindowsCrtPipeProcessLifecycleOfflineTests.RunAsync(Assert);
    await WindowsCodexCdpRuntimeControlHostOfflineTests.RunAsync(Assert);
    await CodexCdpRuntimeOwnershipOfflineTests.RunAsync(Assert);
    await BrokerControlSessionOfflineTests.RunAsync(Assert);
    Console.WriteLine("BROKER_RUNTIME_HOST_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains(
        "--broker-production-host-offline-only",
        StringComparer.OrdinalIgnoreCase))
{
    await PublishedRuntimeDependencyClosureOfflineTests.RunAsync(Assert);
    await VerifiedLocalReleaseManifestOfflineTests.RunAsync(Assert);
    await GuardianBrokerBootstrapOfflineTests.RunAsync(Assert);
    await WindowsGuardianCleanLauncherOfflineTests.RunAsync(Assert);
    await GuardianManagedEntryProofOfflineTests.RunAsync(Assert);
    await CodexCdpRuntimeOwnershipOfflineTests.RunAsync(Assert);
    await BrokerControlSessionOfflineTests.RunAsync(Assert);
    await BrokerProductionHostOfflineTests.RunAsync(Assert);
    Console.WriteLine("BROKER_PRODUCTION_HOST_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Length == 1 &&
    string.Equals(
        args[0],
        "--broker-guardian-admission-offline-only",
        StringComparison.OrdinalIgnoreCase))
{
    await GuardianBrokerAdmissionProtocolOfflineTests.RunAsync(Assert);
    await GuardianBrokerManagedBootstrapOfflineTests.RunAsync(Assert);
    await WindowsGuardianProductionAdmissionOfflineTests.RunAsync(Assert);
    Console.WriteLine("BROKER_GUARDIAN_ADMISSION_OFFLINE_TESTS_COMPLETE");
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains(
        WindowsConnectedClientPeerTrustNativeTests.ParentArgument,
        StringComparer.OrdinalIgnoreCase))
{
    await WindowsConnectedClientPeerTrustNativeTests.RunIfRequestedAsync(Assert);
    Console.WriteLine(failures.Count == 0 ? "\nALL TESTS PASSED" : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

// Reaching this line means no suite switch matched and the full matrix is about to run. That is right
// when no suite was asked for, and a trap when one was: a switch name this binary does not implement
// used to fall through to here and print ALL TESTS PASSED for every case in the tree, which reads
// exactly like the requested suite passing. --attachment-interaction-offline-only is such a name and
// was taken for a real suite on that evidence. The admission suite is the other way to land here --
// it matches only as the sole argument, because its cases assert against this process's own command
// line -- so passing anything alongside it silently became a full run as well. Both now fail closed.
//
// The list holds bare subject names and the switch is assembled when printed, which is deliberate:
// BrokerControlSessionOfflineTests pins each Broker suite switch to exactly one occurrence of its
// quoted literal in this file, so that a second dispatch point cannot appear. Spelling the full
// switches here would break that count while adding no dispatch. Adding a suite means adding its
// subject to this list; a missing entry only shortens this message, since the suite's own branch
// above returns before control arrives here.
const string offlineSuiteSuffix = "-offline-only";
const string admissionSuiteSubject = "broker-guardian-admission";
string[] implementedOfflineSuiteSubjects =
[
    "attachment-foundation",
    "automatic-recovery-fresh-failure-observer",
    "broker-control-session",
    admissionSuiteSubject,
    "broker-production-host",
    "broker-runtime-host",
    "broker-webauthn",
    "conversation-mutation",
    "follow-up",
    "keep-alive-schedule",
    "structured-follow-up",
    "ui-refinement",
    "update-check",
    "workflow-automation",
];

var unmatchedSuiteArguments = args
    .Where(argument =>
        argument.StartsWith("--", StringComparison.Ordinal) &&
        argument.EndsWith(offlineSuiteSuffix, StringComparison.OrdinalIgnoreCase))
    .ToArray();
if (unmatchedSuiteArguments.Length > 0)
{
    Console.Error.WriteLine(
        $"No offline suite matched {string.Join(" ", unmatchedSuiteArguments)}; this run would " +
        "otherwise have executed the entire matrix and reported it as a pass.");
    if (unmatchedSuiteArguments.Any(argument => string.Equals(
            argument,
            "--" + admissionSuiteSubject + offlineSuiteSuffix,
            StringComparison.OrdinalIgnoreCase)))
    {
        Console.Error.WriteLine(
            $"--{admissionSuiteSubject}{offlineSuiteSuffix} has to be the only argument on the " +
            "command line.");
    }

    Console.Error.WriteLine("Implemented offline suites:");
    foreach (var subject in implementedOfflineSuiteSubjects)
    {
        Console.Error.WriteLine($"    --{subject}{offlineSuiteSuffix}");
    }

    return 2;
}

await CdpPipeTransportOfflineTests.RunAsync(Assert);
await CodexCdpObservationSessionOfflineTests.RunAsync(Assert);
await CodexPackageBaselineVerifierOfflineTests.RunAsync(Assert);
await CodexAsarCapabilityOfflineTests.RunAsync(Assert);
await CodexStructuredInputPackageOfflineTests.RunAsync(Assert);
await CodexCdpBrokerOfflineTests.RunAsync(Assert);
await PublishedRuntimeDependencyClosureOfflineTests.RunAsync(Assert);
await WindowsCrtPipeProcessLifecycleOfflineTests.RunAsync(Assert);
await WindowsCodexCdpRuntimeControlHostOfflineTests.RunAsync(Assert);
await CodexCdpRuntimeOwnershipOfflineTests.RunAsync(Assert);
await BrokerControlSessionOfflineTests.RunAsync(Assert);
await VerifiedLocalReleaseManifestOfflineTests.RunAsync(Assert);
await GuardianBrokerBootstrapOfflineTests.RunAsync(Assert);
await GuardianBrokerAdmissionProtocolOfflineTests.RunAsync(Assert);
await WindowsGuardianCleanLauncherOfflineTests.RunAsync(Assert);
await GuardianManagedEntryProofOfflineTests.RunAsync(Assert);
await GuardianBrokerManagedBootstrapOfflineTests.RunAsync(Assert);
await WindowsGuardianProductionAdmissionOfflineTests.RunAsync(Assert);
await BrokerProductionHostOfflineTests.RunAsync(Assert);
await BrokerConsentLedgerContractOfflineTests.RunAsync(Assert);
await BrokerConsentLedgerStoreOfflineTests.RunAsync(args, Assert);
await WindowsNamedPipePeerTrustOfflineTests.RunAsync(Assert);
await AuthenticatedPipePeerConnectionOfflineTests.RunAsync(Assert);
await AutomaticRecoveryClassificationOfflineTests.RunAsync(Assert);
await AutomaticRecoveryProtectionOfflineTests.RunAsync(Assert);
await ConversationIndexOfflineTests.RunAsync(Assert);
await RecoveryAttemptPolicyOfflineTests.RunAsync(Assert);
await AutomaticRecoveryExistingConversationLiveGateOfflineTests.RunAsync(Assert);
await AutomaticRecoveryFreshFailureObserverOfflineTests.RunAsync(Assert);
await AutomaticRecoveryStructuredReplayOfflineTests.RunAsync(Assert);
await RecoveryReconciliationOfflineTests.RunAsync(Assert);
await RecoveryVisibilityOfflineTests.RunAsync(Assert);
await WorkflowAutomationOfflineTests.RunAsync(Assert);
await WorkflowOperationJournalOfflineTests.RunAsync(Assert);
await WorkflowConversationProtectionOfflineTests.RunAsync(Assert);
await WorkflowActionExecutorOfflineTests.RunAsync(Assert);
await WorkflowRuleStoreOfflineTests.RunAsync(Assert);
await WorkflowTriggerCoordinatorOfflineTests.RunAsync(Assert);
await WorkflowExecutionPipelineOfflineTests.RunAsync(Assert);
await WorkflowAutomationRuntimeOfflineTests.RunAsync(Assert);
await WorkflowLineageProjectionOfflineTests.RunAsync(Assert);
await WorkflowLineageViewModelOfflineTests.RunAsync(Assert);
await WorkflowEditorOfflineTests.RunAsync(Assert);
await WorkflowExistingConversationLiveGateOfflineTests.RunAsync(Assert);
await AttachmentPresentationReconciliationOfflineTests.RunAsync(Assert);
await FollowUpAttachmentSaveAuthorityValidatorOfflineTests.RunAsync(Assert);
await StructuredFollowUpOfflineTests.RunAsync(Assert);
await FollowUpOfflineTests.RunAsync(Assert);
await UiRefinementOfflineTests.RunAsync(Assert);
await AttachmentFoundationOfflineTests.RunAsync(Assert);
await AttachmentInteractionOfflineTests.RunAsync(Assert);
await ConversationMutationOfflineTests.RunAsync(Assert);
await KeepAliveScheduleOfflineTests.RunAsync(Assert);
if (args.Contains("--native-peer-child-probe", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains("--package-baseline-live-readonly", StringComparer.OrdinalIgnoreCase))
{
    await CodexPackageBaselineVerifierOfflineTests.RunLiveInstalledPackageReadOnlyAsync(Assert);
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (args.Contains(
        "--package-compatible-candidate-live-readonly",
        StringComparer.OrdinalIgnoreCase))
{
    await CodexPackageBaselineVerifierOfflineTests
        .RunLiveInstalledPackageCandidateReadOnlyAsync(Assert);
    Console.WriteLine(failures.Count == 0
        ? "\nALL TESTS PASSED"
        : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

var cdpPipeProbeExecutable = Path.Combine(AppContext.BaseDirectory, "CodexGuardian.Tests.exe");
if (OperatingSystem.IsWindows() && File.Exists(cdpPipeProbeExecutable))
{
    await CdpPipeTransportOfflineTests.RunWindowsProcessProbeAsync(
        cdpPipeProbeExecutable,
        Assert);
}
else
{
    Assert(false, "Windows direct-handle CDP child probe executable is available");
}

string ComputeSha256(string path) =>
    Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

async Task WithRecoveryJournalTestAsync(string name, Func<string, Task> test)
{
    var root = Path.Combine(
        Path.GetTempPath(),
        "CodexGuardian",
        "journal-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        await test(root);
    }
    catch (Exception exception)
    {
        Assert(false, $"{name}: unexpected {exception.GetType().Name}: {exception.Message}");
    }
    finally
    {
        try
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Assert(false, $"{name}: temporary directory cleanup: {exception.Message}");
        }
    }
}

async Task<bool> ThrowsAsync<TException>(Func<Task> action)
    where TException : Exception
{
    try
    {
        await action();
        return false;
    }
    catch (TException)
    {
        return true;
    }
}

string? ReadCliArgumentValue(string[] values, string name)
{
    var index = Array.FindIndex(
        values,
        value => string.Equals(value, name, StringComparison.OrdinalIgnoreCase));
    return index >= 0 && index + 1 < values.Length ? values[index + 1] : null;
}

bool IsProcessRunning(int processId)
{
    if (processId <= 0)
    {
        return false;
    }

    try
    {
        using var process = Process.GetProcessById(processId);
        return !process.HasExited;
    }
    catch (ArgumentException)
    {
        return false;
    }
}

string DescribeOwnerSnapshot(DesktopThreadOwnerStateSnapshot snapshot) =>
    $"revision={snapshot.Revision} runtime={snapshot.RuntimeStatus} " +
    $"latest={snapshot.LatestTurnId}/{snapshot.LatestTurnStatus} " +
    $"host={snapshot.HostId} owner={snapshot.OwnerClientId}";

RecoveryOperationState? ReadPersistedJournalState(string path, string operationId)
{
    using var stream = new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete);
    using var document = JsonDocument.Parse(stream);
    if (!document.RootElement.TryGetProperty("records", out var records) ||
        records.ValueKind != JsonValueKind.Array)
    {
        return null;
    }

    foreach (var record in records.EnumerateArray())
    {
        if (!record.TryGetProperty("operationId", out var persistedOperationId) ||
            persistedOperationId.ValueKind != JsonValueKind.String ||
            !string.Equals(
                persistedOperationId.GetString(),
                operationId,
                StringComparison.OrdinalIgnoreCase) ||
            !record.TryGetProperty("state", out var state) ||
            !state.TryGetInt32(out var stateValue) ||
            !Enum.IsDefined(typeof(RecoveryOperationState), stateValue))
        {
            continue;
        }

        return (RecoveryOperationState)stateValue;
    }

    return null;
}

string? FindWorkspaceSource(params string[] relativePath)
{
    if (File.Exists(Path.Combine(
            Environment.CurrentDirectory,
            "CodexGuardian.Tests",
            "CodexGuardian.Tests.csproj")))
    {
        return Path.Combine(new[] { Environment.CurrentDirectory }.Concat(relativePath).ToArray());
    }

    var currentWorkDirectory = Path.Combine(Environment.CurrentDirectory, "work");
    if (File.Exists(Path.Combine(currentWorkDirectory, "CodexGuardian.Tests", "CodexGuardian.Tests.csproj")))
    {
        return Path.Combine(new[] { currentWorkDirectory }.Concat(relativePath).ToArray());
    }

    var directory = new DirectoryInfo(AppContext.BaseDirectory);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(directory.FullName, "CodexGuardian.Tests.csproj")))
        {
            var workDirectory = directory.Parent;
            return workDirectory is null
                ? null
                : Path.Combine(new[] { workDirectory.FullName }.Concat(relativePath).ToArray());
        }

        directory = directory.Parent;
    }

    return null;
}

string NormalizeLineEndings(string source) =>
    source.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');

string TrimPowerShellContinuation(string line)
{
    var trimmed = line.Trim();
    return trimmed.EndsWith('`') ? trimmed[..^1].TrimEnd() : trimmed;
}

int PowerShellGroupingDelta(string line)
{
    var delta = 0;
    var inSingleQuote = false;
    var inDoubleQuote = false;
    var escaped = false;
    for (var index = 0; index < line.Length; index++)
    {
        var character = line[index];
        if (inSingleQuote)
        {
            if (character == '\'' && index + 1 < line.Length && line[index + 1] == '\'')
            {
                index++;
            }
            else if (character == '\'')
            {
                inSingleQuote = false;
            }
            continue;
        }
        if (escaped)
        {
            escaped = false;
            continue;
        }
        if (inDoubleQuote)
        {
            if (character == '`')
            {
                escaped = true;
            }
            else if (character == '"')
            {
                inDoubleQuote = false;
            }
            continue;
        }
        if (character == '`')
        {
            escaped = true;
            continue;
        }
        if (character == '#')
        {
            break;
        }
        if (character == '\'')
        {
            inSingleQuote = true;
        }
        else if (character == '"')
        {
            inDoubleQuote = true;
        }
        else if (character == '(')
        {
            delta++;
        }
        else if (character == ')')
        {
            delta--;
        }
    }
    return delta;
}

(bool Valid, List<(int Index, int Delta, int DepthBefore)> Events) ReadPowerShellBraceEvents(
    string source)
{
    var normalized = NormalizeLineEndings(source);
    var events = new List<(int Index, int Delta, int DepthBefore)>();
    var depth = 0;
    var inSingleQuote = false;
    var inDoubleQuote = false;
    var inLineComment = false;
    var inBlockComment = false;
    var escaped = false;
    var hereQuote = '\0';

    for (var index = 0; index < normalized.Length; index++)
    {
        var character = normalized[index];
        if (hereQuote != '\0')
        {
            if (index == 0 || normalized[index - 1] == '\n')
            {
                var cursor = index;
                if (cursor + 1 < normalized.Length &&
                    normalized[cursor] == hereQuote &&
                    normalized[cursor + 1] == '@')
                {
                    var tail = cursor + 2;
                    while (tail < normalized.Length && normalized[tail] is ' ' or '\t')
                    {
                        tail++;
                    }
                    if (tail == normalized.Length || normalized[tail] == '\n')
                    {
                        hereQuote = '\0';
                        index = cursor + 1;
                    }
                }
            }
            continue;
        }
        if (inLineComment)
        {
            if (character == '\n')
            {
                inLineComment = false;
            }
            continue;
        }
        if (inBlockComment)
        {
            if (character == '#' && index + 1 < normalized.Length && normalized[index + 1] == '>')
            {
                inBlockComment = false;
                index++;
            }
            continue;
        }
        if (escaped)
        {
            escaped = false;
            continue;
        }
        if (inSingleQuote)
        {
            if (character == '\'' && index + 1 < normalized.Length && normalized[index + 1] == '\'')
            {
                index++;
            }
            else if (character == '\'')
            {
                inSingleQuote = false;
            }
            continue;
        }
        if (inDoubleQuote)
        {
            if (character == '`')
            {
                escaped = true;
            }
            else if (character == '"')
            {
                inDoubleQuote = false;
            }
            continue;
        }
        if (character == '`')
        {
            escaped = true;
            continue;
        }
        if (character == '<' && index + 1 < normalized.Length && normalized[index + 1] == '#')
        {
            inBlockComment = true;
            index++;
            continue;
        }
        if (character == '#')
        {
            inLineComment = true;
            continue;
        }
        if (character == '@' && index + 1 < normalized.Length && normalized[index + 1] is '\'' or '"')
        {
            var tail = index + 2;
            while (tail < normalized.Length && normalized[tail] is ' ' or '\t')
            {
                tail++;
            }
            if (tail < normalized.Length && normalized[tail] != '\n')
            {
                return (false, events);
            }
            hereQuote = normalized[index + 1];
            index++;
            continue;
        }
        if (character == '\'')
        {
            inSingleQuote = true;
            continue;
        }
        if (character == '"')
        {
            inDoubleQuote = true;
            continue;
        }
        if (character == '{')
        {
            events.Add((index, 1, depth));
            depth++;
        }
        else if (character == '}')
        {
            if (depth == 0)
            {
                return (false, events);
            }
            events.Add((index, -1, depth));
            depth--;
        }
    }

    var valid = depth == 0 &&
                !inSingleQuote &&
                !inDoubleQuote &&
                !inBlockComment &&
                !escaped &&
                hereQuote == '\0';
    return (valid, events);
}

(int HeaderIndex, int OpenBraceIndex, int CloseBraceIndex, int ParentDepth, string Text)?
    FindSinglePowerShellScopedBlock(string source, string exactHeaderLine)
{
    var normalized = NormalizeLineEndings(source);
    var braceScan = ReadPowerShellBraceEvents(normalized);
    if (!braceScan.Valid)
    {
        return null;
    }

    var lines = normalized.Split('\n');
    var offsets = new int[lines.Length];
    var cursor = 0;
    for (var index = 0; index < lines.Length; index++)
    {
        offsets[index] = cursor;
        cursor += lines[index].Length + 1;
    }

    var candidates = new List<(int HeaderIndex, int OpenBraceIndex, int ParentDepth)>();
    for (var index = 0; index < lines.Length; index++)
    {
        if (!string.Equals(
                TrimPowerShellContinuation(lines[index]),
                exactHeaderLine,
                StringComparison.Ordinal))
        {
            continue;
        }
        var relativeOpenBrace = lines[index].LastIndexOf('{');
        if (relativeOpenBrace < 0)
        {
            continue;
        }
        var openBraceIndex = offsets[index] + relativeOpenBrace;
        var matchingOpenEvents = braceScan.Events
            .Where(item => item.Index == openBraceIndex && item.Delta == 1)
            .ToArray();
        if (matchingOpenEvents.Length == 1)
        {
            candidates.Add((offsets[index], openBraceIndex, matchingOpenEvents[0].DepthBefore));
        }
    }
    if (candidates.Count != 1)
    {
        return null;
    }

    var candidate = candidates[0];
    var matchingCloseEvents = braceScan.Events
        .Where(item =>
            item.Index > candidate.OpenBraceIndex &&
            item.Delta == -1 &&
            item.DepthBefore == candidate.ParentDepth + 1)
        .ToArray();
    if (matchingCloseEvents.Length == 0)
    {
        return null;
    }
    var closeBraceIndex = matchingCloseEvents[0].Index;
    return (
        candidate.HeaderIndex,
        candidate.OpenBraceIndex,
        closeBraceIndex,
        candidate.ParentDepth,
        normalized[candidate.HeaderIndex..(closeBraceIndex + 1)]);
}

int GetPowerShellBraceDepthAt(string source, int targetIndex)
{
    var normalized = NormalizeLineEndings(source);
    if (targetIndex < 0 || targetIndex > normalized.Length)
    {
        return -1;
    }
    var braceScan = ReadPowerShellBraceEvents(normalized);
    if (!braceScan.Valid)
    {
        return -1;
    }
    var depth = 0;
    foreach (var item in braceScan.Events)
    {
        if (item.Index >= targetIndex)
        {
            break;
        }
        depth += item.Delta;
    }
    return depth;
}

bool[] ReadPowerShellExecutableMask(string source)
{
    var normalized = NormalizeLineEndings(source);
    var executable = new bool[normalized.Length];
    var inSingleQuote = false;
    var inDoubleQuote = false;
    var inLineComment = false;
    var inBlockComment = false;
    var escaped = false;
    var hereQuote = '\0';

    for (var index = 0; index < normalized.Length; index++)
    {
        var character = normalized[index];
        if (hereQuote != '\0')
        {
            if ((index == 0 || normalized[index - 1] == '\n') &&
                index + 1 < normalized.Length &&
                normalized[index] == hereQuote &&
                normalized[index + 1] == '@')
            {
                var tail = index + 2;
                while (tail < normalized.Length && normalized[tail] is ' ' or '\t')
                {
                    tail++;
                }
                if (tail == normalized.Length || normalized[tail] == '\n')
                {
                    executable[index] = true;
                    executable[index + 1] = true;
                    hereQuote = '\0';
                    index++;
                }
            }
            continue;
        }
        if (inLineComment)
        {
            if (character == '\n')
            {
                inLineComment = false;
            }
            continue;
        }
        if (inBlockComment)
        {
            if (character == '#' && index + 1 < normalized.Length && normalized[index + 1] == '>')
            {
                inBlockComment = false;
                index++;
            }
            continue;
        }
        if (inSingleQuote)
        {
            if (character == '\'' && index + 1 < normalized.Length && normalized[index + 1] == '\'')
            {
                index++;
            }
            else if (character == '\'')
            {
                inSingleQuote = false;
            }
            continue;
        }
        if (escaped)
        {
            executable[index] = true;
            escaped = false;
            continue;
        }
        if (inDoubleQuote)
        {
            if (character == '`')
            {
                escaped = true;
            }
            else if (character == '"')
            {
                inDoubleQuote = false;
            }
            continue;
        }
        if (character == '<' && index + 1 < normalized.Length && normalized[index + 1] == '#')
        {
            inBlockComment = true;
            index++;
            continue;
        }
        if (character == '#')
        {
            inLineComment = true;
            continue;
        }

        executable[index] = true;
        if (character == '`')
        {
            escaped = true;
        }
        else if (character == '@' &&
                 index + 1 < normalized.Length &&
                 normalized[index + 1] is '\'' or '"')
        {
            var tail = index + 2;
            while (tail < normalized.Length && normalized[tail] is ' ' or '\t')
            {
                tail++;
            }
            if (tail == normalized.Length || normalized[tail] == '\n')
            {
                executable[index + 1] = true;
                hereQuote = normalized[index + 1];
                index++;
            }
        }
        else if (character == '\'')
        {
            inSingleQuote = true;
        }
        else if (character == '"')
        {
            inDoubleQuote = true;
        }
    }

    return executable;
}

List<(int Index, string Text)> ReadPowerShellCommandBlocks(string source, string firstLine)
{
    var normalized = NormalizeLineEndings(source);
    var executable = ReadPowerShellExecutableMask(normalized);
    var lines = normalized.Split('\n');
    var offsets = new int[lines.Length];
    var cursor = 0;
    for (var index = 0; index < lines.Length; index++)
    {
        offsets[index] = cursor;
        cursor += lines[index].Length + 1;
    }

    var blocks = new List<(int Index, string Text)>();
    for (var index = 0; index < lines.Length; index++)
    {
        if (!string.Equals(
                TrimPowerShellContinuation(lines[index]),
                firstLine,
                StringComparison.Ordinal))
        {
            continue;
        }
        var firstTokenColumn = 0;
        while (firstTokenColumn < lines[index].Length &&
               lines[index][firstTokenColumn] is ' ' or '\t')
        {
            firstTokenColumn++;
        }
        if (firstTokenColumn >= lines[index].Length ||
            !executable[offsets[index] + firstTokenColumn])
        {
            continue;
        }

        var endIndex = index;
        var groupingDepth = 0;
        while (true)
        {
            groupingDepth += PowerShellGroupingDelta(lines[endIndex]);
            var explicitContinuation = lines[endIndex].TrimEnd().EndsWith('`');
            if (endIndex + 1 >= lines.Length || (!explicitContinuation && groupingDepth <= 0))
            {
                break;
            }
            endIndex++;
        }

        var startOffset = offsets[index];
        var endOffset = offsets[endIndex] + lines[endIndex].Length;
        blocks.Add((startOffset, normalized[startOffset..endOffset]));
        index = endIndex;
    }

    return blocks;
}

int FindSinglePowerShellCommandIndex(string source, string firstLine)
{
    var blocks = ReadPowerShellCommandBlocks(source, firstLine);
    return blocks.Count == 1 ? blocks[0].Index : -1;
}

int FindSinglePowerShellBlockIndex(
    IReadOnlyList<(int Index, string Text)> blocks,
    params string[] requiredFragments)
{
    var matches = blocks
        .Where(block => requiredFragments.All(fragment =>
            block.Text.Contains(fragment, StringComparison.Ordinal)))
        .ToArray();
    return matches.Length == 1 ? matches[0].Index : -1;
}

string SlicePowerShellFunction(string source, string name)
{
    return FindSinglePowerShellScopedBlock(source, $"function {name} {{")?.Text ?? string.Empty;
}

string SlicePackageMain(string source)
{
    var normalized = NormalizeLineEndings(source);
    const string marker =
        "Assert-GuardianStopped\n" +
        "Assert-NoSourceBuildResidue\n" +
        "Assert-DDriveCapacity\n";
    var start = normalized.IndexOf(marker, StringComparison.Ordinal);
    return start >= 0 ? normalized[start..] : string.Empty;
}

string[] ParseLiteralPowerShellArray(string commandBlock, string parameterName)
{
    var lines = NormalizeLineEndings(commandBlock).Split('\n');
    var startLine = $"-{parameterName} @(";
    var start = Array.FindIndex(lines, line =>
        string.Equals(TrimPowerShellContinuation(line), startLine, StringComparison.Ordinal));
    if (start < 0)
    {
        return [];
    }

    var values = new List<string>();
    for (var index = start + 1; index < lines.Length; index++)
    {
        var line = TrimPowerShellContinuation(lines[index]);
        if (string.Equals(line, ")", StringComparison.Ordinal))
        {
            return values.ToArray();
        }

        var literal = Regex.Match(line, "^'(?<value>[^']*)',?$");
        if (!literal.Success)
        {
            return [];
        }
        values.Add(literal.Groups["value"].Value);
    }

    return [];
}

async Task<(int ExitCode, string StandardOutput, string StandardError)> RunExternalProcessAsync(
    string fileName,
    params string[] arguments)
{
    try
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return (-1, string.Empty, "process-start-returned-null");
        }

        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
        }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            return (-1, await output, "process-timeout\n" + await error);
        }

        return (process.ExitCode, await output, await error);
    }
    catch (Exception exception) when (
        exception is InvalidOperationException or System.ComponentModel.Win32Exception or IOException)
    {
        return (-1, string.Empty, exception.GetType().Name + ": " + exception.Message);
    }
}

async Task<(bool Success, string Detail)> ValidatePowerShellSyntaxAsync(string path)
{
    var powershell = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe");
    if (!File.Exists(powershell))
    {
        return (false, "fixed-windows-powershell-missing");
    }

    var pathBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(path));
    var script = $$"""
        $path = [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String('{{pathBase64}}'))
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $path,
            [ref]$tokens,
            [ref]$errors)
        if ($errors.Count -ne 0) {
            [Console]::Error.WriteLine(($errors | ForEach-Object {
                'line=' + $_.Extent.StartLineNumber + ' message=' + $_.Message
            }) -join ' | ')
            exit 1
        }
        [Console]::Out.WriteLine('AST_PARSE_OK')
        """;
    var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
    var result = await RunExternalProcessAsync(
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encodedCommand);
    var success = result.ExitCode == 0 &&
                  string.Equals(result.StandardOutput.Trim(), "AST_PARSE_OK", StringComparison.Ordinal) &&
                  string.IsNullOrWhiteSpace(result.StandardError);
    return (success, success
        ? "AST_PARSE_OK"
        : $"exit={result.ExitCode} stdout={result.StandardOutput.Trim()} stderr={result.StandardError.Trim()}");
}

TurnSnapshot Turn(
    string status,
    string? code = null,
    int? httpStatus = null,
    string input = "do work",
    bool assistant = false,
    bool work = false,
    string? error = null,
    bool confirmedTerminal = false)
{
    return new TurnSnapshot(
        Guid.NewGuid().ToString(),
        status,
        error,
        code,
        httpStatus,
        input,
        false,
        assistant,
        work,
        "fingerprint",
        DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        HasConfirmedLocalTerminal: confirmedTerminal,
        HasUserMessage: !string.IsNullOrWhiteSpace(input),
        HasFinalAssistantOutput:
            assistant && string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase),
        HasCommentaryOutput:
            assistant && !string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase),
        HasReasoningOutput: work,
        HasCompleteItemEvidence: true,
        IsSingleTextUserInput: !string.IsNullOrWhiteSpace(input));
}

JsonElement Json(string value)
{
    using var document = JsonDocument.Parse(value);
    return document.RootElement.Clone();
}

if (args.Contains("--appserver-job-host", StringComparer.OrdinalIgnoreCase))
{
    var hostData = Path.Combine(Path.GetTempPath(), "CodexGuardian", "job-host-" + Environment.ProcessId);
    Directory.CreateDirectory(hostData);
    using var hostLog = new GuardianLog(hostData);
    await using var hostClient = new AppServerClient(new CodexCliLocator(), hostLog);
    await using var hostSession = await hostClient.OpenReadSessionAsync();
    _ = await hostClient.ListThreadsAsync(1, includeSubAgents: false);
    Console.WriteLine($"APP_SERVER_JOB_HOST_READY {Environment.ProcessId}");
    Console.Out.Flush();
    await Task.Delay(Timeout.InfiniteTimeSpan);
    return 0;
}

if (args.Contains("--idle-resource-host", StringComparer.OrdinalIgnoreCase))
{
    static string? ReadArgumentValue(string[] values, string name)
    {
        var index = Array.FindIndex(values, value => string.Equals(value, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < values.Length ? values[index + 1] : null;
    }

    var durationText = ReadArgumentValue(args, "--duration-seconds");
    var targetedRefreshProbe = args.Contains(
        "--targeted-refresh-probe",
        StringComparer.OrdinalIgnoreCase);
    var durationSeconds = int.TryParse(durationText, out var parsedDuration)
        ? Math.Clamp(parsedDuration, 10, 600)
        : 75;
    var hostData = ReadArgumentValue(args, "--data-dir") ??
                   Path.Combine(Path.GetTempPath(), "CodexGuardian", "idle-resource-host-" + Environment.ProcessId);
    Directory.CreateDirectory(hostData);
    var hostSessions = Path.Combine(hostData, "sessions");
    Directory.CreateDirectory(hostSessions);
    using var hostLog = new GuardianLog(hostData);
    var hostSettings = new AppSettings
    {
        MonitoringEnabled = true,
        MonitorOnly = true,
        RecentThreadLimit = 30,
        RecentThreadLookbackDays = 14,
        IncludeSubAgents = false
    };
    var hostLocator = new CodexCliLocator();
    var hostAppServer = new AppServerClient(hostLocator, hostLog);
    var hostDesktop = new DesktopIpcClient(hostLog);
    var hostClassifier = new RecoveryClassifier();
    var hostJournal = new RecoveryOperationJournal(hostData);
    var hostHistory = new LocalConversationHistoryReader(hostSessions);
    var hostRecovery = new RecoveryService(
        hostAppServer,
        hostDesktop,
        new DesktopThreadOwnerActivator(hostDesktop, hostLog),
        hostJournal,
        hostLog);
    var hostEngine = new GuardianEngine(
        hostSettings,
        hostAppServer,
        hostDesktop,
        hostRecovery,
        hostClassifier,
        hostHistory,
        hostLog);
    var firstSnapshot = new TaskCompletionSource<GuardianTaskSnapshot>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    hostEngine.SnapshotUpdated += (_, snapshot) => firstSnapshot.TrySetResult(snapshot);
    try
    {
        hostEngine.Start();
        var initialSnapshot = await firstSnapshot.Task.WaitAsync(TimeSpan.FromSeconds(45));
        await Task.Delay(TimeSpan.FromSeconds(2));
        if (!targetedRefreshProbe)
        {
            await Task.Delay(TimeSpan.FromSeconds(15));
        }
        var journalBefore = await hostJournal.ReadAsync();
        var fileIndexBefore = hostHistory.FileIndexRefreshCount;
        Console.WriteLine($"IDLE_RESOURCE_HOST_READY {Environment.ProcessId}");
        Console.Out.Flush();
        using var hostProcess = Process.GetCurrentProcess();
        hostProcess.Refresh();
        var cpuBefore = hostProcess.TotalProcessorTime;
        var hostResourcesBefore = AppServerClient.CaptureProcessSnapshot(hostProcess);
        var helperBefore = hostAppServer.CaptureProcessSnapshot();
        var lastHelperProcessId = hostAppServer.LastStartedProcessId;
        var helperProcessStoppedBefore = !IsProcessRunning(lastHelperProcessId);
        var startsBefore = hostAppServer.ProcessStartCount;
        var requestsBefore = hostAppServer.RequestCount;
        var listsBefore = hostAppServer.ThreadListRequestCount;
        var targetedBefore = hostAppServer.TargetedReadRequestCount;
        if (targetedRefreshProbe)
        {
            var target = initialSnapshot.States
                .FirstOrDefault(state => !state.Thread.IsArchived && !state.Thread.IsEphemeral);
            if (target is null)
            {
                Console.WriteLine("TARGETED_REFRESH_RESULT accepted=False reason=no-active-task");
                return 1;
            }

            var refreshSnapshot = new TaskCompletionSource<GuardianTaskSnapshot>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            hostEngine.SnapshotUpdated += (_, snapshot) => refreshSnapshot.TrySetResult(snapshot);
            var notificationHandler = typeof(GuardianEngine).GetMethod(
                "OnAppServerNotificationReceived",
                BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new MissingMethodException(nameof(GuardianEngine), "OnAppServerNotificationReceived");
            notificationHandler.Invoke(
                hostEngine,
                [hostAppServer, new AppServerNotificationEventArgs("turn/completed", target.Thread.Id, target.Turn?.Id)]);
            await refreshSnapshot.Task.WaitAsync(TimeSpan.FromSeconds(15));
        }
        else
        {
            await Task.Delay(TimeSpan.FromSeconds(durationSeconds));
        }
        hostProcess.Refresh();
        var cpuDelta = hostProcess.TotalProcessorTime - cpuBefore;
        var hostResourcesAfter = AppServerClient.CaptureProcessSnapshot(hostProcess);
        var hostReadDelta = hostResourcesAfter.ReadTransferBytes >= hostResourcesBefore.ReadTransferBytes
            ? hostResourcesAfter.ReadTransferBytes - hostResourcesBefore.ReadTransferBytes
            : ulong.MaxValue;
        var hostWriteDelta = hostResourcesAfter.WriteTransferBytes >= hostResourcesBefore.WriteTransferBytes
            ? hostResourcesAfter.WriteTransferBytes - hostResourcesBefore.WriteTransferBytes
            : ulong.MaxValue;
        var helperAfter = hostAppServer.CaptureProcessSnapshot();
        var helperProcessStoppedAfter = !IsProcessRunning(lastHelperProcessId);
        var helperCpuDelta = helperAfter.TotalProcessorTime - helperBefore.TotalProcessorTime;
        var helperReadDelta = helperAfter.ReadTransferBytes >= helperBefore.ReadTransferBytes
            ? helperAfter.ReadTransferBytes - helperBefore.ReadTransferBytes
            : ulong.MaxValue;
        var helperWriteDelta = helperAfter.WriteTransferBytes >= helperBefore.WriteTransferBytes
            ? helperAfter.WriteTransferBytes - helperBefore.WriteTransferBytes
            : ulong.MaxValue;
        var journalAfter = await hostJournal.ReadAsync();
        var fileIndexDelta = hostHistory.FileIndexRefreshCount - fileIndexBefore;
        var startDelta = hostAppServer.ProcessStartCount - startsBefore;
        var requestDelta = hostAppServer.RequestCount - requestsBefore;
        var listDelta = hostAppServer.ThreadListRequestCount - listsBefore;
        var targetedDelta = hostAppServer.TargetedReadRequestCount - targetedBefore;
        var cpuLimit = TimeSpan.FromSeconds(Math.Max(1, durationSeconds * 0.02));
        var sameLiveHelper = helperBefore.IsRunning && helperAfter.IsRunning &&
                             helperBefore.ProcessId == helperAfter.ProcessId && hostAppServer.IsConnected;
        var helperRemainedStopped = !helperBefore.IsRunning && !helperAfter.IsRunning &&
                                    helperProcessStoppedBefore && helperProcessStoppedAfter &&
                                    !hostAppServer.IsConnected;
        var hostIoCountersAvailable = hostResourcesBefore.HasIoCounters && hostResourcesAfter.HasIoCounters;
        var helperIoCountersAvailable = helperBefore.HasIoCounters && helperAfter.HasIoCounters;
        var journalStable = journalBefore.Generation == journalAfter.Generation;
        var idleAccepted = targetedRefreshProbe
            ? sameLiveHelper && hostIoCountersAvailable && helperIoCountersAvailable &&
              journalStable && fileIndexDelta == 0 &&
              startDelta == 0 && requestDelta > 0 &&
              listDelta == 0 && targetedDelta > 0
            : startDelta == 0 && requestDelta == 0 && listDelta == 0 && targetedDelta == 0 &&
              sameLiveHelper && hostIoCountersAvailable && helperIoCountersAvailable &&
              journalStable && fileIndexDelta == 0 &&
              cpuDelta <= cpuLimit &&
              helperCpuDelta <= cpuLimit &&
              hostReadDelta <= 1 * 1024 * 1024 && hostWriteDelta <= 1 * 1024 * 1024 &&
              helperReadDelta <= 16 * 1024 * 1024 && helperWriteDelta <= 4 * 1024 * 1024;
        var resultName = targetedRefreshProbe ? "TARGETED_REFRESH_RESULT" : "IDLE_RESOURCE_RESULT";
        Console.WriteLine(
            $"{resultName} accepted={idleAccepted} cpuMs={cpuDelta.TotalMilliseconds:F0} " +
            $"hostReadTransfer={hostReadDelta} hostWriteTransfer={hostWriteDelta} helperPid={helperAfter.ProcessId} " +
            $"helperAlive={sameLiveHelper} helperStopped={helperRemainedStopped} " +
            $"lastHelperPid={lastHelperProcessId} " +
            $"hostIoCounters={hostIoCountersAvailable} helperIoCounters={helperIoCountersAvailable} " +
            $"helperCpuMs={helperCpuDelta.TotalMilliseconds:F0} " +
            $"helperReadTransfer={helperReadDelta} helperWriteTransfer={helperWriteDelta} " +
            $"journalGeneration={journalAfter.Generation} fileIndexRefreshes={fileIndexDelta} " +
            $"helperStarts={startDelta} requests={requestDelta} lists={listDelta} targetedReads={targetedDelta}");
        Console.Out.Flush();
        if (!idleAccepted)
        {
            return 1;
        }
    }
    finally
    {
        await hostEngine.DisposeAsync();
    }

    return 0;
}

{
    var disconnectCount = 0;
    await using var idleDisconnect = new IdleDisconnectScheduler(
        TimeSpan.FromMilliseconds(25),
        _ =>
        {
            Interlocked.Increment(ref disconnectCount);
            return Task.CompletedTask;
        });

    idleDisconnect.Schedule();
    var canceledIdle = idleDisconnect.CancelPending();
    await canceledIdle.WaitAsync(TimeSpan.FromSeconds(1));
    Assert(
        Volatile.Read(ref disconnectCount) == 0 && !idleDisconnect.HasPending,
        "a new read session cancels the pending idle disconnect and preserves the live connection");

    idleDisconnect.Schedule();
    await idleDisconnect.PendingTask.WaitAsync(TimeSpan.FromSeconds(1));
    Assert(
        Volatile.Read(ref disconnectCount) == 1 && !idleDisconnect.HasPending,
        "an unused read connection disconnects once after the idle reuse window");
    Assert(
        AppServerClient.ReadSessionIdleDelay == TimeSpan.FromSeconds(5),
        "an unpinned diagnostic session retains only a bounded five-second helper reuse window");
    Assert(
        AppServerClient.DetermineReadSessionReleaseAction(isConnected: true) ==
        ReadSessionReleaseAction.ScheduleIdleDisconnect &&
        AppServerClient.DetermineReadSessionReleaseAction(
            isConnected: true,
            monitoringPinned: true) == ReadSessionReleaseAction.KeepConnected &&
        AppServerClient.DetermineReadSessionReleaseAction(isConnected: false) ==
        ReadSessionReleaseAction.DisconnectBrokenConnection,
        "read-session release preserves a monitoring subscription and reaps unpinned or broken helpers");
}

{
    var leaseRoot = Path.Combine(Path.GetTempPath(), "CodexGuardian", "monitoring-lease-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(leaseRoot);
    try
    {
        using var leaseLog = new GuardianLog(leaseRoot);
        await using var leaseClient = new AppServerClient(new CodexCliLocator(), leaseLog);
        var firstLease = leaseClient.AcquireMonitoringLease();
        var secondLease = leaseClient.AcquireMonitoringLease();
        Assert(
            leaseClient.MonitoringLeaseCount == 2,
            "monitoring leases reference-count one persistent read-only app-server subscription");
        await firstLease.DisposeAsync();
        await firstLease.DisposeAsync();
        await secondLease.DisposeAsync();
        Assert(
            leaseClient.MonitoringLeaseCount == 0,
            "monitoring lease release is idempotent and returns the helper to bounded idle cleanup");
    }
    finally
    {
        Directory.Delete(leaseRoot, recursive: true);
    }
}

{
    var callbackEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var disconnectCount = 0;
    using var fakeSessionGate = new SemaphoreSlim(0, 1);
    await using var waitingDisconnect = new IdleDisconnectScheduler(
        TimeSpan.Zero,
        async cancellationToken =>
        {
            callbackEntered.TrySetResult();
            await fakeSessionGate.WaitAsync(cancellationToken);
            Interlocked.Increment(ref disconnectCount);
        });

    waitingDisconnect.Schedule();
    await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
    var canceledWaiter = waitingDisconnect.CancelPending();
    await canceledWaiter.WaitAsync(TimeSpan.FromSeconds(1));
    fakeSessionGate.Release();
    Assert(
        Volatile.Read(ref disconnectCount) == 0 && !waitingDisconnect.HasPending,
        "session acquisition cancels an idle disconnect that is waiting for the session gate");
}

{
    var disconnectCount = 0;
    var disposableDisconnect = new IdleDisconnectScheduler(
        TimeSpan.FromMinutes(1),
        _ =>
        {
            Interlocked.Increment(ref disconnectCount);
            return Task.CompletedTask;
        });
    disposableDisconnect.Schedule();
    await disposableDisconnect.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
    await disposableDisconnect.DisposeAsync();
    Assert(
        Volatile.Read(ref disconnectCount) == 0 && !disposableDisconnect.HasPending,
        "disposing the app-server idle scheduler cancels the delay immediately and is idempotent");
}

{
    var queue = new ThreadRefreshQueue(capacity: 2);
    var firstThreadId = Guid.NewGuid().ToString();
    var secondThreadId = Guid.NewGuid().ToString();
    var acceptedDuplicates = true;
    for (var index = 0; index < 100; index++)
    {
        acceptedDuplicates &= queue.TryEnqueue(firstThreadId, ThreadRefreshKind.StateChanged);
    }
    _ = queue.TryEnqueue(firstThreadId, ThreadRefreshKind.ReleaseDesktopWaiter);
    var acceptedSecond = queue.TryEnqueue(secondThreadId, ThreadRefreshKind.StateChanged);
    var rejectedOverflow = !queue.TryEnqueue(Guid.NewGuid().ToString(), ThreadRefreshKind.StateChanged);
    var drained = queue.Drain();
    Assert(
        acceptedDuplicates && acceptedSecond && rejectedOverflow &&
        drained.Count == 2 && queue.Count == 0 &&
        drained[firstThreadId].HasFlag(ThreadRefreshKind.StateChanged) &&
        drained[firstThreadId].HasFlag(ThreadRefreshKind.ReleaseDesktopWaiter),
        "thread refresh events coalesce by ID and fail closed at the bounded capacity");
}

{
    var coordinator = new ReconciliationCycleCoordinator();
    var requestCount = 0;
    var first = coordinator.Request(() => requestCount++);
    var firstCycle = coordinator.Begin(() => { });
    var second = coordinator.Request(() => requestCount++);
    firstCycle?.Complete();
    Assert(
        requestCount == 2 && first.IsCompletedSuccessfully && !second.IsCompleted,
        "a running reconciliation cannot complete a manual request queued for the next generation");

    var secondCycle = coordinator.Begin(() => { });
    secondCycle?.Complete();
    Assert(
        second.IsCompletedSuccessfully,
        "the next reconciliation generation completes only its own manual waiters");

    var pending = coordinator.Request(() => requestCount++);
    coordinator.CancelPending();
    Assert(
        pending.IsCanceled,
        "stopping monitoring cancels only manual reconciliation requests that have not started");
}

{
    var state = 0;
    var firstConnect = DesktopIpcClient.TryTransitionConnectionState(ref state, connected: true);
    var duplicateConnect = DesktopIpcClient.TryTransitionConnectionState(ref state, connected: true);
    var firstDisconnect = DesktopIpcClient.TryTransitionConnectionState(ref state, connected: false);
    var duplicateDisconnect = DesktopIpcClient.TryTransitionConnectionState(ref state, connected: false);
    Assert(
        firstConnect && !duplicateConnect && firstDisconnect && !duplicateDisconnect,
        "Desktop and app-server connection notifications publish only real state edges");
}

{
    var revisionWatermarks = new ConcurrentDictionary<string, long>(StringComparer.OrdinalIgnoreCase);
    var streamKey = GuardianEngine.BuildDesktopStreamKey("thread", "host-a", "owner");
    Assert(
        GuardianEngine.ApplyDesktopStreamRevision(
            revisionWatermarks,
            streamKey,
            "snapshot",
            null,
            7) == DesktopStreamRevisionDisposition.Snapshot &&
        GuardianEngine.ApplyDesktopStreamRevision(
            revisionWatermarks,
            streamKey,
            "patches",
            7,
            8) == DesktopStreamRevisionDisposition.AcceptedPatch &&
        GuardianEngine.ApplyDesktopStreamRevision(
            revisionWatermarks,
            streamKey,
            "patches",
            7,
            8) == DesktopStreamRevisionDisposition.Stale &&
        GuardianEngine.ApplyDesktopStreamRevision(
            revisionWatermarks,
            streamKey,
            "patches",
            10,
            11) == DesktopStreamRevisionDisposition.Gap &&
        GuardianEngine.ApplyDesktopStreamRevision(
            revisionWatermarks,
            streamKey,
            "snapshot",
            null,
            1) == DesktopStreamRevisionDisposition.Snapshot &&
        revisionWatermarks[streamKey] == 1 &&
        GuardianEngine.BuildDesktopStreamKey("thread", "host-b", "owner") != streamKey,
        "Desktop stream patches require a contiguous epoch while a new host-scoped snapshot resets the revision baseline");
    Assert(
        GuardianEngine.ShouldAcceptDesktopConversationSignal(
            Guid.NewGuid().ToString("D"),
            isKnownInteractiveThread: true,
            isInThreadDirectory: false,
            hasRecoveryAttempt: false) &&
        GuardianEngine.ShouldAcceptDesktopConversationSignal(
            Guid.NewGuid().ToString("D"),
            isKnownInteractiveThread: false,
            isInThreadDirectory: true,
            hasRecoveryAttempt: false) &&
        !GuardianEngine.ShouldAcceptDesktopConversationSignal(
            Guid.NewGuid().ToString("D"),
            isKnownInteractiveThread: false,
            isInThreadDirectory: false,
            hasRecoveryAttempt: false) &&
        !GuardianEngine.ShouldAcceptDesktopConversationSignal(
            "desktop-capability-probe",
            isKnownInteractiveThread: true,
            isInThreadDirectory: true,
            hasRecoveryAttempt: true),
        "Desktop activity ignores random capability probes and unverified task identifiers");
}

await WithRecoveryJournalTestAsync("Desktop revision gap veto", async root =>
{
    var sessionsRoot = Path.Combine(root, "sessions");
    Directory.CreateDirectory(sessionsRoot);
    using var gapLog = new GuardianLog(root);
    await using var gapAppServer = new AppServerClient(new CodexCliLocator(), gapLog);
    await using var gapDesktop = new DesktopIpcClient(gapLog);
    var gapRecovery = new RecoveryService(
        gapAppServer,
        gapDesktop,
        new DesktopThreadOwnerActivator(gapDesktop, gapLog),
        new RecoveryOperationJournal(root),
        gapLog);
    await using var gapEngine = new GuardianEngine(
        new AppSettings { MonitorOnly = true, IncludeSubAgents = false },
        gapAppServer,
        gapDesktop,
        gapRecovery,
        new RecoveryClassifier(),
        new LocalConversationHistoryReader(sessionsRoot),
        gapLog);
    var knownThreadsField = typeof(GuardianEngine).GetField(
        "_knownInteractiveThreadIds",
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(nameof(GuardianEngine), "_knownInteractiveThreadIds");
    var activityVetoesField = typeof(GuardianEngine).GetField(
        "_desktopActivityVetoes",
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(nameof(GuardianEngine), "_desktopActivityVetoes");
    var activityHandler = typeof(GuardianEngine).GetMethod(
        "OnDesktopActivityReceived",
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingMethodException(nameof(GuardianEngine), "OnDesktopActivityReceived");
    var knownThreads = (ConcurrentDictionary<string, byte>)knownThreadsField.GetValue(gapEngine)!;
    var activityVetoes =
        (ConcurrentDictionary<string, ConcurrentDictionary<string, byte>>)activityVetoesField.GetValue(gapEngine)!;
    var threadId = Guid.NewGuid().ToString("D");
    const string ownerClientId = "desktop-owner-gap-test";
    knownThreads[threadId] = 0;

    void SendDesktopActivity(string json)
    {
        var activity = DesktopIpcClient.ParseActivityEvent(Json(json))
            ?? throw new InvalidOperationException("Desktop activity test payload was not parsed.");
        activityHandler.Invoke(gapEngine, [gapDesktop, activity]);
    }

    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"{{ownerClientId}}",
          "version":11,
          "params":{
            "conversationId":"{{threadId}}",
            "hostId":"local",
            "change":{
              "type":"snapshot",
              "revision":7,
              "conversationState":{
                "threadRuntimeStatus":{"type":"active","activeFlags":[]}
              }
            }
          }
        }
        """);
    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"{{ownerClientId}}",
          "version":11,
          "params":{
            "conversationId":"{{threadId}}",
            "hostId":"local",
            "change":{
              "type":"patches",
              "baseRevision":10,
              "revision":11,
              "patches":[{"op":"replace","path":["threadRuntimeStatus","type"],"value":"idle"}]
            }
          }
        }
        """);
    var firstGapGeneration = gapEngine.CaptureDesktopRevisionGaps(threadId);
    var oldActiveVetoPreserved = activityVetoes.TryGetValue(threadId, out var sourceVetoes) &&
                                 sourceVetoes.ContainsKey("stream:" + ownerClientId);
    Assert(
        firstGapGeneration.Count == 1 && gapEngine.HasDesktopRevisionGap(threadId) &&
        gapEngine.HasDesktopActivityVeto(threadId) && oldActiveVetoPreserved,
        "a revision gap ignores its idle payload and conservatively preserves the prior active veto");

    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"{{ownerClientId}}",
          "version":11,
          "params":{
            "conversationId":"{{threadId}}",
            "hostId":"local",
            "change":{
              "type":"patches",
              "baseRevision":20,
              "revision":21,
              "patches":[{"op":"replace","path":["threadRuntimeStatus","type"],"value":"idle"}]
            }
          }
        }
        """);
    gapEngine.ClearDesktopRevisionGaps(threadId, firstGapGeneration);
    Assert(
        gapEngine.HasDesktopRevisionGap(threadId),
        "an older targeted-read generation cannot clear a newer Desktop fact edge");

    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"{{ownerClientId}}",
          "version":11,
          "params":{
            "conversationId":"{{threadId}}",
            "hostId":"local",
            "change":{
              "type":"snapshot",
              "revision":1,
              "conversationState":{
                "threadRuntimeStatus":{"type":"idle"}
              }
            }
          }
        }
        """);
    Assert(
        !gapEngine.HasDesktopRevisionGap(threadId) && !gapEngine.HasDesktopActivityVeto(threadId),
        "an authoritative replacement snapshot clears the matching gap and rebuilds an idle veto state");

    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"{{ownerClientId}}",
          "version":11,
          "params":{
            "conversationId":"{{threadId}}",
            "hostId":"local",
            "change":{
              "type":"snapshot",
              "revision":2,
              "conversationState":{
                "threadRuntimeStatus":{"type":"active"}
              }
            }
          }
        }
        """);
    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"{{ownerClientId}}",
          "version":11,
          "params":{
            "conversationId":"{{threadId}}",
            "hostId":"local",
            "change":{
              "type":"patches",
              "baseRevision":5,
              "revision":6,
              "patches":[{"op":"replace","path":["threadRuntimeStatus","type"],"value":"idle"}]
            }
          }
        }
        """);
    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"client-status-changed",
          "sourceClientId":"desktop-host",
          "version":1,
          "params":{"clientId":"{{ownerClientId}}","status":"disconnected"}
        }
        """);
    var verifiedGapGeneration = gapEngine.CaptureDesktopRevisionGaps(threadId);
    Assert(
        verifiedGapGeneration.Count == 1 &&
        gapEngine.HasDesktopRevisionGap(threadId) &&
        gapEngine.HasDesktopActivityVeto(threadId),
        "owner disconnect creates or preserves an unverified revision gap instead of treating it as idle");
    gapEngine.ClearDesktopRevisionGaps(threadId, verifiedGapGeneration);
    Assert(
        !gapEngine.HasDesktopRevisionGap(threadId) && !gapEngine.HasDesktopActivityVeto(threadId),
        "a successful targeted-read generation clears its gap and corresponding stale source veto");

    SendDesktopActivity($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"{{ownerClientId}}",
          "version":11,
          "params":{
            "conversationId":"{{threadId}}",
            "hostId":"local",
            "change":{
              "type":"snapshot",
              "revision":9,
              "conversationState":{
                "threadRuntimeStatus":{"type":"active"}
              }
            }
          }
        }
        """);
    SendDesktopActivity("""
        {
          "type":"broadcast",
          "method":"ipc-connection-reset",
          "version":1,
          "params":{}
        }
        """);
    var resetGapGeneration = gapEngine.CaptureDesktopRevisionGaps(threadId);
    Assert(
        resetGapGeneration.Count == 1 &&
        gapEngine.HasDesktopRevisionGap(threadId) &&
        gapEngine.HasDesktopActivityVeto(threadId),
        "an IPC epoch reset conservatively gaps every previously observed Desktop stream");
    gapEngine.ClearDesktopRevisionGaps(threadId, resetGapGeneration);
    Assert(
        !gapEngine.HasDesktopRevisionGap(threadId) && !gapEngine.HasDesktopActivityVeto(threadId),
        "a targeted read clears the conservative IPC-reset gap generation");
});

{
    EventHandler<EventArgs>? subscribers = null;
    var delivered = 0;
    var failuresObserved = 0;
    subscribers += (_, _) => throw new InvalidOperationException("subscriber failure");
    subscribers += (_, _) => delivered++;
    EventSubscriberDispatcher.Invoke(
        subscribers,
        new object(),
        EventArgs.Empty,
        _ => failuresObserved++);
    Assert(
        delivered == 1 && failuresObserved == 1,
        "one failing signal subscriber cannot terminate delivery to the remaining subscribers");
}

{
    var startedThreadId = Guid.NewGuid().ToString();
    var errorThreadId = Guid.NewGuid().ToString();
    var errorTurnId = Guid.NewGuid().ToString();
    var started = AppServerClient.ParseNotification(Json(JsonSerializer.Serialize(new
    {
        method = "thread/started",
        @params = new { thread = new { id = startedThreadId } }
    })));
    var error = AppServerClient.ParseNotification(Json(JsonSerializer.Serialize(new
    {
        method = "error",
        @params = new { threadId = errorThreadId, turnId = errorTurnId }
    })));
    Assert(
        started is { Method: "thread/started" } && started.ThreadId == startedThreadId &&
        error is { Method: "error" } && error.ThreadId == errorThreadId && error.TurnId == errorTurnId,
        "app-server notification parsing retains nested thread/started and scalar error identifiers");
    Assert(
        GuardianEngine.IsThreadScopedNotification("turn/completed") &&
        GuardianEngine.IsThreadScopedNotification("thread/archived") &&
        !GuardianEngine.IsThreadScopedNotification("account/updated"),
        "only task-scoped app-server notifications with an exact task id can wake targeted monitoring");
}

{
    const string secret = "sk-supersecret123456";
    const string environmentSecret = "environment-supersecret";
    const string querySecret = "query-supersecret";
    const string nestedMessage = "nested private message";
    const string title = "private prompt title";
    var sanitized = GuardianLog.SanitizeForPersistence(
        $"Authorization: Bearer abc.def OPENAI_API_KEY={environmentSecret} " +
        $"https://example.invalid/?token={querySecret} " +
        $"{{\"messages\":[{{\"content\":\"{nestedMessage}\"}}]}}");
    var protocolError = AppServerClient.FormatProtocolError(Json(
        $"{{\"code\":\"invalid_request\",\"message\":\"{nestedMessage} {secret}\"}}"));
    var numericProtocolCode = AppServerClient.ReadProtocolErrorCode(Json("{\"code\":-32600}"));
    var threadReference = GuardianLog.CreateThreadReference(title);
    Assert(
        !sanitized.Contains(secret, StringComparison.Ordinal) &&
        !sanitized.Contains(environmentSecret, StringComparison.Ordinal) &&
        !sanitized.Contains(querySecret, StringComparison.Ordinal) &&
        !sanitized.Contains(nestedMessage, StringComparison.Ordinal) &&
        !sanitized.Contains("abc.def", StringComparison.Ordinal) &&
        !protocolError.Contains(nestedMessage, StringComparison.Ordinal) &&
        !protocolError.Contains(secret, StringComparison.Ordinal) &&
        protocolError.Contains("invalid_request", StringComparison.Ordinal) &&
        numericProtocolCode == "-32600" &&
        GuardianEngine.IsPermanentTargetReadRejection(numericProtocolCode) &&
        threadReference is not null && !threadReference.Contains(title, StringComparison.Ordinal),
        "diagnostic persistence redacts credentials, structured message content, and task titles");

    // Four real threads from the 2026-08-29 automatic recovery run all carried the title "5",
    // so a title-derived label collapsed them into one reference and could not attribute a
    // recovery to a conversation. The label must be derived from the exact task id instead.
    string[] collidingThreadIds =
    [
        "01a01fe2-5baf-7b52-9f13-2c9f4a5d6e70",
        "01a0162e-2955-7a41-8c02-1d7e3b8f9a51",
        "01a00ed9-27a9-7c63-9e84-4f2a1c6b8d92",
        "01a0162f-b099-7d75-8a16-5b3c2e9f7a04"
    ];
    const string sharedTitle = "5";
    var collidingLabels = collidingThreadIds
        .Select(GuardianLog.CreateThreadReference)
        .ToArray();
    Assert(
        collidingLabels.All(static label => label is not null) &&
        collidingLabels.Distinct(StringComparer.Ordinal).Count() == collidingThreadIds.Length &&
        collidingLabels.All(static label =>
            label!.StartsWith("task-", StringComparison.Ordinal)) &&
        !collidingLabels.Contains(
            GuardianLog.CreateThreadReference(sharedTitle),
            StringComparer.Ordinal) &&
        collidingThreadIds.All(static threadId =>
            GuardianLog.CreateThreadReference(threadId) ==
            GuardianLog.CreateOpaqueReference("task", threadId)) &&
        collidingThreadIds.Zip(collidingLabels).All(static pair =>
            !pair.Second!.Contains(pair.First, StringComparison.Ordinal)),
        "log task labels are task-id derived, stay distinct across same-title tasks, and match the diagnostic task reference");

    var logRoot = Path.Combine(Path.GetTempPath(), "CodexGuardian", "bounded-log-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(logRoot);
    try
    {
        using (var boundedLog = new GuardianLog(logRoot))
        {
            var payload = new string('x', GuardianLog.MaximumPersistedMessageCharacters + 128);
            for (var index = 0; index < 2200; index++)
            {
                boundedLog.Info(payload + " " + secret, title);
            }

            var diagnosticTurn = Turn(
                "failed",
                "responseStreamDisconnected",
                input: nestedMessage,
                confirmedTerminal: true);
            var diagnosticDecision = new RecoveryClassifier().Classify(diagnosticTurn);
            for (var index = 0; index < 6500; index++)
            {
                boundedLog.WriteClassification(secret, diagnosticTurn, diagnosticDecision);
                boundedLog.WriteDispatchGate(secret, diagnosticTurn.Id, "beforeStartTurn", "Active", allowed: false);
                boundedLog.WriteMonitorCycle(
                    "targetedRefresh",
                    "stateSignal",
                    "completed",
                    TimeSpan.FromMilliseconds(12),
                    taskCount: 1,
                    helperStarts: 0,
                    protocolRequests: 2,
                    threadListRequests: 0,
                    targetedReadRequests: 2,
                    fileIndexRefreshes: 0);
            }
        }

        var current = Path.Combine(logRoot, "guardian.log");
        var previous = Path.Combine(logRoot, "guardian.previous.log");
        var persisted = File.ReadAllText(current) + (File.Exists(previous) ? File.ReadAllText(previous) : string.Empty);
        var diagnosticCurrent = Path.Combine(logRoot, "guardian-diagnostics.jsonl");
        var diagnosticPrevious = Path.Combine(logRoot, "guardian-diagnostics.previous.jsonl");
        var diagnosticPersisted = File.ReadAllText(diagnosticCurrent) +
                                  (File.Exists(diagnosticPrevious)
                                      ? File.ReadAllText(diagnosticPrevious)
                                      : string.Empty);
        var diagnosticLinesAreJson = diagnosticPersisted
            .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
            .All(line =>
            {
                try
                {
                    using var _ = JsonDocument.Parse(line);
                    return true;
                }
                catch (JsonException)
                {
                    return false;
                }
            });
        Assert(
            new FileInfo(current).Length <= GuardianLog.MaximumLogBytes &&
            File.Exists(previous) && new FileInfo(previous).Length <= GuardianLog.MaximumLogBytes &&
            new FileInfo(diagnosticCurrent).Length <= GuardianLog.MaximumDiagnosticBytes &&
            File.Exists(diagnosticPrevious) &&
            new FileInfo(diagnosticPrevious).Length <= GuardianLog.MaximumDiagnosticBytes &&
            diagnosticLinesAreJson &&
            diagnosticPersisted.Contains("\"eventType\":\"monitorCycle\"", StringComparison.Ordinal) &&
            !persisted.Contains(secret, StringComparison.Ordinal) &&
            !persisted.Contains(title, StringComparison.Ordinal) &&
            !diagnosticPersisted.Contains(secret, StringComparison.Ordinal) &&
            !diagnosticPersisted.Contains(nestedMessage, StringComparison.Ordinal) &&
            !diagnosticPersisted.Contains(title, StringComparison.Ordinal),
            "logs and structured diagnostics rotate within two bounded, valid, and redacted generations");
    }
    finally
    {
        Directory.Delete(logRoot, recursive: true);
    }
}

{
    var lifecycle = new MonitorLifecycle();
    var pendingCommit = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var stopCleanupStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var finishStopCleanup = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var stopOperationCount = 0;
    var duplicateStopOperationCount = 0;
    var stoppingTransitionCount = 0;

    Assert(
        lifecycle.TryStart(_ => pendingCommit.Task) && lifecycle.IsRunning,
        "monitor lifecycle publishes a newly started run");

    var firstStop = lifecycle.StopAsync(async monitorTask =>
    {
        Interlocked.Increment(ref stopOperationCount);
        if (monitorTask is not null)
        {
            await monitorTask;
        }

        stopCleanupStarted.TrySetResult();
        await finishStopCleanup.Task;
    }, () => Interlocked.Increment(ref stoppingTransitionCount));
    var repeatedStop = lifecycle.StopAsync(_ =>
    {
        Interlocked.Increment(ref duplicateStopOperationCount);
        return Task.CompletedTask;
    });
    var overlappingStartAccepted = lifecycle.TryStart(_ => Task.CompletedTask);

    Assert(
        ReferenceEquals(firstStop, repeatedStop) &&
        lifecycle.IsRunning &&
        !firstStop.IsCompleted &&
        !overlappingStartAccepted &&
        Volatile.Read(ref stopOperationCount) == 1 &&
        Volatile.Read(ref stoppingTransitionCount) == 1 &&
        Volatile.Read(ref duplicateStopOperationCount) == 0,
        "stopping remains visible, shares one waiter, and rejects a new run until the pending commit completes");

    pendingCommit.TrySetResult();
    await stopCleanupStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
    Assert(
        lifecycle.IsRunning && !firstStop.IsCompleted,
        "stopping remains visible while post-commit cleanup is still in progress");
    finishStopCleanup.TrySetResult();
    await firstStop.WaitAsync(TimeSpan.FromSeconds(1));
    Assert(
        !lifecycle.IsRunning,
        "monitor lifecycle publishes stopped only after the pending commit and stop cleanup complete");

    var restartedCommit = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var restarted = lifecycle.TryStart(_ => restartedCommit.Task);
    var finalStop = lifecycle.StopAsync(async monitorTask =>
    {
        if (monitorTask is not null)
        {
            await monitorTask;
        }
    });
    Assert(
        restarted && lifecycle.IsRunning && !finalStop.IsCompleted,
        "a completed stop permits a later run while preserving the same stop barrier");
    restartedCommit.TrySetResult();
    await finalStop.WaitAsync(TimeSpan.FromSeconds(1));
    Assert(!lifecycle.IsRunning, "normal final shutdown completes without leaving a stopping state");
}

{
    var lifecycle = new MonitorLifecycle();
    var entered = new TaskCompletionSource<SynchronizationContext?>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var previousContext = SynchronizationContext.Current;
    SynchronizationContext.SetSynchronizationContext(new SynchronizationContext());
    try
    {
        Assert(
            lifecycle.TryStart(async _ =>
            {
                entered.TrySetResult(SynchronizationContext.Current);
                await release.Task;
            }),
            "monitor lifecycle accepts a background scan run");
    }
    finally
    {
        SynchronizationContext.SetSynchronizationContext(previousContext);
    }

    Assert(
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(1)) is null,
        "monitor scans never inherit the WPF synchronization context");
    release.TrySetResult();
    await lifecycle.StopAsync(async monitorTask =>
    {
        if (monitorTask is not null)
        {
            await monitorTask;
        }
    }).WaitAsync(TimeSpan.FromSeconds(1));
}

{
    var uiTestRoot = Path.Combine(Path.GetTempPath(), "CodexGuardian", "ui-diff-" + Guid.NewGuid().ToString("N"));
    try
    {
        Directory.CreateDirectory(uiTestRoot);
        using var uiLog = new GuardianLog(uiTestRoot);
        await using var uiAppServer = new AppServerClient(new CodexCliLocator(), uiLog);
        await using var uiDesktop = new DesktopIpcClient(uiLog);
        var uiSettings = new AppSettings
        {
            MonitoringEnabled = false,
            MonitorOnly = true,
            RecentThreadLimit = 2,
            RecentThreadLookbackDays = 14
        };
        var uiClassifier = new RecoveryClassifier();
        var uiRecovery = new RecoveryService(
            uiAppServer,
            uiDesktop,
            new DesktopThreadOwnerActivator(uiDesktop, uiLog),
            new RecoveryOperationJournal(uiTestRoot),
            uiLog);
        var uiEngine = new GuardianEngine(
            uiSettings,
            uiAppServer,
            uiDesktop,
            uiRecovery,
            uiClassifier,
            new LocalConversationHistoryReader(Path.Combine(uiTestRoot, "sessions")),
            uiLog);
        await using var uiViewModel = new MainViewModel(
            uiSettings,
            new SettingsService(uiTestRoot),
            new StartupService(),
            uiLog,
            uiEngine,
            uiAppServer,
            uiDesktop,
            uiClassifier,
            new LocalizationService());
        var firstScopeGeneration = uiRecovery.BeginScopeValidationGeneration();
        var secondScopeGeneration = uiRecovery.BeginScopeValidationGeneration();
        Assert(
            secondScopeGeneration == firstScopeGeneration + 1,
            "each engine scan receives a distinct shared recovery-scope validation generation");

    GuardianTaskState UiState(
        string id,
        string name,
        long createdAt,
        long updatedAt,
        bool enabled = true,
        TaskHealth health = TaskHealth.Healthy,
        bool archived = false,
        GuardianTaskObservation? observation = null) =>
        new(
            new ThreadSummary(
                id,
                name,
                name,
                "C:\\Work",
                "appServer",
                createdAt,
                updatedAt,
                false,
                false,
                IsArchived: archived),
            null,
            RecoveryDecision.None(health, "test"),
            enabled,
            health,
            "Ready",
            "No recent event",
            0,
            null,
            Observation: observation);

    GuardianTaskState UiClassifiedState(string id, TurnSnapshot turn)
    {
        var decision = uiClassifier.Classify(turn);
        return new GuardianTaskState(
            new ThreadSummary(
                id,
                id,
                id,
                "C:\\Work",
                "appServer",
                100,
                200,
                false,
                false),
            turn,
            decision,
            false,
            decision.Health,
            decision.Reason,
            decision.Reason,
            0,
            null);
    }

    uiViewModel.ApplySnapshot(GuardianTaskSnapshot.FromLegacy(
    [
        UiState("task-b", "Task B", 100, 200),
        UiState("task-a", "Task A", 200, 200)
    ]));
    var originalA = uiViewModel.Tasks.Single(task => task.Id == "task-a");
    var originalB = uiViewModel.Tasks.Single(task => task.Id == "task-b");

    uiViewModel.ApplySnapshot(new GuardianTaskSnapshot(
    [
        UiState("task-b", "Task B updated", 100, 900, enabled: false),
        UiState("task-c", "Task C", 300, 300),
        UiState(
            "task-a",
            "Task A updated",
            200,
            800,
            observation: new GuardianTaskObservation(
                GuardianObservedPhase.Reconnecting,
                null,
                "responseStreamDisconnected",
                429,
                true,
                4,
                5,
                DateTimeOffset.UtcNow))
    ],
        new GuardianSnapshotStatistics(
            DisplayedSessionCount: 3,
            TotalSessionCount: 12,
            ArchivedSessionCount: 4,
            FilteredSessionCount: 5,
            IsTruncated: true,
            IncludesArchived: true)));

    Assert(
        ReferenceEquals(originalA, uiViewModel.Tasks.Single(task => task.Id == "task-a")) &&
        ReferenceEquals(originalB, uiViewModel.Tasks.Single(task => task.Id == "task-b")) &&
        originalA.Name == "Task A updated" &&
        originalA.ObservationText == "进程观察：正在重连 4/5 · HTTP 429" &&
        !originalB.IsEnabled,
        "UI snapshot keyed diff retains task item identity and renders allowlisted deep-observation progress in place");
    Assert(
        uiViewModel.Tasks.Select(task => task.Id).SequenceEqual(["task-b", "task-a", "task-c"]),
        "UI snapshot preserves the Codex-style pinned project and recent-activity order");
    Assert(
        uiViewModel.TaskSessionSummaryText.Contains("总会话数：12", StringComparison.Ordinal) &&
        uiViewModel.TaskSessionSummaryText.Contains("当前显示：3", StringComparison.Ordinal) &&
        uiViewModel.TaskSessionSummaryText.Contains("归档：4", StringComparison.Ordinal) &&
        uiViewModel.TaskFilterSummaryText.Contains("结果已截断", StringComparison.Ordinal),
        "UI snapshot statistics distinguish totals, displayed, archived, filtered, and truncated sessions");

    uiViewModel.ApplySnapshot(GuardianTaskSnapshot.FromLegacy(
    [
        UiState("task-a", "Task A final", 200, 1000),
        UiState("task-c", "Task C", 300, 300)
    ]));
    Assert(
        ReferenceEquals(originalA, uiViewModel.Tasks.Single(task => task.Id == "task-a")) &&
        originalA.ObservationText.Length == 0 &&
        uiViewModel.Tasks.All(task => task.Id != "task-b") &&
        uiViewModel.TaskSessionSummaryText.Contains("服务未返回", StringComparison.Ordinal) &&
        uiViewModel.TaskSessionSummaryText.Contains("归档：未包含", StringComparison.Ordinal) &&
        uiViewModel.TaskFilterSummaryText.Contains("完整性标记", StringComparison.Ordinal),
        "legacy UI snapshots remove only missing IDs and report unknown statistics without inventing totals");

    uiViewModel.ApplySnapshot(new GuardianTaskSnapshot(
    [
        UiState("task-a", "Task A final", 200, 1000),
        UiState("task-c", "Task C", 300, 300),
        UiState("task-archived", "Archived reference", 50, 50, enabled: false, archived: true)
    ],
        new GuardianSnapshotStatistics(3, 3, 1, 0, false, true)));
    var archivedTask = uiViewModel.Tasks.Single(task => task.Id == "task-archived");
    Assert(
        archivedTask.IsArchived &&
        !archivedTask.CanToggleProtection &&
        uiViewModel.TasksView.Cast<object>().Count() == 2 &&
        uiViewModel.TasksView.Cast<GuardianTaskItem>().All(task => !task.IsArchived),
        "all scope excludes archived sessions by default and their recovery switch is read-only");
    uiViewModel.ShowArchived = false;
    Assert(
        uiViewModel.TasksView.Cast<GuardianTaskItem>().All(task => !task.IsArchived) &&
        uiViewModel.TaskSessionSummaryText.Contains("当前显示：2", StringComparison.Ordinal),
        "archived filter updates the in-memory view and displayed count without rebuilding task items");
    uiViewModel.TaskSearchText = "final";
    Assert(
        uiViewModel.TasksView.Cast<GuardianTaskItem>().Select(task => task.Id).SequenceEqual(["task-a"]) &&
        uiViewModel.TaskSessionSummaryText.Contains("当前显示：1", StringComparison.Ordinal),
        "task search filters the stable collection by visible session metadata");
    uiViewModel.TaskSearchText = string.Empty;
    uiViewModel.ShowArchived = true;
    Assert(
        uiViewModel.TasksView.Cast<GuardianTaskItem>().All(task => !task.IsArchived),
        "all conversation scope excludes archived rows even when the legacy visibility property is true");

    uiViewModel.ApplySnapshot(new GuardianTaskSnapshot(
    [
        UiState("task-a", "Task A final", 200, 1000),
        UiState("task-c", "Task C needs review", 300, 1100, health: TaskHealth.ManualReview),
        UiState("task-archived", "Archived reference", 50, 50, enabled: false, archived: true)
    ],
        new GuardianSnapshotStatistics(3, 3, 1, 0, false, true)));
    uiViewModel.SetConversationScopeCommand.Execute("NeedsAttention");
    Assert(
        uiViewModel.ConversationScope == ConversationScopeKind.NeedsAttention &&
        !uiViewModel.ShowArchived &&
        uiViewModel.NeedsAttentionConversationCount == 1 &&
        uiViewModel.TasksView.Cast<GuardianTaskItem>().Select(task => task.Id).SequenceEqual(["task-c"]),
        "conversation attention scope is a real health filter with an independent count");
    uiViewModel.SetConversationScopeCommand.Execute("Archived");
    Assert(
        uiViewModel.ConversationScope == ConversationScopeKind.Archived &&
        uiViewModel.ShowArchived &&
        uiViewModel.ArchivedConversationCount == 1 &&
        uiViewModel.TasksView.Cast<GuardianTaskItem>().Select(task => task.Id).SequenceEqual(["task-archived"]),
        "conversation archived scope isolates archived sessions instead of exposing a loose toggle");
    uiViewModel.TaskSearchText = "missing-conversation";
    Assert(
        uiViewModel.HasTaskSearchText &&
        !uiViewModel.HasVisibleTasks &&
        uiViewModel.TaskCount == 0,
        "conversation search exposes a deterministic empty-result state");
    uiViewModel.ClearTaskSearchCommand.Execute(null);
    uiViewModel.SetConversationScopeCommand.Execute("All");
    Assert(
        !uiViewModel.HasTaskSearchText &&
        uiViewModel.HasVisibleTasks &&
        uiViewModel.AllConversationCount == 2 &&
        uiViewModel.TasksView.Cast<GuardianTaskItem>().Count() == 2 &&
        uiViewModel.TasksView.Cast<GuardianTaskItem>().All(task => !task.IsArchived),
        "conversation search clear and all scope restore only active conversations");

    Assert(
        uiViewModel.MoveConversationAsync(originalA, 0).GetAwaiter().GetResult() &&
        uiViewModel.Tasks.Select(task => task.Id)
            .SequenceEqual(["task-a", "task-c", "task-archived"]),
        "conversation drag order did not move only the visible active slots");
    var persistedUiSettings = new SettingsService(uiTestRoot).LoadAsync().GetAwaiter().GetResult();
    Assert(
        persistedUiSettings.ConversationOrder.SequenceEqual(
            ["task-a", "task-c", "task-archived"],
            StringComparer.OrdinalIgnoreCase),
        "conversation drag order did not survive its atomic settings save");
    uiViewModel.ApplySnapshot(new GuardianTaskSnapshot(
    [
        UiState("task-a", "Task A final", 200, 1200),
        UiState("task-c", "Task C needs review", 300, 1300, health: TaskHealth.ManualReview),
        UiState("task-archived", "Archived reference", 50, 50, enabled: false, archived: true),
        UiState("task-new", "New conversation", 400, 1400)
    ],
        new GuardianSnapshotStatistics(4, 4, 1, 0, false, true)));
    Assert(
        uiViewModel.Tasks.Select(task => task.Id)
            .SequenceEqual(["task-new", "task-a", "task-c", "task-archived"]),
        "a newly discovered active conversation did not enter before the stable manual order");

    var enabledEventCount = 0;
    originalA.EnabledChanged += (_, _) => enabledEventCount++;
    originalA.SetEnabledFromSnapshot(false);
    originalA.IsEnabled = true;
    Assert(
        enabledEventCount == 1,
        "snapshot protection synchronization does not invoke the user-toggle side effect");

    var uiViewModelPath = FindWorkspaceSource("CodexGuardian", "ViewModels", "MainViewModel.cs");
    var mainWindowPath = FindWorkspaceSource("CodexGuardian", "MainWindow.xaml");
    var uiViewModelSource = uiViewModelPath is not null ? File.ReadAllText(uiViewModelPath) : string.Empty;
    var mainWindowSource = mainWindowPath is not null ? File.ReadAllText(mainWindowPath) : string.Empty;
    Assert(
        !uiViewModelSource.Contains("Tasks.Clear()", StringComparison.Ordinal) &&
        uiViewModelSource.Contains("editable.IsAddingNew || editable.IsEditingItem", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"ConversationIndex\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"ConversationScopeAllButton\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"ConversationScopeAttentionButton\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"ConversationScopeArchivedButton\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"ClearConversationSearchButton\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"ConversationEmptyClearSearchButton\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("ItemContainerStyle=\"{StaticResource ConversationListItemStyle}\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"InspectorFollowUpEntryButton\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("AutomationProperties.AutomationId=\"FollowUpMessageList\"", StringComparison.Ordinal) &&
        !mainWindowSource.Contains("<DataGrid", StringComparison.Ordinal) &&
        !mainWindowSource.Contains("IsChecked=\"{Binding ShowArchived", StringComparison.Ordinal) &&
        mainWindowSource.Contains("ScrollViewer.VerticalScrollBarVisibility=\"Auto\"", StringComparison.Ordinal) &&
        mainWindowSource.Contains("VirtualizingPanel.IsVirtualizing=\"True\"", StringComparison.Ordinal),
        "the conversation index and inspector avoid editable tables and retain responsive scrolling");
    Assert(
        uiViewModel.CanEnableConversationProtection &&
        !uiViewModel.AutoRecoveryEnabled &&
        !uiSettings.AutomaticRecoveryEnabled && uiSettings.MonitorOnly &&
        mainWindowSource.Contains("IsEnabled=\"{Binding CanToggleAutoRecovery}\"", StringComparison.Ordinal) &&
        uiViewModelSource.Contains("SetAutomaticRecoveryFromUserAsync", StringComparison.Ordinal) &&
        uiViewModelSource.Contains("SetAutomaticRecoveryPolicy", StringComparison.Ordinal),
        "the recovery control is not bound to the explicit disk-first automatic-recovery authority");

    var unverifiedInterruptedContinue = Turn("interrupted", input: "continue");
    var confirmedUserAbortedContinue = Turn(
        "aborted",
        input: "continue",
        confirmedTerminal: true);
    var unverifiedAbortReasonContinue = Turn(
        RecoveryClassifier.UnverifiedAbortStatus,
        input: "continue");
    var permanentProviderFailure = Turn(
        "failed",
        code: "other",
        httpStatus: 401,
        error: "unauthorized");
    uiViewModel.ApplySnapshot(GuardianTaskSnapshot.FromLegacy(
    [
        UiClassifiedState("unverified-interrupted-continue", unverifiedInterruptedContinue),
        UiClassifiedState("confirmed-user-aborted-continue", confirmedUserAbortedContinue),
        UiClassifiedState("unverified-abort-reason-continue", unverifiedAbortReasonContinue),
        UiClassifiedState("permanent-provider-failure", permanentProviderFailure)
    ]));
    var unverifiedInterruptedItem = uiViewModel.Tasks.Single(task =>
        task.Id == "unverified-interrupted-continue");
    var confirmedUserAbortedItem = uiViewModel.Tasks.Single(task =>
        task.Id == "confirmed-user-aborted-continue");
    var unverifiedAbortReasonItem = uiViewModel.Tasks.Single(task =>
        task.Id == "unverified-abort-reason-continue");
    var permanentProviderFailureItem = uiViewModel.Tasks.Single(task =>
        task.Id == "permanent-provider-failure");
        Assert(
            unverifiedInterruptedItem.Health == TaskHealth.Unknown &&
            unverifiedInterruptedItem.HealthResourceKey == "Health.ContinueInterruptedUnverified" &&
            unverifiedInterruptedItem.HealthText == "continue 已中断，终态未验证" &&
            confirmedUserAbortedItem.Health == TaskHealth.ManualReview &&
            confirmedUserAbortedItem.HealthResourceKey == "Health.ContinueUserAborted" &&
            confirmedUserAbortedItem.HealthText == "continue 已由用户中止" &&
            confirmedUserAbortedItem.StatusText.Contains("不会自动恢复", StringComparison.Ordinal) &&
            unverifiedAbortReasonItem.Health == TaskHealth.Unknown &&
            unverifiedAbortReasonItem.HealthResourceKey == "Health.ContinueAbortReasonUnverified" &&
            unverifiedAbortReasonItem.HealthText == "continue 中止原因待确认" &&
            unverifiedAbortReasonItem.StatusText.Contains("阻止自动恢复", StringComparison.Ordinal) &&
            permanentProviderFailureItem.StatusText ==
                "最近一轮发生明确不可自动恢复的错误（HTTP 401，错误代码 other）。",
            "UI separates abort states and localizes dynamic permanent-failure evidence");
    }
    finally
    {
        try
        {
            if (Directory.Exists(uiTestRoot))
            {
                if ((File.GetAttributes(uiTestRoot) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new IOException("The UI test root unexpectedly became a reparse point.");
                }

                Directory.Delete(uiTestRoot, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Assert(false, "UI test temporary directory cleanup: " + exception.Message);
        }
    }
}

var threadListPages = new Queue<JsonElement>(
[
    Json("""
        {
          "data": [
            {
              "id": "thread-openai",
              "preview": "OpenAI task",
              "cwd": "C:\\Work",
              "source": "appServer",
              "path": "\\\\?\\C:\\History\\thread-openai.jsonl",
              "modelProvider": "openai",
              "createdAt": 100,
              "updatedAt": 300,
              "ephemeral": false,
              "status": { "type": "idle" }
            }
          ],
          "nextCursor": "page-2"
        }
        """),
    Json("""
        {
          "data": [
            {
              "id": "thread-openai",
              "preview": "Overlapping page entry",
              "cwd": "C:\\Work",
              "source": "appServer",
              "path": "C:\\History\\thread-openai.jsonl",
              "modelProvider": "openai",
              "createdAt": 100,
              "updatedAt": 300,
              "ephemeral": false,
              "status": { "type": "idle" }
            },
            {
              "id": "thread-rollout-alias",
              "preview": "Same rollout under a different ID",
              "cwd": "C:\\Work",
              "source": "appServer",
              "path": "C:\\History\\thread-openai.jsonl",
              "modelProvider": "openai",
              "createdAt": 100,
              "updatedAt": 300,
              "ephemeral": false,
              "status": { "type": "idle" }
            },
            {
              "id": "thread-subagent-without-parent-field",
              "preview": "Inherited parent title",
              "cwd": "C:\\Work",
              "source": {
                "subAgent": {
                  "threadSpawn": {
                    "parentThreadId": "thread-openai",
                    "depth": 1
                  }
                }
              },
              "modelProvider": "openai-custom",
              "createdAt": 95,
              "updatedAt": 250,
              "ephemeral": false,
              "status": { "type": "idle" }
            },
            {
              "id": "thread-custom",
              "preview": "Custom provider task",
              "cwd": "C:\\Work",
              "source": "cli",
              "modelProvider": "openai-custom",
              "createdAt": 90,
              "updatedAt": 200,
              "ephemeral": false,
              "status": { "type": "notLoaded" }
            }
          ],
          "nextCursor": "page-3"
        }
        """),
    Json("""
        {
          "data": [
            {
              "id": "thread-third-provider",
              "preview": "Third provider task",
              "cwd": "C:\\Archive",
              "source": "vscode",
              "modelProvider": "third-party",
              "createdAt": 80,
              "updatedAt": 100,
              "ephemeral": false,
              "status": { "type": "idle" }
            }
          ],
          "nextCursor": null
        }
        """)
]);
var threadListRequests = new List<JsonElement>();
var allProviderThreads = await AppServerClient.ListThreadsCoreAsync(
    pageSize: 30,
    includeSubAgents: false,
    archived: false,
    (parameters, _) =>
    {
        threadListRequests.Add(JsonSerializer.SerializeToElement(parameters));
        return Task.FromResult(threadListPages.Dequeue());
    });
Assert(
    allProviderThreads.Select(thread => thread.Id).SequenceEqual(
        ["thread-openai", "thread-custom", "thread-third-provider"]) &&
    threadListRequests.Count == 3 &&
    threadListRequests[0].GetProperty("cursor").ValueKind == JsonValueKind.Null &&
    threadListRequests[1].GetProperty("cursor").GetString() == "page-2" &&
    threadListRequests[2].GetProperty("cursor").GetString() == "page-3",
    "thread/list follows nextCursor, retains providers, and deduplicates stable IDs and rollout paths");
Assert(
    threadListRequests.All(request =>
        request.GetProperty("limit").GetInt32() == 30 &&
        !request.GetProperty("archived").GetBoolean() &&
        request.GetProperty("modelProviders").ValueKind == JsonValueKind.Array &&
        request.GetProperty("modelProviders").GetArrayLength() == 0 &&
        request.GetProperty("useStateDbOnly").GetBoolean() &&
        request.GetProperty("sourceKinds").EnumerateArray().All(source =>
            !source.GetString()!.StartsWith("subAgent", StringComparison.OrdinalIgnoreCase))),
    "thread/list requests all providers from the state DB and excludes subagent source kinds");
Assert(
    allProviderThreads.All(thread => !thread.IsSubAgent) &&
    allProviderThreads.All(thread => thread.Id != "thread-subagent-without-parent-field"),
    "thread/list defensively filters source.subAgent when parentThreadId is absent");

var archivedThreadListRequests = new List<JsonElement>();
var archivedThreads = await AppServerClient.ListThreadsCoreAsync(
    pageSize: 20,
    includeSubAgents: true,
    archived: true,
    (parameters, _) =>
    {
        archivedThreadListRequests.Add(JsonSerializer.SerializeToElement(parameters));
        return Task.FromResult(Json("""
            {
              "data": [
                {
                  "id": "thread-archived",
                  "preview": "Archived task",
                  "cwd": "C:\\Archive",
                  "source": "appServer",
                  "modelProvider": "openai-custom",
                  "createdAt": 50,
                  "updatedAt": 60,
                  "ephemeral": false,
                  "status": { "type": "notLoaded" }
                }
              ],
              "nextCursor": null
            }
            """));
    });
Assert(
    archivedThreads.Count == 1 &&
    archivedThreads[0].Id == "thread-archived" &&
    archivedThreads[0].IsArchived &&
    allProviderThreads.All(thread => !thread.IsArchived) &&
    archivedThreadListRequests.Count == 1 &&
    archivedThreadListRequests[0].GetProperty("archived").GetBoolean() &&
    archivedThreadListRequests[0].GetProperty("sourceKinds").EnumerateArray().Any(source =>
        source.GetString()!.StartsWith("subAgent", StringComparison.OrdinalIgnoreCase)),
    "thread/list supports an explicit archived-thread query");

var targetReadRequests = new List<JsonElement>();
var activeRolloutProbeCount = 0;
var activeTarget = await AppServerClient.ReadThreadForRecoveryCoreAsync(
    "thread-target-active",
    (parameters, _) =>
    {
        targetReadRequests.Add(JsonSerializer.SerializeToElement(parameters));
        return Task.FromResult(Json("""
            {
              "thread": {
                "id": "thread-target-active",
                "name": "Target active",
                "preview": "Target active preview",
                "cwd": "C:\\Work",
                "source": "appServer",
                "createdAt": 100,
                "updatedAt": 200,
                "ephemeral": false,
                "path": "C:\\Users\\tester\\.codex\\sessions\\2026\\07\\27\\rollout-thread-target-active.jsonl",
                "status": { "type": "idle" }
              }
            }
            """));
    },
    rolloutExists: _ =>
    {
        activeRolloutProbeCount++;
        return true;
    });
Assert(
    activeTarget.Id == "thread-target-active" &&
    !activeTarget.IsArchived &&
    !activeTarget.IsSubAgent &&
    targetReadRequests.Count == 1 &&
    activeRolloutProbeCount == 1 &&
    targetReadRequests[0].GetProperty("threadId").GetString() == "thread-target-active" &&
    !targetReadRequests[0].GetProperty("includeTurns").GetBoolean(),
    "pre-dispatch target validation uses one metadata-only thread/read instead of another directory scan");

var archivedTarget = await AppServerClient.ReadThreadForRecoveryCoreAsync(
    "thread-target-archived",
    (_, _) => Task.FromResult(Json("""
        {
          "thread": {
            "id": "thread-target-archived",
            "preview": "Archived target",
            "cwd": "C:\\Work",
            "source": "cli",
            "createdAt": 100,
            "updatedAt": 200,
            "ephemeral": false,
            "path": "C:\\Users\\tester\\.codex\\archived_sessions\\rollout-thread-target-archived.jsonl",
            "status": { "type": "notLoaded" }
          }
        }
        """)),
    rolloutExists: _ => true);
var subAgentTarget = await AppServerClient.ReadThreadForRecoveryCoreAsync(
    "thread-target-subagent",
    (_, _) => Task.FromResult(Json("""
        {
          "thread": {
            "id": "thread-target-subagent",
            "preview": "Subagent target",
            "cwd": "C:\\Work",
            "source": { "subAgent": "review" },
            "parentThreadId": "thread-target-active",
            "createdAt": 100,
            "updatedAt": 200,
            "ephemeral": false,
            "path": "C:\\Users\\tester\\.codex\\sessions\\2026\\07\\27\\rollout-thread-target-subagent.jsonl",
            "status": { "type": "idle" }
          }
        }
        """)),
    rolloutExists: _ => true);
var ephemeralTarget = await AppServerClient.ReadThreadForRecoveryCoreAsync(
    "thread-target-ephemeral",
    (_, _) => Task.FromResult(Json("""
        {
          "thread": {
            "id": "thread-target-ephemeral",
            "preview": "Ephemeral target",
            "cwd": "C:\\Work",
            "source": "appServer",
            "createdAt": 100,
            "updatedAt": 200,
            "ephemeral": true,
            "path": null,
            "status": { "type": "idle" }
          }
        }
        """)));
Assert(
    archivedTarget.IsArchived &&
    subAgentTarget.IsSubAgent &&
    ephemeralTarget.IsEphemeral &&
    AppServerClient.ClassifyThreadArchivedPath(
        @"\\?\C:\Users\tester\.codex\sessions\2026\07\27\rollout.jsonl") == false &&
    AppServerClient.ClassifyThreadArchivedPath(
        @"C:/Users/tester/.codex/archived_sessions/rollout.jsonl") == true,
    "thread/read metadata distinguishes archived storage, source subagents, ephemeral tasks, and path aliases");
var unknownTargetPathRejected = await ThrowsAsync<InvalidDataException>(async () =>
    _ = await AppServerClient.ReadThreadForRecoveryCoreAsync(
        "thread-target-unknown",
        (_, _) => Task.FromResult(Json("""
            {
              "thread": {
                "id": "thread-target-unknown",
                "preview": "Unknown target",
                "cwd": "C:\\Work",
                "source": "appServer",
                "createdAt": 100,
                "updatedAt": 200,
                "ephemeral": false,
                "path": "C:\\Unexpected\\rollout-thread-target-unknown.jsonl",
                "status": { "type": "idle" }
              }
            }
            """))));
var mismatchedTargetIdRejected = await ThrowsAsync<InvalidDataException>(async () =>
    _ = await AppServerClient.ReadThreadForRecoveryCoreAsync(
        "thread-target-expected",
        (_, _) => Task.FromResult(Json("""
            {
              "thread": {
                "id": "thread-target-other",
                "preview": "Wrong target",
                "cwd": "C:\\Work",
                "source": "appServer",
                "createdAt": 100,
                "updatedAt": 200,
                "ephemeral": false,
                "path": "C:\\Users\\tester\\.codex\\sessions\\2026\\07\\27\\rollout-thread-target-other.jsonl",
                "status": { "type": "idle" }
              }
            }
            """))));
var missingActiveRolloutRejected = await ThrowsAsync<InvalidDataException>(async () =>
    _ = await AppServerClient.ReadThreadForRecoveryCoreAsync(
        "thread-target-moved",
        (_, _) => Task.FromResult(Json("""
            {
              "thread": {
                "id": "thread-target-moved",
                "preview": "Moved target",
                "cwd": "C:\\Work",
                "source": "appServer",
                "createdAt": 100,
                "updatedAt": 200,
                "ephemeral": false,
                "path": "C:\\Users\\tester\\.codex\\sessions\\2026\\07\\27\\rollout-thread-target-moved.jsonl",
                "status": { "type": "idle" }
              }
            }
            """)),
        rolloutExists: _ => false));
Assert(
    unknownTargetPathRejected && mismatchedTargetIdRejected && missingActiveRolloutRejected,
    "pre-dispatch target validation fails closed on unverifiable, moved, and mismatched thread/read metadata");

var scopeRootThread = new ThreadSummary(
    "thread-scope-root",
    "Scope root",
    "scope",
    "C:\\Scope",
    "appServer",
    10,
    20,
    IsSubAgent: false,
    IsEphemeral: false);
var scopeSubAgentThread = scopeRootThread with
{
    Id = "thread-scope-subagent",
    IsSubAgent = true,
    Source = "subAgent"
};
var scopeArchivedThread = scopeRootThread with { IsArchived = true, UpdatedAt = 30 };
var scopeEphemeralThread = scopeRootThread with { Id = "thread-scope-ephemeral", IsEphemeral = true };
var freshSettings = new AppSettings();
Assert(
    freshSettings.MonitorOnly && !freshSettings.GlobalProtectionEnabled &&
    !freshSettings.ProtectNewThreadsByDefault &&
    !GuardianEngine.ResolveThreadProtection(freshSettings, scopeRootThread) &&
    freshSettings.ConfigurationVersion == AppSettings.CurrentConfigurationVersion,
    "fresh settings require manual per-conversation protection opt-in");
var scopeSettings = new AppSettings
{
    GlobalProtectionEnabled = true,
    IncludeSubAgents = false,
    ProtectNewThreadsByDefault = true
};
scopeSettings.ThreadProtectionEnabled[scopeRootThread.Id] = true;
scopeSettings.ThreadProtectionEnabled[scopeSubAgentThread.Id] = true;
Assert(
    GuardianEngine.ResolveThreadProtection(scopeSettings, scopeRootThread) &&
    !GuardianEngine.ResolveThreadProtection(scopeSettings, scopeSubAgentThread) &&
    !GuardianEngine.ResolveThreadProtection(scopeSettings, scopeArchivedThread) &&
    !GuardianEngine.ResolveThreadProtection(scopeSettings, scopeEphemeralThread),
    "default task protection includes new roots but always excludes archived, ephemeral, and filtered subagent tasks");
scopeSettings.ProtectNewThreadsByDefault = false;
Assert(
    GuardianEngine.ResolveThreadProtection(scopeSettings, scopeRootThread) &&
    !GuardianEngine.ResolveThreadProtection(scopeSettings, scopeSubAgentThread) &&
    !GuardianEngine.ResolveThreadProtection(
        scopeSettings,
        scopeRootThread with { Id = "thread-scope-future" }),
    "explicit allowlist mode protects only configured roots and cannot be bypassed by a stale subagent snapshot");
scopeSettings.ProtectNewThreadsByDefault = true;
scopeSettings.ThreadProtectionEnabled[scopeRootThread.Id] = false;
Assert(
    !GuardianEngine.ResolveThreadProtection(scopeSettings, scopeRootThread),
    "an explicit task pause overrides automatic protection for new tasks");
var mergedScopeThreads = GuardianEngine.MergeThreadDirectory(
    [scopeRootThread],
    [scopeArchivedThread]);
Assert(
    mergedScopeThreads.Count == 1 && mergedScopeThreads[0].IsArchived,
    "an archived listing wins when active and archived queries race on the same task id");
Assert(
    RecoveryService.ValidateThreadEligibility(
        scopeRootThread.Id,
        includeSubAgents: false,
        [scopeRootThread],
        []) is null &&
    RecoveryService.ValidateThreadEligibility(
        scopeRootThread.Id,
        includeSubAgents: false,
        [scopeRootThread],
        [scopeArchivedThread]) is { FailureKind: RecoveryFailureKind.PolicyChanged } &&
    RecoveryService.ValidateThreadEligibility(
        scopeSubAgentThread.Id,
        includeSubAgents: false,
        [scopeSubAgentThread],
        []) is { FailureKind: RecoveryFailureKind.PolicyChanged } &&
    RecoveryService.ValidateThreadEligibility(
        scopeRootThread.Id,
        includeSubAgents: false,
        [scopeRootThread, scopeRootThread],
        []) is { FailureKind: RecoveryFailureKind.PolicyChanged },
    "pre-dispatch scope validation fails closed on archive conflicts, filtered subagents, and ambiguous active records");
Assert(
    RecoveryService.ValidateTargetThreadEligibility(
        activeTarget.Id,
        includeSubAgents: false,
        activeTarget) is null &&
    RecoveryService.ValidateTargetThreadEligibility(
        archivedTarget.Id,
        includeSubAgents: false,
        archivedTarget) is { FailureKind: RecoveryFailureKind.PolicyChanged } &&
    RecoveryService.ValidateTargetThreadEligibility(
        subAgentTarget.Id,
        includeSubAgents: false,
        subAgentTarget) is { FailureKind: RecoveryFailureKind.PolicyChanged } &&
    RecoveryService.ValidateTargetThreadEligibility(
        subAgentTarget.Id,
        includeSubAgents: true,
        subAgentTarget) is null &&
    RecoveryService.ValidateTargetThreadEligibility(
        ephemeralTarget.Id,
        includeSubAgents: true,
        ephemeralTarget) is { FailureKind: RecoveryFailureKind.PolicyChanged } &&
    RecoveryService.ValidateTargetThreadEligibility(
        "thread-target-expected",
        includeSubAgents: true,
        activeTarget) is { FailureKind: RecoveryFailureKind.PolicyChanged },
    "targeted pre-dispatch validation fails closed on archived, ephemeral, filtered subagent, and mismatched tasks");

var classifier = new RecoveryClassifier();
var localization = new LocalizationService();
using var activeThreadJson = JsonDocument.Parse("""
    {"status":{"type":"active","activeFlags":[]}}
    """);
var cacheNow = DateTimeOffset.UtcNow;
var ipcPayload = Encoding.UTF8.GetBytes("{\"type\":\"response\"}");
var ipcFrame = DesktopIpcClient.EncodeFrame(ipcPayload);
Assert(
    DesktopIpcClient.DecodeFrameLength(ipcFrame.AsSpan(0, sizeof(uint))) == ipcPayload.Length &&
    ipcFrame.AsSpan(sizeof(uint)).SequenceEqual(ipcPayload),
    "Desktop IPC framing uses a little-endian length prefix and UTF-8 JSON payload");
var followingActivity = DesktopIpcClient.ParseActivityEvent(Json("""
    {
      "type":"broadcast",
      "method":"thread-stream-following-changed",
      "sourceClientId":"desktop-client-a",
      "version":1,
      "params":{
        "conversationId":"thread-live",
        "hostId":"local",
        "following":true
      }
    }
    """));
var streamSnapshotActivity = DesktopIpcClient.ParseActivityEvent(Json("""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-a",
      "version":11,
      "params":{
        "conversationId":"thread-live",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":7,
          "conversationState":{
            "threadRuntimeStatus":{"type":"active","activeFlags":[]}
          }
        }
      }
    }
    """));
var streamPatchesActivity = DesktopIpcClient.ParseActivityEvent(Json("""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-a",
      "version":11,
      "params":{
        "conversationId":"thread-live",
        "hostId":"local",
        "change":{
          "type":"patches",
          "baseRevision":7,
          "revision":8,
          "patches":[
            {
              "op":"replace",
              "path":["threadRuntimeStatus","type"],
              "value":"idle"
            },
            {
              "op":"replace",
              "path":["turnHistory","history","entitiesByKey","turn:latest","status"],
              "value":"failed"
            },
            {
              "op":"replace",
              "path":["turnHistory","history","entitiesByKey","item:assistant","text"],
              "value":"streaming text is not a scan edge"
            }
          ]
        }
      }
    }
    """));
var itemStatusPatchesActivity = DesktopIpcClient.ParseActivityEvent(Json("""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-a",
      "version":11,
      "params":{
        "conversationId":"thread-live",
        "hostId":"local",
        "change":{
          "type":"patches",
          "baseRevision":8,
          "revision":9,
          "patches":[
            {
              "op":"replace",
              "path":["turnHistory","history","entitiesByKey","item:tool","status"],
              "value":"completed"
            }
          ]
        }
      }
    }
    """));
Assert(
    followingActivity is
    {
        Method: "thread-stream-following-changed",
        Version: 1,
        SourceClientId: "desktop-client-a",
        ConversationId: "thread-live",
        HostId: "local",
        Following: true
    } &&
    streamSnapshotActivity is
    {
        Method: "thread-stream-state-changed",
        Version: 11,
        SourceClientId: "desktop-owner-a",
        ConversationId: "thread-live",
        ChangeType: "snapshot",
        Revision: 7,
        RuntimeStatus: "active"
    } &&
    streamPatchesActivity is
    {
        ChangeType: "patches",
        BaseRevision: 7,
        Revision: 8,
        RuntimeStatus: "idle",
        HasRelevantStatePatch: true
    } &&
    itemStatusPatchesActivity is { HasRelevantStatePatch: false },
    "Desktop IPC activity parsing retains stream epochs and ignores item churn while extracting runtime or turn-boundary edges");
var ownerStateThreadId = Guid.NewGuid().ToString("D");
var ownerStateTurnId = Guid.NewGuid().ToString("D");
var canonicalOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-canonical",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":9,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":"idle",
            "turns":[],
            "turnHistory":{
              "kind":"canonical",
              "history":{
                "entitiesByKey":{
                  "turn:older":{"turnId":"{{Guid.NewGuid():D}}","status":"completed"},
                  "item:assistant":{"type":"message","status":"completed"},
                  "turn:latest":{"turnId":"{{ownerStateTurnId}}","status":"failed"}
                },
                "islands":[{
                  "entries":[
                    {"key":"turn:older","value":"turn:older"},
                    {"key":"item:assistant","value":"item:assistant"},
                    {"key":"turn:latest","value":"turn:latest"}
                  ],
                  "newerBoundary":{"status":"exhausted","boundaryId":"tail:newer"}
                }]
              }
            }
          }
        }
      }
    }
    """));
DesktopThreadOwnerStateSnapshot? canonicalOwnerSnapshot = null;
var canonicalOwnerParsed = canonicalOwnerActivity is not null &&
                           DesktopThreadOwnerStateSnapshot.TryParse(
                               canonicalOwnerActivity,
                               out canonicalOwnerSnapshot) &&
                           canonicalOwnerSnapshot is not null;
Assert(
    canonicalOwnerParsed &&
    canonicalOwnerSnapshot is
    {
        HostId: "local",
        OwnerClientId: "desktop-owner-canonical",
        Revision: 9,
        RuntimeStatus: "idle",
        LatestTurnStatus: "failed"
    } &&
    canonicalOwnerSnapshot.ConversationId == ownerStateThreadId &&
    canonicalOwnerSnapshot.LatestTurnId == ownerStateTurnId,
    "owner-state parsing walks the stock canonical turn-history tail and resolves its latest turn");
var legacyOwnerTurnId = Guid.NewGuid().ToString("D");
var legacyOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-legacy",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"legacy-host",
        "change":{
          "type":"snapshot",
          "revision":4,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":{"type":"idle"},
            "turns":[
              {"turnId":"{{Guid.NewGuid():D}}","status":"completed"},
              {"turnId":"{{legacyOwnerTurnId}}","status":"interrupted"}
            ]
          }
        }
      }
    }
    """));
DesktopThreadOwnerStateSnapshot? legacyOwnerSnapshot = null;
Assert(
    legacyOwnerActivity is not null &&
    DesktopThreadOwnerStateSnapshot.TryParse(legacyOwnerActivity, out legacyOwnerSnapshot) &&
    legacyOwnerSnapshot is
    {
        HostId: "legacy-host",
        Revision: 4,
        RuntimeStatus: "idle",
        LatestTurnStatus: "interrupted"
    } &&
    legacyOwnerSnapshot.LatestTurnId == legacyOwnerTurnId,
    "owner-state parsing retains the stock legacy turns fallback when canonical history is absent");
var nonExhaustedCanonicalActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-incomplete",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":10,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":"idle",
            "turns":[{"turnId":"{{ownerStateTurnId}}","status":"failed"}],
            "turnHistory":{
              "kind":"canonical",
              "history":{
                "entitiesByKey":{
                  "turn:latest":{"turnId":"{{ownerStateTurnId}}","status":"failed"}
                },
                "islands":[{
                  "entries":[{"key":"turn:latest","value":"turn:latest"}],
                  "newerBoundary":{"status":"available","boundaryId":"tail:newer"}
                }]
              }
            }
          }
        }
      }
    }
    """));
Assert(
    nonExhaustedCanonicalActivity is not null &&
    DesktopThreadOwnerStateSnapshot.Parse(nonExhaustedCanonicalActivity, out _) ==
        DesktopThreadOwnerStateSnapshot.ParseStatus.Pending &&
    !DesktopThreadOwnerStateSnapshot.TryParse(nonExhaustedCanonicalActivity, out _),
    "owner-state parsing keeps a known canonical history with an available newer boundary pending");
var unknownCanonicalOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-unknown-history",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":10,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":"idle",
            "turns":[{"turnId":"{{ownerStateTurnId}}","status":"failed"}],
            "turnHistory":{"kind":"future","history":{ } }
          }
        }
      }
    }
    """));
Assert(
    unknownCanonicalOwnerActivity is not null &&
    DesktopThreadOwnerStateSnapshot.Parse(unknownCanonicalOwnerActivity, out _) ==
        DesktopThreadOwnerStateSnapshot.ParseStatus.Incompatible,
    "owner-state parsing rejects an unknown canonical history shape instead of falling back to legacy turns");
// A live 2026-08-29 recovery cleared the owner-activation gate and then refused at the
// ownerSnapshot stage with a bare "Incompatible", which cannot say whether the stock Desktop
// renamed a field, moved to a new history kind, or sent an empty envelope. The reason has to name
// the rejected field, and it may carry a protocol token only when that token cannot smuggle task
// content: a prose or title-shaped kind must be reported as the bare field name.
var proseKindOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-prose-kind",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":12,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":"idle",
            "turns":[{"turnId":"{{ownerStateTurnId}}","status":"failed"}],
            "turnHistory":{"kind":"canonical history 我的对话 5","history":{ } }
          }
        }
      }
    }
    """));
var unexpectedBoundaryOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-unexpected-boundary",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":13,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":"idle",
            "turns":[{"turnId":"{{ownerStateTurnId}}","status":"failed"}],
            "turnHistory":{
              "kind":"canonical",
              "history":{
                "entitiesByKey":{
                  "turn:latest":{"turnId":"{{ownerStateTurnId}}","status":"failed"}
                },
                "islands":[{
                  "entries":[{"key":"turn:latest","value":"turn:latest"}],
                  "newerBoundary":{"status":"partial","boundaryId":"tail:newer"}
                }]
              }
            }
          }
        }
      }
    }
    """));
var mismatchedStateIdOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-mismatched-state",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":14,
          "conversationState":{
            "id":"{{Guid.NewGuid():D}}",
            "threadRuntimeStatus":"idle",
            "turns":[{"turnId":"{{ownerStateTurnId}}","status":"failed"}]
          }
        }
      }
    }
    """));
// The live 08-29 refusals are all a thread's first `SetThreadFollowingAsync` of the session, which
// makes a not-yet-loaded canonical history the leading suspect. This payload pins what that shape
// reports today — `turnHistory.islands.empty`, and specifically *not* a silent fallback to the
// legacy `turns` array that is present and valid right beside it. If the empty-islands case is ever
// reclassified as Pending, this assertion is the one that must be updated deliberately.
var emptyHistoryIslandsOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-empty-islands",
      "version":11,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":15,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":"idle",
            "turns":[{"turnId":"{{ownerStateTurnId}}","status":"failed"}],
            "turnHistory":{
              "kind":"canonical",
              "history":{
                "entitiesByKey":{
                  "turn:latest":{"turnId":"{{ownerStateTurnId}}","status":"failed"}
                },
                "islands":[]
              }
            }
          }
        }
      }
    }
    """));
string OwnerStateIncompatibleReason(DesktopIpcActivityEventArgs? activity)
{
    if (activity is null)
    {
        return "(activity-not-parsed)";
    }

    DesktopThreadOwnerStateSnapshot.Parse(activity, out _, out var reason);
    return reason;
}

Assert(
    OwnerStateIncompatibleReason(canonicalOwnerActivity).Length == 0 &&
    OwnerStateIncompatibleReason(nonExhaustedCanonicalActivity).Length == 0 &&
    OwnerStateIncompatibleReason(unknownCanonicalOwnerActivity) == "turnHistory.kind=future" &&
    OwnerStateIncompatibleReason(proseKindOwnerActivity) == "turnHistory.kind" &&
    OwnerStateIncompatibleReason(unexpectedBoundaryOwnerActivity) ==
        "turnHistory.newerBoundary.status=partial" &&
    OwnerStateIncompatibleReason(emptyHistoryIslandsOwnerActivity) == "turnHistory.islands.empty" &&
    OwnerStateIncompatibleReason(mismatchedStateIdOwnerActivity) == "conversationState.id",
    "an incompatible owner-state snapshot names the rejected field and reports only protocol tokens");
var wrongVersionOwnerActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
    {
      "type":"broadcast",
      "method":"thread-stream-state-changed",
      "sourceClientId":"desktop-owner-wrong-version",
      "version":12,
      "params":{
        "conversationId":"{{ownerStateThreadId}}",
        "hostId":"local",
        "change":{
          "type":"snapshot",
          "revision":11,
          "conversationState":{
            "id":"{{ownerStateThreadId}}",
            "threadRuntimeStatus":"idle",
            "turns":[{"turnId":"{{ownerStateTurnId}}","status":"failed"}]
          }
        }
      }
    }
    """));
Assert(
    wrongVersionOwnerActivity is not null &&
    !DesktopThreadOwnerStateSnapshot.TryParse(wrongVersionOwnerActivity, out _),
    "owner-state parsing rejects an unexpected stock state-stream version");
Assert(
    canonicalOwnerSnapshot is not null &&
    RecoveryService.ValidateOwnerStateSnapshot(canonicalOwnerSnapshot, ownerStateTurnId) is null &&
    RecoveryService.ValidateOwnerStateSnapshot(
        canonicalOwnerSnapshot with { RuntimeStatus = "active" },
        ownerStateTurnId) is { FailureKind: RecoveryFailureKind.DesktopOwnerUnavailable } &&
    RecoveryService.ValidateOwnerStateSnapshot(
        canonicalOwnerSnapshot with { LatestTurnId = Guid.NewGuid().ToString("D") },
        ownerStateTurnId) is { FailureKind: RecoveryFailureKind.StateChanged } &&
    RecoveryService.ValidateOwnerStateSnapshot(
        canonicalOwnerSnapshot with { LatestTurnStatus = "completed" },
        ownerStateTurnId) is { FailureKind: RecoveryFailureKind.StateChanged },
    "owner-state guard permits only the expected idle failed/interrupted latest turn");
var confirmedProviderFailure = Turn(
    "failed",
    httpStatus: 429,
    error: "exceeded retry limit, last status: 429 Too Many Requests",
    confirmedTerminal: true) with
{
    Id = ownerStateTurnId
};
var confirmedSilentCompletion = confirmedProviderFailure with
{
    Status = RecoveryClassifier.IncompleteTerminalStatus,
    ErrorMessage = null,
    ErrorCode = null,
    HttpStatusCode = null,
    HasUserMessage = true,
    HasCompleteItemEvidence = true,
    HasFinalAssistantOutput = false
};
Assert(
    canonicalOwnerSnapshot is not null &&
    RecoveryService.ValidateOwnerStateSnapshot(
        canonicalOwnerSnapshot with { LatestTurnStatus = "completed" },
        confirmedProviderFailure) is null &&
    RecoveryService.ValidateOwnerStateSnapshot(
        canonicalOwnerSnapshot with { LatestTurnStatus = "completed" },
        confirmedProviderFailure with { HasConfirmedLocalTerminal = false }) is
        { FailureKind: RecoveryFailureKind.StateChanged } &&
    RecoveryService.ValidateOwnerStateSnapshot(
        canonicalOwnerSnapshot with { LatestTurnStatus = "completed" },
        confirmedSilentCompletion) is null &&
    RecoveryService.ValidateOwnerStateSnapshot(
        canonicalOwnerSnapshot with { LatestTurnStatus = "completed" },
        confirmedSilentCompletion with { HasCompleteItemEvidence = false }) is
        { FailureKind: RecoveryFailureKind.StateChanged },
    "owner completed metadata is accepted only for a confirmed provider failure or complete silent-terminal evidence");
await WithRecoveryJournalTestAsync("desktop owner-state guard isolation", async root =>
{
    using var ownerStateLog = new GuardianLog(root);
    await using var ownerStateDesktop = new DesktopIpcClient(ownerStateLog);
    var guardType = typeof(DesktopThreadOwnerStateGuard);
    var guardConstructor = guardType.GetConstructor(
        BindingFlags.Instance | BindingFlags.NonPublic,
        binder: null,
        new[] { typeof(DesktopIpcClient), typeof(string), typeof(string) },
        modifiers: null);
    var activityHandler = guardType.GetMethod(
        "OnActivityReceived",
        BindingFlags.Instance | BindingFlags.NonPublic);
    var connectionHandler = guardType.GetMethod(
        "OnConnectionChanged",
        BindingFlags.Instance | BindingFlags.NonPublic);
    var invalidatedField = guardType.GetField(
        "_invalidated",
        BindingFlags.Instance | BindingFlags.NonPublic);
    var snapshotReceivedField = guardType.GetField(
        "_snapshotReceived",
        BindingFlags.Instance | BindingFlags.NonPublic);
    var snapshotCompletionField = guardType.GetField(
        "_snapshotCompletion",
        BindingFlags.Instance | BindingFlags.NonPublic);
    if (guardConstructor is null ||
        activityHandler is null ||
        connectionHandler is null ||
        invalidatedField is null ||
        snapshotReceivedField is null ||
        snapshotCompletionField is null ||
        canonicalOwnerActivity is null ||
        nonExhaustedCanonicalActivity is null ||
        wrongVersionOwnerActivity is null)
    {
        Assert(false, "owner-state guard exposes the expected isolated event-test surface");
        return;
    }

    DesktopThreadOwnerStateGuard CreateGuard() =>
        (DesktopThreadOwnerStateGuard)guardConstructor.Invoke(
            new object[] { ownerStateDesktop, ownerStateThreadId, "local" });
    int ReadInt(FieldInfo field, DesktopThreadOwnerStateGuard guard) =>
        Convert.ToInt32(field.GetValue(guard));
    void SendActivity(DesktopThreadOwnerStateGuard guard, DesktopIpcActivityEventArgs activity) =>
        activityHandler.Invoke(guard, new object?[] { ownerStateDesktop, activity });

    var loadingGuard = CreateGuard();
    var loadingCompletion =
        (TaskCompletionSource<DesktopThreadOwnerStateSnapshot>)snapshotCompletionField.GetValue(loadingGuard)!;
    SendActivity(loadingGuard, nonExhaustedCanonicalActivity);
    var loadingTimedOut = await ThrowsAsync<TimeoutException>(() =>
        loadingCompletion.Task.WaitAsync(TimeSpan.FromMilliseconds(20)));
    var loadingStayedPending =
        loadingTimedOut &&
        !loadingCompletion.Task.IsCompleted &&
        ReadInt(snapshotReceivedField, loadingGuard) == 0 &&
        ReadInt(invalidatedField, loadingGuard) == 0;
    SendActivity(loadingGuard, canonicalOwnerActivity);
    var loadedSnapshot = await loadingCompletion.Task;
    Assert(
        loadingStayedPending &&
        loadedSnapshot.LatestTurnId == ownerStateTurnId &&
        ReadInt(snapshotReceivedField, loadingGuard) == 1 &&
        ReadInt(invalidatedField, loadingGuard) == 0,
        "owner-state guard treats loading canonical history as transient and accepts the later complete snapshot");
    await loadingGuard.DisposeAsync();

    var patchActivity = DesktopIpcClient.ParseActivityEvent(Json($$"""
        {
          "type":"broadcast",
          "method":"thread-stream-state-changed",
          "sourceClientId":"desktop-owner-canonical",
          "version":11,
          "params":{
            "conversationId":"{{ownerStateThreadId}}",
            "hostId":"local",
            "change":{"type":"patches","baseRevision":9,"revision":10,"patches":[]}
          }
        }
        """));
    var patchGuard = CreateGuard();
    SendActivity(patchGuard, canonicalOwnerActivity);
    var currentAfterSnapshot =
        ReadInt(snapshotReceivedField, patchGuard) == 1 &&
        ReadInt(invalidatedField, patchGuard) == 0;
    if (patchActivity is not null)
    {
        SendActivity(patchGuard, patchActivity);
    }

    Assert(
        patchActivity is not null &&
        currentAfterSnapshot &&
        ReadInt(invalidatedField, patchGuard) == 1,
        "owner-state guard invalidates its captured snapshot after a matching stream patch");
    await patchGuard.DisposeAsync();

    var disconnectGuard = CreateGuard();
    SendActivity(disconnectGuard, canonicalOwnerActivity);
    connectionHandler.Invoke(disconnectGuard, new object?[] { ownerStateDesktop, true });
    var currentAfterConnectedNotice = ReadInt(invalidatedField, disconnectGuard) == 0;
    connectionHandler.Invoke(disconnectGuard, new object?[] { ownerStateDesktop, false });
    Assert(
        currentAfterConnectedNotice && ReadInt(invalidatedField, disconnectGuard) == 1,
        "owner-state guard keeps a snapshot across connected notices and invalidates it on disconnect");
    await disconnectGuard.DisposeAsync();

    var ownerDisconnectedActivity = DesktopIpcClient.ParseActivityEvent(Json("""
        {
          "type":"broadcast",
          "method":"client-status-changed",
          "version":1,
          "params":{"clientId":"desktop-owner-canonical","status":"disconnected"}
        }
        """));
    var ownerDisconnectGuard = CreateGuard();
    SendActivity(ownerDisconnectGuard, canonicalOwnerActivity);
    if (ownerDisconnectedActivity is not null)
    {
        SendActivity(ownerDisconnectGuard, ownerDisconnectedActivity);
    }

    Assert(
        ownerDisconnectedActivity is not null &&
        ReadInt(invalidatedField, ownerDisconnectGuard) == 1,
        "owner-state guard invalidates immediately when the verified Desktop owner client disconnects");
    await ownerDisconnectGuard.DisposeAsync();

    var ipcResetActivity = DesktopIpcClient.ParseActivityEvent(Json("""
        {
          "type":"broadcast",
          "method":"ipc-connection-reset",
          "version":1,
          "params":{}
        }
        """));
    var resetGuard = CreateGuard();
    SendActivity(resetGuard, canonicalOwnerActivity);
    if (ipcResetActivity is not null)
    {
        SendActivity(resetGuard, ipcResetActivity);
    }

    Assert(
        ipcResetActivity is not null && ReadInt(invalidatedField, resetGuard) == 1,
        "owner-state guard invalidates across a stock Desktop IPC stream epoch reset");
    await resetGuard.DisposeAsync();

    var wrongVersionGuard = CreateGuard();
    var wrongVersionCompletion =
        (TaskCompletionSource<DesktopThreadOwnerStateSnapshot>)snapshotCompletionField.GetValue(wrongVersionGuard)!;
    SendActivity(wrongVersionGuard, wrongVersionOwnerActivity);
    var wrongVersionRejected = await ThrowsAsync<InvalidDataException>(
        () => wrongVersionCompletion.Task);
    Assert(
        wrongVersionRejected && ReadInt(invalidatedField, wrongVersionGuard) == 1,
        "owner-state guard marks an unexpected state-stream version incompatible and invalidates it");
    await wrongVersionGuard.DisposeAsync();

    var knownHostsField = typeof(DesktopIpcClient).GetField(
        "_knownOwnerHostIds",
        BindingFlags.Instance | BindingFlags.NonPublic);
    var ownerHostsField = typeof(DesktopIpcClient).GetField(
        "_ownerHostIds",
        BindingFlags.Instance | BindingFlags.NonPublic);
    var onlyHostMethod = typeof(DesktopIpcClient).GetMethod(
        "TryGetOnlyKnownOwnerHostId",
        BindingFlags.Instance | BindingFlags.NonPublic);
    var waitForHostMethod = typeof(DesktopIpcClient).GetMethod(
        "WaitForOwnerHostIdAsync",
        BindingFlags.Instance | BindingFlags.NonPublic);
    if (knownHostsField?.GetValue(ownerStateDesktop) is not ConcurrentDictionary<string, byte> knownHosts ||
        ownerHostsField?.GetValue(ownerStateDesktop) is not ConcurrentDictionary<string, string> ownerHosts ||
        onlyHostMethod is null ||
        waitForHostMethod is null)
    {
        Assert(false, "Desktop host selection exposes the expected isolated cache-test surface");
        return;
    }

    object?[] noHostArgument = { null };
    var noHostSelected = (bool)onlyHostMethod.Invoke(ownerStateDesktop, noHostArgument)!;
    knownHosts["local"] = 0;
    object?[] oneHostArgument = { null };
    var oneHostSelected = (bool)onlyHostMethod.Invoke(ownerStateDesktop, oneHostArgument)!;
    knownHosts["remote"] = 0;
    object?[] multipleHostArgument = { null };
    var multipleHostSelected = (bool)onlyHostMethod.Invoke(ownerStateDesktop, multipleHostArgument)!;
    ownerHosts[ownerStateThreadId] = "remote";
    var exactHostTask = (Task<string?>)waitForHostMethod.Invoke(
        ownerStateDesktop,
        new object[] { ownerStateThreadId, CancellationToken.None })!;
    var exactHost = await exactHostTask;
    Assert(
        !noHostSelected && noHostArgument[0] is null &&
        oneHostSelected && string.Equals(oneHostArgument[0] as string, "local", StringComparison.Ordinal) &&
        !multipleHostSelected && multipleHostArgument[0] is null &&
        string.Equals(exactHost, "remote", StringComparison.Ordinal),
        "Desktop host selection reuses one global host, fails closed on multiple hosts, and honors an exact task mapping");
});
using var nestedDesktopTurn = JsonDocument.Parse("""
    {"result":{"turn":{"id":"019f0000-0000-7000-8000-000000000001"}}}
    """);
using var directDesktopTurn = JsonDocument.Parse("""
    {"turn":{"id":"019f0000-0000-7000-8000-000000000002"}}
    """);
Assert(
    DesktopIpcClient.TryReadTurnId(nestedDesktopTurn.RootElement, out var nestedDesktopTurnId) &&
    nestedDesktopTurnId.EndsWith("0001", StringComparison.Ordinal) &&
    DesktopIpcClient.TryReadTurnId(directDesktopTurn.RootElement, out var directDesktopTurnId) &&
    directDesktopTurnId.EndsWith("0002", StringComparison.Ordinal),
    "Desktop IPC accepts the stock committed-turn acknowledgement shapes");
var nativeContinueInput = DesktopIpcClient.BuildNativeContinueInput("continue");
var structuredOriginal = DesktopIpcClient.BuildNativeOriginalInput(
    """[{"type":"text","text":"retry this","text_elements":[]},{"type":"localImage","path":"C:\\evidence.png"}]""",
    originalMessage: null,
    originalHasAttachments: true);
var fallbackOriginal = DesktopIpcClient.BuildNativeOriginalInput(
    rawOriginalInputJson: null,
    originalMessage: "retry this",
    originalHasAttachments: false);
var replayedFailedContinue = DesktopIpcClient.BuildNativeRecoveryInput(
    RecoveryActionKind.ResendContinue,
    """[{"type":"text","text":"exact failed continue","text_elements":[]}]""",
    originalMessage: "exact failed continue",
    originalHasAttachments: false,
    normalizedContinueMessage: "new configured continue");
var appendedContinue = DesktopIpcClient.BuildNativeRecoveryInput(
    RecoveryActionKind.SendContinue,
    rawOriginalInputJson: null,
    originalMessage: "ignored original",
    originalHasAttachments: false,
    normalizedContinueMessage: "new configured continue");
var attachmentFallbackRejected = false;
try
{
    _ = DesktopIpcClient.BuildNativeOriginalInput(
        rawOriginalInputJson: null,
        originalMessage: "incomplete attachment prompt",
        originalHasAttachments: true);
}
catch (DesktopIpcProtocolException exception)
{
    attachmentFallbackRejected = exception.Code == "guardian-original-input-unavailable";
}

Assert(
    DesktopIpcClient.NativeStartTurnMethod == "thread-follower-start-turn" &&
    DesktopIpcClient.NativeStartTurnVersion == 2 &&
    DesktopIpcClient.LegacyNativeStartTurnVersion == 1 &&
    DesktopIpcClient.NativeEditLastUserTurnMethod == "thread-follower-edit-last-user-turn" &&
    DesktopIpcClient.NativeEditLastUserTurnVersion == 2 &&
    DesktopIpcClient.NativeThreadFollowingMethod == "thread-stream-following-changed" &&
    DesktopIpcClient.NativeThreadFollowingVersion == 1 &&
    DesktopIpcClient.NativeThreadStateMethod == "thread-stream-state-changed" &&
    DesktopIpcClient.NativeThreadStateVersion == 11,
    "Desktop IPC declares the stock start-turn, owner-probe, and read-only follower-state contracts");
var nativeStartThreadId = Guid.NewGuid().ToString("D");
var nativeStartClientMessageId = Guid.NewGuid().ToString("D");
var nativeStartV2 = DesktopIpcClient.BuildNativeStartTurnParameters(
    DesktopIpcClient.NativeStartTurnVersion,
    nativeStartThreadId,
    nativeContinueInput,
    nativeStartClientMessageId);
var nativeStartV1 = DesktopIpcClient.BuildNativeStartTurnParameters(
    DesktopIpcClient.LegacyNativeStartTurnVersion,
    nativeStartThreadId,
    nativeContinueInput,
    nativeStartClientMessageId);
var nativeStartV2Envelope = nativeStartV2.GetProperty("turnStart");
var nativeStartV2Request = nativeStartV2Envelope.GetProperty("request");
Assert(
    nativeStartV2.GetProperty("conversationId").GetString() == nativeStartThreadId &&
    !nativeStartV2.TryGetProperty("turnStartParams", out _) &&
    nativeStartV2Request.GetProperty("threadId").GetString() == nativeStartThreadId &&
    nativeStartV2Request.GetProperty("clientUserMessageId").GetString() == nativeStartClientMessageId &&
    nativeStartV2Request.GetProperty("input").GetRawText() == nativeContinueInput.GetRawText() &&
    nativeStartV2Envelope.GetProperty("context").GetProperty("inheritThreadSettings").GetBoolean() &&
    nativeStartV1.GetProperty("conversationId").GetString() == nativeStartThreadId &&
    !nativeStartV1.TryGetProperty("turnStart", out _) &&
    nativeStartV1.GetProperty("turnStartParams").GetProperty("clientUserMessageId").GetString() ==
        nativeStartClientMessageId &&
    nativeStartV1.GetProperty("turnStartParams").GetProperty("input").GetRawText() ==
        nativeContinueInput.GetRawText(),
    "stock start-turn v2 nests the exact thread request and inherited context while legacy v1 retains turnStartParams");
Assert(
    DesktopIpcClient.ShouldFallbackNativeStartTurn(new DesktopIpcProtocolException(
        "request-version-mismatch",
        "rejected",
        DesktopIpcDeliveryStage.Rejected)) &&
    !DesktopIpcClient.ShouldFallbackNativeStartTurn(new DesktopIpcProtocolException(
        "request-version-mismatch",
        "unknown delivery",
        DesktopIpcDeliveryStage.DispatchedUnknown)) &&
    !DesktopIpcClient.ShouldFallbackNativeStartTurn(new DesktopIpcProtocolException(
        "no-client-found",
        "rejected",
        DesktopIpcDeliveryStage.Rejected)),
    "start-turn falls back only after an explicit uncommitted version mismatch");
Assert(
    structuredOriginal.GetArrayLength() == 2 &&
    structuredOriginal[1].GetProperty("type").GetString() == "localImage" &&
    fallbackOriginal.GetArrayLength() == 1 &&
    fallbackOriginal[0].GetProperty("text").GetString() == "retry this" &&
    attachmentFallbackRejected,
    "stock start-turn preserves structured original input and fails closed instead of dropping attachments");
Assert(
    nativeContinueInput.ValueKind == JsonValueKind.Array &&
    nativeContinueInput.GetArrayLength() == 1 &&
    nativeContinueInput[0].GetProperty("type").GetString() == "text" &&
    nativeContinueInput[0].GetProperty("text").GetString() == "continue" &&
    nativeContinueInput[0].GetProperty("text_elements").ValueKind == JsonValueKind.Array &&
    nativeContinueInput[0].GetProperty("text_elements").GetArrayLength() == 0,
    "native continue payload contains one visible text input with an empty text_elements array");
Assert(
    replayedFailedContinue[0].GetProperty("text").GetString() == "exact failed continue" &&
    appendedContinue[0].GetProperty("text").GetString() == "new configured continue",
    "ResendContinue replays the failed turn input while SendContinue appends the configured message");
Assert(
    DesktopThreadOwnerActivator.BuildThreadUri("019f0000-0000-7000-8000-000000000010") ==
        "codex://threads/019f0000-0000-7000-8000-000000000010",
    "owner activation uses the registered stock Codex task deep link without query flags or patch payloads");
await WithRecoveryJournalTestAsync("desktop owner activation", async root =>
{
    using var ownerLog = new GuardianLog(root);
    var alreadyAvailablePlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromMinutes(1));
    var alreadyAvailable = new DesktopThreadOwnerActivator(
        new FakeDesktopThreadOwnerProbe(_ => OwnerProbe(DesktopThreadOwnerProbeStatus.Available)),
        ownerLog,
        alreadyAvailablePlatform,
        TimeSpan.FromSeconds(15),
        TimeSpan.FromMilliseconds(20),
        TimeSpan.Zero);
    var alreadyAvailableResult = await alreadyAvailable.EnsureOwnerAsync(Guid.NewGuid().ToString("D"));
    Assert(
        alreadyAvailableResult.Status == DesktopThreadOwnerActivationStatus.AlreadyAvailable &&
        alreadyAvailablePlatform.OpenThreadCount == 0,
        "an existing Desktop owner is reused without opening a task deep link");

    var activeExistingOwnerPlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromSeconds(2));
    var activeExistingOwner = new DesktopThreadOwnerActivator(
        new FakeDesktopThreadOwnerProbe(_ => OwnerProbe(DesktopThreadOwnerProbeStatus.Available)),
        ownerLog,
        activeExistingOwnerPlatform,
        TimeSpan.FromSeconds(15),
        TimeSpan.FromMilliseconds(20),
        TimeSpan.Zero);
    var activeExistingOwnerResult = await activeExistingOwner.EnsureOwnerAsync(Guid.NewGuid().ToString("D"));
    Assert(
        activeExistingOwnerResult.Status == DesktopThreadOwnerActivationStatus.AlreadyAvailable &&
        activeExistingOwnerPlatform.OpenThreadCount == 0,
        "an existing owner can be inspected without navigation while the Windows user is active");

    var activeActivity = activeExistingOwner.CheckUserActivity();
    var idleActivity = alreadyAvailable.CheckUserActivity();
    var unknownActivityPlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.Zero)
    {
        IdleTimeException = new InvalidOperationException("idle time unavailable")
    };
    var unknownActivity = new DesktopThreadOwnerActivator(
        new FakeDesktopThreadOwnerProbe(_ => OwnerProbe(DesktopThreadOwnerProbeStatus.Available)),
        ownerLog,
        unknownActivityPlatform,
        TimeSpan.FromSeconds(15),
        TimeSpan.FromMilliseconds(20),
        TimeSpan.Zero).CheckUserActivity();
    Assert(
        activeActivity.Status == DesktopUserActivityStatus.Active &&
        idleActivity.Status == DesktopUserActivityStatus.Idle &&
        unknownActivity.Status == DesktopUserActivityStatus.Unknown,
        "user-activity checks distinguish active, idle, and unverifiable Windows input state");

    var fallbackChecks = 0;
    DesktopUserActivityResult FallbackActivity()
    {
        fallbackChecks++;
        return activeActivity;
    }

    var hookNow = DateTimeOffset.UtcNow;
    var hookClear = RecoveryService.ResolveDispatchActivity(
        new RecoveryInterferenceSnapshot(
            RecoveryInterferenceStatus.Clear,
            "Codex composer is clear.",
            false,
            hookNow),
        FallbackActivity,
        hookNow);
    var hookEditing = RecoveryService.ResolveDispatchActivity(
        new RecoveryInterferenceSnapshot(
            RecoveryInterferenceStatus.Editing,
            "Codex composer is focused.",
            true,
            hookNow),
        FallbackActivity,
        hookNow);
    var hookUnknown = RecoveryService.ResolveDispatchActivity(
        new RecoveryInterferenceSnapshot(
            RecoveryInterferenceStatus.Unknown,
            "Hook unavailable.",
            false,
            hookNow),
        FallbackActivity,
        hookNow);
    var staleHookClear = RecoveryService.ResolveDispatchActivity(
        new RecoveryInterferenceSnapshot(
            RecoveryInterferenceStatus.Clear,
            "Stale clear observation.",
            false,
            hookNow - RecoveryService.DispatchObservationMaxAge - TimeSpan.FromMilliseconds(1)),
        FallbackActivity,
        hookNow);
    var strictUnknown = RecoveryService.ResolveDispatchActivity(
        new RecoveryInterferenceSnapshot(
            RecoveryInterferenceStatus.Unknown,
            "Strict observer unavailable.",
            false,
            hookNow),
        FallbackActivity,
        hookNow,
        requireExplicitClear: true);
    var strictStaleClear = RecoveryService.ResolveDispatchActivity(
        new RecoveryInterferenceSnapshot(
            RecoveryInterferenceStatus.Clear,
            "Strict stale clear observation.",
            false,
            hookNow - RecoveryService.DispatchObservationMaxAge - TimeSpan.FromMilliseconds(1)),
        FallbackActivity,
        hookNow,
        requireExplicitClear: true);
    var strictMissing = RecoveryService.ResolveDispatchActivity(
        null,
        FallbackActivity,
        hookNow,
        requireExplicitClear: true);
    Assert(
        hookClear.Status == DesktopUserActivityStatus.Idle &&
        hookEditing.Status == DesktopUserActivityStatus.Active &&
        hookUnknown.Status == DesktopUserActivityStatus.Active &&
        staleHookClear.Status == DesktopUserActivityStatus.Active &&
        strictUnknown.Status == DesktopUserActivityStatus.Unknown &&
        strictStaleClear.Status == DesktopUserActivityStatus.Unknown &&
        strictMissing.Status == DesktopUserActivityStatus.Unknown &&
        fallbackChecks == 2,
        "production recovery permits only a fresh clear composer observation while legacy offline callers retain the explicit fallback");

    await using (var observationHook = new WindowsCodexInteractionHook(ownerLog))
    {
        var hookCountField = typeof(WindowsCodexInteractionHook).GetField(
            "_hookCount",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingFieldException(nameof(WindowsCodexInteractionHook), "_hookCount");
        var workerField = typeof(WindowsCodexInteractionHook).GetField(
            "_worker",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingFieldException(nameof(WindowsCodexInteractionHook), "_worker");
        var setHealth = typeof(WindowsCodexInteractionHook).GetMethod(
            "SetObservationHealth",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(nameof(WindowsCodexInteractionHook), "SetObservationHealth");
        var workerCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        hookCountField.SetValue(observationHook, 3);
        workerField.SetValue(observationHook, workerCompletion.Task);
        var availabilityChanges = 0;
        observationHook.AvailabilityChanged += (_, _) => availabilityChanges++;

        var initiallyUnverified = !observationHook.IsAvailable;
        setHealth.Invoke(observationHook, [true]);
        var healthyAfterSuccess = observationHook.IsAvailable;
        setHealth.Invoke(observationHook, [true]);
        setHealth.Invoke(observationHook, [false]);
        var unavailableAfterTimeout = !observationHook.IsAvailable;
        setHealth.Invoke(observationHook, [true]);
        var recoveredAfterSuccess = observationHook.IsAvailable;
        workerCompletion.TrySetResult();
        await Task.Yield();

        Assert(
            initiallyUnverified && healthyAfterSuccess && unavailableAfterTimeout &&
            recoveredAfterSuccess && !observationHook.IsAvailable && availabilityChanges == 3,
            "enhanced observation is healthy only after a successful inspection, degrades immediately, and can recover");
    }

    await using var lostWakeReader = new AppServerClient(new CodexCliLocator(), ownerLog);
    await using var lostWakeDesktop = new DesktopIpcClient(ownerLog);
    var lostWakeGuard = new LostWakeRecoveryInterferenceGuard();
    var lostWakeRecovery = new RecoveryService(
        lostWakeReader,
        lostWakeDesktop,
        alreadyAvailable,
        new RecoveryOperationJournal(root),
        ownerLog,
        lostWakeGuard);
    await lostWakeRecovery.WaitForRecoveryInterferenceToClearAsync("lost-wake-test")
        .WaitAsync(TimeSpan.FromSeconds(2));
    Assert(
        lostWakeGuard.CheckCount == 2 && lostWakeGuard.WaitCount == 1,
        "versioned Codex editor waiters cannot lose an editing-to-clear edge between check and wait");

    var deepNow = DateTimeOffset.UtcNow;
    var deepThreadA = "019fabcd-0000-7000-8000-000000000001";
    var deepThreadB = "019fabcd-0000-7000-8000-000000000002";
    var deepTurn = "019fabcd-0000-7000-8000-000000000003";
    var deepThreadUnknownComposer = "019fabcd-0000-7000-8000-000000000004";
    var deepState = new CodexDeepObservationStateStore(
        CodexDeepObservationService.ProtocolVersion,
        CodexDeepObservationService.ContractId,
        CodexDeepObservationService.SnapshotMaxAge);
    deepState.ReplaceExpectedRenderers(["deep-client"], discoveryComplete: true);
    var deepChanges = new List<CodexDeepThreadChangedEventArgs>();
    deepState.ThreadChanged += (_, eventArgs) => deepChanges.Add(eventArgs);
    var wrongContractDeepHello = JsonSerializer.Serialize(new
    {
        kind = "hello",
        seq = 0,
        protocol = CodexDeepObservationService.ProtocolVersion,
        contractId = "wrong-contract",
        source = CodexDeepObservationService.PipeHelloSource,
        windowKind = "electron"
    });
    var legacyDeepHello = JsonSerializer.Serialize(new
    {
        kind = "hello",
        seq = 0,
        protocol = CodexDeepObservationService.ProtocolVersion,
        packageVersion = "26.730.8199.0",
        appBuild = "26.730.61639",
        preloadSha256 = "00",
        windowKind = "electron"
    });
    var mixedDeepHello = JsonSerializer.Serialize(new
    {
        kind = "hello",
        seq = 0,
        protocol = CodexDeepObservationService.ProtocolVersion,
        contractId = CodexDeepObservationService.ContractId,
        source = CodexDeepObservationService.PipeHelloSource,
        packageVersion = "26.730.8199.0",
        appBuild = "26.730.61639",
        windowKind = "electron"
    });
    Assert(
        !deepState.TryConnect(
            "bad-client",
            wrongContractDeepHello,
            deepNow,
            out var badDeepReason) &&
        badDeepReason == "contract-mismatch" &&
        !deepState.TryConnect("bad-client", legacyDeepHello, deepNow, out var legacyReason) &&
        legacyReason == "invalid-hello" &&
        !deepState.TryConnect("bad-client", mixedDeepHello, deepNow, out var mixedReason) &&
        mixedReason == "invalid-hello" &&
        !deepState.IsAvailable(deepNow),
        "deep observation rejects wrong, legacy, and mixed capability handshakes");

    var deepHello = JsonSerializer.Serialize(new
    {
        kind = "hello",
        seq = 0,
        protocol = CodexDeepObservationService.ProtocolVersion,
        contractId = CodexDeepObservationService.ContractId,
        source = CodexDeepObservationService.PipeHelloSource,
        windowKind = "electron"
    });
    Assert(
        deepState.TryConnect("deep-client", deepHello, deepNow, out var deepHelloReason) &&
        deepHelloReason == "accepted" &&
        !deepState.IsAvailable(deepNow),
        "deep observation requires a full renderer snapshot after the handshake");
    var deepSnapshotA = JsonSerializer.Serialize(new
    {
        kind = "snapshot",
        seq = 1,
        routeKnown = true,
        threadId = deepThreadA,
        composerKnown = true,
        editorPresent = true,
        composerFocused = true,
        hasDraft = true
    });
    Assert(
        deepState.Apply("deep-client", deepSnapshotA, deepNow) && deepState.IsAvailable(deepNow),
        "the complete expected renderer set activates only after a version-matched full snapshot");
    deepState.ReplaceExpectedRenderers(["deep-client", "deep-client-b"], discoveryComplete: true);
    Assert(
        deepState.TryConnect("deep-client-b", deepHello, deepNow, out var deepHelloBReason) &&
        deepHelloBReason == "accepted" &&
        !deepState.IsAvailable(deepNow),
        "adding an expected renderer fails the complete set closed until its full snapshot arrives");
    var deepSnapshotB = JsonSerializer.Serialize(new
    {
        kind = "snapshot",
        seq = 1,
        routeKnown = true,
        threadId = deepThreadB,
        composerKnown = true,
        editorPresent = true,
        composerFocused = false,
        hasDraft = false
    });
    Assert(
        deepState.Apply("deep-client-b", deepSnapshotB, deepNow) && deepState.IsAvailable(deepNow),
        "a second target renderer can publish an independently verified clear composer");
    deepState.ReplaceExpectedRenderers(
        ["deep-client", "deep-client-b", "deep-client-unknown"],
        discoveryComplete: true);
    Assert(
        deepState.TryConnect("deep-client-unknown", deepHello, deepNow, out _) &&
        deepState.Apply(
            "deep-client-unknown",
            JsonSerializer.Serialize(new
            {
                kind = "snapshot",
                seq = 1,
                routeKnown = true,
                threadId = deepThreadUnknownComposer,
                composerKnown = true,
                editorPresent = false,
                composerFocused = (bool?)null,
                hasDraft = (bool?)null
            }),
            deepNow) &&
        deepState.CheckInterference(deepThreadUnknownComposer, deepNow).Status ==
            RecoveryInterferenceStatus.Unknown,
        "a visible target with an unverified editor never becomes clear by treating unknown draft state as false");
    var targetAEditing = deepState.CheckInterference(deepThreadA, deepNow);
    var targetBClear = deepState.CheckInterference(deepThreadB, deepNow);
    var unseenTargetUnknown = deepState.CheckInterference(
        "019fabcd-0000-7000-8000-000000000099",
        deepNow);
    Assert(
        targetAEditing.Status == RecoveryInterferenceStatus.Editing &&
        targetAEditing.HasFocusedDraft &&
        targetBClear.Status == RecoveryInterferenceStatus.Clear &&
        targetBClear.ObservedAt == deepNow &&
        unseenTargetUnknown.Status == RecoveryInterferenceStatus.Unknown,
        "deep observation blocks the edited target, permits a directly observed clear target, and fails closed for an unseen target");
    deepState.ReplaceExpectedRenderers(
        ["deep-client", "deep-client-b", "deep-client-unknown", "deep-client-route-unknown"],
        discoveryComplete: true);
    Assert(
        deepState.TryConnect("deep-client-route-unknown", deepHello, deepNow, out _) &&
        deepState.Apply(
            "deep-client-route-unknown",
            JsonSerializer.Serialize(new
            {
                kind = "snapshot",
                seq = 1,
                routeKnown = false,
                threadId = (string?)null,
                composerKnown = true,
                editorPresent = true,
                composerFocused = false,
                hasDraft = false
            }),
            deepNow) &&
        deepState.CheckInterference(deepThreadB, deepNow).Status ==
            RecoveryInterferenceStatus.Unknown,
        "one renderer with an unknown route prevents another renderer from authorizing clear");
    deepState.ReplaceExpectedRenderers(
        ["deep-client", "deep-client-b", "deep-client-unknown"],
        discoveryComplete: true);
    Assert(
        deepState.CheckInterference(deepThreadB, deepNow).Status == RecoveryInterferenceStatus.Clear,
        "removing the unknown-route renderer restores the authoritative expected set");
    var delayedDeepHeartbeatAt = deepNow + RecoveryService.DispatchObservationMaxAge +
        TimeSpan.FromMilliseconds(1);
    var delayedDeepHeartbeat = JsonSerializer.Serialize(new { kind = "heartbeat", seq = 2 });
    Assert(
        deepState.Apply("deep-client-b", delayedDeepHeartbeat, delayedDeepHeartbeatAt),
        "a renderer heartbeat preserves connection health without restamping composer evidence");
    var oldComposerClear = deepState.CheckInterference(deepThreadB, delayedDeepHeartbeatAt);
    var oldComposerActivity = RecoveryService.ResolveDispatchActivity(
        oldComposerClear,
        () => activeActivity,
        delayedDeepHeartbeatAt);
    Assert(
        oldComposerClear.Status == RecoveryInterferenceStatus.Clear &&
        oldComposerClear.ObservedAt == deepNow &&
        oldComposerActivity.Status == DesktopUserActivityStatus.Active,
        "lifecycle traffic cannot make an old clear composer snapshot pass the final dispatch freshness gate");
    var deepSequenceNow = delayedDeepHeartbeatAt;

    var deepStreamError = JsonSerializer.Serialize(new
    {
        kind = "streamError",
        seq = 2,
        threadId = deepThreadA,
        turnId = deepTurn,
        willRetry = true,
        errorKind = "responseStreamDisconnected",
        httpStatusCode = 429,
        reconnectAttempt = 4,
        reconnectMaxAttempts = 5,
        messageText = "must-not-be-retained",
        apiKey = "must-not-be-retained"
    });
    Assert(
        deepState.Apply("deep-client", deepStreamError, deepSequenceNow.AddMilliseconds(1)) &&
        deepState.TryGetThreadSnapshot(
            deepThreadA,
            deepSequenceNow.AddMilliseconds(1),
            out var reconnectSnapshot) &&
        reconnectSnapshot is
        {
            Phase: CodexDeepThreadPhase.Reconnecting,
            ErrorKind: "responseStreamDisconnected",
            HttpStatusCode: 429,
            ReconnectAttempt: 4,
            ReconnectMaxAttempts: 5,
            WillRetry: true
        },
        "deep observation retains only allowlisted reconnect metadata and ignores extra content fields");
    var deepSnapshotProperties = typeof(CodexDeepThreadSnapshot)
        .GetProperties(BindingFlags.Instance | BindingFlags.Public)
        .Select(property => property.Name)
        .ToHashSet(StringComparer.Ordinal);
    Assert(
        !deepSnapshotProperties.Contains("Message") &&
        !deepSnapshotProperties.Contains("Content") &&
        !deepSnapshotProperties.Contains("Token") &&
        !deepSnapshotProperties.Contains("ApiKey"),
        "deep observation state has no field capable of retaining message text, tool output, tokens, or API keys");

    var deepItem = JsonSerializer.Serialize(new
    {
        kind = "item",
        seq = 3,
        threadId = deepThreadA,
        turnId = deepTurn,
        phase = "started",
        itemType = "fileChange"
    });
    Assert(
        deepState.Apply("deep-client", deepItem, deepSequenceNow.AddMilliseconds(2)) &&
        deepState.TryGetThreadSnapshot(
            deepThreadA,
            deepSequenceNow.AddMilliseconds(2),
            out var itemSnapshot) &&
        itemSnapshot is { Phase: CodexDeepThreadPhase.Tool, ItemType: "fileChange" } &&
        deepChanges.LastOrDefault() is { Kind: CodexDeepChangeKind.Item } &&
        !GuardianEngine.ShouldRefreshFromDeepObservation(CodexDeepChangeKind.Item) &&
        !GuardianEngine.ShouldRefreshFromDeepObservation(CodexDeepChangeKind.Expired) &&
        GuardianEngine.ShouldRefreshFromDeepObservation(CodexDeepChangeKind.ThreadState) &&
        GuardianEngine.ShouldRefreshFromDeepObservation(CodexDeepChangeKind.Turn) &&
        GuardianEngine.ShouldRefreshFromDeepObservation(CodexDeepChangeKind.StreamError),
        "deep item phases update the live display cache without scheduling an authoritative read; only state edges wake one");

    var deepVersion = deepState.CheckInterference(
        deepThreadA,
        deepSequenceNow.AddMilliseconds(2)).Version;
    var deepChanged = deepState.WaitForChangeAsync(deepVersion, CancellationToken.None);
    var deepHeartbeat = JsonSerializer.Serialize(new { kind = "heartbeat", seq = 4 });
    Assert(
        deepState.Apply("deep-client", deepHeartbeat, deepSequenceNow.AddMilliseconds(3)),
        "a contiguous deep-observation heartbeat is accepted");
    await deepChanged.WaitAsync(TimeSpan.FromSeconds(1));
    Assert(deepChanged.IsCompletedSuccessfully, "deep-observation waiters wake on the next sequence");

    var deepGap = JsonSerializer.Serialize(new
    {
        kind = "threadState",
        seq = 6,
        threadId = deepThreadA,
        status = "idle"
    });
    Assert(
        !deepState.Apply("deep-client", deepGap, deepSequenceNow.AddMilliseconds(4)) &&
        !deepState.IsAvailable(deepSequenceNow.AddMilliseconds(4)) &&
        deepState.CheckInterference(deepThreadA, deepSequenceNow.AddMilliseconds(4)).Status ==
            RecoveryInterferenceStatus.Unknown,
        "a sequence gap in any expected renderer fails the complete renderer set closed");
    var deepResync = JsonSerializer.Serialize(new
    {
        kind = "snapshot",
        seq = 7,
        routeKnown = true,
        threadId = deepThreadB,
        composerKnown = true,
        editorPresent = true,
        composerFocused = false,
        hasDraft = false
    });
    Assert(
        deepState.Apply("deep-client", deepResync, deepSequenceNow.AddMilliseconds(5)) &&
        deepState.IsAvailable(deepSequenceNow.AddMilliseconds(5)) &&
        deepState.CheckInterference(deepThreadB, deepSequenceNow.AddMilliseconds(5)).Status ==
            RecoveryInterferenceStatus.Clear,
        "a later full renderer snapshot safely resynchronizes a sequence gap");
    var deepExpiredAt = deepSequenceNow + CodexDeepObservationService.SnapshotMaxAge +
        TimeSpan.FromMilliseconds(100);
    Assert(
        !deepState.IsAvailable(deepExpiredAt) &&
        deepState.CheckInterference(deepThreadB, deepExpiredAt).Status == RecoveryInterferenceStatus.Unknown,
        "stale deep-observation state expires to unknown and cannot bypass the fallback gate");
    var deepChangesBeforePrune = deepChanges.Count;
    deepState.PruneStale(deepExpiredAt);
    Assert(
        !deepState.TryGetThreadSnapshot(deepThreadA, deepExpiredAt, out _) &&
        deepChanges.Skip(deepChangesBeforePrune).Any(eventArgs =>
            eventArgs.ThreadId == deepThreadA &&
            eventArgs.Kind == CodexDeepChangeKind.Expired),
        "expired deep task hints publish a display-only clearing edge instead of leaving stale status visible");

    var runtimeResources = CodexCdpRuntimeResources.Load();
    Assert(
        runtimeResources.Profile.Mode == "read-only-cdp-pipe-runtime" &&
        runtimeResources.Profile.Transport == "remote-debugging-io-pipes" &&
        runtimeResources.HookSource.Contains(
            "requestSnapshot: () => publishSnapshot(true)",
            StringComparison.Ordinal) &&
        !runtimeResources.HookSource.Contains("remote-debugging-port", StringComparison.Ordinal),
        "the embedded production CDP resources are exact-hash verified, read-only, and pipe-only");

    var cdpHello = JsonSerializer.Serialize(new
    {
        kind = "hello",
        seq = 1,
        protocol = 1,
        hookVersion = CodexCdpObservationProtocol.HookVersion,
        contractId = CodexCdpObservationProtocol.ContractId,
        source = "cdp-main-world",
        pageProtocol = "app",
        bridgePresent = true
    });
    var contentBearingHello = JsonSerializer.Serialize(new
    {
        kind = "hello",
        seq = 1,
        protocol = 1,
        hookVersion = CodexCdpObservationProtocol.HookVersion,
        contractId = CodexCdpObservationProtocol.ContractId,
        source = "cdp-main-world",
        pageProtocol = "app",
        bridgePresent = true,
        content = "must-be-rejected"
    });
    Assert(
        CodexCdpObservationProtocol.TryValidate(cdpHello, out var parsedCdpHello, out _) &&
        parsedCdpHello is { Kind: "hello", Sequence: 1 } &&
        !CodexCdpObservationProtocol.TryValidate(contentBearingHello, out _, out _),
        "the production observation protocol accepts only the exact runtime hello and rejects extra content fields");

    var cdpNow = DateTimeOffset.UtcNow;
    var cdpThreadA = "019fcdef-0000-7000-8000-000000000001";
    var cdpThreadB = "019fcdef-0000-7000-8000-000000000002";
    var cdpState = new CodexDeepObservationStateStore(
        CodexDeepObservationService.ProtocolVersion,
        CodexDeepObservationService.ContractId,
        CodexDeepObservationService.SnapshotMaxAge);
    var cdpRegistry = new CodexCdpRendererRegistry(cdpState);
    Assert(
        cdpRegistry.ReplaceTargets(["renderer-target-a", "renderer-target-b"], discoveryComplete: true) &&
        cdpRegistry.ClaimSession("renderer-target-a", "renderer-session-a") == RendererClaimResult.Accepted &&
        cdpRegistry.ClaimSession("renderer-target-b", "renderer-session-b") == RendererClaimResult.Accepted &&
        cdpRegistry.ClaimSession("renderer-target-a", "renderer-session-duplicate") ==
            RendererClaimResult.DuplicateSession,
        "the C# renderer registry has one attachment owner and rejects a duplicate session");
    cdpRegistry.MarkInstalled("renderer-session-a");
    cdpRegistry.MarkInstalled("renderer-session-b");
    Assert(
        cdpRegistry.ApplyBindingPayload("renderer-session-a", 11, cdpHello, cdpNow, out _) &&
        cdpRegistry.ApplyBindingPayload("renderer-session-b", 22, cdpHello, cdpNow, out _),
        "each expected renderer completes the exact runtime hello in its own execution context");

    string CdpSnapshot(long seq, string threadId, bool focused, bool draft) =>
        JsonSerializer.Serialize(new
        {
            kind = "snapshot",
            seq,
            routeKnown = true,
            threadId,
            composerKnown = true,
            editorPresent = true,
            composerFocused = focused,
            hasDraft = draft
        });

    Assert(
        cdpRegistry.ApplyBindingPayload(
            "renderer-session-a",
            11,
            CdpSnapshot(2, cdpThreadA, focused: false, draft: false),
            cdpNow,
            out _) &&
        !cdpRegistry.IsFullyVerified(cdpNow) &&
        cdpState.CheckInterference(cdpThreadA, cdpNow).Status == RecoveryInterferenceStatus.Unknown,
        "one verified renderer cannot hide another expected renderer that lacks a full snapshot");
    Assert(
        cdpRegistry.ApplyBindingPayload(
            "renderer-session-b",
            22,
            CdpSnapshot(2, cdpThreadB, focused: true, draft: true),
            cdpNow,
            out _) &&
        cdpRegistry.IsFullyVerified(cdpNow) &&
        cdpState.CheckInterference(cdpThreadA, cdpNow).Status == RecoveryInterferenceStatus.Clear &&
        cdpState.CheckInterference(cdpThreadB, cdpNow).Status == RecoveryInterferenceStatus.Editing,
        "all expected renderers must be verified before target-specific clear or editing evidence is usable");

    var cdpGap = JsonSerializer.Serialize(new
    {
        kind = "threadState",
        seq = 4,
        threadId = cdpThreadA,
        status = "idle",
        notificationEnvelope = "top"
    });
    Assert(
        !cdpRegistry.ApplyBindingPayload("renderer-session-a", 11, cdpGap, cdpNow, out _) &&
        !cdpRegistry.IsFullyVerified(cdpNow) &&
        cdpState.CheckInterference(cdpThreadA, cdpNow).Status == RecoveryInterferenceStatus.Unknown,
        "a sequence gap in one renderer invalidates the complete renderer set");
    Assert(
        cdpRegistry.ApplyBindingPayload(
            "renderer-session-a",
            11,
            CdpSnapshot(5, cdpThreadA, focused: false, draft: false),
            cdpNow.AddMilliseconds(1),
            out _) &&
        cdpRegistry.IsFullyVerified(cdpNow.AddMilliseconds(1)) &&
        !cdpRegistry.ApplyBindingPayload(
            "renderer-session-a",
            99,
            JsonSerializer.Serialize(new
            {
                kind = "threadState",
                seq = 6,
                threadId = cdpThreadA,
                status = "idle",
                notificationEnvelope = "top"
            }),
            cdpNow.AddMilliseconds(2),
            out _),
        "a full snapshot can resynchronize a gap, while an execution-context change without a new hello is rejected");
    Assert(
        !cdpRegistry.ApplyBindingPayload(
            "renderer-session-a",
            11,
            CdpSnapshot(5, cdpThreadA, focused: false, draft: false),
            cdpNow.AddMilliseconds(3),
            out _) &&
        !cdpRegistry.IsFullyVerified(cdpNow.AddMilliseconds(3)) &&
        cdpRegistry.ApplyBindingPayload(
            "renderer-session-a",
            11,
            CdpSnapshot(7, cdpThreadA, focused: false, draft: false),
            cdpNow.AddMilliseconds(4),
            out _),
        "a duplicate full snapshot is rejected and only a later sequence can resynchronize authority");
    Assert(
        !cdpRegistry.ReplaceTargets(["bad target id"], discoveryComplete: true) &&
        !cdpRegistry.IsFullyVerified(cdpNow.AddMilliseconds(2)),
        "an invalid or unbounded target inventory clears prior authority and fails discovery closed");

    var activeUserPlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromSeconds(2));
    var activeUser = new DesktopThreadOwnerActivator(
        new FakeDesktopThreadOwnerProbe(_ => OwnerProbe(DesktopThreadOwnerProbeStatus.Unavailable)),
        ownerLog,
        activeUserPlatform,
        TimeSpan.FromSeconds(15),
        TimeSpan.FromMilliseconds(20),
        TimeSpan.Zero);
    var activeUserResult = await activeUser.EnsureOwnerAsync(Guid.NewGuid().ToString("D"));
    Assert(
        activeUserResult.Status == DesktopThreadOwnerActivationStatus.DeferredForUserActivity &&
        activeUserPlatform.OpenThreadCount == 0,
        "an active Windows user defers owner activation without changing the visible Codex task");

    var idlePlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromMinutes(1));
    var idleProbe = new FakeDesktopThreadOwnerProbe(threadId =>
        OwnerProbe(idlePlatform.HasOpened(threadId)
            ? DesktopThreadOwnerProbeStatus.Available
            : DesktopThreadOwnerProbeStatus.Unavailable));
    var idleActivator = new DesktopThreadOwnerActivator(
        idleProbe,
        ownerLog,
        idlePlatform,
        TimeSpan.Zero,
        TimeSpan.FromMilliseconds(20),
        TimeSpan.Zero);
    var idleThreadId = Guid.NewGuid().ToString("D");
    var idleResult = await idleActivator.EnsureOwnerAsync(idleThreadId);
    Assert(
        idleResult.Status == DesktopThreadOwnerActivationStatus.Activated &&
        idlePlatform.OpenThreadCount == 1 &&
        idlePlatform.HasOpened(idleThreadId),
        "an idle Windows session opens the target deep link once and confirms its Desktop owner");

    var incompatiblePlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromMinutes(1));
    var incompatible = new DesktopThreadOwnerActivator(
        new FakeDesktopThreadOwnerProbe(_ => OwnerProbe(DesktopThreadOwnerProbeStatus.Incompatible)),
        ownerLog,
        incompatiblePlatform,
        TimeSpan.Zero,
        TimeSpan.FromMilliseconds(20),
        TimeSpan.Zero);
    var incompatibleResult = await incompatible.EnsureOwnerAsync(Guid.NewGuid().ToString("D"));
    Assert(
        incompatibleResult.Status == DesktopThreadOwnerActivationStatus.Incompatible &&
        incompatiblePlatform.OpenThreadCount == 0,
        "an incompatible Desktop contract fails closed without task navigation");

    var transientProbeCount = 0;
    var transientPlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromMinutes(1));
    var transientActivator = new DesktopThreadOwnerActivator(
        new FakeDesktopThreadOwnerProbe(_ => OwnerProbe(
            Interlocked.Increment(ref transientProbeCount) == 1
                ? DesktopThreadOwnerProbeStatus.TransientFailure
                : DesktopThreadOwnerProbeStatus.Unavailable)),
        ownerLog,
        transientPlatform,
        TimeSpan.Zero,
        TimeSpan.FromMilliseconds(20),
        TimeSpan.Zero);
    var transientResult = await transientActivator.EnsureOwnerAsync(Guid.NewGuid().ToString("D"));
    Assert(
        transientResult.Status == DesktopThreadOwnerActivationStatus.TimedOut &&
        transientPlatform.OpenThreadCount == 0,
        "a transient owner probe never triggers task navigation even while Windows is idle");

    var timeoutPlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromMinutes(1));
    var timeoutActivator = new DesktopThreadOwnerActivator(
        new FakeDesktopThreadOwnerProbe(_ => OwnerProbe(DesktopThreadOwnerProbeStatus.Unavailable)),
        ownerLog,
        timeoutPlatform,
        TimeSpan.Zero,
        TimeSpan.FromMilliseconds(5),
        TimeSpan.FromMilliseconds(1));
    var timeoutResult = await timeoutActivator.EnsureOwnerAsync(Guid.NewGuid().ToString("D"));
    Assert(
        timeoutResult.Status == DesktopThreadOwnerActivationStatus.TimedOut &&
        timeoutPlatform.OpenThreadCount == 1,
        "a bounded owner timeout never repeats the deep-link activation");

    var serializedPlatform = new FakeDesktopThreadOwnerActivationPlatform(TimeSpan.FromMinutes(1))
    {
        OpenDelay = TimeSpan.FromMilliseconds(75)
    };
    var serializedProbe = new FakeDesktopThreadOwnerProbe(threadId =>
        OwnerProbe(serializedPlatform.HasOpened(threadId)
            ? DesktopThreadOwnerProbeStatus.Available
            : DesktopThreadOwnerProbeStatus.Unavailable));
    var serializedActivator = new DesktopThreadOwnerActivator(
        serializedProbe,
        ownerLog,
        serializedPlatform,
        TimeSpan.Zero,
        TimeSpan.FromSeconds(1),
        TimeSpan.Zero);
    var firstActivation = Task.Run(() => serializedActivator.EnsureOwnerAsync(Guid.NewGuid().ToString("D")));
    var secondActivation = Task.Run(() => serializedActivator.EnsureOwnerAsync(Guid.NewGuid().ToString("D")));
    var serializedResults = await Task.WhenAll(firstActivation, secondActivation);
    Assert(
        serializedResults.All(result => result.Status == DesktopThreadOwnerActivationStatus.Activated) &&
        serializedPlatform.OpenThreadCount == 2 &&
        serializedPlatform.MaximumConcurrentOpenCount == 1,
        "owner activation serializes deep links across tasks instead of racing the Codex window");
});
var idleThread = new ThreadSummary(
    "thread-cache",
    "cache test",
    "cache test",
    "C:\\Temp",
    "appServer",
    100,
    200,
    false,
    false,
    "idle");
Assert(
    AppServerClient.ReadThreadRuntimeStatus(activeThreadJson.RootElement) == "active" &&
    GuardianEngine.IsProtocolThreadActive(idleThread with { RuntimeStatus = "active" }),
    "thread/list protocol status identifies active tasks without UI Automation");
Assert(
    AppServerClient.LatestTurnPageSize == 1 &&
    AppServerClient.SummaryItemsView == "summary" &&
    AppServerClient.FullItemsView == "full",
    "Guardian keeps latest monitoring reads summary-only and exposes a separate bounded full-item recovery read");
var sparseFailedTurn = new TurnSnapshot(
    Guid.NewGuid().ToString("D"),
    "failed",
    "temporary failure",
    "responseTooManyFailedAttempts",
    429,
    string.Empty,
    HasAttachments: false,
    HasAssistantOutput: false,
    HasWorkOutput: false,
    OutputFingerprint: "sparse",
    StartedAt: 1,
    CompletedAt: 2,
    HasConfirmedLocalTerminal: true,
    HasUserMessage: false,
    HasCompleteItemEvidence: false);
Assert(
    GuardianEngine.ShouldReadFullTurnEvidence(sparseFailedTurn) &&
    GuardianEngine.ShouldReadFullTurnEvidence(sparseFailedTurn with
    {
        Status = "interrupted",
        HasUserMessage = true
    }) &&
    !GuardianEngine.ShouldReadFullTurnEvidence(sparseFailedTurn with
    {
        Status = "completed"
    }) &&
    !GuardianEngine.ShouldReadFullTurnEvidence(sparseFailedTurn with
    {
        Status = "inProgress"
    }) &&
    !GuardianEngine.ShouldReadFullTurnEvidence(sparseFailedTurn with
    {
        HasUserMessage = true,
        HasCompleteItemEvidence = true
    }) &&
    !GuardianEngine.ShouldReadFullTurnEvidence(sparseFailedTurn with
    {
        HasConfirmedLocalTerminal = false
    }),
    "bounded full-item reads occur only for an exact confirmed abnormal turn with missing summary evidence");
var subAgentSessionMeta = JsonSerializer.Serialize(new
{
    type = "session_meta",
    payload = new { thread_source = "subagent" }
});
var rootSessionMeta = JsonSerializer.Serialize(new
{
    type = "session_meta",
    payload = new { thread_source = "user" }
});
Assert(
    LocalConversationEventWatcher.TryParseSubAgentSource(subAgentSessionMeta, out var parsedSubAgent) &&
    parsedSubAgent &&
    LocalConversationEventWatcher.TryParseSubAgentSource(rootSessionMeta, out var parsedRoot) &&
    !parsedRoot,
    "new rollout metadata identifies subagents without rereading historical files");
Assert(
    !GuardianEngine.ShouldScheduleLocalTerminal(false, eventIsSubAgent: true, isKnownInteractiveThread: false) &&
    GuardianEngine.ShouldScheduleLocalTerminal(false, eventIsSubAgent: false, isKnownInteractiveThread: false) &&
    GuardianEngine.ShouldScheduleLocalTerminal(false, eventIsSubAgent: null, isKnownInteractiveThread: true) &&
    !GuardianEngine.ShouldScheduleLocalTerminal(false, eventIsSubAgent: null, isKnownInteractiveThread: false) &&
    GuardianEngine.ShouldScheduleLocalTerminal(true, eventIsSubAgent: true, isKnownInteractiveThread: false),
    "filtered subagent terminals do not wake global state sync while root and explicitly included events do");
var appServerSourcePath = FindWorkspaceSource("CodexGuardian", "Services", "AppServerClient.cs");
var recoverySourcePath = FindWorkspaceSource("CodexGuardian", "Services", "RecoveryService.cs");
var guardianEngineSourcePath = FindWorkspaceSource("CodexGuardian", "Services", "GuardianEngine.cs");
var mainViewModelSourcePath = FindWorkspaceSource("CodexGuardian", "ViewModels", "MainViewModel.cs");
var desktopIpcSourcePath = FindWorkspaceSource("CodexGuardian", "Services", "DesktopIpcClient.cs");
var desktopOwnerActivatorSourcePath = FindWorkspaceSource(
    "CodexGuardian",
    "Services",
    "DesktopThreadOwnerActivator.cs");
var localHistorySourcePath = FindWorkspaceSource("CodexGuardian", "Services", "LocalConversationHistoryReader.cs");
var localHistoryModelsSourcePath = FindWorkspaceSource("CodexGuardian", "Models", "LocalConversationHistoryModels.cs");
var localWatcherSourcePath = FindWorkspaceSource("CodexGuardian", "Services", "LocalConversationEventWatcher.cs");
var guardianLogSourcePath = FindWorkspaceSource("CodexGuardian", "Services", "GuardianLog.cs");
var followUpDispatchSourcePath = FindWorkspaceSource(
    "CodexGuardian",
    "Services",
    "FollowUpDispatchService.cs");
var interactionHookSourcePath = FindWorkspaceSource("CodexGuardian", "Services", "WindowsCodexInteractionHook.cs");
var deepObservationSourcePath = FindWorkspaceSource(
    "CodexGuardian",
    "Services",
    "CodexDeepObservationService.cs");
var legacyDeepObservationPayloadNames = new[]
{
    "build-deep-observation-modification-msix.ps1",
    "build-deep-observation-msix.ps1",
    "codex-guardian-preload-hook.js",
    "deep-observation-profile.json",
    "install-deep-observation-modification-msix.ps1",
    "install-deep-observation-msix.ps1",
    "patch-preload.cjs",
    "run-deep-observation-modification-action.ps1"
};
var existingLegacyDeepObservationPayloads = legacyDeepObservationPayloadNames
    .Select(name => FindWorkspaceSource("CodexGuardian", "HookPayload", name))
    .Where(static path => path is not null && File.Exists(path))
    .Select(static path => path!)
    .ToArray();
var cdpHookPath = FindWorkspaceSource(
    "CodexGuardian",
    "HookPayload",
    "codex-guardian-cdp-hook.js");
var cdpObserverPath = FindWorkspaceSource(
    "CodexGuardian",
    "HookPayload",
    "codex-guardian-cdp-observer-poc.mjs");
var cdpRunnerPath = FindWorkspaceSource(
    "CodexGuardian",
    "HookPayload",
    "run-cdp-observation-poc.ps1");
var cdpProfilePath = FindWorkspaceSource(
    "CodexGuardian",
    "HookPayload",
    "cdp-observation-profile.json");
var cdpRuntimeHookPath = FindWorkspaceSource(
    "CodexGuardian",
    "HookPayload",
    "codex-guardian-cdp-runtime-hook.js");
var cdpRuntimeProfilePath = FindWorkspaceSource(
    "CodexGuardian",
    "HookPayload",
    "cdp-runtime-profile.json");
var cdpRuntimeSessionPath = FindWorkspaceSource(
    "CodexGuardian",
    "Services",
    "CodexCdpObservationSession.cs");
var cdpRuntimeProtocolPath = FindWorkspaceSource(
    "CodexGuardian.Control",
    "CodexCdpObservationProtocol.cs");
var cdpPipeLauncherPath = FindWorkspaceSource(
    "CodexGuardian.Control",
    "WindowsCrtPipeProcess.cs");
var appCompositionPath = FindWorkspaceSource("CodexGuardian", "App.xaml.cs");
var guardianProjectPath = FindWorkspaceSource("CodexGuardian", "CodexGuardian.csproj");
var controlProjectPath = FindWorkspaceSource("CodexGuardian.Control", "CodexGuardian.Control.csproj");
var trustProjectPath = FindWorkspaceSource("CodexGuardian.Trust", "CodexGuardian.Trust.csproj");
var brokerProjectPath = FindWorkspaceSource("CodexGuardian.Broker", "CodexGuardian.Broker.csproj");
var testsProjectPath = FindWorkspaceSource("CodexGuardian.Tests", "CodexGuardian.Tests.csproj");
var controlLockFilePath = FindWorkspaceSource("CodexGuardian.Control", "packages.lock.json");
var nuGetConfigPath = FindWorkspaceSource("NuGet.config");
var controlProtocolPath = FindWorkspaceSource("CodexGuardian.Control", "CodexCdpBrokerProtocol.cs");
var controlStateMachinePath = FindWorkspaceSource(
    "CodexGuardian.Control",
    "CodexCdpBrokerStateMachine.cs");
var controlRuntimeOwnershipPath = FindWorkspaceSource(
    "CodexGuardian.Control",
    "CodexCdpRuntimeOwnership.cs");
var brokerRuntimeHostPath = FindWorkspaceSource(
    "CodexGuardian.Broker",
    "WindowsCodexCdpRuntimeControlHost.cs");
var authenticatedPipeConnectionPath = FindWorkspaceSource(
    "CodexGuardian.Trust",
    "AuthenticatedPipePeerConnection.cs");
var nativePeerProbeSourcePath = FindWorkspaceSource(
    "CodexGuardian.Tests",
    "WindowsNamedPipePeerTrustNativeProbeTests.cs");
var connectedClientNativeProbeSourcePath = FindWorkspaceSource(
    "CodexGuardian.Tests",
    "WindowsConnectedClientPeerTrustNativeTests.cs");
var connectedClientPlatformSourcePath = FindWorkspaceSource(
    "CodexGuardian.Trust",
    "Windows",
    "WindowsConnectedClientPeerTrustPlatform.cs");
var namedPipePeerPlatformSourcePath = FindWorkspaceSource(
    "CodexGuardian.Trust",
    "Windows",
    "WindowsNamedPipePeerTrustPlatform.cs");
var sameLogonNamedPipeSourcePath = FindWorkspaceSource(
    "CodexGuardian.Trust",
    "Windows",
    "WindowsSameLogonNamedPipe.cs");
var packageReleaseSourcePath = FindWorkspaceSource("package-release.ps1");
var appServerSource = appServerSourcePath is not null && File.Exists(appServerSourcePath)
    ? File.ReadAllText(appServerSourcePath)
    : string.Empty;
var recoverySource = recoverySourcePath is not null && File.Exists(recoverySourcePath)
    ? File.ReadAllText(recoverySourcePath)
    : string.Empty;
var localWatcherSource = localWatcherSourcePath is not null && File.Exists(localWatcherSourcePath)
    ? File.ReadAllText(localWatcherSourcePath)
    : string.Empty;
var guardianLogSource = guardianLogSourcePath is not null && File.Exists(guardianLogSourcePath)
    ? File.ReadAllText(guardianLogSourcePath)
    : string.Empty;
var followUpDispatchSource = followUpDispatchSourcePath is not null && File.Exists(followUpDispatchSourcePath)
    ? File.ReadAllText(followUpDispatchSourcePath)
    : string.Empty;
var interactionHookSource = interactionHookSourcePath is not null && File.Exists(interactionHookSourcePath)
    ? File.ReadAllText(interactionHookSourcePath)
    : string.Empty;
var deepObservationSource = deepObservationSourcePath is not null && File.Exists(deepObservationSourcePath)
    ? File.ReadAllText(deepObservationSourcePath)
    : string.Empty;
var cdpHookSource = cdpHookPath is not null && File.Exists(cdpHookPath)
    ? File.ReadAllText(cdpHookPath)
    : string.Empty;
var cdpObserverSource = cdpObserverPath is not null && File.Exists(cdpObserverPath)
    ? File.ReadAllText(cdpObserverPath)
    : string.Empty;
var cdpRunnerSource = cdpRunnerPath is not null && File.Exists(cdpRunnerPath)
    ? File.ReadAllText(cdpRunnerPath)
    : string.Empty;
var cdpProfileSource = cdpProfilePath is not null && File.Exists(cdpProfilePath)
    ? File.ReadAllText(cdpProfilePath)
    : string.Empty;
var cdpProfile = string.IsNullOrWhiteSpace(cdpProfileSource)
    ? null
    : JsonNode.Parse(cdpProfileSource);
var cdpRuntimeHookSource = cdpRuntimeHookPath is not null && File.Exists(cdpRuntimeHookPath)
    ? File.ReadAllText(cdpRuntimeHookPath)
    : string.Empty;
var cdpRuntimeProfileSource = cdpRuntimeProfilePath is not null && File.Exists(cdpRuntimeProfilePath)
    ? File.ReadAllText(cdpRuntimeProfilePath)
    : string.Empty;
var cdpRuntimeProfile = string.IsNullOrWhiteSpace(cdpRuntimeProfileSource)
    ? null
    : JsonNode.Parse(cdpRuntimeProfileSource);
var cdpRuntimeSessionSource = cdpRuntimeSessionPath is not null && File.Exists(cdpRuntimeSessionPath)
    ? File.ReadAllText(cdpRuntimeSessionPath)
    : string.Empty;
var cdpRuntimeProtocolSource = cdpRuntimeProtocolPath is not null && File.Exists(cdpRuntimeProtocolPath)
    ? File.ReadAllText(cdpRuntimeProtocolPath)
    : string.Empty;
var cdpPipeLauncherSource = cdpPipeLauncherPath is not null && File.Exists(cdpPipeLauncherPath)
    ? File.ReadAllText(cdpPipeLauncherPath)
    : string.Empty;
var appCompositionSource = appCompositionPath is not null && File.Exists(appCompositionPath)
    ? File.ReadAllText(appCompositionPath)
    : string.Empty;
var normalizedAppComposition = NormalizeLineEndings(appCompositionSource);
var appStartupStart = normalizedAppComposition.IndexOf(
    "private async Task<StartupOutcome> StartupCoreAsync(",
    StringComparison.Ordinal);
var appStartupEnd = appStartupStart < 0
    ? -1
    : normalizedAppComposition.IndexOf(
        "private void ShowStartupNoticeIfAllowed(",
        appStartupStart,
        StringComparison.Ordinal);
var appFinishExitStart = normalizedAppComposition.IndexOf(
    "private async Task FinishExitCoreAsync(TaskCompletionSource exitOwner)",
    StringComparison.Ordinal);
var appFinishExitEnd = appFinishExitStart < 0
    ? -1
    : normalizedAppComposition.IndexOf(
        "protected override void OnExit(ExitEventArgs eventArgs)",
        appFinishExitStart,
        StringComparison.Ordinal);
var appExitStart = normalizedAppComposition.IndexOf(
    "protected override void OnExit(ExitEventArgs eventArgs)",
    StringComparison.Ordinal);
var appExitEnd = appExitStart < 0
    ? -1
    : normalizedAppComposition.IndexOf(
        "private void DisposeOnExitNoThrow(IAsyncDisposable value, string label)",
        appExitStart,
        StringComparison.Ordinal);
var appStartupSource = appStartupStart >= 0 && appStartupEnd > appStartupStart
    ? normalizedAppComposition[appStartupStart..appStartupEnd]
    : string.Empty;
var appFinishExitSource =
    appFinishExitStart >= 0 && appFinishExitEnd > appFinishExitStart
        ? normalizedAppComposition[appFinishExitStart..appFinishExitEnd]
        : string.Empty;
var appExitSource = appExitStart >= 0 && appExitEnd > appExitStart
    ? normalizedAppComposition[appExitStart..appExitEnd]
    : string.Empty;
var appLaunchOptionsParse = appStartupSource.IndexOf(
    "var launchOptions = GuardianLaunchOptions.Parse(eventArgs.Args);",
    StringComparison.Ordinal);
var appSingleInstanceAcquire = appStartupSource.IndexOf(
    "_singleInstance = new Mutex(",
    StringComparison.Ordinal);
var appSingleInstanceMutexResolve = appSingleInstanceAcquire < 0
    ? -1
    : appStartupSource.IndexOf(
        "launchOptions.ResolveStartupMutexName(SingleInstanceMutexName)",
        appSingleInstanceAcquire,
        StringComparison.Ordinal);
var appSingleInstanceReject = appStartupSource.IndexOf(
    "if (!_ownsSingleInstance)",
    StringComparison.Ordinal);
var appReleaseMutexCreate = appStartupSource.IndexOf(
    "_releaseExchange = new Mutex(",
    StringComparison.Ordinal);
var appReleaseMutexResolve = appReleaseMutexCreate < 0
    ? -1
    : appStartupSource.IndexOf(
        "launchOptions.ResolveStartupMutexName(ReleaseExchangeMutexName)",
        appReleaseMutexCreate,
        StringComparison.Ordinal);
var appReleaseMutexWait = appStartupSource.IndexOf(
    "_ownsReleaseExchange = _releaseExchange.WaitOne(0);",
    StringComparison.Ordinal);
var appReleaseMutexAbandoned = appStartupSource.IndexOf(
    "catch (AbandonedMutexException)",
    StringComparison.Ordinal);
var appReleaseMutexAbandonedOwnership = appReleaseMutexAbandoned < 0
    ? -1
    : appStartupSource.IndexOf(
        "_ownsReleaseExchange = true;",
        appReleaseMutexAbandoned,
        StringComparison.Ordinal);
var appReleaseMutexReject = appStartupSource.IndexOf(
    "if (!_ownsReleaseExchange)",
    StringComparison.Ordinal);
var appReleaseMutexRejectEnd = appReleaseMutexReject < 0
    ? -1
    : appStartupSource.IndexOf(
        "startup.Gate();\n        var settingsService = new SettingsService(",
        appReleaseMutexReject,
        StringComparison.Ordinal);
var appReleaseMutexRejectSource =
    appReleaseMutexReject >= 0 && appReleaseMutexRejectEnd > appReleaseMutexReject
        ? appStartupSource[appReleaseMutexReject..appReleaseMutexRejectEnd]
        : string.Empty;
var appSettingsInitialization = appStartupSource.IndexOf(
    "var settingsService = new SettingsService(",
    StringComparison.Ordinal);
var appLogInitialization = appStartupSource.IndexOf(
    "startup.RunTrackedPublication(() =>\n            _log = new GuardianLog(settingsService.DataDirectory));",
    StringComparison.Ordinal);
var appLiveIntegrationGate = appStartupSource.IndexOf(
    "if (launchOptions.AllowsLiveIntegration)",
    StringComparison.Ordinal);
var appRecoveryJournalRead = appStartupSource.IndexOf(
    "recoveryJournal.ReadAsync(startup.CancellationToken)",
    StringComparison.Ordinal);
var appFollowUpJournalRead = appStartupSource.IndexOf(
    "followUpJournal.ReadAsync(\n                startup.CancellationToken)",
    StringComparison.Ordinal);
var appObservationStart = appStartupSource.IndexOf(
    "startup.RunTrackedPublication(() => _deepObservation!.Start());",
    StringComparison.Ordinal);
var appHookStart = appStartupSource.IndexOf(
    "startup.RunTrackedPublication(() => _interactionHook!.Start());",
    StringComparison.Ordinal);
var appWindowCreate = appStartupSource.IndexOf(
    "var window = new MainWindow(\n" +
    "            viewModel,\n" +
    "            enableTray: !launchOptions.SafePreview,\n" +
    "            attachmentRuntime,\n" +
    "            launchOptions.SafePreview,\n" +
    "            log);",
    StringComparison.Ordinal);
var appPreviewFixtureLoad = appStartupSource.IndexOf(
    "viewModel.LoadFollowUpPreviewFixture(previewFixture);",
    StringComparison.Ordinal);
var appInitialize = appStartupSource.IndexOf(
    "await viewModel.InitializeForApplicationStartupAsync(",
    StringComparison.Ordinal);
var appMainWindowPublication = appWindowCreate < 0
    ? -1
    : appStartupSource.IndexOf(
        "MainWindow = window;",
        appWindowCreate,
        StringComparison.Ordinal);
var appWindowActivation = appMainWindowPublication < 0
    ? -1
    : appStartupSource.IndexOf(
        "window.ActivateForStartup(showWindow: !launchOptions.Background);",
        appMainWindowPublication,
        StringComparison.Ordinal);
var appStartupPublished = appWindowActivation < 0
    ? -1
    : appStartupSource.IndexOf(
        "startup.PublishAtomic(viewModel.MarkApplicationStartupPublished);",
        appWindowActivation,
        StringComparison.Ordinal);
var appGateAfterPublication = appStartupPublished < 0
    ? -2
    : appStartupSource.IndexOf(
        "startup.Gate();",
        appStartupPublished,
        StringComparison.Ordinal);
var appWindowCleanup = appExitSource.IndexOf(
    "window.DeactivateForExit();",
    StringComparison.Ordinal);
var appViewModelCleanup = appExitSource.IndexOf(
    "DisposeOnExitNoThrow(viewModel, \"view model\");",
    StringComparison.Ordinal);
var appInteractionHookCleanup = appExitSource.IndexOf(
    "DisposeOnExitNoThrow(interactionHook, \"interaction hook\");",
    StringComparison.Ordinal);
var appObservationCleanup = appExitSource.IndexOf(
    "DisposeOnExitNoThrow(deepObservation, \"deep observation\");",
    StringComparison.Ordinal);
var appBrokerCleanup = appExitSource.IndexOf(
    "brokerBootstrapLifetime.DisposeAsync().AsTask().GetAwaiter().GetResult();",
    StringComparison.Ordinal);
var appLogCleanup = appExitSource.IndexOf(
    "log.Dispose();",
    StringComparison.Ordinal);
var appReleaseOwnershipGuard = appExitSource.IndexOf(
    "if (_ownsReleaseExchange)",
    StringComparison.Ordinal);
var appReleaseMutexRelease = appExitSource.IndexOf(
    "_releaseExchange?.ReleaseMutex();",
    StringComparison.Ordinal);
var appReleaseMutexDispose = appExitSource.IndexOf(
    "_releaseExchange?.Dispose();",
    StringComparison.Ordinal);
var appSingleInstanceRelease = appExitSource.IndexOf(
    "_singleInstance?.ReleaseMutex();",
    StringComparison.Ordinal);
var compiledReleaseMutexName = typeof(global::CodexGuardian.App)
    .GetField(
        "ReleaseExchangeMutexName",
        BindingFlags.Static | BindingFlags.NonPublic)
    ?.GetRawConstantValue() as string;
var cdpHookSha256 = cdpHookPath is not null && File.Exists(cdpHookPath)
    ? ComputeSha256(cdpHookPath)
    : string.Empty;
var cdpRuntimeHookSha256 = cdpRuntimeHookPath is not null && File.Exists(cdpRuntimeHookPath)
    ? ComputeSha256(cdpRuntimeHookPath)
    : string.Empty;
var cdpObserverSha256 = cdpObserverPath is not null && File.Exists(cdpObserverPath)
    ? ComputeSha256(cdpObserverPath)
    : string.Empty;
var cdpProfileSha256 = cdpProfilePath is not null && File.Exists(cdpProfilePath)
    ? ComputeSha256(cdpProfilePath)
    : string.Empty;
var cdpSelfTest = cdpObserverPath is not null && File.Exists(cdpObserverPath)
    ? await RunExternalProcessAsync(
        cdpProfile?["nodePath"]?.GetValue<string>() ?? "node",
        cdpObserverPath,
        "--self-test")
    : (-1, string.Empty, "observer-source-missing");
var scopeRevalidationReferenceCount = recoverySource
    .Split("RevalidateThreadEligibilityAsync", StringSplitOptions.None)
    .Length - 1;
var targetScopeValidation = recoverySource.IndexOf(
    "eligibilityCheck = await RevalidateTargetThreadEligibilityAsync",
    StringComparison.Ordinal);
var targetPolicyValidation = targetScopeValidation < 0
    ? -1
    : recoverySource.IndexOf(
        "policyCheck = ValidateDispatchPolicy(isDispatchAllowed)",
        targetScopeValidation,
        StringComparison.Ordinal);
var targetDispatchTransition = targetPolicyValidation < 0
    ? -1
    : recoverySource.IndexOf(
        "RecoveryOperationState.Dispatching",
        targetPolicyValidation,
        StringComparison.Ordinal);
var ownerActivationStart = recoverySource.IndexOf(
    "var ownerActivation = await _ownerActivator.EnsureOwnerAsync",
    StringComparison.Ordinal);
var ownerStateGuardStart = ownerActivationStart < 0
    ? -1
    : recoverySource.IndexOf(
        "AcquireThreadOwnerStateGuardAsync",
        ownerActivationStart,
        StringComparison.Ordinal);
var finalLatestTurnValidation = ownerActivationStart < 0
    ? -1
    : recoverySource.IndexOf(
        "// Revalidate immediately before the Desktop owner enters the commit path.",
        ownerActivationStart,
        StringComparison.Ordinal);
var desktopStartTurn = targetDispatchTransition < 0
    ? -1
    : recoverySource.IndexOf(
        "var started = await _desktop.AppendRecoverySuccessorAsync",
        targetDispatchTransition,
        StringComparison.Ordinal);
var firstUserIdleCheck = recoverySource.IndexOf(
    "\"beforeDispatchIntent\"",
    StringComparison.Ordinal);
var secondUserIdleCheck = firstUserIdleCheck < 0
    ? -1
    : recoverySource.IndexOf(
        "\"beforeStartTurn\"",
        firstUserIdleCheck + 1,
        StringComparison.Ordinal);
var retryableAfterSecondIdleCheck = secondUserIdleCheck < 0
    ? -1
    : recoverySource.IndexOf(
        "RecoveryOperationState.Retryable",
        secondUserIdleCheck,
        StringComparison.Ordinal);
var dispatchToStartTurnSource = targetDispatchTransition >= 0 && desktopStartTurn > targetDispatchTransition
    ? recoverySource[targetDispatchTransition..desktopStartTurn]
    : string.Empty;
var ownerRejectedCatchStart = recoverySource.IndexOf(
    "exception.Code is \"no-client-found\" or \"guardian-owner-unavailable\"",
    StringComparison.Ordinal);
var ownerRejectedCatchEnd = ownerRejectedCatchStart < 0
    ? -1
    : recoverySource.IndexOf(
        "catch (DesktopIpcProtocolException exception) when (",
        ownerRejectedCatchStart + 1,
        StringComparison.Ordinal);
var ownerRejectedCatchSource = ownerRejectedCatchStart >= 0 && ownerRejectedCatchEnd > ownerRejectedCatchStart
    ? recoverySource[ownerRejectedCatchStart..ownerRejectedCatchEnd]
    : string.Empty;
var guardianEngineSource = guardianEngineSourcePath is not null && File.Exists(guardianEngineSourcePath)
    ? File.ReadAllText(guardianEngineSourcePath)
    : string.Empty;
var mainViewModelSource = mainViewModelSourcePath is not null && File.Exists(mainViewModelSourcePath)
    ? File.ReadAllText(mainViewModelSourcePath)
    : string.Empty;
var desktopIpcSource = desktopIpcSourcePath is not null && File.Exists(desktopIpcSourcePath)
    ? File.ReadAllText(desktopIpcSourcePath)
    : string.Empty;
var desktopOwnerActivatorSource = desktopOwnerActivatorSourcePath is not null &&
                                  File.Exists(desktopOwnerActivatorSourcePath)
    ? File.ReadAllText(desktopOwnerActivatorSourcePath)
    : string.Empty;
var localHistorySource = localHistorySourcePath is not null && File.Exists(localHistorySourcePath)
    ? File.ReadAllText(localHistorySourcePath)
    : string.Empty;
var localHistoryModelsSource = localHistoryModelsSourcePath is not null && File.Exists(localHistoryModelsSourcePath)
    ? File.ReadAllText(localHistoryModelsSourcePath)
    : string.Empty;
var guardianProjectSource = guardianProjectPath is not null && File.Exists(guardianProjectPath)
    ? File.ReadAllText(guardianProjectPath)
    : string.Empty;
var controlProjectSource = controlProjectPath is not null && File.Exists(controlProjectPath)
    ? File.ReadAllText(controlProjectPath)
    : string.Empty;
var trustProjectSource = trustProjectPath is not null && File.Exists(trustProjectPath)
    ? File.ReadAllText(trustProjectPath)
    : string.Empty;
var brokerProjectSource = brokerProjectPath is not null && File.Exists(brokerProjectPath)
    ? File.ReadAllText(brokerProjectPath)
    : string.Empty;
var testsProjectSource = testsProjectPath is not null && File.Exists(testsProjectPath)
    ? File.ReadAllText(testsProjectPath)
    : string.Empty;
var controlLockFileSource = controlLockFilePath is not null && File.Exists(controlLockFilePath)
    ? File.ReadAllText(controlLockFilePath)
    : string.Empty;
var controlLockDocument = string.IsNullOrWhiteSpace(controlLockFileSource)
    ? null
    : JsonNode.Parse(controlLockFileSource);
var controlLockDependencies = controlLockDocument?["dependencies"] as JsonObject;
var controlLockFramework = controlLockDependencies?["net8.0-windows7.0"] as JsonObject;
var controlLockRuntimeFramework =
    controlLockDependencies?["net8.0-windows7.0/win-x64"] as JsonObject;
var controlLockPkcs = controlLockFramework?["System.Security.Cryptography.Pkcs"] as JsonObject;
var controlLockRuntimePkcs =
    controlLockRuntimeFramework?["System.Security.Cryptography.Pkcs"] as JsonObject;
var nuGetConfigSource = nuGetConfigPath is not null && File.Exists(nuGetConfigPath)
    ? File.ReadAllText(nuGetConfigPath)
    : string.Empty;
var expectedNuGetConfigSource = string.Join(
    "\n",
    new[]
    {
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<configuration>",
        "  <packageSources>",
        "    <clear />",
        "    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" protocolVersion=\"3\" />",
        "  </packageSources>",
        "  <packageSourceMapping>",
        "    <clear />",
        "    <packageSource key=\"nuget.org\">",
        "      <package pattern=\"System.Security.Cryptography.Pkcs\" />",
        "      <package pattern=\"System.Formats.Asn1\" />",
        "      <package pattern=\"System.Buffers\" />",
        "      <package pattern=\"System.Memory\" />",
        "      <package pattern=\"System.Security.Cryptography.Cng\" />",
        "      <package pattern=\"System.Runtime.CompilerServices.Unsafe\" />",
        "      <package pattern=\"Microsoft.NETCore.App.Runtime.win-x64\" />",
        "      <package pattern=\"Microsoft.WindowsDesktop.App.Runtime.win-x64\" />",
        "      <package pattern=\"Microsoft.AspNetCore.App.Runtime.win-x64\" />",
        "    </packageSource>",
        "  </packageSourceMapping>",
        "</configuration>",
        string.Empty
    });
var controlProtocolSource = controlProtocolPath is not null && File.Exists(controlProtocolPath)
    ? File.ReadAllText(controlProtocolPath)
    : string.Empty;
var controlStateMachineSource = controlStateMachinePath is not null && File.Exists(controlStateMachinePath)
    ? File.ReadAllText(controlStateMachinePath)
    : string.Empty;
var controlRuntimeOwnershipSource = controlRuntimeOwnershipPath is not null &&
                                    File.Exists(controlRuntimeOwnershipPath)
    ? File.ReadAllText(controlRuntimeOwnershipPath)
    : string.Empty;
var brokerRuntimeHostSource = brokerRuntimeHostPath is not null &&
                              File.Exists(brokerRuntimeHostPath)
    ? File.ReadAllText(brokerRuntimeHostPath)
    : string.Empty;
var authenticatedPipeConnectionSource = authenticatedPipeConnectionPath is not null &&
                                        File.Exists(authenticatedPipeConnectionPath)
    ? File.ReadAllText(authenticatedPipeConnectionPath)
    : string.Empty;
var packageReleaseSource = packageReleaseSourcePath is not null && File.Exists(packageReleaseSourcePath)
    ? File.ReadAllText(packageReleaseSourcePath)
    : string.Empty;
var normalizedPackageReleaseSource = NormalizeLineEndings(packageReleaseSource);
var packagePowerShellSyntax = packageReleaseSourcePath is not null && File.Exists(packageReleaseSourcePath)
    ? await ValidatePowerShellSyntaxAsync(packageReleaseSourcePath)
    : (Success: false, Detail: "package-release-source-missing");
var nativePeerProbeSource = nativePeerProbeSourcePath is not null && File.Exists(nativePeerProbeSourcePath)
    ? File.ReadAllText(nativePeerProbeSourcePath)
    : string.Empty;
var connectedClientNativeProbeSource = connectedClientNativeProbeSourcePath is not null &&
                                       File.Exists(connectedClientNativeProbeSourcePath)
    ? File.ReadAllText(connectedClientNativeProbeSourcePath)
    : string.Empty;
var connectedClientPlatformSource = connectedClientPlatformSourcePath is not null &&
                                   File.Exists(connectedClientPlatformSourcePath)
    ? File.ReadAllText(connectedClientPlatformSourcePath)
    : string.Empty;
var namedPipePeerPlatformSource = namedPipePeerPlatformSourcePath is not null &&
                                  File.Exists(namedPipePeerPlatformSourcePath)
    ? File.ReadAllText(namedPipePeerPlatformSourcePath)
    : string.Empty;
var sameLogonNamedPipeSource = sameLogonNamedPipeSourcePath is not null &&
                               File.Exists(sameLogonNamedPipeSourcePath)
    ? File.ReadAllText(sameLogonNamedPipeSourcePath)
    : string.Empty;
var packageMain = SlicePackageMain(packageReleaseSource);
var normalizedPackageMain = NormalizeLineEndings(packageMain);
var packageMainMarkerIndex = normalizedPackageReleaseSource.IndexOf(
    "Assert-GuardianStopped\nAssert-NoSourceBuildResidue\nAssert-DDriveCapacity\n",
    StringComparison.Ordinal);
var packageCurrentHostGateIndex = normalizedPackageReleaseSource.IndexOf(
    "$currentHostInjectionVariables = @(",
    StringComparison.Ordinal);
var packageCurrentHostFailureIndex = normalizedPackageReleaseSource.IndexOf(
    "The current PowerShell host environment contains forbidden CLR injection variables:",
    StringComparison.Ordinal);
var packageFirstEnvironmentMutationIndex = normalizedPackageReleaseSource.IndexOf(
    "$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'",
    StringComparison.Ordinal);
var packageInternalHarnessDispatch = FindSinglePowerShellScopedBlock(
    packageReleaseSource,
    "if (![string]::IsNullOrWhiteSpace($InternalReleaseTransactionRequestPath)) {");
var packageInternalHarnessDispatchText =
    packageInternalHarnessDispatch?.Text ?? string.Empty;
var packageBootstrapUnavailableIndex = normalizedPackageReleaseSource.IndexOf(
    "broker-production-bootstrap-unavailable:",
    StringComparison.Ordinal);
var packageFirstWorkspaceWriteIndex = normalizedPackageReleaseSource.IndexOf(
    "Initialize-ScratchWorkspace\n",
    StringComparison.Ordinal);
var durableReleaseExchangeFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Invoke-DurableReleaseExchangeTransaction");
var packageHasHereString = packageMain.Contains("@'", StringComparison.Ordinal) ||
                           packageMain.Contains("@\"", StringComparison.Ordinal) ||
                           packageMain.Contains("'@", StringComparison.Ordinal) ||
                           packageMain.Contains("\"@", StringComparison.Ordinal);
var packageMainProcessEscapeCount = Regex.Matches(
    packageMain,
    @"(?im)^[ \t]*(?:&[ \t]+\$DotnetExecutable|dotnet(?:\.exe)?\b|Start-Process\b|Invoke-Expression\b|iex\b|cmd(?:\.exe)?\b|powershell(?:\.exe)?\b|pwsh(?:\.exe)?\b|Start-Job\b)").Count;
var packageStopChecks = ReadPowerShellCommandBlocks(packageMain, "Assert-GuardianStopped");
var durableExchangeStopChecks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "Assert-GuardianStopped");
var packageInitialStopCheck = packageStopChecks.Count == 2 ? packageStopChecks[0].Index : -1;
var packagePreOutputStopCheck = packageStopChecks.Count == 2 ? packageStopChecks[1].Index : -1;
var packagePreJournalStopCheck = durableExchangeStopChecks.Count == 2
    ? durableExchangeStopChecks[0].Index
    : -1;
var packagePromotionStopCheck = durableExchangeStopChecks.Count == 2
    ? durableExchangeStopChecks[1].Index
    : -1;
var packageValidateOnlyBlock = FindSinglePowerShellScopedBlock(packageMain, "if ($ValidateOnly) {");
var packageInitialStopDepth = GetPowerShellBraceDepthAt(packageMain, packageInitialStopCheck);
var packagePreOutputStopDepth = GetPowerShellBraceDepthAt(packageMain, packagePreOutputStopCheck);
var packagePreJournalStopDepth = GetPowerShellBraceDepthAt(
    durableReleaseExchangeFunction,
    packagePreJournalStopCheck);
var packagePromotionStopDepth = GetPowerShellBraceDepthAt(
    durableReleaseExchangeFunction,
    packagePromotionStopCheck);
var packageStageDirectoryCreate = FindSinglePowerShellCommandIndex(
    packageMain,
    "-Path $RuntimeStage,$SourceStage,$ArtifactsRoot,$FormalArtifactsRoot,$TestDataRoot");
var packageScratchInitialize = FindSinglePowerShellCommandIndex(
    packageMain,
    "Initialize-ScratchWorkspace");
var packageTempInitialize = FindSinglePowerShellCommandIndex(
    packageMain,
    "Initialize-TempWorkspace");
var packageNuGetPackagesInitialize = FindSinglePowerShellCommandIndex(
    packageMain,
    "$null = Initialize-DDriveDirectory -Path $NugetPackages -Label 'The NuGet package root'");
var packageNuGetHttpCacheInitialize = FindSinglePowerShellCommandIndex(
    packageMain,
    "$null = Initialize-DDriveDirectory -Path $NugetHttpCache -Label 'The NuGet HTTP cache root'");
var packageNuGetPluginsCacheInitialize = FindSinglePowerShellCommandIndex(
    packageMain,
    "$null = Initialize-DDriveDirectory -Path $NugetPluginsCache -Label 'The NuGet plugin cache root'");
var packageBrokerConsentLedgerTestDataLengthGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "if ($BrokerConsentLedgerTestData.Length -gt 72) {");
var packageBrokerConsentLedgerTestDataPreexistingGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "if (Test-Path -LiteralPath $BrokerConsentLedgerTestData) {");
var packageBrokerConsentLedgerTestDataCreate = FindSinglePowerShellCommandIndex(
    packageMain,
    "New-Item -ItemType Directory -Path $BrokerConsentLedgerTestData -ErrorAction Stop | Out-Null");
var packageValidateOnlyReturn = FindSinglePowerShellCommandIndex(packageMain, "return");
var packageOutputRootTraversal = FindSinglePowerShellCommandIndex(
    packageMain,
    "$null = Assert-NoReparseTraversal $OutputsRoot");
var packageOutputRootTraversalDepth = GetPowerShellBraceDepthAt(
    packageMain,
    packageOutputRootTraversal);
var packageOutputsRootCreate = FindSinglePowerShellCommandIndex(
    packageMain,
    "New-Item -ItemType Directory -Path $OutputsRoot -Force | Out-Null");
var packageRuntimeZipAssignment = FindSinglePowerShellCommandIndex(
    packageMain,
    "$RuntimeZip = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-win-x64.zip')");
var packageResolveDotnet = FindSinglePowerShellCommandIndex(
    packageMain,
    "$DotnetExecutable = Resolve-PinnedDotnetExecutable");
var packageOpenDotnetAuthority = FindSinglePowerShellCommandIndex(
    packageMain,
    "$DotnetAuthority = Open-PinnedDotnetLeases");
var packageDotnetAuthorityAgreement = FindSinglePowerShellCommandIndex(
    packageMain,
    "throw 'The pinned .NET executable and authority disagree.'");
var packageAuthorityCloseBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Close-PinnedDotnetLeases -Authority $DotnetAuthority");
var packageAuthorityNullBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "$DotnetAuthority = $null");
var packageNormalAuthorityClose = packageAuthorityCloseBlocks.Count == 2
    ? packageAuthorityCloseBlocks[0].Index
    : -1;
var packageFinalAuthorityClose = packageAuthorityCloseBlocks.Count == 2
    ? packageAuthorityCloseBlocks[1].Index
    : -1;
var packageNormalAuthorityNull = packageAuthorityNullBlocks.Count == 2
    ? packageAuthorityNullBlocks[0].Index
    : -1;
var packageFinalAuthorityNull = packageAuthorityNullBlocks.Count == 2
    ? packageAuthorityNullBlocks[1].Index
    : -1;
var packageTopLevelFinallyMatches = Regex.Matches(
    normalizedPackageMain,
    @"(?m)^finally \{$");
var packageTopLevelFinally = packageTopLevelFinallyMatches.Count == 1
    ? packageTopLevelFinallyMatches[0].Index
    : -1;
var packageActiveSourceBefore = FindSinglePowerShellCommandIndex(
    packageMain,
    "$activeSourceBefore = @(Get-ReleaseSourceContentManifest");
var packageGuardianCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Invoke-Robocopy $ProjectRoot $StagedProjectRoot");
var packageTestsCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Invoke-Robocopy $TestsRoot $StagedTestsRoot");
var packageControlCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Invoke-Robocopy $ControlRoot $StagedControlRoot");
var packageTrustCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Invoke-Robocopy $TrustRoot $StagedTrustRoot");
var packageBrokerCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Invoke-Robocopy $BrokerProbeRoot $StagedBrokerRoot");
var packageScriptCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Copy-Item -LiteralPath $PSCommandPath -Destination $SourceStage -Force");
var packageGlobalJsonCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Copy-Item -LiteralPath $GlobalJsonPath -Destination $SourceStage -Force");
var packageNuGetConfigCopy = FindSinglePowerShellCommandIndex(
    packageMain,
    "Copy-Item -LiteralPath $NuGetConfigPath -Destination $SourceStage -Force");
var packageSourceStageManifest = FindSinglePowerShellCommandIndex(
    packageMain,
    "$SourceStageManifest = @(Get-TreeContentManifest");
var packageActiveSourceAfter = FindSinglePowerShellCommandIndex(
    packageMain,
    "$activeSourceAfter = @(Get-ReleaseSourceContentManifest");
var packageStagedGlobalJsonGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "Assert-PinnedGlobalJson -Path $StagedGlobalJsonPath");
var packageRestoreInputBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Assert-PinnedRestoreInputs");
var packageSourceRestoreInputsGate = FindSinglePowerShellBlockIndex(
    packageRestoreInputBlocks,
    "$NuGetConfigPath",
    "$ControlLockFilePath");
var packageStagedRestoreInputsGate = FindSinglePowerShellBlockIndex(
    packageRestoreInputBlocks,
    "$StagedNuGetConfigPath",
    "$StagedControlLockFilePath");
var packageImplicitInputsCall = FindSinglePowerShellCommandIndex(
    packageMain,
    "Assert-NoImplicitMsBuildInputs -SourceRoot $SourceStage -Projects $StagedProjects");
var packageClosureBlocks = ReadPowerShellCommandBlocks(packageMain, "Assert-StagedProjectReferenceClosure");
var packageClosureCall = packageClosureBlocks.Count == 1 ? packageClosureBlocks[0].Index : -1;
var packageClosureSource = packageClosureBlocks.Count == 1 ? packageClosureBlocks[0].Text : string.Empty;
var packageExpectedProjects = ParseLiteralPowerShellArray(packageClosureSource, "ExpectedProjects");
var packageExpectedEdges = ParseLiteralPowerShellArray(packageClosureSource, "ExpectedEdges");
var expectedPackageProjects = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "CodexGuardian.Tests\\CodexGuardian.Tests.csproj",
    "CodexGuardian\\CodexGuardian.csproj",
    "CodexGuardian.Control\\CodexGuardian.Control.csproj",
    "CodexGuardian.Trust\\CodexGuardian.Trust.csproj",
    "CodexGuardian.Broker\\CodexGuardian.Broker.csproj"
};
var expectedPackageEdges = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "CodexGuardian.Tests\\CodexGuardian.Tests.csproj->CodexGuardian.Broker\\CodexGuardian.Broker.csproj",
    "CodexGuardian.Tests\\CodexGuardian.Tests.csproj->CodexGuardian.Control\\CodexGuardian.Control.csproj",
    "CodexGuardian.Tests\\CodexGuardian.Tests.csproj->CodexGuardian\\CodexGuardian.csproj",
    "CodexGuardian.Tests\\CodexGuardian.Tests.csproj->CodexGuardian.Trust\\CodexGuardian.Trust.csproj",
    "CodexGuardian\\CodexGuardian.csproj->CodexGuardian.Control\\CodexGuardian.Control.csproj",
    "CodexGuardian\\CodexGuardian.csproj->CodexGuardian.Trust\\CodexGuardian.Trust.csproj",
    "CodexGuardian.Broker\\CodexGuardian.Broker.csproj->CodexGuardian.Control\\CodexGuardian.Control.csproj",
    "CodexGuardian.Broker\\CodexGuardian.Broker.csproj->CodexGuardian.Trust\\CodexGuardian.Trust.csproj"
};
var task15ReleaseClosurePaths = new[]
{
    "CodexGuardian.Control\\GuardianManagedEntryProof.cs",
    "CodexGuardian.Broker\\VerifiedGuardianManagedEntryConnection.cs",
    "CodexGuardian.Trust\\Windows\\WindowsVerifiedLocalReleaseManifestFactory.cs",
    "CodexGuardian.Broker\\BrokerSingleInstanceLease.cs",
    "CodexGuardian.Broker\\BrokerGuardianAcceptLoop.cs",
    "CodexGuardian.Broker\\BrokerProductionHost.cs",
    "CodexGuardian.Tests\\GuardianManagedEntryProofOfflineTests.cs",
    "CodexGuardian.Tests\\VerifiedLocalReleaseManifestOfflineTests.cs",
    "CodexGuardian.Tests\\BrokerProductionHostOfflineTests.cs"
};
var task16ReleaseClosurePaths = new[]
{
    "CodexGuardian.Control\\GuardianBrokerBootstrapProtocol.cs",
    "CodexGuardian.Broker\\WindowsGuardianCleanLauncher.cs",
    "CodexGuardian.Broker\\WindowsGuardianProcessSettlement.cs",
    "CodexGuardian.Tests\\GuardianBrokerBootstrapOfflineTests.cs",
    "CodexGuardian.Tests\\WindowsGuardianCleanLauncherOfflineTests.cs"
};
var task17ReleaseClosurePaths = new[]
{
    "CodexGuardian\\App.xaml",
    "CodexGuardian\\App.xaml.cs",
    "CodexGuardian\\MainWindow.xaml.cs",
    "CodexGuardian\\Program.cs",
    "CodexGuardian\\Services\\SettingsService.cs",
    "CodexGuardian\\Services\\DataDirectorySafety.cs",
    "CodexGuardian\\ViewModels\\MainViewModel.cs",
    "CodexGuardian\\GuardianBrokerManagedBootstrap.cs",
    "CodexGuardian\\GuardianBrokerBootstrapLifetime.cs",
    "CodexGuardian.Broker\\WindowsGuardianProductionAdmission.cs",
    "CodexGuardian.Broker\\BrokerProductionComposition.cs",
    "CodexGuardian.Broker\\Program.cs",
    "CodexGuardian.Control\\GuardianBrokerAdmissionProtocol.cs",
    "CodexGuardian.Tests\\Program.cs",
    "CodexGuardian.Tests\\GuardianBrokerAdmissionProtocolOfflineTests.cs",
    "CodexGuardian.Tests\\WindowsGuardianProductionAdmissionOfflineTests.cs",
    "CodexGuardian.Tests\\GuardianBrokerManagedBootstrapOfflineTests.cs",
    "CodexGuardian.Tests\\FollowUpOfflineTests.cs"
};
var packageFormalSourceClosureStart = packageMain.IndexOf(
    "$publishedExecutable = Join-Path $RuntimeStage 'CodexGuardian.exe'",
    StringComparison.Ordinal);
var packageFormalSourceClosureEnd = packageFormalSourceClosureStart < 0
    ? -1
    : packageMain.IndexOf(
        "$publishedVersionInfo = (Get-Item -LiteralPath $publishedExecutable).VersionInfo",
        packageFormalSourceClosureStart,
        StringComparison.Ordinal);
var packageFormalSourceClosure =
    packageFormalSourceClosureStart >= 0 &&
    packageFormalSourceClosureEnd > packageFormalSourceClosureStart
        ? packageMain.Substring(
            packageFormalSourceClosureStart,
            packageFormalSourceClosureEnd - packageFormalSourceClosureStart)
        : string.Empty;
var task15GuardianRuntimeRequiredFiles = new[]
{
    "CodexGuardian.exe",
    "CodexGuardian.dll",
    "CodexGuardian.Control.dll",
    "CodexGuardian.Trust.dll",
    "System.Security.Cryptography.Pkcs.dll",
    "CodexGuardian.deps.json",
    "CodexGuardian.runtimeconfig.json",
    "CodexGuardian.runtimeconfig.dev.json"
};
var task15BrokerRuntimeRequiredFiles = new[]
{
    "CodexGuardian.Broker.exe",
    "CodexGuardian.Broker.dll",
    "CodexGuardian.Control.dll",
    "CodexGuardian.Trust.dll",
    "System.Security.Cryptography.Pkcs.dll",
    "CodexGuardian.Broker.deps.json",
    "CodexGuardian.Broker.runtimeconfig.json",
    "CodexGuardian.Broker.runtimeconfig.dev.json"
};
var brokerPublishIndex = packageMain.IndexOf(
    "-Label 'Broker runtime publish'",
    StringComparison.Ordinal);
var guardianRuntimeConfigDevWriteIndex = packageMain.IndexOf(
    "(Join-Path $RuntimeStage 'CodexGuardian.runtimeconfig.dev.json')",
    StringComparison.Ordinal);
var brokerRuntimeConfigDevWriteIndex = packageMain.IndexOf(
    "(Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.runtimeconfig.dev.json')",
    StringComparison.Ordinal);
var publishedRuntimeClosureIndex = packageMain.IndexOf(
    "'--verify-published-runtime-closure'",
    StringComparison.Ordinal);
var packagePinnedDotnetCommands = ReadPowerShellCommandBlocks(packageMain, "Invoke-PinnedDotnetCommand");
var packageTestsRestore = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'restore',",
    "$StagedTestsProject",
    "'--configfile', $StagedNuGetConfigPath",
    "'--locked-mode'",
    "-WorkingDirectory $SourceStage");
var packageBuild = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'build',",
    "$StagedTestsProject",
    "-WorkingDirectory $SourceStage");
var packageGuardianAdmission = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--broker-guardian-admission-offline-only'",
    "-WorkingDirectory $SourceStage");
var packageSafeDrill = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--safe-drill-only'",
    "-WorkingDirectory $SourceStage");
var packageWatcher = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--watcher-only'",
    "-WorkingDirectory $SourceStage");
var packageBaseline = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--package-baseline-live-readonly'",
    "-WorkingDirectory $SourceStage");
var packageIdle = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--duration-seconds', '65'",
    "-WorkingDirectory $SourceStage");
var packageTargetedRefresh = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--targeted-refresh-probe'",
    "-WorkingDirectory $SourceStage");
var packagePublishRestore = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'restore',",
    "$StagedProjectFile",
    "'-p:SelfContained=true'",
    "'--locked-mode'",
    "-WorkingDirectory $SourceStage");
var packageBrokerPublishRestore = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'restore',",
    "$StagedBrokerProject",
    "'-p:SelfContained=true'",
    "'--locked-mode'",
    "-WorkingDirectory $SourceStage");
var packagePublish = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'publish',",
    "$StagedProjectFile",
    "-WorkingDirectory $SourceStage");
var packageBrokerPublish = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'publish',",
    "$StagedBrokerProject",
    "'-o', $BrokerRuntimeStage",
    "-WorkingDirectory $SourceStage");
var packagePublishedRuntimeClosure = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--verify-published-runtime-closure',",
    "'--published-runtime-root', $RuntimeStage",
    "'--published-runtime-nuget-packages-root', $NugetPackages",
    "'--published-runtime-root-assembly', 'CodexGuardian'",
    "-WorkingDirectory $SourceStage");
var packagePublishedBrokerRuntimeClosure = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--verify-published-runtime-closure',",
    "'--published-runtime-root', $BrokerRuntimeStage",
    "'--published-runtime-nuget-packages-root', $NugetPackages",
    "'--published-runtime-root-assembly', 'CodexGuardian.Broker'",
    "-WorkingDirectory $SourceStage");
var packagePublishedGuardianManagedEntryProof = FindSinglePowerShellBlockIndex(
    packagePinnedDotnetCommands,
    "'--guardian-managed-entry-apphost-probe',",
    "'--guardian-managed-entry-runtime-root', $RuntimeStage",
    "-WorkingDirectory $SourceStage");
var packageNativeGateBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Invoke-BoundedDotnetGate -Authority $DotnetAuthority -Assembly $TestsAssembly");
var packageNativeUserPresenceCapabilityGate = FindSinglePowerShellBlockIndex(
    packageNativeGateBlocks,
    "'--native-user-presence-capability-probe'",
    "'--native-user-presence-evidence-root', $NativeUserPresenceEvidenceRoot",
    "-WorkingDirectory $SourceStage");
var packageNativePeerGate = FindSinglePowerShellBlockIndex(
    packageNativeGateBlocks,
    "'--native-peer-child-probe'",
    "-WorkingDirectory $SourceStage");
var packageConnectedClientGate = FindSinglePowerShellBlockIndex(
    packageNativeGateBlocks,
    "'--native-connected-client-probe'",
    "-WorkingDirectory $SourceStage");
var packageNativeUserPresenceEvidenceRootAbsentGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "if (Test-Path -LiteralPath $NativeUserPresenceEvidenceRoot) {");
var packageNativeUserPresenceEvidenceRootCreate = FindSinglePowerShellCommandIndex(
    packageMain,
    "New-Item -ItemType Directory -Path $NativeUserPresenceEvidenceRoot -ErrorAction Stop | Out-Null");
var packageNativeUserPresenceEvidenceRootEmptyGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "if (@(Get-ChildItem -LiteralPath $NativeUserPresenceEvidenceRoot -Force -ErrorAction Stop).Count -ne 0) {");
var packageSourcePostBuildParity = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(packageMain, "Assert-TreeMatchesManifest"),
    "-Root $SourceStage",
    "-ExpectedManifest $SourceStageManifest",
    "Staged source after build test and publish");
var packageRuntimeStageManifest = FindSinglePowerShellCommandIndex(
    packageMain,
    "$RuntimeStageManifest = @(Get-TreeContentManifest");
var packageArchiveParityBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Assert-ArchiveMatchesManifest");
var packageTreeParityBlocks = ReadPowerShellCommandBlocks(packageMain, "Assert-TreeMatchesManifest");
var durableExchangeArchiveParityBlocks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "Assert-ArchiveMatchesManifest");
var durableExchangeTreeParityBlocks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "Assert-TreeMatchesManifest");
var packageCanonicalArchiveBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Compress-CanonicalArchive");
var packageValidationRuntimeProducer = FindSinglePowerShellBlockIndex(
    packageCanonicalArchiveBlocks,
    "-Source $RuntimeStage",
    "-Destination $validationRuntimeZip",
    "-ExpectedManifest $RuntimeStageManifest",
    "-DestinationScope scratch");
var packageValidationSourceProducer = FindSinglePowerShellBlockIndex(
    packageCanonicalArchiveBlocks,
    "-Source $SourceStage",
    "-Destination $validationSourceZip",
    "-ExpectedManifest $SourceStageManifest",
    "-DestinationScope scratch");
var packageValidationRuntimeBrokerGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "Assert-NoRuntimeTestArchiveEntries -Path $validationRuntimeZip -Label 'Validation runtime ZIP'");
var packageValidationRuntimeParity = FindSinglePowerShellBlockIndex(
    packageArchiveParityBlocks,
    "-Path $validationRuntimeZip",
    "-ExpectedManifest $RuntimeStageManifest");
var packageValidationSourceParity = FindSinglePowerShellBlockIndex(
    packageArchiveParityBlocks,
    "-Path $validationSourceZip",
    "-ExpectedManifest $SourceStageManifest");
var packageReleaseLock = FindSinglePowerShellCommandIndex(
    packageMain,
    "$releaseExchangeLock = Enter-ReleaseExchangeLock -Path $ReleaseLockPath");
var packageGuardianLeaseAcquire = FindSinglePowerShellCommandIndex(
    packageMain,
    "$guardianReleaseLease = Enter-GuardianReleaseLease");
var packageGuardianLeaseAcquireDepth = GetPowerShellBraceDepthAt(
    packageMain,
    packageGuardianLeaseAcquire);
var packageTransactionRecoveryBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Resolve-ReleaseExchangeTransaction");
var durableExchangeRecoveryBlocks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "Resolve-ReleaseExchangeTransaction");
var packageInitialTransactionRecovery = packageTransactionRecoveryBlocks.Count == 2
    ? packageTransactionRecoveryBlocks[0].Index
    : -1;
var packageCommittedTransactionRecovery = durableExchangeRecoveryBlocks.Count == 1
    ? durableExchangeRecoveryBlocks[0].Index
    : -1;
var packageCatchTransactionRecovery = packageTransactionRecoveryBlocks.Count == 2
    ? packageTransactionRecoveryBlocks[1].Index
    : -1;
var packageSettledBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Assert-ReleaseExchangeWorkspaceSettled");
var durableExchangeSettledBlocks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "Assert-ReleaseExchangeWorkspaceSettled");
var packageInitialSettledGate = packageSettledBlocks.Count == 1
    ? packageSettledBlocks[0].Index
    : -1;
var packageCommittedSettledGate = durableExchangeSettledBlocks.Count == 1
    ? durableExchangeSettledBlocks[0].Index
    : -1;
var packageReleaseBaseline = FindSinglePowerShellCommandIndex(
    packageMain,
    "$releaseBaseline = Get-CurrentReleaseBaseline");
var packageNextRuntimeDirectoryCreate = FindSinglePowerShellCommandIndex(
    packageMain,
    "New-ManagedOutputDirectory -Destination $RuntimeNext");
var packageNextSourceDirectoryCreate = FindSinglePowerShellCommandIndex(
    packageMain,
    "New-ManagedOutputDirectory -Destination $SourceNext");
var packageNextRuntimeCopy = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(packageMain, "Copy-ManagedOutputTree"),
    "-Source $RuntimeStage",
    "-Destination $RuntimeNext");
var packageNextSourceCopy = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(packageMain, "Copy-ManagedOutputTree"),
    "-Source $SourceStage",
    "-Destination $SourceNext");
var packageNextRuntimeBrokerGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "Assert-NoRuntimeTestPayload -Root $RuntimeNext -Label 'Next runtime package'");
var packageNextRuntimeDirectoryParity = FindSinglePowerShellBlockIndex(
    packageTreeParityBlocks,
    "-Root $RuntimeNext",
    "-ExpectedManifest $RuntimeStageManifest");
var packageNextSourceDirectoryParity = FindSinglePowerShellBlockIndex(
    packageTreeParityBlocks,
    "-Root $SourceNext",
    "-ExpectedManifest $SourceStageManifest");
var packageManagedArchiveBlocks = ReadPowerShellCommandBlocks(
    packageMain,
    "Compress-ManagedOutputArchive");
var packageNextRuntimeProducer = FindSinglePowerShellBlockIndex(
    packageManagedArchiveBlocks,
    "-Source $RuntimeNext",
    "-Destination $RuntimeZipNext",
    "-ExpectedManifest $RuntimeStageManifest",
    "-Label 'Next runtime ZIP'");
var packageNextSourceProducer = FindSinglePowerShellBlockIndex(
    packageManagedArchiveBlocks,
    "-Source $SourceNext",
    "-Destination $SourceZipNext",
    "-ExpectedManifest $SourceStageManifest",
    "-Label 'Next source ZIP'");
var packageNextRuntimeZipBrokerGate = FindSinglePowerShellCommandIndex(
    packageMain,
    "Assert-NoRuntimeTestArchiveEntries -Path $RuntimeZipNext -Label 'Next runtime ZIP'");
var packageNextRuntimeParity = FindSinglePowerShellBlockIndex(
    packageArchiveParityBlocks,
    "-Path $RuntimeZipNext",
    "-ExpectedManifest $RuntimeStageManifest");
var packageNextSourceParity = FindSinglePowerShellBlockIndex(
    packageArchiveParityBlocks,
    "-Path $SourceZipNext",
    "-ExpectedManifest $SourceStageManifest");
var packageNextChecksumRead = FindSinglePowerShellCommandIndex(
    packageMain,
    "$writtenChecksumLines = @(Get-Content -LiteralPath $ChecksumNext)");
var durableReleaseExchangeCalls = ReadPowerShellCommandBlocks(
    packageMain,
    "$releaseExchangeSucceeded = Invoke-DurableReleaseExchangeTransaction");
var durableReleaseExchangeCall = durableReleaseExchangeCalls.Count == 1
    ? durableReleaseExchangeCalls[0].Index
    : -1;
var durableReleaseExchangeCallSource = durableReleaseExchangeCalls.Count == 1
    ? durableReleaseExchangeCalls[0].Text
    : string.Empty;
var durableReleaseExchangeCallDepth = GetPowerShellBraceDepthAt(
    packageMain,
    durableReleaseExchangeCall);
var packageCandidateSyncBlocks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "Sync-ManagedArtifact");
var packageCandidateSync = packageCandidateSyncBlocks.Count == 1 &&
                           packageCandidateSyncBlocks[0].Text.Contains(
                               "-Path $artifact.Next",
                               StringComparison.Ordinal) &&
                           packageCandidateSyncBlocks[0].Text.Contains(
                               "-Kind $artifact.Kind",
                               StringComparison.Ordinal) &&
                           packageCandidateSyncBlocks[0].Text.Contains(
                               "-Label \"Sealed candidate $($artifact.Label)\"",
                               StringComparison.Ordinal)
    ? packageCandidateSyncBlocks[0].Index
    : -1;
var packageCandidateEntries = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "$candidateEntries = @(Get-ReleaseCandidateEntries -Artifacts $releaseArtifacts)");
var packageCommitPendingWriteBlocks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "$newCommitSha256 = Write-DurableManagedText");
var packageCommitPendingWrite = packageCommitPendingWriteBlocks.Count == 1 &&
                                packageCommitPendingWriteBlocks[0].Text.Contains(
                                    "-Destination $ReleaseCommitPendingPath",
                                    StringComparison.Ordinal) &&
                                packageCommitPendingWriteBlocks[0].Text.Contains(
                                    "-Text $commitText",
                                    StringComparison.Ordinal)
    ? packageCommitPendingWriteBlocks[0].Index
    : -1;
var packagePendingCommitRead = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(
        durableReleaseExchangeFunction,
        "$pendingCommit = Read-StrictReleaseCommit"),
    "-Path $ReleaseCommitPendingPath",
    "-Artifacts $releaseArtifacts");
var packagePendingCommitGateFailure = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "throw 'The durable pending release commit failed its identity gate.'");
var packageOldCommitBlock = FindSinglePowerShellScopedBlock(
    durableReleaseExchangeFunction,
    "if ([bool]$releaseBaseline.OldCommit.present) {");
var packageOldCommitRead = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(
        durableReleaseExchangeFunction,
        "$currentCommit = Read-StrictReleaseCommit"),
    "-Path $ReleaseCommitPath",
    "-Artifacts $releaseArtifacts");
var packageOldCommitChangedFailure = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "throw 'The old stable commit changed before the write-ahead journal.'");
var packageFirstReleaseCommitBlock = FindSinglePowerShellScopedBlock(
    durableReleaseExchangeFunction,
    "elseif (Test-Path -LiteralPath $ReleaseCommitPath) {");
var packageFirstReleaseCommitFailure = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "throw 'A stable commit appeared before the first-release journal.'");
var packageTransactionSnapshot = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(
        durableReleaseExchangeFunction,
        "Assert-ReleaseTransactionSnapshot"),
    "-Artifacts $releaseArtifacts",
    "-JournalArtifacts @($canonicalJournal.artifacts)");
var packageTransactionSnapshotDepth = GetPowerShellBraceDepthAt(
    durableReleaseExchangeFunction,
    packageTransactionSnapshot);
var packageJournalWriteBlocks = ReadPowerShellCommandBlocks(
    durableReleaseExchangeFunction,
    "$journalSha256 = Write-DurableManagedText");
var packageJournalWrite = packageJournalWriteBlocks.Count == 1 &&
                          packageJournalWriteBlocks[0].Text.Contains(
                              "-Destination $ReleaseJournalPath",
                              StringComparison.Ordinal) &&
                          packageJournalWriteBlocks[0].Text.Contains(
                              "-Text $journalText",
                              StringComparison.Ordinal)
    ? packageJournalWriteBlocks[0].Index
    : -1;
var packagePromotionLoop = packageJournalWrite < 0
    ? -1
    : durableReleaseExchangeFunction.IndexOf(
        "for ($index = 0; $index -lt $releaseArtifacts.Count; $index++) {",
        packageJournalWrite,
        StringComparison.Ordinal);
var packageCurrentBackup = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "Move-ManagedArtifact -Source $artifact.Current -Destination $artifact.Previous");
var packageCandidatePromotion = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "Move-ManagedArtifact -Source $artifact.Next -Destination $artifact.Current");
var packagePostExchangeRequiredFiles = packagePromotionLoop < 0
    ? -1
    : durableReleaseExchangeFunction.IndexOf(
        "foreach ($requiredFile in @(",
        packagePromotionLoop,
        StringComparison.Ordinal);
var packageExchangedRuntimeBrokerGate = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "Assert-NoRuntimeTestPayload -Root $RuntimeOutput -Label 'Exchanged runtime package'");
var packageExchangedRuntimeZipBrokerGate = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "Assert-NoRuntimeTestArchiveEntries -Path $RuntimeZip -Label 'Exchanged runtime ZIP'");
var packageExchangedRuntimeDirectoryParity = FindSinglePowerShellBlockIndex(
    durableExchangeTreeParityBlocks,
    "-Root $RuntimeOutput",
    "-ExpectedManifest $RuntimeStageManifest");
var packageExchangedSourceDirectoryParity = FindSinglePowerShellBlockIndex(
    durableExchangeTreeParityBlocks,
    "-Root $SourceOutput",
    "-ExpectedManifest $SourceStageManifest");
var packageExchangedRuntimeParity = FindSinglePowerShellBlockIndex(
    durableExchangeArchiveParityBlocks,
    "-Path $RuntimeZip",
    "-ExpectedManifest $RuntimeStageManifest",
    "-Label 'Exchanged runtime ZIP'");
var packageExchangedSourceParity = FindSinglePowerShellBlockIndex(
    durableExchangeArchiveParityBlocks,
    "-Path $SourceZip",
    "-ExpectedManifest $SourceStageManifest",
    "-Label 'Exchanged source ZIP'");
var packageExchangedChecksumRead = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "$storedChecksumLines = @(Get-Content -LiteralPath $ChecksumPath)");
var packageCommitMove = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(durableReleaseExchangeFunction, "Move-ManagedArtifact"),
    "-Source $ReleaseCommitPendingPath",
    "-Destination $ReleaseCommitPath",
    "-ReplaceExisting");
var packageCommittedReleaseRead = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(
        durableReleaseExchangeFunction,
        "$committedRelease = Read-StrictReleaseCommit"),
    "-Path $ReleaseCommitPath",
    "-Artifacts $releaseArtifacts");
var packageCommittedReleaseFailure = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "throw 'The stable release commit does not identify the completed transaction.'");
var packageCommittedReleaseParity = FindSinglePowerShellBlockIndex(
    ReadPowerShellCommandBlocks(
        durableReleaseExchangeFunction,
        "Assert-CurrentReleaseMatchesCommit"),
    "-Commit $committedRelease",
    "-Artifacts $releaseArtifacts");
var durableSuccessReturn = FindSinglePowerShellCommandIndex(
    durableReleaseExchangeFunction,
    "return $true");
var durableSuccessReturnDepth = GetPowerShellBraceDepthAt(
    durableReleaseExchangeFunction,
    durableSuccessReturn);
var packageReleaseSucceeded = durableReleaseExchangeCall;
var packageReleaseSucceededDepth = durableReleaseExchangeCallDepth;
var packageCatchRethrow = FindSinglePowerShellCommandIndex(
    packageMain,
    "throw $releaseFailure");
var packageCatchRethrowDepth = GetPowerShellBraceDepthAt(
    packageMain,
    packageCatchRethrow);
var packageReadyGuard = FindSinglePowerShellScopedBlock(
    packageMain,
    "if (!$releaseExchangeSucceeded) {");
var packageReadyGuardFailure = packageReadyGuard.HasValue
    ? FindSinglePowerShellCommandIndex(
        packageReadyGuard.Value.Text,
        "throw 'The release exchange reached its ready path without a verified commit.'")
    : -1;
var packageReleaseReady = FindSinglePowerShellCommandIndex(
    packageMain,
    "Write-Host \"Release ready after validated exchange: $RuntimeOutput\"");
var packageReleaseReadyDepth = GetPowerShellBraceDepthAt(
    packageMain,
    packageReleaseReady);
var packageLockDispose = FindSinglePowerShellCommandIndex(
    packageMain,
    "$releaseExchangeLock.Dispose()");
var packageLockDisposeDepth = GetPowerShellBraceDepthAt(
    packageMain,
    packageLockDispose);
var packageGuardianLeaseRelease = FindSinglePowerShellCommandIndex(
    packageMain,
    "Exit-GuardianReleaseLease -Mutex $guardianReleaseLease");
var packageGuardianLeaseReleaseDepth = GetPowerShellBraceDepthAt(
    packageMain,
    packageGuardianLeaseRelease);
var packageOutputPathVariables = new[]
{
    "RuntimeZip", "SourceZip", "ChecksumPath",
    "RuntimeNext", "RuntimePrevious", "SourceNext", "SourcePrevious",
    "RuntimeZipNext", "RuntimeZipPrevious", "SourceZipNext", "SourceZipPrevious",
    "ChecksumNext", "ChecksumPrevious",
    "ReleaseCommitPath", "ReleaseJournalPath", "ReleaseLockPath", "ReleaseCommitPendingPath"
};
var packageOutputAssignmentsExact = packageOutputPathVariables.All(variable =>
    Regex.Matches(
        packageMain,
        $@"(?im)^[ \t]*\${Regex.Escape(variable)}[ \t]*=").Count == 1);
var packageReleaseArtifactIds = Regex.Matches(
        packageMain,
        @"(?m)^[ \t]*\[pscustomobject\]@\{ Id = '(?<id>[a-z-]+)'; Label =")
    .Cast<Match>()
    .Select(match => match.Groups["id"].Value)
    .ToArray();
var expectedReleaseArtifactIds = new[]
{
    "runtime-directory",
    "source-directory",
    "runtime-zip",
    "source-zip",
    "checksum"
};
var outputPathFunction = SlicePowerShellFunction(packageReleaseSource, "Assert-OutputPath");
var exactPathEntryFunction = SlicePowerShellFunction(packageReleaseSource, "Get-ExactPathEntry");
var removeManagedDirectoryFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Remove-ManagedDirectoryTree");
var removeScratchDirectoryFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Remove-ScratchDirectoryTree");
var removeTempDirectoryFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Remove-TempDirectoryTree");
var cleanupTargetSnapshotFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-CleanupTargetSnapshot");
var pinnedDotnetResolverFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Resolve-PinnedDotnetExecutable");
var pinnedDotnetPlanFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-PinnedDotnetFilePlan");
var pinnedLeaseHashFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-PinnedLeaseStreamSha256");
var pinnedDotnetOpenFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Open-PinnedDotnetLeases");
var pinnedDotnetAssertFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-PinnedDotnetLeases");
var pinnedDotnetCloseFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Close-PinnedDotnetLeases");
var hermeticDotnetEnvironmentFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-HermeticDotnetChildEnvironment");
var releaseDotnetEnvironmentFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-ReleaseDotnetEnvironment");
var pinnedDotnetCommandFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Invoke-PinnedDotnetCommand");
var manifestFileFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-FileContentManifestEntry");
var manifestEqualityFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-ContentManifestsEqual");
var archiveManifestFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-ArchiveContentManifest");
var archiveParityFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-ArchiveMatchesManifest");
var closureFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-StagedProjectReferenceClosure");
var projectConditionFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-StagedProjectConditionShape");
var boundedGateFunction = SlicePowerShellFunction(packageReleaseSource, "Invoke-BoundedDotnetGate");
var boundedCimFunction = SlicePowerShellFunction(packageReleaseSource, "Invoke-BoundedGateCimQuery");
var boundedMarkerFunction = SlicePowerShellFunction(packageReleaseSource, "Get-ExactMarkerCount");
var boundedStopFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Stop-BoundedExactArtifactProcess");
var boundedArtifactQueryFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-BoundedGateArtifactProcesses");
var boundedArtifactCleanupFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Stop-BoundedGateArtifactProcesses");
var releaseProcessShapeFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-ReleaseProcessMethodsShape");
var releaseProcessInitializerFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Initialize-ReleaseProcessMethods");
var boundedReleaseProcessFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Invoke-BoundedReleaseProcess");
var pinnedUnifiedProcessCalls = ReadPowerShellCommandBlocks(
    pinnedDotnetCommandFunction,
    "$result = Invoke-BoundedReleaseProcess");
var nativeUnifiedProcessCalls = ReadPowerShellCommandBlocks(
    boundedGateFunction,
    "$result = Invoke-BoundedReleaseProcess");
var boundedLeaseChecks = ReadPowerShellCommandBlocks(
    boundedReleaseProcessFunction,
    "Assert-PinnedDotnetLeases -Authority $Authority");
var boundedLowLevelRun = FindSinglePowerShellCommandIndex(
    boundedReleaseProcessFunction,
    "$result = [CodexGuardian.ReleaseProcessMethodsV2]::Run(");
var normalizedHermeticEnvironmentFunction = NormalizeLineEndings(
    hermeticDotnetEnvironmentFunction);
var hermeticMapStart = normalizedHermeticEnvironmentFunction.IndexOf(
    "$environment = [ordered]@{",
    StringComparison.Ordinal);
var hermeticMapEnd = hermeticMapStart < 0
    ? -1
    : normalizedHermeticEnvironmentFunction.IndexOf(
        "\n    }\n",
        hermeticMapStart,
        StringComparison.Ordinal);
var hermeticMapSource = hermeticMapStart >= 0 && hermeticMapEnd > hermeticMapStart
    ? normalizedHermeticEnvironmentFunction[hermeticMapStart..hermeticMapEnd]
    : string.Empty;
var hermeticEnvironmentKeys = Regex.Matches(
        hermeticMapSource,
        @"(?m)^[ \t]{8}(?:'(?<quoted>[^']+)'|(?<bare>[A-Za-z][A-Za-z0-9_()]*))[ \t]*=")
    .Cast<Match>()
    .Select(match => match.Groups["quoted"].Success
        ? match.Groups["quoted"].Value
        : match.Groups["bare"].Value)
    .ToArray();
var expectedHermeticEnvironmentKeys = new HashSet<string>(
    new[]
    {
        "WINDIR",
        "SystemRoot",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "CODEX_GUARDIAN_TEST_DATA_ROOT",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "DOTNET_ROOT",
        "DOTNET_ROOT_X64",
        "DOTNET_HOST_PATH",
        "DOTNET_MULTILEVEL_LOOKUP",
        "DOTNET_CLI_HOME",
        "DOTNET_CLI_TELEMETRY_OPTOUT",
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE",
        "DOTNET_NOLOGO",
        "DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER",
        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE",
        "DOTNET_BUNDLE_EXTRACT_BASE_DIR",
        "NUGET_PACKAGES",
        "NUGET_HTTP_CACHE_PATH",
        "NUGET_SCRATCH",
        "NUGET_PLUGINS_CACHE_PATH",
        "NUGET_XMLDOC_MODE",
        "MSBuildUserExtensionsPath",
        "MSBUILDDISABLENODEREUSE"
    },
    StringComparer.OrdinalIgnoreCase);
var releaseProcessEnvironmentBlock = releaseProcessInitializerFunction.IndexOf(
    "environmentBlock = BuildEnvironmentBlock(",
    StringComparison.Ordinal);
var releaseProcessCreate = releaseProcessInitializerFunction.IndexOf(
    "if (!CreateProcessW(",
    StringComparison.Ordinal);
var releaseProcessAssign = releaseProcessInitializerFunction.IndexOf(
    "if (!AssignProcessToJobObject(job, process))",
    StringComparison.Ordinal);
var releaseProcessDrainStart = releaseProcessInitializerFunction.IndexOf(
    "stdoutTask = DrainBoundedAsync(",
    StringComparison.Ordinal);
var releaseProcessResume = releaseProcessInitializerFunction.IndexOf(
    "if (ResumeThread(thread) == UInt32.MaxValue)",
    StringComparison.Ordinal);
var releaseProcessResidualBefore = releaseProcessInitializerFunction.IndexOf(
    "residualBeforeCleanup = checked((int)WaitForJobToEmpty(",
    StringComparison.Ordinal);
var releaseProcessTerminate = releaseProcessInitializerFunction.IndexOf(
    "TerminateJobChecked(job);",
    StringComparison.Ordinal);
var releaseProcessResidualAfter = releaseProcessInitializerFunction.IndexOf(
    "residualAfterCleanup = checked((int)WaitForJobToEmpty(",
    StringComparison.Ordinal);
var releaseProcessDrainWait = releaseProcessInitializerFunction.IndexOf(
    "drainsComplete = WaitForDrains(",
    StringComparison.Ordinal);
var releaseProcessForcedDrain = releaseProcessInitializerFunction.IndexOf(
    "Interlocked.Exchange(ref capture.ForcedDrain, 1);",
    StringComparison.Ordinal);
var releaseProcessForcedDrainCancel = releaseProcessForcedDrain < 0
    ? -1
    : releaseProcessInitializerFunction.IndexOf(
        "drainCancellation.Cancel();",
        releaseProcessForcedDrain,
        StringComparison.Ordinal);
var newOutputDirectoryFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "New-ManagedOutputDirectory");
var copyOutputTreeFunction = SlicePowerShellFunction(packageReleaseSource, "Copy-ManagedOutputTree");
var compressOutputFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Compress-ManagedOutputArchive");
var canonicalArchiveFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Compress-CanonicalArchive");
var runtimeTestPayloadPathFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Test-IsRuntimeTestPayloadPath");
var noRuntimeTestPayloadFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-NoRuntimeTestPayload");
var noRuntimeTestArchiveEntriesFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-NoRuntimeTestArchiveEntries");
var syncArtifactFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Sync-ManagedArtifact");
var enterGuardianReleaseLeaseFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Enter-GuardianReleaseLease");
var exitGuardianReleaseLeaseFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Exit-GuardianReleaseLease");
var writeOutputFunction = SlicePowerShellFunction(packageReleaseSource, "Write-ManagedOutputLines");
var moveOutputFunction = SlicePowerShellFunction(packageReleaseSource, "Move-ManagedArtifact");
var moveOutputSourceGuard = FindSinglePowerShellCommandIndex(
    moveOutputFunction,
    "$managedSource = Assert-OutputPath $Source");
var moveOutputDestinationGuard = FindSinglePowerShellCommandIndex(
    moveOutputFunction,
    "$managedDestination = Assert-OutputPath $Destination");
var moveOutputNativeCall = moveOutputFunction.IndexOf(
    "[CodexGuardian.ReleaseNativeMethodsV2]::MoveFileEx(",
    StringComparison.Ordinal);
var releaseNativeMethodsFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Initialize-ReleaseNativeMethods");
var releaseNativeMethodsShapeFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Assert-ReleaseNativeMethodsShape");
var transactionFaultCallbackFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Invoke-ReleaseTransactionFaultCallback");
var internalTransactionContextFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-InternalReleaseTransactionContext");
var internalTransactionFaultPointsFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-InternalReleaseTransactionFaultPoints");
var internalTransactionRequestFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Read-InternalReleaseTransactionRequest");
var internalTransactionJsonWriterFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Write-InternalReleaseTransactionJson");
var internalTransactionFaultMarkerFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Read-InternalReleaseTransactionFaultMarker");
var internalTransactionPlanFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "New-InternalReleaseArtifactPlan");
var internalTransactionGenerationFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "New-InternalReleaseFixtureGeneration");
var internalTransactionCommitFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "New-InternalReleaseFixtureCommit");
var internalTransactionSnapshotFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Get-InternalReleaseTransactionSnapshot");
var internalTransactionHarnessFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Invoke-InternalReleaseTransactionHarness");
var durableWriteFunction = SlicePowerShellFunction(packageReleaseSource, "Write-DurableManagedText");
var durableTempFaultCallback = durableWriteFunction.IndexOf(
    "-Point ($FaultScope + '.temp-flushed')",
    StringComparison.Ordinal);
var durableStateMove = durableWriteFunction.IndexOf(
    "Move-ManagedArtifact",
    StringComparison.Ordinal);
var durablePublishedFaultCallback = durableWriteFunction.IndexOf(
    "-Point ($FaultScope + '.published')",
    StringComparison.Ordinal);
var strictJsonFunction = SlicePowerShellFunction(packageReleaseSource, "Read-StrictReleaseJsonText");
var strictCommitFunction = SlicePowerShellFunction(packageReleaseSource, "Read-StrictReleaseCommit");
var strictJournalFunction = SlicePowerShellFunction(packageReleaseSource, "Read-StrictReleaseJournal");
var canonicalCommitFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "ConvertTo-CanonicalReleaseCommit");
var canonicalJournalFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "ConvertTo-CanonicalReleaseJournal");
var manifestIdentityFunction = SlicePowerShellFunction(packageReleaseSource, "Get-ManifestIdentity");
var newJournalFunction = SlicePowerShellFunction(packageReleaseSource, "New-ReleaseJournalDocument");
var resolveExchangeFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Resolve-ReleaseExchangeTransaction");
var restoreExchangeFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Restore-UncommittedReleaseTransaction");
var completeExchangeFunction = SlicePowerShellFunction(
    packageReleaseSource,
    "Complete-CommittedReleaseTransaction");
var pendingStateFunction = SlicePowerShellFunction(packageReleaseSource, "Get-ReleasePendingStateFiles");
var discardMoveFunction = SlicePowerShellFunction(packageReleaseSource, "Move-ReleaseArtifactToDiscard");
var nativeRunStart = nativePeerProbeSource.IndexOf(
    "internal static void RunIfRequested",
    StringComparison.Ordinal);
var nativeRunEnd = nativeRunStart < 0
    ? -1
    : nativePeerProbeSource.IndexOf(
        "private static void TestPipeSecurityContract",
        nativeRunStart,
        StringComparison.Ordinal);
var nativeRunSource = nativeRunStart >= 0 && nativeRunEnd > nativeRunStart
    ? nativePeerProbeSource[nativeRunStart..nativeRunEnd]
    : string.Empty;
var nativeRunTargets = Regex.Matches(
        nativeRunSource,
        "RunCase\\(\\s*\"[^\"]*\",\\s*(?<target>[A-Za-z0-9_]+),\\s*assert\\);",
        RegexOptions.Singleline)
    .Cast<Match>()
    .Select(match => match.Groups["target"].Value)
    .ToArray();
var expectedNativeRunTargets = new[]
{
    "TestPipeSecurityContract",
    "TestRealBrokerPeer",
    "TestBlockedHelloCancellation",
    "TestPreCanceledHelloRead",
    "TestSecondFrameRejected",
    "TestOversizedFrameRejected",
    "TestMalformedHelloRejected",
    "TestPeerExitBeforeHello"
};
var packageFrozenSourceTail = packageClosureCall >= 0
    ? packageMain[packageClosureCall..]
    : string.Empty;
var packageActiveSourceReferencesAfterSeal = Regex.Matches(
    packageFrozenSourceTail,
    @"\$(?:ProjectRoot|TestsRoot|TrustRoot|BrokerProbeRoot|ProjectFile|TestsProject|GlobalJsonPath)(?![A-Za-z0-9_])").Count;
var nativeArgumentGuard = nativeRunSource.IndexOf(
    "Environment.GetCommandLineArgs().Contains",
    StringComparison.Ordinal);
var nativeEarlyReturn = nativeArgumentGuard < 0
    ? -1
    : nativeRunSource.IndexOf("return;", nativeArgumentGuard, StringComparison.Ordinal);
var nativeFirstCase = nativeRunSource.IndexOf("RunCase(", StringComparison.Ordinal);
var nativeLastCase = nativeRunSource.LastIndexOf("RunCase(", StringComparison.Ordinal);
var nativeCompletionWrite = nativeRunSource.IndexOf(
    "Console.WriteLine(CompletionMarker);",
    StringComparison.Ordinal);
var guardianSourceRoot = guardianProjectPath is null
    ? null
    : Path.GetDirectoryName(guardianProjectPath);
var forbiddenProductionSourceEntries = guardianSourceRoot is null || !Directory.Exists(guardianSourceRoot)
    ? Array.Empty<string>()
    : Directory.EnumerateFiles(guardianSourceRoot, "*", SearchOption.AllDirectories)
        .Where(path =>
        {
            var relativeParts = Path.GetRelativePath(guardianSourceRoot, path)
                .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return !relativeParts.Contains("bin", StringComparer.OrdinalIgnoreCase) &&
                   !relativeParts.Contains("obj", StringComparer.OrdinalIgnoreCase) &&
                   Path.GetExtension(path) is ".cs" or ".xaml" or ".resx" or ".md" or ".csproj";
        })
        .Where(path =>
        {
            var source = File.ReadAllText(path);
            return source.Contains("install-codex-desktop-bridge", StringComparison.OrdinalIgnoreCase) ||
                   source.Contains("patch-codex-guardian-bridge", StringComparison.OrdinalIgnoreCase) ||
                   source.Contains("DesktopBridge", StringComparison.OrdinalIgnoreCase);
        })
        .Select(path => Path.GetRelativePath(guardianSourceRoot, path))
        .ToArray();
var diagnosticStart = mainViewModelSource.IndexOf(
    "private async Task RunReadOnlyDiagnosticAsync",
    StringComparison.Ordinal);
var diagnosticEnd = diagnosticStart < 0
    ? -1
    : mainViewModelSource.IndexOf(
        "private async Task<bool> SaveSettingsAsync",
        diagnosticStart,
        StringComparison.Ordinal);
var diagnosticSource = diagnosticStart >= 0 && diagnosticEnd > diagnosticStart
    ? mainViewModelSource[diagnosticStart..diagnosticEnd]
    : string.Empty;
var nativeStartTurnStart = desktopIpcSource.IndexOf(
    "public async Task<DesktopStartTurnResult> AppendRecoverySuccessorAsync",
    StringComparison.Ordinal);
// The append-only entry point and the shared recovery channel-readiness guard sit before the
// in-place retry dispatcher, so both append slices end exactly where in-place retry begins.
var inPlaceRetryDispatchStart = desktopIpcSource.IndexOf(
    "private async Task<DesktopInPlaceRetryResult> SendInPlaceRetryAsync",
    StringComparison.Ordinal);
var inPlaceRetryDispatchEnd = desktopIpcSource.IndexOf(
    "internal async Task<DesktopStartTurnResult> StartTextTurnAsync",
    StringComparison.Ordinal);
var inPlaceRetrySource =
    inPlaceRetryDispatchStart >= 0 && inPlaceRetryDispatchEnd > inPlaceRetryDispatchStart
        ? desktopIpcSource[inPlaceRetryDispatchStart..inPlaceRetryDispatchEnd]
        : string.Empty;
var inPlaceRetryEntryStart = desktopIpcSource.IndexOf(
    "public async Task<DesktopInPlaceRetryResult> RetryFailedTurnInPlaceAsync",
    StringComparison.Ordinal);
var inPlaceRetryEntrySource =
    inPlaceRetryEntryStart >= 0 && nativeStartTurnStart > inPlaceRetryEntryStart
        ? desktopIpcSource[inPlaceRetryEntryStart..nativeStartTurnStart]
        : string.Empty;
var nativeStartTurnEnd = nativeStartTurnStart < 0 ? -1 : inPlaceRetryDispatchStart;
var nativeStartTurnSource = nativeStartTurnStart >= 0 && nativeStartTurnEnd > nativeStartTurnStart
    ? desktopIpcSource[nativeStartTurnStart..nativeStartTurnEnd]
    : string.Empty;
var recoveryStartTurnMethodEnd = nativeStartTurnStart < 0 ? -1 : inPlaceRetryDispatchStart;
var recoveryStartTurnMethodSource =
    nativeStartTurnStart >= 0 && recoveryStartTurnMethodEnd > nativeStartTurnStart
        ? desktopIpcSource[nativeStartTurnStart..recoveryStartTurnMethodEnd]
        : string.Empty;
var followUpStartTurnMethodStart = inPlaceRetryDispatchEnd;
var followUpStartTurnMethodEnd = followUpStartTurnMethodStart < 0
    ? -1
    : desktopIpcSource.IndexOf(
        "internal static JsonElement BuildNativeRecoveryInput",
        followUpStartTurnMethodStart,
        StringComparison.Ordinal);
var followUpStartTurnMethodSource =
    followUpStartTurnMethodStart >= 0 && followUpStartTurnMethodEnd > followUpStartTurnMethodStart
        ? desktopIpcSource[followUpStartTurnMethodStart..followUpStartTurnMethodEnd]
        : string.Empty;
var structuredStartTurnMethodStart = desktopIpcSource.IndexOf(
    "internal async Task<DesktopStartTurnResult> StartStructuredTurnAsync",
    StringComparison.Ordinal);
var structuredStartTurnMethodEnd = structuredStartTurnMethodStart < 0
    ? -1
    : desktopIpcSource.IndexOf(
        "public async Task<bool> ProbeNativeDesktopChannelAsync",
        structuredStartTurnMethodStart,
        StringComparison.Ordinal);
var structuredStartTurnMethodSource =
    structuredStartTurnMethodStart >= 0 && structuredStartTurnMethodEnd > structuredStartTurnMethodStart
        ? desktopIpcSource[structuredStartTurnMethodStart..structuredStartTurnMethodEnd]
        : string.Empty;
var compatibleStartTurnMethodStart = desktopIpcSource.IndexOf(
    "private async Task<JsonElement> SendNativeStartTurnCompatibleAsync",
    StringComparison.Ordinal);
var compatibleStartTurnMethodEnd = compatibleStartTurnMethodStart < 0
    ? -1
    : desktopIpcSource.IndexOf(
        "private async Task ProbeNativeDesktopChannelCoreAsync",
        compatibleStartTurnMethodStart,
        StringComparison.Ordinal);
var compatibleStartTurnMethodSource =
    compatibleStartTurnMethodStart >= 0 && compatibleStartTurnMethodEnd > compatibleStartTurnMethodStart
        ? desktopIpcSource[compatibleStartTurnMethodStart..compatibleStartTurnMethodEnd]
        : string.Empty;
var recoveryConnectionAttempt = recoveryStartTurnMethodSource.IndexOf(
    "await EnsureConnectedAsync(cancellationToken)",
    StringComparison.Ordinal);
var recoveryConnectionCancellation = recoveryStartTurnMethodSource.IndexOf(
    "catch (OperationCanceledException exception)",
    StringComparison.Ordinal);
var recoveryConnectionNotDispatched = recoveryConnectionCancellation < 0
    ? -1
    : recoveryStartTurnMethodSource.IndexOf(
        "DesktopIpcDeliveryStage.NotDispatched",
        recoveryConnectionCancellation,
        StringComparison.Ordinal);
var recoveryCancellationClassification = recoveryStartTurnMethodSource.IndexOf(
    "classifyCancellationForRecovery: true",
    StringComparison.Ordinal);
var followUpConnectionAttempt = followUpStartTurnMethodSource.IndexOf(
    "await EnsureConnectedAsync(cancellationToken)",
    StringComparison.Ordinal);
var followUpConnectionCancellation = followUpStartTurnMethodSource.IndexOf(
    "catch (OperationCanceledException exception)",
    StringComparison.Ordinal);
var followUpConnectionNotDispatched = followUpConnectionCancellation < 0
    ? -1
    : followUpStartTurnMethodSource.IndexOf(
        "DesktopIpcDeliveryStage.NotDispatched",
        followUpConnectionCancellation,
        StringComparison.Ordinal);
var followUpCancellationClassification = followUpStartTurnMethodSource.IndexOf(
    "classifyCancellationForRecovery: true",
    StringComparison.Ordinal);
var structuredConnectionAttempt = structuredStartTurnMethodSource.IndexOf(
    "await EnsureConnectedAsync(cancellationToken)",
    StringComparison.Ordinal);
var structuredConnectionCancellation = structuredStartTurnMethodSource.IndexOf(
    "catch (OperationCanceledException exception)",
    StringComparison.Ordinal);
var structuredConnectionNotDispatched = structuredConnectionCancellation < 0
    ? -1
    : structuredStartTurnMethodSource.IndexOf(
        "DesktopIpcDeliveryStage.NotDispatched",
        structuredConnectionCancellation,
        StringComparison.Ordinal);
var structuredCancellationClassification = structuredStartTurnMethodSource.IndexOf(
    "classifyCancellationForRecovery: true",
    StringComparison.Ordinal);
var sendRequestCoreStart = desktopIpcSource.IndexOf(
    "private async Task<JsonElement> SendRequestCoreAsync",
    StringComparison.Ordinal);
var sendRequestCoreEnd = sendRequestCoreStart < 0
    ? -1
    : desktopIpcSource.IndexOf(
        "private async Task WriteFrameAsync",
        sendRequestCoreStart,
        StringComparison.Ordinal);
var sendRequestCoreSource = sendRequestCoreStart >= 0 && sendRequestCoreEnd > sendRequestCoreStart
    ? desktopIpcSource[sendRequestCoreStart..sendRequestCoreEnd]
    : string.Empty;
var recoveryCancellationCatch = sendRequestCoreSource.IndexOf(
    "catch (OperationCanceledException exception) when (classifyCancellationForRecovery)",
    StringComparison.Ordinal);
var callerCancellationCatch = sendRequestCoreSource.IndexOf(
    "catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)",
    StringComparison.Ordinal);
var writeFrameStart = sendRequestCoreEnd;
var writeFrameEnd = writeFrameStart < 0
    ? -1
    : desktopIpcSource.IndexOf(
        "private async Task ReceiveLoopAsync",
        writeFrameStart,
        StringComparison.Ordinal);
var writeFrameSource = writeFrameStart >= 0 && writeFrameEnd > writeFrameStart
    ? desktopIpcSource[writeFrameStart..writeFrameEnd]
    : string.Empty;
var writeGateWait = writeFrameSource.IndexOf(
    "await _writeGate.WaitAsync(cancellationToken)",
    StringComparison.Ordinal);
var preWriteCancellationCheck = writeFrameSource.IndexOf(
    "cancellationToken.ThrowIfCancellationRequested();",
    StringComparison.Ordinal);
var writeStartingMarker = writeFrameSource.IndexOf("onWriteStarting?.Invoke();", StringComparison.Ordinal);
var pipeWriteStart = writeFrameSource.IndexOf("await pipe.WriteAsync", StringComparison.Ordinal);
var nativeInputSelection = nativeStartTurnSource.IndexOf(
    "var input = BuildNativeRecoveryInput(",
    StringComparison.Ordinal);
var nativeStartRequest = nativeStartTurnSource.IndexOf(
    "SendNativeStartTurnCompatibleAsync",
    StringComparison.Ordinal);
var appServerReadMethods = typeof(AppServerClient)
    .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
    .Where(method => method.Name.Contains("Read", StringComparison.Ordinal))
    .Select(method => method.Name)
    .ToArray();
Assert(
    appServerSource.Length > 0 &&
    recoverySource.Length > 0 &&
    appServerSource.Contains("ReadLatestTurnWithFullItemsAsync", StringComparison.Ordinal) &&
    appServerSource.Contains("FullItemsView", StringComparison.Ordinal) &&
    appServerReadMethods.Contains("ReadLatestTurnWithFullItemsAsync", StringComparer.Ordinal) &&
    guardianEngineSource.Contains("ReadLatestTurnWithFullItemsAsync", StringComparison.Ordinal) &&
    !recoverySource.Contains("ReadCompleteTurnHistory", StringComparison.OrdinalIgnoreCase),
    "Guardian exposes one bounded exact-turn full-item recovery read without a full-history API");
Assert(
    packagePowerShellSyntax.Success &&
    string.Equals(packagePowerShellSyntax.Detail, "AST_PARSE_OK", StringComparison.Ordinal),
    $"package-release.ps1 parses with fixed Windows PowerShell: {packagePowerShellSyntax.Detail}");
Assert(
    packageValidateOnlyBlock.HasValue &&
    packageStopChecks.Count == 2 &&
    durableExchangeStopChecks.Count == 2 &&
    packageInitialStopCheck == 0 &&
    packageInitialStopDepth == 0 &&
    packageScratchInitialize > packageInitialStopCheck &&
    packageTempInitialize > packageScratchInitialize &&
    packageNuGetPackagesInitialize > packageTempInitialize &&
    packageNuGetHttpCacheInitialize > packageNuGetPackagesInitialize &&
    packageNuGetPluginsCacheInitialize > packageNuGetHttpCacheInitialize &&
    packageBrokerConsentLedgerTestDataLengthGate > packageInitialStopCheck &&
    packageBrokerConsentLedgerTestDataPreexistingGate > packageBrokerConsentLedgerTestDataLengthGate &&
    packageBrokerConsentLedgerTestDataCreate > packageBrokerConsentLedgerTestDataPreexistingGate &&
    packageStageDirectoryCreate > packageBrokerConsentLedgerTestDataCreate &&
    packageValidationRuntimeProducer > packageValidateOnlyBlock.Value.OpenBraceIndex &&
    packageValidationSourceParity < packageValidateOnlyBlock.Value.CloseBraceIndex &&
    packageValidateOnlyReturn > packageValidationSourceParity &&
    packageValidateOnlyReturn < packageValidateOnlyBlock.Value.CloseBraceIndex &&
    packageGuardianLeaseAcquire > packageValidateOnlyBlock.Value.CloseBraceIndex &&
    packageGuardianLeaseAcquire < packagePreOutputStopCheck &&
    packageGuardianLeaseAcquireDepth == packageValidateOnlyBlock.Value.ParentDepth &&
    packagePreOutputStopDepth == packageValidateOnlyBlock.Value.ParentDepth &&
    packageOutputRootTraversal > packagePreOutputStopCheck &&
    packageOutputRootTraversalDepth == packageValidateOnlyBlock.Value.ParentDepth &&
    packageOutputsRootCreate > packageOutputRootTraversal &&
    packageRuntimeZipAssignment > packageOutputsRootCreate,
    "release packaging parses then gates Guardian before staging and formal output writes");
Assert(
    packageTestsRestore > packageClosureCall && packageBuild > packageTestsRestore &&
    packagePublishRestore > packageTargetedRefresh &&
    packageBrokerPublishRestore > packagePublishRestore &&
    packagePublish > packageBrokerPublishRestore &&
    packageBrokerPublish > packagePublish &&
    packagePublishedRuntimeClosure > packageBrokerPublish &&
    packagePublishedBrokerRuntimeClosure > packagePublishedRuntimeClosure &&
    packagePublishedGuardianManagedEntryProof > packagePublishedBrokerRuntimeClosure,
    "release command graph has separate locked restores, dual publish closure, and apphost proof");
Assert(
    packagePinnedDotnetCommands.Count == 15 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("-TimeoutSeconds 900", StringComparison.Ordinal)) == 3 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("-TimeoutSeconds 300", StringComparison.Ordinal)) == 6 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("-TimeoutSeconds 180", StringComparison.Ordinal)) == 6,
    "release restore build test and publish command counts remain bounded");
Assert(
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'restore',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedTestsProject", StringComparison.Ordinal) &&
        block.Text.Contains("'--configfile', $StagedNuGetConfigPath", StringComparison.Ordinal) &&
        block.Text.Contains("'--packages', $NugetPackages", StringComparison.Ordinal) &&
        block.Text.Contains("'--locked-mode'", StringComparison.Ordinal) &&
        block.Text.Contains("'-r', 'win-x64'", StringComparison.Ordinal) &&
        !block.Text.Contains("'-p:SelfContained=true'", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'restore',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedProjectFile", StringComparison.Ordinal) &&
        block.Text.Contains("'--configfile', $StagedNuGetConfigPath", StringComparison.Ordinal) &&
        block.Text.Contains("'--packages', $NugetPackages", StringComparison.Ordinal) &&
        block.Text.Contains("'--locked-mode'", StringComparison.Ordinal) &&
        block.Text.Contains("'-r', 'win-x64'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:SelfContained=true'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:CodexGuardianTestFriend=false'", StringComparison.Ordinal) &&
        block.Text.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'restore',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedBrokerProject", StringComparison.Ordinal) &&
        block.Text.Contains("'--configfile', $StagedNuGetConfigPath", StringComparison.Ordinal) &&
        block.Text.Contains("'--packages', $NugetPackages", StringComparison.Ordinal) &&
        block.Text.Contains("'--locked-mode'", StringComparison.Ordinal) &&
        block.Text.Contains("'-r', 'win-x64'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:SelfContained=true'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:CodexGuardianTestFriend=false'", StringComparison.Ordinal) &&
        block.Text.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal)) == 1 &&
    !packageReleaseSource.Contains("'--force-evaluate'", StringComparison.Ordinal),
    "locked restores use the pinned source without rewriting the dependency lock");
Assert(
    packageMain.Length > 0 && !packageHasHereString && packageMainProcessEscapeCount == 0 &&
    packageResolveDotnet > packageStageDirectoryCreate &&
    packageOpenDotnetAuthority > packageResolveDotnet &&
    packageDotnetAuthorityAgreement > packageOpenDotnetAuthority &&
    packageSourceRestoreInputsGate > packageDotnetAuthorityAgreement &&
    packageActiveSourceBefore > packageSourceRestoreInputsGate &&
    packageGuardianCopy > packageActiveSourceBefore &&
    packageTestsCopy > packageGuardianCopy &&
    packageControlCopy > packageTestsCopy &&
    packageTrustCopy > packageControlCopy &&
    packageBrokerCopy > packageTrustCopy &&
    packageScriptCopy > packageBrokerCopy &&
    packageGlobalJsonCopy > packageScriptCopy &&
    packageNuGetConfigCopy > packageGlobalJsonCopy &&
    packageSourceStageManifest > packageNuGetConfigCopy &&
    packageActiveSourceAfter > packageSourceStageManifest &&
    packageStagedGlobalJsonGate > packageActiveSourceAfter &&
    packageStagedRestoreInputsGate > packageStagedGlobalJsonGate &&
    packageImplicitInputsCall > packageStagedRestoreInputsGate &&
    packageClosureCall > packageImplicitInputsCall &&
    packageTestsRestore > packageClosureCall && packageBuild > packageTestsRestore &&
    packageGuardianAdmission > packageBuild &&
    packageSafeDrill > packageGuardianAdmission &&
    packageNativeUserPresenceEvidenceRootAbsentGate > packageSafeDrill &&
    packageNativeUserPresenceEvidenceRootCreate > packageNativeUserPresenceEvidenceRootAbsentGate &&
    packageNativeUserPresenceEvidenceRootEmptyGate > packageNativeUserPresenceEvidenceRootCreate &&
    packageNativeUserPresenceCapabilityGate > packageNativeUserPresenceEvidenceRootEmptyGate &&
    packageNativePeerGate > packageNativeUserPresenceCapabilityGate &&
    packageConnectedClientGate > packageNativePeerGate &&
    packageWatcher > packageConnectedClientGate &&
    packageBaseline > packageWatcher && packageIdle > packageBaseline &&
    packageTargetedRefresh > packageIdle &&
    packagePublishRestore > packageTargetedRefresh &&
    packageBrokerPublishRestore > packagePublishRestore &&
    packagePublish > packageBrokerPublishRestore &&
    packageBrokerPublish > packagePublish &&
    packagePublishedRuntimeClosure > packageBrokerPublish &&
    packagePublishedBrokerRuntimeClosure > packagePublishedRuntimeClosure &&
    packagePublishedGuardianManagedEntryProof > packagePublishedBrokerRuntimeClosure &&
    packageNormalAuthorityClose > packagePublishedGuardianManagedEntryProof &&
    packageNormalAuthorityNull > packageNormalAuthorityClose &&
    packageSourcePostBuildParity > packageNormalAuthorityNull &&
    packageRuntimeStageManifest > packageSourcePostBuildParity &&
    packagePinnedDotnetCommands.Count == 15 &&
    pinnedDotnetCommandFunction.Contains("[string]$ExpectedSuccessMarker = ''", StringComparison.Ordinal) &&
    pinnedDotnetCommandFunction.Contains("[switch]$RequireEmptyStderr", StringComparison.Ordinal) &&
    pinnedDotnetCommandFunction.Contains("[regex]::Split([string]$result.Stdout, '\\r?\\n')", StringComparison.Ordinal) &&
    pinnedDotnetCommandFunction.Contains("if ($markerCount -ne 1)", StringComparison.Ordinal) &&
    pinnedDotnetCommandFunction.Contains("![string]::IsNullOrEmpty([string]$result.Stderr)", StringComparison.Ordinal) &&
    packagePinnedDotnetCommands.All(block =>
        block.Text.Contains("-Authority $DotnetAuthority", StringComparison.Ordinal) &&
        block.Text.Contains("-WorkingDirectory $SourceStage", StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds ", StringComparison.Ordinal)) &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("-TimeoutSeconds 900", StringComparison.Ordinal)) == 3 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("-TimeoutSeconds 300", StringComparison.Ordinal)) == 6 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("-TimeoutSeconds 180", StringComparison.Ordinal)) == 6 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("$TestsAssembly", StringComparison.Ordinal) &&
        block.Text.Contains(
            "'--broker-guardian-admission-offline-only'",
            StringComparison.Ordinal) &&
        block.Text.Contains(
            "-Label 'Broker Guardian admission offline tests'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 300", StringComparison.Ordinal) &&
        block.Text.Contains(
            "-ExpectedSuccessMarker 'BROKER_GUARDIAN_ADMISSION_OFFLINE_TESTS_COMPLETE'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-RequireEmptyStderr", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("$TestsAssembly", StringComparison.Ordinal) &&
        block.Text.Contains("'--safe-drill-only'", StringComparison.Ordinal) &&
        block.Text.Contains("-Label 'Safe-drill tests'", StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 300", StringComparison.Ordinal) &&
        block.Text.Contains(
            "-ExpectedSuccessMarker 'ALL TESTS PASSED'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-RequireEmptyStderr", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("$TestsAssembly", StringComparison.Ordinal) &&
        block.Text.Contains("'--watcher-only'", StringComparison.Ordinal) &&
        block.Text.Contains("-Label 'Real-time watcher tests'", StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 300", StringComparison.Ordinal) &&
        block.Text.Contains(
            "-ExpectedSuccessMarker 'ALL TESTS PASSED'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-RequireEmptyStderr", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'restore',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedTestsProject", StringComparison.Ordinal) &&
        block.Text.Contains("'--configfile', $StagedNuGetConfigPath", StringComparison.Ordinal) &&
        block.Text.Contains("'--packages', $NugetPackages", StringComparison.Ordinal) &&
        block.Text.Contains("'--locked-mode'", StringComparison.Ordinal) &&
        block.Text.Contains("'-r', 'win-x64'", StringComparison.Ordinal) &&
        !block.Text.Contains("'-p:SelfContained=true'", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'restore',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedProjectFile", StringComparison.Ordinal) &&
        block.Text.Contains("'--configfile', $StagedNuGetConfigPath", StringComparison.Ordinal) &&
        block.Text.Contains("'--packages', $NugetPackages", StringComparison.Ordinal) &&
        block.Text.Contains("'--locked-mode'", StringComparison.Ordinal) &&
        block.Text.Contains("'-r', 'win-x64'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:SelfContained=true'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:CodexGuardianTestFriend=false'", StringComparison.Ordinal) &&
        block.Text.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'restore',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedBrokerProject", StringComparison.Ordinal) &&
        block.Text.Contains("'--configfile', $StagedNuGetConfigPath", StringComparison.Ordinal) &&
        block.Text.Contains("'--packages', $NugetPackages", StringComparison.Ordinal) &&
        block.Text.Contains("'--locked-mode'", StringComparison.Ordinal) &&
        block.Text.Contains("'-r', 'win-x64'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:SelfContained=true'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:CodexGuardianTestFriend=false'", StringComparison.Ordinal) &&
        block.Text.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal)) == 1 &&
    !packageReleaseSource.Contains("'--force-evaluate'", StringComparison.Ordinal) &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'build',", StringComparison.Ordinal) &&
        block.Text.Contains("'--disable-build-servers'", StringComparison.Ordinal) &&
        block.Text.Contains("'--no-restore'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:RestoreLockedMode=true'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:UseSharedCompilation=false'", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'publish',", StringComparison.Ordinal) &&
        block.Text.Contains("'--disable-build-servers'", StringComparison.Ordinal) &&
        block.Text.Contains("'--no-restore'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:RestoreLockedMode=true'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:UseSharedCompilation=false'", StringComparison.Ordinal) &&
        block.Text.Contains("'-p:CodexGuardianTestFriend=false'", StringComparison.Ordinal) &&
        block.Text.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal)) == 2 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'publish',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedProjectFile", StringComparison.Ordinal) &&
        block.Text.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal) &&
        block.Text.Contains("'-o', $RuntimeStage", StringComparison.Ordinal) &&
        block.Text.Contains("-Label 'Runtime publish'", StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 900", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("'publish',", StringComparison.Ordinal) &&
        block.Text.Contains("$StagedBrokerProject", StringComparison.Ordinal) &&
        block.Text.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal) &&
        block.Text.Contains("'-o', $BrokerRuntimeStage", StringComparison.Ordinal) &&
        block.Text.Contains("-Label 'Broker runtime publish'", StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 900", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("$TestsAssembly", StringComparison.Ordinal) &&
        block.Text.Contains("'--verify-published-runtime-closure',", StringComparison.Ordinal)) == 2 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("$TestsAssembly", StringComparison.Ordinal) &&
        block.Text.Contains("'--verify-published-runtime-closure'", StringComparison.Ordinal) &&
        block.Text.Contains("'--published-runtime-root', $RuntimeStage", StringComparison.Ordinal) &&
        block.Text.Contains(
            "'--published-runtime-nuget-packages-root', $NugetPackages",
            StringComparison.Ordinal) &&
        block.Text.Contains(
            "'--published-runtime-root-assembly', 'CodexGuardian'",
            StringComparison.Ordinal) &&
        block.Text.Contains("'--require-production-runtime-surface'", StringComparison.Ordinal) &&
        block.Text.Contains("-Label 'Published runtime dependency closure'", StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 180", StringComparison.Ordinal) &&
        block.Text.Contains(
            "-ExpectedSuccessMarker 'PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_VERIFIED'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-RequireEmptyStderr", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("$TestsAssembly", StringComparison.Ordinal) &&
        block.Text.Contains(
            "'--guardian-managed-entry-apphost-probe',",
            StringComparison.Ordinal) &&
        block.Text.Contains(
            "'--guardian-managed-entry-runtime-root', $RuntimeStage",
            StringComparison.Ordinal) &&
        block.Text.Contains(
            "-Label 'Published Guardian managed-entry apphost proof'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 180", StringComparison.Ordinal) &&
        block.Text.Contains(
            "-ExpectedSuccessMarker 'GUARDIAN_MANAGED_ENTRY_APPHOST_PROOF_VERIFIED'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-RequireEmptyStderr", StringComparison.Ordinal)) == 1 &&
    packagePinnedDotnetCommands.Count(block =>
        block.Text.Contains("$TestsAssembly", StringComparison.Ordinal) &&
        block.Text.Contains("'--verify-published-runtime-closure'", StringComparison.Ordinal) &&
        block.Text.Contains("'--published-runtime-root', $BrokerRuntimeStage", StringComparison.Ordinal) &&
        block.Text.Contains(
            "'--published-runtime-nuget-packages-root', $NugetPackages",
            StringComparison.Ordinal) &&
        block.Text.Contains(
            "'--published-runtime-root-assembly', 'CodexGuardian.Broker'",
            StringComparison.Ordinal) &&
        block.Text.Contains("'--require-production-runtime-surface'", StringComparison.Ordinal) &&
        block.Text.Contains("-Label 'Published Broker runtime dependency closure'", StringComparison.Ordinal) &&
        block.Text.Contains("-TimeoutSeconds 180", StringComparison.Ordinal) &&
        block.Text.Contains(
            "-ExpectedSuccessMarker 'PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_VERIFIED'",
            StringComparison.Ordinal) &&
        block.Text.Contains("-RequireEmptyStderr", StringComparison.Ordinal)) == 1 &&
    packageAuthorityCloseBlocks.Count == 2 &&
    packageAuthorityNullBlocks.Count == 2 &&
    packageTopLevelFinallyMatches.Count == 1 &&
    packageFinalAuthorityClose > packageTopLevelFinally &&
    packageFinalAuthorityNull > packageFinalAuthorityClose &&
    packageActiveSourceReferencesAfterSeal == 0 &&
    packageReleaseSource.Contains("$env:WINDIR = 'C:\\Windows'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$env:SystemRoot = 'C:\\Windows'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$env:DOTNET_CLI_HOME = $DotnetCliHome", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$env:NUGET_PACKAGES = $NugetPackages", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$NugetPackages = Join-Path $ScratchWorkspace 'nuget-packages'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$NugetHttpCache = Join-Path $ScratchWorkspace 'nuget-http-cache'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$NugetPluginsCache = Join-Path $ScratchWorkspace 'nuget-plugins-cache'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$NugetScratch = Join-Path $TempWorkspace 'nuget-scratch'", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("$NugetPackages = Join-Path $DataRoot 'nuget'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$env:TEMP = $TempWorkspace", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$env:MSBuildUserExtensionsPath = $MSBuildUserExtensionsPath", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Join-Path $DataRoot 'release-package'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$SourceOutput = Join-Path $OutputsRoot 'CodexGuardian-source'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$TestDataRoot = Join-Path $ScratchWorkspace 'test-data'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$BrokerConsentLedgerTestData = Join-Path $TempRoot (",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "'l-' + $PID + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 16))",
        StringComparison.Ordinal) &&
    !packageReleaseSource.Contains(
        "$BrokerConsentLedgerTestData = Join-Path $TestDataRoot 'broker-consent-ledger'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$brokerConsentLedgerTestDataOwned = $false", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$brokerConsentLedgerTestDataOwned = $true", StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "if ($brokerConsentLedgerTestDataOwned) {",
        StringComparison.Ordinal) &&
    packageReleaseSource.Split(
        "(Get-CleanupTargetSnapshot $BrokerConsentLedgerTestData)",
        StringSplitOptions.None).Length - 1 == 1 &&
    packageReleaseSource.Split(
        "Remove-TempDirectoryTree $BrokerConsentLedgerTestData",
        StringSplitOptions.None).Length - 1 == 1 &&
    packageReleaseSource.Split(
        "$null -eq (Get-ExactPathEntry $BrokerConsentLedgerTestData)",
        StringSplitOptions.None).Length - 1 == 1 &&
    exactPathEntryFunction.Contains(
        "$current.EnumerateFileSystemInfos()",
        StringComparison.Ordinal) &&
    exactPathEntryFunction.Contains(
        "[System.StringComparison]::OrdinalIgnoreCase",
        StringComparison.Ordinal) &&
    !exactPathEntryFunction.Contains("Test-Path", StringComparison.Ordinal) &&
    removeManagedDirectoryFunction.IndexOf(
        "$rootItem = Get-ExactPathEntry $fullPath",
        StringComparison.Ordinal) >= 0 &&
    removeManagedDirectoryFunction.IndexOf(
        "ReparsePoint",
        StringComparison.Ordinal) >
        removeManagedDirectoryFunction.IndexOf(
            "$rootItem = Get-ExactPathEntry $fullPath",
            StringComparison.Ordinal) &&
    removeManagedDirectoryFunction.IndexOf(
        "Assert-NoReparsePointsInTree",
        StringComparison.Ordinal) >
        removeManagedDirectoryFunction.IndexOf("ReparsePoint", StringComparison.Ordinal) &&
    removeManagedDirectoryFunction.IndexOf(
        "Remove-Item -LiteralPath $fullPath -Recurse",
        StringComparison.Ordinal) >
        removeManagedDirectoryFunction.IndexOf(
            "Assert-NoReparsePointsInTree",
            StringComparison.Ordinal) &&
    removeManagedDirectoryFunction.LastIndexOf(
        "Get-ExactPathEntry $fullPath",
        StringComparison.Ordinal) >
        removeManagedDirectoryFunction.IndexOf(
            "Remove-Item -LiteralPath $fullPath -Recurse",
            StringComparison.Ordinal) &&
    !removeManagedDirectoryFunction.Contains("Test-Path", StringComparison.Ordinal) &&
    removeScratchDirectoryFunction.IndexOf(
        "$item = Get-ExactPathEntry $fullPath",
        StringComparison.Ordinal) >= 0 &&
    removeScratchDirectoryFunction.IndexOf(
        "Assert-NoReparsePointsInTree",
        StringComparison.Ordinal) >
        removeScratchDirectoryFunction.IndexOf("ReparsePoint", StringComparison.Ordinal) &&
    removeScratchDirectoryFunction.LastIndexOf(
        "Get-ExactPathEntry $fullPath",
        StringComparison.Ordinal) >
        removeScratchDirectoryFunction.IndexOf(
            "Remove-Item -LiteralPath $fullPath -Recurse",
            StringComparison.Ordinal) &&
    !removeScratchDirectoryFunction.Contains("Test-Path", StringComparison.Ordinal) &&
    removeTempDirectoryFunction.IndexOf(
        "$item = Get-ExactPathEntry $fullPath",
        StringComparison.Ordinal) >= 0 &&
    removeTempDirectoryFunction.IndexOf(
        "Assert-NoReparsePointsInTree",
        StringComparison.Ordinal) >
        removeTempDirectoryFunction.IndexOf("ReparsePoint", StringComparison.Ordinal) &&
    removeTempDirectoryFunction.LastIndexOf(
        "Get-ExactPathEntry $fullPath",
        StringComparison.Ordinal) >
        removeTempDirectoryFunction.IndexOf(
            "Remove-Item -LiteralPath $fullPath -Recurse",
            StringComparison.Ordinal) &&
    !removeTempDirectoryFunction.Contains("Test-Path", StringComparison.Ordinal) &&
    cleanupTargetSnapshotFunction.Contains(
        "$entry = Get-ExactPathEntry $fullPath",
        StringComparison.Ordinal) &&
    !cleanupTargetSnapshotFunction.Contains("Test-Path", StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$null -eq (Get-ExactPathEntry $ScratchWorkspace) -and",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$null -eq (Get-ExactPathEntry $TempWorkspace) -and",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Assert-DDriveCapacity", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Assert-NoSourceBuildResidue", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Initialize-TempWorkspace", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Write-CleanupManifest", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$CleanupPendingManifestPath", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("ConvertFrom-Json", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$CleanupManifestPath,", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$CleanupPendingManifestPath)", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("'--artifacts-path', $ArtifactsRoot", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$FormalArtifactsRoot = Join-Path $ScratchWorkspace 'formal-artifacts'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("'--artifacts-path', $FormalArtifactsRoot", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("'-p:ImportDirectoryBuildProps=false'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("'-p:ImportDirectoryBuildTargets=false'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("\"-p:MSBuildUserExtensionsPath=$MSBuildUserExtensionsPath\"", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$TestsAssembly = Join-Path $ArtifactsRoot", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$StagedGlobalJsonPath = Join-Path $SourceStage 'global.json'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $SourceStage 'global.json')", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("Join-Path $WorkRoot '.release-scratch'", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("CodexGuardian-source-package-current", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("CodexGuardian-win-x64.next.zip", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("CodexGuardian-win-x64.previous.zip", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("RecoveryOperationJournal.cs", StringComparison.Ordinal) &&
    packageReleaseSource.Split(
        "CodexPackageCompatibility.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "CodexAsarCapabilityInspector.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "CodexPackageGeneration.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "CodexAppxBlockMapVerifier.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "PublishedRuntimeDependencyClosureVerifier.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "BrokerConsentLedgerContract.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "BrokerConsentLedgerStore.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "CodexAsarCapabilityOfflineTests.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "BrokerConsentLedgerContractOfflineTests.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "BrokerConsentLedgerStoreOfflineTests.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "CodexPackageBaselineVerifier.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "GlobalUsings.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "WindowsCodexCdpRuntimeControlHost.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "WindowsCrtPipeProcessLifecycleOfflineTests.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "WindowsCodexCdpRuntimeControlHostOfflineTests.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "PublishedRuntimeDependencyClosureOfflineTests.cs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "cdp-runtime-profile.json",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "codex-guardian-cdp-observer-poc.mjs",
        StringSplitOptions.None).Length == 4 &&
    packageReleaseSource.Split(
        "System.Security.Cryptography.Pkcs.dll",
        StringSplitOptions.None).Length == 7 &&
    !packageReleaseSource.Contains("Reset-ManagedDirectory $RuntimeOutput", StringComparison.Ordinal),
    "release packaging freezes source before pinned staged builds and validates rollback-capable candidates");
Assert(
    task15ReleaseClosurePaths.Length == 9 &&
    task15ReleaseClosurePaths.Distinct(StringComparer.Ordinal).Count() == 9 &&
    packageFormalSourceClosure.Length > 0 &&
    task15ReleaseClosurePaths.All(relativePath =>
        durableReleaseExchangeFunction.Split(
            "(Join-Path $SourceOutput '" + relativePath + "')",
            StringSplitOptions.None).Length - 1 == 1 &&
        internalTransactionGenerationFunction.Split(
            "'" + relativePath + "'",
            StringSplitOptions.None).Length - 1 == 1 &&
        packageFormalSourceClosure.Split(
            "(Join-Path $SourceStage '" + relativePath + "')",
            StringSplitOptions.None).Length - 1 == 1 &&
        packageReleaseSource.Split(
            relativePath,
            StringSplitOptions.None).Length - 1 == 3),
    "each Task 15 source path occurs once in exchange, fixture, and formal source closure");
Assert(
    task16ReleaseClosurePaths.Length == 5 &&
    task16ReleaseClosurePaths.Distinct(StringComparer.Ordinal).Count() == 5 &&
    packageFormalSourceClosure.Length > 0 &&
    task16ReleaseClosurePaths.All(relativePath =>
        durableReleaseExchangeFunction.Split(
            "(Join-Path $SourceOutput '" + relativePath + "')",
            StringSplitOptions.None).Length - 1 == 1 &&
        internalTransactionGenerationFunction.Split(
            "'" + relativePath + "'",
            StringSplitOptions.None).Length - 1 == 1 &&
        packageFormalSourceClosure.Split(
            "(Join-Path $SourceStage '" + relativePath + "')",
            StringSplitOptions.None).Length - 1 == 1 &&
        packageReleaseSource.Split(
            relativePath,
            StringSplitOptions.None).Length - 1 == 3),
    "each Task 16 source path occurs once in exchange, fixture, and formal source closure");
Assert(
    task17ReleaseClosurePaths.Length == 18 &&
    task17ReleaseClosurePaths.Distinct(StringComparer.Ordinal).Count() == 18 &&
    packageFormalSourceClosure.Length > 0 &&
    task17ReleaseClosurePaths.All(relativePath =>
        durableReleaseExchangeFunction.Split(
            "(Join-Path $SourceOutput '" + relativePath + "')",
            StringSplitOptions.None).Length - 1 == 1 &&
        internalTransactionGenerationFunction.Split(
            "'" + relativePath + "'",
            StringSplitOptions.None).Length - 1 == 1 &&
        packageFormalSourceClosure.Split(
            "(Join-Path $SourceStage '" + relativePath + "')",
            StringSplitOptions.None).Length - 1 == 1 &&
        packageReleaseSource.Split(
            "'" + relativePath + "'",
            StringSplitOptions.None).Length - 1 == 3),
    "each Task 17 source path occurs once in exchange, fixture, and formal source closure");
Assert(
    task15GuardianRuntimeRequiredFiles.Length == 8 &&
    task15GuardianRuntimeRequiredFiles.Distinct(StringComparer.Ordinal).Count() == 8 &&
    task15GuardianRuntimeRequiredFiles.All(fileName =>
        internalTransactionGenerationFunction.Contains(
            "'" + fileName + "'",
            StringComparison.Ordinal) &&
        durableReleaseExchangeFunction.Contains(
            "(Join-Path $RuntimeOutput '" + fileName + "')",
            StringComparison.Ordinal) &&
        (string.Equals(fileName, "CodexGuardian.exe", StringComparison.Ordinal)
            ? packageReleaseSource.Contains(
                "$publishedExecutable = Join-Path $RuntimeStage 'CodexGuardian.exe'",
                StringComparison.Ordinal)
            : packageReleaseSource.Contains(
                "(Join-Path $RuntimeStage '" + fileName + "')",
                StringComparison.Ordinal))) &&
    task15BrokerRuntimeRequiredFiles.Length == 8 &&
    task15BrokerRuntimeRequiredFiles.Distinct(StringComparer.Ordinal).Count() == 8 &&
    task15BrokerRuntimeRequiredFiles.All(fileName =>
        internalTransactionGenerationFunction.Contains(
            "'Broker\\" + fileName + "'",
            StringComparison.Ordinal) &&
        durableReleaseExchangeFunction.Contains(
            "(Join-Path $RuntimeOutput 'Broker\\" + fileName + "')",
            StringComparison.Ordinal) &&
        packageReleaseSource.Contains(
            "(Join-Path $BrokerRuntimeStage '" + fileName + "')",
            StringComparison.Ordinal)) &&
    brokerPublishIndex >= 0 &&
    guardianRuntimeConfigDevWriteIndex > brokerPublishIndex &&
    brokerRuntimeConfigDevWriteIndex > guardianRuntimeConfigDevWriteIndex &&
    publishedRuntimeClosureIndex > brokerRuntimeConfigDevWriteIndex &&
    packageReleaseSource.Contains("function Write-CanonicalRuntimeConfigDev {", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("'{\"runtimeOptions\":{}}' + \"`r`n\"", StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "65F2DFF132AEC14731F86C569B5EC96691CACA7D822D02A18B79ACAEB5DC96D7",
        StringComparison.Ordinal),
    "release runtime closure pins Guardian and Broker eight-file identities and canonical dev configs");
Assert(
    string.Equals(
        NormalizeLineEndings(nuGetConfigSource),
        expectedNuGetConfigSource,
        StringComparison.Ordinal) &&
    controlLockDocument is JsonObject exactControlLockObject &&
    exactControlLockObject.Count == 2 &&
    controlLockDocument["version"]?.GetValue<int>() == 1 &&
    controlLockDependencies?.Count == 2 &&
    controlLockFramework?.Count == 1 &&
    controlLockRuntimeFramework?.Count == 1 &&
    controlLockPkcs?.Count == 4 &&
    controlLockRuntimePkcs?.Count == 4,
    "NuGet config and two-target dependency lock are exact");
Assert(
    packageRestoreInputBlocks.Count == 2 &&
    packageReleaseSource.Contains("$NuGetConfigPath = Join-Path $WorkRoot 'NuGet.config'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$ControlLockFilePath = Join-Path $ControlRoot 'packages.lock.json'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$ExpectedNuGetConfigSha256 = '1B7D09F1EFC7B80C109803EB4CF3CA5EAFA6D392D87061F89DD256FECD520362'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$ExpectedControlLockFileSha256 = 'A94F3A16B20FF4CB3B0AE2EE7BBE6301892DE225F921C2309B40FD1EDDDDD6D7'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$sourceStandaloneFiles = @($PSCommandPath, $GlobalJsonPath, $NuGetConfigPath)",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "(Join-Path $SourceStage 'CodexGuardian.Control\\packages.lock.json')",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $SourceStage 'NuGet.config')", StringComparison.Ordinal),
    "release source stages and hash-pins the exact NuGet inputs");
Assert(
    string.Equals(
        NormalizeLineEndings(nuGetConfigSource),
        expectedNuGetConfigSource,
        StringComparison.Ordinal) &&
    controlLockDocument is JsonObject controlLockObject &&
    controlLockObject.Count == 2 &&
    controlLockDocument["version"]?.GetValue<int>() == 1 &&
    controlLockDependencies?.Count == 2 &&
    controlLockFramework?.Count == 1 &&
    controlLockRuntimeFramework?.Count == 1 &&
    controlLockPkcs?.Count == 4 &&
    controlLockRuntimePkcs?.Count == 4 &&
    string.Equals(controlLockPkcs?["type"]?.GetValue<string>(), "Direct", StringComparison.Ordinal) &&
    string.Equals(
        controlLockRuntimePkcs?["type"]?.GetValue<string>(),
        "Direct",
        StringComparison.Ordinal) &&
    string.Equals(
        controlLockPkcs?["requested"]?.GetValue<string>(),
        "[8.0.1, )",
        StringComparison.Ordinal) &&
    string.Equals(controlLockPkcs?["resolved"]?.GetValue<string>(), "8.0.1", StringComparison.Ordinal) &&
    string.Equals(
        controlLockRuntimePkcs?["requested"]?.GetValue<string>(),
        "[8.0.1, )",
        StringComparison.Ordinal) &&
    string.Equals(
        controlLockRuntimePkcs?["resolved"]?.GetValue<string>(),
        "8.0.1",
        StringComparison.Ordinal) &&
    string.Equals(
        controlLockPkcs?["contentHash"]?.GetValue<string>(),
        "CoCRHFym33aUSf/NtWSVSZa99dkd0Hm7OCZUxORBjRB16LNhIEOf8THPqzIYlvKM0nNDAPTRBa1FxEECrgaxxA==",
        StringComparison.Ordinal) &&
    string.Equals(
        controlLockRuntimePkcs?["contentHash"]?.GetValue<string>(),
        "CoCRHFym33aUSf/NtWSVSZa99dkd0Hm7OCZUxORBjRB16LNhIEOf8THPqzIYlvKM0nNDAPTRBa1FxEECrgaxxA==",
        StringComparison.Ordinal) &&
    packageRestoreInputBlocks.Count == 2 &&
    packageReleaseSource.Contains("$NuGetConfigPath = Join-Path $WorkRoot 'NuGet.config'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$ControlLockFilePath = Join-Path $ControlRoot 'packages.lock.json'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$ExpectedNuGetConfigSha256 = '1B7D09F1EFC7B80C109803EB4CF3CA5EAFA6D392D87061F89DD256FECD520362'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$ExpectedControlLockFileSha256 = 'A94F3A16B20FF4CB3B0AE2EE7BBE6301892DE225F921C2309B40FD1EDDDDD6D7'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$sourceStandaloneFiles = @($PSCommandPath, $GlobalJsonPath, $NuGetConfigPath)",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "(Join-Path $SourceStage 'CodexGuardian.Control\\packages.lock.json')",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $SourceStage 'NuGet.config')", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("function Assert-PinnedRestoreInputs {", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("The Control packages.lock.json dependency closure is unexpected.", StringComparison.Ordinal),
    "NuGet restore uses one official mapped source and one exact Control dependency lock");
Assert(
    new[]
    {
        guardianProjectSource,
        controlProjectSource,
        trustProjectSource,
        brokerProjectSource,
    }.All(source =>
        source.Contains(
            "<CodexGuardianTestFriend Condition=\"'$(CodexGuardianTestFriend)' == ''\">false</CodexGuardianTestFriend>",
            StringComparison.Ordinal) &&
        source.Contains(
            "<ItemGroup Condition=\"'$(CodexGuardianTestFriend)' == 'true'\">",
            StringComparison.Ordinal) &&
        source.Contains(
            "<InternalsVisibleTo Include=\"CodexGuardian.Tests\" />",
            StringComparison.Ordinal)) &&
    Regex.Matches(
        testsProjectSource,
        "AdditionalProperties=\"CodexGuardianTestFriend=true\"",
        RegexOptions.CultureInvariant).Count == 4 &&
    new[] { controlProjectSource, trustProjectSource, brokerProjectSource }.All(source =>
        source.Contains(
            "<PropertyGroup Condition=\"'$(CodexGuardianTestFriend)' == 'true'\">",
            StringComparison.Ordinal) &&
        source.Contains(
            "<DefineConstants>$(DefineConstants);CODEXGUARDIAN_TEST_FRIEND</DefineConstants>",
            StringComparison.Ordinal)) &&
    !guardianProjectSource.Contains("CODEXGUARDIAN_TEST_FRIEND", StringComparison.Ordinal),
    "production assemblies expose the Tests friend only in the explicit test project graph");
Assert(
    controlProjectSource.Contains("<TargetFramework>net8.0-windows</TargetFramework>", StringComparison.Ordinal) &&
    controlProjectSource.Contains("<AssemblyName>CodexGuardian.Control</AssemblyName>", StringComparison.Ordinal) &&
    controlProjectSource.Contains("<RootNamespace>CodexGuardian.Control</RootNamespace>", StringComparison.Ordinal) &&
    controlProjectSource.Contains("<InternalsVisibleTo Include=\"CodexGuardian\" />", StringComparison.Ordinal) &&
    controlProjectSource.Contains("<InternalsVisibleTo Include=\"CodexGuardian.Broker\" />", StringComparison.Ordinal) &&
    controlProjectSource.Contains(
        "<ItemGroup Condition=\"'$(CodexGuardianTestFriend)' == 'true'\">",
        StringComparison.Ordinal) &&
    controlProjectSource.Contains(
        "<PackageReference Include=\"System.Security.Cryptography.Pkcs\" Version=\"8.0.1\" />",
        StringComparison.Ordinal) &&
    controlProjectSource.Contains(
        "<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>",
        StringComparison.Ordinal) &&
    controlProjectSource.Contains(
        "<RestoreLockedMode>true</RestoreLockedMode>",
        StringComparison.Ordinal) &&
    !controlProjectSource.Contains("<UseWPF>", StringComparison.Ordinal) &&
    !controlProjectSource.Contains("<UseWindowsForms>", StringComparison.Ordinal) &&
    !controlProjectSource.Contains("<ProjectReference", StringComparison.Ordinal) &&
    controlProtocolSource.Contains("namespace CodexGuardian.Control;", StringComparison.Ordinal) &&
    controlStateMachineSource.Contains("namespace CodexGuardian.Control;", StringComparison.Ordinal) &&
    controlRuntimeOwnershipSource.Contains("interface ICodexCdpHandleLease", StringComparison.Ordinal) &&
    controlRuntimeOwnershipSource.Contains("interface ICodexCdpRuntimeControlHost", StringComparison.Ordinal) &&
    !controlRuntimeOwnershipSource.Contains("ICdpCommandTransport", StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains(
        "sealed class WindowsCodexCdpRuntimeControlHostV1 : ICodexCdpRuntimeControlHost",
        StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains("CodexPackageTrustMode.StoreOnly", StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains("Browser.getVersion", StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains("Target.getTargets", StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains(
        "CdpPipeTerminalFaultMode.BrokerOwnedDrainUntilDispose",
        StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains("VerifyPreLaunch", StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains("VerifyPostLaunch", StringComparison.Ordinal) &&
    brokerRuntimeHostSource.Contains("CaptureStableInventoryAsync", StringComparison.Ordinal) &&
    !brokerRuntimeHostSource.Contains("TerminateProcess", StringComparison.Ordinal) &&
    !brokerRuntimeHostSource.Contains("remote-debugging-port", StringComparison.Ordinal) &&
    !brokerRuntimeHostSource.Contains("UseWPF", StringComparison.Ordinal) &&
    authenticatedPipeConnectionSource.Contains(
        "sealed class AuthenticatedPipePeerConnection : IAsyncDisposable",
        StringComparison.Ordinal) &&
    !authenticatedPipeConnectionSource.Contains("SafePipeHandle", StringComparison.Ordinal) &&
    !authenticatedPipeConnectionSource.Contains(" Stream ", StringComparison.Ordinal) &&
    !controlProtocolSource.Contains("namespace CodexGuardian.Services;", StringComparison.Ordinal) &&
    !controlStateMachineSource.Contains("namespace CodexGuardian.Services;", StringComparison.Ordinal),
    "shared broker control assembly is non-WPF reference-free and owns both control contracts");
Assert(
    packageClosureBlocks.Count == 1 &&
    packageClosureSource.Contains("-Root $SourceStage", StringComparison.Ordinal) &&
    packageClosureSource.Contains("-EntryProjects @($StagedTestsProject)", StringComparison.Ordinal) &&
    packageExpectedProjects.Length == 5 &&
    packageExpectedProjects.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 5 &&
    new HashSet<string>(packageExpectedProjects, StringComparer.OrdinalIgnoreCase)
        .SetEquals(expectedPackageProjects) &&
    packageExpectedEdges.Length == 8 &&
    packageExpectedEdges.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 8 &&
    new HashSet<string>(packageExpectedEdges, StringComparer.OrdinalIgnoreCase)
        .SetEquals(expectedPackageEdges) &&
    packageReleaseSource.Contains("$ControlRoot = Join-Path $WorkRoot 'CodexGuardian.Control'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$TrustRoot = Join-Path $WorkRoot 'CodexGuardian.Trust'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$BrokerProbeRoot = Join-Path $WorkRoot 'CodexGuardian.Broker'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $RuntimeStage 'CodexGuardian.Control.dll')", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $SourceStage 'CodexGuardian.Control\\CodexCdpBrokerProtocol.cs')", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $SourceStage 'CodexGuardian.Control\\CodexCdpBrokerStateMachine.cs')", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $SourceStage 'CodexGuardian.Control\\CodexCdpRuntimeOwnership.cs')", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("(Join-Path $SourceStage 'CodexGuardian.Trust\\AuthenticatedPipePeerConnection.cs')", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$SourceBuildResiduePaths = @($SourceProjectRoots", StringComparison.Ordinal) &&
    closureFunction.Contains("Get-ChildItem -LiteralPath $fullRoot -Recurse -Force -Filter '*.csproj'", StringComparison.Ordinal) &&
    closureFunction.Contains("$expected.SetEquals($stagedProjects)", StringComparison.Ordinal) &&
    closureFunction.Contains("$expected.SetEquals($visitedRelative)", StringComparison.Ordinal) &&
    closureFunction.Contains("$expectedEdgeSet.SetEquals($visitedEdges)", StringComparison.Ordinal) &&
    closureFunction.Contains("A staged ProjectReference is not statically resolvable", StringComparison.Ordinal) &&
    closureFunction.Contains("A Tests ProjectReference has noncanonical friend metadata", StringComparison.Ordinal) &&
    closureFunction.Contains("duplicate ProjectReference edge", StringComparison.Ordinal) &&
    projectConditionFunction.Contains("$conditionAttributes.Count -ne $expectedConditionCount", StringComparison.Ordinal) &&
    projectConditionFunction.Contains("noncanonical DefineConstants value", StringComparison.Ordinal),
    "release source stage contains the exact Guardian Tests Control Trust and Broker project closure");
Assert(
    packageCurrentHostGateIndex >= 0 &&
    packageCurrentHostFailureIndex > packageCurrentHostGateIndex &&
    packageFirstEnvironmentMutationIndex > packageCurrentHostFailureIndex &&
    packageInternalHarnessDispatch.HasValue &&
    packageInternalHarnessDispatch.Value.HeaderIndex > packageCurrentHostFailureIndex &&
    packageBootstrapUnavailableIndex > packageInternalHarnessDispatch.Value.CloseBraceIndex &&
    packageMainMarkerIndex > packageBootstrapUnavailableIndex &&
    packageFirstWorkspaceWriteIndex > packageBootstrapUnavailableIndex &&
    normalizedPackageReleaseSource.Contains(
        "package validation and formal exchange remain disabled",
        StringComparison.Ordinal) &&
    pinnedDotnetResolverFunction.Contains("Get-PinnedDotnetFilePlan", StringComparison.Ordinal) &&
    !pinnedDotnetResolverFunction.Contains("Get-Command dotnet", StringComparison.OrdinalIgnoreCase) &&
    pinnedDotnetPlanFunction.Contains("$ExpectedDotnetExecutableSha256", StringComparison.Ordinal) &&
    pinnedDotnetPlanFunction.Contains("$ExpectedDotnetExecutableLength", StringComparison.Ordinal) &&
    pinnedDotnetPlanFunction.Contains("$ExpectedDotnetSdkArtifacts.Keys", StringComparison.Ordinal) &&
    pinnedDotnetPlanFunction.Contains("$ExpectedDotnetSdkArtifactLengths", StringComparison.Ordinal) &&
    pinnedLeaseHashFunction.Contains("$position = $Stream.Position", StringComparison.Ordinal) &&
    pinnedLeaseHashFunction.Contains("$Stream.Position = $position", StringComparison.Ordinal) &&
    pinnedDotnetOpenFunction.Contains("[System.IO.FileMode]::Open", StringComparison.Ordinal) &&
    pinnedDotnetOpenFunction.Contains("[System.IO.FileAccess]::Read", StringComparison.Ordinal) &&
    pinnedDotnetOpenFunction.Contains("[System.IO.FileShare]::Read", StringComparison.Ordinal) &&
    pinnedDotnetOpenFunction.Contains("Get-AuthenticodeSignature", StringComparison.Ordinal) &&
    pinnedDotnetOpenFunction.Contains("Get-PinnedLeaseStreamSha256", StringComparison.Ordinal) &&
    pinnedDotnetOpenFunction.Contains("for ($index = $leases.Count - 1; $index -ge 0; $index--)", StringComparison.Ordinal) &&
    pinnedDotnetAssertFunction.Contains("$leases.Count -ne $plan.Count", StringComparison.Ordinal) &&
    pinnedDotnetAssertFunction.Contains("$item.LastWriteTimeUtc.Ticks", StringComparison.Ordinal) &&
    pinnedDotnetAssertFunction.Contains("Get-PinnedLeaseStreamSha256 -Stream $actual.Lease", StringComparison.Ordinal) &&
    pinnedDotnetCloseFunction.Contains("for ($index = $artifacts.Count - 1; $index -ge 0; $index--)", StringComparison.Ordinal) &&
    hermeticEnvironmentKeys.Length == expectedHermeticEnvironmentKeys.Count &&
    hermeticEnvironmentKeys.Distinct(StringComparer.OrdinalIgnoreCase).Count() ==
        expectedHermeticEnvironmentKeys.Count &&
    new HashSet<string>(hermeticEnvironmentKeys, StringComparer.OrdinalIgnoreCase)
        .SetEquals(expectedHermeticEnvironmentKeys) &&
    hermeticDotnetEnvironmentFunction.Contains(
        "CODEX_GUARDIAN_TEST_DATA_ROOT = $TestDataRoot",
        StringComparison.Ordinal) &&
    hermeticDotnetEnvironmentFunction.Contains("HOMEPATH = $ToolUserProfile.Substring(2)", StringComparison.Ordinal) &&
    hermeticDotnetEnvironmentFunction.Contains("NUMBER_OF_PROCESSORS = [string][Environment]::ProcessorCount", StringComparison.Ordinal) &&
    releaseDotnetEnvironmentFunction.Contains("COR_|CORECLR_|COMPlus_", StringComparison.Ordinal) &&
    releaseDotnetEnvironmentFunction.Contains("$required = [ordered]@{", StringComparison.Ordinal) &&
    releaseDotnetEnvironmentFunction.Contains(
        "CODEX_GUARDIAN_TEST_DATA_ROOT = $TestDataRoot",
        StringComparison.Ordinal) &&
    releaseDotnetEnvironmentFunction.Contains("[Environment]::GetEnvironmentVariable", StringComparison.Ordinal),
    "release packaging pins one leased dotnet authority and rebuilds an exact child environment");
Assert(
    pinnedUnifiedProcessCalls.Count == 1 &&
    nativeUnifiedProcessCalls.Count == 1 &&
    boundedLeaseChecks.Count == 2 &&
    boundedLowLevelRun >= 0 &&
    boundedReleaseProcessFunction.IndexOf("Assert-ReleaseDotnetEnvironment", StringComparison.Ordinal) <
        boundedLeaseChecks[0].Index &&
    boundedLeaseChecks[0].Index <
        boundedReleaseProcessFunction.IndexOf("Initialize-ReleaseProcessMethods", StringComparison.Ordinal) &&
    boundedReleaseProcessFunction.IndexOf("Initialize-ReleaseProcessMethods", StringComparison.Ordinal) <
        boundedLowLevelRun &&
    boundedLowLevelRun < boundedLeaseChecks[1].Index &&
    boundedReleaseProcessFunction.Contains("$result.CleanupIncomplete", StringComparison.Ordinal) &&
    boundedReleaseProcessFunction.Contains("$result.ResidualBeforeCleanup -ne 0", StringComparison.Ordinal) &&
    boundedReleaseProcessFunction.Contains("$result.ResidualProcessCount -ne 0", StringComparison.Ordinal) &&
    releaseProcessShapeFunction.Contains("ReleaseProcessMethodsV2", StringComparison.Ordinal) &&
    releaseProcessShapeFunction.Contains("The bounded release process result fields changed", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains(
        "A bounded release process helper type existed before this script initialized it.",
        StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("ReleaseSafeJobHandle", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("ReleaseSafeKernelHandle", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("CreateSuspended |", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("CreateUnicodeEnvironment |", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("ProcThreadAttributeHandleList", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("Interlocked.Add(ref state.TotalBytes, read)", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("public int ForcedDrain;", StringComparison.Ordinal) &&
    !releaseProcessInitializerFunction.Contains("CleanupStarted", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("catch (OperationCanceledException exception)", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("Volatile.Read(ref state.ForcedDrain) == 0 ||", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("cancellationToken.IsCancellationRequested", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("catch (ObjectDisposedException exception)", StringComparison.Ordinal) &&
    !releaseProcessInitializerFunction.Contains("catch (OperationCanceledException) when (", StringComparison.Ordinal) &&
    !releaseProcessInitializerFunction.Contains("catch (ObjectDisposedException) when (", StringComparison.Ordinal) &&
    releaseProcessEnvironmentBlock >= 0 &&
    releaseProcessEnvironmentBlock < releaseProcessCreate &&
    releaseProcessCreate < releaseProcessAssign &&
    releaseProcessAssign < releaseProcessDrainStart &&
    releaseProcessDrainStart < releaseProcessResume &&
    releaseProcessResidualBefore >= 0 &&
    releaseProcessResidualBefore < releaseProcessTerminate &&
    releaseProcessTerminate < releaseProcessResidualAfter &&
    releaseProcessResidualAfter < releaseProcessDrainWait &&
    releaseProcessDrainWait < releaseProcessForcedDrain &&
    releaseProcessForcedDrain < releaseProcessForcedDrainCancel &&
    releaseProcessInitializerFunction.Contains("drainIncomplete = forcedDrain ||", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("byte[] stdoutBytes = !drainIncomplete", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("byte[] stderrBytes = !drainIncomplete", StringComparison.Ordinal) &&
    releaseProcessInitializerFunction.Contains("DrainIncomplete = drainIncomplete", StringComparison.Ordinal) &&
    !releaseProcessInitializerFunction.Contains("ProcessStartInfo", StringComparison.Ordinal) &&
    !releaseProcessInitializerFunction.Contains("process.Start()", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("& $DotnetExecutable", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("Start-Process", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("WaitForExitAsync", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("ProcessStartInfo.ArgumentList", StringComparison.Ordinal) &&
    !Regex.IsMatch(packageReleaseSource, @"\.WaitForExit\(\s*\)"),
    "release dotnet commands use one suspended Job-owned process boundary with bounded total output and cleanup proof");
Assert(
    packageNativeUserPresenceCapabilityGate > packageSafeDrill &&
    packageNativePeerGate > packageNativeUserPresenceCapabilityGate &&
    packageConnectedClientGate > packageNativePeerGate &&
    packagePublish > packageConnectedClientGate &&
    packageNativeGateBlocks.Count == 3 &&
    packageNativeGateBlocks.Single(block => block.Index == packageNativeUserPresenceCapabilityGate).Text.Contains(
        "-TimeoutSeconds $NativeUserPresenceCapabilityProbeTimeoutSeconds",
        StringComparison.Ordinal) &&
    packageNativeGateBlocks.Single(block => block.Index == packageNativeUserPresenceCapabilityGate).Text.Contains(
        "-SuccessMarker $NativeUserPresenceCapabilityProbeMarker",
        StringComparison.Ordinal) &&
    packageNativeGateBlocks.Single(block => block.Index == packageNativeUserPresenceCapabilityGate).Text.Contains(
        "'--native-user-presence-evidence-root', $NativeUserPresenceEvidenceRoot",
        StringComparison.Ordinal) &&
    packageNativeGateBlocks.Single(block => block.Index == packageNativePeerGate).Text.Contains(
        "-TimeoutSeconds $NativePeerProbeTimeoutSeconds",
        StringComparison.Ordinal) &&
    packageNativeGateBlocks.Single(block => block.Index == packageNativePeerGate).Text.Contains(
        "-SuccessMarker $NativePeerProbeMarker",
        StringComparison.Ordinal) &&
    packageNativeGateBlocks.Single(block => block.Index == packageConnectedClientGate).Text.Contains(
        "-TimeoutSeconds $ConnectedClientProbeTimeoutSeconds",
        StringComparison.Ordinal) &&
    packageNativeGateBlocks.Single(block => block.Index == packageConnectedClientGate).Text.Contains(
        "-SuccessMarker $ConnectedClientProbeMarker",
        StringComparison.Ordinal) &&
    packageReleaseSource.Split(
        "--native-user-presence-capability-probe",
        StringSplitOptions.None).Length - 1 == 1 &&
    !packageReleaseSource.Contains(
        "--native-user-presence-interactive-probe",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$NativeUserPresenceCapabilityProbeMarker = 'NATIVE_USER_PRESENCE_CAPABILITY_PROBE_COMPLETE'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$NativeUserPresenceCapabilityProbeTimeoutSeconds = 60",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$NativeUserPresenceEvidenceRoot = Join-Path $TestDataRoot 'native-user-presence-evidence'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "throw 'The native user-presence evidence root must not preexist the capability probe.'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "throw 'The native user-presence evidence root must be empty before the capability probe.'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains("--native-peer-child-probe", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("--native-connected-client-probe", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$NativePeerProbeMarker = 'NATIVE_PEER_PROBE_COMPLETE'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$NativePeerProbeTimeoutSeconds = 120", StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "$ConnectedClientProbeMarker = 'NATIVE_CONNECTED_CLIENT_PROBE_COMPLETE'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$ConnectedClientProbeTimeoutSeconds = 120", StringComparison.Ordinal) &&
    boundedGateFunction.IndexOf("$preexistingArtifactProcesses = @(", StringComparison.Ordinal) >= 0 &&
    boundedGateFunction.IndexOf("$preexistingArtifactProcesses = @(", StringComparison.Ordinal) <
        nativeUnifiedProcessCalls[0].Index &&
    nativeUnifiedProcessCalls[0].Index <
        boundedGateFunction.IndexOf("$escapedArtifactCount = Stop-BoundedGateArtifactProcesses", StringComparison.Ordinal) &&
    boundedGateFunction.IndexOf("$escapedArtifactCount = Stop-BoundedGateArtifactProcesses", StringComparison.Ordinal) <
        boundedGateFunction.IndexOf("$markerCount = Get-ExactMarkerCount", StringComparison.Ordinal) &&
    boundedGateFunction.Contains("$markerCount -ne 1 -or $stderr.Length -ne 0", StringComparison.Ordinal) &&
    boundedGateFunction.Contains("stderrLength=$($stderrBytes.Length) stderrSha256=$stderrSha256", StringComparison.Ordinal) &&
    boundedGateFunction.Contains("[void](Stop-BoundedGateArtifactProcesses", StringComparison.Ordinal) &&
    boundedCimFunction.Contains("-OperationTimeoutSec $operationTimeoutSeconds", StringComparison.Ordinal) &&
    boundedCimFunction.Contains("-ErrorAction Stop", StringComparison.Ordinal) &&
    boundedMarkerFunction.Contains("[System.IO.StringReader]::new($Text)", StringComparison.Ordinal) &&
    !boundedMarkerFunction.Contains("Regex]::Split", StringComparison.Ordinal) &&
    boundedArtifactQueryFunction.Contains("CodexGuardian.Tests.exe", StringComparison.Ordinal) &&
    boundedArtifactQueryFunction.Contains("CodexGuardian.Broker.exe", StringComparison.Ordinal) &&
    boundedArtifactCleanupFunction.Contains("-ExpectedStartTimeUtcTicks $actualStartTimeUtc.Ticks", StringComparison.Ordinal) &&
    boundedStopFunction.Contains("[Parameter(Mandatory = $true)][long]$ExpectedStartTimeUtcTicks", StringComparison.Ordinal) &&
    boundedStopFunction.Contains("$Process.Kill()", StringComparison.Ordinal) &&
    boundedStopFunction.Contains("$Process.WaitForExit($remaining)", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("Get-BoundedGateFileLength", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("Read-BoundedGateUtf8Text", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("Get-BoundedGateStderrTail", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("taskkill", StringComparison.OrdinalIgnoreCase),
    "release packaging runs two marker-exact stderr-clean native gates with exact-handle residual cleanup");
Assert(
    outputPathFunction.Contains("$rootPrefix = $fullRoot + '\\'", StringComparison.Ordinal) &&
    outputPathFunction.Contains("$fullPath.StartsWith($rootPrefix", StringComparison.Ordinal) &&
    outputPathFunction.Contains("Assert-NoReparseTraversal $fullPath", StringComparison.Ordinal) &&
    manifestFileFunction.Contains("[System.IO.File]::Open(", StringComparison.Ordinal) &&
    manifestFileFunction.Contains("$sha256.ComputeHash($stream)", StringComparison.Ordinal) &&
    manifestFileFunction.Contains("$stream.Position -ne $length", StringComparison.Ordinal) &&
    manifestEqualityFunction.Contains("$expectedEntries.Count -ne $actualEntries.Count", StringComparison.Ordinal) &&
    manifestEqualityFunction.Contains("[string]$actualEntry.Path", StringComparison.Ordinal) &&
    manifestEqualityFunction.Contains("[long]$actualEntry.Length", StringComparison.Ordinal) &&
    manifestEqualityFunction.Contains("[string]$actualEntry.Sha256", StringComparison.Ordinal) &&
    archiveManifestFunction.Contains("[System.StringComparer]::Ordinal)", StringComparison.Ordinal) &&
    archiveManifestFunction.Contains("$rawName.Contains('\\')", StringComparison.Ordinal) &&
    !archiveManifestFunction.Contains(".Replace('\\', '/')", StringComparison.Ordinal) &&
    archiveManifestFunction.Contains("$archiveEntry.Open()", StringComparison.Ordinal) &&
    archiveParityFunction.Contains("Get-ArchiveContentManifest", StringComparison.Ordinal) &&
    archiveParityFunction.Contains("Assert-ContentManifestsEqual", StringComparison.Ordinal),
    "release output path and manifest primitives are reparse closed and ordinal exact");
Assert(
    packageOutputAssignmentsExact &&
    packageReleaseArtifactIds.SequenceEqual(expectedReleaseArtifactIds, StringComparer.Ordinal) &&
    newOutputDirectoryFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) >= 0 &&
    newOutputDirectoryFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) <
        newOutputDirectoryFunction.IndexOf("New-Item", StringComparison.Ordinal) &&
    copyOutputTreeFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) >= 0 &&
    copyOutputTreeFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) <
        copyOutputTreeFunction.IndexOf("Copy-Item", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("Compress-Archive", StringComparison.Ordinal) &&
    compressOutputFunction.Contains("Compress-CanonicalArchive", StringComparison.Ordinal) &&
    compressOutputFunction.Contains("-ExpectedManifest $ExpectedManifest", StringComparison.Ordinal) &&
    compressOutputFunction.Contains("-DestinationScope output", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("[ValidateSet('scratch', 'output')]", StringComparison.Ordinal) &&
    canonicalArchiveFunction.IndexOf("Assert-NoReparsePointsInTree -Path $Source", StringComparison.Ordinal) >= 0 &&
    canonicalArchiveFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) >= 0 &&
    canonicalArchiveFunction.IndexOf("Assert-ScratchPath $Destination", StringComparison.Ordinal) >= 0 &&
    canonicalArchiveFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) <
        canonicalArchiveFunction.IndexOf("[System.IO.FileStream]::new(", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("Add-Type -AssemblyName System.IO.Compression", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("Add-Type -AssemblyName System.IO.Compression.FileSystem", StringComparison.Ordinal) &&
    canonicalArchiveFunction.IndexOf("Add-Type -AssemblyName System.IO.Compression", StringComparison.Ordinal) <
        canonicalArchiveFunction.IndexOf("Add-Type -AssemblyName System.IO.Compression.FileSystem", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("Get-OrdinalContentManifest", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("-Entries $ExpectedManifest", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("[System.IO.FileMode]::CreateNew", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("[System.IO.FileShare]::None", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("[System.IO.FileOptions]::WriteThrough", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("[System.IO.Compression.ZipArchiveMode]::Create", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("$entryPath = Assert-CanonicalContentPath", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("$archive.CreateEntry(", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("$entryPath,", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("[System.IO.Compression.CompressionLevel]::Optimal", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("$zipEntry.LastWriteTime = [DateTimeOffset]::new(", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("[TimeSpan]::Zero", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains("$sourceStream.CopyTo($zipStream, 65536)", StringComparison.Ordinal) &&
    canonicalArchiveFunction.IndexOf("$archive.Dispose()", StringComparison.Ordinal) >= 0 &&
    canonicalArchiveFunction.IndexOf("$archive.Dispose()", StringComparison.Ordinal) <
        canonicalArchiveFunction.IndexOf("$archiveStream.Flush($true)", StringComparison.Ordinal) &&
    canonicalArchiveFunction.Contains(
        "if (!$completed -and (Test-Path -LiteralPath $fullDestination))",
        StringComparison.Ordinal) &&
    writeOutputFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) >= 0 &&
    writeOutputFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) <
        writeOutputFunction.IndexOf("WriteAllLines", StringComparison.Ordinal) &&
    moveOutputSourceGuard >= 0 &&
    moveOutputDestinationGuard > moveOutputSourceGuard &&
    moveOutputNativeCall > moveOutputDestinationGuard &&
    moveOutputFunction.Contains("$managedSource,", StringComparison.Ordinal) &&
    moveOutputFunction.Contains("$managedDestination,", StringComparison.Ordinal) &&
    moveOutputFunction.Contains("$moveFlags = [uint32]8", StringComparison.Ordinal) &&
    moveOutputFunction.Contains("-bor [uint32]1", StringComparison.Ordinal) &&
    !Regex.IsMatch(moveOutputFunction, @"(?im)^[ \t]*(?:Move-Item|Rename-Item|Copy-Item|Remove-Item)\b") &&
    !moveOutputFunction.Contains("[System.IO.File]::Move", StringComparison.Ordinal) &&
    !moveOutputFunction.Contains("[System.IO.Directory]::Move", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("function Assert-NoPathOverlap", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("function Assert-NoReparsePointsInTree", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("'/XJ'", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("$ProtectedR13EvidenceRoot", StringComparison.Ordinal) &&
    runtimeTestPayloadPathFunction.Contains(
        "StartsWith('CodexGuardian.Tests', [System.StringComparison]::OrdinalIgnoreCase)",
        StringComparison.Ordinal) &&
    noRuntimeTestPayloadFunction.Contains(
        "Test-IsRuntimeTestPayloadPath (Get-ReleaseRelativePath -Root $fullRoot -Path $_.FullName)",
        StringComparison.Ordinal) &&
    noRuntimeTestArchiveEntriesFunction.Contains(
        "Test-IsRuntimeTestPayloadPath $_.FullName",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "Assert-NoRuntimeTestPayload -Root $RuntimeStage -Label 'Staged runtime package'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "Assert-NoRuntimeTestPayload -Root $RuntimeNext -Label 'Next runtime package'",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "Assert-NoRuntimeTestPayload -Root $RuntimeOutput -Label 'Exchanged runtime package'",
        StringComparison.Ordinal),
    "release formal output helpers preflight paths and retain runtime test-payload exclusion anchors");
Assert(
    syncArtifactFunction.IndexOf("$managedPath = Assert-OutputPath $Path", StringComparison.Ordinal) >= 0 &&
    syncArtifactFunction.Contains("Assert-NoReparsePointsInTree -Path $managedPath", StringComparison.Ordinal) &&
    syncArtifactFunction.Contains("[System.IO.FileMode]::Open", StringComparison.Ordinal) &&
    syncArtifactFunction.Contains("[System.IO.FileAccess]::Write", StringComparison.Ordinal) &&
    syncArtifactFunction.Contains("[System.IO.FileShare]::Read", StringComparison.Ordinal) &&
    syncArtifactFunction.Contains("[System.IO.FileOptions]::WriteThrough", StringComparison.Ordinal) &&
    syncArtifactFunction.Contains("$stream.Flush($true)", StringComparison.Ordinal) &&
    syncArtifactFunction.Contains("$Label after durable barrier", StringComparison.Ordinal),
    "release candidate durability barrier flushes every managed payload before journaling");
Assert(
    packageReleaseSource.Split(
        "$GuardianReleaseMutexName = 'Local\\CodexGuardian.ReleaseExchange'",
        StringSplitOptions.None).Length - 1 == 1 &&
    enterGuardianReleaseLeaseFunction.Contains(
        "[System.Threading.Mutex]::new($false, $GuardianReleaseMutexName)",
        StringComparison.Ordinal) &&
    enterGuardianReleaseLeaseFunction.Contains("$mutex.WaitOne(0)", StringComparison.Ordinal) &&
    enterGuardianReleaseLeaseFunction.Contains(
        "catch [System.Threading.AbandonedMutexException]",
        StringComparison.Ordinal) &&
    enterGuardianReleaseLeaseFunction.Contains("$acquired = $true", StringComparison.Ordinal) &&
    enterGuardianReleaseLeaseFunction.Contains("$mutex.Dispose()", StringComparison.Ordinal) &&
    enterGuardianReleaseLeaseFunction.Contains("return $mutex", StringComparison.Ordinal) &&
    !enterGuardianReleaseLeaseFunction.Contains("$mutex.WaitOne()", StringComparison.Ordinal) &&
    exitGuardianReleaseLeaseFunction.IndexOf("$Mutex.ReleaseMutex()", StringComparison.Ordinal) >= 0 &&
    exitGuardianReleaseLeaseFunction.IndexOf("$Mutex.Dispose()", StringComparison.Ordinal) >
        exitGuardianReleaseLeaseFunction.IndexOf("$Mutex.ReleaseMutex()", StringComparison.Ordinal),
    "release package owns and deterministically releases the shared Guardian lifetime mutex");
Assert(
    string.Equals(
        compiledReleaseMutexName,
        "Local\\CodexGuardian.ReleaseExchange",
        StringComparison.Ordinal) &&
    normalizedAppComposition.Split(
        "private const string ReleaseExchangeMutexName = \"Local\\\\CodexGuardian.ReleaseExchange\";",
        StringSplitOptions.None).Length - 1 == 1 &&
    normalizedAppComposition.Split(
        "private const string SingleInstanceMutexName = \"Local\\\\CodexGuardian.SingleInstance\";",
        StringSplitOptions.None).Length - 1 == 1 &&
    appStartupSource.Length > 0 &&
    appFinishExitSource.Length > 0 &&
    appExitSource.Length > 0 &&
    appLaunchOptionsParse >= 0 &&
    appSingleInstanceAcquire > appLaunchOptionsParse &&
    appSingleInstanceMutexResolve > appSingleInstanceAcquire &&
    appSingleInstanceReject > appSingleInstanceMutexResolve &&
    appReleaseMutexCreate > appSingleInstanceReject &&
    appReleaseMutexResolve > appReleaseMutexCreate &&
    appReleaseMutexWait > appReleaseMutexResolve &&
    appReleaseMutexAbandoned > appReleaseMutexWait &&
    appReleaseMutexAbandonedOwnership > appReleaseMutexAbandoned &&
    appReleaseMutexAbandonedOwnership < appReleaseMutexReject &&
    appReleaseMutexReject > appReleaseMutexAbandoned &&
    appReleaseMutexRejectSource.Contains("_releaseExchange.Dispose();", StringComparison.Ordinal) &&
    appReleaseMutexRejectSource.Contains("_releaseExchange = null;", StringComparison.Ordinal) &&
    appReleaseMutexRejectSource.Contains(
        "return new StartupOutcome(ExitCode: 0, Notice: null);",
        StringComparison.Ordinal) &&
    !appReleaseMutexRejectSource.Contains("Shutdown(", StringComparison.Ordinal) &&
    !appReleaseMutexRejectSource.Contains("MessageBox.Show", StringComparison.Ordinal) &&
    appSettingsInitialization > appReleaseMutexRejectEnd &&
    appLogInitialization > appSettingsInitialization &&
    appLiveIntegrationGate > appLogInitialization &&
    appRecoveryJournalRead > appLiveIntegrationGate &&
    appFollowUpJournalRead > appRecoveryJournalRead &&
    appObservationStart > appFollowUpJournalRead &&
    appHookStart > appObservationStart &&
    appPreviewFixtureLoad > appHookStart &&
    appInitialize > appPreviewFixtureLoad &&
    appWindowCreate > appInitialize &&
    appMainWindowPublication > appWindowCreate &&
    appWindowActivation > appMainWindowPublication &&
    appStartupPublished > appWindowActivation &&
    appGateAfterPublication == -1 &&
    appWindowCleanup >= 0 &&
    appViewModelCleanup > appWindowCleanup &&
    appInteractionHookCleanup > appViewModelCleanup &&
    appObservationCleanup > appInteractionHookCleanup &&
    appBrokerCleanup > appObservationCleanup &&
    appLogCleanup > appBrokerCleanup &&
    appReleaseOwnershipGuard > appLogCleanup &&
    appReleaseMutexRelease > appReleaseOwnershipGuard &&
    appReleaseMutexDispose > appReleaseMutexRelease &&
    appSingleInstanceRelease > appReleaseMutexDispose &&
    !appFinishExitSource.Contains("_releaseExchange", StringComparison.Ordinal) &&
    !appFinishExitSource.Contains("_singleInstance", StringComparison.Ordinal) &&
    appExitSource.Split(
        "_releaseExchange?.ReleaseMutex();",
        StringSplitOptions.None).Length - 1 == 1,
    "Guardian preserves production startup mutexes, isolates safe previews, and fails before side effects");
Assert(
    releaseNativeMethodsShapeFunction.Contains("BindingFlags]::DeclaredOnly", StringComparison.Ordinal) &&
    releaseNativeMethodsShapeFunction.Contains("System.String|System.String|System.UInt32", StringComparison.Ordinal) &&
    releaseNativeMethodsShapeFunction.Contains("DllImportAttribute", StringComparison.Ordinal) &&
    releaseNativeMethodsShapeFunction.Contains("MarshalAsAttribute", StringComparison.Ordinal) &&
    releaseNativeMethodsShapeFunction.Contains("MoveFileExW", StringComparison.Ordinal) &&
    releaseNativeMethodsFunction.Contains("$script:ReleaseNativeMethodsInitialized -eq $true", StringComparison.Ordinal) &&
    releaseNativeMethodsFunction.Contains("Assert-ReleaseNativeMethodsShape", StringComparison.Ordinal) &&
    releaseNativeMethodsFunction.Contains("ReleaseNativeMethodsV2", StringComparison.Ordinal) &&
    releaseNativeMethodsFunction.Contains(
        "A release native helper type existed before this script initialized it.",
        StringComparison.Ordinal) &&
    releaseNativeMethodsFunction.Contains("MoveFileExW", StringComparison.Ordinal) &&
    releaseNativeMethodsFunction.Contains("SetLastError = true", StringComparison.Ordinal) &&
    durableWriteFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) >= 0 &&
    durableWriteFunction.IndexOf("Assert-OutputPath $Destination", StringComparison.Ordinal) <
        durableWriteFunction.IndexOf("[System.IO.FileStream]::new(", StringComparison.Ordinal) &&
    durableWriteFunction.Contains("[System.IO.FileOptions]::WriteThrough", StringComparison.Ordinal) &&
    durableWriteFunction.Contains("$stream.Flush($true)", StringComparison.Ordinal) &&
    durableWriteFunction.Contains("$bytes.Length -gt 65536", StringComparison.Ordinal) &&
    durableWriteFunction.Contains("[System.Text.UTF8Encoding]::new($false, $true)", StringComparison.Ordinal) &&
    durableWriteFunction.Contains("Move-ManagedArtifact", StringComparison.Ordinal) &&
    durableWriteFunction.Contains("[AllowNull()][scriptblock]$FaultCallback", StringComparison.Ordinal) &&
    durableWriteFunction.Contains("[AllowNull()][string]$FaultScope", StringComparison.Ordinal) &&
    durableTempFaultCallback >= 0 &&
    durableStateMove > durableTempFaultCallback &&
    durablePublishedFaultCallback > durableStateMove &&
    strictJsonFunction.Contains("$item.Length -gt 65536", StringComparison.Ordinal) &&
    strictJsonFunction.Contains("$bytes[0] -eq 0xEF", StringComparison.Ordinal) &&
    strictJsonFunction.Contains("[System.Text.UTF8Encoding]::new($false, $true)", StringComparison.Ordinal) &&
    strictJsonFunction.Contains("ConvertFrom-Json -ErrorAction Stop", StringComparison.Ordinal) &&
    strictCommitFunction.Contains("$raw.Text, $canonicalText", StringComparison.Ordinal) &&
    strictJournalFunction.Contains("$raw.Text, $canonicalText", StringComparison.Ordinal) &&
    canonicalCommitFunction.Contains("CODEXGUARDIAN_RELEASE_COMMIT_V1", StringComparison.Ordinal) &&
    canonicalCommitFunction.Contains("@('marker', 'schemaVersion', 'generationId', 'transactionId', 'committedUtc', 'projectVersion', 'artifacts')", StringComparison.Ordinal) &&
    canonicalJournalFunction.Contains("CODEXGUARDIAN_RELEASE_TRANSACTION_V1", StringComparison.Ordinal) &&
    canonicalJournalFunction.Contains("rollback-before-commit", StringComparison.Ordinal) &&
    canonicalJournalFunction.Contains("@('id', 'kind', 'hadCurrent', 'old', 'new')", StringComparison.Ordinal) &&
    manifestIdentityFunction.Contains("HostToNetworkOrder", StringComparison.Ordinal) &&
    manifestIdentityFunction.Contains("Convert-HexStringToBytes", StringComparison.Ordinal) &&
    manifestIdentityFunction.Contains("Get-ReleaseBytesSha256", StringComparison.Ordinal) &&
    !newJournalFunction.Contains(".Current", StringComparison.Ordinal) &&
    !newJournalFunction.Contains(".Next", StringComparison.Ordinal) &&
    !newJournalFunction.Contains(".Previous", StringComparison.Ordinal) &&
    pendingStateFunction.Contains("discard", StringComparison.Ordinal) &&
    discardMoveFunction.Contains("Move-ManagedArtifact -Source $Source -Destination $Discard", StringComparison.Ordinal),
    "release transaction state is canonical bounded write through and path non-authoritative");
Assert(
    transactionFaultCallbackFunction.Contains("[AllowNull()][scriptblock]$Callback", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("$null -eq $Callback", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("$Point.Length -gt 128", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("pending-commit|journal", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("commit\\.published", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("promotion\\.[0-4]", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("[AllowNull()][object]$ArtifactId", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("$ArtifactId -isnot [string]", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("$ArtifactIndex -gt 4", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("point = $Point", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("transactionId = $TransactionId", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains(
        "artifactId = if ($isPromotion) { [string]$ArtifactId } else { $null }",
        StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains(
        "artifactIndex = if ($isPromotion) { $ArtifactIndex } else { -1 }",
        StringComparison.Ordinal) &&
    !transactionFaultCallbackFunction.Contains("[AllowNull()][string]$ArtifactId", StringComparison.Ordinal) &&
    transactionFaultCallbackFunction.Contains("$null = & $Callback $context", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("CODEXGUARDIAN_RELEASE_TRANSACTION_FAULT", StringComparison.OrdinalIgnoreCase) &&
    !packageReleaseSource.Contains("RELEASE_TRANSACTION_FAULT_POINT", StringComparison.OrdinalIgnoreCase),
    "release fault callback is bounded content-free and cannot be enabled through the environment");
Assert(
    packageReleaseSource.Contains("[Parameter(DontShow = $true)]", StringComparison.Ordinal) &&
    packageReleaseSource.Split(
        "[string]$InternalReleaseTransactionRequestPath",
        StringSplitOptions.None).Length - 1 == 1 &&
    packageInternalHarnessDispatch.HasValue &&
    packageInternalHarnessDispatch.Value.ParentDepth == 0 &&
    packageInternalHarnessDispatch.Value.HeaderIndex < packageMainMarkerIndex &&
    packageInternalHarnessDispatch.Value.Text.Contains(
        "Invoke-InternalReleaseTransactionHarness",
        StringComparison.Ordinal) &&
    packageInternalHarnessDispatch.Value.Text.Contains("return", StringComparison.Ordinal) &&
    !packageMain.Contains("InternalReleaseTransactionRequestPath", StringComparison.Ordinal) &&
    internalTransactionContextFunction.Contains("'request.json'", StringComparison.Ordinal) &&
    internalTransactionContextFunction.Contains(
        "^r13-release-transaction-fault-[a-f0-9]{32}$",
        StringComparison.Ordinal) &&
    internalTransactionContextFunction.Contains("$requestItem.Length -gt 16384", StringComparison.Ordinal) &&
    internalTransactionContextFunction.Contains("Assert-NoPathOverlap", StringComparison.Ordinal) &&
    internalTransactionContextFunction.Contains("Assert-NoReparsePointsInTree", StringComparison.Ordinal) &&
    internalTransactionContextFunction.Contains("D:\\CodexTemp\\CodexGuardian", StringComparison.Ordinal) &&
    internalTransactionRequestFunction.Contains(
        "@('marker', 'schemaVersion', 'operation', 'fixtureRoot', 'generation', 'faultPoint')",
        StringComparison.Ordinal) &&
    internalTransactionRequestFunction.Contains("CODEXGUARDIAN_RELEASE_FAULT_REQUEST_V1", StringComparison.Ordinal) &&
    internalTransactionRequestFunction.Contains("ConvertFrom-Json -ErrorAction Stop", StringComparison.Ordinal) &&
    internalTransactionRequestFunction.Contains("ConvertTo-CanonicalReleaseJsonText", StringComparison.Ordinal) &&
    internalTransactionRequestFunction.Contains("exchange', 'resolve', 'snapshot", StringComparison.Ordinal) &&
    internalTransactionRequestFunction.Contains("Resolve and snapshot requests cannot contain a fault point", StringComparison.Ordinal) &&
    internalTransactionFaultPointsFunction.Contains("pending-commit.temp-flushed", StringComparison.Ordinal) &&
    internalTransactionFaultPointsFunction.Contains("journal.published", StringComparison.Ordinal) &&
    internalTransactionFaultPointsFunction.Contains("backup-published", StringComparison.Ordinal) &&
    internalTransactionFaultPointsFunction.Contains("current-published", StringComparison.Ordinal) &&
    internalTransactionFaultPointsFunction.Contains("commit.published", StringComparison.Ordinal),
    "internal transaction requests are hidden canonical and restricted to fixed D-drive fixture operations");
Assert(
    internalTransactionJsonWriterFunction.Contains("'fault-reached.json', 'result.json'", StringComparison.Ordinal) &&
    internalTransactionJsonWriterFunction.Contains("[System.IO.FileOptions]::WriteThrough", StringComparison.Ordinal) &&
    internalTransactionJsonWriterFunction.Contains("$stream.Flush($true)", StringComparison.Ordinal) &&
    internalTransactionJsonWriterFunction.Contains("MoveFileEx", StringComparison.Ordinal) &&
    internalTransactionFaultMarkerFunction.Contains("'fault-reached.json'", StringComparison.Ordinal) &&
    internalTransactionFaultMarkerFunction.Contains("CODEXGUARDIAN_RELEASE_FAULT_REACHED_V1", StringComparison.Ordinal) &&
    internalTransactionPlanFunction.Contains("runtime-directory", StringComparison.Ordinal) &&
    internalTransactionPlanFunction.Contains("source-directory", StringComparison.Ordinal) &&
    internalTransactionPlanFunction.Contains("runtime-zip", StringComparison.Ordinal) &&
    internalTransactionPlanFunction.Contains("source-zip", StringComparison.Ordinal) &&
    internalTransactionPlanFunction.Contains("checksum", StringComparison.Ordinal) &&
    internalTransactionGenerationFunction.Contains("CodexGuardian.exe", StringComparison.Ordinal) &&
    internalTransactionGenerationFunction.Contains("RecoveryOperationJournal.cs", StringComparison.Ordinal) &&
    internalTransactionGenerationFunction.Contains("Compress-ManagedOutputArchive", StringComparison.Ordinal) &&
    internalTransactionCommitFunction.Contains("New-ReleaseCommitDocument", StringComparison.Ordinal) &&
    internalTransactionCommitFunction.Contains("Assert-CurrentReleaseMatchesCommit", StringComparison.Ordinal) &&
    internalTransactionSnapshotFunction.Contains("pendingCount", StringComparison.Ordinal) &&
    internalTransactionSnapshotFunction.Contains("transientCount", StringComparison.Ordinal),
    "internal transaction fixtures use the fixed five-artifact plan and bounded durable result evidence");
Assert(
    internalTransactionHarnessFunction.Contains("$ValidateOnly -or $ScratchRootWasProvided", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.IndexOf("Read-InternalReleaseTransactionRequest", StringComparison.Ordinal) >= 0 &&
    internalTransactionHarnessFunction.IndexOf("Read-InternalReleaseTransactionRequest", StringComparison.Ordinal) <
        internalTransactionHarnessFunction.IndexOf("New-Item -ItemType Directory -Path $outputsPath", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("$script:OutputsRoot = $outputsPath", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("'run-' + $PID", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("-FaultCallback $faultCallback", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains(
        "$faultJsonWriterCommand = Get-Command",
        StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains(
        "-Name Write-InternalReleaseTransactionJson",
        StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains(
        "& $faultJsonWriterCommand",
        StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("TRANSACTION_FAULT_REACHED point=", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("Stop-Process -Id $PID -Force", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("The requested internal release transaction fault point was not reached", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("Resolve-ReleaseExchangeTransaction", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("Assert-ReleaseExchangeWorkspaceSettled", StringComparison.Ordinal) &&
    internalTransactionHarnessFunction.Contains("INTERNAL_RELEASE_TRANSACTION_COMPLETE", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Resolve-PinnedDotnetExecutable", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Get-PinnedDotnetFilePlan", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Open-PinnedDotnetLeases", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Assert-PinnedDotnetLeases", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Close-PinnedDotnetLeases", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Get-HermeticDotnetChildEnvironment", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Assert-ReleaseDotnetEnvironment", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Initialize-ReleaseProcessMethods", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Invoke-BoundedReleaseProcess", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Invoke-PinnedDotnetCommand", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Invoke-BoundedDotnetGate", StringComparison.Ordinal) &&
    !internalTransactionHarnessFunction.Contains("Start-Process", StringComparison.Ordinal) &&
    packageInternalHarnessDispatchText.Split(
        "Invoke-InternalReleaseTransactionHarness",
        StringSplitOptions.None).Length - 1 == 1 &&
    Regex.Matches(
        packageInternalHarnessDispatchText,
        @"(?m)^[ \t]+return[ \t]*$").Count == 1 &&
    !internalTransactionRequestFunction.Contains("scriptblock", StringComparison.OrdinalIgnoreCase) &&
    !internalTransactionRequestFunction.Contains("Current", StringComparison.Ordinal) &&
    !internalTransactionRequestFunction.Contains("Next", StringComparison.Ordinal) &&
    !internalTransactionRequestFunction.Contains("Previous", StringComparison.Ordinal),
    "internal transaction harness invokes the production function and resolver without request-controlled paths or code");
Assert(
    resolveExchangeFunction.Contains("Read-StrictReleaseJournal", StringComparison.Ordinal) &&
    resolveExchangeFunction.Contains("Read-StrictReleaseCommit", StringComparison.Ordinal) &&
    resolveExchangeFunction.Contains("Complete-CommittedReleaseTransaction", StringComparison.Ordinal) &&
    resolveExchangeFunction.Contains("Restore-UncommittedReleaseTransaction", StringComparison.Ordinal) &&
    resolveExchangeFunction.Contains("matches neither side of the durable transaction", StringComparison.Ordinal) &&
    restoreExchangeFunction.Contains("for ($index = $Artifacts.Count - 1; $index -ge 0; $index--)", StringComparison.Ordinal) &&
    restoreExchangeFunction.Contains("Move-ReleaseArtifactToDiscard", StringComparison.Ordinal) &&
    restoreExchangeFunction.Contains("Assert-CurrentReleaseMatchesCommit", StringComparison.Ordinal) &&
    restoreExchangeFunction.IndexOf("Remove-ManagedFile $JournalPath", StringComparison.Ordinal) >= 0 &&
    restoreExchangeFunction.IndexOf("Remove-ManagedFile $JournalPath", StringComparison.Ordinal) <
        restoreExchangeFunction.IndexOf("Remove-ReleaseDiscardArtifacts", StringComparison.Ordinal) &&
    completeExchangeFunction.Contains("Assert-CurrentReleaseMatchesCommit", StringComparison.Ordinal) &&
    completeExchangeFunction.Contains("Move-ReleaseArtifactToDiscard", StringComparison.Ordinal) &&
    completeExchangeFunction.IndexOf("Remove-ManagedFile $JournalPath", StringComparison.Ordinal) >= 0 &&
    completeExchangeFunction.IndexOf("Remove-ManagedFile $JournalPath", StringComparison.Ordinal) <
        completeExchangeFunction.IndexOf("Remove-ReleaseDiscardArtifacts", StringComparison.Ordinal),
    "release recovery classifies the atomic commit then idempotently restores or finalizes");
Assert(
    packageValidationRuntimeProducer > packageRuntimeStageManifest &&
    packageValidationSourceProducer > packageValidationRuntimeProducer &&
    packageValidationRuntimeBrokerGate > packageValidationSourceProducer &&
    packageValidationRuntimeParity > packageValidationRuntimeBrokerGate &&
    packageValidationSourceParity > packageValidationRuntimeParity,
    "release validation archives are produced then Broker gated and matched to sealed manifests");
Assert(
    durableReleaseExchangeFunction.Length > 0 &&
    durableReleaseExchangeCalls.Count == 1 &&
    packageTransactionRecoveryBlocks.Count == 2 &&
    packageSettledBlocks.Count == 1 &&
    durableExchangeRecoveryBlocks.Count == 1 &&
    durableExchangeSettledBlocks.Count == 1 &&
    packageReleaseLock > packageRuntimeZipAssignment &&
    packageInitialTransactionRecovery > packageReleaseLock &&
    packageInitialSettledGate > packageInitialTransactionRecovery &&
    packageReleaseBaseline > packageInitialSettledGate &&
    packageNextRuntimeDirectoryCreate > packageReleaseBaseline &&
    packageNextSourceDirectoryCreate > packageNextRuntimeDirectoryCreate &&
    packageNextRuntimeCopy > packageNextSourceDirectoryCreate &&
    packageNextSourceCopy > packageNextRuntimeCopy &&
    packageNextRuntimeBrokerGate > packageNextSourceCopy &&
    packageNextRuntimeDirectoryParity > packageNextRuntimeBrokerGate &&
    packageNextSourceDirectoryParity > packageNextRuntimeDirectoryParity &&
    packageNextRuntimeProducer > packageNextSourceDirectoryParity &&
    packageNextSourceProducer > packageNextRuntimeProducer &&
    packageNextRuntimeZipBrokerGate > packageNextSourceProducer &&
    packageNextRuntimeParity > packageNextRuntimeZipBrokerGate &&
    packageNextSourceParity > packageNextRuntimeParity &&
    packageNextChecksumRead > packageNextSourceParity &&
    durableReleaseExchangeCall > packageNextChecksumRead &&
    durableReleaseExchangeCallDepth == 2 &&
    durableReleaseExchangeCallSource.Contains("-ReleaseArtifacts $releaseArtifacts", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-ReleaseBaseline $releaseBaseline", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-ReleaseTransactionId $ReleaseTransactionId", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-ReleaseCommitPendingPath $ReleaseCommitPendingPath", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-ReleaseCommitPath $ReleaseCommitPath", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-ReleaseJournalPath $ReleaseJournalPath", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-OutputsRoot $OutputsRoot", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-RuntimeOutput $RuntimeOutput", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-SourceOutput $SourceOutput", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-RuntimeZip $RuntimeZip", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-SourceZip $SourceZip", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-ChecksumPath $ChecksumPath", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-RuntimeStageManifest $RuntimeStageManifest", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-SourceStageManifest $SourceStageManifest", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-RuntimeEntryCount $runtimeEntryCount", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-SourceEntryCount $sourceEntryCount", StringComparison.Ordinal) &&
    durableReleaseExchangeCallSource.Contains("-FaultCallback $null", StringComparison.Ordinal) &&
    packageCatchTransactionRecovery > durableReleaseExchangeCall &&
    packageCatchRethrow > packageCatchTransactionRecovery &&
    packageCatchRethrowDepth == 2 &&
    packageReadyGuard.HasValue &&
    packageReadyGuard.Value.ParentDepth == 1 &&
    packageReadyGuard.Value.HeaderIndex > packageCatchRethrow &&
    packageReadyGuardFailure >= 0 &&
    packageReleaseReady > packageReadyGuard.Value.CloseBraceIndex &&
    packageReleaseReadyDepth == 1 &&
    packageLockDispose > packageReleaseReady &&
    packageGuardianLeaseRelease > packageLockDispose &&
    packageLockDisposeDepth == 2 &&
    packageGuardianLeaseReleaseDepth == 2,
    "release main prepares candidates then calls one durable transaction under both locks and one recovery owner");
Assert(
    packageCandidateSyncBlocks.Count == 1 &&
    packageCandidateSync >= 0 &&
    packageCandidateEntries > packageCandidateSync &&
    packageCommitPendingWrite > packageCandidateEntries &&
    packageCommitPendingWriteBlocks[0].Text.Contains("-FaultCallback $FaultCallback", StringComparison.Ordinal) &&
    packageCommitPendingWriteBlocks[0].Text.Contains("-FaultScope 'pending-commit'", StringComparison.Ordinal) &&
    packagePendingCommitRead > packageCommitPendingWrite &&
    packagePendingCommitGateFailure > packagePendingCommitRead &&
    packagePreJournalStopCheck > packagePendingCommitGateFailure &&
    packagePreJournalStopDepth == 1 &&
    packageOldCommitBlock.HasValue &&
    packageOldCommitBlock.Value.ParentDepth == 1 &&
    packageOldCommitBlock.Value.HeaderIndex > packagePreJournalStopCheck &&
    packageOldCommitRead > packageOldCommitBlock.Value.OpenBraceIndex &&
    packageOldCommitChangedFailure > packageOldCommitRead &&
    packageOldCommitChangedFailure < packageOldCommitBlock.Value.CloseBraceIndex &&
    packageOldCommitBlock.Value.Text.Contains("$currentCommit.Sha256", StringComparison.Ordinal) &&
    packageOldCommitBlock.Value.Text.Contains("$releaseBaseline.OldCommit.sha256", StringComparison.Ordinal) &&
    packageFirstReleaseCommitBlock.HasValue &&
    packageFirstReleaseCommitBlock.Value.ParentDepth == 1 &&
    packageFirstReleaseCommitBlock.Value.HeaderIndex > packageOldCommitBlock.Value.CloseBraceIndex &&
    packageFirstReleaseCommitFailure > packageFirstReleaseCommitBlock.Value.OpenBraceIndex &&
    packageFirstReleaseCommitFailure < packageFirstReleaseCommitBlock.Value.CloseBraceIndex &&
    packageTransactionSnapshot > packageFirstReleaseCommitFailure &&
    packageTransactionSnapshotDepth == 1 &&
    packageJournalWrite > packageTransactionSnapshot &&
    packageJournalWriteBlocks[0].Text.Contains("-FaultCallback $FaultCallback", StringComparison.Ordinal) &&
    packageJournalWriteBlocks[0].Text.Contains("-FaultScope 'journal'", StringComparison.Ordinal),
    "durable transaction seals candidates old commit and the ordinal snapshot before its journal");
Assert(
    packagePromotionLoop > packageJournalWrite &&
    packagePromotionStopCheck > packagePromotionLoop &&
    packagePromotionStopDepth == 2 &&
    packageCurrentBackup > packagePromotionStopCheck &&
    packageCandidatePromotion > packageCurrentBackup &&
    durableReleaseExchangeFunction.Contains("backup-published", StringComparison.Ordinal) &&
    durableReleaseExchangeFunction.Contains("current-published", StringComparison.Ordinal) &&
    packagePostExchangeRequiredFiles > packagePromotionLoop &&
    packageExchangedRuntimeBrokerGate > packagePostExchangeRequiredFiles &&
    packageExchangedRuntimeZipBrokerGate > packageExchangedRuntimeBrokerGate &&
    packageExchangedRuntimeDirectoryParity > packageExchangedRuntimeZipBrokerGate &&
    packageExchangedSourceDirectoryParity > packageExchangedRuntimeDirectoryParity &&
    packageExchangedRuntimeParity > packageExchangedSourceDirectoryParity &&
    packageExchangedSourceParity > packageExchangedRuntimeParity &&
    packageExchangedChecksumRead > packageExchangedSourceParity &&
    packageCommitMove > packageExchangedChecksumRead &&
    durableReleaseExchangeFunction.Contains("-Point 'commit.published'", StringComparison.Ordinal) &&
    durableReleaseExchangeFunction.Split(
        "Invoke-ReleaseTransactionFaultCallback",
        StringSplitOptions.None).Length - 1 == 3 &&
    packageCommittedTransactionRecovery > packageCommitMove &&
    packageCommittedSettledGate > packageCommittedTransactionRecovery &&
    packageCommittedReleaseRead > packageCommittedSettledGate &&
    packageCommittedReleaseFailure > packageCommittedReleaseRead &&
    packageCommittedReleaseParity > packageCommittedReleaseFailure &&
    durableSuccessReturn > packageCommittedReleaseParity &&
    durableSuccessReturnDepth == 1 &&
    !packageMain.Contains("$candidateEntries = @(Get-ReleaseCandidateEntries", StringComparison.Ordinal) &&
    !packageMain.Contains("$newCommitSha256 = Write-DurableManagedText", StringComparison.Ordinal) &&
    !packageMain.Contains("Assert-ReleaseTransactionSnapshot", StringComparison.Ordinal) &&
    !packageMain.Contains("for ($index = 0; $index -lt $releaseArtifacts.Count; $index++) {", StringComparison.Ordinal) &&
    !packageMain.Contains("$committedRelease = Read-StrictReleaseCommit", StringComparison.Ordinal) &&
    !durableReleaseExchangeFunction.Contains("Enter-GuardianReleaseLease", StringComparison.Ordinal) &&
    !durableReleaseExchangeFunction.Contains("Exit-GuardianReleaseLease", StringComparison.Ordinal) &&
    !durableReleaseExchangeFunction.Contains("Enter-ReleaseExchangeLock", StringComparison.Ordinal) &&
    !durableReleaseExchangeFunction.Contains("$releaseExchangeLock.Dispose()", StringComparison.Ordinal) &&
    !durableReleaseExchangeFunction.Contains("catch {", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("$swappedArtifacts", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("$rollbackFailures", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("Release candidate cleanup failed", StringComparison.Ordinal),
    "durable exchange is single-owner and verifies promotion commit recovery and final identity before success");
Assert(
    nativeRunTargets.SequenceEqual(expectedNativeRunTargets, StringComparer.Ordinal) &&
    nativeArgumentGuard >= 0 && nativeEarlyReturn > nativeArgumentGuard &&
    nativeFirstCase > nativeEarlyReturn && nativeLastCase >= nativeFirstCase &&
    nativeCompletionWrite > nativeLastCase &&
    nativePeerProbeSource.Split(
        "internal const string CompletionMarker = \"NATIVE_PEER_PROBE_COMPLETE\";",
        StringSplitOptions.None).Length - 1 == 1 &&
    nativePeerProbeSource.Split(
        "Console.WriteLine(CompletionMarker);",
        StringSplitOptions.None).Length - 1 == 1,
    "native peer suite runs the exact cases before its unique completion marker");
Assert(
    connectedClientNativeProbeSource.Contains(
        "ParentArgument = \"--native-connected-client-probe\";",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "ChildArgument = \"--native-connected-client-child-probe\";",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "RunIfRequestedAsync",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "TakeConnectedClient",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "NamedPipePeerKind.Client",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "NATIVE_CONNECTED_CLIENT_PROBE_COMPLETE",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains("PING", StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains("PONG", StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "the caller retained a live server alias after connected-client ownership transfer",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "native-connected-client-fixture",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "maximumFilesPerRelease = 16",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "maximumBytesPerRelease = 64L * 1024 * 1024",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "EnsureRegularDirectoryChain",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "includeProbeRuntime: true",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "guardianFiles.Length == 9 && brokerFiles.Length == 6",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "File.Copy(source.FullName, target, overwrite: false)",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "r13-connected-client-synthetic-tests-apphost-probe",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "guardianSyntheticTestsApphost",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "DescribeFailure",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "depth < 8",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "NativeErrorCode",
        StringComparison.Ordinal) &&
    connectedClientNativeProbeSource.Contains(
        "TargetSite",
        StringComparison.Ordinal) &&
    !connectedClientNativeProbeSource.Contains(
        ".Message",
        StringComparison.Ordinal) &&
    !connectedClientNativeProbeSource.Contains(
        "CopyBoundedReleaseDirectory",
        StringComparison.Ordinal) &&
    !connectedClientNativeProbeSource.Contains(
        "Directory.Delete(",
        StringComparison.Ordinal) &&
    connectedClientPlatformSource.Contains(
        "public sealed class WindowsConnectedClientPeerTrustPlatform",
        StringComparison.Ordinal) &&
    connectedClientPlatformSource.Contains(
        "TakeConnectedClient",
        StringComparison.Ordinal) &&
    connectedClientPlatformSource.Contains(
        "CaptureImpersonatedClientToken",
        StringComparison.Ordinal) &&
    connectedClientPlatformSource.Contains(
        "connectedServer.TransferOwnership()",
        StringComparison.Ordinal) &&
    connectedClientPlatformSource.Contains(
        "Environment.FailFast",
        StringComparison.Ordinal) &&
    connectedClientPlatformSource.Contains(
        "_nativeReadStop.Dispose()",
        StringComparison.Ordinal) &&
    namedPipePeerPlatformSource.Contains(
        "INamedPipePeerMessageTransport",
        StringComparison.Ordinal) &&
    namedPipePeerPlatformSource.Contains(
        "_nativeReadStop.Dispose()",
        StringComparison.Ordinal) &&
    sameLogonNamedPipeSource.Contains(
        "internal bool IsConnected",
        StringComparison.Ordinal) &&
    sameLogonNamedPipeSource.Contains(
        "internal WindowsSameLogonNamedPipeServer TransferOwnership()",
        StringComparison.Ordinal) &&
    sameLogonNamedPipeSource.Contains(
        "stream.ReadMode = PipeTransmissionMode.Message;",
        StringComparison.Ordinal) &&
    sameLogonNamedPipeSource.Contains(
        "internal static class WindowsNamedPipeMessageIO",
        StringComparison.Ordinal) &&
    sameLogonNamedPipeSource.Contains(
        "internal static async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "CodexGuardian.Tests\\WindowsConnectedClientPeerTrustNativeTests.cs",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "CodexGuardian.Trust\\Windows\\WindowsConnectedClientPeerTrustPlatform.cs",
        StringComparison.Ordinal) &&
    packageReleaseSource.Contains(
        "Synthetic Tests-apphost Guardian-role reverse authentication probe",
        StringComparison.Ordinal),
    "connected Guardian-client adapter and duplex native probe are present in source and release closure");
var localHistoryMethods = typeof(LocalConversationHistoryReader)
    .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
    .Select(method => method.Name)
    .ToArray();
Assert(
    localHistorySource.Length > 0 &&
    localHistoryModelsSource.Length > 0 &&
    localHistorySource.Contains("MaximumTailBytes", StringComparison.Ordinal) &&
    localHistorySource.Contains("MaximumLogicalIncidentBytes", StringComparison.Ordinal) &&
    localHistorySource.Contains("MaximumLogicalIncidentLines", StringComparison.Ordinal) &&
    localHistorySource.Contains("RegisterSourceFile", StringComparison.Ordinal) &&
    localHistorySource.Contains("_fileIndexInitialized", StringComparison.Ordinal) &&
    localHistorySource.Contains("FileOptions.RandomAccess", StringComparison.Ordinal) &&
    localHistorySource.Contains("FileOptions.SequentialScan", StringComparison.Ordinal) &&
    localHistorySource.Contains("fileInfo.Length > MaximumLogicalIncidentBytes", StringComparison.Ordinal) &&
    localHistorySource.Contains("lineCount > MaximumLogicalIncidentLines", StringComparison.Ordinal) &&
    !localHistorySource.Contains("ReadFileAsync", StringComparison.Ordinal) &&
    !localHistoryMethods.Contains("ReadAsync", StringComparer.Ordinal) &&
    !localHistoryMethods.Contains("ReadFailuresAsync", StringComparer.Ordinal) &&
    !localHistoryMethods.Contains("ReadLatestFailureAsync", StringComparer.Ordinal) &&
    !localHistoryModelsSource.Contains("LocalConversationHistoryReadResult", StringComparison.Ordinal) &&
    !localHistoryModelsSource.Contains("LocalConversationFailure", StringComparison.Ordinal) &&
    !localHistoryModelsSource.Contains("LocalConversationReadIssue", StringComparison.Ordinal),
    "local rollout reconciliation keeps ordinary reads tail-bounded and logical incidents file-and-line bounded");
Assert(
    appServerSource.Contains("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", StringComparison.Ordinal) &&
    appServerSource.Contains("AssignProcessToJobObject", StringComparison.Ordinal) &&
    appServerSource.Contains("OpenReadSessionAsync", StringComparison.Ordinal) &&
    appServerSource.Contains("AcquireMonitoringLease", StringComparison.Ordinal) &&
    appServerSource.Contains("MonitoringLeaseCount", StringComparison.Ordinal) &&
    appServerSource.Contains("ReadSessionIdleDelay = TimeSpan.FromSeconds(5)", StringComparison.Ordinal) &&
    appServerSource.Contains("_idleDisconnect.CancelPending()", StringComparison.Ordinal) &&
    appServerSource.Contains("_idleDisconnect.Schedule()", StringComparison.Ordinal) &&
    appServerSource.Contains("CleanupClosedConnectionAsync", StringComparison.Ordinal) &&
    appServerSource.Contains("ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> pending", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("await using var readSession = await _appServer.OpenReadSessionAsync", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("archived: true", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("IsTruncated: false", StringComparison.Ordinal) &&
    !guardianEngineSource.Contains(".Take(_settings.RecentThreadLimit)", StringComparison.Ordinal) &&
    !guardianEngineSource.Contains("AddDays(-_settings.RecentThreadLookbackDays)", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("HasDesktopActivityVeto(thread.Id)", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("thread-stream-following-changed", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("ApplyDesktopStreamRevision", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("DesktopThreadOwnerStateSnapshot.TryParse", StringComparison.Ordinal) &&
    !guardianEngineSource.Contains("\"following:\" +", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("FullReconciliationInterval = TimeSpan.FromMinutes(15)", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("RefreshThreadsAsync", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("ThreadRefreshQueue", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("public bool SupportsAtomicRecoveryPrecondition =>", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("IsStrictAtomicRecoveryEligible", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("public bool SupportsGuardedAutomaticRecovery =>", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("IsGuardedAutomaticRecoveryEligible", StringComparison.Ordinal) &&
    mainViewModelSource.Contains("SupportsGuardedAutomaticRecovery", StringComparison.Ordinal) &&
    recoverySource.Contains("ValidateGuardedAutomaticRecoveryCapability", StringComparison.Ordinal) &&
    !guardianEngineSource.Contains("IsRecoveryBridgeAvailable", StringComparison.Ordinal) &&
    !guardianEngineSource.Contains("_appServer.DisconnectAsync", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("_appServer.NotificationReceived +=", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("_appServer.ConnectionChanged +=", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("AcquireMonitoringLease", StringComparison.Ordinal) &&
    localWatcherSource.Contains("MaximumAppendBytes = 256 * 1024", StringComparison.Ordinal) &&
    localWatcherSource.Contains("BoundedChannelFullMode.Wait", StringComparison.Ordinal) &&
    !localWatcherSource.Contains("Directory.EnumerateFiles", StringComparison.Ordinal) &&
    guardianLogSource.Contains("EnsureWriterCapacity", StringComparison.Ordinal) &&
    guardianLogSource.Contains("SanitizeForPersistence", StringComparison.Ordinal) &&
    guardianLogSource.Contains("WriteMonitorCycle", StringComparison.Ordinal) &&
    interactionHookSource.Contains("SetWinEventHook", StringComparison.Ordinal) &&
    interactionHookSource.Contains("ProseMirror", StringComparison.Ordinal) &&
    interactionHookSource.Contains("BoundedChannelOptions(1)", StringComparison.Ordinal) &&
    !interactionHookSource.Contains("FileSystemWatcher", StringComparison.Ordinal) &&
    !interactionHookSource.Contains("Directory.Enumerate", StringComparison.Ordinal) &&
    diagnosticSource.Contains("await using var readSession = await _appServer.OpenReadSessionAsync", StringComparison.Ordinal) &&
    !diagnosticSource.Contains("DisconnectAsync", StringComparison.Ordinal),
    "monitoring keeps one read-only subscription resident while verification remains targeted, bounded, and redacted");
// A log label can only attribute a line to one conversation if it is derived from the exact task
// id. Passing a title reintroduces collisions that no unit test on the pure hash can catch, so the
// call sites are guarded directly. `state.Thread.Name` stays legal: the UI snapshot fingerprint
// must include the title so a rename repaints. Ordinal comparison separates the two receivers.
Assert(
    !string.IsNullOrEmpty(recoverySource) &&
    !string.IsNullOrEmpty(guardianEngineSource) &&
    !string.IsNullOrEmpty(followUpDispatchSource) &&
    !string.IsNullOrEmpty(guardianLogSource) &&
    !recoverySource.Contains("thread.Name", StringComparison.Ordinal) &&
    !guardianEngineSource.Contains("thread.Name", StringComparison.Ordinal) &&
    !followUpDispatchSource.Contains("thread.Name", StringComparison.Ordinal) &&
    recoverySource.Contains("thread.Id", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("thread.Id", StringComparison.Ordinal) &&
    followUpDispatchSource.Contains("thread.Id", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("state.Thread.Name", StringComparison.Ordinal) &&
    guardianLogSource.Contains("CreateThreadReference(string? threadId)", StringComparison.Ordinal) &&
    guardianLogSource.Contains("CreateOpaqueReference(\"task\", threadId)", StringComparison.Ordinal) &&
    !guardianLogSource.Contains("threadName", StringComparison.Ordinal),
    "log task labels are derived from the exact task id at every call site, never from a task title");
Assert(
    deepObservationSource.Contains("PipeOptions.CurrentUserOnly", StringComparison.Ordinal) &&
    deepObservationSource.Contains("GetNamedPipeClientProcessId", StringComparison.Ordinal) &&
    deepObservationSource.Contains("ContractId = CodexCdpObservationProtocol.ContractId", StringComparison.Ordinal) &&
    deepObservationSource.Contains("HasExactProperties", StringComparison.Ordinal) &&
    !deepObservationSource.Contains("ExpectedPackageVersion", StringComparison.Ordinal) &&
    !deepObservationSource.Contains("ExpectedAppBuild", StringComparison.Ordinal) &&
    !deepObservationSource.Contains("ExpectedOriginalPreloadSha256", StringComparison.Ordinal) &&
    deepObservationSource.Contains("sequence != client.LastSequence + 1", StringComparison.Ordinal) &&
    deepObservationSource.Contains("fullSnapshot", StringComparison.Ordinal) &&
    deepObservationSource.Contains("LastSnapshotAt", StringComparison.Ordinal) &&
    deepObservationSource.Contains("ComposerKnown", StringComparison.Ordinal) &&
    deepObservationSource.Contains("RecoveryInterferenceStatus.Unknown", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("Item phases are display-only", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("ShouldRefreshFromDeepObservation", StringComparison.Ordinal) &&
    deepObservationSource.Contains("CodexDeepChangeKind.Item", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("PublishCachedSnapshot();", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("RequestThreadRefresh(eventArgs.ThreadId)", StringComparison.Ordinal),
    "deep observation validates the client and capability contract, fails closed on gaps, updates item hints in memory, and only wakes targeted fact reads on state edges");
Assert(
    existingLegacyDeepObservationPayloads.Length == 0 &&
    !guardianProjectSource.Contains("CopyToPublishDirectory", StringComparison.Ordinal) &&
    !guardianProjectSource.Contains("HookPayload\\**\\*", StringComparison.Ordinal),
    "obsolete preload and modification-package payloads are absent from the active project and runtime output");
Assert(
    cdpProfileSource.All(character => character <= 0x7f) &&
    cdpProfile is JsonObject cdpProfileObject &&
    cdpProfileObject.Count == 22 &&
    cdpProfile?["schema"]?.GetValue<int>() == 2 &&
    cdpProfile?["mode"]?.GetValue<string>() == "read-only-cdp-poc" &&
    cdpProfile?["packageName"]?.GetValue<string>() == "OpenAI.Codex" &&
    cdpProfile?["packageFamilyName"]?.GetValue<string>() == "OpenAI.Codex_2p2nqsd0c76g0" &&
    cdpProfile?["contractId"]?.GetValue<string>() == CodexCdpObservationProtocol.ContractId &&
    cdpProfile?["asarPackageName"]?.GetValue<string>() == "openai-codex-electron" &&
    cdpProfile?["asarProductName"]?.GetValue<string>() == "Codex" &&
    cdpProfile?["asarMainPath"]?.GetValue<string>() == ".vite/build/early-bootstrap.js" &&
    cdpProfile?["asarMainSha256"]?.GetValue<string>() ==
        "DCC940F4ABB9D2D3C84448B42A6499A19AAE7F3C221D853C48D32C9F62CE5CDB" &&
    cdpProfile?["preloadPath"]?.GetValue<string>() == ".vite/build/preload.js" &&
    cdpProfile?["preloadSha256"]?.GetValue<string>() ==
        "A976C02AB0F9CF0EB11D5E4DA32C95E9F5DB3790D76505888C6E493F137F6AC9" &&
    cdpProfile?["preloadMarkers"] is JsonArray cdpPreloadMarkers &&
    cdpPreloadMarkers.Count == 4 &&
    cdpProfile?["hookSha256"]?.GetValue<string>() == cdpHookSha256 &&
    cdpProfile?["observerSha256"]?.GetValue<string>() == cdpObserverSha256 &&
    cdpProfile?["packageFullName"] is null &&
    cdpProfile?["packageVersion"] is null &&
    cdpProfile?["packageSignatureKind"] is null &&
    cdpProfile?["appBuild"] is null &&
    cdpProfile?["electronVersion"] is null &&
    cdpProfile?["chromiumVersion"] is null &&
    cdpProfile?["manifestSha256"] is null &&
    cdpProfile?["chatGptExeSha256"] is null &&
    cdpProfile?["codexExeSha256"] is null &&
    cdpProfile?["appAsarSha256"] is null &&
    cdpRunnerSource.Contains(
        "$ExpectedHookSha256 = '" + cdpHookSha256 + "'",
        StringComparison.Ordinal) &&
    cdpRunnerSource.Contains(
        "$ExpectedObserverSha256 = '" + cdpObserverSha256 + "'",
        StringComparison.Ordinal) &&
    cdpRunnerSource.Contains(
        "$ExpectedProfileSha256 = '" + cdpProfileSha256 + "'",
        StringComparison.Ordinal) &&
    cdpHookSource.Contains(
        "contractId: \"codex-cdp-observation-v1\"",
        StringComparison.Ordinal) &&
    cdpObserverSource.Contains("helloPropertyNames", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("wrong-contract", StringComparison.Ordinal),
    "the r13 CDP schema 2 profile pins only stable capabilities and Guardian-owned resources");
Assert(
    cdpHookSource.All(character => character <= 0x7f) &&
    cdpObserverSource.All(character => character <= 0x7f) &&
    cdpRunnerSource.All(character => character <= 0x7f) &&
    cdpHookSource.Contains("codex-guardian-cdp-observation-poc-v1", StringComparison.Ordinal) &&
    cdpHookSource.Contains("window.addEventListener(\"message\"", StringComparison.Ordinal) &&
    cdpHookSource.Contains("message?.type === \"mcp-notification\"", StringComparison.Ordinal) &&
    cdpHookSource.Contains("location.protocol !== \"app:\"", StringComparison.Ordinal) &&
    cdpHookSource.Contains("globalThis.electronBridge", StringComparison.Ordinal) &&
    cdpHookSource.Contains("notificationCandidates", StringComparison.Ordinal) &&
    cdpHookSource.Contains("notificationShape", StringComparison.Ordinal) &&
    cdpHookSource.Contains("composerKnown", StringComparison.Ordinal) &&
    cdpHookSource.Contains("editorPresent", StringComparison.Ordinal) &&
    cdpHookSource.Contains("composerFocused", StringComparison.Ordinal) &&
    cdpHookSource.Contains("hasDraft", StringComparison.Ordinal) &&
    cdpHookSource.Contains("remoteTaskCreated", StringComparison.Ordinal) &&
    cdpHookSource.Contains("restarting", StringComparison.Ordinal) &&
    cdpHookSource.Contains("waiting-for-device", StringComparison.Ordinal) &&
    cdpHookSource.Contains("params.turn?.id ?? params.turnId", StringComparison.Ordinal) &&
    !cdpHookSource.Contains("messageText", StringComparison.Ordinal) &&
    !cdpHookSource.Contains("params.item?.content", StringComparison.Ordinal) &&
    !cdpHookSource.Contains("params.turn?.items", StringComparison.Ordinal) &&
    !cdpHookSource.Contains("reasoningText", StringComparison.OrdinalIgnoreCase) &&
    !cdpHookSource.Contains("toolOutput", StringComparison.OrdinalIgnoreCase) &&
    cdpObserverSource.Contains("Runtime.addBinding", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("Page.addScriptToEvaluateOnNewDocument", StringComparison.Ordinal) &&
    !cdpObserverSource.Contains("Target.setAutoAttach", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("Target.targetCreated", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("isCandidateTargetInfo", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("targetInfo.url.startsWith(\"app://\")", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("executionContextId", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("not every active Codex app renderer", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("Target.attachToTarget", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("observerFailure", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("classifyObserverFailure", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("createLiveProofTracker", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("maximumLiveProofTurns = 256", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("liveProofEnabled = true", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("recognizedEnvelope === \"top\"", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("observation.status === \"completed\"", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("--self-test", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("maximumPayloadBytes = 4096", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("maximumLogBytes = 512 * 1024", StringComparison.Ordinal) &&
    cdpObserverSource.Contains("maskIdentifier", StringComparison.Ordinal) &&
    cdpSelfTest.Item1 == 0 &&
    cdpSelfTest.Item2.Contains("SELF_TEST_PASS single-attachment-owner", StringComparison.Ordinal) &&
    cdpSelfTest.Item2.Contains("SELF_TEST_PASS turn-correlated-live-proof", StringComparison.Ordinal) &&
    cdpSelfTest.Item2.Contains("ALL SELF TESTS PASSED", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("--remote-debugging-address=127.0.0.1", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedMainPackageFullName", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedMainFullName", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedMainVersion", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedAppBuild", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedMainManifestSha256", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedMainExecutableSha256", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedCodexExecutableSha256", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ExpectedMainAsarSha256", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("ExpectedContractId", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("ExpectedNodeSha256", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Assert-FileHash", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Get-FrozenFileIdentity", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Assert-PackageBaselineUnchanged", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("signed-patch capability lease", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Read-VerifiedProfile", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Get-VerifiedTestProcessTree", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Wait-ForOwnedLoopbackListener", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Restart-WithoutCdp", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Stop-TestProcessTree", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Join-Path $env:WINDIR 'explorer.exe'", StringComparison.Ordinal) &&
    cdpRunnerSource.Contains("Stop-Process", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ModificationInstallerPath", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("ModificationProfilePath", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("-PackageTypeFilter Optional", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("Remove-AppxPackage", StringComparison.Ordinal) &&
    !cdpRunnerSource.Contains("-PreserveApplicationData", StringComparison.Ordinal),
    "the CDP PoC validates every active renderer and its full local runtime chain, then cleans only its verified process tree and restarts stock Codex without CDP");
Assert(
    cdpRuntimeHookSource.All(character => character <= 0x7f) &&
    cdpRuntimeProfileSource.All(character => character <= 0x7f) &&
    cdpRuntimeProfile is JsonObject cdpRuntimeProfileObject &&
    cdpRuntimeProfileObject.Count == 18 &&
    cdpRuntimeProfile?["schema"]?.GetValue<int>() == 2 &&
    cdpRuntimeProfile?["mode"]?.GetValue<string>() == "read-only-cdp-pipe-runtime" &&
    cdpRuntimeProfile?["transport"]?.GetValue<string>() == "remote-debugging-io-pipes" &&
    cdpRuntimeProfile?["contractId"]?.GetValue<string>() == CodexCdpObservationProtocol.ContractId &&
    cdpRuntimeProfile?["asarMainSha256"]?.GetValue<string>() ==
        "DCC940F4ABB9D2D3C84448B42A6499A19AAE7F3C221D853C48D32C9F62CE5CDB" &&
    cdpRuntimeProfile?["preloadSha256"]?.GetValue<string>() ==
        "A976C02AB0F9CF0EB11D5E4DA32C95E9F5DB3790D76505888C6E493F137F6AC9" &&
    cdpRuntimeProfile?["hookSha256"]?.GetValue<string>() == cdpRuntimeHookSha256 &&
    cdpRuntimeProfile?["packageFullName"] is null &&
    cdpRuntimeProfile?["packageVersion"] is null &&
    cdpRuntimeProfile?["packageSignatureKind"] is null &&
    cdpRuntimeProfile?["appBuild"] is null &&
    cdpRuntimeProfile?["manifestSha256"] is null &&
    cdpRuntimeProfile?["chatGptExeSha256"] is null &&
    cdpRuntimeProfile?["codexExeSha256"] is null &&
    cdpRuntimeProfile?["appAsarSha256"] is null &&
    cdpRuntimeHookSource.Contains(
        "codex-guardian-cdp-observation-runtime-v1",
        StringComparison.Ordinal) &&
    cdpRuntimeHookSource.Contains(
        "requestSnapshot: () => publishSnapshot(true)",
        StringComparison.Ordinal) &&
    cdpRuntimeHookSource.Contains(
        "contractId: \"codex-cdp-observation-v1\"",
        StringComparison.Ordinal) &&
    !cdpRuntimeHookSource.Contains("packageVersion", StringComparison.Ordinal) &&
    !cdpRuntimeHookSource.Contains("appBuild", StringComparison.Ordinal) &&
    !cdpRuntimeHookSource.Contains("messageText", StringComparison.Ordinal) &&
    !cdpRuntimeHookSource.Contains("params.item?.content", StringComparison.Ordinal) &&
    !cdpRuntimeHookSource.Contains("params.turn?.items", StringComparison.Ordinal) &&
    !cdpRuntimeHookSource.Contains("reasoningText", StringComparison.OrdinalIgnoreCase) &&
    !cdpRuntimeHookSource.Contains("toolOutput", StringComparison.OrdinalIgnoreCase) &&
    cdpRuntimeProtocolSource.Contains("MaximumPayloadBytes = 4096", StringComparison.Ordinal) &&
    cdpRuntimeProtocolSource.Contains("HasExactProperties", StringComparison.Ordinal) &&
    cdpRuntimeProtocolSource.Contains(
        "HasString(root, \"notificationEnvelope\", \"top\")",
        StringComparison.Ordinal) &&
    cdpRuntimeSessionSource.Contains("Target.setDiscoverTargets", StringComparison.Ordinal) &&
    cdpRuntimeSessionSource.Contains("Target.getTargets", StringComparison.Ordinal) &&
    cdpRuntimeSessionSource.Contains("Target.attachToTarget", StringComparison.Ordinal) &&
    cdpRuntimeSessionSource.Contains("Runtime.addBinding", StringComparison.Ordinal) &&
    cdpRuntimeSessionSource.Contains(
        "Page.addScriptToEvaluateOnNewDocument",
        StringComparison.Ordinal) &&
    cdpRuntimeSessionSource.Split("\"Runtime.evaluate\"", StringSplitOptions.None).Length == 3 &&
    !cdpRuntimeSessionSource.Contains("Target.setAutoAttach", StringComparison.Ordinal) &&
    !cdpRuntimeSessionSource.Contains("remote-debugging-port", StringComparison.Ordinal) &&
    !cdpRuntimeSessionSource.Contains("remote-debugging-address", StringComparison.Ordinal) &&
    !cdpRuntimeSessionSource.Contains("Network.", StringComparison.Ordinal) &&
    !cdpRuntimeSessionSource.Contains("Browser.close", StringComparison.Ordinal) &&
    !cdpRuntimeSessionSource.Contains("Target.closeTarget", StringComparison.Ordinal) &&
    cdpPipeLauncherSource.Contains("--remote-debugging-pipe", StringComparison.Ordinal) &&
    cdpPipeLauncherSource.Contains("--remote-debugging-io-pipes=", StringComparison.Ordinal) &&
    cdpPipeLauncherSource.Contains("ProcThreadAttributeHandleList", StringComparison.Ordinal) &&
    !cdpPipeLauncherSource.Contains("remote-debugging-port", StringComparison.Ordinal) &&
    !cdpPipeLauncherSource.Contains("remote-debugging-address", StringComparison.Ordinal) &&
    !appCompositionSource.Contains("CodexCdpObservationService", StringComparison.Ordinal) &&
    !appCompositionSource.Contains("WindowsCrtPipeProcess", StringComparison.Ordinal) &&
    !appCompositionSource.Contains("WindowsCodexCdpRuntimeControlHostV1", StringComparison.Ordinal) &&
    !appCompositionSource.Contains("ICodexCdpRuntimeControlHost", StringComparison.Ordinal) &&
    !appCompositionSource.Contains("AuthenticatedPipePeerConnection", StringComparison.Ordinal) &&
    !appCompositionSource.Contains("CodexGuardian.Control", StringComparison.Ordinal) &&
    controlProjectSource.Contains("codex-guardian-cdp-runtime-hook.js", StringComparison.Ordinal) &&
    controlProjectSource.Contains("cdp-runtime-profile.json", StringComparison.Ordinal) &&
    !guardianProjectSource.Contains("codex-guardian-cdp-runtime-hook.js", StringComparison.Ordinal) &&
    !guardianProjectSource.Contains("cdp-runtime-profile.json", StringComparison.Ordinal) &&
    !guardianProjectSource.Contains("codex-guardian-cdp-observer-poc.mjs", StringComparison.Ordinal) &&
    !guardianProjectSource.Contains("run-cdp-observation-poc.ps1", StringComparison.Ordinal),
    "the production C# CDP core is hash-pinned, pipe-only, fixed-command, content-free, and not wired to launch Codex");
Assert(
    guardianEngineSource.Contains("_desktopRevisionGaps", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("CaptureDesktopRevisionGaps", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("ClearDesktopRevisionGaps", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("BuildDesktopRevisionGapState", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("changed |= SetDesktopActivityVeto", StringComparison.Ordinal) &&
    interactionHookSource.Contains("_observationHealthy", StringComparison.Ordinal) &&
    interactionHookSource.Contains("SetObservationHealth(false)", StringComparison.Ordinal) &&
    interactionHookSource.Contains("SetObservationHealth(result.Healthy)", StringComparison.Ordinal),
    "Desktop revision gaps fail closed until targeted verification and enhanced observation reports live health");
Assert(
    !guardianEngineSource.Contains("AbandonPendingOperationsAsync", StringComparison.Ordinal) &&
    !recoverySource.Contains("AbandonPendingOperationsAsync", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("PruneAttemptState(relevantThreads)", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("attempt.NextAttemptAt = null", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("TryTakeDueRetry(DateTimeOffset.Now)", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("ThreadRefreshKind.RetryRecovery", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("CaptureRecoveryRetryTurnId", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("RecoveryPolicySnapshot", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("CapturePolicySnapshot()", StringComparison.Ordinal) &&
    recoverySource.Contains("RevalidateThreadEligibilityAsync", StringComparison.Ordinal) &&
    recoverySource.Contains("BeginScopeValidationGeneration", StringComparison.Ordinal) &&
    !recoverySource.Contains("ScopeRefresh", StringComparison.Ordinal) &&
    !recoverySource.Contains("LoadScopeSnapshotAsync", StringComparison.Ordinal) &&
    !recoverySource.Contains("ListThreadsAsync", StringComparison.Ordinal) &&
    scopeRevalidationReferenceCount == 2 &&
    appServerSource.Contains("SendRequestAsync(\"thread/read\"", StringComparison.Ordinal) &&
    appServerSource.Contains("includeTurns = false", StringComparison.Ordinal) &&
    targetScopeValidation >= 0 &&
    targetPolicyValidation > targetScopeValidation &&
    targetDispatchTransition > targetPolicyValidation &&
    recoverySource.Contains("desktopCommit.Token", StringComparison.Ordinal) &&
    !recoverySource.Contains("finalScopeValidation", StringComparison.Ordinal) &&
    recoverySource.Contains("RecoveryOperationState.Retryable", StringComparison.Ordinal),
    "archiving pauses recovery while two targeted metadata checks precede the bounded at-most-once commit");
Assert(
    ownerActivationStart >= 0 &&
    ownerStateGuardStart > ownerActivationStart &&
    finalLatestTurnValidation > ownerStateGuardStart &&
    targetScopeValidation > finalLatestTurnValidation &&
    targetDispatchTransition > targetScopeValidation &&
    desktopStartTurn > targetDispatchTransition &&
    !dispatchToStartTurnSource.Contains("EnsureOwnerAsync", StringComparison.Ordinal) &&
    !dispatchToStartTurnSource.Contains("AcquireThreadOwnerStateGuardAsync", StringComparison.Ordinal) &&
    !dispatchToStartTurnSource.Contains("ReadLatestTurnAsync", StringComparison.Ordinal) &&
    !dispatchToStartTurnSource.Contains("RevalidateTargetThreadEligibilityAsync", StringComparison.Ordinal),
    "owner activation finishes before final state checks and no navigation or state read enters the dispatch-to-start window");
Assert(
    firstUserIdleCheck > targetScopeValidation &&
    firstUserIdleCheck < targetDispatchTransition &&
    secondUserIdleCheck > targetDispatchTransition &&
    retryableAfterSecondIdleCheck > secondUserIdleCheck &&
    retryableAfterSecondIdleCheck < desktopStartTurn &&
    dispatchToStartTurnSource.Contains("ValidateUserIdleForDispatch", StringComparison.Ordinal),
    "user activity is checked before dispatch intent and again before start-turn, with an unsent retryable rollback path");
Assert(
    ownerRejectedCatchSource.Contains("RecoveryOperationState.Retryable", StringComparison.Ordinal) &&
    ownerRejectedCatchSource.Contains("DesktopOwnerUnavailable", StringComparison.Ordinal) &&
    !ownerRejectedCatchSource.Contains("isUserBlocked: true", StringComparison.Ordinal),
    "an owner lost after activation is explicitly retryable and remains eligible for automatic backoff");
Assert(
    typeof(AppSettings).GetProperty(nameof(AppSettings.ThreadEnabled))!.PropertyType
        .GetGenericTypeDefinition() == typeof(System.Collections.Concurrent.ConcurrentDictionary<,>) &&
    typeof(AppSettings).GetProperty(nameof(AppSettings.ThreadProtectionEnabled))!.PropertyType
        .GetGenericTypeDefinition() == typeof(System.Collections.Concurrent.ConcurrentDictionary<,>) &&
    !mainViewModelSource.Contains("Settings.IncludeSubAgents = value", StringComparison.Ordinal) &&
    !mainViewModelSource.Contains("Settings.ProtectNewThreadsByDefault = value", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("settings.GlobalProtectionEnabled", StringComparison.Ordinal) &&
    guardianEngineSource.Contains("settings.ThreadProtectionEnabled", StringComparison.Ordinal) &&
    !guardianEngineSource.Contains(
        "new Dictionary<string, bool>(settings.ThreadEnabled",
        StringComparison.Ordinal),
    "recovery policy snapshots copy current protection authority and exclude the legacy map");
Assert(
    guardianEngineSource.Contains("MonitorLifecycle", StringComparison.Ordinal) &&
    !mainViewModelSource.Contains("SafeDrill", StringComparison.Ordinal) &&
    !mainViewModelSource.Contains("ToggleMonitoring", StringComparison.Ordinal),
    "the production view model excludes drill infrastructure and a routine monitoring toggle");
var desktopStartTurnParameters = typeof(DesktopIpcClient)
    .GetMethod(nameof(DesktopIpcClient.AppendRecoverySuccessorAsync))!
    .GetParameters();
Assert(
    !desktopStartTurnParameters.Any(parameter => parameter.Name == "expectedFailedTurnId") &&
    desktopStartTurnParameters.Any(parameter =>
        parameter.Name == "action" && parameter.ParameterType == typeof(RecoveryActionKind)) &&
    desktopStartTurnParameters.Any(parameter =>
        parameter.Name == "rawOriginalInputJson" && parameter.ParameterType == typeof(string)) &&
    desktopStartTurnParameters.Any(parameter =>
        parameter.Name == "originalMessage" && parameter.ParameterType == typeof(string)) &&
    desktopStartTurnParameters.Any(parameter =>
        parameter.Name == "originalHasAttachments" && parameter.ParameterType == typeof(bool)) &&
    !desktopStartTurnParameters.Any(parameter => parameter.ParameterType == typeof(JsonElement)),
    "the append-only Desktop method does not pretend to bind a failed turn and retains typed input parameters for the supported continue action");
Assert(
    nativeStartTurnSource.Contains("SendNativeStartTurnCompatibleAsync", StringComparison.Ordinal) &&
    compatibleStartTurnMethodSource.Contains("method: NativeStartTurnMethod", StringComparison.Ordinal) &&
    compatibleStartTurnMethodSource.Contains("version: NativeStartTurnVersion", StringComparison.Ordinal) &&
    compatibleStartTurnMethodSource.Contains("version: LegacyNativeStartTurnVersion", StringComparison.Ordinal) &&
    compatibleStartTurnMethodSource.Contains("ShouldFallbackNativeStartTurn(exception)", StringComparison.Ordinal) &&
    nativeInputSelection >= 0 &&
    nativeStartRequest > nativeInputSelection &&
    nativeStartTurnSource.Contains("action != RecoveryActionKind.SendContinue", StringComparison.Ordinal) &&
    nativeStartTurnSource.Contains("provenUnsentOriginalReplay", StringComparison.Ordinal) &&
    nativeStartTurnSource.Contains("native-append-not-applicable", StringComparison.Ordinal) &&
    nativeStartTurnSource.Contains("clientUserMessageId", StringComparison.Ordinal) &&
    !nativeStartTurnSource.Contains("NativeEditLastUserTurnMethod", StringComparison.Ordinal) &&
    !nativeStartTurnSource.Contains("rollback", StringComparison.OrdinalIgnoreCase) &&
    !nativeStartTurnSource.Contains("Ownerless", StringComparison.OrdinalIgnoreCase) &&
    recoverySource.Contains(
        "Retried the failed turn in place through the native Codex Desktop channel",
        StringComparison.Ordinal) &&
    recoverySource.Contains(
        "Appended a continue successor through the native Codex Desktop channel",
        StringComparison.Ordinal) &&
    !recoverySource.Contains(
        "Replayed the explicitly rejected original message through the stock Codex Desktop channel",
        StringComparison.Ordinal),
    "only continuation recovery appends a stock stable-id successor; resend recovery is refused by the append path and reported as an in-place retry instead");
Assert(
    inPlaceRetryEntrySource.Contains("guardian-attachment-retry-unsupported", StringComparison.Ordinal) &&
    inPlaceRetryEntrySource.Contains("guardian-original-input-unavailable", StringComparison.Ordinal) &&
    inPlaceRetryEntrySource.Contains("MaximumOriginalMessageBytes", StringComparison.Ordinal) &&
    inPlaceRetryEntrySource.Contains(
        "await EnsureRecoveryChannelReadyAsync(cancellationToken)",
        StringComparison.Ordinal) &&
    inPlaceRetryEntrySource.Contains("Guid.TryParse(expectedFailedTurnId", StringComparison.Ordinal) &&
    !inPlaceRetryEntrySource.Contains("AppendRecoverySuccessorAsync", StringComparison.Ordinal) &&
    !inPlaceRetryEntrySource.Contains("clientUserMessageId", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("method: NativeEditLastUserTurnMethod", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("version: NativeEditLastUserTurnVersion", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("turnId = expectedFailedTurnId", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("message = originalMessage", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("shouldSendPermissionOverrides = false", StringComparison.Ordinal) &&
    inPlaceRetrySource.Split(
        "classifyCancellationForRecovery: true",
        StringSplitOptions.None).Length - 1 == 1 &&
    inPlaceRetrySource.Contains("IsInPlaceRetryTurnSuperseded(exception.Code)", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("guardian-state-changed", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("native-edit-rejected", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("DesktopIpcDeliveryStage.DispatchedUnknown", StringComparison.Ordinal) &&
    inPlaceRetrySource.Contains("code.Contains(\"Turn not found\"", StringComparison.Ordinal) &&
    !inPlaceRetrySource.Contains("thread/rollback", StringComparison.Ordinal) &&
    !inPlaceRetrySource.Contains("NativeStartTurnMethod", StringComparison.Ordinal),
    "native in-place retry dispatches the owner edit contract with a compare-and-swap turn id, fails closed on attachments, and classifies cancellation for the recovery ledger");
Assert(
    desktopIpcSource.Contains("BuildNativeOriginalInput", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("RecoveryStructuredInputCanonicalizer.Parse", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("originalHasAttachments", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("guardian-original-input-unavailable", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("canonicalDocument.RootElement.Clone()", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("Text-only recovery is a fixed stock Desktop input shape", StringComparison.Ordinal),
    "stock replay validates and clones bounded structured input and fails closed when attachments cannot be preserved");
Assert(
    recoveryConnectionAttempt >= 0 &&
    recoveryConnectionCancellation > recoveryConnectionAttempt &&
    recoveryConnectionNotDispatched > recoveryConnectionCancellation &&
    recoveryCancellationClassification == -1 &&
    recoveryStartTurnMethodSource.Split(
        "classifyCancellationForRecovery: true",
        StringSplitOptions.None).Length - 1 == 0 &&
    followUpConnectionAttempt >= 0 &&
    followUpConnectionCancellation > followUpConnectionAttempt &&
    followUpConnectionNotDispatched > followUpConnectionCancellation &&
    followUpCancellationClassification == -1 &&
    followUpStartTurnMethodSource.Split(
        "classifyCancellationForRecovery: true",
        StringSplitOptions.None).Length - 1 == 0 &&
    structuredConnectionAttempt >= 0 &&
    structuredConnectionCancellation > structuredConnectionAttempt &&
    structuredConnectionNotDispatched > structuredConnectionCancellation &&
    structuredCancellationClassification == -1 &&
    structuredStartTurnMethodSource.Split(
        "classifyCancellationForRecovery: true",
        StringSplitOptions.None).Length - 1 == 0 &&
    structuredStartTurnMethodSource.Contains("SendNativeStartTurnCompatibleAsync", StringComparison.Ordinal) &&
    structuredStartTurnMethodSource.Contains("IsStructuredWriteCurrent", StringComparison.Ordinal) &&
    compatibleStartTurnMethodSource.Split(
        "classifyCancellationForRecovery: true",
        StringSplitOptions.None).Length - 1 == 2 &&
    compatibleStartTurnMethodSource.Contains("timeout: StartTurnTimeout", StringComparison.Ordinal) &&
    compatibleStartTurnMethodSource.Contains("canStartWrite: canStartWrite", StringComparison.Ordinal) &&
    // Two in the compatible append path plus exactly one in the in-place retry dispatcher.
    desktopIpcSource.Split("classifyCancellationForRecovery: true", StringSplitOptions.None).Length - 1 == 3 &&
    sendRequestCoreSource.Contains("bool classifyCancellationForRecovery = false", StringComparison.Ordinal) &&
    recoveryCancellationCatch >= 0 &&
    callerCancellationCatch > recoveryCancellationCatch &&
    desktopIpcSource.Contains("() => dispatchMayHaveStarted = true", StringComparison.Ordinal) &&
    writeGateWait >= 0 &&
    preWriteCancellationCheck > writeGateWait &&
    writeStartingMarker > preWriteCancellationCheck &&
    pipeWriteStart > writeStartingMarker,
    "recovery cancellation is classified only after the exact pipe-write boundary while connection, write-lock, and non-recovery cancellation remain distinct");
var nativeProbeStart = desktopIpcSource.IndexOf(
    "public async Task<bool> ProbeNativeDesktopChannelAsync",
    StringComparison.Ordinal);
var nativeProbeEnd = nativeProbeStart < 0
    ? -1
    : desktopIpcSource.IndexOf(
        "public async ValueTask DisposeAsync",
        nativeProbeStart,
        StringComparison.Ordinal);
var nativeProbeSource = nativeProbeStart >= 0 && nativeProbeEnd > nativeProbeStart
    ? desktopIpcSource[nativeProbeStart..nativeProbeEnd]
    : string.Empty;
Assert(
    nativeProbeSource.Contains("_connectGate.WaitAsync", StringComparison.Ordinal) &&
    nativeProbeSource.Contains("ProbeNativeDesktopChannelCoreAsync", StringComparison.Ordinal) &&
    !nativeProbeSource.Contains("ConnectionChanged?.Invoke", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("PublishConnectionTransition", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("TryTransitionConnectionState", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("Guid.NewGuid()", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("no-client-found", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("request-version-mismatch", StringComparison.Ordinal) &&
    desktopIpcSource.Contains(
        "IsNativeChannelAvailable = startAvailable && editAvailable && versionGuardResult;",
        StringComparison.Ordinal) &&
    desktopIpcSource.Contains(
        "new[] { \"request-version-mismatch\", \"no-client-found\" }",
        StringComparison.Ordinal) &&
    !desktopIpcSource.Contains(LocalHistoryFallbackThreadId, StringComparison.OrdinalIgnoreCase),
    "channel recheck uses random nonexistent tasks only to prove stock follower routing and version guards");
Assert(
    desktopOwnerActivatorSource.Contains("codex://threads/", StringComparison.Ordinal) &&
    desktopOwnerActivatorSource.Contains("GetLastInputInfo", StringComparison.Ordinal) &&
    desktopOwnerActivatorSource.Contains("DefaultMinimumIdleTime", StringComparison.Ordinal) &&
    desktopOwnerActivatorSource.Contains("ProbeThreadOwnerAsync", StringComparison.Ordinal) &&
    desktopOwnerActivatorSource.Contains("UseShellExecute = true", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("turnId = Guid.NewGuid().ToString", StringComparison.Ordinal) &&
    !desktopIpcSource.Contains("codex-guardian-recovery", StringComparison.OrdinalIgnoreCase) &&
    !desktopIpcSource.Contains("Ownerless", StringComparison.OrdinalIgnoreCase) &&
    !recoverySource.Contains("background bridge", StringComparison.OrdinalIgnoreCase) &&
    !guardianProjectSource.Contains("CodexGuardian.DesktopBridge", StringComparison.OrdinalIgnoreCase) &&
    forbiddenProductionSourceEntries.Length == 0,
    "formal Guardian establishes a stock owner through the registered deep link without a Desktop patch, injection, or modification payload");
Assert(
    packageReleaseSource.Contains("Assert-NoDesktopModificationPayload -Root $RuntimeStage", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Assert-NoDesktopModificationPayload -Root $SourceStage", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Assert-NoDesktopModificationArchiveEntries -Path $RuntimeZip", StringComparison.Ordinal) &&
    packageReleaseSource.Contains("Assert-NoDesktopModificationArchiveEntries -Path $SourceZip", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("SkipTests", StringComparison.OrdinalIgnoreCase) &&
    packageReleaseSource.Contains("'--duration-seconds', '65'", StringComparison.Ordinal) &&
    !packageReleaseSource.Contains("CodexGuardian.DesktopBridge\\", StringComparison.OrdinalIgnoreCase) &&
    !packageReleaseSource.Contains("install-codex-desktop-bridge.ps1", StringComparison.OrdinalIgnoreCase) &&
    !packageReleaseSource.Contains("patch-codex-guardian-bridge.cjs", StringComparison.OrdinalIgnoreCase),
    "release pipeline rejects Desktop modification payloads from runtime, source, and both archives");
Assert(
    !DesktopIpcClient.IsStockOriginalMessageAvailable("   ") &&
    DesktopIpcClient.IsStockOriginalMessageAvailable("retry this") &&
    !DesktopIpcClient.IsStockOriginalMessageAvailable(new string('x', 1024 * 1024 + 1)),
    "stock text-only fallback rejects missing and oversized input without exercising a live task");
Assert(
    GuardianEngine.CanReuseTurnSnapshot(
        idleThread,
        idleThread.UpdatedAt,
        "completed",
        cacheNow,
        cacheNow.AddSeconds(10)) &&
    !GuardianEngine.CanReuseTurnSnapshot(
        idleThread with { UpdatedAt = idleThread.UpdatedAt + 1 },
        idleThread.UpdatedAt,
        "completed",
        cacheNow,
        cacheNow.AddSeconds(10)),
    "stable terminal snapshots are reused only while thread metadata remains unchanged");
Assert(
    GuardianEngine.CanReuseTurnSnapshot(
        idleThread,
        idleThread.UpdatedAt,
        "completed",
        cacheNow,
        cacheNow.AddDays(1)),
    "unchanged stable tasks do not receive a periodic turn reread");
Assert(
    GuardianEngine.CanReuseTurnSnapshot(
        idleThread with { UpdatedAt = idleThread.UpdatedAt + 1 },
        idleThread.UpdatedAt,
        "inProgress",
        cacheNow,
        cacheNow.AddSeconds(10)) &&
    !GuardianEngine.CanReuseTurnSnapshot(
        idleThread with { UpdatedAt = idleThread.UpdatedAt + 1 },
        idleThread.UpdatedAt,
        "inProgress",
        cacheNow,
        cacheNow + GuardianEngine.ActiveTurnCacheLifetime + TimeSpan.FromSeconds(1)),
    "cross-window in-progress turns avoid hot rereads but still receive a bounded fallback refresh");
var desktopFailureAt = DateTimeOffset.UtcNow;
var transportBackoff = TimeSpan.FromSeconds(9);
Assert(
    GuardianEngine.IsRecoveryRetryDue(desktopFailureAt, desktopFailureAt) &&
    GuardianEngine.IsRecoveryRetryDue(desktopFailureAt.AddSeconds(-1), desktopFailureAt) &&
    !GuardianEngine.IsRecoveryRetryDue(null, desktopFailureAt) &&
    !GuardianEngine.IsRecoveryRetryDue(desktopFailureAt.AddSeconds(1), desktopFailureAt),
    "recovery retry deadlines are consumed once only when they are actually due");
Assert(
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.DesktopOwnerUnavailable,
        desktopFailureAt,
        transportBackoff) == desktopFailureAt + transportBackoff &&
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.DesktopUnavailable,
        desktopFailureAt,
        transportBackoff) is null &&
    !GuardianEngine.IsDesktopEventDrivenFailure(RecoveryFailureKind.DesktopOwnerUnavailable) &&
    GuardianEngine.IsDesktopEventDrivenFailure(RecoveryFailureKind.DesktopUnavailable),
    "owner activation uses bounded retry while a broken Desktop channel waits for reconnect events");
Assert(
    GuardianEngine.RecoveryCooldownHealth(
        RecoveryFailureKind.DesktopOwnerUnavailable,
        TaskHealth.NeedsAttention) == TaskHealth.WaitingForDesktop &&
    GuardianEngine.RecoveryCooldownStatus(
        RecoveryFailureKind.DesktopOwnerUnavailable,
        "fallback") == GuardianEngine.WaitingForDesktopStatus &&
    GuardianEngine.RecoveryCooldownHealth(
        RecoveryFailureKind.UserActive,
        TaskHealth.NeedsAttention) == TaskHealth.WaitingForIdle &&
    GuardianEngine.RecoveryCooldownStatus(
        RecoveryFailureKind.UserActive,
        "fallback") == GuardianEngine.WaitingForUserIdleStatus,
    "owner-busy and user-active recovery backoff preserve an explicit waiting projection");
Assert(
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.UserActive,
        desktopFailureAt,
        transportBackoff) == desktopFailureAt + GuardianEngine.UserActivityRetryDelay &&
    !GuardianEngine.ShouldWakeUserIdleWaiter(
        desktopFailureAt + GuardianEngine.UserActivityRetryDelay,
        desktopFailureAt) &&
    GuardianEngine.ShouldWakeUserIdleWaiter(
        desktopFailureAt + GuardianEngine.UserActivityRetryDelay,
        desktopFailureAt + GuardianEngine.UserActivityRetryDelay),
    "active-user deferral uses a bounded deadline and does not refresh when an idle waiter clears early");
Assert(
    GuardianEngine.FullReconciliationInterval == TimeSpan.FromMinutes(15) &&
    GuardianEngine.MinimumDeadline(
        desktopFailureAt + TimeSpan.FromMinutes(15),
        desktopFailureAt + TimeSpan.FromSeconds(20)) == desktopFailureAt + TimeSpan.FromSeconds(20),
    "event-driven monitoring keeps a bounded low-frequency reconciliation deadline without periodic hot scans");
Assert(
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.TransportFailed,
        desktopFailureAt,
        transportBackoff) == desktopFailureAt + transportBackoff,
    "non-Desktop transport failures retain bounded automatic recovery backoff");
Assert(
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.StateChanged,
        desktopFailureAt,
        transportBackoff) is null &&
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.AtomicGuardUnavailable,
        desktopFailureAt,
        transportBackoff) is null &&
    GuardianEngine.ShouldLockFailureUntilNewTurn(RecoveryFailureKind.StateChanged) &&
    GuardianEngine.ShouldLockFailureUntilNewTurn(RecoveryFailureKind.AtomicGuardUnavailable),
    "state conflicts and missing atomic capability stay locked until a different failure turn arrives");
Assert(
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.PolicyChanged,
        desktopFailureAt,
        transportBackoff) is null &&
    !GuardianEngine.ShouldLockFailureUntilNewTurn(RecoveryFailureKind.PolicyChanged),
    "policy and task-scope changes stop the current dispatch without permanently locking the failed turn");
Assert(
    GuardianEngine.NextAttemptAfterFailure(
        RecoveryFailureKind.DesktopUnavailable,
        desktopFailureAt,
        transportBackoff,
        desktopSignalChanged: true) == desktopFailureAt,
    "a Desktop reconnect event racing with a channel failure cannot be lost");
Assert(
    GuardianEngine.ShouldReleaseDesktopWaiters("thread-stream-state-changed") &&
    GuardianEngine.ShouldReleaseDesktopWaiters("thread-stream-following-changed") &&
    !GuardianEngine.ShouldReleaseDesktopWaiters("client-status-changed") &&
    !GuardianEngine.ShouldReleaseDesktopWaiters("turn/completed"),
    "only task-scoped Desktop stream signals release the matching recovery waiter");
Assert(
    GuardianEngine.ComputeDesktopReconnectDelay(1) == TimeSpan.FromSeconds(2) &&
    GuardianEngine.ComputeDesktopReconnectDelay(6) == TimeSpan.FromSeconds(60) &&
    GuardianEngine.ComputeDesktopReconnectDelay(20) == TimeSpan.FromSeconds(60),
    "Desktop pipe reconnect uses a lightweight capped exponential backoff");
var unprotectedFailure = GuardianEngine.DescribeUnprotectedRecovery(
    classifier.Classify(Turn(
        "failed",
        "responseStreamDisconnected",
        confirmedTerminal: true)));
Assert(
    GuardianEngine.ActiveTaskHealth(protectionEnabled: false) == TaskHealth.Processing,
    "disabling protection does not hide the real processing state");
Assert(
    unprotectedFailure.Health == TaskHealth.NeedsAttention &&
    unprotectedFailure.Status == GuardianEngine.ProtectionPausedStatus,
    "an unprotected recoverable failure remains needs-recovery and reports protection paused");
Assert(
    GuardianEngine.GuardianBackgroundRunningStatus.Contains("background", StringComparison.OrdinalIgnoreCase),
    "Guardian-managed active turns have a dedicated background-running state");
var migrationRoot = Path.Combine(AppContext.BaseDirectory, "settings-migration-" + Guid.NewGuid().ToString("N"));
try
{
    var legacyDirectory = Path.Combine(migrationRoot, "legacy");
    Directory.CreateDirectory(legacyDirectory);
    await File.WriteAllTextAsync(
        Path.Combine(legacyDirectory, "settings.json"),
        """{"ConfigurationVersion":3,"MonitoringEnabled":true,"MonitorOnly":false,"ThreadEnabled":{"test":true}}""");
    var migratedSettings = await new SettingsService(legacyDirectory).LoadAsync();
    var currentDirectory = Path.Combine(migrationRoot, "current");
    Directory.CreateDirectory(currentDirectory);
    await File.WriteAllTextAsync(
        Path.Combine(currentDirectory, "settings.json"),
        JsonSerializer.Serialize(new
        {
            ConfigurationVersion = AppSettings.CurrentConfigurationVersion,
            MonitoringEnabled = true,
            MonitorOnly = false,
            ProtectNewThreadsByDefault = false,
            ThreadEnabled = new Dictionary<string, bool>
            {
                ["Task-A"] = true,
                ["task-a"] = false
            }
        }));
    var currentSettings = await new SettingsService(currentDirectory).LoadAsync();
    Assert(
        migratedSettings.ConfigurationVersion == AppSettings.CurrentConfigurationVersion &&
        migratedSettings.MonitorOnly &&
        migratedSettings.MonitoringEnabled &&
        !migratedSettings.ProtectNewThreadsByDefault &&
        migratedSettings.ThreadEnabled.Count == 0 &&
        migratedSettings.ThreadProtectionEnabled.Count == 0 &&
        currentSettings.MonitorOnly &&
        !currentSettings.AutomaticRecoveryEnabled &&
        !currentSettings.ProtectNewThreadsByDefault &&
        currentSettings.ThreadEnabled.Count == 1 &&
        currentSettings.ThreadEnabled.TryGetValue("TASK-A", out var duplicateProtection) &&
        !duplicateProtection,
        "legacy settings reset protection authority while v9 preserves current explicit selections");
}
finally
{
    if (Directory.Exists(migrationRoot))
    {
        Directory.Delete(migrationRoot, recursive: true);
    }
}

Assert(
    localization.LanguageCode == UiLanguages.SimplifiedChinese && localization["Nav.Overview"] == "总览",
    "default interface language is Simplified Chinese");
Assert(
    localization["Status.DiagnosticIdle"] == "尚未执行只读检查" &&
    localization["Diagnostic.Source"] == "证据来源" &&
    localization["Settings.ProtectNewThreadsByDefault"] == "自动保护新任务",
    "Chinese diagnostic resources are complete");
Assert(
    localization["Tasks.Updated"] == "\u6700\u8fd1\u6d3b\u52a8" &&
    localization["Tasks.ProtectionPaused"] == "\u4fdd\u62a4\u6682\u505c" &&
    localization["Health.WaitingForDesktop"] == "\u7b49\u5f85\u684c\u9762\u63a5\u7ba1" &&
    localization["Status.DesktopChannelConnected"] == "\u539f\u751f\u540c\u6d41\u901a\u9053\u5df2\u8fde\u63a5" &&
    localization["Status.DesktopBackgroundChannelConnected"] == "\u540e\u53f0\u540c\u6d41\u6062\u590d\u901a\u9053\u5df2\u8fde\u63a5" &&
    localization["Status.DesktopChannelUnavailable"] == "Codex \u684c\u9762\u7aef\u5df2\u8fde\u63a5\uff0c\u4f46\u539f\u751f\u901a\u9053\u4e0d\u53ef\u7528" &&
    localization["Recovery.DesktopChannelTitle"] == "\u6062\u590d\u901a\u9053" &&
    localization["Health.UserAborted"] == "\u7528\u6237\u5df2\u4e2d\u65ad" &&
    localization["Health.ContinueInterruptedUnverified"] == "continue \u5df2\u4e2d\u65ad\uff0c\u7ec8\u6001\u672a\u9a8c\u8bc1" &&
    localization["Health.ContinueAbortReasonUnverified"] == "continue \u4e2d\u6b62\u539f\u56e0\u5f85\u786e\u8ba4" &&
    localization["Engine.GuardianBackgroundRunning"] == "\u540e\u53f0\u8fd0\u884c\u4e2d",
    "Chinese task state resources separate activity, protection, and runtime state");
localization.SetLanguage(UiLanguages.English);
Assert(
    localization["Nav.Overview"] == "Overview" && localization["Shell.Conversations"] == "Conversations",
    "interface resources switch to English without running a scan");
Assert(
    localization["Status.DiagnosticIdle"] == "Read-only check has not run" &&
    localization["Diagnostic.Source"] == "Evidence source" &&
    localization["Settings.ProtectNewThreadsByDefault"] == "Protect new tasks automatically",
    "English diagnostic resources are complete");
Assert(
    localization["Tasks.Updated"] == "Last activity" &&
    localization["Tasks.ProtectionPaused"] == "Protection paused" &&
    localization["Health.WaitingForDesktop"] == "Waiting for Desktop" &&
    localization["Health.NoHistory"] == "No turn history" &&
    localization["Health.MessageUnanswered"] == "Message unanswered" &&
    localization["Health.ToolWorkInterrupted"] == "Work interrupted" &&
    localization["Health.EvidenceIncomplete"] == "Evidence incomplete" &&
    localization["Health.UserAborted"] == "Stopped by user" &&
    localization["Health.ContinueInterruptedUnverified"] == "Continue stop unverified" &&
    localization["Health.ContinueAbortReasonUnverified"] == "Continue abort unverified" &&
    localization["Status.DesktopChannelConnected"] == "Native same-stream channel connected" &&
    localization["Status.DesktopBackgroundChannelConnected"] == "Background same-stream recovery connected" &&
    localization["Status.DesktopChannelUnavailable"] == "Codex Desktop is connected, but its native channel is unavailable" &&
    localization["Recovery.DesktopChannelTitle"] == "Recovery channel" &&
    localization["Engine.GuardianBackgroundRunning"] == "Running in background",
    "English task state resources separate activity, protection, and runtime state");
localization.SetLanguage(UiLanguages.SimplifiedChinese);
Assert(
    classifier.Classify(Turn("completed", assistant: true)).Health == TaskHealth.Healthy,
    "a completed turn with a final response remains healthy");
var noOutput429Decision = classifier.Classify(Turn(
    "failed",
    "responseTooManyFailedAttempts",
    429,
    confirmedTerminal: true));
var worked429Decision = classifier.Classify(Turn(
    "failed",
    "responseTooManyFailedAttempts",
    429,
    assistant: true,
    confirmedTerminal: true));
var noOutputContinue429Decision = classifier.Classify(Turn(
    "failed",
    "responseTooManyFailedAttempts",
    429,
    "continue",
    confirmedTerminal: true));
Assert(
    noOutput429Decision.Action == RecoveryActionKind.ResendOriginal &&
    worked429Decision.Action == RecoveryActionKind.SendContinue &&
    noOutputContinue429Decision.Action == RecoveryActionKind.ResendContinue,
    "429 establishes recoverability while work evidence selects original replay, continue, or exact continue replay");
const string delegatedSourceThreadId = "019f97d8-85bc-7741-8549-bee07cddf47f";
var delegatedContinue = $$"""
    <codex_delegation>
      <source_thread_id>{{delegatedSourceThreadId}}</source_thread_id>
      <input>continue</input>
    </codex_delegation>
    """;
var delegatedPrompt = $$"""
    <codex_delegation>
      <source_thread_id>{{delegatedSourceThreadId}}</source_thread_id>
      <input>retry this task</input>
    </codex_delegation>
    """;
Assert(
    RecoveryClassifier.NormalizeRecoveryInput(delegatedContinue) == "continue" &&
    classifier.Classify(Turn(
        "failed",
        "responseTooManyFailedAttempts",
        429,
        delegatedContinue,
        confirmedTerminal: true)).Action ==
        RecoveryActionKind.ResendContinue,
    "a valid Codex delegation unwraps an inner continue before classifying the failed turn");
Assert(
    RecoveryClassifier.NormalizeRecoveryInput(delegatedPrompt) == "retry this task" &&
    classifier.Classify(Turn(
        "failed",
        "responseTooManyFailedAttempts",
        429,
        delegatedPrompt,
        confirmedTerminal: true)).Action ==
        RecoveryActionKind.ResendOriginal,
    "a valid Codex delegation unwraps an ordinary inner prompt before classifying the failed turn");
var malformedDelegations = new[]
{
    $$"""
      <codex_delegation>
        <source_thread_id>{{delegatedSourceThreadId}}</source_thread_id>
        <input>continue</input
      </codex_delegation>
      """,
    $$"""
      <codex_delegation>
        <source_thread_id>{{delegatedSourceThreadId}}</source_thread_id>
        <input>continue</input>
        <input>continue</input>
      </codex_delegation>
      """,
    """
      <codex_delegation>
        <source_thread_id>not-a-guid</source_thread_id>
        <input>continue</input>
      </codex_delegation>
      """,
    $$"""
      <codex_delegation>
        <input>continue</input>
        <source_thread_id>{{delegatedSourceThreadId}}</source_thread_id>
      </codex_delegation>
      """
};
Assert(
    malformedDelegations.All(input =>
        RecoveryClassifier.NormalizeRecoveryInput(input) == input.Trim() &&
        classifier.Classify(Turn(
            "failed",
            "responseTooManyFailedAttempts",
            429,
            input,
            confirmedTerminal: true)).Action ==
            RecoveryActionKind.ResendOriginal),
    "malformed, duplicate-node, non-GUID, and reordered delegation envelopes are never unwrapped");
Assert(
    classifier.Classify(Turn(
        "failed",
        "responseStreamDisconnected",
        assistant: true,
        confirmedTerminal: true)).Action == RecoveryActionKind.SendContinue,
    "disconnect after assistant output sends a new continue");
Assert(
    classifier.Classify(Turn(
        "failed",
        "responseStreamDisconnected",
        work: true,
        confirmedTerminal: true)).Action == RecoveryActionKind.SendContinue,
    "disconnect after tool work avoids duplicate side effects");
Assert(
    classifier.Classify(Turn("failed", "unauthorized", 401)).Action == RecoveryActionKind.None,
    "non-transient authorization failure is not retried");
var privatePermanentError = "paid balance insufficient: private request text";
var permanentDecision = classifier.Classify(Turn("failed", "billing", 403, error: privatePermanentError));
Assert(
    permanentDecision.Action == RecoveryActionKind.None &&
    permanentDecision.Reason.Contains("HTTP 403", StringComparison.Ordinal) &&
    !permanentDecision.Reason.Contains(privatePermanentError, StringComparison.Ordinal),
    "permanent provider failures retain structured evidence without exposing raw provider text");
Assert(
    classifier.Classify(Turn("failed", confirmedTerminal: true)).Action == RecoveryActionKind.None,
    "unknown failed terminal state is blocked unless transient evidence is explicit");
Assert(
    classifier.Classify(Turn("interrupted")).Action == RecoveryActionKind.None &&
    classifier.Classify(Turn("interrupted")).Health == TaskHealth.Unknown &&
    classifier.Classify(Turn("interrupted", confirmedTerminal: true)).Action ==
        RecoveryActionKind.None &&
    classifier.Classify(Turn(
        "interrupted",
        "responseStreamDisconnected",
        confirmedTerminal: true)).Action == RecoveryActionKind.ResendOriginal,
    "interrupted state requires both an exact local terminal and explicit transient evidence");
Assert(
    classifier.Classify(Turn("cancelled")).Action == RecoveryActionKind.None &&
    classifier.Classify(Turn("canceled")).Action == RecoveryActionKind.None &&
    classifier.Classify(Turn("aborted")) is
    {
        Action: RecoveryActionKind.None,
        Health: TaskHealth.ManualReview,
        IsTransient: false
    },
    "explicit stop aliases never enter an unsupported recovery retry loop");
Assert(
    classifier.Classify(Turn(RecoveryClassifier.UnverifiedAbortStatus)) is
    {
        Action: RecoveryActionKind.None,
        Health: TaskHealth.Unknown,
        IsTransient: false
    },
    "an abort event with an unknown reason remains fail-closed");
Assert(
    classifier.Classify(Turn("failed", "other", 403, error: "paid balance insufficient")).Action == RecoveryActionKind.None,
    "403 paid balance failure remains permanently blocked");
Assert(
    classifier.Classify(Turn(
        "failed",
        error: "unexpected status 403 Forbidden: insufficient balance")).Action == RecoveryActionKind.None,
    "403 balance text remains permanently blocked when structured status is absent");
Assert(
    RecoveryExecutionResult.Failed("user is active", isUserBlocked: true).IsUserBlocked,
    "user-blocked recovery uses a typed flag instead of localized message parsing");

var recoveryMessageId = AppServerClient.CreateRecoveryMessageId(
    "thread-a",
    "failed-turn-a",
    RecoveryActionKind.SendContinue);
Assert(
    Guid.TryParse(recoveryMessageId, out _) &&
    recoveryMessageId == AppServerClient.CreateRecoveryMessageId(
        "thread-a",
        "failed-turn-a",
        RecoveryActionKind.SendContinue) &&
    recoveryMessageId != AppServerClient.CreateRecoveryMessageId(
        "thread-a",
        "failed-turn-b",
        RecoveryActionKind.SendContinue),
    "background recovery uses deterministic per-failure client message ids for durable reconciliation");
Assert(
    SettingsService.NormalizeContinueMessage("   ") == "continue",
    "an empty custom continue message safely falls back to continue");
var codexSessionsDataDirectory = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".codex",
    "sessions",
    "guardian-data");
var settingsRejectedSessionsDirectory = false;
var journalRejectedSessionsDirectory = false;
try
{
    _ = new SettingsService(codexSessionsDataDirectory);
}
catch (ArgumentException)
{
    settingsRejectedSessionsDirectory = true;
}

try
{
    _ = new RecoveryOperationJournal(@"\\?\" + codexSessionsDataDirectory);
}
catch (ArgumentException)
{
    journalRejectedSessionsDirectory = true;
}

Assert(
    settingsRejectedSessionsDirectory && journalRejectedSessionsDirectory,
    "settings and recovery journal reject normal and extended paths inside Codex sessions");
var deviceAliasRejected = false;
try
{
    _ = new SettingsService(@"\\.\C:\CodexGuardian\unsafe-device-alias");
}
catch (ArgumentException)
{
    deviceAliasRejected = true;
}

Assert(deviceAliasRejected, "Guardian data paths reject Windows device namespace aliases");
var reparseTestRoot = Path.Combine(
    Path.GetTempPath(),
    "CodexGuardian",
    "data-path-reparse-" + Guid.NewGuid().ToString("N"));
var oldCodexHome = Environment.GetEnvironmentVariable("CODEX_HOME");
var junctionCreated = false;
var junctionRejected = false;
var resolvedCodexHomeRejected = false;
var junctionPath = Path.Combine(reparseTestRoot, "sessions-link");
try
{
    var fakeCodexHome = Path.Combine(reparseTestRoot, "codex-home");
    var fakeSessions = Path.Combine(fakeCodexHome, "sessions");
    Directory.CreateDirectory(fakeSessions);
    Environment.SetEnvironmentVariable("CODEX_HOME", fakeCodexHome);

    try
    {
        _ = new SettingsService(Path.Combine(fakeSessions, "guardian-data"));
    }
    catch (ArgumentException)
    {
        resolvedCodexHomeRejected = true;
    }

    var command = new System.Diagnostics.ProcessStartInfo(
        Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe")
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    command.ArgumentList.Add("/d");
    command.ArgumentList.Add("/c");
    command.ArgumentList.Add("mklink");
    command.ArgumentList.Add("/J");
    command.ArgumentList.Add(junctionPath);
    command.ArgumentList.Add(fakeSessions);
    using var junctionProcess = System.Diagnostics.Process.Start(command);
    if (junctionProcess is not null)
    {
        await junctionProcess.WaitForExitAsync();
        junctionCreated = junctionProcess.ExitCode == 0 && Directory.Exists(junctionPath);
    }

    if (junctionCreated)
    {
        try
        {
            _ = new RecoveryOperationJournal(Path.Combine(junctionPath, "guardian-data"));
        }
        catch (Exception exception) when (exception is IOException or ArgumentException)
        {
            junctionRejected = true;
        }
    }
}
finally
{
    Environment.SetEnvironmentVariable("CODEX_HOME", oldCodexHome);
    if (Directory.Exists(junctionPath))
    {
        Directory.Delete(junctionPath);
    }

    if (Directory.Exists(reparseTestRoot))
    {
        Directory.Delete(reparseTestRoot, recursive: true);
    }
}

Assert(
    junctionCreated && junctionRejected && resolvedCodexHomeRejected,
    "data-directory safety rejects junction traversal and the resolved target of CODEX_HOME sessions");
var atomicContinueBlock = RecoveryService.ValidateAtomicRecoveryCapability(
    supportsAtomicRecoveryPrecondition: false,
    RecoveryActionKind.SendContinue);
var atomicOriginalBlock = RecoveryService.ValidateAtomicRecoveryCapability(
    supportsAtomicRecoveryPrecondition: false,
    RecoveryActionKind.ResendOriginal);
Assert(
    atomicContinueBlock is
    {
        Success: false,
        IsUserBlocked: true,
        FailureKind: RecoveryFailureKind.AtomicGuardUnavailable
    } &&
    atomicOriginalBlock is
    {
        Success: false,
        IsUserBlocked: true,
        FailureKind: RecoveryFailureKind.AtomicGuardUnavailable
    } &&
    RecoveryService.ValidateAtomicRecoveryCapability(
        supportsAtomicRecoveryPrecondition: true,
        RecoveryActionKind.SendContinue) is null,
    "strict atomic capability remains unavailable without being the automatic-recovery feature gate");
var automaticRecoveryActions = new[]
{
    RecoveryActionKind.ResendOriginal,
    RecoveryActionKind.SendContinue,
    RecoveryActionKind.ResendContinue
};
var stockRecoveryCapabilities = automaticRecoveryActions
    .Select(DesktopIpcClient.DescribeStockRecoveryCapabilities)
    .ToArray();
var inPlaceRetryCapabilities = stockRecoveryCapabilities.Where(capabilities =>
    capabilities.Action is RecoveryActionKind.ResendOriginal or RecoveryActionKind.ResendContinue)
    .ToArray();
var appendOnlyCapability = stockRecoveryCapabilities.Single(capabilities =>
    capabilities.Action == RecoveryActionKind.SendContinue);
Assert(
    inPlaceRetryCapabilities.Length == 2 &&
    inPlaceRetryCapabilities.All(capabilities =>
        capabilities.SupportsNativeInPlaceRetry &&
        capabilities.SupportsExpectedFailedTurnCompareAndStart &&
        capabilities.SupportsExpectedFailedTurnOwnerValidation &&
        capabilities.SupportsReceiverIdempotency &&
        capabilities.PreservesStructuredOriginalInput &&
        capabilities.SupportsNativeResend &&
        !capabilities.SupportsProvenUnsentReplay &&
        !capabilities.ReturnsCommittedTurnId &&
        capabilities.IsInPlaceRetryConfirmable &&
        capabilities.HasCommittedTurnEvidence &&
        capabilities.IsStrictAtomicRecoveryEligible &&
        capabilities.IsGuardedAutomaticRecoveryEligible) &&
    inPlaceRetryCapabilities.All(capabilities =>
        RecoveryService.ValidateGuardedAutomaticRecoveryCapability(
            capabilities,
            capabilities.Action) is null) &&
    !appendOnlyCapability.SupportsNativeInPlaceRetry &&
    !appendOnlyCapability.SupportsExpectedFailedTurnCompareAndStart &&
    !appendOnlyCapability.SupportsExpectedFailedTurnOwnerValidation &&
    !appendOnlyCapability.SupportsReceiverIdempotency &&
    !appendOnlyCapability.IsInPlaceRetryConfirmable &&
    !appendOnlyCapability.IsStrictAtomicRecoveryEligible &&
    appendOnlyCapability.ReturnsCommittedTurnId &&
    appendOnlyCapability.HasCommittedTurnEvidence &&
    appendOnlyCapability.IsGuardedAutomaticRecoveryEligible &&
    RecoveryService.ValidateGuardedAutomaticRecoveryCapability(
        appendOnlyCapability,
        RecoveryActionKind.SendContinue) is null &&
    stockRecoveryCapabilities.All(capabilities =>
        capabilities.ExecutesThroughDesktopOwner && capabilities.IsTrustedDesktopProtocol),
    "resend recovery is proven through the owner's in-place retry contract without a committed turn id, while continuation recovery stays append-only with one");
var provenUnsentOriginalCapabilities =
    DesktopIpcClient.DescribeStockRecoveryCapabilities(RecoveryActionKind.ResendOriginal) with
    {
        SupportsProvenUnsentReplay = true
    };
Assert(
    provenUnsentOriginalCapabilities.SupportsProvenUnsentReplay &&
    provenUnsentOriginalCapabilities.IsGuardedAutomaticRecoveryEligible &&
    RecoveryService.ValidateGuardedAutomaticRecoveryCapability(
        provenUnsentOriginalCapabilities,
        RecoveryActionKind.ResendOriginal,
        provenUnsentOriginalReplay: true) is null,
    "an explicit no-work HTTP 429 can use the guarded proven-unsent original replay capability");
var unavailableCapabilityBlocks = automaticRecoveryActions
    .Select(action => RecoveryService.ValidateGuardedAutomaticRecoveryCapability(
        RecoveryTransportCapabilities.Unavailable(action),
        action))
    .ToArray();
Assert(
    unavailableCapabilityBlocks.All(result => result is
    {
        Success: false,
        IsUserBlocked: true,
        FailureKind: RecoveryFailureKind.DesktopIncompatible
    }),
    "the pure guarded-capability validator rejects unavailable actions before any IPC client or process exists");

await WithRecoveryJournalTestAsync("missing journal", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var snapshot = await journal.ReadAsync();
    Assert(
        snapshot is
        {
            ReadStatus: RecoveryJournalReadStatus.Missing,
            Generation: 0,
            RequiresConservativeRecovery: false
        } &&
        snapshot.Records.Count == 0 &&
        !File.Exists(journal.JournalPath),
        "a missing recovery journal reads as an empty in-memory snapshot without creating a file");
});

await WithRecoveryJournalTestAsync("idempotent prepare", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var operationId = Guid.NewGuid().ToString("D");
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    const string originalMessage = "JOURNAL-RAW-MESSAGE-MUST-NOT-BE-PERSISTED";
    var inputHash = RecoveryOperationJournal.ComputeInputHash(originalMessage);
    var first = await journal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        inputHash);
    var firstSnapshot = await journal.ReadAsync();
    var second = await journal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        inputHash);
    var secondSnapshot = await journal.ReadAsync();
    var persistedText = await File.ReadAllTextAsync(journal.JournalPath);
    Assert(
        first.Created &&
        !second.Created &&
        first.Record == second.Record &&
        firstSnapshot.Generation == secondSnapshot.Generation &&
        secondSnapshot.Records.Count == 1 &&
        !persistedText.Contains(originalMessage, StringComparison.Ordinal),
        "GetOrCreate is idempotent per failed turn, does not grow generation, and persists only the input hash");
});

await WithRecoveryJournalTestAsync("dispatch attempt count", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("retry original"));
    var dispatch = await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    Assert(
        dispatch is
        {
            Changed: true,
            Record.State: RecoveryOperationState.Dispatching,
            Record.AttemptCount: 1,
            Generation: 2
        },
        "Prepared to Dispatching persists exactly one dispatch attempt");
});

await WithRecoveryJournalTestAsync("explicit rejection retry", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("retry after rejection"));
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    var retryable = await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Retryable);
    var retryDispatch = await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Retryable,
        RecoveryOperationState.Dispatching);
    Assert(
        retryable is { Changed: true, Record.State: RecoveryOperationState.Retryable } &&
        retryDispatch is
        {
            Changed: true,
            Record.State: RecoveryOperationState.Dispatching,
            Record.AttemptCount: 2
        },
        "an explicit transport rejection can move Dispatching to Retryable and dispatch once more");
});

await WithRecoveryJournalTestAsync("uncertain recovery lock", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendContinue,
        RecoveryOperationJournal.ComputeInputHash("continue"));
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Uncertain);
    var redispatchRejected = await ThrowsAsync<InvalidOperationException>(() =>
        journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Uncertain,
            RecoveryOperationState.Dispatching));
    var snapshot = await journal.ReadAsync();
    Assert(
        redispatchRejected &&
        snapshot.Records.Single().State == RecoveryOperationState.Uncertain &&
        snapshot.Records.Single().AttemptCount == 1,
        "an uncertain start-turn operation cannot be dispatched blindly a second time");
});

await WithRecoveryJournalTestAsync("uncertain continue is not redispatched", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var operationId = Guid.NewGuid().ToString("D");
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.SendContinue,
        RecoveryOperationJournal.ComputeInputHash("continue"),
        clientMessageId: operationId);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching,
        clientMessageId: operationId);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Uncertain);
    var retryDispatchRejected = await ThrowsAsync<InvalidOperationException>(() =>
        journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Uncertain,
            RecoveryOperationState.Dispatching,
            clientMessageId: operationId));
    var snapshot = await journal.ReadAsync();
    Assert(
        retryDispatchRejected &&
        snapshot.Records.Single().State == RecoveryOperationState.Uncertain &&
        snapshot.Records.Single().AttemptCount == 1,
        "SendContinue uses its stable id for reconciliation but never redispatches an uncertain request");
});

await WithRecoveryJournalTestAsync("confirmed turn identity", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("confirm recovery"));
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    var missingTurnRejected = await ThrowsAsync<InvalidOperationException>(() =>
        journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Dispatching,
            RecoveryOperationState.Confirmed));
    var committedTurnId = Guid.NewGuid().ToString("D");
    var confirmed = await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Confirmed,
        newTurnId: committedTurnId);
    Assert(
        missingTurnRejected &&
        confirmed is { Changed: true, Record.State: RecoveryOperationState.Confirmed } &&
        string.Equals(confirmed.Record.NewTurnId, committedTurnId, StringComparison.OrdinalIgnoreCase),
        "Confirmed is rejected without the committed turn id and persists it when supplied");
});

await WithRecoveryJournalTestAsync("corrupted journal recovery quarantine", async root =>
{
    Directory.CreateDirectory(root);
    var journalPath = Path.Combine(root, "recovery-operations.json");
    await File.WriteAllTextAsync(journalPath, "{corrupted-json");
    var journal = new RecoveryOperationJournal(root);
    var corrupted = await journal.ReadAsync();
    var prepared = await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("recovery after corruption"));
    Assert(
        corrupted is
        {
            ReadStatus: RecoveryJournalReadStatus.Corrupted,
            RequiresConservativeRecovery: true
        } &&
        prepared is
        {
            Created: true,
            RequiresReconciliation: true,
            Record.State: RecoveryOperationState.Uncertain
        },
        "a syntactically corrupted journal quarantines a new recovery operation as Uncertain");
});

await WithRecoveryJournalTestAsync("checksum tamper recovery quarantine", async root =>
{
    var originalJournal = new RecoveryOperationJournal(root);
    await originalJournal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("persist before tamper"));
    var document = JsonNode.Parse(await File.ReadAllTextAsync(originalJournal.JournalPath))!.AsObject();
    document["checksum"] = new string('0', 64);
    await File.WriteAllTextAsync(originalJournal.JournalPath, document.ToJsonString());

    var reloadedJournal = new RecoveryOperationJournal(root);
    var corrupted = await reloadedJournal.ReadAsync();
    var prepared = await reloadedJournal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        RecoveryActionKind.ResendContinue,
        RecoveryOperationJournal.ComputeInputHash("continue after tamper"));
    Assert(
        corrupted.ReadStatus == RecoveryJournalReadStatus.Corrupted &&
        corrupted.RequiresConservativeRecovery &&
        prepared is
        {
            Created: true,
            RequiresReconciliation: true,
            Record.State: RecoveryOperationState.Uncertain
        },
        "a checksum-tampered journal quarantines a new recovery operation as Uncertain");
});

await WithRecoveryJournalTestAsync("healthy backup recovery", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var operationId = Guid.NewGuid().ToString("D");
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    var inputHash = RecoveryOperationJournal.ComputeInputHash("backup recovery");
    await journal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        inputHash);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Accepted);
    Assert(File.Exists(journal.BackupPath), "atomic journal replacement retains a previous generation");

    await File.WriteAllTextAsync(journal.JournalPath, "{broken-primary");
    var recoveredJournal = new RecoveryOperationJournal(root);
    var recovered = await recoveredJournal.ReadAsync();
    var existing = await recoveredJournal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        inputHash);
    var redispatchRejected = await ThrowsAsync<InvalidOperationException>(() =>
        recoveredJournal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Uncertain,
            RecoveryOperationState.Dispatching));
    Assert(
        recovered.ReadStatus == RecoveryJournalReadStatus.RecoveredFromBackup &&
        existing is
        {
            Created: false,
            RequiresReconciliation: true,
            Record.State: RecoveryOperationState.Uncertain
        } &&
        redispatchRejected,
        "a healthy previous generation recovers a damaged primary and promotes possible dispatches to Uncertain");
});

await WithRecoveryJournalTestAsync("concurrent prepare", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var operationId = Guid.NewGuid().ToString("D");
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    var inputHash = RecoveryOperationJournal.ComputeInputHash("one concurrent operation");
    var preparations = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ =>
        journal.GetOrCreateAsync(
            operationId,
            threadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal,
            inputHash)));
    var snapshot = await journal.ReadAsync();
    Assert(
        preparations.Count(result => result.Created) == 1 &&
        preparations.All(result => result.Record.OperationId == operationId) &&
        snapshot.Generation == 1 &&
        snapshot.Records.Count == 1,
        "concurrent GetOrCreate calls for one failure generation persist exactly one operation");
});

await WithRecoveryJournalTestAsync("terminal count pruning", async root =>
{
    var journal = new RecoveryOperationJournal(root, maximumRecords: 2, maximumFileBytes: 64 * 1024);
    var pendingThreadA = Guid.NewGuid().ToString("D");
    var pendingTurnA = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        pendingThreadA,
        pendingTurnA,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("pending-a"));

    var terminalThread = Guid.NewGuid().ToString("D");
    var terminalTurn = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        terminalThread,
        terminalTurn,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("terminal"));
    var committedTurnId = Guid.NewGuid().ToString("D");
    await journal.TryTransitionAsync(
        terminalThread,
        terminalTurn,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        terminalThread,
        terminalTurn,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Confirmed,
        newTurnId: committedTurnId);
    await journal.AbandonSupersededAsync(terminalThread, committedTurnId);

    var pendingThreadB = Guid.NewGuid().ToString("D");
    var pendingTurnB = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        pendingThreadB,
        pendingTurnB,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("pending-b"));
    var afterTerminalPrune = await journal.ReadAsync();
    var pendingOverflowRejected = await ThrowsAsync<InvalidOperationException>(() =>
        journal.GetOrCreateAsync(
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash("pending-c")));
    Assert(
        afterTerminalPrune.Records.Count == 2 &&
        afterTerminalPrune.Records.All(record => record.State == RecoveryOperationState.Prepared) &&
        afterTerminalPrune.Records.Any(record => record.FailedTurnId == pendingTurnA) &&
        afterTerminalPrune.Records.Any(record => record.FailedTurnId == pendingTurnB) &&
        pendingOverflowRejected,
        "the record limit prunes terminal history but never evicts pending operations");
});

await WithRecoveryJournalTestAsync("terminal byte pruning", async root =>
{
    const long byteLimit = 1024;
    var journal = new RecoveryOperationJournal(root, maximumRecords: 16, maximumFileBytes: byteLimit);

    async Task AddConfirmedAsync(string payload)
    {
        var threadId = Guid.NewGuid().ToString("D");
        var failedTurnId = Guid.NewGuid().ToString("D");
        await journal.GetOrCreateAsync(
            Guid.NewGuid().ToString("D"),
            threadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash(payload));
        var committedTurnId = Guid.NewGuid().ToString("D");
        await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Prepared,
            RecoveryOperationState.Dispatching);
        await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Dispatching,
            RecoveryOperationState.Confirmed,
            newTurnId: committedTurnId);
        await journal.AbandonSupersededAsync(threadId, committedTurnId);
    }

    await AddConfirmedAsync("terminal-byte-a");
    await AddConfirmedAsync("terminal-byte-b");
    var pendingThread = Guid.NewGuid().ToString("D");
    var pendingTurn = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        pendingThread,
        pendingTurn,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("pending-byte-record"));
    var persistedPendingKeys = new List<(string ThreadId, string FailedTurnId)>
    {
        (pendingThread, pendingTurn)
    };
    var pendingByteOverflowRejected = false;
    for (var index = 0; index < 16; index++)
    {
        var nextThread = Guid.NewGuid().ToString("D");
        var nextTurn = Guid.NewGuid().ToString("D");
        try
        {
            await journal.GetOrCreateAsync(
                Guid.NewGuid().ToString("D"),
                nextThread,
                nextTurn,
                RecoveryActionKind.ResendOriginal,
                RecoveryOperationJournal.ComputeInputHash("pending-byte-" + index));
            persistedPendingKeys.Add((nextThread, nextTurn));
        }
        catch (InvalidOperationException)
        {
            pendingByteOverflowRejected = true;
            break;
        }
    }

    var snapshot = await journal.ReadAsync();
    Assert(
        pendingByteOverflowRejected &&
        snapshot.Records.Count == persistedPendingKeys.Count &&
        snapshot.Records.All(record => record.State == RecoveryOperationState.Prepared) &&
        persistedPendingKeys.All(key => snapshot.Records.Any(record =>
            record.ThreadId == key.ThreadId &&
            record.FailedTurnId == key.FailedTurnId)) &&
        new FileInfo(journal.JournalPath).Length <= byteLimit,
        "the byte limit removes terminal history and rejects overflow before evicting any pending operation");
});

await WithRecoveryJournalTestAsync("accepted terminal", async root =>
{
    var journal = new RecoveryOperationJournal(root, maximumRecords: 1, maximumFileBytes: 64 * 1024);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("accepted edit"));
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    var accepted = await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Accepted);
    var generationAfterAccepted = accepted.Generation;
    var redispatchRejected = await ThrowsAsync<InvalidOperationException>(() =>
        journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Accepted,
            RecoveryOperationState.Dispatching));
    var pruneBeforeSupersededRejected = await ThrowsAsync<InvalidOperationException>(() =>
        journal.GetOrCreateAsync(
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash("must not prune acknowledged tombstone")));
    var successorTurnId = Guid.NewGuid().ToString("D");
    var abandoned = await journal.AbandonSupersededAsync(threadId, successorTurnId);
    await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        threadId,
        successorTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("successor"));
    var snapshot = await journal.ReadAsync();
    Assert(
        accepted is
        {
            Changed: true,
            Record.State: RecoveryOperationState.Accepted,
            Record.NewTurnId: null
        } &&
        redispatchRejected &&
        pruneBeforeSupersededRejected &&
        abandoned == 1 &&
        snapshot.Generation > generationAfterAccepted &&
        snapshot.Records.Single() is { State: RecoveryOperationState.Prepared } successor &&
        successor.FailedTurnId == successorTurnId,
        "Accepted cannot redispatch or be pruned until a successor turn closes its at-most-once tombstone");
});

await WithRecoveryJournalTestAsync("abandon superseded", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var currentTurnId = Guid.NewGuid().ToString("D");
    var oldPreparedTurnId = Guid.NewGuid().ToString("D");
    var oldRetryableTurnId = Guid.NewGuid().ToString("D");
    var terminalTurnId = Guid.NewGuid().ToString("D");
    var otherThreadId = Guid.NewGuid().ToString("D");
    var otherTurnId = Guid.NewGuid().ToString("D");

    async Task PrepareAsync(string operationThreadId, string failedTurnId, string payload)
    {
        await journal.GetOrCreateAsync(
            Guid.NewGuid().ToString("D"),
            operationThreadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash(payload));
    }

    await PrepareAsync(threadId, oldPreparedTurnId, "old-prepared");
    await PrepareAsync(threadId, oldRetryableTurnId, "old-retryable");
    await journal.TryTransitionAsync(
        threadId,
        oldRetryableTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        threadId,
        oldRetryableTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Retryable);
    await PrepareAsync(threadId, currentTurnId, "current");
    await PrepareAsync(threadId, terminalTurnId, "terminal");
    await journal.TryTransitionAsync(
        threadId,
        terminalTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        threadId,
        terminalTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Accepted);
    await PrepareAsync(otherThreadId, otherTurnId, "other-thread");

    var changed = await journal.AbandonSupersededAsync(threadId, currentTurnId);
    var firstSnapshot = await journal.ReadAsync();
    var generationAfterFirstCall = firstSnapshot.Generation;
    var changedAgain = await journal.AbandonSupersededAsync(threadId, currentTurnId);
    var secondSnapshot = await journal.ReadAsync();
    RecoveryOperationState StateOf(string operationThreadId, string failedTurnId) =>
        secondSnapshot.Records.Single(record =>
            record.ThreadId == operationThreadId && record.FailedTurnId == failedTurnId).State;
    Assert(
        changed == 3 &&
        changedAgain == 0 &&
        secondSnapshot.Generation == generationAfterFirstCall &&
        StateOf(threadId, oldPreparedTurnId) == RecoveryOperationState.Abandoned &&
        StateOf(threadId, oldRetryableTurnId) == RecoveryOperationState.Abandoned &&
        StateOf(threadId, currentTurnId) == RecoveryOperationState.Prepared &&
        StateOf(otherThreadId, otherTurnId) == RecoveryOperationState.Prepared &&
        StateOf(threadId, terminalTurnId) == RecoveryOperationState.Abandoned,
        "AbandonSuperseded closes older pending and acknowledged operations while preserving the current generation");
});

await WithRecoveryJournalTestAsync("confirmed recovery successor chain guard", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    var operationId = Guid.NewGuid().ToString("D");
    var recoveryTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("confirmed recovery"),
        clientMessageId: operationId);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Confirmed,
        newTurnId: recoveryTurnId);
    var before = await journal.ReadAsync();

    var failedRecoveryTurn = new TurnSnapshot(
        recoveryTurnId,
        Status: "failed",
        ErrorMessage: "high demand",
        ErrorCode: "internal_server_error",
        HttpStatusCode: 429,
        UserText: "retry this",
        HasAttachments: false,
        HasAssistantOutput: false,
        HasWorkOutput: false,
        OutputFingerprint: "recovery-successor",
        StartedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        CompletedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        HasConfirmedLocalTerminal: true,
        UserMessageClientIds: [operationId]);
    var first = await journal.ReconcileCurrentTurnAsync(
        threadId,
        recoveryTurnId,
        failedRecoveryTurn.UserMessageClientIds,
        closeRecoverySuccessor: false);
    var second = await journal.ReconcileCurrentTurnAsync(
        threadId,
        recoveryTurnId,
        failedRecoveryTurn.UserMessageClientIds,
        closeRecoverySuccessor: false);
    using var log = new GuardianLog(root);
    await using var stateReader = new AppServerClient(new CodexCliLocator(), log);
    await using var desktop = new DesktopIpcClient(log);
    var recovery = new RecoveryService(
        stateReader,
        desktop,
        new DesktopThreadOwnerActivator(desktop, log),
        journal,
        log);
    var directExecution = await recovery.ExecuteAsync(
        new ThreadSummary(
            threadId,
            "recovery chain guard",
            "retry this",
            "C:\\Work",
            "appServer",
            CreatedAt: 1,
            UpdatedAt: 2,
            IsSubAgent: false,
            IsEphemeral: false),
        failedRecoveryTurn,
        new RecoveryDecision(
            RecoveryActionKind.ResendOriginal,
            TaskHealth.NeedsAttention,
            "retryable provider failure",
            IsTransient: true),
        continueMessage: "continue",
        includeSubAgents: false,
        scopeGeneration: 0,
        isDispatchAllowed: static () => true);
    var after = await journal.ReadAsync();
    var silentRecoveryTurn = failedRecoveryTurn with
    {
        Status = RecoveryClassifier.IncompleteTerminalStatus,
        ErrorMessage = null,
        ErrorCode = null,
        HttpStatusCode = null
    };

    Assert(
        first is
        {
            RecoverySuccessor.State: RecoveryOperationState.Confirmed,
            IsExactSuccessorMatch: true,
            RecoverySuccessorClosed: false,
            AbandonedCount: 0
        } &&
        second is { RecoverySuccessor.State: RecoveryOperationState.Confirmed, AbandonedCount: 0 } &&
        GuardianEngine.IsFailedRecoverySuccessor(failedRecoveryTurn, first.RecoverySuccessor) &&
        GuardianEngine.IsFailedRecoverySuccessor(silentRecoveryTurn, first.RecoverySuccessor) &&
        directExecution is
        {
            Success: false,
            IsUserBlocked: true,
            FailureKind: RecoveryFailureKind.StateChanged
        } &&
        after.Generation == before.Generation &&
        after.Records.Single() is { State: RecoveryOperationState.Confirmed } retained &&
        retained.NewTurnId == recoveryTurnId &&
        after.Records.All(record => record.FailedTurnId != recoveryTurnId),
        "a failed or silently completed recovery successor remains a tombstone and cannot start a recovery chain");
});

await WithRecoveryJournalTestAsync("unresolved recovery successor tombstones", async root =>
{
    var journal = new RecoveryOperationJournal(root);

    async Task<(string ThreadId, string ClientMessageId, string SuccessorTurnId, long Generation)>
        CreateAsync(RecoveryOperationState terminalState, string payload)
    {
        var threadId = Guid.NewGuid().ToString("D");
        var failedTurnId = Guid.NewGuid().ToString("D");
        var operationId = Guid.NewGuid().ToString("D");
        await journal.GetOrCreateAsync(
            operationId,
            threadId,
            failedTurnId,
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash(payload),
            clientMessageId: operationId);
        await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Prepared,
            RecoveryOperationState.Dispatching);
        await journal.TryTransitionAsync(
            threadId,
            failedTurnId,
            RecoveryOperationState.Dispatching,
            terminalState);
        return (threadId, operationId, Guid.NewGuid().ToString("D"), (await journal.ReadAsync()).Generation);
    }

    var accepted = await CreateAsync(RecoveryOperationState.Accepted, "accepted recovery");
    var acceptedMatch = await journal.ReconcileCurrentTurnAsync(
        accepted.ThreadId,
        accepted.SuccessorTurnId,
        [accepted.ClientMessageId],
        closeRecoverySuccessor: false);
    var afterAccepted = await journal.ReadAsync();

    var uncertain = await CreateAsync(RecoveryOperationState.Uncertain, "uncertain recovery");
    var uncertainMatch = await journal.ReconcileCurrentTurnAsync(
        uncertain.ThreadId,
        uncertain.SuccessorTurnId,
        currentTurnClientMessageIds: null,
        closeRecoverySuccessor: false);
    var afterUncertain = await journal.ReadAsync();

    Assert(
        acceptedMatch is
        {
            RecoverySuccessor.State: RecoveryOperationState.Accepted,
            IsExactSuccessorMatch: true,
            RecoverySuccessorClosed: false,
            AbandonedCount: 0
        } &&
        afterAccepted.Generation == accepted.Generation &&
        uncertainMatch is
        {
            RecoverySuccessor.State: RecoveryOperationState.Uncertain,
            IsExactSuccessorMatch: false,
            RecoverySuccessorClosed: false,
            AbandonedCount: 0
        } &&
        afterUncertain.Generation == uncertain.Generation &&
        afterUncertain.Records.Any(record =>
            record.ThreadId == accepted.ThreadId && record.State == RecoveryOperationState.Accepted) &&
        afterUncertain.Records.Any(record =>
            record.ThreadId == uncertain.ThreadId && record.State == RecoveryOperationState.Uncertain),
        "Accepted and Uncertain successor tombstones survive exact or conservative failed-successor attribution");
});

await WithRecoveryJournalTestAsync("ordinary failure after confirmed recovery", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    var operationId = Guid.NewGuid().ToString("D");
    var committedTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("old recovery"),
        clientMessageId: operationId);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Confirmed,
        newTurnId: committedTurnId);

    var ordinaryTurnId = Guid.NewGuid().ToString("D");
    var ordinaryFailure = new TurnSnapshot(
        ordinaryTurnId,
        Status: "failed",
        ErrorMessage: "connection reset",
        ErrorCode: "stream_error",
        HttpStatusCode: null,
        UserText: "a later user request",
        HasAttachments: false,
        HasAssistantOutput: false,
        HasWorkOutput: false,
        OutputFingerprint: "ordinary-failure",
        StartedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        CompletedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        HasConfirmedLocalTerminal: true,
        UserMessageClientIds: [Guid.NewGuid().ToString("D")]);
    var reconciliation = await journal.ReconcileCurrentTurnAsync(
        threadId,
        ordinaryTurnId,
        ordinaryFailure.UserMessageClientIds,
        closeRecoverySuccessor: false);
    var nextOperation = await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        threadId,
        ordinaryTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("ordinary later failure"));
    var snapshot = await journal.ReadAsync();

    Assert(
        reconciliation is
        {
            RecoverySuccessor: null,
            RecoverySuccessorClosed: false,
            AbandonedCount: 1
        } &&
        !GuardianEngine.IsFailedRecoverySuccessor(ordinaryFailure, reconciliation.RecoverySuccessor) &&
        nextOperation is { Created: true, Record.State: RecoveryOperationState.Prepared } &&
        snapshot.Records.Any(record =>
            record.FailedTurnId == failedTurnId && record.State == RecoveryOperationState.Abandoned) &&
        snapshot.Records.Any(record =>
            record.FailedTurnId == ordinaryTurnId && record.State == RecoveryOperationState.Prepared),
        "an unrelated later user failure closes the old Confirmed tombstone and remains independently recoverable");
});

await WithRecoveryJournalTestAsync("confirmed successful recovery closure", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    var threadId = Guid.NewGuid().ToString("D");
    var failedTurnId = Guid.NewGuid().ToString("D");
    var operationId = Guid.NewGuid().ToString("D");
    var recoveryTurnId = Guid.NewGuid().ToString("D");
    await journal.GetOrCreateAsync(
        operationId,
        threadId,
        failedTurnId,
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("successful recovery"),
        clientMessageId: operationId);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Prepared,
        RecoveryOperationState.Dispatching);
    await journal.TryTransitionAsync(
        threadId,
        failedTurnId,
        RecoveryOperationState.Dispatching,
        RecoveryOperationState.Confirmed,
        newTurnId: recoveryTurnId);

    var closed = await journal.ReconcileCurrentTurnAsync(
        threadId,
        recoveryTurnId,
        [operationId],
        closeRecoverySuccessor: true);
    var snapshot = await journal.ReadAsync();
    Assert(
        closed is
        {
            RecoverySuccessor.State: RecoveryOperationState.Confirmed,
            IsExactSuccessorMatch: true,
            RecoverySuccessorClosed: true,
            AbandonedCount: 1
        } &&
        snapshot.Records.Single().State == RecoveryOperationState.Abandoned,
        "a locally confirmed successful recovery closes its retained tombstone only after success is proven");
});

await WithRecoveryJournalTestAsync("initialization marker without journal", async root =>
{
    var journal = new RecoveryOperationJournal(root);
    Directory.CreateDirectory(root);
    await File.WriteAllTextAsync(journal.InitializationMarkerPath, "schema=1\n");
    var missingPrimary = await journal.ReadAsync();
    var operation = await journal.GetOrCreateAsync(
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        RecoveryActionKind.ResendOriginal,
        RecoveryOperationJournal.ComputeInputHash("recovery after missing primary"));
    Assert(
        missingPrimary is
        {
            ReadStatus: RecoveryJournalReadStatus.Corrupted,
            RequiresConservativeRecovery: true
        } &&
        operation is
        {
            Created: true,
            RequiresReconciliation: true,
            Record.State: RecoveryOperationState.Uncertain
        },
        "an initialization marker without the primary journal quarantines a new recovery operation as Uncertain");
});

await WithRecoveryJournalTestAsync("journal temp cleanup", async root =>
{
    Directory.CreateDirectory(root);
    var staleJournalTemp = Path.Combine(root, ".recovery-operations.json.1234.abcdef.tmp");
    var staleMarkerTemp = Path.Combine(root, ".recovery-operations.initialized.1234.abcdef.tmp");
    var unrelatedTemp = Path.Combine(root, ".unrelated-recovery-operations.json.1234.abcdef.tmp");
    var similarlyNamedFile = Path.Combine(root, ".recovery-operations.json.1234.abcdef.keep");
    await File.WriteAllTextAsync(staleJournalTemp, "stale");
    await File.WriteAllTextAsync(staleMarkerTemp, "stale");
    await File.WriteAllTextAsync(unrelatedTemp, "keep");
    await File.WriteAllTextAsync(similarlyNamedFile, "keep");
    var journal = new RecoveryOperationJournal(root);
    var snapshot = await journal.ReadAsync();
    Assert(
        snapshot.ReadStatus == RecoveryJournalReadStatus.Missing &&
        !File.Exists(staleJournalTemp) &&
        !File.Exists(staleMarkerTemp) &&
        File.Exists(unrelatedTemp) &&
        File.Exists(similarlyNamedFile),
        "journal startup removes only precisely named journal and marker temporary files");
});

await WithRecoveryJournalTestAsync("unsupported journal schema", async root =>
{
    Directory.CreateDirectory(root);
    var journal = new RecoveryOperationJournal(root);
    var unsupportedBytes = Encoding.UTF8.GetBytes("""
        {"schemaVersion":999,"generation":77,"requiresConservativeRecovery":false,"checksum":"ignored","records":[],"futureField":{"preserve":true}}
        """);
    await File.WriteAllBytesAsync(journal.JournalPath, unsupportedBytes);
    var snapshot = await journal.ReadAsync();
    var createRejected = await ThrowsAsync<NotSupportedException>(() =>
        journal.GetOrCreateAsync(
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"),
            RecoveryActionKind.ResendOriginal,
            RecoveryOperationJournal.ComputeInputHash("must not write")));
    var bytesAfterRejectedWrite = await File.ReadAllBytesAsync(journal.JournalPath);
    Assert(
        snapshot is
        {
            ReadStatus: RecoveryJournalReadStatus.UnsupportedSchema,
            RequiresConservativeRecovery: true
        } &&
        createRejected &&
        unsupportedBytes.AsSpan().SequenceEqual(bytesAfterRejectedWrite),
        "an unknown schema with future fields stays UnsupportedSchema and rejects writes without changing its bytes");
});

var protocolRejectedCodes = new[]
{
    "no-client-found",
    "request-version-mismatch",
    "no-handler-for-request",
    "guardian-state-changed",
    "guardian-owner-unavailable",
    "guardian-original-input-unavailable",
    "guardian-invalid-request",
    "native-edit-rejected"
};
Assert(
    protocolRejectedCodes.All(code =>
        DesktopIpcClient.GetProtocolDeliveryStage(code) == DesktopIpcDeliveryStage.Rejected) &&
    DesktopIpcClient.GetProtocolDeliveryStage("future-desktop-error") ==
        DesktopIpcDeliveryStage.DispatchedUnknown &&
    DesktopIpcClient.GetProtocolDeliveryStage("native-edit-ack-invalid") ==
        DesktopIpcDeliveryStage.DispatchedUnknown,
    "Desktop protocol errors are Rejected only on the strict whitelist and unknown codes default to DispatchedUnknown");
Assert(
    DesktopIpcClient.GetRecoveryCancellationDeliveryStage(writeStarted: false) ==
        DesktopIpcDeliveryStage.NotDispatched &&
    DesktopIpcClient.GetRecoveryCancellationDeliveryStage(writeStarted: true) ==
        DesktopIpcDeliveryStage.DispatchedUnknown,
    "Desktop recovery cancellation is retryable before pipe.WriteAsync starts and uncertain once writing may have started");

Assert(
    desktopIpcSource.Contains("public async Task<DesktopThreadOwnerProbeResult> ProbeThreadOwnerAsync", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("turnId = Guid.NewGuid().ToString(\"D\")", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("DesktopThreadOwnerProbeStatus.Unavailable", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("DesktopThreadOwnerProbeStatus.Incompatible", StringComparison.Ordinal) &&
    desktopIpcSource.Contains("DesktopThreadOwnerProbeStatus.TransientFailure", StringComparison.Ordinal) &&
    !nativeStartTurnSource.Contains("editResponse", StringComparison.Ordinal) &&
    !nativeStartTurnSource.Contains("native-edit", StringComparison.Ordinal),
    "owner discovery uses an intentionally nonexistent turn while the recovery commit path never edits a turn");

var parsedClientId = Guid.NewGuid().ToString("D");
var parsedTurn = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"failed",
      "items":[
        {
          "type":"userMessage",
          "clientId":"{{parsedClientId}}",
          "content":[{"type":"text","text":"continue"}]
        },
        {
          "type":"userMessage",
          "clientId":"{{parsedClientId}}",
          "content":[]
        },
        {
          "type":"userMessage",
          "clientId":null,
          "content":[]
        }
      ]
    }
    """));
Assert(
    parsedTurn.UserText == "continue" &&
    parsedTurn.UserMessageClientIds is { Count: 1 } &&
    parsedTurn.UserMessageClientIds.Contains(parsedClientId, StringComparer.OrdinalIgnoreCase) &&
    parsedTurn.HasAmbiguousActivity &&
    classifier.Classify(parsedTurn).Action == RecoveryActionKind.None,
    "summary parsing deduplicates client ids but blocks automatic replay of multiple user-message boundaries");
var reasoningOnlyTurn = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"failed",
      "error":{"message":"stream disconnected","codexErrorInfo":"responseStreamDisconnected"},
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"do work"}]},
        {"type":"reasoning","id":"reasoning-1","summary":["partial analysis"]}
      ]
    }
    """));
Assert(
    reasoningOnlyTurn.HasWorkOutput &&
    reasoningOnlyTurn.HasReasoningOutput &&
    classifier.Classify(reasoningOnlyTurn with { HasConfirmedLocalTerminal = true }).Action ==
        RecoveryActionKind.SendContinue,
    "a reasoning-only failed turn continues instead of editing and replaying the original prompt");

var silentCompletedTurn = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"completed",
      "items":[
        {"type":"userMessage","clientId":"{{Guid.NewGuid():D}}","content":[{"type":"text","text":"retry the original request"}]}
      ]
    }
    """));
var silentCompletedTerminal = new LocalConversationTerminalEvent(
    "silent-thread",
    silentCompletedTurn.Id,
    "rollout.jsonl",
    2000,
    DateTimeOffset.UtcNow,
    silentCompletedTurn with
    {
        UserText = string.Empty,
        RawUserInputJson = null,
        HasUserMessage = false,
        HasCompleteItemEvidence = false
    });
var reconciledSilentCompleted = LocalConversationHistoryReader.ReconcileLatestTurn(
    silentCompletedTurn,
    silentCompletedTerminal);
Assert(
    reconciledSilentCompleted is
    {
        Status: RecoveryClassifier.IncompleteTerminalStatus,
        HasUserMessage: true,
        HasFinalAssistantOutput: false,
        HasConfirmedLocalTerminal: true
    } &&
    classifier.Classify(reconciledSilentCompleted).Action == RecoveryActionKind.None,
    "a locally confirmed completed turn without transient failure evidence remains blocked");

var silentContinueTurn = silentCompletedTurn with
{
    Id = Guid.NewGuid().ToString("D"),
    UserText = "continue",
    RawUserInputJson = "[{\"type\":\"text\",\"text\":\"continue\"}]",
    IsSingleTextUserInput = true
};
var silentContinueTerminal = silentCompletedTerminal with
{
    TurnId = silentContinueTurn.Id,
    Turn = silentContinueTurn with
    {
        UserText = string.Empty,
        RawUserInputJson = null,
        HasUserMessage = false,
        HasCompleteItemEvidence = false
    }
};
var reconciledSilentContinue = LocalConversationHistoryReader.ReconcileLatestTurn(
    silentContinueTurn,
    silentContinueTerminal);
Assert(
    classifier.Classify(reconciledSilentContinue).Action == RecoveryActionKind.None,
    "a locally confirmed unanswered continue remains blocked without transient failure evidence");

var metadataOnlyFailure = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"failed",
      "error":{"message":"stream disconnected","codexErrorInfo":"responseStreamDisconnected"},
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"ordinary prompt"}]},
        {"type":"hookPrompt","id":"hook-1","fragments":[]},
        {"type":"contextCompaction","id":"compact-1"},
        {"type":"subAgentActivity","id":"child-state-1"}
      ]
    }
    """));
Assert(
    !metadataOnlyFailure.HasWorkOutput &&
    !metadataOnlyFailure.HasAmbiguousActivity &&
    classifier.Classify(metadataOnlyFailure with { HasConfirmedLocalTerminal = true }).Action ==
        RecoveryActionKind.ResendOriginal,
    "hook, compaction, and inherited child status do not masquerade as replay-sensitive work");

var unknownItemFailure = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"failed",
      "error":{"message":"stream disconnected","codexErrorInfo":"responseStreamDisconnected"},
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"ordinary prompt"}]},
        {"type":"futureUnknownWorkItem","id":"future-1"}
      ]
    }
    """));
Assert(
    unknownItemFailure.HasAmbiguousActivity &&
    classifier.Classify(unknownItemFailure with { HasConfirmedLocalTerminal = true }) is
    {
        Action: RecoveryActionKind.None,
        Health: TaskHealth.ManualReview
    },
    "an unknown turn item fails closed instead of guessing resend versus continue");

var missingItemTypeFailure = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"failed",
      "error":{"message":"stream disconnected","codexErrorInfo":"responseStreamDisconnected"},
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"ordinary prompt"}]},
        {"id":"protocol-item-without-type"}
      ]
    }
    """));
Assert(
    missingItemTypeFailure.HasAmbiguousActivity &&
    classifier.Classify(missingItemTypeFailure with { HasConfirmedLocalTerminal = true }).Health ==
        TaskHealth.ManualReview,
    "a turn item without a protocol type is evidence-incomplete and cannot trigger recovery");

var missingUserInputFailure = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"failed",
      "error":{"message":"stream disconnected","codexErrorInfo":"responseStreamDisconnected"},
      "items":[{"type":"reasoning","id":"reasoning-without-user-input"}]
    }
    """));
Assert(
    !missingUserInputFailure.HasUserMessage &&
    classifier.Classify(missingUserInputFailure with { HasConfirmedLocalTerminal = true }) is
    {
        Action: RecoveryActionKind.None,
        Health: TaskHealth.ManualReview
    },
    "work evidence without a confirmed user-message input fails closed");

var attachedContinueFailure = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"failed",
      "error":{"message":"rate limited","codexErrorInfo":"responseTooManyFailedAttempts","httpStatusCode":429},
      "items":[
        {"type":"userMessage","content":[
          {"type":"text","text":"continue"},
          {"type":"localImage","path":"redacted-test-path"}
        ]}
      ]
    }
    """));
Assert(
    attachedContinueFailure.HasAttachments &&
    classifier.Classify(attachedContinueFailure with { HasConfirmedLocalTerminal = true }).Action ==
        RecoveryActionKind.ResendOriginal,
    "continue with structured attachments replays its original input instead of synthesizing plain continue");

var completedWithFinalAnswer = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"completed",
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"ordinary prompt"}]},
        {"type":"agentMessage","id":"answer-1","phase":"final_answer","text":"finished"}
      ]
    }
    """));
Assert(
    completedWithFinalAnswer.HasFinalAssistantOutput &&
    classifier.Classify(completedWithFinalAnswer).Health == TaskHealth.Healthy,
    "only a completed turn with final-answer evidence is classified as normally completed");

var legacyCompletedWithoutPhase = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"completed",
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"ordinary prompt"}]},
        {"type":"agentMessage","id":"legacy-answer-1","text":"finished"}
      ]
    }
    """));
Assert(
    legacyCompletedWithoutPhase.HasReliableFinalOutput &&
    classifier.Classify(legacyCompletedWithoutPhase).Health == TaskHealth.Healthy,
    "a legacy provider that omits agent-message phase remains compatible when it returns assistant text");

var completedWithUnknownAgentPhase = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"completed",
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"ordinary prompt"}]},
        {"type":"agentMessage","id":"future-1","phase":"future_provider_phase","text":"not proven final"}
      ]
    }
    """));
Assert(
    !completedWithUnknownAgentPhase.HasFinalAssistantOutput &&
    completedWithUnknownAgentPhase.HasAmbiguousActivity &&
    classifier.Classify(completedWithUnknownAgentPhase with
    {
        ErrorCode = "responseStreamDisconnected",
        HasConfirmedLocalTerminal = true
    }) is
    {
        Action: RecoveryActionKind.None,
        Health: TaskHealth.ManualReview
    },
    "an unknown agent-message phase fails closed instead of masquerading as a final answer");

var completedWithCommentary = AppServerClient.ParseTurn(Json($$"""
    {
      "id":"{{Guid.NewGuid():D}}",
      "status":"completed",
      "items":[
        {"type":"userMessage","content":[{"type":"text","text":"ordinary prompt"}]},
        {"type":"agentMessage","id":"commentary-1","phase":"commentary","text":"still working"}
      ]
    }
    """));
var completedWithCommentaryTerminal = silentCompletedTerminal with
{
    TurnId = completedWithCommentary.Id,
    Turn = completedWithCommentary with
    {
        UserText = string.Empty,
        RawUserInputJson = null,
        HasUserMessage = false,
        HasAssistantOutput = false,
        HasCommentaryOutput = false,
        HasCompleteItemEvidence = false
    }
};
var reconciledCommentaryTerminal = LocalConversationHistoryReader.ReconcileLatestTurn(
    completedWithCommentary,
    completedWithCommentaryTerminal);
Assert(
    reconciledCommentaryTerminal?.Status == RecoveryClassifier.IncompleteTerminalStatus &&
    classifier.Classify(reconciledCommentaryTerminal with
    {
        ErrorCode = "responseStreamDisconnected"
    }).Action == RecoveryActionKind.SendContinue,
    "commentary without a final answer recovers only with explicit stream-failure evidence");

var completedLatestTurn = Turn("completed");
var failedLatestTurn = Turn("FAILED");
var interruptedLatestTurn = Turn("Interrupted");
var silentCompletedLatestTurn = completedLatestTurn with
{
    Status = RecoveryClassifier.IncompleteTerminalStatus
};
var completedLatestResult = RecoveryService.ValidateLatestTurn(
    completedLatestTurn,
    completedLatestTurn.Id);
var failedLatestResult = RecoveryService.ValidateLatestTurn(
    failedLatestTurn,
    failedLatestTurn.Id);
var interruptedLatestResult = RecoveryService.ValidateLatestTurn(
    interruptedLatestTurn,
    interruptedLatestTurn.Id);
var silentCompletedLatestResult = RecoveryService.ValidateLatestTurn(
    silentCompletedLatestTurn,
    silentCompletedLatestTurn.Id);
Assert(
    completedLatestResult is
    {
        Success: false,
        IsUserBlocked: true,
        FailureKind: RecoveryFailureKind.StateChanged
    } &&
    failedLatestResult is null &&
    interruptedLatestResult is null &&
    silentCompletedLatestResult is null,
    "pre-send validation rejects ordinary completion and accepts failed, interrupted, or confirmed silent completion");

var confirmedMaskedProviderFailure = completedLatestTurn with
{
    Status = "failed",
    ErrorMessage = "We're currently experiencing high demand, which may cause temporary errors.",
    ErrorCode = "serverOverloaded",
    HasConfirmedLocalTerminal = true
};
var reconciledDispatchFailure = RecoveryService.ReconcileLatestTurnForDispatch(
    completedLatestTurn,
    confirmedMaskedProviderFailure);
var newerCompletedDispatchTurn = completedLatestTurn with
{
    CompletedAt = confirmedMaskedProviderFailure.CompletedAt + 1
};
var newerCompletedDispatchResult = RecoveryService.ReconcileLatestTurnForDispatch(
    newerCompletedDispatchTurn,
    confirmedMaskedProviderFailure);
var unconfirmedDispatchResult = RecoveryService.ReconcileLatestTurnForDispatch(
    completedLatestTurn,
    confirmedMaskedProviderFailure with { HasConfirmedLocalTerminal = false });
Assert(
    ReferenceEquals(confirmedMaskedProviderFailure, reconciledDispatchFailure) &&
    RecoveryService.ValidateLatestTurn(reconciledDispatchFailure, completedLatestTurn.Id) is null &&
    ReferenceEquals(newerCompletedDispatchTurn, newerCompletedDispatchResult) &&
    RecoveryService.ValidateLatestTurn(newerCompletedDispatchResult, completedLatestTurn.Id) is not null &&
    ReferenceEquals(completedLatestTurn, unconfirmedDispatchResult),
    "pre-send validation preserves a confirmed same-time provider failure but rejects newer or unconfirmed completed state");

var appServerCompletedTurn = new TurnSnapshot(
    "same-turn",
    "completed",
    null,
    null,
    null,
    "finish the task",
    false,
    false,
    true,
    "remote-fingerprint",
    100,
    200,
    HasUserMessage: true,
    HasReasoningOutput: true,
    HasCompleteItemEvidence: true,
    IsSingleTextUserInput: true);
var localFailedTerminalAgainstCompleted = new LocalConversationTerminalEvent(
    "thread",
    "same-turn",
    "rollout.jsonl",
    1000,
    DateTimeOffset.UtcNow,
    appServerCompletedTurn with
    {
        Status = "failed",
        ErrorMessage = "exceeded retry limit, last status: 429 Too Many Requests",
        HttpStatusCode = 429
    });
var completedProviderFailure = LocalConversationHistoryReader.ReconcileLatestTurn(
    appServerCompletedTurn,
    localFailedTerminalAgainstCompleted);
Assert(
    completedProviderFailure is
    {
        Status: "failed",
        HttpStatusCode: 429,
        HasConfirmedLocalTerminal: true
    } &&
    classifier.Classify(completedProviderFailure).Action == RecoveryActionKind.SendContinue,
    "a same-time local provider failure overrides stock Desktop completed/error-null metadata");

var newerDesktopCompletion = appServerCompletedTurn with { CompletedAt = 201 };
var staleCompletedConflict = LocalConversationHistoryReader.ReconcileLatestTurn(
    newerDesktopCompletion,
    localFailedTerminalAgainstCompleted);
Assert(
    ReferenceEquals(newerDesktopCompletion, staleCompletedConflict) &&
    staleCompletedConflict is { Status: "completed", HasConfirmedLocalTerminal: false },
    "a strictly newer Desktop completion vetoes a stale local failure for the same turn id");

var completedBeforeOutputTurn = appServerCompletedTurn with
{
    Id = "completed-before-output",
    UserText = "<codex_delegation><input>probe</input></codex_delegation>",
    HasAssistantOutput = false,
    HasWorkOutput = false,
    HasReasoningOutput = false,
    HasToolActivity = false,
    OutputFingerprint = "empty-fingerprint"
};
var failedBeforeOutputTerminal = localFailedTerminalAgainstCompleted with
{
    TurnId = completedBeforeOutputTurn.Id,
    Turn = completedBeforeOutputTurn with
    {
        Status = "failed",
        ErrorMessage = "We're currently experiencing high demand, which may cause temporary errors.",
        ErrorCode = "serverOverloaded",
        HttpStatusCode = null
    }
};
var reconciledBeforeOutputFailure = LocalConversationHistoryReader.ReconcileLatestTurn(
    completedBeforeOutputTurn,
    failedBeforeOutputTerminal);
Assert(
    reconciledBeforeOutputFailure is
    {
        Status: "failed",
        ErrorCode: "serverOverloaded",
        HasAssistantOutput: false,
        HasWorkOutput: false,
        HasConfirmedLocalTerminal: true
    } &&
    classifier.Classify(reconciledBeforeOutputFailure).Action == RecoveryActionKind.ResendOriginal,
    "a Desktop-completed provider failure before output is recovered by appending the original input");
Assert(
    GuardianEngine.ShouldReadLocalTerminal("completed") &&
    GuardianEngine.ShouldReadLocalTerminal("FAILED") &&
    GuardianEngine.ShouldReadLocalTerminal("Interrupted") &&
    !GuardianEngine.ShouldReadLocalTerminal("inProgress") &&
    !GuardianEngine.ShouldReadLocalTerminal("cancelled") &&
    !GuardianEngine.ShouldReadLocalTerminal("unknown"),
    "engine reconciliation reads local evidence for all terminal states that may carry or hide provider failures");
var activeProviderTurn = appServerCompletedTurn with
{
    Status = "inProgress",
    CompletedAt = null
};
var activeProviderFailureTerminal = localFailedTerminalAgainstCompleted with
{
    Turn = localFailedTerminalAgainstCompleted.Turn with { CompletedAt = 200 }
};
var activeWithoutExplicitWake = LocalConversationHistoryReader.ReconcileLatestTurn(
    activeProviderTurn,
    activeProviderFailureTerminal);
var activeWithExplicitWake = LocalConversationHistoryReader.ReconcileLatestTurn(
    activeProviderTurn,
    activeProviderFailureTerminal,
    allowActiveLocalTerminal: true);
Assert(
    activeWithoutExplicitWake is { Status: "inProgress" } &&
    activeWithExplicitWake is { Status: "failed", HttpStatusCode: 429, HasConfirmedLocalTerminal: true } &&
    GuardianEngine.ShouldForceTerminalVerification(ThreadRefreshKind.StateChanged, "same-turn") &&
    GuardianEngine.ShouldForceTerminalVerification(ThreadRefreshKind.RetryRecovery, "same-turn") &&
    !GuardianEngine.ShouldForceTerminalVerification(ThreadRefreshKind.StateChanged, null) &&
    !GuardianEngine.ShouldForceTerminalVerification(ThreadRefreshKind.RetryFollowUp, "same-turn"),
    "a matching local terminal bypasses the active fast path only for an exact state or recovery-retry wake");

var appServerInterruptedTurn = appServerCompletedTurn with
{
    Status = "interrupted",
    CompletedAt = null
};
var confirmedFailedTerminal = localFailedTerminalAgainstCompleted with
{
    Turn = localFailedTerminalAgainstCompleted.Turn with { CompletedAt = 200 }
};
var reconciledTurn = LocalConversationHistoryReader.ReconcileLatestTurn(
    appServerInterruptedTurn,
    confirmedFailedTerminal);
Assert(
    reconciledTurn is
    {
        Status: "failed",
        HttpStatusCode: 429,
        HasWorkOutput: true,
        HasConfirmedLocalTerminal: true
    } &&
    classifier.Classify(reconciledTurn).Action == RecoveryActionKind.SendContinue,
    "a matching local terminal can confirm an independent interrupted snapshot without losing work evidence");
var localUserAbortTerminal = confirmedFailedTerminal with
{
    Turn = confirmedFailedTerminal.Turn with
    {
        Status = "aborted",
        ErrorMessage = null,
        ErrorCode = null,
        HttpStatusCode = null
    }
};
var reconciledUserAbort = LocalConversationHistoryReader.ReconcileLatestTurn(
    appServerInterruptedTurn,
    localUserAbortTerminal);
var reconciledUserAbortDecision = classifier.Classify(reconciledUserAbort);
Assert(
    reconciledUserAbort is
    {
        Status: "aborted",
        HasConfirmedLocalTerminal: true
    } &&
    reconciledUserAbortDecision is
    {
        Action: RecoveryActionKind.None,
        Health: TaskHealth.ManualReview
    },
    "a matching local user abort overrides interrupted metadata but remains ineligible for recovery");
var localUnverifiedAbortTerminal = localUserAbortTerminal with
{
    Turn = localUserAbortTerminal.Turn with
    {
        Status = RecoveryClassifier.UnverifiedAbortStatus
    }
};
var reconciledUnverifiedAbort = LocalConversationHistoryReader.ReconcileLatestTurn(
    appServerInterruptedTurn,
    localUnverifiedAbortTerminal);
Assert(
    reconciledUnverifiedAbort is
    {
        Status: RecoveryClassifier.UnverifiedAbortStatus,
        HasConfirmedLocalTerminal: false
    } &&
    classifier.Classify(reconciledUnverifiedAbort).Action == RecoveryActionKind.None,
    "an exact abort event with an unknown reason blocks older terminal fallback and automatic recovery");
var appServerProviderFailure = appServerInterruptedTurn with { Status = "failed" };
var userAbortedProviderFailure = LocalConversationHistoryReader.ReconcileLatestTurn(
    appServerProviderFailure,
    localUserAbortTerminal);
Assert(
    userAbortedProviderFailure is
    {
        Status: "aborted",
        HasConfirmedLocalTerminal: true
    } &&
    classifier.Classify(userAbortedProviderFailure).Action == RecoveryActionKind.None,
    "a confirmed local user abort fail-closes a conflicting app-server provider failure");
var reliableCompletedConflict = appServerCompletedTurn with
{
    HasFinalAssistantOutput = true,
    HasAssistantOutput = true
};
Assert(
    ReferenceEquals(
        reliableCompletedConflict,
        LocalConversationHistoryReader.ReconcileLatestTurn(
            reliableCompletedConflict,
            localUserAbortTerminal)),
    "a confirmed final answer is not downgraded by an equal-time abort race");
var activeConflict = LocalConversationHistoryReader.ReconcileLatestTurn(
    appServerInterruptedTurn with { Status = "inProgress" },
    confirmedFailedTerminal);
Assert(
    activeConflict is { Status: "inProgress", HasConfirmedLocalTerminal: false },
    "a local terminal never overrides a live in-progress turn");
var mismatchedTerminal = confirmedFailedTerminal with
{
    TurnId = "older-turn",
    Turn = confirmedFailedTerminal.Turn with { Id = "older-turn" }
};
Assert(
    ReferenceEquals(
        appServerCompletedTurn,
        LocalConversationHistoryReader.ReconcileLatestTurn(appServerCompletedTurn, mismatchedTerminal)),
    "stale local terminal from another turn cannot override the latest app-server turn");

await WithRecoveryJournalTestAsync("local user abort terminal", async root =>
{
    var threadId = Guid.NewGuid().ToString();
    var unknownAbortTurnId = Guid.NewGuid().ToString();
    var confirmedAbortTurnId = Guid.NewGuid().ToString();
    var sessionDay = Path.Combine(root, "sessions", "2026", "07", "29");
    Directory.CreateDirectory(sessionDay);
    var rolloutPath = Path.Combine(
        sessionDay,
        $"rollout-2026-07-29T00-00-00-{threadId}.jsonl");
    var unknownAbortLine = JsonSerializer.Serialize(new
    {
        timestamp = DateTimeOffset.UtcNow.AddSeconds(-1).ToString("O"),
        type = "event_msg",
        payload = new
        {
            type = "turn_aborted",
            turn_id = unknownAbortTurnId,
            reason = "future_abort_reason",
            completed_at = 200L
        }
    });
    await File.WriteAllTextAsync(rolloutPath, unknownAbortLine + "\n");
    var reader = new LocalConversationHistoryReader(Path.Combine(root, "sessions"));
    var unknownAbort = await reader.ReadLatestTerminalEventAsync(threadId);

    var confirmedAbortLine = JsonSerializer.Serialize(new
    {
        timestamp = DateTimeOffset.UtcNow.ToString("O"),
        type = "event_msg",
        payload = new
        {
            type = "turn_aborted",
            turn_id = confirmedAbortTurnId,
            reason = "interrupted",
            started_at = 100L,
            completed_at = 201L
        }
    });
    await File.AppendAllTextAsync(rolloutPath, confirmedAbortLine + "\n");
    var confirmedAbort = await reader.ReadLatestTerminalEventAsync(threadId);
    Assert(
        unknownAbort is not null &&
        unknownAbort.Turn.Status == RecoveryClassifier.UnverifiedAbortStatus &&
        unknownAbort.Turn.CompletedAt == 200 &&
        !unknownAbort.Turn.HasConfirmedLocalTerminal &&
        unknownAbort.TurnId == unknownAbortTurnId &&
        confirmedAbort is not null &&
        confirmedAbort.Turn.Status == "aborted" &&
        confirmedAbort.Turn.StartedAt == 100 &&
        confirmedAbort.Turn.CompletedAt == 201 &&
        !confirmedAbort.Turn.HasConfirmedLocalTerminal &&
        confirmedAbort.TurnId == confirmedAbortTurnId,
        "local tail parsing preserves unknown aborts as blocked evidence and recognizes the known user-abort reason");
});

var deterministicRecovery = new DeterministicRecoveryFixture(classifier);
var deterministicReport = deterministicRecovery.RunAll();
Assert(deterministicReport.Results.Count == 4, "deterministic recovery fixture includes all four classifier scenarios");
Assert(
    deterministicReport.IsNonInvasive && deterministicReport.ExternalOperationCount == 0,
    "deterministic recovery fixture reports zero protocol, UI, input, and pointer operations");

var retryOriginalFixture = deterministicRecovery.RetryOriginalAfter429();
Assert(
    retryOriginalFixture.Decision.Action == RecoveryActionKind.ResendOriginal &&
    retryOriginalFixture.ClassifierMatchedExpectation &&
    retryOriginalFixture.SimulatedState.Health == TaskHealth.Recovering,
    "deterministic fixture classifies a no-output 429 for original-input replay");

var streamContinueFixture = deterministicRecovery.ContinueAfterStreamDisconnect();
Assert(
    streamContinueFixture.Decision.Action == RecoveryActionKind.SendContinue &&
    streamContinueFixture.ClassifierMatchedExpectation &&
    streamContinueFixture.IsNonInvasive,
    "deterministic fixture classifies an output stream disconnect for continue");

var retryContinueFixture = deterministicRecovery.RetryContinueAfter429();
Assert(
    retryContinueFixture.Decision.Action == RecoveryActionKind.ResendContinue &&
    retryContinueFixture.ClassifierMatchedExpectation &&
    retryContinueFixture.IsNonInvasive,
    "deterministic fixture classifies a failed continue input for exact replay");

var forbiddenFixture = deterministicRecovery.Forbidden403();
Assert(
    forbiddenFixture.Decision.Action == RecoveryActionKind.None &&
    forbiddenFixture.Decision.Health == TaskHealth.ManualReview &&
    forbiddenFixture.ClassifierMatchedExpectation &&
    forbiddenFixture.IsNonInvasive,
    "deterministic fixture classifies 403 as manual review without an automatic action");

var deterministicFixtureDependencies = typeof(DeterministicRecoveryFixture)
    .GetConstructors()
    .SelectMany(constructor => constructor.GetParameters())
    .Select(parameter => parameter.ParameterType)
    .ToArray();
Assert(
    deterministicFixtureDependencies.Length == 1 &&
    deterministicFixtureDependencies[0] == typeof(RecoveryClassifier),
    "the tests-only deterministic fixture accepts only the pure recovery classifier dependency");

var safeDrillOnly = args.Contains("--safe-drill-only", StringComparer.OrdinalIgnoreCase);
var watcherOnly = args.Contains("--watcher-only", StringComparer.OrdinalIgnoreCase);
var desktopIpcProbe = args.Contains("--desktop-ipc-probe", StringComparer.OrdinalIgnoreCase);
var desktopOwnerProbe = args.Contains("--desktop-owner-probe", StringComparer.OrdinalIgnoreCase);
var desktopRecoveryExperiment = args.Contains(
    "--desktop-recovery-experiment",
    StringComparer.OrdinalIgnoreCase);
var requireNativeDesktopChannel = args.Contains(
    "--require-native-desktop-channel",
    StringComparer.OrdinalIgnoreCase);
if (desktopOwnerProbe)
{
    var threadId = ReadCliArgumentValue(args, "--thread-id");
    var restoreThreadId = ReadCliArgumentValue(args, "--restore-thread-id");
    var expectedTurnId = ReadCliArgumentValue(args, "--expected-turn-id");
    if (!Guid.TryParse(threadId, out _) ||
        !string.IsNullOrWhiteSpace(restoreThreadId) && !Guid.TryParse(restoreThreadId, out _) ||
        !string.IsNullOrWhiteSpace(expectedTurnId) && !Guid.TryParse(expectedTurnId, out _))
    {
        Assert(
            false,
            "desktop owner probe requires UUID --thread-id and optional UUID --restore-thread-id/--expected-turn-id");
        Console.WriteLine("\n1 TEST(S) FAILED");
        return 1;
    }

    var probeData = ReadCliArgumentValue(args, "--data-dir") ??
                    Path.Combine(Path.GetTempPath(), "CodexGuardian", "desktop-owner-probe");
    Directory.CreateDirectory(probeData);
    using var probeLog = new GuardianLog(probeData);
    await using var desktopIpc = new DesktopIpcClient(probeLog);
    var platform = new WindowsDesktopThreadOwnerActivationPlatform();
    var activator = new DesktopThreadOwnerActivator(
        desktopIpc,
        probeLog,
        platform,
        TimeSpan.Zero,
        DesktopThreadOwnerActivator.DefaultActivationTimeout,
        DesktopThreadOwnerActivator.DefaultProbeInterval);
    desktopIpc.ActivityReceived += (_, eventArgs) =>
    {
        Console.WriteLine(
            $"ACTIVITY method={eventArgs.Method} version={eventArgs.Version} " +
            $"thread={eventArgs.ConversationId} host={eventArgs.HostId} client={eventArgs.ClientId} " +
            $"status={eventArgs.ClientStatus} runtime={eventArgs.RuntimeStatus}");
    };
    try
    {
        var before = await desktopIpc.ProbeThreadOwnerAsync(threadId!);
        Console.WriteLine($"OWNER_BEFORE status={before.Status} detail={before.Detail}");
        var activation = await activator.EnsureOwnerAsync(threadId!);
        Console.WriteLine($"OWNER_ACTIVATION status={activation.Status} detail={activation.Detail}");
        var after = await desktopIpc.ProbeThreadOwnerAsync(threadId!);
        Console.WriteLine($"OWNER_AFTER status={after.Status} detail={after.Detail}");
        Assert(
            activation.IsAvailable && after.Status == DesktopThreadOwnerProbeStatus.Available,
            "stock Desktop owner is available after the bounded deep-link probe without sending a turn");

        var ownerStateResult = await desktopIpc.AcquireThreadOwnerStateGuardAsync(threadId!);
        Assert(
            ownerStateResult.IsAvailable,
            "stock Desktop returns a targeted read-only owner snapshot after the follower handshake");
        if (ownerStateResult.Guard is not null)
        {
            await using var ownerStateGuard = ownerStateResult.Guard;
            Console.WriteLine("OWNER_SNAPSHOT " + DescribeOwnerSnapshot(ownerStateGuard.Snapshot));
            var localTerminal = await new LocalConversationHistoryReader()
                .ReadLatestTerminalEventAsync(threadId!);
            var ownerTurnMatchesExpected =
                !string.IsNullOrWhiteSpace(expectedTurnId) &&
                string.Equals(
                    ownerStateGuard.Snapshot.LatestTurnId,
                    expectedTurnId,
                    StringComparison.OrdinalIgnoreCase);
            var localTurnMatchesExpected =
                !string.IsNullOrWhiteSpace(expectedTurnId) &&
                string.Equals(localTerminal?.TurnId, expectedTurnId, StringComparison.OrdinalIgnoreCase);
            var localEvidence = localTerminal?.Turn;
            if (ownerTurnMatchesExpected && localTurnMatchesExpected && localEvidence is not null)
            {
                localEvidence = localEvidence with { HasConfirmedLocalTerminal = true };
            }

            Console.WriteLine(
                $"LOCAL_TERMINAL id={localTerminal?.TurnId} status={localTerminal?.Turn.Status} " +
                $"http={localTerminal?.Turn.HttpStatusCode} errorCode={localTerminal?.Turn.ErrorCode ?? "<null>"} " +
                $"errorMessage={JsonSerializer.Serialize(localTerminal?.Turn.ErrorMessage)} " +
                $"confirmed={localEvidence?.HasConfirmedLocalTerminal}");
            var expectedTerminalMatches = string.IsNullOrWhiteSpace(expectedTurnId) ||
                                          ownerTurnMatchesExpected && localTurnMatchesExpected;
            var ownerStateCheck = localEvidence is null
                ? RecoveryExecutionResult.Failed(
                    "The local terminal evidence is unavailable.",
                    failureKind: RecoveryFailureKind.TransportFailed)
                : RecoveryService.ValidateOwnerStateSnapshot(ownerStateGuard.Snapshot, localEvidence);
            Assert(
                ownerStateGuard.IsCurrent && expectedTerminalMatches && ownerStateCheck is null,
                "owner snapshot is current, idle, and matches the exact locally confirmed abnormal terminal turn");
        }
    }
    catch (Exception exception)
    {
        Console.WriteLine("INFO  Desktop owner probe failed: " + exception.Message);
        Assert(false, "bounded stock Desktop owner probe");
    }
    finally
    {
        if (!string.IsNullOrWhiteSpace(restoreThreadId))
        {
            platform.OpenThread(restoreThreadId);
            Console.WriteLine($"RESTORE_THREAD id={restoreThreadId}");
            await Task.Delay(TimeSpan.FromMilliseconds(750));
        }
    }

    Console.WriteLine(failures.Count == 0 ? "\nALL TESTS PASSED" : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (desktopRecoveryExperiment)
{
    const string ConfirmationPrefix = "RESEND-ORIGINAL-ONCE:";
    var threadId = ReadCliArgumentValue(args, "--thread-id");
    var restoreThreadId = ReadCliArgumentValue(args, "--restore-thread-id");
    var expectedTurnId = ReadCliArgumentValue(args, "--expected-turn-id");
    var experimentData = ReadCliArgumentValue(args, "--data-dir");
    var confirmation = ReadCliArgumentValue(args, "--confirm-single-send");
    var argumentsValid =
        Guid.TryParse(threadId, out _) &&
        Guid.TryParse(restoreThreadId, out _) &&
        Guid.TryParse(expectedTurnId, out _) &&
        !string.IsNullOrWhiteSpace(experimentData) &&
        string.Equals(
            confirmation,
            ConfirmationPrefix + expectedTurnId,
            StringComparison.Ordinal);
    if (!argumentsValid)
    {
        Assert(
            false,
            "desktop recovery experiment requires exact task, failed-turn, restore-task, fresh data-dir, and single-send confirmation arguments");
        Console.WriteLine("\n1 TEST(S) FAILED");
        return 1;
    }

    var normalizedExperimentData = Path.GetFullPath(experimentData!);
    var dataRoot = Path.GetPathRoot(normalizedExperimentData);
    var freshDDriveDirectory =
        string.Equals(dataRoot, "D:\\", StringComparison.OrdinalIgnoreCase) &&
        !Directory.Exists(normalizedExperimentData) &&
        !File.Exists(normalizedExperimentData);
    var otherGuardianProcesses = System.Diagnostics.Process
        .GetProcessesByName("CodexGuardian")
        .Where(process => process.Id != Environment.ProcessId)
        .ToArray();
    try
    {
        Assert(
            freshDDriveDirectory,
            "desktop recovery experiment uses a fresh D-drive data directory");
        Assert(
            otherGuardianProcesses.Length == 0,
            "no independent Codex Guardian process can race the one-time recovery experiment");
    }
    finally
    {
        foreach (var process in otherGuardianProcesses)
        {
            process.Dispose();
        }
    }

    if (!freshDDriveDirectory || failures.Count > 0)
    {
        Console.WriteLine($"\n{failures.Count} TEST(S) FAILED");
        return 1;
    }

    Directory.CreateDirectory(normalizedExperimentData);
    using var experimentLog = new GuardianLog(normalizedExperimentData);
    await using var stateReader = new AppServerClient(new CodexCliLocator(), experimentLog);
    await using var desktop = new DesktopIpcClient(experimentLog);
    var ownerOnlyPlatform = new ExistingOwnerOnlyActivationPlatform();
    var ownerActivator = new DesktopThreadOwnerActivator(
        desktop,
        experimentLog,
        ownerOnlyPlatform,
        DesktopThreadOwnerActivator.DefaultMinimumIdleTime,
        DesktopThreadOwnerActivator.DefaultActivationTimeout,
        DesktopThreadOwnerActivator.DefaultProbeInterval);
    var journal = new RecoveryOperationJournal(normalizedExperimentData);
    var recovery = new RecoveryService(
        stateReader,
        desktop,
        ownerActivator,
        journal,
        experimentLog);
    var experimentClassifier = new RecoveryClassifier();
    var liveHistory = new LocalConversationHistoryReader();
    var restorePlatform = new WindowsDesktopThreadOwnerActivationPlatform();
    try
    {
        var idleAtEntry = ownerOnlyPlatform.GetUserIdleTime();
        await desktop.EnsureConnectedAsync();
        var idleAfterConnect = ownerOnlyPlatform.GetUserIdleTime();
        var nativeChannelAvailable = await desktop.ProbeNativeDesktopChannelAsync();
        var idleAfterNativeProbe = ownerOnlyPlatform.GetUserIdleTime();
        var ownerBefore = await desktop.ProbeThreadOwnerAsync(threadId!);
        var idleTime = ownerOnlyPlatform.GetUserIdleTime();
        if (idleTime < DesktopThreadOwnerActivator.DefaultMinimumIdleTime)
        {
            Console.WriteLine(
                $"EXPERIMENT_WAITING_FOR_IDLE current={idleTime.TotalSeconds:0.0} " +
                $"required={DesktopThreadOwnerActivator.DefaultMinimumIdleTime.TotalSeconds:0}");
            var idleDeadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5);
            do
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
                idleTime = ownerOnlyPlatform.GetUserIdleTime();
            }
            while (idleTime < DesktopThreadOwnerActivator.DefaultMinimumIdleTime &&
                   DateTimeOffset.UtcNow < idleDeadline);

            // Match the production order: prove the owner again, then measure idle immediately after it.
            ownerBefore = await desktop.ProbeThreadOwnerAsync(threadId!);
            idleTime = ownerOnlyPlatform.GetUserIdleTime();
        }

        var targetThread = await stateReader.ReadThreadForRecoveryAsync(threadId!);
        var remoteTurn = await stateReader.ReadLatestTurnAsync(threadId!);
        var localTerminal = await liveHistory.ReadLatestTerminalEventAsync(threadId!);
        var failedTurn = LocalConversationHistoryReader.ReconcileLatestTurn(remoteTurn, localTerminal);
        var decision = experimentClassifier.Classify(failedTurn);
        var recentBefore = await stateReader.ReadRecentTurnsAsync(threadId!, 20);

        Console.WriteLine(
            $"EXPERIMENT_PREFLIGHT owner={ownerBefore.Status} " +
            $"idleEntry={idleAtEntry.TotalSeconds:0.0} idleConnected={idleAfterConnect.TotalSeconds:0.0} " +
            $"idleNative={idleAfterNativeProbe.TotalSeconds:0.0} idleOwner={idleTime.TotalSeconds:0.0} " +
            $"native={nativeChannelAvailable} task={targetThread.Id} archived={targetThread.IsArchived} " +
            $"subAgent={targetThread.IsSubAgent} ephemeral={targetThread.IsEphemeral}");
        Console.WriteLine(
            $"EXPERIMENT_TERMINAL remote={remoteTurn?.Id}/{remoteTurn?.Status} " +
            $"local={localTerminal?.TurnId}/{localTerminal?.Turn.Status} " +
            $"errorCode={localTerminal?.Turn.ErrorCode ?? "<null>"} " +
            $"errorMessage={JsonSerializer.Serialize(localTerminal?.Turn.ErrorMessage)} " +
            $"reconciled={failedTurn?.Id}/{failedTurn?.Status} " +
            $"confirmed={failedTurn?.HasConfirmedLocalTerminal} action={decision.Action}");

        var preflightPassed =
            nativeChannelAvailable &&
            desktop.IsNativeChannelAvailable &&
            ownerBefore.Status == DesktopThreadOwnerProbeStatus.Available &&
            idleTime >= DesktopThreadOwnerActivator.DefaultMinimumIdleTime &&
            string.Equals(targetThread.Id, threadId, StringComparison.OrdinalIgnoreCase) &&
            !targetThread.IsArchived &&
            !targetThread.IsSubAgent &&
            !targetThread.IsEphemeral &&
            remoteTurn is not null &&
            localTerminal is not null &&
            failedTurn is not null &&
            string.Equals(remoteTurn.Id, expectedTurnId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(localTerminal.TurnId, expectedTurnId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(failedTurn.Id, expectedTurnId, StringComparison.OrdinalIgnoreCase) &&
            failedTurn.HasConfirmedLocalTerminal &&
            (string.Equals(failedTurn.Status, "failed", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(failedTurn.Status, "interrupted", StringComparison.OrdinalIgnoreCase)) &&
            decision.Action == RecoveryActionKind.ResendOriginal &&
            recentBefore.Any(turn =>
                string.Equals(turn.Id, expectedTurnId, StringComparison.OrdinalIgnoreCase));
        Assert(
            preflightPassed,
            "one-time recovery preflight proves the exact active root task, local provider failure, existing owner, idle gate, and ResendOriginal action");
        if (!preflightPassed || failures.Count > 0)
        {
            throw new InvalidOperationException("The one-time recovery preflight did not pass; nothing was sent.");
        }

        var terminalDetected = new TaskCompletionSource<LocalConversationTerminalDetectedEventArgs>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        await using var terminalWatcher = new LocalConversationEventWatcher(experimentLog);
        terminalWatcher.TerminalDetected += (_, eventArgs) =>
        {
            if (string.Equals(eventArgs.ThreadId, threadId, StringComparison.OrdinalIgnoreCase))
            {
                terminalDetected.TrySetResult(eventArgs);
            }
        };
        terminalWatcher.Start();

        var scopeGeneration = recovery.BeginScopeValidationGeneration();
        var result = await recovery.ExecuteAsync(
            targetThread,
            failedTurn!,
            decision,
            "continue",
            includeSubAgents: false,
            scopeGeneration: scopeGeneration,
            isDispatchAllowed: static () => true);
        Console.WriteLine(
            $"EXPERIMENT_RESULT success={result.Success} failureKind={result.FailureKind} " +
            $"newTurn={result.NewTurnId ?? "<null>"} message={JsonSerializer.Serialize(result.Message)}");

        var operationId = AppServerClient.CreateRecoveryMessageId(
            threadId!,
            expectedTurnId!,
            RecoveryActionKind.ResendOriginal);
        var journalSnapshot = await journal.ReadAsync();
        var operation = journalSnapshot.Records.SingleOrDefault(record =>
            string.Equals(record.OperationId, operationId, StringComparison.OrdinalIgnoreCase));
        var previousState = File.Exists(journal.BackupPath)
            ? ReadPersistedJournalState(journal.BackupPath, operationId)
            : null;
        var durableConfirmation =
            result.Success &&
            Guid.TryParse(result.NewTurnId, out _) &&
            !string.Equals(result.NewTurnId, expectedTurnId, StringComparison.OrdinalIgnoreCase) &&
            operation is
            {
                State: RecoveryOperationState.Confirmed,
                Action: RecoveryActionKind.ResendOriginal,
                AttemptCount: 1
            } &&
            string.Equals(operation.ThreadId, threadId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(operation.FailedTurnId, expectedTurnId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(operation.ClientMessageId, operationId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(operation.NewTurnId, result.NewTurnId, StringComparison.OrdinalIgnoreCase) &&
            previousState == RecoveryOperationState.Dispatching;
        Assert(
            durableConfirmation,
            "the one-time recovery persists Prepared -> Dispatching -> Confirmed with one attempt and the committed new turn id");
        Console.WriteLine(
            $"EXPERIMENT_JOURNAL generation={journalSnapshot.Generation} transitions=Prepared->" +
            $"{previousState}->{operation?.State} attempts={operation?.AttemptCount} " +
            $"operation={operationId} newTurn={operation?.NewTurnId}");

        if (!durableConfirmation)
        {
            throw new InvalidOperationException(
                "Desktop recovery was not durably confirmed; the experiment will not issue another request.");
        }

        IReadOnlyList<TurnSnapshot> recentAfter = Array.Empty<TurnSnapshot>();
        for (var attempt = 0; attempt < 20; attempt++)
        {
            recentAfter = await stateReader.ReadRecentTurnsAsync(threadId!, 20);
            if (recentAfter.Any(turn =>
                    string.Equals(turn.Id, result.NewTurnId, StringComparison.OrdinalIgnoreCase)))
            {
                break;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500));
        }

        var beforeIds = recentBefore
            .Select(turn => turn.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newlyVisibleTurnIds = recentAfter
            .Select(turn => turn.Id)
            .Where(id => !beforeIds.Contains(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var exactlyOneNewTurn =
            recentAfter.Any(turn =>
                string.Equals(turn.Id, expectedTurnId, StringComparison.OrdinalIgnoreCase)) &&
            recentAfter.Any(turn =>
                string.Equals(turn.Id, result.NewTurnId, StringComparison.OrdinalIgnoreCase)) &&
            newlyVisibleTurnIds.Length == 1 &&
            string.Equals(newlyVisibleTurnIds[0], result.NewTurnId, StringComparison.OrdinalIgnoreCase);
        Assert(
            exactlyOneNewTurn,
            "the failed turn remains visible and exactly one committed successor turn is added");
        Console.WriteLine(
            $"EXPERIMENT_TURNS before={recentBefore.Count} after={recentAfter.Count} " +
            $"added={string.Join(",", newlyVisibleTurnIds)} failedPreserved=" +
            recentAfter.Any(turn =>
                string.Equals(turn.Id, expectedTurnId, StringComparison.OrdinalIgnoreCase)));

        try
        {
            var terminal = await terminalDetected.Task.WaitAsync(TimeSpan.FromSeconds(60));
            var successorTerminal = await liveHistory.ReadLatestTerminalEventAsync(threadId!);
            var exactSuccessorTerminal =
                string.Equals(terminal.TurnId, result.NewTurnId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(successorTerminal?.TurnId, result.NewTurnId, StringComparison.OrdinalIgnoreCase);
            Assert(
                exactSuccessorTerminal,
                "the observed terminal belongs to the single committed recovery successor");
            Console.WriteLine(
                $"EXPERIMENT_OUTCOME id={successorTerminal?.TurnId} " +
                $"status={successorTerminal?.Turn.Status} http={successorTerminal?.Turn.HttpStatusCode} " +
                $"errorCode={successorTerminal?.Turn.ErrorCode ?? "<null>"} " +
                $"errorMessage={JsonSerializer.Serialize(successorTerminal?.Turn.ErrorMessage)} " +
                $"automaticFollowUp=false retainedTombstone={operation?.State}");
        }
        catch (TimeoutException)
        {
            Console.WriteLine(
                $"EXPERIMENT_OUTCOME id={result.NewTurnId} status=pending " +
                "automaticFollowUp=false retainedTombstone=Confirmed");
        }
    }
    catch (Exception exception)
    {
        Console.WriteLine("INFO  Desktop recovery experiment stopped: " + exception.Message);
        Assert(false, "bounded one-time stock Desktop recovery experiment");
    }
    finally
    {
        try
        {
            restorePlatform.OpenThread(restoreThreadId!);
            Console.WriteLine($"RESTORE_THREAD id={restoreThreadId}");
            await Task.Delay(TimeSpan.FromMilliseconds(750));
        }
        catch (Exception exception)
        {
            Console.WriteLine("INFO  Unable to restore the current task view: " + exception.Message);
            Assert(false, "restore current task after the recovery experiment");
        }
    }

    Console.WriteLine(failures.Count == 0 ? "\nALL TESTS PASSED" : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (desktopIpcProbe)
{
    var probeData = Path.Combine(AppContext.BaseDirectory, "desktop-ipc-probe");
    Directory.CreateDirectory(probeData);
    using var probeLog = new GuardianLog(probeData);
    await using var desktopIpc = new DesktopIpcClient(probeLog);
    try
    {
        await desktopIpc.EnsureConnectedAsync();
        Assert(desktopIpc.IsConnected, "live Codex Desktop IPC initialize handshake");
        var nativeChannelAvailable = await desktopIpc.ProbeNativeDesktopChannelAsync();
        Assert(desktopIpc.IsConnected, "connected Desktop IPC survives a live native-channel recheck");
        if (requireNativeDesktopChannel)
        {
            Assert(
                desktopIpc.IsNativeChannelAvailable && nativeChannelAvailable,
                "Codex Desktop exposes the stock owner-bound follower channel without loading or sending to a task");
        }
        else
        {
            Console.WriteLine(nativeChannelAvailable
                ? "INFO  stock owner-bound Codex Desktop task channel is available"
                : "INFO  Codex Desktop task recovery channel is unavailable");
        }
    }
    catch (Exception exception)
    {
        Console.WriteLine("INFO  Desktop IPC probe failed: " + exception.Message);
        Assert(false, "live Codex Desktop IPC initialize handshake");
    }

    Console.WriteLine(failures.Count == 0 ? "\nALL TESTS PASSED" : $"\n{failures.Count} TEST(S) FAILED");
    return failures.Count == 0 ? 0 : 1;
}

if (safeDrillOnly)
{
    Console.WriteLine("INFO  skipped live Codex integration because --safe-drill-only was requested");
}
else
{
    var locator = new CodexCliLocator();
    var codexPath = locator.Find();
    Assert(!string.IsNullOrWhiteSpace(codexPath) && File.Exists(codexPath), "local runnable codex.exe is discovered");

    var testData = CreatePhaseOwnedTestDataDirectory("watcher");
    using var log = new GuardianLog(testData);

    var watcherThreadId = Guid.NewGuid().ToString();
    var watcherTurnId = Guid.NewGuid().ToString();
    var abortedTurnId = Guid.NewGuid().ToString();
    var watcherStartedAt = DateTimeOffset.UtcNow;
    var watcherRoot = Path.Combine(testData, "watcher-" + Guid.NewGuid().ToString("N"));
    var watcherDay = Path.Combine(watcherRoot, "2026", "07", "25");
    Directory.CreateDirectory(watcherDay);
    var watcherFile = Path.Combine(
        watcherDay,
        $"rollout-2026-07-25T00-00-00-{watcherThreadId}.jsonl");
    await File.WriteAllTextAsync(watcherFile, "{}\n");
    var terminalDetected = new TaskCompletionSource<LocalConversationTerminalDetectedEventArgs>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var abortedTerminalDetected = new TaskCompletionSource<LocalConversationTerminalDetectedEventArgs>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var newFileThreadId = Guid.NewGuid().ToString();
    var inheritedTurnId = Guid.NewGuid().ToString();
    var newFileTurnId = Guid.NewGuid().ToString();
    var newFileTerminalDetected = new TaskCompletionSource<LocalConversationTerminalDetectedEventArgs>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var immediateThreadId = Guid.NewGuid().ToString();
    var immediateTurnId = Guid.NewGuid().ToString();
    var immediateTerminalDetected = new TaskCompletionSource<LocalConversationTerminalDetectedEventArgs>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var immediateThreadTouched = new TaskCompletionSource<LocalConversationThreadTouchedEventArgs>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var oversizedAppendThreadTouched = new TaskCompletionSource<LocalConversationThreadTouchedEventArgs>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var streamingThreadId = Guid.NewGuid().ToString();
    var streamingInheritedTurnId = Guid.NewGuid().ToString();
    var streamingCurrentTurnId = Guid.NewGuid().ToString();
    var streamingTerminalDetected = new TaskCompletionSource<LocalConversationTerminalDetectedEventArgs>(
        TaskCreationOptions.RunContinuationsAsynchronously);
    var detectedTerminalCount = 0;
    var watcherFaultedCount = 0;
    await using (var watcher = new LocalConversationEventWatcher(log, watcherRoot))
    {
        watcher.ThreadTouched += (_, eventArgs) =>
        {
            if (eventArgs.ThreadId == immediateThreadId)
            {
                immediateThreadTouched.TrySetResult(eventArgs);
            }
            else if (eventArgs.ThreadId == watcherThreadId)
            {
                oversizedAppendThreadTouched.TrySetResult(eventArgs);
            }
        };
        watcher.Faulted += (_, _) => Interlocked.Increment(ref watcherFaultedCount);
        watcher.TerminalDetected += (_, eventArgs) =>
        {
            Interlocked.Increment(ref detectedTerminalCount);
            if (eventArgs.TurnId == watcherTurnId)
            {
                terminalDetected.TrySetResult(eventArgs);
            }
            else if (eventArgs.TurnId == abortedTurnId)
            {
                abortedTerminalDetected.TrySetResult(eventArgs);
            }
            else if (eventArgs.TurnId == newFileTurnId)
            {
                newFileTerminalDetected.TrySetResult(eventArgs);
            }
            else if (eventArgs.TurnId == immediateTurnId)
            {
                immediateTerminalDetected.TrySetResult(eventArgs);
            }
            else if (eventArgs.TurnId == streamingCurrentTurnId)
            {
                streamingTerminalDetected.TrySetResult(eventArgs);
            }
        };
        watcher.Start();
        var immediateWatcherFile = Path.Combine(
            watcherDay,
            $"rollout-2026-07-25T00-00-01-{immediateThreadId}.jsonl");
        var immediateTerminalLine = JsonSerializer.Serialize(new
        {
            timestamp = DateTimeOffset.UtcNow.ToString("O"),
            type = "event_msg",
            payload = new
            {
                type = "task_complete",
                turn_id = immediateTurnId,
                error = new { message = "immediate connection close" }
            }
        });
        await File.WriteAllTextAsync(immediateWatcherFile, "{}\n" + immediateTerminalLine + "\n");
        var touched = await immediateThreadTouched.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var immediateDetected = await immediateTerminalDetected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert(
            touched.ThreadId == immediateThreadId && touched.SourceFile == immediateWatcherFile &&
            immediateDetected.ThreadId == immediateThreadId &&
            immediateDetected.TurnId == immediateTurnId &&
            immediateDetected.HasError &&
            Volatile.Read(ref detectedTerminalCount) == 1,
            "new rollout files publish a targeted lifecycle event and their first terminal without replaying old history");

        var terminalLine = JsonSerializer.Serialize(new
        {
            timestamp = watcherStartedAt.ToString("O"),
            type = "event_msg",
            payload = new
            {
                type = "task_complete",
                turn_id = watcherTurnId,
                error = new { message = "connection closed" }
            }
        });
        await File.AppendAllTextAsync(
            watcherFile,
            terminalLine + "\n");
        var detected = await terminalDetected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert(
            detected.ThreadId == watcherThreadId &&
            detected.TurnId == watcherTurnId &&
            detected.HasError &&
            Volatile.Read(ref detectedTerminalCount) == 2,
            "local rollout append events wake monitoring with the exact task and turn ids");
        var boundedTailReader = new LocalConversationHistoryReader(watcherRoot);
        var boundedTailTerminal = await boundedTailReader.ReadLatestTerminalEventAsync(watcherThreadId);
        Assert(
            boundedTailTerminal is { Turn.Status: "failed" } &&
            boundedTailTerminal.ThreadId == watcherThreadId &&
            boundedTailTerminal.TurnId == watcherTurnId &&
            boundedTailTerminal.SourceFile == watcherFile,
            "bounded local tail reader parses the latest terminal without scanning full rollout history");
        _ = await boundedTailReader.ReadLatestTerminalEventAsync(Guid.NewGuid().ToString());
        _ = await boundedTailReader.ReadLatestTerminalEventAsync(Guid.NewGuid().ToString());
        _ = await boundedTailReader.ReadLatestTerminalEventAsync(Guid.NewGuid().ToString());
        Assert(
            boundedTailReader.FileIndexRefreshCount == 1,
            "missing task ids reuse one local rollout index instead of re-enumerating the session tree");

        var newWatcherFile = Path.Combine(
            watcherDay,
            $"rollout-2026-07-25T00-00-02-{newFileThreadId}.jsonl");
        var inheritedTerminalLine = JsonSerializer.Serialize(new
        {
            timestamp = watcherStartedAt.AddMinutes(-5).ToString("O"),
            type = "event_msg",
            payload = new
            {
                type = "task_complete",
                turn_id = inheritedTurnId,
                error = new { message = "inherited history" }
            }
        });
        await File.WriteAllTextAsync(newWatcherFile, "{}\n" + inheritedTerminalLine + "\n");
        await Task.Delay(TimeSpan.FromMilliseconds(750));
        Assert(
            Volatile.Read(ref detectedTerminalCount) == 2,
            "new rollout files do not replay inherited terminal history");

        var newFileTerminalLine = JsonSerializer.Serialize(new
        {
            timestamp = DateTimeOffset.UtcNow.AddSeconds(1).ToString("O"),
            type = "event_msg",
            payload = new
            {
                type = "task_complete",
                turn_id = newFileTurnId,
                error = new { message = "connection closed" }
            }
        });
        await File.AppendAllTextAsync(newWatcherFile, newFileTerminalLine + "\n");
        var newFileDetected = await newFileTerminalDetected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert(
            newFileDetected.ThreadId == newFileThreadId &&
            newFileDetected.TurnId == newFileTurnId &&
            newFileDetected.HasError &&
            Volatile.Read(ref detectedTerminalCount) == 3,
            "new rollout files still emit terminal events appended after creation");
        boundedTailReader.RegisterSourceFile(newFileThreadId, newWatcherFile);
        var registeredTerminal = await boundedTailReader.ReadLatestTerminalEventAsync(newFileThreadId);
        Assert(
            registeredTerminal?.TurnId == newFileTurnId &&
            boundedTailReader.FileIndexRefreshCount == 1,
            "terminal events register new rollout files without rebuilding the local index");

        var streamingWatcherFile = Path.Combine(
            watcherDay,
            $"rollout-2026-07-25T00-00-04-{streamingThreadId}.jsonl");
        await File.WriteAllTextAsync(streamingWatcherFile, "{}\n");
        await Task.Delay(TimeSpan.FromMilliseconds(500));
        var streamingInheritedLine = JsonSerializer.Serialize(new
        {
            timestamp = watcherStartedAt.AddMinutes(-4).ToString("O"),
            type = "event_msg",
            payload = new
            {
                type = "task_complete",
                turn_id = streamingInheritedTurnId,
                error = new { message = "streamed inherited history" }
            }
        });
        var splitAt = streamingInheritedLine.Length / 2;
        await File.AppendAllTextAsync(streamingWatcherFile, streamingInheritedLine[..splitAt]);
        await Task.Delay(TimeSpan.FromMilliseconds(300));
        await File.AppendAllTextAsync(streamingWatcherFile, streamingInheritedLine[splitAt..] + "\n");
        await Task.Delay(TimeSpan.FromMilliseconds(750));
        Assert(
            Volatile.Read(ref detectedTerminalCount) == 3,
            "new rollout files suppress inherited terminal history written in separate append events");

        var streamingCurrentLine = JsonSerializer.Serialize(new
        {
            timestamp = DateTimeOffset.UtcNow.AddSeconds(1).ToString("O"),
            type = "event_msg",
            payload = new
            {
                type = "task_complete",
                turn_id = streamingCurrentTurnId,
                error = new { message = "current streamed terminal" }
            }
        });
        await File.AppendAllTextAsync(streamingWatcherFile, streamingCurrentLine + "\n");
        var streamingDetected = await streamingTerminalDetected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert(
            streamingDetected.ThreadId == streamingThreadId &&
            streamingDetected.TurnId == streamingCurrentTurnId &&
            streamingDetected.HasError &&
            Volatile.Read(ref detectedTerminalCount) == 4,
            "new rollout files emit the current terminal after streamed inherited history");

        var abortedLine = JsonSerializer.Serialize(new
        {
            timestamp = DateTimeOffset.UtcNow.AddSeconds(1).ToString("O"),
            type = "event_msg",
            payload = new
            {
                type = "turn_aborted",
                turn_id = abortedTurnId
            }
        });
        await File.AppendAllTextAsync(watcherFile, abortedLine + "\n");
        var abortedDetected = await abortedTerminalDetected.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert(
            abortedDetected.ThreadId == watcherThreadId &&
            abortedDetected.TurnId == abortedTurnId &&
            !abortedDetected.HasError &&
            Volatile.Read(ref detectedTerminalCount) == 5,
            "local turn_aborted events wake targeted state reads with the exact task and turn ids");

        await File.AppendAllTextAsync(
            watcherFile,
            new string('x', LocalConversationEventWatcher.MaximumAppendBytes + 4096) + "\n");
        var oversizedTouched = await oversizedAppendThreadTouched.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(TimeSpan.FromMilliseconds(300));
        Assert(
            oversizedTouched.ThreadId == watcherThreadId &&
            oversizedTouched.SourceFile == watcherFile &&
            Volatile.Read(ref watcherFaultedCount) == 0,
            "rollout appends larger than the bounded tail request only a targeted task refresh");
    }

    if (watcherOnly)
    {
        Console.WriteLine("INFO  skipped live Codex integration because --watcher-only was requested");
        if (failures.Count > 0)
        {
            Console.WriteLine($"\n{failures.Count} TEST(S) FAILED");
        }
        else
        {
            Console.WriteLine("\nALL TESTS PASSED");
        }

        return failures.Count == 0 ? 0 : 1;
    }

    try
    {
        await using var appServer = new AppServerClient(locator, log);
        var firstSession = await appServer.OpenReadSessionAsync();
        var queuedSession = appServer.OpenReadSessionAsync().AsTask();
        await Task.Delay(TimeSpan.FromMilliseconds(150));
        Assert(!queuedSession.IsCompleted, "read-only state sessions serialize complete top-level operations");
        await firstSession.DisposeAsync();
        await firstSession.DisposeAsync();
        await using var activeSession = await queuedSession;
        Assert(appServer.IsConnected, "a queued state session reconnects after the preceding session closes");

        var threads = await appServer.ListThreadsAsync(10, includeSubAgents: false, archived: false);
        var archivedLiveThreads = await appServer.ListThreadsAsync(10, includeSubAgents: false, archived: true);
        Assert(threads.Count > 0, "read-only app-server lists Desktop tasks");
        Assert(
            threads.All(thread => !thread.IsArchived) &&
            archivedLiveThreads.All(thread => thread.IsArchived) &&
            !threads.Select(thread => thread.Id).Intersect(
                archivedLiveThreads.Select(thread => thread.Id),
                StringComparer.OrdinalIgnoreCase).Any(),
            "read-only app-server returns complete active and archived task directories separately");
        Console.WriteLine(
            $"INFO  complete task directory: active={threads.Count}, archived={archivedLiveThreads.Count}, total={threads.Count + archivedLiveThreads.Count}");
        var current = threads.FirstOrDefault(thread => thread.Id == "019f97d8-85bc-7741-8549-bee07cddf47f") ?? threads.First();
        var latest = await appServer.ReadLatestTurnAsync(current.Id);
        Assert(latest is not null, "read-only app-server reads the latest turn");

        var liveHistory = new LocalConversationHistoryReader();
        var cnoteAppServerTurn = await appServer.ReadLatestTurnAsync(LocalHistoryFallbackThreadId);
        var cnoteLocalTerminal = await liveHistory.ReadLatestTerminalEventAsync(LocalHistoryFallbackThreadId);
        var cnoteReconciledTurn = LocalConversationHistoryReader.ReconcileLatestTurn(
            cnoteAppServerTurn,
            cnoteLocalTerminal);
        if (cnoteLocalTerminal is not null)
        {
            Assert(
                !string.IsNullOrWhiteSpace(cnoteLocalTerminal.SourceFile),
                "bounded local tail reader reports its CNote source file when a current local terminal exists");
        }
        else
        {
            Console.WriteLine("INFO  current CNote terminal is not present in the local rollout index; no historical scan was attempted");
        }

        if (cnoteAppServerTurn is not null &&
            cnoteLocalTerminal is not null &&
            string.Equals(cnoteAppServerTurn.Id, cnoteLocalTerminal.TurnId, StringComparison.OrdinalIgnoreCase))
        {
            var localTerminalAt = cnoteLocalTerminal.Turn.CompletedAt ??
                                  cnoteLocalTerminal.RecordedAt?.ToUnixTimeSeconds();
            var appServerTerminalAt = cnoteAppServerTurn.CompletedAt ?? cnoteAppServerTurn.StartedAt;
            var appServerVetoesLocal = string.Equals(
                    cnoteAppServerTurn.Status,
                    "inProgress",
                    StringComparison.OrdinalIgnoreCase) ||
                localTerminalAt is not null &&
                appServerTerminalAt is not null &&
                appServerTerminalAt > localTerminalAt ||
                string.Equals(cnoteLocalTerminal.Turn.Status, "completed", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(cnoteAppServerTurn.Status, "failed", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(cnoteLocalTerminal.Turn.Status, "completed", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(cnoteLocalTerminal.Turn.Status, "failed", StringComparison.OrdinalIgnoreCase);
            Assert(
                cnoteReconciledTurn is not null &&
                string.Equals(
                    cnoteReconciledTurn.Status,
                    appServerVetoesLocal
                        ? cnoteAppServerTurn.Status
                        : cnoteLocalTerminal.Turn.Status,
                    StringComparison.OrdinalIgnoreCase),
                "same-turn local terminal reconciles unless app-server is live or has a strictly newer terminal");
        }
        else
        {
            Console.WriteLine("INFO  CNote changed while the live test was running; stale local terminal was not applied");
        }
        Console.WriteLine(
            $"INFO  current CNote reconciliation: remote={cnoteAppServerTurn?.Status}/{cnoteAppServerTurn?.Id}, " +
            $"local={cnoteLocalTerminal?.Turn.Status}/{cnoteLocalTerminal?.TurnId}, " +
            $"assistant={cnoteReconciledTurn?.HasAssistantOutput}, work={cnoteReconciledTurn?.HasWorkOutput}, " +
            $"action={classifier.Classify(cnoteReconciledTurn).Action}");

    ThreadSummary? forbiddenThread = null;
    TurnSnapshot? forbidden = null;
    foreach (var thread in threads.Take(18))
    {
        var recentTurns = await appServer.ReadRecentTurnsAsync(thread.Id, 20);
        forbidden = recentTurns.FirstOrDefault(turn =>
            turn.HttpStatusCode == 403 ||
            (turn.ErrorMessage?.Contains("403 Forbidden", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (turn.ErrorMessage?.Contains("paid balance insufficient", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (turn.ErrorMessage?.Contains("可用额度不足", StringComparison.OrdinalIgnoreCase) ?? false));
        if (forbidden is not null)
        {
            forbiddenThread = thread;
            break;
        }
    }
    if (forbidden is null)
    {
        var localTail = await liveHistory.ReadLatestTerminalEventAsync(LocalHistoryFallbackThreadId);
        Console.WriteLine(localTail is null
            ? "INFO  fixed CNote local tail is unavailable; historical rollout scanning remains disabled"
            : $"INFO  bounded local tail fallback thread={LocalHistoryFallbackThreadId} " +
              $"status={localTail.Turn.Status} http={localTail.Turn.HttpStatusCode} offset={localTail.ByteOffset}");
        if (localTail?.Turn.HttpStatusCode == 403)
        {
            forbidden = localTail.Turn;
        }
    }

    if (forbidden is not null)
    {
        Assert(
            classifier.Classify(forbidden).Action == RecoveryActionKind.None,
            "403 balance evidence is classified with no automatic action");
        Console.WriteLine($"INFO  read-only 403 evidence: task={forbiddenThread?.Name ?? "local history"}, turn={forbidden.Id}, action={classifier.Classify(forbidden).Action}, error={forbidden.ErrorMessage}");
    }
    else
    {
        Console.WriteLine("INFO  no recent 403 terminal is available; historical rollout scanning remains disabled");
    }
}
    catch (Exception exception)
    {
        failures.Add("live integration: " + exception.Message);
        Console.WriteLine("FAIL  live integration: " + exception);
    }
}

Console.WriteLine();
Console.WriteLine(failures.Count == 0
    ? "ALL TESTS PASSED"
    : $"{failures.Count} TEST(S) FAILED");

return failures.Count == 0 ? 0 : 1;

static DesktopThreadOwnerProbeResult OwnerProbe(DesktopThreadOwnerProbeStatus status) =>
    new(status, status.ToString());

static string CreatePhaseOwnedTestDataDirectory(string label)
{
    const string environmentVariable = "CODEX_GUARDIAN_TEST_DATA_ROOT";
    var configuredRoot = Environment.GetEnvironmentVariable(environmentVariable);
    if (string.IsNullOrWhiteSpace(configuredRoot))
    {
        throw new InvalidOperationException($"{environmentVariable} is required for watcher tests.");
    }

    var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuredRoot));
    var volumeRoot = Path.GetPathRoot(root);
    if (!string.Equals(volumeRoot, @"D:\", StringComparison.OrdinalIgnoreCase) ||
        !Directory.Exists(root))
    {
        throw new InvalidOperationException(
            "The watcher test-data root must be an existing local D-drive directory.");
    }

    var current = volumeRoot!;
    foreach (var segment in Path.GetRelativePath(volumeRoot!, root).Split(
                 [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                 StringSplitOptions.RemoveEmptyEntries))
    {
        current = Path.Combine(current, segment);
        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException(
                "The watcher test-data root crosses a reparse point.");
        }
    }

    var directory = Path.Combine(
        root,
        label + "-" + Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    return directory;
}

internal sealed class FakeDesktopThreadOwnerProbe(
    Func<string, DesktopThreadOwnerProbeResult> probe) : IDesktopThreadOwnerProbe
{
    public Task<DesktopThreadOwnerProbeResult> ProbeThreadOwnerAsync(
        string conversationId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(probe(conversationId));
    }
}

internal sealed class LostWakeRecoveryInterferenceGuard : IRecoveryInterferenceGuard
{
    private int _checkCount;
    private int _waitCount;
    private long _version = 1;

    public int CheckCount => Volatile.Read(ref _checkCount);

    public int WaitCount => Volatile.Read(ref _waitCount);

    public Task<RecoveryInterferenceSnapshot> CheckAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        _ = threadId;
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Increment(ref _checkCount) == 1)
        {
            var editing = new RecoveryInterferenceSnapshot(
                RecoveryInterferenceStatus.Editing,
                "Editing immediately changed to clear.",
                true,
                DateTimeOffset.UtcNow,
                Version: 1);
            Volatile.Write(ref _version, 2);
            return Task.FromResult(editing);
        }

        return Task.FromResult(new RecoveryInterferenceSnapshot(
            RecoveryInterferenceStatus.Clear,
            "Clear after the raced edge.",
            false,
            DateTimeOffset.UtcNow,
            Version: Volatile.Read(ref _version)));
    }

    public Task WaitForChangeAsync(long observedVersion, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _waitCount);
        return observedVersion != Volatile.Read(ref _version)
            ? Task.CompletedTask
            : Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }
}

internal sealed class FakeDesktopThreadOwnerActivationPlatform(TimeSpan idleTime)
    : IDesktopThreadOwnerActivationPlatform
{
    private readonly object _sync = new();
    private readonly HashSet<string> _openedThreads = new(StringComparer.OrdinalIgnoreCase);
    private int _concurrentOpenCount;
    private int _maximumConcurrentOpenCount;
    private int _openThreadCount;

    public TimeSpan OpenDelay { get; init; }

    public Exception? IdleTimeException { get; init; }

    public int OpenThreadCount => Volatile.Read(ref _openThreadCount);

    public int MaximumConcurrentOpenCount => Volatile.Read(ref _maximumConcurrentOpenCount);

    public TimeSpan GetUserIdleTime()
    {
        if (IdleTimeException is not null)
        {
            throw IdleTimeException;
        }

        return idleTime;
    }

    public bool HasOpened(string threadId)
    {
        lock (_sync)
        {
            return _openedThreads.Contains(threadId);
        }
    }

    public void OpenThread(string threadId)
    {
        Interlocked.Increment(ref _openThreadCount);
        var concurrent = Interlocked.Increment(ref _concurrentOpenCount);
        UpdateMaximumConcurrentOpenCount(concurrent);
        try
        {
            lock (_sync)
            {
                _openedThreads.Add(threadId);
            }

            if (OpenDelay > TimeSpan.Zero)
            {
                Thread.Sleep(OpenDelay);
            }
        }
        finally
        {
            Interlocked.Decrement(ref _concurrentOpenCount);
        }
    }

    private void UpdateMaximumConcurrentOpenCount(int value)
    {
        while (true)
        {
            var current = Volatile.Read(ref _maximumConcurrentOpenCount);
            if (value <= current ||
                Interlocked.CompareExchange(ref _maximumConcurrentOpenCount, value, current) == current)
            {
                return;
            }
        }
    }
}

internal sealed class ExistingOwnerOnlyActivationPlatform : IDesktopThreadOwnerActivationPlatform
{
    private readonly WindowsDesktopThreadOwnerActivationPlatform _windows = new();

    public TimeSpan GetUserIdleTime() => _windows.GetUserIdleTime();

    public void OpenThread(string threadId) =>
        throw new InvalidOperationException(
            "The one-time recovery experiment requires an already-owned Desktop task and will not navigate to create an owner.");
}

internal sealed record DeterministicRecoveryFixtureResult(
    RecoveryDecision Decision,
    RecoveryActionKind ExpectedAction,
    GuardianTaskState SimulatedState,
    int ProtocolRequestCount = 0,
    int CodexUiActionCount = 0,
    int InputInjectionCount = 0,
    int PointerActionCount = 0)
{
    public bool ClassifierMatchedExpectation => Decision.Action == ExpectedAction;

    public bool IsNonInvasive =>
        ProtocolRequestCount == 0 &&
        CodexUiActionCount == 0 &&
        InputInjectionCount == 0 &&
        PointerActionCount == 0;

    public int ExternalOperationCount =>
        ProtocolRequestCount +
        CodexUiActionCount +
        InputInjectionCount +
        PointerActionCount;
}

internal sealed record DeterministicRecoveryFixtureReport(
    IReadOnlyList<DeterministicRecoveryFixtureResult> Results)
{
    public bool IsNonInvasive => Results.All(result => result.IsNonInvasive);

    public int ExternalOperationCount => Results.Sum(result => result.ExternalOperationCount);
}

internal sealed class DeterministicRecoveryFixture
{
    private readonly RecoveryClassifier _classifier;

    public DeterministicRecoveryFixture(RecoveryClassifier classifier)
    {
        _classifier = classifier;
    }

    public DeterministicRecoveryFixtureReport RunAll() =>
        new(
        [
            RetryOriginalAfter429(),
            ContinueAfterStreamDisconnect(),
            RetryContinueAfter429(),
            Forbidden403()
        ]);

    public DeterministicRecoveryFixtureResult RetryOriginalAfter429() =>
        Build(
            "retry-original-429",
            "exceeded retry limit, last status: 429 Too Many Requests",
            "responseTooManyFailedAttempts",
            429,
            "Continue the current work.",
            hasAssistantOutput: false,
            hasWorkOutput: false,
            RecoveryActionKind.ResendOriginal);

    public DeterministicRecoveryFixtureResult ContinueAfterStreamDisconnect() =>
        Build(
            "stream-continue",
            "response stream disconnected while receiving output",
            "responseStreamDisconnected",
            httpStatusCode: null,
            "Continue the current work.",
            hasAssistantOutput: true,
            hasWorkOutput: true,
            RecoveryActionKind.SendContinue);

    public DeterministicRecoveryFixtureResult RetryContinueAfter429() =>
        Build(
            "retry-continue-429",
            "exceeded retry limit, last status: 429 Too Many Requests",
            "responseTooManyFailedAttempts",
            429,
            "continue",
            hasAssistantOutput: false,
            hasWorkOutput: false,
            RecoveryActionKind.ResendContinue);

    public DeterministicRecoveryFixtureResult Forbidden403() =>
        Build(
            "forbidden-403",
            "403 Forbidden: paid balance is insufficient",
            "httpForbidden",
            403,
            "Continue the current work.",
            hasAssistantOutput: false,
            hasWorkOutput: false,
            RecoveryActionKind.None);

    private DeterministicRecoveryFixtureResult Build(
        string suffix,
        string errorMessage,
        string errorCode,
        int? httpStatusCode,
        string userText,
        bool hasAssistantOutput,
        bool hasWorkOutput,
        RecoveryActionKind expectedAction)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var thread = new ThreadSummary(
            "deterministic-recovery-" + suffix,
            "Tests-only deterministic recovery fixture",
            "Classifier input assembled in memory.",
            Cwd: "[tests-only]",
            Source: "tests-only",
            CreatedAt: timestamp,
            UpdatedAt: timestamp,
            IsSubAgent: false,
            IsEphemeral: true);
        var turn = new TurnSnapshot(
            "deterministic-recovery-turn-" + suffix,
            Status: "failed",
            ErrorMessage: errorMessage,
            ErrorCode: errorCode,
            HttpStatusCode: httpStatusCode,
            UserText: userText,
            HasAttachments: false,
            HasAssistantOutput: hasAssistantOutput,
            HasWorkOutput: hasWorkOutput,
            OutputFingerprint: "tests-only",
            StartedAt: timestamp,
            CompletedAt: timestamp,
            HasConfirmedLocalTerminal: true,
            HasUserMessage: !string.IsNullOrWhiteSpace(userText),
            HasCommentaryOutput: hasAssistantOutput,
            HasReasoningOutput: hasWorkOutput,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: !string.IsNullOrWhiteSpace(userText));
        var decision = _classifier.Classify(turn);
        var projectedHealth = decision.Action == RecoveryActionKind.None
            ? TaskHealth.ManualReview
            : TaskHealth.Recovering;
        var state = new GuardianTaskState(
            thread,
            turn,
            decision,
            IsEnabled: true,
            projectedHealth,
            "Tests-only deterministic classifier state.",
            "No external operation was performed.",
            Attempts: 0,
            NextAttemptAt: null);

        return new DeterministicRecoveryFixtureResult(
            decision,
            expectedAction,
            state);
    }
}
