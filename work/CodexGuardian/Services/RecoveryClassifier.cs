using CodexGuardian.Models;
using System.Xml.Linq;

namespace CodexGuardian.Services;

public sealed class RecoveryClassifier
{
    internal const string IncompleteTerminalStatus = "completedWithoutFinalOutput";
    internal const string UnverifiedAbortStatus = "abortReasonUnverified";
    private const string ExplicitRateLimitErrorCode = "responseTooManyFailedAttempts";
    private const string CurrentRateLimitErrorCode = "rateLimitExceeded";
    private const string NormalizedHighDemandErrorCode = "internal_server_error";
    private const string HighDemandErrorMessageFragment = "currently experiencing high demand";
    private const string TemporaryErrorMessageFragment = "temporary errors";

    private static readonly HashSet<string> RecoverableErrorCodes = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "httpConnectionFailed",
        "networkDisconnected",
        "responseStreamConnectionFailed",
        "responseStreamDisconnected",
        "responseTooManyFailedAttempts",
        "rateLimitExceeded",
        "serverOverloaded"
    };

    private static readonly string[] PermanentErrorCodes =
    [
        "unauthorized",
        "forbidden",
        "permissionDenied",
        "invalidRequest",
        "invalidApiKey",
        "contentPolicy",
        "contextLengthExceeded",
        "billing",
        "quotaExceeded",
        "userCancelled",
        "userCanceled"
    ];

    private static readonly string[] PermanentMessageFragments =
    [
        "paid balance insufficient",
        "insufficient balance",
        "balance is insufficient",
        "可用额度不足",
        "403 forbidden",
        "unauthorized",
        "invalid api key",
        "permission denied",
        "authentication failed",
        "content policy",
        "context length exceeded",
        "billing required",
        "quota exceeded",
        "cancelled by user",
        "canceled by user",
        "manually stopped"
    ];

    // Waiting for the independent local terminal event is the right default: it stops Guardian from
    // resending a turn that Codex is in fact still running. But the wait had no ceiling, and a turn
    // whose terminal event never lands in the rollout was abandoned in silence. Live evidence: with
    // several conversations open at once, two of ten tasks classified `interrupted` and were never
    // resent again, while their recovery records sat in `Retryable` for over twenty minutes. Codex
    // only reports `interrupted` after it has stopped working the turn — a turn still in flight is
    // `inProgress` — and it stamps `CompletedAt` when it stops, so once that stamp is this old the
    // missing terminal event is not late, it is absent.
    internal static readonly TimeSpan LocalTerminalWaitCeiling = TimeSpan.FromSeconds(90);

    private static readonly string[] TemporaryOverloadMessageFragments =
    [
        "currently experiencing high demand",
        "temporarily overloaded",
        "server is overloaded",
        "service is overloaded",
        "server is busy",
        "service is busy",
        "服务器繁忙",
        "服务过载"
    ];

    public RecoveryDecision Classify(TurnSnapshot? turn, DateTimeOffset? now = null)
    {
        if (turn is null)
        {
            return RecoveryDecision.None(TaskHealth.Unknown, "No turn history is available yet.");
        }

        var terminalWaitExpired = HasLocalTerminalWaitExpired(turn, now);
        return turn.Status switch
        {
            "inProgress" => RecoveryDecision.None(TaskHealth.Processing, "Codex is still processing this task."),
            "completed" when turn.HasReliableFinalOutput =>
                RecoveryDecision.None(TaskHealth.Healthy, "The latest turn completed with a final response."),
            "completed" when !turn.HasCompleteItemEvidence || turn.HasAmbiguousActivity =>
                ClassifyRecoverableTerminal(turn, terminalWaitExpired),
            "completed" when !turn.HasConfirmedLocalTerminal && !terminalWaitExpired => RecoveryDecision.None(
                TaskHealth.Unknown,
                "Codex reported completion, but a matching local terminal and final response are not both available."),
            "completed" => ClassifyRecoverableTerminal(turn, terminalWaitExpired),
            IncompleteTerminalStatus => ClassifyRecoverableTerminal(turn, terminalWaitExpired),
            "interrupted" when !turn.HasConfirmedLocalTerminal && !terminalWaitExpired => RecoveryDecision.None(
                TaskHealth.Unknown,
                "The independent state reader cannot prove that this turn ended; waiting for a local terminal event."),
            "interrupted" => ClassifyRecoverableTerminal(turn, terminalWaitExpired),
            UnverifiedAbortStatus => RecoveryDecision.None(
                TaskHealth.Unknown,
                "The local rollout contains an abort event with an unrecognized reason; automatic recovery is blocked."),
            "failed" => ClassifyRecoverableTerminal(turn, terminalWaitExpired),
            "cancelled" or "canceled" or "aborted" => RecoveryDecision.None(
                TaskHealth.ManualReview,
                "The task was explicitly stopped and will not be resumed automatically."),
            _ => RecoveryDecision.None(TaskHealth.Unknown, $"Unknown turn status: {turn.Status}")
        };
    }

    // The ceiling only applies once Codex has stamped an end time for the turn. Without that stamp
    // there is no evidence the turn stopped, so the original unbounded wait is kept rather than
    // guessing from wall-clock time alone.
    private static bool HasLocalTerminalWaitExpired(TurnSnapshot turn, DateTimeOffset? now)
    {
        if (turn.HasConfirmedLocalTerminal || turn.CompletedAt is not { } completedAt)
        {
            return false;
        }

        var reference = now ?? DateTimeOffset.UtcNow;
        return reference - DateTimeOffset.FromUnixTimeSeconds(completedAt) >= LocalTerminalWaitCeiling;
    }

    private static RecoveryDecision ClassifyRecoverableTerminal(
        TurnSnapshot turn,
        bool terminalWaitExpired)
    {
        if (IsPermanent(turn))
        {
            return new RecoveryDecision(
                RecoveryActionKind.None,
                TaskHealth.ManualReview,
                DescribePermanentFailure(turn, "The latest turn failed with an explicitly non-recoverable error."),
                false);
        }

        if (!turn.HasConfirmedLocalTerminal && !terminalWaitExpired)
        {
            return RecoveryDecision.None(
                TaskHealth.Unknown,
                "A matching local terminal event is required before automatic recovery can be considered.");
        }

        if (!IsExplicitlyRecoverable(turn))
        {
            return RecoveryDecision.None(
                TaskHealth.ManualReview,
                DescribeUnsupportedFailure(turn));
        }

        return BuildRecoveryDecision(turn);
    }

    private static RecoveryDecision BuildRecoveryDecision(TurnSnapshot turn)
    {
        if (!turn.HasCompleteItemEvidence || turn.HasAmbiguousActivity)
        {
            return RecoveryDecision.None(
                TaskHealth.ManualReview,
                "The turn activity evidence is incomplete or contains an unknown item type; automatic recovery is blocked.");
        }

        if (!turn.HasUserMessage)
        {
            return RecoveryDecision.None(
                TaskHealth.ManualReview,
                "The turn has no confirmed user-message input; automatic recovery is blocked.");
        }

        if (!turn.HasKnownWorkEvidence && !turn.HasReplayableInput)
        {
            return RecoveryDecision.None(
                TaskHealth.ManualReview,
                "The failed turn has no safely replayable user input and no proven work to continue.");
        }

        // Error evidence decides whether a recovery intent is allowed. Once allowed, only observed
        // work decides whether a future resend intent could duplicate side effects.
        if (turn.HasKnownWorkEvidence)
        {
            return new RecoveryDecision(
                RecoveryActionKind.SendContinue,
                TaskHealth.NeedsAttention,
                DescribeInterruptedWork(turn),
                true);
        }

        if (IsContinueInput(turn.UserText) &&
            !turn.HasAttachments &&
            turn.IsSingleTextUserInput)
        {
            return new RecoveryDecision(
                RecoveryActionKind.ResendContinue,
                TaskHealth.NeedsAttention,
                "The continue message ended before output; classify as ResendContinue for a native in-place retry of the failed turn.",
                true);
        }

        return new RecoveryDecision(
            RecoveryActionKind.ResendOriginal,
            TaskHealth.NeedsAttention,
            "The user message reached Codex but ended without a final response or work evidence; classify as ResendOriginal for a native in-place retry of the failed turn.",
            true);
    }

    private static string DescribeInterruptedWork(TurnSnapshot turn)
    {
        if (turn.HasToolActivity)
        {
            return "The task ended after tool or file work started; append continue to avoid repeating side effects.";
        }

        if (turn.HasReasoningOutput)
        {
            return "The task ended while reasoning was underway; append continue instead of replaying the prompt.";
        }

        return "The task ended after assistant output started but before a final response; append continue.";
    }

    private static bool IsPermanent(TurnSnapshot turn)
    {
        if (turn.HttpStatusCode is 400 or 401 or 402 or 403 or 404 or 405 or 406 or 410 or 413 or 415 or 422)
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(turn.ErrorCode) &&
            PermanentErrorCodes.Any(code => turn.ErrorCode.Contains(code, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(turn.ErrorMessage) &&
               PermanentMessageFragments.Any(fragment =>
                   turn.ErrorMessage.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsExplicitlyRecoverable(TurnSnapshot turn)
    {
        if (IsExplicitUnsentProviderRejection(turn) ||
            turn.HttpStatusCode is 500 or 502 or 503 or 504)
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(turn.ErrorCode) &&
               RecoverableErrorCodes.Contains(turn.ErrorCode.Trim()) ||
               !string.IsNullOrWhiteSpace(turn.ErrorMessage) &&
               TemporaryOverloadMessageFragments.Any(fragment =>
                   turn.ErrorMessage.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private static string DescribeUnsupportedFailure(TurnSnapshot turn)
    {
        const string fallback =
            "The terminal failure is not an explicitly supported transient network, stream, overload, rate-limit, or server error.";
        var evidence = new List<string>();
        if (turn.HttpStatusCode is { } statusCode)
        {
            evidence.Add("HTTP " + statusCode);
        }

        if (!string.IsNullOrWhiteSpace(turn.ErrorCode))
        {
            var code = new string(turn.ErrorCode
                .Where(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.')
                .Take(80)
                .ToArray());
            if (!string.IsNullOrWhiteSpace(code))
            {
                evidence.Add("code " + code);
            }
        }

        return evidence.Count == 0
            ? fallback
            : fallback + " (" + string.Join(", ", evidence) + ").";
    }

    private static string DescribePermanentFailure(TurnSnapshot turn, string fallback)
    {
        var evidence = new List<string>();
        if (turn.HttpStatusCode is { } statusCode)
        {
            evidence.Add("HTTP " + statusCode);
        }

        if (!string.IsNullOrWhiteSpace(turn.ErrorCode))
        {
            var code = new string(turn.ErrorCode
                .Where(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.')
                .Take(80)
                .ToArray());
            if (!string.IsNullOrWhiteSpace(code))
            {
                evidence.Add("code " + code);
            }
        }

        return evidence.Count == 0
            ? fallback
            : fallback + " (" + string.Join(", ", evidence) + ").";
    }

    internal static bool IsContinueInput(string value)
    {
        value = NormalizeRecoveryInput(value);
        return value.Equals("continue", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("继续", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("继续。", StringComparison.OrdinalIgnoreCase);
    }

    internal static string NormalizeRecoveryInput(string value)
    {
        var trimmed = value.Trim();
        if (!trimmed.StartsWith("<codex_delegation>", StringComparison.Ordinal) ||
            !trimmed.EndsWith("</codex_delegation>", StringComparison.Ordinal))
        {
            return trimmed;
        }

        try
        {
            var root = XElement.Parse(trimmed, LoadOptions.PreserveWhitespace);
            if (root.Name != "codex_delegation" || root.HasAttributes)
            {
                return trimmed;
            }

            var elements = root.Elements().ToArray();
            if (elements.Length != 2 ||
                elements[0].Name != "source_thread_id" ||
                elements[1].Name != "input" ||
                elements.Any(element => element.HasAttributes || element.Elements().Any()) ||
                root.Nodes().Any(node => node is XText text && !string.IsNullOrWhiteSpace(text.Value)) ||
                !Guid.TryParse(elements[0].Value.Trim(), out _))
            {
                return trimmed;
            }

            return elements[1].Value.Trim();
        }
        catch (System.Xml.XmlException)
        {
            return trimmed;
        }
    }

    internal static bool IsProvenUnsentOriginalReplay(TurnSnapshot turn, RecoveryDecision decision)
    {
        ArgumentNullException.ThrowIfNull(turn);
        ArgumentNullException.ThrowIfNull(decision);
        return decision.Action == RecoveryActionKind.ResendOriginal &&
               decision.IsTransient &&
               IsExplicitUnsentProviderRejection(turn) &&
               turn.HasConfirmedLocalTerminal &&
               turn.HasUserMessage &&
               turn.HasReplayableInput &&
               turn.HasCompleteItemEvidence &&
               !turn.HasKnownWorkEvidence &&
               !turn.HasAmbiguousActivity;
    }

    internal static bool IsExplicitUnsentProviderRejection(TurnSnapshot turn)
    {
        if (turn.HttpStatusCode == 429 ||
            string.Equals(turn.ErrorCode?.Trim(), ExplicitRateLimitErrorCode, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(turn.ErrorCode?.Trim(), CurrentRateLimitErrorCode, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.Equals(
                turn.ErrorCode?.Trim(),
                NormalizedHighDemandErrorCode,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Recent Codex Desktop builds emit the same provider rejection with curly apostrophes,
        // line wrapping, or repeated whitespace. Match its stable semantic fragments after
        // normalizing those presentation differences instead of requiring one ASCII sentence.
        var message = NormalizeProviderErrorMessage(turn.ErrorMessage);
        return message.Contains(HighDemandErrorMessageFragment, StringComparison.OrdinalIgnoreCase) &&
               message.Contains(TemporaryErrorMessageFragment, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeProviderErrorMessage(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim()
            .Replace('\u2018', '\'')
            .Replace('\u2019', '\'')
            .Replace('\u201B', '\'')
            .Replace('\uFF07', '\'');
        return string.Join(' ', normalized.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }
}
