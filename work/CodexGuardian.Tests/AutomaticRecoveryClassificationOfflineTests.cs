using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Text.Json;

internal static class AutomaticRecoveryClassificationOfflineTests
{
    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        await RunCaseAsync(
            "automatic recovery requires a confirmed local terminal",
            TestConfirmedLocalTerminalRequiredAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery rejects permanent ambiguous and unknown failures",
            TestStrictRejectionMatrixAsync,
            assert);
        await RunCaseAsync(
            "automatic recovery accepts only explicit transient evidence",
            TestExplicitTransientAllowlistAsync,
            assert);
        await RunCaseAsync(
            "only a no-work HTTP 429 is eligible for proven-unsent original replay",
            TestProvenUnsentOriginalReplayAsync,
            assert);
        await RunCaseAsync(
            "provider HTTP 429 is read when it is a sibling of codexErrorInfo",
            TestSiblingHttpStatusParsingAsync,
            assert);
        await RunCaseAsync(
            "bounded rollout evidence restores only one exact real user text",
            TestBoundedRolloutUserInputRecoveryAsync,
            assert);
        await RunCaseAsync(
            "logical retry incidents recover original input and preserve post-rollback work",
            TestLogicalRetryIncidentRecoveryAsync,
            assert);
        await RunCaseAsync(
            "logical retry incident recovery fails closed on ambiguous or unbounded evidence",
            TestLogicalRetryIncidentFailClosedAsync,
            assert);
        await RunCaseAsync(
            "text recovery uses the fixed stock input shape without attachment semantics",
            TestPlainTextRecoveryTransportBoundaryAsync,
            assert);
        await RunCaseAsync(
            "completed without final output requires transient failure evidence",
            TestIncompleteTerminalEvidenceAsync,
            assert);
        await RunCaseAsync(
            "a rejected recovery creates no journal and opens no transport",
            TestRejectedServicePathAsync,
            assert);
        await RunCaseAsync(
            "an unproven native owner channel blocks resend before journal and transport",
            TestUnprovenNativeChannelServicePathAsync,
            assert);
    }

    private static Task TestConfirmedLocalTerminalRequiredAsync()
    {
        var classifier = new RecoveryClassifier();
        var candidates = new[]
        {
            Case("network-disconnected", "failed", "networkDisconnected", null),
            Case("stream-disconnected", "failed", "responseStreamDisconnected", null),
            Case("overload", "failed", "serverOverloaded", null),
            Case("http-429", "failed", "rate_limit", 429),
            Case("http-500", "failed", "internalServerError", 500),
            Case("http-502", "failed", "bad_gateway", 502),
            Case("http-503", "failed", "serverOverloaded", 503),
            Case("http-504", "failed", "gateway_timeout", 504),
            Case(
                "incomplete-stream",
                RecoveryClassifier.IncompleteTerminalStatus,
                "responseStreamDisconnected",
                null)
        };

        foreach (var candidate in candidates)
        {
            var turn = CreateTurn(candidate, confirmedTerminal: false);
            var completedAt = DateTimeOffset.FromUnixTimeSeconds(turn.CompletedAt!.Value);
            // The wait for the independent local terminal event is bounded now, so this line is pinned at
            // an explicit instant instead of wall-clock time: the fixture stamps CompletedAt in 1970, and
            // read against the real clock every one of these turns is already decades past the ceiling.
            var insideWait = classifier.Classify(
                turn,
                completedAt + RecoveryClassifier.LocalTerminalWaitCeiling - TimeSpan.FromSeconds(1));
            Ensure(
                insideWait.Action == RecoveryActionKind.None && !insideWait.IsTransient,
                candidate.Name + " recovered without an exact local terminal");
            // The other side of the ceiling is asserted too, because it is the whole reason the bound
            // exists: a turn whose terminal event never lands in the rollout was abandoned in silence, and
            // Codex only stamps CompletedAt once it has stopped working the turn, so past the ceiling the
            // missing event is absent rather than late. Without this the bound could be deleted silently.
            var afterCeiling = classifier.Classify(
                turn,
                completedAt + RecoveryClassifier.LocalTerminalWaitCeiling);
            Ensure(
                afterCeiling is { Action: RecoveryActionKind.ResendOriginal, IsTransient: true },
                candidate.Name + " stayed unrecoverable after the local terminal wait ceiling expired");
        }

        return Task.CompletedTask;
    }

    private static Task TestStrictRejectionMatrixAsync()
    {
        var classifier = new RecoveryClassifier();
        var rejected = new[]
        {
            Case("missing-code-and-status", "failed", null, null),
            Case("empty-code-and-status", "failed", string.Empty, null),
            Case("unknown-code", "failed", "provider_mystery", null),
            Case("http-400", "failed", "invalidRequest", 400),
            Case("http-401", "failed", "unauthorized", 401),
            Case("http-403", "failed", "forbidden", 403),
            Case("quota", "failed", "quotaExceeded", null),
            Case("context-limit", "failed", "contextLengthExceeded", null),
            Case("content-policy", "failed", "contentPolicy", null),
            Case("user-cancelled", "failed", "userCancelled", null),
            Case("user-canceled", "failed", "userCanceled", null),
            Case("429-billing", "failed", "billing", 429),
            Case("429-quota", "failed", "quotaExceeded", 429),
            Case(
                "429-balance-message",
                "failed",
                "rate_limit",
                429,
                "paid balance insufficient"),
            Case("unknown-501", "failed", "internalServerError", 501),
            Case("unknown-505", "failed", "internalServerError", 505),
            Case("unknown-507", "failed", "internalServerError", 507),
            Case("unknown-520", "failed", "provider_error", 520),
            Case("interrupted-without-cause", "interrupted", null, null)
        };

        foreach (var candidate in rejected)
        {
            var decision = classifier.Classify(CreateTurn(candidate));
            Ensure(
                decision.Action == RecoveryActionKind.None && !decision.IsTransient,
                candidate.Name + " escaped the strict rejection matrix as " + decision.Action);
        }

        return Task.CompletedTask;
    }

    private static Task TestExplicitTransientAllowlistAsync()
    {
        var classifier = new RecoveryClassifier();
        var allowed = new[]
        {
            Case("network-disconnected", "failed", "networkDisconnected", null),
            Case("stream-disconnected", "failed", "responseStreamDisconnected", null),
            Case("interrupted-stream", "interrupted", "responseStreamDisconnected", null),
            Case("overload", "failed", "serverOverloaded", null),
            Case("http-429", "failed", "rate_limit", 429),
            Case("http-429-without-code", "failed", null, 429),
            Case("http-500", "failed", null, 500),
            Case("http-502", "failed", null, 502),
            Case("http-503", "failed", null, 503),
            Case("http-504", "failed", null, 504),
            Case("explicit-overload-on-other-5xx", "failed", "serverOverloaded", 520)
        };

        foreach (var candidate in allowed)
        {
            var decision = classifier.Classify(CreateTurn(candidate));
            Ensure(
                decision is
                {
                    Action: RecoveryActionKind.ResendOriginal,
                    Health: TaskHealth.NeedsAttention,
                    IsTransient: true
                },
                candidate.Name + " was not admitted by the explicit transient allowlist");
        }

        var workedStream = classifier.Classify(CreateTurn(
            Case("worked-stream", "failed", "responseStreamDisconnected", null),
            hasKnownWork: true));
        Ensure(
            workedStream is
            {
                Action: RecoveryActionKind.SendContinue,
                Health: TaskHealth.NeedsAttention,
                IsTransient: true
            },
            "explicit stream failure with work evidence did not preserve continue selection");
        return Task.CompletedTask;
    }

    private static Task TestIncompleteTerminalEvidenceAsync()
    {
        var classifier = new RecoveryClassifier();
        var silent = classifier.Classify(CreateTurn(Case(
            "silent-incomplete",
            RecoveryClassifier.IncompleteTerminalStatus,
            null,
            null)));
        var unknown = classifier.Classify(CreateTurn(Case(
            "unknown-incomplete",
            RecoveryClassifier.IncompleteTerminalStatus,
            "provider_mystery",
            null)));
        var silentAfterWork = classifier.Classify(CreateTurn(
            Case(
                "silent-incomplete-after-work",
                RecoveryClassifier.IncompleteTerminalStatus,
                null,
                null),
            hasKnownWork: true));
        var disconnected = classifier.Classify(CreateTurn(Case(
            "stream-incomplete",
            RecoveryClassifier.IncompleteTerminalStatus,
            "responseStreamDisconnected",
            null)));

        Ensure(
            silent.Action == RecoveryActionKind.None &&
            unknown.Action == RecoveryActionKind.None &&
            silentAfterWork.Action == RecoveryActionKind.None,
            "absence of a final answer was treated as recoverable without transient evidence");
        Ensure(
            disconnected.Action == RecoveryActionKind.ResendOriginal && disconnected.IsTransient,
            "confirmed incomplete output with explicit stream failure was not recoverable");
        return Task.CompletedTask;
    }

    private static Task TestProvenUnsentOriginalReplayAsync()
    {
        var classifier = new RecoveryClassifier();
        var noWork429 = CreateTurn(Case("429", "failed", "rate_limit", 429));
        var noWork500 = CreateTurn(Case("500", "failed", "server_error", 500));
        var worked429 = CreateTurn(
            Case("429-work", "failed", "rate_limit", 429),
            hasKnownWork: true);

        var original = classifier.Classify(noWork429);
        Ensure(
            RecoveryClassifier.IsProvenUnsentOriginalReplay(noWork429, original),
            "an explicit no-work HTTP 429 was not recognized as proven unsent");
        Ensure(
            !RecoveryClassifier.IsProvenUnsentOriginalReplay(
                noWork500,
                classifier.Classify(noWork500)) &&
            !RecoveryClassifier.IsProvenUnsentOriginalReplay(
                worked429,
                classifier.Classify(worked429)),
            "a non-429 or a 429 after work entered proven-unsent replay");

        var codeOnly429 = CreateTurn(Case(
            "429-code-only",
            "failed",
            "responseTooManyFailedAttempts",
            null));
        Ensure(
            RecoveryClassifier.IsProvenUnsentOriginalReplay(
                codeOnly429,
                classifier.Classify(codeOnly429)),
            "the explicit rate-limit error code without a sibling HTTP status was not recognized");

        var normalizedHighDemand = CreateTurn(Case(
            "normalized-high-demand",
            "failed",
            "internal_server_error",
            null,
            "We're currently experiencing high demand, which may cause temporary errors."));
        var genericInternalError = normalizedHighDemand with
        {
            ErrorMessage = "An internal server error occurred."
        };
        Ensure(
            RecoveryClassifier.IsProvenUnsentOriginalReplay(
                normalizedHighDemand,
                classifier.Classify(normalizedHighDemand)) &&
            !RecoveryClassifier.IsProvenUnsentOriginalReplay(
                genericInternalError,
                classifier.Classify(genericInternalError)),
            "the exact normalized high-demand rejection was not distinguished from a generic internal error");
        return Task.CompletedTask;
    }

    private static Task TestSiblingHttpStatusParsingAsync()
    {
        using var document = JsonDocument.Parse("""
            {
              "id": "11111111-1111-4111-8111-111111111111",
              "status": "failed",
              "error": {
                "message": "We're currently experiencing high demand, which may cause temporary errors.",
                "codexErrorInfo": "responseTooManyFailedAttempts",
                "httpStatusCode": 429
              },
              "items": [
                {
                  "type": "userMessage",
                  "content": [{"type": "text", "text": "retry this exact request"}]
                }
              ]
            }
            """);

        var turn = AppServerClient.ParseTurn(document.RootElement) with
        {
            HasConfirmedLocalTerminal = true
        };
        var decision = new RecoveryClassifier().Classify(turn);
        Ensure(turn.HttpStatusCode == 429, "the sibling provider HTTP status was not retained");
        Ensure(
            decision.Action == RecoveryActionKind.ResendOriginal &&
            RecoveryClassifier.IsProvenUnsentOriginalReplay(turn, decision),
            "a no-output sibling-field HTTP 429 did not enter proven-unsent original replay");
        return Task.CompletedTask;
    }

    private static async Task TestBoundedRolloutUserInputRecoveryAsync()
    {
        await WithRootAsync(async root =>
        {
            var sessionsRoot = Path.Combine(root, "sessions");
            var acceptedThreadId = Guid.NewGuid().ToString("D");
            var acceptedTurnId = Guid.NewGuid().ToString("D");
            var acceptedClientId = Guid.NewGuid().ToString("D");
            await WriteRolloutAsync(
                sessionsRoot,
                acceptedThreadId,
                acceptedTurnId,
                [
                    UserResponseItem(acceptedTurnId, EnvironmentContextText()),
                    TurnContext(acceptedTurnId),
                    UserResponseItem(acceptedTurnId, "6"),
                    UserMessageEvent("6", acceptedClientId),
                    OpaqueEvent(new string('x', 300 * 1024))
                ]);

            var accepted = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(acceptedThreadId);
            Ensure(
                accepted?.Turn is
                {
                    HasUserMessage: true,
                    HasAttachments: false,
                    IsSingleTextUserInput: true,
                    UserText: "6"
                } &&
                accepted.Turn.UserMessageClientIds is { Count: 1 } &&
                accepted.Turn.UserMessageClientIds[0] == acceptedClientId &&
                !string.IsNullOrWhiteSpace(accepted.Turn.RawUserInputJson),
                "the real same-turn user text was not recovered after injected context");

            using (var rawInput = JsonDocument.Parse(accepted!.Turn.RawUserInputJson!))
            {
                Ensure(
                    rawInput.RootElement.ValueKind == JsonValueKind.Array &&
                    rawInput.RootElement.GetArrayLength() == 1 &&
                    rawInput.RootElement[0].GetProperty("type").GetString() == "text" &&
                    rawInput.RootElement[0].GetProperty("text").GetString() == "6",
                    "the recovered rollout text was not converted to canonical stock input");
            }

            var appServerWithoutInput = new TurnSnapshot(
                acceptedTurnId,
                "failed",
                "We're currently experiencing high demand.",
                "responseTooManyFailedAttempts",
                429,
                string.Empty,
                HasAttachments: false,
                HasAssistantOutput: false,
                HasWorkOutput: false,
                OutputFingerprint: "bounded-rollout",
                StartedAt: 100,
                CompletedAt: 200,
                HasUserMessage: false,
                HasCompleteItemEvidence: true);
            var reconciled = LocalConversationHistoryReader.ReconcileLatestTurn(
                appServerWithoutInput,
                accepted);
            var decision = new RecoveryClassifier().Classify(reconciled!);
            Ensure(
                reconciled is
                {
                    HasUserMessage: true,
                    IsSingleTextUserInput: true,
                    UserText: "6",
                    HasCompleteItemEvidence: true,
                    HasConfirmedLocalTerminal: true
                } &&
                decision.Action == RecoveryActionKind.ResendOriginal &&
                RecoveryClassifier.IsProvenUnsentOriginalReplay(reconciled, decision),
                "the exact rollout text did not complete the proven-unsent 429 classification");

            var environmentOnlyThreadId = Guid.NewGuid().ToString("D");
            var environmentOnlyTurnId = Guid.NewGuid().ToString("D");
            await WriteRolloutAsync(
                sessionsRoot,
                environmentOnlyThreadId,
                environmentOnlyTurnId,
                [UserResponseItem(environmentOnlyTurnId, EnvironmentContextText())]);
            var environmentOnly = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(environmentOnlyThreadId);
            Ensure(
                environmentOnly is not null && !environmentOnly.Turn.HasUserMessage,
                "injected environment context was treated as replayable user input");

            var duplicateThreadId = Guid.NewGuid().ToString("D");
            var duplicateTurnId = Guid.NewGuid().ToString("D");
            await WriteRolloutAsync(
                sessionsRoot,
                duplicateThreadId,
                duplicateTurnId,
                [
                    UserResponseItem(duplicateTurnId, "first"),
                    UserResponseItem(duplicateTurnId, "second")
                ]);
            var duplicate = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(duplicateThreadId);
            Ensure(
                duplicate is not null && !duplicate.Turn.HasUserMessage,
                "multiple same-turn real user messages did not fail closed");

            var unknownThreadId = Guid.NewGuid().ToString("D");
            var unknownTurnId = Guid.NewGuid().ToString("D");
            await WriteRolloutAsync(
                sessionsRoot,
                unknownThreadId,
                unknownTurnId,
                [UnknownUserResponseItem(unknownTurnId)]);
            var unknown = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(unknownThreadId);
            Ensure(
                unknown is not null && !unknown.Turn.HasUserMessage,
                "an unknown rollout input kind entered text replay");
        });
    }

    private static async Task TestLogicalRetryIncidentRecoveryAsync()
    {
        await WithRootAsync(async root =>
        {
            var sessionsRoot = Path.Combine(root, "sessions");
            var classifier = new RecoveryClassifier();

            var zeroThreadId = Guid.NewGuid().ToString("D");
            var zeroSourceTurnId = Guid.NewGuid().ToString("D");
            var zeroRetryTurnId = Guid.NewGuid().ToString("D");
            var zeroTargetTurnId = Guid.NewGuid().ToString("D");
            var zeroClientId = Guid.NewGuid().ToString("D");
            await WriteRolloutLinesAsync(
                sessionsRoot,
                zeroThreadId,
                [
                    TaskStarted(zeroSourceTurnId),
                    UserResponseItem(zeroSourceTurnId, EnvironmentContextText()),
                    TurnContext(zeroSourceTurnId),
                    UserResponseItem(zeroSourceTurnId, "0"),
                    UserMessageEvent("0", zeroClientId),
                    TaskStarted(zeroRetryTurnId),
                    TurnContext(zeroRetryTurnId),
                    HighDemandTaskComplete(zeroRetryTurnId),
                    TaskStarted(zeroTargetTurnId),
                    TurnContext(zeroTargetTurnId),
                    HighDemandTaskComplete(zeroTargetTurnId)
                ]);

            var zeroLocal = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(zeroThreadId);
            var zeroReconciled = LocalConversationHistoryReader.ReconcileLatestTurn(
                CreateHighDemandAppServerTurn(zeroTargetTurnId),
                zeroLocal);
            var zeroDecision = classifier.Classify(zeroReconciled!);
            Ensure(
                zeroLocal?.Turn is
                {
                    UserText: "0",
                    HasUserMessage: true,
                    IsSingleTextUserInput: true,
                    HasKnownWorkEvidence: false,
                    HasAmbiguousActivity: false
                } &&
                zeroLocal.Turn.UserMessageClientIds is { Count: 1 } &&
                zeroLocal.Turn.UserMessageClientIds[0] == zeroClientId &&
                zeroDecision.Action == RecoveryActionKind.ResendOriginal &&
                RecoveryClassifier.IsProvenUnsentOriginalReplay(zeroReconciled!, zeroDecision),
                "the clean zero retry chain did not become proven-unsent ResendOriginal");

            var authoritative = CreateHighDemandAppServerTurn(zeroTargetTurnId) with
            {
                UserText = "app-server-authoritative",
                RawUserInputJson = "[{\"type\":\"text\",\"text\":\"app-server-authoritative\"}]",
                UserMessageClientIds = [Guid.NewGuid().ToString("D")],
                HasUserMessage = true,
                IsSingleTextUserInput = true
            };
            var authoritativeReconciled = LocalConversationHistoryReader.ReconcileLatestTurn(
                authoritative,
                zeroLocal);
            Ensure(
                authoritativeReconciled?.UserText == "app-server-authoritative" &&
                authoritativeReconciled.RawUserInputJson == authoritative.RawUserInputJson,
                "local incident recovery overwrote authoritative app-server user input");

            var nineThreadId = Guid.NewGuid().ToString("D");
            var nineSourceTurnId = Guid.NewGuid().ToString("D");
            var nineWorkTurnId = Guid.NewGuid().ToString("D");
            var nineTargetTurnId = Guid.NewGuid().ToString("D");
            var nineClientId = Guid.NewGuid().ToString("D");
            await WriteRolloutLinesAsync(
                sessionsRoot,
                nineThreadId,
                [
                    TaskStarted(nineSourceTurnId),
                    UserResponseItem(nineSourceTurnId, "9"),
                    UserMessageEvent("9", nineClientId),
                    ToolResponseItem(nineSourceTurnId),
                    HighDemandTaskComplete(nineSourceTurnId),
                    ThreadRolledBack(),
                    TaskStarted(nineWorkTurnId),
                    ReasoningResponseItem(nineWorkTurnId),
                    AssistantResponseItem(nineWorkTurnId),
                    TurnAborted(nineWorkTurnId),
                    TaskStarted(nineTargetTurnId),
                    HighDemandTaskComplete(nineTargetTurnId)
                ]);

            var nineLocal = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(nineThreadId);
            var nineReconciled = LocalConversationHistoryReader.ReconcileLatestTurn(
                CreateHighDemandAppServerTurn(nineTargetTurnId),
                nineLocal);
            var nineDecision = classifier.Classify(nineReconciled!);
            Ensure(
                nineReconciled is
                {
                    UserText: "9",
                    HasAssistantOutput: true,
                    HasWorkOutput: true,
                    HasCommentaryOutput: true,
                    HasReasoningOutput: true,
                    HasToolActivity: false,
                    HasAmbiguousActivity: false
                } &&
                nineDecision.Action == RecoveryActionKind.SendContinue &&
                !RecoveryClassifier.IsProvenUnsentOriginalReplay(nineReconciled, nineDecision),
                "the worked nine retry chain did not preserve post-rollback work as SendContinue");
        });
    }

    private static async Task TestLogicalRetryIncidentFailClosedAsync()
    {
        await WithRootAsync(async root =>
        {
            var sessionsRoot = Path.Combine(root, "sessions");
            foreach (var fixture in new[] { "mismatch", "attachment", "multiple" })
            {
                var threadId = Guid.NewGuid().ToString("D");
                var sourceTurnId = Guid.NewGuid().ToString("D");
                var targetTurnId = Guid.NewGuid().ToString("D");
                var clientId = Guid.NewGuid().ToString("D");
                var userLines = fixture switch
                {
                    "mismatch" => new object[]
                    {
                        UserResponseItem(sourceTurnId, "0"),
                        UserMessageEvent("different", clientId)
                    },
                    "attachment" =>
                    [
                        UnknownUserResponseItem(sourceTurnId),
                        UserMessageEvent("0", clientId)
                    ],
                    _ =>
                    [
                        UserResponseItem(sourceTurnId, "first"),
                        UserResponseItem(sourceTurnId, "second"),
                        UserMessageEvent("second", clientId)
                    ]
                };
                await WriteRolloutLinesAsync(
                    sessionsRoot,
                    threadId,
                    [
                        TaskStarted(sourceTurnId),
                        .. userLines,
                        TaskStarted(targetTurnId),
                        HighDemandTaskComplete(targetTurnId)
                    ]);
                var terminal = await new LocalConversationHistoryReader(sessionsRoot)
                    .ReadLatestTerminalEventAsync(threadId);
                Ensure(
                    terminal is not null &&
                    !terminal.Turn.HasUserMessage &&
                    terminal.Turn.HasAmbiguousActivity,
                    fixture + " logical incident evidence did not fail closed");
            }

            var oversizedThreadId = Guid.NewGuid().ToString("D");
            var oversizedSourceTurnId = Guid.NewGuid().ToString("D");
            var oversizedTargetTurnId = Guid.NewGuid().ToString("D");
            await WriteRolloutLinesAsync(
                sessionsRoot,
                oversizedThreadId,
                [
                    TaskStarted(oversizedSourceTurnId),
                    UserResponseItem(oversizedSourceTurnId, "0"),
                    UserMessageEvent("0", Guid.NewGuid().ToString("D")),
                    OpaqueEvent(new string('x', (33 * 1024 * 1024))),
                    TaskStarted(oversizedTargetTurnId),
                    HighDemandTaskComplete(oversizedTargetTurnId)
                ]);
            var oversized = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(oversizedThreadId);
            Ensure(
                oversized is not null &&
                !oversized.Turn.HasUserMessage &&
                oversized.Turn.HasAmbiguousActivity,
                "a rollout above the 32 MiB incident limit was scanned");

            var lineLimitThreadId = Guid.NewGuid().ToString("D");
            var lineLimitSourceTurnId = Guid.NewGuid().ToString("D");
            var lineLimitTargetTurnId = Guid.NewGuid().ToString("D");
            await WriteLineLimitRolloutAsync(
                sessionsRoot,
                lineLimitThreadId,
                lineLimitSourceTurnId,
                lineLimitTargetTurnId);
            var lineLimited = await new LocalConversationHistoryReader(sessionsRoot)
                .ReadLatestTerminalEventAsync(lineLimitThreadId);
            Ensure(
                lineLimited is not null &&
                !lineLimited.Turn.HasUserMessage &&
                lineLimited.Turn.HasAmbiguousActivity,
                "a rollout above the 100000-line incident limit was scanned");
        });
    }

    private static Task TestPlainTextRecoveryTransportBoundaryAsync()
    {
        var rawFutureInput = "[{\"type\":\"futureInput\",\"value\":\"must-not-pass-through\"}]";
        var encoded = DesktopIpcClient.BuildNativeOriginalInput(
            rawFutureInput,
            "6",
            originalHasAttachments: false);
        Ensure(
            encoded.ValueKind == JsonValueKind.Array &&
            encoded.GetArrayLength() == 1 &&
            encoded[0].GetProperty("type").GetString() == "text" &&
            encoded[0].GetProperty("text").GetString() == "6" &&
            !encoded.GetRawText().Contains("futureInput", StringComparison.Ordinal),
            "text recovery passed through an unproved raw structured input shape");

        var textTurn = CreateTurn(Case("text-429", "failed", "rate_limit", 429));
        var attachmentTurn = textTurn with { HasAttachments = true };
        Ensure(
            !RecoveryService.RequiresStructuredInputReplay(
                textTurn,
                RecoveryActionKind.ResendOriginal) &&
            !RecoveryService.RequiresStructuredInputReplay(
                attachmentTurn,
                RecoveryActionKind.SendContinue) &&
            RecoveryService.RequiresStructuredInputReplay(
                attachmentTurn,
                RecoveryActionKind.ResendOriginal),
            "the production semantic-proof boundary was not limited to structured attachment replay");
        return Task.CompletedTask;
    }

    private static async Task WriteRolloutAsync(
        string sessionsRoot,
        string threadId,
        string turnId,
        IReadOnlyList<object> betweenStartAndTerminal)
    {
        var day = Path.Combine(sessionsRoot, "2026", "08", "24");
        Directory.CreateDirectory(day);
        var path = Path.Combine(day, $"rollout-2026-08-24T00-00-00-{threadId}.jsonl");
        var lines = new List<string>
        {
            JsonSerializer.Serialize(new
            {
                timestamp = "2026-08-24T00:00:00.000Z",
                type = "event_msg",
                payload = new { type = "task_started", turn_id = turnId, started_at = 100L }
            }),
            JsonSerializer.Serialize(new
            {
                timestamp = "2026-08-24T00:00:00.001Z",
                type = "response_item",
                payload = new
                {
                    type = "message",
                    role = "developer",
                    content = new[] { new { type = "input_text", text = "bounded fixture" } },
                    internal_chat_message_metadata_passthrough = new { turn_id = turnId }
                }
            })
        };
        lines.AddRange(betweenStartAndTerminal.Select(item => JsonSerializer.Serialize(item)));
        lines.Add(JsonSerializer.Serialize(new
        {
            timestamp = "2026-08-24T00:00:01.000Z",
            type = "event_msg",
            payload = new
            {
                type = "task_complete",
                turn_id = turnId,
                last_agent_message = (string?)null,
                error = new
                {
                    message = "We're currently experiencing high demand.",
                    codex_error_info = "responseTooManyFailedAttempts",
                    http_status_code = 429
                },
                started_at = 100L,
                completed_at = 200L
            }
        }));
        await File.WriteAllTextAsync(path, string.Join('\n', lines) + "\n");
    }

    private static object UserResponseItem(string turnId, string text) => new
    {
        timestamp = "2026-08-24T00:00:00.100Z",
        type = "response_item",
        payload = new
        {
            type = "message",
            role = "user",
            content = new[] { new { type = "input_text", text } },
            internal_chat_message_metadata_passthrough = new { turn_id = turnId }
        }
    };

    private static object UserMessageEvent(string text, string clientId) => new
    {
        timestamp = "2026-08-24T00:00:00.150Z",
        type = "event_msg",
        payload = new { type = "user_message", message = text, client_id = clientId }
    };

    private static object TaskStarted(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:00.000Z",
        type = "event_msg",
        payload = new { type = "task_started", turn_id = turnId, started_at = 100L }
    };

    private static object HighDemandTaskComplete(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:01.000Z",
        type = "event_msg",
        payload = new
        {
            type = "task_complete",
            turn_id = turnId,
            last_agent_message = (string?)null,
            error = new
            {
                message = "We're currently experiencing high demand, which may cause temporary errors.",
                codex_error_info = "internal_server_error"
            },
            started_at = 100L,
            completed_at = 200L
        }
    };

    private static object ThreadRolledBack() => new
    {
        timestamp = "2026-08-24T00:00:01.100Z",
        type = "event_msg",
        payload = new { type = "thread_rolled_back" }
    };

    private static object TurnAborted(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:01.200Z",
        type = "event_msg",
        payload = new { type = "turn_aborted", turn_id = turnId, reason = "interrupted" }
    };

    private static object ReasoningResponseItem(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:01.300Z",
        type = "response_item",
        payload = new
        {
            type = "reasoning",
            id = Guid.NewGuid().ToString("D"),
            summary = Array.Empty<object>(),
            internal_chat_message_metadata_passthrough = new { turn_id = turnId }
        }
    };

    private static object AssistantResponseItem(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:01.400Z",
        type = "response_item",
        payload = new
        {
            type = "message",
            role = "assistant",
            phase = "commentary",
            content = new[] { new { type = "output_text", text = "partial work" } },
            internal_chat_message_metadata_passthrough = new { turn_id = turnId }
        }
    };

    private static object ToolResponseItem(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:00.500Z",
        type = "response_item",
        payload = new
        {
            type = "function_call",
            id = Guid.NewGuid().ToString("D"),
            name = "fixture",
            arguments = "{}",
            internal_chat_message_metadata_passthrough = new { turn_id = turnId }
        }
    };

    private static object UnknownUserResponseItem(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:00.100Z",
        type = "response_item",
        payload = new
        {
            type = "message",
            role = "user",
            content = new[] { new { type = "input_image", image_url = "opaque" } },
            internal_chat_message_metadata_passthrough = new { turn_id = turnId }
        }
    };

    private static object TurnContext(string turnId) => new
    {
        timestamp = "2026-08-24T00:00:00.200Z",
        type = "turn_context",
        payload = new { turn_id = turnId, cwd = @"D:\Workspace" }
    };

    private static object OpaqueEvent(string data) => new
    {
        timestamp = "2026-08-24T00:00:00.300Z",
        type = "event_msg",
        payload = new { type = "opaque_fixture_event", data }
    };

    private static string EnvironmentContextText() =>
        "<environment_context>\n  <cwd>D:\\Workspace</cwd>\n</environment_context>";

    private static TurnSnapshot CreateHighDemandAppServerTurn(string turnId) => new(
        turnId,
        "failed",
        "We're currently experiencing high demand, which may cause temporary errors.",
        "internal_server_error",
        HttpStatusCode: null,
        UserText: string.Empty,
        HasAttachments: false,
        HasAssistantOutput: false,
        HasWorkOutput: false,
        OutputFingerprint: "logical-retry-incident",
        StartedAt: 100,
        CompletedAt: 200,
        HasUserMessage: false,
        HasCompleteItemEvidence: true);

    private static async Task WriteRolloutLinesAsync(
        string sessionsRoot,
        string threadId,
        IReadOnlyList<object> records)
    {
        var day = Path.Combine(sessionsRoot, "2026", "08", "24");
        Directory.CreateDirectory(day);
        var path = Path.Combine(day, $"rollout-2026-08-24T00-00-00-{threadId}.jsonl");
        await File.WriteAllTextAsync(
            path,
            string.Join('\n', records.Select(record => JsonSerializer.Serialize(record))) + "\n");
    }

    private static async Task WriteLineLimitRolloutAsync(
        string sessionsRoot,
        string threadId,
        string sourceTurnId,
        string targetTurnId)
    {
        var day = Path.Combine(sessionsRoot, "2026", "08", "24");
        Directory.CreateDirectory(day);
        var path = Path.Combine(day, $"rollout-2026-08-24T00-00-00-{threadId}.jsonl");
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false));
        await writer.WriteLineAsync(JsonSerializer.Serialize(TaskStarted(sourceTurnId)));
        await writer.WriteLineAsync(JsonSerializer.Serialize(UserResponseItem(sourceTurnId, "0")));
        await writer.WriteLineAsync(JsonSerializer.Serialize(
            UserMessageEvent("0", Guid.NewGuid().ToString("D"))));
        var padding = JsonSerializer.Serialize(OpaqueEvent("x"));
        for (var index = 0; index < 100_000; index++)
        {
            await writer.WriteLineAsync(padding);
        }

        await writer.WriteLineAsync(JsonSerializer.Serialize(TaskStarted(targetTurnId)));
        await writer.WriteLineAsync(JsonSerializer.Serialize(HighDemandTaskComplete(targetTurnId)));
    }

    private static async Task TestRejectedServicePathAsync()
    {
        await WithRootAsync(async root =>
        {
            var classifier = new RecoveryClassifier();
            var failedTurn = CreateTurn(Case("unauthorized", "failed", "unauthorized", 401));
            var decision = classifier.Classify(failedTurn);
            Ensure(decision.Action == RecoveryActionKind.None, "service fixture was not rejected by classification");
            var forgedDecision = new RecoveryDecision(
                RecoveryActionKind.ResendOriginal,
                TaskHealth.NeedsAttention,
                "forged caller decision",
                IsTransient: true);

            var journal = new RecoveryOperationJournal(root);
            using var log = new GuardianLog(root);
            await using var stateReader = new AppServerClient(new CodexCliLocator(), log);
            await using var desktop = new DesktopIpcClient(log);
            var service = new RecoveryService(
                stateReader,
                desktop,
                new DesktopThreadOwnerActivator(desktop, log),
                journal,
                log);
            var result = await service.ExecuteAsync(
                CreateThread(),
                failedTurn,
                forgedDecision,
                SettingsService.DefaultContinueMessage,
                includeSubAgents: false,
                service.BeginScopeValidationGeneration(),
                isDispatchAllowed: static () => true);

            Ensure(
                !result.Success &&
                result.IsUserBlocked &&
                result.FailureKind == RecoveryFailureKind.StateChanged,
                "RecoveryService trusted a forged recovery action instead of reclassifying");
            Ensure(
                !File.Exists(journal.JournalPath) &&
                !File.Exists(journal.BackupPath) &&
                !File.Exists(journal.InitializationMarkerPath),
                "RecoveryService created durable journal state for a rejected classification");
            Ensure(
                !stateReader.IsConnected && !desktop.IsConnected,
                "RecoveryService opened app-server or Desktop IPC for a rejected classification");
        });
    }

    private static async Task TestUnprovenNativeChannelServicePathAsync()
    {
        await WithRootAsync(async root =>
        {
            var classifier = new RecoveryClassifier();
            // Resend recovery now runs through the owner's in-place retry contract, so capability is
            // no longer the blocker. The remaining gate is the production requirement that the
            // current Desktop native owner channel be proven before anything is dispatched.
            var failedTurn = CreateTurn(Case("http-500", "failed", "server_error", 500));
            var decision = classifier.Classify(failedTurn);
            Ensure(
                decision is { Action: RecoveryActionKind.ResendOriginal, IsTransient: true },
                "service fixture did not require an original-message resend");

            var journal = new RecoveryOperationJournal(root);
            using var log = new GuardianLog(root);
            await using var stateReader = new AppServerClient(new CodexCliLocator(), log);
            await using var desktop = new DesktopIpcClient(log);
            Ensure(
                DesktopIpcClient
                    .DescribeStockRecoveryCapabilities(RecoveryActionKind.ResendOriginal)
                    .IsGuardedAutomaticRecoveryEligible,
                "resend recovery lost the in-place retry capability that makes this a channel-proof test");
            var service = new RecoveryService(
                stateReader,
                desktop,
                new DesktopThreadOwnerActivator(desktop, log),
                journal,
                log,
                requireCurrentNativeChannel: true);
            var result = await service.ExecuteAsync(
                CreateThread(),
                failedTurn,
                decision,
                SettingsService.DefaultContinueMessage,
                includeSubAgents: false,
                service.BeginScopeValidationGeneration(),
                isDispatchAllowed: static () => true);

            Ensure(
                !result.Success &&
                result.IsUserBlocked &&
                // The refusal itself is what this case guards, not its severity. An unproven channel is a
                // transient condition -- Guardian starting before Codex Desktop, or Desktop restarting --
                // and DesktopIncompatible made it permanent: that kind locks until a new failed turn
                // arrives and carries no retry time, so a task refused this way was never retried even
                // after the channel proved itself seconds later. DesktopUnavailable already waits on the
                // desktop signal, so it is asserted here and the version verdict is asserted absent.
                result.FailureKind == RecoveryFailureKind.DesktopUnavailable &&
                result.Message.Contains("native owner channel", StringComparison.OrdinalIgnoreCase) &&
                result.Message.Contains("nothing was sent", StringComparison.OrdinalIgnoreCase),
                "an unproven native owner channel did not fail closed with a truthful, retryable channel result");
            Ensure(
                !File.Exists(journal.JournalPath) &&
                !File.Exists(journal.BackupPath) &&
                !File.Exists(journal.InitializationMarkerPath),
                "an unproven native owner channel created durable journal state");
            Ensure(
                !stateReader.IsConnected && !desktop.IsConnected,
                "an unproven native owner channel opened app-server or Desktop IPC");
        });
    }

    private static ClassificationCase Case(
        string name,
        string status,
        string? errorCode,
        int? httpStatus,
        string? errorMessage = "temporary provider failure") =>
        new(name, status, errorCode, httpStatus, errorMessage);

    private static TurnSnapshot CreateTurn(
        ClassificationCase candidate,
        bool confirmedTerminal = true,
        bool hasKnownWork = false) =>
        new(
            Guid.NewGuid().ToString("D"),
            candidate.Status,
            candidate.ErrorMessage,
            candidate.ErrorCode,
            candidate.HttpStatus,
            "perform the requested work",
            HasAttachments: false,
            HasAssistantOutput: hasKnownWork,
            HasWorkOutput: hasKnownWork,
            OutputFingerprint: "classification-offline",
            StartedAt: 1,
            CompletedAt: 2,
            HasConfirmedLocalTerminal: confirmedTerminal,
            UserMessageClientIds: [Guid.NewGuid().ToString("D")],
            HasUserMessage: true,
            HasCommentaryOutput: hasKnownWork,
            HasReasoningOutput: hasKnownWork,
            HasCompleteItemEvidence: true,
            IsSingleTextUserInput: true);

    private static ThreadSummary CreateThread() =>
        new(
            Guid.NewGuid().ToString("D"),
            "offline classification",
            string.Empty,
            @"D:\Workspace",
            "appServer",
            CreatedAt: 1,
            UpdatedAt: 2,
            IsSubAgent: false,
            IsEphemeral: false);

    private static async Task WithRootAsync(Func<string, Task> action)
    {
        var parent = Environment.GetEnvironmentVariable("CODEX_GUARDIAN_TEST_DATA_ROOT");
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new InvalidOperationException("CODEX_GUARDIAN_TEST_DATA_ROOT is required");
        }

        var root = Path.GetFullPath(Path.Combine(
            parent,
            "automatic-recovery-classification-" + Guid.NewGuid().ToString("N")));
        Ensure(
            root.StartsWith("D:\\", StringComparison.OrdinalIgnoreCase),
            "classification tests use D-drive data");
        try
        {
            await action(root);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> action,
        Action<bool, string> assert)
    {
        try
        {
            await action();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, $"{name}: {exception.GetType().Name} - {exception.Message}");
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record ClassificationCase(
        string Name,
        string Status,
        string? ErrorCode,
        int? HttpStatus,
        string? ErrorMessage);
}
