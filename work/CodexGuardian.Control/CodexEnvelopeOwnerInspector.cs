using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace CodexGuardian.Control;

internal static partial class CodexStructuredInputAsarInspector
{
    private static bool TryInspectEnvelopeOwnerSemantics(string source, out OwnerSemanticShape shape)
    {
        shape = default!;
        if (!TryFindEnvelopeReceiver(source, out var receiver) ||
            !TryFindEnvelopeExecutor(source, receiver, out var executor) ||
            !TryTraceEnvelopeCoordinator(source, executor, out var flow, out var flowBindings) ||
            !TryProveEnvelopeSubmission(source, flow, flowBindings))
        {
            return false;
        }

        var kinds = InspectInputKinds(source);
        if (!kinds.Contains("text")) return false;
        // Existing-conversation proof is not create-and-first-turn idempotency proof.
        var creation = new CodexNewConversationAsarSemantics(
            false, false, false, false, false, false, false, false, false,
            HashText("codex-envelope-create-unverified-v1"));
        shape = new OwnerSemanticShape(
            string.Empty,
            new HashSet<string>(StringComparer.Ordinal) { FollowerStartMethod },
            kinds,
            HashText("codex-envelope-owner-v1\nreceiver=turnStart\nrequest=threadId,input\n" +
                "clientUserMessageId=preserved\nowner=checked-before-native\n" +
                "coordinator=nonempty-input-direct\nreceipt=turn/start-returned"),
            HashText("codex-envelope-input-v1\n" + string.Join('\n', kinds.Order(StringComparer.Ordinal))),
            creation);
        return true;
    }

    private static bool TryFindEnvelopeReceiver(string source, out string receiver)
    {
        receiver = string.Empty;
        var matches = new List<string>();
        foreach (var at in FindQuotedLiteralStarts(source, FollowerStartMethod))
        {
            if (!EnvelopeMatch(source[Math.Max(0, at - 32)..at], @"case\s*$").Success) continue;
            var begin = at + FollowerStartMethod.Length + 2;
            var segment = source[begin..Math.Min(source.Length, begin + 8192)];
            var call = EnvelopeMatch(segment,
                @"^\s*:\s*\{\s*let\s+(?<result>[$\w]+)=await\s+(?<manager>[$\w]+)\.startTurn\(");
            if (!call.Success) continue;
            var opening = call.Length - 1;
            var closing = FindMatchingDelimiter(segment, opening, '(', ')');
            var args = SplitTopLevelArguments(segment[(opening + 1)..closing]);
            if (args.Count != 2) continue;
            var target = EnvelopeMatch(args[0], @"^(?<request>[$\w]+)\.params\.conversationId$");
            if (!target.Success || args[1] != target.Groups["request"].Value + ".params.turnStart") continue;
            var request = target.Groups["request"].Value;
            if (!EnvelopeMatch(segment[(closing + 1)..],
                    @"^;?return\{method:" + Regex.Escape(request) +
                    @"\.method,result:\{result:" + Regex.Escape(call.Groups["result"].Value) + @"\}\}").Success ||
                !TryFindContainingNamedFunction(source, at, out var name, out var parameters) ||
                parameters.Count != 2 || parameters[0] != call.Groups["manager"].Value || parameters[1] != request)
                continue;
            matches.Add(name);
        }

        if (matches.Count != 1) return false;
        receiver = matches[0];
        return true;
    }

    private static bool TryFindEnvelopeExecutor(string source, string receiver, out JavaScriptMethod executor)
    {
        executor = default!;
        var matches = new List<JavaScriptMethod>();
        var search = 0;
        const string marker = "async handleThreadFollowerRequest";
        while ((search = source.IndexOf(marker, search, StringComparison.Ordinal)) >= 0)
        {
            var at = search;
            search += marker.Length;
            if (!TryFindContainingClassBody(source, at, out var body) ||
                !TryFindTopLevelAsyncObjectMethod(body, "handleThreadFollowerRequest", out var handler) ||
                !TryFindTopLevelPlainObjectMethod(body, "startTurn", out var start) ||
                !TryFindTopLevelPlainObjectMethod(body, "executeTurnStart", out var execute)) continue;
            var request = handler.Parameters.Trim();
            if (!IsIdentifier(request) ||
                !EnvelopeMatch(handler.Body, @"^return\s+" + Regex.Escape(receiver) +
                    @"\(this," + Regex.Escape(request) + @"\);?$").Success) continue;
            var args = SplitTopLevelArguments(start.Parameters);
            if (args.Count != 3 || args.Any(arg => !IsIdentifier(arg)) ||
                !EnvelopeMatch(start.Body, @"^return this\.executeTurnStart\(" + Regex.Escape(args[0]) +
                    "," + Regex.Escape(args[1]) + @",(?:`direct`|""direct""|'direct'),void 0," +
                    Regex.Escape(args[2]) + @"\);?$").Success) continue;
            matches.Add(execute);
        }

        if (matches.Count != 1) return false;
        executor = matches[0];
        return true;
    }

    private static bool TryTraceEnvelopeCoordinator(
        string source, JavaScriptMethod executor, out JavaScriptFunction flow,
        out IReadOnlyDictionary<string, string> flowBindings)
    {
        flow = default!;
        flowBindings = new Dictionary<string, string>();
        var args = SplitTopLevelArguments(executor.Parameters);
        if (args.Count < 2 || !IsIdentifier(args[0]) || !IsIdentifier(args[1])) return false;
        var target = args[0];
        var operation = args[1];
        var client = EnvelopeMatch(executor.Body, @"\blet (?<id>[$\w]+)=" + Regex.Escape(operation) +
            @"\.request\.clientUserMessageId\?\?this\.history\.createSearchIslandId\(\);");
        var call = EnvelopeMatch(executor.Body, @"\breturn (?<function>[$\w]+)\(\{");
        if (!client.Success || !call.Success || client.Index > call.Index) return false;
        var open = call.Index + call.Length - 1;
        var close = FindMatchingDelimiter(executor.Body, open, '{', '}');
        var properties = EnvelopeProperties(executor.Body[(open + 1)..close]);
        if (!EnvelopeProperty(properties, "manager", "this") ||
            !EnvelopeProperty(properties, "conversationId", target) ||
            !EnvelopeProperty(properties, "operation", operation) ||
            !EnvelopeProperty(properties, "clientUserMessageId", client.Groups["id"].Value) ||
            !TryProveEnvelopeCapabilities(source, properties, target, client.Groups["id"].Value) ||
            !TryReadEnvelopeFunction(source, call.Groups["function"].Value, out var coordinator) ||
            coordinator.Parameters.Count != 1 || !IsIdentifier(coordinator.Parameters[0])) return false;
        var parameter = coordinator.Parameters[0];
        var aliases = EnvelopeMatch(coordinator.Body, @"^let\{(?<bindings>[^{}]+)\}=" +
            Regex.Escape(parameter) + @";if\(");
        if (!aliases.Success) return false;
        var bindings = EnvelopeProperties(aliases.Groups["bindings"].Value);
        if (!bindings.TryGetValue("operation", out var inputOperation) || !IsIdentifier(inputOperation)) return false;
        open = aliases.Length - 1;
        close = FindMatchingDelimiter(coordinator.Body, open, '(', ')');
        if (!coordinator.Body[(open + 1)..close].StartsWith(inputOperation + ".request.input.length!==0||", StringComparison.Ordinal))
            return false;
        var direct = EnvelopeMatch(coordinator.Body[(close + 1)..], @"^return (?<flow>[$\w]+)\(" +
            Regex.Escape(parameter) + @"\);");
        if (!direct.Success || !TryReadEnvelopeFunction(source, direct.Groups["flow"].Value, out flow) ||
            flow.Parameters.Count != 2 || !flow.Parameters[0].StartsWith('{') || !flow.Parameters[0].EndsWith('}'))
            return false;
        var parsedBindings = EnvelopeProperties(flow.Parameters[0][1..^1]);
        flowBindings = parsedBindings;
        return new[] { "manager", "conversationId", "operation", "clientUserMessageId", "capabilities", "origin" }
            .All(key => parsedBindings.TryGetValue(key, out var value) && IsIdentifier(value));
    }

    private static bool TryProveEnvelopeSubmission(
        string source, JavaScriptFunction flow, IReadOnlyDictionary<string, string> bindings)
    {
        var manager = bindings["manager"];
        var conversation = bindings["conversationId"];
        var operation = bindings["operation"];
        var client = bindings["clientUserMessageId"];
        var capabilities = bindings["capabilities"];
        var body = flow.Body;
        var requestAlias = EnvelopeMatch(body, @"^let (?<request>[$\w]+)=" + Regex.Escape(operation) + @"\.request[,;]");
        if (!requestAlias.Success) return false;
        var targetGuard = EnvelopeMatch(body, @"\bif\(" + Regex.Escape(requestAlias.Groups["request"].Value) +
            @"\.threadId!==" + Regex.Escape(conversation) + @"\)throw\b");
        var factory = EnvelopeMatch(body, @"\blet (?<prepared>[$\w]+)=(?<factory>[$\w]+)\(" +
            Regex.Escape(manager) + "," + Regex.Escape(conversation) + "," + Regex.Escape(operation) + "," +
            Regex.Escape(client) + "," + Regex.Escape(bindings["origin"]) + "," + Regex.Escape(capabilities) + @",");
        if (!targetGuard.Success || !factory.Success || targetGuard.Index > factory.Index) return false;
        var preparation = factory.Groups["prepared"].Value;
        var followers = FindCalls(body, manager, "sendThreadFollowerRequest")
            .Where(call => ContainsQuotedLiteral(call.Arguments, FollowerStartMethod)).ToArray();
        if (followers.Length != 1) return false;
        var forwardArgs = SplitTopLevelArguments(followers[0].Arguments);
        if (forwardArgs.Count != 3 || !TryEnvelopeObject(forwardArgs[2], out var forward) ||
            !EnvelopeProperty(forward, "conversationId", conversation) ||
            !forward.TryGetValue("turnStart", out var envelopeText) ||
            !TryEnvelopeObject(envelopeText, out var envelope) ||
            !EnvelopeProperty(envelope, "request", preparation + ".request") ||
            !envelope.ContainsKey("context")) return false;
        var prepared = EnvelopeMatch(body, @"\blet (?<value>[$\w]+)=await " + Regex.Escape(preparation) + @"\.prepare\(");
        if (!prepared.Success) return false;
        var native = FindCalls(body, manager, "sendRequest")
            .Where(call => ContainsQuotedLiteral(call.Arguments, NativeStartMethod)).ToArray();
        if (native.Length != 1 || !HasOwnerRoleGuard(body, manager, conversation, followers[0].Start, native[0].Start))
            return false;
        var nativeArgs = SplitTopLevelArguments(native[0].Arguments);
        if (nativeArgs.Count != 3 || !IsIdentifier(nativeArgs[1]) ||
            !TryEnvelopeObject(nativeArgs[2], out var nativeOptions) ||
            !EnvelopeProperty(nativeOptions, "clientUserMessageId", client)) return false;
        var adapter = EnvelopeMatch(body[..native[0].Start], @"\b" + Regex.Escape(nativeArgs[1]) +
            @"=(?<adapter>[$\w]+)\(" + Regex.Escape(prepared.Groups["value"].Value) +
            @"\.request," + Regex.Escape(manager) + @"\.requestClient\.getAppServerVersion\(\)\);");
        if (!adapter.Success || adapter.Index < prepared.Index ||
            !TryReadEnvelopeFunction(source, adapter.Groups["adapter"].Value, out var adapt) ||
            adapt.Parameters.Count != 2 || !EnvelopeMatch(adapt.Body,
                @"^return [$\w]+\(" + Regex.Escape(adapt.Parameters[1]) +
                @",(?:`turnTrigger`|""turnTrigger""|'turnTrigger')\)\?" + Regex.Escape(adapt.Parameters[0]) +
                @":\{\.\.\." + Regex.Escape(adapt.Parameters[0]) + @",turnTrigger:void 0\};?$").Success)
            return false;
        var assignment = EnvelopeMatch(body[Math.Max(0, native[0].Start - 80)..native[0].Start], @"(?<receipt>[$\w]+)=await\s*$");
        if (!assignment.Success || !EnvelopeMatch(body, @"return " + Regex.Escape(assignment.Groups["receipt"].Value) + @";?$").Success)
            return false;
        return !HasEnvelopeIdentityMutation(body, operation, requestAlias.Groups["request"].Value) &&
            TryProveEnvelopePreparation(source, factory.Groups["factory"].Value);
    }

    private static bool TryProveEnvelopeCapabilities(
        string source, IReadOnlyDictionary<string, string> executorProperties, string target, string client)
    {
        if (!executorProperties.TryGetValue("capabilities", out var expression)) return false;
        var call = EnvelopeMatch(expression, @"^(?<factory>[$\w]+)\((?<options>\{[\s\S]+\})\)$");
        if (!call.Success || !TryEnvelopeObject(call.Groups["options"].Value, out var options) ||
            !EnvelopeProperty(options, "conversationId", target) ||
            !EnvelopeProperty(options, "clientUserMessageId", client) ||
            !EnvelopeProperty(options, "runtime", "this.runtime") ||
            !TryReadEnvelopeFunction(source, call.Groups["factory"].Value, out var factory) ||
            factory.Parameters.Count != 1 || !TryEnvelopeObject(factory.Parameters[0], out var aliases) ||
            !aliases.TryGetValue("runtime", out var runtime) ||
            !aliases.TryGetValue("conversationId", out var conversation) ||
            !factory.Body.StartsWith("return{", StringComparison.Ordinal)) return false;
        var close = FindMatchingDelimiter(factory.Body, 6, '{', '}');
        var result = EnvelopeProperties(factory.Body[7..close]);
        return EnvelopeProperty(result, "prepareRequest", runtime + ".prepareTurnRequest?.bind(" + runtime + "," + conversation + ")");
    }

    private static bool HasEnvelopeIdentityMutation(string body, params string[] variables) =>
        variables.Any(variable => EnvelopeMatch(body, @"\b" + Regex.Escape(variable) +
            @"(?:\.request)?\.(?:input|threadId|clientUserMessageId)\s*(?:=(?!=)|\+\+|--)").Success);

    private static bool TryProveEnvelopePreparation(string source, string factoryName)
    {
        if (!TryReadEnvelopeFunction(source, factoryName, out var factory) || factory.Parameters.Count != 8)
            return false;
        var p = factory.Parameters;
        if (p.Any(value => !IsIdentifier(value))) return false;
        var aliases = EnvelopeMatch(factory.Body, @"^let (?<operation>[$\w]+)=" + Regex.Escape(p[2]) +
            @",(?<request>[$\w]+)=\k<operation>\.request[,;]");
        if (!aliases.Success) return false;
        var operation = aliases.Groups["operation"].Value;
        var request = aliases.Groups["request"].Value;
        var resultAt = factory.Body.IndexOf("return{", StringComparison.Ordinal);
        if (resultAt < 0) return false;
        var open = resultAt + "return".Length;
        var close = FindMatchingDelimiter(factory.Body, open, '{', '}');
        var properties = EnvelopeProperties(factory.Body[(open + 1)..close]);
        if (!properties.TryGetValue("request", out var requestText) || !TryEnvelopeObject(requestText, out var forward) ||
            !EnvelopeProperty(forward, "...", request) || !EnvelopeProperty(forward, "clientUserMessageId", p[3]) ||
            forward.Keys.Any(key => key is not ("..." or "clientUserMessageId" or "additionalContext")) ||
            !properties.TryGetValue("prepare", out var prepareText)) return false;
        var prepare = EnvelopeMatch(prepareText, @"^async (?<state>[$\w]+)=>\{");
        if (!prepare.Success || !prepareText.EndsWith('}')) return false;
        var body = prepareText[(prepare.Length)..^1];
        var builder = EnvelopeMatch(body, @"\blet (?<result>[$\w]+)=await (?<builder>[$\w]+)\(" +
            Regex.Escape(p[0]) + "," + Regex.Escape(p[1]) + "," + Regex.Escape(operation) + "," + Regex.Escape(p[3]) + @",");
        if (!builder.Success) return false;
        var builderOpen = body.IndexOf('(', builder.Index);
        var builderClose = FindMatchingDelimiter(body, builderOpen, '(', ')');
        var builderArguments = SplitTopLevelArguments(body[(builderOpen + 1)..builderClose]);
        if (builderArguments.Count != 7 || builderArguments[4] != forward["additionalContext"] ||
            builderArguments[5] != prepare.Groups["state"].Value || builderArguments[6] != p[5]) return false;
        var result = builder.Groups["result"].Value;
        if (!EnvelopeMatch(body, @"return " + Regex.Escape(p[5]) + @"\.prepareRequest==null\?" + Regex.Escape(result) +
                @":\{\.\.\." + Regex.Escape(result) + @",request:await " + Regex.Escape(p[5]) +
                @"\.prepareRequest\(" + Regex.Escape(result) + @"\.request\)\};?$").Success ||
            !TryReadEnvelopeFunction(source, builder.Groups["builder"].Value, out var wrapper) ||
            wrapper.Parameters.Count != 7) return false;
        var w = wrapper.Parameters;
        var forwarding = EnvelopeMatch(wrapper.Body, @"let\{useAppServerPermissionDefault:(?<permission>[$\w]+),\.\.\.(?<rest>[$\w]+)\}=await (?<builder>[$\w]+)\(" +
            string.Join(',', w.Take(6).Select(Regex.Escape)) + @",\{");
        if (!forwarding.Success) return false;
        var rest = forwarding.Groups["rest"].Value;
        var returnedAt = wrapper.Body.LastIndexOf("return{", StringComparison.Ordinal);
        if (returnedAt < 0) return false;
        open = returnedAt + "return".Length;
        close = FindMatchingDelimiter(wrapper.Body, open, '{', '}');
        var returned = EnvelopeProperties(wrapper.Body[(open + 1)..close]);
        if (!EnvelopeProperty(returned, "...", rest) || returned.Count != 2 || !returned.ContainsKey("params")) return false;
        if (!TryReadEnvelopeFunction(source, forwarding.Groups["builder"].Value, out var builderFunction) ||
            builderFunction.Parameters.Count != 7) return false;
        var b = builderFunction.Parameters;
        var original = EnvelopeMatch(builderFunction.Body, @"^let (?<request>[$\w]+)=" + Regex.Escape(b[2]) + @"\.request[,;]");
        if (!original.Success) return false;
        var originals = new List<string>();
        foreach (Match match in EnvelopeMatches(builderFunction.Body, @"\b(?<name>[$\w]+)=\{threadId:" + Regex.Escape(b[1]) + @",").Cast<Match>())
        {
            open = builderFunction.Body.IndexOf('{', match.Index);
            close = FindMatchingDelimiter(builderFunction.Body, open, '{', '}');
            var fields = EnvelopeProperties(builderFunction.Body[(open + 1)..close]);
            if (EnvelopeProperty(fields, "threadId", b[1]) && EnvelopeProperty(fields, "clientUserMessageId", b[3]) &&
                EnvelopeProperty(fields, "input", original.Groups["request"].Value + ".input")) originals.Add(match.Groups["name"].Value);
        }
        if (originals.Count != 1 || HasEnvelopeIdentityMutation(builderFunction.Body, b[2], original.Groups["request"].Value, originals[0]) ||
            !EnvelopeMatch(builderFunction.Body,
                @"\{request:" + Regex.Escape(originals[0]) + @",params:").Success) return false;
        return HasPreservingEnvelopeRuntimeHook(source);
    }

    private static bool HasPreservingEnvelopeRuntimeHook(string source)
    {
        // The only optional runtime hook may add cyberAccessProgram, never replace target or input.
        var hooks = EnvelopeMatches(source, @"\bprepareTurnRequest:[$\w]+==null\?void 0:async\((?<target>[$\w]+),(?<request>[$\w]+)\)=>\{")
            .Cast<Match>().ToArray();
        if (hooks.Length != 1) return false;
        var hook = hooks[0];
        var open = hook.Index + hook.Length - 1;
        var close = FindMatchingDelimiter(source, open, '{', '}');
        var body = source[(open + 1)..close];
        var request = hook.Groups["request"].Value;
        return EnvelopeMatch(body, @"return\{\.\.\." + Regex.Escape(request) + @",cyberAccessProgram:[$\w]+\};?$").Success &&
            !EnvelopeMatch(body, Regex.Escape(request) + @"(?:\s*\.[\w$]+|\s*\[[^]]+\])\s*(?:=(?!=)|\+\+|--)").Success;
    }

    private static bool TryReadEnvelopeFunction(string source, string name, out JavaScriptFunction function)
    {
        function = default!;
        if (!IsIdentifier(name)) return false;
        var marker = "function " + name + "(";
        var at = source.IndexOf(marker, StringComparison.Ordinal);
        if (at < 0 || source.IndexOf(marker, at + marker.Length, StringComparison.Ordinal) >= 0) return false;
        var open = at + marker.Length - 1;
        var close = FindMatchingDelimiter(source, open, '(', ')');
        var args = SplitTopLevelArguments(source[(open + 1)..close]);
        open = close + 1;
        SkipWhitespace(source, ref open);
        if (open >= source.Length || source[open] != '{') return false;
        close = FindMatchingDelimiter(source, open, '{', '}');
        if (close - open > 64 * 1024 || args.Count is < 1 or > 16) return false;
        function = new JavaScriptFunction(args, source[(open + 1)..close]);
        return true;
    }

    private static bool TryEnvelopeObject(string value, out IReadOnlyDictionary<string, string> properties)
    {
        properties = new Dictionary<string, string>();
        value = value.Trim();
        if (!value.StartsWith('{') || !value.EndsWith('}') || FindMatchingDelimiter(value, 0, '{', '}') != value.Length - 1)
            return false;
        properties = EnvelopeProperties(value[1..^1]);
        return properties.Count > 0;
    }

    private static IReadOnlyDictionary<string, string> EnvelopeProperties(string body)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in SplitTopLevelArguments(body))
        {
            if (part.StartsWith("...", StringComparison.Ordinal))
            {
                if (!result.TryAdd("...", part[3..].Trim())) return new Dictionary<string, string>();
                continue;
            }
            var match = EnvelopeMatch(part, @"^(?<key>[$\w]+)\s*:\s*(?<value>[\s\S]+)$");
            if (match.Success && !result.TryAdd(match.Groups["key"].Value, match.Groups["value"].Value.Trim()))
                return new Dictionary<string, string>();
        }
        return result;
    }

    private static bool EnvelopeProperty(IReadOnlyDictionary<string, string> properties, string key, string value) =>
        properties.TryGetValue(key, out var actual) && string.Equals(actual, value, StringComparison.Ordinal);

    private static Match EnvelopeMatch(string value, string pattern) =>
        Regex.Match(value, pattern, RegexOptions.CultureInvariant, RegexTimeout);

    private static MatchCollection EnvelopeMatches(string value, string pattern) =>
        Regex.Matches(value, pattern, RegexOptions.CultureInvariant, RegexTimeout);
}
