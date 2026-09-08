using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CodexGuardian.Control;

internal sealed record CodexStructuredInputAsarInspectionLimits(
    long MaximumArchiveBytes,
    int MaximumHeaderBytes,
    int MaximumPackageJsonBytes,
    int MaximumIndexHtmlBytes,
    int MaximumScriptBytes,
    long MaximumTotalReadBytes,
    int MaximumJsonDepth,
    int MaximumJsonValues,
    int MaximumModuleEntries,
    int MaximumDependencyDepth,
    int MaximumImportsPerModule)
{
    // Proven owner modules are not traversed, but their import syntax still gets an
    // independent finite bound so owner short-circuiting cannot bypass this gate.
    internal int MaximumOwnerImportsPerModule { get; init; } = 1024;

    internal static CodexStructuredInputAsarInspectionLimits Default { get; } = new(
        MaximumArchiveBytes: 1024L * 1024 * 1024,
        MaximumHeaderBytes: 32 * 1024 * 1024,
        MaximumPackageJsonBytes: 1024 * 1024,
        MaximumIndexHtmlBytes: 1024 * 1024,
        MaximumScriptBytes: 16 * 1024 * 1024,
        MaximumTotalReadBytes: 32L * 1024 * 1024,
        MaximumJsonDepth: 64,
        MaximumJsonValues: 200_000,
        MaximumModuleEntries: 64,
        MaximumDependencyDepth: 4,
        MaximumImportsPerModule: 128)
    {
        MaximumOwnerImportsPerModule = 1024
    };
}

internal sealed record CodexStructuredInputAsarSelectedEntry(
    string Path,
    long Offset,
    long Size,
    string Sha256);

internal sealed record CodexNewConversationAsarSemantics(
    bool HasCreateAndFirstTurnFlow,
    bool CreationRequestHasStableIdentity,
    bool CreatedConversationReceiptReturned,
    bool FirstTurnRequestHasStableIdentity,
    bool FirstTurnCanBeReconciled,
    bool StableOperationCannotConsumePrewarmedThread,
    bool ClientThreadBindingOccursAfterCreationResponse,
    bool ReceiverCreationIdempotencyProved,
    bool SupportsAutomaticNewConversation,
    string ShapeSha256);

internal sealed record CodexStructuredInputAsarSnapshot(
    string PackageName,
    string ProductName,
    string PackageVersion,
    string MainPath,
    string ModuleRootPath,
    string OwnerEntryPath,
    IReadOnlySet<string> FollowerMethods,
    string StartTurnHostHandler,
    bool StartTurnAssertsOwner,
    string NativeMethod,
    int NativeMethodVersion,
    bool PreservesInput,
    bool PreservesStableClientUserMessageId,
    IReadOnlySet<string> NativeInputKinds,
    string HandlerShapeSha256,
    string InputShapeSha256,
    bool SupportsAttachmentOnly,
    CodexNewConversationAsarSemantics NewConversation,
    string HeaderSha256,
    CodexStructuredInputAsarSelectedEntry PackageJson,
    CodexStructuredInputAsarSelectedEntry WebviewIndex,
    CodexStructuredInputAsarSelectedEntry ModuleRoot,
    CodexStructuredInputAsarSelectedEntry OwnerEntry,
    IReadOnlyList<CodexStructuredInputAsarSelectedEntry> ModuleEntries);

internal sealed class CodexStructuredInputAsarException : IOException
{
    internal CodexStructuredInputAsarException(
        string code,
        bool isCompatibilityFailure,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
        IsCompatibilityFailure = isCompatibilityFailure;
    }

    internal string Code { get; }

    internal bool IsCompatibilityFailure { get; }
}

internal static partial class CodexStructuredInputAsarInspector
{
    private const string PackageJsonPath = "package.json";
    private const string WebviewIndexPath = "webview/index.html";
    private const string FollowerStartMethod = "thread-follower-start-turn";
    private const string FollowerStartHostHandler = "thread-follower-start-turn-for-host";
    private const string NativeStartMethod = "turn/start";
    private const int MaximumPathLength = 512;
    private const int MaximumPathSegments = 32;
    private const int MaximumLiteralOccurrences = 128;
    private const string IdentifierPattern = "[$A-Za-z_][$0-9A-Za-z_]*";
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private static readonly Regex ScriptTagRegex = new(
        "<script\\b(?<attributes>[^>]*)>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        RegexTimeout);
    private static readonly Regex HtmlAttributeRegex = new(
        "(?<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\\s*=\\s*(?:\"(?<double>[^\"]*)\"|'(?<single>[^']*)')",
        RegexOptions.CultureInvariant,
        RegexTimeout);
    private static readonly Regex RelativeImportRegex = new(
        "(?:\\bfrom\\s*|\\bimport\\s*(?:\\(\\s*)?)(?:\"(?<double>\\.{1,2}/[^\"?#]+\\.js)\"|'(?<single>\\.{1,2}/[^'?#]+\\.js)'|`(?<template>\\.{1,2}/[^`?#]+\\.js)`)",
        RegexOptions.CultureInvariant,
        RegexTimeout);

    internal static CodexStructuredInputAsarSnapshot Inspect(
        ICodexAsarRandomAccessSource source,
        CodexStructuredInputAsarInspectionLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        limits ??= CodexStructuredInputAsarInspectionLimits.Default;
        ValidateLimits(limits);
        if (source.Length is < 16 || source.Length > limits.MaximumArchiveBytes)
        {
            throw Failure(
                "structured-asar-size",
                isCompatibilityFailure: false,
                "The installed ASAR archive has an invalid bounded length.");
        }

        var boundedSource = new BoundedRandomAccessSource(source, limits.MaximumTotalReadBytes);
        try
        {
            var header = ReadHeader(boundedSource, limits);
            using var headerDocument = header.Document;
            var cache = new Dictionary<string, CachedEntry>(StringComparer.Ordinal);
            var selectedEntries = new List<PackedEntry>();

            var package = ReadCachedEntry(
                boundedSource,
                header.Files,
                header.DataBase,
                source.Length,
                PackageJsonPath,
                limits.MaximumPackageJsonBytes,
                cache,
                selectedEntries);
            var packageMetadata = ReadPackageMetadata(package.Bytes, limits.MaximumJsonDepth);
            if (!string.Equals(
                    packageMetadata.Name,
                    "openai-codex-electron",
                    StringComparison.Ordinal) ||
                !string.Equals(packageMetadata.ProductName, "Codex", StringComparison.Ordinal))
            {
                throw Failure(
                    "structured-package-semantics",
                    isCompatibilityFailure: true,
                    "The installed ASAR package metadata is not a supported Codex product.");
            }

            var index = ReadCachedEntry(
                boundedSource,
                header.Files,
                header.DataBase,
                source.Length,
                WebviewIndexPath,
                limits.MaximumIndexHtmlBytes,
                cache,
                selectedEntries);
            var indexSource = DecodeStrictUtf8(index.Bytes, "structured-index-utf8");
            var moduleRootPath = ExtractUniqueModuleRoot(indexSource);

            var moduleSources = new Dictionary<string, string>(StringComparer.Ordinal);
            var moduleEntries = new Dictionary<string, PackedEntry>(StringComparer.Ordinal);
            var visitState = new Dictionary<string, ModuleVisitState>(StringComparer.Ordinal);
            VisitModule(
                moduleRootPath,
                depth: 0,
                boundedSource,
                header.Files,
                header.DataBase,
                source.Length,
                limits,
                cache,
                selectedEntries,
                moduleSources,
                moduleEntries,
                visitState);

            var semanticCandidates = new List<OwnerSemanticShape>();
            foreach (var item in moduleSources.OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                if (TryInspectOwnerSemantics(item.Value, out var shape))
                {
                    semanticCandidates.Add(shape with { EntryPath = item.Key });
                }
            }

            if (semanticCandidates.Count != 1)
            {
                throw Failure(
                    semanticCandidates.Count == 0
                        ? "structured-owner-semantics-missing"
                        : "structured-owner-semantics-ambiguous",
                    isCompatibilityFailure: true,
                    semanticCandidates.Count == 0
                        ? "No reachable module proves the required stock Desktop owner semantics."
                        : "Multiple reachable modules claim the required stock Desktop owner semantics.");
            }

            EnsureDisjoint(selectedEntries.DistinctBy(entry => entry.Path).ToArray());
            var semantic = semanticCandidates[0];
            var moduleRoot = cache[moduleRootPath];
            var owner = cache[semantic.EntryPath];
            var projectedModules = moduleEntries.Values
                .OrderBy(entry => entry.Path, StringComparer.Ordinal)
                .Select(entry => ToSnapshot(entry, cache[entry.Path].Bytes))
                .ToArray();
            return new CodexStructuredInputAsarSnapshot(
                packageMetadata.Name,
                packageMetadata.ProductName,
                packageMetadata.Version,
                packageMetadata.MainPath,
                moduleRootPath,
                semantic.EntryPath,
                semantic.FollowerMethods,
                FollowerStartHostHandler,
                StartTurnAssertsOwner: true,
                NativeStartMethod,
                NativeMethodVersion: 1,
                PreservesInput: true,
                PreservesStableClientUserMessageId: true,
                semantic.NativeInputKinds,
                semantic.HandlerShapeSha256,
                semantic.InputShapeSha256,
                SupportsAttachmentOnly: true,
                semantic.NewConversation,
                header.HeaderSha256,
                ToSnapshot(package.Entry, package.Bytes),
                ToSnapshot(index.Entry, index.Bytes),
                ToSnapshot(moduleRoot.Entry, moduleRoot.Bytes),
                ToSnapshot(owner.Entry, owner.Bytes),
                projectedModules);
        }
        catch (CodexStructuredInputAsarException)
        {
            throw;
        }
        catch (RegexMatchTimeoutException exception)
        {
            throw Failure(
                "structured-regex-timeout",
                isCompatibilityFailure: false,
                "The installed ASAR semantic scan exceeded its bounded regex time.",
                exception);
        }
        catch (JsonException exception)
        {
            throw Failure(
                "structured-asar-json",
                isCompatibilityFailure: false,
                "The installed ASAR contains invalid bounded JSON.",
                exception);
        }
        catch (DecoderFallbackException exception)
        {
            throw Failure(
                "structured-asar-utf8",
                isCompatibilityFailure: false,
                "A selected installed ASAR entry is not strict UTF-8.",
                exception);
        }
        catch (Exception exception) when (
            exception is IOException or ArgumentException or InvalidOperationException or OverflowException)
        {
            throw Failure(
                "structured-asar-inspection",
                isCompatibilityFailure: false,
                "The installed ASAR semantic evidence could not be inspected safely.",
                exception);
        }
    }

    private static HeaderSnapshot ReadHeader(
        BoundedRandomAccessSource source,
        CodexStructuredInputAsarInspectionLimits limits)
    {
        Span<byte> prefix = stackalloc byte[16];
        ReadExactly(source, 0, prefix);
        var sizePicklePayload = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        var headerPickleTotal = BinaryPrimitives.ReadUInt32LittleEndian(prefix[4..]);
        var headerPicklePayload = BinaryPrimitives.ReadUInt32LittleEndian(prefix[8..]);
        var jsonLength = BinaryPrimitives.ReadUInt32LittleEndian(prefix[12..]);
        var alignedJsonLength = checked((jsonLength + 3u) & ~3u);
        if (sizePicklePayload != sizeof(uint) ||
            headerPickleTotal is < 8 ||
            headerPickleTotal > limits.MaximumHeaderBytes ||
            (headerPickleTotal & 3) != 0 ||
            headerPicklePayload != headerPickleTotal - sizeof(uint) ||
            headerPicklePayload != checked(sizeof(uint) + alignedJsonLength) ||
            headerPickleTotal != checked(2u * sizeof(uint) + alignedJsonLength) ||
            jsonLength == 0 ||
            jsonLength > int.MaxValue)
        {
            throw Failure(
                "structured-asar-header",
                isCompatibilityFailure: false,
                "The installed ASAR Pickle header is not canonical and bounded.");
        }

        var dataBase = checked(8L + headerPickleTotal);
        if (dataBase > source.Length)
        {
            throw Failure(
                "structured-asar-header",
                isCompatibilityFailure: false,
                "The installed ASAR header extends beyond the retained file.");
        }

        var jsonBytes = new byte[checked((int)jsonLength)];
        ReadExactly(source, 16, jsonBytes);
        var paddingLength = checked((int)(alignedJsonLength - jsonLength));
        if (paddingLength > 0)
        {
            Span<byte> padding = stackalloc byte[3];
            var used = padding[..paddingLength];
            ReadExactly(source, checked(16L + jsonLength), used);
            if (used.IndexOfAnyExcept((byte)0) >= 0)
            {
                throw Failure(
                    "structured-asar-header",
                    isCompatibilityFailure: false,
                    "The installed ASAR header padding is not zero-filled.");
            }
        }

        var document = JsonDocument.Parse(jsonBytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = limits.MaximumJsonDepth
        });
        try
        {
            var valueCount = 0;
            ValidateJsonShape(
                document.RootElement,
                depth: 0,
                ref valueCount,
                limits.MaximumJsonDepth,
                limits.MaximumJsonValues);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw Failure(
                    "structured-asar-json",
                    isCompatibilityFailure: false,
                    "The installed ASAR header root is not an object.");
            }

            JsonElement files = default;
            var propertyCount = 0;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                propertyCount++;
                if (property.NameEquals("files"))
                {
                    files = property.Value;
                }
            }

            if (propertyCount != 1 || files.ValueKind != JsonValueKind.Object)
            {
                throw Failure(
                    "structured-asar-json",
                    isCompatibilityFailure: false,
                    "The installed ASAR header must contain only one files object.");
            }

            return new HeaderSnapshot(
                document,
                files,
                dataBase,
                Convert.ToHexString(SHA256.HashData(jsonBytes)));
        }
        catch
        {
            document.Dispose();
            throw;
        }
    }

    private static void VisitModule(
        string path,
        int depth,
        BoundedRandomAccessSource source,
        JsonElement files,
        long dataBase,
        long archiveLength,
        CodexStructuredInputAsarInspectionLimits limits,
        Dictionary<string, CachedEntry> cache,
        List<PackedEntry> selectedEntries,
        Dictionary<string, string> moduleSources,
        Dictionary<string, PackedEntry> moduleEntries,
        Dictionary<string, ModuleVisitState> visitState)
    {
        if (visitState.TryGetValue(path, out var state))
        {
            if (state == ModuleVisitState.Visiting)
            {
                throw Failure(
                    "structured-module-cycle",
                    isCompatibilityFailure: true,
                    "The reachable webview module graph contains a dependency cycle.");
            }

            return;
        }

        if (depth > limits.MaximumDependencyDepth)
        {
            throw Failure(
                "structured-module-depth",
                isCompatibilityFailure: true,
                "The reachable webview module graph exceeds its depth bound.");
        }

        if (moduleEntries.Count >= limits.MaximumModuleEntries)
        {
            throw Failure(
                "structured-module-count",
                isCompatibilityFailure: true,
                "The reachable webview module graph exceeds its entry bound.");
        }

        visitState[path] = ModuleVisitState.Visiting;
        var cached = ReadCachedEntry(
            source,
            files,
            dataBase,
            archiveLength,
            path,
            limits.MaximumScriptBytes,
            cache,
            selectedEntries);
        var script = DecodeStrictUtf8(cached.Bytes, "structured-module-utf8");
        moduleEntries.Add(path, cached.Entry);
        moduleSources.Add(path, script);
        var isOwner = TryInspectOwnerSemantics(script, out _);
        var dependencies = isOwner
            ? ExtractRelativeImports(path, script, limits.MaximumOwnerImportsPerModule)
            : ExtractRelativeImports(path, script, limits.MaximumImportsPerModule);
        if (isOwner)
        {
            dependencies = Array.Empty<string>();
        }
        foreach (var dependency in dependencies)
        {
            VisitModule(
                dependency,
                depth + 1,
                source,
                files,
                dataBase,
                archiveLength,
                limits,
                cache,
                selectedEntries,
                moduleSources,
                moduleEntries,
                visitState);
        }

        visitState[path] = ModuleVisitState.Visited;
    }

    private static IReadOnlyList<string> ExtractRelativeImports(
        string modulePath,
        string source,
        int maximumImports)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match match in RelativeImportRegex.Matches(source))
        {
            var value = FirstSuccessfulGroup(match, "double", "single", "template");
            var resolved = ResolveRelativePath(modulePath, value, requireWebviewRoot: true);
            if (!result.Add(resolved))
            {
                continue;
            }

            if (result.Count > maximumImports)
            {
                throw Failure(
                    "structured-module-import-count",
                    isCompatibilityFailure: true,
                    "A reachable webview module exceeds its import bound.");
            }
        }

        return result.Order(StringComparer.Ordinal).ToArray();
    }

    private static string ExtractUniqueModuleRoot(string indexSource)
    {
        var roots = new List<string>();
        foreach (Match script in ScriptTagRegex.Matches(indexSource))
        {
            var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match attribute in HtmlAttributeRegex.Matches(script.Groups["attributes"].Value))
            {
                var name = attribute.Groups["name"].Value;
                if (!attributes.TryAdd(name, FirstSuccessfulGroup(attribute, "double", "single")))
                {
                    throw Failure(
                        "structured-index-attribute-duplicate",
                        isCompatibilityFailure: false,
                        "The webview index contains a duplicate script attribute.");
                }
            }

            if (!attributes.TryGetValue("type", out var type) ||
                !string.Equals(type, "module", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!attributes.TryGetValue("src", out var sourcePath))
            {
                throw Failure(
                    "structured-index-module-src",
                    isCompatibilityFailure: true,
                    "A webview module script has no bounded relative source.");
            }

            roots.Add(ResolveRelativePath(WebviewIndexPath, sourcePath, requireWebviewRoot: true));
        }

        if (roots.Count != 1)
        {
            throw Failure(
                "structured-index-module-root",
                isCompatibilityFailure: true,
                "The webview index does not expose exactly one module root.");
        }

        return roots[0];
    }

    private static bool TryInspectOwnerSemantics(
        string source,
        out OwnerSemanticShape shape)
    {
        shape = default!;
        OwnerDispatchTopology topology;
        IReadOnlySet<string> followerMethods;
        string startFunction;
        NativeStartShape nativeShape;
        if (TryInspectLegacyOwnerDispatch(
                source,
                out followerMethods,
                out startFunction,
                out nativeShape))
        {
            topology = OwnerDispatchTopology.LegacyHostHandler;
        }
        else if (TryInspectDirectOwnerDispatch(
                     source,
                     out followerMethods,
                     out startFunction,
                     out nativeShape))
        {
            topology = OwnerDispatchTopology.DirectFollowerReceiver;
        }
        else
        {
            return TryInspectEnvelopeOwnerSemantics(source, out shape);
        }

        var inputKinds = InspectInputKinds(source);
        if (!inputKinds.Contains("text"))
        {
            return false;
        }

        var newConversation = InspectNewConversationSemantics(source, startFunction);

        var handlerShape = topology == OwnerDispatchTopology.LegacyHostHandler
            ? HashText(
                "codexfree-owner-handler-shape-v1\n" +
                "bridge=" + FollowerStartMethod + "->" + FollowerStartHostHandler + "\n" +
                "ownerAssertion=conversationId\n" +
                "turnStartParams=forwarded\n" +
                "clientUserMessageId=stable\n" +
                "input=preserved\n" +
                "native=" + NativeStartMethod + "@1\n" +
                "followerForwarding=" + nativeShape.HasFollowerForwarding + "\n" +
                "nativeRequest=" + nativeShape.HasNativeRequest)
            : HashText(
                "codexfree-owner-handler-shape-v2\n" +
                "bridge=" + FollowerStartMethod + "->direct-startTurn\n" +
                "ownerAssertion=streamRole(owner)\n" +
                "turnStartParams=forwarded\n" +
                "clientUserMessageId=stable\n" +
                "input=preserved\n" +
                "native=" + NativeStartMethod + "@1\n" +
                "followerForwarding=" + nativeShape.HasFollowerForwarding + "\n" +
                "nativeRequest=" + nativeShape.HasNativeRequest);
        var inputShape = HashText(
            "codexfree-owner-input-shape-v1\n" +
            string.Join('\n', inputKinds.Order(StringComparer.Ordinal)) + "\n" +
            "localImagePath=" + inputKinds.Contains("localImage") + "\n" +
            "attachmentOnly=true");
        shape = new OwnerSemanticShape(
            EntryPath: string.Empty,
            followerMethods,
            inputKinds,
            handlerShape,
            inputShape,
            newConversation);
        return true;
    }

    private static bool TryInspectLegacyOwnerDispatch(
        string source,
        out IReadOnlySet<string> followerMethods,
        out string startFunction,
        out NativeStartShape nativeShape)
    {
        followerMethods = new HashSet<string>(StringComparer.Ordinal);
        startFunction = string.Empty;
        nativeShape = default!;
        return TryFindBridge(source, out followerMethods) &&
            TryFindHostHandler(source, out startFunction) &&
            TryFindNamedFunction(source, startFunction, out var function) &&
            TryInspectNativeStart(function, requireOwnerRoleGuard: false, out nativeShape);
    }

    private static bool TryInspectDirectOwnerDispatch(
        string source,
        out IReadOnlySet<string> followerMethods,
        out string startFunction,
        out NativeStartShape nativeShape)
    {
        followerMethods = new HashSet<string>(StringComparer.Ordinal);
        startFunction = string.Empty;
        nativeShape = default!;
        if (!TryFindDirectFollowerReceiver(
                source,
                out var receiverObject,
                out var receiverFunction,
                out var receiverManagerIsFirstParameter) ||
            !TryFindDirectStartFunction(
                source,
                receiverObject,
                receiverFunction,
                receiverManagerIsFirstParameter,
                out startFunction) ||
            !TryFindNamedFunction(source, startFunction, out var function) ||
            !TryInspectNativeStart(function, requireOwnerRoleGuard: true, out nativeShape))
        {
            return false;
        }

        followerMethods = new HashSet<string>(StringComparer.Ordinal)
        {
            FollowerStartMethod
        };
        return true;
    }

    private static bool TryFindDirectFollowerReceiver(
        string source,
        out string receiverObject,
        out string receiverFunction,
        out bool receiverManagerIsFirstParameter)
    {
        receiverObject = string.Empty;
        receiverFunction = string.Empty;
        receiverManagerIsFirstParameter = false;
        var matches = 0;
        var objects = new HashSet<string>(StringComparer.Ordinal);
        var functions = new HashSet<string>(StringComparer.Ordinal);
        var managerParameters = new List<bool>();
        foreach (var quoteIndex in FindQuotedLiteralStarts(source, FollowerStartMethod))
        {
            var prefixStart = Math.Max(0, quoteIndex - 32);
            var prefix = source[prefixStart..quoteIndex];
            if (!Regex.IsMatch(
                    prefix,
                    "case\\s*$",
                    RegexOptions.CultureInvariant,
                    RegexTimeout))
            {
                continue;
            }

            var segmentStart = quoteIndex + FollowerStartMethod.Length + 2;
            var nextCase = source.IndexOf("case", segmentStart, StringComparison.Ordinal);
            var segmentEnd = Math.Min(source.Length, segmentStart + 8192);
            if (nextCase >= segmentStart && nextCase < segmentEnd)
            {
                segmentEnd = nextCase;
            }

            var segment = source[segmentStart..segmentEnd];
            var call = Regex.Match(
                segment,
                "^\\s*:\\s*\\{?\\s*(?:let|const|var)\\s+(?<result>" +
                IdentifierPattern + ")\\s*=\\s*await\\s+(?<manager>" +
                IdentifierPattern + ")\\s*\\.\\s*startTurn\\s*\\(",
                RegexOptions.CultureInvariant,
                RegexTimeout);
            if (!call.Success)
            {
                continue;
            }

            var openParenthesis = call.Index + call.Length - 1;
            var closeParenthesis = FindMatchingDelimiter(segment, openParenthesis, '(', ')');
            var arguments = SplitTopLevelArguments(
                segment[(openParenthesis + 1)..closeParenthesis]);
            if (arguments.Count != 3)
            {
                continue;
            }

            var conversation = Regex.Match(
                arguments[0],
                "^\\s*(?<request>" + IdentifierPattern + ")\\s*\\.\\s*params\\s*\\.\\s*" +
                "conversationId\\s*$",
                RegexOptions.CultureInvariant,
                RegexTimeout);
            if (!conversation.Success)
            {
                continue;
            }

            var request = conversation.Groups["request"].Value;
            if (!Regex.IsMatch(
                    arguments[1],
                    "^\\s*" + Regex.Escape(request) +
                    "\\s*\\.\\s*params\\s*\\.\\s*turnStartParams\\s*$",
                    RegexOptions.CultureInvariant,
                    RegexTimeout) ||
                !HasForwardedReceiverMetadata(arguments[2], request))
            {
                continue;
            }

            var result = call.Groups["result"].Value;
            var tail = segment[(closeParenthesis + 1)..];
            if (!Regex.IsMatch(
                    tail,
                    "\\breturn\\s*\\{\\s*method\\s*:\\s*" + Regex.Escape(request) +
                    "\\s*\\.\\s*method\\s*,\\s*result\\s*:\\s*\\{\\s*result\\s*:\\s*" +
                    Regex.Escape(result) + "\\s*\\}\\s*\\}",
                    RegexOptions.CultureInvariant | RegexOptions.Singleline,
                    RegexTimeout))
            {
                continue;
            }

            if (!TryFindContainingNamedFunction(
                    source,
                    quoteIndex,
                    out var containingFunction,
                    out var containingParameters))
            {
                continue;
            }

            objects.Add(call.Groups["manager"].Value);
            functions.Add(containingFunction);
            managerParameters.Add(
                containingParameters.Count > 0 &&
                string.Equals(
                    containingParameters[0],
                    call.Groups["manager"].Value,
                    StringComparison.Ordinal));
            matches++;
        }

        if (matches != 1 || objects.Count != 1 || functions.Count != 1 ||
            managerParameters.Count != 1)
        {
            return false;
        }

        receiverObject = objects.Single();
        receiverFunction = functions.Single();
        receiverManagerIsFirstParameter = managerParameters[0];
        return true;
    }

    private static bool TryFindContainingNamedFunction(
        string source,
        int contentIndex,
        out string functionName,
        out IReadOnlyList<string> parameters)
    {
        functionName = string.Empty;
        parameters = Array.Empty<string>();
        var search = contentIndex;
        while (search >= 0)
        {
            var index = source.LastIndexOf("function ", search, StringComparison.Ordinal);
            if (index < 0)
            {
                return false;
            }

            search = index - 1;
            var cursor = index + "function ".Length;
            var nameStart = cursor;
            while (cursor < source.Length && IsIdentifierCharacter(source[cursor]))
            {
                cursor++;
            }

            if (cursor == nameStart)
            {
                continue;
            }

            var name = source[nameStart..cursor];
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '(')
            {
                continue;
            }

            var parametersEnd = FindMatchingDelimiter(source, cursor, '(', ')');
            var values = SplitTopLevelArguments(source[(cursor + 1)..parametersEnd]);
            if (values.Any(value => !IsIdentifier(value)))
            {
                continue;
            }

            cursor = parametersEnd + 1;
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '{')
            {
                continue;
            }

            var bodyEnd = FindMatchingDelimiter(source, cursor, '{', '}');
            if (contentIndex <= cursor || contentIndex >= bodyEnd)
            {
                continue;
            }

            functionName = name;
            parameters = values;
            return true;
        }

        return false;
    }

    private static bool HasForwardedReceiverMetadata(string argument, string request)
    {
        var value = argument.Trim();
        if (value.Length < 2 || value[0] != '{' ||
            FindMatchingDelimiter(value, 0, '{', '}') != value.Length - 1)
        {
            return false;
        }

        var body = value[1..^1];
        return HasForwardedRequestProperty(
                body,
                "localTurnMetadata",
                request,
                "localTurnMetadata") &&
            HasForwardedRequestProperty(
                body,
                "mcpAppModelContextAttachments",
                request,
                "mcpAppModelContextAttachments");
    }

    private static bool HasForwardedRequestProperty(
        string objectBody,
        string property,
        string request,
        string requestProperty) =>
        Regex.IsMatch(
            objectBody,
            "(?:^|,)\\s*" + Regex.Escape(property) + "\\s*:\\s*" +
            Regex.Escape(request) + "\\s*\\.\\s*params\\s*\\.\\s*" +
            Regex.Escape(requestProperty) + "\\b",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            RegexTimeout);

    private static bool TryFindDirectStartFunction(
        string source,
        string receiverObject,
        string receiverFunction,
        bool receiverManagerIsFirstParameter,
        out string startFunction)
    {
        startFunction = string.Empty;
        JavaScriptMethod startMethod;
        string? expectedManager = null;
        if (receiverManagerIsFirstParameter)
        {
            if (!TryFindBoundLifecycleStartMethod(
                    source,
                    receiverFunction,
                    out startMethod,
                    out expectedManager))
            {
                return false;
            }
        }
        else if (!TryFindAsyncObjectMethod(
                     source,
                     receiverObject,
                     "startTurn",
                     out startMethod))
        {
            return false;
        }

        var parameters = SplitTopLevelArguments(startMethod.Parameters);
        if (parameters.Count != 3 || parameters.Any(value => !IsIdentifier(value)))
        {
            return false;
        }

        var conversation = parameters[0];
        var startParameters = parameters[1];
        var metadata = parameters[2];
        var matches = new List<string>();
        var callPattern = new Regex(
            "\\bawait\\s+(?<start>" + IdentifierPattern + ")\\s*\\(",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        foreach (Match match in callPattern.Matches(startMethod.Body))
        {
            var openParenthesis = match.Index + match.Length - 1;
            var closeParenthesis = FindMatchingDelimiter(
                startMethod.Body,
                openParenthesis,
                '(',
                ')');
            var arguments = SplitTopLevelArguments(
                startMethod.Body[(openParenthesis + 1)..closeParenthesis]);
            if (arguments.Count < 5 ||
                !IsIdentifier(arguments[0]) ||
                expectedManager is not null &&
                !string.Equals(arguments[0], expectedManager, StringComparison.Ordinal) ||
                !string.Equals(arguments[1], conversation, StringComparison.Ordinal) ||
                !ReferencesIdentifier(arguments[2], startParameters) ||
                !ReferencesMember(
                    arguments[3],
                    metadata,
                    "mcpAppModelContextAttachments") ||
                !ReferencesMember(arguments[4], metadata, "localTurnMetadata"))
            {
                continue;
            }

            matches.Add(match.Groups["start"].Value);
        }

        if (matches.Count != 1)
        {
            return false;
        }

        startFunction = matches[0];
        return true;
    }

    private static bool TryFindBoundLifecycleStartMethod(
        string source,
        string receiverFunction,
        out JavaScriptMethod startMethod,
        out string managerParameter)
    {
        startMethod = default!;
        managerParameter = string.Empty;
        var matches = new List<(JavaScriptMethod Method, string Manager)>();
        var marker = "async handleThreadFollowerRequest";
        var search = 0;
        while (search < source.Length)
        {
            var markerIndex = source.IndexOf(marker, search, StringComparison.Ordinal);
            if (markerIndex < 0)
            {
                break;
            }

            search = markerIndex + marker.Length;
            if (!TryFindContainingClassBody(source, markerIndex, out var classBody) ||
                !TryFindTopLevelAsyncObjectMethod(
                    classBody,
                    "handleThreadFollowerRequest",
                    out var receiverHandler) ||
                !TryFindTopLevelPlainObjectMethod(
                    classBody,
                    "startTurn",
                    out var forwardingMethod) ||
                !TryFindTopLevelPlainObjectMethod(
                    classBody,
                    "constructor",
                    out var constructor))
            {
                continue;
            }

            var handlerParameters = SplitTopLevelArguments(receiverHandler.Parameters);
            if (handlerParameters.Count != 1 || !IsIdentifier(handlerParameters[0]) ||
                !Regex.IsMatch(
                    receiverHandler.Body,
                    "^\\s*return\\s+(?:await\\s+)?" +
                    Regex.Escape(receiverFunction) +
                    "\\s*\\(\\s*this\\s*,\\s*" +
                    Regex.Escape(handlerParameters[0]) +
                    "\\s*\\)\\s*;?\\s*$",
                    RegexOptions.CultureInvariant | RegexOptions.Singleline,
                    RegexTimeout))
            {
                continue;
            }

            var forwardingParameters = SplitTopLevelArguments(forwardingMethod.Parameters);
            if (forwardingParameters.Count != 3 ||
                forwardingParameters.Any(value => !IsIdentifier(value)))
            {
                continue;
            }

            var forwarding = Regex.Match(
                forwardingMethod.Body,
                "^\\s*return\\s+this\\s*\\.\\s*(?<lifecycle>" +
                IdentifierPattern + ")\\s*\\.\\s*startTurn\\s*\\(\\s*" +
                Regex.Escape(forwardingParameters[0]) + "\\s*,\\s*" +
                Regex.Escape(forwardingParameters[1]) + "\\s*,\\s*" +
                Regex.Escape(forwardingParameters[2]) +
                "\\s*\\)\\s*;?\\s*$",
                RegexOptions.CultureInvariant | RegexOptions.Singleline,
                RegexTimeout);
            if (!forwarding.Success)
            {
                continue;
            }

            var lifecycle = forwarding.Groups["lifecycle"].Value;
            var assignments = Regex.Matches(
                    constructor.Body,
                    "\\bthis\\s*\\.\\s*" + Regex.Escape(lifecycle) +
                    "\\s*=\\s*(?<factory>" + IdentifierPattern +
                    ")\\s*\\(\\s*this(?:\\s*,|\\s*\\))",
                    RegexOptions.CultureInvariant | RegexOptions.Singleline,
                    RegexTimeout)
                .Cast<Match>()
                .ToArray();
            if (assignments.Length != 1 ||
                !TryResolveConstructorFactory(
                    constructor.Parameters,
                    assignments[0].Groups["factory"].Value,
                    out var factoryName) ||
                !TryFindNamedFactoryFunction(source, factoryName, out var factory) ||
                factory.Parameters.Count == 0 ||
                !TryFindReturnedAsyncObjectMethod(
                    factory.Body,
                    "startTurn",
                    out var candidate))
            {
                continue;
            }

            matches.Add((candidate, factory.Parameters[0]));
        }

        if (matches.Count != 1)
        {
            return false;
        }

        startMethod = matches[0].Method;
        managerParameter = matches[0].Manager;
        return true;
    }

    private static bool TryFindContainingClassBody(
        string source,
        int contentIndex,
        out string classBody)
    {
        classBody = string.Empty;
        var search = contentIndex;
        while (search >= 0)
        {
            var index = source.LastIndexOf("class", search, StringComparison.Ordinal);
            if (index < 0)
            {
                return false;
            }

            search = index - 1;
            if (index > 0 && IsIdentifierCharacter(source[index - 1]) ||
                index + 5 < source.Length && IsIdentifierCharacter(source[index + 5]))
            {
                continue;
            }

            var openBrace = source.IndexOf('{', index + 5);
            if (openBrace < 0 || openBrace >= contentIndex)
            {
                continue;
            }

            var closeBrace = FindMatchingDelimiter(source, openBrace, '{', '}');
            if (contentIndex <= openBrace || contentIndex >= closeBrace)
            {
                continue;
            }

            classBody = source[(openBrace + 1)..closeBrace];
            return true;
        }

        return false;
    }

    private static bool TryResolveConstructorFactory(
        string constructorParameters,
        string alias,
        out string factoryName)
    {
        factoryName = alias;
        foreach (var parameter in SplitTopLevelArguments(constructorParameters))
        {
            var match = Regex.Match(
                parameter,
                "^\\s*" + Regex.Escape(alias) + "\\s*=\\s*(?<factory>" +
                IdentifierPattern + ")\\s*$",
                RegexOptions.CultureInvariant,
                RegexTimeout);
            if (match.Success)
            {
                factoryName = match.Groups["factory"].Value;
                return true;
            }
        }

        return !SplitTopLevelArguments(constructorParameters).Any(parameter =>
            Regex.IsMatch(
                parameter,
                "^\\s*" + Regex.Escape(alias) + "(?:\\s*=|\\s*$)",
                RegexOptions.CultureInvariant,
                RegexTimeout));
    }

    private static bool TryFindReturnedAsyncObjectMethod(
        string functionBody,
        string methodName,
        out JavaScriptMethod method)
    {
        method = default!;
        var matches = new List<JavaScriptMethod>();
        var pattern = new Regex(
            "\\breturn\\s*\\{",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        foreach (Match match in pattern.Matches(functionBody))
        {
            var openBrace = match.Index + match.Length - 1;
            var closeBrace = FindMatchingDelimiter(functionBody, openBrace, '{', '}');
            if (TryFindTopLevelAsyncObjectMethod(
                    functionBody[(openBrace + 1)..closeBrace],
                    methodName,
                    out var candidate))
            {
                matches.Add(candidate);
            }
        }

        if (matches.Count != 1)
        {
            return false;
        }

        method = matches[0];
        return true;
    }

    private static bool TryFindAsyncObjectMethod(
        string source,
        string objectName,
        string methodName,
        out JavaScriptMethod method)
    {
        method = default!;
        var declaration = new Regex(
            "(?<![A-Za-z0-9_$.])" + Regex.Escape(objectName) +
            "\\s*=\\s*\\{",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        var matches = new List<JavaScriptMethod>();
        foreach (Match match in declaration.Matches(source))
        {
            var openBrace = match.Index + match.Length - 1;
            var closeBrace = FindMatchingDelimiter(source, openBrace, '{', '}');
            var objectBody = source[(openBrace + 1)..closeBrace];
            if (TryFindTopLevelAsyncObjectMethod(objectBody, methodName, out var candidate))
            {
                matches.Add(candidate);
            }
        }

        if (matches.Count != 1)
        {
            return false;
        }

        method = matches[0];
        return true;
    }

    private static bool TryFindTopLevelAsyncObjectMethod(
        string objectBody,
        string methodName,
        out JavaScriptMethod method)
        => TryFindTopLevelObjectMethod(
            objectBody,
            methodName,
            requireAsync: true,
            out method);

    private static bool TryFindTopLevelPlainObjectMethod(
        string objectBody,
        string methodName,
        out JavaScriptMethod method)
        => TryFindTopLevelObjectMethod(
            objectBody,
            methodName,
            requireAsync: false,
            out method);

    private static bool TryFindTopLevelObjectMethod(
        string objectBody,
        string methodName,
        bool requireAsync,
        out JavaScriptMethod method)
    {
        method = default!;
        var marker = (requireAsync ? "async " : string.Empty) + methodName;
        var matches = new List<JavaScriptMethod>();
        var braces = 0;
        var parentheses = 0;
        var brackets = 0;
        for (var index = 0; index < objectBody.Length; index++)
        {
            var character = objectBody[index];
            if (character is '\'' or '"' or '`')
            {
                index = SkipQuoted(objectBody, index, character);
                continue;
            }

            if (character == '/' && index + 1 < objectBody.Length)
            {
                if (objectBody[index + 1] == '/')
                {
                    index = SkipLineComment(objectBody, index + 2);
                    continue;
                }

                if (objectBody[index + 1] == '*')
                {
                    index = SkipBlockComment(objectBody, index + 2);
                    continue;
                }

                if (IsRegularExpressionStart(objectBody, index))
                {
                    index = SkipRegularExpression(objectBody, index);
                    continue;
                }
            }

            if (braces == 0 && parentheses == 0 && brackets == 0 &&
                objectBody.AsSpan(index).StartsWith(marker, StringComparison.Ordinal) &&
                (index == 0 || !IsIdentifierCharacter(objectBody[index - 1])) &&
                (requireAsync ||
                 index < "async ".Length ||
                 !objectBody.AsSpan(index - "async ".Length, "async ".Length)
                     .SequenceEqual("async ")))
            {
                var cursor = index + marker.Length;
                SkipWhitespace(objectBody, ref cursor);
                if (cursor < objectBody.Length && objectBody[cursor] == '(')
                {
                    var parametersEnd = FindMatchingDelimiter(objectBody, cursor, '(', ')');
                    var parameters = objectBody[(cursor + 1)..parametersEnd];
                    cursor = parametersEnd + 1;
                    SkipWhitespace(objectBody, ref cursor);
                    if (cursor < objectBody.Length && objectBody[cursor] == '{')
                    {
                        var bodyEnd = FindMatchingDelimiter(objectBody, cursor, '{', '}');
                        matches.Add(new JavaScriptMethod(
                            parameters,
                            objectBody[(cursor + 1)..bodyEnd]));
                        index = bodyEnd;
                        continue;
                    }
                }
            }

            switch (character)
            {
                case '{':
                    braces++;
                    break;
                case '}':
                    braces--;
                    break;
                case '(':
                    parentheses++;
                    break;
                case ')':
                    parentheses--;
                    break;
                case '[':
                    brackets++;
                    break;
                case ']':
                    brackets--;
                    break;
            }

            if (braces < 0 || parentheses < 0 || brackets < 0)
            {
                return false;
            }
        }

        if (braces != 0 || parentheses != 0 || brackets != 0 || matches.Count != 1)
        {
            return false;
        }

        method = matches[0];
        return true;
    }

    private static bool ReferencesIdentifier(string expression, string identifier) =>
        Regex.IsMatch(
            expression,
            "(?:^|[^$0-9A-Za-z_])" + Regex.Escape(identifier) +
            "(?:$|[^$0-9A-Za-z_])",
            RegexOptions.CultureInvariant,
            RegexTimeout);

    private static bool ReferencesMember(
        string expression,
        string identifier,
        string member) =>
        Regex.IsMatch(
            expression,
            "\\b" + Regex.Escape(identifier) +
            "\\s*(?:\\?\\.|\\.)\\s*" + Regex.Escape(member) + "\\b",
            RegexOptions.CultureInvariant,
            RegexTimeout);

    private static IReadOnlyList<string> SplitTopLevelArguments(string source)
    {
        var result = new List<string>();
        var start = 0;
        var parentheses = 0;
        var braces = 0;
        var brackets = 0;
        for (var index = 0; index < source.Length; index++)
        {
            var character = source[index];
            if (character is '\'' or '"' or '`')
            {
                index = SkipQuoted(source, index, character);
                continue;
            }

            if (character == '/' && index + 1 < source.Length)
            {
                if (source[index + 1] == '/')
                {
                    index = SkipLineComment(source, index + 2);
                    continue;
                }

                if (source[index + 1] == '*')
                {
                    index = SkipBlockComment(source, index + 2);
                    continue;
                }

                if (IsRegularExpressionStart(source, index))
                {
                    index = SkipRegularExpression(source, index);
                    continue;
                }
            }

            switch (character)
            {
                case '(':
                    parentheses++;
                    break;
                case ')':
                    parentheses--;
                    break;
                case '{':
                    braces++;
                    break;
                case '}':
                    braces--;
                    break;
                case '[':
                    brackets++;
                    break;
                case ']':
                    brackets--;
                    break;
                case ',' when parentheses == 0 && braces == 0 && brackets == 0:
                    result.Add(source[start..index].Trim());
                    start = index + 1;
                    break;
            }

            if (parentheses < 0 || braces < 0 || brackets < 0)
            {
                return Array.Empty<string>();
            }
        }

        if (parentheses != 0 || braces != 0 || brackets != 0)
        {
            return Array.Empty<string>();
        }

        if (start < source.Length || result.Count > 0)
        {
            result.Add(source[start..].Trim());
        }

        return result;
    }

    private static bool TryFindBridge(string source, out IReadOnlySet<string> followerMethods)
    {
        followerMethods = new HashSet<string>(StringComparer.Ordinal);
        var matches = 0;
        foreach (var quoteIndex in FindQuotedLiteralStarts(source, FollowerStartMethod))
        {
            var prefixStart = Math.Max(0, quoteIndex - 32);
            var prefix = source[prefixStart..quoteIndex];
            if (!Regex.IsMatch(
                    prefix,
                    "case\\s*$",
                    RegexOptions.CultureInvariant,
                    RegexTimeout))
            {
                continue;
            }

            var segmentStart = quoteIndex + FollowerStartMethod.Length + 2;
            var nextCase = source.IndexOf("case", segmentStart, StringComparison.Ordinal);
            var segmentEnd = Math.Min(source.Length, segmentStart + 8192);
            if (nextCase >= segmentStart && nextCase < segmentEnd)
            {
                segmentEnd = nextCase;
            }

            var segment = source[segmentStart..segmentEnd];
            if (!ContainsQuotedLiteral(segment, FollowerStartHostHandler) ||
                !Regex.IsMatch(
                    segment,
                    "\\.\\.\\.\\s*" + IdentifierPattern + "\\s*\\.\\s*params\\b",
                    RegexOptions.CultureInvariant,
                    RegexTimeout))
            {
                continue;
            }

            matches++;
        }

        if (matches != 1)
        {
            return false;
        }

        followerMethods = new HashSet<string>(StringComparer.Ordinal)
        {
            FollowerStartMethod
        };
        return true;
    }

    private static bool TryFindHostHandler(string source, out string startFunction)
    {
        startFunction = string.Empty;
        var matches = new HashSet<string>(StringComparer.Ordinal);
        foreach (var quoteIndex in FindQuotedLiteralStarts(source, FollowerStartHostHandler))
        {
            var afterLiteral = quoteIndex + FollowerStartHostHandler.Length + 2;
            var length = Math.Min(4096, source.Length - afterLiteral);
            if (length <= 0)
            {
                continue;
            }

            var segment = source.Substring(afterLiteral, length);
            var prefix = Regex.Match(
                segment,
                "^\\s*:\\s*" + IdentifierPattern +
                "\\s*\\(\\s*async\\s*\\(\\s*(?<manager>" + IdentifierPattern +
                ")\\s*,\\s*(?<request>" + IdentifierPattern + ")\\s*\\)\\s*=>\\s*\\(",
                RegexOptions.CultureInvariant,
                RegexTimeout);
            if (!prefix.Success)
            {
                continue;
            }

            var manager = prefix.Groups["manager"].Value;
            var request = prefix.Groups["request"].Value;
            var owner = Regex.Match(
                segment[prefix.Length..],
                Regex.Escape(manager) +
                "\\s*\\.\\s*assertThreadFollowerOwner\\s*\\(\\s*" +
                Regex.Escape(request) + "\\s*\\.\\s*conversationId\\s*\\)",
                RegexOptions.CultureInvariant,
                RegexTimeout);
            if (!owner.Success)
            {
                continue;
            }

            var afterOwner = segment[(prefix.Length + owner.Index + owner.Length)..];
            var start = Regex.Match(
                afterOwner,
                "(?<start>" + IdentifierPattern + ")\\s*\\(\\s*" +
                Regex.Escape(manager) + "\\s*,\\s*" +
                Regex.Escape(request) + "\\s*\\.\\s*conversationId\\s*,\\s*" +
                Regex.Escape(request) + "\\s*\\.\\s*turnStartParams(?:\\s*,|\\s*\\))",
                RegexOptions.CultureInvariant,
                RegexTimeout);
            if (start.Success)
            {
                matches.Add(start.Groups["start"].Value);
            }
        }

        if (matches.Count != 1)
        {
            return false;
        }

        startFunction = matches.Single();
        return true;
    }

    private static bool TryFindNamedFunction(
        string source,
        string functionName,
        out JavaScriptFunction function)
    {
        function = default!;
        var marker = "function " + functionName;
        var matches = new List<JavaScriptFunction>();
        var search = 0;
        while (search < source.Length)
        {
            var index = source.IndexOf(marker, search, StringComparison.Ordinal);
            if (index < 0)
            {
                break;
            }

            search = index + marker.Length;
            if (index > 0 && IsIdentifierCharacter(source[index - 1]))
            {
                continue;
            }

            var cursor = search;
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '(')
            {
                continue;
            }

            var parametersEnd = FindMatchingDelimiter(source, cursor, '(', ')');
            var parameters = source[(cursor + 1)..parametersEnd]
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (parameters.Length < 3 || parameters.Any(value => !IsIdentifier(value)))
            {
                continue;
            }

            cursor = parametersEnd + 1;
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '{')
            {
                continue;
            }

            var bodyEnd = FindMatchingDelimiter(source, cursor, '{', '}');
            matches.Add(new JavaScriptFunction(
                parameters,
                source[(cursor + 1)..bodyEnd]));
        }

        if (matches.Count != 1)
        {
            return false;
        }

        function = matches[0];
        return true;
    }

    private static bool TryFindNamedFactoryFunction(
        string source,
        string functionName,
        out JavaScriptFunction function)
    {
        function = default!;
        var marker = "function " + functionName;
        var matches = new List<JavaScriptFunction>();
        var search = 0;
        while (search < source.Length)
        {
            var index = source.IndexOf(marker, search, StringComparison.Ordinal);
            if (index < 0)
            {
                break;
            }

            search = index + marker.Length;
            if (index > 0 && IsIdentifierCharacter(source[index - 1]))
            {
                continue;
            }

            var cursor = search;
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '(')
            {
                continue;
            }

            var parametersEnd = FindMatchingDelimiter(source, cursor, '(', ')');
            var parameters = SplitTopLevelArguments(source[(cursor + 1)..parametersEnd]);
            if (parameters.Count == 0 || !IsIdentifier(parameters[0]))
            {
                continue;
            }

            cursor = parametersEnd + 1;
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '{')
            {
                continue;
            }

            var bodyEnd = FindMatchingDelimiter(source, cursor, '{', '}');
            matches.Add(new JavaScriptFunction(
                parameters,
                source[(cursor + 1)..bodyEnd]));
        }

        if (matches.Count != 1)
        {
            return false;
        }

        function = matches[0];
        return true;
    }

    private static bool TryInspectNativeStart(
        JavaScriptFunction function,
        bool requireOwnerRoleGuard,
        out NativeStartShape shape)
    {
        shape = default!;
        var manager = function.Parameters[0];
        var conversation = function.Parameters[1];
        var startParameters = function.Parameters[2];
        var stableClient = Regex.Match(
            function.Body,
            "(?:let|const|var)\\s*\\{[^{}]{0,2048}\\.\\.\\.\\s*(?<rest>" +
            IdentifierPattern + ")\\s*\\}\\s*=\\s*" + Regex.Escape(startParameters) +
            "\\s*[,;]\\s*(?<client>" + IdentifierPattern + ")\\s*=\\s*\\k<rest>" +
            "\\s*\\.\\s*clientUserMessageId\\s*\\?\\?",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            RegexTimeout);
        if (!stableClient.Success)
        {
            return false;
        }

        var rest = stableClient.Groups["rest"].Value;
        var client = stableClient.Groups["client"].Value;
        var followerCalls = FindCalls(function.Body, manager, "sendThreadFollowerRequest");
        var validFollowerCalls = followerCalls.Where(call =>
            ContainsQuotedLiteral(call.Arguments, FollowerStartMethod) &&
            Regex.IsMatch(
                call.Arguments,
                "conversationId\\s*:\\s*" + Regex.Escape(conversation) + "\\b",
                RegexOptions.CultureInvariant,
                RegexTimeout) &&
            Regex.IsMatch(
                call.Arguments,
                "turnStartParams\\s*:\\s*\\{[^{}]{0,2048}\\.\\.\\.\\s*" +
                Regex.Escape(startParameters) +
                "\\b[^{}]{0,2048}clientUserMessageId\\s*:\\s*" +
                Regex.Escape(client) + "\\b",
                RegexOptions.CultureInvariant | RegexOptions.Singleline,
                RegexTimeout))
            .ToArray();
        if (validFollowerCalls.Length != 1)
        {
            return false;
        }

        var nativeCalls = new List<(JavaScriptCall Call, string RequestObject)>();
        foreach (var call in FindCalls(function.Body, manager, "sendRequest"))
        {
            var match = Regex.Match(
                call.Arguments,
                "^\\s*(?:\"turn/start\"|'turn/start'|`turn/start`)\\s*,\\s*(?<request>" +
                IdentifierPattern + ")\\b",
                RegexOptions.CultureInvariant,
                RegexTimeout);
            if (match.Success)
            {
                nativeCalls.Add((call, match.Groups["request"].Value));
            }
        }

        if (nativeCalls.Count != 1 ||
            !TryFindRequestObject(
                function.Body,
                nativeCalls[0].Call.Start,
                nativeCalls[0].RequestObject,
                conversation,
                client,
                rest) ||
            requireOwnerRoleGuard &&
            !HasOwnerRoleGuard(
                function.Body,
                manager,
                conversation,
                validFollowerCalls[0].Start,
                nativeCalls[0].Call.Start))
        {
            return false;
        }

        shape = new NativeStartShape(
            HasFollowerForwarding: true,
            HasNativeRequest: true);
        return true;
    }

    private static bool HasOwnerRoleGuard(
        string functionBody,
        string manager,
        string conversation,
        int afterIndex,
        int beforeIndex)
    {
        if (afterIndex < 0 || beforeIndex <= afterIndex || beforeIndex > functionBody.Length)
        {
            return false;
        }

        var window = functionBody[afterIndex..beforeIndex];
        return Regex.IsMatch(
            window,
            "\\bif\\s*\\(\\s*" + Regex.Escape(manager) +
            "\\s*\\.\\s*getStreamRole\\s*\\(\\s*" + Regex.Escape(conversation) +
            "\\s*\\)\\s*\\?\\.\\s*role\\s*!={1,2}\\s*" +
            "(?:\"owner\"|'owner'|`owner`)\\s*\\)\\s*throw\\b",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            RegexTimeout);
    }

    private static CodexNewConversationAsarSemantics InspectNewConversationSemantics(
        string source,
        string startFunction)
    {
        var hasCreate = TryFindAsyncMethod(source, "createConversation", out var create);
        var hasStartThread = TryFindAsyncMethod(source, "startThread", out var startThread);
        var hasStartConversation = TryFindAsyncMethod(
            source,
            "startConversation",
            out var startConversation);
        var hasPrewarm = TryFindAsyncMethod(source, "prewarmThread", out _);
        var hasFlow = hasCreate && hasStartThread && hasStartConversation && hasPrewarm;

        var createClient = string.Empty;
        var createPassesStableIdentity = hasCreate &&
            TryFindDestructuredAlias(create, "clientUserMessageId", out createClient) &&
            FindCalls(create.Body, "this", "startThread").Count(call =>
                HasObjectProperty(call.Arguments, "clientUserMessageId", createClient)) == 1;

        var startClient = string.Empty;
        var threadStartCarriesStableIdentity = hasStartThread &&
            TryFindDestructuredAlias(startThread, "clientUserMessageId", out startClient) &&
            RequestObjectCarriesStableProperty(
                startThread.Body,
                "thread/start",
                "clientUserMessageId",
                startClient);
        var creationRequestHasStableIdentity =
            createPassesStableIdentity && threadStartCarriesStableIdentity;

        var createReceipt = string.Empty;
        var startReceipt = string.Empty;
        var createdConversationReceiptReturned = hasCreate &&
            TryFindCreatedConversationReceipt(create, out createReceipt) &&
            hasStartConversation &&
            TryFindStartConversationReceipt(startConversation, out startReceipt);

        var startConversationClient = string.Empty;
        var firstTurnRequestHasStableIdentity = createdConversationReceiptReturned &&
            TryFindDestructuredAlias(
                startConversation,
                "clientUserMessageId",
                out startConversationClient) &&
            Regex.IsMatch(
                startConversation.Body,
                "\\b" + Regex.Escape(startFunction) +
                "\\s*\\(\\s*this\\s*,\\s*" + Regex.Escape(startReceipt) +
                "\\s*,\\s*\\{[^{}]{0,4096}clientUserMessageId\\s*:\\s*" +
                Regex.Escape(startConversationClient) + "\\b",
                RegexOptions.CultureInvariant | RegexOptions.Singleline,
                RegexTimeout);
        var firstTurnCanBeReconciled =
            createdConversationReceiptReturned && firstTurnRequestHasStableIdentity;

        var consumesPrewarmedThread = hasCreate &&
            create.Body.Contains(".consumePrewarmedThread(", StringComparison.Ordinal);
        var stableOperationCannotConsumePrewarmedThread =
            !consumesPrewarmedThread ||
            createClient.Length > 0 && HasNullGuardBefore(
                create.Body,
                createClient,
                ".consumePrewarmedThread(");

        var callback = string.Empty;
        var clientThreadBindingOccursAfterCreationResponse = hasCreate &&
            createReceipt.Length > 0 &&
            TryFindDestructuredAlias(create, "beforeConversationAdded", out callback) &&
            BindingOccursAfterStartThread(create.Body, callback, createReceipt);

        // A request field alone does not prove receiver idempotency. This stays false until
        // a stock Desktop query or acknowledgement contract can reconcile an uncertain create.
        const bool receiverCreationIdempotencyProved = false;
        var supportsAutomaticNewConversation = hasFlow &&
            creationRequestHasStableIdentity &&
            createdConversationReceiptReturned &&
            firstTurnCanBeReconciled &&
            stableOperationCannotConsumePrewarmedThread &&
            receiverCreationIdempotencyProved;
        var shape = HashText(
            "codexfree-new-conversation-shape-v1\n" +
            "flow=" + hasFlow + "\n" +
            "creationStable=" + creationRequestHasStableIdentity + "\n" +
            "conversationReceipt=" + createdConversationReceiptReturned + "\n" +
            "firstTurnStable=" + firstTurnRequestHasStableIdentity + "\n" +
            "firstTurnReconcile=" + firstTurnCanBeReconciled + "\n" +
            "prewarmBound=" + stableOperationCannotConsumePrewarmedThread + "\n" +
            "bindingAfterResponse=" + clientThreadBindingOccursAfterCreationResponse + "\n" +
            "receiverIdempotency=" + receiverCreationIdempotencyProved + "\n" +
            "automatic=" + supportsAutomaticNewConversation);
        return new CodexNewConversationAsarSemantics(
            hasFlow,
            creationRequestHasStableIdentity,
            createdConversationReceiptReturned,
            firstTurnRequestHasStableIdentity,
            firstTurnCanBeReconciled,
            stableOperationCannotConsumePrewarmedThread,
            clientThreadBindingOccursAfterCreationResponse,
            receiverCreationIdempotencyProved,
            supportsAutomaticNewConversation,
            shape);
    }

    private static bool TryFindAsyncMethod(
        string source,
        string methodName,
        out JavaScriptMethod method)
    {
        method = default!;
        var marker = "async " + methodName;
        var matches = new List<JavaScriptMethod>();
        var search = 0;
        while (search < source.Length)
        {
            var index = source.IndexOf(marker, search, StringComparison.Ordinal);
            if (index < 0)
            {
                break;
            }

            search = index + marker.Length;
            if (index > 0 && IsIdentifierCharacter(source[index - 1]))
            {
                continue;
            }

            var cursor = search;
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '(')
            {
                continue;
            }

            var parametersEnd = FindMatchingDelimiter(source, cursor, '(', ')');
            var parameters = source[(cursor + 1)..parametersEnd];
            cursor = parametersEnd + 1;
            SkipWhitespace(source, ref cursor);
            if (cursor >= source.Length || source[cursor] != '{')
            {
                continue;
            }

            var bodyEnd = FindMatchingDelimiter(source, cursor, '{', '}');
            matches.Add(new JavaScriptMethod(parameters, source[(cursor + 1)..bodyEnd]));
        }

        if (matches.Count != 1)
        {
            return false;
        }

        method = matches[0];
        return true;
    }

    private static bool TryFindDestructuredAlias(
        JavaScriptMethod method,
        string propertyName,
        out string alias)
    {
        alias = string.Empty;
        var parameter = Regex.Match(
            method.Parameters,
            "^\\s*(?<name>" + IdentifierPattern + ")\\b",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        if (!parameter.Success)
        {
            return false;
        }

        var destructuring = new Regex(
            "(?:let|const|var)\\s*\\{(?<properties>[^{}]{0,8192})\\}\\s*=\\s*" +
            Regex.Escape(parameter.Groups["name"].Value) + "\\b",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            RegexTimeout);
        foreach (Match match in destructuring.Matches(method.Body))
        {
            if (TryFindPropertyAlias(match.Groups["properties"].Value, propertyName, out alias))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryFindPropertyAlias(
        string properties,
        string propertyName,
        out string alias)
    {
        alias = string.Empty;
        var match = Regex.Match(
            properties,
            "(?:^|,)\\s*" + Regex.Escape(propertyName) +
            "(?:\\s*:\\s*(?<alias>" + IdentifierPattern + "))?\\s*(?=,|$)",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        if (!match.Success)
        {
            return false;
        }

        alias = match.Groups["alias"].Success
            ? match.Groups["alias"].Value
            : propertyName;
        return true;
    }

    private static bool RequestObjectCarriesStableProperty(
        string body,
        string method,
        string propertyName,
        string value)
    {
        var send = Regex.Match(
            body,
            "\\.sendRequest\\s*\\(\\s*(?:\"" + Regex.Escape(method) +
            "\"|'" + Regex.Escape(method) + "'|`" + Regex.Escape(method) +
            "`)\\s*,\\s*(?<request>" + IdentifierPattern + ")\\b",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        if (!send.Success)
        {
            return false;
        }

        var request = send.Groups["request"].Value;
        var prefix = body[..send.Index];
        if (Regex.IsMatch(
                prefix,
                "\\b" + Regex.Escape(request) + "\\s*\\.\\s*" +
                Regex.Escape(propertyName) + "\\s*=\\s*" + Regex.Escape(value) + "\\b",
                RegexOptions.CultureInvariant,
                RegexTimeout))
        {
            return true;
        }

        var assignment = new Regex(
            "\\b" + Regex.Escape(request) + "\\s*=\\s*\\{",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        foreach (Match match in assignment.Matches(prefix).Cast<Match>().Reverse())
        {
            var openBrace = match.Index + match.Length - 1;
            var closeBrace = FindMatchingDelimiter(prefix, openBrace, '{', '}');
            if (HasObjectProperty(
                    prefix[(openBrace + 1)..closeBrace],
                    propertyName,
                    value))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryFindCreatedConversationReceipt(
        JavaScriptMethod method,
        out string receipt)
    {
        receipt = string.Empty;
        var match = Regex.Match(
            method.Body,
            "\\breturn\\b.{0,8192}\\{\\s*conversationId\\s*:\\s*(?<receipt>" +
            IdentifierPattern + ")\\b.{0,4096}firstTurnContext\\s*:\\s*\\{\\s*" +
            "conversationId\\s*:\\s*\\k<receipt>\\b",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            RegexTimeout);
        if (!match.Success)
        {
            return false;
        }

        receipt = match.Groups["receipt"].Value;
        return true;
    }

    private static bool TryFindStartConversationReceipt(
        JavaScriptMethod method,
        out string receipt)
    {
        receipt = string.Empty;
        var match = Regex.Match(
            method.Body,
            "\\{\\s*conversationId\\s*:\\s*(?<receipt>" + IdentifierPattern +
            ")\\b[^{}]{0,4096}\\}\\s*=\\s*await\\b.{0,4096}\\bthis\\." +
            "threadCreation\\.createConversation\\s*\\(",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            RegexTimeout);
        if (!match.Success)
        {
            return false;
        }

        receipt = match.Groups["receipt"].Value;
        return Regex.IsMatch(
            method.Body,
            "\\breturn\\s+" + Regex.Escape(receipt) + "\\b",
            RegexOptions.CultureInvariant,
            RegexTimeout);
    }

    private static bool HasNullGuardBefore(
        string body,
        string identifier,
        string marker)
    {
        var index = body.IndexOf(marker, StringComparison.Ordinal);
        if (index < 0)
        {
            return false;
        }

        var prefix = body[..index];
        return Regex.IsMatch(
            prefix,
            "(?:\\b" + Regex.Escape(identifier) +
            "\\s*={2,3}\\s*null\\b|\\bnull\\s*={2,3}\\s*" +
            Regex.Escape(identifier) + "\\b)",
            RegexOptions.CultureInvariant,
            RegexTimeout);
    }

    private static bool BindingOccursAfterStartThread(
        string body,
        string callback,
        string conversationReceipt)
    {
        var start = body.IndexOf(".startThread(", StringComparison.Ordinal);
        if (start < 0)
        {
            return false;
        }

        var callbackCall = Regex.Match(
            body,
            "\\bawait\\s+" + Regex.Escape(callback) +
            "\\s*\\?\\.\\s*\\(\\s*" + Regex.Escape(conversationReceipt) +
            "\\s*\\)",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        return callbackCall.Success && callbackCall.Index > start;
    }

    private static bool TryFindRequestObject(
        string functionBody,
        int beforeIndex,
        string requestObject,
        string conversation,
        string client,
        string rest)
    {
        var assignment = new Regex(
            "\\b" + Regex.Escape(requestObject) + "\\s*=\\s*\\{",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        foreach (Match match in assignment.Matches(functionBody[..beforeIndex]).Cast<Match>().Reverse())
        {
            var openBrace = match.Index + match.Length - 1;
            var closeBrace = FindMatchingDelimiter(functionBody, openBrace, '{', '}');
            if (closeBrace >= beforeIndex)
            {
                continue;
            }

            var objectBody = functionBody[(openBrace + 1)..closeBrace];
            if (HasObjectProperty(objectBody, "threadId", conversation) &&
                HasObjectProperty(objectBody, "clientUserMessageId", client) &&
                Regex.IsMatch(
                    objectBody,
                    "(?:^|[,{}])\\s*input\\s*:\\s*" + Regex.Escape(rest) +
                    "\\s*\\.\\s*input\\b",
                    RegexOptions.CultureInvariant | RegexOptions.Singleline,
                    RegexTimeout))
            {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlySet<string> InspectInputKinds(string source)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (HasObjectShapeNearLiteral(source, "text", "text"))
        {
            result.Add("text");
        }

        var hasLocalImageObject = HasObjectShapeNearLiteral(source, "localImage", "path");
        var hasLocalImagePathRead = false;
        foreach (var quoteIndex in FindQuotedLiteralStarts(source, "localImage"))
        {
            var start = Math.Max(0, quoteIndex - 320);
            var end = Math.Min(source.Length, quoteIndex + "localImage".Length + 322);
            var window = source[start..end];
            if (Regex.IsMatch(
                    window,
                    "(?<item>" + IdentifierPattern +
                    ")\\s*\\.\\s*type\\s*===\\s*(?:\"localImage\"|'localImage'|`localImage`)" +
                    "[^;]{0,320}\\k<item>\\s*\\.\\s*path\\b",
                    RegexOptions.CultureInvariant | RegexOptions.Singleline,
                    RegexTimeout))
            {
                hasLocalImagePathRead = true;
                break;
            }
        }

        if (hasLocalImageObject && hasLocalImagePathRead)
        {
            result.Add("localImage");
        }

        return result;
    }

    private static bool HasObjectShapeNearLiteral(
        string source,
        string literal,
        string followingProperty)
    {
        var search = 0;
        var occurrences = 0;
        while (search < source.Length)
        {
            var literalIndex = source.IndexOf(literal, search, StringComparison.Ordinal);
            if (literalIndex < 0)
            {
                break;
            }

            search = literalIndex + literal.Length;
            if (literalIndex == 0 || literalIndex + literal.Length >= source.Length)
            {
                continue;
            }

            var quote = source[literalIndex - 1];
            if (quote is not ('\'' or '"' or '`') ||
                source[literalIndex + literal.Length] != quote)
            {
                continue;
            }

            if (++occurrences > 4096)
            {
                throw Failure(
                    "structured-input-literal-count",
                    isCompatibilityFailure: true,
                    "A selected input-kind literal exceeds its occurrence bound.");
            }

            var quoteIndex = literalIndex - 1;
            var start = Math.Max(0, quoteIndex - 96);
            var end = Math.Min(source.Length, quoteIndex + literal.Length + 194);
            var window = source[start..end];
            if (Regex.IsMatch(
                    window,
                    "type\\s*:\\s*(?:\"" + Regex.Escape(literal) + "\"|'" +
                    Regex.Escape(literal) + "'|`" + Regex.Escape(literal) +
                    "`)\\s*,\\s*" + Regex.Escape(followingProperty) + "\\s*:",
                    RegexOptions.CultureInvariant,
                    RegexTimeout))
            {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<JavaScriptCall> FindCalls(
        string body,
        string receiver,
        string method)
    {
        var result = new List<JavaScriptCall>();
        var regex = new Regex(
            "\\b" + Regex.Escape(receiver) + "\\s*\\.\\s*" + Regex.Escape(method) +
            "\\s*\\(",
            RegexOptions.CultureInvariant,
            RegexTimeout);
        foreach (Match match in regex.Matches(body))
        {
            var openParenthesis = match.Index + match.Length - 1;
            var closeParenthesis = FindMatchingDelimiter(body, openParenthesis, '(', ')');
            result.Add(new JavaScriptCall(
                match.Index,
                body[(openParenthesis + 1)..closeParenthesis]));
        }

        return result;
    }

    private static int FindMatchingDelimiter(
        string source,
        int openingIndex,
        char opening,
        char closing)
    {
        if (openingIndex < 0 || openingIndex >= source.Length || source[openingIndex] != opening)
        {
            throw Failure(
                "structured-javascript-shape",
                isCompatibilityFailure: false,
                "A JavaScript delimiter scan started at an invalid position.");
        }

        var depth = 0;
        for (var index = openingIndex; index < source.Length; index++)
        {
            var character = source[index];
            if (character is '\'' or '"' or '`')
            {
                index = SkipQuoted(source, index, character);
                continue;
            }

            if (character == '/' && index + 1 < source.Length)
            {
                if (source[index + 1] == '/')
                {
                    index = SkipLineComment(source, index + 2);
                    continue;
                }

                if (source[index + 1] == '*')
                {
                    index = SkipBlockComment(source, index + 2);
                    continue;
                }

                if (IsRegularExpressionStart(source, index))
                {
                    index = SkipRegularExpression(source, index);
                    continue;
                }
            }

            if (character == opening)
            {
                depth++;
            }
            else if (character == closing && --depth == 0)
            {
                return index;
            }
        }

        throw Failure(
            "structured-javascript-shape",
            isCompatibilityFailure: false,
            "A selected JavaScript delimiter was not balanced.");
    }

    private static int SkipQuoted(string source, int openingIndex, char quote)
    {
        for (var index = openingIndex + 1; index < source.Length; index++)
        {
            if (source[index] == '\\')
            {
                index++;
                continue;
            }

            if (source[index] == quote)
            {
                return index;
            }
        }

        throw Failure(
            "structured-javascript-shape",
            isCompatibilityFailure: false,
            "A selected JavaScript string literal was not terminated.");
    }

    private static int SkipLineComment(string source, int start)
    {
        var lineFeed = source.IndexOf('\n', start);
        return lineFeed < 0 ? source.Length - 1 : lineFeed;
    }

    private static int SkipBlockComment(string source, int start)
    {
        var end = source.IndexOf("*/", start, StringComparison.Ordinal);
        if (end < 0)
        {
            throw Failure(
                "structured-javascript-shape",
                isCompatibilityFailure: false,
                "A selected JavaScript block comment was not terminated.");
        }

        return end + 1;
    }

    private static int SkipRegularExpression(string source, int openingIndex)
    {
        var inCharacterClass = false;
        for (var index = openingIndex + 1; index < source.Length; index++)
        {
            if (source[index] == '\\')
            {
                index++;
                continue;
            }

            if (source[index] == '[')
            {
                inCharacterClass = true;
            }
            else if (source[index] == ']')
            {
                inCharacterClass = false;
            }
            else if (source[index] == '/' && !inCharacterClass)
            {
                while (index + 1 < source.Length && char.IsAsciiLetter(source[index + 1]))
                {
                    index++;
                }

                return index;
            }
            else if (source[index] is '\r' or '\n')
            {
                break;
            }
        }

        throw Failure(
            "structured-javascript-shape",
            isCompatibilityFailure: false,
            "A selected JavaScript regular expression was not terminated.");
    }

    private static bool IsRegularExpressionStart(string source, int slashIndex)
    {
        var index = slashIndex - 1;
        while (index >= 0 && char.IsWhiteSpace(source[index]))
        {
            index--;
        }

        if (index < 0)
        {
            return true;
        }

        if ("([{=:;,!?&|+-*%^~<>".Contains(source[index], StringComparison.Ordinal))
        {
            return true;
        }

        var end = index + 1;
        while (index >= 0 && IsIdentifierCharacter(source[index]))
        {
            index--;
        }

        var token = source[(index + 1)..end];
        return token is "return" or "case" or "throw" or "typeof" or "instanceof" or
            "in" or "of" or "yield" or "await";
    }

    private static bool HasObjectProperty(string objectBody, string name, string identifier) =>
        Regex.IsMatch(
            objectBody,
            "(?:^|[,{}])\\s*" + Regex.Escape(name) + "\\s*:\\s*" +
            Regex.Escape(identifier) + "\\b",
            RegexOptions.CultureInvariant | RegexOptions.Singleline,
            RegexTimeout);

    private static IReadOnlyList<int> FindQuotedLiteralStarts(string source, string value)
    {
        var result = new List<int>();
        var search = 0;
        while (search < source.Length)
        {
            var index = source.IndexOf(value, search, StringComparison.Ordinal);
            if (index < 0)
            {
                break;
            }

            search = index + value.Length;
            if (index == 0 || index + value.Length >= source.Length)
            {
                continue;
            }

            var quote = source[index - 1];
            if (quote is not ('\'' or '"' or '`') || source[index + value.Length] != quote)
            {
                continue;
            }

            result.Add(index - 1);
            if (result.Count > MaximumLiteralOccurrences)
            {
                throw Failure(
                    "structured-literal-count",
                    isCompatibilityFailure: true,
                    "A selected semantic literal exceeds its occurrence bound.");
            }
        }

        return result;
    }

    private static bool ContainsQuotedLiteral(string source, string value) =>
        source.Contains("\"" + value + "\"", StringComparison.Ordinal) ||
        source.Contains("'" + value + "'", StringComparison.Ordinal) ||
        source.Contains("`" + value + "`", StringComparison.Ordinal);

    private static CachedEntry ReadCachedEntry(
        BoundedRandomAccessSource source,
        JsonElement files,
        long dataBase,
        long archiveLength,
        string path,
        int maximumBytes,
        Dictionary<string, CachedEntry> cache,
        List<PackedEntry> selectedEntries)
    {
        if (cache.TryGetValue(path, out var cached))
        {
            return cached;
        }

        var entry = ResolvePackedEntry(files, path, dataBase, archiveLength);
        if (entry.Size > maximumBytes || entry.Size > int.MaxValue)
        {
            throw Failure(
                "structured-entry-bounds",
                isCompatibilityFailure: false,
                "A selected installed ASAR entry exceeds its byte bound.");
        }

        var bytes = new byte[checked((int)entry.Size)];
        ReadExactly(source, entry.AbsoluteOffset, bytes);
        cached = new CachedEntry(entry, bytes);
        cache.Add(path, cached);
        selectedEntries.Add(entry);
        return cached;
    }

    private static PackedEntry ResolvePackedEntry(
        JsonElement rootFiles,
        string path,
        long dataBase,
        long archiveLength)
    {
        if (!IsCanonicalPath(path))
        {
            throw Failure(
                "structured-asar-path",
                isCompatibilityFailure: false,
                "A selected installed ASAR path is not canonical.");
        }

        var files = rootFiles;
        JsonElement node = default;
        var parts = path.Split('/');
        for (var index = 0; index < parts.Length; index++)
        {
            if (!files.TryGetProperty(parts[index], out node) ||
                node.ValueKind != JsonValueKind.Object)
            {
                throw Failure(
                    "structured-asar-entry",
                    isCompatibilityFailure: true,
                    "A selected installed ASAR entry is missing.");
            }

            if (node.TryGetProperty("link", out _) || node.TryGetProperty("unpacked", out _))
            {
                throw Failure(
                    "structured-asar-entry",
                    isCompatibilityFailure: false,
                    "A selected installed ASAR path uses link or unpacked semantics.");
            }

            if (index < parts.Length - 1)
            {
                if (!node.TryGetProperty("files", out files) ||
                    files.ValueKind != JsonValueKind.Object ||
                    node.TryGetProperty("size", out _) ||
                    node.TryGetProperty("offset", out _))
                {
                    throw Failure(
                        "structured-asar-entry",
                        isCompatibilityFailure: false,
                        "A selected installed ASAR ancestor is not a canonical directory.");
                }
            }
        }

        if (node.TryGetProperty("files", out _) ||
            !node.TryGetProperty("size", out var sizeProperty) ||
            !node.TryGetProperty("offset", out var offsetProperty) ||
            sizeProperty.ValueKind != JsonValueKind.Number ||
            offsetProperty.ValueKind != JsonValueKind.String)
        {
            throw Failure(
                "structured-asar-entry",
                isCompatibilityFailure: false,
                "A selected installed ASAR entry is not a canonical packed file.");
        }

        var size = ParseCanonicalDecimal(sizeProperty.GetRawText());
        var offset = ParseCanonicalDecimal(offsetProperty.GetString());
        if (size <= 0)
        {
            throw Failure(
                "structured-asar-entry",
                isCompatibilityFailure: false,
                "A selected installed ASAR entry is empty.");
        }

        var absoluteOffset = checked(dataBase + offset);
        var absoluteEnd = checked(absoluteOffset + size);
        if (absoluteOffset < dataBase || absoluteEnd > archiveLength)
        {
            throw Failure(
                "structured-asar-range",
                isCompatibilityFailure: false,
                "A selected installed ASAR entry extends beyond the retained file.");
        }

        return new PackedEntry(path, offset, absoluteOffset, absoluteEnd, size);
    }

    private static PackageMetadata ReadPackageMetadata(byte[] bytes, int maximumJsonDepth)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = maximumJsonDepth
        });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw Failure(
                "structured-package-json",
                isCompatibilityFailure: false,
                "The installed ASAR package metadata root is invalid.");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                throw Failure(
                    "structured-package-json",
                    isCompatibilityFailure: false,
                    "The installed ASAR package metadata has duplicate properties.");
            }
        }

        var name = ReadBoundedString(document.RootElement, "name", 128);
        var productName = ReadBoundedString(document.RootElement, "productName", 128);
        var version = ReadBoundedString(document.RootElement, "version", 128);
        var main = ReadBoundedString(document.RootElement, "main", MaximumPathLength);
        if (!IsCanonicalPath(main))
        {
            throw Failure(
                "structured-package-main",
                isCompatibilityFailure: false,
                "The installed ASAR package main path is not canonical.");
        }

        return new PackageMetadata(name, productName, version, main);
    }

    private static string ReadBoundedString(JsonElement root, string name, int maximumLength)
    {
        if (!root.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String ||
            property.GetString() is not { Length: > 0 } value ||
            value.Length > maximumLength)
        {
            throw Failure(
                "structured-package-json",
                isCompatibilityFailure: false,
                "The installed ASAR package metadata is missing or unbounded.");
        }

        return value;
    }

    private static void ValidateJsonShape(
        JsonElement value,
        int depth,
        ref int valueCount,
        int maximumDepth,
        int maximumValues)
    {
        if (depth > maximumDepth || ++valueCount > maximumValues)
        {
            throw Failure(
                "structured-asar-json-bounds",
                isCompatibilityFailure: false,
                "The installed ASAR JSON structure exceeds its bounds.");
        }

        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw Failure(
                        "structured-asar-json-duplicate",
                        isCompatibilityFailure: false,
                        "The installed ASAR JSON structure contains duplicate properties.");
                }

                ValidateJsonShape(
                    property.Value,
                    depth + 1,
                    ref valueCount,
                    maximumDepth,
                    maximumValues);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                ValidateJsonShape(
                    item,
                    depth + 1,
                    ref valueCount,
                    maximumDepth,
                    maximumValues);
            }
        }
    }

    private static string ResolveRelativePath(
        string basePath,
        string relativePath,
        bool requireWebviewRoot)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            relativePath.Length > MaximumPathLength ||
            relativePath.IndexOfAny(['\\', ':', '\0', '?', '#']) >= 0 ||
            relativePath[0] == '/')
        {
            throw Failure(
                "structured-relative-path",
                isCompatibilityFailure: true,
                "A webview module reference is not a bounded relative path.");
        }

        var segments = basePath.Split('/').SkipLast(1).ToList();
        foreach (var segment in relativePath.Split('/', StringSplitOptions.None))
        {
            if (segment is "" or ".")
            {
                continue;
            }

            if (segment == "..")
            {
                if (segments.Count == 0)
                {
                    throw Failure(
                        "structured-relative-path",
                        isCompatibilityFailure: true,
                        "A webview module reference escapes the ASAR root.");
                }

                segments.RemoveAt(segments.Count - 1);
                continue;
            }

            if (segment.Length > 255)
            {
                throw Failure(
                    "structured-relative-path",
                    isCompatibilityFailure: true,
                    "A webview module path segment exceeds its bound.");
            }

            segments.Add(segment);
        }

        var resolved = string.Join('/', segments);
        if (!IsCanonicalPath(resolved) ||
            !resolved.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
            requireWebviewRoot && !resolved.StartsWith("webview/", StringComparison.Ordinal))
        {
            throw Failure(
                "structured-relative-path",
                isCompatibilityFailure: true,
                "A webview module reference resolves outside the supported module root.");
        }

        return resolved;
    }

    private static bool IsCanonicalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            path.Length > MaximumPathLength ||
            path[0] == '/' ||
            path.IndexOfAny(['\\', ':', '\0']) >= 0)
        {
            return false;
        }

        var parts = path.Split('/', StringSplitOptions.None);
        return parts.Length is >= 1 and <= MaximumPathSegments &&
               parts.All(part => part.Length is >= 1 and <= 255 && part is not "." and not "..");
    }

    private static long ParseCanonicalDecimal(string? value)
    {
        if (string.IsNullOrEmpty(value) ||
            value.Length > 19 ||
            value.Length > 1 && value[0] == '0')
        {
            throw Failure(
                "structured-asar-number",
                isCompatibilityFailure: false,
                "An installed ASAR numeric field is not canonical decimal.");
        }

        long result = 0;
        foreach (var character in value)
        {
            if (character is < '0' or > '9')
            {
                throw Failure(
                    "structured-asar-number",
                    isCompatibilityFailure: false,
                    "An installed ASAR numeric field is not canonical decimal.");
            }

            result = checked(result * 10 + character - '0');
        }

        return result;
    }

    private static void EnsureDisjoint(IReadOnlyList<PackedEntry> entries)
    {
        for (var first = 0; first < entries.Count; first++)
        {
            for (var second = first + 1; second < entries.Count; second++)
            {
                if (entries[first].AbsoluteOffset < entries[second].AbsoluteEnd &&
                    entries[second].AbsoluteOffset < entries[first].AbsoluteEnd)
                {
                    throw Failure(
                        "structured-asar-range",
                        isCompatibilityFailure: false,
                        "Selected installed ASAR entry ranges overlap.");
                }
            }
        }
    }

    private static CodexStructuredInputAsarSelectedEntry ToSnapshot(
        PackedEntry entry,
        ReadOnlySpan<byte> bytes) =>
        new(entry.Path, entry.Offset, entry.Size, Convert.ToHexString(SHA256.HashData(bytes)));

    private static string DecodeStrictUtf8(byte[] bytes, string code)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw Failure(
                code,
                isCompatibilityFailure: false,
                "A selected installed ASAR entry is not strict UTF-8.",
                exception);
        }
    }

    private static string FirstSuccessfulGroup(Match match, params string[] groupNames)
    {
        foreach (var name in groupNames)
        {
            if (match.Groups[name].Success)
            {
                return match.Groups[name].Value;
            }
        }

        throw Failure(
            "structured-regex-shape",
            isCompatibilityFailure: false,
            "A bounded semantic regex produced no selected value.");
    }

    private static void ReadExactly(
        ICodexAsarRandomAccessSource source,
        long offset,
        Span<byte> destination)
    {
        try
        {
            source.ReadExactly(offset, destination);
        }
        catch (Exception exception) when (
            exception is IOException or ArgumentException or InvalidOperationException or OverflowException)
        {
            throw Failure(
                "structured-asar-read",
                isCompatibilityFailure: false,
                "The retained installed ASAR could not satisfy a bounded read.",
                exception);
        }
    }

    private static string HashText(string value) =>
        Convert.ToHexString(SHA256.HashData(StrictUtf8.GetBytes(value)));

    private static bool IsIdentifier(string value) =>
        value.Length > 0 &&
        (char.IsAsciiLetter(value[0]) || value[0] is '_' or '$') &&
        value.Skip(1).All(IsIdentifierCharacter);

    private static bool IsIdentifierCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) || character is '_' or '$';

    private static void SkipWhitespace(string source, ref int index)
    {
        while (index < source.Length && char.IsWhiteSpace(source[index]))
        {
            index++;
        }
    }

    private static void ValidateLimits(CodexStructuredInputAsarInspectionLimits limits)
    {
        if (limits.MaximumArchiveBytes is < 16 or > 2L * 1024 * 1024 * 1024 ||
            limits.MaximumHeaderBytes is < 16 or > 64 * 1024 * 1024 ||
            limits.MaximumPackageJsonBytes is < 128 or > 4 * 1024 * 1024 ||
            limits.MaximumIndexHtmlBytes is < 128 or > 4 * 1024 * 1024 ||
            limits.MaximumScriptBytes is < 128 or > 32 * 1024 * 1024 ||
            limits.MaximumTotalReadBytes < limits.MaximumHeaderBytes ||
            limits.MaximumTotalReadBytes > 128L * 1024 * 1024 ||
            limits.MaximumJsonDepth is < 4 or > 128 ||
            limits.MaximumJsonValues is < 16 or > 1_000_000 ||
            limits.MaximumModuleEntries is < 1 or > 256 ||
            limits.MaximumDependencyDepth is < 0 or > 16 ||
            limits.MaximumImportsPerModule is < 1 or > 1024 ||
            limits.MaximumOwnerImportsPerModule is < 1 or > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(limits));
        }
    }

    private static CodexStructuredInputAsarException Failure(
        string code,
        bool isCompatibilityFailure,
        string message,
        Exception? innerException = null) =>
        new(code, isCompatibilityFailure, message, innerException);

    private sealed class BoundedRandomAccessSource(
        ICodexAsarRandomAccessSource inner,
        long maximumBytes) : ICodexAsarRandomAccessSource
    {
        private long _bytesRead;

        public long Length => inner.Length;

        public void ReadExactly(long offset, Span<byte> destination)
        {
            var next = checked(_bytesRead + destination.Length);
            if (next > maximumBytes)
            {
                throw Failure(
                    "structured-asar-read-budget",
                    isCompatibilityFailure: false,
                    "The installed ASAR semantic inspection exceeded its total read budget.");
            }

            inner.ReadExactly(offset, destination);
            _bytesRead = next;
        }
    }

    private sealed record HeaderSnapshot(
        JsonDocument Document,
        JsonElement Files,
        long DataBase,
        string HeaderSha256);

    private sealed record PackedEntry(
        string Path,
        long Offset,
        long AbsoluteOffset,
        long AbsoluteEnd,
        long Size);

    private sealed record CachedEntry(PackedEntry Entry, byte[] Bytes);

    private sealed record PackageMetadata(
        string Name,
        string ProductName,
        string Version,
        string MainPath);

    private sealed record OwnerSemanticShape(
        string EntryPath,
        IReadOnlySet<string> FollowerMethods,
        IReadOnlySet<string> NativeInputKinds,
        string HandlerShapeSha256,
        string InputShapeSha256,
        CodexNewConversationAsarSemantics NewConversation);

    private sealed record JavaScriptFunction(
        IReadOnlyList<string> Parameters,
        string Body);

    private sealed record JavaScriptMethod(string Parameters, string Body);

    private sealed record JavaScriptCall(int Start, string Arguments);

    private sealed record NativeStartShape(bool HasFollowerForwarding, bool HasNativeRequest);

    private enum OwnerDispatchTopology
    {
        LegacyHostHandler,
        DirectFollowerReceiver
    }

    private enum ModuleVisitState
    {
        Visiting,
        Visited
    }
}
