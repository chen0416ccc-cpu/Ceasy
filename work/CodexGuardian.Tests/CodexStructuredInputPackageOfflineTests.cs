using CodexGuardian.Control;
using CodexGuardian.Models;
using CodexGuardian.Services;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal static class CodexStructuredInputPackageOfflineTests
{
    private const string ModuleRootPath = "webview/assets/root.js";
    private const string OwnerPath = "webview/assets/owner.js";
    private const string ValidOwnerSource = """
        async function requestThreadFollower({hostId:h,request:r}){switch(r.method){case"thread-follower-start-turn":return{method:r.method,result:await invoke("thread-follower-start-turn-for-host",{hostId:h,...r.params})};default:return null}}
        const handlers={"thread-follower-start-turn-for-host":wrap(async(m,r)=>(m.assertThreadFollowerOwner(r.conversationId),{result:await startOwnerTurn(m,r.conversationId,r.turnStartParams,r.attachments,r.metadata)}))};
        async function startOwnerTurn(m,c,p,a,d){let{beforeSendRequest:x,...rest}=p,id=rest.clientUserMessageId??createId(),forwarded=m.sendThreadFollowerRequest(peer,"thread-follower-start-turn",{conversationId:c,turnStartParams:{...p,clientUserMessageId:id},attachments:a,metadata:d}),request={threadId:c,clientUserMessageId:id,input:rest.input};return await m.sendRequest("turn/start",request)}
        const textItem={type:"text",text:"hello"};
        function createImage(path){return{type:"localImage",path:path}}
        function readImage(item){return item.type==="localImage"?[item.path]:[]}
        const desktopOwner={
          async prewarmThread({model:e}){let request={model:e};return await this.params.requestClient.prewarmThreadStart(request)},
          async startThread(e){let{clientUserMessageId:f}=e,request={cwd:e.cwd};f!=null&&trace.markRequestDispatched(f,"thread/start");let result=await this.params.requestClient.sendRequest("thread/start",request);return result},
          async createConversation(e){let{clientUserMessageId:p,beforeConversationAdded:f}=e,prewarmed=await this.params.prewarmedThreadManager.consumePrewarmedThread(),result=prewarmed??await this.startThread({clientUserMessageId:p,cwd:e.cwd}),conversationId=result.thread.id;await f?.(conversationId);return{conversationId:conversationId,conversationResponse:result,firstTurnContext:{conversationId:conversationId}}},
          async startConversation(e,{clientThreadId:r}={}){let{input:a,clientUserMessageId:c}=e,{conversationId:F,conversationResponse:I,firstTurnContext:R}=await this.threadStartedNotificationDeferral.run(r!=null,()=>this.threadCreation.createConversation({clientUserMessageId:c,beforeConversationAdded:r==null?null:e=>bindClientThread(r,e)}));if(a.length===0)return F;await startOwnerTurn(this,F,{clientUserMessageId:c,input:a});return F}
        };
        const importLikeDocumentation="from \"./not-a-real-dependency.js\"";
        """;
    private const string DirectOwnerSource = """
        async function receiveFollower(t){switch(t.method){case"thread-follower-start-turn":{let result=await owner.startTurn(t.params.conversationId,t.params.turnStartParams,{localTurnMetadata:t.params.localTurnMetadata,mcpAppModelContextAttachments:t.params.mcpAppModelContextAttachments});return{method:t.method,result:{result:result}}}default:return null}}
        const owner={async startTurn(c,p,i){return await directOwnerTurn(manager,c,p,i?.mcpAppModelContextAttachments,i?.localTurnMetadata)}};
        async function directOwnerTurn(m,c,p,a,d){let{beforeSendRequest:x,...rest}=p,id=rest.clientUserMessageId??createId(),forwarded=m.sendThreadFollowerRequest(peer,"thread-follower-start-turn",{conversationId:c,turnStartParams:{...p,clientUserMessageId:id},mcpAppModelContextAttachments:a,localTurnMetadata:d});if(m.getStreamRole(c)?.role!=="owner")throw Error("not owner");let request={threadId:c,clientUserMessageId:id,input:rest.input};return await m.sendRequest("turn/start",request)}
        const textItem={type:"text",text:"hello"};
        function createImage(path){return{type:"localImage",path:path}}
        function readImage(item){return item.type==="localImage"?[item.path]:[]}
        const desktopOwner={
          async prewarmThread({model:e}){let request={model:e};return await this.params.requestClient.prewarmThreadStart(request)},
          async startThread(e){let{clientUserMessageId:f}=e,request={cwd:e.cwd};f!=null&&trace.markRequestDispatched(f,"thread/start");let result=await this.params.requestClient.sendRequest("thread/start",request);return result},
          async createConversation(e){let{clientUserMessageId:p,beforeConversationAdded:f}=e,prewarmed=await this.params.prewarmedThreadManager.consumePrewarmedThread(),result=prewarmed??await this.startThread({clientUserMessageId:p,cwd:e.cwd}),conversationId=result.thread.id;await f?.(conversationId);return{conversationId:conversationId,conversationResponse:result,firstTurnContext:{conversationId:conversationId}}},
          async startConversation(e,{clientThreadId:r}={}){let{input:a,clientUserMessageId:c}=e,{conversationId:F,conversationResponse:I,firstTurnContext:R}=await this.threadStartedNotificationDeferral.run(r!=null,()=>this.threadCreation.createConversation({clientUserMessageId:c,beforeConversationAdded:r==null?null:e=>bindClientThread(r,e)}));if(a.length===0)return F;await directOwnerTurn(this,F,{clientUserMessageId:c,input:a},null,null);return F}
        };
        """;
    private const string BoundDirectOwnerSource = """
        function receiveBoundFollower(manager,t){switch(t.method){case"thread-follower-start-turn":{let result=await manager.startTurn(t.params.conversationId,t.params.turnStartParams,{localTurnMetadata:t.params.localTurnMetadata,mcpAppModelContextAttachments:t.params.mcpAppModelContextAttachments});return{method:t.method,result:{result:result}}}default:return null}}
        function createLifecycle(manager,settings,{mode:m}){return{async startTurn(c,p,i){return await boundOwnerTurn(manager,c,p,i?.mcpAppModelContextAttachments,i?.localTurnMetadata)}}}
        class BoundOwner{constructor(settings={},factory=createLifecycle){this.taskLifecycle=factory(this,settings,{mode:"desktop"})}startTurn(c,p,i){return this.taskLifecycle.startTurn(c,p,i)}async handleThreadFollowerRequest(t){return receiveBoundFollower(this,t)}}
        async function boundOwnerTurn(m,c,p,a,d){let{beforeSendRequest:x,...rest}=p,id=rest.clientUserMessageId??createId(),forwarded=m.sendThreadFollowerRequest(peer,"thread-follower-start-turn",{conversationId:c,turnStartParams:{...p,clientUserMessageId:id},mcpAppModelContextAttachments:a,localTurnMetadata:d});if(m.getStreamRole(c)?.role!=="owner")throw Error("not owner");let request={threadId:c,clientUserMessageId:id,input:rest.input};return await m.sendRequest("turn/start",request)}
        const textItem={type:"text",text:"hello"};
        function createImage(path){return{type:"localImage",path:path}}
        function readImage(item){return item.type==="localImage"?[item.path]:[]}
        """;

    internal static async Task RunAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        RunCase(
            "structured ASAR semantics ignore package version in the capability shape",
            TestSemanticVersionIndependence,
            assert);
        RunCase(
            "structured ASAR semantics reject missing owner and stable-client relations",
            TestMissingOwnerRelations,
            assert);
        RunCase(
            "structured ASAR semantics prove the direct follower receiver fail closed",
            TestDirectFollowerReceiverSemantics,
            assert);
        RunCase(
            "structured ASAR semantics expose localImage only with coupled path handling",
            TestLocalImageCapability,
            assert);
        RunCase(
            "new-conversation semantics stay unavailable without receiver create idempotency",
            TestNewConversationSemantics,
            assert);
        RunCase(
            "structured ASAR traversal ignores unreachable marker decoys",
            TestUnreachableDecoy,
            assert);
        RunCase(
            "structured ASAR traversal rejects duplicate owners and dependency cycles",
            TestAmbiguousAndCyclicGraphs,
            assert);
        RunCase(
            "structured ASAR traversal enforces path and module-count bounds",
            TestTraversalBounds,
            assert);
        RunCase(
            "structured ASAR traversal enforces import bounds before owner short-circuit",
            TestImportBoundsAndOwnerShortCircuit,
            assert);
        await RunCaseAsync(
            "installed structured provider keeps semantic fingerprint version-independent and epoch-bound",
            TestProviderVersionAndEpochAsync,
            assert);
        await RunCaseAsync(
            "installed structured provider maps semantic incompatibility and evidence drift fail closed",
            TestProviderFailureStatesAsync,
            assert);
    }

    internal static async Task RunLiveInstalledPackageReadOnlyAsync(Action<bool, string> assert)
    {
        ArgumentNullException.ThrowIfNull(assert);
        try
        {
            var reader = new CodexStructuredInputPackageEvidenceReader();
            try
            {
                var evidence = reader.Read();
                Console.WriteLine(
                    "INFO  installed structured-input owner entry " +
                    evidence.AppAsar.Snapshot.OwnerEntryPath +
                    " selected modules " + evidence.AppAsar.Snapshot.ModuleEntries.Count);
                var creation = evidence.AppAsar.Snapshot.NewConversation;
                Console.WriteLine(
                    "INFO  installed new-conversation semantics flow=" +
                    creation.HasCreateAndFirstTurnFlow +
                    " createStable=" + creation.CreationRequestHasStableIdentity +
                    " receipt=" + creation.CreatedConversationReceiptReturned +
                    " firstTurnStable=" + creation.FirstTurnRequestHasStableIdentity +
                    " prewarmBound=" + creation.StableOperationCannotConsumePrewarmedThread +
                    " receiverIdempotency=" + creation.ReceiverCreationIdempotencyProved +
                    " automatic=" + creation.SupportsAutomaticNewConversation);
            }
            catch (CodexStructuredInputPackageException exception)
            {
                Console.WriteLine(
                    "INFO  installed structured-input evidence failure " +
                    exception.Code + " compatibility=" + exception.IsCompatibilityFailure);
                throw;
            }

            var capabilities = await new InstalledCodexStructuredInputCapabilityProvider(
                    new AttachmentLimitSettings(),
                    reader)
                .ReadAsync(CancellationToken.None);
            assert(
                capabilities.State == StructuredInputCapabilityState.Supported &&
                capabilities.SupportedInputKinds.SetEquals(
                    new[] { "text", "local_image" }) &&
                capabilities.SupportsAttachmentOnly &&
                capabilities.Epoch > 0 &&
                IsSha256(capabilities.SemanticFingerprint),
                "installed package read-only structured-input semantics");
            Console.WriteLine(
                "INFO  installed structured-input semantic fingerprint " +
                capabilities.SemanticFingerprint[..Math.Min(16, capabilities.SemanticFingerprint.Length)] +
                " epoch " + capabilities.Epoch);
        }
        catch (Exception exception)
        {
            assert(
                false,
                "installed package read-only structured-input semantics: " +
                exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static void TestSemanticVersionIndependence()
    {
        var first = InspectArchive(BuildStructuredArchive(packageVersion: "1.0.0"));
        var second = InspectArchive(BuildStructuredArchive(packageVersion: "99.0.0"));
        Ensure(first.PackageVersion == "1.0.0", "the first diagnostic package version was lost");
        Ensure(second.PackageVersion == "99.0.0", "the second diagnostic package version was lost");
        Ensure(
            first.HandlerShapeSha256 == second.HandlerShapeSha256 &&
            first.InputShapeSha256 == second.InputShapeSha256 &&
            first.NewConversation.ShapeSha256 == second.NewConversation.ShapeSha256,
            "package version changed a semantic shape hash");
        Ensure(
            first.PackageJson.Sha256 != second.PackageJson.Sha256,
            "the package version fixture did not change package.json identity");
        Ensure(first.OwnerEntryPath == OwnerPath, "the reachable owner module was not selected");
    }

    private static void TestMissingOwnerRelations()
    {
        var noOwnerAssertion = ValidOwnerSource.Replace(
            "m.assertThreadFollowerOwner(r.conversationId)",
            "m.observeThread(r.conversationId)",
            StringComparison.Ordinal);
        ExpectAsarCode(
            () => InspectArchive(BuildStructuredArchive(ownerSource: noOwnerAssertion)),
            "structured-owner-semantics-missing",
            compatibilityFailure: true);

        var unstableClientId = ValidOwnerSource.Replace(
            "id=rest.clientUserMessageId??createId()",
            "id=createId()",
            StringComparison.Ordinal);
        ExpectAsarCode(
            () => InspectArchive(BuildStructuredArchive(ownerSource: unstableClientId)),
            "structured-owner-semantics-missing",
            compatibilityFailure: true);
    }

    private static void TestDirectFollowerReceiverSemantics()
    {
        var legacy = InspectArchive(BuildStructuredArchive());
        var direct = InspectArchive(BuildStructuredArchive(ownerSource: DirectOwnerSource));
        Ensure(direct.OwnerEntryPath == OwnerPath, "the direct follower receiver was not selected");
        Ensure(
            direct.NativeInputKinds.SetEquals(new[] { "text", "localImage" }),
            "the direct follower receiver lost its native input kinds");
        Ensure(
            direct.HandlerShapeSha256 != legacy.HandlerShapeSha256,
            "legacy and direct follower topologies shared a handler fingerprint");
        Ensure(
            direct.InputShapeSha256 == legacy.InputShapeSha256,
            "equivalent legacy and direct native input shapes diverged");
        var bound = InspectArchive(BuildStructuredArchive(ownerSource: BoundDirectOwnerSource));
        Ensure(
            bound.HandlerShapeSha256 == direct.HandlerShapeSha256 &&
            bound.InputShapeSha256 == direct.InputShapeSha256,
            "the receiver-to-class lifecycle binding changed equivalent direct semantics");

        var mutations = new (string Name, string Source)[]
        {
            (
                "receiver conversation",
                DirectOwnerSource.Replace(
                    "t.params.conversationId,t.params.turnStartParams",
                    "t.params.otherConversationId,t.params.turnStartParams",
                    StringComparison.Ordinal)),
            (
                "receiver turn params",
                DirectOwnerSource.Replace(
                    "t.params.conversationId,t.params.turnStartParams",
                    "t.params.conversationId,t.params.otherTurnStartParams",
                    StringComparison.Ordinal)),
            (
                "receiver metadata",
                DirectOwnerSource.Replace(
                    "localTurnMetadata:t.params.localTurnMetadata",
                    "localTurnMetadata:null",
                    StringComparison.Ordinal)),
            (
                "receiver manager binding",
                DirectOwnerSource.Replace(
                    "await owner.startTurn",
                    "await decoy.startTurn",
                    StringComparison.Ordinal) +
                "\nconst decoy={async startTurn(c,p,i){return null}};"),
            (
                "native delegation",
                DirectOwnerSource.Replace(
                    "directOwnerTurn(manager,c,p,i?.mcpAppModelContextAttachments",
                    "directOwnerTurn(manager,c,{input:[]},i?.mcpAppModelContextAttachments",
                    StringComparison.Ordinal)),
            (
                "stable client id",
                DirectOwnerSource.Replace(
                    "id=rest.clientUserMessageId??createId()",
                    "id=createId()",
                    StringComparison.Ordinal)),
            (
                "owner role guard",
                DirectOwnerSource.Replace(
                    "m.getStreamRole(c)?.role!==\"owner\"",
                    "m.getStreamRole(c)?.role===\"owner\"",
                    StringComparison.Ordinal)),
            (
                "native input",
                DirectOwnerSource.Replace(
                    "input:rest.input",
                    "input:[]",
                    StringComparison.Ordinal)),
            (
                "unique native request",
                DirectOwnerSource.Replace(
                    "return await m.sendRequest(\"turn/start\",request)",
                    "await m.sendRequest(\"turn/start\",request);return await m.sendRequest(\"turn/start\",request)",
                    StringComparison.Ordinal)),
            (
                "unique receiver",
                DirectOwnerSource + "\n" + DirectOwnerSource.Replace(
                    "receiveFollower(t)",
                    "receiveFollowerAgain(t)",
                    StringComparison.Ordinal))
        };
        foreach (var mutation in mutations)
        {
            ExpectAsarCode(
                () => InspectArchive(BuildStructuredArchive(ownerSource: mutation.Source)),
                "structured-owner-semantics-missing",
                compatibilityFailure: true);
        }

        var boundMutations = new[]
        {
            BoundDirectOwnerSource.Replace(
                "return receiveBoundFollower(this,t)",
                "return receiveBoundFollower(other,t)",
                StringComparison.Ordinal),
            BoundDirectOwnerSource.Replace(
                "boundOwnerTurn(manager,c,p",
                "boundOwnerTurn(other,c,p",
                StringComparison.Ordinal),
            BoundDirectOwnerSource.Replace(
                "await manager.startTurn",
                "await decoy.startTurn",
                StringComparison.Ordinal) +
            "\nconst decoy={async startTurn(c,p,i){return null}};"
        };
        foreach (var mutation in boundMutations)
        {
            ExpectAsarCode(
                () => InspectArchive(BuildStructuredArchive(ownerSource: mutation)),
                "structured-owner-semantics-missing",
                compatibilityFailure: true);
        }
    }

    private static void TestLocalImageCapability()
    {
        var supported = InspectArchive(BuildStructuredArchive());
        Ensure(
            supported.NativeInputKinds.SetEquals(new[] { "text", "localImage" }),
            "the coupled localImage path shape was not exposed");

        var textOnlySource = ValidOwnerSource
            .Replace(
                "function createImage(path){return{type:\"localImage\",path:path}}",
                "function createValue(path){return path}",
                StringComparison.Ordinal)
            .Replace(
                "function readImage(item){return item.type===\"localImage\"?[item.path]:[]}",
                "function readValue(item){return item}",
                StringComparison.Ordinal);
        var textOnly = InspectArchive(BuildStructuredArchive(ownerSource: textOnlySource));
        Ensure(
            textOnly.NativeInputKinds.SetEquals(new[] { "text" }),
            "localImage was exposed without coupled type and path semantics");
    }

    private static void TestNewConversationSemantics()
    {
        var current = InspectArchive(BuildStructuredArchive()).NewConversation;
        Ensure(current.HasCreateAndFirstTurnFlow, "the create-and-first-turn flow was not found");
        Ensure(
            !current.CreationRequestHasStableIdentity,
            "thread/start incorrectly claimed a stable receiver identity");
        Ensure(
            current.CreatedConversationReceiptReturned &&
            current.FirstTurnRequestHasStableIdentity &&
            current.FirstTurnCanBeReconciled,
            "the bounded conversation and first-turn receipts were not recognized");
        Ensure(
            !current.StableOperationCannotConsumePrewarmedThread &&
            current.ClientThreadBindingOccursAfterCreationResponse,
            "the prewarm or post-response binding risk was lost");
        Ensure(
            !current.ReceiverCreationIdempotencyProved &&
            !current.SupportsAutomaticNewConversation &&
            IsSha256(current.ShapeSha256),
            "unsafe new-conversation capability was exposed");

        var requestIdentifiedSource = ValidOwnerSource.Replace(
            "request={cwd:e.cwd};f!=null&&trace.markRequestDispatched",
            "request={cwd:e.cwd};request.clientUserMessageId=f;f!=null&&trace.markRequestDispatched",
            StringComparison.Ordinal);
        var requestIdentified = InspectArchive(
            BuildStructuredArchive(ownerSource: requestIdentifiedSource)).NewConversation;
        Ensure(
            requestIdentified.CreationRequestHasStableIdentity,
            "a directly bound thread/start identity was not recognized");
        Ensure(
            !requestIdentified.SupportsAutomaticNewConversation,
            "a request field alone incorrectly proved receiver idempotency");

        var prewarmGuardedSource = requestIdentifiedSource.Replace(
            "prewarmed=await this.params.prewarmedThreadManager.consumePrewarmedThread()",
            "prewarmed=p==null?await this.params.prewarmedThreadManager.consumePrewarmedThread():null",
            StringComparison.Ordinal);
        var prewarmGuarded = InspectArchive(
            BuildStructuredArchive(ownerSource: prewarmGuardedSource)).NewConversation;
        Ensure(
            prewarmGuarded.StableOperationCannotConsumePrewarmedThread,
            "a non-null stable operation was not excluded from the prewarmed path");
        Ensure(
            !prewarmGuarded.ReceiverCreationIdempotencyProved &&
            !prewarmGuarded.SupportsAutomaticNewConversation,
            "prewarm exclusion incorrectly became an at-most-once creation proof");
    }

    private static void TestUnreachableDecoy()
    {
        var archive = BuildStructuredArchive(additionalEntries: new Dictionary<string, byte[]>
        {
            ["webview/assets/decoy.js"] = Encoding.UTF8.GetBytes(
                "const decoy=['thread-follower-start-turn','thread-follower-start-turn-for-host'," +
                "'assertThreadFollowerOwner','turn/start','clientUserMessageId','localImage'];")
        });
        var snapshot = InspectArchive(archive);
        Ensure(snapshot.OwnerEntryPath == OwnerPath, "an unreachable marker decoy was selected");
        Ensure(
            snapshot.ModuleEntries.All(entry => entry.Path != "webview/assets/decoy.js"),
            "an unreachable marker decoy entered the dependency closure");
    }

    private static void TestAmbiguousAndCyclicGraphs()
    {
        var duplicateRoot = "import \"./owner.js\"; import \"./owner-copy.js\";";
        ExpectAsarCode(
            () => InspectArchive(BuildStructuredArchive(
                rootSource: duplicateRoot,
                additionalEntries: new Dictionary<string, byte[]>
                {
                    ["webview/assets/owner-copy.js"] = Encoding.UTF8.GetBytes(ValidOwnerSource)
                })),
            "structured-owner-semantics-ambiguous",
            compatibilityFailure: true);

        ExpectAsarCode(
            () => InspectArchive(BuildStructuredArchive(
                rootSource: "import \"./loader.js\"; import \"./owner.js\";",
                additionalEntries: new Dictionary<string, byte[]>
                {
                    ["webview/assets/loader.js"] = Encoding.UTF8.GetBytes(
                        "import \"./root.js\";")
                })),
            "structured-module-cycle",
            compatibilityFailure: true);
    }

    private static void TestTraversalBounds()
    {
        var unsafeIndex = "<script type=\"module\" src=\"../../escape.js\"></script>";
        ExpectAsarCode(
            () => InspectArchive(BuildStructuredArchive(indexHtml: unsafeIndex)),
            "structured-relative-path",
            compatibilityFailure: true);

        var limits = CodexStructuredInputAsarInspectionLimits.Default with
        {
            MaximumModuleEntries = 1
        };
        ExpectAsarCode(
            () => InspectArchive(BuildStructuredArchive(), limits),
            "structured-module-count",
            compatibilityFailure: true);
    }

    private static void TestImportBoundsAndOwnerShortCircuit()
    {
        var expandedModuleLimit = CodexStructuredInputAsarInspectionLimits.Default with
        {
            MaximumModuleEntries = 256
        };
        var acceptedEntries = CreateImportEntries(127);
        var acceptedRoot = CreateImportSource(acceptedEntries.Keys) + "import \"./owner.js\";";
        var accepted = InspectArchive(
            BuildStructuredArchive(
                rootSource: acceptedRoot,
                additionalEntries: acceptedEntries),
            expandedModuleLimit);
        Ensure(
            accepted.ModuleEntries.Count == 129 && accepted.OwnerEntryPath == OwnerPath,
            "exactly 128 unique imports did not remain accepted");

        var rejectedEntries = CreateImportEntries(128);
        var rejectedRoot = CreateImportSource(rejectedEntries.Keys) + "import \"./owner.js\";";
        ExpectAsarCode(
            () => InspectArchive(
                BuildStructuredArchive(
                    rootSource: rejectedRoot,
                    additionalEntries: rejectedEntries),
                expandedModuleLimit),
            "structured-module-import-count",
            compatibilityFailure: true);

        var duplicates = InspectArchive(BuildStructuredArchive(
            rootSource: string.Concat(
                Enumerable.Repeat("import \"./owner.js\";", 129))));
        Ensure(
            duplicates.ModuleEntries.Count == 2 && duplicates.OwnerEntryPath == OwnerPath,
            "duplicate imports consumed the unique-import bound");

        var ownerImportLimits = CodexStructuredInputAsarInspectionLimits.Default with
        {
            MaximumOwnerImportsPerModule = 128
        };
        var ownerAtImportBound = ValidOwnerSource + "\n" +
            string.Concat(Enumerable.Range(0, 128).Select(index =>
                "import \"./missing-" + index.ToString("D3") + ".js\";"));
        var shortCircuited = InspectArchive(
            BuildStructuredArchive(ownerSource: ownerAtImportBound),
            ownerImportLimits);
        Ensure(
            shortCircuited.ModuleEntries.Count == 2 &&
            shortCircuited.OwnerEntryPath == OwnerPath,
            "an owner module at its independent import bound expanded its dependencies");

        var ownerOverImportBound = ownerAtImportBound +
            "import \"./missing-128.js\";";
        ExpectAsarCode(
            () => InspectArchive(
                BuildStructuredArchive(ownerSource: ownerOverImportBound),
                ownerImportLimits),
            "structured-module-import-count",
            compatibilityFailure: true);
    }

    private static Dictionary<string, byte[]> CreateImportEntries(int count) =>
        Enumerable.Range(0, count).ToDictionary(
            index => "webview/assets/decoy-" + index.ToString("D3") + ".js",
            index => Encoding.UTF8.GetBytes("const value" + index + "=" + index + ";"),
            StringComparer.Ordinal);

    private static string CreateImportSource(IEnumerable<string> entryPaths) =>
        string.Concat(entryPaths.Order(StringComparer.Ordinal).Select(path =>
            "import \"./" + Path.GetFileName(path) + "\";"));

    private static async Task TestProviderVersionAndEpochAsync()
    {
        var first = await CreateProvider(
                windowsPackageVersion: "1.0.0.0",
                asarPackageVersion: "1.0.0")
            .ReadAsync(CancellationToken.None);
        var second = await CreateProvider(
                windowsPackageVersion: "2.0.0.0",
                asarPackageVersion: "2.0.0")
            .ReadAsync(CancellationToken.None);
        Ensure(first.State == StructuredInputCapabilityState.Supported, "the first provider was not supported");
        Ensure(second.State == StructuredInputCapabilityState.Supported, "the second provider was not supported");
        Ensure(
            first.SemanticFingerprint == second.SemanticFingerprint,
            "package-only version drift changed the semantic fingerprint");
        Ensure(first.Epoch != second.Epoch, "package generation drift did not change the capability epoch");
        Ensure(
            first.SupportedInputKinds.SetEquals(new[] { "text", "local_image" }),
            "the provider did not map localImage to local_image");
        Ensure(
            first.MaximumAttachmentCount == 20 &&
            first.MaximumBytesPerFile == 100L * 1024 * 1024 &&
            first.MaximumBytesPerPayload == 500L * 1024 * 1024,
            "the provider did not use normalized Ceasy attachment limits");
    }

    private static async Task TestProviderFailureStatesAsync()
    {
        var noOwnerAssertion = ValidOwnerSource.Replace(
            "m.assertThreadFollowerOwner(r.conversationId)",
            "m.observeThread(r.conversationId)",
            StringComparison.Ordinal);
        var unsupported = await CreateProvider(
                ownerSource: noOwnerAssertion)
            .ReadAsync(CancellationToken.None);
        Ensure(
            unsupported.State == StructuredInputCapabilityState.Unsupported,
            "semantic incompatibility did not stay unsupported");

        var drifted = await CreateProvider(registrationDrift: true)
            .ReadAsync(CancellationToken.None);
        Ensure(
            drifted.State == StructuredInputCapabilityState.Unknown,
            "registration drift did not stay unknown");

        var reparse = await CreateProvider(packageDirectoryReparse: true)
            .ReadAsync(CancellationToken.None);
        Ensure(
            reparse.State == StructuredInputCapabilityState.Unknown,
            "a reparse package directory did not stay unknown");
    }

    private static InstalledCodexStructuredInputCapabilityProvider CreateProvider(
        string windowsPackageVersion = "1.0.0.0",
        string asarPackageVersion = "1.0.0",
        string ownerSource = ValidOwnerSource,
        bool registrationDrift = false,
        bool packageDirectoryReparse = false)
    {
        var platform = new FakeStructuredPackagePlatform(
            windowsPackageVersion,
            BuildStructuredArchive(
                ownerSource: ownerSource,
                packageVersion: asarPackageVersion),
            registrationDrift,
            packageDirectoryReparse);
        var reader = new CodexStructuredInputPackageEvidenceReader(platform);
        return new InstalledCodexStructuredInputCapabilityProvider(
            new AttachmentLimitSettings(),
            reader);
    }

    private static byte[] BuildStructuredArchive(
        string ownerSource = ValidOwnerSource,
        string rootSource = "import \"./owner.js\";",
        string indexHtml = "<script type=\"module\" src=\"./assets/root.js\"></script>",
        string packageVersion = "1.0.0",
        IReadOnlyDictionary<string, byte[]>? additionalEntries = null)
    {
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["webview/index.html"] = Encoding.UTF8.GetBytes(indexHtml),
            [ModuleRootPath] = Encoding.UTF8.GetBytes(rootSource),
            [OwnerPath] = Encoding.UTF8.GetBytes(ownerSource)
        };
        if (additionalEntries is not null)
        {
            foreach (var entry in additionalEntries)
            {
                entries.Add(entry.Key, entry.Value);
            }
        }

        return CodexAsarCapabilityOfflineTests.BuildArchive(
            packageVersion: packageVersion,
            additionalEntries: entries);
    }

    private static CodexStructuredInputAsarSnapshot InspectArchive(
        byte[] archive,
        CodexStructuredInputAsarInspectionLimits? limits = null) =>
        CodexStructuredInputAsarInspector.Inspect(
            new ByteArraySource(archive),
            limits);

    private static void ExpectAsarCode(
        Action action,
        string code,
        bool compatibilityFailure)
    {
        try
        {
            action();
        }
        catch (CodexStructuredInputAsarException exception)
        {
            Ensure(exception.Code == code, "expected " + code + " but received " + exception.Code);
            Ensure(
                exception.IsCompatibilityFailure == compatibilityFailure,
                "the ASAR failure disposition was incorrect");
            return;
        }

        throw new InvalidOperationException("Expected ASAR failure code " + code + ".");
    }

    private static void RunCase(string name, Action test, Action<bool, string> assert)
    {
        try
        {
            test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static async Task RunCaseAsync(
        string name,
        Func<Task> test,
        Action<bool, string> assert)
    {
        try
        {
            await test();
            assert(true, name);
        }
        catch (Exception exception)
        {
            assert(false, name + ": " + exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value));

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private sealed class ByteArraySource(byte[] bytes) : ICodexAsarRandomAccessSource
    {
        public long Length => bytes.LongLength;

        public void ReadExactly(long offset, Span<byte> destination)
        {
            if (offset < 0 || offset > bytes.LongLength - destination.Length)
            {
                throw new EndOfStreamException("The synthetic ASAR source was truncated.");
            }

            bytes.AsSpan(checked((int)offset), destination.Length).CopyTo(destination);
        }
    }

    private sealed class FakeStructuredPackagePlatform : ICodexStructuredInputPackagePlatform
    {
        private const string FamilyName = CodexStructuredInputPackagePolicy.DefaultPackageFamilyName;
        private const string Publisher = CodexStructuredInputPackagePolicy.DefaultPublisher;
        private readonly string _firstFullName;
        private readonly string _secondFullName;
        private readonly byte[] _archive;
        private readonly bool _registrationDrift;
        private readonly bool _packageDirectoryReparse;
        private int _inventoryReads;

        internal FakeStructuredPackagePlatform(
            string windowsPackageVersion,
            byte[] archive,
            bool registrationDrift,
            bool packageDirectoryReparse)
        {
            _firstFullName = FullName(windowsPackageVersion);
            _secondFullName = FullName(IncrementVersion(windowsPackageVersion));
            _archive = archive;
            _registrationDrift = registrationDrift;
            _packageDirectoryReparse = packageDirectoryReparse;
        }

        public IReadOnlyList<CodexPackageFamilyMember> ReadCurrentUserPackageFamilyInventory(
            string packageFamilyName)
        {
            Ensure(packageFamilyName == FamilyName, "the reader requested an unexpected package family");
            _inventoryReads++;
            return
            [
                new CodexPackageFamilyMember(
                    _registrationDrift && _inventoryReads > 1 ? _secondFullName : _firstFullName,
                    0)
            ];
        }

        public CodexAppModelPackageIdentity ReadRegisteredPackageIdentity(string packageFullName) =>
            new(
                packageFullName,
                FamilyName,
                CodexStructuredInputPackagePolicy.DefaultPackageName,
                VersionFromFullName(packageFullName),
                Publisher,
                "2p2nqsd0c76g0",
                string.Empty,
                CodexStructuredInputPackagePolicy.DefaultArchitecture,
                CodexPackageOrigin.DeveloperSigned);

        public string ReadRegisteredPackagePath(string packageFullName) =>
            Path.Combine("C:\\Program Files\\WindowsApps", packageFullName);

        public CodexPathObservation InspectDirectory(string path) =>
            new(
                path,
                path,
                FileAttributes.Directory |
                (_packageDirectoryReparse ? FileAttributes.ReparsePoint : 0),
                VolumeSerialNumber: 7,
                FileId: 11);

        public CodexVerifiedPackageSignatureObservation ReadAndVerifyPackageSignature(
            string path,
            long maximumBytes)
        {
            var signature = Encoding.UTF8.GetBytes("fixture-signature");
            Ensure(signature.LongLength <= maximumBytes, "the signature bound was not forwarded");
            return new CodexVerifiedPackageSignatureObservation(
                new CodexPinnedFileObservation(
                    path,
                    path,
                    FileAttributes.Normal,
                    signature.LongLength,
                    Hash(signature),
                    VolumeSerialNumber: 7,
                    FileId: 12,
                    Contents: null),
                new CodexPackageSignerIdentity(
                    Publisher,
                    Publisher,
                    new string('A', 64),
                    new string('B', 64),
                    new string('C', 40),
                    DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
                    DateTimeOffset.Parse("2030-01-01T00:00:00Z"),
                    DateTimeOffset.Parse("2026-08-15T00:00:00Z")));
        }

        public CodexStructuredInputAsarFileObservation ReadStructuredInputAppAsar(
            string path,
            long maximumBytes,
            CodexStructuredInputAsarInspectionLimits limits)
        {
            Ensure(_archive.LongLength <= maximumBytes, "the ASAR bound was not forwarded");
            return new CodexStructuredInputAsarFileObservation(
                path,
                path,
                FileAttributes.Normal,
                _archive.LongLength,
                DateTimeOffset.Parse("2026-08-15T00:00:00Z"),
                VolumeSerialNumber: 7,
                FileId: 13,
                CodexStructuredInputAsarInspector.Inspect(new ByteArraySource(_archive), limits));
        }

        private static string FullName(string version) =>
            "OpenAI.Codex_" + version + "_x64__2p2nqsd0c76g0";

        private static string VersionFromFullName(string fullName)
        {
            const string prefix = "OpenAI.Codex_";
            var suffix = fullName.IndexOf("_x64__", StringComparison.Ordinal);
            return fullName[prefix.Length..suffix];
        }

        private static string IncrementVersion(string version)
        {
            var values = version.Split('.').Select(int.Parse).ToArray();
            values[^1]++;
            return string.Join('.', values);
        }
    }
}
