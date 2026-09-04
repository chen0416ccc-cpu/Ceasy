import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const maximumPayloadBytes = 4096;
const maximumBufferedObservations = 16;
const maximumLiveProofTurns = 256;
const maximumLogBytes = 512 * 1024;
const verifiedRendererTimeoutMs = 30000;
const protocolIdentifierPattern = /^[A-Za-z0-9_-]{8,80}$/;
const helloPropertyNames = Object.freeze([
  "kind",
  "seq",
  "protocol",
  "hookVersion",
  "contractId",
  "source",
  "pageProtocol",
  "bridgePresent"
]);
const expectedHello = Object.freeze({
  protocol: 1,
  hookVersion: "cdp-poc-1",
  contractId: "codex-cdp-observation-v1",
  source: "cdp-main-world",
  pageProtocol: "app",
  bridgePresent: true
});
const allowedKinds = new Set([
  "hello",
  "snapshot",
  "threadState",
  "turn",
  "item",
  "streamError",
  "appServerConnection",
  "notificationShape"
]);
const allowedThreadStatuses = new Set([
  "notLoaded",
  "idle",
  "systemError",
  "active",
  "unknown"
]);
const allowedTurnStatuses = new Set([
  "completed",
  "interrupted",
  "failed",
  "inProgress",
  "unknown"
]);
const allowedPhases = new Set(["started", "completed"]);
const allowedErrorKinds = new Set([
  "contextWindowExceeded",
  "sessionBudgetExceeded",
  "usageLimitExceeded",
  "serverOverloaded",
  "cyberPolicy",
  "httpConnectionFailed",
  "responseStreamConnectionFailed",
  "internalServerError",
  "unauthorized",
  "badRequest",
  "threadRollbackFailed",
  "sandboxError",
  "responseStreamDisconnected",
  "responseTooManyFailedAttempts",
  "activeTurnNotSteerable",
  "other"
]);
const allowedItemTypes = new Set([
  "userMessage",
  "hookPrompt",
  "agentMessage",
  "plan",
  "reasoning",
  "commandExecution",
  "fileChange",
  "mcpToolCall",
  "dynamicToolCall",
  "collabAgentToolCall",
  "subAgentActivity",
  "webSearch",
  "imageView",
  "sleep",
  "imageGeneration",
  "enteredReviewMode",
  "exitedReviewMode",
  "contextCompaction",
  "unknown"
]);
const liveWorkItemTypes = new Set([
  "reasoning",
  "commandExecution",
  "fileChange",
  "mcpToolCall",
  "dynamicToolCall",
  "collabAgentToolCall",
  "webSearch",
  "imageGeneration"
]);
const allowedConnectionStates = new Set([
  "connecting",
  "connected",
  "reconnecting",
  "disconnected",
  "closed",
  "failed",
  "unknown"
]);
const allowedConnectionTransports = new Set([
  "local",
  "remote",
  "stdio",
  "websocket",
  "ipc",
  "unknown"
]);
const allowedConnectionProgress = new Set([
  "starting",
  "connecting",
  "connected",
  "reconnecting",
  "ready",
  "disconnected",
  "failed",
  "unknown"
]);
const allowedNotificationEnvelopes = new Set([
  "top",
  "message",
  "request",
  "notification",
  "payload",
  "unknown"
]);

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === "--self-test") {
    return { selfTest: true };
  }
  const result = {
    selfTest: false,
    port: null,
    hook: null,
    log: null,
    durationSeconds: 600
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--port") {
      result.port = Number(argv[++index]);
    } else if (argument === "--hook") {
      result.hook = argv[++index] ?? null;
    } else if (argument === "--log") {
      result.log = argv[++index] ?? null;
    } else if (argument === "--duration-seconds") {
      result.durationSeconds = Number(argv[++index]);
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  if (!Number.isInteger(result.port) || result.port < 1024 || result.port > 65535 ||
      typeof result.hook !== "string" || !path.isAbsolute(result.hook) ||
      typeof result.log !== "string" || !path.isAbsolute(result.log) ||
      !Number.isInteger(result.durationSeconds) ||
      result.durationSeconds < 10 || result.durationSeconds > 3600) {
    throw new Error(
      "Usage: node codex-guardian-cdp-observer-poc.mjs --port <port> " +
      "--hook <absolute-js> --log <absolute-jsonl> [--duration-seconds <10-3600>] " +
      "or --self-test"
    );
  }
  return result;
}

function maskIdentifier(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 80) {
    return null;
  }
  return crypto.createHash("sha256").update(value, "utf8").digest("hex").slice(0, 12);
}

function maskProtocolIdentifier(value) {
  return typeof value === "string" && protocolIdentifierPattern.test(value)
    ? maskIdentifier(value)
    : null;
}

function readAllowedValue(value, allowedValues, fallback) {
  return typeof value === "string" && allowedValues.has(value) ? value : fallback;
}

function readNotificationEnvelope(value) {
  return readAllowedValue(value, allowedNotificationEnvelopes, "unknown");
}

function readProtocolReference(value, required) {
  if (value == null && !required) {
    return null;
  }
  return maskProtocolIdentifier(value);
}

function readHttpStatusCode(value) {
  return Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;
}

function readReconnectProgress(attempt, maximum) {
  if (attempt == null && maximum == null) {
    return { reconnectAttempt: null, reconnectMaxAttempts: null };
  }
  if (!Number.isInteger(attempt) || !Number.isInteger(maximum) ||
      attempt < 0 || maximum < 1 || attempt > maximum || maximum > 100) {
    return { reconnectAttempt: null, reconnectMaxAttempts: null };
  }
  return { reconnectAttempt: attempt, reconnectMaxAttempts: maximum };
}

function hasExactProperties(value, expectedNames) {
  const names = Object.keys(value);
  return names.length === expectedNames.length &&
    names.every((name) => expectedNames.includes(name));
}

function sanitizeObservation(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value) ||
      !allowedKinds.has(value.kind) || !Number.isSafeInteger(value.seq) || value.seq < 1) {
    return null;
  }
  const base = { kind: value.kind, seq: value.seq };
  if (value.kind === "hello") {
    if (!hasExactProperties(value, helloPropertyNames) ||
        value.protocol !== expectedHello.protocol ||
        value.hookVersion !== expectedHello.hookVersion ||
        value.contractId !== expectedHello.contractId ||
        value.source !== expectedHello.source ||
        value.pageProtocol !== expectedHello.pageProtocol ||
        value.bridgePresent !== expectedHello.bridgePresent) {
      return null;
    }
    return { ...base, ...expectedHello };
  }
  if (value.kind === "snapshot") {
    const taskRef = readProtocolReference(value.threadId, false);
    if (value.threadId != null && taskRef == null ||
        typeof value.routeKnown !== "boolean" ||
        typeof value.composerKnown !== "boolean" ||
        typeof value.editorPresent !== "boolean" ||
        value.routeKnown !== (taskRef != null) ||
        value.editorPresent && !value.composerKnown) {
      return null;
    }
    const focusKnown = typeof value.composerFocused === "boolean";
    const draftKnown = typeof value.hasDraft === "boolean";
    if (value.editorPresent && (!focusKnown || !draftKnown) ||
        !value.editorPresent && (value.composerFocused != null || value.hasDraft != null)) {
      return null;
    }
    return {
      ...base,
      taskRef,
      routeKnown: value.routeKnown,
      composerKnown: value.composerKnown,
      editorPresent: value.editorPresent,
      composerFocused: value.editorPresent ? value.composerFocused : null,
      hasDraft: value.editorPresent ? value.hasDraft : null
    };
  }
  if (value.kind === "notificationShape") {
    if (typeof value.topMethod !== "boolean" ||
        typeof value.messageMethod !== "boolean" ||
        typeof value.requestMethod !== "boolean" ||
        typeof value.notificationMethod !== "boolean" ||
        typeof value.payloadMethod !== "boolean") {
      return null;
    }
    return {
      ...base,
      topMethod: value.topMethod,
      messageMethod: value.messageMethod,
      requestMethod: value.requestMethod,
      notificationMethod: value.notificationMethod,
      payloadMethod: value.payloadMethod,
      recognizedEnvelope: readNotificationEnvelope(value.recognizedEnvelope)
    };
  }
  if (value.kind === "threadState") {
    const taskRef = readProtocolReference(value.threadId, true);
    if (taskRef == null) {
      return null;
    }
    return {
      ...base,
      taskRef,
      status: readAllowedValue(value.status, allowedThreadStatuses, "unknown"),
      notificationEnvelope: readNotificationEnvelope(value.notificationEnvelope)
    };
  }
  if (value.kind === "turn") {
    const taskRef = readProtocolReference(value.threadId, true);
    const turnRef = readProtocolReference(value.turnId, true);
    if (taskRef == null || turnRef == null) {
      return null;
    }
    return {
      ...base,
      taskRef,
      turnRef,
      phase: readAllowedValue(value.phase, allowedPhases, "unknown"),
      status: readAllowedValue(value.status, allowedTurnStatuses, "unknown"),
      errorKind: readAllowedValue(value.errorKind, allowedErrorKinds, "other"),
      httpStatusCode: readHttpStatusCode(value.httpStatusCode),
      willRetry: value.willRetry === true,
      notificationEnvelope: readNotificationEnvelope(value.notificationEnvelope)
    };
  }
  if (value.kind === "item") {
    const taskRef = readProtocolReference(value.threadId, true);
    const turnRef = readProtocolReference(value.turnId, true);
    if (taskRef == null || turnRef == null) {
      return null;
    }
    return {
      ...base,
      taskRef,
      turnRef,
      phase: readAllowedValue(value.phase, allowedPhases, "unknown"),
      itemType: readAllowedValue(value.itemType, allowedItemTypes, "unknown"),
      notificationEnvelope: readNotificationEnvelope(value.notificationEnvelope)
    };
  }
  if (value.kind === "streamError") {
    const taskRef = readProtocolReference(value.threadId, true);
    const turnRef = readProtocolReference(value.turnId, true);
    if (taskRef == null || turnRef == null) {
      return null;
    }
    const progress = readReconnectProgress(
      value.reconnectAttempt,
      value.reconnectMaxAttempts
    );
    return {
      ...base,
      taskRef,
      turnRef,
      willRetry: value.willRetry === true,
      errorKind: readAllowedValue(value.errorKind, allowedErrorKinds, "other"),
      httpStatusCode: readHttpStatusCode(value.httpStatusCode),
      reconnectAttempt: progress.reconnectAttempt,
      reconnectMaxAttempts: progress.reconnectMaxAttempts,
      notificationEnvelope: readNotificationEnvelope(value.notificationEnvelope)
    };
  }
  return {
    ...base,
    state: readAllowedValue(value.state, allowedConnectionStates, "unknown"),
    transport: readAllowedValue(value.transport, allowedConnectionTransports, "unknown"),
    progress: readAllowedValue(value.progress, allowedConnectionProgress, "unknown")
  };
}

function regularFileSize(filePath) {
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`refusing non-regular observation log: ${filePath}`);
    }
    return stat.size;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function appendBoundedLog(logPath, record, maximumBytes = maximumLogBytes) {
  if (!Number.isInteger(maximumBytes) || maximumBytes < 128) {
    throw new Error("the observation log capacity is invalid");
  }
  const line = `${JSON.stringify(record)}\n`;
  const lineBytes = Buffer.byteLength(line, "utf8");
  if (lineBytes > maximumBytes) {
    throw new Error("one sanitized observation exceeds the log capacity");
  }
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  const previousPath = `${logPath}.previous`;
  const previousSize = regularFileSize(previousPath);
  if (previousSize != null && previousSize > maximumBytes) {
    fs.rmSync(previousPath, { force: true });
  }
  const currentSize = regularFileSize(logPath);
  if (currentSize != null && currentSize + lineBytes > maximumBytes) {
    fs.rmSync(previousPath, { force: true });
    if (currentSize <= maximumBytes) {
      fs.renameSync(logPath, previousPath);
    } else {
      fs.rmSync(logPath, { force: true });
    }
  }
  fs.appendFileSync(logPath, line, { encoding: "utf8", flag: "a" });
  if ((regularFileSize(logPath) ?? 0) > maximumBytes ||
      (regularFileSize(previousPath) ?? 0) > maximumBytes) {
    throw new Error("the observation log exceeded its two-generation capacity");
  }
}

function classifyObserverFailure(error) {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("loopback CDP endpoint")) {
    return "endpoint-unavailable";
  }
  if (message.includes("WebSocket open")) {
    return "websocket-open-failed";
  }
  if (message.includes("WebSocket closed") || message.includes("WebSocket reported")) {
    return "websocket-runtime-failed";
  }
  if (message.startsWith("CDP target injection failed")) {
    return "target-injection-failed";
  }
  if (message.startsWith("CDP command timed out")) {
    return "cdp-command-timeout";
  }
  if (/^Target\.|^Runtime\.|^Page\./.test(message) && message.includes(" failed:")) {
    return "cdp-command-rejected";
  }
  if (message.includes("zero Codex app renderers")) {
    return "renderer-handshake-missing";
  }
  if (message.includes("hello") || message.includes("sequence gap") ||
      message.includes("execution context")) {
    return "renderer-handshake-invalid";
  }
  if (message.includes("observation") || message.includes("payload")) {
    return "renderer-observation-invalid";
  }
  if (message.includes("live proof is incomplete")) {
    return "live-proof-incomplete";
  }
  if (message.includes("duplicate CDP session")) {
    return "duplicate-session-cleanup-failed";
  }
  return "observer-failure-unknown";
}

function isCandidateTargetInfo(targetInfo) {
  return targetInfo?.type === "page" &&
    typeof targetInfo.url === "string" &&
    targetInfo.url.startsWith("app://");
}

function createTargetRegistry() {
  const targets = new Map();
  const provisionalSessions = new Map();
  const installedSessions = new Map();

  function reserve(targetInfo) {
    const targetId = targetInfo?.targetId;
    const type = targetInfo?.type;
    if (typeof targetId !== "string" || targetId.length === 0 ||
        !isCandidateTargetInfo(targetInfo)) {
      return null;
    }
    let state = targets.get(targetId);
    if (state == null) {
      state = {
        targetId,
        type,
        sessionId: null,
        status: "reserved",
        installPromise: null,
        manualAttachPromise: null,
        bufferedObservations: [],
        helloSeen: false,
        snapshotSeen: false,
        verified: false,
        lastSequence: 0,
        generation: 0,
        observationContextId: null
      };
      targets.set(targetId, state);
    }
    return state;
  }

  function claim(targetInfo, sessionId) {
    const state = reserve(targetInfo);
    if (state == null || typeof sessionId !== "string" || sessionId.length === 0) {
      return { accepted: false, duplicate: false, state: null };
    }
    if (state.sessionId != null) {
      return {
        accepted: false,
        duplicate: state.sessionId !== sessionId,
        state
      };
    }
    state.sessionId = sessionId;
    state.status = "installing";
    provisionalSessions.set(sessionId, state);
    return { accepted: true, duplicate: false, state };
  }

  function markInstalled(state) {
    if (state?.status !== "installing" || state.sessionId == null) {
      throw new Error("cannot install an unclaimed target session");
    }
    provisionalSessions.delete(state.sessionId);
    installedSessions.set(state.sessionId, state);
    state.status = "installed";
  }

  function markFailed(state) {
    if (state?.sessionId != null) {
      provisionalSessions.delete(state.sessionId);
      installedSessions.delete(state.sessionId);
    }
    if (state != null) {
      state.status = "failed";
      state.verified = false;
    }
  }

  function removeState(state, status) {
    if (state == null) {
      return;
    }
    if (state.sessionId != null) {
      provisionalSessions.delete(state.sessionId);
      installedSessions.delete(state.sessionId);
    }
    if (targets.get(state.targetId) === state) {
      targets.delete(state.targetId);
    }
    state.status = status;
    state.verified = false;
  }

  function getBySession(sessionId) {
    return installedSessions.get(sessionId) ?? provisionalSessions.get(sessionId) ?? null;
  }

  return {
    reserve,
    claim,
    markInstalled,
    markFailed,
    removeBySession: (sessionId, status = "detached") => {
      const state = getBySession(sessionId);
      removeState(state, status);
      return state;
    },
    removeByTarget: (targetId, status = "destroyed") => {
      const state = targets.get(targetId) ?? null;
      removeState(state, status);
      return state;
    },
    getBySession,
    getByTarget: targetId => targets.get(targetId) ?? null,
    states: () => Array.from(targets.values()),
    installedCount: () => installedSessions.size,
    provisionalCount: () => provisionalSessions.size
  };
}

function applyObservationToState(state, rawObservation) {
  const observation = sanitizeObservation(rawObservation);
  if (rawObservation?.kind === "hello" && rawObservation?.seq === 1) {
    if (observation == null) {
      throw new Error("renderer hello fingerprint mismatch");
    }
    state.generation += 1;
    state.lastSequence = 1;
    state.helloSeen = true;
    state.snapshotSeen = false;
    state.verified = false;
    return observation;
  }
  if (!state.helloSeen || state.lastSequence === 0) {
    throw new Error("renderer observation arrived before exact hello seq=1");
  }
  if (!Number.isSafeInteger(rawObservation?.seq) ||
      rawObservation.seq !== state.lastSequence + 1) {
    throw new Error(
      `renderer observation sequence gap: expected ${state.lastSequence + 1}`
    );
  }
  if (observation == null) {
    throw new Error("renderer emitted an invalid observation payload");
  }
  state.lastSequence = rawObservation.seq;
  if (observation.kind === "snapshot") {
    state.snapshotSeen = true;
    state.verified = state.status === "installed" && state.helloSeen;
  }
  return observation;
}

function countVerifiedRenderers(registry) {
  return registry.states().filter(state => state.status === "installed" && state.verified).length;
}

function assertVerifiedRenderer(registry) {
  const states = registry.states();
  const count = countVerifiedRenderers(registry);
  if (count === 0 || count !== states.length) {
    throw new Error(
      "not every active Codex app renderer completed the hello/snapshot handshake"
    );
  }
  return count;
}

function createLiveProofTracker() {
  const evidenceByTurn = new Map();
  let recognizedTopEnvelope = false;
  let provenTurnKey = null;

  function getTurnKey(observation) {
    if (typeof observation.taskRef !== "string" ||
        typeof observation.turnRef !== "string") {
      return null;
    }
    return `${observation.taskRef}:${observation.turnRef}`;
  }

  function getOrCreateEvidence(turnKey) {
    let evidence = evidenceByTurn.get(turnKey);
    if (evidence != null) {
      return evidence;
    }
    if (evidenceByTurn.size >= maximumLiveProofTurns) {
      throw new Error("live proof is incomplete: too many correlated turns were observed");
    }
    evidence = { phasesByType: new Map(), successfulCompletion: false };
    evidenceByTurn.set(turnKey, evidence);
    return evidence;
  }

  function findProvenTurn() {
    if (!recognizedTopEnvelope) {
      return null;
    }
    for (const [turnKey, evidence] of evidenceByTurn) {
      const completedWorkItem = [...evidence.phasesByType.values()].some(
        phases => phases.has("started") && phases.has("completed")
      );
      if (evidence.successfulCompletion && completedWorkItem) {
        return turnKey;
      }
    }
    return null;
  }

  return {
    observe(observation) {
      if (observation.kind === "notificationShape" &&
          observation.recognizedEnvelope === "top") {
        recognizedTopEnvelope = true;
      }
      if (observation.notificationEnvelope === "top") {
        recognizedTopEnvelope = true;
      }
      const turnKey = getTurnKey(observation);
      if (turnKey != null && observation.kind === "item" &&
          liveWorkItemTypes.has(observation.itemType) &&
          observation.notificationEnvelope === "top") {
        const evidence = getOrCreateEvidence(turnKey);
        let phases = evidence.phasesByType.get(observation.itemType);
        if (phases == null) {
          phases = new Set();
          evidence.phasesByType.set(observation.itemType, phases);
        }
        phases.add(observation.phase);
      }
      if (turnKey != null && observation.kind === "turn" &&
          observation.phase === "completed" &&
          observation.status === "completed" &&
          observation.notificationEnvelope === "top") {
        getOrCreateEvidence(turnKey).successfulCompletion = true;
      }
      provenTurnKey ??= findProvenTurn();
      return provenTurnKey;
    },
    get provenTurnKey() {
      return provenTurnKey;
    }
  };
}

async function waitForVersion(port) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
        signal: AbortSignal.timeout(1000)
      });
      if (response.ok) {
        const value = await response.json();
        if (typeof value.webSocketDebuggerUrl === "string" &&
            value.webSocketDebuggerUrl.startsWith(`ws://127.0.0.1:${port}/`)) {
          return value;
        }
      }
    } catch {
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error("the loopback CDP endpoint did not become ready within 30 seconds");
}

async function runObserver(args) {
  const hookSource = fs.readFileSync(args.hook, "utf8");
  if (!hookSource.includes("codex-guardian-cdp-observation-poc-v1") ||
      hookSource.includes("messageText") ||
      hookSource.includes("params.item?.content") ||
      hookSource.includes("params.turn?.items") ||
      hookSource.toLowerCase().includes("reasoningtext") ||
      hookSource.toLowerCase().includes("tooloutput")) {
    throw new Error("the CDP hook source is missing its marker or accesses forbidden content");
  }

  const version = await waitForVersion(args.port);
  const socket = new WebSocket(version.webSocketDebuggerUrl);
  const pending = new Map();
  const registry = createTargetRegistry();
  let nextId = 1;
  let observationCount = 0;
  const liveProofTracker = createLiveProofTracker();
  let liveProofEnabled = false;
  let resolveLiveProof;
  const liveProofPromise = new Promise(resolve => {
    resolveLiveProof = resolve;
  });
  let fatalError = null;
  let rejectFatal;
  let shuttingDown = false;
  const fatalPromise = new Promise((resolve, reject) => {
    rejectFatal = reject;
  });
  fatalPromise.catch(() => {});

  function markFatal(error) {
    if (fatalError != null || shuttingDown) {
      return;
    }
    fatalError = error instanceof Error ? error : new Error(String(error));
    rejectFatal(fatalError);
  }

  function rejectPending(error) {
    for (const command of pending.values()) {
      command.reject(error);
    }
    pending.clear();
  }

  function send(method, params = {}, sessionId = null) {
    if (fatalError != null) {
      return Promise.reject(fatalError);
    }
    const id = nextId++;
    const message = { id, method, params };
    if (sessionId != null) {
      message.sessionId = sessionId;
    }
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, method });
      socket.send(JSON.stringify(message));
      setTimeout(() => {
        const current = pending.get(id);
        if (current != null) {
          pending.delete(id);
          reject(new Error(`CDP command timed out: ${method}`));
        }
      }, 10000).unref();
    });
  }

  function persistObservation(observation, state) {
    observationCount += 1;
    if (liveProofEnabled && liveProofTracker.observe(observation) != null) {
      resolveLiveProof();
    }
    const record = {
      schema: 1,
      timestamp: new Date().toISOString(),
      targetRef: maskIdentifier(state.targetId),
      sessionRef: maskIdentifier(state.sessionId),
      ...observation
    };
    appendBoundedLog(args.log, record);
    process.stdout.write(`[CDP] ${JSON.stringify(record)}\n`);
  }

  function processObservation(state, rawObservation, executionContextId) {
    try {
      if (!Number.isInteger(executionContextId) || executionContextId < 1) {
        throw new Error("renderer observation did not originate from a valid execution context");
      }
      if (rawObservation?.kind === "hello" && rawObservation?.seq === 1) {
        state.observationContextId = executionContextId;
      } else if (state.observationContextId !== executionContextId) {
        throw new Error("renderer observation changed execution context without a new hello");
      }
      const observation = applyObservationToState(state, rawObservation);
      persistObservation(observation, state);
    } catch (error) {
      markFatal(error);
    }
  }

  function handleObservationPayload(payload, sessionId, executionContextId) {
    const state = registry.getBySession(sessionId);
    if (state == null) {
      return;
    }
    if (typeof payload !== "string" || Buffer.byteLength(payload, "utf8") > maximumPayloadBytes) {
      markFatal(new Error("renderer observation exceeded the payload limit"));
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(payload);
    } catch {
      markFatal(new Error("renderer observation was not valid JSON"));
      return;
    }
    if (state.status === "installing") {
      if (state.bufferedObservations.length >= maximumBufferedObservations) {
        markFatal(new Error("renderer emitted too many observations before installation completed"));
        return;
      }
      state.bufferedObservations.push({ parsed, executionContextId });
      return;
    }
    processObservation(state, parsed, executionContextId);
  }

  async function installClaimedSession(state) {
    try {
      await send("Runtime.enable", {}, state.sessionId);
      await send("Page.enable", {}, state.sessionId);
      await send("Runtime.addBinding", { name: "__codexGuardianCdpEmit" }, state.sessionId);
      await send(
        "Page.addScriptToEvaluateOnNewDocument",
        { source: hookSource },
        state.sessionId
      );
      const evaluation = await send("Runtime.evaluate", {
        expression: hookSource,
        awaitPromise: false,
        returnByValue: false,
        userGesture: false
      }, state.sessionId);
      if (evaluation.exceptionDetails != null) {
        throw new Error("the renderer rejected the observation hook");
      }
      registry.markInstalled(state);
      const buffered = state.bufferedObservations.splice(0);
      for (const observation of buffered) {
        processObservation(state, observation.parsed, observation.executionContextId);
        if (fatalError != null) {
          throw fatalError;
        }
      }
    } catch (error) {
      registry.markFailed(state);
      const wrapped = new Error(`CDP target injection failed: ${error.message}`);
      throw wrapped;
    }
  }

  async function claimAndInstall(targetInfo, sessionId) {
    const claim = registry.claim(targetInfo, sessionId);
    if (claim.state == null) {
      throw new Error("CDP supplied an invalid target attachment");
    }
    if (claim.duplicate) {
      try {
        await send("Target.detachFromTarget", { sessionId });
      } catch (error) {
        const wrapped = new Error(`duplicate CDP session detach failed: ${error.message}`);
        markFatal(wrapped);
        throw wrapped;
      }
      return claim.state.installPromise;
    }
    if (!claim.accepted) {
      return claim.state.installPromise;
    }
    claim.state.installPromise = installClaimedSession(claim.state);
    claim.state.installPromise.catch(() => {});
    return claim.state.installPromise;
  }

  async function ensureTargetAttached(targetInfo) {
    const state = registry.reserve(targetInfo);
    if (state == null) {
      return null;
    }
    if (state.installPromise != null) {
      return state.installPromise;
    }
    if (state.manualAttachPromise != null) {
      return state.manualAttachPromise;
    }
    state.manualAttachPromise = (async () => {
      try {
        const attached = await send("Target.attachToTarget", {
          targetId: state.targetId,
          flatten: true
        });
        return await claimAndInstall(targetInfo, attached.sessionId);
      } catch (error) {
        if (state.installPromise != null &&
            String(error.message).toLowerCase().includes("already attached")) {
          return state.installPromise;
        }
        throw error;
      }
    })();
    state.manualAttachPromise.catch(() => {});
    return state.manualAttachPromise;
  }

  async function delayOrFatal(milliseconds) {
    await Promise.race([
      new Promise(resolve => setTimeout(resolve, milliseconds)),
      fatalPromise
    ]);
  }

  async function waitForVerifiedRenderer() {
    const deadline = Date.now() + verifiedRendererTimeoutMs;
    while (Date.now() < deadline) {
      if (fatalError != null) {
        throw fatalError;
      }
      if (countVerifiedRenderers(registry) > 0) {
        return;
      }
      await delayOrFatal(50);
    }
    assertVerifiedRenderer(registry);
  }

  async function waitForLiveProof() {
    let timeoutId;
    const timeoutPromise = new Promise(resolve => {
      timeoutId = setTimeout(() => resolve("timeout"), args.durationSeconds * 1000);
    });
    try {
      return await Promise.race([
        liveProofPromise.then(() => "proof"),
        timeoutPromise,
        fatalPromise
      ]);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("CDP WebSocket open timed out")), 10000);
    socket.addEventListener("open", () => {
      clearTimeout(timeout);
      resolve();
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timeout);
      reject(new Error("CDP WebSocket failed to open"));
    }, { once: true });
  });

  socket.addEventListener("error", () => {
    const error = new Error("CDP WebSocket reported a runtime error");
    rejectPending(error);
    markFatal(error);
  });
  socket.addEventListener("close", () => {
    if (!shuttingDown) {
      const error = new Error("CDP WebSocket closed before observation completed");
      rejectPending(error);
      markFatal(error);
    }
  });
  socket.addEventListener("message", event => {
    let message;
    try {
      message = JSON.parse(String(event.data));
    } catch {
      markFatal(new Error("CDP emitted an invalid protocol message"));
      return;
    }
    if (Number.isInteger(message.id)) {
      const command = pending.get(message.id);
      if (command == null) {
        return;
      }
      pending.delete(message.id);
      if (message.error != null) {
        command.reject(new Error(`${command.method} failed: ${message.error.message}`));
      } else {
        command.resolve(message.result ?? {});
      }
      return;
    }
    if (message.method === "Target.attachedToTarget") {
      const targetInfo = message.params?.targetInfo;
      const sessionId = message.params?.sessionId;
      if (typeof sessionId === "string") {
        if (isCandidateTargetInfo(targetInfo)) {
          claimAndInstall(targetInfo, sessionId).catch(() => {});
        } else {
          send("Target.detachFromTarget", { sessionId }).catch(() => {});
        }
      }
      return;
    }
    if (message.method === "Target.targetCreated" ||
        message.method === "Target.targetInfoChanged") {
      const targetInfo = message.params?.targetInfo;
      if (isCandidateTargetInfo(targetInfo) &&
          registry.getByTarget(targetInfo.targetId) == null) {
        ensureTargetAttached(targetInfo).catch(error => markFatal(error));
      }
      return;
    }
    if (message.method === "Target.detachedFromTarget") {
      const sessionId = message.params?.sessionId;
      registry.removeBySession(sessionId);
      return;
    }
    if (message.method === "Target.targetDestroyed") {
      registry.removeByTarget(message.params?.targetId);
      return;
    }
    if (message.method === "Runtime.bindingCalled" &&
        message.params?.name === "__codexGuardianCdpEmit" &&
        typeof message.sessionId === "string") {
      handleObservationPayload(
        message.params.payload,
        message.sessionId,
        message.params.executionContextId
      );
    }
  });

  try {
    await send("Target.setDiscoverTargets", { discover: true });
    const targets = await send("Target.getTargets");
    const candidateTargets = (targets.targetInfos ?? []).filter(isCandidateTargetInfo);
    const initialInstallations = [];
    for (const target of candidateTargets) {
      initialInstallations.push(ensureTargetAttached(target));
    }
    await Promise.allSettled(initialInstallations);
    await waitForVerifiedRenderer();
    const readyRenderers = assertVerifiedRenderer(registry);
    liveProofEnabled = true;
    process.stdout.write(
      `[CDP] OBSERVER_READY port=${args.port} verifiedRenderers=${readyRenderers} ` +
      `log=${args.log}\n`
    );
    const proofResult = await waitForLiveProof();
    const completedRenderers = assertVerifiedRenderer(registry);
    if (fatalError != null) {
      throw fatalError;
    }
    if (proofResult !== "proof" || liveProofTracker.provenTurnKey == null) {
      throw new Error(
        "live proof is incomplete: no successful turn with a correlated reasoning/tool lifecycle was observed"
      );
    }
    process.stdout.write(
      `[CDP] OBSERVER_COMPLETE observations=${observationCount} ` +
      `verifiedRenderers=${completedRenderers}\n`
    );
  } finally {
    shuttingDown = true;
    rejectPending(new Error("CDP observer is shutting down"));
    socket.close();
  }
}

async function runSelfTests() {
  const exactHello = { kind: "hello", seq: 1, ...expectedHello };
  assert.deepEqual(sanitizeObservation(exactHello), exactHello);
  assert.equal(
    sanitizeObservation({ ...exactHello, contractId: "wrong-contract" }),
    null
  );
  assert.equal(
    sanitizeObservation({
      kind: "hello",
      seq: 1,
      protocol: 1,
      hookVersion: "cdp-poc-1",
      packageVersion: "26.730.8199.0",
      appBuild: "26.730.61639",
      source: "cdp-main-world",
      pageProtocol: "app",
      bridgePresent: true
    }),
    null
  );
  assert.equal(
    sanitizeObservation({
      ...exactHello,
      packageVersion: "26.730.8199.0",
      appBuild: "26.730.61639"
    }),
    null
  );
  const secret = "sk-secret-value-that-must-not-survive";
  const item = sanitizeObservation({
    kind: "item",
    seq: 3,
    threadId: "12345678-1234-1234-1234-123456789012",
    turnId: "87654321-4321-4321-4321-210987654321",
    phase: secret,
    itemType: secret
  });
  assert.equal(item.phase, "unknown");
  assert.equal(item.itemType, "unknown");
  assert.equal(JSON.stringify(item).includes(secret), false);
  const connection = sanitizeObservation({
    kind: "appServerConnection",
    seq: 4,
    state: secret,
    transport: secret,
    progress: secret
  });
  assert.deepEqual(
    { state: connection.state, transport: connection.transport, progress: connection.progress },
    { state: "unknown", transport: "unknown", progress: "unknown" }
  );
  const unknownComposer = sanitizeObservation({
    kind: "snapshot",
    seq: 2,
    threadId: null,
    routeKnown: false,
    composerKnown: false,
    editorPresent: false,
    composerFocused: null,
    hasDraft: null
  });
  assert.equal(unknownComposer.composerFocused, null);
  assert.equal(unknownComposer.hasDraft, null);
  const notificationShape = sanitizeObservation({
    kind: "notificationShape",
    seq: 5,
    topMethod: false,
    messageMethod: true,
    requestMethod: false,
    notificationMethod: false,
    payloadMethod: false,
    recognizedEnvelope: "message"
  });
  assert.equal(notificationShape.recognizedEnvelope, "message");
  process.stdout.write("[CDP] SELF_TEST_PASS sanitizer\n");

  const registry = createTargetRegistry();
  const target = { targetId: "target-0001", type: "page", url: "app://-/local/test" };
  assert.equal(
    registry.reserve({ targetId: "external-0001", type: "page", url: "https://example.invalid" }),
    null
  );
  const firstClaim = registry.claim(target, "session-0001");
  const sameSessionClaim = registry.claim(target, "session-0001");
  const duplicateClaim = registry.claim(target, "session-0002");
  assert.equal(firstClaim.accepted, true);
  assert.equal(firstClaim.duplicate, false);
  assert.equal(sameSessionClaim.accepted, false);
  assert.equal(sameSessionClaim.duplicate, false);
  assert.equal(duplicateClaim.accepted, false);
  assert.equal(duplicateClaim.duplicate, true);
  assert.equal(registry.getByTarget(target.targetId), firstClaim.state);
  process.stdout.write("[CDP] SELF_TEST_PASS single-attachment-owner\n");
  assert.equal(registry.states().length, 1);
  assert.equal(registry.provisionalCount(), 1);
  registry.markInstalled(firstClaim.state);
  assert.equal(registry.installedCount(), 1);
  assert.equal(registry.provisionalCount(), 0);
  process.stdout.write("[CDP] SELF_TEST_PASS target-dedupe\n");

  const helloRecord = applyObservationToState(firstClaim.state, exactHello);
  assert.equal(helloRecord.kind, "hello");
  const snapshotRecord = applyObservationToState(firstClaim.state, {
    kind: "snapshot",
    seq: 2,
    threadId: "12345678-1234-1234-1234-123456789012",
    routeKnown: true,
    composerKnown: true,
    editorPresent: true,
    composerFocused: false,
    hasDraft: true
  });
  assert.equal(snapshotRecord.kind, "snapshot");
  assert.equal(firstClaim.state.verified, true);
  assert.throws(
    () => applyObservationToState(firstClaim.state, {
      kind: "threadState",
      seq: 4,
      threadId: "12345678-1234-1234-1234-123456789012",
      status: "active"
    }),
    /sequence gap/
  );
  process.stdout.write("[CDP] SELF_TEST_PASS sequence-health\n");

  const zeroHelloRegistry = createTargetRegistry();
  const zeroHelloClaim = zeroHelloRegistry.claim(
    { targetId: "target-0002", type: "page", url: "app://-/local/test" },
    "session-0003"
  );
  zeroHelloRegistry.markInstalled(zeroHelloClaim.state);
  assert.throws(() => assertVerifiedRenderer(zeroHelloRegistry), /not every active/);
  process.stdout.write("[CDP] SELF_TEST_PASS zero-hello-health\n");

  const taskA = "111111111111";
  const taskB = "222222222222";
  const turnA = "aaaaaaaaaaaa";
  const turnB = "bbbbbbbbbbbb";
  const crossTurnProof = createLiveProofTracker();
  assert.equal(crossTurnProof.observe({
    kind: "notificationShape", recognizedEnvelope: "top"
  }), null);
  assert.equal(crossTurnProof.observe({
    kind: "item", taskRef: taskA, turnRef: turnA,
    phase: "started", itemType: "commandExecution", notificationEnvelope: "top"
  }), null);
  assert.equal(crossTurnProof.observe({
    kind: "item", taskRef: taskA, turnRef: turnA,
    phase: "completed", itemType: "commandExecution", notificationEnvelope: "top"
  }), null);
  assert.equal(crossTurnProof.observe({
    kind: "turn", taskRef: taskA, turnRef: turnA,
    phase: "completed", status: "failed", notificationEnvelope: "top"
  }), null);
  assert.equal(crossTurnProof.observe({
    kind: "turn", taskRef: taskB, turnRef: turnA,
    phase: "completed", status: "completed", notificationEnvelope: "top"
  }), null);
  assert.equal(crossTurnProof.observe({
    kind: "turn", taskRef: taskA, turnRef: turnB,
    phase: "completed", status: "completed", notificationEnvelope: "top"
  }), null);
  assert.equal(crossTurnProof.observe({
    kind: "turn", taskRef: taskA, turnRef: turnA,
    phase: "completed", status: "completed", notificationEnvelope: "top"
  }), `${taskA}:${turnA}`);

  const reverseOrderProof = createLiveProofTracker();
  assert.equal(reverseOrderProof.observe({
    kind: "turn", taskRef: taskB, turnRef: turnB,
    phase: "completed", status: "completed", notificationEnvelope: "top"
  }), null);
  assert.equal(reverseOrderProof.observe({
    kind: "item", taskRef: taskB, turnRef: turnB,
    phase: "completed", itemType: "reasoning", notificationEnvelope: "top"
  }), null);
  assert.equal(reverseOrderProof.observe({
    kind: "item", taskRef: taskB, turnRef: turnB,
    phase: "started", itemType: "reasoning", notificationEnvelope: "top"
  }), `${taskB}:${turnB}`);
  assert.equal(reverseOrderProof.observe({
    kind: "notificationShape", recognizedEnvelope: "top"
  }), `${taskB}:${turnB}`);

  const unrecognizedEnvelopeProof = createLiveProofTracker();
  unrecognizedEnvelopeProof.observe({
    kind: "item", taskRef: taskA, turnRef: turnA,
    phase: "started", itemType: "commandExecution", notificationEnvelope: "message"
  });
  unrecognizedEnvelopeProof.observe({
    kind: "item", taskRef: taskA, turnRef: turnA,
    phase: "completed", itemType: "commandExecution", notificationEnvelope: "message"
  });
  assert.equal(unrecognizedEnvelopeProof.observe({
    kind: "turn", taskRef: taskA, turnRef: turnA,
    phase: "completed", status: "completed", notificationEnvelope: "message"
  }), null);

  const nonLiveProof = createLiveProofTracker();
  nonLiveProof.observe({ kind: "notificationShape", recognizedEnvelope: "top" });
  nonLiveProof.observe({
    kind: "item", taskRef: taskA, turnRef: turnA,
    phase: "started", itemType: "agentMessage", notificationEnvelope: "top"
  });
  nonLiveProof.observe({
    kind: "item", taskRef: taskA, turnRef: turnA,
    phase: "completed", itemType: "agentMessage", notificationEnvelope: "top"
  });
  assert.equal(nonLiveProof.observe({
    kind: "turn", taskRef: taskA, turnRef: turnA,
    phase: "completed", status: "completed", notificationEnvelope: "top"
  }), null);

  const boundedProof = createLiveProofTracker();
  for (let index = 0; index < maximumLiveProofTurns; index += 1) {
    boundedProof.observe({
      kind: "turn",
      taskRef: index.toString(16).padStart(12, "0"),
      turnRef: turnA,
      phase: "completed",
      status: "completed",
      notificationEnvelope: "top"
    });
  }
  assert.throws(() => boundedProof.observe({
    kind: "turn", taskRef: "ffffffffffff", turnRef: turnA,
    phase: "completed", status: "completed", notificationEnvelope: "top"
  }), /too many correlated turns/);
  process.stdout.write("[CDP] SELF_TEST_PASS turn-correlated-live-proof\n");

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "codex-guardian-cdp-self-test-"));
  try {
    const logPath = path.join(tempRoot, "observation.jsonl");
    for (let index = 0; index < 30; index += 1) {
      appendBoundedLog(logPath, {
        schema: 1,
        kind: "threadState",
        seq: index + 1,
        taskRef: "0123456789ab",
        status: index % 2 === 0 ? "active" : "idle"
      }, 256);
      assert.ok((regularFileSize(logPath) ?? 0) <= 256);
      assert.ok((regularFileSize(`${logPath}.previous`) ?? 0) <= 256);
    }
    assert.ok(fs.existsSync(logPath));
    assert.ok(fs.existsSync(`${logPath}.previous`));
    for (const generation of [logPath, `${logPath}.previous`]) {
      for (const line of fs.readFileSync(generation, "utf8").trim().split("\n")) {
        assert.doesNotThrow(() => JSON.parse(line));
      }
    }
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
  process.stdout.write("[CDP] SELF_TEST_PASS repeated-two-generation-rotation\n");
  process.stdout.write("[CDP] ALL SELF TESTS PASSED\n");
}

const args = parseArguments(process.argv.slice(2));
if (args.selfTest) {
  await runSelfTests();
} else {
  try {
    await runObserver(args);
  } catch (error) {
    const failureCode = classifyObserverFailure(error);
    try {
      appendBoundedLog(args.log, {
        schema: 1,
        timestamp: new Date().toISOString(),
        kind: "observerFailure",
        failureCode
      });
    } catch {
    }
    process.stderr.write(`[CDP] OBSERVER_FAILED code=${failureCode}\n`);
    process.exitCode = 1;
  }
}
