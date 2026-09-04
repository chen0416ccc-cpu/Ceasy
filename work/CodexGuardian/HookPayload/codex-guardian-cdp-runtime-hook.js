/* codex-guardian-cdp-observation-runtime-v1 */
(() => {
  "use strict";

  const slot = "__codexGuardianCdpObservationRuntime";
  if (globalThis[slot] != null) {
    return;
  }
  if (globalThis.window !== globalThis || window.top !== window) {
    return;
  }
  if (location.protocol !== "app:" ||
      globalThis.electronBridge == null ||
      typeof globalThis.electronBridge !== "object") {
    return;
  }

  const emitBinding = "__codexGuardianCdpEmit";
  const identifierPattern = /^[A-Za-z0-9_-]{8,80}$/;
  const threadRoutePattern = /\/(?:local|hotkey-window\/thread)\/([0-9a-fA-F-]{36})(?:\/|$)/;
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
  const allowedThreadStatuses = new Set([
    "notLoaded",
    "idle",
    "systemError",
    "active"
  ]);
  const allowedTurnStatuses = new Set([
    "completed",
    "interrupted",
    "failed",
    "inProgress"
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
    "remoteTaskCreated"
  ]);
  const allowedConnectionStates = new Set([
    "connecting",
    "connected",
    "reconnecting",
    "restarting",
    "disconnected",
    "closed",
    "failed",
    "error"
  ]);
  const allowedConnectionTransports = new Set([
    "local",
    "remote",
    "stdio",
    "websocket",
    "ipc"
  ]);
  const allowedConnectionProgress = new Set([
    "starting",
    "initializing",
    "waiting-for-device",
    "confirming-connection",
    "connecting",
    "connected",
    "reconnecting",
    "ready",
    "disconnected",
    "failed"
  ]);
  const allowedNotificationMethods = new Set([
    "thread/status/changed",
    "thread/started",
    "turn/started",
    "turn/completed",
    "item/started",
    "item/completed",
    "error"
  ]);
  const notificationCandidates = Object.freeze([
    ["top", message => message],
    ["message", message => message?.message],
    ["request", message => message?.request],
    ["notification", message => message?.notification],
    ["payload", message => message?.payload]
  ]);

  let sequence = 0;
  let lastSnapshotFingerprint = null;
  let snapshotScheduled = false;
  let navigationSnapshotTimer = null;
  const observedNotificationShapes = new Set();

  function readAllowedValue(value, allowedValues, fallback) {
    return typeof value === "string" && allowedValues.has(value) ? value : fallback;
  }

  function normalizeProtocolId(value) {
    return typeof value === "string" && identifierPattern.test(value) ? value : null;
  }

  function send(kind, fields = {}) {
    const emit = globalThis[emitBinding];
    if (typeof emit !== "function") {
      return false;
    }
    try {
      emit(JSON.stringify({ kind, seq: ++sequence, ...fields }));
      return true;
    } catch {
      return false;
    }
  }

  function readComposerSnapshot() {
    const pathname = typeof location?.pathname === "string" ? location.pathname : "";
    const routeMatch = threadRoutePattern.exec(pathname);
    const threadId = normalizeProtocolId(routeMatch?.[1] ?? null);
    const composerRoot = document.querySelector("[data-codex-composer]");
    const activeElement = document.activeElement;
    const fallbackEditor = activeElement instanceof Element
      ? activeElement.closest(".ProseMirror")
      : null;
    const editor = composerRoot?.querySelector(
      ".ProseMirror, [contenteditable=\"true\"]"
    ) ?? fallbackEditor;
    const composerKnown = composerRoot instanceof Element || fallbackEditor instanceof Element;
    const editorPresent = editor instanceof Element;
    const composerFocused = editorPresent
      ? editor === activeElement || editor.contains(activeElement)
      : null;
    const hasDraft = editorPresent
      ? (editor.textContent ?? "").trim().length > 0
      : null;
    return {
      routeKnown: threadId != null,
      threadId,
      composerKnown,
      editorPresent,
      composerFocused,
      hasDraft
    };
  }

  function publishSnapshot(force = false) {
    const snapshot = readComposerSnapshot();
    const fingerprint = JSON.stringify(snapshot);
    if (!force && fingerprint === lastSnapshotFingerprint) {
      return;
    }
    lastSnapshotFingerprint = fingerprint;
    send("snapshot", snapshot);
  }

  function scheduleSnapshot() {
    if (snapshotScheduled) {
      return;
    }
    snapshotScheduled = true;
    queueMicrotask(() => {
      snapshotScheduled = false;
      publishSnapshot(false);
    });
  }

  function scheduleNavigationSnapshot() {
    scheduleSnapshot();
    if (navigationSnapshotTimer != null) {
      clearTimeout(navigationSnapshotTimer);
    }
    navigationSnapshotTimer = setTimeout(() => {
      navigationSnapshotTimer = null;
      scheduleSnapshot();
    }, 100);
  }

  function readThreadStatus(status) {
    const value = typeof status === "string" ? status : status?.type;
    return readAllowedValue(value, allowedThreadStatuses, "unknown");
  }

  function readTurnStatus(status) {
    return readAllowedValue(status, allowedTurnStatuses, "unknown");
  }

  function readErrorInfo(error) {
    const info = error?.codexErrorInfo;
    if (typeof info === "string") {
      return {
        errorKind: allowedErrorKinds.has(info) ? info : "other",
        httpStatusCode: null
      };
    }
    if (info == null || typeof info !== "object" || Array.isArray(info)) {
      return { errorKind: "other", httpStatusCode: null };
    }
    const key = Object.keys(info).find(candidate => allowedErrorKinds.has(candidate)) ?? "other";
    const status = info[key]?.httpStatusCode;
    return {
      errorKind: key,
      httpStatusCode: Number.isInteger(status) && status >= 100 && status <= 599
        ? status
        : null
    };
  }

  function readReconnectProgress(message) {
    if (typeof message !== "string") {
      return { reconnectAttempt: null, reconnectMaxAttempts: null };
    }
    const match = /(?:reconnect(?:ing)?\D*)?(\d{1,3})\s*\/\s*(\d{1,3})/i.exec(message);
    if (match == null) {
      return { reconnectAttempt: null, reconnectMaxAttempts: null };
    }
    const reconnectAttempt = Number(match[1]);
    const reconnectMaxAttempts = Number(match[2]);
    if (!Number.isInteger(reconnectAttempt) || !Number.isInteger(reconnectMaxAttempts) ||
        reconnectAttempt < 0 || reconnectMaxAttempts < 1 ||
        reconnectAttempt > reconnectMaxAttempts || reconnectMaxAttempts > 100) {
      return { reconnectAttempt: null, reconnectMaxAttempts: null };
    }
    return { reconnectAttempt, reconnectMaxAttempts };
  }

  function observeNotification(message, notificationEnvelope) {
    const method = message?.method;
    const params = message?.params;
    if (typeof method !== "string" || params == null || typeof params !== "object") {
      return;
    }
    if (method === "thread/status/changed") {
      const threadId = normalizeProtocolId(params.threadId);
      if (threadId != null) {
        send("threadState", {
          threadId,
          status: readThreadStatus(params.status),
          notificationEnvelope
        });
      }
      return;
    }
    if (method === "thread/started") {
      const threadId = normalizeProtocolId(params.thread?.id);
      if (threadId != null) {
        send("threadState", {
          threadId,
          status: readThreadStatus(params.thread?.status),
          notificationEnvelope
        });
      }
      return;
    }
    if (method === "turn/started" || method === "turn/completed") {
      const threadId = normalizeProtocolId(params.threadId);
      const turnId = normalizeProtocolId(params.turn?.id ?? params.turnId);
      if (threadId == null || turnId == null) {
        return;
      }
      const error = readErrorInfo(params.turn?.error);
      send("turn", {
        threadId,
        turnId,
        phase: method === "turn/started" ? "started" : "completed",
        status: readTurnStatus(params.turn?.status),
        errorKind: error.errorKind,
        httpStatusCode: error.httpStatusCode,
        willRetry: false,
        notificationEnvelope
      });
      return;
    }
    if (method === "item/started" || method === "item/completed") {
      const threadId = normalizeProtocolId(params.threadId);
      const turnId = normalizeProtocolId(params.turnId);
      const itemType = readAllowedValue(params.item?.type, allowedItemTypes, "unknown");
      if (threadId != null && turnId != null && itemType != null) {
        send("item", {
          threadId,
          turnId,
          phase: method === "item/started" ? "started" : "completed",
          itemType,
          notificationEnvelope
        });
      }
      return;
    }
    if (method === "error") {
      const threadId = normalizeProtocolId(params.threadId);
      const turnId = normalizeProtocolId(params.turnId);
      if (threadId == null || turnId == null) {
        return;
      }
      const error = readErrorInfo(params.error);
      const progress = params.willRetry === true
        ? readReconnectProgress(params.error?.message)
        : { reconnectAttempt: null, reconnectMaxAttempts: null };
      send("streamError", {
        threadId,
        turnId,
        willRetry: params.willRetry === true,
        errorKind: error.errorKind,
        httpStatusCode: error.httpStatusCode,
        reconnectAttempt: progress.reconnectAttempt,
        reconnectMaxAttempts: progress.reconnectMaxAttempts,
        notificationEnvelope
      });
    }
  }

  function publishNotificationShape(message, recognizedEnvelope) {
    const shape = {
      topMethod: typeof message?.method === "string",
      messageMethod: typeof message?.message?.method === "string",
      requestMethod: typeof message?.request?.method === "string",
      notificationMethod: typeof message?.notification?.method === "string",
      payloadMethod: typeof message?.payload?.method === "string",
      recognizedEnvelope
    };
    const fingerprint = JSON.stringify(shape);
    if (observedNotificationShapes.has(fingerprint) || observedNotificationShapes.size >= 8) {
      return;
    }
    observedNotificationShapes.add(fingerprint);
    send("notificationShape", shape);
  }

  function observeInbound(message) {
    try {
      if (message?.type === "mcp-notification") {
        let recognizedEnvelope = "unknown";
        for (const [name, readCandidate] of notificationCandidates) {
          const candidate = readCandidate(message);
          if (allowedNotificationMethods.has(candidate?.method)) {
            recognizedEnvelope = name;
            observeNotification(candidate, name);
            break;
          }
        }
        publishNotificationShape(message, recognizedEnvelope);
      } else if (message?.type === "codex-app-server-connection-changed") {
        send("appServerConnection", {
          state: readAllowedValue(message.state, allowedConnectionStates, "unknown"),
          transport: readAllowedValue(
            message.transport,
            allowedConnectionTransports,
            "unknown"
          ),
          progress: readAllowedValue(
            message.progress,
            allowedConnectionProgress,
            "unknown"
          )
        });
      }
    } catch {
    }
  }

  const onMessage = event => {
    if (event.source != null && event.source !== window) {
      return;
    }
    observeInbound(event.data);
  };
  window.addEventListener("message", onMessage, true);
  document.addEventListener("input", scheduleSnapshot, true);
  document.addEventListener("focusin", scheduleSnapshot, true);
  document.addEventListener("focusout", scheduleSnapshot, true);
  document.addEventListener("visibilitychange", scheduleSnapshot, true);
  window.addEventListener("popstate", scheduleNavigationSnapshot);
  window.addEventListener("hashchange", scheduleNavigationSnapshot);
  globalThis.navigation?.addEventListener?.("currententrychange", scheduleNavigationSnapshot);

  Object.defineProperty(globalThis, slot, {
    configurable: false,
    enumerable: false,
    value: Object.freeze({
      source: "cdp-main-world",
      requestSnapshot: () => publishSnapshot(true),
      dispose: () => {
        window.removeEventListener("message", onMessage, true);
        document.removeEventListener("input", scheduleSnapshot, true);
        document.removeEventListener("focusin", scheduleSnapshot, true);
        document.removeEventListener("focusout", scheduleSnapshot, true);
        document.removeEventListener("visibilitychange", scheduleSnapshot, true);
        window.removeEventListener("popstate", scheduleNavigationSnapshot);
        window.removeEventListener("hashchange", scheduleNavigationSnapshot);
        globalThis.navigation?.removeEventListener?.(
          "currententrychange",
          scheduleNavigationSnapshot
        );
        if (navigationSnapshotTimer != null) {
          clearTimeout(navigationSnapshotTimer);
          navigationSnapshotTimer = null;
        }
      }
    }),
    writable: false
  });

  send("hello", {
    protocol: 1,
    hookVersion: "cdp-runtime-1",
    contractId: "codex-cdp-observation-v1",
    source: "cdp-main-world",
    pageProtocol: "app",
    bridgePresent: true
  });
  publishSnapshot(true);
})();
