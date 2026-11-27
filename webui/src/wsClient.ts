import type { BlockingStatusResponse } from "./types/BlockingStatusResponse";
import type { CfCdnStatus } from "./types/CfCdnStatus";
import type { QueryEvent } from "./types/QueryEvent";
import type { StatsResponse } from "./types/StatsResponse";
import type { UpdateStatusResponse } from "./types/UpdateStatusResponse";
import type { WsClientMessage } from "./types/WsClientMessage";
import type { WsLogFilter } from "./types/WsLogFilter";
import type { WsServerMessage } from "./types/WsServerMessage";
import type { WsTopic } from "./types/WsTopic";

export interface WsEventClientOptions {
  onOpen: () => void;
  onClose: () => void;
  onAuthExpired: () => void;
  onLogsBatch: (events: QueryEvent[]) => void;
  onStats: (stats: StatsResponse) => void;
  onBlocking: (status: BlockingStatusResponse) => void;
  onUpdate: (status: UpdateStatusResponse) => void;
  onCfCdn: (status: CfCdnStatus) => void;
}

export interface WsEventClient {
  connect: () => void;
  disconnect: () => void;
  setSubscription: (topics: WsTopic[], logFilter: WsLogFilter) => void;
}

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 15000;
const WS_CLOSE_POLICY_VIOLATION = 1008;

export function createWsEventClient(options: WsEventClientOptions): WsEventClient {
  let ws: WebSocket | null = null;
  let enabled = false;
  let backoffMs = INITIAL_BACKOFF_MS;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let lastSentPayload: string | null = null;

  let desiredTopics: WsTopic[] = [];
  let desiredLogFilter: WsLogFilter = {
    search: null,
    outcome: null,
    protocol: null,
    qtype: null,
    client: null,
  };

  let pendingLogs: QueryEvent[] = [];
  let flushHandle: number | ReturnType<typeof setTimeout> | null = null;
  let flushUsesRaf = false;

  function clearScheduledFlush() {
    if (flushHandle === null) return;
    if (flushUsesRaf && typeof cancelAnimationFrame === "function") {
      cancelAnimationFrame(flushHandle as number);
    } else {
      clearTimeout(flushHandle as ReturnType<typeof setTimeout>);
    }
    flushHandle = null;
    flushUsesRaf = false;
  }

  function flushPendingLogs() {
    flushHandle = null;
    flushUsesRaf = false;
    if (pendingLogs.length === 0) return;
    const batch = pendingLogs;
    pendingLogs = [];
    options.onLogsBatch(batch);
  }

  function enqueueLog(event: QueryEvent) {
    pendingLogs.push(event);
    if (flushHandle !== null) return;
    if (typeof requestAnimationFrame === "function") {
      flushUsesRaf = true;
      flushHandle = requestAnimationFrame(flushPendingLogs);
    } else {
      flushUsesRaf = false;
      flushHandle = setTimeout(flushPendingLogs, 50);
    }
  }

  function buildSubscribePayload(): string {
    const msg: WsClientMessage = {
      type: "subscribe",
      topics: desiredTopics,
      log_filter: desiredLogFilter,
    };
    return JSON.stringify(msg);
  }

  function sendCurrentSubscription() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const payload = buildSubscribePayload();
    if (payload === lastSentPayload) return;
    lastSentPayload = payload;
    ws.send(payload);
  }

  function openSocket() {
    if (!enabled) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${wsProto}//${location.host}/api/ws`);
    ws = socket;

    socket.onopen = () => {
      if (ws !== socket) return;
      backoffMs = INITIAL_BACKOFF_MS;
      lastSentPayload = null;
      sendCurrentSubscription();
      options.onOpen();
    };

    socket.onclose = (event) => {
      if (ws !== socket) return;
      ws = null;
      lastSentPayload = null;
      clearScheduledFlush();
      pendingLogs = [];

      if (!enabled) {
        options.onClose();
        return;
      }

      if (event.code === WS_CLOSE_POLICY_VIOLATION) {
        enabled = false;
        options.onAuthExpired();
        return;
      }

      options.onClose();
      const delay = backoffMs;
      backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
      reconnectTimer = setTimeout(() => {
        reconnectTimer = undefined;
        openSocket();
      }, delay);
    };

    socket.onerror = () => {
      // onclose handles state transition and reconnect scheduling
    };

    socket.onmessage = (event) => {
      if (ws !== socket || typeof event.data !== "string") return;
      let msg: WsServerMessage;
      try {
        msg = JSON.parse(event.data) as WsServerMessage;
      } catch {
        return;
      }

      switch (msg.type) {
        case "log":
          enqueueLog(msg.data);
          break;
        case "stats":
          options.onStats(msg.data);
          break;
        case "blocking":
          options.onBlocking(msg.data);
          break;
        case "update":
          options.onUpdate(msg.data);
          break;
        case "cf_cdn":
          options.onCfCdn(msg.data);
          break;
        case "subscribed":
        case "error":
          break;
      }
    };
  }

  function connect() {
    enabled = true;
    if (reconnectTimer !== undefined) {
      clearTimeout(reconnectTimer);
      reconnectTimer = undefined;
    }
    openSocket();
  }

  function disconnect() {
    enabled = false;
    if (reconnectTimer !== undefined) {
      clearTimeout(reconnectTimer);
      reconnectTimer = undefined;
    }
    clearScheduledFlush();
    pendingLogs = [];
    lastSentPayload = null;
    if (ws) {
      const active = ws;
      ws = null;
      active.close();
    }
  }

  function setSubscription(topics: WsTopic[], logFilter: WsLogFilter) {
    desiredTopics = [...topics];
    desiredLogFilter = { ...logFilter };
    sendCurrentSubscription();
  }

  return {
    connect,
    disconnect,
    setSubscription,
  };
}
