import type { WsClientMessage, WsServerMessage } from "../types.js";

export type WsEventType = WsServerMessage["type"];

export type WsEventHandler<T extends WsServerMessage = WsServerMessage> = (msg: T) => void;

export interface HavenWsOptions {
  /** Base URL of the Haven backend (e.g. "http://localhost:8080"). */
  baseUrl: string;

  /** JWT access token for authentication. */
  token: string;

  /** Reconnect after disconnection. Default: true. */
  autoReconnect?: boolean;

  /** Max reconnect attempts before giving up. Default: 10. */
  maxReconnectAttempts?: number;

  /** Base delay in ms for exponential backoff. Default: 1000. */
  reconnectBaseDelay?: number;
}

type ConnectionState = "disconnected" | "connecting" | "connected";

/**
 * WebSocket client for Haven real-time messaging.
 * Handles reconnection with exponential backoff and typed event dispatch.
 */
export class HavenWs {
  private ws: WebSocket | null = null;
  private options: Required<HavenWsOptions>;
  private listeners = new Map<string, Set<WsEventHandler<any>>>();
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private state: ConnectionState = "disconnected";
  private pingInterval: ReturnType<typeof setInterval> | null = null;
  private closed = false;
  private sessionId: string | null = null;
  private heartbeatIntervalMs = 30_000;

  constructor(options: HavenWsOptions) {
    this.options = {
      autoReconnect: true,
      maxReconnectAttempts: 10,
      reconnectBaseDelay: 1000,
      ...options,
    };
  }

  /** Current connection state. */
  get connectionState(): ConnectionState {
    return this.state;
  }

  /** Whether the WebSocket is currently connected and ready to send. */
  get isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /** Update the auth token (e.g. after a refresh). */
  updateToken(token: string): void {
    this.options.token = token;
  }

  // ─── Connect / Disconnect ────────────────────────

  connect(): void {
    if (this.state !== "disconnected") return;
    this.closed = false;
    this.doConnect();
  }

  disconnect(): void {
    this.closed = true;
    this.sessionId = null;
    this.cleanup();
    this.state = "disconnected";
    this.emit("_disconnect", {} as any);
  }

  // ─── Send ────────────────────────────────────────

  send(msg: WsClientMessage): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }
    this.ws.send(JSON.stringify(msg));
  }

  sendMessage(channelId: string, senderToken: string, encryptedBody: string, expiresAt?: string, attachmentIds?: string[], replyToId?: string): void {
    this.send({
      type: "SendMessage",
      payload: { channel_id: channelId, sender_token: senderToken, encrypted_body: encryptedBody, expires_at: expiresAt, attachment_ids: attachmentIds, reply_to_id: replyToId },
    });
  }

  editMessage(messageId: string, encryptedBody: string): void {
    this.send({
      type: "EditMessage",
      payload: { message_id: messageId, encrypted_body: encryptedBody },
    });
  }

  deleteMessage(messageId: string): void {
    this.send({
      type: "DeleteMessage",
      payload: { message_id: messageId },
    });
  }

  addReaction(messageId: string, emoji: string): void {
    this.send({
      type: "AddReaction",
      payload: { message_id: messageId, emoji },
    });
  }

  removeReaction(messageId: string, emoji: string): void {
    this.send({
      type: "RemoveReaction",
      payload: { message_id: messageId, emoji },
    });
  }

  subscribe(channelId: string): void {
    this.send({ type: "Subscribe", payload: { channel_id: channelId } });
  }

  unsubscribe(channelId: string): void {
    this.send({ type: "Unsubscribe", payload: { channel_id: channelId } });
  }

  typing(channelId: string): void {
    this.send({ type: "Typing", payload: { channel_id: channelId } });
  }

  setStatus(status: string): void {
    this.send({ type: "SetStatus", payload: { status } });
  }

  pinMessage(channelId: string, messageId: string): void {
    this.send({ type: "PinMessage", payload: { channel_id: channelId, message_id: messageId } });
  }

  unpinMessage(channelId: string, messageId: string): void {
    this.send({ type: "UnpinMessage", payload: { channel_id: channelId, message_id: messageId } });
  }

  markRead(channelId: string): void {
    this.send({ type: "MarkRead", payload: { channel_id: channelId } });
  }

  // ─── Events ──────────────────────────────────────

  /**
   * Listen for a specific server message type.
   * Returns an unsubscribe function.
   */
  on<T extends WsServerMessage["type"]>(
    type: T,
    handler: WsEventHandler<Extract<WsServerMessage, { type: T }>>,
  ): () => void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, new Set());
    }
    this.listeners.get(type)!.add(handler);
    return () => this.listeners.get(type)?.delete(handler);
  }

  /** Listen for connection state changes. */
  onConnect(handler: () => void): () => void {
    return this.on("_connect" as any, handler as any);
  }

  onDisconnect(handler: () => void): () => void {
    return this.on("_disconnect" as any, handler as any);
  }

  // ─── Internals ───────────────────────────────────

  private doConnect(): void {
    this.state = "connecting";
    const previousSessionId = this.sessionId;

    const wsUrl = this.options.baseUrl
      .replace(/^http/, "ws")
      .replace(/\/$/, "");

    this.ws = new WebSocket(
      `${wsUrl}/api/v1/ws?token=${encodeURIComponent(this.options.token)}`,
    );

    this.ws.onopen = () => {
      this.state = "connected";
      this.reconnectAttempts = 0;
      // Don't emit _connect yet — wait for Hello from server
    };

    this.ws.onmessage = (event) => {
      try {
        const msg: WsServerMessage = JSON.parse(
          typeof event.data === "string" ? event.data : "",
        );

        // Handle session protocol messages before general dispatch
        if (msg.type === "Hello") {
          const { session_id, heartbeat_interval_ms } = msg.payload;
          this.sessionId = session_id;
          this.heartbeatIntervalMs = heartbeat_interval_ms;
          this.startPing();

          // If we have a previous session, attempt resume
          if (previousSessionId && previousSessionId !== session_id) {
            this.send({ type: "Resume", payload: { session_id: previousSessionId } });
            // Don't emit _connect yet — wait for Resumed or InvalidSession
          } else {
            // Fresh connection — ready
            this.emit("_connect", {} as any);
          }
          return;
        }

        if (msg.type === "Resumed") {
          // Resume succeeded — missed events were already replayed before this message
          this.emit("_connect", {} as any);
          this.emit(msg.type, msg);
          return;
        }

        if (msg.type === "InvalidSession") {
          // Resume failed — this is now a fresh connection with the new session from Hello
          this.emit("_connect", {} as any);
          this.emit(msg.type, msg);
          return;
        }

        this.emit(msg.type, msg);
      } catch {
        // Ignore malformed messages
      }
    };

    this.ws.onclose = () => {
      this.cleanup();
      this.state = "disconnected";

      if (!this.closed && this.options.autoReconnect) {
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = () => {
      // onclose will fire after onerror — reconnection handled there
    };
  }

  private emit(type: string, msg: WsServerMessage): void {
    // Fire wildcard handlers for all events (used by multi-tab broadcast)
    const wildcardHandlers = this.listeners.get("*");
    if (wildcardHandlers && type !== "_connect" && type !== "_disconnect") {
      for (const handler of wildcardHandlers) {
        try {
          handler(msg);
        } catch {
          // Don't let a handler error break the event loop
        }
      }
    }
    const handlers = this.listeners.get(type);
    if (handlers) {
      for (const handler of handlers) {
        try {
          handler(msg);
        } catch {
          // Don't let a handler error break the event loop
        }
      }
    }
  }

  private startPing(): void {
    this.stopPing();
    this.pingInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.send({ type: "Ping" });
      }
    }, this.heartbeatIntervalMs);
  }

  private stopPing(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.options.maxReconnectAttempts) {
      return;
    }

    const delay = Math.min(
      this.options.reconnectBaseDelay * 2 ** this.reconnectAttempts,
      30_000,
    );
    this.reconnectAttempts++;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.doConnect();
    }, delay);
  }

  private cleanup(): void {
    this.stopPing();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
        this.ws.close();
      }
      this.ws = null;
    }
  }
}
