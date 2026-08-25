"use strict";

const WebSocket = require("ws");
const { EventEmitter } = require("events");

const HEARTBEAT_MS = 20000;
const RECONNECT_MIN_MS = 2000;
const RECONNECT_MAX_MS = 30000;

/**
 * Persistent connection to Render's /ws relay. Emits:
 *   'open', 'close', 'error'
 *   'peers'        { peers }
 *   'presence'     { node_id, status }
 *   'peer_update'  { node }
 *   'message'      { from, ciphertext, global_seq }
 *   'message_delivered' { target_node_id, global_seq }
 *   'message_queued'    { target_node_id, global_seq }
 *   'sync_events'  { events }
 */
class MeshSocket extends EventEmitter {
  constructor(wsUrl, { nodeId, token }) {
    super();
    this.wsUrl = wsUrl;
    this.nodeId = nodeId;
    this.token = token;
    this.ws = null;
    this.heartbeatTimer = null;
    this.reconnectTimer = null;
    this.reconnectDelay = RECONNECT_MIN_MS;
    this.wantConnected = false;
    this.connected = false;
  }

  start() {
    this.wantConnected = true;
    this._connect();
  }

  stop() {
    this.wantConnected = false;
    clearTimeout(this.reconnectTimer);
    clearInterval(this.heartbeatTimer);
    if (this.ws) this.ws.close();
  }

  send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
      return true;
    }
    return false;
  }

  _connect() {
    const url = `${this.wsUrl}?node_id=${encodeURIComponent(this.nodeId)}&token=${encodeURIComponent(this.token)}`;
    const ws = new WebSocket(url);
    this.ws = ws;

    ws.on("open", () => {
      this.connected = true;
      this.reconnectDelay = RECONNECT_MIN_MS;
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = setInterval(() => this.send({ type: "heartbeat" }), HEARTBEAT_MS);
      this.emit("open");
    });

    ws.on("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (msg.type) this.emit(msg.type, msg);
    });

    ws.on("close", () => {
      const wasConnected = this.connected;
      this.connected = false;
      clearInterval(this.heartbeatTimer);
      if (wasConnected) this.emit("close");
      if (this.wantConnected) this._scheduleReconnect();
    });

    ws.on("error", (err) => {
      this.emit("error", err);
    });
  }

  _scheduleReconnect() {
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      if (this.wantConnected) this._connect();
    }, this.reconnectDelay);
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, RECONNECT_MAX_MS);
  }
}

module.exports = { MeshSocket };
