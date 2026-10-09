"use strict";

const WebSocket = require("ws");
const { EventEmitter } = require("events");

const HEARTBEAT_MS = 20000;
const RECONNECT_MIN_MS = 2000;
const RECONNECT_MAX_MS = 30000;

/**
 * Persistent connection to mesh /ws relay.
 */
class MeshSocket extends EventEmitter {
  constructor(wsUrl, { nodeId, token }, options = {}) {
    super();
    this.wsUrl = wsUrl;
    this.nodeId = nodeId;
    this.token = token;
    this.agent = options.agent || null;
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
    if (this.ws) {
      try {
        this.ws.close();
      } catch {}
    }
    this.connected = false;
  }

  send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
      return true;
    }
    return false;
  }

  _connect() {
    // Auth via HTTP headers (S10) rather than query strings
    const headers = {
      "authorization": `Bearer ${this.token}`,
      "x-node-id": this.nodeId,
    };

    const wsOpts = { headers };
    if (this.agent) wsOpts.agent = this.agent;

    const ws = new WebSocket(this.wsUrl, wsOpts);
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
        msg = JSON.parse(raw.toString("utf8"));
      } catch {
        return;
      }
      if (msg.type) this.emit(msg.type, msg);
    });

    ws.on("close", (code, reason) => {
      this._handleClose(code, reason);
    });

    ws.on("error", (err) => {
      this.emit("error", err);
    });
  }

  _handleClose(code, reason) {
    const wasConnected = this.connected;
    this.connected = false;
    clearInterval(this.heartbeatTimer);
    if (wasConnected) this.emit("close", { code, reason: String(reason) });

    // Stop reconnecting on 4001 (unauthorized) and 4002 (replaced by another connection) (S10, C9)
    if (code === 4001 || code === 4002) {
      this.wantConnected = false;
      return;
    }

    if (this.wantConnected) this._scheduleReconnect();
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
