"use strict";

class ApiError extends Error {
  constructor(status, body) {
    super((body && body.error) || `http_${status}`);
    this.status = status;
    this.body = body;
  }
}

async function request(renderUrl, method, path, { auth, body, timeoutMs = 8000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = {};
    if (body) headers["content-type"] = "application/json";
    if (auth) {
      headers["x-node-id"] = auth.nodeId;
      headers["authorization"] = `Bearer ${auth.token}`;
    }
    const res = await fetch(new URL(path, renderUrl), {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const text = await res.text();
    const data = text ? JSON.parse(text) : {};
    if (!res.ok) throw new ApiError(res.status, data);
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function health(renderUrl) {
  return request(renderUrl, "GET", "/health", { timeoutMs: 5000 });
}

function register(renderUrl, { username, nodeId, publicKey }) {
  return request(renderUrl, "POST", "/register", {
    body: { username, node_id: nodeId, public_key: publicKey },
  });
}

function peers(renderUrl, auth) {
  return request(renderUrl, "GET", "/peers", { auth });
}

function sync(renderUrl, auth, { sinceGlobalSeq, newEvents }) {
  return request(renderUrl, "POST", "/sync", {
    auth,
    body: { since_global_seq: sinceGlobalSeq, new_events: newEvents },
    timeoutMs: 15000,
  });
}

function putBackup(renderUrl, auth, blob) {
  return request(renderUrl, "PUT", "/backup", { auth, body: { blob }, timeoutMs: 15000 });
}

function getBackup(renderUrl, auth) {
  return request(renderUrl, "GET", "/backup", { auth });
}

module.exports = { ApiError, health, register, peers, sync, putBackup, getBackup };
