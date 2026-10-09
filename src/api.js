const http = require("node:http");
const https = require("node:https");

class ApiError extends Error {
  constructor(status, body) {
    const msg = (body && (body.error || body.message)) || `http_${status}`;
    super(msg);
    this.status = status;
    this.body = body;
  }
}

function request(renderUrl, method, path, { auth, body, timeoutMs = 15000, agent } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, renderUrl);
    const isHttps = url.protocol === "https:";
    const transport = isHttps ? https : http;

    const headers = {};
    let postData = null;
    if (body) {
      postData = Buffer.from(JSON.stringify(body), "utf8");
      headers["content-type"] = "application/json";
      headers["content-length"] = postData.length;
    }
    if (auth) {
      headers["x-node-id"] = auth.nodeId;
      headers["authorization"] = `Bearer ${auth.token}`;
    }

    const options = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers,
      timeout: timeoutMs,
    };
    if (agent) options.agent = agent;

    const req = transport.request(options, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => {
        let json;
        try {
          json = data ? JSON.parse(data) : {};
        } catch {
          json = { error: `http_${res.statusCode}`, raw: data.slice(0, 200) };
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new ApiError(res.statusCode, json));
        }
        resolve(json);
      });
    });

    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });
    req.on("error", (err) => {
      reject(err);
    });

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

function health(renderUrl, { agent, timeoutMs = 30000 } = {}) {
  return request(renderUrl, "GET", "/health", { timeoutMs, agent });
}

// Ed25519 Challenge-Response Auth (S2)
function challenge(renderUrl, nodeId, { agent } = {}) {
  return request(renderUrl, "POST", "/auth/challenge", {
    body: { node_id: nodeId },
    timeoutMs: 8000,
    agent,
  });
}

function verifyAuth(renderUrl, { nodeId, nonce, signature }, { agent } = {}) {
  return request(renderUrl, "POST", "/auth/verify", {
    body: { node_id: nodeId, nonce, signature },
    timeoutMs: 8000,
    agent,
  });
}

// Registration with invites and proof-of-possession signatures (S3, Addendum 3)
function register(renderUrl, { username, nodeId, publicKey, inviteCode, signature, receipt }, { agent } = {}) {
  return request(renderUrl, "POST", "/register", {
    body: {
      username,
      node_id: nodeId,
      public_key: publicKey,
      invite_code: inviteCode,
      signature,
      receipt,
    },
    timeoutMs: 15000,
    agent,
  });
}

// Mailbox Operations (S1, S7)
function registerMailbox(renderUrl, auth, mailboxId, { agent } = {}) {
  return request(renderUrl, "POST", "/mailbox/register", {
    auth,
    body: { mailbox_id: mailboxId },
    agent,
  });
}

function putMailbox(renderUrl, mailboxId, { msg_id, envelope }, { agent } = {}) {
  return request(renderUrl, "PUT", `/mailbox/${encodeURIComponent(mailboxId)}`, {
    body: { msg_id, envelope },
    timeoutMs: 15000,
    agent,
  });
}

function fetchMailbox(renderUrl, auth, mailboxId, { limit = 50, agent } = {}) {
  return request(renderUrl, "GET", `/mailbox/${encodeURIComponent(mailboxId)}?limit=${limit}`, {
    auth,
    timeoutMs: 15000,
    agent,
  });
}

function ackMailbox(renderUrl, auth, mailboxId, msgIds, { agent } = {}) {
  return request(renderUrl, "POST", `/mailbox/${encodeURIComponent(mailboxId)}/ack`, {
    auth,
    body: { msg_ids: msgIds },
    timeoutMs: 15000,
    agent,
  });
}

function sync(renderUrl, auth, { sinceGlobalSeq, newEvents, limit = 500 }, { agent } = {}) {
  return request(renderUrl, "POST", "/sync", {
    auth,
    body: { since_global_seq: sinceGlobalSeq, limit, new_events: newEvents },
    timeoutMs: 15000,
    agent,
  });
}

function putBackup(renderUrl, auth, blob, { agent } = {}) {
  return request(renderUrl, "PUT", "/backup", { auth, body: { blob }, timeoutMs: 15000, agent });
}

function getBackup(renderUrl, auth, { agent } = {}) {
  return request(renderUrl, "GET", "/backup", { auth, agent });
}

module.exports = {
  ApiError,
  health,
  challenge,
  verifyAuth,
  register,
  registerMailbox,
  putMailbox,
  fetchMailbox,
  ackMailbox,
  sync,
  putBackup,
  getBackup,
};
