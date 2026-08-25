"use strict";

const api = require("./api");
const cryptoUtil = require("./crypto");

/**
 * Push whatever's in the local outbox, pull whatever the server has that we
 * don't. This is how a client (or the whole mesh) recovers after either side
 * was offline — same mechanism whether it's a dropped wifi connection or a
 * Render outage.
 */
async function syncNow(ctx) {
  const outbox = ctx.db.listOutbox().map((row) => ({
    client_event_id: row.client_event_id,
    event_type: row.event_type,
    payload: JSON.parse(row.payload),
    signature: row.signature || undefined,
  }));

  const res = await api.sync(ctx.renderUrl, ctx.auth, {
    sinceGlobalSeq: ctx.db.lastGlobalSeq(),
    newEvents: outbox,
  });

  for (const clientEventId of res.accepted || []) {
    ctx.db.clearOutboxEntry(clientEventId);
  }

  applyMissingEvents(ctx, res.missing_events || []);
  ctx.lastSyncAt = Date.now();
  return res;
}

/** Apply server event rows into local state: peer registry + decrypted inbox. */
function applyMissingEvents(ctx, events) {
  for (const ev of events) {
    const isNew = ctx.db.applyEvent(ev);
    if (!isNew) continue;

    let payload;
    try {
      payload = typeof ev.payload === "string" ? JSON.parse(ev.payload) : ev.payload;
    } catch {
      payload = {};
    }

    if (ev.event_type === "USER_REGISTERED" || ev.event_type === "KEY_REGISTERED") {
      // We only get the full picture (username + public_key together) once
      // both events for a node have landed, or via /peers below — best
      // effort here, reconciled fully by refreshPeers().
      continue;
    }

    if (ev.event_type === "MESSAGE_CREATED") {
      const targetNodeId = payload.target_node_id;
      if (targetNodeId !== ctx.nodeId) continue; // not addressed to us
      const sender = ctx.db.getPeerByNodeId(ev.node_id);
      if (!sender) continue; // unknown sender key — can't decrypt yet, will retry after /peers refresh
      try {
        const sharedKey = cryptoUtil.deriveSharedKey(ctx.identity.ecdhPrivate, sender.ecdh_public);
        const plaintext = cryptoUtil.decryptMessage(payload.ciphertext, sharedKey);
        ctx.db.addMessage({
          direction: "in",
          peerNodeId: ev.node_id,
          peerUsername: sender.username,
          plaintext,
          status: "received",
          globalSeq: ev.global_seq,
        });
      } catch {
        // Not encrypted to us / corrupt — ignore.
      }
    }
  }
}

/** Pull the full peer/public-key registry from the server and merge locally. */
async function refreshPeers(ctx) {
  const res = await api.peers(ctx.renderUrl, ctx.auth);
  for (const p of res.peers || []) {
    if (p.node_id === ctx.nodeId) continue;
    const keys = cryptoUtil.unpackPublicKey(p.public_key);
    if (!keys) continue;
    ctx.db.upsertPeer({
      node_id: p.node_id,
      username: p.username,
      sign_public: keys.sign,
      ecdh_public: keys.ecdh,
      last_seen: p.last_seen,
    });
  }
  return res.peers || [];
}

module.exports = { syncNow, applyMissingEvents, refreshPeers };
