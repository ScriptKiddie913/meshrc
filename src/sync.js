"use strict";

const api = require("./api");
const cryptoUtil = require("./crypto");

/**
 * Push whatever's in the local outbox, pull whatever the server has that we
 * don't. Loops on has_more until fully synchronized (C10).
 */
async function syncNow(ctx) {
  let hasMore = true;
  let lastRes = null;

  while (hasMore) {
    const outbox = ctx.db.listOutbox().map((row) => ({
      client_event_id: row.client_event_id,
      event_type: row.event_type,
      payload: JSON.parse(row.payload),
      signature: row.signature || undefined,
    }));

    const res = await api.sync(
      ctx.renderUrl,
      ctx.auth,
      {
        sinceGlobalSeq: ctx.db.lastGlobalSeq(),
        newEvents: outbox,
      },
      { agent: ctx.agent }
    );
    lastRes = res;

    for (const clientEventId of res.accepted || []) {
      ctx.db.clearOutboxEntry(clientEventId);
      ctx.db.markMessageStatus(clientEventId, "stored", res.global_seq);
    }

    const missingEvents = res.items || res.missing_events || [];
    applyMissingEvents(ctx, missingEvents);
    ctx.lastSyncAt = Date.now();

    hasMore = !!res.has_more;
    // Safety check to avoid infinite loops if server reports has_more with 0 items
    if (hasMore && missingEvents.length === 0) {
      break;
    }
  }

  return lastRes;
}

/** Apply server event rows into local state: peer registry + decrypted inbox (C6). */
function applyMissingEvents(ctx, events) {
  for (const ev of events) {
    const isNew = ctx.db.applyEvent(ev);

    let payload;
    try {
      payload = typeof ev.payload === "string" ? JSON.parse(ev.payload) : ev.payload;
    } catch {
      payload = {};
    }

    if (ev.event_type === "USER_REGISTERED" || ev.event_type === "KEY_REGISTERED") {
      continue;
    }

    if (ev.event_type === "MESSAGE_CREATED") {
      const targetNodeId = payload.target_node_id;
      if (targetNodeId !== ctx.nodeId) continue; // not addressed to us
      const sender = ctx.db.getPeerByNodeId(ev.node_id);
      if (!sender) continue; // unknown sender key
      try {
        const sharedKey = cryptoUtil.deriveSharedKey(ctx.identity.ecdhPrivate, sender.ecdh_public);
        const plaintext = cryptoUtil.decryptMessage(payload.ciphertext, sharedKey);
        
        // Single ingest path with deduplication (C6)
        ctx.db.ingestMessage({
          direction: "in",
          peerNodeId: ev.node_id,
          peerUsername: sender.username,
          plaintext,
          status: "received",
          clientEventId: ev.client_event_id || null,
          globalSeq: ev.global_seq,
          eventId: ev.event_id,
          timestamp: ev.timestamp,
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
