"use strict";

const crypto = require("crypto");
const api = require("./api");
const identityCrypto = require("./crypto");

/**
 * Disaster Recovery & State Machine (Addendum 9)
 * Guarantees zero data loss across server wipes, rollbacks, and ephemeral restarts.
 */

function verifyHandshake({ nonce, epoch, host, server_sig, server_pub, pinnedServerPub = null }) {
  if (pinnedServerPub && server_pub !== pinnedServerPub) {
    const err = new Error("SECURITY ALERT: Server identity public key DOES NOT MATCH pinned key! Impostor server suspected.");
    err.code = "SERVER_IMPOSTOR";
    throw err;
  }

  const expectedData = `sdmesh-handshake-v2|${nonce}|${epoch}|${host}`;
  const verified = identityCrypto.verify(expectedData, server_sig, server_pub);
  if (!verified) {
    const err = new Error("Server handshake signature verification failed");
    err.code = "HANDSHAKE_SIG_INVALID";
    throw err;
  }

  return { verified: true, epoch, server_pub };
}

function evaluateServerState({ currentEpoch, lastEpoch, clientWatermark = 0, serverWatermark = 0 }) {
  if (!lastEpoch || currentEpoch === lastEpoch) {
    if (serverWatermark < clientWatermark && lastEpoch) {
      return { state: "ROLLBACK_DETECTED", message: "Server watermark lower than client local watermark" };
    }
    return { state: "NORMAL" };
  }

  return {
    state: "SERVER_RESET",
    message: "Server epoch changed: disposable server was wiped or rebuilt.",
  };
}

/**
 * Handle in-ciphertext gap filling (Addendum 9.3)
 */
function createSyncStatePayload(ctx, peerNodeId) {
  const peer = ctx.db.getPeerByNodeId(peerNodeId);
  const recvHighWater = peer ? peer.recv_counter : 0;
  return {
    type: "sync_state",
    sender_node_id: ctx.nodeId,
    recv_high_water: recvHighWater,
    timestamp: Date.now(),
  };
}

function processPeerSyncState(ctx, peerNodeId, syncStatePayload) {
  const { recv_high_water } = syncStatePayload;
  const history = ctx.db.getSentHistory(peerNodeId);
  const toRetransmit = [];

  for (const item of history) {
    if (item.counter > recv_high_water) {
      toRetransmit.push(item);
    }
  }

  return toRetransmit;
}

/**
 * Verify a signed server manifest for standby onion failover (Addendum 9.4)
 */
function verifyServerManifest(manifest, serverPubBase64) {
  if (!manifest || !manifest.onion_addresses || !manifest.valid_until || !manifest.signature) {
    return false;
  }

  if (Date.now() > manifest.valid_until) {
    return false; // Expired
  }

  const data = `sdmesh-manifest-v2|${manifest.valid_until}|${manifest.onion_addresses.join(",")}`;
  return identityCrypto.verify(data, manifest.signature, serverPubBase64);
}

module.exports = {
  verifyHandshake,
  evaluateServerState,
  createSyncStatePayload,
  processPeerSyncState,
  verifyServerManifest,
};
