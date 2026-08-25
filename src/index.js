#!/usr/bin/env node
"use strict";

const config = require("./config");
const identityCrypto = require("./crypto");
const localdb = require("./localdb");
const api = require("./api");
const ui = require("./ui");
const { askHidden, closeShared } = require("./prompt");
const { MeshSocket } = require("./wsclient");
const syncMod = require("./sync");
const { startRepl } = require("./repl");

const HEALTH_RECHECK_MS = 15000;

async function main() {
  if (!config.exists()) {
    console.log(ui.warn("No identity found. Run ./setup.sh first."));
    process.exit(1);
  }

  const cfg = config.load();
  console.log(ui.banner());
  console.log(ui.dim(`                 NODE: ${cfg.username.toUpperCase()}\n`));

  const passphrase = await askHidden("Vault passphrase: ");
  closeShared();
  let secrets;
  try {
    secrets = identityCrypto.decryptBlob(config.loadIdentityBlob(), passphrase);
  } catch {
    console.log(ui.warn("Wrong passphrase."));
    process.exit(1);
  }

  const identity = {
    signPublic: cfg.sign_public,
    signPrivate: secrets.sign_private,
    ecdhPublic: cfg.ecdh_public,
    ecdhPrivate: secrets.ecdh_private,
  };

  const db = localdb.open(config.DB_PATH);

  const ctx = {
    renderUrl: cfg.render_url,
    nodeId: cfg.node_id,
    username: cfg.username,
    identity,
    passphrase,
    auth: { nodeId: cfg.node_id, token: secrets.token },
    db,
    socket: null,
    online: false,
    wsConnected: false,
    lastSyncAt: null,
  };
  Object.defineProperty(ctx, "wsConnected", {
    get() {
      return !!(ctx.socket && ctx.socket.connected);
    },
  });

  // If setup.sh ran while Render was unreachable, finish registration now.
  if (!secrets.token) {
    process.stdout.write(ui.info("Completing registration... "));
    try {
      const publicKey = identityCrypto.packPublicKey(identity);
      const reg = await api.register(cfg.render_url, {
        username: cfg.username,
        nodeId: cfg.node_id,
        publicKey,
      });
      secrets.token = reg.token;
      ctx.auth.token = reg.token;
      config.saveIdentityBlob(identityCrypto.encryptBlob(secrets, passphrase));
      config.save({ ...cfg, registered: true });
      console.log(ui.ok("ok"));
    } catch (err) {
      console.log(ui.warn(`still unreachable (${err.message}) — will retry later`));
    }
  }

  const socket = new MeshSocket(config.wsUrl(cfg.render_url), ctx.auth);
  ctx.socket = socket;
  wireSocket(ctx, socket);

  await checkHealthAndConnect(ctx);
  scheduleHealthWatchdog(ctx);

  startRepl(ctx);
}

function wireSocket(ctx, socket) {
  socket.on("open", () => {
    ctx.online = true;
  });

  socket.on("close", () => {
    // ws layer handles reconnect on its own; dashboard reflects state via ctx.wsConnected.
  });

  socket.on("connected", (msg) => {
    for (const p of msg.peers || []) {
      if (p.node_id === ctx.nodeId) continue;
      const keys = identityCrypto.unpackPublicKey(p.public_key);
      if (keys) {
        ctx.db.upsertPeer({
          node_id: p.node_id,
          username: p.username,
          sign_public: keys.sign,
          ecdh_public: keys.ecdh,
          last_seen: p.last_seen,
        });
      }
    }
    syncMod.syncNow(ctx).catch(() => {});
  });

  socket.on("peers", (msg) => {
    for (const p of msg.peers || []) {
      if (p.node_id === ctx.nodeId) continue;
      const keys = identityCrypto.unpackPublicKey(p.public_key);
      if (keys) {
        ctx.db.upsertPeer({
          node_id: p.node_id,
          username: p.username,
          sign_public: keys.sign,
          ecdh_public: keys.ecdh,
          last_seen: p.last_seen,
        });
      }
    }
  });

  socket.on("presence", (msg) => {
    ctx.db.setPeerOnline(msg.node_id, msg.status === "online");
  });

  socket.on("peer_update", (msg) => {
    const keys = identityCrypto.unpackPublicKey(msg.node.public_key);
    if (keys) {
      ctx.db.upsertPeer({
        node_id: msg.node.node_id,
        username: msg.node.username,
        sign_public: keys.sign,
        ecdh_public: keys.ecdh,
      });
      console.log("\n" + ui.info(`+ new peer: ${msg.node.username}`));
      process.stdout.write(ui.PROMPT);
    }
  });

  socket.on("message", (msg) => {
    const sender = ctx.db.getPeerByNodeId(msg.from);
    if (!sender) return;
    try {
      const sharedKey = identityCrypto.deriveSharedKey(ctx.identity.ecdhPrivate, sender.ecdh_public);
      const plaintext = identityCrypto.decryptMessage(msg.ciphertext, sharedKey);
      ctx.db.addMessage({
        direction: "in",
        peerNodeId: msg.from,
        peerUsername: sender.username,
        plaintext,
        status: "received",
        globalSeq: msg.global_seq,
      });
      console.log("\n" + ui.msgIn(sender.username, plaintext));
      process.stdout.write(ui.PROMPT);
    } catch {
      /* undecryptable — drop */
    }
  });

  socket.on("message_delivered", (msg) => {
    markLatestPendingByTarget(ctx, msg.target_node_id, "delivered", msg.global_seq);
  });

  socket.on("message_queued", (msg) => {
    markLatestPendingByTarget(ctx, msg.target_node_id, "queued", msg.global_seq);
  });

  socket.on("sync_events", (msg) => {
    syncMod.applyMissingEvents(ctx, msg.events || []);
  });

  socket.on("error", () => {
    // swallow — reconnect loop + health watchdog handle recovery visibly via /status
  });

  socket.start();
}

function markLatestPendingByTarget(ctx, targetNodeId, status, globalSeq) {
  const row = ctx.db.raw
    .prepare("SELECT client_event_id FROM messages WHERE peer_node_id = ? AND status = 'pending' ORDER BY id DESC LIMIT 1")
    .get(targetNodeId);
  if (row) ctx.db.markMessageStatus(row.client_event_id, status, globalSeq);
}

async function checkHealthAndConnect(ctx) {
  try {
    await api.health(ctx.renderUrl);
    ctx.online = true;
    await syncMod.refreshPeers(ctx).catch(() => {});
    await syncMod.syncNow(ctx).catch(() => {});
  } catch {
    ctx.online = false;
    console.log(ui.warn("Render unreachable — starting in local/offline mode. Peer messages will queue."));
  }
}

function scheduleHealthWatchdog(ctx) {
  setInterval(async () => {
    if (ctx.online) return;
    try {
      await api.health(ctx.renderUrl);
      ctx.online = true;
      if (!ctx.socket.connected) ctx.socket.start();
      await syncMod.refreshPeers(ctx).catch(() => {});
      await syncMod.syncNow(ctx).catch(() => {});
      console.log("\n" + ui.ok("Render back online — synchronized."));
      process.stdout.write(ui.PROMPT);
    } catch {
      /* still down */
    }
  }, HEALTH_RECHECK_MS);
}

main().catch((err) => {
  console.error(ui.warn(`fatal: ${err.message}`));
  process.exit(1);
});
