#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const config = require("./config");
const identityCrypto = require("./crypto");
const localdb = require("./localdb");
const api = require("./api");
const ui = require("./ui");
const { askHidden, closeShared } = require("./prompt");
const { MeshSocket } = require("./wsclient");
const syncMod = require("./sync");
const { startRepl } = require("./repl");
const { isV3OnionAddress, detectTorSocksPort, createTorAgent } = require("./tor");

const HEALTH_RECHECK_MS = 15000;

async function authenticateWithChallenge(renderUrl, nodeId, signPrivateBase64, { agent } = {}) {
  try {
    const host = new URL(renderUrl).hostname || "sdmesh";
    const ch = await api.challenge(renderUrl, nodeId, { agent });
    const expected = `sdmesh-auth-v2|${ch.nonce}|${host}`;
    const sig = identityCrypto.sign(expected, signPrivateBase64);
    const session = await api.verifyAuth(renderUrl, {
      nodeId,
      nonce: ch.nonce,
      signature: sig,
    }, { agent });
    return session.token;
  } catch {
    return null;
  }
}

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

  let dataKey = secrets.data_key ? Buffer.from(secrets.data_key, "hex") : null;
  if (!dataKey) {
    dataKey = identityCrypto.generateDataKey();
    secrets.data_key = dataKey.toString("hex");
    try {
      config.saveIdentityBlob(identityCrypto.encryptBlob(secrets, passphrase));
    } catch {}
  }

  const db = localdb.open(config.DB_PATH, { dataKey });

  // Initialize Tor Agent if routing to .onion
  let agent = null;
  if (isV3OnionAddress(cfg.render_url)) {
    const socksPort = cfg.socks_port || (await detectTorSocksPort());
    if (socksPort) {
      agent = createTorAgent({ socksPort, isolationUser: cfg.node_id });
      console.log(ui.ok(`✓ Tor routing active via SOCKS proxy (port ${socksPort})`));
    } else {
      console.log(ui.warn("\n[!] Tor is not running locally (ports 9050/9150 closed)."));
      console.log(ui.warn("    Start Tor Browser or background Tor to connect to the onion network.\n"));
    }
  }

  // Authenticate using Ed25519 challenge-response (S2)
  let authToken = secrets.token;
  const freshToken = await authenticateWithChallenge(cfg.render_url, cfg.node_id, identity.signPrivate, { agent });
  if (freshToken) {
    authToken = freshToken;
    secrets.token = freshToken;
    try {
      config.saveIdentityBlob(identityCrypto.encryptBlob(secrets, passphrase));
    } catch {}
  }

  const ctx = {
    renderUrl: cfg.render_url,
    nodeId: cfg.node_id,
    username: cfg.username,
    identity,
    passphrase,
    auth: { nodeId: cfg.node_id, token: authToken },
    db,
    agent,
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

  const socket = new MeshSocket(config.wsUrl(cfg.render_url), ctx.auth, { agent });
  ctx.socket = socket;
  wireSocket(ctx, socket);

  await checkHealthAndConnect(ctx);
  scheduleHealthWatchdog(ctx);

  startRepl(ctx);
}

function wireSocket(ctx, socket) {
  socket.on("open", () => {
    ctx.online = true;
    // Subscribe to all contact inbound mailboxes
    for (const p of ctx.db.listPeers()) {
      if (p.inbound_mailbox) {
        socket.send({ type: "mailbox_subscribe", mailbox_id: p.inbound_mailbox });
      }
    }
  });

  socket.on("close", () => {
    ctx.online = false; // Fix C9
  });

  socket.on("connected", (msg) => {
    for (const p of ctx.db.listPeers()) {
      if (p.inbound_mailbox) {
        socket.send({ type: "mailbox_subscribe", mailbox_id: p.inbound_mailbox });
      }
    }
    syncMod.syncNow(ctx).catch(() => {});
  });

  // Protocol v2 Mailbox Item Receiver (S1, S8)
  socket.on("mailbox_item", (msg) => {
    const { mailbox_id: mailboxId, msg_id: msgId, envelope } = msg;

    for (const peer of ctx.db.listPeers()) {
      try {
        const sharedSecret = identityCrypto.deriveRawSharedSecret(ctx.identity.ecdhPrivate, peer.ecdh_public);
        const decrypted = identityCrypto.decryptEnvelope({
          envelopeBase64: envelope,
          sharedSecret,
          fromId: peer.node_id,
          toId: ctx.nodeId,
          msgId,
          counter: peer.recv_counter + 1,
        });

        // Update recv counter
        ctx.db.updateRecvCounter(peer.node_id, decrypted.counter || peer.recv_counter + 1);

        // Handle End-to-End Delivery Ack
        if (decrypted.type === "ack") {
          const ackMsgId = decrypted.payload && decrypted.payload.ack_msg_id ? decrypted.payload.ack_msg_id : msgId;
          ctx.db.clearOutboxEntry(ackMsgId);
          ctx.db.markMessageStatus(ackMsgId, "delivered");
        } else {
          // Standard message
          const text = decrypted.payload;
          const ingestRes = ctx.db.ingestMessage({
            direction: "in",
            peerNodeId: peer.node_id,
            peerUsername: peer.username,
            plaintext: text,
            status: "received",
            clientEventId: msgId,
          });

          if (ingestRes.isNew) {
            console.log("\n" + ui.msgIn(peer.username, identityCrypto.sanitizeTerminal(text)));
            process.stdout.write(ui.PROMPT);

            // Send E2E Ack back to peer (Addendum 9.2)
            const ackEnvelope = identityCrypto.encryptEnvelope({
              plaintext: { ack_msg_id: msgId },
              sharedSecret,
              fromId: ctx.nodeId,
              toId: peer.node_id,
              msgId: `ack-${msgId}`,
              counter: ctx.db.nextSendCounter(peer.node_id),
              type: "ack",
            });

            if (peer.outbound_mailbox) {
              socket.send({
                type: "mailbox_put",
                mailbox_id: peer.outbound_mailbox,
                msg_id: `ack-${msgId}`,
                envelope: ackEnvelope,
              });
            }
          }
        }

        // Delete from server mailbox (S7: delete-on-ack)
        socket.send({
          type: "mailbox_ack",
          mailbox_id: mailboxId,
          msg_ids: [msgId],
        });
        break;
      } catch {
        // Not from this peer, try next peer
      }
    }
  });

  // Legacy direct message handling for backward compatibility
  socket.on("message", (msg) => {
    const sender = ctx.db.getPeerByNodeId(msg.from);
    if (!sender) return;
    try {
      const sharedKey = identityCrypto.deriveSharedKey(ctx.identity.ecdhPrivate, sender.ecdh_public);
      const plaintext = identityCrypto.decryptMessage(msg.ciphertext, sharedKey);
      
      const ingestRes = ctx.db.ingestMessage({
        direction: "in",
        peerNodeId: msg.from,
        peerUsername: sender.username,
        plaintext,
        status: "received",
        clientEventId: msg.client_event_id || null,
        globalSeq: msg.global_seq || null,
      });

      if (ingestRes.isNew) {
        console.log("\n" + ui.msgIn(sender.username, identityCrypto.sanitizeTerminal(plaintext)));
        process.stdout.write(ui.PROMPT);
      }
    } catch {}
  });

  socket.on("message_stored", (msg) => {
    if (msg.client_event_id) {
      ctx.db.markMessageStatus(msg.client_event_id, "stored", msg.global_seq);
    }
  });

  socket.on("message_delivered", (msg) => {
    if (msg.client_event_id) {
      ctx.db.clearOutboxEntry(msg.client_event_id);
      ctx.db.markMessageStatus(msg.client_event_id, "delivered", msg.global_seq);
    }
  });

  socket.on("message_queued", (msg) => {
    if (msg.client_event_id) {
      ctx.db.markMessageStatus(msg.client_event_id, "queued", msg.global_seq);
    }
  });

  socket.on("sync_events", (msg) => {
    syncMod.applyMissingEvents(ctx, msg.events || []);
  });

  socket.on("error", () => {});
  socket.start();
}

async function checkHealthAndConnect(ctx) {
  try {
    await api.health(ctx.renderUrl, { agent: ctx.agent });
    ctx.online = true;
    await syncMod.syncNow(ctx).catch(() => {});
  } catch {
    ctx.online = false;
    console.log(ui.warn("Server unreachable — starting in local/offline mode."));
  }
}

function scheduleHealthWatchdog(ctx) {
  setInterval(async () => {
    if (ctx.online) return;
    try {
      await api.health(ctx.renderUrl, { agent: ctx.agent });
      ctx.online = true;
      if (!ctx.socket.connected) ctx.socket.start();
      await syncMod.syncNow(ctx).catch(() => {});
      console.log("\n" + ui.ok("Server back online — synchronized."));
      process.stdout.write(ui.PROMPT);
    } catch {}
  }, HEALTH_RECHECK_MS);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(ui.warn(`fatal: ${err.message}`));
    process.exit(1);
  });
}

module.exports = { main, wireSocket, authenticateWithChallenge };
