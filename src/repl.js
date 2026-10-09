"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const readline = require("readline");
const config = require("./config");
const localdb = require("./localdb");
const ui = require("./ui");
const api = require("./api");
const identityCrypto = require("./crypto");
const syncMod = require("./sync");
const { askHidden } = require("./prompt");

const HELP = `
${ui.c.bold}Commands${ui.c.reset}
  /status                 connection + sync dashboard
  /invite                 create an out-of-band contact exchange link
  /accept <link>          accept an invite link and pin peer keys (TOFU)
  /contacts               list known contacts and verification states
  /verify <user>          show safety number (fingerprint check)
  /msg <user> <text...>   send a sealed-sender padded encrypted message
  /history [user] [n]     show recent messages (default: all, 30)
  /sync                   force a two-way sync with server now
  /passwd                 change vault passphrase (min 12 chars)
  /backup export [path]   export encrypted local backup
  /backup import <path>   restore from encrypted local backup
  /panic                  emergency secure wipe of all local data
  /whoami                 show this node's identity & safety number
  /clear                  clear the screen
  /help                   this text
  /quit                   exit
`;

function startRepl(ctx) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: ui.PROMPT,
  });

  console.log(ui.dashboard(ctx));
  console.log(ui.dim("\ntype /help for commands\n"));
  rl.prompt();

  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return rl.prompt();

    try {
      await handleCommand(ctx, trimmed, rl);
    } catch (err) {
      console.log(ui.warn(`error: ${err.message}`));
    }
    rl.prompt();
  });

  rl.on("close", () => {
    console.log(ui.dim("\nsession closed."));
    if (ctx.socket) ctx.socket.stop();
    ctx.db.close();
    process.exit(0);
  });

  return rl;
}

async function handleCommand(ctx, line, rl) {
  const [cmd, ...rest] = line.split(/\s+/);

  switch (cmd) {
    case "/help":
      console.log(HELP);
      break;

    case "/status":
      console.log(ui.dashboard(ctx));
      break;

    case "/clear":
      console.clear();
      break;

    case "/whoami": {
      const fp = crypto.createHash("sha256").update(ctx.identity.signPublic).digest("hex").slice(0, 16);
      console.log(
        [
          `${ui.c.bold}username${ui.c.reset}   ${ctx.username}`,
          `${ui.c.bold}node_id${ui.c.reset}    ${ctx.nodeId}`,
          `${ui.c.bold}fingerprint${ui.c.reset} ${fp}`,
          `${ui.c.bold}endpoint${ui.c.reset}   ${ctx.renderUrl}`,
        ].join("\n")
      );
      break;
    }

    case "/invite": {
      // Create out-of-band contact exchange link (C1)
      const myInboundMailbox = ctx.inboundMailbox || `mbx_${crypto.randomBytes(16).toString("hex")}`;
      ctx.inboundMailbox = myInboundMailbox;

      const params = new URLSearchParams({
        server: ctx.renderUrl,
        node: ctx.nodeId,
        username: ctx.username,
        sign: ctx.identity.signPublic,
        ecdh: ctx.identity.ecdhPublic,
        mailbox: myInboundMailbox,
      });

      const inviteUrl = `sdmesh://invite?${params.toString()}`;
      console.log(ui.info("\nShare this one-time contact link with your peer out-of-band:"));
      console.log(`${ui.c.bold}${inviteUrl}${ui.c.reset}\n`);

      // Register capability on server
      if (ctx.socket && ctx.online) {
        ctx.socket.send({ type: "mailbox_subscribe", mailbox_id: myInboundMailbox });
      }
      break;
    }

    case "/accept": {
      const link = rest[0];
      if (!link || !link.startsWith("sdmesh://invite?")) {
        console.log(ui.warn("usage: /accept sdmesh://invite?<params>"));
        break;
      }
      await acceptInviteLink(ctx, link);
      break;
    }

    case "/contacts":
    case "/peers": {
      printContacts(ctx);
      break;
    }

    case "/verify": {
      const uname = rest[0];
      if (!uname) {
        console.log(ui.warn("usage: /verify <username>"));
        break;
      }
      const peer = ctx.db.getPeerByUsername(uname);
      if (!peer) {
        console.log(ui.warn(`unknown contact: ${uname}`));
        break;
      }

      const num = identityCrypto.safetyNumber(ctx.identity.signPublic, peer.sign_public);
      console.log(`\n${ui.c.bold}Safety Number for ${peer.username}:${ui.c.reset}`);
      console.log(`  ${ui.c.cyan}${num}${ui.c.reset}`);
      console.log(`Status: ${peer.status === "verified" ? ui.ok("VERIFIED") : ui.warn("MISMATCH / UNVERIFIED")}`);
      console.log(ui.dim("Compare these digits out-of-band with your contact to verify key integrity.\n"));
      break;
    }

    case "/msg": {
      const match = line.match(/^\/msg\s+([^\s]+)\s+([\s\S]+)$/);
      if (!match) {
        console.log(ui.warn("usage: /msg <user> <text>"));
        break;
      }
      const username = match[1];
      const text = match[2];
      await sendMessage(ctx, username, text);
      break;
    }

    case "/sync": {
      if (!ctx.online) {
        console.log(ui.warn("offline — nothing to sync right now"));
        break;
      }
      await syncMod.syncNow(ctx);
      console.log(ui.ok("synced with server"));
      break;
    }

    case "/history": {
      let peerNodeId = null;
      let limit = 30;
      const args = [...rest];
      if (args[0] && !/^\d+$/.test(args[0])) {
        const uname = args.shift();
        const peer = ctx.db.getPeerByUsername(uname);
        if (!peer) {
          console.log(ui.warn(`unknown contact: ${uname}`));
          break;
        }
        peerNodeId = peer.node_id;
      }
      if (args[0] && /^\d+$/.test(args[0])) limit = parseInt(args[0], 10);

      const msgs = ctx.db.listMessages(peerNodeId, limit);
      if (msgs.length === 0) {
        console.log(ui.dim("(no messages)"));
        break;
      }
      for (const m of msgs) {
        const who = m.peer_username || m.peer_node_id;
        const cleanText = identityCrypto.sanitizeTerminal(m.plaintext);
        if (m.direction === "in") console.log(ui.msgIn(who, cleanText, m.created_at));
        else console.log(ui.msgOut(who, cleanText, m.status, m.created_at));
      }
      break;
    }

    case "/passwd": {
      const currentPass = await askHidden("Current passphrase: ");
      let decrypted;
      try {
        decrypted = identityCrypto.decryptBlob(config.loadIdentityBlob(), currentPass);
      } catch {
        console.log(ui.warn("Incorrect current passphrase."));
        break;
      }
      const newPass = await askHidden("New passphrase (min 12 chars): ");
      const strength = identityCrypto.checkPassphraseStrength(newPass);
      if (!strength.valid) {
        console.log(ui.warn(strength.message));
        break;
      }
      const confirm = await askHidden("Confirm new passphrase: ");
      if (confirm !== newPass) {
        console.log(ui.warn("Passphrases did not match."));
        break;
      }
      config.saveIdentityBlob(identityCrypto.encryptBlob(decrypted, newPass));
      ctx.passphrase = newPass;
      console.log(ui.ok("Vault passphrase successfully changed."));
      break;
    }

    case "/panic": {
      console.log(ui.warn("\n!!! EMERGENCY SECURE WIPE INITIATED !!!"));
      console.log(ui.warn("Shredding and destroying local keys, database, and configurations..."));
      if (ctx.socket) ctx.socket.stop();
      ctx.db.close();
      localdb.secureWipe(config.DB_PATH);
      localdb.secureWipe(config.DB_PATH + "-wal");
      localdb.secureWipe(config.DB_PATH + "-shm");
      localdb.secureWipe(config.IDENTITY_PATH);
      localdb.secureWipe(config.CONFIG_PATH);
      console.log(ui.ok("All local data shredded. Exiting immediately.\n"));
      process.exit(0);
    }

    case "/backup": {
      const sub = rest[0];
      if (sub === "export") {
        const exportPath = rest[1] || path.join(config.CONFIG_DIR, `backup-${Date.now()}.enc.json`);
        const allMsgs = ctx.db.listMessages(null, 10000);
        const allPeers = ctx.db.listPeers();
        const sentHistory = {};
        for (const p of allPeers) {
          sentHistory[p.node_id] = ctx.db.getSentHistory(p.node_id);
        }
        const recoveryKey = crypto.randomBytes(16).toString("hex");
        const backupBlob = identityCrypto.exportEncryptedBackup(
          { messages: allMsgs, peers: allPeers, sentHistory },
          recoveryKey
        );
        fs.writeFileSync(exportPath, JSON.stringify(backupBlob, null, 2), { mode: 0o600 });
        console.log(ui.ok(`\n✓ Encrypted backup written to ${exportPath}`));
        console.log(ui.warn(`IMPORTANT: SAVE THIS RECOVERY KEY (offline):\n  ${ui.c.bold}${recoveryKey}${ui.c.reset}\n`));
      } else if (sub === "import") {
        const importPath = rest[1];
        if (!importPath || !fs.existsSync(importPath)) {
          console.log(ui.warn("usage: /backup import <filePath>"));
          break;
        }
        const key = await askHidden("Enter backup recovery key: ");
        try {
          const rawBlob = JSON.parse(fs.readFileSync(importPath, "utf8"));
          const restored = identityCrypto.importEncryptedBackup(rawBlob, key);
          let countMsgs = 0;
          for (const p of restored.peers || []) {
            ctx.db.upsertPeer({
              node_id: p.node_id,
              username: p.username,
              sign_public: p.sign_public,
              ecdh_public: p.ecdh_public,
              mySignPublic: ctx.identity.signPublic,
            });
          }
          for (const m of (restored.messages || []).reverse()) {
            ctx.db.ingestMessage({
              direction: m.direction,
              peerNodeId: m.peer_node_id,
              peerUsername: m.peer_username,
              plaintext: m.plaintext,
              status: m.status,
              clientEventId: m.client_event_id,
              timestamp: m.created_at,
            });
            countMsgs++;
          }
          console.log(ui.ok(`\n✓ Backup restored successfully (${countMsgs} messages, ${(restored.peers || []).length} contacts).`));
        } catch (err) {
          console.log(ui.warn(`Backup restore failed: ${err.message}`));
        }
      } else {
        console.log(ui.warn("usage: /backup export [path] | /backup import <path>"));
      }
      break;
    }

    case "/quit":
    case "/exit":
      rl.close();
      break;

    default:
      console.log(ui.warn(`unknown command: ${cmd} (try /help)`));
  }
}

function printContacts(ctx) {
  const peers = ctx.db.listPeers();
  if (peers.length === 0) {
    console.log(ui.dim("(no contacts yet — exchange an /invite link first)"));
    return;
  }
  console.log(`\n${ui.c.bold}Contacts:${ui.c.reset}`);
  for (const p of peers) {
    const isOk = p.status === "verified";
    const statusLabel = isOk ? ui.ok("VERIFIED") : ui.warn("KEY MISMATCH");
    const num = identityCrypto.safetyNumber(ctx.identity.signPublic, p.sign_public);
    console.log(`  ● ${p.username.padEnd(14)} [${statusLabel}] Safety: ${num.slice(0, 11)}...`);
  }
  console.log("");
}

async function acceptInviteLink(ctx, link) {
  try {
    const url = new URL(link.replace("sdmesh://", "http://placeholder/"));
    const peerNodeId = url.searchParams.get("node");
    const peerUsername = url.searchParams.get("username");
    const signPub = url.searchParams.get("sign");
    const ecdhPub = url.searchParams.get("ecdh");
    const peerMailbox = url.searchParams.get("mailbox");

    if (!peerNodeId || !peerUsername || !signPub || !ecdhPub) {
      console.log(ui.warn("invalid invite link: missing parameters"));
      return;
    }

    // TOFU Key Pinning (C1)
    const result = ctx.db.upsertPeer({
      node_id: peerNodeId,
      username: peerUsername,
      sign_public: signPub,
      ecdh_public: ecdhPub,
      mySignPublic: ctx.identity.signPublic,
    });

    // Derive pairwise mailboxes
    const sharedSecret = identityCrypto.deriveRawSharedSecret(ctx.identity.ecdhPrivate, ecdhPub);
    const myInboundMailbox = identityCrypto.derivePairwiseMailbox(sharedSecret, peerNodeId, ctx.nodeId);
    const outboundMailbox = peerMailbox || identityCrypto.derivePairwiseMailbox(sharedSecret, ctx.nodeId, peerNodeId);

    ctx.db.setMailboxes(peerNodeId, myInboundMailbox, outboundMailbox);

    if (ctx.socket && ctx.online) {
      ctx.socket.send({ type: "mailbox_subscribe", mailbox_id: myInboundMailbox });
    }

    const num = identityCrypto.safetyNumber(ctx.identity.signPublic, signPub);
    console.log(ui.ok(`\n✓ Contact "${peerUsername}" added & pinned (TOFU).`));
    console.log(`Safety Number: ${ui.c.cyan}${num}${ui.c.reset}\n`);
  } catch (err) {
    console.log(ui.warn(`Failed to accept invite: ${err.message}`));
  }
}

async function sendMessage(ctx, username, text) {
  const peer = ctx.db.getPeerByUsername(username);
  if (!peer) {
    console.log(ui.warn(`unknown contact "${username}" — add via /accept <link>`));
    return;
  }

  // Hard stop on key mismatch (C1)
  if (peer.status === "key_mismatch") {
    console.log(ui.warn(`SECURITY ALERT: Public key for "${username}" has changed! Sending blocked.`));
    console.log(ui.warn("Use /verify to inspect the safety number before re-verifying."));
    return;
  }

  const sharedSecret = identityCrypto.deriveRawSharedSecret(ctx.identity.ecdhPrivate, peer.ecdh_public);
  const clientEventId = crypto.randomUUID();
  const counter = ctx.db.nextSendCounter(peer.node_id);

  // Protocol v2 Envelope (C2): Directional key, AAD binding, sealed sender, padded bucket
  const envelope = identityCrypto.encryptEnvelope({
    plaintext: text,
    sharedSecret,
    fromId: ctx.nodeId,
    toId: peer.node_id,
    msgId: clientEventId,
    counter,
    bucketSize: 1024,
  });

  // Outbox persistence FIRST (C7): Retain until recipient E2E delivered ack (Addendum 9.2)
  ctx.db.queueOutbox({
    clientEventId,
    eventType: "MAILBOX_ENVELOPE",
    payload: {
      mailbox_id: peer.outbound_mailbox || identityCrypto.derivePairwiseMailbox(sharedSecret, ctx.nodeId, peer.node_id),
      msg_id: clientEventId,
      envelope,
    },
  });

  // Record sent history for retransmit / gap filling (Addendum 9.2)
  ctx.db.recordSentHistory({
    peerNodeId: peer.node_id,
    msgId: clientEventId,
    counter,
    envelope,
    plaintext: text,
  });

  ctx.db.ingestMessage({
    direction: "out",
    peerNodeId: peer.node_id,
    peerUsername: peer.username,
    plaintext: text,
    status: "queued",
    clientEventId,
  });

  const mailboxId = peer.outbound_mailbox || identityCrypto.derivePairwiseMailbox(sharedSecret, ctx.nodeId, peer.node_id);

  // Send via WebSocket mailbox_put if online
  const sentOverWs = ctx.socket && ctx.socket.send({
    type: "mailbox_put",
    mailbox_id: mailboxId,
    msg_id: clientEventId,
    envelope,
  });

  if (sentOverWs) {
    ctx.db.markMessageStatus(clientEventId, "sent");
    console.log(ui.msgOut(peer.username, identityCrypto.sanitizeTerminal(text), "sent"));
  } else {
    console.log(ui.msgOut(peer.username, identityCrypto.sanitizeTerminal(text), "queued — offline"));
  }
}

module.exports = { startRepl };
