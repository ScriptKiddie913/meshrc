"use strict";

const crypto = require("crypto");
const readline = require("readline");
const ui = require("./ui");
const api = require("./api");
const identityCrypto = require("./crypto");
const syncMod = require("./sync");

const HELP = `
${ui.c.bold}Commands${ui.c.reset}
  /status                 connection + sync dashboard
  /peers                  refresh and list known peers
  /msg <user> <text...>   send an encrypted message
  /history [user] [n]     show recent messages (default: all, 30)
  /sync                   force a two-way sync with Render now
  /backup push            push an encrypted snapshot of local state to Render
  /backup pull            restore local state from the Render-stored snapshot
  /whoami                 show this node's identity
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
    ctx.socket.stop();
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
          `${ui.c.bold}render${ui.c.reset}     ${ctx.renderUrl}`,
        ].join("\n")
      );
      break;
    }

    case "/peers": {
      if (!ctx.online) {
        console.log(ui.warn("offline — showing local peer cache"));
        printPeers(ctx);
        break;
      }
      await syncMod.refreshPeers(ctx);
      printPeers(ctx);
      break;
    }

    case "/sync": {
      if (!ctx.online) {
        console.log(ui.warn("offline — nothing to sync against. Message will send once Render is reachable."));
        break;
      }
      const res = await syncMod.syncNow(ctx);
      await syncMod.refreshPeers(ctx);
      console.log(ui.ok(`synced — global_seq ${res.global_seq}, ${(res.missing_events || []).length} new event(s) pulled`));
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
          console.log(ui.warn(`unknown peer: ${uname}`));
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
        if (m.direction === "in") console.log(ui.msgIn(who, m.plaintext, m.created_at));
        else console.log(ui.msgOut(who, m.plaintext, m.status, m.created_at));
      }
      break;
    }

    case "/msg": {
      const username = rest.shift();
      const text = rest.join(" ");
      if (!username || !text) {
        console.log(ui.warn("usage: /msg <user> <text>"));
        break;
      }
      await sendMessage(ctx, username, text);
      break;
    }

    case "/backup": {
      const sub = rest[0];
      if (sub === "push") await backupPush(ctx);
      else if (sub === "pull") await backupPull(ctx);
      else console.log(ui.warn("usage: /backup push | /backup pull"));
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

function printPeers(ctx) {
  const peers = ctx.db.listPeers();
  if (peers.length === 0) {
    console.log(ui.dim("(no known peers)"));
    return;
  }
  for (const p of peers) {
    const state = p.online ? ui.ok("ONLINE") : ui.dim("OFFLINE");
    console.log(`  ${p.online ? ui.c.green + "●" : ui.c.gray + "○"}${ui.c.reset} ${p.username.padEnd(16)} ${state}`);
  }
}

async function sendMessage(ctx, username, text) {
  const peer = ctx.db.getPeerByUsername(username);
  if (!peer) {
    console.log(ui.warn(`unknown peer "${username}" — try /sync or /peers`));
    return;
  }

  const sharedKey = identityCrypto.deriveSharedKey(ctx.identity.ecdhPrivate, peer.ecdh_public);
  const ciphertext = identityCrypto.encryptMessage(text, sharedKey);
  const clientEventId = crypto.randomUUID();

  const sentOverWs = ctx.socket.send({
    type: "message",
    target_node_id: peer.node_id,
    ciphertext,
    client_event_id: clientEventId,
  });

  const status = sentOverWs ? "pending" : "queued";
  ctx.db.addMessage({
    direction: "out",
    peerNodeId: peer.node_id,
    peerUsername: peer.username,
    plaintext: text,
    status,
    clientEventId,
  });

  if (!sentOverWs) {
    // No live connection — fall back to the event outbox, delivered on next /sync.
    ctx.db.queueOutbox({
      clientEventId,
      eventType: "MESSAGE_CREATED",
      payload: { target_node_id: peer.node_id, ciphertext },
    });
    console.log(ui.msgOut(peer.username, text, "queued — offline"));
  } else {
    console.log(ui.msgOut(peer.username, text, "sent"));
  }
}

async function backupPush(ctx) {
  if (!ctx.online) {
    console.log(ui.warn("offline — can't push backup right now"));
    return;
  }
  const snapshot = {
    version: 1,
    created_at: Date.now(),
    events: ctx.db.listAllEvents(),
    peers: ctx.db.listPeers(),
  };
  const envelope = identityCrypto.encryptBlob(snapshot, ctx.passphrase);
  await api.putBackup(ctx.renderUrl, ctx.auth, JSON.stringify(envelope));
  console.log(ui.ok(`backup pushed — ${snapshot.events.length} event(s), ${snapshot.peers.length} peer(s), encrypted client-side`));
}

async function backupPull(ctx) {
  if (!ctx.online) {
    console.log(ui.warn("offline — can't pull backup right now"));
    return;
  }
  let res;
  try {
    res = await api.getBackup(ctx.renderUrl, ctx.auth);
  } catch (err) {
    if (err.status === 404) return console.log(ui.warn("no backup stored on Render for this node"));
    throw err;
  }
  const envelope = JSON.parse(res.blob);
  let snapshot;
  try {
    snapshot = identityCrypto.decryptBlob(envelope, ctx.passphrase);
  } catch {
    console.log(ui.warn("could not decrypt backup — wrong passphrase for this snapshot?"));
    return;
  }
  for (const p of snapshot.peers || []) {
    ctx.db.upsertPeer(p);
  }
  syncMod.applyMissingEvents(ctx, snapshot.events || []);
  console.log(
    ui.ok(`backup restored — merged ${(snapshot.events || []).length} event(s), ${(snapshot.peers || []).length} peer(s)`)
  );
}

module.exports = { startRepl };
