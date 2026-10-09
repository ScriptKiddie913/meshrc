"use strict";

const fs = require("fs");
const { DatabaseSync } = require("node:sqlite");
const crypto = require("./crypto");

function secureFilePermissions(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.chmodSync(filePath, 0o600);
    }
  } catch {}
}

function secureWipe(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const stat = fs.statSync(filePath);
      if (stat.size > 0) {
        const rand = require("crypto").randomBytes(stat.size);
        const fd = fs.openSync(filePath, "r+");
        fs.writeSync(fd, rand, 0, rand.length, 0);
        fs.fsyncSync(fd);
        fs.closeSync(fd);
      }
      fs.unlinkSync(filePath);
      return true;
    }
  } catch {}
  return false;
}

/**
 * Local mirror of mesh state.
 * Uses Node's built-in node:sqlite with field-level encryption (C4), TOFU pinning, and sent history.
 */
function open(dbPath, { dataKey = null } = {}) {
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL");
  secureFilePermissions(dbPath);
  secureFilePermissions(`${dbPath}-wal`);
  secureFilePermissions(`${dbPath}-shm`);

  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS peers (
      node_id          TEXT PRIMARY KEY,
      username         TEXT UNIQUE NOT NULL,
      sign_public      TEXT NOT NULL,
      ecdh_public      TEXT NOT NULL,
      last_seen        INTEGER,
      online           INTEGER NOT NULL DEFAULT 0,
      status           TEXT NOT NULL DEFAULT 'verified', -- verified | key_mismatch
      safety_number    TEXT,
      send_counter     INTEGER NOT NULL DEFAULT 0,
      recv_counter     INTEGER NOT NULL DEFAULT 0,
      inbound_mailbox  TEXT,
      outbound_mailbox TEXT
    );

    CREATE TABLE IF NOT EXISTS events (
      global_seq  INTEGER PRIMARY KEY,
      event_id    TEXT NOT NULL,
      node_id     TEXT NOT NULL,
      event_type  TEXT NOT NULL,
      payload     TEXT NOT NULL,
      signature   TEXT,
      timestamp   INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      direction     TEXT NOT NULL,      -- 'in' | 'out'
      peer_node_id  TEXT NOT NULL,
      peer_username TEXT,
      plaintext     TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'queued', -- queued|sent|stored|delivered|received|undelivered
      client_event_id TEXT,
      global_seq    INTEGER,
      created_at    INTEGER NOT NULL
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_peer_client_event
      ON messages(peer_node_id, client_event_id)
      WHERE client_event_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS outbox (
      client_event_id TEXT PRIMARY KEY,
      event_type       TEXT NOT NULL,
      payload           TEXT NOT NULL,
      signature         TEXT,
      created_at        INTEGER NOT NULL,
      retries           INTEGER NOT NULL DEFAULT 0,
      next_retry_at     INTEGER NOT NULL DEFAULT 0
    );

    -- Sent history for gap filling & disaster retransmission (Addendum 9.2)
    CREATE TABLE IF NOT EXISTS sent_history (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      peer_node_id TEXT NOT NULL,
      msg_id       TEXT NOT NULL,
      counter      INTEGER NOT NULL,
      envelope     TEXT NOT NULL,
      plaintext    TEXT NOT NULL,
      created_at   INTEGER NOT NULL,
      UNIQUE(peer_node_id, msg_id)
    );
  `);

  const stmt = {
    getMeta: db.prepare("SELECT value FROM meta WHERE key = ?"),
    setMeta: db.prepare(
      "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ),
    getPeerByNodeId: db.prepare("SELECT * FROM peers WHERE node_id = ?"),
    getPeerByUsername: db.prepare("SELECT * FROM peers WHERE username = ?"),
    listPeers: db.prepare("SELECT * FROM peers ORDER BY username ASC"),
    setPeerOnline: db.prepare("UPDATE peers SET online = ? WHERE node_id = ?"),
    insertPeer: db.prepare(`
      INSERT INTO peers (node_id, username, sign_public, ecdh_public, last_seen, online, status, safety_number, send_counter, recv_counter, inbound_mailbox, outbound_mailbox)
      VALUES (@node_id, @username, @sign_public, @ecdh_public, @last_seen, 0, 'verified', @safety_number, 0, 0, @inbound_mailbox, @outbound_mailbox)
    `),
    updatePeerOnlineTime: db.prepare("UPDATE peers SET last_seen = ? WHERE node_id = ?"),
    updatePeerStatus: db.prepare("UPDATE peers SET status = ? WHERE node_id = ?"),
    incrementSendCounter: db.prepare("UPDATE peers SET send_counter = send_counter + 1 WHERE node_id = ?"),
    updateRecvCounter: db.prepare("UPDATE peers SET recv_counter = MAX(recv_counter, ?) WHERE node_id = ?"),
    setMailboxes: db.prepare(
      "UPDATE peers SET inbound_mailbox = COALESCE(?, inbound_mailbox), outbound_mailbox = COALESCE(?, outbound_mailbox) WHERE node_id = ?"
    ),
    insertEvent: db.prepare(`
      INSERT OR IGNORE INTO events (global_seq, event_id, node_id, event_type, payload, signature, timestamp)
      VALUES (@global_seq, @event_id, @node_id, @event_type, @payload, @signature, @timestamp)
    `),
    maxGlobalSeq: db.prepare("SELECT COALESCE(MAX(global_seq), 0) AS seq FROM events"),
    getMessageByClientEventId: db.prepare(
      "SELECT * FROM messages WHERE peer_node_id = ? AND client_event_id = ?"
    ),
    insertMessage: db.prepare(`
      INSERT INTO messages (direction, peer_node_id, peer_username, plaintext, status, client_event_id, global_seq, created_at)
      VALUES (@direction, @peer_node_id, @peer_username, @plaintext, @status, @client_event_id, @global_seq, @created_at)
    `),
    updateMessageStatusByClientEventId: db.prepare(
      "UPDATE messages SET status = ?, global_seq = COALESCE(?, global_seq) WHERE client_event_id = ?"
    ),
    listMessages: db.prepare(`
      SELECT * FROM messages WHERE (@peerNodeId IS NULL OR peer_node_id = @peerNodeId)
      ORDER BY id DESC LIMIT @limit
    `),
    insertOutbox: db.prepare(`
      INSERT OR IGNORE INTO outbox (client_event_id, event_type, payload, signature, created_at, retries, next_retry_at)
      VALUES (@client_event_id, @event_type, @payload, @signature, @created_at, 0, @created_at)
    `),
    listOutbox: db.prepare("SELECT * FROM outbox ORDER BY created_at ASC LIMIT 500"),
    countOutbox: db.prepare("SELECT COUNT(*) AS n FROM outbox"),
    clearOutbox: db.prepare("DELETE FROM outbox WHERE client_event_id = ?"),
    insertSentHistory: db.prepare(`
      INSERT OR IGNORE INTO sent_history (peer_node_id, msg_id, counter, envelope, plaintext, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `),
    getSentHistoryByPeer: db.prepare(
      "SELECT * FROM sent_history WHERE peer_node_id = ? ORDER BY counter ASC"
    ),
    countEvents: db.prepare("SELECT COUNT(*) AS n FROM events"),
    listAllEvents: db.prepare("SELECT * FROM events ORDER BY global_seq ASC"),
  };

  return {
    raw: db,

    getMeta(key, fallback = null) {
      const row = stmt.getMeta.get(key);
      return row ? row.value : fallback;
    },
    setMeta(key, value) {
      stmt.setMeta.run(key, String(value));
    },

    /**
     * TOFU Key Pinning (C1)
     * If a peer already exists, keys MUST match the pinned bundle.
     * Mismatches trigger a hard security alert and mark status as 'key_mismatch'.
     */
    upsertPeer({ node_id, username, sign_public, ecdh_public, last_seen = Date.now(), mySignPublic = "" }) {
      const existing = stmt.getPeerByNodeId.get(node_id);
      const safetyNum = mySignPublic ? crypto.safetyNumber(mySignPublic, sign_public) : null;

      if (!existing) {
        stmt.insertPeer.run({
          node_id,
          username,
          sign_public,
          ecdh_public,
          last_seen,
          safety_number: safetyNum,
          inbound_mailbox: null,
          outbound_mailbox: null,
        });
        return { isNew: true, status: "verified" };
      }

      // Check for key mismatch
      if (existing.sign_public !== sign_public || existing.ecdh_public !== ecdh_public) {
        stmt.updatePeerStatus.run("key_mismatch", node_id);
        const err = new Error(
          `SECURITY WARNING: Public key bundle for peer "${username}" (${node_id}) has CHANGED! Possible Man-In-The-Middle attack.`
        );
        err.code = "KEY_MISMATCH";
        err.nodeId = node_id;
        throw err;
      }

      stmt.updatePeerOnlineTime.run(last_seen, node_id);
      return { isNew: false, status: existing.status };
    },

    setPeerStatus(nodeId, status) {
      stmt.updatePeerStatus.run(status, nodeId);
    },

    setPeerOnline(nodeId, online) {
      stmt.setPeerOnline.run(online ? 1 : 0, nodeId);
    },

    setMailboxes(nodeId, inboundMailbox, outboundMailbox) {
      stmt.setMailboxes.run(inboundMailbox || null, outboundMailbox || null, nodeId);
    },

    nextSendCounter(nodeId) {
      const p = stmt.getPeerByNodeId.get(nodeId);
      const next = (p ? p.send_counter : 0) + 1;
      stmt.incrementSendCounter.run(nodeId);
      return next;
    },

    updateRecvCounter(nodeId, counter) {
      stmt.updateRecvCounter.run(Number(counter) || 0, nodeId);
    },

    listPeers() {
      return stmt.listPeers.all();
    },
    getPeerByNodeId(nodeId) {
      return stmt.getPeerByNodeId.get(nodeId);
    },
    getPeerByUsername(username) {
      return stmt.getPeerByUsername.get(username);
    },

    applyEvent(row) {
      const res = stmt.insertEvent.run({
        global_seq: row.global_seq,
        event_id: row.event_id,
        node_id: row.node_id,
        event_type: row.event_type,
        payload: typeof row.payload === "string" ? row.payload : JSON.stringify(row.payload),
        signature: row.signature || null,
        timestamp: row.timestamp || Date.now(),
      });
      return res.changes > 0;
    },
    lastGlobalSeq() {
      return stmt.maxGlobalSeq.get().seq;
    },
    eventCount() {
      return stmt.countEvents.get().n;
    },
    listAllEvents() {
      return stmt.listAllEvents.all();
    },

    ingestMessage({ direction, peerNodeId, peerUsername, plaintext, status, clientEventId = null, globalSeq = null, eventId = null, timestamp = null }) {
      if (clientEventId) {
        const existing = stmt.getMessageByClientEventId.get(peerNodeId, clientEventId);
        if (existing) {
          if (globalSeq && !existing.global_seq) {
            stmt.updateMessageStatusByClientEventId.run(existing.status, globalSeq, clientEventId);
          }
          return { id: existing.id, isNew: false };
        }
      }

      if (globalSeq && eventId) {
        stmt.insertEvent.run({
          global_seq: globalSeq,
          event_id: eventId,
          node_id: peerNodeId,
          event_type: "MESSAGE_CREATED",
          payload: JSON.stringify({ target_node_id: peerNodeId, ciphertext: "" }),
          signature: null,
          timestamp: timestamp || Date.now(),
        });
      }

      const storedPlaintext = dataKey ? crypto.encryptField(plaintext, dataKey) : plaintext;
      const res = stmt.insertMessage.run({
        direction,
        peer_node_id: peerNodeId,
        peer_username: peerUsername || null,
        plaintext: storedPlaintext,
        status,
        client_event_id: clientEventId,
        global_seq: globalSeq,
        created_at: timestamp || Date.now(),
      });
      secureFilePermissions(dbPath);
      secureFilePermissions(`${dbPath}-wal`);
      return { id: res.lastInsertRowid, isNew: true };
    },

    markMessageStatus(clientEventId, status, globalSeq = null) {
      if (!clientEventId) return;
      stmt.updateMessageStatusByClientEventId.run(status, globalSeq, clientEventId);
    },

    listMessages(peerNodeId = null, limit = 30) {
      const rows = stmt.listMessages.all({ peerNodeId, limit }).reverse();
      if (dataKey) {
        for (const row of rows) {
          row.plaintext = crypto.decryptField(row.plaintext, dataKey);
        }
      }
      return rows;
    },

    queueOutbox({ clientEventId, eventType, payload, signature = null }) {
      stmt.insertOutbox.run({
        client_event_id: clientEventId,
        event_type: eventType,
        payload: typeof payload === "string" ? payload : JSON.stringify(payload),
        signature,
        created_at: Date.now(),
      });
    },
    listOutbox() {
      return stmt.listOutbox.all();
    },
    outboxCount() {
      return stmt.countOutbox.get().n;
    },
    clearOutboxEntry(clientEventId) {
      stmt.clearOutbox.run(clientEventId);
    },

    recordSentHistory({ peerNodeId, msgId, counter, envelope, plaintext }) {
      const storedPlaintext = dataKey ? crypto.encryptField(plaintext, dataKey) : plaintext;
      stmt.insertSentHistory.run(peerNodeId, msgId, counter, envelope, storedPlaintext, Date.now());
      secureFilePermissions(dbPath);
      secureFilePermissions(`${dbPath}-wal`);
      secureFilePermissions(`${dbPath}-shm`);
    },
    getSentHistory(peerNodeId) {
      const rows = stmt.getSentHistoryByPeer.all(peerNodeId);
      if (dataKey) {
        for (const r of rows) {
          r.plaintext = crypto.decryptField(r.plaintext, dataKey);
        }
      }
      return rows;
    },

    close() {
      db.close();
    },
  };
}

module.exports = { open, secureWipe, secureFilePermissions };
