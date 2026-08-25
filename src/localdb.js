"use strict";

const Database = require("better-sqlite3");

/**
 * Local mirror of mesh state. Per the architecture: Render is not the only
 * data copy. Every client keeps its own event log, peer cache, message
 * history, and backup — so the mesh keeps functioning if Render is down.
 */
function open(dbPath) {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS peers (
      node_id     TEXT PRIMARY KEY,
      username    TEXT UNIQUE NOT NULL,
      sign_public TEXT NOT NULL,
      ecdh_public TEXT NOT NULL,
      last_seen   INTEGER,
      online      INTEGER NOT NULL DEFAULT 0
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
      status        TEXT NOT NULL DEFAULT 'local', -- local|pending|delivered|queued|received
      client_event_id TEXT,
      global_seq    INTEGER,
      created_at    INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS outbox (
      client_event_id TEXT PRIMARY KEY,
      event_type       TEXT NOT NULL,
      payload           TEXT NOT NULL,
      signature         TEXT,
      created_at        INTEGER NOT NULL
    );
  `);

  const stmt = {
    getMeta: db.prepare("SELECT value FROM meta WHERE key = ?"),
    setMeta: db.prepare(
      "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ),
    upsertPeer: db.prepare(`
      INSERT INTO peers (node_id, username, sign_public, ecdh_public, last_seen, online)
      VALUES (@node_id, @username, @sign_public, @ecdh_public, @last_seen, 0)
      ON CONFLICT(node_id) DO UPDATE SET
        username = excluded.username,
        sign_public = excluded.sign_public,
        ecdh_public = excluded.ecdh_public,
        last_seen = excluded.last_seen
    `),
    setPeerOnline: db.prepare("UPDATE peers SET online = ? WHERE node_id = ?"),
    listPeers: db.prepare("SELECT * FROM peers ORDER BY username ASC"),
    getPeerByNodeId: db.prepare("SELECT * FROM peers WHERE node_id = ?"),
    getPeerByUsername: db.prepare("SELECT * FROM peers WHERE username = ?"),
    insertEvent: db.prepare(`
      INSERT OR IGNORE INTO events (global_seq, event_id, node_id, event_type, payload, signature, timestamp)
      VALUES (@global_seq, @event_id, @node_id, @event_type, @payload, @signature, @timestamp)
    `),
    maxGlobalSeq: db.prepare("SELECT COALESCE(MAX(global_seq), 0) AS seq FROM events"),
    insertMessage: db.prepare(`
      INSERT INTO messages (direction, peer_node_id, peer_username, plaintext, status, client_event_id, global_seq, created_at)
      VALUES (@direction, @peer_node_id, @peer_username, @plaintext, @status, @client_event_id, @global_seq, @created_at)
    `),
    updateMessageStatusByClientEventId: db.prepare(
      "UPDATE messages SET status = ?, global_seq = COALESCE(?, global_seq) WHERE client_event_id = ?"
    ),
    latestPendingToPeer: db.prepare(
      "SELECT id FROM messages WHERE peer_node_id = ? AND status = 'pending' ORDER BY id DESC LIMIT 1"
    ),
    listMessages: db.prepare(`
      SELECT * FROM messages WHERE (@peerNodeId IS NULL OR peer_node_id = @peerNodeId)
      ORDER BY id DESC LIMIT @limit
    `),
    insertOutbox: db.prepare(`
      INSERT OR IGNORE INTO outbox (client_event_id, event_type, payload, signature, created_at)
      VALUES (@client_event_id, @event_type, @payload, @signature, @created_at)
    `),
    listOutbox: db.prepare("SELECT * FROM outbox ORDER BY created_at ASC LIMIT 500"),
    countOutbox: db.prepare("SELECT COUNT(*) AS n FROM outbox"),
    clearOutbox: db.prepare("DELETE FROM outbox WHERE client_event_id = ?"),
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

    upsertPeer({ node_id, username, sign_public, ecdh_public, last_seen = Date.now() }) {
      stmt.upsertPeer.run({ node_id, username, sign_public, ecdh_public, last_seen });
    },
    setPeerOnline(nodeId, online) {
      stmt.setPeerOnline.run(online ? 1 : 0, nodeId);
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

    /** Insert a server event row locally (idempotent) and return whether it was new. */
    applyEvent(row) {
      const res = stmt.insertEvent.run({
        global_seq: row.global_seq,
        event_id: row.event_id,
        node_id: row.node_id,
        event_type: row.event_type,
        payload: typeof row.payload === "string" ? row.payload : JSON.stringify(row.payload),
        signature: row.signature || null,
        timestamp: row.timestamp,
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

    addMessage({ direction, peerNodeId, peerUsername, plaintext, status, clientEventId = null, globalSeq = null }) {
      const res = stmt.insertMessage.run({
        direction,
        peer_node_id: peerNodeId,
        peer_username: peerUsername || null,
        plaintext,
        status,
        client_event_id: clientEventId,
        global_seq: globalSeq,
        created_at: Date.now(),
      });
      return res.lastInsertRowid;
    },
    markMessageStatus(clientEventId, status, globalSeq = null) {
      stmt.updateMessageStatusByClientEventId.run(status, globalSeq, clientEventId);
    },
    latestPendingMessageTo(peerNodeId) {
      return stmt.latestPendingToPeer.get(peerNodeId);
    },
    listMessages(peerNodeId = null, limit = 30) {
      return stmt.listMessages.all({ peerNodeId, limit }).reverse();
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

    close() {
      db.close();
    },
  };
}

module.exports = { open };
