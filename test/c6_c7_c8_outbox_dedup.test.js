"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

const localdb = require("../src/localdb");

test("C6, C7, C8: localdb deduplicates inbound messages, manages outbox, and updates by client_event_id", async () => {
  const dbPath = path.join(__dirname, "temp_client_test.db");
  try { fs.unlinkSync(dbPath); } catch {}

  const db = localdb.open(dbPath);

  // C6 Test: Ingest duplicate message
  const msg1 = db.ingestMessage({
    direction: "in",
    peerNodeId: "bob-node",
    peerUsername: "bob",
    plaintext: "Hello Alice",
    status: "received",
    clientEventId: "client-msg-uuid-1",
    globalSeq: 10,
  });
  assert.equal(msg1.isNew, true, "First message must be new");

  // Ingest identical message again (e.g. from /sync after live ws)
  const msg2 = db.ingestMessage({
    direction: "in",
    peerNodeId: "bob-node",
    peerUsername: "bob",
    plaintext: "Hello Alice",
    status: "received",
    clientEventId: "client-msg-uuid-1",
    globalSeq: 10,
  });
  assert.equal(msg2.isNew, false, "Second message with same client_event_id must not be inserted again");

  const allMsgs = db.listMessages("bob-node", 10);
  assert.equal(allMsgs.length, 1, "Only 1 message row should exist in database");

  // C7 Test: Transactional outbox
  db.queueOutbox({
    clientEventId: "outbox-msg-1",
    eventType: "MESSAGE_CREATED",
    payload: { target_node_id: "bob-node", ciphertext: "encrypted-blob" },
  });
  assert.equal(db.outboxCount(), 1, "Outbox should have 1 queued item");

  // Record initial queued message
  db.ingestMessage({
    direction: "out",
    peerNodeId: "bob-node",
    peerUsername: "bob",
    plaintext: "Outgoing message",
    status: "queued",
    clientEventId: "outbox-msg-1",
  });

  // C8 Test: Exact status update by client_event_id
  db.markMessageStatus("outbox-msg-1", "stored", 11);
  db.clearOutboxEntry("outbox-msg-1");

  assert.equal(db.outboxCount(), 0, "Outbox should be empty after clearOutboxEntry");
  const storedMsg = db.listMessages("bob-node", 10).find((m) => m.client_event_id === "outbox-msg-1");
  assert.equal(storedMsg.status, "stored");
  assert.equal(storedMsg.global_seq, 11);

  db.close();
  try { fs.unlinkSync(dbPath); } catch {}
});
