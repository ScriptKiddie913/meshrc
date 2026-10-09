"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("../src/crypto");
const localdb = require("../src/localdb");

test("C4: Field-level encryption in mesh.db prevents plaintext exposure in raw database bytes", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sdmesh-c4-"));
  const dbPath = path.join(tmpDir, "mesh.db");
  const dataKey = crypto.generateDataKey();

  const db = localdb.open(dbPath, { dataKey });

  const SECRET_MESSAGE = "TOP_SECRET_PLAINTEXT_PAYLOAD_987654321_XYZZY";
  const PEER_ID = "peer-alpha-123";

  // Ingest message and record sent history
  db.ingestMessage({
    direction: "out",
    peerNodeId: PEER_ID,
    peerUsername: "alice",
    plaintext: SECRET_MESSAGE,
    status: "sent",
    clientEventId: "evt-12345",
  });

  db.recordSentHistory({
    peerNodeId: PEER_ID,
    msgId: "evt-12345",
    counter: 1,
    envelope: "enc_blob",
    plaintext: SECRET_MESSAGE,
  });

  db.close();

  // Inspect raw file bytes on disk (equivalent to `strings mesh.db | grep <plaintext>`)
  const dbBytes = fs.readFileSync(dbPath);
  const foundInDb = dbBytes.includes(Buffer.from(SECRET_MESSAGE, "utf8"));
  assert.equal(foundInDb, false, "CRITICAL: Plaintext MUST NOT appear anywhere in mesh.db raw bytes");

  const walPath = `${dbPath}-wal`;
  if (fs.existsSync(walPath)) {
    const walBytes = fs.readFileSync(walPath);
    const foundInWal = walBytes.includes(Buffer.from(SECRET_MESSAGE, "utf8"));
    assert.equal(foundInWal, false, "CRITICAL: Plaintext MUST NOT appear in mesh.db-wal raw bytes");
  }

  // Re-open with dataKey and verify transparent decryption
  const dbReopened = localdb.open(dbPath, { dataKey });
  const msgs = dbReopened.listMessages(PEER_ID);
  assert.equal(msgs.length, 1);
  assert.equal(msgs[0].plaintext, SECRET_MESSAGE, "Decrypted message must match original plaintext");

  const sent = dbReopened.getSentHistory(PEER_ID);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].plaintext, SECRET_MESSAGE, "Decrypted sent history must match original plaintext");
  dbReopened.close();

  // Test secure wipe (/panic)
  const wiped = localdb.secureWipe(dbPath);
  assert.equal(wiped, true);
  assert.equal(fs.existsSync(dbPath), false, "File must be securely shredded and unlinked");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("C12: Vault crypto hygiene, min 12 chars check, and key-check canary", () => {
  // 1. Passphrase strength check
  const short = crypto.checkPassphraseStrength("short789");
  assert.equal(short.valid, false);

  const weak = crypto.checkPassphraseStrength("alllowercasenootherstuff");
  assert.equal(weak.valid, false);

  const strong = crypto.checkPassphraseStrength("CorrectHorseBatteryStaple123!");
  assert.equal(strong.valid, true);

  // 2. Encryption and canary verification
  const secretPayload = { secret: "hunter2", sign_private: "private_key_data" };
  const passphrase = "CorrectHorseBatteryStaple123!";
  const encrypted = crypto.encryptBlob(secretPayload, passphrase);

  assert.equal(encrypted.v, 2);
  assert.equal(encrypted.kdf.N, 131072, "Must use scrypt N=2^17 (131072)");
  assert.ok(encrypted.canary, "Canary must be present in encrypted vault");

  // Decrypt with correct passphrase
  const decrypted = crypto.decryptBlob(encrypted, passphrase);
  assert.deepEqual(decrypted, secretPayload);

  // Decrypt with wrong passphrase must fail immediately via canary or tag
  assert.throws(() => {
    crypto.decryptBlob(encrypted, "WrongPassphrase123!");
  });
});

test("C11: Encrypted backup export and import round-trip restores messages, peers, and sent history", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sdmesh-c11-"));
  const dbPath = path.join(tmpDir, "mesh.db");
  const dataKey = crypto.generateDataKey();

  const db = localdb.open(dbPath, { dataKey });

  // Populate state
  db.upsertPeer({
    node_id: "bob-node-1",
    username: "bob",
    sign_public: "sign_bob_pub",
    ecdh_public: "ecdh_bob_pub",
  });

  db.ingestMessage({
    direction: "out",
    peerNodeId: "bob-node-1",
    peerUsername: "bob",
    plaintext: "Hello Bob from backup test",
    status: "sent",
    clientEventId: "msg-bob-1",
  });

  const allMsgs = db.listMessages(null, 100);
  const allPeers = db.listPeers();
  const sentHistory = { "bob-node-1": db.getSentHistory("bob-node-1") };

  const backupKey = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c";
  const backupBlob = crypto.exportEncryptedBackup(
    { messages: allMsgs, peers: allPeers, sentHistory },
    backupKey
  );

  assert.equal(backupBlob.v, 2);
  db.close();

  // Create a brand new clean database
  const restoredDbPath = path.join(tmpDir, "mesh_restored.db");
  const restoredDb = localdb.open(restoredDbPath, { dataKey });

  // Decrypt and restore
  const restored = crypto.importEncryptedBackup(backupBlob, backupKey);
  for (const p of restored.peers) {
    restoredDb.upsertPeer({
      node_id: p.node_id,
      username: p.username,
      sign_public: p.sign_public,
      ecdh_public: p.ecdh_public,
    });
  }
  for (const m of restored.messages.reverse()) {
    restoredDb.ingestMessage({
      direction: m.direction,
      peerNodeId: m.peer_node_id,
      peerUsername: m.peer_username,
      plaintext: m.plaintext,
      status: m.status,
      clientEventId: m.client_event_id,
      timestamp: m.created_at,
    });
  }

  const restoredMsgs = restoredDb.listMessages("bob-node-1");
  assert.equal(restoredMsgs.length, 1);
  assert.equal(restoredMsgs[0].plaintext, "Hello Bob from backup test");
  assert.equal(restoredDb.getPeerByUsername("bob").node_id, "bob-node-1");

  restoredDb.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
