"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

const localdb = require("../src/localdb");

test("C1: TOFU key pinning blocks key replacement and flags key mismatch", () => {
  const dbPath = path.join(__dirname, "temp_tofu_test.db");
  try { fs.unlinkSync(dbPath); } catch {}

  const db = localdb.open(dbPath);

  // Initial key pinning (TOFU)
  const initial = db.upsertPeer({
    node_id: "bob-node",
    username: "bob",
    sign_public: "bob-original-sign-pub",
    ecdh_public: "bob-original-ecdh-pub",
  });
  assert.equal(initial.isNew, true);
  assert.equal(initial.status, "verified");

  // Harmless idempotent call with same keys
  const same = db.upsertPeer({
    node_id: "bob-node",
    username: "bob",
    sign_public: "bob-original-sign-pub",
    ecdh_public: "bob-original-ecdh-pub",
  });
  assert.equal(same.isNew, false);
  assert.equal(same.status, "verified");

  // MITM key change attack attempt
  assert.throws(
    () => {
      db.upsertPeer({
        node_id: "bob-node",
        username: "bob",
        sign_public: "attacker-substituted-sign-pub",
        ecdh_public: "attacker-substituted-ecdh-pub",
      });
    },
    (err) => {
      assert.equal(err.code, "KEY_MISMATCH");
      assert.ok(err.message.includes("Possible Man-In-The-Middle"));
      return true;
    }
  );

  const bobRow = db.getPeerByNodeId("bob-node");
  assert.equal(bobRow.status, "key_mismatch", "Peer status must be updated to key_mismatch");
  assert.equal(bobRow.sign_public, "bob-original-sign-pub", "Stored key must NOT be overwritten by attacker");

  db.close();
  try { fs.unlinkSync(dbPath); } catch {}
});
