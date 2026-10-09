"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const {
  generateDH,
  initRatchetAlice,
  initRatchetBob,
  ratchetEncrypt,
  ratchetDecrypt,
  randomJitter,
  generateCoverMessage,
} = require("../src/ratchet");

test("Phase 4: Double Ratchet two-party back-and-forth messaging with forward secrecy", async () => {
  // Shared master secret established out-of-band / initial key agreement
  const sharedMasterKey = crypto.randomBytes(32);

  // Bob's initial ratchet key
  const bobInitialDH = generateDH();

  // Initialize sessions
  const alice = initRatchetAlice({
    sharedMasterKey,
    bobDhPublic: bobInitialDH.public,
  });

  const bob = initRatchetBob({
    sharedMasterKey,
    bobDH: bobInitialDH,
  });

  // 1. Alice sends first message to Bob
  const msg1 = ratchetEncrypt(alice, "Hello Bob! This is message 1 from Alice.");
  assert.ok(msg1.ciphertext.length > 500, "Must be padded to 1 KiB bucket size");

  const decrypted1 = ratchetDecrypt(bob, msg1);
  assert.equal(decrypted1.payload, "Hello Bob! This is message 1 from Alice.");

  // 2. Bob replies to Alice (triggers DH ratchet step)
  const msg2 = ratchetEncrypt(bob, "Hey Alice! Received message 1. Replying with message 2.");
  const decrypted2 = ratchetDecrypt(alice, msg2);
  assert.equal(decrypted2.payload, "Hey Alice! Received message 1. Replying with message 2.");

  // 3. Multi-turn conversation
  const msg3 = ratchetEncrypt(alice, "Message 3 from Alice.");
  const msg4 = ratchetEncrypt(alice, "Message 4 from Alice immediately after.");

  const decrypted3 = ratchetDecrypt(bob, msg3);
  const decrypted4 = ratchetDecrypt(bob, msg4);
  assert.equal(decrypted3.payload, "Message 3 from Alice.");
  assert.equal(decrypted4.payload, "Message 4 from Alice immediately after.");

  // 4. Test Key Compromise / Forward Secrecy:
  // An attacker steals the state at time T4 (including current Alice/Bob state: rk, cks, dhs).
  // Can the attacker decrypt message 1 or message 2?
  // Message 1 was encrypted with mk_1 which was never saved and was deleted from the chain.
  // Trying to decrypt msg1 with current ratchet state MUST fail!
  assert.throws(() => {
    ratchetDecrypt(bob, msg1);
  }, "Replay or past message decryption with ratcheted state must fail");

  // 5. Test randomized jitter
  const t0 = Date.now();
  await randomJitter(30, 80);
  const elapsed = Date.now() - t0;
  assert.ok(elapsed >= 25, `Jitter elapsed ${elapsed}ms must be at least 25ms`);

  // 6. Test cover traffic generator
  const cover = generateCoverMessage();
  assert.equal(cover.type, "cover");
  assert.ok(cover.dummyData.length > 10);
});
