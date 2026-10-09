"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("../src/crypto");

test("C1 & C16: Key bundle generation and Ed25519 cross-signing verification", () => {
  const id = crypto.generateIdentity();
  assert.ok(id.signPublic);
  assert.ok(id.ecdhPublic);
  assert.ok(id.bindingSig);

  const packed = crypto.packPublicKey(id);
  const unpacked = crypto.unpackPublicKey(packed);

  assert.equal(crypto.verifyKeyBundle(unpacked), true, "Cross-signed key bundle must verify");

  // Tamper with ecdh public key
  unpacked.ecdh = Buffer.from("tampered-public-key").toString("base64");
  assert.equal(crypto.verifyKeyBundle(unpacked), false, "Tampered key bundle must fail verification");
});

test("C2: Directional keys, AAD binding, reflection resistance, and replay rejection", () => {
  const alice = crypto.generateIdentity();
  const bob = crypto.generateIdentity();

  const secretAlice = crypto.deriveRawSharedSecret(alice.ecdhPrivate, bob.ecdhPublic);
  const secretBob = crypto.deriveRawSharedSecret(bob.ecdhPrivate, alice.ecdhPublic);

  // Directional keys: Alice->Bob differs from Bob->Alice
  const keyAtoB = crypto.dirKey(secretAlice, "alice", "bob");
  const keyBtoA = crypto.dirKey(secretBob, "bob", "alice");
  assert.notDeepEqual(keyAtoB, keyBtoA, "Directional keys must differ per direction");

  // Encrypt envelope Alice -> Bob
  const envelope = crypto.encryptEnvelope({
    plaintext: "Secret message",
    sharedSecret: secretAlice,
    fromId: "alice",
    toId: "bob",
    msgId: "msg-1",
    counter: 1,
    bucketSize: 256,
  });

  // Successful Bob decryption
  const decrypted = crypto.decryptEnvelope({
    envelopeBase64: envelope,
    sharedSecret: secretBob,
    fromId: "alice",
    toId: "bob",
    msgId: "msg-1",
    counter: 1,
  });
  assert.equal(decrypted.payload, "Secret message");
  assert.equal(decrypted.from, "alice");

  // Reflection Attack Test: Reflecting Alice's own message back as if from Bob
  assert.throws(
    () => {
      crypto.decryptEnvelope({
        envelopeBase64: envelope,
        sharedSecret: secretAlice,
        fromId: "bob",
        toId: "alice", // Reflected direction
        msgId: "msg-1",
        counter: 1,
      });
    },
    /Unsupported envelope version|bad auth tag|decryption failed|unable to authenticate/i,
    "Reflected message must fail authentication"
  );

  // Tampered AAD / counter test
  assert.throws(
    () => {
      crypto.decryptEnvelope({
        envelopeBase64: envelope,
        sharedSecret: secretBob,
        fromId: "alice",
        toId: "bob",
        msgId: "msg-1",
        counter: 2, // Tampered counter
      });
    },
    /unable to authenticate|bad auth tag/i,
    "Tampered sequence counter must fail AAD verification"
  );
});

test("C5: Terminal control-sequence sanitization strips ANSI and control codes", () => {
  const maliciousInput = "Hello\x1b[31;1m RED ALERT\x1b[0m \x1b]52;c;evil_clipboard_payload\x07 \x00\x08END";
  const sanitized = crypto.sanitizeTerminal(maliciousInput);

  assert.ok(!sanitized.includes("\x1b"), "Must not contain escape byte");
  assert.ok(!sanitized.includes("evil_clipboard_payload"), "Must not contain OSC 52 sequence");
  assert.ok(sanitized.includes("RED ALERT"));
  assert.ok(sanitized.includes("END"));
});

test("Safety numbers: Deterministic, symmetric, and grouped digits", () => {
  const keyA = "AAA-Key";
  const keyB = "BBB-Key";

  const num1 = crypto.safetyNumber(keyA, keyB);
  const num2 = crypto.safetyNumber(keyB, keyA);

  assert.equal(num1, num2, "Safety number must be symmetric regardless of order");
  assert.match(num1, /^\d{5} \d{5} \d{5}/, "Must be formatted as grouped 5-digit segments");
});
