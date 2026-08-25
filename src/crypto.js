"use strict";

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------
// Every node has two keypairs:
//   sign  (Ed25519) - proves events/messages came from this node
//   ecdh  (X25519)  - derives per-peer shared secrets for message encryption
// Private halves never leave this machine and never touch the server.

function generateIdentity() {
  const sign = crypto.generateKeyPairSync("ed25519");
  const ecdh = crypto.generateKeyPairSync("x25519");
  return {
    signPublic: sign.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    signPrivate: sign.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
    ecdhPublic: ecdh.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    ecdhPrivate: ecdh.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

function signPublicKeyObject(base64Der) {
  return crypto.createPublicKey({ key: Buffer.from(base64Der, "base64"), format: "der", type: "spki" });
}
function signPrivateKeyObject(base64Der) {
  return crypto.createPrivateKey({ key: Buffer.from(base64Der, "base64"), format: "der", type: "pkcs8" });
}
function ecdhPublicKeyObject(base64Der) {
  return crypto.createPublicKey({ key: Buffer.from(base64Der, "base64"), format: "der", type: "spki" });
}
function ecdhPrivateKeyObject(base64Der) {
  return crypto.createPrivateKey({ key: Buffer.from(base64Der, "base64"), format: "der", type: "pkcs8" });
}

/** Combined public_key string registered with the server (opaque to it). */
function packPublicKey({ signPublic, ecdhPublic }) {
  return JSON.stringify({ sign: signPublic, ecdh: ecdhPublic });
}

function unpackPublicKey(raw) {
  try {
    const parsed = JSON.parse(raw);
    if (parsed && parsed.sign && parsed.ecdh) return parsed;
  } catch {
    /* fall through */
  }
  return null;
}

// ---------------------------------------------------------------------------
// Signing (event / message authenticity)
// ---------------------------------------------------------------------------

function sign(data, signPrivateBase64) {
  const key = signPrivateKeyObject(signPrivateBase64);
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  return crypto.sign(null, buf, key).toString("base64");
}

function verify(data, signatureBase64, signPublicBase64) {
  try {
    const key = signPublicKeyObject(signPublicBase64);
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    return crypto.verify(null, buf, key, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Per-peer message encryption (X25519 ECDH -> AES-256-GCM)
// ---------------------------------------------------------------------------

function deriveSharedKey(myEcdhPrivateBase64, peerEcdhPublicBase64) {
  const priv = ecdhPrivateKeyObject(myEcdhPrivateBase64);
  const pub = ecdhPublicKeyObject(peerEcdhPublicBase64);
  const secret = crypto.diffieHellman({ privateKey: priv, publicKey: pub });
  // HKDF-ish: bind the raw ECDH output to a fixed context before use.
  return crypto.createHash("sha256").update(secret).update("sdmesh/msg/v1").digest();
}

function encryptMessage(plaintext, sharedKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", sharedKey, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

function decryptMessage(blobBase64, sharedKey) {
  const buf = Buffer.from(blobBase64, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", sharedKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

// ---------------------------------------------------------------------------
// At-rest encryption of the identity file (passphrase-derived key)
// ---------------------------------------------------------------------------

const SCRYPT_OPTS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function encryptBlob(obj, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, SCRYPT_OPTS);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(obj), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function decryptBlob({ salt, iv, tag, ciphertext }, passphrase) {
  const key = crypto.scryptSync(passphrase, Buffer.from(salt, "base64"), 32, SCRYPT_OPTS);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString("utf8"));
}

module.exports = {
  generateIdentity,
  packPublicKey,
  unpackPublicKey,
  sign,
  verify,
  deriveSharedKey,
  encryptMessage,
  decryptMessage,
  encryptBlob,
  decryptBlob,
};
