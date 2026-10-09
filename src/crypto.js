"use strict";

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Identity & Key Bundles
// ---------------------------------------------------------------------------
function generateIdentity() {
  const sign = crypto.generateKeyPairSync("ed25519");
  const ecdh = crypto.generateKeyPairSync("x25519");

  const signPublic = sign.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const signPrivate = sign.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  const ecdhPublic = ecdh.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const ecdhPrivate = ecdh.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");

  // Cross-sign X25519 key with Ed25519 key (C1, C16)
  const bindingSig = signData(ecdhPublic, signPrivate);

  return {
    signPublic,
    signPrivate,
    ecdhPublic,
    ecdhPrivate,
    bindingSig,
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

function packPublicKey({ signPublic, ecdhPublic, bindingSig = null, signPrivate = null }) {
  const sig = bindingSig || (signPrivate ? signData(ecdhPublic, signPrivate) : null);
  return JSON.stringify({
    v: 2,
    sign: signPublic,
    sign_pub: signPublic,
    ecdh: ecdhPublic,
    ecdh_pub: ecdhPublic,
    binding_sig: sig,
  });
}

function unpackPublicKey(raw) {
  try {
    const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (parsed) {
      const signPub = parsed.sign || parsed.sign_pub;
      const ecdhPub = parsed.ecdh || parsed.ecdh_pub;
      if (signPub && ecdhPub) {
        return {
          v: parsed.v || 1,
          sign: signPub,
          sign_pub: signPub,
          ecdh: ecdhPub,
          ecdh_pub: ecdhPub,
          binding_sig: parsed.binding_sig || null,
        };
      }
    }
  } catch {}
  return null;
}

function verifyKeyBundle(bundle) {
  if (!bundle || !bundle.sign || !bundle.ecdh) return false;
  if (!bundle.binding_sig) return true; // Legacy bundles without binding_sig permitted for migration
  return verifyData(bundle.ecdh, bundle.binding_sig, bundle.sign);
}

// ---------------------------------------------------------------------------
// Signing & Verification
// ---------------------------------------------------------------------------
function signData(data, signPrivateBase64) {
  const key = signPrivateKeyObject(signPrivateBase64);
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
  return crypto.sign(null, buf, key).toString("base64");
}

function verifyData(data, signatureBase64, signPublicBase64) {
  try {
    const key = signPublicKeyObject(signPublicBase64);
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
    return crypto.verify(null, buf, key, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Protocol v2 Directional Crypto & Mailbox Derivation (C2)
// ---------------------------------------------------------------------------
function deriveRawSharedSecret(myEcdhPrivateBase64, peerEcdhPublicBase64) {
  const priv = ecdhPrivateKeyObject(myEcdhPrivateBase64);
  const pub = ecdhPublicKeyObject(peerEcdhPublicBase64);
  return crypto.diffieHellman({ privateKey: priv, publicKey: pub });
}

function dirKey(sharedSecret, fromId, toId) {
  const salt = Buffer.from([fromId, toId].sort().join("|"), "utf8");
  return Buffer.from(
    crypto.hkdfSync("sha256", sharedSecret, salt, `sdmesh/v2/msg|from=${fromId}|to=${toId}`, 32)
  );
}

function derivePairwiseMailbox(sharedSecret, fromId, toId) {
  const salt = Buffer.from([fromId, toId].sort().join("|"), "utf8");
  const derived = crypto.hkdfSync("sha256", sharedSecret, salt, `sdmesh/v2/mbx|from=${fromId}|to=${toId}`, 16);
  return `mbx_${Buffer.from(derived).toString("hex")}`;
}

/**
 * Protocol v2 Envelope:
 * - Sealed sender inside ciphertext
 * - Fixed-size padding (default 1024 bytes)
 * - Version byte 0x02
 * - AAD = "${fromId}|${toId}|${msgId}|${counter}"
 */
function encryptEnvelope({ plaintext, sharedSecret, fromId, toId, msgId, counter, bucketSize = 1024, type = "msg" }) {
  const key = dirKey(sharedSecret, fromId, toId);
  const iv = crypto.randomBytes(12);

  const innerPayload = JSON.stringify({
    v: 2,
    type,
    from: fromId,
    to: toId,
    msg_id: msgId,
    counter,
    payload: plaintext,
    timestamp: Date.now(),
  });

  const innerBuf = Buffer.from(innerPayload, "utf8");
  // Length prefix (4 bytes) + inner payload
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(innerBuf.length, 0);
  const unpadded = Buffer.concat([lenBuf, innerBuf]);

  // Pad to bucket size
  let padded = unpadded;
  if (unpadded.length < bucketSize) {
    const padLen = bucketSize - unpadded.length;
    padded = Buffer.concat([unpadded, crypto.randomBytes(padLen)]);
  }

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const aad = `${fromId}|${toId}|${msgId}|${counter}`;
  cipher.setAAD(Buffer.from(aad, "utf8"));

  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Version 2 byte prefix + iv + tag + ciphertext
  return Buffer.concat([Buffer.from([2]), iv, tag, ciphertext]).toString("base64");
}

function decryptEnvelope({ envelopeBase64, sharedSecret, fromId, toId, msgId, counter }) {
  const buf = Buffer.from(envelopeBase64, "base64");
  const version = buf[0];
  if (version !== 2) {
    throw new Error(`Unsupported envelope version: ${version}`);
  }

  const iv = buf.subarray(1, 13);
  const tag = buf.subarray(13, 29);
  const ciphertext = buf.subarray(29);

  const key = dirKey(sharedSecret, fromId, toId);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  const aad = `${fromId}|${toId}|${msgId}|${counter}`;
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const innerLen = decrypted.readUInt32BE(0);
  const innerJson = decrypted.subarray(4, 4 + innerLen).toString("utf8");

  return JSON.parse(innerJson);
}

// Safety Number calculation for TOFU and verification
function safetyNumber(keyA, keyB) {
  const sorted = [keyA, keyB].sort().join("|");
  const hash = crypto.createHash("sha256").update(sorted, "utf8").digest("hex");
  // Form into grouped 5-digit segments (e.g. 12345 67890 ...)
  const digits = [];
  for (let i = 0; i < 30; i += 5) {
    const chunk = parseInt(hash.slice(i, i + 5), 16) % 100000;
    digits.push(String(chunk).padStart(5, "0"));
  }
  return digits.join(" ");
}

// Terminal control sequence injection defense (C5)
function sanitizeTerminal(str) {
  if (typeof str !== "string") return "";
  // Strip ANSI CSI/OSC escape sequences and C0/C1 control chars except \n and \t
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "") // ANSI CSI sequences
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "") // ANSI OSC sequences
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g, "␛"); // Control characters
}

// ---------------------------------------------------------------------------
// Backward-compatible v1 crypto helpers
// ---------------------------------------------------------------------------
function deriveSharedKey(myEcdhPrivateBase64, peerEcdhPublicBase64) {
  const secret = deriveRawSharedSecret(myEcdhPrivateBase64, peerEcdhPublicBase64);
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

// At-rest encryption (scrypt) with Phase 3 hardening (C12)
const SCRYPT_OPTS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

function generateDataKey() {
  return crypto.randomBytes(32);
}

function encryptField(text, key) {
  if (!key || typeof text !== "string") return text;
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, iv);
  const ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return "enc:v1:" + Buffer.concat([iv, tag, ct]).toString("base64");
}

function decryptField(val, key) {
  if (!key || typeof val !== "string" || !val.startsWith("enc:v1:")) return val;
  try {
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, "hex");
    const raw = Buffer.from(val.slice(7), "base64");
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ct = raw.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    return val;
  }
}

function checkPassphraseStrength(passphrase) {
  if (!passphrase || passphrase.length < 12) {
    return { valid: false, message: "Passphrase must be at least 12 characters long." };
  }
  let score = 0;
  if (/[a-z]/.test(passphrase)) score++;
  if (/[A-Z]/.test(passphrase)) score++;
  if (/[0-9]/.test(passphrase)) score++;
  if (/[^a-zA-Z0-9]/.test(passphrase)) score++;
  if (score < 2) {
    return { valid: false, message: "Passphrase is too simple. Use a mix of letters, numbers, or symbols." };
  }
  return { valid: true, score };
}

function encryptBlob(obj, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, SCRYPT_OPTS);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(obj), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const canary = crypto.createHash("sha256").update(key).digest("base64");

  return {
    v: 2,
    kdf: { N: SCRYPT_OPTS.N, r: SCRYPT_OPTS.r, p: SCRYPT_OPTS.p },
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    canary,
    ciphertext: ciphertext.toString("base64"),
  };
}

function decryptBlob(blob, passphrase) {
  const { salt, iv, tag, ciphertext, kdf, canary } = blob;
  const opts = kdf || SCRYPT_OPTS;
  const key = crypto.scryptSync(passphrase, Buffer.from(salt, "base64"), 32, {
    N: opts.N || SCRYPT_OPTS.N,
    r: opts.r || SCRYPT_OPTS.r,
    p: opts.p || SCRYPT_OPTS.p,
    maxmem: 256 * 1024 * 1024,
  });

  if (canary) {
    const checkCanary = crypto.createHash("sha256").update(key).digest("base64");
    if (checkCanary !== canary) {
      throw new Error("Invalid passphrase: key check canary failed");
    }
  }

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString("utf8"));
}

function exportEncryptedBackup(payload, backupKey) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(backupKey, salt, 32, SCRYPT_OPTS);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const jsonStr = JSON.stringify(payload);
  const ciphertext = Buffer.concat([cipher.update(jsonStr, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    v: 2,
    created_at: Date.now(),
    kdf: { N: SCRYPT_OPTS.N, r: SCRYPT_OPTS.r, p: SCRYPT_OPTS.p },
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function importEncryptedBackup(backupBlob, backupKey) {
  const { salt, iv, tag, ciphertext, kdf } = backupBlob;
  const opts = kdf || SCRYPT_OPTS;
  const key = crypto.scryptSync(backupKey, Buffer.from(salt, "base64"), 32, {
    N: opts.N || SCRYPT_OPTS.N,
    r: opts.r || SCRYPT_OPTS.r,
    p: opts.p || SCRYPT_OPTS.p,
    maxmem: 256 * 1024 * 1024,
  });
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
  verifyKeyBundle,
  sign: signData,
  verify: verifyData,
  deriveRawSharedSecret,
  dirKey,
  derivePairwiseMailbox,
  encryptEnvelope,
  decryptEnvelope,
  safetyNumber,
  sanitizeTerminal,
  deriveSharedKey,
  encryptMessage,
  decryptMessage,
  encryptBlob,
  decryptBlob,
  generateDataKey,
  encryptField,
  decryptField,
  checkPassphraseStrength,
  exportEncryptedBackup,
  importEncryptedBackup,
};
