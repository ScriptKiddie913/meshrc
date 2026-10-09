"use strict";

const crypto = require("crypto");

/**
 * Standard Double Ratchet Algorithm (Signal Specification)
 * Uses Node's built-in crypto: X25519 ECDH + HKDF-SHA256 + AES-256-GCM
 */

function generateDH() {
  const pair = crypto.generateKeyPairSync("x25519");
  return {
    public: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    private: pair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

function computeDH(privateBase64, publicBase64) {
  const priv = crypto.createPrivateKey({
    key: Buffer.from(privateBase64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const pub = crypto.createPublicKey({
    key: Buffer.from(publicBase64, "base64"),
    format: "der",
    type: "spki",
  });
  return crypto.diffieHellman({ privateKey: priv, publicKey: pub });
}

// KDF for root chain: takes root key and DH shared secret, returns (new_rk, chain_key)
function kdfRK(rk, dhShared) {
  const derived = crypto.hkdfSync("sha256", dhShared, rk, "sdmesh/v2/ratchet/rk", 64);
  const buf = Buffer.from(derived);
  return {
    rk: buf.subarray(0, 32),
    ck: buf.subarray(32, 64),
  };
}

// KDF for symmetric chain: takes chain key, returns (new_ck, message_key)
function kdfCK(ck) {
  const derived = crypto.hkdfSync("sha256", ck, Buffer.alloc(32, 0), "sdmesh/v2/ratchet/ck", 64);
  const buf = Buffer.from(derived);
  return {
    ck: buf.subarray(0, 32),
    mk: buf.subarray(32, 64),
  };
}

/**
 * Initialize a Double Ratchet session.
 * - Alice (initiator): has shared secret (e.g. from X3DH or initial ECDH) and Bob's DH ratchet public key.
 * - Bob (responder): has shared secret and his own DH ratchet keypair.
 */
function initRatchetAlice({ sharedMasterKey, bobDhPublic }) {
  const ourDH = generateDH();
  const dhShared = computeDH(ourDH.private, bobDhPublic);
  const { rk, ck } = kdfRK(sharedMasterKey, dhShared);

  return {
    dhs: ourDH,               // Our current DH key pair
    dhr: bobDhPublic,         // Remote DH public key
    rk,                       // Root key
    cks: ck,                  // Sending chain key
    ckr: null,                // Receiving chain key
    ns: 0,                    // Sending message number
    nr: 0,                    // Receiving message number
    pn: 0,                    // Previous chain length
    mkskipped: {},            // Skipped message keys { `${dhr}:${n}`: mk }
  };
}

function initRatchetBob({ sharedMasterKey, bobDH }) {
  return {
    dhs: bobDH,               // Our current DH key pair
    dhr: null,                // Remote DH public key (learned on first message)
    rk: sharedMasterKey,      // Root key
    cks: null,                // Sending chain key
    ckr: null,                // Receiving chain key
    ns: 0,
    nr: 0,
    pn: 0,
    mkskipped: {},
  };
}

/**
 * Encrypt a plaintext message with the Double Ratchet.
 * Returns { header, ciphertext, version: 2 }
 */
function ratchetEncrypt(state, plaintext, { bucketSize = 1024, type = "msg" } = {}) {
  if (!state.cks) {
    throw new Error("Cannot send: sending chain not initialized");
  }

  const { ck: nextCks, mk } = kdfCK(state.cks);
  state.cks = nextCks;

  const header = {
    dh: state.dhs.public,
    pn: state.pn,
    n: state.ns,
  };
  state.ns++;

  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(JSON.stringify(header), "utf8");

  const innerPayload = JSON.stringify({
    v: 2,
    type,
    payload: plaintext,
    timestamp: Date.now(),
  });

  const innerBuf = Buffer.from(innerPayload, "utf8");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(innerBuf.length, 0);
  const unpadded = Buffer.concat([lenBuf, innerBuf]);

  // Fixed-size padded bucket (traffic analysis defense)
  let padded = unpadded;
  if (unpadded.length < bucketSize) {
    padded = Buffer.concat([unpadded, crypto.randomBytes(bucketSize - unpadded.length)]);
  }

  const cipher = crypto.createCipheriv("aes-256-gcm", mk, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    header,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

/**
 * Decrypt a message with the Double Ratchet.
 */
function ratchetDecrypt(state, message) {
  const { header, iv, tag, ciphertext } = message;

  // Check if header DH differs from remote DH -> perform DH ratchet step
  if (!state.dhr || header.dh !== state.dhr) {
    // Skip message keys in previous chain if any
    skipMessageKeys(state, header.pn);
    dhRatchetStep(state, header);
  }

  // Skip any missing message keys in current chain
  skipMessageKeys(state, header.n);

  const { ck: nextCkr, mk } = kdfCK(state.ckr);
  state.ckr = nextCkr;
  state.nr++;

  const aad = Buffer.from(JSON.stringify(header), "utf8");
  const decipher = crypto.createDecipheriv("aes-256-gcm", mk, Buffer.from(iv, "base64"));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(tag, "base64"));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]);

  const innerLen = decrypted.readUInt32BE(0);
  const innerJson = decrypted.subarray(4, 4 + innerLen).toString("utf8");
  return JSON.parse(innerJson);
}

function dhRatchetStep(state, header) {
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
  state.dhr = header.dh;

  const dhSharedReceive = computeDH(state.dhs.private, state.dhr);
  const rkRecv = kdfRK(state.rk, dhSharedReceive);
  state.rk = rkRecv.rk;
  state.ckr = rkRecv.ck;

  state.dhs = generateDH();
  const dhSharedSend = computeDH(state.dhs.private, state.dhr);
  const rkSend = kdfRK(state.rk, dhSharedSend);
  state.rk = rkSend.rk;
  state.cks = rkSend.ck;
}

function skipMessageKeys(state, until) {
  if (state.ckr) {
    while (state.nr < until) {
      const { ck: nextCkr, mk } = kdfCK(state.ckr);
      state.ckr = nextCkr;
      state.mkskipped[`${state.dhr}:${state.nr}`] = mk;
      state.nr++;
    }
  }
}

/**
 * Traffic analysis mitigation helpers:
 * - Randomized send jitter
 * - Dummy cover traffic generator
 */
function randomJitter(minMs = 20, maxMs = 250) {
  const ms = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function generateCoverMessage(bucketSize = 1024) {
  return {
    type: "cover",
    dummyData: crypto.randomBytes(32).toString("hex"),
    timestamp: Date.now(),
  };
}

module.exports = {
  generateDH,
  computeDH,
  initRatchetAlice,
  initRatchetBob,
  ratchetEncrypt,
  ratchetDecrypt,
  randomJitter,
  generateCoverMessage,
};
