#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const config = require("./config");
const identityCrypto = require("./crypto");
const localdb = require("./localdb");
const api = require("./api");
const ui = require("./ui");
const { ask, askHidden, closeShared } = require("./prompt");

const USERNAME_RE = /^[a-zA-Z0-9_-]{2,32}$/;

async function main() {
  console.log(ui.banner());
  console.log(ui.dim("                 NODE SETUP\n"));

  if (config.exists()) {
    const answer = await ask(
      ui.warn(`An identity already exists at ${config.CONFIG_DIR}. Overwrite? (y/N): `)
    );
    if (answer.toLowerCase() !== "y") {
      console.log(ui.info("Setup cancelled. Existing identity left untouched."));
      process.exit(0);
    }
  }

  const argRenderUrl = process.argv[2];
  let renderUrl = argRenderUrl || (await ask(`Render endpoint [${config.DEFAULT_RENDER_URL}]: `));
  renderUrl = (renderUrl || config.DEFAULT_RENDER_URL).trim().replace(/\/+$/, "");

  process.stdout.write(ui.info("Checking Render endpoint... "));
  try {
    const h = await api.health(renderUrl);
    console.log(ui.ok(`ok (service: ${h.service}, global_seq: ${h.global_seq})`));
  } catch (err) {
    console.log(ui.warn(`unreachable (${err.message})`));
    const cont = await ask("Continue anyway and set up offline? (y/N): ");
    if (cont.toLowerCase() !== "y") process.exit(1);
  }

  let username = "";
  while (!USERNAME_RE.test(username)) {
    username = await ask("Username: ");
    if (!USERNAME_RE.test(username)) {
      console.log(ui.warn("2-32 chars, letters/digits/underscore/hyphen only."));
    }
  }

  let passphrase = "";
  while (passphrase.length < 8) {
    passphrase = await askHidden("Vault passphrase (min 8 chars, encrypts your private keys at rest): ");
    if (passphrase.length < 8) console.log(ui.warn("Too short."));
  }
  const confirm = await askHidden("Confirm passphrase: ");
  if (confirm !== passphrase) {
    console.log(ui.warn("Passphrases did not match. Aborting."));
    process.exit(1);
  }

  console.log(ui.info("\nGenerating node identity..."));
  const identity = identityCrypto.generateIdentity();
  console.log(ui.ok("  ✓ Signing keypair generated (Ed25519)"));
  console.log(ui.ok("  ✓ Encryption keypair generated (X25519)"));

  const nodeId = `${username}-${crypto.randomBytes(4).toString("hex")}`;
  console.log(ui.ok(`  ✓ Node ID: ${nodeId}`));

  const publicKey = identityCrypto.packPublicKey(identity);

  let registration = null;
  try {
    process.stdout.write(ui.info("\nRegistering with mesh... "));
    registration = await api.register(renderUrl, { username, nodeId, publicKey });
    console.log(ui.ok("ok"));
  } catch (err) {
    console.log(ui.warn(`failed (${err.message})`));
    console.log(ui.warn("You can still finish setup and register later by running the client — it will retry."));
  }

  // Persist plaintext, non-secret config.
  config.save({
    render_url: renderUrl,
    username,
    node_id: nodeId,
    sign_public: identity.signPublic,
    ecdh_public: identity.ecdhPublic,
    registered: !!registration,
    created_at: Date.now(),
  });

  // Persist encrypted secrets (private keys + bearer token).
  const secretPayload = {
    sign_private: identity.signPrivate,
    ecdh_private: identity.ecdhPrivate,
    token: registration ? registration.token : null,
  };
  config.saveIdentityBlob(identityCrypto.encryptBlob(secretPayload, passphrase));
  console.log(ui.ok("  ✓ Identity encrypted and stored (~/.sdmesh/identity.enc.json)"));

  // Initialize local event/peer/message store, seeded from registration if we got one.
  const db = localdb.open(config.DB_PATH);
  if (registration) {
    for (const p of registration.peers || []) {
      if (p.node_id === nodeId) continue;
      const keys = identityCrypto.unpackPublicKey(p.public_key);
      if (keys) {
        db.upsertPeer({
          node_id: p.node_id,
          username: p.username,
          sign_public: keys.sign,
          ecdh_public: keys.ecdh,
          last_seen: p.last_seen,
        });
      }
    }
  }
  db.close();
  console.log(ui.ok("  ✓ Local store initialized (~/.sdmesh/mesh.db)"));

  console.log(ui.info("\nSetup complete.\n"));
  console.log(`Run:\n    ${ui.c.bold}./run.sh${ui.c.reset}\n`);
  closeShared();
  process.exit(0);
}

main().catch((err) => {
  console.error(ui.warn(`\nSetup failed: ${err.message}`));
  process.exit(1);
});
