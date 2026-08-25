# sdmesh-client

Client for the Secure De-centralized Mesh. This repo is **client-side only**:
CLI, local identity, local encrypted state, local event mirror. It talks to
a headless mesh backend already deployed on Render.

No server code here. No dashboard. The only interface is the CLI.

Default backend: `https://meshcn.onrender.com`

## Install

```
git clone <this-repo-url> sdmesh-client
cd sdmesh-client
./setup.sh
```

`setup.sh` will:
- ping the Render backend
- ask for a username and a vault passphrase (encrypts your keys at rest — never sent anywhere)
- generate an Ed25519 signing keypair and an X25519 encryption keypair, locally
- register your public keys + username with Render
- store everything under `~/.sdmesh/`

Your private keys never leave this machine.

## Run

```
./run.sh
```

Prompts for your vault passphrase, connects, syncs, drops you into the CLI.

```
sdmesh> /status
sdmesh> /peers
sdmesh> /msg alice hey, you there?
sdmesh> /history alice
sdmesh> /sync
sdmesh> /backup push
sdmesh> /help
```

If Render is unreachable, the client starts in local/offline mode: you can
still browse cached peers and message history, and any message you send
queues locally and delivers automatically once the connection comes back —
no need to re-run setup.

## What lives where

| Path | Contents |
|---|---|
| `~/.sdmesh/config.json` | username, node id, render URL, **public** keys — plaintext |
| `~/.sdmesh/identity.enc.json` | private keys + auth token — AES-256-GCM, passphrase-derived key (scrypt) |
| `~/.sdmesh/mesh.db` | local event log mirror, peer cache, message history, outbox — SQLite (`node:sqlite`, built into Node — no native build) |

## Crypto

- **Identity / signing**: Ed25519 keypair per node.
- **Messages**: X25519 ECDH per peer pair → SHA-256-derived key → AES-256-GCM.
  Each message to each peer uses a fresh IV; the server only ever sees
  ciphertext plus routing metadata.
- **At-rest**: private keys are encrypted with a key derived from your vault
  passphrase via scrypt before ever touching disk.
- **Backups**: `/backup push` encrypts a snapshot of your local event log and
  peer cache (never private keys) with your vault passphrase and stores the
  opaque blob on Render. `/backup pull` reverses that on another machine —
  useful for reseeding local state, not for cloning your identity.

## Commands

| Command | Does |
|---|---|
| `/status` | connection + sync dashboard |
| `/peers` | refresh + list known peers, online/offline |
| `/msg <user> <text>` | send an E2E-encrypted message |
| `/history [user] [n]` | recent message history |
| `/sync` | force a two-way sync against Render |
| `/backup push` / `/backup pull` | encrypted state snapshot to/from Render |
| `/whoami` | this node's identity + key fingerprint |
| `/help` | command list |
| `/quit` | exit |

## Config

Override the backend at setup time:

```
./setup.sh https://your-render-app.onrender.com
```

Or edit `~/.sdmesh/config.json` → `render_url` after the fact.

## Requirements

Node.js >= 22.13.0. That's it — `setup.sh` handles `npm install`.

Storage uses Node's built-in `node:sqlite` (no `better-sqlite3`, no native
build step), so `npm install` never touches node-gyp/Python/a C++ toolchain
— it just pulls in `ws`. If `setup.sh` complains about your Node version,
upgrade (`nvm install --lts && nvm use --lts`) rather than downgrading the
client.
