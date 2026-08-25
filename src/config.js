"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const CONFIG_DIR = path.join(os.homedir(), ".sdmesh");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const IDENTITY_PATH = path.join(CONFIG_DIR, "identity.enc.json");
const DB_PATH = path.join(CONFIG_DIR, "mesh.db");

const DEFAULT_RENDER_URL = "https://meshcn.onrender.com";

function ensureDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

function exists() {
  return fs.existsSync(CONFIG_PATH) && fs.existsSync(IDENTITY_PATH);
}

function load() {
  if (!fs.existsSync(CONFIG_PATH)) return null;
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function save(cfg) {
  ensureDir();
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

function loadIdentityBlob() {
  if (!fs.existsSync(IDENTITY_PATH)) return null;
  return JSON.parse(fs.readFileSync(IDENTITY_PATH, "utf8"));
}

function saveIdentityBlob(blob) {
  ensureDir();
  fs.writeFileSync(IDENTITY_PATH, JSON.stringify(blob, null, 2), { mode: 0o600 });
}

/** ws:// or wss:// form of the configured Render HTTP(S) endpoint, with /ws appended. */
function wsUrl(renderUrl) {
  const u = new URL(renderUrl);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  u.pathname = "/ws";
  u.search = "";
  return u.toString();
}

module.exports = {
  CONFIG_DIR,
  CONFIG_PATH,
  IDENTITY_PATH,
  DB_PATH,
  DEFAULT_RENDER_URL,
  ensureDir,
  exists,
  load,
  save,
  loadIdentityBlob,
  saveIdentityBlob,
  wsUrl,
};
