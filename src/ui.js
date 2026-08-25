"use strict";

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  amber: "\x1b[38;5;214m",
  cyan: "\x1b[38;5;51m",
  rust: "\x1b[38;5;166m",
  green: "\x1b[38;5;114m",
  gray: "\x1b[38;5;240m",
};

const ANSI_RE = /\x1b\[[0-9;]*m/g;
function visibleLength(str) {
  return String(str).replace(ANSI_RE, "").length;
}

/** Pad to `len` visible columns, ignoring ANSI escape codes in the width calc. */
function pad(str, len) {
  const s = String(str);
  const vlen = visibleLength(s);
  return vlen >= len ? s : s + " ".repeat(len - vlen);
}

function banner() {
  return (
    `${c.amber}${c.bold}` +
    "┌──────────────────────────────────────────────────┐\n" +
    "│           S E C U R E   D E - M E S H              │\n" +
    "└──────────────────────────────────────────────────┘" +
    `${c.reset}`
  );
}

function ts(t = Date.now()) {
  const d = new Date(t);
  return d.toTimeString().slice(0, 8);
}

/** Render the /status dashboard box. */
function dashboard(ctx) {
  const W = 58;
  const line = "─".repeat(W - 2);
  const top = `${c.amber}┌${line}┐${c.reset}`;
  const bot = `${c.amber}└${line}┘${c.reset}`;
  const rows = [];
  const row = (text) => rows.push(`${c.amber}│${c.reset} ${pad(text, W - 4)} ${c.amber}│${c.reset}`);

  row(`${c.bold}NODE${c.reset}       ${ctx.username}`);
  row("");
  const renderState = ctx.online
    ? `${c.green}● ONLINE${c.reset}`
    : `${c.rust}● OFFLINE${c.reset}`;
  row(`CONNECTION`);
  row(`  ${c.cyan}Render${c.reset}       ${renderState}`);
  const meshState = ctx.wsConnected
    ? `${c.green}SYNCHRONIZED${c.reset}`
    : ctx.online
      ? `${c.amber}CONNECTING${c.reset}`
      : `${c.rust}LOCAL MODE${c.reset}`;
  row(`  ${c.cyan}Mesh${c.reset}         ${meshState}`);
  row(`  ${c.cyan}Identity${c.reset}     ${c.green}VERIFIED${c.reset}`);
  row("");
  row(`NETWORK`);
  const onlinePeers = ctx.db.listPeers().filter((p) => p.online);
  const offlinePeers = ctx.db.listPeers().filter((p) => !p.online);
  if (onlinePeers.length === 0 && offlinePeers.length === 0) {
    row(`  ${c.gray}(no known peers — /sync to discover)${c.reset}`);
  }
  for (const p of onlinePeers) row(`  ${c.green}●${c.reset} ${pad(p.username, 14)} ONLINE`);
  for (const p of offlinePeers) row(`  ${c.gray}○ ${pad(p.username, 14)} OFFLINE${c.reset}`);
  row("");
  row(`SYNC`);
  row(`  Events         ${ctx.db.eventCount()}`);
  row(`  Pending        ${ctx.db.outboxCount()}`);
  row(`  Watermark      ${ctx.db.lastGlobalSeq()}`);
  row(`  Last sync      ${ctx.lastSyncAt ? ts(ctx.lastSyncAt) : c.gray + "never" + c.reset}`);

  return [top, ...rows, bot].join("\n");
}

function msgIn(fromUsername, text, atMs = Date.now()) {
  return `${c.gray}[${ts(atMs)}]${c.reset} ${c.cyan}←${c.reset} ${c.bold}${fromUsername}${c.reset}\n  ${text}`;
}

function msgOut(toUsername, text, statusLabel, atMs = Date.now()) {
  const status = statusLabel ? ` ${c.gray}(${statusLabel})${c.reset}` : "";
  return `${c.gray}[${ts(atMs)}]${c.reset} ${c.amber}→${c.reset} ${c.bold}${toUsername}${c.reset}${status}\n  ${text}`;
}

function info(text) {
  return `${c.cyan}${text}${c.reset}`;
}
function warn(text) {
  return `${c.rust}${text}${c.reset}`;
}
function ok(text) {
  return `${c.green}${text}${c.reset}`;
}
function dim(text) {
  return `${c.dim}${c.gray}${text}${c.reset}`;
}

const PROMPT = `${c.amber}sdmesh${c.reset}${c.gray}>${c.reset} `;

module.exports = { c, banner, dashboard, msgIn, msgOut, info, warn, ok, dim, PROMPT, ts };
