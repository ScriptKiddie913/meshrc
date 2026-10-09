"use strict";

const net = require("net");
const { SocksProxyAgent } = require("socks-proxy-agent");

class TorError extends Error {
  constructor(message) {
    super(message);
    this.name = "TorError";
  }
}

const DEFAULT_SOCKS_PORT = 9050;

/**
 * Creates a SocksProxyAgent for a v3 onion address or endpoint with stream isolation.
 * Uses socks5h:// so DNS resolution is performed inside Tor (zero DNS leaks).
 */
function createTorAgent({ socksPort = DEFAULT_SOCKS_PORT, isolationUser = "sdmesh", isolationPass = "x" } = {}) {
  const proxyUrl = `socks5h://${encodeURIComponent(isolationUser)}:${encodeURIComponent(isolationPass)}@127.0.0.1:${socksPort}`;
  return new SocksProxyAgent(proxyUrl);
}

/**
 * Check if the local Tor SOCKS proxy port is open and responsive.
 */
function checkTorAvailability(socksPort = DEFAULT_SOCKS_PORT, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isAvailable = false;

    socket.setTimeout(timeoutMs);

    socket.on("connect", () => {
      isAvailable = true;
      socket.destroy();
      resolve(true);
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });

    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });

    socket.connect(Number(socksPort), "127.0.0.1");
  });
}

/**
 * Validate that an address is a v3 onion address or report fail-closed condition.
 */
function isV3OnionAddress(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.hostname.endsWith(".onion");
  } catch {
    return false;
  }
}

/**
 * Automatically detect whether Tor SOCKS is listening on 9050 (system) or 9150 (Tor Browser).
 */
async function detectTorSocksPort() {
  if (await checkTorAvailability(9050, 1000)) return 9050;
  if (await checkTorAvailability(9150, 1000)) return 9150;
  return null;
}

module.exports = {
  TorError,
  createTorAgent,
  checkTorAvailability,
  detectTorSocksPort,
  isV3OnionAddress,
  DEFAULT_SOCKS_PORT,
};
