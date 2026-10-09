"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const net = require("net");
const http = require("http");
const { createTorAgent, checkTorAvailability, isV3OnionAddress } = require("../src/tor");

test("C13: Tor SOCKS5 gateway routes traffic, delegates DNS (ATYP=3), and fails closed", async () => {
  // 1. Fail-closed test when Tor port is closed
  const isAvailableWhenDown = await checkTorAvailability(19099, 500);
  assert.equal(isAvailableWhenDown, false, "Must report false when Tor proxy is down");

  // 2. Start a mock target HTTP server
  const targetServer = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "reached_target" }));
  });
  await new Promise((resolve) => targetServer.listen(0, "127.0.0.1", resolve));
  const targetPort = targetServer.address().port;

  // 3. Start a mock SOCKS5 proxy server
  let socksConnectionsCount = 0;
  let receivedAtyp = null;
  let receivedHost = null;

  const socksServer = net.createServer((clientSocket) => {
    socksConnectionsCount++;
    let state = "AUTH";

    const onData = (data) => {
      if (state === "AUTH") {
        if (data[0] !== 0x05) return;
        const supportsUserPass = data.slice(2).includes(0x02);
        if (supportsUserPass) {
          clientSocket.write(Buffer.from([0x05, 0x02]));
          state = "USERPASS";
        } else {
          clientSocket.write(Buffer.from([0x05, 0x00]));
          state = "REQUEST";
        }
      } else if (state === "USERPASS") {
        clientSocket.write(Buffer.from([0x01, 0x00]));
        state = "REQUEST";
      } else if (state === "REQUEST") {
        if (data[0] !== 0x05) return;
        receivedAtyp = data[3];

        if (receivedAtyp === 0x03) {
          const domainLen = data[4];
          receivedHost = data.subarray(5, 5 + domainLen).toString("utf8");
        } else if (receivedAtyp === 0x01) {
          receivedHost = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
        }

        // Remove listener before piping tunnel data
        clientSocket.removeListener("data", onData);

        const targetSocket = net.connect(targetPort, "127.0.0.1", () => {
          clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]));
          clientSocket.pipe(targetSocket);
          targetSocket.pipe(clientSocket);
        });

        targetSocket.on("error", () => clientSocket.destroy());
      }
    };

    clientSocket.on("data", onData);
  });

  await new Promise((resolve) => socksServer.listen(0, "127.0.0.1", resolve));
  const socksPort = socksServer.address().port;

  // Verify availability returns true for live SOCKS port
  const isAvailableWhenUp = await checkTorAvailability(socksPort, 1000);
  assert.equal(isAvailableWhenUp, true, "Must report true when SOCKS proxy is running");

  // 4. Send request through SocksProxyAgent with a dummy .onion domain
  const agent = createTorAgent({
    socksPort,
    isolationUser: "test-user-node",
    isolationPass: "test-circuit",
  });

  const responseData = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "dummyv3hiddenonionaddress1234567.onion",
        port: targetPort,
        method: "GET",
        path: "/status",
        agent,
        timeout: 5000,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve(JSON.parse(body)));
      }
    );
    req.on("error", reject);
    req.end();
  });

  assert.equal(responseData.status, "reached_target");
  assert.ok(socksConnectionsCount >= 1, "Connection must route strictly through the SOCKS port");
  assert.equal(receivedAtyp, 0x03, "Domain resolution must be delegated to SOCKS proxy (ATYP=3, zero DNS leaks)");
  assert.equal(receivedHost, "dummyv3hiddenonionaddress1234567.onion");

  // 5. Test v3 onion address validation helper
  assert.equal(isV3OnionAddress("http://xyz123abc456.onion/ws"), true);
  assert.equal(isV3OnionAddress("https://meshcn.onrender.com"), false);

  // Clean up
  await new Promise((resolve) => targetServer.close(resolve));
  await new Promise((resolve) => socksServer.close(resolve));
});
