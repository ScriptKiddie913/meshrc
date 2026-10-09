"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const api = require("../src/api");
const { MeshSocket } = require("../src/wsclient");

test("C14: api.request surfaces ApiError on non-JSON response without crashing on SyntaxError", async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(502, { "Content-Type": "text/html" });
    res.end("<html><body>502 Bad Gateway</body></html>");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  await assert.rejects(
    async () => {
      await api.health(`http://127.0.0.1:${port}`);
    },
    (err) => {
      assert.ok(err instanceof api.ApiError, "Must be an instance of ApiError");
      assert.equal(err.status, 502);
      assert.ok(err.message.includes("502"), "Error message should include status code");
      return true;
    }
  );

  await new Promise((resolve) => server.close(resolve));
});

test("C9: MeshSocket halts auto-reconnect when server closes with code 4001 or 4002", async () => {
  const socket = new MeshSocket("ws://127.0.0.1:9999/ws", { nodeId: "alice", token: "tok" });
  socket.wantConnected = true;

  // Simulate close with 4001
  socket._handleClose(4001, "unauthorized");
  assert.equal(socket.wantConnected, false, "Must halt reconnect loop on 4001");
  assert.equal(socket.reconnectTimer, null, "Must not schedule reconnect on 4001");

  socket.wantConnected = true;
  socket._handleClose(4002, "replaced");
  assert.equal(socket.wantConnected, false, "Must halt reconnect loop on 4002");
  assert.equal(socket.reconnectTimer, null, "Must not schedule reconnect on 4002");
});

test("C15: /msg regex preserves whitespace verbatim", () => {
  const line = "/msg bob   Hello   world!   Preserve   spaces.  ";
  const match = line.match(/^\/msg\s+([^\s]+)\s+([\s\S]+)$/);
  assert.ok(match);
  assert.equal(match[1], "bob");
  assert.equal(match[2], "Hello   world!   Preserve   spaces.  ");
});
