// Transport fixture contract; API authorization is validated separately.
import http from "node:http";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const base = fileURLToPath(new URL("../.next/standalone", import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function assert(v, m) {
  if (!v) throw new Error(m);
}
(async () => {
  const before = createHash("sha256").update(readFileSync(base + "/server.js")).digest("hex");
  const results = [];
  for (const label of ["alpha", "beta"]) {
    const requests = [];
    const backend = http.createServer((req, res) => {
      requests.push({ url: req.url, cookie: req.headers.cookie, authorization: req.headers.authorization, csrf: req.headers["x-csrf-token"], origin: req.headers.origin });
      if (req.url === "/v1/stream") {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform" });
        res.flushHeaders();
        res.write("data: first\n\n");
        setTimeout(() => res.end("data: last\n\n"), 700);
        return;
      }
      if (req.url === "/v1/auth/dev-session") {
        res.setHeader("set-cookie", ["session=opaque; HttpOnly; SameSite=Lax; Path=/", "csrf=token; SameSite=Lax; Path=/"]);
        res.statusCode = 204;
        res.end();
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ backend: label, ok: true }));
    });
    backend.on("upgrade", (req, socket) => {
      requests.push({ url: req.url, upgrade: true });
      const accept = createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
      socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
      const payload = Buffer.from(label);
      socket.write(Buffer.concat([Buffer.from([129, payload.length]), payload]));
      socket.on("data", () => socket.end());
      socket.on("error", () => {
      });
    });
    await new Promise((r) => backend.listen(0, "127.0.0.1", r));
    const backendPort = backend.address().port;
    const reservation = http.createServer();
    await new Promise((r) => reservation.listen(0, "127.0.0.1", r));
    const port = reservation.address().port;
    await new Promise((r) => reservation.close(r));
    let log = "";
    const child = spawn(process.execPath, [base + "/server.js"], { cwd: base, env: { ...process.env, PORT: String(port), HOSTNAME: "127.0.0.1", AGENT_BOM_API_URL: `http://127.0.0.1:${backendPort}`, NEXT_PUBLIC_API_URL: "http://127.0.0.1:1" }, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (d) => log += d);
    child.stderr.on("data", (d) => log += d);
    try {
      for (let i = 0; i < 100 && !log.includes("Ready"); i++) await sleep(100);
      assert(log.includes("Ready"), "standalone did not start");
      const origin = `http://127.0.0.1:${port}`;
      for (const path of ["/health", "/version", "/v1/auth/me?fixture=1"]) {
        const res = await fetch(origin + path, { headers: { authorization: "Bearer opaque", cookie: "session=opaque", "x-csrf-token": "token", origin }, signal: AbortSignal.timeout(5e3) });
        assert(res.ok && (await res.json()).backend === label, path + " wrong backend");
      }
      assert(requests.every((r) => r.authorization === "Bearer opaque" && r.cookie === "session=opaque" && r.csrf === "token" && r.origin === origin), "credential or origin forwarding failed");
      const session = await fetch(origin + "/v1/auth/dev-session", { method: "POST", headers: { origin } });
      assert(session.status === 204 && session.headers.getSetCookie().length === 2, "session cookies not preserved");
      const stream = await fetch(origin + "/v1/stream");
      const reader = stream.body.getReader();
      const start = Date.now();
      const first = await reader.read();
      assert(Buffer.from(first.value || []).toString().includes("first") && Date.now() - start < 600, "stream buffered");
      await reader.cancel();
      const ws = await new Promise((resolve, reject) => {
        const socket = new WebSocket(`ws://127.0.0.1:${port}/ws/live`);
        const timer = setTimeout(() => {
          socket.close();
          reject(new Error("WebSocket timed out"));
        }, 5e3);
        socket.onmessage = (e) => {
          clearTimeout(timer);
          resolve(e.data);
          socket.close();
        };
        socket.onerror = () => {
          clearTimeout(timer);
          reject(new Error("WebSocket failed"));
        };
      });
      assert(ws === label, "wrong WS backend");
      backend.closeAllConnections();
      await new Promise((r) => backend.close(r));
      const down = await fetch(origin + "/health", { signal: AbortSignal.timeout(5e3) });
      assert(down.status >= 500, "unreachable backend reported success");
      results.push({ backend: label, backendPort, http: true, cookies: true, csrfForwarding: true, streaming: true, websocket: true, unavailableStatus: down.status });
    } finally {
      child.kill("SIGTERM");
      await new Promise((r) => child.once("exit", r));
      backend.closeAllConnections();
      backend.close();
    }
  }
  assert(before === createHash("sha256").update(readFileSync(base + "/server.js")).digest("hex"), "build changed");
  console.log(JSON.stringify({ immutableBuild: before, results }, null, 2));
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
