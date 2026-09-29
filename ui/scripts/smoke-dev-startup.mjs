// Exercise the contributor entry point separately from the production bundle.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const uiRoot = fileURLToPath(new URL("../", import.meta.url));
const reservation = net.createServer();
reservation.listen(0, "127.0.0.1");
await once(reservation, "listening");
const { port } = reservation.address();
await new Promise((resolve) => reservation.close(resolve));

const child = spawn("npm", ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(port)], {
  cwd: uiRoot,
  env: { ...process.env, NEXT_EXPORT: "0", NEXT_TELEMETRY_DISABLED: "1", NEXT_PUBLIC_API_URL: "" },
  detached: process.platform !== "win32",
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
for (const stream of [child.stdout, child.stderr]) {
  stream.on("data", (data) => { output = (output + data.toString()).slice(-64_000); });
}
const exited = once(child, "exit");
try {
  const deadline = Date.now() + 90_000;
  let ready = false;
  while (Date.now() < deadline && child.exitCode === null) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/login`, { signal: AbortSignal.timeout(10_000) });
      const html = await response.text();
      if (response.ok && response.headers.get("content-type")?.includes("text/html") && html.includes("agent-bom")) {
        ready = true;
        break;
      }
    } catch {
      // The server may still be binding or compiling its first route.
    }
    await delay(250);
  }
  assert.ok(ready, `npm run dev did not serve the login route:\n${output}`);
  console.log("Development startup smoke passed: npm run dev served /login.");
} finally {
  if (child.pid) {
    if (process.platform === "win32") child.kill("SIGTERM");
    else {
      try { process.kill(-child.pid, "SIGTERM"); } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    }
  }
  await exited;
}
