import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { waitForOwnedServer } from "../scripts/product-proof-server.mjs";

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function listeningServer() {
  const server = createServer((_request, response) => response.end("old preview"));
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP listener");
  return { port: address.port, url: `http://127.0.0.1:${address.port}` };
}

function pendingChild() {
  return Object.assign(new EventEmitter(), { stdout: new PassThrough(), exitCode: null, signalCode: null });
}

describe("owned product capture server", () => {
  it("accepts the actual spawned listener after readiness and HTTP health", async () => {
    const { port, url } = await listeningServer();
    const reserved = servers.pop()!;
    await new Promise<void>((resolve) => reserved.close(() => resolve()));
    const child = spawn(process.execPath, ["-e", `require('node:http').createServer((req, res) => res.end('current build')).listen(${port}, '127.0.0.1', () => console.log('Ready in 1ms'))`], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      await expect(waitForOwnedServer(url, child, { timeoutMs: 1500 })).resolves.toBeUndefined();
      expect(child.exitCode).toBeNull();
    } finally {
      if (child.exitCode === null) { const exited = once(child, "exit"); child.kill(); await exited; }
    }
  });

  it("rejects a port collision even when an unrelated preview responds with HTTP 200", async () => {
    const { port, url } = await listeningServer();
    const child = spawn(process.execPath, ["-e", `require('node:http').createServer().listen(${port}, '127.0.0.1')`], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      await expect(waitForOwnedServer(url, child, { timeoutMs: 1500 })).rejects.toThrow(/capture server.*exit/i);
    } finally {
      if (child.exitCode === null) { const exited = once(child, "exit"); child.kill(); await exited; }
    }
  });

  it("rejects an already exited child before probing an old preview", async () => {
    const { url } = await listeningServer();
    await expect(waitForOwnedServer(url, { ...pendingChild(), exitCode: 1 })).rejects.toThrow(/capture server.*exit/i);
  });

  it("requires readiness from the spawned child before accepting HTTP health", async () => {
    const { url } = await listeningServer();
    const child = pendingChild();
    await expect(waitForOwnedServer(url, child, { timeoutMs: 80 })).rejects.toThrow(/timed out/i);
  });

  it("accepts a healthy child after its split readiness message", async () => {
    const { url } = await listeningServer();
    const child = pendingChild();
    const ready = waitForOwnedServer(url, child, { timeoutMs: 1000 });
    child.stdout.write("✓ Rea");
    child.stdout.write("dy in 82ms\n");
    await expect(ready).resolves.toBeUndefined();
  });

  it("rejects process launch failure without leaking the process error", async () => {
    const { url } = await listeningServer();
    const child = pendingChild();
    const ready = waitForOwnedServer(url, child, { timeoutMs: 1000 });
    child.emit("error", new Error("private launch path"));
    await expect(ready).rejects.toThrow("Could not launch capture server");
  });
});
