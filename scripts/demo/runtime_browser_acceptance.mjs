// Real browser -> production Next proxy -> Helm API; no route mocks or fake API responses.
// Configuration (including the short-lived session cookie) arrives only through stdin.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdirSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const config = JSON.parse(input);
const require = createRequire(path.join(config.uiRoot, "package.json"));
const { chromium, expect } = require("@playwright/test");
const serverFile = path.join(config.uiRoot, ".next/standalone/server.js");
assert.ok(existsSync(serverFile), "Build the standalone UI first");
mkdirSync(config.output, { recursive: true });

async function freePort() {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
const apiPort = await freePort(), uiPort = await freePort();
const origin = `http://127.0.0.1:${uiPort}`;
let forward, ui, browser, page;
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  await exited;
}
async function startForward() {
  forward = spawn("kubectl", ["--kubeconfig", config.kubeconfig, "-n", config.namespace,
    "port-forward", `pod/${config.pod}`, `${apiPort}:8422`, "--address=127.0.0.1"], { stdio: ["ignore", "pipe", "pipe"] });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("API port-forward did not become ready")), 30000);
    forward.stdout.on("data", chunk => { if (chunk.toString().includes("Forwarding from")) { clearTimeout(timer); resolve(); } });
    forward.once("exit", () => { clearTimeout(timer); reject(new Error("API port-forward exited")); });
  });
}
try {
  await startForward();
  ui = spawn(process.execPath, [serverFile], { cwd: config.uiRoot,
    env: { ...process.env, HOSTNAME: "127.0.0.1", PORT: String(uiPort), AGENT_BOM_API_URL: `http://127.0.0.1:${apiPort}` },
    stdio: "ignore" });
  await expect.poll(async () => {
    try { return (await fetch(origin)).status; } catch { return 0; }
  }, { timeout: 30000 }).toBe(200);
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.addCookies([{ ...config.cookie, url: origin, httpOnly: true, sameSite: "Lax" }]);
  const auth = await context.request.get(origin + "/v1/auth/me");
  assert.equal(auth.status(), 200, "Signed browser session must authenticate against the real API");
  page = await context.newPage();
  await page.goto(origin);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const variants = [];
  for (const theme of ["light", "dark"]) {
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await page.evaluate(value => localStorage.setItem("agent-bom-theme", value), theme);
      await page.goto(origin + "/runtime?tab=gateway");
      const feed = page.getByRole("region", { name: "Gateway activity", exact: true });
      await expect(feed.getByText("Connected to durable activity", { exact: true })).toBeVisible({ timeout: 45000 });
      await expect(feed.getByTestId("gateway-activity-row")).toHaveCount(212);
      await page.getByRole("button", { name: "Runtime profiles", exact: true }).click();
      await expect(page.getByRole("region", { name: "Runtime profiles", exact: true }).getByText("Acceptance · active · revision 1")).toBeVisible();
      await page.getByRole("button", { name: "Live Feed", exact: true }).click();
      await expect(feed.getByTestId("gateway-activity-row")).toHaveCount(212);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Page must fit viewport");
      assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), theme);
      await feed.scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(config.output, `${theme}-${width}.png`), fullPage: false });
      variants.push({ theme, width, events: 212 });
    }
  }
  const feed = page.getByRole("region", { name: "Gateway activity", exact: true });
  await stop(forward);
  await expect(feed.getByRole("status")).not.toHaveText("Connected to durable activity", { timeout: 45000 });
  await expect(feed.getByTestId("gateway-activity-row")).toHaveCount(212);
  await page.screenshot({ path: path.join(config.output, "mobile-degraded.png") });
  let resumed = false;
  page.on("request", request => {
    if (request.url().includes("/v1/gateway/feed/stream") && request.headers()["last-event-id"]) resumed = true;
  });
  await startForward();
  await feed.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect(feed.getByText("Connected to durable activity", { exact: true })).toBeVisible({ timeout: 45000 });
  await expect(feed.getByTestId("gateway-activity-row")).toHaveCount(212);
  assert.ok(resumed, "Reconnect must send the last completed durable cursor");
  await page.screenshot({ path: path.join(config.output, "mobile-reconnected.png") });
  assert.deepEqual(errors, [], "Browser runtime errors");
  await context.clearCookies();
  assert.equal((await context.request.get(origin + "/v1/gateway/feed")).status(), 401);
  process.stdout.write(JSON.stringify({ status: "passed", authentication: "signed session cookie verified by Helm API",
    transport: "production Next proxy and kubectl port-forward", variants, retained_events_during_outage: 212,
    resumed_with_cursor: resumed, anonymous_status: 401, screenshots: config.output }));
} catch (error) {
  if (page) {
    await page.screenshot({ path: path.join(config.output, "failure.png") });
    process.stderr.write((await page.locator("body").innerText()).slice(0, 6000) + "\n");
  }
  throw error;
} finally {
  await browser?.close();
  await stop(ui);
  await stop(forward);
}
