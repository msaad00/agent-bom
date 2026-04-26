// Pin the contract that the dashboard CSP and companion headers come from a
// single source and that script-src no longer carries 'unsafe-inline'. If
// next.config.ts and ui/vercel.json drift, or if a hash for an inline script
// is missing, this test fails before the change can ship.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { THEME_BOOTSTRAP_SCRIPT } from "../lib/csp-source.mjs";
import { cspHeaderValue, securityHeaders } from "../lib/security-headers.mjs";

const UI_ROOT = resolve(__dirname, "..");
const VERCEL_PATH = resolve(UI_ROOT, "vercel.json");

describe("security-headers", () => {
  it("script-src does not carry 'unsafe-inline'", () => {
    const csp = cspHeaderValue();
    const scriptSrc = csp.split(";").find((directive) => directive.trim().startsWith("script-src "));
    expect(scriptSrc, "script-src directive must be present").toBeDefined();
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it("script-src includes the sha256 of THEME_BOOTSTRAP_SCRIPT", async () => {
    // Use the runtime crypto module rather than re-deriving by hand so the
    // test detects an upstream change in security-headers' hash algorithm.
    const { createHash } = await import("node:crypto");
    const expected = `'sha256-${createHash("sha256").update(THEME_BOOTSTRAP_SCRIPT, "utf8").digest("base64")}'`;
    const csp = cspHeaderValue();
    expect(csp).toContain(expected);
  });

  it("emits the standard companion headers", () => {
    const headers = securityHeaders();
    const keys = headers.map((h) => h.key);
    expect(keys).toEqual([
      "Content-Security-Policy",
      "X-Content-Type-Options",
      "X-Frame-Options",
      "Referrer-Policy",
      "Strict-Transport-Security",
      "Permissions-Policy",
    ]);
  });

  it("ui/vercel.json mirrors lib/security-headers.mjs", () => {
    const vercel = JSON.parse(readFileSync(VERCEL_PATH, "utf8"));
    expect(vercel.headers).toHaveLength(1);
    const onDisk = vercel.headers[0].headers as Array<{ key: string; value: string }>;
    const expected = securityHeaders();
    expect(onDisk).toEqual(expected);
  });
});
