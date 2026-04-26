// Pin the contract that the dashboard CSP and companion headers come from a
// single source. The hash-only follow-up to #1954 will remove 'unsafe-inline'
// from script-src once a build-time hash collector for Next.js streaming
// inline scripts is in place; until then this test guards the centralization
// + sync mechanism that makes the flip a one-line change later.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { THEME_BOOTSTRAP_SCRIPT } from "../lib/csp-source.mjs";
import { INLINE_SCRIPT_HASHES, cspHeaderValue, securityHeaders } from "../lib/security-headers.mjs";

const UI_ROOT = resolve(__dirname, "..");
const VERCEL_PATH = resolve(UI_ROOT, "vercel.json");

describe("security-headers", () => {
  it("CSP forbids unsafe-eval and locks down inline-event-handler sinks", () => {
    const csp = cspHeaderValue();
    expect(csp).not.toContain("'unsafe-eval'");
    expect(csp).toContain("script-src-attr 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
  });

  it("THEME_BOOTSTRAP_SCRIPT is inventoried so the hash-only follow-up is a one-line flip", async () => {
    // The hash itself isn't yet enforced in CSP (Next.js streaming inline
    // scripts need build-time hash collection — tracked as a #1954
    // follow-up), but the inventory entry must already exist so the
    // migration only flips the script-src construction.
    const { createHash } = await import("node:crypto");
    const expected = `'sha256-${createHash("sha256").update(THEME_BOOTSTRAP_SCRIPT, "utf8").digest("base64")}'`;
    expect(INLINE_SCRIPT_HASHES).toContain(expected);
  });

  it("emits the standard companion headers in stable order", () => {
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

  it("ui/vercel.json mirrors lib/security-headers.mjs (sync test)", () => {
    const vercel = JSON.parse(readFileSync(VERCEL_PATH, "utf8"));
    expect(vercel.headers).toHaveLength(1);
    const onDisk = vercel.headers[0].headers as Array<{ key: string; value: string }>;
    const expected = securityHeaders();
    expect(onDisk).toEqual(expected);
  });
});
