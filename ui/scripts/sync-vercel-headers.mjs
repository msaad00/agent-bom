#!/usr/bin/env node
// Regenerate the headers section of ui/vercel.json from
// ui/lib/security-headers.mjs (the single source of truth) and report drift
// with --check.
//
// Why: previously next.config.ts and vercel.json each carried a hand-edited
// CSP, which drifted (next.config carried `img-src 'self' data: blob:` while
// vercel only allowed `data:`, vercel had `Strict-Transport-Security` while
// next.config did not, etc.). Closes #1954.
//
// Usage:
//   node scripts/sync-vercel-headers.mjs            # rewrite ui/vercel.json
//   node scripts/sync-vercel-headers.mjs --check    # exit 1 if drift

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { securityHeaders } from "../lib/security-headers.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const UI_ROOT = resolve(HERE, "..");
const VERCEL_PATH = resolve(UI_ROOT, "vercel.json");

const headers = securityHeaders();

const current = JSON.parse(readFileSync(VERCEL_PATH, "utf8"));
const expected = {
  ...current,
  headers: [
    {
      source: "/(.*)",
      headers: headers.map(({ key, value }) => ({ key, value })),
    },
  ],
};

const expectedJson = JSON.stringify(expected, null, 2) + "\n";
const currentJson = readFileSync(VERCEL_PATH, "utf8");

const checkOnly = process.argv.includes("--check");

if (currentJson === expectedJson) {
  if (checkOnly) {
    process.stdout.write(`OK: ui/vercel.json headers match lib/security-headers.mjs (${headers.length} headers).\n`);
  }
  process.exit(0);
}

if (checkOnly) {
  process.stderr.write(
    "ui/vercel.json headers are out of sync with lib/security-headers.mjs.\n" +
      "Run `npm run headers:sync` from the ui/ directory and commit the diff.\n",
  );
  process.exit(1);
}

writeFileSync(VERCEL_PATH, expectedJson, "utf8");
process.stdout.write(`Wrote ui/vercel.json (${headers.length} headers).\n`);
