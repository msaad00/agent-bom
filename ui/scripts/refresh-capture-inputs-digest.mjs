#!/usr/bin/env node
// Recompute ONLY docs/images/product-screenshots.json's capture_inputs_sha256
// field, without re-capturing screenshots and without touching source_commit
// or source_tree.
//
// Use this after PRODUCT_SCREENSHOT_INPUTS changes in this file's shared
// product-proof-provenance.mjs (and its Python mirror in
// scripts/check_release_consistency.py) — i.e. when the counted set of
// capture inputs changed but the screenshots themselves are still accurate.
// A change that can actually affect a rendered pixel must instead go through
// `npm run capture:product-proof`, which re-derives source_commit and
// source_tree from a real capture run.
//
// Usage:
//   node scripts/refresh-capture-inputs-digest.mjs            # rewrite the field
//   node scripts/refresh-capture-inputs-digest.mjs --check    # exit 1 if stale
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { computeCaptureInputsDigest } from "./product-proof-provenance.mjs";

const UI_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = path.resolve(UI_ROOT, "..");
const MANIFEST_PATH = path.join(REPO_ROOT, "docs", "images", "product-screenshots.json");

async function main() {
  const check = process.argv.includes("--check");
  const manifest = JSON.parse(await fs.readFile(MANIFEST_PATH, "utf8"));
  const digest = await computeCaptureInputsDigest(REPO_ROOT);

  if (check) {
    if (manifest.capture_inputs_sha256 !== digest) {
      console.error(
        `docs/images/product-screenshots.json capture_inputs_sha256 is stale: ${manifest.capture_inputs_sha256} != ${digest}`,
      );
      process.exitCode = 1;
      return;
    }
    console.log("docs/images/product-screenshots.json capture_inputs_sha256 is current");
    return;
  }

  if (manifest.capture_inputs_sha256 === digest) {
    console.log("docs/images/product-screenshots.json capture_inputs_sha256 already current");
    return;
  }
  manifest.capture_inputs_sha256 = digest;
  await fs.writeFile(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`Refreshed capture_inputs_sha256: ${digest}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
