/**
 * Fail loudly when node_modules does not match package-lock.json.
 *
 * A gate that measures the installed tree — bundle budgets, builds, E2E — is
 * only telling the truth if the installed tree is the one this branch pins.
 * Switching between branches with different lockfiles leaves the previous
 * branch's packages in place, and every downstream number silently describes
 * the WRONG dependency set.
 *
 * This is not hypothetical: a bundle measurement read 3679.2 KiB against a
 * 3664 KiB ceiling and looked like a real regression introduced by the branch's
 * own changes. node_modules still held a newer Next from another branch; a
 * clean install measured 3660.0 KiB, comfortably under budget. The gate had
 * reported a failure that did not exist, and the obvious "fix" would have been
 * to raise the budget to accommodate a package this branch does not even use.
 *
 * npm maintains node_modules/.package-lock.json as a mirror of what is actually
 * installed, so comparing the two is exact rather than heuristic.
 */

import { readFileSync, statSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const LOCKFILE = path.join(ROOT, "package-lock.json");
const INSTALLED = path.join(ROOT, "node_modules", ".package-lock.json");

/** Packages whose version drift changes what a gate measures.
 *
 * Optional and platform-gated entries are excluded. A lockfile lists every
 * platform's native binaries (`@esbuild/android-arm`, `@rollup/rollup-linux-*`),
 * and npm correctly installs only this host's. Treating those absences as drift
 * makes the check cry wolf on a perfectly clean install — which would train
 * everyone to ignore it, the opposite of the point.
 */
function versionsByPath(lock) {
  const out = new Map();
  for (const [pkgPath, entry] of Object.entries(lock.packages ?? {})) {
    if (!pkgPath.startsWith("node_modules/")) continue;
    if (!entry?.version) continue;
    if (entry.optional === true) continue;
    if (Array.isArray(entry.os) && !entry.os.includes(process.platform)) continue;
    if (Array.isArray(entry.cpu) && !entry.cpu.includes(process.arch)) continue;
    out.set(pkgPath, entry.version);
  }
  return out;
}

function read(file, label) {
  if (!statSync(file, { throwIfNoEntry: false })) {
    console.error(`Missing ${label} (${file}).`);
    if (file === INSTALLED) console.error("Run `npm ci` before any gate that measures the installed tree.");
    process.exit(1);
  }
  return JSON.parse(readFileSync(file, "utf8"));
}

const expected = versionsByPath(read(LOCKFILE, "package-lock.json"));
const actual = versionsByPath(read(INSTALLED, "node_modules/.package-lock.json"));

const drift = [];
for (const [pkgPath, want] of expected) {
  const got = actual.get(pkgPath);
  if (got === undefined) drift.push({ pkgPath, want, got: "missing" });
  else if (got !== want) drift.push({ pkgPath, want, got });
}
for (const [pkgPath, got] of actual) {
  if (!expected.has(pkgPath)) drift.push({ pkgPath, want: "not in lockfile", got });
}

if (drift.length > 0) {
  console.error(`node_modules does not match package-lock.json (${drift.length} package(s) differ).`);
  console.error("Any bundle, build, or E2E measurement taken now describes the WRONG dependency set.\n");
  for (const { pkgPath, want, got } of drift.slice(0, 15)) {
    console.error(`  ${pkgPath.replace(/^node_modules\//, "")}: lockfile ${want}, installed ${got}`);
  }
  if (drift.length > 15) console.error(`  … and ${drift.length - 15} more`);
  console.error("\nRun `npm ci` to install exactly what this branch pins, then re-run the gate.");
  process.exit(1);
}

console.log(`OK: node_modules matches package-lock.json (${expected.size} packages).`);
