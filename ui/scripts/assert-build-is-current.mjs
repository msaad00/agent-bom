/**
 * Fail when .next is older than the sources it was built from.
 *
 * The Playwright config serves a prebuilt `.next/standalone` and reuses an
 * existing server outside CI. That makes E2E fast, and it also makes E2E
 * capable of testing code that no longer exists: edit a component, run the
 * suite, and the assertions run against the PREVIOUS build.
 *
 * This bit exactly once already. A test asserting a panel was collapsed by
 * default kept failing after the fix had been written and typechecked — the
 * served bundle predated the edit. The wrong conclusions available at that
 * moment were "the fix does not work" or "the primitive is broken"; the truth
 * was "you are testing a stale artifact".
 *
 * A stale build must be an explicit, named failure rather than a mysterious
 * assertion mismatch that sends someone debugging the wrong layer.
 */

import { readdirSync, statSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const BUILD_MANIFEST = path.join(ROOT, ".next", "build-manifest.json");
const SOURCE_DIRS = ["app", "components", "lib", "hooks"];
const SOURCE_FILES = ["package.json", "package-lock.json", "next.config.ts", "next.config.js"];
const WATCHED_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".css", ".json"]);

function newestMtime(dir) {
  let newest = 0;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return 0;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      newest = Math.max(newest, newestMtime(full));
      continue;
    }
    if (!WATCHED_EXTENSIONS.has(path.extname(entry.name))) continue;
    const stat = statSync(full, { throwIfNoEntry: false });
    if (stat && stat.mtimeMs > newest) newest = stat.mtimeMs;
  }
  return newest;
}

const manifest = statSync(BUILD_MANIFEST, { throwIfNoEntry: false });
if (!manifest) {
  console.error("Missing .next build output. Run `npm run build` before the E2E suite.");
  process.exit(1);
}

let newestSource = 0;
let newestPath = "";
for (const dir of SOURCE_DIRS) {
  const mtime = newestMtime(path.join(ROOT, dir));
  if (mtime > newestSource) {
    newestSource = mtime;
    newestPath = dir;
  }
}
for (const file of SOURCE_FILES) {
  const stat = statSync(path.join(ROOT, file), { throwIfNoEntry: false });
  if (stat && stat.mtimeMs > newestSource) {
    newestSource = stat.mtimeMs;
    newestPath = file;
  }
}

if (newestSource > manifest.mtimeMs) {
  const ageSeconds = Math.round((newestSource - manifest.mtimeMs) / 1000);
  console.error(`.next is STALE: ${newestPath} changed ${ageSeconds}s after the last build.`);
  console.error("E2E would run against the previous build, so failures would describe code you have already changed.");
  console.error("\nRun `npm run build`, then re-run the suite.");
  process.exit(1);
}

console.log("OK: .next is newer than every watched source.");
