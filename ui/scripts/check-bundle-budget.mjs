import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const NEXT_DIR = path.join(ROOT, ".next");
const CHUNKS_DIR = path.join(NEXT_DIR, "static", "chunks");
const BUILD_MANIFEST = path.join(NEXT_DIR, "build-manifest.json");

const BUDGETS = {
  totalClientJsBytes: 2_700_000,
  largestChunkBytes: 950_000,
  sharedAppBytes: 450_000,
};

function listJsFiles(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listJsFiles(fullPath));
      continue;
    }
    if (entry.isFile() && fullPath.endsWith(".js")) {
      files.push(fullPath);
    }
  }
  return files;
}

function formatBytes(bytes) {
  return `${(bytes / 1024).toFixed(1)} KiB`;
}

if (!statSync(NEXT_DIR, { throwIfNoEntry: false })) {
  console.error("Missing .next/ build output. Run `npm run build` before `npm run bundle:check`.");
  process.exit(1);
}

const chunkFiles = listJsFiles(CHUNKS_DIR);
const totalClientJsBytes = chunkFiles.reduce((sum, file) => sum + statSync(file).size, 0);
const largestChunkBytes = chunkFiles.reduce((max, file) => Math.max(max, statSync(file).size), 0);

const manifest = JSON.parse(readFileSync(BUILD_MANIFEST, "utf8"));
let sharedAppBytes = 0;
for (const file of manifest.rootMainFiles ?? manifest.pages?.["/_app"] ?? []) {
  if (!file.endsWith(".js")) continue;
  const fullPath = path.join(NEXT_DIR, file);
  sharedAppBytes += statSync(fullPath, { throwIfNoEntry: false })?.size ?? 0;
}

const checks = [
  ["total client JS", totalClientJsBytes, BUDGETS.totalClientJsBytes],
  ["largest chunk", largestChunkBytes, BUDGETS.largestChunkBytes],
  ["shared app runtime", sharedAppBytes, BUDGETS.sharedAppBytes],
];

let failed = false;
for (const [label, actual, budget] of checks) {
  const status = actual > budget ? "FAIL" : "PASS";
  console.log(`${status} ${label}: ${formatBytes(actual)} / budget ${formatBytes(budget)}`);
  if (actual > budget) failed = true;
}

if (failed) {
  console.error("UI bundle budget exceeded. Reduce client bundle size or intentionally raise the checked-in budget.");
  process.exit(1);
}
