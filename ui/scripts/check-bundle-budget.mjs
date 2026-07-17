import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const NEXT_DIR = path.join(ROOT, ".next");
const CHUNKS_DIR = path.join(NEXT_DIR, "static", "chunks");
const BUILD_MANIFEST = path.join(NEXT_DIR, "build-manifest.json");

const BUDGETS = {
  // Includes the opt-in Sigma.js + graphology WebGL overview chunk for dense graphs.
  // Also includes the Agent BOM manifest cockpit filters used for AI visibility triage.
  // Includes the root exposure cockpit path card and operational action tiles.
  // Includes the dashboard trust-mesh topology filters and offline-state workflow.
  // Allows measured framework/runtime drift from the June 2026 UI dependency refresh.
  // Includes the parity governance cockpits for cost, identity, and drift.
  // Includes the Gateway Live Feed tab for tool-call auth, DLP, and LLM-call events.
  // Includes cost forecast/chargeback and NHI governance console panels.
  // Includes the cloud CIS benchmark drill-down (per-cloud checks + remediation) on the compliance dashboard.
  // Includes the cross-domain overview landing page entrypoint and API client contract.
  // Includes the self-service cloud-connections page + Add Cloud Account wizard.
  // Includes recurring cloud-connection scan schedules; keep small CI variance headroom.
  // Includes the repo folder/file structure graph layer icons and code-layer filters.
  // Includes measured bundler/runtime drift from the July 2026 UI dependency refresh.
  // Includes the graph drift lens (#3192) — opt-in diff overlay on the lineage canvas.
  // Includes the hosted-demo banner and connect-your-cloud CTA shown from the shared app shell.
  // Includes the runtime evidence lens (#3192/#3610) — opt-in runtime/static evidence overlay.
  // Includes the consolidated operator surfaces: connector setup, jobs DAG, compliance drill-down,
  // and graph investigation. Total counts every emitted route chunk, including lazy-loaded views.
  // Includes the New Scan scope explainer, connected-account picker, and
  // repository-surface coverage cockpit shipped with the operator workflow.
  // Raised for the light-theme tokenization — semantic token class names
  // (`text-[color:var(--text-tertiary)]`) are longer string literals than the raw
  // `zinc-*` utilities they replace, so the compiled className strings grow a few KiB.
  // Allows 4 KiB for the measured Linux/macOS output variance after adding the
  // blueprint route; both builds remain at roughly 3.3 MiB of emitted client JS.
  // Raised to 3456 KiB (~150 KiB headroom over the ~3304 KiB current build) for the
  // active UX/IA polish + feature phase (nav IA, graph, governance surfaces, and the
  // premium design-system foundation's shared-shell token classes): the near-term
  // queue of UI PRs is legitimate feature work, not bloat, and needs room.
  // The first-class AI/ML scan surface stays within that measured phase allowance.
  // Audit evidence, deploy-gate, and exposure-path parity also remain within it.
  // Includes the unified Asset Inventory section (a page per asset type —
  // packages, MCP servers, agents, cloud, identities, containers, code — driven
  // off the canonical context graph with correlated findings and a master/detail
  // split): a full new IA surface, ~12 KiB of client JS, plus small CI variance
  // headroom. Legitimate feature work, not bloat.
  // Includes the campaign command center, durable verification queue, and shared
  // investigation-lens controls. The combined Linux build measured 3511 KiB
  // (+23 KiB / 0.7% over the prior ceiling); 3536 KiB keeps bounded headroom
  // without changing the largest-chunk or shared-runtime budgets.
  totalClientJsBytes: 3_620_864,
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
