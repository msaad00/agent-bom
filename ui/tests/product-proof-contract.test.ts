import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const source = fs.readFileSync(path.join(process.cwd(), "scripts", "capture-product-proof.mjs"), "utf8");
const findingsQueue = fs.readFileSync(path.join(process.cwd(), "components", "findings-queue.tsx"), "utf8");
const graphPage = fs.readFileSync(path.join(process.cwd(), "app", "graph", "graph-page-client.tsx"), "utf8");
const exposurePath = fs.readFileSync(path.join(process.cwd(), "components", "exposure-path-command-center.tsx"), "utf8");

describe("product proof capture contract", () => {
  it("uses the hash-pinned real-advisory lab only for correlation proof and keeps gallery fixtures fictional", () => {
    expect(source).toContain("REFERENCE_LAB_PROOF_PATH");
    expect(source).toContain("REFERENCE_LAB_DIGEST_PATH");
    expect(source).toContain("Reference evidence lab proof is stale");
    expect(source).toContain("CVE-2023-4863");
    expect(source).toContain("DEMO-VULN-");
    expect(source).not.toContain('source: "nvd"');
    expect(source).not.toContain("is_kev: true");
    expect(source).not.toMatch(/\b(?:epss_score|is_kev|cisa_kev|kev)\s*:/);
    expect(source).not.toMatch(/function vuln\([^)]*epss/);
    expect(source).not.toMatch(/cve:\s*\["DEMO-VULN-[^"]+",\s*"[^"]+",\s*\d+(?:\.\d+)?,\s*0\.\d+/);
  });

  it("fails capture on HTTP, browser, visible, or version errors", () => {
    expect(source).toContain("response.ok()");
    expect(source).toContain('page.on("console"');
    expect(source).toContain('page.on("pageerror"');
    expect(source).toContain('page.on("requestfailed"');
    expect(source).toContain('page.on("response"');
    expect(source).toContain("response.status() >= 400");
    expect(source).toContain("fatalWarningPattern");
    expect(source).toContain("expectedApiPaths");
    expect(source).toContain("minGraphNodes");
    expect(source).toContain("visibleErrorPatterns");
    expect(source).toContain("RELEASE_VERSION");
    expect(source).toContain("isBenignAppRouterCancellation");
    expect(source).toContain('request.resourceType() !== "fetch"');
    expect(source).toContain('requestUrl.searchParams.has("_rsc")');
    expect(source).toContain("successfulApiPaths.has(expectedPath)");
    expect(source).toContain("assertNoHorizontalOverflow");
    expect(source).toContain('execFileAsync("git", ["status", "--porcelain"]');
    expect(source).toContain("Release product proof requires a clean committed source tree");
    expect(source).toContain("CAPTURE_BASE_URL is not allowed for release product proof");
    expect(source).toContain("screenshotSha256");
    expect(source).not.toContain("actualPath.startsWith(expectedPath)");
    expect(source).toContain("await browser?.close()");
    expect(source).toContain("await stopServer(server)");
    expect(source).toContain("agent-bom-product-proof-");
    expect(source).toContain('spawn(process.execPath, ["server.js"]');
    expect(source).toContain('path.join(UI_ROOT, ".next", "standalone")');
    expect(source).toContain('path.join(UI_ROOT, ".next", "static")');
    expect(source).not.toContain('["run", "dev"');
    expect(graphPage).toContain("if (captureMode)");
    expect(graphPage).toContain('nextParams.set("capture", "1")');
    expect(graphPage).toContain('history.replaceState(history.state, "", url)');
  });

  it("captures persisted pipeline telemetry and the agent lifecycle surface", () => {
    expect(source).toContain('path: "jobs-pipeline-live.png"');
    expect(source).toContain('path: "agent-lifecycle-live.png"');
    expect(source).toContain('step_id: "discovery"');
    expect(source).toContain('step_id: "output"');
    expect(source).toContain('page.route("**/v1/agents/developer-copilot/lifecycle"');
    expect(source).toContain("/6\\/6 stages complete/i");
  });

  it("locks current and proposed Investigation Canvas proof to both audited viewports", () => {
    expect(source).toContain('path: "investigation-canvas-current-1512x811.png"');
    expect(source).toContain('path: "investigation-canvas-proposed-1568x780.png"');
    expect(source).toContain('page: "/security-graph?lens=estate&rollup=1&capture=1"');
    expect(source).toContain(
      'page: `/security-graph?lens=estate&rollup=1&scenario=${SCENARIO_ID}&state=proposed&capture=1`',
    );
    expect(source).toContain('newCapturePage("dark", { width: 1512, height: 811 })');
    expect(source).toContain('newCapturePage("light", { width: 1568, height: 780 })');
    expect(source).toContain('data-testid="graph-rollup-decision-surface"');
    expect(source).toContain('data-testid="graph-rollup-relationship-completeness"');
    expect(source).toContain("top_level: graph.nodes.slice(0, 30)");
    expect(source).toContain('data-testid="graph-rollup-card-grid"');
    expect(source).toContain('page.route("**/v1/graph/scenarios"');
    expect(source).toContain('page.route(`**/v1/graph/scenarios/${SCENARIO_ID}/comparison?**`');
    expect(source).toContain("Proposed scenario — not observed or deployed");
    expect(source).toContain('section[aria-label="Scenario comparison"]:has-text');
    expect(source).not.toContain('section[aria-label="Architecture scenario"]:has-text');
  });

  it("pins the legacy attack-path proof to its explicit canonical lens", () => {
    expect(source).toContain('page: `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`');
    expect(source).toContain(
      'await capture(page, `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`, "security-graph-live.png"',
    );
    expect(source).not.toContain('"/security-graph?capture=1"');
  });

  it("captures the reference-lab receipt DAG and confirmed path from one pinned artifact", () => {
    expect(source).toContain('path: "correlation-receipts-live.png"');
    expect(source).toContain('path: "correlation-path-live.png"');
    expect(source).toContain('getByTestId("graph-correlation-receipt-dag")');
    expect(source).toContain('getByTestId("attack-path-correlation-proof")');
    expect(source).toContain("referenceLabActualDigest");
    expect(source).toContain("correlation_manifest_sha256");
    expect(source).toContain("Runtime block verified");
    expect(source).toContain("Reference evidence lab — modeled local infrastructure");
    expect(source).toContain('window.scrollTo({ top: workflowTop - 88, behavior: "instant" })');
  });

  it("keeps the base graph fixture from swallowing graph subroutes", () => {
    expect(source).toContain('page.route((url) => url.pathname === "/v1/graph"');
    expect(source).not.toContain('page.route("**/v1/graph?**"');
  });

  it("pins lineage proof through shareable URL filters rather than secondary controls", () => {
    expect(source).toContain('/graph?capture=1&scan=${SCAN_ID}&agent=developer-copilot&vulnOnly=1');
    expect(source).toContain('getByRole("heading", { name: "Lineage Graph" })');
    expect(source).not.toContain('hasText: "Advanced controls"');
    expect(source).not.toContain('getByRole("option", { name: "developer-copilot"');
  });

  it("mocks the overview trend request instead of reaching an absent backend", () => {
    expect(source).toContain('page.route("**/v1/trends?**"');
    expect(source).toContain('scan_id: "scan-proof-baseline"');
    expect(source).toContain("data_points:");
  });

  it("asserts the current canonical Findings vocabulary", () => {
    expect(source).toContain('expectedText: ["Findings queue", "15 issues"');
    expect(source).not.toContain('expectedText: ["Findings queue", "15 findings"');
  });

  it("tracks the current scan workspace proof copy", () => {
    expect(source).toContain('expectedText: ["New Scan", "What this scan collects and produces"');
    expect(source).toContain('"Read-only boundary", /Scope now/i, /Scan jobs/i');
    expect(source).toContain('expectedApiPaths: ["/v1/cloud/connections", "/v1/sources"]');
    expect(source).not.toContain("/Collector plan/i");
    expect(source).not.toContain("/Recent scans/i");
  });

  it("filters audit proof server-side and waits for identity lifecycle rows", () => {
    expect(source).toContain('url.searchParams.get("resource")');
    expect(source).toContain('"agent_identity.issued"');
    expect(source).toContain('"agent_identity.rotated"');
    expect(source).toContain('"agent_identity.revoked"');
    expect(source).toContain('url.searchParams.get("resource") === "identity"');
  });

  it("keeps path subtitles below wrapped two-line graph labels", () => {
    expect(exposurePath).toContain("titleLines.length > 1 ? 72 : 58");
  });

  it("mocks the authenticated ticket list used by remediation", () => {
    expect(source).toContain('page.route("**/v1/ticketing/tickets"');
    expect(source).toContain('schema_version: "ticketing.tickets.v1"');
  });

  it("mocks the campaign-first remediation contracts", () => {
    expect(source).toContain('page.route("**/v1/campaigns"');
    expect(source).toContain('page.route("**/v1/campaigns/verification-queue**"');
    expect(source).toContain('schema_version: "risk-campaigns.v1"');
    expect(source).toContain('page.route("**/v1/ticketing/connections"');
  });

  it("does not present fictional identifiers as OSV advisories", () => {
    expect(findingsQueue).toMatch(/getOsvVulnerabilityUrl\((?:v|vuln)\.id\)/);
    expect(findingsQueue).not.toContain("https://osv.dev/vulnerability/${v.id}");
  });

  it("explains why a finding cannot be verified", () => {
    expect(findingsQueue).not.toContain('"Verify unavailable"');
    expect(findingsQueue).toContain("No scanner-provided verification command");
  });
});
