import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const source = fs.readFileSync(path.join(process.cwd(), "scripts", "capture-product-proof.mjs"), "utf8");
const findingsQueue = fs.readFileSync(path.join(process.cwd(), "components", "findings-queue.tsx"), "utf8");
const graphPage = fs.readFileSync(path.join(process.cwd(), "app", "graph", "graph-page-client.tsx"), "utf8");
const exposurePath = fs.readFileSync(path.join(process.cwd(), "components", "exposure-path-command-center.tsx"), "utf8");

describe("product proof capture contract", () => {
  it("uses unmistakably fictional vulnerability identifiers", () => {
    expect(source).not.toMatch(/CVE-\d{4}-\d+/);
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
    expect(findingsQueue).toContain("getOsvVulnerabilityUrl(v.id)");
    expect(findingsQueue).not.toContain("https://osv.dev/vulnerability/${v.id}");
  });
});
