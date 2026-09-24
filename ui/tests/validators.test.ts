import { describe, expect, it } from "vitest";
import { validateScanReport } from "@/lib/validators";

function report(score: unknown = null) {
  return {
    agents: [{ name: "reviewer", agent_type: "custom", mcp_servers: [{ name: "filesystem", packages: [{ name: "example", version: "1.0.0", ecosystem: "pypi", vulnerabilities: [{ id: "CVE-2026-0001", severity: "high", cvss_score: score, epss_score: score }] }] }] }],
    blast_radius: [{ vulnerability_id: "CVE-2026-0001", severity: "high", affected_agents: ["reviewer"], exposed_credentials: [], reachable_tools: [], blast_score: 10, cvss_score: score, epss_score: score }],
  };
}

describe("CLI JSON report import", () => {
  it("accepts unrated advisories emitted by the CLI", () => {
    const data = report();
    data.agents[0]!.mcp_servers[0]!.packages[0]!.vulnerabilities[0]!.severity = "unknown";
    data.blast_radius[0]!.severity = "unknown";
    expect(validateScanReport(JSON.stringify(data)).ok).toBe(true);
  });
  it("rejects malformed canonical totals instead of rendering them", () => {
    expect(validateScanReport(JSON.stringify({ ...report(), finding_summary: { total: 1, by_severity: { high: "one" } } })).ok).toBe(false);
  });
  it.each([null, undefined, 0, 0.5, 9.8])("accepts unavailable or finite enrichment scores: %s", (score) => {
    expect(validateScanReport(JSON.stringify(report(score))).ok).toBe(true);
  });
  it.each(["NaN", "Infinity", "1", {}, [], true])("rejects non-numeric scores: %s", (score) => {
    expect(validateScanReport(JSON.stringify(report(score))).ok).toBe(false);
  });
  it.each(["NaN", "Infinity", "1e400", "-1e400"])("rejects non-finite JSON scores: %s", (score) => {
    expect(validateScanReport(JSON.stringify(report()).replaceAll('"cvss_score":null', `"cvss_score":${score}`)).ok).toBe(false);
  });
  it("imports the current CLI exposed_tools field without the legacy alias", () => {
    const data = report();
    const entry = data.blast_radius[0]!;
    const current = { ...entry, reachable_tools: undefined };
    const parsed = validateScanReport(JSON.stringify({ ...data, blast_radius: [{ ...current, exposed_tools: ["read_file"] }] }));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.data).toMatchObject({ blast_radius: [{ reachable_tools: ["read_file"] }] });
  });
  it("does not hide a malformed legacy field behind a valid alias", () => {
    const data = report();
    Object.assign(data.blast_radius[0]!, { reachable_tools: null, exposed_tools: [] });
    expect(validateScanReport(JSON.stringify(data)).ok).toBe(false);
  });
  it("still rejects null for the non-nullable blast score", () => {
    expect(validateScanReport(JSON.stringify(report()).replace('"blast_score":10', '"blast_score":null')).ok).toBe(false);
  });
  it.each(["cvss_score", "epss_score"])("validates blast-radius %s independently", (field) => {
    const data = report();
    Object.assign(data.blast_radius[0]!, { [field]: "wrong" });
    expect(validateScanReport(JSON.stringify(data)).ok).toBe(false);
  });
});
