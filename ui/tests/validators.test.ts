import { describe, expect, it } from "vitest";
import { validateScanReport } from "@/lib/validators";

function report(score: unknown = null) {
  return {
    agents: [{ name: "reviewer", agent_type: "custom", mcp_servers: [{ name: "filesystem", packages: [{ name: "example", version: "1.0.0", ecosystem: "pypi", vulnerabilities: [{ id: "CVE-2026-0001", severity: "high", cvss_score: score, epss_score: score }] }] }] }],
    blast_radius: [{ vulnerability_id: "CVE-2026-0001", severity: "high", affected_agents: ["reviewer"], exposed_credentials: [], reachable_tools: [], blast_score: 10, cvss_score: score, epss_score: score }],
  };
}

describe("CLI JSON report import", () => {
  it.each([200, 800])("rejects malformed agents beyond index %s", (index) => {
    const data = report();
    const agents: unknown[] = Array.from({ length: index + 1 }, () => data.agents[0]);
    agents[index] = { name: "unchecked", agent_type: "custom", mcp_servers: null };
    expect(validateScanReport(JSON.stringify({ ...data, agents })).ok).toBe(false);
  });
  it.each([500, 1200])("rejects malformed blast entries beyond index %s", (index) => {
    const data = report();
    const blast_radius: unknown[] = Array.from({ length: index + 1 }, () => data.blast_radius[0]);
    blast_radius[index] = null;
    expect(validateScanReport(JSON.stringify({ ...data, blast_radius })).ok).toBe(false);
  });
  it("normalizes current CLI tool aliases throughout a larger report", () => {
    const data = report();
    const blast = { ...data.blast_radius[0], reachable_tools: undefined, exposed_tools: ["read_file"] };
    const parsed = validateScanReport(JSON.stringify({ ...data, blast_radius: Array.from({ length: 750 }, () => blast) }));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const result = parsed.data as { blast_radius: Array<{ reachable_tools: string[] }> };
      expect(result.blast_radius.every((entry) => entry.reachable_tools?.[0] === "read_file")).toBe(true);
    }
  });
  it.each([0.5, Number.MAX_SAFE_INTEGER + 1])("rejects invalid canonical count %s", (count) => {
    expect(validateScanReport(JSON.stringify({ ...report(), finding_summary: { total: count, by_severity: { high: count } } })).ok).toBe(false);
  });
  it("rejects inconsistent severity totals", () => {
    expect(validateScanReport(JSON.stringify({ ...report(), finding_summary: { total: 1, by_severity: { high: 2 } } })).ok).toBe(false);
  });
  it.each(["affected_agents", "affected_servers", "exposed_credentials", "reachable_tools", "exposed_tools"])("rejects non-string %s entries before dashboard aggregation", (field) => {
    const data = report();
    Object.assign(data.blast_radius[0]!, { [field]: [{}] });
    expect(validateScanReport(JSON.stringify(data)).ok).toBe(false);
  });
  it.each(["package", "canonical_id", "fixed_version", "impact_category"])("rejects malformed exposure label %s", (field) => {
    const data = report();
    Object.assign(data.blast_radius[0]!, { [field]: {} });
    expect(validateScanReport(JSON.stringify(data)).ok).toBe(false);
  });
  it("bounds UTF-8 bytes independently from string length", () => {
    expect(validateScanReport(JSON.stringify({ ...report(), notes: "🌍".repeat(3 * 1024 * 1024) })).ok).toBe(false);
  });
  it("checks the byte limit even when called without a File object", () => {
    expect(validateScanReport(JSON.stringify({ ...report(), notes: "x".repeat(10 * 1024 * 1024) })).ok).toBe(false);
  });
  it("accepts reserved words as ordinary string values", () => {
    expect(validateScanReport(JSON.stringify({ ...report(), notes: "constructor" })).ok).toBe(true);
  });
  it.each(["__proto__", "constructor", "prototype"])("rejects escaped structural key %s", (key) => {
    const escaped = [...key].map((letter) => `\\u${letter.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
    expect(validateScanReport(JSON.stringify(report()).replace('"agents":', `"${escaped}":{},"agents":`)).ok).toBe(false);
  });
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
