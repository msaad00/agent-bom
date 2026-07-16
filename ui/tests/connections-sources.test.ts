import { describe, expect, it } from "vitest";

import type { CloudConnectionRecord, SourceRecord } from "@/lib/api";
import {
  buildUnifiedRows,
  categoryCounts,
  filterUnifiedRows,
  sourceKindCategory,
  statusOptions,
} from "@/lib/connections-sources";

function cloud(overrides: Partial<CloudConnectionRecord> = {}): CloudConnectionRecord {
  return {
    id: "conn-1",
    tenant_id: "tenant-acme",
    provider: "aws",
    display_name: "Production account",
    role_ref: "arn:aws:iam::123456789012:role/agent-bom-readonly",
    has_external_id: true,
    regions: ["us-east-1"],
    status: "active",
    status_detail: "",
    created_at: "2026-06-27T00:00:00Z",
    updated_at: "2026-06-27T00:00:00Z",
    last_scan_at: "2026-06-27T01:00:00Z",
    last_event_at: null,
    last_scan_id: "scan-1",
    scan_interval_minutes: 60,
    ...overrides,
  };
}

function source(overrides: Partial<SourceRecord> = {}): SourceRecord {
  return {
    source_id: "src-1",
    tenant_id: "tenant-acme",
    display_name: "Repo mono",
    kind: "scan.repo",
    description: "",
    owner: "platform-security",
    connector_name: null,
    credential_mode: "none",
    credential_ref: null,
    enabled: true,
    status: "configured",
    config: {},
    last_tested_at: null,
    last_test_status: null,
    last_test_message: null,
    last_run_at: "2026-06-26T00:00:00Z",
    last_run_status: "done",
    last_job_id: "job-1",
    created_at: "2026-06-20T00:00:00Z",
    updated_at: "2026-06-20T00:00:00Z",
    ...overrides,
  };
}

describe("connections-sources merge model", () => {
  it("maps a cloud connection to a cloud-origin row with schedule + provider", () => {
    const rows = buildUnifiedRows([cloud()], []);
    expect(rows).toHaveLength(1);
    const [row] = rows;
    expect(row).toMatchObject({
      id: "cloud:conn-1",
      origin: "cloud",
      name: "Production account",
      category: "cloud",
      provider: "aws",
      connectionId: "conn-1",
      scheduleCount: 1,
      lastScanAt: "2026-06-27T01:00:00Z",
    });
  });

  it("maps registered sources to their category and label", () => {
    const rows = buildUnifiedRows(
      [],
      [
        source({ source_id: "a", display_name: "Repo", kind: "scan.repo" }),
        source({ source_id: "b", display_name: "MCP", kind: "scan.mcp_config" }),
        source({ source_id: "c", display_name: "Lake", kind: "connector.warehouse" }),
        source({ source_id: "d", display_name: "Proxy", kind: "runtime.proxy" }),
        source({ source_id: "e", display_name: "Fleet", kind: "ingest.fleet_sync" }),
      ],
    );
    expect(rows.map((r) => r.category)).toEqual(["code", "ai", "data", "runtime", "ingest"]);
    expect(rows[0]).toMatchObject({ origin: "source", sourceId: "a", kindLabel: "Repo / package scan" });
  });

  it("dedupes a cloud account registered in both surfaces (cloud row wins)", () => {
    const rows = buildUnifiedRows(
      [cloud({ display_name: "Production Account" })],
      [
        source({ source_id: "dup", display_name: "production account", kind: "scan.cloud" }),
        source({ source_id: "keep", display_name: "Repo mono", kind: "scan.repo" }),
      ],
    );
    // The cloud-kind source that mirrors the connection name is dropped.
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.sourceId === "dup")).toBeUndefined();
    expect(rows.find((r) => r.connectionId === "conn-1")).toBeDefined();
    expect(rows.find((r) => r.sourceId === "keep")).toBeDefined();
  });

  it("does not dedupe a non-cloud source that happens to share a name", () => {
    const rows = buildUnifiedRows(
      [cloud({ display_name: "Shared" })],
      [source({ source_id: "repo", display_name: "Shared", kind: "scan.repo" })],
    );
    expect(rows).toHaveLength(2);
  });

  it("counts schedules from a map keyed by source id", () => {
    const rows = buildUnifiedRows(
      [],
      [source({ source_id: "s1" }), source({ source_id: "s2", display_name: "Other" })],
      new Map([["s1", 3]]),
    );
    expect(rows.find((r) => r.sourceId === "s1")?.scheduleCount).toBe(3);
    expect(rows.find((r) => r.sourceId === "s2")?.scheduleCount).toBe(0);
  });

  it("filters by category, status, and free text", () => {
    const rows = buildUnifiedRows(
      [cloud({ display_name: "AWS prod", status: "active" })],
      [
        source({ source_id: "s1", display_name: "Repo mono", kind: "scan.repo", status: "healthy" }),
        source({ source_id: "s2", display_name: "IaC stack", kind: "scan.iac", status: "degraded" }),
      ],
    );
    expect(filterUnifiedRows(rows, { category: "cloud", status: "all", query: "" })).toHaveLength(1);
    expect(filterUnifiedRows(rows, { category: "code", status: "all", query: "" })).toHaveLength(2);
    expect(filterUnifiedRows(rows, { category: "all", status: "degraded", query: "" })).toHaveLength(1);
    expect(filterUnifiedRows(rows, { category: "all", status: "all", query: "iac" })).toHaveLength(1);
    expect(filterUnifiedRows(rows, { category: "all", status: "all", query: "zzz" })).toHaveLength(0);
  });

  it("summarizes category counts and status options", () => {
    const rows = buildUnifiedRows(
      [cloud({ status: "active" })],
      [
        source({ source_id: "s1", kind: "scan.repo", status: "healthy" }),
        source({ source_id: "s2", display_name: "b", kind: "scan.iac", status: "degraded" }),
      ],
    );
    const counts = categoryCounts(rows);
    expect(counts.all).toBe(3);
    expect(counts.cloud).toBe(1);
    expect(counts.code).toBe(2);
    expect(statusOptions(rows)).toEqual(["active", "degraded", "healthy"]);
  });

  it("classifies unknown kinds as ingest without throwing", () => {
    expect(sourceKindCategory("mystery.kind")).toBe("ingest");
  });
});
