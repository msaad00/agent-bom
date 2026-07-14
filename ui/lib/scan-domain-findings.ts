/**
 * Derive per-domain scanner findings from a scan result.
 *
 * Shared by the jobs pipeline panel and the full scan view so both render the
 * same branching DAG lanes and the same reconciled finding count. Cloud CIS
 * fields arrive as `unknown`, so every accessor is defensive.
 */

import type { ScanResult, Summary } from "@/lib/api";
import {
  deriveDomainLanes,
  reconcileFindings,
  type CisSummary,
  type DomainLaneData,
  type ReconciledFindings,
  type ScannerDomain,
} from "@/lib/scan-pipeline-graph";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function cloudResourceCount(inventory: unknown): number | null {
  if (Array.isArray(inventory)) {
    let total = 0;
    let seen = false;
    for (const item of inventory) {
      if (!isRecord(item)) continue;
      const n = asNumber(item.resource_count);
      if (n != null) {
        total += n;
        seen = true;
      }
    }
    return seen ? total : null;
  }
  if (isRecord(inventory)) return asNumber(inventory.resource_count);
  return null;
}

export function cloudIdentityCount(inventory: unknown): number | null {
  if (Array.isArray(inventory)) {
    let total = 0;
    let seen = false;
    for (const item of inventory) {
      if (!isRecord(item)) continue;
      const n = asNumber(item.identity_count);
      if (n != null) {
        total += n;
        seen = true;
      }
    }
    return seen ? total : null;
  }
  if (isRecord(inventory)) return asNumber(inventory.identity_count);
  return null;
}

/** Pass/fail/total for a single CIS benchmark, from explicit counts or a checks array. */
function cisCounts(benchmark: unknown): { passed: number; failed: number; total: number } | null {
  if (!isRecord(benchmark)) return null;
  const passed = asNumber(benchmark.passed);
  const failed = asNumber(benchmark.failed);
  const total = asNumber(benchmark.total);
  if (passed != null || failed != null || total != null) {
    const p = passed ?? 0;
    const f = failed ?? 0;
    return { passed: p, failed: f, total: total ?? p + f };
  }
  const checks = benchmark.checks;
  if (Array.isArray(checks)) {
    let p = 0;
    let f = 0;
    for (const raw of checks) {
      if (!isRecord(raw)) continue;
      const status = String(raw.status ?? raw.result ?? "").toLowerCase();
      if (["pass", "passed", "ok", "success"].includes(status)) p += 1;
      if (["fail", "failed", "error"].includes(status)) f += 1;
    }
    return { passed: p, failed: f, total: checks.length };
  }
  return null;
}

function passRateOnly(benchmark: unknown): number | null {
  if (!isRecord(benchmark)) return null;
  const raw = asNumber(benchmark.pass_rate);
  if (raw == null) return null;
  // Backends emit either 0–1 or 0–100; normalize to a percentage.
  return raw <= 1 ? raw * 100 : raw;
}

/**
 * Aggregate every CIS benchmark on the result into one honest posture summary.
 * `failed` is "controls not passing" (total − passed) so it reconciles with
 * the pass-rate narrative — a 32%-pass run reports 68% as CSPM findings.
 */
export function cisSummaryFromResult(result: ScanResult | null | undefined): CisSummary | null {
  if (!result) return null;
  const benches = [
    result.cis_benchmark,
    result.azure_cis_benchmark,
    result.gcp_cis_benchmark,
    result.snowflake_cis_benchmark,
    result.databricks_cis_benchmark,
  ];
  let passed = 0;
  let total = 0;
  let seen = false;
  for (const bench of benches) {
    const counts = cisCounts(bench);
    if (!counts) continue;
    seen = true;
    passed += counts.passed;
    total += counts.total;
  }
  if (seen && total > 0) {
    return { passed, failed: Math.max(0, total - passed), total, passRate: (passed / total) * 100 };
  }
  const passRate =
    passRateOnly(result.cis_benchmark) ??
    passRateOnly(result.azure_cis_benchmark) ??
    passRateOnly(result.gcp_cis_benchmark) ??
    passRateOnly(result.snowflake_cis_benchmark) ??
    passRateOnly(result.databricks_cis_benchmark);
  if (passRate != null) return { passed: null, failed: null, total: null, passRate };
  return null;
}

export interface DomainFindingsView {
  lanes: Record<ScannerDomain, DomainLaneData>;
  reconciled: ReconciledFindings;
  cis: CisSummary | null;
}

/**
 * Build the scanner-lane table + reconciled totals for a completed scan.
 * A domain only counts as "ran" when the scan produced data for it, so a
 * repo SCA scan leaves the CIS/cloud lanes as "not run".
 */
export function domainFindingsForScan(input: {
  result?: ScanResult | null | undefined;
  summary?: Summary | null | undefined;
  summarized?: boolean;
}): DomainFindingsView {
  const summary = input.result?.summary ?? input.summary ?? undefined;
  const cis = cisSummaryFromResult(input.result);
  const scannedPackages = (summary?.total_packages ?? 0) > 0;
  const vulnerabilities = scannedPackages ? summary?.total_vulnerabilities ?? 0 : null;
  const lanes = deriveDomainLanes({ vulnerabilities, cis, summarized: input.summarized ?? false });
  return { lanes, reconciled: reconcileFindings(lanes), cis };
}
