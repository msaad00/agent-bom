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

/** Preserve reported counts; a missing failure count is not a clean result. */
function cisCounts(benchmark: unknown): { passed: number | null; failed: number | null; total: number | null } | null {
  if (!isRecord(benchmark)) return null;
  const checks = Array.isArray(benchmark.checks) ? benchmark.checks : null;
  const countStatuses = (statuses: string[]) => checks == null ? null : checks.filter(
    (raw) => isRecord(raw) && statuses.includes(String(raw.status ?? raw.result ?? "").toLowerCase()),
  ).length;
  const passed = asNumber(benchmark.passed) ?? countStatuses(["pass", "passed", "ok", "success"]);
  const failed = asNumber(benchmark.failed) ?? countStatuses(["fail", "failed"]);
  const total = asNumber(benchmark.total) ?? checks?.length ?? (passed != null && failed != null ? passed + failed : null);
  if (passed == null && failed == null && total == null) return null;
  return { passed, failed, total };
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
 * Failed, errored, unevaluated and inapplicable checks retain distinct meanings.
 * Never infer failures by subtracting passes from the catalog size.
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
  const counts = benches.map(cisCounts).filter((count) => count != null);
  if (counts.length > 0) {
    const sumKnown = (key: "passed" | "failed" | "total"): number | null =>
      counts.every((count) => count[key] != null) ? counts.reduce((sum, count) => sum + count[key]!, 0) : null;
    const passed = sumKnown("passed");
    const failed = sumKnown("failed");
    const total = sumKnown("total");
    const evaluated = passed != null && failed != null ? passed + failed : null;
    return { passed, failed, total, passRate: passed != null && evaluated != null && evaluated > 0 ? (passed / evaluated) * 100 : null };
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

/** Saved scanner coverage is authoritative even when there are no findings. */
function secretLane(result: ScanResult | null | undefined): DomainLaneData | null {
  const block = result?.ai_inventory?.secrets;
  if (!isRecord(block)) return null;
  const total = asNumber(block.total);
  if (total == null || total < 0) return null;
  const categories = isRecord(block.by_category) ? block.by_category : {};
  const pii = asNumber(categories.pii) ?? 0;
  const secrets = (asNumber(categories.credential) ?? 0) + (asNumber(categories.secret) ?? 0);
  const parts: string[] = [];
  if (secrets > 0) parts.push(`${secrets} ${secrets === 1 ? "secret" : "secrets"}`);
  if (pii > 0) parts.push(`${pii} PII`);
  const counts = parts.length && pii + secrets === total
    ? parts.join(" · ")
    : `${total} ${total === 1 ? "finding" : "findings"}`;
  const incomplete = block.complete === false || (Array.isArray(block.warnings) && block.warnings.length > 0);
  const prefix = incomplete ? "incomplete · " : block.complete === true ? "" : "coverage unknown · ";
  return { ran: true, findings: total, detail: `${prefix}${counts}`, summarized: true };
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
  const secrets = secretLane(input.result);
  if (secrets) lanes.secrets = secrets;
  const resources = cloudResourceCount(input.result?.cloud_inventory);
  const identities = cloudIdentityCount(input.result?.cloud_inventory);
  if (resources != null || identities != null) {
    const detail = [resources != null ? `${resources} resources` : null, identities != null ? `${identities} identities` : null]
      .filter(Boolean).join(" · ");
    lanes.cloud = { ran: true, findings: null, detail, summarized: true };
  }
  return { lanes, reconciled: reconcileFindings(lanes), cis };
}
