import type { FindingTriageItem } from "@/lib/api";
import type { FindingFacets } from "@/lib/api-types";
import type { EnrichedVuln } from "@/lib/findings-view";

export interface FindingsWorkspaceMetric {
  label: string;
  value: string;
  detail: string;
  scope: "query" | "page";
  unavailable?: boolean;
}

export function findingTriageKey(vulnerabilityId: string, packageName: string): string {
  return `${vulnerabilityId}::${packageName || "*"}`;
}

export function triageForFinding(
  vuln: EnrichedVuln,
  triageByKey: ReadonlyMap<string, FindingTriageItem>,
): FindingTriageItem | undefined {
  return triageByKey.get(findingTriageKey(vuln.id, vuln.packages[0] ?? "*"));
}

function freshnessMetric(
  facets: FindingFacets | null,
  approximate: boolean,
): FindingsWorkspaceMetric {
  if (!facets) {
    return {
      label: "Evidence freshness",
      value: "Unavailable",
      detail: "The server did not return freshness facets for this query",
      scope: "query",
      unavailable: true,
    };
  }
  const recent = facets.freshness.last_24_hours + facets.freshness.last_7_days;
  const stale = facets.freshness.last_30_days + facets.freshness.older;
  const unavailable = facets.freshness.unavailable;
  const prefix = approximate ? "~" : "";
  return {
    label: "Evidence freshness",
    value: `${prefix}${recent} observed ≤7d`,
    detail: `${prefix}${stale} older · ${prefix}${unavailable} unavailable`,
    scope: "query",
  };
}

export function buildEngineeringMetrics(
  rows: EnrichedVuln[],
  triageByKey: ReadonlyMap<string, FindingTriageItem>,
  facets: FindingFacets | null,
  facetsApproximate = false,
): FindingsWorkspaceMetric[] {
  const reachabilityKnown = rows.filter((row) => typeof row.graph_reachable === "boolean");
  const reachable = reachabilityKnown.filter((row) => row.graph_reachable === true).length;
  const exploitSignals = rows.filter(
    (row) => row.is_kev === true || typeof row.epss_score === "number",
  ).length;
  const fixes = rows.filter(
    (row) => Boolean(row.fixed_version?.trim()) || (row.remediation_versions?.length ?? 0) > 0,
  ).length;
  const owned = rows.filter((row) =>
    Boolean(row.owner?.trim() || triageForFinding(row, triageByKey)?.assignee?.trim()),
  ).length;

  return [
    freshnessMetric(facets, facetsApproximate),
    reachabilityKnown.length > 0
      ? {
          label: "Reachability",
          value: `${reachable} reachable`,
          detail: `${reachabilityKnown.length} assessed on this page`,
          scope: "page",
        }
      : {
          label: "Reachability",
          value: "Unavailable",
          detail: "No graph reachability evidence on this page",
          scope: "page",
          unavailable: true,
        },
    exploitSignals > 0
      ? {
          label: "Exploit intelligence",
          value: `${exploitSignals} enriched`,
          detail: "KEV and/or EPSS evidence on this page",
          scope: "page",
        }
      : {
          label: "Exploit intelligence",
          value: "Unavailable",
          detail: "No KEV or EPSS evidence on this page",
          scope: "page",
          unavailable: true,
        },
    {
      label: "Fix ownership",
      value: `${fixes} fixable · ${owned} owned`,
      detail: `${Math.max(rows.length - fixes, 0)} without a fix on this page`,
      scope: "page",
    },
  ];
}

export function buildComplianceMetrics(
  rows: EnrichedVuln[],
  triageByKey: ReadonlyMap<string, FindingTriageItem>,
  facets: FindingFacets | null,
  facetsApproximate = false,
): FindingsWorkspaceMetric[] {
  const mapped = rows.filter(
    (row) => (row.framework_tags?.length ?? 0) > 0 || (row.controls?.length ?? 0) > 0,
  ).length;
  const triage = rows
    .map((row) => triageForFinding(row, triageByKey))
    .filter((row): row is FindingTriageItem => Boolean(row));
  const decided = triage.filter(
    (row) => row.decision === "affected" || row.decision === "not_affected",
  ).length;
  const openVexReady = triage.filter((row) => row.vex_eligible).length;

  return [
    freshnessMetric(facets, facetsApproximate),
    {
      label: "Control mapping",
      value: mapped > 0 ? `${mapped} mapped` : "Unavailable",
      detail:
        mapped > 0
          ? `${Math.max(rows.length - mapped, 0)} unmapped on this page`
          : "No framework or control mapping on this page",
      scope: "page",
      unavailable: mapped === 0,
    },
    triage.length > 0
      ? {
          label: "Disposition",
          value: `${decided} decided`,
          detail: `${Math.max(rows.length - decided, 0)} pending on this page`,
          scope: "page",
        }
      : {
          label: "Disposition",
          value: "Unavailable",
          detail: "No disposition records loaded for this page",
          scope: "page",
          unavailable: true,
        },
    {
      label: "Attestation",
      value: `${openVexReady} OpenVEX ready`,
      detail: "Not-affected decisions require justification",
      scope: "page",
    },
  ];
}

export function controlLabels(vuln: EnrichedVuln): string[] {
  const labels = [...(vuln.framework_tags ?? [])];
  for (const control of vuln.controls ?? []) {
    for (const key of ["control_id", "id", "name", "title"] as const) {
      const value = control[key];
      if (typeof value === "string" && value.trim()) {
        labels.push(value.trim());
        break;
      }
    }
  }
  return [...new Set(labels)];
}
