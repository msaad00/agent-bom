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
  _rows: EnrichedVuln[],
  _triageByKey: ReadonlyMap<string, FindingTriageItem>,
  facets: FindingFacets | null,
  facetsApproximate = false,
): FindingsWorkspaceMetric[] {
  const reachability = facets?.reachability;
  const exploit = facets?.exploit_intelligence;
  const fixability = facets?.fixability;
  const ownership = facets?.ownership;
  const prefix = facetsApproximate ? "~" : "";
  const assessed = reachability ? reachability.reachable + reachability.unreachable : 0;
  const exploitEnriched = exploit ? exploit.kev_and_epss + exploit.kev_only + exploit.epss_only : 0;
  const kev = exploit ? exploit.kev_and_epss + exploit.kev_only : 0;
  const epss = exploit ? exploit.kev_and_epss + exploit.epss_only : 0;

  return [
    freshnessMetric(facets, facetsApproximate),
    reachability && assessed > 0
      ? {
          label: "Reachability",
          value: `${prefix}${reachability.reachable} reachable`,
          detail: `${prefix}${assessed} assessed · ${prefix}${reachability.unassessed} unassessed`,
          scope: "query",
        }
      : {
          label: "Reachability",
          value: "Unavailable",
          detail: reachability ? `${prefix}${reachability.unassessed} unassessed across this query` : "The server did not return reachability facets",
          scope: "query",
          unavailable: true,
        },
    exploit
      ? {
          label: "Exploit intelligence",
          value: `${prefix}${exploitEnriched} enriched`,
          detail: `${prefix}${kev} KEV · ${prefix}${epss} EPSS · ${prefix}${exploit.unavailable} unavailable`,
          scope: "query",
        }
      : {
          label: "Exploit intelligence",
          value: "Unavailable",
          detail: "The server did not return exploit-intelligence facets",
          scope: "query",
          unavailable: true,
        },
    fixability && ownership ? {
      label: "Fix ownership",
      value: `${prefix}${fixability.fix_available} fixable · ${prefix}${ownership.owned} owned`,
      detail: `${prefix}${fixability.no_fix_available} without a fix · ${prefix}${ownership.unowned} unowned`,
      scope: "query",
    } : {
      label: "Fix ownership",
      value: "Unavailable",
      detail: "The server did not return fixability and ownership facets",
      scope: "query",
      unavailable: true,
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
  const openVexReady = triage.filter((row) => row.vex_eligible).length;
  const disposition = facets?.disposition;
  const dispositionPrefix = facetsApproximate ? "~" : "";
  const decided = disposition ? disposition.affected + disposition.not_affected : 0;

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
    disposition
      ? {
          label: "Disposition",
          value: `${dispositionPrefix}${decided} decided`,
          detail: `${dispositionPrefix}${disposition.under_investigation} investigating · ${dispositionPrefix}${disposition.untriaged} untriaged`,
          scope: "query",
        }
      : {
          label: "Disposition",
          value: "Unavailable",
          detail: "The server did not return disposition facets for this query",
          scope: "query",
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
