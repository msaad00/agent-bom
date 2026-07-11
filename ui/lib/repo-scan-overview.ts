/**
 * Post-scan repo overview: which static surfaces produced evidence on this job.
 * Catalog labels come from REPO_SCAN_SURFACES; state is evidence-backed, not a DAST claim.
 */

import type { ScanResult } from "@/lib/api-types";
import { REPO_SCAN_SURFACES, type RepoScanSurface } from "@/lib/repo-scan-surfaces";

export type RepoSurfaceEvidenceState = "found" | "idle";

export type RepoSurfaceEvidence = {
  id: string;
  label: string;
  detail: string;
  state: RepoSurfaceEvidenceState;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonempty(value: unknown): boolean {
  if (value == null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value as object).length > 0;
  if (typeof value === "string") return value.trim().length > 0;
  if (typeof value === "number") return value > 0;
  return Boolean(value);
}

/** Prefer top-level project_inventory; fall back to nested AI inventory (API repo path). */
export function resolveProjectInventory(result: ScanResult | null | undefined): Record<string, unknown> | null {
  if (!result) return null;
  const top = asRecord((result as ScanResult & { project_inventory?: unknown }).project_inventory);
  if (top) return top;
  const ai = asRecord((result as ScanResult & { ai_inventory?: unknown }).ai_inventory);
  return asRecord(ai?.dependency_inventory);
}

export function repoGraphHref(scanId: string): string {
  const layers = "directory,source_file,config_file,package,framework,vulnerability";
  return `/graph?scan_id=${encodeURIComponent(scanId)}&layers=${encodeURIComponent(layers)}`;
}

/**
 * Map completed scan result extras onto the honest surface catalog.
 * Surfaces without evidence stay idle (catalog only) — never claim a scan ran them dynamically.
 */
export function deriveRepoSurfaceEvidence(result: ScanResult | null | undefined): RepoSurfaceEvidence[] {
  const ai = asRecord((result as ScanResult & { ai_inventory?: unknown } | undefined)?.ai_inventory);
  const inventory = resolveProjectInventory(result);
  const skillAudit = asRecord((result as ScanResult & { skill_audit?: unknown } | undefined)?.skill_audit);
  const iac = (result as ScanResult & { iac_findings?: unknown } | undefined)?.iac_findings;
  const sast = asRecord((result as ScanResult & { sast?: unknown } | undefined)?.sast);
  const agents = result?.agents ?? [];
  const warnings = result?.warnings ?? [];
  const warningBlob = warnings.join(" ").toLowerCase();

  const found = new Set<string>();

  if (nonempty(inventory) || (result?.summary?.total_packages ?? 0) > 0) {
    found.add("dependencies");
  }
  if (nonempty(ai?.secrets) || /secret/.test(warningBlob)) {
    found.add("secrets");
  }
  if (nonempty(ai?.weak_crypto) || /weak.?crypto|md5|sha-1/.test(warningBlob)) {
    found.add("weak-crypto");
  }
  if (
    nonempty(ai?.sdk_imports) ||
    nonempty(ai?.components) ||
    nonempty(ai?.models) ||
    nonempty(ai?.observability) ||
    (typeof ai?.total_components === "number" && ai.total_components > 0)
  ) {
    found.add("ai-inventory");
  }
  if (nonempty(skillAudit) || nonempty(ai?.skills)) {
    found.add("skills");
  }
  if (nonempty(iac)) {
    found.add("iac");
    const iacText = JSON.stringify(iac).toLowerCase();
    if (iacText.includes("terraform") || iacText.includes("hcl")) {
      found.add("terraform");
    }
    if (iacText.includes("github") && iacText.includes("action")) {
      found.add("github-actions");
    }
  }
  if (
    sast != null &&
    (nonempty(sast.findings) ||
      nonempty(sast.results) ||
      (typeof sast.count === "number" && sast.count > 0))
  ) {
    found.add("sast");
  }
  if (agents.some((agent) => (agent.mcp_servers?.length ?? 0) > 0)) {
    found.add("mcp-config");
  }
  if (
    agents.some((agent) => {
      const type = (agent.agent_type || "").toLowerCase();
      return type.includes("lang") || type.includes("crew") || type.includes("autogen") || type.includes("framework");
    }) ||
    nonempty(ai?.frameworks)
  ) {
    found.add("agent-frameworks");
  }
  if (nonempty(ai?.notebooks) || /jupyter|\.ipynb/.test(JSON.stringify(ai ?? {}))) {
    found.add("jupyter");
  }
  if (nonempty(ai?.ingestion) || nonempty(ai?.data_pipelines)) {
    found.add("ingestion");
  }

  // Connectors are never part of git repo scans — always idle here.
  return REPO_SCAN_SURFACES.filter((surface) => surface.id !== "connectors").map((surface: RepoScanSurface) => ({
    id: surface.id,
    label: surface.label,
    detail: surface.detail,
    state: found.has(surface.id) ? ("found" as const) : ("idle" as const),
  }));
}

export function repoInventoryStats(result: ScanResult | null | undefined): {
  directories: number | null;
  packages: number | null;
  lockfiles: number | null;
} {
  const inventory = resolveProjectInventory(result);
  if (!inventory) {
    return {
      directories: null,
      packages: result?.summary?.total_packages ?? null,
      lockfiles: null,
    };
  }
  const dirs = inventory.directories ?? inventory.dirs;
  const packages = inventory.package_count ?? inventory.packages ?? result?.summary?.total_packages;
  const lockfiles = inventory.lockfiles ?? inventory.lockfile_count;
  return {
    directories: Array.isArray(dirs) ? dirs.length : typeof dirs === "number" ? dirs : null,
    packages: typeof packages === "number" ? packages : Array.isArray(packages) ? packages.length : null,
    lockfiles: Array.isArray(lockfiles) ? lockfiles.length : typeof lockfiles === "number" ? lockfiles : null,
  };
}
