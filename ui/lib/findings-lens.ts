/**
 * Findings page altitude — same queue reframed for two personas. The internal
 * keys stay "ops"/"trust" for URL + storage stability; the user-facing labels
 * use industry language (Engineering / Compliance).
 * ops   → Engineering: reachability, remediation, investigation (SecOps).
 * trust → Compliance: control gaps, disposition, OpenVEX / attestation (GRC/audit).
 */
export type FindingsLens = "ops" | "trust";

export const FINDINGS_LENS_STORAGE_KEY = "agent-bom:findings-lens";

export const FINDINGS_LENSES: FindingsLens[] = ["ops", "trust"];

export function normalizeFindingsLens(value: string | null | undefined): FindingsLens | null {
  if (value === "ops" || value === "engineer" || value === "engineering") return "ops";
  if (value === "trust" || value === "grc" || value === "compliance" || value === "audit") {
    return "trust";
  }
  return null;
}

export function readStoredFindingsLens(): FindingsLens | null {
  if (typeof window === "undefined") return null;
  try {
    return normalizeFindingsLens(window.localStorage?.getItem?.(FINDINGS_LENS_STORAGE_KEY) ?? null);
  } catch {
    return null;
  }
}

export function storeFindingsLens(lens: FindingsLens): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage?.setItem?.(FINDINGS_LENS_STORAGE_KEY, lens);
  } catch {
    // ignore quota / private-mode failures
  }
}

export function findingsLensLabel(lens: FindingsLens): string {
  return lens === "trust" ? "Compliance" : "Engineering";
}

export function findingsLensHint(lens: FindingsLens): string {
  return lens === "trust"
    ? "GRC / audit altitude — disposition, control gaps, and OpenVEX evidence for attestations."
    : "Engineering altitude — reachability, remediation, and investigation triage.";
}

export function findingsPageSubtitle(lens: FindingsLens, countLabel: string, scopeLine: string): string {
  const audience =
    lens === "trust"
      ? "Shared with engineering — filter by issue type for misconfigs and secrets, then record disposition for audit packs."
      : "Shared with compliance and audit — triage decisions and OpenVEX export feed trust reviews.";
  return `${countLabel} · ${scopeLine} ${audience}`;
}

export function findingsQueueTitle(lens: FindingsLens): string {
  return lens === "trust" ? "Disposition queue" : "Findings queue";
}

export function findingsQueueDetail(lens: FindingsLens): string {
  return lens === "trust"
    ? "Review control-relevant findings. Record affected / not-affected disposition and export OpenVEX for attestations."
    : "Triage one finding at a time. Evidence, reachability, fixes, and OpenVEX disposition live in the drawer.";
}

export function findingsSearchPlaceholder(lens: FindingsLens): string {
  return lens === "trust"
    ? "Search CVE, control, framework, package…"
    : "Search CVE, package, agent…";
}

export function findingsDrawerEyebrow(lens: FindingsLens): string {
  return lens === "trust" ? "Evidence & disposition" : "Evidence drawer";
}

export function findingsDrawerSubtitle(lens: FindingsLens): string {
  return lens === "trust"
    ? "Control mapping, impacted assets, remediation, and VEX disposition for GRC and audit."
    : "Reachability, impacted packages, agent exposure, remediation, and VEX decisioning.";
}

export function findingsTriageTitle(lens: FindingsLens): string {
  return lens === "trust" ? "Disposition & attestation" : "Review queue";
}

export function findingsTriageDetail(lens: FindingsLens): string {
  return lens === "trust"
    ? "Record GRC disposition for this finding. Not-affected decisions need an OpenVEX justification and become eligible for signed VEX export used in trust reviews."
    : "Record disposition for this package finding. Not-affected decisions require an OpenVEX justification and become eligible for signed VEX export.";
}
