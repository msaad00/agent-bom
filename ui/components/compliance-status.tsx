import {
  AlertTriangle,
  CheckCircle,
  Shield,
  XCircle,
} from "lucide-react";

// Statuses with no vulnerability-derived evidence to score. The backend emits
// "no_data" (aggregate /v1/compliance) and "not_evaluated" (per-framework
// narratives) for scans that mapped no findings — these must read as neutral
// "Not evaluated", never green "Compliant" or red "Non-compliant".
export function isNotEvaluated(status: string): boolean {
  return status === "not_evaluated" || status === "no_data";
}

export function StatusIcon({ status, className }: { status: string; className?: string }) {
  switch (status) {
    case "pass":
      return (
        <CheckCircle
          className={`${className ?? "h-4 w-4"} text-emerald-600 dark:text-emerald-400`}
        />
      );
    case "warning":
      return (
        <AlertTriangle
          className={`${className ?? "h-4 w-4"} text-yellow-600 dark:text-yellow-400`}
        />
      );
    case "fail":
      return <XCircle className={`${className ?? "h-4 w-4"} text-red-600 dark:text-red-400`} />;
    default:
      return <Shield className={`${className ?? "h-4 w-4"} text-[color:var(--text-secondary)]`} />;
  }
}

export function statusColor(status: string): string {
  switch (status) {
    case "pass":
      return "text-emerald-600 dark:text-emerald-400";
    case "warning":
      return "text-yellow-600 dark:text-yellow-400";
    case "fail":
      return "text-red-600 dark:text-red-400";
    default:
      return "text-[color:var(--text-secondary)]";
  }
}

export function postureLabel(status: string): string {
  switch (status) {
    case "pass":
      return "Compliant";
    case "warning":
      return "Needs attention";
    case "fail":
      return "Non-compliant";
    case "not_evaluated":
    case "no_data":
      return "Not evaluated";
    default:
      return "No data";
  }
}

// A control is "unscored" when its status is anything other than a graded
// pass/warning/fail. The API expresses this as not_evaluated / not_assessed
// (corrective + detective with no usable evidence) or applicable /
// not_applicable (overlay techniques). These never read as green or red — they
// carry an evidence_reason explaining WHY, surfaced beside the status.
const GRADED_STATUSES = new Set(["pass", "warning", "fail"]);

export function isControlUnscored(status: string): boolean {
  return !GRADED_STATUSES.has(status);
}

// Per-control status label (denser than postureLabel, which speaks to the
// framework/estate headline). Keeps the raw code out of the UI.
export function controlStatusLabel(status: string): string {
  switch (status) {
    case "pass":
      return "Pass";
    case "warning":
      return "Warn";
    case "fail":
      return "Fail";
    case "not_assessed":
      return "Not assessed";
    case "not_applicable":
      return "Not applicable";
    case "applicable":
      return "Applicable";
    case "not_evaluated":
    case "no_data":
      return "Not evaluated";
    default:
      return "Not evaluated";
  }
}

// Human labels for the backend's per-control `evidence_reason` codes
// (api/routes/compliance.py + evidence/control_modes.py). This is the single
// map from reason code → concise provenance the UI shows next to an unscored
// control, so a bare "Not evaluated" explains itself.
const EVIDENCE_REASON_LABEL: Record<string, string> = {
  // Detective controls (the scan itself is the evidence).
  no_completed_scan: "No completed scan",
  scan_evidence_age_unknown: "Scan age unknown",
  fresh_scan_evidence: "Fresh scan evidence",
  stale_scan_evidence: "Stale scan evidence",
  future_scan_evidence: "Scan timestamp in the future",
  // Corrective controls (attested by the absence of an open finding).
  no_mapped_finding: "No mapped finding",
  unrated_severity_finding: "Unrated-severity finding",
  open_finding: "Open finding",
  // Overlay techniques (made applicable by an observed weakness, or not).
  no_observed_signal: "No observed signal",
  technique_observed: "Technique observed",
};

export function evidenceReasonLabel(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return EVIDENCE_REASON_LABEL[reason] ?? null;
}

export interface EvidenceReasonCta {
  label: string;
  href: string;
}

// Only reasons that imply a MISSING input get a next-step CTA. "No mapped
// finding" / "unrated severity" mean a scan ran but nothing graded this control
// — there is no honest single action to suggest, so they get none. We never
// imply a source is connected or disconnected; "no observed signal" is a
// statement of absence, and the CTA is the honest way to add coverage.
export function evidenceReasonCta(reason: string | null | undefined): EvidenceReasonCta | null {
  switch (reason) {
    case "no_completed_scan":
    case "scan_evidence_age_unknown":
      return { label: "New Scan", href: "/scan" };
    case "no_observed_signal":
      return { label: "Connect a source", href: "/connections" };
    default:
      return null;
  }
}
