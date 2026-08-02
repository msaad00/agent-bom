import {
  AlertTriangle,
  CheckCircle,
  Shield,
  XCircle,
} from "lucide-react";

// Statuses with no vulnerability-derived evidence to score. The backend emits
// "no_data" (aggregate /v1/compliance), "not_evaluated" (per-framework
// narratives and controls no finding mapped to), "not_assessed" (no completed
// scan) and "not_applicable" (applicability overlay) — these must read as
// neutral "Not evaluated", never green "Compliant" or red "Non-compliant".
const NO_EVIDENCE_STATUSES = new Set([
  "no_data",
  "not_evaluated",
  "not_assessed",
  "not_applicable",
]);

export function isNotEvaluated(status: string): boolean {
  return NO_EVIDENCE_STATUSES.has(status);
}

/** The three tones a per-control status may paint, plus neutral for no evidence. */
export type ControlStatusTone = "pass" | "warning" | "fail" | "neutral";

/**
 * The one tone mapping for a per-control status.
 *
 * Anything that is not an explicit pass/warning/fail is neutral — an unknown
 * or unmeasured control must never be painted as a failure the estate owns.
 */
export function controlStatusTone(status: string): ControlStatusTone {
  if (status === "pass" || status === "warning" || status === "fail") return status;
  return "neutral";
}

const CONTROL_STATUS_LABELS: Record<string, string> = {
  pass: "Pass",
  warning: "Needs attention",
  fail: "Fail",
  applicable: "Applicable",
  not_applicable: "Not applicable",
  not_assessed: "Not assessed",
  not_evaluated: "Not evaluated",
  no_data: "Not evaluated",
};

/**
 * The one label for a per-control status.
 *
 * The backend deliberately distinguishes "we measured this and it failed" from
 * "we never measured this" (see the compliance route's control loop). Every
 * control surface reads that distinction from here so a drawer, a row and a
 * table cannot describe the same control three different ways.
 */
export function controlStatusLabel(status: string): string {
  return CONTROL_STATUS_LABELS[status] ?? "Not evaluated";
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
