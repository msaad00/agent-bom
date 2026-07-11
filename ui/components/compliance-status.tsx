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
