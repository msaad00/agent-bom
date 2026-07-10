import {
  AlertTriangle,
  CheckCircle,
  Shield,
  XCircle,
} from "lucide-react";

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
    default:
      return "No data";
  }
}
