import { AlertTriangle, CheckCircle2, CircleHelp, Gauge, XCircle } from "lucide-react";

import type { GraphAnalysisStatus } from "@/lib/graph-schema";
import { tonedChipClass } from "@/lib/toned-chip";

const REASON_LABELS: Readonly<Record<string, string>> = {
  node_cap_exceeded: "estate exceeded the analysis node cap",
  entry_cap_reached: "entry-point evaluation was capped",
  visit_cap_reached: "path traversal visit budget was reached",
  depth_cap_reached: "path traversal depth was capped",
  path_cap_reached: "additional candidate paths were omitted",
  analysis_error: "analysis failed before completion",
  legacy_snapshot: "this snapshot predates execution-status tracking",
};

export function graphAnalysisStatusCopy(status: GraphAnalysisStatus | undefined): {
  label: string;
  detail: string;
  tone: "ok" | "warn" | "danger" | "neutral";
} {
  if (!status || status.status === "not_recorded") {
    return {
      label: "Analysis status unavailable",
      detail: "This snapshot does not prove whether attack-path analysis completed. Run a fresh scan for a verified result.",
      tone: "neutral",
    };
  }
  if (status.status === "complete") {
    return {
      label: "Attack-path analysis complete",
      detail: "The persisted snapshot records a complete attack-path analysis run.",
      tone: "ok",
    };
  }
  const reasons = status.reason_codes.map((code) => REASON_LABELS[code] ?? code.replaceAll("_", " ")).join("; ");
  if (status.status === "limited") {
    return {
      label: "Attack-path analysis limited",
      detail: `Results are partial: ${reasons || "an execution limit was reached"}.`,
      tone: "warn",
    };
  }
  if (status.status === "skipped") {
    return {
      label: "Attack-path analysis skipped",
      detail: `No complete result is available: ${reasons || "analysis did not run"}.`,
      tone: "danger",
    };
  }
  return {
    label: "Attack-path analysis failed",
    detail: `The snapshot was preserved, but attack-path analysis did not complete: ${reasons || "analysis error"}.`,
    tone: "danger",
  };
}

export function GraphAnalysisStatusBanner({
  status,
  compact = false,
}: {
  status?: GraphAnalysisStatus | undefined;
  compact?: boolean;
}) {
  const copy = graphAnalysisStatusCopy(status);
  const Icon =
    status?.status === "complete"
      ? CheckCircle2
      : status?.status === "limited"
        ? Gauge
        : status?.status === "failed"
          ? XCircle
          : status?.status === "skipped"
            ? AlertTriangle
            : CircleHelp;

  if (compact) {
    return (
      <span
        data-testid="graph-analysis-status"
        className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs ${tonedChipClass(copy.tone)}`}
        title={copy.detail}
      >
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        {copy.label}
      </span>
    );
  }

  return (
    <div
      data-testid="graph-analysis-status"
      className={`flex items-start gap-3 rounded-2xl border p-3 ${tonedChipClass(copy.tone)}`}
      role={copy.tone === "danger" ? "alert" : "status"}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <div>
        <p className="text-xs font-semibold">{copy.label}</p>
        <p className="mt-1 text-xs opacity-90">{copy.detail}</p>
      </div>
    </div>
  );
}
