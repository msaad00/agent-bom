"use client";

import { ChevronRight } from "lucide-react";

import type { ComplianceControl } from "@/lib/api";
import {
  type ControlStatusTone,
  StatusIcon,
  controlStatusTone,
} from "@/components/compliance-status";

// A control nothing was measured for is neutral, not red: the row border must
// agree with the neutral icon StatusIcon already renders for it.
const CONTROL_ROW_TONE: Record<ControlStatusTone, string> = {
  pass: "border-emerald-900/40 bg-emerald-950/15",
  warning: "border-yellow-900/40 bg-yellow-950/15",
  fail: "border-red-900/40 bg-red-950/15",
  neutral: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]",
};

export function ComplianceControlRow({
  control,
  catalogName,
  onOpen,
}: {
  control: ComplianceControl;
  catalogName: string;
  onOpen: () => void;
}) {
  const sev = control.severity_breakdown;
  const topSeverity =
    (sev.critical ?? 0) > 0
      ? `${sev.critical} critical`
      : (sev.high ?? 0) > 0
        ? `${sev.high} high`
        : (sev.medium ?? 0) > 0
          ? `${sev.medium} medium`
          : (sev.low ?? 0) > 0
            ? `${sev.low} low`
            : null;

  return (
    <button
      type="button"
      onClick={onOpen}
      className={`flex w-full items-center gap-3 rounded-xl border px-4 py-3 text-left transition hover:border-[color:var(--border-strong)] ${
        CONTROL_ROW_TONE[controlStatusTone(control.status)]
      }`}
    >
      <StatusIcon status={control.status} className="h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs font-semibold text-[color:var(--foreground)]">
            {control.code}
          </span>
          {control.findings > 0 ? (
            <span className="text-[10px] text-[color:var(--text-tertiary)]">
              {control.findings} finding{control.findings === 1 ? "" : "s"}
            </span>
          ) : null}
        </div>
        <p className="mt-0.5 truncate text-sm text-[color:var(--text-secondary)]">{catalogName}</p>
      </div>
      {topSeverity ? (
        <span className="hidden text-[10px] text-[color:var(--text-tertiary)] sm:block">{topSeverity}</span>
      ) : null}
      <ChevronRight className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)]" />
    </button>
  );
}
