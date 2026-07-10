"use client";

import type { ComplianceFrameworkSummary } from "@/lib/compliance-frameworks";
import { compliancePassRate } from "@/lib/compliance-frameworks";

export function ComplianceFrameworkStrip({
  frameworks,
  selectedId,
  onSelect,
}: {
  frameworks: ComplianceFrameworkSummary[];
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="flex gap-2 overflow-x-auto pb-1">
      {frameworks.map((framework) => {
        const active = framework.id === selectedId;
        const rate = compliancePassRate(framework);
        const disabled = Boolean(framework.disabled);
        return (
          <button
            key={framework.id}
            type="button"
            disabled={disabled}
            title={disabled ? framework.disabledReason : framework.label}
            onClick={() => onSelect(framework.id)}
            className={`min-w-[9.5rem] shrink-0 rounded-xl border px-3 py-2 text-left transition ${
              active
                ? "border-emerald-600/60 bg-emerald-950/30"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] hover:border-[color:var(--border-strong)]"
            } ${disabled ? "cursor-not-allowed opacity-40" : ""}`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-medium text-[color:var(--foreground)]">
                {framework.shortLabel}
              </span>
              <span className="text-[10px] text-[color:var(--text-tertiary)]">
                {framework.pass}/{framework.total}
              </span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-[color:var(--surface-elevated)]">
              <div
                className={`h-full rounded-full ${framework.fail > 0 ? "bg-red-500" : "bg-emerald-500"}`}
                style={{ width: `${Math.max(rate, framework.fail > 0 ? 8 : 0)}%` }}
              />
            </div>
            {framework.fail > 0 ? (
              <p className="mt-1 text-[10px] text-red-400">{framework.fail} failing</p>
            ) : (
              <p className="mt-1 text-[10px] text-emerald-400/80">{rate}% pass</p>
            )}
          </button>
        );
      })}
    </div>
  );
}
