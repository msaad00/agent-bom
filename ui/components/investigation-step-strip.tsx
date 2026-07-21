"use client";

import { CheckCircle2, Focus, Network, Radar, Wrench } from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type InvestigationStep = "path" | "expand" | "impact" | "fix";

const STEPS: {
  key: InvestigationStep;
  label: string;
  icon: LucideIcon;
  hint: string;
}[] = [
  { key: "path", label: "Path", icon: Focus, hint: "Select a ranked exposure path" },
  { key: "expand", label: "Expand", icon: Network, hint: "Pin a node and load neighbors" },
  { key: "impact", label: "Impact", icon: Radar, hint: "Compute blast radius for the pin" },
  { key: "fix", label: "Fix", icon: Wrench, hint: "Open the recommended remediation" },
];

export function parseInvestigationStep(raw: string | null | undefined): InvestigationStep {
  if (raw === "expand" || raw === "impact" || raw === "fix" || raw === "path") return raw;
  return "path";
}

/**
 * Wizard chrome for the security-graph investigation loop.
 * Query-param driven (`step=`) — not a separate product surface.
 */
export function InvestigationStepStrip({
  step,
  onStepChange,
  completed,
}: {
  step: InvestigationStep;
  onStepChange: (next: InvestigationStep) => void;
  /** Steps the operator has already completed in this session. */
  completed?: Partial<Record<InvestigationStep, boolean>> | undefined;
}) {
  const activeIndex = STEPS.findIndex((item) => item.key === step);

  return (
    <nav
      aria-label="Investigation steps"
      data-testid="investigation-step-strip"
      className="flex flex-wrap gap-2"
    >
      {STEPS.map((item, index) => {
        const active = item.key === step;
        const done = Boolean(completed?.[item.key]) || index < activeIndex;
        const Icon = done && !active ? CheckCircle2 : item.icon;
        return (
          <button
            key={item.key}
            type="button"
            aria-current={active ? "step" : undefined}
            title={item.hint}
            onClick={() => onStepChange(item.key)}
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
              active
                ? "border-emerald-600/50 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200"
                : done
                  ? "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-tertiary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
            }`}
          >
            <span className="font-mono text-[10px] opacity-70">{index + 1}</span>
            <Icon className="h-3.5 w-3.5" />
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}
