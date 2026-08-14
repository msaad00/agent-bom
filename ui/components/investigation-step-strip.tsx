"use client";

import Link from "next/link";
import { CheckCircle2, Focus, Radar, ShieldCheck, UserRound, Wrench } from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type InvestigationStep = "path" | "impact" | "owner" | "fix" | "verify";

const STEPS: {
  key: InvestigationStep;
  label: string;
  icon: LucideIcon;
  hint: string;
}[] = [
  { key: "path", label: "Path", icon: Focus, hint: "Select a ranked exposure path" },
  { key: "impact", label: "Impact", icon: Radar, hint: "Review blast radius and affected assets" },
  { key: "owner", label: "Owner", icon: UserRound, hint: "Assign an owner and remediation SLA" },
  { key: "fix", label: "Fix", icon: Wrench, hint: "Open the recommended remediation" },
  { key: "verify", label: "Verify", icon: ShieldCheck, hint: "Rescan and record the evidence-backed result" },
];

export function parseInvestigationStep(raw: string | null | undefined): InvestigationStep {
  // Preserve old graph links while presenting the product lifecycle rather
  // than an implementation-specific graph expansion step.
  if (raw === "expand") return "impact";
  if (raw === "impact" || raw === "owner" || raw === "fix" || raw === "verify" || raw === "path") return raw;
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
  stepHrefs,
}: {
  step: InvestigationStep;
  onStepChange: (next: InvestigationStep) => void;
  /** Steps the operator has already completed in this session. */
  completed?: Partial<Record<InvestigationStep, boolean>> | undefined;
  /** Continue on an existing product surface instead of duplicating it here. */
  stepHrefs?: Partial<Record<InvestigationStep, string>> | undefined;
}) {
  const activeIndex = STEPS.findIndex((item) => item.key === step);

  return (
    <nav aria-label="Investigation steps" data-testid="investigation-step-strip" className="min-w-0">
      <ol className="flex min-w-0 flex-wrap gap-2">
        {STEPS.map((item, index) => {
          const active = item.key === step;
          const done = Boolean(completed?.[item.key]) || index < activeIndex;
          const Icon = done && !active ? CheckCircle2 : item.icon;
          const descriptionId = `investigation-step-${item.key}-hint`;
          const className = `inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition motion-reduce:transition-none ${
            active
              ? "border-emerald-600/50 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200"
              : done
                ? "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-tertiary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          }`;
          const content = (
            <>
              <span className="font-mono text-[10px] opacity-70">{index + 1}</span>
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              {item.label}
              <span id={descriptionId} className="sr-only">{item.hint}</span>
            </>
          );
          return (
            <li key={item.key}>
              {stepHrefs?.[item.key] ? (
                <Link
                  href={stepHrefs[item.key]!}
                  aria-current={active ? "step" : undefined}
                  aria-describedby={descriptionId}
                  title={item.hint}
                  className={className}
                >
                  {content}
                </Link>
              ) : (
                <button
                  type="button"
                  aria-current={active ? "step" : undefined}
                  aria-describedby={descriptionId}
                  title={item.hint}
                  onClick={() => onStepChange(item.key)}
                  className={className}
                >
                  {content}
                </button>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
