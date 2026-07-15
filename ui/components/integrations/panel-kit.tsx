"use client";

import type { ButtonHTMLAttributes, ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info } from "lucide-react";

/** Small shared building blocks for the Operations & Integrations panels so
 *  each panel stays focused on its own endpoint wiring, not chrome. Tokens
 *  only — verified against both themes. */

export function PanelIntro({ title, description, children }: { title: string; description: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col gap-3 border-b border-[color:var(--border-subtle)] pb-4 lg:flex-row lg:items-end lg:justify-between">
      <div className="min-w-0">
        <h2 className="text-lg font-semibold tracking-tight text-[color:var(--foreground)]">{title}</h2>
        <p className="mt-1 max-w-3xl text-sm text-[color:var(--text-secondary)]">{description}</p>
      </div>
      {children ? <div className="flex flex-wrap items-center gap-2">{children}</div> : null}
    </div>
  );
}

type ButtonTone = "primary" | "secondary" | "danger";

const BUTTON_TONE: Record<ButtonTone, string> = {
  primary:
    "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)] hover:bg-[color:var(--accent-soft-hover)]",
  secondary:
    "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]",
  danger:
    "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--severity-critical)] hover:brightness-110",
};

export function PanelButton({
  tone = "secondary",
  className = "",
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { tone?: ButtonTone }) {
  return (
    <button
      type={rest.type ?? "button"}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${BUTTON_TONE[tone]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}

type PillTone = "neutral" | "success" | "warn" | "danger" | "accent";

const PILL_TONE: Record<PillTone, string> = {
  neutral:
    "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]",
  success:
    "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
  warn:
    "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]",
  danger:
    "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--severity-critical)]",
  accent:
    "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)]",
};

export function Pill({ tone = "neutral", children }: { tone?: PillTone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${PILL_TONE[tone]}`}
    >
      {children}
    </span>
  );
}

type NoticeTone = "success" | "error" | "info";

const NOTICE_TONE: Record<NoticeTone, { cls: string; Icon: typeof Info }> = {
  success: {
    cls: "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]",
    Icon: CheckCircle2,
  },
  error: {
    cls: "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--severity-critical)]",
    Icon: AlertTriangle,
  },
  info: {
    cls: "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]",
    Icon: Info,
  },
};

export function InlineNotice({
  tone,
  children,
  "data-testid": testId,
}: {
  tone: NoticeTone;
  children: ReactNode;
  "data-testid"?: string;
}) {
  const { cls, Icon } = NOTICE_TONE[tone];
  return (
    <div
      role="status"
      data-testid={testId}
      className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${cls}`}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <div className="min-w-0">{children}</div>
    </div>
  );
}

/** A read-only labeled field used across the panels. Never used for secrets. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
        {label}
      </span>
      {children}
    </label>
  );
}

export const INPUT_CLASS =
  "w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--border-strong)] placeholder:text-[color:var(--text-tertiary)]";

export function errorMessage(err: unknown): string {
  if (err instanceof Error && err.message) return err.message;
  return "Request failed. Check your permissions and try again.";
}
