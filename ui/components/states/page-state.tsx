"use client";

import Link from "next/link";
import type { ElementType, ReactNode } from "react";
import { AlertTriangle, Loader2, SearchX } from "lucide-react";

export type PageStateAction = {
  label: string;
  href?: string | undefined;
  onClick?: (() => void) | undefined;
  variant?: "primary" | "secondary" | undefined;
};

type PageStateProps = {
  title: string;
  detail: string;
  icon?: ElementType | undefined;
  suggestions?: string[] | undefined;
  command?: string | undefined;
  action?: PageStateAction | undefined;
  actions?: PageStateAction[] | undefined;
  tone?: "neutral" | "warning" | "danger" | "success" | undefined;
  children?: ReactNode;
  "data-testid"?: string | undefined;
};

const TONE_CLASS: Record<NonNullable<PageStateProps["tone"]>, string> = {
  neutral:
    "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-secondary)]",
  warning:
    "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--text-secondary)]",
  danger:
    "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--text-secondary)]",
  success:
    "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--text-secondary)]",
};

export function PageState({
  title,
  detail,
  icon: Icon = SearchX,
  suggestions = [],
  command,
  action,
  actions,
  tone = "neutral",
  children,
  "data-testid": testId,
}: PageStateProps) {
  const resolvedActions = actions ?? (action ? [action] : []);

  return (
    <div className="flex min-h-[18rem] items-center justify-center px-4 py-10" data-testid={testId}>
      <div className={`w-full max-w-2xl rounded-2xl border p-6 elev-2 ${TONE_CLASS[tone]}`}>
        <div className="flex items-start gap-3">
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2">
            <Icon className="h-5 w-5 text-[color:var(--text-secondary)]" />
          </div>
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-[color:var(--foreground)]">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-[color:var(--text-secondary)]">{detail}</p>
          </div>
        </div>

        {suggestions.length > 0 ? (
          <ul className="mt-4 space-y-2 text-sm text-[color:var(--text-secondary)]">
            {suggestions.map((suggestion) => (
              <li key={suggestion} className="flex items-start gap-2">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[color:var(--text-tertiary)]" />
                <span>{suggestion}</span>
              </li>
            ))}
          </ul>
        ) : null}

        {command ? (
          <div className="mt-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">First command</div>
            <code className="mt-1 block overflow-x-auto whitespace-nowrap text-xs text-[color:var(--foreground)]">{command}</code>
          </div>
        ) : null}

        {children}

        {resolvedActions.length > 0 ? (
          <div className="mt-5 flex flex-wrap gap-2">
            {resolvedActions.map((currentAction) => (
              <PageStateActionButton
                key={`${currentAction.label}:${currentAction.href ?? "button"}`}
                action={currentAction}
              />
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function PageStateActionButton({ action }: { action: PageStateAction }) {
  const className =
    action.variant === "secondary"
      ? "inline-flex items-center justify-center rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm font-medium text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
      : "inline-flex items-center justify-center rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-2 text-sm font-medium text-[color:var(--accent)] transition hover:bg-[color:var(--accent-soft-hover)]";

  if (action.href) {
    return (
      <Link href={action.href} className={className}>
        {action.label}
      </Link>
    );
  }

  return (
    <button type="button" onClick={action.onClick} className={className}>
      {action.label}
    </button>
  );
}

export function PageEmptyState(props: Omit<PageStateProps, "tone">) {
  return <PageState {...props} tone="neutral" />;
}

export function PageErrorState(props: Omit<PageStateProps, "tone" | "icon"> & { icon?: ElementType | undefined }) {
  return <PageState {...props} icon={props.icon ?? AlertTriangle} tone="danger" />;
}

export function PageLoadingState({
  title,
  detail,
  "data-testid": testId,
}: {
  title: string;
  detail: string;
  "data-testid"?: string | undefined;
}) {
  return (
    <div className="flex min-h-[18rem] items-center justify-center px-4 py-10" data-testid={testId}>
      <div className="w-full max-w-3xl rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 elev-2">
        <div className="flex items-start gap-3">
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2">
            <Loader2 className="h-5 w-5 animate-spin text-[color:var(--text-secondary)]" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-[color:var(--foreground)]">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-[color:var(--text-secondary)]">{detail}</p>
          </div>
        </div>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {[0, 1, 2].map((column) => (
            <div key={column} className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
              <div className="h-4 w-24 animate-pulse rounded-full bg-[color:var(--surface-elevated)]" />
              <div className="mt-4 space-y-3">
                {[0, 1, 2, 3].map((row) => (
                  <div
                    key={row}
                    className="h-3 animate-pulse rounded-full bg-[color:var(--surface-elevated)]"
                    style={{ width: `${92 - row * 13 - column * 4}%` }}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
