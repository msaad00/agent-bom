"use client";

import Link from "next/link";
import type { ElementType, ReactNode } from "react";
import { AlertTriangle, SearchX } from "lucide-react";

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
    "border-outline bg-surface text-ink-secondary",
  warning:
    "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-ink-secondary",
  danger:
    "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-ink-secondary",
  success:
    "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-ink-secondary",
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
          <div className="rounded-xl border border-outline bg-surface-elevated p-2">
            <Icon className="h-5 w-5 text-ink-secondary" />
          </div>
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-foreground">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-ink-secondary">{detail}</p>
          </div>
        </div>

        {suggestions.length > 0 ? (
          <ul className="mt-4 space-y-2 text-sm text-ink-secondary">
            {suggestions.map((suggestion) => (
              <li key={suggestion} className="flex items-start gap-2">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-ink-tertiary" />
                <span>{suggestion}</span>
              </li>
            ))}
          </ul>
        ) : null}

        {command ? (
          <div className="mt-4 rounded-xl border border-outline bg-surface-muted px-3 py-2">
            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-tertiary">First command</div>
            <code className="mt-1 block overflow-x-auto whitespace-nowrap text-xs text-foreground">{command}</code>
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
      ? "inline-flex items-center justify-center rounded-lg border border-outline bg-surface-muted px-3 py-2 text-sm font-medium text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
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

export { PageLoadingState } from "./page-loading-state";
