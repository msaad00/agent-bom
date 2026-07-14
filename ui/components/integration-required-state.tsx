"use client";

import { Database, RefreshCw, Settings2 } from "lucide-react";

interface IntegrationRequiredStateProps {
  title: string;
  summary: string;
  requirement: string;
  command: string;
  capabilities: string[];
  detail?: string | null | undefined;
  onRetry?: (() => void) | undefined;
}

export function IntegrationRequiredState({
  title,
  summary,
  requirement,
  command,
  capabilities,
  detail,
  onRetry,
}: IntegrationRequiredStateProps) {
  return (
    <div className="py-8">
      <div className="mx-auto max-w-5xl rounded-3xl border border-[var(--border-subtle)] bg-[var(--background)]/70 p-6 shadow-2xl shadow-black/20 md:p-8">
        <div className="grid gap-4 lg:grid-cols-[1.3fr_0.9fr]">
          <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 p-5">
            <div className="flex items-center gap-2 text-sm font-semibold text-[var(--foreground)]">
              <Database className="h-4 w-4 text-emerald-400" />
              {title}
            </div>
            <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">{summary}</p>
            <div className="mt-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">API requirement</div>
              <div className="mt-2 font-mono text-sm text-[var(--foreground)]">{requirement}</div>
            </div>
            <div className="mt-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Enable this surface</div>
              <code className="mt-2 block whitespace-pre-wrap font-mono text-sm leading-7 text-emerald-300">
                {command}
              </code>
            </div>
            {detail ? (
              <p className="mt-4 text-xs text-[var(--text-tertiary)]">
                Current API response: <span className="font-mono text-[var(--text-secondary)]">{detail}</span>
              </p>
            ) : null}
          </div>

          <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 p-5">
            <div className="flex items-center gap-2 text-sm font-semibold text-[var(--foreground)]">
              <Settings2 className="h-4 w-4 text-blue-400" />
              What this unlocks
            </div>
            <ul className="mt-4 space-y-2">
              {capabilities.map((capability) => (
                <li
                  key={capability}
                  className="rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--text-secondary)]"
                >
                  {capability}
                </li>
              ))}
            </ul>
            <p className="mt-4 text-xs leading-5 text-[var(--text-tertiary)]">
              Core scan, graph, remediation, and compliance flows still work without this optional data source.
            </p>
            {onRetry ? (
              <button
                onClick={onRetry}
                className="mt-5 inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]"
              >
                <RefreshCw className="h-4 w-4" />
                Retry
              </button>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
