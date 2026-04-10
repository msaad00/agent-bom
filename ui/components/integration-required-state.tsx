"use client";

import { Database, RefreshCw, Settings2 } from "lucide-react";

interface IntegrationRequiredStateProps {
  title: string;
  summary: string;
  requirement: string;
  command: string;
  capabilities: string[];
  detail?: string | null;
  onRetry?: () => void;
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
      <div className="mx-auto max-w-5xl rounded-3xl border border-zinc-800 bg-zinc-950/70 p-6 shadow-2xl shadow-black/20 md:p-8">
        <div className="grid gap-4 lg:grid-cols-[1.3fr_0.9fr]">
          <div className="rounded-2xl border border-zinc-800 bg-zinc-900/60 p-5">
            <div className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
              <Database className="h-4 w-4 text-emerald-400" />
              {title}
            </div>
            <p className="mt-3 text-sm leading-6 text-zinc-400">{summary}</p>
            <div className="mt-4 rounded-2xl border border-zinc-800 bg-zinc-950 px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">API requirement</div>
              <div className="mt-2 font-mono text-sm text-zinc-200">{requirement}</div>
            </div>
            <div className="mt-4 rounded-2xl border border-zinc-800 bg-zinc-950 px-4 py-3">
              <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-500">Enable this surface</div>
              <code className="mt-2 block whitespace-pre-wrap font-mono text-sm leading-7 text-emerald-300">
                {command}
              </code>
            </div>
            {detail ? (
              <p className="mt-4 text-xs text-zinc-500">
                Current API response: <span className="font-mono text-zinc-400">{detail}</span>
              </p>
            ) : null}
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-900/60 p-5">
            <div className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
              <Settings2 className="h-4 w-4 text-blue-400" />
              What this unlocks
            </div>
            <ul className="mt-4 space-y-2">
              {capabilities.map((capability) => (
                <li
                  key={capability}
                  className="rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-400"
                >
                  {capability}
                </li>
              ))}
            </ul>
            <p className="mt-4 text-xs leading-5 text-zinc-500">
              Core scan, graph, remediation, and compliance flows still work without this optional data source.
            </p>
            {onRetry ? (
              <button
                onClick={onRetry}
                className="mt-5 inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-200 transition-colors hover:bg-zinc-700"
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
