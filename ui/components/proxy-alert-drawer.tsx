"use client";

import { X } from "lucide-react";

import type { ProxyAlert } from "@/lib/api";
import { formatDate } from "@/lib/api";
import { proxyAlertDetailEntries, proxyAlertSummary } from "@/lib/proxy-alerts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-950 text-red-300 border-red-800",
  high: "bg-orange-950 text-orange-300 border-orange-800",
  medium: "bg-yellow-950 text-yellow-300 border-yellow-800",
  low: "bg-blue-950 text-blue-300 border-blue-800",
  info: "bg-zinc-800 text-zinc-300 border-zinc-700",
};

export function ProxyAlertDrawer({
  alert,
  onClose,
}: {
  alert: ProxyAlert;
  onClose: () => void;
}) {
  const rows = proxyAlertDetailEntries(alert);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`Proxy alert details for ${alert.tool_name}`}
    >
      <button
        type="button"
        className="absolute inset-0 cursor-default"
        aria-label="Close proxy alert details"
        onClick={onClose}
      />
      <aside className="relative h-full w-full max-w-lg overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-5 shadow-2xl">
        <div className="mb-4 flex items-start justify-between gap-4 border-b border-zinc-800 pb-4">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500">
              Runtime alert
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span
                className={`text-[10px] px-1.5 py-0.5 rounded border ${
                  SEVERITY_COLORS[alert.severity] ?? SEVERITY_COLORS.info
                }`}
              >
                {alert.severity}
              </span>
              <span className="font-mono text-sm text-zinc-100">{alert.detector}</span>
            </div>
            <h2 className="mt-2 break-all font-mono text-lg font-semibold text-zinc-100">
              {alert.tool_name}
            </h2>
            <p className="mt-1 text-sm text-zinc-400">{proxyAlertSummary(alert)}</p>
            {alert.ts ? (
              <p className="mt-2 text-xs text-zinc-600">{formatDate(alert.ts)}</p>
            ) : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-zinc-800 bg-zinc-900 p-2 text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-100"
            aria-label="Close proxy alert drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <dl className="space-y-3">
          {rows.map((row) => (
            <div
              key={`${row.label}:${row.value}`}
              className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2"
            >
              <dt className="text-[10px] uppercase tracking-[0.16em] text-zinc-500">
                {row.label}
              </dt>
              <dd className="mt-1 break-words font-mono text-xs text-zinc-200">{row.value}</dd>
            </div>
          ))}
        </dl>
      </aside>
    </div>
  );
}
