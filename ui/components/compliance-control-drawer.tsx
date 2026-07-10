"use client";

import Link from "next/link";
import { Package, Server, X } from "lucide-react";

import type { ComplianceControl } from "@/lib/api";

function statusLabel(status: ComplianceControl["status"]): string {
  switch (status) {
    case "pass":
      return "Pass";
    case "warning":
      return "Needs attention";
    default:
      return "Fail";
  }
}

export function ComplianceControlDrawer({
  control,
  frameworkLabel,
  catalogName,
  onClose,
}: {
  control: ComplianceControl;
  frameworkLabel: string;
  catalogName?: string | undefined;
  onClose: () => void;
}) {
  const name = catalogName ?? control.name;
  const sev = control.severity_breakdown;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/45 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`Control details for ${control.code}`}
    >
      <button
        type="button"
        className="absolute inset-0 cursor-default"
        aria-label="Close control details"
        onClick={onClose}
      />
      <aside className="relative h-full w-full max-w-xl overflow-y-auto border-l border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-2xl">
        <div className="mb-4 flex items-start justify-between gap-4 border-b border-[color:var(--border-subtle)] pb-4">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
              {frameworkLabel}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-semibold text-[color:var(--foreground)]">
                {control.code}
              </span>
              <span
                className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                  control.status === "pass"
                    ? "bg-emerald-500/15 text-emerald-300"
                    : control.status === "warning"
                      ? "bg-yellow-500/15 text-yellow-300"
                      : "bg-red-500/15 text-red-300"
                }`}
              >
                {statusLabel(control.status)}
              </span>
            </div>
            <h2 className="mt-2 text-base font-medium leading-snug text-[color:var(--foreground)]">
              {name}
            </h2>
            <p className="mt-2 text-sm text-[color:var(--text-secondary)]">
              {control.findings} finding{control.findings === 1 ? "" : "s"} mapped to this control.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-2 text-[color:var(--text-secondary)] transition-colors hover:text-[color:var(--foreground)]"
            aria-label="Close control drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {(sev.critical ?? 0) + (sev.high ?? 0) + (sev.medium ?? 0) + (sev.low ?? 0) > 0 ? (
          <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              ["Critical", sev.critical ?? 0, "text-red-300"],
              ["High", sev.high ?? 0, "text-orange-300"],
              ["Medium", sev.medium ?? 0, "text-yellow-300"],
              ["Low", sev.low ?? 0, "text-blue-300"],
            ].map(([label, count, tone]) =>
              Number(count) > 0 ? (
                <div
                  key={String(label)}
                  className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2"
                >
                  <p className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                    {label}
                  </p>
                  <p className={`mt-1 text-lg font-semibold ${tone}`}>{count}</p>
                </div>
              ) : null,
            )}
          </div>
        ) : null}

        {control.affected_packages.length > 0 ? (
          <div className="mb-4">
            <div className="mb-2 flex items-center gap-1.5 text-xs text-[color:var(--text-tertiary)]">
              <Package className="h-3.5 w-3.5" />
              Affected packages
            </div>
            <div className="flex flex-wrap gap-1.5">
              {control.affected_packages.map((pkg) => (
                <span
                  key={pkg}
                  className="rounded bg-[color:var(--surface-muted)] px-2 py-0.5 font-mono text-xs text-[color:var(--text-secondary)]"
                >
                  {pkg}
                </span>
              ))}
            </div>
          </div>
        ) : null}

        {control.affected_agents.length > 0 ? (
          <div className="mb-4">
            <div className="mb-2 flex items-center gap-1.5 text-xs text-[color:var(--text-tertiary)]">
              <Server className="h-3.5 w-3.5" />
              Affected agents
            </div>
            <div className="flex flex-wrap gap-1.5">
              {control.affected_agents.map((agent) => (
                <span
                  key={agent}
                  className="rounded bg-[color:var(--surface-muted)] px-2 py-0.5 text-xs text-[color:var(--text-secondary)]"
                >
                  {agent}
                </span>
              ))}
            </div>
          </div>
        ) : null}

        <div className="mt-6 flex flex-wrap gap-2 border-t border-[color:var(--border-subtle)] pt-4">
          <Link
            href={`/findings?q=${encodeURIComponent(control.code)}`}
            className="rounded-lg border border-emerald-700/50 bg-emerald-950/30 px-3 py-1.5 text-xs font-medium text-emerald-200 transition hover:border-emerald-600"
          >
            View findings
          </Link>
          <Link
            href={`/remediation?q=${encodeURIComponent(control.code)}`}
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-secondary)] transition hover:text-[color:var(--foreground)]"
          >
            Remediation
          </Link>
        </div>
      </aside>
    </div>
  );
}
