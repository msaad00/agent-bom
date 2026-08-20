"use client";

import Link from "next/link";
import { useState } from "react";
import { Package, Server } from "lucide-react";

import { DetailTabs } from "@/components/detail-tabs";
import { Drawer } from "@/components/drawer";
import {
  controlStatusLabel,
  evidenceReasonCta,
  evidenceReasonLabel,
  isControlUnscored,
} from "@/components/compliance-status";
import type { ComplianceControl } from "@/lib/api";
import { findingsHref, remediationHref, securityGraphHref } from "@/lib/page-links";

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
  const [tab, setTab] = useState<"overview" | "evidence" | "actions">("overview");
  const name = catalogName ?? control.name;
  const sev = control.severity_breakdown;
  const unscored = isControlUnscored(control.status);
  const reasonLabel = evidenceReasonLabel(control.evidence_reason);
  const reasonCta = unscored ? evidenceReasonCta(control.evidence_reason) : null;

  const statusPill = (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
        control.status === "pass"
          ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
          : control.status === "warning"
            ? "bg-yellow-500/15 text-yellow-700 dark:text-yellow-300"
            : unscored
              ? "bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]"
              : "bg-red-500/15 text-red-700 dark:text-red-300"
      }`}
    >
      {controlStatusLabel(control.status)}
    </span>
  );

  return (
    <Drawer
      open
      onClose={onClose}
      size="xl"
      ariaLabel={`Control details for ${control.code}`}
      eyebrow={frameworkLabel}
      title={<span><span className="font-mono">{control.code}</span> · {name}</span>}
      subtitle={`${control.findings} finding${control.findings === 1 ? "" : "s"} mapped to this control.`}
      headerAside={statusPill}
    >
      <DetailTabs
        tabs={[
          { key: "overview", label: "Overview" },
          { key: "evidence", label: "Evidence" },
          { key: "actions", label: "Actions" },
        ] as const}
        value={tab}
        onChange={setTab}
        ariaLabel="Control detail views"
      />

      {tab === "overview" ? (
        <div>
          {unscored ? (
            <div className="mb-4" data-testid="control-unscored-provenance">
              <p className="text-sm text-[color:var(--text-secondary)]">
                Not evaluated{reasonLabel ? ` — ${reasonLabel.toLowerCase()}` : ""}.
              </p>
              {reasonCta ? (
                <Link
                  href={reasonCta.href}
                  className="mt-2 inline-flex items-center rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-1.5 text-xs font-medium text-[color:var(--accent)] transition hover:bg-[color:var(--accent-soft-hover)]"
                  data-testid="control-evidence-cta"
                >
                  {reasonCta.label}
                </Link>
              ) : null}
            </div>
          ) : null}

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

        </div>
      ) : null}

      {tab === "evidence" ? (
        <div>
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

        {control.affected_packages.length === 0 && control.affected_agents.length === 0 ? (
          <p className="text-sm text-[color:var(--text-secondary)]">
            No affected package or agent identities were reported for this control.
          </p>
        ) : null}
        </div>
      ) : null}

      {tab === "actions" ? (
        <div className="flex flex-wrap gap-2">
          <Link
            href={findingsHref({ q: control.code })}
            className="rounded-lg border border-emerald-700/50 bg-emerald-500/10 dark:bg-emerald-950/30 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-600"
          >
            View findings
          </Link>
          <Link
            href={securityGraphHref({
              packageName: control.affected_packages[0],
              agent: control.affected_agents[0],
            })}
            className="rounded-lg border border-sky-700/40 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-800 dark:text-sky-200 transition hover:border-sky-600"
          >
            Evidence in security graph
          </Link>
          <Link
            href={remediationHref({ q: control.code })}
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-secondary)] transition hover:text-[color:var(--foreground)]"
          >
            Remediation
          </Link>
        </div>
      ) : null}
    </Drawer>
  );
}
