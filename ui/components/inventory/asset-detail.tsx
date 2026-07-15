"use client";

import Link from "next/link";
import { Bug, ExternalLink, FileCheck, Network, Share2 } from "lucide-react";

import { SeverityBadge } from "@/components/severity-badge";
import { ICON_SIZE } from "@/lib/icon-sizes";
import type { AssetKindConfig, AssetRow } from "@/lib/inventory";
import {
  complianceHref,
  findingsHref,
  lineageHref,
  securityGraphHref,
} from "@/lib/inventory-links";

function MetaRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <dt className="shrink-0 text-[11px] font-medium uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">
        {label}
      </dt>
      <dd className="min-w-0 truncate text-right text-sm text-[color:var(--foreground)]">{value}</dd>
    </div>
  );
}

const SKIP_ATTRS = new Set([
  "version",
  "ecosystem",
  "cloud_provider",
  "provider",
  "environment",
]);

function readableAttributes(attributes: Record<string, unknown>): [string, string][] {
  const rows: [string, string][] = [];
  for (const [key, value] of Object.entries(attributes)) {
    if (SKIP_ATTRS.has(key)) continue;
    if (value == null) continue;
    if (typeof value === "object") continue;
    const text = String(value).trim();
    if (!text) continue;
    rows.push([key, text]);
  }
  return rows.slice(0, 12);
}

export function AssetDetail({ row, config }: { row: AssetRow; config: AssetKindConfig }) {
  const Icon = config.icon;
  const attrRows = readableAttributes(row.attributes);
  const compliance = complianceHref(row);

  return (
    <div className="flex flex-col gap-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 elev-1">
      <header className="flex items-start gap-3">
        <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]">
          <Icon className={ICON_SIZE.sm} aria-hidden="true" />
        </span>
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
            {config.singular} · {row.entityType}
          </p>
          <h2 className="mt-0.5 break-words text-lg font-semibold text-[color:var(--foreground)]">
            {row.label}
          </h2>
        </div>
        <span className="ml-auto shrink-0">
          <SeverityBadge severity={row.severity} />
        </span>
      </header>

      <div className="grid grid-cols-3 gap-px overflow-hidden rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--border-subtle)]">
        <div className="bg-[color:var(--surface)] px-3 py-2">
          <p className="text-[10px] uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">Findings</p>
          <p className="mt-0.5 font-mono text-lg font-semibold text-[color:var(--foreground)]">
            {row.findingCount}
          </p>
        </div>
        <div className="bg-[color:var(--surface)] px-3 py-2">
          <p className="text-[10px] uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">Critical</p>
          <p
            className={`mt-0.5 font-mono text-lg font-semibold ${
              row.criticalCount > 0
                ? "text-[color:var(--severity-critical)]"
                : "text-[color:var(--foreground)]"
            }`}
          >
            {row.criticalCount}
          </p>
        </div>
        <div className="bg-[color:var(--surface)] px-3 py-2">
          <p className="text-[10px] uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">Risk</p>
          <p className="mt-0.5 font-mono text-lg font-semibold text-[color:var(--foreground)]">
            {row.riskScore ? row.riskScore.toFixed(0) : "—"}
          </p>
        </div>
      </div>

      <dl className="divide-y divide-[color:var(--border-subtle)]">
        <MetaRow label="Status" value={row.status} />
        {row.version ? <MetaRow label="Version" value={row.version} /> : null}
        {row.ecosystem ? <MetaRow label="Ecosystem" value={row.ecosystem} /> : null}
        {row.provider ? <MetaRow label="Provider" value={row.provider} /> : null}
        {row.environment ? <MetaRow label="Environment" value={row.environment} /> : null}
        <MetaRow
          label="Sources"
          value={row.dataSources.length > 0 ? row.dataSources.join(", ") : "—"}
        />
        {attrRows.map(([key, value]) => (
          <MetaRow key={key} label={key.replace(/_/g, " ")} value={value} />
        ))}
      </dl>

      {row.complianceTags.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {row.complianceTags.slice(0, 8).map((tag) => (
            <span
              key={tag}
              className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 text-[11px] text-[color:var(--text-secondary)]"
            >
              {tag}
            </span>
          ))}
        </div>
      ) : null}

      <div className="mt-1 flex flex-col gap-2 border-t border-[color:var(--border-subtle)] pt-3">
        <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
          Correlate
        </p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <CorrelationLink href={findingsHref(row)} icon={Bug} label="Findings" hint={`${row.findingCount} correlated`} />
          <CorrelationLink href={securityGraphHref(row)} icon={Network} label="Security graph" hint="Blast radius" />
          <CorrelationLink href={lineageHref(row)} icon={Share2} label="Lineage" hint="Upstream & downstream" />
          {compliance ? (
            <CorrelationLink href={compliance} icon={FileCheck} label="Compliance" hint={row.complianceTags[0]} />
          ) : null}
        </div>
      </div>
    </div>
  );
}

function CorrelationLink({
  href,
  icon: Icon,
  label,
  hint,
}: {
  href: string;
  icon: React.ElementType;
  label: string;
  hint?: string | undefined;
}) {
  return (
    <Link
      href={href}
      className="group flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 transition-colors hover:border-[color:var(--border-strong)] hover:bg-[color:var(--surface-elevated)]"
    >
      <Icon className={`${ICON_SIZE.sm} text-[color:var(--text-secondary)]`} aria-hidden="true" />
      <span className="min-w-0">
        <span className="block text-sm font-medium text-[color:var(--foreground)]">{label}</span>
        {hint ? (
          <span className="block truncate text-[11px] text-[color:var(--text-tertiary)]">{hint}</span>
        ) : null}
      </span>
      <ExternalLink
        className={`${ICON_SIZE.xs} ml-auto shrink-0 text-[color:var(--text-tertiary)] transition-colors group-hover:text-[color:var(--text-secondary)]`}
        aria-hidden="true"
      />
    </Link>
  );
}
