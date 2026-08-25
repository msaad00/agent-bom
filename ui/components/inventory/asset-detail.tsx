"use client";

import Link from "next/link";
import { Bug, ExternalLink, FileCheck, Network, Share2 } from "lucide-react";

import { SeverityBadge } from "@/components/severity-badge";
import { ICON_SIZE } from "@/lib/icon-sizes";
import type { InventoryAssetDetailResponse } from "@/lib/api";
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

export function AssetDetail({
  row,
  config,
  detail,
  loading = false,
  error = "",
  scanId,
}: {
  row: AssetRow;
  config: AssetKindConfig;
  detail?: InventoryAssetDetailResponse | undefined;
  loading?: boolean | undefined;
  error?: string | undefined;
  scanId?: string | undefined;
}) {
  const Icon = config.icon;
  const attributes = detail?.asset.attributes ?? row.attributes;
  const attrRows = readableAttributes(attributes);
  const compliance = complianceHref(row);
  const relationshipCount = detail
    ? detail.edges_in.length + detail.edges_out.length
    : null;

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

      <section className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
        <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">
          Snapshot context
        </p>
        {loading ? (
          <p className="mt-1 text-xs text-[color:var(--text-secondary)]">Loading relationships and impact…</p>
        ) : error ? (
          <p className="mt-1 text-xs text-[color:var(--status-danger)]">{error}</p>
        ) : detail ? (
          <dl className="mt-1 divide-y divide-[color:var(--border-subtle)]">
            <MetaRow label="Relationships" value={relationshipCount?.toLocaleString() ?? "0"} />
            <MetaRow label="Neighbors" value={detail.neighbors.length.toLocaleString()} />
            <MetaRow label="Evidence sources" value={detail.sources.length.toLocaleString()} />
            <MetaRow
              label="Impact fields"
              value={Object.keys(detail.impact ?? {}).length.toLocaleString()}
            />
          </dl>
        ) : (
          <p className="mt-1 text-xs text-[color:var(--text-secondary)]">
            Select this row to resolve its tenant-scoped relationships and impact.
          </p>
        )}
      </section>

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
          <CorrelationLink href={findingsHref(row, scanId)} icon={Bug} label="Findings" hint={`${row.findingCount} correlated`} />
          <CorrelationLink href={securityGraphHref(row, scanId)} icon={Network} label="Security graph" hint="Blast radius" />
          <CorrelationLink href={lineageHref(row, scanId)} icon={Share2} label="Lineage" hint="Upstream & downstream" />
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
