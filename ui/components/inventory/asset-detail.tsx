"use client";

import { nodeRiskLabel } from "@/lib/node-risk-assessment";
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
  const relationships = detail
    ? [...new Map([...detail.edges_in, ...detail.edges_out].map((edge) => [
      JSON.stringify([edge.source, edge.target, edge.relationship]), edge,
    ])).values()]
    : [];
  const endpoints = new Map((detail?.nodes ?? []).map((node) => [String(node.id), node]));
  const effectiveScanId = detail?.scan_id || scanId;
  const compliance = complianceHref(row, effectiveScanId);

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
          <p className="mt-0.5 font-mono text-sm font-semibold text-[color:var(--foreground)]">
            {nodeRiskLabel(row.riskScore, row.riskAssessment)}
          </p>
        </div>
      </div>

      <dl className="divide-y divide-[color:var(--border-subtle)]">
        <MetaRow label="Status" value={row.status} />
        {row.version ? <MetaRow label="Version" value={row.version} /> : null}
        {row.ecosystem ? <MetaRow label="Ecosystem" value={row.ecosystem} /> : null}
        {row.provider ? <MetaRow label="Provider" value={row.provider} /> : null}
        {row.environment ? <MetaRow label="Environment" value={row.environment} /> : null}
        <MetaRow label="First seen" value={row.firstSeen || "Not recorded"} />
        <MetaRow label="Last seen" value={row.lastSeen || "Not recorded"} />
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
          <p className="mt-1 text-xs text-[color:var(--text-secondary)]">Loading recorded relationships…</p>
        ) : error ? (
          <p className="mt-1 text-xs text-[color:var(--status-danger)]">{error}</p>
        ) : detail ? (
          <>
            <dl className="mt-1 divide-y divide-[color:var(--border-subtle)]">
              <MetaRow label="Snapshot" value={detail.scan_id} />
              <MetaRow label="Evidence sources" value={(detail.evidence_sources ?? row.dataSources).join(", ") || "Not recorded"} />
              <MetaRow label="Relationships shown" value={relationships.length.toLocaleString()} />
            </dl>
            <p className="mt-2 text-xs text-[color:var(--text-secondary)]">
              {detail.completeness.complete
                ? "Recorded relationship page complete. Collection coverage and blast radius are not assessed here."
                : "Partial relationship page. More records or missing endpoints may remain; this is not the full component chain."}
            </p>
            <ul aria-label="Recorded component relationships" className="mt-2 max-h-72 space-y-2 overflow-y-auto">
              {relationships.map((edge) => {
                const incoming = edge.target === row.id;
                const endpointId = String(incoming ? edge.source : edge.target);
                const endpoint = endpoints.get(endpointId);
                const relationship = String(edge.relationship).replace(/_/g, " ");
                const hierarchy = edge.relationship === "contains" ? (incoming ? "Parent" : "Child") : (incoming ? "Incoming" : "Outgoing");
                const params = new URLSearchParams({ lens: "estate", node: endpointId });
                if (effectiveScanId) params.set("scan", effectiveScanId);
                return (
                  <li key={JSON.stringify([edge.source, edge.target, edge.relationship])} className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2 text-xs">
                    <p className="text-[color:var(--text-secondary)]">{hierarchy} · {relationship}</p>
                    <Link href={`/security-graph?${params.toString()}`} className="mt-1 block break-words font-medium underline underline-offset-2">
                      {String(endpoint?.label || endpointId)}
                    </Link>
                    <details className="mt-1 text-[color:var(--text-secondary)]">
                      <summary className="cursor-pointer">Recorded evidence</summary>
                      <p className="mt-1 break-all">{String(edge.source)} → {String(edge.target)}</p>
                      <p>Last seen: {String(edge.last_seen || "Not recorded")}</p>
                      <p>Source scan: {String(edge.source_scan_id || "Not recorded")}</p>
                      <p>Direction: {String(edge.direction || "Not recorded")}</p>
                    </details>
                  </li>
                );
              })}
            </ul>
            {relationships.length === 0 ? <p className="mt-2 text-xs">No relationships recorded on this page.</p> : null}
            <Link href={securityGraphHref(row, effectiveScanId)} className="mt-3 block text-xs underline underline-offset-2">
              Inspect relationships in the security graph
            </Link>
          </>
        ) : (
          <p className="mt-1 text-xs text-[color:var(--text-secondary)]">
            Select this row to resolve its tenant-scoped recorded relationships.
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
          <CorrelationLink href={findingsHref(row, effectiveScanId)} icon={Bug} label="Findings" hint="Recorded component evidence" />
          <CorrelationLink href={securityGraphHref(row, effectiveScanId)} icon={Network} label="Security graph" hint="Blast radius" />
          <CorrelationLink href={lineageHref(row, effectiveScanId)} icon={Share2} label="Lineage" hint="Upstream & downstream" />
          {compliance ? (
            <CorrelationLink href={compliance} icon={FileCheck} label="Compliance" hint="Recorded control evidence" />
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
