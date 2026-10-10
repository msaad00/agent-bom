"use client";

import { providerLabel,statusTone,type IngestMode } from "@/components/connections/catalog";
import {
  type DiscoveryProvidersResponse,
  type SourceRecord
} from "@/lib/api";
import { vendorLogo } from "@/lib/vendor-logos";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  Clock,
  Cloud,
  FileSearch,
  GitGraph,
  ListChecks,
  ShieldCheck
} from "lucide-react";


export function StatusPill({ status }: { status: string }) {
  const Icon =
    status === "active"
      ? CheckCircle2
      : status === "error"
        ? AlertTriangle
        : Clock;
  const label =
    status === "active" ? "Active" : status === "error" ? "Error" : "Pending";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${statusTone(status)}`}
    >
      <Icon className="h-3 w-3" />
      {label}
    </span>
  );
}


export const SOURCE_STATUS_TONE: Record<string, string> = {
  healthy: "var(--status-success)",
  done: "var(--status-success)",
  active: "var(--status-success)",
  configured: "var(--accent)",
  degraded: "var(--status-warn)",
  paused: "var(--status-warn)",
  pending: "var(--status-warn)",
  disabled: "var(--text-tertiary)",
  error: "var(--status-danger)",
  failed: "var(--status-danger)",
};


export function sourceStatusColor(status: string): string {
  return SOURCE_STATUS_TONE[status.toLowerCase()] ?? "var(--accent)";
}


export function SourceStatusPill({ status }: { status: string }) {
  const tone = sourceStatusColor(status);
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]"
      style={{ color: tone }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: tone }} aria-hidden="true" />
      {status}
    </span>
  );
}


export const MODE_DOT: Record<IngestMode, string> = {
  "Direct scan": "var(--status-success)",
  "Read-only connector": "var(--severity-low)",
  "Pushed ingest": "var(--status-warn)",
  Runtime: "var(--severity-high)",
  "Imported artifact": "var(--text-tertiary)",
};


export function ModeChip({ mode }: { mode: IngestMode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-outline bg-surface-elevated px-2.5 py-0.5 text-[11px] font-medium text-ink-secondary">
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: MODE_DOT[mode] }} aria-hidden="true" />
      {mode}
    </span>
  );
}


export function evidenceLinks(scanId: string) {
  const encoded = encodeURIComponent(scanId);
  return [
    { label: "Scan result", href: `/scan?id=${encoded}`, icon: FileSearch },
    { label: "Jobs", href: `/jobs?q=${encoded}`, icon: ClipboardList },
    { label: "Findings", href: `/findings?scan=${encoded}`, icon: ListChecks },
    { label: "Graph", href: `/graph?scan_id=${encoded}`, icon: GitGraph },
    { label: "Compliance", href: `/compliance?q=${encoded}`, icon: ShieldCheck },
  ];
}


export function sourceEvidenceHref(
  source: SourceRecord,
  target: "jobs" | "findings" | "graph" | "compliance",
): string {
  const jobId = source.last_job_id ?? "";
  if (target === "jobs" || !jobId) return `/jobs?q=${encodeURIComponent(source.source_id)}`;
  const route = target === "graph" ? "security-graph" : target;
  return `/${route}?scan=${encodeURIComponent(jobId)}`;
}


export function summarizeProviders(contracts: DiscoveryProvidersResponse | null) {
  const providers = contracts?.providers ?? [];
  return {
    total: providers.length,
    readOnly: providers.filter((provider) => provider.trust_contract.read_only).length,
    scopeZero: providers.filter((provider) => provider.trust_contract.supports_scope_zero).length,
    permissionCount: providers.reduce(
      (total, provider) => total + provider.capabilities.permissions_used.length,
      0,
    ),
  };
}


export function ProviderLogo({
  provider,
  className = "h-7 w-7",
}: {
  provider: string;
  className?: string;
}) {
  const src = vendorLogo(provider);
  if (!src) {
    return <Cloud className={`${className} text-emerald-400`} aria-hidden="true" />;
  }
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img src={src} alt={`${providerLabel(provider)} logo`} className={`${className} object-contain`} />
  );
}
