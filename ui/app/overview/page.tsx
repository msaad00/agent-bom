"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, formatDate } from "@/lib/api";
import type {
  OverviewResponse,
  OverviewDomain,
  OverviewTopRisk,
} from "@/lib/api-types";
import { ActivityFeed } from "@/components/activity-feed";
import { SeverityBadge } from "@/components/severity-badge";
import { PostureGrade } from "@/components/posture-grade";
import { ApiOfflineState } from "@/components/api-offline-state";
import { EmptyState } from "@/components/empty-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import {
  Cloud,
  ShieldCheck,
  DollarSign,
  Fingerprint,
  ArrowRight,
  ShieldAlert,
  ExternalLink,
  Layers,
} from "lucide-react";

// ─── Domain presentation metadata ─────────────────────────────────────────────

type DomainKey = keyof OverviewResponse["domains"];

const DOMAIN_ICONS: Record<DomainKey, React.ElementType> = {
  cloud: Cloud,
  runtime: ShieldCheck,
  cost: DollarSign,
  identity: Fingerprint,
  ops: Layers,
};

const DOMAIN_ORDER: DomainKey[] = ["cloud", "runtime", "cost", "identity", "ops"];

const STATUS_STYLES: Record<
  OverviewDomain["status"],
  { ring: string; text: string; dot: string; label: string }
> = {
  critical: { ring: "border-red-500/30", text: "text-red-300", dot: "bg-red-500", label: "Critical" },
  warn: { ring: "border-amber-500/30", text: "text-amber-300", dot: "bg-amber-500", label: "Attention" },
  ok: { ring: "border-emerald-500/25", text: "text-emerald-300", dot: "bg-emerald-500", label: "Healthy" },
  idle: { ring: "border-[color:var(--border-subtle)]", text: "text-[color:var(--text-secondary)]", dot: "bg-[color:var(--text-tertiary)]", label: "No data" },
};

function _classifyApiErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function OverviewPage() {
  const [data, setData] = useState<OverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [errorKind, setErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [errorDetail, setErrorDetail] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .getOverview()
      .then((res) => {
        if (cancelled) return;
        setData(res);
        setError(false);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(true);
        setErrorKind(_classifyApiErrorKind(err));
        setErrorDetail(err instanceof Error ? err.message : null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return <ApiOfflineState kind={errorKind} detail={errorDetail} />;
  }

  if (loading || !data) {
    return <OverviewSkeleton />;
  }

  const { headline, posture, domains, top_risks } = data;
  const hasAnySignal = headline.scans > 0 || DOMAIN_ORDER.some((k) => domains[k].metric > 0);

  return (
    <div className="space-y-8">
      {/* Hero */}
      <section className="relative overflow-hidden rounded-[28px] border border-zinc-800/80 bg-[radial-gradient(circle_at_top_left,rgba(16,185,129,0.16),transparent_24%),radial-gradient(circle_at_top_right,rgba(239,68,68,0.12),transparent_24%),linear-gradient(180deg,rgba(24,24,27,0.98),rgba(9,9,11,0.96))] p-6 shadow-2xl shadow-black/20">
        <div className="flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0 max-w-3xl">
            <p className="text-[11px] uppercase tracking-[0.24em] text-emerald-400">Command center</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-50 sm:text-4xl">
              Posture overview
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-300">
              One view across cloud, runtime, LLM cost, identity, and operations. Each tile links
              into its detail surface. {headline.latest_scan_at ? `Last scan ${formatDate(headline.latest_scan_at)}.` : "No scans recorded yet."}
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <HeadlineChip tone="red" label="Critical" value={headline.critical} />
              <HeadlineChip tone="amber" label="High" value={headline.high} />
              <HeadlineChip tone="red" label="Actively exploited" value={headline.kev} />
              <HeadlineChip tone="amber" label="Credential exposed" value={headline.credential_exposed} />
              <HeadlineChip tone="sky" label="Scans" value={headline.scans} />
            </div>
          </div>
          <div className="flex flex-wrap gap-2 xl:justify-end">
            <Link
              href="/scan"
              className="flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500"
            >
              Run scan
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/findings?severity=critical"
              className="flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900/80 px-4 py-2.5 text-sm font-medium text-zinc-200 transition-colors hover:border-zinc-500 hover:bg-zinc-800"
            >
              Fix queue
              <ShieldAlert className="h-4 w-4" />
            </Link>
          </div>
        </div>

        {posture.grade !== "N/A" && (
          <div className="mt-6">
            <PostureGrade
              grade={posture.grade}
              score={posture.score}
              dimensions={{}}
              summary={posture.summary}
              variant="panel"
              defaultExpanded={false}
            />
          </div>
        )}
      </section>

      {/* Domain tiles */}
      <section>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-widest text-[color:var(--text-tertiary)]">Domains</h2>
          <span className="text-[10px] text-[color:var(--text-tertiary)]">{DOMAIN_ORDER.length} surfaces</span>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {DOMAIN_ORDER.map((key) => (
            <DomainCard key={key} domainKey={key} domain={domains[key]} />
          ))}
        </div>
      </section>

      {/* Top risks + activity */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <section className="min-w-0 lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-widest text-[color:var(--text-tertiary)]">
              Top risks
            </h2>
            <Link href="/findings" className="flex items-center gap-1 text-xs text-emerald-500 hover:text-emerald-400">
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          {top_risks.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title={hasAnySignal ? "No scored risks" : "No findings yet"}
              description={
                hasAnySignal
                  ? "No blast-radius findings have a risk score above zero in the current scan set."
                  : "Run a scan to populate cross-domain risk."
              }
              {...(hasAnySignal ? {} : { action: { label: "Run a scan", href: "/scan" } })}
            />
          ) : (
            <div className="space-y-2">
              {top_risks.map((risk, i) => (
                <TopRiskRow key={`${risk.vulnerability_id}:${risk.package ?? "?"}:${i}`} risk={risk} />
              ))}
            </div>
          )}
        </section>

        <section className="min-w-0">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-widest text-[color:var(--text-tertiary)]">Activity</h2>
          <ActivityFeed maxItems={15} refresh={false} />
        </section>
      </div>
    </div>
  );
}

// ─── Components ────────────────────────────────────────────────────────────────

function HeadlineChip({ tone, label, value }: { tone: "red" | "amber" | "sky"; label: string; value: number }) {
  const tones = {
    red: "border-red-500/20 bg-red-500/10 text-red-200/70",
    amber: "border-amber-500/20 bg-amber-500/10 text-amber-200/70",
    sky: "border-sky-500/20 bg-sky-500/10 text-sky-200/70",
  };
  const valueTone = {
    red: "text-red-100",
    amber: "text-amber-100",
    sky: "text-sky-100",
  };
  return (
    <div className={`rounded-2xl border px-3 py-2 ${tones[tone]}`}>
      <div className="text-[10px] uppercase tracking-[0.18em]">{label}</div>
      <div className={`mt-1 font-mono text-lg font-semibold ${valueTone[tone]}`}>{value}</div>
    </div>
  );
}

function DomainCard({ domainKey, domain }: { domainKey: DomainKey; domain: OverviewDomain }) {
  const Icon = DOMAIN_ICONS[domainKey];
  const s = STATUS_STYLES[domain.status];
  return (
    <Link
      href={domain.href}
      className={`group flex min-w-0 flex-col rounded-2xl border bg-[color:var(--surface)] p-4 transition-colors hover:border-[color:var(--border-strong)] ${s.ring}`}
    >
      <div className="flex min-w-0 items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)]">
            <Icon className="h-4 w-4" />
          </span>
          <span className="truncate text-sm font-semibold text-[color:var(--foreground)]">{domain.label}</span>
        </div>
        <span className={`flex shrink-0 items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide ${s.text}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
          {s.label}
        </span>
      </div>
      <div className="mt-4 flex items-end justify-between gap-2">
        <div className="min-w-0">
          <div className="font-mono text-2xl font-bold tracking-tight text-[color:var(--foreground)]">{domain.metric}</div>
          <div className="mt-0.5 truncate text-xs text-[color:var(--text-tertiary)]">{domain.metric_label}</div>
        </div>
        <ArrowRight className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)] transition-colors group-hover:text-[color:var(--foreground)]" />
      </div>
    </Link>
  );
}

function TopRiskRow({ risk }: { risk: OverviewTopRisk }) {
  return (
    <Link
      href={`/findings?cve=${encodeURIComponent(risk.vulnerability_id)}`}
      className="flex min-w-0 items-start gap-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 transition-colors hover:border-[color:var(--border-strong)]"
    >
      <SeverityBadge severity={risk.severity} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-semibold text-[color:var(--foreground)] group-hover:text-emerald-400">
            {risk.vulnerability_id}
          </span>
          {risk.package && <span className="truncate font-mono text-xs text-[color:var(--text-tertiary)]">{risk.package}</span>}
          {risk.is_kev && <span className="text-xs font-semibold text-red-400">CISA KEV</span>}
        </div>
        <div className="mt-1.5 flex flex-wrap gap-3 text-xs text-[color:var(--text-tertiary)]">
          {risk.cvss_score != null && <span>CVSS {risk.cvss_score.toFixed(1)}</span>}
          {risk.epss_score != null && <span>EPSS {(risk.epss_score * 100).toFixed(0)}%</span>}
          {risk.affected_agents.length > 0 && (
            <span>
              {risk.affected_agents.length} agent{risk.affected_agents.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>
      </div>
      <div className="flex shrink-0 flex-col items-end gap-1">
        {risk.risk_score > 0 && (
          <div className="text-right">
            <div className="font-mono text-lg font-bold text-red-400">{risk.risk_score.toFixed(0)}</div>
            <div className="text-[10px] text-[color:var(--text-tertiary)]">score</div>
          </div>
        )}
        <a
          href={`https://osv.dev/vulnerability/${risk.vulnerability_id}`}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="inline-flex items-center gap-1 text-[11px] text-[color:var(--text-tertiary)] transition-colors hover:text-[color:var(--foreground)]"
        >
          OSV <ExternalLink className="h-3 w-3" />
        </a>
      </div>
    </Link>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-8" aria-busy="true">
      <div className="h-48 animate-pulse rounded-[28px] border border-zinc-800/80 bg-zinc-900/40" />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-32 animate-pulse rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="h-64 animate-pulse rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] lg:col-span-2" />
        <div className="h-64 animate-pulse rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]" />
      </div>
    </div>
  );
}
