"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowRight,
  Boxes,
  Cloud,
  KeyRound,
  ListChecks,
  MapPin,
  ShieldCheck,
} from "lucide-react";

import { api } from "@/lib/api";
import type { AccountSummaryDomain, AccountSummaryResponse } from "@/lib/api-types";
import { PageLaneHeader } from "@/components/page-lane";
import { PageLoadingState, PageEmptyState } from "@/components/states/page-state";
import { ApiOfflineState, type ApiOfflineKind } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { providerDisplayName } from "@/lib/scan-scope";

function classifyApiErrorKind(err: unknown): ApiOfflineKind {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

// Severity bands shown in a lane's strip, in descending order, plus ``unrated``
// for findings whose severity is unknown/unscored (issue #3946). Colors come
// from design tokens so light + dark both read correctly.
const SEVERITY_BANDS: {
  key: keyof AccountSummaryDomain["severity"];
  label: string;
  token: string;
}[] = [
  { key: "critical", label: "Critical", token: "--severity-critical" },
  { key: "high", label: "High", token: "--severity-high" },
  { key: "medium", label: "Medium", token: "--severity-medium" },
  { key: "low", label: "Low", token: "--severity-low" },
  { key: "unrated", label: "Unrated", token: "--severity-unrated" },
];

function ScopeChip({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[11px] font-medium text-[color:var(--text-secondary)]">
      {children}
    </span>
  );
}

function StatTile({
  icon: Icon,
  label,
  value,
  sub,
  href,
  tone = "neutral",
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  sub?: string;
  href?: string;
  tone?: "neutral" | "warn" | "danger" | "ok";
}) {
  const toneVar =
    tone === "danger"
      ? "var(--status-danger)"
      : tone === "warn"
        ? "var(--status-warn)"
        : tone === "ok"
          ? "var(--status-success)"
          : "var(--text-secondary)";
  const inner = (
    <div className="flex min-h-full flex-col rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
      <div className="mb-1 flex items-center gap-2">
        <Icon className="h-4 w-4" style={{ color: toneVar }} />
        <span className="text-xs text-[color:var(--text-tertiary)]">{label}</span>
      </div>
      <p className="text-2xl font-bold tabular-nums text-[color:var(--foreground)]" style={{ color: tone === "neutral" ? undefined : toneVar }}>
        {value}
      </p>
      {sub ? <p className="mt-0.5 text-[11px] text-[color:var(--text-tertiary)]">{sub}</p> : null}
    </div>
  );
  return href ? (
    <Link href={href} className="transition-colors hover:opacity-90">
      {inner}
    </Link>
  ) : (
    inner
  );
}

function DomainLane({ lane }: { lane: AccountSummaryDomain }) {
  const total = SEVERITY_BANDS.reduce((sum, band) => sum + (lane.severity[band.key] || 0), 0);
  const bands = SEVERITY_BANDS.filter((band) => (lane.severity[band.key] || 0) > 0);
  return (
    <Link
      href={lane.href}
      data-testid={`account-lane-${lane.domain}`}
      className="flex flex-col gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 transition-colors hover:border-[color:var(--border-strong)]"
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs font-semibold text-[color:var(--foreground)]">{lane.label}</span>
        <span className="text-lg font-bold tabular-nums text-[color:var(--foreground)]">{lane.count}</span>
      </div>
      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
        {total > 0 &&
          bands.map((band) => (
            <span
              key={band.key}
              className="h-full"
              style={{
                width: `${((lane.severity[band.key] || 0) / total) * 100}%`,
                backgroundColor: `var(${band.token})`,
              }}
            />
          ))}
      </div>
      <div className="flex flex-wrap gap-1">
        {total === 0 ? (
          <span className="text-[11px] text-[color:var(--text-tertiary)]">No findings</span>
        ) : (
          bands.map((band) => (
            <span
              key={band.key}
              className="rounded px-1.5 py-0.5 text-[11px] font-medium tabular-nums"
              style={{
                color: `var(${band.token})`,
                backgroundColor: `var(${band.token}-bg)`,
                border: `1px solid var(${band.token}-border)`,
              }}
            >
              {band.label} {lane.severity[band.key]}
            </span>
          ))
        )}
      </div>
    </Link>
  );
}

function ComplianceHealth({ summary }: { summary: AccountSummaryResponse }) {
  const { compliance } = summary;
  const hasRun = compliance.evaluated > 0 && compliance.pass_rate != null;
  const pct = compliance.pass_rate ?? 0;
  const tone = !hasRun ? "muted" : pct >= 90 ? "ok" : pct >= 70 ? "warn" : "danger";
  const barColor =
    tone === "ok"
      ? "var(--status-success)"
      : tone === "warn"
        ? "var(--status-warn)"
        : tone === "danger"
          ? "var(--status-danger)"
          : "var(--text-tertiary)";
  return (
    <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      <div className="mb-3 flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-[color:var(--text-secondary)]" />
        <h2 className="text-sm font-semibold text-[color:var(--foreground)]">CIS / compliance health</h2>
      </div>
      {!hasRun ? (
        <p className="text-sm text-[color:var(--text-tertiary)]">
          No stored CIS benchmark run for this account yet. Run a CIS benchmark for this account to populate a
          pass-rate — the CSPM lane above still counts open misconfiguration findings.
        </p>
      ) : (
        <>
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className="text-3xl font-bold tabular-nums" style={{ color: barColor }}>
              {pct.toFixed(1)}%
            </span>
            <span className="text-xs text-[color:var(--text-tertiary)]">
              {compliance.passed} passed · {compliance.failed} failed · {compliance.evaluated} evaluated
            </span>
          </div>
          <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
            <div className="h-full transition-all duration-700" style={{ width: `${Math.min(100, pct)}%`, backgroundColor: barColor }} />
          </div>
          {compliance.benchmarks.length > 0 ? (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {compliance.benchmarks.map((b) => (
                <span
                  key={`${b.provider}:${b.benchmark}`}
                  className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 text-[11px] text-[color:var(--text-secondary)]"
                >
                  {b.benchmark} · {b.pass_rate != null ? `${b.pass_rate.toFixed(0)}%` : "n/a"}
                </span>
              ))}
            </div>
          ) : null}
        </>
      )}
      <Link
        href={compliance.href}
        className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
      >
        View misconfiguration findings
        <ArrowRight className="h-3 w-3" />
      </Link>
    </section>
  );
}

export default function AccountDetailClient() {
  const params = useParams<{ ref: string }>();
  const rawRef = Array.isArray(params.ref) ? params.ref[0] : params.ref;
  const accountRef = useMemo(() => {
    try {
      return decodeURIComponent(rawRef ?? "");
    } catch {
      return rawRef ?? "";
    }
  }, [rawRef]);

  const [summary, setSummary] = useState<AccountSummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<ApiOfflineKind>("network");

  useEffect(() => {
    if (!accountRef) {
      setLoading(false);
      return;
    }
    let mounted = true;
    setLoading(true);
    api
      .getCloudAccountSummary(accountRef)
      .then((data) => {
        if (!mounted) return;
        setSummary(data);
        setError(null);
      })
      .catch((err) => {
        if (!mounted) return;
        setError(err?.message ?? "Failed to load account summary");
        setErrorKind(classifyApiErrorKind(err));
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [accountRef]);

  if (loading) {
    return (
      <PageLoadingState
        title="Loading account posture"
        detail="Aggregating findings, compliance, and identities for this cloud account."
      />
    );
  }
  if (error) {
    return <ApiOfflineState title="Account summary unavailable" detail={error} kind={errorKind} />;
  }
  if (!summary) return null;

  const providerLabel = summary.provider ? providerDisplayName(summary.provider) : "Cloud";
  const criticalHigh = (summary.severity.critical || 0) + (summary.severity.high || 0);

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="cloud-data"
        title={summary.account ? `${providerLabel} · ${summary.account}` : "Cloud account"}
        subtitle={
          summary.account_ref
            ? `End-to-end read-only posture for ${summary.account_ref}. Findings, compliance, and identities in one pane.`
            : "This account reference could not be parsed. Use a canonical reference such as aws:123456789012."
        }
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            <ScopeChip>
              <Cloud className="h-3 w-3" />
              {providerLabel}
            </ScopeChip>
            {summary.regions.slice(0, 4).map((region) => (
              <ScopeChip key={region}>
                <MapPin className="h-3 w-3" />
                {region}
              </ScopeChip>
            ))}
            {summary.environments.map((env) => (
              <ScopeChip key={env}>{env}</ScopeChip>
            ))}
          </div>
        }
      />

      {summary.empty ? (
        <PageEmptyState
          title="No evidence for this account yet"
          detail={
            summary.provider
              ? `No findings or CIS benchmark runs are recorded for ${summary.account_ref}. Connect and scan this account to populate its posture.`
              : "Provide a canonical account reference like aws:123456789012 (provider:account)."
          }
          icon={Cloud}
        />
      ) : (
        <>
          {/* Leadership altitude — the account at a glance. */}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            <StatTile
              icon={ListChecks}
              label="Open findings"
              value={summary.findings_total.toLocaleString()}
              href={summary.drill.findings_href}
            />
            <StatTile
              icon={ListChecks}
              label="Critical + High"
              value={criticalHigh.toLocaleString()}
              tone={summary.severity.critical > 0 ? "danger" : criticalHigh > 0 ? "warn" : "ok"}
              href={summary.drill.findings_href}
            />
            <StatTile
              icon={ShieldCheck}
              label="CIS pass-rate"
              value={summary.compliance.pass_rate != null ? `${summary.compliance.pass_rate.toFixed(0)}%` : "—"}
              sub={summary.compliance.evaluated > 0 ? `${summary.compliance.evaluated} controls` : "no run yet"}
              tone={
                summary.compliance.pass_rate == null
                  ? "neutral"
                  : summary.compliance.pass_rate >= 90
                    ? "ok"
                    : summary.compliance.pass_rate >= 70
                      ? "warn"
                      : "danger"
              }
              href={summary.compliance.href}
            />
            <StatTile
              icon={Boxes}
              label="Assets"
              value={summary.assets.count.toLocaleString()}
              sub="referenced by findings"
              href={summary.assets.href}
            />
            <StatTile
              icon={KeyRound}
              label="Identities / roles"
              value={`${summary.identities.count} / ${summary.identities.roles}`}
              sub="from findings"
            />
          </div>

          {/* Engineer altitude — domain lanes with drill-in links. */}
          <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            <h2 className="mb-3 text-sm font-semibold text-[color:var(--foreground)]">Findings by security domain</h2>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
              {summary.domains.map((lane) => (
                <DomainLane key={lane.domain} lane={lane} />
              ))}
            </div>
          </section>

          <ComplianceHealth summary={summary} />

          <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold uppercase tracking-wide text-[color:var(--text-tertiary)]">Drill in</span>
              <Link
                href={summary.drill.findings_href}
                className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)]"
              >
                All findings for this account
                <ArrowRight className="h-3 w-3" />
              </Link>
              <Link
                href={summary.drill.graph_href}
                className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)]"
              >
                Open in graph
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>
            {summary.truncated ? (
              <p className="mt-2 text-[11px] text-[color:var(--status-warn)]">
                Showing a bounded sample of this account&apos;s findings. Use the findings view for the full, paged list.
              </p>
            ) : null}
          </section>
        </>
      )}
    </div>
  );
}
