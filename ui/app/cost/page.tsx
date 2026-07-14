"use client";

import { useEffect, useState } from "react";
import {
  DollarSign,
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  AlertTriangle,
  TrendingUp,
  ShieldAlert,
  Gauge,
  Flame,
  CalendarClock,
  Building2,
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
} from "recharts";
import { api, formatDate } from "@/lib/api";
import type {
  CostReport,
  AnomaliesReport,
  CostBreakdownRow,
  CostAnomaly,
  CostForecast,
} from "@/lib/api-types";
import {
  PageLoadingState,
  PageEmptyState,
} from "@/components/states/page-state";
import {
  ApiOfflineState,
  type ApiOfflineKind,
} from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { ChartTooltip } from "@/components/charts";
import { PageLaneHeader } from "@/components/page-lane";
import { ServiceStateBanner, ServiceStateChip } from "@/components/service-state-chip";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { serviceEntry } from "@/lib/service-registry";

function classifyApiErrorKind(err: unknown): ApiOfflineKind {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

const fmtUsd = (n: number) =>
  n >= 1
    ? `$${n.toLocaleString(undefined, { maximumFractionDigits: 2 })}`
    : `$${n.toFixed(4)}`;
const fmtInt = (n: number) => n.toLocaleString();

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
      <div className="mb-1 flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-xs text-[var(--text-tertiary)]">{label}</span>
      </div>
      <p className="text-2xl font-bold text-[var(--foreground)]">{value}</p>
    </div>
  );
}

function BudgetBanner({ budget }: { budget: CostReport["budget"] }) {
  if (!budget?.configured) {
    return (
      <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-4 text-sm text-[var(--text-secondary)]">
        No spend budget configured for this tenant. Set one via{" "}
        <code className="rounded bg-[var(--surface-elevated)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">
          POST /v1/observability/costs/budget
        </code>{" "}
        to enable pre-invocation enforcement at the gateway.
      </div>
    );
  }
  const util = budget.utilization ?? 0;
  const pct = Math.min(100, Math.round(util * 100));
  const enforce = budget.mode === "enforce";
  const barColor = budget.exceeded
    ? "bg-red-500"
    : pct >= 80
      ? "bg-amber-500"
      : "bg-emerald-500";
  return (
    <div
      className={`rounded-xl border p-4 ${
        budget.exceeded
          ? "border-red-800/60 bg-red-950/20"
          : "border-[var(--border-subtle)] bg-[var(--surface)]/40"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Gauge
            className={`h-4 w-4 ${budget.exceeded ? "text-red-400" : "text-emerald-400"}`}
          />
          <span className="text-sm font-medium text-[var(--foreground)]">
            Budget {budget.agent ? `· agent ${budget.agent}` : "· tenant-wide"}
          </span>
          <span
            className={`rounded-full px-2 py-0.5 text-xs font-medium ${
              enforce
                ? "bg-emerald-900/60 text-emerald-300"
                : "bg-[var(--surface-elevated)] text-[var(--text-secondary)]"
            }`}
          >
            {enforce ? "enforce" : "report-only"}
          </span>
          {budget.exceeded && (
            <span className="rounded-full bg-red-900/60 px-2 py-0.5 text-xs font-medium text-red-300">
              exceeded
            </span>
          )}
        </div>
        <span className="text-sm text-[var(--text-secondary)]">
          {fmtUsd(budget.spend_usd)}{" "}
          {budget.limit_usd != null && <>/ {fmtUsd(budget.limit_usd)}</>}
          {budget.remaining_usd != null && (
            <span className="ml-2 text-[var(--text-tertiary)]">
              ({fmtUsd(Math.max(0, budget.remaining_usd))} left)
            </span>
          )}
        </span>
      </div>
      <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-[var(--surface-elevated)]">
        <div
          className={`h-full ${barColor} transition-all duration-700`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function BreakdownTable({
  title,
  rows,
}: {
  title: string;
  rows: CostBreakdownRow[];
}) {
  const top = [...rows].sort((a, b) => b.cost_usd - a.cost_usd).slice(0, 12);
  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
      <h3 className="mb-3 text-sm font-semibold text-[var(--text-secondary)]">{title}</h3>
      {top.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">No cost records yet.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border-subtle)] text-left text-xs text-[var(--text-tertiary)]">
              <th className="pb-2 font-medium">Name</th>
              <th className="pb-2 text-right font-medium">Calls</th>
              <th className="pb-2 text-right font-medium">Tokens (in/out)</th>
              <th className="pb-2 text-right font-medium">Cost</th>
            </tr>
          </thead>
          <tbody>
            {top.map((r) => (
              <tr
                key={r.key}
                className="border-b border-[var(--border-subtle)] last:border-0"
              >
                <td className="py-2 font-mono text-xs text-[var(--text-secondary)]">
                  {r.key || "—"}
                </td>
                <td className="py-2 text-right text-[var(--text-secondary)]">
                  {fmtInt(r.calls)}
                </td>
                <td className="py-2 text-right text-[var(--text-tertiary)]">
                  {fmtInt(r.input_tokens)} / {fmtInt(r.output_tokens)}
                </td>
                <td className="py-2 text-right font-medium text-[var(--foreground)]">
                  {fmtUsd(r.cost_usd)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

const FORECAST_STATUS: Record<
  string,
  { label: string; tone: "ok" | "warn" | "danger" | "muted" }
> = {
  ok: { label: "on track", tone: "ok" },
  no_budget: { label: "no budget", tone: "muted" },
  budget_exceeded: { label: "exceeded", tone: "danger" },
  stale: { label: "stale", tone: "muted" },
  insufficient_history: { label: "insufficient history", tone: "muted" },
};

function fmtDays(n: number): string {
  if (n >= 365) return `${(n / 365).toFixed(1)}y`;
  if (n >= 1) return `${Math.round(n)}d`;
  return `${(n * 24).toFixed(1)}h`;
}

function ForecastPanel({ forecast }: { forecast: CostForecast | null }) {
  const status = forecast?.status ?? "insufficient_history";
  const meta = FORECAST_STATUS[status] ?? {
    label: status.replace(/_/g, " "),
    tone: "muted" as const,
  };
  const toneClass = {
    ok: "bg-emerald-900/60 text-emerald-300",
    warn: "bg-amber-900/60 text-amber-300",
    danger: "bg-red-900/60 text-red-300",
    muted: "bg-[var(--surface-elevated)] text-[var(--text-secondary)]",
  }[meta.tone];

  const hasRate = forecast?.burn_rate_usd_per_day != null;
  const hasRunway = forecast?.days_remaining != null;
  // At-risk when a budgeted forecast projects exhaustion within 14 days.
  const atRisk =
    status === "ok" &&
    forecast?.days_remaining != null &&
    forecast.days_remaining <= 14;

  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
      <div className="mb-3 flex items-center gap-2">
        <CalendarClock className="h-4 w-4 text-sky-400" />
        <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
          Forecast &amp; runway
        </h3>
        <span
          className={`rounded-full px-2 py-0.5 text-xs font-medium ${atRisk ? "bg-amber-900/60 text-amber-300" : toneClass}`}
        >
          {atRisk ? "at risk" : meta.label}
        </span>
      </div>
      {!hasRate && !hasRunway ? (
        <p className="text-sm text-[var(--text-tertiary)]">
          {status === "insufficient_history"
            ? "Not enough timestamped spend yet to project a burn rate. A forecast appears once at least two priced LLM calls are recorded."
            : status === "no_budget"
              ? "A burn rate is available, but no spend budget is configured — there is nothing to project a runway against."
              : status === "stale"
                ? "Recorded spend falls outside the trailing windows, so no current burn rate can be derived."
                : "No forecast data available."}
        </p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
              <div className="mb-1 flex items-center gap-1.5">
                <Flame className="h-3.5 w-3.5 text-orange-400" />
                <span className="text-xs text-[var(--text-tertiary)]">Burn / day</span>
              </div>
              <p className="text-lg font-bold text-[var(--foreground)]">
                {forecast?.burn_rate_usd_per_day != null
                  ? fmtUsd(forecast.burn_rate_usd_per_day)
                  : "—"}
              </p>
              {forecast?.burn_rate_basis && (
                <p className="mt-0.5 text-[11px] text-[var(--text-tertiary)]">
                  {forecast.burn_rate_basis.replace(/_/g, " ")}
                </p>
              )}
            </div>
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
              <div className="mb-1 flex items-center gap-1.5">
                <Gauge className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
                <span className="text-xs text-[var(--text-tertiary)]">Runway</span>
              </div>
              <p
                className={`text-lg font-bold ${atRisk ? "text-amber-300" : "text-[var(--foreground)]"}`}
              >
                {forecast?.days_remaining != null
                  ? fmtDays(forecast.days_remaining)
                  : "—"}
              </p>
            </div>
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
              <div className="mb-1 flex items-center gap-1.5">
                <CalendarClock className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
                <span className="text-xs text-[var(--text-tertiary)]">Exhaustion</span>
              </div>
              <p className="text-sm font-medium text-[var(--foreground)]">
                {forecast?.projected_exhaustion_at
                  ? formatDate(forecast.projected_exhaustion_at)
                  : "—"}
              </p>
            </div>
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
              <div className="mb-1 flex items-center gap-1.5">
                <TrendingUp className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
                <span className="text-xs text-[var(--text-tertiary)]">Projected period</span>
              </div>
              <p className="text-sm font-medium text-[var(--foreground)]">
                {forecast?.projected_period_spend_usd != null
                  ? fmtUsd(forecast.projected_period_spend_usd)
                  : "—"}
              </p>
              {forecast?.budget_limit_usd != null && (
                <p className="mt-0.5 text-[11px] text-[var(--text-tertiary)]">
                  of {fmtUsd(forecast.budget_limit_usd)} cap
                </p>
              )}
            </div>
          </div>
          <p className="mt-3 text-[11px] text-[var(--text-tertiary)]">
            Reference only — a forecast never blocks a call; enforcement stays at
            the gateway.
          </p>
        </>
      )}
    </div>
  );
}

function ChargebackPanel({ rows }: { rows: CostBreakdownRow[] }) {
  const top = [...rows].sort((a, b) => b.cost_usd - a.cost_usd).slice(0, 12);
  const total = rows.reduce((sum, r) => sum + r.cost_usd, 0);
  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
      <div className="mb-3 flex items-center gap-2">
        <Building2 className="h-4 w-4 text-violet-400" />
        <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
          Chargeback by cost-center
        </h3>
      </div>
      {top.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">
          No chargeback allocation recorded. Tag GenAI spans with{" "}
          <code className="rounded bg-[var(--surface-elevated)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">
            agent.cost_center
          </code>{" "}
          (or <code className="text-[var(--text-secondary)]">allocation.tag.*</code>) to attribute
          spend to a budget unit.
        </p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border-subtle)] text-left text-xs text-[var(--text-tertiary)]">
              <th className="pb-2 font-medium">Cost center</th>
              <th className="pb-2 text-right font-medium">Calls</th>
              <th className="pb-2 text-right font-medium">Share</th>
              <th className="pb-2 text-right font-medium">Cost</th>
            </tr>
          </thead>
          <tbody>
            {top.map((r) => {
              const share = total > 0 ? r.cost_usd / total : 0;
              return (
                <tr
                  key={r.key}
                  className="border-b border-[var(--border-subtle)] last:border-0"
                >
                  <td className="py-2 font-mono text-xs text-[var(--text-secondary)]">
                    {r.key || "unallocated"}
                  </td>
                  <td className="py-2 text-right text-[var(--text-secondary)]">
                    {fmtInt(r.calls)}
                  </td>
                  <td className="py-2 text-right text-[var(--text-tertiary)]">
                    {(share * 100).toFixed(1)}%
                  </td>
                  <td className="py-2 text-right font-medium text-[var(--foreground)]">
                    {fmtUsd(r.cost_usd)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function AnomalyRow({ a }: { a: CostAnomaly }) {
  const high = a.severity === "high";
  return (
    <div
      className={`rounded-lg border p-3 ${
        high
          ? "border-red-800/50 bg-red-950/20"
          : "border-amber-800/40 bg-amber-950/10"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert
            className={`h-4 w-4 ${high ? "text-red-400" : "text-amber-400"}`}
          />
          <span className="text-sm font-medium text-[var(--foreground)]">
            {a.type.replace(/_/g, " ")}
          </span>
          <span className="font-mono text-xs text-[var(--text-tertiary)]">
            {a.agent ?? a.session_id ?? ""}
          </span>
        </div>
        <span className="font-mono text-xs text-[var(--text-secondary)]">
          z={a.z_score.toFixed(1)}
        </span>
      </div>
      <p className="mt-1 text-xs text-[var(--text-secondary)]">
        {a.metric} ={" "}
        {typeof a.value === "number" ? a.value.toLocaleString() : a.value} vs
        baseline {a.baseline_median.toLocaleString()} — {a.recommendation}
      </p>
    </div>
  );
}

export default function CostPage() {
  const { counts } = useDeploymentContext();
  const aiSpendService = serviceEntry(counts?.services, "ai_spend");
  const [report, setReport] = useState<CostReport | null>(null);
  const [anomalies, setAnomalies] = useState<AnomaliesReport | null>(null);
  const [forecast, setForecast] = useState<CostForecast | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<ApiOfflineKind>("network");

  useEffect(() => {
    void Promise.allSettled([
      api.getCostReport(),
      api.getCostAnomalies(),
      api.getCostForecast(),
    ])
      .then(([reportResult, anomalyResult, forecastResult]) => {
        if (reportResult.status === "fulfilled") {
          setReport(reportResult.value);
        } else {
          setError(
            reportResult.reason?.message ?? "Failed to load cost report",
          );
          setErrorKind(classifyApiErrorKind(reportResult.reason));
        }
        if (anomalyResult.status === "fulfilled")
          setAnomalies(anomalyResult.value);
        // Prefer the dedicated forecast endpoint; fall back to the block
        // embedded on the cost report so the panel still renders if the
        // standalone call is unavailable.
        if (forecastResult.status === "fulfilled") {
          setForecast(forecastResult.value);
        } else if (
          reportResult.status === "fulfilled" &&
          reportResult.value.forecast
        ) {
          setForecast(reportResult.value.forecast);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading)
    return (
      <PageLoadingState
        title="Loading cost analysis"
        detail="Aggregating LLM spend across agents, models, and providers."
      />
    );
  if (error)
    return (
      <ApiOfflineState
        title="Cost data unavailable"
        detail={error}
        kind={errorKind}
      />
    );
  if (!report) return null;

  const hasData = report.total_calls > 0;
  const agentChart = [...report.by_agent]
    .sort((a, b) => b.cost_usd - a.cost_usd)
    .slice(0, 10)
    .map((r) => ({ name: r.key || "—", cost: Number(r.cost_usd.toFixed(4)) }));
  const anomalyCount = anomalies?.anomaly_count ?? 0;

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="operations"
        title="AI Spend"
        subtitle="Model and token cost from proxy/gateway usage — not cloud infrastructure billing."
        actions={
          <ServiceStateChip
            serviceId="ai_spend"
            entry={aiSpendService}
            registry={counts?.services}
          />
        }
      />

      <ServiceStateBanner
        serviceId="ai_spend"
        entry={aiSpendService}
        registry={counts?.services}
      />

      <BudgetBanner budget={report.budget} />

      <ForecastPanel forecast={forecast} />

      {!hasData ? (
        <PageEmptyState
          title="No cost telemetry yet"
          detail="Cost records appear once agents make priced LLM calls through the proxy or report usage to the cost store."
          icon={DollarSign}
        />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            <StatCard
              icon={DollarSign}
              label="Total spend"
              value={fmtUsd(report.total_cost_usd)}
              color="text-emerald-400"
            />
            <StatCard
              icon={Activity}
              label="LLM calls"
              value={fmtInt(report.total_calls)}
              color="text-blue-400"
            />
            <StatCard
              icon={ArrowDownToLine}
              label="Input tokens"
              value={fmtInt(report.total_input_tokens)}
              color="text-[var(--text-secondary)]"
            />
            <StatCard
              icon={ArrowUpFromLine}
              label="Output tokens"
              value={fmtInt(report.total_output_tokens)}
              color="text-[var(--text-secondary)]"
            />
            <StatCard
              icon={AlertTriangle}
              label="Unpriced calls"
              value={fmtInt(report.unpriced_calls)}
              color={
                report.unpriced_calls > 0 ? "text-amber-400" : "text-[var(--text-secondary)]"
              }
            />
          </div>

          <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
            <div className="mb-3 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
                Spend by agent (top 10)
              </h3>
            </div>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart
                data={agentChart}
                margin={{ top: 8, right: 8, bottom: 8, left: 8 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                <XAxis
                  dataKey="name"
                  stroke="#71717a"
                  tick={{ fontSize: 11 }}
                />
                <YAxis
                  stroke="#71717a"
                  tick={{ fontSize: 11 }}
                  tickFormatter={(v) => `$${v}`}
                />
                <Tooltip
                  content={<ChartTooltip />}
                  cursor={{ fill: "#ffffff08" }}
                />
                <Bar dataKey="cost" radius={[6, 6, 0, 0]}>
                  {agentChart.map((_, i) => (
                    <Cell key={i} fill="#34d399" />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <BreakdownTable title="By model" rows={report.by_model} />
            <BreakdownTable title="By provider" rows={report.by_provider} />
          </div>

          <ChargebackPanel rows={report.by_cost_center ?? []} />
        </>
      )}

      <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
        <div className="mb-3 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-amber-400" />
          <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
            Cost & behavior anomalies
          </h3>
          {anomalyCount > 0 && (
            <span className="rounded-full bg-amber-900/60 px-2 py-0.5 text-xs font-medium text-amber-300">
              {anomalyCount}
            </span>
          )}
        </div>
        {anomalyCount === 0 ? (
          <p className="text-sm text-[var(--text-tertiary)]">
            No statistical anomalies detected across cost or call-rate
            baselines.
          </p>
        ) : (
          <div className="space-y-2">
            {anomalies?.cost_anomalies.map((a, i) => (
              <AnomalyRow key={`c${i}`} a={a} />
            ))}
            {anomalies?.behavior_anomalies.map((a, i) => (
              <AnomalyRow key={`b${i}`} a={a} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
