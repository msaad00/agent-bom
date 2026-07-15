"use client";

import { useEffect, useMemo, useState } from "react";
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
  UserCheck,
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
import { StatStrip, type StatStripItem } from "@/components/stat-strip";
import { DataTable, type DataTableColumn, type SortDirection } from "@/components/data-table";
import { Collapsible } from "@/components/collapsible";
import { Drawer } from "@/components/drawer";
import { useChartTheme } from "@/lib/theme-colors";

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

// ─── Budget (owner-scoped) ───────────────────────────────────────────────────

function budgetScopeLabel(budget: CostReport["budget"]): string {
  if (budget.owner) {
    return budget.workflow
      ? `owner ${budget.owner} · ${budget.workflow}`
      : `owner ${budget.owner}`;
  }
  if (budget.agent) return `agent ${budget.agent}`;
  if (budget.cost_center) return `cost-center ${budget.cost_center}`;
  return "tenant-wide";
}

function BudgetPanel({ budget }: { budget: CostReport["budget"] }) {
  if (!budget?.configured) {
    return (
      <div className="flex h-full flex-col justify-center rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 text-sm text-[color:var(--text-secondary)] elev-1">
        <div className="mb-1 flex items-center gap-2 text-[color:var(--text-tertiary)]">
          <Gauge className="h-4 w-4" />
          <span className="text-[11px] font-medium uppercase tracking-[0.1em]">Budget</span>
        </div>
        No spend budget configured. Set one via{" "}
        <code className="rounded bg-[color:var(--surface-muted)] px-1.5 py-0.5 text-xs text-[color:var(--text-secondary)]">
          POST /v1/observability/costs/budget
        </code>{" "}
        to enable owner-scoped, pre-invocation enforcement at the gateway.
      </div>
    );
  }
  const util = budget.utilization ?? 0;
  const pct = Math.min(100, Math.round(util * 100));
  const enforce = budget.mode === "enforce";
  const tone = budget.exceeded ? "danger" : pct >= 80 ? "warn" : "success";
  const barVar =
    tone === "danger"
      ? "var(--status-danger)"
      : tone === "warn"
        ? "var(--status-warn)"
        : "var(--status-success)";
  return (
    <div
      className={`rounded-xl border p-4 elev-1 ${
        budget.exceeded
          ? "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)]"
          : "border-[color:var(--border-subtle)] bg-[color:var(--surface)]"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Gauge
            className="h-4 w-4"
            style={{ color: budget.exceeded ? "var(--status-danger)" : "var(--status-success)" }}
          />
          <span className="text-sm font-medium text-[color:var(--foreground)]">
            Budget · {budgetScopeLabel(budget)}
          </span>
          <span
            className={`rounded-full px-2 py-0.5 text-xs font-medium ${
              enforce
                ? "border border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]"
                : "border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]"
            }`}
          >
            {enforce ? "enforce" : "report-only"}
          </span>
          {budget.exceeded && (
            <span className="rounded-full border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-2 py-0.5 text-xs font-medium text-[color:var(--status-danger)]">
              exceeded
            </span>
          )}
        </div>
        <span className="text-sm text-[color:var(--text-secondary)]">
          {fmtUsd(budget.spend_usd)}{" "}
          {budget.limit_usd != null && <>/ {fmtUsd(budget.limit_usd)}</>}
          {budget.remaining_usd != null && (
            <span className="ml-2 text-[color:var(--text-tertiary)]">
              ({fmtUsd(Math.max(0, budget.remaining_usd))} left)
            </span>
          )}
        </span>
      </div>
      <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
        <div
          className="h-full transition-all duration-700"
          style={{ width: `${pct}%`, backgroundColor: barVar }}
        />
      </div>
    </div>
  );
}

// ─── Forecast & runway ───────────────────────────────────────────────────────

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

function toneChipClass(tone: "ok" | "warn" | "danger" | "muted"): string {
  switch (tone) {
    case "ok":
      return "border border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)] text-[color:var(--status-success)]";
    case "warn":
      return "border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] text-[color:var(--status-warn)]";
    case "danger":
      return "border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] text-[color:var(--status-danger)]";
    default:
      return "border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]";
  }
}

function ForecastPanel({ forecast }: { forecast: CostForecast | null }) {
  const status = forecast?.status ?? "insufficient_history";
  const meta = FORECAST_STATUS[status] ?? {
    label: status.replace(/_/g, " "),
    tone: "muted" as const,
  };

  const hasRate = forecast?.burn_rate_usd_per_day != null;
  const hasRunway = forecast?.days_remaining != null;
  // At-risk when a budgeted forecast projects exhaustion within 14 days.
  const atRisk =
    status === "ok" &&
    forecast?.days_remaining != null &&
    forecast.days_remaining <= 14;

  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 elev-1">
      <div className="mb-3 flex items-center gap-2">
        <CalendarClock className="h-4 w-4 text-[color:var(--accent)]" />
        <h3 className="text-sm font-semibold text-[color:var(--foreground)]">
          Forecast &amp; runway
        </h3>
        <span
          className={`rounded-full px-2 py-0.5 text-xs font-medium ${
            atRisk ? toneChipClass("warn") : toneChipClass(meta.tone)
          }`}
        >
          {atRisk ? "at risk" : meta.label}
        </span>
      </div>
      {!hasRate && !hasRunway ? (
        <p className="text-sm text-[color:var(--text-tertiary)]">
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
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <ForecastStat
              icon={Flame}
              label="Burn / day"
              value={
                forecast?.burn_rate_usd_per_day != null
                  ? fmtUsd(forecast.burn_rate_usd_per_day)
                  : "—"
              }
              hint={forecast?.burn_rate_basis?.replace(/_/g, " ")}
            />
            <ForecastStat
              icon={Gauge}
              label="Runway"
              value={
                forecast?.days_remaining != null ? fmtDays(forecast.days_remaining) : "—"
              }
              valueClass={atRisk ? "text-[color:var(--status-warn)]" : undefined}
            />
            <ForecastStat
              icon={CalendarClock}
              label="Exhaustion"
              value={
                forecast?.projected_exhaustion_at
                  ? formatDate(forecast.projected_exhaustion_at)
                  : "—"
              }
            />
            <ForecastStat
              icon={TrendingUp}
              label="Projected period"
              value={
                forecast?.projected_period_spend_usd != null
                  ? fmtUsd(forecast.projected_period_spend_usd)
                  : "—"
              }
              hint={
                forecast?.budget_limit_usd != null
                  ? `of ${fmtUsd(forecast.budget_limit_usd)} cap`
                  : undefined
              }
            />
          </div>
          <p className="mt-3 text-[11px] text-[color:var(--text-tertiary)]">
            Reference only — a forecast never blocks a call; enforcement stays at
            the gateway.
          </p>
        </>
      )}
    </div>
  );
}

function ForecastStat({
  icon: Icon,
  label,
  value,
  hint,
  valueClass,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  hint?: string | undefined;
  valueClass?: string | undefined;
}) {
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
      <div className="mb-1 flex items-center gap-1.5">
        <Icon className="h-3.5 w-3.5 text-[color:var(--text-tertiary)]" />
        <span className="text-[11px] text-[color:var(--text-tertiary)]">{label}</span>
      </div>
      <p className={`text-lg font-bold ${valueClass ?? "text-[color:var(--foreground)]"}`}>
        {value}
      </p>
      {hint ? <p className="mt-0.5 text-[11px] text-[color:var(--text-tertiary)]">{hint}</p> : null}
    </div>
  );
}

// ─── Breakdown (unified, dimension-switched) ─────────────────────────────────

type BreakdownDim = {
  key: string;
  label: string;
  noun: string;
  rows: CostBreakdownRow[];
  emptyKey: string;
  emptyHint: string;
};

type SortKey = "cost_usd" | "calls" | "key";

function BreakdownExplorer({ report }: { report: CostReport }) {
  const dims = useMemo<BreakdownDim[]>(
    () => [
      { key: "agent", label: "Agent", noun: "agent", rows: report.by_agent, emptyKey: "—", emptyHint: "" },
      { key: "model", label: "Model", noun: "model", rows: report.by_model, emptyKey: "—", emptyHint: "" },
      { key: "provider", label: "Provider", noun: "provider", rows: report.by_provider, emptyKey: "—", emptyHint: "" },
      {
        key: "owner",
        label: "Owner",
        noun: "accountable owner",
        rows: report.by_owner ?? [],
        emptyKey: "unattributed",
        emptyHint:
          "Approve a governance blueprint listing an agent to attribute its spend to the accountable owner.",
      },
      {
        key: "cost_center",
        label: "Cost center",
        noun: "cost-center",
        rows: report.by_cost_center ?? [],
        emptyKey: "unallocated",
        emptyHint:
          "Tag GenAI spans with agent.cost_center (or allocation.tag.*) to attribute spend to a budget unit.",
      },
    ],
    [report],
  );

  const [activeKey, setActiveKey] = useState("agent");
  const [sort, setSort] = useState<{ key: SortKey; direction: SortDirection }>({
    key: "cost_usd",
    direction: "desc",
  });
  const [selected, setSelected] = useState<CostBreakdownRow | null>(null);

  const active = dims.find((d) => d.key === activeKey) ?? dims[0]!;
  const total = useMemo(
    () => active.rows.reduce((sum, r) => sum + r.cost_usd, 0),
    [active],
  );

  const sortedRows = useMemo(() => {
    const rows = [...active.rows];
    rows.sort((a, b) => {
      const dir = sort.direction === "asc" ? 1 : -1;
      if (sort.key === "key") return dir * a.key.localeCompare(b.key);
      return dir * (a[sort.key] - b[sort.key]);
    });
    return rows;
  }, [active, sort]);

  const cycleSort = (key: string) => {
    setSort((prev) =>
      prev.key === key
        ? { key: key as SortKey, direction: prev.direction === "asc" ? "desc" : "asc" }
        : { key: key as SortKey, direction: key === "key" ? "asc" : "desc" },
    );
  };

  const columns: DataTableColumn<CostBreakdownRow>[] = [
    {
      key: "key",
      header: active.label,
      sortable: true,
      cell: (r) => (
        <span className="font-mono text-xs text-[color:var(--text-secondary)]">
          {r.key || active.emptyKey}
        </span>
      ),
    },
    {
      key: "calls",
      header: "Calls",
      align: "right",
      sortable: true,
      cell: (r) => fmtInt(r.calls),
    },
    {
      key: "tokens",
      header: "Tokens (in/out)",
      align: "right",
      cell: (r) => (
        <span className="text-[color:var(--text-tertiary)]">
          {fmtInt(r.input_tokens)} / {fmtInt(r.output_tokens)}
        </span>
      ),
    },
    {
      key: "share",
      header: "Share",
      align: "right",
      cell: (r) => (
        <span className="text-[color:var(--text-tertiary)]">
          {(total > 0 ? (r.cost_usd / total) * 100 : 0).toFixed(1)}%
        </span>
      ),
    },
    {
      key: "cost_usd",
      header: "Cost",
      align: "right",
      sortable: true,
      cell: (r) => (
        <span className="font-medium text-[color:var(--foreground)]">{fmtUsd(r.cost_usd)}</span>
      ),
    },
  ];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-[color:var(--foreground)]">Cost breakdown</h3>
        <div className="flex flex-wrap items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5">
          {dims.map((dim) => (
            <button
              key={dim.key}
              type="button"
              onClick={() => {
                setActiveKey(dim.key);
                setSelected(null);
              }}
              className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                dim.key === activeKey
                  ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                  : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
              }`}
            >
              {dim.label}
            </button>
          ))}
        </div>
      </div>

      <DataTable
        rows={sortedRows}
        rowKey={(r) => r.key || active.emptyKey}
        columns={columns}
        selectedKey={selected ? selected.key || active.emptyKey : undefined}
        onRowClick={setSelected}
        sort={sort}
        onSortChange={cycleSort}
        maxHeight="26rem"
        caption={`Spend by ${active.noun}`}
        empty={
          active.emptyHint || `No spend recorded by ${active.noun} yet.`
        }
        data-testid="cost-breakdown-table"
      />

      <Drawer
        open={selected != null}
        onClose={() => setSelected(null)}
        eyebrow={`Spend by ${active.label}`}
        title={selected?.key || active.emptyKey}
        size="lg"
        ariaLabel="Cost breakdown detail"
      >
        {selected ? (
          <div className="space-y-4">
            <StatStrip
              items={[
                { label: "Cost", value: fmtUsd(selected.cost_usd), accent: "success" },
                {
                  label: "Share",
                  value: `${(total > 0 ? (selected.cost_usd / total) * 100 : 0).toFixed(1)}%`,
                },
                { label: "Calls", value: fmtInt(selected.calls) },
              ]}
            />
            <dl className="grid grid-cols-2 gap-3 text-sm">
              <DetailStat label="Input tokens" value={fmtInt(selected.input_tokens)} />
              <DetailStat label="Output tokens" value={fmtInt(selected.output_tokens)} />
              <DetailStat
                label="Unpriced calls"
                value={fmtInt(selected.unpriced_calls)}
                warn={selected.unpriced_calls > 0}
              />
              <DetailStat
                label="Avg cost / call"
                value={fmtUsd(selected.calls > 0 ? selected.cost_usd / selected.calls : 0)}
              />
            </dl>
            {selected.unpriced_calls > 0 ? (
              <p className="rounded-lg border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] px-3 py-2 text-xs text-[color:var(--text-secondary)]">
                {fmtInt(selected.unpriced_calls)} call
                {selected.unpriced_calls === 1 ? "" : "s"} lacked a captured price model, so real
                spend for this {active.noun} may be higher.
              </p>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}

function DetailStat({
  label,
  value,
  warn,
}: {
  label: string;
  value: string;
  warn?: boolean;
}) {
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
      <dt className="text-[11px] uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">
        {label}
      </dt>
      <dd
        className={`mt-1 font-mono text-base font-semibold ${
          warn ? "text-[color:var(--status-warn)]" : "text-[color:var(--foreground)]"
        }`}
      >
        {value}
      </dd>
    </div>
  );
}

// ─── Anomalies ───────────────────────────────────────────────────────────────

function AnomalyRow({ a }: { a: CostAnomaly }) {
  const high = a.severity === "high";
  return (
    <div
      className={`rounded-lg border p-3 ${
        high
          ? "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)]"
          : "border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)]"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert
            className="h-4 w-4"
            style={{ color: high ? "var(--status-danger)" : "var(--status-warn)" }}
          />
          <span className="text-sm font-medium text-[color:var(--foreground)]">
            {a.type.replace(/_/g, " ")}
          </span>
          <span className="font-mono text-xs text-[color:var(--text-tertiary)]">
            {a.agent ?? a.session_id ?? ""}
          </span>
        </div>
        <span className="font-mono text-xs text-[color:var(--text-secondary)]">
          z={a.z_score.toFixed(1)}
        </span>
      </div>
      <p className="mt-1 text-xs text-[color:var(--text-secondary)]">
        {a.metric} ={" "}
        {typeof a.value === "number" ? a.value.toLocaleString() : a.value} vs
        baseline {a.baseline_median.toLocaleString()} — {a.recommendation}
      </p>
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function CostPage() {
  const { counts } = useDeploymentContext();
  const aiSpendService = serviceEntry(counts?.services, "ai_spend");
  const chart = useChartTheme();
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

  const kpis: StatStripItem[] = [
    { label: "Total spend", value: fmtUsd(report.total_cost_usd), icon: DollarSign, accent: "success" },
    { label: "LLM calls", value: fmtInt(report.total_calls), icon: Activity },
    { label: "Input tokens", value: fmtInt(report.total_input_tokens), icon: ArrowDownToLine },
    { label: "Output tokens", value: fmtInt(report.total_output_tokens), icon: ArrowUpFromLine },
    {
      label: "Unpriced calls",
      value: fmtInt(report.unpriced_calls),
      icon: AlertTriangle,
      accent: "warn",
      accentThreshold: 0,
      hint: report.unpriced_calls > 0 ? "spend may be understated" : undefined,
    },
  ];

  return (
    <div className="space-y-5">
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

      <StatStrip items={kpis} data-testid="cost-kpi-strip" />

      <div className="grid gap-4 lg:grid-cols-2">
        <BudgetPanel budget={report.budget} />
        <ForecastPanel forecast={forecast} />
      </div>

      {!hasData ? (
        <PageEmptyState
          title="No cost telemetry yet"
          detail="Cost records appear once agents make priced LLM calls through the proxy or report usage to the cost store."
          icon={DollarSign}
          data-testid="cost-empty-state"
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 elev-1">
            <BreakdownExplorer report={report} />
          </div>
          <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 elev-1">
            <div className="mb-3 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-[color:var(--accent)]" />
              <h3 className="text-sm font-semibold text-[color:var(--foreground)]">
                Spend by agent (top 10)
              </h3>
            </div>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={agentChart}
                margin={{ top: 8, right: 8, bottom: 8, left: 8 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke={chart.grid} />
                <XAxis dataKey="name" stroke={chart.text} tick={{ fontSize: 11 }} />
                <YAxis
                  stroke={chart.text}
                  tick={{ fontSize: 11 }}
                  tickFormatter={(v) => `$${v}`}
                />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--surface-muted)" }} />
                <Bar dataKey="cost" radius={[6, 6, 0, 0]}>
                  {agentChart.map((_, i) => (
                    <Cell key={i} fill={chart.accent} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <Collapsible
        title="Cost & behavior anomalies"
        subtitle="Statistical outliers across cost and call-rate baselines"
        icon={ShieldAlert}
        count={anomalyCount}
        defaultOpen={anomalyCount > 0}
        data-testid="cost-anomalies"
      >
        {anomalyCount === 0 ? (
          <p className="text-sm text-[color:var(--text-tertiary)]">
            No statistical anomalies detected across cost or call-rate baselines.
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
      </Collapsible>

      {hasData && report.by_owner && report.by_owner.length > 0 ? (
        <p className="flex items-center gap-1.5 text-[11px] text-[color:var(--text-tertiary)]">
          <UserCheck className="h-3.5 w-3.5" />
          Owner rollup attributes each agent&apos;s spend to the accountable owner from its governing blueprint. Switch the breakdown to <span className="font-medium text-[color:var(--text-secondary)]">Owner</span> to review chargeback.
        </p>
      ) : null}
    </div>
  );
}
