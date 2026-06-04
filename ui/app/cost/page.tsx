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
import { api } from "@/lib/api";
import type {
  CostReport,
  AnomaliesReport,
  CostBreakdownRow,
  CostAnomaly,
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
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="mb-1 flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-xs text-zinc-500">{label}</span>
      </div>
      <p className="text-2xl font-bold text-zinc-100">{value}</p>
    </div>
  );
}

function BudgetBanner({ budget }: { budget: CostReport["budget"] }) {
  if (!budget?.configured) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 text-sm text-zinc-400">
        No spend budget configured for this tenant. Set one via{" "}
        <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-300">
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
          : "border-zinc-800 bg-zinc-900/40"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Gauge
            className={`h-4 w-4 ${budget.exceeded ? "text-red-400" : "text-emerald-400"}`}
          />
          <span className="text-sm font-medium text-zinc-200">
            Budget {budget.agent ? `· agent ${budget.agent}` : "· tenant-wide"}
          </span>
          <span
            className={`rounded-full px-2 py-0.5 text-xs font-medium ${
              enforce
                ? "bg-emerald-900/60 text-emerald-300"
                : "bg-zinc-800 text-zinc-400"
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
        <span className="text-sm text-zinc-400">
          {fmtUsd(budget.spend_usd)}{" "}
          {budget.limit_usd != null && <>/ {fmtUsd(budget.limit_usd)}</>}
          {budget.remaining_usd != null && (
            <span className="ml-2 text-zinc-500">
              ({fmtUsd(Math.max(0, budget.remaining_usd))} left)
            </span>
          )}
        </span>
      </div>
      <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-zinc-800">
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
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
      <h3 className="mb-3 text-sm font-semibold text-zinc-300">{title}</h3>
      {top.length === 0 ? (
        <p className="text-sm text-zinc-500">No cost records yet.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 text-left text-xs text-zinc-500">
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
                className="border-b border-zinc-900 last:border-0"
              >
                <td className="py-2 font-mono text-xs text-zinc-300">
                  {r.key || "—"}
                </td>
                <td className="py-2 text-right text-zinc-400">
                  {fmtInt(r.calls)}
                </td>
                <td className="py-2 text-right text-zinc-500">
                  {fmtInt(r.input_tokens)} / {fmtInt(r.output_tokens)}
                </td>
                <td className="py-2 text-right font-medium text-zinc-200">
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
          <span className="text-sm font-medium text-zinc-200">
            {a.type.replace(/_/g, " ")}
          </span>
          <span className="font-mono text-xs text-zinc-500">
            {a.agent ?? a.session_id ?? ""}
          </span>
        </div>
        <span className="font-mono text-xs text-zinc-400">
          z={a.z_score.toFixed(1)}
        </span>
      </div>
      <p className="mt-1 text-xs text-zinc-400">
        {a.metric} ={" "}
        {typeof a.value === "number" ? a.value.toLocaleString() : a.value} vs
        baseline {a.baseline_median.toLocaleString()} — {a.recommendation}
      </p>
    </div>
  );
}

export default function CostPage() {
  const [report, setReport] = useState<CostReport | null>(null);
  const [anomalies, setAnomalies] = useState<AnomaliesReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<ApiOfflineKind>("network");

  useEffect(() => {
    void Promise.allSettled([api.getCostReport(), api.getCostAnomalies()])
      .then(([reportResult, anomalyResult]) => {
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
      <div className="flex items-center gap-2">
        <DollarSign className="h-6 w-6 text-emerald-400" />
        <div>
          <h1 className="text-2xl font-semibold text-zinc-100">Cost</h1>
          <p className="text-sm text-zinc-500">
            LLM spend, per-agent attribution, and budget enforcement posture.
          </p>
        </div>
      </div>

      <BudgetBanner budget={report.budget} />

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
              color="text-zinc-400"
            />
            <StatCard
              icon={ArrowUpFromLine}
              label="Output tokens"
              value={fmtInt(report.total_output_tokens)}
              color="text-zinc-400"
            />
            <StatCard
              icon={AlertTriangle}
              label="Unpriced calls"
              value={fmtInt(report.unpriced_calls)}
              color={
                report.unpriced_calls > 0 ? "text-amber-400" : "text-zinc-400"
              }
            />
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
            <div className="mb-3 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-zinc-300">
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
        </>
      )}

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
        <div className="mb-3 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-amber-400" />
          <h3 className="text-sm font-semibold text-zinc-300">
            Cost & behavior anomalies
          </h3>
          {anomalyCount > 0 && (
            <span className="rounded-full bg-amber-900/60 px-2 py-0.5 text-xs font-medium text-amber-300">
              {anomalyCount}
            </span>
          )}
        </div>
        {anomalyCount === 0 ? (
          <p className="text-sm text-zinc-500">
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
