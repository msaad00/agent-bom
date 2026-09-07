"use client";

import { useEffect, useState } from "react";
import { api, type GatewayFeedKpis } from "@/lib/api";
import { producerEvidenceLabel, PRODUCER_EVIDENCE_HINT } from "@/lib/gateway-feed";

/** Format a KPI count; absent fields render an em dash instead of crashing. */
export function fmtCount(value: number | undefined | null): string {
  return typeof value === "number" ? value.toLocaleString() : "—";
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

function KpiCard({
  label,
  value,
  color,
  hint,
}: {
  label: string;
  value: string;
  color: string;
  hint?: string;
}) {
  return (
    <div
      className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 shadow-sm"
      title={hint}
    >
      <span className={`mb-2 block h-2 w-2 rounded-full ${color}`} aria-hidden="true" />
      <div className="font-mono text-2xl font-bold text-[color:var(--foreground)]">{value}</div>
      <div className="mt-0.5 text-xs text-[color:var(--text-secondary)]">{label}</div>
    </div>
  );
}

/** Runtime rollup visible on every gateway tab, not only Live Feed. */
export function GatewayFeedKpiBar({ refreshKey = 0 }: { refreshKey?: number }) {
  const [kpis, setKpis] = useState<GatewayFeedKpis | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "unavailable">("loading");

  useEffect(() => {
    let cancelled = false;
    void api.getGatewayFeedKpis().then(
      (value) => {
        if (!cancelled) {
          setKpis(value);
          setLoadState("ready");
        }
      },
      () => {
        if (!cancelled) setLoadState("unavailable");
      },
    );
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--text-secondary)]" role="status">
        {loadState !== "ready" ? (
          <span>
            {loadState === "loading"
              ? "Loading activity summary…"
              : kpis
                ? "Activity refresh unavailable; showing last summary"
                : "Activity summary unavailable"}
          </span>
        ) : null}
        {kpis ? <>
          <span title={PRODUCER_EVIDENCE_HINT}>{producerEvidenceLabel(kpis.producer_assurance)}</span>
          <span title={kpis.completeness?.reasons?.join(", ")}>
            {kpis.completeness?.status === "partial" || kpis.window?.exact === false
              ? "Partial retained window"
              : kpis.completeness?.status === "complete" && kpis.window?.exact === true
                ? "Complete retained window"
                : "Window scope unavailable"}
            {kpis.window ? ` · ${kpis.window.timezone}` : ""}
          </span>
          {kpis.window ? <span>{formatWindow(kpis.window.start)} – {formatWindow(kpis.window.end)}</span> : null}
        </> : null}
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
        <KpiCard label="Calls today" value={fmtCount(kpis?.calls_today)} color="bg-emerald-400" />
        <KpiCard label="Blocked today" value={fmtCount(kpis?.blocked_today)} color="bg-red-400" />
        <KpiCard
          label="Shadow AI blocked"
          value={fmtCount(kpis?.shadow_ai_blocked)}
          color="bg-orange-400"
          hint="undeclared agents and shadow MCP servers"
        />
        <KpiCard
          label="Data filters"
          value={fmtCount(kpis?.data_filters_applied)}
          color="bg-amber-400"
        />
        {kpis?.uptime_seconds != null && (
          <KpiCard
            label="Reported uptime"
            value={formatUptime(kpis.uptime_seconds)}
            color="bg-[color:var(--text-secondary)]"
          />
        )}
      </div>
    </div>
  );
}

function formatWindow(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isFinite(date.getTime())
    ? date.toLocaleString(undefined, { timeZone: "UTC", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false })
    : "Unavailable";
}
