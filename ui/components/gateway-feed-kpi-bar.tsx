"use client";

import { useEffect, useState } from "react";
import { Activity, Ban, Bot, EyeOff, Zap } from "lucide-react";
import { api, type GatewayFeedKpis } from "@/lib/api";

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
  icon: Icon,
  color,
  hint,
}: {
  label: string;
  value: string;
  icon: React.ElementType;
  color: string;
  hint?: string;
}) {
  return (
    <div
      className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 shadow-sm"
      title={hint}
    >
      <Icon className={`mb-2 h-4 w-4 ${color}`} />
      <div className="font-mono text-2xl font-bold text-[color:var(--foreground)]">{value}</div>
      <div className="mt-0.5 text-xs text-[color:var(--text-secondary)]">{label}</div>
    </div>
  );
}

/** Natoma-style runtime rollup — visible on every gateway tab, not only Live Feed. */
export function GatewayFeedKpiBar({ refreshKey = 0 }: { refreshKey?: number }) {
  const [kpis, setKpis] = useState<GatewayFeedKpis | null>(null);

  useEffect(() => {
    let cancelled = false;
    void api.getGatewayFeedKpis().then(
      (value) => {
        if (!cancelled) setKpis(value);
      },
      () => {
        if (!cancelled) setKpis(null);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
      <KpiCard label="Calls today" value={fmtCount(kpis?.calls_today)} icon={Zap} color="text-emerald-400" />
      <KpiCard label="Blocked today" value={fmtCount(kpis?.blocked_today)} icon={Ban} color="text-red-400" />
      <KpiCard
        label="Shadow AI blocked"
        value={fmtCount(kpis?.shadow_ai_blocked)}
        icon={Bot}
        color="text-orange-400"
        hint="undeclared agents and shadow MCP servers"
      />
      <KpiCard
        label="Data filters"
        value={fmtCount(kpis?.data_filters_applied)}
        icon={EyeOff}
        color="text-amber-400"
      />
      {kpis?.uptime_seconds != null && (
        <KpiCard
          label="Gateway uptime"
          value={formatUptime(kpis.uptime_seconds)}
          icon={Activity}
          color="text-[color:var(--text-secondary)]"
        />
      )}
    </div>
  );
}
