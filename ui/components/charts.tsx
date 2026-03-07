"use client";

import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

// ─── Shared ──────────────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
} as const;

const CHART_THEME = {
  bg: "#18181b",
  border: "#27272a",
  grid: "#27272a",
  text: "#71717a",
  tooltip: {
    bg: "#09090b",
    border: "#27272a",
    text: "#e4e4e7",
  },
} as const;

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-lg border px-3 py-2 text-xs shadow-xl"
      style={{
        background: CHART_THEME.tooltip.bg,
        borderColor: CHART_THEME.tooltip.border,
      }}
    >
      {label && (
        <div className="text-zinc-500 mb-1 font-mono text-[10px]">{label}</div>
      )}
      {payload.map((entry) => (
        <div
          key={entry.name}
          className="flex items-center gap-2"
          style={{ color: CHART_THEME.tooltip.text }}
        >
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: entry.color }}
          />
          <span className="capitalize">{entry.name}</span>
          <span className="font-mono font-semibold ml-auto">{entry.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Vulnerability Trend (area chart) ────────────────────────────────────────

export interface TrendDataPoint {
  label: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export function VulnTrendChart({ data }: { data: TrendDataPoint[] }) {
  if (data.length < 2) return null;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-4">
        Vulnerability Trend
      </h3>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={CHART_THEME.grid}
              vertical={false}
            />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 10, fill: CHART_THEME.text }}
              tickLine={false}
              axisLine={{ stroke: CHART_THEME.border }}
            />
            <YAxis
              tick={{ fontSize: 10, fill: CHART_THEME.text }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
              width={30}
            />
            <Tooltip content={<ChartTooltip />} />
            <Area
              type="monotone"
              dataKey="critical"
              stackId="1"
              stroke={SEVERITY_COLORS.critical}
              fill={SEVERITY_COLORS.critical}
              fillOpacity={0.3}
            />
            <Area
              type="monotone"
              dataKey="high"
              stackId="1"
              stroke={SEVERITY_COLORS.high}
              fill={SEVERITY_COLORS.high}
              fillOpacity={0.3}
            />
            <Area
              type="monotone"
              dataKey="medium"
              stackId="1"
              stroke={SEVERITY_COLORS.medium}
              fill={SEVERITY_COLORS.medium}
              fillOpacity={0.2}
            />
            <Area
              type="monotone"
              dataKey="low"
              stackId="1"
              stroke={SEVERITY_COLORS.low}
              fill={SEVERITY_COLORS.low}
              fillOpacity={0.15}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ─── EPSS Distribution (bar chart) ───────────────────────────────────────────

export interface EpssDataPoint {
  range: string;
  count: number;
}

export function EpssDistributionChart({ data }: { data: EpssDataPoint[] }) {
  if (data.length === 0) return null;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-1">
        EPSS Distribution
      </h3>
      <p className="text-[10px] text-zinc-600 mb-4">
        Exploit probability scores across findings
      </p>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={CHART_THEME.grid}
              vertical={false}
            />
            <XAxis
              dataKey="range"
              tick={{ fontSize: 9, fill: CHART_THEME.text }}
              tickLine={false}
              axisLine={{ stroke: CHART_THEME.border }}
            />
            <YAxis
              tick={{ fontSize: 10, fill: CHART_THEME.text }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
              width={30}
            />
            <Tooltip content={<ChartTooltip />} />
            <Bar
              dataKey="count"
              name="findings"
              fill="#10b981"
              radius={[4, 4, 0, 0]}
              fillOpacity={0.7}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ─── Severity Donut (pie chart) ──────────────────────────────────────────────

export interface SeveritySlice {
  name: string;
  value: number;
}

export function SeverityDonut({ data }: { data: SeveritySlice[] }) {
  const filtered = data.filter((d) => d.value > 0);
  if (filtered.length === 0) return null;
  const total = filtered.reduce((s, d) => s + d.value, 0);
  const colors = filtered.map(
    (d) => SEVERITY_COLORS[d.name as keyof typeof SEVERITY_COLORS] ?? "#71717a"
  );

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-4">
        Severity Breakdown
      </h3>
      <div className="h-48 flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={filtered}
              cx="50%"
              cy="50%"
              innerRadius="55%"
              outerRadius="85%"
              paddingAngle={2}
              dataKey="value"
              stroke="none"
            >
              {filtered.map((_, i) => (
                <Cell key={i} fill={colors[i]} fillOpacity={0.85} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute text-center pointer-events-none">
          <div className="text-2xl font-bold font-mono text-zinc-100">
            {total}
          </div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-wide">
            total
          </div>
        </div>
      </div>
    </div>
  );
}
