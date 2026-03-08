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
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
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

// ─── EPSS vs CVSS Scatter Chart ───────────────────────────────────────────────

export interface EpssVsCvssPoint {
  cve: string;
  cvss: number;
  epss: number;
  blast: number;
  severity: string;
  kev: boolean;
  package?: string;
}

function ScatterTooltipContent({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ payload: EpssVsCvssPoint }>;
}) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  const sevColor =
    SEVERITY_COLORS[d.severity as keyof typeof SEVERITY_COLORS] ?? "#71717a";
  return (
    <div
      className="rounded-lg border px-3 py-2 text-xs shadow-xl max-w-[200px]"
      style={{
        background: CHART_THEME.tooltip.bg,
        borderColor: CHART_THEME.tooltip.border,
      }}
    >
      <div className="font-mono font-semibold mb-1" style={{ color: sevColor }}>
        {d.cve}
        {d.kev && (
          <span className="ml-1 text-[9px] bg-red-950 border border-red-800 text-red-400 rounded px-1">
            KEV
          </span>
        )}
      </div>
      {d.package && (
        <div className="text-zinc-500 truncate mb-1">{d.package}</div>
      )}
      <div className="flex justify-between gap-4">
        <span className="text-zinc-500">CVSS</span>
        <span className="font-mono" style={{ color: CHART_THEME.tooltip.text }}>
          {d.cvss.toFixed(1)}
        </span>
      </div>
      <div className="flex justify-between gap-4">
        <span className="text-zinc-500">EPSS</span>
        <span className="font-mono" style={{ color: CHART_THEME.tooltip.text }}>
          {(d.epss * 100).toFixed(1)}%
        </span>
      </div>
      <div className="flex justify-between gap-4">
        <span className="text-zinc-500">Blast</span>
        <span className="font-mono" style={{ color: CHART_THEME.tooltip.text }}>
          {d.blast.toFixed(1)}
        </span>
      </div>
    </div>
  );
}

export function EpssVsCvssChart({ data }: { data: EpssVsCvssPoint[] }) {
  if (data.length === 0) return null;

  // Group by severity so each gets its own colored scatter series
  const bySev = {
    critical: data.filter((d) => d.severity === "critical"),
    high: data.filter((d) => d.severity === "high"),
    medium: data.filter((d) => d.severity === "medium"),
    low: data.filter((d) => d.severity === "low"),
  } as const;

  // Bubble size range: blast_score mapped to [40, 600] area
  const blastValues = data.map((d) => d.blast);
  const minBlast = Math.min(...blastValues);
  const maxBlast = Math.max(...blastValues);
  const zRange: [number, number] =
    maxBlast > minBlast ? [40, 600] : [100, 100];

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-1">
        EPSS × CVSS Risk Map
      </h3>
      <p className="text-[10px] text-zinc-600 mb-4">
        Bubble size = blast score · top-right = highest priority
      </p>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={CHART_THEME.grid}
            />
            <XAxis
              type="number"
              dataKey="cvss"
              domain={[0, 10]}
              ticks={[0, 2, 4, 6, 8, 10]}
              tick={{ fontSize: 9, fill: CHART_THEME.text }}
              tickLine={false}
              axisLine={{ stroke: CHART_THEME.border }}
              label={{
                value: "CVSS",
                position: "insideBottom",
                offset: -2,
                fill: CHART_THEME.text,
                fontSize: 9,
              }}
            />
            <YAxis
              type="number"
              dataKey="epss"
              domain={[0, 1]}
              tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
              tick={{ fontSize: 9, fill: CHART_THEME.text }}
              tickLine={false}
              axisLine={false}
              width={36}
            />
            <ZAxis type="number" dataKey="blast" range={zRange} />
            <Tooltip content={<ScatterTooltipContent />} />
            {/* Threshold lines marking the "action zone" */}
            <ReferenceLine
              x={7}
              stroke="#ef4444"
              strokeDasharray="4 3"
              strokeOpacity={0.3}
            />
            <ReferenceLine
              y={0.1}
              stroke="#f97316"
              strokeDasharray="4 3"
              strokeOpacity={0.3}
            />
            {(["critical", "high", "medium", "low"] as const).map((sev) =>
              bySev[sev].length > 0 ? (
                <Scatter
                  key={sev}
                  name={sev}
                  data={bySev[sev]}
                  fill={SEVERITY_COLORS[sev]}
                  fillOpacity={0.75}
                  stroke={SEVERITY_COLORS[sev]}
                  strokeWidth={1}
                  strokeOpacity={0.4}
                />
              ) : null
            )}
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      {/* Legend */}
      <div className="flex gap-4 mt-3">
        {(["critical", "high", "medium", "low"] as const)
          .filter((s) => bySev[s].length > 0)
          .map((sev) => (
            <div key={sev} className="flex items-center gap-1.5">
              <span
                className="w-2 h-2 rounded-full"
                style={{ background: SEVERITY_COLORS[sev] }}
              />
              <span className="text-[10px] text-zinc-500 capitalize">{sev}</span>
              <span className="text-[10px] text-zinc-700 font-mono">
                ({bySev[sev].length})
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}
