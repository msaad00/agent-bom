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
  Treemap,
  RadialBarChart,
  RadialBar,
} from "recharts";
import type { Agent, BlastRadius, ScanResult } from "@/lib/api";

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
      {payload?.map((entry) => (
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
  const colors = filtered?.map(
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
              {filtered?.map((_, i) => (
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

// ─── Supply Chain Treemap ─────────────────────────────────────────────────────

interface TreemapItem {
  name: string;
  size?: number;
  color?: string;
  children?: TreemapItem[];
  [key: string]: unknown;
}

function TreemapCell({
  x, y, width, height, name, color,
}: {
  x?: number; y?: number; width?: number; height?: number;
  name?: string; color?: string;
}) {
  if (!width || !height || width < 4 || height < 4) return null;
  const bg = color ?? "#27272a";
  return (
    <g>
      <rect
        x={x} y={y} width={width} height={height}
        fill={bg}
        fillOpacity={0.85}
        stroke="#18181b"
        strokeWidth={1.5}
        rx={3}
      />
      {width > 40 && height > 20 && (
        <text
          x={(x ?? 0) + (width) / 2}
          y={(y ?? 0) + (height) / 2}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#e4e4e7"
          fontSize={Math.min(11, Math.max(8, width / 10))}
          fontFamily="monospace"
        >
          {name && name.length > 16 ? name.slice(0, 14) + "…" : name}
        </text>
      )}
    </g>
  );
}

export function SupplyChainTreemap({
  agents,
  onPackageClick,
}: {
  agents: Agent[];
  onPackageClick?: (pkgName: string) => void;
}) {
  const treeData: TreemapItem[] = agents?.map((agent) => ({
    name: agent.name,
    children: agent.mcp_servers?.map((srv) => ({
      name: srv.name,
      children: (() => {
        const vulnerablePackages = srv.packages
          ?.filter((pkg) => (pkg.vulnerabilities?.length ?? 0) > 0)
          .sort((left, right) => (right.vulnerabilities?.length ?? 0) - (left.vulnerabilities?.length ?? 0))
          .map((pkg) => {
            const vulns = pkg.vulnerabilities ?? [];
            const worst = vulns.reduce(
              (w, v) => {
                const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
                return (order[v.severity] ?? 0) > (order[w] ?? 0) ? v.severity : w;
              },
              "none" as string
            );
            const color = worst === "critical"
              ? "#ef4444"
              : worst === "high"
                ? "#f97316"
                : worst === "medium"
                  ? "#eab308"
                  : "#3b82f6";
            return {
              name: `${pkg.name}@${pkg.version}`,
              size: Math.max(2, vulns.length * 3),
              color,
            };
          }) ?? [];
        const cleanCount = srv.packages?.filter((pkg) => (pkg.vulnerabilities?.length ?? 0) === 0).length ?? 0;
        return [
          ...vulnerablePackages,
          ...(cleanCount > 0
            ? [{ name: `Clean packages (${cleanCount})`, size: cleanCount, color: "#22c55e", aggregate: true }]
            : []),
        ];
      })(),
    })),
  }));

  if (treeData.length === 0) return null;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-1">Supply Chain Map</h3>
      <p className="text-[10px] text-zinc-600 mb-4">
        Vulnerable packages stay expanded. Clean inventory is rolled up per server for readability.
      </p>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <Treemap
            data={treeData}
            dataKey="size"
            content={<TreemapCell />}
            onClick={(node: Record<string, unknown>) => {
              if (
                onPackageClick &&
                node &&
                typeof node.name === "string" &&
                node.size !== undefined &&
                node.aggregate !== true
              ) {
                // Leaf node (package) — strip version suffix for package name
                const name = node.name.replace(/@[^@]+$/, "");
                onPackageClick(name);
              }
            }}
          />
        </ResponsiveContainer>
      </div>
      <div className="flex gap-4 mt-3">
        {[
          { label: "Clean", color: "#22c55e" },
          { label: "Low", color: "#3b82f6" },
          { label: "Medium", color: "#eab308" },
          { label: "High", color: "#f97316" },
          { label: "Critical", color: "#ef4444" },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-sm" style={{ background: color }} />
            <span className="text-[10px] text-zinc-500">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Blast Radius Radial Bar ──────────────────────────────────────────────────

interface RadialPoint {
  name: string;
  value: number;
  fill: string;
}

export function BlastRadiusRadial({ data }: { data: BlastRadius[] }) {
  const top = [...data]
    .sort((a, b) => b.blast_score - a.blast_score)
    .slice(0, 8);

  if (top.length === 0) return null;

  const maxScore = top[0].blast_score;

  const radialData: RadialPoint[] = top?.map((br) => {
    const sev = br.severity?.toLowerCase() ?? "low";
    const fill =
      sev === "critical" ? "#ef4444"
      : sev === "high" ? "#f97316"
      : sev === "medium" ? "#eab308"
      : "#3b82f6";
    return {
      name: br.package ?? br.vulnerability_id,
      value: Math.round((br.blast_score / Math.max(maxScore, 1)) * 100),
      fill,
    };
  });

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-1">Blast Radius</h3>
      <p className="text-[10px] text-zinc-600 mb-2">
        Top packages by blast score (relative %)
      </p>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            cx="50%"
            cy="50%"
            innerRadius="15%"
            outerRadius="90%"
            barSize={10}
            data={radialData}
            startAngle={180}
            endAngle={0}
          >
            <RadialBar
              dataKey="value"
              cornerRadius={4}
              background={{ fill: "#27272a" }}
              label={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const d = payload[0].payload as RadialPoint;
                return (
                  <div
                    className="rounded-lg border px-3 py-2 text-xs shadow-xl"
                    style={{ background: "#09090b", borderColor: "#27272a" }}
                  >
                    <div className="font-mono text-zinc-300 mb-1 truncate max-w-[160px]">{d.name}</div>
                    <div className="flex justify-between gap-4">
                      <span className="text-zinc-500">Blast %</span>
                      <span className="font-mono" style={{ color: d.fill }}>{d.value}%</span>
                    </div>
                  </div>
                );
              }}
            />
          </RadialBarChart>
        </ResponsiveContainer>
      </div>
      <div className="space-y-1 mt-2">
        {radialData.slice(0, 5).map((d) => (
          <div key={d.name} className="flex items-center gap-2 text-[10px]">
            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: d.fill }} />
            <span className="text-zinc-400 font-mono truncate flex-1">{d.name}</span>
            <span className="text-zinc-600 font-mono">{d.value}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Pipeline Flow ────────────────────────────────────────────────────────────

export interface PipelineStats {
  agents: number;
  servers: number;
  packages: number;
  vulnerabilities: number;
  critical: number;
  high: number;
  kev: number;
}

const PIPELINE_STAGES = [
  { id: "discovery",  label: "Discovery",  stat: (s: PipelineStats) => `${s.agents} agents` },
  { id: "extraction", label: "Extraction", stat: (s: PipelineStats) => `${s.servers} servers` },
  { id: "scanning",   label: "Scanning",   stat: (s: PipelineStats) => `${s.packages} pkgs` },
  { id: "enrichment", label: "Enrichment", stat: (s: PipelineStats) => `${s.vulnerabilities} CVEs` },
  { id: "analysis",   label: "Analysis",   stat: (s: PipelineStats) => `${s.critical}C ${s.high}H` },
  { id: "output",     label: "Report",     stat: (s: PipelineStats) => s.kev > 0 ? `${s.kev} KEV` : "Clean" },
] as const;

export function PipelineFlow({ stats }: { stats: PipelineStats }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg shadow-zinc-950/50">
      <h3 className="text-sm font-semibold text-zinc-300 mb-1">Scan Pipeline</h3>
      <p className="text-[10px] text-zinc-600 mb-5">
        End-to-end flow with live stats from the latest scan
      </p>
      <div className="flex items-stretch gap-0 overflow-x-auto pb-2">
        {PIPELINE_STAGES?.map((stage, i) => {
          const isLast = i === PIPELINE_STAGES.length - 1;
          const isAlert = stage.id === "output" && stats.kev > 0;
          return (
            <div key={stage.id} className="flex items-center flex-1 min-w-0">
              <div
                className={`flex-1 min-w-[72px] flex flex-col items-center gap-1.5 px-3 py-3 rounded-lg border transition-colors ${
                  isAlert
                    ? "bg-red-950/30 border-red-800/50"
                    : "bg-zinc-800/50 border-zinc-700/40"
                }`}
              >
                <div
                  className={`w-1.5 h-1.5 rounded-full ${
                    isAlert ? "bg-red-500" : "bg-emerald-500"
                  }`}
                />
                <span className="text-[10px] font-semibold text-zinc-300 uppercase tracking-wide whitespace-nowrap">
                  {stage.label}
                </span>
                <span
                  className={`text-[11px] font-mono font-bold ${
                    isAlert ? "text-red-400" : "text-emerald-400"
                  }`}
                >
                  {stage.stat(stats)}
                </span>
              </div>
              {!isLast && (
                <div className="w-4 flex-shrink-0 flex items-center justify-center">
                  <svg width="12" height="10" viewBox="0 0 12 10" fill="none">
                    <path d="M0 5H10M7 1L11 5L7 9" stroke="#52525b" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              )}
            </div>
          );
        })}
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
  const blastValues = data?.map((d) => d.blast);
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
