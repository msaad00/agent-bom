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
import type { Agent, BlastRadius } from "@/lib/api";
import { buildBlastRadiusSummary } from "@/lib/insights-risk";
import { severityRank } from "@/lib/severity";
import { SEVERITY_HEX, getChartTheme } from "@/lib/theme-colors";

// ─── Shared ──────────────────────────────────────────────────────────────────

const SEVERITY_COLORS = SEVERITY_HEX;
const CHART_PANEL =
  "rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg";

export function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean | undefined;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string | undefined;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-lg border px-3 py-2 text-xs shadow-xl"
      style={{
        background: getChartTheme().tooltip.bg,
        borderColor: getChartTheme().tooltip.border,
      }}
    >
      {label && (
        <div className="mb-1 font-mono text-[10px] text-[color:var(--text-tertiary)]">{label}</div>
      )}
      {payload?.map((entry) => (
        <div
          key={entry.name}
          className="flex items-center gap-2"
          style={{ color: getChartTheme().tooltip.text }}
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
    <div className={CHART_PANEL}>
      <h3 className="text-sm font-semibold text-[color:var(--foreground)] mb-4">
        Vulnerability Trend
      </h3>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={getChartTheme().grid}
              vertical={false}
            />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 10, fill: getChartTheme().text }}
              tickLine={false}
              axisLine={{ stroke: getChartTheme().border }}
            />
            <YAxis
              tick={{ fontSize: 10, fill: getChartTheme().text }}
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
    <div className={CHART_PANEL}>
      <h3 className="text-sm font-semibold text-[color:var(--foreground)] mb-1">
        EPSS Distribution
      </h3>
      <p className="text-[10px] text-[color:var(--text-tertiary)] mb-4">
        Exploit probability scores across findings
      </p>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={getChartTheme().grid}
              vertical={false}
            />
            <XAxis
              dataKey="range"
              tick={{ fontSize: 9, fill: getChartTheme().text }}
              tickLine={false}
              axisLine={{ stroke: getChartTheme().border }}
            />
            <YAxis
              tick={{ fontSize: 10, fill: getChartTheme().text }}
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
    (d) => SEVERITY_COLORS[d.name as keyof typeof SEVERITY_COLORS] ?? SEVERITY_HEX.none
  );

  return (
    <div className={CHART_PANEL}>
      <h3 className="text-sm font-semibold text-[color:var(--foreground)] mb-4">
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
                <Cell key={i} fill={colors[i] ?? SEVERITY_HEX.none} fillOpacity={0.85} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute text-center pointer-events-none">
          <div className="text-2xl font-bold font-mono text-[color:var(--foreground)]">
            {total}
          </div>
          <div className="text-[10px] text-[color:var(--text-tertiary)] uppercase tracking-wide">
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
  size?: number | undefined;
  color?: string | undefined;
  children?: TreemapItem[] | undefined;
  [key: string]: unknown;
}

function TreemapCell({
  x, y, width, height, name, color,
}: {
  x?: number; y?: number; width?: number; height?: number;
  name?: string; color?: string;
}) {
  if (!width || !height || width < 4 || height < 4) return null;
  const bg = color ?? SEVERITY_HEX.none;
  const showLabel = Boolean(name) && width >= 72 && height >= 34;
  const maxChars = Math.max(6, Math.floor((width - 16) / 7));
  const label = name && name.length > maxChars ? `${name.slice(0, Math.max(3, maxChars - 1))}…` : name;
  const clipId = `treemap-cell-${Math.round(x ?? 0)}-${Math.round(y ?? 0)}-${Math.round(width)}-${Math.round(height)}`;
  return (
    <g>
      <defs>
        <clipPath id={clipId}>
          <rect
            x={(x ?? 0) + 6}
            y={(y ?? 0) + 4}
            width={Math.max(0, width - 12)}
            height={Math.max(0, height - 8)}
            rx={2}
          />
        </clipPath>
      </defs>
      <rect
        x={x} y={y} width={width} height={height}
        fill={bg}
        fillOpacity={0.85}
        stroke="var(--surface)"
        strokeWidth={1.5}
        rx={3}
      />
      {showLabel && (
        <text
          x={(x ?? 0) + 8}
          y={(y ?? 0) + 18}
          clipPath={`url(#${clipId})`}
          fill="var(--foreground)"
          fontSize={Math.min(11, Math.max(9, width / 18))}
          fontFamily="monospace"
          fontWeight={700}
        >
          {label}
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
  onPackageClick?: ((pkgName: string) => void) | undefined;
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
                return severityRank(v.severity) > severityRank(w) ? v.severity : w;
              },
              "none" as string
            );
            const color = worst === "critical"
              ? SEVERITY_HEX.critical
              : worst === "high"
                ? SEVERITY_HEX.high
                : worst === "medium"
                  ? SEVERITY_HEX.medium
                  : SEVERITY_HEX.low;
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
            ? [{ name: `Clean packages (${cleanCount})`, size: cleanCount, color: "#34d399", aggregate: true }]
            : []),
        ];
      })(),
    })),
  }));

  if (treeData.length === 0) return null;

  return (
    <div className={CHART_PANEL}>
      <h3 className="text-sm font-semibold text-[color:var(--foreground)] mb-1">Supply Chain Map</h3>
      <p className="text-[10px] text-[color:var(--text-tertiary)] mb-4">
        Vulnerable packages stay expanded. Clean inventory is rolled up per server for readability.
      </p>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <Treemap
            data={treeData as unknown as readonly Record<string, unknown>[]}
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
          { label: "Clean", color: "#34d399" },
          { label: "Low", color: SEVERITY_HEX.low },
          { label: "Medium", color: SEVERITY_HEX.medium },
          { label: "High", color: SEVERITY_HEX.high },
          { label: "Critical", color: SEVERITY_HEX.critical },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-sm" style={{ background: color }} />
            <span className="text-[10px] text-[color:var(--text-tertiary)]">{label}</span>
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
  score: number;
  vulnerabilityCount: number;
  agentCount: number;
  serverCount: number;
  fill: string;
}

export function BlastRadiusRadial({ data }: { data: BlastRadius[] }) {
  const top = buildBlastRadiusSummary(data, 8);

  if (top.length === 0) return null;

  const maxScore = Math.max(...top.map((entry) => entry.score), 1);

  const radialData: RadialPoint[] = top?.map((entry) => {
    const sev = entry.severity?.toLowerCase() ?? "low";
    const score = entry.score;
    const fill =
      sev === "critical" ? SEVERITY_HEX.critical
      : sev === "high" ? SEVERITY_HEX.high
      : sev === "medium" ? SEVERITY_HEX.medium
      : SEVERITY_HEX.low;
    return {
      name: entry.name,
      value: Math.round((score / maxScore) * 100),
      score,
      vulnerabilityCount: entry.vulnerability_count,
      agentCount: entry.agent_count,
      serverCount: entry.server_count,
      fill,
    };
  });

  return (
    <div className={CHART_PANEL}>
      <h3 className="text-sm font-semibold text-[color:var(--foreground)] mb-1">Blast Radius</h3>
      <p className="text-[10px] text-[color:var(--text-tertiary)] mb-2">
        Top reachable packages by highest priority, grouped by package
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
              background={{ fill: getChartTheme().bg }}
              label={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const d = payload[0]!.payload as RadialPoint;
                return (
                  <div
                    className="rounded-lg border px-3 py-2 text-xs shadow-xl"
                    style={{ background: getChartTheme().tooltip.bg, borderColor: getChartTheme().tooltip.border }}
                  >
                    <div className="font-mono text-[color:var(--foreground)] mb-1 truncate max-w-[160px]">{d.name}</div>
                    <div className="flex justify-between gap-4">
                      <span className="text-[color:var(--text-tertiary)]">Findings</span>
                      <span className="font-mono text-[color:var(--foreground)]">{d.vulnerabilityCount}</span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-[color:var(--text-tertiary)]">Agents</span>
                      <span className="font-mono text-[color:var(--foreground)]">{d.agentCount || "n/a"}</span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-[color:var(--text-tertiary)]">Priority</span>
                      <span className="font-mono" style={{ color: d.fill }}>{d.score.toFixed(1)}</span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-[color:var(--text-tertiary)]">Relative</span>
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
            <span className="font-mono text-[color:var(--text-secondary)] truncate flex-1">{d.name}</span>
            <span className="font-mono text-[color:var(--text-tertiary)]">{d.vulnerabilityCount} findings</span>
            <span className="font-mono text-[color:var(--text-tertiary)]">{d.score.toFixed(0)}</span>
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
    <div className={CHART_PANEL}>
      <h3 className="text-sm font-semibold text-[color:var(--foreground)] mb-1">Scan Pipeline</h3>
      <p className="text-[10px] text-[color:var(--text-tertiary)] mb-5">
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
                    : "bg-[color:var(--surface-muted)] border-[color:var(--border-subtle)]"
                }`}
              >
                <div
                  className={`w-1.5 h-1.5 rounded-full ${
                    isAlert ? "bg-red-500" : "bg-emerald-500"
                  }`}
                />
                <span className="text-[10px] font-semibold uppercase tracking-wide whitespace-nowrap text-[color:var(--foreground)]">
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
  package?: string | undefined;
}

function ScatterTooltipContent({
  active,
  payload,
}: {
  active?: boolean | undefined;
  payload?: Array<{ payload: EpssVsCvssPoint }> | undefined;
}) {
  if (!active || !payload?.length) return null;
  const d = payload[0]!.payload;
  const sevColor =
    SEVERITY_COLORS[d.severity as keyof typeof SEVERITY_COLORS] ?? SEVERITY_HEX.none;
  return (
    <div
      className="rounded-lg border px-3 py-2 text-xs shadow-xl max-w-[200px]"
      style={{
        background: getChartTheme().tooltip.bg,
        borderColor: getChartTheme().tooltip.border,
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
        <div className="text-[color:var(--text-tertiary)] truncate mb-1">{d.package}</div>
      )}
      <div className="flex justify-between gap-4">
        <span className="text-[color:var(--text-tertiary)]">CVSS</span>
        <span className="font-mono" style={{ color: getChartTheme().tooltip.text }}>
          {d.cvss.toFixed(1)}
        </span>
      </div>
      <div className="flex justify-between gap-4">
        <span className="text-[color:var(--text-tertiary)]">EPSS</span>
        <span className="font-mono" style={{ color: getChartTheme().tooltip.text }}>
          {(d.epss * 100).toFixed(1)}%
        </span>
      </div>
      <div className="flex justify-between gap-4">
        <span className="text-[color:var(--text-tertiary)]">Blast</span>
        <span className="font-mono" style={{ color: getChartTheme().tooltip.text }}>
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
    <div className={CHART_PANEL}>
      <h3 className="text-sm font-semibold text-[color:var(--foreground)] mb-1">
        EPSS × CVSS Risk Map
      </h3>
      <p className="text-[10px] text-[color:var(--text-tertiary)] mb-4">
        Bubble size = blast score · top-right = highest priority
      </p>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={getChartTheme().grid}
            />
            <XAxis
              type="number"
              dataKey="cvss"
              domain={[0, 10]}
              ticks={[0, 2, 4, 6, 8, 10]}
              tick={{ fontSize: 9, fill: getChartTheme().text }}
              tickLine={false}
              axisLine={{ stroke: getChartTheme().border }}
              label={{
                value: "CVSS",
                position: "insideBottom",
                offset: -2,
                fill: getChartTheme().text,
                fontSize: 9,
              }}
            />
            <YAxis
              type="number"
              dataKey="epss"
              domain={[0, 1]}
              tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
              tick={{ fontSize: 9, fill: getChartTheme().text }}
              tickLine={false}
              axisLine={false}
              width={36}
            />
            <ZAxis type="number" dataKey="blast" range={zRange} />
            <Tooltip content={<ScatterTooltipContent />} />
            {/* Threshold lines marking the "action zone" */}
            <ReferenceLine
              x={7}
              stroke={SEVERITY_HEX.critical}
              strokeDasharray="4 3"
              strokeOpacity={0.3}
            />
            <ReferenceLine
              y={0.1}
              stroke={SEVERITY_HEX.high}
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
              <span className="text-[10px] text-[color:var(--text-tertiary)] capitalize">{sev}</span>
              <span className="text-[10px] font-mono text-[color:var(--text-tertiary)]">
                ({bySev[sev].length})
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}
