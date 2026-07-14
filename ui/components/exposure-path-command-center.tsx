"use client";

import Link from "next/link";
import type { LucideIcon } from "lucide-react";
import {
  Bot,
  Bug,
  CheckCircle2,
  ChevronDown,
  Database,
  KeyRound,
  Package,
  Server,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import { pathDisplayTitle, pathFixLabel, type ExposureEntityRole, type ExposurePath } from "@/lib/exposure-path";
import { ExposurePathNeighborExplorer } from "@/components/exposure-path-neighbor-explorer";

export interface ExposurePathCommandAction {
  title: string;
  detail: string;
  href: string;
}

const ROLE_META: Record<ExposureEntityRole, { label: string; icon: LucideIcon; tint: string }> = {
  agent: { label: "Agent", icon: Bot, tint: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200" },
  server: { label: "Server", icon: Server, tint: "border-sky-500/30 bg-sky-500/10 text-sky-200" },
  package: { label: "Package", icon: Package, tint: "border-amber-500/30 bg-amber-500/10 text-amber-200" },
  finding: { label: "Finding", icon: Bug, tint: "border-red-500/30 bg-red-500/10 text-red-200" },
  credential: { label: "Credential", icon: KeyRound, tint: "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-200" },
  tool: { label: "Tool", icon: Wrench, tint: "border-purple-500/30 bg-purple-500/10 text-purple-200" },
  environment: { label: "Environment", icon: Database, tint: "border-cyan-500/30 bg-cyan-500/10 text-cyan-200" },
  cluster: { label: "Cluster", icon: Database, tint: "border-indigo-500/30 bg-indigo-500/10 text-indigo-200" },
  unknown: { label: "Entity", icon: ShieldAlert, tint: "border-zinc-500/30 bg-zinc-500/10 text-zinc-200" },
};

const GRAPH_ROLE_STYLE: Record<ExposureEntityRole, { fill: string; stroke: string; text: string; accent: string }> = {
  agent: { fill: "#052e24", stroke: "#10b981", text: "#d1fae5", accent: "#34d399" },
  server: { fill: "#082f49", stroke: "#0ea5e9", text: "#e0f2fe", accent: "#38bdf8" },
  package: { fill: "#422006", stroke: "#f59e0b", text: "#fef3c7", accent: "#fbbf24" },
  finding: { fill: "#450a0a", stroke: "#ef4444", text: "#fee2e2", accent: "#f87171" },
  credential: { fill: "#3b0764", stroke: "#d946ef", text: "#fae8ff", accent: "#e879f9" },
  tool: { fill: "#2e1065", stroke: "#a855f7", text: "#f3e8ff", accent: "#c084fc" },
  environment: { fill: "#164e63", stroke: "#06b6d4", text: "#cffafe", accent: "#22d3ee" },
  cluster: { fill: "#312e81", stroke: "#6366f1", text: "#e0e7ff", accent: "#818cf8" },
  unknown: { fill: "#27272a", stroke: "#71717a", text: "#f4f4f5", accent: "#a1a1aa" },
};

export function ExposurePathCommandCenter({
  path,
  actions = [],
  scanId,
}: {
  path: ExposurePath;
  actions?: ExposurePathCommandAction[] | undefined;
  scanId?: string | undefined;
}) {
  const fixLabel = pathFixLabel(path);
  const evidence = path.evidence;
  const primaryAction = actions[0];
  const hopCount = Math.max(0, path.hops.length - 1);
  const severityTone =
    path.severity === "critical"
      ? "from-red-500/80 via-red-500/20 to-transparent"
      : path.severity === "high"
        ? "from-orange-500/70 via-orange-500/15 to-transparent"
        : "from-sky-500/50 via-sky-500/10 to-transparent";

  return (
    <div className="relative overflow-hidden rounded-2xl border border-[color:var(--border-subtle)] bg-[linear-gradient(160deg,var(--surface),var(--surface-elevated))] shadow-xl shadow-black/20">
      <div className={`absolute inset-y-0 left-0 w-1 bg-gradient-to-b ${severityTone}`} aria-hidden="true" />
      <div className="space-y-5 p-5 pl-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-red-500/35 bg-red-500/12 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-red-200">
                {String(path.severity)} risk
              </span>
              <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-0.5 font-mono text-[11px] text-[color:var(--foreground)]">
                {path.riskScore.toFixed(1)}
              </span>
              {evidence?.isKev ? (
                <span className="rounded-full border border-amber-500/35 bg-amber-500/10 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-200">
                  CISA KEV
                </span>
              ) : null}
            </div>
            <h2 className="text-xl font-semibold leading-8 text-[color:var(--foreground)] [overflow-wrap:anywhere]">
              {pathDisplayTitle(path)}
            </h2>
            <p className="max-w-3xl text-sm leading-6 text-[color:var(--text-secondary)]">
              {path.summary ||
                "A reachable package or service on this path inherits downstream credential and tool exposure from the agent runtime."}
            </p>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
            <MetricPill label="Risk" value={path.riskScore.toFixed(1)} tone="red" />
            <MetricPill label="Hops" value={String(hopCount)} />
            <MetricPill label="Agents" value={String(path.affectedAgents.length)} />
            {fixLabel ? <MetricPill label="Fix" value={fixLabel} tone="green" /> : null}
          </div>
        </div>

        <section aria-label="Selected exposure path graph" className="rounded-2xl border border-[color:var(--border-subtle)] bg-[#05070b] p-1">
          <ExposurePathGraph path={path} />
        </section>

        <ExposurePathNeighborExplorer path={path} scanId={scanId} />

        <details className="group rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]/70">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-medium text-[color:var(--foreground)] [&::-webkit-details-marker]:hidden">
            <span>Evidence & relationships</span>
            <ChevronDown className="h-4 w-4 shrink-0 text-[color:var(--text-tertiary)] transition-transform group-open:rotate-180" />
          </summary>
        <div className="space-y-4 border-t border-[color:var(--border-subtle)] px-4 py-4">
          <section aria-label="Relationship proof">
            <div className="mb-2 text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
              Relationship proof
            </div>
            <div className="max-h-48 divide-y divide-[color:var(--border-subtle)] overflow-y-auto rounded-xl border border-[color:var(--border-subtle)]">
              {path.relationships.slice(0, 8).map((relationship) => (
                <div key={relationship.id} className="grid gap-2 px-3 py-2 text-xs md:grid-cols-[1fr_auto]">
                  <div className="min-w-0">
                    <span className="font-mono text-[color:var(--foreground)] [overflow-wrap:anywhere]">{relationship.relationship}</span>
                    <span className="ml-2 break-all text-[color:var(--text-tertiary)] [overflow-wrap:anywhere]">
                      {relationship.source} → {relationship.target}
                    </span>
                  </div>
                </div>
              ))}
              {path.relationships.length === 0 && (
                <div className="px-3 py-3 text-xs text-[color:var(--text-secondary)]">No relationship evidence attached.</div>
              )}
            </div>
          </section>

          <aside aria-label="Evidence drawer" className="grid gap-2 sm:grid-cols-2">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)] sm:col-span-2">
              Evidence drawer
            </div>
            <EvidenceRow label="Findings" values={path.findings} />
            <EvidenceRow label="Agents" values={path.affectedAgents} />
            <EvidenceRow label="Servers" values={path.affectedServers} />
            <EvidenceRow label="Tools" values={path.reachableTools} emptyLabel="none" />
            <EvidenceRow label="Credentials" values={path.exposedCredentials} emptyLabel="none" />
            <div className="rounded-xl border border-[color:var(--border-subtle)] px-3 py-2 text-xs sm:col-span-2">
              <div className="flex flex-wrap items-center gap-2 text-[color:var(--text-secondary)]">
                <ShieldAlert className="h-3.5 w-3.5 text-red-300" />
                <span>CVSS {evidence?.cvssScore ?? "n/a"}</span>
                <span>EPSS {typeof evidence?.epssScore === "number" ? evidence.epssScore.toFixed(3) : "n/a"}</span>
                {evidence?.isKev && <span className="font-semibold text-red-300">KEV</span>}
              </div>
            </div>
          </aside>
        </div>
      </details>

      {primaryAction && (
        <div className="flex flex-wrap gap-2">
          <Link
            href={primaryAction.href}
            className="inline-flex items-center gap-2 rounded-xl border border-emerald-700/50 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-200 transition hover:border-emerald-500 hover:bg-emerald-500/15"
          >
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{primaryAction.title}</span>
          </Link>
        </div>
      )}
      </div>
    </div>
  );
}

function MetricPill({
  label,
  value,
  tone = "zinc",
}: {
  label: string;
  value: string;
  tone?: "red" | "green" | "zinc";
}) {
  const toneClass =
    tone === "red"
      ? "border-red-500/30 bg-red-500/10 text-[color:var(--foreground)]"
      : tone === "green"
        ? "border-emerald-500/30 bg-emerald-500/10 text-[color:var(--foreground)]"
        : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--foreground)]";

  return (
    <div className={`rounded-lg border px-2.5 py-1.5 ${toneClass}`}>
      <span className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</span>{" "}
      <span className="font-mono font-semibold">{value}</span>
    </div>
  );
}

function ExposurePathGraph({ path }: { path: ExposurePath }) {
  const layout = buildPathGraphLayout(path);

  return (
    <div className="overflow-x-auto p-2">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        role="img"
        aria-label={`Selected exposure path graph for ${pathDisplayTitle(path)}`}
        className="block h-auto min-w-[720px] w-full md:min-w-0"
      >
        <defs>
          <marker id="exposure-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#94a3b8" />
          </marker>
          <filter id="node-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="#000000" floodOpacity="0.45" />
          </filter>
        </defs>

        <rect x="0" y="0" width={layout.width} height={layout.height} fill="#05070b" />

        {layout.edges.map((edge) => (
          <path
            key={edge.id}
            d={edge.path}
            fill="none"
            stroke={edge.stroke}
            strokeWidth="2.5"
            strokeLinecap="round"
            markerEnd="url(#exposure-arrow)"
            opacity="0.88"
          />
        ))}

        {layout.relationshipLabels.map((label) => (
          <g key={label.id} transform={`translate(${label.x} ${label.y})`}>
            <rect
              x={-label.width / 2}
              y="-11"
              width={label.width}
              height="22"
              rx="11"
              fill="#0f172a"
              stroke="#334155"
            />
            <text x="0" y="4" textAnchor="middle" fill="#cbd5e1" fontSize="11" fontFamily="var(--font-mono), monospace">
              {label.text}
            </text>
          </g>
        ))}

        {layout.nodes.map((node, index) => {
          const style = GRAPH_ROLE_STYLE[node.role] ?? GRAPH_ROLE_STYLE.unknown;
          const meta = ROLE_META[node.role] ?? ROLE_META.unknown;
          const titleLines = wrapGraphText(node.label, 18, 2);
          return (
            <g key={`${node.id}-${index}`} transform={`translate(${node.x} ${node.y})`}>
              <rect
                width={layout.nodeWidth}
                height={layout.nodeHeight}
                rx="14"
                fill={style.fill}
                stroke={style.stroke}
                strokeWidth="2"
                filter="url(#node-glow)"
              />
              <text x="14" y="20" fill={style.accent} fontSize="9" fontWeight="700" letterSpacing="1.4" fontFamily="var(--font-mono), monospace">
                {meta.label.toUpperCase()}
              </text>
              <text x="14" y="40" fill={style.text} fontSize="13" fontWeight="600" fontFamily="var(--font-sans), system-ui">
                {titleLines.map((line, lineIndex) => (
                  <tspan key={`${node.id}-line-${lineIndex}`} x="14" dy={lineIndex === 0 ? 0 : 15}>
                    {line}
                  </tspan>
                ))}
              </text>
              {node.subtitle ? (
                <text x="14" y="58" fill="#94a3b8" fontSize="10" fontFamily="var(--font-sans), system-ui">
                  {truncateGraphText(node.subtitle, 24)}
                </text>
              ) : null}
              <title>{`${meta.label}: ${node.label}${node.subtitle ? ` · ${node.subtitle}` : ""}`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function buildPathGraphLayout(path: ExposurePath) {
  // Geometry note: nodes are spaced with a generous horizontal gap so the
  // relationship pill sits centred in the clear channel between two node boxes
  // — never overlapping a node or getting clipped at the container edge. The
  // SVG scales to its container via viewBox, so a wider board just renders a
  // little smaller; it never crowds the labels.
  const nodeWidth = 188;
  const nodeHeight = 76;
  const marginX = 28;
  const marginY = 30;
  const columnGap = 132;
  const rowGap = 116;
  const columns = Math.min(4, Math.max(1, path.hops.length));
  const rows = Math.max(1, Math.ceil(path.hops.length / columns));
  const pitchX = nodeWidth + columnGap;
  const width = marginX * 2 + columns * nodeWidth + (columns - 1) * columnGap;
  const height = marginY * 2 + rows * nodeHeight + (rows - 1) * (rowGap - nodeHeight);
  const nodes = path.hops.map((hop, index) => {
    const row = Math.floor(index / columns);
    const col = index % columns;
    const visualCol = row % 2 === 0 ? col : columns - 1 - col;
    return {
      ...hop,
      x: marginX + visualCol * pitchX,
      y: marginY + row * rowGap,
    };
  });
  const edges = nodes.slice(0, -1).map((source, index) => {
    const target = nodes[index + 1]!;
    const relationship = relationshipForPathStep(path, source.id, target.id, index);
    const startX = source.x + nodeWidth;
    const startY = source.y + nodeHeight / 2;
    const endX = target.x;
    const endY = target.y + nodeHeight / 2;
    const sameRow = Math.abs(startY - endY) < 10;
    const control = sameRow ? Math.max(40, Math.abs(endX - startX) / 2) : 56;
    const pathD = sameRow
      ? `M ${startX} ${startY} C ${startX + control} ${startY}, ${endX - control} ${endY}, ${endX} ${endY}`
      : `M ${source.x + nodeWidth / 2} ${source.y + nodeHeight} C ${source.x + nodeWidth / 2} ${source.y + nodeHeight + control}, ${target.x + nodeWidth / 2} ${target.y - control}, ${target.x + nodeWidth / 2} ${target.y}`;
    const style = GRAPH_ROLE_STYLE[target.role] ?? GRAPH_ROLE_STYLE.unknown;
    return {
      id: `${source.id}->${target.id}`,
      path: pathD,
      stroke: style.stroke,
      label: truncateGraphText(relationship, 16),
      // Centre the pill on the edge line, mid-channel between the two nodes.
      labelX: sameRow ? (startX + endX) / 2 : source.x + nodeWidth / 2,
      labelY: sameRow ? startY : (source.y + nodeHeight + target.y) / 2,
    };
  });
  const relationshipLabels = edges.map((edge) => ({
    id: `${edge.id}:label`,
    text: edge.label,
    x: edge.labelX,
    y: edge.labelY,
    width: Math.max(50, Math.round(edge.label.length * 6.6 + 22)),
  }));

  return { width, height, nodeWidth, nodeHeight, nodes, edges, relationshipLabels };
}

function relationshipForPathStep(path: ExposurePath, source: string, target: string, index: number): string {
  const byEndpoints = path.relationships.find((relationship) => relationship.source === source && relationship.target === target);
  const raw = byEndpoints?.relationship ?? path.relationships[index]?.relationship ?? "reaches";
  return humanizeRelationship(raw);
}

function humanizeRelationship(value: string): string {
  return value
    .replace(/[_:]+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function truncateGraphText(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, Math.max(1, maxLength - 1))}…` : value;
}

function wrapGraphText(value: string, maxLineLength: number, maxLines: number): string[] {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLineLength) return [normalized];

  const lines: string[] = [];
  let remaining = normalized;
  while (remaining.length > 0 && lines.length < maxLines) {
    const isLastLine = lines.length === maxLines - 1;
    if (remaining.length <= maxLineLength) {
      lines.push(remaining);
      break;
    }
    if (isLastLine) {
      lines.push(truncateGraphText(remaining, maxLineLength));
      break;
    }

    const window = remaining.slice(0, maxLineLength + 1);
    const breakpoints = [" ", "-", "_", "/", ":", "@", "."].map((character) => window.lastIndexOf(character));
    const breakpoint = Math.max(...breakpoints);
    const cut = breakpoint >= Math.floor(maxLineLength * 0.45) ? breakpoint + 1 : maxLineLength;
    lines.push(remaining.slice(0, cut).trim());
    remaining = remaining.slice(cut).trim();
  }

  return lines.length > 0 ? lines : [truncateGraphText(normalized, maxLineLength)];
}

function EvidenceRow({
  label,
  values,
  emptyLabel = "none",
}: {
  label: string;
  values: string[];
  emptyLabel?: string;
}) {
  return (
    <div className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] px-3 py-2 text-xs">
      <div className="mb-1 text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {(values.length > 0 ? values : [emptyLabel]).slice(0, 3).map((value) => (
          <span
            key={`${label}-${value}`}
            className="max-w-full rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-0.5 text-[color:var(--text-secondary)] [overflow-wrap:anywhere]"
          >
            {value}
          </span>
        ))}
        {values.length > 3 && (
          <span className="rounded border border-[color:var(--border-subtle)] px-2 py-0.5 text-[color:var(--text-tertiary)]">
            +{values.length - 3}
          </span>
        )}
      </div>
    </div>
  );
}
