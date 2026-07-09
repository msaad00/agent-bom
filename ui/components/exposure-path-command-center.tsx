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
}: {
  path: ExposurePath;
  actions?: ExposurePathCommandAction[] | undefined;
}) {
  const fixLabel = pathFixLabel(path);
  const evidence = path.evidence;
  const primaryAction = actions[0];
  const investigationBrief = buildInvestigationBrief(path, fixLabel);
  const hopCount = Math.max(0, path.hops.length - 1);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Command center</p>
          <h2 className="mt-1 text-lg font-semibold leading-7 text-[color:var(--foreground)] [overflow-wrap:anywhere]">
            {pathDisplayTitle(path)}
          </h2>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <MetricPill label="Risk" value={path.riskScore.toFixed(1)} tone="red" />
          <MetricPill label="Hops" value={String(hopCount)} />
          <MetricPill label="Agents" value={String(path.affectedAgents.length)} />
          {fixLabel && <MetricPill label="Fix" value={fixLabel} tone="green" />}
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {investigationBrief.map((item) => (
          <BriefChip key={item.label} label={item.label} value={item.value} detail={item.detail} />
        ))}
      </div>

      <section aria-label="Selected exposure path graph">
        <ExposurePathGraph path={path} />
      </section>

      <details className="group rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-medium text-[color:var(--foreground)] [&::-webkit-details-marker]:hidden">
          <span>Relationship proof & evidence drawer</span>
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
        <Link
          href={primaryAction.href}
          className="flex items-start gap-3 rounded-xl border border-emerald-500/25 bg-emerald-500/10 px-4 py-3 text-sm transition hover:border-emerald-400/60"
        >
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
          <span>
            <span className="block font-semibold text-[color:var(--foreground)]">{primaryAction.title}</span>
            <span className="mt-1 block text-xs leading-5 text-[color:var(--text-secondary)]">{primaryAction.detail}</span>
          </span>
        </Link>
      )}
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
      ? "border-red-500/25 bg-red-500/10 text-red-200"
      : tone === "green"
        ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-200"
        : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--foreground)]";

  return (
    <div className={`rounded-lg border px-2.5 py-1.5 ${toneClass}`}>
      <span className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</span>{" "}
      <span className="font-mono font-semibold">{value}</span>
    </div>
  );
}

function BriefChip({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div
      className="min-w-[9rem] max-w-full flex-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2"
      title={detail ? `${label}: ${detail}` : label}
    >
      <div className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-0.5 truncate text-sm font-medium text-[color:var(--foreground)]">{value}</div>
    </div>
  );
}

function buildInvestigationBrief(path: ExposurePath, fixLabel: string | undefined) {
  const exposed = firstNonEmpty(path.exposedCredentials, path.reachableTools, path.affectedServers, path.affectedAgents);
  const finding = path.findings[0] ?? path.target.label;
  const proofCount = path.relationships.length;

  return [
    { label: "What is exposed", value: exposed.value, detail: exposed.label },
    { label: "Why it matters", value: finding, detail: path.severity || "ranked by graph risk" },
    { label: "What proves it", value: `${proofCount} relationship${proofCount === 1 ? "" : "s"}`, detail: path.provenance?.source ?? "graph evidence" },
    { label: "What fixes it", value: fixLabel ?? "triage path", detail: path.fix?.version ? `Target ${path.fix.version}` : primaryFixDetail(path) },
  ];
}

function firstNonEmpty(...groups: string[][]) {
  const labels = ["credentials", "tools", "servers", "agents"];
  for (let index = 0; index < groups.length; index += 1) {
    const values = groups[index] ?? [];
    if (values.length > 0) {
      const first = values[0] ?? "unknown";
      return {
        value: values.length > 1 ? `${first} +${values.length - 1}` : first,
        label: labels[index] ?? "entities",
      };
    }
  }
  return { value: "path target", label: "selected exposure path" };
}

function primaryFixDetail(path: ExposurePath): string {
  if (path.fix?.label) return path.fix.label;
  if (path.dependencyContext?.packageName) return path.dependencyContext.packageName;
  return "validate, contain, or accept risk";
}

function ExposurePathGraph({ path }: { path: ExposurePath }) {
  const layout = buildPathGraphLayout(path);

  return (
    <div className="overflow-x-auto rounded-xl border border-[color:var(--border-subtle)] bg-[#05070b]">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        role="img"
        aria-label={`Selected exposure path graph for ${pathDisplayTitle(path)}`}
        className="block h-auto min-w-[640px] w-full md:min-w-0"
      >
        <defs>
          <marker id="exposure-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#94a3b8" />
          </marker>
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
          >
            <title>{edge.label}</title>
          </path>
        ))}

        {layout.relationshipLabels.map((label) => (
          <g key={label.id} transform={`translate(${label.x} ${label.y})`}>
            <rect x="-48" y="-10" width="96" height="20" rx="10" fill="#0f172a" stroke="#334155" />
            <text x="0" y="4" textAnchor="middle" fill="#cbd5e1" fontSize="10" fontFamily="var(--font-mono), monospace">
              {label.text}
            </text>
          </g>
        ))}

        {layout.nodes.map((node, index) => {
          const style = GRAPH_ROLE_STYLE[node.role] ?? GRAPH_ROLE_STYLE.unknown;
          const meta = ROLE_META[node.role] ?? ROLE_META.unknown;
          return (
            <g key={`${node.id}-${index}`} transform={`translate(${node.x} ${node.y})`}>
              <rect width={layout.nodeWidth} height={layout.nodeHeight} rx="12" fill={style.fill} stroke={style.stroke} strokeWidth="2" />
              <text x="14" y="22" fill={style.accent} fontSize="9" fontWeight="700" letterSpacing="1.5" fontFamily="var(--font-mono), monospace">
                {meta.label.toUpperCase()}
              </text>
              <text x="14" y="44" fill={style.text} fontSize="13" fontWeight="600" fontFamily="var(--font-sans), system-ui">
                {wrapGraphText(node.label, 16, 2).map((line, lineIndex) => (
                  <tspan key={`${node.id}-line-${lineIndex}`} x="14" dy={lineIndex === 0 ? 0 : 15}>
                    {line}
                  </tspan>
                ))}
              </text>
              <title>{`${meta.label}: ${node.label}`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function buildPathGraphLayout(path: ExposurePath) {
  const width = 920;
  const nodeWidth = 168;
  const nodeHeight = 72;
  const columns = Math.min(4, Math.max(1, path.hops.length));
  const rows = Math.max(1, Math.ceil(path.hops.length / columns));
  const xGap = columns > 1 ? (width - nodeWidth - 48) / (columns - 1) : 0;
  const yGap = 108;
  const height = 40 + rows * nodeHeight + (rows - 1) * (yGap - nodeHeight) + 24;
  const nodes = path.hops.map((hop, index) => {
    const row = Math.floor(index / columns);
    const col = index % columns;
    const visualCol = row % 2 === 0 ? col : columns - 1 - col;
    return {
      ...hop,
      x: 24 + visualCol * xGap,
      y: 28 + row * yGap,
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
      label: relationship,
      labelX: sameRow ? (startX + endX) / 2 : (source.x + target.x + nodeWidth) / 2,
      labelY: sameRow ? startY - 14 : (source.y + target.y + nodeHeight) / 2,
    };
  });
  const relationshipLabels = edges.map((edge) => ({
    id: `${edge.id}:label`,
    text: truncateGraphText(edge.label, 12),
    x: edge.labelX,
    y: edge.labelY,
  }));

  return { width, height, nodeWidth, nodeHeight, nodes, edges, relationshipLabels };
}

function relationshipForPathStep(path: ExposurePath, source: string, target: string, index: number): string {
  const byEndpoints = path.relationships.find((relationship) => relationship.source === source && relationship.target === target);
  if (byEndpoints) return byEndpoints.relationship;
  return path.relationships[index]?.relationship ?? "reaches";
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
