"use client";

import Link from "next/link";
import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Bot,
  Bug,
  CheckCircle2,
  ChevronDown,
  Database,
  GitBranch,
  KeyRound,
  List,
  Network,
  Package,
  Server,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import { pathDisplayTitle, pathFixLabel, type ExposureEntityRole, type ExposurePath } from "@/lib/exposure-path";
import { GRAPH_ROLE_STYLE } from "@/lib/exposure-path-graph-style";
import { buildPathGraphLayout, wrapGraphText, truncateGraphText } from "@/lib/exposure-path-graph-layout";
import { ExposurePathNeighborExplorer } from "@/components/exposure-path-neighbor-explorer";

export interface ExposurePathCommandAction {
  title: string;
  detail: string;
  href: string;
}

/**
 * Which single representation of the selected path is shown. The command center
 * used to stack the path DAG, the neighbor list, and a full interactive graph
 * all at once; the toggle collapses that to one view at a time.
 */
export type ExposurePathView = "path" | "graph" | "list";

const PATH_VIEW_ITEMS: { key: ExposurePathView; label: string; icon: LucideIcon }[] = [
  { key: "path", label: "Path", icon: GitBranch },
  { key: "graph", label: "Graph", icon: Network },
  { key: "list", label: "List", icon: List },
];

function PathViewToggle({
  view,
  onChange,
}: {
  view: ExposurePathView;
  onChange: (next: ExposurePathView) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Exposure path view"
      className="inline-flex items-center overflow-hidden rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]"
    >
      {PATH_VIEW_ITEMS.map(({ key, label, icon: Icon }) => {
        const active = view === key;
        return (
          <button
            key={key}
            type="button"
            onClick={() => onChange(key)}
            aria-pressed={active}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-medium transition ${
              active
                ? "bg-emerald-600 text-white"
                : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
            }`}
          >
            <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            {label}
          </button>
        );
      })}
    </div>
  );
}

const ROLE_META: Record<ExposureEntityRole, { label: string; icon: LucideIcon; tint: string }> = {
  agent: { label: "Agent", icon: Bot, tint: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200" },
  server: { label: "Server", icon: Server, tint: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-200" },
  package: { label: "Package", icon: Package, tint: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200" },
  finding: { label: "Finding", icon: Bug, tint: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-200" },
  credential: { label: "Credential", icon: KeyRound, tint: "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-200" },
  tool: { label: "Tool", icon: Wrench, tint: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-200" },
  environment: { label: "Environment", icon: Database, tint: "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-200" },
  cluster: { label: "Cluster", icon: Database, tint: "border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-200" },
  unknown: { label: "Entity", icon: ShieldAlert, tint: "border-slate-500/30 bg-slate-500/10 text-slate-700 dark:text-slate-200" },
};

export function ExposurePathCommandCenter({
  path,
  actions = [],
  scanId,
  view: controlledView,
  onViewChange,
  graphSlot,
}: {
  path: ExposurePath;
  actions?: ExposurePathCommandAction[] | undefined;
  scanId?: string | undefined;
  /** Controlled active view. When omitted the component owns the state. */
  view?: ExposurePathView | undefined;
  /**
   * Notified when the operator switches views. The page wires this to render
   * the interactive investigation graph on demand in "graph" view instead of
   * reserving a full screen-height of blank canvas underneath.
   */
  onViewChange?: ((next: ExposurePathView) => void) | undefined;
  /**
   * Interactive graph rendered inline in "graph" view. Consolidating the graph
   * here means selecting "Graph" shows the live investigation immediately in
   * one place — no dashed "opens below" placeholder pointing at a separate,
   * disconnected panel further down the page.
   */
  graphSlot?: React.ReactNode | undefined;
}) {
  const [internalView, setInternalView] = useState<ExposurePathView>("path");
  const view = controlledView ?? internalView;
  const setView = (next: ExposurePathView) => {
    if (!controlledView) setInternalView(next);
    onViewChange?.(next);
  };
  const fixLabel = pathFixLabel(path);
  const evidence = path.evidence;
  const pathSummary =
    path.summary ||
    "A reachable package or service on this path inherits downstream credential and tool exposure from the agent runtime.";
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
      <div className="space-y-5 p-4 pl-5 sm:p-5 sm:pl-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="w-full min-w-0 space-y-2 sm:flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-red-500/35 bg-red-500/12 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-red-700 dark:text-red-200">
                {String(path.severity)} risk
              </span>
              {evidence?.isKev ? (
                <span className="rounded-full border border-amber-500/35 bg-amber-500/10 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-700 dark:text-amber-200">
                  CISA KEV
                </span>
              ) : null}
            </div>
            <h2 className="text-xl font-semibold leading-8 text-[color:var(--foreground)] [overflow-wrap:anywhere]">
              {pathDisplayTitle(path)}
            </h2>
            <p
              title={pathSummary}
              className="line-clamp-3 max-w-3xl text-sm leading-6 text-[color:var(--text-secondary)] sm:line-clamp-2"
            >
              {pathSummary}
            </p>
          </div>
          <div className="grid w-full grid-cols-3 gap-2 text-xs sm:w-auto sm:grid-cols-4">
            <MetricPill label="Path risk" value={path.riskScore.toFixed(1)} tone="red" />
            <MetricPill label="Hops" value={String(hopCount)} />
            <MetricPill label="Agents" value={String(path.affectedAgents.length)} />
            {fixLabel ? <MetricPill label="Fix" value={fixLabel} tone="green" /> : null}
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
            {view === "path"
              ? "Attack path"
              : view === "graph"
                ? "Interactive graph"
                : "Path neighbors"}
          </div>
          <PathViewToggle view={view} onChange={setView} />
        </div>

        {view === "path" ? (
          <section aria-label="Selected exposure path graph" className="rounded-2xl border border-[color:var(--border-subtle)] bg-[#05070b] p-1">
            <ExposurePathGraph path={path} />
          </section>
        ) : view === "list" ? (
          <ExposurePathNeighborExplorer path={path} scanId={scanId} />
        ) : graphSlot ? (
          <section aria-label="Interactive graph">{graphSlot}</section>
        ) : (
          <section
            aria-label="Interactive graph hint"
            className="rounded-2xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]/60 px-4 py-6 text-center text-xs text-[color:var(--text-secondary)]"
          >
            Interactive graph loads here once graph evidence is available for this snapshot.
          </section>
        )}

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
            className="inline-flex items-center gap-2 rounded-xl border border-emerald-700/50 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500 hover:bg-emerald-500/15"
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
    <div className="flex justify-center overflow-x-auto p-2">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label={`Selected exposure path graph for ${pathDisplayTitle(path)}`}
        style={{ maxWidth: `${layout.fitWidth}px` }}
        className="mx-auto block h-auto w-full"
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
          const titleLines = wrapGraphText(node.label, layout.labelChars, 2);
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
