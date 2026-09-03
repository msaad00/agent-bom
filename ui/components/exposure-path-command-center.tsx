"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Bot,
  Bug,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
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
import {
  exposurePathKey,
  pathDisplayTitle,
  pathFixLabel,
  pathSpanLabel,
  type ExposureEntityRef,
  type ExposureEntityRole,
  type ExposurePath,
} from "@/lib/exposure-path";
import { GRAPH_ROLE_STYLE } from "@/lib/exposure-path-graph-style";
import { formatExposureEntityTitle } from "@/lib/entity-display";
import {
  COLLAPSED_HOPS_NODE_ID,
  buildPathGraphLayout,
  humanizeRelationship,
  shouldCollapsePath,
  wrapGraphText,
  truncateGraphText,
} from "@/lib/exposure-path-graph-layout";
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
      className="ep-view-toggle"
    >
      {PATH_VIEW_ITEMS.map(({ key, label, icon: Icon }) => {
        const active = view === key;
        return (
          <button
            key={key}
            type="button"
            onClick={() => onChange(key)}
            aria-pressed={active}
            className={`ep-view-option ${
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
  techniquesSlot,
  detailsSlot,
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
  /**
   * Compact, decision-relevant proof rendered directly under the path.
   */
  techniquesSlot?: React.ReactNode | undefined;
  /** Technical analysis retained behind the Evidence & relationships disclosure. */
  detailsSlot?: React.ReactNode | undefined;
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
  const severityTone =
    path.severity === "critical"
      ? "from-red-500/80 via-red-500/20 to-transparent"
      : path.severity === "high"
        ? "from-orange-500/70 via-orange-500/15 to-transparent"
        : "from-sky-500/50 via-sky-500/10 to-transparent";

  return (
    <div data-testid="selected-exposure-path" className="ep-root">
      <div className={`ep-severity-rail ${severityTone}`} aria-hidden="true" />
      <div className="ep-body">
        <div className="ep-header">
          <div className="ep-header-copy">
            <div className="ep-badges">
              <span className="ep-severity">
                {String(path.severity)} risk
              </span>
              {evidence?.isKev ? (
                <span className="ep-kev">
                  CISA KEV
                </span>
              ) : null}
            </div>
            <h2 className="sr-only">{pathDisplayTitle(path)}</h2>
            <ExposurePathHopTitle hops={path.hops.length > 0 ? path.hops : [path.source, path.target]} />
            <p
              title={pathSummary}
              className="ep-summary"
            >
              {pathSummary}
            </p>
          </div>
          <div className="ep-metrics">
            <MetricPill label="Path risk" value={path.riskScore.toFixed(1)} tone="red" />
            <MetricPill label="Path span" value={pathSpanLabel(path.hops.length)} />
            <MetricPill label="Agents" value={String(path.affectedAgents.length)} />
            {fixLabel ? <MetricPill label="Fix" value={fixLabel} tone="green" /> : null}
          </div>
        </div>

        <div className="ep-view-row">
          <div className="ep-view-label">
            {view === "path"
              ? "Attack path"
              : view === "graph"
                ? "Interactive graph"
                : "Path neighbors"}
          </div>
          <PathViewToggle view={view} onChange={setView} />
        </div>

        {view === "path" ? (
          <section aria-label="Selected exposure path graph" className="ep-path-frame">
            {/* Keyed by path so selecting a new path re-enters the fit-first
                frame instead of inheriting the previous path's expanded board. */}
            <ExposurePathGraph key={exposurePathKey(path)} path={path} />
          </section>
        ) : view === "list" ? (
          <ExposurePathNeighborExplorer path={path} scanId={scanId} />
        ) : graphSlot ? (
          <section aria-label="Interactive graph">{graphSlot}</section>
        ) : (
          <section
            aria-label="Interactive graph hint"
            className="ep-graph-hint"
          >
            Interactive graph loads here once graph evidence is available for this snapshot.
          </section>
        )}

        {techniquesSlot}

        {primaryAction && (
          <div className="ep-actions">
            <Link
              href={primaryAction.href}
              data-testid="exposure-path-primary-action"
              className="ep-primary-action"
            >
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{primaryAction.title}</span>
            </Link>
          </div>
        )}

        <details className="ep-details group">
          <summary className="ep-details-summary">
            <span>Evidence & relationships</span>
            <ChevronDown className="ep-chevron" />
          </summary>
        <div className="ep-details-body">
          <section aria-label="Relationship proof">
            <div className="ep-kicker mb-2">
              Relationship proof
            </div>
            <div className="ep-proof-list">
              {path.relationships.slice(0, 8).map((relationship) => (
                <div key={relationship.id} className="ep-proof-row">
                  <div className="min-w-0">
                    <span className="ep-proof-source">{relationship.relationship}</span>
                    <span className="ep-proof-target">
                      {relationship.source} → {relationship.target}
                    </span>
                  </div>
                </div>
              ))}
              {path.relationships.length === 0 && (
                <div className="ep-empty-proof">No relationship evidence attached.</div>
              )}
            </div>
          </section>

          <aside aria-label="Evidence drawer" className="ep-role-row">
            <div className="ep-kicker ep-kicker-wide">
              Evidence drawer
            </div>
            <EvidenceRow label="Findings" values={path.findings} />
            <EvidenceRow label="Agents" values={path.affectedAgents} />
            <EvidenceRow label="Servers" values={path.affectedServers} />
            <EvidenceRow label="Tools" values={path.reachableTools} emptyLabel="none" />
            <EvidenceRow label="Credentials" values={path.exposedCredentials} emptyLabel="none" />
            <div className="ep-evidence-score">
              <div className="ep-evidence-meta">
                <ShieldAlert className="h-3.5 w-3.5 text-red-300" />
                <span>CVSS {evidence?.cvssScore ?? "n/a"}</span>
                <span>EPSS {typeof evidence?.epssScore === "number" ? evidence.epssScore.toFixed(3) : "n/a"}</span>
                {evidence?.isKev && <span className="font-semibold text-red-300">KEV</span>}
              </div>
            </div>
          </aside>
          {detailsSlot ? <div>{detailsSlot}</div> : null}
        </div>
      </details>
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
    <div className={`ep-metric ${toneClass}`}>
      <span className="ep-metric-label">{label}</span>{" "}
      <span className="font-mono font-semibold">{value}</span>
    </div>
  );
}

function ExposurePathGraph({ path }: { path: ExposurePath }) {
  const [expanded, setExpanded] = useState(false);
  const boardRef = useRef<HTMLDivElement>(null);
  const [availableWidth, setAvailableWidth] = useState<number | undefined>(undefined);

  useEffect(() => {
    const board = boardRef.current;
    if (!board) return;
    const updateWidth = (width: number) => {
      if (width > 0) setAvailableWidth(Math.floor(width));
    };
    updateWidth(board.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver((entries) => updateWidth(entries[0]?.contentRect.width ?? 0));
    observer.observe(board);
    return () => observer.disconnect();
  }, []);

  const collapsible = shouldCollapsePath(path.hops.length, availableWidth);
  const layout = buildPathGraphLayout(path, { expanded, availableWidth });
  // Only the fully expanded board is wider than its container, so scrolling is
  // opt-in: the collapsed board shrinks to fit and never clips a hop.
  const scrollable = collapsible && expanded;

  return (
    <div className="space-y-2">
      <ExposurePathSequence path={path} showDesktop={collapsible && !expanded} />
      <div ref={boardRef} className="hidden sm:block">
        {collapsible && !expanded ? (
          null
        ) : (
        <div className={`${scrollable ? "overflow-x-auto p-2" : "p-2"}`} data-testid="exposure-path-graph-scroll">
        <svg
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          {...(scrollable
            ? { width: layout.width, height: layout.height }
            : {
                width: "100%",
                style: { maxWidth: layout.fitWidth, aspectRatio: `${layout.width} / ${layout.height}` },
              })}
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-label={`Selected exposure path graph for ${pathDisplayTitle(path)}`}
          className={`mx-auto block ${scrollable ? "shrink-0" : ""}`}
        >
          <defs>
            <marker id="exposure-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L9,3 z" style={{ fill: "var(--text-tertiary)" }} />
            </marker>
          </defs>

          <rect x="0" y="0" width={layout.width} height={layout.height} style={{ fill: "var(--surface-panel)" }} />

          {layout.edges.map((edge) => (
            <path
              key={edge.id}
              d={edge.path}
              fill="none"
              style={{ stroke: edge.stroke }}
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
                style={{ fill: "var(--surface-elevated)", stroke: "var(--border-strong)" }}
              />
              <text
                x="0"
                y="4"
                textAnchor="middle"
                style={{ fill: "var(--text-secondary)" }}
                fontSize="11"
                fontFamily="var(--font-mono), monospace"
              >
                {label.text}
              </text>
            </g>
          ))}

          {layout.nodes.map((node, index) => {
            const style = GRAPH_ROLE_STYLE[node.role] ?? GRAPH_ROLE_STYLE.unknown;
            const summaryNode = node.id === COLLAPSED_HOPS_NODE_ID;
            const roleLabel = summaryNode
              ? "Hidden hops"
              : node.kindLabel ?? (ROLE_META[node.role] ?? ROLE_META.unknown).label;
            const titleLines = wrapGraphText(node.label, layout.labelChars, 2);
            return (
              <g key={`${node.id}-${index}`} transform={`translate(${node.x} ${node.y})`}>
                <rect
                  width={layout.nodeWidth}
                  height={layout.nodeHeight}
                  rx="14"
                  // CSS drop-shadow rather than an feDropShadow flood: it takes
                  // the theme's shadow token directly, so the node lift follows
                  // the theme instead of flooding fixed black in light mode.
                  style={{
                    fill: style.fill,
                    stroke: style.stroke,
                    filter: "drop-shadow(0 2px 6px var(--shadow-color))",
                  }}
                  strokeWidth="2"
                  strokeDasharray={summaryNode ? "6 4" : undefined}
                />
                <text
                  x="14"
                  y="20"
                  style={{ fill: style.accent }}
                  fontSize="9"
                  fontWeight="700"
                  letterSpacing="1.4"
                  fontFamily="var(--font-mono), monospace"
                >
                  {roleLabel.toUpperCase()}
                </text>
                <text
                  x="14"
                  y="40"
                  style={{ fill: style.text }}
                  fontSize="13"
                  fontWeight="600"
                  fontFamily="var(--font-sans), system-ui"
                >
                  {titleLines.map((line, lineIndex) => (
                    <tspan key={`${node.id}-line-${lineIndex}`} x="14" dy={lineIndex === 0 ? 0 : 15}>
                      {line}
                    </tspan>
                  ))}
                </text>
                {node.subtitle ? (
                  <text
                    x="14"
                    y={titleLines.length > 1 ? 72 : 58}
                    style={{ fill: "var(--text-secondary)" }}
                    fontSize="10"
                    fontFamily="var(--font-sans), system-ui"
                  >
                    {truncateGraphText(node.subtitle, 24)}
                  </text>
                ) : null}
                <title>{`${roleLabel}: ${node.label}${node.subtitle ? ` · ${node.subtitle}` : ""}`}</title>
              </g>
            );
          })}
        </svg>
        </div>
        )}
      </div>

      {collapsible ? (
        <div className="ep-board-controls">
          <button
            type="button"
            aria-expanded={expanded}
            onClick={() => setExpanded((current) => !current)}
            className="ep-board-toggle"
          >
            {expanded ? "Return to ordered path" : "Open full-width diagram"}
          </button>
          <span className="text-[color:var(--text-tertiary)]">
            {expanded
              ? "Full-width diagram — scroll horizontally."
              : `All ${layout.totalHopCount} hops shown in order.`}
          </span>
        </div>
      ) : null}
    </div>
  );
}

function pathRelationship(path: ExposurePath, index: number): string | undefined {
  if (index === 0) return undefined;
  const previous = path.hops[index - 1];
  const current = path.hops[index];
  if (!previous || !current) return undefined;
  return path.relationships.find(
    (candidate) => candidate.source === previous.id && candidate.target === current.id,
  )?.relationship;
}

function ExposurePathSequence({
  path,
  showDesktop,
}: {
  path: ExposurePath;
  showDesktop: boolean;
}) {
  return (
    <ol
      aria-label={`Selected exposure path ordered steps for ${pathDisplayTitle(path)}`}
      className={`space-y-0 p-2 ${showDesktop ? "sm:grid sm:grid-cols-2 sm:gap-2 lg:grid-cols-4" : "sm:hidden"}`}
      data-testid="exposure-path-sequence"
    >
      {path.hops.map((hop, index) => {
        const meta = ROLE_META[hop.role] ?? ROLE_META.unknown;
        const Icon = meta.icon;
        const roleLabel = hop.kindLabel ?? meta.label;
        const relationship = pathRelationship(path, index);
        return (
          <li
            key={`${hop.id}-${index}`}
            className="relative min-w-0"
          >
            {index > 0 ? (
              <div className="ep-sequence-relationship">
                <ChevronRight className="hidden h-3.5 w-3.5 shrink-0 sm:block" aria-hidden="true" />
                <span className="ep-sequence-relationship-label" title={relationship ? humanizeRelationship(relationship) : "Relationship not recorded"}>
                  {relationship ? humanizeRelationship(relationship) : "Relationship not recorded"}
                </span>
              </div>
            ) : (
              <div className="ep-sequence-entry">
                Entry point
              </div>
            )}
            <div className={`ep-sequence-card ${meta.tint}`}>
              <span className="ep-sequence-icon">
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              </span>
              <div className="min-w-0">
                <p className="ep-sequence-role">
                  {index + 1}. {roleLabel}
                </p>
                <p className="ep-sequence-title" title={hop.label}>
                  {hop.label}
                </p>
                {hop.subtitle ? (
                  <p className="ep-sequence-subtitle" title={hop.subtitle}>
                    {hop.subtitle}
                  </p>
                ) : null}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function ExposurePathHopTitle({ hops }: { hops: ExposureEntityRef[] }) {
  /** Single-row scrollable hop chips — never wrap mid-chain. */
  return (
    <div
      className="ep-hop-title"
      aria-hidden="true"
      data-testid="exposure-path-hop-title"
    >
      {hops.map((hop, index) => {
        const meta = ROLE_META[hop.role] ?? ROLE_META.unknown;
        return (
          <div key={`${hop.id}-${index}`} className="ep-hop">
            {index > 0 ? (
              <ChevronRight className="ep-hop-arrow" aria-hidden="true" />
            ) : null}
            <span
              title={hop.label}
              className={`ep-hop-chip ${meta.tint}`}
            >
              {formatExposureEntityTitle(hop.label, hop.role)}
            </span>
          </div>
        );
      })}
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
    <div className="ep-evidence-row">
      <div className="ep-evidence-label">{label}</div>
      <div className="ep-evidence-values">
        {(values.length > 0 ? values : [emptyLabel]).slice(0, 3).map((value) => (
          <span
            key={`${label}-${value}`}
            className="ep-evidence-chip"
          >
            {value}
          </span>
        ))}
        {values.length > 3 && (
          <span className="ep-evidence-more">
            +{values.length - 3}
          </span>
        )}
      </div>
    </div>
  );
}
