"use client";

import Link from "next/link";
import type { LucideIcon } from "lucide-react";
import {
  Bot,
  Bug,
  CheckCircle2,
  Database,
  KeyRound,
  Package,
  Route,
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

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_280px]">
        <div>
          <p className="text-[10px] uppercase tracking-[0.2em] text-orange-400">Command center</p>
          <h2 className="mt-1 text-lg font-semibold text-[color:var(--foreground)]">{pathDisplayTitle(path)}</h2>
          <p className="mt-2 max-w-4xl text-sm leading-6 text-[color:var(--text-secondary)]">
            {path.summary ||
              evidence?.attackVectorSummary ||
              "Selected exposure path with the entities, relationships, and evidence needed to choose the first fix."}
          </p>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <CommandMetric label="Risk" value={path.riskScore.toFixed(1)} tone="red" />
          <CommandMetric label="Hops" value={String(Math.max(0, path.hops.length - 1))} />
          <CommandMetric label="Agents" value={String(path.affectedAgents.length)} />
          <CommandMetric label="Fix" value={fixLabel ?? "triage"} tone={fixLabel ? "green" : "zinc"} />
        </div>
      </div>

      <section aria-label="Investigation brief" className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        {investigationBrief.map((item) => (
          <div
            key={item.label}
            className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2"
          >
            <div className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">{item.label}</div>
            <div className="mt-1 text-sm font-semibold leading-5 text-[color:var(--foreground)]">{item.value}</div>
            {item.detail && <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)]">{item.detail}</p>}
          </div>
        ))}
      </section>

      <section aria-label="Selected exposure path graph">
        <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
          <Route className="h-3.5 w-3.5" />
          Selected path graph
        </div>
        <ExposurePathGraph path={path} />
      </section>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <section aria-label="Relationship proof">
          <div className="mb-2 text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
            Relationship proof
          </div>
          <div className="max-h-64 overflow-y-auto divide-y divide-[color:var(--border-subtle)] rounded-xl border border-[color:var(--border-subtle)]">
            {path.relationships.slice(0, 5).map((relationship) => (
              <div key={relationship.id} className="grid gap-2 px-3 py-2 text-xs md:grid-cols-[1fr_auto]">
                <div className="min-w-0">
                  <span className="font-mono text-[color:var(--foreground)]">{relationship.relationship}</span>
                  <span className="ml-2 break-all text-[color:var(--text-tertiary)]">
                    {relationship.source} → {relationship.target}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                  <span>{relationship.direction ?? "directed"}</span>
                  <span>{relationship.traversable === false ? "blocked" : "traversable"}</span>
                  {relationship.confidence && <span>{relationship.confidence}</span>}
                </div>
              </div>
            ))}
            {path.relationships.length === 0 && (
              <div className="px-3 py-3 text-xs text-[color:var(--text-secondary)]">No relationship evidence attached.</div>
            )}
          </div>
        </section>

        <aside aria-label="Evidence drawer" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
          <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Evidence drawer</div>
          <EvidenceRow label="Findings" values={path.findings} />
          <EvidenceRow label="Agents" values={path.affectedAgents} />
          <EvidenceRow label="Servers" values={path.affectedServers} />
          <EvidenceRow label="Tools" values={path.reachableTools} emptyLabel="none" />
          <EvidenceRow label="Credentials" values={path.exposedCredentials} emptyLabel="none" />
          <div className="rounded-xl border border-[color:var(--border-subtle)] px-3 py-2 text-xs">
            <div className="flex items-center gap-2 text-[color:var(--text-secondary)]">
              <ShieldAlert className="h-3.5 w-3.5 text-red-300" />
              <span>CVSS {evidence?.cvssScore ?? "n/a"}</span>
              <span>EPSS {typeof evidence?.epssScore === "number" ? evidence.epssScore.toFixed(3) : "n/a"}</span>
              {evidence?.isKev && <span className="font-semibold text-red-300">KEV</span>}
            </div>
          </div>
        </aside>
      </div>

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

function buildInvestigationBrief(path: ExposurePath, fixLabel: string | undefined) {
  const exposed = firstNonEmpty(path.exposedCredentials, path.reachableTools, path.affectedServers, path.affectedAgents);
  const finding = path.findings[0] ?? path.target.label;
  const proofCount = path.relationships.length;
  const evidence = path.evidence;
  const riskSignals = [
    evidence?.isKev ? "KEV" : "",
    typeof evidence?.epssScore === "number" ? `EPSS ${evidence.epssScore.toFixed(3)}` : "",
    typeof evidence?.cvssScore === "number" ? `CVSS ${evidence.cvssScore}` : "",
  ].filter(Boolean);

  return [
    {
      label: "What is exposed",
      value: exposed.value,
      detail: exposed.label,
    },
    {
      label: "Why it matters",
      value: finding,
      detail: riskSignals.length > 0 ? riskSignals.join(" · ") : path.severity || "ranked by graph risk",
    },
    {
      label: "What proves it",
      value: `${proofCount} relationship${proofCount === 1 ? "" : "s"}`,
      detail: path.provenance?.source ?? "graph evidence",
    },
    {
      label: "What fixes it",
      value: fixLabel ?? "triage path",
      detail: path.fix?.version ? `Target ${path.fix.version}` : primaryFixDetail(path),
    },
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
    <div className="overflow-x-auto rounded-2xl border border-[color:var(--border-subtle)] bg-[#05070b]">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        role="img"
        aria-label={`Selected exposure path graph for ${pathDisplayTitle(path)}`}
        className="block h-auto min-w-[760px] md:min-w-0 md:w-full"
      >
        <defs>
          <marker id="exposure-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#94a3b8" />
          </marker>
          <filter id="node-shadow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="10" stdDeviation="10" floodColor="#000000" floodOpacity="0.35" />
          </filter>
        </defs>

        <rect x="0" y="0" width={layout.width} height={layout.height} fill="#05070b" />
        <g opacity="0.18">
          {Array.from({ length: 10 }).map((_, index) => (
            <line key={index} x1="0" y1={34 + index * 38} x2={layout.width} y2={34 + index * 38} stroke="#334155" strokeWidth="1" />
          ))}
        </g>

        {layout.edges.map((edge) => (
          <path
            key={edge.id}
            d={edge.path}
            fill="none"
            stroke={edge.stroke}
            strokeWidth="3"
            strokeLinecap="round"
            markerEnd="url(#exposure-arrow)"
            opacity="0.88"
          >
            <title>{edge.label}</title>
          </path>
        ))}

        {layout.relationshipLabels.map((label) => (
          <g key={label.id} transform={`translate(${label.x} ${label.y})`}>
            <rect x="-52" y="-11" width="104" height="22" rx="11" fill="#0f172a" stroke="#334155" />
            <text x="0" y="4" textAnchor="middle" fill="#cbd5e1" fontSize="11" fontFamily="var(--font-mono), monospace">
              {label.text}
            </text>
          </g>
        ))}

        {layout.nodes.map((node, index) => {
          const style = GRAPH_ROLE_STYLE[node.role] ?? GRAPH_ROLE_STYLE.unknown;
          const meta = ROLE_META[node.role] ?? ROLE_META.unknown;
          return (
            <g key={`${node.id}-${index}`} transform={`translate(${node.x} ${node.y})`} filter="url(#node-shadow)">
              <rect width={layout.nodeWidth} height={layout.nodeHeight} rx="14" fill={style.fill} stroke={style.stroke} strokeWidth="2" />
              <circle cx="18" cy="20" r="5" fill={style.accent} />
              <text x="32" y="24" fill={style.accent} fontSize="10" fontWeight="700" letterSpacing="2" fontFamily="var(--font-mono), monospace">
                {meta.label.toUpperCase()}
              </text>
              <text x="16" y="50" fill={style.text} fontSize="16" fontWeight="700" fontFamily="var(--font-sans), system-ui">
                {truncateGraphText(node.label, 17)}
              </text>
              {node.severity && (
                <text x="16" y="70" fill="#94a3b8" fontSize="11" letterSpacing="1.4" fontFamily="var(--font-mono), monospace">
                  {String(node.severity).toUpperCase()}
                </text>
              )}
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
  const nodeWidth = 178;
  const nodeHeight = 84;
  const columns = Math.min(3, Math.max(1, path.hops.length));
  const rows = Math.max(1, Math.ceil(path.hops.length / columns));
  const xGap = columns > 1 ? (width - nodeWidth - 64) / (columns - 1) : 0;
  const yGap = 138;
  const height = 52 + rows * nodeHeight + (rows - 1) * (yGap - nodeHeight) + 36;
  const nodes = path.hops.map((hop, index) => {
    const row = Math.floor(index / columns);
    const col = index % columns;
    const visualCol = row % 2 === 0 ? col : columns - 1 - col;
    return {
      ...hop,
      x: 32 + visualCol * xGap,
      y: 38 + row * yGap,
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
    const control = sameRow ? Math.max(48, Math.abs(endX - startX) / 2) : 70;
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
      labelY: sameRow ? startY - 16 : (source.y + target.y + nodeHeight) / 2,
    };
  });
  const relationshipLabels = edges.map((edge) => ({
    id: `${edge.id}:label`,
    text: truncateGraphText(edge.label, 14),
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

function CommandMetric({ label, value, tone = "zinc" }: { label: string; value: string; tone?: "red" | "green" | "zinc" }) {
  const toneClass =
    tone === "red"
      ? "border-red-500/25 bg-red-500/10 text-red-200"
      : tone === "green"
        ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-200"
        : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]";

  return (
    <div className={`rounded-xl border px-3 py-2 ${toneClass}`}>
      <div className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="mt-1 truncate font-mono text-sm font-semibold">{value}</div>
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
    <div className="rounded-xl border border-[color:var(--border-subtle)] px-3 py-2 text-xs">
      <div className="mb-1 text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {(values.length > 0 ? values : [emptyLabel]).slice(0, 4).map((value) => (
          <span
            key={`${label}-${value}`}
            className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-0.5 text-[color:var(--text-secondary)]"
          >
            {value}
          </span>
        ))}
        {values.length > 4 && (
          <span className="rounded border border-[color:var(--border-subtle)] px-2 py-0.5 text-[color:var(--text-tertiary)]">
            +{values.length - 4}
          </span>
        )}
      </div>
    </div>
  );
}
