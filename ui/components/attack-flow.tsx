"use client";

import { useState, useCallback, useMemo, useEffect } from "react";
import Link from "next/link";
import {
  ReactFlow, Background, Controls, MiniMap, Handle, Position,
  useReactFlow, ReactFlowProvider,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ArrowLeft, Loader2, AlertTriangle, Bug, Package, Server,
  ShieldAlert, KeyRound, Wrench, X, Download, Filter, ExternalLink,
} from "lucide-react";
import {
  api, type ScanJob, type BlastRadius, severityColor,
  OWASP_LLM_TOP10, OWASP_MCP_TOP10, MITRE_ATLAS,
} from "@/lib/api";
import type { AttackFlowNodeData, AttackFlowResponse } from "@/lib/api";
import { FrameworkTagChips } from "@/components/framework-tag-chips";
import { SeverityBadge } from "@/components/severity-badge";
import { CONTROLS_CLASS, MINIMAP_CLASS, BACKGROUND_COLOR, BACKGROUND_GAP, ATTACK_FLOW_MINIMAP_COLORS, graphNodeDisplayLabels, readableGraphEdges } from "@/lib/graph-utils";
import { getOsvVulnerabilityUrl } from "@/lib/vulnerabilities";
import { FullscreenButton, GraphInteractionToolbar } from "@/components/graph-chrome";
import { useGraphPresentation } from "@/hooks/use-graph-presentation";
import { graphTopologyKey } from "@/lib/graph-presentation";
import { useAuthState } from "@/components/auth-provider";

// ─── Constants ──────────────────────────────────────────────────────────────

const NODE_ICONS: Record<string, React.ElementType> = {
  cve: Bug, package: Package, server: Server,
  agent: ShieldAlert, credential: KeyRound, tool: Wrench,
};

const NODE_COLORS: Record<string, string> = {
  cve: "border-red-600 bg-red-950/80",
  package: "border-[var(--border-strong)] bg-[var(--surface)]/80",
  server: "border-blue-600 bg-blue-950/80",
  agent: "border-emerald-600 bg-emerald-950/80",
  credential: "border-yellow-600 bg-yellow-950/80",
  tool: "border-purple-600 bg-purple-950/80",
};

// ─── Custom Node ────────────────────────────────────────────────────────────

function AttackFlowNode({ data }: { data: AttackFlowNodeData }) {
  const nodeType = data.nodeType;
  const Icon = NODE_ICONS[nodeType] ?? Bug;

  let colorClass = NODE_COLORS[nodeType] ?? NODE_COLORS.cve;
  if (nodeType === "cve" && data.severity) {
    const sev = data.severity.toLowerCase();
    if (sev === "critical") colorClass = "border-red-600 bg-red-950/80";
    else if (sev === "high") colorClass = "border-orange-600 bg-orange-950/80";
    else if (sev === "medium") colorClass = "border-yellow-600 bg-yellow-950/80";
    else colorClass = "border-blue-600 bg-blue-950/80";
  }

  const showTarget = nodeType !== "cve";
  const showSource = nodeType !== "agent" && nodeType !== "credential" && nodeType !== "tool";

  return (
    <div className={`attack-flow-node ${colorClass}`}>
      {showTarget && <Handle type="target" position={Position.Left} className="attack-flow-handle" />}
      <div className="flex items-center gap-1.5 mb-0.5">
        <Icon className="w-3.5 h-3.5 shrink-0" />
        <span className="attack-flow-node-label">{data.label}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1">
        {nodeType === "cve" && data.severity && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${severityColor(data.severity)}`}>{data.severity}</span>
        )}
        {nodeType === "cve" && data.is_kev && (
          <span className="attack-flow-kev">KEV</span>
        )}
        {nodeType === "cve" && data.cvss_score != null && (
          <span className="attack-flow-meta">CVSS {data.cvss_score.toFixed(1)}</span>
        )}
        {nodeType === "package" && data.version && <span className="attack-flow-meta">@{data.version}</span>}
        {nodeType === "package" && data.ecosystem && <span className="attack-flow-meta-muted">{data.ecosystem}</span>}
        {nodeType === "agent" && data.agent_type && <span className="attack-flow-meta">{data.agent_type}</span>}
      </div>
      {nodeType === "cve" && (data.owasp_tags?.length || data.atlas_tags?.length || data.owasp_mcp_tags?.length) ? (
        <div className="flex flex-wrap gap-0.5 mt-1">
          {data.owasp_tags?.slice(0, 2).map((tag) => (
            <span key={tag} className="attack-flow-tag attack-flow-tag-purple">{tag}</span>
          ))}
          {data.owasp_mcp_tags?.slice(0, 2).map((tag) => (
            <span key={tag} className="attack-flow-tag attack-flow-tag-amber">{tag}</span>
          ))}
          {data.atlas_tags?.slice(0, 1).map((tag) => (
            <span key={tag} className="attack-flow-tag attack-flow-tag-cyan">{tag}</span>
          ))}
        </div>
      ) : null}
      {showSource && <Handle type="source" position={Position.Right} className="attack-flow-handle" />}
    </div>
  );
}

const nodeTypes = { attackFlowNode: AttackFlowNode };

// ─── Detail Panel ───────────────────────────────────────────────────────────

function DetailPanel({ data, onClose }: { data: AttackFlowNodeData; onClose: () => void }) {
  const typeLabels: Record<string, string> = { cve: "Vulnerability", package: "Package", server: "MCP Server", agent: "Agent", credential: "Credential", tool: "Tool" };
  const borderColors: Record<string, string> = { cve: "border-red-700", package: "border-[var(--border-subtle)]", server: "border-blue-700", agent: "border-emerald-700", credential: "border-yellow-700", tool: "border-purple-700" };
  const osvUrl = data.nodeType === "cve" ? getOsvVulnerabilityUrl(data.label) : null;

  return (
    <div className={`absolute right-0 top-0 bottom-0 w-80 bg-[var(--background)]/95 backdrop-blur-sm border-l ${borderColors[data.nodeType] ?? "border-[var(--border-subtle)]"} z-50 overflow-y-auto`}>
      <div className="p-4 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <span className="attack-flow-drawer-kicker">{typeLabels[data.nodeType] ?? data.nodeType}</span>
            <h3 className="attack-flow-drawer-title">{data.label}</h3>
          </div>
          <button onClick={onClose} className="attack-flow-close"><X className="w-4 h-4" /></button>
        </div>
        {data.nodeType === "cve" && (
          <div className="space-y-3">
            {data.severity && <SeverityBadge severity={data.severity} />}
            <div className="grid grid-cols-2 gap-2">
              {data.cvss_score != null && <div className="bg-[var(--surface)] rounded-lg p-2 text-center"><div className="attack-flow-stat-value">{data.cvss_score.toFixed(1)}</div><div className="text-[10px] text-[var(--text-tertiary)]">CVSS</div></div>}
              {data.epss_score != null && <div className="bg-[var(--surface)] rounded-lg p-2 text-center"><div className="attack-flow-stat-value">{(data.epss_score * 100).toFixed(1)}%</div><div className="text-[10px] text-[var(--text-tertiary)]">EPSS</div></div>}
            </div>
            {data.is_kev && <div className="attack-flow-kev-banner"><AlertTriangle className="w-3 h-3" />CISA Known Exploited Vulnerability</div>}
            {data.fixed_version && <div className="text-xs text-[var(--text-secondary)]">Fix available: <span className="text-emerald-400 font-mono font-semibold">{data.fixed_version}</span></div>}
            {data.owasp_tags && data.owasp_tags.length > 0 && <FrameworkTags title="OWASP LLM Top 10" tags={data.owasp_tags} catalog={OWASP_LLM_TOP10} tone="owasp" />}
            {data.owasp_mcp_tags && data.owasp_mcp_tags.length > 0 && <FrameworkTags title="OWASP MCP Top 10" tags={data.owasp_mcp_tags} catalog={OWASP_MCP_TOP10} tone="mcp" />}
            {data.atlas_tags && data.atlas_tags.length > 0 && <FrameworkTags title="MITRE ATLAS" tags={data.atlas_tags} catalog={MITRE_ATLAS} tone="atlas" />}
            {data.risk_score != null && <div className="text-xs text-[var(--text-secondary)]">Risk score: <span className="text-red-400 font-mono font-bold">{data.risk_score}</span></div>}
            {osvUrl && (
              <a href={osvUrl} target="_blank" rel="noopener noreferrer" className="attack-flow-external-link">
                <ExternalLink className="w-3 h-3" />View on OSV
              </a>
            )}
          </div>
        )}
        {data.nodeType === "package" && <div className="space-y-2">{data.version && <div className="text-xs text-[var(--text-secondary)] font-mono">Version: {data.version}</div>}{data.ecosystem && <div className="text-xs text-[var(--text-secondary)] font-mono">Ecosystem: {data.ecosystem}</div>}</div>}
        {data.nodeType === "server" && <div className="text-xs text-[var(--text-secondary)]">MCP server in the supply chain</div>}
        {data.nodeType === "agent" && <div className="space-y-2">{data.agent_type && <div className="text-xs text-[var(--text-secondary)] font-mono">Type: {data.agent_type}</div>}{data.status && <div className={`text-xs px-2 py-1 rounded border font-mono ${data.status === "installed-not-configured" ? "border-yellow-800 bg-yellow-950 text-yellow-400" : "border-emerald-800 bg-emerald-950 text-emerald-400"}`}>{data.status === "installed-not-configured" ? "Not Configured" : "Configured"}</div>}</div>}
        {data.nodeType === "credential" && <div className="space-y-2"><div className="flex items-center gap-1.5 text-xs text-amber-400"><KeyRound className="w-3 h-3" />Exposed credential env var</div><div className="text-xs text-[var(--text-secondary)]">This credential is accessible through a vulnerable MCP server in the supply chain.</div></div>}
        {data.nodeType === "tool" && <div className="space-y-2"><div className="flex items-center gap-1.5 text-xs text-purple-400"><Wrench className="w-3 h-3" />Reachable MCP tool</div><div className="text-xs text-[var(--text-secondary)]">This tool is exposed through a vulnerable MCP server and could be invoked by an attacker.</div></div>}
      </div>
    </div>
  );
}

function FrameworkTags({ title, tags, catalog, tone }: { title: string; tags: string[]; catalog: Record<string, string>; tone: "owasp" | "mcp" | "atlas" }) {
  return (
    <div>
      <div className="attack-flow-filter-label">{title}</div>
      {/* One row per technique put 36 rows in a node panel for a single CVE.
          Wrapped chips behind a disclosure keep the panel a panel. */}
      <div className="flex flex-wrap items-center gap-1">
        <FrameworkTagChips tags={tags} catalog={catalog} tone={tone} showNames visible={4} />
      </div>
    </div>
  );
}

// ─── Export Button ───────────────────────────────────────────────────────────

function ExportButton() {
  const { getNodes, getEdges } = useReactFlow();
  const handleExport = useCallback(() => {
    const flowData = { nodes: getNodes(), edges: getEdges() };
    const blob = new Blob([JSON.stringify(flowData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `attack-flow-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  }, [getNodes, getEdges]);

  return (
    <button onClick={handleExport} className="attack-flow-export">
      <Download className="w-3 h-3" />Export JSON
    </button>
  );
}

// ─── Filter Bar ─────────────────────────────────────────────────────────────

interface AttackFlowFilters { cve: string; severity: string; framework: string; agent: string; }

function FilterBar({ filters, onChange, blastRadius }: { filters: AttackFlowFilters; onChange: (f: AttackFlowFilters) => void; blastRadius: BlastRadius[] }) {
  const cveIds = useMemo(() => Array.from(new Set(blastRadius.map((br) => br.vulnerability_id))).sort(), [blastRadius]);
  const frameworkTags = useMemo(() => {
    const tags = new Set<string>();
    for (const br of blastRadius) {
      for (const t of br.owasp_tags ?? []) tags.add(t);
      for (const t of br.owasp_mcp_tags ?? []) tags.add(t);
      for (const t of br.atlas_tags ?? []) tags.add(t);
      for (const t of br.nist_ai_rmf_tags ?? []) tags.add(t);
    }
    return Array.from(tags).sort();
  }, [blastRadius]);
  const agentNames = useMemo(() => Array.from(new Set(blastRadius.flatMap((br) => br.affected_agents))).sort(), [blastRadius]);
  const severities = ["critical", "high", "medium", "low"];
  const activeSev = filters.severity.toLowerCase();

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <Filter className="w-3.5 h-3.5 text-[var(--text-tertiary)]" />
      <select value={filters.cve} onChange={(e) => onChange({ ...filters, cve: e.target.value })} className="attack-flow-select">
        <option value="">All CVEs</option>
        {cveIds?.map((id) => <option key={id} value={id}>{id}</option>)}
      </select>
      <div className="flex gap-0.5">
        {severities?.map((sev) => (
          <button key={sev} onClick={() => onChange({ ...filters, severity: activeSev === sev ? "" : sev })} className={`text-[10px] font-mono uppercase px-2 py-1 rounded border transition-colors ${activeSev === sev ? severityColor(sev) : "border-[var(--border-subtle)] bg-[var(--surface)] text-[var(--text-tertiary)] hover:border-[var(--border-strong)]"}`}>{sev}</button>
        ))}
      </div>
      {frameworkTags.length > 0 && (
        <select value={filters.framework} onChange={(e) => onChange({ ...filters, framework: e.target.value })} className="attack-flow-select">
          <option value="">All Frameworks</option>
          {frameworkTags?.map((tag) => <option key={tag} value={tag}>{tag} {OWASP_LLM_TOP10[tag] ? `- ${OWASP_LLM_TOP10[tag]}` : OWASP_MCP_TOP10[tag] ? `- ${OWASP_MCP_TOP10[tag]}` : MITRE_ATLAS[tag] ? `- ${MITRE_ATLAS[tag]}` : ""}</option>)}
        </select>
      )}
      {agentNames.length > 0 && (
        <select value={filters.agent} onChange={(e) => onChange({ ...filters, agent: e.target.value })} className="attack-flow-select">
          <option value="">All Agents</option>
          {agentNames?.map((name) => <option key={name} value={name}>{name}</option>)}
        </select>
      )}
      {(filters.cve || filters.severity || filters.framework || filters.agent) && (
        <button onClick={() => onChange({ cve: "", severity: "", framework: "", agent: "" })} className="attack-flow-clear-small">Clear filters</button>
      )}
    </div>
  );
}

// ─── Stats Bar ──────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: AttackFlowResponse["stats"] }) {
  const items = [
    { label: "CVEs", value: stats.total_cves, color: "text-red-400" },
    { label: "Packages", value: stats.total_packages, color: "text-[var(--text-secondary)]" },
    { label: "Servers", value: stats.total_servers, color: "text-blue-400" },
    { label: "Agents", value: stats.total_agents, color: "text-emerald-400" },
    { label: "Credentials", value: stats.total_credentials, color: "text-yellow-400" },
    { label: "Tools", value: stats.total_tools, color: "text-purple-400" },
  ];
  return (
    <div className="flex items-center gap-3">
      {items.filter((i) => i.value > 0).map((item) => (
        <span key={item.label} className="flex items-center gap-1 text-xs">
          <span className={`font-mono font-bold ${item.color}`}>{item.value}</span>
          <span className="text-[var(--text-tertiary)]">{item.label}</span>
        </span>
      ))}
      <span className="text-[var(--text-tertiary)]">|</span>
      {Object.entries(stats.severity_counts).filter(([, v]) => v > 0).map(([sev, count]) => (
        <span key={sev} className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border ${severityColor(sev)}`}>{count} {sev}</span>
      ))}
    </div>
  );
}

// ─── Flow Content ───────────────────────────────────────────────────────────

function AttackFlowContent({ id, job, flowData, filters, onFiltersChange }: { id: string; job: ScanJob; flowData: AttackFlowResponse; filters: AttackFlowFilters; onFiltersChange: (f: AttackFlowFilters) => void }) {
  const { session, loading: authLoading } = useAuthState();
  const [selectedNode, setSelectedNode] = useState<AttackFlowNodeData | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const flowInstance = useReactFlow();
  const blastRadius = job.result?.blast_radius ?? [];

  const nodes = useMemo(
    () => flowData.nodes?.map((n) => ({ ...n, type: "attackFlowNode" as const, data: n.data as unknown as Record<string, unknown> })) as Node[],
    [flowData.nodes],
  );
  const edges = useMemo(
    () => readableGraphEdges(flowData.edges as unknown as Edge[], undefined, { nodeLabels: graphNodeDisplayLabels(nodes) }),
    [flowData.edges, nodes],
  );
  const presentation = useGraphPresentation({
    nodes,
    scope: {
      tenantId: session?.tenant_id || "local",
      subject: session?.subject || session?.auth_method || "local-viewer",
      snapshotId: id,
      lens: "attack-flow",
      scope: JSON.stringify({ filters, topology: graphTopologyKey(nodes, edges) }),
    },
    layout: "attack-flow",
    enabled: !authLoading && Boolean(session),
    ownerActive: Boolean(session),
    localMode: session?.recommended_ui_mode === "no_auth",
  });

  const fitVisible = useCallback(
    () => void flowInstance.fitView({ padding: 0.2, duration: 240 }),
    [flowInstance],
  );
  const fitSelection = useCallback(() => {
    const node = selectedNodeId ? flowInstance.getNode(selectedNodeId) : undefined;
    if (node) void flowInstance.fitView({ nodes: [node], padding: 0.7, duration: 240 });
  }, [flowInstance, selectedNodeId]);

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      <div className="attack-flow-header">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href={`/scan?id=${id}`} className="attack-flow-back"><ArrowLeft className="w-4 h-4" /></Link>
            <div>
              <h1 className="text-lg font-semibold text-[var(--foreground)]">Attack Flow</h1>
              <p className="text-xs text-[var(--text-tertiary)]">CVE &rarr; Package &rarr; Server &rarr; Agent blast radius chain</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <StatsBar stats={flowData.stats} />
            {presentation.enabled && nodes.length > 0 && <GraphInteractionToolbar
              editing={presentation.editing}
              hasSelection={Boolean(selectedNodeId)}
              onFitVisible={fitVisible}
              onFitSelection={fitSelection}
              onAutoLayout={() => { presentation.autoLayout(); window.setTimeout(fitVisible, 0); }}
              onReset={() => { presentation.reset(); window.setTimeout(fitVisible, 0); }}
              onToggleEditing={presentation.toggleEditing}
            />}
            <FullscreenButton />
            <ExportButton />
          </div>
        </div>
        <FilterBar filters={filters} onChange={onFiltersChange} blastRadius={blastRadius} />
      </div>
      <div className="flex-1 relative">
        {flowData.nodes.length === 0 ? (
          <div className="attack-flow-empty">
            <Filter className="w-8 h-8 text-[var(--text-tertiary)]" />
            <p className="text-sm">No results match the current filters</p>
            <button onClick={() => onFiltersChange({ cve: "", severity: "", framework: "", agent: "" })} className="attack-flow-clear">Clear all filters</button>
          </div>
        ) : (
          <ReactFlow
            key={presentation.storageKey}
            nodes={presentation.nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView={!presentation.hasSavedState}
            defaultViewport={presentation.viewport}
            minZoom={0.1}
            maxZoom={2}
            deleteKeyCode={null}
            nodesDraggable={presentation.editing}
            nodesConnectable={false}
            onNodesChange={presentation.onNodesChange}
            onNodeDragStop={presentation.onNodeDragStop}
            onMoveEnd={presentation.onMoveEnd}
            defaultEdgeOptions={{ type: "smoothstep" }}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_event, node) => { setSelectedNode(node.data as unknown as AttackFlowNodeData); setSelectedNodeId(node.id); }}
            onPaneClick={() => { setSelectedNode(null); setSelectedNodeId(null); }}
          >
            <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
            <Controls className={CONTROLS_CLASS} />
            <MiniMap nodeColor={(n) => { const d = n.data as unknown as AttackFlowNodeData; return ATTACK_FLOW_MINIMAP_COLORS[d.nodeType] ?? "#52525b"; }} className={MINIMAP_CLASS} />
          </ReactFlow>
        )}
        {selectedNode && <DetailPanel data={selectedNode} onClose={() => { setSelectedNode(null); setSelectedNodeId(null); }} />}
      </div>
      <div className="attack-flow-legend">
        <span className="flex items-center gap-1"><span className="attack-flow-swatch border-red-600 bg-red-950" /> CVE</span>
        <span className="flex items-center gap-1"><span className="attack-flow-swatch border-[var(--border-strong)] bg-[var(--surface)]" /> Package</span>
        <span className="flex items-center gap-1"><span className="attack-flow-swatch border-blue-600 bg-blue-950" /> Server</span>
        <span className="flex items-center gap-1"><span className="attack-flow-swatch border-emerald-600 bg-emerald-950" /> Agent</span>
        <span className="flex items-center gap-1"><span className="attack-flow-swatch border-yellow-600 bg-yellow-950" /> Credential</span>
        <span className="flex items-center gap-1"><span className="attack-flow-swatch border-purple-600 bg-purple-950" /> Tool</span>
      </div>
    </div>
  );
}

// ─── Attack Flow View (main export) ─────────────────────────────────────────

export function AttackFlowView({ id }: { id: string }) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [flowData, setFlowData] = useState<AttackFlowResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<AttackFlowFilters>({ cve: "", severity: "", framework: "", agent: "" });

  useEffect(() => { api.getScan(id).then(setJob).catch((e) => setError(e.message)); }, [id]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLoading(true);
      const filterParams: Record<string, string> = {};
      if (filters.cve) filterParams.cve = filters.cve;
      if (filters.severity) filterParams.severity = filters.severity;
      if (filters.framework) filterParams.framework = filters.framework;
      if (filters.agent) filterParams.agent = filters.agent;
      api.getAttackFlow(id, Object.keys(filterParams).length > 0 ? filterParams : undefined).then(setFlowData).catch((e) => setError(e.message)).finally(() => setLoading(false));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [id, filters]);

  if (loading && !flowData) return <div className="attack-flow-loading"><Loader2 className="w-5 h-5 animate-spin mr-2" />Loading attack flow...</div>;
  if (error) return <div className="attack-flow-error"><AlertTriangle className="w-8 h-8 text-amber-500" /><p className="text-sm">Could not load attack flow</p><p className="text-xs text-[var(--text-tertiary)]">{error}</p><Link href={`/scan?id=${id}`} className="attack-flow-clear">Back to scan results</Link></div>;
  if (!job || !flowData) return null;

  return <ReactFlowProvider><AttackFlowContent id={id} job={job} flowData={flowData} filters={filters} onFiltersChange={setFilters} /></ReactFlowProvider>;
}
