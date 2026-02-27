"use client";

import { use, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  useReactFlow,
  ReactFlowProvider,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ArrowLeft,
  Bug,
  Download,
  Filter,
  KeyRound,
  Loader2,
  Package,
  Server,
  ShieldAlert,
  Wrench,
  X,
  ExternalLink,
  AlertTriangle,
} from "lucide-react";
import {
  api,
  type AttackFlowNodeData,
  type AttackFlowResponse,
  type ScanJob,
  type BlastRadius,
  severityColor,
  OWASP_LLM_TOP10,
  OWASP_MCP_TOP10,
  MITRE_ATLAS,
} from "@/lib/api";
import { SeverityBadge } from "@/components/severity-badge";

// ─── Constants ───────────────────────────────────────────────────────────────

const NODE_ICONS: Record<string, React.ElementType> = {
  cve: Bug,
  package: Package,
  server: Server,
  agent: ShieldAlert,
  credential: KeyRound,
  tool: Wrench,
};

const NODE_COLORS: Record<string, string> = {
  cve: "border-red-600 bg-red-950/80",
  package: "border-zinc-600 bg-zinc-900/80",
  server: "border-blue-600 bg-blue-950/80",
  agent: "border-emerald-600 bg-emerald-950/80",
  credential: "border-yellow-600 bg-yellow-950/80",
  tool: "border-purple-600 bg-purple-950/80",
};

const NODE_MINIMAP_COLORS: Record<string, string> = {
  cve: "#ef4444",
  package: "#52525b",
  server: "#3b82f6",
  agent: "#10b981",
  credential: "#eab308",
  tool: "#a855f7",
};

// ─── Custom Node Component ──────────────────────────────────────────────────

function AttackFlowNode({ data }: { data: AttackFlowNodeData }) {
  const nodeType = data.nodeType;
  const Icon = NODE_ICONS[nodeType] ?? Bug;

  // Severity-aware CVE coloring
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
    <div className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[220px] shadow-lg backdrop-blur ${colorClass}`}>
      {showTarget && (
        <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2 !border-zinc-400" />
      )}
      <div className="flex items-center gap-1.5 mb-0.5">
        <Icon className="w-3.5 h-3.5 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>

      {/* Type-specific details */}
      <div className="flex flex-wrap gap-1 mt-1">
        {nodeType === "cve" && data.severity && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${severityColor(data.severity)}`}>
            {data.severity}
          </span>
        )}
        {nodeType === "cve" && data.is_kev && (
          <span className="text-[10px] px-1 py-0.5 rounded border font-mono border-red-700 bg-red-950 text-red-400">
            KEV
          </span>
        )}
        {nodeType === "cve" && data.cvss_score != null && (
          <span className="text-[10px] text-zinc-400 font-mono">CVSS {data.cvss_score.toFixed(1)}</span>
        )}
        {nodeType === "package" && data.version && (
          <span className="text-[10px] text-zinc-400 font-mono">@{data.version}</span>
        )}
        {nodeType === "package" && data.ecosystem && (
          <span className="text-[10px] text-zinc-500 font-mono">{data.ecosystem}</span>
        )}
        {nodeType === "agent" && data.agent_type && (
          <span className="text-[10px] text-zinc-400 font-mono">{data.agent_type}</span>
        )}
      </div>

      {/* Framework tags (CVE nodes only) */}
      {nodeType === "cve" && (data.owasp_tags?.length || data.atlas_tags?.length || data.owasp_mcp_tags?.length) ? (
        <div className="flex flex-wrap gap-0.5 mt-1">
          {data.owasp_tags?.slice(0, 2).map((tag) => (
            <span key={tag} className="text-[9px] font-mono bg-purple-950/60 border border-purple-800/50 text-purple-400 rounded px-1">
              {tag}
            </span>
          ))}
          {data.owasp_mcp_tags?.slice(0, 2).map((tag) => (
            <span key={tag} className="text-[9px] font-mono bg-amber-950/60 border border-amber-800/50 text-amber-400 rounded px-1">
              {tag}
            </span>
          ))}
          {data.atlas_tags?.slice(0, 1).map((tag) => (
            <span key={tag} className="text-[9px] font-mono bg-cyan-950/60 border border-cyan-800/50 text-cyan-400 rounded px-1">
              {tag}
            </span>
          ))}
        </div>
      ) : null}

      {showSource && (
        <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2 !border-zinc-400" />
      )}
    </div>
  );
}

const nodeTypes = { attackFlowNode: AttackFlowNode };

// ─── Detail Panel ────────────────────────────────────────────────────────────

function DetailPanel({ data, onClose }: { data: AttackFlowNodeData; onClose: () => void }) {
  const typeLabels: Record<string, string> = {
    cve: "Vulnerability",
    package: "Package",
    server: "MCP Server",
    agent: "Agent",
    credential: "Credential",
    tool: "Tool",
  };
  const borderColors: Record<string, string> = {
    cve: "border-red-700",
    package: "border-zinc-700",
    server: "border-blue-700",
    agent: "border-emerald-700",
    credential: "border-yellow-700",
    tool: "border-purple-700",
  };

  return (
    <div className={`absolute right-0 top-0 bottom-0 w-80 bg-zinc-950/95 backdrop-blur-sm border-l ${borderColors[data.nodeType] ?? "border-zinc-700"} z-50 overflow-y-auto`}>
      <div className="p-4 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[10px] uppercase tracking-wider text-zinc-500">{typeLabels[data.nodeType] ?? data.nodeType}</span>
            <h3 className="text-sm font-semibold text-zinc-100 mt-0.5 break-all">{data.label}</h3>
          </div>
          <button onClick={onClose} className="p-1 text-zinc-500 hover:text-zinc-300 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* CVE details */}
        {data.nodeType === "cve" && (
          <div className="space-y-3">
            {data.severity && <SeverityBadge severity={data.severity} />}
            <div className="grid grid-cols-2 gap-2">
              {data.cvss_score != null && (
                <div className="bg-zinc-900 rounded-lg p-2 text-center">
                  <div className="text-lg font-bold font-mono text-zinc-100">{data.cvss_score.toFixed(1)}</div>
                  <div className="text-[10px] text-zinc-500">CVSS</div>
                </div>
              )}
              {data.epss_score != null && (
                <div className="bg-zinc-900 rounded-lg p-2 text-center">
                  <div className="text-lg font-bold font-mono text-zinc-100">{(data.epss_score * 100).toFixed(1)}%</div>
                  <div className="text-[10px] text-zinc-500">EPSS</div>
                </div>
              )}
            </div>
            {data.is_kev && (
              <div className="text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-2 py-1.5 flex items-center gap-1.5">
                <AlertTriangle className="w-3 h-3" />
                CISA Known Exploited Vulnerability
              </div>
            )}
            {data.fixed_version && (
              <div className="text-xs text-zinc-400">
                Fix available: <span className="text-emerald-400 font-mono font-semibold">{data.fixed_version}</span>
              </div>
            )}
            {data.owasp_tags && data.owasp_tags.length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">OWASP LLM Top 10</div>
                <div className="space-y-1">
                  {data.owasp_tags.map((tag) => (
                    <div key={tag} className="text-xs font-mono bg-purple-950/40 border border-purple-800/50 text-purple-400 rounded px-2 py-1">
                      {tag} <span className="text-purple-600 font-sans">{OWASP_LLM_TOP10[tag]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.owasp_mcp_tags && data.owasp_mcp_tags.length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">OWASP MCP Top 10</div>
                <div className="space-y-1">
                  {data.owasp_mcp_tags.map((tag) => (
                    <div key={tag} className="text-xs font-mono bg-amber-950/40 border border-amber-800/50 text-amber-400 rounded px-2 py-1">
                      {tag} <span className="text-amber-600 font-sans">{OWASP_MCP_TOP10[tag]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.atlas_tags && data.atlas_tags.length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">MITRE ATLAS</div>
                <div className="space-y-1">
                  {data.atlas_tags.map((tag) => (
                    <div key={tag} className="text-xs font-mono bg-cyan-950/40 border border-cyan-800/50 text-cyan-400 rounded px-2 py-1">
                      {tag} <span className="text-cyan-600 font-sans">{MITRE_ATLAS[tag]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.risk_score != null && (
              <div className="text-xs text-zinc-400">
                Risk score: <span className="text-red-400 font-mono font-bold">{data.risk_score}</span>
              </div>
            )}
            <a
              href={`https://osv.dev/vulnerability/${data.label}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 transition-colors"
            >
              <ExternalLink className="w-3 h-3" />
              View on OSV
            </a>
          </div>
        )}

        {/* Package details */}
        {data.nodeType === "package" && (
          <div className="space-y-2">
            {data.version && <div className="text-xs text-zinc-400 font-mono">Version: {data.version}</div>}
            {data.ecosystem && <div className="text-xs text-zinc-400 font-mono">Ecosystem: {data.ecosystem}</div>}
          </div>
        )}

        {/* Server details */}
        {data.nodeType === "server" && (
          <div className="text-xs text-zinc-400">MCP server in the supply chain</div>
        )}

        {/* Agent details */}
        {data.nodeType === "agent" && (
          <div className="space-y-2">
            {data.agent_type && <div className="text-xs text-zinc-400 font-mono">Type: {data.agent_type}</div>}
            {data.status && (
              <div className={`text-xs px-2 py-1 rounded border font-mono ${
                data.status === "installed-not-configured"
                  ? "border-yellow-800 bg-yellow-950 text-yellow-400"
                  : "border-emerald-800 bg-emerald-950 text-emerald-400"
              }`}>
                {data.status === "installed-not-configured" ? "Not Configured" : "Configured"}
              </div>
            )}
          </div>
        )}

        {/* Credential details */}
        {data.nodeType === "credential" && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-amber-400">
              <KeyRound className="w-3 h-3" />
              Exposed credential env var
            </div>
            <div className="text-xs text-zinc-400">
              This credential is accessible through a vulnerable MCP server in the supply chain.
            </div>
          </div>
        )}

        {/* Tool details */}
        {data.nodeType === "tool" && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-purple-400">
              <Wrench className="w-3 h-3" />
              Reachable MCP tool
            </div>
            <div className="text-xs text-zinc-400">
              This tool is exposed through a vulnerable MCP server and could be invoked by an attacker.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Export Button ────────────────────────────────────────────────────────────

function ExportButton() {
  const { getNodes, getEdges } = useReactFlow();

  const handleExport = useCallback(() => {
    const flowData = { nodes: getNodes(), edges: getEdges() };
    const blob = new Blob([JSON.stringify(flowData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attack-flow-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [getNodes, getEdges]);

  return (
    <button
      onClick={handleExport}
      className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 border border-zinc-700 rounded-lg text-xs text-zinc-300 hover:bg-zinc-700 transition-colors"
    >
      <Download className="w-3 h-3" />
      Export JSON
    </button>
  );
}

// ─── Filter Bar ──────────────────────────────────────────────────────────────

interface Filters {
  cve: string;
  severity: string;
  framework: string;
  agent: string;
}

function FilterBar({
  filters,
  onChange,
  blastRadius,
}: {
  filters: Filters;
  onChange: (f: Filters) => void;
  blastRadius: BlastRadius[];
}) {
  // Extract unique values for dropdowns
  const cveIds = useMemo(() => {
    const ids = new Set<string>();
    for (const br of blastRadius) ids.add(br.vulnerability_id);
    return Array.from(ids).sort();
  }, [blastRadius]);

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

  const agentNames = useMemo(() => {
    const names = new Set<string>();
    for (const br of blastRadius) {
      for (const a of br.affected_agents) names.add(a);
    }
    return Array.from(names).sort();
  }, [blastRadius]);

  const severities = ["critical", "high", "medium", "low"];
  const activeSev = filters.severity.toLowerCase();

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <Filter className="w-3.5 h-3.5 text-zinc-500" />

      {/* CVE dropdown */}
      <select
        value={filters.cve}
        onChange={(e) => onChange({ ...filters, cve: e.target.value })}
        className="bg-zinc-900 border border-zinc-700 rounded-md px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-600"
      >
        <option value="">All CVEs</option>
        {cveIds.map((id) => (
          <option key={id} value={id}>{id}</option>
        ))}
      </select>

      {/* Severity toggle buttons */}
      <div className="flex gap-0.5">
        {severities.map((sev) => (
          <button
            key={sev}
            onClick={() => onChange({ ...filters, severity: activeSev === sev ? "" : sev })}
            className={`text-[10px] font-mono uppercase px-2 py-1 rounded border transition-colors ${
              activeSev === sev
                ? severityColor(sev)
                : "border-zinc-700 bg-zinc-900 text-zinc-500 hover:border-zinc-600"
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Framework dropdown */}
      {frameworkTags.length > 0 && (
        <select
          value={filters.framework}
          onChange={(e) => onChange({ ...filters, framework: e.target.value })}
          className="bg-zinc-900 border border-zinc-700 rounded-md px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          <option value="">All Frameworks</option>
          {frameworkTags.map((tag) => (
            <option key={tag} value={tag}>
              {tag} {OWASP_LLM_TOP10[tag] ? `- ${OWASP_LLM_TOP10[tag]}` : OWASP_MCP_TOP10[tag] ? `- ${OWASP_MCP_TOP10[tag]}` : MITRE_ATLAS[tag] ? `- ${MITRE_ATLAS[tag]}` : ""}
            </option>
          ))}
        </select>
      )}

      {/* Agent dropdown */}
      {agentNames.length > 0 && (
        <select
          value={filters.agent}
          onChange={(e) => onChange({ ...filters, agent: e.target.value })}
          className="bg-zinc-900 border border-zinc-700 rounded-md px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          <option value="">All Agents</option>
          {agentNames.map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
      )}

      {/* Clear all */}
      {(filters.cve || filters.severity || filters.framework || filters.agent) && (
        <button
          onClick={() => onChange({ cve: "", severity: "", framework: "", agent: "" })}
          className="text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors underline"
        >
          Clear filters
        </button>
      )}
    </div>
  );
}

// ─── Stats Bar ───────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: AttackFlowResponse["stats"] }) {
  const items = [
    { label: "CVEs", value: stats.total_cves, color: "text-red-400" },
    { label: "Packages", value: stats.total_packages, color: "text-zinc-300" },
    { label: "Servers", value: stats.total_servers, color: "text-blue-400" },
    { label: "Agents", value: stats.total_agents, color: "text-emerald-400" },
    { label: "Credentials", value: stats.total_credentials, color: "text-yellow-400" },
    { label: "Tools", value: stats.total_tools, color: "text-purple-400" },
  ];

  return (
    <div className="flex items-center gap-3">
      {items
        .filter((i) => i.value > 0)
        .map((item) => (
          <span key={item.label} className="flex items-center gap-1 text-xs">
            <span className={`font-mono font-bold ${item.color}`}>{item.value}</span>
            <span className="text-zinc-500">{item.label}</span>
          </span>
        ))}
      {/* Severity breakdown */}
      <span className="text-zinc-700">|</span>
      {Object.entries(stats.severity_counts)
        .filter(([, v]) => v > 0)
        .map(([sev, count]) => (
          <span key={sev} className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border ${severityColor(sev)}`}>
            {count} {sev}
          </span>
        ))}
    </div>
  );
}

// ─── Main Flow Content ──────────────────────────────────────────────────────

function AttackFlowContent({
  id,
  job,
  flowData,
  filters,
  onFiltersChange,
}: {
  id: string;
  job: ScanJob;
  flowData: AttackFlowResponse;
  filters: Filters;
  onFiltersChange: (f: Filters) => void;
}) {
  const [selectedNode, setSelectedNode] = useState<AttackFlowNodeData | null>(null);
  const blastRadius = job.result?.blast_radius ?? [];

  const nodes = flowData.nodes.map((n) => ({
    ...n,
    type: "attackFlowNode" as const,
    data: n.data as unknown as Record<string, unknown>,
  }));
  const edges = flowData.edges;

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header */}
      <div className="px-4 py-3 border-b border-zinc-800 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href={`/scan/${id}`} className="text-zinc-500 hover:text-zinc-300 transition-colors">
              <ArrowLeft className="w-4 h-4" />
            </Link>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100">Attack Flow</h1>
              <p className="text-xs text-zinc-500">
                CVE → Package → Server → Agent blast radius chain
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <StatsBar stats={flowData.stats} />
            <ExportButton />
          </div>
        </div>

        {/* Filter bar */}
        <FilterBar filters={filters} onChange={onFiltersChange} blastRadius={blastRadius} />
      </div>

      {/* Graph or empty state */}
      <div className="flex-1 relative">
        {flowData.nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-zinc-400 gap-3">
            <Filter className="w-8 h-8 text-zinc-600" />
            <p className="text-sm">No results match the current filters</p>
            <button
              onClick={() => onFiltersChange({ cve: "", severity: "", framework: "", agent: "" })}
              className="text-xs text-emerald-400 hover:text-emerald-300 underline"
            >
              Clear all filters
            </button>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.1}
            maxZoom={2}
            defaultEdgeOptions={{ type: "smoothstep" }}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_event, node) => {
              setSelectedNode(node.data as unknown as AttackFlowNodeData);
            }}
            onPaneClick={() => setSelectedNode(null)}
          >
            <Background color="#27272a" gap={20} />
            <Controls
              className="!bg-zinc-900 !border-zinc-700 !rounded-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300 [&>button:hover]:!bg-zinc-700"
            />
            <MiniMap
              nodeColor={(n) => {
                const d = n.data as unknown as AttackFlowNodeData;
                return NODE_MINIMAP_COLORS[d.nodeType] ?? "#52525b";
              }}
              className="!bg-zinc-900 !border-zinc-700 !rounded-lg"
            />
          </ReactFlow>
        )}

        {/* Detail slide-over panel */}
        {selectedNode && (
          <DetailPanel data={selectedNode} onClose={() => setSelectedNode(null)} />
        )}
      </div>

      {/* Legend */}
      <div className="px-4 py-2 border-t border-zinc-800 flex items-center gap-4 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-red-600 bg-red-950" /> CVE</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-zinc-600 bg-zinc-900" /> Package</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-blue-600 bg-blue-950" /> Server</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-emerald-600 bg-emerald-950" /> Agent</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-yellow-600 bg-yellow-950" /> Credential</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-purple-600 bg-purple-950" /> Tool</span>
      </div>
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AttackFlowPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [flowData, setFlowData] = useState<AttackFlowResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<Filters>({ cve: "", severity: "", framework: "", agent: "" });

  // Load job data
  useEffect(() => {
    api.getScan(id).then(setJob).catch((e) => setError(e.message));
  }, [id]);

  // Load attack flow (re-fetch when filters change)
  useEffect(() => {
    setLoading(true);
    const filterParams: Record<string, string> = {};
    if (filters.cve) filterParams.cve = filters.cve;
    if (filters.severity) filterParams.severity = filters.severity;
    if (filters.framework) filterParams.framework = filters.framework;
    if (filters.agent) filterParams.agent = filters.agent;

    api
      .getAttackFlow(id, Object.keys(filterParams).length > 0 ? filterParams : undefined)
      .then(setFlowData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id, filters]);

  if (loading && !flowData) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading attack flow...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">Could not load attack flow</p>
        <p className="text-xs text-zinc-500">{error}</p>
        <Link href={`/scan/${id}`} className="text-xs text-emerald-400 hover:text-emerald-300 underline">
          Back to scan results
        </Link>
      </div>
    );
  }

  if (!job || !flowData) return null;

  return (
    <ReactFlowProvider>
      <AttackFlowContent
        id={id}
        job={job}
        flowData={flowData}
        filters={filters}
        onFiltersChange={setFilters}
      />
    </ReactFlowProvider>
  );
}
