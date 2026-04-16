"use client";

/**
 * Context Graph page — agent interaction graph with lateral movement analysis.
 * Shows reachability between agents, servers, credentials, tools, and
 * vulnerabilities.  Selecting an agent highlights lateral movement paths.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ShieldAlert,
  Loader2,
  AlertTriangle,
  Search,
  Waypoints,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { api, type JobListItem, type ScanJob } from "@/lib/api";
import { applyDagreLayout } from "@/lib/dagre-layout";
import {
  lineageNodeTypes,
  type LineageNodeData,
} from "@/components/lineage-nodes";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { getConnectedIds, searchNodes } from "@/lib/mesh-graph";
import {
  buildContextFlowGraph,
  type ContextGraphData,
  type LateralPath,
  type InteractionRisk,
} from "@/lib/context-graph";
import {
  CONTROLS_CLASS,
  MINIMAP_BG,
  MINIMAP_CLASS,
  MINIMAP_MASK,
  BACKGROUND_COLOR,
  BACKGROUND_GAP,
  legendItemsForVisibleNodes,
  minimapNodeColor,
} from "@/lib/graph-utils";
import { FullscreenButton, GraphLegend } from "@/components/graph-chrome";

// ─── Stats Bar ──────────────────────────────────────────────────────────────

function ContextStats({ data }: { data: ContextGraphData }) {
  const s = data.stats;
  const items = [
    { label: "Agents", value: s.agent_count, color: "text-emerald-400" },
    { label: "Shared Servers", value: s.shared_server_count, color: "text-cyan-400" },
    { label: "Shared Credentials", value: s.shared_credential_count, color: "text-amber-400" },
    { label: "Lateral Paths", value: s.lateral_path_count, color: "text-orange-400" },
    { label: "Highest Risk", value: s.highest_path_risk.toFixed(1), color: s.highest_path_risk >= 7 ? "text-red-400" : "text-zinc-400" },
    { label: "Risk Patterns", value: s.interaction_risk_count, color: "text-purple-400" },
  ];

  return (
    <div className="flex items-center gap-4 px-4 py-2 border-b border-zinc-800 text-xs">
      {items?.map((it) => (
        <div key={it.label} className="flex items-center gap-1.5">
          <span className="text-zinc-500">{it.label}</span>
          <span className={`font-semibold ${it.color}`}>{it.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Lateral Movement Panel ─────────────────────────────────────────────────

function LateralPanel({
  paths,
  risks,
  selectedAgent,
}: {
  paths: LateralPath[];
  risks: InteractionRisk[];
  selectedAgent: string | null;
}) {
  const [risksOpen, setRisksOpen] = useState(true);
  const filtered = selectedAgent
    ? paths.filter((p) => p.source === `agent:${selectedAgent}`)
    : paths;
  const distinctPaths = Array.from(
    new Map(filtered.map((path) => [`${path.hops.join("->")}::${path.vuln_ids.join(",")}`, path])).values(),
  );
  const topPaths = distinctPaths.slice(0, 6);

  return (
    <div className="w-72 border-l border-zinc-800 overflow-y-auto bg-zinc-950">
      {/* Lateral paths */}
      <div className="p-3 border-b border-zinc-800">
        <h3 className="text-xs font-semibold text-zinc-300 mb-2">
          Lateral Movement{selectedAgent ? ` from ${selectedAgent}` : ""}
        </h3>
        {topPaths.length === 0 ? (
          <p className="text-[10px] text-zinc-600">No lateral paths found</p>
        ) : (
          <div className="space-y-2">
            {topPaths?.map((p, i) => (
              <div
                key={i}
                className="bg-zinc-900 border border-zinc-800 rounded-lg p-2"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-zinc-500">
                    {p.hops.length - 1} hop{p.hops.length - 1 !== 1 ? "s" : ""}
                  </span>
                  <span
                    className={`text-[10px] font-semibold ${
                      p.composite_risk >= 7
                        ? "text-red-400"
                        : p.composite_risk >= 4
                        ? "text-amber-400"
                        : "text-zinc-400"
                    }`}
                  >
                    Risk {p.composite_risk}
                  </span>
                </div>
                <p className="text-[10px] text-zinc-300 leading-relaxed">
                  {p.summary}
                </p>
                {p.credential_exposure.length > 0 && (
                  <p className="text-[10px] text-amber-400 mt-1">
                    Creds: {p.credential_exposure.join(", ")}
                  </p>
                )}
                {p.tool_exposure.length > 0 && (
                  <p className="text-[10px] text-purple-400 mt-1">
                    Tools: {p.tool_exposure.join(", ")}
                  </p>
                )}
                {p.vuln_ids.length > 0 && (
                  <p className="text-[10px] text-red-400 mt-1">
                    Vulns: {p.vuln_ids.join(", ")}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Interaction risks */}
      <div className="p-3">
        <button
          onClick={() => setRisksOpen(!risksOpen)}
          className="flex items-center gap-1 text-xs font-semibold text-zinc-300 mb-2"
        >
          {risksOpen ? (
            <ChevronDown className="w-3 h-3" />
          ) : (
            <ChevronRight className="w-3 h-3" />
          )}
          Interaction Risks ({risks.length})
        </button>
        {risksOpen && (
          <div className="space-y-2">
            {risks?.map((r, i) => (
              <div
                key={i}
                className="bg-zinc-900 border border-zinc-800 rounded-lg p-2"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-zinc-500 capitalize">
                    {r.pattern.replace(/_/g, " ")}
                  </span>
                  <span
                    className={`text-[10px] font-semibold ${
                      r.risk_score >= 7
                        ? "text-red-400"
                        : r.risk_score >= 5
                        ? "text-amber-400"
                        : "text-zinc-400"
                    }`}
                  >
                    {r.risk_score.toFixed(1)}
                  </span>
                </div>
                <p className="text-[10px] text-zinc-400 leading-relaxed">
                  {r.description}
                </p>
                {r.owasp_agentic_tag && (
                  <span className="inline-block mt-1 text-[9px] bg-purple-900/50 text-purple-300 px-1.5 py-0.5 rounded">
                    {r.owasp_agentic_tag}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function ContextPage() {
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string>("");
  const [graphData, setGraphData] = useState<ContextGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeJob, setActiveJob] = useState<ScanJob | null>(null);

  // Load completed jobs
  useEffect(() => {
    api
      .listJobs()
      .then((res) => {
        const doneJobs = res.jobs.filter((j) => j.status === "done");
        setJobs(doneJobs);
        if (doneJobs.length > 0) setSelectedJobId(doneJobs[0].job_id);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(() => {
      if (!selectedJobId) {
        setActiveJob(null);
        return;
      }
      setDetailLoading(true);
      api
        .getScan(selectedJobId)
        .then((job) => {
          if (!cancelled) {
            setActiveJob(job.result ? job : null);
            setError(null);
          }
        })
        .catch((e) => {
          if (!cancelled) {
            setActiveJob(null);
            setError(e.message);
          }
        })
        .finally(() => {
          if (!cancelled) setDetailLoading(false);
        });
    }, 0);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [selectedJobId]);

  const agentNames = useMemo(
    () => activeJob?.result?.agents.map((agent) => agent.name).sort((left, right) => left.localeCompare(right)) ?? [],
    [activeJob],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (agentNames.length === 0) {
        setSelectedAgent(null);
        return;
      }
      setSelectedAgent((current) => (current && agentNames.includes(current) ? current : agentNames[0]));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [agentNames]);

  // Fetch context graph when job changes
  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!selectedJobId) return;
      setGraphData(null);
      api
        .getContextGraph(selectedJobId, selectedAgent ?? undefined)
        .then((resp) => setGraphData(resp as unknown as ContextGraphData))
        .catch((e) => setError(e.message));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [selectedJobId, selectedAgent]);

  // Build ReactFlow graph
  const { rawNodes, rawEdges } = useMemo(() => {
    if (!graphData) return { rawNodes: [] as Node[], rawEdges: [] as Edge[] };
    const { nodes, edges } = buildContextFlowGraph(graphData, selectedAgent ?? undefined);
    return { rawNodes: nodes, rawEdges: edges };
  }, [graphData, selectedAgent]);

  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(
    () =>
      rawNodes.length > 0
        ? applyDagreLayout(rawNodes, rawEdges, {
            direction: "LR",
            nodeWidth: 200,
            nodeHeight: 70,
            rankSep: 140,
            nodeSep: 25,
          })
        : { nodes: [] as Node[], edges: [] as Edge[] },
    [rawNodes, rawEdges]
  );

  // Search highlighting
  const searchMatches = useMemo(
    () => (searchQuery ? searchNodes(layoutNodes, searchQuery) : null),
    [layoutNodes, searchQuery]
  );

  // Hover highlighting
  const connectedIds = useMemo(
    () => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null),
    [hoveredNodeId, layoutEdges]
  );

  const displayNodes = useMemo(() => {
    if (searchMatches && searchMatches.size > 0) {
      return layoutNodes?.map((n) => ({
        ...n,
        data: {
          ...n.data,
          dimmed: !searchMatches.has(n.id),
          highlighted: searchMatches.has(n.id),
        },
      }));
    }
    if (!connectedIds) return layoutNodes;
    return layoutNodes?.map((n) => ({
      ...n,
      data: {
        ...n.data,
        dimmed: !connectedIds.has(n.id),
        highlighted: connectedIds.has(n.id),
      },
    }));
  }, [layoutNodes, connectedIds, searchMatches]);

  const displayEdges = useMemo(() => {
    const activeSet =
      searchMatches && searchMatches.size > 0 ? searchMatches : connectedIds;
    if (!activeSet) return layoutEdges;
    return layoutEdges?.map((e) => ({
      ...e,
      style: {
        ...e.style,
        opacity:
          activeSet.has(e.source) && activeSet.has(e.target) ? 1 : 0.12,
      },
    }));
  }, [layoutEdges, connectedIds, searchMatches]);

  const legendItems = useMemo(() => {
    const extras =
      displayEdges.some((edge) => edge.animated || Boolean(edge.style?.strokeDasharray))
        ? [{ label: "Lateral", color: "#f97316", dashed: true, shape: "diamond" as const }]
        : [];
    return legendItemsForVisibleNodes(displayNodes, extras);
  }, [displayEdges, displayNodes]);

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node.data as LineageNodeData);
    setHoveredNodeId(null);
  }, []);

  const onNodeMouseEnter = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setHoveredNodeId(node.id);
    },
    []
  );

  const onNodeMouseLeave = useCallback(() => {
    setHoveredNodeId(null);
  }, []);

  if (loading || (detailLoading && !graphData)) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading context view...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">Could not connect to agent-bom API</p>
        <p className="text-xs text-zinc-500">
          Make sure the API is running at localhost:8422
        </p>
      </div>
    );
  }

  if (jobs.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <ShieldAlert className="w-8 h-8 text-zinc-600" />
        <p className="text-sm">No completed scans found</p>
        <p className="text-xs text-zinc-500">
          Run a scan first to visualize the context graph
        </p>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
            <Waypoints className="w-5 h-5 text-orange-400" />
            Context Graph
          </h1>
          <p className="text-xs text-zinc-500">
            Focused lateral-movement map for one agent scope at a time
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Agent selector */}
          <select
            value={selectedAgent ?? ""}
            onChange={(e) =>
              setSelectedAgent(e.target.value || null)
            }
            className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300 focus:outline-none focus:border-orange-600"
          >
            <option value="">All agents</option>
            {agentNames?.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>

          {/* Job selector */}
          <select
            value={selectedJobId}
            onChange={(e) => setSelectedJobId(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300 focus:outline-none focus:border-emerald-600"
          >
            {jobs?.map((j) => (
              <option key={j.job_id} value={j.job_id}>
                Scan {j.job_id.slice(0, 8)} —{" "}
                {new Date(j.created_at).toLocaleDateString()}
              </option>
            ))}
          </select>

          {/* Search */}
          <div className="relative max-w-xs">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search agent, server, tool, or CVE"
              className="w-full bg-zinc-900 border border-zinc-700 rounded pl-7 pr-2 py-1.5 text-xs text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-600"
            />
          </div>

          <FullscreenButton />
          <GraphLegend items={legendItems} />
        </div>
      </div>

      {/* Stats */}
      {graphData && <ContextStats data={graphData} />}

      {/* Main area: graph + sidebar */}
      <div className="flex-1 flex overflow-hidden">
        {/* Graph */}
        <div className="flex-1 relative">
          {detailLoading && graphData && (
            <div className="absolute inset-x-0 top-0 z-10 flex items-center justify-center py-2 text-xs text-zinc-400 bg-zinc-950/70 backdrop-blur-sm">
              <Loader2 className="w-3.5 h-3.5 animate-spin mr-2" />
              Updating context graph...
            </div>
          )}
          {!graphData ? (
            <div className="flex items-center justify-center h-full text-zinc-400">
              <Loader2 className="w-5 h-5 animate-spin mr-2" />
              Loading context graph...
            </div>
          ) : (
            <ReactFlow
              nodes={displayNodes}
              edges={displayEdges}
              nodeTypes={lineageNodeTypes}
              fitView
              fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
              minZoom={0.16}
              maxZoom={2.5}
              onlyRenderVisibleElements
              defaultEdgeOptions={{ type: "smoothstep" }}
              proOptions={{ hideAttribution: true }}
              onNodeClick={onNodeClick}
              onNodeMouseEnter={onNodeMouseEnter}
              onNodeMouseLeave={onNodeMouseLeave}
              onPaneClick={() => {
                setSelectedNode(null);
                setHoveredNodeId(null);
              }}
            >
              <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
              <Controls className={CONTROLS_CLASS} />
              <MiniMap
                nodeColor={minimapNodeColor}
                className={MINIMAP_CLASS}
                bgColor={MINIMAP_BG}
                maskColor={MINIMAP_MASK}
              />
            </ReactFlow>
          )}

          {selectedNode && (
            <LineageDetailPanel
              data={selectedNode}
              onClose={() => setSelectedNode(null)}
            />
          )}
        </div>

        {/* Lateral movement sidebar */}
        {graphData && (
          <LateralPanel
            paths={graphData.lateral_paths}
            risks={graphData.interaction_risks}
            selectedAgent={selectedAgent}
          />
        )}
      </div>
    </div>
  );
}
