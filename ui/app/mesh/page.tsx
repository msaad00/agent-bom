"use client";

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
import { ShieldAlert, Loader2, AlertTriangle, Search, SlidersHorizontal, Network, GitBranch } from "lucide-react";
import { api, type JobListItem, type ScanJob } from "@/lib/api";
import { applyDagreLayout } from "@/lib/dagre-layout";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { MeshStats } from "@/components/mesh-stats";
import {
  buildMeshGraph,
  getConnectedIds,
  searchNodes,
  type NodeTypeFilter,
  type SeverityFilter,
  type MeshStatsData,
} from "@/lib/mesh-graph";
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

// ─── Filter Toolbar ─────────────────────────────────────────────────────────

function MeshToolbar({
  nodeFilter,
  setNodeFilter,
  severityFilter,
  setSeverityFilter,
  searchQuery,
  setSearchQuery,
  vulnerableOnly,
  setVulnerableOnly,
  agentNames,
  selectedAgents,
  toggleAgent,
}: {
  nodeFilter: NodeTypeFilter;
  setNodeFilter: (f: NodeTypeFilter) => void;
  severityFilter: SeverityFilter;
  setSeverityFilter: (f: SeverityFilter) => void;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  vulnerableOnly: boolean;
  setVulnerableOnly: (next: boolean) => void;
  agentNames: string[];
  selectedAgents: string[];
  toggleAgent: (name: string) => void;
}) {
  const toggles: { key: keyof NodeTypeFilter; label: string; color: string }[] = [
    { key: "packages", label: "Packages", color: "text-zinc-400" },
    { key: "vulnerabilities", label: "Vulns", color: "text-red-400" },
    { key: "credentials", label: "Creds", color: "text-amber-400" },
    { key: "tools", label: "Tools", color: "text-purple-400" },
  ];

  return (
    <div className="flex items-center gap-3 px-4 py-2 border-b border-zinc-800 text-xs">
      <SlidersHorizontal className="w-3.5 h-3.5 text-zinc-500 shrink-0" />

      {/* Node type toggles */}
      {toggles?.map((t) => (
        <label key={t.key} className="flex items-center gap-1 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={nodeFilter[t.key]}
            onChange={() => setNodeFilter({ ...nodeFilter, [t.key]: !nodeFilter[t.key] })}
            className="w-3 h-3 rounded border-zinc-600 bg-zinc-800 text-emerald-500 focus:ring-0 focus:ring-offset-0"
          />
          <span className={nodeFilter[t.key] ? t.color : "text-zinc-600"}>{t.label}</span>
        </label>
      ))}

      <div className="w-px h-4 bg-zinc-700" />

      {/* Severity filter */}
      <select
        value={severityFilter}
        onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
        className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-600"
      >
        <option value="all">All Severities</option>
        <option value="critical">Critical Only</option>
        <option value="high">High+</option>
        <option value="medium">Medium+</option>
        <option value="low">Low+</option>
      </select>

      <label className="flex items-center gap-1.5 text-zinc-400">
        <input
          type="checkbox"
          checked={vulnerableOnly}
          onChange={(event) => setVulnerableOnly(event.target.checked)}
          className="w-3 h-3 rounded border-zinc-600 bg-zinc-800 text-emerald-500 focus:ring-0 focus:ring-offset-0"
        />
        Vulnerable only
      </label>

      <div className="w-px h-4 bg-zinc-700" />

      {/* Search */}
      <div className="relative flex-1 max-w-xs">
        <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search nodes, CVEs, packages..."
          className="w-full bg-zinc-900 border border-zinc-700 rounded pl-7 pr-2 py-1 text-xs text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-600"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery("")}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
          >
            ×
          </button>
        )}
      </div>

      {agentNames.length > 0 && (
        <>
          <div className="w-px h-4 bg-zinc-700" />
          <div className="flex items-center gap-1.5 overflow-x-auto max-w-[28rem] pb-1">
            {agentNames.map((name) => {
              const active = selectedAgents.includes(name);
              return (
                <button
                  key={name}
                  type="button"
                  onClick={() => toggleAgent(name)}
                  className={`rounded-full border px-2.5 py-1 text-[11px] transition ${
                    active
                      ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-200"
                      : "border-zinc-700 bg-zinc-900/70 text-zinc-500 hover:border-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  {name}
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function MeshPage() {
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [selectedJob, setSelectedJob] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<ScanJob | null>(null);

  // Layout direction: "LR" for topology, "TB" for spawn tree
  const [layoutMode, setLayoutMode] = useState<"LR" | "TB">("LR");

  // Filters
  const [nodeFilter, setNodeFilter] = useState<NodeTypeFilter>({
    packages: true,
    vulnerabilities: true,
    credentials: true,
    tools: true,
  });
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("high");
  const [vulnerableOnly, setVulnerableOnly] = useState(true);
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    api
      .listJobs()
      .then((res) => {
        const doneJobs = res.jobs.filter((j) => j.status === "done");
        setJobs(doneJobs);
        if (doneJobs.length > 0) setSelectedJob(doneJobs[0].job_id);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(() => {
      if (!selectedJob) {
        setActiveJob(null);
        return;
      }
      setDetailLoading(true);
      api
        .getScan(selectedJob)
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
  }, [selectedJob]);

  const activeResult = useMemo(() => activeJob?.result ?? null, [activeJob]);

  const agentNames = useMemo(
    () => activeResult?.agents.map((agent) => agent.name).sort((left, right) => left.localeCompare(right)) ?? [],
    [activeResult],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (agentNames.length === 0) {
        setSelectedAgents([]);
        return;
      }
      setSelectedAgents((current) => {
        const retained = current.filter((name) => agentNames.includes(name));
        return retained.length > 0 ? retained : [agentNames[0]];
      });
    }, 0);
    return () => window.clearTimeout(timer);
  }, [agentNames]);

  const { rawNodes, rawEdges, stats } = useMemo(() => {
    const empty: MeshStatsData = {
      totalAgents: 0, sharedServers: 0, uniqueCredentials: 0, toolOverlap: 0,
      credentialBlast: [], totalPackages: 0, totalVulnerabilities: 0,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, kevCount: 0,
    };
    if (!activeResult) return { rawNodes: [] as Node[], rawEdges: [] as Edge[], stats: empty };
    const { nodes, edges, stats } = buildMeshGraph(activeResult, nodeFilter, severityFilter, {
      selectedAgents,
      vulnerableOnly,
    });
    return { rawNodes: nodes, rawEdges: edges, stats };
  }, [activeResult, nodeFilter, severityFilter, selectedAgents, vulnerableOnly]);

  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(
    () =>
      rawNodes.length > 0
        ? applyDagreLayout(rawNodes, rawEdges, {
            direction: layoutMode,
            nodeWidth: 200,
            nodeHeight: 70,
            rankSep: 140,
            nodeSep: 25,
          })
        : { nodes: [] as Node[], edges: [] as Edge[] },
    [rawNodes, rawEdges, layoutMode]
  );

  // Search highlighting
  const searchMatches = useMemo(
    () => (searchQuery ? searchNodes(layoutNodes, searchQuery) : null),
    [layoutNodes, searchQuery]
  );

  const toggleAgent = useCallback((name: string) => {
    setSelectedAgents((current) => {
      if (current.includes(name)) {
        return current.length === 1 ? current : current.filter((entry) => entry !== name);
      }
      return [...current, name];
    });
  }, []);

  // Hover highlighting
  const connectedIds = useMemo(
    () => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null),
    [hoveredNodeId, layoutEdges]
  );

  const displayNodes = useMemo(() => {
    if (searchMatches && searchMatches.size > 0) {
      return layoutNodes?.map((n) => ({
        ...n,
        data: { ...n.data, dimmed: !searchMatches.has(n.id), highlighted: searchMatches.has(n.id) },
      }));
    }
    if (!connectedIds) return layoutNodes;
    return layoutNodes?.map((n) => ({
      ...n,
      data: { ...n.data, dimmed: !connectedIds.has(n.id), highlighted: connectedIds.has(n.id) },
    }));
  }, [layoutNodes, connectedIds, searchMatches]);

  const displayEdges = useMemo(() => {
    const activeSet = searchMatches && searchMatches.size > 0 ? searchMatches : connectedIds;
    if (!activeSet) return layoutEdges;
    return layoutEdges?.map((e) => ({
      ...e,
      style: {
        ...e.style,
        opacity: activeSet.has(e.source) && activeSet.has(e.target) ? 1 : 0.12,
      },
    }));
  }, [layoutEdges, connectedIds, searchMatches]);

  const legendItems = useMemo(() => legendItemsForVisibleNodes(displayNodes), [displayNodes]);

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node.data as LineageNodeData);
    setHoveredNodeId(null);
  }, []);

  const onNodeMouseEnter = useCallback((_event: React.MouseEvent, node: Node) => {
    setHoveredNodeId(node.id);
  }, []);

  const onNodeMouseLeave = useCallback(() => {
    setHoveredNodeId(null);
  }, []);

  if (loading || (detailLoading && !activeResult)) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading mesh view...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">Could not connect to agent-bom API</p>
        <p className="text-xs text-zinc-500">Make sure the API is running at localhost:8422</p>
      </div>
    );
  }

  if (jobs.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <ShieldAlert className="w-8 h-8 text-zinc-600" />
        <p className="text-sm">No completed scans found</p>
        <p className="text-xs text-zinc-500">Run a scan first to visualize the agent mesh</p>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Agent Mesh</h1>
          <p className="text-xs text-zinc-500">
            Agent-centered shared infrastructure across MCP servers, packages, tools, and findings
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Layout toggle */}
          <div className="flex items-center bg-zinc-800 rounded-lg border border-zinc-700 overflow-hidden">
            <button
              onClick={() => setLayoutMode("LR")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
                layoutMode === "LR"
                  ? "bg-emerald-600 text-white"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              Topology
            </button>
            <button
              onClick={() => setLayoutMode("TB")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
                layoutMode === "TB"
                  ? "bg-emerald-600 text-white"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              Spawn Tree
            </button>
          </div>

          <select
            value={selectedJob}
            onChange={(e) => setSelectedJob(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300 focus:outline-none focus:border-emerald-600"
          >
            {jobs?.map((j) => (
              <option key={j.job_id} value={j.job_id}>
                Scan {j.job_id.slice(0, 8)} — {new Date(j.created_at).toLocaleDateString()}
              </option>
            ))}
          </select>
          <FullscreenButton />
          <GraphLegend items={legendItems} />
        </div>
      </div>

      {/* Stats bar */}
      <MeshStats stats={stats} />

      {/* Filter toolbar */}
      <MeshToolbar
        nodeFilter={nodeFilter}
        setNodeFilter={setNodeFilter}
        severityFilter={severityFilter}
        setSeverityFilter={setSeverityFilter}
        searchQuery={searchQuery}
        setSearchQuery={setSearchQuery}
        vulnerableOnly={vulnerableOnly}
        setVulnerableOnly={setVulnerableOnly}
        agentNames={agentNames}
        selectedAgents={selectedAgents}
        toggleAgent={toggleAgent}
      />

      {/* Graph */}
      <div className="flex-1 relative">
        {detailLoading && activeResult && (
          <div className="absolute inset-x-0 top-0 z-10 flex items-center justify-center py-2 text-xs text-zinc-400 bg-zinc-950/70 backdrop-blur-sm">
            <Loader2 className="w-3.5 h-3.5 animate-spin mr-2" />
            Updating mesh...
          </div>
        )}
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
          onPaneClick={() => { setSelectedNode(null); setHoveredNodeId(null); }}
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

        {selectedNode && (
          <LineageDetailPanel
            data={selectedNode}
            onClose={() => setSelectedNode(null)}
          />
        )}
      </div>
    </div>
  );
}
