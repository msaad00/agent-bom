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
import {
  Search,
  SlidersHorizontal,
  Network,
  GitBranch,
  Orbit,
} from "lucide-react";
import { api, type JobListItem, type ScanJob } from "@/lib/api";
import { useGraphLayout } from "@/lib/use-graph-layout";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { MeshStats } from "@/components/mesh-stats";
import {
  buildMeshGraph,
  getConnectedIds,
  getMeshAgentKey,
  getMeshAgentLabel,
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
  legendItemsForVisibleGraph,
  minimapNodeColor,
  readableGraphEdges,
} from "@/lib/graph-utils";
import { graphFitViewOptions, shouldShowGraphMiniMap } from "@/lib/graph-viewport";
import { FullscreenButton, GraphLegend } from "@/components/graph-chrome";
import { GraphEmptyState, GraphPanelSkeleton, GraphRefreshOverlay } from "@/components/graph-state-panels";
import { DeploymentSurfaceRequiredState } from "@/components/deployment-surface-required-state";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { isDeploymentSurfaceAvailable } from "@/lib/deployment-context";
import { useCaptureMode } from "@/lib/use-capture-mode";

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
  agentOptions,
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
  agentOptions: { key: string; label: string }[];
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

      {agentOptions.length > 0 && (
        <>
          <div className="w-px h-4 bg-zinc-700" />
          <div className="flex items-center gap-1.5 overflow-x-auto max-w-[28rem] pb-1">
            {agentOptions.map(({ key, label }) => {
              const active = selectedAgents.includes(key);
              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => toggleAgent(key)}
                  className={`rounded-full border px-2.5 py-1 text-[11px] transition ${
                    active
                      ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-200"
                      : "border-zinc-700 bg-zinc-900/70 text-zinc-500 hover:border-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  {label}
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

type MeshLayoutMode = "radial" | "topology" | "spawn-tree";

export default function MeshPage() {
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [selectedJob, setSelectedJob] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<ScanJob | null>(null);
  const [layoutMode, setLayoutMode] = useState<MeshLayoutMode>("topology");

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
  const { counts } = useDeploymentContext();
  const captureMode = useCaptureMode();

  useEffect(() => {
    api
      .listJobs()
      .then((res) => {
        const doneJobs = res.jobs.filter((j) => j.status === "done");
        setJobs(doneJobs);
        if (doneJobs.length > 0) setSelectedJob(doneJobs[0]!.job_id);
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

  const agentOptions = useMemo(() => {
    if (!activeResult) return [];
    const options = new Map<string, string>();
    for (const agent of activeResult.agents) {
      options.set(getMeshAgentKey(agent), getMeshAgentLabel(agent));
    }
    return [...options.entries()]
      .map(([key, label]) => ({ key, label }))
      .sort((left, right) => left.label.localeCompare(right.label));
  }, [activeResult]);

  const rankedAgentNames = useMemo(() => {
    if (!activeResult) return [];
    const scoreByAgent = new Map<string, number>();
    for (const agent of activeResult.agents) {
      const score = agent.mcp_servers.reduce((total, server) => {
        return total + server.packages.reduce((packageTotal, pkg) => {
          return packageTotal + (pkg.vulnerabilities?.length ?? 0);
        }, 0);
      }, 0);
      scoreByAgent.set(getMeshAgentKey(agent), score);
    }
    const labelByKey = new Map(agentOptions.map((option) => [option.key, option.label]));
    return agentOptions.map((option) => option.key).sort((left, right) => {
      const scoreDiff = (scoreByAgent.get(right) ?? 0) - (scoreByAgent.get(left) ?? 0);
      return scoreDiff !== 0 ? scoreDiff : (labelByKey.get(left) ?? left).localeCompare(labelByKey.get(right) ?? right);
    });
  }, [activeResult, agentOptions]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (rankedAgentNames.length === 0) {
        setSelectedAgents([]);
        return;
      }
      setSelectedAgents((current) => {
        const retained = current.filter((name) => rankedAgentNames.includes(name));
        return retained.length > 0 ? retained : rankedAgentNames.slice(0, 1);
      });
    }, 0);
    return () => window.clearTimeout(timer);
  }, [rankedAgentNames]);

  const { rawNodes, rawEdges, stats } = useMemo(() => {
    const empty: MeshStatsData = {
      totalAgents: 0, sharedServers: 0, uniqueCredentials: 0, toolOverlap: 0,
      credentialBlast: [], totalPackages: 0, totalVulnerabilities: 0,
      omittedCredentials: 0, omittedTools: 0, omittedPackages: 0, omittedVulnerabilities: 0,
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, kevCount: 0,
    };
    if (!activeResult) return { rawNodes: [] as Node[], rawEdges: [] as Edge[], stats: empty };
    const { nodes, edges, stats } = buildMeshGraph(activeResult, nodeFilter, severityFilter, {
      selectedAgents,
      vulnerableOnly,
      maxCredentialNodesPerServer: 2,
      maxToolNodesPerServer: 2,
      maxVulnerablePackagesPerServer: 3,
      maxCleanPackagesPerServer: vulnerableOnly ? 0 : 1,
      maxVulnerabilitiesPerPackage: 1,
    });
    return { rawNodes: nodes, rawEdges: edges, stats };
  }, [activeResult, nodeFilter, severityFilter, selectedAgents, vulnerableOnly]);

  const { nodes: visibleNodes, edges: visibleEdges } = useGraphLayout(layoutMode, rawNodes, rawEdges, {
    radial: {
      baseRadius: 240,
      ringSpacing: 220,
    },
    dagre: {
      nodeWidth: 230,
      nodeHeight: 84,
      rankSep: 140,
      nodeSep: 34,
    },
  });

  // Search highlighting
  const searchMatches = useMemo(
    () => (searchQuery ? searchNodes(visibleNodes, searchQuery) : null),
    [visibleNodes, searchQuery]
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
    () => (hoveredNodeId ? getConnectedIds(hoveredNodeId, visibleEdges) : null),
    [hoveredNodeId, visibleEdges]
  );

  const displayNodes = useMemo(() => {
    if (searchMatches && searchMatches.size > 0) {
      return visibleNodes?.map((n) => ({
        ...n,
        data: { ...n.data, dimmed: !searchMatches.has(n.id), highlighted: searchMatches.has(n.id) },
      }));
    }
    if (!connectedIds) return visibleNodes;
    return visibleNodes?.map((n) => ({
      ...n,
      data: { ...n.data, dimmed: !connectedIds.has(n.id), highlighted: connectedIds.has(n.id) },
    }));
  }, [visibleNodes, connectedIds, searchMatches]);

  const displayEdges = useMemo(() => {
    const activeSet = searchMatches && searchMatches.size > 0 ? searchMatches : connectedIds;
    return readableGraphEdges(visibleEdges, activeSet, {
      baseOpacity: 0.3,
      highSignalOpacity: 0.58,
      inactiveOpacity: 0.06,
      captureMode,
    });
  }, [visibleEdges, connectedIds, searchMatches, captureMode]);

  const legendItems = useMemo(
    () => legendItemsForVisibleGraph(displayNodes, displayEdges),
    [displayEdges, displayNodes],
  );
  const viewportOptions = useMemo(
    () =>
      graphFitViewOptions({
        nodeCount: displayNodes.length,
        edgeCount: displayEdges.length,
        selectedNode: Boolean(selectedNode),
        mode: "mesh",
      }),
    [displayEdges.length, displayNodes.length, selectedNode],
  );
  const showMiniMap = useMemo(
    () =>
      !captureMode && shouldShowGraphMiniMap({
        nodeCount: displayNodes.length,
        edgeCount: displayEdges.length,
        selectedNode: Boolean(selectedNode),
        mode: "mesh",
      }),
    [captureMode, displayEdges.length, displayNodes.length, selectedNode],
  );

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
      <div className="h-[80vh]">
        <GraphPanelSkeleton
          title="Loading agent mesh"
          detail="Fetching completed scans and preparing the bounded agent-centered topology."
        />
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-[80vh]">
        <GraphEmptyState
          title="Cannot load agent mesh"
          detail={error || "The API did not return scan evidence for the agent mesh view."}
          suggestions={[
            "Confirm the API is reachable before reopening the mesh view.",
            "Run a fresh scan when the control plane has no completed job history.",
            "Use the security graph once graph snapshots are persisted.",
          ]}
          command="agent-bom serve --api"
        />
      </div>
    );
  }

  if (jobs.length === 0) {
    if (counts && !isDeploymentSurfaceAvailable("mesh", counts)) {
      return <DeploymentSurfaceRequiredState surface="mesh" counts={counts} detail={error} />;
    }
    return (
      <div className="h-[80vh]">
        <GraphEmptyState
          title="No completed scans found"
          detail="Run a scan first so the agent mesh can show selected agents, shared MCP servers, tools, packages, credentials, and findings."
          suggestions={[
            "Use a demo scan for a local proof point.",
            "Keep the first mesh view scoped to the highest-risk agent.",
            "Open the full graph after the scan persists graph evidence.",
          ]}
          command="agent-bom agents --demo --offline"
        />
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col bg-background text-foreground">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Agent Mesh</h1>
          <p className="text-xs text-[var(--text-secondary)]">
            Evidence-scoped path view across agents, MCP servers, tools, packages, credential references, and findings
          </p>
          <p className="mt-1 text-[11px] text-[var(--text-tertiary)]">
            Default view ranks the highest-risk agent first and hides lower-priority nodes until you expand filters.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center overflow-hidden rounded-lg border border-zinc-700 bg-zinc-800">
            {[
              { key: "radial" as const, label: "Risk Map", icon: Orbit },
              { key: "topology" as const, label: "Dependency Flow", icon: Network },
              { key: "spawn-tree" as const, label: "Spawn Tree", icon: GitBranch },
            ].map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                type="button"
                onClick={() => setLayoutMode(key)}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
                  layoutMode === key
                    ? "bg-emerald-600 text-white"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            ))}
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
          <GraphLegend items={legendItems} defaultOpen={captureMode} />
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
        agentOptions={agentOptions}
        selectedAgents={selectedAgents}
        toggleAgent={toggleAgent}
      />

      {/* Graph */}
      <div className="flex-1 relative">
        {detailLoading && activeResult && (
          <GraphRefreshOverlay label="Updating agent mesh" />
        )}
        {displayNodes.length === 0 ? (
          <GraphEmptyState
            title="No mesh relationships match this scope"
            detail="The selected scan loaded, but the current agent, severity, or vulnerable-only filters removed the relationships needed to draw an agent mesh."
            suggestions={[
              "Choose another agent from the scope selector.",
              "Lower the severity filter or disable vulnerable-only mode.",
              "Switch to dependency flow after expanding the scope.",
            ]}
            command="agent-bom scan -p . -f graph"
          />
        ) : (
          <ReactFlow
            nodes={displayNodes}
            edges={displayEdges}
            nodeTypes={lineageNodeTypes}
            fitView
            fitViewOptions={viewportOptions}
            minZoom={0.16}
            maxZoom={2.5}
            zoomOnScroll={false}
            panOnScroll={false}
            preventScrolling={false}
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
            {showMiniMap && (
              <MiniMap
                nodeColor={minimapNodeColor}
                className={MINIMAP_CLASS}
                bgColor={MINIMAP_BG}
                maskColor={MINIMAP_MASK}
              />
            )}
          </ReactFlow>
        )}

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
