"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ShieldAlert,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { api, type ScanJob, type ScanResult } from "@/lib/api";
import { applyDagreLayout } from "@/lib/dagre-layout";
import { lineageNodeTypes, type LineageNodeData, type LineageNodeType } from "@/components/lineage-nodes";
import { FilterPanel, DEFAULT_FILTERS, type FilterState } from "@/components/lineage-filter";
import { LineageDetailPanel } from "@/components/lineage-detail";

// ─── Graph Builder ───────────────────────────────────────────────────────────

function buildLineageGraph(
  result: ScanResult,
  filters: FilterState
): { nodes: Node[]; edges: Edge[]; agentNames: string[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const seen = new Set<string>();
  const agentNames: string[] = [];

  // Collect vulnerable package keys for vulnOnly filter
  const vulnPkgKeys = new Set<string>();
  for (const agent of result.agents) {
    for (const server of agent.mcp_servers) {
      for (const pkg of server.packages) {
        if (pkg.vulnerabilities && pkg.vulnerabilities.length > 0) {
          vulnPkgKeys.add(`${pkg.name}@${pkg.version}`);
        }
      }
    }
  }

  // Collect vulnerable server keys
  const vulnServerKeys = new Set<string>();
  for (const agent of result.agents) {
    for (const server of agent.mcp_servers) {
      for (const pkg of server.packages) {
        if (vulnPkgKeys.has(`${pkg.name}@${pkg.version}`)) {
          vulnServerKeys.add(`${agent.name}:${server.name}`);
        }
      }
    }
  }

  for (const agent of result.agents) {
    agentNames.push(agent.name);

    // Agent name filter
    if (filters.agentName && agent.name !== filters.agentName) continue;

    // Vuln-only: skip agents with no vulnerable servers
    const agentHasVulns = agent.mcp_servers.some((s) =>
      vulnServerKeys.has(`${agent.name}:${s.name}`)
    );
    if (filters.vulnOnly && !agentHasVulns) continue;

    const agentId = `agent:${agent.name}`;

    if (filters.layers.agent && !seen.has(agentId)) {
      seen.add(agentId);
      const totalPkgs = agent.mcp_servers.reduce((s, srv) => s + srv.packages.length, 0);
      const totalVulns = agent.mcp_servers.reduce(
        (s, srv) => s + srv.packages.reduce((vs, p) => vs + (p.vulnerabilities?.length ?? 0), 0),
        0
      );

      nodes.push({
        id: agentId,
        type: "agentNode",
        position: { x: 0, y: 0 },
        data: {
          label: agent.name,
          nodeType: "agent",
          agentType: agent.agent_type,
          agentStatus: agent.status,
          serverCount: agent.mcp_servers.length,
          packageCount: totalPkgs,
          vulnCount: totalVulns,
        } satisfies LineageNodeData,
      });
    }

    for (const server of agent.mcp_servers) {
      const serverHasVulns = vulnServerKeys.has(`${agent.name}:${server.name}`);
      if (filters.vulnOnly && !serverHasVulns) continue;

      const serverId = `server:${agent.name}:${server.name}`;
      const credKeys = server.env
        ? Object.keys(server.env).filter((k) =>
            /key|token|secret|password|credential|auth/i.test(k)
          )
        : [];

      if (filters.layers.server && !seen.has(serverId)) {
        seen.add(serverId);
        nodes.push({
          id: serverId,
          type: "serverNode",
          position: { x: 0, y: 0 },
          data: {
            label: server.name,
            nodeType: "server",
            command: server.command || server.transport || "",
            toolCount: server.tools?.length ?? 0,
            credentialCount: credKeys.length,
          } satisfies LineageNodeData,
        });
      }

      // Agent → Server edge
      if (filters.layers.agent && filters.layers.server) {
        const edgeId = `${agentId}->${serverId}`;
        if (!seen.has(edgeId)) {
          seen.add(edgeId);
          edges.push({
            id: edgeId,
            source: agentId,
            target: serverId,
            type: "smoothstep",
            animated: true,
            style: { stroke: "#10b981", strokeWidth: 2 },
            markerEnd: { type: MarkerType.ArrowClosed, color: "#10b981" },
          });
        }
      }

      // Credential nodes
      if (filters.layers.credential && credKeys.length > 0) {
        for (const cred of credKeys) {
          const credId = `cred:${server.name}:${cred}`;
          if (!seen.has(credId)) {
            seen.add(credId);
            nodes.push({
              id: credId,
              type: "credentialNode",
              position: { x: 0, y: 0 },
              data: {
                label: cred,
                nodeType: "credential",
                serverName: server.name,
              } satisfies LineageNodeData,
            });
          }
          const credEdgeId = `${serverId}->${credId}`;
          if (filters.layers.server && !seen.has(credEdgeId)) {
            seen.add(credEdgeId);
            edges.push({
              id: credEdgeId,
              source: serverId,
              target: credId,
              type: "smoothstep",
              style: { stroke: "#f59e0b", strokeWidth: 1.5, strokeDasharray: "5 3" },
              markerEnd: { type: MarkerType.ArrowClosed, color: "#f59e0b" },
            });
          }
        }
      }

      // Tool nodes (limit to 8 per server to avoid clutter)
      if (filters.layers.tool && server.tools && server.tools.length > 0) {
        const displayTools = server.tools.slice(0, 8);
        for (const tool of displayTools) {
          const toolId = `tool:${server.name}:${tool.name}`;
          if (!seen.has(toolId)) {
            seen.add(toolId);
            nodes.push({
              id: toolId,
              type: "toolNode",
              position: { x: 0, y: 0 },
              data: {
                label: tool.name,
                nodeType: "tool",
                description: tool.description,
              } satisfies LineageNodeData,
            });
          }
          const toolEdgeId = `${serverId}->${toolId}`;
          if (filters.layers.server && !seen.has(toolEdgeId)) {
            seen.add(toolEdgeId);
            edges.push({
              id: toolEdgeId,
              source: serverId,
              target: toolId,
              type: "smoothstep",
              style: { stroke: "#a855f7", strokeWidth: 1 },
              markerEnd: { type: MarkerType.ArrowClosed, color: "#a855f7" },
            });
          }
        }
      }

      // Package nodes
      for (const pkg of server.packages) {
        const pkgKey = `${pkg.name}@${pkg.version}`;
        const pkgHasVulns = vulnPkgKeys.has(pkgKey);
        if (filters.vulnOnly && !pkgHasVulns) continue;

        const pkgId = `pkg:${pkgKey}`;
        const vulnCount = pkg.vulnerabilities?.length ?? 0;

        if (filters.layers.package && !seen.has(pkgId)) {
          seen.add(pkgId);
          nodes.push({
            id: pkgId,
            type: "packageNode",
            position: { x: 0, y: 0 },
            data: {
              label: pkgKey,
              nodeType: "package",
              ecosystem: pkg.ecosystem,
              version: pkg.version,
              vulnCount,
            } satisfies LineageNodeData,
          });
        }

        // Server → Package edge
        if (filters.layers.server && filters.layers.package) {
          const pkgEdgeId = `${serverId}->${pkgId}`;
          if (!seen.has(pkgEdgeId)) {
            seen.add(pkgEdgeId);
            edges.push({
              id: pkgEdgeId,
              source: serverId,
              target: pkgId,
              type: "smoothstep",
              style: { stroke: "#3b82f6", strokeWidth: 1.5 },
              markerEnd: { type: MarkerType.ArrowClosed, color: "#3b82f6" },
            });
          }
        }

        // Vulnerability nodes
        if (filters.layers.vulnerability && pkg.vulnerabilities) {
          for (const vuln of pkg.vulnerabilities) {
            // Severity filter
            if (filters.severity && vuln.severity !== filters.severity) continue;

            const vulnId = `vuln:${vuln.id}`;
            if (!seen.has(vulnId)) {
              seen.add(vulnId);
              // Find blast radius info
              const br = result.blast_radius?.find((b) => b.vulnerability_id === vuln.id);
              nodes.push({
                id: vulnId,
                type: "vulnNode",
                position: { x: 0, y: 0 },
                data: {
                  label: vuln.id,
                  nodeType: "vulnerability",
                  severity: vuln.severity,
                  cvssScore: vuln.cvss_score ?? br?.cvss_score,
                  epssScore: vuln.epss_score ?? br?.epss_score,
                  isKev: vuln.cisa_kev ?? br?.is_kev,
                  fixedVersion: vuln.fixed_version ?? br?.fixed_version,
                  owaspTags: br?.owasp_tags,
                  atlasTags: br?.atlas_tags,
                } satisfies LineageNodeData,
              });
            }

            // Package → Vuln edge
            if (filters.layers.package) {
              const vulnEdgeId = `${pkgId}->${vulnId}`;
              if (!seen.has(vulnEdgeId)) {
                seen.add(vulnEdgeId);
                const color =
                  vuln.severity === "critical" ? "#ef4444" :
                  vuln.severity === "high" ? "#f97316" :
                  vuln.severity === "medium" ? "#eab308" : "#3b82f6";
                // Thicker edges for higher blast radius
                const brCount = result.blast_radius?.find((b) => b.vulnerability_id === vuln.id)?.affected_agents.length ?? 1;
                edges.push({
                  id: vulnEdgeId,
                  source: pkgId,
                  target: vulnId,
                  type: "smoothstep",
                  style: { stroke: color, strokeWidth: Math.min(1 + brCount, 4) },
                  markerEnd: { type: MarkerType.ArrowClosed, color },
                });
              }
            }
          }
        }
      }
    }
  }

  return { nodes, edges, agentNames };
}

// ─── Hover Highlighting ──────────────────────────────────────────────────────

function getConnectedIds(nodeId: string, edges: Edge[]): Set<string> {
  const connected = new Set<string>([nodeId]);
  // Walk outgoing
  const queue = [nodeId];
  const visited = new Set<string>([nodeId]);
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const e of edges) {
      if (e.source === current && !visited.has(e.target)) {
        visited.add(e.target);
        connected.add(e.target);
        queue.push(e.target);
      }
    }
  }
  // Walk incoming
  const queue2 = [nodeId];
  const visited2 = new Set<string>([nodeId]);
  while (queue2.length > 0) {
    const current = queue2.shift()!;
    for (const e of edges) {
      if (e.target === current && !visited2.has(e.source)) {
        visited2.add(e.source);
        connected.add(e.source);
        queue2.push(e.source);
      }
    }
  }
  return connected;
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function GraphPage() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);

  useEffect(() => {
    api
      .listJobs()
      .then(async (res) => {
        const fullJobs: ScanJob[] = [];
        for (const j of res.jobs) {
          if (j.status === "done") {
            try {
              const full = await api.getScan(j.job_id);
              if (full.result) fullJobs.push(full);
            } catch {
              /* skip */
            }
          }
        }
        setJobs(fullJobs);
        if (fullJobs.length > 0) setSelectedJob(fullJobs[0].job_id);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const activeResult = useMemo(
    () => jobs.find((j) => j.job_id === selectedJob)?.result ?? null,
    [jobs, selectedJob]
  );

  const { rawNodes, rawEdges, agentNames } = useMemo(() => {
    if (!activeResult) return { rawNodes: [], rawEdges: [], agentNames: [] };
    const { nodes, edges, agentNames } = buildLineageGraph(activeResult, filters);
    return { rawNodes: nodes, rawEdges: edges, agentNames };
  }, [activeResult, filters]);

  // Apply dagre layout
  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(
    () =>
      rawNodes.length > 0
        ? applyDagreLayout(rawNodes, rawEdges, {
            direction: "LR",
            nodeWidth: 180,
            nodeHeight: 60,
            rankSep: 100,
            nodeSep: 25,
          })
        : { nodes: [], edges: [] },
    [rawNodes, rawEdges]
  );

  // Apply hover highlighting
  const connectedIds = useMemo(
    () => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null),
    [hoveredNodeId, layoutEdges]
  );

  const displayNodes = useMemo(() => {
    if (!connectedIds) return layoutNodes;
    return layoutNodes.map((n) => ({
      ...n,
      data: {
        ...n.data,
        dimmed: !connectedIds.has(n.id),
        highlighted: connectedIds.has(n.id),
      },
    }));
  }, [layoutNodes, connectedIds]);

  const displayEdges = useMemo(() => {
    if (!connectedIds) return layoutEdges;
    return layoutEdges.map((e) => ({
      ...e,
      style: {
        ...e.style,
        opacity: connectedIds.has(e.source) && connectedIds.has(e.target) ? 1 : 0.15,
      },
    }));
  }, [layoutEdges, connectedIds]);

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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading scan data...
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
        <p className="text-xs text-zinc-500">Run a scan first to visualize the lineage graph</p>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Lineage Graph</h1>
          <p className="text-xs text-zinc-500">
            Agent → Server → Package → CVE · Credentials · Tools
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={selectedJob}
            onChange={(e) => setSelectedJob(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300 focus:outline-none focus:border-emerald-600"
          >
            {jobs.map((j) => (
              <option key={j.job_id} value={j.job_id}>
                Scan {j.job_id.slice(0, 8)} — {new Date(j.created_at).toLocaleDateString()}
              </option>
            ))}
          </select>
          <div className="flex items-center gap-2.5 text-[10px] text-zinc-500">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500" /> Agent
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-blue-500" /> Server
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-zinc-500" /> Package
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-500" /> CVE
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-amber-500" /> Cred
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-purple-500" /> Tool
            </span>
          </div>
        </div>
      </div>

      {/* Body: Filter + Graph + Detail */}
      <div className="flex-1 flex relative overflow-hidden">
        <FilterPanel
          filters={filters}
          onChange={setFilters}
          agentNames={agentNames}
        />

        <div className="flex-1 relative">
          <ReactFlow
            nodes={displayNodes}
            edges={displayEdges}
            nodeTypes={lineageNodeTypes}
            fitView
            minZoom={0.05}
            maxZoom={2.5}
            defaultEdgeOptions={{ type: "smoothstep" }}
            proOptions={{ hideAttribution: true }}
            onNodeClick={onNodeClick}
            onNodeMouseEnter={onNodeMouseEnter}
            onNodeMouseLeave={onNodeMouseLeave}
            onPaneClick={() => { setSelectedNode(null); setHoveredNodeId(null); }}
          >
            <Background color="#27272a" gap={20} />
            <Controls
              className="!bg-zinc-900 !border-zinc-700 !rounded-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300 [&>button:hover]:!bg-zinc-700"
            />
            <MiniMap
              nodeColor={(n) => {
                const d = n.data as LineageNodeData;
                const colors: Record<LineageNodeType, string> = {
                  agent: "#10b981",
                  server: "#3b82f6",
                  package: "#52525b",
                  vulnerability: "#ef4444",
                  credential: "#f59e0b",
                  tool: "#a855f7",
                };
                return colors[d.nodeType] ?? "#52525b";
              }}
              className="!bg-zinc-900 !border-zinc-700 !rounded-lg"
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
    </div>
  );
}
