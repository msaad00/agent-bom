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
import { ShieldAlert, Loader2, AlertTriangle } from "lucide-react";
import { api, type ScanJob, type ScanResult, type MCPServer } from "@/lib/api";
import { applyDagreLayout } from "@/lib/dagre-layout";
import { lineageNodeTypes, type LineageNodeData, type LineageNodeType } from "@/components/lineage-nodes";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { MeshStats, type MeshStatsData } from "@/components/mesh-stats";

// ─── Credential detection ────────────────────────────────────────────────────

const CRED_RE = /key|token|secret|password|credential|auth/i;

function getCredKeys(server: MCPServer): string[] {
  return server.env ? Object.keys(server.env).filter((k) => CRED_RE.test(k)) : [];
}

// ─── Shared Server Detection ─────────────────────────────────────────────────

interface ServerGroup {
  name: string;
  agents: Set<string>;
  servers: MCPServer[];
  totalTools: number;
  totalCreds: number;
  totalPackages: number;
  credNames: Set<string>;
}

function detectSharedServers(result: ScanResult): Map<string, ServerGroup> {
  const groups = new Map<string, ServerGroup>();

  for (const agent of result.agents) {
    for (const server of agent.mcp_servers) {
      const key = server.name;
      const existing = groups.get(key);
      const creds = getCredKeys(server);
      if (existing) {
        existing.agents.add(agent.name);
        existing.servers.push(server);
        existing.totalTools += server.tools?.length ?? 0;
        existing.totalCreds += creds.length;
        existing.totalPackages += server.packages.length;
        creds.forEach((c) => existing.credNames.add(c));
      } else {
        groups.set(key, {
          name: server.name,
          agents: new Set([agent.name]),
          servers: [server],
          totalTools: server.tools?.length ?? 0,
          totalCreds: creds.length,
          totalPackages: server.packages.length,
          credNames: new Set(creds),
        });
      }
    }
  }

  return groups;
}

// ─── Graph Builder ───────────────────────────────────────────────────────────

function buildMeshGraph(result: ScanResult): {
  nodes: Node[];
  edges: Edge[];
  stats: MeshStatsData;
} {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const seen = new Set<string>();

  const serverGroups = detectSharedServers(result);
  const sharedServerNames = new Set(
    [...serverGroups.entries()]
      .filter(([, g]) => g.agents.size > 1)
      .map(([name]) => name)
  );

  // Credential blast: creds exposed to multiple agents
  const credAgentMap = new Map<string, Set<string>>();
  for (const [, group] of serverGroups) {
    for (const cred of group.credNames) {
      const existing = credAgentMap.get(cred) ?? new Set<string>();
      group.agents.forEach((a) => existing.add(a));
      credAgentMap.set(cred, existing);
    }
  }
  const credentialBlast = [...credAgentMap.entries()]
    .filter(([, agents]) => agents.size > 1)
    .map(([cred, agents]) => `${cred} → ${agents.size} agents`);

  // Stats
  const allCreds = new Set<string>();
  for (const [, g] of serverGroups) g.credNames.forEach((c) => allCreds.add(c));

  // Tool overlap: tools available to >1 agent
  const toolAgentMap = new Map<string, Set<string>>();
  for (const agent of result.agents) {
    for (const server of agent.mcp_servers) {
      for (const tool of server.tools ?? []) {
        const existing = toolAgentMap.get(tool.name) ?? new Set<string>();
        existing.add(agent.name);
        toolAgentMap.set(tool.name, existing);
      }
    }
  }
  const toolOverlap = [...toolAgentMap.values()].filter((a) => a.size > 1).length;

  const stats: MeshStatsData = {
    totalAgents: result.agents.length,
    sharedServers: sharedServerNames.size,
    uniqueCredentials: allCreds.size,
    toolOverlap,
    credentialBlast,
  };

  // Agent nodes
  for (const agent of result.agents) {
    const agentId = `agent:${agent.name}`;
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
        packageCount: agent.mcp_servers.reduce((s, srv) => s + srv.packages.length, 0),
        vulnCount: totalVulns,
      } satisfies LineageNodeData,
    });
  }

  // Server nodes (shared vs regular)
  for (const [name, group] of serverGroups) {
    const isShared = group.agents.size > 1;
    const serverId = `server:${name}`;
    const firstServer = group.servers[0];

    nodes.push({
      id: serverId,
      type: isShared ? "sharedServerNode" : "serverNode",
      position: { x: 0, y: 0 },
      data: {
        label: name,
        nodeType: isShared ? "sharedServer" : "server",
        command: firstServer.command || firstServer.transport || "",
        toolCount: group.totalTools,
        credentialCount: group.totalCreds,
        packageCount: group.totalPackages,
        sharedBy: group.agents.size,
        sharedAgents: [...group.agents],
      } satisfies LineageNodeData,
    });

    // Agent → Server edges
    for (const agentName of group.agents) {
      const edgeId = `agent:${agentName}->server:${name}`;
      if (!seen.has(edgeId)) {
        seen.add(edgeId);
        edges.push({
          id: edgeId,
          source: `agent:${agentName}`,
          target: serverId,
          type: "smoothstep",
          animated: isShared,
          style: {
            stroke: isShared ? "#22d3ee" : "#10b981",
            strokeWidth: isShared ? 2.5 : 1.5,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isShared ? "#22d3ee" : "#10b981",
          },
        });
      }
    }

    // Credential nodes
    for (const cred of group.credNames) {
      const credId = `cred:${name}:${cred}`;
      if (!seen.has(credId)) {
        seen.add(credId);
        const multiAgent = (credAgentMap.get(cred)?.size ?? 0) > 1;
        nodes.push({
          id: credId,
          type: "credentialNode",
          position: { x: 0, y: 0 },
          data: {
            label: cred,
            nodeType: "credential",
            serverName: name,
            sharedBy: credAgentMap.get(cred)?.size,
          } satisfies LineageNodeData,
        });
        edges.push({
          id: `${serverId}->${credId}`,
          source: serverId,
          target: credId,
          type: "smoothstep",
          style: {
            stroke: multiAgent ? "#f59e0b" : "#92400e",
            strokeWidth: multiAgent ? 2 : 1,
            strokeDasharray: "5 3",
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#f59e0b" },
        });
      }
    }

    // Tool nodes (limit 5 per server for mesh readability)
    const allTools = group.servers.flatMap((s) => s.tools ?? []);
    const uniqueTools = [...new Map(allTools.map((t) => [t.name, t])).values()].slice(0, 5);
    for (const tool of uniqueTools) {
      const toolId = `tool:${name}:${tool.name}`;
      if (!seen.has(toolId)) {
        seen.add(toolId);
        const multiAgent = (toolAgentMap.get(tool.name)?.size ?? 0) > 1;
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
        edges.push({
          id: `${serverId}->${toolId}`,
          source: serverId,
          target: toolId,
          type: "smoothstep",
          style: {
            stroke: multiAgent ? "#a855f7" : "#6b21a8",
            strokeWidth: multiAgent ? 1.5 : 1,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#a855f7" },
        });
      }
    }
  }

  return { nodes, edges, stats };
}

// ─── Hover Highlighting ──────────────────────────────────────────────────────

function getConnectedIds(nodeId: string, edges: Edge[]): Set<string> {
  const connected = new Set<string>([nodeId]);
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
      if (e.target === current && !visited.has(e.source)) {
        visited.add(e.source);
        connected.add(e.source);
        queue.push(e.source);
      }
    }
  }
  return connected;
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function MeshPage() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<LineageNodeData | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

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

  const { rawNodes, rawEdges, stats } = useMemo(() => {
    if (!activeResult) return { rawNodes: [], rawEdges: [], stats: { totalAgents: 0, sharedServers: 0, uniqueCredentials: 0, toolOverlap: 0, credentialBlast: [] } };
    const { nodes, edges, stats } = buildMeshGraph(activeResult);
    return { rawNodes: nodes, rawEdges: edges, stats };
  }, [activeResult]);

  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(
    () =>
      rawNodes.length > 0
        ? applyDagreLayout(rawNodes, rawEdges, {
            direction: "LR",
            nodeWidth: 200,
            nodeHeight: 70,
            rankSep: 120,
            nodeSep: 30,
          })
        : { nodes: [], edges: [] },
    [rawNodes, rawEdges]
  );

  const connectedIds = useMemo(
    () => (hoveredNodeId ? getConnectedIds(hoveredNodeId, layoutEdges) : null),
    [hoveredNodeId, layoutEdges]
  );

  const displayNodes = useMemo(() => {
    if (!connectedIds) return layoutNodes;
    return layoutNodes.map((n) => ({
      ...n,
      data: { ...n.data, dimmed: !connectedIds.has(n.id), highlighted: connectedIds.has(n.id) },
    }));
  }, [layoutNodes, connectedIds]);

  const displayEdges = useMemo(() => {
    if (!connectedIds) return layoutEdges;
    return layoutEdges.map((e) => ({
      ...e,
      style: {
        ...e.style,
        opacity: connectedIds.has(e.source) && connectedIds.has(e.target) ? 1 : 0.12,
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
            Cross-agent topology — shared servers, credential blast, tool overlap
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
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Shared
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-blue-500" /> Server
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

      {/* Stats bar */}
      <MeshStats stats={stats} />

      {/* Graph */}
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
                sharedServer: "#22d3ee",
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
  );
}
