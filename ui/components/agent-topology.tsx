"use client";

import { useCallback, useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  ReactFlow,
  Background,
  Controls,
  ReactFlowProvider,
  useReactFlow,
  Handle,
  Position,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Server, ShieldAlert, Package, Lock, Wrench } from "lucide-react";
import type { Agent } from "@/lib/api";

// ─── Custom Node Components with proper Handles ─────────────────────────────

function AgentNode({ data }: { data: { label: string; type: string; serverCount: number; vulnCount: number } }) {
  return (
    <div className="rounded-xl border border-emerald-500/40 bg-zinc-900/90 backdrop-blur px-4 py-3 min-w-[140px] shadow-lg shadow-emerald-500/5 hover:border-emerald-400/60 transition-colors cursor-pointer">
      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-emerald-400 !border-emerald-500" />
      <Handle type="source" position={Position.Bottom} className="!w-2 !h-2 !bg-emerald-400 !border-emerald-500" />
      <div className="flex items-center gap-2.5 mb-1.5">
        <div className="w-7 h-7 rounded-lg bg-emerald-500/15 flex items-center justify-center">
          <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
        </div>
        <div className="min-w-0">
          <span className="text-xs font-semibold text-zinc-100 block truncate">{data.label}</span>
          <span className="text-[10px] text-zinc-500">{data.type}</span>
        </div>
      </div>
      <div className="flex items-center gap-3 text-[10px] text-zinc-500 mt-1 border-t border-zinc-800/60 pt-1.5">
        <span className="flex items-center gap-1">
          <Server className="w-3 h-3" />
          {data.serverCount}
        </span>
        {data.vulnCount > 0 && (
          <span className="flex items-center gap-1 text-red-400">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
            {data.vulnCount} CVE{data.vulnCount !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </div>
  );
}

function ServerNode({ data }: { data: { label: string; pkgCount: number; toolCount: number; hasCredentials: boolean; vulnCount: number } }) {
  const borderColor = data.vulnCount > 0 ? "border-red-500/40 hover:border-red-400/60" : "border-blue-500/30 hover:border-blue-400/50";
  const shadowColor = data.vulnCount > 0 ? "shadow-red-500/5" : "shadow-blue-500/5";

  return (
    <div className={`rounded-xl border ${borderColor} bg-zinc-900/90 backdrop-blur px-4 py-3 min-w-[140px] shadow-lg ${shadowColor} transition-colors`}>
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-blue-400 !border-blue-500" />
      <Handle type="target" position={Position.Top} className="!w-2 !h-2 !bg-blue-400 !border-blue-500" />
      <div className="flex items-center gap-2.5 mb-1.5">
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${data.vulnCount > 0 ? "bg-red-500/15" : "bg-blue-500/15"}`}>
          <Server className={`w-3.5 h-3.5 ${data.vulnCount > 0 ? "text-red-400" : "text-blue-400"}`} />
        </div>
        <span className="text-xs font-semibold text-zinc-100 truncate max-w-[120px]">{data.label}</span>
      </div>
      <div className="flex items-center gap-2.5 text-[10px] text-zinc-500 mt-1 border-t border-zinc-800/60 pt-1.5 flex-wrap">
        <span className="flex items-center gap-1">
          <Package className="w-3 h-3" />
          {data.pkgCount}
        </span>
        {data.toolCount > 0 && (
          <span className="flex items-center gap-1">
            <Wrench className="w-3 h-3" />
            {data.toolCount}
          </span>
        )}
        {data.hasCredentials && (
          <span className="flex items-center gap-1 text-yellow-400">
            <Lock className="w-3 h-3" />
          </span>
        )}
        {data.vulnCount > 0 && (
          <span className="flex items-center gap-1 text-red-400 font-medium">
            {data.vulnCount} CVE{data.vulnCount !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </div>
  );
}

const nodeTypes = { agentNode: AgentNode, serverNode: ServerNode };

// ─── Graph builder ──────────────────────────────────────────────────────────

function buildGraph(agents: Agent[], direction: "LR" | "TB" = "LR"): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const GAP_Y = 110;
  const GAP_X = 120;
  const OFFSET = 320;

  let cursor = 0;

  for (const agent of agents) {
    const agentId = `agent-${agent.name}`;
    const servers = agent.mcp_servers || [];

    // Count total vulns across servers
    const totalVulns = servers.reduce((acc, srv) => {
      return acc + (srv.packages || []).reduce((a, p) => a + (p.vulnerabilities?.length || 0), 0);
    }, 0);

    if (direction === "TB") {
      nodes.push({
        id: agentId,
        type: "agentNode",
        position: { x: cursor, y: 0 },
        data: { label: agent.name, type: agent.agent_type || "agent", serverCount: servers.length, vulnCount: totalVulns },
      });

      const serverStartX = cursor - ((servers.length - 1) * GAP_X) / 2;
      servers.forEach((srv, i) => {
        const srvId = `srv-${agent.name}-${srv.name}`;
        const srvVulns = (srv.packages || []).reduce((a, p) => a + (p.vulnerabilities?.length || 0), 0);

        nodes.push({
          id: srvId,
          type: "serverNode",
          position: { x: serverStartX + i * GAP_X, y: OFFSET },
          data: {
            label: srv.name,
            pkgCount: (srv.packages || []).length,
            toolCount: srv.tools?.length ?? 0,
            hasCredentials: Object.keys(srv.env || {}).length > 0,
            vulnCount: srvVulns,
          },
        });
        edges.push({
          id: `e-${agentId}-${srvId}`,
          source: agentId,
          target: srvId,
          type: "smoothstep",
          animated: srvVulns > 0,
          style: { stroke: srvVulns > 0 ? "#ef4444" : "#10b981", strokeWidth: 1.5, opacity: 0.7 },
        });
      });

      cursor += Math.max(servers.length, 1) * GAP_X + 100;
    } else {
      nodes.push({
        id: agentId,
        type: "agentNode",
        position: { x: 0, y: cursor },
        data: { label: agent.name, type: agent.agent_type || "agent", serverCount: servers.length, vulnCount: totalVulns },
      });

      const serverStartY = cursor - ((servers.length - 1) * GAP_Y) / 2;
      servers.forEach((srv, i) => {
        const srvId = `srv-${agent.name}-${srv.name}`;
        const srvVulns = (srv.packages || []).reduce((a, p) => a + (p.vulnerabilities?.length || 0), 0);

        nodes.push({
          id: srvId,
          type: "serverNode",
          position: { x: OFFSET, y: serverStartY + i * GAP_Y },
          data: {
            label: srv.name,
            pkgCount: (srv.packages || []).length,
            toolCount: srv.tools?.length ?? 0,
            hasCredentials: Object.keys(srv.env || {}).length > 0,
            vulnCount: srvVulns,
          },
        });
        edges.push({
          id: `e-${agentId}-${srvId}`,
          source: agentId,
          target: srvId,
          type: "smoothstep",
          animated: srvVulns > 0,
          style: { stroke: srvVulns > 0 ? "#ef4444" : "#10b981", strokeWidth: 1.5, opacity: 0.7 },
        });
      });

      cursor += Math.max(servers.length, 1) * GAP_Y + 50;
    }
  }

  return { nodes, edges };
}

// ─── Inner flow (needs ReactFlowProvider) ───────────────────────────────────

function TopologyFlow({ agents, onAgentClick, direction = "LR" }: { agents: Agent[]; onAgentClick: (name: string) => void; direction?: "LR" | "TB" }) {
  const { fitView } = useReactFlow();
  const { nodes, edges } = useMemo(() => buildGraph(agents, direction), [agents, direction]);

  useEffect(() => {
    setTimeout(() => fitView({ padding: 0.25 }), 150);
  }, [fitView, nodes]);

  const handleNodeClick = useCallback(
    (_: unknown, node: Node) => {
      if (node.id.startsWith("agent-")) {
        onAgentClick(node.id.replace("agent-", ""));
      }
    },
    [onAgentClick],
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={handleNodeClick}
      fitView
      minZoom={0.2}
      maxZoom={2}
      panOnDrag
      zoomOnScroll
      className="!bg-zinc-950"
      proOptions={{ hideAttribution: true }}
    >
      <Background color="#1a1a1e" gap={24} size={1} />
      <Controls
        showInteractive={false}
        className="!bg-zinc-900 !border-zinc-700 !rounded-lg !shadow-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-400 [&>button:hover]:!bg-zinc-700"
      />
    </ReactFlow>
  );
}

// ─── Public component ───────────────────────────────────────────────────────

export function AgentTopology({ agents, direction = "LR" }: { agents: Agent[]; direction?: "LR" | "TB" }) {
  const router = useRouter();

  const handleAgentClick = useCallback(
    (name: string) => {
      router.push(`/agents?name=${encodeURIComponent(name)}`);
    },
    [router],
  );

  if (!agents || agents.length === 0) {
    return (
      <div className="bg-zinc-900/50 border border-zinc-800/60 rounded-xl flex items-center justify-center h-[320px]">
        <div className="text-center">
          <Network className="w-8 h-8 text-zinc-700 mx-auto mb-2" />
          <p className="text-sm text-zinc-500">No agents discovered yet</p>
          <p className="text-xs text-zinc-600 mt-1">Run a scan to see the topology</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-zinc-900/50 border border-zinc-800/60 rounded-xl overflow-hidden" style={{ height: 400 }}>
      <ReactFlowProvider>
        <TopologyFlow agents={agents} onAgentClick={handleAgentClick} direction={direction} />
      </ReactFlowProvider>
    </div>
  );
}

// Need to import Network for the empty state
import { Network } from "lucide-react";
