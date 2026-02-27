"use client";

import { useCallback, useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  ReactFlow,
  Background,
  ReactFlowProvider,
  useReactFlow,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Server, ShieldAlert } from "lucide-react";
import type { Agent } from "@/lib/api";

// ─── Node renderers ─────────────────────────────────────────────────────────

function AgentNode({ data }: { data: { label: string; type: string } }) {
  return (
    <div className="rounded-lg border-2 border-emerald-600 bg-emerald-950/80 px-3 py-2 min-w-[120px] shadow-lg">
      <div className="flex items-center gap-2">
        <ShieldAlert className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      <div className="text-[10px] text-zinc-500 mt-0.5">{data.type}</div>
    </div>
  );
}

function ServerNode({ data }: { data: { label: string; pkgCount: number; toolCount: number } }) {
  return (
    <div className="rounded-lg border-2 border-blue-600 bg-blue-950/80 px-3 py-2 min-w-[120px] shadow-lg">
      <div className="flex items-center gap-2">
        <Server className="w-3.5 h-3.5 text-blue-400 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      <div className="text-[10px] text-zinc-500 mt-0.5">
        {data.pkgCount} pkg{data.pkgCount !== 1 ? "s" : ""}
        {data.toolCount > 0 && ` · ${data.toolCount} tool${data.toolCount !== 1 ? "s" : ""}`}
      </div>
    </div>
  );
}

const nodeTypes = { agentNode: AgentNode, serverNode: ServerNode };

// ─── Graph builder ──────────────────────────────────────────────────────────

function buildGraph(agents: Agent[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const Y_GAP = 100;
  const X_GAP = 280;

  let agentY = 0;

  for (const agent of agents) {
    const agentId = `agent-${agent.name}`;
    nodes.push({
      id: agentId,
      type: "agentNode",
      position: { x: 0, y: agentY },
      data: { label: agent.name, type: agent.agent_type },
    });

    const servers = agent.mcp_servers;
    const serverStartY = agentY - ((servers.length - 1) * Y_GAP) / 2;

    servers.forEach((srv, i) => {
      const srvId = `srv-${agent.name}-${srv.name}`;
      nodes.push({
        id: srvId,
        type: "serverNode",
        position: { x: X_GAP, y: serverStartY + i * Y_GAP },
        data: {
          label: srv.name,
          pkgCount: srv.packages.length,
          toolCount: srv.tools?.length ?? 0,
        },
      });
      edges.push({
        id: `e-${agentId}-${srvId}`,
        source: agentId,
        target: srvId,
        type: "smoothstep",
        style: { stroke: "#10b981" },
      });
    });

    agentY += Math.max(servers.length, 1) * Y_GAP + 40;
  }

  return { nodes, edges };
}

// ─── Inner flow (needs ReactFlowProvider) ───────────────────────────────────

function TopologyFlow({ agents, onAgentClick }: { agents: Agent[]; onAgentClick: (name: string) => void }) {
  const { fitView } = useReactFlow();
  const { nodes, edges } = useMemo(() => buildGraph(agents), [agents]);

  useEffect(() => {
    setTimeout(() => fitView({ padding: 0.3 }), 100);
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
      minZoom={0.3}
      maxZoom={1.5}
      panOnDrag
      zoomOnScroll={false}
      className="!bg-zinc-950"
      proOptions={{ hideAttribution: true }}
    >
      <Background color="#27272a" gap={20} />
    </ReactFlow>
  );
}

// ─── Public component ───────────────────────────────────────────────────────

export function AgentTopology({ agents }: { agents: Agent[] }) {
  const router = useRouter();

  const handleAgentClick = useCallback(
    (name: string) => {
      router.push(`/agents/${encodeURIComponent(name)}`);
    },
    [router],
  );

  if (agents.length === 0) return null;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden" style={{ height: 320 }}>
      <ReactFlowProvider>
        <TopologyFlow agents={agents} onAgentClick={handleAgentClick} />
      </ReactFlowProvider>
    </div>
  );
}
