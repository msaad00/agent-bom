"use client";

import { useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  ReactFlowProvider,
  useReactFlow,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Server, ShieldAlert, Wrench, Key, Package, Download, Bug } from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

interface MeshNodeData {
  nodeType: "agent" | "server" | "tool";
  label: string;
  agent_type?: string;
  server_count?: number;
  transport?: string;
  package_count?: number;
  tool_count?: number;
  credential_count?: number;
  vuln_count?: number;
  color?: string;
}

export interface MeshStats {
  total_agents: number;
  total_servers: number;
  total_packages: number;
  total_tools: number;
  total_credentials: number;
  total_vulnerabilities: number;
}

export interface MeshData {
  nodes: Node[];
  edges: Edge[];
  stats: MeshStats;
}

// ─── Mesh Node Renderer ─────────────────────────────────────────────────────

function MeshNode({ data }: { data: MeshNodeData }) {
  const { nodeType } = data;

  if (nodeType === "agent") {
    return (
      <div className="rounded-xl border-2 border-emerald-600 bg-emerald-950/80 px-4 py-3 min-w-[160px] shadow-lg">
        <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2" />
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="text-sm font-semibold text-zinc-100 truncate">{data.label}</span>
        </div>
        <div className="text-[10px] text-zinc-500 mt-0.5">{data.agent_type}</div>
        <div className="flex items-center gap-3 mt-1.5 text-[10px] text-zinc-400">
          <span className="flex items-center gap-0.5">
            <Server className="w-2.5 h-2.5" /> {data.server_count ?? 0}
          </span>
          {(data.vuln_count ?? 0) > 0 && (
            <span className="flex items-center gap-0.5 text-red-400 font-medium">
              <Bug className="w-2.5 h-2.5" /> {data.vuln_count}
            </span>
          )}
        </div>
        <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2" />
      </div>
    );
  }

  if (nodeType === "server") {
    const borderColor = data.color ? `border-[${data.color}]` : "border-blue-600";
    return (
      <div
        className={`rounded-lg border-2 ${borderColor} bg-blue-950/80 px-3 py-2 min-w-[140px] shadow-lg`}
        style={data.color ? { borderColor: data.color } : undefined}
      >
        <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2" />
        <div className="flex items-center gap-2">
          <Server className="w-3.5 h-3.5 text-blue-400 shrink-0" />
          <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
        </div>
        {data.transport && (
          <div className="text-[10px] text-zinc-500 mt-0.5 font-mono">{data.transport}</div>
        )}
        <div className="flex items-center gap-2 mt-1 text-[10px] text-zinc-400">
          {(data.package_count ?? 0) > 0 && (
            <span className="flex items-center gap-0.5">
              <Package className="w-2.5 h-2.5" /> {data.package_count}
            </span>
          )}
          {(data.tool_count ?? 0) > 0 && (
            <span className="flex items-center gap-0.5">
              <Wrench className="w-2.5 h-2.5" /> {data.tool_count}
            </span>
          )}
          {(data.credential_count ?? 0) > 0 && (
            <span className="flex items-center gap-0.5 text-yellow-400">
              <Key className="w-2.5 h-2.5" /> {data.credential_count}
            </span>
          )}
          {(data.vuln_count ?? 0) > 0 && (
            <span className="flex items-center gap-0.5 text-red-400 font-medium">
              <Bug className="w-2.5 h-2.5" /> {data.vuln_count}
            </span>
          )}
        </div>
        <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2" />
      </div>
    );
  }

  // tool node
  return (
    <div className="rounded-md border-2 border-purple-600 bg-purple-950/80 px-2.5 py-1.5 min-w-[100px] shadow-lg">
      <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2" />
      <div className="flex items-center gap-1.5">
        <Wrench className="w-3 h-3 text-purple-400 shrink-0" />
        <span className="text-[11px] font-medium text-zinc-200 truncate">{data.label}</span>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2" />
    </div>
  );
}

const meshNodeTypes = { meshNode: MeshNode };

// ─── Minimap Colors ─────────────────────────────────────────────────────────

const MESH_MINIMAP_COLORS: Record<string, string> = {
  agent: "#10b981",
  server: "#3b82f6",
  tool: "#a855f7",
};

// ─── Stats Bar ──────────────────────────────────────────────────────────────

function MeshStatsBar({ stats }: { stats: MeshStats }) {
  const items = [
    { icon: ShieldAlert, label: "Agents", value: stats.total_agents, color: "text-emerald-400" },
    { icon: Server, label: "Servers", value: stats.total_servers, color: "text-blue-400" },
    { icon: Package, label: "Packages", value: stats.total_packages, color: "text-zinc-400" },
    { icon: Wrench, label: "Tools", value: stats.total_tools, color: "text-purple-400" },
    { icon: Key, label: "Credentials", value: stats.total_credentials, color: "text-yellow-400" },
    { icon: Bug, label: "Vulns", value: stats.total_vulnerabilities, color: "text-red-400" },
  ];

  return (
    <div className="flex items-center gap-4 text-xs">
      {items.map((s) => (
        <div key={s.label} className="flex items-center gap-1.5">
          <s.icon className={`w-3 h-3 ${s.color}`} />
          <span className="text-zinc-500">{s.label}</span>
          <span className={`font-bold ${s.color}`}>{s.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Inner Flow (needs ReactFlowProvider) ───────────────────────────────────

function MeshFlow({ data, onAgentClick, onExport }: {
  data: MeshData;
  onAgentClick: (name: string) => void;
  onExport: () => void;
}) {
  const { fitView } = useReactFlow();

  useEffect(() => {
    setTimeout(() => fitView({ padding: 0.2 }), 100);
  }, [fitView, data]);

  const handleNodeClick = useCallback(
    (_: unknown, node: Node) => {
      const d = node.data as MeshNodeData;
      if (d.nodeType === "agent") {
        onAgentClick(d.label);
      }
    },
    [onAgentClick],
  );

  return (
    <div className="relative w-full h-full">
      <div className="absolute top-0 left-0 right-0 z-10 bg-zinc-950/90 backdrop-blur-sm border-b border-zinc-800 px-4 py-3 flex items-center justify-between">
        <MeshStatsBar stats={data.stats} />
        <button
          onClick={onExport}
          className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 text-xs border border-zinc-700 rounded px-2 py-1"
        >
          <Download className="w-3.5 h-3.5" /> Export JSON
        </button>
      </div>

      <ReactFlow
        nodes={data.nodes}
        edges={data.edges}
        nodeTypes={meshNodeTypes}
        onNodeClick={handleNodeClick}
        fitView
        minZoom={0.1}
        maxZoom={2}
        panOnDrag
        className="!bg-zinc-950"
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#27272a" gap={20} />
        <Controls className="!bg-zinc-900 !border-zinc-700 !rounded-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300" />
        <MiniMap
          nodeColor={(n) => MESH_MINIMAP_COLORS[(n.data as MeshNodeData)?.nodeType] ?? "#52525b"}
          className="!bg-zinc-900 !border-zinc-700 !rounded-lg"
          maskColor="rgba(0,0,0,0.7)"
        />
      </ReactFlow>
    </div>
  );
}

// ─── Public Component ───────────────────────────────────────────────────────

export function AgentMesh({ data }: { data: MeshData }) {
  const router = useRouter();

  const handleAgentClick = useCallback(
    (name: string) => {
      router.push(`/agents?name=${encodeURIComponent(name)}`);
    },
    [router],
  );

  const handleExport = useCallback(() => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "agent-mesh.json";
    a.click();
    URL.revokeObjectURL(url);
  }, [data]);

  if (!data.nodes.length) return null;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden" style={{ height: 520 }}>
      <ReactFlowProvider>
        <MeshFlow data={data} onAgentClick={handleAgentClick} onExport={handleExport} />
      </ReactFlowProvider>
    </div>
  );
}
