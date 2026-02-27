"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
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
import {
  ArrowLeft,
  Bug,
  Download,
  KeyRound,
  Loader2,
  Package,
  Server,
  ShieldAlert,
  Wrench,
  X,
} from "lucide-react";
import { api, type AgentLifecycleResponse, type AttackFlowNodeData } from "@/lib/api";
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

const MINIMAP_COLORS: Record<string, string> = {
  cve: "#ef4444",
  package: "#52525b",
  server: "#3b82f6",
  agent: "#10b981",
  credential: "#eab308",
  tool: "#a855f7",
};

// ─── Custom Node ─────────────────────────────────────────────────────────────

function LifecycleNode({ data }: { data: AttackFlowNodeData }) {
  const nodeType = data.nodeType;
  const Icon = NODE_ICONS[nodeType] ?? Bug;

  const sevColors: Record<string, string> = {
    critical: "border-red-500 bg-red-950",
    high: "border-orange-500 bg-orange-950",
    medium: "border-yellow-500 bg-yellow-950",
    low: "border-blue-500 bg-blue-950",
  };
  const border = nodeType === "cve" && data.severity
    ? sevColors[data.severity.toLowerCase()] ?? NODE_COLORS[nodeType]
    : NODE_COLORS[nodeType];

  return (
    <div className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[200px] shadow-lg ${border}`}>
      <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2" />
      <div className="flex items-center gap-2">
        <Icon className="w-3.5 h-3.5 shrink-0 text-zinc-300" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      {data.version && (
        <div className="text-[10px] text-zinc-500 mt-0.5 font-mono">{data.version}</div>
      )}
      {data.severity && (
        <div className="mt-1"><SeverityBadge severity={data.severity} /></div>
      )}
      {data.description && (
        <div className="text-[10px] text-zinc-500 mt-0.5 truncate">{data.description}</div>
      )}
      <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2" />
    </div>
  );
}

const nodeTypes = { lifecycleNode: LifecycleNode };

// ─── Stats Bar ───────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: Record<string, number> }) {
  const items = [
    { label: "Servers", value: stats.total_servers ?? 0, color: "text-blue-400" },
    { label: "Packages", value: stats.total_packages ?? 0, color: "text-zinc-400" },
    { label: "Tools", value: stats.total_tools ?? 0, color: "text-purple-400" },
    { label: "Credentials", value: stats.total_credentials ?? 0, color: "text-yellow-400" },
    { label: "Vulns", value: stats.total_vulnerabilities ?? 0, color: "text-red-400" },
  ];
  return (
    <div className="flex items-center gap-4 text-xs">
      {items.map((s) => (
        <div key={s.label} className="flex items-center gap-1">
          <span className={`font-bold ${s.color}`}>{s.value}</span>
          <span className="text-zinc-500">{s.label}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Detail Panel ────────────────────────────────────────────────────────────

function DetailPanel({
  node,
  onClose,
}: {
  node: Node<AttackFlowNodeData>;
  onClose: () => void;
}) {
  const d = node.data;
  const Icon = NODE_ICONS[d.nodeType] ?? Bug;
  return (
    <div className="absolute top-4 right-4 w-72 bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl z-50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-zinc-400" />
          <span className="font-semibold text-sm">{d.label}</span>
        </div>
        <button onClick={onClose} className="text-zinc-500 hover:text-zinc-200">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="px-4 py-3 space-y-2 text-xs">
        <div className="flex justify-between text-zinc-400">
          <span>Type</span>
          <span className="text-zinc-200 capitalize">{d.nodeType}</span>
        </div>
        {d.severity && (
          <div className="flex justify-between">
            <span className="text-zinc-400">Severity</span>
            <SeverityBadge severity={d.severity} />
          </div>
        )}
        {d.cvss_score != null && (
          <div className="flex justify-between text-zinc-400">
            <span>CVSS</span>
            <span className="text-zinc-200">{d.cvss_score}</span>
          </div>
        )}
        {d.version && (
          <div className="flex justify-between text-zinc-400">
            <span>Version</span>
            <span className="text-zinc-200 font-mono">{d.version}</span>
          </div>
        )}
        {d.ecosystem && (
          <div className="flex justify-between text-zinc-400">
            <span>Ecosystem</span>
            <span className="text-zinc-200">{d.ecosystem}</span>
          </div>
        )}
        {d.agent_type && (
          <div className="flex justify-between text-zinc-400">
            <span>Agent Type</span>
            <span className="text-zinc-200">{d.agent_type}</span>
          </div>
        )}
        {d.description && (
          <div className="text-zinc-400 pt-1 border-t border-zinc-800">
            <span className="block mb-0.5">Description</span>
            <span className="text-zinc-300">{d.description}</span>
          </div>
        )}
        {d.fixed_version && (
          <div className="flex justify-between text-zinc-400">
            <span>Fix Available</span>
            <span className="text-emerald-400 font-mono">{d.fixed_version}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Flow Canvas ─────────────────────────────────────────────────────────────

function LifecycleFlow({
  data,
  agentName,
}: {
  data: AgentLifecycleResponse;
  agentName: string;
}) {
  const { fitView } = useReactFlow();
  const [selectedNode, setSelectedNode] = useState<Node<AttackFlowNodeData> | null>(null);

  useEffect(() => {
    setTimeout(() => fitView({ padding: 0.2 }), 100);
  }, [fitView, data]);

  const onNodeClick = useCallback((_: unknown, node: Node) => {
    setSelectedNode(node as Node<AttackFlowNodeData>);
  }, []);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${agentName}-lifecycle.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="relative w-full h-full">
      {/* Header bar */}
      <div className="absolute top-0 left-0 right-0 z-10 bg-zinc-950/90 backdrop-blur-sm border-b border-zinc-800 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            href={`/agents/${encodeURIComponent(agentName)}`}
            className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 text-sm"
          >
            <ArrowLeft className="w-4 h-4" /> {agentName}
          </Link>
          <span className="text-zinc-600">|</span>
          <span className="text-sm font-semibold text-zinc-300">Lifecycle Graph</span>
        </div>
        <div className="flex items-center gap-4">
          <StatsBar stats={data.stats} />
          <button
            onClick={handleExport}
            className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 text-xs border border-zinc-700 rounded px-2 py-1"
          >
            <Download className="w-3.5 h-3.5" /> Export
          </button>
        </div>
      </div>

      <ReactFlow
        nodes={data.nodes as Node[]}
        edges={data.edges as Edge[]}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        fitView
        minZoom={0.1}
        maxZoom={2}
        className="!bg-zinc-950"
      >
        <Background color="#27272a" gap={20} />
        <Controls className="!bg-zinc-900 !border-zinc-700 !rounded-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300" />
        <MiniMap
          nodeColor={(n) => MINIMAP_COLORS[(n.data as AttackFlowNodeData)?.nodeType] ?? "#52525b"}
          className="!bg-zinc-900 !border-zinc-700 !rounded-lg"
          maskColor="rgba(0,0,0,0.7)"
        />
      </ReactFlow>

      {selectedNode && (
        <DetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AgentLifecyclePage({
  params,
}: {
  params: Promise<{ name: string }>;
}) {
  const { name } = use(params);
  const agentName = decodeURIComponent(name);
  const [data, setData] = useState<AgentLifecycleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getAgentLifecycle(agentName)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [agentName]);

  if (loading) {
    return (
      <div className="h-screen bg-zinc-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-zinc-500" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="h-screen bg-zinc-950 p-8">
        <Link href="/agents" className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 mb-6">
          <ArrowLeft className="w-4 h-4" /> Back to agents
        </Link>
        <div className="text-red-400 bg-red-950 border border-red-800 rounded-lg p-4">
          {error || "Agent not found"}
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen bg-zinc-950">
      <ReactFlowProvider>
        <LifecycleFlow data={data} agentName={agentName} />
      </ReactFlowProvider>
    </div>
  );
}
