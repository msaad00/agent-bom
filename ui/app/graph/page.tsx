"use client";

import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  type Node,
  type Edge,
  Position,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ShieldAlert,
  Server,
  Package,
  Bug,
  KeyRound,
  Wrench,
  Loader2,
  AlertTriangle,
  X,
  ExternalLink,
} from "lucide-react";
import { api, type ScanJob, type ScanResult, severityColor } from "@/lib/api";

// ─── Custom Node Component ───────────────────────────────────────────────────

type NodeData = {
  label: string;
  type: "agent" | "server" | "package" | "vulnerability";
  severity?: string;
  meta?: string;
  tools?: number;
  credentials?: number;
  vulnCount?: number;
  agentStatus?: string;
};

function CustomNode({ data }: { data: NodeData }) {
  const icons = {
    agent: ShieldAlert,
    server: Server,
    package: Package,
    vulnerability: Bug,
  };
  const colors = {
    agent: data.agentStatus === "installed-not-configured"
      ? "border-yellow-600 bg-yellow-950/80 border-dashed"
      : "border-emerald-600 bg-emerald-950/80",
    server: "border-blue-600 bg-blue-950/80",
    package: "border-zinc-600 bg-zinc-900/80",
    vulnerability: data.severity === "critical"
      ? "border-red-600 bg-red-950/80"
      : data.severity === "high"
      ? "border-orange-600 bg-orange-950/80"
      : data.severity === "medium"
      ? "border-yellow-600 bg-yellow-950/80"
      : "border-blue-600 bg-blue-950/80",
  };
  const Icon = icons[data.type];

  const hasTarget = data.type !== "agent";
  const hasSource = data.type !== "vulnerability";

  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[200px] shadow-lg backdrop-blur ${colors[data.type]}`}
    >
      {hasTarget && (
        <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2 !border-zinc-400" />
      )}
      <div className="flex items-center gap-1.5 mb-0.5">
        <Icon className="w-3.5 h-3.5 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      {data.meta && (
        <div className="text-[10px] text-zinc-400 truncate">{data.meta}</div>
      )}
      <div className="flex gap-2 mt-1">
        {data.type === "server" && data.tools !== undefined && data.tools > 0 && (
          <span className="flex items-center gap-0.5 text-[10px] text-zinc-500">
            <Wrench className="w-2.5 h-2.5" /> {data.tools}
          </span>
        )}
        {data.type === "server" && data.credentials !== undefined && data.credentials > 0 && (
          <span className="flex items-center gap-0.5 text-[10px] text-amber-500">
            <KeyRound className="w-2.5 h-2.5" /> {data.credentials}
          </span>
        )}
        {data.type === "package" && data.vulnCount !== undefined && data.vulnCount > 0 && (
          <span className="flex items-center gap-0.5 text-[10px] text-red-400">
            <Bug className="w-2.5 h-2.5" /> {data.vulnCount} CVE{data.vulnCount > 1 ? "s" : ""}
          </span>
        )}
        {data.type === "vulnerability" && data.severity && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${severityColor(data.severity)}`}>
            {data.severity}
          </span>
        )}
      </div>
      {hasSource && (
        <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2 !border-zinc-400" />
      )}
    </div>
  );
}

const nodeTypes = { custom: CustomNode };

// ─── Graph Builder ───────────────────────────────────────────────────────────

function buildGraph(result: ScanResult): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const seen = new Set<string>();

  let agentY = 0;

  for (const agent of result.agents) {
    const agentId = `agent:${agent.name}`;
    if (seen.has(agentId)) continue;
    seen.add(agentId);

    nodes.push({
      id: agentId,
      type: "custom",
      position: { x: 0, y: agentY },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: {
        label: agent.name,
        type: "agent",
        meta: agent.agent_type,
        agentStatus: agent.status,
      },
    });

    let serverY = agentY - ((agent.mcp_servers.length - 1) * 100) / 2;

    for (const server of agent.mcp_servers) {
      const serverId = `server:${agent.name}:${server.name}`;
      if (!seen.has(serverId)) {
        seen.add(serverId);
        const credCount = server.env
          ? Object.keys(server.env).filter((k) =>
              /key|token|secret|password|credential|auth/i.test(k)
            ).length
          : 0;

        nodes.push({
          id: serverId,
          type: "custom",
          position: { x: 300, y: serverY },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: server.name,
            type: "server",
            meta: server.command || server.transport || "",
            tools: server.tools?.length || 0,
            credentials: credCount,
          },
        });
      }

      edges.push({
        id: `${agentId}->${serverId}`,
        source: agentId,
        target: serverId,
        type: "smoothstep",
        animated: true,
        style: { stroke: "#10b981", strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#10b981" },
      });

      let pkgY = serverY - ((server.packages.length - 1) * 80) / 2;

      for (const pkg of server.packages) {
        const pkgId = `pkg:${pkg.name}@${pkg.version}`;
        if (!seen.has(pkgId)) {
          seen.add(pkgId);
          const vulnCount = pkg.vulnerabilities?.length || 0;

          nodes.push({
            id: pkgId,
            type: "custom",
            position: { x: 600, y: pkgY },
            sourcePosition: Position.Right,
            targetPosition: Position.Left,
            data: {
              label: `${pkg.name}@${pkg.version}`,
              type: "package",
              meta: pkg.ecosystem,
              vulnCount,
            },
          });

          // Vulnerability nodes
          let vulnY = pkgY;
          for (const vuln of pkg.vulnerabilities || []) {
            const vulnId = `vuln:${vuln.id}`;
            if (!seen.has(vulnId)) {
              seen.add(vulnId);
              nodes.push({
                id: vulnId,
                type: "custom",
                position: { x: 900, y: vulnY },
                targetPosition: Position.Left,
                data: {
                  label: vuln.id,
                  type: "vulnerability",
                  severity: vuln.severity,
                  meta: vuln.cvss_score ? `CVSS ${vuln.cvss_score}` : undefined,
                },
              });
            }

            edges.push({
              id: `${pkgId}->${vulnId}`,
              source: pkgId,
              target: vulnId,
              type: "smoothstep",
              style: {
                stroke: vuln.severity === "critical" ? "#ef4444" : vuln.severity === "high" ? "#f97316" : "#eab308",
                strokeWidth: 2,
              },
              markerEnd: {
                type: MarkerType.ArrowClosed,
                color: vuln.severity === "critical" ? "#ef4444" : vuln.severity === "high" ? "#f97316" : "#eab308",
              },
            });
            vulnY += 70;
          }
        }

        edges.push({
          id: `${serverId}->${pkgId}`,
          source: serverId,
          target: pkgId,
          type: "smoothstep",
          style: { stroke: "#3b82f6", strokeWidth: 1.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#3b82f6" },
        });

        pkgY += 80;
      }

      serverY += 120;
    }

    agentY += Math.max(agent.mcp_servers.length * 120, 200);
  }

  return { nodes, edges };
}

// ─── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({ data, onClose }: { data: NodeData; onClose: () => void }) {
  const typeLabels = { agent: "Agent", server: "MCP Server", package: "Package", vulnerability: "Vulnerability" };
  const typeColors = {
    agent: "border-emerald-700",
    server: "border-blue-700",
    package: "border-zinc-700",
    vulnerability: "border-red-700",
  };

  return (
    <div className={`absolute right-0 top-0 bottom-0 w-80 bg-zinc-950/95 backdrop-blur-sm border-l ${typeColors[data.type]} z-50 overflow-y-auto`}>
      <div className="p-4 space-y-4">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[10px] uppercase tracking-wider text-zinc-500">{typeLabels[data.type]}</span>
            <h3 className="text-sm font-semibold text-zinc-100 mt-0.5">{data.label}</h3>
          </div>
          <button onClick={onClose} className="p-1 text-zinc-500 hover:text-zinc-300 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {data.meta && (
          <div className="text-xs text-zinc-400 font-mono">{data.meta}</div>
        )}

        {/* Agent details */}
        {data.type === "agent" && (
          <div className="space-y-2">
            {data.agentStatus && (
              <div className={`text-xs px-2 py-1 rounded border font-mono ${
                data.agentStatus === "installed-not-configured"
                  ? "border-yellow-800 bg-yellow-950 text-yellow-400"
                  : "border-emerald-800 bg-emerald-950 text-emerald-400"
              }`}>
                {data.agentStatus === "installed-not-configured" ? "Not Configured" : "Configured"}
              </div>
            )}
          </div>
        )}

        {/* Server details */}
        {data.type === "server" && (
          <div className="space-y-2">
            {data.tools !== undefined && data.tools > 0 && (
              <div className="flex items-center gap-2 text-xs text-zinc-400">
                <Wrench className="w-3 h-3" /> {data.tools} tool{data.tools !== 1 ? "s" : ""} available
              </div>
            )}
            {data.credentials !== undefined && data.credentials > 0 && (
              <div className="flex items-center gap-2 text-xs text-amber-400">
                <KeyRound className="w-3 h-3" /> {data.credentials} credential{data.credentials !== 1 ? "s" : ""} exposed
              </div>
            )}
          </div>
        )}

        {/* Package details */}
        {data.type === "package" && (
          <div className="space-y-2">
            {data.vulnCount !== undefined && data.vulnCount > 0 ? (
              <div className="flex items-center gap-2 text-xs text-red-400">
                <Bug className="w-3 h-3" /> {data.vulnCount} vulnerability{data.vulnCount !== 1 ? "ies" : "y"}
              </div>
            ) : (
              <div className="text-xs text-emerald-400">No known vulnerabilities</div>
            )}
          </div>
        )}

        {/* Vulnerability details */}
        {data.type === "vulnerability" && (
          <div className="space-y-2">
            {data.severity && (
              <span className={`text-xs px-2 py-1 rounded border font-mono uppercase ${severityColor(data.severity)}`}>
                {data.severity}
              </span>
            )}
            {data.meta && data.meta.startsWith("CVSS") && (
              <div className="text-xs text-zinc-400">{data.meta}</div>
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
      </div>
    </div>
  );
}

// ─── Tooltip ──────────────────────────────────────────────────────────────────

function GraphTooltip({ x, y, data }: { x: number; y: number; data: NodeData }) {
  return (
    <div
      className="fixed z-50 pointer-events-none bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 shadow-xl max-w-[200px]"
      style={{ left: x + 12, top: y - 8 }}
    >
      <div className="text-xs font-semibold text-zinc-200 truncate">{data.label}</div>
      {data.meta && <div className="text-[10px] text-zinc-500 truncate">{data.meta}</div>}
      {data.type === "server" && data.tools !== undefined && data.tools > 0 && (
        <div className="text-[10px] text-zinc-400 mt-1">{data.tools} tools</div>
      )}
      {data.type === "package" && data.vulnCount !== undefined && data.vulnCount > 0 && (
        <div className="text-[10px] text-red-400 mt-1">{data.vulnCount} CVEs</div>
      )}
      <div className="text-[10px] text-zinc-600 mt-1">Click for details</div>
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function GraphPage() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; data: NodeData } | null>(null);

  // Load all completed jobs
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
              // skip failed fetches
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

  const { nodes, edges } = useMemo(
    () => (activeResult ? buildGraph(activeResult) : { nodes: [], edges: [] }),
    [activeResult]
  );

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
        <p className="text-xs text-zinc-500">Run a scan first to visualize the supply chain graph</p>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Supply Chain Graph</h1>
          <p className="text-xs text-zinc-500">
            Agent → MCP Server → Package → CVE dependency chain
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Job selector */}
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
          {/* Legend */}
          <div className="flex items-center gap-3 text-[10px] text-zinc-500">
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded border-2 border-emerald-600 bg-emerald-950" /> Agent
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded border-2 border-dashed border-yellow-600 bg-yellow-950" /> Not configured
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded border-2 border-blue-600 bg-blue-950" /> Server
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded border-2 border-zinc-600 bg-zinc-900" /> Package
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded border-2 border-red-600 bg-red-950" /> CVE
            </span>
          </div>
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1 relative">
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
            setSelectedNode(node.data as NodeData);
            setTooltip(null);
          }}
          onNodeMouseEnter={(event, node) => {
            setTooltip({ x: (event as unknown as MouseEvent).clientX, y: (event as unknown as MouseEvent).clientY, data: node.data as NodeData });
          }}
          onNodeMouseLeave={() => setTooltip(null)}
          onPaneClick={() => setSelectedNode(null)}
        >
          <Background color="#27272a" gap={20} />
          <Controls
            className="!bg-zinc-900 !border-zinc-700 !rounded-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300 [&>button:hover]:!bg-zinc-700"
          />
          <MiniMap
            nodeColor={(n) => {
              const d = n.data as NodeData;
              if (d.type === "agent") return d.agentStatus === "installed-not-configured" ? "#eab308" : "#10b981";
              if (d.type === "server") return "#3b82f6";
              if (d.type === "vulnerability") return "#ef4444";
              return "#52525b";
            }}
            className="!bg-zinc-900 !border-zinc-700 !rounded-lg"
          />
        </ReactFlow>

        {/* Detail slide-over panel */}
        {selectedNode && (
          <DetailPanel data={selectedNode} onClose={() => setSelectedNode(null)} />
        )}

        {/* Hover tooltip */}
        {tooltip && !selectedNode && (
          <GraphTooltip x={tooltip.x} y={tooltip.y} data={tooltip.data} />
        )}
      </div>
    </div>
  );
}
