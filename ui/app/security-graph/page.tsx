"use client";

import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, MiniMap, Controls,
  type Node, type Edge, MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api, type ScanJob, type ScanResult, type Agent, type BlastRadius } from "@/lib/api";
import { EmptyState } from "@/components/empty-state";
import { FullscreenButton, GraphLegend } from "@/components/graph-chrome";
import {
  CONTROLS_CLASS, MINIMAP_CLASS, BACKGROUND_COLOR, BACKGROUND_GAP,
} from "@/lib/graph-utils";
import { Network, Loader2, AlertTriangle } from "lucide-react";

// ── Column positions for the layered layout ──────────────────────────────────

const COLUMN_X = { agent: 0, server: 400, package: 800, registry: 1200 };
const ROW_SPACING = 100;

// ── Legend ────────────────────────────────────────────────────────────────────

const SECURITY_LEGEND = [
  { label: "Agent",      color: "#58a6ff" },   // blue  — discover layer
  { label: "MCP Server", color: "#60a5fa" },   // blue-400
  { label: "Package",    color: "#d29922" },   // amber — analyze layer
  { label: "Vulnerable", color: "#f85149" },   // red   — scan layer
  { label: "Credential", color: "#eab308", dashed: true },
];

// ── Custom Node ──────────────────────────────────────────────────────────────

function SecurityNode({ data }: { data: any }) {
  // Architecture color semantics: scan=red, analyze=amber, discover=blue, neutral=zinc
  const borderColor = data.dimmed
    ? "#27272a"
    : data.vulnCount > 0
      ? data.hasCritical ? "#f85149" : "#f97316"  // scan-red / orange
      : data.hasCredentials ? "#eab308" : "#3f3f46";

  const riskBorderColor = data.riskBorder ?? borderColor;

  return (
    <div
      className="relative px-3 py-2 rounded-lg border-2 bg-zinc-900 min-w-[180px] max-w-[220px] shadow-lg backdrop-blur transition-opacity"
      style={{
        borderColor: riskBorderColor !== borderColor ? riskBorderColor : borderColor,
        opacity: data.dimmed ? 0.3 : 1,
      }}
    >
      <div className="flex items-center gap-2">
        <span className="text-lg">{data.icon}</span>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-zinc-200 truncate">{data.label}</div>
          <div className="text-[10px] text-zinc-500 truncate">{data.sublabel}</div>
        </div>
      </div>
      {data.vulnCount > 0 && (
        <div className="absolute -top-2 -right-2 w-5 h-5 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">
          {data.vulnCount}
        </div>
      )}
      {data.hasCredentials && (
        <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-yellow-500 text-black text-[8px] flex items-center justify-center">
          🔑
        </div>
      )}
      {data.riskLabel && (
        <div className="mt-1 text-[9px] font-mono text-zinc-400 truncate">{data.riskLabel}</div>
      )}
    </div>
  );
}

const nodeTypes = { securityNode: SecurityNode };

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SecurityGraphPage() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [insightLayer, setInsightLayer] = useState<"risk" | "credentials" | "none">("none");

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
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Get latest scan result
  const latestResult = useMemo(() => {
    for (const job of jobs) {
      if (job.status === "done" && job.result) return job.result as ScanResult;
    }
    return null;
  }, [jobs]);

  // Build blast_radius lookup keyed by package name for Gap 3
  const blastMap = useMemo(() => {
    const map = new Map<string, BlastRadius>();
    if (!latestResult?.blast_radius) return map;
    for (const br of latestResult.blast_radius) {
      if (br.package) {
        // Use package name as key; first entry wins (highest severity typically first)
        if (!map.has(br.package)) {
          map.set(br.package, br);
        } else {
          // Merge: keep the entry with the higher risk_score
          const existing = map.get(br.package)!;
          if ((br.risk_score ?? 0) > (existing.risk_score ?? 0)) {
            map.set(br.package, br);
          }
        }
      }
    }
    return map;
  }, [latestResult]);

  // Build graph from scan result — branches on insightLayer (Gap 2) and uses blastMap (Gap 3)
  const { nodes, edges } = useMemo(() => {
    if (!latestResult) return { nodes: [], edges: [] };

    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const serverSet = new Set<string>();
    const packageSet = new Set<string>();

    // Track which nodes have credentials for the credentials layer
    const credentialNodeIds = new Set<string>();

    // Column headers
    const headers = [
      { id: "h-agents",   x: COLUMN_X.agent + 60,   label: "Agents" },
      { id: "h-servers",  x: COLUMN_X.server + 60,  label: "MCP Servers" },
      { id: "h-packages", x: COLUMN_X.package + 60, label: "Packages" },
    ];
    headers.forEach((h) =>
      nodes.push({
        id: h.id,
        position: { x: h.x, y: -50 },
        type: "default",
        data: { label: h.label },
        style: {
          background: "transparent",
          border: "none",
          color: "#a1a1aa",
          fontWeight: 600,
          fontSize: 14,
        },
        draggable: false,
        selectable: false,
      })
    );

    // Helper: risk layer border color for a vuln count — architecture color semantics
    function riskBorder(vulnCount: number): string {
      if (vulnCount > 5) return "#f85149"; // scan-red
      if (vulnCount > 0) return "#f97316"; // orange
      return "#3fb950"; // output-green (safe)
    }

    latestResult.agents.forEach((agent, ai) => {
      const agentId = `agent-${ai}`;
      const hasCredentials = agent.mcp_servers.some(
        (s) => (s.env ? Object.keys(s.env).filter((k) => /key|token|secret|password|credential|auth/i.test(k)).length : 0) > 0
      );
      if (hasCredentials) credentialNodeIds.add(agentId);

      // Compute agent-level vuln count for risk layer
      const agentVulnCount = agent.mcp_servers.reduce(
        (sum, s) => sum + (s.packages ?? []).reduce((ps: number, p) => ps + (p.vulnerabilities?.length ?? 0), 0),
        0
      );

      nodes.push({
        id: agentId,
        position: { x: COLUMN_X.agent, y: ai * ROW_SPACING + 20 },
        type: "securityNode",
        data: {
          label: agent.name,
          sublabel: agent.agent_type ?? "agent",
          icon: "🤖",
          vulnCount: 0,
          hasCredentials,
          hasCritical: false,
          // Insight layer data
          riskBorder: insightLayer === "risk" ? riskBorder(agentVulnCount) : undefined,
          riskLabel: insightLayer === "risk" && agentVulnCount > 0 ? `${agentVulnCount} vuln${agentVulnCount !== 1 ? "s" : ""}` : undefined,
          dimmed: insightLayer === "credentials" && !hasCredentials,
        },
      });

      agent.mcp_servers.forEach((server) => {
        const serverId = `server-${agent.name}-${server.name}`;
        const credKeys = server.env
          ? Object.keys(server.env).filter((k) => /key|token|secret|password|credential|auth/i.test(k))
          : [];
        const serverHasCreds = credKeys.length > 0;
        if (serverHasCreds) credentialNodeIds.add(serverId);

        if (!serverSet.has(serverId)) {
          serverSet.add(serverId);
          const serverVulns = (server.packages ?? []).reduce(
            (sum: number, p) => sum + (p.vulnerabilities?.length ?? 0),
            0
          );
          const hasCrit = (server.packages ?? []).some((p) =>
            p.vulnerabilities?.some((v) => v.severity === "critical")
          );
          nodes.push({
            id: serverId,
            position: { x: COLUMN_X.server, y: (serverSet.size - 1) * ROW_SPACING + 20 },
            type: "securityNode",
            data: {
              label: server.name,
              sublabel: server.transport ?? server.command ?? "stdio",
              icon: "🖥️",
              vulnCount: serverVulns,
              hasCredentials: serverHasCreds,
              hasCritical: hasCrit,
              riskBorder: insightLayer === "risk" ? riskBorder(serverVulns) : undefined,
              riskLabel: insightLayer === "risk" && serverVulns > 0 ? `${serverVulns} vuln${serverVulns !== 1 ? "s" : ""}` : undefined,
              dimmed: insightLayer === "credentials" && !serverHasCreds,
            },
          });
        }

        // Edge: agent → server
        const edgeIsCredPath = hasCredentials || serverHasCreds;
        const dimEdge = insightLayer === "credentials" && !edgeIsCredPath;
        edges.push({
          id: `e-${agentId}-${serverId}`,
          source: agentId,
          target: serverId,
          type: "smoothstep",
          style: {
            stroke: dimEdge ? "#18181b" : (edgeIsCredPath && insightLayer === "credentials") ? "#eab308" : hasCredentials ? "#eab308" : "#58a6ff",
            strokeWidth: dimEdge ? 1 : 2,
            opacity: dimEdge ? 0.15 : 0.85,
          },
          animated: insightLayer === "credentials" ? edgeIsCredPath : hasCredentials,
          markerEnd: { type: MarkerType.ArrowClosed, color: dimEdge ? "#18181b" : "#58a6ff", width: 16, height: 12 },
        });

        (server.packages ?? []).forEach((pkg) => {
          const pkgId = `pkg-${pkg.name}-${pkg.version}`;
          if (!packageSet.has(pkgId)) {
            packageSet.add(pkgId);
            const vulnCount = pkg.vulnerabilities?.length ?? 0;
            const hasCrit = pkg.vulnerabilities?.some((v) => v.severity === "critical");

            // Gap 3: Look up blast_radius data for this package
            const br = blastMap.get(pkg.name);
            const riskScore = br?.risk_score;
            const isKev = br?.is_kev ?? br?.cisa_kev ?? false;
            const epssScore = br?.epss_score;

            // Build sublabel based on layer
            let sublabel = `${pkg.version} · ${pkg.ecosystem}`;
            let riskLabel: string | undefined;
            if (insightLayer === "risk") {
              const parts: string[] = [];
              if (riskScore != null) parts.push(`risk: ${riskScore.toFixed(1)}`);
              if (isKev) parts.push("KEV");
              if (epssScore != null) parts.push(`EPSS: ${(epssScore * 100).toFixed(1)}%`);
              if (parts.length > 0) riskLabel = parts.join(" · ");
            }

            nodes.push({
              id: pkgId,
              position: { x: COLUMN_X.package, y: (packageSet.size - 1) * (ROW_SPACING * 0.6) + 20 },
              type: "securityNode",
              data: {
                label: pkg.name,
                sublabel,
                icon: "📦",
                vulnCount,
                hasCredentials: false,
                hasCritical: hasCrit,
                riskBorder: insightLayer === "risk" ? riskBorder(vulnCount) : undefined,
                riskLabel,
                dimmed: insightLayer === "credentials" && !serverHasCreds,
              },
            });
          }

          // Edge: server → package
          const dimPkgEdge = insightLayer === "credentials" && !serverHasCreds;
          edges.push({
            id: `e-${serverId}-${pkgId}`,
            source: serverId,
            target: pkgId,
            type: "smoothstep",
            style: {
              stroke: dimPkgEdge ? "#18181b" : "#27272a",
              strokeWidth: dimPkgEdge ? 1 : 1.5,
              opacity: dimPkgEdge ? 0.15 : 0.8,
            },
            markerEnd: { type: MarkerType.ArrowClosed, color: dimPkgEdge ? "#18181b" : "#3f3f46", width: 14, height: 10 },
          });
        });
      });
    });

    return { nodes, edges };
  }, [latestResult, insightLayer, blastMap]);

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

  if (!latestResult) {
    return (
      <EmptyState
        icon={Network}
        title="No scan data"
        description="Run a scan to generate the security graph."
        action={{ label: "New Scan", href: "/scan" }}
      />
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Agentic Security Graph</h1>
          <p className="text-xs text-zinc-500">
            Agent → MCP Server → Package — full AI attack surface
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Insight layer toggles */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-zinc-500 mr-1">Layers:</span>
            {(["none", "risk", "credentials"] as const).map((layer) => (
              <button
                key={layer}
                onClick={() => setInsightLayer(layer)}
                className={`px-2 py-1 rounded text-xs transition-colors ${
                  insightLayer === layer
                    ? "bg-zinc-700 text-zinc-200"
                    : "bg-zinc-900 text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {layer === "none" ? "Default" : layer === "risk" ? "Risk" : "Credentials"}
              </button>
            ))}
          </div>
          <FullscreenButton />
          <GraphLegend items={SECURITY_LEGEND} />
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.05}
          maxZoom={2.5}
          defaultEdgeOptions={{ type: "smoothstep" }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} />
          <Controls className={CONTROLS_CLASS} />
          <MiniMap
            nodeColor={(n) => {
              const d = n.data as any;
              if (d?.hasCritical) return "#f85149"; // scan-red
              if (d?.vulnCount > 0) return "#f97316"; // orange
              if (d?.hasCredentials) return "#eab308"; // amber credential
              return "#3f3f46"; // zinc neutral
            }}
            className={MINIMAP_CLASS}
          />
        </ReactFlow>
      </div>
    </div>
  );
}
