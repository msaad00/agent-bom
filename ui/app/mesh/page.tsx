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
  ArrowRight,
  Bug,
  KeyRound,
  Loader2,
  AlertTriangle,
  Package,
  Search,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Network,
  GitBranch,
  Orbit,
  Wrench,
  type LucideIcon,
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
} from "@/lib/graph-utils";
import { FullscreenButton, GraphLegend } from "@/components/graph-chrome";
import { DeploymentSurfaceRequiredState } from "@/components/deployment-surface-required-state";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { isDeploymentSurfaceAvailable } from "@/lib/deployment-context";

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

type MeshStoryItem = {
  label: string;
  detail?: string | undefined;
  tone: "agent" | "server" | "package" | "tool" | "finding" | "credential";
};

const STORY_TONE: Record<MeshStoryItem["tone"], { icon: LucideIcon; className: string; label: string }> = {
  agent: { icon: ShieldAlert, className: "border-emerald-200 bg-emerald-50 text-emerald-950", label: "Agent" },
  server: { icon: Server, className: "border-sky-200 bg-sky-50 text-sky-950", label: "MCP server" },
  package: { icon: Package, className: "border-rose-200 bg-rose-50 text-rose-950", label: "Package" },
  tool: { icon: Wrench, className: "border-violet-200 bg-violet-50 text-violet-950", label: "Tool" },
  finding: { icon: Bug, className: "border-orange-200 bg-orange-50 text-orange-950", label: "Finding" },
  credential: { icon: KeyRound, className: "border-amber-200 bg-amber-50 text-amber-950", label: "Credential ref" },
};

function summarizeNode(node: Node, tone: MeshStoryItem["tone"]): MeshStoryItem {
  const data = node.data as LineageNodeData;
  const detailParts = [
    data.version ? `${data.ecosystem ?? "package"} ${data.version}` : undefined,
    data.command,
    data.severity ? `${data.severity} severity` : undefined,
    data.vulnCount ? `${data.vulnCount} findings` : undefined,
    data.toolCount ? `${data.toolCount} tools` : undefined,
    data.packageCount ? `${data.packageCount} packages` : undefined,
  ].filter(Boolean);
  return {
    label: data.label,
    detail: detailParts.slice(0, 2).join(" · ") || undefined,
    tone,
  };
}

function stageItems(nodes: Node[], type: LineageNodeData["nodeType"], tone: MeshStoryItem["tone"], limit: number): MeshStoryItem[] {
  return nodes
    .filter((node) => (node.data as LineageNodeData).nodeType === type)
    .slice(0, limit)
    .map((node) => summarizeNode(node, tone));
}

function MeshStoryColumn({
  title,
  eyebrow,
  items,
  count,
}: {
  title: string;
  eyebrow: string;
  items: MeshStoryItem[];
  count: number;
}) {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-slate-500">{eyebrow}</p>
          <h2 className="mt-1 text-base font-semibold text-slate-950">{title}</h2>
        </div>
        <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 font-mono text-xs font-semibold text-slate-700">
          {count}
        </span>
      </div>
      <div className="mt-4 space-y-2">
        {items.map((item) => {
          const tone = STORY_TONE[item.tone];
          const Icon = tone.icon;
          return (
            <div key={`${item.tone}-${item.label}`} className={`rounded-xl border px-3 py-2.5 ${tone.className}`}>
              <div className="flex items-center gap-2">
                <Icon className="h-4 w-4 shrink-0" />
                <span className="min-w-0 flex-1 truncate text-sm font-semibold">{item.label}</span>
                <span className="rounded bg-white/70 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  {tone.label}
                </span>
              </div>
              {item.detail && <p className="mt-1 truncate text-xs text-slate-600">{item.detail}</p>}
            </div>
          );
        })}
        {items.length === 0 && (
          <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 px-3 py-5 text-center text-xs text-slate-500">
            Not in the current scope
          </div>
        )}
      </div>
    </section>
  );
}

function MeshCaptureView({
  nodes,
  stats,
  selectedJob,
}: {
  nodes: Node[];
  stats: MeshStatsData;
  selectedJob: string;
}) {
  const agents = stageItems(nodes, "agent", "agent", 1);
  const servers = [...stageItems(nodes, "sharedServer", "server", 2), ...stageItems(nodes, "server", "server", 2)].slice(0, 2);
  const packages = stageItems(nodes, "package", "package", 3);
  const tools = stageItems(nodes, "tool", "tool", 2);
  const findings = stageItems(nodes, "vulnerability", "finding", 5);
  const credentialItems = stageItems(nodes, "credential", "credential", 2);
  const exposureItems = [...packages, ...tools, ...credentialItems].slice(0, 4);
  const hiddenCount =
    stats.omittedCredentials + stats.omittedTools + stats.omittedPackages + stats.omittedVulnerabilities;

  return (
    <div className="min-h-full bg-slate-50 px-8 py-7 text-slate-950">
      <div className="mx-auto max-w-[1560px]">
        <header className="flex items-start justify-between gap-6">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-emerald-700">Agent mesh</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-normal text-slate-950">
              Readable AI supply-chain path, scoped to the riskiest agent
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              The mesh starts with a bounded path view so teams can see which agent, MCP servers, packages, tools, and findings are driving risk before opening the full graph canvas.
            </p>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white p-4 text-right shadow-sm">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Scan snapshot</p>
            <p className="mt-1 font-mono text-sm font-semibold text-slate-900">{selectedJob.slice(0, 8) || "demo"}</p>
            <p className="mt-2 text-xs text-slate-500">Customer-controlled evidence model</p>
          </div>
        </header>

        <div className="mt-5 grid grid-cols-5 gap-3">
          <Metric label="Agents" value={stats.totalAgents} tone="emerald" />
          <Metric label="MCP servers" value={stats.sharedServers || servers.length} tone="sky" />
          <Metric label="Packages in view" value={stats.totalPackages} tone="rose" />
          <Metric label="Findings in view" value={stats.totalVulnerabilities} tone="orange" />
          <Metric label="Hidden lower-priority" value={hiddenCount} tone="slate" />
        </div>

        <div className="relative mt-5">
          <div className="absolute left-[12%] right-[12%] top-[48%] hidden h-px bg-gradient-to-r from-emerald-200 via-sky-200 to-orange-200 lg:block" />
          <div className="relative grid gap-4 lg:grid-cols-[minmax(0,0.75fr)_44px_minmax(0,1.25fr)_44px_minmax(0,1.05fr)_44px_minmax(0,1.05fr)]">
            <MeshStoryColumn title="Selected agent" eyebrow="Scope" items={agents} count={stats.totalAgents} />
            <ArrowDivider />
            <MeshStoryColumn title="MCP infrastructure" eyebrow="Shared runtime" items={servers} count={servers.length} />
            <ArrowDivider />
            <MeshStoryColumn title="Reachable assets" eyebrow="Packages + tools" items={exposureItems} count={stats.totalPackages + stats.toolOverlap} />
            <ArrowDivider />
            <MeshStoryColumn title="Prioritized findings" eyebrow="Fix first" items={findings} count={stats.totalVulnerabilities} />
          </div>
        </div>

        <div className="mt-5 grid gap-4 lg:grid-cols-3">
          <EvidenceCard title="Bounded by default" body="Lower-priority nodes stay hidden until an operator expands filters, keeping the first view readable instead of rendering the whole tenant." />
          <EvidenceCard title="Credential-aware" body="Credential references and shared MCP servers are first-class nodes, so blast radius is tied to actual agent and server relationships." />
          <EvidenceCard title="Drilldown-ready" body="The same scan evidence feeds the full graph, security graph, findings, compliance, and runtime enforcement surfaces." />
        </div>
      </div>
    </div>
  );
}

function ArrowDivider() {
  return (
    <div className="hidden items-center justify-center lg:flex">
      <div className="rounded-full border border-slate-200 bg-white p-2 text-slate-400 shadow-sm">
        <ArrowRight className="h-4 w-4" />
      </div>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: number; tone: "emerald" | "sky" | "rose" | "orange" | "slate" }) {
  const toneClass = {
    emerald: "text-emerald-700",
    sky: "text-sky-700",
    rose: "text-rose-700",
    orange: "text-orange-700",
    slate: "text-slate-700",
  }[tone];
  return (
    <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</p>
      <p className={`mt-1 font-mono text-2xl font-semibold ${toneClass}`}>{value}</p>
    </div>
  );
}

function EvidenceCard({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <h3 className="text-sm font-semibold text-slate-950">{title}</h3>
      <p className="mt-2 text-xs leading-5 text-slate-600">{body}</p>
    </div>
  );
}

export default function MeshPage() {
  const [captureMode] = useState(() => {
    if (typeof window === "undefined") return false;
    return new URLSearchParams(window.location.search).get("capture") === "1";
  });
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
      ...(captureMode
        ? {
            maxCredentialNodesPerServer: 2,
            maxToolNodesPerServer: 2,
            maxVulnerablePackagesPerServer: 3,
            maxVulnerabilitiesPerPackage: 1,
          }
        : {}),
    });
    return { rawNodes: nodes, rawEdges: edges, stats };
  }, [activeResult, captureMode, nodeFilter, severityFilter, selectedAgents, vulnerableOnly]);

  const { nodes: visibleNodes, edges: visibleEdges } = useGraphLayout(layoutMode, rawNodes, rawEdges, {
    radial: {
      baseRadius: 240,
      ringSpacing: 220,
    },
    dagre: {
      nodeWidth: 200,
      nodeHeight: 70,
      rankSep: 95,
      nodeSep: 18,
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
    if (!activeSet) return visibleEdges;
    return visibleEdges?.map((e) => ({
      ...e,
      style: {
        ...e.style,
        opacity: activeSet.has(e.source) && activeSet.has(e.target) ? 1 : 0.12,
      },
    }));
  }, [visibleEdges, connectedIds, searchMatches]);

  const legendItems = useMemo(
    () => legendItemsForVisibleGraph(displayNodes, displayEdges),
    [displayEdges, displayNodes],
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
    if (counts && !isDeploymentSurfaceAvailable("mesh", counts)) {
      return <DeploymentSurfaceRequiredState surface="mesh" counts={counts} detail={error} />;
    }
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <ShieldAlert className="w-8 h-8 text-zinc-600" />
        <p className="text-sm">No completed scans found</p>
        <p className="text-xs text-zinc-500">Run a scan first to visualize the agent mesh</p>
      </div>
    );
  }

  if (captureMode) {
    return <MeshCaptureView nodes={displayNodes} stats={stats} selectedJob={selectedJob} />;
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
              { key: "radial" as const, label: "Radial", icon: Orbit },
              { key: "topology" as const, label: "Topology", icon: Network },
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
        agentOptions={agentOptions}
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
          fitViewOptions={{ padding: 0.08, maxZoom: 1.45 }}
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
