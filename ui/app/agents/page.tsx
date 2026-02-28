"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  api,
  Agent,
  isConfigured,
  type AgentDetailResponse,
  type AgentLifecycleResponse,
  type BlastRadius,
  type AttackFlowNodeData,
  severityColor,
  OWASP_LLM_TOP10,
  MITRE_ATLAS,
} from "@/lib/api";
import { SeverityBadge } from "@/components/severity-badge";
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
  ArrowRight,
  AlertCircle,
  Bug,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  GitBranch,
  Key,
  KeyRound,
  Loader2,
  Network,
  Package,
  Server,
  Shield,
  ShieldAlert,
  Wrench,
  X,
} from "lucide-react";

// ─── Agents List Helpers ────────────────────────────────────────────────────

function useAgentStats(agents: Agent[]) {
  const configured = agents.filter(isConfigured);
  const notConfigured = agents.filter((a) => !isConfigured(a));
  const totalServers = agents.reduce((s, a) => s + a.mcp_servers.length, 0);
  const totalPackages = agents.reduce(
    (s, a) => s + a.mcp_servers.reduce((ss, srv) => ss + srv.packages.length, 0),
    0
  );
  const totalCredentials = agents.reduce(
    (s, a) =>
      s +
      a.mcp_servers.reduce(
        (ss, srv) =>
          ss +
          (srv.env
            ? Object.keys(srv.env).filter((k) =>
                /key|token|secret|password|credential|auth/i.test(k)
              ).length
            : 0),
        0
      ),
    0
  );

  // ecosystem breakdown
  const ecosystems: Record<string, number> = {};
  for (const a of agents) {
    for (const srv of a.mcp_servers) {
      for (const pkg of srv.packages) {
        const eco = (pkg as { ecosystem?: string }).ecosystem || "unknown";
        ecosystems[eco] = (ecosystems[eco] || 0) + 1;
      }
    }
  }

  return { configured, notConfigured, totalServers, totalPackages, totalCredentials, ecosystems };
}

// ─── Agents List View ───────────────────────────────────────────────────────

function AgentsList() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());

  function toggleCollapse(idx: number) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }

  useEffect(() => {
    api.listAgents()
      .then((r) => setAgents(r.agents))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const { configured, notConfigured: installedOnly, totalServers, totalPackages, totalCredentials, ecosystems } =
    useAgentStats(agents);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
          <p className="text-zinc-400 text-sm mt-1">
            Auto-discovered local AI agent configurations
          </p>
        </div>
        <Link
          href="/mesh"
          className="flex items-center gap-2 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-sm text-zinc-300 transition-colors"
        >
          <Network className="w-4 h-4" />
          Mesh View
        </Link>
      </div>

      {loading && <p className="text-zinc-500 text-sm">Discovering agents...</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {/* Summary stats bar */}
      {!loading && agents.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-zinc-400 text-xs mb-1">
              <Shield className="w-3 h-3" /> Agents
            </div>
            <div className="text-lg font-semibold text-zinc-100">{agents.length}</div>
            <div className="text-[10px] text-zinc-500 mt-0.5">
              {configured.length} configured{installedOnly.length > 0 ? `, ${installedOnly.length} not configured` : ""}
            </div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-zinc-400 text-xs mb-1">
              <Server className="w-3 h-3" /> Servers
            </div>
            <div className="text-lg font-semibold text-zinc-100">{totalServers}</div>
            <div className="text-[10px] text-zinc-500 mt-0.5">MCP server instances</div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-zinc-400 text-xs mb-1">
              <Package className="w-3 h-3" /> Packages
            </div>
            <div className="text-lg font-semibold text-zinc-100">{totalPackages}</div>
            <div className="text-[10px] text-zinc-500 mt-0.5">
              {Object.entries(ecosystems).map(([eco, count]) => `${eco}: ${count}`).join(", ") || "\u2014"}
            </div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-zinc-400 text-xs mb-1">
              <Key className="w-3 h-3" /> Credentials
            </div>
            <div className={`text-lg font-semibold ${totalCredentials > 0 ? "text-orange-400" : "text-zinc-100"}`}>
              {totalCredentials}
            </div>
            <div className="text-[10px] text-zinc-500 mt-0.5">
              {totalCredentials > 0 ? "Exposed env vars" : "None detected"}
            </div>
          </div>
        </div>
      )}

      {!loading && agents.length === 0 && (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Server className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">No agents discovered locally.</p>
          <p className="text-zinc-600 text-xs mt-1">
            Install Claude Desktop, Cursor, or Windsurf and configure MCP servers.
          </p>
        </div>
      )}

      {/* Configured agents */}
      <div className="space-y-4">
        {configured.map((agent, i) => (
          <div key={i} className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
            <button
              type="button"
              onClick={() => toggleCollapse(i)}
              className="w-full flex items-center justify-between"
            >
              <div className="flex items-center gap-2">
                {collapsed.has(i) ? (
                  <ChevronRight className="w-4 h-4 text-zinc-500" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-zinc-500" />
                )}
                <h2 className="font-semibold text-zinc-100">{agent.name}</h2>
                <span className="text-[10px] font-mono bg-emerald-950 border border-emerald-800 text-emerald-400 rounded px-1.5 py-0.5">
                  configured
                </span>
                <span className="text-xs font-mono text-zinc-500">{agent.agent_type}</span>
                {agent.source && (
                  <span className="text-xs text-zinc-600">{agent.source}</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-zinc-400">
                  {agent.mcp_servers.length} server{agent.mcp_servers.length !== 1 ? "s" : ""}
                </span>
                <Link
                  href={`/agents?name=${encodeURIComponent(agent.name)}`}
                  onClick={(e) => e.stopPropagation()}
                  className="text-zinc-500 hover:text-emerald-400 transition-colors"
                  title="View agent detail"
                >
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </button>

            {!collapsed.has(i) && (
              <div className="space-y-2 mt-4">
                {agent.mcp_servers.map((srv, j) => (
                  <div key={j} className="bg-zinc-800 border border-zinc-700 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-semibold text-zinc-200">{srv.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {srv.transport && (
                          <span className="text-xs text-zinc-600 font-mono">{srv.transport}</span>
                        )}
                      </div>
                    </div>

                    {srv.command && (
                      <div className="text-xs font-mono text-zinc-500 mb-2">
                        $ {srv.command} {srv.env ? Object.keys(srv.env).length > 0 ? `[${Object.keys(srv.env).length} env vars]` : "" : ""}
                      </div>
                    )}

                    <div className="flex flex-wrap gap-3 text-xs text-zinc-500">
                      {srv.packages.length > 0 && (
                        <span className="flex items-center gap-1">
                          <Package className="w-3 h-3" />
                          {srv.packages.length} package{srv.packages.length !== 1 ? "s" : ""}
                        </span>
                      )}
                      {srv.tools && srv.tools.length > 0 && (
                        <span className="flex items-center gap-1">
                          <Wrench className="w-3 h-3" />
                          {srv.tools.length} tool{srv.tools.length !== 1 ? "s" : ""}
                        </span>
                      )}
                      {srv.env && Object.keys(srv.env).length > 0 && (
                        <span className="flex items-center gap-1 text-orange-400">
                          <Key className="w-3 h-3" />
                          {Object.keys(srv.env).length} credential{Object.keys(srv.env).length !== 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Installed but not configured */}
      {installedOnly.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest flex items-center gap-2">
            <AlertCircle className="w-3.5 h-3.5 text-yellow-500" />
            Installed but not configured
          </h2>
          {installedOnly.map((agent, i) => (
            <div key={i} className="bg-zinc-900/50 border border-dashed border-zinc-800 rounded-xl p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-zinc-300">{agent.name}</h3>
                    <span className="text-[10px] font-mono bg-yellow-950 border border-yellow-800 text-yellow-400 rounded px-1.5 py-0.5">
                      not configured
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xs font-mono text-zinc-500">{agent.agent_type}</span>
                    {agent.config_path && (
                      <span className="text-xs text-zinc-600 font-mono">{agent.config_path}</span>
                    )}
                  </div>
                </div>
                <span className="text-xs text-zinc-600">0 servers</span>
              </div>
              <p className="text-xs text-zinc-600 mt-2">
                Binary detected on PATH. Run setup to configure MCP servers.
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Agent Detail Components ────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-3">
      <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-1">
        <Icon className={`w-3.5 h-3.5 ${color}`} />
        {label}
      </div>
      <div className="text-xl font-bold">{value}</div>
    </div>
  );
}

// ─── Agent Detail View ──────────────────────────────────────────────────────

function AgentDetail({ agentName }: { agentName: string }) {
  const [data, setData] = useState<AgentDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedServers, setExpandedServers] = useState<Set<string>>(new Set());

  useEffect(() => {
    api
      .getAgentDetail(agentName)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [agentName]);

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-zinc-500" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-zinc-950 p-8">
        <Link href="/agents" className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 mb-6">
          <ArrowLeft className="w-4 h-4" /> Back to agents
        </Link>
        <div className="text-red-400 bg-red-950 border border-red-800 rounded-lg p-4">
          {error || "Agent not found"}
        </div>
      </div>
    );
  }

  const { agent, summary, blast_radius, credentials } = data;
  const sev = summary.severity_breakdown;

  const toggleServer = (name: string) => {
    setExpandedServers((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Header */}
      <div className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <Link href="/agents" className="text-zinc-500 hover:text-zinc-300 flex items-center gap-1 text-sm mb-2">
            <ArrowLeft className="w-3.5 h-3.5" /> All Agents
          </Link>
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-3">
                <ShieldAlert className="w-6 h-6 text-emerald-400" />
                {agent.name}
              </h1>
              <div className="flex items-center gap-3 mt-1 text-sm text-zinc-500">
                <span className="bg-zinc-800 px-2 py-0.5 rounded text-xs">
                  {agent.agent_type}
                </span>
                {agent.config_path && (
                  <span className="font-mono text-xs truncate max-w-md">
                    {agent.config_path}
                  </span>
                )}
              </div>
            </div>
            <Link
              href={`/agents?name=${encodeURIComponent(agentName)}&view=lifecycle`}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors"
            >
              <GitBranch className="w-4 h-4" />
              View Lifecycle Graph
            </Link>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard icon={Server} label="MCP Servers" value={summary.total_servers} color="text-blue-400" />
          <StatCard icon={Package} label="Packages" value={summary.total_packages} color="text-zinc-400" />
          <StatCard icon={Wrench} label="Tools" value={summary.total_tools} color="text-purple-400" />
          <StatCard icon={KeyRound} label="Credentials" value={summary.total_credentials} color="text-yellow-400" />
          <StatCard icon={Bug} label="Vulnerabilities" value={summary.total_vulnerabilities} color="text-red-400" />
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-3">
            <div className="text-xs text-zinc-500 mb-1">Severity</div>
            <div className="flex items-center gap-2 text-xs">
              {sev.critical > 0 && <span className="text-red-400 font-bold">{sev.critical}C</span>}
              {sev.high > 0 && <span className="text-orange-400 font-bold">{sev.high}H</span>}
              {sev.medium > 0 && <span className="text-yellow-400">{sev.medium}M</span>}
              {sev.low > 0 && <span className="text-blue-400">{sev.low}L</span>}
              {sev.critical + sev.high + sev.medium + sev.low === 0 && (
                <span className="text-emerald-400 font-medium">Clean</span>
              )}
            </div>
          </div>
        </div>

        {/* Exposed Credentials */}
        {credentials.length > 0 && (
          <div className="bg-yellow-950/30 border border-yellow-800/50 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-yellow-400 flex items-center gap-2 mb-2">
              <KeyRound className="w-4 h-4" /> Exposed Credentials ({credentials.length})
            </h3>
            <div className="flex flex-wrap gap-2">
              {credentials.map((c) => (
                <span key={c} className="bg-yellow-950 border border-yellow-800 text-yellow-300 px-2 py-0.5 rounded text-xs font-mono">
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* MCP Servers */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-400" /> MCP Servers
          </h2>
          <div className="space-y-2">
            {agent.mcp_servers.map((srv) => {
              const isExpanded = expandedServers.has(srv.name);
              const srvPkgs = srv.packages || [];
              const srvTools = srv.tools || [];
              const vulnCount = srvPkgs.reduce(
                (sum, p) => sum + (p.vulnerabilities?.length ?? 0),
                0
              );
              return (
                <div key={srv.name} className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
                  <button
                    onClick={() => toggleServer(srv.name)}
                    className="w-full px-4 py-3 flex items-center justify-between hover:bg-zinc-800/50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      {isExpanded ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
                      <span className="font-medium">{srv.name}</span>
                      <span className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded">
                        {srv.transport || "stdio"}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-zinc-500">
                      <span>{srvPkgs.length} pkgs</span>
                      <span>{srvTools.length} tools</span>
                      {vulnCount > 0 && (
                        <span className="text-red-400 font-medium">{vulnCount} vulns</span>
                      )}
                    </div>
                  </button>
                  {isExpanded && (
                    <div className="border-t border-zinc-800 px-4 py-3 space-y-3">
                      {/* Tools */}
                      {srvTools.length > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-purple-400 mb-1">Tools</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {srvTools.map((t) => (
                              <span key={t.name} className="bg-purple-950 border border-purple-800 text-purple-300 px-2 py-0.5 rounded text-xs">
                                {t.name}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {/* Packages */}
                      {srvPkgs.length > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-zinc-400 mb-1">Packages</h4>
                          <div className="space-y-1">
                            {srvPkgs.map((pkg) => (
                              <div key={`${pkg.name}@${pkg.version}`} className="flex items-center justify-between text-xs">
                                <span className="font-mono">
                                  {pkg.name}
                                  <span className="text-zinc-500">@{pkg.version}</span>
                                </span>
                                <span className="text-zinc-600">{pkg.ecosystem}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Blast Radius */}
        {blast_radius.length > 0 && (
          <div>
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Bug className="w-5 h-5 text-red-400" /> Blast Radius ({blast_radius.length})
            </h2>
            <div className="space-y-2">
              {blast_radius.map((br, i) => (
                <div key={`${br.vulnerability_id}-${i}`} className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={br.severity} />
                      <span className="font-mono font-medium">{br.vulnerability_id}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-zinc-500">
                      {br.cvss_score && <span>CVSS {br.cvss_score}</span>}
                      {br.is_kev && <span className="text-red-400 font-bold">KEV</span>}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-3 text-xs text-zinc-400">
                    {br.package && <span>Package: <span className="text-zinc-300">{br.package}</span></span>}
                    {br.exposed_credentials.length > 0 && (
                      <span className="text-yellow-400">{br.exposed_credentials.length} credentials exposed</span>
                    )}
                    {br.reachable_tools.length > 0 && (
                      <span className="text-purple-400">{br.reachable_tools.length} tools reachable</span>
                    )}
                  </div>
                  {/* Framework tags */}
                  <div className="flex flex-wrap gap-1 mt-2">
                    {(br.owasp_tags ?? []).map((t) => (
                      <span key={t} className="bg-indigo-950 border border-indigo-800 text-indigo-300 px-1.5 py-0.5 rounded text-[10px]">
                        {t} {OWASP_LLM_TOP10[t] ?? ""}
                      </span>
                    ))}
                    {(br.atlas_tags ?? []).map((t) => (
                      <span key={t} className="bg-rose-950 border border-rose-800 text-rose-300 px-1.5 py-0.5 rounded text-[10px]">
                        {t} {MITRE_ATLAS[t] ?? ""}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Lifecycle Graph Constants ──────────────────────────────────────────────

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

// ─── Lifecycle Custom Node ──────────────────────────────────────────────────

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

// ─── Lifecycle Stats Bar ────────────────────────────────────────────────────

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

// ─── Lifecycle Detail Panel ─────────────────────────────────────────────────

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

// ─── Lifecycle Flow Canvas ──────────────────────────────────────────────────

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
            href={`/agents?name=${encodeURIComponent(agentName)}`}
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

// ─── Lifecycle View ─────────────────────────────────────────────────────────

function AgentLifecycle({ agentName }: { agentName: string }) {
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

// ─── Router Component ───────────────────────────────────────────────────────

function AgentsRouter() {
  const searchParams = useSearchParams();
  const name = searchParams.get("name") || "";
  const view = searchParams.get("view") || "";

  if (name && view === "lifecycle") {
    return <AgentLifecycle agentName={name} />;
  }

  if (name) {
    return <AgentDetail agentName={name} />;
  }

  return <AgentsList />;
}

// ─── Page (with Suspense boundary for useSearchParams) ──────────────────────

export default function AgentsPage() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center min-h-screen"><Loader2 className="w-8 h-8 animate-spin text-zinc-500" /></div>}>
      <AgentsRouter />
    </Suspense>
  );
}
