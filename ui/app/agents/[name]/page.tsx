"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import {
  api,
  type AgentDetailResponse,
  type BlastRadius,
  severityColor,
  OWASP_LLM_TOP10,
  MITRE_ATLAS,
} from "@/lib/api";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ArrowLeft,
  Bug,
  GitBranch,
  KeyRound,
  Loader2,
  Package,
  Server,
  ShieldAlert,
  Wrench,
  ChevronDown,
  ChevronRight,
  ExternalLink,
} from "lucide-react";

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AgentDetailPage({
  params,
}: {
  params: Promise<{ name: string }>;
}) {
  const { name } = use(params);
  const agentName = decodeURIComponent(name);
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
              href={`/agents/${encodeURIComponent(agentName)}/lifecycle`}
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

// ─── Components ──────────────────────────────────────────────────────────────

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
