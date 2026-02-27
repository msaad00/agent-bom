"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, Agent, isConfigured } from "@/lib/api";
import { Server, Package, Wrench, Key, AlertCircle, Shield, ChevronDown, ChevronRight, ArrowRight } from "lucide-react";

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

export default function AgentsPage() {
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
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
        <p className="text-zinc-400 text-sm mt-1">
          Auto-discovered local AI agent configurations
        </p>
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
              {Object.entries(ecosystems).map(([eco, count]) => `${eco}: ${count}`).join(", ") || "—"}
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
                  href={`/agents/${encodeURIComponent(agent.name)}`}
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
