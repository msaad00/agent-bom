"use client";

import { useEffect, useState } from "react";
import {
  api,
  type FleetAgent,
  type FleetStatsResponse,
  type FleetLifecycleState,
  formatDate,
} from "@/lib/api";
import {
  Users,
  RefreshCw,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ChevronDown,
  ChevronRight,
  Server,
  Package,
  KeyRound,
  Bug,
} from "lucide-react";

// ─── Helpers ────────────────────────────────────────────────────────────────

const STATE_LABELS: Record<FleetLifecycleState, string> = {
  discovered: "Discovered",
  pending_review: "Pending Review",
  approved: "Approved",
  quarantined: "Quarantined",
  decommissioned: "Decommissioned",
};

const STATE_COLORS: Record<FleetLifecycleState, string> = {
  discovered: "bg-zinc-800 text-zinc-300 border-zinc-700",
  pending_review: "bg-yellow-950 text-yellow-300 border-yellow-800",
  approved: "bg-emerald-950 text-emerald-300 border-emerald-800",
  quarantined: "bg-red-950 text-red-300 border-red-800",
  decommissioned: "bg-zinc-900 text-zinc-500 border-zinc-800",
};

const TRANSITIONS: Record<FleetLifecycleState, FleetLifecycleState[]> = {
  discovered: ["pending_review", "approved", "quarantined"],
  pending_review: ["approved", "quarantined"],
  approved: ["quarantined", "decommissioned"],
  quarantined: ["approved", "decommissioned"],
  decommissioned: [],
};

function trustColor(score: number): string {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 50) return "bg-yellow-500";
  return "bg-red-500";
}

function trustTextColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-yellow-400";
  return "text-red-400";
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function FleetPage() {
  const [agents, setAgents] = useState<FleetAgent[]>([]);
  const [stats, setStats] = useState<FleetStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [stateFilter, setStateFilter] = useState<string>("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = () => {
    setLoading(true);
    Promise.all([api.listFleet(), api.getFleetStats()])
      .then(([fleet, s]) => {
        setAgents(fleet.agents);
        setStats(s);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleSync = async () => {
    setSyncing(true);
    try {
      await api.syncFleet();
      load();
    } finally {
      setSyncing(false);
    }
  };

  const handleStateChange = async (agentId: string, newState: FleetLifecycleState) => {
    await api.updateFleetState(agentId, newState);
    load();
  };

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filtered = stateFilter === "all"
    ? agents
    : agents.filter((a) => a.lifecycle_state === stateFilter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Users className="w-6 h-6 text-emerald-400" />
            Agent Fleet
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            Persistent agent inventory with lifecycle management and trust scoring
          </p>
        </div>
        <button
          onClick={handleSync}
          disabled={syncing}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${syncing ? "animate-spin" : ""}`} />
          {syncing ? "Syncing..." : "Sync Now"}
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Total Agents" value={stats.total} icon={Users} color="text-zinc-400" />
          <StatCard label="Approved" value={stats.by_state.approved ?? 0} icon={ShieldCheck} color="text-emerald-400" />
          <StatCard label="Low Trust" value={stats.low_trust_count} icon={ShieldAlert} color="text-yellow-400" />
          <StatCard
            label="Avg Trust"
            value={stats.avg_trust_score}
            icon={ShieldX}
            color={trustTextColor(stats.avg_trust_score)}
            suffix="%"
          />
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex gap-1.5 flex-wrap">
        {["all", "discovered", "pending_review", "approved", "quarantined", "decommissioned"].map((s) => (
          <button
            key={s}
            onClick={() => setStateFilter(s)}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              stateFilter === s
                ? "bg-zinc-800 text-zinc-100"
                : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900"
            }`}
          >
            {s === "all" ? "All" : STATE_LABELS[s as FleetLifecycleState]}
            {s !== "all" && stats && (
              <span className="ml-1 text-zinc-600">
                {stats.by_state[s] ?? 0}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-zinc-500" />
        </div>
      )}

      {/* Empty state */}
      {!loading && agents.length === 0 && (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Users className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">No agents in fleet yet.</p>
          <p className="text-zinc-600 text-xs mt-1">
            Click &quot;Sync Now&quot; to discover and register agents.
          </p>
        </div>
      )}

      {/* Agent list */}
      {!loading && filtered.length > 0 && (
        <div className="space-y-2">
          {filtered.map((agent) => {
            const isExpanded = expanded.has(agent.agent_id);
            const transitions = TRANSITIONS[agent.lifecycle_state] ?? [];
            return (
              <div key={agent.agent_id} className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
                <button
                  onClick={() => toggleExpand(agent.agent_id)}
                  className="w-full px-4 py-3 flex items-center justify-between hover:bg-zinc-800/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {isExpanded ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
                    <span className="font-medium text-zinc-100">{agent.name}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${STATE_COLORS[agent.lifecycle_state]}`}>
                      {STATE_LABELS[agent.lifecycle_state]}
                    </span>
                    <span className="text-xs text-zinc-600">{agent.agent_type}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    {/* Trust score bar */}
                    <div className="flex items-center gap-2 w-32">
                      <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${trustColor(agent.trust_score)}`}
                          style={{ width: `${agent.trust_score}%` }}
                        />
                      </div>
                      <span className={`text-xs font-mono font-semibold ${trustTextColor(agent.trust_score)}`}>
                        {Math.round(agent.trust_score)}
                      </span>
                    </div>
                    {/* Counts */}
                    <div className="flex items-center gap-3 text-xs text-zinc-500">
                      <span className="flex items-center gap-1"><Server className="w-3 h-3" />{agent.server_count}</span>
                      <span className="flex items-center gap-1"><Package className="w-3 h-3" />{agent.package_count}</span>
                      {agent.credential_count > 0 && (
                        <span className="flex items-center gap-1 text-yellow-400"><KeyRound className="w-3 h-3" />{agent.credential_count}</span>
                      )}
                      {agent.vuln_count > 0 && (
                        <span className="flex items-center gap-1 text-red-400"><Bug className="w-3 h-3" />{agent.vuln_count}</span>
                      )}
                    </div>
                  </div>
                </button>
                {isExpanded && (
                  <div className="border-t border-zinc-800 px-4 py-3 space-y-3">
                    {/* Detail grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                      <div>
                        <span className="text-zinc-500">Owner</span>
                        <div className="text-zinc-300 mt-0.5">{agent.owner || "—"}</div>
                      </div>
                      <div>
                        <span className="text-zinc-500">Environment</span>
                        <div className="text-zinc-300 mt-0.5">{agent.environment || "—"}</div>
                      </div>
                      <div>
                        <span className="text-zinc-500">Last Discovery</span>
                        <div className="text-zinc-300 mt-0.5">{agent.last_discovery ? formatDate(agent.last_discovery) : "—"}</div>
                      </div>
                      <div>
                        <span className="text-zinc-500">Config</span>
                        <div className="text-zinc-300 mt-0.5 font-mono truncate">{agent.config_path || "—"}</div>
                      </div>
                    </div>
                    {/* Trust factors */}
                    {Object.keys(agent.trust_factors).length > 0 && (
                      <div>
                        <span className="text-xs text-zinc-500 block mb-1">Trust Factors</span>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(agent.trust_factors).map(([k, v]) => (
                            <span key={k} className="text-xs bg-zinc-800 border border-zinc-700 rounded px-2 py-0.5 text-zinc-400">
                              {k.replace(/_/g, " ")}: <span className="text-zinc-200 font-mono">{v}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {/* State transitions */}
                    {transitions.length > 0 && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-zinc-500">Transition:</span>
                        {transitions.map((t) => (
                          <button
                            key={t}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleStateChange(agent.agent_id, t);
                            }}
                            className={`text-[10px] px-2 py-0.5 rounded border transition-colors hover:opacity-80 ${STATE_COLORS[t]}`}
                          >
                            {STATE_LABELS[t]}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Components ──────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  color,
  suffix,
}: {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
  suffix?: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <Icon className={`w-4 h-4 mb-2 ${color}`} />
      <div className="text-2xl font-bold font-mono">
        {Math.round(value)}{suffix}
      </div>
      <div className="text-xs text-zinc-500 mt-0.5">{label}</div>
    </div>
  );
}
