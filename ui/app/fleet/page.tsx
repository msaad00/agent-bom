"use client";

import { useEffect, useMemo, useState } from "react";
import {
  api,
  type FleetAgent,
  type FleetStatsResponse,
  type FleetLifecycleState,
  formatDate,
} from "@/lib/api";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from "recharts";
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
  AlertTriangle,
  Settings,
  Download,
  Search,
} from "lucide-react";

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

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
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [stateFilter, setStateFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [trustThreshold, setTrustThreshold] = useState(50);
  const [autoQuarantine, setAutoQuarantine] = useState(false);

  const belowThresholdCount = useMemo(
    () => agents.filter((a) => a.trust_score < trustThreshold).length,
    [agents, trustThreshold]
  );

  const load = () => {
    setLoading(true);
    setError(null);
    setWarning(null);
    Promise.allSettled([api.listFleet(), api.getFleetStats()])
      .then(([fleetResult, statsResult]) => {
        if (fleetResult.status === "fulfilled") {
          setAgents(fleetResult.value.agents);
        } else {
          setAgents([]);
        }

        if (statsResult.status === "fulfilled") {
          setStats(statsResult.value);
        } else {
          setStats(null);
        }

        if (fleetResult.status === "rejected" && statsResult.status === "rejected") {
          setError(fleetResult.reason?.message ?? statsResult.reason?.message ?? "Fleet API requests failed");
          return;
        }

        if (fleetResult.status === "rejected") {
          setError(fleetResult.reason?.message ?? "Fleet inventory request failed");
          return;
        }

        if (statsResult.status === "rejected") {
          setWarning(statsResult.reason?.message ?? "Fleet stats request failed");
        }
      })
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
    if (!confirm(`Change this agent state to ${newState}?`)) return;
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

  const filtered = agents
    .filter((a) => stateFilter === "all" || a.lifecycle_state === stateFilter)
    .filter((a) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        a.name.toLowerCase().includes(q) ||
        (a.owner ?? "").toLowerCase().includes(q) ||
        (a.environment ?? "").toLowerCase().includes(q)
      );
    });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Users className="w-6 h-6 text-emerald-400" />
            Fleet
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            Persisted agent inventory, review state, and trust score from the fleet store
          </p>
        </div>
        <div className="flex items-center gap-2">
          {agents.length > 0 && (
            <button
              onClick={() => downloadJson(filtered, `fleet-${new Date().toISOString().slice(0, 10)}.json`)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-sm font-medium rounded-lg transition-colors"
              title="Export fleet list as JSON"
            >
              <Download className="w-3.5 h-3.5" />
              Export
            </button>
          )}
          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${syncing ? "animate-spin" : ""}`} />
            {syncing ? "Syncing..." : "Sync Now"}
          </button>
        </div>
      </div>

      {/* Trust Threshold Settings */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
        <div className="flex items-center gap-2 mb-3">
          <Settings className="w-4 h-4 text-zinc-400" />
          <h3 className="text-sm font-semibold text-zinc-300">Policy threshold</h3>
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <div className="flex-1">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-zinc-500">Minimum trust score</span>
              <span className="text-xs font-mono text-zinc-200">{trustThreshold}</span>
            </div>
            <input
              type="range"
              min={0}
              max={100}
              value={trustThreshold}
              onChange={(e) => setTrustThreshold(Number(e.target.value))}
              className="w-full h-1.5 bg-zinc-800 rounded-full appearance-none cursor-pointer accent-emerald-500"
            />
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-zinc-400">
              <span className="font-mono text-yellow-400">{belowThresholdCount}</span> agents below threshold
            </span>
            <label className="flex items-center gap-2 cursor-pointer">
              <span className="text-xs text-zinc-500">Auto-quarantine</span>
              <button
                onClick={() => {
                  if (!autoQuarantine && !confirm('This will quarantine agents below the trust threshold. Continue?')) return;
                  setAutoQuarantine((v) => !v);
                }}
                className={`relative w-8 h-4 rounded-full transition-colors ${
                  autoQuarantine ? "bg-emerald-600" : "bg-zinc-700"
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${
                    autoQuarantine ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </button>
            </label>
          </div>
        </div>
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

      {/* Fleet state distribution chart */}
      {stats && stats.total > 0 && (() => {
        const STATE_CHART_COLORS: Record<string, string> = {
          discovered: "#71717a",
          pending_review: "#eab308",
          approved: "#22c55e",
          quarantined: "#ef4444",
          decommissioned: "#3f3f46",
        };
        const chartData = Object.entries(stats.by_state)
          .filter(([, v]) => v > 0)
          .map(([state, count]) => ({ state: STATE_LABELS[state as FleetLifecycleState] ?? state, count, fill: STATE_CHART_COLORS[state] ?? "#71717a" }));
        return (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-zinc-300 mb-1">Lifecycle Distribution</h3>
            <p className="text-[10px] text-zinc-600 mb-4">Agent count by lifecycle state</p>
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
                  <XAxis dataKey="state" tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={{ stroke: "#27272a" }} />
                  <YAxis tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                  <Tooltip contentStyle={{ background: "#09090b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} itemStyle={{ color: "#e4e4e7" }} labelStyle={{ color: "#71717a", marginBottom: 4 }} />
                  <Bar dataKey="count" name="agents" radius={[4, 4, 0, 0]}>
                    {chartData?.map((entry, i) => <Cell key={i} fill={entry.fill} fillOpacity={0.8} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        );
      })()}

      {/* Search + Filter tabs */}
      <div className="relative w-full sm:w-72">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-600" />
        <input
          type="text"
          placeholder="Search by name, owner, environment…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-zinc-900 border border-zinc-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
        />
      </div>

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

      {/* Error state */}
      {error && !loading && (
        <div className="text-center py-16 border border-dashed border-red-900/50 rounded-xl">
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-3" />
          <p className="text-red-400 text-sm">Failed to load fleet data</p>
          <p className="text-zinc-500 text-xs mt-1">{error}</p>
        </div>
      )}

      {warning && !loading && !error && (
        <div className="rounded-xl border border-yellow-900/40 bg-yellow-950/20 px-4 py-3">
          <p className="text-sm text-yellow-300">Fleet loaded with partial data</p>
          <p className="mt-1 text-xs text-yellow-100/70">{warning}</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && agents.length === 0 && (
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
          {filtered?.map((agent) => {
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
                        {transitions?.map((t) => (
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
