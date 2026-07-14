"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { PaginationBar } from "@/components/pagination-bar";
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
  Ban,
} from "lucide-react";
import { DeploymentSurfaceRequiredState } from "@/components/deployment-surface-required-state";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { isDeploymentSurfaceAvailable } from "@/lib/deployment-context";
import { useChartTheme } from "@/lib/theme-colors";

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
  discovered: "bg-[var(--surface-elevated)] text-[var(--text-secondary)] border-[var(--border-subtle)]",
  pending_review: "bg-yellow-950 text-yellow-300 border-yellow-800",
  approved: "bg-emerald-950 text-emerald-300 border-emerald-800",
  quarantined: "bg-red-950 text-red-300 border-red-800",
  decommissioned: "bg-[var(--surface)] text-[var(--text-tertiary)] border-[var(--border-subtle)]",
};

const TRANSITIONS: Record<FleetLifecycleState, FleetLifecycleState[]> = {
  discovered: ["pending_review", "approved", "quarantined"],
  pending_review: ["approved", "quarantined"],
  approved: ["quarantined", "decommissioned"],
  quarantined: ["approved", "decommissioned"],
  decommissioned: [],
};

const FLEET_PAGE_SIZE = 100;

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
  const chart = useChartTheme();
  const [agents, setAgents] = useState<FleetAgent[]>([]);
  const [stats, setStats] = useState<FleetStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [quarantiningId, setQuarantiningId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [stateFilter, setStateFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [fleetTotal, setFleetTotal] = useState(0);
  const [fleetOffset, setFleetOffset] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [trustThreshold, setTrustThreshold] = useState(50);
  const { counts } = useDeploymentContext();

  const belowThresholdCount = useMemo(
    () => agents.filter((a) => a.trust_score < trustThreshold).length,
    [agents, trustThreshold]
  );

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    setWarning(null);
    const filters = {
      state: stateFilter === "all" ? undefined : stateFilter,
      search: search.trim() || undefined,
      include_quarantined: stateFilter !== "all",
      limit: FLEET_PAGE_SIZE,
      offset: fleetOffset,
    };
    void Promise.allSettled([api.listFleet(filters), api.getFleetStats()])
      .then(([fleetResult, statsResult]) => {
        if (fleetResult.status === "fulfilled") {
          setAgents(fleetResult.value.agents);
          setFleetTotal(fleetResult.value.total);
        } else {
          setAgents([]);
          setFleetTotal(0);
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
  }, [fleetOffset, search, stateFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setFleetOffset(0);
  }, [search, stateFilter]);

  const handleSync = async () => {
    setSyncing(true);
    try {
      await api.syncFleet();
      void load();
    } finally {
      setSyncing(false);
    }
  };

  const handleStateChange = async (agentId: string, newState: FleetLifecycleState) => {
    if (!confirm(`Change this agent state to ${newState}?`)) return;
    await api.updateFleetState(agentId, newState);
    void load();
  };

  const handleQuarantine = async (agentId: string, agentName: string) => {
    if (
      !confirm(
        `Quarantine "${agentName}" and enforce a gateway DENY policy for its identity?\n\n` +
          "This blocks every tool call from this agent at the gateway until you re-approve it.",
      )
    )
      return;
    setQuarantiningId(agentId);
    setNotice(null);
    try {
      const result = await api.quarantineFleetAgent(agentId);
      setNotice(
        `Quarantined "${agentName}" — gateway ${result.gateway_policy.mode} deny policy ${
          result.gateway_policy.created ? "created" : "re-enabled"
        }.`,
      );
      void load();
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "Failed to quarantine agent");
    } finally {
      setQuarantiningId(null);
    }
  };

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filtered = agents;
  const pageStart = fleetTotal > 0 ? fleetOffset + 1 : 0;
  const pageEnd = fleetTotal > 0 ? Math.min(fleetOffset + agents.length, fleetTotal) : 0;
  const pageNumber = Math.floor(fleetOffset / FLEET_PAGE_SIZE) + 1;
  const totalPages = Math.max(1, Math.ceil(fleetTotal / FLEET_PAGE_SIZE));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Users className="w-6 h-6 text-emerald-400" />
            Fleet
          </h1>
          <p className="text-[var(--text-secondary)] text-sm mt-1">
            Persisted agent inventory, review state, and trust score from the fleet store
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {agents.length > 0 && (
            <button
              onClick={() => downloadJson(filtered, `fleet-${new Date().toISOString().slice(0, 10)}.json`)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--surface-elevated)] hover:bg-[var(--surface-muted)] border border-[var(--border-subtle)] text-[var(--text-secondary)] text-sm font-medium rounded-lg transition-colors"
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
      <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-4">
        <div className="flex items-center gap-2 mb-3">
          <Settings className="w-4 h-4 text-[var(--text-secondary)]" />
          <h3 className="text-sm font-semibold text-[var(--text-secondary)]">Policy threshold</h3>
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <div className="flex-1">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-[var(--text-tertiary)]">Minimum trust score</span>
              <span className="text-xs font-mono text-[var(--foreground)]">{trustThreshold}</span>
            </div>
            <input
              type="range"
              min={0}
              max={100}
              value={trustThreshold}
              onChange={(e) => setTrustThreshold(Number(e.target.value))}
              className="w-full h-1.5 bg-[var(--surface-elevated)] rounded-full appearance-none cursor-pointer accent-emerald-500"
            />
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-[var(--text-secondary)]">
              <span className="font-mono text-yellow-400">{belowThresholdCount}</span> agents below threshold
            </span>
          </div>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Total Agents" value={stats.total} icon={Users} color="text-[var(--text-secondary)]" />
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
          discovered: chart.severity.unrated,
          pending_review: chart.status.warn,
          approved: chart.status.success,
          quarantined: chart.status.danger,
          decommissioned: chart.text,
        };
        const chartData = Object.entries(stats.by_state)
          .filter(([, v]) => v > 0)
          .map(([state, count]) => ({ state: STATE_LABELS[state as FleetLifecycleState] ?? state, count, fill: STATE_CHART_COLORS[state] ?? chart.severity.unrated }));
        return (
          <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-5">
            <h3 className="text-sm font-semibold text-[var(--text-secondary)] mb-1">Lifecycle Distribution</h3>
            <p className="text-[10px] text-[var(--text-tertiary)] mb-4">Agent count by lifecycle state</p>
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
                  <XAxis dataKey="state" tick={{ fontSize: 10, fill: chart.text }} tickLine={false} axisLine={{ stroke: chart.border }} />
                  <YAxis tick={{ fontSize: 10, fill: chart.text }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                  <Tooltip contentStyle={{ background: chart.tooltip.bg, border: `1px solid ${chart.tooltip.border}`, borderRadius: 8, fontSize: 12 }} itemStyle={{ color: chart.tooltip.text }} labelStyle={{ color: chart.text, marginBottom: 4 }} />
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
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="relative w-full sm:w-96">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-tertiary)]" />
          <input
            type="text"
            placeholder="Search by name, owner, environment, or tag..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[var(--surface)] border border-[var(--border-subtle)] rounded-lg pl-8 pr-3 py-1.5 text-sm text-[var(--foreground)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-[var(--border-strong)]"
          />
        </div>
        <div className="text-xs text-[var(--text-tertiary)]">
          {fleetTotal > 0 ? (
            <span>
              Showing <span className="font-mono text-[var(--text-secondary)]">{pageStart}-{pageEnd}</span> of{" "}
              <span className="font-mono text-[var(--text-secondary)]">{fleetTotal}</span> agents
            </span>
          ) : (
            <span>No matching agents</span>
          )}
        </div>
      </div>

      <div className="flex gap-1.5 flex-wrap">
        {["all", "discovered", "pending_review", "approved", "quarantined", "decommissioned"].map((s) => (
          <button
            key={s}
            onClick={() => setStateFilter(s)}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              stateFilter === s
                ? "bg-[var(--surface-elevated)] text-[var(--foreground)]"
                : "text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:bg-[var(--surface)]"
            }`}
          >
            {s === "all" ? "All" : STATE_LABELS[s as FleetLifecycleState]}
            {s !== "all" && stats && (
              <span className="ml-1 text-[var(--text-tertiary)]">
                {stats.by_state[s] ?? 0}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-[var(--text-tertiary)]" />
        </div>
      )}

      {/* Error state */}
      {error && !loading && (
        <div className="text-center py-16 border border-dashed border-red-900/50 rounded-xl">
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-3" />
          <p className="text-red-400 text-sm">Failed to load fleet data</p>
          <p className="text-[var(--text-tertiary)] text-xs mt-1">{error}</p>
        </div>
      )}

      {warning && !loading && !error && (
        <div className="rounded-xl border border-yellow-900/40 bg-yellow-950/20 px-4 py-3">
          <p className="text-sm text-yellow-300">Fleet loaded with partial data</p>
          <p className="mt-1 text-xs text-yellow-100/70">{warning}</p>
        </div>
      )}

      {notice && (
        <div className="flex items-start justify-between gap-3 rounded-xl border border-red-900/50 bg-red-950/20 px-4 py-3">
          <p className="text-sm text-red-200">{notice}</p>
          <button
            onClick={() => setNotice(null)}
            className="text-xs text-red-300/70 hover:text-red-200"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && agents.length === 0 &&
        (counts && !isDeploymentSurfaceAvailable("fleet", counts) ? (
          <DeploymentSurfaceRequiredState surface="fleet" counts={counts} detail={warning} />
        ) : (
          <div className="text-center py-16 border border-dashed border-[var(--border-subtle)] rounded-xl">
            <Users className="w-8 h-8 text-[var(--text-tertiary)] mx-auto mb-3" />
            <p className="text-[var(--text-tertiary)] text-sm">No agents in fleet yet.</p>
            <p className="text-[var(--text-tertiary)] text-xs mt-1">
              Click &quot;Sync Now&quot; to discover and register agents.
            </p>
          </div>
        ))}

      {/* Agent list */}
      {!loading && filtered.length > 0 && (
        <div className="space-y-2">
          {filtered?.map((agent) => {
            const isExpanded = expanded.has(agent.agent_id);
            const transitions = TRANSITIONS[agent.lifecycle_state] ?? [];
            return (
              <div key={agent.agent_id} className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl overflow-hidden">
                <button
                  onClick={() => toggleExpand(agent.agent_id)}
                  className="w-full px-4 py-3 flex flex-col gap-3 text-left transition-colors hover:bg-[var(--surface-elevated)]/50 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="flex min-w-0 flex-wrap items-center gap-3">
                    {isExpanded ? <ChevronDown className="w-4 h-4 shrink-0 text-[var(--text-tertiary)]" /> : <ChevronRight className="w-4 h-4 shrink-0 text-[var(--text-tertiary)]" />}
                    <span className="min-w-0 break-words font-medium text-[var(--foreground)]">{agent.name}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${STATE_COLORS[agent.lifecycle_state]}`}>
                      {STATE_LABELS[agent.lifecycle_state]}
                    </span>
                    <span className="break-words text-xs text-[var(--text-tertiary)]">{agent.agent_type}</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-4">
                    {/* Trust score bar */}
                    <div className="flex items-center gap-2 w-32">
                      <div className="flex-1 h-1.5 bg-[var(--surface-elevated)] rounded-full overflow-hidden">
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
                    <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-tertiary)]">
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
                  <div className="border-t border-[var(--border-subtle)] px-4 py-3 space-y-3">
                    {/* Detail grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                      <div>
                        <span className="text-[var(--text-tertiary)]">Owner</span>
                        <div className="text-[var(--text-secondary)] mt-0.5 break-words">{agent.owner || "—"}</div>
                      </div>
                      <div>
                        <span className="text-[var(--text-tertiary)]">Environment</span>
                        <div className="text-[var(--text-secondary)] mt-0.5 break-words">{agent.environment || "—"}</div>
                      </div>
                      <div>
                        <span className="text-[var(--text-tertiary)]">Last Discovery</span>
                        <div className="text-[var(--text-secondary)] mt-0.5">{agent.last_discovery ? formatDate(agent.last_discovery) : "—"}</div>
                      </div>
                      <div>
                        <span className="text-[var(--text-tertiary)]">Config</span>
                        <div className="text-[var(--text-secondary)] mt-0.5 break-all font-mono">{agent.config_path || "—"}</div>
                      </div>
                    </div>
                    {/* Trust factors */}
                    {Object.keys(agent.trust_factors).length > 0 && (
                      <div>
                        <span className="text-xs text-[var(--text-tertiary)] block mb-1">Trust Factors</span>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(agent.trust_factors).map(([k, v]) => (
                            <span key={k} className="text-xs bg-[var(--surface-elevated)] border border-[var(--border-subtle)] rounded px-2 py-0.5 text-[var(--text-secondary)]">
                              {k.replace(/_/g, " ")}: <span className="break-all font-mono text-[var(--foreground)]">{v}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {/* State transitions */}
                    {transitions.length > 0 && (
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs text-[var(--text-tertiary)]">Transition:</span>
                        {transitions?.map((t) => (
                          <button
                            key={t}
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleStateChange(agent.agent_id, t);
                            }}
                            className={`text-[10px] px-2 py-0.5 rounded border transition-colors hover:opacity-80 ${STATE_COLORS[t]}`}
                          >
                            {STATE_LABELS[t]}
                          </button>
                        ))}
                      </div>
                    )}
                    {/* One-click containment: quarantine + gateway deny */}
                    {agent.lifecycle_state !== "decommissioned" && (
                      <div className="flex flex-col gap-2 border-t border-[var(--border-subtle)] pt-3 sm:flex-row sm:items-center">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            void handleQuarantine(agent.agent_id, agent.name);
                          }}
                          disabled={quarantiningId === agent.agent_id}
                          title="Quarantine this agent and enforce a gateway DENY policy for its identity"
                          className="flex items-center gap-1.5 rounded-md border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs font-medium text-red-300 transition-colors hover:bg-red-900/40 disabled:opacity-50"
                          data-testid="fleet-quarantine-deny"
                        >
                          {quarantiningId === agent.agent_id ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Ban className="h-3.5 w-3.5" />
                          )}
                          {agent.lifecycle_state === "quarantined"
                            ? "Re-enforce gateway deny"
                            : "Quarantine + gateway deny"}
                        </button>
                        <span className="min-w-0 break-words text-[10px] text-[var(--text-tertiary)]">
                          Blocks every tool call from this agent at the gateway.
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {!loading && fleetTotal > FLEET_PAGE_SIZE && (
        <PaginationBar
          page={pageNumber}
          totalPages={totalPages}
          onPrevious={() => setFleetOffset((current) => Math.max(0, current - FLEET_PAGE_SIZE))}
          onNext={() => setFleetOffset((current) => current + FLEET_PAGE_SIZE)}
          previousDisabled={fleetOffset === 0}
          nextDisabled={fleetOffset + agents.length >= fleetTotal}
          className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] px-4 py-3"
        />
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
    <div className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-xl p-4">
      <Icon className={`w-4 h-4 mb-2 ${color}`} />
      <div className="text-2xl font-bold font-mono">
        {Math.round(value)}{suffix}
      </div>
      <div className="text-xs text-[var(--text-tertiary)] mt-0.5">{label}</div>
    </div>
  );
}
