"use client";

import { useEffect, useState } from "react";
import {
  api,
  type GatewayPolicy,
  type GatewayPolicyRuntimeSummary,
  type GatewayStatsResponse,
  type PolicyAuditEntry,
  type PolicyMode,
  formatDate,
} from "@/lib/api";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import {
  Lock,
  RefreshCw,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Plus,
  Trash2,
  Play,
  FileText,
  AlertTriangle,
} from "lucide-react";

// ─── Helpers ────────────────────────────────────────────────────────────────

const MODE_COLORS: Record<PolicyMode, string> = {
  audit: "bg-blue-950 text-blue-300 border-blue-800",
  enforce: "bg-red-950 text-red-300 border-red-800",
};

const RUNTIME_COLORS: Record<GatewayPolicyRuntimeSummary["rollout_mode"], string> = {
  disabled: "bg-zinc-900 text-zinc-300 border-zinc-700",
  advisory_only: "bg-blue-950 text-blue-300 border-blue-800",
  mixed: "bg-amber-950 text-amber-300 border-amber-800",
  default_deny: "bg-red-950 text-red-300 border-red-800",
  blocking: "bg-emerald-950 text-emerald-300 border-emerald-800",
};

// ─── Page ───────────────────────────────────────────────────────────────────

export default function GatewayPage() {
  const [policies, setPolicies] = useState<GatewayPolicy[]>([]);
  const [stats, setStats] = useState<GatewayStatsResponse | null>(null);
  const [audit, setAudit] = useState<PolicyAuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [tab, setTab] = useState<"policies" | "audit" | "evaluate">("policies");

  // Evaluate form state
  const [evalTool, setEvalTool] = useState("");
  const [evalArgs, setEvalArgs] = useState("{}");
  const [evalResult, setEvalResult] = useState<{ allowed: boolean; reason: string } | null>(null);

  // Create form state
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newMode, setNewMode] = useState<PolicyMode>("audit");
  const [newBlockTools, setNewBlockTools] = useState("");
  const [newDescription, setNewDescription] = useState("");

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      api.listGatewayPolicies(),
      api.getGatewayStats(),
      api.listGatewayAudit(),
    ])
      .then(([p, s, a]) => {
        setPolicies(p.policies);
        setStats(s);
        setAudit(a.entries);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleCreate = async () => {
    const tools = newBlockTools.split(",").map((t) => t.trim()).filter(Boolean);
    const rules = tools.length > 0
      ? [{ id: "r1", action: "block", block_tools: tools, description: "Block listed tools" }]
      : [];
    await api.createGatewayPolicy({
      name: newName,
      description: newDescription,
      mode: newMode,
      rules,
      enabled: true,
    } as Partial<GatewayPolicy>);
    setShowCreate(false);
    setNewName("");
    setNewMode("audit");
    setNewBlockTools("");
    setNewDescription("");
    void load();
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this policy? This cannot be undone.')) return;
    await api.deleteGatewayPolicy(id);
    void load();
  };

  const handleToggleEnabled = async (policy: GatewayPolicy) => {
    await api.updateGatewayPolicy(policy.policy_id, { enabled: !policy.enabled } as Partial<GatewayPolicy>);
    void load();
  };

  const handleEvaluate = async () => {
    try {
      const args = JSON.parse(evalArgs);
      const result = await api.evaluateGateway({ tool_name: evalTool, arguments: args });
      setEvalResult(result);
    } catch {
      setEvalResult({ allowed: false, reason: "Invalid JSON arguments" });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Lock className="w-6 h-6 text-blue-400" />
            Gateway Policies
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            Runtime MCP gateway rules with policy-as-code enforcement
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          Create Policy
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <>
          <RuntimePostureCard runtime={stats.policy_runtime} />
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatCard label="Total Policies" value={stats.total_policies} icon={Lock} color="text-zinc-400" />
            <StatCard label="Enforce Mode" value={stats.enforce_count} icon={ShieldAlert} color="text-red-400" />
            <StatCard label="Audit Mode" value={stats.audit_count} icon={ShieldCheck} color="text-blue-400" />
            <StatCard label="Blocked" value={stats.blocked_count} icon={ShieldAlert} color="text-orange-400" />
          </div>
        </>
      )}

      {/* Tabs */}
      <div className="flex gap-1.5">
        {(["policies", "audit", "evaluate"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              tab === t
                ? "bg-zinc-800 text-zinc-100"
                : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900"
            }`}
          >
            {t === "policies" ? "Policies" : t === "audit" ? "Audit Log" : "Evaluate"}
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
        <div className="text-center py-10 border border-dashed border-red-900/50 rounded-xl space-y-3">
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto" />
          <p className="text-red-400 text-sm">Failed to load gateway data</p>
          <p className="text-zinc-500 text-xs">{error}</p>
          <button onClick={load} className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors">
            <RefreshCw className="w-3.5 h-3.5" /> Retry
          </button>
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-semibold text-zinc-100">New Gateway Policy</h3>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Name</label>
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 focus:outline-none focus:border-blue-600"
                placeholder="block-exec-tools"
              />
            </div>
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Mode</label>
              <select
                value={newMode}
                onChange={(e) => setNewMode(e.target.value as PolicyMode)}
                className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 focus:outline-none focus:border-blue-600"
              >
                <option value="audit">Audit (log only)</option>
                <option value="enforce">Enforce (block)</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-zinc-500 block mb-1">Block Tools (comma-separated)</label>
            <input
              value={newBlockTools}
              onChange={(e) => setNewBlockTools(e.target.value)}
              className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 focus:outline-none focus:border-blue-600"
              placeholder="execute_command, write_file, http_request"
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 block mb-1">Description</label>
            <input
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 focus:outline-none focus:border-blue-600"
              placeholder="Block dangerous command execution tools"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <button
              onClick={() => setShowCreate(false)}
              className="px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleCreate}
              disabled={!newName}
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded text-sm font-medium transition-colors"
            >
              Create
            </button>
          </div>
        </div>
      )}

      {/* Policies tab */}
      {!loading && tab === "policies" && (
        <>
          {policies.length === 0 && (
            <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
              <Lock className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
              <p className="text-zinc-500 text-sm">No gateway policies yet.</p>
              <p className="text-zinc-600 text-xs mt-1">
                Create a policy to define runtime MCP tool enforcement rules.
              </p>
            </div>
          )}
          <div className="space-y-2">
            {policies?.map((policy) => {
              const isExpanded = expanded.has(policy.policy_id);
              return (
                <div key={policy.policy_id} className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
                  <button
                    onClick={() => toggleExpand(policy.policy_id)}
                    className="w-full px-4 py-3 flex items-center justify-between hover:bg-zinc-800/50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      {isExpanded ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
                      <span className="font-medium text-zinc-100">{policy.name}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${MODE_COLORS[policy.mode]}`}>
                        {policy.mode}
                      </span>
                      {!policy.enabled && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded border bg-zinc-900 text-zinc-500 border-zinc-800">
                          disabled
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-zinc-500">
                      <span>{policy.rules.length} rule{policy.rules.length !== 1 ? "s" : ""}</span>
                      {policy.bound_agents.length > 0 && (
                        <span>{policy.bound_agents.length} bound</span>
                      )}
                    </div>
                  </button>
                  {isExpanded && (
                    <div className="border-t border-zinc-800 px-4 py-3 space-y-3">
                      {policy.description && (
                        <p className="text-xs text-zinc-400">{policy.description}</p>
                      )}
                      {/* Rules */}
                      {policy.rules.length > 0 && (
                        <div>
                          <span className="text-xs text-zinc-500 block mb-1">Rules</span>
                          <div className="space-y-1">
                            {policy.rules?.map((rule) => (
                              <div key={rule.id} className="text-xs bg-zinc-800 border border-zinc-700 rounded px-2 py-1.5 text-zinc-400">
                                <span className="text-zinc-200 font-mono">{rule.id}</span>
                                {rule.description && <span className="ml-2">{rule.description}</span>}
                                {rule.block_tools.length > 0 && (
                                  <span className="ml-2 text-red-400">
                                    blocks: {rule.block_tools.join(", ")}
                                  </span>
                                )}
                                {rule.tool_name_pattern && (
                                  <span className="ml-2 text-yellow-400">
                                    pattern: {rule.tool_name_pattern}
                                  </span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {/* Detail grid */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                        <div>
                          <span className="text-zinc-500">Created</span>
                          <div className="text-zinc-300 mt-0.5">{policy.created_at ? formatDate(policy.created_at) : "—"}</div>
                        </div>
                        <div>
                          <span className="text-zinc-500">Updated</span>
                          <div className="text-zinc-300 mt-0.5">{policy.updated_at ? formatDate(policy.updated_at) : "—"}</div>
                        </div>
                        <div>
                          <span className="text-zinc-500">Bound Agents</span>
                          <div className="text-zinc-300 mt-0.5">{policy.bound_agents.length > 0 ? policy.bound_agents.join(", ") : "All"}</div>
                        </div>
                        <div>
                          <span className="text-zinc-500">Environments</span>
                          <div className="text-zinc-300 mt-0.5">{policy.bound_environments.length > 0 ? policy.bound_environments.join(", ") : "All"}</div>
                        </div>
                      </div>
                      {/* Actions */}
                      <div className="flex items-center gap-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); void handleToggleEnabled(policy); }}
                          className="text-[10px] px-2 py-0.5 rounded border transition-colors hover:opacity-80 bg-zinc-800 text-zinc-300 border-zinc-700"
                        >
                          {policy.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); void handleDelete(policy.policy_id); }}
                          className="text-[10px] px-2 py-0.5 rounded border transition-colors hover:opacity-80 bg-red-950 text-red-300 border-red-800 flex items-center gap-1"
                        >
                          <Trash2 className="w-3 h-3" />
                          Delete
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      {/* Audit tab */}
      {!loading && tab === "audit" && (
        <>
          {audit.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
              <FileText className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
              <p className="text-zinc-500 text-sm">No audit entries yet.</p>
            </div>
          ) : (
            <>
              {/* Audit chart: action breakdown by top tools */}
              {(() => {
                const toolCounts: Record<string, { blocked: number; alerted: number; allowed: number }> = {};
                for (const e of audit) {
                  if (!toolCounts[e.tool_name]) toolCounts[e.tool_name] = { blocked: 0, alerted: 0, allowed: 0 };
                  const key = e.action_taken as "blocked" | "alerted" | "allowed";
                  if (key in toolCounts[e.tool_name]) toolCounts[e.tool_name][key]++;
                }
                const chartData = Object.entries(toolCounts)
                  .sort(([, a], [, b]) => (b.blocked + b.alerted) - (a.blocked + a.alerted))
                  .slice(0, 10)
                  .map(([tool, counts]) => ({ tool: tool.length > 16 ? tool.slice(0, 14) + "…" : tool, ...counts }));
                return (
                  <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
                    <h3 className="text-sm font-semibold text-zinc-300 mb-1">Enforcement Actions by Tool</h3>
                    <p className="text-[10px] text-zinc-600 mb-4">Top tools by blocked + alerted count</p>
                    <div className="h-44">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                          <XAxis dataKey="tool" tick={{ fontSize: 9, fill: "#71717a" }} tickLine={false} axisLine={{ stroke: "#27272a" }} />
                          <YAxis tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
                          <Tooltip contentStyle={{ background: "#09090b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} itemStyle={{ color: "#e4e4e7" }} labelStyle={{ color: "#71717a", marginBottom: 4 }} />
                          <Bar dataKey="blocked" name="blocked" stackId="a" fill="#ef4444" fillOpacity={0.8} />
                          <Bar dataKey="alerted" name="alerted" stackId="a" fill="#f97316" fillOpacity={0.8} />
                          <Bar dataKey="allowed" name="allowed" stackId="a" fill="#22c55e" fillOpacity={0.5} radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                );
              })()}
            <div className="space-y-1">
              {audit?.map((entry) => (
                <div key={entry.entry_id} className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                      entry.action_taken === "blocked"
                        ? "bg-red-950 text-red-300 border-red-800"
                        : entry.action_taken === "alerted"
                        ? "bg-yellow-950 text-yellow-300 border-yellow-800"
                        : "bg-emerald-950 text-emerald-300 border-emerald-800"
                    }`}>
                      {entry.action_taken}
                    </span>
                    <span className="text-xs text-zinc-300 font-mono">{entry.tool_name}</span>
                    <span className="text-xs text-zinc-500">{entry.agent_name || "—"}</span>
                    <span className="text-xs text-zinc-600 truncate max-w-xs">{entry.reason}</span>
                  </div>
                  <span className="text-xs text-zinc-600">{entry.timestamp ? formatDate(entry.timestamp) : ""}</span>
                </div>
              ))}
            </div>
            </>
          )}
        </>
      )}

      {/* Evaluate tab */}
      {!loading && tab === "evaluate" && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <Play className="w-4 h-4 text-blue-400" />
            Dry-Run Evaluation
          </h3>
          <p className="text-xs text-zinc-500">
            Test how gateway policies would evaluate a tool call without actually making one.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Tool Name</label>
              <input
                value={evalTool}
                onChange={(e) => setEvalTool(e.target.value)}
                className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 font-mono focus:outline-none focus:border-blue-600"
                placeholder="execute_command"
              />
            </div>
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Arguments (JSON)</label>
              <input
                value={evalArgs}
                onChange={(e) => setEvalArgs(e.target.value)}
                className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 font-mono focus:outline-none focus:border-blue-600"
                placeholder='{"command": "rm -rf /"}'
              />
            </div>
          </div>
          <button
            onClick={handleEvaluate}
            disabled={!evalTool}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Play className="w-4 h-4" />
            Evaluate
          </button>
          {evalResult && (
            <div className={`rounded-lg border p-4 ${
              evalResult.allowed
                ? "border-emerald-800 bg-emerald-950/50"
                : "border-red-800 bg-red-950/50"
            }`}>
              <div className="flex items-center gap-2">
                {evalResult.allowed ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                )}
                <span className={`text-sm font-semibold ${evalResult.allowed ? "text-emerald-300" : "text-red-300"}`}>
                  {evalResult.allowed ? "Allowed" : "Blocked"}
                </span>
              </div>
              {evalResult.reason && (
                <p className="text-xs text-zinc-400 mt-1">{evalResult.reason}</p>
              )}
            </div>
          )}
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
}: {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <Icon className={`w-4 h-4 mb-2 ${color}`} />
      <div className="text-2xl font-bold font-mono">{value}</div>
      <div className="text-xs text-zinc-500 mt-0.5">{label}</div>
    </div>
  );
}

function RuntimePostureCard({ runtime }: { runtime: GatewayPolicyRuntimeSummary }) {
  const highlights = [
    { label: "Enabled policies", value: String(runtime.enabled_policies) },
    { label: "Blocking rules", value: String(runtime.blocking_rules) },
    { label: "Advisory rules", value: String(runtime.advisory_rules) },
    { label: "Allowlist rules", value: String(runtime.allowlist_rules) },
  ];

  if (runtime.protects_secret_paths) {
    highlights.push({ label: "Secret path guard", value: "On" });
  }
  if (runtime.restricts_unknown_egress) {
    highlights.push({ label: "Unknown egress guard", value: "On" });
  }

  return (
    <div className="rounded-2xl border border-zinc-800 bg-[linear-gradient(135deg,rgba(24,24,27,0.98),rgba(9,9,11,0.98))] p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-[0.18em] text-zinc-500">
              Runtime posture
            </span>
            <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.14em] ${RUNTIME_COLORS[runtime.rollout_mode]}`}>
              {runtime.rollout_mode.replaceAll("_", " ")}
            </span>
          </div>
          <p className="max-w-2xl text-sm text-zinc-300">{runtime.summary}</p>
          {runtime.denied_tool_classes.length > 0 && (
            <p className="text-xs text-zinc-500">
              Denied tool classes: {runtime.denied_tool_classes.join(", ")}
            </p>
          )}
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {highlights.map((item) => (
            <div key={item.label} className="rounded-xl border border-zinc-800 bg-zinc-950/80 px-3 py-2">
              <div className="text-[10px] uppercase tracking-[0.16em] text-zinc-600">{item.label}</div>
              <div className="mt-1 text-sm font-semibold text-zinc-100">{item.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
