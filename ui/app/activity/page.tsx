"use client";

import { useEffect, useState } from "react";
import {
  Clock,
  AlertTriangle,
  Bot,
  Terminal,
  Wrench,
  Zap,
  Search,
} from "lucide-react";
import { api, formatDate } from "@/lib/api";
import type { ActivityTimeline } from "@/lib/api";

export default function ActivityPage() {
  const [timeline, setTimeline] = useState<ActivityTimeline | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(30);
  const [tab, setTab] = useState<"queries" | "events">("queries");
  const [search, setSearch] = useState("");

  useEffect(() => {
    setLoading(true);
    setError(null);
    api
      .getActivity(days)
      .then(setTimeline)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [days]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-zinc-500">
        <div className="animate-pulse">Loading activity timeline...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/50 p-6 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
        <p className="text-red-300 text-sm">{error}</p>
        <p className="text-zinc-500 text-xs mt-2">
          Activity requires SNOWFLAKE_ACCOUNT env var on the API server.
        </p>
      </div>
    );
  }

  if (!timeline) return null;

  const filteredQueries = timeline.query_history.filter(
    (q) =>
      !search ||
      q.query_text.toLowerCase().includes(search.toLowerCase()) ||
      q.agent_pattern.toLowerCase().includes(search.toLowerCase()) ||
      q.user_name.toLowerCase().includes(search.toLowerCase())
  );

  const filteredEvents = timeline.observability_events.filter(
    (e) =>
      !search ||
      e.agent_name.toLowerCase().includes(search.toLowerCase()) ||
      e.tool_name.toLowerCase().includes(search.toLowerCase()) ||
      e.event_type.toLowerCase().includes(search.toLowerCase())
  );

  // Aggregate query patterns
  const patternCounts: Record<string, number> = {};
  for (const q of timeline.query_history) {
    if (q.agent_pattern) {
      patternCounts[q.agent_pattern] = (patternCounts[q.agent_pattern] || 0) + 1;
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Clock className="w-6 h-6 text-emerald-400" />
            Agent Activity Timeline
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Account: {timeline.account} | Discovered: {formatDate(timeline.discovered_at)}
          </p>
        </div>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300"
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
          <option value={365}>Last 365 days</option>
        </select>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          icon={Terminal}
          label="Total Queries"
          value={timeline.summary.total_queries}
          color="text-blue-400"
        />
        <StatCard
          icon={Bot}
          label="Agent Queries"
          value={timeline.summary.agent_queries}
          color="text-emerald-400"
        />
        <StatCard
          icon={Zap}
          label="AI Events"
          value={timeline.summary.observability_events}
          color="text-purple-400"
        />
        <StatCard
          icon={Bot}
          label="Unique Agents"
          value={timeline.summary.unique_agents}
          color="text-amber-400"
        />
        <StatCard
          icon={Wrench}
          label="Tool Calls"
          value={timeline.summary.tool_calls}
          color="text-cyan-400"
        />
      </div>

      {/* Warnings */}
      {timeline.warnings.length > 0 && (
        <div className="rounded-lg border border-yellow-800/50 bg-yellow-950/20 p-4">
          <p className="text-xs font-medium text-yellow-400 mb-2">Warnings</p>
          {timeline.warnings.map((w, i) => (
            <p key={i} className="text-xs text-yellow-300/70">{w}</p>
          ))}
        </div>
      )}

      {/* Pattern breakdown */}
      {Object.keys(patternCounts).length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
          <h3 className="text-sm font-semibold text-zinc-300 mb-3">
            Agent Query Patterns
          </h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(patternCounts)
              .sort(([, a], [, b]) => b - a)
              .map(([pattern, count]) => (
                <span
                  key={pattern}
                  className="px-3 py-1 rounded-md text-xs font-mono bg-zinc-800 text-zinc-300 border border-zinc-700"
                >
                  {pattern}{" "}
                  <span className="text-emerald-400 ml-1">{count}</span>
                </span>
              ))}
          </div>
        </div>
      )}

      {/* Search + Tabs */}
      <div className="flex items-center gap-4">
        <div className="flex gap-1">
          <TabButton
            label={`Queries (${timeline.query_history.length})`}
            active={tab === "queries"}
            onClick={() => setTab("queries")}
          />
          <TabButton
            label={`AI Events (${timeline.observability_events.length})`}
            active={tab === "events"}
            onClick={() => setTab("events")}
          />
        </div>
        <div className="relative flex-1 max-w-xs">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            placeholder="Search..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-zinc-900 border border-zinc-700 rounded-md pl-9 pr-3 py-1.5 text-sm text-zinc-300 placeholder-zinc-600"
          />
        </div>
      </div>

      {/* Query History Tab */}
      {tab === "queries" && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-zinc-500 border-b border-zinc-800 bg-zinc-900">
                  <th className="text-left py-2 px-3">Time</th>
                  <th className="text-left py-2 px-3">User</th>
                  <th className="text-left py-2 px-3">Role</th>
                  <th className="text-left py-2 px-3">Pattern</th>
                  <th className="text-left py-2 px-3">Query</th>
                  <th className="text-left py-2 px-3">Status</th>
                  <th className="text-right py-2 px-3">Time (ms)</th>
                </tr>
              </thead>
              <tbody>
                {filteredQueries.slice(0, 100).map((q) => (
                  <tr
                    key={q.query_id}
                    className="border-b border-zinc-800/50 hover:bg-zinc-800/30"
                  >
                    <td className="py-1.5 px-3 text-zinc-500 whitespace-nowrap">
                      {formatDate(q.start_time)}
                    </td>
                    <td className="py-1.5 px-3 text-zinc-300 font-mono">
                      {q.user_name}
                    </td>
                    <td className="py-1.5 px-3 text-zinc-400 font-mono">
                      {q.role_name}
                    </td>
                    <td className="py-1.5 px-3">
                      {q.is_agent_query ? (
                        <span className="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-400 border border-emerald-800">
                          {q.agent_pattern}
                        </span>
                      ) : (
                        <span className="text-zinc-600">-</span>
                      )}
                    </td>
                    <td className="py-1.5 px-3 text-zinc-400 font-mono truncate max-w-[300px]">
                      {q.query_text}
                    </td>
                    <td className="py-1.5 px-3">
                      <StatusBadge status={q.execution_status} />
                    </td>
                    <td className="py-1.5 px-3 text-right text-zinc-500 font-mono">
                      {q.execution_time_ms.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredQueries.length === 0 && (
              <div className="text-center py-8 text-zinc-500 text-sm">
                No queries match the search.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Observability Events Tab */}
      {tab === "events" && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-zinc-500 border-b border-zinc-800 bg-zinc-900">
                  <th className="text-left py-2 px-3">Time</th>
                  <th className="text-left py-2 px-3">Agent</th>
                  <th className="text-left py-2 px-3">Event Type</th>
                  <th className="text-left py-2 px-3">Tool</th>
                  <th className="text-left py-2 px-3">Model</th>
                  <th className="text-left py-2 px-3">Trace</th>
                  <th className="text-right py-2 px-3">Tokens</th>
                  <th className="text-right py-2 px-3">Duration</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.slice(0, 100).map((e) => (
                  <tr
                    key={e.event_id}
                    className="border-b border-zinc-800/50 hover:bg-zinc-800/30"
                  >
                    <td className="py-1.5 px-3 text-zinc-500 whitespace-nowrap">
                      {formatDate(e.timestamp)}
                    </td>
                    <td className="py-1.5 px-3 text-zinc-300 font-mono">
                      {e.agent_name || "-"}
                    </td>
                    <td className="py-1.5 px-3">
                      <EventTypeBadge type={e.event_type} />
                    </td>
                    <td className="py-1.5 px-3 text-zinc-400 font-mono">
                      {e.tool_name || "-"}
                    </td>
                    <td className="py-1.5 px-3 text-zinc-500 font-mono text-xs">
                      {e.model_name || "-"}
                    </td>
                    <td className="py-1.5 px-3 text-zinc-600 font-mono truncate max-w-[100px]">
                      {e.trace_id || "-"}
                    </td>
                    <td className="py-1.5 px-3 text-right text-zinc-500 font-mono">
                      {(e.input_tokens + e.output_tokens).toLocaleString()}
                    </td>
                    <td className="py-1.5 px-3 text-right text-zinc-500 font-mono">
                      {e.duration_ms.toLocaleString()}ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredEvents.length === 0 && (
              <div className="text-center py-8 text-zinc-500 text-sm">
                {timeline.observability_events.length === 0
                  ? "No AI observability events available. Enable AI observability in Snowflake."
                  : "No events match the search."}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

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
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="text-xs text-zinc-500">{label}</span>
      </div>
      <p className="text-2xl font-bold text-zinc-100">{value.toLocaleString()}</p>
    </div>
  );
}

function TabButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
        active
          ? "bg-zinc-700 text-zinc-100"
          : "bg-zinc-900 text-zinc-400 hover:bg-zinc-800"
      }`}
    >
      {label}
    </button>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color =
    status === "SUCCESS"
      ? "text-emerald-400 bg-emerald-950 border-emerald-800"
      : status === "FAIL" || status === "FAILED"
        ? "text-red-400 bg-red-950 border-red-800"
        : "text-zinc-400 bg-zinc-800 border-zinc-700";

  return (
    <span className={`px-2 py-0.5 rounded text-xs border ${color}`}>
      {status}
    </span>
  );
}

function EventTypeBadge({ type }: { type: string }) {
  const colorMap: Record<string, string> = {
    TOOL_CALL: "text-cyan-400 bg-cyan-950 border-cyan-800",
    LLM_INFERENCE: "text-purple-400 bg-purple-950 border-purple-800",
    AGENT_RUN: "text-emerald-400 bg-emerald-950 border-emerald-800",
    USER_FEEDBACK: "text-amber-400 bg-amber-950 border-amber-800",
  };

  return (
    <span
      className={`px-2 py-0.5 rounded text-xs border ${
        colorMap[type] || "text-zinc-400 bg-zinc-800 border-zinc-700"
      }`}
    >
      {type}
    </span>
  );
}
