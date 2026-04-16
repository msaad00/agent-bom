"use client";

import { useEffect, useRef, useState } from "react";
import {
  api,
  type ProxyStatusResponse,
  type ProxyAlert,
  formatDate,
} from "@/lib/api";
import { getConfiguredApiUrl } from "@/lib/runtime-config";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  Shield,
  Activity,
  AlertTriangle,
  Loader2,
  RefreshCw,
  Wifi,
  WifiOff,
  Zap,
  Clock,
  ShieldAlert,
  ShieldCheck,
  Ban,
} from "lucide-react";

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-950 text-red-300 border-red-800",
  high: "bg-orange-950 text-orange-300 border-orange-800",
  medium: "bg-yellow-950 text-yellow-300 border-yellow-800",
  low: "bg-blue-950 text-blue-300 border-blue-800",
  info: "bg-zinc-800 text-zinc-300 border-zinc-700",
};

const PIE_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#71717a"];

// ─── WebSocket metrics type ──────────────────────────────────────────────────

interface LiveMetrics {
  ts: number;
  tool_calls: Record<string, number>;
  blocked: Record<string, number>;
  alerts_last_60s: number;
  latency_p95_ms: number | null;
  total_tool_calls: number;
  total_blocked: number;
  uptime_seconds: number | null;
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function ProxyDashboard() {
  const [status, setStatus] = useState<ProxyStatusResponse | null>(null);
  const [alerts, setAlerts] = useState<ProxyAlert[]>([]);
  const [live, setLive] = useState<LiveMetrics | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial data
  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([api.getProxyStatus(), api.getProxyAlerts({ limit: 200 })])
      .then(([s, a]) => {
        setStatus(s);
        setAlerts(a.alerts);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      load();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  // WebSocket for live metrics
  useEffect(() => {
    const base = getConfiguredApiUrl() || window.location.origin;
    const wsUrl = base.replace(/^http/, "ws") + "/ws/proxy/metrics";

    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => {
        setWsConnected(false);
        reconnectTimer = setTimeout(connect, 5000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          setLive(JSON.parse(e.data));
        } catch {
          // ignore parse errors
        }
      };
    };

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, []);

  // Derived data
  const totalCalls = live?.total_tool_calls ?? status?.total_tool_calls ?? 0;
  const totalBlocked = live?.total_blocked ?? status?.total_blocked ?? 0;
  const uptime = live?.uptime_seconds ?? status?.uptime_seconds ?? null;
  const alertCount = live?.alerts_last_60s ?? 0;
  const latencyP95 = live?.latency_p95_ms ?? status?.latency?.p95_ms ?? null;
  const isActive = status?.status !== "no_proxy_session";

  // Tool call chart data
  const toolCalls = live?.tool_calls ?? status?.calls_by_tool ?? {};
  const toolChartData = Object.entries(toolCalls)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 12)
    .map(([tool, count]) => ({
      tool: tool.length > 18 ? tool.slice(0, 16) + "…" : tool,
      count,
    }));

  // Blocked breakdown for pie chart
  const blockedMap = live?.blocked ?? status?.blocked_by_reason ?? {};
  const blockedPieData = Object.entries(blockedMap)
    .filter(([, v]) => v > 0)
    .map(([reason, count]) => ({ name: reason, value: count }));

  // Filtered alerts
  const filteredAlerts = severityFilter
    ? alerts.filter((a) => a.severity === severityFilter)
    : alerts;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            Proxy Dashboard
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            Runtime MCP proxy metrics, detector activity, and security alerts
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs">
            {wsConnected ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-zinc-500" />
                <span className="text-zinc-500">Disconnected</span>
              </>
            )}
          </div>
          <button
            onClick={load}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-zinc-500" />
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="text-center py-10 border border-dashed border-red-900/50 rounded-xl space-y-3">
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto" />
          <p className="text-red-400 text-sm">Failed to load proxy data</p>
          <p className="text-zinc-500 text-xs">{error}</p>
          <button
            onClick={load}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Retry
          </button>
        </div>
      )}

      {/* No proxy session */}
      {!loading && !error && !isActive && (
        <div className="rounded-xl border border-dashed border-zinc-800 bg-zinc-950/70 p-8">
          <Shield className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-300 text-sm text-center">No runtime telemetry connected</p>
          <p className="text-zinc-500 text-xs mt-2 max-w-2xl mx-auto text-center">
            Proxy is an optional runtime feed for live tool-call review, policy enforcement, and audit alerts. Core scanning,
            graph analysis, and compliance workflows do not depend on it.
          </p>
          <div className="mt-6 grid gap-3 md:grid-cols-3">
            <SetupCard
              title="Local proxy"
              body="Start an inline MCP proxy for live tool-call telemetry during local testing."
              command="agent-bom proxy -- npx @modelcontextprotocol/server-fs /workspace"
            />
            <SetupCard
              title="Audit log replay"
              body="Point the API at an existing runtime log if you already capture MCP activity elsewhere."
              command="export AGENT_BOM_LOG=/path/to/proxy-audit.log"
            />
            <SetupCard
              title="Hosted runtime feed"
              body="Forward proxy events or audit logs into the API when running agent-bom behind a central service."
              command="POST /v1/proxy/events or /ws/proxy/metrics"
            />
          </div>
        </div>
      )}

      {/* Stats cards */}
      {!loading && !error && isActive && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <StatCard
              label="Tool Calls"
              value={totalCalls.toLocaleString()}
              icon={Zap}
              color="text-emerald-400"
            />
            <StatCard
              label="Blocked"
              value={totalBlocked.toLocaleString()}
              icon={Ban}
              color="text-red-400"
            />
            <StatCard
              label="Alerts (60s)"
              value={String(alertCount)}
              icon={ShieldAlert}
              color="text-orange-400"
            />
            <StatCard
              label="P95 Latency"
              value={latencyP95 != null ? `${latencyP95.toFixed(1)}ms` : "—"}
              icon={Clock}
              color="text-blue-400"
            />
            <StatCard
              label="Uptime"
              value={uptime != null ? formatUptime(uptime) : "—"}
              icon={Activity}
              color="text-zinc-400"
            />
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Tool call frequency */}
            <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-zinc-300 mb-1">
                Tool Call Frequency
              </h3>
              <p className="text-[10px] text-zinc-600 mb-4">
                Top tools by invocation count
              </p>
              {toolChartData.length > 0 ? (
                <div className="h-52">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={toolChartData}
                      margin={{ top: 4, right: 8, bottom: 4, left: 0 }}
                    >
                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="#27272a"
                        vertical={false}
                      />
                      <XAxis
                        dataKey="tool"
                        tick={{ fontSize: 9, fill: "#71717a" }}
                        tickLine={false}
                        axisLine={{ stroke: "#27272a" }}
                      />
                      <YAxis
                        tick={{ fontSize: 10, fill: "#71717a" }}
                        tickLine={false}
                        axisLine={false}
                        allowDecimals={false}
                        width={36}
                      />
                      <Tooltip
                        contentStyle={{
                          background: "#09090b",
                          border: "1px solid #27272a",
                          borderRadius: 8,
                          fontSize: 12,
                        }}
                        itemStyle={{ color: "#e4e4e7" }}
                        labelStyle={{ color: "#71717a", marginBottom: 4 }}
                      />
                      <Bar
                        dataKey="count"
                        name="Calls"
                        fill="#34d399"
                        fillOpacity={0.8}
                        radius={[4, 4, 0, 0]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-52 flex items-center justify-center text-zinc-600 text-xs">
                  No tool calls recorded yet
                </div>
              )}
            </div>

            {/* Blocked breakdown pie */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-zinc-300 mb-1">
                Block Reasons
              </h3>
              <p className="text-[10px] text-zinc-600 mb-4">
                Why tool calls were blocked
              </p>
              {blockedPieData.length > 0 ? (
                <div className="h-52">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={blockedPieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={70}
                        dataKey="value"
                        nameKey="name"
                        stroke="#09090b"
                        strokeWidth={2}
                      >
                        {blockedPieData?.map((_, i) => (
                          <Cell
                            key={i}
                            fill={PIE_COLORS[i % PIE_COLORS.length]}
                            fillOpacity={0.85}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: "#09090b",
                          border: "1px solid #27272a",
                          borderRadius: 8,
                          fontSize: 12,
                        }}
                        itemStyle={{ color: "#e4e4e7" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {blockedPieData?.map((d, i) => (
                      <div
                        key={d.name}
                        className="flex items-center gap-1.5 text-[10px] text-zinc-400"
                      >
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{
                            backgroundColor:
                              PIE_COLORS[i % PIE_COLORS.length],
                          }}
                        />
                        {d.name}: {d.value}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="h-52 flex items-center justify-center">
                  <div className="text-center">
                    <ShieldCheck className="w-6 h-6 text-emerald-600 mx-auto mb-2" />
                    <span className="text-zinc-600 text-xs">
                      No blocked calls
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Detectors */}
          {status?.detectors_active && status.detectors_active.length > 0 && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-zinc-300 mb-3">
                Active Detectors
              </h3>
              <div className="flex flex-wrap gap-2">
                {status.detectors_active?.map((d) => (
                  <span
                    key={d}
                    className="text-[11px] px-2.5 py-1 rounded-full bg-emerald-950/50 text-emerald-300 border border-emerald-800/50 font-mono"
                  >
                    {d}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Alerts */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-zinc-300">
                  Recent Alerts
                </h3>
                <p className="text-[10px] text-zinc-600 mt-0.5">
                  Security alerts from proxy detectors
                </p>
              </div>
              <div className="flex gap-1">
                {["", "critical", "high", "medium", "low"].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-2 py-1 rounded text-[10px] font-medium transition-colors ${
                      severityFilter === sev
                        ? "bg-zinc-700 text-zinc-100"
                        : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800"
                    }`}
                  >
                    {sev || "All"}
                  </button>
                ))}
              </div>
            </div>

            {filteredAlerts.length === 0 ? (
              <div className="text-center py-8">
                <ShieldCheck className="w-6 h-6 text-emerald-600 mx-auto mb-2" />
                <p className="text-zinc-600 text-xs">No alerts</p>
              </div>
            ) : (
              <div className="space-y-1 max-h-96 overflow-y-auto">
                {filteredAlerts?.map((alert, i) => (
                  <div
                    key={`${alert.ts}-${i}`}
                    className="flex items-center justify-between px-3 py-2 bg-zinc-800/50 border border-zinc-800 rounded-lg"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border shrink-0 ${
                          SEVERITY_COLORS[alert.severity] ?? SEVERITY_COLORS.info
                        }`}
                      >
                        {alert.severity}
                      </span>
                      <span className="text-xs text-zinc-400 font-mono shrink-0">
                        {alert.detector}
                      </span>
                      <span className="text-xs text-zinc-300 font-mono shrink-0">
                        {alert.tool_name}
                      </span>
                      <span className="text-xs text-zinc-500 truncate">
                        {alert.message}
                      </span>
                    </div>
                    <span className="text-[10px] text-zinc-600 shrink-0 ml-3">
                      {alert.ts
                        ? formatDate(new Date(alert.ts * 1000).toISOString())
                        : ""}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function SetupCard({
  title,
  body,
  command,
}: {
  title: string;
  body: string;
  command: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-4">
      <p className="text-sm font-medium text-zinc-100">{title}</p>
      <p className="mt-2 text-xs leading-5 text-zinc-500">{body}</p>
      <code className="mt-3 block rounded-lg bg-zinc-950 px-3 py-2 text-[11px] text-zinc-300">
        {command}
      </code>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.round((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: string;
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
