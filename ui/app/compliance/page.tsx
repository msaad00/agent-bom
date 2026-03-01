"use client";

import { useEffect, useState } from "react";
import {
  api,
  ComplianceResponse,
  ComplianceControl,
  OWASP_LLM_TOP10,
  OWASP_MCP_TOP10,
  OWASP_AGENTIC_TOP10,
  EU_AI_ACT,
  MITRE_ATLAS,
  NIST_AI_RMF,
  formatDate,
} from "@/lib/api";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Package,
  Server,
  ChevronDown,
  ChevronRight,
  Loader2,
  Scan,
  Grid3X3,
  List,
} from "lucide-react";
import Link from "next/link";
import { ComplianceHeatmap } from "@/components/compliance-heatmap";

// ─── Status helpers ──────────────────────────────────────────────────────────

function statusColor(status: string): string {
  switch (status) {
    case "pass":    return "text-emerald-400";
    case "warning": return "text-yellow-400";
    case "fail":    return "text-red-400";
    default:        return "text-zinc-400";
  }
}

function statusBg(status: string): string {
  switch (status) {
    case "pass":    return "bg-emerald-950 border-emerald-800";
    case "warning": return "bg-yellow-950 border-yellow-800";
    case "fail":    return "bg-red-950 border-red-800";
    default:        return "bg-zinc-900 border-zinc-800";
  }
}

function StatusIcon({ status, className }: { status: string; className?: string }) {
  switch (status) {
    case "pass":    return <CheckCircle className={`${className ?? "w-4 h-4"} text-emerald-400`} />;
    case "warning": return <AlertTriangle className={`${className ?? "w-4 h-4"} text-yellow-400`} />;
    case "fail":    return <XCircle className={`${className ?? "w-4 h-4"} text-red-400`} />;
    default:        return <Shield className={`${className ?? "w-4 h-4"} text-zinc-400`} />;
  }
}

function PostureIcon({ status }: { status: string }) {
  switch (status) {
    case "pass":    return <ShieldCheck className="w-10 h-10 text-emerald-400" />;
    case "warning": return <ShieldAlert className="w-10 h-10 text-yellow-400" />;
    case "fail":    return <ShieldX className="w-10 h-10 text-red-400" />;
    default:        return <Shield className="w-10 h-10 text-zinc-400" />;
  }
}

function postureLabel(status: string): string {
  switch (status) {
    case "pass":    return "COMPLIANT";
    case "warning": return "NEEDS ATTENTION";
    case "fail":    return "NON-COMPLIANT";
    default:        return "NO DATA";
  }
}

// ─── Score Ring ──────────────────────────────────────────────────────────────

function ScoreRing({ score, status }: { score: number; status: string }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = status === "pass" ? "#34d399" : status === "warning" ? "#facc15" : "#f87171";

  return (
    <div className="relative w-32 h-32">
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#27272a" strokeWidth="8" />
        <circle
          cx="60" cy="60" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-1000"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-zinc-100">{Math.round(score)}%</span>
        <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Score</span>
      </div>
    </div>
  );
}

// ─── Framework Summary Bar ──────────────────────────────────────────────────

function FrameworkBar({
  label, pass: p, warn, fail, total,
}: {
  label: string; pass: number; warn: number; fail: number; total: number;
}) {
  const pPct = (p / total) * 100;
  const wPct = (warn / total) * 100;
  const fPct = (fail / total) * 100;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-zinc-300">{label}</span>
        <span className="text-xs text-zinc-500">{p}/{total} pass</span>
      </div>
      <div className="h-2.5 rounded-full bg-zinc-800 overflow-hidden flex">
        {p > 0 && (
          <div className="bg-emerald-500 transition-all duration-700" style={{ width: `${pPct}%` }} />
        )}
        {warn > 0 && (
          <div className="bg-yellow-500 transition-all duration-700" style={{ width: `${wPct}%` }} />
        )}
        {fail > 0 && (
          <div className="bg-red-500 transition-all duration-700" style={{ width: `${fPct}%` }} />
        )}
      </div>
      <div className="flex gap-4 text-xs text-zinc-500">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-emerald-500" /> {p} pass
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-yellow-500" /> {warn} warning
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500" /> {fail} fail
        </span>
      </div>
    </div>
  );
}

// ─── Control Card ───────────────────────────────────────────────────────────

function ControlCard({ control, catalog }: { control: ComplianceControl; catalog?: Record<string, string> }) {
  const [expanded, setExpanded] = useState(false);
  const name = catalog?.[control.code] ?? control.name;
  const sev = control.severity_breakdown;
  const hasSev = sev.critical > 0 || sev.high > 0 || sev.medium > 0 || sev.low > 0;

  return (
    <div
      className={`border rounded-xl p-4 transition-colors ${statusBg(control.status)}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <StatusIcon status={control.status} className="w-5 h-5 mt-0.5 shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-semibold text-zinc-200">{control.code}</span>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                control.status === "pass"
                  ? "bg-emerald-900/60 text-emerald-300"
                  : control.status === "warning"
                  ? "bg-yellow-900/60 text-yellow-300"
                  : "bg-red-900/60 text-red-300"
              }`}>
                {control.status === "pass" ? "Pass" : control.status === "warning" ? "Needs Attention" : "Fail"}
              </span>
            </div>
            <p className="text-sm text-zinc-400 mt-1 leading-snug">{name}</p>
          </div>
        </div>
        {control.findings > 0 && (
          <span className="text-xs font-mono px-2 py-1 rounded bg-zinc-800 text-zinc-300 shrink-0">
            {control.findings} finding{control.findings !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* Severity dots */}
      {hasSev && (
        <div className="flex gap-3 mt-3 ml-8 text-xs text-zinc-500">
          {sev.critical > 0 && (
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-500" /> {sev.critical} critical
            </span>
          )}
          {sev.high > 0 && (
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-orange-500" /> {sev.high} high
            </span>
          )}
          {sev.medium > 0 && (
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-yellow-500" /> {sev.medium} medium
            </span>
          )}
          {sev.low > 0 && (
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-blue-500" /> {sev.low} low
            </span>
          )}
        </div>
      )}

      {/* Expandable details */}
      {(control.affected_packages.length > 0 || control.affected_agents.length > 0) && (
        <div className="mt-3 ml-8">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            Details
          </button>
          {expanded && (
            <div className="mt-2 space-y-2">
              {control.affected_packages.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-1">
                    <Package className="w-3 h-3" /> Affected Packages
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {control.affected_packages.map((pkg) => (
                      <span key={pkg} className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono">
                        {pkg}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {control.affected_agents.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-1">
                    <Server className="w-3 h-3" /> Affected Agents
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {control.affected_agents.map((agent) => (
                      <span key={agent} className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                        {agent}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [data, setData] = useState<ComplianceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"detail" | "heatmap">("detail");

  useEffect(() => {
    api
      .getCompliance()
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <Loader2 className="w-6 h-6 text-zinc-500 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-xl mx-auto mt-20 text-center space-y-4">
        <ShieldX className="w-12 h-12 text-red-400 mx-auto" />
        <h2 className="text-lg font-semibold text-zinc-200">Unable to load compliance data</h2>
        <p className="text-sm text-zinc-500">
          Make sure the API server is running: <code className="text-zinc-300">agent-bom api</code>
        </p>
        <p className="text-xs text-zinc-600">{error}</p>
      </div>
    );
  }

  if (!data) return null;

  const { summary: s } = data;

  return (
    <div className="space-y-8">
      {/* ── Posture Header ─────────────────────────────────────────────── */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
        <div className="flex items-center gap-6">
          <ScoreRing score={data.overall_score} status={data.overall_status} />
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-3">
              <PostureIcon status={data.overall_status} />
              <div>
                <h1 className={`text-xl font-bold ${statusColor(data.overall_status)}`}>
                  {postureLabel(data.overall_status)}
                </h1>
                <p className="text-sm text-zinc-500">
                  AI Supply Chain Compliance Posture
                </p>
              </div>
            </div>
            <div className="flex gap-6 text-xs text-zinc-500">
              <span>
                {data.scan_count} scan{data.scan_count !== 1 ? "s" : ""} analyzed
              </span>
              {data.latest_scan && (
                <span>Latest: {formatDate(data.latest_scan)}</span>
              )}
            </div>
          </div>
        </div>

        {/* Framework mini-cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mt-6">
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-zinc-500 mb-1">OWASP LLM Top 10</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.owasp_pass}</span>
              <span className="text-sm text-zinc-500">/ 10 pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.owasp_fail > 0 && <span className="text-red-400">{s.owasp_fail} fail</span>}
              {s.owasp_warn > 0 && <span className="text-yellow-400">{s.owasp_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-amber-500/80 mb-1">OWASP MCP Top 10</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.owasp_mcp_pass}</span>
              <span className="text-sm text-zinc-500">/ 10 pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.owasp_mcp_fail > 0 && <span className="text-red-400">{s.owasp_mcp_fail} fail</span>}
              {s.owasp_mcp_warn > 0 && <span className="text-yellow-400">{s.owasp_mcp_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-zinc-500 mb-1">MITRE ATLAS</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.atlas_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.mitre_atlas.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.atlas_fail > 0 && <span className="text-red-400">{s.atlas_fail} fail</span>}
              {s.atlas_warn > 0 && <span className="text-yellow-400">{s.atlas_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-zinc-500 mb-1">NIST AI RMF</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.nist_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.nist_ai_rmf.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.nist_fail > 0 && <span className="text-red-400">{s.nist_fail} fail</span>}
              {s.nist_warn > 0 && <span className="text-yellow-400">{s.nist_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-fuchsia-500/80 mb-1">OWASP Agentic Top 10</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.owasp_agentic_pass}</span>
              <span className="text-sm text-zinc-500">/ 10 pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.owasp_agentic_fail > 0 && <span className="text-red-400">{s.owasp_agentic_fail} fail</span>}
              {s.owasp_agentic_warn > 0 && <span className="text-yellow-400">{s.owasp_agentic_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-blue-500/80 mb-1">EU AI Act</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.eu_ai_act_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.eu_ai_act.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.eu_ai_act_fail > 0 && <span className="text-red-400">{s.eu_ai_act_fail} fail</span>}
              {s.eu_ai_act_warn > 0 && <span className="text-yellow-400">{s.eu_ai_act_warn} warn</span>}
            </div>
          </div>
        </div>
      </div>

      {/* ── View Toggle ────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setViewMode("detail")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            viewMode === "detail"
              ? "bg-emerald-600 text-white"
              : "bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-700"
          }`}
        >
          <List className="w-3.5 h-3.5" />
          Detail
        </button>
        <button
          onClick={() => setViewMode("heatmap")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            viewMode === "heatmap"
              ? "bg-emerald-600 text-white"
              : "bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-700"
          }`}
        >
          <Grid3X3 className="w-3.5 h-3.5" />
          Heatmap
        </button>
      </div>

      {/* ── Heatmap View ──────────────────────────────────────────────── */}
      {viewMode === "heatmap" && <ComplianceHeatmap data={data} />}

      {/* ── Detail View ───────────────────────────────────────────────── */}
      {viewMode === "detail" && (
      <>

      {/* ── Framework Coverage Bars ────────────────────────────────────── */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 space-y-5">
        <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wider">Framework Coverage</h2>
        <FrameworkBar label="OWASP LLM Top 10" pass={s.owasp_pass} warn={s.owasp_warn} fail={s.owasp_fail} total={10} />
        <FrameworkBar label="MITRE ATLAS" pass={s.atlas_pass} warn={s.atlas_warn} fail={s.atlas_fail} total={data.mitre_atlas.length} />
        <FrameworkBar label="OWASP MCP Top 10" pass={s.owasp_mcp_pass} warn={s.owasp_mcp_warn} fail={s.owasp_mcp_fail} total={10} />
        <FrameworkBar label="NIST AI RMF" pass={s.nist_pass} warn={s.nist_warn} fail={s.nist_fail} total={data.nist_ai_rmf.length} />
        <FrameworkBar label="OWASP Agentic Top 10" pass={s.owasp_agentic_pass} warn={s.owasp_agentic_warn} fail={s.owasp_agentic_fail} total={10} />
        <FrameworkBar label="EU AI Act" pass={s.eu_ai_act_pass} warn={s.eu_ai_act_warn} fail={s.eu_ai_act_fail} total={data.eu_ai_act.length} />
      </div>

      {/* ── OWASP LLM Top 10 ──────────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-emerald-400" />
          <h2 className="text-lg font-semibold text-zinc-200">OWASP LLM Top 10</h2>
          <span className="text-xs text-zinc-500 ml-2">2025 Edition</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.owasp_llm_top10.map((c) => (
            <ControlCard key={c.code} control={c} catalog={OWASP_LLM_TOP10} />
          ))}
        </div>
      </section>

      {/* ── OWASP MCP Top 10 ─────────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-amber-400" />
          <h2 className="text-lg font-semibold text-zinc-200">OWASP MCP Top 10</h2>
          <span className="text-xs text-zinc-500 ml-2">MCP Security Risks</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.owasp_mcp_top10.map((c) => (
            <ControlCard key={c.code} control={c} catalog={OWASP_MCP_TOP10} />
          ))}
        </div>
      </section>

      {/* ── MITRE ATLAS ───────────────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-semibold text-zinc-200">MITRE ATLAS</h2>
          <span className="text-xs text-zinc-500 ml-2">Adversarial ML Techniques</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.mitre_atlas.map((c) => (
            <ControlCard key={c.code} control={c} catalog={MITRE_ATLAS} />
          ))}
        </div>
      </section>

      {/* ── NIST AI RMF ───────────────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-purple-400" />
          <h2 className="text-lg font-semibold text-zinc-200">NIST AI RMF 1.0</h2>
          <span className="text-xs text-zinc-500 ml-2">Govern / Map / Measure / Manage</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.nist_ai_rmf.map((c) => (
            <ControlCard key={c.code} control={c} catalog={NIST_AI_RMF} />
          ))}
        </div>
      </section>

      {/* ── OWASP Agentic Top 10 ─────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-fuchsia-400" />
          <h2 className="text-lg font-semibold text-zinc-200">OWASP Agentic Top 10</h2>
          <span className="text-xs text-zinc-500 ml-2">2026 Edition</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.owasp_agentic_top10.map((c) => (
            <ControlCard key={c.code} control={c} catalog={OWASP_AGENTIC_TOP10} />
          ))}
        </div>
      </section>

      {/* ── EU AI Act ────────────────────────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-semibold text-zinc-200">EU AI Act</h2>
          <span className="text-xs text-zinc-500 ml-2">Regulation (EU) 2024/1689</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.eu_ai_act.map((c) => (
            <ControlCard key={c.code} control={c} catalog={EU_AI_ACT} />
          ))}
        </div>
      </section>

      </>
      )}

      {/* ── Empty state ───────────────────────────────────────────────── */}
      {data.scan_count === 0 && (
        <div className="text-center py-12 space-y-4">
          <Scan className="w-12 h-12 text-zinc-600 mx-auto" />
          <h3 className="text-lg font-medium text-zinc-300">No scans yet</h3>
          <p className="text-sm text-zinc-500 max-w-md mx-auto">
            Run a scan to populate the compliance posture dashboard.
            Compliance scores are computed from OWASP, ATLAS, and NIST
            framework tags on your blast radius findings.
          </p>
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors"
          >
            <Scan className="w-4 h-4" />
            Start a Scan
          </Link>
        </div>
      )}
    </div>
  );
}
