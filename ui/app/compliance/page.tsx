"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  api,
  ComplianceResponse,
  ComplianceControl,
  FrameworkCatalogMetadata,
  MitreAtlasCatalogMetadata,
  HubPostureResponse,
  OWASP_LLM_TOP10,
  OWASP_MCP_TOP10,
  OWASP_AGENTIC_TOP10,
  EU_AI_ACT,
  MITRE_ATLAS,
  NIST_AI_RMF,
  NIST_CSF,
  ISO_27001,
  SOC2_TSC,
  CIS_CONTROLS,
  CMMC_PRACTICES,
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
  Search,
} from "lucide-react";
import Link from "next/link";
import { ComplianceHeatmap } from "@/components/compliance-heatmap";
import { ComplianceMatrix } from "@/components/compliance-matrix";
import { ApiOfflineState } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";

function _classifyApiErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

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

function ControlCard({ control, catalog }: { control: ComplianceControl; catalog?: Record<string, string> | undefined }) {
  const [expanded, setExpanded] = useState(false);
  const name = catalog?.[control.code] ?? control.name;
  const sev = {
    critical: control.severity_breakdown.critical ?? 0,
    high: control.severity_breakdown.high ?? 0,
    medium: control.severity_breakdown.medium ?? 0,
    low: control.severity_breakdown.low ?? 0,
  };
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
                    {control.affected_packages?.map((pkg) => (
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
                    {control.affected_agents?.map((agent) => (
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

function FrameworkSection({
  title,
  subtitle,
  accentClass,
  controls,
  catalog,
  query,
  statusFilter,
  emptyMessage,
  defaultOpen = true,
}: {
  title: string;
  subtitle?: string | undefined;
  accentClass: string;
  controls: ComplianceControl[];
  catalog?: Record<string, string> | undefined;
  query: string;
  statusFilter: "all" | "pass" | "warning" | "fail";
  emptyMessage?: string | undefined;
  defaultOpen?: boolean | undefined;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const normalizedQuery = query.trim().toLowerCase();
  const visibleControls = useMemo(
    () =>
      controls.filter((control) => {
        const matchesStatus = statusFilter === "all" || control.status === statusFilter;
        const searchable = [
          control.code,
          control.name,
          ...control.affected_packages,
          ...control.affected_agents,
        ]
          .join(" ")
          .toLowerCase();
        const matchesQuery = !normalizedQuery || searchable.includes(normalizedQuery);
        return matchesStatus && matchesQuery;
      }),
    [controls, normalizedQuery, statusFilter],
  );
  const failCount = controls.filter((control) => control.status === "fail").length;
  const warningCount = controls.filter((control) => control.status === "warning").length;

  return (
    <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40">
      <button
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left"
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 className={`text-lg font-semibold ${accentClass}`}>{title}</h2>
            {subtitle ? <span className="text-xs text-zinc-500">{subtitle}</span> : null}
          </div>
          <div className="mt-2 flex flex-wrap gap-3 text-xs text-zinc-500">
            <span>{controls.length} controls</span>
            <span>{failCount} fail</span>
            <span>{warningCount} warning</span>
            {visibleControls.length !== controls.length ? <span>{visibleControls.length} shown</span> : null}
          </div>
        </div>
        {open ? <ChevronDown className="h-4 w-4 text-zinc-500" /> : <ChevronRight className="h-4 w-4 text-zinc-500" />}
      </button>
      {open ? (
        <div className="border-t border-zinc-800 px-5 py-5">
          {controls.length === 0 && emptyMessage ? (
            <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-5 text-sm text-zinc-500">
              {emptyMessage}
            </div>
          ) : visibleControls.length === 0 ? (
            <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-5 text-sm text-zinc-500">
              No controls match the current filters.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {visibleControls.map((control) => (
                <ControlCard key={control.code} control={control} catalog={catalog} />
              ))}
            </div>
          )}
        </div>
      ) : null}
    </section>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────────

function CompliancePageContent() {
  const searchParams = useSearchParams();
  const queryParam = searchParams.get("q") ?? "";
  const [data, setData] = useState<ComplianceResponse | null>(null);
  const [mitreCatalog, setMitreCatalog] = useState<FrameworkCatalogMetadata | null>(null);
  const [atlasCatalog, setAtlasCatalog] = useState<MitreAtlasCatalogMetadata | null>(null);
  const [hubPosture, setHubPosture] = useState<HubPostureResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Per #2199 splash-kind sweep: classify API errors so the splash matches
  // the actual cause (auth/forbidden/network) instead of always reading as
  // "Cannot connect to the agent-bom API".
  const [errorKind, setErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [viewMode, setViewMode] = useState<"detail" | "heatmap" | "matrix">("detail");
  const [controlQuery, setControlQuery] = useState(queryParam);
  const [statusFilter, setStatusFilter] = useState<"all" | "pass" | "warning" | "fail">("all");

  useEffect(() => {
    setControlQuery(queryParam);
  }, [queryParam]);

  useEffect(() => {
    void Promise.allSettled([
      api.getCompliance(),
      api.getFrameworkCatalogs(),
      api.getHubPosture(),
    ])
      .then(([complianceResult, catalogResult, hubResult]) => {
        if (complianceResult.status === "fulfilled") {
          setData(complianceResult.value);
        } else {
          const reason = complianceResult.reason;
          setError(reason?.message ?? "Failed to load compliance view");
          setErrorKind(_classifyApiErrorKind(reason));
        }
        if (catalogResult.status === "fulfilled") {
          setMitreCatalog(catalogResult.value.frameworks?.mitre_attack ?? null);
          setAtlasCatalog(catalogResult.value.frameworks?.mitre_atlas ?? null);
        }
        // Hub posture is best-effort: a missing endpoint shouldn't blank the page
        if (hubResult.status === "fulfilled") {
          setHubPosture(hubResult.value);
        }
      })
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
    const fallbackTitle = errorKind === "network" ? "Compliance view needs the agent-bom API" : undefined;
    return (
      <ApiOfflineState
        title={fallbackTitle}
        detail={error}
        kind={errorKind}
      />
    );
  }

  if (!data) return null;

  const { summary: s } = data;
  const hasMcp = data.has_mcp_context ?? false;
  const detailSections: Array<{
    id: string;
    title: string;
    subtitle?: string | undefined;
    accentClass: string;
    controls: ComplianceControl[];
    catalog?: Record<string, string>;
    emptyMessage?: string | undefined;
  }> = [
    {
      id: "owasp-llm",
      title: "OWASP LLM Top 10",
      subtitle: "2025 Edition",
      accentClass: "text-zinc-200",
      controls: data.owasp_llm_top10,
      catalog: OWASP_LLM_TOP10,
    },
    {
      id: "owasp-mcp",
      title: "OWASP MCP Top 10",
      subtitle: "MCP security risks",
      accentClass: hasMcp ? "text-zinc-200" : "text-zinc-500",
      controls: hasMcp ? data.owasp_mcp_top10 : [],
      catalog: OWASP_MCP_TOP10,
      emptyMessage: "MCP-specific controls appear after a scan with MCP server context.",
    },
    {
      id: "atlas",
      title: "MITRE ATLAS",
      subtitle: "Adversarial ML techniques",
      accentClass: "text-zinc-200",
      controls: data.mitre_atlas,
      catalog: MITRE_ATLAS,
    },
    {
      id: "nist-ai-rmf",
      title: "NIST AI RMF 1.0",
      subtitle: "Govern / Map / Measure / Manage",
      accentClass: "text-zinc-200",
      controls: data.nist_ai_rmf,
      catalog: NIST_AI_RMF,
    },
    {
      id: "owasp-agentic",
      title: "OWASP Agentic Top 10",
      subtitle: "2026 Edition",
      accentClass: hasMcp ? "text-zinc-200" : "text-zinc-500",
      controls: hasMcp ? data.owasp_agentic_top10 : [],
      catalog: OWASP_AGENTIC_TOP10,
      emptyMessage: "Agentic controls appear after a scan with agent and MCP context.",
    },
    {
      id: "eu-ai-act",
      title: "EU AI Act",
      subtitle: "Regulation (EU) 2024/1689",
      accentClass: "text-zinc-200",
      controls: data.eu_ai_act,
      catalog: EU_AI_ACT,
    },
    {
      id: "nist-csf",
      title: "NIST CSF 2.0",
      subtitle: "Cybersecurity Framework",
      accentClass: "text-zinc-200",
      controls: data.nist_csf,
      catalog: NIST_CSF,
    },
    {
      id: "iso27001",
      title: "ISO/IEC 27001:2022",
      subtitle: "Annex A controls",
      accentClass: "text-zinc-200",
      controls: data.iso_27001,
      catalog: ISO_27001,
    },
    {
      id: "soc2",
      title: "SOC 2",
      subtitle: "Trust Services Criteria",
      accentClass: "text-zinc-200",
      controls: data.soc2,
      catalog: SOC2_TSC,
    },
    {
      id: "cis",
      title: "CIS Controls v8",
      subtitle: "Critical security controls",
      accentClass: "text-zinc-200",
      controls: data.cis_controls,
      catalog: CIS_CONTROLS,
    },
    {
      id: "cmmc",
      title: "CMMC 2.0",
      subtitle: "Level 2 practices",
      accentClass: "text-zinc-200",
      controls: data.cmmc,
      catalog: CMMC_PRACTICES,
    },
  ];

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

        {/* Compliance Hub aggregate (#1044) — surfaces external ingest counts
            alongside the native posture so the page tells one unified story. */}
        {hubPosture && hubPosture.totals.combined > 0 ? (
          <div className="mt-6 rounded-xl border border-emerald-900/40 bg-emerald-950/20 p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-1">
                <div className="text-xs uppercase tracking-[0.24em] text-emerald-400">Compliance Hub</div>
                <div className="text-sm text-zinc-200">
                  {hubPosture.totals.combined.toLocaleString()} finding{hubPosture.totals.combined !== 1 ? "s" : ""} across all sources
                  {hubPosture.totals.hub > 0 ? (
                    <>
                      {" "}<span className="text-emerald-400">({hubPosture.totals.hub.toLocaleString()} ingested external)</span>
                    </>
                  ) : null}
                </div>
                <div className="text-xs text-zinc-500">
                  Native: {hubPosture.totals.native.toLocaleString()} · Hub-ingested: {hubPosture.totals.hub.toLocaleString()}
                  {Object.keys(hubPosture.framework_counts.combined).length > 0 ? (
                    <> · Frameworks lit: {Object.keys(hubPosture.framework_counts.combined).length}</>
                  ) : null}
                </div>
              </div>
              <div className="text-xs text-zinc-500 lg:max-w-sm">
                Import SARIF / CycloneDX / CSV / JSON via{" "}
                <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-300">POST /v1/compliance/ingest</code>{" "}
                — every external finding is auto-mapped to the same framework set as native scans.
              </div>
            </div>
          </div>
        ) : null}

        {/* Framework mini-cards */}
        {mitreCatalog ? (
          <div className="mt-6 rounded-xl border border-zinc-800 bg-zinc-950/70 p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-1">
                <div className="text-xs uppercase tracking-[0.24em] text-cyan-400">MITRE ATT&CK catalog</div>
                <div className="text-sm text-zinc-300">
                  {mitreCatalog.attack_version || "unknown version"} · {mitreCatalog.technique_count} techniques · {mitreCatalog.cwe_mapping_count} CWE mappings
                </div>
                <div className="text-xs text-zinc-500">
                  Source: {mitreCatalog.source}
                  {mitreCatalog.updated_at ? ` · updated ${formatDate(mitreCatalog.updated_at)}` : ""}
                </div>
              </div>
              <div className="text-xs text-zinc-500 lg:max-w-sm">
                Bundled by default for deterministic scans. Refresh explicitly with{" "}
                <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-300">agent-bom db update-frameworks</code>{" "}
                when you want a newer upstream snapshot.
              </div>
            </div>
          </div>
        ) : null}
        {atlasCatalog ? (
          <div className="mt-3 rounded-xl border border-zinc-800 bg-zinc-950/70 p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-1">
                <div className="text-xs uppercase tracking-[0.24em] text-fuchsia-400">MITRE ATLAS catalog</div>
                <div className="text-sm text-zinc-300">
                  {atlasCatalog.atlas_version || "unknown version"} ·{" "}
                  {typeof atlasCatalog.curated_count === "number"
                    ? `${atlasCatalog.curated_count} curated / ${atlasCatalog.technique_count} upstream`
                    : `${atlasCatalog.technique_count} techniques`}{" "}
                  · {atlasCatalog.tactic_count} tactics
                </div>
                <div className="text-xs text-zinc-500">
                  Source: {atlasCatalog.source}
                  {atlasCatalog.updated_at ? ` · updated ${formatDate(atlasCatalog.updated_at)}` : ""}
                </div>
              </div>
              <div className="text-xs text-zinc-500 lg:max-w-sm">
                Curated tag surface stays load-bearing for tagging precision; the bundled
                upstream catalog powers coverage rollups. Refresh explicitly with{" "}
                <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-300">
                  agent-bom db update-frameworks --framework atlas
                </code>
                .
              </div>
            </div>
          </div>
        ) : null}

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
          <div className={`bg-zinc-950 rounded-xl p-4 border border-zinc-800 ${!hasMcp ? "opacity-40" : ""}`}>
            <div className="text-xs text-amber-500/80 mb-1">OWASP MCP Top 10</div>
            {hasMcp ? (
              <>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-zinc-100">{s.owasp_mcp_pass}</span>
                  <span className="text-sm text-zinc-500">/ 10 pass</span>
                </div>
                <div className="flex gap-2 mt-2 text-xs">
                  {s.owasp_mcp_fail > 0 && <span className="text-red-400">{s.owasp_mcp_fail} fail</span>}
                  {s.owasp_mcp_warn > 0 && <span className="text-yellow-400">{s.owasp_mcp_warn} warn</span>}
                </div>
              </>
            ) : (
              <div className="text-xs text-zinc-600 mt-1">No MCP servers detected</div>
            )}
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
          <div className={`bg-zinc-950 rounded-xl p-4 border border-zinc-800 ${!hasMcp ? "opacity-40" : ""}`}>
            <div className="text-xs text-fuchsia-500/80 mb-1">OWASP Agentic Top 10</div>
            {hasMcp ? (
              <>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-zinc-100">{s.owasp_agentic_pass}</span>
                  <span className="text-sm text-zinc-500">/ 10 pass</span>
                </div>
                <div className="flex gap-2 mt-2 text-xs">
                  {s.owasp_agentic_fail > 0 && <span className="text-red-400">{s.owasp_agentic_fail} fail</span>}
                  {s.owasp_agentic_warn > 0 && <span className="text-yellow-400">{s.owasp_agentic_warn} warn</span>}
                </div>
              </>
            ) : (
              <div className="text-xs text-zinc-600 mt-1">No agents detected</div>
            )}
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
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-teal-500/80 mb-1">NIST CSF 2.0</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.nist_csf_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.nist_csf.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.nist_csf_fail > 0 && <span className="text-red-400">{s.nist_csf_fail} fail</span>}
              {s.nist_csf_warn > 0 && <span className="text-yellow-400">{s.nist_csf_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-sky-500/80 mb-1">ISO 27001</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.iso_27001_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.iso_27001.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.iso_27001_fail > 0 && <span className="text-red-400">{s.iso_27001_fail} fail</span>}
              {s.iso_27001_warn > 0 && <span className="text-yellow-400">{s.iso_27001_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-indigo-500/80 mb-1">SOC 2</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.soc2_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.soc2.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.soc2_fail > 0 && <span className="text-red-400">{s.soc2_fail} fail</span>}
              {s.soc2_warn > 0 && <span className="text-yellow-400">{s.soc2_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-lime-500/80 mb-1">CIS Controls v8</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.cis_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.cis_controls.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.cis_fail > 0 && <span className="text-red-400">{s.cis_fail} fail</span>}
              {s.cis_warn > 0 && <span className="text-yellow-400">{s.cis_warn} warn</span>}
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl p-4 border border-zinc-800">
            <div className="text-xs text-rose-500/80 mb-1">CMMC 2.0</div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-zinc-100">{s.cmmc_pass}</span>
              <span className="text-sm text-zinc-500">/ {data.cmmc.length} pass</span>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {s.cmmc_fail > 0 && <span className="text-red-400">{s.cmmc_fail} fail</span>}
              {s.cmmc_warn > 0 && <span className="text-yellow-400">{s.cmmc_warn} warn</span>}
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
        <button
          onClick={() => setViewMode("matrix")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            viewMode === "matrix"
              ? "bg-emerald-600 text-white"
              : "bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-700"
          }`}
        >
          <Scan className="w-3.5 h-3.5" />
          Matrix
        </button>
      </div>

      {/* ── Heatmap View ──────────────────────────────────────────────── */}
      {viewMode === "heatmap" && <ComplianceHeatmap data={data} />}

      {/* ── Matrix View ───────────────────────────────────────────────── */}
      {viewMode === "matrix" && <ComplianceMatrix data={data} />}

      {/* ── Detail View ───────────────────────────────────────────────── */}
      {viewMode === "detail" && (
      <>

      {/* ── Framework Coverage Bars ────────────────────────────────────── */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 space-y-5">
        <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wider">Framework Coverage</h2>
        <FrameworkBar label="OWASP LLM Top 10" pass={s.owasp_pass} warn={s.owasp_warn} fail={s.owasp_fail} total={10} />
        <FrameworkBar label="MITRE ATLAS" pass={s.atlas_pass} warn={s.atlas_warn} fail={s.atlas_fail} total={data.mitre_atlas.length} />
        {hasMcp && <FrameworkBar label="OWASP MCP Top 10" pass={s.owasp_mcp_pass} warn={s.owasp_mcp_warn} fail={s.owasp_mcp_fail} total={10} />}
        <FrameworkBar label="NIST AI RMF" pass={s.nist_pass} warn={s.nist_warn} fail={s.nist_fail} total={data.nist_ai_rmf.length} />
        {hasMcp && <FrameworkBar label="OWASP Agentic Top 10" pass={s.owasp_agentic_pass} warn={s.owasp_agentic_warn} fail={s.owasp_agentic_fail} total={10} />}
        <FrameworkBar label="EU AI Act" pass={s.eu_ai_act_pass} warn={s.eu_ai_act_warn} fail={s.eu_ai_act_fail} total={data.eu_ai_act.length} />
        <FrameworkBar label="NIST CSF 2.0" pass={s.nist_csf_pass} warn={s.nist_csf_warn} fail={s.nist_csf_fail} total={data.nist_csf.length} />
        <FrameworkBar label="ISO 27001" pass={s.iso_27001_pass} warn={s.iso_27001_warn} fail={s.iso_27001_fail} total={data.iso_27001.length} />
        <FrameworkBar label="SOC 2" pass={s.soc2_pass} warn={s.soc2_warn} fail={s.soc2_fail} total={data.soc2.length} />
        <FrameworkBar label="CIS Controls v8" pass={s.cis_pass} warn={s.cis_warn} fail={s.cis_fail} total={data.cis_controls.length} />
        <FrameworkBar label="CMMC 2.0" pass={s.cmmc_pass} warn={s.cmmc_warn} fail={s.cmmc_fail} total={data.cmmc.length} />
      </div>

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-zinc-200">Control explorer</h2>
            <p className="mt-1 text-xs text-zinc-500">Filter once, then expand only the frameworks you need.</p>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative min-w-[240px]">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
              <input
                type="text"
                value={controlQuery}
                onChange={(e) => setControlQuery(e.target.value)}
                placeholder="Search control, package, or agent"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 py-2 pl-9 pr-3 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
            <div className="flex items-center gap-1">
              {(["all", "fail", "warning", "pass"] as const).map((value) => (
                <button
                  key={value}
                  onClick={() => setStatusFilter(value)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                    statusFilter === value
                      ? "bg-zinc-800 text-zinc-100"
                      : "text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300"
                  }`}
                >
                  {value === "all" ? "All" : value === "pass" ? "Passing" : value === "warning" ? "Warnings" : "Failing"}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {detailSections.map((section) => (
          <FrameworkSection
            key={section.id}
            title={section.title}
            subtitle={section.subtitle}
            accentClass={section.accentClass}
            controls={section.controls}
            catalog={section.catalog}
            query={controlQuery}
            statusFilter={statusFilter}
            emptyMessage={section.emptyMessage}
          />
        ))}
      </div>

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

export default function CompliancePage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-20 text-zinc-400">
          <Loader2 className="mr-2 h-6 w-6 animate-spin" />
          Loading compliance posture...
        </div>
      }
    >
      <CompliancePageContent />
    </Suspense>
  );
}
