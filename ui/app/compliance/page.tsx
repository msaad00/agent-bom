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
  Scan,
  Grid3X3,
  List,
  Search,
  Download,
  Loader2,
} from "lucide-react";
import { ComplianceControlDrawer } from "@/components/compliance-control-drawer";
import { ComplianceControlRow } from "@/components/compliance-control-row";
import { isNotEvaluated, postureLabel, statusColor } from "@/components/compliance-status";
import { ComplianceHeatmap } from "@/components/compliance-heatmap";
import { ComplianceMatrix } from "@/components/compliance-matrix";
import { CISBenchmarkDetail } from "@/components/cis-benchmark-detail";
import { FrameworkCoveragePanel, type FrameworkCoverageItem } from "@/components/framework-coverage-panel";
import { FrameworkIcon } from "@/components/framework-icon";
import {
  complianceFrameworkSummaries,
  controlMatchesQuery,
} from "@/lib/compliance-frameworks";
import { ApiOfflineState } from "@/components/api-offline-state";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { FIRST_EVIDENCE_ACTIONS } from "@/lib/empty-state-actions";

function _classifyApiErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

function downloadBlobToFile(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Score Ring ──────────────────────────────────────────────────────────────

function ScoreRing({ score, status }: { score: number; status: string }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  // A no-evidence scan has nothing to score. Render a neutral, empty ring with
  // a "Not evaluated" label rather than a red 0% that reads as "failing".
  const notEvaluated = isNotEvaluated(status);
  const offset = notEvaluated ? circ : circ - (score / 100) * circ;
  const color = notEvaluated
    ? "var(--text-tertiary)"
    : status === "pass"
      ? "#34d399"
      : status === "warning"
        ? "#facc15"
        : "#f87171";

  return (
    <div className="relative w-32 h-32">
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--border-strong)" strokeWidth="8" />
        <circle
          cx="60" cy="60" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-1000"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {notEvaluated ? (
          <>
            <span className="text-lg font-bold text-[color:var(--text-secondary)]">—</span>
            <span className="px-1 text-center text-[9px] leading-tight text-[color:var(--text-tertiary)] uppercase tracking-wider">
              Not evaluated
            </span>
          </>
        ) : (
          <>
            <span className="text-2xl font-bold text-[color:var(--foreground)]">{Math.round(score)}%</span>
            <span className="text-[10px] text-[color:var(--text-tertiary)] uppercase tracking-wider">Score</span>
          </>
        )}
      </div>
    </div>
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
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [selectedFrameworkId, setSelectedFrameworkId] = useState("");
  const [selectedControl, setSelectedControl] = useState<{
    control: ComplianceControl;
    frameworkLabel: string;
    catalog?: Record<string, string> | undefined;
  } | null>(null);

  const hasMcp = data?.has_mcp_context ?? false;

  const detailSections = useMemo(() => {
    if (!data) return [];
    return [
      {
        id: "owasp-llm",
        title: "OWASP LLM Top 10",
        subtitle: "2025 Edition",
        controls: data.owasp_llm_top10,
        catalog: OWASP_LLM_TOP10,
        emptyMessage: undefined as string | undefined,
      },
      {
        id: "owasp-mcp",
        title: "OWASP MCP Top 10",
        subtitle: "MCP security risks",
        controls: hasMcp ? data.owasp_mcp_top10 : [],
        catalog: OWASP_MCP_TOP10,
        emptyMessage: "MCP-specific controls appear after a scan with MCP server context.",
      },
      {
        id: "atlas",
        title: "MITRE ATLAS",
        subtitle: "Adversarial ML techniques",
        controls: data.mitre_atlas,
        catalog: MITRE_ATLAS,
        emptyMessage: undefined,
      },
      {
        id: "nist-ai-rmf",
        title: "NIST AI RMF 1.0",
        subtitle: "Govern / Map / Measure / Manage",
        controls: data.nist_ai_rmf,
        catalog: NIST_AI_RMF,
        emptyMessage: undefined,
      },
      {
        id: "owasp-agentic",
        title: "OWASP Agentic Top 10",
        subtitle: "2026 Edition",
        controls: hasMcp ? data.owasp_agentic_top10 : [],
        catalog: OWASP_AGENTIC_TOP10,
        emptyMessage: "Agentic controls appear after a scan with agent and MCP context.",
      },
      {
        id: "eu-ai-act",
        title: "EU AI Act",
        subtitle: "Regulation (EU) 2024/1689",
        controls: data.eu_ai_act,
        catalog: EU_AI_ACT,
        emptyMessage: undefined,
      },
      {
        id: "nist-csf",
        title: "NIST CSF 2.0",
        subtitle: "Cybersecurity Framework",
        controls: data.nist_csf,
        catalog: NIST_CSF,
        emptyMessage: undefined,
      },
      {
        id: "iso27001",
        title: "ISO/IEC 27001:2022",
        subtitle: "Annex A controls",
        controls: data.iso_27001,
        catalog: ISO_27001,
        emptyMessage: undefined,
      },
      {
        id: "soc2",
        title: "SOC 2",
        subtitle: "Trust Services Criteria",
        controls: data.soc2,
        catalog: SOC2_TSC,
        emptyMessage: undefined,
      },
      {
        id: "cis",
        title: "CIS Controls v8",
        subtitle: "Critical security controls",
        controls: data.cis_controls,
        catalog: CIS_CONTROLS,
        emptyMessage: undefined,
      },
      {
        id: "cmmc",
        title: "CMMC 2.0",
        subtitle: "Level 2 practices",
        controls: data.cmmc,
        catalog: CMMC_PRACTICES,
        emptyMessage: undefined,
      },
    ];
  }, [data, hasMcp]);

  const frameworks = useMemo(
    () => (data ? complianceFrameworkSummaries(data, hasMcp) : []),
    [data, hasMcp],
  );

  const frameworkCoverageItems = useMemo((): FrameworkCoverageItem[] => {
    const categoryFor = (id: string): FrameworkCoverageItem["category"] => {
      if (id === "cis" || id === "cmmc") return "cloud";
      if (id === "eu-ai-act" || id === "nist-csf" || id === "iso27001" || id === "soc2") return "governance";
      return "ai";
    };
    return frameworks.map((framework) => ({
      id: framework.id,
      label: framework.label,
      pass: framework.pass,
      warn: framework.warn,
      fail: framework.fail,
      total: framework.total,
      category: categoryFor(framework.id),
    }));
  }, [frameworks]);

  const selectedSection = useMemo(
    () => detailSections.find((section) => section.id === selectedFrameworkId) ?? detailSections[0],
    [detailSections, selectedFrameworkId],
  );

  const visibleControls = useMemo(() => {
    if (!selectedSection) return [];
    return selectedSection.controls.filter((control) => {
      const matchesStatus = statusFilter === "all" || control.status === statusFilter;
      return matchesStatus && controlMatchesQuery(control, controlQuery);
    });
  }, [controlQuery, selectedSection, statusFilter]);

  useEffect(() => {
    if (!frameworks.length || selectedFrameworkId) return;
    const firstFailing = frameworks.find((framework) => !framework.disabled && framework.fail > 0);
    const fallback = frameworks.find((framework) => !framework.disabled);
    setSelectedFrameworkId(firstFailing?.id ?? fallback?.id ?? "");
  }, [frameworks, selectedFrameworkId]);

  const handleExportPack = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const blob = await api.downloadCompliancePack();
      const stamp = new Date().toISOString().slice(0, 10);
      downloadBlobToFile(blob, `agent-bom-compliance-pack-${stamp}.json`);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Failed to export compliance pack");
    } finally {
      setExporting(false);
    }
  };

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
      <PageLoadingState
        title="Loading compliance posture"
        detail="Fetching framework coverage, catalog metadata, and hub posture evidence from the API."
        data-testid="compliance-loading-state"
      />
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

  return (
    <div className="space-y-5">
      {/* ── Trust center header ─────────────────────────────────────────── */}
      <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-5">
            <ScoreRing score={data.overall_score} status={data.overall_status} />
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">
                Trust center
              </p>
              <h1 className={`text-2xl font-bold ${statusColor(data.overall_status)}`}>
                {postureLabel(data.overall_status)}
              </h1>
              <p className="mt-1 text-sm text-[color:var(--text-tertiary)]">
                AI supply-chain frameworks plus cloud CIS posture when accounts are connected — not a full CNAPP claim.
              </p>
              <div className="mt-2 flex flex-wrap gap-4 text-xs text-[color:var(--text-tertiary)]">
                <span>
                  {data.scan_count} scan{data.scan_count !== 1 ? "s" : ""} analyzed
                </span>
                {data.latest_scan ? <span>Latest {formatDate(data.latest_scan)}</span> : null}
                <span>
                  {frameworks.reduce((total, framework) => total + framework.fail, 0)} failing controls
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={() => void handleExportPack()}
            disabled={exporting}
            title="Download a signed evidence pack covering every framework"
            className="flex items-center gap-1.5 self-start rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm font-medium text-emerald-700 transition-colors hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300 dark:hover:bg-emerald-900/40"
            data-testid="compliance-export-pack"
          >
            {exporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {exporting ? "Exporting…" : "Export pack"}
          </button>
        </div>
        {exportError ? (
          <p className="mt-2 text-right text-xs text-red-400">{exportError}</p>
        ) : null}

        <FrameworkCoveragePanel
          items={frameworkCoverageItems}
          onFocusFramework={(frameworkId) => {
            setSelectedFrameworkId(frameworkId);
            setViewMode("detail");
          }}
        />

        {(hubPosture && hubPosture.totals.combined > 0) || mitreCatalog || atlasCatalog ? (
          <details className="mt-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
            <summary className="cursor-pointer text-xs font-medium text-[color:var(--text-secondary)]">
              Operator & catalog context
            </summary>
            <div className="mt-3 space-y-3 text-xs text-[color:var(--text-tertiary)]">
              {hubPosture && hubPosture.totals.combined > 0 ? (
                <p>
                  Compliance hub: {hubPosture.totals.combined.toLocaleString()} findings (
                  {hubPosture.totals.native.toLocaleString()} native ·{" "}
                  {hubPosture.totals.hub.toLocaleString()} ingested). Import via{" "}
                  <code className="rounded bg-[color:var(--surface)] px-1 py-0.5">
                    POST /v1/compliance/ingest
                  </code>
                  .
                </p>
              ) : null}
              {mitreCatalog ? (
                <p>
                  MITRE ATT&CK {mitreCatalog.attack_version || "catalog"} ·{" "}
                  {mitreCatalog.technique_count} techniques · refresh with{" "}
                  <code className="rounded bg-[color:var(--surface)] px-1 py-0.5">
                    agent-bom db update-frameworks
                  </code>
                  .
                </p>
              ) : null}
              {atlasCatalog ? (
                <p>
                  MITRE ATLAS {atlasCatalog.atlas_version || "catalog"} ·{" "}
                  {atlasCatalog.technique_count} techniques · refresh with{" "}
                  <code className="rounded bg-[color:var(--surface)] px-1 py-0.5">
                    agent-bom db update-frameworks --framework atlas
                  </code>
                  .
                </p>
              ) : null}
            </div>
          </details>
        ) : null}
      </div>

      {/* ── View Toggle ────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setViewMode("detail")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            viewMode === "detail"
              ? "bg-emerald-600 text-white"
              : "bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] border border-[color:var(--border-strong)]"
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
              : "bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] border border-[color:var(--border-strong)]"
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
              : "bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] border border-[color:var(--border-strong)]"
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

      {viewMode === "detail" && selectedSection ? (
      <>
      <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <FrameworkIcon frameworkId={selectedSection.id} size={24} />
              <h2 className="text-base font-semibold text-[color:var(--foreground)]">
                {selectedSection.title}
              </h2>
            </div>
            {selectedSection.subtitle ? (
              <p className="mt-0.5 text-xs text-[color:var(--text-tertiary)]">{selectedSection.subtitle}</p>
            ) : null}
            <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
              {visibleControls.length} of {selectedSection.controls.length} controls shown · click a row for evidence
            </p>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative min-w-[220px]">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[color:var(--text-tertiary)]" />
              <input
                type="text"
                value={controlQuery}
                onChange={(e) => setControlQuery(e.target.value)}
                placeholder="Search control, package, agent"
                className="w-full rounded-lg border border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] py-2 pl-9 pr-3 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] p-0.5">
              {(["all", "fail", "warning", "pass"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setStatusFilter(value)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                    statusFilter === value
                      ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                      : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
                  }`}
                >
                  {value === "all" ? "All" : value === "pass" ? "Pass" : value === "warning" ? "Warn" : "Fail"}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <section className="space-y-2">
        {selectedSection.controls.length === 0 && selectedSection.emptyMessage ? (
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5 text-sm text-[color:var(--text-tertiary)]">
            {selectedSection.emptyMessage}
          </div>
        ) : visibleControls.length === 0 ? (
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5 text-sm text-[color:var(--text-tertiary)]">
            No controls match the current filters.
          </div>
        ) : (
          visibleControls.map((control) => (
            <ComplianceControlRow
              key={control.code}
              control={control}
              catalogName={selectedSection.catalog?.[control.code] ?? control.name}
              onOpen={() =>
                setSelectedControl({
                  control,
                  frameworkLabel: selectedSection.title,
                  catalog: selectedSection.catalog,
                })
              }
            />
          ))
        )}
      </section>

      <details className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]">
        <summary className="cursor-pointer px-5 py-4 text-sm font-medium text-[color:var(--foreground)]">
          Cloud CIS benchmark drill-down (AWS / Azure / GCP / Snowflake / Databricks)
        </summary>
        <div className="border-t border-[color:var(--border-subtle)] px-2 pb-2">
          <CISBenchmarkDetail />
        </div>
      </details>

      {selectedControl ? (
        <ComplianceControlDrawer
          control={selectedControl.control}
          frameworkLabel={selectedControl.frameworkLabel}
          catalogName={selectedControl.catalog?.[selectedControl.control.code]}
          onClose={() => setSelectedControl(null)}
        />
      ) : null}
      </>
      ) : null}

      {/* ── Empty state ───────────────────────────────────────────────── */}
      {data.scan_count === 0 && (
        <PageEmptyState
          title="No compliance scans yet"
          detail="Run a scan to populate framework coverage, control status, affected packages, and governance evidence."
          icon={Scan}
          suggestions={[
            "Start with a local scan to generate compliance-tagged findings.",
            "Open findings after the scan to verify the evidence behind failed controls.",
            "Use the matrix view once multiple frameworks have populated control coverage.",
          ]}
          command="agent-bom agents --demo --offline"
          actions={FIRST_EVIDENCE_ACTIONS}
          data-testid="compliance-empty-state"
        />
      )}
    </div>
  );
}

export default function CompliancePage() {
  return (
    <Suspense
      fallback={
        <PageLoadingState
          title="Loading compliance posture"
          detail="Preparing framework controls and scan-derived posture summaries."
        />
      }
    >
      <CompliancePageContent />
    </Suspense>
  );
}
