"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
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
import {
  controlStatusLabel,
  evidenceReasonLabel,
  isControlUnscored,
  isNotEvaluated,
  postureLabel,
  statusColor,
  StatusIcon,
} from "@/components/compliance-status";
import { ComplianceHeatmap } from "@/components/compliance-heatmap";
import { ComplianceMatrix } from "@/components/compliance-matrix";
import { CISBenchmarkDetail } from "@/components/cis-benchmark-detail";
import { ComplianceNistCatalog } from "@/components/compliance-nist-catalog";
import { FrameworkIcon } from "@/components/framework-icon";
import {
  complianceFrameworkSummaries,
  compliancePassRate,
  complianceScoredTotals,
  controlMatchesQuery,
  type ComplianceFrameworkSummary,
} from "@/lib/compliance-frameworks";
import { ApiOfflineState } from "@/components/api-offline-state";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { FIRST_EVIDENCE_ACTIONS } from "@/lib/empty-state-actions";
import { StatStrip, type StatStripItem, type StatAccent } from "@/components/stat-strip";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { SplitLayout } from "@/components/split-layout";
import { Collapsible } from "@/components/collapsible";

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

function statusToAccent(status: string): StatAccent {
  if (isNotEvaluated(status)) return "neutral";
  if (status === "pass") return "success";
  if (status === "warning") return "warn";
  if (status === "fail") return "critical";
  return "neutral";
}

/** Compact three-segment pass/warn/fail bar, token-styled for both themes. */
function CoverageBar({
  pass,
  warn,
  fail,
  total,
}: Pick<ComplianceFrameworkSummary, "pass" | "warn" | "fail" | "total">) {
  const seg = (n: number) => (total > 0 ? (n / total) * 100 : 0);
  return (
    <div className="flex h-1.5 w-full min-w-[72px] max-w-[140px] overflow-hidden rounded-full bg-[color:var(--surface-muted)]">
      {pass > 0 ? (
        <div style={{ width: `${seg(pass)}%`, backgroundColor: "var(--status-success)" }} />
      ) : null}
      {warn > 0 ? (
        <div style={{ width: `${seg(warn)}%`, backgroundColor: "var(--status-warn)" }} />
      ) : null}
      {fail > 0 ? (
        <div style={{ width: `${seg(fail)}%`, backgroundColor: "var(--status-danger)" }} />
      ) : null}
    </div>
  );
}

type CategoryFilter = "all" | "ai" | "governance" | "cloud";

function categoryFor(id: string): "ai" | "governance" | "cloud" {
  if (id === "cis" || id === "cmmc" || id === "cis-foundations") return "cloud";
  if (
    id === "eu-ai-act" ||
    id === "nist-csf" ||
    id === "iso27001" ||
    id === "soc2" ||
    id === "nist-800-53" ||
    id === "pci-dss" ||
    id === "fedramp"
  )
    return "governance";
  return "ai";
}

// ─── Page ───────────────────────────────────────────────────────────────────

function CompliancePageContent() {
  const searchParams = useSearchParams();
  const queryParam = searchParams.get("q") ?? "";
  const scanParam = searchParams.get("scan") ?? "";
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
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");
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
  const hasAgent = data?.has_agent_context ?? false;

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
        controls: hasAgent ? data.owasp_agentic_top10 : [],
        catalog: OWASP_AGENTIC_TOP10,
        emptyMessage: "Agentic controls appear after a scan with agent context.",
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
      // Scored on every response and counted by the headline, previously shown
      // in no section. The API returns each control's code and name, so these
      // need no bundled catalog.
      {
        id: "nist-800-53",
        title: "NIST SP 800-53 Rev 5",
        subtitle: "Controls with mapped evidence",
        controls: data.nist_800_53,
        catalog: {},
        emptyMessage: undefined,
      },
      {
        id: "pci-dss",
        title: "PCI DSS 4.0",
        subtitle: "Requirements with mapped evidence",
        controls: data.pci_dss,
        catalog: {},
        emptyMessage: undefined,
      },
      {
        id: "fedramp",
        title: "FedRAMP Moderate",
        subtitle: "Baseline controls",
        controls: data.fedramp,
        catalog: {},
        emptyMessage: undefined,
      },
    ];
  }, [data, hasAgent, hasMcp]);

  const frameworks = useMemo(
    () => (data ? complianceFrameworkSummaries(data) : []),
    [data],
  );

  const visibleFrameworks = useMemo(
    () =>
      categoryFilter === "all"
        ? frameworks
        : frameworks.filter((framework) => categoryFor(framework.id) === categoryFilter),
    [frameworks, categoryFilter],
  );

  const selectedSection = useMemo(
    () => detailSections.find((section) => section.id === selectedFrameworkId) ?? detailSections[0],
    [detailSections, selectedFrameworkId],
  );

  const sectionCatalog = selectedSection?.catalog;

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
      api.getCompliance(scanParam),
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
  }, [scanParam]);

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

  // Scored rows only, which is the same basis as `evaluated_controls`: the two
  // reconcile by construction (ui/tests/compliance-reconciliation.test.ts).
  // Technique catalogs have no pass/fail to add, and the independently scored
  // NIST catalog rescores evidence these rows already counted.
  const { pass: totalPass, warn: totalWarn, fail: totalFail } = complianceScoredTotals(frameworks);
  const evaluatedFrameworks = frameworks.filter((f) => !f.disabled).length;
  const overallNotEvaluated = isNotEvaluated(data.overall_status);

  const kpis: StatStripItem[] = [
    {
      label: "Overall",
      value: overallNotEvaluated ? "—" : `${Math.round(data.overall_score)}%`,
      accent: statusToAccent(data.overall_status),
      // The score is a percentage of EVALUATED controls, so it always ships its
      // denominator. Without it, passing the handful of controls a scan can
      // actually evaluate renders as a bare "100% / Compliant" over an estate
      // that was almost entirely unmeasured.
      hint: overallNotEvaluated
        ? postureLabel(data.overall_status)
        : `${postureLabel(data.overall_status)} · ${data.evaluated_controls} of ${data.total_controls} controls evaluated`,
    },
    {
      label: "Frameworks",
      value: evaluatedFrameworks,
      hint: `${frameworks.length} tracked`,
    },
    {
      label: "Passing",
      value: totalPass,
      accent: "success",
      // Passing + Attention + Failing is exactly `evaluated_controls` above.
      // Say so, because the page also shows a NIST 800-53 catalog line scored
      // independently over the same evidence — a reader who adds it to these
      // gets a larger number than the headline and no way to tell which is
      // wrong.
      hint: "of the evaluated controls",
    },
    { label: "Attention", value: totalWarn, accent: "warn", accentThreshold: 0 },
    { label: "Failing", value: totalFail, accent: "critical", accentThreshold: 0 },
  ];

  // ── Frameworks master table ────────────────────────────────────────────────
  const frameworkColumns: DataTableColumn<ComplianceFrameworkSummary>[] = [
    {
      key: "label",
      header: "Framework",
      cell: (f) => (
        <div className="flex items-center gap-2">
          <FrameworkIcon frameworkId={f.id} size={18} />
          <div className="min-w-0">
            <div className="truncate font-medium text-[color:var(--foreground)]">{f.shortLabel}</div>
            <div className="truncate text-[11px] text-[color:var(--text-tertiary)]">{f.label}</div>
          </div>
        </div>
      ),
    },
    {
      key: "coverage",
      header: "Coverage",
      cell: (f) =>
        f.disabled ? (
          <span className="text-[11px] text-[color:var(--text-tertiary)]">
            {f.disabledReason ?? "Not evaluated"}
          </span>
        ) : f.kind === "applicability" ? (
          // A technique catalog reports which techniques the evidence puts in
          // play. Rendering that as a pass/fail bar would claim the estate
          // passed the ones nothing matched.
          <span className="text-[11px] text-[color:var(--text-tertiary)]">
            {f.applicable ?? 0} of {f.total} applicable
          </span>
        ) : (
          <div className="flex items-center gap-2">
            <CoverageBar pass={f.pass} warn={f.warn} fail={f.fail} total={f.total} />
            <span className="tabular-nums text-[11px] text-[color:var(--text-tertiary)]">
              {compliancePassRate(f)}%
            </span>
          </div>
        ),
    },
    {
      key: "fail",
      header: "Fail",
      align: "right",
      sortable: true,
      width: "4rem",
      cell: (f) =>
        f.kind === "applicability" ? (
          <span className="text-[color:var(--text-tertiary)]">—</span>
        ) : (
          <span
            className={
              f.fail > 0 ? "font-semibold text-[color:var(--status-danger)]" : "text-[color:var(--text-tertiary)]"
            }
          >
            {f.fail}
          </span>
        ),
    },
  ];

  const master = (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5">
        {(["all", "ai", "governance", "cloud"] as const).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => setCategoryFilter(value)}
            className={`rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
              categoryFilter === value
                ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
            }`}
          >
            {value === "ai" ? "AI" : value}
          </button>
        ))}
      </div>
      <DataTable
        rows={visibleFrameworks}
        rowKey={(f) => f.id}
        columns={frameworkColumns}
        selectedKey={selectedSection?.id}
        onRowClick={(f) => {
          if (f.disabled) return;
          // Benchmark rows are in the table because the headline counts them,
          // but their evidence has its own drill-down below rather than a
          // control list here. Selecting one would show a different framework's
          // controls under its name.
          if (!detailSections.some((section) => section.id === f.id)) return;
          setSelectedFrameworkId(f.id);
        }}
        maxHeight="calc(100vh - 22rem)"
        caption="Framework coverage"
        empty="No frameworks in this category."
        data-testid="compliance-frameworks-table"
      />
    </div>
  );

  // ── Controls detail table ──────────────────────────────────────────────────
  const controlColumns: DataTableColumn<ComplianceControl>[] = [
    {
      key: "code",
      header: "Control",
      cell: (c) => (
        <div className="min-w-0">
          <div className="font-mono text-xs font-medium text-[color:var(--foreground)]">{c.code}</div>
          <div className="truncate text-[11px] text-[color:var(--text-tertiary)]">
            {sectionCatalog?.[c.code] ?? c.name}
          </div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "9rem",
      cell: (c) => {
        // Surface the provenance behind an unscored control: instead of a bare
        // "Not evaluated", show WHY (e.g. "No completed scan"). The full CTA
        // lives in the drawer; here it's a dense, honest one-liner.
        const reason = isControlUnscored(c.status) ? evidenceReasonLabel(c.evidence_reason) : null;
        return (
          <div className="min-w-0">
            <span className="inline-flex items-center gap-1.5">
              <StatusIcon status={c.status} className="h-3.5 w-3.5" />
              <span className={`text-xs font-medium ${statusColor(c.status)}`}>
                {controlStatusLabel(c.status)}
              </span>
            </span>
            {reason ? (
              <span
                className="mt-0.5 block truncate text-[10px] text-[color:var(--text-tertiary)]"
                title={reason}
                data-testid="control-evidence-reason"
              >
                {reason}
              </span>
            ) : null}
          </div>
        );
      },
    },
    {
      key: "findings",
      header: "Findings",
      align: "right",
      width: "5rem",
      cell: (c) =>
        c.findings > 0 ? (
          // Drill a non-zero count into the findings queue, scoped to this
          // control's framework + control id. stopPropagation keeps the row
          // click (which opens the evidence drawer) from also firing.
          <Link
            href={`/findings?framework=${encodeURIComponent(selectedSection?.id ?? "")}&control=${encodeURIComponent(c.code)}`}
            onClick={(e) => e.stopPropagation()}
            aria-label={`View ${c.findings} findings for ${c.code}`}
            className="font-semibold text-[color:var(--accent)] underline-offset-2 hover:underline focus-visible:underline focus-visible:outline-none"
          >
            {c.findings}
          </Link>
        ) : (
          <span className="text-[color:var(--text-tertiary)]">{c.findings}</span>
        ),
    },
  ];

  const detail = selectedSection ? (
    <div className="flex h-full min-h-0 flex-col rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] elev-1">
      <div className="border-b border-[color:var(--border-subtle)] p-4">
        <div className="flex items-center gap-2">
          <FrameworkIcon frameworkId={selectedSection.id} size={22} />
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
        <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative min-w-0 flex-1">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[color:var(--text-tertiary)]" />
            <input
              type="text"
              value={controlQuery}
              onChange={(e) => setControlQuery(e.target.value)}
              placeholder="Search control, package, agent"
              className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] py-2 pl-9 pr-3 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5">
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
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {selectedSection.controls.length === 0 && selectedSection.emptyMessage ? (
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-5 text-sm text-[color:var(--text-tertiary)]">
            {selectedSection.emptyMessage}
          </div>
        ) : (
          <DataTable
            rows={visibleControls}
            rowKey={(c) => c.code}
            columns={controlColumns}
            onRowClick={(control) =>
              setSelectedControl({
                control,
                frameworkLabel: selectedSection.title,
                catalog: selectedSection.catalog,
              })
            }
            selectedKey={selectedControl?.control.code}
            caption={`${selectedSection.title} controls`}
            empty="No controls match the current filters."
          />
        )}
      </div>
    </div>
  ) : null;

  return (
    <div className="space-y-5">
      {/* ── Trust center header ─────────────────────────────────────────── */}
      <div className="flex flex-col gap-3 rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 elev-1 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[color:var(--text-tertiary)]">
            Trust center
          </p>
          <h1 className={`text-xl font-bold ${statusColor(data.overall_status)}`}>
            {postureLabel(data.overall_status)}
          </h1>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[color:var(--text-tertiary)]">
            <span>
              {data.scan_count} scan{data.scan_count !== 1 ? "s" : ""} analyzed
            </span>
            {data.latest_scan ? <span>Latest {formatDate(data.latest_scan)}</span> : null}
            <span>{totalFail} failing controls</span>
          </div>
          <p
            className="mt-2 max-w-3xl text-xs leading-relaxed text-[color:var(--text-secondary)]"
            data-testid="compliance-helper-disclaimer"
          >
            Curated evidence helper for AI/MCP/agent risk — not a certification, audit opinion, or complete
            control catalog. Validate mapped controls against your environment and auditor scope.
          </p>
        </div>
        <button
          onClick={() => void handleExportPack()}
          disabled={exporting}
          title="Download a signed evidence pack covering every framework"
          className="flex shrink-0 items-center gap-1.5 self-start rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-2 text-sm font-medium text-[color:var(--accent)] transition-colors hover:bg-[color:var(--accent-soft-hover)] disabled:opacity-50"
          data-testid="compliance-export-pack"
        >
          {exporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
          {exporting ? "Exporting…" : "Export pack"}
        </button>
      </div>
      {exportError ? (
        <p className="text-right text-xs text-[color:var(--status-danger)]">{exportError}</p>
      ) : null}

      <StatStrip items={kpis} data-testid="compliance-kpi-strip" />

      {/* ── View Toggle ────────────────────────────────────────────────── */}
      <div className="flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5 self-start w-fit">
        {(
          [
            { key: "detail", label: "Detail", icon: List },
            { key: "heatmap", label: "Heatmap", icon: Grid3X3 },
            { key: "matrix", label: "Matrix", icon: Scan },
          ] as const
        ).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            type="button"
            onClick={() => setViewMode(key)}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === key
                ? "bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
            }`}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {viewMode === "heatmap" && <ComplianceHeatmap data={data} />}
      {viewMode === "matrix" && (
        <ComplianceMatrix
          data={data}
          onSelectControl={(selection) => setSelectedControl(selection)}
        />
      )}

      {viewMode === "detail" ? (
        <>
          <SplitLayout
            masterWidth="24rem"
            height="calc(100vh - 20rem)"
            master={master}
            detail={detail}
            placeholder="Select a framework to review its controls and evidence."
            data-testid="compliance-split"
          />

          <ComplianceNistCatalog />

          <Collapsible
            title="Cloud CIS benchmark drill-down"
            subtitle="AWS / Azure / GCP / Snowflake / Databricks"
            icon={Scan}
            defaultOpen={false}
          >
            <CISBenchmarkDetail />
          </Collapsible>

          {(hubPosture && hubPosture.totals.combined > 0) || mitreCatalog || atlasCatalog ? (
            <Collapsible title="Operator & catalog context" defaultOpen={false}>
              <div className="space-y-3 text-xs text-[color:var(--text-tertiary)]">
                {hubPosture && hubPosture.totals.combined > 0 ? (
                  <p>
                    Compliance hub: {hubPosture.totals.combined.toLocaleString()} findings (
                    {hubPosture.totals.native.toLocaleString()} native ·{" "}
                    {hubPosture.totals.hub.toLocaleString()} ingested). Import via{" "}
                    <code className="rounded bg-[color:var(--surface-muted)] px-1 py-0.5">
                      POST /v1/compliance/ingest
                    </code>
                    .
                  </p>
                ) : null}
                {mitreCatalog ? (
                  <p>
                    MITRE ATT&CK {mitreCatalog.attack_version || "catalog"} ·{" "}
                    {mitreCatalog.technique_count} techniques · refresh with{" "}
                    <code className="rounded bg-[color:var(--surface-muted)] px-1 py-0.5">
                      agent-bom db update-frameworks
                    </code>
                    .
                  </p>
                ) : null}
                {atlasCatalog ? (
                  <p>
                    MITRE ATLAS {atlasCatalog.atlas_version || "catalog"} ·{" "}
                    {atlasCatalog.technique_count} techniques · refresh with{" "}
                    <code className="rounded bg-[color:var(--surface-muted)] px-1 py-0.5">
                      agent-bom db update-frameworks --framework atlas
                    </code>
                    .
                  </p>
                ) : null}
              </div>
            </Collapsible>
          ) : null}
        </>
      ) : null}

      {selectedControl ? (
        <ComplianceControlDrawer
          control={selectedControl.control}
          frameworkLabel={selectedControl.frameworkLabel}
          catalogName={selectedControl.catalog?.[selectedControl.control.code]}
          onClose={() => setSelectedControl(null)}
        />
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
