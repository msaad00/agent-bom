"use client";

import { Suspense, useCallback, useEffect, useState, useMemo, useRef } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  api,
  Vulnerability,
  UnifiedFinding,
  type FindingTriageDecision,
  type FindingTriageItem,
  type FindingTriageJustification,
  type ReadWindow,
} from "@/lib/api";
import type { FindingFacets } from "@/lib/api-types";
import { ApiOfflineState } from "@/components/api-offline-state";
import { FindingDrawer } from "@/components/finding-drawer";
import { FindingsQueueTable } from "@/components/findings-queue";
import { PaginationBar } from "@/components/pagination-bar";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { FIRST_SCAN_ACTIONS } from "@/lib/empty-state-actions";
import {
  type EnrichedVuln,
  type SeverityFilter,
  type SortKey,
  uniqueStrings,
  serverFindingsSort,
  formatFindingsTotal,
  vulnRowKey,
} from "@/lib/findings-view";
import {
  ISSUE_TYPE_FILTERS,
  type IssueTypeFilter,
} from "@/lib/finding-issue-type";
import {
  findingsPageSubtitle,
  findingsQueueDetail,
  findingsQueueTitle,
  findingsSearchPlaceholder,
} from "@/lib/findings-lens";
import { useFindingsLens } from "@/hooks/use-findings-lens";
import { Bug, Loader2, ClipboardCheck, SlidersHorizontal, X } from "lucide-react";
import { PageLaneHeader } from "@/components/page-lane";
import {
  buildComplianceMetrics,
  buildEngineeringMetrics,
  findingTriageKey,
} from "@/lib/findings-workspace";

function _classifyApiErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}



function triageKey(vulnerabilityId: string, packageName: string) {
  return findingTriageKey(vulnerabilityId, packageName);
}

function recordString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function recordNumber(record: Record<string, unknown>, key: string): number | undefined {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function recordStrings(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && Boolean(item.trim()));
}

function normalizedSeverity(value: string | undefined): Vulnerability["severity"] {
  const normalized = (value ?? "").toLowerCase();
  return normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low" || normalized === "none"
    ? normalized
    : "none";
}


function collectUnifiedFindings(findings: UnifiedFinding[]): EnrichedVuln[] {
  return findings.map((finding): EnrichedVuln => {
    const raw = finding as UnifiedFinding & {
      framework_tags?: string[];
      phantom_tools?: string[];
      runtime_evidence?: EnrichedVuln["runtime_evidence"];
      workload_runtime_evidence?: EnrichedVuln["workload_runtime_evidence"];
      effective_reach_band?: string;
      effective_reach_score?: number;
      attack_vector_summary?: string;
    };
    const assetName = finding.asset?.name?.trim() || finding.asset?.identifier || finding.asset?.stable_id || "asset";
    const findingLabel = finding.cve_id || finding.title || finding.id;
    const sourceLabel = uniqueStrings([finding.source, finding.finding_type, ...(finding.scan_sources ?? [])]);
    const evidence = finding.evidence ?? {};
    const references = uniqueStrings([
      ...(finding.references ?? []),
      ...recordStrings(evidence, "references"),
    ]);
    const advisorySources = uniqueStrings([
      ...(finding.advisory_sources ?? []),
      ...recordStrings(evidence, "advisory_sources"),
    ]);
    return {
      id: findingLabel,
      finding_id: finding.id,
      node_id: finding.node_id ?? undefined,
      finding_node_id: finding.finding_node_id ?? undefined,
      entity_type: finding.entity_type ?? undefined,
      asset_type: finding.asset?.asset_type ?? undefined,
      severity: normalizedSeverity(finding.effective_severity ?? finding.severity),
      summary: raw.attack_vector_summary ?? finding.title ?? finding.description,
      description: finding.description ?? finding.title,
      references,
      advisory_sources: advisorySources,
      aliases: uniqueStrings([
        ...(finding.aliases ?? []),
        ...(finding.advisory_aliases ?? []),
        ...recordStrings(evidence, "advisory_aliases"),
      ]),
      cvss_score: finding.cvss_score ?? undefined,
      cvss_vector: finding.cvss_vector ?? recordString(evidence, "cvss_vector"),
      cvss_severity: finding.cvss_severity ?? undefined,
      epss_score: finding.epss_score ?? undefined,
      epss_percentile: finding.epss_percentile ?? recordNumber(evidence, "epss_percentile"),
      is_kev: typeof finding.is_kev === "boolean" ? finding.is_kev : undefined,
      cisa_kev: typeof finding.is_kev === "boolean" ? finding.is_kev : undefined,
      kev_date_added: finding.kev_date_added ?? recordString(evidence, "kev_date_added"),
      kev_due_date: finding.kev_due_date ?? recordString(evidence, "kev_due_date"),
      fixed_version: finding.fixed_version ?? undefined,
      current_version:
        finding.package_version ??
        recordString(evidence, "package_version"),
      published_at: finding.published_at ?? recordString(evidence, "published_at"),
      modified_at: finding.modified_at ?? recordString(evidence, "modified_at"),
      severity_source: finding.severity_source ?? recordString(evidence, "severity_source"),
      confidence: finding.confidence ?? recordNumber(evidence, "confidence"),
      match_confidence_tier:
        finding.match_confidence_tier ?? recordString(evidence, "match_confidence_tier"),
      packages: [assetName],
      agents: finding.affected_agents ?? [],
      sources: sourceLabel.length > 0 ? sourceLabel : ["finding"],
      affected_servers: finding.affected_servers ?? [],
      exposed_credentials: finding.exposed_credentials ?? [],
      reachable_tools: finding.exposed_tools ?? [],
      phantom_tools: raw.phantom_tools ?? [],
      framework_tags: raw.framework_tags ?? finding.compliance_tags ?? [],
      controls: finding.controls ?? [],
      attack_vector_summary: raw.attack_vector_summary ?? (finding.network_exploitable ? "Network exploitable" : undefined),
      impact_category: finding.impact_category ?? finding.finding_type,
      finding_type: finding.finding_type,
      finding_class: finding.finding_class,
      risk_score: finding.risk_score,
      effective_reach_band: raw.effective_reach_band,
      effective_reach_score: raw.effective_reach_score,
      runtime_evidence: raw.runtime_evidence,
      workload_runtime_evidence: raw.workload_runtime_evidence ?? finding.workload_runtime_evidence,
      remediation_items: finding.remediation_guidance
        ? [
            {
              package: assetName,
              ecosystem: finding.asset?.asset_type ?? finding.finding_type ?? "finding",
              current_version: "",
              fixed_version: finding.fixed_version ?? null,
              action: "review",
              command: null,
              verify_command: null,
              references: [],
              risk_narrative: finding.remediation_guidance,
            },
          ]
        : [],
      graph_reachable: null,
      graph_min_hop_distance: null,
      lifecycle_status: finding.status ?? undefined,
      first_seen: finding.first_seen ?? undefined,
      last_seen: finding.last_seen ?? undefined,
      resolved_at: finding.resolved_at ?? undefined,
      reopened_at: finding.reopened_at ?? undefined,
      scan_count: finding.scan_count,
      last_observed: finding.last_observed ?? finding.last_seen ?? undefined,
      occurrence_count: finding.occurrence_count ?? finding.scan_count,
      remediation_versions: finding.remediation_versions ?? undefined,
      provenance: finding.provenance ?? undefined,
      owner: finding.owner ?? undefined,
      sla_due_at: finding.sla_due_at ?? undefined,
      scan_id: finding.scan_id,
    };
  });
}


// Security-domain facets (issue #3946). Map 1:1 to the overview coverage lanes
// so drilling from a coverage lane lands on the matching findings filter.
const DOMAIN_FILTERS: { key: string; label: string }[] = [
  { key: "all", label: "All domains" },
  { key: "cspm", label: "CSPM" },
  { key: "vuln", label: "Vuln mgmt" },
  { key: "aspm", label: "ASPM" },
  { key: "dspm", label: "DSPM" },
  { key: "aispm", label: "AISPM" },
];

const PROVIDER_OPTIONS = ["aws", "azure", "gcp", "snowflake", "databricks"];

// Default read-window (#4009): findings default to the last ~90 days so counts
// are honestly scoped, with an explicit widen-to-all option.
const DEFAULT_FINDINGS_WINDOW_DAYS = 90;
const WINDOW_OPTIONS: { value: number; label: string }[] = [
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
  { value: 365, label: "Last 12 months" },
  { value: 0, label: "All time" },
];

export default function FindingsPageWrapper() {
  return (
    <Suspense fallback={
      <PageLoadingState
        title="Loading findings"
        detail="Preparing scan summaries and vulnerability evidence for the findings view."
      />
    }>
      <FindingsPage />
    </Suspense>
  );
}

function FindingsPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const paramSeverity = searchParams.get("severity");
  const paramCve = searchParams.get("cve");
  const paramAgent = searchParams.get("agent");
  const paramQuery = searchParams.get("q");
  const paramPage = searchParams.get("page");
  const paramScan = searchParams.get("scan") ?? searchParams.get("scan_id");
  const paramIssueType = searchParams.get("issue");
  const paramLens = searchParams.get("lens");
  const paramWindow = searchParams.get("window");
  const paramScope = searchParams.get("scope");
  // First-class scope + taxonomy facets (issue #3946), URL-synced.
  const paramDomain = searchParams.get("domain");
  const paramProvider = searchParams.get("provider");
  const paramAccount = searchParams.get("account");
  const paramEnvironment = searchParams.get("environment");
  const { lens, selectLens, lenses, label: lensLabel, hint: lensHint } = useFindingsLens(paramLens);

  const [vulns, setVulns] = useState<EnrichedVuln[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");
  // Per #2199 splash-kind sweep: track auth/forbidden/network so the splash
  // matches the actual cause instead of always reading as a connect failure.
  const [errorKind, setErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [filter, setFilter] = useState<SeverityFilter>(
    paramSeverity && ["critical", "high", "medium", "low"].includes(paramSeverity)
      ? (paramSeverity as SeverityFilter)
      : "all"
  );
  const [issueTypeFilter, setIssueTypeFilter] = useState<IssueTypeFilter>(() => {
    if (paramIssueType && ISSUE_TYPE_FILTERS.some((entry) => entry.key === paramIssueType)) {
      return paramIssueType as IssueTypeFilter;
    }
    return "all";
  });
  const [domainFilter, setDomainFilter] = useState<string>(
    paramDomain && DOMAIN_FILTERS.some((d) => d.key === paramDomain) ? paramDomain : "all",
  );
  const [providerFilter, setProviderFilter] = useState<string>(paramProvider ?? "");
  const [accountFilter, setAccountFilter] = useState<string>(paramAccount ?? "");
  const [environmentFilter, setEnvironmentFilter] = useState<string>(paramEnvironment ?? "");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  // Default read-window (#4009): findings default to the last ~90 days so the
  // count is honestly "last 90d", not "all". ``0`` widens to all history.
  const [windowDays, setWindowDays] = useState<number>(() => {
    const parsed = Number(paramWindow);
    return paramWindow != null && Number.isFinite(parsed) && parsed >= 0
      ? Math.floor(parsed)
      : DEFAULT_FINDINGS_WINDOW_DAYS;
  });
  const [appliedWindow, setAppliedWindow] = useState<ReadWindow | null>(null);
  const [search, setSearch] = useState(paramQuery ?? paramCve ?? paramAgent ?? "");
  const [suppressed, setSuppressed] = useState<Set<string>>(new Set());
  const [triageRows, setTriageRows] = useState<FindingTriageItem[]>([]);
  const [triageError, setTriageError] = useState("");
  const [triageBusyKey, setTriageBusyKey] = useState<string | null>(null);
  const [vexExporting, setVexExporting] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(paramCve ?? null);
  const [page, setPage] = useState(() => {
    const parsed = Number(paramPage ?? "1");
    return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 1;
  });
  const [findingsTotal, setFindingsTotal] = useState<number | null>(0);
  const [findingsTotalApproximate, setFindingsTotalApproximate] = useState(false);
  const [findingFacets, setFindingFacets] = useState<FindingFacets | null>(null);
  const [findingFacetsApproximate, setFindingFacetsApproximate] = useState(false);
  const [hasMoreFindings, setHasMoreFindings] = useState(false);
  const [nextFindingsCursor, setNextFindingsCursor] = useState("");
  const [pageCursors, setPageCursors] = useState<string[]>([""]);
  const PAGE_SIZE = 25;
  // Advanced-filter popover (scope / domain / cloud scope) — kept behind a
  // single "Filters (n)" control so the primary toolbar stays compact.
  const [filtersOpen, setFiltersOpen] = useState(false);
  const filtersRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!filtersOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFiltersOpen(false);
    };
    const onPointer = (e: MouseEvent) => {
      if (filtersRef.current && !filtersRef.current.contains(e.target as Node)) {
        setFiltersOpen(false);
      }
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onPointer);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onPointer);
    };
  }, [filtersOpen]);

  // URL-as-source-of-truth: when the query string changes (link, back/forward),
  // re-sync the derived filter state so the view matches the address bar instead
  // of staying frozen at the values captured on first mount. Local control
  // changes don't write to the URL, so these effects only fire on navigation.
  useEffect(() => {
    setFilter(
      paramSeverity && ["critical", "high", "medium", "low"].includes(paramSeverity)
        ? (paramSeverity as SeverityFilter)
        : "all",
    );
  }, [paramSeverity]);

  useEffect(() => {
    setSearch(paramQuery ?? paramCve ?? paramAgent ?? "");
  }, [paramQuery, paramCve, paramAgent]);

  useEffect(() => {
    const parsed = Number(paramPage ?? "1");
    setPage(Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 1);
  }, [paramPage]);

  useEffect(() => {
    if (paramCve) setSelectedId(paramCve);
  }, [paramCve]);

  useEffect(() => {
    if (paramIssueType && ISSUE_TYPE_FILTERS.some((entry) => entry.key === paramIssueType)) {
      setIssueTypeFilter(paramIssueType as IssueTypeFilter);
    } else {
      setIssueTypeFilter("all");
    }
  }, [paramIssueType]);

  useEffect(() => {
    setDomainFilter(paramDomain && DOMAIN_FILTERS.some((d) => d.key === paramDomain) ? paramDomain : "all");
  }, [paramDomain]);

  useEffect(() => {
    setProviderFilter(paramProvider ?? "");
  }, [paramProvider]);

  useEffect(() => {
    setAccountFilter(paramAccount ?? "");
  }, [paramAccount]);

  useEffect(() => {
    setEnvironmentFilter(paramEnvironment ?? "");
  }, [paramEnvironment]);

  useEffect(() => {
    const parsed = Number(paramWindow);
    setWindowDays(
      paramWindow != null && Number.isFinite(parsed) && parsed >= 0
        ? Math.floor(parsed)
        : DEFAULT_FINDINGS_WINDOW_DAYS,
    );
  }, [paramWindow]);

  useEffect(() => {
    const params = new URLSearchParams();
    // `scope=all` is an explicit cross-scan contract used by Overview and
    // other posture deep links. Preserve it while synchronizing page-local
    // controls so navigation does not silently narrow or rewrite that scope.
    if (paramScope === "all") params.set("scope", "all");
    if (filter !== "all") params.set("severity", filter);
    if (issueTypeFilter !== "all") params.set("issue", issueTypeFilter);
    if (lens !== "ops") params.set("lens", lens);
    if (search.trim()) params.set("q", search.trim());
    if (domainFilter !== "all") params.set("domain", domainFilter);
    if (providerFilter.trim()) params.set("provider", providerFilter.trim());
    if (accountFilter.trim()) params.set("account", accountFilter.trim());
    if (environmentFilter.trim()) params.set("environment", environmentFilter.trim());
    if (windowDays !== DEFAULT_FINDINGS_WINDOW_DAYS) params.set("window", String(windowDays));
    if (page > 1) params.set("page", String(page));
    if (paramScan) params.set("scan", paramScan);
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [
    filter,
    issueTypeFilter,
    lens,
    search,
    domainFilter,
    providerFilter,
    accountFilter,
    environmentFilter,
    windowDays,
    page,
    paramScope,
    paramScan,
    pathname,
    router,
  ]);

  const handleMarkFP = useCallback(async (vulnId: string, packageName: string) => {
    try {
      await api.createException({
        vulnerability_id: vulnId,
        package_name: packageName,
        reason: "false_positive",
      });
      setSuppressed((prev) => new Set(prev).add(vulnId));
    } catch {
      // silently fail — button stays visible for retry
    }
  }, []);

  const refreshTriage = useCallback(async () => {
    try {
      const response = await api.listFindingTriage({ limit: 1000 });
      setTriageRows(response.triage);
      setTriageError("");
    } catch (e: unknown) {
      if (e instanceof ApiAuthError || e instanceof ApiForbiddenError) {
        setTriageError("Sign in with a write-capable role (analyst/admin) to load triage — used by engineering and GRC.");
      } else {
        setTriageError(e instanceof Error ? e.message : "Unable to load finding triage queue.");
      }
    }
  }, []);

  const handleTriageDecision = useCallback(async (
    vuln: EnrichedVuln,
    decision: FindingTriageDecision,
    justification?: FindingTriageJustification,
  ) => {
    const packageName = vuln.packages[0] ?? "*";
    const key = triageKey(vuln.id, packageName);
    setTriageBusyKey(key);
    setTriageError("");
    const decisionReason =
      decision === "not_affected"
        ? "Reviewed from Findings: vulnerable code is not in the executable path for this deployment."
        : decision === "affected"
          ? "Reviewed from Findings: finding remains applicable to this deployment."
          : "Queued from Findings for investigation (engineering or GRC disposition).";
    try {
      const existing = triageRows.find((row) => triageKey(row.vulnerability_id, row.package) === key);
      if (existing && decision !== "under_investigation") {
        const updated = await api.updateFindingTriageDecision(existing.id, {
          decision,
          justification,
          decision_reason: decisionReason,
        });
        setTriageRows((rows) => rows.map((row) => (row.id === updated.id ? updated : row)));
      } else if (!existing) {
        const created = await api.createFindingTriage({
          vulnerability_id: vuln.id,
          package: packageName,
          queue_state: decision === "under_investigation" ? "assigned" : "decided",
          decision,
          justification,
          decision_reason: decisionReason,
        });
        setTriageRows((rows) => [created, ...rows]);
      }
    } catch (e: unknown) {
      if (e instanceof ApiAuthError || e instanceof ApiForbiddenError) {
        setTriageError("Sign in with a write-capable role (analyst/admin) to record triage — shared by engineering and GRC.");
      } else {
        setTriageError(e instanceof Error ? e.message : "Unable to record triage decision.");
      }
    } finally {
      setTriageBusyKey(null);
    }
  }, [triageRows]);

  const handleExportVex = useCallback(async () => {
    setVexExporting(true);
    setTriageError("");
    try {
      const exported = await api.exportFindingTriageVex();
      downloadJson(exported, `finding-triage-openvex-${new Date().toISOString().slice(0, 10)}.json`);
    } catch (e: unknown) {
      if (e instanceof ApiAuthError || e instanceof ApiForbiddenError) {
        setTriageError("Sign in with a write-capable role (analyst/admin) to export OpenVEX — used for trust attestations.");
      } else {
        setTriageError(e instanceof Error ? e.message : "Unable to export signed VEX evidence.");
      }
    } finally {
      setVexExporting(false);
    }
  }, []);

  useEffect(() => {
    void refreshTriage();
  }, [refreshTriage]);

  useEffect(() => {
    async function loadFindings() {
      setDetailLoading(true);
      setError("");
      try {
        const currentCursor = pageCursors[page - 1] || undefined;
        const response = await api.listFindings({
          ...(paramScan ? { scanId: paramScan } : {}),
          ...(search.trim() ? { query: search.trim() } : {}),
          ...(filter !== "all" ? { severity: filter } : {}),
          ...(domainFilter !== "all" ? { domain: domainFilter } : {}),
          ...(providerFilter.trim() ? { provider: providerFilter.trim() } : {}),
          ...(accountFilter.trim() ? { account: accountFilter.trim() } : {}),
          ...(environmentFilter.trim() ? { environment: environmentFilter.trim() } : {}),
          ...(issueTypeFilter !== "all" ? { findingClass: issueTypeFilter } : {}),
          sort: serverFindingsSort(sortKey),
          limit: PAGE_SIZE,
          ...(!currentCursor ? { offset: (page - 1) * PAGE_SIZE } : {}),
          ...(currentCursor ? { cursor: currentCursor } : {}),
          approximateTotal: true,
          includeFacets: true,
          windowDays,
        });
        setAppliedWindow(response.window ?? null);
        setVulns(collectUnifiedFindings(response.findings));
        setFindingsTotal(typeof response.total === "number" ? response.total : null);
        setFindingsTotalApproximate(Boolean(response.total_approximate));
        setFindingFacets(response.facets ?? null);
        setFindingFacetsApproximate(Boolean(response.facets_approximate));
        setHasMoreFindings(Boolean(response.has_more || response.next_cursor));
        setNextFindingsCursor(response.next_cursor ?? "");
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load");
        setErrorKind(_classifyApiErrorKind(e));
      } finally {
        setLoading(false);
        setDetailLoading(false);
      }
    }

    void loadFindings();
  }, [
    paramScan,
    search,
    page,
    filter,
    domainFilter,
    providerFilter,
    accountFilter,
    environmentFilter,
    issueTypeFilter,
    windowDays,
    sortKey,
    pageCursors,
  ]);

  function handleSort(field: SortKey) {
    setSortKey(field);
    setSortDir("desc");
  }

  const triageByKey = useMemo(() => {
    const rows = new Map<string, FindingTriageItem>();
    for (const row of triageRows) {
      rows.set(triageKey(row.vulnerability_id, row.package), row);
    }
    return rows;
  }, [triageRows]);

  const displayed = vulns;

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
    setPageCursors((existing) =>
      existing.length === 1 && existing[0] === "" ? existing : [""],
    );
    setNextFindingsCursor("");
  }, [
    filter,
    issueTypeFilter,
    search,
    sortKey,
    sortDir,
    paramScan,
    domainFilter,
    providerFilter,
    accountFilter,
    environmentFilter,
    windowDays,
  ]);

  const totalPages = findingsTotal == null
    ? null
    : Math.max(1, Math.ceil(findingsTotal / PAGE_SIZE));
  const selectedVuln = useMemo(
    () =>
      displayed.find((vuln) => vulnRowKey(vuln) === selectedId || vuln.id === selectedId) ??
      vulns.find((vuln) => vulnRowKey(vuln) === selectedId || vuln.id === selectedId) ??
      null,
    [displayed, selectedId, vulns],
  );
  const vexEligibleCount = triageRows.filter((row) => row.vex_eligible).length;

  const workspaceMetrics = useMemo(
    () =>
      lens === "trust"
        ? buildComplianceMetrics(vulns, triageByKey, findingFacets, findingFacetsApproximate)
        : buildEngineeringMetrics(vulns, triageByKey, findingFacets, findingFacetsApproximate),
    [findingFacets, findingFacetsApproximate, lens, triageByKey, vulns],
  );

  const findingsTotalLabel = findingsTotal == null
    ? "Total unavailable"
    : formatFindingsTotal(findingsTotal, findingsTotalApproximate);
  const findingsFilterTotalLabel = findingsTotal == null ? "unknown total" : findingsTotalLabel;
  const findingsWindowLabel = appliedWindow?.label ??
    WINDOW_OPTIONS.find((option) => option.value === windowDays)?.label ??
    "Last 90 days";

  // Advanced filters live behind the "Filters (n)" popover. ``n`` counts the
  // non-default ones; each active filter is also surfaced as a removable chip so
  // state stays visible without opening the panel. Clearing a chip resets the
  // filter to its default, which the URL-sync effect drops from the query string.
  const domainFilterLabel = DOMAIN_FILTERS.find((d) => d.key === domainFilter)?.label ?? domainFilter;
  const activeFilterChips: { key: string; label: string; onClear: () => void }[] = [
    domainFilter !== "all"
      ? { key: "domain", label: `Domain: ${domainFilterLabel}`, onClear: () => setDomainFilter("all") }
      : null,
    providerFilter.trim()
      ? { key: "provider", label: `Cloud: ${providerFilter.trim().toUpperCase()}`, onClear: () => setProviderFilter("") }
      : null,
    accountFilter.trim()
      ? { key: "account", label: `Account: ${accountFilter.trim()}`, onClear: () => setAccountFilter("") }
      : null,
    environmentFilter.trim()
      ? { key: "environment", label: `Env: ${environmentFilter.trim()}`, onClear: () => setEnvironmentFilter("") }
      : null,
  ].filter((chip): chip is { key: string; label: string; onClear: () => void } => chip !== null);
  const activeFilterCount = activeFilterChips.length;
  const clearAdvancedFilters = () => {
    setDomainFilter("all");
    setProviderFilter("");
    setAccountFilter("");
    setEnvironmentFilter("");
  };

  const FILTERS: { key: SeverityFilter; label: string; color: string }[] = [
    {
      key: "all",
      label: `All (${findingsFilterTotalLabel})`,
      color: "text-[var(--text-secondary)]",
    },
    { key: "critical", label: `Critical${findingFacets ? ` (${findingFacets.severity.critical})` : ""}`, color: "text-red-400" },
    { key: "high", label: `High${findingFacets ? ` (${findingFacets.severity.high})` : ""}`, color: "text-orange-400" },
    { key: "medium", label: `Medium${findingFacets ? ` (${findingFacets.severity.medium})` : ""}`, color: "text-yellow-400" },
    { key: "low", label: `Low${findingFacets ? ` (${findingFacets.severity.low})` : ""}`, color: "text-blue-400" },
  ];

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="command"
        title="Findings"
        subtitle={findingsPageSubtitle(
          lens,
          `${findingsTotalLabel}${findingsTotal == null ? "" : " findings"}`,
          paramScan
            ? `from scan ${paramScan.slice(0, 8)}.`
            : `current state across completed scans · ${findingsWindowLabel}.`,
        )}
        scopeChip={
          <span className="inline-flex items-center rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-0.5 text-[11px] font-medium text-cyan-700 dark:text-cyan-200">
            {paramScan ? `Scan ${paramScan.slice(0, 8)}` : `Current state · ${findingsWindowLabel}`}
          </span>
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div
              className="flex rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5"
              role="group"
              aria-label="Findings altitude"
            >
              {lenses.map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => selectLens(value)}
                  className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition ${
                    lens === value
                      ? "bg-[color:var(--surface)] text-[color:var(--foreground)] shadow-sm"
                      : "text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
                  }`}
                >
                  {lensLabel(value)}
                </button>
              ))}
            </div>
            {vulns.length > 0 ? (
              <>
                <button
                  onClick={handleExportVex}
                  disabled={vexExporting || vexEligibleCount === 0}
                  className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-900 bg-emerald-500/10 dark:bg-emerald-950/40 px-3 py-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-300 transition-colors hover:bg-emerald-500/10 dark:hover:bg-emerald-950/70 disabled:cursor-not-allowed disabled:opacity-50"
                  title={
                    vexEligibleCount > 0
                      ? "Export signed OpenVEX JSON for findings triaged as not_affected"
                      : "Mark a finding not_affected with justification to enable OpenVEX export"
                  }
                >
                  {vexExporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ClipboardCheck className="h-3.5 w-3.5" />}
                  Export OpenVEX
                </button>
              </>
            ) : null}
          </div>
        }
      />
      <p className="text-xs text-[color:var(--text-tertiary)]">{lensHint}</p>

      {triageError && (
        <div className="rounded-lg border border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/20 px-3 py-2 text-sm text-amber-700 dark:text-amber-200">
          {triageError}
        </div>
      )}

      {loading && (
        <PageLoadingState
          title="Loading findings"
          detail="Fetching the canonical finding queue, facets, and observation evidence."
          data-testid="findings-loading-state"
        />
      )}
      {!loading && detailLoading && vulns.length === 0 && (
        <PageLoadingState
          title="Refreshing findings"
          detail="Applying server-backed filters and loading the next evidence page."
        />
      )}
      {!loading && error && (
        <ApiOfflineState
          title={errorKind === "network" ? "Findings need the agent-bom API" : undefined}
          detail={error}
          kind={errorKind}
        />
      )}

      {!loading && !error && vulns.length === 0 && (
        <PageEmptyState
          title="No findings found"
          detail="Run a scan or connect a cloud account to populate CVE, cloud posture, graph, and remediation evidence."
          icon={Bug}
          suggestions={[
            "Start with the offline demo if you want predictable sample data.",
            "Run a project scan with graph output to connect findings to packages and agents.",
            "Use the current-state queue or open a specific scan from Jobs.",
          ]}
          command="agent-bom agents --demo --offline"
          actions={FIRST_SCAN_ACTIONS}
          data-testid="findings-empty-state"
        />
      )}

      {!error && vulns.length > 0 && (
        <>
          <section
            aria-label={`${lensLabel(lens)} findings summary`}
            data-testid="findings-workspace-summary"
            className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4"
          >
            {workspaceMetrics.map((metric) => (
              <div
                key={metric.label}
                className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]">
                    {metric.label}
                  </span>
                  <span className="rounded-full border border-[var(--border-subtle)] px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-[var(--text-tertiary)]">
                    {metric.scope === "query" ? "Whole query" : "Current page"}
                  </span>
                </div>
                <p className={`mt-1 text-sm font-semibold ${metric.unavailable ? "text-[var(--text-tertiary)]" : "text-[var(--foreground)]"}`}>
                  {metric.value}
                </p>
                <p className="mt-0.5 text-[11px] text-[var(--text-tertiary)]">{metric.detail}</p>
              </div>
            ))}
          </section>

          {/* Controls — compact toolbar; advanced facets live behind a single
              "Filters (n)" popover with removable active-filter chips. */}
          <div className="flex flex-col gap-3">
            {/* One-line queue caption (verbose explainer moved to the title tooltip). */}
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="flex flex-wrap items-center gap-x-1.5 text-xs text-[var(--text-tertiary)]">
                <span className="font-semibold text-[var(--text-secondary)]" title={findingsQueueDetail(lens)}>
                  {findingsQueueTitle(lens)}
                </span>
                <span aria-hidden="true">·</span>
                <span>{displayed.length} on this page</span>
                <span aria-hidden="true">·</span>
                <span>{PAGE_SIZE} per page</span>
              </p>
              <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--text-tertiary)]">
                <span title="OpenVEX export is available after a finding is triaged as not_affected with justification">
                  {vexEligibleCount} OpenVEX-ready
                </span>
                {lens === "trust" ? (
                  <a
                    href="/compliance"
                    className="rounded-full border border-emerald-500/30 dark:border-emerald-900/50 bg-emerald-500/10 dark:bg-emerald-950/30 px-2 py-1 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 dark:hover:bg-emerald-950/50"
                  >
                    Trust center
                  </a>
                ) : (
                  <a
                    href="/remediation"
                    className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-1 hover:border-[var(--border-strong)] hover:text-[var(--text-secondary)]"
                  >
                    Remediation
                  </a>
                )}
              </div>
            </div>

            {/* Primary toolbar: search + issue type + severity, with
                advanced filters tucked into the "Filters (n)" popover. */}
            <div className="flex flex-col gap-2.5 rounded-xl border border-[var(--border-subtle)] bg-[var(--background)]/70 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="text"
                  placeholder={findingsSearchPlaceholder(lens)}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="min-w-[12rem] flex-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--foreground)] placeholder-[var(--text-tertiary)] focus:border-[var(--border-strong)] focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setFiltersOpen(true)}
                  data-testid="findings-window-chip"
                  title="Findings are scoped to this time window. Open Filters to widen."
                  className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 text-[11px] font-medium text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                >
                  <span className="text-[color:var(--text-tertiary)]">Window</span>
                  {appliedWindow?.label ??
                    WINDOW_OPTIONS.find((o) => o.value === windowDays)?.label ??
                    "Last 90 days"}
                </button>
                <div className="relative" ref={filtersRef}>
                  <button
                    type="button"
                    onClick={() => setFiltersOpen((o) => !o)}
                    aria-expanded={filtersOpen}
                    aria-haspopup="dialog"
                    data-testid="findings-filters-toggle"
                    className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                      activeFilterCount > 0
                        ? "border-[color:var(--border-strong)] bg-[var(--surface-elevated)] text-[var(--foreground)]"
                        : "border-[var(--border-subtle)] text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
                    }`}
                  >
                    <SlidersHorizontal className="h-3.5 w-3.5" />
                    Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ""}
                  </button>
                  {filtersOpen && (
                    <div
                      role="dialog"
                      aria-label="Advanced filters"
                      data-testid="findings-filters-popover"
                      className="absolute right-0 z-40 mt-2 flex w-[min(22rem,90vw)] flex-col gap-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3 shadow-xl"
                    >
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Time window</span>
                        <select
                          value={windowDays}
                          onChange={(e) => setWindowDays(Number(e.target.value))}
                          data-testid="findings-window-select"
                          className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--foreground)] focus:border-[var(--border-strong)] focus:outline-none"
                        >
                          {WINDOW_OPTIONS.map(({ value, label }) => (
                            <option key={value} value={value}>
                              {label}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Domain</span>
                        <div className="flex flex-wrap items-center gap-1">
                          {DOMAIN_FILTERS.map(({ key, label }) => (
                            <button
                              key={key}
                              type="button"
                              onClick={() => setDomainFilter(key)}
                              className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                                domainFilter === key
                                  ? "border-[color:var(--accent-mint)] bg-[color:var(--surface-muted)] text-[color:var(--foreground)]"
                                  : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                              }`}
                            >
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Cloud</span>
                        <select
                          value={providerFilter}
                          onChange={(e) => setProviderFilter(e.target.value)}
                          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-1.5 text-sm text-[color:var(--foreground)] focus:border-[color:var(--border-strong)] focus:outline-none"
                        >
                          <option value="">Any provider</option>
                          {PROVIDER_OPTIONS.map((p) => (
                            <option key={p} value={p}>
                              {p.toUpperCase()}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Account</span>
                        <input
                          type="text"
                          placeholder="e.g. aws:123456789012"
                          value={accountFilter}
                          onChange={(e) => setAccountFilter(e.target.value)}
                          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-1.5 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none"
                        />
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Environment</span>
                        <input
                          type="text"
                          placeholder="e.g. prod"
                          value={environmentFilter}
                          onChange={(e) => setEnvironmentFilter(e.target.value)}
                          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-1.5 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none"
                        />
                      </div>
                      <div className="flex items-center justify-between gap-2 border-t border-[color:var(--border-subtle)] pt-2">
                        <button
                          type="button"
                          onClick={clearAdvancedFilters}
                          disabled={activeFilterCount === 0}
                          className="rounded-lg px-2.5 py-1.5 text-xs font-medium text-[color:var(--text-secondary)] transition-colors hover:text-[color:var(--foreground)] disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          Clear all
                        </button>
                        <button
                          type="button"
                          onClick={() => setFiltersOpen(false)}
                          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition-colors hover:border-[color:var(--border-strong)]"
                        >
                          Done
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-1">
                <span className="mr-1 text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]">Issue type</span>
                {ISSUE_TYPE_FILTERS.map(({ key, label, hint }) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setIssueTypeFilter(key)}
                    title={hint}
                    className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                      issueTypeFilter === key
                        ? "border-cyan-700 bg-cyan-500/10 dark:bg-cyan-950/40 text-cyan-700 dark:text-cyan-200"
                        : "border-[var(--border-subtle)] text-[var(--text-tertiary)] hover:border-[var(--border-strong)] hover:text-[var(--text-secondary)]"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-1">
                <div className="flex flex-wrap items-center gap-1">
                  <span className="mr-1 text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]">Severity</span>
                  {FILTERS?.map(({ key, label, color }) => (
                    <button
                      key={key}
                      onClick={() => setFilter(key)}
                      className={`rounded-md border px-3 py-1 text-xs font-medium transition-colors ${
                        filter === key
                          ? `${color} border-[var(--border-strong)] bg-[var(--surface-elevated)]`
                          : "text-[var(--text-tertiary)] border-[var(--border-subtle)] hover:border-[var(--border-strong)] hover:text-[var(--text-secondary)]"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Active advanced-filter chips — removable, keep state visible
                without opening the panel. Clearing resets to default, which the
                URL-sync effect drops from the query string. */}
            {activeFilterChips.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5" data-testid="findings-active-filters">
                {activeFilterChips.map((chip) => (
                  <button
                    key={chip.key}
                    type="button"
                    onClick={chip.onClear}
                    data-testid={`findings-chip-${chip.key}`}
                    aria-label={`Remove filter ${chip.label}`}
                    className="inline-flex items-center gap-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 text-xs font-medium text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                  >
                    {chip.label}
                    <X className="h-3 w-3" aria-hidden="true" />
                  </button>
                ))}
                <button
                  type="button"
                  onClick={clearAdvancedFilters}
                  className="rounded-full px-2 py-1 text-xs font-medium text-[color:var(--text-tertiary)] transition hover:text-[color:var(--foreground)]"
                >
                  Clear all
                </button>
              </div>
            )}

            {detailLoading && vulns.length > 0 && (
              <div className="flex items-center gap-2 text-xs text-[var(--text-tertiary)]">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Refreshing the server-backed queue…
              </div>
            )}
          </div>

          <FindingsQueueTable
            vulns={displayed}
            sortKey={sortKey}
            sortDir={sortDir}
            handleSort={handleSort}
            suppressed={suppressed}
            onMarkFP={handleMarkFP}
            selectedId={selectedId}
            onSelect={setSelectedId}
            lens={lens}
            triageByKey={triageByKey}
          />

          <PaginationBar
            page={page}
            totalPages={totalPages}
            totalItems={findingsTotal}
            hasMore={hasMoreFindings}
            itemLabel={findingsTotalApproximate ? "findings (approx.)" : "findings"}
            onPrevious={() => setPage((p) => Math.max(1, p - 1))}
            onNext={() => {
              if (nextFindingsCursor) {
                setPageCursors((existing) => {
                  const next = [...existing];
                  next[page] = nextFindingsCursor;
                  return next;
                });
              }
              setPage((current) => totalPages == null ? current + 1 : Math.min(totalPages, current + 1));
            }}
          />

          {selectedVuln && (
            <FindingDrawer
              vuln={selectedVuln}
              triage={triageByKey.get(triageKey(selectedVuln.id, selectedVuln.packages[0] ?? "*"))}
              triageBusy={triageBusyKey === triageKey(selectedVuln.id, selectedVuln.packages[0] ?? "*")}
              onTriageDecision={handleTriageDecision}
              onClose={() => setSelectedId(null)}
              lens={lens}
            />
          )}
        </>
      )}
    </div>
  );
}
