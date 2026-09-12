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
import type { FindingFacets, ScopeCompleteness } from "@/lib/api-types";
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
  severityFilterDefinitions,
  serverFindingsSort,
  formatFindingsTotal,
  vulnRowKey,
} from "@/lib/findings-view";
import {
  ISSUE_TYPE_FILTERS,
  type IssueTypeFilter,
} from "@/lib/finding-issue-type";
import { Bug, Loader2, ClipboardCheck, SlidersHorizontal, X } from "lucide-react";
import { PageLaneHeader } from "@/components/page-lane";
import {
  findingTriageKey,
} from "@/lib/findings-workspace";

type ReachabilityFilter = "" | "reachable" | "unreachable" | "unassessed";
type TriageFilter = "" | FindingTriageDecision | "untriaged";

const REACHABILITY_FILTERS: ReachabilityFilter[] = ["", "reachable", "unreachable", "unassessed"];
const TRIAGE_FILTERS: TriageFilter[] = ["", "not_affected", "affected", "under_investigation", "untriaged"];

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
    const assetName =
      finding.asset?.name?.trim() ||
      finding.package?.trim() ||
      finding.package_name?.trim() ||
      finding.asset?.identifier ||
      finding.asset?.stable_id ||
      "Unavailable";
    const findingLabel = finding.cve_id || finding.title || finding.id;
    const sourceLabel = uniqueStrings([finding.source, finding.finding_type, ...(finding.scan_sources ?? [])]);
    const evidence = finding.evidence ?? {};
    const packageName = finding.package_name?.trim() || finding.package?.trim() || recordString(evidence, "package_name") || assetName;
    const currentVersion = finding.package_version ?? recordString(evidence, "package_version");
    const serverAsset = finding.asset?.asset_type === "server" || finding.asset?.asset_type === "mcp_server" || finding.entity_type === "server";
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
      finding_id: finding.finding_id ?? finding.id,
      finding_group_id: finding.finding_group_id,
      finding_group_key: finding.finding_group_key,
      node_id: finding.node_id ?? undefined,
      finding_node_id: finding.finding_node_id ?? undefined,
      entity_type: finding.entity_type ?? undefined,
      asset_type: finding.asset?.asset_type ?? undefined,
      severity: normalizedSeverity(finding.effective_severity ?? finding.severity),
      summary: raw.attack_vector_summary ?? finding.title ?? finding.description,
      description: finding.description ?? finding.title,
      references,
      advisory_sources: advisorySources,
      cwe_ids: uniqueStrings(finding.cwe_ids ?? []),
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
      current_version: currentVersion,
      published_at: finding.published_at ?? recordString(evidence, "published_at"),
      modified_at: finding.modified_at ?? recordString(evidence, "modified_at"),
      severity_source: finding.severity_source ?? recordString(evidence, "severity_source"),
      confidence: finding.confidence ?? recordNumber(evidence, "confidence"),
      match_confidence_tier:
        finding.match_confidence_tier ?? recordString(evidence, "match_confidence_tier"),
      packages: [packageName],
      agents: finding.affected_agents ?? [],
      sources: sourceLabel.length > 0 ? sourceLabel : ["finding"],
      detection_source: finding.source || undefined,
      affected_servers: uniqueStrings([...(finding.affected_servers ?? []), ...(serverAsset && assetName !== "Unavailable" ? [assetName] : [])]),
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
              package: packageName,
              ecosystem: finding.asset?.asset_type ?? finding.finding_type ?? "finding",
              current_version: currentVersion ?? "",
              fixed_version: finding.fixed_version ?? null,
              action: "review",
              command: null,
              verify_command: null,
              references: [],
              risk_narrative: finding.remediation_guidance,
            },
          ]
        : [],
      graph_reachable: finding.graph_reachable ?? null,
      graph_min_hop_distance: finding.graph_min_hop_distance ?? null,
      graph_reachable_from_agents: finding.graph_reachable_from_agents ?? [],
      lifecycle_status: finding.status ?? undefined,
      first_seen: finding.first_seen ?? undefined,
      last_seen: finding.last_seen ?? undefined,
      resolved_at: finding.resolved_at ?? undefined,
      reopened_at: finding.reopened_at ?? undefined,
      scan_count: finding.scan_count,
      last_observed: finding.last_observed ?? finding.last_seen ?? undefined,
      occurrence_count: finding.occurrence_count ?? finding.scan_count,
      occurrences: finding.occurrences,
      occurrences_truncated: finding.occurrences_truncated,
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
  const paramFinding = searchParams.get("finding");
  const paramCve = searchParams.get("cve");
  const paramAgent = searchParams.get("agent");
  const paramQuery = searchParams.get("q");
  const paramPage = searchParams.get("page");
  const paramScan = searchParams.get("scan") ?? searchParams.get("scan_id");
  const paramIssueType = searchParams.get("issue");
  const paramWindow = searchParams.get("window");
  const paramScope = searchParams.get("scope");
  // First-class scope + taxonomy facets (issue #3946), URL-synced.
  const paramDomain = searchParams.get("domain");
  const paramProvider = searchParams.get("provider");
  const paramAccount = searchParams.get("account");
  const paramEnvironment = searchParams.get("environment");
  const paramOwner = searchParams.get("owner");
  const paramSla = searchParams.get("sla");
  const paramReachability = searchParams.get("reachability");
  const paramTriage = searchParams.get("triage");
  // Compliance drill-through (epic #4790): a framework section id + optional
  // control code linked from the Compliance view's per-control finding count.
  const paramFramework = searchParams.get("framework");
  const paramControl = searchParams.get("control");


  const [vulns, setVulns] = useState<EnrichedVuln[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");
  // Per #2199 splash-kind sweep: track auth/forbidden/network so the splash
  // matches the actual cause instead of always reading as a connect failure.
  const [errorKind, setErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [filter, setFilter] = useState<SeverityFilter>(
    paramSeverity && ["critical", "high", "medium", "low", "info", "unrated"].includes(paramSeverity)
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
  const [ownerFilter, setOwnerFilter] = useState<string>(paramOwner ?? "");
  const [slaFilter, setSlaFilter] = useState<"" | "overdue" | "due" | "unassigned">(
    paramSla === "overdue" || paramSla === "due" || paramSla === "unassigned" ? paramSla : "",
  );
  const [reachabilityFilter, setReachabilityFilter] = useState<ReachabilityFilter>(
    REACHABILITY_FILTERS.includes(paramReachability as ReachabilityFilter)
      ? (paramReachability as ReachabilityFilter)
      : "",
  );
  const [triageFilter, setTriageFilter] = useState<TriageFilter>(
    TRIAGE_FILTERS.includes(paramTriage as TriageFilter) ? (paramTriage as TriageFilter) : "",
  );
  const [frameworkFilter, setFrameworkFilter] = useState<string>(paramFramework ?? "");
  // A control code is only meaningful alongside a framework; it is cleared with it.
  const [controlFilter, setControlFilter] = useState<string>(paramFramework ? (paramControl ?? "") : "");
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
  const [selectedId, setSelectedId] = useState<string | null>(paramFinding ?? paramCve ?? null);
  const [page, setPage] = useState(() => {
    const parsed = Number(paramPage ?? "1");
    return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 1;
  });
  // The API owns the canonical total. ``null`` means it has not answered yet;
  // initializing this to zero makes the loading state assert an all-clear count.
  const [findingsTotal, setFindingsTotal] = useState<number | null>(null);
  const [findingsTotalApproximate, setFindingsTotalApproximate] = useState(false);
  const [findingFacets, setFindingFacets] = useState<FindingFacets | null>(null);
  const [findingFacetsApproximate, setFindingFacetsApproximate] = useState(false);
  const [scopeCompleteness, setScopeCompleteness] = useState<ScopeCompleteness | null>(null);
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
      paramSeverity && ["critical", "high", "medium", "low", "info", "unrated"].includes(paramSeverity)
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
    setSelectedId(paramFinding ?? paramCve ?? null);
  }, [paramFinding, paramCve]);

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
    setOwnerFilter(paramOwner ?? "");
    setSlaFilter(paramSla === "overdue" || paramSla === "due" || paramSla === "unassigned" ? paramSla : "");
  }, [paramOwner, paramSla]);

  useEffect(() => {
    setReachabilityFilter(
      REACHABILITY_FILTERS.includes(paramReachability as ReachabilityFilter)
        ? (paramReachability as ReachabilityFilter)
        : "",
    );
    setTriageFilter(
      TRIAGE_FILTERS.includes(paramTriage as TriageFilter) ? (paramTriage as TriageFilter) : "",
    );
  }, [paramReachability, paramTriage]);

  useEffect(() => {
    setFrameworkFilter(paramFramework ?? "");
    setControlFilter(paramFramework ? (paramControl ?? "") : "");
  }, [paramFramework, paramControl]);

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
    if (selectedId) params.set("finding", selectedId);
    if (filter !== "all") params.set("severity", filter);
    if (issueTypeFilter !== "all") params.set("issue", issueTypeFilter);
    if (search.trim()) params.set("q", search.trim());
    if (domainFilter !== "all") params.set("domain", domainFilter);
    if (providerFilter.trim()) params.set("provider", providerFilter.trim());
    if (accountFilter.trim()) params.set("account", accountFilter.trim());
    if (environmentFilter.trim()) params.set("environment", environmentFilter.trim());
    if (ownerFilter.trim()) params.set("owner", ownerFilter.trim());
    if (slaFilter) params.set("sla", slaFilter);
    if (reachabilityFilter) params.set("reachability", reachabilityFilter);
    if (triageFilter) params.set("triage", triageFilter);
    if (frameworkFilter.trim()) params.set("framework", frameworkFilter.trim());
    // A control code without a framework is meaningless — only sync it alongside.
    if (frameworkFilter.trim() && controlFilter.trim()) params.set("control", controlFilter.trim());
    if (windowDays !== DEFAULT_FINDINGS_WINDOW_DAYS) params.set("window", String(windowDays));
    if (page > 1) params.set("page", String(page));
    if (paramScan) params.set("scan", paramScan);
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [
    filter,
    issueTypeFilter,
    search,
    domainFilter,
    providerFilter,
    accountFilter,
    environmentFilter,
    ownerFilter,
    slaFilter,
    reachabilityFilter,
    triageFilter,
    frameworkFilter,
    controlFilter,
    windowDays,
    page,
    selectedId,
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
      const findingQuery = search.trim();
      const exported = await api.exportFindingTriageVex({
        scope: "current",
        ...(findingQuery ? { query: findingQuery } : {}),
        ...(filter !== "all" ? { severity: filter === "unrated" ? "unknown" : filter } : {}),
        ...(paramScan ? { scanId: paramScan } : {}),
        ...(domainFilter !== "all" ? { domain: domainFilter } : {}),
        ...(providerFilter.trim() ? { provider: providerFilter.trim() } : {}),
        ...(accountFilter.trim() ? { account: accountFilter.trim() } : {}),
        ...(environmentFilter.trim() ? { environment: environmentFilter.trim() } : {}),
        ...(ownerFilter.trim() ? { owner: ownerFilter.trim() } : {}),
        ...(slaFilter ? { sla: slaFilter } : {}),
        ...(reachabilityFilter ? { reachability: reachabilityFilter } : {}),
        ...(triageFilter ? { triage: triageFilter } : {}),
        ...(frameworkFilter.trim() ? { framework: frameworkFilter.trim() } : {}),
        ...(frameworkFilter.trim() && controlFilter.trim() ? { control: controlFilter.trim() } : {}),
        ...(issueTypeFilter !== "all" ? { findingClass: issueTypeFilter } : {}),
        windowDays,
      });
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
  }, [
    accountFilter,
    controlFilter,
    domainFilter,
    environmentFilter,
    filter,
    frameworkFilter,
    issueTypeFilter,
    ownerFilter,
    paramScan,
    providerFilter,
    search,
    slaFilter,
    reachabilityFilter,
    triageFilter,
    windowDays,
  ]);

  useEffect(() => {
    void refreshTriage();
  }, [refreshTriage]);

  useEffect(() => {
    async function loadFindings() {
      setDetailLoading(true);
      setError("");
      try {
        const currentCursor = pageCursors[page - 1] || undefined;
        const findingQuery = search.trim() || paramFinding;
        const response = await api.listFindings({
          ...(paramScan ? { scanId: paramScan } : {}),
          ...(findingQuery ? { query: findingQuery } : {}),
          ...(filter !== "all" ? { severity: filter === "unrated" ? "unknown" : filter } : {}),
          ...(domainFilter !== "all" ? { domain: domainFilter } : {}),
          ...(providerFilter.trim() ? { provider: providerFilter.trim() } : {}),
          ...(accountFilter.trim() ? { account: accountFilter.trim() } : {}),
          ...(environmentFilter.trim() ? { environment: environmentFilter.trim() } : {}),
          ...(ownerFilter.trim() ? { owner: ownerFilter.trim() } : {}),
          ...(slaFilter ? { sla: slaFilter } : {}),
          ...(reachabilityFilter ? { reachability: reachabilityFilter } : {}),
          ...(triageFilter ? { triage: triageFilter } : {}),
          ...(frameworkFilter.trim() ? { framework: frameworkFilter.trim() } : {}),
          ...(frameworkFilter.trim() && controlFilter.trim() ? { control: controlFilter.trim() } : {}),
          ...(issueTypeFilter !== "all" ? { findingClass: issueTypeFilter } : {}),
          sort: serverFindingsSort(sortKey),
          limit: PAGE_SIZE,
          ...(!currentCursor ? { offset: (page - 1) * PAGE_SIZE } : {}),
          ...(currentCursor ? { cursor: currentCursor } : {}),
          approximateTotal: true,
          groupOccurrences: true,
          includeFacets: true,
          windowDays,
        });
        setAppliedWindow(response.window ?? null);
        setVulns(collectUnifiedFindings(response.findings));
        setFindingsTotal(typeof response.total === "number" ? response.total : null);
        setFindingsTotalApproximate(Boolean(response.total_approximate));
        setFindingFacets(response.facets ?? null);
        setFindingFacetsApproximate(Boolean(response.facets_approximate));
        setScopeCompleteness(response.scope_completeness ?? null);
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
    paramFinding,
    search,
    page,
    filter,
    domainFilter,
    providerFilter,
    accountFilter,
    environmentFilter,
    ownerFilter,
    slaFilter,
    reachabilityFilter,
    triageFilter,
    frameworkFilter,
    controlFilter,
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
    ownerFilter,
    slaFilter,
    reachabilityFilter,
    triageFilter,
    frameworkFilter,
    controlFilter,
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
    ownerFilter.trim()
      ? { key: "owner", label: `Owner: ${ownerFilter.trim()}`, onClear: () => setOwnerFilter("") }
      : null,
    slaFilter
      ? { key: "sla", label: `SLA: ${slaFilter}`, onClear: () => setSlaFilter("") }
      : null,
    reachabilityFilter
      ? { key: "reachability", label: `Reach: ${reachabilityFilter}`, onClear: () => setReachabilityFilter("") }
      : null,
    triageFilter
      ? { key: "triage", label: `Triage: ${triageFilter.replaceAll("_", " ")}`, onClear: () => setTriageFilter("") }
      : null,
    // Compliance drill-through chips. Clearing the framework also clears the
    // control, since a control code without its framework is meaningless.
    frameworkFilter.trim()
      ? {
          key: "framework",
          label: `Framework: ${frameworkFilter.trim().toUpperCase()}`,
          onClear: () => {
            setFrameworkFilter("");
            setControlFilter("");
          },
        }
      : null,
    frameworkFilter.trim() && controlFilter.trim()
      ? { key: "control", label: `Control: ${controlFilter.trim()}`, onClear: () => setControlFilter("") }
      : null,
  ].filter((chip): chip is { key: string; label: string; onClear: () => void } => chip !== null);
  const activeFilterCount = activeFilterChips.length;
  const clearAdvancedFilters = () => {
    setDomainFilter("all");
    setProviderFilter("");
    setAccountFilter("");
    setEnvironmentFilter("");
    setOwnerFilter("");
    setSlaFilter("");
    setReachabilityFilter("");
    setTriageFilter("");
    setFrameworkFilter("");
    setControlFilter("");
  };

  const hasActiveFilters = Boolean(search.trim() || filter !== "all" || issueTypeFilter !== "all" || activeFilterCount || windowDays !== 90);
  const clearFilters = () => {
    clearAdvancedFilters();
    setSearch("");
    setFilter("all");
    setIssueTypeFilter("all");
    setWindowDays(90);
  };

  const FILTERS = severityFilterDefinitions(findingFacetsApproximate ? null : findingFacets, findingsFilterTotalLabel);

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="command"
        title="Findings"
        scopeChip={false}
        subtitle={`${findingsTotalLabel}${findingsTotal == null ? "" : (findingsTotal === 1 ? " finding" : " findings")} · ${paramScan ? `Scan ${paramScan.slice(0, 8)} · ` : ""}${findingsWindowLabel}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {vulns.length > 0 ? (
              <>
                <button
                  onClick={handleExportVex}
                  disabled={vexExporting || vexEligibleCount === 0}
                  className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-900 bg-emerald-500/10 dark:bg-emerald-950/40 px-3 py-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-300 transition-colors hover:bg-emerald-500/10 dark:hover:bg-emerald-950/70 disabled:cursor-not-allowed disabled:opacity-50"
                  title={
                    vexEligibleCount > 0
                      ? "Export signed OpenVEX JSON for the current filtered Findings view"
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

      {/* A scope walk that stopped on its row budget is NOT evidence of an empty
          estate. Say so, and never let the "No findings found" empty state stand
          in for a partial page. */}
      {!loading && !error && scopeCompleteness?.status === "partial" && (
        <div
          data-testid="findings-scope-partial"
          className="rounded-md border border-outline bg-surface-muted px-3 py-2 text-xs text-ink-secondary"
        >
          Partial results — filter matching stopped after {scopeCompleteness.scanned_rows.toLocaleString()} scanned rows
          to keep the read fast. Page through with Next for the rest, or narrow the filters.
        </div>
      )}

      {!loading && !error && vulns.length === 0 && !hasActiveFilters && scopeCompleteness?.status !== "partial" && (
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

      {!error && (vulns.length > 0 || hasActiveFilters) && (
        <>
          <div className="flex flex-col gap-3">
            {/* Primary toolbar: search + issue type + severity, with
                advanced filters tucked into the "Filters (n)" popover. */}
            <div className="flex flex-col gap-2.5 rounded-xl border border-outline bg-background/70 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="text"
                  placeholder="Search findings, assets, or controls…"
                  aria-label="Search findings"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="min-w-[12rem] flex-1 rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground placeholder-[var(--text-tertiary)] focus:border-outline-strong focus:outline-none"
                />
                <div className="relative" ref={filtersRef}>
                  <button
                    type="button"
                    onClick={() => setFiltersOpen((o) => !o)}
                    aria-expanded={filtersOpen}
                    aria-haspopup="dialog"
                    data-testid="findings-filters-toggle"
                    className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                      activeFilterCount > 0
                        ? "border-outline-strong bg-surface-elevated text-foreground"
                        : "border-outline text-ink-secondary hover:border-outline-strong hover:text-foreground"
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
                      className="absolute right-0 z-40 mt-2 flex w-[min(22rem,90vw)] flex-col gap-3 rounded-xl border border-outline bg-surface p-3 shadow-xl"
                    >
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Time window</span>
                        <select
                          value={windowDays}
                          onChange={(e) => setWindowDays(Number(e.target.value))}
                          data-testid="findings-window-select"
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
                        >
                          {WINDOW_OPTIONS.map(({ value, label }) => (
                            <option key={value} value={value}>
                              {label}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Domain</span>
                        <div className="flex flex-wrap items-center gap-1">
                          {DOMAIN_FILTERS.map(({ key, label }) => (
                            <button
                              key={key}
                              type="button"
                              onClick={() => setDomainFilter(key)}
                              className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                                domainFilter === key
                                  ? "border-accent-mint bg-surface-muted text-foreground"
                                  : "border-outline text-ink-secondary hover:border-outline-strong hover:text-foreground"
                              }`}
                            >
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Cloud</span>
                        <select
                          value={providerFilter}
                          onChange={(e) => setProviderFilter(e.target.value)}
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
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
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Account</span>
                        <input
                          type="text"
                          placeholder="e.g. aws:123456789012"
                          value={accountFilter}
                          onChange={(e) => setAccountFilter(e.target.value)}
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground placeholder-[color:var(--text-tertiary)] focus:border-outline-strong focus:outline-none"
                        />
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Environment</span>
                        <input
                          type="text"
                          placeholder="e.g. prod"
                          value={environmentFilter}
                          onChange={(e) => setEnvironmentFilter(e.target.value)}
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground placeholder-[color:var(--text-tertiary)] focus:border-outline-strong focus:outline-none"
                        />
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Owner</span>
                        <input
                          type="text"
                          placeholder="e.g. payments-security"
                          value={ownerFilter}
                          onChange={(e) => setOwnerFilter(e.target.value)}
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground placeholder-[color:var(--text-tertiary)] focus:border-outline-strong focus:outline-none"
                        />
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">SLA</span>
                        <select
                          value={slaFilter}
                          onChange={(e) => setSlaFilter(e.target.value as "" | "overdue" | "due" | "unassigned")}
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
                        >
                          <option value="">Any SLA</option>
                          <option value="overdue">Overdue</option>
                          <option value="due">Due later</option>
                          <option value="unassigned">No SLA</option>
                        </select>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Reachability</span>
                        <select
                          value={reachabilityFilter}
                          onChange={(e) => setReachabilityFilter(e.target.value as ReachabilityFilter)}
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
                        >
                          <option value="">Any reachability</option>
                          <option value="reachable">Reachable</option>
                          <option value="unreachable">Unreachable</option>
                          <option value="unassessed">Unassessed</option>
                        </select>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Triage</span>
                        <select
                          value={triageFilter}
                          onChange={(e) => setTriageFilter(e.target.value as TriageFilter)}
                          className="rounded-lg border border-outline bg-surface px-3 py-1.5 text-sm text-foreground focus:border-outline-strong focus:outline-none"
                        >
                          <option value="">Any triage state</option>
                          <option value="not_affected">Not affected</option>
                          <option value="affected">Affected</option>
                          <option value="under_investigation">Under investigation</option>
                          <option value="untriaged">Untriaged</option>
                        </select>
                      </div>
                      <div className="flex items-center justify-between gap-2 border-t border-outline pt-2">
                        <button
                          type="button"
                          onClick={clearAdvancedFilters}
                          disabled={activeFilterCount === 0}
                          className="rounded-lg px-2.5 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          Clear all
                        </button>
                        <button
                          type="button"
                          onClick={() => setFiltersOpen(false)}
                          className="rounded-lg border border-outline bg-surface-elevated px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:border-outline-strong"
                        >
                          Done
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-1">
                <span className="mr-1 text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Issue type</span>
                {ISSUE_TYPE_FILTERS.map(({ key, label, hint }) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setIssueTypeFilter(key)}
                    title={hint}
                    className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                      issueTypeFilter === key
                        ? "border-cyan-700 bg-cyan-500/10 dark:bg-cyan-950/40 text-cyan-700 dark:text-cyan-200"
                        : "border-outline text-ink-tertiary hover:border-outline-strong hover:text-ink-secondary"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-1">
                <div className="flex flex-wrap items-center gap-1">
                  <span className="mr-1 text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">Severity</span>
                  {FILTERS?.map(({ key, label, color }) => (
                    <button
                      key={key}
                      onClick={() => setFilter(key)}
                      className={`rounded-md border px-3 py-1 text-xs font-medium transition-colors ${
                        filter === key
                          ? `${color} border-outline-strong bg-surface-elevated`
                          : "text-ink-tertiary border-outline hover:border-outline-strong hover:text-ink-secondary"
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
                    className="inline-flex items-center gap-1 rounded-full border border-outline bg-surface-muted px-2.5 py-1 text-xs font-medium text-ink-secondary transition hover:border-outline-strong hover:text-foreground"
                  >
                    {chip.label}
                    <X className="h-3 w-3" aria-hidden="true" />
                  </button>
                ))}
                <button
                  type="button"
                  onClick={clearAdvancedFilters}
                  className="rounded-full px-2 py-1 text-xs font-medium text-ink-tertiary transition hover:text-foreground"
                >
                  Clear all
                </button>
              </div>
            )}

            {hasActiveFilters ? <button type="button" onClick={clearFilters} className="w-fit rounded border border-outline px-3 py-1.5 text-xs text-ink-secondary">Clear filters</button> : null}

            {detailLoading && vulns.length > 0 && (
              <div className="flex items-center gap-2 text-xs text-ink-tertiary">
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
            triageByKey={triageByKey}
          />

          <PaginationBar
            page={page}
            totalPages={totalPages}
            totalItems={findingsTotal}
            hasMore={hasMoreFindings}
            itemLabel={findingsTotalApproximate ? "issues (approx.)" : "issues"}
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
              />
          )}
        </>
      )}
    </div>
  );
}
