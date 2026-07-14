"use client";

import { Suspense, useCallback, useEffect, useState, useMemo, type ElementType } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  api,
  Vulnerability,
  ScanJob,
  ScanResult,
  JobListItem,
  RemediationItem,
  UnifiedFinding,
  type FindingTriageDecision,
  type FindingTriageItem,
  type FindingTriageJustification,
  type UnifiedGraphResponse,
} from "@/lib/api";
import { ApiOfflineState } from "@/components/api-offline-state";
import { FindingDrawer } from "@/components/finding-drawer";
import { FindingsQueueTable } from "@/components/findings-queue";
import { PaginationBar } from "@/components/pagination-bar";
import { PageEmptyState, PageLoadingState } from "@/components/states/page-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { FIRST_SCAN_ACTIONS } from "@/lib/empty-state-actions";
import {
  type EnrichedVuln,
  type GroupKey,
  type RemediationSummary,
  type ScanScope,
  type SeverityFilter,
  type SortKey,
  uniqueStrings,
  serverFindingsSort,
  formatFindingsTotal,
  hasLifecycleMetadata,
  computeFindingColumns,
  vulnRowKey,
} from "@/lib/findings-view";
import {
  ISSUE_TYPE_FILTERS,
  matchesIssueTypeFilter,
  type IssueTypeFilter,
} from "@/lib/finding-issue-type";
import {
  findingsPageSubtitle,
  findingsQueueDetail,
  findingsQueueTitle,
  findingsSearchPlaceholder,
} from "@/lib/findings-lens";
import { useFindingsLens } from "@/hooks/use-findings-lens";
import { severityRank } from "@/lib/severity";
import { Bug, ChevronDown, ChevronRight, Download, Layers, Loader2, Package, Server, ClipboardCheck } from "lucide-react";
import { PageLaneHeader } from "@/components/page-lane";

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



function toRemediationSummary(item: RemediationItem): RemediationSummary {
  return {
    package: item.package,
    ecosystem: item.ecosystem,
    current_version: item.current_version,
    fixed_version: item.fixed_version,
    action: item.action,
    command: item.command,
    verify_command: item.verify_command,
    references: item.references ?? [],
    risk_narrative: item.risk_narrative,
  };
}

function mergeRemediationItems(existing: RemediationSummary[], incoming: RemediationSummary[]) {
  const merged = new Map(existing.map((item) => [`${item.package}:${item.current_version}:${item.fixed_version ?? "none"}`, item]));
  for (const item of incoming) {
    const key = `${item.package}:${item.current_version}:${item.fixed_version ?? "none"}`;
    if (!merged.has(key)) {
      merged.set(key, item);
    }
  }
  return Array.from(merged.values());
}

function triageKey(vulnerabilityId: string, packageName: string) {
  return `${vulnerabilityId}::${packageName || "*"}`;
}

type GraphNode = UnifiedGraphResponse["nodes"][number];

function graphNodeKind(node: GraphNode): string {
  return String(node.entity_type).toLowerCase();
}

function attrString(node: GraphNode, key: string): string | undefined {
  const value = node.attributes?.[key];
  return typeof value === "string" && value.trim() ? value : undefined;
}

function attrNumber(node: GraphNode, key: string): number | undefined {
  const value = node.attributes?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function normalizedSeverity(value: string | undefined): Vulnerability["severity"] {
  const normalized = (value ?? "").toLowerCase();
  return normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low" || normalized === "none"
    ? normalized
    : "none";
}

function collectGraphVulns(graph: UnifiedGraphResponse): EnrichedVuln[] {
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const packagesByFinding = new Map<string, Set<string>>();
  const agentsByFinding = new Map<string, Set<string>>();

  for (const edge of graph.edges) {
    const source = nodeById.get(edge.source);
    const target = nodeById.get(edge.target);
    if (!source || !target) continue;
    const sourceKind = graphNodeKind(source);
    const targetKind = graphNodeKind(target);
    const finding = sourceKind === "vulnerability" ? source : targetKind === "vulnerability" ? target : null;
    const other = finding?.id === source.id ? target : source;
    if (!finding || !other) continue;
    const otherKind = graphNodeKind(other);
    if (otherKind === "package") {
      const values = packagesByFinding.get(finding.id) ?? new Set<string>();
      values.add(other.label);
      packagesByFinding.set(finding.id, values);
    } else if (otherKind === "agent") {
      const values = agentsByFinding.get(finding.id) ?? new Set<string>();
      values.add(other.label);
      agentsByFinding.set(finding.id, values);
    }
  }

  return graph.nodes
    .filter((node) => graphNodeKind(node) === "vulnerability")
    .map((node): EnrichedVuln => ({
      id: node.label,
      severity: normalizedSeverity(node.severity),
      summary: attrString(node, "summary") ?? attrString(node, "description"),
      description: attrString(node, "description") ?? attrString(node, "summary"),
      references: [],
      advisory_sources: [],
      aliases: [],
      cvss_score: attrNumber(node, "cvss_score") ?? attrNumber(node, "cvss"),
      epss_score: attrNumber(node, "epss_score") ?? attrNumber(node, "epss"),
      is_kev: Boolean(node.attributes?.is_kev ?? node.attributes?.cisa_kev),
      cisa_kev: Boolean(node.attributes?.cisa_kev ?? node.attributes?.is_kev),
      fixed_version: attrString(node, "fixed_version"),
      packages: Array.from(packagesByFinding.get(node.id) ?? []),
      agents: Array.from(agentsByFinding.get(node.id) ?? []),
      sources: node.data_sources.length > 0 ? node.data_sources : [`graph:${graph.scan_id.slice(0, 8)}`],
      affected_servers: [],
      exposed_credentials: [],
      reachable_tools: [],
      attack_vector_summary: attrString(node, "attack_vector_summary"),
      impact_category: attrString(node, "impact_category"),
      risk_score: node.risk_score,
      remediation_items: [],
      graph_reachable: null,
      graph_min_hop_distance: null,
    }));
}

function collectUnifiedFindings(findings: UnifiedFinding[]): EnrichedVuln[] {
  return findings.map((finding): EnrichedVuln => {
    const raw = finding as UnifiedFinding & {
      framework_tags?: string[];
      phantom_tools?: string[];
      runtime_evidence?: EnrichedVuln["runtime_evidence"];
      effective_reach_band?: string;
      effective_reach_score?: number;
      attack_vector_summary?: string;
    };
    const assetName = finding.asset?.name?.trim() || finding.asset?.identifier || finding.asset?.stable_id || "asset";
    const findingLabel = finding.cve_id || finding.title || finding.id;
    const sourceLabel = uniqueStrings([finding.source, finding.finding_type, ...(finding.scan_sources ?? [])]);
    return {
      id: findingLabel,
      finding_id: finding.id,
      severity: normalizedSeverity(finding.effective_severity ?? finding.severity),
      summary: raw.attack_vector_summary ?? finding.title ?? finding.description,
      description: finding.description ?? finding.title,
      references: [],
      advisory_sources: sourceLabel,
      aliases: [],
      cvss_score: finding.cvss_score ?? undefined,
      epss_score: finding.epss_score ?? undefined,
      is_kev: Boolean(finding.is_kev),
      cisa_kev: Boolean(finding.is_kev),
      fixed_version: finding.fixed_version ?? undefined,
      packages: [assetName],
      agents: finding.affected_agents ?? [],
      sources: sourceLabel.length > 0 ? sourceLabel : ["finding"],
      affected_servers: finding.affected_servers ?? [],
      exposed_credentials: finding.exposed_credentials ?? [],
      reachable_tools: finding.exposed_tools ?? [],
      phantom_tools: raw.phantom_tools ?? [],
      framework_tags: raw.framework_tags ?? finding.compliance_tags ?? [],
      attack_vector_summary: raw.attack_vector_summary ?? (finding.network_exploitable ? "Network exploitable" : undefined),
      impact_category: finding.impact_category ?? finding.finding_type,
      finding_type: finding.finding_type,
      risk_score: finding.risk_score,
      effective_reach_band: raw.effective_reach_band,
      effective_reach_score: raw.effective_reach_score,
      runtime_evidence: raw.runtime_evidence,
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
    };
  });
}


// Security-domain facets (issue #3946). Map 1:1 to the overview coverage lanes
// so drilling from a coverage lane lands on the matching findings filter.
const DOMAIN_FILTERS: { key: string; label: string }[] = [
  { key: "all", label: "All domains" },
  { key: "cspm", label: "CSPM" },
  { key: "vuln", label: "Vuln mgmt" },
  { key: "appsec_sca", label: "AppSec / SCA" },
  { key: "dspm", label: "DSPM" },
  { key: "aispm", label: "AISPM" },
];

const PROVIDER_OPTIONS = ["aws", "azure", "gcp", "snowflake", "databricks"];

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
  const paramScope = searchParams.get("scope");
  const paramGroup = searchParams.get("group");
  const paramPage = searchParams.get("page");
  const paramScan = searchParams.get("scan") ?? searchParams.get("scan_id");
  const paramIssueType = searchParams.get("issue");
  const paramLens = searchParams.get("lens");
  // First-class scope + taxonomy facets (issue #3946), URL-synced.
  const paramDomain = searchParams.get("domain");
  const paramProvider = searchParams.get("provider");
  const paramAccount = searchParams.get("account");
  const paramEnvironment = searchParams.get("environment");
  const { lens, selectLens, lenses, label: lensLabel, hint: lensHint } = useFindingsLens(paramLens);

  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [vulns, setVulns] = useState<EnrichedVuln[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");
  // Per #2199 splash-kind sweep: track auth/forbidden/network so the splash
  // matches the actual cause instead of always reading as a connect failure.
  const [errorKind, setErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [scope, setScope] = useState<ScanScope>(paramScope === "all" ? "all" : "latest");
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
  const [search, setSearch] = useState(paramQuery ?? paramCve ?? paramAgent ?? "");
  const [groupBy, setGroupBy] = useState<GroupKey>(
    paramGroup === "package" || paramGroup === "agent" || paramGroup === "severity" ? paramGroup : "none",
  );
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
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsTotalApproximate, setFindingsTotalApproximate] = useState(false);
  const PAGE_SIZE = 25;
  const useServerPaging = groupBy === "none" && !search.trim();
  const showLifecycleColumns = useMemo(() => hasLifecycleMetadata(vulns), [vulns]);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const toggleGroup = useCallback((groupLabel: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupLabel)) next.delete(groupLabel);
      else next.add(groupLabel);
      return next;
    });
  }, []);

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
    setScope(paramScope === "all" ? "all" : "latest");
  }, [paramScope]);

  useEffect(() => {
    setGroupBy(
      paramGroup === "package" || paramGroup === "agent" || paramGroup === "severity" ? paramGroup : "none",
    );
  }, [paramGroup]);

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
    const params = new URLSearchParams();
    if (filter !== "all") params.set("severity", filter);
    if (issueTypeFilter !== "all") params.set("issue", issueTypeFilter);
    if (lens !== "ops") params.set("lens", lens);
    if (search.trim()) params.set("q", search.trim());
    if (scope !== "latest") params.set("scope", scope);
    if (groupBy !== "none") params.set("group", groupBy);
    if (domainFilter !== "all") params.set("domain", domainFilter);
    if (providerFilter.trim()) params.set("provider", providerFilter.trim());
    if (accountFilter.trim()) params.set("account", accountFilter.trim());
    if (environmentFilter.trim()) params.set("environment", environmentFilter.trim());
    if (page > 1) params.set("page", String(page));
    if (paramScan) params.set("scan", paramScan);
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [
    filter,
    issueTypeFilter,
    lens,
    search,
    scope,
    groupBy,
    domainFilter,
    providerFilter,
    accountFilter,
    environmentFilter,
    page,
    paramScan,
    pathname,
    router,
  ]);

  const collectVulns = useCallback((fullJobs: ScanJob[]) => {
    const vulnMap = new Map<string, EnrichedVuln>();
    for (const job of fullJobs) {
      if (!job.result) continue;
      const result = job.result as ScanResult;
      const blastById = new Map(result.blast_radius?.map((item) => [item.vulnerability_id, item]) ?? []);
      const remediationByVulnId = new Map<string, RemediationSummary[]>();
      for (const item of result.remediation_plan ?? []) {
        const summary = toRemediationSummary(item);
        for (const vulnId of item.vulnerabilities ?? []) {
          const existing = remediationByVulnId.get(vulnId) ?? [];
          existing.push(summary);
          remediationByVulnId.set(vulnId, existing);
        }
      }

      const scanSources: string[] = [];
      if (job.request.images?.length) scanSources.push(...job.request.images);
      if (job.request.k8s) scanSources.push("kubernetes");
      if (job.request.sbom) scanSources.push("sbom-import");
      if (scanSources.length === 0) scanSources.push("local-agents");

      for (const agent of result.agents) {
        for (const srv of agent.mcp_servers) {
          for (const pkg of srv.packages) {
            for (const vuln of pkg.vulnerabilities ?? []) {
              const blast = blastById.get(vuln.id);
              const remediationItems = remediationByVulnId.get(vuln.id) ?? [];
              const existing = vulnMap.get(vuln.id);
              if (existing) {
                if (!existing.packages.includes(pkg.name)) existing.packages.push(pkg.name);
                if (!existing.agents.includes(agent.name)) existing.agents.push(agent.name);
                for (const src of scanSources) {
                  if (!existing.sources.includes(src)) existing.sources.push(src);
                }
                existing.cvss_score = existing.cvss_score ?? blast?.cvss_score ?? vuln.cvss_score;
                existing.epss_score = existing.epss_score ?? blast?.epss_score ?? vuln.epss_score;
                existing.fixed_version = existing.fixed_version ?? blast?.fixed_version ?? vuln.fixed_version;
                // Graph-walk reachability: prefer "reachable=true" + smallest
                // hop count when multiple blast rows touch the same vuln.
                if (blast?.graph_reachable === true) existing.graph_reachable = true;
                else if (existing.graph_reachable !== true && blast?.graph_reachable === false) existing.graph_reachable = false;
                if (typeof blast?.graph_min_hop_distance === "number") {
                  existing.graph_min_hop_distance =
                    typeof existing.graph_min_hop_distance === "number"
                      ? Math.min(existing.graph_min_hop_distance, blast.graph_min_hop_distance)
                      : blast.graph_min_hop_distance;
                }
                existing.summary = existing.summary ?? blast?.attack_vector_summary ?? vuln.summary ?? vuln.description;
                existing.attack_vector_summary = existing.attack_vector_summary ?? blast?.attack_vector_summary;
                existing.impact_category = existing.impact_category ?? blast?.impact_category;
                existing.risk_score = existing.risk_score ?? blast?.risk_score ?? blast?.blast_score;
                existing.affected_servers = uniqueStrings([...existing.affected_servers, ...(blast?.affected_servers ?? [])]);
                existing.exposed_credentials = uniqueStrings([...existing.exposed_credentials, ...(blast?.exposed_credentials ?? [])]);
                existing.reachable_tools = uniqueStrings([
                  ...existing.reachable_tools,
                  ...(blast?.exposed_tools ?? []),
                  ...(blast?.reachable_tools ?? []),
                ]);
                existing.phantom_tools = uniqueStrings([...(existing.phantom_tools ?? []), ...(blast?.phantom_tools ?? [])]);
                existing.framework_tags = uniqueStrings([...(existing.framework_tags ?? []), ...(blast?.framework_tags ?? [])]);
                existing.effective_reach_band = existing.effective_reach_band ?? blast?.effective_reach_band;
                existing.effective_reach_score = existing.effective_reach_score ?? blast?.effective_reach_score;
                existing.runtime_evidence = existing.runtime_evidence ?? blast?.runtime_evidence;
                existing.references = uniqueStrings([...existing.references, ...(vuln.references ?? []), ...remediationItems.flatMap((item) => item.references)]);
                existing.advisory_sources = uniqueStrings([...existing.advisory_sources, ...(vuln.advisory_sources ?? [])]);
                existing.aliases = uniqueStrings([...(existing.aliases ?? []), ...(vuln.aliases ?? [])]);
                existing.remediation_items = mergeRemediationItems(existing.remediation_items, remediationItems);
              } else {
                vulnMap.set(vuln.id, {
                  ...vuln,
                  cvss_score: blast?.cvss_score ?? vuln.cvss_score,
                  epss_score: blast?.epss_score ?? vuln.epss_score,
                  fixed_version: blast?.fixed_version ?? vuln.fixed_version,
                  summary: blast?.attack_vector_summary ?? vuln.summary ?? vuln.description,
                  packages: [pkg.name],
                  agents: [agent.name],
                  sources: [...scanSources],
                  affected_servers: blast?.affected_servers ?? [],
                  exposed_credentials: blast?.exposed_credentials ?? [],
                  reachable_tools: uniqueStrings([...(blast?.exposed_tools ?? []), ...(blast?.reachable_tools ?? [])]),
                  phantom_tools: blast?.phantom_tools ?? [],
                  framework_tags: blast?.framework_tags ?? [],
                  effective_reach_band: blast?.effective_reach_band,
                  effective_reach_score: blast?.effective_reach_score,
                  runtime_evidence: blast?.runtime_evidence,
                  references: uniqueStrings([...(vuln.references ?? []), ...remediationItems.flatMap((item) => item.references)]),
                  advisory_sources: vuln.advisory_sources ?? [],
                  aliases: vuln.aliases ?? [],
                  attack_vector_summary: blast?.attack_vector_summary,
                  impact_category: blast?.impact_category,
                  risk_score: blast?.risk_score ?? blast?.blast_score,
                  remediation_items: remediationItems,
                  graph_reachable: blast?.graph_reachable ?? null,
                  graph_min_hop_distance: blast?.graph_min_hop_distance ?? null,
                });
              }
            }
          }
        }
      }
    }
    return Array.from(vulnMap.values());
  }, []);

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
    async function loadSummaries() {
      try {
        const jobsResp = await api.listJobs();
        const doneJobs = jobsResp.jobs
          .filter((j) => j.status === "done")
          .sort((a, b) => b.created_at.localeCompare(a.created_at));
        setJobs(doneJobs);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load");
        setErrorKind(_classifyApiErrorKind(e));
      } finally {
        setLoading(false);
      }
    }
    void loadSummaries();
  }, []);

  useEffect(() => {
    void refreshTriage();
  }, [refreshTriage]);

  useEffect(() => {
    async function loadLegacyFindings() {
      if (paramScan) {
        try {
          const findings = await api.listFindings({ scanId: paramScan, limit: 1000 });
          if (findings.findings.length > 0) {
            setVulns(collectUnifiedFindings(findings.findings));
            setFindingsTotal(findings.total);
            setFindingsTotalApproximate(false);
            return;
          }
          const graph = await api.getGraph({ scanId: paramScan, limit: 2500 });
          setVulns(collectGraphVulns(graph));
          setFindingsTotal(graph.nodes.filter((node) => graphNodeKind(node) === "vulnerability").length);
          setFindingsTotalApproximate(false);
          return;
        } catch {
          const selectedJob = await api.getScan(paramScan);
          setVulns(collectVulns([selectedJob]));
          setFindingsTotal(collectVulns([selectedJob]).length);
          setFindingsTotalApproximate(false);
          return;
        }
      }

      if (jobs.length === 0) {
        setVulns([]);
        setFindingsTotal(0);
        setFindingsTotalApproximate(false);
        return;
      }

      if (scope === "latest") {
        const latestJob = await api.getScan(jobs[0]!.job_id);
        const collected = collectVulns([latestJob]);
        setVulns(collected);
        setFindingsTotal(collected.length);
        setFindingsTotalApproximate(false);
        return;
      }

      const fullJobs = await Promise.all(jobs.map((job) => api.getScan(job.job_id).catch(() => null)));
      const collected = collectVulns(fullJobs.filter((job): job is ScanJob => Boolean(job)));
      setVulns(collected);
      setFindingsTotal(collected.length);
      setFindingsTotalApproximate(false);
    }

    async function loadDetails() {
      if (loading) return;

      setDetailLoading(true);
      setError("");
      try {
        if (useServerPaging) {
          const scanId =
            paramScan ?? (scope === "latest" && jobs[0] ? jobs[0].job_id : undefined);
          const response = await api.listFindings({
            ...(scanId ? { scanId } : {}),
            ...(filter !== "all" ? { severity: filter } : {}),
            ...(domainFilter !== "all" ? { domain: domainFilter } : {}),
            ...(providerFilter.trim() ? { provider: providerFilter.trim() } : {}),
            ...(accountFilter.trim() ? { account: accountFilter.trim() } : {}),
            ...(environmentFilter.trim() ? { environment: environmentFilter.trim() } : {}),
            sort: serverFindingsSort(sortKey),
            limit: PAGE_SIZE,
            offset: (page - 1) * PAGE_SIZE,
            approximateTotal: true,
          });
          if (response.total > 0 || response.findings.length > 0) {
            setVulns(collectUnifiedFindings(response.findings));
            setFindingsTotal(response.total);
            setFindingsTotalApproximate(Boolean(response.total_approximate));
            return;
          }
        }

        await loadLegacyFindings();
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load");
        setErrorKind(_classifyApiErrorKind(e));
      } finally {
        setDetailLoading(false);
      }
    }

    void loadDetails();
  }, [
    jobs,
    scope,
    loading,
    collectVulns,
    paramScan,
    useServerPaging,
    page,
    filter,
    domainFilter,
    providerFilter,
    accountFilter,
    environmentFilter,
    sortKey,
  ]);

  function handleSort(field: SortKey) {
    if (sortKey === field) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortKey(field);
      setSortDir("desc");
    }
  }

  const displayed = useMemo(() => {
    if (useServerPaging) {
      return vulns;
    }
    let list = vulns;
    if (filter !== "all") {
      list = list.filter((v) => v.severity.toLowerCase() === filter);
    }
    if (issueTypeFilter !== "all") {
      list = list.filter((v) => matchesIssueTypeFilter(v, issueTypeFilter));
    }
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (v) =>
          v.id.toLowerCase().includes(q) ||
          (v.summary ?? v.description)?.toLowerCase().includes(q) ||
          v.packages.some((p) => p.toLowerCase().includes(q)) ||
          v.agents.some((a) => a.toLowerCase().includes(q))
      );
    }
    list = [...list].sort((a, b) => {
      let diff = 0;
      if (sortKey === "severity") {
        diff = severityRank(a.severity) - severityRank(b.severity);
      } else if (sortKey === "cvss") {
        diff = (a.cvss_score ?? 0) - (b.cvss_score ?? 0);
      } else if (sortKey === "epss") {
        diff = (a.epss_score ?? 0) - (b.epss_score ?? 0);
      } else {
        diff = a.id.localeCompare(b.id);
      }
      return sortDir === "desc" ? -diff : diff;
    });
    return list;
  }, [vulns, filter, issueTypeFilter, search, sortKey, sortDir, useServerPaging]);

  // Reset page when filters change
  useEffect(() => { setPage(1); }, [filter, issueTypeFilter, search, sortKey, sortDir, groupBy, scope, paramScan, domainFilter, providerFilter, accountFilter, environmentFilter]);

  const totalPages = useServerPaging
    ? Math.max(1, Math.ceil(findingsTotal / PAGE_SIZE))
    : Math.max(1, Math.ceil(displayed.length / PAGE_SIZE));
  const paged = useServerPaging
    ? displayed
    : displayed.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const selectedVuln = useMemo(
    () =>
      displayed.find((vuln) => vulnRowKey(vuln) === selectedId || vuln.id === selectedId) ??
      vulns.find((vuln) => vulnRowKey(vuln) === selectedId || vuln.id === selectedId) ??
      null,
    [displayed, selectedId, vulns],
  );
  const triageByKey = useMemo(() => {
    const rows = new Map<string, FindingTriageItem>();
    for (const row of triageRows) {
      rows.set(triageKey(row.vulnerability_id, row.package), row);
    }
    return rows;
  }, [triageRows]);
  const vexEligibleCount = triageRows.filter((row) => row.vex_eligible).length;

  // Group displayed vulns
  const grouped = useMemo(() => {
    if (groupBy === "none") return null;

    const groups = new Map<string, EnrichedVuln[]>();
    for (const v of displayed) {
      let keys: string[] = [];
      if (groupBy === "package") keys = v.packages;
      else if (groupBy === "agent") keys = v.agents;
      else if (groupBy === "severity") keys = [v.severity];

      for (const key of keys) {
        const existing = groups.get(key) ?? [];
        existing.push(v);
        groups.set(key, existing);
      }
    }

    // Sort groups: by count descending
    return Array.from(groups.entries()).sort((a, b) => b[1].length - a[1].length);
  }, [displayed, groupBy]);

  // Auto-hide columns that are entirely empty/N/A across the filtered set — for
  // CIS/misconfiguration scans CVSS, EPSS, Packages and Fix are pure noise.
  const visibleColumns = useMemo(() => computeFindingColumns(displayed), [displayed]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of vulns) {
      const s = v.severity.toLowerCase() as keyof typeof c;
      if (s in c) c[s]++;
    }
    return c;
  }, [vulns]);

  const findingsTotalLabel = formatFindingsTotal(
    findingsTotal,
    useServerPaging && findingsTotalApproximate,
  );

  const cloudScopeActive = Boolean(providerFilter.trim() || accountFilter.trim() || environmentFilter.trim());

  const FILTERS: { key: SeverityFilter; label: string; color: string }[] = [
    {
      key: "all",
      label: `All (${useServerPaging ? findingsTotalLabel : vulns.length})`,
      color: "text-[var(--text-secondary)]",
    },
    { key: "critical", label: `Critical${useServerPaging ? "" : ` (${counts.critical})`}`, color: "text-red-400" },
    { key: "high",     label: `High${useServerPaging ? "" : ` (${counts.high})`}`,         color: "text-orange-400" },
    { key: "medium",   label: `Medium${useServerPaging ? "" : ` (${counts.medium})`}`,     color: "text-yellow-400" },
    { key: "low",      label: `Low${useServerPaging ? "" : ` (${counts.low})`}`,           color: "text-blue-400" },
  ];

  const GROUP_OPTIONS: { key: GroupKey; label: string; icon: ElementType }[] = [
    { key: "none", label: "Flat", icon: Layers },
    { key: "severity", label: "Severity", icon: Bug },
    { key: "package", label: "Package", icon: Package },
    { key: "agent", label: "Agent", icon: Server },
  ];

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="command"
        title="Findings"
        subtitle={findingsPageSubtitle(
          lens,
          `${useServerPaging ? findingsTotalLabel : vulns.length} findings`,
          scope === "latest"
            ? paramScan
              ? `from scan ${paramScan.slice(0, 8)}.`
              : "from the latest completed scan."
            : "aggregated across completed scans.",
        )}
        scopeChip={
          <span className="inline-flex items-center rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-0.5 text-[11px] font-medium text-cyan-200">
            Shared · Engineering &amp; Compliance
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
                  className="flex items-center gap-1.5 rounded-lg border border-emerald-900 bg-emerald-950/40 px-3 py-1.5 text-sm font-medium text-emerald-300 transition-colors hover:bg-emerald-950/70 disabled:cursor-not-allowed disabled:opacity-50"
                  title={
                    vexEligibleCount > 0
                      ? "Export signed OpenVEX JSON for findings triaged as not_affected"
                      : "Mark a finding not_affected with justification to enable OpenVEX export"
                  }
                >
                  {vexExporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ClipboardCheck className="h-3.5 w-3.5" />}
                  Export OpenVEX
                </button>
                <button
                  onClick={() => downloadJson(displayed, `findings-${new Date().toISOString().slice(0, 10)}.json`)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--surface-elevated)] hover:bg-[var(--surface-muted)] border border-[var(--border-subtle)] text-[var(--text-secondary)] text-sm font-medium rounded-lg transition-colors"
                  title="Export filtered findings as JSON"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export JSON
                </button>
              </>
            ) : null}
          </div>
        }
      />
      <p className="text-xs text-[color:var(--text-tertiary)]">{lensHint}</p>

      {triageError && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-sm text-amber-200">
          {triageError}
        </div>
      )}

      {loading && (
        <PageLoadingState
          title="Loading scan summaries"
          detail="Fetching completed scan jobs before loading vulnerability and graph-backed finding evidence."
          data-testid="findings-loading-state"
        />
      )}
      {!loading && detailLoading && vulns.length === 0 && (
        <PageLoadingState
          title={scope === "latest" ? "Loading latest scan" : "Aggregating completed scans"}
          detail="Resolving vulnerability records, affected packages, agents, reachability, and remediation links."
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
            "Use all completed scans when you need aggregate evidence across jobs.",
          ]}
          command="agent-bom agents --demo --offline"
          actions={FIRST_SCAN_ACTIONS}
          data-testid="findings-empty-state"
        />
      )}

      {!error && vulns.length > 0 && (
        <>
          {/* Controls */}
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--background)]/70 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-sm font-semibold text-[var(--foreground)]">{findingsQueueTitle(lens)}</h2>
                <p className="mt-1 text-xs text-[var(--text-tertiary)]">{findingsQueueDetail(lens)}</p>
              </div>
              <div className="flex flex-wrap gap-2 text-xs text-[var(--text-tertiary)]">
                <span className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-1">{PAGE_SIZE} per page</span>
                <span className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-1">{displayed.length} filtered</span>
                <span
                  className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-1"
                  title="OpenVEX export is available after a finding is triaged as not_affected with justification"
                >
                  {vexEligibleCount} OpenVEX-ready
                </span>
                {lens === "trust" ? (
                  <a
                    href="/compliance"
                    className="rounded-full border border-emerald-900/50 bg-emerald-950/30 px-2 py-1 text-emerald-300 hover:bg-emerald-950/50"
                  >
                    Trust center
                  </a>
                ) : (
                  <a
                    href="/remediation"
                    className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface)] px-2 py-1 hover:border-[var(--border-subtle)] hover:text-[var(--text-secondary)]"
                  >
                    Remediation
                  </a>
                )}
              </div>
            </div>

            {/* Issue type + severity filters */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex flex-col gap-2">
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
                          ? "border-cyan-700 bg-cyan-950/40 text-cyan-200"
                          : "border-[var(--border-subtle)] text-[var(--text-tertiary)] hover:border-[var(--border-subtle)] hover:text-[var(--text-secondary)]"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  <span className="mr-1 text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]">Severity</span>
                  {FILTERS?.map(({ key, label, color }) => (
                    <button
                      key={key}
                      onClick={() => setFilter(key)}
                      className={`rounded-md border px-3 py-1 text-xs font-medium transition-colors ${
                        filter === key
                          ? `${color} border-[var(--border-strong)] bg-[var(--surface-elevated)]`
                          : "text-[var(--text-tertiary)] border-[var(--border-subtle)] hover:border-[var(--border-subtle)] hover:text-[var(--text-secondary)]"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <input
                type="text"
                placeholder={findingsSearchPlaceholder(lens)}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full sm:w-64 bg-[var(--surface)] border border-[var(--border-subtle)] rounded-lg px-3 py-1.5 text-sm text-[var(--foreground)] placeholder-[var(--text-tertiary)] focus:outline-none focus:border-[var(--border-strong)]"
              />
            </div>

            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-wide font-medium">Scope</span>
                <select
                  value={scope}
                  onChange={(e) => setScope(e.target.value as ScanScope)}
                  className="bg-[var(--surface)] border border-[var(--border-subtle)] rounded-lg px-3 py-1.5 text-sm text-[var(--foreground)] focus:outline-none focus:border-[var(--border-strong)]"
                >
                  <option value="latest">Latest completed scan</option>
                  <option value="all">All completed scans</option>
                </select>
              </div>
              <p className="text-xs text-[var(--text-tertiary)]">
                Default stays scoped for speed. Expand to all scans only when you need history-wide findings aggregation.
              </p>
            </div>

            {/* Security domain + cloud scope facets (issue #3946). Design-token
                styled so both themes read correctly; URL-synced via state. */}
            <div className="flex flex-col gap-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3">
              <div className="flex flex-wrap items-center gap-1">
                <span className="mr-1 text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                  Domain
                </span>
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
              <div className="flex flex-wrap items-end gap-3">
                <label className="flex flex-col gap-1">
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
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Account</span>
                  <input
                    type="text"
                    placeholder="e.g. aws:123456789012"
                    value={accountFilter}
                    onChange={(e) => setAccountFilter(e.target.value)}
                    className="w-52 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-1.5 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Environment</span>
                  <input
                    type="text"
                    placeholder="e.g. prod"
                    value={environmentFilter}
                    onChange={(e) => setEnvironmentFilter(e.target.value)}
                    className="w-40 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-1.5 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none"
                  />
                </label>
                {(cloudScopeActive || domainFilter !== "all") && (
                  <button
                    type="button"
                    onClick={() => {
                      setDomainFilter("all");
                      setProviderFilter("");
                      setAccountFilter("");
                      setEnvironmentFilter("");
                    }}
                    className="rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
                  >
                    Clear scope
                  </button>
                )}
              </div>
            </div>

            {detailLoading && vulns.length > 0 && (
              <div className="flex items-center gap-2 text-xs text-[var(--text-tertiary)]">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                {scope === "latest" ? "Refreshing latest scan..." : "Refreshing historical aggregation..."}
              </div>
            )}

            {/* Group by */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-wide font-medium">Group by</span>
              {GROUP_OPTIONS?.map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => setGroupBy(key)}
                  className={`flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border transition-colors ${
                    groupBy === key
                      ? "text-[var(--foreground)] border-[var(--border-strong)] bg-[var(--surface-elevated)]"
                      : "text-[var(--text-tertiary)] border-[var(--border-subtle)] hover:border-[var(--border-subtle)] hover:text-[var(--text-secondary)]"
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Grouped view */}
          {grouped ? (
            <div className="space-y-6">
              {grouped?.map(([groupLabel, groupVulns]) => {
                // Per-group windowing for the grouped view (#1955 vulns
                // half). The flat path was already paginated via
                // `paged`; the grouped path used to render every vuln in
                // every group flat, which collapsed UX on group-by-package
                // for tenants with hundreds of CVEs per package. Cap each
                // group at PAGE_SIZE and surface a remaining-count line
                // so users know they're seeing a slice.
                const visibleGroupVulns = groupVulns.slice(0, PAGE_SIZE);
                const groupOverflow = groupVulns.length - visibleGroupVulns.length;
                const collapsed = collapsedGroups.has(groupLabel);
                return (
                  <div key={groupLabel}>
                    <button
                      type="button"
                      onClick={() => toggleGroup(groupLabel)}
                      aria-expanded={!collapsed}
                      className="flex w-full items-center gap-2 mb-2 text-left transition-colors group"
                    >
                      {collapsed ? (
                        <ChevronRight className="h-4 w-4 text-[var(--text-tertiary)] group-hover:text-[var(--text-secondary)]" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-[var(--text-tertiary)] group-hover:text-[var(--text-secondary)]" />
                      )}
                      <h3 className="text-sm font-semibold text-[var(--text-secondary)]">{groupLabel}</h3>
                      <span className="text-xs font-mono text-[var(--text-tertiary)] bg-[var(--surface-elevated)] rounded px-1.5 py-0.5">
                        {groupVulns.length}
                      </span>
                    </button>
                    {!collapsed && (
                      <>
                        <FindingsQueueTable
                          vulns={visibleGroupVulns}
                          sortKey={sortKey}
                          sortDir={sortDir}
                          handleSort={handleSort}
                          suppressed={suppressed}
                          onMarkFP={handleMarkFP}
                          selectedId={selectedId}
                          onSelect={setSelectedId}
                          showLifecycle={showLifecycleColumns}
                          columns={visibleColumns}
                        />
                        {groupOverflow > 0 && (
                          <p className="mt-2 text-xs text-[var(--text-tertiary)]">
                            Showing first {PAGE_SIZE} of {groupVulns.length} —
                            narrow with the search box or switch to the flat
                            view (Group: none) for full pagination.
                          </p>
                        )}
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <FindingsQueueTable
              vulns={paged}
              sortKey={sortKey}
              sortDir={sortDir}
              handleSort={handleSort}
              suppressed={suppressed}
              onMarkFP={handleMarkFP}
              selectedId={selectedId}
              onSelect={setSelectedId}
              showLifecycle={showLifecycleColumns}
              columns={visibleColumns}
            />
          )}

          {!grouped && (
            <PaginationBar
              page={page}
              totalPages={totalPages}
              totalItems={useServerPaging ? findingsTotal : displayed.length}
              itemLabel={useServerPaging && findingsTotalApproximate ? "findings (approx.)" : "findings"}
              onPrevious={() => setPage((p) => Math.max(1, p - 1))}
              onNext={() => setPage((p) => Math.min(totalPages, p + 1))}
            />
          )}

          {grouped && (
            <p className="text-xs text-[var(--text-tertiary)] text-right">
              Showing {displayed.length} of {vulns.length} findings
            </p>
          )}

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

