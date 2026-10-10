"use client";

import { useAuthState } from "@/components/auth-provider";
import { CONNECTOR_CATALOG,DEFAULT_FORM_STATE,formatWhenShort,isContinuousMode,kindOption,parseTab,SCANNABLE_PROVIDERS,scanRequestForSourceTarget,SOURCE_KIND_OPTIONS,sourceTargetSpec,type CatalogConnector,type ConnectorCategory,type FormState,type HubTab } from "@/components/connections/catalog";
import { CodingAgentDrawer,ConnectorGallery,ConnectSegment,HubTabs } from "@/components/connections/connect-workflow";
import { ConnectionDetailDrawer } from "@/components/connections/connection-detail";
import { AddConnectionWizard } from "@/components/connections/connection-wizard";
import { summarizeProviders } from "@/components/connections/display";
import { SourceDrawer } from "@/components/connections/source-detail";
import { SourcesSegment } from "@/components/connections/sources-workflow";
import { EndpointConnectionsPanel } from "@/components/endpoint-connections";
import { PageLaneHeader } from "@/components/page-lane";
import { PermissionDeniedNotice } from "@/components/role-access";
import { useDemoMode } from "@/hooks/use-demo-mode";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import {
  api,
  type CloudConnectionRecord,
  type CloudConnectionScanResponse,
  type CloudConnectionTestResponse,
  type ConnectorHealthResponse,
  type DiscoveryProvidersResponse,
  type ScanSchedule,
  type SourceCreateRequest,
  type SourceKind,
  type SourceRecord
} from "@/lib/api";
import {
  buildUnifiedRows,
  categoryCounts,
  filterUnifiedRows,
  statusOptions,
  type SourceCategory,
  type UnifiedSourceRow
} from "@/lib/connections-sources";
import { deploymentModeLabel } from "@/lib/deployment-context";
import { serviceEntry } from "@/lib/service-registry";
import {
  Plus,
  RefreshCcw
} from "lucide-react";
import { useRouter,useSearchParams } from "next/navigation";
import { useCallback,useEffect,useMemo,useState } from "react";


export function ConnectionsHub() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const { hasCapability, session } = useAuthState();
  const { counts } = useDeploymentContext();
  const { isDemoMode } = useDemoMode();
  const managedTrialSession = Boolean(
    session?.managed_trial_mode || session?.auth_method === "managed_trial_oidc",
  );
  const managedTrialEnvelope = session?.managed_trial_envelope ?? null;
  const canManage = hasCapability("scan.run");
  const canManageSources = !managedTrialSession && hasCapability("sources.manage");
  const canRunScans = hasCapability("scan.run");
  const canUpdateConnections = canManage && !managedTrialSession;
  const canDeleteConnections = canManage && !managedTrialSession;
  const canRunSources = !managedTrialSession && canRunScans;
  const canDeleteSources = !managedTrialSession && session?.role === "admin";
  const canManageFleet = !managedTrialSession && hasCapability("fleet.manage");
  const registryCloudService = serviceEntry(counts?.services, "cloud_accounts");
  const dataSourcesService = serviceEntry(counts?.services, "data_sources");

  // Cloud connections.
  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [connectionsSchedulerEnabled, setConnectionsSchedulerEnabled] = useState(false);
  const [workloadAuthModes, setWorkloadAuthModes] = useState<Record<string, string[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardProvider, setWizardProvider] = useState<string | undefined>(undefined);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, CloudConnectionScanResponse>>({});
  const [scanErrors, setScanErrors] = useState<Record<string, string>>({});
  const [testResults, setTestResults] = useState<Record<string, CloudConnectionTestResponse>>({});
  const [scheduleErrors, setScheduleErrors] = useState<Record<string, string>>({});

  // Registered sources + control-plane source state.
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const [sourcesUnavailable, setSourcesUnavailable] = useState(false);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [schedulesUnavailable, setSchedulesUnavailable] = useState(false);
  const [connectorHealth, setConnectorHealth] = useState<ConnectorHealthResponse[]>([]);
  const [connectorHealthUnavailable, setConnectorHealthUnavailable] = useState(false);
  const [providerContracts, setProviderContracts] = useState<DiscoveryProvidersResponse | null>(null);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const [busySourceId, setBusySourceId] = useState<string | null>(null);
  const [busyScheduleId, setBusyScheduleId] = useState<string | null>(null);
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [formState, setFormState] = useState<FormState>(DEFAULT_FORM_STATE);
  const [submitting, setSubmitting] = useState(false);
  const [submittingSchedule, setSubmittingSchedule] = useState(false);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleCron, setScheduleCron] = useState("0 * * * *");
  const [createNonce, setCreateNonce] = useState(0);
  const [syncingFleet, setSyncingFleet] = useState(false);
  const [fleetSyncSummary, setFleetSyncSummary] = useState<string | null>(null);

  // Connect gallery + coding-agent.
  const [galleryCategory, setGalleryCategory] = useState<ConnectorCategory | "all">("all");
  const [gallerySearch, setGallerySearch] = useState("");
  const [codingAgentOpen, setCodingAgentOpen] = useState(false);

  // Unified table filters.
  const [filterCategory, setFilterCategory] = useState<SourceCategory | "all">("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterQuery, setFilterQuery] = useState("");

  const tab = parseTab(searchParams.get("tab"), connections.length > 0 || sources.length > 0);

  const setTab = useCallback(
    (next: HubTab) => {
      router.replace(`/connections?tab=${next}`);
    },
    [router],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listCloudConnections();
      setConnections(result.connections);
      const advertised = "workload_auth_modes" in result ? result.workload_auth_modes : null;
      const modes: Record<string, string[]> = {};
      if (advertised && typeof advertised === "object") {
        for (const [provider, values] of Object.entries(advertised)) {
          if (!Array.isArray(values)) continue;
          modes[provider] = values.filter((value): value is string => typeof value === "string" &&
            (provider === "azure" ? ["managed_identity", "workload_identity"].includes(value) : ["gcp", "snowflake"].includes(provider) && value === "workload_identity"));
        }
      }
      setWorkloadAuthModes(modes);
      setConnectionsSchedulerEnabled(Boolean(result.connections_scheduler_enabled));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load cloud connections.");
      setConnections([]);
      setWorkloadAuthModes({});
      setConnectionsSchedulerEnabled(false);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshSources = useCallback(async () => {
    setSourcesLoading(true);
    try {
      const [connectorsResult, schedulesResult, sourcesResult, providerContractsResult] =
        await Promise.allSettled([
          api.listConnectors(),
          api.listSchedules(),
          api.listSources(),
          api.listDiscoveryProviders(),
        ]);

      if (sourcesResult.status === "fulfilled") {
        setSources(sourcesResult.value.sources ?? []);
        setSourcesUnavailable(false);
      } else {
        setSources([]);
        setSourcesUnavailable(true);
      }

      if (providerContractsResult.status === "fulfilled") {
        setProviderContracts(providerContractsResult.value);
      } else {
        setProviderContracts(null);
      }

      if (schedulesResult.status === "fulfilled") {
        const sorted = [...schedulesResult.value].sort((left, right) => {
          const leftTime = left.next_run ? Date.parse(left.next_run) : Number.POSITIVE_INFINITY;
          const rightTime = right.next_run ? Date.parse(right.next_run) : Number.POSITIVE_INFINITY;
          return leftTime - rightTime;
        });
        setSchedules(sorted);
        setSchedulesUnavailable(false);
      } else {
        setSchedules([]);
        setSchedulesUnavailable(true);
      }

      if (connectorsResult.status === "fulfilled") {
        const healthResults = await Promise.allSettled(
          connectorsResult.value.connectors.map((name) => api.getConnectorHealth(name)),
        );
        setConnectorHealth(
          healthResults.flatMap((result) => (result.status === "fulfilled" ? [result.value] : [])),
        );
        setConnectorHealthUnavailable(healthResults.some((result) => result.status === "rejected"));
      } else {
        setConnectorHealth([]);
        setConnectorHealthUnavailable(true);
      }
    } finally {
      setSourcesLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    void refreshSources();
  }, [refresh, refreshSources]);

  const refreshAll = useCallback(() => {
    void refresh();
    void refreshSources();
  }, [refresh, refreshSources]);

  const openWizard = useCallback((provider?: string) => {
    if (
      !canManage ||
      (managedTrialSession &&
        provider != null &&
        !managedTrialEnvelope?.providers.includes(provider))
    ) return;
    setWizardProvider(provider);
    setWizardOpen(true);
  }, [canManage, managedTrialEnvelope, managedTrialSession]);

  const handleCreated = useCallback(
    (created: CloudConnectionRecord) => {
      // The connection now exists; the wizard stays open on its Verify step so the
      // operator sees the live connectivity/permission check before closing. We
      // refresh the background list so the new row appears immediately.
      setMessage(`Connected ${created.display_name}.`);
      void refresh();
    },
    [refresh],
  );

  const handleWizardClose = useCallback(() => {
    setWizardOpen(false);
    // Pick up any status change from an in-wizard verify / first scan.
    void refresh();
  }, [refresh]);

  const handleRegisterSource = useCallback(
    (kind: SourceKind) => {
      if (!canManageSources) return;
      setFormState((current) => ({ ...current, kind, target: "" }));
      setCreateNonce((n) => n + 1);
      setTab("sources");
    },
    [canManageSources, setTab],
  );

  async function handleScan(connection: CloudConnectionRecord) {
    if (!canRunScans || connection.status !== "active") return;
    setBusyId(connection.id);
    setMessage(null);
    setScanErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const result = await api.scanCloudConnection(connection.id);
      setScanResults((prev) => ({ ...prev, [connection.id]: result }));
      setMessage(`${connection.display_name} scan queued.`);
      await refresh();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Scan failed.";
      setScanErrors((prev) => ({ ...prev, [connection.id]: detail }));
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleTest(connection: CloudConnectionRecord) {
    if (!canManage) return;
    setBusyId(connection.id);
    setMessage(null);
    setScanErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const result = await api.testCloudConnection(connection.id);
      setTestResults((prev) => ({ ...prev, [connection.id]: result }));
      setMessage(`${connection.display_name} read-only provider capability verified.`);
      await refresh();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Connection test failed.";
      setScanErrors((prev) => ({ ...prev, [connection.id]: detail }));
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(connection: CloudConnectionRecord) {
    if (!canDeleteConnections) return;
    if (!window.confirm(`Delete ${connection.display_name}? The encrypted connection credential will be removed.`)) return;
    setBusyId(connection.id);
    setMessage(null);
    try {
      await api.deleteCloudConnection(connection.id);
      setDetailId(null);
      setScanResults((prev) => {
        const next = { ...prev };
        delete next[connection.id];
        return next;
      });
      setMessage(`Removed ${connection.display_name}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete connection.");
    } finally {
      setBusyId(null);
    }
  }

  async function handleScheduleChange(connection: CloudConnectionRecord, value: string) {
    if (!canUpdateConnections) return;
    const scanIntervalMinutes = value === "" ? null : Number(value);
    setScheduleErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const updated = await api.updateCloudConnection(connection.id, {
        scan_interval_minutes: scanIntervalMinutes,
      });
      setConnections((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
      setMessage(`${updated.display_name} scan schedule updated.`);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Failed to update schedule.";
      setScheduleErrors((prev) => ({ ...prev, [connection.id]: detail }));
    }
  }

  async function handleScanModeChange(connection: CloudConnectionRecord, continuous: boolean) {
    if (!canUpdateConnections) return;
    setScheduleErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const updated = await api.updateCloudConnection(connection.id, {
        scan_mode: continuous ? "continuous" : "full",
      });
      setConnections((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
      setMessage(`${updated.display_name} scan mode updated.`);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Failed to update scan mode.";
      setScheduleErrors((prev) => ({ ...prev, [connection.id]: detail }));
    }
  }

  async function handleFleetSync() {
    if (!canManageFleet) return;
    setSyncingFleet(true);
    setFleetSyncSummary(null);
    try {
      const result = await api.syncFleet();
      setFleetSyncSummary(`${result.synced} synced · ${result.new} new · ${result.updated} updated`);
      await refreshSources();
    } catch (err) {
      setFleetSyncSummary(err instanceof Error ? err.message : "Fleet sync failed");
    } finally {
      setSyncingFleet(false);
    }
  }

  function updateForm<K extends keyof FormState>(field: K, value: FormState[K]) {
    setFormState((current) => ({
      ...current,
      [field]: value,
      ...(field === "kind" ? { target: "" } : {}),
    }));
  }

  async function handleCreateSource(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManageSources) return;
    setFormMessage(null);
    const selected = kindOption(formState.kind) ?? SOURCE_KIND_OPTIONS[0]!;

    const payload: SourceCreateRequest = {
      display_name: formState.display_name.trim(),
      kind: formState.kind,
      description: formState.description.trim(),
      owner: formState.owner.trim(),
      enabled: true,
      credential_mode: "none",
    };

    if (!payload.display_name) {
      setFormMessage("Display name is required.");
      return;
    }
    const targetSpec = sourceTargetSpec(formState.kind);
    if (targetSpec) {
      const target = formState.target.trim();
      if (!target) {
        setFormMessage(targetSpec.requiredMessage);
        return;
      }
      payload.config = { scan_request: scanRequestForSourceTarget(formState.kind, target) };
    } else if (formState.kind === "scan.cloud") {
      setFormMessage("Cloud accounts use the read-only cloud account connection workflow.");
      return;
    } else if (formState.kind === "ingest.artifact_import") {
      setFormMessage("Artifact sources require an API-side inventory, SBOM, external_scan, or VEX path.");
      return;
    }
    if (selected.mode === "Read-only connector") {
      if (!formState.connector_name.trim()) {
        setFormMessage("Connector-backed sources require a connector name.");
        return;
      }
      payload.connector_name = formState.connector_name.trim();
    }

    setSubmitting(true);
    try {
      await api.createSource(payload);
      setFormMessage(`Created source ${payload.display_name}.`);
      setFormState({ ...DEFAULT_FORM_STATE, kind: payload.kind });
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Failed to create source.");
    } finally {
      setSubmitting(false);
    }
  }

  async function runSourceAction(sourceId: string, action: "test" | "run" | "delete") {
    const allowed =
      action === "run"
        ? canRunSources
        : action === "delete"
          ? canDeleteSources
          : canManageSources;
    if (!allowed) return;
    if (action === "delete") {
      const source = sourceById.get(sourceId);
      const label = source?.display_name || "this source";
      if (!window.confirm(`Delete ${label}? Its registration and linked recurring schedules will be disabled and removed.`)) return;
    }
    setBusySourceId(sourceId);
    setFormMessage(null);
    try {
      if (action === "test") {
        const result = await api.testSource(sourceId);
        setFormMessage(result.message);
      } else if (action === "run") {
        const result = await api.runSource(sourceId);
        setFormMessage(`Queued job ${result.job_id}.`);
      } else {
        await api.deleteSource(sourceId);
        setFormMessage("Source deleted.");
        setSelectedSourceId(null);
      }
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Source action failed.");
    } finally {
      setBusySourceId(null);
    }
  }

  async function handleCreateSchedule(event: React.FormEvent<HTMLFormElement>, source: SourceRecord) {
    event.preventDefault();
    if (!canManageSources) return;
    setFormMessage(null);
    if (!scheduleCron.trim()) {
      setFormMessage("Cron expression is required.");
      return;
    }
    const name = scheduleName.trim() || `${source.display_name} recurring run`;
    setSubmittingSchedule(true);
    try {
      await api.createSchedule({
        name,
        cron_expression: scheduleCron.trim(),
        enabled: true,
        scan_config: { source_id: source.source_id },
      });
      setFormMessage(`Created schedule ${name}.`);
      setScheduleName("");
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Failed to create schedule.");
    } finally {
      setSubmittingSchedule(false);
    }
  }

  async function runScheduleAction(scheduleId: string, action: "toggle" | "delete") {
    if (!canManageSources) return;
    setBusyScheduleId(scheduleId);
    setFormMessage(null);
    try {
      if (action === "toggle") {
        const updated = await api.toggleSchedule(scheduleId);
        setFormMessage(`${updated.name} ${updated.enabled ? "enabled" : "paused"}.`);
      } else {
        await api.deleteSchedule(scheduleId);
        setFormMessage("Schedule deleted.");
      }
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Schedule action failed.");
    } finally {
      setBusyScheduleId(null);
    }
  }

  // Derived data.
  const lastAccountScan = useMemo(() => {
    const stamps = connections
      .map((c) => c.last_scan_at)
      .filter((v): v is string => Boolean(v))
      .sort((a, b) => b.localeCompare(a));
    return stamps[0] ?? null;
  }, [connections]);
  // The registry also counts cloud scopes evidenced only by pushed CLI scans
  // (no brokered connection), so the banner takes the larger count and the
  // later of the two scan times.
  const cloudAccountCount = Math.max(connections.length, registryCloudService.count);
  const lastCloudScan = [lastAccountScan, registryCloudService.last_scan_at ?? null]
    .filter((v): v is string => Boolean(v))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
  const hasConnections = connections.length > 0;
  // The direct connection inventory is the most specific source of truth for
  // this page. Older posture responses can omit service-registry state, so do
  // not tell an operator that cloud accounts are locked while rendering a
  // connected account beside that banner.
  const cloudService =
    hasConnections && registryCloudService.state === "locked"
      ? {
          ...registryCloudService,
          state: lastAccountScan ? ("live" as const) : ("connected" as const),
          count: Math.max(registryCloudService.count, connections.length),
        }
      : registryCloudService;

  const connectedByProvider = useMemo(() => {
    const map: Record<string, number> = {};
    for (const connection of connections) {
      map[connection.provider] = (map[connection.provider] ?? 0) + 1;
    }
    return map;
  }, [connections]);

  const sourceCountByKind = useMemo(() => {
    const map: Record<string, number> = {};
    for (const source of sources) {
      map[source.kind] = (map[source.kind] ?? 0) + 1;
    }
    return map;
  }, [sources]);

  const scheduleCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const schedule of schedules) {
      const linked =
        typeof schedule.scan_config?.source_id === "string"
          ? String(schedule.scan_config.source_id)
          : "";
      if (!linked) continue;
      map.set(linked, (map.get(linked) ?? 0) + 1);
    }
    return map;
  }, [schedules]);

  const schedulesBySource = useMemo(() => {
    const map = new Map<string, ScanSchedule[]>();
    for (const schedule of schedules) {
      const linked =
        typeof schedule.scan_config?.source_id === "string"
          ? String(schedule.scan_config.source_id)
          : "";
      if (!linked) continue;
      const list = map.get(linked) ?? [];
      list.push(schedule);
      map.set(linked, list);
    }
    return map;
  }, [schedules]);

  const unifiedRows = useMemo(
    () => buildUnifiedRows(connections, sources, scheduleCounts),
    [connections, sources, scheduleCounts],
  );
  const rowCategoryCounts = useMemo(() => categoryCounts(unifiedRows), [unifiedRows]);
  const rowStatusOptions = useMemo(() => statusOptions(unifiedRows), [unifiedRows]);
  const filteredRows = useMemo(
    () =>
      filterUnifiedRows(unifiedRows, {
        category: filterCategory,
        status: filterStatus,
        query: filterQuery,
      }),
    [unifiedRows, filterCategory, filterStatus, filterQuery],
  );

  const connectionById = useMemo(() => {
    const map = new Map<string, CloudConnectionRecord>();
    for (const connection of connections) map.set(connection.id, connection);
    return map;
  }, [connections]);
  const sourceById = useMemo(() => {
    const map = new Map<string, SourceRecord>();
    for (const source of sources) map.set(source.source_id, source);
    return map;
  }, [sources]);

  const connectorConnectedCount = useCallback(
    (connector: CatalogConnector): number => {
      if (connector.action.type === "cloud") {
        return connectedByProvider[connector.action.provider] ?? 0;
      }
      if (connector.action.type === "source") {
        return sourceCountByKind[connector.action.sourceKind] ?? 0;
      }
      return 0;
    },
    [connectedByProvider, sourceCountByKind],
  );

  const connectorNames = useMemo(
    () => connectorHealth.map((connector) => connector.connector).sort((l, r) => l.localeCompare(r)),
    [connectorHealth],
  );
  const healthyConnectors = useMemo(
    () => connectorHealth.filter((connector) => connector.state === "healthy").length,
    [connectorHealth],
  );
  const providerSummary = useMemo(() => summarizeProviders(providerContracts), [providerContracts]);

  const selectedSource = selectedSourceId ? sourceById.get(selectedSourceId) ?? null : null;

  const openRow = useCallback((row: UnifiedSourceRow) => {
    if (row.origin === "cloud" && row.connectionId) {
      setDetailId(row.connectionId);
    } else if (row.origin === "source" && row.sourceId) {
      setSelectedSourceId(row.sourceId);
    }
  }, []);

  const gallery = (
    <ConnectorGallery
      activeCategory={galleryCategory}
      onCategoryChange={setGalleryCategory}
      search={gallerySearch}
      onSearchChange={setGallerySearch}
      connectedCountFor={connectorConnectedCount}
      canManage={canManage}
      canManageSources={canManageSources}
      managedTrial={managedTrialSession}
      managedTrialProviders={managedTrialEnvelope?.providers ?? null}
      onConnectCloud={openWizard}
      onRegisterSource={handleRegisterSource}
      onConnectCodingAgent={() => setCodingAgentOpen(true)}
    />
  );

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="cloud-data"
        title="Connections"
        subtitle="Connect cloud, code, AI, data and endpoints, then inspect scoped evidence."
        scopeChip={
          <span className="inline-flex items-center rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 text-[11px] font-medium text-purple-700 dark:text-purple-200">
            {deploymentModeLabel(counts?.deployment_mode)} · brokered read-only
          </span>
        }
        actions={tab === "endpoints" ? undefined :
          <>
            <button
              onClick={refreshAll}
              className="inline-flex items-center gap-2 rounded-xl border border-outline bg-surface-muted px-4 py-2 text-sm text-foreground transition hover:border-outline-strong"
            >
              <RefreshCcw className="h-4 w-4" />
              Refresh
            </button>
            <button
              onClick={() => openWizard()}
              disabled={!canManage}
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Plus className="h-4 w-4" />
              Add cloud account
            </button>
          </>
        }
        banner={tab === "endpoints" ? undefined :
          <dl aria-label="Source status" className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
            <div className="flex gap-2"><dt className="text-ink-secondary">Cloud accounts</dt><dd className="font-semibold tabular-nums">{loading ? "…" : error ? "Unavailable" : cloudAccountCount}</dd></div>
            <div className="flex gap-2"><dt className="text-ink-secondary">Registered sources</dt><dd className="font-semibold tabular-nums">{sourcesLoading ? "…" : sourcesUnavailable ? "Unavailable" : sources.length}</dd></div>
            <div className="flex gap-2"><dt className="text-ink-secondary">Last cloud scan</dt><dd>{loading ? "…" : error ? "Unavailable" : formatWhenShort(lastCloudScan)}</dd></div>
          </dl>
        }
      />

      <HubTabs tab={tab} onChange={setTab} connectCount={CONNECTOR_CATALOG.length} sourceCount={unifiedRows.length} />

      {message ? <p className="text-sm text-emerald-400">{message}</p> : null}
      {tab !== "endpoints" && <div className="grid gap-3 lg:grid-cols-2">
      {!connectionsSchedulerEnabled &&
      connections.some(
        (connection) => connection.scan_interval_minutes || isContinuousMode(connection),
      ) ? (
        <div
          role="status"
          data-testid="connections-scheduler-disabled-banner"
          className="rounded-xl border border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/20 px-4 py-3 text-sm text-amber-800 dark:text-amber-100"
        >
          <details>
          <summary className="w-fit cursor-pointer font-medium">Scheduler disabled on this control plane</summary>
          <p className="mt-1 text-xs leading-5 text-amber-900/80 dark:text-amber-100/80">
            One or more connections use a scan interval or Continuous mode, but neither recurring
            scans nor continuous event drains run until{" "}
            <code className="font-mono text-[11px]">AGENT_BOM_CONNECTIONS_SCHEDULER=1</code> (or Helm{" "}
            <code className="font-mono text-[11px]">controlPlane.connectionsScheduler.enabled</code>) is
            turned on. Continuous mode additionally needs a provider event queue env.
          </p>
          </details>
        </div>
      ) : null}
      {!canManage ? (
        <PermissionDeniedNotice
          session={session}
          needed="analyst"
          action="connect a cloud account, run a scan, or delete a connection"
        />
      ) : null}

      </div>}

      {tab === "endpoints" ? (
        <EndpointConnectionsPanel key={session?.tenant_id ?? "unauthenticated"} canManage={session?.role === "admin" && !managedTrialSession} demo={isDemoMode} />
      ) : tab === "connect" ? (
        <ConnectSegment
          session={session}
          counts={counts}
          cloudService={cloudService}
          connections={connections}
          connectionsCount={connections.length}
          canManage={canManage}
          gallery={gallery}
          onConnect={() => openWizard("aws")}
        />
      ) : (
        <SourcesSegment
          rows={filteredRows}
          totalRows={unifiedRows.length}
          categoryCountsMap={rowCategoryCounts}
          statusChoices={rowStatusOptions}
          filterCategory={filterCategory}
          onFilterCategory={setFilterCategory}
          filterStatus={filterStatus}
          onFilterStatus={setFilterStatus}
          filterQuery={filterQuery}
          onFilterQuery={setFilterQuery}
          loading={loading || sourcesLoading}
          error={error ?? (sourcesUnavailable ? "Registered sources are unavailable." : null)}
          onRetry={refreshAll}
          onRowOpen={openRow}
          connectionById={connectionById}
          busyId={busyId}
          canManage={canManage}
          canUpdateConnections={canUpdateConnections}
          canDeleteConnections={canDeleteConnections}
          onCloudTest={(c) => void handleTest(c)}
          onCloudScan={(c) => void handleScan(c)}
          onCloudDelete={(c) => void handleDelete(c)}
          onCloudScheduleChange={(c, v) => void handleScheduleChange(c, v)}
          onCloudScanModeChange={(c, continuous) => void handleScanModeChange(c, continuous)}
          isDemoMode={isDemoMode}
          dataSourcesService={dataSourcesService}
          servicesRegistry={counts?.services}
          formMessage={formMessage}
          fleetSyncSummary={fleetSyncSummary}
          syncingFleet={syncingFleet}
          canManageFleet={canManageFleet}
          onFleetSync={() => void handleFleetSync()}
          connectorHealth={connectorHealth}
          connectorHealthUnavailable={connectorHealthUnavailable}
          connectorNames={connectorNames}
          healthyConnectors={healthyConnectors}
          providerContracts={providerContracts}
          providerSummary={providerSummary}
          schedulesCount={schedules.length}
          schedulesUnavailable={schedulesUnavailable}
          nextSchedule={schedules[0]?.next_run ?? null}
          canManageSources={canManageSources}
          formState={formState}
          onUpdateForm={updateForm}
          submitting={submitting}
          onCreateSource={handleCreateSource}
          createDefaultOpen={createNonce > 0 || unifiedRows.length === 0}
          createKey={`create-${createNonce}`}
          onGoConnect={() => setTab("connect")}
        />
      )}

      <ConnectionDetailDrawer
        connection={detailId ? connectionById.get(detailId) ?? null : null}
        result={detailId ? scanResults[detailId] : undefined}
        testResult={detailId ? testResults[detailId] : undefined}
        scanError={detailId ? scanErrors[detailId] : undefined}
        scheduleError={detailId ? scheduleErrors[detailId] : undefined}
        isBusy={busyId === detailId}
        canManage={canManage}
        canDelete={canDeleteConnections}
        scannable={detailId ? SCANNABLE_PROVIDERS.has(connectionById.get(detailId)?.provider ?? "") : false}
        onClose={() => setDetailId(null)}
        onTest={(connection) => void handleTest(connection)}
        onScan={(connection) => void handleScan(connection)}
        onDelete={(connection) => void handleDelete(connection)}
      />

      <SourceDrawer
        source={selectedSource}
        open={selectedSource != null}
        onClose={() => setSelectedSourceId(null)}
        schedules={selectedSource ? schedulesBySource.get(selectedSource.source_id) ?? [] : []}
        busySourceId={busySourceId}
        busyScheduleId={busyScheduleId}
        canManageSources={canManageSources}
        canRunScans={canRunSources}
        canDeleteSources={canDeleteSources}
        onSourceAction={runSourceAction}
        onScheduleAction={runScheduleAction}
        onCreateSchedule={handleCreateSchedule}
        submittingSchedule={submittingSchedule}
        scheduleName={scheduleName}
        scheduleCron={scheduleCron}
        onScheduleNameChange={setScheduleName}
        onScheduleCronChange={setScheduleCron}
      />

      {wizardOpen ? (
        <AddConnectionWizard
          workloadAuthModes={workloadAuthModes}
          initialProvider={wizardProvider}
          providerContracts={providerContracts}
          managedTrial={managedTrialSession}
          managedTrialEnvelope={managedTrialEnvelope}
          providerConnectionCount={
            connectedByProvider[wizardProvider ?? "aws"] ?? 0
          }
          onClose={handleWizardClose}
          onCreated={handleCreated}
        />
      ) : null}

      <CodingAgentDrawer open={codingAgentOpen} onClose={() => setCodingAgentOpen(false)} />
    </div>
  );
}
