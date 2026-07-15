"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  CalendarClock,
  FileCheck2,
  Plus,
  Radio,
  RefreshCcw,
  ServerCog,
  Shield,
  Workflow,
} from "lucide-react";

import {
  api,
  type ConnectorHealthResponse,
  type DiscoveryProviderContract,
  type DiscoveryProvidersResponse,
  type ScanSchedule,
  type SourceCreateRequest,
  type SourceKind,
  type SourceRecord,
} from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { DemoConnectCard } from "@/components/demo-mode-cta";
import { useDemoMode } from "@/hooks/use-demo-mode";
import { ServiceStateBanner, ServiceStateChip } from "@/components/service-state-chip";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { serviceEntry } from "@/lib/service-registry";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { StatStrip } from "@/components/stat-strip";
import { Collapsible } from "@/components/collapsible";
import { Drawer } from "@/components/drawer";
import { PageEmptyState } from "@/components/states/page-state";

type IngestMode = "Direct scan" | "Read-only connector" | "Pushed ingest" | "Runtime" | "Imported artifact";

interface KindOption {
  value: SourceKind;
  label: string;
  mode: IngestMode;
  detail: string;
}

interface FormState {
  display_name: string;
  kind: SourceKind;
  description: string;
  owner: string;
  connector_name: string;
}

const SOURCE_KIND_OPTIONS: KindOption[] = [
  {
    value: "scan.repo",
    label: "Repo / package scan",
    mode: "Direct scan",
    detail: "Trigger repo, package, or SBOM-oriented discovery jobs through the control plane.",
  },
  {
    value: "scan.image",
    label: "Container / image scan",
    mode: "Direct scan",
    detail: "Run image and package analysis as a queued scan job instead of from the browser.",
  },
  {
    value: "scan.iac",
    label: "IaC / cluster scan",
    mode: "Direct scan",
    detail: "Schedule Terraform, Kubernetes, and infrastructure posture scans.",
  },
  {
    value: "scan.cloud",
    label: "Cloud account scan",
    mode: "Direct scan",
    detail: "Launch cloud discovery through backend-owned jobs and read-only account access.",
  },
  {
    value: "scan.mcp_config",
    label: "MCP configuration scan",
    mode: "Direct scan",
    detail: "Discover MCP servers, tools, and agent config entry points from inventory sources.",
  },
  {
    value: "connector.cloud_read_only",
    label: "Cloud API connector",
    mode: "Read-only connector",
    detail: "Use a named backend connector to read approved cloud APIs with customer-managed credentials.",
  },
  {
    value: "connector.registry",
    label: "Registry / package connector",
    mode: "Read-only connector",
    detail: "Attach registry-style connectors and run them as first-class sources.",
  },
  {
    value: "connector.warehouse",
    label: "Warehouse / lake connector",
    mode: "Read-only connector",
    detail: "Consume inventory or security-lake evidence from the customer’s existing data platform.",
  },
  {
    value: "ingest.fleet_sync",
    label: "Fleet sync",
    mode: "Pushed ingest",
    detail: "Accept fleet inventory from authenticated push routes instead of direct browser collection.",
  },
  {
    value: "ingest.trace_push",
    label: "Trace ingest",
    mode: "Pushed ingest",
    detail: "Receive OTLP-style traces and correlate runtime evidence inside the control plane.",
  },
  {
    value: "ingest.result_push",
    label: "Result push",
    mode: "Pushed ingest",
    detail: "Store pushed findings or inventory evidence from other approved producers.",
  },
  {
    value: "ingest.artifact_import",
    label: "Artifact import",
    mode: "Imported artifact",
    detail: "Use exported SBOMs, inventories, or third-party results as a customer-approved intake path.",
  },
  {
    value: "runtime.proxy",
    label: "MCP proxy runtime",
    mode: "Runtime",
    detail: "Track runtime evidence from agent-bom proxy deployment paths in customer-controlled environments.",
  },
  {
    value: "runtime.gateway",
    label: "MCP gateway runtime",
    mode: "Runtime",
    detail: "Treat the MCP gateway as a first-class runtime source with policy-audited upstream traffic.",
  },
];

const DEFAULT_FORM_STATE: FormState = {
  display_name: "",
  kind: "scan.repo",
  description: "",
  owner: "",
  connector_name: "",
};

const SCHEDULABLE_KINDS = new Set<SourceKind>([
  "scan.repo",
  "scan.image",
  "scan.iac",
  "scan.cloud",
  "scan.mcp_config",
  "connector.cloud_read_only",
  "connector.registry",
  "connector.warehouse",
]);

const OPERATING_SURFACES = [
  {
    title: "Security graph and path analysis",
    href: "/security-graph",
    summary: "Persisted graph snapshots, attack-path focus, and blast-radius analysis across agents, servers, packages, tools, and credentials.",
    status: "Analyze",
    icon: Workflow,
  },
  {
    title: "Fleet management",
    href: "/fleet",
    summary: "Persisted fleet inventory and trust posture once the data lands in the control plane.",
    status: "Operate",
    icon: Activity,
  },
  {
    title: "Runtime proxy and alerts",
    href: "/runtime?tab=proxy",
    summary: "Live runtime enforcement, detector alerts, drift protection, and audit review for MCP and tool-call activity.",
    status: "Runtime",
    icon: Radio,
  },
  {
    title: "Gateway and policy enforcement",
    href: "/runtime?tab=gateway",
    summary: "Policy evaluation and enforcement for high-impact tool usage and approval workflows.",
    status: "Protect",
    icon: Shield,
  },
];

function formatWhen(value: string | null): string {
  if (!value) return "Not yet";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatShortId(value: string, head = 10, tail = 6): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

const PROVIDER_SCAN_MODE_PREVIEW = 3;

/** Mode dot colors — token-only so both themes track. */
const MODE_DOT: Record<IngestMode, string> = {
  "Direct scan": "var(--status-success)",
  "Read-only connector": "var(--severity-low)",
  "Pushed ingest": "var(--status-warn)",
  Runtime: "var(--severity-high)",
  "Imported artifact": "var(--text-tertiary)",
};

const STATUS_TONE: Record<string, string> = {
  healthy: "var(--status-success)",
  done: "var(--status-success)",
  active: "var(--status-success)",
  degraded: "var(--status-warn)",
  paused: "var(--status-warn)",
  pending: "var(--status-warn)",
  disabled: "var(--text-tertiary)",
  error: "var(--status-danger)",
  failed: "var(--status-danger)",
};

function statusTone(status: string): string {
  return STATUS_TONE[status.toLowerCase()] ?? "var(--accent)";
}

function ModeChip({ mode }: { mode: IngestMode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-0.5 text-[11px] font-medium text-[color:var(--text-secondary)]">
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: MODE_DOT[mode] }} aria-hidden="true" />
      {mode}
    </span>
  );
}

function StatusPill({ status }: { status: string }) {
  const tone = statusTone(status);
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]"
      style={{ color: tone }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: tone }} aria-hidden="true" />
      {status}
    </span>
  );
}

function formatMode(value: string): string {
  return value.replaceAll("_", " ");
}

function sourceEvidenceHref(source: SourceRecord, target: "jobs" | "findings" | "graph" | "compliance"): string {
  const jobId = source.last_job_id ?? "";
  if (target === "jobs" || !jobId) return `/jobs?q=${encodeURIComponent(source.source_id)}`;
  const route = target === "graph" ? "security-graph" : target;
  return `/${route}?scan=${encodeURIComponent(jobId)}`;
}

function summarizeProviders(contracts: DiscoveryProvidersResponse | null) {
  const providers = contracts?.providers ?? [];
  return {
    total: providers.length,
    readOnly: providers.filter((provider) => provider.trust_contract.read_only).length,
    scopeZero: providers.filter((provider) => provider.trust_contract.supports_scope_zero).length,
    permissionCount: providers.reduce((total, provider) => total + provider.capabilities.permissions_used.length, 0),
  };
}

export default function SourcesPage() {
  const { session, loading: authLoading, hasCapability } = useAuthState();
  const { isDemoMode } = useDemoMode();
  const { counts } = useDeploymentContext();
  const dataSourcesService = serviceEntry(counts?.services, "data_sources");
  const [connectorHealth, setConnectorHealth] = useState<ConnectorHealthResponse[]>([]);
  const [providerContracts, setProviderContracts] = useState<DiscoveryProvidersResponse | null>(null);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncingFleet, setSyncingFleet] = useState(false);
  const [fleetSyncSummary, setFleetSyncSummary] = useState<string | null>(null);
  const [formState, setFormState] = useState<FormState>(DEFAULT_FORM_STATE);
  const [submitting, setSubmitting] = useState(false);
  const [submittingSchedule, setSubmittingSchedule] = useState(false);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const [busySourceId, setBusySourceId] = useState<string | null>(null);
  const [busyScheduleId, setBusyScheduleId] = useState<string | null>(null);
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleCron, setScheduleCron] = useState("0 * * * *");

  const connectorNames = useMemo(
    () => connectorHealth.map((connector) => connector.connector).sort((left, right) => left.localeCompare(right)),
    [connectorHealth]
  );
  const selectedKind = useMemo(
    () => SOURCE_KIND_OPTIONS.find((option) => option.value === formState.kind) ?? SOURCE_KIND_OPTIONS[0]!,
    [formState.kind]
  );
  const sourceCount = sources.length;
  const healthyConnectors = useMemo(
    () => connectorHealth.filter((connector) => connector.state === "healthy").length,
    [connectorHealth]
  );
  const providerSummary = useMemo(() => summarizeProviders(providerContracts), [providerContracts]);
  const sourceIndex = useMemo(() => new Map(sources.map((source) => [source.source_id, source])), [sources]);
  const scheduleCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const schedule of schedules) {
      const linkedSourceId = typeof schedule.scan_config?.source_id === "string" ? String(schedule.scan_config.source_id) : "";
      if (!linkedSourceId) continue;
      map.set(linkedSourceId, (map.get(linkedSourceId) ?? 0) + 1);
    }
    return map;
  }, [schedules]);
  const schedulesBySource = useMemo(() => {
    const map = new Map<string, ScanSchedule[]>();
    for (const schedule of schedules) {
      const linkedSourceId = typeof schedule.scan_config?.source_id === "string" ? String(schedule.scan_config.source_id) : "";
      if (!linkedSourceId) continue;
      const list = map.get(linkedSourceId) ?? [];
      list.push(schedule);
      map.set(linkedSourceId, list);
    }
    return map;
  }, [schedules]);
  const roleSummary = session?.role_summary ?? null;
  const roleLabel = roleSummary?.display_name ?? session?.role ?? "Unknown";
  const canManageSources = hasCapability("sources.manage");
  const canRunScans = hasCapability("scan.run");
  const canManageFleet = hasCapability("fleet.manage");

  const selectedSource = selectedSourceId ? sourceIndex.get(selectedSourceId) ?? null : null;

  function updateForm<K extends keyof FormState>(field: K, value: FormState[K]) {
    setFormState((current) => ({ ...current, [field]: value }));
  }

  async function refreshControlPlane() {
    setLoading(true);
    setError(null);

    try {
      const [connectorsResult, schedulesResult, sourcesResult, providerContractsResult] = await Promise.allSettled([
        api.listConnectors(),
        api.listSchedules(),
        api.listSources(),
        api.listDiscoveryProviders(),
      ]);

      if (sourcesResult.status === "fulfilled") {
        setSources(sourcesResult.value.sources);
      } else {
        setSources([]);
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
      } else {
        setSchedules([]);
      }

      if (connectorsResult.status === "fulfilled") {
        const healthResults = await Promise.allSettled(
          connectorsResult.value.connectors.map((name) => api.getConnectorHealth(name))
        );
        const healthy = healthResults.flatMap((result) => (result.status === "fulfilled" ? [result.value] : []));
        setConnectorHealth(healthy);
      } else {
        setConnectorHealth([]);
      }

      const failures = [connectorsResult, schedulesResult, sourcesResult, providerContractsResult].filter(
        (result) => result.status === "rejected"
      );
      if (failures.length === 4) {
        setError("Failed to load control-plane source state.");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refreshControlPlane().catch((err) => {
      setError(err instanceof Error ? err.message : "Failed to load source state.");
      setLoading(false);
    });
  }, []);

  async function handleFleetSync() {
    setSyncingFleet(true);
    setFleetSyncSummary(null);
    try {
      const result = await api.syncFleet();
      setFleetSyncSummary(`${result.synced} synced · ${result.new} new · ${result.updated} updated`);
      await refreshControlPlane();
    } catch (err) {
      setFleetSyncSummary(err instanceof Error ? err.message : "Fleet sync failed");
    } finally {
      setSyncingFleet(false);
    }
  }

  async function handleCreateSource(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormMessage(null);

    const payload: SourceCreateRequest = {
      display_name: formState.display_name.trim(),
      kind: formState.kind,
      description: formState.description.trim(),
      owner: formState.owner.trim(),
      enabled: true,
      credential_mode: selectedKind.mode === "Read-only connector" ? "reference" : "none",
    };

    if (!payload.display_name) {
      setFormMessage("Display name is required.");
      return;
    }

    if (selectedKind.mode === "Read-only connector") {
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
      setFormState({
        ...DEFAULT_FORM_STATE,
        kind: payload.kind,
      });
      await refreshControlPlane();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Failed to create source.");
    } finally {
      setSubmitting(false);
    }
  }

  async function runSourceAction(sourceId: string, action: "test" | "run" | "delete") {
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
      await refreshControlPlane();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Source action failed.");
    } finally {
      setBusySourceId(null);
    }
  }

  async function handleCreateSchedule(event: React.FormEvent<HTMLFormElement>, source: SourceRecord) {
    event.preventDefault();
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
      await refreshControlPlane();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Failed to create schedule.");
    } finally {
      setSubmittingSchedule(false);
    }
  }

  async function runScheduleAction(scheduleId: string, action: "toggle" | "delete") {
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
      await refreshControlPlane();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Schedule action failed.");
    } finally {
      setBusyScheduleId(null);
    }
  }

  const columns: DataTableColumn<SourceRecord>[] = [
    {
      key: "name",
      header: "Name",
      cell: (source) => {
        const option = SOURCE_KIND_OPTIONS.find((entry) => entry.value === source.kind);
        return (
          <div className="min-w-0">
            <div className="truncate font-medium text-[color:var(--foreground)]">{source.display_name}</div>
            <div className="truncate text-xs text-[color:var(--text-tertiary)]">{option?.label ?? source.kind}</div>
          </div>
        );
      },
    },
    {
      key: "kind",
      header: "Kind",
      cell: (source) => {
        const option = SOURCE_KIND_OPTIONS.find((entry) => entry.value === source.kind);
        return <ModeChip mode={option?.mode ?? "Direct scan"} />;
      },
    },
    {
      key: "status",
      header: "Status",
      cell: (source) => <StatusPill status={source.status} />,
    },
    {
      key: "last_run",
      header: "Last run",
      cell: (source) => <span className="text-xs">{formatWhen(source.last_run_at)}</span>,
    },
    {
      key: "schedule",
      header: "Schedule",
      align: "right",
      cell: (source) => <span className="tabular-nums">{scheduleCounts.get(source.source_id) ?? 0}</span>,
    },
    {
      key: "connector",
      header: "Connector",
      cell: (source) => (
        <span className="truncate text-xs text-[color:var(--text-secondary)]">{source.connector_name || "—"}</span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">Data sources</h1>
          <p className="mt-1 text-sm text-[color:var(--text-secondary)]">
            Register scan targets, review connector health, and manage schedules.
          </p>
          <div className="mt-2">
            <ServiceStateChip
              serviceId="data_sources"
              entry={dataSourcesService}
              registry={counts?.services}
              showUnlock={false}
            />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => refreshControlPlane()}
            className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
          >
            <RefreshCcw className="h-4 w-4" />
            Refresh
          </button>
          {!isDemoMode && (
            <button
              onClick={handleFleetSync}
              disabled={syncingFleet || !canManageFleet}
              className="inline-flex items-center gap-2 rounded-lg bg-[color:var(--accent)] px-3 py-2 text-sm font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Activity className="h-4 w-4" />
              {syncingFleet ? "Syncing…" : "Fleet sync"}
            </button>
          )}
        </div>
      </header>

      {isDemoMode && <DemoConnectCard />}

      <ServiceStateBanner serviceId="data_sources" entry={dataSourcesService} registry={counts?.services} />

      <StatStrip
        data-testid="sources-kpis"
        items={[
          {
            label: "Auth mode",
            value: session?.auth_method ?? (authLoading ? "…" : "Unknown"),
            hint: session ? `${roleLabel} · ${session.tenant_id}` : "Control plane owns auth",
          },
          {
            label: "Registered sources",
            value: loading ? "…" : sourceCount,
          },
          {
            label: "Connector health",
            value: loading ? "…" : `${healthyConnectors}/${connectorHealth.length || 0}`,
            accent: connectorHealth.length > 0 && healthyConnectors === connectorHealth.length ? "success" : "neutral",
          },
          {
            label: "Schedules",
            value: loading ? "…" : schedules.length,
            hint: schedules[0]?.next_run ? `Next ${formatWhen(schedules[0].next_run)}` : "None yet",
          },
        ]}
      />

      {(fleetSyncSummary || formMessage || error) && (
        <div className="space-y-1 text-sm">
          {fleetSyncSummary ? <p className="text-[color:var(--status-success)]">{fleetSyncSummary}</p> : null}
          {formMessage ? <p className="text-[color:var(--accent)]">{formMessage}</p> : null}
          {error ? <p className="text-[color:var(--status-danger)]">{error}</p> : null}
        </div>
      )}

      {!loading && sources.length === 0 ? (
        isDemoMode ? (
          <PageEmptyState
            title="No demo sources registered"
            detail="Explore New Scan or Scan Jobs with sample data to see how registered sources drive evidence."
            icon={ServerCog}
            actions={[
              { label: "New Scan", href: "/scan" },
              { label: "Scan Jobs", href: "/jobs", variant: "secondary" },
            ]}
          />
        ) : (
          <PageEmptyState
            title="No registered sources yet"
            detail="Register a scan target or connector-backed source to test, run, and schedule it from the control plane."
            icon={ServerCog}
          />
        )
      ) : (
        <section className="space-y-2">
          <div className="flex items-baseline justify-between">
            <h2 className="text-base font-semibold text-[color:var(--foreground)]">Source registry</h2>
            <p className="text-xs text-[color:var(--text-tertiary)]">Row → detail, evidence, and actions</p>
          </div>
          <DataTable<SourceRecord>
            data-testid="sources-table"
            columns={columns}
            rows={sources}
            rowKey={(source) => source.source_id}
            onRowClick={(source) => setSelectedSourceId(source.source_id)}
            selectedKey={selectedSourceId ?? undefined}
            loading={loading}
            maxHeight="32rem"
            caption="Registered data sources with status, last run, schedule count, and connector"
          />
        </section>
      )}

      {!isDemoMode && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Collapsible title="Create source" icon={Plus} defaultOpen={sources.length === 0}>
            <form className="space-y-4" onSubmit={handleCreateSource}>
              <label className="block">
                <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                  Display name
                </span>
                <input
                  value={formState.display_name}
                  onChange={(event) => updateForm("display_name", event.target.value)}
                  className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  placeholder="AWS production account"
                />
              </label>

              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                    Kind
                  </span>
                  <select
                    value={formState.kind}
                    onChange={(event) => updateForm("kind", event.target.value as SourceKind)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  >
                    {SOURCE_KIND_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                    Owner
                  </span>
                  <input
                    value={formState.owner}
                    onChange={(event) => updateForm("owner", event.target.value)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                    placeholder="platform-security"
                  />
                </label>
              </div>

              {selectedKind.mode === "Read-only connector" ? (
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                    Connector name
                  </span>
                  <select
                    value={formState.connector_name}
                    onChange={(event) => updateForm("connector_name", event.target.value)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  >
                    <option value="">Choose connector…</option>
                    {connectorNames.map((connector) => (
                      <option key={connector} value={connector}>
                        {connector}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}

              <label className="block">
                <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                  Description
                </span>
                <textarea
                  value={formState.description}
                  onChange={(event) => updateForm("description", event.target.value)}
                  rows={2}
                  className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  placeholder={selectedKind.detail}
                />
              </label>

              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 text-xs leading-5 text-[color:var(--text-secondary)]">
                <ModeChip mode={selectedKind.mode} />
                <p className="mt-2">{selectedKind.detail}</p>
              </div>

              <button
                type="submit"
                disabled={submitting || !canManageSources}
                className="inline-flex items-center gap-2 rounded-lg bg-[color:var(--accent)] px-4 py-2 text-sm font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {submitting ? "Creating…" : "Create source"}
              </button>
            </form>
          </Collapsible>

          <Collapsible
            title="Connector health"
            count={connectorHealth.length}
            defaultOpen={false}
            scrollMaxHeight="20rem"
          >
            {connectorHealth.length === 0 && !loading ? (
              <p className="text-sm text-[color:var(--text-secondary)]">No connector health state loaded yet.</p>
            ) : (
              <div className="space-y-2">
                {connectorHealth.map((connector) => (
                  <div
                    key={connector.connector}
                    className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <h3 className="text-sm font-semibold text-[color:var(--foreground)]">{connector.connector}</h3>
                        <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)]">{connector.message}</p>
                      </div>
                      <StatusPill status={connector.state} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Collapsible>
        </div>
      )}

      <Collapsible
        title="Provider trust contracts"
        subtitle={
          providerContracts ? `${providerSummary.total} providers · v${providerContracts.contract_version}` : undefined
        }
        defaultOpen={false}
      >
        <div className="space-y-4">
          <p className="text-sm text-[color:var(--text-secondary)]">
            Backend provider registry: scan modes, declared permissions, and read-only guarantees.
          </p>

          <StatStrip
            items={[
              { label: "Providers", value: loading ? "…" : providerSummary.total },
              { label: "Read-only", value: loading ? "…" : `${providerSummary.readOnly}/${providerSummary.total}` },
              { label: "Scope-zero modes", value: loading ? "…" : providerSummary.scopeZero },
              { label: "Declared permissions", value: loading ? "…" : providerSummary.permissionCount },
            ]}
          />

          {providerContracts?.warnings?.length ? (
            <div className="rounded-lg border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] p-3 text-xs leading-5 text-[color:var(--text-secondary)]">
              {providerContracts.warnings.slice(0, 2).join(" · ")}
            </div>
          ) : null}

          <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
            {!providerContracts && !loading ? (
              <div className="rounded-lg border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-sm text-[color:var(--text-secondary)]">
                Provider contracts are unavailable from the API.
              </div>
            ) : (
              (providerContracts?.providers ?? []).slice(0, 12).map((provider) => (
                <ProviderContractCard key={provider.name} provider={provider} />
              ))
            )}
          </div>
        </div>
      </Collapsible>

      {roleSummary && !isDemoMode ? (
        <Collapsible title={`${roleSummary.display_name} access in this tenant`} icon={Shield} defaultOpen={false}>
          <p className="text-sm text-[color:var(--text-secondary)]">{roleSummary.description}</p>
          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <AccessList title="Can see" items={roleSummary.can_see} />
            <AccessList title="Can do" items={roleSummary.can_do} />
            <AccessList title="Blocked from" items={roleSummary.cannot_do} />
          </div>
        </Collapsible>
      ) : null}

      {!isDemoMode && (
        <Collapsible title="Related operating surfaces" defaultOpen={false}>
          <div className="grid gap-3 xl:grid-cols-2">
            {OPERATING_SURFACES.map((surface) => {
              const Icon = surface.icon;
              return (
                <Link key={surface.title} href={surface.href}>
                  <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 transition-colors hover:border-[color:var(--border-strong)]">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2">
                          <Icon className="h-4 w-4 text-[color:var(--accent)]" />
                        </span>
                        <div>
                          <p className="text-sm font-semibold text-[color:var(--foreground)]">{surface.title}</p>
                          <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)]">{surface.summary}</p>
                        </div>
                      </div>
                      <ArrowRight className="mt-1 h-4 w-4 text-[color:var(--text-tertiary)]" />
                    </div>
                    <div className="mt-4 text-[11px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                      {surface.status}
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        </Collapsible>
      )}

      <SourceDrawer
        source={selectedSource}
        open={selectedSource != null}
        onClose={() => setSelectedSourceId(null)}
        schedules={selectedSource ? schedulesBySource.get(selectedSource.source_id) ?? [] : []}
        busySourceId={busySourceId}
        busyScheduleId={busyScheduleId}
        canManageSources={canManageSources}
        canRunScans={canRunScans}
        onSourceAction={runSourceAction}
        onScheduleAction={runScheduleAction}
        onCreateSchedule={handleCreateSchedule}
        submittingSchedule={submittingSchedule}
        scheduleName={scheduleName}
        scheduleCron={scheduleCron}
        onScheduleNameChange={setScheduleName}
        onScheduleCronChange={setScheduleCron}
      />
    </div>
  );
}

function SourceDrawer({
  source,
  open,
  onClose,
  schedules,
  busySourceId,
  busyScheduleId,
  canManageSources,
  canRunScans,
  onSourceAction,
  onScheduleAction,
  onCreateSchedule,
  submittingSchedule,
  scheduleName,
  scheduleCron,
  onScheduleNameChange,
  onScheduleCronChange,
}: {
  source: SourceRecord | null;
  open: boolean;
  onClose: () => void;
  schedules: ScanSchedule[];
  busySourceId: string | null;
  busyScheduleId: string | null;
  canManageSources: boolean;
  canRunScans: boolean;
  onSourceAction: (sourceId: string, action: "test" | "run" | "delete") => void;
  onScheduleAction: (scheduleId: string, action: "toggle" | "delete") => void;
  onCreateSchedule: (event: React.FormEvent<HTMLFormElement>, source: SourceRecord) => void;
  submittingSchedule: boolean;
  scheduleName: string;
  scheduleCron: string;
  onScheduleNameChange: (value: string) => void;
  onScheduleCronChange: (value: string) => void;
}) {
  if (!source) return null;
  const option = SOURCE_KIND_OPTIONS.find((entry) => entry.value === source.kind);
  const mode = option?.mode ?? "Direct scan";
  const isBusy = busySourceId === source.source_id;
  const schedulable = SCHEDULABLE_KINDS.has(source.kind);

  const meta: [string, React.ReactNode][] = [
    ["Owner", source.owner || "Unassigned"],
    ["Credential mode", source.credential_mode],
    ["Connector", source.connector_name || "—"],
    ["Enabled", source.enabled ? "Enabled" : "Disabled"],
    ["Last tested", formatWhen(source.last_tested_at)],
    ["Last run", formatWhen(source.last_run_at)],
  ];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      eyebrow={mode}
      title={source.display_name}
      subtitle={option?.label ?? source.kind}
      headerAside={<StatusPill status={source.status} />}
      size="2xl"
      ariaLabel={`Source ${source.display_name}`}
      footer={
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onSourceAction(source.source_id, "test")}
            disabled={isBusy || !canManageSources}
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isBusy ? "Working…" : "Test"}
          </button>
          <button
            onClick={() => onSourceAction(source.source_id, "run")}
            disabled={isBusy || !source.enabled || !canRunScans}
            className="rounded-lg bg-[color:var(--accent)] px-3 py-2 text-xs font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Run now
          </button>
          <button
            onClick={() => onSourceAction(source.source_id, "delete")}
            disabled={isBusy || !canManageSources}
            className="rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-xs font-medium text-[color:var(--status-danger)] transition hover:border-[color:var(--status-danger)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Delete
          </button>
        </div>
      }
    >
      <div className="space-y-5" data-testid={`source-detail-${source.source_id}`}>
        {source.description ? (
          <p className="text-sm leading-6 text-[color:var(--text-secondary)]">{source.description}</p>
        ) : null}

        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
          {meta.map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-[11px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</dt>
              <dd className="mt-0.5 truncate text-[color:var(--text-secondary)]">{value}</dd>
            </div>
          ))}
          <div className="col-span-2 min-w-0">
            <dt className="text-[11px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Last job</dt>
            <dd className="mt-0.5">
              {source.last_job_id ? (
                <Link
                  href={`/scan?id=${encodeURIComponent(source.last_job_id)}`}
                  className="inline-block max-w-full truncate font-mono text-[color:var(--accent)] hover:underline"
                  title={source.last_job_id}
                >
                  {formatShortId(source.last_job_id)}
                </Link>
              ) : (
                <span className="text-[color:var(--text-secondary)]">—</span>
              )}
            </dd>
          </div>
        </dl>

        {source.last_test_message ? (
          <p className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 text-xs leading-5 text-[color:var(--text-secondary)]">
            {source.last_test_message}
          </p>
        ) : null}

        <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
          <div className="flex items-start gap-2">
            <FileCheck2 className="mt-0.5 h-4 w-4 text-[color:var(--accent)]" />
            <div>
              <p className="text-xs font-semibold text-[color:var(--foreground)]">Evidence workflow</p>
              <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)]">
                {source.last_job_id
                  ? "Open the completed job surfaces created from this source."
                  : "Run this source to create findings, graph, and compliance evidence."}
              </p>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {[
              { target: "jobs" as const, label: "Jobs" },
              { target: "findings" as const, label: "Findings" },
              { target: "graph" as const, label: "Graph" },
              { target: "compliance" as const, label: "Compliance" },
            ].map((link) => {
              const disabled = link.target !== "jobs" && !source.last_job_id;
              return (
                <Link
                  key={link.target}
                  href={sourceEvidenceHref(source, link.target)}
                  aria-disabled={disabled}
                  className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition ${
                    disabled
                      ? "pointer-events-none border-[color:var(--border-subtle)] text-[color:var(--text-tertiary)] opacity-60"
                      : "border-[color:var(--border-subtle)] text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]"
                  }`}
                >
                  {link.label}
                </Link>
              );
            })}
          </div>
        </div>

        <div>
          <h3 className="text-sm font-semibold text-[color:var(--foreground)]">Schedules</h3>
          <div className="mt-3 space-y-2">
            {schedules.length === 0 ? (
              <p className="text-xs text-[color:var(--text-secondary)]">No schedules bound to this source yet.</p>
            ) : (
              schedules.map((schedule) => {
                const isScheduleBusy = busyScheduleId === schedule.schedule_id;
                return (
                  <div
                    key={schedule.schedule_id}
                    className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-[color:var(--foreground)]">{schedule.name}</p>
                        <p className="mt-0.5 font-mono text-xs text-[color:var(--text-secondary)]">
                          {schedule.cron_expression}
                        </p>
                      </div>
                      <StatusPill status={schedule.enabled ? "active" : "paused"} />
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-[color:var(--text-secondary)]">
                      <span>Next: {formatWhen(schedule.next_run)}</span>
                      <span>Last: {formatWhen(schedule.last_run)}</span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        onClick={() => onScheduleAction(schedule.schedule_id, "toggle")}
                        disabled={isScheduleBusy || !canManageSources}
                        className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {isScheduleBusy ? "Working…" : schedule.enabled ? "Pause" : "Enable"}
                      </button>
                      <button
                        onClick={() => onScheduleAction(schedule.schedule_id, "delete")}
                        disabled={isScheduleBusy || !canManageSources}
                        className="rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-1.5 text-xs font-medium text-[color:var(--status-danger)] transition hover:border-[color:var(--status-danger)] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                );
              })
            )}

            {schedulable ? (
              <form
                className="rounded-lg border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
                onSubmit={(event) => onCreateSchedule(event, source)}
              >
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="block">
                    <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                      Name
                    </span>
                    <input
                      aria-label="Schedule name"
                      value={scheduleName}
                      onChange={(event) => onScheduleNameChange(event.target.value)}
                      className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                      placeholder="Nightly posture"
                    />
                  </label>
                  <label className="block">
                    <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                      Cron
                    </span>
                    <input
                      aria-label="Schedule cron"
                      value={scheduleCron}
                      onChange={(event) => onScheduleCronChange(event.target.value)}
                      className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 font-mono text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                      placeholder="0 * * * *"
                    />
                  </label>
                </div>
                <button
                  type="submit"
                  disabled={submittingSchedule || !canManageSources}
                  className="mt-3 inline-flex items-center gap-2 rounded-lg bg-[color:var(--accent)] px-4 py-2 text-sm font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <CalendarClock className="h-4 w-4" />
                  {submittingSchedule ? "Creating…" : "Create schedule"}
                </button>
              </form>
            ) : null}
          </div>
        </div>
      </div>
    </Drawer>
  );
}

function ProviderContractCard({ provider }: { provider: DiscoveryProviderContract }) {
  const trust = provider.trust_contract;
  const capabilities = provider.capabilities;
  const destinations = capabilities.network_destinations ?? capabilities.outbound_destinations;
  const permissions = capabilities.permissions_used;
  const scanModes = capabilities.scan_modes;
  const previewModes = scanModes.slice(0, PROVIDER_SCAN_MODE_PREVIEW);
  const extraModeCount = scanModes.length - previewModes.length;

  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-[color:var(--foreground)]">{provider.name}</h3>
          <p className="mt-1 truncate font-mono text-[11px] text-[color:var(--text-tertiary)]">{provider.source}</p>
        </div>
        <span
          className="shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-medium"
          style={
            trust.supports_scope_zero
              ? {
                  borderColor: "var(--status-success-border)",
                  backgroundColor: "var(--status-success-bg)",
                  color: "var(--status-success)",
                }
              : {
                  borderColor: "var(--border-subtle)",
                  backgroundColor: "var(--surface)",
                  color: "var(--text-secondary)",
                }
          }
        >
          {trust.supports_scope_zero ? "scope-zero" : "direct pull"}
        </span>
      </div>

      <div className="mt-3 flex max-h-14 flex-wrap gap-1.5 overflow-hidden">
        {previewModes.map((mode) => (
          <span
            key={mode}
            className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] font-mono text-[color:var(--text-secondary)]"
          >
            {formatMode(mode)}
          </span>
        ))}
        {extraModeCount > 0 ? (
          <span
            className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] font-medium text-[color:var(--text-tertiary)]"
            title={scanModes.slice(PROVIDER_SCAN_MODE_PREVIEW).map(formatMode).join(", ")}
          >
            +{extraModeCount} mode{extraModeCount === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>

      <div className="mt-4 grid gap-2 text-xs text-[color:var(--text-secondary)] sm:grid-cols-2">
        <span>Read-only: {trust.read_only ? "yes" : "no"}</span>
        <span>Agentless: {trust.agentless ? "yes" : "no"}</span>
        <span>Redaction: {formatMode(trust.redaction_status)}</span>
        <span>Residency: {formatMode(trust.data_residency)}</span>
      </div>

      <div className="mt-4 space-y-2 text-xs text-[color:var(--text-secondary)]">
        <div>
          <span className="text-[color:var(--text-tertiary)]">Permissions used: </span>
          <span className="text-[color:var(--foreground)]">{permissions.length}</span>
          {permissions.length > 0 ? (
            <span className="ml-1 font-mono text-[11px] text-[color:var(--text-secondary)]">
              {permissions.slice(0, 3).join(", ")}
              {permissions.length > 3 ? ` +${permissions.length - 3}` : ""}
            </span>
          ) : null}
        </div>
        <div>
          <span className="text-[color:var(--text-tertiary)]">Network: </span>
          <span className="font-mono text-[11px] text-[color:var(--text-secondary)]">
            {destinations.length ? destinations.slice(0, 3).join(", ") : "none"}
            {destinations.length > 3 ? ` +${destinations.length - 3}` : ""}
          </span>
        </div>
      </div>
    </div>
  );
}

function AccessList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
      <p className="text-xs uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">{title}</p>
      {items.length === 0 ? (
        <p className="mt-3 text-sm text-[color:var(--text-secondary)]">No additional access in this category.</p>
      ) : (
        <ul className="mt-3 space-y-2 text-sm text-[color:var(--text-secondary)]">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
