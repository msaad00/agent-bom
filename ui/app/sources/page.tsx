"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  CalendarClock,
  Cloud,
  Database,
  Plus,
  Radio,
  RefreshCcw,
  ServerCog,
  Shield,
  ShieldCheck,
  Workflow,
} from "lucide-react";

import {
  api,
  type AuthDebugResponse,
  type ConnectorHealthResponse,
  type ScanSchedule,
  type SourceCreateRequest,
  type SourceKind,
  type SourceRecord,
} from "@/lib/api";

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
    href: "/proxy",
    summary: "Live runtime enforcement, detector alerts, drift protection, and audit review for MCP and tool-call activity.",
    status: "Runtime",
    icon: Radio,
  },
  {
    title: "Gateway and policy enforcement",
    href: "/gateway",
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

function toneForMode(mode: IngestMode): string {
  switch (mode) {
    case "Direct scan":
      return "border-emerald-900/60 bg-emerald-950/30 text-emerald-400";
    case "Read-only connector":
      return "border-sky-900/60 bg-sky-950/30 text-sky-400";
    case "Pushed ingest":
      return "border-amber-900/60 bg-amber-950/30 text-amber-400";
    case "Runtime":
      return "border-violet-900/60 bg-violet-950/30 text-violet-400";
    case "Imported artifact":
      return "border-fuchsia-900/60 bg-fuchsia-950/30 text-fuchsia-400";
  }
}

function toneForStatus(status: string): string {
  switch (status) {
    case "healthy":
      return "text-emerald-400";
    case "degraded":
      return "text-amber-400";
    case "disabled":
      return "text-zinc-400";
    default:
      return "text-sky-400";
  }
}

export default function SourcesPage() {
  const [authDebug, setAuthDebug] = useState<AuthDebugResponse | null>(null);
  const [connectorHealth, setConnectorHealth] = useState<ConnectorHealthResponse[]>([]);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncingFleet, setSyncingFleet] = useState(false);
  const [fleetSyncSummary, setFleetSyncSummary] = useState<string | null>(null);
  const [formState, setFormState] = useState<FormState>(DEFAULT_FORM_STATE);
  const [submitting, setSubmitting] = useState(false);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const [busySourceId, setBusySourceId] = useState<string | null>(null);

  const connectorNames = useMemo(
    () => connectorHealth.map((connector) => connector.connector).sort((left, right) => left.localeCompare(right)),
    [connectorHealth]
  );
  const selectedKind = useMemo(
    () => SOURCE_KIND_OPTIONS.find((option) => option.value === formState.kind) ?? SOURCE_KIND_OPTIONS[0],
    [formState.kind]
  );
  const sourceCount = sources.length;
  const healthyConnectors = useMemo(
    () => connectorHealth.filter((connector) => connector.state === "healthy").length,
    [connectorHealth]
  );

  function updateForm<K extends keyof FormState>(field: K, value: FormState[K]) {
    setFormState((current) => ({ ...current, [field]: value }));
  }

  async function refreshControlPlane() {
    setLoading(true);
    setError(null);

    try {
      const [authResult, connectorsResult, schedulesResult, sourcesResult] = await Promise.allSettled([
        api.getAuthDebug(),
        api.listConnectors(),
        api.listSchedules(),
        api.listSources(),
      ]);

      if (authResult.status === "fulfilled") {
        setAuthDebug(authResult.value);
      }

      if (sourcesResult.status === "fulfilled") {
        setSources(sourcesResult.value.sources);
      } else {
        setSources([]);
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

      const failures = [authResult, connectorsResult, schedulesResult, sourcesResult].filter(
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
      }
      await refreshControlPlane();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Source action failed.");
    } finally {
      setBusySourceId(null);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[linear-gradient(135deg,var(--surface),var(--surface-elevated))] p-6 shadow-2xl shadow-black/10">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-[11px] uppercase tracking-[0.22em] text-emerald-400">Hosted control plane</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[var(--foreground)]">Sources and ingest control</h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-[var(--text-secondary)]">
              The UI should declare intent and review state. The API owns auth, orchestration, graph, persistence, audit, and policy. Workers,
              connectors, proxy, and gateway paths do the privileged collection work.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => refreshControlPlane()}
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              <RefreshCcw className="h-4 w-4" />
              Refresh
            </button>
            <button
              onClick={handleFleetSync}
              disabled={syncingFleet}
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Activity className="h-4 w-4" />
              {syncingFleet ? "Syncing fleet…" : "Run fleet sync"}
            </button>
          </div>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            icon={ShieldCheck}
            label="Auth mode"
            value={authDebug?.auth_method ?? (loading ? "Loading…" : "Unknown")}
            detail={
              authDebug
                ? `${authDebug.role ?? "no role"} · tenant ${authDebug.tenant_id} · ${authDebug.recommended_ui_mode}`
                : "API/control plane owns auth and tenant scope"
            }
          />
          <MetricCard
            icon={ServerCog}
            label="Registered sources"
            value={loading ? "Loading…" : String(sourceCount)}
            detail={sources[0]?.updated_at ? `Last update ${formatWhen(sources[0].updated_at)}` : "No source registry records yet"}
          />
          <MetricCard
            icon={Cloud}
            label="Connector health"
            value={loading ? "Loading…" : `${healthyConnectors}/${connectorHealth.length || 0}`}
            detail="Read-only integrations checked through backend health routes"
          />
          <MetricCard
            icon={CalendarClock}
            label="Schedules"
            value={loading ? "Loading…" : String(schedules.length)}
            detail={schedules[0]?.next_run ? `Next run ${formatWhen(schedules[0].next_run)}` : "No persisted schedules yet"}
          />
        </div>

        {fleetSyncSummary ? <p className="mt-4 text-sm text-emerald-400">{fleetSyncSummary}</p> : null}
        {formMessage ? <p className="mt-2 text-sm text-emerald-400">{formMessage}</p> : null}
        {error ? <p className="mt-2 text-sm text-red-400">{error}</p> : null}
      </section>

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5">
          <div className="flex items-start gap-3">
            <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
              <Database className="h-5 w-5 text-emerald-400" />
            </span>
            <div>
              <h2 className="text-base font-semibold text-[var(--foreground)]">Source registry</h2>
              <p className="mt-1 text-sm text-[var(--text-secondary)]">
                Each source is a persisted control-plane record with tenant scope, ownership, credential mode, last test, and last run state.
              </p>
            </div>
          </div>

          <div className="mt-5 space-y-3">
            {sources.length === 0 && !loading ? (
              <div className="rounded-2xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-sm text-[var(--text-secondary)]">
                No registered sources yet. Create one here, then test it or run it from the control plane.
              </div>
            ) : (
              sources.map((source) => {
                const option = SOURCE_KIND_OPTIONS.find((entry) => entry.value === source.kind);
                const isBusy = busySourceId === source.source_id;
                return (
                  <div
                    key={source.source_id}
                    className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium ${toneForMode(option?.mode ?? "Direct scan")}`}>
                          {option?.mode ?? source.kind}
                        </div>
                        <h3 className="mt-3 text-sm font-semibold text-[var(--foreground)]">{source.display_name}</h3>
                        <p className="mt-1 text-xs text-[var(--text-secondary)]">{option?.label ?? source.kind}</p>
                      </div>
                      <div className="text-right">
                        <p className={`text-[11px] uppercase tracking-[0.18em] ${toneForStatus(source.status)}`}>{source.status}</p>
                        <p className="mt-1 text-[11px] text-[var(--text-tertiary)]">{source.enabled ? "Enabled" : "Disabled"}</p>
                      </div>
                    </div>

                    {source.description ? <p className="mt-3 text-xs leading-5 text-[var(--text-secondary)]">{source.description}</p> : null}

                    <div className="mt-3 grid gap-2 text-xs text-[var(--text-secondary)] sm:grid-cols-2">
                      <span>Owner: {source.owner || "Unassigned"}</span>
                      <span>Credential mode: {source.credential_mode}</span>
                      <span>Connector: {source.connector_name || "—"}</span>
                      <span>Last tested: {formatWhen(source.last_tested_at)}</span>
                      <span>Last run: {formatWhen(source.last_run_at)}</span>
                      <span>Last job: {source.last_job_id || "—"}</span>
                    </div>

                    {source.last_test_message ? (
                      <p className="mt-3 text-xs leading-5 text-[var(--text-secondary)]">{source.last_test_message}</p>
                    ) : null}

                    <div className="mt-4 flex flex-wrap gap-2">
                      <button
                        onClick={() => runSourceAction(source.source_id, "test")}
                        disabled={isBusy}
                        className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-xs font-medium text-[var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {isBusy ? "Working…" : "Test"}
                      </button>
                      <button
                        onClick={() => runSourceAction(source.source_id, "run")}
                        disabled={isBusy || !source.enabled}
                        className="rounded-xl bg-emerald-500 px-3 py-2 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Run now
                      </button>
                      <button
                        onClick={() => runSourceAction(source.source_id, "delete")}
                        disabled={isBusy}
                        className="rounded-xl border border-red-900/60 bg-red-950/20 px-3 py-2 text-xs font-medium text-red-300 transition hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        <section className="space-y-6">
          <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5">
            <div className="flex items-start gap-3">
              <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
                <Plus className="h-5 w-5 text-emerald-400" />
              </span>
              <div>
                <h2 className="text-base font-semibold text-[var(--foreground)]">Create source</h2>
                <p className="mt-1 text-sm text-[var(--text-secondary)]">
                  Register the source here, then let backend jobs, connectors, proxy, or gateway paths do the collection work.
                </p>
              </div>
            </div>

            <form className="mt-5 space-y-4" onSubmit={handleCreateSource}>
              <label className="block">
                <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Display name</span>
                <input
                  value={formState.display_name}
                  onChange={(event) => updateForm("display_name", event.target.value)}
                  className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  placeholder="AWS production account"
                />
              </label>

              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Kind</span>
                  <select
                    value={formState.kind}
                    onChange={(event) => updateForm("kind", event.target.value as SourceKind)}
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  >
                    {SOURCE_KIND_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Owner</span>
                  <input
                    value={formState.owner}
                    onChange={(event) => updateForm("owner", event.target.value)}
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                    placeholder="platform-security"
                  />
                </label>
              </div>

              {selectedKind.mode === "Read-only connector" ? (
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Connector name</span>
                  <select
                    value={formState.connector_name}
                    onChange={(event) => updateForm("connector_name", event.target.value)}
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
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
                <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Description</span>
                <textarea
                  value={formState.description}
                  onChange={(event) => updateForm("description", event.target.value)}
                  rows={3}
                  className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  placeholder={selectedKind.detail}
                />
              </label>

              <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-xs leading-5 text-[var(--text-secondary)]">
                <div className={`inline-flex rounded-full border px-2.5 py-1 font-medium ${toneForMode(selectedKind.mode)}`}>{selectedKind.mode}</div>
                <p className="mt-3">{selectedKind.detail}</p>
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {submitting ? "Creating…" : "Create source"}
              </button>
            </form>
          </section>

          <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5">
            <div className="flex items-start gap-3">
              <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
                <Cloud className="h-5 w-5 text-emerald-400" />
              </span>
              <div>
                <h2 className="text-base font-semibold text-[var(--foreground)]">Connector health</h2>
                <p className="mt-1 text-sm text-[var(--text-secondary)]">
                  Read-only integrations are backend-owned. The browser only reviews health and initiates control-plane actions.
                </p>
              </div>
            </div>

            <div className="mt-5 space-y-3">
              {connectorHealth.length === 0 && !loading ? (
                <div className="rounded-2xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-sm text-[var(--text-secondary)]">
                  No connector health state loaded yet.
                </div>
              ) : (
                connectorHealth.map((connector) => (
                  <div key={connector.connector} className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="text-sm font-semibold text-[var(--foreground)]">{connector.connector}</h3>
                        <p className="mt-1 text-xs leading-5 text-[var(--text-secondary)]">{connector.message}</p>
                      </div>
                      <span className={`text-[11px] uppercase tracking-[0.18em] ${toneForStatus(connector.state)}`}>{connector.state}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5">
            <div className="flex items-start gap-3">
              <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
                <CalendarClock className="h-5 w-5 text-emerald-400" />
              </span>
              <div>
                <h2 className="text-base font-semibold text-[var(--foreground)]">Persisted schedules</h2>
                <p className="mt-1 text-sm text-[var(--text-secondary)]">
                  Recurring collection belongs to the control plane. This page already reflects real schedule state from the backend.
                </p>
              </div>
            </div>

            <div className="mt-5 space-y-3">
              {schedules.length === 0 && !loading ? (
                <div className="rounded-2xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
                  <p className="text-sm text-[var(--text-secondary)]">No scan schedules yet.</p>
                  <Link href="/scan" className="mt-3 inline-flex items-center gap-2 text-sm font-medium text-emerald-400">
                    Open New Scan
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </div>
              ) : (
                schedules.slice(0, 4).map((schedule) => (
                  <div key={schedule.schedule_id} className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="text-sm font-semibold text-[var(--foreground)]">{schedule.name}</h3>
                        <p className="mt-1 font-mono text-xs text-[var(--text-secondary)]">{schedule.cron_expression}</p>
                      </div>
                      <span className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                        {schedule.enabled ? "Enabled" : "Paused"}
                      </span>
                    </div>
                    <div className="mt-3 grid gap-2 text-xs text-[var(--text-secondary)] sm:grid-cols-2">
                      <span>Next run: {formatWhen(schedule.next_run)}</span>
                      <span>Last run: {formatWhen(schedule.last_run)}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>
        </section>
      </div>

      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5">
        <div className="flex items-start gap-3">
          <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
            <Activity className="h-5 w-5 text-emerald-400" />
          </span>
          <div>
            <h2 className="text-base font-semibold text-[var(--foreground)]">Operating surfaces after ingest</h2>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              Discovery and ingest are only the front door. Agent-bom also needs clear surfaces for runtime review, fleet operations, policy
              enforcement, and graph analysis after the data lands.
            </p>
          </div>
        </div>

        <div className="mt-5 grid gap-3 xl:grid-cols-2">
          {OPERATING_SURFACES.map((surface) => {
            const Icon = surface.icon;
            return (
              <Link key={surface.title} href={surface.href}>
                <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 transition-colors hover:border-[color:var(--border-strong)]">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2">
                        <Icon className="h-4 w-4 text-emerald-400" />
                      </span>
                      <div>
                        <p className="text-sm font-semibold text-[var(--foreground)]">{surface.title}</p>
                        <p className="mt-1 text-xs leading-5 text-[var(--text-secondary)]">{surface.summary}</p>
                      </div>
                    </div>
                    <ArrowRight className="mt-1 h-4 w-4 text-[var(--text-tertiary)]" />
                  </div>
                  <div className="mt-4 text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{surface.status}</div>
                </div>
              </Link>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
      <div className="flex items-center gap-3">
        <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2">
          <Icon className="h-4 w-4 text-emerald-400" />
        </span>
        <div>
          <p className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{label}</p>
          <p className="mt-1 text-lg font-semibold text-[var(--foreground)]">{value}</p>
        </div>
      </div>
      <p className="mt-3 text-xs leading-5 text-[var(--text-secondary)]">{detail}</p>
    </div>
  );
}
