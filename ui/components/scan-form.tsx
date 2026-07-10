"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  Bot,
  CalendarClock,
  ChevronDown,
  Cloud,
  Container,
  Link2,
  Loader2,
  Plus,
  Server,
  Upload,
  X,
} from "lucide-react";

import { useDeploymentContext } from "@/hooks/use-deployment-context";
import {
  api,
  type CloudConnectionRecord,
  type ScanRequest,
  type SourceRecord,
} from "@/lib/api";
import { deploymentModeLabel } from "@/lib/deployment-context";
import {
  adhocScopeChips,
  cloudConnectionScopeChips,
  isScannableConnection,
  providerDisplayName,
  scheduledSourceScopeChips,
  type AdhocScanTarget,
  type ScanMode,
  type ScanScopeChip,
} from "@/lib/scan-scope";
import { REPO_SCAN_SURFACES, repoScanLanguageSummary } from "@/lib/repo-scan-surfaces";

type ScanFormProps = {
  initialConnectionId?: string | undefined;
};

export function ScanForm({ initialConnectionId }: ScanFormProps) {
  const router = useRouter();
  const { counts } = useDeploymentContext();
  const deploymentMode = counts?.deployment_mode ?? "local";
  const [scanMode, setScanMode] = useState<ScanMode>(
    initialConnectionId ? "connected" : deploymentMode === "local" ? "adhoc" : "connected",
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);
  const [connectionsError, setConnectionsError] = useState("");
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const [selectedConnectionId, setSelectedConnectionId] = useState(initialConnectionId ?? "");
  const [selectedSourceId, setSelectedSourceId] = useState("");
  const [target, setTarget] = useState<AdhocScanTarget>(
    deploymentMode === "local" ? "workstation" : "workstation",
  );
  const [form, setForm] = useState<ScanRequest>({
    enrich: false,
    k8s: false,
    images: [],
    tf_dirs: [],
    agent_projects: [],
  });
  const [imageInput, setImageInput] = useState("");
  const [showBulkImages, setShowBulkImages] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [tfInput, setTfInput] = useState("");
  const [apInput, setApInput] = useState("");
  const [repoUrlInput, setRepoUrlInput] = useState("");

  useEffect(() => {
    let mounted = true;
    api
      .listCloudConnections()
      .then((response) => {
        if (!mounted) return;
        setConnections(response.connections ?? []);
        setConnectionsError("");
        setConnectionsLoading(false);
        const loaded = response.connections ?? [];
        setSelectedConnectionId((current) => {
          if (initialConnectionId && loaded.some((connection) => connection.id === initialConnectionId)) {
            return initialConnectionId;
          }
          if (current && loaded.some((connection) => connection.id === current)) {
            return current;
          }
          return loaded[0]?.id ?? "";
        });
        if (initialConnectionId) {
          setScanMode("connected");
        }
      })
      .catch((err: Error) => {
        if (!mounted) return;
        setConnectionsError(err.message);
        setConnectionsLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [initialConnectionId]);

  useEffect(() => {
    let mounted = true;
    api
      .listSources()
      .then((response) => {
        if (!mounted) return;
        const nextSources = response.sources ?? [];
        setSources(nextSources);
        setSourcesLoading(false);
        setSelectedSourceId((current) => current || nextSources[0]?.source_id || "");
      })
      .catch(() => {
        if (!mounted) return;
        setSourcesLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const deploymentLabel = deploymentModeLabel(deploymentMode);
  const deploymentHint = useMemo(() => {
    switch (deploymentMode) {
      case "fleet":
        return "Fleet control plane — connect cloud accounts for continuous coverage, or run ad-hoc workstation scans.";
      case "cluster":
        return "Cluster control plane — prioritize Kubernetes and connected cloud accounts.";
      case "hybrid":
        return "Hybrid deployment — cloud connectors plus workstation and cluster scans share one graph.";
      case "local":
      default:
        return "Local control plane — scans run on this machine against paths and kube context you provide.";
    }
  }, [deploymentMode]);

  const selectedConnection = useMemo(
    () => connections.find((connection) => connection.id === selectedConnectionId) ?? null,
    [connections, selectedConnectionId],
  );
  const selectedSource = useMemo(
    () => sources.find((source) => source.source_id === selectedSourceId) ?? null,
    [sources, selectedSourceId],
  );

  const scopeChips = useMemo((): ScanScopeChip[] => {
    if (scanMode === "connected" && selectedConnection) {
      return cloudConnectionScopeChips(selectedConnection);
    }
    if (scanMode === "scheduled" && selectedSource) {
      return scheduledSourceScopeChips(selectedSource);
    }
    return adhocScopeChips(form, target);
  }, [form, scanMode, selectedConnection, selectedSource, target]);

  function addToList(key: "images" | "tf_dirs" | "agent_projects", value: string, reset: () => void) {
    if (!value.trim()) return;
    setForm((f) => ({ ...f, [key]: [...(f[key] ?? []), value.trim()] }));
    reset();
  }

  function removeFromList(key: "images" | "tf_dirs" | "agent_projects", idx: number) {
    setForm((f) => ({ ...f, [key]: (f[key] ?? []).filter((_, i) => i !== idx) }));
  }

  function parseBulkImages(text: string): string[] {
    return text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  }

  function applyBulk() {
    const parsed = parseBulkImages(bulkText);
    if (parsed.length === 0) return;
    setForm((f) => ({ ...f, images: [...(f.images ?? []), ...parsed] }));
    setBulkText("");
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      const parsed = parseBulkImages(text);
      if (parsed.length > 0) {
        setForm((f) => ({ ...f, images: [...(f.images ?? []), ...parsed] }));
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  async function handleAdhocSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const request: ScanRequest =
        target === "repository"
          ? {
              repo_url: repoUrlInput.trim(),
              enrich: form.enrich ?? false,
            }
          : {
              ...form,
              repo_url: undefined,
            };
      if (target === "repository" && !request.repo_url) {
        setError("Enter a public repository URL (https://github.com/org/repo)");
        setLoading(false);
        return;
      }
      const job = await api.startScan(request);
      router.push(`/scan?id=${job.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setLoading(false);
    }
  }

  async function handleCloudScan() {
    if (!selectedConnection) return;
    setLoading(true);
    setError("");
    try {
      const result = await api.scanCloudConnection(selectedConnection.id);
      router.push(`/scan?id=${result.scan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start cloud scan");
      setLoading(false);
    }
  }

  async function handleSourceRun() {
    if (!selectedSource) return;
    setLoading(true);
    setError("");
    try {
      const result = await api.runSource(selectedSource.source_id);
      router.push(`/scan?id=${result.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run source");
      setLoading(false);
    }
  }

  const queuedImages = form.images ?? [];
  const cloudScanReady = Boolean(selectedConnection && isScannableConnection(selectedConnection));
  const sourceRunReady = Boolean(selectedSource?.enabled);
  const repoScanReady = target !== "repository" || Boolean(repoUrlInput.trim());

  return (
    <div className="max-w-5xl">
      <header className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">New Scan</h1>
            <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-0.5 text-[10px] font-mono uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
              {deploymentLabel}
            </span>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-[color:var(--text-secondary)]">
            Pick where evidence comes from: a connected cloud account, an ad-hoc target on this control plane, or a registered data source.
          </p>
          <nav aria-label="Related scan surfaces" className="mt-3 flex flex-wrap items-center gap-x-1 gap-y-1 text-xs text-[color:var(--text-tertiary)]">
            <RelatedLink href="/sources">Data sources</RelatedLink>
            <span aria-hidden="true">·</span>
            <RelatedLink href="/connections">Cloud accounts</RelatedLink>
            <span aria-hidden="true">·</span>
            <RelatedLink href="/jobs">Scan jobs</RelatedLink>
          </nav>
        </div>
        <Link
          href="/connections"
          className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] transition-colors hover:border-[color:var(--border-strong)]"
        >
          Connect cloud account
          <ArrowRight className="h-4 w-4" />
        </Link>
      </header>

      <div className="mb-5 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3 text-sm text-[color:var(--text-secondary)]">
        <span className="font-medium text-[color:var(--foreground)]">{deploymentLabel} control plane.</span>{" "}
        {deploymentHint}
      </div>

      <section
        aria-labelledby="scan-mode-heading"
        className="mb-5 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4"
      >
        <h2 id="scan-mode-heading" className="text-sm font-semibold text-[color:var(--foreground)]">
          Where am I scanning?
        </h2>
        <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
          Connected accounts use brokered read-only credentials. Ad-hoc scans run on this control plane host. Scheduled sources enqueue jobs from saved configs.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {(
            [
              { id: "connected" as const, label: "Connected account", icon: Cloud, hint: "One onboarded cloud account" },
              { id: "adhoc" as const, label: "Ad-hoc target", icon: Bot, hint: "Workstation · images · Kubernetes" },
              { id: "scheduled" as const, label: "Data source", icon: CalendarClock, hint: "Registered source config" },
            ] as const
          ).map((option) => {
            const Icon = option.icon;
            const active = scanMode === option.id;
            return (
              <button
                key={option.id}
                type="button"
                onClick={() => setScanMode(option.id)}
                className={`min-w-[10rem] rounded-xl border px-3 py-2.5 text-left transition ${
                  active
                    ? "border-emerald-600/50 bg-emerald-500/10 text-[color:var(--foreground)]"
                    : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
                }`}
              >
                <div className="flex items-center gap-2 text-sm font-medium">
                  <Icon className="h-4 w-4 shrink-0" />
                  {option.label}
                </div>
                <p className="mt-1 text-[11px] text-[color:var(--text-tertiary)]">{option.hint}</p>
              </button>
            );
          })}
        </div>
      </section>

      <form
        onSubmit={scanMode === "adhoc" ? handleAdhocSubmit : (e) => e.preventDefault()}
        className="grid gap-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)] lg:items-start"
      >
        <div className="space-y-5">
          {scanMode === "connected" && (
            <Section title="Connected cloud account">
              {connectionsLoading ? (
                <p className="text-sm text-[color:var(--text-secondary)]">Loading cloud accounts…</p>
              ) : connectionsError ? (
                <p className="text-sm text-red-400">{connectionsError}</p>
              ) : connections.length === 0 ? (
                <div className="space-y-3">
                  <p className="text-sm text-[color:var(--text-secondary)]">
                    No cloud accounts are connected yet. Onboard one to run read-only inventory and CIS for a specific account boundary.
                  </p>
                  <Link
                    href="/connections"
                    className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500"
                  >
                    Connect cloud account
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </div>
              ) : (
                <div className="space-y-3">
                  <label htmlFor="connection-picker" className="text-xs font-medium text-[color:var(--text-secondary)]">
                    Account
                  </label>
                  <select
                    id="connection-picker"
                    value={selectedConnectionId}
                    onChange={(event) => setSelectedConnectionId(event.target.value)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                  >
                    {connections.map((connection) => (
                      <option key={connection.id} value={connection.id}>
                        {providerDisplayName(connection.provider)} · {connection.display_name}
                      </option>
                    ))}
                  </select>
                  {selectedConnection && !isScannableConnection(selectedConnection) ? (
                    <p className="text-xs text-amber-300">
                      Scanning is not available for this provider yet. Test the connection from Cloud Accounts or choose another account.
                    </p>
                  ) : null}
                  <p className="text-xs text-[color:var(--text-tertiary)]">
                    Scope is the connected account boundary — not a per-scan region picker. Update regions on the connection record in Cloud Accounts.
                  </p>
                </div>
              )}
            </Section>
          )}

          {scanMode === "adhoc" && (
            <>
              <div className="flex flex-wrap gap-2">
                {(
                  [
                    { id: "repository" as const, label: "Public repo", icon: Link2, hint: "GitHub/GitLab URL — shallow clone" },
                    { id: "workstation" as const, label: "Workstation", icon: Bot, hint: "Agent projects on this machine" },
                    { id: "containers" as const, label: "Containers", icon: Container, hint: "OCI images and registries" },
                    { id: "kubernetes" as const, label: "Kubernetes", icon: Server, hint: "Pods in current kube context" },
                  ] as const
                ).map((option) => {
                  const Icon = option.icon;
                  const active = target === option.id;
                  return (
                    <button
                      key={option.id}
                      type="button"
                      onClick={() => setTarget(option.id)}
                      className={`min-w-[9.5rem] rounded-xl border px-3 py-2.5 text-left transition ${
                        active
                          ? "border-emerald-600/50 bg-emerald-500/10 text-[color:var(--foreground)]"
                          : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
                      }`}
                    >
                      <div className="flex items-center gap-2 text-sm font-medium">
                        <Icon className="h-4 w-4 shrink-0" />
                        {option.label}
                      </div>
                      <p className="mt-1 text-[11px] text-[color:var(--text-tertiary)]">{option.hint}</p>
                    </button>
                  );
                })}
              </div>

              {target === "repository" && (
                <Section title="Public git repository">
                  <p className="mb-3 text-xs text-[color:var(--text-tertiary)]">
                    Paste an https git URL. We shallow-clone on the control plane, auto-detect OSS apps, agent code,
                    uv.lock/requirements manifests, ingestion pipelines, Terraform/cloud infra, secrets, weak crypto,
                    MCP configs, and skill files — then visualize findings in the graph.
                  </p>
                  <input
                    type="url"
                    placeholder="https://github.com/org/agent-repo"
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 font-mono text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                    value={repoUrlInput}
                    onChange={(event) => {
                      const value = event.target.value;
                      setRepoUrlInput(value);
                      setForm((current) => ({ ...current, repo_url: value.trim() || undefined }));
                    }}
                  />
                  <div className="mt-4 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
                    <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                      Auto-detected at scan time · {repoScanLanguageSummary()}
                    </p>
                    <ul className="mt-2 space-y-2">
                      {REPO_SCAN_SURFACES.map((surface) => (
                        <li key={surface.id} className="text-xs text-[color:var(--text-secondary)]">
                          <span className="font-medium text-[color:var(--foreground)]">{surface.label}</span>
                          {" — "}
                          {surface.detail}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <p className="mt-2 text-xs text-[color:var(--text-tertiary)]">
                    Private repos: set <span className="font-mono">AGENT_BOM_REPO_SCAN_TOKEN</span> on the control plane host.
                  </p>
                </Section>
              )}

              {target === "workstation" && (
                <Section title="Python agent projects">
                  <p className="mb-3 text-xs text-[color:var(--text-tertiary)]">
                    Scan LangChain, CrewAI, or custom agent repos on this workstation. MCP configs in the project are discovered automatically.
                  </p>
                  <ListInput
                    placeholder="/path/to/my-langchain-app"
                    value={apInput}
                    onChange={setApInput}
                    onAdd={() => addToList("agent_projects", apInput, () => setApInput(""))}
                    items={form.agent_projects ?? []}
                    onRemove={(i) => removeFromList("agent_projects", i)}
                  />
                </Section>
              )}

              {target === "containers" && (
                <Section title="Container images">
                  <ListInput
                    placeholder="nginx:1.25 or ghcr.io/org/app:v1"
                    value={imageInput}
                    onChange={setImageInput}
                    onAdd={() => addToList("images", imageInput, () => setImageInput(""))}
                    items={[]}
                    onRemove={() => {}}
                  />
                  <button
                    type="button"
                    onClick={() => setShowBulkImages((current) => !current)}
                    className="mt-3 inline-flex items-center gap-1.5 text-xs text-[color:var(--text-secondary)] transition hover:text-[color:var(--foreground)]"
                  >
                    <ChevronDown className={`h-3.5 w-3.5 transition-transform ${showBulkImages ? "rotate-180" : ""}`} />
                    Add multiple images
                  </button>
                  {showBulkImages && (
                    <div className="mt-3 space-y-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3">
                      <textarea
                        placeholder={"# One image per line\nnginx:1.25\nredis:7-alpine"}
                        value={bulkText}
                        onChange={(e) => setBulkText(e.target.value)}
                        rows={4}
                        className="w-full resize-y rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 font-mono text-sm text-[color:var(--foreground)] placeholder:text-[color:var(--text-tertiary)] focus:border-emerald-600 focus:outline-none"
                      />
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={applyBulk}
                          disabled={!bulkText.trim()}
                          className="flex items-center gap-1.5 rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <Plus className="h-3.5 w-3.5" />
                          Add {parseBulkImages(bulkText).length || 0} image{parseBulkImages(bulkText).length !== 1 ? "s" : ""}
                        </button>
                        <input ref={fileInputRef} type="file" accept=".txt,.csv,.list" onChange={handleFileUpload} className="hidden" />
                        <button
                          type="button"
                          onClick={() => fileInputRef.current?.click()}
                          className="flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)]"
                        >
                          <Upload className="h-3.5 w-3.5" />
                          Import list file
                        </button>
                      </div>
                    </div>
                  )}
                  {queuedImages.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      <div className="text-xs font-medium text-[color:var(--text-tertiary)]">
                        {queuedImages.length} image{queuedImages.length !== 1 ? "s" : ""} queued
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {queuedImages.map((item, i) => (
                          <span key={i} className="flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 font-mono text-xs text-[color:var(--foreground)]">
                            {item}
                            <button type="button" onClick={() => removeFromList("images", i)}>
                              <X className="h-3 w-3 text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]" />
                            </button>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </Section>
              )}

              {target === "kubernetes" && (
                <Section title="Kubernetes cluster">
                  <label className="flex cursor-pointer items-center gap-2">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-emerald-500"
                      checked={form.k8s ?? false}
                      onChange={(e) => setForm((f) => ({ ...f, k8s: e.target.checked }))}
                    />
                    <span className="text-sm text-[color:var(--foreground)]">Scan running pods via current kubectl context</span>
                  </label>
                  {form.k8s && (
                    <div className="mt-3 space-y-1.5">
                      <label htmlFor="k8s-namespace-filter" className="text-xs font-medium text-[color:var(--text-secondary)]">
                        Namespace filter
                      </label>
                      <input
                        id="k8s-namespace-filter"
                        type="text"
                        placeholder="All namespaces"
                        className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                        value={form.k8s_namespace ?? ""}
                        onChange={(e) => setForm((f) => ({ ...f, k8s_namespace: e.target.value || undefined }))}
                      />
                      <p className="text-xs text-[color:var(--text-tertiary)]">
                        Leave blank to scan every namespace visible in your current kube context. Enter one namespace name to limit scope.
                      </p>
                    </div>
                  )}
                </Section>
              )}
            </>
          )}

          {scanMode === "scheduled" && (
            <Section title="Registered data source">
              {sourcesLoading ? (
                <p className="text-sm text-[color:var(--text-secondary)]">Loading data sources…</p>
              ) : sources.length === 0 ? (
                <div className="space-y-3">
                  <p className="text-sm text-[color:var(--text-secondary)]">
                    No data sources are registered. Sources enqueue scan jobs from saved connector or repo configs.
                  </p>
                  <Link
                    href="/sources"
                    className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500"
                  >
                    Register data source
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </div>
              ) : (
                <div className="space-y-3">
                  <label htmlFor="source-picker" className="text-xs font-medium text-[color:var(--text-secondary)]">
                    Source
                  </label>
                  <select
                    id="source-picker"
                    value={selectedSourceId}
                    onChange={(event) => setSelectedSourceId(event.target.value)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                  >
                    {sources.map((source) => (
                      <option key={source.source_id} value={source.source_id}>
                        {source.display_name} · {source.kind}
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-[color:var(--text-tertiary)]">
                    Scope follows the source&apos;s saved config. For recurring cadence, manage schedules from Data Sources.
                  </p>
                  <Link href="/sources" className="inline-flex text-xs text-emerald-400 hover:text-emerald-300">
                    Manage all data sources
                  </Link>
                </div>
              )}
            </Section>
          )}
        </div>

        <div className="space-y-5">
          <ScopeSummaryPanel chips={scopeChips} mode={scanMode} />

          {scanMode === "adhoc" && target !== "repository" && (
            <details className="group rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 text-sm font-semibold text-[color:var(--foreground)] [&::-webkit-details-marker]:hidden">
                Advanced targets
                <ChevronDown className="h-4 w-4 text-[color:var(--text-tertiary)] transition-transform group-open:rotate-180" />
              </summary>
              <div className="space-y-5 border-t border-[color:var(--border-subtle)] px-5 py-4">
                <div>
                  <h3 className="mb-2 text-sm font-medium text-[color:var(--foreground)]">Terraform directories</h3>
                  <ListInput
                    placeholder="/path/to/infra"
                    value={tfInput}
                    onChange={setTfInput}
                    onAdd={() => addToList("tf_dirs", tfInput, () => setTfInput(""))}
                    items={form.tf_dirs ?? []}
                    onRemove={(i) => removeFromList("tf_dirs", i)}
                  />
                </div>
                <div>
                  <h3 className="mb-2 text-sm font-medium text-[color:var(--foreground)]">GitHub Actions</h3>
                  <input
                    type="text"
                    placeholder="/path/to/git/repo"
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                    value={form.gha_path ?? ""}
                    onChange={(e) => setForm((f) => ({ ...f, gha_path: e.target.value || undefined }))}
                  />
                </div>
                <div>
                  <h3 className="mb-2 text-sm font-medium text-[color:var(--foreground)]">Custom inventory</h3>
                  <input
                    type="text"
                    placeholder="/path/to/agents.json"
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                    value={form.inventory ?? ""}
                    onChange={(e) => setForm((f) => ({ ...f, inventory: e.target.value || undefined }))}
                  />
                </div>
              </div>
            </details>
          )}

          {scanMode === "adhoc" && (
            <Section title="Options">
              <label className="flex cursor-pointer items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 rounded border-[color:var(--border-subtle)] bg-[color:var(--surface)] text-emerald-500"
                  checked={form.enrich ?? false}
                  onChange={(e) => setForm((f) => ({ ...f, enrich: e.target.checked }))}
                />
                <span className="text-sm text-[color:var(--foreground)]">
                  Enrich with NVD CVSS, EPSS, and CISA KEV
                  <span className="mt-0.5 block text-xs text-[color:var(--text-tertiary)]">Slower; requires internet</span>
                </span>
              </label>
            </Section>
          )}

          {error && (
            <p className="rounded-lg border border-red-900 bg-red-950 px-4 py-3 text-sm text-red-400">{error}</p>
          )}

          {scanMode === "connected" ? (
            <button
              type="button"
              onClick={handleCloudScan}
              disabled={loading || !cloudScanReady}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-6 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Starting cloud scan...
                </>
              ) : (
                <>
                  Run cloud scan <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          ) : scanMode === "scheduled" ? (
            <button
              type="button"
              onClick={handleSourceRun}
              disabled={loading || !sourceRunReady}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-6 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Running source...
                </>
              ) : (
                <>
                  Run source now <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          ) : (
            <button
              type="submit"
              disabled={loading || !repoScanReady}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-6 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Starting scan...
                </>
              ) : (
                <>
                  {target === "repository" ? "Scan repository" : "Start ad-hoc scan"} <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          )}
        </div>
      </form>
    </div>
  );
}

function ScopeSummaryPanel({ chips, mode }: { chips: ScanScopeChip[]; mode: ScanMode }) {
  const title =
    mode === "connected"
      ? "Cloud scan scope"
      : mode === "scheduled"
        ? "Source scope"
        : "Ad-hoc scan scope";

  return (
    <Section title={title}>
      <p className="mb-3 text-xs text-[color:var(--text-tertiary)]">
        Review what this run will touch before you start.
      </p>
      <dl className="space-y-2">
        {chips.map((chip) => (
          <div key={`${chip.label}-${chip.value}`} className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
            <dt className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
              {chip.label}
            </dt>
            <dd className="mt-0.5 text-sm text-[color:var(--foreground)]">{chip.value}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function RelatedLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link href={href} className="text-[color:var(--text-secondary)] transition-colors hover:text-emerald-400">
      {children}
    </Link>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
      <h3 className="mb-3 text-sm font-semibold text-[color:var(--foreground)]">{title}</h3>
      {children}
    </div>
  );
}

function ListInput({
  placeholder, value, onChange, onAdd, items, onRemove,
}: {
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  onAdd: () => void;
  items: string[];
  onRemove: (i: number) => void;
}) {
  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <input
          type="text"
          placeholder={placeholder}
          className="flex-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onAdd(); } }}
        />
        <button
          type="button"
          onClick={onAdd}
          className="flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs text-[color:var(--foreground)] transition-colors hover:border-[color:var(--border-strong)]"
        >
          <Plus className="h-3.5 w-3.5" />
          Add
        </button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {items.map((item, i) => (
            <span key={i} className="flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 font-mono text-xs text-[color:var(--foreground)]">
              {item}
              <button type="button" onClick={() => onRemove(i)}>
                <X className="h-3 w-3 text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
