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
  Sparkles,
  X,
} from "lucide-react";

import { AiScanPanel } from "@/components/ai-scan-panel";

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

/** Scan sources shown in the top tablist. Extends the job-queue ``ScanMode``
 * with the synchronous AI/ML supply-chain surface, which renders its results
 * inline rather than routing to a job. */
type FormMode = ScanMode | "aiml";

type ScanFormProps = {
  initialConnectionId?: string | undefined;
  /**
   * Optional preset carried in the URL (``/scan?preset=enterprise``) by the
   * in-product "Run introspection scan" actions. It pre-fills the form to the
   * equivalent of the ``agent-bom scan --introspect --preset enterprise`` CLI:
   * an ad-hoc workstation introspection scan with enrichment on. Absent or
   * unknown values leave the normal defaults untouched.
   */
  initialPreset?: string | undefined;
};

/** ``enterprise`` mirrors ``--introspect --preset enterprise``: an ad-hoc
 * workstation introspection scan with CVSS/EPSS/KEV enrichment enabled. */
function isEnterprisePreset(preset: string | undefined): boolean {
  return preset === "enterprise";
}

/** Client-side guard: accept only well-formed ``http(s)://<host>`` repo URLs
 * before enabling submit. Server-side validation remains authoritative. */
function isHttpRepoUrl(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  return Boolean(parsed.hostname) && parsed.hostname.includes(".");
}

export function ScanForm({ initialConnectionId, initialPreset }: ScanFormProps) {
  const router = useRouter();
  const { counts } = useDeploymentContext();
  const deploymentMode = counts?.deployment_mode ?? "local";
  const enterprisePreset = isEnterprisePreset(initialPreset);
  const [scanMode, setScanMode] = useState<FormMode>(
    initialConnectionId
      ? "connected"
      : enterprisePreset
        ? "adhoc"
        : deploymentMode === "local"
          ? "adhoc"
          : "connected",
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
    enrich: enterprisePreset,
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
              agent_projects: (form.agent_projects ?? []).map((p) => p.trim()).filter(Boolean),
              tf_dirs: (form.tf_dirs ?? []).map((p) => p.trim()).filter(Boolean),
              gha_path: form.gha_path?.trim() || undefined,
              repo_url: undefined,
            };
      if (target === "repository" && !isHttpRepoUrl(repoUrlInput)) {
        setError("Enter a valid public repository URL (https://github.com/org/repo)");
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
  const repoUrlValid = isHttpRepoUrl(repoUrlInput);
  const repoUrlInvalid = target === "repository" && repoUrlInput.trim().length > 0 && !repoUrlValid;
  const repoScanReady = target !== "repository" || repoUrlValid;

  return (
    <div className="max-w-4xl" data-testid="scan-form">
      <header className="mb-6 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">New Scan</h1>
            <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-0.5 text-[10px] font-mono uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
              {deploymentLabel}
            </span>
          </div>
          <p className="mt-1 text-sm text-[color:var(--text-secondary)]">Choose a source, set the target, run.</p>
        </div>
        <Link
          href="/connections"
          className="hidden shrink-0 items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] sm:inline-flex"
        >
          Connect account <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </header>

      <div className="overflow-hidden rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
        <div
          role="tablist"
          aria-label="Scan source"
          className="flex border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-1"
        >
          {(
            [
              { id: "connected" as const, label: "Cloud account", icon: Cloud },
              { id: "adhoc" as const, label: "Ad-hoc", icon: Bot },
              { id: "scheduled" as const, label: "Data source", icon: CalendarClock },
              { id: "aiml" as const, label: "AI / ML", icon: Sparkles },
            ] as const
          ).map((option) => {
            const Icon = option.icon;
            const active = scanMode === option.id;
            return (
              <button
                key={option.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setScanMode(option.id)}
                className={`flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2.5 text-sm font-medium transition ${
                  active
                    ? "bg-[color:var(--surface)] text-[color:var(--foreground)] shadow-sm"
                    : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {option.label}
              </button>
            );
          })}
        </div>

        {scanMode === "aiml" ? (
          <div className="p-5">
            <AiScanPanel />
          </div>
        ) : (
        <form
          onSubmit={scanMode === "adhoc" ? handleAdhocSubmit : (e) => e.preventDefault()}
          className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_220px]"
        >
          <div className="space-y-4 p-5">
            {scanMode === "connected" && (
              <ConnectedAccountPanel
                connections={connections}
                connectionsLoading={connectionsLoading}
                connectionsError={connectionsError}
                selectedConnectionId={selectedConnectionId}
                onSelectConnection={setSelectedConnectionId}
                selectedConnection={selectedConnection}
              />
            )}

            {scanMode === "adhoc" && (
              <>
                <div role="tablist" aria-label="Ad-hoc target" className="flex flex-wrap gap-1.5">
                  {(
                    [
                      { id: "repository" as const, label: "Public repo", icon: Link2 },
                      { id: "workstation" as const, label: "Workstation", icon: Bot },
                      { id: "containers" as const, label: "Containers", icon: Container },
                      { id: "kubernetes" as const, label: "Kubernetes", icon: Server },
                    ] as const
                  ).map((option) => {
                    const Icon = option.icon;
                    const active = target === option.id;
                    return (
                      <button
                        key={option.id}
                        type="button"
                        role="tab"
                        aria-selected={active}
                        onClick={() => setTarget(option.id)}
                        className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                          active
                            ? "border-emerald-600/50 bg-emerald-500/10 text-[color:var(--foreground)]"
                            : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
                        }`}
                      >
                        <Icon className="h-3.5 w-3.5" />
                        {option.label}
                      </button>
                    );
                  })}
                </div>

                {target === "repository" && (
                  <div className="space-y-3">
                    <input
                      type="url"
                      aria-label="Public repository URL"
                      placeholder="https://github.com/org/repo"
                      aria-invalid={repoUrlInvalid}
                      className={`w-full rounded-xl border bg-[color:var(--surface-muted)] px-4 py-3 font-mono text-sm text-[color:var(--foreground)] focus:outline-none ${
                        repoUrlInvalid
                          ? "border-red-600/70 focus:border-red-500"
                          : "border-[color:var(--border-subtle)] focus:border-emerald-600"
                      }`}
                      value={repoUrlInput}
                      onChange={(event) => {
                        const value = event.target.value;
                        setRepoUrlInput(value);
                        setForm((current) => ({ ...current, repo_url: value.trim() || undefined }));
                      }}
                    />
                    {repoUrlInvalid ? (
                      <p className="text-xs text-red-400">Enter a full http(s):// URL, e.g. https://github.com/org/repo</p>
                    ) : null}
                    <RepoSurfaceCatalog />
                  </div>
                )}

                {target === "workstation" && (
                  <ListInput
                    placeholder="/path/to/agent-project"
                    value={apInput}
                    onChange={setApInput}
                    onAdd={() => addToList("agent_projects", apInput, () => setApInput(""))}
                    items={form.agent_projects ?? []}
                    onRemove={(i) => removeFromList("agent_projects", i)}
                  />
                )}

                {target === "containers" && (
                  <ContainerTargetPanel
                    imageInput={imageInput}
                    setImageInput={setImageInput}
                    onAdd={() => addToList("images", imageInput, () => setImageInput(""))}
                    queuedImages={queuedImages}
                    onRemove={(i) => removeFromList("images", i)}
                    showBulkImages={showBulkImages}
                    setShowBulkImages={setShowBulkImages}
                    bulkText={bulkText}
                    setBulkText={setBulkText}
                    applyBulk={applyBulk}
                    parseBulkImages={parseBulkImages}
                    fileInputRef={fileInputRef}
                    handleFileUpload={handleFileUpload}
                  />
                )}

                {target === "kubernetes" && (
                  <div className="space-y-3">
                    <label className="flex cursor-pointer items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
                      <input
                        type="checkbox"
                        className="h-4 w-4 rounded border-[color:var(--border-subtle)] text-emerald-500"
                        checked={form.k8s ?? false}
                        onChange={(e) => setForm((f) => ({ ...f, k8s: e.target.checked }))}
                      />
                      <span className="text-sm text-[color:var(--foreground)]">Scan pods in current kube context</span>
                    </label>
                    {form.k8s ? (
                      <input
                        id="k8s-namespace-filter"
                        aria-label="Namespace filter"
                        type="text"
                        placeholder="All namespaces"
                        className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
                        value={form.k8s_namespace ?? ""}
                        onChange={(e) => setForm((f) => ({ ...f, k8s_namespace: e.target.value || undefined }))}
                      />
                    ) : null}
                  </div>
                )}

                {target !== "repository" && (
                  <details className="group rounded-xl border border-[color:var(--border-subtle)]">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-3 text-xs font-medium text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
                      Advanced targets
                      <ChevronDown className="h-3.5 w-3.5 transition-transform group-open:rotate-180" />
                    </summary>
                    <div className="space-y-3 border-t border-[color:var(--border-subtle)] px-4 py-3">
                      <ListInput
                        placeholder="Terraform directory"
                        value={tfInput}
                        onChange={setTfInput}
                        onAdd={() => addToList("tf_dirs", tfInput, () => setTfInput(""))}
                        items={form.tf_dirs ?? []}
                        onRemove={(i) => removeFromList("tf_dirs", i)}
                      />
                      <input
                        type="text"
                        placeholder="GitHub Actions repo path"
                        className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm"
                        value={form.gha_path ?? ""}
                        onChange={(e) => setForm((f) => ({ ...f, gha_path: e.target.value || undefined }))}
                      />
                    </div>
                  </details>
                )}
              </>
            )}

            {scanMode === "scheduled" && (
              <ScheduledSourcePanel
                sources={sources}
                sourcesLoading={sourcesLoading}
                selectedSourceId={selectedSourceId}
                onSelectSource={setSelectedSourceId}
              />
            )}

            {scanMode === "adhoc" && (
              <label className="flex items-center gap-2 text-xs text-[color:var(--text-secondary)]">
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 rounded border-[color:var(--border-subtle)] text-emerald-500"
                  checked={form.enrich ?? false}
                  onChange={(e) => setForm((f) => ({ ...f, enrich: e.target.checked }))}
                />
                Enrich with CVSS / EPSS / KEV (slower)
              </label>
            )}

            {error ? (
              <p className="rounded-lg border border-red-900/60 bg-red-950/30 px-3 py-2 text-sm text-red-400">{error}</p>
            ) : null}
          </div>

          <aside className="flex flex-col border-t border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4 lg:border-t-0 lg:border-l">
            <ScopeSummaryPanel chips={scopeChips} mode={scanMode} />
            <div className="mt-auto pt-4">
              {scanMode === "connected" ? (
                <button
                  type="button"
                  onClick={handleCloudScan}
                  disabled={loading || !cloudScanReady}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Run cloud scan <ArrowRight className="h-4 w-4" />
                </button>
              ) : scanMode === "scheduled" ? (
                <button
                  type="button"
                  onClick={handleSourceRun}
                  disabled={loading || !sourceRunReady}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Run source <ArrowRight className="h-4 w-4" />
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={loading || !repoScanReady}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  {target === "repository" ? "Scan repo" : "Start scan"} <ArrowRight className="h-4 w-4" />
                </button>
              )}
            </div>
          </aside>
        </form>
        )}
      </div>

      <nav aria-label="Related" className="mt-4 flex flex-wrap gap-3 text-xs text-[color:var(--text-tertiary)]">
        <RelatedLink href="/connections">Cloud accounts</RelatedLink>
        <RelatedLink href="/sources">Data sources</RelatedLink>
        <RelatedLink href="/jobs">Scan jobs</RelatedLink>
      </nav>
    </div>
  );
}

function ScopeSummaryPanel({ chips, mode }: { chips: ScanScopeChip[]; mode: FormMode }) {
  const title = mode === "connected" ? "Scope" : mode === "scheduled" ? "Scope" : "Scope";

  return (
    <div>
      <h2 className="text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{title}</h2>
      <div className="mt-2 flex flex-col gap-1.5">
        {chips.map((chip) => (
          <div key={`${chip.label}-${chip.value}`} className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-2">
            <p className="text-[10px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">{chip.label}</p>
            <p className="mt-0.5 text-xs text-[color:var(--foreground)]">{chip.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConnectedAccountPanel({
  connections,
  connectionsLoading,
  connectionsError,
  selectedConnectionId,
  onSelectConnection,
  selectedConnection,
}: {
  connections: CloudConnectionRecord[];
  connectionsLoading: boolean;
  connectionsError: string;
  selectedConnectionId: string;
  onSelectConnection: (id: string) => void;
  selectedConnection: CloudConnectionRecord | null;
}) {
  if (connectionsLoading) return <p className="text-sm text-[color:var(--text-secondary)]">Loading…</p>;
  if (connectionsError) return <p className="text-sm text-red-400">{connectionsError}</p>;
  if (connections.length === 0) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-[color:var(--text-secondary)]">No accounts connected.</p>
        <Link href="/connections" className="inline-flex items-center gap-1.5 text-sm text-emerald-400 hover:text-emerald-300">
          Connect account <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <select
        id="connection-picker"
        aria-label="Account"
        value={selectedConnectionId}
        onChange={(event) => onSelectConnection(event.target.value)}
        className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2.5 text-sm text-[color:var(--foreground)] focus:border-emerald-600 focus:outline-none"
      >
        {connections.map((connection) => (
          <option key={connection.id} value={connection.id}>
            {providerDisplayName(connection.provider)} · {connection.display_name}
          </option>
        ))}
      </select>
      {selectedConnection && !isScannableConnection(selectedConnection) ? (
        <p className="text-xs text-amber-300">Provider not scannable yet.</p>
      ) : null}
    </div>
  );
}

function ScheduledSourcePanel({
  sources,
  sourcesLoading,
  selectedSourceId,
  onSelectSource,
}: {
  sources: SourceRecord[];
  sourcesLoading: boolean;
  selectedSourceId: string;
  onSelectSource: (id: string) => void;
}) {
  if (sourcesLoading) return <p className="text-sm text-[color:var(--text-secondary)]">Loading…</p>;
  if (sources.length === 0) {
    return (
      <Link href="/sources" className="inline-flex items-center gap-1.5 text-sm text-emerald-400 hover:text-emerald-300">
        Register data source <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    );
  }
  return (
    <select
      id="source-picker"
      aria-label="Source"
      value={selectedSourceId}
      onChange={(event) => onSelectSource(event.target.value)}
      className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2.5 text-sm focus:border-emerald-600 focus:outline-none"
    >
      {sources.map((source) => (
        <option key={source.source_id} value={source.source_id}>
          {source.display_name} · {source.kind}
        </option>
      ))}
    </select>
  );
}

function RepoSurfaceCatalog() {
  return (
    <details className="group rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2.5 text-xs text-[color:var(--text-secondary)] [&::-webkit-details-marker]:hidden">
        <span>
          {REPO_SCAN_SURFACES.length} surfaces auto-detected · {repoScanLanguageSummary()}
        </span>
        <ChevronDown className="h-3.5 w-3.5 shrink-0 transition-transform group-open:rotate-180" />
      </summary>
      <div className="border-t border-[color:var(--border-subtle)] px-3 py-3">
        <div className="flex flex-wrap gap-1.5">
          {REPO_SCAN_SURFACES.map((surface) => (
            <span
              key={surface.id}
              title={surface.detail}
              className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] text-[color:var(--text-secondary)]"
            >
              {surface.label}
            </span>
          ))}
        </div>
        <p className="mt-2 text-[10px] text-[color:var(--text-tertiary)]">
          Shallow read-only clone. Optional Semgrep SAST reports findings, clean, skipped, or failed explicitly. SaaS connectors use{" "}
          <Link href="/sources" className="text-emerald-400 hover:text-emerald-300">Data Sources</Link>, not git URLs.
        </p>
      </div>
    </details>
  );
}

function ContainerTargetPanel({
  imageInput,
  setImageInput,
  onAdd,
  queuedImages,
  onRemove,
  showBulkImages,
  setShowBulkImages,
  bulkText,
  setBulkText,
  applyBulk,
  parseBulkImages,
  fileInputRef,
  handleFileUpload,
}: {
  imageInput: string;
  setImageInput: (value: string) => void;
  onAdd: () => void;
  queuedImages: string[];
  onRemove: (index: number) => void;
  showBulkImages: boolean;
  setShowBulkImages: (value: boolean | ((current: boolean) => boolean)) => void;
  bulkText: string;
  setBulkText: (value: string) => void;
  applyBulk: () => void;
  parseBulkImages: (text: string) => string[];
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  handleFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <div className="space-y-3">
      <ListInput
        placeholder="nginx:1.25 or ghcr.io/org/app:v1"
        value={imageInput}
        onChange={setImageInput}
        onAdd={onAdd}
        items={[]}
        onRemove={() => {}}
      />
      <button
        type="button"
        onClick={() => setShowBulkImages((current) => !current)}
        className="text-xs text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
      >
        {showBulkImages ? "Hide bulk add" : "Bulk add images"}
      </button>
      {showBulkImages ? (
        <textarea
          placeholder={"# one image per line"}
          value={bulkText}
          onChange={(e) => setBulkText(e.target.value)}
          rows={3}
          className="w-full resize-y rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 font-mono text-xs"
        />
      ) : null}
      {showBulkImages ? (
        <div className="flex gap-2">
          <button type="button" onClick={applyBulk} disabled={!bulkText.trim()} className="rounded-lg bg-emerald-700 px-3 py-1.5 text-xs text-white disabled:opacity-40">
            Add {parseBulkImages(bulkText).length || 0}
          </button>
          <input ref={fileInputRef} type="file" accept=".txt,.csv,.list" onChange={handleFileUpload} className="hidden" />
          <button type="button" onClick={() => fileInputRef.current?.click()} className="rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-xs">
            Import file
          </button>
        </div>
      ) : null}
      {queuedImages.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {queuedImages.map((item, i) => (
            <span key={i} className="flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-0.5 font-mono text-[10px]">
              {item}
              <button type="button" onClick={() => onRemove(i)} aria-label={`Remove ${item}`}>
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function RelatedLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link href={href} className="text-[color:var(--text-secondary)] transition-colors hover:text-emerald-400">
      {children}
    </Link>
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
