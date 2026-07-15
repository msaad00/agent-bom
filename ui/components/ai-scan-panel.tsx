"use client";

import { useMemo, useState, type ReactNode } from "react";
import { ArrowRight, Loader2, Plus, ScanSearch, ShieldCheck, X } from "lucide-react";

import { api } from "@/lib/api";
import {
  AI_SCAN_TYPES,
  aiSeverityRank,
  highestFlagSeverity,
  type AiScanResponse,
  type AiScanTypeId,
  type AiSecurityFlag,
  type BrowserExtension,
  type BrowserExtensionsResponse,
  type DatasetCard,
  type DatasetCardsResponse,
  type ModelFileEntry,
  type ModelFilesResponse,
  type ModelProvenanceResponse,
  type PromptFinding,
  type PromptScanResponse,
  type ProvenanceResult,
  type TrainingArtifact,
  type TrainingPipelinesResponse,
} from "@/lib/ai-scan";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { Drawer } from "@/components/drawer";
import { SeverityBadge } from "@/components/severity-badge";
import { StatStrip, type StatStripItem } from "@/components/stat-strip";
import {
  PageEmptyState,
  PageErrorState,
  PageLoadingState,
} from "@/components/states/page-state";

/** Normalized detail record shown in the drawer for any scan-type row. */
type DetailView = {
  eyebrow: string;
  title: string;
  subtitle?: string | undefined;
  flags?: AiSecurityFlag[] | undefined;
  fields: { label: string; value: ReactNode }[];
};

function cleanList(values: string[]): string[] {
  return values.map((v) => v.trim()).filter(Boolean);
}

export function AiScanPanel() {
  const [scanType, setScanType] = useState<AiScanTypeId>("dataset-cards");
  const [dirs, setDirs] = useState<string[]>([]);
  const [files, setFiles] = useState<string[]>([]);
  const [hfModels, setHfModels] = useState<string[]>([]);
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [includeLowRisk, setIncludeLowRisk] = useState(false);
  const [verifyHashes, setVerifyHashes] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<AiScanResponse | null>(null);
  const [detail, setDetail] = useState<DetailView | null>(null);

  const meta = useMemo(
    () => AI_SCAN_TYPES.find((t) => t.id === scanType) ?? AI_SCAN_TYPES[0]!,
    [scanType],
  );
  const kind = meta.inputKind;

  function selectType(next: AiScanTypeId) {
    setScanType(next);
    setResult(null);
    setError("");
    setDetail(null);
  }

  const cleanedDirs = cleanList(dirs);
  const cleanedFiles = cleanList(files);
  const cleanedHf = cleanList(hfModels);
  const cleanedOllama = cleanList(ollamaModels);

  const canRun = (() => {
    switch (kind) {
      case "directories":
      case "model-files":
        return cleanedDirs.length > 0;
      case "prompt":
        return cleanedDirs.length > 0 || cleanedFiles.length > 0;
      case "models":
        return cleanedHf.length > 0 || cleanedOllama.length > 0;
      case "extensions":
        return true;
      default:
        return false;
    }
  })();

  async function run() {
    if (!canRun || loading) return;
    setLoading(true);
    setError("");
    setDetail(null);
    try {
      let response: AiScanResponse;
      switch (scanType) {
        case "dataset-cards":
          response = await api.scanDatasetCards({ directories: cleanedDirs });
          break;
        case "training-pipelines":
          response = await api.scanTrainingPipelines({ directories: cleanedDirs });
          break;
        case "browser-extensions":
          response = await api.scanBrowserExtensions({ include_low_risk: includeLowRisk });
          break;
        case "model-provenance":
          response = await api.scanModelProvenance({
            hf_models: cleanedHf,
            ollama_models: cleanedOllama,
          });
          break;
        case "prompt-scan":
          response = await api.scanPrompts({
            directories: cleanedDirs,
            files: cleanedFiles,
          });
          break;
        case "model-files":
          response = await api.scanModelFiles({
            directories: cleanedDirs,
            verify_hashes: verifyHashes,
          });
          break;
      }
      setResult(response);
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,15rem)_minmax(0,1fr)]" data-testid="ai-scan-panel">
      <nav aria-label="AI supply-chain scan type" className="space-y-2">
        <p className="px-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
          AI supply chain
        </p>
        <ul className="space-y-1.5">
          {AI_SCAN_TYPES.map((type) => {
            const active = type.id === scanType;
            return (
              <li key={type.id}>
                <button
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => selectType(type.id)}
                  className={`w-full rounded-xl border px-3 py-2.5 text-left transition ${
                    active
                      ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)]"
                      : "border-[color:var(--border-subtle)] bg-[color:var(--surface)] hover:border-[color:var(--border-strong)]"
                  }`}
                >
                  <span
                    className={`block text-sm font-medium ${
                      active ? "text-[color:var(--accent)]" : "text-[color:var(--foreground)]"
                    }`}
                  >
                    {type.label}
                  </span>
                  <span className="mt-0.5 block text-xs leading-snug text-[color:var(--text-secondary)]">
                    {type.blurb}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="min-w-0 space-y-4">
        <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 elev-1">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-[color:var(--foreground)]">{meta.label}</h2>
            <p className="mt-1 text-sm text-[color:var(--text-secondary)]">{meta.blurb}</p>
          </div>

          <div className="space-y-3">
            {(kind === "directories" || kind === "prompt" || kind === "model-files") && (
              <PathListInput
                label="Directories"
                placeholder="/path/to/scan"
                items={dirs}
                onChange={setDirs}
              />
            )}

            {kind === "prompt" && (
              <PathListInput
                label="Prompt files (optional)"
                placeholder="/path/to/system.prompt"
                items={files}
                onChange={setFiles}
              />
            )}

            {kind === "models" && (
              <>
                <PathListInput
                  label="HuggingFace models"
                  placeholder="meta-llama/Llama-2-7b-hf"
                  mono
                  items={hfModels}
                  onChange={setHfModels}
                />
                <PathListInput
                  label="Ollama models"
                  placeholder="llama2"
                  mono
                  items={ollamaModels}
                  onChange={setOllamaModels}
                />
              </>
            )}

            {kind === "extensions" && (
              <label className="flex cursor-pointer items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-[color:var(--border-subtle)]"
                  checked={includeLowRisk}
                  onChange={(e) => setIncludeLowRisk(e.target.checked)}
                />
                <span className="text-sm text-[color:var(--foreground)]">
                  Include low-risk extensions
                </span>
              </label>
            )}

            {kind === "model-files" && (
              <label className="flex cursor-pointer items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-[color:var(--border-subtle)]"
                  checked={verifyHashes}
                  onChange={(e) => setVerifyHashes(e.target.checked)}
                />
                <span className="text-sm text-[color:var(--foreground)]">
                  Compute SHA-256 integrity hashes (slower)
                </span>
              </label>
            )}
          </div>

          {error ? (
            <p className="mt-3 rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-sm text-[color:var(--severity-critical)]">
              {error}
            </p>
          ) : null}

          <div className="mt-4 flex items-center justify-between gap-3">
            <p className="text-xs text-[color:var(--text-tertiary)]">
              {kind === "extensions"
                ? "Scans browser extensions installed on the control-plane host."
                : "Paths resolve on the control-plane host running the scan."}
            </p>
            <button
              type="button"
              onClick={run}
              disabled={!canRun || loading}
              className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-[color:var(--accent)] px-4 py-2.5 text-sm font-medium text-[color:var(--accent-contrast)] transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ScanSearch className="h-4 w-4" />
              )}
              Run scan <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>

        <AiScanResults
          loading={loading}
          error={error}
          result={result}
          onOpenDetail={setDetail}
        />
      </div>

      <Drawer
        open={detail !== null}
        onClose={() => setDetail(null)}
        eyebrow={detail?.eyebrow}
        title={detail?.title ?? ""}
        subtitle={detail?.subtitle}
        size="2xl"
      >
        {detail ? <DetailBody detail={detail} /> : null}
      </Drawer>
    </div>
  );
}

// ─── Results ────────────────────────────────────────────────────────────────

function AiScanResults({
  loading,
  error,
  result,
  onOpenDetail,
}: {
  loading: boolean;
  error: string;
  result: AiScanResponse | null;
  onOpenDetail: (detail: DetailView) => void;
}) {
  if (loading) {
    return (
      <PageLoadingState
        title="Scanning…"
        detail="Running the scan on the control-plane host and collecting real results."
        data-testid="ai-scan-loading"
      />
    );
  }
  if (error) {
    return (
      <PageErrorState
        title="Scan failed"
        detail={error}
        data-testid="ai-scan-error"
      />
    );
  }
  if (!result) {
    return (
      <PageEmptyState
        title="No scan run yet"
        detail="Set the inputs above and run the scan. Results are rendered here from the API — nothing is sampled or faked."
        icon={ShieldCheck}
        data-testid="ai-scan-empty"
      />
    );
  }

  switch (result.scan_type) {
    case "dataset-cards":
      return <DatasetCardsResult result={result} onOpenDetail={onOpenDetail} />;
    case "training-pipelines":
      return <TrainingPipelinesResult result={result} onOpenDetail={onOpenDetail} />;
    case "browser-extensions":
      return <BrowserExtensionsResult result={result} onOpenDetail={onOpenDetail} />;
    case "model-provenance":
      return <ModelProvenanceResult result={result} onOpenDetail={onOpenDetail} />;
    case "prompt-scan":
      return <PromptScanResult result={result} onOpenDetail={onOpenDetail} />;
    case "model-files":
      return <ModelFilesResult result={result} onOpenDetail={onOpenDetail} />;
    default:
      return null;
  }
}

function FlagCell({ flags }: { flags: AiSecurityFlag[] | undefined }) {
  const highest = highestFlagSeverity(flags);
  if (!highest) {
    return <span className="text-xs text-[color:var(--status-success)]">clean</span>;
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <SeverityBadge severity={highest} />
      {flags && flags.length > 1 ? (
        <span className="text-xs tabular-nums text-[color:var(--text-tertiary)]">×{flags.length}</span>
      ) : null}
    </span>
  );
}

function BoolTag({ value, trueLabel, falseLabel }: { value: boolean | undefined; trueLabel: string; falseLabel: string }) {
  return (
    <span className={`text-xs ${value ? "text-[color:var(--status-warn)]" : "text-[color:var(--text-tertiary)]"}`}>
      {value ? trueLabel : falseLabel}
    </span>
  );
}

function DatasetCardsResult({
  result,
  onOpenDetail,
}: {
  result: DatasetCardsResponse;
  onOpenDetail: (d: DetailView) => void;
}) {
  const datasets = result.results.flatMap((r) => r.datasets);
  const warnings = result.results.flatMap((r) => r.warnings);
  const flagged = result.results.reduce((sum, r) => sum + r.flagged_count, 0);
  const stats: StatStripItem[] = [
    { label: "Directories", value: result.directories.length },
    { label: "Datasets", value: datasets.length },
    { label: "Flagged", value: flagged, accent: "high" },
    { label: "Warnings", value: warnings.length, accent: "warn" },
  ];
  const columns: DataTableColumn<DatasetCard>[] = [
    { key: "name", header: "Dataset", cell: (d) => <span className="text-[color:var(--foreground)]">{d.name}</span> },
    { key: "license", header: "License", cell: (d) => d.license || "—" },
    { key: "source", header: "Source", cell: (d) => <span className="font-mono text-xs">{d.source_file ?? "—"}</span> },
    { key: "flags", header: "Risk", cell: (d) => <FlagCell flags={d.security_flags} /> },
  ];
  return (
    <ResultShell stats={stats} warnings={warnings}>
      <DataTable
        data-testid="ai-scan-table"
        rows={datasets}
        rowKey={(d, i) => `${d.source_file ?? d.name}-${i}`}
        columns={columns}
        onRowClick={(d) =>
          onOpenDetail({
            eyebrow: "Dataset card",
            title: d.name,
            subtitle: d.source_file,
            flags: d.security_flags,
            fields: buildFields(d, ["name", "security_flags", "source_file"]),
          })
        }
        empty="No dataset cards found in the scanned directories."
      />
    </ResultShell>
  );
}

function TrainingPipelinesResult({
  result,
  onOpenDetail,
}: {
  result: TrainingPipelinesResponse;
  onOpenDetail: (d: DetailView) => void;
}) {
  type Row = TrainingArtifact & { _kind: "run" | "serving" };
  const rows: Row[] = [
    ...result.results.flatMap((r) => r.training_runs.map((t) => ({ ...t, _kind: "run" as const }))),
    ...result.results.flatMap((r) => r.serving_configs.map((t) => ({ ...t, _kind: "serving" as const }))),
  ];
  const warnings = result.results.flatMap((r) => r.warnings);
  const flagged = result.results.reduce((sum, r) => sum + r.flagged_count, 0);
  const stats: StatStripItem[] = [
    { label: "Training runs", value: result.results.reduce((s, r) => s + r.total_runs, 0) },
    { label: "Serving configs", value: result.results.reduce((s, r) => s + r.total_serving, 0) },
    { label: "Flagged", value: flagged, accent: "high" },
    { label: "Warnings", value: warnings.length, accent: "warn" },
  ];
  const columns: DataTableColumn<Row>[] = [
    { key: "name", header: "Artifact", cell: (t) => <span className="text-[color:var(--foreground)]">{t.name}</span> },
    { key: "kind", header: "Kind", cell: (t) => (t._kind === "run" ? "Training run" : "Serving config") },
    { key: "framework", header: "Framework", cell: (t) => t.framework ?? "—" },
    { key: "source", header: "Source", cell: (t) => <span className="font-mono text-xs">{t.source_file ?? "—"}</span> },
    { key: "flags", header: "Risk", cell: (t) => <FlagCell flags={t.security_flags} /> },
  ];
  return (
    <ResultShell stats={stats} warnings={warnings}>
      <DataTable
        data-testid="ai-scan-table"
        rows={rows}
        rowKey={(t, i) => `${t._kind}-${t.source_file ?? t.name}-${i}`}
        columns={columns}
        onRowClick={(t) =>
          onOpenDetail({
            eyebrow: t._kind === "run" ? "Training run" : "Serving config",
            title: t.name,
            subtitle: t.source_file,
            flags: t.security_flags,
            fields: buildFields(t, ["name", "security_flags", "source_file", "_kind"]),
          })
        }
        empty="No training or serving artifacts found."
      />
    </ResultShell>
  );
}

function BrowserExtensionsResult({
  result,
  onOpenDetail,
}: {
  result: BrowserExtensionsResponse;
  onOpenDetail: (d: DetailView) => void;
}) {
  const rows = [...result.extensions].sort(
    (a, b) => aiSeverityRank(b.risk_level) - aiSeverityRank(a.risk_level),
  );
  const stats: StatStripItem[] = [
    { label: "Extensions", value: result.total },
    { label: "Critical", value: result.critical, accent: "critical" },
    { label: "High", value: result.high, accent: "high" },
  ];
  const columns: DataTableColumn<BrowserExtension>[] = [
    { key: "name", header: "Extension", cell: (e) => <span className="text-[color:var(--foreground)]">{e.name}</span> },
    { key: "browser", header: "Browser", cell: (e) => e.browser ?? "—" },
    { key: "risk", header: "Risk", cell: (e) => (e.risk_level ? <SeverityBadge severity={e.risk_level} /> : "—") },
    { key: "perms", header: "Perms", align: "right", cell: (e) => (e.permissions?.length ?? 0) + (e.host_permissions?.length ?? 0) },
    { key: "native", header: "Native msg", cell: (e) => <BoolTag value={e.has_native_messaging} trueLabel="yes" falseLabel="no" /> },
    { key: "ai", header: "AI host", cell: (e) => <BoolTag value={e.has_ai_host_access} trueLabel="yes" falseLabel="no" /> },
  ];
  return (
    <ResultShell stats={stats} warnings={[]}>
      <DataTable
        data-testid="ai-scan-table"
        rows={rows}
        rowKey={(e, i) => `${e.id}-${i}`}
        columns={columns}
        onRowClick={(e) =>
          onOpenDetail({
            eyebrow: `${e.browser ?? "Extension"} · ${e.risk_level ?? "unknown"} risk`,
            title: e.name,
            subtitle: e.id,
            fields: buildFields(e, ["name", "id", "browser", "risk_level"]),
          })
        }
        empty="No extensions matched the risk filter."
      />
    </ResultShell>
  );
}

function ModelProvenanceResult({
  result,
  onOpenDetail,
}: {
  result: ModelProvenanceResponse;
  onOpenDetail: (d: DetailView) => void;
}) {
  const rows = [...result.results].sort(
    (a, b) => aiSeverityRank(b.risk_level) - aiSeverityRank(a.risk_level),
  );
  const stats: StatStripItem[] = [
    { label: "Models", value: result.total },
    { label: "Unsafe format", value: result.unsafe_format, accent: "critical" },
  ];
  const columns: DataTableColumn<ProvenanceResult>[] = [
    { key: "model", header: "Model", cell: (m) => <span className="font-mono text-xs text-[color:var(--foreground)]">{m.model_id}</span> },
    { key: "source", header: "Source", cell: (m) => m.source ?? "—" },
    { key: "format", header: "Format", cell: (m) => m.format ?? "—" },
    {
      key: "safe",
      header: "Serialization",
      cell: (m) =>
        m.is_safe_format ? (
          <span className="text-xs text-[color:var(--status-success)]">safe</span>
        ) : (
          <span className="text-xs text-[color:var(--severity-critical)]">unsafe</span>
        ),
    },
    { key: "risk", header: "Risk", cell: (m) => (m.risk_level ? <SeverityBadge severity={m.risk_level} /> : "—") },
  ];
  return (
    <ResultShell stats={stats} warnings={[]}>
      <DataTable
        data-testid="ai-scan-table"
        rows={rows}
        rowKey={(m, i) => `${m.model_id}-${i}`}
        columns={columns}
        onRowClick={(m) =>
          onOpenDetail({
            eyebrow: `${m.source ?? "model"} provenance`,
            title: m.model_id,
            subtitle: m.format,
            fields: buildFields(m, ["model_id"]),
          })
        }
        empty="No models resolved. Check the model IDs and network access."
      />
    </ResultShell>
  );
}

function PromptScanResult({
  result,
  onOpenDetail,
}: {
  result: PromptScanResponse;
  onOpenDetail: (d: DetailView) => void;
}) {
  const findings = result.results
    .flatMap((r) => r.findings)
    .sort((a, b) => aiSeverityRank(b.severity) - aiSeverityRank(a.severity));
  const filesScanned = result.results.reduce((s, r) => s + r.files_scanned, 0);
  const passed = result.results.every((r) => r.passed);
  const critical = findings.filter((f) => f.severity?.toLowerCase() === "critical").length;
  const high = findings.filter((f) => f.severity?.toLowerCase() === "high").length;
  const stats: StatStripItem[] = [
    { label: "Files scanned", value: filesScanned },
    { label: "Findings", value: findings.length },
    { label: "Critical", value: critical, accent: "critical" },
    { label: "High", value: high, accent: "high" },
    {
      label: "Verdict",
      value: passed ? "pass" : "fail",
      accent: passed ? "success" : "critical",
    },
  ];
  const columns: DataTableColumn<PromptFinding>[] = [
    { key: "severity", header: "Severity", cell: (f) => <SeverityBadge severity={f.severity} /> },
    { key: "category", header: "Category", cell: (f) => f.category ?? "—" },
    { key: "title", header: "Finding", cell: (f) => <span className="text-[color:var(--foreground)]">{f.title ?? "—"}</span> },
    {
      key: "source",
      header: "Location",
      cell: (f) => (
        <span className="font-mono text-xs">
          {f.source_file ?? "—"}
          {typeof f.line_number === "number" ? `:${f.line_number}` : ""}
        </span>
      ),
    },
  ];
  return (
    <ResultShell stats={stats} warnings={[]}>
      <DataTable
        data-testid="ai-scan-table"
        rows={findings}
        rowKey={(f, i) => `${f.source_file ?? f.title}-${i}`}
        columns={columns}
        onRowClick={(f) =>
          onOpenDetail({
            eyebrow: `${f.severity} · ${f.category ?? "prompt"}`,
            title: f.title ?? "Prompt finding",
            subtitle: f.source_file,
            fields: buildFields(f, ["title", "source_file", "severity"]),
          })
        }
        empty="No prompt-security findings."
      />
    </ResultShell>
  );
}

function ModelFilesResult({
  result,
  onOpenDetail,
}: {
  result: ModelFilesResponse;
  onOpenDetail: (d: DetailView) => void;
}) {
  const rows = [...result.files].sort(
    (a, b) => aiSeverityRank(highestFlagSeverity(b.security_flags)) - aiSeverityRank(highestFlagSeverity(a.security_flags)),
  );
  const stats: StatStripItem[] = [
    { label: "Model files", value: result.total },
    { label: "Manifests", value: result.manifest_total },
    { label: "Unsafe", value: result.unsafe, accent: "critical" },
    { label: "Warnings", value: result.warnings.length, accent: "warn" },
  ];
  const columns: DataTableColumn<ModelFileEntry>[] = [
    { key: "file", header: "File", cell: (f) => <span className="font-mono text-xs text-[color:var(--foreground)]">{f.filename ?? f.path}</span> },
    { key: "format", header: "Format", cell: (f) => f.format ?? "—" },
    { key: "eco", header: "Ecosystem", cell: (f) => f.ecosystem ?? "—" },
    { key: "size", header: "Size", align: "right", cell: (f) => f.size_human ?? "—" },
    { key: "flags", header: "Risk", cell: (f) => <FlagCell flags={f.security_flags} /> },
  ];
  return (
    <ResultShell stats={stats} warnings={result.warnings}>
      <DataTable
        data-testid="ai-scan-table"
        rows={rows}
        rowKey={(f, i) => `${f.path}-${i}`}
        columns={columns}
        onRowClick={(f) =>
          onOpenDetail({
            eyebrow: `${f.format ?? "model file"} · ${f.ecosystem ?? ""}`.trim(),
            title: f.filename ?? f.path,
            subtitle: f.path,
            flags: f.security_flags,
            fields: buildFields(f, ["filename", "path", "security_flags"]),
          })
        }
        empty="No model files found in the scanned directories."
      />
    </ResultShell>
  );
}

// ─── Shared render helpers ──────────────────────────────────────────────────

function ResultShell({
  stats,
  warnings,
  children,
}: {
  stats: StatStripItem[];
  warnings: string[];
  children: ReactNode;
}) {
  return (
    <div className="space-y-3" data-testid="ai-scan-results">
      <StatStrip items={stats} data-testid="ai-scan-stats" />
      {children}
      {warnings.length > 0 ? (
        <ul className="space-y-1 rounded-xl border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] px-4 py-3 text-xs text-[color:var(--text-secondary)]">
          {warnings.slice(0, 12).map((warning, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-[color:var(--status-warn)]" />
              <span>{warning}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function DetailBody({ detail }: { detail: DetailView }) {
  return (
    <div className="space-y-5">
      {detail.flags && detail.flags.length > 0 ? (
        <section>
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            Security flags
          </h3>
          <ul className="space-y-2">
            {detail.flags.map((flag, i) => (
              <li
                key={i}
                className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3"
              >
                <div className="flex items-center gap-2">
                  {flag.severity ? <SeverityBadge severity={flag.severity} /> : null}
                  {flag.type ? (
                    <span className="font-mono text-xs text-[color:var(--foreground)]">{flag.type}</span>
                  ) : null}
                </div>
                {flag.description ? (
                  <p className="mt-1.5 text-sm text-[color:var(--text-secondary)]">{flag.description}</p>
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section>
        <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
          Details
        </h3>
        <dl className="divide-y divide-[color:var(--border-subtle)] rounded-xl border border-[color:var(--border-subtle)]">
          {detail.fields.map((field) => (
            <div key={field.label} className="grid grid-cols-[10rem_minmax(0,1fr)] gap-3 px-3 py-2">
              <dt className="text-xs uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">{field.label}</dt>
              <dd className="min-w-0 break-words text-sm text-[color:var(--foreground)]">{field.value}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}

/** Turn an arbitrary result object into labelled detail fields, skipping keys
 * already surfaced in the drawer header / flags section and empty values. */
function buildFields(obj: Record<string, unknown>, skip: string[]): { label: string; value: ReactNode }[] {
  const fields: { label: string; value: ReactNode }[] = [];
  for (const [key, raw] of Object.entries(obj)) {
    if (skip.includes(key)) continue;
    if (raw === null || raw === undefined || raw === "") continue;
    if (Array.isArray(raw) && raw.length === 0) continue;
    if (typeof raw === "object" && !Array.isArray(raw) && Object.keys(raw as object).length === 0) continue;
    fields.push({ label: prettyLabel(key), value: renderValue(raw) });
  }
  return fields;
}

function prettyLabel(key: string): string {
  return key.replace(/^_/, "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function renderValue(raw: unknown): ReactNode {
  if (typeof raw === "boolean") return raw ? "yes" : "no";
  if (Array.isArray(raw)) {
    return (
      <span className="flex flex-wrap gap-1">
        {raw.map((item, i) => (
          <span
            key={i}
            className="rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-1.5 py-0.5 font-mono text-[11px] text-[color:var(--text-secondary)]"
          >
            {typeof item === "object" ? JSON.stringify(item) : String(item)}
          </span>
        ))}
      </span>
    );
  }
  if (typeof raw === "object") {
    return <span className="font-mono text-xs">{JSON.stringify(raw)}</span>;
  }
  return String(raw);
}

// ─── Inputs ─────────────────────────────────────────────────────────────────

function PathListInput({
  label,
  placeholder,
  items,
  onChange,
  mono = false,
}: {
  label: string;
  placeholder: string;
  items: string[];
  onChange: (next: string[]) => void;
  mono?: boolean;
}) {
  const [draft, setDraft] = useState("");

  function add() {
    const value = draft.trim();
    if (!value) return;
    onChange([...items, value]);
    setDraft("");
  }

  return (
    <div className="space-y-2">
      <label className="block text-xs font-medium text-[color:var(--text-secondary)]">{label}</label>
      <div className="flex gap-2">
        <input
          type="text"
          aria-label={label}
          placeholder={placeholder}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
          className={`flex-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] focus:border-[color:var(--accent)] focus:outline-none ${
            mono ? "font-mono" : ""
          }`}
        />
        <button
          type="button"
          onClick={add}
          className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
        >
          <Plus className="h-3.5 w-3.5" />
          Add
        </button>
      </div>
      {items.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {items.map((item, i) => (
            <span
              key={`${item}-${i}`}
              className="flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 font-mono text-xs text-[color:var(--foreground)]"
            >
              {item}
              <button
                type="button"
                aria-label={`Remove ${item}`}
                onClick={() => onChange(items.filter((_, idx) => idx !== i))}
              >
                <X className="h-3 w-3 text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]" />
              </button>
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}
