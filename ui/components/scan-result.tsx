"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { api, type ScanJob, type ScanJobStatus, type ScanResult, type BlastRadius, type RemediationItem, type GraphExportFormat, formatDate, OWASP_LLM_TOP10, MITRE_ATLAS, severityColor } from "@/lib/api";
import { useScanStream } from "@/lib/use-scan-stream";
import { mergePipelineSteps, parsePipelineStepsFromProgress } from "@/lib/scan-pipeline-progress";
import { ScanPipeline } from "@/components/scan-pipeline";
import { RepoScanOverviewPanel } from "@/components/repo-scan-overview-panel";
import { SeverityBadge } from "@/components/severity-badge";
import { StatCard } from "@/components/stat-card";
import {
  ArrowLeft, Loader2, CheckCircle, Clock, Zap, Key, Wrench,
  ArrowUpCircle, AlertTriangle, ChevronDown, ChevronRight, Download, GitBranch, Server,
  Cloud, Database, ShieldCheck,
} from "lucide-react";

// ─── Scan Result View ───────────────────────────────────────────────────────

function mergeScanStatus(prev: ScanJob | null, status: ScanJobStatus): ScanJob {
  return {
    job_id: status.job_id,
    tenant_id: status.tenant_id ?? prev?.tenant_id,
    status: status.status,
    created_at: status.created_at,
    completed_at: status.completed_at ?? prev?.completed_at,
    request: status.request ?? prev?.request ?? {},
    progress: prev?.progress ?? [],
    result: prev?.result,
    error: status.error ?? prev?.error,
  };
}

export function ScanResultView({ id }: { id: string }) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");
  const logRef = useRef<HTMLDivElement>(null);
  const fetchedResultRef = useRef(false);
  const fetchingResultRef = useRef(false);
  const activeJobIdRef = useRef(id);

  const fetchFullResultOnce = useCallback(async () => {
    if (fetchedResultRef.current || fetchingResultRef.current) return;
    fetchingResultRef.current = true;
    try {
      const fullJob = await api.getScan(id);
      if (activeJobIdRef.current === id) {
        setJob(fullJob);
        fetchedResultRef.current = true;
      }
    } finally {
      fetchingResultRef.current = false;
    }
  }, [id]);

  const refreshStatus = useCallback(async () => {
    const status = await api.getScanStatus(id);
    if (activeJobIdRef.current !== id) return;
    setJob((prev) => mergeScanStatus(prev, status));
    if (status.status === "done" || status.status === "failed" || status.status === "cancelled") {
      await fetchFullResultOnce();
    }
  }, [fetchFullResultOnce, id]);

  useEffect(() => {
    activeJobIdRef.current = id;
    fetchedResultRef.current = false;
    fetchingResultRef.current = false;
    refreshStatus().catch(() => {});
  }, [id, refreshStatus]);

  const handleStreamUpdate = useCallback(() => {
    refreshStatus().catch(() => {});
  }, [refreshStatus]);

  const { messages, pipelineSteps, streaming } = useScanStream(id, {
    onDone: handleStreamUpdate,
    onEvent: handleStreamUpdate,
  });

  const replayedSteps = useMemo(
    () => mergePipelineSteps(parsePipelineStepsFromProgress(job?.progress ?? []), pipelineSteps),
    [job?.progress, pipelineSteps],
  );

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [messages]);

  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());

  function toggleSection(key: string) {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const result = job?.result as ScanResult | undefined;
  const summary = result?.summary;
  const blastRadius = result?.blast_radius ?? [];
  const cloudEvidence = result ? summarizeCloudEvidence(result) : null;
  const repoUrl =
    typeof job?.request?.repo_url === "string" && job.request.repo_url.trim()
      ? job.request.repo_url.trim()
      : null;

  async function handleExport(format: GraphExportFormat = "json") {
    setExporting(true);
    setExportError("");
    try {
      const blob = await api.downloadScanGraph(id, format);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `scan-${id}-graph.${format === "json" ? "json" : format}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Failed to export graph");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Back + header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4">
          <Link href="/" className="text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)] transition-colors">
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-semibold">Scan Results</h1>
              <JobStatusBadge status={job?.status ?? "pending"} streaming={streaming} />
            </div>
            <p className="text-xs text-[color:var(--text-tertiary)] font-mono mt-0.5">{id}</p>
          </div>
        </div>
        {job?.status === "done" ? (
          <button
            type="button"
            onClick={() => void handleExport("json")}
            disabled={exporting}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-900/60 bg-cyan-950/30 px-3 py-2 text-sm font-medium text-cyan-200 transition-colors hover:border-cyan-800 hover:bg-cyan-950/50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {exporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            Export graph JSON
          </button>
        ) : null}
      </div>

      {exportError ? (
        <div className="rounded-xl border border-red-900/50 bg-red-950/20 px-4 py-3 text-sm text-red-300">
          {exportError}
        </div>
      ) : null}

      {/* Scan Pipeline DAG */}
      {(streaming || replayedSteps.size > 0) && (
        <div className="bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            {streaming ? (
              <Loader2 className="w-3.5 h-3.5 text-emerald-400 animate-spin" />
            ) : (
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
            )}
            <span className="text-xs font-semibold text-[color:var(--text-secondary)]">
              {streaming ? "Scanning..." : "Complete"}
            </span>
          </div>
          {replayedSteps.size > 0 ? (
            <ScanPipeline steps={replayedSteps} />
          ) : (
            <p className="text-xs font-mono text-[color:var(--text-tertiary)] animate-pulse">Waiting for scan to start...</p>
          )}
        </div>
      )}

      {/* Collapsible raw log */}
      {messages.length > 0 && (
        <details className="bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-xl">
          <summary className="px-4 py-3 text-xs font-semibold text-[color:var(--text-tertiary)] cursor-pointer hover:text-[color:var(--text-secondary)]">
            Raw log ({messages.length} messages)
          </summary>
          <div ref={logRef} className="max-h-48 overflow-y-auto px-4 pb-3 space-y-1">
            {messages?.map((m, i) => (
              <p key={i} className="text-xs font-mono text-[color:var(--text-secondary)]">{m}</p>
            ))}
          </div>
        </details>
      )}

      {/* Error */}
      {job?.status === "failed" && (
        <div className="bg-red-950 border border-red-900 rounded-xl p-4 text-sm text-red-300">
          <strong>Scan failed:</strong> {job.error ?? "Unknown error"}
        </div>
      )}

      {/* Summary stats */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <MiniStat label="Agents" value={summary.total_agents} />
          <MiniStat label="Packages" value={summary.total_packages} />
          <MiniStat label="Vulnerabilities" value={summary.total_vulnerabilities} />
          <MiniStat label="Critical" value={summary.critical_findings} accent="red" />
        </div>
      )}

      {repoUrl && result ? <RepoScanOverviewPanel scanId={id} repoUrl={repoUrl} result={result} /> : null}

      {cloudEvidence ? <CloudEvidencePanel evidence={cloudEvidence} /> : null}

      {/* Blast radius */}
      {blastRadius.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <button type="button" onClick={() => toggleSection("blast")} className="flex items-center gap-2 group">
              {collapsedSections.has("blast") ? <ChevronRight className="w-4 h-4 text-[color:var(--text-tertiary)]" /> : <ChevronDown className="w-4 h-4 text-[color:var(--text-tertiary)]" />}
              <h2 className="text-sm font-semibold text-[color:var(--text-secondary)] uppercase tracking-widest group-hover:text-[color:var(--foreground)] transition-colors">
                Blast Radius ({blastRadius.length})
              </h2>
            </button>
            <Link
              href={`/scan?id=${id}&view=mesh`}
              className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition-colors bg-cyan-950/30 border border-cyan-900/50 rounded-lg px-3 py-1.5"
            >
              <Server className="w-3 h-3" />
              View Mesh
            </Link>
            <Link
              href={`/scan?id=${id}&view=attack-flow`}
              className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 transition-colors bg-emerald-950/30 border border-emerald-900/50 rounded-lg px-3 py-1.5"
            >
              <GitBranch className="w-3 h-3" />
              View Attack Flow
            </Link>
          </div>
          {!collapsedSections.has("blast") && (
            <div className="space-y-3">
              {blastRadius.sort((a, b) => b.blast_score - a.blast_score).map((b, index) => (
                <BlastRadiusCard key={`${b.vulnerability_id}:${b.package ?? "unknown"}:${index}`} blast={b} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* Threat Framework Coverage */}
      {blastRadius.length > 0 && <ThreatMatrix blastRadius={blastRadius} />}

      {/* Remediation Plan */}
      {result?.remediation_plan && result.remediation_plan.length > 0 && (
        <section>
          <button type="button" onClick={() => toggleSection("remediation")} className="flex items-center gap-2 mb-3 group">
            {collapsedSections.has("remediation") ? <ChevronRight className="w-4 h-4 text-[color:var(--text-tertiary)]" /> : <ChevronDown className="w-4 h-4 text-[color:var(--text-tertiary)]" />}
            <h2 className="text-sm font-semibold text-[color:var(--text-secondary)] uppercase tracking-widest group-hover:text-[color:var(--foreground)] transition-colors">
              Remediation Plan ({result.remediation_plan.filter((i) => i.fixed_version).length} fixable)
            </h2>
          </button>
          {!collapsedSections.has("remediation") && <RemediationPlan items={result.remediation_plan} />}
        </section>
      )}

      {/* Agent inventory */}
      {result && result.agents.length > 0 && (
        <section>
          <button type="button" onClick={() => toggleSection("agents")} className="flex items-center gap-2 mb-3 group">
            {collapsedSections.has("agents") ? <ChevronRight className="w-4 h-4 text-[color:var(--text-tertiary)]" /> : <ChevronDown className="w-4 h-4 text-[color:var(--text-tertiary)]" />}
            <h2 className="text-sm font-semibold text-[color:var(--text-secondary)] uppercase tracking-widest group-hover:text-[color:var(--foreground)] transition-colors">
              Agents ({result.agents.length})
            </h2>
          </button>
          {!collapsedSections.has("agents") && (
            <div className="space-y-3">
              {result.agents?.map((agent, i) => (
                <div key={i} className={`bg-[color:var(--surface)] border rounded-xl p-4 ${agent.status === "installed-not-configured" ? "border-dashed border-[color:var(--border-subtle)]" : "border-[color:var(--border-subtle)]"}`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm">{agent.name}</span>
                      <span className="text-xs text-[color:var(--text-tertiary)] font-mono">{agent.agent_type}</span>
                      {agent.status === "installed-not-configured" ? (
                        <span className="text-[10px] font-mono bg-yellow-950 border border-yellow-800 text-yellow-400 rounded px-1.5 py-0.5">not configured</span>
                      ) : (
                        <span className="text-[10px] font-mono bg-emerald-950 border border-emerald-800 text-emerald-400 rounded px-1.5 py-0.5">configured</span>
                      )}
                    </div>
                    <span className="text-xs text-[color:var(--text-tertiary)]">{agent.source}</span>
                  </div>
                  <div className="space-y-2">
                    {agent.mcp_servers?.map((srv, j) => (
                      <div key={j} className="bg-[color:var(--surface-muted)] rounded-lg p-3">
                        <div className="text-xs font-mono text-[color:var(--text-secondary)] mb-1.5">{srv.name}</div>
                        <div className="flex flex-wrap gap-2">
                          {srv.packages.slice(0, 8).map((pkg, k) => {
                            const hasCrit = pkg.vulnerabilities?.some((v) => v.severity === "critical");
                            const hasHigh = pkg.vulnerabilities?.some((v) => v.severity === "high");
                            return (
                              <span
                                key={k}
                                className={`text-xs font-mono px-2 py-0.5 rounded ${
                                  hasCrit ? "bg-red-950 border border-red-900 text-red-300"
                                  : hasHigh ? "bg-orange-950 border border-orange-900 text-orange-300"
                                  : "bg-[color:var(--surface-elevated)] border border-[color:var(--border-subtle)] text-[color:var(--text-secondary)]"
                                }`}
                              >
                                {pkg.name}@{pkg.version}
                                {pkg.vulnerabilities && pkg.vulnerabilities.length > 0 && (
                                  <span className="ml-1 opacity-70">({pkg.vulnerabilities.length})</span>
                                )}
                              </span>
                            );
                          })}
                          {srv.packages.length > 8 && <span className="text-xs text-[color:var(--text-tertiary)]">+{srv.packages.length - 8} more</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Warnings */}
      {result?.warnings && result.warnings.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-[color:var(--text-secondary)] uppercase tracking-widest mb-3">Warnings</h2>
          <div className="space-y-1">
            {result.warnings?.map((w, i) => (
              <p key={i} className="text-xs text-yellow-400 font-mono bg-yellow-950/30 rounded px-3 py-2">{w}</p>
            ))}
          </div>
        </section>
      )}

      {result && cloudEvidence && blastRadius.length === 0 && (!result.agents || result.agents.length === 0) ? (
        <div className="rounded-xl border border-cyan-900/50 bg-cyan-950/20 px-4 py-3 text-sm text-cyan-100">
          Cloud inventory and posture evidence was persisted for this scan. No
          package attack-path findings were produced for this evidence set.
        </div>
      ) : null}

      {/* Scan metadata */}
      {job?.completed_at && (
        <div className="text-xs text-[color:var(--text-tertiary)] flex items-center gap-2">
          <Clock className="w-3 h-3" />
          Completed {formatDate(job.completed_at)}
        </div>
      )}
    </div>
  );
}

// ─── Sub-Components ─────────────────────────────────────────────────────────

interface CloudBenchmarkDisplay {
  key: string;
  label: string;
  passed: number | null;
  failed: number | null;
  total: number | null;
  passRate: number | null;
}

interface CloudEvidenceDisplay {
  providers: string[];
  resourceCount: number | null;
  identityCount: number | null;
  agentCount: number | null;
  inventoryItems: number | null;
  benchmarks: CloudBenchmarkDisplay[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function uniqueValues(values: Array<string | null | undefined>): string[] {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value)))).sort();
}

function countChecksByStatus(checks: unknown): Pick<CloudBenchmarkDisplay, "passed" | "failed" | "total"> {
  if (!Array.isArray(checks)) return { passed: null, failed: null, total: null };
  let passed = 0;
  let failed = 0;
  for (const raw of checks) {
    if (!isRecord(raw)) continue;
    const status = String(raw.status ?? raw.result ?? "").toLowerCase();
    if (["pass", "passed", "ok", "success"].includes(status)) passed += 1;
    if (["fail", "failed", "error"].includes(status)) failed += 1;
  }
  return { passed, failed, total: checks.length };
}

function benchmarkDisplay(key: string, label: string, data: unknown): CloudBenchmarkDisplay | null {
  if (!isRecord(data)) return null;
  const counted = countChecksByStatus(data.checks);
  const passed = asNumber(data.passed) ?? counted.passed;
  const failed = asNumber(data.failed) ?? counted.failed;
  const total = asNumber(data.total) ?? counted.total;
  const passRate = asNumber(data.pass_rate);
  return { key, label, passed, failed, total, passRate };
}

function summarizeCloudInventory(inventory: unknown): Pick<
  CloudEvidenceDisplay,
  "providers" | "resourceCount" | "identityCount" | "agentCount" | "inventoryItems"
> {
  if (Array.isArray(inventory)) {
    const providers = uniqueValues(
      inventory.map((item) => (isRecord(item) ? String(item.provider ?? item.cloud ?? "") : "")),
    );
    let resourceCount = 0;
    let identityCount = 0;
    let agentCount = 0;
    for (const item of inventory) {
      if (!isRecord(item)) continue;
      resourceCount += asNumber(item.resource_count) ?? 0;
      identityCount += asNumber(item.identity_count) ?? 0;
      agentCount += asNumber(item.agent_count) ?? 0;
    }
    return {
      providers,
      resourceCount: resourceCount || null,
      identityCount: identityCount || null,
      agentCount: agentCount || null,
      inventoryItems: inventory.length,
    };
  }

  if (!isRecord(inventory)) {
    return { providers: [], resourceCount: null, identityCount: null, agentCount: null, inventoryItems: null };
  }

  let resourceCount = asNumber(inventory.resource_count);
  const nodeSummary = inventory.node_summary;
  if (resourceCount == null && isRecord(nodeSummary)) {
    resourceCount = Object.values(nodeSummary).reduce<number>(
      (sum, value) => sum + (asNumber(value) ?? 0),
      0,
    );
  }

  return {
    providers: uniqueValues([String(inventory.provider ?? inventory.cloud ?? "")]),
    resourceCount,
    identityCount: asNumber(inventory.identity_count),
    agentCount: asNumber(inventory.agent_count),
    inventoryItems: null,
  };
}

function summarizeCloudEvidence(result: ScanResult): CloudEvidenceDisplay | null {
  const inventory = summarizeCloudInventory(result.cloud_inventory);
  const benchmarks = [
    benchmarkDisplay("aws", "AWS CIS", result.cis_benchmark),
    benchmarkDisplay("azure", "Azure CIS", result.azure_cis_benchmark),
    benchmarkDisplay("gcp", "GCP CIS", result.gcp_cis_benchmark),
    benchmarkDisplay("snowflake", "Snowflake CIS", result.snowflake_cis_benchmark),
    benchmarkDisplay("databricks", "Databricks", result.databricks_cis_benchmark),
  ].filter((item): item is CloudBenchmarkDisplay => item !== null);

  const hasInventory =
    inventory.providers.length > 0 ||
    inventory.resourceCount != null ||
    inventory.identityCount != null ||
    inventory.agentCount != null ||
    inventory.inventoryItems != null;
  if (!hasInventory && benchmarks.length === 0) return null;
  return { ...inventory, benchmarks };
}

function formatEvidenceCount(value: number | null): string {
  return value == null ? "—" : value.toLocaleString();
}

function formatBenchmarkRate(benchmark: CloudBenchmarkDisplay): string {
  if (benchmark.passRate != null) {
    const pct = benchmark.passRate <= 1 ? benchmark.passRate * 100 : benchmark.passRate;
    return `${pct.toFixed(0)}%`;
  }
  if (benchmark.total && benchmark.passed != null) {
    return `${((benchmark.passed / benchmark.total) * 100).toFixed(0)}%`;
  }
  return "—";
}

function CloudEvidencePanel({ evidence }: { evidence: CloudEvidenceDisplay }) {
  const providerLabel = evidence.providers.length > 0 ? evidence.providers.join(", ").toUpperCase() : "Cloud";
  return (
    <section className="rounded-xl border border-cyan-900/50 bg-cyan-950/20 p-4">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <Cloud className="h-4 w-4 text-cyan-300" />
          <h2 className="text-sm font-semibold text-cyan-100">Cloud evidence</h2>
        </div>
        <span className="font-mono text-[11px] uppercase tracking-wide text-cyan-300/80">{providerLabel}</span>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <EvidenceMetric icon={Database} label="Resources" value={formatEvidenceCount(evidence.resourceCount ?? evidence.inventoryItems)} />
        <EvidenceMetric icon={Key} label="Identities" value={formatEvidenceCount(evidence.identityCount)} />
        <EvidenceMetric icon={Server} label="Agents" value={formatEvidenceCount(evidence.agentCount)} />
        <EvidenceMetric icon={ShieldCheck} label="Benchmarks" value={formatEvidenceCount(evidence.benchmarks.length)} />
      </div>
      {evidence.benchmarks.length > 0 ? (
        <div className="mt-4 grid gap-2 lg:grid-cols-2">
          {evidence.benchmarks.map((benchmark) => (
            <div
              key={benchmark.key}
              className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyan-900/40 bg-[color:var(--surface-muted)] px-3 py-2"
            >
              <span className="text-xs font-medium text-[color:var(--foreground)]">{benchmark.label}</span>
              <span className="font-mono text-xs text-cyan-200">
                {benchmark.passed ?? "—"}/{benchmark.total ?? "—"} passed · {formatBenchmarkRate(benchmark)}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function EvidenceMetric({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-lg border border-cyan-900/40 bg-[color:var(--surface-muted)] p-3">
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-cyan-300/80">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <p className="mt-1.5 text-lg font-semibold text-[color:var(--foreground)]">{value}</p>
    </div>
  );
}

function JobStatusBadge({ status, streaming }: { status: string; streaming: boolean }) {
  if (status === "done") return <span className="text-xs bg-emerald-950 border border-emerald-900 text-emerald-400 rounded-full px-2 py-0.5 font-mono">done</span>;
  if (status === "failed") return <span className="text-xs bg-red-950 border border-red-900 text-red-400 rounded-full px-2 py-0.5 font-mono">failed</span>;
  if (status === "running" || streaming) return (
    <span className="text-xs bg-yellow-950 border border-yellow-900 text-yellow-400 rounded-full px-2 py-0.5 font-mono flex items-center gap-1">
      <Loader2 className="w-3 h-3 animate-spin" /> running
    </span>
  );
  return <span className="text-xs bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] rounded-full px-2 py-0.5 font-mono">{status}</span>;
}

function MiniStat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return <StatCard label={label} value={value} accent={accent === "red" ? "critical" : "neutral"} />;
}

function BlastRadiusCard({ blast }: { blast: BlastRadius }) {
  return (
    <div className="bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-xl p-5">
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <SeverityBadge severity={blast.severity} />
            {blast.cisa_kev && (
              <span className="text-xs bg-red-950 border border-red-900 text-red-400 rounded px-2 py-0.5 font-mono font-semibold">CISA KEV</span>
            )}
          </div>
          <h3 className="font-mono font-semibold text-[color:var(--foreground)]">{blast.vulnerability_id}</h3>
        </div>
        <div className="text-right flex-shrink-0">
          {blast.blast_score > 0 && (
            <>
              <div className="text-2xl font-bold font-mono text-red-400">{blast.blast_score.toFixed(0)}</div>
              <div className="text-xs text-[color:var(--text-tertiary)]">blast score</div>
            </>
          )}
          {blast.cvss_score && <div className="text-xs text-[color:var(--text-tertiary)] mt-1">CVSS {blast.cvss_score.toFixed(1)}</div>}
          {blast.epss_score && <div className="text-xs text-[color:var(--text-tertiary)]">EPSS {(blast.epss_score * 100).toFixed(1)}%</div>}
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <ImpactPill icon={Zap} label="Agents affected" items={blast.affected_agents ?? []} />
        <ImpactPill icon={Key} label="Credentials exposed" items={blast.exposed_credentials ?? []} accent="orange" />
        <ImpactPill icon={Wrench} label="Tools reachable" items={blast.reachable_tools ?? blast.exposed_tools ?? []} />
      </div>
      {((blast.owasp_tags && blast.owasp_tags.length > 0) || (blast.atlas_tags && blast.atlas_tags.length > 0)) && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {blast.owasp_tags?.map((tag) => (
            <span key={tag} title={OWASP_LLM_TOP10[tag] ?? tag} className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1.5 py-0.5 cursor-help">
              {tag}<span className="ml-1 text-purple-600 font-sans">{OWASP_LLM_TOP10[tag]}</span>
            </span>
          ))}
          {blast.atlas_tags?.map((tag) => (
            <span key={tag} title={MITRE_ATLAS[tag] ?? tag} className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1.5 py-0.5 cursor-help">
              {tag}<span className="ml-1 text-cyan-600 font-sans">{MITRE_ATLAS[tag]}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ImpactPill({ icon: Icon, label, items, accent }: { icon: React.ElementType; label: string; items?: string[]; accent?: string }) {
  const safeItems = items ?? [];
  const accentClass = accent === "orange" && safeItems.length > 0 ? "text-orange-400" : "text-[color:var(--text-secondary)]";
  return (
    <div className="bg-[color:var(--surface-muted)] rounded-lg p-3">
      <div className={`flex items-center gap-1.5 text-xs font-semibold mb-2 ${accentClass}`}>
        <Icon className="w-3.5 h-3.5" /><span>{label} ({safeItems.length})</span>
      </div>
      {safeItems.length > 0 ? (
        <div className="space-y-1">
          {safeItems.slice(0, 4).map((item, i) => <p key={i} className="text-xs font-mono text-[color:var(--text-secondary)] truncate">{item}</p>)}
          {safeItems.length > 4 && <p className="text-xs text-[color:var(--text-tertiary)]">+{safeItems.length - 4} more</p>}
        </div>
      ) : (
        <p className="text-xs text-[color:var(--text-tertiary)]">None</p>
      )}
    </div>
  );
}

function RemediationPlan({ items }: { items: RemediationItem[] }) {
  const fixable = items.filter((i) => i.fixed_version);
  const unfixable = items.filter((i) => !i.fixed_version);

  return (
    <div className="space-y-3">
      {fixable?.map((item, i) => (
        <div key={i} className="bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-xl p-5">
          <div className="flex items-start justify-between gap-4 mb-3">
            <div className="flex items-center gap-3">
              <ArrowUpCircle className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-semibold text-[color:var(--foreground)]">{item.package}</span>
                  <span className="text-xs text-[color:var(--text-tertiary)] font-mono">{item.current_version}</span>
                  <span className="text-[color:var(--text-tertiary)]">&rarr;</span>
                  <span className="text-xs text-emerald-400 font-mono font-semibold">{item.fixed_version}</span>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(item.severity)}`}>{item.severity}</span>
                  {item.is_kev && <span className="text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-1.5 py-0.5">KEV</span>}
                </div>
                <p className="text-xs text-[color:var(--text-tertiary)] mt-0.5">Clears {item.vulnerabilities.length} vuln{item.vulnerabilities.length !== 1 ? "s" : ""} · {item.ecosystem}</p>
              </div>
            </div>
            <div className="text-right flex-shrink-0">
              <div className="text-lg font-bold font-mono text-emerald-400">{item.impact_score.toFixed(1)}</div>
              <div className="text-xs text-[color:var(--text-tertiary)]">risk</div>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
            <ImpactBox label="Agents protected" items={item.affected_agents} pct={item.agents_pct} color="emerald" />
            <ImpactBox label="Credentials freed" items={item.exposed_credentials} pct={item.credentials_pct} color="yellow" />
            <ImpactBox label="Tools secured" items={item.reachable_tools} pct={item.tools_pct} color="blue" />
          </div>
          {(item.owasp_tags.length > 0 || item.atlas_tags.length > 0) && (
            <div className="flex flex-wrap gap-1.5 mb-3">
              <span className="text-xs text-[color:var(--text-tertiary)] mr-1">mitigates:</span>
              {item.owasp_tags?.map((tag) => (
                <span key={tag} title={OWASP_LLM_TOP10[tag] ?? tag} className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1.5 py-0.5 cursor-help">{tag}</span>
              ))}
              {item.atlas_tags?.map((tag) => (
                <span key={tag} title={MITRE_ATLAS[tag] ?? tag} className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1.5 py-0.5 cursor-help">{tag}</span>
              ))}
            </div>
          )}
          <div className="flex items-start gap-2 bg-red-950/20 border border-red-900/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-red-300/80">{item.risk_narrative}</p>
          </div>
        </div>
      ))}
      {unfixable.length > 0 && (
        <div className="bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-xl p-4">
          <p className="text-xs text-yellow-400 font-semibold mb-2">{unfixable.length} package{unfixable.length !== 1 ? "s" : ""} with no fix available -- monitor upstream</p>
          <div className="space-y-1">
            {unfixable.slice(0, 5).map((item, i) => (
              <p key={i} className="text-xs font-mono text-[color:var(--text-tertiary)]">{item.package}@{item.current_version} -- {item.vulnerabilities.slice(0, 3).join(", ")}</p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ImpactBox({ label, items, pct, color }: { label: string; items: string[]; pct: number; color: "emerald" | "yellow" | "blue" }) {
  const colors = {
    emerald: { bg: "bg-emerald-950/30", border: "border-emerald-900/50", text: "text-emerald-400", bar: "bg-emerald-500" },
    yellow: { bg: "bg-yellow-950/30", border: "border-yellow-900/50", text: "text-yellow-400", bar: "bg-yellow-500" },
    blue: { bg: "bg-blue-950/30", border: "border-blue-900/50", text: "text-blue-400", bar: "bg-blue-500" },
  };
  const c = colors[color];
  return (
    <div className={`${c.bg} border ${c.border} rounded-lg p-3`}>
      <div className="flex items-center justify-between mb-1.5">
        <span className={`text-xs font-semibold ${c.text}`}>{label}</span>
        <span className="text-xs font-mono text-[color:var(--text-secondary)]">{pct}%</span>
      </div>
      <div className="h-1.5 rounded-full bg-[color:var(--surface-muted)] mb-2">
        <div className={`h-1.5 rounded-full ${c.bar} transition-all duration-500`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      {items.length > 0 ? (
        <div className="space-y-0.5">
          {items.slice(0, 3).map((item, i) => <p key={i} className="text-xs font-mono text-[color:var(--text-secondary)] truncate">{item}</p>)}
          {items.length > 3 && <p className="text-xs text-[color:var(--text-tertiary)]">+{items.length - 3} more</p>}
        </div>
      ) : (
        <p className="text-xs text-[color:var(--text-tertiary)]">None</p>
      )}
    </div>
  );
}

function ThreatMatrix({ blastRadius }: { blastRadius: BlastRadius[] }) {
  const owaspCounts: Record<string, number> = {};
  const atlasCounts: Record<string, number> = {};
  for (const br of blastRadius) {
    for (const tag of br.owasp_tags ?? []) owaspCounts[tag] = (owaspCounts[tag] ?? 0) + 1;
    for (const tag of br.atlas_tags ?? []) atlasCounts[tag] = (atlasCounts[tag] ?? 0) + 1;
  }
  const owaspTriggered = Object.keys(owaspCounts).length;
  const atlasTriggered = Object.keys(atlasCounts).length;
  if (owaspTriggered === 0 && atlasTriggered === 0) return null;

  return (
    <section>
      <h2 className="text-sm font-semibold text-[color:var(--text-secondary)] uppercase tracking-widest mb-3">Threat Framework Coverage</h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <FrameworkPanel title="OWASP LLM Top 10" color="purple" counts={owaspCounts} catalog={OWASP_LLM_TOP10} triggered={owaspTriggered} />
        <FrameworkPanel title="MITRE ATLAS" color="cyan" counts={atlasCounts} catalog={MITRE_ATLAS} triggered={atlasTriggered} />
      </div>
    </section>
  );
}

function FrameworkPanel({
  title, color, counts, catalog, triggered,
}: {
  title: string;
  color: "purple" | "cyan";
  counts: Record<string, number>;
  catalog: Record<string, string>;
  triggered: number;
}) {
  const dotActive = color === "purple" ? "bg-purple-400" : "bg-cyan-400";
  const textActive = color === "purple" ? "text-purple-400" : "text-cyan-400";
  const bgActive = color === "purple" ? "bg-purple-950/40" : "bg-cyan-950/40";
  const codeWidth = color === "purple" ? "w-12" : "w-20";

  return (
    <div className="bg-[color:var(--surface)] border border-[color:var(--border-subtle)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className={`text-xs font-semibold ${textActive} uppercase tracking-wider`}>{title}</h3>
        <span className="text-xs text-[color:var(--text-tertiary)]">{triggered}/{Object.keys(catalog).length} triggered</span>
      </div>
      <div className="space-y-1.5">
        {Object.entries(catalog).map(([code, name]) => {
          const count = counts[code] ?? 0;
          const on = count > 0;
          return (
            <div key={code} className={`flex items-center gap-3 px-2.5 py-1.5 rounded-md ${on ? bgActive : "opacity-40"}`}>
              <span className={`w-2 h-2 rounded-full flex-shrink-0 ${on ? dotActive : "bg-[color:var(--border-strong)]"}`} />
              <span className={`text-xs font-mono ${codeWidth} flex-shrink-0 ${on ? textActive : "text-[color:var(--text-tertiary)]"}`}>{code}</span>
              <span className={`text-xs flex-1 ${on ? "text-[color:var(--text-secondary)]" : "text-[color:var(--text-tertiary)]"}`}>{name}</span>
              {on && <span className={`text-xs font-mono font-semibold ${textActive}`}>{count}</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
