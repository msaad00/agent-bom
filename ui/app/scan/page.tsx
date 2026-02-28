"use client";

import { Suspense, useState, useRef, useEffect, useCallback, useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { api, ScanRequest, ScanJob, ScanResult, BlastRadius, RemediationItem, formatDate, OWASP_LLM_TOP10, MITRE_ATLAS, severityColor } from "@/lib/api";
import type { AttackFlowNodeData, AttackFlowResponse } from "@/lib/api";
import { OWASP_MCP_TOP10 } from "@/lib/api";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ArrowRight,
  Loader2,
  Plus,
  X,
  Upload,
  ArrowLeft,
  CheckCircle,
  XCircle,
  Clock,
  Zap,
  Shield,
  Key,
  Wrench,
  ArrowUpCircle,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  GitBranch,
  Bug,
  Download,
  Filter,
  KeyRound,
  Package,
  Server,
  ShieldAlert,
  ExternalLink,
} from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  useReactFlow,
  ReactFlowProvider,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

// ═══════════════════════════════════════════════════════════════════════════════
// Router: picks ScanForm, ScanResultView, or AttackFlowView based on query
// ═══════════════════════════════════════════════════════════════════════════════

function ScanRouter() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") || "";
  const view = searchParams.get("view") || "";

  if (id && view === "attack-flow") {
    return <AttackFlowView id={id} />;
  }

  if (id) {
    return <ScanResultView id={id} />;
  }

  return <ScanForm />;
}

export default function ScanPage() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center h-[50vh] text-zinc-400"><Loader2 className="w-5 h-5 animate-spin mr-2" />Loading...</div>}>
      <ScanRouter />
    </Suspense>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. SCAN FORM (original scan/page.tsx)
// ═══════════════════════════════════════════════════════════════════════════════

function ScanForm() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [form, setForm] = useState<ScanRequest>({
    enrich: false,
    k8s: false,
    images: [],
    tf_dirs: [],
    agent_projects: [],
  });
  const [imageInput, setImageInput] = useState("");
  const [imageMode, setImageMode] = useState<"single" | "bulk" | "upload">("single");
  const [bulkText, setBulkText] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [tfInput, setTfInput] = useState("");
  const [apInput, setApInput] = useState("");

  function addToList(key: "images" | "tf_dirs" | "agent_projects", value: string, reset: () => void) {
    if (!value.trim()) return;
    setForm((f) => ({ ...f, [key]: [...(f[key] ?? []), value.trim()] }));
    reset();
  }

  function removeFromList(key: "images" | "tf_dirs" | "agent_projects", idx: number) {
    setForm((f) => ({ ...f, [key]: (f[key] ?? []).filter((_, i) => i !== idx) }));
  }

  function parseBulkImages(text: string): string[] {
    return text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
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

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const job = await api.startScan(form);
      router.push(`/scan?id=${job.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-semibold tracking-tight mb-1">New Scan</h1>
      <p className="text-zinc-400 text-sm mb-8">
        Select sources to scan. All sources feed into one unified CVE pipeline.
      </p>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Auto-discover */}
        <Section title="Local MCP configs" subtitle="Claude Desktop, Cursor, Windsurf, Cline, VS Code... (auto)">
          <p className="text-xs text-zinc-500">Always included automatically.</p>
        </Section>

        {/* Docker images */}
        <Section title="Docker images" subtitle="--image flag · supports bulk input for enterprise scale">
          {/* Mode tabs */}
          <div className="flex items-center gap-1 mb-3">
            {(["single", "bulk", "upload"] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setImageMode(mode)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  imageMode === mode
                    ? "bg-zinc-700 text-zinc-100"
                    : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                }`}
              >
                {mode === "single" ? "One at a time" : mode === "bulk" ? "Bulk paste" : "Upload .txt"}
              </button>
            ))}
          </div>

          {/* Single mode */}
          {imageMode === "single" && (
            <ListInput
              placeholder="nginx:1.25 or ghcr.io/org/app:v1"
              value={imageInput}
              onChange={setImageInput}
              onAdd={() => addToList("images", imageInput, () => setImageInput(""))}
              items={[]}
              onRemove={() => {}}
            />
          )}

          {/* Bulk paste mode */}
          {imageMode === "bulk" && (
            <div className="space-y-2">
              <textarea
                placeholder={"# One image per line\nnginx:1.25\nredis:7-alpine\nghcr.io/org/app:latest"}
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                rows={5}
                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm font-mono text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-600 resize-y"
              />
              <button
                type="button"
                onClick={applyBulk}
                disabled={!bulkText.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg text-xs text-white font-medium transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                Add {parseBulkImages(bulkText).length || 0} image{parseBulkImages(bulkText).length !== 1 ? "s" : ""}
              </button>
            </div>
          )}

          {/* Upload mode */}
          {imageMode === "upload" && (
            <div className="space-y-2">
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.csv,.list"
                onChange={handleFileUpload}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-2 px-4 py-3 w-full bg-zinc-800 hover:bg-zinc-700 border border-dashed border-zinc-600 rounded-lg text-sm text-zinc-300 transition-colors justify-center"
              >
                <Upload className="w-4 h-4" />
                Choose .txt file (one image per line)
              </button>
              <p className="text-[10px] text-zinc-600">
                Lines starting with # are ignored. Supports .txt, .csv, .list files.
              </p>
            </div>
          )}

          {/* Always show current image list */}
          {(form.images ?? []).length > 0 && (
            <div className="mt-3 space-y-1.5">
              <div className="text-xs text-zinc-500 font-medium">
                {(form.images ?? []).length} image{(form.images ?? []).length !== 1 ? "s" : ""} queued
              </div>
              <div className="flex flex-wrap gap-2">
                {(form.images ?? []).map((item, i) => (
                  <span key={i} className="flex items-center gap-1.5 bg-zinc-800 border border-zinc-700 rounded-lg px-2.5 py-1 text-xs font-mono text-zinc-300">
                    {item}
                    <button type="button" onClick={() => removeFromList("images", i)}>
                      <X className="w-3 h-3 text-zinc-500 hover:text-zinc-300" />
                    </button>
                  </span>
                ))}
              </div>
            </div>
          )}
        </Section>

        {/* Kubernetes */}
        <Section title="Kubernetes cluster" subtitle="--k8s (requires kubectl)">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              className="w-4 h-4 rounded border-zinc-700 bg-zinc-900 text-emerald-500"
              checked={form.k8s ?? false}
              onChange={(e) => setForm((f) => ({ ...f, k8s: e.target.checked }))}
            />
            <span className="text-sm text-zinc-300">Scan all running pods via kubectl</span>
          </label>
          {form.k8s && (
            <input
              type="text"
              placeholder="Namespace (leave empty for all)"
              className="mt-2 w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-600"
              value={form.k8s_namespace ?? ""}
              onChange={(e) => setForm((f) => ({ ...f, k8s_namespace: e.target.value || undefined }))}
            />
          )}
        </Section>

        {/* Terraform */}
        <Section title="Terraform directories" subtitle="--tf-dir">
          <ListInput
            placeholder="/path/to/infra or infra/prod"
            value={tfInput}
            onChange={setTfInput}
            onAdd={() => addToList("tf_dirs", tfInput, () => setTfInput(""))}
            items={form.tf_dirs ?? []}
            onRemove={(i) => removeFromList("tf_dirs", i)}
          />
        </Section>

        {/* Python agent projects */}
        <Section title="Python agent projects" subtitle="--agent-project (LangChain, OpenAI Agents, CrewAI, AutoGen...)">
          <ListInput
            placeholder="/path/to/my-langchain-app or ."
            value={apInput}
            onChange={setApInput}
            onAdd={() => addToList("agent_projects", apInput, () => setApInput(""))}
            items={form.agent_projects ?? []}
            onRemove={(i) => removeFromList("agent_projects", i)}
          />
        </Section>

        {/* GitHub Actions */}
        <Section title="GitHub Actions" subtitle="--gha (scans .github/workflows/)">
          <input
            type="text"
            placeholder="/path/to/git/repo"
            className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-600"
            value={form.gha_path ?? ""}
            onChange={(e) => setForm((f) => ({ ...f, gha_path: e.target.value || undefined }))}
          />
        </Section>

        {/* Inventory file */}
        <Section title="Custom inventory" subtitle="--inventory (JSON file with custom agents)">
          <input
            type="text"
            placeholder="/path/to/agents.json"
            className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-600"
            value={form.inventory ?? ""}
            onChange={(e) => setForm((f) => ({ ...f, inventory: e.target.value || undefined }))}
          />
        </Section>

        {/* Options */}
        <Section title="Options" subtitle="">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              className="w-4 h-4 rounded border-zinc-700 bg-zinc-900 text-emerald-500"
              checked={form.enrich ?? false}
              onChange={(e) => setForm((f) => ({ ...f, enrich: e.target.checked }))}
            />
            <span className="text-sm text-zinc-300">
              Enrich with NVD CVSS, EPSS, and CISA KEV{" "}
              <span className="text-zinc-500">(slower, requires internet)</span>
            </span>
          </label>
        </Section>

        {error && (
          <p className="text-red-400 text-sm bg-red-950 border border-red-900 rounded-lg px-4 py-3">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="flex items-center gap-2 px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
        >
          {loading ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Starting scan...</>
          ) : (
            <>Start scan <ArrowRight className="w-4 h-4" /></>
          )}
        </button>
      </form>
    </div>
  );
}

function Section({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-zinc-200">{title}</h3>
        {subtitle && <p className="text-xs text-zinc-500 mt-0.5">{subtitle}</p>}
      </div>
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
          className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-600"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onAdd(); } }}
        />
        <button
          type="button"
          onClick={onAdd}
          className="flex items-center gap-1 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs text-zinc-300 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          Add
        </button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {items.map((item, i) => (
            <span key={i} className="flex items-center gap-1.5 bg-zinc-800 border border-zinc-700 rounded-lg px-2.5 py-1 text-xs font-mono text-zinc-300">
              {item}
              <button type="button" onClick={() => onRemove(i)}>
                <X className="w-3 h-3 text-zinc-500 hover:text-zinc-300" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. SCAN RESULT VIEW (from scan/[id]/page.tsx)
// ═══════════════════════════════════════════════════════════════════════════════

function ScanResultView({ id }: { id: string }) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [streaming, setStreaming] = useState(true);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Load initial state
    api.getScan(id).then(setJob).catch(() => {});

    // Subscribe to SSE stream
    const cleanup = api.streamScan(
      id,
      (data) => {
        const d = data as { type: string; message?: string };
        if (d.type === "progress" && d.message) {
          setMessages((m) => [...m, d.message!]);
          // Also refresh job state
          api.getScan(id).then(setJob).catch(() => {});
        }
      },
      () => {
        setStreaming(false);
        api.getScan(id).then(setJob).catch(() => {});
      }
    );
    return cleanup;
  }, [id]);

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
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

  return (
    <div className="space-y-8">
      {/* Back + header */}
      <div className="flex items-center gap-4">
        <Link href="/" className="text-zinc-500 hover:text-zinc-300 transition-colors">
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold">Scan Results</h1>
            <JobStatusBadge status={job?.status ?? "pending"} streaming={streaming} />
          </div>
          <p className="text-xs text-zinc-500 font-mono mt-0.5">{id}</p>
        </div>
      </div>

      {/* Live log */}
      {(streaming || messages.length > 0) && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            {streaming ? (
              <Loader2 className="w-3.5 h-3.5 text-emerald-400 animate-spin" />
            ) : (
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
            )}
            <span className="text-xs font-semibold text-zinc-400">
              {streaming ? "Scanning..." : "Complete"}
            </span>
          </div>
          <div ref={logRef} className="max-h-48 overflow-y-auto space-y-1">
            {messages.map((m, i) => (
              <p key={i} className="text-xs font-mono text-zinc-400">{m}</p>
            ))}
            {streaming && messages.length === 0 && (
              <p className="text-xs font-mono text-zinc-600 animate-pulse">Waiting for scan to start...</p>
            )}
          </div>
        </div>
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

      {/* Blast radius */}
      {blastRadius.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <button
              type="button"
              onClick={() => toggleSection("blast")}
              className="flex items-center gap-2 group"
            >
              {collapsedSections.has("blast") ? (
                <ChevronRight className="w-4 h-4 text-zinc-500" />
              ) : (
                <ChevronDown className="w-4 h-4 text-zinc-500" />
              )}
              <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest group-hover:text-zinc-300 transition-colors">
                Blast Radius ({blastRadius.length})
              </h2>
            </button>
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
              {blastRadius
                .sort((a, b) => b.blast_score - a.blast_score)
                .map((b) => (
                  <BlastRadiusCard key={b.vulnerability_id} blast={b} />
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
          <button
            type="button"
            onClick={() => toggleSection("remediation")}
            className="flex items-center gap-2 mb-3 group"
          >
            {collapsedSections.has("remediation") ? (
              <ChevronRight className="w-4 h-4 text-zinc-500" />
            ) : (
              <ChevronDown className="w-4 h-4 text-zinc-500" />
            )}
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest group-hover:text-zinc-300 transition-colors">
              Remediation Plan ({result.remediation_plan.filter((i) => i.fixed_version).length} fixable)
            </h2>
          </button>
          {!collapsedSections.has("remediation") && (
            <RemediationPlan items={result.remediation_plan} />
          )}
        </section>
      )}

      {/* Agent inventory */}
      {result && result.agents.length > 0 && (
        <section>
          <button
            type="button"
            onClick={() => toggleSection("agents")}
            className="flex items-center gap-2 mb-3 group"
          >
            {collapsedSections.has("agents") ? (
              <ChevronRight className="w-4 h-4 text-zinc-500" />
            ) : (
              <ChevronDown className="w-4 h-4 text-zinc-500" />
            )}
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest group-hover:text-zinc-300 transition-colors">
              Agents ({result.agents.length})
            </h2>
          </button>
          {!collapsedSections.has("agents") && (
          <div className="space-y-3">
            {result.agents.map((agent, i) => (
              <div key={i} className={`bg-zinc-900 border rounded-xl p-4 ${agent.status === "installed-not-configured" ? "border-dashed border-zinc-800" : "border-zinc-800"}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-sm">{agent.name}</span>
                    <span className="text-xs text-zinc-500 font-mono">{agent.agent_type}</span>
                    {agent.status === "installed-not-configured" ? (
                      <span className="text-[10px] font-mono bg-yellow-950 border border-yellow-800 text-yellow-400 rounded px-1.5 py-0.5">
                        not configured
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono bg-emerald-950 border border-emerald-800 text-emerald-400 rounded px-1.5 py-0.5">
                        configured
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-zinc-600">{agent.source}</span>
                </div>
                <div className="space-y-2">
                  {agent.mcp_servers.map((srv, j) => (
                    <div key={j} className="bg-zinc-800 rounded-lg p-3">
                      <div className="text-xs font-mono text-zinc-300 mb-1.5">{srv.name}</div>
                      <div className="flex flex-wrap gap-2">
                        {srv.packages.slice(0, 8).map((pkg, k) => {
                          const hasCrit = pkg.vulnerabilities?.some((v) => v.severity === "critical");
                          const hasHigh = pkg.vulnerabilities?.some((v) => v.severity === "high");
                          return (
                            <span
                              key={k}
                              className={`text-xs font-mono px-2 py-0.5 rounded ${
                                hasCrit
                                  ? "bg-red-950 border border-red-900 text-red-300"
                                  : hasHigh
                                  ? "bg-orange-950 border border-orange-900 text-orange-300"
                                  : "bg-zinc-700 border border-zinc-600 text-zinc-400"
                              }`}
                            >
                              {pkg.name}@{pkg.version}
                              {pkg.vulnerabilities && pkg.vulnerabilities.length > 0 && (
                                <span className="ml-1 opacity-70">({pkg.vulnerabilities.length})</span>
                              )}
                            </span>
                          );
                        })}
                        {srv.packages.length > 8 && (
                          <span className="text-xs text-zinc-600">+{srv.packages.length - 8} more</span>
                        )}
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
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Warnings
          </h2>
          <div className="space-y-1">
            {result.warnings.map((w, i) => (
              <p key={i} className="text-xs text-yellow-400 font-mono bg-yellow-950/30 rounded px-3 py-2">
                {w}
              </p>
            ))}
          </div>
        </section>
      )}

      {/* Scan metadata */}
      {job?.completed_at && (
        <div className="text-xs text-zinc-600 flex items-center gap-2">
          <Clock className="w-3 h-3" />
          Completed {formatDate(job.completed_at)}
        </div>
      )}
    </div>
  );
}

// ─── Scan Result Sub-Components ──────────────────────────────────────────────

function JobStatusBadge({ status, streaming }: { status: string; streaming: boolean }) {
  if (status === "done") return <span className="text-xs bg-emerald-950 border border-emerald-900 text-emerald-400 rounded-full px-2 py-0.5 font-mono">done</span>;
  if (status === "failed") return <span className="text-xs bg-red-950 border border-red-900 text-red-400 rounded-full px-2 py-0.5 font-mono">failed</span>;
  if (status === "running" || streaming) return (
    <span className="text-xs bg-yellow-950 border border-yellow-900 text-yellow-400 rounded-full px-2 py-0.5 font-mono flex items-center gap-1">
      <Loader2 className="w-3 h-3 animate-spin" /> running
    </span>
  );
  return <span className="text-xs bg-zinc-800 border border-zinc-700 text-zinc-400 rounded-full px-2 py-0.5 font-mono">{status}</span>;
}

function MiniStat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 text-center">
      <div className={`text-2xl font-bold font-mono ${accent === "red" && value > 0 ? "text-red-400" : ""}`}>
        {value}
      </div>
      <div className="text-xs text-zinc-500 mt-1">{label}</div>
    </div>
  );
}

function BlastRadiusCard({ blast }: { blast: BlastRadius }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <SeverityBadge severity={blast.severity} />
            {blast.cisa_kev && (
              <span className="text-xs bg-red-950 border border-red-900 text-red-400 rounded px-2 py-0.5 font-mono font-semibold">
                CISA KEV
              </span>
            )}
          </div>
          <h3 className="font-mono font-semibold text-zinc-100">{blast.vulnerability_id}</h3>
        </div>
        <div className="text-right flex-shrink-0">
          {blast.blast_score > 0 && (
            <>
              <div className="text-2xl font-bold font-mono text-red-400">{blast.blast_score.toFixed(0)}</div>
              <div className="text-xs text-zinc-600">blast score</div>
            </>
          )}
          {blast.cvss_score && (
            <div className="text-xs text-zinc-500 mt-1">CVSS {blast.cvss_score.toFixed(1)}</div>
          )}
          {blast.epss_score && (
            <div className="text-xs text-zinc-500">EPSS {(blast.epss_score * 100).toFixed(1)}%</div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <ImpactPill icon={Zap} label="Agents affected" items={blast.affected_agents} />
        <ImpactPill icon={Key} label="Credentials exposed" items={blast.exposed_credentials} accent="orange" />
        <ImpactPill icon={Wrench} label="Tools reachable" items={blast.reachable_tools} />
      </div>

      {/* OWASP + ATLAS threat tags with tooltips */}
      {((blast.owasp_tags && blast.owasp_tags.length > 0) || (blast.atlas_tags && blast.atlas_tags.length > 0)) && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {blast.owasp_tags?.map((tag) => (
            <span
              key={tag}
              title={OWASP_LLM_TOP10[tag] ?? tag}
              className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1.5 py-0.5 cursor-help"
            >
              {tag}
              <span className="ml-1 text-purple-600 font-sans">{OWASP_LLM_TOP10[tag]}</span>
            </span>
          ))}
          {blast.atlas_tags?.map((tag) => (
            <span
              key={tag}
              title={MITRE_ATLAS[tag] ?? tag}
              className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1.5 py-0.5 cursor-help"
            >
              {tag}
              <span className="ml-1 text-cyan-600 font-sans">{MITRE_ATLAS[tag]}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ImpactPill({
  icon: Icon, label, items, accent,
}: {
  icon: React.ElementType;
  label: string;
  items: string[];
  accent?: string;
}) {
  const accentClass = accent === "orange" && items.length > 0 ? "text-orange-400" : "text-zinc-300";
  return (
    <div className="bg-zinc-800 rounded-lg p-3">
      <div className={`flex items-center gap-1.5 text-xs font-semibold mb-2 ${accentClass}`}>
        <Icon className="w-3.5 h-3.5" />
        <span>{label} ({items.length})</span>
      </div>
      {items.length > 0 ? (
        <div className="space-y-1">
          {items.slice(0, 4).map((item, i) => (
            <p key={i} className="text-xs font-mono text-zinc-400 truncate">{item}</p>
          ))}
          {items.length > 4 && (
            <p className="text-xs text-zinc-600">+{items.length - 4} more</p>
          )}
        </div>
      ) : (
        <p className="text-xs text-zinc-600">None</p>
      )}
    </div>
  );
}

function RemediationPlan({ items }: { items: RemediationItem[] }) {
  const fixable = items.filter((i) => i.fixed_version);
  const unfixable = items.filter((i) => !i.fixed_version);

  return (
      <div className="space-y-3">
        {fixable.map((item, i) => (
          <div key={i} className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
            {/* Header: upgrade action */}
            <div className="flex items-start justify-between gap-4 mb-3">
              <div className="flex items-center gap-3">
                <ArrowUpCircle className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm font-semibold text-zinc-100">{item.package}</span>
                    <span className="text-xs text-zinc-500 font-mono">{item.current_version}</span>
                    <span className="text-zinc-600">&rarr;</span>
                    <span className="text-xs text-emerald-400 font-mono font-semibold">{item.fixed_version}</span>
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(item.severity)}`}>
                      {item.severity}
                    </span>
                    {item.is_kev && (
                      <span className="text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-1.5 py-0.5">KEV</span>
                    )}
                  </div>
                  <p className="text-xs text-zinc-500 mt-0.5">
                    Clears {item.vulnerabilities.length} vuln{item.vulnerabilities.length !== 1 ? "s" : ""}
                    {" \u00B7 "}
                    {item.ecosystem}
                  </p>
                </div>
              </div>
              <div className="text-right flex-shrink-0">
                <div className="text-lg font-bold font-mono text-emerald-400">{item.impact_score}</div>
                <div className="text-xs text-zinc-600">impact</div>
              </div>
            </div>

            {/* Impact grid: assets protected */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
              <ImpactBox
                label="Agents protected"
                items={item.affected_agents}
                pct={item.agents_pct}
                color="emerald"
              />
              <ImpactBox
                label="Credentials freed"
                items={item.exposed_credentials}
                pct={item.credentials_pct}
                color="yellow"
              />
              <ImpactBox
                label="Tools secured"
                items={item.reachable_tools}
                pct={item.tools_pct}
                color="blue"
              />
            </div>

            {/* Threat tags */}
            {(item.owasp_tags.length > 0 || item.atlas_tags.length > 0) && (
              <div className="flex flex-wrap gap-1.5 mb-3">
                <span className="text-xs text-zinc-500 mr-1">mitigates:</span>
                {item.owasp_tags.map((tag) => (
                  <span key={tag} title={OWASP_LLM_TOP10[tag] ?? tag} className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1.5 py-0.5 cursor-help">
                    {tag}
                  </span>
                ))}
                {item.atlas_tags.map((tag) => (
                  <span key={tag} title={MITRE_ATLAS[tag] ?? tag} className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1.5 py-0.5 cursor-help">
                    {tag}
                  </span>
                ))}
              </div>
            )}

            {/* Risk narrative */}
            <div className="flex items-start gap-2 bg-red-950/20 border border-red-900/30 rounded-lg px-3 py-2">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-red-300/80">{item.risk_narrative}</p>
            </div>
          </div>
        ))}

        {unfixable.length > 0 && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <p className="text-xs text-yellow-400 font-semibold mb-2">
              {unfixable.length} package{unfixable.length !== 1 ? "s" : ""} with no fix available -- monitor upstream
            </p>
            <div className="space-y-1">
              {unfixable.slice(0, 5).map((item, i) => (
                <p key={i} className="text-xs font-mono text-zinc-500">
                  {item.package}@{item.current_version} -- {item.vulnerabilities.slice(0, 3).join(", ")}
                </p>
              ))}
            </div>
          </div>
        )}
      </div>
  );
}

function ImpactBox({
  label, items, pct, color,
}: {
  label: string;
  items: string[];
  pct: number;
  color: "emerald" | "yellow" | "blue";
}) {
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
        <span className="text-xs font-mono text-zinc-400">{pct}%</span>
      </div>
      {/* Progress bar */}
      <div className="h-1.5 rounded-full bg-zinc-800 mb-2">
        <div className={`h-1.5 rounded-full ${c.bar} transition-all duration-500`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      {items.length > 0 ? (
        <div className="space-y-0.5">
          {items.slice(0, 3).map((item, i) => (
            <p key={i} className="text-xs font-mono text-zinc-400 truncate">{item}</p>
          ))}
          {items.length > 3 && (
            <p className="text-xs text-zinc-600">+{items.length - 3} more</p>
          )}
        </div>
      ) : (
        <p className="text-xs text-zinc-600">None</p>
      )}
    </div>
  );
}

function ThreatMatrix({ blastRadius }: { blastRadius: BlastRadius[] }) {
  // Aggregate counts
  const owaspCounts: Record<string, number> = {};
  const atlasCounts: Record<string, number> = {};

  for (const br of blastRadius) {
    for (const tag of br.owasp_tags ?? []) {
      owaspCounts[tag] = (owaspCounts[tag] ?? 0) + 1;
    }
    for (const tag of br.atlas_tags ?? []) {
      atlasCounts[tag] = (atlasCounts[tag] ?? 0) + 1;
    }
  }

  const owaspTriggered = Object.keys(owaspCounts).length;
  const atlasTriggered = Object.keys(atlasCounts).length;

  if (owaspTriggered === 0 && atlasTriggered === 0) return null;

  return (
    <section>
      <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
        Threat Framework Coverage
      </h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* OWASP LLM Top 10 */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-purple-400 uppercase tracking-wider">OWASP LLM Top 10</h3>
            <span className="text-xs text-zinc-500">
              {owaspTriggered}/{Object.keys(OWASP_LLM_TOP10).length} triggered
            </span>
          </div>
          <div className="space-y-1.5">
            {Object.entries(OWASP_LLM_TOP10).map(([code, name]) => {
              const count = owaspCounts[code] ?? 0;
              const triggered = count > 0;
              return (
                <div
                  key={code}
                  className={`flex items-center gap-3 px-2.5 py-1.5 rounded-md ${
                    triggered ? "bg-purple-950/40" : "opacity-40"
                  }`}
                >
                  <span
                    className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      triggered ? "bg-purple-400" : "bg-zinc-700"
                    }`}
                  />
                  <span className={`text-xs font-mono w-12 flex-shrink-0 ${triggered ? "text-purple-400" : "text-zinc-600"}`}>
                    {code}
                  </span>
                  <span className={`text-xs flex-1 ${triggered ? "text-zinc-300" : "text-zinc-600"}`}>
                    {name}
                  </span>
                  {triggered && (
                    <span className="text-xs font-mono font-semibold text-purple-400">
                      {count}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* MITRE ATLAS */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">MITRE ATLAS</h3>
            <span className="text-xs text-zinc-500">
              {atlasTriggered}/{Object.keys(MITRE_ATLAS).length} triggered
            </span>
          </div>
          <div className="space-y-1.5">
            {Object.entries(MITRE_ATLAS).map(([code, name]) => {
              const count = atlasCounts[code] ?? 0;
              const triggered = count > 0;
              return (
                <div
                  key={code}
                  className={`flex items-center gap-3 px-2.5 py-1.5 rounded-md ${
                    triggered ? "bg-cyan-950/40" : "opacity-40"
                  }`}
                >
                  <span
                    className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      triggered ? "bg-cyan-400" : "bg-zinc-700"
                    }`}
                  />
                  <span className={`text-xs font-mono w-20 flex-shrink-0 ${triggered ? "text-cyan-400" : "text-zinc-600"}`}>
                    {code}
                  </span>
                  <span className={`text-xs flex-1 ${triggered ? "text-zinc-300" : "text-zinc-600"}`}>
                    {name}
                  </span>
                  {triggered && (
                    <span className="text-xs font-mono font-semibold text-cyan-400">
                      {count}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. ATTACK FLOW VIEW (from scan/[id]/attack-flow/page.tsx)
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Constants ───────────────────────────────────────────────────────────────

const NODE_ICONS: Record<string, React.ElementType> = {
  cve: Bug,
  package: Package,
  server: Server,
  agent: ShieldAlert,
  credential: KeyRound,
  tool: Wrench,
};

const NODE_COLORS: Record<string, string> = {
  cve: "border-red-600 bg-red-950/80",
  package: "border-zinc-600 bg-zinc-900/80",
  server: "border-blue-600 bg-blue-950/80",
  agent: "border-emerald-600 bg-emerald-950/80",
  credential: "border-yellow-600 bg-yellow-950/80",
  tool: "border-purple-600 bg-purple-950/80",
};

const NODE_MINIMAP_COLORS: Record<string, string> = {
  cve: "#ef4444",
  package: "#52525b",
  server: "#3b82f6",
  agent: "#10b981",
  credential: "#eab308",
  tool: "#a855f7",
};

// ─── Custom Node Component ──────────────────────────────────────────────────

function AttackFlowNode({ data }: { data: AttackFlowNodeData }) {
  const nodeType = data.nodeType;
  const Icon = NODE_ICONS[nodeType] ?? Bug;

  // Severity-aware CVE coloring
  let colorClass = NODE_COLORS[nodeType] ?? NODE_COLORS.cve;
  if (nodeType === "cve" && data.severity) {
    const sev = data.severity.toLowerCase();
    if (sev === "critical") colorClass = "border-red-600 bg-red-950/80";
    else if (sev === "high") colorClass = "border-orange-600 bg-orange-950/80";
    else if (sev === "medium") colorClass = "border-yellow-600 bg-yellow-950/80";
    else colorClass = "border-blue-600 bg-blue-950/80";
  }

  const showTarget = nodeType !== "cve";
  const showSource = nodeType !== "agent" && nodeType !== "credential" && nodeType !== "tool";

  return (
    <div className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[220px] shadow-lg backdrop-blur ${colorClass}`}>
      {showTarget && (
        <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2 !border-zinc-400" />
      )}
      <div className="flex items-center gap-1.5 mb-0.5">
        <Icon className="w-3.5 h-3.5 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>

      {/* Type-specific details */}
      <div className="flex flex-wrap gap-1 mt-1">
        {nodeType === "cve" && data.severity && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${severityColor(data.severity)}`}>
            {data.severity}
          </span>
        )}
        {nodeType === "cve" && data.is_kev && (
          <span className="text-[10px] px-1 py-0.5 rounded border font-mono border-red-700 bg-red-950 text-red-400">
            KEV
          </span>
        )}
        {nodeType === "cve" && data.cvss_score != null && (
          <span className="text-[10px] text-zinc-400 font-mono">CVSS {data.cvss_score.toFixed(1)}</span>
        )}
        {nodeType === "package" && data.version && (
          <span className="text-[10px] text-zinc-400 font-mono">@{data.version}</span>
        )}
        {nodeType === "package" && data.ecosystem && (
          <span className="text-[10px] text-zinc-500 font-mono">{data.ecosystem}</span>
        )}
        {nodeType === "agent" && data.agent_type && (
          <span className="text-[10px] text-zinc-400 font-mono">{data.agent_type}</span>
        )}
      </div>

      {/* Framework tags (CVE nodes only) */}
      {nodeType === "cve" && (data.owasp_tags?.length || data.atlas_tags?.length || data.owasp_mcp_tags?.length) ? (
        <div className="flex flex-wrap gap-0.5 mt-1">
          {data.owasp_tags?.slice(0, 2).map((tag) => (
            <span key={tag} className="text-[9px] font-mono bg-purple-950/60 border border-purple-800/50 text-purple-400 rounded px-1">
              {tag}
            </span>
          ))}
          {data.owasp_mcp_tags?.slice(0, 2).map((tag) => (
            <span key={tag} className="text-[9px] font-mono bg-amber-950/60 border border-amber-800/50 text-amber-400 rounded px-1">
              {tag}
            </span>
          ))}
          {data.atlas_tags?.slice(0, 1).map((tag) => (
            <span key={tag} className="text-[9px] font-mono bg-cyan-950/60 border border-cyan-800/50 text-cyan-400 rounded px-1">
              {tag}
            </span>
          ))}
        </div>
      ) : null}

      {showSource && (
        <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2 !border-zinc-400" />
      )}
    </div>
  );
}

const nodeTypes = { attackFlowNode: AttackFlowNode };

// ─── Detail Panel ────────────────────────────────────────────────────────────

function DetailPanel({ data, onClose }: { data: AttackFlowNodeData; onClose: () => void }) {
  const typeLabels: Record<string, string> = {
    cve: "Vulnerability",
    package: "Package",
    server: "MCP Server",
    agent: "Agent",
    credential: "Credential",
    tool: "Tool",
  };
  const borderColors: Record<string, string> = {
    cve: "border-red-700",
    package: "border-zinc-700",
    server: "border-blue-700",
    agent: "border-emerald-700",
    credential: "border-yellow-700",
    tool: "border-purple-700",
  };

  return (
    <div className={`absolute right-0 top-0 bottom-0 w-80 bg-zinc-950/95 backdrop-blur-sm border-l ${borderColors[data.nodeType] ?? "border-zinc-700"} z-50 overflow-y-auto`}>
      <div className="p-4 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[10px] uppercase tracking-wider text-zinc-500">{typeLabels[data.nodeType] ?? data.nodeType}</span>
            <h3 className="text-sm font-semibold text-zinc-100 mt-0.5 break-all">{data.label}</h3>
          </div>
          <button onClick={onClose} className="p-1 text-zinc-500 hover:text-zinc-300 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* CVE details */}
        {data.nodeType === "cve" && (
          <div className="space-y-3">
            {data.severity && <SeverityBadge severity={data.severity} />}
            <div className="grid grid-cols-2 gap-2">
              {data.cvss_score != null && (
                <div className="bg-zinc-900 rounded-lg p-2 text-center">
                  <div className="text-lg font-bold font-mono text-zinc-100">{data.cvss_score.toFixed(1)}</div>
                  <div className="text-[10px] text-zinc-500">CVSS</div>
                </div>
              )}
              {data.epss_score != null && (
                <div className="bg-zinc-900 rounded-lg p-2 text-center">
                  <div className="text-lg font-bold font-mono text-zinc-100">{(data.epss_score * 100).toFixed(1)}%</div>
                  <div className="text-[10px] text-zinc-500">EPSS</div>
                </div>
              )}
            </div>
            {data.is_kev && (
              <div className="text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-2 py-1.5 flex items-center gap-1.5">
                <AlertTriangle className="w-3 h-3" />
                CISA Known Exploited Vulnerability
              </div>
            )}
            {data.fixed_version && (
              <div className="text-xs text-zinc-400">
                Fix available: <span className="text-emerald-400 font-mono font-semibold">{data.fixed_version}</span>
              </div>
            )}
            {data.owasp_tags && data.owasp_tags.length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">OWASP LLM Top 10</div>
                <div className="space-y-1">
                  {data.owasp_tags.map((tag) => (
                    <div key={tag} className="text-xs font-mono bg-purple-950/40 border border-purple-800/50 text-purple-400 rounded px-2 py-1">
                      {tag} <span className="text-purple-600 font-sans">{OWASP_LLM_TOP10[tag]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.owasp_mcp_tags && data.owasp_mcp_tags.length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">OWASP MCP Top 10</div>
                <div className="space-y-1">
                  {data.owasp_mcp_tags.map((tag) => (
                    <div key={tag} className="text-xs font-mono bg-amber-950/40 border border-amber-800/50 text-amber-400 rounded px-2 py-1">
                      {tag} <span className="text-amber-600 font-sans">{OWASP_MCP_TOP10[tag]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.atlas_tags && data.atlas_tags.length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">MITRE ATLAS</div>
                <div className="space-y-1">
                  {data.atlas_tags.map((tag) => (
                    <div key={tag} className="text-xs font-mono bg-cyan-950/40 border border-cyan-800/50 text-cyan-400 rounded px-2 py-1">
                      {tag} <span className="text-cyan-600 font-sans">{MITRE_ATLAS[tag]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.risk_score != null && (
              <div className="text-xs text-zinc-400">
                Risk score: <span className="text-red-400 font-mono font-bold">{data.risk_score}</span>
              </div>
            )}
            <a
              href={`https://osv.dev/vulnerability/${data.label}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 transition-colors"
            >
              <ExternalLink className="w-3 h-3" />
              View on OSV
            </a>
          </div>
        )}

        {/* Package details */}
        {data.nodeType === "package" && (
          <div className="space-y-2">
            {data.version && <div className="text-xs text-zinc-400 font-mono">Version: {data.version}</div>}
            {data.ecosystem && <div className="text-xs text-zinc-400 font-mono">Ecosystem: {data.ecosystem}</div>}
          </div>
        )}

        {/* Server details */}
        {data.nodeType === "server" && (
          <div className="text-xs text-zinc-400">MCP server in the supply chain</div>
        )}

        {/* Agent details */}
        {data.nodeType === "agent" && (
          <div className="space-y-2">
            {data.agent_type && <div className="text-xs text-zinc-400 font-mono">Type: {data.agent_type}</div>}
            {data.status && (
              <div className={`text-xs px-2 py-1 rounded border font-mono ${
                data.status === "installed-not-configured"
                  ? "border-yellow-800 bg-yellow-950 text-yellow-400"
                  : "border-emerald-800 bg-emerald-950 text-emerald-400"
              }`}>
                {data.status === "installed-not-configured" ? "Not Configured" : "Configured"}
              </div>
            )}
          </div>
        )}

        {/* Credential details */}
        {data.nodeType === "credential" && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-amber-400">
              <KeyRound className="w-3 h-3" />
              Exposed credential env var
            </div>
            <div className="text-xs text-zinc-400">
              This credential is accessible through a vulnerable MCP server in the supply chain.
            </div>
          </div>
        )}

        {/* Tool details */}
        {data.nodeType === "tool" && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-purple-400">
              <Wrench className="w-3 h-3" />
              Reachable MCP tool
            </div>
            <div className="text-xs text-zinc-400">
              This tool is exposed through a vulnerable MCP server and could be invoked by an attacker.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Export Button ────────────────────────────────────────────────────────────

function ExportButton() {
  const { getNodes, getEdges } = useReactFlow();

  const handleExport = useCallback(() => {
    const flowData = { nodes: getNodes(), edges: getEdges() };
    const blob = new Blob([JSON.stringify(flowData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attack-flow-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [getNodes, getEdges]);

  return (
    <button
      onClick={handleExport}
      className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 border border-zinc-700 rounded-lg text-xs text-zinc-300 hover:bg-zinc-700 transition-colors"
    >
      <Download className="w-3 h-3" />
      Export JSON
    </button>
  );
}

// ─── Filter Bar ──────────────────────────────────────────────────────────────

interface AttackFlowFilters {
  cve: string;
  severity: string;
  framework: string;
  agent: string;
}

function FilterBar({
  filters,
  onChange,
  blastRadius,
}: {
  filters: AttackFlowFilters;
  onChange: (f: AttackFlowFilters) => void;
  blastRadius: BlastRadius[];
}) {
  // Extract unique values for dropdowns
  const cveIds = useMemo(() => {
    const ids = new Set<string>();
    for (const br of blastRadius) ids.add(br.vulnerability_id);
    return Array.from(ids).sort();
  }, [blastRadius]);

  const frameworkTags = useMemo(() => {
    const tags = new Set<string>();
    for (const br of blastRadius) {
      for (const t of br.owasp_tags ?? []) tags.add(t);
      for (const t of br.owasp_mcp_tags ?? []) tags.add(t);
      for (const t of br.atlas_tags ?? []) tags.add(t);
      for (const t of br.nist_ai_rmf_tags ?? []) tags.add(t);
    }
    return Array.from(tags).sort();
  }, [blastRadius]);

  const agentNames = useMemo(() => {
    const names = new Set<string>();
    for (const br of blastRadius) {
      for (const a of br.affected_agents) names.add(a);
    }
    return Array.from(names).sort();
  }, [blastRadius]);

  const severities = ["critical", "high", "medium", "low"];
  const activeSev = filters.severity.toLowerCase();

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <Filter className="w-3.5 h-3.5 text-zinc-500" />

      {/* CVE dropdown */}
      <select
        value={filters.cve}
        onChange={(e) => onChange({ ...filters, cve: e.target.value })}
        className="bg-zinc-900 border border-zinc-700 rounded-md px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-600"
      >
        <option value="">All CVEs</option>
        {cveIds.map((id) => (
          <option key={id} value={id}>{id}</option>
        ))}
      </select>

      {/* Severity toggle buttons */}
      <div className="flex gap-0.5">
        {severities.map((sev) => (
          <button
            key={sev}
            onClick={() => onChange({ ...filters, severity: activeSev === sev ? "" : sev })}
            className={`text-[10px] font-mono uppercase px-2 py-1 rounded border transition-colors ${
              activeSev === sev
                ? severityColor(sev)
                : "border-zinc-700 bg-zinc-900 text-zinc-500 hover:border-zinc-600"
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Framework dropdown */}
      {frameworkTags.length > 0 && (
        <select
          value={filters.framework}
          onChange={(e) => onChange({ ...filters, framework: e.target.value })}
          className="bg-zinc-900 border border-zinc-700 rounded-md px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          <option value="">All Frameworks</option>
          {frameworkTags.map((tag) => (
            <option key={tag} value={tag}>
              {tag} {OWASP_LLM_TOP10[tag] ? `- ${OWASP_LLM_TOP10[tag]}` : OWASP_MCP_TOP10[tag] ? `- ${OWASP_MCP_TOP10[tag]}` : MITRE_ATLAS[tag] ? `- ${MITRE_ATLAS[tag]}` : ""}
            </option>
          ))}
        </select>
      )}

      {/* Agent dropdown */}
      {agentNames.length > 0 && (
        <select
          value={filters.agent}
          onChange={(e) => onChange({ ...filters, agent: e.target.value })}
          className="bg-zinc-900 border border-zinc-700 rounded-md px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          <option value="">All Agents</option>
          {agentNames.map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
      )}

      {/* Clear all */}
      {(filters.cve || filters.severity || filters.framework || filters.agent) && (
        <button
          onClick={() => onChange({ cve: "", severity: "", framework: "", agent: "" })}
          className="text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors underline"
        >
          Clear filters
        </button>
      )}
    </div>
  );
}

// ─── Stats Bar ───────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: AttackFlowResponse["stats"] }) {
  const items = [
    { label: "CVEs", value: stats.total_cves, color: "text-red-400" },
    { label: "Packages", value: stats.total_packages, color: "text-zinc-300" },
    { label: "Servers", value: stats.total_servers, color: "text-blue-400" },
    { label: "Agents", value: stats.total_agents, color: "text-emerald-400" },
    { label: "Credentials", value: stats.total_credentials, color: "text-yellow-400" },
    { label: "Tools", value: stats.total_tools, color: "text-purple-400" },
  ];

  return (
    <div className="flex items-center gap-3">
      {items
        .filter((i) => i.value > 0)
        .map((item) => (
          <span key={item.label} className="flex items-center gap-1 text-xs">
            <span className={`font-mono font-bold ${item.color}`}>{item.value}</span>
            <span className="text-zinc-500">{item.label}</span>
          </span>
        ))}
      {/* Severity breakdown */}
      <span className="text-zinc-700">|</span>
      {Object.entries(stats.severity_counts)
        .filter(([, v]) => v > 0)
        .map(([sev, count]) => (
          <span key={sev} className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border ${severityColor(sev)}`}>
            {count} {sev}
          </span>
        ))}
    </div>
  );
}

// ─── Main Flow Content ──────────────────────────────────────────────────────

function AttackFlowContent({
  id,
  job,
  flowData,
  filters,
  onFiltersChange,
}: {
  id: string;
  job: ScanJob;
  flowData: AttackFlowResponse;
  filters: AttackFlowFilters;
  onFiltersChange: (f: AttackFlowFilters) => void;
}) {
  const [selectedNode, setSelectedNode] = useState<AttackFlowNodeData | null>(null);
  const blastRadius = job.result?.blast_radius ?? [];

  const nodes = flowData.nodes.map((n) => ({
    ...n,
    type: "attackFlowNode" as const,
    data: n.data as unknown as Record<string, unknown>,
  }));
  const edges = flowData.edges;

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col">
      {/* Header */}
      <div className="px-4 py-3 border-b border-zinc-800 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href={`/scan?id=${id}`} className="text-zinc-500 hover:text-zinc-300 transition-colors">
              <ArrowLeft className="w-4 h-4" />
            </Link>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100">Attack Flow</h1>
              <p className="text-xs text-zinc-500">
                CVE &rarr; Package &rarr; Server &rarr; Agent blast radius chain
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <StatsBar stats={flowData.stats} />
            <ExportButton />
          </div>
        </div>

        {/* Filter bar */}
        <FilterBar filters={filters} onChange={onFiltersChange} blastRadius={blastRadius} />
      </div>

      {/* Graph or empty state */}
      <div className="flex-1 relative">
        {flowData.nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-zinc-400 gap-3">
            <Filter className="w-8 h-8 text-zinc-600" />
            <p className="text-sm">No results match the current filters</p>
            <button
              onClick={() => onFiltersChange({ cve: "", severity: "", framework: "", agent: "" })}
              className="text-xs text-emerald-400 hover:text-emerald-300 underline"
            >
              Clear all filters
            </button>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.1}
            maxZoom={2}
            defaultEdgeOptions={{ type: "smoothstep" }}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_event, node) => {
              setSelectedNode(node.data as unknown as AttackFlowNodeData);
            }}
            onPaneClick={() => setSelectedNode(null)}
          >
            <Background color="#27272a" gap={20} />
            <Controls
              className="!bg-zinc-900 !border-zinc-700 !rounded-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-300 [&>button:hover]:!bg-zinc-700"
            />
            <MiniMap
              nodeColor={(n) => {
                const d = n.data as unknown as AttackFlowNodeData;
                return NODE_MINIMAP_COLORS[d.nodeType] ?? "#52525b";
              }}
              className="!bg-zinc-900 !border-zinc-700 !rounded-lg"
            />
          </ReactFlow>
        )}

        {/* Detail slide-over panel */}
        {selectedNode && (
          <DetailPanel data={selectedNode} onClose={() => setSelectedNode(null)} />
        )}
      </div>

      {/* Legend */}
      <div className="px-4 py-2 border-t border-zinc-800 flex items-center gap-4 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-red-600 bg-red-950" /> CVE</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-zinc-600 bg-zinc-900" /> Package</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-blue-600 bg-blue-950" /> Server</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-emerald-600 bg-emerald-950" /> Agent</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-yellow-600 bg-yellow-950" /> Credential</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded border-2 border-purple-600 bg-purple-950" /> Tool</span>
      </div>
    </div>
  );
}

// ─── Attack Flow View ────────────────────────────────────────────────────────

function AttackFlowView({ id }: { id: string }) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [flowData, setFlowData] = useState<AttackFlowResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<AttackFlowFilters>({ cve: "", severity: "", framework: "", agent: "" });

  // Load job data
  useEffect(() => {
    api.getScan(id).then(setJob).catch((e) => setError(e.message));
  }, [id]);

  // Load attack flow (re-fetch when filters change)
  useEffect(() => {
    setLoading(true);
    const filterParams: Record<string, string> = {};
    if (filters.cve) filterParams.cve = filters.cve;
    if (filters.severity) filterParams.severity = filters.severity;
    if (filters.framework) filterParams.framework = filters.framework;
    if (filters.agent) filterParams.agent = filters.agent;

    api
      .getAttackFlow(id, Object.keys(filterParams).length > 0 ? filterParams : undefined)
      .then(setFlowData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id, filters]);

  if (loading && !flowData) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading attack flow...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">Could not load attack flow</p>
        <p className="text-xs text-zinc-500">{error}</p>
        <Link href={`/scan?id=${id}`} className="text-xs text-emerald-400 hover:text-emerald-300 underline">
          Back to scan results
        </Link>
      </div>
    );
  }

  if (!job || !flowData) return null;

  return (
    <ReactFlowProvider>
      <AttackFlowContent
        id={id}
        job={job}
        flowData={flowData}
        filters={filters}
        onFiltersChange={setFilters}
      />
    </ReactFlowProvider>
  );
}
