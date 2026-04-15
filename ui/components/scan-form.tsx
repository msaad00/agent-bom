"use client";

import { useState, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, type ScanRequest } from "@/lib/api";
import { ArrowRight, Cloud, Loader2, Plus, Radio, Upload, Workflow, X } from "lucide-react";

// ─── Scan Form ──────────────────────────────────────────────────────────────

export function ScanForm() {
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
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight mb-1">New Scan</h1>
          <p className="text-zinc-400 text-sm">
            Launch direct scan jobs from this page. Cloud-backed governance feeds, connector-backed discovery, and trace ingest live in separate product
            surfaces.
          </p>
        </div>
        <Link
          href="/sources"
          className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm font-medium text-zinc-200 transition-colors hover:border-zinc-600 hover:bg-zinc-800"
        >
          Explore data sources
          <ArrowRight className="h-4 w-4" />
        </Link>
      </div>

      <div className="grid gap-3 md:grid-cols-2 mb-8">
        <SurfaceCard
          icon={Workflow}
          title="Direct scans"
          description="Local MCP configs, images, Kubernetes, Terraform, GitHub Actions, custom inventory, and Python agent projects start here."
          badge="This page"
        />
        <SurfaceCard
          icon={Cloud}
          title="Cloud and governance feeds"
          description="Snowflake and other cloud-backed governance or activity data are surfaced through the governance and activity pages, not this scan form."
          href="/governance"
          action="Open governance"
        />
        <SurfaceCard
          icon={Radio}
          title="Trace ingest"
          description="OTLP and runtime-event ingest are handled through the traces surface and the POST /v1/traces API contract."
          href="/traces"
          action="Open traces"
        />
        <SurfaceCard
          icon={Cloud}
          title="Connectors and enterprise sources"
          description="Connector-backed discovery and SIEM integrations exist in the backend today, but they are not yet exposed as first-class setup flows on this page."
          badge="API today"
        />
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Auto-discover */}
        <Section title="Local MCP configs" subtitle="Claude Desktop, Cursor, Windsurf, Cline, VS Code... (auto)">
          <p className="text-xs text-zinc-500">Always included automatically.</p>
        </Section>

        {/* Docker images */}
        <Section title="Docker images" subtitle="--image flag · supports bulk input for enterprise scale">
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

          {imageMode === "upload" && (
            <div className="space-y-2">
              <input ref={fileInputRef} type="file" accept=".txt,.csv,.list" onChange={handleFileUpload} className="hidden" />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-2 px-4 py-3 w-full bg-zinc-800 hover:bg-zinc-700 border border-dashed border-zinc-600 rounded-lg text-sm text-zinc-300 transition-colors justify-center"
              >
                <Upload className="w-4 h-4" />
                Choose .txt file (one image per line)
              </button>
              <p className="text-[10px] text-zinc-600">Lines starting with # are ignored. Supports .txt, .csv, .list files.</p>
            </div>
          )}

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
          <p className="text-red-400 text-sm bg-red-950 border border-red-900 rounded-lg px-4 py-3">{error}</p>
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

// ─── Helpers ────────────────────────────────────────────────────────────────

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

function SurfaceCard({
  icon: Icon,
  title,
  description,
  href,
  action,
  badge,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  href?: string;
  action?: string;
  badge?: string;
}) {
  const content = (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 transition-colors hover:border-zinc-700 hover:bg-zinc-900/80">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <span className="rounded-lg border border-zinc-800 bg-zinc-950 p-2">
            <Icon className="w-4 h-4 text-emerald-400" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">{title}</h3>
            {badge && <p className="text-[11px] uppercase tracking-[0.18em] text-zinc-500 mt-0.5">{badge}</p>}
          </div>
        </div>
        {href && <ArrowRight className="w-4 h-4 text-zinc-500" />}
      </div>
      <p className="text-xs leading-5 text-zinc-400">{description}</p>
      {href && action && <div className="mt-4 text-xs font-medium text-emerald-400">{action}</div>}
    </div>
  );

  if (!href) return content;

  return <Link href={href}>{content}</Link>;
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
          {items?.map((item, i) => (
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
