"use client";

import { useState, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, type ScanRequest } from "@/lib/api";
import { ArrowRight, ChevronDown, Loader2, Plus, Upload, X } from "lucide-react";

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

  const queuedImages = form.images ?? [];

  return (
    <div className="max-w-5xl">
      <header className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-100">New Scan</h1>
          <p className="mt-1 max-w-2xl text-sm text-zinc-400">
            Run a direct scan job. Local MCP configs are included automatically.
          </p>
          <nav aria-label="Related scan surfaces" className="mt-3 flex flex-wrap items-center gap-x-1 gap-y-1 text-xs text-zinc-500">
            <RelatedLink href="/sources">Data sources</RelatedLink>
            <span aria-hidden="true">·</span>
            <RelatedLink href="/governance">Governance</RelatedLink>
            <span aria-hidden="true">·</span>
            <RelatedLink href="/traces">Traces</RelatedLink>
            <span aria-hidden="true">·</span>
            <RelatedLink href="/jobs">Scan jobs</RelatedLink>
          </nav>
        </div>
        <Link
          href="/sources"
          className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm font-medium text-zinc-200 transition-colors hover:border-zinc-600 hover:bg-zinc-800"
        >
          Connect source
          <ArrowRight className="h-4 w-4" />
        </Link>
      </header>

      <form onSubmit={handleSubmit} className="grid gap-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)] lg:items-start">
        <div className="space-y-5">
          <Section title="Docker images">
            <div className="mb-3 flex flex-wrap items-center gap-1">
              {(["single", "bulk", "upload"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setImageMode(mode)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
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
                  rows={4}
                  className="w-full resize-y rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 font-mono text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-600 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={applyBulk}
                  disabled={!bulkText.trim()}
                  className="flex items-center gap-1.5 rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Plus className="h-3.5 w-3.5" />
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
                  className="flex w-full items-center justify-center gap-2 rounded-lg border border-dashed border-zinc-600 bg-zinc-800 px-4 py-3 text-sm text-zinc-300 transition-colors hover:bg-zinc-700"
                >
                  <Upload className="h-4 w-4" />
                  Choose .txt file
                </button>
              </div>
            )}

            {queuedImages.length > 0 && (
              <div className="mt-3 space-y-1.5">
                <div className="text-xs font-medium text-zinc-500">
                  {queuedImages.length} image{queuedImages.length !== 1 ? "s" : ""} queued
                </div>
                <div className="flex flex-wrap gap-2">
                  {queuedImages.map((item, i) => (
                    <span key={i} className="flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800 px-2.5 py-1 font-mono text-xs text-zinc-300">
                      {item}
                      <button type="button" onClick={() => removeFromList("images", i)}>
                        <X className="h-3 w-3 text-zinc-500 hover:text-zinc-300" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Section>

          <Section title="Kubernetes cluster">
            <label className="flex cursor-pointer items-center gap-2">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-zinc-700 bg-zinc-900 text-emerald-500"
                checked={form.k8s ?? false}
                onChange={(e) => setForm((f) => ({ ...f, k8s: e.target.checked }))}
              />
              <span className="text-sm text-zinc-300">Scan running pods via kubectl</span>
            </label>
            {form.k8s && (
              <input
                type="text"
                placeholder="Namespace (optional)"
                className="mt-2 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-emerald-600 focus:outline-none"
                value={form.k8s_namespace ?? ""}
                onChange={(e) => setForm((f) => ({ ...f, k8s_namespace: e.target.value || undefined }))}
              />
            )}
          </Section>

          <Section title="Python agent projects">
            <ListInput
              placeholder="/path/to/my-langchain-app"
              value={apInput}
              onChange={setApInput}
              onAdd={() => addToList("agent_projects", apInput, () => setApInput(""))}
              items={form.agent_projects ?? []}
              onRemove={(i) => removeFromList("agent_projects", i)}
            />
          </Section>
        </div>

        <div className="space-y-5">
          <details className="group rounded-xl border border-zinc-800 bg-zinc-900">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 text-sm font-semibold text-zinc-200 [&::-webkit-details-marker]:hidden">
              Advanced targets
              <ChevronDown className="h-4 w-4 text-zinc-500 transition-transform group-open:rotate-180" />
            </summary>
            <div className="space-y-5 border-t border-zinc-800 px-5 py-4">
              <div>
                <h3 className="mb-2 text-sm font-medium text-zinc-200">Terraform directories</h3>
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
                <h3 className="mb-2 text-sm font-medium text-zinc-200">GitHub Actions</h3>
                <input
                  type="text"
                  placeholder="/path/to/git/repo"
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-emerald-600 focus:outline-none"
                  value={form.gha_path ?? ""}
                  onChange={(e) => setForm((f) => ({ ...f, gha_path: e.target.value || undefined }))}
                />
              </div>
              <div>
                <h3 className="mb-2 text-sm font-medium text-zinc-200">Custom inventory</h3>
                <input
                  type="text"
                  placeholder="/path/to/agents.json"
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-emerald-600 focus:outline-none"
                  value={form.inventory ?? ""}
                  onChange={(e) => setForm((f) => ({ ...f, inventory: e.target.value || undefined }))}
                />
              </div>
            </div>
          </details>

          <Section title="Options">
            <label className="flex cursor-pointer items-start gap-2">
              <input
                type="checkbox"
                className="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 text-emerald-500"
                checked={form.enrich ?? false}
                onChange={(e) => setForm((f) => ({ ...f, enrich: e.target.checked }))}
              />
              <span className="text-sm text-zinc-300">
                Enrich with NVD CVSS, EPSS, and CISA KEV
                <span className="mt-0.5 block text-xs text-zinc-500">Slower; requires internet</span>
              </span>
            </label>
          </Section>

          {error && (
            <p className="rounded-lg border border-red-900 bg-red-950 px-4 py-3 text-sm text-red-400">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-6 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50 sm:w-auto"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Starting scan...
              </>
            ) : (
              <>
                Start scan <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function RelatedLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link href={href} className="text-zinc-400 transition-colors hover:text-emerald-400">
      {children}
    </Link>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
      <h3 className="mb-3 text-sm font-semibold text-zinc-200">{title}</h3>
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
          className="flex-1 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:border-emerald-600 focus:outline-none"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onAdd(); } }}
        />
        <button
          type="button"
          onClick={onAdd}
          className="flex items-center gap-1 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-xs text-zinc-300 transition-colors hover:bg-zinc-700"
        >
          <Plus className="h-3.5 w-3.5" />
          Add
        </button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {items?.map((item, i) => (
            <span key={i} className="flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800 px-2.5 py-1 font-mono text-xs text-zinc-300">
              {item}
              <button type="button" onClick={() => onRemove(i)}>
                <X className="h-3 w-3 text-zinc-500 hover:text-zinc-300" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
