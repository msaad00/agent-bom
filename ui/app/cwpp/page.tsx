"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  CheckCircle2,
  CircleSlash,
  Disc3,
  HardDrive,
  Loader2,
  Play,
  RefreshCw,
  ShieldAlert,
  Terminal,
  XCircle,
} from "lucide-react";

import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { PaginationBar } from "@/components/pagination-bar";
import { useAuthState } from "@/components/auth-provider";
import {
  api,
  type SideScanExecutionRecord,
  type SideScanListResponse,
  type SideScanProviderCapability,
  type SideScanTriggerRequest,
} from "@/lib/api";
import { securityGraphHref } from "@/lib/page-links";

const EXECUTION_PAGE_SIZE = 25;

// Terminal execution states that never imply a clean workload — mirrors the
// honest lifecycle statuses (queued/running/scan_complete/partial/failed/…).
function statusTone(status: string): { label: string; className: string; icon: typeof CheckCircle2 } {
  switch (status) {
    case "scan_complete":
      return { label: "Scan complete", className: "text-emerald-500", icon: CheckCircle2 };
    case "partial":
      return { label: "Partial", className: "text-amber-500", icon: ShieldAlert };
    case "running":
      return { label: "Running", className: "text-blue-500", icon: Loader2 };
    case "queued":
      return { label: "Queued", className: "text-[color:var(--text-tertiary)]", icon: Loader2 };
    case "failed":
      return { label: "Failed", className: "text-red-500", icon: XCircle };
    case "disabled":
      return { label: "Disabled", className: "text-[color:var(--text-tertiary)]", icon: CircleSlash };
    case "denied":
      return { label: "Denied", className: "text-red-500", icon: CircleSlash };
    case "unavailable":
      return { label: "Unavailable", className: "text-amber-500", icon: ShieldAlert };
    default:
      return { label: status || "Unknown", className: "text-[color:var(--text-secondary)]", icon: Disc3 };
  }
}

function cleanupTone(status: string): { label: string; className: string } {
  switch (status) {
    case "complete":
      return { label: "Cleaned up", className: "text-emerald-500" };
    case "partial":
      return { label: "Partial cleanup", className: "text-amber-500" };
    case "not_started":
      return { label: "Not started", className: "text-[color:var(--text-tertiary)]" };
    default:
      return { label: status.replace(/_/g, " "), className: "text-[color:var(--text-secondary)]" };
  }
}

function shortTarget(target: string): string {
  const trimmed = target.replace(/\/+$/, "");
  const tail = trimmed.split("/").pop() ?? trimmed;
  return tail || target;
}

function CapabilityCard({ cap }: { cap: SideScanProviderCapability }) {
  const rows: { label: string; ok: boolean; note?: string | undefined }[] = [
    { label: "Target discovery", ok: cap.target_discovery },
    { label: "Lifecycle contract", ok: cap.lifecycle_contract },
    { label: "CLI executor", ok: cap.cli_available },
    { label: "Credentialed smoke", ok: cap.credentialed_smoke, note: cap.credentialed_smoke ? undefined : "not yet proven" },
  ];
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold uppercase tracking-wide text-[color:var(--foreground)]">{cap.provider}</span>
        <span className="rounded-md bg-[color:var(--surface-muted)] px-2 py-0.5 text-[11px] font-medium text-[color:var(--text-secondary)]">
          {cap.executor}
        </span>
      </div>
      <dl className="mt-3 space-y-1.5">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between text-xs">
            <dt className="text-[color:var(--text-secondary)]">{row.label}</dt>
            <dd className={`inline-flex items-center gap-1 font-medium ${row.ok ? "text-emerald-500" : "text-[color:var(--text-tertiary)]"}`}>
              {row.ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : <CircleSlash className="h-3.5 w-3.5" />}
              {row.ok ? "yes" : row.note ?? "no"}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function ExecutionRow({ record }: { record: SideScanExecutionRecord }) {
  const tone = statusTone(record.status);
  const cleanup = cleanupTone(record.cleanup_status);
  const StatusIcon = tone.icon;
  const spinning = record.status === "running" || record.status === "queued";
  return (
    <tr data-testid="cwpp-execution-row" className="border-t border-[color:var(--border-subtle)] hover:bg-[color:var(--surface-muted)]">
      <td className="px-3 py-2 align-top">
        <span className={`inline-flex items-center gap-1.5 text-sm font-medium ${tone.className}`}>
          <StatusIcon className={`h-4 w-4 ${spinning ? "animate-spin" : ""}`} />
          {tone.label}
        </span>
      </td>
      <td className="px-3 py-2 align-top text-sm uppercase text-[color:var(--text-secondary)]">{record.provider}</td>
      <td className="px-3 py-2 align-top">
        <span className="font-mono text-xs text-[color:var(--foreground)]" title={record.target_id}>
          {shortTarget(record.target_id)}
        </span>
        <div className="font-mono text-[11px] text-[color:var(--text-tertiary)]">{record.account_id}</div>
      </td>
      <td className="px-3 py-2 align-top text-right tabular-nums text-sm text-[color:var(--foreground)]">{record.counts.package_count}</td>
      <td className="px-3 py-2 align-top text-right tabular-nums text-sm text-[color:var(--foreground)]">{record.counts.vulnerability_count}</td>
      <td className="px-3 py-2 align-top text-right tabular-nums text-sm text-[color:var(--foreground)]">{record.counts.secret_count}</td>
      <td className="px-3 py-2 align-top">
        <span className={`text-xs font-medium ${cleanup.className}`}>{cleanup.label}</span>
      </td>
    </tr>
  );
}

const EMPTY_FORM: SideScanTriggerRequest = {
  provider: "gcp",
  target_id: "",
  account_id: "",
  location: "",
  collector_id: "",
  collector_resource_group: "",
};

function fieldClass(): string {
  return "w-full rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1.5 text-sm text-[color:var(--foreground)] placeholder:text-[color:var(--text-tertiary)] focus:border-[color:var(--accent)] focus:outline-none";
}

export default function CwppSideScanPage() {
  const { hasCapability } = useAuthState();
  const canRun = hasCapability("scan.run");
  const [data, setData] = useState<SideScanListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<SideScanTriggerRequest>(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [triggerNote, setTriggerNote] = useState<{ tone: "ok" | "warn" | "err"; text: string } | null>(null);
  const [executionPage, setExecutionPage] = useState(1);
  const [executionProvider, setExecutionProvider] = useState("all");
  const [executionStatus, setExecutionStatus] = useState("all");
  const [executionQuery, setExecutionQuery] = useState("");
  const [debouncedExecutionQuery, setDebouncedExecutionQuery] = useState("");
  const requestIdentity = useRef(0);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedExecutionQuery(executionQuery);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [executionQuery]);

  useEffect(
    () => () => {
      requestIdentity.current += 1;
    },
    [],
  );

  const load = useCallback(async () => {
    const requestId = ++requestIdentity.current;
    setLoading(true);
    setError(null);
    try {
      const resp = await api.listSideScans({
        limit: EXECUTION_PAGE_SIZE,
        offset: (executionPage - 1) * EXECUTION_PAGE_SIZE,
        ...(executionProvider !== "all" ? { provider: executionProvider as "aws" | "azure" | "gcp" } : {}),
        ...(executionStatus !== "all" ? { status: executionStatus } : {}),
        ...(debouncedExecutionQuery.trim() ? { query: debouncedExecutionQuery.trim() } : {}),
      });
      if (requestId !== requestIdentity.current) return;
      setData(resp);
    } catch (err) {
      if (requestId !== requestIdentity.current) return;
      setError(err instanceof Error ? err.message : "Failed to load side-scan executions.");
    } finally {
      if (requestId === requestIdentity.current) setLoading(false);
    }
  }, [debouncedExecutionQuery, executionPage, executionProvider, executionStatus]);

  useEffect(() => {
    void load();
  }, [load]);

  const cliSnippet = useMemo(() => {
    const p = form.provider;
    const rg = p === "azure" && form.collector_resource_group ? ` \\\n    --collector-resource-group ${form.collector_resource_group}` : "";
    return [
      `AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan --provider ${p} \\`,
      `    --volume-id ${form.target_id || "<disk-id>"} --account-id ${form.account_id || "<account>"} \\`,
      `    --collector-instance-id ${form.collector_id || "<collector>"} --availability-zone ${form.location || "<zone>"}${rg}`,
    ].join("\n");
  }, [form]);

  const onSubmit = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      setSubmitting(true);
      setTriggerNote(null);
      try {
        const body: SideScanTriggerRequest = {
          provider: form.provider,
          target_id: form.target_id.trim(),
          account_id: form.account_id.trim(),
          location: form.location.trim(),
          collector_id: form.collector_id.trim(),
          ...(form.provider === "azure" && form.collector_resource_group
            ? { collector_resource_group: form.collector_resource_group.trim() }
            : {}),
        };
        const resp = await api.triggerSideScan(body);
        if (resp.status === "disabled") {
          setTriggerNote({ tone: "warn", text: resp.enable ?? "Side-scan is disabled (AGENT_BOM_SIDESCAN unset)." });
        } else if (resp.status === "unavailable") {
          setTriggerNote({ tone: "warn", text: resp.reason ?? "Provider executor unavailable (extra or credentials missing)." });
        } else {
          setTriggerNote({ tone: "ok", text: `Execution ${resp.execution_id.slice(0, 12)}… → ${statusTone(resp.status).label}.` });
        }
        await load();
      } catch (err) {
        setTriggerNote({ tone: "err", text: err instanceof Error ? err.message : "Side-scan trigger failed." });
      } finally {
        setSubmitting(false);
      }
    },
    [form, load],
  );

  const executions = data?.executions ?? [];
  const executionStatuses = ["queued", "running", "scan_complete", "partial", "disabled", "denied", "failed"];
  const executionTotalItems = data?.page?.total ?? executions.length;
  const executionTotalPages = Math.max(1, Math.ceil(executionTotalItems / EXECUTION_PAGE_SIZE));

  if (loading && !data) {
    return <PageLoadingState title="Loading CWPP side-scans" detail="Reading recent agentless disk side-scan executions and provider capabilities." data-testid="cwpp-loading" />;
  }
  if (error) {
    return (
      <PageErrorState
        title="Could not load side-scans"
        detail={error}
        action={{ label: "Retry", onClick: () => void load() }}
      />
    );
  }

  const capabilities = data?.capabilities ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 border-b border-[color:var(--border-subtle)] pb-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">
            <HardDrive className="h-6 w-6 text-[color:var(--accent)]" /> CWPP side-scan
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-[color:var(--text-secondary)]">
            Agentless disk side-scan for Azure Managed Disk and GCP Persistent Disk. Each run snapshots the target
            disk, mounts a temp copy on an in-account collector read-only, records SBOM + CVE + redacted secret
            metadata, and tears every owned temporary resource down. No block data leaves the account, and a zero-finding
            run is never a clean-workload claim.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href={securityGraphHref()}
            className="inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border-subtle)] px-2.5 py-1.5 text-sm text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
          >
            <Disc3 className="h-4 w-4" /> Workload graph
          </Link>
          <button
            type="button"
            onClick={() => void load()}
            className="inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border-subtle)] px-2.5 py-1.5 text-sm text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
          >
            <RefreshCw className="h-4 w-4" /> Refresh
          </button>
        </div>
      </div>

      {/* Provider executor capabilities — honest surface, credentialed smoke stays false. */}
      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-[color:var(--text-secondary)]">Executor capabilities</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {capabilities.map((cap) => (
            <CapabilityCard key={cap.provider} cap={cap} />
          ))}
        </div>
        <p className="mt-2 text-xs text-[color:var(--text-tertiary)]">
          No live credentialed smoke is claimed for any provider yet (credentialed_smoke=false). AWS EBS keeps its own
          CLI entrypoint and is not persisted to this lifecycle store.
        </p>
      </section>

      {/* Trigger — in-product action + headless (CLI) parity side by side. */}
      <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <form onSubmit={onSubmit} className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
            <Play className="h-4 w-4 text-[color:var(--accent)]" /> Run a side-scan
          </h2>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <label className="text-xs text-[color:var(--text-secondary)]">
              Provider
              <select
                value={form.provider}
                onChange={(e) => setForm((f) => ({ ...f, provider: e.target.value as "azure" | "gcp" }))}
                className={`mt-1 ${fieldClass()}`}
                aria-label="Provider"
              >
                <option value="gcp">gcp</option>
                <option value="azure">azure</option>
              </select>
            </label>
            <label className="text-xs text-[color:var(--text-secondary)]">
              Account id (subscription / project)
              <input className={`mt-1 ${fieldClass()}`} value={form.account_id} onChange={(e) => setForm((f) => ({ ...f, account_id: e.target.value }))} placeholder="proj / SUB" />
            </label>
            <label className="text-xs text-[color:var(--text-secondary)] sm:col-span-2">
              Disk resource id
              <input className={`mt-1 ${fieldClass()}`} value={form.target_id} onChange={(e) => setForm((f) => ({ ...f, target_id: e.target.value }))} placeholder="projects/…/disks/os" />
            </label>
            <label className="text-xs text-[color:var(--text-secondary)]">
              Location / zone
              <input className={`mt-1 ${fieldClass()}`} value={form.location} onChange={(e) => setForm((f) => ({ ...f, location: e.target.value }))} placeholder="us-central1-a" />
            </label>
            <label className="text-xs text-[color:var(--text-secondary)]">
              Collector instance id
              <input className={`mt-1 ${fieldClass()}`} value={form.collector_id} onChange={(e) => setForm((f) => ({ ...f, collector_id: e.target.value }))} placeholder="collector-vm" />
            </label>
            {form.provider === "azure" && (
              <label className="text-xs text-[color:var(--text-secondary)] sm:col-span-2">
                Collector resource group (Azure)
                <input className={`mt-1 ${fieldClass()}`} value={form.collector_resource_group ?? ""} onChange={(e) => setForm((f) => ({ ...f, collector_resource_group: e.target.value }))} placeholder="collectors" />
              </label>
            )}
          </div>
          <p className="mt-2 text-[11px] text-[color:var(--text-tertiary)]">
            Runs through the stored, in-account collector — never a per-action credential. Requires an admin operator.
          </p>
          <div className="mt-3 flex items-center gap-3">
            <button
              type="submit"
              disabled={submitting || !canRun || !form.target_id || !form.account_id || !form.location || !form.collector_id}
              className="inline-flex items-center gap-1.5 rounded-md bg-[color:var(--accent)] px-3 py-1.5 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
            >
              {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Run side-scan
            </button>
            {!canRun && <span className="text-xs text-[color:var(--text-tertiary)]">Admin role required to run.</span>}
          </div>
          {triggerNote && (
            <p
              className={`mt-2 text-xs ${
                triggerNote.tone === "ok" ? "text-emerald-500" : triggerNote.tone === "warn" ? "text-amber-500" : "text-red-500"
              }`}
              role="status"
            >
              {triggerNote.text}
            </p>
          )}
        </form>

        <div className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
            <Terminal className="h-4 w-4 text-[color:var(--text-secondary)]" /> Headless equivalent (CLI)
          </h2>
          <p className="mt-1 text-xs text-[color:var(--text-secondary)]">The same executor for agents / CI — mirrors the form above.</p>
          <pre className="mt-2 overflow-x-auto rounded-md bg-[color:var(--surface)] p-3 font-mono text-[11px] leading-5 text-[color:var(--foreground)]">{cliSnippet}</pre>
        </div>
      </section>

      {/* Recent executions. */}
      <section>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <h2 className="mr-auto text-sm font-semibold uppercase tracking-wide text-[color:var(--text-secondary)]">Recent executions</h2>
          <label className="sr-only" htmlFor="cwpp-provider-filter">Filter executions by provider</label>
          <select
            id="cwpp-provider-filter"
            aria-label="Filter executions by provider"
            value={executionProvider}
            onChange={(event) => {
              setExecutionProvider(event.target.value);
              setExecutionPage(1);
            }}
            className="h-8 rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 text-xs text-[color:var(--foreground)]"
          >
            <option value="all">All providers</option>
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
            <option value="gcp">GCP</option>
          </select>
          <label className="sr-only" htmlFor="cwpp-status-filter">Filter executions by status</label>
          <select
            id="cwpp-status-filter"
            aria-label="Filter executions by status"
            value={executionStatus}
            onChange={(event) => {
              setExecutionStatus(event.target.value);
              setExecutionPage(1);
            }}
            className="h-8 rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 text-xs text-[color:var(--foreground)]"
          >
            <option value="all">All statuses</option>
            {executionStatuses.map((status) => <option key={status} value={status}>{statusTone(status).label}</option>)}
          </select>
          <input
            value={executionQuery}
            onChange={(event) => {
              setExecutionQuery(event.target.value);
              setExecutionPage(1);
            }}
            aria-label="Filter executions by target or account"
            placeholder="Target or account"
            className="h-8 w-44 rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 text-xs text-[color:var(--foreground)] placeholder:text-[color:var(--text-tertiary)]"
          />
        </div>
        {executions.length === 0 ? (
          <PageEmptyState
            icon={Disc3}
            title="No side-scan executions yet"
            detail="Trigger an Azure or GCP disk side-scan above, or run the CLI equivalent. Executions appear here with honest status and cleanup state."
          />
        ) : (
          <div className="overflow-x-auto rounded-xl border border-[color:var(--border-subtle)]">
            <table className="w-full text-left">
              <thead>
                <tr className="text-xs uppercase tracking-wide text-[color:var(--text-tertiary)]">
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Provider</th>
                  <th className="px-3 py-2 font-medium">Disk / account</th>
                  <th className="px-3 py-2 text-right font-medium">Packages</th>
                  <th className="px-3 py-2 text-right font-medium">Vulns</th>
                  <th className="px-3 py-2 text-right font-medium">Secrets</th>
                  <th className="px-3 py-2 font-medium">Cleanup</th>
                </tr>
              </thead>
              <tbody>
                {executions.map((record) => (
                  <ExecutionRow key={record.execution_id} record={record} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {executionTotalItems > 0 ? (
          <PaginationBar
            className="mt-3"
            page={executionPage}
            totalPages={executionTotalPages}
            totalItems={executionTotalItems}
            itemLabel="executions"
            onPrevious={() => setExecutionPage((current) => Math.max(1, current - 1))}
            onNext={() => setExecutionPage((current) => Math.min(executionTotalPages, current + 1))}
          />
        ) : null}
      </section>
    </div>
  );
}
