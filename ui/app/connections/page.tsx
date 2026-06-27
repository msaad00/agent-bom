"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Cloud,
  Plus,
  RefreshCcw,
  ShieldCheck,
  Trash2,
  X,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ArrowRight,
  ArrowLeft,
  Boxes,
  Fingerprint,
  KeyRound,
} from "lucide-react";

import {
  api,
  type CloudConnectionRecord,
  type CloudConnectionCreateRequest,
  type CloudConnectionScanResponse,
} from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { EmptyState, ErrorBanner } from "@/components/empty-state";

// ── Provider catalog ──────────────────────────────────────────────────────────
// AWS is broker-enabled today (read-only AssumeRole). Azure / GCP / Snowflake are
// accepted by the store but the credential broker raises a clear "planned" 501,
// so they are surfaced as "coming soon" and disabled in the wizard.

interface ProviderOption {
  value: string;
  label: string;
  enabled: boolean;
  roleLabel: string;
  rolePlaceholder: string;
  secretLabel: string;
  secretHint: string;
}

const PROVIDER_OPTIONS: ProviderOption[] = [
  {
    value: "aws",
    label: "Amazon Web Services",
    enabled: true,
    roleLabel: "Read-only role ARN",
    rolePlaceholder: "arn:aws:iam::123456789012:role/agent-bom-readonly",
    secretLabel: "External ID",
    secretHint: "The ExternalId from the role's trust policy. Stored encrypted, never shown again.",
  },
  {
    value: "azure",
    label: "Microsoft Azure",
    enabled: false,
    roleLabel: "Service principal reference",
    rolePlaceholder: "subscription / app registration",
    secretLabel: "Client secret reference",
    secretHint: "Broker support is planned.",
  },
  {
    value: "gcp",
    label: "Google Cloud",
    enabled: false,
    roleLabel: "Service account",
    rolePlaceholder: "agent-bom@project.iam.gserviceaccount.com",
    secretLabel: "Workload identity reference",
    secretHint: "Broker support is planned.",
  },
  {
    value: "snowflake",
    label: "Snowflake",
    enabled: false,
    roleLabel: "Account / role",
    rolePlaceholder: "org-account / READONLY_ROLE",
    secretLabel: "Key-pair reference",
    secretHint: "Broker support is planned.",
  },
];

function providerLabel(value: string): string {
  return PROVIDER_OPTIONS.find((option) => option.value === value)?.label ?? value.toUpperCase();
}

function formatWhen(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function statusTone(status: string): string {
  switch (status) {
    case "active":
      return "border-emerald-900/60 bg-emerald-950/30 text-emerald-300";
    case "error":
      return "border-red-900/60 bg-red-950/30 text-red-300";
    default:
      return "border-amber-900/60 bg-amber-950/30 text-amber-300";
  }
}

function StatusPill({ status }: { status: string }) {
  const Icon = status === "active" ? CheckCircle2 : status === "error" ? AlertTriangle : Clock;
  const label = status === "active" ? "Active" : status === "error" ? "Error" : "Pending";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${statusTone(status)}`}>
      <Icon className="h-3 w-3" />
      {label}
    </span>
  );
}

function formatPassRate(rate: number | null): string {
  if (rate == null) return "—";
  // pass_rate may be 0–1 or 0–100 depending on the benchmark; normalize to a percent.
  const pct = rate <= 1 ? rate * 100 : rate;
  return `${pct.toFixed(0)}%`;
}

export default function ConnectionsPage() {
  const { hasCapability, session } = useAuthState();
  const canManage = !session?.auth_required || hasCapability("scan.run");

  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, CloudConnectionScanResponse>>({});
  const [scanErrors, setScanErrors] = useState<Record<string, string>>({});

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listCloudConnections();
      setConnections(result.connections);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load cloud connections.");
      setConnections([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleCreated = useCallback(
    (created: CloudConnectionRecord) => {
      setWizardOpen(false);
      setMessage(`Connected ${created.display_name}.`);
      void refresh();
    },
    [refresh],
  );

  async function handleScan(connection: CloudConnectionRecord) {
    setBusyId(connection.id);
    setMessage(null);
    setScanErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const result = await api.scanCloudConnection(connection.id);
      setScanResults((prev) => ({ ...prev, [connection.id]: result }));
      await refresh();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Scan failed.";
      setScanErrors((prev) => ({ ...prev, [connection.id]: detail }));
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(connection: CloudConnectionRecord) {
    setBusyId(connection.id);
    setMessage(null);
    try {
      await api.deleteCloudConnection(connection.id);
      setScanResults((prev) => {
        const next = { ...prev };
        delete next[connection.id];
        return next;
      });
      setMessage(`Removed ${connection.display_name}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete connection.");
    } finally {
      setBusyId(null);
    }
  }

  const activeCount = useMemo(() => connections.filter((c) => c.status === "active").length, [connections]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[linear-gradient(135deg,var(--surface),var(--surface-elevated))] p-6 shadow-2xl shadow-black/10">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-[0.22em] text-emerald-400">Connections plane</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[var(--foreground)]">Cloud accounts</h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-[var(--text-secondary)]">
              Connect a customer cloud account in read-only mode, then launch inventory and CIS
              discovery against a short-lived assumed role. The connection secret is encrypted at
              rest and is never returned to the browser.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => void refresh()}
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              <RefreshCcw className="h-4 w-4" />
              Refresh
            </button>
            <button
              onClick={() => setWizardOpen(true)}
              disabled={!canManage}
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Plus className="h-4 w-4" />
              Add cloud account
            </button>
          </div>
        </div>

        <div className="mt-5 grid gap-3 sm:grid-cols-3">
          <MetricCard icon={Cloud} label="Connections" value={loading ? "…" : String(connections.length)} />
          <MetricCard icon={CheckCircle2} label="Active" value={loading ? "…" : String(activeCount)} />
          <MetricCard icon={Lock} label="Secret storage" value="Encrypted" detail="Write-only external IDs" />
        </div>

        {message ? <p className="mt-4 text-sm text-emerald-400">{message}</p> : null}
        {!canManage ? (
          <p className="mt-3 text-sm text-amber-300">
            Your role can review connections but cannot create, scan, or delete them.
          </p>
        ) : null}
      </section>

      {/* Connections table */}
      <section className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5 shadow-lg shadow-black/5">
        <div className="flex items-start gap-3">
          <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
          </span>
          <div>
            <h2 className="text-base font-semibold text-[var(--foreground)]">Connected accounts</h2>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              Each row is a tenant-scoped, encrypted connection. Run a read-only scan to see live
              inventory counts and CIS pass rate.
            </p>
          </div>
        </div>

        <div className="mt-5">
          {error ? (
            <ErrorBanner message={error} onRetry={() => void refresh()} />
          ) : loading ? (
            <div className="space-y-2" aria-busy="true">
              {[0, 1, 2].map((i) => (
                <div key={i} className="h-14 animate-pulse rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]" />
              ))}
            </div>
          ) : connections.length === 0 ? (
            <EmptyState
              icon={Cloud}
              title="No cloud accounts connected"
              description="Add a read-only AWS account to launch inventory and CIS discovery from the control plane."
            />
          ) : (
            <div className="overflow-x-auto rounded-xl border border-[color:var(--border-subtle)]">
              <table className="w-full min-w-[720px] border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[11px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
                    <th className="px-4 py-3 font-medium">Account</th>
                    <th className="px-4 py-3 font-medium">Provider</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Last scan</th>
                    <th className="px-4 py-3 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.map((connection) => {
                    const isBusy = busyId === connection.id;
                    const result = scanResults[connection.id];
                    const scanError = scanErrors[connection.id];
                    const scannable = connection.provider === "aws";
                    return (
                      <FragmentRow
                        key={connection.id}
                        connection={connection}
                        isBusy={isBusy}
                        canManage={canManage}
                        scannable={scannable}
                        result={result}
                        scanError={scanError}
                        statusDetail={connection.status === "error" ? connection.status_detail : ""}
                        onScan={() => void handleScan(connection)}
                        onDelete={() => void handleDelete(connection)}
                      />
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {wizardOpen ? (
        <AddConnectionWizard onClose={() => setWizardOpen(false)} onCreated={handleCreated} />
      ) : null}
    </div>
  );
}

// ── Table row + inline scan result ────────────────────────────────────────────

function FragmentRow({
  connection,
  isBusy,
  canManage,
  scannable,
  result,
  scanError,
  statusDetail,
  onScan,
  onDelete,
}: {
  connection: CloudConnectionRecord;
  isBusy: boolean;
  canManage: boolean;
  scannable: boolean;
  result: CloudConnectionScanResponse | undefined;
  scanError: string | undefined;
  statusDetail: string;
  onScan: () => void;
  onDelete: () => void;
}) {
  const showDetail = Boolean(result || scanError || statusDetail);
  return (
    <>
      <tr className="border-b border-[color:var(--border-subtle)] last:border-b-0 align-top">
        <td className="px-4 py-3">
          <p className="font-medium text-[var(--foreground)]">{connection.display_name}</p>
          <p className="mt-0.5 break-all font-mono text-[11px] text-[var(--text-tertiary)]">{connection.role_ref}</p>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {connection.has_external_id ? (
              <span className="inline-flex items-center gap-1 rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]">
                <Lock className="h-2.5 w-2.5" /> Secret configured
              </span>
            ) : null}
            {connection.regions.slice(0, 3).map((region) => (
              <span key={region} className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">
                {region}
              </span>
            ))}
            {connection.regions.length > 3 ? (
              <span className="text-[10px] text-[var(--text-tertiary)]">+{connection.regions.length - 3}</span>
            ) : null}
          </div>
        </td>
        <td className="px-4 py-3 text-[var(--text-secondary)]">{providerLabel(connection.provider)}</td>
        <td className="px-4 py-3"><StatusPill status={connection.status} /></td>
        <td className="px-4 py-3 text-[var(--text-secondary)]">{formatWhen(connection.last_scan_at)}</td>
        <td className="px-4 py-3">
          <div className="flex justify-end gap-2">
            <button
              onClick={onScan}
              disabled={isBusy || !canManage || !scannable}
              title={scannable ? "Run a read-only scan" : "Scanning for this provider is planned"}
              className="rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isBusy ? "Scanning…" : "Scan now"}
            </button>
            <button
              onClick={onDelete}
              disabled={isBusy || !canManage}
              aria-label={`Delete ${connection.display_name}`}
              className="inline-flex items-center gap-1 rounded-lg border border-red-900/60 bg-red-950/20 px-3 py-1.5 text-xs font-medium text-red-300 transition hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Delete
            </button>
          </div>
        </td>
      </tr>
      {showDetail ? (
        <tr className="border-b border-[color:var(--border-subtle)] last:border-b-0 bg-[color:var(--surface-elevated)]/40">
          <td colSpan={5} className="px-4 pb-4 pt-0">
            {result ? <ScanResultPanel result={result} /> : null}
            {!result && scanError ? (
              <div className="rounded-xl border border-red-900/60 bg-red-950/20 p-3 text-xs text-red-300">
                {scanError}
              </div>
            ) : null}
            {!result && !scanError && statusDetail ? (
              <div className="rounded-xl border border-amber-900/60 bg-amber-950/20 p-3 text-xs text-amber-200">
                {statusDetail}
              </div>
            ) : null}
          </td>
        </tr>
      ) : null}
    </>
  );
}

function ScanResultPanel({ result }: { result: CloudConnectionScanResponse }) {
  const { inventory, cis_benchmark: cis } = result;
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="inline-flex items-center gap-2 text-xs font-semibold text-[var(--foreground)]">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          Read-only scan complete
        </p>
        <span className="font-mono text-[10px] text-[var(--text-tertiary)]">scan {result.scan_id.slice(0, 8)}</span>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile icon={Boxes} label="Resources" value={String(inventory.resource_count)} />
        <StatTile icon={Fingerprint} label="Identities" value={String(inventory.identity_count)} />
        <StatTile
          icon={CheckCircle2}
          label="CIS passed"
          value={cis.passed == null ? "—" : `${cis.passed}/${cis.total ?? "—"}`}
        />
        <StatTile icon={KeyRound} label="CIS pass rate" value={formatPassRate(cis.pass_rate)} />
      </div>
      {inventory.warnings.length > 0 ? (
        <p className="mt-3 text-[11px] leading-5 text-amber-300">{inventory.warnings.join(" · ")}</p>
      ) : null}
      <p className="mt-3 text-[11px] leading-5 text-[var(--text-tertiary)]">{result.audit_metadata.note}</p>
    </div>
  );
}

function StatTile({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3">
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
        <Icon className="h-3.5 w-3.5 text-emerald-400" />
        {label}
      </div>
      <p className="mt-1.5 text-lg font-semibold text-[var(--foreground)]">{value}</p>
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
  detail?: string;
}) {
  return (
    <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
      <div className="flex items-center gap-3">
        <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2">
          <Icon className="h-4 w-4 text-emerald-400" />
        </span>
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{label}</p>
          <p className="mt-1 text-lg font-semibold text-[var(--foreground)]">{value}</p>
        </div>
      </div>
      {detail ? <p className="mt-2 text-xs leading-5 text-[var(--text-secondary)]">{detail}</p> : null}
    </div>
  );
}

// ── Add connection wizard ─────────────────────────────────────────────────────

interface WizardForm {
  provider: string;
  display_name: string;
  role_ref: string;
  external_id: string;
  regions: string;
}

const DEFAULT_WIZARD_FORM: WizardForm = {
  provider: "aws",
  display_name: "",
  role_ref: "",
  external_id: "",
  regions: "",
};

function AddConnectionWizard({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (created: CloudConnectionRecord) => void;
}) {
  const [step, setStep] = useState<0 | 1 | 2>(0);
  const [form, setForm] = useState<WizardForm>(DEFAULT_WIZARD_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const provider = useMemo(
    () => PROVIDER_OPTIONS.find((option) => option.value === form.provider) ?? PROVIDER_OPTIONS[0]!,
    [form.provider],
  );

  function update<K extends keyof WizardForm>(field: K, value: WizardForm[K]) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    const displayName = form.display_name.trim();
    const roleRef = form.role_ref.trim();
    const externalId = form.external_id;
    const regions = form.regions
      .split(/[\s,]+/)
      .map((region) => region.trim())
      .filter(Boolean);

    if (!displayName) {
      setFormError("A display name is required.");
      return;
    }
    if (!roleRef) {
      setFormError(`${provider.roleLabel} is required.`);
      return;
    }
    if (!externalId.trim()) {
      setFormError(`${provider.secretLabel} is required.`);
      return;
    }

    const payload: CloudConnectionCreateRequest = {
      provider: form.provider,
      display_name: displayName,
      role_ref: roleRef,
      external_id: externalId,
      regions,
    };

    setSubmitting(true);
    try {
      const created = await api.createCloudConnection(payload);
      // Drop the plaintext secret from component state immediately on success.
      setForm((current) => ({ ...current, external_id: "" }));
      onCreated(created);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to create connection.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-[80] flex items-start justify-center overflow-y-auto bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Add cloud account"
      onClick={onClose}
    >
      <div
        className="my-8 w-full max-w-xl rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] shadow-2xl shadow-black/40"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-[color:var(--border-subtle)] px-5 py-4">
          <div className="flex items-center gap-3">
            <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2">
              <Cloud className="h-5 w-5 text-emerald-400" />
            </span>
            <div>
              <h2 className="text-base font-semibold text-[var(--foreground)]">Add cloud account</h2>
              <p className="text-xs text-[var(--text-secondary)]">Read-only connection · step {step + 1} of 3</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg p-1.5 text-[var(--text-secondary)] transition hover:bg-[color:var(--surface-elevated)] hover:text-[var(--foreground)]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="space-y-5 px-5 py-5">
            <StepIndicator step={step} />

            {step === 0 ? (
              <fieldset className="space-y-3">
                <legend className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Choose a provider</legend>
                <div className="grid gap-2 sm:grid-cols-2">
                  {PROVIDER_OPTIONS.map((option) => {
                    const selected = form.provider === option.value;
                    return (
                      <button
                        type="button"
                        key={option.value}
                        disabled={!option.enabled}
                        onClick={() => update("provider", option.value)}
                        aria-pressed={selected}
                        className={`rounded-xl border p-3 text-left transition ${
                          selected
                            ? "border-emerald-500 bg-emerald-950/20"
                            : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] hover:border-[color:var(--border-strong)]"
                        } ${option.enabled ? "" : "cursor-not-allowed opacity-60"}`}
                      >
                        <p className="text-sm font-medium text-[var(--foreground)]">{option.label}</p>
                        <p className="mt-1 text-[11px] text-[var(--text-secondary)]">
                          {option.enabled ? "Read-only AssumeRole" : "Coming soon"}
                        </p>
                      </button>
                    );
                  })}
                </div>
              </fieldset>
            ) : null}

            {step === 1 ? (
              <div className="space-y-3">
                <p className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Read-only setup</p>
                <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-xs leading-6 text-[var(--text-secondary)]">
                  <p className="text-[var(--foreground)]">Create a read-only role agent-bom can assume:</p>
                  <ol className="mt-2 list-decimal space-y-1.5 pl-4">
                    <li>Create an IAM role with a trust policy that allows the agent-bom control plane to assume it.</li>
                    <li>Require an <code className="rounded bg-[color:var(--surface)] px-1">ExternalId</code> on the trust policy and keep it secret.</li>
                    <li>Attach AWS-managed <code className="rounded bg-[color:var(--surface)] px-1">ReadOnlyAccess</code> (or <code className="rounded bg-[color:var(--surface)] px-1">SecurityAudit</code>).</li>
                    <li>Copy the role ARN and the ExternalId into the next step.</li>
                  </ol>
                  <p className="mt-3 inline-flex items-center gap-1.5 text-emerald-300">
                    <Lock className="h-3.5 w-3.5" /> The ExternalId is stored encrypted and never displayed again.
                  </p>
                </div>
              </div>
            ) : null}

            {step === 2 ? (
              <div className="space-y-4">
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Display name</span>
                  <input
                    value={form.display_name}
                    onChange={(event) => update("display_name", event.target.value)}
                    placeholder="Production account"
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  />
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{provider.roleLabel}</span>
                  <input
                    value={form.role_ref}
                    onChange={(event) => update("role_ref", event.target.value)}
                    placeholder={provider.rolePlaceholder}
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  />
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{provider.secretLabel}</span>
                  <input
                    type="password"
                    autoComplete="off"
                    value={form.external_id}
                    onChange={(event) => update("external_id", event.target.value)}
                    placeholder="••••••••••••"
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  />
                  <span className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] text-[var(--text-tertiary)]">
                    <Lock className="h-3 w-3" /> {provider.secretHint}
                  </span>
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Regions (optional)</span>
                  <input
                    value={form.regions}
                    onChange={(event) => update("regions", event.target.value)}
                    placeholder="us-east-1, us-west-2"
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  />
                </label>
              </div>
            ) : null}

            {formError ? <p className="text-sm text-red-400">{formError}</p> : null}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-[color:var(--border-subtle)] px-5 py-4">
            <button
              type="button"
              onClick={() => (step === 0 ? onClose() : setStep((s) => (s - 1) as 0 | 1 | 2))}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              {step === 0 ? "Cancel" : <><ArrowLeft className="h-4 w-4" /> Back</>}
            </button>
            {step < 2 ? (
              <button
                key="wizard-next"
                type="button"
                onClick={() => setStep((s) => (s + 1) as 0 | 1 | 2)}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400"
              >
                Next <ArrowRight className="h-4 w-4" />
              </button>
            ) : (
              <button
                key="wizard-submit"
                type="submit"
                disabled={submitting}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {submitting ? "Connecting…" : "Create connection"}
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}

function StepIndicator({ step }: { step: number }) {
  const labels = ["Provider", "Setup", "Details"];
  return (
    <div className="flex items-center gap-2">
      {labels.map((label, index) => (
        <div key={label} className="flex flex-1 items-center gap-2">
          <span
            className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold ${
              index <= step
                ? "border-emerald-500 bg-emerald-500 text-black"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[var(--text-tertiary)]"
            }`}
          >
            {index + 1}
          </span>
          <span className={`text-xs ${index <= step ? "text-[var(--foreground)]" : "text-[var(--text-tertiary)]"}`}>{label}</span>
          {index < labels.length - 1 ? <span className="h-px flex-1 bg-[color:var(--border-subtle)]" /> : null}
        </div>
      ))}
    </div>
  );
}
