"use client";

import { useEffect, useMemo, useState } from "react";
import {
  api,
  type ApiKeyRecord,
  type AuthPolicyResponse,
  type CreateApiKeyRequest,
  type RotateApiKeyRequest,
  type TenantQuotaUpdateRequest,
  formatDate,
} from "@/lib/api";
import {
  CheckCircle2,
  Copy,
  KeyRound,
  Loader2,
  Plus,
  RefreshCw,
  RotateCw,
  ShieldAlert,
  ShieldOff,
} from "lucide-react";

function formatSeconds(value: number): string {
  if (value < 60) return `${value}s`;
  if (value < 3600) return `${Math.floor(value / 60)}m`;
  if (value < 86400) return `${Math.floor(value / 3600)}h`;
  return `${Math.floor(value / 86400)}d`;
}

function toIsoOrNull(value: string): string | null {
  if (!value.trim()) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error("Expiration must be a valid date/time");
  }
  return parsed.toISOString();
}

function keyStateTone(state: ApiKeyRecord["state"]): string {
  switch (state) {
    case "active":
      return "border-emerald-900/60 bg-emerald-950/30 text-emerald-300";
    case "rotation_overlap":
      return "border-sky-900/60 bg-sky-950/30 text-sky-300";
    case "rotated":
      return "border-amber-900/60 bg-amber-950/30 text-amber-300";
    case "revoked":
      return "border-red-900/60 bg-red-950/30 text-red-300";
    case "expired":
    default:
      return "border-zinc-800 bg-zinc-900 text-zinc-400";
  }
}

function stateLabel(state: ApiKeyRecord["state"]): string {
  switch (state) {
    case "rotation_overlap":
      return "Rotation overlap";
    default:
      return state[0].toUpperCase() + state.slice(1);
  }
}

type TenantQuotaUsageEntry =
  AuthPolicyResponse["tenant_quota_runtime"]["usage"][keyof AuthPolicyResponse["tenant_quota_runtime"]["usage"]];
type QuotaKey = keyof AuthPolicyResponse["tenant_quota_runtime"]["usage"];
type QuotaCard = {
  field: QuotaKey;
  label: string;
  value: TenantQuotaUsageEntry;
};
type QuotaForm = Record<QuotaKey, string>;

function isSessionKey(key: ApiKeyRecord): boolean {
  return key.name.startsWith("saml:") || key.scopes.includes("saml-session");
}

function formatModeLabel(value: string): string {
  const acronyms: Record<string, string> = {
    oidc: "OIDC",
    api: "API",
    ui: "UI",
  };
  return value
    .split("_")
    .filter(Boolean)
    .map((segment) => acronyms[segment] ?? (segment[0].toUpperCase() + segment.slice(1)))
    .join(" ");
}

function modeTone(value: string): string {
  switch (value) {
    case "reverse_proxy_oidc":
    case "trusted_proxy":
      return "border-emerald-900/60 bg-emerald-950/30 text-emerald-300";
    case "oidc_bearer":
      return "border-sky-900/60 bg-sky-950/30 text-sky-300";
    case "session_api_key":
    case "api_key":
      return "border-amber-900/60 bg-amber-950/30 text-amber-300";
    case "no_auth":
    default:
      return "border-zinc-800 bg-zinc-900 text-zinc-400";
  }
}

function quotaInputValue(value: number | null | undefined): string {
  return value == null ? "" : String(value);
}

function formatStatusLabel(value: string): string {
  return value.replaceAll("_", " ");
}

function formatCadence(rotationDays: number | null, maxAgeDays: number | null): string | null {
  const parts = [];
  if (rotationDays != null) parts.push(`rotate ${rotationDays}d`);
  if (maxAgeDays != null) parts.push(`max ${maxAgeDays}d`);
  return parts.length ? parts.join(" · ") : null;
}

function formatRotationDetail(posture: {
  rotation_status: string;
  rotation_method: string;
  last_rotated: string | null;
  age_days: number | null;
  rotation_days: number | null;
  max_age_days: number | null;
}): string {
  return [
    formatStatusLabel(posture.rotation_status),
    posture.last_rotated ? `rotated ${formatDate(posture.last_rotated)}` : "timestamp unset",
    posture.age_days != null ? `${posture.age_days}d old` : null,
    formatCadence(posture.rotation_days, posture.max_age_days),
    posture.rotation_method.replaceAll("_", " "),
  ]
    .filter(Boolean)
    .join(" · ");
}

function formatRateLimitRotationDetail(rateLimit: AuthPolicyResponse["rate_limit_key"]): string {
  return [
    formatStatusLabel(rateLimit.status),
    rateLimit.last_rotated ? `rotated ${formatDate(rateLimit.last_rotated)}` : "timestamp unset",
    rateLimit.age_days != null ? `${rateLimit.age_days}d old` : null,
    formatCadence(rateLimit.rotation_days ?? null, rateLimit.max_age_days ?? null),
    rateLimit.fallback_source ? `fallback ${rateLimit.fallback_source}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function KeyLifecyclePanel({
  loading,
  error,
  policy,
  keys,
  onRefresh,
  roleLabel,
}: {
  loading: boolean;
  error: string | null;
  policy: AuthPolicyResponse | null;
  keys: ApiKeyRecord[];
  onRefresh: () => Promise<void> | void;
  roleLabel?: string | null;
}) {
  const [busyKeyId, setBusyKeyId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<"create" | "rotate" | "revoke" | "quota" | null>(null);
  const [copied, setCopied] = useState(false);
  const [issuedSecret, setIssuedSecret] = useState<{
    title: string;
    rawKey: string;
    detail: string;
  } | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [rotationTarget, setRotationTarget] = useState<ApiKeyRecord | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const [createForm, setCreateForm] = useState({
    name: "",
    role: "viewer",
    expiresAt: "",
  });
  const [rotateForm, setRotateForm] = useState({
    name: "",
    expiresAt: "",
    overlapSeconds: "",
  });
  const [quotaForm, setQuotaForm] = useState<QuotaForm>({
    active_scan_jobs: "",
    retained_scan_jobs: "",
    fleet_agents: "",
    schedules: "",
  });

  const stateCounts = useMemo(() => {
    return keys.reduce<Record<string, number>>((acc, key) => {
      acc[key.state] = (acc[key.state] || 0) + 1;
      return acc;
    }, {});
  }, [keys]);

  const quotaCards = useMemo<QuotaCard[]>(() => {
    if (!policy) return [];
    return [
      { field: "active_scan_jobs", label: "Active scan jobs", value: policy.tenant_quota_runtime.usage.active_scan_jobs },
      { field: "retained_scan_jobs", label: "Retained scan jobs", value: policy.tenant_quota_runtime.usage.retained_scan_jobs },
      { field: "fleet_agents", label: "Fleet agents", value: policy.tenant_quota_runtime.usage.fleet_agents },
      { field: "schedules", label: "Schedules", value: policy.tenant_quota_runtime.usage.schedules },
    ];
  }, [policy]);

  useEffect(() => {
    if (!policy) return;
    setQuotaForm({
      active_scan_jobs: quotaInputValue(policy.tenant_quota_runtime.usage.active_scan_jobs.override_limit),
      retained_scan_jobs: quotaInputValue(policy.tenant_quota_runtime.usage.retained_scan_jobs.override_limit),
      fleet_agents: quotaInputValue(policy.tenant_quota_runtime.usage.fleet_agents.override_limit),
      schedules: quotaInputValue(policy.tenant_quota_runtime.usage.schedules.override_limit),
    });
  }, [policy]);

  async function copyIssuedSecret() {
    if (!issuedSecret?.rawKey) return;
    await navigator.clipboard.writeText(issuedSecret.rawKey);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  async function handleCreateSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusyAction("create");
    setFormError(null);
    try {
      const body: CreateApiKeyRequest = {
        name: createForm.name.trim(),
        role: createForm.role,
        expires_at: toIsoOrNull(createForm.expiresAt),
      };
      const created = await api.createKey(body);
      setIssuedSecret({
        title: `Created key ${created.name}`,
        rawKey: created.raw_key,
        detail: created.message,
      });
      setCreateOpen(false);
      setCreateForm({ name: "", role: "viewer", expiresAt: "" });
      await onRefresh();
    } catch (nextError) {
      setFormError(nextError instanceof Error ? nextError.message : "Failed to create API key");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRotateSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!rotationTarget) return;
    setBusyAction("rotate");
    setBusyKeyId(rotationTarget.key_id);
    setFormError(null);
    try {
      const overlap = rotateForm.overlapSeconds.trim();
      const body: RotateApiKeyRequest = {
        name: rotateForm.name.trim() || undefined,
        expires_at: toIsoOrNull(rotateForm.expiresAt) ?? undefined,
        overlap_seconds: overlap ? Number(overlap) : undefined,
      };
      const rotated = await api.rotateKey(rotationTarget.key_id, body);
      setIssuedSecret({
        title: `Rotated key ${rotationTarget.name}`,
        rawKey: rotated.raw_key,
        detail: `${rotated.message} Overlap ends ${formatDate(rotated.overlap_until)}.`,
      });
      setRotationTarget(null);
      setRotateForm({ name: "", expiresAt: "", overlapSeconds: "" });
      await onRefresh();
    } catch (nextError) {
      setFormError(nextError instanceof Error ? nextError.message : "Failed to rotate API key");
    } finally {
      setBusyKeyId(null);
      setBusyAction(null);
    }
  }

  async function handleRevoke(key: ApiKeyRecord) {
    if (!window.confirm(`Revoke ${key.name}? Existing clients will stop authenticating immediately.`)) {
      return;
    }
    setBusyAction("revoke");
    setBusyKeyId(key.key_id);
    setFormError(null);
    try {
      await api.deleteKey(key.key_id);
      await onRefresh();
    } catch (nextError) {
      setFormError(nextError instanceof Error ? nextError.message : "Failed to revoke API key");
    } finally {
      setBusyKeyId(null);
      setBusyAction(null);
    }
  }

  async function handleQuotaSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusyAction("quota");
    setFormError(null);
    try {
      const payload: TenantQuotaUpdateRequest = {};
      for (const [name, raw] of Object.entries(quotaForm) as Array<[QuotaKey, string]>) {
        const value = raw.trim();
        if (!value) {
          payload[name] = null;
          continue;
        }
        const parsed = Number(value);
        if (!Number.isInteger(parsed) || parsed < 0) {
          throw new Error(`${name.replaceAll("_", " ")} must be a whole number greater than or equal to 0`);
        }
        payload[name] = parsed;
      }
      await api.updateTenantQuota(payload);
      await onRefresh();
    } catch (nextError) {
      setFormError(nextError instanceof Error ? nextError.message : "Failed to update tenant quotas");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleQuotaReset() {
    setBusyAction("quota");
    setFormError(null);
    try {
      await api.resetTenantQuota();
      await onRefresh();
    } catch (nextError) {
      setFormError(nextError instanceof Error ? nextError.message : "Failed to reset tenant quotas");
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <section className="space-y-4 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
            <KeyRound className="h-5 w-5 text-emerald-400" />
            Control-plane auth and API keys
          </h2>
          <p className="mt-1 text-sm text-zinc-400">
            Rotate service keys with an overlap window, inspect auth policy, and revoke stale machine-to-machine access
            without leaving the control plane.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => {
              setRotationTarget(null);
              setCreateOpen((value) => !value);
              setFormError(null);
            }}
            className="inline-flex items-center gap-1.5 rounded-xl border border-emerald-900/60 bg-emerald-950/30 px-3 py-2 text-sm text-emerald-300 transition hover:bg-emerald-950/50"
          >
            <Plus className="h-4 w-4" />
            New key
          </button>
          <button
            onClick={() => void onRefresh()}
            className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 transition hover:bg-zinc-800"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {issuedSecret ? (
        <div className="rounded-2xl border border-emerald-900/60 bg-emerald-950/20 p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div>
              <p className="text-sm font-semibold text-emerald-300">{issuedSecret.title}</p>
              <p className="mt-1 text-sm text-zinc-300">{issuedSecret.detail}</p>
              <p className="mt-2 text-xs text-zinc-500">This raw key is shown once. Store it securely before you close this panel.</p>
            </div>
            <button
              onClick={() => void copyIssuedSecret()}
              className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 transition hover:bg-zinc-800"
            >
              {copied ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
              {copied ? "Copied" : "Copy raw key"}
            </button>
          </div>
          <pre className="mt-3 overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-3 text-sm text-zinc-100">
            {issuedSecret.rawKey}
          </pre>
        </div>
      ) : null}

      {formError ? (
        <div className="rounded-xl border border-red-900/50 bg-red-950/20 px-4 py-3 text-sm text-red-300">{formError}</div>
      ) : null}

      {createOpen ? (
        <form onSubmit={handleCreateSubmit} className="grid gap-4 rounded-2xl border border-zinc-800 bg-zinc-900/50 p-4 md:grid-cols-3">
          <label className="space-y-2 text-sm text-zinc-300">
            <span>Name</span>
            <input
              required
              value={createForm.name}
              onChange={(event) => setCreateForm((current) => ({ ...current, name: event.target.value }))}
              className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
              placeholder="ci-service"
            />
          </label>
          <label className="space-y-2 text-sm text-zinc-300">
            <span>Role</span>
            <select
              value={createForm.role}
              onChange={(event) => setCreateForm((current) => ({ ...current, role: event.target.value }))}
              className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
            >
              <option value="viewer">viewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
          </label>
          <label className="space-y-2 text-sm text-zinc-300">
            <span>Expires at (optional)</span>
            <input
              type="datetime-local"
              value={createForm.expiresAt}
              onChange={(event) => setCreateForm((current) => ({ ...current, expiresAt: event.target.value }))}
              className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
            />
          </label>
          <div className="md:col-span-3 flex items-center justify-between gap-3">
            <p className="text-xs text-zinc-500">
              Default TTL: {policy ? formatSeconds(policy.api_key.default_ttl_seconds) : "policy unavailable"}.
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setCreateOpen(false)}
                className="rounded-xl border border-zinc-700 px-3 py-2 text-sm text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={busyAction === "create"}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-zinc-950 transition hover:bg-emerald-400 disabled:opacity-60"
              >
                {busyAction === "create" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                Create key
              </button>
            </div>
          </div>
        </form>
      ) : null}

      {rotationTarget ? (
        <form onSubmit={handleRotateSubmit} className="grid gap-4 rounded-2xl border border-sky-900/50 bg-sky-950/20 p-4 md:grid-cols-3">
          <div className="md:col-span-3">
            <p className="text-sm font-semibold text-sky-300">Rotate {rotationTarget.name}</p>
            <p className="mt-1 text-sm text-zinc-300">
              The current key stays valid during the overlap window so clients can roll without downtime.
            </p>
          </div>
          <label className="space-y-2 text-sm text-zinc-300">
            <span>Replacement name (optional)</span>
            <input
              value={rotateForm.name}
              onChange={(event) => setRotateForm((current) => ({ ...current, name: event.target.value }))}
              className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
              placeholder={rotationTarget.name}
            />
          </label>
          <label className="space-y-2 text-sm text-zinc-300">
            <span>Replacement expiry (optional)</span>
            <input
              type="datetime-local"
              value={rotateForm.expiresAt}
              onChange={(event) => setRotateForm((current) => ({ ...current, expiresAt: event.target.value }))}
              className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
            />
          </label>
          <label className="space-y-2 text-sm text-zinc-300">
            <span>Overlap seconds</span>
            <input
              type="number"
              min={0}
              max={policy?.api_key.max_overlap_seconds ?? 86400}
              value={rotateForm.overlapSeconds}
              onChange={(event) => setRotateForm((current) => ({ ...current, overlapSeconds: event.target.value }))}
              className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
              placeholder={String(policy?.api_key.default_overlap_seconds ?? 900)}
            />
          </label>
          <div className="md:col-span-3 flex items-center justify-between gap-3">
            <p className="text-xs text-zinc-500">
              Allowed overlap: up to {policy ? formatSeconds(policy.api_key.max_overlap_seconds) : "policy unavailable"}.
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setRotationTarget(null)}
                className="rounded-xl border border-zinc-700 px-3 py-2 text-sm text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={busyAction === "rotate"}
                className="inline-flex items-center gap-1.5 rounded-xl bg-sky-500 px-4 py-2 text-sm font-medium text-zinc-950 transition hover:bg-sky-400 disabled:opacity-60"
              >
                {busyAction === "rotate" ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCw className="h-4 w-4" />}
                Rotate key
              </button>
            </div>
          </div>
        </form>
      ) : null}

      {loading ? (
        <div className="flex items-center justify-center rounded-2xl border border-zinc-800 bg-zinc-900/40 px-4 py-10 text-zinc-400">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" />
          Loading auth policy and keys...
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-amber-900/50 bg-amber-950/20 p-4">
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-0.5 h-5 w-5 text-amber-300" />
            <div>
              <p className="text-sm font-semibold text-amber-200">Admin access is required for key lifecycle operations</p>
              <p className="mt-1 text-sm text-amber-100/80">{error}</p>
              {roleLabel ? (
                <p className="mt-2 text-xs text-amber-100/70">
                  Current role: {roleLabel}. Contributors and viewers can review audit state, but only admins can manage service keys.
                </p>
              ) : null}
            </div>
          </div>
        </div>
      ) : policy ? (
        <>
          <div className="grid gap-3 md:grid-cols-4">
            <MetricCard label="Default TTL" value={formatSeconds(policy.api_key.default_ttl_seconds)} hint="Issued key lifetime" />
            <MetricCard label="Default overlap" value={formatSeconds(policy.api_key.default_overlap_seconds)} hint="Rotation grace window" />
            <MetricCard label="Recommended UI mode" value={formatModeLabel(policy.ui.recommended_mode)} hint="Browser auth posture" />
            <MetricCard label="Active keys" value={String(stateCounts.active ?? 0)} hint={`${keys.length} total in tenant`} />
          </div>

          <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
            <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Operator guidance</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs ${modeTone(policy.ui.recommended_mode)}`}>
                  Recommended: {formatModeLabel(policy.ui.recommended_mode)}
                </span>
                {policy.ui.configured_modes.map((mode) => (
                  <span key={mode} className={`inline-flex rounded-full border px-2.5 py-1 text-xs ${modeTone(mode)}`}>
                    {formatModeLabel(mode)}
                  </span>
                ))}
              </div>
              <p className="mt-3 text-sm text-zinc-300">{policy.ui.message}</p>
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
                  <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Runtime rate-limit backend</p>
                  <p className="mt-2 text-sm font-semibold text-zinc-100">
                    {policy.rate_limit_runtime.backend}
                    {policy.rate_limit_runtime.shared_across_replicas ? " · shared" : " · process-local"}
                  </p>
                  <p className="mt-1 text-xs text-zinc-400">{policy.rate_limit_runtime.message}</p>
                </div>
                <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
                  <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Trusted browser path</p>
                  <p className="mt-2 text-sm font-semibold text-zinc-100">{policy.ui.credentials_mode === "include" ? "Cookie-backed browser session" : policy.ui.credentials_mode}</p>
                  <p className="mt-1 text-xs text-zinc-400">
                    Trusted headers: {policy.ui.trusted_proxy_headers.length ? policy.ui.trusted_proxy_headers.join(", ") : "none"}.
                  </p>
                </div>
              </div>
            </section>

            <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Tenant guardrails</p>
              <p className="mt-3 text-sm text-zinc-300">{policy.tenant_quota_runtime.message}</p>
              <div className="mt-3 rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
                <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Quota source</p>
                <p className="mt-2 text-sm font-semibold text-zinc-100">
                  {policy.tenant_quota_runtime.source}
                  {policy.tenant_quota_runtime.active_override ? " · tenant override active" : " · global defaults active"}
                </p>
                <p className="mt-1 text-xs text-zinc-400">Manage overrides at {policy.tenant_quota_runtime.override_endpoint}.</p>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-3">
                {quotaCards.map(({ field, label, value }) => (
                  <div key={field} className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
                    <p className="text-[11px] uppercase tracking-[0.16em] text-zinc-500">{label}</p>
                    <p className="mt-2 text-lg font-semibold text-zinc-100">{value.limit}</p>
                    <p className="mt-1 text-xs text-zinc-400">
                      Current {value.current}
                      {value.remaining != null ? ` · Remaining ${value.remaining}` : " · Unlimited"}
                    </p>
                    <p className="mt-1 text-[11px] uppercase tracking-[0.14em] text-zinc-500">
                      {value.source === "tenant_override" ? "Tenant override" : "Global default"}
                    </p>
                  </div>
                ))}
              </div>
              <form onSubmit={handleQuotaSubmit} className="mt-3 rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
                <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Override management</p>
                <p className="mt-2 text-xs text-zinc-400">
                  Leave a field blank to inherit the global default. Set `0` only when you intentionally want an unlimited or disabled guardrail.
                </p>
                <div className="mt-3 grid grid-cols-2 gap-3">
                  {quotaCards.map(({ field, label, value }) => (
                    <label key={field} className="space-y-2 text-sm text-zinc-300">
                      <span>{label}</span>
                      <input
                        type="number"
                        min={0}
                        value={quotaForm[field]}
                        onChange={(event) => setQuotaForm((current) => ({ ...current, [field]: event.target.value }))}
                        className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-emerald-500"
                        placeholder={`Default ${value.default_limit}`}
                      />
                    </label>
                  ))}
                </div>
                <div className="mt-3 flex items-center justify-between gap-3">
                  <p className="text-xs text-zinc-500">
                    {policy.tenant_quota_runtime.active_override ? "Tenant-specific overrides are active." : "No tenant-specific overrides are active."}
                  </p>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => void handleQuotaReset()}
                      disabled={busyAction === "quota"}
                      className="rounded-xl border border-zinc-700 px-3 py-2 text-sm text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-60"
                    >
                      Reset overrides
                    </button>
                    <button
                      type="submit"
                      disabled={busyAction === "quota"}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-zinc-950 transition hover:bg-emerald-400 disabled:opacity-60"
                    >
                      {busyAction === "quota" ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                      Save overrides
                    </button>
                  </div>
                </div>
              </form>
            </section>
          </div>

          <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Secret and integrity posture</p>
            <div className="mt-3 grid gap-3 lg:grid-cols-2">
              <BoundaryCard
                title="Audit HMAC"
                body={policy.secret_integrity.audit_hmac.message}
                accent="teal"
                detail={`${policy.secret_integrity.audit_hmac.status.replaceAll("_", " ")} · ${policy.secret_integrity.audit_hmac.source}${
                  policy.secret_integrity.audit_hmac.persists_across_restart ? " · survives restart" : " · resets on restart"
                }`}
              />
              <BoundaryCard
                title="Compliance evidence signing"
                body={policy.secret_integrity.compliance_signing.message}
                accent="teal"
                detail={`${policy.secret_integrity.compliance_signing.algorithm} · ${policy.secret_integrity.compliance_signing.mode.replaceAll("_", " ")}${
                  policy.secret_integrity.compliance_signing.key_id ? ` · key ${policy.secret_integrity.compliance_signing.key_id}` : ""
                }${policy.secret_integrity.compliance_signing.public_key_endpoint ? ` · ${policy.secret_integrity.compliance_signing.public_key_endpoint}` : ""}`}
              />
            </div>
          </section>

          <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Rotation posture</p>
            <div className="mt-3 grid gap-3 lg:grid-cols-2 xl:grid-cols-4">
              <BoundaryCard
                title="Service API keys"
                body="Service keys rotate through an overlap-aware replacement flow so callers can roll without downtime."
                detail={`enforced · ${formatSeconds(policy.api_key.default_overlap_seconds)} default overlap · ${policy.api_key.rotation_endpoint}`}
              />
              <BoundaryCard
                title="Rate-limit key"
                body={policy.rate_limit_key.message ?? "Rate-limit fingerprint rotation posture is not available."}
                detail={formatRateLimitRotationDetail(policy.rate_limit_key)}
              />
              <BoundaryCard
                title="Audit HMAC rotation"
                body={policy.secret_integrity.audit_hmac.rotation_message}
                detail={formatRotationDetail(policy.secret_integrity.audit_hmac)}
              />
              <BoundaryCard
                title="Compliance signing rotation"
                body={policy.secret_integrity.compliance_signing.rotation_message}
                detail={formatRotationDetail(policy.secret_integrity.compliance_signing)}
              />
            </div>
          </section>

          <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Identity lifecycle</p>
            <div className="mt-3 grid gap-3 lg:grid-cols-3">
              <BoundaryCard
                title="OIDC browser / bearer"
                body={policy.identity_provisioning.oidc.message}
                detail={`${formatModeLabel(policy.identity_provisioning.oidc.mode)} · ${policy.identity_provisioning.oidc.provider_count} issuer${
                  policy.identity_provisioning.oidc.provider_count === 1 ? "" : "s"
                } · ${policy.identity_provisioning.oidc.require_tenant_claim ? "tenant claim required" : "default tenant allowed"}`}
              />
              <BoundaryCard
                title="SAML assertion exchange"
                body={policy.identity_provisioning.saml.message}
                detail={`${policy.identity_provisioning.saml.metadata_endpoint}${
                  policy.identity_provisioning.saml.acs_path ? ` · ${policy.identity_provisioning.saml.acs_path}` : ""
                } · ${formatSeconds(policy.identity_provisioning.saml.session_ttl_seconds)} session`}
              />
              <BoundaryCard
                title="SCIM provisioning"
                body={policy.identity_provisioning.scim.message}
                detail={`${policy.identity_provisioning.scim.status.replaceAll("_", " ")} · ${policy.identity_provisioning.scim.base_path} · ${
                  policy.identity_provisioning.scim.token_configured ? "token configured" : "token missing"
                }`}
              />
              <BoundaryCard
                title="Provisioning posture"
                body={`Role ${policy.identity_provisioning.scim.role_attribute} · tenant ${policy.identity_provisioning.scim.tenant_attribute} · external ID ${policy.identity_provisioning.scim.external_id_attribute}${
                  policy.identity_provisioning.scim.groups_required ? " · groups required" : ""
                }`}
              />
            </div>
          </section>

          <section className="rounded-2xl border border-amber-900/40 bg-amber-950/10 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-amber-200/70">Revocation boundaries</p>
            <div className="mt-3 grid gap-3 lg:grid-cols-3">
              <BoundaryCard
                title="Service keys"
                body={policy.identity_provisioning.session_revocation.service_keys}
              />
              <BoundaryCard
                title="Session API key fallback"
                body={policy.identity_provisioning.session_revocation.session_api_key}
              />
              <BoundaryCard
                title="Reverse-proxy or OIDC sessions"
                body={policy.identity_provisioning.session_revocation.browser_sessions}
              />
            </div>
          </section>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-zinc-200">Key inventory</h3>
                <p className="mt-1 text-xs text-zinc-500">
                  Rotation overlap lets old and new keys coexist briefly while clients roll.
                </p>
              </div>
              <div className="flex flex-wrap gap-2 text-xs text-zinc-500">
                <span>{stateCounts.rotation_overlap ?? 0} rotating</span>
                <span>{stateCounts.rotated ?? 0} rotated</span>
                <span>{stateCounts.revoked ?? 0} revoked</span>
              </div>
            </div>

            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-[0.18em] text-zinc-500">
                  <tr>
                    <th className="pb-2">Name</th>
                    <th className="pb-2">Role</th>
                    <th className="pb-2">State</th>
                    <th className="pb-2">Expires</th>
                    <th className="pb-2">Overlap</th>
                    <th className="pb-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {keys.map((key) => {
                    const sessionKey = isSessionKey(key);
                    const canRotate = key.state === "active" && !sessionKey;
                    const canRevoke = key.state !== "revoked";
                    return (
                      <tr key={key.key_id}>
                        <td className="py-3">
                          <div className="font-medium text-zinc-200">{key.name}</div>
                          <div className="text-xs text-zinc-500">
                            {key.key_prefix} · {sessionKey ? "session key" : "service key"}
                          </div>
                        </td>
                        <td className="py-3 text-zinc-300">{key.role}</td>
                        <td className="py-3">
                          <span className={`inline-flex rounded-full border px-2 py-1 text-xs ${keyStateTone(key.state)}`}>
                            {stateLabel(key.state)}
                          </span>
                        </td>
                        <td className="py-3 text-zinc-400">{key.expires_at ? formatDate(key.expires_at) : "Never"}</td>
                        <td className="py-3 text-zinc-400">
                          {key.rotation_overlap_until
                            ? `${formatDate(key.rotation_overlap_until)}${
                                key.overlap_seconds_remaining != null ? ` · ${formatSeconds(key.overlap_seconds_remaining)} left` : ""
                              }`
                            : "—"}
                        </td>
                        <td className="py-3">
                          <div className="flex justify-end gap-2">
                            <button
                              onClick={() => {
                                setCreateOpen(false);
                                setFormError(null);
                                setRotateForm({
                                  name: "",
                                  expiresAt: "",
                                  overlapSeconds: String(policy.api_key.default_overlap_seconds),
                                });
                                setRotationTarget(key);
                              }}
                              disabled={!canRotate || busyKeyId === key.key_id}
                              className="inline-flex items-center gap-1.5 rounded-lg border border-sky-900/60 bg-sky-950/20 px-3 py-1.5 text-xs text-sky-300 transition hover:bg-sky-950/40 disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              {busyAction === "rotate" && busyKeyId === key.key_id ? (
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              ) : (
                                <RotateCw className="h-3.5 w-3.5" />
                              )}
                              Rotate
                            </button>
                            <button
                              onClick={() => void handleRevoke(key)}
                              disabled={!canRevoke || busyKeyId === key.key_id}
                              className="inline-flex items-center gap-1.5 rounded-lg border border-red-900/60 bg-red-950/20 px-3 py-1.5 text-xs text-red-300 transition hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              {busyAction === "revoke" && busyKeyId === key.key_id ? (
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              ) : (
                                <ShieldOff className="h-3.5 w-3.5" />
                              )}
                              Revoke
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </section>
  );
}

function MetricCard({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-4">
      <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{label}</p>
      <p className="mt-2 text-lg font-semibold text-zinc-100">{value}</p>
      <p className="mt-1 text-xs text-zinc-500">{hint}</p>
    </div>
  );
}

function BoundaryCard({
  title,
  body,
  detail,
  accent = "amber",
}: {
  title: string;
  body: string;
  detail?: string;
  accent?: "amber" | "teal";
}) {
  const tone =
    accent === "teal"
      ? {
          border: "border-teal-900/30",
          title: "text-teal-100",
          detail: "text-teal-200/70",
        }
      : {
          border: "border-amber-900/30",
          title: "text-amber-100",
          detail: "text-amber-200/70",
        };
  return (
    <div className={`rounded-xl border bg-zinc-950/50 p-3 ${tone.border}`}>
      <p className={`text-sm font-semibold ${tone.title}`}>{title}</p>
      <p className="mt-1 text-xs leading-5 text-zinc-300">{body}</p>
      {detail ? <p className={`mt-2 text-[11px] uppercase tracking-[0.14em] ${tone.detail}`}>{detail}</p> : null}
    </div>
  );
}
