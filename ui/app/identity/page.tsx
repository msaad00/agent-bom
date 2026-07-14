"use client";

import { useEffect, useState } from "react";
import {
  Fingerprint,
  KeyRound,
  Clock,
  ShieldCheck,
  Ban,
  CalendarCheck,
  Radar,
  AlertCircle,
} from "lucide-react";
import { api } from "@/lib/api";
import type {
  AgentIdentitySummary,
  JITGrant,
  ConditionalAccessPolicy,
  CredentialExpiryReport,
  CredentialExpiryItem,
  AccessReviewCampaign,
  NhiDiscoveryResponse,
} from "@/lib/api-types";
import { formatDate } from "@/lib/api";
import {
  PageLoadingState,
  PageEmptyState,
} from "@/components/states/page-state";
import {
  ApiOfflineState,
  type ApiOfflineKind,
} from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";

function classifyApiErrorKind(err: unknown): ApiOfflineKind {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function Badge({
  tone,
  children,
}: {
  tone: "green" | "blue" | "red" | "amber" | "zinc";
  children: React.ReactNode;
}) {
  const map = {
    green: "bg-emerald-900/60 text-emerald-300",
    blue: "bg-blue-900/60 text-blue-300",
    red: "bg-red-900/60 text-red-300",
    amber: "bg-amber-900/60 text-amber-300",
    zinc: "bg-[var(--surface-elevated)] text-[var(--text-secondary)]",
  } as const;
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${map[tone]}`}
    >
      {children}
    </span>
  );
}

function identityTone(status: string) {
  return status === "active"
    ? "green"
    : status === "rotating"
      ? "blue"
      : status === "revoked"
        ? "red"
        : "zinc";
}
function jitTone(status: string) {
  return status === "active"
    ? "green"
    : status === "requested"
      ? "amber"
      : status === "denied"
        ? "red"
        : "zinc";
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-4">
      <div className="mb-1 flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-xs text-[var(--text-tertiary)]">{label}</span>
      </div>
      <p className="text-2xl font-bold text-[var(--foreground)]">
        {value.toLocaleString()}
      </p>
    </div>
  );
}

function conditionSummary(p: ConditionalAccessPolicy): string {
  const parts: string[] = [];
  if (p.allowed_environments.length)
    parts.push(`env ∈ {${p.allowed_environments.join(", ")}}`);
  if (p.allowed_hours_utc.length) {
    const h = p.allowed_hours_utc;
    parts.push(`hours ${Math.min(...h)}–${Math.max(...h)} UTC`);
  }
  if (p.allowed_weekdays.length)
    parts.push(`days ${p.allowed_weekdays.map((d) => WEEKDAYS[d]).join("/")}`);
  if (p.allowed_source_cidrs.length)
    parts.push(`from ${p.allowed_source_cidrs.join(", ")}`);
  return parts.length ? parts.join(" · ") : "no conditions (unconditional)";
}

function scopeSummary(p: ConditionalAccessPolicy): string {
  const parts: string[] = [];
  if (p.agent_ids.length) parts.push(`agents ${p.agent_ids.join(", ")}`);
  if (p.identity_ids.length)
    parts.push(
      `${p.identity_ids.length} identit${p.identity_ids.length === 1 ? "y" : "ies"}`,
    );
  if (p.tools.length) parts.push(`tools ${p.tools.join(", ")}`);
  return parts.length ? parts.join(" · ") : "any agent / identity / tool";
}

function credStateTone(
  state: string,
): "red" | "amber" | "green" | "zinc" {
  if (state === "expired" || state === "overdue") return "red";
  if (state === "rotation_due" || state === "near_expiry") return "amber";
  if (state === "ok") return "green";
  return "zinc";
}

function campaignTone(status: string): "green" | "blue" | "amber" | "red" | "zinc" {
  if (status === "completed") return "green";
  if (status === "in_progress") return "blue";
  if (status === "overdue") return "red";
  if (status === "open") return "amber";
  return "zinc";
}

function CredentialExpiryPanel({ report }: { report: CredentialExpiryReport }) {
  const expiringStates = new Set([
    "near_expiry",
    "rotation_due",
    "expired",
    "overdue",
  ]);
  const overdue =
    (report.counts.overdue ?? 0) + (report.counts.expired ?? 0);
  const expiring =
    (report.counts.near_expiry ?? 0) + (report.counts.rotation_due ?? 0);
  // Show the credentials needing attention first; the API already sorts
  // action_required worst-first.
  const rows: CredentialExpiryItem[] =
    report.action_required.length > 0
      ? report.action_required
      : report.credentials.filter((c) => expiringStates.has(c.state));

  const statusTone =
    report.status === "blocked"
      ? "red"
      : report.status === "attention_required"
        ? "amber"
        : "green";

  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
      <div className="mb-3 flex items-center gap-2">
        <KeyRound className="h-4 w-4 text-amber-400" />
        <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
          Credential expiry &amp; rotation
        </h3>
        <Badge tone={statusTone}>{report.status.replace(/_/g, " ")}</Badge>
        <span className="ml-auto text-xs text-[var(--text-tertiary)]">
          {report.evaluated} evaluated · reference-only, no secret values
        </span>
      </div>
      <div className="mb-3 grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
          <span className="text-xs text-[var(--text-tertiary)]">Expired / overdue</span>
          <p
            className={`text-xl font-bold ${overdue > 0 ? "text-red-400" : "text-[var(--foreground)]"}`}
          >
            {overdue.toLocaleString()}
          </p>
        </div>
        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
          <span className="text-xs text-[var(--text-tertiary)]">Expiring / rotation due</span>
          <p
            className={`text-xl font-bold ${expiring > 0 ? "text-amber-400" : "text-[var(--foreground)]"}`}
          >
            {expiring.toLocaleString()}
          </p>
        </div>
        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
          <span className="text-xs text-[var(--text-tertiary)]">Healthy</span>
          <p className="text-xl font-bold text-[var(--foreground)]">
            {(report.counts.ok ?? 0).toLocaleString()}
          </p>
        </div>
      </div>
      {report.evaluated === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">
          No control-plane secrets or discovered NHI credentials carry an age or
          expiry signal yet.
        </p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">
          All evaluated credentials are within rotation and expiry bounds.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] text-left text-xs text-[var(--text-tertiary)]">
                <th className="pb-2 font-medium">Credential</th>
                <th className="pb-2 font-medium">Provider</th>
                <th className="pb-2 font-medium">State</th>
                <th className="pb-2 text-right font-medium">Age</th>
                <th className="pb-2 text-right font-medium">Expires in</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c, i) => (
                <tr
                  key={`${c.id ?? c.name ?? "cred"}-${i}`}
                  className="border-b border-[var(--border-subtle)] last:border-0"
                >
                  <td className="py-2 font-medium text-[var(--foreground)]">
                    {c.name ?? c.id ?? "—"}
                  </td>
                  <td className="py-2 text-[var(--text-secondary)]">{c.provider ?? "—"}</td>
                  <td className="py-2">
                    <Badge tone={credStateTone(c.state)}>
                      {c.state.replace(/_/g, " ")}
                    </Badge>
                  </td>
                  <td className="py-2 text-right text-[var(--text-secondary)]">
                    {c.age_days != null ? `${c.age_days}d` : "—"}
                  </td>
                  <td className="py-2 text-right text-[var(--text-secondary)]">
                    {c.days_until_expiry != null
                      ? `${c.days_until_expiry}d`
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AccessReviewPanel({
  campaigns,
}: {
  campaigns: AccessReviewCampaign[];
}) {
  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
      <div className="mb-3 flex items-center gap-2">
        <CalendarCheck className="h-4 w-4 text-emerald-400" />
        <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
          Access-review campaigns
        </h3>
      </div>
      {campaigns.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">
          No recertification campaigns. Create one via{" "}
          <code className="rounded bg-[var(--surface-elevated)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">
            POST /v1/identities/access-reviews
          </code>{" "}
          to schedule a review of non-human identities and their effective
          permissions.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] text-left text-xs text-[var(--text-tertiary)]">
                <th className="pb-2 font-medium">Campaign</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 text-right font-medium">Reviewed</th>
                <th className="pb-2 font-medium">Due</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr
                  key={c.campaign_id}
                  className="border-b border-[var(--border-subtle)] last:border-0"
                >
                  <td className="py-2 font-medium text-[var(--foreground)]">{c.name}</td>
                  <td className="py-2">
                    <Badge tone={campaignTone(c.status)}>
                      {c.status.replace(/_/g, " ")}
                    </Badge>
                  </td>
                  <td className="py-2 text-right text-[var(--text-secondary)]">
                    {c.decided_count} / {c.item_count}
                  </td>
                  <td className="py-2 text-[var(--text-tertiary)]">
                    {c.due_at ? formatDate(c.due_at) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function NhiDiscoveryPanel({
  discovery,
}: {
  discovery: NhiDiscoveryResponse | null;
}) {
  // No provider gated on → discovery disabled. The merge layer reports
  // status "empty" with each provider's own gated status.
  const enabledProviders = (discovery?.providers ?? []).filter(
    (p) => (p.status ?? "").toLowerCase() === "ok",
  );
  const disabled =
    discovery == null ||
    (discovery.count === 0 && enabledProviders.length === 0);

  return (
    <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
      <div className="mb-3 flex items-center gap-2">
        <Radar className="h-4 w-4 text-sky-400" />
        <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
          Discovered non-human identities
        </h3>
      </div>
      {disabled ? (
        <div className="flex items-start gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3 text-sm text-[var(--text-secondary)]">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--text-tertiary)]" />
          <span>
            NHI discovery is disabled. Enable an IdP connector (Okta / Entra) via
            its <code className="text-[var(--text-secondary)]">*_DISCOVERY</code> environment
            flag and token to enumerate service accounts and service principals.
            Discovery is read-only and reference-only — it never reads secret
            material.
          </span>
        </div>
      ) : (
        <>
          <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-4">
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3">
              <span className="text-xs text-[var(--text-tertiary)]">Identities</span>
              <p className="text-xl font-bold text-[var(--foreground)]">
                {discovery.count.toLocaleString()}
              </p>
            </div>
            {discovery.providers.map((p) => (
              <div
                key={p.provider ?? "provider"}
                className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3"
              >
                <span className="text-xs capitalize text-[var(--text-tertiary)]">
                  {p.provider ?? "provider"}
                </span>
                <div className="flex items-baseline gap-2">
                  <p className="text-xl font-bold text-[var(--foreground)]">
                    {p.count.toLocaleString()}
                  </p>
                  <Badge tone={p.status === "ok" ? "green" : "zinc"}>
                    {p.status ?? "—"}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
          {discovery.warnings.length > 0 && (
            <ul className="space-y-1 text-xs text-[var(--text-tertiary)]">
              {discovery.warnings.map((w, i) => (
                <li key={i}>· {w}</li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

export default function IdentityPage() {
  const [identities, setIdentities] = useState<AgentIdentitySummary[]>([]);
  const [grants, setGrants] = useState<JITGrant[]>([]);
  const [policies, setPolicies] = useState<ConditionalAccessPolicy[]>([]);
  const [credExpiry, setCredExpiry] = useState<CredentialExpiryReport | null>(
    null,
  );
  const [campaigns, setCampaigns] = useState<AccessReviewCampaign[]>([]);
  const [discovery, setDiscovery] = useState<NhiDiscoveryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<ApiOfflineKind>("network");

  useEffect(() => {
    void Promise.allSettled([
      api.listIdentities(true),
      api.listJitGrants(true),
      api.listConditionalAccessPolicies(true),
      api.getCredentialExpiry(),
      api.listAccessReviews(),
      api.discoverNonHumanIdentities(),
    ])
      .then(
        ([
          idResult,
          jitResult,
          polResult,
          credResult,
          reviewResult,
          discoverResult,
        ]) => {
          if (idResult.status === "fulfilled") {
            setIdentities(idResult.value.identities);
          } else {
            setError(idResult.reason?.message ?? "Failed to load identities");
            setErrorKind(classifyApiErrorKind(idResult.reason));
          }
          if (jitResult.status === "fulfilled")
            setGrants(jitResult.value.grants);
          if (polResult.status === "fulfilled")
            setPolicies(polResult.value.policies);
          if (credResult.status === "fulfilled")
            setCredExpiry(credResult.value);
          if (reviewResult.status === "fulfilled")
            setCampaigns(reviewResult.value.campaigns);
          if (discoverResult.status === "fulfilled")
            setDiscovery(discoverResult.value);
        },
      )
      .finally(() => setLoading(false));
  }, []);

  if (loading)
    return (
      <PageLoadingState
        title="Loading identity governance"
        detail="Managed agent identities, JIT grants, and conditional-access policies."
      />
    );
  if (error)
    return (
      <ApiOfflineState
        title="Identity data unavailable"
        detail={error}
        kind={errorKind}
      />
    );

  const activeIdentities = identities.filter(
    (i) => i.status === "active" || i.status === "rotating",
  ).length;
  const activeGrants = grants.filter((g) => g.status === "active").length;
  const activePolicies = policies.filter((p) => p.status === "active").length;
  const inactiveIdentities = identities.filter(
    (i) => i.status === "revoked" || i.status === "expired",
  ).length;

  const hasGovernanceData =
    (credExpiry?.evaluated ?? 0) > 0 ||
    campaigns.length > 0 ||
    (discovery?.count ?? 0) > 0;
  const isEmpty =
    identities.length === 0 &&
    grants.length === 0 &&
    policies.length === 0 &&
    !hasGovernanceData;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Fingerprint className="h-6 w-6 text-indigo-400" />
        <div>
          <h1 className="text-2xl font-semibold text-[var(--foreground)]">Identity</h1>
          <p className="text-sm text-[var(--text-tertiary)]">
            Managed agent identities, just-in-time access, and context-aware
            conditional access.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard
          icon={Fingerprint}
          label="Active identities"
          value={activeIdentities}
          color="text-indigo-400"
        />
        <StatCard
          icon={Clock}
          label="Active JIT grants"
          value={activeGrants}
          color="text-emerald-400"
        />
        <StatCard
          icon={ShieldCheck}
          label="Conditional policies"
          value={activePolicies}
          color="text-blue-400"
        />
        <StatCard
          icon={Ban}
          label="Revoked / expired"
          value={inactiveIdentities}
          color="text-[var(--text-secondary)]"
        />
      </div>

      {isEmpty && (
        <PageEmptyState
          title="No managed identities yet"
          detail="Issue a time-scoped agent identity via POST /v1/identities to provision, rotate, and revoke credentials with an audit chain."
          icon={Fingerprint}
        />
      )}

      {credExpiry && <CredentialExpiryPanel report={credExpiry} />}

      <AccessReviewPanel campaigns={campaigns} />

      <NhiDiscoveryPanel discovery={discovery} />

      {identities.length > 0 && (
        <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
          <div className="mb-3 flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
              Managed identities
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-left text-xs text-[var(--text-tertiary)]">
                  <th className="pb-2 font-medium">Agent</th>
                  <th className="pb-2 font-medium">Role</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Tool scope</th>
                  <th className="pb-2 font-medium">Token</th>
                  <th className="pb-2 font-medium">Expires</th>
                </tr>
              </thead>
              <tbody>
                {identities.map((i) => (
                  <tr
                    key={i.identity_id}
                    className="border-b border-[var(--border-subtle)] last:border-0"
                  >
                    <td className="py-2 font-medium text-[var(--foreground)]">
                      {i.agent_id}
                    </td>
                    <td className="py-2 text-[var(--text-secondary)]">{i.role}</td>
                    <td className="py-2">
                      <Badge tone={identityTone(i.status)}>{i.status}</Badge>
                    </td>
                    <td className="py-2 text-[var(--text-secondary)]">
                      {i.allowed_tools.length === 0 ? (
                        <span className="text-[var(--text-tertiary)]">any tool</span>
                      ) : (
                        <span className="font-mono text-xs">
                          {i.allowed_tools.join(", ")}
                        </span>
                      )}
                    </td>
                    <td className="py-2 font-mono text-xs text-[var(--text-tertiary)]">
                      abi_{i.token_prefix}…
                    </td>
                    <td className="py-2 text-[var(--text-tertiary)]">
                      {i.expires_at ? formatDate(i.expires_at) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {grants.length > 0 && (
        <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
          <div className="mb-3 flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
              JIT access grants
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-left text-xs text-[var(--text-tertiary)]">
                  <th className="pb-2 font-medium">Tool</th>
                  <th className="pb-2 font-medium">Agent</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Ticket</th>
                  <th className="pb-2 font-medium">Approved by</th>
                  <th className="pb-2 font-medium">Expires</th>
                </tr>
              </thead>
              <tbody>
                {grants.map((g) => (
                  <tr
                    key={g.grant_id}
                    className="border-b border-[var(--border-subtle)] last:border-0"
                  >
                    <td className="py-2 font-mono text-xs text-[var(--foreground)]">
                      {g.tool_name}
                    </td>
                    <td className="py-2 text-[var(--text-secondary)]">{g.agent_id}</td>
                    <td className="py-2">
                      <Badge tone={jitTone(g.status)}>{g.status}</Badge>
                    </td>
                    <td className="py-2 font-mono text-xs text-[var(--text-tertiary)]">
                      {g.ticket_id || "—"}
                    </td>
                    <td className="py-2 text-[var(--text-secondary)]">
                      {g.approved_by || "—"}
                    </td>
                    <td className="py-2 text-[var(--text-tertiary)]">
                      {g.expires_at ? formatDate(g.expires_at) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {policies.length > 0 && (
        <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-5">
          <div className="mb-3 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-[var(--text-secondary)]">
              Conditional-access policies
            </h3>
          </div>
          <div className="space-y-2">
            {[...policies]
              .sort((a, b) => a.priority - b.priority)
              .map((p) => (
                <div
                  key={p.policy_id}
                  className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/50 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-[var(--foreground)]">
                      {p.name}
                    </span>
                    <Badge tone={p.effect === "deny" ? "red" : "blue"}>
                      {p.effect}
                    </Badge>
                    <Badge tone={p.status === "active" ? "green" : "zinc"}>
                      {p.status}
                    </Badge>
                    <span className="text-xs text-[var(--text-tertiary)]">
                      priority {p.priority}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-[var(--text-secondary)]">
                    <span className="text-[var(--text-tertiary)]">scope:</span>{" "}
                    {scopeSummary(p)}
                  </p>
                  <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
                    <span className="text-[var(--text-tertiary)]">when:</span>{" "}
                    {conditionSummary(p)}
                  </p>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
