"use client";

import { useEffect, useState } from "react";
import { Fingerprint, KeyRound, Clock, ShieldCheck, Ban } from "lucide-react";
import { api } from "@/lib/api";
import type {
  AgentIdentitySummary,
  JITGrant,
  ConditionalAccessPolicy,
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
    zinc: "bg-zinc-800 text-zinc-400",
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
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="mb-1 flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-xs text-zinc-500">{label}</span>
      </div>
      <p className="text-2xl font-bold text-zinc-100">
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

export default function IdentityPage() {
  const [identities, setIdentities] = useState<AgentIdentitySummary[]>([]);
  const [grants, setGrants] = useState<JITGrant[]>([]);
  const [policies, setPolicies] = useState<ConditionalAccessPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<ApiOfflineKind>("network");

  useEffect(() => {
    void Promise.allSettled([
      api.listIdentities(true),
      api.listJitGrants(true),
      api.listConditionalAccessPolicies(true),
    ])
      .then(([idResult, jitResult, polResult]) => {
        if (idResult.status === "fulfilled") {
          setIdentities(idResult.value.identities);
        } else {
          setError(idResult.reason?.message ?? "Failed to load identities");
          setErrorKind(classifyApiErrorKind(idResult.reason));
        }
        if (jitResult.status === "fulfilled") setGrants(jitResult.value.grants);
        if (polResult.status === "fulfilled")
          setPolicies(polResult.value.policies);
      })
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

  const isEmpty =
    identities.length === 0 && grants.length === 0 && policies.length === 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Fingerprint className="h-6 w-6 text-indigo-400" />
        <div>
          <h1 className="text-2xl font-semibold text-zinc-100">Identity</h1>
          <p className="text-sm text-zinc-500">
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
          color="text-zinc-400"
        />
      </div>

      {isEmpty && (
        <PageEmptyState
          title="No managed identities yet"
          detail="Issue a time-scoped agent identity via POST /v1/identities to provision, rotate, and revoke credentials with an audit chain."
          icon={Fingerprint}
        />
      )}

      {identities.length > 0 && (
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
          <div className="mb-3 flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-zinc-300">
              Managed identities
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-left text-xs text-zinc-500">
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
                    className="border-b border-zinc-900 last:border-0"
                  >
                    <td className="py-2 font-medium text-zinc-200">
                      {i.agent_id}
                    </td>
                    <td className="py-2 text-zinc-400">{i.role}</td>
                    <td className="py-2">
                      <Badge tone={identityTone(i.status)}>{i.status}</Badge>
                    </td>
                    <td className="py-2 text-zinc-400">
                      {i.allowed_tools.length === 0 ? (
                        <span className="text-zinc-600">any tool</span>
                      ) : (
                        <span className="font-mono text-xs">
                          {i.allowed_tools.join(", ")}
                        </span>
                      )}
                    </td>
                    <td className="py-2 font-mono text-xs text-zinc-500">
                      abi_{i.token_prefix}…
                    </td>
                    <td className="py-2 text-zinc-500">
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
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
          <div className="mb-3 flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-zinc-300">
              JIT access grants
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-left text-xs text-zinc-500">
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
                    className="border-b border-zinc-900 last:border-0"
                  >
                    <td className="py-2 font-mono text-xs text-zinc-200">
                      {g.tool_name}
                    </td>
                    <td className="py-2 text-zinc-400">{g.agent_id}</td>
                    <td className="py-2">
                      <Badge tone={jitTone(g.status)}>{g.status}</Badge>
                    </td>
                    <td className="py-2 font-mono text-xs text-zinc-500">
                      {g.ticket_id || "—"}
                    </td>
                    <td className="py-2 text-zinc-400">
                      {g.approved_by || "—"}
                    </td>
                    <td className="py-2 text-zinc-500">
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
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5">
          <div className="mb-3 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-zinc-300">
              Conditional-access policies
            </h3>
          </div>
          <div className="space-y-2">
            {[...policies]
              .sort((a, b) => a.priority - b.priority)
              .map((p) => (
                <div
                  key={p.policy_id}
                  className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-zinc-200">
                      {p.name}
                    </span>
                    <Badge tone={p.effect === "deny" ? "red" : "blue"}>
                      {p.effect}
                    </Badge>
                    <Badge tone={p.status === "active" ? "green" : "zinc"}>
                      {p.status}
                    </Badge>
                    <span className="text-xs text-zinc-600">
                      priority {p.priority}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-zinc-400">
                    <span className="text-zinc-500">scope:</span>{" "}
                    {scopeSummary(p)}
                  </p>
                  <p className="mt-0.5 text-xs text-zinc-400">
                    <span className="text-zinc-500">when:</span>{" "}
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
