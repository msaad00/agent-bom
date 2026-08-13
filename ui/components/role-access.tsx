"use client";

import { Check, ChevronDown, Eye, Lock, ShieldCheck, TriangleAlert, Wrench, X } from "lucide-react";

import { useDemoMode } from "@/hooks/use-demo-mode";
import type { AuthMeResponse } from "@/lib/api";
import {
  ROLE_LADDER,
  type RoleId,
  normalizeRoleId,
  roleElevationGuidance,
  roleRank,
} from "@/lib/roles";

const ROLE_ICON: Record<RoleId, typeof Eye> = {
  viewer: Eye,
  analyst: Wrench,
  admin: ShieldCheck,
};

function activeRoleId(session: AuthMeResponse | null): RoleId | null {
  return normalizeRoleId(session?.role_summary?.role ?? session?.role ?? null);
}

/** Compact chip naming the caller's current role. */
export function RoleBadge({ session }: { session: AuthMeResponse | null }) {
  const roleId = activeRoleId(session);
  const entry = ROLE_LADDER.find((r) => r.id === roleId);
  if (!entry) return null;
  const Icon = ROLE_ICON[entry.id];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]">
      <Icon className="h-3 w-3 text-emerald-400" />
      Your role · {entry.label}
    </span>
  );
}

/**
 * Actionable, non-403 permission notice. Names the current role, what the
 * blocked action needs, and the concrete lever to elevate — self-host env var
 * or an admin grant — instead of a raw "Role 'viewer' does not have 'scan'".
 */
export function PermissionDeniedNotice({
  session,
  needed = "analyst",
  action = "connect a cloud account or run a scan",
  className = "",
}: {
  session: AuthMeResponse | null;
  needed?: RoleId;
  action?: string;
  className?: string;
}) {
  // On the public demo, the caller is an anonymous read-only visitor. Operator
  // env-var / config guidance (AGENT_BOM_NO_AUTH_ROLE, AGENT_BOM_DEMO_ESTATE)
  // is internal ops instruction that must never reach that visitor — surface a
  // neutral read-only line instead. The self-host operator path keeps the full
  // elevation guidance.
  const { isDemoMode } = useDemoMode();
  const roleId = activeRoleId(session);
  const current = ROLE_LADDER.find((r) => r.id === roleId);
  const authRequired = Boolean(session?.auth_required);
  const neededLabel = ROLE_LADDER.find((r) => r.id === needed)?.label ?? "Contributor";
  const roleAlreadySufficient = roleRank(roleId) >= roleRank(needed);

  const headline = isDemoMode
    ? "This is a read-only public demo."
    : current && !roleAlreadySufficient
      ? `Your ${current.label} role is read-only for this action.`
      : roleAlreadySufficient
        ? "This environment is read-only for this action."
        : "This action needs a higher role.";

  const secondary = isDemoMode
    ? "Connect, scan, and other write actions are disabled here so anyone can explore safely."
    : roleAlreadySufficient
      ? `Your ${current?.label ?? "current"} role meets the ${neededLabel} requirement, but writes are disabled here.`
      : `To ${action} you need the ${neededLabel} role or higher.`;

  // Operator elevation steps are shown only off the public demo.
  const guidance = isDemoMode
    ? null
    : roleAlreadySufficient
      ? {
          title: "Review this environment's write policy",
          steps: [
            `The current role already meets the ${neededLabel} requirement; an environment policy is denying writes.`,
            "Public demo estates remain read-only. On a self-hosted instance, review the demo clamp and deployment policy before enabling writes.",
          ],
        }
      : roleElevationGuidance({ authRequired, needed });

  return (
    <details
      role="note"
      className={`group rounded-lg border border-amber-500/30 bg-amber-500/10 text-sm text-amber-900 dark:text-amber-100 ${className}`}
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 font-medium marker:content-none [&::-webkit-details-marker]:hidden">
        <TriangleAlert className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-300" />
        <span className="min-w-0 flex-1">{headline}</span>
        <ChevronDown className="h-4 w-4 shrink-0 text-amber-600 transition-transform group-open:rotate-180 dark:text-amber-300" />
      </summary>
      <div className="space-y-2 border-t border-amber-500/20 px-3 pb-3 pt-2">
        <p className="text-[13px] leading-6 text-amber-800 dark:text-amber-100/90">
          {secondary}
        </p>
        {guidance ? (
          <>
            <p className="mt-2 text-[12px] font-semibold uppercase tracking-[0.12em] text-amber-700 dark:text-amber-200/90">
              {guidance.title}
            </p>
            <ul className="space-y-1 text-[13px] leading-6 text-amber-800 dark:text-amber-100/90">
              {guidance.steps.map((step) => (
                <li key={step} className="flex items-start gap-2">
                  <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500/70 dark:bg-amber-300/80" />
                  <span>{step}</span>
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </div>
    </details>
  );
}

/**
 * The viewer / contributor / admin ladder with the caller's current role
 * highlighted. Static ladder mirrors rbac.py; the live capability facts come
 * from the session's role_summary when present.
 */
export function RolePermissionsPanel({
  session,
  bare = false,
}: {
  session: AuthMeResponse | null;
  /** Omit the panel's own header + card chrome when wrapped in a disclosure. */
  bare?: boolean;
}) {
  const roleId = activeRoleId(session);
  const grid = (
    <div className={`grid gap-3 md:grid-cols-3 ${bare ? "" : "mt-4"}`}>
      {ROLE_LADDER.map((entry) => {
          const Icon = ROLE_ICON[entry.id];
          const active = entry.id === roleId;
          return (
            <div
              key={entry.id}
              aria-current={active ? "true" : undefined}
              data-testid={`role-card-${entry.id}`}
              className={`flex h-full flex-col rounded-xl border p-3 transition ${
                active
                  ? "border-emerald-500/60 bg-emerald-500/10"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-2 text-sm font-semibold text-[var(--foreground)]">
                  <Icon className="h-4 w-4 text-emerald-400" />
                  {entry.label}
                </span>
                {active ? (
                  <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-200">
                    You
                  </span>
                ) : null}
              </div>
              <p className="mt-2 text-[12px] leading-5 text-[var(--text-secondary)]">
                {entry.summary}
              </p>
              <ul className="mt-3 space-y-1 text-[12px] leading-5">
                {entry.can.map((item) => (
                  <li key={item} className="flex items-start gap-1.5 text-[var(--text-secondary)]">
                    <Check className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                    <span>{item}</span>
                  </li>
                ))}
                {entry.cannot.map((item) => (
                  <li key={item} className="flex items-start gap-1.5 text-[var(--text-tertiary)]">
                    <X className="mt-0.5 h-3 w-3 shrink-0 text-[var(--text-tertiary)]" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
    </div>
  );

  if (bare) return grid;

  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
      <div className="flex items-start gap-3">
        <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
          <Lock className="h-5 w-5 text-emerald-400" />
        </span>
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-[var(--foreground)]">
            Roles &amp; permissions
          </h2>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Three roles gate the control plane. Viewer reads; Contributor connects
            and scans; Admin manages keys, policy, and fleet.
          </p>
        </div>
      </div>
      {grid}
    </div>
  );
}
