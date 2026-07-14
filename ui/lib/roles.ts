// Honest, code-true role model for the dashboard.
//
// Mirrors the closed role enum and permission matrix in
// `src/agent_bom/rbac.py` (viewer / analyst / admin). The live per-session
// capabilities come from `/v1/auth/me` (`role_summary`); this module supplies
// the *ladder* — what each of the three roles can and cannot do — plus the
// elevation guidance the API cannot infer, so a user who hits a 403 knows the
// concrete next step instead of a raw "Role 'viewer' does not have 'scan'".

export type RoleId = "viewer" | "analyst" | "admin";

export interface RoleLadderEntry {
  id: RoleId;
  /** UI-facing label. analyst surfaces as "Contributor" (matches rbac display names). */
  label: string;
  /** The raw role value the API reports (what a 403 message names). */
  value: RoleId;
  summary: string;
  can: string[];
  cannot: string[];
}

const RANK: Record<RoleId, number> = { viewer: 1, analyst: 2, admin: 3 };

export const ROLE_LADDER: RoleLadderEntry[] = [
  {
    id: "viewer",
    label: "Viewer",
    value: "viewer",
    summary: "Read-only across inventory, findings, graph, compliance, and audit.",
    can: [
      "View inventory, findings, graph, posture, compliance, and audit",
      "Open evidence and export what is already scanned",
    ],
    cannot: [
      "Connect a cloud account or source",
      "Run or schedule scans",
      "Create exceptions, keys, policy, or fleet writes",
    ],
  },
  {
    id: "analyst",
    label: "Contributor",
    value: "analyst",
    summary: "Everything a viewer sees, plus connect, scan, and evidence workflows.",
    can: [
      "Connect cloud accounts and manage sources + schedules",
      "Run read-only scans and push runtime evidence",
      "Create exception / false-positive workflows",
    ],
    cannot: [
      "Create, rotate, or revoke API keys",
      "Change protected admin policy, fleet writes, or break-glass state",
    ],
  },
  {
    id: "admin",
    label: "Admin",
    value: "admin",
    summary: "Full control-plane administration and protected writes.",
    can: [
      "Everything a contributor can do",
      "Manage API keys, gateway policy, and fleet sync",
      "Approve exceptions and protected break-glass actions",
    ],
    cannot: [],
  },
];

export function normalizeRoleId(value: string | null | undefined): RoleId | null {
  const raw = (value ?? "").trim().toLowerCase();
  if (raw === "viewer" || raw === "analyst" || raw === "admin") return raw;
  // rbac's UI display name for analyst is "contributor".
  if (raw === "contributor") return "analyst";
  return null;
}

export function roleRank(value: string | null | undefined): number {
  const id = normalizeRoleId(value);
  return id ? RANK[id] : 0;
}

/** analyst + admin can connect/scan (the `scan` permission in rbac.py). */
export function roleCanConnect(value: string | null | undefined): boolean {
  return roleRank(value) >= RANK.analyst;
}

export interface ElevationGuidance {
  title: string;
  steps: string[];
}

/**
 * Concrete, honest guidance for raising the effective role. The path differs
 * for an authenticated deployment vs a local unauthenticated (self-host) one —
 * agent-bom never self-elevates, so we point at the real lever.
 */
export function roleElevationGuidance(opts: {
  authRequired: boolean;
  needed?: RoleId;
}): ElevationGuidance {
  const needed = opts.needed ?? "analyst";
  const neededLabel = ROLE_LADDER.find((r) => r.id === needed)?.label ?? "Contributor";
  if (opts.authRequired) {
    return {
      title: `Ask an admin to grant ${neededLabel} access`,
      steps: [
        "Your role comes from your API key or SSO group mapping, not from this UI.",
        `An admin assigns ${neededLabel} (${needed}) to your identity; sign in again to pick it up.`,
      ],
    };
  }
  return {
    title: `Grant this local instance ${neededLabel} access`,
    steps: [
      `Set AGENT_BOM_NO_AUTH_ROLE=${needed} on the API and restart (the shipped pilot compose already defaults to analyst).`,
      "AGENT_BOM_DEMO_ESTATE=1 always clamps to read-only viewer for public demos.",
    ],
  };
}
