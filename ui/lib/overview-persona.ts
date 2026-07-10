import type { AuthMeResponse } from "@/lib/api";

/**
 * Overview altitude lenses — same estate evidence, different depth.
 * CISO (leadership) ← Trust/GRC (evidence) ← Engineer (operations).
 * Operators can move up or down without leaving Overview.
 */
export type OverviewPersona = "ciso" | "trust" | "engineer";

/** @deprecated Prefer OverviewPersona; kept for storage migration. */
type LegacyOverviewPersona = "executive";

export const OVERVIEW_PERSONAS: OverviewPersona[] = ["ciso", "trust", "engineer"];

export const OVERVIEW_PERSONA_STORAGE_KEY = "agent-bom:overview-persona";

export function defaultOverviewPersona(session: AuthMeResponse | null): OverviewPersona {
  const role = (session?.role ?? session?.role_summary?.role ?? "viewer").toLowerCase();
  const uiRole = (session?.role_summary?.ui_role ?? "").toLowerCase();
  if (role === "admin" || role === "analyst" || uiRole === "contributor") {
    return "engineer";
  }
  if (role === "auditor" || uiRole === "auditor" || uiRole === "compliance") {
    return "trust";
  }
  return "ciso";
}

function normalizePersona(value: string | null): OverviewPersona | null {
  if (value === "executive") return "ciso"; // migrate legacy Exec lens
  if (value === "ciso" || value === "trust" || value === "engineer") return value;
  return null;
}

export function readStoredOverviewPersona(): OverviewPersona | null {
  if (typeof window === "undefined") return null;
  return normalizePersona(window.localStorage.getItem(OVERVIEW_PERSONA_STORAGE_KEY));
}

export function storeOverviewPersona(persona: OverviewPersona): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(OVERVIEW_PERSONA_STORAGE_KEY, persona);
}

export function overviewPersonaLabel(persona: OverviewPersona): string {
  switch (persona) {
    case "ciso":
      return "CISO";
    case "trust":
      return "Trust";
    case "engineer":
      return "Engineer";
  }
}

export function overviewPersonaHint(persona: OverviewPersona): string {
  switch (persona) {
    case "ciso":
      return "Leadership altitude — posture, risk themes, and board-ready roll-up.";
    case "trust":
      return "GRC altitude — frameworks, evidence, and audit-ready trust signals.";
    case "engineer":
      return "Ops altitude — blast-radius paths, graph drill-down, and remediation.";
  }
}

/** Next deeper lens (CISO → Trust → Engineer), or null at the bottom. */
export function overviewPersonaDrillDown(persona: OverviewPersona): OverviewPersona | null {
  if (persona === "ciso") return "trust";
  if (persona === "trust") return "engineer";
  return null;
}

/** Next higher lens (Engineer → Trust → CISO), or null at the top. */
export function overviewPersonaZoomOut(persona: OverviewPersona): OverviewPersona | null {
  if (persona === "engineer") return "trust";
  if (persona === "trust") return "ciso";
  return null;
}

export type { LegacyOverviewPersona };
