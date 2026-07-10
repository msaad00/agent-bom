import type { AuthMeResponse } from "@/lib/api";

export type OverviewPersona = "executive" | "engineer";

export const OVERVIEW_PERSONA_STORAGE_KEY = "agent-bom:overview-persona";

export function defaultOverviewPersona(session: AuthMeResponse | null): OverviewPersona {
  const role = (session?.role ?? session?.role_summary?.role ?? "viewer").toLowerCase();
  const uiRole = (session?.role_summary?.ui_role ?? "").toLowerCase();
  if (role === "admin" || role === "analyst" || uiRole === "contributor") {
    return "engineer";
  }
  return "executive";
}

export function readStoredOverviewPersona(): OverviewPersona | null {
  if (typeof window === "undefined") return null;
  const stored = window.localStorage.getItem(OVERVIEW_PERSONA_STORAGE_KEY);
  return stored === "executive" || stored === "engineer" ? stored : null;
}

export function storeOverviewPersona(persona: OverviewPersona): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(OVERVIEW_PERSONA_STORAGE_KEY, persona);
}

export function overviewPersonaLabel(persona: OverviewPersona): string {
  return persona === "executive" ? "Executive" : "Engineer";
}

export function overviewPersonaHint(persona: OverviewPersona): string {
  return persona === "executive"
    ? "Posture, domain coverage, and risk roll-up — no attack-path chains."
    : "Blast-radius paths, graph drill-down, and fleet topology evidence.";
}
