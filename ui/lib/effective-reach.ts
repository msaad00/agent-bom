/**
 * Effective-reach scoring — UI helpers.
 *
 * Mirrors the Python band thresholds from
 * `src/agent_bom/effective_reach.py::ReachScore.band` so the dashboard
 * can color nodes / edges directly off the score returned by the API
 * without re-implementing the policy.
 */

export type ReachBand = "green" | "amber" | "red" | "pulsing-red";

export type ReachBreakdown = {
  cvss: number;
  epss: number;
  is_kev: boolean;
  tool_capability: number;
  cred_visibility: number;
  agent_breadth: number;
  reachable_tools?: string[] | undefined;
  reachable_creds?: string[] | undefined;
  reachable_agents?: string[] | undefined;
  composite: number;
  band: ReachBand;
};

/**
 * Map an effective-reach composite (0..100) to its triage band.
 * Thresholds match the issue acceptance criteria:
 *   green ≤ 30 / amber 30..70 / red > 70 / pulsing-red ≥ 90.
 */
export function reachBand(score: number): ReachBand {
  if (!Number.isFinite(score)) return "green";
  if (score >= 90) return "pulsing-red";
  if (score > 70) return "red";
  if (score > 30) return "amber";
  return "green";
}

/**
 * Tailwind background class for a band — used for node tint and the
 * lineage detail panel header chip.
 */
export function reachColorClass(band: ReachBand): string {
  switch (band) {
    case "pulsing-red":
      return "bg-red-500 animate-pulse";
    case "red":
      return "bg-red-500";
    case "amber":
      return "bg-amber-500";
    case "green":
    default:
      return "bg-green-500";
  }
}

/**
 * Tailwind text-color class for a band — used for the breakdown line.
 */
export function reachTextClass(band: ReachBand): string {
  switch (band) {
    case "pulsing-red":
      return "text-red-400 animate-pulse";
    case "red":
      return "text-red-400";
    case "amber":
      return "text-amber-400";
    case "green":
    default:
      return "text-emerald-400";
  }
}

/**
 * Edge-thickness multiplier (1.0..3.0) for a given composite score.
 * Used by the dashboard graph view — stays linear so neighbouring
 * scores stay visually proportional.
 */
export function reachEdgeWidth(score: number | undefined): number {
  if (score == null || !Number.isFinite(score)) return 1.0;
  const clamped = Math.max(0, Math.min(score, 100));
  return 1.0 + (clamped / 100) * 2.0;
}

/**
 * Stroke color for reach-weighted edges. This intentionally uses the same
 * band thresholds as node chips so edge emphasis has one meaning.
 */
export function reachStrokeColor(score: number | undefined): string | undefined {
  if (score == null || !Number.isFinite(score)) return undefined;
  switch (reachBand(score)) {
    case "pulsing-red":
    case "red":
      return "#ef4444";
    case "amber":
      return "#f59e0b";
    case "green":
    default:
      return "#22c55e";
  }
}

export function readReachScore(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function readReachBreakdown(value: unknown): ReachBreakdown | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const composite = readReachScore(raw.composite);
  if (composite == null) return undefined;
  const band = raw.band;
  return {
    cvss: readReachScore(raw.cvss) ?? 0,
    epss: readReachScore(raw.epss) ?? 0,
    is_kev: raw.is_kev === true,
    tool_capability: readReachScore(raw.tool_capability) ?? 0,
    cred_visibility: readReachScore(raw.cred_visibility) ?? 0,
    agent_breadth: readReachScore(raw.agent_breadth) ?? 0,
    reachable_tools: stringList(raw.reachable_tools),
    reachable_creds: stringList(raw.reachable_creds),
    reachable_agents: stringList(raw.reachable_agents),
    composite,
    band:
      band === "green" || band === "amber" || band === "red" || band === "pulsing-red"
        ? band
        : reachBand(composite),
  };
}

/**
 * Human-readable score string for the lineage detail panel.
 * Mirrors the additive weighted Python model:
 *   CVSS points + EPSS points + KEV bonus + tool + credential + agent breadth.
 */
export function reachFormula(b: ReachBreakdown): string {
  const cvssPoints = (Math.max(0, Math.min(b.cvss, 10)) / 10) * 30;
  const epssPoints = Math.max(0, Math.min(b.epss, 1)) * 20;
  const kevPoints = b.is_kev ? 40 : 0;
  const toolPoints = Math.max(0, Math.min(b.tool_capability, 1)) * 25;
  const credPoints = Math.max(0, Math.min(b.cred_visibility, 1)) * 20;
  const agentPoints = Math.max(0, Math.min(b.agent_breadth, 5)) * 5;
  return [
    `CVSS ${cvssPoints.toFixed(1)}`,
    `EPSS ${epssPoints.toFixed(1)}`,
    `KEV +${kevPoints.toFixed(0)}`,
    `tool ${toolPoints.toFixed(1)}`,
    `cred ${credPoints.toFixed(1)}`,
    `agents ${agentPoints.toFixed(1)}`,
  ].join(" + ") + ` = ${b.composite.toFixed(1)}`;
}

function stringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((entry): entry is string => typeof entry === "string");
}
