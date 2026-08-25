export type SecurityGraphSurface = "estate" | "attack-path" | "graph";

const LEGACY_ATTACK_PATH_FOCUS_KEYS = [
  "agent",
  "cve",
  "finding",
  "node",
  "package",
  "trace",
] as const;

/**
 * Resolve the composed investigation surface without treating a scan selector
 * as attack-path focus. New links should set a lens explicitly; focus-key
 * inference exists only so previously shared finding links remain stable.
 */
export function resolveSecurityGraphSurface(params: {
  get(name: string): string | null;
}): SecurityGraphSurface {
  const lens = params.get("lens")?.trim();
  if (lens === "attack-path") return "attack-path";
  if (lens === "estate") return "estate";
  if (lens) return "graph";

  const hasLegacyAttackPathFocus = LEGACY_ATTACK_PATH_FOCUS_KEYS.some((key) =>
    Boolean(params.get(key)?.trim()),
  );
  return hasLegacyAttackPathFocus ? "attack-path" : "estate";
}
