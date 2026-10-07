export type SecurityGraphSurface = "estate" | "attack-path" | "graph";

/**
 * Resolve the composed investigation surface without treating a scan selector
 * as a different surface. Ranked exposure paths are the default; explicit
 * lenses preserve estate browsing and previously shared finding links.
 */
export function resolveSecurityGraphSurface(params: {
  get(name: string): string | null;
}): SecurityGraphSurface {
  const lens = params.get("lens")?.trim();
  if (lens === "attack-path") return "attack-path";
  if (lens === "estate") return "estate";
  if (lens) return "graph";

  return "attack-path";
}
