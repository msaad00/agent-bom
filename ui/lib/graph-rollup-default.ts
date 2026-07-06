/**
 * Estate roll-up is the default graph entry when a snapshot is loaded.
 * Operators opt out with `?rollup=0` or "Show full graph".
 */

export type GraphRollupUrlPreference = "default" | "force" | "off";

export function parseGraphRollupUrlPreference(
  params: URLSearchParams | { get(name: string): string | null },
): GraphRollupUrlPreference {
  const rollup = params.get("rollup");
  if (rollup === "0" || rollup === "false") return "off";
  if (rollup === "1" || rollup === "true") return "force";
  return "default";
}

export interface GraphRollupEligibilityInput {
  hasSelectedScan: boolean;
  rollupPreference: GraphRollupUrlPreference;
  rollupDismissed: boolean;
  investigationMode: boolean;
  selectedAttackPath: boolean;
  reachabilityActive: boolean;
  blastRadiusActive: boolean;
}

/** Whether the graph should fetch and prefer the CONTAINS roll-up view. */
export function graphRollupEligible(input: GraphRollupEligibilityInput): boolean {
  if (!input.hasSelectedScan) return false;
  if (input.rollupPreference === "off" || input.rollupDismissed) return false;
  if (input.investigationMode) return false;
  if (input.selectedAttackPath) return false;
  if (input.reachabilityActive) return false;
  if (input.blastRadiusActive) return false;
  return true;
}

export function rollupViewHasContainers(
  mode: "rollup" | "drilldown" | "attack_path",
  topLevel: unknown[] | undefined,
  children: unknown[] | undefined,
): boolean {
  const items = mode === "drilldown" ? children : topLevel;
  return Array.isArray(items) && items.length > 0;
}
