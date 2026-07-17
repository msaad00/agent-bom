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

/** Drill-down container id persisted in shareable graph URLs. */
export function parseRollupNodeParam(
  params: URLSearchParams | { get(name: string): string | null },
): string | null {
  const node = params.get("rollup_node")?.trim();
  return node || null;
}

export interface GraphRollupEligibilityInput {
  hasSelectedScan: boolean;
  rollupPreference: GraphRollupUrlPreference;
  rollupDismissed: boolean;
  investigationMode: boolean;
  selectedAttackPath: boolean;
  reachabilityActive: boolean;
  blastRadiusActive: boolean;
  /** When ranked attack paths exist, prefer path-focused canvas over roll-up. */
  attackPathCount?: number;
}

/** Whether the graph should fetch and prefer the CONTAINS roll-up view. */
export function graphRollupEligible(input: GraphRollupEligibilityInput): boolean {
  if (!input.hasSelectedScan) return false;
  if (input.rollupPreference === "off" || input.rollupDismissed) return false;
  // Detail overlays require their focused/raw node set regardless of the
  // estate default or an explicit cluster preference.
  if (input.investigationMode) return false;
  if (input.selectedAttackPath) return false;
  if (input.reachabilityActive) return false;
  if (input.blastRadiusActive) return false;
  // An explicit `?rollup=1` is an operator decision. It must win over the
  // automatic attack-path-count default, but not the detail overlays above.
  if (input.rollupPreference === "force") return true;
  if ((input.attackPathCount ?? 0) > 0) return false;
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
