/**
 * Estate roll-up is the default graph entry for snapshots at the scale
 * threshold. Smaller snapshots lead with their real relationship topology.
 */

export type GraphRollupUrlPreference = "default" | "force" | "off";
export type GraphRollupCanvasMode = "raw" | "loading" | "active";

export function parseGraphRollupUrlPreference(
  params: URLSearchParams | { get(name: string): string | null },
): GraphRollupUrlPreference {
  const rollup = params.get("rollup");
  if (rollup === "0" || rollup === "false") return "off";
  if (rollup === "1" || rollup === "true") return "force";
  return "default";
}

/** Only an explicit URL/operator opt-out dismisses roll-up navigation. */
export function rollupDismissedForPreference(
  preference: GraphRollupUrlPreference,
): boolean {
  return preference === "off";
}

/** Keep raw topology off-canvas while an eligible roll-up request is pending. */
export function graphRollupCanvasMode(input: {
  eligible: boolean;
  dismissed: boolean;
  hasView: boolean;
  unavailable: boolean;
  failed: boolean;
}): GraphRollupCanvasMode {
  if (!input.eligible || input.dismissed) return "raw";
  if (input.hasView) return "active";
  if (input.unavailable || input.failed) return "raw";
  return "loading";
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
  estateNodeCount: number;
  investigationMode: boolean;
  selectedAttackPath: boolean;
  reachabilityActive: boolean;
  blastRadiusActive: boolean;
  /** Retained for call-site compatibility; availability alone does not select a path. */
  attackPathCount?: number;
}

export const DEFAULT_GRAPH_ROLLUP_NODE_THRESHOLD = 200;

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
  // An explicit `?rollup=1` is an operator decision, but detail overlays above
  // still require their focused node set.
  if (input.rollupPreference === "force") return true;
  return input.estateNodeCount >= DEFAULT_GRAPH_ROLLUP_NODE_THRESHOLD;
}

export function rollupViewHasContainers(
  mode: "rollup" | "drilldown" | "attack_path",
  topLevel: unknown[] | undefined,
  children: unknown[] | undefined,
): boolean {
  const items = mode === "drilldown" ? children : topLevel;
  return Array.isArray(items) && items.length > 0;
}
