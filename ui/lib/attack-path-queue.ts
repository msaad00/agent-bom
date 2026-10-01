import type { AttackPath, UnifiedNode } from "./graph-schema";
import { matchesAttackPathFocus, type AttackPathFocus } from "./attack-paths";

/** The server orders the occurrence queue by evidence, then risk. Enrichment
 * cards must not reorder it or introduce occurrences outside the current page. */
export function selectAttackPathQueue(
  page: AttackPath[] | undefined,
  fallback: AttackPath[],
  nodes: Map<string, UnifiedNode>,
  focus: AttackPathFocus,
  campaignMembers?: string[],
): AttackPath[] {
  const members = campaignMembers?.length ? new Set(campaignMembers) : null;
  const hasFocus = [focus.cve, focus.packageName, focus.agentName, focus.nodeId, focus.findingId].some(value => value?.trim());
  return (page ?? fallback).filter((path) =>
    (!hasFocus || matchesAttackPathFocus(path, nodes, focus))
    && (!members || members.has(`${path.source}->${path.target}`)),
  );
}
