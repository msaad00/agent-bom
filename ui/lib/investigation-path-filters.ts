/**
 * Filter ranked attack paths for the investigation portfolio chips
 * (severity · layer · evidence_tier · environment).
 */

import type { InvestigationPresetFilters } from "@/components/graph-preset-controls";
import { exposureSeverityRank } from "@/lib/exposure-path";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";
import { GRAPH_NODE_KIND_META, type GraphNodeKindKey } from "@/lib/graph-schema";

function nodeKindKey(entityType: string): GraphNodeKindKey | null {
  const normalized = entityType.trim().toLowerCase().replaceAll("-", "_");
  if (normalized in GRAPH_NODE_KIND_META) {
    return normalized as GraphNodeKindKey;
  }
  return null;
}

function pathSeverity(path: AttackPath, nodeById: Map<string, UnifiedNode>): string {
  // The server's finding severity is independent of the path priority scale.
  if (path.severity !== undefined) return path.severity.toLowerCase();
  const findings = path.hops.flatMap(id => {
    const node = nodeById.get(id);
    return node && ["vulnerability", "misconfiguration"].includes(String(node.entity_type))
      && ["critical", "high", "medium", "low", "none"].includes(node.severity.toLowerCase()) ? [node.severity.toLowerCase()] : [];
  });
  return findings.sort((a, b) => exposureSeverityRank(b) - exposureSeverityRank(a))[0] ?? "unknown";
}

function hopEvidenceTier(
  node: UnifiedNode | undefined,
): string | null {
  if (!node) return null;
  const attrs = node.attributes ?? {};
  const tier = attrs.evidence_tier ?? attrs.tier;
  return typeof tier === "string" ? tier.toLowerCase() : null;
}

function hopEnvironment(node: UnifiedNode | undefined): string | null {
  if (!node) return null;
  const attrs = node.attributes ?? {};
  const env = node.dimensions?.environment || attrs.environment || attrs.env;
  return typeof env === "string" && env.length > 0 ? env : null;
}

export function collectPathEnvironments(
  paths: AttackPath[],
  nodeById: Map<string, UnifiedNode>,
): string[] {
  const found = new Set<string>();
  for (const path of paths) {
    for (const hop of path.hops) {
      const env = hopEnvironment(nodeById.get(hop));
      if (env) found.add(env);
    }
  }
  return [...found].sort((a, b) => a.localeCompare(b));
}

export function filterAttackPathsForInvestigation(
  paths: AttackPath[],
  nodeById: Map<string, UnifiedNode>,
  filters: InvestigationPresetFilters,
): AttackPath[] {
  const hasAny =
    filters.severity || filters.layer || filters.evidenceTier || filters.environment;
  if (!hasAny) return paths;

  return paths.filter((path) => {
    if (filters.severity && pathSeverity(path, nodeById) !== filters.severity.toLowerCase()) {
      return false;
    }

    const hopNodes = path.hops
      .map((hop) => nodeById.get(hop))
      .filter((node): node is UnifiedNode => Boolean(node));

    if (filters.layer) {
      const layerMatch = hopNodes.some((node) => {
        const kind = nodeKindKey(String(node.entity_type));
        return kind ? GRAPH_NODE_KIND_META[kind].layer === filters.layer : false;
      });
      if (!layerMatch) return false;
    }

    if (filters.evidenceTier) {
      const evidenceMatch = hopNodes.some(
        (node) => hopEvidenceTier(node) === filters.evidenceTier!.toLowerCase(),
      );
      if (!evidenceMatch) return false;
    }

    if (filters.environment) {
      const envMatch = hopNodes.some(
        (node) => hopEnvironment(node) === filters.environment,
      );
      if (!envMatch) return false;
    }

    return true;
  });
}
