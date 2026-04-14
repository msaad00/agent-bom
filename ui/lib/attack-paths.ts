import { EntityType, type AttackPath, type UnifiedNode } from "./graph-schema";

export type AttackPathCardNode = {
  type: "cve" | "package" | "server" | "agent" | "credential";
  label: string;
  severity?: string;
};

export function attackPathKey(path: AttackPath): string {
  return `${path.source}::${path.target}::${path.hops.join("->")}`;
}

export function mapAttackPathNodeType(entityType: string): AttackPathCardNode["type"] | null {
  switch (entityType) {
    case EntityType.VULNERABILITY:
    case EntityType.MISCONFIGURATION:
      return "cve";
    case EntityType.PACKAGE:
      return "package";
    case EntityType.SERVER:
    case EntityType.CONTAINER:
    case EntityType.CLOUD_RESOURCE:
      return "server";
    case EntityType.AGENT:
    case EntityType.USER:
    case EntityType.GROUP:
    case EntityType.SERVICE_ACCOUNT:
      return "agent";
    case EntityType.CREDENTIAL:
      return "credential";
    default:
      return null;
  }
}

export function toAttackCardNodes(path: AttackPath, nodeById: Map<string, UnifiedNode>): AttackPathCardNode[] {
  const nodes: AttackPathCardNode[] = [];
  for (const hop of path.hops) {
    const node = nodeById.get(hop);
    if (!node) continue;
    const type = mapAttackPathNodeType(String(node.entity_type));
    if (!type) continue;
    nodes.push({
      type,
      label: node.label,
      severity: node.severity,
    });
  }
  return nodes;
}
