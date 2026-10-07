import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";

// A synthetic permission chain for renderer mechanics. It is not product proof.
const ids = ["agent:test", "identity:test", "data-store:test"] as const;
const relationships = ["authenticates_as", "has_permission"];
const stamp = "2026-08-30T04:00:00Z";
export const selectedPathFixture = {
  scan_id: "synthetic-path-test", tenant_id: "test-tenant", created_at: stamp,
  nodes: ids.map((id, index) => ({
    id, entity_type: ["agent", "service_account", "data_store"][index], label: id,
    category_uid: 0, class_uid: 0, type_uid: 0, status: "active", severity: "none", severity_id: 0,
    risk_score: 0, attributes: {}, dimensions: {}, compliance_tags: [], data_sources: ["synthetic-test"],
    first_seen: stamp, last_seen: stamp,
  })),
  edges: relationships.map((relationship, index) => ({
    id: `test-edge-${index}`, source: ids[index], target: ids[index + 1], relationship,
    direction: "directed", traversable: true, weight: 1, activity_id: 1, evidence: { modeled: true },
    first_seen: stamp, last_seen: stamp,
  })),
  interaction_risks: [],
  attack_paths: [{
    source: ids[0], target: ids[2], hops: [...ids], edges: relationships, composite_risk: 0,
    summary: "Synthetic selected-path rendering fixture", reachability: "unknown",
    vuln_ids: [], credential_exposure: [], tool_exposure: [],
    hop_evidence: relationships.map((relationship, index) => ({
      source_node_id: ids[index], target_node_id: ids[index + 1], relationship,
      complete: true, direction: "directed", traversable: true, evidence_tier: "modeled_infrastructure",
      source_snapshot_ids: ["synthetic-path-test"], runtime_observed_state: "not_observed",
      confidence: 1, freshness: "fresh", truncated: false,
    })),
  } as AttackPath],
  stats: { total_nodes: 3, total_edges: 2, node_types: { agent: 1, service_account: 1, data_store: 1 },
    severity_counts: { none: 3 }, relationship_types: { authenticates_as: 1, has_permission: 1 },
    attack_path_count: 1, interaction_risk_count: 0, max_attack_path_risk: 0, highest_interaction_risk: 0 },
} as UnifiedGraphData;
