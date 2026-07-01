WITH node_digest AS (
  SELECT COUNT(*) AS node_count,
         md5(COALESCE(string_agg(id || ':' || entity_type || ':' || label || ':' ||
             COALESCE(severity, '') || ':' || COALESCE(risk_score::text, '0'), '|' ORDER BY id), '')) AS digest
  FROM graph_nodes
  WHERE tenant_id = 'default' AND scan_id = 'graph-benchmark-estate-current'
),
edge_digest AS (
  SELECT COUNT(*) AS edge_count,
         md5(COALESCE(string_agg(source_id || '>' || target_id || ':' || relationship || ':' ||
             COALESCE(weight::text, '0') || ':' || COALESCE(confidence::text, '1'), '|'
             ORDER BY source_id, target_id, relationship), '')) AS digest
  FROM graph_edges
  WHERE tenant_id = 'default' AND scan_id = 'graph-benchmark-estate-current'
),
finding_digest AS (
  SELECT COUNT(*) AS finding_count,
         md5(COALESCE(string_agg(id || ':' || entity_type || ':' || COALESCE(severity, ''), '|' ORDER BY id), '')) AS digest
  FROM graph_nodes
  WHERE tenant_id = 'default'
    AND scan_id = 'graph-benchmark-estate-current'
    AND entity_type IN ('vulnerability', 'misconfiguration', 'drift_incident')
)
SELECT 'graph-benchmark-estate-current' AS scan_id,
       node_digest.node_count,
       edge_digest.edge_count,
       finding_digest.finding_count,
       md5(node_digest.digest || ':' || edge_digest.digest) AS graph_digest,
       finding_digest.digest AS findings_digest
FROM node_digest, edge_digest, finding_digest;
