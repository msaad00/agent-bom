EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT source_node, target_node, hop_count, composite_risk, path_nodes, path_edges
FROM attack_paths
WHERE tenant_id = 'default'
  AND scan_id = 'graph-benchmark-estate-current'
  AND source_node = 'agent:agent-00000'
ORDER BY composite_risk DESC
LIMIT 100;
