EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT gn.id, gn.entity_type, gn.label, gn.severity_id, gn.risk_score
FROM graph_node_search gns
JOIN graph_nodes gn
  ON gn.id = gns.node_id
 AND gn.scan_id = gns.scan_id
 AND gn.tenant_id = gns.tenant_id
WHERE gns.tenant_id = 'default'
  AND gns.scan_id = 'graph-benchmark-estate-current'
  AND LOWER(gns.search_text) LIKE '%langchain%'
ORDER BY gn.severity_id DESC, gn.risk_score DESC, gn.label ASC, gn.id ASC
LIMIT 50;
