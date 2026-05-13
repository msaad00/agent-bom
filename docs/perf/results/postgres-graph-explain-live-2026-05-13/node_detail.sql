EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT source_id, target_id, relationship, direction, weight, traversable
FROM graph_edges
WHERE tenant_id = 'default'
  AND scan_id = 'graph-benchmark-estate-current'
  AND (source_id = 'pkg:go:langchain@1.0.0' OR target_id = 'pkg:go:langchain@1.0.0');
