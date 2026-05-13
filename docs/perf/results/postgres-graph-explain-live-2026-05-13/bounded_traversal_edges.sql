EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
WITH RECURSIVE walk(node_id, depth) AS (
  SELECT 'agent:agent-00000'::text, 0
  UNION ALL
  SELECT e.target_id, walk.depth + 1
  FROM walk
  JOIN graph_edges e
    ON e.tenant_id = 'default'
   AND e.scan_id = 'graph-benchmark-estate-current'
   AND e.source_id = walk.node_id
   AND e.traversable = 1
  WHERE walk.depth < 3
)
SELECT DISTINCT node_id, depth
FROM walk
LIMIT 500;
