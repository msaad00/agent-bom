EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT COALESCE(new_nodes.id, old_nodes.id) AS node_id,
       CASE
         WHEN old_nodes.id IS NULL THEN 'added'
         WHEN new_nodes.id IS NULL THEN 'removed'
         WHEN old_nodes.attributes <> new_nodes.attributes THEN 'changed'
         ELSE 'same'
       END AS diff_state
FROM (
  SELECT id, attributes FROM graph_nodes
  WHERE tenant_id = 'default' AND scan_id = 'graph-benchmark-estate-old'
) old_nodes
FULL OUTER JOIN (
  SELECT id, attributes FROM graph_nodes
  WHERE tenant_id = 'default' AND scan_id = 'graph-benchmark-estate-current'
) new_nodes USING (id)
WHERE old_nodes.id IS NULL
   OR new_nodes.id IS NULL
   OR old_nodes.attributes <> new_nodes.attributes
LIMIT 500;
