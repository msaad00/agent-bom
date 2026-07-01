SELECT scan_id, created_at, node_count, edge_count,
       LAG(scan_id) OVER (ORDER BY created_at ASC, scan_id ASC) AS diff_baseline_scan_id
FROM graph_snapshots
WHERE tenant_id = 'default'
ORDER BY created_at DESC, scan_id DESC
LIMIT 50;
