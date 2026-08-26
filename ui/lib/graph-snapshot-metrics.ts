type SnapshotAttackPathCountInput = {
  pageTotal: number | null | undefined;
  statsTotal: number | null | undefined;
  returnedPaths: number;
};

/**
 * Keep bounded API pages from masquerading as snapshot totals in the graph UI.
 */
export function resolveSnapshotAttackPathCount({
  pageTotal,
  statsTotal,
  returnedPaths,
}: SnapshotAttackPathCountInput): number {
  return pageTotal ?? statsTotal ?? returnedPaths;
}
