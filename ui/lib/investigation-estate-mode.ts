const LARGE_ESTATE_NODE_THRESHOLD = 1_000;

export interface InvestigationEstateMode {
  large: boolean;
  summary: string;
  clusteredHref: string;
  rawHref: string;
}

export function investigationEstateMode(nodeCount: number, scanId?: string): InvestigationEstateMode {
  const params = new URLSearchParams();
  if (scanId) params.set("scan", scanId);
  params.set("lens", "lineage");
  params.set("rollup", "1");
  const clusteredHref = `/security-graph?${params.toString()}`;
  params.set("rollup", "0");

  return {
    large: nodeCount >= LARGE_ESTATE_NODE_THRESHOLD,
    summary: `${nodeCount.toLocaleString("en-US")} nodes`,
    clusteredHref,
    rawHref: `/security-graph?${params.toString()}`,
  };
}
