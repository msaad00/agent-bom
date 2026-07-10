export type PageLane =
  | "command"
  | "ai-estate"
  | "cloud-data"
  | "runtime"
  | "governance"
  | "reference"
  | "operations";

export const PAGE_LANE_META: Record<
  PageLane,
  { label: string; scope: string; accent: string }
> = {
  command: { label: "Command", scope: "Posture & paths", accent: "#58a6ff" },
  "ai-estate": { label: "AI inventory", scope: "Local · Your agents", accent: "#3fb950" },
  "cloud-data": { label: "Cloud & Data", scope: "Cloud · Read-only", accent: "#a371f7" },
  runtime: { label: "Runtime", scope: "Live · Enforced", accent: "#f778ba" },
  governance: { label: "Governance", scope: "Policy & evidence", accent: "#3fb950" },
  reference: { label: "Reference", scope: "Catalog · Not yours", accent: "#d29922" },
  operations: { label: "Operations", scope: "AI usage · Jobs", accent: "#db6d28" },
};

const PATH_TO_LANE: Record<string, PageLane> = {
  "/": "command",
  "/findings": "command",
  "/security-graph": "command",
  "/remediation": "command",
  "/graph": "command",
  "/mesh": "command",
  "/context": "command",
  "/agents": "ai-estate",
  "/manifest": "ai-estate",
  "/fleet": "ai-estate",
  "/connections": "cloud-data",
  "/sources": "cloud-data",
  "/scan": "cloud-data",
  "/identity": "cloud-data",
  "/drift": "cloud-data",
  "/runtime": "runtime",
  "/traces": "runtime",
  "/compliance": "governance",
  "/governance": "governance",
  "/audit": "governance",
  "/registry": "reference",
  "/cost": "operations",
  "/jobs": "operations",
  "/activity": "operations",
};

export function laneForPath(path: string): PageLane | null {
  if (PATH_TO_LANE[path]) {
    return PATH_TO_LANE[path]!;
  }
  const match = Object.keys(PATH_TO_LANE)
    .filter((prefix) => prefix !== "/")
    .sort((a, b) => b.length - a.length)
    .find((prefix) => path.startsWith(prefix));
  return match ? PATH_TO_LANE[match]! : null;
}
