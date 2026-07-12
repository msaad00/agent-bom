import type { PageStateAction } from "@/components/states/page-state";

export const CONNECT_CLOUD_ACTION: PageStateAction = {
  label: "Connect cloud",
  href: "/connections",
};

// Canonical scan entry point: "New Scan" opens the /scan configurator.
// (Use "Run scan" only for actions that execute immediately on a scoped target.)
export const RUN_SCAN_ACTION: PageStateAction = {
  label: "New Scan",
  href: "/scan",
};

export const OPEN_SECURITY_GRAPH_ACTION: PageStateAction = {
  label: "Open graph",
  href: "/security-graph",
  variant: "secondary",
};

export const OPEN_FINDINGS_ACTION: PageStateAction = {
  label: "Open findings",
  href: "/findings",
  variant: "secondary",
};

export const FIRST_SCAN_ACTIONS: PageStateAction[] = [
  RUN_SCAN_ACTION,
  CONNECT_CLOUD_ACTION,
  OPEN_SECURITY_GRAPH_ACTION,
];

export const FIRST_EVIDENCE_ACTIONS: PageStateAction[] = [
  RUN_SCAN_ACTION,
  CONNECT_CLOUD_ACTION,
  OPEN_FINDINGS_ACTION,
];
