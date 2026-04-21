import type { DeploymentMode, PostureCountsResponse } from "@/lib/api";

export type DeploymentSurface =
  | "agents"
  | "fleet"
  | "mesh"
  | "context"
  | "proxy"
  | "gateway"
  | "traces"
  | "audit";

interface DeploymentSurfaceDefinition {
  label: string;
  navHref: string;
  isAvailable: (counts: PostureCountsResponse | null) => boolean;
  requirement: string;
  command: string;
  capabilities: string[];
  summary: (mode: string) => string;
}

function bool(value: boolean | undefined): boolean {
  return Boolean(value);
}

export function deploymentModeLabel(mode?: DeploymentMode): string {
  switch (mode) {
    case "fleet":
      return "Fleet";
    case "cluster":
      return "Cluster";
    case "hybrid":
      return "Hybrid";
    case "local":
    default:
      return "Local";
  }
}

export function hasDeploymentSignals(counts: PostureCountsResponse | null): boolean {
  if (!counts) return false;
  return Boolean(
    (counts.scan_count ?? 0) > 0 ||
      counts.has_local_scan ||
      counts.has_fleet_ingest ||
      counts.has_cluster_scan ||
      counts.has_ci_cd_scan ||
      counts.has_mesh ||
      counts.has_gateway ||
      counts.has_proxy ||
      counts.has_traces ||
      counts.has_registry,
  );
}

const SURFACE_DEFINITIONS: Record<DeploymentSurface, DeploymentSurfaceDefinition> = {
  agents: {
    label: "Agents",
    navHref: "/agents",
    isAvailable: (counts) => bool(counts?.has_local_scan),
    requirement: "Local agent discovery or workstation scan evidence",
    command: "agent-bom agents --push-url https://<control-plane>/v1/fleet/sync",
    capabilities: [
      "Local MCP config-file discovery from developer workstations",
      "Configured agent inventory with attached MCP servers",
      "Agent detail views sourced from local scan output",
    ],
    summary: (mode) =>
      `The Agents page is populated by local workstation discovery. Your current deployment mode is ${mode}, so this surface stays empty until local agent scans are pushed into the control plane.`,
  },
  fleet: {
    label: "Fleet",
    navHref: "/fleet",
    isAvailable: (counts) => bool(counts?.has_fleet_ingest),
    requirement: "Persisted fleet ingest from endpoints or collectors",
    command: "agent-bom agents --push-url https://<control-plane>/v1/fleet/sync",
    capabilities: [
      "Tenant-scoped fleet inventory with lifecycle and trust score",
      "Fleet sync state for laptops, workstations, and collectors",
      "Persisted endpoint evidence separate from one-off local scans",
    ],
    summary: (mode) =>
      `The Fleet page is populated by persisted endpoint sync, not by standalone local scans. Your current deployment mode is ${mode}, so this surface remains empty until fleet ingest is enabled.`,
  },
  mesh: {
    label: "Agent Mesh",
    navHref: "/mesh",
    isAvailable: (counts) => bool(counts?.has_mesh),
    requirement: "Completed scans with agent and runtime relationship context",
    command: "agent-bom scan --introspect --preset enterprise",
    capabilities: [
      "Shared infrastructure across agents, tools, packages, and findings",
      "Highest-risk agent defaults and mesh-wide overlap analysis",
      "Runtime-aware graph exploration instead of a raw scan list",
    ],
    summary: (mode) =>
      `The Agent Mesh needs relationship-rich scan data. Your current deployment mode is ${mode}, so this page stays empty until scans produce mesh context for agents, workloads, or fleet inventory.`,
  },
  context: {
    label: "Context Map",
    navHref: "/context",
    isAvailable: (counts) => bool(counts?.has_mcp_context),
    requirement: "MCP and agent context from completed scans",
    command: "agent-bom scan --introspect --preset enterprise",
    capabilities: [
      "Lateral path analysis across agents, credentials, tools, and servers",
      "Context graph stats for shared credentials and shared servers",
      "Direct drilldown into MCP interaction risk instead of raw findings only",
    ],
    summary: (mode) =>
      `The Context Map is built from MCP-aware scan results. Your current deployment mode is ${mode}, so this page stays empty until scans collect agent and MCP context.`,
  },
  proxy: {
    label: "Proxy",
    navHref: "/proxy",
    isAvailable: (counts) => bool(counts?.has_proxy),
    requirement: "Runtime proxy audit or detector telemetry",
    command: "agent-bom proxy --help",
    capabilities: [
      "Runtime MCP proxy alerts and detector activity",
      "Live tool-call blocking and severity breakdowns",
      "Proxy-specific metrics separate from control-plane-only scans",
    ],
    summary: (mode) =>
      `The Proxy dashboard is only populated when runtime proxy telemetry is present. Your current deployment mode is ${mode}, so this surface is idle until proxy enforcement is enabled.`,
  },
  gateway: {
    label: "Gateway",
    navHref: "/gateway",
    isAvailable: (counts) => bool(counts?.has_gateway),
    requirement: "Gateway policy usage or managed runtime policy state",
    command: "helm upgrade --install agent-bom deploy/helm/agent-bom --set gateway.enabled=true",
    capabilities: [
      "Central gateway policy inventory and evaluation",
      "Gateway audit entries tied to runtime enforcement",
      "A shared relay/policy surface for cluster or hybrid MCP traffic",
    ],
    summary: (mode) =>
      `The Gateway page becomes active when the shared runtime gateway is in use. Your current deployment mode is ${mode}, so this surface remains optional until gateway policy management is enabled.`,
  },
  traces: {
    label: "Traces",
    navHref: "/traces",
    isAvailable: (counts) => bool(counts?.has_traces),
    requirement: "Runtime trace payloads or proxy/gateway telemetry",
    command: "POST /v1/traces with MCP or runtime correlation payloads",
    capabilities: [
      "Trace-to-asset correlation for runtime MCP traffic",
      "Flagged call review against vulnerable packages and servers",
      "Manual or pipeline-fed runtime evidence beyond static scans",
    ],
    summary: (mode) =>
      `The Traces page needs runtime telemetry, not just stored scan results. Your current deployment mode is ${mode}, so this surface stays empty until traces or proxy/gateway telemetry are pushed in.`,
  },
  audit: {
    label: "Audit Log",
    navHref: "/audit",
    isAvailable: (counts) => bool(counts?.has_proxy || counts?.has_gateway || counts?.has_traces),
    requirement: "Runtime or control-plane audit activity",
    command: "Enable proxy, gateway, or runtime audit push into the control plane",
    capabilities: [
      "Tamper-evident audit records for runtime and policy actions",
      "Cross-surface activity review across proxy, gateway, and fleet actions",
      "Integrity status for operator-visible audit history",
    ],
    summary: (mode) =>
      `The Audit Log becomes useful when runtime or policy surfaces emit audit events. Your current deployment mode is ${mode}, so this page stays quiet until those surfaces are active.`,
  },
};

export function deploymentSurfaceForHref(href: string): DeploymentSurface | null {
  const normalized = href === "/vulns" ? "/findings" : href;
  const match = Object.entries(SURFACE_DEFINITIONS).find(([, definition]) => definition.navHref === normalized);
  return (match?.[0] as DeploymentSurface | undefined) ?? null;
}

export function isDeploymentSurfaceAvailable(
  surface: DeploymentSurface,
  counts: PostureCountsResponse | null,
): boolean {
  if (!counts) return true;
  return SURFACE_DEFINITIONS[surface].isAvailable(counts);
}

export function isNavLinkVisible(href: string, counts: PostureCountsResponse | null): boolean {
  if (!hasDeploymentSignals(counts)) return true;
  const surface = deploymentSurfaceForHref(href);
  if (!surface) return true;
  return isDeploymentSurfaceAvailable(surface, counts);
}

export function getDeploymentSurfaceState(
  surface: DeploymentSurface,
  counts: PostureCountsResponse | null,
  detail?: string | null,
) {
  const definition = SURFACE_DEFINITIONS[surface];
  const mode = deploymentModeLabel(counts?.deployment_mode);
  return {
    title: `${definition.label} is not active in this deployment`,
    summary: definition.summary(mode),
    requirement: definition.requirement,
    command: definition.command,
    capabilities: definition.capabilities,
    detail,
  };
}
