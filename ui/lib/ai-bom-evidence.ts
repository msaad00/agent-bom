import type { AgentBomManifestResponse, PostureCountsResponse } from "@/lib/api";
import { deploymentModeLabel } from "@/lib/deployment-context";

export type AiBomEvidenceSource = {
  id: string;
  label: string;
  detail: string;
  active: boolean;
  href?: string;
};

export type AiBomEntityRollup = {
  agents: number;
  mcpServers: number;
  models: number;
  frameworks: number;
  packages: number;
  credentials: number;
  cloudAssets: number;
  findings: number;
};

export function aiBomScopeLabel(
  counts: PostureCountsResponse | null,
  manifest: AgentBomManifestResponse | null,
): string {
  const mode = deploymentModeLabel(counts?.deployment_mode);
  const tenant = manifest?.tenant_id?.trim() || "default";
  const source = manifest?.source === "control-plane" ? "control plane" : "local discovery";
  return `${mode} · tenant ${tenant} · ${source}`;
}

export function deriveAiBomEvidenceSources(
  counts: PostureCountsResponse | null,
  manifest: AgentBomManifestResponse | null,
): AiBomEvidenceSource[] {
  const scanSources = new Set((counts?.scan_sources ?? []).map((source) => source.toLowerCase()));
  const hasCloudScan = ["aws", "azure", "gcp", "snowflake", "databricks"].some((provider) =>
    [...scanSources].some((source) => source.includes(provider)),
  );

  return [
    {
      id: "workstation",
      label: "Workstation agents",
      detail: "Local MCP and agent project discovery",
      active: Boolean(counts?.has_local_scan || counts?.has_agent_context || manifest?.summary.agents),
      href: "/agents",
    },
    {
      id: "fleet",
      label: "Fleet endpoints",
      detail: "Laptops, VMs, and collectors pushing inventory",
      active: Boolean(counts?.has_fleet_ingest),
      href: "/fleet",
    },
    {
      id: "cloud",
      label: "Cloud AI services",
      detail: "Connected accounts for models, endpoints, and managed AI",
      active: hasCloudScan || Boolean(counts?.services && Object.keys(counts.services).length > 0),
      href: "/connections",
    },
    {
      id: "cluster",
      label: "Kubernetes",
      detail: "Cluster scans for pods, images, and runtime AI workloads",
      active: Boolean(counts?.has_cluster_scan),
      href: "/scan",
    },
    {
      id: "runtime",
      label: "Runtime enforcement",
      detail: "Proxy, gateway, and trace observations",
      active: Boolean(counts?.has_proxy || counts?.has_gateway || counts?.has_traces),
      href: "/runtime",
    },
    {
      id: "control-plane",
      label: "Control-plane manifest",
      detail: "Tenant-scoped Agent BOM assembled from fleet + runtime stores",
      active: Boolean(manifest),
      href: "/manifest",
    },
  ];
}

export function summarizeAiBomEntities(
  manifest: AgentBomManifestResponse | null,
): AiBomEntityRollup {
  const nodes = manifest?.graph.nodes ?? [];
  const byType = nodes.reduce<Record<string, number>>((acc, node) => {
    const key = node.entity_type.toLowerCase();
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});

  return {
    agents: manifest?.summary.agents ?? byType.agent ?? 0,
    mcpServers: manifest?.summary.mcp_servers ?? byType.server ?? 0,
    models: byType.model ?? 0,
    frameworks: byType.framework ?? 0,
    packages: byType.package ?? 0,
    credentials: manifest?.summary.credential_refs ?? byType.credential ?? 0,
    cloudAssets: (byType.cloud_resource ?? 0) + (byType.cloudresource ?? 0) + (byType.container ?? 0),
    findings: (byType.vulnerability ?? 0) + (byType.misconfiguration ?? 0),
  };
}

export function countActiveEvidenceSources(sources: AiBomEvidenceSource[]): number {
  return sources.filter((source) => source.active).length;
}
