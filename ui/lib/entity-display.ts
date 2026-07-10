import type { ExposureEntityRole } from "@/lib/exposure-path";
import {
  formatInventoryAgentLabel,
  topologyAgentTypeLabel,
} from "@/lib/agent-topology-graph";

const SERVER_VENDOR_LABELS: Record<string, string> = {
  github: "GitHub",
  gitlab: "GitLab",
  slack: "Slack",
  jira: "Jira",
  postgres: "PostgreSQL",
  snowflake: "Snowflake",
  kubernetes: "Kubernetes",
  docker: "Docker",
  aws: "AWS",
  azure: "Azure",
  gcp: "Google Cloud",
};

export type EntityDisplayParts = {
  title: string;
  subtitle?: string | undefined;
};

function normalizeKey(value: string): string {
  return value.trim().toLowerCase();
}

function titleCaseWords(value: string): string {
  return value
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function parsePackageLabel(label: string): { name: string; version?: string } {
  const at = label.lastIndexOf("@");
  if (at > 0) {
    return {
      name: label.slice(0, at),
      version: label.slice(at + 1),
    };
  }
  return { name: label };
}

export function formatExposureEntityDisplay(
  label: string,
  role: ExposureEntityRole,
  attributes: Record<string, unknown> = {},
): EntityDisplayParts {
  const trimmed = label.trim();
  if (!trimmed) return { title: "Unknown entity" };

  switch (role) {
    case "agent": {
      const agentType =
        typeof attributes.agent_type === "string" ? attributes.agent_type : undefined;
      return {
        title: formatInventoryAgentLabel(trimmed),
        subtitle: agentType ? topologyAgentTypeLabel(agentType) : "AI agent runtime",
      };
    }
    case "server": {
      const key = normalizeKey(trimmed);
      const vendor = SERVER_VENDOR_LABELS[key];
      const transport =
        typeof attributes.transport === "string" ? attributes.transport : undefined;
      return {
        title: vendor ? `${vendor} connector` : `${titleCaseWords(trimmed)} service`,
        subtitle: transport ? `${transport} MCP server` : "MCP server",
      };
    }
    case "package": {
      const parsed = parsePackageLabel(trimmed);
      const ecosystem =
        typeof attributes.ecosystem === "string" ? attributes.ecosystem : undefined;
      return {
        title: parsed.name,
        subtitle: [parsed.version ? `v${parsed.version}` : null, ecosystem?.toUpperCase()]
          .filter(Boolean)
          .join(" · "),
      };
    }
    case "finding":
      return {
        title: trimmed,
        subtitle: "Reachable vulnerability",
      };
    case "credential":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "Exposed secret surface",
      };
    case "tool":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "MCP tool capability",
      };
    case "environment":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "Deployment environment",
      };
    case "cluster":
      return {
        title: titleCaseWords(trimmed),
        subtitle: "Kubernetes cluster",
      };
    default:
      return { title: titleCaseWords(trimmed) };
  }
}

export function formatExposureEntityTitle(
  label: string,
  role: ExposureEntityRole,
  attributes: Record<string, unknown> = {},
): string {
  return formatExposureEntityDisplay(label, role, attributes).title;
}

export function formatExposurePathSequence(
  hops: Array<{ label: string; role: ExposureEntityRole; attributes?: Record<string, unknown> | undefined }>,
): string {
  return hops
    .map((hop) => formatExposureEntityTitle(hop.label, hop.role, hop.attributes ?? {}))
    .join(" → ");
}
