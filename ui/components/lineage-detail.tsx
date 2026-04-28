"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import {
  Brain,
  Bug,
  Building2,
  Cloud,
  Database,
  ExternalLink,
  KeyRound,
  Package,
  Server,
  ShieldAlert,
  TriangleAlert,
  Wrench,
  X,
} from "lucide-react";

import { severityColor } from "@/lib/api";
import { getOsvVulnerabilityUrl } from "@/lib/vulnerabilities";
import type { LineageNodeData } from "./lineage-nodes";

const TYPE_ICON = {
  provider: Building2,
  agent: ShieldAlert,
  user: ShieldAlert,
  group: Building2,
  serviceAccount: KeyRound,
  environment: Cloud,
  fleet: Building2,
  cluster: Server,
  server: Server,
  sharedServer: Server,
  package: Package,
  vulnerability: Bug,
  misconfiguration: TriangleAlert,
  credential: KeyRound,
  tool: Wrench,
  model: Brain,
  dataset: Database,
  container: Package,
  cloudResource: Cloud,
} as const;

const TYPE_LABELS: Record<LineageNodeData["nodeType"], string> = {
  provider: "Provider",
  agent: "Agent",
  user: "User",
  group: "Group",
  serviceAccount: "Service Account",
  environment: "Environment",
  fleet: "Fleet",
  cluster: "Cluster",
  server: "MCP Server",
  sharedServer: "Shared MCP Server",
  package: "Package",
  vulnerability: "Vulnerability",
  misconfiguration: "Misconfiguration",
  credential: "Credential",
  tool: "Tool",
  model: "Model",
  dataset: "Dataset",
  container: "Container",
  cloudResource: "Cloud Resource",
};

const TYPE_BORDER: Record<LineageNodeData["nodeType"], string> = {
  provider: "border-zinc-700",
  agent: "border-emerald-700",
  user: "border-emerald-700",
  group: "border-fuchsia-700",
  serviceAccount: "border-amber-700",
  environment: "border-teal-700",
  fleet: "border-cyan-700",
  cluster: "border-sky-700",
  server: "border-blue-700",
  sharedServer: "border-cyan-700",
  package: "border-zinc-700",
  vulnerability: "border-red-700",
  misconfiguration: "border-orange-700",
  credential: "border-amber-700",
  tool: "border-purple-700",
  model: "border-violet-700",
  dataset: "border-cyan-700",
  container: "border-indigo-700",
  cloudResource: "border-sky-700",
};

export function LineageDetailPanel({
  data,
  onClose,
}: {
  data: LineageNodeData;
  onClose: () => void;
}) {
  const Icon = TYPE_ICON[data.nodeType];
  const osvUrl = data.nodeType === "vulnerability" ? getOsvVulnerabilityUrl(data.label) : null;
  const extraAttributes = Object.entries(data.attributes ?? {}).filter(([key]) => {
    return !new Set([
      "agent_type",
      "status",
      "version",
      "ecosystem",
      "description",
      "framework",
      "source",
      "hash",
      "verified",
      "container_image",
      "cloud_provider",
      "resource_id",
      "source_section",
      "rule_id",
      "check_id",
      "recommendation",
      "evidence",
      "path",
      "file_path",
      "line",
      "start_line",
      "end_line",
      "cvss_score",
      "epss_score",
      "is_kev",
      "fixed_version",
    ]).has(key);
  });

  return (
    <div
      className={`absolute right-0 top-0 bottom-0 w-80 bg-zinc-950/95 backdrop-blur-sm border-l ${TYPE_BORDER[data.nodeType]} z-50 overflow-y-auto`}
    >
      <div className="p-4 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[10px] uppercase tracking-wider text-zinc-500">
              {TYPE_LABELS[data.nodeType]}
            </span>
            <div className="flex items-center gap-2 mt-0.5">
              <Icon className="w-4 h-4 text-zinc-400" />
              <h3 className="text-sm font-semibold text-zinc-100">{data.label}</h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {data.nodeType === "provider" && data.agentCount !== undefined && (
          <Row label="Hosted agents" value={data.agentCount} />
        )}

        {data.nodeType === "agent" && (
          <div className="space-y-3">
            {data.agentType && <Row label="Type" value={data.agentType} />}
            {data.agentStatus && (
              <div
                className={`text-xs px-2 py-1 rounded border font-mono ${
                  data.agentStatus === "installed-not-configured"
                    ? "border-yellow-800 bg-yellow-950 text-yellow-400"
                    : "border-emerald-800 bg-emerald-950 text-emerald-400"
                }`}
              >
                {data.agentStatus === "installed-not-configured" ? "Not Configured" : "Configured"}
              </div>
            )}
            {data.serverCount !== undefined && <Row label="Servers" value={data.serverCount} />}
            {data.packageCount !== undefined && <Row label="Packages" value={data.packageCount} />}
            {(data.vulnCount ?? 0) > 0 && (
              <Row label="Findings" value={data.vulnCount ?? 0} className="text-red-400" />
            )}
          </div>
        )}

        {(data.nodeType === "user" ||
          data.nodeType === "group" ||
          data.nodeType === "serviceAccount" ||
          data.nodeType === "environment" ||
          data.nodeType === "fleet" ||
          data.nodeType === "cluster") && (
          <GenericAssetSection
            description={data.description}
            version={data.version}
            attributes={data.attributes}
          />
        )}

        {data.nodeType === "server" && (
          <div className="space-y-3">
            {data.command && (
              <CodeBlock label="Connection" value={data.command} />
            )}
            {data.toolCount !== undefined && data.toolCount > 0 && <Row label="Tools" value={data.toolCount} />}
            {data.credentialCount !== undefined && data.credentialCount > 0 && (
              <Row label="Credentials" value={data.credentialCount} className="text-amber-400" />
            )}
            {data.packageCount !== undefined && data.packageCount > 0 && (
              <Row label="Packages" value={data.packageCount} />
            )}
          </div>
        )}

        {data.nodeType === "sharedServer" && (
          <div className="space-y-3">
            {data.sharedBy && (
              <div className="text-xs px-2 py-1 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700 font-mono">
                Shared by {data.sharedBy} agents
              </div>
            )}
            {data.sharedAgents && data.sharedAgents.length > 0 && (
              <TagList label="Connected Agents" tags={data.sharedAgents} />
            )}
            {data.command && <CodeBlock label="Connection" value={data.command} />}
          </div>
        )}

        {data.nodeType === "package" && (
          <div className="space-y-3">
            {data.ecosystem && <Row label="Ecosystem" value={data.ecosystem} />}
            {data.version && <Row label="Version" value={data.version} />}
            {(data.vulnCount ?? 0) > 0 ? (
              <Row label="Findings" value={data.vulnCount ?? 0} className="text-red-400" />
            ) : (
              <div className="text-xs text-emerald-400">No known findings on this package node</div>
            )}
          </div>
        )}

        {data.nodeType === "vulnerability" && (
          <div className="space-y-3">
            {data.severity && (
              <span
                className={`inline-block text-xs px-2 py-1 rounded border font-mono uppercase ${severityColor(data.severity)}`}
              >
                {data.severity}
              </span>
            )}
            {typeof data.cvssScore === "number" && Number.isFinite(data.cvssScore) && (
              <Row label="CVSS" value={data.cvssScore.toFixed(1)} />
            )}
            {typeof data.epssScore === "number" && data.epssScore > 0 && (
              <Row label="EPSS" value={`${(data.epssScore * 100).toFixed(1)}%`} />
            )}
            {data.isKev && (
              <div className="text-xs px-2 py-1 rounded bg-red-900 text-red-300 border border-red-700 font-mono inline-block">
                CISA Known Exploited
              </div>
            )}
            {data.fixedVersion && <Row label="Fix version" value={data.fixedVersion} className="text-emerald-400" />}
            {data.owaspTags && data.owaspTags.length > 0 && <TagList label="OWASP" tags={data.owaspTags} />}
            {data.atlasTags && data.atlasTags.length > 0 && <TagList label="ATLAS" tags={data.atlasTags} />}
            {osvUrl && (
              <a
                href={osvUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 transition-colors"
              >
                <ExternalLink className="w-3 h-3" />
                View on OSV
              </a>
            )}
          </div>
        )}

        {data.nodeType === "misconfiguration" && (
          <div className="space-y-3">
            {data.severity && (
              <span
                className={`inline-block text-xs px-2 py-1 rounded border font-mono uppercase ${severityColor(data.severity)}`}
              >
                {data.severity}
              </span>
            )}
            {data.description && <div className="text-xs text-zinc-400">{data.description}</div>}
          </div>
        )}

        {data.nodeType === "credential" && (
          <div className="space-y-3">
            <div className="text-xs text-amber-400">Environment variable or credential-like secret exposed in configuration.</div>
            {data.serverName && <Row label="Linked server" value={data.serverName} />}
          </div>
        )}

        {data.nodeType === "tool" && data.description && (
          <div className="text-xs text-zinc-400">{data.description}</div>
        )}

        {data.nodeType === "model" && (
          <GenericAssetSection
            description={data.description}
            version={data.version}
            attributes={data.attributes}
          />
        )}

        {data.nodeType === "dataset" && (
          <GenericAssetSection
            description={data.description}
            version={data.version}
            attributes={data.attributes}
          />
        )}

        {data.nodeType === "container" && (
          <GenericAssetSection description={data.description} attributes={data.attributes} />
        )}

        {data.nodeType === "cloudResource" && (
          <GenericAssetSection description={data.description} attributes={data.attributes} />
        )}

        {(data.status || data.riskScore != null || data.firstSeen || data.lastSeen) && (
          <div className="space-y-2">
            <Label>Lifecycle</Label>
            {data.status && <Row label="Status" value={data.status} />}
            {data.riskScore != null && <Row label="Risk score" value={data.riskScore.toFixed(1)} />}
            {data.firstSeen && <Row label="First seen" value={shortDate(data.firstSeen)} />}
            {data.lastSeen && <Row label="Last seen" value={shortDate(data.lastSeen)} />}
          </div>
        )}

        {typeof data.attributes?.node_id === "string" && data.attributes.node_id && (
          <div className="space-y-2">
            <Label>Identifier</Label>
            <CodeBlock label="Node ID" value={String(data.attributes.node_id)} />
          </div>
        )}

        {(data.neighborCount != null ||
          data.sourceCount != null ||
          data.incomingEdgeCount != null ||
          data.outgoingEdgeCount != null ||
          data.impactCount != null) && (
          <div className="space-y-2">
            <Label>Graph Context</Label>
            {data.neighborCount != null && <Row label="Neighbors" value={data.neighborCount} />}
            {data.sourceCount != null && <Row label="Sources" value={data.sourceCount} />}
            {data.incomingEdgeCount != null && <Row label="Incoming edges" value={data.incomingEdgeCount} />}
            {data.outgoingEdgeCount != null && <Row label="Outgoing edges" value={data.outgoingEdgeCount} />}
            {data.impactCount != null && <Row label="Affected nodes" value={data.impactCount} className="text-orange-300" />}
            {data.maxImpactDepth != null && <Row label="Impact depth" value={data.maxImpactDepth} />}
          </div>
        )}

        {data.impactByType && Object.keys(data.impactByType).length > 0 && (
          <div>
            <Label>Impact By Type</Label>
            <div className="mt-1 flex flex-wrap gap-1">
              {Object.entries(data.impactByType)
                .sort((left, right) => right[1] - left[1])
                .map(([key, value]) => (
                  <Link
                    key={key}
                    href={`/graph?q=${encodeURIComponent(key)}`}
                    className="rounded border border-orange-800 bg-orange-950 px-1.5 py-0.5 text-[10px] text-orange-300 transition-colors hover:bg-orange-900"
                  >
                    {prettifyKey(key)}: {value}
                  </Link>
                ))}
            </div>
          </div>
        )}

        {data.dataSources && data.dataSources.length > 0 && (
          <TagList
            label="Data Sources"
            tags={data.dataSources}
            tone="blue"
            linkBuilder={(tag) => `/jobs?q=${encodeURIComponent(tag)}`}
          />
        )}

        {data.complianceTags && data.complianceTags.length > 0 && (
          <TagList
            label="Compliance Tags"
            tags={data.complianceTags}
            linkBuilder={(tag) => `/compliance?q=${encodeURIComponent(tag)}`}
          />
        )}

        {extraAttributes.length > 0 && (
          <div className="space-y-2">
            <Label>Attributes</Label>
            <div className="space-y-1.5">
              {extraAttributes.slice(0, 10).map(([key, value]) => (
                <Row key={key} label={prettifyKey(key)} value={formatValue(value)} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function GenericAssetSection({
  description,
  version,
  attributes,
}: {
  description?: string | undefined;
  version?: string | undefined;
  attributes?: Record<string, unknown> | undefined;
}) {
  return (
    <div className="space-y-3">
      {description && <div className="text-xs text-zinc-400">{description}</div>}
      {version && <Row label="Version / hash" value={version} />}
      {typeof attributes?.verified === "boolean" && (
        <Row label="Verified" value={attributes.verified ? "yes" : "no"} />
      )}
    </div>
  );
}

function TagList({
  label,
  tags,
  tone = "zinc",
  linkBuilder,
}: {
  label: string;
  tags: string[];
  tone?: "zinc" | "blue" | undefined;
  linkBuilder?: (tag: string) => string | undefined;
}) {
  const toneClass =
    tone === "blue"
      ? "bg-blue-950 text-blue-300 border-blue-800"
      : "bg-zinc-800 text-zinc-400 border-zinc-700";
  return (
    <div>
      <Label>{label}</Label>
      <div className="flex flex-wrap gap-1 mt-1">
        {tags.map((tag) => (
          linkBuilder ? (
            <Link
              key={tag}
              href={linkBuilder(tag) ?? "#"}
              className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors hover:brightness-110 ${toneClass}`}
            >
              {tag}
            </Link>
          ) : (
            <span key={tag} className={`text-[10px] px-1.5 py-0.5 rounded border ${toneClass}`}>
              {tag}
            </span>
          )
        ))}
      </div>
    </div>
  );
}

function CodeBlock({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Label>{label}</Label>
      <div className="text-xs font-mono text-zinc-300 bg-zinc-900 rounded px-2 py-1 break-all">
        {value}
      </div>
    </div>
  );
}

function Label({ children }: { children: ReactNode }) {
  return <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-0.5">{children}</div>;
}

function Row({
  label,
  value,
  className = "",
}: {
  label: string;
  value: string | number;
  className?: string | undefined;
}) {
  return (
    <div className="flex items-center justify-between gap-4 text-xs">
      <span className="text-zinc-500">{label}</span>
      <span className={`text-zinc-300 font-mono text-right break-all ${className}`}>{value}</span>
    </div>
  );
}

function shortDate(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function formatValue(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.slice(0, 4).map((item) => String(item)).join(", ");
  return JSON.stringify(value);
}

function prettifyKey(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}
