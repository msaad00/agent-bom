"use client";

import type { ComponentType, ReactNode } from "react";
import { Handle, Position } from "@xyflow/react";
import {
  Brain,
  Box,
  Bug,
  Building2,
  Cloud,
  Database,
  KeyRound,
  Package,
  Server,
  ShieldAlert,
  TriangleAlert,
  Wrench,
} from "lucide-react";

import { severityColor } from "@/lib/api";
import type { ReachBreakdown } from "@/lib/effective-reach";

export type LineageNodeType =
  | "provider"
  | "agent"
  | "server"
  | "package"
  | "vulnerability"
  | "misconfiguration"
  | "credential"
  | "tool"
  | "model"
  | "dataset"
  | "container"
  | "cloudResource"
  | "user"
  | "group"
  | "serviceAccount"
  | "environment"
  | "fleet"
  | "cluster"
  | "sharedServer";

export type LineageNodeData = {
  label: string;
  nodeType: LineageNodeType;
  entityType?: string | undefined;
  status?: string | undefined;
  riskScore?: number | undefined;
  firstSeen?: string | undefined;
  lastSeen?: string | undefined;
  dataSources?: string[] | undefined;
  complianceTags?: string[] | undefined;
  attributes?: Record<string, unknown> | undefined;
  neighborCount?: number | undefined;
  sourceCount?: number | undefined;
  incomingEdgeCount?: number | undefined;
  outgoingEdgeCount?: number | undefined;
  impactCount?: number | undefined;
  maxImpactDepth?: number | undefined;
  impactByType?: Record<string, number> | undefined;
  // Agent / provider
  agentType?: string | undefined;
  agentStatus?: string | undefined;
  agentCount?: number | undefined;
  serverCount?: number | undefined;
  packageCount?: number | undefined;
  vulnCount?: number | undefined;
  // Server / Shared Server
  toolCount?: number | undefined;
  credentialCount?: number | undefined;
  command?: string | undefined;
  sharedBy?: number | undefined;
  sharedAgents?: string[] | undefined;
  // Package / model / dataset
  ecosystem?: string | undefined;
  version?: string | undefined;
  versionSource?: string | undefined;
  versionConfidence?: string | undefined;
  registryVersion?: string | undefined;
  // Vulnerability / misconfiguration
  severity?: string | undefined;
  cvssScore?: number | undefined;
  epssScore?: number | undefined;
  isKev?: boolean | undefined;
  effectiveReach?: ReachBreakdown | undefined;
  fixedVersion?: string | undefined;
  owaspTags?: string[] | undefined;
  atlasTags?: string[] | undefined;
  // Credential
  serverName?: string | undefined;
  // Tool / generic assets
  description?: string | undefined;
  // Highlighting
  dimmed?: boolean | undefined;
  highlighted?: boolean | undefined;
  isCritical?: boolean | undefined;
  // Evidence redaction tier (#2261) — per-row badge in lineage detail panel.
  evidenceTier?: "safe_to_store" | "replay_only" | undefined;
  evidenceCaptureReplay?: boolean | undefined;
  evidenceNotAfter?: string | undefined;
  renderBand?: "detail" | "summary" | "cluster" | undefined;
};

type CardProps = {
  data: LineageNodeData;
  borderClass: string;
  bgClass: string;
  ringClass: string;
  shapeClass?: string;
  icon: ComponentType<{ className?: string }>;
  iconClass: string;
  source?: boolean;
  target?: boolean;
  footer?: ReactNode;
  subtitle?: ReactNode;
};

function NodeCard({
  data,
  borderClass,
  bgClass,
  ringClass,
  shapeClass = "rounded-xl",
  icon: Icon,
  iconClass,
  source = true,
  target = true,
  subtitle,
  footer,
}: CardProps) {
  return (
    <div
      title={data.label}
      className={`${shapeClass} border-2 px-3 py-2 min-w-[168px] max-w-[240px] shadow-lg backdrop-blur transition-opacity ${borderClass} ${bgClass} ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? `ring-2 ${ringClass}` : ""}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className={`!w-2 !h-2 !bg-current ${target ? "" : "!opacity-0"}`}
      />
      <Handle
        type="source"
        position={Position.Right}
        className={`!w-2 !h-2 !bg-current ${source ? "" : "!opacity-0"}`}
      />
      <div className="flex items-center gap-1.5 mb-0.5">
        <Icon className={`w-3.5 h-3.5 shrink-0 ${iconClass}`} />
        <span className="text-[13px] font-semibold leading-4 text-zinc-50 truncate">{data.label}</span>
        <span className="ml-auto rounded border border-white/15 bg-black/25 px-1.5 py-0.5 text-[9px] uppercase tracking-[0.12em] text-zinc-300">
          {NODE_TYPE_BADGES[data.nodeType]}
        </span>
      </div>
      {subtitle && <div className="text-[11px] leading-4 text-zinc-300 truncate">{subtitle}</div>}
      {footer}
    </div>
  );
}

const NODE_TYPE_BADGES: Record<LineageNodeType, string> = {
  provider: "Provider",
  agent: "Agent",
  server: "Server",
  package: "Package",
  vulnerability: "CVE",
  misconfiguration: "Config",
  credential: "Cred ref",
  tool: "Tool",
  model: "Model",
  dataset: "Dataset",
  container: "Container",
  cloudResource: "Cloud",
  user: "User",
  group: "Group",
  serviceAccount: "Service",
  environment: "Env",
  fleet: "Fleet",
  cluster: "Cluster",
  sharedServer: "Shared",
};

function AgentNode({ data }: { data: LineageNodeData }) {
  const notConfigured = data.agentStatus === "installed-not-configured";
  return (
    <NodeCard
      data={data}
      borderClass={notConfigured ? "border-yellow-600 border-dashed" : "border-emerald-600"}
      bgClass={notConfigured ? "bg-yellow-950/80" : "bg-emerald-950/80"}
      ringClass="ring-emerald-400"
      icon={ShieldAlert}
      iconClass="text-emerald-400"
      target={false}
      subtitle={data.agentType}
      footer={
        <div className="flex gap-2 mt-1 text-[10px] text-zinc-500">
          {data.serverCount !== undefined && <span>{data.serverCount} srv</span>}
          {data.packageCount !== undefined && <span>{data.packageCount} pkg</span>}
          {(data.vulnCount ?? 0) > 0 && <span className="text-red-400">{data.vulnCount} finding</span>}
        </div>
      }
    />
  );
}

function ProviderNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-zinc-600"
      bgClass="bg-zinc-900/90"
      ringClass="ring-zinc-400"
      icon={Building2}
      iconClass="text-zinc-400"
      target={false}
      footer={
        data.agentCount !== undefined ? (
          <div className="mt-1 text-[10px] text-zinc-500">{data.agentCount} agents</div>
        ) : undefined
      }
    />
  );
}

function IdentityNode({
  data,
  borderClass,
  bgClass,
  ringClass,
  icon,
  iconClass,
  subtitle,
}: {
  data: LineageNodeData;
  borderClass: string;
  bgClass: string;
  ringClass: string;
  icon: ComponentType<{ className?: string }>;
  iconClass: string;
  subtitle?: ReactNode;
}) {
  return (
    <NodeCard
      data={data}
      borderClass={borderClass}
      bgClass={bgClass}
      ringClass={ringClass}
      icon={icon}
      iconClass={iconClass}
      subtitle={subtitle}
    />
  );
}

function UserNode({ data }: { data: LineageNodeData }) {
  return (
    <IdentityNode
      data={data}
      borderClass="border-emerald-700"
      bgClass="bg-emerald-950/60"
      ringClass="ring-emerald-400"
      icon={ShieldAlert}
      iconClass="text-emerald-300"
      subtitle={data.description}
    />
  );
}

function GroupNode({ data }: { data: LineageNodeData }) {
  return (
    <IdentityNode
      data={data}
      borderClass="border-fuchsia-700"
      bgClass="bg-fuchsia-950/55"
      ringClass="ring-fuchsia-400"
      icon={Building2}
      iconClass="text-fuchsia-300"
      subtitle={data.description}
    />
  );
}

function ServiceAccountNode({ data }: { data: LineageNodeData }) {
  return (
    <IdentityNode
      data={data}
      borderClass="border-amber-700"
      bgClass="bg-amber-950/55"
      ringClass="ring-amber-400"
      icon={KeyRound}
      iconClass="text-amber-300"
      subtitle={data.description}
    />
  );
}

function StructureNode({
  data,
  borderClass,
  bgClass,
  ringClass,
  icon,
  iconClass,
}: {
  data: LineageNodeData;
  borderClass: string;
  bgClass: string;
  ringClass: string;
  icon: ComponentType<{ className?: string }>;
  iconClass: string;
}) {
  return (
    <NodeCard
      data={data}
      borderClass={borderClass}
      bgClass={bgClass}
      ringClass={ringClass}
      icon={icon}
      iconClass={iconClass}
      subtitle={data.description}
      footer={
        <div className="flex gap-2 mt-1 text-[10px] text-zinc-500">
          {data.agentCount !== undefined && <span>{data.agentCount} agents</span>}
          {data.serverCount !== undefined && <span>{data.serverCount} servers</span>}
        </div>
      }
    />
  );
}

function EnvironmentNode({ data }: { data: LineageNodeData }) {
  return (
    <StructureNode
      data={data}
      borderClass="border-teal-700"
      bgClass="bg-teal-950/55"
      ringClass="ring-teal-400"
      icon={Cloud}
      iconClass="text-teal-300"
    />
  );
}

function FleetNode({ data }: { data: LineageNodeData }) {
  return (
    <StructureNode
      data={data}
      borderClass="border-cyan-700"
      bgClass="bg-cyan-950/55"
      ringClass="ring-cyan-400"
      icon={Building2}
      iconClass="text-cyan-300"
    />
  );
}

function ClusterNode({ data }: { data: LineageNodeData }) {
  return (
    <StructureNode
      data={data}
      borderClass="border-sky-700"
      bgClass="bg-sky-950/55"
      ringClass="ring-sky-400"
      icon={Server}
      iconClass="text-sky-300"
    />
  );
}

function ServerNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-blue-600"
      bgClass="bg-blue-950/80"
      ringClass="ring-blue-400"
      icon={Server}
      iconClass="text-blue-400"
      subtitle={data.command}
      footer={
        <div className="flex gap-2 mt-1">
          {data.toolCount !== undefined && data.toolCount > 0 && (
            <span className="flex items-center gap-0.5 text-[10px] text-purple-400">
              <Wrench className="w-2.5 h-2.5" /> {data.toolCount}
            </span>
          )}
          {data.credentialCount !== undefined && data.credentialCount > 0 && (
            <span className="flex items-center gap-0.5 text-[10px] text-amber-400">
              <KeyRound className="w-2.5 h-2.5" /> {data.credentialCount}
            </span>
          )}
          {data.packageCount !== undefined && data.packageCount > 0 && (
            <span className="flex items-center gap-0.5 text-[10px] text-zinc-400">
              <Package className="w-2.5 h-2.5" /> {data.packageCount}
            </span>
          )}
        </div>
      }
    />
  );
}

function PackageNode({ data }: { data: LineageNodeData }) {
  const hasVulns = (data.vulnCount ?? 0) > 0;
  const provenance = data.versionSource
    ? `${data.versionSource}${data.versionConfidence ? ` · ${data.versionConfidence}` : ""}`
    : "";
  return (
    <NodeCard
      data={data}
      borderClass={hasVulns ? "border-red-600/60" : "border-zinc-600"}
      bgClass={hasVulns ? "bg-red-950/40" : "bg-zinc-900/80"}
      ringClass="ring-zinc-400"
      icon={Package}
      iconClass="text-zinc-400"
      subtitle={
        data.version
          ? `${data.version}${data.ecosystem ? ` · ${data.ecosystem}` : ""}${provenance ? ` · ${provenance}` : ""}`
          : data.ecosystem
      }
      footer={
        hasVulns ? (
          <div className="mt-1 text-[10px] text-red-400">
            <Bug className="w-2.5 h-2.5 inline mr-0.5" />
            {data.vulnCount}
          </div>
        ) : undefined
      }
    />
  );
}

function FindingNode({
  data,
  accentClass,
  borderClass,
  bgClass,
}: {
  data: LineageNodeData;
  accentClass: string;
  borderClass: string;
  bgClass: string;
}) {
  return (
    <NodeCard
      data={data}
      borderClass={borderClass}
      bgClass={bgClass}
      ringClass="ring-white/50"
      shapeClass={data.nodeType === "misconfiguration" ? "rounded-md" : "rounded-lg"}
      icon={data.nodeType === "misconfiguration" ? TriangleAlert : Bug}
      iconClass={accentClass}
      source={false}
      subtitle={data.description}
      footer={
        <div className="flex flex-wrap gap-1 mt-1">
          {data.severity && (
            <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${severityColor(data.severity)}`}>
              {data.severity}
            </span>
          )}
          {typeof data.cvssScore === "number" && Number.isFinite(data.cvssScore) ? (
            <span className="text-[10px] text-zinc-400">CVSS {data.cvssScore.toFixed(1)}</span>
          ) : null}
          {data.isKev && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900 text-red-300 border border-red-700 font-mono">
              KEV
            </span>
          )}
        </div>
      }
    />
  );
}

function VulnNode({ data }: { data: LineageNodeData }) {
  const sev = data.severity ?? "medium";
  const borderClass =
    sev === "critical" ? "border-red-500" :
    sev === "high" ? "border-orange-500" :
    sev === "medium" ? "border-yellow-500" :
    "border-blue-500";
  const bgClass =
    sev === "critical" ? "bg-red-950/80" :
    sev === "high" ? "bg-orange-950/80" :
    sev === "medium" ? "bg-yellow-950/80" :
    "bg-blue-950/80";
  return <FindingNode data={data} accentClass="text-red-300" borderClass={borderClass} bgClass={bgClass} />;
}

function MisconfigNode({ data }: { data: LineageNodeData }) {
  return <FindingNode data={data} accentClass="text-orange-300" borderClass="border-orange-500" bgClass="bg-orange-950/75" />;
}

function CredentialNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-amber-500 border-dashed"
      bgClass="bg-amber-950/60"
      ringClass="ring-amber-400"
      shapeClass="rounded-2xl"
      icon={KeyRound}
      iconClass="text-amber-400"
      source={false}
      subtitle={data.serverName}
    />
  );
}

function ToolNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-purple-600"
      bgClass="bg-purple-950/60"
      ringClass="ring-purple-400"
      shapeClass="rounded-2xl"
      icon={Wrench}
      iconClass="text-purple-400"
      source={false}
      subtitle={data.description}
    />
  );
}

function ModelNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-violet-600"
      bgClass="bg-violet-950/70"
      ringClass="ring-violet-400"
      icon={Brain}
      iconClass="text-violet-300"
      subtitle={data.description}
    />
  );
}

function DatasetNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-cyan-600"
      bgClass="bg-cyan-950/70"
      ringClass="ring-cyan-400"
      icon={Database}
      iconClass="text-cyan-300"
      subtitle={data.description}
    />
  );
}

function ContainerNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-indigo-600"
      bgClass="bg-indigo-950/70"
      ringClass="ring-indigo-400"
      icon={Box}
      iconClass="text-indigo-300"
      subtitle={data.description}
    />
  );
}

function CloudResourceNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-sky-600"
      bgClass="bg-sky-950/70"
      ringClass="ring-sky-400"
      icon={Cloud}
      iconClass="text-sky-300"
      subtitle={data.description}
    />
  );
}

/**
 * Cluster pill (#2257 — sibling aggregation).
 *
 * Visually distinct rounded pill that absorbs N siblings of the same type
 * and edge kind. Subtle pulse signals "click me to expand". The data shape
 * is the union of `LineageNodeData` + extra cluster fields injected by
 * `aggregateSiblings` — we read the cluster fields off `data` defensively
 * because the renderer is registered globally and any node could in theory
 * land here under that key.
 */
function ClusterPillNode({ data }: { data: LineageNodeData }) {
  const cluster = data as LineageNodeData & {
    count?: number;
    childType?: LineageNodeType;
  };
  const count = cluster.count ?? 0;
  const childType = (cluster.childType ?? cluster.nodeType) as LineageNodeType;
  const Icon = CLUSTER_PILL_ICONS[childType] ?? Box;
  return (
    <div
      data-testid="cluster-pill"
      data-cluster-count={count}
      className={`relative rounded-full border border-sky-400/60 bg-sky-500/10 px-3 py-1.5 shadow-lg backdrop-blur transition-opacity hover:border-sky-300 hover:bg-sky-500/15 ${
        data.dimmed ? "opacity-25" : ""
      } cluster-pill-pulse cursor-pointer`}
      title="Click to expand"
    >
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-sky-300" />
      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-sky-300" />
      <div className="flex items-center gap-1.5">
        <Icon className="w-3.5 h-3.5 text-sky-200" />
        <span className="text-xs font-semibold text-sky-100 whitespace-nowrap">
          {data.label}
        </span>
        <span className="text-[9px] uppercase tracking-[0.18em] text-sky-300/80">
          expand
        </span>
      </div>
    </div>
  );
}

const CLUSTER_PILL_ICONS: Partial<Record<LineageNodeType, ComponentType<{ className?: string }>>> = {
  agent: ShieldAlert,
  server: Server,
  sharedServer: Server,
  package: Package,
  vulnerability: Bug,
  misconfiguration: TriangleAlert,
  credential: KeyRound,
  tool: Wrench,
  model: Brain,
  dataset: Database,
  container: Box,
  cloudResource: Cloud,
  provider: Building2,
  environment: Cloud,
  fleet: Building2,
  cluster: Server,
};

function SharedServerNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-cyan-400"
      bgClass="bg-cyan-950/80"
      ringClass="ring-cyan-300"
      shapeClass="rounded-[18px]"
      icon={Server}
      iconClass="text-cyan-300"
      subtitle={data.command}
      footer={
        <div className="flex gap-2 mt-1">
          {data.sharedBy && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700 font-mono">
              Shared by {data.sharedBy}
            </span>
          )}
          {data.packageCount !== undefined && data.packageCount > 0 && (
            <span className="flex items-center gap-0.5 text-[10px] text-zinc-300">
              <Package className="w-2.5 h-2.5" /> {data.packageCount}
            </span>
          )}
        </div>
      }
    />
  );
}

/**
 * Summary-band renderer (#2257 LOD): compact dot with severity badge + label.
 *
 * Used when 0.4 <= zoom < 1.0 — the operator can still parse a label and a
 * one-glance severity/CVE-count chip but the canvas isn't drowning in chips
 * and footers. The same data shape as `LineageNodeData` so swap-in is free.
 */
function SummaryNode({ data }: { data: LineageNodeData }) {
  const sev = (data.severity ?? "").toLowerCase();
  const accent =
    sev === "critical"
      ? "border-red-500 bg-red-950/70 text-red-200"
      : sev === "high"
        ? "border-orange-500 bg-orange-950/60 text-orange-200"
        : sev === "medium"
          ? "border-yellow-500 bg-yellow-950/55 text-yellow-200"
          : "border-zinc-700 bg-zinc-900/80 text-zinc-200";
  const vulnCount = data.vulnCount ?? 0;
  return (
    <div
      data-testid="summary-node"
      className={`rounded-lg border px-2 py-1 min-w-[96px] max-w-[160px] shadow transition-opacity ${accent} ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-sky-400" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!w-1.5 !h-1.5" />
      <Handle type="source" position={Position.Right} className="!w-1.5 !h-1.5" />
      <div className="flex items-center gap-1">
        <span className="text-[10px] font-medium truncate">{data.label}</span>
        {vulnCount > 0 && (
          <span className="ml-auto rounded bg-black/40 px-1 text-[9px] font-mono">
            {vulnCount}
          </span>
        )}
      </div>
    </div>
  );
}

/**
 * Cluster-band renderer (#2257 LOD): one bubble per node — the operator
 * is zoomed too far out for labels to be readable anyway, so we render a
 * coloured circle keyed by entity type. The entity colour comes from the
 * standard ENTITY_COLOR_MAP via the parent's `nodeType`.
 */
function ClusterBubbleNode({ data }: { data: LineageNodeData }) {
  const color = CLUSTER_BUBBLE_COLORS[data.nodeType] ?? "#52525b";
  return (
    <div
      data-testid="cluster-bubble"
      className={`rounded-full border-2 transition-opacity ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-sky-400" : ""}`}
      style={{
        width: 18,
        height: 18,
        backgroundColor: `${color}cc`,
        borderColor: color,
      }}
    >
      <Handle type="target" position={Position.Left} className="!w-1 !h-1 !bg-transparent !border-0" />
      <Handle type="source" position={Position.Right} className="!w-1 !h-1 !bg-transparent !border-0" />
    </div>
  );
}

const CLUSTER_BUBBLE_COLORS: Record<LineageNodeType, string> = {
  provider: "#71717a",
  agent: "#10b981",
  user: "#34d399",
  group: "#d946ef",
  serviceAccount: "#fbbf24",
  environment: "#14b8a6",
  fleet: "#22d3ee",
  cluster: "#38bdf8",
  server: "#3b82f6",
  sharedServer: "#22d3ee",
  package: "#52525b",
  vulnerability: "#ef4444",
  credential: "#f59e0b",
  tool: "#a855f7",
  model: "#8b5cf6",
  dataset: "#06b6d4",
  container: "#6366f1",
  cloudResource: "#0ea5e9",
  misconfiguration: "#f97316",
};

const DETAIL_RENDERERS: Record<LineageNodeType, ComponentType<{ data: LineageNodeData }>> = {
  provider: ProviderNode,
  agent: AgentNode,
  user: UserNode,
  group: GroupNode,
  serviceAccount: ServiceAccountNode,
  environment: EnvironmentNode,
  fleet: FleetNode,
  cluster: ClusterNode,
  server: ServerNode,
  sharedServer: SharedServerNode,
  package: PackageNode,
  vulnerability: VulnNode,
  misconfiguration: MisconfigNode,
  credential: CredentialNode,
  tool: ToolNode,
  model: ModelNode,
  dataset: DatasetNode,
  container: ContainerNode,
  cloudResource: CloudResourceNode,
};

function AdaptiveLineageNode({ data }: { data: LineageNodeData }) {
  if (data.renderBand === "cluster") return <ClusterBubbleNode data={data} />;
  if (data.renderBand === "summary") return <SummaryNode data={data} />;
  const Renderer = DETAIL_RENDERERS[data.nodeType] ?? SummaryNode;
  return <Renderer data={data} />;
}

export const lineageNodeTypesAdaptive = {
  providerNode: AdaptiveLineageNode,
  agentNode: AdaptiveLineageNode,
  userNode: AdaptiveLineageNode,
  groupNode: AdaptiveLineageNode,
  serviceAccountNode: AdaptiveLineageNode,
  environmentNode: AdaptiveLineageNode,
  fleetNode: AdaptiveLineageNode,
  clusterNode: AdaptiveLineageNode,
  serverNode: AdaptiveLineageNode,
  packageNode: AdaptiveLineageNode,
  vulnNode: AdaptiveLineageNode,
  misconfigNode: AdaptiveLineageNode,
  credentialNode: AdaptiveLineageNode,
  toolNode: AdaptiveLineageNode,
  modelNode: AdaptiveLineageNode,
  datasetNode: AdaptiveLineageNode,
  containerNode: AdaptiveLineageNode,
  cloudResourceNode: AdaptiveLineageNode,
  sharedServerNode: AdaptiveLineageNode,
  clusterPillNode: ClusterPillNode,
};

/**
 * Detail-band renderer registry — the full chip-laden cards. This is the
 * "default" map and matches what /graph rendered before LOD existed.
 */
export const lineageNodeTypes = {
  providerNode: ProviderNode,
  agentNode: AgentNode,
  userNode: UserNode,
  groupNode: GroupNode,
  serviceAccountNode: ServiceAccountNode,
  environmentNode: EnvironmentNode,
  fleetNode: FleetNode,
  clusterNode: ClusterNode,
  serverNode: ServerNode,
  packageNode: PackageNode,
  vulnNode: VulnNode,
  misconfigNode: MisconfigNode,
  credentialNode: CredentialNode,
  toolNode: ToolNode,
  modelNode: ModelNode,
  datasetNode: DatasetNode,
  containerNode: ContainerNode,
  cloudResourceNode: CloudResourceNode,
  sharedServerNode: SharedServerNode,
  clusterPillNode: ClusterPillNode,
};

/**
 * Summary-band registry — every node-type collapses to `SummaryNode`
 * except cluster pills, which keep their dedicated renderer because they
 * already encode "+N children" copy and wouldn't survive the squeeze.
 */
export const lineageNodeTypesSummary = {
  providerNode: SummaryNode,
  agentNode: SummaryNode,
  userNode: SummaryNode,
  groupNode: SummaryNode,
  serviceAccountNode: SummaryNode,
  environmentNode: SummaryNode,
  fleetNode: SummaryNode,
  clusterNode: SummaryNode,
  serverNode: SummaryNode,
  packageNode: SummaryNode,
  vulnNode: SummaryNode,
  misconfigNode: SummaryNode,
  credentialNode: SummaryNode,
  toolNode: SummaryNode,
  modelNode: SummaryNode,
  datasetNode: SummaryNode,
  containerNode: SummaryNode,
  cloudResourceNode: SummaryNode,
  sharedServerNode: SummaryNode,
  clusterPillNode: ClusterPillNode,
};

/**
 * Cluster-band registry — regular node-types collapse to `ClusterBubbleNode`.
 * Aggregation pills keep their summary representation so a materially
 * compressed graph still shows meaningful "+N" cluster affordances.
 */
export const lineageNodeTypesCluster = {
  providerNode: ClusterBubbleNode,
  agentNode: ClusterBubbleNode,
  userNode: ClusterBubbleNode,
  groupNode: ClusterBubbleNode,
  serviceAccountNode: ClusterBubbleNode,
  environmentNode: ClusterBubbleNode,
  fleetNode: ClusterBubbleNode,
  clusterNode: ClusterBubbleNode,
  serverNode: ClusterBubbleNode,
  packageNode: ClusterBubbleNode,
  vulnNode: ClusterBubbleNode,
  misconfigNode: ClusterBubbleNode,
  credentialNode: ClusterBubbleNode,
  toolNode: ClusterBubbleNode,
  modelNode: ClusterBubbleNode,
  datasetNode: ClusterBubbleNode,
  containerNode: ClusterBubbleNode,
  cloudResourceNode: ClusterBubbleNode,
  sharedServerNode: ClusterBubbleNode,
  clusterPillNode: ClusterPillNode,
};
