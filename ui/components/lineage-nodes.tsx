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
  entityType?: string;
  status?: string;
  riskScore?: number;
  firstSeen?: string;
  lastSeen?: string;
  dataSources?: string[];
  complianceTags?: string[];
  attributes?: Record<string, unknown>;
  neighborCount?: number;
  sourceCount?: number;
  incomingEdgeCount?: number;
  outgoingEdgeCount?: number;
  impactCount?: number;
  maxImpactDepth?: number;
  impactByType?: Record<string, number>;
  // Agent / provider
  agentType?: string;
  agentStatus?: string;
  agentCount?: number;
  serverCount?: number;
  packageCount?: number;
  vulnCount?: number;
  // Server / Shared Server
  toolCount?: number;
  credentialCount?: number;
  command?: string;
  sharedBy?: number;
  sharedAgents?: string[];
  // Package / model / dataset
  ecosystem?: string;
  version?: string;
  versionSource?: string;
  registryVersion?: string;
  // Vulnerability / misconfiguration
  severity?: string;
  cvssScore?: number;
  epssScore?: number;
  isKev?: boolean;
  fixedVersion?: string;
  owaspTags?: string[];
  atlasTags?: string[];
  // Credential
  serverName?: string;
  // Tool / generic assets
  description?: string;
  // Highlighting
  dimmed?: boolean;
  highlighted?: boolean;
  isCritical?: boolean;
};

type CardProps = {
  data: LineageNodeData;
  borderClass: string;
  bgClass: string;
  ringClass: string;
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
  icon: Icon,
  iconClass,
  source = true,
  target = true,
  subtitle,
  footer,
}: CardProps) {
  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 min-w-[148px] max-w-[220px] shadow-lg backdrop-blur transition-opacity ${borderClass} ${bgClass} ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? `ring-2 ${ringClass}` : ""}`}
    >
      {target && <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-current" />}
      {source && <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-current" />}
      <div className="flex items-center gap-1.5 mb-0.5">
        <Icon className={`w-3.5 h-3.5 shrink-0 ${iconClass}`} />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      {subtitle && <div className="text-[10px] text-zinc-400 truncate">{subtitle}</div>}
      {footer}
    </div>
  );
}

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
  return (
    <NodeCard
      data={data}
      borderClass={hasVulns ? "border-red-600/60" : "border-zinc-600"}
      bgClass={hasVulns ? "bg-red-950/40" : "bg-zinc-900/80"}
      ringClass="ring-zinc-400"
      icon={Package}
      iconClass="text-zinc-400"
      subtitle={data.version ? `${data.version}${data.ecosystem ? ` · ${data.ecosystem}` : ""}` : data.ecosystem}
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
          {data.cvssScore !== undefined && (
            <span className="text-[10px] text-zinc-400">CVSS {data.cvssScore.toFixed(1)}</span>
          )}
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

function SharedServerNode({ data }: { data: LineageNodeData }) {
  return (
    <NodeCard
      data={data}
      borderClass="border-cyan-400"
      bgClass="bg-cyan-950/80"
      ringClass="ring-cyan-300"
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
};
