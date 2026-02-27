"use client";

import { Handle, Position } from "@xyflow/react";
import {
  ShieldAlert,
  Server,
  Package,
  Bug,
  KeyRound,
  Wrench,
} from "lucide-react";
import { severityColor } from "@/lib/api";

// ─── Shared types ────────────────────────────────────────────────────────────

export type LineageNodeType =
  | "agent"
  | "server"
  | "package"
  | "vulnerability"
  | "credential"
  | "tool"
  | "sharedServer";

export type LineageNodeData = {
  label: string;
  nodeType: LineageNodeType;
  // Agent
  agentType?: string;
  agentStatus?: string;
  serverCount?: number;
  packageCount?: number;
  vulnCount?: number;
  // Server / Shared Server
  toolCount?: number;
  credentialCount?: number;
  command?: string;
  sharedBy?: number;
  sharedAgents?: string[];
  // Package
  ecosystem?: string;
  version?: string;
  versionSource?: string;
  registryVersion?: string;
  // Vulnerability
  severity?: string;
  cvssScore?: number;
  epssScore?: number;
  isKev?: boolean;
  fixedVersion?: string;
  owaspTags?: string[];
  atlasTags?: string[];
  // Credential
  serverName?: string;
  // Tool
  description?: string;
  // Highlighting
  dimmed?: boolean;
  highlighted?: boolean;
};

// ─── Agent Node ──────────────────────────────────────────────────────────────

function AgentNode({ data }: { data: LineageNodeData }) {
  const notConfigured = data.agentStatus === "installed-not-configured";
  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 min-w-[150px] max-w-[210px] shadow-lg backdrop-blur transition-opacity ${
        notConfigured
          ? "border-yellow-600 bg-yellow-950/80 border-dashed"
          : "border-emerald-600 bg-emerald-950/80"
      } ${data.dimmed ? "opacity-25" : ""} ${data.highlighted ? "ring-2 ring-emerald-400" : ""}`}
    >
      <Handle type="source" position={Position.Right} className="!bg-emerald-500 !w-2 !h-2" />
      <div className="flex items-center gap-1.5 mb-0.5">
        <ShieldAlert className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      {data.agentType && (
        <div className="text-[10px] text-zinc-400 truncate">{data.agentType}</div>
      )}
      <div className="flex gap-2 mt-1 text-[10px] text-zinc-500">
        {data.serverCount !== undefined && <span>{data.serverCount} srv</span>}
        {data.packageCount !== undefined && <span>{data.packageCount} pkg</span>}
        {data.vulnCount !== undefined && data.vulnCount > 0 && (
          <span className="text-red-400">{data.vulnCount} vuln</span>
        )}
      </div>
    </div>
  );
}

// ─── Server Node ─────────────────────────────────────────────────────────────

function ServerNode({ data }: { data: LineageNodeData }) {
  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[200px] shadow-lg backdrop-blur border-blue-600 bg-blue-950/80 transition-opacity ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-blue-400" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!bg-blue-500 !w-2 !h-2" />
      <Handle type="source" position={Position.Right} className="!bg-blue-500 !w-2 !h-2" />
      <div className="flex items-center gap-1.5 mb-0.5">
        <Server className="w-3.5 h-3.5 text-blue-400 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      {data.command && (
        <div className="text-[10px] text-zinc-400 truncate font-mono">{data.command}</div>
      )}
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
      </div>
    </div>
  );
}

// ─── Package Node ────────────────────────────────────────────────────────────

function PackageNode({ data }: { data: LineageNodeData }) {
  const hasVulns = (data.vulnCount ?? 0) > 0;
  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[200px] shadow-lg backdrop-blur transition-opacity ${
        hasVulns ? "border-red-600/60 bg-red-950/40" : "border-zinc-600 bg-zinc-900/80"
      } ${data.dimmed ? "opacity-25" : ""} ${data.highlighted ? "ring-2 ring-zinc-400" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!bg-zinc-500 !w-2 !h-2" />
      <Handle type="source" position={Position.Right} className="!bg-zinc-500 !w-2 !h-2" />
      <div className="flex items-center gap-1.5 mb-0.5">
        <Package className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      <div className="flex gap-2 text-[10px]">
        {data.ecosystem && <span className="text-zinc-500">{data.ecosystem}</span>}
        {hasVulns && (
          <span className="text-red-400">
            <Bug className="w-2.5 h-2.5 inline mr-0.5" />
            {data.vulnCount}
          </span>
        )}
      </div>
    </div>
  );
}

// ─── Vulnerability Node ──────────────────────────────────────────────────────

function VulnNode({ data }: { data: LineageNodeData }) {
  const sev = data.severity ?? "medium";
  const glowColor =
    sev === "critical" ? "shadow-red-500/40 shadow-lg" :
    sev === "high" ? "shadow-orange-500/30 shadow-md" : "";
  const borderColor =
    sev === "critical" ? "border-red-500" :
    sev === "high" ? "border-orange-500" :
    sev === "medium" ? "border-yellow-500" : "border-blue-500";
  const bgColor =
    sev === "critical" ? "bg-red-950/80" :
    sev === "high" ? "bg-orange-950/80" :
    sev === "medium" ? "bg-yellow-950/80" : "bg-blue-950/80";

  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[220px] backdrop-blur transition-opacity ${borderColor} ${bgColor} ${glowColor} ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-white/50" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!bg-red-500 !w-2 !h-2" />
      <div className="flex items-center gap-1.5 mb-0.5">
        <Bug className="w-3.5 h-3.5 shrink-0" />
        <span className="text-xs font-semibold text-zinc-100 truncate">{data.label}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1">
        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${severityColor(sev)}`}>
          {sev}
        </span>
        {data.cvssScore !== undefined && (
          <span className="text-[10px] text-zinc-400">CVSS {data.cvssScore.toFixed(1)}</span>
        )}
        {data.epssScore !== undefined && data.epssScore > 0 && (
          <span className="text-[10px] text-zinc-400">EPSS {(data.epssScore * 100).toFixed(1)}%</span>
        )}
        {data.isKev && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900 text-red-300 border border-red-700 font-mono">KEV</span>
        )}
      </div>
    </div>
  );
}

// ─── Credential Node ─────────────────────────────────────────────────────────

function CredentialNode({ data }: { data: LineageNodeData }) {
  return (
    <div
      className={`rounded-lg border-2 border-dashed px-3 py-2 min-w-[120px] max-w-[180px] shadow-lg backdrop-blur border-amber-500 bg-amber-950/60 transition-opacity ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-amber-400" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!bg-amber-500 !w-2 !h-2" />
      <div className="flex items-center gap-1.5">
        <KeyRound className="w-3.5 h-3.5 text-amber-400 shrink-0" />
        <span className="text-xs font-semibold text-amber-200 truncate">{data.label}</span>
      </div>
      {data.serverName && (
        <div className="text-[10px] text-amber-400/60 truncate mt-0.5">{data.serverName}</div>
      )}
    </div>
  );
}

// ─── Tool Node ───────────────────────────────────────────────────────────────

function ToolNode({ data }: { data: LineageNodeData }) {
  return (
    <div
      className={`rounded-lg border px-2.5 py-1.5 min-w-[100px] max-w-[160px] shadow backdrop-blur border-purple-600 bg-purple-950/60 transition-opacity ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-purple-400" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!bg-purple-500 !w-2 !h-2" />
      <div className="flex items-center gap-1.5">
        <Wrench className="w-3 h-3 text-purple-400 shrink-0" />
        <span className="text-[11px] font-medium text-purple-200 truncate">{data.label}</span>
      </div>
    </div>
  );
}

// ─── Shared Server Node ──────────────────────────────────────────────────────

function SharedServerNode({ data }: { data: LineageNodeData }) {
  return (
    <div
      className={`rounded-xl border-2 px-4 py-3 min-w-[170px] max-w-[240px] shadow-lg shadow-cyan-500/20 backdrop-blur border-cyan-400 bg-cyan-950/80 transition-opacity ${
        data.dimmed ? "opacity-25" : ""
      } ${data.highlighted ? "ring-2 ring-cyan-300" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!bg-cyan-400 !w-2.5 !h-2.5" />
      <Handle type="source" position={Position.Right} className="!bg-cyan-400 !w-2.5 !h-2.5" />
      <div className="flex items-center gap-1.5 mb-1">
        <Server className="w-4 h-4 text-cyan-300 shrink-0" />
        <span className="text-xs font-bold text-cyan-100 truncate">{data.label}</span>
      </div>
      {data.sharedBy && data.sharedBy > 1 && (
        <div className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700 font-mono inline-block mb-1">
          Shared by {data.sharedBy} agents
        </div>
      )}
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
    </div>
  );
}

// ─── Node Types Map ──────────────────────────────────────────────────────────

export const lineageNodeTypes = {
  agentNode: AgentNode,
  serverNode: ServerNode,
  packageNode: PackageNode,
  vulnNode: VulnNode,
  credentialNode: CredentialNode,
  toolNode: ToolNode,
  sharedServerNode: SharedServerNode,
};
