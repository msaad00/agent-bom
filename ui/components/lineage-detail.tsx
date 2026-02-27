"use client";

import {
  X,
  ExternalLink,
  ShieldAlert,
  Server,
  Package,
  Bug,
  KeyRound,
  Wrench,
} from "lucide-react";
import { severityColor } from "@/lib/api";
import type { LineageNodeData } from "./lineage-nodes";

const TYPE_ICON: Record<string, typeof ShieldAlert> = {
  agent: ShieldAlert,
  server: Server,
  sharedServer: Server,
  package: Package,
  vulnerability: Bug,
  credential: KeyRound,
  tool: Wrench,
};

const TYPE_LABELS: Record<string, string> = {
  agent: "Agent",
  server: "MCP Server",
  sharedServer: "Shared MCP Server",
  package: "Package",
  vulnerability: "Vulnerability",
  credential: "Credential",
  tool: "Tool",
};

const TYPE_BORDER: Record<string, string> = {
  agent: "border-emerald-700",
  server: "border-blue-700",
  sharedServer: "border-cyan-700",
  package: "border-zinc-700",
  vulnerability: "border-red-700",
  credential: "border-amber-700",
  tool: "border-purple-700",
};

export function LineageDetailPanel({
  data,
  onClose,
}: {
  data: LineageNodeData;
  onClose: () => void;
}) {
  const Icon = TYPE_ICON[data.nodeType];

  return (
    <div
      className={`absolute right-0 top-0 bottom-0 w-80 bg-zinc-950/95 backdrop-blur-sm border-l ${TYPE_BORDER[data.nodeType]} z-50 overflow-y-auto`}
    >
      <div className="p-4 space-y-4">
        {/* Header */}
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

        {/* Agent */}
        {data.nodeType === "agent" && (
          <div className="space-y-3">
            {data.agentType && (
              <Row label="Type" value={data.agentType} />
            )}
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
            <Row label="Servers" value={data.serverCount ?? 0} />
            <Row label="Packages" value={data.packageCount ?? 0} />
            {(data.vulnCount ?? 0) > 0 && (
              <Row label="Vulnerabilities" value={data.vulnCount!} className="text-red-400" />
            )}
          </div>
        )}

        {/* Server */}
        {data.nodeType === "server" && (
          <div className="space-y-3">
            {data.command && (
              <div>
                <Label>Command</Label>
                <div className="text-xs font-mono text-zinc-300 bg-zinc-900 rounded px-2 py-1 break-all">
                  {data.command}
                </div>
              </div>
            )}
            {(data.toolCount ?? 0) > 0 && (
              <Row label="Tools" value={data.toolCount!} />
            )}
            {(data.credentialCount ?? 0) > 0 && (
              <Row label="Credentials" value={data.credentialCount!} className="text-amber-400" />
            )}
          </div>
        )}

        {/* Shared Server */}
        {data.nodeType === "sharedServer" && (
          <div className="space-y-3">
            {data.sharedBy && (
              <div className="text-xs px-2 py-1 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700 font-mono">
                Shared by {data.sharedBy} agents
              </div>
            )}
            {data.sharedAgents && data.sharedAgents.length > 0 && (
              <div>
                <Label>Connected Agents</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {data.sharedAgents.map((a) => (
                    <span key={a} className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                      {a}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {data.command && (
              <div>
                <Label>Command</Label>
                <div className="text-xs font-mono text-zinc-300 bg-zinc-900 rounded px-2 py-1 break-all">
                  {data.command}
                </div>
              </div>
            )}
            {(data.toolCount ?? 0) > 0 && (
              <Row label="Tools" value={data.toolCount!} />
            )}
            {(data.credentialCount ?? 0) > 0 && (
              <Row label="Credentials" value={data.credentialCount!} className="text-amber-400" />
            )}
            {(data.packageCount ?? 0) > 0 && (
              <Row label="Packages" value={data.packageCount!} />
            )}
          </div>
        )}

        {/* Package */}
        {data.nodeType === "package" && (
          <div className="space-y-3">
            {data.ecosystem && <Row label="Ecosystem" value={data.ecosystem} />}
            {data.version && <Row label="Version" value={data.version} />}
            {(data.vulnCount ?? 0) > 0 ? (
              <Row label="Vulnerabilities" value={data.vulnCount!} className="text-red-400" />
            ) : (
              <div className="text-xs text-emerald-400">No known vulnerabilities</div>
            )}
          </div>
        )}

        {/* Vulnerability */}
        {data.nodeType === "vulnerability" && (
          <div className="space-y-3">
            {data.severity && (
              <span
                className={`inline-block text-xs px-2 py-1 rounded border font-mono uppercase ${severityColor(data.severity)}`}
              >
                {data.severity}
              </span>
            )}
            {data.cvssScore !== undefined && (
              <Row label="CVSS" value={data.cvssScore.toFixed(1)} />
            )}
            {data.epssScore !== undefined && data.epssScore > 0 && (
              <Row label="EPSS" value={`${(data.epssScore * 100).toFixed(1)}%`} />
            )}
            {data.isKev && (
              <div className="text-xs px-2 py-1 rounded bg-red-900 text-red-300 border border-red-700 font-mono inline-block">
                CISA Known Exploited
              </div>
            )}
            {data.fixedVersion && (
              <Row label="Fix version" value={data.fixedVersion} className="text-emerald-400" />
            )}
            {data.owaspTags && data.owaspTags.length > 0 && (
              <div>
                <Label>OWASP</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {data.owaspTags.map((t) => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {data.atlasTags && data.atlasTags.length > 0 && (
              <div>
                <Label>MITRE ATLAS</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {data.atlasTags.map((t) => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
            <a
              href={`https://osv.dev/vulnerability/${data.label}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 transition-colors"
            >
              <ExternalLink className="w-3 h-3" />
              View on OSV
            </a>
          </div>
        )}

        {/* Credential */}
        {data.nodeType === "credential" && (
          <div className="space-y-3">
            <div className="text-xs text-amber-400">
              Environment variable exposed in MCP server configuration
            </div>
            {data.serverName && <Row label="Server" value={data.serverName} />}
          </div>
        )}

        {/* Tool */}
        {data.nodeType === "tool" && (
          <div className="space-y-3">
            {data.description && (
              <div className="text-xs text-zinc-400">{data.description}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function Label({ children }: { children: React.ReactNode }) {
  return <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-0.5">{children}</div>;
}

function Row({
  label,
  value,
  className = "",
}: {
  label: string;
  value: string | number;
  className?: string;
}) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-zinc-500">{label}</span>
      <span className={`text-zinc-300 font-mono ${className}`}>{value}</span>
    </div>
  );
}
