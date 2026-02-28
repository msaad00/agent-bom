"use client";

import { Server, KeyRound, Wrench, ShieldAlert, Package, Bug, AlertTriangle } from "lucide-react";
import type { MeshStatsData } from "@/lib/mesh-graph";

export type { MeshStatsData };

export function MeshStats({ stats }: { stats: MeshStatsData }) {
  const totalSev = stats.criticalCount + stats.highCount + stats.mediumCount + stats.lowCount;

  return (
    <div className="flex items-center gap-4 px-4 py-2 border-b border-zinc-800 text-xs flex-wrap">
      <Stat icon={ShieldAlert} label="Agents" value={stats.totalAgents} color="text-emerald-400" />
      <Stat icon={Server} label="Shared Servers" value={stats.sharedServers} color="text-cyan-400" />
      <Stat icon={Package} label="Packages" value={stats.totalPackages} color="text-zinc-400" />
      <Stat icon={Bug} label="Vulns" value={stats.totalVulnerabilities} color="text-red-400" />
      <Stat icon={KeyRound} label="Credentials" value={stats.uniqueCredentials} color="text-amber-400" />
      <Stat icon={Wrench} label="Tool Overlap" value={stats.toolOverlap} color="text-purple-400" />

      {/* Severity breakdown mini-bar */}
      {totalSev > 0 && (
        <div className="flex items-center gap-1.5 ml-2">
          <span className="text-zinc-500">Severity:</span>
          <div className="flex h-2.5 rounded-full overflow-hidden w-24 bg-zinc-800">
            {stats.criticalCount > 0 && (
              <div
                className="bg-red-500 h-full"
                style={{ width: `${(stats.criticalCount / totalSev) * 100}%` }}
                title={`${stats.criticalCount} critical`}
              />
            )}
            {stats.highCount > 0 && (
              <div
                className="bg-orange-500 h-full"
                style={{ width: `${(stats.highCount / totalSev) * 100}%` }}
                title={`${stats.highCount} high`}
              />
            )}
            {stats.mediumCount > 0 && (
              <div
                className="bg-yellow-500 h-full"
                style={{ width: `${(stats.mediumCount / totalSev) * 100}%` }}
                title={`${stats.mediumCount} medium`}
              />
            )}
            {stats.lowCount > 0 && (
              <div
                className="bg-blue-500 h-full"
                style={{ width: `${(stats.lowCount / totalSev) * 100}%` }}
                title={`${stats.lowCount} low`}
              />
            )}
          </div>
          {stats.criticalCount > 0 && (
            <span className="text-red-400 font-semibold">{stats.criticalCount}C</span>
          )}
          {stats.highCount > 0 && (
            <span className="text-orange-400 font-semibold">{stats.highCount}H</span>
          )}
        </div>
      )}

      {/* KEV badge */}
      {stats.kevCount > 0 && (
        <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-red-900/60 border border-red-700">
          <AlertTriangle className="w-3 h-3 text-red-400" />
          <span className="text-red-300 font-mono text-[10px]">{stats.kevCount} KEV</span>
        </div>
      )}

      {/* Credential blast */}
      {stats.credentialBlast.length > 0 && (
        <div className="ml-auto flex items-center gap-1.5 text-amber-400">
          <KeyRound className="w-3 h-3" />
          <span className="text-[10px]">
            {stats.credentialBlast.slice(0, 2).join(", ")}
            {stats.credentialBlast.length > 2 && ` +${stats.credentialBlast.length - 2}`}
          </span>
        </div>
      )}
    </div>
  );
}

function Stat({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: typeof ShieldAlert;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <Icon className={`w-3.5 h-3.5 ${color}`} />
      <span className="text-zinc-500">{label}</span>
      <span className="font-semibold text-zinc-200">{value}</span>
    </div>
  );
}
