"use client";

import { Server, KeyRound, Wrench, ShieldAlert } from "lucide-react";

export interface MeshStatsData {
  totalAgents: number;
  sharedServers: number;
  uniqueCredentials: number;
  toolOverlap: number;
  credentialBlast: string[];
}

export function MeshStats({ stats }: { stats: MeshStatsData }) {
  return (
    <div className="flex items-center gap-4 px-4 py-2 border-b border-zinc-800 text-xs">
      <Stat icon={ShieldAlert} label="Agents" value={stats.totalAgents} color="text-emerald-400" />
      <Stat icon={Server} label="Shared Servers" value={stats.sharedServers} color="text-cyan-400" />
      <Stat icon={KeyRound} label="Credentials" value={stats.uniqueCredentials} color="text-amber-400" />
      <Stat icon={Wrench} label="Tool Overlap" value={stats.toolOverlap} color="text-purple-400" />
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
