"use client";

import Link from "next/link";
import type { LucideIcon } from "lucide-react";
import { Bot, Bug, ChevronRight, KeyRound, Package, Server } from "lucide-react";

interface AttackPathNode {
  type: "cve" | "package" | "server" | "agent" | "credential";
  label: string;
  severity?: string;
}

interface AttackPathCardProps {
  nodes: AttackPathNode[];
  riskScore: number;
  onClick?: () => void;
  href?: string;
}

const NODE_META: Record<AttackPathNode["type"], { icon: LucideIcon; tint: string; ring: string }> = {
  cve: { icon: Bug, tint: "text-red-300 bg-red-500/12", ring: "border-red-500/25" },
  package: { icon: Package, tint: "text-amber-300 bg-amber-500/12", ring: "border-amber-500/25" },
  server: { icon: Server, tint: "text-sky-300 bg-sky-500/12", ring: "border-sky-500/25" },
  agent: { icon: Bot, tint: "text-emerald-300 bg-emerald-500/12", ring: "border-emerald-500/25" },
  credential: { icon: KeyRound, tint: "text-fuchsia-300 bg-fuchsia-500/12", ring: "border-fuchsia-500/25" },
};

export function AttackPathCard({ nodes, riskScore, onClick, href }: AttackPathCardProps) {
  const riskTone =
    riskScore >= 8
      ? "text-red-400 text-red-300 border-red-500/25 bg-red-500/10"
      : riskScore >= 5
        ? "text-orange-400 text-amber-300 border-amber-500/25 bg-amber-500/10"
        : "text-zinc-400 text-zinc-300 border-zinc-700 bg-zinc-800/70";

  const cardBody = (
    <>
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.24em] text-zinc-500">Attack path</p>
          <p className="mt-1 text-sm font-semibold text-zinc-100">Credential-aware blast radius</p>
        </div>
        <div className={`rounded-xl border px-2.5 py-1 font-mono text-xs font-semibold ${riskTone}`}>
          <span className="text-[10px] uppercase tracking-[0.16em]">Risk</span>{" "}
          <span>{riskScore.toFixed(1)}</span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        {nodes.map((node, i) => {
          const meta = NODE_META[node.type];
          const Icon = meta.icon;
          const severityRing =
            node.severity === "critical"
              ? "border-red-500/30"
              : node.severity === "high"
                ? "border-orange-500/30"
                : meta.ring;
          return (
            <div key={`${node.type}-${node.label}-${i}`} className="flex items-center gap-1.5">
              {i > 0 && (
                <div className="flex h-5 w-5 items-center justify-center text-zinc-600">
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                  <span className="sr-only">→</span>
                </div>
              )}
              <div className={`flex items-center gap-2 rounded-xl border px-2.5 py-1.5 ${severityRing} ${meta.tint}`}>
                <Icon className="h-3.5 w-3.5 shrink-0" />
                <div className="min-w-0">
                  <p className="max-w-[120px] truncate text-[11px] font-medium text-zinc-100">{node.label}</p>
                  <p className="text-[9px] uppercase tracking-[0.16em] text-zinc-500">{node.type}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      {href && (
        <div className="mt-3 text-xs font-medium text-emerald-300">
          Open focused security graph
        </div>
      )}
    </>
  );

  const className =
    "group block w-full rounded-2xl border border-zinc-800 bg-[linear-gradient(135deg,rgba(24,24,27,0.98),rgba(15,23,42,0.88))] px-4 py-3 text-left shadow-lg shadow-black/20 transition-all hover:-translate-y-0.5 hover:border-zinc-600 hover:shadow-xl hover:shadow-emerald-500/5";

  if (href && !onClick) {
    return (
      <Link href={href} className={className}>
        {cardBody}
      </Link>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      className={className}
    >
      {cardBody}
    </button>
  );
}
