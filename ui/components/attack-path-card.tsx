"use client";

interface AttackPathNode {
  type: "cve" | "package" | "server" | "agent" | "credential";
  label: string;
  severity?: string;
}

interface AttackPathCardProps {
  nodes: AttackPathNode[];
  riskScore: number;
  onClick?: () => void;
}

export function AttackPathCard({ nodes, riskScore, onClick }: AttackPathCardProps) {
  const icons: Record<string, string> = {
    cve: "\uD83D\uDD13", package: "\uD83D\uDCE6", server: "\uD83D\uDDA5\uFE0F", agent: "\uD83E\uDD16", credential: "\uD83D\uDD11",
  };

  return (
    <button onClick={onClick}
      className="flex items-center gap-1 px-3 py-2 rounded-lg border border-zinc-800 bg-zinc-900/50 hover:border-zinc-600 hover:bg-zinc-900 transition-all w-full text-left">
      {nodes.map((node, i) => (
        <div key={i} className="flex items-center gap-1">
          {i > 0 && <span className="text-zinc-600 text-xs">{"\u2192"}</span>}
          <div className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-xs ${
            node.severity === "critical" ? "border border-red-500/30 bg-red-500/10" :
            node.severity === "high" ? "border border-orange-500/30 bg-orange-500/10" :
            "border border-zinc-700 bg-zinc-800/50"
          }`}>
            <span>{icons[node.type] ?? "\u2022"}</span>
            <span className="truncate max-w-[100px] text-zinc-300">{node.label}</span>
          </div>
        </div>
      ))}
      <div className="ml-auto flex items-center gap-1 text-xs">
        <span className="text-zinc-500">Risk</span>
        <span className={`font-mono font-bold ${riskScore >= 8 ? "text-red-400" : riskScore >= 5 ? "text-orange-400" : "text-zinc-400"}`}>
          {riskScore.toFixed(1)}
        </span>
      </div>
    </button>
  );
}
