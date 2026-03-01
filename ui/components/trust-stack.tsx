"use client";

import Link from "next/link";

const LAYERS = [
  { num: 4, name: "Trust", desc: "Supply Chain Integrity", href: "/compliance", color: "emerald", coverage: "Full" },
  { num: 3, name: "Agent-Build", desc: "Tool & Framework Security", href: "/mesh", color: "blue", coverage: "Full" },
  { num: 2, name: "Semantic", desc: "Data Context & Meaning", href: "/governance", color: "purple", coverage: "Partial" },
  { num: 1, name: "Data", desc: "Storage & Pipelines", href: "/agents", color: "amber", coverage: "Partial" },
] as const;

type LayerColor = (typeof LAYERS)[number]["color"];

const colorMap: Record<LayerColor, { border: string; bg: string; hoverBg: string; text: string; accent: string }> = {
  emerald: {
    border: "border-emerald-700",
    bg: "bg-emerald-950/40",
    hoverBg: "hover:bg-emerald-950/70",
    text: "text-emerald-400",
    accent: "text-emerald-300",
  },
  blue: {
    border: "border-blue-700",
    bg: "bg-blue-950/40",
    hoverBg: "hover:bg-blue-950/70",
    text: "text-blue-400",
    accent: "text-blue-300",
  },
  purple: {
    border: "border-purple-700",
    bg: "bg-purple-950/40",
    hoverBg: "hover:bg-purple-950/70",
    text: "text-purple-400",
    accent: "text-purple-300",
  },
  amber: {
    border: "border-amber-700",
    bg: "bg-amber-950/40",
    hoverBg: "hover:bg-amber-950/70",
    text: "text-amber-400",
    accent: "text-amber-300",
  },
};

export function TrustStack() {
  return (
    <div className="space-y-2">
      {LAYERS.map((layer) => {
        const c = colorMap[layer.color];
        return (
          <Link
            key={layer.num}
            href={layer.href}
            className={`flex items-center gap-4 rounded-xl border ${c.border} ${c.bg} ${c.hoverBg} px-5 py-3.5 transition-all duration-200 group`}
          >
            {/* Layer number + name */}
            <div className="flex items-center gap-3 min-w-[160px]">
              <span className={`text-lg font-bold font-mono ${c.text}`}>
                L{layer.num}
              </span>
              <span className={`text-sm font-semibold ${c.accent}`}>
                {layer.name}
              </span>
            </div>

            {/* Description */}
            <div className="flex-1 text-sm text-zinc-400 group-hover:text-zinc-300 transition-colors">
              {layer.desc}
            </div>

            {/* Coverage badge */}
            <span
              className={`text-xs font-medium px-2.5 py-1 rounded-full ${
                layer.coverage === "Full"
                  ? "bg-emerald-900/60 text-emerald-300 border border-emerald-700"
                  : "bg-yellow-900/60 text-yellow-300 border border-yellow-700"
              }`}
            >
              {layer.coverage}
            </span>
          </Link>
        );
      })}
    </div>
  );
}
