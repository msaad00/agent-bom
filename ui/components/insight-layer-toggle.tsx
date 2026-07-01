"use client";

interface InsightLayerToggleProps {
  layers: { id: string; label: string; icon: string; active: boolean }[];
  onToggle: (id: string) => void;
}

export function InsightLayerToggle({ layers, onToggle }: InsightLayerToggleProps) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1">
      <span className="mr-1 whitespace-nowrap text-xs text-zinc-500">
        Insight Layers:
      </span>
      {layers.map((layer) => (
        <button key={layer.id} onClick={() => onToggle(layer.id)}
          className={`flex max-w-full items-center gap-1 rounded px-2 py-1 text-xs transition-colors ${
            layer.active
              ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
              : "bg-zinc-900 text-zinc-500 hover:text-zinc-300 border border-zinc-800"
          }`}>
          <span>{layer.icon}</span>
          <span className="truncate">{layer.label}</span>
        </button>
      ))}
    </div>
  );
}
