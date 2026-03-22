"use client";

interface InsightLayerToggleProps {
  layers: { id: string; label: string; icon: string; active: boolean }[];
  onToggle: (id: string) => void;
}

export function InsightLayerToggle({ layers, onToggle }: InsightLayerToggleProps) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-xs text-zinc-500 mr-1">Insight Layers:</span>
      {layers.map((layer) => (
        <button key={layer.id} onClick={() => onToggle(layer.id)}
          className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${
            layer.active
              ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
              : "bg-zinc-900 text-zinc-500 hover:text-zinc-300 border border-zinc-800"
          }`}>
          <span>{layer.icon}</span>
          <span>{layer.label}</span>
        </button>
      ))}
    </div>
  );
}
